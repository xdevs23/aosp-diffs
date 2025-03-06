```diff
diff --git a/alsa_utils/Android.bp b/alsa_utils/Android.bp
index 9d96c42b..402b76fe 100644
--- a/alsa_utils/Android.bp
+++ b/alsa_utils/Android.bp
@@ -22,7 +22,7 @@ package {
 
 cc_defaults {
     name: "libalsautils_defaults",
-    vendor: true,
+    vendor_available: true,
     srcs: [
         "alsa_device_profile.c",
         "alsa_device_proxy.c",
@@ -48,7 +48,7 @@ cc_defaults {
     ],
 }
 
-cc_library_shared {
+cc_library {
     name: "libalsautils",
     defaults: ["libalsautils_defaults"],
     shared_libs: [
@@ -56,7 +56,7 @@ cc_library_shared {
     ],
 }
 
-cc_library_shared {
+cc_library {
     name: "libalsautilsv2",
     defaults: ["libalsautils_defaults"],
     shared_libs: [
diff --git a/audio/include/system/audio-base-utils.h b/audio/include/system/audio-base-utils.h
index a348f052..e318f6af 100644
--- a/audio/include/system/audio-base-utils.h
+++ b/audio/include/system/audio-base-utils.h
@@ -77,6 +77,7 @@ enum {
                                 AUDIO_DEVICE_OUT_AUX_LINE |
                                 AUDIO_DEVICE_OUT_SPEAKER_SAFE |
                                 AUDIO_DEVICE_OUT_IP |
+                                AUDIO_DEVICE_OUT_MULTICHANNEL_GROUP |
                                 AUDIO_DEVICE_OUT_BUS |
                                 AUDIO_DEVICE_OUT_PROXY |
                                 AUDIO_DEVICE_OUT_USB_HEADSET |
@@ -178,6 +179,7 @@ static CONST_ARRAY audio_devices_t AUDIO_DEVICE_OUT_ALL_ARRAY[] = {
     AUDIO_DEVICE_OUT_AUX_LINE,                  // 0x00200000u
     AUDIO_DEVICE_OUT_SPEAKER_SAFE,              // 0x00400000u
     AUDIO_DEVICE_OUT_IP,                        // 0x00800000u
+    AUDIO_DEVICE_OUT_MULTICHANNEL_GROUP,        // 0x00800001u
     AUDIO_DEVICE_OUT_BUS,                       // 0x01000000u
     AUDIO_DEVICE_OUT_PROXY,                     // 0x02000000u
     AUDIO_DEVICE_OUT_USB_HEADSET,               // 0x04000000u
@@ -220,6 +222,7 @@ static CONST_ARRAY audio_devices_t AUDIO_DEVICE_OUT_ALL_DIGITAL_ARRAY[] = {
     AUDIO_DEVICE_OUT_HDMI_EARC,                 // 0x00040001u
     AUDIO_DEVICE_OUT_SPDIF,                     // 0x00080000u
     AUDIO_DEVICE_OUT_IP,                        // 0x00800000u
+    AUDIO_DEVICE_OUT_MULTICHANNEL_GROUP,        // 0x00800001u
     AUDIO_DEVICE_OUT_BUS,                       // 0x01000000u
     AUDIO_DEVICE_OUT_USB_HEADSET,               // 0x04000000u
 };
diff --git a/audio/include/system/audio-hal-enums.h b/audio/include/system/audio-hal-enums.h
index bb2f9559..d8e8e3b5 100644
--- a/audio/include/system/audio-hal-enums.h
+++ b/audio/include/system/audio-hal-enums.h
@@ -362,6 +362,7 @@ enum {
     V(AUDIO_DEVICE_OUT_AUX_LINE, 0x200000u) \
     V(AUDIO_DEVICE_OUT_SPEAKER_SAFE, 0x400000u) \
     V(AUDIO_DEVICE_OUT_IP, 0x800000u) \
+    V(AUDIO_DEVICE_OUT_MULTICHANNEL_GROUP, 0x800001u) \
     V(AUDIO_DEVICE_OUT_BUS, 0x1000000u) \
     V(AUDIO_DEVICE_OUT_PROXY, 0x2000000u) \
     V(AUDIO_DEVICE_OUT_USB_HEADSET, 0x4000000u) \
@@ -532,6 +533,8 @@ enum {
 
     AUDIO_FORMAT_E_AC3_SUB_JOC         = 0x1u,
 
+    AUDIO_FORMAT_AC4_SUB_L4            = 0x1u,
+
     AUDIO_FORMAT_MAT_SUB_1_0           = 0x1u,
     AUDIO_FORMAT_MAT_SUB_2_0           = 0x2u,
     AUDIO_FORMAT_MAT_SUB_2_1           = 0x3u,
@@ -540,6 +543,19 @@ enum {
     AUDIO_FORMAT_MPEGH_SUB_BL_L4       = 0x14u,
     AUDIO_FORMAT_MPEGH_SUB_LC_L3       = 0x23u,
     AUDIO_FORMAT_MPEGH_SUB_LC_L4       = 0x24u,
+
+    // never used alone, but always as a combination of profile and codec
+    AUDIO_FORMAT_IAMF                  = 0x34000000u,
+    // values for profiles and codecs match the java MediaCodecInfo definitions
+    // codecs used in an IAMF stream
+    AUDIO_FORMAT_IAMF_CODEC_OPUS       = 0x1u,
+    AUDIO_FORMAT_IAMF_CODEC_AAC        = 0x1u << 1,
+    AUDIO_FORMAT_IAMF_CODEC_FLAC       = 0x1u << 2,
+    AUDIO_FORMAT_IAMF_CODEC_PCM        = 0x1u << 3,
+    // profiles
+    AUDIO_FORMAT_IAMF_SIMPLE        = 0x1 << 16,
+    AUDIO_FORMAT_IAMF_BASE          = 0x1 << 17,
+    AUDIO_FORMAT_IAMF_BASE_ENHANCED = 0x1 << 18,
 };
 
 #define AUDIO_FORMAT_LIST_UNIQUE_DEF(V) \
@@ -606,6 +622,7 @@ enum {
     V(AUDIO_FORMAT_APTX, 0x20000000u) \
     V(AUDIO_FORMAT_APTX_HD, 0x21000000u) \
     V(AUDIO_FORMAT_AC4, 0x22000000u) \
+    V(AUDIO_FORMAT_AC4_L4, AUDIO_FORMAT_AC4 | AUDIO_FORMAT_AC4_SUB_L4) \
     V(AUDIO_FORMAT_LDAC, 0x23000000u) \
     V(AUDIO_FORMAT_MAT, 0x24000000u) \
     V(AUDIO_FORMAT_MAT_1_0, AUDIO_FORMAT_MAT | AUDIO_FORMAT_MAT_SUB_1_0) \
@@ -632,8 +649,19 @@ enum {
     V(AUDIO_FORMAT_APTX_ADAPTIVE_QLEA, 0x30000000u) \
     V(AUDIO_FORMAT_APTX_ADAPTIVE_R4, 0x31000000u) \
     V(AUDIO_FORMAT_DTS_HD_MA, 0x32000000u) \
-    V(AUDIO_FORMAT_DTS_UHD_P2, 0x33000000u)
-
+    V(AUDIO_FORMAT_DTS_UHD_P2, 0x33000000u)        \
+    V(AUDIO_FORMAT_IAMF_SIMPLE_OPUS, AUDIO_FORMAT_IAMF | AUDIO_FORMAT_IAMF_SIMPLE | AUDIO_FORMAT_IAMF_CODEC_OPUS) \
+    V(AUDIO_FORMAT_IAMF_SIMPLE_AAC, AUDIO_FORMAT_IAMF | AUDIO_FORMAT_IAMF_SIMPLE | AUDIO_FORMAT_IAMF_CODEC_AAC) \
+    V(AUDIO_FORMAT_IAMF_SIMPLE_PCM, AUDIO_FORMAT_IAMF | AUDIO_FORMAT_IAMF_SIMPLE | AUDIO_FORMAT_IAMF_CODEC_PCM) \
+    V(AUDIO_FORMAT_IAMF_SIMPLE_FLAC, AUDIO_FORMAT_IAMF | AUDIO_FORMAT_IAMF_SIMPLE | AUDIO_FORMAT_IAMF_CODEC_FLAC) \
+    V(AUDIO_FORMAT_IAMF_BASE_OPUS, AUDIO_FORMAT_IAMF | AUDIO_FORMAT_IAMF_BASE | AUDIO_FORMAT_IAMF_CODEC_OPUS) \
+    V(AUDIO_FORMAT_IAMF_BASE_AAC, AUDIO_FORMAT_IAMF | AUDIO_FORMAT_IAMF_BASE | AUDIO_FORMAT_IAMF_CODEC_AAC) \
+    V(AUDIO_FORMAT_IAMF_BASE_PCM, AUDIO_FORMAT_IAMF | AUDIO_FORMAT_IAMF_BASE | AUDIO_FORMAT_IAMF_CODEC_PCM) \
+    V(AUDIO_FORMAT_IAMF_BASE_FLAC, AUDIO_FORMAT_IAMF | AUDIO_FORMAT_IAMF_BASE | AUDIO_FORMAT_IAMF_CODEC_FLAC)     \
+    V(AUDIO_FORMAT_IAMF_BASE_ENHANCED_OPUS, AUDIO_FORMAT_IAMF | AUDIO_FORMAT_IAMF_BASE_ENHANCED | AUDIO_FORMAT_IAMF_CODEC_OPUS) \
+    V(AUDIO_FORMAT_IAMF_BASE_ENHANCED_AAC, AUDIO_FORMAT_IAMF | AUDIO_FORMAT_IAMF_BASE_ENHANCED | AUDIO_FORMAT_IAMF_CODEC_AAC) \
+    V(AUDIO_FORMAT_IAMF_BASE_ENHANCED_PCM, AUDIO_FORMAT_IAMF | AUDIO_FORMAT_IAMF_BASE_ENHANCED | AUDIO_FORMAT_IAMF_CODEC_PCM) \
+    V(AUDIO_FORMAT_IAMF_BASE_ENHANCED_FLAC, AUDIO_FORMAT_IAMF | AUDIO_FORMAT_IAMF_BASE_ENHANCED | AUDIO_FORMAT_IAMF_CODEC_FLAC)
 #define AUDIO_FORMAT_LIST_DEF(V) \
     AUDIO_FORMAT_LIST_UNIQUE_DEF(V) \
     V(VX_AUDIO_FORMAT_LC3, AUDIO_FORMAT_LC3)
@@ -792,7 +820,8 @@ inline bool audio_stream_type_from_string(const char* s, audio_stream_type_t* t)
     V(AUDIO_USAGE_EMERGENCY, 1000) \
     V(AUDIO_USAGE_SAFETY, 1001) \
     V(AUDIO_USAGE_VEHICLE_STATUS, 1002) \
-    V(AUDIO_USAGE_ANNOUNCEMENT, 1003)
+    V(AUDIO_USAGE_ANNOUNCEMENT, 1003) \
+    V(AUDIO_USAGE_SPEAKER_CLEANUP, 1004)
 #ifdef AUDIO_NO_SYSTEM_DECLARATIONS
 #define AUDIO_USAGE_LIST_DEF AUDIO_USAGE_LIST_NO_SYS_DEF
 #else
diff --git a/audio/include/system/audio.h b/audio/include/system/audio.h
index f6f8b8ba..b0d5ba96 100644
--- a/audio/include/system/audio.h
+++ b/audio/include/system/audio.h
@@ -631,6 +631,7 @@ struct audio_port_config_device_ext {
     audio_module_handle_t hw_module;                /* module the device is attached to */
     audio_devices_t       type;                     /* device type (e.g AUDIO_DEVICE_OUT_SPEAKER) */
     char                  address[AUDIO_DEVICE_MAX_ADDRESS_LEN]; /* device address. "" if N/A */
+    audio_channel_mask_t  speaker_layout_channel_mask; /* represents physical speaker layout. */
 };
 
 /* extension for audio port configuration structure when the audio port is a
@@ -956,6 +957,8 @@ static inline bool audio_port_configs_are_equal(
     case AUDIO_PORT_TYPE_DEVICE:
         if (lhs->ext.device.hw_module != rhs->ext.device.hw_module ||
                 lhs->ext.device.type != rhs->ext.device.type ||
+                lhs->ext.device.speaker_layout_channel_mask !=
+                        rhs->ext.device.speaker_layout_channel_mask ||
                 strncmp(lhs->ext.device.address, rhs->ext.device.address,
                         AUDIO_DEVICE_MAX_ADDRESS_LEN) != 0) {
             return false;
@@ -1900,7 +1903,16 @@ static inline bool audio_is_valid_format(audio_format_t format)
     case AUDIO_FORMAT_SBC:
     case AUDIO_FORMAT_APTX:
     case AUDIO_FORMAT_APTX_HD:
+        return true;
     case AUDIO_FORMAT_AC4:
+        switch (format) {
+        case AUDIO_FORMAT_AC4:
+        case AUDIO_FORMAT_AC4_L4:
+            return true;
+        default:
+            return false;
+        }
+        /* not reached */
     case AUDIO_FORMAT_LDAC:
         return true;
     case AUDIO_FORMAT_MAT:
@@ -1950,6 +1962,25 @@ static inline bool audio_is_valid_format(audio_format_t format)
     case AUDIO_FORMAT_DTS_HD_MA:
     case AUDIO_FORMAT_DTS_UHD_P2:
         return true;
+    case AUDIO_FORMAT_IAMF:
+        switch (format) {
+        case AUDIO_FORMAT_IAMF_SIMPLE_OPUS:
+        case AUDIO_FORMAT_IAMF_SIMPLE_AAC:
+        case AUDIO_FORMAT_IAMF_SIMPLE_PCM:
+        case AUDIO_FORMAT_IAMF_SIMPLE_FLAC:
+        case AUDIO_FORMAT_IAMF_BASE_OPUS:
+        case AUDIO_FORMAT_IAMF_BASE_AAC:
+        case AUDIO_FORMAT_IAMF_BASE_PCM:
+        case AUDIO_FORMAT_IAMF_BASE_FLAC:
+        case AUDIO_FORMAT_IAMF_BASE_ENHANCED_OPUS:
+        case AUDIO_FORMAT_IAMF_BASE_ENHANCED_AAC:
+        case AUDIO_FORMAT_IAMF_BASE_ENHANCED_PCM:
+        case AUDIO_FORMAT_IAMF_BASE_ENHANCED_FLAC:
+                return true;
+        default:
+                return false;
+        }
+        /* not reached */
     default:
         return false;
     }
@@ -1960,6 +1991,7 @@ static inline bool audio_is_iec61937_compatible(audio_format_t format)
     switch (format) {
     case AUDIO_FORMAT_AC3:         // IEC 61937-3:2017
     case AUDIO_FORMAT_AC4:         // IEC 61937-14:2017
+    case AUDIO_FORMAT_AC4_L4:      // IEC 61937-14:2017
     case AUDIO_FORMAT_E_AC3:       // IEC 61937-3:2017
     case AUDIO_FORMAT_E_AC3_JOC:   // IEC 61937-3:2017
     case AUDIO_FORMAT_MAT:         // IEC 61937-9:2017
@@ -2313,6 +2345,13 @@ inline const char* audio_channel_mask_to_string(audio_channel_mask_t channel_mas
     }
 }
 
+inline CONSTEXPR bool audio_output_is_mixed_output_flags(audio_output_flags_t flags) {
+    return (flags & (AUDIO_OUTPUT_FLAG_DIRECT | AUDIO_OUTPUT_FLAG_COMPRESS_OFFLOAD |
+            AUDIO_OUTPUT_FLAG_HW_AV_SYNC | AUDIO_OUTPUT_FLAG_IEC958_NONAUDIO |
+            AUDIO_OUTPUT_FLAG_DIRECT_PCM | AUDIO_OUTPUT_FLAG_GAPLESS_OFFLOAD |
+            AUDIO_OUTPUT_FLAG_BIT_PERFECT)) == 0;
+}
+
 __END_DECLS
 
 /**
diff --git a/audio/include/system/audio_effects/aidl_effects_utils.h b/audio/include/system/audio_effects/aidl_effects_utils.h
index b2b3c19d..2752ca78 100644
--- a/audio/include/system/audio_effects/aidl_effects_utils.h
+++ b/audio/include/system/audio_effects/aidl_effects_utils.h
@@ -15,12 +15,16 @@
  */
 
 #pragma once
-#include <optional>
-
 #include <aidl/android/hardware/audio/effect/AcousticEchoCanceler.h>
+#include <aidl/android/hardware/audio/effect/Capability.h>
 #include <aidl/android/hardware/audio/effect/DynamicsProcessing.h>
 #include <aidl/android/hardware/audio/effect/Parameter.h>
 #include <aidl/android/hardware/audio/effect/Range.h>
+#include <audio_utils/template_utils.h>
+#include <system/elementwise_op.h>
+
+#include <optional>
+#include <set>
 
 namespace aidl::android::hardware::audio::effect {
 
@@ -29,6 +33,15 @@ namespace aidl::android::hardware::audio::effect {
  */
 static constexpr int32_t kReopenSupportedVersion = 2;
 
+/**
+ * The first AIDL version that introduced the android.hardware.audio.effect.State.DRAINING state.
+ */
+static constexpr int32_t kDrainSupportedVersion = 3;
+/**
+ * The first AIDL version that support effect destroy at any state.
+ */
+static constexpr int32_t kDestroyAnyStateSupportedVersion = 3;
+
 /**
  * EventFlag to indicate that the client has written data to the FMQ, align with
  * EffectHalAidl.
@@ -120,4 +133,130 @@ static inline bool isRangeValid(const T& paramTag, const Capability& cap) {
   return true;
 }
 
-}  // namespace aidl::android::hardware::audio::effect
+/**
+ * @brief Clamps a parameter to its valid range with `android::audio_utils::elementwise_clamp`.
+ *
+ * @tparam RangeTag, `Range::dynamicsProcessing` for example.
+ * @tparam SpecificTag The effect specific tag in Parameter,
+ *         `Parameter::Specific::dynamicsProcessing` for example.
+ * @param param The parameter to clamp, `DynamicsProcessing` for example.
+ * @param cap The effect capability.
+ * @return Return the clamped parameter on success, `std::nullopt` on any failure.
+ */
+template <Range::Tag RangeTag, Parameter::Specific::Tag SpecificTag>
+[[nodiscard]]
+static inline std::optional<Parameter> clampParameter(const Parameter& param,
+                                                      const Capability& cap) {
+  if constexpr (RangeTag == Range::vendorExtension) return std::nullopt;
+
+  // field tag must matching to continue
+  if (param.getTag() != Parameter::specific) return std::nullopt;
+
+  Parameter::Specific specific = param.template get<Parameter::specific>();
+  auto effect = specific.template get<SpecificTag>();
+  std::optional<decltype(effect)> clamped = std::nullopt;
+
+  const Range& range = cap.range;
+  // no need to clamp if the range capability not defined
+  if (range.getTag() != RangeTag) return param;
+
+  const auto& ranges = range.template get<RangeTag>();
+  for (const auto& r : ranges) {
+    clamped = ::android::audio_utils::elementwise_clamp(effect, r.min, r.max);
+    if (clamped != std::nullopt) {
+      if (effect != clamped.value()) {
+        ALOGI("%s from \"%s\" to \"%s\"", __func__, effect.toString().c_str(),
+              clamped->toString().c_str());
+      }
+      break;
+    }
+  }
+
+  if (clamped == std::nullopt) return std::nullopt;
+  return Parameter::make<Parameter::specific>(
+      Parameter::Specific::make<SpecificTag>(clamped.value()));
+}
+
+/**
+ * Customized comparison for AIDL effect Range classes, the comparison is based on the tag value of
+ * the class.
+ * `VendorExtensionRange` is special because the underlying `VendorExtension` is not an AIDL union,
+ * so we compare the value directly.
+ */
+template <typename T>
+struct RangeTagLessThan {
+  bool operator()(const T& a, const T& b) const {
+    if constexpr (std::is_same_v<T, Range::VendorExtensionRange>) return a < b;
+    else return a.min.getTag() < b.min.getTag();
+  }
+};
+
+/**
+ * @brief Find the shared capability of two capabilities `cap1` and `cap2`.
+ * A shared range is the intersection part of these two capabilities.
+ *
+ * For example, for below capabilities:
+ * Capability cap1 = {.range = Range::make<Range::volume>({MAKE_RANGE(Volume, levelDb, -4800, 0)})};
+ * Capability cap2 = {.range = Range::make<Range::volume>({MAKE_RANGE(Volume, levelDb, -9600,
+ *                    -1600)})};
+ * Capability cap3 = {.range = Range::make<Range::volume>({MAKE_RANGE(Volume, levelDb, -800, 0)})};
+ *
+ * The shared capability of cap1 and cap2 is:
+ * Capability{.range = Range::make<Range::volume>({MAKE_RANGE(Volume, levelDb, -4800, -1600)})};
+ * The shared capability of cap1 and cap3 is:
+ * Capability{.range = Range::make<Range::volume>({MAKE_RANGE(Volume, levelDb, -800, 0)})};
+ * The shared capability of cap2 and cap3 is empty so `findSharedCapability` return std::nullopt.
+ *
+ * @param cap1 The first capability
+ * @param cap2 The second capability
+ * @return The shared capability on success, std::nullopt on any failure.
+ */
+ [[nodiscard]]
+static inline std::optional<Capability> findSharedCapability(
+    const Capability& cap1, const Capability& cap2) {
+  if (cap1.range.getTag() != cap2.range.getTag()) return std::nullopt;
+
+  std::optional<Capability> sharedCap = std::nullopt;
+  // RangeTag: tag id of the Effect range, `Range::dynamicsProcessing` for example.
+  // T: type of the effect range, `DynamicsProcessingRange` for example.
+  auto overlapRangeFinder = [&]<Range::Tag RangeTag, typename T>(
+                                const std::vector<T>& vec1,
+                                const std::vector<T>& vec2) {
+    if constexpr (RangeTag == Range::vendorExtension) {
+      sharedCap = {.range = Range::make<RangeTag>(vec1)};
+      return;
+    }
+
+    if (vec1.empty()) {
+      sharedCap = {.range = Range::make<RangeTag>(vec2)};
+      return;
+    }
+    if (vec2.empty()) {
+      sharedCap = {.range = Range::make<RangeTag>(vec1)};
+      return;
+    }
+
+    std::vector<T> sharedVec;
+    std::set<T, RangeTagLessThan<T>> set2{vec2.begin(), vec2.end()};
+    std::for_each(vec1.begin(), vec1.end(), [&](const auto& v1) {
+      const auto& v2 = set2.find(v1);
+      if (v2 != set2.end()) {
+        auto min = ::android::audio_utils::elementwise_max(v1.min, v2->min);
+        auto max = ::android::audio_utils::elementwise_min(v1.max, v2->max);
+        // only add range to vector when at least min or max is valid
+        if (min != std::nullopt || max != std::nullopt) {
+          using ElementType = decltype(v1.min);
+          sharedVec.emplace_back(T{.min = min.value_or(ElementType{}),
+                                   .max = max.value_or(ElementType{})});
+        }
+      }
+    });
+    if (!sharedVec.empty()) sharedCap = {.range = Range::make<RangeTag>(sharedVec)};
+  };
+
+  // find the underlying value in these two ranges, and call `overlapRangeFinder` lambda
+  ::android::audio_utils::aidl_union_op(overlapRangeFinder, cap1.range, cap2.range);
+  return sharedCap;
+}
+
+}  // namespace aidl::android::hardware::audio::effect
\ No newline at end of file
diff --git a/audio/include/system/audio_effects/audio_effects_utils.h b/audio/include/system/audio_effects/audio_effects_utils.h
index f619b5c7..b18ec04c 100644
--- a/audio/include/system/audio_effects/audio_effects_utils.h
+++ b/audio/include/system/audio_effects/audio_effects_utils.h
@@ -255,6 +255,26 @@ class EffectParamWriter : public EffectParamReader {
   size_t mValueWOffset = 0;
 };
 
+inline std::string ToString(const audio_uuid_t& uuid) {
+    char str[64];
+    snprintf(str, sizeof(str), "%08x-%04x-%04x-%04x-%02x%02x%02x%02x%02x%02x",
+             uuid.timeLow, uuid.timeMid, uuid.timeHiAndVersion, uuid.clockSeq,
+             uuid.node[0], uuid.node[1], uuid.node[2], uuid.node[3],
+             uuid.node[4], uuid.node[5]);
+    return str;
+}
+
+inline bool operator==(const audio_uuid_t& lhs, const audio_uuid_t& rhs) {
+  return lhs.timeLow == rhs.timeLow && lhs.timeMid == rhs.timeMid &&
+         lhs.timeHiAndVersion == rhs.timeHiAndVersion &&
+         lhs.clockSeq == rhs.clockSeq &&
+         std::memcmp(lhs.node, rhs.node, sizeof(lhs.node)) == 0;
+}
+
+inline bool operator!=(const audio_uuid_t& lhs, const audio_uuid_t& rhs) {
+    return !(lhs == rhs);
+}
+
 }  // namespace utils
 }  // namespace effect
 }  // namespace android
diff --git a/audio/include/system/audio_effects/effect_spatializer.h b/audio/include/system/audio_effects/effect_spatializer.h
index 2035d45f..a39bfb5d 100644
--- a/audio/include/system/audio_effects/effect_spatializer.h
+++ b/audio/include/system/audio_effects/effect_spatializer.h
@@ -94,6 +94,23 @@ typedef enum
     // silence. The effect can configure spatialization settings accordingly when this parameter is
     // received.
     SPATIALIZER_PARAM_INPUT_CHANNEL_MASK,
+
+    // Query the list of spatialized channel masks supported by the spatializer.
+    // A spatialized channel mask is one where each virtual speaker position is rendered
+    // at its corresponding virtual position, and is not downmixed with any other.
+    // For instance if a spatializer is only capable of distinct positions for 5.1, it would only
+    // return 5.1:
+    //    - the list wouldn't include 4.0, because that mask is "contained" within 5.1
+    //    - the list wouldn't include 7.1 (and so on) because the side and rear channels would be
+    //      downmixed together.
+    // Another example is a spatializer that can only spatialize up to 9 channels (not counting .1)
+    // and that supports 5.1.4, and 7.1.2, the list should include both.
+    // Note that the masks must be a subset of those returned
+    // by SPATIALIZER_PARAM_SUPPORTED_CHANNEL_MASKS
+    // Encoding of the results:
+    //  first uint32_t is the number of channel masks followed by the corresponding
+    //  number of audio_channel_mask_t.
+    SPATIALIZER_PARAM_SPATIALIZED_CHANNEL_MASKS,
 } t_virtualizer_stage_params;
 
 // See SpatializationLevel.aidl
diff --git a/audio/include/system/audio_effects/effect_uuid.h b/audio/include/system/audio_effects/effect_uuid.h
index 3f58332d..2766a32e 100644
--- a/audio/include/system/audio_effects/effect_uuid.h
+++ b/audio/include/system/audio_effects/effect_uuid.h
@@ -59,6 +59,8 @@ inline const char* const& kEffectTypeUuidEnvReverb =
     Descriptor::EFFECT_TYPE_UUID_ENV_REVERB;
 inline const char* const& kEffectTypeUuidEqualizer =
     Descriptor::EFFECT_TYPE_UUID_EQUALIZER;
+inline const char* const& kEffectTypeUuidEraser =
+    Descriptor::EFFECT_TYPE_UUID_ERASER;
 inline const char* const& kEffectTypeUuidHapticGenerator =
     Descriptor::EFFECT_TYPE_UUID_HAPTIC_GENERATOR;
 inline const char* const& kEffectTypeUuidLoudnessEnhancer =
@@ -89,6 +91,7 @@ constexpr char kEffectImplUuidDynamicsProcessing[] = "e0e6539b-1781-7261-676f-6d
 constexpr char kEffectImplUuidEqualizerSw[] = "0bed4300-847d-11df-bb17-0002a5d5c51b";
 constexpr char kEffectImplUuidEqualizerBundle[] = "ce772f20-847d-11df-bb17-0002a5d5c51b";
 constexpr char kEffectImplUuidEqualizerProxy[] = "c8e70ecd-48ca-456e-8a4f-0002a5d5c51b";
+constexpr char kEffectImplUuidEraserSw[] = "fa81ab46-588b-11ed-9b6a-0242ac120002";
 constexpr char kEffectImplUuidHapticGeneratorSw[] = "fa819110-588b-11ed-9b6a-0242ac120002";
 constexpr char kEffectImplUuidHapticGenerator[] = "97c4acd1-8b82-4f2f-832e-c2fe5d7a9931";
 constexpr char kEffectImplUuidLoudnessEnhancerSw[] = "fa819610-588b-11ed-9b6a-0242ac120002";
@@ -124,6 +127,7 @@ constexpr char kEffectImplUuidExtension[] = "fa81dd00-588b-11ed-9b6a-0242ac12000
     V(TypeUuidDownmix)                \
     V(TypeUuidDynamicsProcessing)     \
     V(TypeUuidEqualizer)              \
+    V(TypeUuidEraser)                 \
     V(TypeUuidExtension)              \
     V(TypeUuidHapticGenerator)        \
     V(TypeUuidLoudnessEnhancer)       \
@@ -149,6 +153,7 @@ constexpr char kEffectImplUuidExtension[] = "fa81dd00-588b-11ed-9b6a-0242ac12000
     V(ImplUuidEqualizerSw)              \
     V(ImplUuidEqualizerBundle)          \
     V(ImplUuidEqualizerProxy)           \
+    V(ImplUuidEraserSw)                 \
     V(ImplUuidExtension)                \
     V(ImplUuidHapticGeneratorSw)        \
     V(ImplUuidHapticGenerator)          \
diff --git a/audio/include/system/audio_policy.h b/audio/include/system/audio_policy.h
index c19de7ff..c6ed9eec 100644
--- a/audio/include/system/audio_policy.h
+++ b/audio/include/system/audio_policy.h
@@ -28,27 +28,35 @@ __BEGIN_DECLS
  * frameworks/base/include/media/AudioSystem.h
  */
 
+#define AUDIO_ENUM_QUOTE(x) #x
+#define AUDIO_ENUM_STRINGIFY(x) AUDIO_ENUM_QUOTE(x)
+#define AUDIO_DEFINE_ENUM_SYMBOL(symbol) symbol,
+#define AUDIO_DEFINE_STRINGIFY_CASE(symbol) case symbol: return AUDIO_ENUM_STRINGIFY(symbol);
+
 /* device categories used for audio_policy->set_force_use()
  * These must match the values in AudioSystem.java
  */
+#define AUDIO_POLICY_FORCE_LIST_DEF(V)                       \
+    V(AUDIO_POLICY_FORCE_NONE)                               \
+    V(AUDIO_POLICY_FORCE_SPEAKER)                            \
+    V(AUDIO_POLICY_FORCE_HEADPHONES)                         \
+    V(AUDIO_POLICY_FORCE_BT_SCO)                             \
+    V(AUDIO_POLICY_FORCE_BT_A2DP)                            \
+    V(AUDIO_POLICY_FORCE_WIRED_ACCESSORY)                    \
+    V(AUDIO_POLICY_FORCE_BT_CAR_DOCK)                        \
+    V(AUDIO_POLICY_FORCE_BT_DESK_DOCK)                       \
+    V(AUDIO_POLICY_FORCE_ANALOG_DOCK)                        \
+    V(AUDIO_POLICY_FORCE_DIGITAL_DOCK)                       \
+    V(AUDIO_POLICY_FORCE_NO_BT_A2DP)                         \
+    V(AUDIO_POLICY_FORCE_SYSTEM_ENFORCED)                    \
+    V(AUDIO_POLICY_FORCE_HDMI_SYSTEM_AUDIO_ENFORCED)         \
+    V(AUDIO_POLICY_FORCE_ENCODED_SURROUND_NEVER)             \
+    V(AUDIO_POLICY_FORCE_ENCODED_SURROUND_ALWAYS)            \
+    V(AUDIO_POLICY_FORCE_ENCODED_SURROUND_MANUAL)            \
+    V(AUDIO_POLICY_FORCE_BT_BLE)
+
 typedef enum {
-    AUDIO_POLICY_FORCE_NONE,
-    AUDIO_POLICY_FORCE_SPEAKER,
-    AUDIO_POLICY_FORCE_HEADPHONES,
-    AUDIO_POLICY_FORCE_BT_SCO,
-    AUDIO_POLICY_FORCE_BT_A2DP,
-    AUDIO_POLICY_FORCE_WIRED_ACCESSORY,
-    AUDIO_POLICY_FORCE_BT_CAR_DOCK,
-    AUDIO_POLICY_FORCE_BT_DESK_DOCK,
-    AUDIO_POLICY_FORCE_ANALOG_DOCK,
-    AUDIO_POLICY_FORCE_DIGITAL_DOCK,
-    AUDIO_POLICY_FORCE_NO_BT_A2DP, /* A2DP sink is not preferred to speaker or wired HS */
-    AUDIO_POLICY_FORCE_SYSTEM_ENFORCED,
-    AUDIO_POLICY_FORCE_HDMI_SYSTEM_AUDIO_ENFORCED,
-    AUDIO_POLICY_FORCE_ENCODED_SURROUND_NEVER,
-    AUDIO_POLICY_FORCE_ENCODED_SURROUND_ALWAYS,
-    AUDIO_POLICY_FORCE_ENCODED_SURROUND_MANUAL,
-    AUDIO_POLICY_FORCE_BT_BLE,
+    AUDIO_POLICY_FORCE_LIST_DEF(AUDIO_DEFINE_ENUM_SYMBOL)
 
     AUDIO_POLICY_FORCE_CFG_CNT,
     AUDIO_POLICY_FORCE_CFG_MAX = AUDIO_POLICY_FORCE_CFG_CNT - 1,
@@ -56,6 +64,16 @@ typedef enum {
     AUDIO_POLICY_FORCE_DEFAULT = AUDIO_POLICY_FORCE_NONE,
 } audio_policy_forced_cfg_t;
 
+inline const char* audio_policy_forced_cfg_to_string(audio_policy_forced_cfg_t t) {
+    switch (t) {
+    AUDIO_POLICY_FORCE_LIST_DEF(AUDIO_DEFINE_STRINGIFY_CASE)
+    default:
+        return "";
+    }
+}
+
+#undef AUDIO_POLICY_FORCE_LIST_DEF
+
 /* usages used for audio_policy->set_force_use()
  * These must match the values in AudioSystem.java
  */
@@ -111,6 +129,11 @@ typedef enum {
     DEVICE_ROLE_DISABLED = 2, /* devices cannot be used */
 } device_role_t;
 
+#undef AUDIO_DEFINE_STRINGIFY_CASE
+#undef AUDIO_DEFINE_ENUM_SYMBOL
+#undef AUDIO_ENUM_STRINGIFY
+#undef AUDIO_ENUM_QUOTE
+
 __END_DECLS
 
 #endif  // ANDROID_AUDIO_POLICY_CORE_H
diff --git a/audio/include/system/elementwise_op.h b/audio/include/system/elementwise_op.h
new file mode 100644
index 00000000..50d614da
--- /dev/null
+++ b/audio/include/system/elementwise_op.h
@@ -0,0 +1,510 @@
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
+#pragma once
+
+#ifdef __cplusplus
+
+#include <algorithm>
+#include <optional>
+#include <type_traits>
+#include <vector>
+
+#include <audio_utils/template_utils.h>
+#include <android/binder_enums.h>
+
+namespace android::audio_utils {
+
+using android::audio_utils::has_tag_and_get_tag_v;
+using android::audio_utils::is_specialization_v;
+using android::audio_utils::op_aggregate;
+
+/**
+ * Type of elements needs custom comparison for the elementwise ops.
+ * When `CustomOpElementTypes` evaluated to true, custom comparison is implemented in this header.
+ * When `CustomOpElementTypes` evaluated to false, fallback to std implementation.
+ */
+template <typename T>
+concept CustomOpElementTypes =
+    (std::is_class_v<T> && std::is_aggregate_v<T>) ||
+    is_specialization_v<T, std::vector> || has_tag_and_get_tag_v<T>;
+
+/**
+ * Find the underlying value of AIDL union objects, and run an `op` with the underlying values
+ */
+template <typename Op, typename T, std::size_t... Is, typename... Ts>
+void aidl_union_op_helper(Op&& op, std::index_sequence<Is...>, const T& first, const Ts&... rest) {
+  (([&]() -> bool {
+     const typename T::Tag TAG = static_cast<typename T::Tag>(Is);
+     if (((first.getTag() == TAG) && ... && (rest.getTag() == TAG))) {
+       // handle the case of a sub union class inside another union
+       using FieldType = decltype(first.template get<TAG>());
+       if constexpr (has_tag_and_get_tag_v<FieldType>) {
+         static constexpr std::size_t tagSize = std::ranges::distance(
+             ndk::enum_range<typename FieldType::Tag>().begin(),
+             ndk::enum_range<typename FieldType::Tag>().end());
+         return aidl_union_op_helper(op, std::make_index_sequence<tagSize>{},
+                                     first.template get<TAG>(),
+                                     rest.template get<TAG>()...);
+       } else {
+         op.template operator()<TAG>(first.template get<TAG>(), rest.template get<TAG>()...);
+         // exit the index sequence
+         return true;
+       }
+     } else {
+       return false;
+     }
+   }()) ||
+   ...);
+}
+
+// check if the class `T` is an AIDL union with `has_tag_and_get_tag_v`
+template <typename Op, typename T, typename... Ts>
+  requires(has_tag_and_get_tag_v<T> && ... && has_tag_and_get_tag_v<Ts>)
+void aidl_union_op(Op&& op, const T& first, const Ts&... rest) {
+  static constexpr std::size_t tagSize =
+      std::ranges::distance(ndk::enum_range<typename T::Tag>().begin(),
+                            ndk::enum_range<typename T::Tag>().end());
+  aidl_union_op_helper(op, std::make_index_sequence<tagSize>{}, first, rest...);
+}
+
+/**
+ * Utility functions for clamping values of different types within a specified
+ * range of [min, max]. Supported types are evaluated with
+ * `CustomOpElementTypes`.
+ *
+ * - For **structures**, each member is clamped individually and reassembled
+ *   after clamping.
+ * - For **vectors**, the `min` and `max` ranges (if defined) may have either
+ *   one element or match the size of the target vector. If `min`/`max` have
+ *   only one element, each target vector element is clamped within that range.
+ *   If `min`/`max` match the target's size, each target element is clamped
+ *   within the corresponding `min`/`max` elements.
+ * - For **AIDL union** class, `aidl_union_op` is used to find the underlying
+ *   value automatically first, and then do `elementwise_clamp` on the
+ *   underlying value.
+ * - For all other types, `std::clamp` is used directly, std::string
+ *   comparison and clamp is performed lexicographically.
+ *
+ * The maximum number of members supported in a structure is `kMaxStructMember`
+ * as defined in the template_utils.h header.
+ */
+
+/**
+ * @brief Clamp function for aggregate types (structs).
+ */
+template <typename T>
+  requires std::is_class_v<T> && std::is_aggregate_v<T>
+[[nodiscard]]
+std::optional<T> elementwise_clamp(const T& target, const T& min, const T& max);
+
+template <typename T>
+  requires has_tag_and_get_tag_v<T>
+[[nodiscard]]
+std::optional<T> elementwise_clamp(const T& target, const T& min, const T& max);
+
+/**
+ * @brief Clamp function for all other types, `std::clamp` is used.
+ */
+template <typename T>
+  requires(!CustomOpElementTypes<T>)
+[[nodiscard]]
+std::optional<T> elementwise_clamp(const T& target, const T& min, const T& max) {
+  if (min > max) {
+    return std::nullopt;
+  }
+  return std::clamp(target, min, max);
+}
+
+/**
+ * @brief Clamp function for vectors.
+ *
+ * Clamping each vector element within a specified range. The `min` and `max`
+ * vectors may have either one element or the same number of elements as the
+ * `target` vector.
+ *
+ * - If `min` or `max` contain only one element, each element in `target` is
+ *   clamped by this single value.
+ * - If `min` or `max` match `target` in size, each element in `target` is
+ *   clamped by the corresponding elements in `min` and `max`.
+ * - If size of `min` or `max` vector is neither 1 nor same size as `target`,
+ *   the range will be considered as invalid, and `std::nullopt` will be
+ *   returned.
+ *
+ * Some examples:
+ * std::vector<int> target({3, 0, 5, 2});
+ * std::vector<int> min({1});
+ * std::vector<int> max({3});
+ * elementwise_clamp(target, min, max) result will be std::vector({3, 1, 3, 2})
+ *
+ * std::vector<int> target({3, 0, 5, 2});
+ * std::vector<int> min({1, 2, 3, 4});
+ * std::vector<int> max({3, 4, 5, 6});
+ * elementwise_clamp(target, min, max) result will be std::vector({3, 2, 5, 4})
+ *
+ * std::vector<int> target({3, 0, 5, 2});
+ * std::vector<int> min({});
+ * std::vector<int> max({3, 4});
+ * elementwise_clamp(target, min, max) result will be std::nullopt
+ */
+template <typename T>
+  requires is_specialization_v<T, std::vector>
+[[nodiscard]]
+std::optional<T> elementwise_clamp(const T& target, const T& min, const T& max) {
+  using ElemType = typename T::value_type;
+
+  const size_t min_size = min.size(), max_size = max.size(),
+               target_size = target.size();
+  if (min_size == 0 || max_size == 0 || target_size == 0) {
+    return std::nullopt;
+  }
+
+  T result;
+  result.reserve(target_size);
+
+  if (min_size == 1 && max_size == 1) {
+    const ElemType clamp_min = min[0], clamp_max = max[0];
+    for (size_t i = 0; i < target_size; ++i) {
+      auto clamped_elem = elementwise_clamp(target[i], clamp_min, clamp_max);
+      if (clamped_elem) {
+        result.emplace_back(*clamped_elem);
+      } else {
+        return std::nullopt;
+      }
+    }
+  } else if (min_size == target_size && max_size == target_size) {
+    for (size_t i = 0; i < target_size; ++i) {
+      auto clamped_elem = elementwise_clamp(target[i], min[i], max[i]);
+      if (clamped_elem) {
+        result.emplace_back(*clamped_elem);
+      } else {
+        return std::nullopt;
+      }
+    }
+  } else if (min_size == 1 && max_size == target_size) {
+    const ElemType clamp_min = min[0];
+    for (size_t i = 0; i < target_size; ++i) {
+      auto clamped_elem = elementwise_clamp(target[i], clamp_min, max[i]);
+      if (clamped_elem) {
+        result.emplace_back(*clamped_elem);
+      } else {
+        return std::nullopt;
+      }
+    }
+  } else if (min_size == target_size && max_size == 1) {
+    const ElemType clamp_max = max[0];
+    for (size_t i = 0; i < target_size; ++i) {
+      auto clamped_elem = elementwise_clamp(target[i], min[i], clamp_max);
+      if (clamped_elem) {
+        result.emplace_back(*clamped_elem);
+      } else {
+        return std::nullopt;
+      }
+    }
+  } else {
+    // incompatible size
+    return std::nullopt;
+  }
+
+  return result;
+}
+
+/**
+ * @brief Clamp function for class and aggregate type (structs).
+ *
+ * Uses `opAggregate` with elementwise_clamp_op to perform clamping on each member of the
+ * aggregate type `T`, the max number of supported members in `T` is
+ * `kMaxStructMember`.
+ */
+template <typename T>
+  requires std::is_class_v<T> && std::is_aggregate_v<T>
+[[nodiscard]]
+std::optional<T> elementwise_clamp(const T& target, const T& min, const T& max) {
+  const auto elementwise_clamp_op = [](const auto& a, const auto& b, const auto& c) {
+    return elementwise_clamp(a, b, c);
+  };
+  return op_aggregate(elementwise_clamp_op, target, min, max);
+}
+
+template <typename T>
+  requires has_tag_and_get_tag_v<T>
+[[nodiscard]]
+std::optional<T> elementwise_clamp(const T& target, const T& min, const T& max) {
+  std::optional<T> ret = std::nullopt;
+
+  auto elementwise_clamp_op = [&]<typename T::Tag TAG, typename P>(
+                          const P& p1, const P& p2, const P& p3) {
+    auto p = elementwise_clamp(p1, p2, p3);
+    if (!p) return;
+    ret = T::template make<TAG>(*p);
+  };
+
+  aidl_union_op(elementwise_clamp_op, target, min, max);
+  return ret;
+}
+
+/**
+ * Utility functions to determine the element-wise min/max of two values with
+ * same type. The `elementwise_min` function accepts two inputs and return
+ * the element-wise min of them, while the `elementwise_max` function
+ * calculates the element-wise max.
+ *
+ * - For **vectors**, the two input vectors may have either `0`, `1`, or `n`
+ *   elements. If both input vectors have more than one element, their sizes
+ *   must match. If either input vector has only one element, it is compared
+ *   with each element of the other input vector.
+ * - For **structures (aggregate types)**, each element field is compared
+ *   individually, and the final result is reassembled from the element field
+ *   comparison result.
+ * - For **AIDL union** class, `aidl_union_op` is used to find the underlying
+ *   value automatically first, and then do elementwise min/max on the
+ *   underlying value.
+ * - For all other types, `std::min`/`std::max` is used directly, std::string
+ *   comparison and clamp is performed lexicographically.
+ *
+ * The maximum number of element fields supported in a structure is defined by
+ * `android::audio_utils::kMaxStructMember` as defined in the `template_utils.h`
+ * header.
+ */
+
+template <typename T>
+  requires std::is_class_v<T> && std::is_aggregate_v<T>
+[[nodiscard]]
+std::optional<T> elementwise_min(const T& a, const T& b);
+
+template <typename T>
+  requires has_tag_and_get_tag_v<T>
+[[nodiscard]]
+std::optional<T> elementwise_min(const T& a, const T& b);
+
+template <typename T>
+  requires std::is_class_v<T> && std::is_aggregate_v<T>
+[[nodiscard]]
+std::optional<T> elementwise_max(const T& a, const T& b);
+
+template <typename T>
+  requires has_tag_and_get_tag_v<T>
+[[nodiscard]]
+std::optional<T> elementwise_max(const T& a, const T& b);
+
+/**
+ * @brief Determines the min/max for all other type values.
+ *
+ * @tparam T The target type.
+ * @param a The first value.
+ * @param b The second value.
+ * @return The min/max of the two inputs.
+ *
+ * Example:
+ * int a = 3;
+ * int b = 5;
+ * auto result = elementwise_min(a, b);  // result will be 3
+ * auto result = elementwise_max(a, b);  // result will be 5
+ */
+template <typename T>
+  requires(!CustomOpElementTypes<T>)
+[[nodiscard]]
+std::optional<T> elementwise_min(const T& a, const T& b) {
+  return std::min(a, b);
+}
+
+template <typename T>
+  requires(!CustomOpElementTypes<T>)
+[[nodiscard]]
+std::optional<T> elementwise_max(const T& a, const T& b) {
+  return std::max(a, b);
+}
+
+/**
+ * @brief Determines the element-wise min/max of two vectors by comparing
+ * each corresponding element.
+ *
+ * This function calculates the element-wise min/max of two input vectors. The
+ * valid sizes for input vectors `a` and `b` can be 0, 1, or `n` (where `n >
+ * 1`). If both `a` and `b` contain more than one element, their sizes must be
+ * equal. If either vector has only one element, that value will be compared
+ * with each element of the other vector.
+ *
+ * Some examples:
+ * std::vector<int> a({1, 2, 3, 4});
+ * std::vector<int> b({3, 4, 5, 0});
+ * elementwise_min(a, b) result will be std::vector({1, 2, 3, 0})
+ * elementwise_max(a, b) result will be std::vector({3, 4, 5, 4})
+ *
+ * std::vector<int> a({1});
+ * std::vector<int> b({3, 4, 5, 0});
+ * elementwise_min(a, b) result will be std::vector({1, 1, 1, 0})
+ * elementwise_max(a, b) result will be std::vector({3, 4, 5, 1})
+ *
+ * std::vector<int> a({1, 2, 3});
+ * std::vector<int> b({});
+ * elementwise_min(a, b) result will be std::vector({})
+ * elementwise_max(a, b) result will be std::vector({1, 2, 3})
+ *
+ * std::vector<int> a({1, 2, 3, 4});
+ * std::vector<int> b({3, 4, 0});
+ * elementwise_min(a, b) and elementwise_max(a, b) result will be std::nullopt
+ *
+ * @tparam T The vector type.
+ * @param a The first vector.
+ * @param b The second vector.
+ * @return A vector representing the element-wise min/max, or `std::nullopt` if
+ * sizes are incompatible.
+ */
+template <typename T>
+  requires is_specialization_v<T, std::vector>
+[[nodiscard]]
+std::optional<T> elementwise_min(const T& a, const T& b) {
+  T result;
+  const size_t a_size = a.size(), b_size = b.size();
+  if (a_size == 0 || b_size == 0) {
+    return result;
+  }
+
+  if (a_size == b_size) {
+    for (size_t i = 0; i < a_size; ++i) {
+      auto lower_elem = elementwise_min(a[i], b[i]);
+      if (lower_elem) {
+        result.emplace_back(*lower_elem);
+      }
+    }
+  } else if (a_size == 1) {
+    for (size_t i = 0; i < b_size; ++i) {
+      auto lower_elem = elementwise_min(a[0], b[i]);
+      if (lower_elem) {
+        result.emplace_back(*lower_elem);
+      }
+    }
+  } else if (b_size == 1) {
+    for (size_t i = 0; i < a_size; ++i) {
+      auto lower_elem = elementwise_min(a[i], b[0]);
+      if (lower_elem) {
+        result.emplace_back(*lower_elem);
+      }
+    }
+  } else {
+    // incompatible size
+    return std::nullopt;
+  }
+
+  return result;
+}
+
+template <typename T>
+  requires is_specialization_v<T, std::vector>
+[[nodiscard]]
+std::optional<T> elementwise_max(const T& a, const T& b) {
+  T result;
+  const size_t a_size = a.size(), b_size = b.size();
+  if (a_size == 0) {
+    result = b;
+  } else if (b_size == 0) {
+    result = a;
+  } else if (a_size == b_size) {
+    for (size_t i = 0; i < a_size; ++i) {
+      auto upper_elem = elementwise_max(a[i], b[i]);
+      if (upper_elem) result.emplace_back(*upper_elem);
+    }
+  } else if (a_size == 1) {
+    for (size_t i = 0; i < b_size; ++i) {
+      auto upper_elem = elementwise_max(a[0], b[i]);
+      if (upper_elem) result.emplace_back(*upper_elem);
+    }
+  } else if (b_size == 1) {
+    for (size_t i = 0; i < a_size; ++i) {
+      auto upper_elem = elementwise_max(a[i], b[0]);
+      if (upper_elem) result.emplace_back(*upper_elem);
+    }
+  } else {
+    // incompatible size
+    return std::nullopt;
+  }
+
+  return result;
+}
+
+/**
+ * @brief Determines the element-wise min/max of two aggregate type values
+ * by comparing each corresponding element.
+ *
+ * @tparam T The type of the aggregate values.
+ * @param a The first aggregate.
+ * @param b The second aggregate.
+ * @return A new aggregate representing the element-wise min/max of the two
+ * inputs, or `std::nullopt` if the element-wise comparison fails.
+ *
+ * Example:
+ * struct Point {
+ *   int x;
+ *   int y;
+ * };
+ * Point p1{3, 5};
+ * Point p2{4, 2};
+ * auto result = elementwise_min(p1, p2);  // result will be Point{3, 2}
+ * auto result = elementwise_max(p1, p2);  // result will be Point{4, 5}
+ */
+template <typename T>
+  requires std::is_class_v<T> && std::is_aggregate_v<T>
+[[nodiscard]]
+std::optional<T> elementwise_min(const T& a, const T& b) {
+  const auto elementwise_min_op = [](const auto& a_member, const auto& b_member) {
+    return elementwise_min(a_member, b_member);
+  };
+  return op_aggregate(elementwise_min_op, a, b);
+}
+
+template <typename T>
+  requires std::is_class_v<T> && std::is_aggregate_v<T>
+[[nodiscard]]
+std::optional<T> elementwise_max(const T& a, const T& b) {
+  const auto elementwise_max_op = [](const auto& a_member, const auto& b_member) {
+    return elementwise_max(a_member, b_member);
+  };
+  return op_aggregate(elementwise_max_op, a, b);
+}
+
+template <typename T>
+  requires has_tag_and_get_tag_v<T>
+[[nodiscard]]
+std::optional<T> elementwise_min(const T& a, const T& b) {
+  std::optional<T> ret = std::nullopt;
+  auto elementwise_min_op = [&]<typename T::Tag TAG, typename P>(const P& p1, const P& p2) {
+    auto p = elementwise_min(p1, p2);
+    if (!p) return;
+    ret = T::template make<TAG>(*p);
+  };
+  aidl_union_op(elementwise_min_op, a, b);
+  return ret;
+}
+
+// handle the case of a sub union class inside another union
+template <typename T>
+  requires has_tag_and_get_tag_v<T>
+[[nodiscard]]
+std::optional<T> elementwise_max(const T& a, const T& b) {
+  std::optional<T> ret = std::nullopt;
+  auto elementwise_max_op = [&]<typename T::Tag TAG, typename P>(const P& p1, const P& p2) {
+    auto p = elementwise_max(p1, p2);
+    if (!p) return;
+    ret = T::template make<TAG>(*p);
+  };
+  aidl_union_op(elementwise_max_op, a, b);
+  return ret;
+}
+
+}  // namespace android::audio_utils
+
+#endif  // __cplusplus
\ No newline at end of file
diff --git a/audio_utils/Android.bp b/audio_utils/Android.bp
index 9ffb966b..33fb04ee 100644
--- a/audio_utils/Android.bp
+++ b/audio_utils/Android.bp
@@ -17,6 +17,7 @@ cc_defaults {
     cflags: [
         "-Wall",
         "-Werror",
+        "-Wthread-safety",
     ],
 }
 
@@ -48,6 +49,7 @@ cc_library {
         "MelProcessor.cpp",
         "Metadata.cpp",
         "PowerLog.cpp",
+        "StringUtils.cpp",
         "channels.cpp",
         "fifo.cpp",
         "fifo_index.cpp",
diff --git a/audio_utils/MelProcessor.cpp b/audio_utils/MelProcessor.cpp
index 768578c6..afcdaed3 100644
--- a/audio_utils/MelProcessor.cpp
+++ b/audio_utils/MelProcessor.cpp
@@ -26,7 +26,9 @@
 #include <audio_utils/MelProcessor.h>
 
 #include <audio_utils/format.h>
+#include <audio_utils/mutex.h>
 #include <audio_utils/power.h>
+#include <chrono>
 #include <log/log.h>
 #include <sstream>
 #include <unordered_map>
@@ -126,10 +128,8 @@ MelProcessor::MelProcessor(uint32_t sampleRate,
       mFloatSamples(mFramesPerMelValue * mChannelCount),
       mCurrentChannelEnergy(channelCount, 0.0f),
       mMelValues(maxMelsCallback),
-      mCurrentIndex(0),
       mDeviceId(deviceId),
-      mRs2UpperBound(rs2Value),
-      mCurrentSamples(0)
+      mRs2UpperBound(rs2Value)
 {
     createBiquads_l();
 
@@ -212,6 +212,20 @@ void MelProcessor::resume()
     mPaused = false;
 }
 
+void MelProcessor::drain()
+{
+    ALOGV("%s", __func__);
+    mMelWorker.drain();
+}
+
+void MelProcessor::drainAndWait() {
+    constexpr size_t kPollMs = 8;
+    while (!mMelWorker.ringBufferIsEmpty()) {
+        drain();
+        std::this_thread::sleep_for(std::chrono::milliseconds(kPollMs));
+    }
+}
+
 void MelProcessor::updateAudioFormat(uint32_t sampleRate,
                                      uint32_t channelCount,
                                      audio_format_t format) {
@@ -298,7 +312,7 @@ void MelProcessor::addMelValue_l(float mel) {
     }
 
     if (notifyWorker) {
-        mMelWorker.mCondVar.notify_one();
+        mMelWorker.notify();
     }
 }
 
@@ -363,7 +377,7 @@ void MelProcessor::setAttenuation(float attenuationDB) {
 
 void MelProcessor::onLastStrongRef(const void* id __attribute__((unused))) {
    mMelWorker.stop();
-   ALOGV("%s: Stopped thread: %s for device %d", __func__, mMelWorker.mThreadName.c_str(),
+   ALOGV("%s: Stopped thread: %s for device %d", __func__, mMelWorker.getThreadName().c_str(),
          mDeviceId.load());
 }
 
@@ -380,35 +394,38 @@ void MelProcessor::MelWorker::run() {
         androidSetThreadName(mThreadName.c_str());
         ALOGV("%s::run(): Started thread", mThreadName.c_str());
 
+        audio_utils::unique_lock l(mCondVarMutex);
         while (true) {
-            std::unique_lock l(mCondVarMutex);
             if (mStopRequested) {
                 return;
             }
-            mCondVar.wait(l, [&] { return (mRbReadPtr != mRbWritePtr) || mStopRequested; });
-
-            while (mRbReadPtr != mRbWritePtr && !mStopRequested) {
+            mCondVar.wait(l);
+            while (mRbReadPtr != mRbWritePtr && !mStopRequested) { // load-acquire mRbWritePtr
                 ALOGV("%s::run(): new callbacks, rb idx read=%zu, write=%zu",
                       mThreadName.c_str(),
                       mRbReadPtr.load(),
                       mRbWritePtr.load());
-                auto callback = mCallback.promote();
+                const auto callback = mCallback.promote();
                 if (callback == nullptr) {
                     ALOGW("%s::run(): MelCallback is null, quitting MelWorker",
                           mThreadName.c_str());
                     return;
                 }
 
-                MelCallbackData data = mCallbackRingBuffer[mRbReadPtr];
+                const MelCallbackData& data = mCallbackRingBuffer[mRbReadPtr];
                 if (data.mMel != 0.f) {
+                    l.unlock();
                     callback->onMomentaryExposure(data.mMel, data.mPort);
+                    l.lock();
                 } else if (data.mMelsSize != 0) {
+                    l.unlock();
                     callback->onNewMelValues(data.mMels, 0, data.mMelsSize,
                                              data.mPort, /*attenuated=*/true);
+                    l.lock();
                 } else {
                     ALOGE("%s::run(): Invalid MEL data. Skipping callback", mThreadName.c_str());
                 }
-                incRingBufferIndex(mRbReadPtr);
+                mRbReadPtr = nextRingBufferIndex(mRbReadPtr);  // single reader updates this.
             }
         }
     });
@@ -427,6 +444,11 @@ void MelProcessor::MelWorker::stop() {
     }
 }
 
+void MelProcessor::MelWorker::drain() {
+    std::lock_guard l(mCondVarMutex);
+    mCondVar.notify_one();
+}
+
 void MelProcessor::MelWorker::momentaryExposure(float mel, audio_port_handle_t port) {
     ALOGV("%s", __func__);
 
@@ -442,7 +464,7 @@ void MelProcessor::MelWorker::momentaryExposure(float mel, audio_port_handle_t p
     mCallbackRingBuffer[mRbWritePtr].mMelsSize = 0;
     mCallbackRingBuffer[mRbWritePtr].mPort = port;
 
-    incRingBufferIndex(mRbWritePtr);
+    mRbWritePtr = nextRingBufferIndex(mRbWritePtr);  // single writer, store-release.
 }
 
 void MelProcessor::MelWorker::newMelValues(const std::vector<float>& mels,
@@ -463,23 +485,11 @@ void MelProcessor::MelWorker::newMelValues(const std::vector<float>& mels,
     mCallbackRingBuffer[mRbWritePtr].mMel = 0.f;
     mCallbackRingBuffer[mRbWritePtr].mPort = port;
 
-    incRingBufferIndex(mRbWritePtr);
+    mRbWritePtr = nextRingBufferIndex(mRbWritePtr);  // single writer, store-release.
 }
 
 bool MelProcessor::MelWorker::ringBufferIsFull() const {
-    size_t curIdx = mRbWritePtr.load();
-    size_t nextIdx = curIdx >= kRingBufferSize - 1 ? 0 : curIdx + 1;
-
-    return nextIdx == mRbReadPtr;
-}
-
-void MelProcessor::MelWorker::incRingBufferIndex(std::atomic_size_t& idx) {
-    size_t nextIdx;
-    size_t expected;
-    do {
-        expected = idx.load();
-        nextIdx = expected >= kRingBufferSize - 1 ? 0 : expected + 1;
-    } while (!idx.compare_exchange_strong(expected, nextIdx));
+    return nextRingBufferIndex(mRbWritePtr) == mRbReadPtr;
 }
 
 }   // namespace android
diff --git a/audio_utils/StringUtils.cpp b/audio_utils/StringUtils.cpp
new file mode 100644
index 00000000..0f875bf7
--- /dev/null
+++ b/audio_utils/StringUtils.cpp
@@ -0,0 +1,200 @@
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
+#include <audio_utils/StringUtils.h>
+#include <charconv>
+
+namespace android::audio_utils::stringutils {
+
+// Moved from frameworks/av/services/mediametrics
+
+std::string tokenizer(std::string::const_iterator& it,
+                      const std::string::const_iterator& end, const char* reserved)
+{
+    // consume leading white space
+    for (; it != end && std::isspace(*it); ++it);
+    if (it == end) return {};
+
+    auto start = it;
+    // parse until we hit a reserved keyword or space
+    if (strchr(reserved, *it)) return {start, ++it};
+    for (;;) {
+        ++it;
+        if (it == end || std::isspace(*it) || strchr(reserved, *it)) return {start, it};
+    }
+}
+
+std::vector<std::string> split(const std::string& flags, const char* delim)
+{
+    std::vector<std::string> result;
+    for (auto it = flags.begin(); ; ) {
+        auto flag = tokenizer(it, flags.end(), delim);
+        if (flag.empty() || !std::isalnum(flag[0])) return result;
+        result.emplace_back(std::move(flag));
+
+        // look for the delimiter and discard
+        auto token = tokenizer(it, flags.end(), delim);
+        if (token.size() != 1 || strchr(delim, token[0]) == nullptr) return result;
+    }
+}
+
+bool parseVector(const std::string& str, std::vector<int32_t>* vector) {
+    std::vector<int32_t> values;
+    const char* p = str.c_str();
+    const char* last = p + str.size();
+    while (p != last) {
+        if (*p == ',' || *p == '{' || *p == '}') {
+            p++;
+        }
+        int32_t value = -1;
+        auto [ptr, error] = std::from_chars(p, last, value);
+        if (error == std::errc::invalid_argument || error == std::errc::result_out_of_range) {
+            return false;
+        }
+        p = ptr;
+        values.push_back(value);
+    }
+    *vector = std::move(values);
+    return true;
+}
+
+std::vector<std::pair<std::string, std::string>>
+getDeviceAddressPairs(const std::string& devices)
+{
+    std::vector<std::pair<std::string, std::string>> result;
+
+    // Currently, the device format is
+    //
+    // devices = device_addr OR device_addr|devices
+    // device_addr = device OR (device, addr)
+    //
+    // EXAMPLE:
+    // device1|(device2, addr2)|...
+
+    static constexpr char delim[] = "()|,";
+    for (auto it = devices.begin(); ; ) {
+        std::string address;
+        std::string device = tokenizer(it, devices.end(), delim);
+        if (device.empty()) return result;
+        if (device == "(") {  // it is a pair otherwise we consider it a device
+            device = tokenizer(it, devices.end(), delim); // get actual device
+            auto token = tokenizer(it, devices.end(), delim);
+            if (token != ",") return result;  // malformed, must have a comma
+
+            // special handling here for empty addresses
+            address = tokenizer(it, devices.end(), delim);
+            if (address.empty()) return result;
+            if (address == ")") {  // no address, just the ")"
+                address.clear();
+            } else {
+                token = tokenizer(it, devices.end(), delim);
+                if (token != ")") return result;
+            }
+        }
+        // misaligned token, device must start alphanumeric.
+        if (!std::isalnum(device[0])) return result;
+
+        result.emplace_back(std::move(device), std::move(address));
+
+        auto token = tokenizer(it, devices.end(), delim);
+        if (token != "|") return result;  // this includes end of string detection
+    }
+}
+
+std::string changeNameFormat(const std::string& name, NameFormat format) {
+    std::string s;
+
+    char prevAlphaNum = 0;  // last alphanum encountered, 0 starts new name.
+    for (auto it = name.begin(); it != name.end(); ++it) {
+
+        // underscores
+        bool prevUnderscore = false;
+        bool firstCharOfWord = false;
+        if (*it == '_') {  // handle multiple _.
+            do {
+                ++it;
+                if (it == name.end()) return s;  // trailing '_' stripped.
+            } while (*it == '_');
+            firstCharOfWord = true;
+            prevUnderscore = true;
+        }
+
+        // a digit
+        if (isdigit(*it)) {
+            if (prevUnderscore &&
+                    ((format == NameFormat::kFormatLowerSnakeCase
+                            || format == NameFormat::kFormatUpperSnakeCase) // preserve underscore
+                     || (prevAlphaNum != 0 && isdigit(prevAlphaNum)))) {
+                s.push_back('_');  // do not concatenate 899_100 -> 899100, leave _
+            }
+            s.push_back(*it);
+            prevAlphaNum = *it;
+            continue;
+        }
+
+        // a non-alpha sequence. we copy as if '.' or ' '
+        if (!isalpha(*it)) {
+            s.push_back(*it);
+            prevAlphaNum = 0;
+            continue;
+        }
+
+        // an alpha char - determine whether to convert to upper or lower case.
+        if (!firstCharOfWord) {
+            if (prevAlphaNum == 0 || (prevAlphaNum
+                    && (islower(prevAlphaNum) || isdigit(prevAlphaNum)) && isupper(*it))) {
+                firstCharOfWord = true;
+            }
+        }
+        switch (format) {
+            case NameFormat::kFormatLowerCamelCase:
+                if (firstCharOfWord && prevAlphaNum != 0) {
+                    s.push_back(toupper(*it));
+                } else {
+                    s.push_back(tolower(*it));
+                }
+                break;
+            case NameFormat::kFormatUpperCamelCase:
+                if (firstCharOfWord) {
+                    s.push_back(toupper(*it));
+                } else {
+                    s.push_back(tolower(*it));
+                }
+                break;
+            case NameFormat::kFormatLowerSnakeCase:
+                if (prevUnderscore || // preserve underscore
+                        (firstCharOfWord && prevAlphaNum != 0 && !isdigit(prevAlphaNum))) {
+                    s.push_back('_');
+                }
+                s.push_back(tolower(*it));
+                break;
+            case NameFormat::kFormatUpperSnakeCase:
+                if (prevUnderscore || // preserve underscore
+                        (firstCharOfWord && prevAlphaNum != 0 && !isdigit(prevAlphaNum))) {
+                    s.push_back('_');
+                }
+                s.push_back(toupper(*it));
+                break;
+           default:
+                s.push_back(*it);
+                break;
+        }
+        prevAlphaNum = *it;
+    }
+    return s;
+}
+
+} // namespace android::audio_utils::stringutils
diff --git a/audio_utils/benchmarks/audio_mutex_benchmark.cpp b/audio_utils/benchmarks/audio_mutex_benchmark.cpp
index 5c0cdf85..4937e17e 100644
--- a/audio_utils/benchmarks/audio_mutex_benchmark.cpp
+++ b/audio_utils/benchmarks/audio_mutex_benchmark.cpp
@@ -499,7 +499,7 @@ static void BM_StdMutexBlockingConditionVariable(benchmark::State &state) {
 BENCHMARK(BM_StdMutexBlockingConditionVariable)->Threads(THREADS);
 
 MutexBlockingConditionVariable<AudioMutex,
-        android::audio_utils::unique_lock,
+        android::audio_utils::unique_lock<AudioMutex>,
         android::audio_utils::condition_variable> CvAu;
 
 static void BM_AudioUtilsMutexBlockingConditionVariable(benchmark::State &state) {
@@ -509,7 +509,7 @@ static void BM_AudioUtilsMutexBlockingConditionVariable(benchmark::State &state)
 BENCHMARK(BM_AudioUtilsMutexBlockingConditionVariable)->Threads(THREADS);
 
 MutexBlockingConditionVariable<AudioPIMutex,
-        android::audio_utils::unique_lock,
+        android::audio_utils::unique_lock<AudioPIMutex>,
         android::audio_utils::condition_variable> CvAuPI;
 
 static void BM_AudioUtilsPIMutexBlockingConditionVariable(benchmark::State &state) {
diff --git a/audio_utils/include/audio_utils/CommandThread.h b/audio_utils/include/audio_utils/CommandThread.h
index b82188f4..092fb78b 100644
--- a/audio_utils/include/audio_utils/CommandThread.h
+++ b/audio_utils/include/audio_utils/CommandThread.h
@@ -19,7 +19,7 @@
 #include <deque>
 #include <mutex>
 #include <thread>
-#include <utils/Mutex.h> // has thread safety annotations
+#include <audio_utils/mutex.h>
 
 namespace android::audio_utils {
 
@@ -96,8 +96,8 @@ private:
     std::deque<std::pair<std::string, std::function<void()>>> mCommands GUARDED_BY(mMutex);
     bool mQuit GUARDED_BY(mMutex) = false;
 
-    void threadLoop() NO_THREAD_SAFETY_ANALYSIS {
-        std::unique_lock ul(mMutex);
+    void threadLoop() {
+        audio_utils::unique_lock ul(mMutex);
         while (!mQuit) {
             if (!mCommands.empty()) {
                 auto name = std::move(mCommands.front().first);
diff --git a/audio_utils/include/audio_utils/MelProcessor.h b/audio_utils/include/audio_utils/MelProcessor.h
index 86953fb0..2d4adb89 100644
--- a/audio_utils/include/audio_utils/MelProcessor.h
+++ b/audio_utils/include/audio_utils/MelProcessor.h
@@ -113,7 +113,8 @@ public:
     audio_port_handle_t getDeviceId();
 
     /** Update the format to use for the input frames to process. */
-    void updateAudioFormat(uint32_t sampleRate, uint32_t channelCount, audio_format_t newFormat);
+    void updateAudioFormat(uint32_t sampleRate, uint32_t channelCount, audio_format_t newFormat)
+            EXCLUDES(mLock);
 
     /**
      * \brief Computes the MEL values for the given buffer and triggers a
@@ -137,6 +138,13 @@ public:
     /** Resumes the processing of MEL values. */
     void resume();
 
+    /** Signals to drain the remaining mel data.  Does not wait. */
+    void drain();
+
+    /** Signals to drain the remaining mel data and waits for completion.
+     * If more data is being delivered, wait time may be long. */
+    void drainAndWait();
+
     /**
      * Sets the given attenuation for the MEL calculation. This can be used when
      * the audio framework is operating in absolute volume mode.
@@ -170,31 +178,51 @@ private:
               mThreadName(std::move(threadName)),
               mCallbackRingBuffer(kRingBufferSize) {};
 
-        void run();
+        void run() EXCLUDES(mCondVarMutex);
 
         // blocks until the MelWorker thread is stopped
-        void stop();
+        void stop() EXCLUDES(mCondVarMutex);
 
-        // callback methods for new MEL values
+        // Signals the MelWorker to wake up to process
+        // any remaining queued data.  Like notify() but with lock held.
+        void drain() EXCLUDES(mCondVarMutex);
+
+       // callback methods for new MEL values
         void momentaryExposure(float mel, audio_port_handle_t port);
         void newMelValues(const std::vector<float>& mels,
                           size_t melsSize,
                           audio_port_handle_t port);
 
-        static void incRingBufferIndex(std::atomic_size_t& idx);
+        std::string getThreadName() const { return mThreadName; }
+
+        void notify() { mCondVar.notify_one(); }
+
+        bool ringBufferIsEmpty() const {  return mRbReadPtr == mRbWritePtr; }
+
+    private:
+        static size_t nextRingBufferIndex(size_t idx) {
+            return idx >= kRingBufferSize - 1 ? 0 : idx + 1;
+        }
         bool ringBufferIsFull() const;
 
         const wp<MelCallback> mCallback;
         const std::string mThreadName;
-        std::vector<MelCallbackData> mCallbackRingBuffer GUARDED_BY(mCondVarMutex);
+        std::mutex mCondVarMutex;
+        std::condition_variable mCondVar;
 
+        // mRbReadPtr, mRbWritePtr, mCallbackRingBuffer form a lock free queue.
+        std::vector<MelCallbackData> mCallbackRingBuffer;  // reader / writer on different indices
+
+        // reader updated only, aligned to cache line.
+        alignas(64 /* std::hardware_destructive_interference_size */)
         std::atomic_size_t mRbReadPtr = 0;
+
+        // writer updated only, aligned to cache line.
+        alignas(64 /* std::hardware_destructive_interference_size */)
         std::atomic_size_t mRbWritePtr = 0;
 
-        std::thread mThread;
-        std::condition_variable mCondVar;
-        std::mutex mCondVarMutex;
         bool mStopRequested GUARDED_BY(mCondVarMutex) = false;
+        std::thread mThread;
     };
 
     std::string pointerString() const;
@@ -220,6 +248,8 @@ private:
     uint32_t mChannelCount GUARDED_BY(mLock);
     // audio data format
     audio_format_t mFormat GUARDED_BY(mLock);
+    // number of samples in the energy
+    size_t mCurrentSamples GUARDED_BY(mLock) = 0;
     // contains the A-weighted input samples to be processed
     std::vector<float> mAWeightSamples GUARDED_BY(mLock);
     // contains the input samples converted to float
@@ -229,7 +259,7 @@ private:
     // accumulated MEL values
     std::vector<float> mMelValues GUARDED_BY(mLock);
     // current index to store the MEL values
-    uint32_t mCurrentIndex GUARDED_BY(mLock);
+    uint32_t mCurrentIndex GUARDED_BY(mLock) = 0;
     using DefaultBiquadFilter = BiquadFilter<float, true, details::DefaultBiquadConstOptions>;
     // Biquads used for the A-weighting
     std::array<std::unique_ptr<DefaultBiquadFilter>, kCascadeBiquadNumber>
@@ -240,9 +270,8 @@ private:
     std::atomic<audio_port_handle_t> mDeviceId;
     // Value used for momentary exposure
     std::atomic<float> mRs2UpperBound;
-    // number of samples in the energy
-    std::atomic_size_t mCurrentSamples;
-    std::atomic_bool mPaused;
+    // Skip processing data.
+    std::atomic_bool mPaused = false;
 };
 
 }  // namespace android::audio_utils
diff --git a/audio_utils/include/audio_utils/Metadata.h b/audio_utils/include/audio_utils/Metadata.h
index 90186a82..75b17ac8 100644
--- a/audio_utils/include/audio_utils/Metadata.h
+++ b/audio_utils/include/audio_utils/Metadata.h
@@ -23,6 +23,8 @@
 
 #ifdef __cplusplus
 
+#include "template_utils.h"
+
 #include <algorithm>
 #include <any>
 #include <map>
@@ -89,40 +91,8 @@
 
 namespace android::audio_utils::metadata {
 
-// Determine if a type is a specialization of a templated type
-// Example: is_specialization_v<T, std::vector>
-// https://stackoverflow.com/questions/16337610/how-to-know-if-a-type-is-a-specialization-of-stdvector
-
-template <typename Test, template <typename...> class Ref>
-struct is_specialization : std::false_type {};
-
-template <template <typename...> class Ref, typename... Args>
-struct is_specialization<Ref<Args...>, Ref>: std::true_type {};
-
-template <typename Test, template <typename...> class Ref>
-inline constexpr bool is_specialization_v = is_specialization<Test, Ref>::value;
-
-// For static assert(false) we need a template version to avoid early failure.
-// See: https://stackoverflow.com/questions/51523965/template-dependent-false
-template <typename T>
-inline constexpr bool dependent_false_v = false;
-
-// Determine the number of arguments required for structured binding.
-// See the discussion here and follow the links:
-// https://isocpp.org/blog/2016/08/cpp17-structured-bindings-convert-struct-to-a-tuple-simple-reflection
-struct any_type {
-  template<class T>
-  constexpr operator T(); // non explicit
-};
-
-template <typename T, typename... TArgs>
-decltype(void(T{std::declval<TArgs>()...}), std::true_type{}) test_is_braces_constructible(int);
-
-template <typename, typename...>
-std::false_type test_is_braces_constructible(...);
-
-template <typename T, typename... TArgs>
-using is_braces_constructible = decltype(test_is_braces_constructible<T, TArgs...>(0));
+using android::audio_utils::is_specialization_v;
+using android::audio_utils::is_braces_constructible;
 
 // Set up type comparison system
 // see std::variant for the how the type_index() may be used.
diff --git a/audio_utils/include/audio_utils/RunRemote.h b/audio_utils/include/audio_utils/RunRemote.h
new file mode 100644
index 00000000..e991e7cc
--- /dev/null
+++ b/audio_utils/include/audio_utils/RunRemote.h
@@ -0,0 +1,146 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+#include <functional>
+#include <sys/wait.h>
+#include <unistd.h>
+
+namespace android::audio_utils {
+
+/**
+ * RunRemote run a method in a remote process.
+ *
+ * This can be used for lightweight remote process testing.
+ * This can be used for implementing microservices.
+ */
+class RunRemote {
+public:
+    /** Runs the method without a communication pipe. */
+    explicit RunRemote(std::function<void()>&& runnable, bool detached = false)
+            : mRunnable{std::move(runnable)}
+            , mDetached(detached) {}
+
+    /** Runs the method with a reference back to the RunRemote for communication */
+    explicit RunRemote(
+            std::function<void(RunRemote& runRemote)>&& runnable, bool detached = false)
+            : mRunnableExt{std::move(runnable)}
+            , mDetached(detached) {}
+
+    ~RunRemote() {
+        if (!mDetached) stop();
+    }
+
+    bool run() {
+        int fd1[2] = {-1, -1};
+        int fd2[2] = {-1, -1};
+        if (mRunnableExt) {
+            if (pipe(fd1) != 0) return false;
+            if (pipe(fd2) != 0) {
+                close(fd1[0]);
+                close(fd1[1]);
+                return false;
+            }
+        }
+        pid_t ret = fork();
+        if (ret < 0) {
+            close(fd1[0]);
+            close(fd1[1]);
+            close(fd2[0]);
+            close(fd2[1]);
+            return false;
+        } else if (ret == 0) {
+            // child
+            if (mRunnableExt) {
+                mInFd = fd2[0];
+                close(fd2[1]);
+                mOutFd = fd1[1];
+                close(fd1[0]);
+                mRunnableExt(*this);
+            } else {
+                mRunnable();
+            }
+            // let the system reclaim handles.
+            exit(EXIT_SUCCESS);
+        } else {
+            // parent
+            if (mRunnableExt) {
+                mInFd = fd1[0];
+                close(fd1[1]);
+                mOutFd = fd2[1];
+                close(fd2[0]);
+            }
+            mChildPid = ret;
+            return true;
+        }
+    }
+
+    bool stop() {
+        if (mInFd != -1) {
+            close(mInFd);
+            mInFd = -1;
+        }
+        if (mOutFd != -1) {
+            close(mOutFd);
+            mOutFd = -1;
+        }
+        if (!mDetached && mChildPid > 0) {
+            if (kill(mChildPid, SIGTERM)) {
+                return false;
+            }
+            int status = 0;
+            if (TEMP_FAILURE_RETRY(waitpid(mChildPid, &status, 0)) != mChildPid) {
+                return false;
+            }
+            mChildPid = 0;
+            return WIFEXITED(status) && WEXITSTATUS(status) == 0;
+        }
+        return true;
+    }
+
+    /** waits for a char from the remote process. */
+    int getc() {
+        unsigned char c;
+        // EOF returns 0 (this is a blocking read), -1 on error.
+        if (read(mInFd, &c, 1) != 1) return -1;
+        return c;
+    }
+
+    /** sends a char to the remote process. */
+    int putc(int c) {
+        while (true) {
+            int ret = write(mOutFd, &c, 1);  // LE.
+            if (ret == 1) return 1;
+            if (ret < 0) return -1;
+            // on 0, retry.
+        }
+    }
+
+private:
+    const std::function<void()> mRunnable;
+    const std::function<void(RunRemote& runRemote)> mRunnableExt;
+    const bool mDetached;
+
+    // These values are effectively const after calling run(), which does the fork,
+    // until stop() is called, which terminates the remote process.  run() is assumed
+    // called shortly after construction, and not asynchronously with a reader or writer.
+
+    pid_t mChildPid = 0;
+    int mOutFd = -1;
+    int mInFd =1;
+};
+
+}  // namespace android::audio_utils
diff --git a/audio_utils/include/audio_utils/StringUtils.h b/audio_utils/include/audio_utils/StringUtils.h
new file mode 100644
index 00000000..57e6ef53
--- /dev/null
+++ b/audio_utils/include/audio_utils/StringUtils.h
@@ -0,0 +1,133 @@
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
+#pragma once
+
+#include <string>
+#include <vector>
+
+namespace android::audio_utils::stringutils {
+
+// C++ String Utilities
+//
+// Original file extracted from frameworks/av/services/mediametrics
+
+/**
+ * Return string tokens from iterator, separated by spaces and reserved chars.
+ */
+std::string tokenizer(std::string::const_iterator& it,
+        const std::string::const_iterator& end, const char* reserved);
+
+/**
+ * Splits flags string based on delimiters (or, whitespace which is removed).
+ */
+std::vector<std::string> split(const std::string& flags, const char* delim);
+
+
+/**
+ * Parses a vector of integers using ',' '{' and '}' as delimiters. Leaves
+ * vector unmodified if the parsing fails.
+ */
+bool parseVector(const std::string& str, std::vector<int32_t>* vector);
+
+/**
+ * Returns a vector of device address pairs from the devices string.
+ *
+ * A failure to parse returns early with the contents that were able to be parsed.
+ */
+std::vector<std::pair<std::string, std::string>>
+getDeviceAddressPairs(const std::string& devices);
+
+/**
+ * For purposes of field naming and logging, we have common formats:
+ *
+ * Lower camel case: Often used for variables or method names.
+ *                   "helloWorld" "toString()"
+ *
+ * Upper camel case: Often used for classes or structs.
+ *                   "HelloWorld" "MyClass"
+ *
+ * Lower snake case: Often used for variable names or method names.
+ *                   "hello_world" "to_string()"
+ *
+ * Upper snake case: Often used for MACRO names or constants.
+ *                   "HELLO_WORLD" "TO_STRING()"
+ */
+enum class NameFormat {
+    kFormatLowerCamelCase,  // Example: helloWorld
+    kFormatUpperCamelCase,  // Example: HelloWorld
+    kFormatLowerSnakeCase,  // Example: hello_world
+    kFormatUpperSnakeCase,  // Example: HELLO_WORLD
+};
+
+/**
+ * Returns a string with the name tokens converted to a particular format.
+ *
+ * changeNameFormat("hello_world", NameFormat::kFormatLowerCamelCase) -> "helloWorld"
+ *
+ * This is used for consistent logging, where the log convention may differ from
+ * the string/stringify convention of the name.
+ *
+ * The following rules are used:
+ *
+ * 1) A name consists of one or more concatenated words, connected by a case change,
+ *    a '_', or a switch between number to alpha sequence.
+ *
+ * 2) A '_', a number, or a lower to upper case transition will count as a new word.
+ *    A number sequence counts as a word.
+ *
+ * 3) A non alphanumeric character (such as '.') signifies a new name follows
+ *    and is copied through. For example, "helloWorld.toString".
+ *
+ * 4) Conversion of multiple numeric fields separated by '_' will preserve the underscore
+ *    to avoid confusion.  As an example:
+ *    changeNameFormat("alpha_10_100", NameFormat::kFormatUpperCamelCase)
+ *            -> "Alpha10_100" (not Alpha10100)
+ *
+ * 5) When the target format is upper or lower snake case, attempt to preserve underscores.
+ */
+std::string changeNameFormat(const std::string& name, NameFormat format);
+
+inline std::string toLowerCamelCase(const std::string& name) {
+    return changeNameFormat(name, NameFormat::kFormatLowerCamelCase);
+}
+
+inline std::string toUpperCamelCase(const std::string& name) {
+    return changeNameFormat(name, NameFormat::kFormatUpperCamelCase);
+}
+
+inline std::string toLowerSnakeCase(const std::string& name) {
+    return changeNameFormat(name, NameFormat::kFormatLowerSnakeCase);
+}
+
+inline std::string toUpperSnakeCase(const std::string& name) {
+    return changeNameFormat(name, NameFormat::kFormatUpperSnakeCase);
+}
+
+/**
+ * Appends a suffix string, with replacement of a character.
+ *
+ * \param s string to append suffix to.
+ * \param suffix string suffix.
+ * \param from target character to replace in suffix.
+ * \param to character to replace with.
+ */
+inline void appendWithReplacement(std::string& s, const std::string& suffix, char from, char to) {
+    std::transform(suffix.begin(), suffix.end(), std::back_inserter(s),
+                   [from, to](char in) { return in == from ? to : in; });
+}
+
+} // android::audio_utils::stringutils
diff --git a/audio_utils/include/audio_utils/Trace.h b/audio_utils/include/audio_utils/Trace.h
new file mode 100644
index 00000000..438e7554
--- /dev/null
+++ b/audio_utils/include/audio_utils/Trace.h
@@ -0,0 +1,143 @@
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
+#pragma once
+
+#include "StringUtils.h"
+#include "TraceConstants.h"
+
+#include <string>
+#include <type_traits>
+
+namespace android::audio_utils::trace {
+
+/*
+ * Audio Tracing.
+ *
+ * We use an "Object" metadata formatter to ensure consistent
+ * behavior.  The Object formatter is not thread-safe, so
+ * locking must be provided by the caller.
+ *
+ * Object:
+ * This is a C++ object encapsulating key, value pairs.
+ *
+ * Native                              Java equivalent
+ * int32                               (int)
+ * int64                               (long)
+ * float                               (float)
+ * double                              (double)
+ * std::string                         (String)
+ *
+ * TBD: Array definition.
+ * TBD: Recursive definition.
+ *
+ * The Object may be dumped in text form (used for ATRACE)
+ * using the method toTrace().
+ *
+ * The canonical Object format will have all key, value pairs sorted
+ * by key, with no duplicate keys.
+ *
+ * For practical use, we relax the sorting requirement by allowing
+ * "new" keys to be appended to the end.
+ *
+ * To service such requirements (and to add JSON, XML based
+ * output) requires an auxiliary map<> data structure, which
+ * is heavier weight.
+ *
+ * Currently the object supports a set() but no get().
+ *
+ * TODO(b/377400056): Add JSON output formatting.
+ * TODO(b/377400056): Add XML output formatting.
+ * TODO(b/377400056): Enforce sorted output.
+ * TODO(b/377400056): Select trailing commas.
+ * TODO(b/377400056): Enable sorted output.
+ * TODO(b/377400056): Allow key conversion between camel case to snake case.
+ * TODO(b/377400056): Escape string delimiter token from strings.
+ * TODO(b/377400056): Consider nested objects, or strings that contain {}.
+ */
+class Object {
+public:
+    /**
+     * Add a numeric value to the Object.
+     *
+     * @param key name to us.
+     * @param value an arithmetic value.
+     * @return Object for use in fluent style.
+     */
+    template <typename S, typename T>
+    requires std::is_convertible_v<S, std::string> && std::is_arithmetic_v<T>
+    Object& set(const S& key, const T& value) {
+        if (!object_.empty()) object_.append(object_delimiter_token_);
+        object_.append(key).append(assign_token_).append(std::to_string(value));
+        return *this;
+    }
+
+    /**
+     * Add a string value to the Object.
+     *
+     * @param key name to us.
+     * @param value a string convertible value.
+     * @return Object for use in fluent style.
+     */
+    template <typename S, typename T>
+    requires std::is_convertible_v<S, std::string> && std::is_convertible_v<T, std::string>
+    Object& set(const S& key, const T& value) {
+        if (!object_.empty()) object_.append(object_delimiter_token_);
+        object_.append(key).append(assign_token_).append(string_begin_token_);
+        // ATRACE does not like '|', so replace with '+'.
+        stringutils::appendWithReplacement(object_, value, '|', '+');
+        object_.append(string_end_token_);
+        return *this;
+    }
+
+    /**
+     * Returns true if the Object is empty (nothing is recorded).
+     */
+    bool empty() const { return object_.empty(); }
+
+    /**
+     * Clears the contents of the object.
+     */
+    void clear() { object_.clear(); }
+
+    /**
+     * Returns a text-formatted string suitable for ATRACE.
+     */
+    template <typename S>
+    requires std::is_convertible_v<S, std::string>
+    std::string toTrace(const S& tag) const {
+        std::string ret(tag);
+        ret.append(object_begin_token_).append(object_).append(object_end_token_);
+        return ret;
+    }
+
+    std::string toTrace() const {
+        return toTrace("");
+    }
+
+protected:
+    // Make these configurable  (ATRACE text definition)
+    static constexpr char assign_token_[] = "=";
+    static constexpr char object_begin_token_[] = "{ ";
+    static constexpr char object_end_token_[] = " }";
+    static constexpr char object_delimiter_token_[] = " ";
+    static constexpr char string_begin_token_[] = "\"";
+    static constexpr char string_end_token_[] = "\"";
+
+    std::string object_;
+};
+
+} // namespace android::audio_utils::trace
diff --git a/audio_utils/include/audio_utils/TraceConstants.h b/audio_utils/include/audio_utils/TraceConstants.h
new file mode 100644
index 00000000..43cbd306
--- /dev/null
+++ b/audio_utils/include/audio_utils/TraceConstants.h
@@ -0,0 +1,89 @@
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
+#pragma once
+
+/*
+ * To promote uniform usage of audio key values within the ATRACE environment
+ * we keep a master list of all keys used and the meaning of the associated values.
+ *
+ * These macro definitions allow compile-time check of misspellings.
+ *
+ * By convention we use camel case, but automated conversion to snake case
+ * depending on the output medium is possible.
+ *
+ * Values here are all specified in alphabetical order.
+ */
+
+/*
+ * Do not modify any AUDIO_TRACE_THREAD_ or AUDIO_TRACE_TRACK_
+ * events without consulting the git blame owner.
+ *
+ * These form a taxonomy of events suitable for prefix filtering.
+ *
+ * audio.track will include all track events.
+ * audio.track.interval will include only the track interval events.
+ */
+
+// This is used for the linux thread name, which is limited to 16 chars in linux.
+#define AUDIO_TRACE_THREAD_NAME_PREFIX "atd."             // Data worker thread
+
+#define AUDIO_TRACE_PREFIX_AUDIO         "audio."         // Top level prefix
+#define AUDIO_TRACE_PREFIX_FASTCAPTURE   "fastCapture."
+#define AUDIO_TRACE_PREFIX_FASTMIXER     "fastMixer."
+#define AUDIO_TRACE_PREFIX_THREAD        "thread."        // Data worker thread
+#define AUDIO_TRACE_PREFIX_TRACK         "track."         // Audio(Track|Record)
+
+#define AUDIO_TRACE_PREFIX_AUDIO_THREAD         AUDIO_TRACE_PREFIX_AUDIO AUDIO_TRACE_PREFIX_THREAD
+#define AUDIO_TRACE_PREFIX_AUDIO_TRACK          AUDIO_TRACE_PREFIX_AUDIO AUDIO_TRACE_PREFIX_TRACK
+
+#define AUDIO_TRACE_PREFIX_AUDIO_TRACK_ACTION   AUDIO_TRACE_PREFIX_AUDIO_TRACK "action."
+#define AUDIO_TRACE_PREFIX_AUDIO_TRACK_FRDY     AUDIO_TRACE_PREFIX_AUDIO_TRACK "fRdy."
+#define AUDIO_TRACE_PREFIX_AUDIO_TRACK_INTERVAL AUDIO_TRACE_PREFIX_AUDIO_TRACK "interval."
+#define AUDIO_TRACE_PREFIX_AUDIO_TRACK_NRDY     AUDIO_TRACE_PREFIX_AUDIO_TRACK "nRdy."
+
+/*
+ * Events occur during the trace timeline.
+ */
+#define AUDIO_TRACE_EVENT_BEGIN_INTERVAL     "beginInterval"
+#define AUDIO_TRACE_EVENT_END_INTERVAL       "endInterval"
+#define AUDIO_TRACE_EVENT_FLUSH              "flush"
+#define AUDIO_TRACE_EVENT_PAUSE              "pause"
+#define AUDIO_TRACE_EVENT_REFRESH_INTERVAL   "refreshInterval"
+#define AUDIO_TRACE_EVENT_START              "start"
+#define AUDIO_TRACE_EVENT_STOP               "stop"
+#define AUDIO_TRACE_EVENT_UNDERRUN           "underrun"
+
+/*
+ * Key, Value pairs are used to designate what happens during an event.
+ */
+#define AUDIO_TRACE_OBJECT_KEY_CHANNEL_MASK "channelMask" // int32_t
+#define AUDIO_TRACE_OBJECT_KEY_CONTENT_TYPE "contentType" // string (audio_content_type_t)
+#define AUDIO_TRACE_OBJECT_KEY_DEVICES      "devices"     // string (audio_devices_t,
+                                                          //   separated by '+')
+#define AUDIO_TRACE_OBJECT_KEY_EVENT        "event"       // string (AUDIO_TRACE_EVENT_*)
+#define AUDIO_TRACE_OBJECT_KEY_FLAGS        "flags"       // string (audio_output_flags_t,
+                                                          //   audio_input_flags_t,
+                                                          //   separated by '+')
+#define AUDIO_TRACE_OBJECT_KEY_FRAMECOUNT   "frameCount"  // int64_t
+#define AUDIO_TRACE_OBJECT_KEY_FORMAT       "format"      // string
+#define AUDIO_TRACE_OBJECT_KEY_ID           "id"          // int32_t (for threads io_handle_t)
+#define AUDIO_TRACE_OBJECT_KEY_PID          "pid"         // int32_t
+#define AUDIO_TRACE_OBJECT_KEY_SAMPLE_RATE  "sampleRate"  // int32_t
+#define AUDIO_TRACE_OBJECT_KEY_TYPE         "type"        // string (for threads
+                                                          //   IAfThreadBase::type_t)
+#define AUDIO_TRACE_OBJECT_KEY_UID          "uid"         // int32_t
+#define AUDIO_TRACE_OBJECT_KEY_USAGE        "usage"       // string (audio_usage_t)
diff --git a/audio_utils/include/audio_utils/mutex.h b/audio_utils/include/audio_utils/mutex.h
index 31bd0176..31c9da90 100644
--- a/audio_utils/include/audio_utils/mutex.h
+++ b/audio_utils/include/audio_utils/mutex.h
@@ -839,6 +839,7 @@ enum class other_wait_reason_t {
     none = 0,
     cv = 1,
     join = 2,
+    queue = 3,
 };
 
 inline constexpr const char* reason_to_string(other_wait_reason_t reason) {
@@ -846,6 +847,7 @@ inline constexpr const char* reason_to_string(other_wait_reason_t reason) {
         case other_wait_reason_t::none: return "none";
         case other_wait_reason_t::cv: return "cv";
         case other_wait_reason_t::join: return "join";
+        case other_wait_reason_t::queue: return "queue";
         default: return "invalid";
     }
 }
@@ -899,6 +901,9 @@ public:
                 case other_wait_reason_t::join:
                     s.append("join_tid: ").append(std::to_string(tid));
                     break;
+                case other_wait_reason_t::queue:
+                    s.append("queue_tid: ").append(std::to_string(tid));
+                    break;
                 }
             }
             return s;
@@ -975,6 +980,16 @@ public:
         other_wait_info_.tid_ = kInvalidTid;
     }
 
+    // Add waiting state for queue.
+    void add_wait_queue(pid_t waiting_tid) {
+        other_wait_info_.reason_ = other_wait_reason_t::queue;
+        other_wait_info_.tid_ = waiting_tid;
+    }
+
+    void remove_wait_queue() {
+        other_wait_info_.tid_ = kInvalidTid;
+    }
+
     /*
      * Due to the fact that the thread_mutex_info contents are not globally locked,
      * there may be temporal shear.  The string representation is
@@ -1259,7 +1274,8 @@ public:
             deadlock_info.chain.emplace_back(tid2,
                     reason == other_wait_reason_t::cv
                             ? std::string("cv-").append(name).c_str()
-                    : reason == other_wait_reason_t::join ? "join" : name);
+                    : reason == other_wait_reason_t::join ? "join"
+                    : reason == other_wait_reason_t::queue ? "queue" : name);
 
             // cycle detected
             if (visited.count(tid2)) {
@@ -1270,6 +1286,10 @@ public:
 
             // if tid not waiting return (could be blocked on binder).
             const auto tinfo = tid_to_info(registry_map, tid2);
+            if (tinfo == nullptr) {
+                // thread may have disappeared.
+                return deadlock_info;
+            }
             m = tinfo->mutex_wait_.load();
             other_wait_tid = tinfo->other_wait_info_.tid_.load();
             other_wait_reason = tinfo->other_wait_info_.reason_.load();
@@ -1293,6 +1313,27 @@ private:
 
 extern bool mutex_get_enable_flag();
 
+// Returns true if the mutex was locked within the timeout_ns.
+//
+// std::timed_mutex is implemented using a condition variable and doesn't
+// have complete thread safety annotations.
+//
+// Here, we add the flexibility of a timed lock on an existing std::mutex.
+//
+inline bool std_mutex_timed_lock(std::mutex& m, int64_t timeout_ns) TRY_ACQUIRE(true, m) {
+    const int64_t deadline_ns =
+            safe_add_sat(timeout_ns, systemTime(SYSTEM_TIME_REALTIME));
+    const struct timespec ts = {
+            .tv_sec = static_cast<time_t>(deadline_ns / 1'000'000'000),
+            .tv_nsec = static_cast<long>(deadline_ns % 1'000'000'000),
+    };
+    if (pthread_mutex_timedlock(m.native_handle(), &ts) != 0) {
+        metadata_memory_barrier_if_needed();
+        return false;
+    }
+    return true;
+}
+
 template <typename Attributes>
 class CAPABILITY("mutex") [[nodiscard]] mutex_impl {
 public:
@@ -1552,6 +1593,29 @@ public:
         }
     };
 
+    // A RAII class that implements queue wait detection
+    // for the deadlock check.
+    //
+    // During the lifetime of this class object, the current thread
+    // is assumed blocked on the thread tid due to a
+    // cross-thread communication via a queue.
+    //
+    // {
+    //   scoped_queue_wait_check sjw(tid_of_thread);
+    //   queue.add(...);
+    // }
+    //
+
+    class [[nodiscard]] scoped_queue_wait_check {
+    public:
+        explicit scoped_queue_wait_check(pid_t tid) {
+            get_thread_mutex_info()->add_wait_queue(tid);
+        }
+        ~scoped_queue_wait_check() {
+            get_thread_mutex_info()->remove_wait_queue();
+        }
+    };
+
     class lock_scoped_stat_disabled {
     public:
         explicit lock_scoped_stat_disabled(mutex&) {}
@@ -1627,6 +1691,18 @@ inline thread_mutex_info<MutexHandle, Order, N>::~thread_mutex_info() {
     }
 }
 
+
+namespace details {
+
+// Discovery of the audio_utils::mutex vs std::mutex.
+template<typename T>
+concept IsAudioMutex = requires (T& a) {
+    a.std_mutex();  // std::mutex does not have this method.
+};
+
+} // details
+
+
 // audio_utils::lock_guard only works with the defined mutex.
 //
 // We add [[nodiscard]] to prevent accidentally ignoring construction.
@@ -1661,9 +1737,42 @@ private:
 // safety annotations.
 //
 // We add [[nodiscard]] to prevent accidentally ignoring construction.
-class [[nodiscard]] SCOPED_CAPABILITY unique_lock {
+
+// The generic unique_lock.  This works for std::mutex.
+template <typename Mutex>
+class [[nodiscard]] SCOPED_CAPABILITY unique_lock : public std::unique_lock<Mutex> {
+public:
+    explicit unique_lock(Mutex& m) ACQUIRE(m)
+        : std::unique_lock<Mutex>(m) {}
+    ~unique_lock() RELEASE() {}
+
+    void lock() ACQUIRE() { std::unique_lock<Mutex>::lock(); }
+    void unlock() RELEASE() { std::unique_lock<Mutex>::unlock(); }
+
+    bool try_lock() TRY_ACQUIRE(true) { return std::unique_lock<Mutex>::try_lock(); }
+
+    template<class Rep, class Period>
+    bool try_lock_for(const std::chrono::duration<Rep, Period>& timeout_duration)
+            TRY_ACQUIRE(true) {
+        return std::unique_lock<Mutex>::try_lock_for(timeout_duration);
+    }
+
+    template<class Clock, class Duration>
+    bool try_lock_until(const std::chrono::time_point<Clock, Duration>& timeout_time)
+            TRY_ACQUIRE(true) {
+        return std::unique_lock<Mutex>::try_lock_until(timeout_time);
+    }
+};
+
+// Specialized unique_lock for the audio_utlis::mutex.
+//
+// the requires() clause selects this over the generic case upon match.
+//
+template <typename Mutex>
+requires details::IsAudioMutex<Mutex>
+class [[nodiscard]] SCOPED_CAPABILITY unique_lock<Mutex> {
 public:
-    explicit unique_lock(mutex& m) ACQUIRE(m)
+    explicit unique_lock(Mutex& m) ACQUIRE(m)
         : ul_(m.std_mutex(), std::defer_lock)
         , mutex_(m) {
         lock();
@@ -1676,7 +1785,7 @@ public:
     void lock() ACQUIRE() {
         mutex::lock_scoped_stat_t::pre_lock(mutex_);
         if (!ul_.try_lock()) {
-            mutex::lock_scoped_stat_t ls(mutex_);
+            typename Mutex::lock_scoped_stat_t ls(mutex_);
             ul_.lock();
         }
         mutex::lock_scoped_stat_t::post_lock(mutex_);
@@ -1698,7 +1807,7 @@ public:
     }
 
     template<class Rep, class Period>
-    bool try_lock_for(const std::chrono::duration<Rep,Period>& timeout_duration)
+    bool try_lock_for(const std::chrono::duration<Rep, Period>& timeout_duration)
             TRY_ACQUIRE(true) {
         mutex::lock_scoped_stat_t::pre_lock(mutex_);
         if (!ul_.try_lock_for(timeout_duration)) return false;
@@ -1708,7 +1817,7 @@ public:
     }
 
     template<class Clock, class Duration>
-    bool try_lock_until(const std::chrono::time_point<Clock,Duration>& timeout_time)
+    bool try_lock_until(const std::chrono::time_point<Clock, Duration>& timeout_time)
             TRY_ACQUIRE(true) {
         mutex::lock_scoped_stat_t::pre_lock(mutex_);
         if (!ul_.try_lock_until(timeout_time)) return false;
@@ -1758,46 +1867,47 @@ public:
         cv_.notify_all();
     }
 
-    void wait(unique_lock& lock, pid_t notifier_tid = kInvalidTid) {
-        mutex::cv_wait_scoped_stat_t ws(lock.native_mutex(), notifier_tid);
+    template <typename Mutex>
+    void wait(unique_lock<Mutex>& lock, pid_t notifier_tid = kInvalidTid) {
+        typename Mutex::cv_wait_scoped_stat_t ws(lock.native_mutex(), notifier_tid);
         cv_.wait(lock.std_unique_lock());
     }
 
-    template<typename Predicate>
-    void wait(unique_lock& lock, Predicate stop_waiting, pid_t notifier_tid = kInvalidTid) {
-        mutex::cv_wait_scoped_stat_t ws(lock.native_mutex(), notifier_tid);
+    template<typename Mutex, typename Predicate>
+    void wait(unique_lock<Mutex>& lock, Predicate stop_waiting, pid_t notifier_tid = kInvalidTid) {
+        typename Mutex::cv_wait_scoped_stat_t ws(lock.native_mutex(), notifier_tid);
         cv_.wait(lock.std_unique_lock(), std::move(stop_waiting));
     }
 
-    template<typename Rep, typename Period>
-    std::cv_status wait_for(unique_lock& lock,
+    template<typename Mutex, typename Rep, typename Period>
+    std::cv_status wait_for(unique_lock<Mutex>& lock,
             const std::chrono::duration<Rep, Period>& rel_time,
             pid_t notifier_tid = kInvalidTid) {
-        mutex::cv_wait_scoped_stat_t ws(lock.native_mutex(), notifier_tid);
+        typename Mutex::cv_wait_scoped_stat_t ws(lock.native_mutex(), notifier_tid);
         return cv_.wait_for(lock.std_unique_lock(), rel_time);
     }
 
-    template<typename Rep, typename Period, typename Predicate>
-    bool wait_for(unique_lock& lock,
+    template<typename Mutex, typename Rep, typename Period, typename Predicate>
+    bool wait_for(unique_lock<Mutex>& lock,
             const std::chrono::duration<Rep, Period>& rel_time,
             Predicate stop_waiting, pid_t notifier_tid = kInvalidTid) {
-        mutex::cv_wait_scoped_stat_t ws(lock.native_mutex(), notifier_tid);
+        typename Mutex::cv_wait_scoped_stat_t ws(lock.native_mutex(), notifier_tid);
         return cv_.wait_for(lock.std_unique_lock(), rel_time, std::move(stop_waiting));
     }
 
-    template<typename Clock, typename Duration>
-    std::cv_status wait_until(unique_lock& lock,
+    template<typename Mutex, typename Clock, typename Duration>
+    std::cv_status wait_until(unique_lock<Mutex>& lock,
             const std::chrono::time_point<Clock, Duration>& timeout_time,
             pid_t notifier_tid = kInvalidTid) {
-        mutex::cv_wait_scoped_stat_t ws(lock.native_mutex(), notifier_tid);
+        typename Mutex::cv_wait_scoped_stat_t ws(lock.native_mutex(), notifier_tid);
         return cv_.wait_until(lock.std_unique_lock(), timeout_time);
     }
 
-    template<typename Clock, typename Duration, typename Predicate>
-    bool wait_until(unique_lock& lock,
+    template<typename Mutex, typename Clock, typename Duration, typename Predicate>
+    bool wait_until(unique_lock<Mutex>& lock,
             const std::chrono::time_point<Clock, Duration>& timeout_time,
             Predicate stop_waiting, pid_t notifier_tid = kInvalidTid) {
-        mutex::cv_wait_scoped_stat_t ws(lock.native_mutex(), notifier_tid);
+        typename Mutex::cv_wait_scoped_stat_t ws(lock.native_mutex(), notifier_tid);
         return cv_.wait_until(lock.std_unique_lock(), timeout_time, std::move(stop_waiting));
     }
 
diff --git a/audio_utils/include/audio_utils/template_utils.h b/audio_utils/include/audio_utils/template_utils.h
new file mode 100644
index 00000000..66cafbe1
--- /dev/null
+++ b/audio_utils/include/audio_utils/template_utils.h
@@ -0,0 +1,414 @@
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
+#pragma once
+
+#ifdef __cplusplus
+
+#include <optional>
+#include <tuple>
+#include <type_traits>
+#include <utility>
+
+namespace android::audio_utils {
+
+// Determine if a type is a specialization of a templated type
+// Example: is_specialization_v<T, std::vector>
+template <typename Test, template <typename...> class Ref>
+struct is_specialization : std::false_type {};
+
+template <template <typename...> class Ref, typename... Args>
+struct is_specialization<Ref<Args...>, Ref> : std::true_type {};
+
+template <typename Test, template <typename...> class Ref>
+inline constexpr bool is_specialization_v = is_specialization<Test, Ref>::value;
+
+// For static assert(false) we need a template version to avoid early failure.
+template <typename T>
+inline constexpr bool dependent_false_v = false;
+
+// Determine the number of arguments required for structured binding.
+// See the discussion here and follow the links:
+// https://isocpp.org/blog/2016/08/cpp17-structured-bindings-convert-struct-to-a-tuple-simple-reflection
+// Example: is_braces_constructible<T, any_type>()
+struct any_type {
+  template <class T>
+  constexpr operator T();  // non explicit
+};
+
+template <typename T, typename... TArgs>
+decltype(void(T{std::declval<TArgs>()...}), std::true_type{})
+test_is_braces_constructible(int);
+
+template <typename, typename...>
+std::false_type test_is_braces_constructible(...);
+
+template <typename T, typename... TArgs>
+using is_braces_constructible =
+    decltype(test_is_braces_constructible<T, TArgs...>(0));
+
+template <typename T, typename... Args>
+constexpr bool is_braces_constructible_v =
+    is_braces_constructible<T, Args...>::value;
+
+// Define a concept to check if a class has a member type `Tag` and `getTag()` method
+template <typename T>
+concept has_tag_and_get_tag = requires(T t) {
+    { t.getTag() } -> std::same_as<typename T::Tag>;
+};
+
+template <typename T>
+inline constexpr bool has_tag_and_get_tag_v = has_tag_and_get_tag<T>;
+
+/**
+ * Concept to identify primitive types, includes fundamental types, enums, and
+ * std::string.
+ */
+template <typename T>
+concept PrimitiveType = std::is_arithmetic_v<T> || std::is_enum_v<T> ||
+                        std::is_same_v<T, std::string>;
+
+// Helper to access elements by runtime index
+template <typename Tuple, typename Func, size_t... Is>
+void op_tuple_elements_by_index(Tuple&& tuple, size_t index, Func&& func,
+                                std::index_sequence<Is...>) {
+  ((index == Is ? func(std::get<Is>(tuple)) : void()), ...);
+}
+
+template <typename Tuple, typename Func>
+void op_tuple_elements(Tuple&& tuple, size_t index, Func&& func) {
+  constexpr size_t tuple_size = std::tuple_size_v<std::decay_t<Tuple>>;
+  op_tuple_elements_by_index(std::forward<Tuple>(tuple), index,
+                             std::forward<Func>(func),
+                             std::make_index_sequence<tuple_size>{});
+}
+
+/**
+ * The maximum structure members supported in the structure.
+ * If this utility is used for a structure with more than `N` members, the
+ * compiler will fail. In that case, `structure_to_tuple` must be extended.
+ *
+ */
+constexpr size_t kMaxStructMember = 20;
+
+/**
+ * @brief Converts a structure to a tuple.
+ *
+ * This function uses structured bindings to decompose the input structure `t`
+ * into individual elements, and then returns a `std::tuple` containing those
+ * elements.
+ *
+ * Example:
+ * ```cpp
+ * struct Point3D {
+ *     int x;
+ *     int y;
+ *     int z;
+ * };
+ * Point3D point{1, 2, 3};
+ * auto tuple = structure_to_tuple(point);  // tuple will be std::make_tuple(1,
+ * 2, 3)
+ * ```
+ *
+ * @tparam T The type of the structure to be converted.
+ * @param t The structure to be converted to a tuple.
+ * @return A `std::tuple` containing all members of the input structure.
+ *
+ * @note The maximum number of members supported in a structure is
+ * `kMaxStructMember`. If the input structure has more than `kMaxStructMember`
+ * members, a compile-time error will occur.
+ */
+template <typename T>
+auto structure_to_tuple(const T& t) {
+  if constexpr (is_braces_constructible<
+                    T, any_type, any_type, any_type, any_type, any_type,
+                    any_type, any_type, any_type, any_type, any_type, any_type,
+                    any_type, any_type, any_type, any_type, any_type, any_type,
+                    any_type, any_type, any_type>()) {
+    auto&& [t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, t14, t15,
+            t16, t17, t18, t19, t20] = t;
+    return std::make_tuple(t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12,
+                           t13, t14, t15, t16, t17, t18, t19, t20);
+  } else if constexpr (is_braces_constructible<
+                           T, any_type, any_type, any_type, any_type, any_type,
+                           any_type, any_type, any_type, any_type, any_type,
+                           any_type, any_type, any_type, any_type, any_type,
+                           any_type, any_type, any_type, any_type>()) {
+    auto&& [t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, t14, t15,
+            t16, t17, t18, t19] = t;
+    return std::make_tuple(t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12,
+                           t13, t14, t15, t16, t17, t18, t19);
+  } else if constexpr (is_braces_constructible<
+                           T, any_type, any_type, any_type, any_type, any_type,
+                           any_type, any_type, any_type, any_type, any_type,
+                           any_type, any_type, any_type, any_type, any_type,
+                           any_type, any_type, any_type>()) {
+    auto&& [t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, t14, t15,
+            t16, t17, t18] = t;
+    return std::make_tuple(t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12,
+                           t13, t14, t15, t16, t17, t18);
+  } else if constexpr (is_braces_constructible<
+                           T, any_type, any_type, any_type, any_type, any_type,
+                           any_type, any_type, any_type, any_type, any_type,
+                           any_type, any_type, any_type, any_type, any_type,
+                           any_type, any_type>()) {
+    auto&& [t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, t14, t15,
+            t16, t17] = t;
+    return std::make_tuple(t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12,
+                           t13, t14, t15, t16, t17);
+  } else if constexpr (is_braces_constructible<
+                           T, any_type, any_type, any_type, any_type, any_type,
+                           any_type, any_type, any_type, any_type, any_type,
+                           any_type, any_type, any_type, any_type, any_type,
+                           any_type>()) {
+    auto&& [t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, t14, t15,
+            t16] = t;
+    return std::make_tuple(t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12,
+                           t13, t14, t15, t16);
+  } else if constexpr (is_braces_constructible<
+                           T, any_type, any_type, any_type, any_type, any_type,
+                           any_type, any_type, any_type, any_type, any_type,
+                           any_type, any_type, any_type, any_type,
+                           any_type>()) {
+    auto&& [t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, t14, t15] =
+        t;
+    return std::make_tuple(t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12,
+                           t13, t14, t15);
+  } else if constexpr (is_braces_constructible<
+                           T, any_type, any_type, any_type, any_type, any_type,
+                           any_type, any_type, any_type, any_type, any_type,
+                           any_type, any_type, any_type, any_type>()) {
+    auto&& [t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, t14] = t;
+    return std::make_tuple(t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12,
+                           t13, t14);
+  } else if constexpr (is_braces_constructible<
+                           T, any_type, any_type, any_type, any_type, any_type,
+                           any_type, any_type, any_type, any_type, any_type,
+                           any_type, any_type, any_type>()) {
+    auto&& [t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13] = t;
+    return std::make_tuple(t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12,
+                           t13);
+  } else if constexpr (is_braces_constructible<
+                           T, any_type, any_type, any_type, any_type, any_type,
+                           any_type, any_type, any_type, any_type, any_type,
+                           any_type, any_type>()) {
+    auto&& [t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12] = t;
+    return std::make_tuple(t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12);
+  } else if constexpr (is_braces_constructible<T, any_type, any_type, any_type,
+                                               any_type, any_type, any_type,
+                                               any_type, any_type, any_type,
+                                               any_type, any_type>()) {
+    auto&& [t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11] = t;
+    return std::make_tuple(t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11);
+  } else if constexpr (is_braces_constructible<T, any_type, any_type, any_type,
+                                               any_type, any_type, any_type,
+                                               any_type, any_type, any_type,
+                                               any_type>()) {
+    auto&& [t1, t2, t3, t4, t5, t6, t7, t8, t9, t10] = t;
+    return std::make_tuple(t1, t2, t3, t4, t5, t6, t7, t8, t9, t10);
+  } else if constexpr (is_braces_constructible<
+                           T, any_type, any_type, any_type, any_type, any_type,
+                           any_type, any_type, any_type, any_type>()) {
+    auto&& [t1, t2, t3, t4, t5, t6, t7, t8, t9] = t;
+    return std::make_tuple(t1, t2, t3, t4, t5, t6, t7, t8, t9);
+  } else if constexpr (is_braces_constructible<T, any_type, any_type, any_type,
+                                               any_type, any_type, any_type,
+                                               any_type, any_type>()) {
+    auto&& [t1, t2, t3, t4, t5, t6, t7, t8] = t;
+    return std::make_tuple(t1, t2, t3, t4, t5, t6, t7, t8);
+  } else if constexpr (is_braces_constructible<T, any_type, any_type, any_type,
+                                               any_type, any_type, any_type,
+                                               any_type>()) {
+    auto&& [t1, t2, t3, t4, t5, t6, t7] = t;
+    return std::make_tuple(t1, t2, t3, t4, t5, t6, t7);
+  } else if constexpr (is_braces_constructible<T, any_type, any_type, any_type,
+                                               any_type, any_type,
+                                               any_type>()) {
+    auto&& [t1, t2, t3, t4, t5, t6] = t;
+    return std::make_tuple(t1, t2, t3, t4, t5, t6);
+  } else if constexpr (is_braces_constructible<T, any_type, any_type, any_type,
+                                               any_type, any_type>()) {
+    auto&& [t1, t2, t3, t4, t5] = t;
+    return std::make_tuple(t1, t2, t3, t4, t5);
+  } else if constexpr (is_braces_constructible<T, any_type, any_type, any_type,
+                                               any_type>()) {
+    auto&& [t1, t2, t3, t4] = t;
+    return std::make_tuple(t1, t2, t3, t4);
+  } else if constexpr (is_braces_constructible<T, any_type, any_type,
+                                               any_type>()) {
+    auto&& [t1, t2, t3] = t;
+    return std::make_tuple(t1, t2, t3);
+  } else if constexpr (is_braces_constructible<T, any_type, any_type>()) {
+    auto&& [t1, t2] = t;
+    return std::make_tuple(t1, t2);
+  } else if constexpr (is_braces_constructible<T, any_type>()) {
+    auto&& [t1] = t;
+    return std::make_tuple(t1);
+  } else {
+    static_assert(false, "Currently supports up to 20 members only.");
+  }
+}
+
+/**
+ * @brief Applies a ternary operation element-wise to structs of type T and
+ * transform the results into a new struct of the same type.
+ *
+ * This function template takes three structs of the same type `T` and an
+ * ternary operation `op`, then applies `op` element-wise to the corresponding
+ * members of the input structs. If all the results of `op` are valid (i.e., not
+ * `std::nullopt`), it constructs a new struct `T` with these results and
+ * returns it as `std::optional<T>`. Otherwise, it returns `std::nullopt`.
+ *
+ * @example
+ * struct Point3D {
+ *   int x;
+ *   int y;
+ *   int z;
+ * };
+ *
+ * std::vector<int> v1{10, 2, 1};
+ * std::vector<int> v2{4, 5, 8};
+ * std::vector<int> v3{1, 8, 6};
+ *
+ * const auto addOp3 = [](const auto& a, const auto& b, const auto& c) {
+ *   return {a + b + c};
+ * };
+ * auto result = op_aggregate(addOp3, v1, v2, v3);
+ * The value of `result` will be std::vector<int>({15, 15, 15})
+ *
+ * @tparam TernaryOp The ternary operation apply to parameters `a`, `b`, and
+ * `c`.
+ * @tparam T The type of `a`, `b`, and `c`.
+ * @param op The ternary operation to apply.
+ * @param a The first input struct.
+ * @param b The second input struct.
+ * @param c The third input struct.
+ * @return A new struct with the aggregated results if all results are valid,
+ *         `std::nullopt` otherwise.
+ */
+template <typename TernaryOp, typename T, size_t... Is>
+std::optional<T> op_aggregate_helper(TernaryOp op, const T& a, const T& b,
+                                     const T& c, std::index_sequence<Is...>) {
+  const auto aTuple = structure_to_tuple<T>(a);
+  const auto bTuple = structure_to_tuple<T>(b);
+  const auto cTuple = structure_to_tuple<T>(c);
+
+  T result;
+  auto resultTuple = structure_to_tuple<T>(result);
+
+  bool success = true;
+  (
+      [&]() {
+        if (!success) return;  // stop op with any previous error
+        auto val = op(std::get<Is>(aTuple), std::get<Is>(bTuple),
+                      std::get<Is>(cTuple));
+        if (!val) {
+          success = false;
+          return;
+        }
+        std::get<Is>(resultTuple) = *val;
+      }(),
+      ...);
+
+  if (!success) {
+    return std::nullopt;
+  }
+
+  return std::apply([](auto&&... args) { return T{args...}; }, resultTuple);
+}
+
+template <typename TernaryOp, typename T>
+std::optional<T> op_aggregate(TernaryOp op, const T& a, const T& b,
+                              const T& c) {
+  constexpr size_t tuple_size =
+      std::tuple_size_v<std::decay_t<decltype(structure_to_tuple(a))>>;
+  return op_aggregate_helper<TernaryOp, T>(
+      op, a, b, c, std::make_index_sequence<tuple_size>{});
+}
+
+/**
+ * @brief Applies a binary operation element-wise to structs of type T and
+ * transform the results into a new struct of the same type.
+ *
+ * This function template takes three structs of the same type `T` and an
+ * operation `op`, and applies `op` element-wise to the corresponding members of
+ * the input structs. If all the results of `op` are valid (i.e., not
+ * `std::nullopt`), it constructs a new struct `T` with these results and
+ * returns it as `std::optional<T>`. Otherwise, it returns `std::nullopt`.
+ *
+ * @example
+ * struct Point3D {
+ *   int x;
+ *   int y;
+ *   int z;
+ * };
+ *
+ * std::vector<int> v1{10, 2, 1};
+ * std::vector<int> v2{4, 5, 8};
+ * const auto addOp2 = [](const auto& a, const auto& b) {
+ *   return {a + b};
+ * };
+ * auto result = op_aggregate(addOp2, v1, v2);
+ * The value of `result` will be std::vector<int>({14, 7, 9})
+ *
+ * @tparam BinaryOp The binary operation to apply to parameters `a` and `b`.
+ * @tparam T The type of `a` and `b`.
+ * @param op The ternary operation to apply.
+ * @param a The first input struct.
+ * @param b The second input struct.
+ * @return A new struct with the aggregated results if all results are valid,
+ *         `std::nullopt` otherwise.
+ */
+template <typename BinaryOp, typename T, size_t... Is>
+std::optional<T> op_aggregate_helper(BinaryOp op, const T& a, const T& b,
+                                     std::index_sequence<Is...>) {
+  const auto aTuple = structure_to_tuple<T>(a);
+  const auto bTuple = structure_to_tuple<T>(b);
+
+  T result;
+  auto resultTuple = structure_to_tuple<T>(result);
+
+  bool success = true;
+  (
+      [&]() {
+        if (!success) return;  // stop op with any previous error
+        auto val = op(std::get<Is>(aTuple), std::get<Is>(bTuple));
+        if (!val) {
+          success = false;
+          return;
+        }
+        std::get<Is>(resultTuple) = *val;
+      }(),
+      ...);
+
+  if (!success) {
+    return std::nullopt;
+  }
+
+  return std::apply([](auto&&... args) { return T{args...}; }, resultTuple);
+}
+
+template <typename BinaryOp, typename T>
+std::optional<T> op_aggregate(BinaryOp op, const T& a, const T& b) {
+  constexpr size_t tuple_size =
+      std::tuple_size_v<std::decay_t<decltype(structure_to_tuple(a))>>;
+  return op_aggregate_helper<BinaryOp, T>(
+      op, a, b, std::make_index_sequence<tuple_size>{});
+}
+
+}  // namespace android::audio_utils
+
+#endif  // __cplusplus
\ No newline at end of file
diff --git a/audio_utils/tests/Android.bp b/audio_utils/tests/Android.bp
index 0a952e0f..39898f81 100644
--- a/audio_utils/tests/Android.bp
+++ b/audio_utils/tests/Android.bp
@@ -147,6 +147,32 @@ cc_test {
     ],
 }
 
+cc_test {
+    name: "audio_stringutils_tests",
+    host_supported: true,
+
+    srcs: [
+        "audio_stringutils_tests.cpp",
+    ],
+
+    shared_libs: [
+        "libbase",
+        "liblog",
+        "libutils",
+    ],
+
+    static_libs: [
+        "libaudioutils",
+    ],
+
+    cflags: [
+        "-Wall",
+        "-Werror",
+        "-Wextra",
+        "-Wthread-safety",
+    ],
+}
+
 cc_test {
     name: "audio_thread_tests",
 
@@ -172,6 +198,24 @@ cc_test {
     ],
 }
 
+cc_test {
+    name: "audio_trace_tests",
+    host_supported: true,
+    srcs: ["audio_trace_tests.cpp"],
+    shared_libs: [
+        "libbase",
+        "libbinder",
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
     name: "audio_nnapi_tests",
 
@@ -309,6 +353,7 @@ cc_test {
         "-Wall",
         "-Werror",
         "-Wextra",
+        "-Wthread-safety",
     ],
 }
 
@@ -334,6 +379,7 @@ cc_test {
         "-Wall",
         "-Werror",
         "-Wextra",
+        "-Wthread-safety",
     ],
 }
 
@@ -540,6 +586,27 @@ cc_test {
     },
 }
 
+cc_test {
+    name: "run_remote_tests",
+    host_supported: true,
+
+    shared_libs: [
+        "libcutils",
+        "liblog",
+    ],
+
+    static_libs: [
+        "libaudioutils",
+    ],
+
+    srcs: ["run_remote_tests.cpp"],
+    cflags: [
+        "-Wall",
+        "-Werror",
+        "-Wextra",
+    ],
+}
+
 cc_test {
     name: "errorlog_tests",
     host_supported: true,
diff --git a/audio_utils/tests/audio_mutex_tests.cpp b/audio_utils/tests/audio_mutex_tests.cpp
index 59201d21..4ba0acf6 100644
--- a/audio_utils/tests/audio_mutex_tests.cpp
+++ b/audio_utils/tests/audio_mutex_tests.cpp
@@ -372,6 +372,72 @@ TEST(audio_mutex_tests, OrderDetection) {
     EXPECT_EQ(0, nil2.second.load());
 }
 
+
+TEST(audio_mutex_tests, StdTimedLock) {
+    using ConditionVariable = std::condition_variable;
+    using Mutex = std::mutex;
+    using UniqueLock = android::audio_utils::unique_lock<Mutex>;
+
+    Mutex m, m1;
+    ConditionVariable cv;
+    bool quit = false;  // GUARDED_BY(m)
+
+    std::atomic<pid_t> tid1{};
+
+    // launch thread.
+    std::thread t1([&]() {
+        UniqueLock ul1(m1);
+        UniqueLock ul(m);
+        tid1 = android::audio_utils::gettid_wrapper();
+        while (!quit) {
+            cv.wait(ul, [&]{ return quit; });
+            if (quit) break;
+        }
+    });
+
+    // ensure thread tid1 has acquired all locks.
+    while (tid1 == 0) { usleep(1000); }
+
+    // try lock for 500ms.
+    // (don't make this too large otherwise the successful timeout will take > 500ms).
+    constexpr int64_t kTimeoutNs = 500'000'000;
+    {
+        //  verify timed out state.
+        const int64_t beginNs = systemTime();
+        const bool success = audio_utils::std_mutex_timed_lock(m1, kTimeoutNs);
+        const int64_t endNs = systemTime();
+        const int64_t diffNs = endNs - beginNs;
+
+        if (success) m1.unlock();
+        EXPECT_GT(diffNs, kTimeoutNs);
+        EXPECT_FALSE(success);
+    }
+
+    // exit the thread
+    {
+        UniqueLock ul(m);
+
+        quit = true;
+        cv.notify_one();
+    }
+
+    t1.join();
+
+    {
+        // verify success state.
+        const int64_t beginNs = systemTime();
+        const bool success = audio_utils::std_mutex_timed_lock(m1, kTimeoutNs);
+        const int64_t endNs = systemTime();
+        const int64_t diffNs = endNs - beginNs;
+
+        if (success) m1.unlock();
+
+        // we're expecting to lock within 250ms (should be efficient).
+        constexpr int64_t kSuccessLockNs = 250'000'000;
+        EXPECT_LT(diffNs, kSuccessLockNs);
+        EXPECT_TRUE(success);
+    }
+}
 // The following tests are evaluated for the android::audio_utils::mutex
 // Non-Priority Inheritance and Priority Inheritance cases.
 
@@ -440,7 +506,7 @@ NO_THREAD_SAFETY_ANALYSIS {
 TEST_P(MutexTestSuite, TimedLock) {
     using ConditionVariable = android::audio_utils::condition_variable;
     using Mutex = android::audio_utils::mutex;
-    using UniqueLock = android::audio_utils::unique_lock;
+    using UniqueLock = android::audio_utils::unique_lock<Mutex>;
     const bool priority_inheritance = GetParam();
 
     Mutex m{priority_inheritance}, m1{priority_inheritance};
@@ -506,7 +572,7 @@ TEST_P(MutexTestSuite, TimedLock) {
 
 TEST_P(MutexTestSuite, DeadlockDetection) {
     using Mutex = android::audio_utils::mutex;
-    using UniqueLock = android::audio_utils::unique_lock;
+    using UniqueLock = android::audio_utils::unique_lock<Mutex>;
     using ConditionVariable = android::audio_utils::condition_variable;
     const bool priority_inheritance = GetParam();
 
@@ -611,7 +677,7 @@ TEST_P(MutexTestSuite, DeadlockDetection) {
 
 TEST_P(MutexTestSuite, DeadlockConditionVariableDetection) {
     using Mutex = android::audio_utils::mutex;
-    using UniqueLock = android::audio_utils::unique_lock;
+    using UniqueLock = android::audio_utils::unique_lock<Mutex>;
     using ConditionVariable = android::audio_utils::condition_variable;
     const bool priority_inheritance = GetParam();
 
@@ -739,7 +805,7 @@ TEST_P(MutexTestSuite, DeadlockConditionVariableDetection) {
 
 TEST_P(MutexTestSuite, DeadlockJoinDetection) {
     using Mutex = android::audio_utils::mutex;
-    using UniqueLock = android::audio_utils::unique_lock;
+    using UniqueLock = android::audio_utils::unique_lock<Mutex>;
     using ConditionVariable = android::audio_utils::condition_variable;
     const bool priority_inheritance = GetParam();
 
diff --git a/audio_utils/tests/audio_stringutils_tests.cpp b/audio_utils/tests/audio_stringutils_tests.cpp
new file mode 100644
index 00000000..70e4db33
--- /dev/null
+++ b/audio_utils/tests/audio_stringutils_tests.cpp
@@ -0,0 +1,174 @@
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
+//#define LOG_NDEBUG 0
+#define LOG_TAG "audio_stringutils_tests"
+
+#include <audio_utils/StringUtils.h>
+#include <gtest/gtest.h>
+
+TEST(audio_utils_string, parseVector) {
+    {
+        std::vector<int32_t> values;
+        EXPECT_EQ(true, android::audio_utils::stringutils::parseVector(
+                "0{4,300,0,-112343,350}9", &values));
+        EXPECT_EQ(values, std::vector<int32_t>({0, 4, 300, 0, -112343, 350, 9}));
+    }
+    {
+        std::vector<int32_t> values;
+        EXPECT_EQ(true, android::audio_utils::stringutils::parseVector("53", &values));
+        EXPECT_EQ(values, std::vector<int32_t>({53}));
+    }
+    {
+        std::vector<int32_t> values;
+        EXPECT_EQ(false, android::audio_utils::stringutils::parseVector("5{3,6*3}3", &values));
+        EXPECT_EQ(values, std::vector<int32_t>({}));
+    }
+    {
+        std::vector<int32_t> values = {1}; // should still be this when parsing fails
+        std::vector<int32_t> expected = {1};
+        EXPECT_EQ(false, android::audio_utils::stringutils::parseVector("51342abcd,1232", &values));
+        EXPECT_EQ(values, std::vector<int32_t>({1}));
+    }
+    {
+        std::vector<int32_t> values = {2}; // should still be this when parsing fails
+        EXPECT_EQ(false, android::audio_utils::stringutils::parseVector(
+                "12345678901234,12345678901234", &values));
+        EXPECT_EQ(values, std::vector<int32_t>({2}));
+    }
+}
+
+
+TEST(audio_utils_string, device_parsing) {
+    auto devaddr = android::audio_utils::stringutils::getDeviceAddressPairs("(DEVICE, )");
+    ASSERT_EQ((size_t)1, devaddr.size());
+    ASSERT_EQ("DEVICE", devaddr[0].first);
+    ASSERT_EQ("", devaddr[0].second);
+
+    devaddr = android::audio_utils::stringutils::getDeviceAddressPairs(
+            "(DEVICE1, A)|(D, ADDRB)");
+    ASSERT_EQ((size_t)2, devaddr.size());
+    ASSERT_EQ("DEVICE1", devaddr[0].first);
+    ASSERT_EQ("A", devaddr[0].second);
+    ASSERT_EQ("D", devaddr[1].first);
+    ASSERT_EQ("ADDRB", devaddr[1].second);
+
+    devaddr = android::audio_utils::stringutils::getDeviceAddressPairs(
+            "(A,B)|(C,D)");
+    ASSERT_EQ((size_t)2, devaddr.size());
+    ASSERT_EQ("A", devaddr[0].first);
+    ASSERT_EQ("B", devaddr[0].second);
+    ASSERT_EQ("C", devaddr[1].first);
+    ASSERT_EQ("D", devaddr[1].second);
+
+    devaddr = android::audio_utils::stringutils::getDeviceAddressPairs(
+            "  ( A1 , B )  | ( C , D2 )  ");
+    ASSERT_EQ((size_t)2, devaddr.size());
+    ASSERT_EQ("A1", devaddr[0].first);
+    ASSERT_EQ("B", devaddr[0].second);
+    ASSERT_EQ("C", devaddr[1].first);
+    ASSERT_EQ("D2", devaddr[1].second);
+
+    devaddr = android::audio_utils::stringutils::getDeviceAddressPairs(
+            " Z  ");
+    ASSERT_EQ((size_t)1, devaddr.size());
+    ASSERT_EQ("Z", devaddr[0].first);
+
+    devaddr = android::audio_utils::stringutils::getDeviceAddressPairs(
+            "  A | B|C  ");
+    ASSERT_EQ((size_t)3, devaddr.size());
+    ASSERT_EQ("A", devaddr[0].first);
+    ASSERT_EQ("", devaddr[0].second);
+    ASSERT_EQ("B", devaddr[1].first);
+    ASSERT_EQ("", devaddr[1].second);
+    ASSERT_EQ("C", devaddr[2].first);
+    ASSERT_EQ("", devaddr[2].second);
+
+    devaddr = android::audio_utils::stringutils::getDeviceAddressPairs(
+            "  A | (B1, 10) |C  ");
+    ASSERT_EQ((size_t)3, devaddr.size());
+    ASSERT_EQ("A", devaddr[0].first);
+    ASSERT_EQ("", devaddr[0].second);
+    ASSERT_EQ("B1", devaddr[1].first);
+    ASSERT_EQ("10", devaddr[1].second);
+    ASSERT_EQ("C", devaddr[2].first);
+    ASSERT_EQ("", devaddr[2].second);
+}
+
+TEST(audio_utils_string, ConvertToLowerCamelCase) {
+    EXPECT_EQ("camelCase.andSnakeCase.4Fun.2Funny.look4It",
+            android::audio_utils::stringutils::toLowerCamelCase(
+                    "camel_case.AndSnake_Case.4Fun.2FUNNY.Look_4__it"));
+
+    EXPECT_EQ("abc.abc1_10_100$def #!g",
+            android::audio_utils::stringutils::toLowerCamelCase(
+                    "ABC.abc_1_10_100$def #!g"));
+}
+
+TEST(audio_utils_string, ConvertToUpperCamelCase) {
+    EXPECT_EQ("CamelCase.AndSnakeCase.4Fun.2Funny.Look4It",
+            android::audio_utils::stringutils::toUpperCamelCase(
+                    "camel_case.AndSnake_Case.4Fun.2FUNNY.Look_4__it"));
+
+    EXPECT_EQ("Abc.Abc1_10_100$Def #!G",
+            android::audio_utils::stringutils::toUpperCamelCase(
+                    "ABC.abc_1_10_100$def #!g"));
+}
+
+TEST(audio_utils_string, ConvertToLowerSnakeCase) {
+    EXPECT_EQ("camel_case.and_snake_case.4fun.2funny.look_4_it",
+            android::audio_utils::stringutils::toLowerSnakeCase(
+                    "camel_case.AndSnake_Case.4Fun.2FUNNY.Look_4__it"));
+
+    EXPECT_EQ("abc.abc_1_10_100$def #!g",
+            android::audio_utils::stringutils::toLowerSnakeCase(
+                    "ABC.abc_1_10_100$def #!g"));
+}
+
+TEST(audio_utils_string, ConvertToUpperSnakeCase) {
+    EXPECT_EQ("CAMEL_CASE.AND_SNAKE_CASE.4FUN.2FUNNY.LOOK_4_IT",
+            android::audio_utils::stringutils::toUpperSnakeCase(
+                    "camel_case.AndSnake_Case.4Fun.2FUNNY.Look_4__it"));
+
+    EXPECT_EQ("ABC.ABC_1_10_100$DEF #!G",
+            android::audio_utils::stringutils::toUpperSnakeCase(
+                    "ABC.abc_1_10_100$def #!g"));
+}
+
+TEST(audio_utils_string, PreserveDigitSequence) {
+    EXPECT_EQ("CamelCase10_100",
+            android::audio_utils::stringutils::toUpperCamelCase("camel_case10_100"));
+    EXPECT_EQ("camelCase10_100",
+            android::audio_utils::stringutils::toLowerCamelCase("camel_case10_100"));
+}
+
+TEST(audio_utils_string, appendWithReplacement_empty) {
+    std::string s("");
+    android::audio_utils::stringutils::appendWithReplacement(s, "", '|', '+');
+    EXPECT_EQ("", s);
+}
+
+TEST(audio_utils_string, appendWithReplacement_basic) {
+    std::string s("hello");
+    android::audio_utils::stringutils::appendWithReplacement(s, "+||", '|', '+');
+    EXPECT_EQ("hello+++", s);
+}
+
+TEST(audio_utils_string, appendWithReplacement_copy) {
+    std::string s("hello");
+    android::audio_utils::stringutils::appendWithReplacement(s, " world", '|', '+');
+    EXPECT_EQ("hello world", s);
+}
\ No newline at end of file
diff --git a/audio_utils/tests/audio_trace_tests.cpp b/audio_utils/tests/audio_trace_tests.cpp
new file mode 100644
index 00000000..d2305929
--- /dev/null
+++ b/audio_utils/tests/audio_trace_tests.cpp
@@ -0,0 +1,45 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+#include <audio_utils/Trace.h>
+
+#include <gtest/gtest.h>
+
+TEST(trace_object, basic) {
+    android::audio_utils::trace::Object obj;
+
+    EXPECT_TRUE(obj.empty());
+    obj.set("one", 10);
+    EXPECT_FALSE(obj.empty());
+
+    auto trace = obj.toTrace();
+
+    EXPECT_NE(trace.find("one"), std::string::npos);
+    EXPECT_NE(trace.find("10"), std::string::npos);
+    EXPECT_EQ("{ one=10 }", trace);
+
+    obj.set("two", "twenty");
+    auto trace2 = obj.toTrace();
+    EXPECT_NE(trace2.find("one"), std::string::npos);
+    EXPECT_NE(trace2.find("10"), std::string::npos);
+    EXPECT_NE(trace2.find("two"), std::string::npos);
+    EXPECT_NE(trace2.find("twenty"), std::string::npos);
+    EXPECT_EQ("{ one=10 two=\"twenty\" }", trace2);
+
+    obj.clear();
+    EXPECT_TRUE(obj.empty());
+    EXPECT_EQ("{  }", obj.toTrace());
+}
diff --git a/audio_utils/tests/mel_processor_tests.cpp b/audio_utils/tests/mel_processor_tests.cpp
index ee063836..fc5dc301 100644
--- a/audio_utils/tests/mel_processor_tests.cpp
+++ b/audio_utils/tests/mel_processor_tests.cpp
@@ -52,9 +52,6 @@ const std::unordered_map<int32_t, float> kAWeightFResponse =
 // attenuation of 1kHz this will result to approx. kFilterAccuracy/2 percent accuracy
 constexpr float kFilterAccuracy = 2.f;
 
-// TODO(b/276849537): should replace this with proper synchornization
-constexpr size_t kCallbackTimeoutInMs = 20;
-
 class MelCallbackMock : public MelProcessor::MelCallback {
 public:
     MOCK_METHOD(void, onNewMelValues, (const std::vector<float>&, size_t, size_t,
@@ -125,7 +122,7 @@ TEST_P(MelProcessorFixtureTest, CheckNumberOfCallbacks) {
                 onNewMelValues(_, _, Le(size_t{2}), Eq(mDeviceId), Eq(true))).Times(1);
 
     EXPECT_GT(mProcessor->process(mBuffer.data(), mBuffer.size() * sizeof(float)), 0);
-    std::this_thread::sleep_for(std::chrono::milliseconds(kCallbackTimeoutInMs));
+    mProcessor->drainAndWait();
 }
 
 TEST_P(MelProcessorFixtureTest, CheckAWeightingFrequency) {
@@ -151,7 +148,7 @@ TEST_P(MelProcessorFixtureTest, CheckAWeightingFrequency) {
         });
 
     EXPECT_GT(mProcessor->process(mBuffer.data(), mBuffer.size() * sizeof(float)), 0);
-    std::this_thread::sleep_for(std::chrono::milliseconds(kCallbackTimeoutInMs));
+    mProcessor->drainAndWait();
 }
 
 TEST_P(MelProcessorFixtureTest, AttenuationCheck) {
@@ -188,7 +185,8 @@ TEST_P(MelProcessorFixtureTest, AttenuationCheck) {
                                   mSampleRate * mMaxMelsCallback * sizeof(float)), 0);
     EXPECT_GT(processorAttenuation->process(bufferAttenuation.data(),
                                             mSampleRate * mMaxMelsCallback * sizeof(float)), 0);
-    std::this_thread::sleep_for(std::chrono::milliseconds(kCallbackTimeoutInMs));
+    mProcessor->drainAndWait();
+    processorAttenuation->drainAndWait();
     // with attenuation for some frequencies the MEL callback does not exceed the RS1 threshold
     if (melAttenuation > 0.f) {
         EXPECT_EQ(melNoAttenuation - melAttenuation, attenuationDB);
diff --git a/audio_utils/tests/run_remote_tests.cpp b/audio_utils/tests/run_remote_tests.cpp
new file mode 100644
index 00000000..a3b31874
--- /dev/null
+++ b/audio_utils/tests/run_remote_tests.cpp
@@ -0,0 +1,53 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+#include <audio_utils/RunRemote.h>
+#include <gtest/gtest.h>
+#include <memory>
+
+static void WorkerThread(android::audio_utils::RunRemote& runRemote) {
+    while (true) {
+        const int c = runRemote.getc();
+        switch (c) {
+            case 'a':
+                runRemote.putc('a');  // send ack
+                break;
+            case 'b':
+                runRemote.putc('b');
+                break;
+            default:
+                runRemote.putc('x');
+                break;
+        }
+    }
+}
+
+TEST(RunRemote, basic) {
+    auto remoteWorker = std::make_shared<android::audio_utils::RunRemote>(WorkerThread);
+    remoteWorker->run();
+
+    remoteWorker->putc('a');
+    EXPECT_EQ('a', remoteWorker->getc());
+
+    remoteWorker->putc('b');
+    EXPECT_EQ('b', remoteWorker->getc());
+
+    remoteWorker->putc('c');
+    EXPECT_EQ('x', remoteWorker->getc());
+
+    remoteWorker->stop();
+    EXPECT_EQ(-1, remoteWorker->getc());  // remote closed
+}
diff --git a/camera/Android.bp b/camera/Android.bp
index ef490d5a..cc42218f 100644
--- a/camera/Android.bp
+++ b/camera/Android.bp
@@ -66,7 +66,7 @@ cc_library_shared {
     local_include_dirs: ["include"],
 
     static_libs: [
-        "android.hardware.camera.metadata-V3-ndk",
+        "android.hardware.camera.metadata-V4-ndk",
     ],
     shared_libs: [
         "libcamera2ndk",
diff --git a/camera/docs/ACameraMetadata.mako b/camera/docs/ACameraMetadata.mako
index d62fcc3e..ffbad4b8 100644
--- a/camera/docs/ACameraMetadata.mako
+++ b/camera/docs/ACameraMetadata.mako
@@ -20,11 +20,12 @@
 % for outer_namespace in metadata.outer_namespaces: ## assumes single 'android' namespace
   % for section in outer_namespace.sections:
     % if section.find_first(lambda x: isinstance(x, metadata_model.Entry) and x.kind == kind_name) and \
-         any_visible(section, kind_name, ('public','ndk_public') ):
+         any_visible(section, kind_name, ('public','ndk_public','fwk_public','fwk_ndk_public') ):
       % for inner_namespace in get_children_by_filtering_kind(section, kind_name, 'namespaces'):
 ## We only support 1 level of inner namespace, i.e. android.a.b and android.a.b.c works, but not android.a.b.c.d
 ## If we need to support more, we should use a recursive function here instead.. but the indentation gets trickier.
-        % for entry in filter_visibility(inner_namespace.merged_entries, ('public','ndk_public')):
+        % for entry in filter_visibility(inner_namespace.merged_entries, ('public','ndk_public',\
+	      'fwk_public','fwk_ndk_public')):
           % if not entry.synthetic:
         case ${ndk(entry.name) | csym}:
           % else:
@@ -34,7 +35,7 @@
     % endfor
     % for entry in filter_visibility( \
         get_children_by_filtering_kind(section, kind_name, 'merged_entries'), \
-                                         ('public','ndk_public')):
+                                         ('public','ndk_public','fwk_public','fwk_ndk_public')):
       % if not entry.synthetic:
         case ${ndk(entry.name) | csym}:
       % endif
diff --git a/camera/docs/CameraDeviceInfo.mako b/camera/docs/CameraDeviceInfo.mako
index de575917..beae4b46 100644
--- a/camera/docs/CameraDeviceInfo.mako
+++ b/camera/docs/CameraDeviceInfo.mako
@@ -25,7 +25,7 @@
 % for sec in find_all_sections(metadata):
   % for entry in find_unique_entries(sec):
     % if entry.kind == 'static' and entry.visibility in \
-            ("public", "java_public", "fwk_java_public"):
+            ("public", "java_public", "fwk_java_public", "fwk_public"):
       % if not entry.aconfig_flag:
         charsKeyNames.add(CameraCharacteristics.${jkey_identifier(entry.name)}.getName());
       % else:
diff --git a/camera/docs/CameraMetadataEnums.mako b/camera/docs/CameraMetadataEnums.mako
index 9ecc746b..cbc74e72 100644
--- a/camera/docs/CameraMetadataEnums.mako
+++ b/camera/docs/CameraMetadataEnums.mako
@@ -38,7 +38,8 @@ ${value.notes | javadoc(metadata)}\
 ${value.sdk_notes | javadoc(metadata)}\
     % endif
      * @see ${target_class}#${entry.name | jkey_identifier}
-    % if entry.applied_visibility in ('hidden', 'ndk_public', 'extension') or value.hidden:
+    % if entry.applied_visibility in ('hidden', 'ndk_public', 'fwk_only', 'extension')\
+          or value.hidden:
      * @hide
     %endif
     % if value.deprecated:
@@ -65,12 +66,12 @@ ${value.sdk_notes | javadoc(metadata)}\
   % for section in outer_namespace.sections:
     % if section.find_first(lambda x: isinstance(x, metadata_model.Entry) and x.kind == xml_name) and \
          any_visible(section, xml_name, ('public','hidden', 'ndk_public', 'java_public', \
-         'fwk_java_public', 'extension') ):
+         'fwk_java_public', 'fwk_public', 'fwk_only', 'extension') ):
       % for inner_namespace in get_children_by_filtering_kind(section, xml_name, 'namespaces'):
 ## We only support 1 level of inner namespace, i.e. android.a.b and android.a.b.c works, but not android.a.b.c.d
 ## If we need to support more, we should use a recursive function here instead.. but the indentation gets trickier.
         % for entry in filter_visibility(inner_namespace.entries, ('hidden','public', 'ndk_public', \
-        'java_public', 'fwk_pubic', 'extension')):
+        'java_public', 'fwk_pubic', 'fwk_only', 'extension')):
           % if entry.enum \
               and not (entry.typedef and entry.typedef.languages.get('java')) \
               and not entry.is_clone():
@@ -80,7 +81,8 @@ ${generate_enum(entry, target_class)}\
       % endfor
       % for entry in filter_visibility( \
           get_children_by_filtering_kind(section, xml_name, 'entries'), \
-              ('hidden', 'public', 'ndk_public', 'java_public', 'fwk_java_public', 'extension')):
+              ('hidden', 'public', 'ndk_public', 'java_public', 'fwk_java_public', 'fwk_public', \
+              'fwk_only', 'extension')):
         % if entry.enum \
              and not (entry.typedef and entry.typedef.languages.get('java')) \
              and not entry.is_clone():
diff --git a/camera/docs/CameraMetadataKeys.mako b/camera/docs/CameraMetadataKeys.mako
index f28f293d..1de389ac 100644
--- a/camera/docs/CameraMetadataKeys.mako
+++ b/camera/docs/CameraMetadataKeys.mako
@@ -55,17 +55,21 @@ ${concatenated_info | javadoc(metadata)}\
      * @deprecated
 ${entry.deprecation_description | javadoc(metadata)}
   % endif
-  % if entry.applied_visibility in ('hidden', 'ndk_public', 'fwk_only', 'extension'):
+  % if entry.applied_visibility in ('hidden', 'ndk_public', 'fwk_only', 'extension', 'fwk_system_public'):
      * @hide
   % endif
      */
   % if entry.deprecated:
     @Deprecated
   % endif
-  % if entry.applied_visibility in ('public', 'java_public', 'fwk_java_public'):
+  % if entry.applied_visibility in ('public', 'java_public', 'fwk_java_public', 'fwk_public'):
     @PublicKey
     @NonNull
   % endif
+  % if entry.applied_visibility == 'fwk_system_public':
+    @SystemApi
+    @NonNull
+  % endif
   % if entry.synthetic:
     @SyntheticKey
   % endif
@@ -84,17 +88,21 @@ ${entry.deprecation_description | javadoc(metadata)}
 % for outer_namespace in metadata.outer_namespaces: ## assumes single 'android' namespace
   % for section in outer_namespace.sections:
     % if section.find_first(lambda x: isinstance(x, metadata_model.Entry) and x.kind == xml_name) and \
-         any_visible(section, xml_name, ('public','hidden','ndk_public','java_public','fwk_only','fwk_java_public','extension') ):
+         any_visible(section, xml_name, ('public','hidden','ndk_public','java_public','fwk_only',\
+             'fwk_java_public','fwk_public','extension','fwk_system_public') ):
       % for inner_namespace in get_children_by_filtering_kind(section, xml_name, 'namespaces'):
 ## We only support 1 level of inner namespace, i.e. android.a.b and android.a.b.c works, but not android.a.b.c.d
 ## If we need to support more, we should use a recursive function here instead.. but the indentation gets trickier.
-        % for entry in filter_visibility(inner_namespace.merged_entries, ('hidden','public','ndk_public','java_public','fwk_only','fwk_java_public','extension')):
+        % for entry in filter_visibility(inner_namespace.merged_entries, ('hidden','public',\
+              'ndk_public','java_public','fwk_only','fwk_java_public','fwk_public',\
+              'extension','fwk_system_public')):
 ${generate_key(entry)}
        % endfor
     % endfor
     % for entry in filter_visibility( \
         get_children_by_filtering_kind(section, xml_name, 'merged_entries'), \
-               ('hidden', 'public', 'ndk_public', 'java_public', 'fwk_only', 'fwk_java_public','extension')):
+               ('hidden', 'public', 'ndk_public', 'java_public', 'fwk_only', 'fwk_java_public',\
+               'fwk_public','extension','fwk_system_public')):
 ${generate_key(entry)}
     % endfor
     % endif
diff --git a/camera/docs/CaptureResultTest.mako b/camera/docs/CaptureResultTest.mako
index fce1ca47..a111fab7 100644
--- a/camera/docs/CaptureResultTest.mako
+++ b/camera/docs/CaptureResultTest.mako
@@ -24,7 +24,8 @@
         ArrayList<CaptureResult.Key<?>> resultKeys = new ArrayList<CaptureResult.Key<?>>();
 % for sec in find_all_sections(metadata):
   % for entry in find_unique_entries(sec):
-    % if entry.kind == 'dynamic' and entry.visibility in ("public", "java_public"):
+    % if entry.kind == 'dynamic' and entry.visibility in ("public", "java_public",\
+          "fwk_java_public", "fwk_public"):
       % if not entry.aconfig_flag:
         resultKeys.add(CaptureResult.${jkey_identifier(entry.name)});
       % else:
diff --git a/camera/docs/aidl/CameraMetadataTag.mako b/camera/docs/aidl/CameraMetadataTag.mako
index 8d400de8..db95baeb 100644
--- a/camera/docs/aidl/CameraMetadataTag.mako
+++ b/camera/docs/aidl/CameraMetadataTag.mako
@@ -57,7 +57,12 @@ enum CameraMetadataTag {
 <% gap = False %>\
 % for sec_idx,sec in enumerate(find_all_sections_filtered(metadata, ('extension'))):
   % for idx,entry in enumerate(remove_synthetic(find_unique_entries(sec))):
-    % if entry.visibility in ('fwk_only', 'fwk_java_public'):
+    % if idx == 0:
+<% gap = False %>\
+<% curIdx = sec_idx << 16 %>\
+    % endif
+    % if entry.visibility in ('fwk_only', 'fwk_java_public', 'fwk_public', 'fwk_system_public',\
+          'fwk_ndk_public'):
 <% gap = True %>\
 <% curIdx += 1 %>\
 <% continue %>\
@@ -70,17 +75,14 @@ ${entry.description | hidldoc(metadata)}\
     % endif
      */
     % if idx == 0:
-<% gap = False %>\
-<% curIdx = sec_idx << 16 %>\
     ${entry.name + " =" | csym} CameraMetadataSectionStart.${path_name(find_parent_section(entry)) | csym}_START,
     % elif gap:
 <% gap = False %>\
-<% curIdx += 1 %>\
     ${entry.name | csym} = ${curIdx},
     % else:
-<% curIdx += 1 %>\
     ${entry.name + "," | csym}
     % endif
+<% curIdx += 1 %>\
   % endfor
 %endfor
 }
diff --git a/camera/docs/camera_device_info.mako b/camera/docs/camera_device_info.mako
index dadf1285..0923d0b7 100644
--- a/camera/docs/camera_device_info.mako
+++ b/camera/docs/camera_device_info.mako
@@ -128,7 +128,8 @@ message CameraDeviceInfo {
   idx = section_idx * pow(2,16)
 %>\
 % for entry in find_unique_entries(sec):
-% if entry.kind == 'static' and entry.visibility in ("public", "java_public", "fwk_java_public"):
+% if entry.kind == 'static' and entry.visibility in ("public", "java_public",\
+      "fwk_java_public", "fwk_public"):
     ${protobuf_type(entry)} ${protobuf_name(entry)} = ${idx};
 <%
     idx += 1
diff --git a/camera/docs/camera_device_info.proto b/camera/docs/camera_device_info.proto
index 3c58eda2..ac8259c7 100644
--- a/camera/docs/camera_device_info.proto
+++ b/camera/docs/camera_device_info.proto
@@ -120,6 +120,8 @@ message CameraDeviceInfo {
 
     // Start of codegen fields
     repeated int32 android_colorCorrection_availableAberrationModes = 65536;
+    optional RangeInt android_colorCorrection_colorTemperatureRange = 65537;
+    repeated int32 android_colorCorrection_availableModes = 65538;
     repeated int32 android_control_aeAvailableAntibandingModes = 131072;
     repeated int32 android_control_aeAvailableModes = 131073;
     repeated RangeInt android_control_aeAvailableTargetFpsRanges = 131074;
@@ -142,6 +144,7 @@ message CameraDeviceInfo {
     repeated int32 android_control_availableSettingsOverrides = 131091;
     optional bool android_control_autoframingAvailable = 131092;
     optional RangeFloat android_control_lowLightBoostInfoLuminanceRange = 131093;
+    repeated int32 android_control_aeAvailablePriorityModes = 131094;
     repeated int32 android_edge_availableEdgeModes = 262144;
     optional int32 android_flash_singleStrengthMaxLevel = 327680;
     optional int32 android_flash_singleStrengthDefaultLevel = 327681;
diff --git a/camera/docs/docs.html b/camera/docs/docs.html
index 88c6bfc4..4d45e207 100644
--- a/camera/docs/docs.html
+++ b/camera/docs/docs.html
@@ -123,6 +123,10 @@
             ><a href="#controls_android.colorCorrection.gains">android.colorCorrection.gains</a></li>
             <li
             ><a href="#controls_android.colorCorrection.aberrationMode">android.colorCorrection.aberrationMode</a></li>
+            <li
+            ><a href="#controls_android.colorCorrection.colorTemperature">android.colorCorrection.colorTemperature</a></li>
+            <li
+            ><a href="#controls_android.colorCorrection.colorTint">android.colorCorrection.colorTint</a></li>
           </ul>
         </li>
         <li>
@@ -136,6 +140,10 @@
             ><a href="#dynamic_android.colorCorrection.gains">android.colorCorrection.gains</a></li>
             <li
             ><a href="#dynamic_android.colorCorrection.aberrationMode">android.colorCorrection.aberrationMode</a></li>
+            <li
+            ><a href="#dynamic_android.colorCorrection.colorTemperature">android.colorCorrection.colorTemperature</a></li>
+            <li
+            ><a href="#dynamic_android.colorCorrection.colorTint">android.colorCorrection.colorTint</a></li>
           </ul>
         </li>
         <li>
@@ -143,6 +151,10 @@
           <ul class="toc_section">
             <li
             ><a href="#static_android.colorCorrection.availableAberrationModes">android.colorCorrection.availableAberrationModes</a></li>
+            <li
+            ><a href="#static_android.colorCorrection.colorTemperatureRange">android.colorCorrection.colorTemperatureRange</a></li>
+            <li
+            ><a href="#static_android.colorCorrection.availableModes">android.colorCorrection.availableModes</a></li>
           </ul>
         </li>
       </ul> <!-- toc_section -->
@@ -207,6 +219,10 @@
             ><a href="#controls_android.control.settingsOverride">android.control.settingsOverride</a></li>
             <li
             ><a href="#controls_android.control.autoframing">android.control.autoframing</a></li>
+            <li
+            ><a href="#controls_android.control.zoomMethod">android.control.zoomMethod</a></li>
+            <li
+            ><a href="#controls_android.control.aePriorityMode">android.control.aePriorityMode</a></li>
           </ul>
         </li>
         <li>
@@ -268,6 +284,8 @@
             ><a href="#static_android.control.autoframingAvailable">android.control.autoframingAvailable</a></li>
             <li
             ><a href="#static_android.control.lowLightBoostInfoLuminanceRange">android.control.lowLightBoostInfoLuminanceRange</a></li>
+            <li
+            ><a href="#static_android.control.aeAvailablePriorityModes">android.control.aeAvailablePriorityModes</a></li>
           </ul>
         </li>
         <li>
@@ -341,6 +359,10 @@
             ><a href="#dynamic_android.control.autoframingState">android.control.autoframingState</a></li>
             <li
             ><a href="#dynamic_android.control.lowLightBoostState">android.control.lowLightBoostState</a></li>
+            <li
+            ><a href="#dynamic_android.control.zoomMethod">android.control.zoomMethod</a></li>
+            <li
+            ><a href="#dynamic_android.control.aePriorityMode">android.control.aePriorityMode</a></li>
           </ul>
         </li>
       </ul> <!-- toc_section -->
@@ -1420,6 +1442,18 @@
             ><a href="#static_android.heic.availableHeicMinFrameDurationsMaximumResolution">android.heic.availableHeicMinFrameDurationsMaximumResolution</a></li>
             <li
             ><a href="#static_android.heic.availableHeicStallDurationsMaximumResolution">android.heic.availableHeicStallDurationsMaximumResolution</a></li>
+            <li
+            ><a href="#static_android.heic.availableHeicUltraHdrStreamConfigurations">android.heic.availableHeicUltraHdrStreamConfigurations</a></li>
+            <li
+            ><a href="#static_android.heic.availableHeicUltraHdrMinFrameDurations">android.heic.availableHeicUltraHdrMinFrameDurations</a></li>
+            <li
+            ><a href="#static_android.heic.availableHeicUltraHdrStallDurations">android.heic.availableHeicUltraHdrStallDurations</a></li>
+            <li
+            ><a href="#static_android.heic.availableHeicUltraHdrStreamConfigurationsMaximumResolution">android.heic.availableHeicUltraHdrStreamConfigurationsMaximumResolution</a></li>
+            <li
+            ><a href="#static_android.heic.availableHeicUltraHdrMinFrameDurationsMaximumResolution">android.heic.availableHeicUltraHdrMinFrameDurationsMaximumResolution</a></li>
+            <li
+            ><a href="#static_android.heic.availableHeicUltraHdrStallDurationsMaximumResolution">android.heic.availableHeicUltraHdrStallDurationsMaximumResolution</a></li>
           </ul>
         </li>
       </ul> <!-- toc_section -->
@@ -1457,6 +1491,8 @@
             ><a href="#dynamic_android.extension.currentType">android.extension.currentType</a></li>
             <li
             ><a href="#dynamic_android.extension.strength">android.extension.strength</a></li>
+            <li
+            ><a href="#dynamic_android.extension.nightModeIndicator">android.extension.nightModeIndicator</a></li>
           </ul>
         </li>
       </ul> <!-- toc_section -->
@@ -1483,6 +1519,49 @@
         </li>
       </ul> <!-- toc_section -->
     </li>
+    <li>
+      <span class="toc_section_header"><a href="#section_sharedSession">sharedSession</a></span>
+      <ul class="toc_section">
+        <li>
+          <span class="toc_kind_header">static</span>
+          <ul class="toc_section">
+            <li
+            ><a href="#static_android.sharedSession.colorSpace">android.sharedSession.colorSpace</a></li>
+            <li
+            ><a href="#static_android.sharedSession.outputConfigurations">android.sharedSession.outputConfigurations</a></li>
+            <li
+            ><a href="#static_android.sharedSession.configuration">android.sharedSession.configuration</a></li>
+          </ul>
+        </li>
+      </ul> <!-- toc_section -->
+    </li>
+    <li>
+      <span class="toc_section_header"><a href="#section_desktopEffects">desktopEffects</a></span>
+      <ul class="toc_section">
+        <li>
+          <span class="toc_kind_header">static</span>
+          <ul class="toc_section">
+            <li
+            ><a href="#static_android.desktopEffects.capabilities">android.desktopEffects.capabilities</a></li>
+            <li
+            ><a href="#static_android.desktopEffects.backgroundBlurModes">android.desktopEffects.backgroundBlurModes</a></li>
+          </ul>
+        </li>
+        <li>
+          <span class="toc_kind_header">controls</span>
+          <ul class="toc_section">
+            <li
+            ><a href="#controls_android.desktopEffects.backgroundBlurMode">android.desktopEffects.backgroundBlurMode</a></li>
+            <li
+            ><a href="#controls_android.desktopEffects.faceRetouchMode">android.desktopEffects.faceRetouchMode</a></li>
+            <li
+            ><a href="#controls_android.desktopEffects.faceRetouchStrength">android.desktopEffects.faceRetouchStrength</a></li>
+            <li
+            ><a href="#controls_android.desktopEffects.portraitRelightMode">android.desktopEffects.portraitRelightMode</a></li>
+          </ul>
+        </li>
+      </ul> <!-- toc_section -->
+    </li>
   </ul>
 
 
@@ -1577,6 +1656,15 @@ the specified white balance pipeline may be applied.<wbr/></p>
 the camera device uses the last frame's AWB values
 (or defaults if AWB has never been run).<wbr/></p></span>
                   </li>
+                  <li>
+                    <span class="entry_type_enum_name">CCT (v3.11)</span>
+                    <span class="entry_type_enum_notes"><p>Use
+<a href="#controls_android.colorCorrection.colorTemperature">android.<wbr/>color<wbr/>Correction.<wbr/>color<wbr/>Temperature</a> and
+<a href="#controls_android.colorCorrection.colorTint">android.<wbr/>color<wbr/>Correction.<wbr/>color<wbr/>Tint</a> to adjust the white balance based
+on correlated color temperature.<wbr/></p>
+<p>If AWB is enabled with <code><a href="#controls_android.control.awbMode">android.<wbr/>control.<wbr/>awb<wbr/>Mode</a> != OFF</code>,<wbr/> then
+CCT is ignored.<wbr/></p></span>
+                  </li>
                 </ul>
 
             </td> <!-- entry_type -->
@@ -1590,6 +1678,10 @@ sensor's native color into linear sRGB color.<wbr/></p>
             </td>
 
             <td class="entry_range">
+              <p>Starting from API level 36,<wbr/> <a href="#static_android.colorCorrection.availableModes">android.<wbr/>color<wbr/>Correction.<wbr/>available<wbr/>Modes</a>
+can be used to check the list of supported values.<wbr/> Prior to API level 36,<wbr/>
+TRANSFORM_<wbr/>MATRIX,<wbr/> HIGH_<wbr/>QUALITY,<wbr/> and FAST are guaranteed to be available
+as valid modes on devices that support this key.<wbr/></p>
             </td>
 
             <td class="entry_hal_version">
@@ -1886,6 +1978,128 @@ applying aberration correction.<wbr/></p>
           <tr class="entry_spacer"><td class="entry_spacer" colspan="7"></td></tr>
            <!-- end of entry -->
         
+                
+          <tr class="entry" id="controls_android.colorCorrection.colorTemperature">
+            <td class="entry_name
+             " rowspan="3">
+              android.<wbr/>color<wbr/>Correction.<wbr/>color<wbr/>Temperature
+            </td>
+            <td class="entry_type">
+                <span class="entry_type_name">int32</span>
+
+              <span class="entry_type_visibility"> [public]</span>
+
+
+
+
+
+
+            </td> <!-- entry_type -->
+
+            <td class="entry_description">
+              <p>Specifies the color temperature for CCT mode in Kelvin
+to adjust the white balance of the image.<wbr/></p>
+            </td>
+
+            <td class="entry_units">
+              Kelvin
+            </td>
+
+            <td class="entry_range">
+              <p><a href="#static_android.colorCorrection.colorTemperatureRange">android.<wbr/>color<wbr/>Correction.<wbr/>color<wbr/>Temperature<wbr/>Range</a></p>
+            </td>
+
+            <td class="entry_hal_version">
+              <p>3.<wbr/>11</p>
+            </td>
+
+            <td class="entry_tags">
+            </td>
+
+          </tr>
+          <tr class="entries_header">
+            <th class="th_details" colspan="6">Details</th>
+          </tr>
+          <tr class="entry_cont">
+            <td class="entry_details" colspan="6">
+              <p>Sets the color temperature in Kelvin units for when
+<a href="#controls_android.colorCorrection.mode">android.<wbr/>color<wbr/>Correction.<wbr/>mode</a> is CCT to adjust the
+white balance of the image.<wbr/></p>
+<p>If CCT mode is enabled without a requested color temperature,<wbr/>
+a default value will be set by the camera device.<wbr/> The default value can be
+retrieved by checking the corresponding capture result.<wbr/> Color temperatures
+requested outside the advertised <a href="#static_android.colorCorrection.colorTemperatureRange">android.<wbr/>color<wbr/>Correction.<wbr/>color<wbr/>Temperature<wbr/>Range</a>
+will be clamped.<wbr/></p>
+            </td>
+          </tr>
+
+
+          <tr class="entry_spacer"><td class="entry_spacer" colspan="7"></td></tr>
+           <!-- end of entry -->
+        
+                
+          <tr class="entry" id="controls_android.colorCorrection.colorTint">
+            <td class="entry_name
+             " rowspan="3">
+              android.<wbr/>color<wbr/>Correction.<wbr/>color<wbr/>Tint
+            </td>
+            <td class="entry_type">
+                <span class="entry_type_name">int32</span>
+
+              <span class="entry_type_visibility"> [public]</span>
+
+
+
+
+
+
+            </td> <!-- entry_type -->
+
+            <td class="entry_description">
+              <p>Specifies the color tint for CCT mode to adjust the white
+balance of the image.<wbr/></p>
+            </td>
+
+            <td class="entry_units">
+              D_<wbr/>uv defined as the distance from the Planckian locus on the CIE 1931 xy
+          chromaticity diagram,<wbr/> with the range ±50 mapping to ±0.<wbr/>01 D_<wbr/>uv
+            </td>
+
+            <td class="entry_range">
+              <p>The supported range,<wbr/> -50 to +50,<wbr/> corresponds to a D_<wbr/>uv distance
+of ±0.<wbr/>01 below and above the Planckian locus.<wbr/> Some camera devices may have
+limitations to achieving the full ±0.<wbr/>01 D_<wbr/>uv range at some color temperatures
+(e.<wbr/>g.,<wbr/> below 1500K).<wbr/> In these cases,<wbr/> the applied D_<wbr/>uv value may be clamped and
+the actual color tint will be reported in the <a href="#controls_android.colorCorrection.colorTint">android.<wbr/>color<wbr/>Correction.<wbr/>color<wbr/>Tint</a>
+result.<wbr/></p>
+            </td>
+
+            <td class="entry_hal_version">
+              <p>3.<wbr/>11</p>
+            </td>
+
+            <td class="entry_tags">
+            </td>
+
+          </tr>
+          <tr class="entries_header">
+            <th class="th_details" colspan="6">Details</th>
+          </tr>
+          <tr class="entry_cont">
+            <td class="entry_details" colspan="6">
+              <p>Sets the color tint for when <a href="#controls_android.colorCorrection.mode">android.<wbr/>color<wbr/>Correction.<wbr/>mode</a>
+is CCT to adjust the white balance of the image.<wbr/></p>
+<p>If CCT mode is enabled without a requested color tint,<wbr/>
+a default value will be set by the camera device.<wbr/> The default value can be
+retrieved by checking the corresponding capture result.<wbr/> Color tints requested
+outside the supported range will be clamped to the nearest limit (-50 or +50).<wbr/></p>
+            </td>
+          </tr>
+
+
+          <tr class="entry_spacer"><td class="entry_spacer" colspan="7"></td></tr>
+           <!-- end of entry -->
+        
         
 
       <!-- end of kind -->
@@ -1962,6 +2176,15 @@ the specified white balance pipeline may be applied.<wbr/></p>
 the camera device uses the last frame's AWB values
 (or defaults if AWB has never been run).<wbr/></p></span>
                   </li>
+                  <li>
+                    <span class="entry_type_enum_name">CCT (v3.11)</span>
+                    <span class="entry_type_enum_notes"><p>Use
+<a href="#controls_android.colorCorrection.colorTemperature">android.<wbr/>color<wbr/>Correction.<wbr/>color<wbr/>Temperature</a> and
+<a href="#controls_android.colorCorrection.colorTint">android.<wbr/>color<wbr/>Correction.<wbr/>color<wbr/>Tint</a> to adjust the white balance based
+on correlated color temperature.<wbr/></p>
+<p>If AWB is enabled with <code><a href="#controls_android.control.awbMode">android.<wbr/>control.<wbr/>awb<wbr/>Mode</a> != OFF</code>,<wbr/> then
+CCT is ignored.<wbr/></p></span>
+                  </li>
                 </ul>
 
             </td> <!-- entry_type -->
@@ -1975,6 +2198,10 @@ sensor's native color into linear sRGB color.<wbr/></p>
             </td>
 
             <td class="entry_range">
+              <p>Starting from API level 36,<wbr/> <a href="#static_android.colorCorrection.availableModes">android.<wbr/>color<wbr/>Correction.<wbr/>available<wbr/>Modes</a>
+can be used to check the list of supported values.<wbr/> Prior to API level 36,<wbr/>
+TRANSFORM_<wbr/>MATRIX,<wbr/> HIGH_<wbr/>QUALITY,<wbr/> and FAST are guaranteed to be available
+as valid modes on devices that support this key.<wbr/></p>
             </td>
 
             <td class="entry_hal_version">
@@ -2271,6 +2498,128 @@ applying aberration correction.<wbr/></p>
           <tr class="entry_spacer"><td class="entry_spacer" colspan="7"></td></tr>
            <!-- end of entry -->
         
+                
+          <tr class="entry" id="dynamic_android.colorCorrection.colorTemperature">
+            <td class="entry_name
+             " rowspan="3">
+              android.<wbr/>color<wbr/>Correction.<wbr/>color<wbr/>Temperature
+            </td>
+            <td class="entry_type">
+                <span class="entry_type_name">int32</span>
+
+              <span class="entry_type_visibility"> [public]</span>
+
+
+
+
+
+
+            </td> <!-- entry_type -->
+
+            <td class="entry_description">
+              <p>Specifies the color temperature for CCT mode in Kelvin
+to adjust the white balance of the image.<wbr/></p>
+            </td>
+
+            <td class="entry_units">
+              Kelvin
+            </td>
+
+            <td class="entry_range">
+              <p><a href="#static_android.colorCorrection.colorTemperatureRange">android.<wbr/>color<wbr/>Correction.<wbr/>color<wbr/>Temperature<wbr/>Range</a></p>
+            </td>
+
+            <td class="entry_hal_version">
+              <p>3.<wbr/>11</p>
+            </td>
+
+            <td class="entry_tags">
+            </td>
+
+          </tr>
+          <tr class="entries_header">
+            <th class="th_details" colspan="6">Details</th>
+          </tr>
+          <tr class="entry_cont">
+            <td class="entry_details" colspan="6">
+              <p>Sets the color temperature in Kelvin units for when
+<a href="#controls_android.colorCorrection.mode">android.<wbr/>color<wbr/>Correction.<wbr/>mode</a> is CCT to adjust the
+white balance of the image.<wbr/></p>
+<p>If CCT mode is enabled without a requested color temperature,<wbr/>
+a default value will be set by the camera device.<wbr/> The default value can be
+retrieved by checking the corresponding capture result.<wbr/> Color temperatures
+requested outside the advertised <a href="#static_android.colorCorrection.colorTemperatureRange">android.<wbr/>color<wbr/>Correction.<wbr/>color<wbr/>Temperature<wbr/>Range</a>
+will be clamped.<wbr/></p>
+            </td>
+          </tr>
+
+
+          <tr class="entry_spacer"><td class="entry_spacer" colspan="7"></td></tr>
+           <!-- end of entry -->
+        
+                
+          <tr class="entry" id="dynamic_android.colorCorrection.colorTint">
+            <td class="entry_name
+             " rowspan="3">
+              android.<wbr/>color<wbr/>Correction.<wbr/>color<wbr/>Tint
+            </td>
+            <td class="entry_type">
+                <span class="entry_type_name">int32</span>
+
+              <span class="entry_type_visibility"> [public]</span>
+
+
+
+
+
+
+            </td> <!-- entry_type -->
+
+            <td class="entry_description">
+              <p>Specifies the color tint for CCT mode to adjust the white
+balance of the image.<wbr/></p>
+            </td>
+
+            <td class="entry_units">
+              D_<wbr/>uv defined as the distance from the Planckian locus on the CIE 1931 xy
+          chromaticity diagram,<wbr/> with the range ±50 mapping to ±0.<wbr/>01 D_<wbr/>uv
+            </td>
+
+            <td class="entry_range">
+              <p>The supported range,<wbr/> -50 to +50,<wbr/> corresponds to a D_<wbr/>uv distance
+of ±0.<wbr/>01 below and above the Planckian locus.<wbr/> Some camera devices may have
+limitations to achieving the full ±0.<wbr/>01 D_<wbr/>uv range at some color temperatures
+(e.<wbr/>g.,<wbr/> below 1500K).<wbr/> In these cases,<wbr/> the applied D_<wbr/>uv value may be clamped and
+the actual color tint will be reported in the <a href="#controls_android.colorCorrection.colorTint">android.<wbr/>color<wbr/>Correction.<wbr/>color<wbr/>Tint</a>
+result.<wbr/></p>
+            </td>
+
+            <td class="entry_hal_version">
+              <p>3.<wbr/>11</p>
+            </td>
+
+            <td class="entry_tags">
+            </td>
+
+          </tr>
+          <tr class="entries_header">
+            <th class="th_details" colspan="6">Details</th>
+          </tr>
+          <tr class="entry_cont">
+            <td class="entry_details" colspan="6">
+              <p>Sets the color tint for when <a href="#controls_android.colorCorrection.mode">android.<wbr/>color<wbr/>Correction.<wbr/>mode</a>
+is CCT to adjust the white balance of the image.<wbr/></p>
+<p>If CCT mode is enabled without a requested color tint,<wbr/>
+a default value will be set by the camera device.<wbr/> The default value can be
+retrieved by checking the corresponding capture result.<wbr/> Color tints requested
+outside the supported range will be clamped to the nearest limit (-50 or +50).<wbr/></p>
+            </td>
+          </tr>
+
+
+          <tr class="entry_spacer"><td class="entry_spacer" colspan="7"></td></tr>
+           <!-- end of entry -->
+        
         
 
       <!-- end of kind -->
@@ -2375,6 +2724,124 @@ capture rate,<wbr/> then FAST and HIGH_<wbr/>QUALITY will generate the same outp
           <tr class="entry_spacer"><td class="entry_spacer" colspan="7"></td></tr>
            <!-- end of entry -->
         
+                
+          <tr class="entry" id="static_android.colorCorrection.colorTemperatureRange">
+            <td class="entry_name
+             " rowspan="3">
+              android.<wbr/>color<wbr/>Correction.<wbr/>color<wbr/>Temperature<wbr/>Range
+            </td>
+            <td class="entry_type">
+                <span class="entry_type_name">int32</span>
+                <span class="entry_type_container">x</span>
+
+                <span class="entry_type_array">
+                  2
+                </span>
+              <span class="entry_type_visibility"> [public as rangeInt]</span>
+
+
+
+
+
+
+            </td> <!-- entry_type -->
+
+            <td class="entry_description">
+              <p>The range of supported color temperature values for
+<a href="#controls_android.colorCorrection.colorTemperature">android.<wbr/>color<wbr/>Correction.<wbr/>color<wbr/>Temperature</a>.<wbr/></p>
+            </td>
+
+            <td class="entry_units">
+            </td>
+
+            <td class="entry_range">
+              <p>The minimum supported range will be [2856K,<wbr/>6500K].<wbr/> The maximum supported
+range will be [1000K,<wbr/>40000K].<wbr/></p>
+            </td>
+
+            <td class="entry_hal_version">
+              <p>3.<wbr/>11</p>
+            </td>
+
+            <td class="entry_tags">
+            </td>
+
+          </tr>
+          <tr class="entries_header">
+            <th class="th_details" colspan="6">Details</th>
+          </tr>
+          <tr class="entry_cont">
+            <td class="entry_details" colspan="6">
+              <p>This key lists the valid range of color temperature values for
+<a href="#controls_android.colorCorrection.colorTemperature">android.<wbr/>color<wbr/>Correction.<wbr/>color<wbr/>Temperature</a> supported by this camera device.<wbr/></p>
+<p>This key will be null on devices that do not support CCT mode for
+<a href="#controls_android.colorCorrection.mode">android.<wbr/>color<wbr/>Correction.<wbr/>mode</a>.<wbr/></p>
+            </td>
+          </tr>
+
+
+          <tr class="entry_spacer"><td class="entry_spacer" colspan="7"></td></tr>
+           <!-- end of entry -->
+        
+                
+          <tr class="entry" id="static_android.colorCorrection.availableModes">
+            <td class="entry_name
+             " rowspan="3">
+              android.<wbr/>color<wbr/>Correction.<wbr/>available<wbr/>Modes
+            </td>
+            <td class="entry_type">
+                <span class="entry_type_name">byte</span>
+                <span class="entry_type_container">x</span>
+
+                <span class="entry_type_array">
+                  n
+                </span>
+              <span class="entry_type_visibility"> [public as enumList]</span>
+
+
+
+
+                <div class="entry_type_notes">list of enums</div>
+
+
+            </td> <!-- entry_type -->
+
+            <td class="entry_description">
+              <p>List of color correction modes for <a href="#controls_android.colorCorrection.mode">android.<wbr/>color<wbr/>Correction.<wbr/>mode</a> that are
+supported by this camera device.<wbr/></p>
+            </td>
+
+            <td class="entry_units">
+            </td>
+
+            <td class="entry_range">
+              <p>Any value listed in <a href="#controls_android.colorCorrection.mode">android.<wbr/>color<wbr/>Correction.<wbr/>mode</a></p>
+            </td>
+
+            <td class="entry_hal_version">
+              <p>3.<wbr/>11</p>
+            </td>
+
+            <td class="entry_tags">
+            </td>
+
+          </tr>
+          <tr class="entries_header">
+            <th class="th_details" colspan="6">Details</th>
+          </tr>
+          <tr class="entry_cont">
+            <td class="entry_details" colspan="6">
+              <p>This key lists the valid modes for <a href="#controls_android.colorCorrection.mode">android.<wbr/>color<wbr/>Correction.<wbr/>mode</a>.<wbr/> If no
+color correction modes are available for a device,<wbr/> this key will be null.<wbr/></p>
+<p>Camera devices that have a FULL hardware level will always include at least
+FAST,<wbr/> HIGH_<wbr/>QUALITY,<wbr/> and TRANSFORM_<wbr/>MATRIX modes.<wbr/></p>
+            </td>
+          </tr>
+
+
+          <tr class="entry_spacer"><td class="entry_spacer" colspan="7"></td></tr>
+           <!-- end of entry -->
+        
         
 
       <!-- end of kind -->
@@ -2750,7 +3217,14 @@ with no flash control.<wbr/></p>
 <a href="#controls_android.sensor.sensitivity">android.<wbr/>sensor.<wbr/>sensitivity</a>,<wbr/> and
 <a href="#controls_android.sensor.frameDuration">android.<wbr/>sensor.<wbr/>frame<wbr/>Duration</a> are ignored.<wbr/> The
 application has control over the various
-android.<wbr/>flash.<wbr/>* fields.<wbr/></p></span>
+android.<wbr/>flash.<wbr/>* fields.<wbr/></p>
+<p>If the device supports manual flash strength control,<wbr/> i.<wbr/>e.,<wbr/>
+if <a href="#static_android.flash.singleStrengthMaxLevel">android.<wbr/>flash.<wbr/>single<wbr/>Strength<wbr/>Max<wbr/>Level</a> and
+<a href="#static_android.flash.torchStrengthMaxLevel">android.<wbr/>flash.<wbr/>torch<wbr/>Strength<wbr/>Max<wbr/>Level</a> are greater than 1,<wbr/> then
+the auto-exposure (AE) precapture metering sequence should be
+triggered for the configured flash mode and strength to avoid
+the image being incorrectly exposed at different
+<a href="#controls_android.flash.strengthLevel">android.<wbr/>flash.<wbr/>strength<wbr/>Level</a>.<wbr/></p></span>
                   </li>
                   <li>
                     <span class="entry_type_enum_name">ON_AUTO_FLASH (v3.2)</span>
@@ -2866,7 +3340,9 @@ auto-exposure routine is enabled,<wbr/> overriding the
 application's selected exposure time,<wbr/> sensor sensitivity,<wbr/>
 and frame duration (<a href="#controls_android.sensor.exposureTime">android.<wbr/>sensor.<wbr/>exposure<wbr/>Time</a>,<wbr/>
 <a href="#controls_android.sensor.sensitivity">android.<wbr/>sensor.<wbr/>sensitivity</a>,<wbr/> and
-<a href="#controls_android.sensor.frameDuration">android.<wbr/>sensor.<wbr/>frame<wbr/>Duration</a>).<wbr/> If one of the FLASH modes
+<a href="#controls_android.sensor.frameDuration">android.<wbr/>sensor.<wbr/>frame<wbr/>Duration</a>).<wbr/> If <a href="#controls_android.control.aePriorityMode">android.<wbr/>control.<wbr/>ae<wbr/>Priority<wbr/>Mode</a> is
+enabled,<wbr/> the relevant priority CaptureRequest settings will not be overridden.<wbr/>
+See <a href="#controls_android.control.aePriorityMode">android.<wbr/>control.<wbr/>ae<wbr/>Priority<wbr/>Mode</a> for more details.<wbr/> If one of the FLASH modes
 is selected,<wbr/> the camera device's flash unit controls are
 also overridden.<wbr/></p>
 <p>The FLASH modes are only available if the camera device
@@ -2877,6 +3353,13 @@ ON or OFF,<wbr/> and <a href="#controls_android.flash.mode">android.<wbr/>flash.
 camera device auto-exposure routine for the overridden
 fields for a given capture will be available in its
 CaptureResult.<wbr/></p>
+<p>When <a href="#controls_android.control.aeMode">android.<wbr/>control.<wbr/>ae<wbr/>Mode</a> is AE_<wbr/>MODE_<wbr/>ON and if the device
+supports manual flash strength control,<wbr/> i.<wbr/>e.,<wbr/>
+if <a href="#static_android.flash.singleStrengthMaxLevel">android.<wbr/>flash.<wbr/>single<wbr/>Strength<wbr/>Max<wbr/>Level</a> and
+<a href="#static_android.flash.torchStrengthMaxLevel">android.<wbr/>flash.<wbr/>torch<wbr/>Strength<wbr/>Max<wbr/>Level</a> are greater than 1,<wbr/> then
+the auto-exposure (AE) precapture metering sequence should be
+triggered to avoid the image being incorrectly exposed at
+different <a href="#controls_android.flash.strengthLevel">android.<wbr/>flash.<wbr/>strength<wbr/>Level</a>.<wbr/></p>
             </td>
           </tr>
 
@@ -2999,7 +3482,7 @@ mode.<wbr/></p>
 <a href="https://developer.android.com/reference/android/hardware/camera2/CameraMetadata.html#REQUEST_AVAILABLE_CAPABILITIES_ULTRA_HIGH_RESOLUTION_SENSOR">Camera<wbr/>Metadata#REQUEST_<wbr/>AVAILABLE_<wbr/>CAPABILITIES_<wbr/>ULTRA_<wbr/>HIGH_<wbr/>RESOLUTION_<wbr/>SENSOR</a>
 capability or devices where
 <a href="https://developer.android.com/reference/CameraCharacteristics.html#getAvailableCaptureRequestKeys">CameraCharacteristics#getAvailableCaptureRequestKeys</a>
-lists <a href="https://developer.android.com/reference/CaptureRequest.html#SENSOR_PIXEL_MODE"><a href="#controls_android.sensor.pixelMode">android.<wbr/>sensor.<wbr/>pixel<wbr/>Mode</a></a>
+lists <a href="#controls_android.sensor.pixelMode">android.<wbr/>sensor.<wbr/>pixel<wbr/>Mode</a>,<wbr/>
 <a href="#static_android.sensor.info.activeArraySizeMaximumResolution">android.<wbr/>sensor.<wbr/>info.<wbr/>active<wbr/>Array<wbr/>Size<wbr/>Maximum<wbr/>Resolution</a> /<wbr/>
 <a href="#static_android.sensor.info.preCorrectionActiveArraySizeMaximumResolution">android.<wbr/>sensor.<wbr/>info.<wbr/>pre<wbr/>Correction<wbr/>Active<wbr/>Array<wbr/>Size<wbr/>Maximum<wbr/>Resolution</a> must be used as the
 coordinate system for requests where <a href="#controls_android.sensor.pixelMode">android.<wbr/>sensor.<wbr/>pixel<wbr/>Mode</a> is set to
@@ -3526,7 +4009,7 @@ mode.<wbr/></p>
 <a href="https://developer.android.com/reference/android/hardware/camera2/CameraMetadata.html#REQUEST_AVAILABLE_CAPABILITIES_ULTRA_HIGH_RESOLUTION_SENSOR">Camera<wbr/>Metadata#REQUEST_<wbr/>AVAILABLE_<wbr/>CAPABILITIES_<wbr/>ULTRA_<wbr/>HIGH_<wbr/>RESOLUTION_<wbr/>SENSOR</a>
 capability or devices where
 <a href="https://developer.android.com/reference/CameraCharacteristics.html#getAvailableCaptureRequestKeys">CameraCharacteristics#getAvailableCaptureRequestKeys</a>
-lists <a href="https://developer.android.com/reference/CaptureRequest.html#SENSOR_PIXEL_MODE"><a href="#controls_android.sensor.pixelMode">android.<wbr/>sensor.<wbr/>pixel<wbr/>Mode</a></a>,<wbr/>
+lists <a href="#controls_android.sensor.pixelMode">android.<wbr/>sensor.<wbr/>pixel<wbr/>Mode</a>,<wbr/>
 <a href="#static_android.sensor.info.activeArraySizeMaximumResolution">android.<wbr/>sensor.<wbr/>info.<wbr/>active<wbr/>Array<wbr/>Size<wbr/>Maximum<wbr/>Resolution</a> /<wbr/>
 <a href="#static_android.sensor.info.preCorrectionActiveArraySizeMaximumResolution">android.<wbr/>sensor.<wbr/>info.<wbr/>pre<wbr/>Correction<wbr/>Active<wbr/>Array<wbr/>Size<wbr/>Maximum<wbr/>Resolution</a> must be used as the
 coordinate system for requests where <a href="#controls_android.sensor.pixelMode">android.<wbr/>sensor.<wbr/>pixel<wbr/>Mode</a> is set to
@@ -4033,7 +4516,7 @@ mode.<wbr/></p>
 <a href="https://developer.android.com/reference/android/hardware/camera2/CameraMetadata.html#REQUEST_AVAILABLE_CAPABILITIES_ULTRA_HIGH_RESOLUTION_SENSOR">Camera<wbr/>Metadata#REQUEST_<wbr/>AVAILABLE_<wbr/>CAPABILITIES_<wbr/>ULTRA_<wbr/>HIGH_<wbr/>RESOLUTION_<wbr/>SENSOR</a>
 capability or devices where
 <a href="https://developer.android.com/reference/CameraCharacteristics.html#getAvailableCaptureRequestKeys">CameraCharacteristics#getAvailableCaptureRequestKeys</a>
-lists <a href="https://developer.android.com/reference/CaptureRequest.html#SENSOR_PIXEL_MODE"><a href="#controls_android.sensor.pixelMode">android.<wbr/>sensor.<wbr/>pixel<wbr/>Mode</a></a>,<wbr/>
+lists <a href="#controls_android.sensor.pixelMode">android.<wbr/>sensor.<wbr/>pixel<wbr/>Mode</a>,<wbr/>
 <a href="#static_android.sensor.info.activeArraySizeMaximumResolution">android.<wbr/>sensor.<wbr/>info.<wbr/>active<wbr/>Array<wbr/>Size<wbr/>Maximum<wbr/>Resolution</a> /<wbr/>
 <a href="#static_android.sensor.info.preCorrectionActiveArraySizeMaximumResolution">android.<wbr/>sensor.<wbr/>info.<wbr/>pre<wbr/>Correction<wbr/>Active<wbr/>Array<wbr/>Size<wbr/>Maximum<wbr/>Resolution</a> must be used as the
 coordinate system for requests where <a href="#controls_android.sensor.pixelMode">android.<wbr/>sensor.<wbr/>pixel<wbr/>Mode</a> is set to
@@ -5726,6 +6209,187 @@ transition can be immediate or smooth.<wbr/></p>
           <tr class="entry_spacer"><td class="entry_spacer" colspan="7"></td></tr>
            <!-- end of entry -->
         
+                
+          <tr class="entry" id="controls_android.control.zoomMethod">
+            <td class="entry_name
+             " rowspan="5">
+              android.<wbr/>control.<wbr/>zoom<wbr/>Method
+            </td>
+            <td class="entry_type">
+                <span class="entry_type_name entry_type_name_enum">byte</span>
+
+              <span class="entry_type_visibility"> [fwk_public]</span>
+
+
+              <span class="entry_type_hwlevel">[limited] </span>
+
+
+
+                <ul class="entry_type_enum">
+                  <li>
+                    <span class="entry_type_enum_name">AUTO (v3.11)</span>
+                    <span class="entry_type_enum_value">0</span>
+                    <span class="entry_type_enum_notes"><p>The camera device automatically detects whether the application does zoom with
+<a href="#controls_android.scaler.cropRegion">android.<wbr/>scaler.<wbr/>crop<wbr/>Region</a> or <a href="#controls_android.control.zoomRatio">android.<wbr/>control.<wbr/>zoom<wbr/>Ratio</a>,<wbr/> and in turn decides which
+metadata tag reflects the effective zoom level.<wbr/></p></span>
+                  </li>
+                  <li>
+                    <span class="entry_type_enum_name">ZOOM_RATIO (v3.11)</span>
+                    <span class="entry_type_enum_value">1</span>
+                    <span class="entry_type_enum_notes"><p>The application intends to control zoom via <a href="#controls_android.control.zoomRatio">android.<wbr/>control.<wbr/>zoom<wbr/>Ratio</a>,<wbr/> and
+the effective zoom level is reflected by <a href="#controls_android.control.zoomRatio">android.<wbr/>control.<wbr/>zoom<wbr/>Ratio</a> in capture results.<wbr/></p></span>
+                  </li>
+                </ul>
+
+            </td> <!-- entry_type -->
+
+            <td class="entry_description">
+              <p>Whether the application uses <a href="#controls_android.scaler.cropRegion">android.<wbr/>scaler.<wbr/>crop<wbr/>Region</a> or <a href="#controls_android.control.zoomRatio">android.<wbr/>control.<wbr/>zoom<wbr/>Ratio</a>
+to control zoom levels.<wbr/></p>
+            </td>
+
+            <td class="entry_units">
+            </td>
+
+            <td class="entry_range">
+            </td>
+
+            <td class="entry_hal_version">
+              <p>3.<wbr/>11</p>
+            </td>
+
+            <td class="entry_tags">
+            </td>
+
+          </tr>
+          <tr class="entries_header">
+            <th class="th_details" colspan="6">Details</th>
+          </tr>
+          <tr class="entry_cont">
+            <td class="entry_details" colspan="6">
+              <p>If set to AUTO,<wbr/> the camera device detects which capture request key the application uses
+to do zoom,<wbr/> <a href="#controls_android.scaler.cropRegion">android.<wbr/>scaler.<wbr/>crop<wbr/>Region</a> or <a href="#controls_android.control.zoomRatio">android.<wbr/>control.<wbr/>zoom<wbr/>Ratio</a>.<wbr/> If
+the application doesn't set android.<wbr/>scaler.<wbr/>zoom<wbr/>Ratio or sets it to 1.<wbr/>0 in the capture
+request,<wbr/> the effective zoom level is reflected in <a href="#controls_android.scaler.cropRegion">android.<wbr/>scaler.<wbr/>crop<wbr/>Region</a> in capture
+results.<wbr/> If <a href="#controls_android.control.zoomRatio">android.<wbr/>control.<wbr/>zoom<wbr/>Ratio</a> is set to values other than 1.<wbr/>0,<wbr/> the effective
+zoom level is reflected in <a href="#controls_android.control.zoomRatio">android.<wbr/>control.<wbr/>zoom<wbr/>Ratio</a>.<wbr/> AUTO is the default value
+for this control,<wbr/> and also the behavior of the OS before Android version
+<a href="https://developer.android.com/reference/android/os/Build.VERSION_CODES.html#BAKLAVA">BAKLAVA</a>.<wbr/></p>
+<p>If set to ZOOM_<wbr/>RATIO,<wbr/> the application explicitly specifies zoom level be controlled
+by <a href="#controls_android.control.zoomRatio">android.<wbr/>control.<wbr/>zoom<wbr/>Ratio</a>,<wbr/> and the effective zoom level is reflected in
+<a href="#controls_android.control.zoomRatio">android.<wbr/>control.<wbr/>zoom<wbr/>Ratio</a> in capture results.<wbr/> This addresses an ambiguity with AUTO,<wbr/>
+with which the camera device cannot know if the application is using cropRegion or
+zoomRatio at 1.<wbr/>0x.<wbr/></p>
+            </td>
+          </tr>
+
+          <tr class="entries_header">
+            <th class="th_details" colspan="6">HAL Implementation Details</th>
+          </tr>
+          <tr class="entry_cont">
+            <td class="entry_details" colspan="6">
+              <p>Do not use this key directly.<wbr/> It's for camera framework usage,<wbr/>
+and not for HAL consumption.<wbr/></p>
+            </td>
+          </tr>
+
+          <tr class="entry_spacer"><td class="entry_spacer" colspan="7"></td></tr>
+           <!-- end of entry -->
+        
+                
+          <tr class="entry" id="controls_android.control.aePriorityMode">
+            <td class="entry_name
+             " rowspan="5">
+              android.<wbr/>control.<wbr/>ae<wbr/>Priority<wbr/>Mode
+            </td>
+            <td class="entry_type">
+                <span class="entry_type_name entry_type_name_enum">byte</span>
+
+              <span class="entry_type_visibility"> [public]</span>
+
+
+
+
+
+                <ul class="entry_type_enum">
+                  <li>
+                    <span class="entry_type_enum_name">OFF (v3.11)</span>
+                    <span class="entry_type_enum_notes"><p>Disable AE priority mode.<wbr/> This is the default value.<wbr/></p></span>
+                  </li>
+                  <li>
+                    <span class="entry_type_enum_name">SENSOR_SENSITIVITY_PRIORITY (v3.11)</span>
+                    <span class="entry_type_enum_notes"><p>The camera device's auto-exposure routine is active and
+prioritizes the application-selected ISO (<a href="#controls_android.sensor.sensitivity">android.<wbr/>sensor.<wbr/>sensitivity</a>).<wbr/></p>
+<p>The application has control over <a href="#controls_android.sensor.sensitivity">android.<wbr/>sensor.<wbr/>sensitivity</a> while
+the application's values for <a href="#controls_android.sensor.exposureTime">android.<wbr/>sensor.<wbr/>exposure<wbr/>Time</a> and
+<a href="#controls_android.sensor.frameDuration">android.<wbr/>sensor.<wbr/>frame<wbr/>Duration</a> are ignored.<wbr/></p></span>
+                  </li>
+                  <li>
+                    <span class="entry_type_enum_name">SENSOR_EXPOSURE_TIME_PRIORITY (v3.11)</span>
+                    <span class="entry_type_enum_notes"><p>The camera device's auto-exposure routine is active and
+prioritizes the application-selected exposure time
+(<a href="#controls_android.sensor.exposureTime">android.<wbr/>sensor.<wbr/>exposure<wbr/>Time</a>).<wbr/></p>
+<p>The application has control over <a href="#controls_android.sensor.exposureTime">android.<wbr/>sensor.<wbr/>exposure<wbr/>Time</a> while
+the application's values for <a href="#controls_android.sensor.sensitivity">android.<wbr/>sensor.<wbr/>sensitivity</a> and
+<a href="#controls_android.sensor.frameDuration">android.<wbr/>sensor.<wbr/>frame<wbr/>Duration</a> are ignored.<wbr/></p></span>
+                  </li>
+                </ul>
+
+            </td> <!-- entry_type -->
+
+            <td class="entry_description">
+              <p>Turn on AE priority mode.<wbr/></p>
+            </td>
+
+            <td class="entry_units">
+            </td>
+
+            <td class="entry_range">
+            </td>
+
+            <td class="entry_hal_version">
+              <p>3.<wbr/>11</p>
+            </td>
+
+            <td class="entry_tags">
+            </td>
+
+          </tr>
+          <tr class="entries_header">
+            <th class="th_details" colspan="6">Details</th>
+          </tr>
+          <tr class="entry_cont">
+            <td class="entry_details" colspan="6">
+              <p>This control is only effective if <a href="#controls_android.control.mode">android.<wbr/>control.<wbr/>mode</a> is
+AUTO and <a href="#controls_android.control.aeMode">android.<wbr/>control.<wbr/>ae<wbr/>Mode</a> is set to one of its
+ON modes,<wbr/> with the exception of ON_<wbr/>LOW_<wbr/>LIGHT_<wbr/>BOOST_<wbr/>BRIGHTNESS_<wbr/>PRIORITY.<wbr/></p>
+<p>When a priority mode is enabled,<wbr/> the camera device's
+auto-exposure routine will maintain the application's
+selected parameters relevant to the priority mode while overriding
+the remaining exposure parameters
+(<a href="#controls_android.sensor.exposureTime">android.<wbr/>sensor.<wbr/>exposure<wbr/>Time</a>,<wbr/> <a href="#controls_android.sensor.sensitivity">android.<wbr/>sensor.<wbr/>sensitivity</a>,<wbr/> and
+<a href="#controls_android.sensor.frameDuration">android.<wbr/>sensor.<wbr/>frame<wbr/>Duration</a>).<wbr/> For example,<wbr/> if
+SENSOR_<wbr/>SENSITIVITY_<wbr/>PRIORITY mode is enabled,<wbr/> the camera device will
+maintain the application-selected <a href="#controls_android.sensor.sensitivity">android.<wbr/>sensor.<wbr/>sensitivity</a>
+while adjusting <a href="#controls_android.sensor.exposureTime">android.<wbr/>sensor.<wbr/>exposure<wbr/>Time</a>
+and <a href="#controls_android.sensor.frameDuration">android.<wbr/>sensor.<wbr/>frame<wbr/>Duration</a>.<wbr/> The overridden fields for a
+given capture will be available in its CaptureResult.<wbr/></p>
+            </td>
+          </tr>
+
+          <tr class="entries_header">
+            <th class="th_details" colspan="6">HAL Implementation Details</th>
+          </tr>
+          <tr class="entry_cont">
+            <td class="entry_details" colspan="6">
+              <p>The total sensitivity applied for SENSOR_<wbr/>SENSITIVITY_<wbr/>PRIORITY should not be
+adjusted by any HAL applied <a href="#controls_android.control.postRawSensitivityBoost">android.<wbr/>control.<wbr/>post<wbr/>Raw<wbr/>Sensitivity<wbr/>Boost</a>.<wbr/></p>
+            </td>
+          </tr>
+
+          <tr class="entry_spacer"><td class="entry_spacer" colspan="7"></td></tr>
+           <!-- end of entry -->
+        
         
 
       <!-- end of kind -->
@@ -7707,6 +8371,64 @@ also be present.<wbr/></p>
           <tr class="entry_spacer"><td class="entry_spacer" colspan="7"></td></tr>
            <!-- end of entry -->
         
+                
+          <tr class="entry" id="static_android.control.aeAvailablePriorityModes">
+            <td class="entry_name
+             " rowspan="3">
+              android.<wbr/>control.<wbr/>ae<wbr/>Available<wbr/>Priority<wbr/>Modes
+            </td>
+            <td class="entry_type">
+                <span class="entry_type_name">byte</span>
+                <span class="entry_type_container">x</span>
+
+                <span class="entry_type_array">
+                  n
+                </span>
+              <span class="entry_type_visibility"> [public as enumList]</span>
+
+
+
+
+                <div class="entry_type_notes">list of enums</div>
+
+
+            </td> <!-- entry_type -->
+
+            <td class="entry_description">
+              <p>List of auto-exposure priority modes for <a href="#controls_android.control.aePriorityMode">android.<wbr/>control.<wbr/>ae<wbr/>Priority<wbr/>Mode</a>
+that are supported by this camera device.<wbr/></p>
+            </td>
+
+            <td class="entry_units">
+            </td>
+
+            <td class="entry_range">
+              <p>Any value listed in <a href="#controls_android.control.aePriorityMode">android.<wbr/>control.<wbr/>ae<wbr/>Priority<wbr/>Mode</a></p>
+            </td>
+
+            <td class="entry_hal_version">
+              <p>3.<wbr/>11</p>
+            </td>
+
+            <td class="entry_tags">
+            </td>
+
+          </tr>
+          <tr class="entries_header">
+            <th class="th_details" colspan="6">Details</th>
+          </tr>
+          <tr class="entry_cont">
+            <td class="entry_details" colspan="6">
+              <p>This entry lists the valid modes for
+<a href="#controls_android.control.aePriorityMode">android.<wbr/>control.<wbr/>ae<wbr/>Priority<wbr/>Mode</a> for this camera device.<wbr/>
+If no AE priority modes are available for a device,<wbr/> this will only list OFF.<wbr/></p>
+            </td>
+          </tr>
+
+
+          <tr class="entry_spacer"><td class="entry_spacer" colspan="7"></td></tr>
+           <!-- end of entry -->
+        
         
 
       <!-- end of kind -->
@@ -8133,7 +8855,14 @@ with no flash control.<wbr/></p>
 <a href="#controls_android.sensor.sensitivity">android.<wbr/>sensor.<wbr/>sensitivity</a>,<wbr/> and
 <a href="#controls_android.sensor.frameDuration">android.<wbr/>sensor.<wbr/>frame<wbr/>Duration</a> are ignored.<wbr/> The
 application has control over the various
-android.<wbr/>flash.<wbr/>* fields.<wbr/></p></span>
+android.<wbr/>flash.<wbr/>* fields.<wbr/></p>
+<p>If the device supports manual flash strength control,<wbr/> i.<wbr/>e.,<wbr/>
+if <a href="#static_android.flash.singleStrengthMaxLevel">android.<wbr/>flash.<wbr/>single<wbr/>Strength<wbr/>Max<wbr/>Level</a> and
+<a href="#static_android.flash.torchStrengthMaxLevel">android.<wbr/>flash.<wbr/>torch<wbr/>Strength<wbr/>Max<wbr/>Level</a> are greater than 1,<wbr/> then
+the auto-exposure (AE) precapture metering sequence should be
+triggered for the configured flash mode and strength to avoid
+the image being incorrectly exposed at different
+<a href="#controls_android.flash.strengthLevel">android.<wbr/>flash.<wbr/>strength<wbr/>Level</a>.<wbr/></p></span>
                   </li>
                   <li>
                     <span class="entry_type_enum_name">ON_AUTO_FLASH (v3.2)</span>
@@ -8249,7 +8978,9 @@ auto-exposure routine is enabled,<wbr/> overriding the
 application's selected exposure time,<wbr/> sensor sensitivity,<wbr/>
 and frame duration (<a href="#controls_android.sensor.exposureTime">android.<wbr/>sensor.<wbr/>exposure<wbr/>Time</a>,<wbr/>
 <a href="#controls_android.sensor.sensitivity">android.<wbr/>sensor.<wbr/>sensitivity</a>,<wbr/> and
-<a href="#controls_android.sensor.frameDuration">android.<wbr/>sensor.<wbr/>frame<wbr/>Duration</a>).<wbr/> If one of the FLASH modes
+<a href="#controls_android.sensor.frameDuration">android.<wbr/>sensor.<wbr/>frame<wbr/>Duration</a>).<wbr/> If <a href="#controls_android.control.aePriorityMode">android.<wbr/>control.<wbr/>ae<wbr/>Priority<wbr/>Mode</a> is
+enabled,<wbr/> the relevant priority CaptureRequest settings will not be overridden.<wbr/>
+See <a href="#controls_android.control.aePriorityMode">android.<wbr/>control.<wbr/>ae<wbr/>Priority<wbr/>Mode</a> for more details.<wbr/> If one of the FLASH modes
 is selected,<wbr/> the camera device's flash unit controls are
 also overridden.<wbr/></p>
 <p>The FLASH modes are only available if the camera device
@@ -8260,6 +8991,13 @@ ON or OFF,<wbr/> and <a href="#controls_android.flash.mode">android.<wbr/>flash.
 camera device auto-exposure routine for the overridden
 fields for a given capture will be available in its
 CaptureResult.<wbr/></p>
+<p>When <a href="#controls_android.control.aeMode">android.<wbr/>control.<wbr/>ae<wbr/>Mode</a> is AE_<wbr/>MODE_<wbr/>ON and if the device
+supports manual flash strength control,<wbr/> i.<wbr/>e.,<wbr/>
+if <a href="#static_android.flash.singleStrengthMaxLevel">android.<wbr/>flash.<wbr/>single<wbr/>Strength<wbr/>Max<wbr/>Level</a> and
+<a href="#static_android.flash.torchStrengthMaxLevel">android.<wbr/>flash.<wbr/>torch<wbr/>Strength<wbr/>Max<wbr/>Level</a> are greater than 1,<wbr/> then
+the auto-exposure (AE) precapture metering sequence should be
+triggered to avoid the image being incorrectly exposed at
+different <a href="#controls_android.flash.strengthLevel">android.<wbr/>flash.<wbr/>strength<wbr/>Level</a>.<wbr/></p>
             </td>
           </tr>
 
@@ -8382,7 +9120,7 @@ mode.<wbr/></p>
 <a href="https://developer.android.com/reference/android/hardware/camera2/CameraMetadata.html#REQUEST_AVAILABLE_CAPABILITIES_ULTRA_HIGH_RESOLUTION_SENSOR">Camera<wbr/>Metadata#REQUEST_<wbr/>AVAILABLE_<wbr/>CAPABILITIES_<wbr/>ULTRA_<wbr/>HIGH_<wbr/>RESOLUTION_<wbr/>SENSOR</a>
 capability or devices where
 <a href="https://developer.android.com/reference/CameraCharacteristics.html#getAvailableCaptureRequestKeys">CameraCharacteristics#getAvailableCaptureRequestKeys</a>
-lists <a href="https://developer.android.com/reference/CaptureRequest.html#SENSOR_PIXEL_MODE"><a href="#controls_android.sensor.pixelMode">android.<wbr/>sensor.<wbr/>pixel<wbr/>Mode</a></a>
+lists <a href="#controls_android.sensor.pixelMode">android.<wbr/>sensor.<wbr/>pixel<wbr/>Mode</a>,<wbr/>
 <a href="#static_android.sensor.info.activeArraySizeMaximumResolution">android.<wbr/>sensor.<wbr/>info.<wbr/>active<wbr/>Array<wbr/>Size<wbr/>Maximum<wbr/>Resolution</a> /<wbr/>
 <a href="#static_android.sensor.info.preCorrectionActiveArraySizeMaximumResolution">android.<wbr/>sensor.<wbr/>info.<wbr/>pre<wbr/>Correction<wbr/>Active<wbr/>Array<wbr/>Size<wbr/>Maximum<wbr/>Resolution</a> must be used as the
 coordinate system for requests where <a href="#controls_android.sensor.pixelMode">android.<wbr/>sensor.<wbr/>pixel<wbr/>Mode</a> is set to
@@ -9216,7 +9954,7 @@ mode.<wbr/></p>
 <a href="https://developer.android.com/reference/android/hardware/camera2/CameraMetadata.html#REQUEST_AVAILABLE_CAPABILITIES_ULTRA_HIGH_RESOLUTION_SENSOR">Camera<wbr/>Metadata#REQUEST_<wbr/>AVAILABLE_<wbr/>CAPABILITIES_<wbr/>ULTRA_<wbr/>HIGH_<wbr/>RESOLUTION_<wbr/>SENSOR</a>
 capability or devices where
 <a href="https://developer.android.com/reference/CameraCharacteristics.html#getAvailableCaptureRequestKeys">CameraCharacteristics#getAvailableCaptureRequestKeys</a>
-lists <a href="https://developer.android.com/reference/CaptureRequest.html#SENSOR_PIXEL_MODE"><a href="#controls_android.sensor.pixelMode">android.<wbr/>sensor.<wbr/>pixel<wbr/>Mode</a></a>,<wbr/>
+lists <a href="#controls_android.sensor.pixelMode">android.<wbr/>sensor.<wbr/>pixel<wbr/>Mode</a>,<wbr/>
 <a href="#static_android.sensor.info.activeArraySizeMaximumResolution">android.<wbr/>sensor.<wbr/>info.<wbr/>active<wbr/>Array<wbr/>Size<wbr/>Maximum<wbr/>Resolution</a> /<wbr/>
 <a href="#static_android.sensor.info.preCorrectionActiveArraySizeMaximumResolution">android.<wbr/>sensor.<wbr/>info.<wbr/>pre<wbr/>Correction<wbr/>Active<wbr/>Array<wbr/>Size<wbr/>Maximum<wbr/>Resolution</a> must be used as the
 coordinate system for requests where <a href="#controls_android.sensor.pixelMode">android.<wbr/>sensor.<wbr/>pixel<wbr/>Mode</a> is set to
@@ -10269,7 +11007,7 @@ mode.<wbr/></p>
 <a href="https://developer.android.com/reference/android/hardware/camera2/CameraMetadata.html#REQUEST_AVAILABLE_CAPABILITIES_ULTRA_HIGH_RESOLUTION_SENSOR">Camera<wbr/>Metadata#REQUEST_<wbr/>AVAILABLE_<wbr/>CAPABILITIES_<wbr/>ULTRA_<wbr/>HIGH_<wbr/>RESOLUTION_<wbr/>SENSOR</a>
 capability or devices where
 <a href="https://developer.android.com/reference/CameraCharacteristics.html#getAvailableCaptureRequestKeys">CameraCharacteristics#getAvailableCaptureRequestKeys</a>
-lists <a href="https://developer.android.com/reference/CaptureRequest.html#SENSOR_PIXEL_MODE"><a href="#controls_android.sensor.pixelMode">android.<wbr/>sensor.<wbr/>pixel<wbr/>Mode</a></a>,<wbr/>
+lists <a href="#controls_android.sensor.pixelMode">android.<wbr/>sensor.<wbr/>pixel<wbr/>Mode</a>,<wbr/>
 <a href="#static_android.sensor.info.activeArraySizeMaximumResolution">android.<wbr/>sensor.<wbr/>info.<wbr/>active<wbr/>Array<wbr/>Size<wbr/>Maximum<wbr/>Resolution</a> /<wbr/>
 <a href="#static_android.sensor.info.preCorrectionActiveArraySizeMaximumResolution">android.<wbr/>sensor.<wbr/>info.<wbr/>pre<wbr/>Correction<wbr/>Active<wbr/>Array<wbr/>Size<wbr/>Maximum<wbr/>Resolution</a> must be used as the
 coordinate system for requests where <a href="#controls_android.sensor.pixelMode">android.<wbr/>sensor.<wbr/>pixel<wbr/>Mode</a> is set to
@@ -12223,49 +12961,103 @@ indicate when it is not being applied by returning 'INACTIVE'.<wbr/></p>
           <tr class="entry_spacer"><td class="entry_spacer" colspan="7"></td></tr>
            <!-- end of entry -->
         
-        
+                
+          <tr class="entry" id="dynamic_android.control.zoomMethod">
+            <td class="entry_name
+             " rowspan="5">
+              android.<wbr/>control.<wbr/>zoom<wbr/>Method
+            </td>
+            <td class="entry_type">
+                <span class="entry_type_name entry_type_name_enum">byte</span>
 
-      <!-- end of kind -->
-      </tbody>
+              <span class="entry_type_visibility"> [fwk_public]</span>
 
-  <!-- end of section -->
-  <tr><td colspan="7" id="section_demosaic" class="section">demosaic</td></tr>
 
+              <span class="entry_type_hwlevel">[limited] </span>
 
-      <tr><td colspan="7" class="kind">controls</td></tr>
 
-      <thead class="entries_header">
-        <tr>
-          <th class="th_name">Property Name</th>
-          <th class="th_type">Type</th>
-          <th class="th_description">Description</th>
-          <th class="th_units">Units</th>
-          <th class="th_range">Range</th>
-          <th class="th_hal_version">Initial HIDL HAL version</th>
-          <th class="th_tags">Tags</th>
-        </tr>
-      </thead>
 
-      <tbody>
+                <ul class="entry_type_enum">
+                  <li>
+                    <span class="entry_type_enum_name">AUTO (v3.11)</span>
+                    <span class="entry_type_enum_value">0</span>
+                    <span class="entry_type_enum_notes"><p>The camera device automatically detects whether the application does zoom with
+<a href="#controls_android.scaler.cropRegion">android.<wbr/>scaler.<wbr/>crop<wbr/>Region</a> or <a href="#controls_android.control.zoomRatio">android.<wbr/>control.<wbr/>zoom<wbr/>Ratio</a>,<wbr/> and in turn decides which
+metadata tag reflects the effective zoom level.<wbr/></p></span>
+                  </li>
+                  <li>
+                    <span class="entry_type_enum_name">ZOOM_RATIO (v3.11)</span>
+                    <span class="entry_type_enum_value">1</span>
+                    <span class="entry_type_enum_notes"><p>The application intends to control zoom via <a href="#controls_android.control.zoomRatio">android.<wbr/>control.<wbr/>zoom<wbr/>Ratio</a>,<wbr/> and
+the effective zoom level is reflected by <a href="#controls_android.control.zoomRatio">android.<wbr/>control.<wbr/>zoom<wbr/>Ratio</a> in capture results.<wbr/></p></span>
+                  </li>
+                </ul>
 
-        
+            </td> <!-- entry_type -->
 
-        
+            <td class="entry_description">
+              <p>Whether the application uses <a href="#controls_android.scaler.cropRegion">android.<wbr/>scaler.<wbr/>crop<wbr/>Region</a> or <a href="#controls_android.control.zoomRatio">android.<wbr/>control.<wbr/>zoom<wbr/>Ratio</a>
+to control zoom levels.<wbr/></p>
+            </td>
 
-        
+            <td class="entry_units">
+            </td>
 
-        
+            <td class="entry_range">
+            </td>
+
+            <td class="entry_hal_version">
+              <p>3.<wbr/>11</p>
+            </td>
 
+            <td class="entry_tags">
+            </td>
+
+          </tr>
+          <tr class="entries_header">
+            <th class="th_details" colspan="6">Details</th>
+          </tr>
+          <tr class="entry_cont">
+            <td class="entry_details" colspan="6">
+              <p>If set to AUTO,<wbr/> the camera device detects which capture request key the application uses
+to do zoom,<wbr/> <a href="#controls_android.scaler.cropRegion">android.<wbr/>scaler.<wbr/>crop<wbr/>Region</a> or <a href="#controls_android.control.zoomRatio">android.<wbr/>control.<wbr/>zoom<wbr/>Ratio</a>.<wbr/> If
+the application doesn't set android.<wbr/>scaler.<wbr/>zoom<wbr/>Ratio or sets it to 1.<wbr/>0 in the capture
+request,<wbr/> the effective zoom level is reflected in <a href="#controls_android.scaler.cropRegion">android.<wbr/>scaler.<wbr/>crop<wbr/>Region</a> in capture
+results.<wbr/> If <a href="#controls_android.control.zoomRatio">android.<wbr/>control.<wbr/>zoom<wbr/>Ratio</a> is set to values other than 1.<wbr/>0,<wbr/> the effective
+zoom level is reflected in <a href="#controls_android.control.zoomRatio">android.<wbr/>control.<wbr/>zoom<wbr/>Ratio</a>.<wbr/> AUTO is the default value
+for this control,<wbr/> and also the behavior of the OS before Android version
+<a href="https://developer.android.com/reference/android/os/Build.VERSION_CODES.html#BAKLAVA">BAKLAVA</a>.<wbr/></p>
+<p>If set to ZOOM_<wbr/>RATIO,<wbr/> the application explicitly specifies zoom level be controlled
+by <a href="#controls_android.control.zoomRatio">android.<wbr/>control.<wbr/>zoom<wbr/>Ratio</a>,<wbr/> and the effective zoom level is reflected in
+<a href="#controls_android.control.zoomRatio">android.<wbr/>control.<wbr/>zoom<wbr/>Ratio</a> in capture results.<wbr/> This addresses an ambiguity with AUTO,<wbr/>
+with which the camera device cannot know if the application is using cropRegion or
+zoomRatio at 1.<wbr/>0x.<wbr/></p>
+            </td>
+          </tr>
+
+          <tr class="entries_header">
+            <th class="th_details" colspan="6">HAL Implementation Details</th>
+          </tr>
+          <tr class="entry_cont">
+            <td class="entry_details" colspan="6">
+              <p>Do not use this key directly.<wbr/> It's for camera framework usage,<wbr/>
+and not for HAL consumption.<wbr/></p>
+            </td>
+          </tr>
+
+          <tr class="entry_spacer"><td class="entry_spacer" colspan="7"></td></tr>
+           <!-- end of entry -->
+        
                 
-          <tr class="entry" id="controls_android.demosaic.mode">
+          <tr class="entry" id="dynamic_android.control.aePriorityMode">
             <td class="entry_name
-             " rowspan="1">
-              android.<wbr/>demosaic.<wbr/>mode
+             " rowspan="5">
+              android.<wbr/>control.<wbr/>ae<wbr/>Priority<wbr/>Mode
             </td>
             <td class="entry_type">
                 <span class="entry_type_name entry_type_name_enum">byte</span>
 
-              <span class="entry_type_visibility"> [system]</span>
+              <span class="entry_type_visibility"> [public]</span>
 
 
 
@@ -12273,22 +13065,32 @@ indicate when it is not being applied by returning 'INACTIVE'.<wbr/></p>
 
                 <ul class="entry_type_enum">
                   <li>
-                    <span class="entry_type_enum_name">FAST (v3.2)</span>
-                    <span class="entry_type_enum_notes"><p>Minimal or no slowdown of frame rate compared to
-Bayer RAW output.<wbr/></p></span>
+                    <span class="entry_type_enum_name">OFF (v3.11)</span>
+                    <span class="entry_type_enum_notes"><p>Disable AE priority mode.<wbr/> This is the default value.<wbr/></p></span>
                   </li>
                   <li>
-                    <span class="entry_type_enum_name">HIGH_QUALITY (v3.2)</span>
-                    <span class="entry_type_enum_notes"><p>Improved processing quality but the frame rate might be slowed down
-relative to raw output.<wbr/></p></span>
+                    <span class="entry_type_enum_name">SENSOR_SENSITIVITY_PRIORITY (v3.11)</span>
+                    <span class="entry_type_enum_notes"><p>The camera device's auto-exposure routine is active and
+prioritizes the application-selected ISO (<a href="#controls_android.sensor.sensitivity">android.<wbr/>sensor.<wbr/>sensitivity</a>).<wbr/></p>
+<p>The application has control over <a href="#controls_android.sensor.sensitivity">android.<wbr/>sensor.<wbr/>sensitivity</a> while
+the application's values for <a href="#controls_android.sensor.exposureTime">android.<wbr/>sensor.<wbr/>exposure<wbr/>Time</a> and
+<a href="#controls_android.sensor.frameDuration">android.<wbr/>sensor.<wbr/>frame<wbr/>Duration</a> are ignored.<wbr/></p></span>
+                  </li>
+                  <li>
+                    <span class="entry_type_enum_name">SENSOR_EXPOSURE_TIME_PRIORITY (v3.11)</span>
+                    <span class="entry_type_enum_notes"><p>The camera device's auto-exposure routine is active and
+prioritizes the application-selected exposure time
+(<a href="#controls_android.sensor.exposureTime">android.<wbr/>sensor.<wbr/>exposure<wbr/>Time</a>).<wbr/></p>
+<p>The application has control over <a href="#controls_android.sensor.exposureTime">android.<wbr/>sensor.<wbr/>exposure<wbr/>Time</a> while
+the application's values for <a href="#controls_android.sensor.sensitivity">android.<wbr/>sensor.<wbr/>sensitivity</a> and
+<a href="#controls_android.sensor.frameDuration">android.<wbr/>sensor.<wbr/>frame<wbr/>Duration</a> are ignored.<wbr/></p></span>
                   </li>
                 </ul>
 
             </td> <!-- entry_type -->
 
             <td class="entry_description">
-              <p>Controls the quality of the demosaicing
-processing.<wbr/></p>
+              <p>Turn on AE priority mode.<wbr/></p>
             </td>
 
             <td class="entry_units">
@@ -12298,17 +13100,44 @@ processing.<wbr/></p>
             </td>
 
             <td class="entry_hal_version">
-              <p>3.<wbr/>2</p>
+              <p>3.<wbr/>11</p>
             </td>
 
             <td class="entry_tags">
-              <ul class="entry_tags">
-                  <li><a href="#tag_FUTURE">FUTURE</a></li>
-              </ul>
             </td>
 
           </tr>
+          <tr class="entries_header">
+            <th class="th_details" colspan="6">Details</th>
+          </tr>
+          <tr class="entry_cont">
+            <td class="entry_details" colspan="6">
+              <p>This control is only effective if <a href="#controls_android.control.mode">android.<wbr/>control.<wbr/>mode</a> is
+AUTO and <a href="#controls_android.control.aeMode">android.<wbr/>control.<wbr/>ae<wbr/>Mode</a> is set to one of its
+ON modes,<wbr/> with the exception of ON_<wbr/>LOW_<wbr/>LIGHT_<wbr/>BOOST_<wbr/>BRIGHTNESS_<wbr/>PRIORITY.<wbr/></p>
+<p>When a priority mode is enabled,<wbr/> the camera device's
+auto-exposure routine will maintain the application's
+selected parameters relevant to the priority mode while overriding
+the remaining exposure parameters
+(<a href="#controls_android.sensor.exposureTime">android.<wbr/>sensor.<wbr/>exposure<wbr/>Time</a>,<wbr/> <a href="#controls_android.sensor.sensitivity">android.<wbr/>sensor.<wbr/>sensitivity</a>,<wbr/> and
+<a href="#controls_android.sensor.frameDuration">android.<wbr/>sensor.<wbr/>frame<wbr/>Duration</a>).<wbr/> For example,<wbr/> if
+SENSOR_<wbr/>SENSITIVITY_<wbr/>PRIORITY mode is enabled,<wbr/> the camera device will
+maintain the application-selected <a href="#controls_android.sensor.sensitivity">android.<wbr/>sensor.<wbr/>sensitivity</a>
+while adjusting <a href="#controls_android.sensor.exposureTime">android.<wbr/>sensor.<wbr/>exposure<wbr/>Time</a>
+and <a href="#controls_android.sensor.frameDuration">android.<wbr/>sensor.<wbr/>frame<wbr/>Duration</a>.<wbr/> The overridden fields for a
+given capture will be available in its CaptureResult.<wbr/></p>
+            </td>
+          </tr>
 
+          <tr class="entries_header">
+            <th class="th_details" colspan="6">HAL Implementation Details</th>
+          </tr>
+          <tr class="entry_cont">
+            <td class="entry_details" colspan="6">
+              <p>The total sensitivity applied for SENSOR_<wbr/>SENSITIVITY_<wbr/>PRIORITY should not be
+adjusted by any HAL applied <a href="#controls_android.control.postRawSensitivityBoost">android.<wbr/>control.<wbr/>post<wbr/>Raw<wbr/>Sensitivity<wbr/>Boost</a>.<wbr/></p>
+            </td>
+          </tr>
 
           <tr class="entry_spacer"><td class="entry_spacer" colspan="7"></td></tr>
            <!-- end of entry -->
@@ -12319,7 +13148,97 @@ processing.<wbr/></p>
       </tbody>
 
   <!-- end of section -->
-  <tr><td colspan="7" id="section_edge" class="section">edge</td></tr>
+  <tr><td colspan="7" id="section_demosaic" class="section">demosaic</td></tr>
+
+
+      <tr><td colspan="7" class="kind">controls</td></tr>
+
+      <thead class="entries_header">
+        <tr>
+          <th class="th_name">Property Name</th>
+          <th class="th_type">Type</th>
+          <th class="th_description">Description</th>
+          <th class="th_units">Units</th>
+          <th class="th_range">Range</th>
+          <th class="th_hal_version">Initial HIDL HAL version</th>
+          <th class="th_tags">Tags</th>
+        </tr>
+      </thead>
+
+      <tbody>
+
+        
+
+        
+
+        
+
+        
+
+                
+          <tr class="entry" id="controls_android.demosaic.mode">
+            <td class="entry_name
+             " rowspan="1">
+              android.<wbr/>demosaic.<wbr/>mode
+            </td>
+            <td class="entry_type">
+                <span class="entry_type_name entry_type_name_enum">byte</span>
+
+              <span class="entry_type_visibility"> [system]</span>
+
+
+
+
+
+                <ul class="entry_type_enum">
+                  <li>
+                    <span class="entry_type_enum_name">FAST (v3.2)</span>
+                    <span class="entry_type_enum_notes"><p>Minimal or no slowdown of frame rate compared to
+Bayer RAW output.<wbr/></p></span>
+                  </li>
+                  <li>
+                    <span class="entry_type_enum_name">HIGH_QUALITY (v3.2)</span>
+                    <span class="entry_type_enum_notes"><p>Improved processing quality but the frame rate might be slowed down
+relative to raw output.<wbr/></p></span>
+                  </li>
+                </ul>
+
+            </td> <!-- entry_type -->
+
+            <td class="entry_description">
+              <p>Controls the quality of the demosaicing
+processing.<wbr/></p>
+            </td>
+
+            <td class="entry_units">
+            </td>
+
+            <td class="entry_range">
+            </td>
+
+            <td class="entry_hal_version">
+              <p>3.<wbr/>2</p>
+            </td>
+
+            <td class="entry_tags">
+              <ul class="entry_tags">
+                  <li><a href="#tag_FUTURE">FUTURE</a></li>
+              </ul>
+            </td>
+
+          </tr>
+
+
+          <tr class="entry_spacer"><td class="entry_spacer" colspan="7"></td></tr>
+           <!-- end of entry -->
+        
+        
+
+      <!-- end of kind -->
+      </tbody>
+
+  <!-- end of section -->
+  <tr><td colspan="7" id="section_edge" class="section">edge</td></tr>
 
 
       <tr><td colspan="7" class="kind">controls</td></tr>
@@ -22595,8 +23514,8 @@ preCorrectionActiveArraySize covers the camera device's field of view "after" zo
 <p>For camera devices with the
 <a href="https://developer.android.com/reference/android/hardware/camera2/CameraMetadata.html#REQUEST_AVAILABLE_CAPABILITIES_ULTRA_HIGH_RESOLUTION_SENSOR">Camera<wbr/>Metadata#REQUEST_<wbr/>AVAILABLE_<wbr/>CAPABILITIES_<wbr/>ULTRA_<wbr/>HIGH_<wbr/>RESOLUTION_<wbr/>SENSOR</a>
 capability or devices where <a href="https://developer.android.com/reference/CameraCharacteristics.html#getAvailableCaptureRequestKeys">CameraCharacteristics#getAvailableCaptureRequestKeys</a>
-lists <a href="https://developer.android.com/reference/CaptureRequest.html#SENSOR_PIXEL_MODE"><a href="#controls_android.sensor.pixelMode">android.<wbr/>sensor.<wbr/>pixel<wbr/>Mode</a></a></p>
-<p><a href="#static_android.sensor.info.activeArraySizeMaximumResolution">android.<wbr/>sensor.<wbr/>info.<wbr/>active<wbr/>Array<wbr/>Size<wbr/>Maximum<wbr/>Resolution</a> /<wbr/>
+lists <a href="#controls_android.sensor.pixelMode">android.<wbr/>sensor.<wbr/>pixel<wbr/>Mode</a>,<wbr/>
+<a href="#static_android.sensor.info.activeArraySizeMaximumResolution">android.<wbr/>sensor.<wbr/>info.<wbr/>active<wbr/>Array<wbr/>Size<wbr/>Maximum<wbr/>Resolution</a> /<wbr/>
 <a href="#static_android.sensor.info.preCorrectionActiveArraySizeMaximumResolution">android.<wbr/>sensor.<wbr/>info.<wbr/>pre<wbr/>Correction<wbr/>Active<wbr/>Array<wbr/>Size<wbr/>Maximum<wbr/>Resolution</a> must be used as the
 coordinate system for requests where <a href="#controls_android.sensor.pixelMode">android.<wbr/>sensor.<wbr/>pixel<wbr/>Mode</a> is set to
 <a href="https://developer.android.com/reference/android/hardware/camera2/CameraMetadata.html#SENSOR_PIXEL_MODE_MAXIMUM_RESOLUTION">Camera<wbr/>Metadata#SENSOR_<wbr/>PIXEL_<wbr/>MODE_<wbr/>MAXIMUM_<wbr/>RESOLUTION</a>.<wbr/></p>
@@ -26387,8 +27306,8 @@ preCorrectionActiveArraySize covers the camera device's field of view "after" zo
 <p>For camera devices with the
 <a href="https://developer.android.com/reference/android/hardware/camera2/CameraMetadata.html#REQUEST_AVAILABLE_CAPABILITIES_ULTRA_HIGH_RESOLUTION_SENSOR">Camera<wbr/>Metadata#REQUEST_<wbr/>AVAILABLE_<wbr/>CAPABILITIES_<wbr/>ULTRA_<wbr/>HIGH_<wbr/>RESOLUTION_<wbr/>SENSOR</a>
 capability or devices where <a href="https://developer.android.com/reference/CameraCharacteristics.html#getAvailableCaptureRequestKeys">CameraCharacteristics#getAvailableCaptureRequestKeys</a>
-lists <a href="https://developer.android.com/reference/CaptureRequest.html#SENSOR_PIXEL_MODE"><a href="#controls_android.sensor.pixelMode">android.<wbr/>sensor.<wbr/>pixel<wbr/>Mode</a></a></p>
-<p><a href="#static_android.sensor.info.activeArraySizeMaximumResolution">android.<wbr/>sensor.<wbr/>info.<wbr/>active<wbr/>Array<wbr/>Size<wbr/>Maximum<wbr/>Resolution</a> /<wbr/>
+lists <a href="#controls_android.sensor.pixelMode">android.<wbr/>sensor.<wbr/>pixel<wbr/>Mode</a>,<wbr/>
+<a href="#static_android.sensor.info.activeArraySizeMaximumResolution">android.<wbr/>sensor.<wbr/>info.<wbr/>active<wbr/>Array<wbr/>Size<wbr/>Maximum<wbr/>Resolution</a> /<wbr/>
 <a href="#static_android.sensor.info.preCorrectionActiveArraySizeMaximumResolution">android.<wbr/>sensor.<wbr/>info.<wbr/>pre<wbr/>Correction<wbr/>Active<wbr/>Array<wbr/>Size<wbr/>Maximum<wbr/>Resolution</a> must be used as the
 coordinate system for requests where <a href="#controls_android.sensor.pixelMode">android.<wbr/>sensor.<wbr/>pixel<wbr/>Mode</a> is set to
 <a href="https://developer.android.com/reference/android/hardware/camera2/CameraMetadata.html#SENSOR_PIXEL_MODE_MAXIMUM_RESOLUTION">Camera<wbr/>Metadata#SENSOR_<wbr/>PIXEL_<wbr/>MODE_<wbr/>MAXIMUM_<wbr/>RESOLUTION</a>.<wbr/></p>
@@ -26758,7 +27677,9 @@ light.<wbr/></p>
 duration exposed to the nearest possible value (rather than expose longer).<wbr/>
 The final exposure time used will be available in the output capture result.<wbr/></p>
 <p>This control is only effective if <a href="#controls_android.control.aeMode">android.<wbr/>control.<wbr/>ae<wbr/>Mode</a> or <a href="#controls_android.control.mode">android.<wbr/>control.<wbr/>mode</a> is set to
-OFF; otherwise the auto-exposure algorithm will override this value.<wbr/></p>
+OFF; otherwise the auto-exposure algorithm will override this value.<wbr/> However,<wbr/> in the
+case that <a href="#controls_android.control.aePriorityMode">android.<wbr/>control.<wbr/>ae<wbr/>Priority<wbr/>Mode</a> is set to SENSOR_<wbr/>EXPOSURE_<wbr/>TIME_<wbr/>PRIORITY,<wbr/> this
+control will be effective and not controlled by the auto-exposure algorithm.<wbr/></p>
             </td>
           </tr>
 
@@ -26953,7 +27874,9 @@ requested,<wbr/> it will reduce the gain to the nearest supported
 value.<wbr/> The final sensitivity used will be available in the
 output capture result.<wbr/></p>
 <p>This control is only effective if <a href="#controls_android.control.aeMode">android.<wbr/>control.<wbr/>ae<wbr/>Mode</a> or <a href="#controls_android.control.mode">android.<wbr/>control.<wbr/>mode</a> is set to
-OFF; otherwise the auto-exposure algorithm will override this value.<wbr/></p>
+OFF; otherwise the auto-exposure algorithm will override this value.<wbr/> However,<wbr/> in the
+case that <a href="#controls_android.control.aePriorityMode">android.<wbr/>control.<wbr/>ae<wbr/>Priority<wbr/>Mode</a> is set to SENSOR_<wbr/>SENSITIVITY_<wbr/>PRIORITY,<wbr/> this
+control will be effective and not controlled by the auto-exposure algorithm.<wbr/></p>
 <p>Note that for devices supporting postRawSensitivityBoost,<wbr/> the total sensitivity applied
 to the final processed image is the combination of <a href="#controls_android.sensor.sensitivity">android.<wbr/>sensor.<wbr/>sensitivity</a> and
 <a href="#controls_android.control.postRawSensitivityBoost">android.<wbr/>control.<wbr/>post<wbr/>Raw<wbr/>Sensitivity<wbr/>Boost</a>.<wbr/> In case the application uses the sensor
@@ -28315,7 +29238,7 @@ counterparts.<wbr/>
 This key will only be present for devices which advertise the
 <a href="https://developer.android.com/reference/android/hardware/camera2/CameraMetadata.html#REQUEST_AVAILABLE_CAPABILITIES_ULTRA_HIGH_RESOLUTION_SENSOR">Camera<wbr/>Metadata#REQUEST_<wbr/>AVAILABLE_<wbr/>CAPABILITIES_<wbr/>ULTRA_<wbr/>HIGH_<wbr/>RESOLUTION_<wbr/>SENSOR</a>
 capability or devices where <a href="https://developer.android.com/reference/CameraCharacteristics.html#getAvailableCaptureRequestKeys">CameraCharacteristics#getAvailableCaptureRequestKeys</a>
-lists <a href="https://developer.android.com/reference/CaptureRequest.html#SENSOR_PIXEL_MODE"><a href="#controls_android.sensor.pixelMode">android.<wbr/>sensor.<wbr/>pixel<wbr/>Mode</a></a></p>
+lists <a href="#controls_android.sensor.pixelMode">android.<wbr/>sensor.<wbr/>pixel<wbr/>Mode</a>.<wbr/></p>
             </td>
           </tr>
 
@@ -28394,7 +29317,7 @@ is,<wbr/> when <a href="#controls_android.sensor.pixelMode">android.<wbr/>sensor
 This key will only be present for devices which advertise the
 <a href="https://developer.android.com/reference/android/hardware/camera2/CameraMetadata.html#REQUEST_AVAILABLE_CAPABILITIES_ULTRA_HIGH_RESOLUTION_SENSOR">Camera<wbr/>Metadata#REQUEST_<wbr/>AVAILABLE_<wbr/>CAPABILITIES_<wbr/>ULTRA_<wbr/>HIGH_<wbr/>RESOLUTION_<wbr/>SENSOR</a>
 capability or devices where <a href="https://developer.android.com/reference/CameraCharacteristics.html#getAvailableCaptureRequestKeys">CameraCharacteristics#getAvailableCaptureRequestKeys</a>
-lists <a href="https://developer.android.com/reference/CaptureRequest.html#SENSOR_PIXEL_MODE"><a href="#controls_android.sensor.pixelMode">android.<wbr/>sensor.<wbr/>pixel<wbr/>Mode</a></a></p>
+lists <a href="#controls_android.sensor.pixelMode">android.<wbr/>sensor.<wbr/>pixel<wbr/>Mode</a>.<wbr/></p>
             </td>
           </tr>
 
@@ -28462,7 +29385,7 @@ when <a href="#controls_android.sensor.pixelMode">android.<wbr/>sensor.<wbr/>pix
 This key will only be present for devices which advertise the
 <a href="https://developer.android.com/reference/android/hardware/camera2/CameraMetadata.html#REQUEST_AVAILABLE_CAPABILITIES_ULTRA_HIGH_RESOLUTION_SENSOR">Camera<wbr/>Metadata#REQUEST_<wbr/>AVAILABLE_<wbr/>CAPABILITIES_<wbr/>ULTRA_<wbr/>HIGH_<wbr/>RESOLUTION_<wbr/>SENSOR</a>
 capability or devices where <a href="https://developer.android.com/reference/CameraCharacteristics.html#getAvailableCaptureRequestKeys">CameraCharacteristics#getAvailableCaptureRequestKeys</a>
-lists <a href="https://developer.android.com/reference/CaptureRequest.html#SENSOR_PIXEL_MODE"><a href="#controls_android.sensor.pixelMode">android.<wbr/>sensor.<wbr/>pixel<wbr/>Mode</a></a></p>
+lists <a href="#controls_android.sensor.pixelMode">android.<wbr/>sensor.<wbr/>pixel<wbr/>Mode</a>.<wbr/></p>
             </td>
           </tr>
 
@@ -28549,7 +29472,7 @@ capability :</p>
 <ul>
 <li>This key will be present if
   <a href="https://developer.android.com/reference/CameraCharacteristics.html#getAvailableCaptureRequestKeys">CameraCharacteristics#getAvailableCaptureRequestKeys</a>
-  lists <a href="https://developer.android.com/reference/CaptureRequest.html#SENSOR_PIXEL_MODE"><a href="#controls_android.sensor.pixelMode">android.<wbr/>sensor.<wbr/>pixel<wbr/>Mode</a></a>,<wbr/> since RAW
+  lists <a href="#controls_android.sensor.pixelMode">android.<wbr/>sensor.<wbr/>pixel<wbr/>Mode</a>,<wbr/> since RAW
   images may not necessarily have a regular bayer pattern when
   <a href="https://developer.android.com/reference/CaptureRequest.html#SENSOR_PIXEL_MODE"><a href="#controls_android.sensor.pixelMode">android.<wbr/>sensor.<wbr/>pixel<wbr/>Mode</a></a> is set to
   <a href="https://developer.android.com/reference/android/hardware/camera2/CameraMetadata.html#SENSOR_PIXEL_MODE_MAXIMUM_RESOLUTION">Camera<wbr/>Metadata#SENSOR_<wbr/>PIXEL_<wbr/>MODE_<wbr/>MAXIMUM_<wbr/>RESOLUTION</a>.<wbr/></li>
@@ -29997,7 +30920,9 @@ light.<wbr/></p>
 duration exposed to the nearest possible value (rather than expose longer).<wbr/>
 The final exposure time used will be available in the output capture result.<wbr/></p>
 <p>This control is only effective if <a href="#controls_android.control.aeMode">android.<wbr/>control.<wbr/>ae<wbr/>Mode</a> or <a href="#controls_android.control.mode">android.<wbr/>control.<wbr/>mode</a> is set to
-OFF; otherwise the auto-exposure algorithm will override this value.<wbr/></p>
+OFF; otherwise the auto-exposure algorithm will override this value.<wbr/> However,<wbr/> in the
+case that <a href="#controls_android.control.aePriorityMode">android.<wbr/>control.<wbr/>ae<wbr/>Priority<wbr/>Mode</a> is set to SENSOR_<wbr/>EXPOSURE_<wbr/>TIME_<wbr/>PRIORITY,<wbr/> this
+control will be effective and not controlled by the auto-exposure algorithm.<wbr/></p>
             </td>
           </tr>
 
@@ -30192,7 +31117,9 @@ requested,<wbr/> it will reduce the gain to the nearest supported
 value.<wbr/> The final sensitivity used will be available in the
 output capture result.<wbr/></p>
 <p>This control is only effective if <a href="#controls_android.control.aeMode">android.<wbr/>control.<wbr/>ae<wbr/>Mode</a> or <a href="#controls_android.control.mode">android.<wbr/>control.<wbr/>mode</a> is set to
-OFF; otherwise the auto-exposure algorithm will override this value.<wbr/></p>
+OFF; otherwise the auto-exposure algorithm will override this value.<wbr/> However,<wbr/> in the
+case that <a href="#controls_android.control.aePriorityMode">android.<wbr/>control.<wbr/>ae<wbr/>Priority<wbr/>Mode</a> is set to SENSOR_<wbr/>SENSITIVITY_<wbr/>PRIORITY,<wbr/> this
+control will be effective and not controlled by the auto-exposure algorithm.<wbr/></p>
 <p>Note that for devices supporting postRawSensitivityBoost,<wbr/> the total sensitivity applied
 to the final processed image is the combination of <a href="#controls_android.sensor.sensitivity">android.<wbr/>sensor.<wbr/>sensitivity</a> and
 <a href="#controls_android.control.postRawSensitivityBoost">android.<wbr/>control.<wbr/>post<wbr/>Raw<wbr/>Sensitivity<wbr/>Boost</a>.<wbr/> In case the application uses the sensor
@@ -34001,6 +34928,14 @@ bottom-right of the pixel array,<wbr/> respectively.<wbr/> The width and
 height dimensions are given in <a href="#static_android.sensor.info.pixelArraySize">android.<wbr/>sensor.<wbr/>info.<wbr/>pixel<wbr/>Array<wbr/>Size</a>.<wbr/>
 This may include hot pixels that lie outside of the active array
 bounds given by <a href="#static_android.sensor.info.activeArraySize">android.<wbr/>sensor.<wbr/>info.<wbr/>active<wbr/>Array<wbr/>Size</a>.<wbr/></p>
+<p>For camera devices with the
+<a href="https://developer.android.com/reference/android/hardware/camera2/CameraMetadata.html#REQUEST_AVAILABLE_CAPABILITIES_ULTRA_HIGH_RESOLUTION_SENSOR">Camera<wbr/>Metadata#REQUEST_<wbr/>AVAILABLE_<wbr/>CAPABILITIES_<wbr/>ULTRA_<wbr/>HIGH_<wbr/>RESOLUTION_<wbr/>SENSOR</a>
+capability or devices where
+<a href="https://developer.android.com/reference/CameraCharacteristics.html#getAvailableCaptureRequestKeys">CameraCharacteristics#getAvailableCaptureRequestKeys</a>
+lists <a href="#controls_android.sensor.pixelMode">android.<wbr/>sensor.<wbr/>pixel<wbr/>Mode</a>,<wbr/>
+<a href="#static_android.sensor.info.pixelArraySizeMaximumResolution">android.<wbr/>sensor.<wbr/>info.<wbr/>pixel<wbr/>Array<wbr/>Size<wbr/>Maximum<wbr/>Resolution</a> will be used as the
+pixel array size if the corresponding request sets <a href="#controls_android.sensor.pixelMode">android.<wbr/>sensor.<wbr/>pixel<wbr/>Mode</a> to
+<a href="https://developer.android.com/reference/android/hardware/camera2/CameraMetadata.html#SENSOR_PIXEL_MODE_MAXIMUM_RESOLUTION">Camera<wbr/>Metadata#SENSOR_<wbr/>PIXEL_<wbr/>MODE_<wbr/>MAXIMUM_<wbr/>RESOLUTION</a>.<wbr/></p>
             </td>
           </tr>
 
@@ -36718,6 +37653,10 @@ supported device state bitwise combination.<wbr/></p>
                     <span class="entry_type_enum_name">VANILLA_ICE_CREAM (v3.10)</span>
                     <span class="entry_type_enum_value">35</span>
                   </li>
+                  <li>
+                    <span class="entry_type_enum_name">BAKLAVA (v3.11)</span>
+                    <span class="entry_type_enum_value">36</span>
+                  </li>
                 </ul>
 
             </td> <!-- entry_type -->
@@ -36878,6 +37817,32 @@ by the compliance tests:</p>
 <p>All of the above configurations can be set up with a SessionConfiguration.<wbr/> The list of
 OutputConfiguration contains the stream configurations and DYNAMIC_<wbr/>RANGE_<wbr/>PROFILE,<wbr/> and
 the AE_<wbr/>TARGET_<wbr/>FPS_<wbr/>RANGE and VIDEO_<wbr/>STABILIZATION_<wbr/>MODE are set as session parameters.<wbr/></p>
+<p>When set to BAKLAVA,<wbr/> the additional stream combinations below are verified
+by the compliance tests:</p>
+<table>
+<thead>
+<tr>
+<th style="text-align: center;">Target 1</th>
+<th style="text-align: center;">Size</th>
+<th style="text-align: center;">Target 2</th>
+<th style="text-align: center;">Size</th>
+</tr>
+</thead>
+<tbody>
+<tr>
+<td style="text-align: center;">PRIV</td>
+<td style="text-align: center;">S1080P</td>
+<td style="text-align: center;">PRIV</td>
+<td style="text-align: center;">S1080P</td>
+</tr>
+<tr>
+<td style="text-align: center;">PRIV</td>
+<td style="text-align: center;">S1080P</td>
+<td style="text-align: center;">PRIV</td>
+<td style="text-align: center;">S1440P</td>
+</tr>
+</tbody>
+</table>
             </td>
           </tr>
 
@@ -39310,8 +40275,8 @@ the top-left pixel of the active array.<wbr/></p>
 <p>For camera devices with the
 <a href="https://developer.android.com/reference/android/hardware/camera2/CameraMetadata.html#REQUEST_AVAILABLE_CAPABILITIES_ULTRA_HIGH_RESOLUTION_SENSOR">Camera<wbr/>Metadata#REQUEST_<wbr/>AVAILABLE_<wbr/>CAPABILITIES_<wbr/>ULTRA_<wbr/>HIGH_<wbr/>RESOLUTION_<wbr/>SENSOR</a>
 capability or devices where <a href="https://developer.android.com/reference/CameraCharacteristics.html#getAvailableCaptureRequestKeys">CameraCharacteristics#getAvailableCaptureRequestKeys</a>
-lists <a href="https://developer.android.com/reference/CaptureRequest.html#SENSOR_PIXEL_MODE"><a href="#controls_android.sensor.pixelMode">android.<wbr/>sensor.<wbr/>pixel<wbr/>Mode</a></a>
-,<wbr/> the current active physical device
+lists <a href="#controls_android.sensor.pixelMode">android.<wbr/>sensor.<wbr/>pixel<wbr/>Mode</a>,<wbr/>
+the current active physical device
 <a href="#static_android.sensor.info.activeArraySizeMaximumResolution">android.<wbr/>sensor.<wbr/>info.<wbr/>active<wbr/>Array<wbr/>Size<wbr/>Maximum<wbr/>Resolution</a> /<wbr/>
 <a href="#static_android.sensor.info.preCorrectionActiveArraySizeMaximumResolution">android.<wbr/>sensor.<wbr/>info.<wbr/>pre<wbr/>Correction<wbr/>Active<wbr/>Array<wbr/>Size<wbr/>Maximum<wbr/>Resolution</a> must be used as the
 coordinate system for requests where <a href="#controls_android.sensor.pixelMode">android.<wbr/>sensor.<wbr/>pixel<wbr/>Mode</a> is set to
@@ -40363,6 +41328,411 @@ set by the HAL layer.<wbr/></p>
           <tr class="entry_spacer"><td class="entry_spacer" colspan="7"></td></tr>
            <!-- end of entry -->
         
+                
+          <tr class="entry" id="static_android.heic.availableHeicUltraHdrStreamConfigurations">
+            <td class="entry_name
+             " rowspan="5">
+              android.<wbr/>heic.<wbr/>available<wbr/>Heic<wbr/>Ultra<wbr/>Hdr<wbr/>Stream<wbr/>Configurations
+            </td>
+            <td class="entry_type">
+                <span class="entry_type_name entry_type_name_enum">int32</span>
+                <span class="entry_type_container">x</span>
+
+                <span class="entry_type_array">
+                  n x 4
+                </span>
+              <span class="entry_type_visibility"> [ndk_public as streamConfiguration]</span>
+
+
+              <span class="entry_type_hwlevel">[limited] </span>
+
+
+
+                <ul class="entry_type_enum">
+                  <li>
+                    <span class="entry_type_enum_name">OUTPUT (v3.11)</span>
+                  </li>
+                  <li>
+                    <span class="entry_type_enum_name">INPUT (v3.11)</span>
+                  </li>
+                </ul>
+
+            </td> <!-- entry_type -->
+
+            <td class="entry_description">
+              <p>The available HEIC (ISO/<wbr/>IEC 23008-12/<wbr/>24) UltraHDR stream
+configurations that this camera device supports
+(i.<wbr/>e.<wbr/> format,<wbr/> width,<wbr/> height,<wbr/> output/<wbr/>input stream).<wbr/></p>
+            </td>
+
+            <td class="entry_units">
+            </td>
+
+            <td class="entry_range">
+            </td>
+
+            <td class="entry_hal_version">
+              <p>3.<wbr/>11</p>
+            </td>
+
+            <td class="entry_tags">
+              <ul class="entry_tags">
+                  <li><a href="#tag_HEIC">HEIC</a></li>
+              </ul>
+            </td>
+
+          </tr>
+          <tr class="entries_header">
+            <th class="th_details" colspan="6">Details</th>
+          </tr>
+          <tr class="entry_cont">
+            <td class="entry_details" colspan="6">
+              <p>The configurations are listed as <code>(format,<wbr/> width,<wbr/> height,<wbr/> input?)</code> tuples.<wbr/></p>
+<p>All the static,<wbr/> control,<wbr/> and dynamic metadata tags related to JPEG apply to HEIC formats.<wbr/>
+Configuring JPEG and HEIC streams at the same time is not supported.<wbr/></p>
+            </td>
+          </tr>
+
+          <tr class="entries_header">
+            <th class="th_details" colspan="6">HAL Implementation Details</th>
+          </tr>
+          <tr class="entry_cont">
+            <td class="entry_details" colspan="6">
+              <p>These are output stream configurations for use with dataSpace DATASPACE_<wbr/>HEIF_<wbr/>ULTRAHDR.<wbr/></p>
+            </td>
+          </tr>
+
+          <tr class="entry_spacer"><td class="entry_spacer" colspan="7"></td></tr>
+           <!-- end of entry -->
+        
+                
+          <tr class="entry" id="static_android.heic.availableHeicUltraHdrMinFrameDurations">
+            <td class="entry_name
+             " rowspan="3">
+              android.<wbr/>heic.<wbr/>available<wbr/>Heic<wbr/>Ultra<wbr/>Hdr<wbr/>Min<wbr/>Frame<wbr/>Durations
+            </td>
+            <td class="entry_type">
+                <span class="entry_type_name">int64</span>
+                <span class="entry_type_container">x</span>
+
+                <span class="entry_type_array">
+                  4 x n
+                </span>
+              <span class="entry_type_visibility"> [ndk_public as streamConfigurationDuration]</span>
+
+
+              <span class="entry_type_hwlevel">[limited] </span>
+
+
+
+
+            </td> <!-- entry_type -->
+
+            <td class="entry_description">
+              <p>This lists the minimum frame duration for each
+format/<wbr/>size combination for HEIC UltraHDR output formats.<wbr/></p>
+            </td>
+
+            <td class="entry_units">
+              (format,<wbr/> width,<wbr/> height,<wbr/> ns) x n
+            </td>
+
+            <td class="entry_range">
+            </td>
+
+            <td class="entry_hal_version">
+              <p>3.<wbr/>11</p>
+            </td>
+
+            <td class="entry_tags">
+              <ul class="entry_tags">
+                  <li><a href="#tag_HEIC">HEIC</a></li>
+              </ul>
+            </td>
+
+          </tr>
+          <tr class="entries_header">
+            <th class="th_details" colspan="6">Details</th>
+          </tr>
+          <tr class="entry_cont">
+            <td class="entry_details" colspan="6">
+              <p>This should correspond to the frame duration when only that
+stream is active,<wbr/> with all processing (typically in android.<wbr/>*.<wbr/>mode)
+set to either OFF or FAST.<wbr/></p>
+<p>When multiple streams are used in a request,<wbr/> the minimum frame
+duration will be max(individual stream min durations).<wbr/></p>
+<p>See <a href="#controls_android.sensor.frameDuration">android.<wbr/>sensor.<wbr/>frame<wbr/>Duration</a> and
+<a href="#static_android.scaler.availableStallDurations">android.<wbr/>scaler.<wbr/>available<wbr/>Stall<wbr/>Durations</a> for more details about
+calculating the max frame rate.<wbr/></p>
+            </td>
+          </tr>
+
+
+          <tr class="entry_spacer"><td class="entry_spacer" colspan="7"></td></tr>
+           <!-- end of entry -->
+        
+                
+          <tr class="entry" id="static_android.heic.availableHeicUltraHdrStallDurations">
+            <td class="entry_name
+             " rowspan="3">
+              android.<wbr/>heic.<wbr/>available<wbr/>Heic<wbr/>Ultra<wbr/>Hdr<wbr/>Stall<wbr/>Durations
+            </td>
+            <td class="entry_type">
+                <span class="entry_type_name">int64</span>
+                <span class="entry_type_container">x</span>
+
+                <span class="entry_type_array">
+                  4 x n
+                </span>
+              <span class="entry_type_visibility"> [ndk_public as streamConfigurationDuration]</span>
+
+
+              <span class="entry_type_hwlevel">[limited] </span>
+
+
+
+
+            </td> <!-- entry_type -->
+
+            <td class="entry_description">
+              <p>This lists the maximum stall duration for each
+output format/<wbr/>size combination for HEIC UltraHDR streams.<wbr/></p>
+            </td>
+
+            <td class="entry_units">
+              (format,<wbr/> width,<wbr/> height,<wbr/> ns) x n
+            </td>
+
+            <td class="entry_range">
+            </td>
+
+            <td class="entry_hal_version">
+              <p>3.<wbr/>11</p>
+            </td>
+
+            <td class="entry_tags">
+              <ul class="entry_tags">
+                  <li><a href="#tag_HEIC">HEIC</a></li>
+              </ul>
+            </td>
+
+          </tr>
+          <tr class="entries_header">
+            <th class="th_details" colspan="6">Details</th>
+          </tr>
+          <tr class="entry_cont">
+            <td class="entry_details" colspan="6">
+              <p>A stall duration is how much extra time would get added
+to the normal minimum frame duration for a repeating request
+that has streams with non-zero stall.<wbr/></p>
+<p>This functions similarly to
+<a href="#static_android.scaler.availableStallDurations">android.<wbr/>scaler.<wbr/>available<wbr/>Stall<wbr/>Durations</a> for HEIC UltraHDR
+streams.<wbr/></p>
+<p>All HEIC output stream formats may have a nonzero stall
+duration.<wbr/></p>
+            </td>
+          </tr>
+
+
+          <tr class="entry_spacer"><td class="entry_spacer" colspan="7"></td></tr>
+           <!-- end of entry -->
+        
+                
+          <tr class="entry" id="static_android.heic.availableHeicUltraHdrStreamConfigurationsMaximumResolution">
+            <td class="entry_name
+             " rowspan="5">
+              android.<wbr/>heic.<wbr/>available<wbr/>Heic<wbr/>Ultra<wbr/>Hdr<wbr/>Stream<wbr/>Configurations<wbr/>Maximum<wbr/>Resolution
+            </td>
+            <td class="entry_type">
+                <span class="entry_type_name entry_type_name_enum">int32</span>
+                <span class="entry_type_container">x</span>
+
+                <span class="entry_type_array">
+                  n x 4
+                </span>
+              <span class="entry_type_visibility"> [ndk_public as streamConfiguration]</span>
+
+
+
+
+
+                <ul class="entry_type_enum">
+                  <li>
+                    <span class="entry_type_enum_name">OUTPUT (v3.11)</span>
+                  </li>
+                  <li>
+                    <span class="entry_type_enum_name">INPUT (v3.11)</span>
+                  </li>
+                </ul>
+
+            </td> <!-- entry_type -->
+
+            <td class="entry_description">
+              <p>The available HEIC (ISO/<wbr/>IEC 23008-12/<wbr/>24) UltraHDR stream
+configurations that this camera device supports
+(i.<wbr/>e.<wbr/> format,<wbr/> width,<wbr/> height,<wbr/> output/<wbr/>input stream) for CaptureRequests where
+<a href="#controls_android.sensor.pixelMode">android.<wbr/>sensor.<wbr/>pixel<wbr/>Mode</a> is set to
+<a href="https://developer.android.com/reference/android/hardware/camera2/CameraMetadata.html#SENSOR_PIXEL_MODE_MAXIMUM_RESOLUTION">Camera<wbr/>Metadata#SENSOR_<wbr/>PIXEL_<wbr/>MODE_<wbr/>MAXIMUM_<wbr/>RESOLUTION</a>.<wbr/></p>
+            </td>
+
+            <td class="entry_units">
+            </td>
+
+            <td class="entry_range">
+            </td>
+
+            <td class="entry_hal_version">
+              <p>3.<wbr/>11</p>
+            </td>
+
+            <td class="entry_tags">
+              <ul class="entry_tags">
+                  <li><a href="#tag_HEIC">HEIC</a></li>
+              </ul>
+            </td>
+
+          </tr>
+          <tr class="entries_header">
+            <th class="th_details" colspan="6">Details</th>
+          </tr>
+          <tr class="entry_cont">
+            <td class="entry_details" colspan="6">
+              <p>Refer to <a href="#static_android.heic.availableHeicStreamConfigurations">android.<wbr/>heic.<wbr/>available<wbr/>Heic<wbr/>Stream<wbr/>Configurations</a> for details.<wbr/></p>
+            </td>
+          </tr>
+
+          <tr class="entries_header">
+            <th class="th_details" colspan="6">HAL Implementation Details</th>
+          </tr>
+          <tr class="entry_cont">
+            <td class="entry_details" colspan="6">
+              <p>These are output stream configurations for use with dataSpace DATASPACE_<wbr/>HEIF_<wbr/>ULTRAHDR.<wbr/></p>
+            </td>
+          </tr>
+
+          <tr class="entry_spacer"><td class="entry_spacer" colspan="7"></td></tr>
+           <!-- end of entry -->
+        
+                
+          <tr class="entry" id="static_android.heic.availableHeicUltraHdrMinFrameDurationsMaximumResolution">
+            <td class="entry_name
+             " rowspan="3">
+              android.<wbr/>heic.<wbr/>available<wbr/>Heic<wbr/>Ultra<wbr/>Hdr<wbr/>Min<wbr/>Frame<wbr/>Durations<wbr/>Maximum<wbr/>Resolution
+            </td>
+            <td class="entry_type">
+                <span class="entry_type_name">int64</span>
+                <span class="entry_type_container">x</span>
+
+                <span class="entry_type_array">
+                  4 x n
+                </span>
+              <span class="entry_type_visibility"> [ndk_public as streamConfigurationDuration]</span>
+
+
+
+
+
+
+            </td> <!-- entry_type -->
+
+            <td class="entry_description">
+              <p>This lists the minimum frame duration for each
+format/<wbr/>size combination for HEIC UltraHDR output formats for CaptureRequests where
+<a href="#controls_android.sensor.pixelMode">android.<wbr/>sensor.<wbr/>pixel<wbr/>Mode</a> is set to
+<a href="https://developer.android.com/reference/android/hardware/camera2/CameraMetadata.html#SENSOR_PIXEL_MODE_MAXIMUM_RESOLUTION">Camera<wbr/>Metadata#SENSOR_<wbr/>PIXEL_<wbr/>MODE_<wbr/>MAXIMUM_<wbr/>RESOLUTION</a>.<wbr/></p>
+            </td>
+
+            <td class="entry_units">
+              (format,<wbr/> width,<wbr/> height,<wbr/> ns) x n
+            </td>
+
+            <td class="entry_range">
+            </td>
+
+            <td class="entry_hal_version">
+              <p>3.<wbr/>11</p>
+            </td>
+
+            <td class="entry_tags">
+              <ul class="entry_tags">
+                  <li><a href="#tag_HEIC">HEIC</a></li>
+              </ul>
+            </td>
+
+          </tr>
+          <tr class="entries_header">
+            <th class="th_details" colspan="6">Details</th>
+          </tr>
+          <tr class="entry_cont">
+            <td class="entry_details" colspan="6">
+              <p>Refer to <a href="#static_android.heic.availableHeicMinFrameDurations">android.<wbr/>heic.<wbr/>available<wbr/>Heic<wbr/>Min<wbr/>Frame<wbr/>Durations</a> for details.<wbr/></p>
+            </td>
+          </tr>
+
+
+          <tr class="entry_spacer"><td class="entry_spacer" colspan="7"></td></tr>
+           <!-- end of entry -->
+        
+                
+          <tr class="entry" id="static_android.heic.availableHeicUltraHdrStallDurationsMaximumResolution">
+            <td class="entry_name
+             " rowspan="3">
+              android.<wbr/>heic.<wbr/>available<wbr/>Heic<wbr/>Ultra<wbr/>Hdr<wbr/>Stall<wbr/>Durations<wbr/>Maximum<wbr/>Resolution
+            </td>
+            <td class="entry_type">
+                <span class="entry_type_name">int64</span>
+                <span class="entry_type_container">x</span>
+
+                <span class="entry_type_array">
+                  4 x n
+                </span>
+              <span class="entry_type_visibility"> [ndk_public as streamConfigurationDuration]</span>
+
+
+
+
+
+
+            </td> <!-- entry_type -->
+
+            <td class="entry_description">
+              <p>This lists the maximum stall duration for each
+output format/<wbr/>size combination for HEIC UltraHDR streams for CaptureRequests where
+<a href="#controls_android.sensor.pixelMode">android.<wbr/>sensor.<wbr/>pixel<wbr/>Mode</a> is set to
+<a href="https://developer.android.com/reference/android/hardware/camera2/CameraMetadata.html#SENSOR_PIXEL_MODE_MAXIMUM_RESOLUTION">Camera<wbr/>Metadata#SENSOR_<wbr/>PIXEL_<wbr/>MODE_<wbr/>MAXIMUM_<wbr/>RESOLUTION</a>.<wbr/></p>
+            </td>
+
+            <td class="entry_units">
+              (format,<wbr/> width,<wbr/> height,<wbr/> ns) x n
+            </td>
+
+            <td class="entry_range">
+            </td>
+
+            <td class="entry_hal_version">
+              <p>3.<wbr/>11</p>
+            </td>
+
+            <td class="entry_tags">
+              <ul class="entry_tags">
+                  <li><a href="#tag_HEIC">HEIC</a></li>
+              </ul>
+            </td>
+
+          </tr>
+          <tr class="entries_header">
+            <th class="th_details" colspan="6">Details</th>
+          </tr>
+          <tr class="entry_cont">
+            <td class="entry_details" colspan="6">
+              <p>Refer to <a href="#static_android.heic.availableHeicStallDurations">android.<wbr/>heic.<wbr/>available<wbr/>Heic<wbr/>Stall<wbr/>Durations</a> for details.<wbr/></p>
+            </td>
+          </tr>
+
+
+          <tr class="entry_spacer"><td class="entry_spacer" colspan="7"></td></tr>
+           <!-- end of entry -->
+        
         
 
       <!-- end of kind -->
@@ -40927,6 +42297,88 @@ corresponding capture result.<wbr/></p>
           <tr class="entry_spacer"><td class="entry_spacer" colspan="7"></td></tr>
            <!-- end of entry -->
         
+                
+          <tr class="entry" id="dynamic_android.extension.nightModeIndicator">
+            <td class="entry_name
+             " rowspan="3">
+              android.<wbr/>extension.<wbr/>night<wbr/>Mode<wbr/>Indicator
+            </td>
+            <td class="entry_type">
+                <span class="entry_type_name entry_type_name_enum">int32</span>
+
+              <span class="entry_type_visibility"> [public]</span>
+
+
+
+
+
+                <ul class="entry_type_enum">
+                  <li>
+                    <span class="entry_type_enum_name">UNKNOWN (v3.11)</span>
+                    <span class="entry_type_enum_notes"><p>The camera can't accurately assess the scene's lighting to determine if a Night Mode
+Camera Extension capture would improve the photo.<wbr/> This can happen when the current
+camera configuration doesn't support night mode indicator detection,<wbr/> such as when
+the auto exposure mode is ON_<wbr/>AUTO_<wbr/>FLASH,<wbr/> ON_<wbr/>ALWAYS_<wbr/>FLASH,<wbr/> ON_<wbr/>AUTO_<wbr/>FLASH_<wbr/>REDEYE,<wbr/> or
+ON_<wbr/>EXTERNAL_<wbr/>FLASH.<wbr/></p></span>
+                  </li>
+                  <li>
+                    <span class="entry_type_enum_name">OFF (v3.11)</span>
+                    <span class="entry_type_enum_notes"><p>The camera has detected lighting conditions that are sufficiently bright.<wbr/> Night
+Mode Camera Extensions is available but may not be able to optimize the camera
+settings to take a higher quality photo.<wbr/></p></span>
+                  </li>
+                  <li>
+                    <span class="entry_type_enum_name">ON (v3.11)</span>
+                    <span class="entry_type_enum_notes"><p>The camera has detected low-light conditions.<wbr/> It is recommended to use Night Mode
+Camera Extension to optimize the camera settings to take a high-quality photo in
+the dark.<wbr/></p></span>
+                  </li>
+                </ul>
+
+            </td> <!-- entry_type -->
+
+            <td class="entry_description">
+              <p>Indicates when to activate Night Mode Camera Extension for high-quality
+still captures in low-light conditions.<wbr/></p>
+            </td>
+
+            <td class="entry_units">
+            </td>
+
+            <td class="entry_range">
+            </td>
+
+            <td class="entry_hal_version">
+              <p>3.<wbr/>11</p>
+            </td>
+
+            <td class="entry_tags">
+            </td>
+
+          </tr>
+          <tr class="entries_header">
+            <th class="th_details" colspan="6">Details</th>
+          </tr>
+          <tr class="entry_cont">
+            <td class="entry_details" colspan="6">
+              <p>Provides awareness to the application when the current scene can benefit from using a
+Night Mode Camera Extension to take a high-quality photo.<wbr/></p>
+<p>Support for this capture result can be queried via
+<a href="https://developer.android.com/reference/android/hardware/camera2/CameraCharacteristics.html#getAvailableCaptureResultKeys">CameraCharacteristics#getAvailableCaptureResultKeys</a>.<wbr/></p>
+<p>If the device supports this capability then it will also support
+<a href="https://developer.android.com/reference/android/hardware/camera2/CameraExtensionCharacteristics.html#EXTENSION_NIGHT">NIGHT</a>
+and will be available in both
+<a href="https://developer.android.com/reference/android/hardware/camera2/CameraCaptureSession.html">sessions</a> and
+<a href="https://developer.android.com/reference/android/hardware/camera2/CameraExtensionSession.html">sessions</a>.<wbr/></p>
+<p>The value will be {@code UNKNOWN} in the following auto exposure modes: ON_<wbr/>AUTO_<wbr/>FLASH,<wbr/>
+ON_<wbr/>ALWAYS_<wbr/>FLASH,<wbr/> ON_<wbr/>AUTO_<wbr/>FLASH_<wbr/>REDEYE,<wbr/> or ON_<wbr/>EXTERNAL_<wbr/>FLASH.<wbr/></p>
+            </td>
+          </tr>
+
+
+          <tr class="entry_spacer"><td class="entry_spacer" colspan="7"></td></tr>
+           <!-- end of entry -->
+        
         
 
       <!-- end of kind -->
@@ -41334,6 +42786,617 @@ output format/<wbr/>size combination for Jpeg/<wbr/>R streams for CaptureRequest
         
         
 
+      <!-- end of kind -->
+      </tbody>
+
+  <!-- end of section -->
+  <tr><td colspan="7" id="section_sharedSession" class="section">sharedSession</td></tr>
+
+
+      <tr><td colspan="7" class="kind">static</td></tr>
+
+      <thead class="entries_header">
+        <tr>
+          <th class="th_name">Property Name</th>
+          <th class="th_type">Type</th>
+          <th class="th_description">Description</th>
+          <th class="th_units">Units</th>
+          <th class="th_range">Range</th>
+          <th class="th_hal_version">Initial HIDL HAL version</th>
+          <th class="th_tags">Tags</th>
+        </tr>
+      </thead>
+
+      <tbody>
+
+        
+
+        
+
+        
+
+        
+
+                
+          <tr class="entry" id="static_android.sharedSession.colorSpace">
+            <td class="entry_name
+             " rowspan="3">
+              android.<wbr/>shared<wbr/>Session.<wbr/>color<wbr/>Space
+            </td>
+            <td class="entry_type">
+                <span class="entry_type_name entry_type_name_enum">byte</span>
+
+              <span class="entry_type_visibility"> [fwk_only]</span>
+
+
+
+
+
+                <ul class="entry_type_enum">
+                  <li>
+                    <span class="entry_type_enum_name">UNSPECIFIED (v3.11)</span>
+                    <span class="entry_type_enum_value">-1</span>
+                  </li>
+                  <li>
+                    <span class="entry_type_enum_name">SRGB (v3.11)</span>
+                    <span class="entry_type_enum_value">0</span>
+                  </li>
+                  <li>
+                    <span class="entry_type_enum_name">DISPLAY_P3 (v3.11)</span>
+                    <span class="entry_type_enum_value">7</span>
+                  </li>
+                  <li>
+                    <span class="entry_type_enum_name">BT2020_HLG (v3.11)</span>
+                    <span class="entry_type_enum_value">16</span>
+                  </li>
+                </ul>
+
+            </td> <!-- entry_type -->
+
+            <td class="entry_description">
+              <p>Color space used for shared session configuration for all the output targets
+when camera is opened in shared mode.<wbr/> This should be one of the values specified in
+availableColorSpaceProfilesMap.<wbr/></p>
+            </td>
+
+            <td class="entry_units">
+            </td>
+
+            <td class="entry_range">
+            </td>
+
+            <td class="entry_hal_version">
+              <p>3.<wbr/>11</p>
+            </td>
+
+            <td class="entry_tags">
+            </td>
+
+          </tr>
+
+          <tr class="entries_header">
+            <th class="th_details" colspan="6">HAL Implementation Details</th>
+          </tr>
+          <tr class="entry_cont">
+            <td class="entry_details" colspan="6">
+              <p>Do not set this property directly.<wbr/> Android camera framework will generate this tag if the
+camera device can be opened in shared mode.<wbr/></p>
+            </td>
+          </tr>
+
+          <tr class="entry_spacer"><td class="entry_spacer" colspan="7"></td></tr>
+           <!-- end of entry -->
+        
+                
+          <tr class="entry" id="static_android.sharedSession.outputConfigurations">
+            <td class="entry_name
+             " rowspan="3">
+              android.<wbr/>shared<wbr/>Session.<wbr/>output<wbr/>Configurations
+            </td>
+            <td class="entry_type">
+                <span class="entry_type_name">int64</span>
+                <span class="entry_type_container">x</span>
+
+                <span class="entry_type_array">
+                  n
+                </span>
+              <span class="entry_type_visibility"> [fwk_only]</span>
+
+
+
+
+
+
+            </td> <!-- entry_type -->
+
+            <td class="entry_description">
+              <p>List of shared output configurations that this camera device supports when
+camera is opened in shared mode.<wbr/> Array contains following entries for each supported
+shared configuration:
+1) surface type
+2) width
+3) height
+4) format
+5) mirrorMode
+6) useReadoutTimestamp
+7) timestampBase
+8) dataspace
+9) usage
+10) streamUsecase
+11) physical camera id len
+12) physical camera id as UTF-8 null terminated string.<wbr/></p>
+            </td>
+
+            <td class="entry_units">
+            </td>
+
+            <td class="entry_range">
+            </td>
+
+            <td class="entry_hal_version">
+              <p>3.<wbr/>11</p>
+            </td>
+
+            <td class="entry_tags">
+            </td>
+
+          </tr>
+
+          <tr class="entries_header">
+            <th class="th_details" colspan="6">HAL Implementation Details</th>
+          </tr>
+          <tr class="entry_cont">
+            <td class="entry_details" colspan="6">
+              <p>Do not set this property directly.<wbr/> Android camera framework will generate this tag if the
+camera device can be opened in shared mode.<wbr/></p>
+            </td>
+          </tr>
+
+          <tr class="entry_spacer"><td class="entry_spacer" colspan="7"></td></tr>
+           <!-- end of entry -->
+        
+                
+          <tr class="entry" id="static_android.sharedSession.configuration">
+            <td class="entry_name
+             " rowspan="3">
+              android.<wbr/>shared<wbr/>Session.<wbr/>configuration
+            </td>
+            <td class="entry_type">
+                <span class="entry_type_name">byte</span>
+
+              <span class="entry_type_visibility"> [fwk_system_public as sharedSessionConfiguration]</span>
+
+              <span class="entry_type_synthetic">[synthetic] </span>
+
+
+
+
+
+            </td> <!-- entry_type -->
+
+            <td class="entry_description">
+              <p>The available stream configurations that this camera device supports for
+shared capture session when camera is opened in shared mode.<wbr/> Android camera framework
+will generate this tag if the camera device can be opened in shared mode.<wbr/></p>
+            </td>
+
+            <td class="entry_units">
+            </td>
+
+            <td class="entry_range">
+            </td>
+
+            <td class="entry_hal_version">
+              <p>3.<wbr/>2</p>
+            </td>
+
+            <td class="entry_tags">
+            </td>
+
+          </tr>
+
+          <tr class="entries_header">
+            <th class="th_details" colspan="6">HAL Implementation Details</th>
+          </tr>
+          <tr class="entry_cont">
+            <td class="entry_details" colspan="6">
+              <p>Do not set this property directly (it is synthetic and will not be available at the
+HAL layer);</p>
+            </td>
+          </tr>
+
+          <tr class="entry_spacer"><td class="entry_spacer" colspan="7"></td></tr>
+           <!-- end of entry -->
+        
+        
+
+      <!-- end of kind -->
+      </tbody>
+
+  <!-- end of section -->
+  <tr><td colspan="7" id="section_desktopEffects" class="section">desktopEffects</td></tr>
+
+
+      <tr><td colspan="7" class="kind">static</td></tr>
+
+      <thead class="entries_header">
+        <tr>
+          <th class="th_name">Property Name</th>
+          <th class="th_type">Type</th>
+          <th class="th_description">Description</th>
+          <th class="th_units">Units</th>
+          <th class="th_range">Range</th>
+          <th class="th_hal_version">Initial HIDL HAL version</th>
+          <th class="th_tags">Tags</th>
+        </tr>
+      </thead>
+
+      <tbody>
+
+        
+
+        
+
+        
+
+        
+
+                
+          <tr class="entry" id="static_android.desktopEffects.capabilities">
+            <td class="entry_name
+             " rowspan="3">
+              android.<wbr/>desktop<wbr/>Effects.<wbr/>capabilities
+            </td>
+            <td class="entry_type">
+                <span class="entry_type_name entry_type_name_enum">byte</span>
+                <span class="entry_type_container">x</span>
+
+                <span class="entry_type_array">
+                  n
+                </span>
+              <span class="entry_type_visibility"> [system as enumList]</span>
+
+
+
+
+                <div class="entry_type_notes">list of enums</div>
+
+                <ul class="entry_type_enum">
+                  <li>
+                    <span class="entry_type_enum_name">BACKGROUND_BLUR (v3.2)</span>
+                    <span class="entry_type_enum_notes"><p>Background blur can be activated via <a href="#controls_android.desktopEffects.backgroundBlurMode">android.<wbr/>desktop<wbr/>Effects.<wbr/>background<wbr/>Blur<wbr/>Mode</a></p></span>
+                  </li>
+                  <li>
+                    <span class="entry_type_enum_name">FACE_RETOUCH (v3.2)</span>
+                    <span class="entry_type_enum_notes"><p>Face retouch can be activated via <a href="#controls_android.desktopEffects.faceRetouchMode">android.<wbr/>desktop<wbr/>Effects.<wbr/>face<wbr/>Retouch<wbr/>Mode</a></p></span>
+                  </li>
+                  <li>
+                    <span class="entry_type_enum_name">PORTRAIT_RELIGHT (v3.2)</span>
+                    <span class="entry_type_enum_notes"><p>Portrait relight can be activated via <a href="#controls_android.desktopEffects.portraitRelightMode">android.<wbr/>desktop<wbr/>Effects.<wbr/>portrait<wbr/>Relight<wbr/>Mode</a></p></span>
+                  </li>
+                </ul>
+
+            </td> <!-- entry_type -->
+
+            <td class="entry_description">
+              <p>List of special effects supported by the camera device.<wbr/></p>
+            </td>
+
+            <td class="entry_units">
+            </td>
+
+            <td class="entry_range">
+            </td>
+
+            <td class="entry_hal_version">
+              <p>3.<wbr/>2</p>
+            </td>
+
+            <td class="entry_tags">
+            </td>
+
+          </tr>
+          <tr class="entries_header">
+            <th class="th_details" colspan="6">Details</th>
+          </tr>
+          <tr class="entry_cont">
+            <td class="entry_details" colspan="6">
+              <p>Available features supported by the camera device for large screen video conferencing.<wbr/></p>
+            </td>
+          </tr>
+
+
+          <tr class="entry_spacer"><td class="entry_spacer" colspan="7"></td></tr>
+           <!-- end of entry -->
+        
+                
+          <tr class="entry" id="static_android.desktopEffects.backgroundBlurModes">
+            <td class="entry_name
+             " rowspan="3">
+              android.<wbr/>desktop<wbr/>Effects.<wbr/>background<wbr/>Blur<wbr/>Modes
+            </td>
+            <td class="entry_type">
+                <span class="entry_type_name">byte</span>
+                <span class="entry_type_container">x</span>
+
+                <span class="entry_type_array">
+                  n
+                </span>
+              <span class="entry_type_visibility"> [system as enumList]</span>
+
+
+
+
+                <div class="entry_type_notes">list of enums (android.<wbr/>desktop<wbr/>Effects.<wbr/>background<wbr/>Blur<wbr/>Mode)</div>
+
+
+            </td> <!-- entry_type -->
+
+            <td class="entry_description">
+              <p>List of background blur modes supported by the camera device.<wbr/> The key will only exist
+if BACKGROUND_<wbr/>BLUR is listed by <a href="#static_android.desktopEffects.capabilities">android.<wbr/>desktop<wbr/>Effects.<wbr/>capabilities</a>.<wbr/></p>
+            </td>
+
+            <td class="entry_units">
+            </td>
+
+            <td class="entry_range">
+              <p>Any value listed in <a href="#controls_android.desktopEffects.backgroundBlurMode">android.<wbr/>desktop<wbr/>Effects.<wbr/>background<wbr/>Blur<wbr/>Mode</a></p>
+            </td>
+
+            <td class="entry_hal_version">
+              <p>3.<wbr/>2</p>
+            </td>
+
+            <td class="entry_tags">
+            </td>
+
+          </tr>
+          <tr class="entries_header">
+            <th class="th_details" colspan="6">Details</th>
+          </tr>
+          <tr class="entry_cont">
+            <td class="entry_details" colspan="6">
+              <p>Lists the valid modes for <a href="#controls_android.desktopEffects.backgroundBlurMode">android.<wbr/>desktop<wbr/>Effects.<wbr/>background<wbr/>Blur<wbr/>Mode</a>.<wbr/></p>
+            </td>
+          </tr>
+
+
+          <tr class="entry_spacer"><td class="entry_spacer" colspan="7"></td></tr>
+           <!-- end of entry -->
+        
+        
+
+      <!-- end of kind -->
+      </tbody>
+      <tr><td colspan="7" class="kind">controls</td></tr>
+
+      <thead class="entries_header">
+        <tr>
+          <th class="th_name">Property Name</th>
+          <th class="th_type">Type</th>
+          <th class="th_description">Description</th>
+          <th class="th_units">Units</th>
+          <th class="th_range">Range</th>
+          <th class="th_hal_version">Initial HIDL HAL version</th>
+          <th class="th_tags">Tags</th>
+        </tr>
+      </thead>
+
+      <tbody>
+
+        
+
+        
+
+        
+
+        
+
+                
+          <tr class="entry" id="controls_android.desktopEffects.backgroundBlurMode">
+            <td class="entry_name
+             " rowspan="1">
+              android.<wbr/>desktop<wbr/>Effects.<wbr/>background<wbr/>Blur<wbr/>Mode
+            </td>
+            <td class="entry_type">
+                <span class="entry_type_name entry_type_name_enum">byte</span>
+
+              <span class="entry_type_visibility"> [system]</span>
+
+
+
+
+
+                <ul class="entry_type_enum">
+                  <li>
+                    <span class="entry_type_enum_name">OFF (v3.2)</span>
+                    <span class="entry_type_enum_notes"><p>Don't use background blur</p></span>
+                  </li>
+                  <li>
+                    <span class="entry_type_enum_name">LIGHT (v3.2)</span>
+                    <span class="entry_type_enum_notes"><p>Blur the background with light blur strength</p></span>
+                  </li>
+                  <li>
+                    <span class="entry_type_enum_name">FULL (v3.2)</span>
+                    <span class="entry_type_enum_notes"><p>Blur the background with full blur strength</p></span>
+                  </li>
+                </ul>
+
+            </td> <!-- entry_type -->
+
+            <td class="entry_description">
+              <p>Control how the background should be blurred.<wbr/> Supported modes are listed in
+<a href="#static_android.desktopEffects.backgroundBlurModes">android.<wbr/>desktop<wbr/>Effects.<wbr/>background<wbr/>Blur<wbr/>Modes</a> by the camera device.<wbr/></p>
+            </td>
+
+            <td class="entry_units">
+            </td>
+
+            <td class="entry_range">
+            </td>
+
+            <td class="entry_hal_version">
+              <p>3.<wbr/>2</p>
+            </td>
+
+            <td class="entry_tags">
+            </td>
+
+          </tr>
+
+
+          <tr class="entry_spacer"><td class="entry_spacer" colspan="7"></td></tr>
+           <!-- end of entry -->
+        
+                
+          <tr class="entry" id="controls_android.desktopEffects.faceRetouchMode">
+            <td class="entry_name
+             " rowspan="1">
+              android.<wbr/>desktop<wbr/>Effects.<wbr/>face<wbr/>Retouch<wbr/>Mode
+            </td>
+            <td class="entry_type">
+                <span class="entry_type_name entry_type_name_enum">byte</span>
+
+              <span class="entry_type_visibility"> [system as boolean]</span>
+
+
+
+
+
+                <ul class="entry_type_enum">
+                  <li>
+                    <span class="entry_type_enum_name">OFF (v3.2)</span>
+                    <span class="entry_type_enum_notes"><p>Turn off face retouch</p></span>
+                  </li>
+                  <li>
+                    <span class="entry_type_enum_name">ON (v3.2)</span>
+                    <span class="entry_type_enum_notes"><p>Turn on face retouch.<wbr/> A strength can be set by <a href="#controls_android.desktopEffects.faceRetouchStrength">android.<wbr/>desktop<wbr/>Effects.<wbr/>face<wbr/>Retouch<wbr/>Strength</a></p></span>
+                  </li>
+                </ul>
+
+            </td> <!-- entry_type -->
+
+            <td class="entry_description">
+              <p>Whether to enable face retouch effect.<wbr/></p>
+            </td>
+
+            <td class="entry_units">
+            </td>
+
+            <td class="entry_range">
+            </td>
+
+            <td class="entry_hal_version">
+              <p>3.<wbr/>2</p>
+            </td>
+
+            <td class="entry_tags">
+            </td>
+
+          </tr>
+
+
+          <tr class="entry_spacer"><td class="entry_spacer" colspan="7"></td></tr>
+           <!-- end of entry -->
+        
+                
+          <tr class="entry" id="controls_android.desktopEffects.faceRetouchStrength">
+            <td class="entry_name
+             " rowspan="1">
+              android.<wbr/>desktop<wbr/>Effects.<wbr/>face<wbr/>Retouch<wbr/>Strength
+            </td>
+            <td class="entry_type">
+                <span class="entry_type_name">byte</span>
+
+              <span class="entry_type_visibility"> [system]</span>
+
+
+
+
+
+
+            </td> <!-- entry_type -->
+
+            <td class="entry_description">
+              <p>Control the strength of face retouch applied to the frames.<wbr/> If
+<a href="#controls_android.desktopEffects.faceRetouchMode">android.<wbr/>desktop<wbr/>Effects.<wbr/>face<wbr/>Retouch<wbr/>Mode</a> in ON without a faceRetouchStrength,<wbr/>
+a default will be set by the camera device.<wbr/></p>
+            </td>
+
+            <td class="entry_units">
+              1-100; 100 is maximum strength.<wbr/>
+            </td>
+
+            <td class="entry_range">
+            </td>
+
+            <td class="entry_hal_version">
+              <p>3.<wbr/>2</p>
+            </td>
+
+            <td class="entry_tags">
+            </td>
+
+          </tr>
+
+
+          <tr class="entry_spacer"><td class="entry_spacer" colspan="7"></td></tr>
+           <!-- end of entry -->
+        
+                
+          <tr class="entry" id="controls_android.desktopEffects.portraitRelightMode">
+            <td class="entry_name
+             " rowspan="1">
+              android.<wbr/>desktop<wbr/>Effects.<wbr/>portrait<wbr/>Relight<wbr/>Mode
+            </td>
+            <td class="entry_type">
+                <span class="entry_type_name entry_type_name_enum">byte</span>
+
+              <span class="entry_type_visibility"> [system as boolean]</span>
+
+
+
+
+
+                <ul class="entry_type_enum">
+                  <li>
+                    <span class="entry_type_enum_name">OFF (v3.2)</span>
+                    <span class="entry_type_enum_notes"><p>Do not use portrait relight</p></span>
+                  </li>
+                  <li>
+                    <span class="entry_type_enum_name">ON (v3.2)</span>
+                    <span class="entry_type_enum_notes"><p>Use portrait relight</p></span>
+                  </li>
+                </ul>
+
+            </td> <!-- entry_type -->
+
+            <td class="entry_description">
+              <p>Whether to enable portrait relighting effect.<wbr/></p>
+            </td>
+
+            <td class="entry_units">
+            </td>
+
+            <td class="entry_range">
+            </td>
+
+            <td class="entry_hal_version">
+              <p>3.<wbr/>2</p>
+            </td>
+
+            <td class="entry_tags">
+            </td>
+
+          </tr>
+
+
+          <tr class="entry_spacer"><td class="entry_spacer" colspan="7"></td></tr>
+           <!-- end of entry -->
+        
+        
+
       <!-- end of kind -->
       </tbody>
 
@@ -41593,6 +43656,12 @@ output format/<wbr/>size combination for Jpeg/<wbr/>R streams for CaptureRequest
           <li><a href="#static_android.heic.availableHeicStreamConfigurationsMaximumResolution">android.heic.availableHeicStreamConfigurationsMaximumResolution</a> (static)</li>
           <li><a href="#static_android.heic.availableHeicMinFrameDurationsMaximumResolution">android.heic.availableHeicMinFrameDurationsMaximumResolution</a> (static)</li>
           <li><a href="#static_android.heic.availableHeicStallDurationsMaximumResolution">android.heic.availableHeicStallDurationsMaximumResolution</a> (static)</li>
+          <li><a href="#static_android.heic.availableHeicUltraHdrStreamConfigurations">android.heic.availableHeicUltraHdrStreamConfigurations</a> (static)</li>
+          <li><a href="#static_android.heic.availableHeicUltraHdrMinFrameDurations">android.heic.availableHeicUltraHdrMinFrameDurations</a> (static)</li>
+          <li><a href="#static_android.heic.availableHeicUltraHdrStallDurations">android.heic.availableHeicUltraHdrStallDurations</a> (static)</li>
+          <li><a href="#static_android.heic.availableHeicUltraHdrStreamConfigurationsMaximumResolution">android.heic.availableHeicUltraHdrStreamConfigurationsMaximumResolution</a> (static)</li>
+          <li><a href="#static_android.heic.availableHeicUltraHdrMinFrameDurationsMaximumResolution">android.heic.availableHeicUltraHdrMinFrameDurationsMaximumResolution</a> (static)</li>
+          <li><a href="#static_android.heic.availableHeicUltraHdrStallDurationsMaximumResolution">android.heic.availableHeicUltraHdrStallDurationsMaximumResolution</a> (static)</li>
         </ul>
       </li> <!-- tag_HEIC -->
       <li id="tag_FUTURE">FUTURE - 
diff --git a/camera/docs/fwk_only_metadata_tags.mako b/camera/docs/fwk_only_metadata_tags.mako
new file mode 100644
index 00000000..95f39b8c
--- /dev/null
+++ b/camera/docs/fwk_only_metadata_tags.mako
@@ -0,0 +1,44 @@
+## -*- coding: utf-8 -*-
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+#include <array>
+#pragma once
+
+/**
+ * ! Do not edit this file directly !
+ *
+ * Generated automatically from fwk_only_metadata_tags.mako. To be included in libcameraservice
+ * only by Camera3Device.cpp.
+ */
+
+namespace android {
+
+/**
+ * Framework only CaptureRequest keys. To be used for filtering out keys in CaptureRequest
+ * before sending to the HAL.
+ */
+constexpr std::array kFwkOnlyMetadataKeys = {
+  %for sec in find_all_sections(metadata):
+    %for entry in find_unique_entries(sec):
+      %if metadata.is_entry_this_kind(entry, 'controls') and is_not_hal_visible(entry):
+        ${entry.name |csym},
+      %endif
+    %endfor
+  %endfor
+};
+
+} //namespace android
diff --git a/camera/docs/metadata-generate b/camera/docs/metadata-generate
index 20445487..fe8136ba 100755
--- a/camera/docs/metadata-generate
+++ b/camera/docs/metadata-generate
@@ -43,7 +43,8 @@ ctstopdir="$ANDROID_BUILD_TOP/cts/tests/camera/"
 outdir="$ANDROID_PRODUCT_OUT/obj/ETC/system-media-camera-docs_intermediates"
 ndk_header_dir="$ANDROID_BUILD_TOP/frameworks/av/camera/ndk/include/camera"
 ndk_impl_dir="$ANDROID_BUILD_TOP/frameworks/av/camera/ndk/impl"
-libcameraservice_aidl_dir="$ANDROID_BUILD_TOP/frameworks/av/services/camera/libcameraservice/aidl"
+libcameraservice_dir="$ANDROID_BUILD_TOP/frameworks/av/services/camera/libcameraservice"
+libcameraservice_aidl_dir="$libcameraservice_dir/aidl"
 device_info_dir="$ANDROID_BUILD_TOP/cts/tools/cts-device-info/"`
         `"src/com/android/cts/deviceinfo"
 out_files=()
@@ -239,6 +240,9 @@ gen_file ndk_camera_metadata_asserts.mako ../src/ndk_camera_metadata_asserts.cpp
 #Generate tags with vndk versions for filtering
 gen_file_abs vndk_camera_metadata_tags.mako "$libcameraservice_aidl_dir/VndkVersionMetadataTags.h" yes || exit 1
 
+#Generate framework only tags being filtered out before sending to HAL
+gen_file_abs fwk_only_metadata_tags.mako "$libcameraservice_dir/FwkOnlyMetadataTags.h" yes || exit 1
+
 #Generate Session Characteristics Keys
 gen_file_abs session_characteristics_tags.mako "$libcameraservice_aidl_dir/SessionCharacteristicsTags.h" yes || exit 1
 
diff --git a/camera/docs/metadata_definitions.xml b/camera/docs/metadata_definitions.xml
index 0e11e293..f947d6c2 100644
--- a/camera/docs/metadata_definitions.xml
+++ b/camera/docs/metadata_definitions.xml
@@ -166,6 +166,9 @@ xsi:schemaLocation="http://schemas.android.com/service/camera/metadata/ metadata
     </typedef>
     <typedef name="lensIntrinsicsSample">
         <language name="java">android.hardware.camera2.params.LensIntrinsicsSample</language>
+      </typedef>
+    <typedef name="sharedSessionConfiguration">
+        <language name="java">android.hardware.camera2.params.SharedSessionConfiguration</language>
     </typedef>
   </types>
 
@@ -211,12 +214,26 @@ xsi:schemaLocation="http://schemas.android.com/service/camera/metadata/ metadata
               (or defaults if AWB has never been run).
             </notes>
             </value>
+            <value hal_version="3.11" aconfig_flag="color_temperature">CCT
+              <notes>Use
+                android.colorCorrection.colorTemperature and
+                android.colorCorrection.colorTint to adjust the white balance based
+                on correlated color temperature.
+
+                If AWB is enabled with `android.control.awbMode != OFF`, then
+                CCT is ignored.
+              </notes>
+            </value>
           </enum>
 
           <description>
           The mode control selects how the image data is converted from the
           sensor's native color into linear sRGB color.
           </description>
+          <range>Starting from API level 36, android.colorCorrection.availableModes
+          can be used to check the list of supported values. Prior to API level 36,
+          TRANSFORM_MATRIX, HIGH_QUALITY, and FAST are guaranteed to be available
+          as valid modes on devices that support this key.</range>
           <details>
           When auto-white balance (AWB) is enabled with android.control.awbMode, this
           control is overridden by the AWB routine. When AWB is disabled, the
@@ -418,6 +435,99 @@ xsi:schemaLocation="http://schemas.android.com/service/camera/metadata/ metadata
           <tag id="V1" />
         </entry>
       </static>
+      <controls>
+        <entry name="colorTemperature" type="int32" visibility="public" optional="true"
+          aconfig_flag="color_temperature" hal_version="3.11">
+          <description>
+            Specifies the color temperature for CCT mode in Kelvin
+            to adjust the white balance of the image.
+          </description>
+          <units>Kelvin</units>
+          <range>android.colorCorrection.colorTemperatureRange</range>
+          <details>
+            Sets the color temperature in Kelvin units for when
+            android.colorCorrection.mode is CCT to adjust the
+            white balance of the image.
+
+            If CCT mode is enabled without a requested color temperature,
+            a default value will be set by the camera device. The default value can be
+            retrieved by checking the corresponding capture result. Color temperatures
+            requested outside the advertised android.colorCorrection.colorTemperatureRange
+            will be clamped.
+          </details>
+        </entry>
+        <entry name="colorTint" type="int32" visibility="public" optional="true"
+          aconfig_flag="color_temperature" hal_version="3.11">
+          <description>
+            Specifies the color tint for CCT mode to adjust the white
+            balance of the image.
+          </description>
+          <units>D_uv defined as the distance from the Planckian locus on the CIE 1931 xy
+          chromaticity diagram, with the range ±50 mapping to ±0.01 D_uv</units>
+          <range>The supported range, -50 to +50, corresponds to a D_uv distance
+          of ±0.01 below and above the Planckian locus. Some camera devices may have
+          limitations to achieving the full ±0.01 D_uv range at some color temperatures
+          (e.g., below 1500K). In these cases, the applied D_uv value may be clamped and
+          the actual color tint will be reported in the android.colorCorrection.colorTint
+          result.</range>
+          <details>
+            Sets the color tint for when android.colorCorrection.mode
+            is CCT to adjust the white balance of the image.
+
+            If CCT mode is enabled without a requested color tint,
+            a default value will be set by the camera device. The default value can be
+            retrieved by checking the corresponding capture result. Color tints requested
+            outside the supported range will be clamped to the nearest limit (-50 or +50).
+          </details>
+        </entry>
+      </controls>
+      <dynamic>
+        <clone entry="android.colorCorrection.colorTemperature" kind="controls">
+        </clone>
+        <clone entry="android.colorCorrection.colorTint" kind="controls">
+        </clone>
+      </dynamic>
+      <static>
+        <entry name="colorTemperatureRange" type="int32" visibility="public"
+               optional="true" container="array" typedef="rangeInt"
+               aconfig_flag="color_temperature" hal_version="3.11">
+          <array>
+            <size>2</size>
+          </array>
+          <description>The range of supported color temperature values for
+            android.colorCorrection.colorTemperature.</description>
+          <range>
+            The minimum supported range will be [2856K,6500K]. The maximum supported
+            range will be [1000K,40000K].
+          </range>
+          <details>
+            This key lists the valid range of color temperature values for
+            android.colorCorrection.colorTemperature supported by this camera device.
+
+            This key will be null on devices that do not support CCT mode for
+            android.colorCorrection.mode.
+          </details>
+        </entry>
+        <entry name="availableModes" type="byte" visibility="public"
+        optional="true" type_notes="list of enums" container="array" typedef="enumList"
+        aconfig_flag="color_temperature" hal_version="3.11">
+          <array>
+            <size>n</size>
+          </array>
+          <description>
+            List of color correction modes for android.colorCorrection.mode that are
+            supported by this camera device.
+          </description>
+          <range>Any value listed in android.colorCorrection.mode</range>
+          <details>
+            This key lists the valid modes for android.colorCorrection.mode. If no
+            color correction modes are available for a device, this key will be null.
+
+            Camera devices that have a FULL hardware level will always include at least
+            FAST, HIGH_QUALITY, and TRANSFORM_MATRIX modes.
+          </details>
+        </entry>
+      </static>
     </section>
     <section name="control">
       <controls>
@@ -632,6 +742,14 @@ xsi:schemaLocation="http://schemas.android.com/service/camera/metadata/ metadata
                 android.sensor.frameDuration are ignored. The
                 application has control over the various
                 android.flash.* fields.
+
+                If the device supports manual flash strength control, i.e.,
+                if android.flash.singleStrengthMaxLevel and
+                android.flash.torchStrengthMaxLevel are greater than 1, then
+                the auto-exposure (AE) precapture metering sequence should be
+                triggered for the configured flash mode and strength to avoid
+                the image being incorrectly exposed at different
+                android.flash.strengthLevel.
               </notes>
             </value>
             <value>ON_AUTO_FLASH
@@ -740,7 +858,9 @@ xsi:schemaLocation="http://schemas.android.com/service/camera/metadata/ metadata
             application's selected exposure time, sensor sensitivity,
             and frame duration (android.sensor.exposureTime,
             android.sensor.sensitivity, and
-            android.sensor.frameDuration). If one of the FLASH modes
+            android.sensor.frameDuration). If android.control.aePriorityMode is
+            enabled, the relevant priority CaptureRequest settings will not be overridden.
+            See android.control.aePriorityMode for more details. If one of the FLASH modes
             is selected, the camera device's flash unit controls are
             also overridden.
 
@@ -754,6 +874,14 @@ xsi:schemaLocation="http://schemas.android.com/service/camera/metadata/ metadata
             camera device auto-exposure routine for the overridden
             fields for a given capture will be available in its
             CaptureResult.
+
+            When android.control.aeMode is AE_MODE_ON and if the device
+            supports manual flash strength control, i.e.,
+            if android.flash.singleStrengthMaxLevel and
+            android.flash.torchStrengthMaxLevel are greater than 1, then
+            the auto-exposure (AE) precapture metering sequence should be
+            triggered to avoid the image being incorrectly exposed at
+            different android.flash.strengthLevel.
           </details>
           <tag id="BC" />
         </entry>
@@ -842,7 +970,7 @@ xsi:schemaLocation="http://schemas.android.com/service/camera/metadata/ metadata
               {@link android.hardware.camera2.CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_ULTRA_HIGH_RESOLUTION_SENSOR}
               capability or devices where
               {@link CameraCharacteristics#getAvailableCaptureRequestKeys}
-              lists {@link CaptureRequest#SENSOR_PIXEL_MODE android.sensor.pixelMode}
+              lists android.sensor.pixelMode,
               android.sensor.info.activeArraySizeMaximumResolution /
               android.sensor.info.preCorrectionActiveArraySizeMaximumResolution must be used as the
               coordinate system for requests where android.sensor.pixelMode is set to
@@ -1199,7 +1327,7 @@ xsi:schemaLocation="http://schemas.android.com/service/camera/metadata/ metadata
               {@link android.hardware.camera2.CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_ULTRA_HIGH_RESOLUTION_SENSOR}
               capability or devices where
               {@link CameraCharacteristics#getAvailableCaptureRequestKeys}
-              lists {@link CaptureRequest#SENSOR_PIXEL_MODE android.sensor.pixelMode},
+              lists android.sensor.pixelMode,
               android.sensor.info.activeArraySizeMaximumResolution /
               android.sensor.info.preCorrectionActiveArraySizeMaximumResolution must be used as the
               coordinate system for requests where android.sensor.pixelMode is set to
@@ -1559,7 +1687,7 @@ xsi:schemaLocation="http://schemas.android.com/service/camera/metadata/ metadata
               {@link android.hardware.camera2.CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_ULTRA_HIGH_RESOLUTION_SENSOR}
               capability or devices where
               {@link CameraCharacteristics#getAvailableCaptureRequestKeys}
-              lists {@link CaptureRequest#SENSOR_PIXEL_MODE android.sensor.pixelMode},
+              lists android.sensor.pixelMode,
               android.sensor.info.activeArraySizeMaximumResolution /
               android.sensor.info.preCorrectionActiveArraySizeMaximumResolution must be used as the
               coordinate system for requests where android.sensor.pixelMode is set to
@@ -3961,6 +4089,132 @@ xsi:schemaLocation="http://schemas.android.com/service/camera/metadata/ metadata
           </details>
         </entry>
       </dynamic>
+      <controls>
+        <entry name="zoomMethod" type="byte" visibility="fwk_public" enum="true"
+            hwlevel="limited" aconfig_flag="zoom_method" hal_version="3.11">
+          <enum>
+            <value id="0">AUTO
+            <notes>
+              The camera device automatically detects whether the application does zoom with
+              android.scaler.cropRegion or android.control.zoomRatio, and in turn decides which
+              metadata tag reflects the effective zoom level.
+            </notes></value>
+            <value id="1">ZOOM_RATIO
+            <notes>
+              The application intends to control zoom via android.control.zoomRatio, and
+              the effective zoom level is reflected by android.control.zoomRatio in capture results.
+            </notes></value>
+          </enum>
+          <description>
+            Whether the application uses android.scaler.cropRegion or android.control.zoomRatio
+            to control zoom levels.
+          </description>
+          <details>
+            If set to AUTO, the camera device detects which capture request key the application uses
+            to do zoom, android.scaler.cropRegion or android.control.zoomRatio. If
+            the application doesn't set android.scaler.zoomRatio or sets it to 1.0 in the capture
+            request, the effective zoom level is reflected in android.scaler.cropRegion in capture
+            results. If android.control.zoomRatio is set to values other than 1.0, the effective
+            zoom level is reflected in android.control.zoomRatio. AUTO is the default value
+            for this control, and also the behavior of the OS before Android version
+            {@link android.os.Build.VERSION_CODES#BAKLAVA BAKLAVA}.
+
+            If set to ZOOM_RATIO, the application explicitly specifies zoom level be controlled
+            by android.control.zoomRatio, and the effective zoom level is reflected in
+            android.control.zoomRatio in capture results. This addresses an ambiguity with AUTO,
+            with which the camera device cannot know if the application is using cropRegion or
+            zoomRatio at 1.0x.
+          </details>
+          <hal_details>
+            Do not use this key directly. It's for camera framework usage,
+            and not for HAL consumption.
+          </hal_details>
+        </entry>
+      </controls>
+      <dynamic>
+        <clone entry="android.control.zoomMethod" kind="controls">
+        </clone>
+      </dynamic>
+      <controls>
+        <entry name="aePriorityMode" type="byte" visibility="public"
+            optional="true" enum="true" aconfig_flag="ae_priority" hal_version="3.11">
+          <enum>
+            <value>OFF
+              <notes>
+                Disable AE priority mode. This is the default value.
+              </notes>
+            </value>
+            <value>SENSOR_SENSITIVITY_PRIORITY
+              <notes>
+              The camera device's auto-exposure routine is active and
+              prioritizes the application-selected ISO (android.sensor.sensitivity).
+
+              The application has control over android.sensor.sensitivity while
+              the application's values for android.sensor.exposureTime and
+              android.sensor.frameDuration are ignored.
+              </notes>
+            </value>
+            <value>SENSOR_EXPOSURE_TIME_PRIORITY
+              <notes>
+              The camera device's auto-exposure routine is active and
+              prioritizes the application-selected exposure time
+              (android.sensor.exposureTime).
+
+              The application has control over android.sensor.exposureTime while
+              the application's values for android.sensor.sensitivity and
+              android.sensor.frameDuration are ignored.
+              </notes>
+            </value>
+          </enum>
+          <description>
+            Turn on AE priority mode.
+          </description>
+          <details>
+            This control is only effective if android.control.mode is
+            AUTO and android.control.aeMode is set to one of its
+            ON modes, with the exception of ON_LOW_LIGHT_BOOST_BRIGHTNESS_PRIORITY.
+
+            When a priority mode is enabled, the camera device's
+            auto-exposure routine will maintain the application's
+            selected parameters relevant to the priority mode while overriding
+            the remaining exposure parameters
+            (android.sensor.exposureTime, android.sensor.sensitivity, and
+            android.sensor.frameDuration). For example, if
+            SENSOR_SENSITIVITY_PRIORITY mode is enabled, the camera device will
+            maintain the application-selected android.sensor.sensitivity
+            while adjusting android.sensor.exposureTime
+            and android.sensor.frameDuration. The overridden fields for a
+            given capture will be available in its CaptureResult.
+          </details>
+          <hal_details>
+          The total sensitivity applied for SENSOR_SENSITIVITY_PRIORITY should not be
+          adjusted by any HAL applied android.control.postRawSensitivityBoost.
+          </hal_details>
+        </entry>
+      </controls>
+      <dynamic>
+        <clone entry="android.control.aePriorityMode" kind="controls">
+        </clone>
+      </dynamic>
+      <static>
+        <entry name="aeAvailablePriorityModes" type="byte" visibility="public"
+               type_notes="list of enums" container="array" typedef="enumList"
+               aconfig_flag="ae_priority" hal_version="3.11">
+          <array>
+            <size>n</size>
+          </array>
+          <description>
+            List of auto-exposure priority modes for android.control.aePriorityMode
+            that are supported by this camera device.
+          </description>
+          <range>Any value listed in android.control.aePriorityMode</range>
+          <details>
+            This entry lists the valid modes for
+            android.control.aePriorityMode for this camera device.
+            If no AE priority modes are available for a device, this will only list OFF.
+          </details>
+        </entry>
+      </static>
     </section>
     <section name="demosaic">
       <controls>
@@ -7625,8 +7879,7 @@ xsi:schemaLocation="http://schemas.android.com/service/camera/metadata/ metadata
             For camera devices with the
             {@link android.hardware.camera2.CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_ULTRA_HIGH_RESOLUTION_SENSOR}
             capability or devices where {@link CameraCharacteristics#getAvailableCaptureRequestKeys}
-            lists {@link CaptureRequest#SENSOR_PIXEL_MODE android.sensor.pixelMode}
-
+            lists android.sensor.pixelMode,
             android.sensor.info.activeArraySizeMaximumResolution /
             android.sensor.info.preCorrectionActiveArraySizeMaximumResolution must be used as the
             coordinate system for requests where android.sensor.pixelMode is set to
@@ -9546,7 +9799,9 @@ xsi:schemaLocation="http://schemas.android.com/service/camera/metadata/ metadata
           The final exposure time used will be available in the output capture result.
 
           This control is only effective if android.control.aeMode or android.control.mode is set to
-          OFF; otherwise the auto-exposure algorithm will override this value.
+          OFF; otherwise the auto-exposure algorithm will override this value. However, in the
+          case that android.control.aePriorityMode is set to SENSOR_EXPOSURE_TIME_PRIORITY, this
+          control will be effective and not controlled by the auto-exposure algorithm.
           </details>
           <tag id="V1" />
         </entry>
@@ -9658,7 +9913,9 @@ xsi:schemaLocation="http://schemas.android.com/service/camera/metadata/ metadata
           output capture result.
 
           This control is only effective if android.control.aeMode or android.control.mode is set to
-          OFF; otherwise the auto-exposure algorithm will override this value.
+          OFF; otherwise the auto-exposure algorithm will override this value. However, in the
+          case that android.control.aePriorityMode is set to SENSOR_SENSITIVITY_PRIORITY, this
+          control will be effective and not controlled by the auto-exposure algorithm.
 
           Note that for devices supporting postRawSensitivityBoost, the total sensitivity applied
           to the final processed image is the combination of android.sensor.sensitivity and
@@ -10090,7 +10347,7 @@ xsi:schemaLocation="http://schemas.android.com/service/camera/metadata/ metadata
             This key will only be present for devices which advertise the
             {@link android.hardware.camera2.CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_ULTRA_HIGH_RESOLUTION_SENSOR}
             capability or devices where {@link CameraCharacteristics#getAvailableCaptureRequestKeys}
-            lists {@link CaptureRequest#SENSOR_PIXEL_MODE android.sensor.pixelMode}
+            lists android.sensor.pixelMode.
             </details>
             <ndk_details>
             The data representation is `int[4]`, which maps to `(left, top, width, height)`.
@@ -10123,7 +10380,7 @@ xsi:schemaLocation="http://schemas.android.com/service/camera/metadata/ metadata
             This key will only be present for devices which advertise the
             {@link android.hardware.camera2.CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_ULTRA_HIGH_RESOLUTION_SENSOR}
             capability or devices where {@link CameraCharacteristics#getAvailableCaptureRequestKeys}
-            lists {@link CaptureRequest#SENSOR_PIXEL_MODE android.sensor.pixelMode}
+            lists android.sensor.pixelMode.
             </details>
             <tag id="RAW" />
           </entry>
@@ -10148,7 +10405,7 @@ xsi:schemaLocation="http://schemas.android.com/service/camera/metadata/ metadata
             This key will only be present for devices which advertise the
             {@link android.hardware.camera2.CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_ULTRA_HIGH_RESOLUTION_SENSOR}
             capability or devices where {@link CameraCharacteristics#getAvailableCaptureRequestKeys}
-            lists {@link CaptureRequest#SENSOR_PIXEL_MODE android.sensor.pixelMode}
+            lists android.sensor.pixelMode.
             </details>
             <ndk_details>
             The data representation is `int[4]`, which maps to `(left, top, width, height)`.
@@ -10192,7 +10449,7 @@ xsi:schemaLocation="http://schemas.android.com/service/camera/metadata/ metadata
 
             * This key will be present if
               {@link CameraCharacteristics#getAvailableCaptureRequestKeys}
-              lists {@link CaptureRequest#SENSOR_PIXEL_MODE android.sensor.pixelMode}, since RAW
+              lists android.sensor.pixelMode, since RAW
               images may not necessarily have a regular bayer pattern when
               {@link CaptureRequest#SENSOR_PIXEL_MODE android.sensor.pixelMode} is set to
               {@link android.hardware.camera2.CameraMetadata#SENSOR_PIXEL_MODE_MAXIMUM_RESOLUTION}.
@@ -12124,6 +12381,15 @@ xsi:schemaLocation="http://schemas.android.com/service/camera/metadata/ metadata
           height dimensions are given in android.sensor.info.pixelArraySize.
           This may include hot pixels that lie outside of the active array
           bounds given by android.sensor.info.activeArraySize.
+
+          For camera devices with the
+          {@link android.hardware.camera2.CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_ULTRA_HIGH_RESOLUTION_SENSOR}
+          capability or devices where
+          {@link CameraCharacteristics#getAvailableCaptureRequestKeys}
+          lists android.sensor.pixelMode,
+          android.sensor.info.pixelArraySizeMaximumResolution will be used as the
+          pixel array size if the corresponding request sets android.sensor.pixelMode to
+          {@link android.hardware.camera2.CameraMetadata#SENSOR_PIXEL_MODE_MAXIMUM_RESOLUTION}.
           </details>
           <hal_details>
           A hotpixel map contains the coordinates of pixels on the camera
@@ -12985,7 +13251,7 @@ xsi:schemaLocation="http://schemas.android.com/service/camera/metadata/ metadata
               HIDL ICameraDevice version 3.5.
               </notes>
             </value>
-            <value hal_version="3.10" aconfig_flag="session_hal_buf_manager">
+            <value hal_version="3.10">
               SESSION_CONFIGURABLE
               <notes>
               This camera device supports the buffer management APIs provided by AIDL ICameraDevice
@@ -13040,6 +13306,7 @@ xsi:schemaLocation="http://schemas.android.com/service/camera/metadata/ metadata
           <enum>
             <value id="34">UPSIDE_DOWN_CAKE</value>
             <value id="35">VANILLA_ICE_CREAM</value>
+            <value id="36" hal_version="3.11">BAKLAVA</value>
           </enum>
           <description>The version of the session configuration query
           {@link android.hardware.camera2.CameraDevice.CameraDeviceSetup#isSessionConfigurationSupported}
@@ -13104,6 +13371,15 @@ xsi:schemaLocation="http://schemas.android.com/service/camera/metadata/ metadata
           All of the above configurations can be set up with a SessionConfiguration. The list of
           OutputConfiguration contains the stream configurations and DYNAMIC_RANGE_PROFILE, and
           the AE_TARGET_FPS_RANGE and VIDEO_STABILIZATION_MODE are set as session parameters.
+
+          When set to BAKLAVA, the additional stream combinations below are verified
+          by the compliance tests:
+
+          Target 1    |     Size      | Target 2        |     Size     |
+          :----------:|:-------------:|:---------------:|:------------:|
+          PRIV        | S1080P        | PRIV            | S1080P       |
+          PRIV        | S1080P        | PRIV            | S1440P       |
+
           </details>
           <hal_details>
           Preview stabilization must be orthogonal to other features. In other words, if preview
@@ -13999,8 +14275,8 @@ xsi:schemaLocation="http://schemas.android.com/service/camera/metadata/ metadata
           For camera devices with the
           {@link android.hardware.camera2.CameraMetadata#REQUEST_AVAILABLE_CAPABILITIES_ULTRA_HIGH_RESOLUTION_SENSOR}
           capability or devices where {@link CameraCharacteristics#getAvailableCaptureRequestKeys}
-          lists {@link CaptureRequest#SENSOR_PIXEL_MODE android.sensor.pixelMode}
-          , the current active physical device
+          lists android.sensor.pixelMode,
+          the current active physical device
           android.sensor.info.activeArraySizeMaximumResolution /
           android.sensor.info.preCorrectionActiveArraySizeMaximumResolution must be used as the
           coordinate system for requests where android.sensor.pixelMode is set to
@@ -14378,6 +14654,151 @@ xsi:schemaLocation="http://schemas.android.com/service/camera/metadata/ metadata
           </hal_details>
           <tag id="HEIC" />
         </entry>
+        <entry name="availableHeicUltraHdrStreamConfigurations" type="int32" visibility="ndk_public"
+            enum="true" container="array" typedef="streamConfiguration" hwlevel="limited"
+            aconfig_flag="camera_heif_gainmap" hal_version="3.11">
+          <array>
+            <size>n</size>
+            <size>4</size>
+          </array>
+          <enum>
+            <value>OUTPUT</value>
+            <value>INPUT</value>
+          </enum>
+          <description>The available HEIC (ISO/IEC 23008-12/24) UltraHDR stream
+          configurations that this camera device supports
+          (i.e. format, width, height, output/input stream).
+          </description>
+          <details>
+          The configurations are listed as `(format, width, height, input?)` tuples.
+
+          All the static, control, and dynamic metadata tags related to JPEG apply to HEIC formats.
+          Configuring JPEG and HEIC streams at the same time is not supported.
+          </details>
+          <ndk_details>
+          All the configuration tuples `(format, width, height, input?)` will contain
+          AIMAGE_FORMAT_HEIC format as OUTPUT only.
+          </ndk_details>
+          <hal_details>
+          These are output stream configurations for use with dataSpace DATASPACE_HEIF_ULTRAHDR.
+          </hal_details>
+         <tag id="HEIC" />
+        </entry>
+        <entry name="availableHeicUltraHdrMinFrameDurations" type="int64" visibility="ndk_public"
+               container="array" typedef="streamConfigurationDuration" hwlevel="limited"
+               aconfig_flag="camera_heif_gainmap" hal_version="3.11">
+          <array>
+            <size>4</size>
+            <size>n</size>
+          </array>
+          <description>This lists the minimum frame duration for each
+          format/size combination for HEIC UltraHDR output formats.
+          </description>
+          <units>(format, width, height, ns) x n</units>
+          <details>
+          This should correspond to the frame duration when only that
+          stream is active, with all processing (typically in android.*.mode)
+          set to either OFF or FAST.
+
+          When multiple streams are used in a request, the minimum frame
+          duration will be max(individual stream min durations).
+
+          See android.sensor.frameDuration and
+          android.scaler.availableStallDurations for more details about
+          calculating the max frame rate.
+          </details>
+          <tag id="HEIC" />
+        </entry>
+        <entry name="availableHeicUltraHdrStallDurations" type="int64" visibility="ndk_public"
+               container="array" typedef="streamConfigurationDuration" hwlevel="limited"
+               aconfig_flag="camera_heif_gainmap" hal_version="3.11">
+          <array>
+            <size>4</size>
+            <size>n</size>
+          </array>
+          <description>This lists the maximum stall duration for each
+          output format/size combination for HEIC UltraHDR streams.
+          </description>
+          <units>(format, width, height, ns) x n</units>
+          <details>
+          A stall duration is how much extra time would get added
+          to the normal minimum frame duration for a repeating request
+          that has streams with non-zero stall.
+
+          This functions similarly to
+          android.scaler.availableStallDurations for HEIC UltraHDR
+          streams.
+
+          All HEIC output stream formats may have a nonzero stall
+          duration.
+          </details>
+          <tag id="HEIC" />
+        </entry>
+        <entry name="availableHeicUltraHdrStreamConfigurationsMaximumResolution" type="int32"
+          visibility="ndk_public" enum="true" container="array" typedef="streamConfiguration"
+          aconfig_flag="camera_heif_gainmap" hal_version="3.11">
+          <array>
+            <size>n</size>
+            <size>4</size>
+          </array>
+          <enum>
+            <value>OUTPUT</value>
+            <value>INPUT</value>
+          </enum>
+          <description>The available HEIC (ISO/IEC 23008-12/24) UltraHDR stream
+          configurations that this camera device supports
+          (i.e. format, width, height, output/input stream) for CaptureRequests where
+          android.sensor.pixelMode is set to
+          {@link android.hardware.camera2.CameraMetadata#SENSOR_PIXEL_MODE_MAXIMUM_RESOLUTION}.
+          </description>
+          <details>
+          Refer to android.heic.availableHeicStreamConfigurations for details.
+          </details>
+          <ndk_details>
+          All the configuration tuples `(format, width, height, input?)` will contain
+          AIMAGE_FORMAT_HEIC format as OUTPUT only.
+          </ndk_details>
+          <hal_details>
+          These are output stream configurations for use with dataSpace DATASPACE_HEIF_ULTRAHDR.
+          </hal_details>
+         <tag id="HEIC" />
+        </entry>
+        <entry name="availableHeicUltraHdrMinFrameDurationsMaximumResolution" type="int64"
+          visibility="ndk_public" container="array" typedef="streamConfigurationDuration"
+          aconfig_flag="camera_heif_gainmap" hal_version="3.11">
+          <array>
+            <size>4</size>
+            <size>n</size>
+          </array>
+          <description>This lists the minimum frame duration for each
+          format/size combination for HEIC UltraHDR output formats for CaptureRequests where
+          android.sensor.pixelMode is set to
+          {@link android.hardware.camera2.CameraMetadata#SENSOR_PIXEL_MODE_MAXIMUM_RESOLUTION}.
+          </description>
+          <units>(format, width, height, ns) x n</units>
+          <details>
+          Refer to android.heic.availableHeicMinFrameDurations for details.
+          </details>
+          <tag id="HEIC" />
+        </entry>
+        <entry name="availableHeicUltraHdrStallDurationsMaximumResolution" type="int64"
+          visibility="ndk_public" container="array" typedef="streamConfigurationDuration"
+          aconfig_flag="camera_heif_gainmap" hal_version="3.11">
+          <array>
+            <size>4</size>
+            <size>n</size>
+          </array>
+          <description>This lists the maximum stall duration for each
+          output format/size combination for HEIC UltraHDR streams for CaptureRequests where
+          android.sensor.pixelMode is set to
+          {@link android.hardware.camera2.CameraMetadata#SENSOR_PIXEL_MODE_MAXIMUM_RESOLUTION}.
+          </description>
+          <units>(format, width, height, ns) x n</units>
+          <details>
+          Refer to android.heic.availableHeicStallDurations for details.
+          </details>
+          <tag id="HEIC" />
+        </entry>
       </static>
     </section>
     <section name="automotive">
@@ -14647,6 +15068,52 @@ xsi:schemaLocation="http://schemas.android.com/service/camera/metadata/ metadata
         </entry>
         <clone entry="android.extension.strength" kind="controls">
         </clone>
+        <entry name="nightModeIndicator" type="int32" visibility="public" optional="true"
+               enum="true" aconfig_flag="night_mode_indicator" hal_version="3.11">
+          <enum>
+            <value>UNKNOWN
+              <notes>
+                The camera can't accurately assess the scene's lighting to determine if a Night Mode
+                Camera Extension capture would improve the photo. This can happen when the current
+                camera configuration doesn't support night mode indicator detection, such as when
+                the auto exposure mode is ON_AUTO_FLASH, ON_ALWAYS_FLASH, ON_AUTO_FLASH_REDEYE, or
+                ON_EXTERNAL_FLASH.
+              </notes>
+            </value>
+            <value>OFF
+              <notes>
+                The camera has detected lighting conditions that are sufficiently bright. Night
+                Mode Camera Extensions is available but may not be able to optimize the camera
+                settings to take a higher quality photo.
+              </notes>
+            </value>
+            <value>ON
+              <notes>
+                The camera has detected low-light conditions. It is recommended to use Night Mode
+                Camera Extension to optimize the camera settings to take a high-quality photo in
+                the dark.
+              </notes>
+            </value>
+          </enum>
+          <description>Indicates when to activate Night Mode Camera Extension for high-quality
+          still captures in low-light conditions.</description>
+          <details>
+            Provides awareness to the application when the current scene can benefit from using a
+            Night Mode Camera Extension to take a high-quality photo.
+
+            Support for this capture result can be queried via
+            {@link android.hardware.camera2.CameraCharacteristics#getAvailableCaptureResultKeys}.
+
+            If the device supports this capability then it will also support
+            {@link android.hardware.camera2.CameraExtensionCharacteristics#EXTENSION_NIGHT NIGHT}
+            and will be available in both
+            {@link android.hardware.camera2.CameraCaptureSession sessions} and
+            {@link android.hardware.camera2.CameraExtensionSession sessions}.
+
+            The value will be {@code UNKNOWN} in the following auto exposure modes: ON_AUTO_FLASH,
+            ON_ALWAYS_FLASH, ON_AUTO_FLASH_REDEYE, or ON_EXTERNAL_FLASH.
+          </details>
+        </entry>
       </dynamic>
     </section>
     <section name="jpegr">
@@ -14788,5 +15255,177 @@ xsi:schemaLocation="http://schemas.android.com/service/camera/metadata/ metadata
         </entry>
       </static>
     </section>
+    <section name="sharedSession">
+      <static>
+        <entry name="colorSpace" type="byte" visibility="fwk_only" optional="true"
+          enum="true" aconfig_flag="camera_multi_client" hal_version="3.11">
+          <enum>
+            <value id="-1">UNSPECIFIED</value>
+            <value id="0">SRGB</value>
+            <value id="7">DISPLAY_P3</value>
+            <value id="16">BT2020_HLG</value>
+          </enum>
+          <description>Color space used for shared session configuration for all the output targets
+            when camera is opened in shared mode. This should be one of the values specified in
+            availableColorSpaceProfilesMap.
+          </description>
+          <hal_details>
+            Do not set this property directly. Android camera framework will generate this tag if the
+            camera device can be opened in shared mode.
+          </hal_details>
+        </entry>
+        <entry name="outputConfigurations" type="int64" visibility="fwk_only"
+          optional="true" container="array" aconfig_flag="camera_multi_client"
+          hal_version="3.11">
+          <array>
+            <size>n</size>
+          </array>
+          <description>List of shared output configurations that this camera device supports when
+            camera is opened in shared mode. Array contains following entries for each supported
+            shared configuration:
+            1) surface type
+            2) width
+            3) height
+            4) format
+            5) mirrorMode
+            6) useReadoutTimestamp
+            7) timestampBase
+            8) dataspace
+            9) usage
+            10) streamUsecase
+            11) physical camera id len
+            12) physical camera id as UTF-8 null terminated string.
+          </description>
+          <hal_details>
+            Do not set this property directly. Android camera framework will generate this tag if the
+            camera device can be opened in shared mode.
+          </hal_details>
+        </entry>
+        <entry name="configuration" type="byte" visibility="fwk_system_public"
+          synthetic="true" optional="true" typedef="sharedSessionConfiguration"
+          aconfig_flag="camera_multi_client">
+          <description>The available stream configurations that this camera device supports for
+            shared capture session when camera is opened in shared mode. Android camera framework
+            will generate this tag if the camera device can be opened in shared mode.
+          </description>
+          <hal_details>
+            Do not set this property directly (it is synthetic and will not be available at the
+            HAL layer);
+          </hal_details>
+        </entry>
+      </static>
+    </section>
+    <section name="desktopEffects">
+      <static>
+        <entry name="capabilities" type="byte" visibility="system" optional="true"
+            enum="true" type_notes="list of enums" container="array" typedef="enumList"
+            aconfig_flag="desktop_effects">
+          <array>
+            <size>n</size>
+          </array>
+          <enum>
+            <value>BACKGROUND_BLUR
+              <notes>
+                Background blur can be activated via android.desktopEffects.backgroundBlurMode
+              </notes>
+            </value>
+            <value>FACE_RETOUCH
+              <notes>
+                Face retouch can be activated via android.desktopEffects.faceRetouchMode
+              </notes>
+            </value>
+            <value>PORTRAIT_RELIGHT
+              <notes>
+                Portrait relight can be activated via android.desktopEffects.portraitRelightMode
+              </notes>
+            </value>
+          </enum>
+          <description>
+            List of special effects supported by the camera device.
+          </description>
+          <details>
+            Available features supported by the camera device for large screen video conferencing.
+          </details>
+        </entry>
+        <entry name="backgroundBlurModes" type="byte" visibility="system" optional="true"
+            type_notes="list of enums (android.desktopEffects.backgroundBlurMode)" container="array"
+            typedef="enumList" aconfig_flag="desktop_effects">
+          <array>
+            <size>n</size>
+          </array>
+          <description>
+            List of background blur modes supported by the camera device. The key will only exist
+            if BACKGROUND_BLUR is listed by android.desktopEffects.capabilities.
+          </description>
+          <range>Any value listed in android.desktopEffects.backgroundBlurMode</range>
+          <details>
+            Lists the valid modes for android.desktopEffects.backgroundBlurMode.
+          </details>
+        </entry>
+      </static>
+      <controls>
+        <entry name="backgroundBlurMode" type="byte" visibility="system"
+            optional="true" enum="true" aconfig_flag="desktop_effects">
+          <enum>
+            <value>OFF
+              <notes>
+                Don't use background blur
+              </notes>
+            </value>
+            <value>LIGHT
+              <notes>
+                Blur the background with light blur strength
+              </notes>
+            </value>
+            <value>FULL
+              <notes>
+                Blur the background with full blur strength
+              </notes>
+            </value>
+          </enum>
+          <description>Control how the background should be blurred. Supported modes are listed in
+            android.desktopEffects.backgroundBlurModes by the camera device.</description>
+        </entry>
+        <entry name="faceRetouchMode" type="byte" visibility="system"
+            optional="true" enum="true" typedef="boolean" aconfig_flag="desktop_effects">
+          <enum>
+            <value>OFF
+              <notes>
+                Turn off face retouch
+              </notes>
+            </value>
+            <value>ON
+              <notes>
+                Turn on face retouch. A strength can be set by android.desktopEffects.faceRetouchStrength
+              </notes>
+            </value>
+          </enum>
+          <description>Whether to enable face retouch effect.</description>
+        </entry>
+        <entry name="faceRetouchStrength" type="byte" visibility="system"
+            optional="true" aconfig_flag="desktop_effects">
+          <description>Control the strength of face retouch applied to the frames. If
+            android.desktopEffects.faceRetouchMode in ON without a faceRetouchStrength,
+            a default will be set by the camera device.</description>
+          <units>1-100; 100 is maximum strength.</units>
+        </entry>
+        <entry name="portraitRelightMode" type="byte" visibility="system"
+            optional="true" enum="true" typedef="boolean" aconfig_flag="desktop_effects">
+          <enum>
+            <value>OFF
+              <notes>
+                Do not use portrait relight
+              </notes>
+            </value>
+            <value>ON
+              <notes>
+                Use portrait relight
+              </notes>
+            </value>
+          </enum>
+          <description>Whether to enable portrait relighting effect.</description>
+        </entry>
+      </controls>
+    </section>
   </namespace>
 </metadata>
diff --git a/camera/docs/metadata_definitions.xsd b/camera/docs/metadata_definitions.xsd
index c5458406..71e74bbf 100644
--- a/camera/docs/metadata_definitions.xsd
+++ b/camera/docs/metadata_definitions.xsd
@@ -200,14 +200,17 @@
         <attribute name="visibility">
             <simpleType>
                 <restriction base="string">
-                    <enumeration value="system" /> <!-- do not expose to java/NDK API -->
-                    <enumeration value="java_public" /> <!-- java as public SDK. Not included in NDK -->
-                    <enumeration value="ndk_public" /> <!-- public in NDK. @hide in java -->
-                    <enumeration value="hidden" /> <!-- java as @hide. Not included in NDK -->
-                    <enumeration value="extension" /> <!-- java as @hide. Included as a public key in the extensions. -->
-                    <enumeration value="public" /> <!-- public to both java and NDK -->
+                    <enumeration value="system" /> <!-- do not expose to java/NDK API, visible to HAL -->
+                    <enumeration value="java_public" /> <!-- java as public SDK. Not included in NDK, visible to HAL -->
+                    <enumeration value="ndk_public" /> <!-- public in NDK. @hide in java, visible to HAL -->
+                    <enumeration value="hidden" /> <!-- java as @hide. Not included in NDK, visible to HAL -->
+                    <enumeration value="extension" /> <!-- java as @hide. Included as a public key in the extensions, visible to HAL -->
+                    <enumeration value="public" /> <!-- public to both java and NDK, visible to HAL -->
                     <enumeration value="fwk_only" /> <!-- java as @hide. Not included in NDK. Not included in hal interfaces. -->
                     <enumeration value="fwk_java_public" /> <!-- public to java. Not included in NDK. Not included in hal interfaces. -->
+                    <enumeration value="fwk_system_public" /> <!-- system API in java. Not included in NDK. Not included in hal interfaces -->
+                    <enumeration value="fwk_public" /> <!-- public to both java and NDK. Not included in hal interfaces. -->
+                    <enumeration value="fwk_ndk_public" /> <!-- public to NDK. Not included in java or hal interfaces. -->
                 </restriction>
             </simpleType>
         </attribute>
diff --git a/camera/docs/metadata_helpers.py b/camera/docs/metadata_helpers.py
index c006f711..eafb9929 100644
--- a/camera/docs/metadata_helpers.py
+++ b/camera/docs/metadata_helpers.py
@@ -217,6 +217,7 @@ def protobuf_type(entry):
     "dynamicRangeProfiles"   : "DynamicRangeProfiles",
     "colorSpaceProfiles"     : "ColorSpaceProfiles",
     "versionCode"            : "int32",
+    "sharedSessionConfiguration"  : "SharedSessionConfiguration",
   }
 
   if typeName not in typename_to_protobuftype:
@@ -881,7 +882,8 @@ def javadoc(metadata, indent = 4):
     # Convert metadata entry "android.x.y.z" to form
     # "{@link CaptureRequest#X_Y_Z android.x.y.z}"
     def javadoc_crossref_filter(node):
-      if node.applied_visibility in ('public', 'java_public', 'fwk_java_public'):
+      if node.applied_visibility in ('public', 'java_public', 'fwk_java_public', 'fwk_public',\
+                                     'fwk_system_public'):
         return '{@link %s#%s %s}' % (kind_mapping[node.kind],
                                      jkey_identifier(node.name),
                                      node.name)
@@ -892,7 +894,7 @@ def javadoc(metadata, indent = 4):
     # "@see CaptureRequest#X_Y_Z"
     def javadoc_crossref_see_filter(node_set):
       node_set = (x for x in node_set if x.applied_visibility in \
-                  ('public', 'java_public', 'fwk_java_public'))
+                  ('public', 'java_public', 'fwk_java_public', 'fwk_public', 'fwk_system_public'))
 
       text = '\n'
       for node in node_set:
@@ -1373,7 +1375,6 @@ def any_visible(section, kind_name, visibilities):
                                                               'merged_entries'),
                                visibilities))
 
-
 def filter_visibility(entries, visibilities):
   """
   Remove entries whose applied visibility is not in the supplied visibilities.
@@ -1387,9 +1388,40 @@ def filter_visibility(entries, visibilities):
   """
   return (e for e in entries if e.applied_visibility in visibilities)
 
+def is_not_hal_visible(e):
+  """
+  Determine that the entry being passed in is not visible to HAL.
+
+  Args:
+    e: An entry node
+
+  Returns:
+    True if the entry is not visible to HAL
+  """
+  return (e.visibility == 'fwk_only' or
+          e.visibility == 'fwk_java_public' or
+          e.visibility == 'fwk_public' or
+          e.visibility == 'fwk_system_public' or
+          e.visibility == 'fwk_ndk_public' or
+          e.visibility == 'extension')
+
 def remove_hal_non_visible(entries):
   """
   Filter the given entries by removing those that are not HAL visible:
+  synthetic, fwk_only, extension, fwk_java_public, fwk_system_public, fwk_ndk_public,
+  or fwk_public.
+
+  Args:
+    entries: An iterable of Entry nodes
+
+  Yields:
+    An iterable of Entry nodes
+  """
+  return (e for e in entries if not (e.synthetic or is_not_hal_visible(e)))
+
+def remove_ndk_non_visible(entries):
+  """
+  Filter the given entries by removing those that are not NDK visible:
   synthetic, fwk_only, extension, or fwk_java_public.
 
   Args:
diff --git a/camera/docs/metadata_model.py b/camera/docs/metadata_model.py
index c83148f8..4238db9f 100644
--- a/camera/docs/metadata_model.py
+++ b/camera/docs/metadata_model.py
@@ -978,7 +978,7 @@ class EnumValue(Node):
     deprecated: A boolean, True if the enum should be deprecated.
     optional: A boolean
     visibility: A string, one of "system", "java_public", "ndk_public", "hidden", "public",
-                "fwk_java_public", "extension"
+                "fwk_java_public", "fwk_public", "fwk_ndk_public", "extension", "fwk_system_public"
     notes: A string describing the notes, or None.
     sdk_notes: A string describing extra notes for public SDK only
     ndk_notes: A string describing extra notes for public NDK only
@@ -1040,14 +1040,15 @@ class EnumValue(Node):
     parent_enum = None
     if (self.parent is not None and self.parent.parent is not None):
       parent_enum = self.parent.parent
-    if parent_enum is not None and parent_enum.visibility in ('fwk_only', 'fwk_java_public') \
-        or self._visibility in ('fwk_only', 'fwk_java_public'):
+    if parent_enum is not None and parent_enum.visibility in ('fwk_only', 'fwk_java_public',\
+        'fwk_public', 'fwk_ndk_public') or self._visibility in ('fwk_only', 'fwk_java_public',\
+        'fwk_public', 'fwk_ndk_public'):
       return ','
     return ', // HIDL v' + str(self._hal_major_version) + '.' + str(self.hal_minor_version)
 
   @property
   def hidden(self):
-    return self.visibility in {'hidden', 'ndk_public', 'test', 'extension'}
+    return self.visibility in {'hidden', 'ndk_public', 'test', 'extension', 'fwk_system_public'}
 
   @property
   def ndk_hidden(self):
@@ -1129,7 +1130,7 @@ class Entry(Node):
     container: The container attribute from <entry container="array">, or None.
     container_sizes: A sequence of size strings or None if container is None.
     enum: An Enum instance if the enum attribute is true, None otherwise.
-    visibility: The visibility of this entry ('system', 'hidden', 'public')
+    visibility: The visibility of this entry ('system', 'hidden', 'public' etc)
                 across the system. System entries are only visible in native code
                 headers. Hidden entries are marked @hide in managed code, while
                 public entries are visible in the Android SDK.
@@ -1266,14 +1267,14 @@ class Entry(Node):
 
   @property
   def hidl_comment_string(self):
-    if self._visibility in ('fwk_only', 'fwk_java_public'):
+    if self._visibility in ('fwk_only', 'fwk_java_public', 'fwk_public', 'fwk_ndk_public'):
       return self._visibility
     visibility_lj = str(self.applied_visibility).ljust(12)
     return visibility_lj + ' | HIDL v' + str(self._hal_major_version) + '.' + str(self._hal_minor_version)
 
   @property
   def applied_ndk_visible(self):
-    if self._visibility in ("public", "ndk_public"):
+    if self._visibility in ("public", "ndk_public", "fwk_public", "fwk_ndk_public"):
       return "true"
     return "false"
 
diff --git a/camera/docs/ndk_camera_metadata_tags.mako b/camera/docs/ndk_camera_metadata_tags.mako
index eb72dea6..fe9b5d53 100644
--- a/camera/docs/ndk_camera_metadata_tags.mako
+++ b/camera/docs/ndk_camera_metadata_tags.mako
@@ -94,7 +94,7 @@ typedef enum acamera_metadata_section_start {
 typedef enum acamera_metadata_tag {
     % for sec in find_all_sections(metadata):
 <%
-      entries = remove_hal_non_visible(find_unique_entries(sec))
+      entries = remove_ndk_non_visible(find_unique_entries(sec))
       skip_sec = all(e.applied_ndk_visible == "false" for e in entries)
       if skip_sec:
         continue
@@ -149,7 +149,7 @@ ${entry.applied_ndk_details | ndkdoc(metadata)}\
  */
 
 % for sec in find_all_sections(metadata):
-  % for entry in filter_ndk_visible(remove_hal_non_visible(find_unique_entries(sec))):
+  % for entry in filter_ndk_visible(remove_ndk_non_visible(find_unique_entries(sec))):
     % if entry.enum:
 // ${ndk(entry.name) | csym}
 typedef enum acamera_metadata_enum_${csym(ndk(entry.name)).lower()} {
diff --git a/camera/docs/ndk_name_to_tag.mako b/camera/docs/ndk_name_to_tag.mako
index 89cb6e27..69340364 100644
--- a/camera/docs/ndk_name_to_tag.mako
+++ b/camera/docs/ndk_name_to_tag.mako
@@ -43,7 +43,7 @@
 
     std::map<const char*, acamera_metadata_tag_t> ndk_metadata_name_to_tag {
 % for sec in find_all_sections(metadata):
-  % for entry in remove_hal_non_visible(find_unique_entries(sec)):
+  % for entry in remove_ndk_non_visible(find_unique_entries(sec)):
     % if entry.applied_ndk_visible == "true":
       {"${entry.name}", ${csym(ndk(entry.name))}},
     % endif
diff --git a/camera/include/system/camera_metadata_tags.h b/camera/include/system/camera_metadata_tags.h
index 76c36588..c73950e9 100644
--- a/camera/include/system/camera_metadata_tags.h
+++ b/camera/include/system/camera_metadata_tags.h
@@ -69,6 +69,8 @@ typedef enum camera_metadata_section {
     ANDROID_AUTOMOTIVE_LENS,
     ANDROID_EXTENSION,
     ANDROID_JPEGR,
+    ANDROID_SHARED_SESSION,
+    ANDROID_DESKTOP_EFFECTS,
     ANDROID_SECTION_COUNT,
 
     VENDOR_SECTION = 0x8000
@@ -117,6 +119,8 @@ typedef enum camera_metadata_section_start {
     ANDROID_AUTOMOTIVE_LENS_START  = ANDROID_AUTOMOTIVE_LENS   << 16,
     ANDROID_EXTENSION_START        = ANDROID_EXTENSION         << 16,
     ANDROID_JPEGR_START            = ANDROID_JPEGR             << 16,
+    ANDROID_SHARED_SESSION_START   = ANDROID_SHARED_SESSION    << 16,
+    ANDROID_DESKTOP_EFFECTS_START  = ANDROID_DESKTOP_EFFECTS   << 16,
     VENDOR_SECTION_START           = VENDOR_SECTION            << 16
 } camera_metadata_section_start_t;
 
@@ -134,6 +138,10 @@ typedef enum camera_metadata_tag {
     ANDROID_COLOR_CORRECTION_ABERRATION_MODE,         // enum         | public       | HIDL v3.2
     ANDROID_COLOR_CORRECTION_AVAILABLE_ABERRATION_MODES,
                                                       // byte[]       | public       | HIDL v3.2
+    ANDROID_COLOR_CORRECTION_COLOR_TEMPERATURE,       // int32        | public       | HIDL v3.11
+    ANDROID_COLOR_CORRECTION_COLOR_TINT,              // int32        | public       | HIDL v3.11
+    ANDROID_COLOR_CORRECTION_COLOR_TEMPERATURE_RANGE, // int32[]      | public       | HIDL v3.11
+    ANDROID_COLOR_CORRECTION_AVAILABLE_MODES,         // byte[]       | public       | HIDL v3.11
     ANDROID_COLOR_CORRECTION_END,
 
     ANDROID_CONTROL_AE_ANTIBANDING_MODE =             // enum         | public       | HIDL v3.2
@@ -203,6 +211,9 @@ typedef enum camera_metadata_tag {
     ANDROID_CONTROL_LOW_LIGHT_BOOST_INFO_LUMINANCE_RANGE,
                                                       // float[]      | public       | HIDL v3.10
     ANDROID_CONTROL_LOW_LIGHT_BOOST_STATE,            // enum         | public       | HIDL v3.10
+    ANDROID_CONTROL_ZOOM_METHOD,                      // enum         | fwk_public
+    ANDROID_CONTROL_AE_PRIORITY_MODE,                 // enum         | public       | HIDL v3.11
+    ANDROID_CONTROL_AE_AVAILABLE_PRIORITY_MODES,      // byte[]       | public       | HIDL v3.11
     ANDROID_CONTROL_END,
 
     ANDROID_DEMOSAIC_MODE =                           // enum         | system       | HIDL v3.2
@@ -567,6 +578,18 @@ typedef enum camera_metadata_tag {
                                                       // int64[]      | ndk_public   | HIDL v3.6
     ANDROID_HEIC_AVAILABLE_HEIC_STALL_DURATIONS_MAXIMUM_RESOLUTION,
                                                       // int64[]      | ndk_public   | HIDL v3.6
+    ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STREAM_CONFIGURATIONS,
+                                                      // enum[]       | ndk_public   | HIDL v3.11
+    ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_MIN_FRAME_DURATIONS,
+                                                      // int64[]      | ndk_public   | HIDL v3.11
+    ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STALL_DURATIONS,
+                                                      // int64[]      | ndk_public   | HIDL v3.11
+    ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STREAM_CONFIGURATIONS_MAXIMUM_RESOLUTION,
+                                                      // enum[]       | ndk_public   | HIDL v3.11
+    ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_MIN_FRAME_DURATIONS_MAXIMUM_RESOLUTION,
+                                                      // int64[]      | ndk_public   | HIDL v3.11
+    ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STALL_DURATIONS_MAXIMUM_RESOLUTION,
+                                                      // int64[]      | ndk_public   | HIDL v3.11
     ANDROID_HEIC_END,
 
     ANDROID_HEIC_INFO_SUPPORTED =                     // enum         | system       | HIDL v3.4
@@ -585,6 +608,7 @@ typedef enum camera_metadata_tag {
     ANDROID_EXTENSION_STRENGTH =                      // int32        | fwk_java_public
             ANDROID_EXTENSION_START,
     ANDROID_EXTENSION_CURRENT_TYPE,                   // int32        | fwk_java_public
+    ANDROID_EXTENSION_NIGHT_MODE_INDICATOR,           // enum         | public       | HIDL v3.11
     ANDROID_EXTENSION_END,
 
     ANDROID_JPEGR_AVAILABLE_JPEG_R_STREAM_CONFIGURATIONS = 
@@ -601,6 +625,20 @@ typedef enum camera_metadata_tag {
                                                       // int64[]      | ndk_public   | HIDL v3.9
     ANDROID_JPEGR_END,
 
+    ANDROID_SHARED_SESSION_COLOR_SPACE =              // enum         | fwk_only
+            ANDROID_SHARED_SESSION_START,
+    ANDROID_SHARED_SESSION_OUTPUT_CONFIGURATIONS,     // int64[]      | fwk_only
+    ANDROID_SHARED_SESSION_END,
+
+    ANDROID_DESKTOP_EFFECTS_CAPABILITIES =            // enum[]       | system       | HIDL v3.2
+            ANDROID_DESKTOP_EFFECTS_START,
+    ANDROID_DESKTOP_EFFECTS_BACKGROUND_BLUR_MODES,    // byte[]       | system       | HIDL v3.2
+    ANDROID_DESKTOP_EFFECTS_BACKGROUND_BLUR_MODE,     // enum         | system       | HIDL v3.2
+    ANDROID_DESKTOP_EFFECTS_FACE_RETOUCH_MODE,        // enum         | system       | HIDL v3.2
+    ANDROID_DESKTOP_EFFECTS_FACE_RETOUCH_STRENGTH,    // byte         | system       | HIDL v3.2
+    ANDROID_DESKTOP_EFFECTS_PORTRAIT_RELIGHT_MODE,    // enum         | system       | HIDL v3.2
+    ANDROID_DESKTOP_EFFECTS_END,
+
 } camera_metadata_tag_t;
 
 /**
@@ -612,6 +650,7 @@ typedef enum camera_metadata_enum_android_color_correction_mode {
     ANDROID_COLOR_CORRECTION_MODE_TRANSFORM_MATRIX                  , // HIDL v3.2
     ANDROID_COLOR_CORRECTION_MODE_FAST                              , // HIDL v3.2
     ANDROID_COLOR_CORRECTION_MODE_HIGH_QUALITY                      , // HIDL v3.2
+    ANDROID_COLOR_CORRECTION_MODE_CCT                               , // HIDL v3.11
 } camera_metadata_enum_android_color_correction_mode_t;
 
 // ANDROID_COLOR_CORRECTION_ABERRATION_MODE
@@ -869,6 +908,19 @@ typedef enum camera_metadata_enum_android_control_low_light_boost_state {
     ANDROID_CONTROL_LOW_LIGHT_BOOST_STATE_ACTIVE                    , // HIDL v3.10
 } camera_metadata_enum_android_control_low_light_boost_state_t;
 
+// ANDROID_CONTROL_ZOOM_METHOD
+typedef enum camera_metadata_enum_android_control_zoom_method {
+    ANDROID_CONTROL_ZOOM_METHOD_AUTO                                 = 0,
+    ANDROID_CONTROL_ZOOM_METHOD_ZOOM_RATIO                           = 1,
+} camera_metadata_enum_android_control_zoom_method_t;
+
+// ANDROID_CONTROL_AE_PRIORITY_MODE
+typedef enum camera_metadata_enum_android_control_ae_priority_mode {
+    ANDROID_CONTROL_AE_PRIORITY_MODE_OFF                            , // HIDL v3.11
+    ANDROID_CONTROL_AE_PRIORITY_MODE_SENSOR_SENSITIVITY_PRIORITY    , // HIDL v3.11
+    ANDROID_CONTROL_AE_PRIORITY_MODE_SENSOR_EXPOSURE_TIME_PRIORITY  , // HIDL v3.11
+} camera_metadata_enum_android_control_ae_priority_mode_t;
+
 
 // ANDROID_DEMOSAIC_MODE
 typedef enum camera_metadata_enum_android_demosaic_mode {
@@ -1326,6 +1378,7 @@ typedef enum camera_metadata_enum_android_info_session_configuration_query_versi
                                                                       = 34,
     ANDROID_INFO_SESSION_CONFIGURATION_QUERY_VERSION_VANILLA_ICE_CREAM
                                                                       = 35,
+    ANDROID_INFO_SESSION_CONFIGURATION_QUERY_VERSION_BAKLAVA         = 36,
 } camera_metadata_enum_android_info_session_configuration_query_version_t;
 
 
@@ -1416,6 +1469,22 @@ typedef enum camera_metadata_enum_android_heic_available_heic_stream_configurati
                                                                      , // HIDL v3.6
 } camera_metadata_enum_android_heic_available_heic_stream_configurations_maximum_resolution_t;
 
+// ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STREAM_CONFIGURATIONS
+typedef enum camera_metadata_enum_android_heic_available_heic_ultra_hdr_stream_configurations {
+    ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STREAM_CONFIGURATIONS_OUTPUT
+                                                                     , // HIDL v3.11
+    ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STREAM_CONFIGURATIONS_INPUT
+                                                                     , // HIDL v3.11
+} camera_metadata_enum_android_heic_available_heic_ultra_hdr_stream_configurations_t;
+
+// ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STREAM_CONFIGURATIONS_MAXIMUM_RESOLUTION
+typedef enum camera_metadata_enum_android_heic_available_heic_ultra_hdr_stream_configurations_maximum_resolution {
+    ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STREAM_CONFIGURATIONS_MAXIMUM_RESOLUTION_OUTPUT
+                                                                     , // HIDL v3.11
+    ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STREAM_CONFIGURATIONS_MAXIMUM_RESOLUTION_INPUT
+                                                                     , // HIDL v3.11
+} camera_metadata_enum_android_heic_available_heic_ultra_hdr_stream_configurations_maximum_resolution_t;
+
 
 // ANDROID_HEIC_INFO_SUPPORTED
 typedef enum camera_metadata_enum_android_heic_info_supported {
@@ -1460,6 +1529,13 @@ typedef enum camera_metadata_enum_android_automotive_lens_facing {
 } camera_metadata_enum_android_automotive_lens_facing_t;
 
 
+// ANDROID_EXTENSION_NIGHT_MODE_INDICATOR
+typedef enum camera_metadata_enum_android_extension_night_mode_indicator {
+    ANDROID_EXTENSION_NIGHT_MODE_INDICATOR_UNKNOWN                  , // HIDL v3.11
+    ANDROID_EXTENSION_NIGHT_MODE_INDICATOR_OFF                      , // HIDL v3.11
+    ANDROID_EXTENSION_NIGHT_MODE_INDICATOR_ON                       , // HIDL v3.11
+} camera_metadata_enum_android_extension_night_mode_indicator_t;
+
 
 // ANDROID_JPEGR_AVAILABLE_JPEG_R_STREAM_CONFIGURATIONS
 typedef enum camera_metadata_enum_android_jpegr_available_jpeg_r_stream_configurations {
@@ -1476,3 +1552,39 @@ typedef enum camera_metadata_enum_android_jpegr_available_jpeg_r_stream_configur
 } camera_metadata_enum_android_jpegr_available_jpeg_r_stream_configurations_maximum_resolution_t;
 
 
+// ANDROID_SHARED_SESSION_COLOR_SPACE
+typedef enum camera_metadata_enum_android_shared_session_color_space {
+    ANDROID_SHARED_SESSION_COLOR_SPACE_UNSPECIFIED                   = -1,
+    ANDROID_SHARED_SESSION_COLOR_SPACE_SRGB                          = 0,
+    ANDROID_SHARED_SESSION_COLOR_SPACE_DISPLAY_P3                    = 7,
+    ANDROID_SHARED_SESSION_COLOR_SPACE_BT2020_HLG                    = 16,
+} camera_metadata_enum_android_shared_session_color_space_t;
+
+
+// ANDROID_DESKTOP_EFFECTS_CAPABILITIES
+typedef enum camera_metadata_enum_android_desktop_effects_capabilities {
+    ANDROID_DESKTOP_EFFECTS_CAPABILITIES_BACKGROUND_BLUR            , // HIDL v3.2
+    ANDROID_DESKTOP_EFFECTS_CAPABILITIES_FACE_RETOUCH               , // HIDL v3.2
+    ANDROID_DESKTOP_EFFECTS_CAPABILITIES_PORTRAIT_RELIGHT           , // HIDL v3.2
+} camera_metadata_enum_android_desktop_effects_capabilities_t;
+
+// ANDROID_DESKTOP_EFFECTS_BACKGROUND_BLUR_MODE
+typedef enum camera_metadata_enum_android_desktop_effects_background_blur_mode {
+    ANDROID_DESKTOP_EFFECTS_BACKGROUND_BLUR_MODE_OFF                , // HIDL v3.2
+    ANDROID_DESKTOP_EFFECTS_BACKGROUND_BLUR_MODE_LIGHT              , // HIDL v3.2
+    ANDROID_DESKTOP_EFFECTS_BACKGROUND_BLUR_MODE_FULL               , // HIDL v3.2
+} camera_metadata_enum_android_desktop_effects_background_blur_mode_t;
+
+// ANDROID_DESKTOP_EFFECTS_FACE_RETOUCH_MODE
+typedef enum camera_metadata_enum_android_desktop_effects_face_retouch_mode {
+    ANDROID_DESKTOP_EFFECTS_FACE_RETOUCH_MODE_OFF                   , // HIDL v3.2
+    ANDROID_DESKTOP_EFFECTS_FACE_RETOUCH_MODE_ON                    , // HIDL v3.2
+} camera_metadata_enum_android_desktop_effects_face_retouch_mode_t;
+
+// ANDROID_DESKTOP_EFFECTS_PORTRAIT_RELIGHT_MODE
+typedef enum camera_metadata_enum_android_desktop_effects_portrait_relight_mode {
+    ANDROID_DESKTOP_EFFECTS_PORTRAIT_RELIGHT_MODE_OFF               , // HIDL v3.2
+    ANDROID_DESKTOP_EFFECTS_PORTRAIT_RELIGHT_MODE_ON                , // HIDL v3.2
+} camera_metadata_enum_android_desktop_effects_portrait_relight_mode_t;
+
+
diff --git a/camera/src/camera_metadata.c b/camera/src/camera_metadata.c
index bc587905..1f09d5b1 100644
--- a/camera/src/camera_metadata.c
+++ b/camera/src/camera_metadata.c
@@ -1211,6 +1211,11 @@ static void print_data(int fd, const uint8_t *data_ptr, uint32_t tag, int type,
                                                      sizeof(value_string_tmp))
                         == OK) {
                         dprintf(fd, "%s ", value_string_tmp);
+                    } else if (tag == ANDROID_LOGICAL_MULTI_CAMERA_PHYSICAL_IDS) {
+                        if (value != 0) {
+                            dprintf(fd, "%c ",
+                                    *(data_ptr + index));
+                        }
                     } else {
                         dprintf(fd, "%hhu ",
                                 *(data_ptr + index));
diff --git a/camera/src/camera_metadata_asserts.cpp b/camera/src/camera_metadata_asserts.cpp
index 9d96fa6d..d721a1c1 100644
--- a/camera/src/camera_metadata_asserts.cpp
+++ b/camera/src/camera_metadata_asserts.cpp
@@ -51,6 +51,7 @@
 #include <aidl/android/hardware/camera/metadata/ControlAutoframingAvailable.h>
 #include <aidl/android/hardware/camera/metadata/ControlAutoframingState.h>
 #include <aidl/android/hardware/camera/metadata/ControlLowLightBoostState.h>
+#include <aidl/android/hardware/camera/metadata/ControlAePriorityMode.h>
 #include <aidl/android/hardware/camera/metadata/DemosaicMode.h>
 #include <aidl/android/hardware/camera/metadata/EdgeMode.h>
 #include <aidl/android/hardware/camera/metadata/FlashMode.h>
@@ -112,11 +113,18 @@
 #include <aidl/android/hardware/camera/metadata/DistortionCorrectionMode.h>
 #include <aidl/android/hardware/camera/metadata/HeicAvailableHeicStreamConfigurations.h>
 #include <aidl/android/hardware/camera/metadata/HeicAvailableHeicStreamConfigurationsMaximumResolution.h>
+#include <aidl/android/hardware/camera/metadata/HeicAvailableHeicUltraHdrStreamConfigurations.h>
+#include <aidl/android/hardware/camera/metadata/HeicAvailableHeicUltraHdrStreamConfigurationsMaximumResolution.h>
 #include <aidl/android/hardware/camera/metadata/HeicInfoSupported.h>
 #include <aidl/android/hardware/camera/metadata/AutomotiveLocation.h>
 #include <aidl/android/hardware/camera/metadata/AutomotiveLensFacing.h>
+#include <aidl/android/hardware/camera/metadata/ExtensionNightModeIndicator.h>
 #include <aidl/android/hardware/camera/metadata/JpegrAvailableJpegRStreamConfigurations.h>
 #include <aidl/android/hardware/camera/metadata/JpegrAvailableJpegRStreamConfigurationsMaximumResolution.h>
+#include <aidl/android/hardware/camera/metadata/DesktopEffectsCapabilities.h>
+#include <aidl/android/hardware/camera/metadata/DesktopEffectsBackgroundBlurMode.h>
+#include <aidl/android/hardware/camera/metadata/DesktopEffectsFaceRetouchMode.h>
+#include <aidl/android/hardware/camera/metadata/DesktopEffectsPortraitRelightMode.h>
 
 #include <system/camera_metadata_tags.h>
 
@@ -188,6 +196,10 @@ static_assert(static_cast<int>(ANDROID_EXTENSION)
         == static_cast<int>(::aidl::android::hardware::camera::metadata::CameraMetadataSection::ANDROID_EXTENSION));
 static_assert(static_cast<int>(ANDROID_JPEGR)
         == static_cast<int>(::aidl::android::hardware::camera::metadata::CameraMetadataSection::ANDROID_JPEGR));
+static_assert(static_cast<int>(ANDROID_SHARED_SESSION)
+        == static_cast<int>(::aidl::android::hardware::camera::metadata::CameraMetadataSection::ANDROID_SHARED_SESSION));
+static_assert(static_cast<int>(ANDROID_DESKTOP_EFFECTS)
+        == static_cast<int>(::aidl::android::hardware::camera::metadata::CameraMetadataSection::ANDROID_DESKTOP_EFFECTS));
 static_assert(static_cast<int>(VENDOR_SECTION)
         == static_cast<int>(::aidl::android::hardware::camera::metadata::CameraMetadataSection::VENDOR_SECTION));
 
@@ -259,6 +271,10 @@ static_assert(static_cast<int>(ANDROID_EXTENSION_START)
         == static_cast<int>(::aidl::android::hardware::camera::metadata::CameraMetadataSectionStart::ANDROID_EXTENSION_START));
 static_assert(static_cast<int>(ANDROID_JPEGR_START)
         == static_cast<int>(::aidl::android::hardware::camera::metadata::CameraMetadataSectionStart::ANDROID_JPEGR_START));
+static_assert(static_cast<int>(ANDROID_SHARED_SESSION_START)
+        == static_cast<int>(::aidl::android::hardware::camera::metadata::CameraMetadataSectionStart::ANDROID_SHARED_SESSION_START));
+static_assert(static_cast<int>(ANDROID_DESKTOP_EFFECTS_START)
+        == static_cast<int>(::aidl::android::hardware::camera::metadata::CameraMetadataSectionStart::ANDROID_DESKTOP_EFFECTS_START));
 static_assert(static_cast<int>(VENDOR_SECTION_START)
         == static_cast<int>(::aidl::android::hardware::camera::metadata::CameraMetadataSectionStart::VENDOR_SECTION_START));
 
@@ -272,6 +288,14 @@ static_assert(static_cast<int>(ANDROID_COLOR_CORRECTION_ABERRATION_MODE)
         == static_cast<int>(::aidl::android::hardware::camera::metadata::CameraMetadataTag::ANDROID_COLOR_CORRECTION_ABERRATION_MODE));
 static_assert(static_cast<int>(ANDROID_COLOR_CORRECTION_AVAILABLE_ABERRATION_MODES)
         == static_cast<int>(::aidl::android::hardware::camera::metadata::CameraMetadataTag::ANDROID_COLOR_CORRECTION_AVAILABLE_ABERRATION_MODES));
+static_assert(static_cast<int>(ANDROID_COLOR_CORRECTION_COLOR_TEMPERATURE)
+        == static_cast<int>(::aidl::android::hardware::camera::metadata::CameraMetadataTag::ANDROID_COLOR_CORRECTION_COLOR_TEMPERATURE));
+static_assert(static_cast<int>(ANDROID_COLOR_CORRECTION_COLOR_TINT)
+        == static_cast<int>(::aidl::android::hardware::camera::metadata::CameraMetadataTag::ANDROID_COLOR_CORRECTION_COLOR_TINT));
+static_assert(static_cast<int>(ANDROID_COLOR_CORRECTION_COLOR_TEMPERATURE_RANGE)
+        == static_cast<int>(::aidl::android::hardware::camera::metadata::CameraMetadataTag::ANDROID_COLOR_CORRECTION_COLOR_TEMPERATURE_RANGE));
+static_assert(static_cast<int>(ANDROID_COLOR_CORRECTION_AVAILABLE_MODES)
+        == static_cast<int>(::aidl::android::hardware::camera::metadata::CameraMetadataTag::ANDROID_COLOR_CORRECTION_AVAILABLE_MODES));
 static_assert(static_cast<int>(ANDROID_CONTROL_AE_ANTIBANDING_MODE)
         == static_cast<int>(::aidl::android::hardware::camera::metadata::CameraMetadataTag::ANDROID_CONTROL_AE_ANTIBANDING_MODE));
 static_assert(static_cast<int>(ANDROID_CONTROL_AE_EXPOSURE_COMPENSATION)
@@ -386,6 +410,10 @@ static_assert(static_cast<int>(ANDROID_CONTROL_LOW_LIGHT_BOOST_INFO_LUMINANCE_RA
         == static_cast<int>(::aidl::android::hardware::camera::metadata::CameraMetadataTag::ANDROID_CONTROL_LOW_LIGHT_BOOST_INFO_LUMINANCE_RANGE));
 static_assert(static_cast<int>(ANDROID_CONTROL_LOW_LIGHT_BOOST_STATE)
         == static_cast<int>(::aidl::android::hardware::camera::metadata::CameraMetadataTag::ANDROID_CONTROL_LOW_LIGHT_BOOST_STATE));
+static_assert(static_cast<int>(ANDROID_CONTROL_AE_PRIORITY_MODE)
+        == static_cast<int>(::aidl::android::hardware::camera::metadata::CameraMetadataTag::ANDROID_CONTROL_AE_PRIORITY_MODE));
+static_assert(static_cast<int>(ANDROID_CONTROL_AE_AVAILABLE_PRIORITY_MODES)
+        == static_cast<int>(::aidl::android::hardware::camera::metadata::CameraMetadataTag::ANDROID_CONTROL_AE_AVAILABLE_PRIORITY_MODES));
 static_assert(static_cast<int>(ANDROID_DEMOSAIC_MODE)
         == static_cast<int>(::aidl::android::hardware::camera::metadata::CameraMetadataTag::ANDROID_DEMOSAIC_MODE));
 static_assert(static_cast<int>(ANDROID_EDGE_MODE)
@@ -872,6 +900,18 @@ static_assert(static_cast<int>(ANDROID_HEIC_AVAILABLE_HEIC_MIN_FRAME_DURATIONS_M
         == static_cast<int>(::aidl::android::hardware::camera::metadata::CameraMetadataTag::ANDROID_HEIC_AVAILABLE_HEIC_MIN_FRAME_DURATIONS_MAXIMUM_RESOLUTION));
 static_assert(static_cast<int>(ANDROID_HEIC_AVAILABLE_HEIC_STALL_DURATIONS_MAXIMUM_RESOLUTION)
         == static_cast<int>(::aidl::android::hardware::camera::metadata::CameraMetadataTag::ANDROID_HEIC_AVAILABLE_HEIC_STALL_DURATIONS_MAXIMUM_RESOLUTION));
+static_assert(static_cast<int>(ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STREAM_CONFIGURATIONS)
+        == static_cast<int>(::aidl::android::hardware::camera::metadata::CameraMetadataTag::ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STREAM_CONFIGURATIONS));
+static_assert(static_cast<int>(ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_MIN_FRAME_DURATIONS)
+        == static_cast<int>(::aidl::android::hardware::camera::metadata::CameraMetadataTag::ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_MIN_FRAME_DURATIONS));
+static_assert(static_cast<int>(ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STALL_DURATIONS)
+        == static_cast<int>(::aidl::android::hardware::camera::metadata::CameraMetadataTag::ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STALL_DURATIONS));
+static_assert(static_cast<int>(ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STREAM_CONFIGURATIONS_MAXIMUM_RESOLUTION)
+        == static_cast<int>(::aidl::android::hardware::camera::metadata::CameraMetadataTag::ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STREAM_CONFIGURATIONS_MAXIMUM_RESOLUTION));
+static_assert(static_cast<int>(ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_MIN_FRAME_DURATIONS_MAXIMUM_RESOLUTION)
+        == static_cast<int>(::aidl::android::hardware::camera::metadata::CameraMetadataTag::ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_MIN_FRAME_DURATIONS_MAXIMUM_RESOLUTION));
+static_assert(static_cast<int>(ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STALL_DURATIONS_MAXIMUM_RESOLUTION)
+        == static_cast<int>(::aidl::android::hardware::camera::metadata::CameraMetadataTag::ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STALL_DURATIONS_MAXIMUM_RESOLUTION));
 static_assert(static_cast<int>(ANDROID_HEIC_INFO_SUPPORTED)
         == static_cast<int>(::aidl::android::hardware::camera::metadata::CameraMetadataTag::ANDROID_HEIC_INFO_SUPPORTED));
 static_assert(static_cast<int>(ANDROID_HEIC_INFO_MAX_JPEG_APP_SEGMENTS_COUNT)
@@ -880,6 +920,8 @@ static_assert(static_cast<int>(ANDROID_AUTOMOTIVE_LOCATION)
         == static_cast<int>(::aidl::android::hardware::camera::metadata::CameraMetadataTag::ANDROID_AUTOMOTIVE_LOCATION));
 static_assert(static_cast<int>(ANDROID_AUTOMOTIVE_LENS_FACING)
         == static_cast<int>(::aidl::android::hardware::camera::metadata::CameraMetadataTag::ANDROID_AUTOMOTIVE_LENS_FACING));
+static_assert(static_cast<int>(ANDROID_EXTENSION_NIGHT_MODE_INDICATOR)
+        == static_cast<int>(::aidl::android::hardware::camera::metadata::CameraMetadataTag::ANDROID_EXTENSION_NIGHT_MODE_INDICATOR));
 static_assert(static_cast<int>(ANDROID_JPEGR_AVAILABLE_JPEG_R_STREAM_CONFIGURATIONS)
         == static_cast<int>(::aidl::android::hardware::camera::metadata::CameraMetadataTag::ANDROID_JPEGR_AVAILABLE_JPEG_R_STREAM_CONFIGURATIONS));
 static_assert(static_cast<int>(ANDROID_JPEGR_AVAILABLE_JPEG_R_MIN_FRAME_DURATIONS)
@@ -892,6 +934,18 @@ static_assert(static_cast<int>(ANDROID_JPEGR_AVAILABLE_JPEG_R_MIN_FRAME_DURATION
         == static_cast<int>(::aidl::android::hardware::camera::metadata::CameraMetadataTag::ANDROID_JPEGR_AVAILABLE_JPEG_R_MIN_FRAME_DURATIONS_MAXIMUM_RESOLUTION));
 static_assert(static_cast<int>(ANDROID_JPEGR_AVAILABLE_JPEG_R_STALL_DURATIONS_MAXIMUM_RESOLUTION)
         == static_cast<int>(::aidl::android::hardware::camera::metadata::CameraMetadataTag::ANDROID_JPEGR_AVAILABLE_JPEG_R_STALL_DURATIONS_MAXIMUM_RESOLUTION));
+static_assert(static_cast<int>(ANDROID_DESKTOP_EFFECTS_CAPABILITIES)
+        == static_cast<int>(::aidl::android::hardware::camera::metadata::CameraMetadataTag::ANDROID_DESKTOP_EFFECTS_CAPABILITIES));
+static_assert(static_cast<int>(ANDROID_DESKTOP_EFFECTS_BACKGROUND_BLUR_MODES)
+        == static_cast<int>(::aidl::android::hardware::camera::metadata::CameraMetadataTag::ANDROID_DESKTOP_EFFECTS_BACKGROUND_BLUR_MODES));
+static_assert(static_cast<int>(ANDROID_DESKTOP_EFFECTS_BACKGROUND_BLUR_MODE)
+        == static_cast<int>(::aidl::android::hardware::camera::metadata::CameraMetadataTag::ANDROID_DESKTOP_EFFECTS_BACKGROUND_BLUR_MODE));
+static_assert(static_cast<int>(ANDROID_DESKTOP_EFFECTS_FACE_RETOUCH_MODE)
+        == static_cast<int>(::aidl::android::hardware::camera::metadata::CameraMetadataTag::ANDROID_DESKTOP_EFFECTS_FACE_RETOUCH_MODE));
+static_assert(static_cast<int>(ANDROID_DESKTOP_EFFECTS_FACE_RETOUCH_STRENGTH)
+        == static_cast<int>(::aidl::android::hardware::camera::metadata::CameraMetadataTag::ANDROID_DESKTOP_EFFECTS_FACE_RETOUCH_STRENGTH));
+static_assert(static_cast<int>(ANDROID_DESKTOP_EFFECTS_PORTRAIT_RELIGHT_MODE)
+        == static_cast<int>(::aidl::android::hardware::camera::metadata::CameraMetadataTag::ANDROID_DESKTOP_EFFECTS_PORTRAIT_RELIGHT_MODE));
 
 static_assert(static_cast<int32_t>(ANDROID_COLOR_CORRECTION_MODE_TRANSFORM_MATRIX)
         == static_cast<int32_t>(::aidl::android::hardware::camera::metadata::ColorCorrectionMode::ANDROID_COLOR_CORRECTION_MODE_TRANSFORM_MATRIX));
@@ -899,6 +953,8 @@ static_assert(static_cast<int32_t>(ANDROID_COLOR_CORRECTION_MODE_FAST)
         == static_cast<int32_t>(::aidl::android::hardware::camera::metadata::ColorCorrectionMode::ANDROID_COLOR_CORRECTION_MODE_FAST));
 static_assert(static_cast<int32_t>(ANDROID_COLOR_CORRECTION_MODE_HIGH_QUALITY)
         == static_cast<int32_t>(::aidl::android::hardware::camera::metadata::ColorCorrectionMode::ANDROID_COLOR_CORRECTION_MODE_HIGH_QUALITY));
+static_assert(static_cast<int32_t>(ANDROID_COLOR_CORRECTION_MODE_CCT)
+        == static_cast<int32_t>(::aidl::android::hardware::camera::metadata::ColorCorrectionMode::ANDROID_COLOR_CORRECTION_MODE_CCT));
 
 static_assert(static_cast<int32_t>(ANDROID_COLOR_CORRECTION_ABERRATION_MODE_OFF)
         == static_cast<int32_t>(::aidl::android::hardware::camera::metadata::ColorCorrectionAberrationMode::ANDROID_COLOR_CORRECTION_ABERRATION_MODE_OFF));
@@ -1183,6 +1239,13 @@ static_assert(static_cast<int32_t>(ANDROID_CONTROL_LOW_LIGHT_BOOST_STATE_INACTIV
 static_assert(static_cast<int32_t>(ANDROID_CONTROL_LOW_LIGHT_BOOST_STATE_ACTIVE)
         == static_cast<int32_t>(::aidl::android::hardware::camera::metadata::ControlLowLightBoostState::ANDROID_CONTROL_LOW_LIGHT_BOOST_STATE_ACTIVE));
 
+static_assert(static_cast<int32_t>(ANDROID_CONTROL_AE_PRIORITY_MODE_OFF)
+        == static_cast<int32_t>(::aidl::android::hardware::camera::metadata::ControlAePriorityMode::ANDROID_CONTROL_AE_PRIORITY_MODE_OFF));
+static_assert(static_cast<int32_t>(ANDROID_CONTROL_AE_PRIORITY_MODE_SENSOR_SENSITIVITY_PRIORITY)
+        == static_cast<int32_t>(::aidl::android::hardware::camera::metadata::ControlAePriorityMode::ANDROID_CONTROL_AE_PRIORITY_MODE_SENSOR_SENSITIVITY_PRIORITY));
+static_assert(static_cast<int32_t>(ANDROID_CONTROL_AE_PRIORITY_MODE_SENSOR_EXPOSURE_TIME_PRIORITY)
+        == static_cast<int32_t>(::aidl::android::hardware::camera::metadata::ControlAePriorityMode::ANDROID_CONTROL_AE_PRIORITY_MODE_SENSOR_EXPOSURE_TIME_PRIORITY));
+
 static_assert(static_cast<int32_t>(ANDROID_DEMOSAIC_MODE_FAST)
         == static_cast<int32_t>(::aidl::android::hardware::camera::metadata::DemosaicMode::ANDROID_DEMOSAIC_MODE_FAST));
 static_assert(static_cast<int32_t>(ANDROID_DEMOSAIC_MODE_HIGH_QUALITY)
@@ -1700,6 +1763,16 @@ static_assert(static_cast<int32_t>(ANDROID_HEIC_AVAILABLE_HEIC_STREAM_CONFIGURAT
 static_assert(static_cast<int32_t>(ANDROID_HEIC_AVAILABLE_HEIC_STREAM_CONFIGURATIONS_MAXIMUM_RESOLUTION_INPUT)
         == static_cast<int32_t>(::aidl::android::hardware::camera::metadata::HeicAvailableHeicStreamConfigurationsMaximumResolution::ANDROID_HEIC_AVAILABLE_HEIC_STREAM_CONFIGURATIONS_MAXIMUM_RESOLUTION_INPUT));
 
+static_assert(static_cast<int32_t>(ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STREAM_CONFIGURATIONS_OUTPUT)
+        == static_cast<int32_t>(::aidl::android::hardware::camera::metadata::HeicAvailableHeicUltraHdrStreamConfigurations::ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STREAM_CONFIGURATIONS_OUTPUT));
+static_assert(static_cast<int32_t>(ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STREAM_CONFIGURATIONS_INPUT)
+        == static_cast<int32_t>(::aidl::android::hardware::camera::metadata::HeicAvailableHeicUltraHdrStreamConfigurations::ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STREAM_CONFIGURATIONS_INPUT));
+
+static_assert(static_cast<int32_t>(ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STREAM_CONFIGURATIONS_MAXIMUM_RESOLUTION_OUTPUT)
+        == static_cast<int32_t>(::aidl::android::hardware::camera::metadata::HeicAvailableHeicUltraHdrStreamConfigurationsMaximumResolution::ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STREAM_CONFIGURATIONS_MAXIMUM_RESOLUTION_OUTPUT));
+static_assert(static_cast<int32_t>(ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STREAM_CONFIGURATIONS_MAXIMUM_RESOLUTION_INPUT)
+        == static_cast<int32_t>(::aidl::android::hardware::camera::metadata::HeicAvailableHeicUltraHdrStreamConfigurationsMaximumResolution::ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STREAM_CONFIGURATIONS_MAXIMUM_RESOLUTION_INPUT));
+
 static_assert(static_cast<int32_t>(ANDROID_HEIC_INFO_SUPPORTED_FALSE)
         == static_cast<int32_t>(::aidl::android::hardware::camera::metadata::HeicInfoSupported::ANDROID_HEIC_INFO_SUPPORTED_FALSE));
 static_assert(static_cast<int32_t>(ANDROID_HEIC_INFO_SUPPORTED_TRUE)
@@ -1759,6 +1832,13 @@ static_assert(static_cast<int32_t>(ANDROID_AUTOMOTIVE_LENS_FACING_INTERIOR_SEAT_
 static_assert(static_cast<int32_t>(ANDROID_AUTOMOTIVE_LENS_FACING_INTERIOR_SEAT_ROW_3_RIGHT)
         == static_cast<int32_t>(::aidl::android::hardware::camera::metadata::AutomotiveLensFacing::ANDROID_AUTOMOTIVE_LENS_FACING_INTERIOR_SEAT_ROW_3_RIGHT));
 
+static_assert(static_cast<int32_t>(ANDROID_EXTENSION_NIGHT_MODE_INDICATOR_UNKNOWN)
+        == static_cast<int32_t>(::aidl::android::hardware::camera::metadata::ExtensionNightModeIndicator::ANDROID_EXTENSION_NIGHT_MODE_INDICATOR_UNKNOWN));
+static_assert(static_cast<int32_t>(ANDROID_EXTENSION_NIGHT_MODE_INDICATOR_OFF)
+        == static_cast<int32_t>(::aidl::android::hardware::camera::metadata::ExtensionNightModeIndicator::ANDROID_EXTENSION_NIGHT_MODE_INDICATOR_OFF));
+static_assert(static_cast<int32_t>(ANDROID_EXTENSION_NIGHT_MODE_INDICATOR_ON)
+        == static_cast<int32_t>(::aidl::android::hardware::camera::metadata::ExtensionNightModeIndicator::ANDROID_EXTENSION_NIGHT_MODE_INDICATOR_ON));
+
 static_assert(static_cast<int32_t>(ANDROID_JPEGR_AVAILABLE_JPEG_R_STREAM_CONFIGURATIONS_OUTPUT)
         == static_cast<int32_t>(::aidl::android::hardware::camera::metadata::JpegrAvailableJpegRStreamConfigurations::ANDROID_JPEGR_AVAILABLE_JPEG_R_STREAM_CONFIGURATIONS_OUTPUT));
 static_assert(static_cast<int32_t>(ANDROID_JPEGR_AVAILABLE_JPEG_R_STREAM_CONFIGURATIONS_INPUT)
@@ -1768,3 +1848,27 @@ static_assert(static_cast<int32_t>(ANDROID_JPEGR_AVAILABLE_JPEG_R_STREAM_CONFIGU
         == static_cast<int32_t>(::aidl::android::hardware::camera::metadata::JpegrAvailableJpegRStreamConfigurationsMaximumResolution::ANDROID_JPEGR_AVAILABLE_JPEG_R_STREAM_CONFIGURATIONS_MAXIMUM_RESOLUTION_OUTPUT));
 static_assert(static_cast<int32_t>(ANDROID_JPEGR_AVAILABLE_JPEG_R_STREAM_CONFIGURATIONS_MAXIMUM_RESOLUTION_INPUT)
         == static_cast<int32_t>(::aidl::android::hardware::camera::metadata::JpegrAvailableJpegRStreamConfigurationsMaximumResolution::ANDROID_JPEGR_AVAILABLE_JPEG_R_STREAM_CONFIGURATIONS_MAXIMUM_RESOLUTION_INPUT));
+
+static_assert(static_cast<int32_t>(ANDROID_DESKTOP_EFFECTS_CAPABILITIES_BACKGROUND_BLUR)
+        == static_cast<int32_t>(::aidl::android::hardware::camera::metadata::DesktopEffectsCapabilities::ANDROID_DESKTOP_EFFECTS_CAPABILITIES_BACKGROUND_BLUR));
+static_assert(static_cast<int32_t>(ANDROID_DESKTOP_EFFECTS_CAPABILITIES_FACE_RETOUCH)
+        == static_cast<int32_t>(::aidl::android::hardware::camera::metadata::DesktopEffectsCapabilities::ANDROID_DESKTOP_EFFECTS_CAPABILITIES_FACE_RETOUCH));
+static_assert(static_cast<int32_t>(ANDROID_DESKTOP_EFFECTS_CAPABILITIES_PORTRAIT_RELIGHT)
+        == static_cast<int32_t>(::aidl::android::hardware::camera::metadata::DesktopEffectsCapabilities::ANDROID_DESKTOP_EFFECTS_CAPABILITIES_PORTRAIT_RELIGHT));
+
+static_assert(static_cast<int32_t>(ANDROID_DESKTOP_EFFECTS_BACKGROUND_BLUR_MODE_OFF)
+        == static_cast<int32_t>(::aidl::android::hardware::camera::metadata::DesktopEffectsBackgroundBlurMode::ANDROID_DESKTOP_EFFECTS_BACKGROUND_BLUR_MODE_OFF));
+static_assert(static_cast<int32_t>(ANDROID_DESKTOP_EFFECTS_BACKGROUND_BLUR_MODE_LIGHT)
+        == static_cast<int32_t>(::aidl::android::hardware::camera::metadata::DesktopEffectsBackgroundBlurMode::ANDROID_DESKTOP_EFFECTS_BACKGROUND_BLUR_MODE_LIGHT));
+static_assert(static_cast<int32_t>(ANDROID_DESKTOP_EFFECTS_BACKGROUND_BLUR_MODE_FULL)
+        == static_cast<int32_t>(::aidl::android::hardware::camera::metadata::DesktopEffectsBackgroundBlurMode::ANDROID_DESKTOP_EFFECTS_BACKGROUND_BLUR_MODE_FULL));
+
+static_assert(static_cast<int32_t>(ANDROID_DESKTOP_EFFECTS_FACE_RETOUCH_MODE_OFF)
+        == static_cast<int32_t>(::aidl::android::hardware::camera::metadata::DesktopEffectsFaceRetouchMode::ANDROID_DESKTOP_EFFECTS_FACE_RETOUCH_MODE_OFF));
+static_assert(static_cast<int32_t>(ANDROID_DESKTOP_EFFECTS_FACE_RETOUCH_MODE_ON)
+        == static_cast<int32_t>(::aidl::android::hardware::camera::metadata::DesktopEffectsFaceRetouchMode::ANDROID_DESKTOP_EFFECTS_FACE_RETOUCH_MODE_ON));
+
+static_assert(static_cast<int32_t>(ANDROID_DESKTOP_EFFECTS_PORTRAIT_RELIGHT_MODE_OFF)
+        == static_cast<int32_t>(::aidl::android::hardware::camera::metadata::DesktopEffectsPortraitRelightMode::ANDROID_DESKTOP_EFFECTS_PORTRAIT_RELIGHT_MODE_OFF));
+static_assert(static_cast<int32_t>(ANDROID_DESKTOP_EFFECTS_PORTRAIT_RELIGHT_MODE_ON)
+        == static_cast<int32_t>(::aidl::android::hardware::camera::metadata::DesktopEffectsPortraitRelightMode::ANDROID_DESKTOP_EFFECTS_PORTRAIT_RELIGHT_MODE_ON));
diff --git a/camera/src/camera_metadata_tag_info.c b/camera/src/camera_metadata_tag_info.c
index e4b7df8f..59494d29 100644
--- a/camera/src/camera_metadata_tag_info.c
+++ b/camera/src/camera_metadata_tag_info.c
@@ -66,6 +66,8 @@ const char *camera_metadata_section_names[ANDROID_SECTION_COUNT] = {
     [ANDROID_AUTOMOTIVE_LENS]      = "android.automotive.lens",
     [ANDROID_EXTENSION]            = "android.extension",
     [ANDROID_JPEGR]                = "android.jpegr",
+    [ANDROID_SHARED_SESSION]       = "android.sharedSession",
+    [ANDROID_DESKTOP_EFFECTS]      = "android.desktopEffects",
 };
 
 unsigned int camera_metadata_section_bounds[ANDROID_SECTION_COUNT][2] = {
@@ -138,6 +140,10 @@ unsigned int camera_metadata_section_bounds[ANDROID_SECTION_COUNT][2] = {
                                        ANDROID_EXTENSION_END },
     [ANDROID_JPEGR]                = { ANDROID_JPEGR_START,
                                        ANDROID_JPEGR_END },
+    [ANDROID_SHARED_SESSION]       = { ANDROID_SHARED_SESSION_START,
+                                       ANDROID_SHARED_SESSION_END },
+    [ANDROID_DESKTOP_EFFECTS]      = { ANDROID_DESKTOP_EFFECTS_START,
+                                       ANDROID_DESKTOP_EFFECTS_END },
 };
 
 static tag_info_t android_color_correction[ANDROID_COLOR_CORRECTION_END -
@@ -153,6 +159,14 @@ static tag_info_t android_color_correction[ANDROID_COLOR_CORRECTION_END -
     { "aberrationMode",                TYPE_BYTE   },
     [ ANDROID_COLOR_CORRECTION_AVAILABLE_ABERRATION_MODES - ANDROID_COLOR_CORRECTION_START ] =
     { "availableAberrationModes",      TYPE_BYTE   },
+    [ ANDROID_COLOR_CORRECTION_COLOR_TEMPERATURE - ANDROID_COLOR_CORRECTION_START ] =
+    { "colorTemperature",              TYPE_INT32  },
+    [ ANDROID_COLOR_CORRECTION_COLOR_TINT - ANDROID_COLOR_CORRECTION_START ] =
+    { "colorTint",                     TYPE_INT32  },
+    [ ANDROID_COLOR_CORRECTION_COLOR_TEMPERATURE_RANGE - ANDROID_COLOR_CORRECTION_START ] =
+    { "colorTemperatureRange",         TYPE_INT32  },
+    [ ANDROID_COLOR_CORRECTION_AVAILABLE_MODES - ANDROID_COLOR_CORRECTION_START ] =
+    { "availableModes",                TYPE_BYTE   },
 };
 
 static tag_info_t android_control[ANDROID_CONTROL_END -
@@ -284,6 +298,12 @@ static tag_info_t android_control[ANDROID_CONTROL_END -
                                         TYPE_FLOAT  },
     [ ANDROID_CONTROL_LOW_LIGHT_BOOST_STATE - ANDROID_CONTROL_START ] =
     { "lowLightBoostState",            TYPE_BYTE   },
+    [ ANDROID_CONTROL_ZOOM_METHOD - ANDROID_CONTROL_START ] =
+    { "zoomMethod",                    TYPE_BYTE   },
+    [ ANDROID_CONTROL_AE_PRIORITY_MODE - ANDROID_CONTROL_START ] =
+    { "aePriorityMode",                TYPE_BYTE   },
+    [ ANDROID_CONTROL_AE_AVAILABLE_PRIORITY_MODES - ANDROID_CONTROL_START ] =
+    { "aeAvailablePriorityModes",      TYPE_BYTE   },
 };
 
 static tag_info_t android_demosaic[ANDROID_DEMOSAIC_END -
@@ -933,6 +953,24 @@ static tag_info_t android_heic[ANDROID_HEIC_END -
     [ ANDROID_HEIC_AVAILABLE_HEIC_STALL_DURATIONS_MAXIMUM_RESOLUTION - ANDROID_HEIC_START ] =
     { "availableHeicStallDurationsMaximumResolution",
                                         TYPE_INT64  },
+    [ ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STREAM_CONFIGURATIONS - ANDROID_HEIC_START ] =
+    { "availableHeicUltraHdrStreamConfigurations",
+                                        TYPE_INT32  },
+    [ ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_MIN_FRAME_DURATIONS - ANDROID_HEIC_START ] =
+    { "availableHeicUltraHdrMinFrameDurations",
+                                        TYPE_INT64  },
+    [ ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STALL_DURATIONS - ANDROID_HEIC_START ] =
+    { "availableHeicUltraHdrStallDurations",
+                                        TYPE_INT64  },
+    [ ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STREAM_CONFIGURATIONS_MAXIMUM_RESOLUTION - ANDROID_HEIC_START ] =
+    { "availableHeicUltraHdrStreamConfigurationsMaximumResolution",
+                                        TYPE_INT32  },
+    [ ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_MIN_FRAME_DURATIONS_MAXIMUM_RESOLUTION - ANDROID_HEIC_START ] =
+    { "availableHeicUltraHdrMinFrameDurationsMaximumResolution",
+                                        TYPE_INT64  },
+    [ ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STALL_DURATIONS_MAXIMUM_RESOLUTION - ANDROID_HEIC_START ] =
+    { "availableHeicUltraHdrStallDurationsMaximumResolution",
+                                        TYPE_INT64  },
 };
 
 static tag_info_t android_heic_info[ANDROID_HEIC_INFO_END -
@@ -961,6 +999,8 @@ static tag_info_t android_extension[ANDROID_EXTENSION_END -
     { "strength",                      TYPE_INT32  },
     [ ANDROID_EXTENSION_CURRENT_TYPE - ANDROID_EXTENSION_START ] =
     { "currentType",                   TYPE_INT32  },
+    [ ANDROID_EXTENSION_NIGHT_MODE_INDICATOR - ANDROID_EXTENSION_START ] =
+    { "nightModeIndicator",            TYPE_INT32  },
 };
 
 static tag_info_t android_jpegr[ANDROID_JPEGR_END -
@@ -984,6 +1024,30 @@ static tag_info_t android_jpegr[ANDROID_JPEGR_END -
                                         TYPE_INT64  },
 };
 
+static tag_info_t android_shared_session[ANDROID_SHARED_SESSION_END -
+        ANDROID_SHARED_SESSION_START] = {
+    [ ANDROID_SHARED_SESSION_COLOR_SPACE - ANDROID_SHARED_SESSION_START ] =
+    { "colorSpace",                    TYPE_BYTE   },
+    [ ANDROID_SHARED_SESSION_OUTPUT_CONFIGURATIONS - ANDROID_SHARED_SESSION_START ] =
+    { "outputConfigurations",          TYPE_INT64  },
+};
+
+static tag_info_t android_desktop_effects[ANDROID_DESKTOP_EFFECTS_END -
+        ANDROID_DESKTOP_EFFECTS_START] = {
+    [ ANDROID_DESKTOP_EFFECTS_CAPABILITIES - ANDROID_DESKTOP_EFFECTS_START ] =
+    { "capabilities",                  TYPE_BYTE   },
+    [ ANDROID_DESKTOP_EFFECTS_BACKGROUND_BLUR_MODES - ANDROID_DESKTOP_EFFECTS_START ] =
+    { "backgroundBlurModes",           TYPE_BYTE   },
+    [ ANDROID_DESKTOP_EFFECTS_BACKGROUND_BLUR_MODE - ANDROID_DESKTOP_EFFECTS_START ] =
+    { "backgroundBlurMode",            TYPE_BYTE   },
+    [ ANDROID_DESKTOP_EFFECTS_FACE_RETOUCH_MODE - ANDROID_DESKTOP_EFFECTS_START ] =
+    { "faceRetouchMode",               TYPE_BYTE   },
+    [ ANDROID_DESKTOP_EFFECTS_FACE_RETOUCH_STRENGTH - ANDROID_DESKTOP_EFFECTS_START ] =
+    { "faceRetouchStrength",           TYPE_BYTE   },
+    [ ANDROID_DESKTOP_EFFECTS_PORTRAIT_RELIGHT_MODE - ANDROID_DESKTOP_EFFECTS_START ] =
+    { "portraitRelightMode",           TYPE_BYTE   },
+};
+
 
 tag_info_t *tag_info[ANDROID_SECTION_COUNT] = {
     android_color_correction,
@@ -1020,6 +1084,8 @@ tag_info_t *tag_info[ANDROID_SECTION_COUNT] = {
     android_automotive_lens,
     android_extension,
     android_jpegr,
+    android_shared_session,
+    android_desktop_effects,
 };
 
 static int32_t tag_permission_needed[18] = {
@@ -1065,6 +1131,10 @@ int camera_metadata_enum_snprint(uint32_t tag,
                     msg = "HIGH_QUALITY";
                     ret = 0;
                     break;
+                case ANDROID_COLOR_CORRECTION_MODE_CCT:
+                    msg = "CCT";
+                    ret = 0;
+                    break;
                 default:
                     msg = "error: enum value out of range";
             }
@@ -1098,6 +1168,18 @@ int camera_metadata_enum_snprint(uint32_t tag,
         case ANDROID_COLOR_CORRECTION_AVAILABLE_ABERRATION_MODES: {
             break;
         }
+        case ANDROID_COLOR_CORRECTION_COLOR_TEMPERATURE: {
+            break;
+        }
+        case ANDROID_COLOR_CORRECTION_COLOR_TINT: {
+            break;
+        }
+        case ANDROID_COLOR_CORRECTION_COLOR_TEMPERATURE_RANGE: {
+            break;
+        }
+        case ANDROID_COLOR_CORRECTION_AVAILABLE_MODES: {
+            break;
+        }
 
         case ANDROID_CONTROL_AE_ANTIBANDING_MODE: {
             switch (value) {
@@ -1919,6 +2001,43 @@ int camera_metadata_enum_snprint(uint32_t tag,
             }
             break;
         }
+        case ANDROID_CONTROL_ZOOM_METHOD: {
+            switch (value) {
+                case ANDROID_CONTROL_ZOOM_METHOD_AUTO:
+                    msg = "AUTO";
+                    ret = 0;
+                    break;
+                case ANDROID_CONTROL_ZOOM_METHOD_ZOOM_RATIO:
+                    msg = "ZOOM_RATIO";
+                    ret = 0;
+                    break;
+                default:
+                    msg = "error: enum value out of range";
+            }
+            break;
+        }
+        case ANDROID_CONTROL_AE_PRIORITY_MODE: {
+            switch (value) {
+                case ANDROID_CONTROL_AE_PRIORITY_MODE_OFF:
+                    msg = "OFF";
+                    ret = 0;
+                    break;
+                case ANDROID_CONTROL_AE_PRIORITY_MODE_SENSOR_SENSITIVITY_PRIORITY:
+                    msg = "SENSOR_SENSITIVITY_PRIORITY";
+                    ret = 0;
+                    break;
+                case ANDROID_CONTROL_AE_PRIORITY_MODE_SENSOR_EXPOSURE_TIME_PRIORITY:
+                    msg = "SENSOR_EXPOSURE_TIME_PRIORITY";
+                    ret = 0;
+                    break;
+                default:
+                    msg = "error: enum value out of range";
+            }
+            break;
+        }
+        case ANDROID_CONTROL_AE_AVAILABLE_PRIORITY_MODES: {
+            break;
+        }
 
         case ANDROID_DEMOSAIC_MODE: {
             switch (value) {
@@ -3613,6 +3732,10 @@ int camera_metadata_enum_snprint(uint32_t tag,
                     msg = "VANILLA_ICE_CREAM";
                     ret = 0;
                     break;
+                case ANDROID_INFO_SESSION_CONFIGURATION_QUERY_VERSION_BAKLAVA:
+                    msg = "BAKLAVA";
+                    ret = 0;
+                    break;
                 default:
                     msg = "error: enum value out of range";
             }
@@ -3872,6 +3995,48 @@ int camera_metadata_enum_snprint(uint32_t tag,
         case ANDROID_HEIC_AVAILABLE_HEIC_STALL_DURATIONS_MAXIMUM_RESOLUTION: {
             break;
         }
+        case ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STREAM_CONFIGURATIONS: {
+            switch (value) {
+                case ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STREAM_CONFIGURATIONS_OUTPUT:
+                    msg = "OUTPUT";
+                    ret = 0;
+                    break;
+                case ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STREAM_CONFIGURATIONS_INPUT:
+                    msg = "INPUT";
+                    ret = 0;
+                    break;
+                default:
+                    msg = "error: enum value out of range";
+            }
+            break;
+        }
+        case ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_MIN_FRAME_DURATIONS: {
+            break;
+        }
+        case ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STALL_DURATIONS: {
+            break;
+        }
+        case ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STREAM_CONFIGURATIONS_MAXIMUM_RESOLUTION: {
+            switch (value) {
+                case ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STREAM_CONFIGURATIONS_MAXIMUM_RESOLUTION_OUTPUT:
+                    msg = "OUTPUT";
+                    ret = 0;
+                    break;
+                case ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STREAM_CONFIGURATIONS_MAXIMUM_RESOLUTION_INPUT:
+                    msg = "INPUT";
+                    ret = 0;
+                    break;
+                default:
+                    msg = "error: enum value out of range";
+            }
+            break;
+        }
+        case ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_MIN_FRAME_DURATIONS_MAXIMUM_RESOLUTION: {
+            break;
+        }
+        case ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STALL_DURATIONS_MAXIMUM_RESOLUTION: {
+            break;
+        }
 
         case ANDROID_HEIC_INFO_SUPPORTED: {
             switch (value) {
@@ -4018,6 +4183,25 @@ int camera_metadata_enum_snprint(uint32_t tag,
         case ANDROID_EXTENSION_CURRENT_TYPE: {
             break;
         }
+        case ANDROID_EXTENSION_NIGHT_MODE_INDICATOR: {
+            switch (value) {
+                case ANDROID_EXTENSION_NIGHT_MODE_INDICATOR_UNKNOWN:
+                    msg = "UNKNOWN";
+                    ret = 0;
+                    break;
+                case ANDROID_EXTENSION_NIGHT_MODE_INDICATOR_OFF:
+                    msg = "OFF";
+                    ret = 0;
+                    break;
+                case ANDROID_EXTENSION_NIGHT_MODE_INDICATOR_ON:
+                    msg = "ON";
+                    ret = 0;
+                    break;
+                default:
+                    msg = "error: enum value out of range";
+            }
+            break;
+        }
 
         case ANDROID_JPEGR_AVAILABLE_JPEG_R_STREAM_CONFIGURATIONS: {
             switch (value) {
@@ -4062,6 +4246,108 @@ int camera_metadata_enum_snprint(uint32_t tag,
             break;
         }
 
+        case ANDROID_SHARED_SESSION_COLOR_SPACE: {
+            switch (value) {
+                case ANDROID_SHARED_SESSION_COLOR_SPACE_UNSPECIFIED:
+                    msg = "UNSPECIFIED";
+                    ret = 0;
+                    break;
+                case ANDROID_SHARED_SESSION_COLOR_SPACE_SRGB:
+                    msg = "SRGB";
+                    ret = 0;
+                    break;
+                case ANDROID_SHARED_SESSION_COLOR_SPACE_DISPLAY_P3:
+                    msg = "DISPLAY_P3";
+                    ret = 0;
+                    break;
+                case ANDROID_SHARED_SESSION_COLOR_SPACE_BT2020_HLG:
+                    msg = "BT2020_HLG";
+                    ret = 0;
+                    break;
+                default:
+                    msg = "error: enum value out of range";
+            }
+            break;
+        }
+        case ANDROID_SHARED_SESSION_OUTPUT_CONFIGURATIONS: {
+            break;
+        }
+
+        case ANDROID_DESKTOP_EFFECTS_CAPABILITIES: {
+            switch (value) {
+                case ANDROID_DESKTOP_EFFECTS_CAPABILITIES_BACKGROUND_BLUR:
+                    msg = "BACKGROUND_BLUR";
+                    ret = 0;
+                    break;
+                case ANDROID_DESKTOP_EFFECTS_CAPABILITIES_FACE_RETOUCH:
+                    msg = "FACE_RETOUCH";
+                    ret = 0;
+                    break;
+                case ANDROID_DESKTOP_EFFECTS_CAPABILITIES_PORTRAIT_RELIGHT:
+                    msg = "PORTRAIT_RELIGHT";
+                    ret = 0;
+                    break;
+                default:
+                    msg = "error: enum value out of range";
+            }
+            break;
+        }
+        case ANDROID_DESKTOP_EFFECTS_BACKGROUND_BLUR_MODES: {
+            break;
+        }
+        case ANDROID_DESKTOP_EFFECTS_BACKGROUND_BLUR_MODE: {
+            switch (value) {
+                case ANDROID_DESKTOP_EFFECTS_BACKGROUND_BLUR_MODE_OFF:
+                    msg = "OFF";
+                    ret = 0;
+                    break;
+                case ANDROID_DESKTOP_EFFECTS_BACKGROUND_BLUR_MODE_LIGHT:
+                    msg = "LIGHT";
+                    ret = 0;
+                    break;
+                case ANDROID_DESKTOP_EFFECTS_BACKGROUND_BLUR_MODE_FULL:
+                    msg = "FULL";
+                    ret = 0;
+                    break;
+                default:
+                    msg = "error: enum value out of range";
+            }
+            break;
+        }
+        case ANDROID_DESKTOP_EFFECTS_FACE_RETOUCH_MODE: {
+            switch (value) {
+                case ANDROID_DESKTOP_EFFECTS_FACE_RETOUCH_MODE_OFF:
+                    msg = "OFF";
+                    ret = 0;
+                    break;
+                case ANDROID_DESKTOP_EFFECTS_FACE_RETOUCH_MODE_ON:
+                    msg = "ON";
+                    ret = 0;
+                    break;
+                default:
+                    msg = "error: enum value out of range";
+            }
+            break;
+        }
+        case ANDROID_DESKTOP_EFFECTS_FACE_RETOUCH_STRENGTH: {
+            break;
+        }
+        case ANDROID_DESKTOP_EFFECTS_PORTRAIT_RELIGHT_MODE: {
+            switch (value) {
+                case ANDROID_DESKTOP_EFFECTS_PORTRAIT_RELIGHT_MODE_OFF:
+                    msg = "OFF";
+                    ret = 0;
+                    break;
+                case ANDROID_DESKTOP_EFFECTS_PORTRAIT_RELIGHT_MODE_ON:
+                    msg = "ON";
+                    ret = 0;
+                    break;
+                default:
+                    msg = "error: enum value out of range";
+            }
+            break;
+        }
+
     }
 
     strncpy(dst, msg, size - 1);
@@ -4101,6 +4387,12 @@ int camera_metadata_enum_value(uint32_t tag,
                     ret = 0;
                     break;
                 }
+                enumName = "CCT";
+                if (strncmp(name, enumName, size) == 0) {
+                    *value = ANDROID_COLOR_CORRECTION_MODE_CCT;
+                    ret = 0;
+                    break;
+                }
             break;
         }
         case ANDROID_COLOR_CORRECTION_TRANSFORM: {
@@ -4133,6 +4425,18 @@ int camera_metadata_enum_value(uint32_t tag,
         case ANDROID_COLOR_CORRECTION_AVAILABLE_ABERRATION_MODES: {
             break;
         }
+        case ANDROID_COLOR_CORRECTION_COLOR_TEMPERATURE: {
+            break;
+        }
+        case ANDROID_COLOR_CORRECTION_COLOR_TINT: {
+            break;
+        }
+        case ANDROID_COLOR_CORRECTION_COLOR_TEMPERATURE_RANGE: {
+            break;
+        }
+        case ANDROID_COLOR_CORRECTION_AVAILABLE_MODES: {
+            break;
+        }
 
         case ANDROID_CONTROL_AE_ANTIBANDING_MODE: {
                 enumName = "OFF";
@@ -5100,6 +5404,45 @@ int camera_metadata_enum_value(uint32_t tag,
                 }
             break;
         }
+        case ANDROID_CONTROL_ZOOM_METHOD: {
+                enumName = "AUTO";
+                if (strncmp(name, enumName, size) == 0) {
+                    *value = ANDROID_CONTROL_ZOOM_METHOD_AUTO;
+                    ret = 0;
+                    break;
+                }
+                enumName = "ZOOM_RATIO";
+                if (strncmp(name, enumName, size) == 0) {
+                    *value = ANDROID_CONTROL_ZOOM_METHOD_ZOOM_RATIO;
+                    ret = 0;
+                    break;
+                }
+            break;
+        }
+        case ANDROID_CONTROL_AE_PRIORITY_MODE: {
+                enumName = "OFF";
+                if (strncmp(name, enumName, size) == 0) {
+                    *value = ANDROID_CONTROL_AE_PRIORITY_MODE_OFF;
+                    ret = 0;
+                    break;
+                }
+                enumName = "SENSOR_SENSITIVITY_PRIORITY";
+                if (strncmp(name, enumName, size) == 0) {
+                    *value = ANDROID_CONTROL_AE_PRIORITY_MODE_SENSOR_SENSITIVITY_PRIORITY;
+                    ret = 0;
+                    break;
+                }
+                enumName = "SENSOR_EXPOSURE_TIME_PRIORITY";
+                if (strncmp(name, enumName, size) == 0) {
+                    *value = ANDROID_CONTROL_AE_PRIORITY_MODE_SENSOR_EXPOSURE_TIME_PRIORITY;
+                    ret = 0;
+                    break;
+                }
+            break;
+        }
+        case ANDROID_CONTROL_AE_AVAILABLE_PRIORITY_MODES: {
+            break;
+        }
 
         case ANDROID_DEMOSAIC_MODE: {
                 enumName = "FAST";
@@ -7011,6 +7354,12 @@ int camera_metadata_enum_value(uint32_t tag,
                     ret = 0;
                     break;
                 }
+                enumName = "BAKLAVA";
+                if (strncmp(name, enumName, size) == 0) {
+                    *value = ANDROID_INFO_SESSION_CONFIGURATION_QUERY_VERSION_BAKLAVA;
+                    ret = 0;
+                    break;
+                }
             break;
         }
         case ANDROID_INFO_DEVICE_ID: {
@@ -7269,6 +7618,48 @@ int camera_metadata_enum_value(uint32_t tag,
         case ANDROID_HEIC_AVAILABLE_HEIC_STALL_DURATIONS_MAXIMUM_RESOLUTION: {
             break;
         }
+        case ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STREAM_CONFIGURATIONS: {
+                enumName = "OUTPUT";
+                if (strncmp(name, enumName, size) == 0) {
+                    *value = ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STREAM_CONFIGURATIONS_OUTPUT;
+                    ret = 0;
+                    break;
+                }
+                enumName = "INPUT";
+                if (strncmp(name, enumName, size) == 0) {
+                    *value = ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STREAM_CONFIGURATIONS_INPUT;
+                    ret = 0;
+                    break;
+                }
+            break;
+        }
+        case ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_MIN_FRAME_DURATIONS: {
+            break;
+        }
+        case ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STALL_DURATIONS: {
+            break;
+        }
+        case ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STREAM_CONFIGURATIONS_MAXIMUM_RESOLUTION: {
+                enumName = "OUTPUT";
+                if (strncmp(name, enumName, size) == 0) {
+                    *value = ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STREAM_CONFIGURATIONS_MAXIMUM_RESOLUTION_OUTPUT;
+                    ret = 0;
+                    break;
+                }
+                enumName = "INPUT";
+                if (strncmp(name, enumName, size) == 0) {
+                    *value = ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STREAM_CONFIGURATIONS_MAXIMUM_RESOLUTION_INPUT;
+                    ret = 0;
+                    break;
+                }
+            break;
+        }
+        case ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_MIN_FRAME_DURATIONS_MAXIMUM_RESOLUTION: {
+            break;
+        }
+        case ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STALL_DURATIONS_MAXIMUM_RESOLUTION: {
+            break;
+        }
 
         case ANDROID_HEIC_INFO_SUPPORTED: {
                 enumName = "FALSE";
@@ -7459,6 +7850,27 @@ int camera_metadata_enum_value(uint32_t tag,
         case ANDROID_EXTENSION_CURRENT_TYPE: {
             break;
         }
+        case ANDROID_EXTENSION_NIGHT_MODE_INDICATOR: {
+                enumName = "UNKNOWN";
+                if (strncmp(name, enumName, size) == 0) {
+                    *value = ANDROID_EXTENSION_NIGHT_MODE_INDICATOR_UNKNOWN;
+                    ret = 0;
+                    break;
+                }
+                enumName = "OFF";
+                if (strncmp(name, enumName, size) == 0) {
+                    *value = ANDROID_EXTENSION_NIGHT_MODE_INDICATOR_OFF;
+                    ret = 0;
+                    break;
+                }
+                enumName = "ON";
+                if (strncmp(name, enumName, size) == 0) {
+                    *value = ANDROID_EXTENSION_NIGHT_MODE_INDICATOR_ON;
+                    ret = 0;
+                    break;
+                }
+            break;
+        }
 
         case ANDROID_JPEGR_AVAILABLE_JPEG_R_STREAM_CONFIGURATIONS: {
                 enumName = "OUTPUT";
@@ -7503,6 +7915,116 @@ int camera_metadata_enum_value(uint32_t tag,
             break;
         }
 
+        case ANDROID_SHARED_SESSION_COLOR_SPACE: {
+                enumName = "UNSPECIFIED";
+                if (strncmp(name, enumName, size) == 0) {
+                    *value = ANDROID_SHARED_SESSION_COLOR_SPACE_UNSPECIFIED;
+                    ret = 0;
+                    break;
+                }
+                enumName = "SRGB";
+                if (strncmp(name, enumName, size) == 0) {
+                    *value = ANDROID_SHARED_SESSION_COLOR_SPACE_SRGB;
+                    ret = 0;
+                    break;
+                }
+                enumName = "DISPLAY_P3";
+                if (strncmp(name, enumName, size) == 0) {
+                    *value = ANDROID_SHARED_SESSION_COLOR_SPACE_DISPLAY_P3;
+                    ret = 0;
+                    break;
+                }
+                enumName = "BT2020_HLG";
+                if (strncmp(name, enumName, size) == 0) {
+                    *value = ANDROID_SHARED_SESSION_COLOR_SPACE_BT2020_HLG;
+                    ret = 0;
+                    break;
+                }
+            break;
+        }
+        case ANDROID_SHARED_SESSION_OUTPUT_CONFIGURATIONS: {
+            break;
+        }
+
+        case ANDROID_DESKTOP_EFFECTS_CAPABILITIES: {
+                enumName = "BACKGROUND_BLUR";
+                if (strncmp(name, enumName, size) == 0) {
+                    *value = ANDROID_DESKTOP_EFFECTS_CAPABILITIES_BACKGROUND_BLUR;
+                    ret = 0;
+                    break;
+                }
+                enumName = "FACE_RETOUCH";
+                if (strncmp(name, enumName, size) == 0) {
+                    *value = ANDROID_DESKTOP_EFFECTS_CAPABILITIES_FACE_RETOUCH;
+                    ret = 0;
+                    break;
+                }
+                enumName = "PORTRAIT_RELIGHT";
+                if (strncmp(name, enumName, size) == 0) {
+                    *value = ANDROID_DESKTOP_EFFECTS_CAPABILITIES_PORTRAIT_RELIGHT;
+                    ret = 0;
+                    break;
+                }
+            break;
+        }
+        case ANDROID_DESKTOP_EFFECTS_BACKGROUND_BLUR_MODES: {
+            break;
+        }
+        case ANDROID_DESKTOP_EFFECTS_BACKGROUND_BLUR_MODE: {
+                enumName = "OFF";
+                if (strncmp(name, enumName, size) == 0) {
+                    *value = ANDROID_DESKTOP_EFFECTS_BACKGROUND_BLUR_MODE_OFF;
+                    ret = 0;
+                    break;
+                }
+                enumName = "LIGHT";
+                if (strncmp(name, enumName, size) == 0) {
+                    *value = ANDROID_DESKTOP_EFFECTS_BACKGROUND_BLUR_MODE_LIGHT;
+                    ret = 0;
+                    break;
+                }
+                enumName = "FULL";
+                if (strncmp(name, enumName, size) == 0) {
+                    *value = ANDROID_DESKTOP_EFFECTS_BACKGROUND_BLUR_MODE_FULL;
+                    ret = 0;
+                    break;
+                }
+            break;
+        }
+        case ANDROID_DESKTOP_EFFECTS_FACE_RETOUCH_MODE: {
+                enumName = "OFF";
+                if (strncmp(name, enumName, size) == 0) {
+                    *value = ANDROID_DESKTOP_EFFECTS_FACE_RETOUCH_MODE_OFF;
+                    ret = 0;
+                    break;
+                }
+                enumName = "ON";
+                if (strncmp(name, enumName, size) == 0) {
+                    *value = ANDROID_DESKTOP_EFFECTS_FACE_RETOUCH_MODE_ON;
+                    ret = 0;
+                    break;
+                }
+            break;
+        }
+        case ANDROID_DESKTOP_EFFECTS_FACE_RETOUCH_STRENGTH: {
+            break;
+        }
+        case ANDROID_DESKTOP_EFFECTS_PORTRAIT_RELIGHT_MODE: {
+                enumName = "OFF";
+                if (strncmp(name, enumName, size) == 0) {
+                    *value = ANDROID_DESKTOP_EFFECTS_PORTRAIT_RELIGHT_MODE_OFF;
+                    ret = 0;
+                    break;
+                }
+                enumName = "ON";
+                if (strncmp(name, enumName, size) == 0) {
+                    *value = ANDROID_DESKTOP_EFFECTS_PORTRAIT_RELIGHT_MODE_ON;
+                    ret = 0;
+                    break;
+                }
+            break;
+        }
+
     }
 
     return ret;
diff --git a/camera/src/ndk_camera_metadata_asserts.cpp b/camera/src/ndk_camera_metadata_asserts.cpp
index 8df42ae1..1caa2bb0 100644
--- a/camera/src/ndk_camera_metadata_asserts.cpp
+++ b/camera/src/ndk_camera_metadata_asserts.cpp
@@ -94,6 +94,10 @@ static_assert(static_cast<int>(ANDROID_EXTENSION)
         == static_cast<int>(ACAMERA_EXTENSION));
 static_assert(static_cast<int>(ANDROID_JPEGR)
         == static_cast<int>(ACAMERA_JPEGR));
+static_assert(static_cast<int>(ANDROID_SHARED_SESSION)
+        == static_cast<int>(ACAMERA_SHARED_SESSION));
+static_assert(static_cast<int>(ANDROID_DESKTOP_EFFECTS)
+        == static_cast<int>(ACAMERA_DESKTOP_EFFECTS));
 
 static_assert(static_cast<int>(ANDROID_COLOR_CORRECTION_START)
         == static_cast<int>(ACAMERA_COLOR_CORRECTION_START));
@@ -163,6 +167,10 @@ static_assert(static_cast<int>(ANDROID_EXTENSION_START)
         == static_cast<int>(ACAMERA_EXTENSION_START));
 static_assert(static_cast<int>(ANDROID_JPEGR_START)
         == static_cast<int>(ACAMERA_JPEGR_START));
+static_assert(static_cast<int>(ANDROID_SHARED_SESSION_START)
+        == static_cast<int>(ACAMERA_SHARED_SESSION_START));
+static_assert(static_cast<int>(ANDROID_DESKTOP_EFFECTS_START)
+        == static_cast<int>(ACAMERA_DESKTOP_EFFECTS_START));
 
 
 static_assert(static_cast<int>(ANDROID_COLOR_CORRECTION_MODE)
@@ -180,6 +188,18 @@ static_assert(static_cast<int>(ANDROID_COLOR_CORRECTION_ABERRATION_MODE)
 static_assert(static_cast<int>(ANDROID_COLOR_CORRECTION_AVAILABLE_ABERRATION_MODES)
         == static_cast<int>(ACAMERA_COLOR_CORRECTION_AVAILABLE_ABERRATION_MODES));
 
+static_assert(static_cast<int>(ANDROID_COLOR_CORRECTION_COLOR_TEMPERATURE)
+        == static_cast<int>(ACAMERA_COLOR_CORRECTION_COLOR_TEMPERATURE));
+
+static_assert(static_cast<int>(ANDROID_COLOR_CORRECTION_COLOR_TINT)
+        == static_cast<int>(ACAMERA_COLOR_CORRECTION_COLOR_TINT));
+
+static_assert(static_cast<int>(ANDROID_COLOR_CORRECTION_COLOR_TEMPERATURE_RANGE)
+        == static_cast<int>(ACAMERA_COLOR_CORRECTION_COLOR_TEMPERATURE_RANGE));
+
+static_assert(static_cast<int>(ANDROID_COLOR_CORRECTION_AVAILABLE_MODES)
+        == static_cast<int>(ACAMERA_COLOR_CORRECTION_AVAILABLE_MODES));
+
 static_assert(static_cast<int>(ANDROID_CONTROL_AE_ANTIBANDING_MODE)
         == static_cast<int>(ACAMERA_CONTROL_AE_ANTIBANDING_MODE));
 
@@ -333,6 +353,12 @@ static_assert(static_cast<int>(ANDROID_CONTROL_LOW_LIGHT_BOOST_INFO_LUMINANCE_RA
 static_assert(static_cast<int>(ANDROID_CONTROL_LOW_LIGHT_BOOST_STATE)
         == static_cast<int>(ACAMERA_CONTROL_LOW_LIGHT_BOOST_STATE));
 
+static_assert(static_cast<int>(ANDROID_CONTROL_AE_PRIORITY_MODE)
+        == static_cast<int>(ACAMERA_CONTROL_AE_PRIORITY_MODE));
+
+static_assert(static_cast<int>(ANDROID_CONTROL_AE_AVAILABLE_PRIORITY_MODES)
+        == static_cast<int>(ACAMERA_CONTROL_AE_AVAILABLE_PRIORITY_MODES));
+
 static_assert(static_cast<int>(ANDROID_EDGE_MODE)
         == static_cast<int>(ACAMERA_EDGE_MODE));
 
@@ -882,12 +908,33 @@ static_assert(static_cast<int>(ANDROID_HEIC_AVAILABLE_HEIC_MIN_FRAME_DURATIONS_M
 static_assert(static_cast<int>(ANDROID_HEIC_AVAILABLE_HEIC_STALL_DURATIONS_MAXIMUM_RESOLUTION)
         == static_cast<int>(ACAMERA_HEIC_AVAILABLE_HEIC_STALL_DURATIONS_MAXIMUM_RESOLUTION));
 
+static_assert(static_cast<int>(ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STREAM_CONFIGURATIONS)
+        == static_cast<int>(ACAMERA_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STREAM_CONFIGURATIONS));
+
+static_assert(static_cast<int>(ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_MIN_FRAME_DURATIONS)
+        == static_cast<int>(ACAMERA_HEIC_AVAILABLE_HEIC_ULTRA_HDR_MIN_FRAME_DURATIONS));
+
+static_assert(static_cast<int>(ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STALL_DURATIONS)
+        == static_cast<int>(ACAMERA_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STALL_DURATIONS));
+
+static_assert(static_cast<int>(ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STREAM_CONFIGURATIONS_MAXIMUM_RESOLUTION)
+        == static_cast<int>(ACAMERA_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STREAM_CONFIGURATIONS_MAXIMUM_RESOLUTION));
+
+static_assert(static_cast<int>(ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_MIN_FRAME_DURATIONS_MAXIMUM_RESOLUTION)
+        == static_cast<int>(ACAMERA_HEIC_AVAILABLE_HEIC_ULTRA_HDR_MIN_FRAME_DURATIONS_MAXIMUM_RESOLUTION));
+
+static_assert(static_cast<int>(ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STALL_DURATIONS_MAXIMUM_RESOLUTION)
+        == static_cast<int>(ACAMERA_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STALL_DURATIONS_MAXIMUM_RESOLUTION));
+
 static_assert(static_cast<int>(ANDROID_AUTOMOTIVE_LOCATION)
         == static_cast<int>(ACAMERA_AUTOMOTIVE_LOCATION));
 
 static_assert(static_cast<int>(ANDROID_AUTOMOTIVE_LENS_FACING)
         == static_cast<int>(ACAMERA_AUTOMOTIVE_LENS_FACING));
 
+static_assert(static_cast<int>(ANDROID_EXTENSION_NIGHT_MODE_INDICATOR)
+        == static_cast<int>(ACAMERA_EXTENSION_NIGHT_MODE_INDICATOR));
+
 static_assert(static_cast<int>(ANDROID_JPEGR_AVAILABLE_JPEG_R_STREAM_CONFIGURATIONS)
         == static_cast<int>(ACAMERA_JPEGR_AVAILABLE_JPEG_R_STREAM_CONFIGURATIONS));
 
@@ -912,6 +959,8 @@ static_assert(static_cast<int32_t>(ANDROID_COLOR_CORRECTION_MODE_FAST)
         == static_cast<int32_t>(ACAMERA_COLOR_CORRECTION_MODE_FAST));
 static_assert(static_cast<int32_t>(ANDROID_COLOR_CORRECTION_MODE_HIGH_QUALITY)
         == static_cast<int32_t>(ACAMERA_COLOR_CORRECTION_MODE_HIGH_QUALITY));
+static_assert(static_cast<int32_t>(ANDROID_COLOR_CORRECTION_MODE_CCT)
+        == static_cast<int32_t>(ACAMERA_COLOR_CORRECTION_MODE_CCT));
 static_assert(static_cast<int32_t>(ANDROID_COLOR_CORRECTION_ABERRATION_MODE_OFF)
         == static_cast<int32_t>(ACAMERA_COLOR_CORRECTION_ABERRATION_MODE_OFF));
 static_assert(static_cast<int32_t>(ANDROID_COLOR_CORRECTION_ABERRATION_MODE_FAST)
@@ -1155,6 +1204,12 @@ static_assert(static_cast<int32_t>(ANDROID_CONTROL_LOW_LIGHT_BOOST_STATE_INACTIV
         == static_cast<int32_t>(ACAMERA_CONTROL_LOW_LIGHT_BOOST_STATE_INACTIVE));
 static_assert(static_cast<int32_t>(ANDROID_CONTROL_LOW_LIGHT_BOOST_STATE_ACTIVE)
         == static_cast<int32_t>(ACAMERA_CONTROL_LOW_LIGHT_BOOST_STATE_ACTIVE));
+static_assert(static_cast<int32_t>(ANDROID_CONTROL_AE_PRIORITY_MODE_OFF)
+        == static_cast<int32_t>(ACAMERA_CONTROL_AE_PRIORITY_MODE_OFF));
+static_assert(static_cast<int32_t>(ANDROID_CONTROL_AE_PRIORITY_MODE_SENSOR_SENSITIVITY_PRIORITY)
+        == static_cast<int32_t>(ACAMERA_CONTROL_AE_PRIORITY_MODE_SENSOR_SENSITIVITY_PRIORITY));
+static_assert(static_cast<int32_t>(ANDROID_CONTROL_AE_PRIORITY_MODE_SENSOR_EXPOSURE_TIME_PRIORITY)
+        == static_cast<int32_t>(ACAMERA_CONTROL_AE_PRIORITY_MODE_SENSOR_EXPOSURE_TIME_PRIORITY));
 
 
 static_assert(static_cast<int32_t>(ANDROID_EDGE_MODE_OFF)
@@ -1562,6 +1617,14 @@ static_assert(static_cast<int32_t>(ANDROID_HEIC_AVAILABLE_HEIC_STREAM_CONFIGURAT
         == static_cast<int32_t>(ACAMERA_HEIC_AVAILABLE_HEIC_STREAM_CONFIGURATIONS_MAXIMUM_RESOLUTION_OUTPUT));
 static_assert(static_cast<int32_t>(ANDROID_HEIC_AVAILABLE_HEIC_STREAM_CONFIGURATIONS_MAXIMUM_RESOLUTION_INPUT)
         == static_cast<int32_t>(ACAMERA_HEIC_AVAILABLE_HEIC_STREAM_CONFIGURATIONS_MAXIMUM_RESOLUTION_INPUT));
+static_assert(static_cast<int32_t>(ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STREAM_CONFIGURATIONS_OUTPUT)
+        == static_cast<int32_t>(ACAMERA_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STREAM_CONFIGURATIONS_OUTPUT));
+static_assert(static_cast<int32_t>(ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STREAM_CONFIGURATIONS_INPUT)
+        == static_cast<int32_t>(ACAMERA_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STREAM_CONFIGURATIONS_INPUT));
+static_assert(static_cast<int32_t>(ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STREAM_CONFIGURATIONS_MAXIMUM_RESOLUTION_OUTPUT)
+        == static_cast<int32_t>(ACAMERA_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STREAM_CONFIGURATIONS_MAXIMUM_RESOLUTION_OUTPUT));
+static_assert(static_cast<int32_t>(ANDROID_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STREAM_CONFIGURATIONS_MAXIMUM_RESOLUTION_INPUT)
+        == static_cast<int32_t>(ACAMERA_HEIC_AVAILABLE_HEIC_ULTRA_HDR_STREAM_CONFIGURATIONS_MAXIMUM_RESOLUTION_INPUT));
 
 
 static_assert(static_cast<int32_t>(ANDROID_AUTOMOTIVE_LOCATION_INTERIOR)
@@ -1618,6 +1681,12 @@ static_assert(static_cast<int32_t>(ANDROID_AUTOMOTIVE_LENS_FACING_INTERIOR_SEAT_
 static_assert(static_cast<int32_t>(ANDROID_AUTOMOTIVE_LENS_FACING_INTERIOR_SEAT_ROW_3_RIGHT)
         == static_cast<int32_t>(ACAMERA_AUTOMOTIVE_LENS_FACING_INTERIOR_SEAT_ROW_3_RIGHT));
 
+static_assert(static_cast<int32_t>(ANDROID_EXTENSION_NIGHT_MODE_INDICATOR_UNKNOWN)
+        == static_cast<int32_t>(ACAMERA_EXTENSION_NIGHT_MODE_INDICATOR_UNKNOWN));
+static_assert(static_cast<int32_t>(ANDROID_EXTENSION_NIGHT_MODE_INDICATOR_OFF)
+        == static_cast<int32_t>(ACAMERA_EXTENSION_NIGHT_MODE_INDICATOR_OFF));
+static_assert(static_cast<int32_t>(ANDROID_EXTENSION_NIGHT_MODE_INDICATOR_ON)
+        == static_cast<int32_t>(ACAMERA_EXTENSION_NIGHT_MODE_INDICATOR_ON));
 
 static_assert(static_cast<int32_t>(ANDROID_JPEGR_AVAILABLE_JPEG_R_STREAM_CONFIGURATIONS_OUTPUT)
         == static_cast<int32_t>(ACAMERA_JPEGR_AVAILABLE_JPEG_R_STREAM_CONFIGURATIONS_OUTPUT));
@@ -1628,3 +1697,5 @@ static_assert(static_cast<int32_t>(ANDROID_JPEGR_AVAILABLE_JPEG_R_STREAM_CONFIGU
 static_assert(static_cast<int32_t>(ANDROID_JPEGR_AVAILABLE_JPEG_R_STREAM_CONFIGURATIONS_MAXIMUM_RESOLUTION_INPUT)
         == static_cast<int32_t>(ACAMERA_JPEGR_AVAILABLE_JPEG_R_STREAM_CONFIGURATIONS_MAXIMUM_RESOLUTION_INPUT));
 
+
+
diff --git a/tests/Android.bp b/tests/Android.bp
index 6583b68c..99cb0062 100644
--- a/tests/Android.bp
+++ b/tests/Android.bp
@@ -9,36 +9,57 @@ package {
     default_applicable_licenses: ["system_media_license"],
 }
 
-cc_test {
-    name: "audio_aidl_utils_test",
-
-    defaults: [
-        "latest_android_hardware_audio_effect_ndk_static",
-        "latest_android_media_audio_common_types_ndk_static",
-    ],
-
+cc_defaults {
+    name: "aidl_utils_test_defaults",
     shared_libs: [
+        "libaudioutils",
         "libbase",
+        "libbinder_ndk",
+        "libcutils",
         "liblog",
-        "libutils",
     ],
-
-    header_libs: ["libmedia_headers"],
-
-    srcs: [
-        "audio_aidl_utils_test.cpp",
+    defaults: [
+        "latest_android_hardware_audio_effect_ndk_static",
+        "latest_android_media_audio_common_types_ndk_static",
     ],
-
     cflags: [
         "-Wall",
         "-Werror",
+        "-Wextra",
     ],
+}
+
+cc_test {
+    name: "elementwise_op_basic_tests",
+    host_supported: true,
+    defaults: ["aidl_utils_test_defaults"],
+    srcs: ["elementwise_op_basic_tests.cpp"],
+}
+
+cc_test {
+    name: "elementwise_op_aidl_tests",
+    host_supported: true,
+    defaults: ["aidl_utils_test_defaults"],
+    srcs: ["elementwise_op_aidl_union_tests.cpp"],
+}
 
+cc_test {
+    name: "audio_aidl_utils_test",
+    defaults: ["aidl_utils_test_defaults"],
+    header_libs: ["libmedia_headers"],
+    srcs: ["audio_aidl_utils_test.cpp"],
+    test_suites: ["device-tests"],
+}
+
+cc_test {
+    name: "aidl_effects_utils_test",
+    defaults: ["aidl_utils_test_defaults"],
+    srcs: ["aidl_effects_utils_test.cpp"],
     test_suites: ["device-tests"],
 }
 
 cc_test {
-    name: "EffectParamWrapper_tests",
+    name: "audio_effects_utils_tests",
 
     shared_libs: [
         "libbase",
@@ -49,7 +70,7 @@ cc_test {
     header_libs: ["libmedia_headers"],
 
     srcs: [
-        "EffectParamWrapper_tests.cpp",
+        "audio_effects_utils_tests.cpp",
     ],
 
     cflags: [
diff --git a/tests/aidl_effects_utils_test.cpp b/tests/aidl_effects_utils_test.cpp
new file mode 100644
index 00000000..46f39af4
--- /dev/null
+++ b/tests/aidl_effects_utils_test.cpp
@@ -0,0 +1,239 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+#include <array>
+
+#define LOG_TAG "AidlEffectsUtilsTest"
+
+#include <aidl/android/hardware/audio/effect/IEffect.h>
+#include <gtest/gtest.h>
+#include <log/log.h>
+#include <system/audio_effects/aidl_effects_utils.h>
+
+using ::aidl::android::hardware::audio::effect::Capability;
+using ::aidl::android::hardware::audio::effect::Downmix;
+using ::aidl::android::hardware::audio::effect::DynamicsProcessing;
+using ::aidl::android::hardware::audio::effect::Parameter;
+using ::aidl::android::hardware::audio::effect::Range;
+
+// Helper function to create a DynamicsProcessing parameter with custom tag
+template <typename DynamicsProcessing::Tag TAG = DynamicsProcessing::engineArchitecture>
+static DynamicsProcessing dynamicsProcessing(int v, int n = 0) {
+  if constexpr (TAG == DynamicsProcessing::engineArchitecture) {
+    const DynamicsProcessing::EngineArchitecture engine{
+        .preferredProcessingDurationMs = static_cast<float>(v),
+        .preEqStage = DynamicsProcessing::StageEnablement{.bandCount = v},
+        .postEqStage = DynamicsProcessing::StageEnablement{.bandCount = v},
+        .mbcStage = DynamicsProcessing::StageEnablement{.bandCount = v},
+    };
+    return DynamicsProcessing::make<DynamicsProcessing::engineArchitecture>(engine);
+  } else if constexpr (TAG == DynamicsProcessing::inputGain) {
+    std::vector<DynamicsProcessing::InputGain> gain;
+    for (int i = 0; i < n; i++) {
+      gain.emplace_back(DynamicsProcessing::InputGain{
+          .channel = i, .gainDb = static_cast<float>(v)});
+    }
+    return DynamicsProcessing::make<DynamicsProcessing::inputGain>(gain);
+  } else {
+    static_assert(false, "tag not supported");
+  }
+}
+
+static Parameter parameter(int v) {
+  return Parameter::make<Parameter::specific>(
+      Parameter::Specific::make<Parameter::Specific::dynamicsProcessing>(dynamicsProcessing(v)));
+}
+
+static Capability capability(int min, int max) {
+  return Capability{
+      .range =
+          Range::make<Range::dynamicsProcessing>({Range::DynamicsProcessingRange{
+              .min = dynamicsProcessing(min), .max = dynamicsProcessing(max),
+          }}),
+  };
+}
+
+static Capability multiCapability(int min, int max) {
+  return Capability{
+      .range = Range::make<Range::dynamicsProcessing>({
+          Range::DynamicsProcessingRange{
+              .min = dynamicsProcessing(min), .max = dynamicsProcessing(max),
+          },
+          Range::DynamicsProcessingRange{
+              .min = dynamicsProcessing<DynamicsProcessing::inputGain>(min),
+              .max = dynamicsProcessing<DynamicsProcessing::inputGain>(max),
+          },
+      }),
+  };
+}
+
+// construct an invalid capability with different vector size
+static Capability capabilityWithDifferentVecSize(int min, int minVecSize, int max, int maxVecSize) {
+  return Capability{
+      .range = Range::make<Range::dynamicsProcessing>({
+          Range::DynamicsProcessingRange{
+              .min = dynamicsProcessing<DynamicsProcessing::inputGain>(min, minVecSize),
+              .max = dynamicsProcessing<DynamicsProcessing::inputGain>(max, maxVecSize),
+          },
+      }),
+  };
+}
+
+static Capability downmixCapability() {
+  return Capability{.range = Range::make<Range::downmix>({Range::DownmixRange{}})};
+}
+
+// static Range::DynamicsProcessingRange createMultiRange(int min, int max) {
+//   return Range::DynamicsProcessingRange{.min = min, .max = max};
+// }
+
+using FindSharedCapabilityTestParam =
+    std::tuple<int /* a_min */, int /* a_max */, int /*b_min*/, int /*b_max*/>;
+class FindSharedCapabilityTest
+    : public ::testing::TestWithParam<FindSharedCapabilityTestParam> {
+ public:
+  FindSharedCapabilityTest()
+      : a_min(std::get<0>(GetParam())),
+        a_max(std::get<1>(GetParam())),
+        b_min(std::get<2>(GetParam())),
+        b_max(std::get<3>(GetParam())) {}
+
+ protected:
+  const int a_min, a_max, b_min, b_max;
+};
+
+/**
+ * Find shared capability with all elements in the predefined capability array `kCapArray`.
+ */
+TEST_P(FindSharedCapabilityTest, basic) {
+  std::optional<Capability> cap =
+      findSharedCapability(capability(a_min, a_max), capability(b_min, b_max));
+  ASSERT_NE(std::nullopt, cap);
+  EXPECT_EQ(capability(std::max(a_min, b_min), std::min(a_max, b_max)).range, cap->range);
+}
+
+TEST_P(FindSharedCapabilityTest, multi_tags) {
+  std::optional<Capability> cap = findSharedCapability(
+      multiCapability(a_min, a_max), multiCapability(b_min, b_max));
+  ASSERT_NE(std::nullopt, cap);
+  EXPECT_EQ(multiCapability(std::max(a_min, b_min), std::min(a_max, b_max)).range, cap->range);
+}
+
+TEST(FindSharedCapabilityTest, diff_effects) {
+  EXPECT_EQ(std::nullopt, findSharedCapability(capability(0, 1), downmixCapability()));
+}
+
+TEST(FindSharedCapabilityTest, capability_with_diff_vec) {
+  auto target = capabilityWithDifferentVecSize(1, 5, 2, 6);
+  auto shared = findSharedCapability(
+      capabilityWithDifferentVecSize(0 /*min*/, 5 /*minVacSize*/, 3 /*max*/, 6 /*maxVacSize*/),
+      capabilityWithDifferentVecSize(1 /*min*/, 5 /*minVacSize*/, 2 /*max*/, 6 /*maxVacSize*/));
+  ASSERT_NE(std::nullopt, shared);
+  EXPECT_EQ(target.range, shared->range);
+
+  // the shared min is invalid because the vector size is different
+  target = capabilityWithDifferentVecSize(0, 0, 1, 3);
+  shared = findSharedCapability(
+      capabilityWithDifferentVecSize(0 /*min*/, 2 /*minVacSize*/, 1 /*max*/, 3 /*maxVacSize*/),
+      capabilityWithDifferentVecSize(0 /*min*/, 3 /*minVacSize*/, 1 /*max*/, 3 /*maxVacSize*/));
+  ASSERT_NE(std::nullopt, shared);
+  ASSERT_EQ(Range::dynamicsProcessing, shared->range.getTag());
+  auto dpRanges = shared->range.get<Range::dynamicsProcessing>();
+  ASSERT_EQ(1ul, dpRanges.size());
+  EXPECT_EQ(DynamicsProcessing::vendor, dpRanges[0].min.getTag());
+  const auto targetRanges = target.range.get<Range::dynamicsProcessing>();
+  EXPECT_EQ(targetRanges[0].max, dpRanges[0].max);
+
+  // the shared min and max both invalid because the vector size is different
+  target = capabilityWithDifferentVecSize(0, 0, 1, 3);
+  shared = findSharedCapability(
+      capabilityWithDifferentVecSize(0 /*min*/, 2 /*minVacSize*/, 1 /*max*/, 5 /*maxVacSize*/),
+      capabilityWithDifferentVecSize(0 /*min*/, 3 /*minVacSize*/, 1 /*max*/, 3 /*maxVacSize*/));
+  EXPECT_EQ(std::nullopt, shared);
+}
+
+using ClampParameterTestParam = std::tuple<int /* a */, int /* b */>;
+class ClampParameterTest
+    : public ::testing::TestWithParam<ClampParameterTestParam> {
+ public:
+  ClampParameterTest()
+      : a(std::get<0>(GetParam())), b(std::get<1>(GetParam())) {}
+
+ protected:
+  const int a, b;
+};
+
+TEST_P(ClampParameterTest, basic) {
+  const std::optional<Parameter> clamped =
+      clampParameter<Range::dynamicsProcessing, Parameter::Specific::dynamicsProcessing>(
+          parameter(a), capability(a, b));
+  if (a <= b) {
+    ASSERT_NE(std::nullopt, clamped);
+    EXPECT_EQ(parameter(a), clamped.value());
+  } else {
+    EXPECT_EQ(std::nullopt, clamped);
+  }
+}
+
+TEST_P(ClampParameterTest, clamp_to_min) {
+  const std::optional<Parameter> clamped =
+      clampParameter<Range::dynamicsProcessing, Parameter::Specific::dynamicsProcessing>(
+          parameter(a - 1), capability(a, b));
+  if (a <= b) {
+    ASSERT_NE(std::nullopt, clamped);
+    EXPECT_EQ(parameter(a), clamped.value());
+  } else {
+    EXPECT_EQ(std::nullopt, clamped);
+  }
+}
+
+TEST_P(ClampParameterTest, clamp_to_max) {
+  const std::optional<Parameter> clamped =
+      clampParameter<Range::dynamicsProcessing, Parameter::Specific::dynamicsProcessing>(
+          parameter(b + 1), capability(a, b));
+  if (a <= b) {
+    ASSERT_NE(std::nullopt, clamped);
+    EXPECT_EQ(parameter(b), clamped.value());
+  } else {
+    EXPECT_EQ(std::nullopt, clamped);
+  }
+}
+
+// minimum and maximum value used to initialize effect parameters for comparison
+static constexpr int kParameterStartValue = 1;
+static constexpr int kParameterEndValue = 4; // end will not included in the generated values
+
+INSTANTIATE_TEST_SUITE_P(
+    AidlEffectsUtilsTest, FindSharedCapabilityTest,
+    ::testing::Combine(testing::Range(kParameterStartValue, kParameterEndValue),
+                       testing::Range(kParameterStartValue, kParameterEndValue),
+                       testing::Range(kParameterStartValue, kParameterEndValue),
+                       testing::Range(kParameterStartValue, kParameterEndValue)),
+    [](const testing::TestParamInfo<FindSharedCapabilityTest::ParamType>& info) {
+      return std::to_string(std::get<0>(info.param)) + "_" +
+             std::to_string(std::get<1>(info.param)) + "_" +
+             std::to_string(std::get<2>(info.param)) + "_" +
+             std::to_string(std::get<3>(info.param));
+    });
+
+INSTANTIATE_TEST_SUITE_P(
+    AidlEffectsUtilsTest, ClampParameterTest,
+    ::testing::Combine(testing::Range(kParameterStartValue, kParameterEndValue),
+                       testing::Range(kParameterStartValue, kParameterEndValue)),
+    [](const testing::TestParamInfo<ClampParameterTest::ParamType>& info) {
+      return std::to_string(std::get<0>(info.param)) + "_" +
+             std::to_string(std::get<1>(info.param));
+    });
\ No newline at end of file
diff --git a/tests/audio_aidl_utils_test.cpp b/tests/audio_aidl_utils_test.cpp
index 2292d1f8..d4418a07 100644
--- a/tests/audio_aidl_utils_test.cpp
+++ b/tests/audio_aidl_utils_test.cpp
@@ -27,4 +27,4 @@ TEST(AudioAidlUtilTest, UuidToString) {
   const auto uuid = ::aidl::android::hardware::audio::effect::stringToUuid(testStr.c_str());
   const auto targetStr = ::android::audio::utils::toString(uuid);
   EXPECT_EQ(testStr, targetStr);
-}
+}
\ No newline at end of file
diff --git a/tests/EffectParamWrapper_tests.cpp b/tests/audio_effects_utils_tests.cpp
similarity index 89%
rename from tests/EffectParamWrapper_tests.cpp
rename to tests/audio_effects_utils_tests.cpp
index cda3f026..5af268b4 100644
--- a/tests/EffectParamWrapper_tests.cpp
+++ b/tests/audio_effects_utils_tests.cpp
@@ -29,6 +29,9 @@ using namespace android;
 using android::effect::utils::EffectParamReader;
 using android::effect::utils::EffectParamWrapper;
 using android::effect::utils::EffectParamWriter;
+using android::effect::utils::operator==;
+using android::effect::utils::operator!=;
+using android::effect::utils::ToString;
 
 TEST(EffectParamWrapperTest, setAndGetMatches) {
     effect_param_t param = {.psize = 2, .vsize = 0x10};
@@ -99,11 +102,11 @@ TEST(EffectParamWrapperTest, getPaddedParameterSize) {
 }
 
 TEST(EffectParamWrapperTest, getPVSize) {
-    effect_param_t vsize1 = {.vsize = 1, .psize = 0xff};
+    effect_param_t vsize1 = {.psize = 0xff, .vsize = 1};
     const auto wrapper1 = EffectParamWrapper(vsize1);
     EXPECT_EQ(vsize1.vsize, wrapper1.getValueSize());
 
-    effect_param_t vsize2 = {.vsize = 0xff, .psize = 0xbe};
+    effect_param_t vsize2 = {.psize = 0xbe, .vsize = 0xff};
     const auto wrapper2 = EffectParamWrapper(vsize2);
     EXPECT_EQ(vsize2.vsize, wrapper2.getValueSize());
 
@@ -421,4 +424,57 @@ TEST(EffectParamWriterTest, overwriteWithLargerSize) {
     newwriter.finishValueWrite();
 
     EXPECT_NE(OK, writer.overwrite(newwriter.getEffectParam()));
-}
\ No newline at end of file
+}
+
+TEST(AudioEffectsUtilsTest, EqualityOperator) {
+    audio_uuid_t uuid1 = {0x12345678, 0x1234, 0x5678, 0x90AB, {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01}};
+    audio_uuid_t uuid2 = {0x12345678, 0x1234, 0x5678, 0x90AB, {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01}};
+
+    EXPECT_TRUE(uuid1 == uuid2);
+    EXPECT_FALSE(uuid1 != uuid2);
+}
+
+TEST(AudioEffectsUtilsTest, InequalityOperator) {
+    audio_uuid_t uuid1 = {0x12345678, 0x1234, 0x5678, 0x90AB, {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01}};
+    audio_uuid_t uuid2 = {0x87654321, 0x4321, 0x8765, 0xBA09, {0x01, 0x00, 0xEF, 0xBE, 0xAD, 0xDE}};
+
+    EXPECT_TRUE(uuid1 != uuid2);
+    EXPECT_FALSE(uuid1 == uuid2);
+}
+
+TEST(AudioEffectsUtilsTest, EqualityWithModifiedNode) {
+    audio_uuid_t uuid1 = {0x12345678, 0x1234, 0x5678, 0x90AB, {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01}};
+    audio_uuid_t uuid2 = uuid1;
+    uuid2.node[5] = 0x02;  // Modify one byte in the `node` array
+
+    EXPECT_FALSE(uuid1 == uuid2);
+    EXPECT_TRUE(uuid1 != uuid2);
+}
+
+TEST(AudioEffectsUtilsTest, ToString) {
+    audio_uuid_t uuid = {0x12345678, 0x1234, 0x5678, 0x90AB, {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01}};
+    std::string expected = "12345678-1234-5678-90ab-deadbeef0001";
+
+    EXPECT_EQ(ToString(uuid), expected);
+}
+
+TEST(AudioEffectsUtilsTest, ToStringUpperCase) {
+    audio_uuid_t uuid = {0x87654321, 0x4321, 0x8765, 0xBA09, {0x01, 0x00, 0xEF, 0xBE, 0xAD, 0xDE}};
+    std::string expected = "87654321-4321-8765-ba09-0100efbeadde";
+
+    EXPECT_EQ(ToString(uuid), expected);
+}
+
+TEST(AudioEffectsUtilsTest, ToStringAllZeros) {
+    audio_uuid_t uuid = {0, 0, 0, 0, {0, 0, 0, 0, 0, 0}};
+    std::string expected = "00000000-0000-0000-0000-000000000000";
+
+    EXPECT_EQ(ToString(uuid), expected);
+}
+
+TEST(AudioEffectsUtilsTest, ToStringBoundaryValues) {
+    audio_uuid_t uuid = {0xFFFFFFFF, 0xFFFF, 0xFFFF, 0xFFFF, {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}};
+    std::string expected = "ffffffff-ffff-ffff-ffff-ffffffffffff";
+
+    EXPECT_EQ(ToString(uuid), expected);
+}
diff --git a/tests/elementwise_op_aidl_union_tests.cpp b/tests/elementwise_op_aidl_union_tests.cpp
new file mode 100644
index 00000000..67ccfa59
--- /dev/null
+++ b/tests/elementwise_op_aidl_union_tests.cpp
@@ -0,0 +1,194 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+#define LOG_TAG "ElementWiseAidlUnionTest"
+
+#include <aidl/android/hardware/audio/effect/DynamicsProcessing.h>
+#include <gtest/gtest.h>
+#include <log/log.h>
+#include <system/elementwise_op.h>
+
+using ::aidl::android::hardware::audio::effect::DynamicsProcessing;
+using ::android::audio_utils::elementwise_clamp;
+using ::android::audio_utils::elementwise_max;
+using ::android::audio_utils::elementwise_min;
+
+static DynamicsProcessing dynamicsProcessing(int v = 0) {
+  const DynamicsProcessing::EngineArchitecture engine{
+      .preferredProcessingDurationMs = static_cast<float>(v),
+      .preEqStage = DynamicsProcessing::StageEnablement{.bandCount = v},
+      .postEqStage = DynamicsProcessing::StageEnablement{.bandCount = v},
+      .mbcStage = DynamicsProcessing::StageEnablement{.bandCount = v},
+  };
+
+  return DynamicsProcessing::make<DynamicsProcessing::engineArchitecture>(engine);
+}
+
+static DynamicsProcessing dynamicsProcessing(int v1, int v2) {
+  const DynamicsProcessing::EngineArchitecture engine{
+      .preferredProcessingDurationMs = static_cast<float>(v1),
+      .preEqStage = DynamicsProcessing::StageEnablement{.bandCount = v2},
+      .postEqStage = DynamicsProcessing::StageEnablement{.bandCount = v1},
+      .mbcStage = DynamicsProcessing::StageEnablement{.bandCount = v2},
+  };
+
+  return DynamicsProcessing::make<DynamicsProcessing::engineArchitecture>(engine);
+}
+
+static const DynamicsProcessing kDpDifferentTag;
+
+class ElementWiseAidlUnionTest : public ::testing::TestWithParam<int> {
+ public:
+  ElementWiseAidlUnionTest() : value(GetParam()) {}
+
+ protected:
+  const int value;
+};
+
+// min/max/clamp op on same AIDL unions should get same value as result
+TEST_P(ElementWiseAidlUnionTest, aidl_union_op_self) {
+  const DynamicsProcessing dp = dynamicsProcessing(value);
+  auto min = elementwise_min(dp, dp);
+  ASSERT_NE(std::nullopt, min);
+  EXPECT_EQ(dp, min.value());
+  auto max = elementwise_max(dp, dp);
+  ASSERT_NE(std::nullopt, max);
+  EXPECT_EQ(dp, max.value());
+  auto clamp = elementwise_clamp(dp, dp, dp);
+  ASSERT_NE(std::nullopt, clamp);
+  EXPECT_EQ(dp, clamp.value());
+}
+
+// min/max/clamp op on AIDL unions with ascending order
+TEST_P(ElementWiseAidlUnionTest, aidl_union_op_ascending) {
+  const DynamicsProcessing dp1 = dynamicsProcessing(value);
+  const DynamicsProcessing dp2 = dynamicsProcessing(value + 1);
+  const DynamicsProcessing dp3 = dynamicsProcessing(value + 2);
+  auto min = elementwise_min(dp1, dp2);
+  ASSERT_NE(std::nullopt, min);
+  EXPECT_EQ(dp1, min.value());
+
+  auto max = elementwise_max(dp1, dp2);
+  ASSERT_NE(std::nullopt, max);
+  EXPECT_EQ(dp2, max.value());
+
+  auto clamped = elementwise_clamp(dp1, dp1, dp3);
+  ASSERT_NE(std::nullopt, clamped);
+  EXPECT_EQ(dp1, clamped.value());
+
+  clamped = elementwise_clamp(dp2, dp1, dp3);
+  ASSERT_NE(std::nullopt, clamped);
+  EXPECT_EQ(dp2, clamped.value());
+
+  clamped = elementwise_clamp(dp3, dp1, dp3);
+  ASSERT_NE(std::nullopt, clamped);
+  EXPECT_EQ(dp3, clamped.value());
+
+  clamped = elementwise_clamp(dp1, dp2, dp3);
+  ASSERT_NE(std::nullopt, clamped);
+  EXPECT_EQ(dp2, clamped.value());
+}
+
+// min/max/clamp op on AIDL unions with descending order
+TEST_P(ElementWiseAidlUnionTest, aidl_union_op_descending) {
+  const DynamicsProcessing dp1 = dynamicsProcessing(value);
+  const DynamicsProcessing dp2 = dynamicsProcessing(value + 1);
+  const DynamicsProcessing dp3 = dynamicsProcessing(value + 2);
+  auto min = elementwise_min(dp2, dp1);
+  ASSERT_NE(std::nullopt, min);
+  EXPECT_EQ(dp1, min.value());
+
+  auto max = elementwise_max(dp2, dp1);
+  ASSERT_NE(std::nullopt, max);
+  EXPECT_EQ(dp2, max.value());
+
+  auto clamped = elementwise_clamp(dp3, dp2, dp1);
+  ASSERT_EQ(std::nullopt, clamped);
+
+  clamped = elementwise_clamp(dp1, dp3, dp1);
+  ASSERT_EQ(std::nullopt, clamped);
+
+  clamped = elementwise_clamp(dp2, dp3, dp1);
+  ASSERT_EQ(std::nullopt, clamped);
+
+  clamped = elementwise_clamp(dp3, dp3, dp1);
+  ASSERT_EQ(std::nullopt, clamped);
+
+  clamped = elementwise_clamp(dp1, dp3, dp2);
+  ASSERT_EQ(std::nullopt, clamped);
+}
+
+constexpr int kTestParamValues[] = {0, 1, 10};
+
+INSTANTIATE_TEST_SUITE_P(AidlUtilsTest, ElementWiseAidlUnionTest,
+                         testing::ValuesIn(kTestParamValues));
+
+// expect `std::nullopt` when comparing two AIDL unions with different tags
+TEST(ElementWiseAidlUnionTest, aidl_union_op_mismatch_tag) {
+  const DynamicsProcessing dp = dynamicsProcessing();
+
+  EXPECT_EQ(std::nullopt, elementwise_min(dp, kDpDifferentTag));
+  EXPECT_EQ(std::nullopt, elementwise_min(kDpDifferentTag, dp));
+  EXPECT_EQ(std::nullopt, elementwise_max(dp, kDpDifferentTag));
+  EXPECT_EQ(std::nullopt, elementwise_max(kDpDifferentTag, dp));
+  EXPECT_EQ(std::nullopt, elementwise_clamp(dp, dp, kDpDifferentTag));
+  EXPECT_EQ(std::nullopt, elementwise_clamp(dp, kDpDifferentTag, dp));
+}
+
+// min/max op on AIDL unions with mixed parameter values
+TEST(ElementWiseAidlUnionTest, aidl_union_op_compare_mix) {
+  const auto dp12 = dynamicsProcessing(1, 2);
+  const auto dp21 = dynamicsProcessing(2, 1);
+  const auto dp34 = dynamicsProcessing(3, 4);
+  const auto dp43 = dynamicsProcessing(4, 3);
+
+  auto min = elementwise_min(dp12, dp21);
+  ASSERT_NE(std::nullopt, min);
+  EXPECT_EQ(dynamicsProcessing(1), min.value());
+  auto max = elementwise_max(dp12, dp21);
+  ASSERT_NE(std::nullopt, max);
+  EXPECT_EQ(dynamicsProcessing(2), max.value());
+
+  min = elementwise_min(dp34, dp43);
+  ASSERT_NE(std::nullopt, min);
+  EXPECT_EQ(dynamicsProcessing(3), min.value());
+  max = elementwise_max(dp34, dp43);
+  ASSERT_NE(std::nullopt, max);
+  EXPECT_EQ(dynamicsProcessing(4), max.value());
+}
+
+// clamp op on AIDL unions with mixed parameter values
+TEST(ElementWiseAidlUnionTest, aidl_union_op_clamp_mix) {
+  const auto dp3 = dynamicsProcessing(3);
+  const auto dp4 = dynamicsProcessing(4);
+  const auto dp34 = dynamicsProcessing(3, 4);
+  const auto dp43 = dynamicsProcessing(4, 3);
+  const auto dp33 = dynamicsProcessing(3, 3);
+  const auto dp44 = dynamicsProcessing(4, 4);
+
+  auto clamped = elementwise_clamp(dp34, dp3, dp4);
+  ASSERT_NE(std::nullopt, clamped);
+  EXPECT_EQ(dp34, clamped.value());
+  clamped = elementwise_clamp(dp43, dp33, dp44);
+  ASSERT_NE(std::nullopt, clamped);
+  EXPECT_EQ(dp43, clamped.value());
+  clamped = elementwise_clamp(dp34, dp3, dp3);
+  ASSERT_NE(std::nullopt, clamped);
+  EXPECT_EQ(dp3, clamped.value());
+  clamped = elementwise_clamp(dp43, dp4, dp4);
+  ASSERT_NE(std::nullopt, clamped);
+  EXPECT_EQ(dp4, clamped.value());
+}
\ No newline at end of file
diff --git a/tests/elementwise_op_basic_tests.cpp b/tests/elementwise_op_basic_tests.cpp
new file mode 100644
index 00000000..67be1c90
--- /dev/null
+++ b/tests/elementwise_op_basic_tests.cpp
@@ -0,0 +1,783 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+#include <string>
+
+#include <audio_utils/template_utils.h>
+#include <gtest/gtest.h>
+#include <log/log.h>
+#include <system/elementwise_op.h>
+
+using android::audio_utils::elementwise_clamp;
+using android::audio_utils::elementwise_max;
+using android::audio_utils::elementwise_min;
+using android::audio_utils::kMaxStructMember;
+using android::audio_utils::op_tuple_elements;
+
+enum class OpTestEnum { E1, E2, E3 };
+
+struct OpTestSSS {
+  double a;
+  bool b;
+};
+
+struct OpTestSS {
+  OpTestSSS sss;
+  int c;
+  std::vector<float> d;
+  OpTestEnum e;
+};
+
+struct OpTestS {
+  OpTestSS ss;
+  int f;
+  bool g;
+  std::string h;
+};
+
+std::ostream& operator<<(std::ostream& os, const OpTestEnum& e) {
+  switch (e) {
+    case OpTestEnum::E1: {
+      os << "E1";
+      break;
+    }
+    case OpTestEnum::E2: {
+      os << "E2";
+      break;
+    }
+    case OpTestEnum::E3: {
+      os << "E3";
+      break;
+    }
+  }
+  return os;
+}
+
+std::ostream& operator<<(std::ostream& os, const OpTestSSS& sss) {
+  os << "a: " << sss.a << ", b: " << sss.b;
+  return os;
+}
+
+std::ostream& operator<<(std::ostream& os, const OpTestSS& ss) {
+  os << ss.sss << ", c: " << ss.c << ", d: [";
+  for (const auto& itor : ss.d) {
+    os << itor << " ";
+  }
+  os << "], e: " << ss.e;
+  return os;
+}
+
+std::ostream& operator<<(std::ostream& os, const OpTestS& s) {
+  os << s.ss << ", f: " << s.f << ", g: " << s.g << ", h" << s.h;
+  return os;
+}
+
+constexpr bool operator==(const OpTestSSS& lhs, const OpTestSSS& rhs) {
+  return lhs.a == rhs.a && lhs.b == rhs.b;
+}
+
+constexpr bool operator==(const OpTestSS& lhs, const OpTestSS& rhs) {
+  return lhs.sss == rhs.sss && lhs.c == rhs.c && lhs.d == rhs.d &&
+         lhs.e == rhs.e;
+}
+
+constexpr bool operator==(const OpTestS& lhs, const OpTestS& rhs) {
+  return lhs.ss == rhs.ss && lhs.f == rhs.f && lhs.g == rhs.g && lhs.h == rhs.h;
+}
+
+const OpTestSSS sss1{.a = 1, .b = false};
+const OpTestSSS sss2{.a = sss1.a + 1, .b = true};
+const OpTestSSS sss3{.a = sss2.a + 1, .b = true};
+const OpTestSSS sss_mixed{.a = sss1.a - 1, .b = true};
+const OpTestSSS sss_clamped_1_3{.a = sss1.a, .b = true};
+const OpTestSSS sss_clamped_2_3{.a = sss2.a, .b = true};
+
+const OpTestSS ss1{.sss = sss1, .c = 1, .d = {1.f}, .e = OpTestEnum::E1};
+const OpTestSS ss2{
+    .sss = sss2, .c = ss1.c + 1, .d = {ss1.d[0] + 1}, .e = OpTestEnum::E2};
+const OpTestSS ss3{
+    .sss = sss3, .c = ss2.c + 1, .d = {ss2.d[0] + 1}, .e = OpTestEnum::E3};
+const OpTestSS ss_mixed{
+    .sss = sss_mixed, .c = ss1.c - 1, .d = {ss3.d[0] + 1}, .e = OpTestEnum::E3};
+const OpTestSS ss_clamped_1_3{
+    .sss = sss_clamped_1_3, .c = ss1.c, .d = {ss3.d[0]}, .e = OpTestEnum::E3};
+const OpTestSS ss_clamped_2_3{
+    .sss = sss_clamped_2_3, .c = ss2.c, .d = {ss3.d[0]}, .e = OpTestEnum::E3};
+
+const OpTestS s1{.ss = ss1, .f = 1, .g = false, .h = "s1"};
+const OpTestS s2{.ss = ss2, .f = s1.f + 1, .g = false, .h = "s2"};
+const OpTestS s3{.ss = ss3, .f = s2.f + 1, .g = true, .h = "s3"};
+const OpTestS s_mixed{.ss = ss_mixed, .f = s1.f - 1, .g = true, .h = "mixed"};
+const OpTestS s_clamped_1_3{
+    .ss = ss_clamped_1_3, .f = s1.f, .g = true, .h = "s1"};
+const OpTestS s_clamped_2_3{
+    .ss = ss_clamped_2_3, .f = s2.f, .g = true, .h = "s2"};
+
+// clamp a structure with range of min == max
+TEST(ClampOpTest, elementwise_clamp) {
+  std::optional<OpTestS> clamped;
+
+  clamped = elementwise_clamp(s2, s1, s3);
+  ASSERT_NE(clamped, std::nullopt);
+  EXPECT_EQ(*clamped, s2);
+
+  clamped = elementwise_clamp(s1, s2, s3);
+  ASSERT_NE(clamped, std::nullopt);
+  EXPECT_EQ(*clamped, s2);
+
+  clamped = elementwise_clamp(s3, s1, s2);
+  ASSERT_NE(clamped, std::nullopt);
+  EXPECT_EQ(*clamped, s2);
+}
+
+// clamp a structure with range of min == max
+TEST(ClampOpTest, clamp_same_min_max) {
+  std::optional<OpTestS> clamped;
+
+  clamped = elementwise_clamp(s1, s1, s1);
+  ASSERT_NE(clamped, std::nullopt);
+  EXPECT_EQ(*clamped, s1);
+
+  clamped = elementwise_clamp(s2, s1, s1);
+  ASSERT_NE(clamped, std::nullopt);
+  EXPECT_EQ(*clamped, s1);
+
+  clamped = elementwise_clamp(s3, s1, s1);
+  ASSERT_NE(clamped, std::nullopt);
+  EXPECT_EQ(*clamped, s1);
+
+  clamped = elementwise_clamp(s1, s2, s2);
+  ASSERT_NE(clamped, std::nullopt);
+  EXPECT_EQ(*clamped, s2);
+
+  clamped = elementwise_clamp(s2, s2, s2);
+  ASSERT_NE(clamped, std::nullopt);
+  EXPECT_EQ(*clamped, s2);
+
+  clamped = elementwise_clamp(s3, s2, s2);
+  ASSERT_NE(clamped, std::nullopt);
+  EXPECT_EQ(*clamped, s2);
+
+  clamped = elementwise_clamp(s1, s3, s3);
+  ASSERT_NE(clamped, std::nullopt);
+  EXPECT_EQ(*clamped, s3);
+
+  clamped = elementwise_clamp(s2, s3, s3);
+  ASSERT_NE(clamped, std::nullopt);
+  EXPECT_EQ(*clamped, s3);
+
+  clamped = elementwise_clamp(s3, s3, s3);
+  ASSERT_NE(clamped, std::nullopt);
+  EXPECT_EQ(*clamped, s3);
+}
+
+// clamp a structure with invalid range (min > max)
+TEST(ClampOpTest, clamp_invalid_range) {
+  EXPECT_EQ(std::nullopt, elementwise_clamp(s1, s2, s1));
+  EXPECT_EQ(std::nullopt, elementwise_clamp(s2, s3, s2));
+  EXPECT_EQ(std::nullopt, elementwise_clamp(s3, s3, s1));
+}
+
+// all members in p3 clamped to s2 but p3.ss.sss.a
+TEST(ClampOpTest, clamp_to_max_a) {
+  OpTestS p3 = s3;
+  std::optional<OpTestS> clamped;
+
+  p3.ss.sss.a = s1.ss.sss.a;
+  clamped = elementwise_clamp(p3, s1, s2);
+  ASSERT_NE(clamped, std::nullopt);
+  // ensure p3.ss.sss.a is not clamped
+  EXPECT_EQ(clamped->ss.sss.a, s1.ss.sss.a);
+  // ensure all other members correctly clamped to max
+  clamped->ss.sss.a = s2.ss.sss.a;
+  EXPECT_EQ(*clamped, s2);
+}
+
+// all members in p3 clamped to s2 but p3.ss.sss.b
+TEST(ClampOpTest, clamp_to_max_b) {
+  OpTestS p3 = s3;
+  std::optional<OpTestS> clamped;
+
+  p3.ss.sss.b = s1.ss.sss.b;
+  clamped = elementwise_clamp(p3, s1, s2);
+  ASSERT_NE(clamped, std::nullopt);
+  // ensure p3.ss.sss.b is not clamped
+  EXPECT_EQ(clamped->ss.sss.b, s1.ss.sss.b);
+  // ensure all other members correctly clamped to max
+  clamped->ss.sss.b = s2.ss.sss.b;
+  EXPECT_EQ(*clamped, s2);
+}
+
+// all members in p3 clamped to s2 but p3.ss.c
+TEST(ClampOpTest, clamp_to_max_c) {
+  OpTestS p3 = s3;
+  std::optional<OpTestS> clamped;
+
+  p3.ss.c = s1.ss.c;
+  clamped = elementwise_clamp(p3, s1, s2);
+  ASSERT_NE(clamped, std::nullopt);
+  EXPECT_EQ(p3.ss.c, s1.ss.c);
+  // ensure p3.ss.c is not clamped
+  EXPECT_EQ(clamped->ss.c, s1.ss.c);
+  // ensure all other members correctly clamped to max
+  clamped->ss.c = s2.ss.c;
+  EXPECT_EQ(*clamped, s2);
+}
+
+// all members in p3 clamped to s2 but p3.ss.d
+TEST(ClampOpTest, clamp_to_max_d) {
+  OpTestS p3 = s3;
+  std::optional<OpTestS> clamped;
+
+  p3.ss.d = s1.ss.d;
+  clamped = elementwise_clamp(p3, s1, s2);
+  ASSERT_NE(clamped, std::nullopt);
+  // ensure p3.ss.d is not clamped
+  EXPECT_EQ(clamped->ss.d, s1.ss.d);
+  // ensure all other members correctly clamped to max
+  clamped->ss.d = s2.ss.d;
+  EXPECT_EQ(*clamped, s2);
+}
+
+// all members in p3 clamped to s2 but p3.ss.e
+TEST(ClampOpTest, clamp_to_max_e) {
+  OpTestS p3 = s3;
+  std::optional<OpTestS> clamped;
+
+  p3.ss.e = s1.ss.e;
+  clamped = elementwise_clamp(p3, s1, s2);
+  ASSERT_NE(clamped, std::nullopt);
+  // ensure p3.ss.e is not clamped
+  EXPECT_EQ(clamped->ss.e, s1.ss.e);
+  // ensure all other members correctly clamped to max
+  clamped->ss.e = s2.ss.e;
+  EXPECT_EQ(*clamped, s2);
+}
+
+// all members in p3 clamped to s2 but p3.f
+TEST(ClampOpTest, clamp_to_max_f) {
+  OpTestS p3 = s3;
+  std::optional<OpTestS> clamped;
+
+  p3.f = s1.f;
+  clamped = elementwise_clamp(p3, s1, s2);
+  ASSERT_NE(clamped, std::nullopt);
+  // ensure p3.f is not clamped
+  EXPECT_EQ(clamped->f, s1.f);
+  // ensure all other members correctly clamped to max
+  clamped->f = s2.f;
+  EXPECT_EQ(*clamped, s2);
+}
+
+// all members in p3 clamped to s2 but p3.g
+TEST(ClampOpTest, clamp_to_max_g) {
+  OpTestS p3 = s3;
+  std::optional<OpTestS> clamped;
+
+  p3.g = s1.g;
+  clamped = elementwise_clamp(p3, s1, s2);
+  ASSERT_NE(clamped, std::nullopt);
+  // ensure p3.g is not clamped
+  EXPECT_EQ(clamped->g, s1.g);
+  // ensure all other members correctly clamped to max
+  clamped->g = s2.g;
+  EXPECT_EQ(*clamped, s2);
+}
+
+// all members in p3 clamped to s2 but p3.h
+TEST(ClampOpTest, clamp_to_max_h) {
+  OpTestS p3 = s3;
+  std::optional<OpTestS> clamped;
+
+  p3.h = s1.h;
+  clamped = elementwise_clamp(p3, s1, s2);
+  ASSERT_NE(clamped, std::nullopt);
+  // ensure p3.g is not clamped
+  EXPECT_EQ(clamped->h, s1.h);
+  // ensure all other members correctly clamped to max
+  clamped->h = s2.h;
+  EXPECT_EQ(*clamped, s2);
+}
+
+// all members in p1 clamped to s2 except p1.ss.sss.a
+TEST(ClampOpTest, clamp_to_min_a) {
+  OpTestS p1 = s1;
+  p1.ss.sss.a = s3.ss.sss.a;
+  std::optional<OpTestS> clamped = elementwise_clamp(p1, s2, s3);
+  ASSERT_NE(clamped, std::nullopt);
+  // ensure p1.ss.sss.a is not clamped
+  EXPECT_EQ(clamped->ss.sss.a, s3.ss.sss.a);
+  // ensure all other members correctly clamped to max
+  clamped->ss.sss.a = s2.ss.sss.a;
+  EXPECT_EQ(*clamped, s2);
+}
+
+// all members in p1 clamped to s2 but p1.ss.sss.b
+TEST(ClampOpTest, clamp_to_min_b) {
+  OpTestS p1 = s1;
+  p1.ss.sss.b = s3.ss.sss.b;
+  std::optional<OpTestS> clamped = elementwise_clamp(p1, s2, s3);
+  ASSERT_NE(clamped, std::nullopt);
+  // ensure p1.ss.sss.b is not clamped
+  EXPECT_EQ(clamped->ss.sss.b, s3.ss.sss.b);
+  // ensure all other members correctly clamped to max
+  clamped->ss.sss.b = s2.ss.sss.b;
+  EXPECT_EQ(*clamped, s2);
+}
+
+TEST(ClampOpTest, clamp_to_min_c) {
+  OpTestS p1 = s1;
+  p1.ss.c = s3.ss.c;
+  std::optional<OpTestS> clamped = elementwise_clamp(p1, s2, s3);
+  ASSERT_NE(clamped, std::nullopt);
+  EXPECT_EQ(p1.ss.c, s3.ss.c);
+  // ensure p1.ss.c is not clamped
+  EXPECT_EQ(clamped->ss.c, s3.ss.c);
+  // ensure all other members correctly clamped to max
+  clamped->ss.c = s2.ss.c;
+  EXPECT_EQ(*clamped, s2);
+}
+
+TEST(ClampOpTest, clamp_to_min_d) {
+  OpTestS p1 = s1;
+  p1.ss.d = s3.ss.d;
+  std::optional<OpTestS> clamped = elementwise_clamp(p1, s2, s3);
+  ASSERT_NE(clamped, std::nullopt);
+  // ensure p1.ss.d is not clamped
+  EXPECT_EQ(clamped->ss.d, s3.ss.d);
+  // ensure all other members correctly clamped to max
+  clamped->ss.d = s2.ss.d;
+  EXPECT_EQ(*clamped, s2);
+}
+
+TEST(ClampOpTest, clamp_to_min_e) {
+  OpTestS p1 = s1;
+  p1.ss.e = s3.ss.e;
+  std::optional<OpTestS> clamped = elementwise_clamp(p1, s2, s3);
+  ASSERT_NE(clamped, std::nullopt);
+  // ensure p1.ss.e is not clamped
+  EXPECT_EQ(clamped->ss.e, s3.ss.e);
+  // ensure all other members correctly clamped to max
+  clamped->ss.e = s2.ss.e;
+  EXPECT_EQ(*clamped, s2);
+}
+
+TEST(ClampOpTest, clamp_to_min_f) {
+  OpTestS p1 = s1;
+  p1.f = s3.f;
+  std::optional<OpTestS> clamped = elementwise_clamp(p1, s2, s3);
+  ASSERT_NE(clamped, std::nullopt);
+  // ensure p1.f is not clamped
+  EXPECT_EQ(clamped->f, s3.f);
+  // ensure all other members correctly clamped to max
+  clamped->f = s2.f;
+  EXPECT_EQ(*clamped, s2);
+}
+
+TEST(ClampOpTest, clamp_to_min_g) {
+  OpTestS p1 = s1;
+  p1.g = s3.g;
+  std::optional<OpTestS> clamped = elementwise_clamp(p1, s2, s3);
+  ASSERT_NE(clamped, std::nullopt);
+  // ensure p1.g is not clamped
+  EXPECT_EQ(clamped->g, s3.g);
+  // ensure all other members correctly clamped to max
+  clamped->g = s2.g;
+  EXPECT_EQ(*clamped, s2);
+}
+
+TEST(ClampOpTest, clamp_to_min_h) {
+  OpTestS p1 = s1;
+  p1.h = s3.h;
+  std::optional<OpTestS> clamped = elementwise_clamp(p1, s2, s3);
+  ASSERT_NE(clamped, std::nullopt);
+  // ensure p1.g is not clamped
+  EXPECT_EQ(clamped->h, s3.h);
+  // ensure all other members correctly clamped to max
+  clamped->h = s2.h;
+  EXPECT_EQ(*clamped, s2);
+}
+
+// test vector clamp with same size target and min/max
+TEST(ClampOpTest, clamp_vector_same_size) {
+  std::optional<OpTestS> clamped;
+  OpTestS target = s2, min = s1, max = s3;
+
+  min.ss.d = {1, 11, 21};
+  max.ss.d = {10, 20, 30};
+  target.ss.d = {0, 30, 21};
+  std::vector<float> expect = {1, 20, 21};
+  clamped = elementwise_clamp(target, min, max);
+  ASSERT_NE(clamped, std::nullopt);
+  EXPECT_EQ(clamped->ss.d, expect);
+
+  min.ss.d = {10, 11, 1};
+  max.ss.d = {10, 20, 30};
+  target.ss.d = {20, 20, 20};
+  expect = {10, 20, 20};
+  clamped = elementwise_clamp(target, min, max);
+  ASSERT_NE(clamped, std::nullopt);
+  EXPECT_EQ(clamped->ss.d, expect);
+
+  clamped = elementwise_clamp(target, min, min);
+  ASSERT_NE(clamped, std::nullopt);
+  EXPECT_EQ(*clamped, min);
+
+  clamped = elementwise_clamp(target, max, max);
+  ASSERT_NE(clamped, std::nullopt);
+  EXPECT_EQ(*clamped, max);
+}
+
+// test vector clamp with one element min and max
+TEST(ClampOpTest, clamp_vector_one_member_min_max) {
+  std::optional<OpTestS> clamped;
+  OpTestS target = s2, min = s1, max = s3;
+
+  min.ss.d = {10};
+  max.ss.d = {20};
+  target.ss.d = {0, 30, 20};
+  std::vector<float> expect = {10, 20, 20};
+
+  clamped = elementwise_clamp(target, min, max);
+  ASSERT_NE(clamped, std::nullopt);
+  EXPECT_EQ(clamped->ss.d, expect);
+}
+
+TEST(ClampOpTest, clamp_vector_one_min) {
+  std::optional<OpTestS> clamped;
+  OpTestS target = s2, min = s1, max = s3;
+
+  min.ss.d = {0};
+  max.ss.d = {20, 10, 30};
+  target.ss.d = {-1, 30, 20};
+  std::vector<float> expect = {0, 10, 20};
+
+  clamped = elementwise_clamp(target, min, max);
+  ASSERT_NE(clamped, std::nullopt);
+  EXPECT_EQ(clamped->ss.d, expect);
+}
+
+TEST(ClampOpTest, clamp_vector_one_max) {
+  std::optional<OpTestS> clamped;
+  OpTestS target = s2, min = s1, max = s3;
+
+  min.ss.d = {0, 10, 20};
+  max.ss.d = {20};
+  target.ss.d = {-1, 30, 20};
+  std::vector<float> expect = {0, 20, 20};
+
+  clamped = elementwise_clamp(target, min, max);
+  ASSERT_NE(clamped, std::nullopt);
+  EXPECT_EQ(clamped->ss.d, expect);
+}
+
+TEST(ClampOpTest, clamp_vector_invalid_range) {
+  std::optional<OpTestS> clamped;
+  OpTestS target = s2, min = s1, max = s3;
+
+  target.ss.d = {-1, 30, 20};
+  std::vector<float> expect = {0, 20, 20};
+
+  min.ss.d = {0, 10};
+  max.ss.d = {20};
+  clamped = elementwise_clamp(target, min, max);
+  EXPECT_EQ(clamped, std::nullopt);
+
+  min.ss.d = {0, 10, 20};
+  max.ss.d = {};
+  clamped = elementwise_clamp(target, min, max);
+  EXPECT_EQ(clamped, std::nullopt);
+
+  min.ss.d = {};
+  max.ss.d = {0, 10, 20};
+  clamped = elementwise_clamp(target, min, max);
+  EXPECT_EQ(clamped, std::nullopt);
+
+  min.ss.d = {0, 10, 20};
+  max.ss.d = {0, 10, 10};
+  clamped = elementwise_clamp(target, min, max);
+  EXPECT_EQ(clamped, std::nullopt);
+
+  min.ss.d = {0, 10, 5, 10};
+  max.ss.d = {0, 10, 10};
+  clamped = elementwise_clamp(target, min, max);
+  EXPECT_EQ(clamped, std::nullopt);
+
+  min.ss.d = {};
+  max.ss.d = {};
+  target.ss.d = {};
+  clamped = elementwise_clamp(target, min, max);
+  EXPECT_EQ(clamped, std::nullopt);
+}
+
+TEST(ClampOpTest, clamp_string) {
+  std::optional<OpTestS> clamped;
+  OpTestS target = s2, min = s1, max = s3;
+
+  min.h = "";
+  max.h = "";
+  target.h = "";
+  clamped = elementwise_clamp(target, min, max);
+  EXPECT_EQ(*clamped, target);
+
+  min.h = "apple";
+  max.h = "pear";
+  target.h = "orange";
+  clamped = elementwise_clamp(target, min, max);
+  ASSERT_NE(clamped, std::nullopt);
+  EXPECT_EQ(clamped->h, std::clamp(target.h, min.h, max.h));
+  EXPECT_EQ(*clamped, target);
+
+  target.h = "aardvark";
+  clamped = elementwise_clamp(target, min, max);
+  ASSERT_NE(clamped, std::nullopt);
+  EXPECT_EQ(clamped->h, std::clamp(target.h, min.h, max.h));
+  target.h = clamped->h;
+  EXPECT_EQ(*clamped, target);
+
+  target.h = "zebra";
+  clamped = elementwise_clamp(target, min, max);
+  ASSERT_NE(clamped, std::nullopt);
+  EXPECT_EQ(clamped->h, std::clamp(target.h, min.h, max.h));
+  target.h = clamped->h;
+  EXPECT_EQ(*clamped, target);
+}
+
+// clamp a mixed structure in range
+TEST(ClampOpTest, clamp_mixed) {
+  std::optional<OpTestS> clamped;
+
+  clamped = elementwise_clamp(s_mixed, s1, s3);
+  ASSERT_NE(clamped, std::nullopt);
+  EXPECT_EQ(*clamped, s_clamped_1_3);
+
+  clamped = elementwise_clamp(s_mixed, s2, s3);
+  ASSERT_NE(clamped, std::nullopt);
+  EXPECT_EQ(*clamped, s_clamped_2_3);
+}
+
+// clamp a mixed structure in range
+TEST(ClampOpTest, clamp_primitive_type) {
+  std::optional<OpTestS> clamped;
+
+  clamped = elementwise_clamp(s_mixed, s1, s3);
+  ASSERT_NE(clamped, std::nullopt);
+  EXPECT_EQ(*clamped, s_clamped_1_3);
+
+  clamped = elementwise_clamp(s_mixed, s2, s3);
+  ASSERT_NE(clamped, std::nullopt);
+  EXPECT_EQ(*clamped, s_clamped_2_3);
+}
+
+// Template function to return an array of size N
+template <size_t N>
+auto getArrayN() {
+  return std::array<int, N>{};
+}
+
+// Recursive function to make a tuple of arrays up to size N
+template <std::size_t N>
+auto makeTupleOfArrays() {
+  if constexpr (N == 1) {
+    return std::make_tuple(getArrayN<1>());
+  } else {
+    return std::tuple_cat(makeTupleOfArrays<N - 1>(),
+                          std::make_tuple(getArrayN<N>()));
+  }
+}
+
+// test the clamp utility can handle structures with up to
+// `android::audio_utils::kMaxStructMember` members
+TEST(ClampOpTest, clamp_different_struct_members) {
+  auto clampVerifyOp = [](auto&& arr) {
+    auto m1(arr), m2(arr), m3(arr);
+    m1.fill(1);
+    m2.fill(2);
+    m3.fill(3);
+
+    auto clamped = elementwise_clamp(m2, m1, m3);
+    ASSERT_NE(clamped, std::nullopt);
+    EXPECT_EQ(*clamped, m2);
+
+    clamped = elementwise_clamp(m1, m2, m3);
+    ASSERT_NE(clamped, std::nullopt);
+    EXPECT_EQ(*clamped, m2);
+
+    clamped = elementwise_clamp(m3, m1, m2);
+    ASSERT_NE(clamped, std::nullopt);
+    EXPECT_EQ(*clamped, m2);
+
+    // invalid range
+    EXPECT_EQ(elementwise_clamp(m3, m2, m1), std::nullopt);
+    EXPECT_EQ(elementwise_clamp(m3, m3, m1), std::nullopt);
+    EXPECT_EQ(elementwise_clamp(m3, m3, m2), std::nullopt);
+  };
+
+  auto arrays = makeTupleOfArrays<kMaxStructMember>();
+  for (size_t i = 0; i < kMaxStructMember; i++) {
+    op_tuple_elements(arrays, i, clampVerifyOp);
+  }
+}
+
+template <typename T>
+void MinMaxOpTestHelper(const T& a, const T& b, const T& expectedLower,
+                        const T& expectedUpper,
+                        const std::optional<T>& unexpected = std::nullopt) {
+  // lower
+  auto result = elementwise_min(a, b);
+  ASSERT_NE(unexpected, *result);
+  EXPECT_EQ(expectedLower, *result);
+
+  result = elementwise_min(b, a);
+  ASSERT_NE(unexpected, *result);
+  EXPECT_EQ(expectedLower, *result);
+
+  result = elementwise_min(a, a);
+  EXPECT_EQ(a, elementwise_min(a, a));
+  EXPECT_EQ(b, elementwise_min(b, b));
+
+  // upper
+  result = elementwise_max(a, b);
+  ASSERT_NE(unexpected, result);
+  EXPECT_EQ(expectedUpper, *result);
+
+  result = elementwise_max(b, a);
+  ASSERT_NE(unexpected, result);
+  EXPECT_EQ(expectedUpper, *result);
+
+  EXPECT_EQ(a, elementwise_max(a, a));
+  EXPECT_EQ(b, elementwise_max(b, b));
+}
+
+TEST(MinMaxOpTest, primitive_type_int) {
+  EXPECT_NO_FATAL_FAILURE(MinMaxOpTestHelper(1, 2, 1, 2));
+}
+
+TEST(MinMaxOpTest, primitive_type_float) {
+  EXPECT_NO_FATAL_FAILURE(MinMaxOpTestHelper(.1f, .2f, .1f, .2f));
+}
+
+TEST(MinMaxOpTest, primitive_type_string) {
+  std::string a = "ab", b = "ba";
+  EXPECT_NO_FATAL_FAILURE(
+      MinMaxOpTestHelper(a, b, std::min(a, b), std::max(a, b)));
+  a = "", b = "0";
+  EXPECT_NO_FATAL_FAILURE(
+      MinMaxOpTestHelper(a, b, std::min(a, b), std::max(a, b)));
+  a = "abc", b = "1234";
+  EXPECT_NO_FATAL_FAILURE(
+      MinMaxOpTestHelper(a, b, std::min(a, b), std::max(a, b)));
+}
+
+TEST(MinMaxOpTest, primitive_type_enum) {
+  EXPECT_NO_FATAL_FAILURE(MinMaxOpTestHelper(OpTestEnum::E1, OpTestEnum::E2,
+                                             OpTestEnum::E1, OpTestEnum::E2));
+  EXPECT_NO_FATAL_FAILURE(MinMaxOpTestHelper(OpTestEnum::E3, OpTestEnum::E2,
+                                             OpTestEnum::E2, OpTestEnum::E3));
+}
+
+TEST(MinMaxOpTest, vector_same_size) {
+  std::vector<int> v1, v2, expected_lower, expected_upper;
+  EXPECT_NO_FATAL_FAILURE(
+      MinMaxOpTestHelper(v1, v2, expected_lower, expected_upper));
+
+  v1 = {1}, v2 = {2}, expected_lower = {1}, expected_upper = {2};
+  EXPECT_NO_FATAL_FAILURE(
+      MinMaxOpTestHelper(v1, v2, expected_lower, expected_upper));
+
+  v1 = {3, 2, 3}, v2 = {2, 2, 2}, expected_lower = v2, expected_upper = v1;
+  EXPECT_NO_FATAL_FAILURE(
+      MinMaxOpTestHelper(v1, v2, expected_lower, expected_upper));
+
+  v1 = {3, 2, 3}, v2 = {1, 4, 1}, expected_lower = {1, 2, 1},
+  expected_upper = {3, 4, 3};
+  EXPECT_NO_FATAL_FAILURE(
+      MinMaxOpTestHelper(v1, v2, expected_lower, expected_upper));
+}
+
+TEST(MinMaxOpTest, vector_different_size_valid) {
+  std::vector<int> v1, v2({1}), expected_lower, expected_upper({1});
+  EXPECT_NO_FATAL_FAILURE(
+      MinMaxOpTestHelper(v1, v2, expected_lower, expected_upper));
+
+  v1 = {1, 2, 3, 1, 0, 5}, v2 = {2}, expected_lower = {1, 2, 2, 1, 0, 2},
+  expected_upper = {2, 2, 3, 2, 2, 5};
+  EXPECT_NO_FATAL_FAILURE(
+      MinMaxOpTestHelper(v1, v2, expected_lower, expected_upper));
+}
+
+// invalid vector size combination, expect std::nullopt
+TEST(MinMaxOpTest, invalid_vector_size) {
+  std::vector<int> v1 = {3, 2}, v2 = {2, 2, 2};
+  EXPECT_EQ(std::nullopt, elementwise_min(v1, v2));
+  EXPECT_EQ(std::nullopt, elementwise_min(v2, v1));
+  EXPECT_EQ(std::nullopt, elementwise_max(v1, v2));
+  EXPECT_EQ(std::nullopt, elementwise_max(v2, v1));
+}
+
+TEST(MinMaxOpTest, aggregate_type) {
+  EXPECT_NO_FATAL_FAILURE(MinMaxOpTestHelper(sss1, sss2, sss1, sss2));
+  EXPECT_NO_FATAL_FAILURE(MinMaxOpTestHelper(sss2, sss3, sss2, sss3));
+  EXPECT_NO_FATAL_FAILURE(MinMaxOpTestHelper(sss1, sss3, sss1, sss3));
+
+  EXPECT_NO_FATAL_FAILURE(MinMaxOpTestHelper(ss1, ss2, ss1, ss2));
+  EXPECT_NO_FATAL_FAILURE(MinMaxOpTestHelper(ss2, ss3, ss2, ss3));
+  EXPECT_NO_FATAL_FAILURE(MinMaxOpTestHelper(ss1, ss3, ss1, ss3));
+
+  EXPECT_NO_FATAL_FAILURE(MinMaxOpTestHelper(s1, s2, s1, s2));
+  EXPECT_NO_FATAL_FAILURE(MinMaxOpTestHelper(s2, s3, s2, s3));
+  EXPECT_NO_FATAL_FAILURE(MinMaxOpTestHelper(s1, s3, s1, s3));
+}
+
+// invalid vector size combination in nested structure
+TEST(MinMaxOpTest, invalid_vector_in_structure) {
+  auto tt1 = ss1, tt2 = ss2;
+  tt1.d = {.1f, .2f, .3f};
+  tt2.d = {.1f, .2f, .3f, .4f, .5f};
+
+  EXPECT_EQ(std::nullopt, elementwise_min(tt1, tt2));
+  EXPECT_EQ(std::nullopt, elementwise_min(tt2, tt1));
+  EXPECT_EQ(std::nullopt, elementwise_max(tt1, tt2));
+  EXPECT_EQ(std::nullopt, elementwise_max(tt2, tt1));
+
+  auto t1 = s1, t2 = s2;
+  t1.ss = tt1, t2.ss = tt2;
+  EXPECT_EQ(std::nullopt, elementwise_min(t1, t2));
+  EXPECT_EQ(std::nullopt, elementwise_min(t2, t1));
+  EXPECT_EQ(std::nullopt, elementwise_max(t1, t2));
+  EXPECT_EQ(std::nullopt, elementwise_max(t2, t1));
+}
+
+TEST(MinMaxOpTest, aggregate_different_members) {
+  auto boundaryVerifyOp = [](auto&& arr) {
+    auto m1(arr), m2(arr);
+    m1.fill(1);
+    m2.fill(2);
+
+    auto lower = elementwise_min(m1, m2);
+    ASSERT_NE(lower, std::nullopt);
+    EXPECT_EQ(*lower, m1);
+
+    auto upper = elementwise_max(m1, m2);
+    ASSERT_NE(upper, std::nullopt);
+    EXPECT_EQ(*upper, m2);
+  };
+
+  auto arrays = makeTupleOfArrays<kMaxStructMember>();
+  for (size_t i = 0; i < kMaxStructMember; i++) {
+    op_tuple_elements(arrays, i, boundaryVerifyOp);
+  }
+}
\ No newline at end of file
diff --git a/tests/systemaudio_tests.cpp b/tests/systemaudio_tests.cpp
index ae66c32e..c6169045 100644
--- a/tests/systemaudio_tests.cpp
+++ b/tests/systemaudio_tests.cpp
@@ -368,7 +368,7 @@ protected:
         case AUDIO_PORT_TYPE_DEVICE:
             port->ext.device.hw_module = mHwModule;
             port->ext.device.type = port->role == AUDIO_PORT_ROLE_SINK ? mOutputDeviceType
-                                                                       : mInputDeviceType;
+                                        : mInputDeviceType;
             strncpy(port->ext.device.address, mAddress.c_str(), AUDIO_DEVICE_MAX_ADDRESS_LEN);
 #ifndef AUDIO_NO_SYSTEM_DECLARATIONS
             port->ext.device.encapsulation_modes = AUDIO_ENCAPSULATION_MODE_ELEMENTARY_STREAM;
@@ -501,12 +501,15 @@ void SystemAudioPortTest::fillFakeAudioPortConfigInfo(struct audio_port_config*
     } else {
         config->flags.output = mOutputFlag;
     }
+    const bool outputDevice = config->role == AUDIO_PORT_ROLE_SINK;
     switch (config->type) {
     case AUDIO_PORT_TYPE_DEVICE:
         config->ext.device.hw_module = mHwModule;
         config->ext.device.type =
-                config->role == AUDIO_PORT_ROLE_SINK ? mOutputDeviceType : mInputDeviceType;
+            outputDevice ? mOutputDeviceType : mInputDeviceType;
         strncpy(config->ext.device.address, mAddress.c_str(), AUDIO_DEVICE_MAX_ADDRESS_LEN);
+        config->ext.device.speaker_layout_channel_mask =
+            outputDevice ? AUDIO_CHANNEL_OUT_5POINT1 : AUDIO_CHANNEL_NONE;
         break;
     case AUDIO_PORT_TYPE_MIX:
         config->ext.mix.hw_module = mHwModule;
@@ -697,6 +700,13 @@ TEST_P(SystemAudioPortTest, AudioPortConfigEquivalentTest) {
             ASSERT_TRUE(audio_port_configs_are_equal(&lhs, &rhs));
         }
     }
+    if (lhs.type == AUDIO_PORT_TYPE_DEVICE) {
+      lhs.ext.device.speaker_layout_channel_mask = AUDIO_CHANNEL_OUT_MONO;
+      ASSERT_FALSE(audio_port_configs_are_equal(&lhs, &rhs));
+      lhs.ext.device.speaker_layout_channel_mask =
+          rhs.ext.device.speaker_layout_channel_mask;
+      ASSERT_TRUE(audio_port_configs_are_equal(&lhs, &rhs));
+    }
 }
 
 TEST_P(SystemAudioPortTest, AudioPortEquivalentTest) {
```

