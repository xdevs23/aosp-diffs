```diff
diff --git a/audio/include/system/audio.h b/audio/include/system/audio.h
index 93664fe2..f6f8b8ba 100644
--- a/audio/include/system/audio.h
+++ b/audio/include/system/audio.h
@@ -2490,5 +2490,41 @@ __END_DECLS
 #define AUDIO_OFFLOAD_CODEC_DELAY_SAMPLES  "delay_samples"
 #define AUDIO_OFFLOAD_CODEC_PADDING_SAMPLES  "padding_samples"
 
+/**
+ * The maximum supported audio sample rate.
+ *
+ * note: The audio policy will use it as the max mixer sample rate for mixed
+ * output and inputs.
+ */
+#define SAMPLE_RATE_HZ_MAX 192000
+
+/**
+ * The minimum supported audio sample rate.
+ */
+#define SAMPLE_RATE_HZ_MIN 4000
+
+/**
+ * The maximum possible audio sample rate as defined in IEC61937.
+ * This definition is for a pre-check before asking the lower level service to
+ * open an AAudio stream.
+ *
+ * note: HDMI supports up to 32 channels at 1536000 Hz.
+ * note: This definition serve the purpose of parameter pre-check, real
+ * validation happens in the audio policy.
+ */
+#define SAMPLE_RATE_HZ_MAX_IEC610937 1600000
+
+/**
+ * The minimum audio sample rate supported by AAudio stream.
+ * This definition is for a pre-check before asking the lower level service to
+ * open an AAudio stream.
+ */
+#define SAMPLE_RATE_HZ_MIN_AAUDIO 8000
+
+/**
+ * Minimum/maximum channel count supported by AAudio stream.
+ */
+#define CHANNEL_COUNT_MIN_AAUDIO 1
+#define CHANNEL_COUNT_MAX_AAUDIO FCC_LIMIT
 
 #endif  // ANDROID_AUDIO_CORE_H
diff --git a/audio/include/system/audio_policy.h b/audio/include/system/audio_policy.h
index 51767777..c19de7ff 100644
--- a/audio/include/system/audio_policy.h
+++ b/audio/include/system/audio_policy.h
@@ -48,6 +48,7 @@ typedef enum {
     AUDIO_POLICY_FORCE_ENCODED_SURROUND_NEVER,
     AUDIO_POLICY_FORCE_ENCODED_SURROUND_ALWAYS,
     AUDIO_POLICY_FORCE_ENCODED_SURROUND_MANUAL,
+    AUDIO_POLICY_FORCE_BT_BLE,
 
     AUDIO_POLICY_FORCE_CFG_CNT,
     AUDIO_POLICY_FORCE_CFG_MAX = AUDIO_POLICY_FORCE_CFG_CNT - 1,
diff --git a/audio_route/audio_route.c b/audio_route/audio_route.c
index 189f1dd9..a28fa65e 100644
--- a/audio_route/audio_route.c
+++ b/audio_route/audio_route.c
@@ -95,6 +95,7 @@ struct config_parse_state {
     struct audio_route *ar;
     struct mixer_path *path;
     int level;
+    bool enum_mixer_numeric_fallback;
 };
 
 /* path functions */
@@ -445,8 +446,23 @@ static int path_reset(struct audio_route *ar, struct mixer_path *path)
     return 0;
 }
 
+static bool safe_strtol(const char *str, long *val)
+{
+    char *end;
+    long v;
+    if (str == NULL || strlen(str) == 0)
+        return false;
+    errno = 0;
+    v = strtol(str, &end, 0);
+    if (errno || *end)
+        return false;
+    *val = v;
+    return true;
+}
+
 /* mixer helper function */
-static int mixer_enum_string_to_value(struct mixer_ctl *ctl, const char *string)
+static int mixer_enum_string_to_value(struct mixer_ctl *ctl, const char *string,
+                                      bool allow_numeric_fallback)
 {
     unsigned int i;
     unsigned int num_values = mixer_ctl_get_num_enums(ctl);
@@ -463,6 +479,13 @@ static int mixer_enum_string_to_value(struct mixer_ctl *ctl, const char *string)
             break;
     }
     if (i == num_values) {
+        /* No enum string match. Check the flag before numeric parsing. */
+        if (allow_numeric_fallback) {
+            long value = 0;
+            if (safe_strtol(string, &value) && value >= 0 && value < num_values) {
+                return value;
+            }
+        }
         ALOGW("unknown enum value string %s for ctl %s",
               string, mixer_ctl_get_name(ctl));
         return 0;
@@ -476,6 +499,7 @@ static void start_tag(void *data, const XML_Char *tag_name,
     const XML_Char *attr_name = NULL;
     const XML_Char *attr_id = NULL;
     const XML_Char *attr_value = NULL;
+    const XML_Char *attr_enum_mixer_numeric_fallback = NULL;
     struct config_parse_state *state = data;
     struct audio_route *ar = state->ar;
     unsigned int i;
@@ -495,10 +519,16 @@ static void start_tag(void *data, const XML_Char *tag_name,
             attr_id = attr[i + 1];
         else if (strcmp(attr[i], "value") == 0)
             attr_value = attr[i + 1];
+        else if (strcmp(attr[i], "enum_mixer_numeric_fallback") == 0)
+            attr_enum_mixer_numeric_fallback = attr[i + 1];
     }
 
     /* Look at tags */
-    if (strcmp(tag_name, "path") == 0) {
+    if (strcmp(tag_name, "mixer") == 0) {
+        state->enum_mixer_numeric_fallback =
+                attr_enum_mixer_numeric_fallback != NULL &&
+                strcmp(attr_enum_mixer_numeric_fallback, "true") == 0 ;
+    } else if (strcmp(tag_name, "path") == 0) {
         if (attr_name == NULL) {
             ALOGE("Unnamed path!");
         } else {
@@ -571,7 +601,8 @@ static void start_tag(void *data, const XML_Char *tag_name,
                 ALOGE("No value specified for ctl %s", attr_name);
                 goto done;
             }
-            value = mixer_enum_string_to_value(ctl, (char *)attr_value);
+            value = mixer_enum_string_to_value(ctl, (char *)attr_value,
+                                               state->enum_mixer_numeric_fallback);
             break;
         default:
             value = 0;
diff --git a/audio_utils/Android.bp b/audio_utils/Android.bp
index de12cc30..9ffb966b 100644
--- a/audio_utils/Android.bp
+++ b/audio_utils/Android.bp
@@ -83,9 +83,6 @@ cc_library {
     ],
 
     whole_static_libs: [
-        // if libaudioutils is added as a static lib AND flags are used in the utils object,
-        // then add server_configurable_flags as a shared lib.
-        "com.android.media.audioserver-aconfig-cc",
         "libaudioutils_fastmath",
     ],
 
@@ -96,13 +93,23 @@ cc_library {
                 "echo_reference.c",
                 "resampler.c",
             ],
-            whole_static_libs: ["libaudioutils_fixedfft"],
+            whole_static_libs: [
+                "libaudioutils_fixedfft",
+                // if libaudioutils is added as a static lib AND flags are used in the utils object,
+                // then add server_configurable_flags as a shared lib.
+                "com.android.media.audioserver-aconfig-cc",
+            ],
             shared_libs: [
                 "libspeexresampler",
             ],
         },
         host: {
             cflags: ["-D__unused=__attribute__((unused))"],
+            whole_static_libs: [
+                // if libaudioutils is added as a static lib AND flags are used in the utils object,
+                // then add server_configurable_flags as a shared lib.
+                "com.android.media.audioserver-aconfig-cc-ro",
+            ],
         },
     },
     min_sdk_version: "29",
@@ -176,6 +183,7 @@ cc_library_static {
     name: "libsndfile",
     defaults: ["audio_utils_defaults"],
     host_supported: true,
+    vendor_available: true,
     srcs: [
         "primitives.c",
         "tinysndfile.c",
@@ -183,6 +191,12 @@ cc_library_static {
     cflags: [
         "-UHAVE_STDERR",
     ],
+    header_libs: [
+        "libaudio_system_headers",
+    ],
+    export_header_lib_headers: [
+        "libaudio_system_headers",
+    ],
 }
 
 cc_library_static {
diff --git a/audio_utils/include/audio_utils/DeferredExecutor.h b/audio_utils/include/audio_utils/DeferredExecutor.h
new file mode 100644
index 00000000..96a4135c
--- /dev/null
+++ b/audio_utils/include/audio_utils/DeferredExecutor.h
@@ -0,0 +1,147 @@
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
+
+#include <android-base/thread_annotations.h>
+#include <any>
+#include <functional>
+#include <mutex>
+#include <vector>
+
+namespace android::audio_utils {
+
+/**
+ * The DeferredExecutor class accumulates objects to dispose
+ * and functors to execute.
+ *
+ * The class is used in a worker thread loop to allow objects
+ * and functors to be accumulated under a mutex,
+ * where such object dtors or functors might cause
+ * deadlocks or order inversion issues when executed.
+ * The process() method is then called outside of the mutex
+ * to dispose any objects and execute any functors accumulated.
+ */
+
+class DeferredExecutor {
+public:
+
+    /**
+     * \param processInDtor if true calls process in the dtor.
+     *
+     * processInDtor defaults to false to prevent use after free.
+     */
+    explicit DeferredExecutor(bool processInDtor = false)
+        : mProcessInDtor(processInDtor)
+    {}
+
+    /**
+     * If processInDtor is set true in the ctor, then
+     * deferred functors are executed.  Then any
+     * deferred functors and garbage are deallocated.
+     */
+    ~DeferredExecutor() {
+        if (mProcessInDtor) process(true /* recursive */);
+    }
+
+    /**
+     * Delays destruction of an object to the
+     * invocation of process() (generally outside of lock).
+     *
+     * Example Usage:
+     *
+     * std::vector<std::vector<sp<IFoo>>> interfaces;
+     * ...
+     * executor.dispose(std::move(interfaces));
+     */
+    template<typename T>
+    void dispose(T&& object) {
+        std::lock_guard lg(mMutex);
+        mGarbage.emplace_back(std::forward<T>(object));
+    }
+
+    /**
+     * Defers execution of a functor to the invocation
+     * of process() (generally outside of lock).
+     *
+     * Example Usage:
+     *
+     * executor.defer([]{ foo(); });
+     */
+    template<typename F>
+    void defer(F&& functor) {
+        std::lock_guard lg(mMutex);
+        mDeferred.emplace_back(std::forward<F>(functor));
+    }
+
+    /**
+     * Runs deferred functors (in order of adding)
+     * and then dellocates the functors and empties the garbage
+     * (in reverse order of adding).
+     *
+     * \param recursive if set to true, will loop the process
+     *     to ensure no garbage or deferred objects remain.
+     */
+    void process(bool recursive = false) {
+        do {
+            // Note the declaration order of garbage and deferred.
+            std::vector <std::any> garbage;
+            std::vector <std::function<void()>> deferred;
+            {
+                std::lock_guard lg(mMutex);
+                if (mGarbage.empty() && mDeferred.empty()) return;
+                std::swap(garbage, mGarbage);
+                std::swap(deferred, mDeferred);
+            }
+            // execution in order of adding.
+            // destruction in reverse order of adding.
+            for (const auto& f: deferred) {
+                f();
+            }
+        } while (recursive);
+    }
+
+    /**
+     * Skips running any deferred functors and dellocates the functors
+     * and empties the garbage (in reverse order of adding).
+     */
+    void clear() {
+        // Note the declaration order of garbage and deferred.
+        std::vector<std::any> garbage;
+        std::vector<std::function<void()>> deferred;
+        {
+            std::lock_guard lg(mMutex);
+            std::swap(garbage, mGarbage);
+            std::swap(deferred, mDeferred);
+        }
+    }
+
+    /**
+     * Returns true if there is no garbage and no deferred methods.
+     */
+    bool empty() const {
+        std::lock_guard lg(mMutex);
+        return mGarbage.empty() && mDeferred.empty();
+    }
+
+private:
+    const bool mProcessInDtor;
+    mutable std::mutex mMutex;
+    std::vector<std::any> mGarbage GUARDED_BY(mMutex);
+    std::vector<std::function<void()>> mDeferred GUARDED_BY(mMutex);
+};
+
+}  // namespace android::audio_utils
diff --git a/audio_utils/include/audio_utils/linked_hash_map.h b/audio_utils/include/audio_utils/linked_hash_map.h
new file mode 100644
index 00000000..3ab4cc09
--- /dev/null
+++ b/audio_utils/include/audio_utils/linked_hash_map.h
@@ -0,0 +1,101 @@
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
+
+#include <list>
+#include <unordered_map>
+
+namespace android::audio_utils {
+
+/**
+ * linked_hash_map
+ *
+ * A hash map that iterates in order of oldest to newest inserted.
+ * See also Java LinkedHashMap.
+ *
+ * O(1) lookup, insertion, deletion, iteration (with std::unordered_map and std::list)
+ *
+ * This can be used to hold historical records indexed on a key,
+ * whose container size can be controlled by evicting the least recently used record.
+ *
+ * The class is not thread safe: Locking must occur at the caller.
+ *
+ * This is a basic implementation, many STL map methods are not implemented.
+ *
+ * @tparam K Key type
+ * @tparam V Value type
+ * @tparam M Map type (std::unordered_map or std::map)
+ * @tparam L List type should have fast and stable iterator
+ *           insertion and erasure.
+ */
+template<typename K, typename V,
+        template<typename, typename, typename...> class M = std::unordered_map,
+        template<typename, typename...> class L = std::list>
+class linked_hash_map {
+    using List = L<std::pair<K, V>>;
+
+    // if K is large, could use a map with a reference_wrapper<K>.
+    // or a set with an iterator_wrapper<List::iterator>.
+    using Map = M<K, typename List::iterator>;
+
+public:
+    // The iterator returned is the list iterator.
+    using iterator = List::iterator;
+
+    // Equivalent linked hash maps must contain the same elements
+    // inserted in the same order.
+    bool operator==(const linked_hash_map<K, V, M, L>& other) const {
+        return list_ == other.list_;
+    }
+
+    // The iterators returned are List::iterator.
+    auto find(const K& k) {
+        auto map_it = map_.find(k);
+        if (map_it == map_.end()) return list_.end();
+        return map_it->second;
+    }
+
+    auto erase(const List::iterator& it) {
+        if (it != list_.end()) {
+            map_.erase(it->first);
+            return list_.erase(it);
+        }
+        return it;
+    }
+
+    auto size() const { return list_.size(); }
+    auto begin() const { return list_.begin(); }
+    auto end() const { return list_.end(); }
+
+    auto begin() { return list_.begin(); }
+    auto end() { return list_.end(); }
+    template <typename KU>
+    auto& operator[](KU&& k) {
+        auto map_it = map_.find(k);
+        if (map_it != map_.end()) return map_it->second->second;
+        auto it = list_.insert(list_.end(),
+                std::make_pair(std::forward<KU>(k), V{})); // oldest to newest.
+        map_[it->first] = it;
+        return it->second;
+    }
+
+private:
+    Map map_;
+    List list_;  // oldest is first.
+};
+
+} // namespace android::audio_utils
diff --git a/audio_utils/include/audio_utils/mutex.h b/audio_utils/include/audio_utils/mutex.h
index f21248de..31bd0176 100644
--- a/audio_utils/include/audio_utils/mutex.h
+++ b/audio_utils/include/audio_utils/mutex.h
@@ -59,26 +59,27 @@ enum class MutexOrder : uint32_t {
     kAudioCommand_Mutex = 6,
     kUidPolicy_Mutex = 7,
     kAudioFlinger_Mutex = 8,
-    kAudioFlinger_HardwareMutex = 9,
-    kDeviceEffectManager_Mutex = 10,
-    kPatchCommandThread_Mutex = 11,
-    kThreadBase_Mutex = 12,
-    kAudioFlinger_ClientMutex = 13,
-    kMelReporter_Mutex = 14,
+    kDeviceEffectManager_Mutex = 9,
+    kDeviceEffectProxy_ProxyMutex = 10,
+    kDeviceEffectHandle_Mutex = 11,
+    kPatchCommandThread_Mutex = 12,
+    kThreadBase_Mutex = 13,
+    kAudioFlinger_ClientMutex = 14,
     kEffectChain_Mutex = 15,
-    kDeviceEffectProxy_ProxyMutex = 16,
-    kEffectBase_Mutex = 17,
-    kAudioFlinger_UnregisteredWritersMutex = 18,
-    kAsyncCallbackThread_Mutex = 19,
-    kConfigEvent_Mutex = 20,
-    kOutputTrack_TrackMetadataMutex = 21,
-    kPassthruPatchRecord_ReadMutex = 22,
-    kPatchCommandThread_ListenerMutex = 23,
-    kPlaybackThread_AudioTrackCbMutex = 24,
-    kAudioPolicyService_NotificationClientsMutex = 25,
-    kMediaLogNotifier_Mutex = 26,
-    kOtherMutex = 27,
-    kSize = 28,
+    kEffectBase_Mutex = 16,
+    kAudioFlinger_HardwareMutex = 17,
+    kMelReporter_Mutex = 18,
+    kAudioFlinger_UnregisteredWritersMutex = 19,
+    kAsyncCallbackThread_Mutex = 20,
+    kConfigEvent_Mutex = 21,
+    kOutputTrack_TrackMetadataMutex = 22,
+    kPassthruPatchRecord_ReadMutex = 23,
+    kPatchCommandThread_ListenerMutex = 24,
+    kPlaybackThread_AudioTrackCbMutex = 25,
+    kAudioPolicyService_NotificationClientsMutex = 26,
+    kMediaLogNotifier_Mutex = 27,
+    kOtherMutex = 28,
+    kSize = 29,
 };
 
 // Lock by name
@@ -92,15 +93,16 @@ inline constexpr const char* const gMutexNames[] = {
     "AudioCommand_Mutex",
     "UidPolicy_Mutex",
     "AudioFlinger_Mutex",
-    "AudioFlinger_HardwareMutex",
     "DeviceEffectManager_Mutex",
+    "DeviceEffectProxy_ProxyMutex",
+    "DeviceEffectHandle_Mutex",
     "PatchCommandThread_Mutex",
     "ThreadBase_Mutex",
     "AudioFlinger_ClientMutex",
-    "MelReporter_Mutex",
     "EffectChain_Mutex",
-    "DeviceEffectProxy_ProxyMutex",
     "EffectBase_Mutex",
+    "AudioFlinger_HardwareMutex",
+    "MelReporter_Mutex",
     "AudioFlinger_UnregisteredWritersMutex",
     "AsyncCallbackThread_Mutex",
     "ConfigEvent_Mutex",
@@ -137,26 +139,28 @@ inline mutex* UidPolicy_Mutex
         ACQUIRED_AFTER(android::audio_utils::AudioCommand_Mutex);
 inline mutex* AudioFlinger_Mutex
         ACQUIRED_AFTER(android::audio_utils::UidPolicy_Mutex);
-inline mutex* AudioFlinger_HardwareMutex
-        ACQUIRED_AFTER(android::audio_utils::AudioFlinger_Mutex);
 inline mutex* DeviceEffectManager_Mutex
-        ACQUIRED_AFTER(android::audio_utils::AudioFlinger_HardwareMutex);
-inline mutex* PatchCommandThread_Mutex
+        ACQUIRED_AFTER(android::audio_utils::AudioFlinger_Mutex);
+inline mutex* DeviceEffectProxy_ProxyMutex
         ACQUIRED_AFTER(android::audio_utils::DeviceEffectManager_Mutex);
+inline mutex* DeviceEffectHandle_Mutex
+        ACQUIRED_AFTER(android::audio_utils::DeviceEffectProxy_ProxyMutex);
+inline mutex* PatchCommandThread_Mutex
+        ACQUIRED_AFTER(android::audio_utils::DeviceEffectHandle_Mutex);
 inline mutex* ThreadBase_Mutex
         ACQUIRED_AFTER(android::audio_utils::PatchCommandThread_Mutex);
 inline mutex* AudioFlinger_ClientMutex
         ACQUIRED_AFTER(android::audio_utils::ThreadBase_Mutex);
-inline mutex* MelReporter_Mutex
-        ACQUIRED_AFTER(android::audio_utils::AudioFlinger_ClientMutex);
 inline mutex* EffectChain_Mutex
-        ACQUIRED_AFTER(android::audio_utils::MelReporter_Mutex);
-inline mutex* DeviceEffectProxy_ProxyMutex
-        ACQUIRED_AFTER(android::audio_utils::EffectChain_Mutex);
+        ACQUIRED_AFTER(android::audio_utils::AudioFlinger_ClientMutex);
 inline mutex* EffectBase_Mutex
-        ACQUIRED_AFTER(android::audio_utils::DeviceEffectProxy_ProxyMutex);
-inline mutex* AudioFlinger_UnregisteredWritersMutex
+        ACQUIRED_AFTER(android::audio_utils::EffectChain_Mutex);
+inline mutex* AudioFlinger_HardwareMutex
         ACQUIRED_AFTER(android::audio_utils::EffectBase_Mutex);
+inline mutex* MelReporter_Mutex
+        ACQUIRED_AFTER(android::audio_utils::AudioFlinger_HardwareMutex);
+inline mutex* AudioFlinger_UnregisteredWritersMutex
+        ACQUIRED_AFTER(android::audio_utils::MelReporter_Mutex);
 inline mutex* AsyncCallbackThread_Mutex
         ACQUIRED_AFTER(android::audio_utils::AudioFlinger_UnregisteredWritersMutex);
 inline mutex* ConfigEvent_Mutex
@@ -236,32 +240,32 @@ inline mutex* OtherMutex
     EXCLUDES(android::audio_utils::AudioFlinger_UnregisteredWritersMutex) \
     EXCLUDES_BELOW_AudioFlinger_UnregisteredWritersMutex
 
-#define EXCLUDES_BELOW_EffectBase_Mutex \
+#define EXCLUDES_BELOW_MelReporter_Mutex \
     EXCLUDES_AudioFlinger_UnregisteredWritersMutex
+#define EXCLUDES_MelReporter_Mutex \
+    EXCLUDES(android::audio_utils::MelReporter_Mutex) \
+    EXCLUDES_BELOW_MelReporter_Mutex
+
+#define EXCLUDES_BELOW_AudioFlinger_HardwareMutex \
+    EXCLUDES_MelReporter_Mutex
+#define EXCLUDES_AudioFlinger_HardwareMutex \
+    EXCLUDES(android::audio_utils::AudioFlinger_HardwareMutex) \
+    EXCLUDES_BELOW_AudioFlinger_HardwareMutex
+
+#define EXCLUDES_BELOW_EffectBase_Mutex \
+    EXCLUDES_AudioFlinger_HardwareMutex
 #define EXCLUDES_EffectBase_Mutex \
     EXCLUDES(android::audio_utils::EffectBase_Mutex) \
     EXCLUDES_BELOW_EffectBase_Mutex
 
-#define EXCLUDES_BELOW_DeviceEffectProxy_ProxyMutex \
-    EXCLUDES_EffectBase_Mutex
-#define EXCLUDES_DeviceEffectProxy_ProxyMutex \
-    EXCLUDES(android::audio_utils::DeviceEffectProxy_ProxyMutex) \
-    EXCLUDES_BELOW_DeviceEffectProxy_ProxyMutex
-
 #define EXCLUDES_BELOW_EffectChain_Mutex \
-    EXCLUDES_DeviceEffectProxy_ProxyMutex
+    EXCLUDES_EffectBase_Mutex
 #define EXCLUDES_EffectChain_Mutex \
     EXCLUDES(android::audio_utils::EffectChain_Mutex) \
     EXCLUDES_BELOW_EffectChain_Mutex
 
-#define EXCLUDES_BELOW_MelReporter_Mutex \
-    EXCLUDES_EffectChain_Mutex
-#define EXCLUDES_MelReporter_Mutex \
-    EXCLUDES(android::audio_utils::MelReporter_Mutex) \
-    EXCLUDES_BELOW_MelReporter_Mutex
-
 #define EXCLUDES_BELOW_AudioFlinger_ClientMutex \
-    EXCLUDES_MelReporter_Mutex
+    EXCLUDES_EffectChain_Mutex
 #define EXCLUDES_AudioFlinger_ClientMutex \
     EXCLUDES(android::audio_utils::AudioFlinger_ClientMutex) \
     EXCLUDES_BELOW_AudioFlinger_ClientMutex
@@ -278,20 +282,26 @@ inline mutex* OtherMutex
     EXCLUDES(android::audio_utils::PatchCommandThread_Mutex) \
     EXCLUDES_BELOW_PatchCommandThread_Mutex
 
-#define EXCLUDES_BELOW_DeviceEffectManager_Mutex \
+#define EXCLUDES_BELOW_DeviceEffectHandle_Mutex \
     EXCLUDES_PatchCommandThread_Mutex
+#define EXCLUDES_DeviceEffectHandle_Mutex \
+    EXCLUDES(android::audio_utils::DeviceEffectHandle_Mutex) \
+    EXCLUDES_BELOW_DeviceEffectHandle_Mutex
+
+#define EXCLUDES_BELOW_DeviceEffectProxy_ProxyMutex \
+    EXCLUDES_DeviceEffectHandle_Mutex
+#define EXCLUDES_DeviceEffectProxy_ProxyMutex \
+    EXCLUDES(android::audio_utils::DeviceEffectProxy_ProxyMutex) \
+    EXCLUDES_BELOW_DeviceEffectProxy_ProxyMutex
+
+#define EXCLUDES_BELOW_DeviceEffectManager_Mutex \
+    EXCLUDES_DeviceEffectProxy_ProxyMutex
 #define EXCLUDES_DeviceEffectManager_Mutex \
     EXCLUDES(android::audio_utils::DeviceEffectManager_Mutex) \
     EXCLUDES_BELOW_DeviceEffectManager_Mutex
 
-#define EXCLUDES_BELOW_AudioFlinger_HardwareMutex \
-    EXCLUDES_DeviceEffectManager_Mutex
-#define EXCLUDES_AudioFlinger_HardwareMutex \
-    EXCLUDES(android::audio_utils::AudioFlinger_HardwareMutex) \
-    EXCLUDES_BELOW_AudioFlinger_HardwareMutex
-
 #define EXCLUDES_BELOW_AudioFlinger_Mutex \
-    EXCLUDES_AudioFlinger_HardwareMutex
+    EXCLUDES_DeviceEffectManager_Mutex
 #define EXCLUDES_AudioFlinger_Mutex \
     EXCLUDES(android::audio_utils::AudioFlinger_Mutex) \
     EXCLUDES_BELOW_AudioFlinger_Mutex
diff --git a/audio_utils/include/audio_utils/threads.h b/audio_utils/include/audio_utils/threads.h
index 2bf59eba..418d5b8f 100644
--- a/audio_utils/include/audio_utils/threads.h
+++ b/audio_utils/include/audio_utils/threads.h
@@ -17,6 +17,7 @@
 #pragma once
 
 #include <algorithm>
+#include <bitset>
 #include <sys/syscall.h>   // SYS_gettid
 #include <unistd.h>        // bionic gettid
 #include <utils/Errors.h>  // status_t
@@ -143,4 +144,44 @@ status_t set_thread_priority(pid_t tid, int priority);
  */
 int get_thread_priority(int tid);
 
+/**
+ * An arbitrary CPU limit for Android running on Chrome / Linux / Windows devices.
+ */
+inline constexpr size_t kMaxCpus = std::min(256, CPU_SETSIZE);
+
+/**
+ * Sets the thread affinity based on a bit mask.
+ *
+ * \param  tid where 0 represents the current thread.
+ * \param  mask where a set bit indicates that core is available for the thread
+ *         to execute on.
+ *         A 64 bit integer may be used so long as you only need to access
+ *         the first 64 cores (an integer will implicitly convert to the std::bitset).
+ * \return 0 on success or -errno on failure.
+ */
+status_t set_thread_affinity(pid_t tid, const std::bitset<kMaxCpus>& mask);
+
+/**
+ * Returns the CPU mask thread affinity, which has a count of 0 if not found.
+ *
+ * \param  tid where 0 represents the current thread.
+ * \return a mask where a set bit indicates that core is allowed for the thread.
+ *         The bitset method to_ullong() may be used for devices with 64 CPUs or less.
+ */
+std::bitset<kMaxCpus> get_thread_affinity(pid_t tid);
+
+/**
+ * Returns current thread's CPU core or -1 if not found.
+ */
+ int get_cpu();
+
+/**
+ * Returns number of CPUs (equivalent to std::thread::hardware_concurrency()
+ * but is internally cached).
+ *
+ * If the value is not well defined or not computable, 0 is returned.
+ * This is not cached and a subsequent call will retry.
+ */
+size_t get_number_cpus();
+
 } // namespace android::audio_utils
diff --git a/audio_utils/tests/Android.bp b/audio_utils/tests/Android.bp
index ac4772d1..0a952e0f 100644
--- a/audio_utils/tests/Android.bp
+++ b/audio_utils/tests/Android.bp
@@ -27,6 +27,23 @@ cc_test {
     ],
 }
 
+cc_test {
+    name: "audio_deferredexecutor_tests",
+    host_supported: true,
+    srcs: ["audio_deferredexecutor_tests.cpp"],
+    shared_libs: [
+        "libbase",
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
@@ -45,6 +62,23 @@ cc_test {
     ],
 }
 
+cc_test {
+    name: "audio_linkedhashmap_tests",
+    host_supported: true,
+    srcs: ["audio_linkedhashmap_tests.cpp"],
+    shared_libs: [
+        "libbase",
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
 cc_defaults {
     name: "audio_math_test_defaults",
     host_supported: true,
diff --git a/audio_utils/tests/audio_deferredexecutor_tests.cpp b/audio_utils/tests/audio_deferredexecutor_tests.cpp
new file mode 100644
index 00000000..59c35a52
--- /dev/null
+++ b/audio_utils/tests/audio_deferredexecutor_tests.cpp
@@ -0,0 +1,107 @@
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
+#include <audio_utils/DeferredExecutor.h>
+#include <atomic>
+#include <gtest/gtest.h>
+
+// Test object
+class RunOnClose {
+public:
+    template <typename F>
+    explicit RunOnClose(F&& f) : thunk_(std::forward<F>(f)) {}
+    explicit RunOnClose(RunOnClose&& other) = default;
+    ~RunOnClose() { if (thunk_) thunk_(); }
+private:
+    std::function<void()> thunk_;
+};
+
+TEST(deferredexecutor, basic) {
+    std::atomic<int> disposed{};
+    std::atomic<int> deferred{};
+    {
+        android::audio_utils::DeferredExecutor de;
+
+        de.defer([&](){++deferred;});
+        de.dispose(std::make_shared<RunOnClose>([&]{++disposed;}));
+        EXPECT_EQ(0, deferred);
+        EXPECT_EQ(0, disposed);
+        EXPECT_EQ(false, de.empty());
+        de.process();
+        EXPECT_EQ(1, deferred);
+        EXPECT_EQ(1, disposed);
+        EXPECT_EQ(true, de.empty());
+    }
+    EXPECT_EQ(1, deferred);
+    EXPECT_EQ(1, disposed);
+}
+
+TEST(deferredexecutor, clear) {
+    std::atomic<int> disposed{};
+    std::atomic<int> deferred{};
+    {
+        android::audio_utils::DeferredExecutor de;
+
+        de.defer([&](){++deferred;});
+        de.dispose(std::make_shared<RunOnClose>([&]{++disposed;}));
+        EXPECT_EQ(0, deferred);
+        EXPECT_EQ(0, disposed);
+        EXPECT_EQ(false, de.empty());
+        de.clear();
+        EXPECT_EQ(0, deferred);
+        EXPECT_EQ(1, disposed);
+        EXPECT_EQ(true, de.empty());
+    }
+    EXPECT_EQ(0, deferred);
+    EXPECT_EQ(1, disposed);
+}
+
+class DtorAndRecursive : public testing::TestWithParam<std::tuple<bool, bool>> {};
+
+TEST_P(DtorAndRecursive, deferred_adds_deferred) {
+    const auto [processInDtor, recursive] = GetParam();
+    std::atomic<int> disposed{};
+    std::atomic<int> deferred{};
+    {
+        android::audio_utils::DeferredExecutor de(processInDtor);
+
+        // The deferred action adds another deferred action.
+        de.defer([&](){ de.defer([&](){++deferred;}); ++deferred;});
+        de.dispose(std::make_shared<RunOnClose>([&]{++disposed;}));
+        EXPECT_EQ(0, deferred);
+        EXPECT_EQ(0, disposed);
+        EXPECT_EQ(false, de.empty());
+        de.process(recursive);
+        EXPECT_EQ(1 + recursive, deferred);
+        EXPECT_EQ(1, disposed);
+        EXPECT_EQ(recursive, de.empty());
+    }
+    EXPECT_EQ(1 + (recursive || processInDtor), deferred);
+    EXPECT_EQ(1, disposed);
+}
+
+static const auto paramToString = [](const auto& param) {
+    const auto [processInDtor, recursive] = param.param;
+    return std::string("processInDtor_")
+            .append(processInDtor ? "true" : "false")
+            .append("__recursive_")
+            .append(recursive ? "true" : "false");
+};
+
+INSTANTIATE_TEST_SUITE_P(DeferredExecutorSuite,
+        DtorAndRecursive,
+        testing::Combine(testing::Bool(), testing::Bool()),
+        paramToString);
diff --git a/audio_utils/tests/audio_linkedhashmap_tests.cpp b/audio_utils/tests/audio_linkedhashmap_tests.cpp
new file mode 100644
index 00000000..b8f0afba
--- /dev/null
+++ b/audio_utils/tests/audio_linkedhashmap_tests.cpp
@@ -0,0 +1,108 @@
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
+#include <audio_utils/linked_hash_map.h>
+
+#include <gtest/gtest.h>
+
+using android::audio_utils::linked_hash_map;
+
+TEST(linked_hash_map, basic) {
+    linked_hash_map<int, int> lhm;
+
+    // assignment
+    lhm[10] = 1;
+    lhm[20] = 2;
+    lhm[30] = 3;
+
+    // access by key
+    ASSERT_EQ(1, lhm[10]);
+    ASSERT_EQ(2, lhm[20]);
+    ASSERT_EQ(3, lhm[30]);
+
+    // iterates in insertion order
+    auto it = lhm.begin();
+    ASSERT_EQ(1UL, it->second);
+    ++it;
+    ASSERT_EQ(2UL, it->second);
+    ++it;
+    ASSERT_EQ(3UL, it->second);
+    ++it;
+    ASSERT_EQ(lhm.end(), it);
+
+    // correct size
+    ASSERT_EQ(3UL, lhm.size());
+
+    // invalid key search returns end().
+    it = lhm.find(22);
+    ASSERT_EQ(lhm.end(), it);
+
+    // valid key search returns proper iterator.
+    it = lhm.find(20);
+    ASSERT_EQ(20, it->first);
+    ASSERT_EQ(2, it->second);
+
+    // test deletion
+    lhm.erase(it);
+    it = lhm.find(20);
+    ASSERT_EQ(lhm.end(), it);
+
+    // correct size
+    ASSERT_EQ(2UL, lhm.size());
+
+    // iterates in order
+    it = lhm.begin();
+    ASSERT_EQ(1UL, it->second);
+    ++it;
+    ASSERT_EQ(3UL, it->second);
+    ++it;
+    ASSERT_EQ(lhm.end(), it);
+
+    // add new value
+    lhm[2] = -1;
+
+    ASSERT_EQ(-1, lhm[2]);
+
+    // iterates in order of insertion
+    it = lhm.begin();
+    ASSERT_EQ(1UL, it->second);
+    ++it;
+    ASSERT_EQ(3UL, it->second);
+    ++it;
+    ASSERT_EQ(-1UL, it->second);
+    ++it;
+    ASSERT_EQ(lhm.end(), it);
+}
+
+TEST(linked_hash_map, structural) {
+    linked_hash_map<int, int> lhm;
+
+    // assignment
+    lhm[10] = 1;
+    lhm[20] = 2;
+    lhm[30] = 3;
+
+    // exercise default copy ctor (or move ctor)
+    auto lhm2 = lhm;
+
+    // exercise comparator
+    ASSERT_EQ(lhm, lhm2);
+
+    // access by key
+    ASSERT_EQ(1, lhm2[10]);
+    ASSERT_EQ(2, lhm2[20]);
+    ASSERT_EQ(3, lhm2[30]);
+}
diff --git a/audio_utils/tests/audio_thread_tests.cpp b/audio_utils/tests/audio_thread_tests.cpp
index 360fc3ad..2b540f2c 100644
--- a/audio_utils/tests/audio_thread_tests.cpp
+++ b/audio_utils/tests/audio_thread_tests.cpp
@@ -16,6 +16,7 @@
 
 #include <audio_utils/threads.h>
 #include <gtest/gtest.h>
+#include <thread>
 
 using namespace android;
 using namespace android::audio_utils;
@@ -62,3 +63,25 @@ TEST(audio_thread_tests, priority) {
 
     EXPECT_EQ(NO_ERROR, set_thread_priority(tid, priority));
 }
+
+TEST(audio_thread_tests, cpu_count) {
+    const unsigned cpu_count = std::thread::hardware_concurrency();
+    ASSERT_EQ(cpu_count, get_number_cpus());
+}
+
+TEST(audio_thread_tests, affinity) {
+    constexpr pid_t self = 0;
+    const int limit = std::min(get_number_cpus(), sizeof(uint64_t) * CHAR_BIT);
+    for (int i = 0; i < limit; ++i) {
+        uint64_t mask = 1ULL << i;
+        const status_t result = set_thread_affinity(self, mask);
+        ASSERT_EQ(NO_ERROR, result);
+        EXPECT_EQ(mask, get_thread_affinity(self).to_ullong());
+    }
+}
+
+TEST(audio_thread_tests, invalid_affinity) {
+    constexpr pid_t self = 0;
+    const int cpu_count = get_number_cpus();
+    ASSERT_NE(NO_ERROR, set_thread_affinity(self, std::bitset<kMaxCpus>{}.set(cpu_count)));
+}
diff --git a/audio_utils/tests/generate_mutex_order.cpp b/audio_utils/tests/generate_mutex_order.cpp
index feec60c5..8dde2b8e 100644
--- a/audio_utils/tests/generate_mutex_order.cpp
+++ b/audio_utils/tests/generate_mutex_order.cpp
@@ -18,7 +18,7 @@
 
 // To dump the mutex code to stdout:
 //
-// $ clang++ generate_mutex_order.cpp
+// $ clang++ -std=c++2a generate_mutex_order.cpp
 // $ ./a.out
 //
 
@@ -32,7 +32,9 @@ constexpr const char* mutexes[] {
   //    avoids acquiring AudioFlinger::mutex() from inside thread loop.
   // 4) AudioFlinger -> ThreadBase -> EffectChain -> EffectBase(EffectModule)
   // 5) EffectHandle -> ThreadBase -> EffectChain -> EffectBase(EffectModule)
-
+  // 6) AudioFlinger::mutex() -> DeviceEffectManager -> DeviceEffectProxy -> EffectChain
+  //    -> AudioFlinger::hardwareMutex() when adding/removing effect to/from HAL
+  // 7) AudioFlinger -> DeviceEffectManager -> DeviceEffectProxy -> DeviceEffectHandle
 
   "Spatializer_Mutex",         // AP - must come before EffectHandle_Mutex
   "AudioPolicyEffects_Mutex",  // AP - never hold AudioPolicyEffects_Mutex while calling APS,
@@ -47,15 +49,16 @@ constexpr const char* mutexes[] {
   "UidPolicy_Mutex",           // AP
 
   "AudioFlinger_Mutex",            // AF
-  "AudioFlinger_HardwareMutex",    // AF
   "DeviceEffectManager_Mutex",     // AF
+  "DeviceEffectProxy_ProxyMutex",  // AF: used for device effects (which have no chain).
+  "DeviceEffectHandle_Mutex",      // AF: used for device effects when controlled internally.
   "PatchCommandThread_Mutex",      // AF
   "ThreadBase_Mutex",              // AF
   "AudioFlinger_ClientMutex",      // AF
-  "MelReporter_Mutex",             // AF
   "EffectChain_Mutex",             // AF
-  "DeviceEffectProxy_ProxyMutex",  // AF: used for device effects (which have no chain).
   "EffectBase_Mutex",              // AF
+  "AudioFlinger_HardwareMutex",    // AF: used for HAL, called from AF or DeviceEffectManager
+  "MelReporter_Mutex",             // AF
 
   // These mutexes are in leaf objects
   // and are presented afterwards in arbitrary order.
diff --git a/audio_utils/threads.cpp b/audio_utils/threads.cpp
index aeaf59af..709fc6d4 100644
--- a/audio_utils/threads.cpp
+++ b/audio_utils/threads.cpp
@@ -22,6 +22,7 @@
 #include <errno.h>
 #include <sched.h>    // scheduler
 #include <sys/resource.h>
+#include <thread>
 #include <utils/Errors.h>  // status_t
 #include <utils/Log.h>
 
@@ -86,4 +87,55 @@ int get_thread_priority(int tid) {
     }
 }
 
+status_t set_thread_affinity(pid_t tid, const std::bitset<kMaxCpus>& mask) {
+    cpu_set_t cpuset;
+    CPU_ZERO(&cpuset);
+    const size_t limit = std::min(get_number_cpus(), kMaxCpus);
+    for (size_t i = 0; i < limit; ++i) {
+        if (mask.test(i)) {
+            CPU_SET(i, &cpuset);
+        }
+    }
+    if (sched_setaffinity(tid, sizeof(cpuset), &cpuset) == 0) {
+        return OK;
+    }
+    return -errno;
+}
+
+std::bitset<kMaxCpus> get_thread_affinity(pid_t tid) {
+    cpu_set_t cpuset;
+    CPU_ZERO(&cpuset);
+    std::bitset<kMaxCpus> mask;
+    if (sched_getaffinity(tid, sizeof(cpuset), &cpuset) == 0) {
+        const size_t limit = std::min(get_number_cpus(), kMaxCpus);
+        for (size_t i = 0; i < limit; ++i) {
+            if (CPU_ISSET(i, &cpuset)) {
+                mask.set(i);
+            }
+        }
+    }
+    return mask;
+}
+
+int get_cpu() {
+    return sched_getcpu();
+}
+
+/*
+ * std::thread::hardware_concurrency() is not optimized.  We cache the value here
+ * and it is implementation dependent whether std::thread::hardware_concurrency()
+ * returns only the cpus currently online, or includes offline hot plug cpus.
+ *
+ * See external/libcxx/src/thread.cpp.
+ */
+size_t get_number_cpus() {
+    static constinit std::atomic<size_t> n{};  // zero initialized.
+    size_t value = n.load(std::memory_order_relaxed);
+    if (value == 0) {  // not set, so we fetch.
+        value = std::thread::hardware_concurrency();
+        n.store(value, std::memory_order_relaxed);  // on race, this store is idempotent.
+    }
+    return value;
+}
+
 } // namespace android::audio_utils
diff --git a/camera/docs/docs.html b/camera/docs/docs.html
index 3b23cbc7..88c6bfc4 100644
--- a/camera/docs/docs.html
+++ b/camera/docs/docs.html
@@ -1483,58 +1483,6 @@
         </li>
       </ul> <!-- toc_section -->
     </li>
-    <li>
-      <span class="toc_section_header"><a href="#section_efv">efv</a></span>
-      <ul class="toc_section">
-        <li>
-          <span class="toc_kind_header">static</span>
-          <ul class="toc_section">
-            <li
-            ><a href="#static_android.efv.paddingZoomFactorRange">android.efv.paddingZoomFactorRange</a></li>
-          </ul>
-        </li>
-        <li>
-          <span class="toc_kind_header">controls</span>
-          <ul class="toc_section">
-            <li
-            ><a href="#controls_android.efv.paddingZoomFactor">android.efv.paddingZoomFactor</a></li>
-            <li
-            ><a href="#controls_android.efv.autoZoom">android.efv.autoZoom</a></li>
-            <li
-            ><a href="#controls_android.efv.maxPaddingZoomFactor">android.efv.maxPaddingZoomFactor</a></li>
-            <li
-            ><a href="#controls_android.efv.stabilizationMode">android.efv.stabilizationMode</a></li>
-            <li
-            ><a href="#controls_android.efv.translateViewport">android.efv.translateViewport</a></li>
-            <li
-            ><a href="#controls_android.efv.rotateViewport">android.efv.rotateViewport</a></li>
-          </ul>
-        </li>
-        <li>
-          <span class="toc_kind_header">dynamic</span>
-          <ul class="toc_section">
-            <li
-            ><a href="#dynamic_android.efv.paddingRegion">android.efv.paddingRegion</a></li>
-            <li
-            ><a href="#dynamic_android.efv.autoZoomPaddingRegion">android.efv.autoZoomPaddingRegion</a></li>
-            <li
-            ><a href="#dynamic_android.efv.targetCoordinates">android.efv.targetCoordinates</a></li>
-            <li
-            ><a href="#dynamic_android.efv.paddingZoomFactor">android.efv.paddingZoomFactor</a></li>
-            <li
-            ><a href="#dynamic_android.efv.stabilizationMode">android.efv.stabilizationMode</a></li>
-            <li
-            ><a href="#dynamic_android.efv.autoZoom">android.efv.autoZoom</a></li>
-            <li
-            ><a href="#dynamic_android.efv.rotateViewport">android.efv.rotateViewport</a></li>
-            <li
-            ><a href="#dynamic_android.efv.translateViewport">android.efv.translateViewport</a></li>
-            <li
-            ><a href="#dynamic_android.efv.maxPaddingZoomFactor">android.efv.maxPaddingZoomFactor</a></li>
-          </ul>
-        </li>
-      </ul> <!-- toc_section -->
-    </li>
   </ul>
 
 
@@ -3233,9 +3181,14 @@ high-quality still capture for final metering decisions to
 be made,<wbr/> and for firing pre-capture flash pulses to estimate
 scene brightness and required final capture flash power,<wbr/> when
 the flash is enabled.<wbr/></p>
-<p>Normally,<wbr/> this entry should be set to START for only a
-single request,<wbr/> and the application should wait until the
-sequence completes before starting a new one.<wbr/></p>
+<p>Flash is enabled during precapture sequence when:</p>
+<ul>
+<li>AE mode is ON_<wbr/>ALWAYS_<wbr/>FLASH</li>
+<li>AE mode is ON_<wbr/>AUTO_<wbr/>FLASH and the scene is deemed too dark without flash,<wbr/> or</li>
+<li>AE mode is ON and flash mode is TORCH or SINGLE</li>
+</ul>
+<p>Normally,<wbr/> this entry should be set to START for only single request,<wbr/> and the
+application should wait until the sequence completes before starting a new one.<wbr/></p>
 <p>When a precapture metering sequence is finished,<wbr/> the camera device
 may lock the auto-exposure routine internally to be able to accurately expose the
 subsequent still capture image (<code><a href="#controls_android.control.captureIntent">android.<wbr/>control.<wbr/>capture<wbr/>Intent</a> == STILL_<wbr/>CAPTURE</code>).<wbr/>
@@ -8611,9 +8564,14 @@ high-quality still capture for final metering decisions to
 be made,<wbr/> and for firing pre-capture flash pulses to estimate
 scene brightness and required final capture flash power,<wbr/> when
 the flash is enabled.<wbr/></p>
-<p>Normally,<wbr/> this entry should be set to START for only a
-single request,<wbr/> and the application should wait until the
-sequence completes before starting a new one.<wbr/></p>
+<p>Flash is enabled during precapture sequence when:</p>
+<ul>
+<li>AE mode is ON_<wbr/>ALWAYS_<wbr/>FLASH</li>
+<li>AE mode is ON_<wbr/>AUTO_<wbr/>FLASH and the scene is deemed too dark without flash,<wbr/> or</li>
+<li>AE mode is ON and flash mode is TORCH or SINGLE</li>
+</ul>
+<p>Normally,<wbr/> this entry should be set to START for only single request,<wbr/> and the
+application should wait until the sequence completes before starting a new one.<wbr/></p>
 <p>When a precapture metering sequence is finished,<wbr/> the camera device
 may lock the auto-exposure routine internally to be able to accurately expose the
 subsequent still capture image (<code><a href="#controls_android.control.captureIntent">android.<wbr/>control.<wbr/>capture<wbr/>Intent</a> == STILL_<wbr/>CAPTURE</code>).<wbr/>
@@ -12257,8 +12215,6 @@ state will be CONVERGED.<wbr/></li>
 boost when the light level threshold is exceeded.<wbr/></p>
 <p>This state indicates when low light boost is 'ACTIVE' and applied.<wbr/> Similarly,<wbr/> it can
 indicate when it is not being applied by returning 'INACTIVE'.<wbr/></p>
-<p>This key will be absent from the CaptureResult if AE mode is not set to
-'ON_<wbr/>LOW_<wbr/>LIGHT_<wbr/>BOOST_<wbr/>BRIGHTNESS_<wbr/>PRIORITY.<wbr/></p>
 <p>The default value will always be 'INACTIVE'.<wbr/></p>
             </td>
           </tr>
@@ -13105,6 +13061,13 @@ then the flash will be fired at the default level set by HAL
 in <a href="#static_android.flash.singleStrengthDefaultLevel">android.<wbr/>flash.<wbr/>single<wbr/>Strength<wbr/>Default<wbr/>Level</a>.<wbr/>
 If <a href="#controls_android.control.aeMode">android.<wbr/>control.<wbr/>ae<wbr/>Mode</a> is set to any of <code>ON_<wbr/>AUTO_<wbr/>FLASH</code>,<wbr/> <code>ON_<wbr/>ALWAYS_<wbr/>FLASH</code>,<wbr/>
 <code>ON_<wbr/>AUTO_<wbr/>FLASH_<wbr/>REDEYE</code>,<wbr/> <code>ON_<wbr/>EXTERNAL_<wbr/>FLASH</code> values,<wbr/> then the strengthLevel will be ignored.<wbr/></p>
+<p>When AE mode is ON and flash mode is TORCH or SINGLE,<wbr/> the application should make sure
+the AE mode,<wbr/> flash mode,<wbr/> and flash strength level remain the same between precapture
+trigger request and final capture request.<wbr/> The flash strength level being set during
+precapture sequence is used by the camera device as a reference.<wbr/> The actual strength
+may be less,<wbr/> and the auto-exposure routine makes sure proper conversions of sensor
+exposure time and sensitivities between precapture and final capture for the specified
+strength level.<wbr/></p>
             </td>
           </tr>
 
@@ -14071,6 +14034,13 @@ then the flash will be fired at the default level set by HAL
 in <a href="#static_android.flash.singleStrengthDefaultLevel">android.<wbr/>flash.<wbr/>single<wbr/>Strength<wbr/>Default<wbr/>Level</a>.<wbr/>
 If <a href="#controls_android.control.aeMode">android.<wbr/>control.<wbr/>ae<wbr/>Mode</a> is set to any of <code>ON_<wbr/>AUTO_<wbr/>FLASH</code>,<wbr/> <code>ON_<wbr/>ALWAYS_<wbr/>FLASH</code>,<wbr/>
 <code>ON_<wbr/>AUTO_<wbr/>FLASH_<wbr/>REDEYE</code>,<wbr/> <code>ON_<wbr/>EXTERNAL_<wbr/>FLASH</code> values,<wbr/> then the strengthLevel will be ignored.<wbr/></p>
+<p>When AE mode is ON and flash mode is TORCH or SINGLE,<wbr/> the application should make sure
+the AE mode,<wbr/> flash mode,<wbr/> and flash strength level remain the same between precapture
+trigger request and final capture request.<wbr/> The flash strength level being set during
+precapture sequence is used by the camera device as a reference.<wbr/> The actual strength
+may be less,<wbr/> and the auto-exposure routine makes sure proper conversions of sensor
+exposure time and sensitivities between precapture and final capture for the specified
+strength level.<wbr/></p>
             </td>
           </tr>
 
@@ -41364,1097 +41334,6 @@ output format/<wbr/>size combination for Jpeg/<wbr/>R streams for CaptureRequest
         
         
 
-      <!-- end of kind -->
-      </tbody>
-
-  <!-- end of section -->
-  <tr><td colspan="7" id="section_efv" class="section">efv</td></tr>
-
-
-      <tr><td colspan="7" class="kind">static</td></tr>
-
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
-
-      <tbody>
-
-        
-
-        
-
-        
-
-        
-
-                
-          <tr class="entry" id="static_android.efv.paddingZoomFactorRange">
-            <td class="entry_name
-             " rowspan="3">
-              android.<wbr/>efv.<wbr/>padding<wbr/>Zoom<wbr/>Factor<wbr/>Range
-            </td>
-            <td class="entry_type">
-                <span class="entry_type_name">float</span>
-                <span class="entry_type_container">x</span>
-
-                <span class="entry_type_array">
-                  2
-                </span>
-              <span class="entry_type_visibility"> [extension as rangeFloat]</span>
-
-
-
-
-
-
-            </td> <!-- entry_type -->
-
-            <td class="entry_description">
-              <p>Minimum and maximum padding zoom factors supported by this camera device for
-<a href="#controls_android.efv.paddingZoomFactor">android.<wbr/>efv.<wbr/>padding<wbr/>Zoom<wbr/>Factor</a> used for the
-<a href="https://developer.android.com/reference/android/hardware/camera2/CameraExtensionCharacteristics.html#EXTENSION_EYES_FREE_VIDEOGRAPHY">Camera<wbr/>Extension<wbr/>Characteristics#EXTENSION_<wbr/>EYES_<wbr/>FREE_<wbr/>VIDEOGRAPHY</a>
-extension.<wbr/></p>
-            </td>
-
-            <td class="entry_units">
-              A pair of padding zoom factors in floating-points:
-          (minPaddingZoomFactor,<wbr/> maxPaddingZoomFactor)
-            </td>
-
-            <td class="entry_range">
-              <p>1.<wbr/>0 &lt; minPaddingZoomFactor &lt;= maxPaddingZoomFactor</p>
-            </td>
-
-            <td class="entry_hal_version">
-              <p>3.<wbr/>10</p>
-            </td>
-
-            <td class="entry_tags">
-            </td>
-
-          </tr>
-          <tr class="entries_header">
-            <th class="th_details" colspan="6">Details</th>
-          </tr>
-          <tr class="entry_cont">
-            <td class="entry_details" colspan="6">
-              <p>The minimum and maximum padding zoom factors supported by the device for
-<a href="#controls_android.efv.paddingZoomFactor">android.<wbr/>efv.<wbr/>padding<wbr/>Zoom<wbr/>Factor</a> used as part of the
-<a href="https://developer.android.com/reference/android/hardware/camera2/CameraExtensionCharacteristics.html#EXTENSION_EYES_FREE_VIDEOGRAPHY">Camera<wbr/>Extension<wbr/>Characteristics#EXTENSION_<wbr/>EYES_<wbr/>FREE_<wbr/>VIDEOGRAPHY</a>
-extension feature.<wbr/> This extension specific camera characteristic can be queried using
-<a href="https://developer.android.com/reference/android/hardware/camera2/CameraExtensionCharacteristics.html#get">CameraExtensionCharacteristics#get</a>.<wbr/></p>
-            </td>
-          </tr>
-
-
-          <tr class="entry_spacer"><td class="entry_spacer" colspan="7"></td></tr>
-           <!-- end of entry -->
-        
-        
-
-      <!-- end of kind -->
-      </tbody>
-      <tr><td colspan="7" class="kind">controls</td></tr>
-
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
-
-      <tbody>
-
-        
-
-        
-
-        
-
-        
-
-                
-          <tr class="entry" id="controls_android.efv.paddingZoomFactor">
-            <td class="entry_name
-             " rowspan="3">
-              android.<wbr/>efv.<wbr/>padding<wbr/>Zoom<wbr/>Factor
-            </td>
-            <td class="entry_type">
-                <span class="entry_type_name">float</span>
-
-              <span class="entry_type_visibility"> [extension]</span>
-
-
-
-
-
-
-            </td> <!-- entry_type -->
-
-            <td class="entry_description">
-              <p>Used to apply an additional digital zoom factor for the
-<a href="https://developer.android.com/reference/android/hardware/camera2/CameraExtensionCharacteristics.html#EXTENSION_EYES_FREE_VIDEOGRAPHY">Camera<wbr/>Extension<wbr/>Characteristics#EXTENSION_<wbr/>EYES_<wbr/>FREE_<wbr/>VIDEOGRAPHY</a>
-extension in <a href="https://developer.android.com/reference/android/hardware/camera2/CameraMetadata.html#EFV_STABILIZATION_MODE_LOCKED">Camera<wbr/>Metadata#EFV_<wbr/>STABILIZATION_<wbr/>MODE_<wbr/>LOCKED</a> mode.<wbr/></p>
-            </td>
-
-            <td class="entry_units">
-            </td>
-
-            <td class="entry_range">
-              <p><a href="#static_android.efv.paddingZoomFactorRange">android.<wbr/>efv.<wbr/>padding<wbr/>Zoom<wbr/>Factor<wbr/>Range</a></p>
-            </td>
-
-            <td class="entry_hal_version">
-              <p>3.<wbr/>10</p>
-            </td>
-
-            <td class="entry_tags">
-            </td>
-
-          </tr>
-          <tr class="entries_header">
-            <th class="th_details" colspan="6">Details</th>
-          </tr>
-          <tr class="entry_cont">
-            <td class="entry_details" colspan="6">
-              <p>For the <a href="https://developer.android.com/reference/android/hardware/camera2/CameraExtensionCharacteristics.html#EXTENSION_EYES_FREE_VIDEOGRAPHY">Camera<wbr/>Extension<wbr/>Characteristics#EXTENSION_<wbr/>EYES_<wbr/>FREE_<wbr/>VIDEOGRAPHY</a>
-feature,<wbr/> an additional zoom factor is applied on top of the existing <a href="#controls_android.control.zoomRatio">android.<wbr/>control.<wbr/>zoom<wbr/>Ratio</a>.<wbr/>
-This additional zoom factor serves as a buffer to provide more flexibility for the
-<a href="https://developer.android.com/reference/android/hardware/camera2/CameraMetadata.html#EFV_STABILIZATION_MODE_LOCKED">Camera<wbr/>Metadata#EFV_<wbr/>STABILIZATION_<wbr/>MODE_<wbr/>LOCKED</a>
-mode.<wbr/> If <a href="#controls_android.efv.paddingZoomFactor">android.<wbr/>efv.<wbr/>padding<wbr/>Zoom<wbr/>Factor</a> is not set,<wbr/> the default will be used.<wbr/>
-The effectiveness of the stabilization may be influenced by the amount of padding zoom
-applied.<wbr/> A higher padding zoom factor can stabilize the target region more effectively
-with greater flexibility but may potentially impact image quality.<wbr/> Conversely,<wbr/> a lower
-padding zoom factor may be used to prioritize preserving image quality,<wbr/> albeit with less
-leeway in stabilizing the target region.<wbr/> It is recommended to set the
-<a href="#controls_android.efv.paddingZoomFactor">android.<wbr/>efv.<wbr/>padding<wbr/>Zoom<wbr/>Factor</a> to at least 1.<wbr/>5.<wbr/></p>
-<p>If <a href="#controls_android.efv.autoZoom">android.<wbr/>efv.<wbr/>auto<wbr/>Zoom</a> is enabled,<wbr/> the requested <a href="#controls_android.efv.paddingZoomFactor">android.<wbr/>efv.<wbr/>padding<wbr/>Zoom<wbr/>Factor</a> will be overridden.<wbr/>
-<a href="#controls_android.efv.maxPaddingZoomFactor">android.<wbr/>efv.<wbr/>max<wbr/>Padding<wbr/>Zoom<wbr/>Factor</a> can be checked for more details on controlling the
-padding zoom factor during <a href="#controls_android.efv.autoZoom">android.<wbr/>efv.<wbr/>auto<wbr/>Zoom</a>.<wbr/></p>
-            </td>
-          </tr>
-
-
-          <tr class="entry_spacer"><td class="entry_spacer" colspan="7"></td></tr>
-           <!-- end of entry -->
-        
-                
-          <tr class="entry" id="controls_android.efv.autoZoom">
-            <td class="entry_name
-             " rowspan="3">
-              android.<wbr/>efv.<wbr/>auto<wbr/>Zoom
-            </td>
-            <td class="entry_type">
-                <span class="entry_type_name entry_type_name_enum">byte</span>
-
-              <span class="entry_type_visibility"> [extension as boolean]</span>
-
-
-
-
-
-                <ul class="entry_type_enum">
-                  <li>
-                    <span class="entry_type_enum_name">TRUE (v3.10)</span>
-                  </li>
-                  <li>
-                    <span class="entry_type_enum_name">FALSE (v3.10)</span>
-                  </li>
-                </ul>
-
-            </td> <!-- entry_type -->
-
-            <td class="entry_description">
-              <p>Used to enable or disable auto zoom for the
-<a href="https://developer.android.com/reference/android/hardware/camera2/CameraExtensionCharacteristics.html#EXTENSION_EYES_FREE_VIDEOGRAPHY">Camera<wbr/>Extension<wbr/>Characteristics#EXTENSION_<wbr/>EYES_<wbr/>FREE_<wbr/>VIDEOGRAPHY</a>
-extension in <a href="https://developer.android.com/reference/android/hardware/camera2/CameraMetadata.html#EFV_STABILIZATION_MODE_LOCKED">Camera<wbr/>Metadata#EFV_<wbr/>STABILIZATION_<wbr/>MODE_<wbr/>LOCKED</a> mode.<wbr/></p>
-            </td>
-
-            <td class="entry_units">
-            </td>
-
-            <td class="entry_range">
-            </td>
-
-            <td class="entry_hal_version">
-              <p>3.<wbr/>10</p>
-            </td>
-
-            <td class="entry_tags">
-            </td>
-
-          </tr>
-          <tr class="entries_header">
-            <th class="th_details" colspan="6">Details</th>
-          </tr>
-          <tr class="entry_cont">
-            <td class="entry_details" colspan="6">
-              <p>Turn on auto zoom to let the
-<a href="https://developer.android.com/reference/android/hardware/camera2/CameraExtensionCharacteristics.html#EXTENSION_EYES_FREE_VIDEOGRAPHY">Camera<wbr/>Extension<wbr/>Characteristics#EXTENSION_<wbr/>EYES_<wbr/>FREE_<wbr/>VIDEOGRAPHY</a>
-feature decide at any given point a combination of
-<a href="#controls_android.control.zoomRatio">android.<wbr/>control.<wbr/>zoom<wbr/>Ratio</a> and <a href="#controls_android.efv.paddingZoomFactor">android.<wbr/>efv.<wbr/>padding<wbr/>Zoom<wbr/>Factor</a>
-to keep the target region in view and stabilized.<wbr/> The combination chosen by the
-<a href="https://developer.android.com/reference/android/hardware/camera2/CameraExtensionCharacteristics.html#EXTENSION_EYES_FREE_VIDEOGRAPHY">Camera<wbr/>Extension<wbr/>Characteristics#EXTENSION_<wbr/>EYES_<wbr/>FREE_<wbr/>VIDEOGRAPHY</a>
-will equal the requested <a href="#controls_android.control.zoomRatio">android.<wbr/>control.<wbr/>zoom<wbr/>Ratio</a> multiplied with the requested
-<a href="#controls_android.efv.paddingZoomFactor">android.<wbr/>efv.<wbr/>padding<wbr/>Zoom<wbr/>Factor</a>.<wbr/> A limit can be set on the padding zoom if wanting
-to control image quality further using <a href="#controls_android.efv.maxPaddingZoomFactor">android.<wbr/>efv.<wbr/>max<wbr/>Padding<wbr/>Zoom<wbr/>Factor</a>.<wbr/></p>
-            </td>
-          </tr>
-
-
-          <tr class="entry_spacer"><td class="entry_spacer" colspan="7"></td></tr>
-           <!-- end of entry -->
-        
-                
-          <tr class="entry" id="controls_android.efv.maxPaddingZoomFactor">
-            <td class="entry_name
-             " rowspan="3">
-              android.<wbr/>efv.<wbr/>max<wbr/>Padding<wbr/>Zoom<wbr/>Factor
-            </td>
-            <td class="entry_type">
-                <span class="entry_type_name">float</span>
-
-              <span class="entry_type_visibility"> [extension]</span>
-
-
-
-
-
-
-            </td> <!-- entry_type -->
-
-            <td class="entry_description">
-              <p>Used to limit the <a href="#controls_android.efv.paddingZoomFactor">android.<wbr/>efv.<wbr/>padding<wbr/>Zoom<wbr/>Factor</a> if
-<a href="#controls_android.efv.autoZoom">android.<wbr/>efv.<wbr/>auto<wbr/>Zoom</a> is enabled for the
-<a href="https://developer.android.com/reference/android/hardware/camera2/CameraExtensionCharacteristics.html#EXTENSION_EYES_FREE_VIDEOGRAPHY">Camera<wbr/>Extension<wbr/>Characteristics#EXTENSION_<wbr/>EYES_<wbr/>FREE_<wbr/>VIDEOGRAPHY</a>
-extension in <a href="https://developer.android.com/reference/android/hardware/camera2/CameraMetadata.html#EFV_STABILIZATION_MODE_LOCKED">Camera<wbr/>Metadata#EFV_<wbr/>STABILIZATION_<wbr/>MODE_<wbr/>LOCKED</a> mode.<wbr/></p>
-            </td>
-
-            <td class="entry_units">
-            </td>
-
-            <td class="entry_range">
-              <p>The range of <a href="#static_android.efv.paddingZoomFactorRange">android.<wbr/>efv.<wbr/>padding<wbr/>Zoom<wbr/>Factor<wbr/>Range</a>.<wbr/> Use a value greater than or equal to
-the <a href="#controls_android.efv.paddingZoomFactor">android.<wbr/>efv.<wbr/>padding<wbr/>Zoom<wbr/>Factor</a> to effectively utilize this key.<wbr/></p>
-            </td>
-
-            <td class="entry_hal_version">
-              <p>3.<wbr/>10</p>
-            </td>
-
-            <td class="entry_tags">
-            </td>
-
-          </tr>
-          <tr class="entries_header">
-            <th class="th_details" colspan="6">Details</th>
-          </tr>
-          <tr class="entry_cont">
-            <td class="entry_details" colspan="6">
-              <p>If <a href="#controls_android.efv.autoZoom">android.<wbr/>efv.<wbr/>auto<wbr/>Zoom</a> is enabled,<wbr/> this key can be used to set a limit
-on the <a href="#controls_android.efv.paddingZoomFactor">android.<wbr/>efv.<wbr/>padding<wbr/>Zoom<wbr/>Factor</a> chosen by the
-<a href="https://developer.android.com/reference/android/hardware/camera2/CameraExtensionCharacteristics.html#EXTENSION_EYES_FREE_VIDEOGRAPHY">Camera<wbr/>Extension<wbr/>Characteristics#EXTENSION_<wbr/>EYES_<wbr/>FREE_<wbr/>VIDEOGRAPHY</a>
-extension in <a href="https://developer.android.com/reference/android/hardware/camera2/CameraMetadata.html#EFV_STABILIZATION_MODE_LOCKED">Camera<wbr/>Metadata#EFV_<wbr/>STABILIZATION_<wbr/>MODE_<wbr/>LOCKED</a> mode
-to control image quality.<wbr/></p>
-            </td>
-          </tr>
-
-
-          <tr class="entry_spacer"><td class="entry_spacer" colspan="7"></td></tr>
-           <!-- end of entry -->
-        
-                
-          <tr class="entry" id="controls_android.efv.stabilizationMode">
-            <td class="entry_name
-             " rowspan="3">
-              android.<wbr/>efv.<wbr/>stabilization<wbr/>Mode
-            </td>
-            <td class="entry_type">
-                <span class="entry_type_name entry_type_name_enum">int32</span>
-
-              <span class="entry_type_visibility"> [extension]</span>
-
-
-
-
-
-                <ul class="entry_type_enum">
-                  <li>
-                    <span class="entry_type_enum_name">OFF (v3.10)</span>
-                    <span class="entry_type_enum_notes"><p>No stabilization.<wbr/></p></span>
-                  </li>
-                  <li>
-                    <span class="entry_type_enum_name">GIMBAL (v3.10)</span>
-                    <span class="entry_type_enum_notes"><p>Gimbal stabilization mode.<wbr/></p></span>
-                  </li>
-                  <li>
-                    <span class="entry_type_enum_name">LOCKED (v3.10)</span>
-                    <span class="entry_type_enum_notes"><p>Locked stabilization mode which uses the
-<a href="https://developer.android.com/reference/android/hardware/camera2/CameraExtensionCharacteristics.html#EXTENSION_EYES_FREE_VIDEOGRAPHY">Camera<wbr/>Extension<wbr/>Characteristics#EXTENSION_<wbr/>EYES_<wbr/>FREE_<wbr/>VIDEOGRAPHY</a>
-stabilization to directionally steady the target region.<wbr/></p></span>
-                  </li>
-                </ul>
-
-            </td> <!-- entry_type -->
-
-            <td class="entry_description">
-              <p>Set the stabilization mode for the
-<a href="https://developer.android.com/reference/android/hardware/camera2/CameraExtensionCharacteristics.html#EXTENSION_EYES_FREE_VIDEOGRAPHY">Camera<wbr/>Extension<wbr/>Characteristics#EXTENSION_<wbr/>EYES_<wbr/>FREE_<wbr/>VIDEOGRAPHY</a>
-extension</p>
-            </td>
-
-            <td class="entry_units">
-            </td>
-
-            <td class="entry_range">
-            </td>
-
-            <td class="entry_hal_version">
-              <p>3.<wbr/>10</p>
-            </td>
-
-            <td class="entry_tags">
-            </td>
-
-          </tr>
-          <tr class="entries_header">
-            <th class="th_details" colspan="6">Details</th>
-          </tr>
-          <tr class="entry_cont">
-            <td class="entry_details" colspan="6">
-              <p>The desired stabilization mode.<wbr/> Gimbal stabilization mode provides simple,<wbr/> non-locked
-video stabilization.<wbr/> Locked mode uses the
-<a href="https://developer.android.com/reference/android/hardware/camera2/CameraExtensionCharacteristics.html#EXTENSION_EYES_FREE_VIDEOGRAPHY">Camera<wbr/>Extension<wbr/>Characteristics#EXTENSION_<wbr/>EYES_<wbr/>FREE_<wbr/>VIDEOGRAPHY</a>
-stabilization feature to fixate on the current region,<wbr/> utilizing it as the target area for
-stabilization.<wbr/></p>
-            </td>
-          </tr>
-
-
-          <tr class="entry_spacer"><td class="entry_spacer" colspan="7"></td></tr>
-           <!-- end of entry -->
-        
-                
-          <tr class="entry" id="controls_android.efv.translateViewport">
-            <td class="entry_name
-             " rowspan="3">
-              android.<wbr/>efv.<wbr/>translate<wbr/>Viewport
-            </td>
-            <td class="entry_type">
-                <span class="entry_type_name">int32</span>
-
-              <span class="entry_type_visibility"> [extension as pairIntegerInteger]</span>
-
-
-
-
-
-
-            </td> <!-- entry_type -->
-
-            <td class="entry_description">
-              <p>Used to update the target region for the
-<a href="https://developer.android.com/reference/android/hardware/camera2/CameraExtensionCharacteristics.html#EXTENSION_EYES_FREE_VIDEOGRAPHY">Camera<wbr/>Extension<wbr/>Characteristics#EXTENSION_<wbr/>EYES_<wbr/>FREE_<wbr/>VIDEOGRAPHY</a>
-extension in <a href="https://developer.android.com/reference/android/hardware/camera2/CameraMetadata.html#EFV_STABILIZATION_MODE_LOCKED">Camera<wbr/>Metadata#EFV_<wbr/>STABILIZATION_<wbr/>MODE_<wbr/>LOCKED</a> mode.<wbr/></p>
-            </td>
-
-            <td class="entry_units">
-            </td>
-
-            <td class="entry_range">
-              <p>android.<wbr/>util.<wbr/>Pair<integer,integer> represents the
-<horizontal,vertical> shift.<wbr/> The range for the horizontal shift is
-[-max(<a href="#dynamic_android.efv.paddingRegion">android.<wbr/>efv.<wbr/>padding<wbr/>Region</a>-left),<wbr/> max(<a href="#dynamic_android.efv.paddingRegion">android.<wbr/>efv.<wbr/>padding<wbr/>Region</a>-right)].<wbr/>
-The range for the vertical shift is
-[-max(<a href="#dynamic_android.efv.paddingRegion">android.<wbr/>efv.<wbr/>padding<wbr/>Region</a>-top),<wbr/> max(<a href="#dynamic_android.efv.paddingRegion">android.<wbr/>efv.<wbr/>padding<wbr/>Region</a>-bottom)]</horizontal,vertical></integer,integer></p>
-            </td>
-
-            <td class="entry_hal_version">
-              <p>3.<wbr/>10</p>
-            </td>
-
-            <td class="entry_tags">
-            </td>
-
-          </tr>
-          <tr class="entries_header">
-            <th class="th_details" colspan="6">Details</th>
-          </tr>
-          <tr class="entry_cont">
-            <td class="entry_details" colspan="6">
-              <p>A android.<wbr/>util.<wbr/>Pair<integer,integer> that represents the desired
-<horizontal,vertical> shift of the current locked view (or target region) in
-pixels.<wbr/> Negative values indicate left and upward shifts,<wbr/> while positive values indicate
-right and downward shifts in the active array coordinate system.<wbr/></horizontal,vertical></integer,integer></p>
-            </td>
-          </tr>
-
-
-          <tr class="entry_spacer"><td class="entry_spacer" colspan="7"></td></tr>
-           <!-- end of entry -->
-        
-                
-          <tr class="entry" id="controls_android.efv.rotateViewport">
-            <td class="entry_name
-             " rowspan="3">
-              android.<wbr/>efv.<wbr/>rotate<wbr/>Viewport
-            </td>
-            <td class="entry_type">
-                <span class="entry_type_name">float</span>
-
-              <span class="entry_type_visibility"> [extension]</span>
-
-
-
-
-
-
-            </td> <!-- entry_type -->
-
-            <td class="entry_description">
-              <p>Representing the desired clockwise rotation
-of the target region in degrees for the
-<a href="https://developer.android.com/reference/android/hardware/camera2/CameraExtensionCharacteristics.html#EXTENSION_EYES_FREE_VIDEOGRAPHY">Camera<wbr/>Extension<wbr/>Characteristics#EXTENSION_<wbr/>EYES_<wbr/>FREE_<wbr/>VIDEOGRAPHY</a>
-extension in <a href="https://developer.android.com/reference/android/hardware/camera2/CameraMetadata.html#EFV_STABILIZATION_MODE_LOCKED">Camera<wbr/>Metadata#EFV_<wbr/>STABILIZATION_<wbr/>MODE_<wbr/>LOCKED</a> mode.<wbr/></p>
-            </td>
-
-            <td class="entry_units">
-            </td>
-
-            <td class="entry_range">
-              <p>0 to 360</p>
-            </td>
-
-            <td class="entry_hal_version">
-              <p>3.<wbr/>10</p>
-            </td>
-
-            <td class="entry_tags">
-            </td>
-
-          </tr>
-          <tr class="entries_header">
-            <th class="th_details" colspan="6">Details</th>
-          </tr>
-          <tr class="entry_cont">
-            <td class="entry_details" colspan="6">
-              <p>Value representing the desired clockwise rotation of the target
-region in degrees.<wbr/></p>
-            </td>
-          </tr>
-
-
-          <tr class="entry_spacer"><td class="entry_spacer" colspan="7"></td></tr>
-           <!-- end of entry -->
-        
-        
-
-      <!-- end of kind -->
-      </tbody>
-      <tr><td colspan="7" class="kind">dynamic</td></tr>
-
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
-
-      <tbody>
-
-        
-
-        
-
-        
-
-        
-
-                
-          <tr class="entry" id="dynamic_android.efv.paddingRegion">
-            <td class="entry_name
-             " rowspan="3">
-              android.<wbr/>efv.<wbr/>padding<wbr/>Region
-            </td>
-            <td class="entry_type">
-                <span class="entry_type_name">int32</span>
-                <span class="entry_type_container">x</span>
-
-                <span class="entry_type_array">
-                  4
-                </span>
-              <span class="entry_type_visibility"> [extension]</span>
-
-
-
-
-
-
-            </td> <!-- entry_type -->
-
-            <td class="entry_description">
-              <p>The padding region for the
-<a href="https://developer.android.com/reference/android/hardware/camera2/CameraExtensionCharacteristics.html#EXTENSION_EYES_FREE_VIDEOGRAPHY">Camera<wbr/>Extension<wbr/>Characteristics#EXTENSION_<wbr/>EYES_<wbr/>FREE_<wbr/>VIDEOGRAPHY</a>
-extension in <a href="https://developer.android.com/reference/android/hardware/camera2/CameraMetadata.html#EFV_STABILIZATION_MODE_LOCKED">Camera<wbr/>Metadata#EFV_<wbr/>STABILIZATION_<wbr/>MODE_<wbr/>LOCKED</a> mode.<wbr/></p>
-            </td>
-
-            <td class="entry_units">
-            </td>
-
-            <td class="entry_range">
-              <p>The padding is the number of remaining pixels of padding in each direction.<wbr/>
-The pixels reference the active array coordinate system.<wbr/> Negative values indicate the target
-region is out of bounds.<wbr/> The value for this key may be null for when the stabilization mode is
-in <a href="https://developer.android.com/reference/android/hardware/camera2/CameraMetadata.html#EFV_STABILIZATION_MODE_OFF">Camera<wbr/>Metadata#EFV_<wbr/>STABILIZATION_<wbr/>MODE_<wbr/>OFF</a>
-or <a href="https://developer.android.com/reference/android/hardware/camera2/CameraMetadata.html#EFV_STABILIZATION_MODE_GIMBAL">Camera<wbr/>Metadata#EFV_<wbr/>STABILIZATION_<wbr/>MODE_<wbr/>GIMBAL</a> mode.<wbr/></p>
-            </td>
-
-            <td class="entry_hal_version">
-              <p>3.<wbr/>10</p>
-            </td>
-
-            <td class="entry_tags">
-            </td>
-
-          </tr>
-          <tr class="entries_header">
-            <th class="th_details" colspan="6">Details</th>
-          </tr>
-          <tr class="entry_cont">
-            <td class="entry_details" colspan="6">
-              <p>An array [left,<wbr/> top,<wbr/> right,<wbr/> bottom] of the padding in pixels remaining on all four sides
-before the target region starts to go out of bounds.<wbr/></p>
-<p>The padding region denotes the area surrounding the stabilized target region within which
-the camera can be moved while maintaining the target region in view.<wbr/> As the camera moves,<wbr/>
-the padding region adjusts to represent the proximity of the target region to the
-boundary,<wbr/> which is the point at which the target region will start to go out of bounds.<wbr/></p>
-            </td>
-          </tr>
-
-
-          <tr class="entry_spacer"><td class="entry_spacer" colspan="7"></td></tr>
-           <!-- end of entry -->
-        
-                
-          <tr class="entry" id="dynamic_android.efv.autoZoomPaddingRegion">
-            <td class="entry_name
-             " rowspan="3">
-              android.<wbr/>efv.<wbr/>auto<wbr/>Zoom<wbr/>Padding<wbr/>Region
-            </td>
-            <td class="entry_type">
-                <span class="entry_type_name">int32</span>
-                <span class="entry_type_container">x</span>
-
-                <span class="entry_type_array">
-                  4
-                </span>
-              <span class="entry_type_visibility"> [extension]</span>
-
-
-
-
-
-
-            </td> <!-- entry_type -->
-
-            <td class="entry_description">
-              <p>The padding region when <a href="#controls_android.efv.autoZoom">android.<wbr/>efv.<wbr/>auto<wbr/>Zoom</a> is enabled for the
-<a href="https://developer.android.com/reference/android/hardware/camera2/CameraExtensionCharacteristics.html#EXTENSION_EYES_FREE_VIDEOGRAPHY">Camera<wbr/>Extension<wbr/>Characteristics#EXTENSION_<wbr/>EYES_<wbr/>FREE_<wbr/>VIDEOGRAPHY</a>
-extension in <a href="https://developer.android.com/reference/android/hardware/camera2/CameraMetadata.html#EFV_STABILIZATION_MODE_LOCKED">Camera<wbr/>Metadata#EFV_<wbr/>STABILIZATION_<wbr/>MODE_<wbr/>LOCKED</a> mode.<wbr/></p>
-            </td>
-
-            <td class="entry_units">
-            </td>
-
-            <td class="entry_range">
-              <p>The padding is the number of remaining pixels of padding in each direction
-when <a href="#controls_android.efv.autoZoom">android.<wbr/>efv.<wbr/>auto<wbr/>Zoom</a> is enabled.<wbr/> Negative values indicate the target region is out of bounds.<wbr/>
-The value for this key may be null for when the <a href="#controls_android.efv.autoZoom">android.<wbr/>efv.<wbr/>auto<wbr/>Zoom</a> is not enabled.<wbr/></p>
-            </td>
-
-            <td class="entry_hal_version">
-              <p>3.<wbr/>10</p>
-            </td>
-
-            <td class="entry_tags">
-            </td>
-
-          </tr>
-          <tr class="entries_header">
-            <th class="th_details" colspan="6">Details</th>
-          </tr>
-          <tr class="entry_cont">
-            <td class="entry_details" colspan="6">
-              <p>An array [left,<wbr/> top,<wbr/> right,<wbr/> bottom] of the padding in pixels remaining on all four sides
-before the target region starts to go out of bounds.<wbr/></p>
-<p>This may differ from <a href="#dynamic_android.efv.paddingRegion">android.<wbr/>efv.<wbr/>padding<wbr/>Region</a> as the field of view can change
-during <a href="#controls_android.efv.autoZoom">android.<wbr/>efv.<wbr/>auto<wbr/>Zoom</a>,<wbr/> altering the boundary region and thus updating the padding between the
-target region and the boundary.<wbr/></p>
-            </td>
-          </tr>
-
-
-          <tr class="entry_spacer"><td class="entry_spacer" colspan="7"></td></tr>
-           <!-- end of entry -->
-        
-                
-          <tr class="entry" id="dynamic_android.efv.targetCoordinates">
-            <td class="entry_name
-             " rowspan="3">
-              android.<wbr/>efv.<wbr/>target<wbr/>Coordinates
-            </td>
-            <td class="entry_type">
-                <span class="entry_type_name">float</span>
-                <span class="entry_type_container">x</span>
-
-                <span class="entry_type_array">
-                  4 x n
-                </span>
-              <span class="entry_type_visibility"> [extension as pointF]</span>
-
-
-
-
-
-
-            </td> <!-- entry_type -->
-
-            <td class="entry_description">
-              <p>List of coordinates representing the target region relative to the
-<a href="https://developer.android.com/reference/android/hardware/camera2/CameraCharacteristics.html#SENSOR_INFO_ACTIVE_ARRAY_SIZE">Camera<wbr/>Characteristics#SENSOR_<wbr/>INFO_<wbr/>ACTIVE_<wbr/>ARRAY_<wbr/>SIZE</a>
-for the
-<a href="https://developer.android.com/reference/android/hardware/camera2/CameraExtensionCharacteristics.html#EXTENSION_EYES_FREE_VIDEOGRAPHY">Camera<wbr/>Extension<wbr/>Characteristics#EXTENSION_<wbr/>EYES_<wbr/>FREE_<wbr/>VIDEOGRAPHY</a>
-extension in
-<a href="https://developer.android.com/reference/android/hardware/camera2/CameraMetadata.html#EFV_STABILIZATION_MODE_LOCKED">Camera<wbr/>Metadata#EFV_<wbr/>STABILIZATION_<wbr/>MODE_<wbr/>LOCKED</a> mode.<wbr/></p>
-            </td>
-
-            <td class="entry_units">
-            </td>
-
-            <td class="entry_range">
-              <p>The list of target coordinates will define a region within the bounds of the
-<a href="https://developer.android.com/reference/android/hardware/camera2/CameraCharacteristics.html#SENSOR_INFO_ACTIVE_ARRAY_SIZE">Camera<wbr/>Characteristics#SENSOR_<wbr/>INFO_<wbr/>ACTIVE_<wbr/>ARRAY_<wbr/>SIZE</a></p>
-            </td>
-
-            <td class="entry_hal_version">
-              <p>3.<wbr/>10</p>
-            </td>
-
-            <td class="entry_tags">
-            </td>
-
-          </tr>
-          <tr class="entries_header">
-            <th class="th_details" colspan="6">Details</th>
-          </tr>
-          <tr class="entry_cont">
-            <td class="entry_details" colspan="6">
-              <p>A list of android.<wbr/>graphics.<wbr/>Point<wbr/>F that define the coordinates of the target region
-relative to the
-<a href="https://developer.android.com/reference/android/hardware/camera2/CameraCharacteristics.html#SENSOR_INFO_ACTIVE_ARRAY_SIZE">Camera<wbr/>Characteristics#SENSOR_<wbr/>INFO_<wbr/>ACTIVE_<wbr/>ARRAY_<wbr/>SIZE</a>.<wbr/>
-The array represents the target region coordinates as: top-left,<wbr/> top-right,<wbr/> bottom-left,<wbr/>
-bottom-right.<wbr/></p>
-            </td>
-          </tr>
-
-
-          <tr class="entry_spacer"><td class="entry_spacer" colspan="7"></td></tr>
-           <!-- end of entry -->
-        
-                
-          <tr class="entry" id="dynamic_android.efv.paddingZoomFactor">
-            <td class="entry_name
-             " rowspan="3">
-              android.<wbr/>efv.<wbr/>padding<wbr/>Zoom<wbr/>Factor
-            </td>
-            <td class="entry_type">
-                <span class="entry_type_name">float</span>
-
-              <span class="entry_type_visibility"> [extension]</span>
-
-
-
-
-
-
-            </td> <!-- entry_type -->
-
-            <td class="entry_description">
-              <p>Used to apply an additional digital zoom factor for the
-<a href="https://developer.android.com/reference/android/hardware/camera2/CameraExtensionCharacteristics.html#EXTENSION_EYES_FREE_VIDEOGRAPHY">Camera<wbr/>Extension<wbr/>Characteristics#EXTENSION_<wbr/>EYES_<wbr/>FREE_<wbr/>VIDEOGRAPHY</a>
-extension in <a href="https://developer.android.com/reference/android/hardware/camera2/CameraMetadata.html#EFV_STABILIZATION_MODE_LOCKED">Camera<wbr/>Metadata#EFV_<wbr/>STABILIZATION_<wbr/>MODE_<wbr/>LOCKED</a> mode.<wbr/></p>
-            </td>
-
-            <td class="entry_units">
-            </td>
-
-            <td class="entry_range">
-              <p><a href="#static_android.efv.paddingZoomFactorRange">android.<wbr/>efv.<wbr/>padding<wbr/>Zoom<wbr/>Factor<wbr/>Range</a></p>
-            </td>
-
-            <td class="entry_hal_version">
-              <p>3.<wbr/>10</p>
-            </td>
-
-            <td class="entry_tags">
-            </td>
-
-          </tr>
-          <tr class="entries_header">
-            <th class="th_details" colspan="6">Details</th>
-          </tr>
-          <tr class="entry_cont">
-            <td class="entry_details" colspan="6">
-              <p>For the <a href="https://developer.android.com/reference/android/hardware/camera2/CameraExtensionCharacteristics.html#EXTENSION_EYES_FREE_VIDEOGRAPHY">Camera<wbr/>Extension<wbr/>Characteristics#EXTENSION_<wbr/>EYES_<wbr/>FREE_<wbr/>VIDEOGRAPHY</a>
-feature,<wbr/> an additional zoom factor is applied on top of the existing <a href="#controls_android.control.zoomRatio">android.<wbr/>control.<wbr/>zoom<wbr/>Ratio</a>.<wbr/>
-This additional zoom factor serves as a buffer to provide more flexibility for the
-<a href="https://developer.android.com/reference/android/hardware/camera2/CameraMetadata.html#EFV_STABILIZATION_MODE_LOCKED">Camera<wbr/>Metadata#EFV_<wbr/>STABILIZATION_<wbr/>MODE_<wbr/>LOCKED</a>
-mode.<wbr/> If <a href="#controls_android.efv.paddingZoomFactor">android.<wbr/>efv.<wbr/>padding<wbr/>Zoom<wbr/>Factor</a> is not set,<wbr/> the default will be used.<wbr/>
-The effectiveness of the stabilization may be influenced by the amount of padding zoom
-applied.<wbr/> A higher padding zoom factor can stabilize the target region more effectively
-with greater flexibility but may potentially impact image quality.<wbr/> Conversely,<wbr/> a lower
-padding zoom factor may be used to prioritize preserving image quality,<wbr/> albeit with less
-leeway in stabilizing the target region.<wbr/> It is recommended to set the
-<a href="#controls_android.efv.paddingZoomFactor">android.<wbr/>efv.<wbr/>padding<wbr/>Zoom<wbr/>Factor</a> to at least 1.<wbr/>5.<wbr/></p>
-<p>If <a href="#controls_android.efv.autoZoom">android.<wbr/>efv.<wbr/>auto<wbr/>Zoom</a> is enabled,<wbr/> the requested <a href="#controls_android.efv.paddingZoomFactor">android.<wbr/>efv.<wbr/>padding<wbr/>Zoom<wbr/>Factor</a> will be overridden.<wbr/>
-<a href="#controls_android.efv.maxPaddingZoomFactor">android.<wbr/>efv.<wbr/>max<wbr/>Padding<wbr/>Zoom<wbr/>Factor</a> can be checked for more details on controlling the
-padding zoom factor during <a href="#controls_android.efv.autoZoom">android.<wbr/>efv.<wbr/>auto<wbr/>Zoom</a>.<wbr/></p>
-            </td>
-          </tr>
-
-
-          <tr class="entry_spacer"><td class="entry_spacer" colspan="7"></td></tr>
-           <!-- end of entry -->
-        
-                
-          <tr class="entry" id="dynamic_android.efv.stabilizationMode">
-            <td class="entry_name
-             " rowspan="3">
-              android.<wbr/>efv.<wbr/>stabilization<wbr/>Mode
-            </td>
-            <td class="entry_type">
-                <span class="entry_type_name entry_type_name_enum">int32</span>
-
-              <span class="entry_type_visibility"> [extension]</span>
-
-
-
-
-
-                <ul class="entry_type_enum">
-                  <li>
-                    <span class="entry_type_enum_name">OFF (v3.10)</span>
-                    <span class="entry_type_enum_notes"><p>No stabilization.<wbr/></p></span>
-                  </li>
-                  <li>
-                    <span class="entry_type_enum_name">GIMBAL (v3.10)</span>
-                    <span class="entry_type_enum_notes"><p>Gimbal stabilization mode.<wbr/></p></span>
-                  </li>
-                  <li>
-                    <span class="entry_type_enum_name">LOCKED (v3.10)</span>
-                    <span class="entry_type_enum_notes"><p>Locked stabilization mode which uses the
-<a href="https://developer.android.com/reference/android/hardware/camera2/CameraExtensionCharacteristics.html#EXTENSION_EYES_FREE_VIDEOGRAPHY">Camera<wbr/>Extension<wbr/>Characteristics#EXTENSION_<wbr/>EYES_<wbr/>FREE_<wbr/>VIDEOGRAPHY</a>
-stabilization to directionally steady the target region.<wbr/></p></span>
-                  </li>
-                </ul>
-
-            </td> <!-- entry_type -->
-
-            <td class="entry_description">
-              <p>Set the stabilization mode for the
-<a href="https://developer.android.com/reference/android/hardware/camera2/CameraExtensionCharacteristics.html#EXTENSION_EYES_FREE_VIDEOGRAPHY">Camera<wbr/>Extension<wbr/>Characteristics#EXTENSION_<wbr/>EYES_<wbr/>FREE_<wbr/>VIDEOGRAPHY</a>
-extension</p>
-            </td>
-
-            <td class="entry_units">
-            </td>
-
-            <td class="entry_range">
-            </td>
-
-            <td class="entry_hal_version">
-              <p>3.<wbr/>10</p>
-            </td>
-
-            <td class="entry_tags">
-            </td>
-
-          </tr>
-          <tr class="entries_header">
-            <th class="th_details" colspan="6">Details</th>
-          </tr>
-          <tr class="entry_cont">
-            <td class="entry_details" colspan="6">
-              <p>The desired stabilization mode.<wbr/> Gimbal stabilization mode provides simple,<wbr/> non-locked
-video stabilization.<wbr/> Locked mode uses the
-<a href="https://developer.android.com/reference/android/hardware/camera2/CameraExtensionCharacteristics.html#EXTENSION_EYES_FREE_VIDEOGRAPHY">Camera<wbr/>Extension<wbr/>Characteristics#EXTENSION_<wbr/>EYES_<wbr/>FREE_<wbr/>VIDEOGRAPHY</a>
-stabilization feature to fixate on the current region,<wbr/> utilizing it as the target area for
-stabilization.<wbr/></p>
-            </td>
-          </tr>
-
-
-          <tr class="entry_spacer"><td class="entry_spacer" colspan="7"></td></tr>
-           <!-- end of entry -->
-        
-                
-          <tr class="entry" id="dynamic_android.efv.autoZoom">
-            <td class="entry_name
-             " rowspan="3">
-              android.<wbr/>efv.<wbr/>auto<wbr/>Zoom
-            </td>
-            <td class="entry_type">
-                <span class="entry_type_name entry_type_name_enum">byte</span>
-
-              <span class="entry_type_visibility"> [extension as boolean]</span>
-
-
-
-
-
-                <ul class="entry_type_enum">
-                  <li>
-                    <span class="entry_type_enum_name">TRUE (v3.10)</span>
-                  </li>
-                  <li>
-                    <span class="entry_type_enum_name">FALSE (v3.10)</span>
-                  </li>
-                </ul>
-
-            </td> <!-- entry_type -->
-
-            <td class="entry_description">
-              <p>Used to enable or disable auto zoom for the
-<a href="https://developer.android.com/reference/android/hardware/camera2/CameraExtensionCharacteristics.html#EXTENSION_EYES_FREE_VIDEOGRAPHY">Camera<wbr/>Extension<wbr/>Characteristics#EXTENSION_<wbr/>EYES_<wbr/>FREE_<wbr/>VIDEOGRAPHY</a>
-extension in <a href="https://developer.android.com/reference/android/hardware/camera2/CameraMetadata.html#EFV_STABILIZATION_MODE_LOCKED">Camera<wbr/>Metadata#EFV_<wbr/>STABILIZATION_<wbr/>MODE_<wbr/>LOCKED</a> mode.<wbr/></p>
-            </td>
-
-            <td class="entry_units">
-            </td>
-
-            <td class="entry_range">
-            </td>
-
-            <td class="entry_hal_version">
-              <p>3.<wbr/>10</p>
-            </td>
-
-            <td class="entry_tags">
-            </td>
-
-          </tr>
-          <tr class="entries_header">
-            <th class="th_details" colspan="6">Details</th>
-          </tr>
-          <tr class="entry_cont">
-            <td class="entry_details" colspan="6">
-              <p>Turn on auto zoom to let the
-<a href="https://developer.android.com/reference/android/hardware/camera2/CameraExtensionCharacteristics.html#EXTENSION_EYES_FREE_VIDEOGRAPHY">Camera<wbr/>Extension<wbr/>Characteristics#EXTENSION_<wbr/>EYES_<wbr/>FREE_<wbr/>VIDEOGRAPHY</a>
-feature decide at any given point a combination of
-<a href="#controls_android.control.zoomRatio">android.<wbr/>control.<wbr/>zoom<wbr/>Ratio</a> and <a href="#controls_android.efv.paddingZoomFactor">android.<wbr/>efv.<wbr/>padding<wbr/>Zoom<wbr/>Factor</a>
-to keep the target region in view and stabilized.<wbr/> The combination chosen by the
-<a href="https://developer.android.com/reference/android/hardware/camera2/CameraExtensionCharacteristics.html#EXTENSION_EYES_FREE_VIDEOGRAPHY">Camera<wbr/>Extension<wbr/>Characteristics#EXTENSION_<wbr/>EYES_<wbr/>FREE_<wbr/>VIDEOGRAPHY</a>
-will equal the requested <a href="#controls_android.control.zoomRatio">android.<wbr/>control.<wbr/>zoom<wbr/>Ratio</a> multiplied with the requested
-<a href="#controls_android.efv.paddingZoomFactor">android.<wbr/>efv.<wbr/>padding<wbr/>Zoom<wbr/>Factor</a>.<wbr/> A limit can be set on the padding zoom if wanting
-to control image quality further using <a href="#controls_android.efv.maxPaddingZoomFactor">android.<wbr/>efv.<wbr/>max<wbr/>Padding<wbr/>Zoom<wbr/>Factor</a>.<wbr/></p>
-            </td>
-          </tr>
-
-
-          <tr class="entry_spacer"><td class="entry_spacer" colspan="7"></td></tr>
-           <!-- end of entry -->
-        
-                
-          <tr class="entry" id="dynamic_android.efv.rotateViewport">
-            <td class="entry_name
-             " rowspan="3">
-              android.<wbr/>efv.<wbr/>rotate<wbr/>Viewport
-            </td>
-            <td class="entry_type">
-                <span class="entry_type_name">float</span>
-
-              <span class="entry_type_visibility"> [extension]</span>
-
-
-
-
-
-
-            </td> <!-- entry_type -->
-
-            <td class="entry_description">
-              <p>Representing the desired clockwise rotation
-of the target region in degrees for the
-<a href="https://developer.android.com/reference/android/hardware/camera2/CameraExtensionCharacteristics.html#EXTENSION_EYES_FREE_VIDEOGRAPHY">Camera<wbr/>Extension<wbr/>Characteristics#EXTENSION_<wbr/>EYES_<wbr/>FREE_<wbr/>VIDEOGRAPHY</a>
-extension in <a href="https://developer.android.com/reference/android/hardware/camera2/CameraMetadata.html#EFV_STABILIZATION_MODE_LOCKED">Camera<wbr/>Metadata#EFV_<wbr/>STABILIZATION_<wbr/>MODE_<wbr/>LOCKED</a> mode.<wbr/></p>
-            </td>
-
-            <td class="entry_units">
-            </td>
-
-            <td class="entry_range">
-              <p>0 to 360</p>
-            </td>
-
-            <td class="entry_hal_version">
-              <p>3.<wbr/>10</p>
-            </td>
-
-            <td class="entry_tags">
-            </td>
-
-          </tr>
-          <tr class="entries_header">
-            <th class="th_details" colspan="6">Details</th>
-          </tr>
-          <tr class="entry_cont">
-            <td class="entry_details" colspan="6">
-              <p>Value representing the desired clockwise rotation of the target
-region in degrees.<wbr/></p>
-            </td>
-          </tr>
-
-
-          <tr class="entry_spacer"><td class="entry_spacer" colspan="7"></td></tr>
-           <!-- end of entry -->
-        
-                
-          <tr class="entry" id="dynamic_android.efv.translateViewport">
-            <td class="entry_name
-             " rowspan="3">
-              android.<wbr/>efv.<wbr/>translate<wbr/>Viewport
-            </td>
-            <td class="entry_type">
-                <span class="entry_type_name">int32</span>
-
-              <span class="entry_type_visibility"> [extension as pairIntegerInteger]</span>
-
-
-
-
-
-
-            </td> <!-- entry_type -->
-
-            <td class="entry_description">
-              <p>Used to update the target region for the
-<a href="https://developer.android.com/reference/android/hardware/camera2/CameraExtensionCharacteristics.html#EXTENSION_EYES_FREE_VIDEOGRAPHY">Camera<wbr/>Extension<wbr/>Characteristics#EXTENSION_<wbr/>EYES_<wbr/>FREE_<wbr/>VIDEOGRAPHY</a>
-extension in <a href="https://developer.android.com/reference/android/hardware/camera2/CameraMetadata.html#EFV_STABILIZATION_MODE_LOCKED">Camera<wbr/>Metadata#EFV_<wbr/>STABILIZATION_<wbr/>MODE_<wbr/>LOCKED</a> mode.<wbr/></p>
-            </td>
-
-            <td class="entry_units">
-            </td>
-
-            <td class="entry_range">
-              <p>android.<wbr/>util.<wbr/>Pair<integer,integer> represents the
-<horizontal,vertical> shift.<wbr/> The range for the horizontal shift is
-[-max(<a href="#dynamic_android.efv.paddingRegion">android.<wbr/>efv.<wbr/>padding<wbr/>Region</a>-left),<wbr/> max(<a href="#dynamic_android.efv.paddingRegion">android.<wbr/>efv.<wbr/>padding<wbr/>Region</a>-right)].<wbr/>
-The range for the vertical shift is
-[-max(<a href="#dynamic_android.efv.paddingRegion">android.<wbr/>efv.<wbr/>padding<wbr/>Region</a>-top),<wbr/> max(<a href="#dynamic_android.efv.paddingRegion">android.<wbr/>efv.<wbr/>padding<wbr/>Region</a>-bottom)]</horizontal,vertical></integer,integer></p>
-            </td>
-
-            <td class="entry_hal_version">
-              <p>3.<wbr/>10</p>
-            </td>
-
-            <td class="entry_tags">
-            </td>
-
-          </tr>
-          <tr class="entries_header">
-            <th class="th_details" colspan="6">Details</th>
-          </tr>
-          <tr class="entry_cont">
-            <td class="entry_details" colspan="6">
-              <p>A android.<wbr/>util.<wbr/>Pair<integer,integer> that represents the desired
-<horizontal,vertical> shift of the current locked view (or target region) in
-pixels.<wbr/> Negative values indicate left and upward shifts,<wbr/> while positive values indicate
-right and downward shifts in the active array coordinate system.<wbr/></horizontal,vertical></integer,integer></p>
-            </td>
-          </tr>
-
-
-          <tr class="entry_spacer"><td class="entry_spacer" colspan="7"></td></tr>
-           <!-- end of entry -->
-        
-                
-          <tr class="entry" id="dynamic_android.efv.maxPaddingZoomFactor">
-            <td class="entry_name
-             " rowspan="3">
-              android.<wbr/>efv.<wbr/>max<wbr/>Padding<wbr/>Zoom<wbr/>Factor
-            </td>
-            <td class="entry_type">
-                <span class="entry_type_name">float</span>
-
-              <span class="entry_type_visibility"> [extension]</span>
-
-
-
-
-
-
-            </td> <!-- entry_type -->
-
-            <td class="entry_description">
-              <p>Used to limit the <a href="#controls_android.efv.paddingZoomFactor">android.<wbr/>efv.<wbr/>padding<wbr/>Zoom<wbr/>Factor</a> if
-<a href="#controls_android.efv.autoZoom">android.<wbr/>efv.<wbr/>auto<wbr/>Zoom</a> is enabled for the
-<a href="https://developer.android.com/reference/android/hardware/camera2/CameraExtensionCharacteristics.html#EXTENSION_EYES_FREE_VIDEOGRAPHY">Camera<wbr/>Extension<wbr/>Characteristics#EXTENSION_<wbr/>EYES_<wbr/>FREE_<wbr/>VIDEOGRAPHY</a>
-extension in <a href="https://developer.android.com/reference/android/hardware/camera2/CameraMetadata.html#EFV_STABILIZATION_MODE_LOCKED">Camera<wbr/>Metadata#EFV_<wbr/>STABILIZATION_<wbr/>MODE_<wbr/>LOCKED</a> mode.<wbr/></p>
-            </td>
-
-            <td class="entry_units">
-            </td>
-
-            <td class="entry_range">
-              <p>The range of <a href="#static_android.efv.paddingZoomFactorRange">android.<wbr/>efv.<wbr/>padding<wbr/>Zoom<wbr/>Factor<wbr/>Range</a>.<wbr/> Use a value greater than or equal to
-the <a href="#controls_android.efv.paddingZoomFactor">android.<wbr/>efv.<wbr/>padding<wbr/>Zoom<wbr/>Factor</a> to effectively utilize this key.<wbr/></p>
-            </td>
-
-            <td class="entry_hal_version">
-              <p>3.<wbr/>10</p>
-            </td>
-
-            <td class="entry_tags">
-            </td>
-
-          </tr>
-          <tr class="entries_header">
-            <th class="th_details" colspan="6">Details</th>
-          </tr>
-          <tr class="entry_cont">
-            <td class="entry_details" colspan="6">
-              <p>If <a href="#controls_android.efv.autoZoom">android.<wbr/>efv.<wbr/>auto<wbr/>Zoom</a> is enabled,<wbr/> this key can be used to set a limit
-on the <a href="#controls_android.efv.paddingZoomFactor">android.<wbr/>efv.<wbr/>padding<wbr/>Zoom<wbr/>Factor</a> chosen by the
-<a href="https://developer.android.com/reference/android/hardware/camera2/CameraExtensionCharacteristics.html#EXTENSION_EYES_FREE_VIDEOGRAPHY">Camera<wbr/>Extension<wbr/>Characteristics#EXTENSION_<wbr/>EYES_<wbr/>FREE_<wbr/>VIDEOGRAPHY</a>
-extension in <a href="https://developer.android.com/reference/android/hardware/camera2/CameraMetadata.html#EFV_STABILIZATION_MODE_LOCKED">Camera<wbr/>Metadata#EFV_<wbr/>STABILIZATION_<wbr/>MODE_<wbr/>LOCKED</a> mode
-to control image quality.<wbr/></p>
-            </td>
-          </tr>
-
-
-          <tr class="entry_spacer"><td class="entry_spacer" colspan="7"></td></tr>
-           <!-- end of entry -->
-        
-        
-
       <!-- end of kind -->
       </tbody>
 
diff --git a/camera/docs/metadata_definitions.xml b/camera/docs/metadata_definitions.xml
index a006edde..0e11e293 100644
--- a/camera/docs/metadata_definitions.xml
+++ b/camera/docs/metadata_definitions.xml
@@ -935,9 +935,14 @@ xsi:schemaLocation="http://schemas.android.com/service/camera/metadata/ metadata
           scene brightness and required final capture flash power, when
           the flash is enabled.
 
-          Normally, this entry should be set to START for only a
-          single request, and the application should wait until the
-          sequence completes before starting a new one.
+          Flash is enabled during precapture sequence when:
+
+          * AE mode is ON_ALWAYS_FLASH
+          * AE mode is ON_AUTO_FLASH and the scene is deemed too dark without flash, or
+          * AE mode is ON and flash mode is TORCH or SINGLE
+
+          Normally, this entry should be set to START for only single request, and the
+          application should wait until the sequence completes before starting a new one.
 
           When a precapture metering sequence is finished, the camera device
           may lock the auto-exposure routine internally to be able to accurately expose the
@@ -3952,9 +3957,6 @@ xsi:schemaLocation="http://schemas.android.com/service/camera/metadata/ metadata
             This state indicates when low light boost is 'ACTIVE' and applied. Similarly, it can
             indicate when it is not being applied by returning 'INACTIVE'.
 
-            This key will be absent from the CaptureResult if AE mode is not set to
-            'ON_LOW_LIGHT_BOOST_BRIGHTNESS_PRIORITY.
-
             The default value will always be 'INACTIVE'.
           </details>
         </entry>
@@ -4273,7 +4275,7 @@ xsi:schemaLocation="http://schemas.android.com/service/camera/metadata/ metadata
       </dynamic>
       <controls>
         <entry name="strengthLevel" type="int32" visibility="public" hwlevel="legacy"
-          aconfig_flag="camera_manual_flash_strength_control" hal_version="3.10">
+          hal_version="3.10">
           <description>Flash strength level to be used when manual flash control is active.
           </description>
           <range>`[1-android.flash.torchStrengthMaxLevel]` when the android.flash.mode is
@@ -4305,12 +4307,20 @@ xsi:schemaLocation="http://schemas.android.com/service/camera/metadata/ metadata
             in android.flash.singleStrengthDefaultLevel.
             If android.control.aeMode is set to any of `ON_AUTO_FLASH`, `ON_ALWAYS_FLASH`,
             `ON_AUTO_FLASH_REDEYE`, `ON_EXTERNAL_FLASH` values, then the strengthLevel will be ignored.
+
+            When AE mode is ON and flash mode is TORCH or SINGLE, the application should make sure
+            the AE mode, flash mode, and flash strength level remain the same between precapture
+            trigger request and final capture request. The flash strength level being set during
+            precapture sequence is used by the camera device as a reference. The actual strength
+            may be less, and the auto-exposure routine makes sure proper conversions of sensor
+            exposure time and sensitivities between precapture and final capture for the specified
+            strength level.
           </details>
         </entry>
       </controls>
       <static>
-        <entry name="singleStrengthMaxLevel" type="int32" visibility="public" hwlevel="legacy"
-               aconfig_flag="camera_manual_flash_strength_control" hal_version="3.10">
+        <entry name="singleStrengthMaxLevel" type="int32" visibility="public"
+          hwlevel="legacy" hal_version="3.10">
           <description>Maximum flash brightness level for manual flash control in `SINGLE` mode.
           </description>
           <details>
@@ -4322,8 +4332,8 @@ xsi:schemaLocation="http://schemas.android.com/service/camera/metadata/ metadata
             There is no actual physical power units tied to this level.
           </details>
         </entry>
-        <entry name="singleStrengthDefaultLevel" type="int32" visibility="public" hwlevel="legacy"
-               aconfig_flag="camera_manual_flash_strength_control" hal_version="3.10">
+        <entry name="singleStrengthDefaultLevel" type="int32"
+          visibility="public" hwlevel="legacy" hal_version="3.10">
           <description>Default flash brightness level for manual flash control in `SINGLE` mode.
           </description>
           <details>
@@ -4333,8 +4343,8 @@ xsi:schemaLocation="http://schemas.android.com/service/camera/metadata/ metadata
             feature, this level will always be equal to 1.
           </details>
         </entry>
-        <entry name="torchStrengthMaxLevel" type="int32" visibility="public" hwlevel="legacy"
-               aconfig_flag="camera_manual_flash_strength_control" hal_version="3.10">
+        <entry name="torchStrengthMaxLevel" type="int32" visibility="public"
+          hwlevel="legacy" hal_version="3.10">
           <description>Maximum flash brightness level for manual flash control in `TORCH` mode
           </description>
           <details>
@@ -4351,8 +4361,8 @@ xsi:schemaLocation="http://schemas.android.com/service/camera/metadata/ metadata
             is not guaranteed to be the ratio of actual brightness.
           </details>
         </entry>
-        <entry name="torchStrengthDefaultLevel" type="int32" visibility="public" hwlevel="legacy"
-               aconfig_flag="camera_manual_flash_strength_control" hal_version="3.10">
+        <entry name="torchStrengthDefaultLevel" type="int32" visibility="public"
+          hwlevel="legacy" hal_version="3.10">
           <description>Default flash brightness level for manual flash control in `TORCH` mode
           </description>
           <details>
@@ -12272,7 +12282,7 @@ xsi:schemaLocation="http://schemas.android.com/service/camera/metadata/ metadata
           </details>
         </entry>
         <entry name="lensIntrinsicsSamples" type="float" visibility="java_public" synthetic="true"
-               container="array" typedef="lensIntrinsicsSample" aconfig_flag="concert_mode"
+               container="array" typedef="lensIntrinsicsSample"
                hal_version="3.10">
           <array>
             <size>n</size>
@@ -12294,7 +12304,7 @@ xsi:schemaLocation="http://schemas.android.com/service/camera/metadata/ metadata
           </details>
         </entry>
         <entry name="lensIntrinsicTimestamps" type="int64" visibility="ndk_public" container="array"
-               aconfig_flag="concert_mode" hal_version="3.10">
+               hal_version="3.10">
           <array>
             <size>n</size>
           </array>
@@ -12308,7 +12318,7 @@ xsi:schemaLocation="http://schemas.android.com/service/camera/metadata/ metadata
           </details>
         </entry>
         <entry name="lensIntrinsicSamples" type="float" visibility="ndk_public"
-               container="array" aconfig_flag="concert_mode" hal_version="3.10">
+               container="array" hal_version="3.10">
           <array>
             <size>5</size>
             <size>n</size>
@@ -13026,8 +13036,7 @@ xsi:schemaLocation="http://schemas.android.com/service/camera/metadata/ metadata
         </entry>
         <entry name="sessionConfigurationQueryVersion" type="int32"
           visibility="fwk_java_public" enum="true" typedef="versionCode"
-          hwlevel="legacy" aconfig_flag="feature_combination_query"
-          hal_version="3.10">
+          hwlevel="legacy" hal_version="3.10">
           <enum>
             <value id="34">UPSIDE_DOWN_CAKE</value>
             <value id="35">VANILLA_ICE_CREAM</value>
@@ -13959,7 +13968,7 @@ xsi:schemaLocation="http://schemas.android.com/service/camera/metadata/ metadata
         <tag id="LOGICALCAMERA" />
       </entry>
       <entry name="activePhysicalSensorCropRegion" type="int32" visibility="public"
-             container="array" typedef="rectangle" aconfig_flag="concert_mode" hal_version="3.10">
+             container="array" typedef="rectangle" hal_version="3.10">
         <array>
           <size>4</size>
         </array>
@@ -14779,247 +14788,5 @@ xsi:schemaLocation="http://schemas.android.com/service/camera/metadata/ metadata
         </entry>
       </static>
     </section>
-    <section name="efv">
-      <static>
-        <entry name="paddingZoomFactorRange" type="float" visibility="extension"
-            optional="true" container="array" typedef="rangeFloat" aconfig_flag="concert_mode_api"
-            hal_version="3.10">
-          <array>
-            <size>2</size>
-          </array>
-          <description>
-          Minimum and maximum padding zoom factors supported by this camera device for
-          android.efv.paddingZoomFactor used for the
-          {@link android.hardware.camera2.CameraExtensionCharacteristics#EXTENSION_EYES_FREE_VIDEOGRAPHY}
-          extension.
-          </description>
-          <units>A pair of padding zoom factors in floating-points:
-          (minPaddingZoomFactor, maxPaddingZoomFactor)</units>
-          <range>
-            1.0 &lt; minPaddingZoomFactor &lt;= maxPaddingZoomFactor
-          </range>
-          <details>
-          The minimum and maximum padding zoom factors supported by the device for
-          android.efv.paddingZoomFactor used as part of the
-          {@link android.hardware.camera2.CameraExtensionCharacteristics#EXTENSION_EYES_FREE_VIDEOGRAPHY}
-          extension feature. This extension specific camera characteristic can be queried using
-          {@link android.hardware.camera2.CameraExtensionCharacteristics#get}.
-          </details>
-        </entry>
-      </static>
-      <controls>
-        <entry name="paddingZoomFactor" type="float" visibility="extension"
-            aconfig_flag="concert_mode_api" hal_version="3.10">
-          <description>Used to apply an additional digital zoom factor for the
-          {@link android.hardware.camera2.CameraExtensionCharacteristics#EXTENSION_EYES_FREE_VIDEOGRAPHY}
-          extension in {@link android.hardware.camera2.CameraMetadata#EFV_STABILIZATION_MODE_LOCKED} mode.
-          </description>
-          <range>android.efv.paddingZoomFactorRange</range>
-          <details>
-          For the {@link android.hardware.camera2.CameraExtensionCharacteristics#EXTENSION_EYES_FREE_VIDEOGRAPHY}
-          feature, an additional zoom factor is applied on top of the existing android.control.zoomRatio.
-          This additional zoom factor serves as a buffer to provide more flexibility for the
-          {@link android.hardware.camera2.CameraMetadata#EFV_STABILIZATION_MODE_LOCKED}
-          mode. If android.efv.paddingZoomFactor is not set, the default will be used.
-          The effectiveness of the stabilization may be influenced by the amount of padding zoom
-          applied. A higher padding zoom factor can stabilize the target region more effectively
-          with greater flexibility but may potentially impact image quality. Conversely, a lower
-          padding zoom factor may be used to prioritize preserving image quality, albeit with less
-          leeway in stabilizing the target region. It is recommended to set the
-          android.efv.paddingZoomFactor to at least 1.5.
-
-          If android.efv.autoZoom is enabled, the requested android.efv.paddingZoomFactor will be overridden.
-          android.efv.maxPaddingZoomFactor can be checked for more details on controlling the
-          padding zoom factor during android.efv.autoZoom.
-          </details>
-        </entry>
-        <entry name="autoZoom" type="byte" visibility="extension" enum="true"
-            typedef="boolean" aconfig_flag="concert_mode_api" hal_version="3.10">
-          <enum>
-            <value>TRUE</value>
-            <value>FALSE</value>
-          </enum>
-          <description>Used to enable or disable auto zoom for the
-          {@link android.hardware.camera2.CameraExtensionCharacteristics#EXTENSION_EYES_FREE_VIDEOGRAPHY}
-          extension in {@link android.hardware.camera2.CameraMetadata#EFV_STABILIZATION_MODE_LOCKED} mode.
-          </description>
-          <details>
-          Turn on auto zoom to let the
-          {@link android.hardware.camera2.CameraExtensionCharacteristics#EXTENSION_EYES_FREE_VIDEOGRAPHY}
-          feature decide at any given point a combination of
-          android.control.zoomRatio and android.efv.paddingZoomFactor
-          to keep the target region in view and stabilized. The combination chosen by the
-          {@link android.hardware.camera2.CameraExtensionCharacteristics#EXTENSION_EYES_FREE_VIDEOGRAPHY}
-          will equal the requested android.control.zoomRatio multiplied with the requested
-          android.efv.paddingZoomFactor. A limit can be set on the padding zoom if wanting
-          to control image quality further using android.efv.maxPaddingZoomFactor.
-          </details>
-        </entry>
-        <entry name="maxPaddingZoomFactor" type="float" visibility="extension"
-            aconfig_flag="concert_mode_api" hal_version="3.10">
-          <description>Used to limit the android.efv.paddingZoomFactor if
-          android.efv.autoZoom is enabled for the
-          {@link android.hardware.camera2.CameraExtensionCharacteristics#EXTENSION_EYES_FREE_VIDEOGRAPHY}
-          extension in {@link android.hardware.camera2.CameraMetadata#EFV_STABILIZATION_MODE_LOCKED} mode.
-          </description>
-          <range>The range of android.efv.paddingZoomFactorRange. Use a value greater than or equal to
-          the android.efv.paddingZoomFactor to effectively utilize this key.</range>
-          <details>
-          If android.efv.autoZoom is enabled, this key can be used to set a limit
-          on the android.efv.paddingZoomFactor chosen by the
-          {@link android.hardware.camera2.CameraExtensionCharacteristics#EXTENSION_EYES_FREE_VIDEOGRAPHY}
-          extension in {@link android.hardware.camera2.CameraMetadata#EFV_STABILIZATION_MODE_LOCKED} mode
-          to control image quality.
-          </details>
-        </entry>
-        <entry name="stabilizationMode" type="int32" visibility="extension" enum="true"
-            aconfig_flag="concert_mode_api" hal_version="3.10">
-          <enum>
-            <value>OFF
-              <notes>
-                No stabilization.
-              </notes></value>
-            <value>GIMBAL
-              <notes>
-                Gimbal stabilization mode.
-              </notes></value>
-            <value>LOCKED
-              <notes>
-                Locked stabilization mode which uses the
-                {@link android.hardware.camera2.CameraExtensionCharacteristics#EXTENSION_EYES_FREE_VIDEOGRAPHY}
-                stabilization to directionally steady the target region.
-              </notes></value>
-          </enum>
-          <description>Set the stabilization mode for the
-          {@link android.hardware.camera2.CameraExtensionCharacteristics#EXTENSION_EYES_FREE_VIDEOGRAPHY}
-          extension
-          </description>
-          <details>
-          The desired stabilization mode. Gimbal stabilization mode provides simple, non-locked
-          video stabilization. Locked mode uses the
-          {@link android.hardware.camera2.CameraExtensionCharacteristics#EXTENSION_EYES_FREE_VIDEOGRAPHY}
-          stabilization feature to fixate on the current region, utilizing it as the target area for
-          stabilization.
-          </details>
-        </entry>
-        <entry name="translateViewport" type="int32" visibility="extension"
-            typedef="pairIntegerInteger" aconfig_flag="concert_mode_api" hal_version="3.10">
-          <description>Used to update the target region for the
-          {@link android.hardware.camera2.CameraExtensionCharacteristics#EXTENSION_EYES_FREE_VIDEOGRAPHY}
-          extension in {@link android.hardware.camera2.CameraMetadata#EFV_STABILIZATION_MODE_LOCKED} mode.
-          </description>
-          <range>android.util.Pair&lt;Integer,Integer&gt; represents the
-          &lt;Horizontal,Vertical&gt; shift. The range for the horizontal shift is
-          [-max(android.efv.paddingRegion-left), max(android.efv.paddingRegion-right)].
-          The range for the vertical shift is
-          [-max(android.efv.paddingRegion-top), max(android.efv.paddingRegion-bottom)]
-          </range>
-          <details>
-          A android.util.Pair&lt;Integer,Integer&gt; that represents the desired
-          &lt;Horizontal,Vertical&gt; shift of the current locked view (or target region) in
-          pixels. Negative values indicate left and upward shifts, while positive values indicate
-          right and downward shifts in the active array coordinate system.
-          </details>
-        </entry>
-        <entry name="rotateViewport" type="float" visibility="extension"
-            aconfig_flag="concert_mode_api" hal_version="3.10">
-          <description>Representing the desired clockwise rotation
-          of the target region in degrees for the
-          {@link android.hardware.camera2.CameraExtensionCharacteristics#EXTENSION_EYES_FREE_VIDEOGRAPHY}
-          extension in {@link android.hardware.camera2.CameraMetadata#EFV_STABILIZATION_MODE_LOCKED} mode.
-          </description>
-          <range>0 to 360
-          </range>
-          <details>
-          Value representing the desired clockwise rotation of the target
-          region in degrees.
-          </details>
-        </entry>
-      </controls>
-      <dynamic>
-        <entry name="paddingRegion" type="int32" visibility="extension" container="array"
-            aconfig_flag="concert_mode_api" hal_version="3.10">
-          <array>
-            <size>4</size>
-          </array>
-          <description>The padding region for the
-          {@link android.hardware.camera2.CameraExtensionCharacteristics#EXTENSION_EYES_FREE_VIDEOGRAPHY}
-          extension in {@link android.hardware.camera2.CameraMetadata#EFV_STABILIZATION_MODE_LOCKED} mode.
-          </description>
-          <range>The padding is the number of remaining pixels of padding in each direction.
-          The pixels reference the active array coordinate system. Negative values indicate the target
-          region is out of bounds. The value for this key may be null for when the stabilization mode is
-          in {@link android.hardware.camera2.CameraMetadata#EFV_STABILIZATION_MODE_OFF}
-          or {@link android.hardware.camera2.CameraMetadata#EFV_STABILIZATION_MODE_GIMBAL} mode.
-          </range>
-          <details>
-          An array [left, top, right, bottom] of the padding in pixels remaining on all four sides
-          before the target region starts to go out of bounds.
-
-          The padding region denotes the area surrounding the stabilized target region within which
-          the camera can be moved while maintaining the target region in view. As the camera moves,
-          the padding region adjusts to represent the proximity of the target region to the
-          boundary, which is the point at which the target region will start to go out of bounds.
-          </details>
-        </entry>
-        <entry name="autoZoomPaddingRegion" type="int32" visibility="extension"
-            container="array" aconfig_flag="concert_mode_api" hal_version="3.10">
-          <array>
-            <size>4</size>
-          </array>
-          <description>The padding region when android.efv.autoZoom is enabled for the
-          {@link android.hardware.camera2.CameraExtensionCharacteristics#EXTENSION_EYES_FREE_VIDEOGRAPHY}
-          extension in {@link android.hardware.camera2.CameraMetadata#EFV_STABILIZATION_MODE_LOCKED} mode.
-          </description>
-          <range>The padding is the number of remaining pixels of padding in each direction
-          when android.efv.autoZoom is enabled. Negative values indicate the target region is out of bounds.
-          The value for this key may be null for when the android.efv.autoZoom is not enabled.</range>
-          <details>
-          An array [left, top, right, bottom] of the padding in pixels remaining on all four sides
-          before the target region starts to go out of bounds.
-
-          This may differ from android.efv.paddingRegion as the field of view can change
-          during android.efv.autoZoom, altering the boundary region and thus updating the padding between the
-          target region and the boundary.
-          </details>
-        </entry>
-        <entry name="targetCoordinates" type="float" visibility="extension"
-            container="array" typedef="pointF" aconfig_flag="concert_mode_api" hal_version="3.10">
-          <array>
-            <size>4</size>
-            <size>n</size>
-          </array>
-          <description>List of coordinates representing the target region relative to the
-          {@link android.hardware.camera2.CameraCharacteristics#SENSOR_INFO_ACTIVE_ARRAY_SIZE}
-          for the
-          {@link android.hardware.camera2.CameraExtensionCharacteristics#EXTENSION_EYES_FREE_VIDEOGRAPHY}
-          extension in
-          {@link android.hardware.camera2.CameraMetadata#EFV_STABILIZATION_MODE_LOCKED} mode.
-          </description>
-          <range>The list of target coordinates will define a region within the bounds of the
-          {@link android.hardware.camera2.CameraCharacteristics#SENSOR_INFO_ACTIVE_ARRAY_SIZE}
-          </range>
-          <details>
-          A list of android.graphics.PointF that define the coordinates of the target region
-          relative to the
-          {@link android.hardware.camera2.CameraCharacteristics#SENSOR_INFO_ACTIVE_ARRAY_SIZE}.
-          The array represents the target region coordinates as: top-left, top-right, bottom-left,
-          bottom-right.
-          </details>
-        </entry>
-        <clone entry="android.efv.paddingZoomFactor" kind="controls">
-        </clone>
-        <clone entry="android.efv.stabilizationMode" kind="controls">
-        </clone>
-        <clone entry="android.efv.autoZoom" kind="controls">
-        </clone>
-        <clone entry="android.efv.rotateViewport" kind="controls">
-        </clone>
-        <clone entry="android.efv.translateViewport" kind="controls">
-        </clone>
-        <clone entry="android.efv.maxPaddingZoomFactor" kind="controls">
-        </clone>
-      </dynamic>
-    </section>
   </namespace>
 </metadata>
diff --git a/camera/include/system/camera_metadata_tags.h b/camera/include/system/camera_metadata_tags.h
index 20e84256..76c36588 100644
--- a/camera/include/system/camera_metadata_tags.h
+++ b/camera/include/system/camera_metadata_tags.h
@@ -69,7 +69,6 @@ typedef enum camera_metadata_section {
     ANDROID_AUTOMOTIVE_LENS,
     ANDROID_EXTENSION,
     ANDROID_JPEGR,
-    ANDROID_EFV,
     ANDROID_SECTION_COUNT,
 
     VENDOR_SECTION = 0x8000
@@ -118,7 +117,6 @@ typedef enum camera_metadata_section_start {
     ANDROID_AUTOMOTIVE_LENS_START  = ANDROID_AUTOMOTIVE_LENS   << 16,
     ANDROID_EXTENSION_START        = ANDROID_EXTENSION         << 16,
     ANDROID_JPEGR_START            = ANDROID_JPEGR             << 16,
-    ANDROID_EFV_START              = ANDROID_EFV               << 16,
     VENDOR_SECTION_START           = VENDOR_SECTION            << 16
 } camera_metadata_section_start_t;
 
@@ -603,19 +601,6 @@ typedef enum camera_metadata_tag {
                                                       // int64[]      | ndk_public   | HIDL v3.9
     ANDROID_JPEGR_END,
 
-    ANDROID_EFV_PADDING_ZOOM_FACTOR_RANGE =           // float[]      | extension    | HIDL v3.10
-            ANDROID_EFV_START,
-    ANDROID_EFV_PADDING_ZOOM_FACTOR,                  // float        | extension    | HIDL v3.10
-    ANDROID_EFV_AUTO_ZOOM,                            // enum         | extension    | HIDL v3.10
-    ANDROID_EFV_MAX_PADDING_ZOOM_FACTOR,              // float        | extension    | HIDL v3.10
-    ANDROID_EFV_STABILIZATION_MODE,                   // enum         | extension    | HIDL v3.10
-    ANDROID_EFV_TRANSLATE_VIEWPORT,                   // int32        | extension    | HIDL v3.10
-    ANDROID_EFV_ROTATE_VIEWPORT,                      // float        | extension    | HIDL v3.10
-    ANDROID_EFV_PADDING_REGION,                       // int32[]      | extension    | HIDL v3.10
-    ANDROID_EFV_AUTO_ZOOM_PADDING_REGION,             // int32[]      | extension    | HIDL v3.10
-    ANDROID_EFV_TARGET_COORDINATES,                   // float[]      | extension    | HIDL v3.10
-    ANDROID_EFV_END,
-
 } camera_metadata_tag_t;
 
 /**
@@ -1491,17 +1476,3 @@ typedef enum camera_metadata_enum_android_jpegr_available_jpeg_r_stream_configur
 } camera_metadata_enum_android_jpegr_available_jpeg_r_stream_configurations_maximum_resolution_t;
 
 
-// ANDROID_EFV_AUTO_ZOOM
-typedef enum camera_metadata_enum_android_efv_auto_zoom {
-    ANDROID_EFV_AUTO_ZOOM_TRUE                                      , // HIDL v3.10
-    ANDROID_EFV_AUTO_ZOOM_FALSE                                     , // HIDL v3.10
-} camera_metadata_enum_android_efv_auto_zoom_t;
-
-// ANDROID_EFV_STABILIZATION_MODE
-typedef enum camera_metadata_enum_android_efv_stabilization_mode {
-    ANDROID_EFV_STABILIZATION_MODE_OFF                              , // HIDL v3.10
-    ANDROID_EFV_STABILIZATION_MODE_GIMBAL                           , // HIDL v3.10
-    ANDROID_EFV_STABILIZATION_MODE_LOCKED                           , // HIDL v3.10
-} camera_metadata_enum_android_efv_stabilization_mode_t;
-
-
diff --git a/camera/src/camera_metadata.c b/camera/src/camera_metadata.c
index e0c1cadb..bc587905 100644
--- a/camera/src/camera_metadata.c
+++ b/camera/src/camera_metadata.c
@@ -1167,6 +1167,29 @@ static void print_data(int fd, const uint8_t *data_ptr, uint32_t tag, int type,
     size_t type_size = camera_metadata_type_size[type];
     char value_string_tmp[CAMERA_METADATA_ENUM_STRING_MAX_SIZE];
     uint32_t value;
+    size_t value_offset;
+    size_t entry_size;
+    // It is possible that the tag value is only found at specific
+    // offset. The rest of the data must not be enumerated.
+    switch (tag) {
+        case ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS:
+        case ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS_MAXIMUM_RESOLUTION:
+        case ANDROID_DEPTH_AVAILABLE_DEPTH_STREAM_CONFIGURATIONS:
+        case ANDROID_DEPTH_AVAILABLE_DEPTH_STREAM_CONFIGURATIONS_MAXIMUM_RESOLUTION:
+        case ANDROID_DEPTH_AVAILABLE_DYNAMIC_DEPTH_STREAM_CONFIGURATIONS:
+        case ANDROID_DEPTH_AVAILABLE_DYNAMIC_DEPTH_STREAM_CONFIGURATIONS_MAXIMUM_RESOLUTION:
+        case ANDROID_HEIC_AVAILABLE_HEIC_STREAM_CONFIGURATIONS:
+        case ANDROID_HEIC_AVAILABLE_HEIC_STREAM_CONFIGURATIONS_MAXIMUM_RESOLUTION:
+        case ANDROID_JPEGR_AVAILABLE_JPEG_R_STREAM_CONFIGURATIONS:
+        case ANDROID_JPEGR_AVAILABLE_JPEG_R_STREAM_CONFIGURATIONS_MAXIMUM_RESOLUTION:
+        case ANDROID_SCALER_PHYSICAL_CAMERA_MULTI_RESOLUTION_STREAM_CONFIGURATIONS:
+            value_offset = 3 * type_size;
+            entry_size = 4 * type_size;
+            break;
+        default:
+            value_offset = 0;
+            entry_size = 0;
+    }
 
     int lines = count / values_per_line[type];
     if (count % values_per_line[type] != 0) lines++;
@@ -1195,6 +1218,12 @@ static void print_data(int fd, const uint8_t *data_ptr, uint32_t tag, int type,
                     break;
                 case TYPE_INT32:
                     value = *(int32_t*)(data_ptr + index);
+
+                    if ((entry_size > 0) && ((index % entry_size ) != value_offset)) {
+                        dprintf(fd, "%" PRId32 " ", value);
+                        break;
+                    }
+
                     if (camera_metadata_enum_snprint(tag,
                                                      value,
                                                      value_string_tmp,
diff --git a/camera/src/camera_metadata_tag_info.c b/camera/src/camera_metadata_tag_info.c
index def770e2..e4b7df8f 100644
--- a/camera/src/camera_metadata_tag_info.c
+++ b/camera/src/camera_metadata_tag_info.c
@@ -66,7 +66,6 @@ const char *camera_metadata_section_names[ANDROID_SECTION_COUNT] = {
     [ANDROID_AUTOMOTIVE_LENS]      = "android.automotive.lens",
     [ANDROID_EXTENSION]            = "android.extension",
     [ANDROID_JPEGR]                = "android.jpegr",
-    [ANDROID_EFV]                  = "android.efv",
 };
 
 unsigned int camera_metadata_section_bounds[ANDROID_SECTION_COUNT][2] = {
@@ -139,8 +138,6 @@ unsigned int camera_metadata_section_bounds[ANDROID_SECTION_COUNT][2] = {
                                        ANDROID_EXTENSION_END },
     [ANDROID_JPEGR]                = { ANDROID_JPEGR_START,
                                        ANDROID_JPEGR_END },
-    [ANDROID_EFV]                  = { ANDROID_EFV_START,
-                                       ANDROID_EFV_END },
 };
 
 static tag_info_t android_color_correction[ANDROID_COLOR_CORRECTION_END -
@@ -987,30 +984,6 @@ static tag_info_t android_jpegr[ANDROID_JPEGR_END -
                                         TYPE_INT64  },
 };
 
-static tag_info_t android_efv[ANDROID_EFV_END -
-        ANDROID_EFV_START] = {
-    [ ANDROID_EFV_PADDING_ZOOM_FACTOR_RANGE - ANDROID_EFV_START ] =
-    { "paddingZoomFactorRange",        TYPE_FLOAT  },
-    [ ANDROID_EFV_PADDING_ZOOM_FACTOR - ANDROID_EFV_START ] =
-    { "paddingZoomFactor",             TYPE_FLOAT  },
-    [ ANDROID_EFV_AUTO_ZOOM - ANDROID_EFV_START ] =
-    { "autoZoom",                      TYPE_BYTE   },
-    [ ANDROID_EFV_MAX_PADDING_ZOOM_FACTOR - ANDROID_EFV_START ] =
-    { "maxPaddingZoomFactor",          TYPE_FLOAT  },
-    [ ANDROID_EFV_STABILIZATION_MODE - ANDROID_EFV_START ] =
-    { "stabilizationMode",             TYPE_INT32  },
-    [ ANDROID_EFV_TRANSLATE_VIEWPORT - ANDROID_EFV_START ] =
-    { "translateViewport",             TYPE_INT32  },
-    [ ANDROID_EFV_ROTATE_VIEWPORT - ANDROID_EFV_START ] =
-    { "rotateViewport",                TYPE_FLOAT  },
-    [ ANDROID_EFV_PADDING_REGION - ANDROID_EFV_START ] =
-    { "paddingRegion",                 TYPE_INT32  },
-    [ ANDROID_EFV_AUTO_ZOOM_PADDING_REGION - ANDROID_EFV_START ] =
-    { "autoZoomPaddingRegion",         TYPE_INT32  },
-    [ ANDROID_EFV_TARGET_COORDINATES - ANDROID_EFV_START ] =
-    { "targetCoordinates",             TYPE_FLOAT  },
-};
-
 
 tag_info_t *tag_info[ANDROID_SECTION_COUNT] = {
     android_color_correction,
@@ -1047,7 +1020,6 @@ tag_info_t *tag_info[ANDROID_SECTION_COUNT] = {
     android_automotive_lens,
     android_extension,
     android_jpegr,
-    android_efv,
 };
 
 static int32_t tag_permission_needed[18] = {
@@ -4090,65 +4062,6 @@ int camera_metadata_enum_snprint(uint32_t tag,
             break;
         }
 
-        case ANDROID_EFV_PADDING_ZOOM_FACTOR_RANGE: {
-            break;
-        }
-        case ANDROID_EFV_PADDING_ZOOM_FACTOR: {
-            break;
-        }
-        case ANDROID_EFV_AUTO_ZOOM: {
-            switch (value) {
-                case ANDROID_EFV_AUTO_ZOOM_TRUE:
-                    msg = "TRUE";
-                    ret = 0;
-                    break;
-                case ANDROID_EFV_AUTO_ZOOM_FALSE:
-                    msg = "FALSE";
-                    ret = 0;
-                    break;
-                default:
-                    msg = "error: enum value out of range";
-            }
-            break;
-        }
-        case ANDROID_EFV_MAX_PADDING_ZOOM_FACTOR: {
-            break;
-        }
-        case ANDROID_EFV_STABILIZATION_MODE: {
-            switch (value) {
-                case ANDROID_EFV_STABILIZATION_MODE_OFF:
-                    msg = "OFF";
-                    ret = 0;
-                    break;
-                case ANDROID_EFV_STABILIZATION_MODE_GIMBAL:
-                    msg = "GIMBAL";
-                    ret = 0;
-                    break;
-                case ANDROID_EFV_STABILIZATION_MODE_LOCKED:
-                    msg = "LOCKED";
-                    ret = 0;
-                    break;
-                default:
-                    msg = "error: enum value out of range";
-            }
-            break;
-        }
-        case ANDROID_EFV_TRANSLATE_VIEWPORT: {
-            break;
-        }
-        case ANDROID_EFV_ROTATE_VIEWPORT: {
-            break;
-        }
-        case ANDROID_EFV_PADDING_REGION: {
-            break;
-        }
-        case ANDROID_EFV_AUTO_ZOOM_PADDING_REGION: {
-            break;
-        }
-        case ANDROID_EFV_TARGET_COORDINATES: {
-            break;
-        }
-
     }
 
     strncpy(dst, msg, size - 1);
@@ -7590,67 +7503,6 @@ int camera_metadata_enum_value(uint32_t tag,
             break;
         }
 
-        case ANDROID_EFV_PADDING_ZOOM_FACTOR_RANGE: {
-            break;
-        }
-        case ANDROID_EFV_PADDING_ZOOM_FACTOR: {
-            break;
-        }
-        case ANDROID_EFV_AUTO_ZOOM: {
-                enumName = "TRUE";
-                if (strncmp(name, enumName, size) == 0) {
-                    *value = ANDROID_EFV_AUTO_ZOOM_TRUE;
-                    ret = 0;
-                    break;
-                }
-                enumName = "FALSE";
-                if (strncmp(name, enumName, size) == 0) {
-                    *value = ANDROID_EFV_AUTO_ZOOM_FALSE;
-                    ret = 0;
-                    break;
-                }
-            break;
-        }
-        case ANDROID_EFV_MAX_PADDING_ZOOM_FACTOR: {
-            break;
-        }
-        case ANDROID_EFV_STABILIZATION_MODE: {
-                enumName = "OFF";
-                if (strncmp(name, enumName, size) == 0) {
-                    *value = ANDROID_EFV_STABILIZATION_MODE_OFF;
-                    ret = 0;
-                    break;
-                }
-                enumName = "GIMBAL";
-                if (strncmp(name, enumName, size) == 0) {
-                    *value = ANDROID_EFV_STABILIZATION_MODE_GIMBAL;
-                    ret = 0;
-                    break;
-                }
-                enumName = "LOCKED";
-                if (strncmp(name, enumName, size) == 0) {
-                    *value = ANDROID_EFV_STABILIZATION_MODE_LOCKED;
-                    ret = 0;
-                    break;
-                }
-            break;
-        }
-        case ANDROID_EFV_TRANSLATE_VIEWPORT: {
-            break;
-        }
-        case ANDROID_EFV_ROTATE_VIEWPORT: {
-            break;
-        }
-        case ANDROID_EFV_PADDING_REGION: {
-            break;
-        }
-        case ANDROID_EFV_AUTO_ZOOM_PADDING_REGION: {
-            break;
-        }
-        case ANDROID_EFV_TARGET_COORDINATES: {
-            break;
-        }
-
     }
 
     return ret;
```

