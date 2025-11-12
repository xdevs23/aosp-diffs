```diff
diff --git a/OWNERS b/OWNERS
index fc99e730..a46178ce 100644
--- a/OWNERS
+++ b/OWNERS
@@ -6,4 +6,3 @@ elaurent@google.com
 hunga@google.com
 jiabin@google.com
 mnaganov@google.com
-philburk@google.com
diff --git a/audio/include/system/audio-hal-enums.h b/audio/include/system/audio-hal-enums.h
index e258b450..d2b1a670 100644
--- a/audio/include/system/audio-hal-enums.h
+++ b/audio/include/system/audio-hal-enums.h
@@ -557,6 +557,8 @@ enum {
     AUDIO_FORMAT_IAMF_SIMPLE        = 0x1 << 16,
     AUDIO_FORMAT_IAMF_BASE          = 0x1 << 17,
     AUDIO_FORMAT_IAMF_BASE_ENHANCED = 0x1 << 18,
+
+    AUDIO_FORMAT_OPUS_SUB_HI_RES    = 0x1u,
 };
 
 #define AUDIO_FORMAT_LIST_UNIQUE_DEF(V) \
@@ -586,6 +588,7 @@ enum {
     V(AUDIO_FORMAT_HE_AAC_V2, 0x06000000u) \
     V(AUDIO_FORMAT_VORBIS, 0x07000000u) \
     V(AUDIO_FORMAT_OPUS, 0x08000000u) \
+    V(AUDIO_FORMAT_OPUS_HI_RES, AUDIO_FORMAT_OPUS | AUDIO_FORMAT_OPUS_SUB_HI_RES) \
     V(AUDIO_FORMAT_AC3, 0x09000000u) \
     V(AUDIO_FORMAT_E_AC3, 0x0A000000u) \
     V(AUDIO_FORMAT_E_AC3_JOC, AUDIO_FORMAT_E_AC3 | AUDIO_FORMAT_E_AC3_SUB_JOC) \
diff --git a/audio/include/system/audio_effects/effect_aec.h b/audio/include/system/audio_effects/effect_aec.h
index 260a4a24..c7b6bfb4 100644
--- a/audio/include/system/audio_effects/effect_aec.h
+++ b/audio/include/system/audio_effects/effect_aec.h
@@ -34,7 +34,7 @@ typedef enum
     AEC_PARAM_ECHO_DELAY,           // echo delay in microseconds
     AEC_PARAM_PROPERTIES,
 #ifndef WEBRTC_LEGACY
-    AEC_PARAM_MOBILE_MODE,
+    AEC_PARAM_MOBILE_MODE,          // deprecated
 #endif
 } t_aec_params;
 
diff --git a/audio/include/system/audio_effects/effect_uuid.h b/audio/include/system/audio_effects/effect_uuid.h
index 2766a32e..a104c235 100644
--- a/audio/include/system/audio_effects/effect_uuid.h
+++ b/audio/include/system/audio_effects/effect_uuid.h
@@ -91,6 +91,7 @@ constexpr char kEffectImplUuidDynamicsProcessing[] = "e0e6539b-1781-7261-676f-6d
 constexpr char kEffectImplUuidEqualizerSw[] = "0bed4300-847d-11df-bb17-0002a5d5c51b";
 constexpr char kEffectImplUuidEqualizerBundle[] = "ce772f20-847d-11df-bb17-0002a5d5c51b";
 constexpr char kEffectImplUuidEqualizerProxy[] = "c8e70ecd-48ca-456e-8a4f-0002a5d5c51b";
+constexpr char kEffectImplUuidEraser[] = "fa81ad26-588b-11ed-9b6a-0242ac120002";
 constexpr char kEffectImplUuidEraserSw[] = "fa81ab46-588b-11ed-9b6a-0242ac120002";
 constexpr char kEffectImplUuidHapticGeneratorSw[] = "fa819110-588b-11ed-9b6a-0242ac120002";
 constexpr char kEffectImplUuidHapticGenerator[] = "97c4acd1-8b82-4f2f-832e-c2fe5d7a9931";
@@ -153,6 +154,7 @@ constexpr char kEffectImplUuidExtension[] = "fa81dd00-588b-11ed-9b6a-0242ac12000
     V(ImplUuidEqualizerSw)              \
     V(ImplUuidEqualizerBundle)          \
     V(ImplUuidEqualizerProxy)           \
+    V(ImplUuidEraser)                   \
     V(ImplUuidEraserSw)                 \
     V(ImplUuidExtension)                \
     V(ImplUuidHapticGeneratorSw)        \
diff --git a/audio_utils/benchmarks/Android.bp b/audio_utils/benchmarks/Android.bp
index 42305908..5df12b91 100644
--- a/audio_utils/benchmarks/Android.bp
+++ b/audio_utils/benchmarks/Android.bp
@@ -9,6 +9,24 @@ package {
     default_applicable_licenses: ["system_media_license"],
 }
 
+cc_benchmark {
+    name: "audio_atomic_benchmark",
+
+    srcs: ["audio_atomic_benchmark.cpp"],
+    cflags: [
+        "-Wall",
+        "-Werror",
+    ],
+    shared_libs: [
+        "libbase",
+        "liblog",
+        "libutils",
+    ],
+    static_libs: [
+        "libaudioutils",
+    ],
+}
+
 cc_benchmark {
     name: "audio_mutex_benchmark",
 
diff --git a/audio_utils/benchmarks/audio_atomic_benchmark.cpp b/audio_utils/benchmarks/audio_atomic_benchmark.cpp
new file mode 100644
index 00000000..3aa3f9fb
--- /dev/null
+++ b/audio_utils/benchmarks/audio_atomic_benchmark.cpp
@@ -0,0 +1,223 @@
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
+#include <audio_utils/atomic.h>
+
+#include <android-base/logging.h>
+#include <benchmark/benchmark.h>
+
+/*
+On Pixel 9 Pro XL Android 16
+
+Note: to bump up the scheduler clock frequency, one can use the toybox uclampset:
+$ adb shell uclampset -m 1024 /data/benchmarktest64/audio_atomic_benchmark/audio_atomic_benchmark
+
+For simplicity these tests use the regular invocation:
+$ atest audio_atomic_benchmark
+
+Benchmark                                             Time             CPU   Iterations
+---------------------------------------------------------------------------------------
+BM_std_atomic_add_equals<int32_t>                  6.09 ns         6.06 ns    111837415
+BM_std_atomic_add_to_relaxed<int16_t>              4.73 ns         4.71 ns    148254244
+BM_std_atomic_add_to_relaxed<int32_t>              4.74 ns         4.72 ns    148431804
+BM_std_atomic_add_to_relaxed<int64_t>              4.73 ns         4.72 ns    148325212
+BM_std_atomic_add_to_relaxed<float>                8.43 ns         8.40 ns     83275005
+BM_std_atomic_add_to_relaxed<double>               8.44 ns         8.41 ns     83175275
+BM_std_atomic_add_to_seq_cst<int16_t>              6.15 ns         6.12 ns    114333415
+BM_std_atomic_add_to_seq_cst<int32_t>              6.14 ns         6.12 ns    114419640
+BM_std_atomic_add_to_seq_cst<int64_t>              6.14 ns         6.12 ns    114268405
+BM_std_atomic_add_to_seq_cst<float>                8.24 ns         8.22 ns     84437565
+BM_std_atomic_add_to_seq_cst<double>               8.25 ns         8.22 ns     85743036
+BM_atomic_add_to_unordered<int16_t>               0.324 ns        0.323 ns   2164817147
+BM_atomic_add_to_unordered<int32_t>               0.324 ns        0.323 ns   2165111368
+BM_atomic_add_to_unordered<int64_t>               0.324 ns        0.323 ns   2166007205
+BM_atomic_add_to_unordered<float>                 0.650 ns        0.647 ns   1082261791
+BM_atomic_add_to_unordered<double>                0.649 ns        0.647 ns   1084858584
+BM_atomic_add_to_unordered<volatile_int16_t>       1.97 ns         1.97 ns    356078819
+BM_atomic_add_to_unordered<volatile_int32_t>       1.97 ns         1.97 ns    356752252
+BM_atomic_add_to_unordered<volatile_int64_t>       1.97 ns         1.97 ns    355550844
+BM_atomic_add_to_unordered<volatile_float>         2.73 ns         2.72 ns    257345858
+BM_atomic_add_to_unordered<volatile_double>        2.73 ns         2.72 ns    257569407
+BM_atomic_add_to_relaxed<int16_t>                  4.66 ns         4.64 ns    150820948
+BM_atomic_add_to_relaxed<int32_t>                  4.66 ns         4.65 ns    150876792
+BM_atomic_add_to_relaxed<int64_t>                  4.66 ns         4.65 ns    150875922
+BM_atomic_add_to_relaxed<float>                    8.59 ns         8.57 ns     81660591
+BM_atomic_add_to_relaxed<double>                   8.59 ns         8.57 ns     81708337
+BM_atomic_add_to_acq_rel<int16_t>                  6.09 ns         6.07 ns    115522143
+BM_atomic_add_to_acq_rel<int32_t>                  6.09 ns         6.07 ns    115954305
+BM_atomic_add_to_acq_rel<int64_t>                  6.09 ns         6.07 ns    115475851
+BM_atomic_add_to_acq_rel<float>                    8.31 ns         8.28 ns     84750753
+BM_atomic_add_to_acq_rel<double>                   8.33 ns         8.31 ns     84298009
+BM_atomic_add_to_seq_cst<int16_t>                  6.08 ns         6.06 ns    115819800
+BM_atomic_add_to_seq_cst<int32_t>                  6.09 ns         6.07 ns    115277139
+BM_atomic_add_to_seq_cst<int64_t>                  6.09 ns         6.06 ns    115215686
+BM_atomic_add_to_seq_cst<float>                    8.37 ns         8.35 ns     84116069
+BM_atomic_add_to_seq_cst<double>                   8.35 ns         8.32 ns     83978265
+BM_atomic_min_unordered<int16_t>                  0.324 ns        0.323 ns   2162398052
+BM_atomic_min_unordered<int32_t>                  0.325 ns        0.324 ns   2167766537
+BM_atomic_min_unordered<int64_t>                  0.324 ns        0.323 ns   2166667968
+BM_atomic_min_unordered<float>                    0.325 ns        0.324 ns   2167960175
+BM_atomic_min_unordered<double>                   0.325 ns        0.324 ns   2167053545
+BM_atomic_min_seq_cst<int16_t>                     11.5 ns         11.5 ns     61168869
+BM_atomic_min_seq_cst<int32_t>                     10.3 ns         10.2 ns     68411173
+BM_atomic_min_seq_cst<int64_t>                     10.2 ns         10.2 ns     68716761
+BM_atomic_min_seq_cst<float>                       10.6 ns         10.6 ns     66304219
+BM_atomic_min_seq_cst<double>                      10.5 ns         10.5 ns     66700397
+
+*/
+
+// ---
+
+template<typename Integer>
+static void BM_std_atomic_add_equals(benchmark::State &state) {
+    Integer i = 10;
+    std::atomic<Integer> dst;
+    while (state.KeepRunning()) {
+        dst += i;
+    }
+}
+
+BENCHMARK(BM_std_atomic_add_equals<int32_t>);
+
+template <typename T, android::audio_utils::memory_order MO>
+static void BM_atomic_add_to(benchmark::State &state) {
+    int64_t i64 = 10;
+    android::audio_utils::atomic<T, MO> dst;
+    while (state.KeepRunning()) {
+        dst.fetch_add(i64, MO);
+    }
+}
+
+template <typename T>
+static void BM_std_atomic_add_to(benchmark::State &state, std::memory_order order) {
+    int64_t i64 = 10;
+    std::atomic<T> dst;
+    while (state.KeepRunning()) {
+        dst.fetch_add(i64, order);
+    }
+}
+
+template <typename T>
+static void BM_std_atomic_add_to_relaxed(benchmark::State &state) {
+    BM_std_atomic_add_to<T>(state, std::memory_order_relaxed);
+}
+
+BENCHMARK(BM_std_atomic_add_to_relaxed<int16_t>);
+BENCHMARK(BM_std_atomic_add_to_relaxed<int32_t>);
+BENCHMARK(BM_std_atomic_add_to_relaxed<int64_t>);
+BENCHMARK(BM_std_atomic_add_to_relaxed<float>);
+BENCHMARK(BM_std_atomic_add_to_relaxed<double>);
+
+template <typename T>
+static void BM_std_atomic_add_to_seq_cst(benchmark::State &state) {
+    BM_std_atomic_add_to<T>(state, std::memory_order_seq_cst);
+}
+
+BENCHMARK(BM_std_atomic_add_to_seq_cst<int16_t>);
+BENCHMARK(BM_std_atomic_add_to_seq_cst<int32_t>);
+BENCHMARK(BM_std_atomic_add_to_seq_cst<int64_t>);
+BENCHMARK(BM_std_atomic_add_to_seq_cst<float>);
+BENCHMARK(BM_std_atomic_add_to_seq_cst<double>);
+
+template <typename T>
+static void BM_atomic_add_to_unordered(benchmark::State &state) {
+    BM_atomic_add_to<T, android::audio_utils::memory_order_unordered>(state);
+}
+
+BENCHMARK(BM_atomic_add_to_unordered<int16_t>);
+BENCHMARK(BM_atomic_add_to_unordered<int32_t>);
+BENCHMARK(BM_atomic_add_to_unordered<int64_t>);
+BENCHMARK(BM_atomic_add_to_unordered<float>);
+BENCHMARK(BM_atomic_add_to_unordered<double>);
+
+// type aliases to allow for macro parsing.
+using volatile_int16_t = volatile int16_t;
+using volatile_int32_t = volatile int32_t;
+using volatile_int64_t = volatile int64_t;
+using volatile_float = volatile float;
+using volatile_double = volatile double;
+
+BENCHMARK(BM_atomic_add_to_unordered<volatile_int16_t>);
+BENCHMARK(BM_atomic_add_to_unordered<volatile_int32_t>);
+BENCHMARK(BM_atomic_add_to_unordered<volatile_int64_t>);
+BENCHMARK(BM_atomic_add_to_unordered<volatile_float>);
+BENCHMARK(BM_atomic_add_to_unordered<volatile_double>);
+
+template <typename T>
+static void BM_atomic_add_to_relaxed(benchmark::State &state) {
+    BM_atomic_add_to<T, android::audio_utils::memory_order_relaxed>(state);
+}
+
+BENCHMARK(BM_atomic_add_to_relaxed<int16_t>);
+BENCHMARK(BM_atomic_add_to_relaxed<int32_t>);
+BENCHMARK(BM_atomic_add_to_relaxed<int64_t>);
+BENCHMARK(BM_atomic_add_to_relaxed<float>);
+BENCHMARK(BM_atomic_add_to_relaxed<double>);
+
+template <typename T>
+static void BM_atomic_add_to_acq_rel(benchmark::State &state) {
+    BM_atomic_add_to<T, android::audio_utils::memory_order_acq_rel>(state);
+}
+
+BENCHMARK(BM_atomic_add_to_acq_rel<int16_t>);
+BENCHMARK(BM_atomic_add_to_acq_rel<int32_t>);
+BENCHMARK(BM_atomic_add_to_acq_rel<int64_t>);
+BENCHMARK(BM_atomic_add_to_acq_rel<float>);
+BENCHMARK(BM_atomic_add_to_acq_rel<double>);
+
+template <typename T>
+static void BM_atomic_add_to_seq_cst(benchmark::State &state) {
+    BM_atomic_add_to<T, android::audio_utils::memory_order_seq_cst>(state);
+}
+
+BENCHMARK(BM_atomic_add_to_seq_cst<int16_t>);
+BENCHMARK(BM_atomic_add_to_seq_cst<int32_t>);
+BENCHMARK(BM_atomic_add_to_seq_cst<int64_t>);
+BENCHMARK(BM_atomic_add_to_seq_cst<float>);
+BENCHMARK(BM_atomic_add_to_seq_cst<double>);
+
+template <typename T, android::audio_utils::memory_order MO>
+static void BM_atomic_min(benchmark::State &state) {
+    int64_t i64 = 10;
+    android::audio_utils::atomic<T, MO> dst;
+    while (state.KeepRunning()) {
+        dst.min(i64, MO);  // MO is optional, as same as atomic decl.
+    }
+}
+
+template <typename T>
+static void BM_atomic_min_unordered(benchmark::State &state) {
+    BM_atomic_min<T, android::audio_utils::memory_order_unordered>(state);
+}
+
+BENCHMARK(BM_atomic_min_unordered<int16_t>);
+BENCHMARK(BM_atomic_min_unordered<int32_t>);
+BENCHMARK(BM_atomic_min_unordered<int64_t>);
+BENCHMARK(BM_atomic_min_unordered<float>);
+BENCHMARK(BM_atomic_min_unordered<double>);
+
+template <typename T>
+static void BM_atomic_min_seq_cst(benchmark::State &state) {
+    BM_atomic_min<T, android::audio_utils::memory_order_seq_cst>(state);
+}
+
+BENCHMARK(BM_atomic_min_seq_cst<int16_t>);
+BENCHMARK(BM_atomic_min_seq_cst<int32_t>);
+BENCHMARK(BM_atomic_min_seq_cst<int64_t>);
+BENCHMARK(BM_atomic_min_seq_cst<float>);
+BENCHMARK(BM_atomic_min_seq_cst<double>);
+
+BENCHMARK_MAIN();
diff --git a/audio_utils/benchmarks/audio_mutex_benchmark.cpp b/audio_utils/benchmarks/audio_mutex_benchmark.cpp
index 4937e17e..b4cf4fa3 100644
--- a/audio_utils/benchmarks/audio_mutex_benchmark.cpp
+++ b/audio_utils/benchmarks/audio_mutex_benchmark.cpp
@@ -34,27 +34,6 @@ $ atest audio_mutex_benchmark
 
 Benchmark                                                     Time        CPU        Iteration
 audio_mutex_benchmark:
-  #BM_atomic_add_equals<int32_t>                                6.502025194439543 ns       6.47205015631869 ns     108145417
-  #BM_atomic_add_to_seq_cst<int16_t>                             6.55807517340572 ns      6.526952655561198 ns     107217450
-  #BM_atomic_add_to_seq_cst<int32_t>                            6.610803828172807 ns       6.58148248625125 ns     106355671
-  #BM_atomic_add_to_seq_cst<int64_t>                           6.5568264443311595 ns      6.526632489003918 ns     107237292
-  #BM_atomic_add_to_seq_cst<float>                              7.884542958080632 ns     7.8526649209116375 ns      89368018
-  #BM_atomic_add_to_seq_cst<double>                             7.931010792308195 ns      7.893661616016361 ns      88487681
-  #BM_atomic_add_to_relaxed<int16_t>                            5.167222836799001 ns      5.144664678496968 ns     136918225
-  #BM_atomic_add_to_relaxed<int32_t>                            5.181042322951031 ns       5.15622768069756 ns     135684124
-  #BM_atomic_add_to_relaxed<int64_t>                             5.16751983474899 ns      5.144558629227656 ns     138681351
-  #BM_atomic_add_to_relaxed<float>                             7.7921119585599525 ns      7.741060701068997 ns      90441768
-  #BM_atomic_add_to_relaxed<double>                             7.774451559752642 ns      7.737580743492468 ns      90244734
-  #BM_atomic_add_to_unordered<int16_t>                         0.3535942390008131 ns            0.351996905 ns    1000000000
-  #BM_atomic_add_to_unordered<int32_t>                        0.35363073799817357 ns     0.3519564250000009 ns    1000000000
-  #BM_atomic_add_to_unordered<int64_t>                        0.35689860000275075 ns    0.35208711699999995 ns    1000000000
-  #BM_atomic_add_to_unordered<float>                           0.7052556854655034 ns     0.7020281104213322 ns     997014156
-  #BM_atomic_add_to_unordered<double>                          0.7050851735423606 ns     0.7020307730369924 ns     997136097
-  #BM_atomic_add_to_unordered<volatile_int16_t>                1.7630191837466263 ns      1.755060622823009 ns     398830899
-  #BM_atomic_add_to_unordered<volatile_int32_t>                1.7636458882248507 ns     1.7551169249266374 ns     398840618
-  #BM_atomic_add_to_unordered<volatile_int64_t>                 1.762758401503814 ns      1.755028484468997 ns     398845420
-  #BM_atomic_add_to_unordered<volatile_float>                  2.6616841096538084 ns     2.6491095463299206 ns     264227784
-  #BM_atomic_add_to_unordered<volatile_double>                  2.659741383344485 ns     2.6476598391107227 ns     264613772
   #BM_gettid                                                   2.1159776035370936 ns       2.10614115284375 ns     332373750
   #BM_systemTime                                                45.25256074688064 ns     45.040996499041846 ns      15560597
   #BM_thread_8_variables                                       2.8218847925890063 ns      2.808269438152783 ns     249265931
@@ -124,96 +103,6 @@ audio_mutex_benchmark:
 
 // ---
 
-template<typename Integer>
-static void BM_atomic_add_equals(benchmark::State &state) {
-    Integer i = 10;
-    std::atomic<Integer> dst;
-    while (state.KeepRunning()) {
-        dst += i;
-    }
-    LOG(DEBUG) << __func__ << "  " << dst.load();
-}
-
-BENCHMARK(BM_atomic_add_equals<int32_t>);
-
-template <typename T>
-static void BM_atomic_add_to(benchmark::State &state, std::memory_order order) {
-    int64_t i64 = 10;
-    std::atomic<T> dst;
-    while (state.KeepRunning()) {
-        android::audio_utils::atomic_add_to(dst, i64, order);
-    }
-    LOG(DEBUG) << __func__ << "  " << dst.load();
-}
-
-// Avoid macro issues with the comma.
-template <typename T>
-static void BM_atomic_add_to_seq_cst(benchmark::State &state) {
-    BM_atomic_add_to<T>(state, std::memory_order_seq_cst);
-}
-
-BENCHMARK(BM_atomic_add_to_seq_cst<int16_t>);
-
-BENCHMARK(BM_atomic_add_to_seq_cst<int32_t>);
-
-BENCHMARK(BM_atomic_add_to_seq_cst<int64_t>);
-
-BENCHMARK(BM_atomic_add_to_seq_cst<float>);
-
-BENCHMARK(BM_atomic_add_to_seq_cst<double>);
-
-template <typename T>
-static void BM_atomic_add_to_relaxed(benchmark::State &state) {
-    BM_atomic_add_to<T>(state, std::memory_order_relaxed);
-}
-
-BENCHMARK(BM_atomic_add_to_relaxed<int16_t>);
-
-BENCHMARK(BM_atomic_add_to_relaxed<int32_t>);
-
-BENCHMARK(BM_atomic_add_to_relaxed<int64_t>);
-
-BENCHMARK(BM_atomic_add_to_relaxed<float>);
-
-BENCHMARK(BM_atomic_add_to_relaxed<double>);
-
-template <typename T>
-static void BM_atomic_add_to_unordered(benchmark::State &state) {
-    int64_t i64 = 10;
-    android::audio_utils::unordered_atomic<T> dst;
-    while (state.KeepRunning()) {
-        android::audio_utils::atomic_add_to(dst, i64, std::memory_order_relaxed);
-    }
-    LOG(DEBUG) << __func__ << "  " << dst.load();
-}
-
-BENCHMARK(BM_atomic_add_to_unordered<int16_t>);
-
-BENCHMARK(BM_atomic_add_to_unordered<int32_t>);
-
-BENCHMARK(BM_atomic_add_to_unordered<int64_t>);
-
-BENCHMARK(BM_atomic_add_to_unordered<float>);
-
-BENCHMARK(BM_atomic_add_to_unordered<double>);
-
-// type aliases to allow for macro parsing.
-using volatile_int16_t = volatile int16_t;
-using volatile_int32_t = volatile int32_t;
-using volatile_int64_t = volatile int64_t;
-using volatile_float = volatile float;
-using volatile_double = volatile double;
-
-BENCHMARK(BM_atomic_add_to_unordered<volatile_int16_t>);
-
-BENCHMARK(BM_atomic_add_to_unordered<volatile_int32_t>);
-
-BENCHMARK(BM_atomic_add_to_unordered<volatile_int64_t>);
-
-BENCHMARK(BM_atomic_add_to_unordered<volatile_float>);
-
-BENCHMARK(BM_atomic_add_to_unordered<volatile_double>);
-
 // Benchmark gettid().  The mutex class uses this to get the linux thread id.
 static void BM_gettid(benchmark::State &state) {
     int32_t value = 0;
diff --git a/audio_utils/benchmarks/intrinsic_benchmark.cpp b/audio_utils/benchmarks/intrinsic_benchmark.cpp
index 3ebe05de..859d53b6 100644
--- a/audio_utils/benchmarks/intrinsic_benchmark.cpp
+++ b/audio_utils/benchmarks/intrinsic_benchmark.cpp
@@ -17,6 +17,7 @@
 #include <array>
 #include <climits>
 #include <cstdlib>
+#include <functional>
 #include <random>
 #include <vector>
 
diff --git a/audio_utils/include/audio_utils/CommandThread.h b/audio_utils/include/audio_utils/CommandThread.h
index 092fb78b..ff0d05e8 100644
--- a/audio_utils/include/audio_utils/CommandThread.h
+++ b/audio_utils/include/audio_utils/CommandThread.h
@@ -17,6 +17,7 @@
 #pragma once
 
 #include <deque>
+#include <functional>
 #include <mutex>
 #include <thread>
 #include <audio_utils/mutex.h>
diff --git a/audio_utils/include/audio_utils/RunRemote.h b/audio_utils/include/audio_utils/RunRemote.h
index e991e7cc..47d5ba8b 100644
--- a/audio_utils/include/audio_utils/RunRemote.h
+++ b/audio_utils/include/audio_utils/RunRemote.h
@@ -112,7 +112,7 @@ public:
     }
 
     /** waits for a char from the remote process. */
-    int getc() {
+    int getChar() {
         unsigned char c;
         // EOF returns 0 (this is a blocking read), -1 on error.
         if (read(mInFd, &c, 1) != 1) return -1;
@@ -120,7 +120,7 @@ public:
     }
 
     /** sends a char to the remote process. */
-    int putc(int c) {
+    int putChar(int c) {
         while (true) {
             int ret = write(mOutFd, &c, 1);  // LE.
             if (ret == 1) return 1;
diff --git a/audio_utils/include/audio_utils/atomic.h b/audio_utils/include/audio_utils/atomic.h
new file mode 100644
index 00000000..e8b2a357
--- /dev/null
+++ b/audio_utils/include/audio_utils/atomic.h
@@ -0,0 +1,373 @@
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
+#include <utils/Log.h>
+
+#include <atomic>
+
+#pragma push_macro("LOG_TAG")
+#undef LOG_TAG
+#define LOG_TAG "audio_utils::atomic"
+
+#include <algorithm>
+#include <atomic>
+#include <functional>
+
+namespace android::audio_utils {
+
+// Rationale:
+
+// std::atomic defaults to memory_order_seq_cst access, with no template options to change the
+// default behavior (one must specify a different memory order on each method call).
+// This confuses the atomic-by-method-access strategy used in Linux (and older Android methods)
+// with an incomplete atomic-by-declaration strategy for C++.
+//
+// Although the std::atomic default memory_order_seq_cst is the safest and strictest,
+// we can often relax the conditions of access based on the variable usage.
+//
+// The audio_utils atomic fixes this declaration deficiency of std::atomic.
+// It allows template specification of relaxed and unordered access by default.
+// Consistent atomic behavior is then based on the variable declaration, and switching
+// and benchmarking different atomic safety guarantees is easy.
+
+// About unordered access.
+//
+// memory_order_unordered implements data storage such that memory reads have a value
+// consistent with a memory write in some order.
+//
+// Unordered memory reads and writes may not actually take place but be implicitly cached.
+// Nevertheless, a memory read should return at least as contemporaneous a value
+// as the last memory write before the write thread memory barrier that
+// preceded the most recent read thread memory barrier.
+//
+// This is weaker than relaxed_atomic and has no equivalent C++ terminology.
+// unordered_atomic would be used for a single writer, multiple reader case,
+// where data access of type T would be a implemented by the compiler and
+// hw architecture with a single "uninterruptible" memory operation.
+// (The current implementation holds true for general realized CPU architectures).
+// Note that multiple writers would cause read-modify-write unordered_atomic
+// operations to have inconsistent results.
+//
+// unordered_atomic is implemented with normal operations such that compiler
+// optimizations can take place which would otherwise be discouraged for atomics.
+// https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2016/p0062r1.html
+
+// std::atomic and the C11 atomics are not sufficient to implement these libraries
+// with unordered access.  We use the C++ compiler built-ins.
+//
+// https://en.cppreference.com/w/c/language/atomic
+
+enum memory_order {
+    memory_order_unordered = -1,
+    memory_order_relaxed = (int)std::memory_order_relaxed,
+    // memory_order_consume = (int)std::memory_order_consume, // deprecated and omitted.
+    memory_order_acquire = (int)std::memory_order_acquire,
+    memory_order_release = (int)std::memory_order_release,
+    memory_order_acq_rel = (int)std::memory_order_acq_rel,
+    memory_order_seq_cst = (int)std::memory_order_seq_cst,
+};
+
+inline constexpr int to_gnu_memory_order(memory_order mo) {
+    return mo == memory_order_relaxed ? __ATOMIC_RELAXED
+    // : mo == memory_order_consume ? __ATOMIC_CONSUME  // deprecated and omitted.
+    : mo == memory_order_acquire ? __ATOMIC_ACQUIRE
+    : mo == memory_order_release ? __ATOMIC_RELEASE
+    : mo == memory_order_acq_rel ? __ATOMIC_ACQ_REL
+    : mo == memory_order_seq_cst ? __ATOMIC_SEQ_CST : -1;
+}
+
+inline constexpr int to_gnu_load_memory_order(memory_order mo) {
+    return mo == memory_order_relaxed ? __ATOMIC_RELAXED
+    // : mo == memory_order_consume ? __ATOMIC_CONSUME  // deprecated and omitted.
+    : mo == memory_order_acquire ? __ATOMIC_ACQUIRE
+    : mo == memory_order_release ? __ATOMIC_RELAXED  // see compare-exchange
+    : mo == memory_order_acq_rel ? __ATOMIC_ACQUIRE
+    : mo == memory_order_seq_cst ? __ATOMIC_SEQ_CST : -1;
+}
+
+inline constexpr int to_gnu_store_memory_order(memory_order mo) {
+    return mo == memory_order_relaxed ? __ATOMIC_RELAXED
+    // : mo == memory_order_consume ? __ATOMIC_CONSUME  // deprecated and omitted.
+    : mo == memory_order_acquire ? __ATOMIC_RELAXED  // for symmetry with load.
+    : mo == memory_order_release ? __ATOMIC_RELEASE
+    : mo == memory_order_acq_rel ? __ATOMIC_RELEASE
+    : mo == memory_order_seq_cst ? __ATOMIC_SEQ_CST : -1;
+}
+
+template <typename VT, memory_order MO>
+class atomic {
+    using T = std::decay_t<VT>;
+    static_assert(std::atomic<T>::is_always_lock_free);
+public:
+    constexpr atomic(T desired = {}) : t_(desired) {}
+
+    constexpr operator T() const { return load(); }
+
+    constexpr T operator=(T desired) {
+        store(desired);
+        return desired;
+    }
+
+    constexpr T operator--(int) { return fetch_sub(1); }
+    constexpr T operator++(int) { return fetch_add(1); }
+    constexpr T operator--() { return operator-=(1); }
+    constexpr T operator++() { return operator+=(1); }
+
+    // these operations return the result.
+    constexpr T operator+=(T value) {
+        if constexpr (MO == memory_order_unordered) {
+            if constexpr (std::is_integral_v<T>) {
+                T output;
+                // use 2's complement overflow to match atomic spec.
+                (void)__builtin_add_overflow(t_, value, &output);
+                return operator=(output);
+            } else /* constexpr */ {
+                return t_ += value;
+            }
+        } else /* constexpr */ {
+            return __atomic_add_fetch(&t_, value, to_gnu_memory_order(MO));
+        }
+    }
+    constexpr T operator-=(T value) {
+        if constexpr (MO == memory_order_unordered) {
+            if constexpr (std::is_integral_v<T>) {
+                T output;
+                // use 2's complement overflow to match atomic spec.
+                (void)__builtin_sub_overflow(t_, value, &output);
+                return operator=(output);
+            } else /* constexpr */ {
+                return t_ -= value;
+            }
+        } else /* constexpr */ {
+            return __atomic_sub_fetch(&t_, value, to_gnu_memory_order(MO));
+        }
+    }
+    constexpr T operator&=(T value) {
+        if constexpr (MO == memory_order_unordered) {
+            return t_ &= value;
+        } else /* constexpr */ {
+            return __atomic_and_fetch(&t_, value, to_gnu_memory_order(MO));
+        }
+    }
+    constexpr T operator|=(T value) {
+        if constexpr (MO == memory_order_unordered) {
+            return t_ |= value;
+        } else /* constexpr */ {
+            return __atomic_or_fetch(&t_, value, to_gnu_memory_order(MO));
+        }
+    }
+    constexpr T operator^=(T value) {
+        if constexpr (MO == memory_order_unordered) {
+            return t_ ^= value;
+        } else /* constexpr */ {
+            return __atomic_xor_fetch(&t_, value, to_gnu_memory_order(MO));
+        }
+    }
+
+    // classic atomic load and store
+    constexpr T load() const {
+        if constexpr (MO == memory_order_unordered) {
+            return t_;
+        } else /* constexpr */ {
+            return load(MO);
+        }
+    }
+    constexpr T load(memory_order mo) const {
+        if (mo == memory_order_unordered) {
+            return t_;
+        } else {
+            T ret;
+            __atomic_load(&t_, &ret, to_gnu_load_memory_order(mo));
+            return ret;
+        }
+    }
+    constexpr void store(T value) {
+        if constexpr (MO == memory_order_unordered) {
+            t_ = value;
+        } else /* constexpr */ {
+            store(value, MO);
+        }
+    }
+    constexpr void store(T value, memory_order mo) {
+        if (mo == memory_order_unordered) {
+            t_ = value;
+        } else {
+            __atomic_store(&t_, &value, to_gnu_store_memory_order(mo));
+        }
+    }
+
+    constexpr T apply(const std::function<T(T)>& f, memory_order mo = MO) {
+        if (mo == memory_order_unordered) {
+            return t_ = f(t_);
+        } else {
+            T expected, result;
+            do {
+                expected = t_;
+                result = f(expected);
+            } while (!compare_exchange_weak(expected, result, mo));
+            return result;
+        }
+    }
+
+    constexpr T max(T value) {
+        if constexpr (MO == memory_order_unordered) {
+            return t_ = std::max(t_, value);
+        } else /* constexpr */ {
+            return max(value, MO);
+        }
+    }
+
+    constexpr T max(T value, memory_order mo) {
+        if (mo == memory_order_unordered) {
+            return t_ = std::max(t_, value);
+        } else {
+            return apply([value](T a) -> T { return std::max(value, a); }, mo);
+        }
+    }
+
+    constexpr T min(T value) {
+        if constexpr (MO == memory_order_unordered) {
+            return t_ = std::min(t_, value);
+        } else /* constexpr */ {
+            return min(value, MO);
+        }
+    }
+
+    constexpr T min(T value, memory_order mo) {
+        if (mo == memory_order_unordered) {
+            return t_ = std::min(t_, value);
+        } else {
+            return apply([value](T a) -> T { return std::min(value, a); }, mo);
+        }
+    }
+
+    // these operations return the value prior to the result.
+    constexpr T fetch_add(T value) {
+        if constexpr (MO == memory_order_unordered) {
+            auto old = t_;
+            T output;
+            if constexpr (std::is_floating_point_v<T>) {
+                output = t_ + value;
+            } else /* constexpr */ {
+                (void)__builtin_add_overflow(t_, value, &output);
+            }
+            store(output);
+            return old;
+        } else /* constexpr */ {
+            return fetch_add(value, MO);
+        }
+    }
+    constexpr T fetch_add(T value, memory_order mo) {
+        if (mo == memory_order_unordered) {
+            auto old = t_;
+            T output;
+            if constexpr (std::is_floating_point_v<T>) {
+                output = t_ + value;
+            } else /* constexpr */ {
+                (void)__builtin_add_overflow(t_, value, &output);
+            }
+            store(output, mo);
+            return old;
+        } else {
+            return __atomic_fetch_add(&t_, value, to_gnu_memory_order(mo));
+        }
+    }
+    constexpr T fetch_sub(T value) {
+        if constexpr (MO == memory_order_unordered) {
+            auto old = t_;
+            T output;
+            if constexpr (std::is_floating_point_v<T>) {
+                output = t_ - value;
+            } else /* constexpr */ {
+                (void)__builtin_sub_overflow(t_, value, &output);
+            }
+            store(output);
+            return old;
+        } else /* constexpr */ {
+            return fetch_sub(value, MO);
+        }
+    }
+    constexpr T fetch_sub(T value, memory_order mo) {
+        if (mo == memory_order_unordered) {
+            auto old = t_;
+            T output;
+            if constexpr (std::is_floating_point_v<T>) {
+                output = t_ - value;
+            } else /* constexpr */ {
+                (void)__builtin_sub_overflow(t_, value, &output);
+            }
+            store(output, mo);
+            return old;
+        } else {
+            return __atomic_fetch_sub(&t_, value, to_gnu_memory_order(mo));
+        }
+    }
+    constexpr T fetch_and(T value, memory_order mo = MO) {
+        if (mo == memory_order_unordered) {
+            auto old = t_;
+            t_ &= value;
+            return old;
+        } else {
+            return __atomic_fetch_and(&t_, value, to_gnu_memory_order(mo));
+        }
+    }
+    constexpr T fetch_or(T value, memory_order mo = MO) {
+        if (mo == memory_order_unordered) {
+            auto old = t_;
+            t_ |= value;
+            return old;
+        } else {
+            return __atomic_fetch_or(&t_, value, to_gnu_memory_order(mo));
+        }
+    }
+    constexpr T fetch_xor(T value, memory_order mo = MO) {
+        if (mo == memory_order_unordered) {
+            auto old = t_;
+            t_ ^= value;
+            return old;
+        } else {
+            return __atomic_fetch_xor(&t_, value, to_gnu_memory_order(mo));
+        }
+    }
+
+    bool compare_exchange_weak(VT& expected, T desired, memory_order mo = MO) {
+        if (mo == memory_order_unordered) {
+            if (t_ == expected) {
+                t_= desired;
+                return true;
+            } else {
+                expected = t_;
+                return false;
+            }
+        } else {
+            return __atomic_compare_exchange(&t_,
+                    const_cast<T*>(&expected),  // builtin does not take volatile ptr.
+                    &desired,
+                    true /* weak */,
+                    to_gnu_memory_order(mo),
+                    to_gnu_load_memory_order(mo));
+        }
+    }
+
+private:
+    // align 8 byte long long/double on 8 bytes on x86.
+    VT t_ __attribute__((aligned(std::max(sizeof(VT), alignof(VT)))));
+};
+
+} // namespace android::audio_utils
+
+#pragma pop_macro("LOG_TAG")
diff --git a/audio_utils/include/audio_utils/intrinsic_utils.h b/audio_utils/include/audio_utils/intrinsic_utils.h
index 9c1eda5d..a531a4fc 100644
--- a/audio_utils/include/audio_utils/intrinsic_utils.h
+++ b/audio_utils/include/audio_utils/intrinsic_utils.h
@@ -18,6 +18,7 @@
 #define ANDROID_AUDIO_UTILS_INTRINSIC_UTILS_H
 
 #include <array>  // std::size
+#include <cstdlib>  // std::abs
 #include <type_traits>
 #include "template_utils.h"
 
diff --git a/audio_utils/include/audio_utils/mutex.h b/audio_utils/include/audio_utils/mutex.h
index 31c9da90..d4ae4b67 100644
--- a/audio_utils/include/audio_utils/mutex.h
+++ b/audio_utils/include/audio_utils/mutex.h
@@ -17,6 +17,7 @@
 #pragma once
 
 #include <android-base/thread_annotations.h>
+#include <audio_utils/atomic.h>
 #include <audio_utils/safe_math.h>
 #include <audio_utils/threads.h>
 #include <utils/Log.h>
@@ -24,10 +25,12 @@
 
 #include <algorithm>
 #include <array>
+#include <atomic>
 #include <cmath>
 #include <map>
 #include <memory>
 #include <mutex>
+#include <queue>
 #include <sys/syscall.h>
 #include <unordered_map>
 #include <unordered_set>
@@ -120,6 +123,47 @@ class AudioMutexAttributes;
 template <typename T> class mutex_impl;
 using mutex = mutex_impl<AudioMutexAttributes>;
 
+// fair_mutex is a mutex that guarantees fairness: threads acquire the lock in the
+// order they attempt to acquire it.
+//
+// This is implemented by maintaining a queue of threads waiting to acquire the
+// lock. When a thread attempts to acquire the lock, it adds itself to the
+// queue and waits until it is at the front of the queue if waiting is needed.
+// When a thread releases the lock, it notifies the next thread in the queue.
+class CAPABILITY("mutex") fair_mutex {
+public:
+    void lock() ACQUIRE() {
+        std::unique_lock ul(mutex_);
+        if (++clients_ == 1) return;  // we're the only one.
+        auto cvp = std::make_shared<std::pair<bool, std::condition_variable>>();
+        queue_.push(cvp);
+        while (!cvp->first) {
+            cvp->second.wait(ul);
+        }
+    }
+
+    void unlock() RELEASE() {
+        std::shared_ptr<std::pair<bool, std::condition_variable>> cvp;
+        {
+            std::lock_guard lg(mutex_);
+            if (--clients_ == 0) return;  // noone else.
+            LOG_ALWAYS_FATAL_IF(clients_ < 0,
+                    "%s: unlock called too many times (%lld)",
+                    __func__, (long long)clients_);
+            cvp = queue_.front();
+            cvp->first = true;
+            queue_.pop();
+        }
+        cvp->second.notify_all();
+    }
+
+private:
+    std::mutex mutex_;
+    std::queue<std::shared_ptr<std::pair<bool, std::condition_variable>>>
+            queue_ GUARDED_BY(mutex_);
+    int64_t clients_ GUARDED_BY(mutex_) = 0;
+};
+
 // Capabilities in priority order
 // (declaration only, value is nullptr)
 inline mutex* Spatializer_Mutex;
@@ -400,80 +444,6 @@ public:
     static constexpr bool abort_on_invalid_unlock_ = true;
 };
 
-// relaxed_atomic implements the same features as std::atomic<T> but using
-// std::memory_order_relaxed as default.
-//
-// This is the minimum consistency for the multiple writer multiple reader case.
-
-template <typename T>
-class relaxed_atomic : private std::atomic<T> {
-public:
-    constexpr relaxed_atomic(T desired = {}) : std::atomic<T>(desired) {}
-    operator T() const { return std::atomic<T>::load(std::memory_order_relaxed); }
-    T operator=(T desired) {
-        std::atomic<T>::store(desired, std::memory_order_relaxed); return desired;
-    }
-
-    T operator--() { return std::atomic<T>::fetch_sub(1, std::memory_order_relaxed) - 1; }
-    T operator++() { return std::atomic<T>::fetch_add(1, std::memory_order_relaxed) + 1;  }
-    T operator+=(const T value) {
-        return std::atomic<T>::fetch_add(value, std::memory_order_relaxed) + value;
-    }
-
-    T load(std::memory_order order = std::memory_order_relaxed) const {
-        return std::atomic<T>::load(order);
-    }
-    T fetch_add(T arg, std::memory_order order =std::memory_order_relaxed) {
-        return std::atomic<T>::fetch_add(arg, order);
-    }
-    bool compare_exchange_weak(
-            T& expected, T desired, std::memory_order order = std::memory_order_relaxed) {
-        return std::atomic<T>::compare_exchange_weak(expected, desired, order);
-    }
-};
-
-// unordered_atomic implements data storage such that memory reads have a value
-// consistent with a memory write in some order, i.e. not having values
-// "out of thin air".
-//
-// Unordered memory reads and writes may not actually take place but be implicitly cached.
-// Nevertheless, a memory read should return at least as contemporaneous a value
-// as the last memory write before the write thread memory barrier that
-// preceded the most recent read thread memory barrier.
-//
-// This is weaker than relaxed_atomic and has no equivalent C++ terminology.
-// unordered_atomic would be used for a single writer, multiple reader case,
-// where data access of type T would be a implemented by the compiler and
-// hw architecture with a single "uninterruptible" memory operation.
-// (The current implementation holds true for general realized CPU architectures).
-// Note that multiple writers would cause read-modify-write unordered_atomic
-// operations to have inconsistent results.
-//
-// unordered_atomic is implemented with normal operations such that compiler
-// optimizations can take place which would otherwise be discouraged for atomics.
-// https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2016/p0062r1.html
-
-// VT may be volatile qualified, if desired, or a normal arithmetic type.
-template <typename VT>
-class unordered_atomic {
-    using T = std::decay_t<VT>;
-    static_assert(std::atomic<T>::is_always_lock_free);
-public:
-    constexpr unordered_atomic(T desired = {}) : t_(desired) {}
-    operator T() const { return t_; }
-    T operator=(T desired) { t_ = desired; return desired; }
-
-    // a volatile ++t_ or t_ += 1 is deprecated in C++20.
-    T operator--() { return operator=(t_ - 1); }
-    T operator++() { return operator=(t_ + 1); }
-    T operator+=(const T value) { return operator=(t_ + value); }
-
-    T load(std::memory_order order = std::memory_order_relaxed) const { (void)order; return t_; }
-
-private:
-    VT t_;
-};
-
 inline constexpr pid_t kInvalidTid = -1;
 
 // While std::atomic with the default std::memory_order_seq_cst
@@ -487,7 +457,7 @@ inline constexpr pid_t kInvalidTid = -1;
 //
 // We used relaxed_atomic instead of std::atomic/memory_order_seq_cst here.
 template <typename T>
-using stats_atomic = relaxed_atomic<T>;
+using stats_atomic = atomic<T, memory_order_relaxed>;
 
 // thread_atomic is a single writer multiple reader object.
 //
@@ -497,7 +467,7 @@ using stats_atomic = relaxed_atomic<T>;
 //
 // We use unordered_atomic instead of std::atomic/memory_order_seq_cst here.
 template <typename T>
-using thread_atomic = unordered_atomic<T>;
+using thread_atomic = atomic<T, memory_order_unordered>;
 
 inline void compiler_memory_barrier() {
     // Reads or writes are not migrated or cached by the compiler across this barrier.
@@ -524,58 +494,12 @@ inline void compiler_memory_barrier() {
 inline void metadata_memory_barrier_if_needed() {
     // check the level of atomicity used for thread metadata to alter the
     // use of a barrier here.
-    if constexpr (std::is_same_v<thread_atomic<int32_t>, unordered_atomic<int32_t>>
-            || std::is_same_v<thread_atomic<int32_t>, relaxed_atomic<int32_t>>) {
+    if constexpr (std::is_same_v<thread_atomic<int32_t>, atomic<int32_t, memory_order_unordered>>
+            || std::is_same_v<thread_atomic<int32_t>, atomic<int32_t, memory_order_relaxed>>) {
         compiler_memory_barrier();
     }
 }
 
-/**
- * Helper method to accumulate floating point values to an atomic
- * prior to C++23 support of atomic<float> atomic<double> accumulation.
- */
-template <typename AccumulateType, typename ValueType>
-requires std::is_floating_point<AccumulateType>::value
-void atomic_add_to(std::atomic<AccumulateType> &dst, ValueType src,
-        std::memory_order order = std::memory_order_seq_cst) {
-    static_assert(std::atomic<AccumulateType>::is_always_lock_free);
-    AccumulateType expected;
-    do {
-        expected = dst;
-    } while (!dst.compare_exchange_weak(expected, expected + src, order));
-}
-
-template <typename AccumulateType, typename ValueType>
-requires std::is_integral<AccumulateType>::value
-void atomic_add_to(std::atomic<AccumulateType> &dst, ValueType src,
-        std::memory_order order = std::memory_order_seq_cst) {
-    dst.fetch_add(src, order);
-}
-
-template <typename AccumulateType, typename ValueType>
-requires std::is_floating_point<AccumulateType>::value
-void atomic_add_to(relaxed_atomic<AccumulateType> &dst, ValueType src,
-        std::memory_order order = std::memory_order_relaxed) {
-    AccumulateType expected;
-    do {
-        expected = dst;
-    } while (!dst.compare_exchange_weak(expected, expected + src, order));
-}
-
-template <typename AccumulateType, typename ValueType>
-requires std::is_integral<AccumulateType>::value
-void atomic_add_to(relaxed_atomic<AccumulateType> &dst, ValueType src,
-        std::memory_order order = std::memory_order_relaxed) {
-    dst.fetch_add(src, order);
-}
-
-template <typename AccumulateType, typename ValueType>
-void atomic_add_to(unordered_atomic<AccumulateType> &dst, ValueType src,
-        std::memory_order order = std::memory_order_relaxed) {
-    (void)order; // unused
-    dst = dst + src;
-}
-
 /**
  * mutex_stat is a struct composed of atomic members associated
  * with usage of a particular mutex order.
@@ -601,8 +525,8 @@ struct mutex_stat {
     template <typename WaitTimeType>
     void add_wait_time(WaitTimeType wait_ns) {
         AccumulatorType value_ns = wait_ns;
-        atomic_add_to(wait_sum_ns, value_ns);
-        atomic_add_to(wait_sumsq_ns, value_ns * value_ns);
+        (void) wait_sum_ns.fetch_add(value_ns);
+        (void) wait_sumsq_ns.fetch_add(value_ns * value_ns);
     }
 
     std::string to_string() const {
diff --git a/audio_utils/include/audio_utils/threads.h b/audio_utils/include/audio_utils/threads.h
index 418d5b8f..41e43042 100644
--- a/audio_utils/include/audio_utils/threads.h
+++ b/audio_utils/include/audio_utils/threads.h
@@ -18,6 +18,7 @@
 
 #include <algorithm>
 #include <bitset>
+#include <sched.h>         // CPU_SETSIZE
 #include <sys/syscall.h>   // SYS_gettid
 #include <unistd.h>        // bionic gettid
 #include <utils/Errors.h>  // status_t
diff --git a/audio_utils/spdif/OWNERS b/audio_utils/spdif/OWNERS
index f4d51f91..e69de29b 100644
--- a/audio_utils/spdif/OWNERS
+++ b/audio_utils/spdif/OWNERS
@@ -1 +0,0 @@
-philburk@google.com
diff --git a/audio_utils/tests/Android.bp b/audio_utils/tests/Android.bp
index a300c7c3..4266af13 100644
--- a/audio_utils/tests/Android.bp
+++ b/audio_utils/tests/Android.bp
@@ -9,6 +9,28 @@ package {
     default_applicable_licenses: ["system_media_license"],
 }
 
+cc_test {
+    name: "audio_atomic_tests",
+    host_supported: true,
+    srcs: [
+        "audio_atomic_tests.cpp",
+    ],
+    shared_libs: [
+        "libbase",
+        "liblog",
+        "libutils",
+    ],
+    static_libs: [
+        "libaudioutils",
+    ],
+    cflags: [
+        "-Wall",
+        "-Werror",
+        "-Wextra",
+        "-Wthread-safety",
+    ],
+}
+
 cc_test {
     name: "audio_commandthread_tests",
     host_supported: true,
diff --git a/audio_utils/tests/audio_atomic_tests.cpp b/audio_utils/tests/audio_atomic_tests.cpp
new file mode 100644
index 00000000..9a91a2d5
--- /dev/null
+++ b/audio_utils/tests/audio_atomic_tests.cpp
@@ -0,0 +1,246 @@
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
+#include <audio_utils/atomic.h>
+#include <gtest/gtest.h>
+
+#include <random>
+#include <thread>
+
+using namespace android::audio_utils;
+
+// fetch_op always returns previous value
+static_assert(atomic<int, memory_order_unordered>(1).fetch_add(1) == 1);
+static_assert(atomic<int, memory_order_unordered>(1).fetch_sub(1) == 1);
+static_assert(atomic<int, memory_order_unordered>(1).fetch_and(1, memory_order_unordered) == 1);
+static_assert(atomic<int, memory_order_unordered>(1).fetch_or(1, memory_order_unordered) == 1);
+static_assert(atomic<int, memory_order_unordered>(1).fetch_xor(1, memory_order_unordered) == 1);
+
+// op equals always returns current (updated) value
+static_assert(atomic<int, memory_order_unordered>(1).operator+=(1) == 2);
+static_assert(atomic<int, memory_order_unordered>(1).operator-=(1) == 0);
+static_assert(atomic<int, memory_order_unordered>(1).operator&=(1) == 1);
+static_assert(atomic<int, memory_order_unordered>(1).operator|=(1) == 1);
+static_assert(atomic<int, memory_order_unordered>(1).operator^=(1) == 0);
+
+// min/max ops
+static_assert(atomic<int, memory_order_unordered>(1).min(2, memory_order_unordered) == 1);
+static_assert(atomic<int, memory_order_unordered>(3).min(2, memory_order_unordered) == 2);
+static_assert(atomic<int, memory_order_unordered>(1).max(2, memory_order_unordered) == 2);
+static_assert(atomic<int, memory_order_unordered>(3).max(2, memory_order_unordered) == 3);
+
+// overflow
+static_assert(atomic<int, memory_order_unordered>(INT_MAX).operator+=(INT_MAX)
+         == (INT_MAX << 1));
+static_assert(atomic<int, memory_order_unordered>(-INT_MAX).operator-=(INT_MAX)
+         == (-INT_MAX << 1));
+
+template <android::audio_utils::memory_order MO>
+void testAdd() {
+    constexpr size_t kNumThreads = 10;
+    constexpr size_t kWorkerIterations = 100;
+    std::vector<std::thread> threads;
+    atomic<size_t, MO> value;
+
+    auto worker = [&] {
+        for (size_t i = 0; i < kWorkerIterations; ++i) {
+            ++value;
+        }
+    };
+    for (size_t i = 0; i < kNumThreads; ++i) {
+        threads.emplace_back(worker);
+    }
+    for (auto& t : threads) {
+        t.join();
+    }
+    EXPECT_EQ(value, kNumThreads * kWorkerIterations);
+}
+
+TEST(audio_atomic_tests, add_relaxed) {
+    testAdd<memory_order_relaxed>();
+}
+TEST(audio_atomic_tests, add_acquire) {
+    testAdd<memory_order_acquire>();
+}
+TEST(audio_atomic_tests, add_release) {
+    testAdd<memory_order_release>();
+}
+TEST(audio_atomic_tests, add_acq_rel) {
+    testAdd<memory_order_acq_rel>();
+}
+TEST(audio_atomic_tests, add_seq_cst) {
+    testAdd<memory_order_seq_cst>();
+}
+
+template <android::audio_utils::memory_order MO>
+void testMin() {
+    constexpr size_t kNumThreads = 10;
+    std::vector<std::thread> threads;
+    atomic<size_t, MO> value = INT32_MAX;
+
+    for (size_t i = 0; i < kNumThreads; ++i) {
+        threads.emplace_back([&value, i] {
+            value.min(i);
+        });
+    }
+    for (auto& t : threads) {
+        t.join();
+    }
+    EXPECT_EQ(value, 0UL);
+}
+
+TEST(audio_atomic_tests, min_relaxed) {
+testMin<memory_order_relaxed>();
+}
+TEST(audio_atomic_tests, min_acquire) {
+testMin<memory_order_acquire>();
+}
+TEST(audio_atomic_tests, min_release) {
+testMin<memory_order_release>();
+}
+TEST(audio_atomic_tests, min_acq_rel) {
+testMin<memory_order_acq_rel>();
+}
+TEST(audio_atomic_tests, min_seq_cst) {
+testMin<memory_order_seq_cst>();
+}
+
+template <android::audio_utils::memory_order MO>
+void testMax() {
+    constexpr size_t kNumThreads = 10;
+    std::vector<std::thread> threads;
+    atomic<size_t, MO> value = 0;
+
+    for (size_t i = 0; i < kNumThreads; ++i) {
+        threads.emplace_back([&value, i] {
+            value.max(i);
+        });
+    }
+    for (auto& t : threads) {
+        t.join();
+    }
+    EXPECT_EQ(value, kNumThreads - 1);
+}
+
+TEST(audio_atomic_tests, max_relaxed) {
+testMax<memory_order_relaxed>();
+}
+TEST(audio_atomic_tests, max_acquire) {
+testMax<memory_order_acquire>();
+}
+TEST(audio_atomic_tests, max_release) {
+testMax<memory_order_release>();
+}
+TEST(audio_atomic_tests, max_acq_rel) {
+testMax<memory_order_acq_rel>();
+}
+TEST(audio_atomic_tests, max_seq_cst) {
+testMax<memory_order_seq_cst>();
+}
+
+template <typename T, android::audio_utils::memory_order MO>
+void testOp() {
+    size_t kTrials = 1000;
+    std::minstd_rand gen(45);
+    std::uniform_int_distribution<T> dis(-100, 100);
+
+    for (size_t i = 0; i < kTrials; ++i) {
+        int r = dis(gen);
+        T value(r);
+        atomic<T, MO> avalue(r);
+        EXPECT_EQ(value, avalue);
+
+        r = dis(gen);
+        value += r;
+        avalue += r;
+        EXPECT_EQ(value, avalue);
+
+        r = dis(gen);
+        value -= r;
+        avalue -= r;
+        EXPECT_EQ(value, avalue);
+
+        r = dis(gen);
+        value &= r;
+        avalue &= r;
+        EXPECT_EQ(value, avalue);
+
+        r = dis(gen);
+        value |= r;
+        avalue |= r;
+        EXPECT_EQ(value, avalue);
+
+        r = dis(gen);
+        value ^= r;
+        avalue ^= r;
+        EXPECT_EQ(value, avalue);
+
+        r = dis(gen);
+        value  = std::min(value, r);
+        avalue.min(r);
+        EXPECT_EQ(value, avalue);
+
+        r = dis(gen);
+        value  = std::max(value, r);
+        avalue.max(r);
+        EXPECT_EQ(value, avalue);
+    }
+}
+
+TEST(audio_atomic_tests, op_relaxed) {
+    testOp<int32_t, memory_order_relaxed>();
+}
+TEST(audio_atomic_tests, op_acquire) {
+    testOp<int32_t, memory_order_acquire>();
+}
+TEST(audio_atomic_tests, op_release) {
+    testOp<int32_t, memory_order_release>();
+}
+TEST(audio_atomic_tests, op_acq_rel) {
+    testOp<int32_t, memory_order_acq_rel>();
+}
+TEST(audio_atomic_tests, op_seq_cst) {
+    testOp<int32_t, memory_order_seq_cst>();
+}
+
+template <typename T, android::audio_utils::memory_order MO>
+void testOverflow() {
+    atomic<T, MO> avalue(std::numeric_limits<T>::max());
+    avalue += avalue;
+    EXPECT_EQ(avalue, std::numeric_limits<T>::max() << 1);
+
+    if constexpr (std::is_signed_v<T>) {
+         avalue = -std::numeric_limits<T>::max();
+         avalue -= std::numeric_limits<T>::max();
+         EXPECT_EQ(avalue, -std::numeric_limits<T>::max() << 1);
+    } else /* constexpr */ {
+         avalue = 0;
+         avalue -= std::numeric_limits<T>::max();
+         EXPECT_EQ(avalue, static_cast<T>(-std::numeric_limits<T>::max()));
+    }
+}
+
+TEST(audio_atomic_tests, overflow) {
+    testOverflow<int32_t, memory_order_unordered>();
+    testOverflow<uint32_t, memory_order_unordered>();
+    testOverflow<int64_t, memory_order_unordered>();
+    testOverflow<uint64_t, memory_order_unordered>();
+
+    testOverflow<int32_t, memory_order_relaxed>();
+    testOverflow<uint32_t, memory_order_relaxed>();
+    testOverflow<int64_t, memory_order_relaxed>();
+    testOverflow<uint64_t, memory_order_relaxed>();
+}
diff --git a/audio_utils/tests/audio_mutex_tests.cpp b/audio_utils/tests/audio_mutex_tests.cpp
index 4ba0acf6..795d356e 100644
--- a/audio_utils/tests/audio_mutex_tests.cpp
+++ b/audio_utils/tests/audio_mutex_tests.cpp
@@ -438,6 +438,84 @@ TEST(audio_mutex_tests, StdTimedLock) {
         EXPECT_TRUE(success);
     }
 }
+
+TEST(audio_mutex_tests, FairMutexBasic) {
+    audio_utils::fair_mutex fm;
+    int critical_section = 0;
+    constexpr int kNumThreads = 2;
+    constexpr int kWorkerIterations = 100;
+    std::vector<std::thread> threads;
+
+    auto worker = [&] {
+        for (int i = 0; i < kWorkerIterations; ++i) {
+            std::lock_guard lg(fm);
+            ++critical_section;
+            std::this_thread::yield();
+        }
+    };
+
+    for (int i = 0; i < kNumThreads; ++i) {
+        threads.emplace_back(worker);
+    }
+
+    for (auto& t : threads) {
+        t.join();
+    }
+
+    EXPECT_EQ(critical_section, kNumThreads * kWorkerIterations);
+}
+
+TEST(audio_mutex_tests, FairMutexFairness) {
+    audio_utils::fair_mutex fm;
+    std::mutex order_mutex;
+    std::vector<int> acquisition_order;
+    const std::vector<int> expected_order = {1, 2, 3, 4};
+
+    // Main thread acquires lock first to establish a barrier
+    std::unique_lock outer_lg(fm);
+
+    // Synchronization control variables (one atomic flag per thread)
+    std::vector<std::atomic<bool>> thread_ready(expected_order.size() + 1);
+    for (auto& flag : thread_ready) {
+        flag.store(false, std::memory_order_relaxed);
+    }
+
+    // Generic thread task template
+    auto thread_task = [&](int thread_id, std::atomic<bool>& ready_flag) {
+        ready_flag.store(true);  // Notify main thread of startup completion
+        std::lock_guard inner_lg(fm);  // Blocking lock acquisition
+
+        {   // Record lock acquisition order
+            std::lock_guard lgo(order_mutex);
+            acquisition_order.push_back(thread_id);
+        }
+    };
+
+    // Start four threads sequentially
+    std::vector<std::thread> threads;
+    for (size_t i = 0; i < expected_order.size(); ++i) {
+        int thread_id = expected_order[i];
+        threads.emplace_back([&, thread_id] {
+            thread_task(thread_id, thread_ready[thread_id]);
+        });
+        while (!thread_ready[thread_id].load(
+            std::memory_order_acquire)) {} // Wait until thread enters wait queue
+    }
+
+    // Ensure all threads enter kernel-level wait queue
+    std::this_thread::sleep_for(100ms);
+    outer_lg.unlock();  // Release lock to trigger contention
+
+    // Wait for all threads to complete
+    for (auto& t : threads) {
+        t.join();
+    }
+
+    // Validation loop
+    for (size_t i = 0; i < expected_order.size(); ++i) {
+        EXPECT_EQ(acquisition_order[i], expected_order[i]);
+    }
+}
 // The following tests are evaluated for the android::audio_utils::mutex
 // Non-Priority Inheritance and Priority Inheritance cases.
 
diff --git a/audio_utils/tests/run_remote_tests.cpp b/audio_utils/tests/run_remote_tests.cpp
index a3b31874..72856e67 100644
--- a/audio_utils/tests/run_remote_tests.cpp
+++ b/audio_utils/tests/run_remote_tests.cpp
@@ -20,16 +20,16 @@
 
 static void WorkerThread(android::audio_utils::RunRemote& runRemote) {
     while (true) {
-        const int c = runRemote.getc();
+        const int c = runRemote.getChar();
         switch (c) {
             case 'a':
-                runRemote.putc('a');  // send ack
+                runRemote.putChar('a');  // send ack
                 break;
             case 'b':
-                runRemote.putc('b');
+                runRemote.putChar('b');
                 break;
             default:
-                runRemote.putc('x');
+                runRemote.putChar('x');
                 break;
         }
     }
@@ -39,15 +39,15 @@ TEST(RunRemote, basic) {
     auto remoteWorker = std::make_shared<android::audio_utils::RunRemote>(WorkerThread);
     remoteWorker->run();
 
-    remoteWorker->putc('a');
-    EXPECT_EQ('a', remoteWorker->getc());
+    remoteWorker->putChar('a');
+    EXPECT_EQ('a', remoteWorker->getChar());
 
-    remoteWorker->putc('b');
-    EXPECT_EQ('b', remoteWorker->getc());
+    remoteWorker->putChar('b');
+    EXPECT_EQ('b', remoteWorker->getChar());
 
-    remoteWorker->putc('c');
-    EXPECT_EQ('x', remoteWorker->getc());
+    remoteWorker->putChar('c');
+    EXPECT_EQ('x', remoteWorker->getChar());
 
     remoteWorker->stop();
-    EXPECT_EQ(-1, remoteWorker->getc());  // remote closed
+    EXPECT_EQ(-1, remoteWorker->getChar());  // remote closed
 }
diff --git a/camera/docs/README.md b/camera/docs/README.md
index 8a8e0864..27684bb3 100644
--- a/camera/docs/README.md
+++ b/camera/docs/README.md
@@ -8,11 +8,11 @@ C code, Java code, and even XML itself (as a round-trip validity check).
 
 ## Dependencies
 * Python 2.7.x+
-* Beautiful Soup 4+ - HTML/XML parser, used to parse `metadata_definitions.xml`
-* Mako 0.7+         - Template engine, needed to do file generation.
-* Markdown 2.1+     - Plain text to HTML converter, for docs formatting.
-* Tidy              - Cleans up the XML/HTML files.
-* XML Lint          - Validates XML against XSD schema.
+* Beautiful Soup 4.13.x+ - HTML/XML parser, used to parse `metadata_definitions.xml`
+* Mako 0.7+              - Template engine, needed to do file generation.
+* Markdown 2.1+          - Plain text to HTML converter, for docs formatting.
+* Tidy                   - Cleans up the XML/HTML files.
+* XML Lint               - Validates XML against XSD schema.
 
 ## Quick Setup (Debian Rodete):
 NOTE: Debian (and most Linux distros) no longer package Python 2.
diff --git a/camera/docs/docs.html b/camera/docs/docs.html
index da4abace..6427895f 100644
--- a/camera/docs/docs.html
+++ b/camera/docs/docs.html
@@ -3235,7 +3235,12 @@ conditions.<wbr/></p>
 (triggered by <a href="#controls_android.control.aePrecaptureTrigger">android.<wbr/>control.<wbr/>ae<wbr/>Precapture<wbr/>Trigger</a>) and
 may be fired for captures for which the
 <a href="#controls_android.control.captureIntent">android.<wbr/>control.<wbr/>capture<wbr/>Intent</a> field is set to
-STILL_<wbr/>CAPTURE</p></span>
+STILL_<wbr/>CAPTURE.<wbr/></p>
+<p>It's important to wait for the precapture sequence
+to complete (i.<wbr/>e.,<wbr/> <a href="#dynamic_android.control.aeState">android.<wbr/>control.<wbr/>ae<wbr/>State</a> reaches
+FLASH_<wbr/>REQUIRED,<wbr/> CONVERGED,<wbr/> or LOCKED) before submitting a
+STILL_<wbr/>CAPTURE request.<wbr/> Otherwise,<wbr/> in low-light conditions,<wbr/>
+the image captures with flash fired won't have correct exposures.<wbr/></p></span>
                   </li>
                   <li>
                     <span class="entry_type_enum_name">ON_ALWAYS_FLASH (v3.2)</span>
@@ -3246,7 +3251,12 @@ captures.<wbr/></p>
 (triggered by <a href="#controls_android.control.aePrecaptureTrigger">android.<wbr/>control.<wbr/>ae<wbr/>Precapture<wbr/>Trigger</a>) and
 will always be fired for captures for which the
 <a href="#controls_android.control.captureIntent">android.<wbr/>control.<wbr/>capture<wbr/>Intent</a> field is set to
-STILL_<wbr/>CAPTURE</p></span>
+STILL_<wbr/>CAPTURE.<wbr/></p>
+<p>It's important to wait for the precapture sequence
+to complete (i.<wbr/>e.,<wbr/> <a href="#dynamic_android.control.aeState">android.<wbr/>control.<wbr/>ae<wbr/>State</a> reaches
+FLASH_<wbr/>REQUIRED,<wbr/> CONVERGED,<wbr/> or LOCKED) Dbefore submitting a
+STILL_<wbr/>CAPTURE request.<wbr/> Otherwise,<wbr/> in low-light conditions,<wbr/>
+the image captures with flash fired won't have correct exposures.<wbr/></p></span>
                   </li>
                   <li>
                     <span class="entry_type_enum_name">ON_AUTO_FLASH_REDEYE (v3.2)</span>
@@ -6269,7 +6279,7 @@ to control zoom levels.<wbr/></p>
             <td class="entry_details" colspan="6">
               <p>If set to AUTO,<wbr/> the camera device detects which capture request key the application uses
 to do zoom,<wbr/> <a href="#controls_android.scaler.cropRegion">android.<wbr/>scaler.<wbr/>crop<wbr/>Region</a> or <a href="#controls_android.control.zoomRatio">android.<wbr/>control.<wbr/>zoom<wbr/>Ratio</a>.<wbr/> If
-the application doesn't set android.<wbr/>scaler.<wbr/>zoom<wbr/>Ratio or sets it to 1.<wbr/>0 in the capture
+the application doesn't set <a href="#controls_android.control.zoomRatio">android.<wbr/>control.<wbr/>zoom<wbr/>Ratio</a> or sets it to 1.<wbr/>0 in the capture
 request,<wbr/> the effective zoom level is reflected in <a href="#controls_android.scaler.cropRegion">android.<wbr/>scaler.<wbr/>crop<wbr/>Region</a> in capture
 results.<wbr/> If <a href="#controls_android.control.zoomRatio">android.<wbr/>control.<wbr/>zoom<wbr/>Ratio</a> is set to values other than 1.<wbr/>0,<wbr/> the effective
 zoom level is reflected in <a href="#controls_android.control.zoomRatio">android.<wbr/>control.<wbr/>zoom<wbr/>Ratio</a>.<wbr/> AUTO is the default value
@@ -6299,7 +6309,7 @@ and not for HAL consumption.<wbr/></p>
                 
           <tr class="entry" id="controls_android.control.aePriorityMode">
             <td class="entry_name
-             " rowspan="5">
+             " rowspan="3">
               android.<wbr/>control.<wbr/>ae<wbr/>Priority<wbr/>Mode
             </td>
             <td class="entry_type">
@@ -6377,15 +6387,6 @@ given capture will be available in its CaptureResult.<wbr/></p>
             </td>
           </tr>
 
-          <tr class="entries_header">
-            <th class="th_details" colspan="6">HAL Implementation Details</th>
-          </tr>
-          <tr class="entry_cont">
-            <td class="entry_details" colspan="6">
-              <p>The total sensitivity applied for SENSOR_<wbr/>SENSITIVITY_<wbr/>PRIORITY should not be
-adjusted by any HAL applied <a href="#controls_android.control.postRawSensitivityBoost">android.<wbr/>control.<wbr/>post<wbr/>Raw<wbr/>Sensitivity<wbr/>Boost</a>.<wbr/></p>
-            </td>
-          </tr>
 
           <tr class="entry_spacer"><td class="entry_spacer" colspan="7"></td></tr>
            <!-- end of entry -->
@@ -8873,7 +8874,12 @@ conditions.<wbr/></p>
 (triggered by <a href="#controls_android.control.aePrecaptureTrigger">android.<wbr/>control.<wbr/>ae<wbr/>Precapture<wbr/>Trigger</a>) and
 may be fired for captures for which the
 <a href="#controls_android.control.captureIntent">android.<wbr/>control.<wbr/>capture<wbr/>Intent</a> field is set to
-STILL_<wbr/>CAPTURE</p></span>
+STILL_<wbr/>CAPTURE.<wbr/></p>
+<p>It's important to wait for the precapture sequence
+to complete (i.<wbr/>e.,<wbr/> <a href="#dynamic_android.control.aeState">android.<wbr/>control.<wbr/>ae<wbr/>State</a> reaches
+FLASH_<wbr/>REQUIRED,<wbr/> CONVERGED,<wbr/> or LOCKED) before submitting a
+STILL_<wbr/>CAPTURE request.<wbr/> Otherwise,<wbr/> in low-light conditions,<wbr/>
+the image captures with flash fired won't have correct exposures.<wbr/></p></span>
                   </li>
                   <li>
                     <span class="entry_type_enum_name">ON_ALWAYS_FLASH (v3.2)</span>
@@ -8884,7 +8890,12 @@ captures.<wbr/></p>
 (triggered by <a href="#controls_android.control.aePrecaptureTrigger">android.<wbr/>control.<wbr/>ae<wbr/>Precapture<wbr/>Trigger</a>) and
 will always be fired for captures for which the
 <a href="#controls_android.control.captureIntent">android.<wbr/>control.<wbr/>capture<wbr/>Intent</a> field is set to
-STILL_<wbr/>CAPTURE</p></span>
+STILL_<wbr/>CAPTURE.<wbr/></p>
+<p>It's important to wait for the precapture sequence
+to complete (i.<wbr/>e.,<wbr/> <a href="#dynamic_android.control.aeState">android.<wbr/>control.<wbr/>ae<wbr/>State</a> reaches
+FLASH_<wbr/>REQUIRED,<wbr/> CONVERGED,<wbr/> or LOCKED) Dbefore submitting a
+STILL_<wbr/>CAPTURE request.<wbr/> Otherwise,<wbr/> in low-light conditions,<wbr/>
+the image captures with flash fired won't have correct exposures.<wbr/></p></span>
                   </li>
                   <li>
                     <span class="entry_type_enum_name">ON_AUTO_FLASH_REDEYE (v3.2)</span>
@@ -13021,7 +13032,7 @@ to control zoom levels.<wbr/></p>
             <td class="entry_details" colspan="6">
               <p>If set to AUTO,<wbr/> the camera device detects which capture request key the application uses
 to do zoom,<wbr/> <a href="#controls_android.scaler.cropRegion">android.<wbr/>scaler.<wbr/>crop<wbr/>Region</a> or <a href="#controls_android.control.zoomRatio">android.<wbr/>control.<wbr/>zoom<wbr/>Ratio</a>.<wbr/> If
-the application doesn't set android.<wbr/>scaler.<wbr/>zoom<wbr/>Ratio or sets it to 1.<wbr/>0 in the capture
+the application doesn't set <a href="#controls_android.control.zoomRatio">android.<wbr/>control.<wbr/>zoom<wbr/>Ratio</a> or sets it to 1.<wbr/>0 in the capture
 request,<wbr/> the effective zoom level is reflected in <a href="#controls_android.scaler.cropRegion">android.<wbr/>scaler.<wbr/>crop<wbr/>Region</a> in capture
 results.<wbr/> If <a href="#controls_android.control.zoomRatio">android.<wbr/>control.<wbr/>zoom<wbr/>Ratio</a> is set to values other than 1.<wbr/>0,<wbr/> the effective
 zoom level is reflected in <a href="#controls_android.control.zoomRatio">android.<wbr/>control.<wbr/>zoom<wbr/>Ratio</a>.<wbr/> AUTO is the default value
@@ -13051,7 +13062,7 @@ and not for HAL consumption.<wbr/></p>
                 
           <tr class="entry" id="dynamic_android.control.aePriorityMode">
             <td class="entry_name
-             " rowspan="5">
+             " rowspan="3">
               android.<wbr/>control.<wbr/>ae<wbr/>Priority<wbr/>Mode
             </td>
             <td class="entry_type">
@@ -13129,15 +13140,6 @@ given capture will be available in its CaptureResult.<wbr/></p>
             </td>
           </tr>
 
-          <tr class="entries_header">
-            <th class="th_details" colspan="6">HAL Implementation Details</th>
-          </tr>
-          <tr class="entry_cont">
-            <td class="entry_details" colspan="6">
-              <p>The total sensitivity applied for SENSOR_<wbr/>SENSITIVITY_<wbr/>PRIORITY should not be
-adjusted by any HAL applied <a href="#controls_android.control.postRawSensitivityBoost">android.<wbr/>control.<wbr/>post<wbr/>Raw<wbr/>Sensitivity<wbr/>Boost</a>.<wbr/></p>
-            </td>
-          </tr>
 
           <tr class="entry_spacer"><td class="entry_spacer" colspan="7"></td></tr>
            <!-- end of entry -->
diff --git a/camera/docs/metadata_definitions.xml b/camera/docs/metadata_definitions.xml
index b85ee2f0..40970c90 100644
--- a/camera/docs/metadata_definitions.xml
+++ b/camera/docs/metadata_definitions.xml
@@ -762,7 +762,13 @@ xsi:schemaLocation="http://schemas.android.com/service/camera/metadata/ metadata
                 (triggered by android.control.aePrecaptureTrigger) and
                 may be fired for captures for which the
                 android.control.captureIntent field is set to
-                STILL_CAPTURE
+                STILL_CAPTURE.
+
+                It's important to wait for the precapture sequence
+                to complete (i.e., android.control.aeState reaches
+                FLASH_REQUIRED, CONVERGED, or LOCKED) before submitting a
+                STILL_CAPTURE request. Otherwise, in low-light conditions,
+                the image captures with flash fired won't have correct exposures.
               </notes>
             </value>
             <value>ON_ALWAYS_FLASH
@@ -775,7 +781,13 @@ xsi:schemaLocation="http://schemas.android.com/service/camera/metadata/ metadata
                 (triggered by android.control.aePrecaptureTrigger) and
                 will always be fired for captures for which the
                 android.control.captureIntent field is set to
-                STILL_CAPTURE
+                STILL_CAPTURE.
+
+                It's important to wait for the precapture sequence
+                to complete (i.e., android.control.aeState reaches
+                FLASH_REQUIRED, CONVERGED, or LOCKED) Dbefore submitting a
+                STILL_CAPTURE request. Otherwise, in low-light conditions,
+                the image captures with flash fired won't have correct exposures.
               </notes>
             </value>
             <value>ON_AUTO_FLASH_REDEYE
@@ -4112,7 +4124,7 @@ xsi:schemaLocation="http://schemas.android.com/service/camera/metadata/ metadata
           <details>
             If set to AUTO, the camera device detects which capture request key the application uses
             to do zoom, android.scaler.cropRegion or android.control.zoomRatio. If
-            the application doesn't set android.scaler.zoomRatio or sets it to 1.0 in the capture
+            the application doesn't set android.control.zoomRatio or sets it to 1.0 in the capture
             request, the effective zoom level is reflected in android.scaler.cropRegion in capture
             results. If android.control.zoomRatio is set to values other than 1.0, the effective
             zoom level is reflected in android.control.zoomRatio. AUTO is the default value
@@ -4186,10 +4198,6 @@ xsi:schemaLocation="http://schemas.android.com/service/camera/metadata/ metadata
             and android.sensor.frameDuration. The overridden fields for a
             given capture will be available in its CaptureResult.
           </details>
-          <hal_details>
-          The total sensitivity applied for SENSOR_SENSITIVITY_PRIORITY should not be
-          adjusted by any HAL applied android.control.postRawSensitivityBoost.
-          </hal_details>
         </entry>
       </controls>
       <dynamic>
diff --git a/camera/docs/metadata_helpers.py b/camera/docs/metadata_helpers.py
index 35b72e31..7815c699 100644
--- a/camera/docs/metadata_helpers.py
+++ b/camera/docs/metadata_helpers.py
@@ -24,8 +24,6 @@ import markdown
 import textwrap
 import sys
 import bs4
-# Monkey-patch BS4. WBR element must not have an end tag.
-bs4.builder.HTMLTreeBuilder.empty_element_tags.add("wbr")
 
 from collections import OrderedDict, defaultdict
 from operator import itemgetter
diff --git a/camera/tests/camera_metadata_tests.cpp b/camera/tests/camera_metadata_tests.cpp
index bcebf2e1..a99ccc6c 100644
--- a/camera/tests/camera_metadata_tests.cpp
+++ b/camera/tests/camera_metadata_tests.cpp
@@ -1217,6 +1217,8 @@ TEST(camera_metadata, delete_metadata) {
     EXPECT_EQ(num_data, get_camera_metadata_data_count(m));
     EXPECT_EQ(data_capacity, get_camera_metadata_data_capacity(m));
 
+    int64_t exposureTimeExpected = 0;
+    int64_t exposureTimeFound = 0;
     for (size_t i = 0; i < num_entries; i++) {
         camera_metadata_entry e2;
         result = get_camera_metadata_entry(m, i, &e2);
@@ -1224,9 +1226,10 @@ TEST(camera_metadata, delete_metadata) {
         EXPECT_EQ(i, e2.index);
         EXPECT_EQ(ANDROID_SENSOR_EXPOSURE_TIME, e2.tag);
         EXPECT_EQ(TYPE_INT64, e2.type);
-        int64_t exposureTime = i < 1 ? 100 : 200 + 100 * i;
-        EXPECT_EQ(exposureTime, *e2.data.i64);
+        exposureTimeExpected += i < 1 ? 100 : 200 + 100 * i;
+        exposureTimeFound += *e2.data.i64;
     }
+    EXPECT_EQ(exposureTimeExpected, exposureTimeFound);
 }
 
 TEST(camera_metadata, update_metadata) {
@@ -1406,6 +1409,8 @@ TEST(camera_metadata, update_metadata) {
     EXPECT_EQ((size_t)1, e.count);
     EXPECT_EQ(newFrameCount, *e.data.i32);
 
+    int64_t exposureTimeExpected = 0;
+    int64_t exposureTimeFound = 0;
     for (size_t i = 1; i < num_entries; i++) {
         camera_metadata_entry e2;
         result = get_camera_metadata_entry(m, i, &e2);
@@ -1413,9 +1418,10 @@ TEST(camera_metadata, update_metadata) {
         EXPECT_EQ(i, e2.index);
         EXPECT_EQ(ANDROID_SENSOR_EXPOSURE_TIME, e2.tag);
         EXPECT_EQ(TYPE_INT64, e2.type);
-        int64_t exposureTime = 100 * i;
-        EXPECT_EQ(exposureTime, *e2.data.i64);
+        exposureTimeExpected += 100 * i;
+        exposureTimeFound += *e2.data.i64;
     }
+    EXPECT_EQ(exposureTimeExpected, exposureTimeFound);
 
     // Update to bigger than entry
 
@@ -1456,6 +1462,8 @@ TEST(camera_metadata, update_metadata) {
     EXPECT_EQ(newFrameCounts[2], e.data.i32[2]);
     EXPECT_EQ(newFrameCounts[3], e.data.i32[3]);
 
+    exposureTimeExpected = 0;
+    exposureTimeFound = 0;
     for (size_t i = 1; i < num_entries; i++) {
         camera_metadata_entry e2;
         result = get_camera_metadata_entry(m, i, &e2);
@@ -1463,9 +1471,10 @@ TEST(camera_metadata, update_metadata) {
         EXPECT_EQ(i, e2.index);
         EXPECT_EQ(ANDROID_SENSOR_EXPOSURE_TIME, e2.tag);
         EXPECT_EQ(TYPE_INT64, e2.type);
-        int64_t exposureTime = 100 * i;
-        EXPECT_EQ(exposureTime, *e2.data.i64);
+        exposureTimeExpected += 100 * i;
+        exposureTimeFound += *e2.data.i64;
     }
+    EXPECT_EQ(exposureTimeExpected, exposureTimeFound);
 
     // Update to smaller than entry
     result = update_camera_metadata_entry(m,
@@ -1494,6 +1503,8 @@ TEST(camera_metadata, update_metadata) {
     EXPECT_EQ((size_t)1, e.count);
     EXPECT_EQ(newFrameCount, *e.data.i32);
 
+    exposureTimeExpected = 0;
+    exposureTimeFound = 0;
     for (size_t i = 1; i < num_entries; i++) {
         camera_metadata_entry_t e2;
         result = get_camera_metadata_entry(m, i, &e2);
@@ -1501,9 +1512,10 @@ TEST(camera_metadata, update_metadata) {
         EXPECT_EQ(i, e2.index);
         EXPECT_EQ(ANDROID_SENSOR_EXPOSURE_TIME, e2.tag);
         EXPECT_EQ(TYPE_INT64, e2.type);
-        int64_t exposureTime = 100 * i;
-        EXPECT_EQ(exposureTime, *e2.data.i64);
+        exposureTimeExpected += 100 * i;
+        exposureTimeFound += *e2.data.i64;
     }
+    EXPECT_EQ(exposureTimeExpected, exposureTimeFound);
 
     // Setup new buffer with no spare data space
 
@@ -1590,6 +1602,8 @@ TEST(camera_metadata, update_metadata) {
     EXPECT_EQ(newExposures[0], e.data.i64[0]);
     EXPECT_EQ(newExposures[1], e.data.i64[1]);
 
+    exposureTimeExpected = 0;
+    exposureTimeFound = 0;
     for (size_t i = 2; i < num_entries; i++) {
         camera_metadata_entry_t e2;
         result = get_camera_metadata_entry(m2, i, &e2);
@@ -1597,9 +1611,10 @@ TEST(camera_metadata, update_metadata) {
         EXPECT_EQ(i, e2.index);
         EXPECT_EQ(ANDROID_SENSOR_EXPOSURE_TIME, e2.tag);
         EXPECT_EQ(TYPE_INT64, e2.type);
-        int64_t exposureTime = 100 * i;
-        EXPECT_EQ(exposureTime, *e2.data.i64);
+        exposureTimeExpected += 100 * i;
+        exposureTimeFound += *e2.data.i64;
     }
+    EXPECT_EQ(exposureTimeExpected, exposureTimeFound);
 
     // Update when there's no data room, but data size doesn't change
 
@@ -1629,6 +1644,8 @@ TEST(camera_metadata, update_metadata) {
     EXPECT_EQ((size_t)1, e.count);
     EXPECT_EQ(newFrameCount, *e.data.i32);
 
+    exposureTimeExpected = 0;
+    exposureTimeFound = 0;
     for (size_t i = 2; i < num_entries; i++) {
         camera_metadata_entry_t e2;
         result = get_camera_metadata_entry(m2, i, &e2);
@@ -1636,9 +1653,10 @@ TEST(camera_metadata, update_metadata) {
         EXPECT_EQ(i, e2.index);
         EXPECT_EQ(ANDROID_SENSOR_EXPOSURE_TIME, e2.tag);
         EXPECT_EQ(TYPE_INT64, e2.type);
-        int64_t exposureTime = 100 * i;
-        EXPECT_EQ(exposureTime, *e2.data.i64);
+        exposureTimeExpected += 100 * i;
+        exposureTimeFound += *e2.data.i64;
     }
+    EXPECT_EQ(exposureTimeExpected, exposureTimeFound);
 
     // Update when there's no data room, but data size shrinks
 
@@ -1668,6 +1686,8 @@ TEST(camera_metadata, update_metadata) {
     EXPECT_EQ((size_t)1, e.count);
     EXPECT_EQ(newFrameCount, *e.data.i32);
 
+    exposureTimeExpected = 0;
+    exposureTimeFound = 0;
     for (size_t i = 2; i < num_entries; i++) {
         camera_metadata_entry_t e2;
         result = get_camera_metadata_entry(m2, i, &e2);
@@ -1675,9 +1695,10 @@ TEST(camera_metadata, update_metadata) {
         EXPECT_EQ(i, e2.index);
         EXPECT_EQ(ANDROID_SENSOR_EXPOSURE_TIME, e2.tag);
         EXPECT_EQ(TYPE_INT64, e2.type);
-        int64_t exposureTime = 100 * i;
-        EXPECT_EQ(exposureTime, *e2.data.i64);
+        exposureTimeExpected += 100 * i;
+        exposureTimeFound += *e2.data.i64;
     }
+    EXPECT_EQ(exposureTimeExpected, exposureTimeFound);
 
 }
 
```

