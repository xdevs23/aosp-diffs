```diff
diff --git a/Android.bp b/Android.bp
index 985714fb1f..7a257f8196 100644
--- a/Android.bp
+++ b/Android.bp
@@ -100,10 +100,8 @@ cc_defaults {
         "-Wnon-virtual-dtor",
         "-Woverloaded-virtual",
     ],
-    header_libs: [
-        "libwebrtc_absl_headers",
-    ],
     static_libs: [
+        "libabsl",
         "libaom",
         "libevent",
         "libopus",
@@ -1441,150 +1439,6 @@ cc_library_static {
     host_supported: true,
 }
 
-/* From target:
-//third_party/abseil-cpp/absl/base:base
-*/
-cc_library_static {
-    name: "webrtc_base__base",
-    defaults: ["webrtc_defaults"],
-    srcs: [
-        "third_party/abseil-cpp/absl/base/internal/cycleclock.cc",
-        "third_party/abseil-cpp/absl/base/internal/spinlock.cc",
-        "third_party/abseil-cpp/absl/base/internal/sysinfo.cc",
-        "third_party/abseil-cpp/absl/base/internal/thread_identity.cc",
-        "third_party/abseil-cpp/absl/base/internal/unscaledcycleclock.cc",
-    ],
-    host_supported: true,
-    cflags: ["-Wno-unused-variable"],
-    cppflags: [
-        "-Wbitfield-enum-conversion",
-        "-Wbool-conversion",
-        "-Wconstant-conversion",
-        "-Wenum-conversion",
-        "-Wint-conversion",
-        "-Wliteral-conversion",
-        "-Wnon-literal-null-conversion",
-        "-Wnull-conversion",
-        "-Wobjc-literal-conversion",
-        "-Wstring-conversion",
-    ],
-}
-
-/* From target:
-//third_party/abseil-cpp/absl/base:log_severity
-*/
-cc_library_static {
-    name: "webrtc_base__log_severity",
-    defaults: ["webrtc_defaults"],
-    srcs: ["third_party/abseil-cpp/absl/base/log_severity.cc"],
-    host_supported: true,
-    cflags: ["-Wno-unused-variable"],
-    cppflags: [
-        "-Wbitfield-enum-conversion",
-        "-Wbool-conversion",
-        "-Wconstant-conversion",
-        "-Wenum-conversion",
-        "-Wint-conversion",
-        "-Wliteral-conversion",
-        "-Wnon-literal-null-conversion",
-        "-Wnull-conversion",
-        "-Wobjc-literal-conversion",
-        "-Wstring-conversion",
-    ],
-}
-
-/* From target:
-//third_party/abseil-cpp/absl/base:malloc_internal
-*/
-cc_library_static {
-    name: "webrtc_base__malloc_internal",
-    defaults: ["webrtc_defaults"],
-    srcs: ["third_party/abseil-cpp/absl/base/internal/low_level_alloc.cc"],
-    host_supported: true,
-    cflags: ["-Wno-unused-variable"],
-    cppflags: [
-        "-Wbitfield-enum-conversion",
-        "-Wbool-conversion",
-        "-Wconstant-conversion",
-        "-Wenum-conversion",
-        "-Wint-conversion",
-        "-Wliteral-conversion",
-        "-Wnon-literal-null-conversion",
-        "-Wnull-conversion",
-        "-Wobjc-literal-conversion",
-        "-Wstring-conversion",
-    ],
-}
-
-/* From target:
-//third_party/abseil-cpp/absl/base:raw_logging_internal
-*/
-cc_library_static {
-    name: "webrtc_base__raw_logging_internal",
-    defaults: ["webrtc_defaults"],
-    srcs: ["third_party/abseil-cpp/absl/base/internal/raw_logging.cc"],
-    host_supported: true,
-    cflags: ["-Wno-unused-variable"],
-    cppflags: [
-        "-Wbitfield-enum-conversion",
-        "-Wbool-conversion",
-        "-Wconstant-conversion",
-        "-Wenum-conversion",
-        "-Wint-conversion",
-        "-Wliteral-conversion",
-        "-Wnon-literal-null-conversion",
-        "-Wnull-conversion",
-        "-Wobjc-literal-conversion",
-        "-Wstring-conversion",
-    ],
-}
-
-/* From target:
-//third_party/abseil-cpp/absl/base:spinlock_wait
-*/
-cc_library_static {
-    name: "webrtc_base__spinlock_wait",
-    defaults: ["webrtc_defaults"],
-    srcs: ["third_party/abseil-cpp/absl/base/internal/spinlock_wait.cc"],
-    host_supported: true,
-    cflags: ["-Wno-unused-variable"],
-    cppflags: [
-        "-Wbitfield-enum-conversion",
-        "-Wbool-conversion",
-        "-Wconstant-conversion",
-        "-Wenum-conversion",
-        "-Wint-conversion",
-        "-Wliteral-conversion",
-        "-Wnon-literal-null-conversion",
-        "-Wnull-conversion",
-        "-Wobjc-literal-conversion",
-        "-Wstring-conversion",
-    ],
-}
-
-/* From target:
-//third_party/abseil-cpp/absl/base:throw_delegate
-*/
-cc_library_static {
-    name: "webrtc_base__throw_delegate",
-    defaults: ["webrtc_defaults"],
-    srcs: ["third_party/abseil-cpp/absl/base/internal/throw_delegate.cc"],
-    host_supported: true,
-    cflags: ["-Wno-unused-variable"],
-    cppflags: [
-        "-Wbitfield-enum-conversion",
-        "-Wbool-conversion",
-        "-Wconstant-conversion",
-        "-Wenum-conversion",
-        "-Wint-conversion",
-        "-Wliteral-conversion",
-        "-Wnon-literal-null-conversion",
-        "-Wnull-conversion",
-        "-Wobjc-literal-conversion",
-        "-Wstring-conversion",
-    ],
-}
-
 /* From target:
 //call:bitrate_allocator
 */
@@ -1732,62 +1586,6 @@ cc_library_static {
     host_supported: true,
 }
 
-/* From target:
-//third_party/abseil-cpp/absl/time/internal/cctz:civil_time
-*/
-cc_library_static {
-    name: "webrtc_cctz__civil_time",
-    defaults: ["webrtc_defaults"],
-    srcs: ["third_party/abseil-cpp/absl/time/internal/cctz/src/civil_time_detail.cc"],
-    host_supported: true,
-    cflags: ["-Wno-unused-variable"],
-    cppflags: [
-        "-Wbitfield-enum-conversion",
-        "-Wbool-conversion",
-        "-Wconstant-conversion",
-        "-Wenum-conversion",
-        "-Wint-conversion",
-        "-Wliteral-conversion",
-        "-Wnon-literal-null-conversion",
-        "-Wnull-conversion",
-        "-Wobjc-literal-conversion",
-        "-Wstring-conversion",
-    ],
-}
-
-/* From target:
-//third_party/abseil-cpp/absl/time/internal/cctz:time_zone
-*/
-cc_library_static {
-    name: "webrtc_cctz__time_zone",
-    defaults: ["webrtc_defaults"],
-    srcs: [
-        "third_party/abseil-cpp/absl/time/internal/cctz/src/time_zone_fixed.cc",
-        "third_party/abseil-cpp/absl/time/internal/cctz/src/time_zone_format.cc",
-        "third_party/abseil-cpp/absl/time/internal/cctz/src/time_zone_if.cc",
-        "third_party/abseil-cpp/absl/time/internal/cctz/src/time_zone_impl.cc",
-        "third_party/abseil-cpp/absl/time/internal/cctz/src/time_zone_info.cc",
-        "third_party/abseil-cpp/absl/time/internal/cctz/src/time_zone_libc.cc",
-        "third_party/abseil-cpp/absl/time/internal/cctz/src/time_zone_lookup.cc",
-        "third_party/abseil-cpp/absl/time/internal/cctz/src/time_zone_posix.cc",
-        "third_party/abseil-cpp/absl/time/internal/cctz/src/zone_info_source.cc",
-    ],
-    host_supported: true,
-    cflags: ["-Wno-unused-variable"],
-    cppflags: [
-        "-Wbitfield-enum-conversion",
-        "-Wbool-conversion",
-        "-Wconstant-conversion",
-        "-Wenum-conversion",
-        "-Wint-conversion",
-        "-Wliteral-conversion",
-        "-Wnon-literal-null-conversion",
-        "-Wnull-conversion",
-        "-Wobjc-literal-conversion",
-        "-Wstring-conversion",
-    ],
-}
-
 /* From target:
 //common_audio:common_audio
 */
@@ -2114,55 +1912,6 @@ cc_library_static {
     cflags: ["-DBWE_TEST_LOGGING_COMPILE_TIME_ENABLE=0"],
 }
 
-/* From target:
-//third_party/abseil-cpp/absl/container:hashtablez_sampler
-*/
-cc_library_static {
-    name: "webrtc_container__hashtablez_sampler",
-    defaults: ["webrtc_defaults"],
-    srcs: [
-        "third_party/abseil-cpp/absl/container/internal/hashtablez_sampler.cc",
-        "third_party/abseil-cpp/absl/container/internal/hashtablez_sampler_force_weak_definition.cc",
-    ],
-    host_supported: true,
-    cflags: ["-Wno-unused-variable"],
-    cppflags: [
-        "-Wbitfield-enum-conversion",
-        "-Wbool-conversion",
-        "-Wconstant-conversion",
-        "-Wenum-conversion",
-        "-Wint-conversion",
-        "-Wliteral-conversion",
-        "-Wnon-literal-null-conversion",
-        "-Wnull-conversion",
-        "-Wobjc-literal-conversion",
-        "-Wstring-conversion",
-    ],
-}
-
-/* From target:
-//third_party/abseil-cpp/absl/container:raw_hash_set
-*/
-cc_library_static {
-    name: "webrtc_container__raw_hash_set",
-    defaults: ["webrtc_defaults"],
-    srcs: ["third_party/abseil-cpp/absl/container/internal/raw_hash_set.cc"],
-    host_supported: true,
-    cflags: ["-Wno-unused-variable"],
-    cppflags: [
-        "-Wbitfield-enum-conversion",
-        "-Wbool-conversion",
-        "-Wconstant-conversion",
-        "-Wenum-conversion",
-        "-Wint-conversion",
-        "-Wliteral-conversion",
-        "-Wnon-literal-null-conversion",
-        "-Wnull-conversion",
-        "-Wobjc-literal-conversion",
-        "-Wstring-conversion",
-    ],
-}
-
 /* From target:
 //rtc_base/containers:flat_containers_internal
 */
@@ -2336,102 +2085,6 @@ cc_library_static {
     host_supported: true,
 }
 
-/* From target:
-//third_party/abseil-cpp/absl/debugging:debugging_internal
-*/
-cc_library_static {
-    name: "webrtc_debugging__debugging_internal",
-    defaults: ["webrtc_defaults"],
-    srcs: [
-        "third_party/abseil-cpp/absl/debugging/internal/address_is_readable.cc",
-        "third_party/abseil-cpp/absl/debugging/internal/elf_mem_image.cc",
-        "third_party/abseil-cpp/absl/debugging/internal/vdso_support.cc",
-    ],
-    host_supported: true,
-    cflags: ["-Wno-unused-variable"],
-    cppflags: [
-        "-Wbitfield-enum-conversion",
-        "-Wbool-conversion",
-        "-Wconstant-conversion",
-        "-Wenum-conversion",
-        "-Wint-conversion",
-        "-Wliteral-conversion",
-        "-Wnon-literal-null-conversion",
-        "-Wnull-conversion",
-        "-Wobjc-literal-conversion",
-        "-Wstring-conversion",
-    ],
-}
-
-/* From target:
-//third_party/abseil-cpp/absl/debugging:demangle_internal
-*/
-cc_library_static {
-    name: "webrtc_debugging__demangle_internal",
-    defaults: ["webrtc_defaults"],
-    srcs: ["third_party/abseil-cpp/absl/debugging/internal/demangle.cc"],
-    host_supported: true,
-    cflags: ["-Wno-unused-variable"],
-    cppflags: [
-        "-Wbitfield-enum-conversion",
-        "-Wbool-conversion",
-        "-Wconstant-conversion",
-        "-Wenum-conversion",
-        "-Wint-conversion",
-        "-Wliteral-conversion",
-        "-Wnon-literal-null-conversion",
-        "-Wnull-conversion",
-        "-Wobjc-literal-conversion",
-        "-Wstring-conversion",
-    ],
-}
-
-/* From target:
-//third_party/abseil-cpp/absl/debugging:stacktrace
-*/
-cc_library_static {
-    name: "webrtc_debugging__stacktrace",
-    defaults: ["webrtc_defaults"],
-    srcs: ["third_party/abseil-cpp/absl/debugging/stacktrace.cc"],
-    host_supported: true,
-    cflags: ["-Wno-unused-variable"],
-    cppflags: [
-        "-Wbitfield-enum-conversion",
-        "-Wbool-conversion",
-        "-Wconstant-conversion",
-        "-Wenum-conversion",
-        "-Wint-conversion",
-        "-Wliteral-conversion",
-        "-Wnon-literal-null-conversion",
-        "-Wnull-conversion",
-        "-Wobjc-literal-conversion",
-        "-Wstring-conversion",
-    ],
-}
-
-/* From target:
-//third_party/abseil-cpp/absl/debugging:symbolize
-*/
-cc_library_static {
-    name: "webrtc_debugging__symbolize",
-    defaults: ["webrtc_defaults"],
-    srcs: ["third_party/abseil-cpp/absl/debugging/symbolize.cc"],
-    host_supported: true,
-    cflags: ["-Wno-unused-variable"],
-    cppflags: [
-        "-Wbitfield-enum-conversion",
-        "-Wbool-conversion",
-        "-Wconstant-conversion",
-        "-Wenum-conversion",
-        "-Wint-conversion",
-        "-Wliteral-conversion",
-        "-Wnon-literal-null-conversion",
-        "-Wnull-conversion",
-        "-Wobjc-literal-conversion",
-        "-Wstring-conversion",
-    ],
-}
-
 /* From target:
 //rtc_base/experiments:alr_experiment
 */
@@ -2785,75 +2438,6 @@ cc_library_static {
     cflags: ["-DBWE_TEST_LOGGING_COMPILE_TIME_ENABLE=0"],
 }
 
-/* From target:
-//third_party/abseil-cpp/absl/hash:city
-*/
-cc_library_static {
-    name: "webrtc_hash__city",
-    defaults: ["webrtc_defaults"],
-    srcs: ["third_party/abseil-cpp/absl/hash/internal/city.cc"],
-    host_supported: true,
-    cflags: ["-Wno-unused-variable"],
-    cppflags: [
-        "-Wbitfield-enum-conversion",
-        "-Wbool-conversion",
-        "-Wconstant-conversion",
-        "-Wenum-conversion",
-        "-Wint-conversion",
-        "-Wliteral-conversion",
-        "-Wnon-literal-null-conversion",
-        "-Wnull-conversion",
-        "-Wobjc-literal-conversion",
-        "-Wstring-conversion",
-    ],
-}
-
-/* From target:
-//third_party/abseil-cpp/absl/hash:hash
-*/
-cc_library_static {
-    name: "webrtc_hash__hash",
-    defaults: ["webrtc_defaults"],
-    srcs: ["third_party/abseil-cpp/absl/hash/internal/hash.cc"],
-    host_supported: true,
-    cflags: ["-Wno-unused-variable"],
-    cppflags: [
-        "-Wbitfield-enum-conversion",
-        "-Wbool-conversion",
-        "-Wconstant-conversion",
-        "-Wenum-conversion",
-        "-Wint-conversion",
-        "-Wliteral-conversion",
-        "-Wnon-literal-null-conversion",
-        "-Wnull-conversion",
-        "-Wobjc-literal-conversion",
-        "-Wstring-conversion",
-    ],
-}
-
-/* From target:
-//third_party/abseil-cpp/absl/hash:low_level_hash
-*/
-cc_library_static {
-    name: "webrtc_hash__low_level_hash",
-    defaults: ["webrtc_defaults"],
-    srcs: ["third_party/abseil-cpp/absl/hash/internal/low_level_hash.cc"],
-    host_supported: true,
-    cflags: ["-Wno-unused-variable"],
-    cppflags: [
-        "-Wbitfield-enum-conversion",
-        "-Wbool-conversion",
-        "-Wconstant-conversion",
-        "-Wenum-conversion",
-        "-Wint-conversion",
-        "-Wliteral-conversion",
-        "-Wnon-literal-null-conversion",
-        "-Wnull-conversion",
-        "-Wobjc-literal-conversion",
-        "-Wstring-conversion",
-    ],
-}
-
 /* From target:
 //api/audio_codecs/ilbc:audio_decoder_ilbc
 */
@@ -3257,29 +2841,6 @@ cc_library_static {
     host_supported: true,
 }
 
-/* From target:
-//third_party/abseil-cpp/absl/numeric:int128
-*/
-cc_library_static {
-    name: "webrtc_numeric__int128",
-    defaults: ["webrtc_defaults"],
-    srcs: ["third_party/abseil-cpp/absl/numeric/int128.cc"],
-    host_supported: true,
-    cflags: ["-Wno-unused-variable"],
-    cppflags: [
-        "-Wbitfield-enum-conversion",
-        "-Wbool-conversion",
-        "-Wconstant-conversion",
-        "-Wenum-conversion",
-        "-Wint-conversion",
-        "-Wliteral-conversion",
-        "-Wnon-literal-null-conversion",
-        "-Wnull-conversion",
-        "-Wobjc-literal-conversion",
-        "-Wstring-conversion",
-    ],
-}
-
 /* From target:
 //api/numerics:numerics
 */
@@ -4165,29 +3726,6 @@ cc_library_static {
     host_supported: true,
 }
 
-/* From target:
-//third_party/abseil-cpp/absl/profiling:exponential_biased
-*/
-cc_library_static {
-    name: "webrtc_profiling__exponential_biased",
-    defaults: ["webrtc_defaults"],
-    srcs: ["third_party/abseil-cpp/absl/profiling/internal/exponential_biased.cc"],
-    host_supported: true,
-    cflags: ["-Wno-unused-variable"],
-    cppflags: [
-        "-Wbitfield-enum-conversion",
-        "-Wbool-conversion",
-        "-Wconstant-conversion",
-        "-Wenum-conversion",
-        "-Wint-conversion",
-        "-Wliteral-conversion",
-        "-Wnon-literal-null-conversion",
-        "-Wnull-conversion",
-        "-Wobjc-literal-conversion",
-        "-Wstring-conversion",
-    ],
-}
-
 /* From target:
 //net/dcsctp/public:factory
 */
@@ -5143,229 +4681,6 @@ cc_library_static {
     host_supported: true,
 }
 
-/* From target:
-//third_party/abseil-cpp/absl/strings:cord
-*/
-cc_library_static {
-    name: "webrtc_strings__cord",
-    defaults: ["webrtc_defaults"],
-    srcs: [
-        "third_party/abseil-cpp/absl/strings/cord.cc",
-        "third_party/abseil-cpp/absl/strings/cord_analysis.cc",
-        "third_party/abseil-cpp/absl/strings/cord_buffer.cc",
-    ],
-    host_supported: true,
-    cflags: ["-Wno-unused-variable"],
-    cppflags: [
-        "-Wbitfield-enum-conversion",
-        "-Wbool-conversion",
-        "-Wconstant-conversion",
-        "-Wenum-conversion",
-        "-Wint-conversion",
-        "-Wliteral-conversion",
-        "-Wnon-literal-null-conversion",
-        "-Wnull-conversion",
-        "-Wobjc-literal-conversion",
-        "-Wstring-conversion",
-    ],
-}
-
-/* From target:
-//third_party/abseil-cpp/absl/strings:cord_internal
-*/
-cc_library_static {
-    name: "webrtc_strings__cord_internal",
-    defaults: ["webrtc_defaults"],
-    srcs: [
-        "third_party/abseil-cpp/absl/strings/internal/cord_internal.cc",
-        "third_party/abseil-cpp/absl/strings/internal/cord_rep_btree.cc",
-        "third_party/abseil-cpp/absl/strings/internal/cord_rep_btree_navigator.cc",
-        "third_party/abseil-cpp/absl/strings/internal/cord_rep_btree_reader.cc",
-        "third_party/abseil-cpp/absl/strings/internal/cord_rep_consume.cc",
-        "third_party/abseil-cpp/absl/strings/internal/cord_rep_crc.cc",
-        "third_party/abseil-cpp/absl/strings/internal/cord_rep_ring.cc",
-    ],
-    host_supported: true,
-    cflags: ["-Wno-unused-variable"],
-    cppflags: [
-        "-Wbitfield-enum-conversion",
-        "-Wbool-conversion",
-        "-Wconstant-conversion",
-        "-Wenum-conversion",
-        "-Wint-conversion",
-        "-Wliteral-conversion",
-        "-Wnon-literal-null-conversion",
-        "-Wnull-conversion",
-        "-Wobjc-literal-conversion",
-        "-Wstring-conversion",
-    ],
-}
-
-/* From target:
-//third_party/abseil-cpp/absl/strings:cordz_functions
-*/
-cc_library_static {
-    name: "webrtc_strings__cordz_functions",
-    defaults: ["webrtc_defaults"],
-    srcs: ["third_party/abseil-cpp/absl/strings/internal/cordz_functions.cc"],
-    host_supported: true,
-    cflags: ["-Wno-unused-variable"],
-    cppflags: [
-        "-Wbitfield-enum-conversion",
-        "-Wbool-conversion",
-        "-Wconstant-conversion",
-        "-Wenum-conversion",
-        "-Wint-conversion",
-        "-Wliteral-conversion",
-        "-Wnon-literal-null-conversion",
-        "-Wnull-conversion",
-        "-Wobjc-literal-conversion",
-        "-Wstring-conversion",
-    ],
-}
-
-/* From target:
-//third_party/abseil-cpp/absl/strings:cordz_handle
-*/
-cc_library_static {
-    name: "webrtc_strings__cordz_handle",
-    defaults: ["webrtc_defaults"],
-    srcs: ["third_party/abseil-cpp/absl/strings/internal/cordz_handle.cc"],
-    host_supported: true,
-    cflags: ["-Wno-unused-variable"],
-    cppflags: [
-        "-Wbitfield-enum-conversion",
-        "-Wbool-conversion",
-        "-Wconstant-conversion",
-        "-Wenum-conversion",
-        "-Wint-conversion",
-        "-Wliteral-conversion",
-        "-Wnon-literal-null-conversion",
-        "-Wnull-conversion",
-        "-Wobjc-literal-conversion",
-        "-Wstring-conversion",
-    ],
-}
-
-/* From target:
-//third_party/abseil-cpp/absl/strings:cordz_info
-*/
-cc_library_static {
-    name: "webrtc_strings__cordz_info",
-    defaults: ["webrtc_defaults"],
-    srcs: ["third_party/abseil-cpp/absl/strings/internal/cordz_info.cc"],
-    host_supported: true,
-    cflags: ["-Wno-unused-variable"],
-    cppflags: [
-        "-Wbitfield-enum-conversion",
-        "-Wbool-conversion",
-        "-Wconstant-conversion",
-        "-Wenum-conversion",
-        "-Wint-conversion",
-        "-Wliteral-conversion",
-        "-Wnon-literal-null-conversion",
-        "-Wnull-conversion",
-        "-Wobjc-literal-conversion",
-        "-Wstring-conversion",
-    ],
-}
-
-/* From target:
-//third_party/abseil-cpp/absl/strings:internal
-*/
-cc_library_static {
-    name: "webrtc_strings__internal",
-    defaults: ["webrtc_defaults"],
-    srcs: [
-        "third_party/abseil-cpp/absl/strings/internal/escaping.cc",
-        "third_party/abseil-cpp/absl/strings/internal/ostringstream.cc",
-        "third_party/abseil-cpp/absl/strings/internal/utf8.cc",
-    ],
-    host_supported: true,
-    cflags: ["-Wno-unused-variable"],
-    cppflags: [
-        "-Wbitfield-enum-conversion",
-        "-Wbool-conversion",
-        "-Wconstant-conversion",
-        "-Wenum-conversion",
-        "-Wint-conversion",
-        "-Wliteral-conversion",
-        "-Wnon-literal-null-conversion",
-        "-Wnull-conversion",
-        "-Wobjc-literal-conversion",
-        "-Wstring-conversion",
-    ],
-}
-
-/* From target:
-//third_party/abseil-cpp/absl/strings:str_format_internal
-*/
-cc_library_static {
-    name: "webrtc_strings__str_format_internal",
-    defaults: ["webrtc_defaults"],
-    srcs: [
-        "third_party/abseil-cpp/absl/strings/internal/str_format/arg.cc",
-        "third_party/abseil-cpp/absl/strings/internal/str_format/bind.cc",
-        "third_party/abseil-cpp/absl/strings/internal/str_format/extension.cc",
-        "third_party/abseil-cpp/absl/strings/internal/str_format/float_conversion.cc",
-        "third_party/abseil-cpp/absl/strings/internal/str_format/output.cc",
-        "third_party/abseil-cpp/absl/strings/internal/str_format/parser.cc",
-    ],
-    host_supported: true,
-    cflags: ["-Wno-unused-variable"],
-    cppflags: [
-        "-Wbitfield-enum-conversion",
-        "-Wbool-conversion",
-        "-Wconstant-conversion",
-        "-Wenum-conversion",
-        "-Wint-conversion",
-        "-Wliteral-conversion",
-        "-Wnon-literal-null-conversion",
-        "-Wnull-conversion",
-        "-Wobjc-literal-conversion",
-        "-Wstring-conversion",
-    ],
-}
-
-/* From target:
-//third_party/abseil-cpp/absl/strings:strings
-*/
-cc_library_static {
-    name: "webrtc_strings__strings",
-    defaults: ["webrtc_defaults"],
-    srcs: [
-        "third_party/abseil-cpp/absl/strings/ascii.cc",
-        "third_party/abseil-cpp/absl/strings/charconv.cc",
-        "third_party/abseil-cpp/absl/strings/escaping.cc",
-        "third_party/abseil-cpp/absl/strings/internal/charconv_bigint.cc",
-        "third_party/abseil-cpp/absl/strings/internal/charconv_parse.cc",
-        "third_party/abseil-cpp/absl/strings/internal/damerau_levenshtein_distance.cc",
-        "third_party/abseil-cpp/absl/strings/internal/memutil.cc",
-        "third_party/abseil-cpp/absl/strings/internal/stringify_sink.cc",
-        "third_party/abseil-cpp/absl/strings/match.cc",
-        "third_party/abseil-cpp/absl/strings/numbers.cc",
-        "third_party/abseil-cpp/absl/strings/str_cat.cc",
-        "third_party/abseil-cpp/absl/strings/str_replace.cc",
-        "third_party/abseil-cpp/absl/strings/str_split.cc",
-        "third_party/abseil-cpp/absl/strings/string_view.cc",
-        "third_party/abseil-cpp/absl/strings/substitute.cc",
-    ],
-    host_supported: true,
-    cflags: ["-Wno-unused-variable"],
-    cppflags: [
-        "-Wbitfield-enum-conversion",
-        "-Wbool-conversion",
-        "-Wconstant-conversion",
-        "-Wenum-conversion",
-        "-Wint-conversion",
-        "-Wliteral-conversion",
-        "-Wnon-literal-null-conversion",
-        "-Wnull-conversion",
-        "-Wobjc-literal-conversion",
-        "-Wstring-conversion",
-    ],
-}
-
 /* From target:
 //modules/video_coding/svc:scalability_mode_util
 */
@@ -5412,29 +4727,6 @@ cc_library_static {
     host_supported: true,
 }
 
-/* From target:
-//third_party/abseil-cpp/absl/synchronization:graphcycles_internal
-*/
-cc_library_static {
-    name: "webrtc_synchronization__graphcycles_internal",
-    defaults: ["webrtc_defaults"],
-    srcs: ["third_party/abseil-cpp/absl/synchronization/internal/graphcycles.cc"],
-    host_supported: true,
-    cflags: ["-Wno-unused-variable"],
-    cppflags: [
-        "-Wbitfield-enum-conversion",
-        "-Wbool-conversion",
-        "-Wconstant-conversion",
-        "-Wenum-conversion",
-        "-Wint-conversion",
-        "-Wliteral-conversion",
-        "-Wnon-literal-null-conversion",
-        "-Wnull-conversion",
-        "-Wobjc-literal-conversion",
-        "-Wstring-conversion",
-    ],
-}
-
 /* From target:
 //rtc_base/synchronization:sequence_checker_internal
 */
@@ -5445,37 +4737,6 @@ cc_library_static {
     host_supported: true,
 }
 
-/* From target:
-//third_party/abseil-cpp/absl/synchronization:synchronization
-*/
-cc_library_static {
-    name: "webrtc_synchronization__synchronization",
-    defaults: ["webrtc_defaults"],
-    srcs: [
-        "third_party/abseil-cpp/absl/synchronization/barrier.cc",
-        "third_party/abseil-cpp/absl/synchronization/blocking_counter.cc",
-        "third_party/abseil-cpp/absl/synchronization/internal/create_thread_identity.cc",
-        "third_party/abseil-cpp/absl/synchronization/internal/per_thread_sem.cc",
-        "third_party/abseil-cpp/absl/synchronization/internal/waiter.cc",
-        "third_party/abseil-cpp/absl/synchronization/mutex.cc",
-        "third_party/abseil-cpp/absl/synchronization/notification.cc",
-    ],
-    host_supported: true,
-    cflags: ["-Wno-unused-variable"],
-    cppflags: [
-        "-Wbitfield-enum-conversion",
-        "-Wbool-conversion",
-        "-Wconstant-conversion",
-        "-Wenum-conversion",
-        "-Wint-conversion",
-        "-Wliteral-conversion",
-        "-Wnon-literal-null-conversion",
-        "-Wnull-conversion",
-        "-Wobjc-literal-conversion",
-        "-Wstring-conversion",
-    ],
-}
-
 /* From target:
 //rtc_base/synchronization:yield
 */
@@ -5610,35 +4871,6 @@ cc_library_static {
     host_supported: true,
 }
 
-/* From target:
-//third_party/abseil-cpp/absl/time:time
-*/
-cc_library_static {
-    name: "webrtc_time__time",
-    defaults: ["webrtc_defaults"],
-    srcs: [
-        "third_party/abseil-cpp/absl/time/civil_time.cc",
-        "third_party/abseil-cpp/absl/time/clock.cc",
-        "third_party/abseil-cpp/absl/time/duration.cc",
-        "third_party/abseil-cpp/absl/time/format.cc",
-        "third_party/abseil-cpp/absl/time/time.cc",
-    ],
-    host_supported: true,
-    cflags: ["-Wno-unused-variable"],
-    cppflags: [
-        "-Wbitfield-enum-conversion",
-        "-Wbool-conversion",
-        "-Wconstant-conversion",
-        "-Wenum-conversion",
-        "-Wint-conversion",
-        "-Wliteral-conversion",
-        "-Wnon-literal-null-conversion",
-        "-Wnull-conversion",
-        "-Wobjc-literal-conversion",
-        "-Wstring-conversion",
-    ],
-}
-
 /* From target:
 //net/dcsctp/timer:task_queue_timeout
 */
@@ -5865,52 +5097,6 @@ cc_library_static {
     host_supported: true,
 }
 
-/* From target:
-//third_party/abseil-cpp/absl/types:bad_optional_access
-*/
-cc_library_static {
-    name: "webrtc_types__bad_optional_access",
-    defaults: ["webrtc_defaults"],
-    srcs: ["third_party/abseil-cpp/absl/types/bad_optional_access.cc"],
-    host_supported: true,
-    cflags: ["-Wno-unused-variable"],
-    cppflags: [
-        "-Wbitfield-enum-conversion",
-        "-Wbool-conversion",
-        "-Wconstant-conversion",
-        "-Wenum-conversion",
-        "-Wint-conversion",
-        "-Wliteral-conversion",
-        "-Wnon-literal-null-conversion",
-        "-Wnull-conversion",
-        "-Wobjc-literal-conversion",
-        "-Wstring-conversion",
-    ],
-}
-
-/* From target:
-//third_party/abseil-cpp/absl/types:bad_variant_access
-*/
-cc_library_static {
-    name: "webrtc_types__bad_variant_access",
-    defaults: ["webrtc_defaults"],
-    srcs: ["third_party/abseil-cpp/absl/types/bad_variant_access.cc"],
-    host_supported: true,
-    cflags: ["-Wno-unused-variable"],
-    cppflags: [
-        "-Wbitfield-enum-conversion",
-        "-Wbool-conversion",
-        "-Wconstant-conversion",
-        "-Wenum-conversion",
-        "-Wint-conversion",
-        "-Wliteral-conversion",
-        "-Wnon-literal-null-conversion",
-        "-Wnull-conversion",
-        "-Wobjc-literal-conversion",
-        "-Wstring-conversion",
-    ],
-}
-
 /* From target:
 //api/units:data_rate
 */
@@ -6720,12 +5906,6 @@ cc_library_static {
         "webrtc_audio_processing__rms_level",
         "webrtc_av1__av1_svc_config",
         "webrtc_base64__base64",
-        "webrtc_base__base",
-        "webrtc_base__log_severity",
-        "webrtc_base__malloc_internal",
-        "webrtc_base__raw_logging_internal",
-        "webrtc_base__spinlock_wait",
-        "webrtc_base__throw_delegate",
         "webrtc_call__bitrate_allocator",
         "webrtc_call__bitrate_configurator",
         "webrtc_call__call",
@@ -6738,8 +5918,6 @@ cc_library_static {
         "webrtc_call__version",
         "webrtc_call__video_stream_api",
         "webrtc_capture_levels_adjuster__capture_levels_adjuster",
-        "webrtc_cctz__civil_time",
-        "webrtc_cctz__time_zone",
         "webrtc_common_audio__common_audio",
         "webrtc_common_audio__common_audio_c",
         "webrtc_common_audio__common_audio_cc",
@@ -6748,17 +5926,11 @@ cc_library_static {
         "webrtc_config__encoder_config",
         "webrtc_config__streams_config",
         "webrtc_congestion_controller__congestion_controller",
-        "webrtc_container__hashtablez_sampler",
-        "webrtc_container__raw_hash_set",
         "webrtc_containers__flat_containers_internal",
         "webrtc_crc32c__crc32c",
         "webrtc_crc32c__crc32c_arm64",
         "webrtc_crc32c__crc32c_sse42",
         "webrtc_crypto__options",
-        "webrtc_debugging__debugging_internal",
-        "webrtc_debugging__demangle_internal",
-        "webrtc_debugging__stacktrace",
-        "webrtc_debugging__symbolize",
         "webrtc_experiments__alr_experiment",
         "webrtc_experiments__balanced_degradation_settings",
         "webrtc_experiments__bandwidth_quality_scaler_settings",
@@ -6792,9 +5964,6 @@ cc_library_static {
         "webrtc_goog_cc__probe_controller",
         "webrtc_goog_cc__pushback_controller",
         "webrtc_goog_cc__send_side_bwe",
-        "webrtc_hash__city",
-        "webrtc_hash__hash",
-        "webrtc_hash__low_level_hash",
         "webrtc_ilbc__audio_decoder_ilbc",
         "webrtc_ilbc__audio_encoder_ilbc",
         "webrtc_logging__ice_log",
@@ -6827,7 +5996,6 @@ cc_library_static {
         "webrtc_neteq__tick_timer",
         "webrtc_network__sent_packet",
         "webrtc_ns__ns",
-        "webrtc_numeric__int128",
         "webrtc_numerics__numerics",
         "webrtc_ooura__fft_size_128",
         "webrtc_ooura__fft_size_256",
@@ -6906,7 +6074,6 @@ cc_library_static {
         "webrtc_pc__video_track_source_proxy",
         "webrtc_pc__webrtc_sdp",
         "webrtc_pc__webrtc_session_description_factory",
-        "webrtc_profiling__exponential_biased",
         "webrtc_public__factory",
         "webrtc_public__socket",
         "webrtc_public__utils",
@@ -6979,21 +6146,11 @@ cc_library_static {
         "webrtc_socket__transmission_control_block",
         "webrtc_spl_sqrt_floor__spl_sqrt_floor",
         "webrtc_stats__rtc_stats",
-        "webrtc_strings__cord",
-        "webrtc_strings__cord_internal",
-        "webrtc_strings__cordz_functions",
-        "webrtc_strings__cordz_handle",
-        "webrtc_strings__cordz_info",
-        "webrtc_strings__internal",
-        "webrtc_strings__str_format_internal",
-        "webrtc_strings__strings",
         "webrtc_svc__scalability_mode_util",
         "webrtc_svc__scalability_structures",
         "webrtc_svc__scalable_video_controller",
         "webrtc_svc__svc_rate_allocator",
-        "webrtc_synchronization__graphcycles_internal",
         "webrtc_synchronization__sequence_checker_internal",
-        "webrtc_synchronization__synchronization",
         "webrtc_synchronization__yield",
         "webrtc_synchronization__yield_policy",
         "webrtc_system__file_wrapper",
@@ -7006,7 +6163,6 @@ cc_library_static {
         "webrtc_task_queue__task_queue",
         "webrtc_task_utils__repeating_task",
         "webrtc_test__fake_video_codecs",
-        "webrtc_time__time",
         "webrtc_timer__task_queue_timeout",
         "webrtc_timer__timer",
         "webrtc_timing__codec_timer",
@@ -7029,8 +6185,6 @@ cc_library_static {
         "webrtc_tx__retransmission_timeout",
         "webrtc_tx__rr_send_queue",
         "webrtc_tx__stream_scheduler",
-        "webrtc_types__bad_optional_access",
-        "webrtc_types__bad_variant_access",
         "webrtc_units__data_rate",
         "webrtc_units__data_size",
         "webrtc_units__frequency",
@@ -7180,11 +6334,6 @@ cc_library_static {
         "webrtc_audio_processing__high_pass_filter",
         "webrtc_audio_processing__optionally_built_submodule_creators",
         "webrtc_audio_processing__rms_level",
-        "webrtc_base__base",
-        "webrtc_base__log_severity",
-        "webrtc_base__raw_logging_internal",
-        "webrtc_base__spinlock_wait",
-        "webrtc_base__throw_delegate",
         "webrtc_capture_levels_adjuster__capture_levels_adjuster",
         "webrtc_common_audio__common_audio",
         "webrtc_common_audio__common_audio_c",
@@ -7195,7 +6344,6 @@ cc_library_static {
         "webrtc_fft__fft",
         "webrtc_memory__aligned_malloc",
         "webrtc_ns__ns",
-        "webrtc_numeric__int128",
         "webrtc_ooura__fft_size_128",
         "webrtc_ooura__fft_size_256",
         "webrtc_rnn_vad__rnn_vad",
@@ -7216,8 +6364,6 @@ cc_library_static {
         "webrtc_rtc_base__stringutils",
         "webrtc_rtc_base__timeutils",
         "webrtc_spl_sqrt_floor__spl_sqrt_floor",
-        "webrtc_strings__internal",
-        "webrtc_strings__strings",
         "webrtc_synchronization__sequence_checker_internal",
         "webrtc_synchronization__yield",
         "webrtc_synchronization__yield_policy",
@@ -7229,7 +6375,6 @@ cc_library_static {
         "webrtc_task_queue__task_queue",
         "webrtc_transient__transient_suppressor_impl",
         "webrtc_transient__voice_probability_delay_unit",
-        "webrtc_types__bad_optional_access",
         "webrtc_units__data_rate",
         "webrtc_units__data_size",
         "webrtc_units__frequency",
diff --git a/android_tools/generate_bp.py b/android_tools/generate_bp.py
index e61f922307..c6b70034ec 100755
--- a/android_tools/generate_bp.py
+++ b/android_tools/generate_bp.py
@@ -204,10 +204,8 @@ def GenerateDefault(targets_by_arch):
             for flag in flags:
                 print('        "{0}",'.format(flag.replace('"', '\\"')))
             print('    ],')
-    print('    header_libs: [')
-    print('      "libwebrtc_absl_headers",')
-    print('    ],')
     print('    static_libs: [')
+    print('        "libabsl",')
     print('        "libaom",')
     print('        "libevent",')
     print('        "libopus",')
@@ -400,11 +398,17 @@ def Preprocess(project):
         # Skip all "action" targets
         if target['type'] in {'action', 'action_foreach'}:
             ignored_targets.add(name)
-    targets = {name: target for name, target in targets.items() if name not in ignored_targets}
+
+    def is_ignored(target):
+        if target.startswith('//third_party/abseil-cpp'):
+            return True
+        return target in ignored_targets
+
+    targets = {name: target for name, target in targets.items() if not is_ignored(name)}
 
     for target in targets.values():
         # Don't depend on ignored targets
-        target['deps'] = [d for d in target['deps'] if d not in ignored_targets]
+        target['deps'] = [d for d in target['deps'] if not is_ignored(d) ]
 
     # Ignore empty static libraries
     empty_libs = set()
```

