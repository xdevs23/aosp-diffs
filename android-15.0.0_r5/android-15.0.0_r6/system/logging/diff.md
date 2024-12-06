```diff
diff --git a/liblog/Android.bp b/liblog/Android.bp
index f253edae..49a26f8c 100644
--- a/liblog/Android.bp
+++ b/liblog/Android.bp
@@ -86,6 +86,7 @@ cc_library_headers {
 // ========================================================
 cc_defaults {
     name: "liblog.defaults",
+    defaults: ["bug_24465209_workaround"],
     host_supported: true,
     ramdisk_available: true,
     vendor_ramdisk_available: true,
@@ -102,11 +103,6 @@ cc_defaults {
                 address: false,
             },
         },
-        android_arm: {
-            // TODO: This is to work around b/24465209. Remove after root cause is fixed
-            pack_relocations: false,
-            ldflags: ["-Wl,--hash-style=both"],
-        },
         windows: {
             enabled: true,
         },
@@ -207,9 +203,6 @@ ndk_library {
     symbol_file: "liblog.map.txt",
     first_version: "9",
     unversioned_until: "current",
-    export_header_libs: [
-        "liblog_ndk_headers",
-    ],
 }
 
 rust_bindgen {
diff --git a/liblog/logprint.cpp b/liblog/logprint.cpp
index aece1fa0..d5c8fd08 100644
--- a/liblog/logprint.cpp
+++ b/liblog/logprint.cpp
@@ -877,9 +877,9 @@ static int android_log_printBinaryEvent(const unsigned char** pEventData, size_t
           }
           break;
         case TYPE_MONOTONIC: {
-          static const uint64_t minute = 60;
-          static const uint64_t hour = 60 * minute;
-          static const uint64_t day = 24 * hour;
+          static constexpr uint64_t minute = 60;
+          static constexpr uint64_t hour = 60 * minute;
+          static constexpr uint64_t day = 24 * hour;
 
           /* Repaint as unsigned seconds, minutes, hours ... */
           outBuf -= outCount;
diff --git a/liblog/properties.cpp b/liblog/properties.cpp
index 657901a3..8a8b4439 100644
--- a/liblog/properties.cpp
+++ b/liblog/properties.cpp
@@ -31,8 +31,7 @@
 #include "logger_write.h"
 
 #ifdef __ANDROID__
-#define _REALLY_INCLUDE_SYS__SYSTEM_PROPERTIES_H_
-#include <sys/_system_properties.h>
+#include <sys/system_properties.h>
 
 static pthread_mutex_t lock_loggable = PTHREAD_MUTEX_INITIALIZER;
 
diff --git a/liblog/tests/device_test_config.xml b/liblog/tests/device_test_config.xml
index 9d0912f5..302c6161 100644
--- a/liblog/tests/device_test_config.xml
+++ b/liblog/tests/device_test_config.xml
@@ -19,6 +19,7 @@
     <option name="config-descriptor:metadata" key="parameter" value="not_instant_app" />
     <option name="config-descriptor:metadata" key="parameter" value="multi_abi" />
     <option name="config-descriptor:metadata" key="parameter" value="secondary_user" />
+    <option name="config-descriptor:metadata" key="parameter" value="secondary_user_on_secondary_display" />
     <target_preparer class="com.android.compatibility.common.tradefed.targetprep.FilePusher">
         <option name="cleanup" value="true" />
         <option name="push" value="CtsLiblogTestCases->/data/local/tests/unrestricted/CtsLiblogTestCases" />
diff --git a/liblog/tests/liblog_benchmark.cpp b/liblog/tests/liblog_benchmark.cpp
index 6dc5da61..008b3067 100644
--- a/liblog/tests/liblog_benchmark.cpp
+++ b/liblog/tests/liblog_benchmark.cpp
@@ -845,7 +845,7 @@ static uint32_t notTag = 1;
 static void BM_lookupEventTag_NOT(benchmark::State& state) {
   prechargeEventMap();
 
-  while (set.find(notTag) != set.end()) {
+  while (set.contains(notTag)) {
     ++notTag;
     if (notTag >= USHRT_MAX) notTag = 1;
   }
diff --git a/liblog/tests/liblog_test.cpp b/liblog/tests/liblog_test.cpp
index cde5a5bb..fb05c12e 100644
--- a/liblog/tests/liblog_test.cpp
+++ b/liblog/tests/liblog_test.cpp
@@ -86,7 +86,7 @@ static void RunLogTests(log_id_t log_buffer, FWrite write_messages, FCheck check
   pid_t pid = getpid();
 
   auto logger_list = std::unique_ptr<struct logger_list, ListCloser>{
-      android_logger_list_open(log_buffer, 0, 1000, pid)};
+      android_logger_list_open(log_buffer, 0, INT_MAX, pid)};
   ASSERT_TRUE(logger_list);
 
   write_messages();
@@ -107,7 +107,7 @@ static void RunLogTests(log_id_t log_buffer, FWrite write_messages, FCheck check
   }
 
   auto logger_list_non_block = std::unique_ptr<struct logger_list, ListCloser>{
-      android_logger_list_open(log_buffer, ANDROID_LOG_NONBLOCK, 1000, pid)};
+      android_logger_list_open(log_buffer, ANDROID_LOG_NONBLOCK, INT_MAX, pid)};
   ASSERT_TRUE(logger_list_non_block);
 
   size_t count = 0;
@@ -567,7 +567,7 @@ TEST(liblog, android_logger_list_read__cpu_signal) {
 
   v += pid & 0xFFFF;
 
-  ASSERT_TRUE(NULL != (logger_list = android_logger_list_open(LOG_ID_EVENTS, 0, 1000, pid)));
+  ASSERT_TRUE(NULL != (logger_list = android_logger_list_open(LOG_ID_EVENTS, 0, INT_MAX, pid)));
 
   int count = 0;
 
@@ -720,7 +720,7 @@ TEST(liblog, android_logger_list_read__cpu_thread) {
 
   v += pid & 0xFFFF;
 
-  ASSERT_TRUE(NULL != (logger_list = android_logger_list_open(LOG_ID_EVENTS, 0, 1000, pid)));
+  ASSERT_TRUE(NULL != (logger_list = android_logger_list_open(LOG_ID_EVENTS, 0, INT_MAX, pid)));
 
   int count = 0;
 
@@ -1530,7 +1530,7 @@ static int count_matching_ts(log_time ts) {
   pid_t pid = getpid();
 
   struct logger_list* logger_list =
-      android_logger_list_open(LOG_ID_EVENTS, ANDROID_LOG_NONBLOCK, 1000, pid);
+      android_logger_list_open(LOG_ID_EVENTS, ANDROID_LOG_NONBLOCK, INT_MAX, pid);
 
   int count = 0;
   if (logger_list == NULL) return count;
@@ -1769,7 +1769,7 @@ TEST(liblog, __security_buffer) {
   pid_t pid = getpid();
 
   ASSERT_TRUE(NULL != (logger_list = android_logger_list_open(LOG_ID_SECURITY, ANDROID_LOG_NONBLOCK,
-                                                              1000, pid)));
+                                                              INT_MAX, pid)));
 
   log_time ts(CLOCK_MONOTONIC);
 
diff --git a/liblog/tests/log_wrap_test.cpp b/liblog/tests/log_wrap_test.cpp
index a0f717b7..395b1afc 100644
--- a/liblog/tests/log_wrap_test.cpp
+++ b/liblog/tests/log_wrap_test.cpp
@@ -35,7 +35,7 @@ static void read_with_wrap() {
   // Read the last line in the log to get a starting timestamp. We're assuming
   // the log is not empty.
   const int mode = ANDROID_LOG_NONBLOCK;
-  struct logger_list* logger_list = android_logger_list_open(LOG_ID_SYSTEM, mode, 1000, 0);
+  struct logger_list* logger_list = android_logger_list_open(LOG_ID_SYSTEM, mode, INT_MAX, 0);
 
   ASSERT_NE(logger_list, nullptr);
 
diff --git a/logcat/process_names.cpp b/logcat/process_names.cpp
index 8971809c..71ccc21f 100644
--- a/logcat/process_names.cpp
+++ b/logcat/process_names.cpp
@@ -73,6 +73,11 @@ std::string ProcessNames::Get(uint64_t pid) {
 
     // Cache miss!
     std::string name = Resolve(pid);
-    cache.put(pid, name);
+    // When an app starts, after it forks from zygote process, the process name remains
+    // zygote/zygote64, then <pre-initialized>, then the package/process name is set.
+    // We don't cache until we know the final value.
+    if (name != "<pre-initialized>" && !name.starts_with("zygote")) {
+        cache.put(pid, name);
+    }
     return name;
 }
diff --git a/logd/LogSize.cpp b/logd/LogSize.cpp
index 94c5fe65..1a9ffa84 100644
--- a/logd/LogSize.cpp
+++ b/logd/LogSize.cpp
@@ -65,8 +65,8 @@ static std::optional<size_t> GetBufferSizePropertyOverride(log_id_t log_id) {
 /* This method should only be used for debuggable devices. */
 static bool isAllowedToOverrideBufferSize() {
     const auto hwType = android::base::GetProperty("ro.hardware.type", "");
-    /* We allow automotive devices to optionally override the default. */
-    return (hwType == "automotive");
+    /* Allow automotive and desktop devices to optionally override the default. */
+    return (hwType == "automotive" || hwType == "desktop");
 }
 
 size_t GetBufferSizeFromProperties(log_id_t log_id) {
diff --git a/logd/LogTags.cpp b/logd/LogTags.cpp
index 5c8aa6b2..6fd57b8a 100644
--- a/logd/LogTags.cpp
+++ b/logd/LogTags.cpp
@@ -151,11 +151,11 @@ void LogTags::AddEventLogTags(uint32_t tag, uid_t uid, const std::string& Name,
         // unlikely except for dupes, or updates to uid list (more later)
         if (itot != tag2total.end()) update = false;
 
-        newOne = tag2name.find(tag) == tag2name.end();
+        newOne = !tag2name.contains(tag);
         key2tag[Key] = tag;
 
         if (Format.length()) {
-            if (key2tag.find(Name) == key2tag.end()) {
+            if (!key2tag.contains(Name)) {
                 key2tag[Name] = tag;
             }
             tag2format[tag] = Format;
@@ -167,7 +167,7 @@ void LogTags::AddEventLogTags(uint32_t tag, uid_t uid, const std::string& Name,
             if (uid == AID_ROOT) {
                 tag2uid.erase(ut);
                 update = true;
-            } else if (ut->second.find(uid) == ut->second.end()) {
+            } else if (!ut->second.contains(uid)) {
                 const_cast<uid_list&>(ut->second).emplace(uid);
                 update = true;
             }
@@ -693,7 +693,7 @@ uint32_t LogTags::nameToTag(uid_t uid, const char* name, const char* format) {
         if (updateUid && (Tag != emptyTag) && !unique) {
             tag2uid_const_iterator ut = tag2uid.find(Tag);
             if ((ut != tag2uid.end()) &&
-                (ut->second.find(uid) == ut->second.end())) {
+                (!ut->second.contains(uid))) {
                 unique = write;  // write passthrough to update uid counts
                 if (!write) Tag = emptyTag;  // deny read access
             }
@@ -713,7 +713,7 @@ uint32_t LogTags::nameToTag(uid_t uid, const char* name, const char* format) {
         android::RWLock::AutoWLock writeLock(rwlock);
 
         // double check after switch from read lock to write lock for Tag
-        updateTag = tag2name.find(Tag) == tag2name.end();
+        updateTag = !tag2name.contains(Tag);
         // unlikely, either update, race inviting conflict or multiple uids
         if (!updateTag) {
             Tag = nameToTag_locked(Name, format, unique);
@@ -723,8 +723,7 @@ uint32_t LogTags::nameToTag(uid_t uid, const char* name, const char* format) {
                 tag2uid_const_iterator ut = tag2uid.find(Tag);
                 if (updateUid) {
                     // Add it to the uid list
-                    if ((ut == tag2uid.end()) ||
-                        (ut->second.find(uid) != ut->second.end())) {
+                    if (ut == tag2uid.end() || ut->second.contains(uid)) {
                         return Tag;
                     }
                     const_cast<uid_list&>(ut->second).emplace(uid);
@@ -768,7 +767,7 @@ uint32_t LogTags::nameToTag(uid_t uid, const char* name, const char* format) {
 
             if (*format) {
                 key2tag[Name + "+" + format] = Tag;
-                if (key2tag.find(Name) == key2tag.end()) key2tag[Name] = Tag;
+                if (!key2tag.contains(Name)) key2tag[Name] = Tag;
             } else {
                 key2tag[Name] = Tag;
             }
@@ -818,7 +817,7 @@ std::string LogTags::formatEntry_locked(uint32_t tag, uid_t uid,
         return formatEntry(tag, AID_ROOT, name, format);
     }
     if (uid != AID_ROOT) {
-        if (authenticate && (ut->second.find(uid) == ut->second.end())) {
+        if (authenticate && !ut->second.contains(uid)) {
             return std::string("");
         }
         return formatEntry(tag, uid, name, format);
diff --git a/logd/SimpleLogBuffer.cpp b/logd/SimpleLogBuffer.cpp
index 6fbe113a..f492a406 100644
--- a/logd/SimpleLogBuffer.cpp
+++ b/logd/SimpleLogBuffer.cpp
@@ -43,14 +43,14 @@ void SimpleLogBuffer::Init() {
 }
 
 std::list<LogBufferElement>::iterator SimpleLogBuffer::GetOldest(log_id_t log_id) {
-    auto it = logs().begin();
+    auto it = logs_.begin();
     if (oldest_[log_id]) {
         it = *oldest_[log_id];
     }
-    while (it != logs().end() && it->log_id() != log_id) {
+    while (it != logs_.end() && it->log_id() != log_id) {
         it++;
     }
-    if (it != logs().end()) {
+    if (it != logs_.end()) {
         oldest_[log_id] = it;
     }
     return it;
@@ -290,7 +290,7 @@ std::list<LogBufferElement>::iterator SimpleLogBuffer::Erase(
 
     log_id_for_each(i) {
         if (oldest_is_it[i]) {
-            if (__predict_false(it == logs().end())) {
+            if (__predict_false(it == logs_.end())) {
                 oldest_[i] = std::nullopt;
             } else {
                 oldest_[i] = it;  // Store the next iterator even if it does not correspond to
diff --git a/logd/SimpleLogBuffer.h b/logd/SimpleLogBuffer.h
index 51779aba..369aff3e 100644
--- a/logd/SimpleLogBuffer.h
+++ b/logd/SimpleLogBuffer.h
@@ -63,7 +63,6 @@ class SimpleLogBuffer : public LogBuffer {
     LogStatistics* stats() { return stats_; }
     LogReaderList* reader_list() { return reader_list_; }
     size_t max_size(log_id_t id) REQUIRES_SHARED(logd_lock) { return max_size_[id]; }
-    std::list<LogBufferElement>& logs() { return logs_; }
 
   private:
     bool ShouldLog(log_id_t log_id, const char* msg, uint16_t len);
diff --git a/logd/device_test_config.xml b/logd/device_test_config.xml
index cc7932b0..cd842bf2 100644
--- a/logd/device_test_config.xml
+++ b/logd/device_test_config.xml
@@ -19,6 +19,7 @@
     <option name="config-descriptor:metadata" key="parameter" value="not_instant_app" />
     <option name="config-descriptor:metadata" key="parameter" value="multi_abi" />
     <option name="config-descriptor:metadata" key="parameter" value="secondary_user" />
+    <option name="config-descriptor:metadata" key="parameter" value="secondary_user_on_secondary_display" />
     <target_preparer class="com.android.compatibility.common.tradefed.targetprep.FilePusher">
         <option name="cleanup" value="true" />
         <option name="push" value="CtsLogdTestCases->/data/local/tests/unrestricted/CtsLogdTestCases" />
```

