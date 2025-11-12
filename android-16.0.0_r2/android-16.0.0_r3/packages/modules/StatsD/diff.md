```diff
diff --git a/OWNERS b/OWNERS
index 09ff1560..ac4030b1 100644
--- a/OWNERS
+++ b/OWNERS
@@ -2,7 +2,6 @@
 jeffreyhuang@google.com
 monicamwang@google.com
 muhammadq@google.com
-rayhdez@google.com
 sharaienko@google.com
 singhtejinder@google.com
 tsaichristine@google.com
diff --git a/apex/Android.bp b/apex/Android.bp
index 0bad0aca..d017353c 100644
--- a/apex/Android.bp
+++ b/apex/Android.bp
@@ -20,6 +20,10 @@ apex {
     name: "com.android.os.statsd",
     defaults: ["com.android.os.statsd-defaults"],
     manifest: "apex_manifest.json",
+    licenses: [
+        "Android-Apache-2.0",
+        "opensourcerequest",
+    ],
 }
 
 apex_defaults {
diff --git a/flags/statsd_flags.aconfig b/flags/statsd_flags.aconfig
index 46915e19..dc9abb81 100644
--- a/flags/statsd_flags.aconfig
+++ b/flags/statsd_flags.aconfig
@@ -20,7 +20,7 @@ flag {
 }
 
 flag {
-    name: "enable_iouring"
+    name: "use_iouring"
     namespace: "statsd"
     description: "Enables iouring implementation of the statsd"
     bug: "380509817"
@@ -34,3 +34,11 @@ flag {
     bug: "382574781"
     is_fixed_read_only: true
 }
+
+flag {
+  name: "keep_value_metric_max_dimension_bucket"
+  namespace: "statsd"
+  description: "Whether to keep the bucket in ValueMetric when dimension guardrail is hit."
+  bug: "408060408"
+}
+
diff --git a/lib/libstatssocket/Android.bp b/lib/libstatssocket/Android.bp
index cc38035f..b27a6cae 100644
--- a/lib/libstatssocket/Android.bp
+++ b/lib/libstatssocket/Android.bp
@@ -27,10 +27,10 @@ cc_defaults {
     srcs: [
         "stats_buffer_writer.cpp",
         "stats_buffer_writer_queue.cpp",
-        "stats_event.c",
-        "stats_socket.c",
-        "statsd_writer.cpp",
+        "stats_event.cpp",
+        "stats_socket.cpp",
         "stats_socket_loss_reporter.cpp",
+        "statsd_writer.cpp",
         "utils.cpp",
     ],
     local_include_dirs: [
@@ -202,5 +202,9 @@ cc_fuzz {
             "singhtejinder@google.com",
             "sharaienko@google.com",
         ],
+        vector: "local_no_privileges_required",
+        service_privilege: "privileged",
+        users: "multi_user",
+        fuzzed_code_usage: "shipped",
     },
 }
diff --git a/lib/libstatssocket/stats_event.c b/lib/libstatssocket/stats_event.cpp
similarity index 99%
rename from lib/libstatssocket/stats_event.c
rename to lib/libstatssocket/stats_event.cpp
index 1c8aaf2d..3f189559 100644
--- a/lib/libstatssocket/stats_event.c
+++ b/lib/libstatssocket/stats_event.cpp
@@ -19,7 +19,7 @@
 #include <stdlib.h>
 #include <string.h>
 
-#include "stats_buffer_writer.h"
+#include "include/stats_buffer_writer.h"
 #include "utils.h"
 
 #define LOGGER_ENTRY_MAX_PAYLOAD 4068
@@ -84,7 +84,7 @@ struct AStatsEvent {
 };
 
 AStatsEvent* AStatsEvent_obtain() {
-    AStatsEvent* event = malloc(sizeof(AStatsEvent));
+    AStatsEvent* event = static_cast<AStatsEvent*>(malloc(sizeof(AStatsEvent)));
     event->lastFieldPos = 0;
     event->numBytesWritten = 2;  // reserve first 2 bytes for root event type and number of elements
     event->numElements = 0;
diff --git a/lib/libstatssocket/stats_socket.c b/lib/libstatssocket/stats_socket.cpp
similarity index 94%
rename from lib/libstatssocket/stats_socket.c
rename to lib/libstatssocket/stats_socket.cpp
index 09f8967b..6739443f 100644
--- a/lib/libstatssocket/stats_socket.c
+++ b/lib/libstatssocket/stats_socket.cpp
@@ -15,7 +15,8 @@
  */
 
 #include "include/stats_socket.h"
-#include "stats_buffer_writer.h"
+
+#include "include/stats_buffer_writer.h"
 
 void AStatsSocket_close() {
     stats_log_close();
diff --git a/lib/libstatssocket/utils.h b/lib/libstatssocket/utils.h
index 1eada991..def2c1ae 100644
--- a/lib/libstatssocket/utils.h
+++ b/lib/libstatssocket/utils.h
@@ -16,14 +16,8 @@
 
 #pragma once
 
-#include <stddef.h>
 #include <stdint.h>
-#include <sys/cdefs.h>
-
-__BEGIN_DECLS
 
 int64_t get_elapsed_realtime_ns();
 
 int toSocketLossError(int errno_code);
-
-__END_DECLS
diff --git a/statsd/Android.bp b/statsd/Android.bp
index d027759e..bb35bf16 100644
--- a/statsd/Android.bp
+++ b/statsd/Android.bp
@@ -113,6 +113,7 @@ cc_defaults {
         "src/shell/ShellSubscriberClient.cpp",
         "src/socket/BaseStatsSocketListener.cpp",
         "src/socket/StatsSocketListener.cpp",
+        "src/socket/StatsSocketListenerIoUring.cpp",
         "src/state/StateManager.cpp",
         "src/state/StateTracker.cpp",
         "src/stats_log_util.cpp",
@@ -148,6 +149,8 @@ cc_defaults {
         "libstatslog_statsd",
         "libsysutils",
         "libutils",
+        "liburing",
+        "liburingutils",
         "server_configurable_flags",
         "statsd-aidl-ndk",
         "statsd_flags_c_lib",
diff --git a/statsd/fuzzers/statsd_socket_data_fuzzer.cpp b/statsd/fuzzers/statsd_socket_data_fuzzer.cpp
index d65b010f..96ad2113 100644
--- a/statsd/fuzzers/statsd_socket_data_fuzzer.cpp
+++ b/statsd/fuzzers/statsd_socket_data_fuzzer.cpp
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-#include "socket/BaseStatsSocketListener.h"
+#include "socket/StatsSocketListener.h"
 
 namespace android {
 namespace os {
@@ -25,7 +25,7 @@ void fuzzSocket(const uint8_t* data, size_t size) {
     std::shared_ptr<LogEventFilter> filter(new LogEventFilter());
     filter->setFilteringEnabled(false);
 
-    BaseStatsSocketListener statsSocketListener(queue, filter);
+    StatsSocketListener statsSocketListener(queue, filter);
 
     statsSocketListener.processSocketMessage((void*) data, size, 0, 0);
     statsSocketListener.processStatsEventBuffer(data, size, 0, 0, *queue, *filter);
diff --git a/statsd/src/FieldValue.cpp b/statsd/src/FieldValue.cpp
index 92ed96d3..a4877a03 100644
--- a/statsd/src/FieldValue.cpp
+++ b/statsd/src/FieldValue.cpp
@@ -23,6 +23,9 @@
 #include "hash.h"
 #include "math.h"
 
+using std::string;
+using std::vector;
+
 namespace android {
 namespace os {
 namespace statsd {
@@ -60,8 +63,8 @@ bool Field::matches(const Matcher& matcher) const {
     return false;
 }
 
-std::vector<Matcher> dedupFieldMatchers(const std::vector<Matcher>& fieldMatchers) {
-    std::vector<Matcher> dedupedFieldMatchers;
+vector<Matcher> dedupFieldMatchers(const vector<Matcher>& fieldMatchers) {
+    vector<Matcher> dedupedFieldMatchers;
     for (size_t i = 0; i < fieldMatchers.size(); i++) {
         if (std::find(dedupedFieldMatchers.begin(), dedupedFieldMatchers.end(), fieldMatchers[i]) ==
             dedupedFieldMatchers.end()) {
@@ -72,7 +75,7 @@ std::vector<Matcher> dedupFieldMatchers(const std::vector<Matcher>& fieldMatcher
 }
 
 void translateFieldMatcher(int tag, const FieldMatcher& matcher, int depth, int* pos, int* mask,
-                           std::vector<Matcher>* output) {
+                           vector<Matcher>* output) {
     if (depth > kMaxLogDepth) {
         ALOGE("depth > 2");
         return;
@@ -119,7 +122,7 @@ void translateFieldMatcher(int tag, const FieldMatcher& matcher, int depth, int*
     }
 }
 
-void translateFieldMatcher(const FieldMatcher& matcher, std::vector<Matcher>* output) {
+void translateFieldMatcher(const FieldMatcher& matcher, vector<Matcher>* output) {
     int pos[] = {1, 1, 1};
     int mask[] = {0x7f, 0x7f, 0x7f};
     int tag = matcher.field();
@@ -136,7 +139,7 @@ int32_t getUidIfExists(const FieldValue& value) {
     // the field is uid field if the field is the uid field in attribution node
     // or annotated as such in the atom
     bool isUid = isAttributionUidField(value) || isUidField(value);
-    return isUid ? value.mValue.int_value : -1;
+    return isUid ? value.mValue.get<int32_t>() : -1;
 }
 
 bool isAttributionUidField(const Field& field, const Value& value) {
@@ -155,241 +158,85 @@ bool isPrimitiveRepeatedField(const Field& field) {
     return field.getDepth() == 1;
 }
 
-Value::Value(const Value& from) {
-    type = from.getType();
-    switch (type) {
-        case INT:
-            int_value = from.int_value;
-            break;
-        case LONG:
-            long_value = from.long_value;
-            break;
-        case FLOAT:
-            float_value = from.float_value;
-            break;
-        case DOUBLE:
-            double_value = from.double_value;
-            break;
-        case STRING:
-            str_value = from.str_value;
-            break;
-        case STORAGE:
-            storage_value = from.storage_value;
-            break;
-        default:
-            break;
+// anonymous namespace for Value variant visitors
+namespace {
+// Visitor for printing type information currently stored in the Value.
+struct ToStringVisitor {
+    string operator()(int32_t value) const {
+        return std::to_string(value) + "[I]";
     }
-}
-
-std::string Value::toString() const {
-    switch (type) {
-        case INT:
-            return std::to_string(int_value) + "[I]";
-        case LONG:
-            return std::to_string(long_value) + "[L]";
-        case FLOAT:
-            return std::to_string(float_value) + "[F]";
-        case DOUBLE:
-            return std::to_string(double_value) + "[D]";
-        case STRING:
-            return str_value + "[S]";
-        case STORAGE:
-            return "bytes of size " + std::to_string(storage_value.size()) + "[ST]";
-        default:
-            return "[UNKNOWN]";
+    string operator()(int64_t value) const {
+        return std::to_string(value) + "[L]";
     }
-}
-
-bool Value::isZero() const {
-    switch (type) {
-        case INT:
-            return int_value == 0;
-        case LONG:
-            return long_value == 0;
-        case FLOAT:
-            return fabs(float_value) <= std::numeric_limits<float>::epsilon();
-        case DOUBLE:
-            return fabs(double_value) <= std::numeric_limits<double>::epsilon();
-        case STRING:
-            return str_value.size() == 0;
-        case STORAGE:
-            return storage_value.size() == 0;
-        default:
-            return false;
+    string operator()(float value) const {
+        return std::to_string(value) + "[F]";
     }
-}
-
-bool Value::operator==(const Value& that) const {
-    if (type != that.getType()) return false;
-
-    switch (type) {
-        case INT:
-            return int_value == that.int_value;
-        case LONG:
-            return long_value == that.long_value;
-        case FLOAT:
-            return float_value == that.float_value;
-        case DOUBLE:
-            return double_value == that.double_value;
-        case STRING:
-            return str_value == that.str_value;
-        case STORAGE:
-            return storage_value == that.storage_value;
-        default:
-            return false;
+    string operator()(double value) const {
+        return std::to_string(value) + "[D]";
     }
-}
-
-bool Value::operator!=(const Value& that) const {
-    if (type != that.getType()) return true;
-    switch (type) {
-        case INT:
-            return int_value != that.int_value;
-        case LONG:
-            return long_value != that.long_value;
-        case FLOAT:
-            return float_value != that.float_value;
-        case DOUBLE:
-            return double_value != that.double_value;
-        case STRING:
-            return str_value != that.str_value;
-        case STORAGE:
-            return storage_value != that.storage_value;
-        default:
-            return false;
+    string operator()(const string& value) const {
+        return value + "[S]";
     }
-}
-
-bool Value::operator<(const Value& that) const {
-    if (type != that.getType()) return type < that.getType();
-
-    switch (type) {
-        case INT:
-            return int_value < that.int_value;
-        case LONG:
-            return long_value < that.long_value;
-        case FLOAT:
-            return float_value < that.float_value;
-        case DOUBLE:
-            return double_value < that.double_value;
-        case STRING:
-            return str_value < that.str_value;
-        case STORAGE:
-            return storage_value < that.storage_value;
-        default:
-            return false;
+    string operator()(const vector<uint8_t>& value) const {
+        return "bytes of size " + std::to_string(value.size()) + "[ST]";
     }
-}
-
-bool Value::operator>(const Value& that) const {
-    if (type != that.getType()) return type > that.getType();
-
-    switch (type) {
-        case INT:
-            return int_value > that.int_value;
-        case LONG:
-            return long_value > that.long_value;
-        case FLOAT:
-            return float_value > that.float_value;
-        case DOUBLE:
-            return double_value > that.double_value;
-        case STRING:
-            return str_value > that.str_value;
-        case STORAGE:
-            return storage_value > that.storage_value;
-        default:
-            return false;
+    string operator()(std::monostate) const {
+        return "[UNKNOWN]";
     }
-}
-
-bool Value::operator>=(const Value& that) const {
-    if (type != that.getType()) return type >= that.getType();
+};
 
-    switch (type) {
-        case INT:
-            return int_value >= that.int_value;
-        case LONG:
-            return long_value >= that.long_value;
-        case FLOAT:
-            return float_value >= that.float_value;
-        case DOUBLE:
-            return double_value >= that.double_value;
-        case STRING:
-            return str_value >= that.str_value;
-        case STORAGE:
-            return storage_value >= that.storage_value;
-        default:
-            return false;
+struct GetSizeVisitor {
+    size_t operator()(const string& value) const {
+        return sizeof(char) * value.length();
     }
-}
-
-Value Value::operator-(const Value& that) const {
-    Value v;
-    if (type != that.type) {
-        ALOGE("Can't operate on different value types, %d, %d", type, that.type);
-        return v;
+    size_t operator()(const vector<uint8_t>& value) const {
+        return sizeof(uint8_t) * value.size();
     }
-    if (type == STRING) {
-        ALOGE("Can't operate on string value type");
-        return v;
+    size_t operator()(const auto& value) const {
+        return sizeof(value);
     }
+};
+}  // namespace
 
-    if (type == STORAGE) {
-        ALOGE("Can't operate on storage value type");
-        return v;
-    }
+// Keeping the impl in the cpp file and explicitly naming the templates prevents accidentally
+// accessing unsupported types.
+template <typename V>
+V& Value::get() {
+    return std::get<V>(mData);
+}
+template int32_t& Value::get<int32_t>();
+template int64_t& Value::get<int64_t>();
+template float& Value::get<float>();
+template double& Value::get<double>();
+template string& Value::get<string>();
+template vector<uint8_t>& Value::get<vector<uint8_t>>();
 
-    switch (type) {
-        case INT:
-            v.setInt(int_value - that.int_value);
-            break;
-        case LONG:
-            v.setLong(long_value - that.long_value);
-            break;
-        case FLOAT:
-            v.setFloat(float_value - that.float_value);
-            break;
-        case DOUBLE:
-            v.setDouble(double_value - that.double_value);
-            break;
-        default:
-            break;
-    }
-    return v;
+template <typename V>
+const V& Value::get() const {
+    return std::get<V>(mData);
 }
+template const int32_t& Value::get<int32_t>() const;
+template const int64_t& Value::get<int64_t>() const;
+template const float& Value::get<float>() const;
+template const double& Value::get<double>() const;
+template const string& Value::get<string>() const;
+template const vector<uint8_t>& Value::get<vector<uint8_t>>() const;
 
-Value& Value::operator=(const Value& that) {
-    if (this != &that) {
-        type = that.type;
-        switch (type) {
-            case INT:
-                int_value = that.int_value;
-                break;
-            case LONG:
-                long_value = that.long_value;
-                break;
-            case FLOAT:
-                float_value = that.float_value;
-                break;
-            case DOUBLE:
-                double_value = that.double_value;
-                break;
-            case STRING:
-                str_value = that.str_value;
-                break;
-            case STORAGE:
-                storage_value = that.storage_value;
-                break;
-            default:
-                break;
-        }
-    }
-    return *this;
+template <typename V>
+void Value::set(V v) {
+    mData = v;
+}
+template void Value::set<int32_t>(int32_t);
+template void Value::set<int64_t>(int64_t);
+
+string Value::toString() const {
+    return std::visit(ToStringVisitor{}, mData);
 }
 
 Value& Value::operator+=(const Value& that) {
-    if (type != that.type) {
-        ALOGE("Can't operate on different value types, %d, %d", type, that.type);
+    Type type = getType();
+    if (type != that.getType()) {
+        ALOGE("Can't operate on different value types, %d, %d", type, that.getType());
         return *this;
     }
     if (type == STRING) {
@@ -403,16 +250,16 @@ Value& Value::operator+=(const Value& that) {
 
     switch (type) {
         case INT:
-            int_value += that.int_value;
+            mData = get<int32_t>() + that.get<int32_t>();
             break;
         case LONG:
-            long_value += that.long_value;
+            mData = get<int64_t>() + that.get<int64_t>();
             break;
         case FLOAT:
-            float_value += that.float_value;
+            mData = get<float>() + that.get<float>();
             break;
         case DOUBLE:
-            double_value += that.double_value;
+            mData = get<double>() + that.get<double>();
             break;
         default:
             break;
@@ -420,50 +267,12 @@ Value& Value::operator+=(const Value& that) {
     return *this;
 }
 
-double Value::getDouble() const {
-    switch (type) {
-        case INT:
-            return int_value;
-        case LONG:
-            return long_value;
-        case FLOAT:
-            return float_value;
-        case DOUBLE:
-            return double_value;
-        default:
-            return 0;
-    }
-}
-
 size_t Value::getSize() const {
-    size_t size = 0;
-    switch (type) {
-        case INT:
-            size = sizeof(int32_t);
-            break;
-        case LONG:
-            size = sizeof(int64_t);
-            break;
-        case FLOAT:
-            size = sizeof(float);
-            break;
-        case DOUBLE:
-            size = sizeof(double);
-            break;
-        case STRING:
-            size = sizeof(char) * str_value.length();
-            break;
-        case STORAGE:
-            size = sizeof(uint8_t) * storage_value.size();
-            break;
-        default:
-            break;
-    }
-    return size;
+    return std::visit(GetSizeVisitor{}, mData);
 }
 
-std::string Annotations::toString() const {
-    std::string annotations;
+string Annotations::toString() const {
+    string annotations;
     if (isUidField()) {
         annotations += "UID";
     }
@@ -482,8 +291,7 @@ std::string Annotations::toString() const {
     return annotations;
 }
 
-bool equalDimensions(const std::vector<Matcher>& dimension_a,
-                     const std::vector<Matcher>& dimension_b) {
+bool equalDimensions(const vector<Matcher>& dimension_a, const vector<Matcher>& dimension_b) {
     bool eq = dimension_a.size() == dimension_b.size();
     for (size_t i = 0; eq && i < dimension_a.size(); ++i) {
         if (dimension_b[i] != dimension_a[i]) {
@@ -494,8 +302,7 @@ bool equalDimensions(const std::vector<Matcher>& dimension_a,
 }
 
 /* Is dimension_a a subset of dimension_b. */
-bool subsetDimensions(const std::vector<Matcher>& dimension_a,
-                      const std::vector<Matcher>& dimension_b) {
+bool subsetDimensions(const vector<Matcher>& dimension_a, const vector<Matcher>& dimension_b) {
     if (dimension_a.size() > dimension_b.size()) {
         return false;
     }
@@ -562,7 +369,7 @@ bool ShouldUseNestedDimensions(const FieldMatcher& matcher) {
     return HasPositionALL(matcher) || HasPrimitiveRepeatedField(matcher);
 }
 
-size_t getSize(const std::vector<FieldValue>& fieldValues) {
+size_t getSize(const vector<FieldValue>& fieldValues) {
     size_t totalSize = 0;
     for (const FieldValue& fieldValue : fieldValues) {
         totalSize += fieldValue.getSize();
@@ -570,7 +377,7 @@ size_t getSize(const std::vector<FieldValue>& fieldValues) {
     return totalSize;
 }
 
-size_t getFieldValuesSizeV2(const std::vector<FieldValue>& fieldValues) {
+size_t getFieldValuesSizeV2(const vector<FieldValue>& fieldValues) {
     size_t totalSize = 0;
     for (const FieldValue& fieldValue : fieldValues) {
         totalSize += fieldValue.getSizeV2();
@@ -580,29 +387,32 @@ size_t getFieldValuesSizeV2(const std::vector<FieldValue>& fieldValues) {
 
 bool shouldKeepSample(const FieldValue& sampleFieldValue, int shardOffset, int shardCount) {
     int hashValue = 0;
-    switch (sampleFieldValue.mValue.type) {
+    switch (sampleFieldValue.mValue.getType()) {
         case INT:
-            hashValue = Hash32(reinterpret_cast<const char*>(&sampleFieldValue.mValue.int_value),
-                               sizeof(sampleFieldValue.mValue.int_value));
+            hashValue =
+                    Hash32(reinterpret_cast<const char*>(&sampleFieldValue.mValue.get<int32_t>()),
+                           sizeof(sampleFieldValue.mValue.get<int32_t>()));
             break;
         case LONG:
-            hashValue = Hash32(reinterpret_cast<const char*>(&sampleFieldValue.mValue.long_value),
-                               sizeof(sampleFieldValue.mValue.long_value));
+            hashValue =
+                    Hash32(reinterpret_cast<const char*>(&sampleFieldValue.mValue.get<int64_t>()),
+                           sizeof(sampleFieldValue.mValue.get<int64_t>()));
             break;
         case FLOAT:
-            hashValue = Hash32(reinterpret_cast<const char*>(&sampleFieldValue.mValue.float_value),
-                               sizeof(sampleFieldValue.mValue.float_value));
+            hashValue = Hash32(reinterpret_cast<const char*>(&sampleFieldValue.mValue.get<float>()),
+                               sizeof(sampleFieldValue.mValue.get<float>()));
             break;
         case DOUBLE:
-            hashValue = Hash32(reinterpret_cast<const char*>(&sampleFieldValue.mValue.double_value),
-                               sizeof(sampleFieldValue.mValue.double_value));
+            hashValue =
+                    Hash32(reinterpret_cast<const char*>(&sampleFieldValue.mValue.get<double>()),
+                           sizeof(sampleFieldValue.mValue.get<double>()));
             break;
         case STRING:
-            hashValue = Hash32(sampleFieldValue.mValue.str_value);
+            hashValue = Hash32(sampleFieldValue.mValue.get<string>());
             break;
         case STORAGE:
-            hashValue = Hash32((const char*)sampleFieldValue.mValue.storage_value.data(),
-                               sampleFieldValue.mValue.storage_value.size());
+            hashValue = Hash32((const char*)sampleFieldValue.mValue.get<vector<uint8_t>>().data(),
+                               sampleFieldValue.mValue.get<vector<uint8_t>>().size());
             break;
         default:
             return true;
diff --git a/statsd/src/FieldValue.h b/statsd/src/FieldValue.h
index 22fa89b1..43a08bc1 100644
--- a/statsd/src/FieldValue.h
+++ b/statsd/src/FieldValue.h
@@ -15,6 +15,8 @@
  */
 #pragma once
 
+#include <string>
+
 #include "src/statsd_config.pb.h"
 
 namespace android {
@@ -31,7 +33,8 @@ const int32_t kLastBitMask = 0x80;
 const int32_t kClearLastBitDeco = 0x7f;
 const int32_t kClearAllPositionMatcherMask = 0xffff00ff;
 
-enum Type { UNKNOWN, INT, LONG, FLOAT, DOUBLE, STRING, STORAGE };
+// MUST BE DECLARED IN THE SAME ORDER AS THE ALTERNATIVES IN VALUE VARIANT
+enum Type { UNKNOWN = 0, INT = 1, LONG = 2, FLOAT = 3, DOUBLE = 4, STRING = 5, STORAGE = 6 };
 
 int32_t getEncodedField(int32_t pos[], int32_t depth, bool includeDepth);
 
@@ -279,93 +282,42 @@ inline Matcher getFirstUidMatcher(int32_t atomId) {
  * A wrapper for a union type to contain multiple types of values.
  *
  */
-struct Value {
-    Value() : type(UNKNOWN) {}
-
-    Value(int32_t v) {
-        int_value = v;
-        type = INT;
-    }
-
-    Value(int64_t v) {
-        long_value = v;
-        type = LONG;
-    }
-
-    Value(float v) {
-        float_value = v;
-        type = FLOAT;
-    }
-
-    Value(double v) {
-        double_value = v;
-        type = DOUBLE;
-    }
-
-    Value(const std::string& v) {
-        str_value = v;
-        type = STRING;
-    }
-
-    Value(const std::vector<uint8_t>& v) {
-        storage_value = v;
-        type = STORAGE;
-    }
-
-    void setInt(int32_t v) {
-        int_value = v;
-        type = INT;
-    }
-
-    void setLong(int64_t v) {
-        long_value = v;
-        type = LONG;
-    }
+class Value {
+public:
+    Value() noexcept = default;
 
-    void setFloat(float v) {
-        float_value = v;
-        type = FLOAT;
+    // Copy constructor for contained types
+    template <typename V>
+    Value(const V& value) : mData(value) {
     }
 
-    void setDouble(double v) {
-        double_value = v;
-        type = DOUBLE;
-    }
+    template <typename V>
+    V& get();
 
-    union {
-        int32_t int_value;
-        int64_t long_value;
-        float float_value;
-        double double_value;
-    };
-    std::string str_value;
-    std::vector<uint8_t> storage_value;
+    template <typename V>
+    const V& get() const;
 
-    Type type;
+    template <typename V>
+    void set(V v);
 
     std::string toString() const;
 
-    bool isZero() const;
-
     Type getType() const {
-        return type;
+        return static_cast<Type>(mData.index());
     }
 
-    double getDouble() const;
-
     size_t getSize() const;
 
-    Value(const Value& from);
+    constexpr Value(const Value& other) = default;
 
-    bool operator==(const Value& that) const;
-    bool operator!=(const Value& that) const;
+    auto operator<=>(const Value& that) const = default;
 
-    bool operator<(const Value& that) const;
-    bool operator>(const Value& that) const;
-    bool operator>=(const Value& that) const;
-    Value operator-(const Value& that) const;
     Value& operator+=(const Value& that);
-    Value& operator=(const Value& that);
+    Value& operator=(const Value& that) = default;
+
+private:
+    std::variant<std::monostate, int32_t, int64_t, float, double, std::string, std::vector<uint8_t>>
+            mData;
 };
 
 class Annotations {
diff --git a/statsd/src/HashableDimensionKey.cpp b/statsd/src/HashableDimensionKey.cpp
index fb42efd5..bdb2b4ff 100644
--- a/statsd/src/HashableDimensionKey.cpp
+++ b/statsd/src/HashableDimensionKey.cpp
@@ -58,19 +58,19 @@ static void populateStatsDimensionsValueParcelChildren(StatsDimensionsValueParce
             switch (dim.mValue.getType()) {
                 case INT:
                     child.valueType = STATS_DIMENSIONS_VALUE_INT_TYPE;
-                    child.intValue = dim.mValue.int_value;
+                    child.intValue = dim.mValue.get<int32_t>();
                     break;
                 case LONG:
                     child.valueType = STATS_DIMENSIONS_VALUE_LONG_TYPE;
-                    child.longValue = dim.mValue.long_value;
+                    child.longValue = dim.mValue.get<int64_t>();
                     break;
                 case FLOAT:
                     child.valueType = STATS_DIMENSIONS_VALUE_FLOAT_TYPE;
-                    child.floatValue = dim.mValue.float_value;
+                    child.floatValue = dim.mValue.get<float>();
                     break;
                 case STRING:
                     child.valueType = STATS_DIMENSIONS_VALUE_STRING_TYPE;
-                    child.stringValue = dim.mValue.str_value;
+                    child.stringValue = dim.mValue.get<string>();
                     break;
                 default:
                     ALOGE("Encountered FieldValue with unsupported value type.");
@@ -119,30 +119,31 @@ android::hash_t hashDimension(const HashableDimensionKey& value) {
         hash = android::JenkinsHashMix(hash, android::hash_type((int)fieldValue.mValue.getType()));
         switch (fieldValue.mValue.getType()) {
             case INT:
-                hash = android::JenkinsHashMix(hash,
-                                               android::hash_type(fieldValue.mValue.int_value));
+                hash = android::JenkinsHashMix(
+                        hash, android::hash_type(fieldValue.mValue.get<int32_t>()));
                 break;
             case LONG:
-                hash = android::JenkinsHashMix(hash,
-                                               android::hash_type(fieldValue.mValue.long_value));
+                hash = android::JenkinsHashMix(
+                        hash, android::hash_type(fieldValue.mValue.get<int64_t>()));
                 break;
             case STRING:
                 hash = android::JenkinsHashMix(hash, static_cast<uint32_t>(std::hash<std::string>()(
-                                                             fieldValue.mValue.str_value)));
+                                                             fieldValue.mValue.get<string>())));
                 break;
             case FLOAT: {
                 hash = android::JenkinsHashMix(hash,
-                                               android::hash_type(fieldValue.mValue.float_value));
+                                               android::hash_type(fieldValue.mValue.get<float>()));
                 break;
             }
             case DOUBLE: {
                 hash = android::JenkinsHashMix(hash,
-                                               android::hash_type(fieldValue.mValue.double_value));
+                                               android::hash_type(fieldValue.mValue.get<double>()));
                 break;
             }
             case STORAGE: {
-                hash = android::JenkinsHashMixBytes(hash, fieldValue.mValue.storage_value.data(),
-                                                    fieldValue.mValue.storage_value.size());
+                hash = android::JenkinsHashMixBytes(
+                        hash, fieldValue.mValue.get<vector<uint8_t>>().data(),
+                        fieldValue.mValue.get<vector<uint8_t>>().size());
                 break;
             }
             default:
@@ -229,10 +230,6 @@ bool filterPrimaryKey(const std::vector<FieldValue>& values, HashableDimensionKe
 
 vector<FieldValue> filterValues(const std::vector<Matcher>& matcherFields,
                                 const std::vector<FieldValue>& values, bool omitMatches) {
-    if (matcherFields.empty()) {
-        return values;
-    }
-
     vector<FieldValue> output;
     for (const auto& field : matcherFields) {
         for (const auto& value : values) {
diff --git a/statsd/src/HashableDimensionKey.h b/statsd/src/HashableDimensionKey.h
index e3f82b62..79623b69 100644
--- a/statsd/src/HashableDimensionKey.h
+++ b/statsd/src/HashableDimensionKey.h
@@ -52,8 +52,7 @@ struct Metric2State {
 
 class HashableDimensionKey {
 public:
-    explicit HashableDimensionKey(const std::vector<FieldValue>& values) {
-        mValues = values;
+    explicit HashableDimensionKey(const std::vector<FieldValue>& values) : mValues(values) {
     }
 
     HashableDimensionKey() {};
diff --git a/statsd/src/StatsLogProcessor.cpp b/statsd/src/StatsLogProcessor.cpp
index 6be387ff..8364a086 100644
--- a/statsd/src/StatsLogProcessor.cpp
+++ b/statsd/src/StatsLogProcessor.cpp
@@ -169,8 +169,8 @@ void StatsLogProcessor::mapIsolatedUidToHostUidIfNecessaryLocked(LogEvent* event
         for (size_t i = indexRange.first; i <= indexRange.second; i++) {
             FieldValue& fieldValue = fieldValues->at(i);
             if (isAttributionUidField(fieldValue)) {
-                const int hostUid = mUidMap->getHostUidOrSelf(fieldValue.mValue.int_value);
-                fieldValue.mValue.setInt(hostUid);
+                const int hostUid = mUidMap->getHostUidOrSelf(fieldValue.mValue.get<int32_t>());
+                fieldValue.mValue.set(hostUid);
             }
         }
     } else {
@@ -230,9 +230,15 @@ void StatsLogProcessor::onBinaryPushStateChangedEventLocked(LogEvent* event) {
     trainInfo.experimentIds = {trainExperimentIds.experiment_id().begin(),
                                trainExperimentIds.experiment_id().end()};
 
+    VLOG("trainInfo.experimentIds before update %s",
+         InstallTrainInfo::experimentIdsToString(trainInfo.experimentIds).c_str());
+
     // Update the train info on disk and get any data the logevent is missing.
     getAndUpdateTrainInfoOnDisk(is_rollback, &trainInfo);
 
+    VLOG("trainInfo.experimentIds after update %s",
+         InstallTrainInfo::experimentIdsToString(trainInfo.experimentIds).c_str());
+
     std::vector<uint8_t> trainExperimentIdProto;
     writeExperimentIdsToProto(trainInfo.experimentIds, &trainExperimentIdProto);
     int32_t userId = multiuser_get_user_id(uid);
@@ -827,7 +833,8 @@ void StatsLogProcessor::onConfigMetricsReportLocked(
     // Data corrupted reason
     writeDataCorruptedReasons(tempProto, FIELD_ID_DATA_CORRUPTED_REASON,
                               StatsdStats::getInstance().hasEventQueueOverflow(),
-                              StatsdStats::getInstance().hasSocketLoss());
+                              StatsdStats::getInstance().hasSocketLoss(),
+                              StatsdStats::getInstance().hasSystemServerRestart());
 
     // Estimated memory bytes
     tempProto.write(FIELD_TYPE_INT64 | FIELD_ID_ESTIMATED_DATA_BYTES, totalSize);
diff --git a/statsd/src/StatsLogProcessor.h b/statsd/src/StatsLogProcessor.h
index 732e2259..da65ecc5 100644
--- a/statsd/src/StatsLogProcessor.h
+++ b/statsd/src/StatsLogProcessor.h
@@ -476,6 +476,7 @@ private:
     FRIEND_TEST(CountMetricE2eTest, TestRepeatedFieldsAndEmptyArrays);
 
     FRIEND_TEST(DurationMetricE2eTest, TestOneBucket);
+    FRIEND_TEST(DurationMetricE2eTest, TestOneBucketDifferentAtomsForPredicate);
     FRIEND_TEST(DurationMetricE2eTest, TestTwoBuckets);
     FRIEND_TEST(DurationMetricE2eTest, TestWithActivation);
     FRIEND_TEST(DurationMetricE2eTest, TestWithCondition);
@@ -506,6 +507,9 @@ private:
     FRIEND_TEST(ValueMetricE2eTest, TestInitWithValueFieldPositionALL);
     FRIEND_TEST(ValueMetricE2eTest, TestInitWithMultipleAggTypes);
     FRIEND_TEST(ValueMetricE2eTest, TestInitWithDefaultAggType);
+    FRIEND_TEST(ValueMetricE2eTest, TestDimensionGuardrailHitWithZeroDefaultBase);
+    FRIEND_TEST(ValueMetricE2eTest,
+                TestDimensionGuardrailHitWithZeroDefaultBaseAndConditionAndState);
 
     FRIEND_TEST(KllMetricE2eTest, TestInitWithKllFieldPositionALL);
 
diff --git a/statsd/src/external/StatsPullerManager.cpp b/statsd/src/external/StatsPullerManager.cpp
index 81e586ab..8c5773a4 100644
--- a/statsd/src/external/StatsPullerManager.cpp
+++ b/statsd/src/external/StatsPullerManager.cpp
@@ -231,8 +231,7 @@ void StatsPullerManager::UnregisterPullUidProvider(const ConfigKey& configKey,
 static void processPullerQueue(ThreadSafeQueue<StatsPullerManager::PullerParams>& pullerQueue,
                                std::queue<StatsPullerManager::PulledInfo>& pulledData,
                                const int64_t wallClockNs, const int64_t elapsedTimeNs,
-                               std::atomic_int& pendingThreads,
-                               std::condition_variable& mainThreadCondition,
+                               int& pendingThreads, std::condition_variable& mainThreadCondition,
                                std::mutex& mainThreadConditionLock) {
     std::optional<StatsPullerManager::PullerParams> queueResult = pullerQueue.pop();
     while (queueResult.has_value()) {
@@ -269,7 +268,9 @@ static void processPullerQueue(ThreadSafeQueue<StatsPullerManager::PullerParams>
 
         queueResult = pullerQueue.pop();
     }
+    mainThreadConditionLock.lock();
     pendingThreads--;
+    mainThreadConditionLock.unlock();
     mainThreadCondition.notify_one();
 }
 
@@ -283,20 +284,28 @@ void StatsPullerManager::OnAlarmFired(int64_t elapsedTimeNs) {
         ThreadSafeQueue<PullerParams> pullerQueue;
         std::queue<PulledInfo> pulledData;
         initPullerQueue(pullerQueue, pulledData, elapsedTimeNs, minNextPullTimeNs);
+        int pendingThreads = 0;
+        vector<thread> pullerThreads;
         std::mutex mainThreadConditionLock;
         std::condition_variable waitForPullerThreadsCondition;
-        vector<thread> pullerThreads;
-        std::atomic_int pendingThreads = PULLER_THREAD_COUNT;
-        pullerThreads.reserve(PULLER_THREAD_COUNT);
-        // Spawn multiple threads to simultaneously pull all necessary pullers. These pullers push
-        // the pulled data to a queue for the main thread to process.
-        for (int i = 0; i < PULLER_THREAD_COUNT; ++i) {
-            pullerThreads.emplace_back(
-                    processPullerQueue, std::ref(pullerQueue), std::ref(pulledData), wallClockNs,
-                    elapsedTimeNs, std::ref(pendingThreads),
-                    std::ref(waitForPullerThreadsCondition), std::ref(mainThreadConditionLock));
+        if (!pullerQueue.empty()) {
+            StatsdStats::getInstance().notePullerAlarmHasPull();
+            const int numThreads = std::min(pullerQueue.size(), PULLER_THREAD_COUNT);
+            pendingThreads = numThreads;
+            pullerThreads.reserve(numThreads);
+            // Spawn multiple threads to simultaneously pull all necessary pullers. These pullers
+            // push the pulled data to a queue for the main thread to process.
+            for (int i = 0; i < numThreads; ++i) {
+                pullerThreads.emplace_back(
+                        processPullerQueue, std::ref(pullerQueue), std::ref(pulledData),
+                        wallClockNs, elapsedTimeNs, std::ref(pendingThreads),
+                        std::ref(waitForPullerThreadsCondition), std::ref(mainThreadConditionLock));
+            }
+        } else if (!pulledData.empty()) {
+            StatsdStats::getInstance().notePullerAlarmError();
+        } else {
+            StatsdStats::getInstance().notePullerAlarmNoPull();
         }
-
         // Process all pull results on the main thread without waiting for the puller threads
         // to finish.
         while (true) {
@@ -340,7 +349,6 @@ void StatsPullerManager::OnAlarmFired(int64_t elapsedTimeNs) {
         for (thread& pullerThread : pullerThreads) {
             pullerThread.join();
         }
-
     } else {
         onAlarmFiredSynchronous(elapsedTimeNs, wallClockNs, minNextPullTimeNs);
     }
@@ -444,56 +452,53 @@ void StatsPullerManager::initPullerQueue(ThreadSafeQueue<PullerParams>& pullerQu
                                          const int64_t elapsedTimeNs, int64_t& minNextPullTimeNs) {
     for (auto& pair : mReceivers) {
         vector<ReceiverInfo*> receivers;
-        if (pair.second.size() != 0) {
-            for (ReceiverInfo& receiverInfo : pair.second) {
-                // If pullNecessary and enough time has passed for the next bucket, then add
-                // receiver to the list that will pull on this alarm.
-                // If pullNecessary is false, check if next pull time needs to be updated.
-                sp<PullDataReceiver> receiverPtr = receiverInfo.receiver.promote();
-                if (receiverInfo.nextPullTimeNs <= elapsedTimeNs && receiverPtr != nullptr &&
-                    receiverPtr->isPullNeeded()) {
-                    receivers.push_back(&receiverInfo);
-                } else {
-                    if (receiverInfo.nextPullTimeNs <= elapsedTimeNs) {
-                        receiverPtr->onDataPulled({}, PullResult::PULL_NOT_NEEDED, elapsedTimeNs);
-                        int numBucketsAhead = (elapsedTimeNs - receiverInfo.nextPullTimeNs) /
-                                              receiverInfo.intervalNs;
-                        receiverInfo.nextPullTimeNs +=
-                                (numBucketsAhead + 1) * receiverInfo.intervalNs;
-                    }
-                    minNextPullTimeNs = min(receiverInfo.nextPullTimeNs, minNextPullTimeNs);
+        for (ReceiverInfo& receiverInfo : pair.second) {
+            // If pullNecessary and enough time has passed for the next bucket, then add
+            // receiver to the list that will pull on this alarm.
+            // If pullNecessary is false, check if next pull time needs to be updated.
+            sp<PullDataReceiver> receiverPtr = receiverInfo.receiver.promote();
+            if (receiverInfo.nextPullTimeNs <= elapsedTimeNs && receiverPtr != nullptr &&
+                receiverPtr->isPullNeeded()) {
+                receivers.push_back(&receiverInfo);
+            } else {
+                if (receiverInfo.nextPullTimeNs <= elapsedTimeNs) {
+                    receiverPtr->onDataPulled({}, PullResult::PULL_NOT_NEEDED, elapsedTimeNs);
+                    int numBucketsAhead =
+                            (elapsedTimeNs - receiverInfo.nextPullTimeNs) / receiverInfo.intervalNs;
+                    receiverInfo.nextPullTimeNs += (numBucketsAhead + 1) * receiverInfo.intervalNs;
                 }
+                minNextPullTimeNs = min(receiverInfo.nextPullTimeNs, minNextPullTimeNs);
             }
-            if (receivers.size() > 0) {
-                bool foundPuller = false;
-                int tagId = pair.first.atomTag;
-                vector<int32_t> uids;
-                if (getPullerUidsLocked(tagId, pair.first.configKey, uids)) {
-                    for (int32_t uid : uids) {
-                        PullerKey key = {.uid = uid, .atomTag = tagId};
-                        auto pullerIt = mAllPullAtomInfo.find(key);
-                        if (pullerIt != mAllPullAtomInfo.end()) {
-                            PullerParams params;
-                            params.key = key;
-                            params.puller = pullerIt->second;
-                            params.receivers = std::move(receivers);
-                            pullerQueue.push(params);
-                            foundPuller = true;
-                            break;
-                        }
-                    }
-                    if (!foundPuller) {
-                        StatsdStats::getInstance().notePullerNotFound(tagId);
-                        ALOGW("StatsPullerManager: Unknown tagId %d", tagId);
+        }
+        if (receivers.size() > 0) {
+            bool foundPuller = false;
+            int tagId = pair.first.atomTag;
+            vector<int32_t> uids;
+            if (getPullerUidsLocked(tagId, pair.first.configKey, uids)) {
+                for (int32_t uid : uids) {
+                    PullerKey key = {.uid = uid, .atomTag = tagId};
+                    auto pullerIt = mAllPullAtomInfo.find(key);
+                    if (pullerIt != mAllPullAtomInfo.end()) {
+                        PullerParams params;
+                        params.key = key;
+                        params.puller = pullerIt->second;
+                        params.receivers = std::move(receivers);
+                        pullerQueue.push(params);
+                        foundPuller = true;
+                        break;
                     }
                 }
                 if (!foundPuller) {
-                    PulledInfo pulledInfo;
-                    pulledInfo.pullErrorCode = PullErrorCode::PULL_FAIL;
-                    pulledInfo.receiverInfo = std::move(receivers);
-                    pulledData.push(pulledInfo);
+                    StatsdStats::getInstance().notePullerNotFound(tagId);
+                    ALOGW("StatsPullerManager: Unknown tagId %d", tagId);
                 }
             }
+            if (!foundPuller) {
+                PulledInfo pulledInfo;
+                pulledInfo.pullErrorCode = PullErrorCode::PULL_FAIL;
+                pulledInfo.receiverInfo = std::move(receivers);
+                pulledData.push(pulledInfo);
+            }
         }
     }
 }
diff --git a/statsd/src/external/ThreadSafeQueue.h b/statsd/src/external/ThreadSafeQueue.h
index de578c28..c8436dbb 100644
--- a/statsd/src/external/ThreadSafeQueue.h
+++ b/statsd/src/external/ThreadSafeQueue.h
@@ -40,6 +40,11 @@ public:
         mQueue.push(value);
     }
 
+    int32_t size() const {
+        std::unique_lock<std::mutex> lock(mMutex);
+        return mQueue.size();
+    }
+
     bool empty() const {
         std::unique_lock<std::mutex> lock(mMutex);
         return mQueue.empty();
diff --git a/statsd/src/external/puller_util.cpp b/statsd/src/external/puller_util.cpp
index b0c68f41..0a4db425 100644
--- a/statsd/src/external/puller_util.cpp
+++ b/statsd/src/external/puller_util.cpp
@@ -71,8 +71,8 @@ void mapAndMergeIsolatedUidsToHostUid(vector<shared_ptr<LogEvent>>& data, const
             for (size_t i = attrIndexRange.first; i <= attrIndexRange.second; i++) {
                 FieldValue& fieldValue = fieldValues->at(i);
                 if (isAttributionUidField(fieldValue)) {
-                    const int hostUid = uidMap->getHostUidOrSelf(fieldValue.mValue.int_value);
-                    fieldValue.mValue.setInt(hostUid);
+                    const int hostUid = uidMap->getHostUidOrSelf(fieldValue.mValue.get<int32_t>());
+                    fieldValue.mValue.set(hostUid);
                 }
             }
         } else {
diff --git a/statsd/src/guardrail/StatsdStats.cpp b/statsd/src/guardrail/StatsdStats.cpp
index 5ebfa8c3..784b73cd 100644
--- a/statsd/src/guardrail/StatsdStats.cpp
+++ b/statsd/src/guardrail/StatsdStats.cpp
@@ -69,6 +69,7 @@ const int FIELD_ID_QUEUE_STATS = 25;
 const int FIELD_ID_SOCKET_READ_STATS = 26;
 const int FIELD_ID_ERROR_STATS = 27;
 const int FIELD_ID_PEAK_LOGGING_RATES = 28;
+const int FIELD_ID_PULLER_ALARM_STATS = 29;
 
 const int FIELD_ID_RESTRICTED_METRIC_QUERY_STATS_CALLING_UID = 1;
 const int FIELD_ID_RESTRICTED_METRIC_QUERY_STATS_CONFIG_ID = 2;
@@ -227,6 +228,11 @@ const int FIELD_ID_LARGE_BATCH_SOCKET_READ_ATOM_STATS_COUNT = 2;
 // ErrorStats
 const int FIELD_ID_ERROR_STATS_COUNTERS = 1;
 
+// PullerAlarmStats
+const int FIELD_ID_PULLER_ALARM_STATS_ALARM_WITH_PULLS_COUNT = 1;
+const int FIELD_ID_PULLER_ALARM_STATS_ALARM_WITHOUT_PULLS_COUNT = 2;
+const int FIELD_ID_PULLER_ALARM_STATS_ALARM_WITH_ERROR_COUNT = 3;
+
 // CounterStats counters
 const int FIELD_ID_COUNTER_STATS_COUNTER_TYPE = 1;
 const int FIELD_ID_COUNTER_STATS_COUNT = 2;
@@ -373,6 +379,22 @@ void StatsdStats::noteBatchSocketRead(int32_t size, int64_t lastReadTimeNs, int6
                                                 localAtomCounts);
     }
 }
+
+void StatsdStats::notePullerAlarmNoPull() {
+    lock_guard<std::mutex> lock(mLock);
+    mPullerAlarmStats.alarm_without_pulls_count++;
+}
+
+void StatsdStats::notePullerAlarmHasPull() {
+    lock_guard<std::mutex> lock(mLock);
+    mPullerAlarmStats.alarm_with_pulls_count++;
+}
+
+void StatsdStats::notePullerAlarmError() {
+    lock_guard<std::mutex> lock(mLock);
+    mPullerAlarmStats.alarm_with_puller_errors_count++;
+}
+
 void StatsdStats::noteBroadcastSent(const ConfigKey& key) {
     noteBroadcastSent(key, getWallClockSec());
 }
@@ -799,6 +821,10 @@ void StatsdStats::noteSystemServerRestart(int32_t timeSec) {
     mSystemServerRestartSec.push_back(timeSec);
 }
 
+bool StatsdStats::hasSystemServerRestart() {
+    return mSystemServerRestartSec.size() > 0;
+}
+
 void StatsdStats::notePullFailed(int atomId) {
     lock_guard<std::mutex> lock(mLock);
     mPulledAtomStats[atomId].pullFailed++;
@@ -1216,6 +1242,9 @@ void StatsdStats::resetInternalLocked() {
 
     mErrorStats.clear();
     mLoggingRateStats.reset();
+    mPullerAlarmStats.alarm_with_pulls_count = 0;
+    mPullerAlarmStats.alarm_without_pulls_count = 0;
+    mPullerAlarmStats.alarm_with_puller_errors_count = 0;
 }
 
 string buildTimeString(int64_t timeSec) {
@@ -1662,6 +1691,15 @@ void StatsdStats::dumpStats(int out) const {
         // TODO(b/343464656): add enum toString helper API
         dprintf(out, "IllegalState type %d: count=%d\n", errorType, count);
     }
+
+    if (flags::parallel_pulls()) {
+        dprintf(out, "********PullerAlarmStats********\n");
+        dprintf(out, "Alarms with pulls: %d\n", mPullerAlarmStats.alarm_with_pulls_count);
+        dprintf(out, "Alarms without pulls: %d\n", mPullerAlarmStats.alarm_without_pulls_count);
+        dprintf(out, "Alarms with puller errors: %d\n",
+                mPullerAlarmStats.alarm_with_puller_errors_count);
+    }
+
     dprintf(out, "\n");
     dprintf(out, "********Statsd Stats Id***********\n");
     dprintf(out, "Statsd Stats Id %d\n", mStatsdStatsId);
@@ -1690,6 +1728,26 @@ void addErrorStatsToProto(const std::map<CounterType, int32_t>& stats, ProtoOutp
     proto->end(token);
 }
 
+void addPullerAlarmStatsToProto(const PullerAlarmStats& pullerAlarmStats,
+                                ProtoOutputStream* proto) {
+    if (pullerAlarmStats.alarm_with_pulls_count == 0 &&
+        pullerAlarmStats.alarm_without_pulls_count == 0 &&
+        pullerAlarmStats.alarm_with_puller_errors_count == 0) {
+        return;
+    }
+
+    uint64_t token = proto->start(FIELD_TYPE_MESSAGE | FIELD_ID_PULLER_ALARM_STATS);
+
+    proto->write(FIELD_TYPE_INT32 | FIELD_ID_PULLER_ALARM_STATS_ALARM_WITH_PULLS_COUNT,
+                 pullerAlarmStats.alarm_with_pulls_count);
+    proto->write(FIELD_TYPE_INT32 | FIELD_ID_PULLER_ALARM_STATS_ALARM_WITHOUT_PULLS_COUNT,
+                 pullerAlarmStats.alarm_without_pulls_count);
+    proto->write(FIELD_TYPE_INT32 | FIELD_ID_PULLER_ALARM_STATS_ALARM_WITH_ERROR_COUNT,
+                 pullerAlarmStats.alarm_with_puller_errors_count);
+
+    proto->end(token);
+}
+
 void addConfigStatsToProto(const ConfigStats& configStats, ProtoOutputStream* proto) {
     uint64_t token =
             proto->start(FIELD_TYPE_MESSAGE | FIELD_COUNT_REPEATED | FIELD_ID_CONFIG_STATS);
@@ -2187,6 +2245,7 @@ void StatsdStats::dumpStats(vector<uint8_t>* output, bool reset) {
     proto.end(socketReadStatsToken);
 
     addErrorStatsToProto(mErrorStats, &proto);
+    addPullerAlarmStatsToProto(mPullerAlarmStats, &proto);
 
     output->clear();
     proto.serializeToVector(output);
diff --git a/statsd/src/guardrail/StatsdStats.h b/statsd/src/guardrail/StatsdStats.h
index 57c58e77..717cd894 100644
--- a/statsd/src/guardrail/StatsdStats.h
+++ b/statsd/src/guardrail/StatsdStats.h
@@ -169,6 +169,12 @@ struct SubscriptionStats {
     int32_t flush_count = 0;
 };
 
+struct PullerAlarmStats {
+    int32_t alarm_with_pulls_count = 0;
+    int32_t alarm_without_pulls_count = 0;
+    int32_t alarm_with_puller_errors_count = 0;
+};
+
 // Keeps track of stats of statsd.
 // Single instance shared across the process. All public methods are thread safe.
 class StatsdStats {
@@ -536,6 +542,11 @@ public:
      */
     void noteSystemServerRestart(int32_t timeSec);
 
+    /**
+     * Records whether a system server restart has occurred.
+     */
+    bool hasSystemServerRestart();
+
     /**
      * Records statsd skipped an event.
      */
@@ -738,6 +749,12 @@ public:
                              int64_t minAtomReadTimeNs, int64_t maxAtomReadTimeNs,
                              const std::unordered_map<int32_t, int32_t>& atomCounts);
 
+    void notePullerAlarmNoPull();
+
+    void notePullerAlarmHasPull();
+
+    void notePullerAlarmError();
+
     /**
      * Reset the historical stats. Including all stats in icebox, and the tracked stats about
      * metrics, matchers, and atoms. The active configs will be kept and StatsdStats will continue
@@ -856,6 +873,9 @@ private:
     // Track the number of dropped entries used by the uid map.
     UidMapStats mUidMapStats;
 
+    // Tracks the number of times a pulling alarm resulted in a pull.
+    PullerAlarmStats mPullerAlarmStats;
+
     // The stats about the configs that are still in use.
     // The map size is capped by kMaxConfigCount.
     std::map<const ConfigKey, std::shared_ptr<ConfigStats>> mConfigStats;
@@ -1094,6 +1114,7 @@ private:
     FRIEND_TEST(StatsPullerManagerTest, TestOnAlarmFiredNoPullerForUidNotesPullerNotFound);
     FRIEND_TEST(StatsPullerManagerTest, TestOnAlarmFiredNoUidProviderUpdatesNextPullTime);
     FRIEND_TEST(StatsPullerManagerTest, TestOnAlarmFiredUidsNotRegisteredInPullAtomCallback);
+    FRIEND_TEST(StatsPullerManagerTest, TestOnAlarmFiredNoPulls);
     FRIEND_TEST(StatsdStatsTest, TestActivationBroadcastGuardrailHit);
     FRIEND_TEST(StatsdStatsTest, TestAnomalyMonitor);
     FRIEND_TEST(StatsdStatsTest, TestAtomDroppedStats);
@@ -1134,6 +1155,8 @@ private:
     FRIEND_TEST(StatsdStatsTest, TestLoggingRateReport);
     FRIEND_TEST(StatsdStatsTest, TestLoggingRateReportOnlyTopN);
     FRIEND_TEST(StatsdStatsTest, TestLoggingRateReportReset);
+    FRIEND_TEST(StatsdStatsTest, TestPullerAlarmStatsReport);
+    FRIEND_TEST(StatsdStatsTest, TestPullerAlarmStatsReset);
 };
 
 InvalidConfigReason createInvalidConfigReasonWithMatcher(const InvalidConfigReasonEnum reason,
diff --git a/statsd/src/guardrail/stats_log_enums.proto b/statsd/src/guardrail/stats_log_enums.proto
index 2019c277..40fc884c 100644
--- a/statsd/src/guardrail/stats_log_enums.proto
+++ b/statsd/src/guardrail/stats_log_enums.proto
@@ -41,6 +41,7 @@ enum DataCorruptedReason {
     DATA_CORRUPTED_UNKNOWN = 0;
     DATA_CORRUPTED_EVENT_QUEUE_OVERFLOW = 1;
     DATA_CORRUPTED_SOCKET_LOSS = 2;
+    DATA_CORRUPTED_SYSTEM_SERVER_CRASH = 3;
 };
 
 enum DumpReportReason {
@@ -182,4 +183,6 @@ enum InvalidQueryReason {
 enum CounterType {
     COUNTER_TYPE_UNKNOWN = 0;
     COUNTER_TYPE_ERROR_ATOM_FILTER_SKIPPED = 1;
+    COUNTER_TYPE_ERROR_STOP_IOURING_LISTENER_SYNC_LISTENER_NULLPTR = 2;
+    COUNTER_TYPE_ERROR_STOP_IOURING_LISTENER_LIBURINGUTIL_NULLPTR = 3;
 };
diff --git a/statsd/src/logd/LogEvent.cpp b/statsd/src/logd/LogEvent.cpp
index d51499b0..c35685bc 100644
--- a/statsd/src/logd/LogEvent.cpp
+++ b/statsd/src/logd/LogEvent.cpp
@@ -53,6 +53,17 @@ uint8_t getNumAnnotations(uint8_t typeInfo) {
 
 }  // namespace
 
+std::string InstallTrainInfo::experimentIdsToString(const std::vector<int64_t>& experimentIds) {
+    std::string str;
+    for (size_t i = 0; i < experimentIds.size(); i++) {
+        str += std::to_string(experimentIds[i]);
+        if (i != experimentIds.size() - 1) {
+            str += ",";
+        }
+    }
+    return str;
+}
+
 LogEvent::LogEvent(int32_t uid, int32_t pid)
     : mLogdTimestampNs(getWallClockNs()), mLogUid(uid), mLogPid(pid) {
 }
@@ -621,9 +632,9 @@ int64_t LogEvent::GetLong(size_t key, status_t* err) const {
     for (const auto& value : mValues) {
         if (value.mField.getField() == field) {
             if (value.mValue.getType() == LONG) {
-                return value.mValue.long_value;
+                return value.mValue.get<int64_t>();
             } else if (value.mValue.getType() == INT) {
-                return value.mValue.int_value;
+                return value.mValue.get<int32_t>();
             } else {
                 *err = BAD_TYPE;
                 return 0;
@@ -643,7 +654,7 @@ int LogEvent::GetInt(size_t key, status_t* err) const {
     for (const auto& value : mValues) {
         if (value.mField.getField() == field) {
             if (value.mValue.getType() == INT) {
-                return value.mValue.int_value;
+                return value.mValue.get<int32_t>();
             } else {
                 *err = BAD_TYPE;
                 return 0;
@@ -663,7 +674,7 @@ const char* LogEvent::GetString(size_t key, status_t* err) const {
     for (const auto& value : mValues) {
         if (value.mField.getField() == field) {
             if (value.mValue.getType() == STRING) {
-                return value.mValue.str_value.c_str();
+                return value.mValue.get<string>().c_str();
             } else {
                 *err = BAD_TYPE;
                 return 0;
@@ -683,9 +694,9 @@ bool LogEvent::GetBool(size_t key, status_t* err) const {
     for (const auto& value : mValues) {
         if (value.mField.getField() == field) {
             if (value.mValue.getType() == INT) {
-                return value.mValue.int_value != 0;
+                return value.mValue.get<int32_t>() != 0;
             } else if (value.mValue.getType() == LONG) {
-                return value.mValue.long_value != 0;
+                return value.mValue.get<int64_t>() != 0;
             } else {
                 *err = BAD_TYPE;
                 return false;
@@ -705,7 +716,7 @@ float LogEvent::GetFloat(size_t key, status_t* err) const {
     for (const auto& value : mValues) {
         if (value.mField.getField() == field) {
             if (value.mValue.getType() == FLOAT) {
-                return value.mValue.float_value;
+                return value.mValue.get<float>();
             } else {
                 *err = BAD_TYPE;
                 return 0.0;
@@ -725,7 +736,7 @@ std::vector<uint8_t> LogEvent::GetStorage(size_t key, status_t* err) const {
     for (const auto& value : mValues) {
         if (value.mField.getField() == field) {
             if (value.mValue.getType() == STORAGE) {
-                return value.mValue.storage_value;
+                return value.mValue.get<vector<uint8_t>>();
             } else {
                 *err = BAD_TYPE;
                 return vector<uint8_t>();
diff --git a/statsd/src/logd/LogEvent.h b/statsd/src/logd/LogEvent.h
index 96d81e27..d36eb9ee 100644
--- a/statsd/src/logd/LogEvent.h
+++ b/statsd/src/logd/LogEvent.h
@@ -68,6 +68,8 @@ struct InstallTrainInfo {
     bool requiresStaging;
     bool rollbackEnabled;
     bool requiresLowLatencyMonitor;
+
+    static std::string experimentIdsToString(const std::vector<int64_t>& experimentIds);
 };
 
 /**
diff --git a/statsd/src/logd/logevent_util.cpp b/statsd/src/logd/logevent_util.cpp
index 77005451..af886cc7 100644
--- a/statsd/src/logd/logevent_util.cpp
+++ b/statsd/src/logd/logevent_util.cpp
@@ -35,7 +35,7 @@ std::optional<SocketLossInfo> toSocketLossInfo(const LogEvent& event) {
     result.uid = event.GetUid();
     if (logEventValues[1].mField.getPosAtDepth(0) == 2 &&
         logEventValues[1].mValue.getType() == LONG) {
-        result.firstLossTsNanos = logEventValues[1].mValue.long_value;
+        result.firstLossTsNanos = logEventValues[1].mValue.get<int64_t>();
     } else {
         // atom content is invalid
         return std::nullopt;
@@ -43,7 +43,7 @@ std::optional<SocketLossInfo> toSocketLossInfo(const LogEvent& event) {
 
     if (logEventValues[2].mField.getPosAtDepth(0) == 3 &&
         logEventValues[2].mValue.getType() == LONG) {
-        result.lastLossTsNanos = logEventValues[2].mValue.long_value;
+        result.lastLossTsNanos = logEventValues[2].mValue.get<int64_t>();
     } else {
         // atom content is invalid
         return std::nullopt;
@@ -51,7 +51,7 @@ std::optional<SocketLossInfo> toSocketLossInfo(const LogEvent& event) {
 
     if (logEventValues[3].mField.getPosAtDepth(0) == 4 &&
         logEventValues[3].mValue.getType() == INT) {
-        result.overflowCounter = logEventValues[3].mValue.int_value;
+        result.overflowCounter = logEventValues[3].mValue.get<int32_t>();
     } else {
         // atom content is invalid
         return std::nullopt;
@@ -72,7 +72,7 @@ std::optional<SocketLossInfo> toSocketLossInfo(const LogEvent& event) {
     std::vector<FieldValue>::const_iterator valuesIt = logEventValues.begin() + arraysOffset;
     while (valuesIt != logEventValues.end() && valuesIt->mField.getPosAtDepth(0) == 5 &&
            valuesIt->mValue.getType() == INT) {
-        result.errors.push_back(valuesIt->mValue.int_value);
+        result.errors.push_back(valuesIt->mValue.get<int32_t>());
         valuesIt++;
     }
     if (result.errors.size() != expectedEntriesCount) {
@@ -82,7 +82,7 @@ std::optional<SocketLossInfo> toSocketLossInfo(const LogEvent& event) {
 
     while (valuesIt != logEventValues.end() && valuesIt->mField.getPosAtDepth(0) == 6 &&
            valuesIt->mValue.getType() == INT) {
-        result.atomIds.push_back(valuesIt->mValue.int_value);
+        result.atomIds.push_back(valuesIt->mValue.get<int32_t>());
         valuesIt++;
     }
     if (result.atomIds.size() != expectedEntriesCount) {
@@ -92,7 +92,7 @@ std::optional<SocketLossInfo> toSocketLossInfo(const LogEvent& event) {
 
     while (valuesIt != logEventValues.end() && valuesIt->mField.getPosAtDepth(0) == 7 &&
            valuesIt->mValue.getType() == INT) {
-        result.counts.push_back(valuesIt->mValue.int_value);
+        result.counts.push_back(valuesIt->mValue.get<int32_t>());
         valuesIt++;
     }
     if (result.counts.size() != expectedEntriesCount) {
diff --git a/statsd/src/main.cpp b/statsd/src/main.cpp
index 691e90eb..b42414a4 100644
--- a/statsd/src/main.cpp
+++ b/statsd/src/main.cpp
@@ -17,11 +17,13 @@
 #define STATSD_DEBUG false  // STOPSHIP if true
 #include "Log.h"
 
+#include <IOUringSocketHandler/IOUringSocketHandler.h>
 #include <android/binder_ibinder.h>
 #include <android/binder_ibinder_platform.h>
 #include <android/binder_interface_utils.h>
 #include <android/binder_manager.h>
 #include <android/binder_process.h>
+#include <com_android_os_statsd_flags.h>
 #include <stdio.h>
 #include <sys/random.h>
 #include <sys/stat.h>
@@ -33,6 +35,9 @@
 #include "flags/FlagProvider.h"
 #include "packages/UidMap.h"
 #include "socket/StatsSocketListener.h"
+#include "socket/StatsSocketListenerIoUring.h"
+
+namespace flags = com::android::os::statsd::flags;
 
 using namespace android;
 using namespace android::os::statsd;
@@ -41,7 +46,7 @@ using std::shared_ptr;
 using std::make_shared;
 
 shared_ptr<StatsService> gStatsService = nullptr;
-sp<StatsSocketListener> gSocketListener = nullptr;
+sp<BaseStatsSocketListener> gSocketListener = nullptr;
 int gCtrlPipe[2];
 
 void signalHandler(int sig) {
@@ -102,13 +107,15 @@ int main(int /*argc*/, char** /*argv*/) {
     // Start reading events from the socket as early as possible.
     // Processing from the queue is delayed until StatsService::startup to allow
     // config initialization to occur before we start processing atoms.
-    gSocketListener = new StatsSocketListener(eventQueue, logEventFilter);
+    if (flags::use_iouring() && IOUringSocketHandler::IsIouringSupported()) {
+        gSocketListener = new StatsSocketListenerIoUring(eventQueue, logEventFilter);
+    } else {
+        gSocketListener = new StatsSocketListener(eventQueue, logEventFilter);
+    }
 
     ALOGI("Statsd starts to listen to socket.");
     // Backlog and /proc/sys/net/unix/max_dgram_qlen set to large value
-    if (gSocketListener->startListener(600)) {
-        exit(1);
-    }
+    gSocketListener->startListener();
 
     // Create the service
     gStatsService = SharedRefBase::make<StatsService>(uidMap, eventQueue, logEventFilter);
diff --git a/statsd/src/matchers/matcher_util.cpp b/statsd/src/matchers/matcher_util.cpp
index 2f7ec810..552d551b 100644
--- a/statsd/src/matchers/matcher_util.cpp
+++ b/statsd/src/matchers/matcher_util.cpp
@@ -89,14 +89,14 @@ bool combinationMatch(const vector<int>& children, const LogicalOperation& opera
 static bool tryMatchString(const sp<UidMap>& uidMap, const FieldValue& fieldValue,
                            const string& str_match) {
     if (isAttributionUidField(fieldValue) || isUidField(fieldValue)) {
-        int uid = fieldValue.mValue.int_value;
+        int uid = fieldValue.mValue.get<int32_t>();
         auto aidIt = UidMap::sAidToUidMapping.find(str_match);
         if (aidIt != UidMap::sAidToUidMapping.end()) {
             return ((int)aidIt->second) == uid;
         }
         return uidMap->hasApp(uid, str_match);
     } else if (fieldValue.mValue.getType() == STRING) {
-        return fieldValue.mValue.str_value == str_match;
+        return fieldValue.mValue.get<string>() == str_match;
     }
     return false;
 }
@@ -104,7 +104,7 @@ static bool tryMatchString(const sp<UidMap>& uidMap, const FieldValue& fieldValu
 static bool tryMatchWildcardString(const sp<UidMap>& uidMap, const FieldValue& fieldValue,
                                    const string& wildcardPattern) {
     if (isAttributionUidField(fieldValue) || isUidField(fieldValue)) {
-        int uid = fieldValue.mValue.int_value;
+        int uid = fieldValue.mValue.get<int32_t>();
         // TODO(b/236886985): replace aid/uid mapping with efficient bidirectional container
         // AidToUidMapping will never have uids above 10000
         if (uid < 10000) {
@@ -123,7 +123,7 @@ static bool tryMatchWildcardString(const sp<UidMap>& uidMap, const FieldValue& f
             }
         }
     } else if (fieldValue.mValue.getType() == STRING) {
-        return fnmatch(wildcardPattern.c_str(), fieldValue.mValue.str_value.c_str(), 0) == 0;
+        return fnmatch(wildcardPattern.c_str(), fieldValue.mValue.get<string>().c_str(), 0) == 0;
     }
     return false;
 }
@@ -148,8 +148,8 @@ static unique_ptr<LogEvent> getTransformedEvent(const FieldValueMatcher& matcher
         if (fieldValue.mValue.getType() != STRING) {
             continue;
         }
-        string str = fieldValue.mValue.str_value;
-        if (!re->replace(str, replacement) || str == fieldValue.mValue.str_value) {
+        string str = fieldValue.mValue.get<string>();
+        if (!re->replace(str, replacement) || str == fieldValue.mValue.get<string>()) {
             continue;
         }
 
@@ -157,7 +157,7 @@ static unique_ptr<LogEvent> getTransformedEvent(const FieldValueMatcher& matcher
         if (transformedEvent == nullptr) {
             transformedEvent = std::make_unique<LogEvent>(event);
         }
-        (*transformedEvent->getMutableValues())[i].mValue.str_value = str;
+        (*transformedEvent->getMutableValues())[i].mValue.get<string>() = str;
     }
     return transformedEvent;
 }
@@ -340,9 +340,9 @@ static MatchResult matchesSimple(const sp<UidMap>& uidMap, const FieldValueMatch
         case FieldValueMatcher::ValueMatcherCase::kEqBool: {
             for (int i = start; i < end; i++) {
                 if ((values[i].mValue.getType() == INT &&
-                     (values[i].mValue.int_value != 0) == matcher.eq_bool()) ||
+                     (values[i].mValue.get<int32_t>() != 0) == matcher.eq_bool()) ||
                     (values[i].mValue.getType() == LONG &&
-                     (values[i].mValue.long_value != 0) == matcher.eq_bool())) {
+                     (values[i].mValue.get<int64_t>() != 0) == matcher.eq_bool())) {
                     return {true, std::move(transformedEvent)};
                 }
             }
@@ -421,12 +421,12 @@ static MatchResult matchesSimple(const sp<UidMap>& uidMap, const FieldValueMatch
         case FieldValueMatcher::ValueMatcherCase::kEqInt: {
             for (int i = start; i < end; i++) {
                 if (values[i].mValue.getType() == INT &&
-                    (matcher.eq_int() == values[i].mValue.int_value)) {
+                    (matcher.eq_int() == values[i].mValue.get<int32_t>())) {
                     return {true, std::move(transformedEvent)};
                 }
                 // eq_int covers both int and long.
                 if (values[i].mValue.getType() == LONG &&
-                    (matcher.eq_int() == values[i].mValue.long_value)) {
+                    (matcher.eq_int() == values[i].mValue.get<int64_t>())) {
                     return {true, std::move(transformedEvent)};
                 }
             }
@@ -437,12 +437,12 @@ static MatchResult matchesSimple(const sp<UidMap>& uidMap, const FieldValueMatch
             for (int i = start; i < end; i++) {
                 for (const int int_value : int_list.int_value()) {
                     if (values[i].mValue.getType() == INT &&
-                        (int_value == values[i].mValue.int_value)) {
+                        (int_value == values[i].mValue.get<int32_t>())) {
                         return {true, std::move(transformedEvent)};
                     }
                     // eq_any_int covers both int and long.
                     if (values[i].mValue.getType() == LONG &&
-                        (int_value == values[i].mValue.long_value)) {
+                        (int_value == values[i].mValue.get<int64_t>())) {
                         return {true, std::move(transformedEvent)};
                     }
                 }
@@ -455,13 +455,13 @@ static MatchResult matchesSimple(const sp<UidMap>& uidMap, const FieldValueMatch
                 bool notEqAll = true;
                 for (const int int_value : int_list.int_value()) {
                     if (values[i].mValue.getType() == INT &&
-                        (int_value == values[i].mValue.int_value)) {
+                        (int_value == values[i].mValue.get<int32_t>())) {
                         notEqAll = false;
                         break;
                     }
                     // neq_any_int covers both int and long.
                     if (values[i].mValue.getType() == LONG &&
-                        (int_value == values[i].mValue.long_value)) {
+                        (int_value == values[i].mValue.get<int64_t>())) {
                         notEqAll = false;
                         break;
                     }
@@ -475,12 +475,12 @@ static MatchResult matchesSimple(const sp<UidMap>& uidMap, const FieldValueMatch
         case FieldValueMatcher::ValueMatcherCase::kLtInt: {
             for (int i = start; i < end; i++) {
                 if (values[i].mValue.getType() == INT &&
-                    (values[i].mValue.int_value < matcher.lt_int())) {
+                    (values[i].mValue.get<int32_t>() < matcher.lt_int())) {
                     return {true, std::move(transformedEvent)};
                 }
                 // lt_int covers both int and long.
                 if (values[i].mValue.getType() == LONG &&
-                    (values[i].mValue.long_value < matcher.lt_int())) {
+                    (values[i].mValue.get<int64_t>() < matcher.lt_int())) {
                     return {true, std::move(transformedEvent)};
                 }
             }
@@ -489,12 +489,12 @@ static MatchResult matchesSimple(const sp<UidMap>& uidMap, const FieldValueMatch
         case FieldValueMatcher::ValueMatcherCase::kGtInt: {
             for (int i = start; i < end; i++) {
                 if (values[i].mValue.getType() == INT &&
-                    (values[i].mValue.int_value > matcher.gt_int())) {
+                    (values[i].mValue.get<int32_t>() > matcher.gt_int())) {
                     return {true, std::move(transformedEvent)};
                 }
                 // gt_int covers both int and long.
                 if (values[i].mValue.getType() == LONG &&
-                    (values[i].mValue.long_value > matcher.gt_int())) {
+                    (values[i].mValue.get<int64_t>() > matcher.gt_int())) {
                     return {true, std::move(transformedEvent)};
                 }
             }
@@ -503,7 +503,7 @@ static MatchResult matchesSimple(const sp<UidMap>& uidMap, const FieldValueMatch
         case FieldValueMatcher::ValueMatcherCase::kLtFloat: {
             for (int i = start; i < end; i++) {
                 if (values[i].mValue.getType() == FLOAT &&
-                    (values[i].mValue.float_value < matcher.lt_float())) {
+                    (values[i].mValue.get<float>() < matcher.lt_float())) {
                     return {true, std::move(transformedEvent)};
                 }
             }
@@ -512,7 +512,7 @@ static MatchResult matchesSimple(const sp<UidMap>& uidMap, const FieldValueMatch
         case FieldValueMatcher::ValueMatcherCase::kGtFloat: {
             for (int i = start; i < end; i++) {
                 if (values[i].mValue.getType() == FLOAT &&
-                    (values[i].mValue.float_value > matcher.gt_float())) {
+                    (values[i].mValue.get<float>() > matcher.gt_float())) {
                     return {true, std::move(transformedEvent)};
                 }
             }
@@ -521,12 +521,12 @@ static MatchResult matchesSimple(const sp<UidMap>& uidMap, const FieldValueMatch
         case FieldValueMatcher::ValueMatcherCase::kLteInt: {
             for (int i = start; i < end; i++) {
                 if (values[i].mValue.getType() == INT &&
-                    (values[i].mValue.int_value <= matcher.lte_int())) {
+                    (values[i].mValue.get<int32_t>() <= matcher.lte_int())) {
                     return {true, std::move(transformedEvent)};
                 }
                 // lte_int covers both int and long.
                 if (values[i].mValue.getType() == LONG &&
-                    (values[i].mValue.long_value <= matcher.lte_int())) {
+                    (values[i].mValue.get<int64_t>() <= matcher.lte_int())) {
                     return {true, std::move(transformedEvent)};
                 }
             }
@@ -535,12 +535,12 @@ static MatchResult matchesSimple(const sp<UidMap>& uidMap, const FieldValueMatch
         case FieldValueMatcher::ValueMatcherCase::kGteInt: {
             for (int i = start; i < end; i++) {
                 if (values[i].mValue.getType() == INT &&
-                    (values[i].mValue.int_value >= matcher.gte_int())) {
+                    (values[i].mValue.get<int32_t>() >= matcher.gte_int())) {
                     return {true, std::move(transformedEvent)};
                 }
                 // gte_int covers both int and long.
                 if (values[i].mValue.getType() == LONG &&
-                    (values[i].mValue.long_value >= matcher.gte_int())) {
+                    (values[i].mValue.get<int64_t>() >= matcher.gte_int())) {
                     return {true, std::move(transformedEvent)};
                 }
             }
diff --git a/statsd/src/metadata_util.cpp b/statsd/src/metadata_util.cpp
index 27ee59b3..0075a582 100644
--- a/statsd/src/metadata_util.cpp
+++ b/statsd/src/metadata_util.cpp
@@ -27,22 +27,22 @@ void writeValueToProto(metadata::FieldValue* metadataFieldValue, const Value& va
     std::string storage_value;
     switch (value.getType()) {
         case INT:
-            metadataFieldValue->set_value_int(value.int_value);
+            metadataFieldValue->set_value_int(value.get<int32_t>());
             break;
         case LONG:
-            metadataFieldValue->set_value_long(value.long_value);
+            metadataFieldValue->set_value_long(value.get<int64_t>());
             break;
         case FLOAT:
-            metadataFieldValue->set_value_float(value.float_value);
+            metadataFieldValue->set_value_float(value.get<float>());
             break;
         case DOUBLE:
-            metadataFieldValue->set_value_double(value.double_value);
+            metadataFieldValue->set_value_double(value.get<double>());
             break;
         case STRING:
-            metadataFieldValue->set_value_str(value.str_value.c_str());
+            metadataFieldValue->set_value_str(value.get<std::string>().c_str());
             break;
         case STORAGE: // byte array
-            storage_value = ((char*) value.storage_value.data());
+            storage_value = ((char*)value.get<std::vector<uint8_t>>().data());
             metadataFieldValue->set_value_storage(storage_value);
             break;
         default:
diff --git a/statsd/src/metrics/CountMetricProducer.cpp b/statsd/src/metrics/CountMetricProducer.cpp
index b5e5f92b..9995f10d 100644
--- a/statsd/src/metrics/CountMetricProducer.cpp
+++ b/statsd/src/metrics/CountMetricProducer.cpp
@@ -189,7 +189,7 @@ void CountMetricProducer::onStateChanged(const int64_t eventTimeNs, const int32_
                                          const FieldValue& oldState, const FieldValue& newState) {
     VLOG("CountMetric %lld onStateChanged time %lld, State%d, key %s, %d -> %d",
          (long long)mMetricId, (long long)eventTimeNs, atomId, primaryKey.toString().c_str(),
-         oldState.mValue.int_value, newState.mValue.int_value);
+         oldState.mValue.get<int32_t>(), newState.mValue.get<int32_t>());
 }
 
 void CountMetricProducer::dumpStatesLocked(int out, bool verbose) const {
diff --git a/statsd/src/metrics/EventMetricProducer.cpp b/statsd/src/metrics/EventMetricProducer.cpp
index beb52362..49cb4bab 100644
--- a/statsd/src/metrics/EventMetricProducer.cpp
+++ b/statsd/src/metrics/EventMetricProducer.cpp
@@ -277,7 +277,7 @@ void EventMetricProducer::onStateChanged(const int64_t eventTimeNs, const int32_
                                          const FieldValue& oldState, const FieldValue& newState) {
     VLOG("EventMetric %lld onStateChanged time %lld, State%d, key %s, %d -> %d",
          (long long)mMetricId, (long long)eventTimeNs, atomId, primaryKey.toString().c_str(),
-         oldState.mValue.int_value, newState.mValue.int_value);
+         oldState.mValue.get<int32_t>(), newState.mValue.get<int32_t>());
 }
 
 void EventMetricProducer::onMatchedLogEventInternalLocked(
@@ -295,7 +295,10 @@ void EventMetricProducer::onMatchedLogEventInternalLocked(
     const int64_t elapsedTimeNs = truncateTimestampIfNecessary(event);
     AtomDimensionKey key(
             event.GetTagId(),
-            HashableDimensionKey(filterValues(mFieldMatchers, event.getValues(), mOmitFields)));
+            HashableDimensionKey(
+                    mFieldMatchers.empty()
+                            ? event.getValues()
+                            : filterValues(mFieldMatchers, event.getValues(), mOmitFields)));
     // TODO(b/383929503): Optimize slice_by_state performance
     if (!mAggregatedAtoms.contains(key) && !mAggAtomsAndStates.contains(key)) {
         sp<ConfigMetadataProvider> provider = getConfigMetadataProvider();
diff --git a/statsd/src/metrics/GaugeMetricProducer.cpp b/statsd/src/metrics/GaugeMetricProducer.cpp
index c9f81cc2..20d9fcbc 100644
--- a/statsd/src/metrics/GaugeMetricProducer.cpp
+++ b/statsd/src/metrics/GaugeMetricProducer.cpp
@@ -239,7 +239,7 @@ void GaugeMetricProducer::onStateChanged(const int64_t eventTimeNs, const int32_
                                          const FieldValue& oldState, const FieldValue& newState) {
     VLOG("GaugeMetric %lld onStateChanged time %lld, State%d, key %s, %d -> %d",
          (long long)mMetricId, (long long)eventTimeNs, atomId, primaryKey.toString().c_str(),
-         oldState.mValue.int_value, newState.mValue.int_value);
+         oldState.mValue.get<int32_t>(), newState.mValue.get<int32_t>());
 }
 
 void GaugeMetricProducer::dumpStatesLocked(int out, bool verbose) const {
@@ -514,7 +514,9 @@ void GaugeMetricProducer::onSlicedConditionMayChangeLocked(bool overallCondition
 }
 
 vector<FieldValue> GaugeMetricProducer::getGaugeFields(const LogEvent& event) {
-    vector<FieldValue> gaugeFields = filterValues(mFieldMatchers, event.getValues(), mOmitFields);
+    vector<FieldValue> gaugeFields =
+            mFieldMatchers.empty() ? event.getValues()
+                                   : filterValues(mFieldMatchers, event.getValues(), mOmitFields);
 
     // Trim all dimension fields from output. Dimensions will appear in output report and will
     // benefit from dictionary encoding. For large pulled atoms, this can give the benefit of
@@ -621,7 +623,9 @@ void GaugeMetricProducer::onMatchedLogEventInternalLocked(
     }
 
     const int64_t truncatedElapsedTimestampNs = truncateTimestampIfNecessary(event);
-    GaugeAtom gaugeAtom(getGaugeFields(event), truncatedElapsedTimestampNs);
+    GaugeAtom gaugeAtom(mFieldMatchers.empty() && mDimensionsInWhat.empty() ? event.getValues()
+                                                                            : getGaugeFields(event),
+                        truncatedElapsedTimestampNs);
     (*mCurrentSlicedBucket)[eventKey].push_back(gaugeAtom);
     // Anomaly detection on gauge metric only works when there is one numeric
     // field specified.
@@ -630,9 +634,9 @@ void GaugeMetricProducer::onMatchedLogEventInternalLocked(
             const Value& value = gaugeAtom.mFields.begin()->mValue;
             long gaugeVal = 0;
             if (value.getType() == INT) {
-                gaugeVal = (long)value.int_value;
+                gaugeVal = (long)value.get<int32_t>();
             } else if (value.getType() == LONG) {
-                gaugeVal = value.long_value;
+                gaugeVal = value.get<int64_t>();
             }
             for (auto& tracker : mAnomalyTrackers) {
                 tracker->detectAndDeclareAnomaly(eventTimeNs, mCurrentBucketNum, mMetricId,
@@ -650,9 +654,9 @@ void GaugeMetricProducer::updateCurrentSlicedBucketForAnomaly() {
         const Value& value = slice.second.front().mFields.front().mValue;
         long gaugeVal = 0;
         if (value.getType() == INT) {
-            gaugeVal = (long)value.int_value;
+            gaugeVal = (long)value.get<int32_t>();
         } else if (value.getType() == LONG) {
-            gaugeVal = value.long_value;
+            gaugeVal = value.get<int64_t>();
         }
         (*mCurrentSlicedBucketForAnomaly)[slice.first] = gaugeVal;
     }
diff --git a/statsd/src/metrics/GaugeMetricProducer.h b/statsd/src/metrics/GaugeMetricProducer.h
index 9408785c..42690d8c 100644
--- a/statsd/src/metrics/GaugeMetricProducer.h
+++ b/statsd/src/metrics/GaugeMetricProducer.h
@@ -34,7 +34,7 @@ namespace os {
 namespace statsd {
 
 struct GaugeAtom {
-    GaugeAtom(std::vector<FieldValue> fields, int64_t elapsedTimeNs)
+    GaugeAtom(const std::vector<FieldValue>& fields, int64_t elapsedTimeNs)
         : mFields(fields), mElapsedTimestampNs(elapsedTimeNs) {
     }
     std::vector<FieldValue> mFields;
diff --git a/statsd/src/metrics/KllMetricProducer.cpp b/statsd/src/metrics/KllMetricProducer.cpp
index e2814cb5..05526087 100644
--- a/statsd/src/metrics/KllMetricProducer.cpp
+++ b/statsd/src/metrics/KllMetricProducer.cpp
@@ -95,11 +95,11 @@ void KllMetricProducer::writePastBucketAggregateToProto(
 optional<int64_t> getInt64ValueFromEvent(const LogEvent& event, const Matcher& matcher) {
     for (const FieldValue& value : event.getValues()) {
         if (value.mField.matches(matcher)) {
-            switch (value.mValue.type) {
+            switch (value.mValue.getType()) {
                 case INT:
-                    return {value.mValue.int_value};
+                    return {value.mValue.get<int32_t>()};
                 case LONG:
-                    return {value.mValue.long_value};
+                    return {value.mValue.get<int64_t>()};
                 default:
                     return nullopt;
             }
diff --git a/statsd/src/metrics/MetricProducer.cpp b/statsd/src/metrics/MetricProducer.cpp
index a72c68de..ecc84608 100644
--- a/statsd/src/metrics/MetricProducer.cpp
+++ b/statsd/src/metrics/MetricProducer.cpp
@@ -366,15 +366,15 @@ void MetricProducer::mapStateValue(int32_t atomId, FieldValue* value) {
     if (atomIt == mStateGroupMap.end()) {
         return;
     }
-    auto valueIt = atomIt->second.find(value->mValue.int_value);
+    auto valueIt = atomIt->second.find(value->mValue.get<int32_t>());
     if (valueIt == atomIt->second.end()) {
         // state map exists, but value was not put in a state group
         // so set mValue to kStateUnknown
         // TODO(tsaichristine): handle incomplete state maps
-        value->mValue.setInt(StateTracker::kStateUnknown);
+        value->mValue.set(StateTracker::kStateUnknown);
     } else {
         // set mValue to group_id
-        value->mValue.setLong(valueIt->second);
+        value->mValue.set(valueIt->second);
     }
 }
 
@@ -383,7 +383,7 @@ HashableDimensionKey MetricProducer::getUnknownStateKey() {
     for (auto atom : mSlicedStateAtoms) {
         FieldValue fieldValue;
         fieldValue.mField.setTag(atom);
-        fieldValue.mValue.setInt(StateTracker::kStateUnknown);
+        fieldValue.mValue.set(StateTracker::kStateUnknown);
         stateKey.addValue(fieldValue);
     }
     return stateKey;
diff --git a/statsd/src/metrics/MetricProducer.h b/statsd/src/metrics/MetricProducer.h
index d7b2a36a..d164da83 100644
--- a/statsd/src/metrics/MetricProducer.h
+++ b/statsd/src/metrics/MetricProducer.h
@@ -646,8 +646,6 @@ protected:
     FRIEND_TEST(CountMetricE2eTest, TestSlicedStateWithPrimaryFields);
     FRIEND_TEST(CountMetricE2eTest, TestInitialConditionChanges);
 
-    FRIEND_TEST(DurationMetricE2eTest, TestOneBucket);
-    FRIEND_TEST(DurationMetricE2eTest, TestTwoBuckets);
     FRIEND_TEST(DurationMetricE2eTest, TestWithActivation);
     FRIEND_TEST(DurationMetricE2eTest, TestWithCondition);
     FRIEND_TEST(DurationMetricE2eTest, TestWithSlicedCondition);
@@ -655,9 +653,7 @@ protected:
     FRIEND_TEST(DurationMetricE2eTest, TestWithSlicedState);
     FRIEND_TEST(DurationMetricE2eTest, TestWithConditionAndSlicedState);
     FRIEND_TEST(DurationMetricE2eTest, TestWithSlicedStateMapped);
-    FRIEND_TEST(DurationMetricE2eTest, TestSlicedStatePrimaryFieldsNotSubsetDimInWhat);
     FRIEND_TEST(DurationMetricE2eTest, TestWithSlicedStatePrimaryFieldsSubset);
-    FRIEND_TEST(DurationMetricE2eTest, TestUploadThreshold);
 
     FRIEND_TEST(EventMetricE2eTest, TestSlicedState);
 
diff --git a/statsd/src/metrics/NumericValueMetricProducer.cpp b/statsd/src/metrics/NumericValueMetricProducer.cpp
index c12cf69b..ac287a2a 100644
--- a/statsd/src/metrics/NumericValueMetricProducer.cpp
+++ b/statsd/src/metrics/NumericValueMetricProducer.cpp
@@ -19,6 +19,7 @@
 
 #include "NumericValueMetricProducer.h"
 
+#include <com_android_os_statsd_flags.h>
 #include <stdlib.h>
 
 #include <algorithm>
@@ -46,6 +47,8 @@ namespace android {
 namespace os {
 namespace statsd {
 
+namespace flags = com::android::os::statsd::flags;
+
 namespace {  // anonymous namespace
 // for StatsLogReport
 const int FIELD_ID_VALUE_METRICS = 7;
@@ -92,6 +95,7 @@ NumericValueMetricProducer::NumericValueMetricProducer(
       mSkipZeroDiffOutput(metric.skip_zero_diff_output()),
       mUseZeroDefaultBase(metric.use_zero_default_base()),
       mHasGlobalBase(false),
+      mDropBucketOnDimensionHardLimitExceeded(metric.drop_bucket_on_max_dimensions_exceeded()),
       mMaxPullDelayNs(metric.has_max_pull_delay_sec() ? metric.max_pull_delay_sec() * NS_PER_SEC
                                                       : StatsdStats::kPullMaxDelayNs),
       mDedupedFieldMatchers(dedupFieldMatchers(whatOptions.fieldMatchers)),
@@ -288,7 +292,7 @@ void NumericValueMetricProducer::accumulateEvents(const vector<shared_ptr<LogEve
     if (mUseDiff) {
         // An extra aggregation step is needed to sum values with matching dimensions
         // before calculating the diff between sums of consecutive pulls.
-        std::unordered_map<HashableDimensionKey, pair<LogEvent, vector<int>>> aggregateEvents;
+        std::map<HashableDimensionKey, pair<LogEvent, vector<int>>> aggregateEvents;
         for (const auto& data : allData) {
             const auto [matchResult, transformedEvent] =
                     mEventMatcherWizard->matchLogEvent(*data, mWhatMatcherIndex);
@@ -355,15 +359,32 @@ void NumericValueMetricProducer::accumulateEvents(const vector<shared_ptr<LogEve
     mMatchedMetricDimensionKeys.clear();
     mHasGlobalBase = true;
 
-    // If we reach the guardrail, we might have dropped some data which means the bucket is
-    // incomplete.
-    //
-    // The base also needs to be reset. If we do not have the full data, we might
-    // incorrectly compute the diff when mUseZeroDefaultBase is true since an existing key
-    // might be missing from mCurrentSlicedBucket.
-    if (hasReachedGuardRailLimit()) {
-        invalidateCurrentBucket(eventElapsedTimeNs, BucketDropReason::DIMENSION_GUARDRAIL_REACHED);
-        mCurrentSlicedBucket.clear();
+    if (mHasHitGuardrail) {
+        if (flags::keep_value_metric_max_dimension_bucket()) {
+            // If we reach the guardrail, we might have dropped some data which means the bucket is
+            // incomplete. Drop this bucket if mDropBucketOnDimensionHardLimitExceeded is true and
+            // reset the base. If the bucket is not dropped, we might incorrectly compute the diff
+            // when mUseZeroDefaultBase is true since an existing base might have been ignored if it
+            // was part of the data ignored after the dimension guardrail was hit.
+            if (mDropBucketOnDimensionHardLimitExceeded) {
+                invalidateCurrentBucket(eventElapsedTimeNs,
+                                        BucketDropReason::DIMENSION_GUARDRAIL_REACHED);
+                mCurrentSlicedBucket.clear();
+                mHasHitGuardrail = false;
+            }
+            mHasGlobalBase = false;
+        } else {
+            // If we reach the guardrail, we might have dropped some data which means the bucket is
+            // incomplete.
+            //
+            // The base also needs to be reset. If we do not have the full data, we might
+            // incorrectly compute the diff when mUseZeroDefaultBase is true since an existing key
+            // might be missing from mCurrentSlicedBucket.
+            invalidateCurrentBucket(eventElapsedTimeNs,
+                                    BucketDropReason::DIMENSION_GUARDRAIL_REACHED);
+            mCurrentSlicedBucket.clear();
+            mHasHitGuardrail = false;
+        }
     }
 }
 
@@ -398,7 +419,7 @@ NumericValue getAggregationInputValue(const LogEvent& event, const Matcher& matc
                 continue;
             }
             if (value.mValue.getType() == INT) {
-                binCounts.push_back(value.mValue.int_value);
+                binCounts.push_back(value.mValue.get<int32_t>());
             } else {
                 return NumericValue{};
             }
@@ -410,15 +431,15 @@ NumericValue getAggregationInputValue(const LogEvent& event, const Matcher& matc
         if (!value.mField.matches(matcher)) {
             continue;
         }
-        switch (value.mValue.type) {
+        switch (value.mValue.getType()) {
             case INT:
-                return NumericValue((int64_t)value.mValue.int_value);
+                return NumericValue((int64_t)value.mValue.get<int32_t>());
             case LONG:
-                return NumericValue((int64_t)value.mValue.long_value);
+                return NumericValue((int64_t)value.mValue.get<int64_t>());
             case FLOAT:
-                return NumericValue((double)value.mValue.float_value);
+                return NumericValue((double)value.mValue.get<float>());
             case DOUBLE:
-                return NumericValue((double)value.mValue.double_value);
+                return NumericValue((double)value.mValue.get<double>());
             default:
                 return NumericValue{};
         }
diff --git a/statsd/src/metrics/NumericValueMetricProducer.h b/statsd/src/metrics/NumericValueMetricProducer.h
index 613678e0..c22864ee 100644
--- a/statsd/src/metrics/NumericValueMetricProducer.h
+++ b/statsd/src/metrics/NumericValueMetricProducer.h
@@ -188,10 +188,13 @@ private:
 
     // For pulled metrics, this is always set to true whenever a pull succeeds.
     // It is set to false when a pull fails, or upon condition change to false.
+    // It is also set to false when the dimension guardrail is hit.
     // This is used to decide if we have the right base data to compute the
     // diff against.
     bool mHasGlobalBase;
 
+    const bool mDropBucketOnDimensionHardLimitExceeded;
+
     const int64_t mMaxPullDelayNs;
 
     // Deduped value fields for matching.
diff --git a/statsd/src/metrics/ValueMetricProducer.cpp b/statsd/src/metrics/ValueMetricProducer.cpp
index a053f82f..dfc8a108 100644
--- a/statsd/src/metrics/ValueMetricProducer.cpp
+++ b/statsd/src/metrics/ValueMetricProducer.cpp
@@ -259,7 +259,7 @@ void ValueMetricProducer<AggregatedValue, DimExtras>::onStateChanged(
     std::lock_guard<std::mutex> lock(mMutex);
     VLOG("ValueMetricProducer %lld onStateChanged time %lld, State %d, key %s, %d -> %d",
          (long long)mMetricId, (long long)eventTimeNs, atomId, primaryKey.toString().c_str(),
-         oldState.mValue.int_value, newState.mValue.int_value);
+         oldState.mValue.get<int32_t>(), newState.mValue.get<int32_t>());
 
     FieldValue oldStateCopy = oldState;
     FieldValue newStateCopy = newState;
@@ -660,11 +660,6 @@ void ValueMetricProducer<AggregatedValue, DimExtras>::dumpStatesLocked(int out,
     }
 }
 
-template <typename AggregatedValue, typename DimExtras>
-bool ValueMetricProducer<AggregatedValue, DimExtras>::hasReachedGuardRailLimit() const {
-    return mCurrentSlicedBucket.size() >= mDimensionHardLimit;
-}
-
 template <typename AggregatedValue, typename DimExtras>
 bool ValueMetricProducer<AggregatedValue, DimExtras>::hitGuardRailLocked(
         const MetricDimensionKey& newKey) const {
@@ -677,7 +672,7 @@ bool ValueMetricProducer<AggregatedValue, DimExtras>::hitGuardRailLocked(
         size_t newTupleCount = mCurrentSlicedBucket.size() + 1;
         StatsdStats::getInstance().noteMetricDimensionSize(mConfigKey, mMetricId, newTupleCount);
         // 2. Don't add more tuples, we are above the allowed threshold. Drop the data.
-        if (hasReachedGuardRailLimit()) {
+        if (newTupleCount > mDimensionHardLimit) {
             if (!mHasHitGuardrail) {
                 ALOGE("ValueMetricProducer %lld dropping data for dimension key %s",
                       (long long)mMetricId, newKey.toString().c_str());
@@ -725,14 +720,16 @@ void ValueMetricProducer<AggregatedValue, DimExtras>::onMatchedLogEventInternalL
         return;
     }
 
-    if (hitGuardRailLocked(eventKey)) {
-        return;
-    }
-
     const auto& returnVal = mDimInfos.emplace(whatKey, DimensionsInWhatInfo(getUnknownStateKey()));
     DimensionsInWhatInfo& dimensionsInWhatInfo = returnVal.first->second;
     const HashableDimensionKey& oldStateKey = dimensionsInWhatInfo.currentState;
-    CurrentBucket& currentBucket = mCurrentSlicedBucket[MetricDimensionKey(whatKey, oldStateKey)];
+    const MetricDimensionKey oldKey(whatKey, oldStateKey);
+
+    if (hitGuardRailLocked(oldKey)) {
+        return;
+    }
+
+    CurrentBucket& currentBucket = mCurrentSlicedBucket[oldKey];
 
     // Ensure we turn on the condition timer in the case where dimensions
     // were missing on a previous pull due to a state change.
@@ -759,8 +756,9 @@ void ValueMetricProducer<AggregatedValue, DimExtras>::onMatchedLogEventInternalL
         currentBucket.conditionTimer.onConditionChanged(false, eventTimeNs);
 
         // Turn ON the condition timer for the new state key.
-        mCurrentSlicedBucket[MetricDimensionKey(whatKey, stateKey)]
-                .conditionTimer.onConditionChanged(true, eventTimeNs);
+        if (!hitGuardRailLocked(eventKey)) {
+            mCurrentSlicedBucket[eventKey].conditionTimer.onConditionChanged(true, eventTimeNs);
+        }
     }
 }
 
diff --git a/statsd/src/metrics/ValueMetricProducer.h b/statsd/src/metrics/ValueMetricProducer.h
index 5b7cae24..9f9abc55 100644
--- a/statsd/src/metrics/ValueMetricProducer.h
+++ b/statsd/src/metrics/ValueMetricProducer.h
@@ -330,8 +330,6 @@ protected:
     // Util function to check whether the specified dimension hits the guardrail.
     bool hitGuardRailLocked(const MetricDimensionKey& newKey) const;
 
-    bool hasReachedGuardRailLimit() const;
-
     virtual void pullAndMatchEventsLocked(const int64_t timestampNs) {
     }
 
diff --git a/statsd/src/metrics/parsing_utils/config_update_utils.cpp b/statsd/src/metrics/parsing_utils/config_update_utils.cpp
index f4c2409b..4d77ff70 100644
--- a/statsd/src/metrics/parsing_utils/config_update_utils.cpp
+++ b/statsd/src/metrics/parsing_utils/config_update_utils.cpp
@@ -30,16 +30,16 @@ namespace android {
 namespace os {
 namespace statsd {
 
-// Recursive function to determine if a matcher needs to be updated. Populates matcherToUpdate.
+// Recursive function to determine if a matcher needs to be updated. Populates matcherUpdateStatus.
 // Returns nullopt if successful and InvalidConfigReason if not.
 optional<InvalidConfigReason> determineMatcherUpdateStatus(
         const StatsdConfig& config, const int matcherIdx,
         const unordered_map<int64_t, int>& oldAtomMatchingTrackerMap,
         const vector<sp<AtomMatchingTracker>>& oldAtomMatchingTrackers,
         const unordered_map<int64_t, int>& newAtomMatchingTrackerMap,
-        vector<UpdateStatus>& matchersToUpdate, vector<uint8_t>& cycleTracker) {
+        vector<UpdateStatus>& matcherUpdateStatus, vector<uint8_t>& cycleTracker) {
     // Have already examined this matcher.
-    if (matchersToUpdate[matcherIdx] != UPDATE_UNKNOWN) {
+    if (matcherUpdateStatus[matcherIdx] != UPDATE_UNKNOWN) {
         return nullopt;
     }
 
@@ -48,7 +48,7 @@ optional<InvalidConfigReason> determineMatcherUpdateStatus(
     // Check if new matcher.
     const auto& oldAtomMatchingTrackerIt = oldAtomMatchingTrackerMap.find(id);
     if (oldAtomMatchingTrackerIt == oldAtomMatchingTrackerMap.end()) {
-        matchersToUpdate[matcherIdx] = UPDATE_NEW;
+        matcherUpdateStatus[matcherIdx] = UPDATE_NEW;
         return nullopt;
     }
 
@@ -61,14 +61,14 @@ optional<InvalidConfigReason> determineMatcherUpdateStatus(
     }
     uint64_t newProtoHash = Hash64(serializedMatcher);
     if (newProtoHash != oldAtomMatchingTrackers[oldAtomMatchingTrackerIt->second]->getProtoHash()) {
-        matchersToUpdate[matcherIdx] = UPDATE_REPLACE;
+        matcherUpdateStatus[matcherIdx] = UPDATE_REPLACE;
         return nullopt;
     }
 
     optional<InvalidConfigReason> invalidConfigReason;
     switch (matcher.contents_case()) {
         case AtomMatcher::ContentsCase::kSimpleAtomMatcher: {
-            matchersToUpdate[matcherIdx] = UPDATE_PRESERVE;
+            matcherUpdateStatus[matcherIdx] = UPDATE_PRESERVE;
             return nullopt;
         }
         case AtomMatcher::ContentsCase::kCombination: {
@@ -94,18 +94,18 @@ optional<InvalidConfigReason> determineMatcherUpdateStatus(
                 }
                 invalidConfigReason = determineMatcherUpdateStatus(
                         config, childIdx, oldAtomMatchingTrackerMap, oldAtomMatchingTrackers,
-                        newAtomMatchingTrackerMap, matchersToUpdate, cycleTracker);
+                        newAtomMatchingTrackerMap, matcherUpdateStatus, cycleTracker);
                 if (invalidConfigReason.has_value()) {
                     invalidConfigReason->matcherIds.push_back(id);
                     return invalidConfigReason;
                 }
 
-                if (matchersToUpdate[childIdx] == UPDATE_REPLACE) {
+                if (matcherUpdateStatus[childIdx] == UPDATE_REPLACE) {
                     status = UPDATE_REPLACE;
                     break;
                 }
             }
-            matchersToUpdate[matcherIdx] = status;
+            matcherUpdateStatus[matcherIdx] = status;
             cycleTracker[matcherIdx] = false;
             return nullopt;
         }
@@ -144,12 +144,12 @@ optional<InvalidConfigReason> updateAtomMatchingTrackers(
     }
 
     // For combination matchers, we need to determine if any children need to be updated.
-    vector<UpdateStatus> matchersToUpdate(atomMatcherCount, UPDATE_UNKNOWN);
+    vector<UpdateStatus> matcherUpdateStatus(atomMatcherCount, UPDATE_UNKNOWN);
     vector<uint8_t> cycleTracker(atomMatcherCount, false);
     for (int i = 0; i < atomMatcherCount; i++) {
         invalidConfigReason = determineMatcherUpdateStatus(
                 config, i, oldAtomMatchingTrackerMap, oldAtomMatchingTrackers,
-                newAtomMatchingTrackerMap, matchersToUpdate, cycleTracker);
+                newAtomMatchingTrackerMap, matcherUpdateStatus, cycleTracker);
         if (invalidConfigReason.has_value()) {
             return invalidConfigReason;
         }
@@ -158,7 +158,7 @@ optional<InvalidConfigReason> updateAtomMatchingTrackers(
     for (int i = 0; i < atomMatcherCount; i++) {
         const AtomMatcher& matcher = config.atom_matcher(i);
         const int64_t id = matcher.id();
-        switch (matchersToUpdate[i]) {
+        switch (matcherUpdateStatus[i]) {
             case UPDATE_PRESERVE: {
                 const auto& oldAtomMatchingTrackerIt = oldAtomMatchingTrackerMap.find(id);
                 if (oldAtomMatchingTrackerIt == oldAtomMatchingTrackerMap.end()) {
@@ -231,17 +231,17 @@ optional<InvalidConfigReason> updateAtomMatchingTrackers(
     return nullopt;
 }
 
-// Recursive function to determine if a condition needs to be updated. Populates conditionsToUpdate.
-// Returns nullopt if successful and InvalidConfigReason if not.
+// Recursive function to determine if a condition needs to be updated. Populates
+// conditionUpdateStatus. Returns nullopt if successful and InvalidConfigReason if not.
 optional<InvalidConfigReason> determineConditionUpdateStatus(
         const StatsdConfig& config, const int conditionIdx,
         const unordered_map<int64_t, int>& oldConditionTrackerMap,
         const vector<sp<ConditionTracker>>& oldConditionTrackers,
         const unordered_map<int64_t, int>& newConditionTrackerMap,
-        const set<int64_t>& replacedMatchers, vector<UpdateStatus>& conditionsToUpdate,
+        const set<int64_t>& replacedMatchers, vector<UpdateStatus>& conditionUpdateStatus,
         vector<uint8_t>& cycleTracker) {
     // Have already examined this condition.
-    if (conditionsToUpdate[conditionIdx] != UPDATE_UNKNOWN) {
+    if (conditionUpdateStatus[conditionIdx] != UPDATE_UNKNOWN) {
         return nullopt;
     }
 
@@ -250,7 +250,7 @@ optional<InvalidConfigReason> determineConditionUpdateStatus(
     // Check if new condition.
     const auto& oldConditionTrackerIt = oldConditionTrackerMap.find(id);
     if (oldConditionTrackerIt == oldConditionTrackerMap.end()) {
-        conditionsToUpdate[conditionIdx] = UPDATE_NEW;
+        conditionUpdateStatus[conditionIdx] = UPDATE_NEW;
         return nullopt;
     }
 
@@ -263,7 +263,7 @@ optional<InvalidConfigReason> determineConditionUpdateStatus(
     }
     uint64_t newProtoHash = Hash64(serializedCondition);
     if (newProtoHash != oldConditionTrackers[oldConditionTrackerIt->second]->getProtoHash()) {
-        conditionsToUpdate[conditionIdx] = UPDATE_REPLACE;
+        conditionUpdateStatus[conditionIdx] = UPDATE_REPLACE;
         return nullopt;
     }
 
@@ -274,23 +274,23 @@ optional<InvalidConfigReason> determineConditionUpdateStatus(
             const SimplePredicate& simplePredicate = predicate.simple_predicate();
             if (simplePredicate.has_start()) {
                 if (replacedMatchers.find(simplePredicate.start()) != replacedMatchers.end()) {
-                    conditionsToUpdate[conditionIdx] = UPDATE_REPLACE;
+                    conditionUpdateStatus[conditionIdx] = UPDATE_REPLACE;
                     return nullopt;
                 }
             }
             if (simplePredicate.has_stop()) {
                 if (replacedMatchers.find(simplePredicate.stop()) != replacedMatchers.end()) {
-                    conditionsToUpdate[conditionIdx] = UPDATE_REPLACE;
+                    conditionUpdateStatus[conditionIdx] = UPDATE_REPLACE;
                     return nullopt;
                 }
             }
             if (simplePredicate.has_stop_all()) {
                 if (replacedMatchers.find(simplePredicate.stop_all()) != replacedMatchers.end()) {
-                    conditionsToUpdate[conditionIdx] = UPDATE_REPLACE;
+                    conditionUpdateStatus[conditionIdx] = UPDATE_REPLACE;
                     return nullopt;
                 }
             }
-            conditionsToUpdate[conditionIdx] = UPDATE_PRESERVE;
+            conditionUpdateStatus[conditionIdx] = UPDATE_PRESERVE;
             return nullopt;
         }
         case Predicate::ContentsCase::kCombination: {
@@ -316,18 +316,19 @@ optional<InvalidConfigReason> determineConditionUpdateStatus(
                 }
                 invalidConfigReason = determineConditionUpdateStatus(
                         config, childIdx, oldConditionTrackerMap, oldConditionTrackers,
-                        newConditionTrackerMap, replacedMatchers, conditionsToUpdate, cycleTracker);
+                        newConditionTrackerMap, replacedMatchers, conditionUpdateStatus,
+                        cycleTracker);
                 if (invalidConfigReason.has_value()) {
                     invalidConfigReason->conditionIds.push_back(id);
                     return invalidConfigReason;
                 }
 
-                if (conditionsToUpdate[childIdx] == UPDATE_REPLACE) {
+                if (conditionUpdateStatus[childIdx] == UPDATE_REPLACE) {
                     status = UPDATE_REPLACE;
                     break;
                 }
             }
-            conditionsToUpdate[conditionIdx] = status;
+            conditionUpdateStatus[conditionIdx] = status;
             cycleTracker[conditionIdx] = false;
             return nullopt;
         }
@@ -369,12 +370,12 @@ optional<InvalidConfigReason> updateConditions(
         conditionProtos.push_back(condition);
     }
 
-    vector<UpdateStatus> conditionsToUpdate(conditionTrackerCount, UPDATE_UNKNOWN);
+    vector<UpdateStatus> conditionUpdateStatus(conditionTrackerCount, UPDATE_UNKNOWN);
     vector<uint8_t> cycleTracker(conditionTrackerCount, false);
     for (int i = 0; i < conditionTrackerCount; i++) {
         invalidConfigReason = determineConditionUpdateStatus(
                 config, i, oldConditionTrackerMap, oldConditionTrackers, newConditionTrackerMap,
-                replacedMatchers, conditionsToUpdate, cycleTracker);
+                replacedMatchers, conditionUpdateStatus, cycleTracker);
         if (invalidConfigReason.has_value()) {
             return invalidConfigReason;
         }
@@ -385,7 +386,7 @@ optional<InvalidConfigReason> updateConditions(
     for (int i = 0; i < conditionTrackerCount; i++) {
         const Predicate& predicate = config.predicate(i);
         const int64_t id = predicate.id();
-        switch (conditionsToUpdate[i]) {
+        switch (conditionUpdateStatus[i]) {
             case UPDATE_PRESERVE: {
                 preservedConditions.insert(i);
                 const auto& oldConditionTrackerIt = oldConditionTrackerMap.find(id);
@@ -573,7 +574,7 @@ optional<InvalidConfigReason> determineAllMetricUpdateStatuses(
         const vector<sp<MetricProducer>>& oldMetricProducers,
         const unordered_map<int64_t, int>& metricToActivationMap,
         const set<int64_t>& replacedMatchers, const set<int64_t>& replacedConditions,
-        const set<int64_t>& replacedStates, vector<UpdateStatus>& metricsToUpdate) {
+        const set<int64_t>& replacedStates, vector<UpdateStatus>& metricUpdateStatus) {
     int metricIndex = 0;
     optional<InvalidConfigReason> invalidConfigReason;
     for (int i = 0; i < config.count_metric_size(); i++, metricIndex++) {
@@ -586,7 +587,7 @@ optional<InvalidConfigReason> determineAllMetricUpdateStatuses(
                 config, metric, metric.id(), METRIC_TYPE_COUNT, {metric.what()},
                 conditionDependencies, metric.slice_by_state(), metric.links(),
                 oldMetricProducerMap, oldMetricProducers, metricToActivationMap, replacedMatchers,
-                replacedConditions, replacedStates, metricsToUpdate[metricIndex]);
+                replacedConditions, replacedStates, metricUpdateStatus[metricIndex]);
         if (invalidConfigReason.has_value()) {
             return invalidConfigReason;
         }
@@ -601,7 +602,7 @@ optional<InvalidConfigReason> determineAllMetricUpdateStatuses(
                 config, metric, metric.id(), METRIC_TYPE_DURATION, /*matcherDependencies=*/{},
                 conditionDependencies, metric.slice_by_state(), metric.links(),
                 oldMetricProducerMap, oldMetricProducers, metricToActivationMap, replacedMatchers,
-                replacedConditions, replacedStates, metricsToUpdate[metricIndex]);
+                replacedConditions, replacedStates, metricUpdateStatus[metricIndex]);
         if (invalidConfigReason.has_value()) {
             return invalidConfigReason;
         }
@@ -616,7 +617,7 @@ optional<InvalidConfigReason> determineAllMetricUpdateStatuses(
                 config, metric, metric.id(), METRIC_TYPE_EVENT, {metric.what()},
                 conditionDependencies, ::google::protobuf::RepeatedField<int64_t>(), metric.links(),
                 oldMetricProducerMap, oldMetricProducers, metricToActivationMap, replacedMatchers,
-                replacedConditions, replacedStates, metricsToUpdate[metricIndex]);
+                replacedConditions, replacedStates, metricUpdateStatus[metricIndex]);
         if (invalidConfigReason.has_value()) {
             return invalidConfigReason;
         }
@@ -631,7 +632,7 @@ optional<InvalidConfigReason> determineAllMetricUpdateStatuses(
                 config, metric, metric.id(), METRIC_TYPE_VALUE, {metric.what()},
                 conditionDependencies, metric.slice_by_state(), metric.links(),
                 oldMetricProducerMap, oldMetricProducers, metricToActivationMap, replacedMatchers,
-                replacedConditions, replacedStates, metricsToUpdate[metricIndex]);
+                replacedConditions, replacedStates, metricUpdateStatus[metricIndex]);
         if (invalidConfigReason.has_value()) {
             return invalidConfigReason;
         }
@@ -650,7 +651,7 @@ optional<InvalidConfigReason> determineAllMetricUpdateStatuses(
                 config, metric, metric.id(), METRIC_TYPE_GAUGE, matcherDependencies,
                 conditionDependencies, ::google::protobuf::RepeatedField<int64_t>(), metric.links(),
                 oldMetricProducerMap, oldMetricProducers, metricToActivationMap, replacedMatchers,
-                replacedConditions, replacedStates, metricsToUpdate[metricIndex]);
+                replacedConditions, replacedStates, metricUpdateStatus[metricIndex]);
         if (invalidConfigReason.has_value()) {
             return invalidConfigReason;
         }
@@ -666,7 +667,7 @@ optional<InvalidConfigReason> determineAllMetricUpdateStatuses(
                 config, metric, metric.id(), METRIC_TYPE_KLL, {metric.what()},
                 conditionDependencies, metric.slice_by_state(), metric.links(),
                 oldMetricProducerMap, oldMetricProducers, metricToActivationMap, replacedMatchers,
-                replacedConditions, replacedStates, metricsToUpdate[metricIndex]);
+                replacedConditions, replacedStates, metricUpdateStatus[metricIndex]);
         if (invalidConfigReason.has_value()) {
             return invalidConfigReason;
         }
@@ -766,10 +767,10 @@ optional<InvalidConfigReason> updateMetrics(
         metricToActivationMap.insert({metricId, i});
     }
 
-    vector<UpdateStatus> metricsToUpdate(allMetricsCount, UPDATE_UNKNOWN);
+    vector<UpdateStatus> metricUpdateStatus(allMetricsCount, UPDATE_UNKNOWN);
     invalidConfigReason = determineAllMetricUpdateStatuses(
             config, oldMetricProducerMap, oldMetricProducers, metricToActivationMap,
-            replacedMatchers, replacedConditions, replacedStates, metricsToUpdate);
+            replacedMatchers, replacedConditions, replacedStates, metricUpdateStatus);
     if (invalidConfigReason.has_value()) {
         return invalidConfigReason;
     }
@@ -780,7 +781,7 @@ optional<InvalidConfigReason> updateMetrics(
         const CountMetric& metric = config.count_metric(i);
         newMetricProducerMap[metric.id()] = metricIndex;
         optional<sp<MetricProducer>> producer;
-        switch (metricsToUpdate[metricIndex]) {
+        switch (metricUpdateStatus[metricIndex]) {
             case UPDATE_PRESERVE: {
                 producer = updateMetric(
                         config, i, metricIndex, metric.id(), allAtomMatchingTrackers,
@@ -822,7 +823,7 @@ optional<InvalidConfigReason> updateMetrics(
         const DurationMetric& metric = config.duration_metric(i);
         newMetricProducerMap[metric.id()] = metricIndex;
         optional<sp<MetricProducer>> producer;
-        switch (metricsToUpdate[metricIndex]) {
+        switch (metricUpdateStatus[metricIndex]) {
             case UPDATE_PRESERVE: {
                 producer = updateMetric(
                         config, i, metricIndex, metric.id(), allAtomMatchingTrackers,
@@ -864,7 +865,7 @@ optional<InvalidConfigReason> updateMetrics(
         const EventMetric& metric = config.event_metric(i);
         newMetricProducerMap[metric.id()] = metricIndex;
         optional<sp<MetricProducer>> producer;
-        switch (metricsToUpdate[metricIndex]) {
+        switch (metricUpdateStatus[metricIndex]) {
             case UPDATE_PRESERVE: {
                 producer = updateMetric(
                         config, i, metricIndex, metric.id(), allAtomMatchingTrackers,
@@ -906,7 +907,7 @@ optional<InvalidConfigReason> updateMetrics(
         const ValueMetric& metric = config.value_metric(i);
         newMetricProducerMap[metric.id()] = metricIndex;
         optional<sp<MetricProducer>> producer;
-        switch (metricsToUpdate[metricIndex]) {
+        switch (metricUpdateStatus[metricIndex]) {
             case UPDATE_PRESERVE: {
                 producer = updateMetric(
                         config, i, metricIndex, metric.id(), allAtomMatchingTrackers,
@@ -949,7 +950,7 @@ optional<InvalidConfigReason> updateMetrics(
         const GaugeMetric& metric = config.gauge_metric(i);
         newMetricProducerMap[metric.id()] = metricIndex;
         optional<sp<MetricProducer>> producer;
-        switch (metricsToUpdate[metricIndex]) {
+        switch (metricUpdateStatus[metricIndex]) {
             case UPDATE_PRESERVE: {
                 producer = updateMetric(
                         config, i, metricIndex, metric.id(), allAtomMatchingTrackers,
@@ -992,7 +993,7 @@ optional<InvalidConfigReason> updateMetrics(
         const KllMetric& metric = config.kll_metric(i);
         newMetricProducerMap[metric.id()] = metricIndex;
         optional<sp<MetricProducer>> producer;
-        switch (metricsToUpdate[metricIndex]) {
+        switch (metricUpdateStatus[metricIndex]) {
             case UPDATE_PRESERVE: {
                 producer = updateMetric(
                         config, i, metricIndex, metric.id(), allAtomMatchingTrackers,
@@ -1055,7 +1056,7 @@ optional<InvalidConfigReason> updateMetrics(
                         INVALID_CONFIG_REASON_METRIC_SLICED_STATE_ATOM_ALLOWED_FROM_ANY_UID,
                         producer->getMetricId());
                 // Preserved metrics should've already registered.`
-            } else if (metricsToUpdate[i] != UPDATE_PRESERVE) {
+            } else if (metricUpdateStatus[i] != UPDATE_PRESERVE) {
                 StateManager::getInstance().registerListener(atomId, producer);
             }
         }
@@ -1063,7 +1064,7 @@ optional<InvalidConfigReason> updateMetrics(
 
     // Init new/replaced metrics.
     for (size_t i = 0; i < newMetricProducers.size(); i++) {
-        if (metricsToUpdate[i] == UPDATE_REPLACE || metricsToUpdate[i] == UPDATE_NEW) {
+        if (metricUpdateStatus[i] == UPDATE_REPLACE || metricUpdateStatus[i] == UPDATE_NEW) {
             newMetricProducers[i]->prepareFirstBucket();
         }
     }
diff --git a/statsd/src/socket/BaseStatsSocketListener.h b/statsd/src/socket/BaseStatsSocketListener.h
index d64a2dee..bcf8df13 100644
--- a/statsd/src/socket/BaseStatsSocketListener.h
+++ b/statsd/src/socket/BaseStatsSocketListener.h
@@ -45,6 +45,10 @@ public:
      */
     explicit BaseStatsSocketListener(const std::shared_ptr<LogEventQueue>& queue,
                             const std::shared_ptr<LogEventFilter>& logEventFilter);
+
+    virtual int startListener() = 0;
+    virtual int stopListener() = 0;
+
 protected:
     static int getLogSocket();
 
diff --git a/statsd/src/socket/StatsSocketListener.cpp b/statsd/src/socket/StatsSocketListener.cpp
index ccdbc8b7..007bb640 100644
--- a/statsd/src/socket/StatsSocketListener.cpp
+++ b/statsd/src/socket/StatsSocketListener.cpp
@@ -47,6 +47,14 @@ StatsSocketListener::StatsSocketListener(const std::shared_ptr<LogEventQueue>& q
       SocketListener(getLogSocket(), false /*start listen*/){
 }
 
+int StatsSocketListener::startListener() {
+    return SocketListener::startListener(600);
+}
+
+int StatsSocketListener::stopListener() {
+    return SocketListener::stopListener();
+}
+
 bool StatsSocketListener::onDataAvailable(SocketClient* cli) {
     ATRACE_CALL_DEBUG();
     static bool name_set;
diff --git a/statsd/src/socket/StatsSocketListener.h b/statsd/src/socket/StatsSocketListener.h
index cb39e8e4..288d15cc 100644
--- a/statsd/src/socket/StatsSocketListener.h
+++ b/statsd/src/socket/StatsSocketListener.h
@@ -34,6 +34,9 @@ public:
 
     virtual ~StatsSocketListener() = default;
 
+    virtual int startListener() override;
+    virtual int stopListener() override;
+
 protected:
     bool onDataAvailable(SocketClient* cli) override;
 };
diff --git a/statsd/src/socket/StatsSocketListenerIoUring.cpp b/statsd/src/socket/StatsSocketListenerIoUring.cpp
new file mode 100644
index 00000000..1a650233
--- /dev/null
+++ b/statsd/src/socket/StatsSocketListenerIoUring.cpp
@@ -0,0 +1,171 @@
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
+#define STATSD_DEBUG false  // STOPSHIP if true
+#include "Log.h"
+
+#include "StatsSocketListenerIoUring.h"
+
+#include <IOUringSocketHandler/IOUringSocketHandler.h>
+#include <ctype.h>
+#include <cutils/sockets.h>
+#include <limits.h>
+#include <stdio.h>
+#include <sys/cdefs.h>
+#include <sys/prctl.h>
+#include <sys/socket.h>
+#include <sys/types.h>
+#include <sys/un.h>
+#include <unistd.h>
+
+#include "StatsSocketListener.h"
+#include "android-base/scopeguard.h"
+#include "guardrail/StatsdStats.h"
+#include "logd/logevent_util.h"
+#include "stats_log_util.h"
+#include "statslog_statsd.h"
+#include "utils/api_tracing.h"
+
+using namespace std;
+
+namespace android {
+namespace os {
+namespace statsd {
+
+StatsSocketListenerIoUring::StatsSocketListenerIoUring(
+        const std::shared_ptr<LogEventQueue>& queue,
+        const std::shared_ptr<LogEventFilter>& logEventFilter)
+    : BaseStatsSocketListener(queue, logEventFilter) {
+    VLOG("IoUring Socket Initializing");
+    mIoUringSocketHandler = std::make_unique<IOUringSocketHandler>(getLogSocket());
+}
+
+int StatsSocketListenerIoUring::startListener() {
+    VLOG("IoUring Socket Listener starting");
+    if (this->getLogSocket() <= 0) {
+        ALOGE("IoUring Socket Listener: Missing socket");
+        return -1;
+    }
+
+    mThread = std::thread(&StatsSocketListenerIoUring::threadFunction, this);
+    VLOG("IoUring Socket Listener started");
+    return 0;
+}
+
+int StatsSocketListenerIoUring::stopListener() {
+    if (mFalledBackToSyncListener) {
+        if (gSocketListener == nullptr) {
+            ALOGE("StatsSocketListener pointer is NULL when stopping the IoUring version, this "
+                  "should not be possible");
+            StatsdStats::getInstance().noteIllegalState(
+                    COUNTER_TYPE_ERROR_STOP_IOURING_LISTENER_SYNC_LISTENER_NULLPTR);
+            return -1;
+        }
+        gSocketListener->stopListener();
+        return 0;
+    }
+    mShouldStopThreadFunction = true;
+    if (mThread.joinable()) {
+        mThread.join();
+    }
+    return 0;
+}
+
+bool StatsSocketListenerIoUring::initializeIoUring() {
+    if (mIoUringSocketHandler == nullptr) {
+        ALOGE("IoUring Socket Listener: LibUringUtils is null");
+        return false;
+    }
+    if (!mIoUringSocketHandler->SetupIoUring(MAX_BUFFERS)) {
+        ALOGE("IoUring Socket Listener: SetupIoUring failed");
+        return false;
+    }
+    if (!mIoUringSocketHandler->AllocateAndRegisterBuffers(
+                MAX_BUFFERS, sizeof(android_log_header_t) + LOGGER_ENTRY_MAX_PAYLOAD + 1)) {
+        ALOGE("IoUring Socket Listener: RegisterBuffers failed");
+        return false;
+    }
+    if (!mIoUringSocketHandler->EnqueueMultishotRecvmsg()) {
+        ALOGE("IoUring Socket Listener: EnqueueMultishotRecvmsg failed");
+        return false;
+    }
+    return true;
+}
+
+void StatsSocketListenerIoUring::startStatsSocketListener() {
+    gSocketListener = std::make_unique<StatsSocketListener>(mQueue, mLogEventFilter);
+    if (gSocketListener->startListener()) {
+        VLOG("IoUring Fallback Socket Initialization failed. Terminating");
+        exit(1);
+    }
+    mFalledBackToSyncListener = true;
+}
+
+void StatsSocketListenerIoUring::threadFunction() {
+    // If initialization of the IoUring library failed, fall back to the original
+    // StatsSocketListener
+    VLOG("IoUring Socket Listener started");
+    if (!initializeIoUring()) {
+        startStatsSocketListener();
+        return;
+    }
+
+    static bool name_set;
+    if (!name_set) {
+        prctl(PR_SET_NAME, "statsd.writer");
+        name_set = true;
+    }
+
+    while (!mShouldStopThreadFunction) {
+        void* receivedData = nullptr;
+        size_t length = 0;
+        struct ucred* credential = nullptr;
+        mIoUringSocketHandler->ReceiveData(&receivedData, length, &credential);
+        if (!onDataAvailable(receivedData, length, credential)) {
+            VLOG("StatsSocketListenerIoUring::threadFunction, onDataAvailable failed");
+        }
+    }
+}
+
+bool StatsSocketListenerIoUring::onDataAvailable(void* buffer, int len, struct ucred* credential) {
+    ATRACE_CALL_DEBUG();
+    // Release the buffer from here onwards
+    auto scope_guard = android::base::make_scope_guard(
+            [this]() -> void { mIoUringSocketHandler->ReleaseBuffer(); });
+
+    if (len <= (ssize_t)(sizeof(android_log_header_t))) {
+        VLOG("IoUring onDataReceived error: len <= android_log_header_t");
+        return false;
+    }
+
+    struct ucred fake_cred;
+    if (credential == NULL) {
+        credential = &fake_cred;
+        credential->pid = 0;
+        credential->uid = DEFAULT_OVERFLOWUID;
+    }
+
+    const uint32_t uid = credential->uid;
+    const uint32_t pid = credential->pid;
+
+    // TODO: b/382145446 - Revisit the handling of batch read and call noteBatchSocketRead with
+    //  statistics of atoms.
+    processSocketMessage(buffer, len, uid, pid);
+
+    return true;
+}
+}  // namespace statsd
+}  // namespace os
+}  // namespace android
diff --git a/statsd/src/socket/StatsSocketListenerIoUring.h b/statsd/src/socket/StatsSocketListenerIoUring.h
new file mode 100644
index 00000000..c6972f0c
--- /dev/null
+++ b/statsd/src/socket/StatsSocketListenerIoUring.h
@@ -0,0 +1,67 @@
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
+#pragma once
+
+#include <IOUringSocketHandler/IOUringSocketHandler.h>
+#include <gtest/gtest_prod.h>
+#include <utils/RefBase.h>
+
+#include <thread>
+
+#include "BaseStatsSocketListener.h"
+#include "LogEventFilter.h"
+#include "logd/LogEventQueue.h"
+
+namespace android {
+namespace os {
+namespace statsd {
+
+class StatsSocketListenerIoUring : public virtual BaseStatsSocketListener, public virtual RefBase {
+public:
+    explicit StatsSocketListenerIoUring(const std::shared_ptr<LogEventQueue>& queue,
+                                        const std::shared_ptr<LogEventFilter>& logEventFilter);
+
+    virtual ~StatsSocketListenerIoUring() = default;
+
+    virtual int startListener() override;
+    virtual int stopListener() override;
+
+protected:
+    bool onDataAvailable(void* buffer, int len, struct ucred* credential);
+
+private:
+    void threadFunction();
+
+    bool initializeIoUring();
+
+    void startStatsSocketListener();
+
+    std::unique_ptr<IOUringSocketHandler> mIoUringSocketHandler;
+
+    static const int MAX_BUFFERS = 64;
+
+    std::unique_ptr<BaseStatsSocketListener> gSocketListener = nullptr;
+
+    bool mFalledBackToSyncListener = false;
+
+    std::atomic_bool mShouldStopThreadFunction = false;
+
+    std::thread mThread;
+};
+
+}  // namespace statsd
+}  // namespace os
+}  // namespace android
diff --git a/statsd/src/state/StateTracker.cpp b/statsd/src/state/StateTracker.cpp
index 40219b11..f024bd4b 100644
--- a/statsd/src/state/StateTracker.cpp
+++ b/statsd/src/state/StateTracker.cpp
@@ -128,9 +128,9 @@ void StateTracker::updateStateForPrimaryKey(const int64_t eventTimeNs,
                                             StateValueInfo& stateValueInfo) {
     FieldValue oldState;
     oldState.mField = mField;
-    oldState.mValue.setInt(stateValueInfo.state);
+    oldState.mValue.set(stateValueInfo.state);
     const int32_t oldStateValue = stateValueInfo.state;
-    const int32_t newStateValue = newState.mValue.int_value;
+    const int32_t newStateValue = newState.mValue.get<int32_t>();
 
     // Update state map and notify listeners if state has changed.
     // Every state event triggers a state overwrite.
diff --git a/statsd/src/stats_log.proto b/statsd/src/stats_log.proto
index 63ace823..dbef1a3d 100644
--- a/statsd/src/stats_log.proto
+++ b/statsd/src/stats_log.proto
@@ -756,6 +756,14 @@ message StatsdStatsReport {
     }
 
     optional ErrorStats error_stats = 27;
+
+    message PullerAlarmStats {
+        optional int32 alarm_with_pulls_count = 1;
+        optional int32 alarm_without_pulls_count = 2;
+        optional int32 alarm_with_puller_errors_count = 3;
+    }
+
+    optional PullerAlarmStats puller_alarm_stats = 29;
 }
 
 message AlertTriggerDetails {
diff --git a/statsd/src/stats_log_util.cpp b/statsd/src/stats_log_util.cpp
index 43d6bc87..64cb00ac 100644
--- a/statsd/src/stats_log_util.cpp
+++ b/statsd/src/stats_log_util.cpp
@@ -140,27 +140,27 @@ void writeDimensionToProtoHelper(const std::vector<FieldValue>& dims,
             switch (dim.mValue.getType()) {
                 case INT:
                     if (isUidField(dim, uidFields) || isAttributionUidField(dim)) {
-                        usedUids.insert(dim.mValue.int_value);
+                        usedUids.insert(dim.mValue.get<int32_t>());
                     }
                     protoOutput->write(FIELD_TYPE_INT32 | DIMENSIONS_VALUE_VALUE_INT,
-                                       dim.mValue.int_value);
+                                       dim.mValue.get<int32_t>());
                     break;
                 case LONG:
                     protoOutput->write(FIELD_TYPE_INT64 | DIMENSIONS_VALUE_VALUE_LONG,
-                                       (long long)dim.mValue.long_value);
+                                       (long long)dim.mValue.get<int64_t>());
                     break;
                 case FLOAT:
                     protoOutput->write(FIELD_TYPE_FLOAT | DIMENSIONS_VALUE_VALUE_FLOAT,
-                                       dim.mValue.float_value);
+                                       dim.mValue.get<float>());
                     break;
                 case STRING:
                     if (str_set == nullptr) {
                         protoOutput->write(FIELD_TYPE_STRING | DIMENSIONS_VALUE_VALUE_STR,
-                                           dim.mValue.str_value);
+                                           dim.mValue.get<string>());
                     } else {
-                        str_set->insert(dim.mValue.str_value);
+                        str_set->insert(dim.mValue.get<string>());
                         protoOutput->write(FIELD_TYPE_UINT64 | DIMENSIONS_VALUE_VALUE_STR_HASH,
-                                           (long long)Hash64(dim.mValue.str_value));
+                                           (long long)Hash64(dim.mValue.get<string>()));
                     }
                     break;
                 default:
@@ -211,27 +211,27 @@ void writeDimensionLeafToProtoHelper(const std::vector<FieldValue>& dims,
             switch (dim.mValue.getType()) {
                 case INT:
                     if (isUidField(dim, uidFields) || isAttributionUidField(dim)) {
-                        usedUids.insert(dim.mValue.int_value);
+                        usedUids.insert(dim.mValue.get<int32_t>());
                     }
                     protoOutput->write(FIELD_TYPE_INT32 | DIMENSIONS_VALUE_VALUE_INT,
-                                       dim.mValue.int_value);
+                                       dim.mValue.get<int32_t>());
                     break;
                 case LONG:
                     protoOutput->write(FIELD_TYPE_INT64 | DIMENSIONS_VALUE_VALUE_LONG,
-                                       (long long)dim.mValue.long_value);
+                                       (long long)dim.mValue.get<int64_t>());
                     break;
                 case FLOAT:
                     protoOutput->write(FIELD_TYPE_FLOAT | DIMENSIONS_VALUE_VALUE_FLOAT,
-                                       dim.mValue.float_value);
+                                       dim.mValue.get<float>());
                     break;
                 case STRING:
                     if (str_set == nullptr) {
                         protoOutput->write(FIELD_TYPE_STRING | DIMENSIONS_VALUE_VALUE_STR,
-                                           dim.mValue.str_value);
+                                           dim.mValue.get<string>());
                     } else {
-                        str_set->insert(dim.mValue.str_value);
+                        str_set->insert(dim.mValue.get<string>());
                         protoOutput->write(FIELD_TYPE_UINT64 | DIMENSIONS_VALUE_VALUE_STR_HASH,
-                                           (long long)Hash64(dim.mValue.str_value));
+                                           (long long)Hash64(dim.mValue.get<string>()));
                     }
                     break;
                 default:
@@ -382,28 +382,28 @@ void writeFieldValueTreeToStreamHelper(int tagId, const std::vector<FieldValue>&
             switch (dim.mValue.getType()) {
                 case INT:
                     if (isUidField(dim, uidFields) || isAttributionUidField(dim)) {
-                        usedUids.insert(dim.mValue.int_value);
+                        usedUids.insert(dim.mValue.get<int32_t>());
                     }
                     protoOutput->write(FIELD_TYPE_INT32 | repeatedFieldMask | fieldNum,
-                                       dim.mValue.int_value);
+                                       dim.mValue.get<int32_t>());
                     break;
                 case LONG:
                     protoOutput->write(FIELD_TYPE_INT64 | repeatedFieldMask | fieldNum,
-                                       (long long)dim.mValue.long_value);
+                                       (long long)dim.mValue.get<int64_t>());
                     break;
                 case FLOAT:
                     protoOutput->write(FIELD_TYPE_FLOAT | repeatedFieldMask | fieldNum,
-                                       dim.mValue.float_value);
+                                       dim.mValue.get<float>());
                     break;
                 case STRING: {
                     protoOutput->write(FIELD_TYPE_STRING | repeatedFieldMask | fieldNum,
-                                       dim.mValue.str_value);
+                                       dim.mValue.get<string>());
                     break;
                 }
                 case STORAGE:
                     protoOutput->write(FIELD_TYPE_MESSAGE | fieldNum,
-                                       (const char*)dim.mValue.storage_value.data(),
-                                       dim.mValue.storage_value.size());
+                                       (const char*)dim.mValue.get<vector<uint8_t>>().data(),
+                                       dim.mValue.get<vector<uint8_t>>().size());
                     break;
                 default:
                     break;
@@ -445,11 +445,11 @@ void writeStateToProto(const FieldValue& state, util::ProtoOutputStream* protoOu
     switch (state.mValue.getType()) {
         case INT:
             protoOutput->write(FIELD_TYPE_INT32 | STATE_VALUE_CONTENTS_VALUE,
-                               state.mValue.int_value);
+                               state.mValue.get<int32_t>());
             break;
         case LONG:
             protoOutput->write(FIELD_TYPE_INT64 | STATE_VALUE_CONTENTS_GROUP_ID,
-                               state.mValue.long_value);
+                               state.mValue.get<int64_t>());
             break;
         default:
             break;
@@ -587,6 +587,13 @@ void writeAtomMetricStatsToStream(const std::pair<int64_t, StatsdStats::AtomMetr
 
 void writeDataCorruptedReasons(ProtoOutputStream& proto, int fieldIdDataCorruptedReason,
                                bool hasQueueOverflow, bool hasSocketLoss) {
+    writeDataCorruptedReasons(proto, fieldIdDataCorruptedReason, hasQueueOverflow, hasSocketLoss,
+                              /*hasSystemServerRestart=*/false);
+}
+
+void writeDataCorruptedReasons(ProtoOutputStream& proto, int fieldIdDataCorruptedReason,
+                               bool hasQueueOverflow, bool hasSocketLoss,
+                               bool hasSystemServerRestart) {
     if (hasQueueOverflow) {
         proto.write(FIELD_TYPE_INT32 | FIELD_COUNT_REPEATED | fieldIdDataCorruptedReason,
                     DATA_CORRUPTED_EVENT_QUEUE_OVERFLOW);
@@ -595,6 +602,10 @@ void writeDataCorruptedReasons(ProtoOutputStream& proto, int fieldIdDataCorrupte
         proto.write(FIELD_TYPE_INT32 | FIELD_COUNT_REPEATED | fieldIdDataCorruptedReason,
                     DATA_CORRUPTED_SOCKET_LOSS);
     }
+    if (hasSystemServerRestart) {
+        proto.write(FIELD_TYPE_INT32 | FIELD_COUNT_REPEATED | fieldIdDataCorruptedReason,
+                    DATA_CORRUPTED_SYSTEM_SERVER_CRASH);
+    }
 }
 
 int64_t getElapsedRealtimeNs() {
@@ -670,7 +681,7 @@ void mapIsolatedUidsToHostUidInLogEvent(const sp<UidMap>& uidMap, LogEvent& even
     auto it = fieldValues->begin();
     while(it != fieldValues->end() && remainingUidCount > 0) {
         if (isUidField(*it)) {
-            it->mValue.setInt(uidMap->getHostUidOrSelf(it->mValue.int_value));
+            it->mValue.set(uidMap->getHostUidOrSelf(it->mValue.get<int32_t>()));
             remainingUidCount--;
         }
         ++it;
diff --git a/statsd/src/stats_log_util.h b/statsd/src/stats_log_util.h
index 6520f8e1..a1664053 100644
--- a/statsd/src/stats_log_util.h
+++ b/statsd/src/stats_log_util.h
@@ -99,6 +99,10 @@ void writeAtomMetricStatsToStream(const std::pair<int64_t, StatsdStats::AtomMetr
 void writeDataCorruptedReasons(ProtoOutputStream& proto, int fieldIdDataCorruptedReason,
                                bool hasQueueOverflow, bool hasSocketLoss);
 
+void writeDataCorruptedReasons(ProtoOutputStream& proto, int fieldIdDataCorruptedReason,
+                               bool hasQueueOverflow, bool hasSocketLoss,
+                               bool hasSystemServerRestart);
+
 template<class T>
 bool parseProtoOutputStream(ProtoOutputStream& protoOutput, T* message) {
     std::string pbBytes;
diff --git a/statsd/src/statsd_config.proto b/statsd/src/statsd_config.proto
index 6fdeb08f..40e426ec 100644
--- a/statsd/src/statsd_config.proto
+++ b/statsd/src/statsd_config.proto
@@ -488,6 +488,8 @@ message ValueMetric {
 
   optional FieldMatcher uid_fields = 27;
 
+  optional bool drop_bucket_on_max_dimensions_exceeded = 28 [default = false];
+
   reserved 100;
   reserved 101;
 }
@@ -715,5 +717,5 @@ message StatsdConfig {
   optional StatsdConfigOptions statsd_config_options = 30;
 
   // Do not use.
-  reserved 1000, 1001;
+  reserved 1000, 1001, 1002;
 }
diff --git a/statsd/src/utils/DbUtils.cpp b/statsd/src/utils/DbUtils.cpp
index bc605672..953924b7 100644
--- a/statsd/src/utils/DbUtils.cpp
+++ b/statsd/src/utils/DbUtils.cpp
@@ -258,17 +258,17 @@ static bool getInsertSqlStmt(sqlite3* db, sqlite3_stmt** stmt, const int64_t met
             }
             switch (fieldValue.mValue.getType()) {
                 case INT:
-                    sqlite3_bind_int(*stmt, index, fieldValue.mValue.int_value);
+                    sqlite3_bind_int(*stmt, index, fieldValue.mValue.get<int32_t>());
                     break;
                 case LONG:
-                    sqlite3_bind_int64(*stmt, index, fieldValue.mValue.long_value);
+                    sqlite3_bind_int64(*stmt, index, fieldValue.mValue.get<int64_t>());
                     break;
                 case STRING:
-                    sqlite3_bind_text(*stmt, index, fieldValue.mValue.str_value.c_str(), -1,
+                    sqlite3_bind_text(*stmt, index, fieldValue.mValue.get<string>().c_str(), -1,
                                       SQLITE_STATIC);
                     break;
                 case FLOAT:
-                    sqlite3_bind_double(*stmt, index, fieldValue.mValue.float_value);
+                    sqlite3_bind_double(*stmt, index, fieldValue.mValue.get<float>());
                     break;
                 default:
                     // Byte array fields are not supported.
diff --git a/statsd/src/utils/MultiConditionTrigger.h b/statsd/src/utils/MultiConditionTrigger.h
index 773197d3..e1591a03 100644
--- a/statsd/src/utils/MultiConditionTrigger.h
+++ b/statsd/src/utils/MultiConditionTrigger.h
@@ -17,6 +17,7 @@
 
 #include <gtest/gtest_prod.h>
 
+#include <functional>
 #include <mutex>
 #include <set>
 #include <thread>
diff --git a/statsd/tests/FieldValue_test.cpp b/statsd/tests/FieldValue_test.cpp
index 539469c8..4d58771b 100644
--- a/statsd/tests/FieldValue_test.cpp
+++ b/statsd/tests/FieldValue_test.cpp
@@ -28,6 +28,7 @@
 #ifdef __ANDROID__
 
 using android::util::ProtoReader;
+using std::string;
 
 namespace android {
 namespace os {
@@ -140,22 +141,22 @@ TEST(AtomMatcherTest, TestFilter_ALL) {
 
     ASSERT_EQ((size_t)7, output.getValues().size());
     EXPECT_EQ((int32_t)0x02010101, output.getValues()[0].mField.getField());
-    EXPECT_EQ((int32_t)1111, output.getValues()[0].mValue.int_value);
+    EXPECT_EQ((int32_t)1111, output.getValues()[0].mValue.get<int32_t>());
     EXPECT_EQ((int32_t)0x02010102, output.getValues()[1].mField.getField());
-    EXPECT_EQ("location1", output.getValues()[1].mValue.str_value);
+    EXPECT_EQ("location1", output.getValues()[1].mValue.get<string>());
 
     EXPECT_EQ((int32_t)0x02010201, output.getValues()[2].mField.getField());
-    EXPECT_EQ((int32_t)2222, output.getValues()[2].mValue.int_value);
+    EXPECT_EQ((int32_t)2222, output.getValues()[2].mValue.get<int32_t>());
     EXPECT_EQ((int32_t)0x02010202, output.getValues()[3].mField.getField());
-    EXPECT_EQ("location2", output.getValues()[3].mValue.str_value);
+    EXPECT_EQ("location2", output.getValues()[3].mValue.get<string>());
 
     EXPECT_EQ((int32_t)0x02010301, output.getValues()[4].mField.getField());
-    EXPECT_EQ((int32_t)3333, output.getValues()[4].mValue.int_value);
+    EXPECT_EQ((int32_t)3333, output.getValues()[4].mValue.get<int32_t>());
     EXPECT_EQ((int32_t)0x02010302, output.getValues()[5].mField.getField());
-    EXPECT_EQ("location3", output.getValues()[5].mValue.str_value);
+    EXPECT_EQ("location3", output.getValues()[5].mValue.get<string>());
 
     EXPECT_EQ((int32_t)0x00020000, output.getValues()[6].mField.getField());
-    EXPECT_EQ("some value", output.getValues()[6].mValue.str_value);
+    EXPECT_EQ("some value", output.getValues()[6].mValue.get<string>());
 }
 
 TEST(AtomMatcherTest, TestFilter_FIRST) {
@@ -185,11 +186,11 @@ TEST(AtomMatcherTest, TestFilter_FIRST) {
 
     ASSERT_EQ((size_t)3, output.getValues().size());
     EXPECT_EQ((int32_t)0x02010101, output.getValues()[0].mField.getField());
-    EXPECT_EQ((int32_t)1111, output.getValues()[0].mValue.int_value);
+    EXPECT_EQ((int32_t)1111, output.getValues()[0].mValue.get<int32_t>());
     EXPECT_EQ((int32_t)0x02010102, output.getValues()[1].mField.getField());
-    EXPECT_EQ("location1", output.getValues()[1].mValue.str_value);
+    EXPECT_EQ("location1", output.getValues()[1].mValue.get<string>());
     EXPECT_EQ((int32_t)0x00020000, output.getValues()[2].mField.getField());
-    EXPECT_EQ("some value", output.getValues()[2].mValue.str_value);
+    EXPECT_EQ("some value", output.getValues()[2].mValue.get<string>());
 };
 
 TEST_GUARDED(AtomMatcherTest, TestFilterRepeated_FIRST, __ANDROID_API_T__) {
@@ -211,7 +212,7 @@ TEST_GUARDED(AtomMatcherTest, TestFilterRepeated_FIRST, __ANDROID_API_T__) {
 
     ASSERT_EQ((size_t)1, output.getValues().size());
     EXPECT_EQ((int32_t)0x01010100, output.getValues()[0].mField.getField());
-    EXPECT_EQ((int32_t)21, output.getValues()[0].mValue.int_value);
+    EXPECT_EQ((int32_t)21, output.getValues()[0].mValue.get<int32_t>());
 }
 
 TEST_GUARDED(AtomMatcherTest, TestFilterRepeated_LAST, __ANDROID_API_T__) {
@@ -233,7 +234,7 @@ TEST_GUARDED(AtomMatcherTest, TestFilterRepeated_LAST, __ANDROID_API_T__) {
 
     ASSERT_EQ((size_t)1, output.getValues().size());
     EXPECT_EQ((int32_t)0x01018000, output.getValues()[0].mField.getField());
-    EXPECT_EQ((int32_t)13, output.getValues()[0].mValue.int_value);
+    EXPECT_EQ((int32_t)13, output.getValues()[0].mValue.get<int32_t>());
 }
 
 TEST_GUARDED(AtomMatcherTest, TestFilterRepeated_ALL, __ANDROID_API_T__) {
@@ -255,11 +256,11 @@ TEST_GUARDED(AtomMatcherTest, TestFilterRepeated_ALL, __ANDROID_API_T__) {
 
     ASSERT_EQ((size_t)3, output.getValues().size());
     EXPECT_EQ((int32_t)0x01010100, output.getValues()[0].mField.getField());
-    EXPECT_EQ((int32_t)21, output.getValues()[0].mValue.int_value);
+    EXPECT_EQ((int32_t)21, output.getValues()[0].mValue.get<int32_t>());
     EXPECT_EQ((int32_t)0x01010200, output.getValues()[1].mField.getField());
-    EXPECT_EQ((int32_t)9, output.getValues()[1].mValue.int_value);
+    EXPECT_EQ((int32_t)9, output.getValues()[1].mValue.get<int32_t>());
     EXPECT_EQ((int32_t)0x01010300, output.getValues()[2].mField.getField());
-    EXPECT_EQ((int32_t)13, output.getValues()[2].mValue.int_value);
+    EXPECT_EQ((int32_t)13, output.getValues()[2].mValue.get<int32_t>());
 }
 
 TEST(AtomMatcherTest, TestFilterWithOneMatcher) {
@@ -281,7 +282,7 @@ TEST(AtomMatcherTest, TestFilterWithOneMatcher) {
 
     EXPECT_TRUE(filterValues(matchers[0], event.getValues(), &value));
     EXPECT_EQ((int32_t)0x20000, value.mField.getField());
-    EXPECT_EQ("some value", value.mValue.str_value);
+    EXPECT_EQ("some value", value.mValue.get<string>());
 }
 
 TEST(AtomMatcherTest, TestFilterWithOneMatcher_PositionFIRST) {
@@ -306,7 +307,7 @@ TEST(AtomMatcherTest, TestFilterWithOneMatcher_PositionFIRST) {
     // Should only match the first field.
     EXPECT_TRUE(filterValues(matchers[0], event.getValues(), &value));
     EXPECT_EQ((int32_t)0x02010101, value.mField.getField());
-    EXPECT_EQ((int32_t)1111, value.mValue.int_value);
+    EXPECT_EQ((int32_t)1111, value.mValue.get<int32_t>());
 }
 
 TEST(AtomMatcherTest, TestFilterWithOneMatcher_PositionLAST) {
@@ -331,7 +332,7 @@ TEST(AtomMatcherTest, TestFilterWithOneMatcher_PositionLAST) {
     // Should only match the last field.
     EXPECT_TRUE(filterValues(matchers[0], event.getValues(), &value));
     EXPECT_EQ((int32_t)0x02018301, value.mField.getField());
-    EXPECT_EQ((int32_t)3333, value.mValue.int_value);
+    EXPECT_EQ((int32_t)3333, value.mValue.get<int32_t>());
 }
 
 TEST(AtomMatcherTest, TestFilterWithOneMatcher_PositionALL) {
@@ -719,16 +720,16 @@ TEST(AtomMatcherTest, TestSubscriberDimensionWrite) {
     ASSERT_EQ(attributionChainParcel.tupleValue.size(), 2);
     checkAttributionNodeInDimensionsValueParcel(attributionChainParcel.tupleValue[0],
                                                 /*nodeDepthInAttributionChain=*/1,
-                                                value1.int_value, value2.str_value);
+                                                value1.get<int32_t>(), value2.get<string>());
     checkAttributionNodeInDimensionsValueParcel(attributionChainParcel.tupleValue[1],
                                                 /*nodeDepthInAttributionChain=*/2,
-                                                value3.int_value, value4.str_value);
+                                                value3.get<int32_t>(), value4.get<string>());
 
     // Check that the float is populated correctly
     StatsDimensionsValueParcel floatParcel = rootParcel.tupleValue[1];
     EXPECT_EQ(floatParcel.field, 2 /*position at depth 0*/);
     EXPECT_EQ(floatParcel.valueType, STATS_DIMENSIONS_VALUE_FLOAT_TYPE);
-    EXPECT_EQ(floatParcel.floatValue, value5.float_value);
+    EXPECT_EQ(floatParcel.floatValue, value5.get<float>());
 }
 
 TEST(AtomMatcherTest, TestWriteDimensionToProto) {
@@ -1326,6 +1327,27 @@ TEST(FieldValueTest, TestShouldKeepSampleByteArray) {
     EXPECT_TRUE(shouldKeepSample(fieldValue2, shardOffset, shardCount));
 }
 
+TEST(FieldValueTest, TestValueType) {
+    Value v(3);
+    EXPECT_EQ(v.getType(), INT);
+
+    v = "foo";
+    EXPECT_EQ(v.getType(), STRING);
+
+    v = (int64_t)25;
+    EXPECT_EQ(v.getType(), LONG);
+
+    v = 0.5f;
+    EXPECT_EQ(v.getType(), FLOAT);
+
+    v = -3.14;
+    EXPECT_EQ(v.getType(), DOUBLE);
+
+    vector<uint8_t> test{'t', 'e', 's', 't'};
+    v = test;
+    EXPECT_EQ(v.getType(), STORAGE);
+}
+
 }  // namespace statsd
 }  // namespace os
 }  // namespace android
diff --git a/statsd/tests/LogEntryMatcher_test.cpp b/statsd/tests/LogEntryMatcher_test.cpp
index e989c9b9..60c68eed 100644
--- a/statsd/tests/LogEntryMatcher_test.cpp
+++ b/statsd/tests/LogEntryMatcher_test.cpp
@@ -25,6 +25,7 @@
 
 using namespace android::os::statsd;
 using std::shared_ptr;
+using std::string;
 using std::unordered_map;
 using std::vector;
 
@@ -1527,13 +1528,13 @@ TEST(AtomMatcherTest, TestStringReplaceRoot) {
 
     const vector<FieldValue>& fieldValues = transformedEvent->getValues();
     ASSERT_EQ(fieldValues.size(), 7);
-    EXPECT_EQ(fieldValues[0].mValue.int_value, 1111);
-    EXPECT_EQ(fieldValues[1].mValue.str_value, "location1");
-    EXPECT_EQ(fieldValues[2].mValue.int_value, 2222);
-    EXPECT_EQ(fieldValues[3].mValue.str_value, "location2");
-    EXPECT_EQ(fieldValues[4].mValue.int_value, 3333);
-    EXPECT_EQ(fieldValues[5].mValue.str_value, "location3");
-    EXPECT_EQ(fieldValues[6].mValue.str_value, "some value");
+    EXPECT_EQ(fieldValues[0].mValue.get<int32_t>(), 1111);
+    EXPECT_EQ(fieldValues[1].mValue.get<string>(), "location1");
+    EXPECT_EQ(fieldValues[2].mValue.get<int32_t>(), 2222);
+    EXPECT_EQ(fieldValues[3].mValue.get<string>(), "location2");
+    EXPECT_EQ(fieldValues[4].mValue.get<int32_t>(), 3333);
+    EXPECT_EQ(fieldValues[5].mValue.get<string>(), "location3");
+    EXPECT_EQ(fieldValues[6].mValue.get<string>(), "some value");
 }
 
 TEST(AtomMatcherTest, TestStringReplaceAttributionTagFirst) {
@@ -1564,13 +1565,13 @@ TEST(AtomMatcherTest, TestStringReplaceAttributionTagFirst) {
     ASSERT_NE(transformedEvent, nullptr);
     const vector<FieldValue>& fieldValues = transformedEvent->getValues();
     ASSERT_EQ(fieldValues.size(), 7);
-    EXPECT_EQ(fieldValues[0].mValue.int_value, 1111);
-    EXPECT_EQ(fieldValues[1].mValue.str_value, "location");
-    EXPECT_EQ(fieldValues[2].mValue.int_value, 2222);
-    EXPECT_EQ(fieldValues[3].mValue.str_value, "location2");
-    EXPECT_EQ(fieldValues[4].mValue.int_value, 3333);
-    EXPECT_EQ(fieldValues[5].mValue.str_value, "location3");
-    EXPECT_EQ(fieldValues[6].mValue.str_value, "some value123");
+    EXPECT_EQ(fieldValues[0].mValue.get<int32_t>(), 1111);
+    EXPECT_EQ(fieldValues[1].mValue.get<string>(), "location");
+    EXPECT_EQ(fieldValues[2].mValue.get<int32_t>(), 2222);
+    EXPECT_EQ(fieldValues[3].mValue.get<string>(), "location2");
+    EXPECT_EQ(fieldValues[4].mValue.get<int32_t>(), 3333);
+    EXPECT_EQ(fieldValues[5].mValue.get<string>(), "location3");
+    EXPECT_EQ(fieldValues[6].mValue.get<string>(), "some value123");
 }
 
 TEST(AtomMatcherTest, TestStringReplaceAttributionTagLast) {
@@ -1602,13 +1603,13 @@ TEST(AtomMatcherTest, TestStringReplaceAttributionTagLast) {
 
     const vector<FieldValue>& fieldValues = transformedEvent->getValues();
     ASSERT_EQ(fieldValues.size(), 7);
-    EXPECT_EQ(fieldValues[0].mValue.int_value, 1111);
-    EXPECT_EQ(fieldValues[1].mValue.str_value, "location1");
-    EXPECT_EQ(fieldValues[2].mValue.int_value, 2222);
-    EXPECT_EQ(fieldValues[3].mValue.str_value, "location2");
-    EXPECT_EQ(fieldValues[4].mValue.int_value, 3333);
-    EXPECT_EQ(fieldValues[5].mValue.str_value, "location");
-    EXPECT_EQ(fieldValues[6].mValue.str_value, "some value123");
+    EXPECT_EQ(fieldValues[0].mValue.get<int32_t>(), 1111);
+    EXPECT_EQ(fieldValues[1].mValue.get<string>(), "location1");
+    EXPECT_EQ(fieldValues[2].mValue.get<int32_t>(), 2222);
+    EXPECT_EQ(fieldValues[3].mValue.get<string>(), "location2");
+    EXPECT_EQ(fieldValues[4].mValue.get<int32_t>(), 3333);
+    EXPECT_EQ(fieldValues[5].mValue.get<string>(), "location");
+    EXPECT_EQ(fieldValues[6].mValue.get<string>(), "some value123");
 }
 
 TEST(AtomMatcherTest, TestStringReplaceAttributionTagAll) {
@@ -1640,13 +1641,13 @@ TEST(AtomMatcherTest, TestStringReplaceAttributionTagAll) {
 
     const vector<FieldValue>& fieldValues = transformedEvent->getValues();
     ASSERT_EQ(fieldValues.size(), 7);
-    EXPECT_EQ(fieldValues[0].mValue.int_value, 1111);
-    EXPECT_EQ(fieldValues[1].mValue.str_value, "location");
-    EXPECT_EQ(fieldValues[2].mValue.int_value, 2222);
-    EXPECT_EQ(fieldValues[3].mValue.str_value, "location");
-    EXPECT_EQ(fieldValues[4].mValue.int_value, 3333);
-    EXPECT_EQ(fieldValues[5].mValue.str_value, "location");
-    EXPECT_EQ(fieldValues[6].mValue.str_value, "some value123");
+    EXPECT_EQ(fieldValues[0].mValue.get<int32_t>(), 1111);
+    EXPECT_EQ(fieldValues[1].mValue.get<string>(), "location");
+    EXPECT_EQ(fieldValues[2].mValue.get<int32_t>(), 2222);
+    EXPECT_EQ(fieldValues[3].mValue.get<string>(), "location");
+    EXPECT_EQ(fieldValues[4].mValue.get<int32_t>(), 3333);
+    EXPECT_EQ(fieldValues[5].mValue.get<string>(), "location");
+    EXPECT_EQ(fieldValues[6].mValue.get<string>(), "some value123");
 }
 
 TEST(AtomMatcherTest, TestStringReplaceNestedAllWithMultipleNestedStringFields) {
@@ -1684,13 +1685,13 @@ TEST(AtomMatcherTest, TestStringReplaceNestedAllWithMultipleNestedStringFields)
 
     const vector<FieldValue>& fieldValues = transformedEvent->getValues();
     ASSERT_EQ(fieldValues.size(), 7);
-    EXPECT_EQ(fieldValues[0].mValue.str_value, "abc1");
-    EXPECT_EQ(fieldValues[1].mValue.str_value, "location");
-    EXPECT_EQ(fieldValues[2].mValue.str_value, "xyz2");
-    EXPECT_EQ(fieldValues[3].mValue.str_value, "location");
-    EXPECT_EQ(fieldValues[4].mValue.str_value, "abc3");
-    EXPECT_EQ(fieldValues[5].mValue.str_value, "location");
-    EXPECT_EQ(fieldValues[6].mValue.str_value, "some value123");
+    EXPECT_EQ(fieldValues[0].mValue.get<string>(), "abc1");
+    EXPECT_EQ(fieldValues[1].mValue.get<string>(), "location");
+    EXPECT_EQ(fieldValues[2].mValue.get<string>(), "xyz2");
+    EXPECT_EQ(fieldValues[3].mValue.get<string>(), "location");
+    EXPECT_EQ(fieldValues[4].mValue.get<string>(), "abc3");
+    EXPECT_EQ(fieldValues[5].mValue.get<string>(), "location");
+    EXPECT_EQ(fieldValues[6].mValue.get<string>(), "some value123");
 }
 
 TEST(AtomMatcherTest, TestStringReplaceRootOnMatchedField) {
@@ -1725,13 +1726,13 @@ TEST(AtomMatcherTest, TestStringReplaceRootOnMatchedField) {
         ASSERT_NE(transformedEvent, nullptr);
         const vector<FieldValue>& fieldValues = transformedEvent->getValues();
         ASSERT_EQ(fieldValues.size(), 7);
-        EXPECT_EQ(fieldValues[0].mValue.int_value, 1111);
-        EXPECT_EQ(fieldValues[1].mValue.str_value, "location1");
-        EXPECT_EQ(fieldValues[2].mValue.int_value, 2222);
-        EXPECT_EQ(fieldValues[3].mValue.str_value, "location2");
-        EXPECT_EQ(fieldValues[4].mValue.int_value, 3333);
-        EXPECT_EQ(fieldValues[5].mValue.str_value, "location3");
-        EXPECT_EQ(fieldValues[6].mValue.str_value, "bar");
+        EXPECT_EQ(fieldValues[0].mValue.get<int32_t>(), 1111);
+        EXPECT_EQ(fieldValues[1].mValue.get<string>(), "location1");
+        EXPECT_EQ(fieldValues[2].mValue.get<int32_t>(), 2222);
+        EXPECT_EQ(fieldValues[3].mValue.get<string>(), "location2");
+        EXPECT_EQ(fieldValues[4].mValue.get<int32_t>(), 3333);
+        EXPECT_EQ(fieldValues[5].mValue.get<string>(), "location3");
+        EXPECT_EQ(fieldValues[6].mValue.get<string>(), "bar");
     }
 }
 
@@ -1773,13 +1774,13 @@ TEST(AtomMatcherTest, TestStringReplaceAttributionTagFirstOnMatchedField) {
         ASSERT_NE(transformedEvent, nullptr);
         const vector<FieldValue>& fieldValues = transformedEvent->getValues();
         ASSERT_EQ(fieldValues.size(), 7);
-        EXPECT_EQ(fieldValues[0].mValue.int_value, 1111);
-        EXPECT_EQ(fieldValues[1].mValue.str_value, "bar");
-        EXPECT_EQ(fieldValues[2].mValue.int_value, 2222);
-        EXPECT_EQ(fieldValues[3].mValue.str_value, "bar2");
-        EXPECT_EQ(fieldValues[4].mValue.int_value, 3333);
-        EXPECT_EQ(fieldValues[5].mValue.str_value, "bar3");
-        EXPECT_EQ(fieldValues[6].mValue.str_value, "bar123");
+        EXPECT_EQ(fieldValues[0].mValue.get<int32_t>(), 1111);
+        EXPECT_EQ(fieldValues[1].mValue.get<string>(), "bar");
+        EXPECT_EQ(fieldValues[2].mValue.get<int32_t>(), 2222);
+        EXPECT_EQ(fieldValues[3].mValue.get<string>(), "bar2");
+        EXPECT_EQ(fieldValues[4].mValue.get<int32_t>(), 3333);
+        EXPECT_EQ(fieldValues[5].mValue.get<string>(), "bar3");
+        EXPECT_EQ(fieldValues[6].mValue.get<string>(), "bar123");
     }
 }
 
@@ -1821,13 +1822,13 @@ TEST(AtomMatcherTest, TestStringReplaceAttributionTagLastOnMatchedField) {
         ASSERT_NE(transformedEvent, nullptr);
         const vector<FieldValue>& fieldValues = transformedEvent->getValues();
         ASSERT_EQ(fieldValues.size(), 7);
-        EXPECT_EQ(fieldValues[0].mValue.int_value, 1111);
-        EXPECT_EQ(fieldValues[1].mValue.str_value, "bar1");
-        EXPECT_EQ(fieldValues[2].mValue.int_value, 2222);
-        EXPECT_EQ(fieldValues[3].mValue.str_value, "bar2");
-        EXPECT_EQ(fieldValues[4].mValue.int_value, 3333);
-        EXPECT_EQ(fieldValues[5].mValue.str_value, "bar");
-        EXPECT_EQ(fieldValues[6].mValue.str_value, "bar123");
+        EXPECT_EQ(fieldValues[0].mValue.get<int32_t>(), 1111);
+        EXPECT_EQ(fieldValues[1].mValue.get<string>(), "bar1");
+        EXPECT_EQ(fieldValues[2].mValue.get<int32_t>(), 2222);
+        EXPECT_EQ(fieldValues[3].mValue.get<string>(), "bar2");
+        EXPECT_EQ(fieldValues[4].mValue.get<int32_t>(), 3333);
+        EXPECT_EQ(fieldValues[5].mValue.get<string>(), "bar");
+        EXPECT_EQ(fieldValues[6].mValue.get<string>(), "bar123");
     }
 }
 
@@ -1869,13 +1870,13 @@ TEST(AtomMatcherTest, TestStringReplaceAttributionTagAnyOnMatchedField) {
         ASSERT_NE(transformedEvent, nullptr);
         const vector<FieldValue>& fieldValues = transformedEvent->getValues();
         ASSERT_EQ(fieldValues.size(), 7);
-        EXPECT_EQ(fieldValues[0].mValue.int_value, 1111);
-        EXPECT_EQ(fieldValues[1].mValue.str_value, "foo");
-        EXPECT_EQ(fieldValues[2].mValue.int_value, 2222);
-        EXPECT_EQ(fieldValues[3].mValue.str_value, "bar");
-        EXPECT_EQ(fieldValues[4].mValue.int_value, 3333);
-        EXPECT_EQ(fieldValues[5].mValue.str_value, "foo");
-        EXPECT_EQ(fieldValues[6].mValue.str_value, "bar123");
+        EXPECT_EQ(fieldValues[0].mValue.get<int32_t>(), 1111);
+        EXPECT_EQ(fieldValues[1].mValue.get<string>(), "foo");
+        EXPECT_EQ(fieldValues[2].mValue.get<int32_t>(), 2222);
+        EXPECT_EQ(fieldValues[3].mValue.get<string>(), "bar");
+        EXPECT_EQ(fieldValues[4].mValue.get<int32_t>(), 3333);
+        EXPECT_EQ(fieldValues[5].mValue.get<string>(), "foo");
+        EXPECT_EQ(fieldValues[6].mValue.get<string>(), "bar123");
     }
 }
 
@@ -1928,13 +1929,13 @@ TEST(AtomMatcherTest, TestStringReplaceAttributionTagAnyAndRootOnMatchedFields)
         ASSERT_NE(transformedEvent, nullptr);
         const vector<FieldValue>& fieldValues = transformedEvent->getValues();
         ASSERT_EQ(fieldValues.size(), 7);
-        EXPECT_EQ(fieldValues[0].mValue.int_value, 1111);
-        EXPECT_EQ(fieldValues[1].mValue.str_value, "foo");
-        EXPECT_EQ(fieldValues[2].mValue.int_value, 2222);
-        EXPECT_EQ(fieldValues[3].mValue.str_value, "bar");
-        EXPECT_EQ(fieldValues[4].mValue.int_value, 3333);
-        EXPECT_EQ(fieldValues[5].mValue.str_value, "foo");
-        EXPECT_EQ(fieldValues[6].mValue.str_value, "blah");
+        EXPECT_EQ(fieldValues[0].mValue.get<int32_t>(), 1111);
+        EXPECT_EQ(fieldValues[1].mValue.get<string>(), "foo");
+        EXPECT_EQ(fieldValues[2].mValue.get<int32_t>(), 2222);
+        EXPECT_EQ(fieldValues[3].mValue.get<string>(), "bar");
+        EXPECT_EQ(fieldValues[4].mValue.get<int32_t>(), 3333);
+        EXPECT_EQ(fieldValues[5].mValue.get<string>(), "foo");
+        EXPECT_EQ(fieldValues[6].mValue.get<string>(), "blah");
     }
 }
 
@@ -1985,13 +1986,13 @@ TEST(AtomMatcherTest, TestStringReplaceAttributionTagAnyWithAttributionUidValueM
         ASSERT_NE(transformedEvent, nullptr);
         const vector<FieldValue>& fieldValues = transformedEvent->getValues();
         ASSERT_EQ(fieldValues.size(), 7);
-        EXPECT_EQ(fieldValues[0].mValue.int_value, 1111);
-        EXPECT_EQ(fieldValues[1].mValue.str_value, "foo");
-        EXPECT_EQ(fieldValues[2].mValue.int_value, 2222);
-        EXPECT_EQ(fieldValues[3].mValue.str_value, "bar");
-        EXPECT_EQ(fieldValues[4].mValue.int_value, 3333);
-        EXPECT_EQ(fieldValues[5].mValue.str_value, "foo");
-        EXPECT_EQ(fieldValues[6].mValue.str_value, "bar123");
+        EXPECT_EQ(fieldValues[0].mValue.get<int32_t>(), 1111);
+        EXPECT_EQ(fieldValues[1].mValue.get<string>(), "foo");
+        EXPECT_EQ(fieldValues[2].mValue.get<int32_t>(), 2222);
+        EXPECT_EQ(fieldValues[3].mValue.get<string>(), "bar");
+        EXPECT_EQ(fieldValues[4].mValue.get<int32_t>(), 3333);
+        EXPECT_EQ(fieldValues[5].mValue.get<string>(), "foo");
+        EXPECT_EQ(fieldValues[6].mValue.get<string>(), "bar123");
     }
 }
 
diff --git a/statsd/tests/LogEvent_test.cpp b/statsd/tests/LogEvent_test.cpp
index 292eea16..f4bbecfd 100644
--- a/statsd/tests/LogEvent_test.cpp
+++ b/statsd/tests/LogEvent_test.cpp
@@ -239,25 +239,25 @@ TEST_P(LogEventTest, TestPrimitiveParsing) {
     Field expectedField = getField(100, {1, 1, 1}, 0, {false, false, false});
     EXPECT_EQ(expectedField, int32Item.mField);
     EXPECT_EQ(Type::INT, int32Item.mValue.getType());
-    EXPECT_EQ(10, int32Item.mValue.int_value);
+    EXPECT_EQ(10, int32Item.mValue.get<int32_t>());
 
     const FieldValue& int64Item = values[1];
     expectedField = getField(100, {2, 1, 1}, 0, {false, false, false});
     EXPECT_EQ(expectedField, int64Item.mField);
     EXPECT_EQ(Type::LONG, int64Item.mValue.getType());
-    EXPECT_EQ(0x123456789, int64Item.mValue.long_value);
+    EXPECT_EQ(0x123456789, int64Item.mValue.get<int64_t>());
 
     const FieldValue& floatItem = values[2];
     expectedField = getField(100, {3, 1, 1}, 0, {false, false, false});
     EXPECT_EQ(expectedField, floatItem.mField);
     EXPECT_EQ(Type::FLOAT, floatItem.mValue.getType());
-    EXPECT_EQ(2.0, floatItem.mValue.float_value);
+    EXPECT_EQ(2.0, floatItem.mValue.get<float>());
 
     const FieldValue& boolItem = values[3];
     expectedField = getField(100, {4, 1, 1}, 0, {true, false, false});
     EXPECT_EQ(expectedField, boolItem.mField);
     EXPECT_EQ(Type::INT, boolItem.mValue.getType());  // FieldValue does not support boolean type
-    EXPECT_EQ(1, boolItem.mValue.int_value);
+    EXPECT_EQ(1, boolItem.mValue.get<int32_t>());
 
     AStatsEvent_release(event);
 }
@@ -340,14 +340,14 @@ TEST_P(LogEventTest, TestStringAndByteArrayParsing) {
     Field expectedField = getField(100, {1, 1, 1}, 0, {false, false, false});
     EXPECT_EQ(expectedField, stringItem.mField);
     EXPECT_EQ(Type::STRING, stringItem.mValue.getType());
-    EXPECT_EQ(str, stringItem.mValue.str_value);
+    EXPECT_EQ(str, stringItem.mValue.get<string>());
 
     const FieldValue& storageItem = values[1];
     expectedField = getField(100, {2, 1, 1}, 0, {true, false, false});
     EXPECT_EQ(expectedField, storageItem.mField);
     EXPECT_EQ(Type::STORAGE, storageItem.mValue.getType());
     vector<uint8_t> expectedValue = {'t', 'e', 's', 't'};
-    EXPECT_EQ(expectedValue, storageItem.mValue.storage_value);
+    EXPECT_EQ(expectedValue, storageItem.mValue.get<vector<uint8_t>>());
 
     AStatsEvent_release(event);
 }
@@ -377,7 +377,7 @@ TEST_P(LogEventTest, TestEmptyString) {
     Field expectedField = getField(100, {1, 1, 1}, 0, {true, false, false});
     EXPECT_EQ(expectedField, item.mField);
     EXPECT_EQ(Type::STRING, item.mValue.getType());
-    EXPECT_EQ(empty, item.mValue.str_value);
+    EXPECT_EQ(empty, item.mValue.get<string>());
 
     AStatsEvent_release(event);
 }
@@ -407,7 +407,7 @@ TEST_P(LogEventTest, TestByteArrayWithNullCharacter) {
     EXPECT_EQ(expectedField, item.mField);
     EXPECT_EQ(Type::STORAGE, item.mValue.getType());
     vector<uint8_t> expectedValue(message, message + 5);
-    EXPECT_EQ(expectedValue, item.mValue.storage_value);
+    EXPECT_EQ(expectedValue, item.mValue.get<vector<uint8_t>>());
 
     AStatsEvent_release(event);
 }
@@ -467,26 +467,26 @@ TEST_P(LogEventTest, TestAttributionChain) {
     Field expectedField = getField(100, {1, 1, 1}, 2, {true, false, false});
     EXPECT_EQ(expectedField, uid1Item.mField);
     EXPECT_EQ(Type::INT, uid1Item.mValue.getType());
-    EXPECT_EQ(1001, uid1Item.mValue.int_value);
+    EXPECT_EQ(1001, uid1Item.mValue.get<int32_t>());
 
     const FieldValue& tag1Item = values[1];
     expectedField = getField(100, {1, 1, 2}, 2, {true, false, true});
     EXPECT_EQ(expectedField, tag1Item.mField);
     EXPECT_EQ(Type::STRING, tag1Item.mValue.getType());
-    EXPECT_EQ(tag1, tag1Item.mValue.str_value);
+    EXPECT_EQ(tag1, tag1Item.mValue.get<string>());
 
     // Check second attribution nodes
     const FieldValue& uid2Item = values[2];
     expectedField = getField(100, {1, 2, 1}, 2, {true, true, false});
     EXPECT_EQ(expectedField, uid2Item.mField);
     EXPECT_EQ(Type::INT, uid2Item.mValue.getType());
-    EXPECT_EQ(1002, uid2Item.mValue.int_value);
+    EXPECT_EQ(1002, uid2Item.mValue.get<int32_t>());
 
     const FieldValue& tag2Item = values[3];
     expectedField = getField(100, {1, 2, 2}, 2, {true, true, true});
     EXPECT_EQ(expectedField, tag2Item.mField);
     EXPECT_EQ(Type::STRING, tag2Item.mValue.getType());
-    EXPECT_EQ(tag2, tag2Item.mValue.str_value);
+    EXPECT_EQ(tag2, tag2Item.mValue.get<string>());
 
     AStatsEvent_release(event);
 }
@@ -573,63 +573,63 @@ TEST_P_GUARDED(LogEventTest, TestArrayParsing, __ANDROID_API_T__) {
     Field expectedField = getField(100, {1, 1, 1}, 1, {false, false, false});
     EXPECT_EQ(expectedField, int32ArrayItem1.mField);
     EXPECT_EQ(Type::INT, int32ArrayItem1.mValue.getType());
-    EXPECT_EQ(3, int32ArrayItem1.mValue.int_value);
+    EXPECT_EQ(3, int32ArrayItem1.mValue.get<int32_t>());
 
     const FieldValue& int32ArrayItem2 = values[1];
     expectedField = getField(100, {1, 2, 1}, 1, {false, true, false});
     EXPECT_EQ(expectedField, int32ArrayItem2.mField);
     EXPECT_EQ(Type::INT, int32ArrayItem2.mValue.getType());
-    EXPECT_EQ(6, int32ArrayItem2.mValue.int_value);
+    EXPECT_EQ(6, int32ArrayItem2.mValue.get<int32_t>());
 
     const FieldValue& int64ArrayItem1 = values[2];
     expectedField = getField(100, {2, 1, 1}, 1, {false, false, false});
     EXPECT_EQ(expectedField, int64ArrayItem1.mField);
     EXPECT_EQ(Type::LONG, int64ArrayItem1.mValue.getType());
-    EXPECT_EQ(1000L, int64ArrayItem1.mValue.long_value);
+    EXPECT_EQ(1000L, int64ArrayItem1.mValue.get<int64_t>());
 
     const FieldValue& int64ArrayItem2 = values[3];
     expectedField = getField(100, {2, 2, 1}, 1, {false, true, false});
     EXPECT_EQ(expectedField, int64ArrayItem2.mField);
     EXPECT_EQ(Type::LONG, int64ArrayItem2.mValue.getType());
-    EXPECT_EQ(1002L, int64ArrayItem2.mValue.long_value);
+    EXPECT_EQ(1002L, int64ArrayItem2.mValue.get<int64_t>());
 
     const FieldValue& floatArrayItem1 = values[4];
     expectedField = getField(100, {3, 1, 1}, 1, {false, false, false});
     EXPECT_EQ(expectedField, floatArrayItem1.mField);
     EXPECT_EQ(Type::FLOAT, floatArrayItem1.mValue.getType());
-    EXPECT_EQ(0.3f, floatArrayItem1.mValue.float_value);
+    EXPECT_EQ(0.3f, floatArrayItem1.mValue.get<float>());
 
     const FieldValue& floatArrayItem2 = values[5];
     expectedField = getField(100, {3, 2, 1}, 1, {false, true, false});
     EXPECT_EQ(expectedField, floatArrayItem2.mField);
     EXPECT_EQ(Type::FLOAT, floatArrayItem2.mValue.getType());
-    EXPECT_EQ(0.09f, floatArrayItem2.mValue.float_value);
+    EXPECT_EQ(0.09f, floatArrayItem2.mValue.get<float>());
 
     const FieldValue& boolArrayItem1 = values[6];
     expectedField = getField(100, {4, 1, 1}, 1, {false, false, false});
     EXPECT_EQ(expectedField, boolArrayItem1.mField);
     EXPECT_EQ(Type::INT,
               boolArrayItem1.mValue.getType());  // FieldValue does not support boolean type
-    EXPECT_EQ(false, boolArrayItem1.mValue.int_value);
+    EXPECT_EQ(false, boolArrayItem1.mValue.get<int32_t>());
 
     const FieldValue& boolArrayItem2 = values[7];
     expectedField = getField(100, {4, 2, 1}, 1, {false, true, false});
     EXPECT_EQ(expectedField, boolArrayItem2.mField);
     EXPECT_EQ(Type::INT,
               boolArrayItem2.mValue.getType());  // FieldValue does not support boolean type
-    EXPECT_EQ(true, boolArrayItem2.mValue.int_value);
+    EXPECT_EQ(true, boolArrayItem2.mValue.get<int32_t>());
 
     const FieldValue& stringArrayItem1 = values[8];
     expectedField = getField(100, {5, 1, 1}, 1, {true, false, false});
     EXPECT_EQ(expectedField, stringArrayItem1.mField);
     EXPECT_EQ(Type::STRING, stringArrayItem1.mValue.getType());
-    EXPECT_EQ("str1", stringArrayItem1.mValue.str_value);
+    EXPECT_EQ("str1", stringArrayItem1.mValue.get<string>());
 
     const FieldValue& stringArrayItem2 = values[9];
     expectedField = getField(100, {5, 2, 1}, 1, {true, true, false});
     EXPECT_EQ(expectedField, stringArrayItem2.mField);
     EXPECT_EQ(Type::STRING, stringArrayItem2.mValue.getType());
-    EXPECT_EQ("str2", stringArrayItem2.mValue.str_value);
+    EXPECT_EQ("str2", stringArrayItem2.mValue.get<string>());
 }
 
 TEST_P_GUARDED(LogEventTest, TestEmptyStringArray, __ANDROID_API_T__) {
@@ -660,13 +660,13 @@ TEST_P_GUARDED(LogEventTest, TestEmptyStringArray, __ANDROID_API_T__) {
     Field expectedField = getField(100, {1, 1, 1}, 1, {true, false, false});
     EXPECT_EQ(expectedField, stringArrayItem1.mField);
     EXPECT_EQ(Type::STRING, stringArrayItem1.mValue.getType());
-    EXPECT_EQ(empty, stringArrayItem1.mValue.str_value);
+    EXPECT_EQ(empty, stringArrayItem1.mValue.get<string>());
 
     const FieldValue& stringArrayItem2 = values[1];
     expectedField = getField(100, {1, 2, 1}, 1, {true, true, false});
     EXPECT_EQ(expectedField, stringArrayItem2.mField);
     EXPECT_EQ(Type::STRING, stringArrayItem2.mValue.getType());
-    EXPECT_EQ(empty, stringArrayItem2.mValue.str_value);
+    EXPECT_EQ(empty, stringArrayItem2.mValue.get<string>());
 
     AStatsEvent_release(event);
 }
diff --git a/statsd/tests/StatsLogProcessor_test.cpp b/statsd/tests/StatsLogProcessor_test.cpp
index 43ef4ddb..e59666d4 100644
--- a/statsd/tests/StatsLogProcessor_test.cpp
+++ b/statsd/tests/StatsLogProcessor_test.cpp
@@ -1897,9 +1897,9 @@ TEST(StatsLogProcessorTest_mapIsolatedUidToHostUid, LogHostUid) {
 
     const vector<FieldValue>* actualFieldValues = &logEvent->getValues();
     ASSERT_EQ(3, actualFieldValues->size());
-    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.int_value);
-    EXPECT_EQ(field1, actualFieldValues->at(1).mValue.int_value);
-    EXPECT_EQ(field2, actualFieldValues->at(2).mValue.int_value);
+    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.get<int32_t>());
+    EXPECT_EQ(field1, actualFieldValues->at(1).mValue.get<int32_t>());
+    EXPECT_EQ(field2, actualFieldValues->at(2).mValue.get<int32_t>());
 }
 
 TEST(StatsLogProcessorTest_mapIsolatedUidToHostUid, LogIsolatedUid) {
@@ -1923,9 +1923,9 @@ TEST(StatsLogProcessorTest_mapIsolatedUidToHostUid, LogIsolatedUid) {
 
     const vector<FieldValue>* actualFieldValues = &logEvent->getValues();
     ASSERT_EQ(3, actualFieldValues->size());
-    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.int_value);
-    EXPECT_EQ(field1, actualFieldValues->at(1).mValue.int_value);
-    EXPECT_EQ(field2, actualFieldValues->at(2).mValue.int_value);
+    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.get<int32_t>());
+    EXPECT_EQ(field1, actualFieldValues->at(1).mValue.get<int32_t>());
+    EXPECT_EQ(field2, actualFieldValues->at(2).mValue.get<int32_t>());
 }
 
 TEST(StatsLogProcessorTest_mapIsolatedUidToHostUid, LogThreeIsolatedUids) {
@@ -1953,11 +1953,11 @@ TEST(StatsLogProcessorTest_mapIsolatedUidToHostUid, LogThreeIsolatedUids) {
 
     const vector<FieldValue>* actualFieldValues = &logEvent->getValues();
     ASSERT_EQ(5, actualFieldValues->size());
-    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.int_value);
-    EXPECT_EQ(field1, actualFieldValues->at(1).mValue.int_value);
-    EXPECT_EQ(field2, actualFieldValues->at(2).mValue.int_value);
-    EXPECT_EQ(hostUid2, actualFieldValues->at(3).mValue.int_value);
-    EXPECT_EQ(hostUid3, actualFieldValues->at(4).mValue.int_value);
+    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.get<int32_t>());
+    EXPECT_EQ(field1, actualFieldValues->at(1).mValue.get<int32_t>());
+    EXPECT_EQ(field2, actualFieldValues->at(2).mValue.get<int32_t>());
+    EXPECT_EQ(hostUid2, actualFieldValues->at(3).mValue.get<int32_t>());
+    EXPECT_EQ(hostUid3, actualFieldValues->at(4).mValue.get<int32_t>());
 }
 
 TEST(StatsLogProcessorTest_mapIsolatedUidToHostUid, LogHostUidAttributionChain) {
@@ -1981,12 +1981,12 @@ TEST(StatsLogProcessorTest_mapIsolatedUidToHostUid, LogHostUidAttributionChain)
 
     const vector<FieldValue>* actualFieldValues = &logEvent->getValues();
     ASSERT_EQ(6, actualFieldValues->size());
-    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.int_value);
-    EXPECT_EQ("tag1", actualFieldValues->at(1).mValue.str_value);
-    EXPECT_EQ(200, actualFieldValues->at(2).mValue.int_value);
-    EXPECT_EQ("tag2", actualFieldValues->at(3).mValue.str_value);
-    EXPECT_EQ(field1, actualFieldValues->at(4).mValue.int_value);
-    EXPECT_EQ(field2, actualFieldValues->at(5).mValue.int_value);
+    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.get<int32_t>());
+    EXPECT_EQ("tag1", actualFieldValues->at(1).mValue.get<string>());
+    EXPECT_EQ(200, actualFieldValues->at(2).mValue.get<int32_t>());
+    EXPECT_EQ("tag2", actualFieldValues->at(3).mValue.get<string>());
+    EXPECT_EQ(field1, actualFieldValues->at(4).mValue.get<int32_t>());
+    EXPECT_EQ(field2, actualFieldValues->at(5).mValue.get<int32_t>());
 }
 
 TEST(StatsLogProcessorTest_mapIsolatedUidToHostUid, LogIsolatedUidAttributionChain) {
@@ -2009,12 +2009,12 @@ TEST(StatsLogProcessorTest_mapIsolatedUidToHostUid, LogIsolatedUidAttributionCha
 
     const vector<FieldValue>* actualFieldValues = &logEvent->getValues();
     ASSERT_EQ(6, actualFieldValues->size());
-    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.int_value);
-    EXPECT_EQ("tag1", actualFieldValues->at(1).mValue.str_value);
-    EXPECT_EQ(200, actualFieldValues->at(2).mValue.int_value);
-    EXPECT_EQ("tag2", actualFieldValues->at(3).mValue.str_value);
-    EXPECT_EQ(field1, actualFieldValues->at(4).mValue.int_value);
-    EXPECT_EQ(field2, actualFieldValues->at(5).mValue.int_value);
+    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.get<int32_t>());
+    EXPECT_EQ("tag1", actualFieldValues->at(1).mValue.get<string>());
+    EXPECT_EQ(200, actualFieldValues->at(2).mValue.get<int32_t>());
+    EXPECT_EQ("tag2", actualFieldValues->at(3).mValue.get<string>());
+    EXPECT_EQ(field1, actualFieldValues->at(4).mValue.get<int32_t>());
+    EXPECT_EQ(field2, actualFieldValues->at(5).mValue.get<int32_t>());
 }
 
 /* *
@@ -2057,7 +2057,7 @@ TEST_GUARDED(StatsLogProcessorTest_mapIsolatedUidToHostUid, LogRepeatedUidField,
 
     actualFieldValues = &logEvent->getValues();
     ASSERT_EQ(1, actualFieldValues->size());
-    EXPECT_EQ(hostUid1, actualFieldValues->at(0).mValue.int_value);
+    EXPECT_EQ(hostUid1, actualFieldValues->at(0).mValue.get<int32_t>());
 
     // Single isolated uid.
     logEvent = makeRepeatedUidLogEvent(atomId, eventTimeNs, {isolatedUid1});
@@ -2065,7 +2065,7 @@ TEST_GUARDED(StatsLogProcessorTest_mapIsolatedUidToHostUid, LogRepeatedUidField,
 
     actualFieldValues = &logEvent->getValues();
     ASSERT_EQ(1, actualFieldValues->size());
-    EXPECT_EQ(hostUid1, actualFieldValues->at(0).mValue.int_value);
+    EXPECT_EQ(hostUid1, actualFieldValues->at(0).mValue.get<int32_t>());
 
     // Multiple host uids.
     logEvent = makeRepeatedUidLogEvent(atomId, eventTimeNs, {hostUid1, hostUid2});
@@ -2073,8 +2073,8 @@ TEST_GUARDED(StatsLogProcessorTest_mapIsolatedUidToHostUid, LogRepeatedUidField,
 
     actualFieldValues = &logEvent->getValues();
     ASSERT_EQ(2, actualFieldValues->size());
-    EXPECT_EQ(hostUid1, actualFieldValues->at(0).mValue.int_value);
-    EXPECT_EQ(hostUid2, actualFieldValues->at(1).mValue.int_value);
+    EXPECT_EQ(hostUid1, actualFieldValues->at(0).mValue.get<int32_t>());
+    EXPECT_EQ(hostUid2, actualFieldValues->at(1).mValue.get<int32_t>());
 
     // Multiple isolated uids.
     logEvent = makeRepeatedUidLogEvent(atomId, eventTimeNs, {isolatedUid1, isolatedUid2});
@@ -2082,8 +2082,8 @@ TEST_GUARDED(StatsLogProcessorTest_mapIsolatedUidToHostUid, LogRepeatedUidField,
 
     actualFieldValues = &logEvent->getValues();
     ASSERT_EQ(2, actualFieldValues->size());
-    EXPECT_EQ(hostUid1, actualFieldValues->at(0).mValue.int_value);
-    EXPECT_EQ(hostUid2, actualFieldValues->at(1).mValue.int_value);
+    EXPECT_EQ(hostUid1, actualFieldValues->at(0).mValue.get<int32_t>());
+    EXPECT_EQ(hostUid2, actualFieldValues->at(1).mValue.get<int32_t>());
 
     // Multiple host and isolated uids.
     logEvent = makeRepeatedUidLogEvent(atomId, eventTimeNs,
@@ -2092,10 +2092,10 @@ TEST_GUARDED(StatsLogProcessorTest_mapIsolatedUidToHostUid, LogRepeatedUidField,
 
     actualFieldValues = &logEvent->getValues();
     ASSERT_EQ(4, actualFieldValues->size());
-    EXPECT_EQ(hostUid1, actualFieldValues->at(0).mValue.int_value);
-    EXPECT_EQ(hostUid2, actualFieldValues->at(1).mValue.int_value);
-    EXPECT_EQ(hostUid2, actualFieldValues->at(2).mValue.int_value);
-    EXPECT_EQ(hostUid1, actualFieldValues->at(3).mValue.int_value);
+    EXPECT_EQ(hostUid1, actualFieldValues->at(0).mValue.get<int32_t>());
+    EXPECT_EQ(hostUid2, actualFieldValues->at(1).mValue.get<int32_t>());
+    EXPECT_EQ(hostUid2, actualFieldValues->at(2).mValue.get<int32_t>());
+    EXPECT_EQ(hostUid1, actualFieldValues->at(3).mValue.get<int32_t>());
 }
 
 TEST(StatsLogProcessorTest, TestDumpReportWithoutErasingDataDoesNotUpdateTimestamp) {
@@ -2152,15 +2152,17 @@ TEST(StatsLogProcessorTest, TestDataCorruptedEnum) {
     StatsdStats::getInstance().noteEventQueueOverflow(/*oldestEventTimestampNs=*/0, /*atomId=*/100);
     StatsdStats::getInstance().noteLogLost(/*wallClockTimeSec=*/0, /*count=*/1, /*lastError=*/0,
                                            /*lastTag=*/0, /*uid=*/0, /*pid=*/0);
+    StatsdStats::getInstance().noteSystemServerRestart(/*timeSec=*/1);
     vector<uint8_t> bytes;
     ConfigMetricsReportList output;
     processor->onDumpReport(cfgKey, 3, true, true, ADB_DUMP, FAST, &bytes);
 
     output.ParseFromArray(bytes.data(), bytes.size());
     ASSERT_EQ(output.reports_size(), 1);
-    ASSERT_EQ(output.reports(0).data_corrupted_reason().size(), 2);
+    ASSERT_EQ(output.reports(0).data_corrupted_reason().size(), 3);
     EXPECT_EQ(output.reports(0).data_corrupted_reason(0), DATA_CORRUPTED_EVENT_QUEUE_OVERFLOW);
     EXPECT_EQ(output.reports(0).data_corrupted_reason(1), DATA_CORRUPTED_SOCKET_LOSS);
+    EXPECT_EQ(output.reports(0).data_corrupted_reason(2), DATA_CORRUPTED_SYSTEM_SERVER_CRASH);
 }
 
 class StatsLogProcessorTestRestricted : public Test {
diff --git a/statsd/tests/e2e/Anomaly_count_e2e_test.cpp b/statsd/tests/e2e/Anomaly_count_e2e_test.cpp
index 97198887..c593b53a 100644
--- a/statsd/tests/e2e/Anomaly_count_e2e_test.cpp
+++ b/statsd/tests/e2e/Anomaly_count_e2e_test.cpp
@@ -325,7 +325,7 @@ TEST(AnomalyCountDetectionE2eTest, TestCountMetric_save_refractory_to_disk) {
     metadata::FieldValue dimKeyInWhat = metadataDimKey.dimension_key_in_what(0);
     EXPECT_EQ(dimKeyInWhat.field().tag(), fieldValue1.mField.getTag());
     EXPECT_EQ(dimKeyInWhat.field().field(), fieldValue1.mField.getField());
-    EXPECT_EQ(dimKeyInWhat.value_int(), fieldValue1.mValue.int_value);
+    EXPECT_EQ(dimKeyInWhat.value_int(), fieldValue1.mValue.get<int32_t>());
 }
 
 TEST(AnomalyCountDetectionE2eTest, TestCountMetric_load_refractory_from_disk) {
diff --git a/statsd/tests/e2e/DurationMetric_e2e_test.cpp b/statsd/tests/e2e/DurationMetric_e2e_test.cpp
index 6b93dd3c..a4e89d65 100644
--- a/statsd/tests/e2e/DurationMetric_e2e_test.cpp
+++ b/statsd/tests/e2e/DurationMetric_e2e_test.cpp
@@ -62,7 +62,7 @@ TEST(DurationMetricE2eTest, TestOneBucket) {
     ASSERT_EQ(metricsManager->mAllMetricProducers.size(), 1);
     sp<MetricProducer> metricProducer = metricsManager->mAllMetricProducers[0];
     EXPECT_TRUE(metricsManager->isActive());
-    EXPECT_TRUE(metricProducer->mIsActive);
+    EXPECT_TRUE(metricProducer->isActive());
 
     std::unique_ptr<LogEvent> event;
 
@@ -110,6 +110,83 @@ TEST(DurationMetricE2eTest, TestOneBucket) {
     EXPECT_EQ(baseTimeNs + bucketSizeNs, data.bucket_info(0).end_bucket_elapsed_nanos());
 }
 
+TEST(DurationMetricE2eTest, TestOneBucketDifferentAtomsForPredicate) {
+    StatsdConfig config;
+
+    auto startMatcher = CreateScreenTurnedOnAtomMatcher();
+    auto stopMatcher = CreateBatteryStateNoneMatcher();
+    *config.add_atom_matcher() = startMatcher;
+    *config.add_atom_matcher() = stopMatcher;
+
+    Predicate durationPredicate;
+    durationPredicate.set_id(StringToId("ScreenIsOn"));
+    durationPredicate.mutable_simple_predicate()->set_start(StringToId("ScreenTurnedOn"));
+    durationPredicate.mutable_simple_predicate()->set_stop(StringToId("BatteryPluggedNone"));
+
+    *config.add_predicate() = durationPredicate;
+
+    int64_t metricId = 123456;
+    auto durationMetric = config.add_duration_metric();
+    durationMetric->set_id(metricId);
+    durationMetric->set_what(durationPredicate.id());
+    durationMetric->set_bucket(FIVE_MINUTES);
+    durationMetric->set_aggregation_type(DurationMetric_AggregationType_SUM);
+
+    const int64_t baseTimeNs = 0;                                   // 0:00
+    const int64_t configAddedTimeNs = baseTimeNs + 1 * NS_PER_SEC;  // 0:01
+    const int64_t bucketSizeNs =
+            TimeUnitToBucketSizeInMillis(config.duration_metric(0).bucket()) * 1000LL * 1000LL;
+
+    int uid = 12345;
+    int64_t cfgId = 98765;
+    ConfigKey cfgKey(uid, cfgId);
+
+    auto processor = CreateStatsLogProcessor(baseTimeNs, configAddedTimeNs, config, cfgKey);
+
+    std::unique_ptr<LogEvent> event;
+
+    // Screen is off at start of bucket.
+    event = CreateScreenStateChangedEvent(configAddedTimeNs,
+                                          android::view::DISPLAY_STATE_OFF);  // 0:01
+    processor->OnLogEvent(event.get());
+
+    // Turn screen on.
+    const int64_t durationStartNs = configAddedTimeNs + 10 * NS_PER_SEC;  // 0:11
+    event = CreateScreenStateChangedEvent(durationStartNs, android::view::DISPLAY_STATE_ON);
+    processor->OnLogEvent(event.get());
+
+    // Change BatteryPluggedState to trigger stop predicate
+    const int64_t durationEndNs = durationStartNs + 30 * NS_PER_SEC;  // 0:41
+    event = CreateBatteryStateChangedEvent(durationEndNs,
+                                           BatteryPluggedStateEnum::BATTERY_PLUGGED_NONE);  // 2:00
+
+    processor->OnLogEvent(event.get());
+
+    ConfigMetricsReportList reports;
+    vector<uint8_t> buffer;
+    processor->onDumpReport(cfgKey, configAddedTimeNs + bucketSizeNs + 1 * NS_PER_SEC, false, true,
+                            ADB_DUMP, FAST, &buffer);  // 5:01
+    EXPECT_TRUE(buffer.size() > 0);
+    EXPECT_TRUE(reports.ParseFromArray(&buffer[0], buffer.size()));
+    backfillDimensionPath(&reports);
+    backfillStartEndTimestamp(&reports);
+    ASSERT_EQ(1, reports.reports_size());
+    ASSERT_EQ(1, reports.reports(0).metrics_size());
+    EXPECT_TRUE(reports.reports(0).metrics(0).has_estimated_data_bytes());
+    EXPECT_EQ(metricId, reports.reports(0).metrics(0).metric_id());
+    EXPECT_TRUE(reports.reports(0).metrics(0).has_duration_metrics());
+
+    StatsLogReport::DurationMetricDataWrapper durationMetrics;
+    sortMetricDataByDimensionsValue(reports.reports(0).metrics(0).duration_metrics(),
+                                    &durationMetrics);
+    ASSERT_EQ(1, durationMetrics.data_size());
+
+    DurationMetricData data = durationMetrics.data(0);
+    ASSERT_EQ(1, data.bucket_info_size());
+    ValidateDurationBucket(durationMetrics.data(0).bucket_info(0), configAddedTimeNs,
+                           baseTimeNs + bucketSizeNs, durationEndNs - durationStartNs);
+}
+
 TEST(DurationMetricE2eTest, TestTwoBuckets) {
     StatsdConfig config;
 
@@ -145,7 +222,7 @@ TEST(DurationMetricE2eTest, TestTwoBuckets) {
     ASSERT_EQ(metricsManager->mAllMetricProducers.size(), 1);
     sp<MetricProducer> metricProducer = metricsManager->mAllMetricProducers[0];
     EXPECT_TRUE(metricsManager->isActive());
-    EXPECT_TRUE(metricProducer->mIsActive);
+    EXPECT_TRUE(metricProducer->isActive());
 
     std::unique_ptr<LogEvent> event;
 
@@ -267,7 +344,7 @@ TEST(DurationMetricE2eTest, TestWithActivation) {
     auto& eventActivationMap = metricProducer->mEventActivationMap;
 
     EXPECT_FALSE(metricsManager->isActive());
-    EXPECT_FALSE(metricProducer->mIsActive);
+    EXPECT_FALSE(metricProducer->isActive());
     ASSERT_EQ(eventActivationMap.size(), 1u);
     EXPECT_TRUE(eventActivationMap.find(2) != eventActivationMap.end());
     EXPECT_EQ(eventActivationMap[2]->state, ActivationState::kNotActive);
@@ -293,7 +370,7 @@ TEST(DurationMetricE2eTest, TestWithActivation) {
     event = CreateAppCrashEvent(activationStartNs, 111);
     processor.OnLogEvent(event.get(), activationStartNs);
     EXPECT_TRUE(metricsManager->isActive());
-    EXPECT_TRUE(metricProducer->mIsActive);
+    EXPECT_TRUE(metricProducer->isActive());
     EXPECT_EQ(broadcastCount, 1);
     ASSERT_EQ(activeConfigsBroadcast.size(), 1);
     EXPECT_EQ(activeConfigsBroadcast[0], cfgId);
@@ -306,7 +383,7 @@ TEST(DurationMetricE2eTest, TestWithActivation) {
     event = CreateScreenBrightnessChangedEvent(expirationNs, 64);  // 0:47
     processor.OnLogEvent(event.get(), expirationNs);
     EXPECT_FALSE(metricsManager->isActive());
-    EXPECT_FALSE(metricProducer->mIsActive);
+    EXPECT_FALSE(metricProducer->isActive());
     EXPECT_EQ(broadcastCount, 2);
     ASSERT_EQ(activeConfigsBroadcast.size(), 0);
     ASSERT_EQ(eventActivationMap.size(), 1u);
@@ -337,7 +414,7 @@ TEST(DurationMetricE2eTest, TestWithActivation) {
     event = CreateAppCrashEvent(activation2StartNs, 211);
     processor.OnLogEvent(event.get(), activation2StartNs);
     EXPECT_TRUE(metricsManager->isActive());
-    EXPECT_TRUE(metricProducer->mIsActive);
+    EXPECT_TRUE(metricProducer->isActive());
     EXPECT_EQ(broadcastCount, 3);
     ASSERT_EQ(activeConfigsBroadcast.size(), 1);
     EXPECT_EQ(activeConfigsBroadcast[0], cfgId);
@@ -405,7 +482,7 @@ TEST(DurationMetricE2eTest, TestWithCondition) {
     sp<MetricProducer> metricProducer = metricsManager->mAllMetricProducers[0];
     auto& eventActivationMap = metricProducer->mEventActivationMap;
     EXPECT_TRUE(metricsManager->isActive());
-    EXPECT_TRUE(metricProducer->mIsActive);
+    EXPECT_TRUE(metricProducer->isActive());
     EXPECT_TRUE(eventActivationMap.empty());
 
     int appUid = 123;
@@ -515,7 +592,7 @@ TEST(DurationMetricE2eTest, TestWithSlicedCondition) {
     sp<MetricProducer> metricProducer = metricsManager->mAllMetricProducers[0];
     auto& eventActivationMap = metricProducer->mEventActivationMap;
     EXPECT_TRUE(metricsManager->isActive());
-    EXPECT_TRUE(metricProducer->mIsActive);
+    EXPECT_TRUE(metricProducer->isActive());
     EXPECT_TRUE(eventActivationMap.empty());
 
     int appUid = 123;
@@ -625,7 +702,7 @@ TEST(DurationMetricE2eTest, TestWithActivationAndSlicedCondition) {
     sp<MetricProducer> metricProducer = metricsManager->mAllMetricProducers[0];
     auto& eventActivationMap = metricProducer->mEventActivationMap;
     EXPECT_FALSE(metricsManager->isActive());
-    EXPECT_FALSE(metricProducer->mIsActive);
+    EXPECT_FALSE(metricProducer->isActive());
     ASSERT_EQ(eventActivationMap.size(), 1u);
     EXPECT_TRUE(eventActivationMap.find(4) != eventActivationMap.end());
     EXPECT_EQ(eventActivationMap[4]->state, ActivationState::kNotActive);
@@ -640,7 +717,7 @@ TEST(DurationMetricE2eTest, TestWithActivationAndSlicedCondition) {
                                             attributionTags1, "wl1");  // 0:10
     processor->OnLogEvent(event.get());
     EXPECT_FALSE(metricsManager->isActive());
-    EXPECT_FALSE(metricProducer->mIsActive);
+    EXPECT_FALSE(metricProducer->isActive());
     EXPECT_EQ(eventActivationMap[4]->state, ActivationState::kNotActive);
     EXPECT_EQ(eventActivationMap[4]->start_ns, 0);
     EXPECT_EQ(eventActivationMap[4]->ttl_ns, event_activation1->ttl_seconds() * NS_PER_SEC);
@@ -648,7 +725,7 @@ TEST(DurationMetricE2eTest, TestWithActivationAndSlicedCondition) {
     event = CreateMoveToBackgroundEvent(bucketStartTimeNs + 22 * NS_PER_SEC, appUid);  // 0:22
     processor->OnLogEvent(event.get());
     EXPECT_FALSE(metricsManager->isActive());
-    EXPECT_FALSE(metricProducer->mIsActive);
+    EXPECT_FALSE(metricProducer->isActive());
     EXPECT_EQ(eventActivationMap[4]->state, ActivationState::kNotActive);
     EXPECT_EQ(eventActivationMap[4]->start_ns, 0);
     EXPECT_EQ(eventActivationMap[4]->ttl_ns, event_activation1->ttl_seconds() * NS_PER_SEC);
@@ -657,7 +734,7 @@ TEST(DurationMetricE2eTest, TestWithActivationAndSlicedCondition) {
     event = CreateScreenStateChangedEvent(durationStartNs, android::view::DISPLAY_STATE_ON);
     processor->OnLogEvent(event.get());
     EXPECT_TRUE(metricsManager->isActive());
-    EXPECT_TRUE(metricProducer->mIsActive);
+    EXPECT_TRUE(metricProducer->isActive());
     EXPECT_EQ(eventActivationMap[4]->state, ActivationState::kActive);
     EXPECT_EQ(eventActivationMap[4]->start_ns, durationStartNs);
     EXPECT_EQ(eventActivationMap[4]->ttl_ns, event_activation1->ttl_seconds() * NS_PER_SEC);
@@ -667,7 +744,7 @@ TEST(DurationMetricE2eTest, TestWithActivationAndSlicedCondition) {
     event = CreateAppCrashEvent(durationEndNs, 333);
     processor->OnLogEvent(event.get());
     EXPECT_FALSE(metricsManager->isActive());
-    EXPECT_FALSE(metricProducer->mIsActive);
+    EXPECT_FALSE(metricProducer->isActive());
     EXPECT_EQ(eventActivationMap[4]->state, ActivationState::kNotActive);
     EXPECT_EQ(eventActivationMap[4]->start_ns, durationStartNs);
     EXPECT_EQ(eventActivationMap[4]->ttl_ns, event_activation1->ttl_seconds() * NS_PER_SEC);
@@ -692,7 +769,7 @@ TEST(DurationMetricE2eTest, TestWithActivationAndSlicedCondition) {
     event = CreateScreenStateChangedEvent(duration2StartNs, android::view::DISPLAY_STATE_ON);
     processor->OnLogEvent(event.get());
     EXPECT_TRUE(metricsManager->isActive());
-    EXPECT_TRUE(metricProducer->mIsActive);
+    EXPECT_TRUE(metricProducer->isActive());
     EXPECT_EQ(eventActivationMap[4]->state, ActivationState::kActive);
     EXPECT_EQ(eventActivationMap[4]->start_ns, duration2StartNs);
     EXPECT_EQ(eventActivationMap[4]->ttl_ns, event_activation1->ttl_seconds() * NS_PER_SEC);
@@ -768,7 +845,7 @@ TEST(DurationMetricE2eTest, TestWithSlicedState) {
     ASSERT_EQ(metricsManager->mAllMetricProducers.size(), 1);
     EXPECT_TRUE(metricsManager->isActive());
     sp<MetricProducer> metricProducer = metricsManager->mAllMetricProducers[0];
-    EXPECT_TRUE(metricProducer->mIsActive);
+    EXPECT_TRUE(metricProducer->isActive());
     ASSERT_EQ(metricProducer->mSlicedStateAtoms.size(), 1);
     EXPECT_EQ(metricProducer->mSlicedStateAtoms.at(0), SCREEN_STATE_ATOM_ID);
     ASSERT_EQ(metricProducer->mStateGroupMap.size(), 0);
@@ -916,7 +993,7 @@ TEST(DurationMetricE2eTest, TestWithConditionAndSlicedState) {
     ASSERT_EQ(metricsManager->mAllMetricProducers.size(), 1);
     EXPECT_TRUE(metricsManager->isActive());
     sp<MetricProducer> metricProducer = metricsManager->mAllMetricProducers[0];
-    EXPECT_TRUE(metricProducer->mIsActive);
+    EXPECT_TRUE(metricProducer->isActive());
     ASSERT_EQ(metricProducer->mSlicedStateAtoms.size(), 1);
     EXPECT_EQ(metricProducer->mSlicedStateAtoms.at(0), SCREEN_STATE_ATOM_ID);
     ASSERT_EQ(metricProducer->mStateGroupMap.size(), 0);
@@ -1073,7 +1150,7 @@ TEST(DurationMetricE2eTest, TestWithSlicedStateMapped) {
     ASSERT_EQ(metricsManager->mAllMetricProducers.size(), 1);
     EXPECT_TRUE(metricsManager->isActive());
     sp<MetricProducer> metricProducer = metricsManager->mAllMetricProducers[0];
-    EXPECT_TRUE(metricProducer->mIsActive);
+    EXPECT_TRUE(metricProducer->isActive());
     ASSERT_EQ(metricProducer->mSlicedStateAtoms.size(), 1);
     EXPECT_EQ(metricProducer->mSlicedStateAtoms.at(0), SCREEN_STATE_ATOM_ID);
     ASSERT_EQ(metricProducer->mStateGroupMap.size(), 1);
@@ -1275,7 +1352,7 @@ TEST(DurationMetricE2eTest, TestWithSlicedStatePrimaryFieldsSubset) {
     ASSERT_EQ(metricsManager->mAllMetricProducers.size(), 1);
     EXPECT_TRUE(metricsManager->isActive());
     sp<MetricProducer> metricProducer = metricsManager->mAllMetricProducers[0];
-    EXPECT_TRUE(metricProducer->mIsActive);
+    EXPECT_TRUE(metricProducer->isActive());
     ASSERT_EQ(metricProducer->mSlicedStateAtoms.size(), 1);
     EXPECT_EQ(metricProducer->mSlicedStateAtoms.at(0), UID_PROCESS_STATE_ATOM_ID);
     ASSERT_EQ(metricProducer->mStateGroupMap.size(), 0);
@@ -1512,7 +1589,7 @@ TEST(DurationMetricE2eTest, TestUploadThreshold) {
     ASSERT_EQ(metricsManager->mAllMetricProducers.size(), 1);
     sp<MetricProducer> metricProducer = metricsManager->mAllMetricProducers[0];
     EXPECT_TRUE(metricsManager->isActive());
-    EXPECT_TRUE(metricProducer->mIsActive);
+    EXPECT_TRUE(metricProducer->isActive());
 
     std::unique_ptr<LogEvent> event;
 
diff --git a/statsd/tests/e2e/MetricActivation_e2e_test.cpp b/statsd/tests/e2e/MetricActivation_e2e_test.cpp
index 6da3f99b..7774abbd 100644
--- a/statsd/tests/e2e/MetricActivation_e2e_test.cpp
+++ b/statsd/tests/e2e/MetricActivation_e2e_test.cpp
@@ -277,7 +277,7 @@ TEST(MetricActivationE2eTest, TestCountMetric) {
     auto& eventActivationMap = metricProducer->mEventActivationMap;
 
     EXPECT_FALSE(metricsManager->isActive());
-    EXPECT_FALSE(metricProducer->mIsActive);
+    EXPECT_FALSE(metricProducer->isActive());
     // Two activations: one is triggered by battery saver mode (tracker index 0), the other is
     // triggered by screen on event (tracker index 2).
     ASSERT_EQ(eventActivationMap.size(), 2u);
@@ -295,14 +295,14 @@ TEST(MetricActivationE2eTest, TestCountMetric) {
     event = CreateAppCrashEvent(bucketStartTimeNs + 5, 111);
     processor.OnLogEvent(event.get(), bucketStartTimeNs + 5);
     EXPECT_FALSE(metricsManager->isActive());
-    EXPECT_FALSE(metricProducer->mIsActive);
+    EXPECT_FALSE(metricProducer->isActive());
     EXPECT_EQ(broadcastCount, 0);
 
     // Activated by battery save mode.
     event = CreateBatterySaverOnEvent(bucketStartTimeNs + 10);
     processor.OnLogEvent(event.get(), bucketStartTimeNs + 10);
     EXPECT_TRUE(metricsManager->isActive());
-    EXPECT_TRUE(metricProducer->mIsActive);
+    EXPECT_TRUE(metricProducer->isActive());
     EXPECT_EQ(broadcastCount, 1);
     ASSERT_EQ(activeConfigsBroadcast.size(), 1);
     EXPECT_EQ(activeConfigsBroadcast[0], cfgId);
@@ -321,7 +321,7 @@ TEST(MetricActivationE2eTest, TestCountMetric) {
     event = CreateScreenStateChangedEvent(bucketStartTimeNs + 20, android::view::DISPLAY_STATE_ON);
     processor.OnLogEvent(event.get(), bucketStartTimeNs + 20);
     EXPECT_TRUE(metricsManager->isActive());
-    EXPECT_TRUE(metricProducer->mIsActive);
+    EXPECT_TRUE(metricProducer->isActive());
     EXPECT_EQ(eventActivationMap[0]->state, ActivationState::kActive);
     EXPECT_EQ(eventActivationMap[0]->start_ns, bucketStartTimeNs + 10);
     EXPECT_EQ(eventActivationMap[0]->ttl_ns, 60 * 6 * NS_PER_SEC);
@@ -334,7 +334,7 @@ TEST(MetricActivationE2eTest, TestCountMetric) {
     event = CreateAppCrashEvent(bucketStartTimeNs + NS_PER_SEC * 60 * 2 + 25, 333);
     processor.OnLogEvent(event.get(), bucketStartTimeNs + NS_PER_SEC * 60 * 2 + 25);
     EXPECT_TRUE(metricsManager->isActive());
-    EXPECT_TRUE(metricProducer->mIsActive);
+    EXPECT_TRUE(metricProducer->isActive());
     EXPECT_EQ(eventActivationMap[0]->state, ActivationState::kActive);
     EXPECT_EQ(eventActivationMap[0]->start_ns, bucketStartTimeNs + 10);
     EXPECT_EQ(eventActivationMap[0]->ttl_ns, 60 * 6 * NS_PER_SEC);
@@ -352,7 +352,7 @@ TEST(MetricActivationE2eTest, TestCountMetric) {
     event = CreateAppCrashEvent(bucketStartTimeNs + NS_PER_SEC * 60 * 8, 555);
     processor.OnLogEvent(event.get(), bucketStartTimeNs + NS_PER_SEC * 60 * 8);
     EXPECT_FALSE(metricsManager->isActive());
-    EXPECT_FALSE(metricProducer->mIsActive);
+    EXPECT_FALSE(metricProducer->isActive());
     // New broadcast since the config is no longer active.
     EXPECT_EQ(broadcastCount, 2);
     ASSERT_EQ(activeConfigsBroadcast.size(), 0);
@@ -368,7 +368,7 @@ TEST(MetricActivationE2eTest, TestCountMetric) {
                                           android::view::DISPLAY_STATE_ON);
     processor.OnLogEvent(event.get(), bucketStartTimeNs + NS_PER_SEC * 60 * 10 + 10);
     EXPECT_TRUE(metricsManager->isActive());
-    EXPECT_TRUE(metricProducer->mIsActive);
+    EXPECT_TRUE(metricProducer->isActive());
     EXPECT_EQ(broadcastCount, 3);
     ASSERT_EQ(activeConfigsBroadcast.size(), 1);
     EXPECT_EQ(activeConfigsBroadcast[0], cfgId);
@@ -496,7 +496,7 @@ TEST(MetricActivationE2eTest, TestCountMetricWithOneDeactivation) {
     auto& eventDeactivationMap = metricProducer->mEventDeactivationMap;
 
     EXPECT_FALSE(metricsManager->isActive());
-    EXPECT_FALSE(metricProducer->mIsActive);
+    EXPECT_FALSE(metricProducer->isActive());
     // Two activations: one is triggered by battery saver mode (tracker index 0), the other is
     // triggered by screen on event (tracker index 2).
     ASSERT_EQ(eventActivationMap.size(), 2u);
@@ -518,14 +518,14 @@ TEST(MetricActivationE2eTest, TestCountMetricWithOneDeactivation) {
     event = CreateAppCrashEvent(bucketStartTimeNs + 5, 111);
     processor.OnLogEvent(event.get(), bucketStartTimeNs + 5);
     EXPECT_FALSE(metricsManager->isActive());
-    EXPECT_FALSE(metricProducer->mIsActive);
+    EXPECT_FALSE(metricProducer->isActive());
     EXPECT_EQ(broadcastCount, 0);
 
     // Activated by battery save mode.
     event = CreateBatterySaverOnEvent(bucketStartTimeNs + 10);
     processor.OnLogEvent(event.get(), bucketStartTimeNs + 10);
     EXPECT_TRUE(metricsManager->isActive());
-    EXPECT_TRUE(metricProducer->mIsActive);
+    EXPECT_TRUE(metricProducer->isActive());
     EXPECT_EQ(broadcastCount, 1);
     ASSERT_EQ(activeConfigsBroadcast.size(), 1);
     EXPECT_EQ(activeConfigsBroadcast[0], cfgId);
@@ -545,7 +545,7 @@ TEST(MetricActivationE2eTest, TestCountMetricWithOneDeactivation) {
     event = CreateScreenStateChangedEvent(bucketStartTimeNs + 20, android::view::DISPLAY_STATE_ON);
     processor.OnLogEvent(event.get(), bucketStartTimeNs + 20);
     EXPECT_TRUE(metricsManager->isActive());
-    EXPECT_TRUE(metricProducer->mIsActive);
+    EXPECT_TRUE(metricProducer->isActive());
     EXPECT_EQ(eventActivationMap[0]->state, ActivationState::kActive);
     EXPECT_EQ(eventActivationMap[0]->start_ns, bucketStartTimeNs + 10);
     EXPECT_EQ(eventActivationMap[0]->ttl_ns, 60 * 6 * NS_PER_SEC);
@@ -559,7 +559,7 @@ TEST(MetricActivationE2eTest, TestCountMetricWithOneDeactivation) {
     event = CreateAppCrashEvent(bucketStartTimeNs + NS_PER_SEC * 60 * 2 + 25, 333);
     processor.OnLogEvent(event.get(), bucketStartTimeNs + NS_PER_SEC * 60 * 2 + 25);
     EXPECT_TRUE(metricsManager->isActive());
-    EXPECT_TRUE(metricProducer->mIsActive);
+    EXPECT_TRUE(metricProducer->isActive());
     EXPECT_EQ(eventActivationMap[0]->state, ActivationState::kActive);
     EXPECT_EQ(eventActivationMap[0]->start_ns, bucketStartTimeNs + 10);
     EXPECT_EQ(eventActivationMap[0]->ttl_ns, 60 * 6 * NS_PER_SEC);
@@ -578,7 +578,7 @@ TEST(MetricActivationE2eTest, TestCountMetricWithOneDeactivation) {
     event = CreateAppCrashEvent(bucketStartTimeNs + NS_PER_SEC * 60 * 8, 555);
     processor.OnLogEvent(event.get(), bucketStartTimeNs + NS_PER_SEC * 60 * 8);
     EXPECT_FALSE(metricsManager->isActive());
-    EXPECT_FALSE(metricProducer->mIsActive);
+    EXPECT_FALSE(metricProducer->isActive());
     // New broadcast since the config is no longer active.
     EXPECT_EQ(broadcastCount, 2);
     ASSERT_EQ(activeConfigsBroadcast.size(), 0);
@@ -595,7 +595,7 @@ TEST(MetricActivationE2eTest, TestCountMetricWithOneDeactivation) {
                                           android::view::DISPLAY_STATE_ON);
     processor.OnLogEvent(event.get(), bucketStartTimeNs + NS_PER_SEC * 60 * 10 + 10);
     EXPECT_TRUE(metricsManager->isActive());
-    EXPECT_TRUE(metricProducer->mIsActive);
+    EXPECT_TRUE(metricProducer->isActive());
     EXPECT_EQ(broadcastCount, 3);
     ASSERT_EQ(activeConfigsBroadcast.size(), 1);
     EXPECT_EQ(activeConfigsBroadcast[0], cfgId);
@@ -615,7 +615,7 @@ TEST(MetricActivationE2eTest, TestCountMetricWithOneDeactivation) {
     event = CreateBatterySaverOnEvent(bucketStartTimeNs + NS_PER_SEC * 60 * 11 + 15);
     processor.OnLogEvent(event.get(), bucketStartTimeNs + NS_PER_SEC * 60 * 11 + 15);
     EXPECT_TRUE(metricsManager->isActive());
-    EXPECT_TRUE(metricProducer->mIsActive);
+    EXPECT_TRUE(metricProducer->isActive());
     EXPECT_EQ(broadcastCount, 3);
     ASSERT_EQ(activeConfigsBroadcast.size(), 1);
     EXPECT_EQ(activeConfigsBroadcast[0], cfgId);
@@ -635,7 +635,7 @@ TEST(MetricActivationE2eTest, TestCountMetricWithOneDeactivation) {
     event = CreateScreenBrightnessChangedEvent(bucketStartTimeNs + NS_PER_SEC * 60 * 11 + 60, 64);
     processor.OnLogEvent(event.get(), bucketStartTimeNs + NS_PER_SEC * 60 * 11 + 60);
     EXPECT_TRUE(metricsManager->isActive());
-    EXPECT_TRUE(metricProducer->mIsActive);
+    EXPECT_TRUE(metricProducer->isActive());
     EXPECT_EQ(broadcastCount, 3);
     ASSERT_EQ(activeConfigsBroadcast.size(), 1);
     EXPECT_EQ(activeConfigsBroadcast[0], cfgId);
@@ -651,7 +651,7 @@ TEST(MetricActivationE2eTest, TestCountMetricWithOneDeactivation) {
     event = CreateAppCrashEvent(bucketStartTimeNs + NS_PER_SEC * 60 * 13, 888);
     processor.OnLogEvent(event.get(), bucketStartTimeNs + NS_PER_SEC * 60 * 13);
     EXPECT_FALSE(metricsManager->isActive());
-    EXPECT_FALSE(metricProducer->mIsActive);
+    EXPECT_FALSE(metricProducer->isActive());
     // New broadcast since the config is no longer active.
     EXPECT_EQ(broadcastCount, 4);
     ASSERT_EQ(activeConfigsBroadcast.size(), 0);
@@ -670,7 +670,7 @@ TEST(MetricActivationE2eTest, TestCountMetricWithOneDeactivation) {
     event = CreateBatterySaverOnEvent(bucketStartTimeNs + NS_PER_SEC * 60 * 15 + 15);
     processor.OnLogEvent(event.get(), bucketStartTimeNs + NS_PER_SEC * 60 * 15 + 15);
     EXPECT_TRUE(metricsManager->isActive());
-    EXPECT_TRUE(metricProducer->mIsActive);
+    EXPECT_TRUE(metricProducer->isActive());
     EXPECT_EQ(broadcastCount, 5);
     ASSERT_EQ(activeConfigsBroadcast.size(), 1);
     EXPECT_EQ(activeConfigsBroadcast[0], cfgId);
@@ -686,7 +686,7 @@ TEST(MetricActivationE2eTest, TestCountMetricWithOneDeactivation) {
     event = CreateScreenBrightnessChangedEvent(bucketStartTimeNs + NS_PER_SEC * 60 * 16, 140);
     processor.OnLogEvent(event.get(), bucketStartTimeNs + NS_PER_SEC * 60 * 16);
     EXPECT_FALSE(metricsManager->isActive());
-    EXPECT_FALSE(metricProducer->mIsActive);
+    EXPECT_FALSE(metricProducer->isActive());
     EXPECT_EQ(broadcastCount, 6);
     ASSERT_EQ(activeConfigsBroadcast.size(), 0);
     EXPECT_EQ(eventActivationMap[0]->state, ActivationState::kNotActive);
@@ -824,7 +824,7 @@ TEST(MetricActivationE2eTest, TestCountMetricWithTwoDeactivations) {
     auto& eventDeactivationMap = metricProducer->mEventDeactivationMap;
 
     EXPECT_FALSE(metricsManager->isActive());
-    EXPECT_FALSE(metricProducer->mIsActive);
+    EXPECT_FALSE(metricProducer->isActive());
     // Two activations: one is triggered by battery saver mode (tracker index 0), the other is
     // triggered by screen on event (tracker index 2).
     ASSERT_EQ(eventActivationMap.size(), 2u);
@@ -849,14 +849,14 @@ TEST(MetricActivationE2eTest, TestCountMetricWithTwoDeactivations) {
     event = CreateAppCrashEvent(bucketStartTimeNs + 5, 111);
     processor.OnLogEvent(event.get(), bucketStartTimeNs + 5);
     EXPECT_FALSE(metricsManager->isActive());
-    EXPECT_FALSE(metricProducer->mIsActive);
+    EXPECT_FALSE(metricProducer->isActive());
     EXPECT_EQ(broadcastCount, 0);
 
     // Activated by battery save mode.
     event = CreateBatterySaverOnEvent(bucketStartTimeNs + 10);
     processor.OnLogEvent(event.get(), bucketStartTimeNs + 10);
     EXPECT_TRUE(metricsManager->isActive());
-    EXPECT_TRUE(metricProducer->mIsActive);
+    EXPECT_TRUE(metricProducer->isActive());
     EXPECT_EQ(broadcastCount, 1);
     ASSERT_EQ(activeConfigsBroadcast.size(), 1);
     EXPECT_EQ(activeConfigsBroadcast[0], cfgId);
@@ -877,7 +877,7 @@ TEST(MetricActivationE2eTest, TestCountMetricWithTwoDeactivations) {
     event = CreateScreenStateChangedEvent(bucketStartTimeNs + 20, android::view::DISPLAY_STATE_ON);
     processor.OnLogEvent(event.get(), bucketStartTimeNs + 20);
     EXPECT_TRUE(metricsManager->isActive());
-    EXPECT_TRUE(metricProducer->mIsActive);
+    EXPECT_TRUE(metricProducer->isActive());
     EXPECT_EQ(eventActivationMap[0]->state, ActivationState::kActive);
     EXPECT_EQ(eventActivationMap[0]->start_ns, bucketStartTimeNs + 10);
     EXPECT_EQ(eventActivationMap[0]->ttl_ns, 60 * 6 * NS_PER_SEC);
@@ -892,7 +892,7 @@ TEST(MetricActivationE2eTest, TestCountMetricWithTwoDeactivations) {
     event = CreateAppCrashEvent(bucketStartTimeNs + NS_PER_SEC * 60 * 2 + 25, 333);
     processor.OnLogEvent(event.get(), bucketStartTimeNs + NS_PER_SEC * 60 * 2 + 25);
     EXPECT_TRUE(metricsManager->isActive());
-    EXPECT_TRUE(metricProducer->mIsActive);
+    EXPECT_TRUE(metricProducer->isActive());
     EXPECT_EQ(eventActivationMap[0]->state, ActivationState::kActive);
     EXPECT_EQ(eventActivationMap[0]->start_ns, bucketStartTimeNs + 10);
     EXPECT_EQ(eventActivationMap[0]->ttl_ns, 60 * 6 * NS_PER_SEC);
@@ -912,7 +912,7 @@ TEST(MetricActivationE2eTest, TestCountMetricWithTwoDeactivations) {
     event = CreateAppCrashEvent(bucketStartTimeNs + NS_PER_SEC * 60 * 8, 555);
     processor.OnLogEvent(event.get(), bucketStartTimeNs + NS_PER_SEC * 60 * 8);
     EXPECT_FALSE(metricsManager->isActive());
-    EXPECT_FALSE(metricProducer->mIsActive);
+    EXPECT_FALSE(metricProducer->isActive());
     // New broadcast since the config is no longer active.
     EXPECT_EQ(broadcastCount, 2);
     ASSERT_EQ(activeConfigsBroadcast.size(), 0);
@@ -930,7 +930,7 @@ TEST(MetricActivationE2eTest, TestCountMetricWithTwoDeactivations) {
                                           android::view::DISPLAY_STATE_ON);
     processor.OnLogEvent(event.get(), bucketStartTimeNs + NS_PER_SEC * 60 * 10 + 10);
     EXPECT_TRUE(metricsManager->isActive());
-    EXPECT_TRUE(metricProducer->mIsActive);
+    EXPECT_TRUE(metricProducer->isActive());
     EXPECT_EQ(broadcastCount, 3);
     ASSERT_EQ(activeConfigsBroadcast.size(), 1);
     EXPECT_EQ(activeConfigsBroadcast[0], cfgId);
@@ -951,7 +951,7 @@ TEST(MetricActivationE2eTest, TestCountMetricWithTwoDeactivations) {
     event = CreateBatterySaverOnEvent(bucketStartTimeNs + NS_PER_SEC * 60 * 11 + 15);
     processor.OnLogEvent(event.get(), bucketStartTimeNs + NS_PER_SEC * 60 * 11 + 15);
     EXPECT_TRUE(metricsManager->isActive());
-    EXPECT_TRUE(metricProducer->mIsActive);
+    EXPECT_TRUE(metricProducer->isActive());
     EXPECT_EQ(broadcastCount, 3);
     ASSERT_EQ(activeConfigsBroadcast.size(), 1);
     EXPECT_EQ(activeConfigsBroadcast[0], cfgId);
@@ -972,7 +972,7 @@ TEST(MetricActivationE2eTest, TestCountMetricWithTwoDeactivations) {
     event = CreateScreenBrightnessChangedEvent(bucketStartTimeNs + NS_PER_SEC * 60 * 11 + 60, 64);
     processor.OnLogEvent(event.get(), bucketStartTimeNs + NS_PER_SEC * 60 * 11 + 60);
     EXPECT_FALSE(metricsManager->isActive());
-    EXPECT_FALSE(metricProducer->mIsActive);
+    EXPECT_FALSE(metricProducer->isActive());
     // New broadcast since the config is no longer active.
     EXPECT_EQ(broadcastCount, 4);
     ASSERT_EQ(activeConfigsBroadcast.size(), 0);
@@ -989,7 +989,7 @@ TEST(MetricActivationE2eTest, TestCountMetricWithTwoDeactivations) {
     event = CreateAppCrashEvent(bucketStartTimeNs + NS_PER_SEC * 60 * 13, 888);
     processor.OnLogEvent(event.get(), bucketStartTimeNs + NS_PER_SEC * 60 * 13);
     EXPECT_FALSE(metricsManager->isActive());
-    EXPECT_FALSE(metricProducer->mIsActive);
+    EXPECT_FALSE(metricProducer->isActive());
     EXPECT_EQ(broadcastCount, 4);
     ASSERT_EQ(activeConfigsBroadcast.size(), 0);
     EXPECT_EQ(eventActivationMap[0]->state, ActivationState::kNotActive);
@@ -1008,7 +1008,7 @@ TEST(MetricActivationE2eTest, TestCountMetricWithTwoDeactivations) {
     event = CreateBatterySaverOnEvent(bucketStartTimeNs + NS_PER_SEC * 60 * 15 + 15);
     processor.OnLogEvent(event.get(), bucketStartTimeNs + NS_PER_SEC * 60 * 15 + 15);
     EXPECT_TRUE(metricsManager->isActive());
-    EXPECT_TRUE(metricProducer->mIsActive);
+    EXPECT_TRUE(metricProducer->isActive());
     EXPECT_EQ(broadcastCount, 5);
     ASSERT_EQ(activeConfigsBroadcast.size(), 1);
     EXPECT_EQ(activeConfigsBroadcast[0], cfgId);
@@ -1025,7 +1025,7 @@ TEST(MetricActivationE2eTest, TestCountMetricWithTwoDeactivations) {
     event = CreateScreenBrightnessChangedEvent(bucketStartTimeNs + NS_PER_SEC * 60 * 16, 140);
     processor.OnLogEvent(event.get(), bucketStartTimeNs + NS_PER_SEC * 60 * 16);
     EXPECT_FALSE(metricsManager->isActive());
-    EXPECT_FALSE(metricProducer->mIsActive);
+    EXPECT_FALSE(metricProducer->isActive());
     EXPECT_EQ(broadcastCount, 6);
     ASSERT_EQ(activeConfigsBroadcast.size(), 0);
     EXPECT_EQ(eventActivationMap[0]->state, ActivationState::kNotActive);
@@ -1164,7 +1164,7 @@ TEST(MetricActivationE2eTest, TestCountMetricWithSameDeactivation) {
     auto& eventDeactivationMap = metricProducer->mEventDeactivationMap;
 
     EXPECT_FALSE(metricsManager->isActive());
-    EXPECT_FALSE(metricProducer->mIsActive);
+    EXPECT_FALSE(metricProducer->isActive());
     // Two activations: one is triggered by battery saver mode (tracker index 0), the other is
     // triggered by screen on event (tracker index 2).
     ASSERT_EQ(eventActivationMap.size(), 2u);
@@ -1193,7 +1193,7 @@ TEST(MetricActivationE2eTest, TestCountMetricWithSameDeactivation) {
     event = CreateScreenStateChangedEvent(bucketStartTimeNs + 10, android::view::DISPLAY_STATE_ON);
     processor.OnLogEvent(event.get(), bucketStartTimeNs + 10);
     EXPECT_TRUE(metricsManager->isActive());
-    EXPECT_TRUE(metricProducer->mIsActive);
+    EXPECT_TRUE(metricProducer->isActive());
     EXPECT_EQ(broadcastCount, 1);
     ASSERT_EQ(activeConfigsBroadcast.size(), 1);
     EXPECT_EQ(activeConfigsBroadcast[0], cfgId);
@@ -1209,7 +1209,7 @@ TEST(MetricActivationE2eTest, TestCountMetricWithSameDeactivation) {
     event = CreateBatterySaverOnEvent(bucketStartTimeNs + NS_PER_SEC * 60 + 10);
     processor.OnLogEvent(event.get(), bucketStartTimeNs + NS_PER_SEC * 60 + 10);
     EXPECT_TRUE(metricsManager->isActive());
-    EXPECT_TRUE(metricProducer->mIsActive);
+    EXPECT_TRUE(metricProducer->isActive());
     EXPECT_EQ(broadcastCount, 1);
     EXPECT_EQ(eventActivationMap[0]->state, ActivationState::kActive);
     EXPECT_EQ(eventActivationMap[0]->start_ns, bucketStartTimeNs + NS_PER_SEC * 60 + 10);
@@ -1225,7 +1225,7 @@ TEST(MetricActivationE2eTest, TestCountMetricWithSameDeactivation) {
     event = CreateScreenBrightnessChangedEvent(firstDeactivation, 64);
     processor.OnLogEvent(event.get(), firstDeactivation);
     EXPECT_FALSE(metricsManager->isActive());
-    EXPECT_FALSE(metricProducer->mIsActive);
+    EXPECT_FALSE(metricProducer->isActive());
     // New broadcast since the config is no longer active.
     EXPECT_EQ(broadcastCount, 2);
     ASSERT_EQ(activeConfigsBroadcast.size(), 0);
@@ -1240,7 +1240,7 @@ TEST(MetricActivationE2eTest, TestCountMetricWithSameDeactivation) {
     event = CreateBatterySaverOnEvent(bucketStartTimeNs + NS_PER_SEC * 60 * 10 + 15);
     processor.OnLogEvent(event.get(), bucketStartTimeNs + NS_PER_SEC * 60 * 10 + 15);
     EXPECT_TRUE(metricsManager->isActive());
-    EXPECT_TRUE(metricProducer->mIsActive);
+    EXPECT_TRUE(metricProducer->isActive());
     EXPECT_EQ(broadcastCount, 3);
     ASSERT_EQ(activeConfigsBroadcast.size(), 1);
     EXPECT_EQ(activeConfigsBroadcast[0], cfgId);
@@ -1257,7 +1257,7 @@ TEST(MetricActivationE2eTest, TestCountMetricWithSameDeactivation) {
     event = CreateScreenBrightnessChangedEvent(secondDeactivation, 140);
     processor.OnLogEvent(event.get(), secondDeactivation);
     EXPECT_FALSE(metricsManager->isActive());
-    EXPECT_FALSE(metricProducer->mIsActive);
+    EXPECT_FALSE(metricProducer->isActive());
     EXPECT_EQ(broadcastCount, 4);
     ASSERT_EQ(activeConfigsBroadcast.size(), 0);
     EXPECT_EQ(eventActivationMap[0]->state, ActivationState::kNotActive);
@@ -1371,8 +1371,8 @@ TEST(MetricActivationE2eTest, TestCountMetricWithTwoMetricsTwoDeactivations) {
     auto& eventDeactivationMap2 = metricProducer2->mEventDeactivationMap;
 
     EXPECT_FALSE(metricsManager->isActive());
-    EXPECT_FALSE(metricProducer->mIsActive);
-    EXPECT_FALSE(metricProducer2->mIsActive);
+    EXPECT_FALSE(metricProducer->isActive());
+    EXPECT_FALSE(metricProducer2->isActive());
     // Two activations: one is triggered by battery saver mode (tracker index 0), the other is
     // triggered by screen on event (tracker index 2).
     ASSERT_EQ(eventActivationMap.size(), 2u);
@@ -1416,8 +1416,8 @@ TEST(MetricActivationE2eTest, TestCountMetricWithTwoMetricsTwoDeactivations) {
     event = CreateMoveToForegroundEvent(bucketStartTimeNs + 5, 1111);
     processor.OnLogEvent(event.get(), bucketStartTimeNs + 5);
     EXPECT_FALSE(metricsManager->isActive());
-    EXPECT_FALSE(metricProducer->mIsActive);
-    EXPECT_FALSE(metricProducer2->mIsActive);
+    EXPECT_FALSE(metricProducer->isActive());
+    EXPECT_FALSE(metricProducer2->isActive());
     EXPECT_EQ(broadcastCount, 0);
 
     // Activated by battery save mode.
@@ -1427,7 +1427,7 @@ TEST(MetricActivationE2eTest, TestCountMetricWithTwoMetricsTwoDeactivations) {
     EXPECT_EQ(broadcastCount, 1);
     ASSERT_EQ(activeConfigsBroadcast.size(), 1);
     EXPECT_EQ(activeConfigsBroadcast[0], cfgId);
-    EXPECT_TRUE(metricProducer->mIsActive);
+    EXPECT_TRUE(metricProducer->isActive());
     EXPECT_EQ(eventActivationMap[0]->state, ActivationState::kActive);
     EXPECT_EQ(eventActivationMap[0]->start_ns, bucketStartTimeNs + 10);
     EXPECT_EQ(eventActivationMap[0]->ttl_ns, 60 * 6 * NS_PER_SEC);
@@ -1436,7 +1436,7 @@ TEST(MetricActivationE2eTest, TestCountMetricWithTwoMetricsTwoDeactivations) {
     EXPECT_EQ(eventActivationMap[2]->ttl_ns, 60 * 2 * NS_PER_SEC);
     EXPECT_EQ(eventDeactivationMap[3][0], eventActivationMap[0]);
     EXPECT_EQ(eventDeactivationMap[4][0], eventActivationMap[2]);
-    EXPECT_TRUE(metricProducer2->mIsActive);
+    EXPECT_TRUE(metricProducer2->isActive());
     EXPECT_EQ(eventActivationMap2[0]->state, ActivationState::kActive);
     EXPECT_EQ(eventActivationMap2[0]->start_ns, bucketStartTimeNs + 10);
     EXPECT_EQ(eventActivationMap2[0]->ttl_ns, 60 * 6 * NS_PER_SEC);
@@ -1456,7 +1456,7 @@ TEST(MetricActivationE2eTest, TestCountMetricWithTwoMetricsTwoDeactivations) {
     event = CreateScreenStateChangedEvent(bucketStartTimeNs + 20, android::view::DISPLAY_STATE_ON);
     processor.OnLogEvent(event.get(), bucketStartTimeNs + 20);
     EXPECT_TRUE(metricsManager->isActive());
-    EXPECT_TRUE(metricProducer->mIsActive);
+    EXPECT_TRUE(metricProducer->isActive());
     EXPECT_EQ(eventActivationMap[0]->state, ActivationState::kActive);
     EXPECT_EQ(eventActivationMap[0]->start_ns, bucketStartTimeNs + 10);
     EXPECT_EQ(eventActivationMap[0]->ttl_ns, 60 * 6 * NS_PER_SEC);
@@ -1465,7 +1465,7 @@ TEST(MetricActivationE2eTest, TestCountMetricWithTwoMetricsTwoDeactivations) {
     EXPECT_EQ(eventActivationMap[2]->ttl_ns, 60 * 2 * NS_PER_SEC);
     EXPECT_EQ(eventDeactivationMap[3][0], eventActivationMap[0]);
     EXPECT_EQ(eventDeactivationMap[4][0], eventActivationMap[2]);
-    EXPECT_TRUE(metricProducer2->mIsActive);
+    EXPECT_TRUE(metricProducer2->isActive());
     EXPECT_EQ(eventActivationMap2[0]->state, ActivationState::kActive);
     EXPECT_EQ(eventActivationMap2[0]->start_ns, bucketStartTimeNs + 10);
     EXPECT_EQ(eventActivationMap2[0]->ttl_ns, 60 * 6 * NS_PER_SEC);
@@ -1482,7 +1482,7 @@ TEST(MetricActivationE2eTest, TestCountMetricWithTwoMetricsTwoDeactivations) {
     event = CreateMoveToForegroundEvent(bucketStartTimeNs + NS_PER_SEC * 60 * 2 + 25, 3333);
     processor.OnLogEvent(event.get(), bucketStartTimeNs + NS_PER_SEC * 60 * 2 + 25);
     EXPECT_TRUE(metricsManager->isActive());
-    EXPECT_TRUE(metricProducer->mIsActive);
+    EXPECT_TRUE(metricProducer->isActive());
     EXPECT_EQ(eventActivationMap[0]->state, ActivationState::kActive);
     EXPECT_EQ(eventActivationMap[0]->start_ns, bucketStartTimeNs + 10);
     EXPECT_EQ(eventActivationMap[0]->ttl_ns, 60 * 6 * NS_PER_SEC);
@@ -1491,7 +1491,7 @@ TEST(MetricActivationE2eTest, TestCountMetricWithTwoMetricsTwoDeactivations) {
     EXPECT_EQ(eventActivationMap[2]->ttl_ns, 60 * 2 * NS_PER_SEC);
     EXPECT_EQ(eventDeactivationMap[3][0], eventActivationMap[0]);
     EXPECT_EQ(eventDeactivationMap[4][0], eventActivationMap[2]);
-    EXPECT_TRUE(metricProducer2->mIsActive);
+    EXPECT_TRUE(metricProducer2->isActive());
     EXPECT_EQ(eventActivationMap2[0]->state, ActivationState::kActive);
     EXPECT_EQ(eventActivationMap2[0]->start_ns, bucketStartTimeNs + 10);
     EXPECT_EQ(eventActivationMap2[0]->ttl_ns, 60 * 6 * NS_PER_SEC);
@@ -1518,7 +1518,7 @@ TEST(MetricActivationE2eTest, TestCountMetricWithTwoMetricsTwoDeactivations) {
     // New broadcast since the config is no longer active.
     EXPECT_EQ(broadcastCount, 2);
     ASSERT_EQ(activeConfigsBroadcast.size(), 0);
-    EXPECT_FALSE(metricProducer->mIsActive);
+    EXPECT_FALSE(metricProducer->isActive());
     EXPECT_EQ(eventActivationMap[0]->state, ActivationState::kNotActive);
     EXPECT_EQ(eventActivationMap[0]->start_ns, bucketStartTimeNs + 10);
     EXPECT_EQ(eventActivationMap[0]->ttl_ns, 60 * 6 * NS_PER_SEC);
@@ -1527,7 +1527,7 @@ TEST(MetricActivationE2eTest, TestCountMetricWithTwoMetricsTwoDeactivations) {
     EXPECT_EQ(eventActivationMap[2]->ttl_ns, 60 * 2 * NS_PER_SEC);
     EXPECT_EQ(eventDeactivationMap[3][0], eventActivationMap[0]);
     EXPECT_EQ(eventDeactivationMap[4][0], eventActivationMap[2]);
-    EXPECT_FALSE(metricProducer2->mIsActive);
+    EXPECT_FALSE(metricProducer2->isActive());
     EXPECT_EQ(eventActivationMap2[0]->state, ActivationState::kNotActive);
     EXPECT_EQ(eventActivationMap2[0]->start_ns, bucketStartTimeNs + 10);
     EXPECT_EQ(eventActivationMap2[0]->ttl_ns, 60 * 6 * NS_PER_SEC);
@@ -1545,7 +1545,7 @@ TEST(MetricActivationE2eTest, TestCountMetricWithTwoMetricsTwoDeactivations) {
     EXPECT_EQ(broadcastCount, 3);
     ASSERT_EQ(activeConfigsBroadcast.size(), 1);
     EXPECT_EQ(activeConfigsBroadcast[0], cfgId);
-    EXPECT_TRUE(metricProducer->mIsActive);
+    EXPECT_TRUE(metricProducer->isActive());
     EXPECT_EQ(eventActivationMap[0]->state, ActivationState::kNotActive);
     EXPECT_EQ(eventActivationMap[0]->start_ns, bucketStartTimeNs + 10);
     EXPECT_EQ(eventActivationMap[0]->ttl_ns, 60 * 6 * NS_PER_SEC);
@@ -1554,7 +1554,7 @@ TEST(MetricActivationE2eTest, TestCountMetricWithTwoMetricsTwoDeactivations) {
     EXPECT_EQ(eventActivationMap[2]->ttl_ns, 60 * 2 * NS_PER_SEC);
     EXPECT_EQ(eventDeactivationMap[3][0], eventActivationMap[0]);
     EXPECT_EQ(eventDeactivationMap[4][0], eventActivationMap[2]);
-    EXPECT_TRUE(metricProducer2->mIsActive);
+    EXPECT_TRUE(metricProducer2->isActive());
     EXPECT_EQ(eventActivationMap2[0]->state, ActivationState::kNotActive);
     EXPECT_EQ(eventActivationMap2[0]->start_ns, bucketStartTimeNs + 10);
     EXPECT_EQ(eventActivationMap2[0]->ttl_ns, 60 * 6 * NS_PER_SEC);
@@ -1577,7 +1577,7 @@ TEST(MetricActivationE2eTest, TestCountMetricWithTwoMetricsTwoDeactivations) {
     EXPECT_EQ(broadcastCount, 3);
     ASSERT_EQ(activeConfigsBroadcast.size(), 1);
     EXPECT_EQ(activeConfigsBroadcast[0], cfgId);
-    EXPECT_TRUE(metricProducer->mIsActive);
+    EXPECT_TRUE(metricProducer->isActive());
     EXPECT_EQ(eventActivationMap[0]->state, ActivationState::kActive);
     EXPECT_EQ(eventActivationMap[0]->start_ns, bucketStartTimeNs + NS_PER_SEC * 60 * 11 + 15);
     EXPECT_EQ(eventActivationMap[0]->ttl_ns, 60 * 6 * NS_PER_SEC);
@@ -1586,7 +1586,7 @@ TEST(MetricActivationE2eTest, TestCountMetricWithTwoMetricsTwoDeactivations) {
     EXPECT_EQ(eventActivationMap[2]->ttl_ns, 60 * 2 * NS_PER_SEC);
     EXPECT_EQ(eventDeactivationMap[3][0], eventActivationMap[0]);
     EXPECT_EQ(eventDeactivationMap[4][0], eventActivationMap[2]);
-    EXPECT_TRUE(metricProducer2->mIsActive);
+    EXPECT_TRUE(metricProducer2->isActive());
     EXPECT_EQ(eventActivationMap2[0]->state, ActivationState::kActive);
     EXPECT_EQ(eventActivationMap2[0]->start_ns, bucketStartTimeNs + NS_PER_SEC * 60 * 11 + 15);
     EXPECT_EQ(eventActivationMap2[0]->ttl_ns, 60 * 6 * NS_PER_SEC);
@@ -1609,7 +1609,7 @@ TEST(MetricActivationE2eTest, TestCountMetricWithTwoMetricsTwoDeactivations) {
     // New broadcast since the config is no longer active.
     EXPECT_EQ(broadcastCount, 4);
     ASSERT_EQ(activeConfigsBroadcast.size(), 0);
-    EXPECT_FALSE(metricProducer->mIsActive);
+    EXPECT_FALSE(metricProducer->isActive());
     EXPECT_EQ(eventActivationMap[0]->state, ActivationState::kNotActive);
     EXPECT_EQ(eventActivationMap[0]->start_ns, bucketStartTimeNs + NS_PER_SEC * 60 * 11 + 15);
     EXPECT_EQ(eventActivationMap[0]->ttl_ns, 60 * 6 * NS_PER_SEC);
@@ -1618,7 +1618,7 @@ TEST(MetricActivationE2eTest, TestCountMetricWithTwoMetricsTwoDeactivations) {
     EXPECT_EQ(eventActivationMap[2]->ttl_ns, 60 * 2 * NS_PER_SEC);
     EXPECT_EQ(eventDeactivationMap[3][0], eventActivationMap[0]);
     EXPECT_EQ(eventDeactivationMap[4][0], eventActivationMap[2]);
-    EXPECT_FALSE(metricProducer2->mIsActive);
+    EXPECT_FALSE(metricProducer2->isActive());
     EXPECT_EQ(eventActivationMap2[0]->state, ActivationState::kNotActive);
     EXPECT_EQ(eventActivationMap2[0]->start_ns, bucketStartTimeNs + NS_PER_SEC * 60 * 11 + 15);
     EXPECT_EQ(eventActivationMap2[0]->ttl_ns, 60 * 6 * NS_PER_SEC);
@@ -1636,7 +1636,7 @@ TEST(MetricActivationE2eTest, TestCountMetricWithTwoMetricsTwoDeactivations) {
     EXPECT_FALSE(metricsManager->isActive());
     EXPECT_EQ(broadcastCount, 4);
     ASSERT_EQ(activeConfigsBroadcast.size(), 0);
-    EXPECT_FALSE(metricProducer->mIsActive);
+    EXPECT_FALSE(metricProducer->isActive());
     EXPECT_EQ(eventActivationMap[0]->state, ActivationState::kNotActive);
     EXPECT_EQ(eventActivationMap[0]->start_ns, bucketStartTimeNs + NS_PER_SEC * 60 * 11 + 15);
     EXPECT_EQ(eventActivationMap[0]->ttl_ns, 60 * 6 * NS_PER_SEC);
@@ -1645,7 +1645,7 @@ TEST(MetricActivationE2eTest, TestCountMetricWithTwoMetricsTwoDeactivations) {
     EXPECT_EQ(eventActivationMap[2]->ttl_ns, 60 * 2 * NS_PER_SEC);
     EXPECT_EQ(eventDeactivationMap[3][0], eventActivationMap[0]);
     EXPECT_EQ(eventDeactivationMap[4][0], eventActivationMap[2]);
-    EXPECT_FALSE(metricProducer2->mIsActive);
+    EXPECT_FALSE(metricProducer2->isActive());
     EXPECT_EQ(eventActivationMap2[0]->state, ActivationState::kNotActive);
     EXPECT_EQ(eventActivationMap2[0]->start_ns, bucketStartTimeNs + NS_PER_SEC * 60 * 11 + 15);
     EXPECT_EQ(eventActivationMap2[0]->ttl_ns, 60 * 6 * NS_PER_SEC);
@@ -1667,7 +1667,7 @@ TEST(MetricActivationE2eTest, TestCountMetricWithTwoMetricsTwoDeactivations) {
     EXPECT_EQ(broadcastCount, 5);
     ASSERT_EQ(activeConfigsBroadcast.size(), 1);
     EXPECT_EQ(activeConfigsBroadcast[0], cfgId);
-    EXPECT_TRUE(metricProducer->mIsActive);
+    EXPECT_TRUE(metricProducer->isActive());
     EXPECT_EQ(eventActivationMap[0]->state, ActivationState::kActive);
     EXPECT_EQ(eventActivationMap[0]->start_ns, bucketStartTimeNs + NS_PER_SEC * 60 * 15 + 15);
     EXPECT_EQ(eventActivationMap[0]->ttl_ns, 60 * 6 * NS_PER_SEC);
@@ -1676,7 +1676,7 @@ TEST(MetricActivationE2eTest, TestCountMetricWithTwoMetricsTwoDeactivations) {
     EXPECT_EQ(eventActivationMap[2]->ttl_ns, 60 * 2 * NS_PER_SEC);
     EXPECT_EQ(eventDeactivationMap[3][0], eventActivationMap[0]);
     EXPECT_EQ(eventDeactivationMap[4][0], eventActivationMap[2]);
-    EXPECT_TRUE(metricProducer2->mIsActive);
+    EXPECT_TRUE(metricProducer2->isActive());
     EXPECT_EQ(eventActivationMap2[0]->state, ActivationState::kActive);
     EXPECT_EQ(eventActivationMap2[0]->start_ns, bucketStartTimeNs + NS_PER_SEC * 60 * 15 + 15);
     EXPECT_EQ(eventActivationMap2[0]->ttl_ns, 60 * 6 * NS_PER_SEC);
@@ -1692,7 +1692,7 @@ TEST(MetricActivationE2eTest, TestCountMetricWithTwoMetricsTwoDeactivations) {
     EXPECT_FALSE(metricsManager->isActive());
     EXPECT_EQ(broadcastCount, 6);
     ASSERT_EQ(activeConfigsBroadcast.size(), 0);
-    EXPECT_FALSE(metricProducer->mIsActive);
+    EXPECT_FALSE(metricProducer->isActive());
     EXPECT_EQ(eventActivationMap[0]->state, ActivationState::kNotActive);
     EXPECT_EQ(eventActivationMap[0]->start_ns, bucketStartTimeNs + NS_PER_SEC * 60 * 15 + 15);
     EXPECT_EQ(eventActivationMap[0]->ttl_ns, 60 * 6 * NS_PER_SEC);
@@ -1701,7 +1701,7 @@ TEST(MetricActivationE2eTest, TestCountMetricWithTwoMetricsTwoDeactivations) {
     EXPECT_EQ(eventActivationMap[2]->ttl_ns, 60 * 2 * NS_PER_SEC);
     EXPECT_EQ(eventDeactivationMap[3][0], eventActivationMap[0]);
     EXPECT_EQ(eventDeactivationMap[4][0], eventActivationMap[2]);
-    EXPECT_FALSE(metricProducer2->mIsActive);
+    EXPECT_FALSE(metricProducer2->isActive());
     EXPECT_EQ(eventActivationMap2[0]->state, ActivationState::kNotActive);
     EXPECT_EQ(eventActivationMap2[0]->start_ns, bucketStartTimeNs + NS_PER_SEC * 60 * 15 + 15);
     EXPECT_EQ(eventActivationMap2[0]->ttl_ns, 60 * 6 * NS_PER_SEC);
diff --git a/statsd/tests/e2e/ValueMetric_pull_e2e_test.cpp b/statsd/tests/e2e/ValueMetric_pull_e2e_test.cpp
index 16b41b1c..c0ccdcc9 100644
--- a/statsd/tests/e2e/ValueMetric_pull_e2e_test.cpp
+++ b/statsd/tests/e2e/ValueMetric_pull_e2e_test.cpp
@@ -13,6 +13,8 @@
 // limitations under the License.
 
 #include <android/binder_interface_utils.h>
+#include <com_android_os_statsd_flags.h>
+#include <flag_macros.h>
 #include <gtest/gtest.h>
 
 #include <vector>
@@ -29,15 +31,19 @@ namespace statsd {
 
 #ifdef __ANDROID__
 
+using aidl::android::util::StatsEventParcel;
+using namespace std;
+using namespace testing;
+
 namespace {
 
 const int64_t metricId = 123456;
 
-StatsdConfig CreateStatsdConfig(bool useCondition = true) {
+StatsdConfig CreateStatsdConfig(int whatAtomId, int valueField, int dimField,
+                                bool useCondition = true) {
     StatsdConfig config;
     config.add_default_pull_packages("AID_ROOT");  // Fake puller is registered with root.
-    auto pulledAtomMatcher =
-            CreateSimpleAtomMatcher("TestMatcher", util::SUBSYSTEM_SLEEP_STATE);
+    auto pulledAtomMatcher = CreateSimpleAtomMatcher("TestMatcher", whatAtomId);
     *config.add_atom_matcher() = pulledAtomMatcher;
     *config.add_atom_matcher() = CreateScreenTurnedOnAtomMatcher();
     *config.add_atom_matcher() = CreateScreenTurnedOffAtomMatcher();
@@ -51,10 +57,8 @@ StatsdConfig CreateStatsdConfig(bool useCondition = true) {
     if (useCondition) {
         valueMetric->set_condition(screenIsOffPredicate.id());
     }
-    *valueMetric->mutable_value_field() =
-            CreateDimensions(util::SUBSYSTEM_SLEEP_STATE, {4 /* time sleeping field */});
-    *valueMetric->mutable_dimensions_in_what() =
-            CreateDimensions(util::SUBSYSTEM_SLEEP_STATE, {1 /* subsystem name */});
+    *valueMetric->mutable_value_field() = CreateDimensions(whatAtomId, {valueField});
+    *valueMetric->mutable_dimensions_in_what() = CreateDimensions(whatAtomId, {dimField});
     valueMetric->set_bucket(FIVE_MINUTES);
     valueMetric->set_use_absolute_value_on_reset(true);
     valueMetric->set_skip_zero_diff_output(false);
@@ -201,7 +205,8 @@ TEST(ValueMetricE2eTest, TestInitialConditionChanges) {
 }
 
 TEST(ValueMetricE2eTest, TestPulledEvents) {
-    auto config = CreateStatsdConfig();
+    auto config = CreateStatsdConfig(util::SUBSYSTEM_SLEEP_STATE, /* valueField = */ 4,
+                                     /* dimField = */ 1);
     int64_t baseTimeNs = getElapsedRealtimeNs();
     int64_t configAddedTimeNs = 10 * 60 * NS_PER_SEC + baseTimeNs;
     int64_t bucketSizeNs = TimeUnitToBucketSizeInMillis(config.value_metric(0).bucket()) * 1000000;
@@ -322,7 +327,8 @@ TEST(ValueMetricE2eTest, TestPulledEvents) {
 }
 
 TEST(ValueMetricE2eTest, TestPulledEvents_LateAlarm) {
-    auto config = CreateStatsdConfig();
+    auto config = CreateStatsdConfig(util::SUBSYSTEM_SLEEP_STATE, /* valueField = */ 4,
+                                     /* dimField = */ 1);
     int64_t baseTimeNs = getElapsedRealtimeNs();
     // 10 mins == 2 bucket durations.
     int64_t configAddedTimeNs = 10 * 60 * NS_PER_SEC + baseTimeNs;
@@ -449,7 +455,8 @@ TEST(ValueMetricE2eTest, TestPulledEvents_LateAlarm) {
 }
 
 TEST(ValueMetricE2eTest, TestPulledEvents_WithActivation) {
-    auto config = CreateStatsdConfig(false);
+    auto config = CreateStatsdConfig(util::SUBSYSTEM_SLEEP_STATE, /* valueField = */ 4,
+                                     /* dimField = */ 1, /* useCondition = */ false);
     int64_t baseTimeNs = getElapsedRealtimeNs();
     int64_t configAddedTimeNs = 10 * 60 * NS_PER_SEC + baseTimeNs;
     int64_t bucketSizeNs = TimeUnitToBucketSizeInMillis(config.value_metric(0).bucket()) * 1000000;
@@ -915,6 +922,386 @@ TEST(ValueMetricE2eTest, TestInitWithDefaultAggType) {
     EXPECT_FALSE(valueProducer->mIncludeSampleSize);
 }
 
+namespace {
+
+class Puller : public BnPullAtomCallback {
+public:
+    int curPullNum = 0;
+
+    struct AtomData {
+        int uid;
+        int value;
+    };
+
+    // Mapping of uid to values for each pull
+    const vector<vector<AtomData>> data;
+
+    Puller(const vector<vector<AtomData>>& data) : data(data) {
+    }
+
+    Status onPullAtom(int atomId,
+                      const shared_ptr<IPullAtomResultReceiver>& resultReceiver) override {
+        vector<StatsEventParcel> parcels;
+        for (const auto [uid, value] : data[curPullNum]) {
+            AStatsEvent* statsEvent = AStatsEvent_obtain();
+            AStatsEvent_setAtomId(statsEvent, atomId);
+            AStatsEvent_writeInt32(statsEvent, uid);
+            AStatsEvent_writeInt32(statsEvent, value);
+            AStatsEvent_build(statsEvent);
+            size_t size;
+            uint8_t* buffer = AStatsEvent_getBuffer(statsEvent, &size);
+
+            StatsEventParcel p;
+            // vector.assign() creates a copy, but this is inevitable unless
+            // stats_event.h/c uses a vector as opposed to a buffer.
+            p.buffer.assign(buffer, buffer + size);
+            parcels.push_back(std::move(p));
+            AStatsEvent_release(statsEvent);
+        }
+        curPullNum++;
+        resultReceiver->pullFinished(atomId, /*success=*/true, parcels);
+        return Status::ok();
+    }
+};
+
+}  // anonymous namespace
+
+TEST_WITH_FLAGS(ValueMetricE2eTest, TestDimensionGuardrailHitWithZeroDefaultBase,
+                REQUIRES_FLAGS_ENABLED(ACONFIG_FLAG(com::android::os::statsd::flags,
+                                                    keep_value_metric_max_dimension_bucket))) {
+    const int atomId = 10'000;
+    StatsdConfig config = CreateStatsdConfig(atomId, /* valueField = */ 2, /* dimField = */ 1,
+                                             /* useCondition = */ false);
+    config.mutable_value_metric(0)->set_use_zero_default_base(true);
+
+    // Initialize StatsLogProcessor.
+    const uint64_t baseTimeNs = getElapsedRealtimeNs();
+    const uint64_t bucketSizeNs = TimeUnitToBucketSizeInMillis(FIVE_MINUTES) * 1000000LL;
+    const uint64_t bucketStartTimeNs = baseTimeNs + bucketSizeNs;
+    int uid = 12345;
+    int64_t cfgId = 98765;
+    ConfigKey cfgKey(uid, cfgId);
+    vector<vector<Puller::AtomData>> atomData;
+    atomData.push_back({});
+    const int maxDims = 800;
+
+    // Initial pull to set the base.
+    for (int dim = 1; dim <= maxDims + 2; dim++) {
+        atomData[0].push_back({dim, 1});
+    }
+
+    // End of first bucket.
+    atomData.push_back({});
+    for (int dim = maxDims - 1; dim <= maxDims + 2; dim++) {
+        atomData[1].push_back({dim, 3});
+    }
+
+    // End of second bucket.
+    atomData.push_back({});
+    for (int dim = 1; dim <= maxDims + 2; dim++) {
+        atomData[2].push_back({dim, 6});
+    }
+
+    shared_ptr<Puller> puller = SharedRefBase::make<Puller>(atomData);
+    sp<StatsLogProcessor> processor =
+            CreateStatsLogProcessor(baseTimeNs, bucketStartTimeNs, config, cfgKey, puller, atomId);
+
+    processor->mPullerManager->ForceClearPullerCache();
+    processor->informPullAlarmFired(baseTimeNs + bucketSizeNs * 2 + 1);
+
+    processor->mPullerManager->ForceClearPullerCache();
+    processor->informPullAlarmFired(baseTimeNs + bucketSizeNs * 3 + 1);
+
+    optional<ConfigMetricsReportList> reports =
+            getReports(*processor, baseTimeNs + bucketSizeNs * 3 + 2, cfgKey,
+                       /* includeCurrentBucket */ false);
+
+    ASSERT_NE(reports, nullopt);
+    ASSERT_EQ(reports->reports_size(), 1);
+    ConfigMetricsReport report = reports->reports(0);
+    ASSERT_EQ(report.metrics_size(), 1);
+
+    StatsLogReport metricReport = report.metrics(0);
+    EXPECT_TRUE(metricReport.dimension_guardrail_hit());
+    ASSERT_TRUE(metricReport.has_value_metrics());
+    EXPECT_EQ(metricReport.value_metrics().skipped_size(), 0);
+    StatsLogReport::ValueMetricDataWrapper valueMetrics;
+    sortMetricDataByDimensionsValue(metricReport.value_metrics(), &valueMetrics);
+
+    ASSERT_EQ(valueMetrics.data_size(), 2);
+    {  // uid = 799
+        ValueMetricData data = valueMetrics.data(0);
+        EXPECT_EQ(atomId, data.dimensions_in_what().field());
+        ASSERT_EQ(1, data.dimensions_in_what().value_tuple().dimensions_value_size());
+        EXPECT_EQ(1 /* uid field tag */,
+                  data.dimensions_in_what().value_tuple().dimensions_value(0).field());
+        EXPECT_EQ(maxDims - 1 /* uid field value */,
+                  data.dimensions_in_what().value_tuple().dimensions_value(0).value_int());
+
+        ASSERT_EQ(data.bucket_info_size(), 2);
+        {
+            ValueBucketInfo bucket = data.bucket_info(0);
+            ASSERT_EQ(bucket.values_size(), 1);
+            EXPECT_THAT(bucket.values(0),
+                        Property(&ValueBucketInfo::Value::has_value_long, IsTrue()));
+            EXPECT_EQ(bucket.values(0).value_long(), 2);
+        }
+
+        {
+            ValueBucketInfo bucket = data.bucket_info(1);
+            ASSERT_EQ(bucket.values_size(), 1);
+            EXPECT_THAT(bucket.values(0),
+                        Property(&ValueBucketInfo::Value::has_value_long, IsTrue()));
+            EXPECT_EQ(bucket.values(0).value_long(), 3);
+        }
+    }
+
+    {  // uid = 800
+        ValueMetricData data = valueMetrics.data(1);
+        EXPECT_EQ(atomId, data.dimensions_in_what().field());
+        ASSERT_EQ(1, data.dimensions_in_what().value_tuple().dimensions_value_size());
+        EXPECT_EQ(1 /* uid field tag */,
+                  data.dimensions_in_what().value_tuple().dimensions_value(0).field());
+        EXPECT_EQ(maxDims /* uid field value */,
+                  data.dimensions_in_what().value_tuple().dimensions_value(0).value_int());
+
+        ASSERT_EQ(data.bucket_info_size(), 2);
+        {
+            ValueBucketInfo bucket = data.bucket_info(0);
+            ASSERT_EQ(bucket.values_size(), 1);
+            EXPECT_THAT(bucket.values(0),
+                        Property(&ValueBucketInfo::Value::has_value_long, IsTrue()));
+            EXPECT_EQ(bucket.values(0).value_long(), 2);
+        }
+
+        {
+            ValueBucketInfo bucket = data.bucket_info(1);
+            ASSERT_EQ(bucket.values_size(), 1);
+            EXPECT_THAT(bucket.values(0),
+                        Property(&ValueBucketInfo::Value::has_value_long, IsTrue()));
+            EXPECT_EQ(bucket.values(0).value_long(), 3);
+        }
+    }
+}
+
+TEST_WITH_FLAGS(ValueMetricE2eTest,
+                TestDimensionGuardrailHitWithZeroDefaultBaseAndConditionAndState,
+                REQUIRES_FLAGS_ENABLED(ACONFIG_FLAG(com::android::os::statsd::flags,
+                                                    keep_value_metric_max_dimension_bucket))) {
+    const int atomId = 10'000;
+    StatsdConfig config = CreateStatsdConfig(atomId, /* valueField = */ 2, /* dimField = */ 1,
+                                             /* useCondition = */ true);
+    *config.add_atom_matcher() = CreateBatteryStateNoneMatcher();
+    *config.add_atom_matcher() = CreateBatteryStateUsbMatcher();
+    State state;
+    state.set_id(StringToId("PluggedState"));
+    state.set_atom_id(util::PLUGGED_STATE_CHANGED);
+    *config.add_state() = state;
+    config.mutable_value_metric(0)->add_slice_by_state(state.id());
+    config.mutable_value_metric(0)->set_use_zero_default_base(true);
+
+    // Initialize StatsLogProcessor.
+    const uint64_t baseTimeNs = getElapsedRealtimeNs();
+    const uint64_t bucketSizeNs = TimeUnitToBucketSizeInMillis(FIVE_MINUTES) * 1000000LL;
+    const uint64_t bucketStartTimeNs = baseTimeNs + bucketSizeNs;
+    int uid = 12345;
+    int64_t cfgId = 98765;
+    ConfigKey cfgKey(uid, cfgId);
+    vector<vector<Puller::AtomData>> atomData;
+    atomData.push_back({});
+    const int numDims = 400;
+
+    // There is no initial pull to set the base because condition is false.
+    // This pull is for condition change to true. Bucket is skipped because initial condition is
+    // unknown.
+    for (int dim = 1; dim <= numDims; dim++) {
+        atomData[0].push_back({dim, 1});
+    }
+
+    // End of first bucket.
+    atomData.push_back({});
+    for (int dim = 1; dim <= numDims; dim++) {
+        atomData[1].push_back({dim, 3});
+    }
+
+    // State change. For each dim, values are calculated for old state and condition timer is
+    // started for new state. This doubles the number of keys in mCurrentSlicedBucket. Hence, there
+    // are 804 keys total, of which the first 800 are kept.
+    atomData.push_back({});
+    for (int dim = 1; dim <= numDims + 2; dim++) {
+        atomData[2].push_back({dim, 6});
+    }
+
+    // End of 2nd bucket.
+    atomData.push_back({});
+    for (int dim = 1; dim <= numDims; dim++) {
+        atomData[3].push_back({dim, 10});
+    }
+
+    // Condition change to false.
+    atomData.push_back({});
+    for (int dim = 1; dim <= numDims * 2 + 1; dim++) {
+        atomData[4].push_back({dim, 15});
+    }
+
+    // This would be end of third bucket but this pull doesn't happen since condition is false.
+    atomData.push_back({});
+    for (int dim = 1; dim <= numDims; dim++) {
+        atomData[5].push_back({dim, 21});
+    }
+
+    StateManager::getInstance().clear();
+    shared_ptr<Puller> puller = SharedRefBase::make<Puller>(atomData);
+    sp<StatsLogProcessor> processor =
+            CreateStatsLogProcessor(baseTimeNs, bucketStartTimeNs, config, cfgKey, puller, atomId);
+
+    processor->mPullerManager->ForceClearPullerCache();
+    unique_ptr<LogEvent> screenOffEvent = CreateScreenStateChangedEvent(
+            baseTimeNs + bucketSizeNs + 40, android::view::DISPLAY_STATE_OFF);
+    processor->OnLogEvent(screenOffEvent.get());
+
+    processor->mPullerManager->ForceClearPullerCache();
+    processor->informPullAlarmFired(baseTimeNs + bucketSizeNs * 2 + 1);
+
+    processor->mPullerManager->ForceClearPullerCache();
+    unique_ptr<LogEvent> pluggedUsbEvent = CreateBatteryStateChangedEvent(
+            baseTimeNs + bucketSizeNs * 2 + 10, BatteryPluggedStateEnum::BATTERY_PLUGGED_USB);
+    processor->OnLogEvent(pluggedUsbEvent.get());
+
+    processor->mPullerManager->ForceClearPullerCache();
+    processor->informPullAlarmFired(baseTimeNs + bucketSizeNs * 3 + 1);
+
+    processor->mPullerManager->ForceClearPullerCache();
+    unique_ptr<LogEvent> screenOnEvent = CreateScreenStateChangedEvent(
+            baseTimeNs + bucketSizeNs * 3 + 10, android::view::DISPLAY_STATE_ON);
+    processor->OnLogEvent(screenOnEvent.get());
+
+    processor->mPullerManager->ForceClearPullerCache();
+    processor->informPullAlarmFired(baseTimeNs + bucketSizeNs * 4 + 1);
+
+    optional<ConfigMetricsReportList> reports =
+            getReports(*processor, baseTimeNs + bucketSizeNs * 5 + 2, cfgKey,
+                       /* includeCurrentBucket */ false);
+
+    ASSERT_NE(reports, nullopt);
+    ASSERT_EQ(reports->reports_size(), 1);
+    ConfigMetricsReport report = reports->reports(0);
+    ASSERT_EQ(report.metrics_size(), 1);
+
+    StatsLogReport metricReport = report.metrics(0);
+    EXPECT_TRUE(metricReport.dimension_guardrail_hit());
+    ASSERT_TRUE(metricReport.has_value_metrics());
+    EXPECT_EQ(metricReport.value_metrics().skipped_size(), 1);
+    EXPECT_EQ(metricReport.value_metrics().skipped(0).drop_event(0).drop_reason(),
+              BucketDropReason::CONDITION_UNKNOWN);
+    StatsLogReport::ValueMetricDataWrapper valueMetrics;
+    sortMetricDataByDimensionsValue(metricReport.value_metrics(), &valueMetrics);
+
+    // 800 dimension + state combinations
+    EXPECT_EQ(valueMetrics.data_size(), 800);
+
+    // Verify slice_by_state atom ID
+    EXPECT_THAT(valueMetrics.data(),
+                Each(Property(
+                        &ValueMetricData::slice_by_state,
+                        ElementsAre(Property(&StateValue::atom_id, util::PLUGGED_STATE_CHANGED)))));
+
+    // Verify dimension_in_what atom ID
+    EXPECT_THAT(valueMetrics.data(), Each(Property(&ValueMetricData::dimensions_in_what,
+                                                   Property(&DimensionsValue::field, atomId))));
+
+    // Data where state = unknown
+    vector<ValueMetricData> stateUnknownData;
+    std::copy_if(valueMetrics.data().begin(), valueMetrics.data().end(),
+                 std::back_inserter(stateUnknownData), [](const ValueMetricData& data) {
+                     return data.slice_by_state_size() == 1 &&
+                            data.slice_by_state(0).value() == -1 /* kStateUnknown */;
+                 });
+    EXPECT_EQ(stateUnknownData.size(), 400);
+
+    vector<DimensionsValueTuple> valueTuples(stateUnknownData.size());
+    std::transform(
+            stateUnknownData.cbegin(), stateUnknownData.cend(), valueTuples.begin(),
+            [](const ValueMetricData& data) { return data.dimensions_in_what().value_tuple(); });
+    EXPECT_THAT(valueTuples, Each(Property(&DimensionsValueTuple::dimensions_value_size, 1)));
+
+    vector<DimensionsValue> dimensionsValues(valueTuples.size());
+    std::transform(valueTuples.cbegin(), valueTuples.cend(), dimensionsValues.begin(),
+                   [](const DimensionsValueTuple& tuple) { return tuple.dimensions_value(0); });
+    EXPECT_THAT(dimensionsValues, Each(Property(&DimensionsValue::field, 1)));
+
+    // Verify uids 1 - 400 are present in the dimensions
+    vector<testing::Matcher<DimensionsValue>> dimensionsValueMatchers(dimensionsValues.size());
+    std::generate(dimensionsValueMatchers.begin(), dimensionsValueMatchers.end(), []() {
+        static int uid = 1;
+        return Property(&DimensionsValue::value_int, uid++);
+    });
+    EXPECT_THAT(dimensionsValues, ElementsAreArray(dimensionsValueMatchers));
+
+    EXPECT_THAT(stateUnknownData, Each(Property(&ValueMetricData::bucket_info_size, 1)));
+    EXPECT_THAT(stateUnknownData, Each(Property(&ValueMetricData::bucket_info,
+                                                Each(Property(&ValueBucketInfo::values_size, 1)))));
+    vector<ValueBucketInfo::Value> values(stateUnknownData.size());
+    std::transform(stateUnknownData.cbegin(), stateUnknownData.cend(), values.begin(),
+                   [](const ValueMetricData& data) { return data.bucket_info(0).values(0); });
+    EXPECT_THAT(values, Each(Property(&ValueBucketInfo::Value::has_value_long, IsTrue())));
+
+    // Value for each dimension is 6 - 3 = 3
+    EXPECT_THAT(values, Each(Property(&ValueBucketInfo::Value::value_long, 3)));
+
+    // Data where state = plugged
+    vector<ValueMetricData> statePluggedData;
+    std::copy_if(valueMetrics.data().begin(), valueMetrics.data().end(),
+                 std::back_inserter(statePluggedData), [](const ValueMetricData& data) {
+                     return data.slice_by_state_size() == 1 &&
+                            data.slice_by_state(0).value() ==
+                                    BatteryPluggedStateEnum::BATTERY_PLUGGED_USB;
+                 });
+    EXPECT_EQ(statePluggedData.size(), 400);
+
+    valueTuples.resize(statePluggedData.size());
+    std::transform(
+            statePluggedData.cbegin(), statePluggedData.cend(), valueTuples.begin(),
+            [](const ValueMetricData& data) { return data.dimensions_in_what().value_tuple(); });
+    EXPECT_THAT(valueTuples, Each(Property(&DimensionsValueTuple::dimensions_value_size, 1)));
+
+    dimensionsValues.resize(valueTuples.size());
+    std::transform(valueTuples.cbegin(), valueTuples.cend(), dimensionsValues.begin(),
+                   [](const DimensionsValueTuple& tuple) { return tuple.dimensions_value(0); });
+    EXPECT_THAT(dimensionsValues, Each(Property(&DimensionsValue::field, 1)));
+
+    // Verify uids 1 - 400 are present in the dimensions for plugged state
+    dimensionsValueMatchers.resize(dimensionsValues.size());
+    std::generate(dimensionsValueMatchers.begin(), dimensionsValueMatchers.end(), []() {
+        static int uid = 1;
+        return Property(&DimensionsValue::value_int, uid++);
+    });
+    EXPECT_THAT(dimensionsValues, ElementsAreArray(dimensionsValueMatchers));
+
+    // Two buckets per dimension for state == plugged
+    EXPECT_THAT(statePluggedData, Each(Property(&ValueMetricData::bucket_info_size, 2)));
+    EXPECT_THAT(statePluggedData, Each(Property(&ValueMetricData::bucket_info,
+                                                Each(Property(&ValueBucketInfo::values_size, 1)))));
+    EXPECT_THAT(statePluggedData,
+                Each(Property(&ValueMetricData::bucket_info,
+                              Each(Property(&ValueBucketInfo::values,
+                                            Each(Property(&ValueBucketInfo::Value::has_value_long,
+                                                          IsTrue())))))));
+
+    // 2nd bucket values
+    // Value for each dimension is 10 - 6 = 4
+    values.resize(statePluggedData.size());
+    std::transform(statePluggedData.cbegin(), statePluggedData.cend(), values.begin(),
+                   [](const ValueMetricData& data) { return data.bucket_info(0).values(0); });
+    EXPECT_THAT(values, Each(Property(&ValueBucketInfo::Value::value_long, 4)));
+
+    // 3rd bucket values
+    // Value for each dimension is 15 - 10 = 5
+    std::transform(statePluggedData.cbegin(), statePluggedData.cend(), values.begin(),
+                   [](const ValueMetricData& data) { return data.bucket_info(1).values(0); });
+    EXPECT_THAT(values, Each(Property(&ValueBucketInfo::Value::value_long, 5)));
+}
+
 #else
 GTEST_LOG_(INFO) << "This test does nothing.\n";
 #endif
diff --git a/statsd/tests/external/StatsCallbackPuller_test.cpp b/statsd/tests/external/StatsCallbackPuller_test.cpp
index 151aae35..eb0845a4 100644
--- a/statsd/tests/external/StatsCallbackPuller_test.cpp
+++ b/statsd/tests/external/StatsCallbackPuller_test.cpp
@@ -136,7 +136,7 @@ TEST_F(StatsCallbackPullerTest, PullSuccess) {
     EXPECT_LT(startTimeNs, dataHolder[0]->GetElapsedTimestampNs());
     EXPECT_GT(endTimeNs, dataHolder[0]->GetElapsedTimestampNs());
     ASSERT_EQ(1, dataHolder[0]->size());
-    EXPECT_EQ(value, dataHolder[0]->getValues()[0].mValue.int_value);
+    EXPECT_EQ(value, dataHolder[0]->getValues()[0].mValue.get<int64_t>());
 }
 
 TEST_F(StatsCallbackPullerTest, PullFail) {
diff --git a/statsd/tests/external/StatsPullerManager_test.cpp b/statsd/tests/external/StatsPullerManager_test.cpp
index b112d802..3aa1c2d2 100644
--- a/statsd/tests/external/StatsPullerManager_test.cpp
+++ b/statsd/tests/external/StatsPullerManager_test.cpp
@@ -16,6 +16,8 @@
 
 #include <aidl/android/os/IPullAtomResultReceiver.h>
 #include <aidl/android/util/StatsEventParcel.h>
+#include <com_android_os_statsd_flags.h>
+#include <flag_macros.h>
 #include <gmock/gmock.h>
 #include <gtest/gtest.h>
 
@@ -165,7 +167,7 @@ TEST(StatsPullerManagerTest, TestPullChoosesCorrectUid) {
     ASSERT_EQ(data.size(), 1);
     EXPECT_EQ(data[0]->GetTagId(), pullTagId1);
     ASSERT_EQ(data[0]->getValues().size(), 1);
-    EXPECT_EQ(data[0]->getValues()[0].mValue.int_value, uid1);
+    EXPECT_EQ(data[0]->getValues()[0].mValue.get<int32_t>(), uid1);
 }
 
 TEST(StatsPullerManagerTest, TestPullInvalidConfigKey) {
@@ -186,7 +188,7 @@ TEST(StatsPullerManagerTest, TestPullConfigKeyGood) {
     EXPECT_TRUE(pullerManager->Pull(pullTagId1, configKey, /*timestamp =*/1, &data));
     EXPECT_EQ(data[0]->GetTagId(), pullTagId1);
     ASSERT_EQ(data[0]->getValues().size(), 1);
-    EXPECT_EQ(data[0]->getValues()[0].mValue.int_value, uid2);
+    EXPECT_EQ(data[0]->getValues()[0].mValue.get<int32_t>(), uid2);
 }
 
 TEST(StatsPullerManagerTest, TestPullConfigKeyNoPullerWithUid) {
@@ -354,6 +356,7 @@ TEST(StatsPullerManagerTest, TestOnAlarmFiredMultipleUidsSelectsFirstUid) {
 }
 
 TEST(StatsPullerManagerTest, TestOnAlarmFiredUidsNotRegisteredInPullAtomCallback) {
+    StatsdStats::getInstance().reset();
     sp<MockPullDataReceiver> receiver = new StrictMock<MockPullDataReceiver>();
     EXPECT_CALL(*receiver, onDataPulled(_, PullResult::PULL_RESULT_FAIL, _)).Times(1);
     sp<StatsPullerManager> pullerManager = new StatsPullerManager();
@@ -373,6 +376,17 @@ TEST(StatsPullerManagerTest, TestOnAlarmFiredUidsNotRegisteredInPullAtomCallback
     EXPECT_EQ(StatsdStats::getInstance().mPulledAtomStats[pullTagId1].pullFailed, 0);
 }
 
+TEST_WITH_FLAGS(StatsPullerManagerTest, TestOnAlarmFiredNoPulls,
+                REQUIRES_FLAGS_ENABLED(ACONFIG_FLAG(com::android::os::statsd::flags,
+                                                    parallel_pulls))) {
+    StatsdStats::getInstance().reset();
+    sp<StatsPullerManager> pullerManager = new StatsPullerManager();
+
+    pullerManager->OnAlarmFired(100);
+
+    EXPECT_EQ(StatsdStats::getInstance().mPullerAlarmStats.alarm_without_pulls_count, 1);
+}
+
 }  // namespace statsd
 }  // namespace os
 }  // namespace android
diff --git a/statsd/tests/external/StatsPuller_test.cpp b/statsd/tests/external/StatsPuller_test.cpp
index a491d83b..a0a15069 100644
--- a/statsd/tests/external/StatsPuller_test.cpp
+++ b/statsd/tests/external/StatsPuller_test.cpp
@@ -97,7 +97,7 @@ TEST_F(StatsPullerTest, PullSuccess) {
     EXPECT_EQ(pullTagId, dataHolder[0]->GetTagId());
     EXPECT_EQ(1111L, dataHolder[0]->GetElapsedTimestampNs());
     ASSERT_EQ(1, dataHolder[0]->size());
-    EXPECT_EQ(33, dataHolder[0]->getValues()[0].mValue.int_value);
+    EXPECT_EQ(33, dataHolder[0]->getValues()[0].mValue.get<int64_t>());
 
     sleep_for(std::chrono::milliseconds(11));
 
@@ -111,7 +111,7 @@ TEST_F(StatsPullerTest, PullSuccess) {
     EXPECT_EQ(pullTagId, dataHolder[0]->GetTagId());
     EXPECT_EQ(2222L, dataHolder[0]->GetElapsedTimestampNs());
     ASSERT_EQ(1, dataHolder[0]->size());
-    EXPECT_EQ(44, dataHolder[0]->getValues()[0].mValue.int_value);
+    EXPECT_EQ(44, dataHolder[0]->getValues()[0].mValue.get<int64_t>());
 }
 
 TEST_F(StatsPullerTest, PullFailAfterSuccess) {
@@ -125,7 +125,7 @@ TEST_F(StatsPullerTest, PullFailAfterSuccess) {
     EXPECT_EQ(pullTagId, dataHolder[0]->GetTagId());
     EXPECT_EQ(1111L, dataHolder[0]->GetElapsedTimestampNs());
     ASSERT_EQ(1, dataHolder[0]->size());
-    EXPECT_EQ(33, dataHolder[0]->getValues()[0].mValue.int_value);
+    EXPECT_EQ(33, dataHolder[0]->getValues()[0].mValue.get<int64_t>());
 
     sleep_for(std::chrono::milliseconds(11));
 
@@ -197,7 +197,7 @@ TEST_F(StatsPullerTest, PullTooFast) {
     EXPECT_EQ(pullTagId, dataHolder[0]->GetTagId());
     EXPECT_EQ(1111L, dataHolder[0]->GetElapsedTimestampNs());
     ASSERT_EQ(1, dataHolder[0]->size());
-    EXPECT_EQ(33, dataHolder[0]->getValues()[0].mValue.int_value);
+    EXPECT_EQ(33, dataHolder[0]->getValues()[0].mValue.get<int64_t>());
 
     pullData.clear();
     pullData.push_back(createSimpleEvent(2222L, 44));
@@ -210,7 +210,7 @@ TEST_F(StatsPullerTest, PullTooFast) {
     EXPECT_EQ(pullTagId, dataHolder[0]->GetTagId());
     EXPECT_EQ(1111L, dataHolder[0]->GetElapsedTimestampNs());
     ASSERT_EQ(1, dataHolder[0]->size());
-    EXPECT_EQ(33, dataHolder[0]->getValues()[0].mValue.int_value);
+    EXPECT_EQ(33, dataHolder[0]->getValues()[0].mValue.get<int64_t>());
 }
 
 TEST_F(StatsPullerTest, PullFailsAndTooFast) {
@@ -243,7 +243,7 @@ TEST_F(StatsPullerTest, PullSameEventTime) {
     EXPECT_EQ(pullTagId, dataHolder[0]->GetTagId());
     EXPECT_EQ(1111L, dataHolder[0]->GetElapsedTimestampNs());
     ASSERT_EQ(1, dataHolder[0]->size());
-    EXPECT_EQ(33, dataHolder[0]->getValues()[0].mValue.int_value);
+    EXPECT_EQ(33, dataHolder[0]->getValues()[0].mValue.get<int64_t>());
 
     pullData.clear();
     pullData.push_back(createSimpleEvent(2222L, 44));
@@ -258,7 +258,7 @@ TEST_F(StatsPullerTest, PullSameEventTime) {
     EXPECT_EQ(pullTagId, dataHolder[0]->GetTagId());
     EXPECT_EQ(1111L, dataHolder[0]->GetElapsedTimestampNs());
     ASSERT_EQ(1, dataHolder[0]->size());
-    EXPECT_EQ(33, dataHolder[0]->getValues()[0].mValue.int_value);
+    EXPECT_EQ(33, dataHolder[0]->getValues()[0].mValue.get<int64_t>());
 }
 
 // Test pull takes longer than timeout, 2nd pull happens at same event time
diff --git a/statsd/tests/external/puller_util_test.cpp b/statsd/tests/external/puller_util_test.cpp
index a577f8d7..6914bf76 100644
--- a/statsd/tests/external/puller_util_test.cpp
+++ b/statsd/tests/external/puller_util_test.cpp
@@ -33,6 +33,7 @@ namespace statsd {
 
 using namespace testing;
 using std::shared_ptr;
+using std::string;
 using std::vector;
 /*
  * Test merge isolated and host uid
@@ -78,9 +79,10 @@ TEST(PullerUtilTest, MergeNoDimension) {
     ASSERT_EQ(1, (int)data.size());
     const vector<FieldValue>* actualFieldValues = &data[0]->getValues();
     ASSERT_EQ(3, actualFieldValues->size());
-    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.int_value);
-    EXPECT_EQ(hostNonAdditiveData, actualFieldValues->at(1).mValue.int_value);
-    EXPECT_EQ(isolatedAdditiveData + hostAdditiveData, actualFieldValues->at(2).mValue.int_value);
+    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.get<int32_t>());
+    EXPECT_EQ(hostNonAdditiveData, actualFieldValues->at(1).mValue.get<int32_t>());
+    EXPECT_EQ(isolatedAdditiveData + hostAdditiveData,
+              actualFieldValues->at(2).mValue.get<int32_t>());
 }
 
 TEST(PullerUtilTest, MergeWithDimension) {
@@ -105,15 +107,16 @@ TEST(PullerUtilTest, MergeWithDimension) {
 
     const vector<FieldValue>* actualFieldValues = &data[0]->getValues();
     ASSERT_EQ(3, actualFieldValues->size());
-    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.int_value);
-    EXPECT_EQ(hostNonAdditiveData, actualFieldValues->at(1).mValue.int_value);
-    EXPECT_EQ(hostAdditiveData, actualFieldValues->at(2).mValue.int_value);
+    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.get<int32_t>());
+    EXPECT_EQ(hostNonAdditiveData, actualFieldValues->at(1).mValue.get<int32_t>());
+    EXPECT_EQ(hostAdditiveData, actualFieldValues->at(2).mValue.get<int32_t>());
 
     actualFieldValues = &data[1]->getValues();
     ASSERT_EQ(3, actualFieldValues->size());
-    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.int_value);
-    EXPECT_EQ(isolatedNonAdditiveData, actualFieldValues->at(1).mValue.int_value);
-    EXPECT_EQ(hostAdditiveData + isolatedAdditiveData, actualFieldValues->at(2).mValue.int_value);
+    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.get<int32_t>());
+    EXPECT_EQ(isolatedNonAdditiveData, actualFieldValues->at(1).mValue.get<int32_t>());
+    EXPECT_EQ(hostAdditiveData + isolatedAdditiveData,
+              actualFieldValues->at(2).mValue.get<int32_t>());
 }
 
 TEST(PullerUtilTest, NoMergeHostUidOnly) {
@@ -134,15 +137,15 @@ TEST(PullerUtilTest, NoMergeHostUidOnly) {
 
     const vector<FieldValue>* actualFieldValues = &data[0]->getValues();
     ASSERT_EQ(3, actualFieldValues->size());
-    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.int_value);
-    EXPECT_EQ(hostNonAdditiveData, actualFieldValues->at(1).mValue.int_value);
-    EXPECT_EQ(hostAdditiveData, actualFieldValues->at(2).mValue.int_value);
+    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.get<int32_t>());
+    EXPECT_EQ(hostNonAdditiveData, actualFieldValues->at(1).mValue.get<int32_t>());
+    EXPECT_EQ(hostAdditiveData, actualFieldValues->at(2).mValue.get<int32_t>());
 
     actualFieldValues = &data[1]->getValues();
     ASSERT_EQ(3, actualFieldValues->size());
-    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.int_value);
-    EXPECT_EQ(isolatedNonAdditiveData, actualFieldValues->at(1).mValue.int_value);
-    EXPECT_EQ(isolatedAdditiveData, actualFieldValues->at(2).mValue.int_value);
+    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.get<int32_t>());
+    EXPECT_EQ(isolatedNonAdditiveData, actualFieldValues->at(1).mValue.get<int32_t>());
+    EXPECT_EQ(isolatedAdditiveData, actualFieldValues->at(2).mValue.get<int32_t>());
 }
 
 TEST(PullerUtilTest, IsolatedUidOnly) {
@@ -164,16 +167,16 @@ TEST(PullerUtilTest, IsolatedUidOnly) {
     // 20->32->31
     const vector<FieldValue>* actualFieldValues = &data[0]->getValues();
     ASSERT_EQ(3, actualFieldValues->size());
-    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.int_value);
-    EXPECT_EQ(hostNonAdditiveData, actualFieldValues->at(1).mValue.int_value);
-    EXPECT_EQ(hostAdditiveData, actualFieldValues->at(2).mValue.int_value);
+    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.get<int32_t>());
+    EXPECT_EQ(hostNonAdditiveData, actualFieldValues->at(1).mValue.get<int32_t>());
+    EXPECT_EQ(hostAdditiveData, actualFieldValues->at(2).mValue.get<int32_t>());
 
     // 20->22->21
     actualFieldValues = &data[1]->getValues();
     ASSERT_EQ(3, actualFieldValues->size());
-    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.int_value);
-    EXPECT_EQ(isolatedNonAdditiveData, actualFieldValues->at(1).mValue.int_value);
-    EXPECT_EQ(isolatedAdditiveData, actualFieldValues->at(2).mValue.int_value);
+    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.get<int32_t>());
+    EXPECT_EQ(isolatedNonAdditiveData, actualFieldValues->at(1).mValue.get<int32_t>());
+    EXPECT_EQ(isolatedAdditiveData, actualFieldValues->at(2).mValue.get<int32_t>());
 }
 
 TEST(PullerUtilTest, MultipleIsolatedUidToOneHostUid) {
@@ -198,10 +201,10 @@ TEST(PullerUtilTest, MultipleIsolatedUidToOneHostUid) {
 
     const vector<FieldValue>* actualFieldValues = &data[0]->getValues();
     ASSERT_EQ(3, actualFieldValues->size());
-    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.int_value);
-    EXPECT_EQ(isolatedNonAdditiveData, actualFieldValues->at(1).mValue.int_value);
+    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.get<int32_t>());
+    EXPECT_EQ(isolatedNonAdditiveData, actualFieldValues->at(1).mValue.get<int32_t>());
     EXPECT_EQ(isolatedAdditiveData + hostAdditiveData + hostAdditiveData,
-              actualFieldValues->at(2).mValue.int_value);
+              actualFieldValues->at(2).mValue.get<int32_t>());
 }
 
 TEST(PullerUtilTest, TwoIsolatedUidsOneAtom) {
@@ -223,11 +226,11 @@ TEST(PullerUtilTest, TwoIsolatedUidsOneAtom) {
 
     const vector<FieldValue>* actualFieldValues = &data[0]->getValues();
     ASSERT_EQ(4, actualFieldValues->size());
-    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.int_value);
-    EXPECT_EQ(isolatedNonAdditiveData, actualFieldValues->at(1).mValue.int_value);
+    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.get<int32_t>());
+    EXPECT_EQ(isolatedNonAdditiveData, actualFieldValues->at(1).mValue.get<int32_t>());
     EXPECT_EQ(isolatedAdditiveData + hostAdditiveData + hostAdditiveData,
-              actualFieldValues->at(2).mValue.int_value);
-    EXPECT_EQ(hostUid2, actualFieldValues->at(3).mValue.int_value);
+              actualFieldValues->at(2).mValue.get<int32_t>());
+    EXPECT_EQ(hostUid2, actualFieldValues->at(3).mValue.get<int32_t>());
 }
 
 TEST(PullerUtilTest, NoNeedToMerge) {
@@ -249,13 +252,13 @@ TEST(PullerUtilTest, NoNeedToMerge) {
 
     const vector<FieldValue>* actualFieldValues = &data[0]->getValues();
     ASSERT_EQ(2, actualFieldValues->size());
-    EXPECT_EQ(isolatedNonAdditiveData, actualFieldValues->at(0).mValue.int_value);
-    EXPECT_EQ(isolatedAdditiveData, actualFieldValues->at(1).mValue.int_value);
+    EXPECT_EQ(isolatedNonAdditiveData, actualFieldValues->at(0).mValue.get<int32_t>());
+    EXPECT_EQ(isolatedAdditiveData, actualFieldValues->at(1).mValue.get<int32_t>());
 
     actualFieldValues = &data[1]->getValues();
     ASSERT_EQ(2, actualFieldValues->size());
-    EXPECT_EQ(hostNonAdditiveData, actualFieldValues->at(0).mValue.int_value);
-    EXPECT_EQ(hostAdditiveData, actualFieldValues->at(1).mValue.int_value);
+    EXPECT_EQ(hostNonAdditiveData, actualFieldValues->at(0).mValue.get<int32_t>());
+    EXPECT_EQ(hostAdditiveData, actualFieldValues->at(1).mValue.get<int32_t>());
 }
 
 TEST(PullerUtilTest, MergeNoDimensionAttributionChain) {
@@ -275,12 +278,13 @@ TEST(PullerUtilTest, MergeNoDimensionAttributionChain) {
     ASSERT_EQ(1, (int)data.size());
     const vector<FieldValue>* actualFieldValues = &data[0]->getValues();
     ASSERT_EQ(6, actualFieldValues->size());
-    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.int_value);
-    EXPECT_EQ("tag1", actualFieldValues->at(1).mValue.str_value);
-    EXPECT_EQ(400, actualFieldValues->at(2).mValue.int_value);
-    EXPECT_EQ("tag2", actualFieldValues->at(3).mValue.str_value);
-    EXPECT_EQ(hostNonAdditiveData, actualFieldValues->at(4).mValue.int_value);
-    EXPECT_EQ(isolatedAdditiveData + hostAdditiveData, actualFieldValues->at(5).mValue.int_value);
+    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.get<int32_t>());
+    EXPECT_EQ("tag1", actualFieldValues->at(1).mValue.get<string>());
+    EXPECT_EQ(400, actualFieldValues->at(2).mValue.get<int32_t>());
+    EXPECT_EQ("tag2", actualFieldValues->at(3).mValue.get<string>());
+    EXPECT_EQ(hostNonAdditiveData, actualFieldValues->at(4).mValue.get<int32_t>());
+    EXPECT_EQ(isolatedAdditiveData + hostAdditiveData,
+              actualFieldValues->at(5).mValue.get<int32_t>());
 }
 
 TEST(PullerUtilTest, MergeWithDimensionAttributionChain) {
@@ -306,21 +310,22 @@ TEST(PullerUtilTest, MergeWithDimensionAttributionChain) {
 
     const vector<FieldValue>* actualFieldValues = &data[0]->getValues();
     ASSERT_EQ(6, actualFieldValues->size());
-    EXPECT_EQ(200, actualFieldValues->at(0).mValue.int_value);
-    EXPECT_EQ("tag1", actualFieldValues->at(1).mValue.str_value);
-    EXPECT_EQ(hostUid, actualFieldValues->at(2).mValue.int_value);
-    EXPECT_EQ("tag2", actualFieldValues->at(3).mValue.str_value);
-    EXPECT_EQ(hostNonAdditiveData, actualFieldValues->at(4).mValue.int_value);
-    EXPECT_EQ(hostAdditiveData, actualFieldValues->at(5).mValue.int_value);
+    EXPECT_EQ(200, actualFieldValues->at(0).mValue.get<int32_t>());
+    EXPECT_EQ("tag1", actualFieldValues->at(1).mValue.get<string>());
+    EXPECT_EQ(hostUid, actualFieldValues->at(2).mValue.get<int32_t>());
+    EXPECT_EQ("tag2", actualFieldValues->at(3).mValue.get<string>());
+    EXPECT_EQ(hostNonAdditiveData, actualFieldValues->at(4).mValue.get<int32_t>());
+    EXPECT_EQ(hostAdditiveData, actualFieldValues->at(5).mValue.get<int32_t>());
 
     actualFieldValues = &data[1]->getValues();
     ASSERT_EQ(6, actualFieldValues->size());
-    EXPECT_EQ(200, actualFieldValues->at(0).mValue.int_value);
-    EXPECT_EQ("tag1", actualFieldValues->at(1).mValue.str_value);
-    EXPECT_EQ(hostUid, actualFieldValues->at(2).mValue.int_value);
-    EXPECT_EQ("tag2", actualFieldValues->at(3).mValue.str_value);
-    EXPECT_EQ(isolatedNonAdditiveData, actualFieldValues->at(4).mValue.int_value);
-    EXPECT_EQ(hostAdditiveData + isolatedAdditiveData, actualFieldValues->at(5).mValue.int_value);
+    EXPECT_EQ(200, actualFieldValues->at(0).mValue.get<int32_t>());
+    EXPECT_EQ("tag1", actualFieldValues->at(1).mValue.get<string>());
+    EXPECT_EQ(hostUid, actualFieldValues->at(2).mValue.get<int32_t>());
+    EXPECT_EQ("tag2", actualFieldValues->at(3).mValue.get<string>());
+    EXPECT_EQ(isolatedNonAdditiveData, actualFieldValues->at(4).mValue.get<int32_t>());
+    EXPECT_EQ(hostAdditiveData + isolatedAdditiveData,
+              actualFieldValues->at(5).mValue.get<int32_t>());
 }
 
 TEST(PullerUtilTest, NoMergeHostUidOnlyAttributionChain) {
@@ -342,21 +347,21 @@ TEST(PullerUtilTest, NoMergeHostUidOnlyAttributionChain) {
 
     const vector<FieldValue>* actualFieldValues = &data[0]->getValues();
     ASSERT_EQ(6, actualFieldValues->size());
-    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.int_value);
-    EXPECT_EQ("tag1", actualFieldValues->at(1).mValue.str_value);
-    EXPECT_EQ(400, actualFieldValues->at(2).mValue.int_value);
-    EXPECT_EQ("tag2", actualFieldValues->at(3).mValue.str_value);
-    EXPECT_EQ(hostNonAdditiveData, actualFieldValues->at(4).mValue.int_value);
-    EXPECT_EQ(hostAdditiveData, actualFieldValues->at(5).mValue.int_value);
+    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.get<int32_t>());
+    EXPECT_EQ("tag1", actualFieldValues->at(1).mValue.get<string>());
+    EXPECT_EQ(400, actualFieldValues->at(2).mValue.get<int32_t>());
+    EXPECT_EQ("tag2", actualFieldValues->at(3).mValue.get<string>());
+    EXPECT_EQ(hostNonAdditiveData, actualFieldValues->at(4).mValue.get<int32_t>());
+    EXPECT_EQ(hostAdditiveData, actualFieldValues->at(5).mValue.get<int32_t>());
 
     actualFieldValues = &data[1]->getValues();
     ASSERT_EQ(6, actualFieldValues->size());
-    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.int_value);
-    EXPECT_EQ("tag1", actualFieldValues->at(1).mValue.str_value);
-    EXPECT_EQ(400, actualFieldValues->at(2).mValue.int_value);
-    EXPECT_EQ("tag2", actualFieldValues->at(3).mValue.str_value);
-    EXPECT_EQ(isolatedNonAdditiveData, actualFieldValues->at(4).mValue.int_value);
-    EXPECT_EQ(isolatedAdditiveData, actualFieldValues->at(5).mValue.int_value);
+    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.get<int32_t>());
+    EXPECT_EQ("tag1", actualFieldValues->at(1).mValue.get<string>());
+    EXPECT_EQ(400, actualFieldValues->at(2).mValue.get<int32_t>());
+    EXPECT_EQ("tag2", actualFieldValues->at(3).mValue.get<string>());
+    EXPECT_EQ(isolatedNonAdditiveData, actualFieldValues->at(4).mValue.get<int32_t>());
+    EXPECT_EQ(isolatedAdditiveData, actualFieldValues->at(5).mValue.get<int32_t>());
 }
 
 TEST(PullerUtilTest, IsolatedUidOnlyAttributionChain) {
@@ -379,22 +384,22 @@ TEST(PullerUtilTest, IsolatedUidOnlyAttributionChain) {
     // 20->tag1->400->tag2->32->31
     const vector<FieldValue>* actualFieldValues = &data[0]->getValues();
     ASSERT_EQ(6, actualFieldValues->size());
-    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.int_value);
-    EXPECT_EQ("tag1", actualFieldValues->at(1).mValue.str_value);
-    EXPECT_EQ(400, actualFieldValues->at(2).mValue.int_value);
-    EXPECT_EQ("tag2", actualFieldValues->at(3).mValue.str_value);
-    EXPECT_EQ(hostNonAdditiveData, actualFieldValues->at(4).mValue.int_value);
-    EXPECT_EQ(hostAdditiveData, actualFieldValues->at(5).mValue.int_value);
+    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.get<int32_t>());
+    EXPECT_EQ("tag1", actualFieldValues->at(1).mValue.get<string>());
+    EXPECT_EQ(400, actualFieldValues->at(2).mValue.get<int32_t>());
+    EXPECT_EQ("tag2", actualFieldValues->at(3).mValue.get<string>());
+    EXPECT_EQ(hostNonAdditiveData, actualFieldValues->at(4).mValue.get<int32_t>());
+    EXPECT_EQ(hostAdditiveData, actualFieldValues->at(5).mValue.get<int32_t>());
 
     // 20->tag1->400->tag2->22->21
     actualFieldValues = &data[1]->getValues();
     ASSERT_EQ(6, actualFieldValues->size());
-    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.int_value);
-    EXPECT_EQ("tag1", actualFieldValues->at(1).mValue.str_value);
-    EXPECT_EQ(400, actualFieldValues->at(2).mValue.int_value);
-    EXPECT_EQ("tag2", actualFieldValues->at(3).mValue.str_value);
-    EXPECT_EQ(isolatedNonAdditiveData, actualFieldValues->at(4).mValue.int_value);
-    EXPECT_EQ(isolatedAdditiveData, actualFieldValues->at(5).mValue.int_value);
+    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.get<int32_t>());
+    EXPECT_EQ("tag1", actualFieldValues->at(1).mValue.get<string>());
+    EXPECT_EQ(400, actualFieldValues->at(2).mValue.get<int32_t>());
+    EXPECT_EQ("tag2", actualFieldValues->at(3).mValue.get<string>());
+    EXPECT_EQ(isolatedNonAdditiveData, actualFieldValues->at(4).mValue.get<int32_t>());
+    EXPECT_EQ(isolatedAdditiveData, actualFieldValues->at(5).mValue.get<int32_t>());
 }
 
 TEST(PullerUtilTest, MultipleIsolatedUidToOneHostUidAttributionChain) {
@@ -420,13 +425,13 @@ TEST(PullerUtilTest, MultipleIsolatedUidToOneHostUidAttributionChain) {
 
     const vector<FieldValue>* actualFieldValues = &data[0]->getValues();
     ASSERT_EQ(6, actualFieldValues->size());
-    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.int_value);
-    EXPECT_EQ("tag1", actualFieldValues->at(1).mValue.str_value);
-    EXPECT_EQ(400, actualFieldValues->at(2).mValue.int_value);
-    EXPECT_EQ("tag2", actualFieldValues->at(3).mValue.str_value);
-    EXPECT_EQ(isolatedNonAdditiveData, actualFieldValues->at(4).mValue.int_value);
+    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.get<int32_t>());
+    EXPECT_EQ("tag1", actualFieldValues->at(1).mValue.get<string>());
+    EXPECT_EQ(400, actualFieldValues->at(2).mValue.get<int32_t>());
+    EXPECT_EQ("tag2", actualFieldValues->at(3).mValue.get<string>());
+    EXPECT_EQ(isolatedNonAdditiveData, actualFieldValues->at(4).mValue.get<int32_t>());
     EXPECT_EQ(isolatedAdditiveData + hostAdditiveData + hostAdditiveData,
-              actualFieldValues->at(5).mValue.int_value);
+              actualFieldValues->at(5).mValue.get<int32_t>());
 }
 
 // Test that repeated fields are treated as non-additive fields even when marked as additive.
@@ -455,18 +460,18 @@ TEST_GUARDED(PullerUtilTest, RepeatedAdditiveField, __ANDROID_API_T__) {
     // are equal.
     const vector<FieldValue>* actualFieldValues = &data[0]->getValues();
     ASSERT_EQ(4, actualFieldValues->size());
-    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.int_value);
-    EXPECT_EQ(hostNonAdditiveData, actualFieldValues->at(1).mValue.int_value);
-    EXPECT_EQ(3, actualFieldValues->at(2).mValue.int_value);
-    EXPECT_EQ(6, actualFieldValues->at(3).mValue.int_value);
+    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.get<int32_t>());
+    EXPECT_EQ(hostNonAdditiveData, actualFieldValues->at(1).mValue.get<int32_t>());
+    EXPECT_EQ(3, actualFieldValues->at(2).mValue.get<int32_t>());
+    EXPECT_EQ(6, actualFieldValues->at(3).mValue.get<int32_t>());
 
     // Event 2 isn't merged - repeated additive field is not equal.
     actualFieldValues = &data[1]->getValues();
     ASSERT_EQ(4, actualFieldValues->size());
-    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.int_value);
-    EXPECT_EQ(hostNonAdditiveData, actualFieldValues->at(1).mValue.int_value);
-    EXPECT_EQ(6, actualFieldValues->at(2).mValue.int_value);
-    EXPECT_EQ(9, actualFieldValues->at(3).mValue.int_value);
+    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.get<int32_t>());
+    EXPECT_EQ(hostNonAdditiveData, actualFieldValues->at(1).mValue.get<int32_t>());
+    EXPECT_EQ(6, actualFieldValues->at(2).mValue.get<int32_t>());
+    EXPECT_EQ(9, actualFieldValues->at(3).mValue.get<int32_t>());
 }
 
 // Test that repeated uid events are sorted and merged correctly.
@@ -508,36 +513,36 @@ TEST_GUARDED(PullerUtilTest, RepeatedUidField, __ANDROID_API_T__) {
     // Events 1 and 3 and 6 are merged.
     const vector<FieldValue>* actualFieldValues = &data[0]->getValues();
     ASSERT_EQ(4, actualFieldValues->size());
-    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.int_value);
-    EXPECT_EQ(hostUid, actualFieldValues->at(1).mValue.int_value);
-    EXPECT_EQ(hostNonAdditiveData, actualFieldValues->at(2).mValue.int_value);
+    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.get<int32_t>());
+    EXPECT_EQ(hostUid, actualFieldValues->at(1).mValue.get<int32_t>());
+    EXPECT_EQ(hostNonAdditiveData, actualFieldValues->at(2).mValue.get<int32_t>());
     EXPECT_EQ(hostAdditiveData + isolatedAdditiveData + hostAdditiveData,
-              actualFieldValues->at(3).mValue.int_value);
+              actualFieldValues->at(3).mValue.get<int32_t>());
 
     // Event 4 isn't merged - different non-additive data.
     actualFieldValues = &data[1]->getValues();
     ASSERT_EQ(4, actualFieldValues->size());
-    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.int_value);
-    EXPECT_EQ(hostUid, actualFieldValues->at(1).mValue.int_value);
-    EXPECT_EQ(isolatedNonAdditiveData, actualFieldValues->at(2).mValue.int_value);
-    EXPECT_EQ(hostAdditiveData, actualFieldValues->at(3).mValue.int_value);
+    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.get<int32_t>());
+    EXPECT_EQ(hostUid, actualFieldValues->at(1).mValue.get<int32_t>());
+    EXPECT_EQ(isolatedNonAdditiveData, actualFieldValues->at(2).mValue.get<int32_t>());
+    EXPECT_EQ(hostAdditiveData, actualFieldValues->at(3).mValue.get<int32_t>());
 
     // Event 2 isn't merged - different uid.
     actualFieldValues = &data[2]->getValues();
     ASSERT_EQ(4, actualFieldValues->size());
-    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.int_value);
-    EXPECT_EQ(hostUid2, actualFieldValues->at(1).mValue.int_value);
-    EXPECT_EQ(hostNonAdditiveData, actualFieldValues->at(2).mValue.int_value);
-    EXPECT_EQ(hostAdditiveData, actualFieldValues->at(3).mValue.int_value);
+    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.get<int32_t>());
+    EXPECT_EQ(hostUid2, actualFieldValues->at(1).mValue.get<int32_t>());
+    EXPECT_EQ(hostNonAdditiveData, actualFieldValues->at(2).mValue.get<int32_t>());
+    EXPECT_EQ(hostAdditiveData, actualFieldValues->at(3).mValue.get<int32_t>());
 
     // Event 5 isn't merged - different repeated uid length.
     actualFieldValues = &data[3]->getValues();
     ASSERT_EQ(5, actualFieldValues->size());
-    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.int_value);
-    EXPECT_EQ(hostUid, actualFieldValues->at(1).mValue.int_value);
-    EXPECT_EQ(hostUid, actualFieldValues->at(2).mValue.int_value);
-    EXPECT_EQ(hostNonAdditiveData, actualFieldValues->at(3).mValue.int_value);
-    EXPECT_EQ(hostAdditiveData, actualFieldValues->at(4).mValue.int_value);
+    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.get<int32_t>());
+    EXPECT_EQ(hostUid, actualFieldValues->at(1).mValue.get<int32_t>());
+    EXPECT_EQ(hostUid, actualFieldValues->at(2).mValue.get<int32_t>());
+    EXPECT_EQ(hostNonAdditiveData, actualFieldValues->at(3).mValue.get<int32_t>());
+    EXPECT_EQ(hostAdditiveData, actualFieldValues->at(4).mValue.get<int32_t>());
 }
 
 // Test that repeated uid events with multiple repeated non-additive fields are sorted and merged
@@ -604,42 +609,43 @@ TEST_GUARDED(PullerUtilTest, MultipleRepeatedFields, __ANDROID_API_T__) {
     // fields, though length is same.
     const vector<FieldValue>* actualFieldValues = &data[0]->getValues();
     ASSERT_EQ(6, actualFieldValues->size());
-    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.int_value);
-    EXPECT_EQ(hostUid, actualFieldValues->at(1).mValue.int_value);
-    EXPECT_EQ(hostUid, actualFieldValues->at(2).mValue.int_value);
-    EXPECT_EQ(hostAdditiveData + isolatedAdditiveData, actualFieldValues->at(3).mValue.int_value);
-    EXPECT_EQ(1, actualFieldValues->at(4).mValue.int_value);
-    EXPECT_EQ(2, actualFieldValues->at(5).mValue.int_value);
+    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.get<int32_t>());
+    EXPECT_EQ(hostUid, actualFieldValues->at(1).mValue.get<int32_t>());
+    EXPECT_EQ(hostUid, actualFieldValues->at(2).mValue.get<int32_t>());
+    EXPECT_EQ(hostAdditiveData + isolatedAdditiveData,
+              actualFieldValues->at(3).mValue.get<int32_t>());
+    EXPECT_EQ(1, actualFieldValues->at(4).mValue.get<int32_t>());
+    EXPECT_EQ(2, actualFieldValues->at(5).mValue.get<int32_t>());
 
     // Events 1 and 4 are merged.
     actualFieldValues = &data[1]->getValues();
     ASSERT_EQ(6, actualFieldValues->size());
-    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.int_value);
-    EXPECT_EQ(hostUid, actualFieldValues->at(1).mValue.int_value);
-    EXPECT_EQ(hostAdditiveData + hostAdditiveData, actualFieldValues->at(2).mValue.int_value);
-    EXPECT_EQ(1, actualFieldValues->at(3).mValue.int_value);
-    EXPECT_EQ(2, actualFieldValues->at(4).mValue.int_value);
-    EXPECT_EQ(3, actualFieldValues->at(5).mValue.int_value);
+    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.get<int32_t>());
+    EXPECT_EQ(hostUid, actualFieldValues->at(1).mValue.get<int32_t>());
+    EXPECT_EQ(hostAdditiveData + hostAdditiveData, actualFieldValues->at(2).mValue.get<int32_t>());
+    EXPECT_EQ(1, actualFieldValues->at(3).mValue.get<int32_t>());
+    EXPECT_EQ(2, actualFieldValues->at(4).mValue.get<int32_t>());
+    EXPECT_EQ(3, actualFieldValues->at(5).mValue.get<int32_t>());
 
     // Event 5 isn't merged - different repeated field.
     actualFieldValues = &data[2]->getValues();
     ASSERT_EQ(6, actualFieldValues->size());
-    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.int_value);
-    EXPECT_EQ(hostUid, actualFieldValues->at(1).mValue.int_value);
-    EXPECT_EQ(hostAdditiveData, actualFieldValues->at(2).mValue.int_value);
-    EXPECT_EQ(1, actualFieldValues->at(3).mValue.int_value);
-    EXPECT_EQ(5, actualFieldValues->at(4).mValue.int_value);
-    EXPECT_EQ(3, actualFieldValues->at(5).mValue.int_value);
+    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.get<int32_t>());
+    EXPECT_EQ(hostUid, actualFieldValues->at(1).mValue.get<int32_t>());
+    EXPECT_EQ(hostAdditiveData, actualFieldValues->at(2).mValue.get<int32_t>());
+    EXPECT_EQ(1, actualFieldValues->at(3).mValue.get<int32_t>());
+    EXPECT_EQ(5, actualFieldValues->at(4).mValue.get<int32_t>());
+    EXPECT_EQ(3, actualFieldValues->at(5).mValue.get<int32_t>());
 
     // Event 2 isn't merged - different uid.
     actualFieldValues = &data[3]->getValues();
     ASSERT_EQ(6, actualFieldValues->size());
-    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.int_value);
-    EXPECT_EQ(hostUid2, actualFieldValues->at(1).mValue.int_value);
-    EXPECT_EQ(hostAdditiveData, actualFieldValues->at(2).mValue.int_value);
-    EXPECT_EQ(1, actualFieldValues->at(3).mValue.int_value);
-    EXPECT_EQ(2, actualFieldValues->at(4).mValue.int_value);
-    EXPECT_EQ(3, actualFieldValues->at(5).mValue.int_value);
+    EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.get<int32_t>());
+    EXPECT_EQ(hostUid2, actualFieldValues->at(1).mValue.get<int32_t>());
+    EXPECT_EQ(hostAdditiveData, actualFieldValues->at(2).mValue.get<int32_t>());
+    EXPECT_EQ(1, actualFieldValues->at(3).mValue.get<int32_t>());
+    EXPECT_EQ(2, actualFieldValues->at(4).mValue.get<int32_t>());
+    EXPECT_EQ(3, actualFieldValues->at(5).mValue.get<int32_t>());
 }
 
 }  // namespace statsd
diff --git a/statsd/tests/guardrail/StatsdStats_test.cpp b/statsd/tests/guardrail/StatsdStats_test.cpp
index b324604b..1fc88c36 100644
--- a/statsd/tests/guardrail/StatsdStats_test.cpp
+++ b/statsd/tests/guardrail/StatsdStats_test.cpp
@@ -1255,6 +1255,35 @@ TEST(StatsdStatsTest, TestErrorStatsReportReset) {
     EXPECT_TRUE(stats.mErrorStats.empty());
 }
 
+TEST(StatsdStatsTest, TestPullerAlarmStatsReport) {
+    StatsdStats stats;
+    stats.notePullerAlarmHasPull();
+    stats.notePullerAlarmHasPull();
+    stats.notePullerAlarmNoPull();
+    stats.notePullerAlarmError();
+
+    auto report = getStatsdStatsReport(stats, /* reset stats */ false);
+
+    EXPECT_TRUE(report.has_puller_alarm_stats());
+    EXPECT_THAT(report.puller_alarm_stats().alarm_with_pulls_count(), 2);
+    EXPECT_THAT(report.puller_alarm_stats().alarm_without_pulls_count(), 1);
+    EXPECT_THAT(report.puller_alarm_stats().alarm_with_puller_errors_count(), 1);
+}
+
+TEST(StatsdStatsTest, TestPullerAlarmStatsReset) {
+    StatsdStats stats;
+    stats.notePullerAlarmHasPull();
+    stats.notePullerAlarmHasPull();
+    stats.notePullerAlarmNoPull();
+    stats.notePullerAlarmError();
+
+    auto report = getStatsdStatsReport(stats, /* reset stats */ true);
+
+    EXPECT_THAT(stats.mPullerAlarmStats.alarm_with_pulls_count, 0);
+    EXPECT_THAT(stats.mPullerAlarmStats.alarm_without_pulls_count, 0);
+    EXPECT_THAT(stats.mPullerAlarmStats.alarm_with_puller_errors_count, 0);
+}
+
 AtomStats buildAtomStats(int32_t atomId, int32_t count) {
     AtomStats msg;
     msg.set_tag(atomId);
diff --git a/statsd/tests/metrics/GaugeMetricProducer_test.cpp b/statsd/tests/metrics/GaugeMetricProducer_test.cpp
index 35e8b54d..6b894441 100644
--- a/statsd/tests/metrics/GaugeMetricProducer_test.cpp
+++ b/statsd/tests/metrics/GaugeMetricProducer_test.cpp
@@ -165,9 +165,9 @@ TEST(GaugeMetricProducerTest, TestPulledEventsNoCondition) {
     ASSERT_EQ(1UL, gaugeProducer.mCurrentSlicedBucket->size());
     auto it = gaugeProducer.mCurrentSlicedBucket->begin()->second.front().mFields.begin();
     EXPECT_EQ(INT, it->mValue.getType());
-    EXPECT_EQ(10, it->mValue.int_value);
+    EXPECT_EQ(10, it->mValue.get<int32_t>());
     it++;
-    EXPECT_EQ(11, it->mValue.int_value);
+    EXPECT_EQ(11, it->mValue.get<int32_t>());
     ASSERT_EQ(1UL, gaugeProducer.mPastBuckets.size());
     EXPECT_EQ(3, gaugeProducer.mPastBuckets.begin()
                          ->second.back()
@@ -175,7 +175,7 @@ TEST(GaugeMetricProducerTest, TestPulledEventsNoCondition) {
                          ->first.getAtomFieldValues()
                          .getValues()
                          .begin()
-                         ->mValue.int_value);
+                         ->mValue.get<int32_t>());
 
     allData.clear();
     allData.push_back(makeLogEvent(tagId, bucket3StartTimeNs + 10, 24, "some value", 25));
@@ -183,10 +183,10 @@ TEST(GaugeMetricProducerTest, TestPulledEventsNoCondition) {
     ASSERT_EQ(1UL, gaugeProducer.mCurrentSlicedBucket->size());
     it = gaugeProducer.mCurrentSlicedBucket->begin()->second.front().mFields.begin();
     EXPECT_EQ(INT, it->mValue.getType());
-    EXPECT_EQ(24, it->mValue.int_value);
+    EXPECT_EQ(24, it->mValue.get<int32_t>());
     it++;
     EXPECT_EQ(INT, it->mValue.getType());
-    EXPECT_EQ(25, it->mValue.int_value);
+    EXPECT_EQ(25, it->mValue.get<int32_t>());
     // One dimension.
     ASSERT_EQ(1UL, gaugeProducer.mPastBuckets.size());
     ASSERT_EQ(2UL, gaugeProducer.mPastBuckets.begin()->second.size());
@@ -197,10 +197,10 @@ TEST(GaugeMetricProducerTest, TestPulledEventsNoCondition) {
                        .getValues()
                        .begin();
     EXPECT_EQ(INT, it2->mValue.getType());
-    EXPECT_EQ(10L, it2->mValue.int_value);
+    EXPECT_EQ(10L, it2->mValue.get<int32_t>());
     it2++;
     EXPECT_EQ(INT, it2->mValue.getType());
-    EXPECT_EQ(11L, it2->mValue.int_value);
+    EXPECT_EQ(11L, it2->mValue.get<int32_t>());
 
     gaugeProducer.flushIfNeededLocked(bucket4StartTimeNs);
     ASSERT_EQ(0UL, gaugeProducer.mCurrentSlicedBucket->size());
@@ -214,10 +214,10 @@ TEST(GaugeMetricProducerTest, TestPulledEventsNoCondition) {
                   .getValues()
                   .begin();
     EXPECT_EQ(INT, it2->mValue.getType());
-    EXPECT_EQ(24L, it2->mValue.int_value);
+    EXPECT_EQ(24L, it2->mValue.get<int32_t>());
     it2++;
     EXPECT_EQ(INT, it2->mValue.getType());
-    EXPECT_EQ(25L, it2->mValue.int_value);
+    EXPECT_EQ(25L, it2->mValue.get<int32_t>());
 }
 
 TEST_P(GaugeMetricProducerTest_PartialBucket, TestPushedEvents) {
@@ -350,7 +350,7 @@ TEST_P(GaugeMetricProducerTest_PartialBucket, TestPulled) {
     EXPECT_EQ(1, gaugeProducer.mCurrentSlicedBucket->begin()
                          ->second.front()
                          .mFields.begin()
-                         ->mValue.int_value);
+                         ->mValue.get<int32_t>());
 
     switch (GetParam()) {
         case APP_UPGRADE:
@@ -371,7 +371,7 @@ TEST_P(GaugeMetricProducerTest_PartialBucket, TestPulled) {
     EXPECT_EQ(2, gaugeProducer.mCurrentSlicedBucket->begin()
                          ->second.front()
                          .mFields.begin()
-                         ->mValue.int_value);
+                         ->mValue.get<int32_t>());
 
     allData.clear();
     allData.push_back(CreateRepeatedValueLogEvent(tagId, bucketStartTimeNs + bucketSizeNs + 1, 3));
@@ -382,7 +382,7 @@ TEST_P(GaugeMetricProducerTest_PartialBucket, TestPulled) {
     EXPECT_EQ(3, gaugeProducer.mCurrentSlicedBucket->begin()
                          ->second.front()
                          .mFields.begin()
-                         ->mValue.int_value);
+                         ->mValue.get<int32_t>());
 }
 
 TEST(GaugeMetricProducerTest, TestPulledWithAppUpgradeDisabled) {
@@ -421,7 +421,7 @@ TEST(GaugeMetricProducerTest, TestPulledWithAppUpgradeDisabled) {
     EXPECT_EQ(1, gaugeProducer.mCurrentSlicedBucket->begin()
                          ->second.front()
                          .mFields.begin()
-                         ->mValue.int_value);
+                         ->mValue.get<int32_t>());
 
     gaugeProducer.notifyAppUpgrade(partialBucketSplitTimeNs);
     ASSERT_EQ(0UL, gaugeProducer.mPastBuckets[DEFAULT_METRIC_DIMENSION_KEY].size());
@@ -431,7 +431,7 @@ TEST(GaugeMetricProducerTest, TestPulledWithAppUpgradeDisabled) {
     EXPECT_EQ(1, gaugeProducer.mCurrentSlicedBucket->begin()
                          ->second.front()
                          .mFields.begin()
-                         ->mValue.int_value);
+                         ->mValue.get<int32_t>());
 }
 
 TEST(GaugeMetricProducerTest, TestPulledEventsWithCondition) {
@@ -475,7 +475,7 @@ TEST(GaugeMetricProducerTest, TestPulledEventsWithCondition) {
     EXPECT_EQ(100, gaugeProducer.mCurrentSlicedBucket->begin()
                            ->second.front()
                            .mFields.begin()
-                           ->mValue.int_value);
+                           ->mValue.get<int32_t>());
     ASSERT_EQ(0UL, gaugeProducer.mPastBuckets.size());
 
     vector<shared_ptr<LogEvent>> allData;
@@ -487,7 +487,7 @@ TEST(GaugeMetricProducerTest, TestPulledEventsWithCondition) {
     EXPECT_EQ(110, gaugeProducer.mCurrentSlicedBucket->begin()
                            ->second.front()
                            .mFields.begin()
-                           ->mValue.int_value);
+                           ->mValue.get<int32_t>());
     ASSERT_EQ(1UL, gaugeProducer.mPastBuckets.size());
 
     EXPECT_EQ(100, gaugeProducer.mPastBuckets.begin()
@@ -496,7 +496,7 @@ TEST(GaugeMetricProducerTest, TestPulledEventsWithCondition) {
                            ->first.getAtomFieldValues()
                            .getValues()
                            .begin()
-                           ->mValue.int_value);
+                           ->mValue.get<int32_t>());
 
     gaugeProducer.onConditionChanged(false, bucket2StartTimeNs + 10);
     gaugeProducer.flushIfNeededLocked(bucket3StartTimeNs + 10);
@@ -508,7 +508,7 @@ TEST(GaugeMetricProducerTest, TestPulledEventsWithCondition) {
                             ->first.getAtomFieldValues()
                             .getValues()
                             .begin()
-                            ->mValue.int_value);
+                            ->mValue.get<int32_t>());
 }
 
 TEST(GaugeMetricProducerTest, TestPulledEventsWithSlicedCondition) {
@@ -564,7 +564,7 @@ TEST(GaugeMetricProducerTest, TestPulledEventsWithSlicedCondition) {
     ASSERT_EQ(1UL, gaugeProducer.mCurrentSlicedBucket->size());
     const auto& key = gaugeProducer.mCurrentSlicedBucket->begin()->first;
     ASSERT_EQ(1UL, key.getDimensionKeyInWhat().getValues().size());
-    EXPECT_EQ(1000, key.getDimensionKeyInWhat().getValues()[0].mValue.int_value);
+    EXPECT_EQ(1000, key.getDimensionKeyInWhat().getValues()[0].mValue.get<int32_t>());
 
     ASSERT_EQ(0UL, gaugeProducer.mPastBuckets.size());
 
@@ -625,7 +625,7 @@ TEST(GaugeMetricProducerTest, TestPulledEventsAnomalyDetection) {
     EXPECT_EQ(13L, gaugeProducer.mCurrentSlicedBucket->begin()
                            ->second.front()
                            .mFields.begin()
-                           ->mValue.int_value);
+                           ->mValue.get<int32_t>());
     EXPECT_EQ(anomalyTracker->getRefractoryPeriodEndsSec(DEFAULT_METRIC_DIMENSION_KEY), 0U);
 
     std::shared_ptr<LogEvent> event2 =
@@ -639,7 +639,7 @@ TEST(GaugeMetricProducerTest, TestPulledEventsAnomalyDetection) {
     EXPECT_EQ(15L, gaugeProducer.mCurrentSlicedBucket->begin()
                            ->second.front()
                            .mFields.begin()
-                           ->mValue.int_value);
+                           ->mValue.get<int32_t>());
     EXPECT_EQ(anomalyTracker->getRefractoryPeriodEndsSec(DEFAULT_METRIC_DIMENSION_KEY),
               std::ceil(1.0 * event2->GetElapsedTimestampNs() / NS_PER_SEC) + refPeriodSec);
 
@@ -652,7 +652,7 @@ TEST(GaugeMetricProducerTest, TestPulledEventsAnomalyDetection) {
     EXPECT_EQ(26L, gaugeProducer.mCurrentSlicedBucket->begin()
                            ->second.front()
                            .mFields.begin()
-                           ->mValue.int_value);
+                           ->mValue.get<int32_t>());
     EXPECT_EQ(anomalyTracker->getRefractoryPeriodEndsSec(DEFAULT_METRIC_DIMENSION_KEY),
               std::ceil(1.0 * event2->GetElapsedTimestampNs() / NS_PER_SEC + refPeriodSec));
 
@@ -723,9 +723,11 @@ TEST(GaugeMetricProducerTest, TestPullOnTrigger) {
     ASSERT_EQ(2UL, gaugeProducer.mPastBuckets.begin()->second.back().mAggregatedAtoms.size());
     auto it = gaugeProducer.mPastBuckets.begin()->second.back().mAggregatedAtoms.begin();
     vector<int> atomValues;
-    atomValues.emplace_back(it->first.getAtomFieldValues().getValues().begin()->mValue.int_value);
+    atomValues.emplace_back(
+            it->first.getAtomFieldValues().getValues().begin()->mValue.get<int32_t>());
     it++;
-    atomValues.emplace_back(it->first.getAtomFieldValues().getValues().begin()->mValue.int_value);
+    atomValues.emplace_back(
+            it->first.getAtomFieldValues().getValues().begin()->mValue.get<int32_t>());
     EXPECT_THAT(atomValues, UnorderedElementsAre(4, 5));
 }
 
@@ -781,11 +783,14 @@ TEST(GaugeMetricProducerTest, TestPullNWithoutTrigger) {
     ASSERT_EQ(3UL, gaugeProducer.mPastBuckets.begin()->second.back().mAggregatedAtoms.size());
     auto it = gaugeProducer.mPastBuckets.begin()->second.back().mAggregatedAtoms.begin();
     vector<int> atomValues;
-    atomValues.emplace_back(it->first.getAtomFieldValues().getValues().begin()->mValue.int_value);
+    atomValues.emplace_back(
+            it->first.getAtomFieldValues().getValues().begin()->mValue.get<int32_t>());
     it++;
-    atomValues.emplace_back(it->first.getAtomFieldValues().getValues().begin()->mValue.int_value);
+    atomValues.emplace_back(
+            it->first.getAtomFieldValues().getValues().begin()->mValue.get<int32_t>());
     it++;
-    atomValues.emplace_back(it->first.getAtomFieldValues().getValues().begin()->mValue.int_value);
+    atomValues.emplace_back(
+            it->first.getAtomFieldValues().getValues().begin()->mValue.get<int32_t>());
     EXPECT_THAT(atomValues, UnorderedElementsAre(4, 5, 6));
 }
 
@@ -856,23 +861,25 @@ TEST(GaugeMetricProducerTest, TestRemoveDimensionInOutput) {
     ASSERT_EQ(2UL, gaugeProducer.mPastBuckets.size());
     auto bucketIt = gaugeProducer.mPastBuckets.begin();
     ASSERT_EQ(1UL, bucketIt->second.back().mAggregatedAtoms.size());
-    EXPECT_EQ(3, bucketIt->first.getDimensionKeyInWhat().getValues().begin()->mValue.int_value);
+    EXPECT_EQ(3,
+              bucketIt->first.getDimensionKeyInWhat().getValues().begin()->mValue.get<int32_t>());
     EXPECT_EQ(4, bucketIt->second.back()
                          .mAggregatedAtoms.begin()
                          ->first.getAtomFieldValues()
                          .getValues()
                          .begin()
-                         ->mValue.int_value);
+                         ->mValue.get<int32_t>());
     bucketIt++;
     ASSERT_EQ(2UL, bucketIt->second.back().mAggregatedAtoms.size());
-    EXPECT_EQ(4, bucketIt->first.getDimensionKeyInWhat().getValues().begin()->mValue.int_value);
+    EXPECT_EQ(4,
+              bucketIt->first.getDimensionKeyInWhat().getValues().begin()->mValue.get<int32_t>());
     auto atomIt = bucketIt->second.back().mAggregatedAtoms.begin();
     vector<int> atomValues;
     atomValues.emplace_back(
-            atomIt->first.getAtomFieldValues().getValues().begin()->mValue.int_value);
+            atomIt->first.getAtomFieldValues().getValues().begin()->mValue.get<int32_t>());
     atomIt++;
     atomValues.emplace_back(
-            atomIt->first.getAtomFieldValues().getValues().begin()->mValue.int_value);
+            atomIt->first.getAtomFieldValues().getValues().begin()->mValue.get<int32_t>());
     EXPECT_THAT(atomValues, UnorderedElementsAre(5, 6));
 }
 
diff --git a/statsd/tests/metrics/NumericValueMetricProducer_test.cpp b/statsd/tests/metrics/NumericValueMetricProducer_test.cpp
index 2d48b4b6..b6f57c9f 100644
--- a/statsd/tests/metrics/NumericValueMetricProducer_test.cpp
+++ b/statsd/tests/metrics/NumericValueMetricProducer_test.cpp
@@ -1704,7 +1704,7 @@ TEST(NumericValueMetricProducerTest, TestUseZeroDefaultBase) {
     auto& interval1 = iter->second.intervals[0];
     auto iterBase = valueProducer->mDimInfos.begin();
     auto& base1 = iterBase->second.dimExtras[0];
-    EXPECT_EQ(1, iter->first.getDimensionKeyInWhat().getValues()[0].mValue.int_value);
+    EXPECT_EQ(1, iter->first.getDimensionKeyInWhat().getValues()[0].mValue.get<int32_t>());
     EXPECT_TRUE(base1.is<int64_t>());
     EXPECT_EQ(3, base1.getValue<int64_t>());
     EXPECT_EQ(0, interval1.sampleSize);
@@ -1770,7 +1770,7 @@ TEST(NumericValueMetricProducerTest, TestUseZeroDefaultBaseWithPullFailures) {
     NumericValueMetricProducer::Interval& interval1 = it->second.intervals[0];
     NumericValue& base1 =
             valueProducer->mDimInfos.find(it->first.getDimensionKeyInWhat())->second.dimExtras[0];
-    EXPECT_EQ(1, it->first.getDimensionKeyInWhat().getValues()[0].mValue.int_value);
+    EXPECT_EQ(1, it->first.getDimensionKeyInWhat().getValues()[0].mValue.get<int32_t>());
     EXPECT_TRUE(base1.is<int64_t>());
     EXPECT_EQ(3, base1.getValue<int64_t>());
     EXPECT_EQ(0, interval1.sampleSize);
@@ -1796,7 +1796,7 @@ TEST(NumericValueMetricProducerTest, TestUseZeroDefaultBaseWithPullFailures) {
     }
     NumericValue& base2 = itBase2->second.dimExtras[0];
     EXPECT_TRUE(base2 != base1);
-    EXPECT_EQ(2, itBase2->first.getValues()[0].mValue.int_value);
+    EXPECT_EQ(2, itBase2->first.getValues()[0].mValue.get<int32_t>());
     EXPECT_TRUE(base2.is<int64_t>());
     EXPECT_EQ(4, base2.getValue<int64_t>());
     ASSERT_EQ(2UL, valueProducer->mPastBuckets.size());
@@ -1809,7 +1809,7 @@ TEST(NumericValueMetricProducerTest, TestUseZeroDefaultBaseWithPullFailures) {
 
     ASSERT_EQ(0UL, valueProducer->mCurrentSlicedBucket.size());
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
-    EXPECT_EQ(2, valueProducer->mDimInfos.begin()->first.getValues()[0].mValue.int_value);
+    EXPECT_EQ(2, valueProducer->mDimInfos.begin()->first.getValues()[0].mValue.get<int32_t>());
     NumericValue& base3 = valueProducer->mDimInfos.begin()->second.dimExtras[0];
     EXPECT_TRUE(base3.is<int64_t>());
     EXPECT_EQ(5, base3.getValue<int64_t>());
@@ -1862,7 +1862,7 @@ TEST(NumericValueMetricProducerTest, TestTrimUnusedDimensionKey) {
     auto& interval1 = iter->second.intervals[0];
     auto iterBase = valueProducer->mDimInfos.begin();
     auto& base1 = iterBase->second.dimExtras[0];
-    EXPECT_EQ(1, iter->first.getDimensionKeyInWhat().getValues()[0].mValue.int_value);
+    EXPECT_EQ(1, iter->first.getDimensionKeyInWhat().getValues()[0].mValue.get<int32_t>());
     EXPECT_TRUE(base1.is<int64_t>());
     EXPECT_EQ(3, base1.getValue<int64_t>());
     EXPECT_EQ(0, interval1.sampleSize);
@@ -1890,7 +1890,7 @@ TEST(NumericValueMetricProducerTest, TestTrimUnusedDimensionKey) {
     }
     EXPECT_TRUE(itBase != iterBase);
     auto base2 = itBase->second.dimExtras[0];
-    EXPECT_EQ(2, itBase->first.getValues()[0].mValue.int_value);
+    EXPECT_EQ(2, itBase->first.getValues()[0].mValue.get<int32_t>());
     EXPECT_TRUE(base2.is<int64_t>());
     EXPECT_EQ(4, base2.getValue<int64_t>());
     EXPECT_FALSE(itBase->second.seenNewData);
@@ -1903,7 +1903,7 @@ TEST(NumericValueMetricProducerTest, TestTrimUnusedDimensionKey) {
     ASSERT_EQ(0UL, valueProducer->mCurrentSlicedBucket.size());
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
     base2 = valueProducer->mDimInfos.begin()->second.dimExtras[0];
-    EXPECT_EQ(2, valueProducer->mDimInfos.begin()->first.getValues()[0].mValue.int_value);
+    EXPECT_EQ(2, valueProducer->mDimInfos.begin()->first.getValues()[0].mValue.get<int32_t>());
     EXPECT_TRUE(base2.is<int64_t>());
     EXPECT_EQ(5, base2.getValue<int64_t>());
     EXPECT_FALSE(valueProducer->mDimInfos.begin()->second.seenNewData);
@@ -1930,7 +1930,7 @@ TEST(NumericValueMetricProducerTest, TestTrimUnusedDimensionKey) {
     // Dimension = 2
     auto iterator = valueProducer->mPastBuckets.begin();
     ASSERT_EQ(1, iterator->first.getDimensionKeyInWhat().getValues().size());
-    EXPECT_EQ(2, iterator->first.getDimensionKeyInWhat().getValues()[0].mValue.int_value);
+    EXPECT_EQ(2, iterator->first.getDimensionKeyInWhat().getValues()[0].mValue.get<int32_t>());
     ASSERT_EQ(2, iterator->second.size());
     EXPECT_EQ(bucket4StartTimeNs, iterator->second[0].mBucketStartNs);
     EXPECT_EQ(bucket5StartTimeNs, iterator->second[0].mBucketEndNs);
@@ -1943,7 +1943,7 @@ TEST(NumericValueMetricProducerTest, TestTrimUnusedDimensionKey) {
     iterator++;
     // Dimension = 1
     ASSERT_EQ(1, iterator->first.getDimensionKeyInWhat().getValues().size());
-    EXPECT_EQ(1, iterator->first.getDimensionKeyInWhat().getValues()[0].mValue.int_value);
+    EXPECT_EQ(1, iterator->first.getDimensionKeyInWhat().getValues()[0].mValue.get<int32_t>());
     ASSERT_EQ(2, iterator->second.size());
     EXPECT_EQ(bucketStartTimeNs, iterator->second[0].mBucketStartNs);
     EXPECT_EQ(bucket2StartTimeNs, iterator->second[0].mBucketEndNs);
@@ -2220,6 +2220,7 @@ TEST(NumericValueMetricProducerTest_BucketDrop, TestInvalidBucketWhenGuardRailHi
     metric.mutable_dimensions_in_what()->set_field(tagId);
     metric.mutable_dimensions_in_what()->add_child()->set_field(1);
     metric.set_condition(StringToId("SCREEN_ON"));
+    metric.set_drop_bucket_on_max_dimensions_exceeded(true);
 
     sp<MockStatsPullerManager> pullerManager = new StrictMock<MockStatsPullerManager>();
     EXPECT_CALL(*pullerManager, Pull(tagId, kConfigKey, bucketStartTimeNs + 2, _))
@@ -3989,12 +3990,12 @@ TEST(NumericValueMetricProducerTest, TestSlicedState) {
     EXPECT_TRUE(itBase->second.hasCurrentState);
     ASSERT_EQ(1, itBase->second.currentState.getValues().size());
     EXPECT_EQ(-1 /* StateTracker::kStateUnknown */,
-              itBase->second.currentState.getValues()[0].mValue.int_value);
+              itBase->second.currentState.getValues()[0].mValue.get<int32_t>());
     // Value for dimension, state key {{}, kStateUnknown}
     EXPECT_EQ(0, it->first.getDimensionKeyInWhat().getValues().size());
     ASSERT_EQ(1, it->first.getStateValuesKey().getValues().size());
     EXPECT_EQ(-1 /* StateTracker::kStateUnknown */,
-              it->first.getStateValuesKey().getValues()[0].mValue.int_value);
+              it->first.getStateValuesKey().getValues()[0].mValue.get<int32_t>());
     EXPECT_EQ(0, it->second.intervals[0].sampleSize);
     assertConditionTimer(it->second.conditionTimer, true, 0, bucketStartTimeNs);
 
@@ -4012,12 +4013,12 @@ TEST(NumericValueMetricProducerTest, TestSlicedState) {
     EXPECT_TRUE(itBase->second.hasCurrentState);
     ASSERT_EQ(1, itBase->second.currentState.getValues().size());
     EXPECT_EQ(android::view::DisplayStateEnum::DISPLAY_STATE_ON,
-              itBase->second.currentState.getValues()[0].mValue.int_value);
+              itBase->second.currentState.getValues()[0].mValue.get<int32_t>());
     // Value for dimension, state key {{}, ON}
     EXPECT_EQ(0, it->first.getDimensionKeyInWhat().getValues().size());
     ASSERT_EQ(1, it->first.getStateValuesKey().getValues().size());
     EXPECT_EQ(android::view::DisplayStateEnum::DISPLAY_STATE_ON,
-              it->first.getStateValuesKey().getValues()[0].mValue.int_value);
+              it->first.getStateValuesKey().getValues()[0].mValue.get<int32_t>());
     EXPECT_EQ(0, it->second.intervals.size());
     assertConditionTimer(it->second.conditionTimer, true, 0, bucketStartTimeNs + 5 * NS_PER_SEC);
     // Value for dimension, state key {{}, kStateUnknown}
@@ -4025,7 +4026,7 @@ TEST(NumericValueMetricProducerTest, TestSlicedState) {
     EXPECT_EQ(0, it->first.getDimensionKeyInWhat().getValues().size());
     ASSERT_EQ(1, it->first.getStateValuesKey().getValues().size());
     EXPECT_EQ(-1 /* StateTracker::kStateUnknown */,
-              it->first.getStateValuesKey().getValues()[0].mValue.int_value);
+              it->first.getStateValuesKey().getValues()[0].mValue.get<int32_t>());
     EXPECT_GT(it->second.intervals[0].sampleSize, 0);
     EXPECT_EQ(2, it->second.intervals[0].aggregate.getValue<int64_t>());
     assertConditionTimer(it->second.conditionTimer, false, 5 * NS_PER_SEC,
@@ -4044,12 +4045,12 @@ TEST(NumericValueMetricProducerTest, TestSlicedState) {
     EXPECT_EQ(9, itBase->second.dimExtras[0].getValue<int64_t>());
     EXPECT_TRUE(itBase->second.hasCurrentState);
     EXPECT_EQ(android::view::DisplayStateEnum::DISPLAY_STATE_OFF,
-              itBase->second.currentState.getValues()[0].mValue.int_value);
+              itBase->second.currentState.getValues()[0].mValue.get<int32_t>());
     // Value for dimension, state key {{}, OFF}
     EXPECT_EQ(0, it->first.getDimensionKeyInWhat().getValues().size());
     ASSERT_EQ(1, it->first.getStateValuesKey().getValues().size());
     EXPECT_EQ(android::view::DisplayStateEnum::DISPLAY_STATE_OFF,
-              it->first.getStateValuesKey().getValues()[0].mValue.int_value);
+              it->first.getStateValuesKey().getValues()[0].mValue.get<int32_t>());
     EXPECT_EQ(0, it->second.intervals.size());
     assertConditionTimer(it->second.conditionTimer, true, 0, bucketStartTimeNs + 10 * NS_PER_SEC);
     // Value for dimension, state key {{}, ON}
@@ -4057,7 +4058,7 @@ TEST(NumericValueMetricProducerTest, TestSlicedState) {
     EXPECT_EQ(0, it->first.getDimensionKeyInWhat().getValues().size());
     ASSERT_EQ(1, it->first.getStateValuesKey().getValues().size());
     EXPECT_EQ(android::view::DisplayStateEnum::DISPLAY_STATE_ON,
-              it->first.getStateValuesKey().getValues()[0].mValue.int_value);
+              it->first.getStateValuesKey().getValues()[0].mValue.get<int32_t>());
     EXPECT_GT(it->second.intervals[0].sampleSize, 0);
     EXPECT_EQ(4, it->second.intervals[0].aggregate.getValue<int64_t>());
     assertConditionTimer(it->second.conditionTimer, false, 5 * NS_PER_SEC,
@@ -4067,7 +4068,7 @@ TEST(NumericValueMetricProducerTest, TestSlicedState) {
     EXPECT_EQ(0, it->first.getDimensionKeyInWhat().getValues().size());
     ASSERT_EQ(1, it->first.getStateValuesKey().getValues().size());
     EXPECT_EQ(-1 /* StateTracker::kStateUnknown */,
-              it->first.getStateValuesKey().getValues()[0].mValue.int_value);
+              it->first.getStateValuesKey().getValues()[0].mValue.get<int32_t>());
     EXPECT_GT(it->second.intervals[0].sampleSize, 0);
     EXPECT_EQ(2, it->second.intervals[0].aggregate.getValue<int64_t>());
     assertConditionTimer(it->second.conditionTimer, false, 5 * NS_PER_SEC,
@@ -4087,12 +4088,12 @@ TEST(NumericValueMetricProducerTest, TestSlicedState) {
     EXPECT_TRUE(itBase->second.hasCurrentState);
     ASSERT_EQ(1, itBase->second.currentState.getValues().size());
     EXPECT_EQ(android::view::DisplayStateEnum::DISPLAY_STATE_ON,
-              itBase->second.currentState.getValues()[0].mValue.int_value);
+              itBase->second.currentState.getValues()[0].mValue.get<int32_t>());
     // Value for dimension, state key {{}, OFF}
     EXPECT_EQ(0, it->first.getDimensionKeyInWhat().getValues().size());
     ASSERT_EQ(1, it->first.getStateValuesKey().getValues().size());
     EXPECT_EQ(android::view::DisplayStateEnum::DISPLAY_STATE_OFF,
-              it->first.getStateValuesKey().getValues()[0].mValue.int_value);
+              it->first.getStateValuesKey().getValues()[0].mValue.get<int32_t>());
     EXPECT_GT(it->second.intervals[0].sampleSize, 0);
     EXPECT_EQ(12, it->second.intervals[0].aggregate.getValue<int64_t>());
     assertConditionTimer(it->second.conditionTimer, false, 5 * NS_PER_SEC,
@@ -4102,7 +4103,7 @@ TEST(NumericValueMetricProducerTest, TestSlicedState) {
     EXPECT_EQ(0, it->first.getDimensionKeyInWhat().getValues().size());
     ASSERT_EQ(1, it->first.getStateValuesKey().getValues().size());
     EXPECT_EQ(android::view::DisplayStateEnum::DISPLAY_STATE_ON,
-              it->first.getStateValuesKey().getValues()[0].mValue.int_value);
+              it->first.getStateValuesKey().getValues()[0].mValue.get<int32_t>());
     EXPECT_GT(it->second.intervals[0].sampleSize, 0);
     EXPECT_EQ(4, it->second.intervals[0].aggregate.getValue<int64_t>());
     assertConditionTimer(it->second.conditionTimer, true, 5 * NS_PER_SEC,
@@ -4112,7 +4113,7 @@ TEST(NumericValueMetricProducerTest, TestSlicedState) {
     EXPECT_EQ(0, it->first.getDimensionKeyInWhat().getValues().size());
     ASSERT_EQ(1, it->first.getStateValuesKey().getValues().size());
     EXPECT_EQ(-1 /* StateTracker::kStateUnknown */,
-              it->first.getStateValuesKey().getValues()[0].mValue.int_value);
+              it->first.getStateValuesKey().getValues()[0].mValue.get<int32_t>());
     EXPECT_GT(it->second.intervals[0].sampleSize, 0);
     EXPECT_EQ(2, it->second.intervals[0].aggregate.getValue<int64_t>());
     assertConditionTimer(it->second.conditionTimer, false, 5 * NS_PER_SEC,
@@ -4132,12 +4133,12 @@ TEST(NumericValueMetricProducerTest, TestSlicedState) {
     EXPECT_TRUE(itBase->second.hasCurrentState);
     ASSERT_EQ(1, itBase->second.currentState.getValues().size());
     EXPECT_EQ(android::view::DisplayStateEnum::DISPLAY_STATE_ON,
-              itBase->second.currentState.getValues()[0].mValue.int_value);
+              itBase->second.currentState.getValues()[0].mValue.get<int32_t>());
     // Value for dimension, state key {{}, ON}
     EXPECT_EQ(0, it->first.getDimensionKeyInWhat().getValues().size());
     ASSERT_EQ(1, it->first.getStateValuesKey().getValues().size());
     EXPECT_EQ(android::view::DisplayStateEnum::DISPLAY_STATE_ON,
-              it->first.getStateValuesKey().getValues()[0].mValue.int_value);
+              it->first.getStateValuesKey().getValues()[0].mValue.get<int32_t>());
     EXPECT_EQ(it->second.intervals[0].sampleSize, 0);
     assertConditionTimer(it->second.conditionTimer, true, 0, bucketStartTimeNs + 50 * NS_PER_SEC);
 
@@ -4259,12 +4260,12 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithMap) {
     EXPECT_TRUE(itBase->second.hasCurrentState);
     ASSERT_EQ(1, itBase->second.currentState.getValues().size());
     EXPECT_EQ(-1 /* StateTracker::kStateUnknown */,
-              itBase->second.currentState.getValues()[0].mValue.int_value);
+              itBase->second.currentState.getValues()[0].mValue.get<int32_t>());
     // Value for dimension, state key {{}, {kStateUnknown}}
     EXPECT_EQ(0, it->first.getDimensionKeyInWhat().getValues().size());
     ASSERT_EQ(1, it->first.getStateValuesKey().getValues().size());
     EXPECT_EQ(-1 /* StateTracker::kStateUnknown */,
-              it->first.getStateValuesKey().getValues()[0].mValue.int_value);
+              it->first.getStateValuesKey().getValues()[0].mValue.get<int32_t>());
     EXPECT_EQ(0, it->second.intervals[0].sampleSize);
     assertConditionTimer(it->second.conditionTimer, true, 0, bucketStartTimeNs);
 
@@ -4282,19 +4283,19 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithMap) {
     EXPECT_TRUE(itBase->second.hasCurrentState);
     ASSERT_EQ(1, itBase->second.currentState.getValues().size());
     EXPECT_EQ(screenOnGroup.group_id(),
-              itBase->second.currentState.getValues()[0].mValue.long_value);
+              itBase->second.currentState.getValues()[0].mValue.get<int64_t>());
     // Value for dimension, state key {{}, ON GROUP}
     EXPECT_EQ(0, it->first.getDimensionKeyInWhat().getValues().size());
     ASSERT_EQ(1, it->first.getStateValuesKey().getValues().size());
     EXPECT_EQ(screenOnGroup.group_id(),
-              it->first.getStateValuesKey().getValues()[0].mValue.int_value);
+              it->first.getStateValuesKey().getValues()[0].mValue.get<int64_t>());
     assertConditionTimer(it->second.conditionTimer, true, 0, bucketStartTimeNs + 5 * NS_PER_SEC);
     // Value for dimension, state key {{}, kStateUnknown}
     it++;
     EXPECT_EQ(0, it->first.getDimensionKeyInWhat().getValues().size());
     ASSERT_EQ(1, it->first.getStateValuesKey().getValues().size());
     EXPECT_EQ(-1 /* StateTracker::kStateUnknown */,
-              it->first.getStateValuesKey().getValues()[0].mValue.int_value);
+              it->first.getStateValuesKey().getValues()[0].mValue.get<int32_t>());
     EXPECT_GT(it->second.intervals[0].sampleSize, 0);
     EXPECT_EQ(2, it->second.intervals[0].aggregate.getValue<int64_t>());
     assertConditionTimer(it->second.conditionTimer, false, 5 * NS_PER_SEC,
@@ -4315,19 +4316,19 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithMap) {
     EXPECT_TRUE(itBase->second.hasCurrentState);
     ASSERT_EQ(1, itBase->second.currentState.getValues().size());
     EXPECT_EQ(screenOnGroup.group_id(),
-              itBase->second.currentState.getValues()[0].mValue.int_value);
+              itBase->second.currentState.getValues()[0].mValue.get<int64_t>());
     // Value for dimension, state key {{}, ON GROUP}
     EXPECT_EQ(0, it->first.getDimensionKeyInWhat().getValues().size());
     ASSERT_EQ(1, it->first.getStateValuesKey().getValues().size());
     EXPECT_EQ(screenOnGroup.group_id(),
-              it->first.getStateValuesKey().getValues()[0].mValue.int_value);
+              it->first.getStateValuesKey().getValues()[0].mValue.get<int64_t>());
     assertConditionTimer(it->second.conditionTimer, true, 0, bucketStartTimeNs + 5 * NS_PER_SEC);
     // Value for dimension, state key {{}, kStateUnknown}
     it++;
     EXPECT_EQ(0, it->first.getDimensionKeyInWhat().getValues().size());
     ASSERT_EQ(1, it->first.getStateValuesKey().getValues().size());
     EXPECT_EQ(-1 /* StateTracker::kStateUnknown */,
-              it->first.getStateValuesKey().getValues()[0].mValue.int_value);
+              it->first.getStateValuesKey().getValues()[0].mValue.get<int32_t>());
     EXPECT_GT(it->second.intervals[0].sampleSize, 0);
     EXPECT_EQ(2, it->second.intervals[0].aggregate.getValue<int64_t>());
     assertConditionTimer(it->second.conditionTimer, false, 5 * NS_PER_SEC,
@@ -4348,19 +4349,19 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithMap) {
     EXPECT_TRUE(itBase->second.hasCurrentState);
     ASSERT_EQ(1, itBase->second.currentState.getValues().size());
     EXPECT_EQ(screenOnGroup.group_id(),
-              itBase->second.currentState.getValues()[0].mValue.int_value);
+              itBase->second.currentState.getValues()[0].mValue.get<int64_t>());
     // Value for dimension, state key {{}, ON GROUP}
     EXPECT_EQ(0, it->first.getDimensionKeyInWhat().getValues().size());
     ASSERT_EQ(1, it->first.getStateValuesKey().getValues().size());
     EXPECT_EQ(screenOnGroup.group_id(),
-              it->first.getStateValuesKey().getValues()[0].mValue.int_value);
+              it->first.getStateValuesKey().getValues()[0].mValue.get<int64_t>());
     assertConditionTimer(it->second.conditionTimer, true, 0, bucketStartTimeNs + 5 * NS_PER_SEC);
     // Value for dimension, state key {{}, kStateUnknown}
     it++;
     EXPECT_EQ(0, it->first.getDimensionKeyInWhat().getValues().size());
     ASSERT_EQ(1, it->first.getStateValuesKey().getValues().size());
     EXPECT_EQ(-1 /* StateTracker::kStateUnknown */,
-              it->first.getStateValuesKey().getValues()[0].mValue.int_value);
+              it->first.getStateValuesKey().getValues()[0].mValue.get<int32_t>());
     EXPECT_GT(it->second.intervals[0].sampleSize, 0);
     EXPECT_EQ(2, it->second.intervals[0].aggregate.getValue<int64_t>());
     assertConditionTimer(it->second.conditionTimer, false, 5 * NS_PER_SEC,
@@ -4380,19 +4381,19 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithMap) {
     EXPECT_TRUE(itBase->second.hasCurrentState);
     ASSERT_EQ(1, itBase->second.currentState.getValues().size());
     EXPECT_EQ(screenOffGroup.group_id(),
-              itBase->second.currentState.getValues()[0].mValue.int_value);
+              itBase->second.currentState.getValues()[0].mValue.get<int64_t>());
     // Value for dimension, state key {{}, OFF GROUP}
     EXPECT_EQ(0, it->first.getDimensionKeyInWhat().getValues().size());
     ASSERT_EQ(1, it->first.getStateValuesKey().getValues().size());
     EXPECT_EQ(screenOffGroup.group_id(),
-              it->first.getStateValuesKey().getValues()[0].mValue.long_value);
+              it->first.getStateValuesKey().getValues()[0].mValue.get<int64_t>());
     assertConditionTimer(it->second.conditionTimer, true, 0, bucketStartTimeNs + 15 * NS_PER_SEC);
     // Value for dimension, state key {{}, ON GROUP}
     it++;
     EXPECT_EQ(0, it->first.getDimensionKeyInWhat().getValues().size());
     ASSERT_EQ(1, it->first.getStateValuesKey().getValues().size());
     EXPECT_EQ(screenOnGroup.group_id(),
-              it->first.getStateValuesKey().getValues()[0].mValue.long_value);
+              it->first.getStateValuesKey().getValues()[0].mValue.get<int64_t>());
     EXPECT_GT(it->second.intervals[0].sampleSize, 0);
     EXPECT_EQ(16, it->second.intervals[0].aggregate.getValue<int64_t>());
     assertConditionTimer(it->second.conditionTimer, false, 10 * NS_PER_SEC,
@@ -4402,7 +4403,7 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithMap) {
     EXPECT_EQ(0, it->first.getDimensionKeyInWhat().getValues().size());
     ASSERT_EQ(1, it->first.getStateValuesKey().getValues().size());
     EXPECT_EQ(-1 /* StateTracker::kStateUnknown */,
-              it->first.getStateValuesKey().getValues()[0].mValue.int_value);
+              it->first.getStateValuesKey().getValues()[0].mValue.get<int32_t>());
     EXPECT_GT(it->second.intervals[0].sampleSize, 0);
     EXPECT_EQ(2, it->second.intervals[0].aggregate.getValue<int64_t>());
     assertConditionTimer(it->second.conditionTimer, false, 5 * NS_PER_SEC,
@@ -4422,12 +4423,12 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithMap) {
     EXPECT_TRUE(itBase->second.hasCurrentState);
     ASSERT_EQ(1, itBase->second.currentState.getValues().size());
     EXPECT_EQ(screenOffGroup.group_id(),
-              itBase->second.currentState.getValues()[0].mValue.int_value);
+              itBase->second.currentState.getValues()[0].mValue.get<int64_t>());
     // Value for dimension, state key {{}, OFF GROUP}
     EXPECT_EQ(0, it->first.getDimensionKeyInWhat().getValues().size());
     ASSERT_EQ(1, it->first.getStateValuesKey().getValues().size());
     EXPECT_EQ(screenOffGroup.group_id(),
-              it->first.getStateValuesKey().getValues()[0].mValue.long_value);
+              it->first.getStateValuesKey().getValues()[0].mValue.get<int64_t>());
     assertConditionTimer(it->second.conditionTimer, true, 0, bucketStartTimeNs + 50 * NS_PER_SEC);
 
     EXPECT_TRUE(report.has_value_metrics());
@@ -4624,16 +4625,16 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithPrimaryField_WithDimensi
     ASSERT_EQ(2UL, valueProducer->mDimInfos.size());
     auto it = valueProducer->mCurrentSlicedBucket.begin();  // dimension, state key {2, BACKGROUND}
     EXPECT_EQ(1, it->first.getDimensionKeyInWhat().getValues().size());
-    EXPECT_EQ(2, it->first.getDimensionKeyInWhat().getValues()[0].mValue.int_value);
+    EXPECT_EQ(2, it->first.getDimensionKeyInWhat().getValues()[0].mValue.get<int32_t>());
     ASSERT_EQ(1, it->first.getStateValuesKey().getValues().size());
     EXPECT_EQ(android::app::PROCESS_STATE_IMPORTANT_BACKGROUND,
-              it->first.getStateValuesKey().getValues()[0].mValue.int_value);
+              it->first.getStateValuesKey().getValues()[0].mValue.get<int32_t>());
     it++;  // dimension, state key {1, FOREGROUND}
     EXPECT_EQ(1, it->first.getDimensionKeyInWhat().getValues().size());
-    EXPECT_EQ(1, it->first.getDimensionKeyInWhat().getValues()[0].mValue.int_value);
+    EXPECT_EQ(1, it->first.getDimensionKeyInWhat().getValues()[0].mValue.get<int32_t>());
     ASSERT_EQ(1, it->first.getStateValuesKey().getValues().size());
     EXPECT_EQ(android::app::PROCESS_STATE_IMPORTANT_FOREGROUND,
-              it->first.getStateValuesKey().getValues()[0].mValue.int_value);
+              it->first.getStateValuesKey().getValues()[0].mValue.get<int32_t>());
 
     // Bucket status after uid 1 process state change from Foreground -> Background.
     uidProcessEvent =
@@ -4806,12 +4807,12 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithMissingDataInStateChange
     EXPECT_TRUE(itBase->second.hasCurrentState);
     ASSERT_EQ(1, itBase->second.currentState.getValues().size());
     EXPECT_EQ(-1 /* StateTracker::kStateUnknown */,
-              itBase->second.currentState.getValues()[0].mValue.int_value);
+              itBase->second.currentState.getValues()[0].mValue.get<int32_t>());
     // Value for dimension, state key {{}, kStateUnknown}
     EXPECT_EQ(0, it->first.getDimensionKeyInWhat().getValues().size());
     ASSERT_EQ(1, it->first.getStateValuesKey().getValues().size());
     EXPECT_EQ(-1 /* StateTracker::kStateUnknown */,
-              it->first.getStateValuesKey().getValues()[0].mValue.int_value);
+              it->first.getStateValuesKey().getValues()[0].mValue.get<int32_t>());
     assertConditionTimer(it->second.conditionTimer, true, 0, bucketStartTimeNs);
 
     // Bucket status after battery saver mode ON event.
@@ -4828,12 +4829,12 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithMissingDataInStateChange
     EXPECT_TRUE(itBase->second.hasCurrentState);
     ASSERT_EQ(1, itBase->second.currentState.getValues().size());
     EXPECT_EQ(BatterySaverModeStateChanged::ON,
-              itBase->second.currentState.getValues()[0].mValue.int_value);
+              itBase->second.currentState.getValues()[0].mValue.get<int32_t>());
     // Value for key {{}, ON}
     EXPECT_EQ(0, it->first.getDimensionKeyInWhat().getValues().size());
     ASSERT_EQ(1, it->first.getStateValuesKey().getValues().size());
     EXPECT_EQ(BatterySaverModeStateChanged::ON,
-              it->first.getStateValuesKey().getValues()[0].mValue.int_value);
+              it->first.getStateValuesKey().getValues()[0].mValue.get<int32_t>());
     assertConditionTimer(it->second.conditionTimer, true, 0, bucketStartTimeNs + 10 * NS_PER_SEC);
 
     // Value for key {{}, -1}
@@ -4841,7 +4842,7 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithMissingDataInStateChange
     EXPECT_EQ(0, it->first.getDimensionKeyInWhat().getValues().size());
     ASSERT_EQ(1, it->first.getStateValuesKey().getValues().size());
     EXPECT_EQ(-1 /*StateTracker::kUnknown*/,
-              it->first.getStateValuesKey().getValues()[0].mValue.int_value);
+              it->first.getStateValuesKey().getValues()[0].mValue.get<int32_t>());
     assertConditionTimer(it->second.conditionTimer, false, 10 * NS_PER_SEC,
                          bucketStartTimeNs + 10 * NS_PER_SEC);
 
@@ -4859,7 +4860,7 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithMissingDataInStateChange
     EXPECT_EQ(0, it->first.getDimensionKeyInWhat().getValues().size());
     ASSERT_EQ(1, it->first.getStateValuesKey().getValues().size());
     EXPECT_EQ(BatterySaverModeStateChanged::ON,
-              it->first.getStateValuesKey().getValues()[0].mValue.int_value);
+              it->first.getStateValuesKey().getValues()[0].mValue.get<int32_t>());
     assertConditionTimer(it->second.conditionTimer, false, 20 * NS_PER_SEC,
                          bucketStartTimeNs + 30 * NS_PER_SEC);
 
@@ -4868,7 +4869,7 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithMissingDataInStateChange
     EXPECT_EQ(0, it->first.getDimensionKeyInWhat().getValues().size());
     ASSERT_EQ(1, it->first.getStateValuesKey().getValues().size());
     EXPECT_EQ(-1 /*StateTracker::kUnknown*/,
-              it->first.getStateValuesKey().getValues()[0].mValue.int_value);
+              it->first.getStateValuesKey().getValues()[0].mValue.get<int32_t>());
     assertConditionTimer(it->second.conditionTimer, false, 10 * NS_PER_SEC,
                          bucketStartTimeNs + 10 * NS_PER_SEC);
 
@@ -4884,12 +4885,12 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithMissingDataInStateChange
     itBase = valueProducer->mDimInfos.find(it->first.getDimensionKeyInWhat());
     ASSERT_EQ(1, itBase->second.currentState.getValues().size());
     EXPECT_EQ(BatterySaverModeStateChanged::ON,
-              itBase->second.currentState.getValues()[0].mValue.int_value);
+              itBase->second.currentState.getValues()[0].mValue.get<int32_t>());
     // Value for key {{}, ON}
     EXPECT_EQ(0, it->first.getDimensionKeyInWhat().getValues().size());
     ASSERT_EQ(1, it->first.getStateValuesKey().getValues().size());
     EXPECT_EQ(BatterySaverModeStateChanged::ON,
-              it->first.getStateValuesKey().getValues()[0].mValue.int_value);
+              it->first.getStateValuesKey().getValues()[0].mValue.get<int32_t>());
     assertConditionTimer(it->second.conditionTimer, true, 20 * NS_PER_SEC,
                          bucketStartTimeNs + 40 * NS_PER_SEC);
 
@@ -4898,7 +4899,7 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithMissingDataInStateChange
     EXPECT_EQ(0, it->first.getDimensionKeyInWhat().getValues().size());
     ASSERT_EQ(1, it->first.getStateValuesKey().getValues().size());
     EXPECT_EQ(-1 /*StateTracker::kUnknown*/,
-              it->first.getStateValuesKey().getValues()[0].mValue.int_value);
+              it->first.getStateValuesKey().getValues()[0].mValue.get<int32_t>());
     assertConditionTimer(it->second.conditionTimer, false, 10 * NS_PER_SEC,
                          bucketStartTimeNs + 10 * NS_PER_SEC);
 
@@ -5097,12 +5098,12 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithNoPullOnBucketBoundary)
     EXPECT_TRUE(itBase->second.hasCurrentState);
     ASSERT_EQ(1, itBase->second.currentState.getValues().size());
     EXPECT_EQ(-1 /* StateTracker::kStateUnknown */,
-              itBase->second.currentState.getValues()[0].mValue.int_value);
+              itBase->second.currentState.getValues()[0].mValue.get<int32_t>());
     // Value for dimension, state key {{}, kStateUnknown}
     EXPECT_EQ(0, it->first.getDimensionKeyInWhat().getValues().size());
     ASSERT_EQ(1, it->first.getStateValuesKey().getValues().size());
     EXPECT_EQ(-1 /* StateTracker::kStateUnknown */,
-              it->first.getStateValuesKey().getValues()[0].mValue.int_value);
+              it->first.getStateValuesKey().getValues()[0].mValue.get<int32_t>());
     assertConditionTimer(it->second.conditionTimer, true, 0, bucketStartTimeNs);
 
     // Bucket status after battery saver mode ON event.
@@ -5116,12 +5117,12 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithNoPullOnBucketBoundary)
     itBase = valueProducer->mDimInfos.find(it->first.getDimensionKeyInWhat());
     ASSERT_EQ(1, itBase->second.currentState.getValues().size());
     EXPECT_EQ(BatterySaverModeStateChanged::ON,
-              itBase->second.currentState.getValues()[0].mValue.int_value);
+              itBase->second.currentState.getValues()[0].mValue.get<int32_t>());
     // Value for key {{}, ON}
     EXPECT_EQ(0, it->first.getDimensionKeyInWhat().getValues().size());
     ASSERT_EQ(1, it->first.getStateValuesKey().getValues().size());
     EXPECT_EQ(BatterySaverModeStateChanged::ON,
-              it->first.getStateValuesKey().getValues()[0].mValue.int_value);
+              it->first.getStateValuesKey().getValues()[0].mValue.get<int32_t>());
     assertConditionTimer(it->second.conditionTimer, true, 0, bucketStartTimeNs + 10 * NS_PER_SEC);
 
     // Value for key {{}, -1}
@@ -5129,7 +5130,7 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithNoPullOnBucketBoundary)
     EXPECT_EQ(0, it->first.getDimensionKeyInWhat().getValues().size());
     ASSERT_EQ(1, it->first.getStateValuesKey().getValues().size());
     EXPECT_EQ(-1 /*StateTracker::kUnknown*/,
-              it->first.getStateValuesKey().getValues()[0].mValue.int_value);
+              it->first.getStateValuesKey().getValues()[0].mValue.get<int32_t>());
     assertConditionTimer(it->second.conditionTimer, false, 10 * NS_PER_SEC,
                          bucketStartTimeNs + 10 * NS_PER_SEC);
 
@@ -5144,12 +5145,12 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithNoPullOnBucketBoundary)
     itBase = valueProducer->mDimInfos.find(it->first.getDimensionKeyInWhat());
     ASSERT_EQ(1, itBase->second.currentState.getValues().size());
     EXPECT_EQ(BatterySaverModeStateChanged::OFF,
-              itBase->second.currentState.getValues()[0].mValue.int_value);
+              itBase->second.currentState.getValues()[0].mValue.get<int32_t>());
     // Value for key {{}, OFF}
     EXPECT_EQ(0, it->first.getDimensionKeyInWhat().getValues().size());
     ASSERT_EQ(1, it->first.getStateValuesKey().getValues().size());
     EXPECT_EQ(BatterySaverModeStateChanged::OFF,
-              it->first.getStateValuesKey().getValues()[0].mValue.int_value);
+              it->first.getStateValuesKey().getValues()[0].mValue.get<int32_t>());
     assertConditionTimer(it->second.conditionTimer, true, 0, bucketStartTimeNs + 20 * NS_PER_SEC);
 
     // Value for key {{}, ON}
@@ -5157,7 +5158,7 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithNoPullOnBucketBoundary)
     EXPECT_EQ(0, it->first.getDimensionKeyInWhat().getValues().size());
     ASSERT_EQ(1, it->first.getStateValuesKey().getValues().size());
     EXPECT_EQ(BatterySaverModeStateChanged::ON,
-              it->first.getStateValuesKey().getValues()[0].mValue.int_value);
+              it->first.getStateValuesKey().getValues()[0].mValue.get<int32_t>());
     assertConditionTimer(it->second.conditionTimer, false, 10 * NS_PER_SEC,
                          bucketStartTimeNs + 20 * NS_PER_SEC);
 
@@ -5166,7 +5167,7 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithNoPullOnBucketBoundary)
     EXPECT_EQ(0, it->first.getDimensionKeyInWhat().getValues().size());
     ASSERT_EQ(1, it->first.getStateValuesKey().getValues().size());
     EXPECT_EQ(-1 /*StateTracker::kUnknown*/,
-              it->first.getStateValuesKey().getValues()[0].mValue.int_value);
+              it->first.getStateValuesKey().getValues()[0].mValue.get<int32_t>());
     assertConditionTimer(it->second.conditionTimer, false, 10 * NS_PER_SEC,
                          bucketStartTimeNs + 10 * NS_PER_SEC);
 
@@ -5182,12 +5183,12 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithNoPullOnBucketBoundary)
     itBase = valueProducer->mDimInfos.find(it->first.getDimensionKeyInWhat());
     ASSERT_EQ(1, itBase->second.currentState.getValues().size());
     EXPECT_EQ(BatterySaverModeStateChanged::ON,
-              itBase->second.currentState.getValues()[0].mValue.int_value);
+              itBase->second.currentState.getValues()[0].mValue.get<int32_t>());
     // Value for key {{}, ON}
     EXPECT_EQ(0, it->first.getDimensionKeyInWhat().getValues().size());
     ASSERT_EQ(1, it->first.getStateValuesKey().getValues().size());
     EXPECT_EQ(BatterySaverModeStateChanged::ON,
-              it->first.getStateValuesKey().getValues()[0].mValue.int_value);
+              it->first.getStateValuesKey().getValues()[0].mValue.get<int32_t>());
     assertConditionTimer(it->second.conditionTimer, true, 0, bucket2StartTimeNs + 30 * NS_PER_SEC);
 
     // Start dump report and check output.
@@ -5323,12 +5324,12 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithDataMissingInConditionCh
     EXPECT_TRUE(itBase->second.hasCurrentState);
     ASSERT_EQ(1, itBase->second.currentState.getValues().size());
     EXPECT_EQ(BatterySaverModeStateChanged::ON,
-              itBase->second.currentState.getValues()[0].mValue.int_value);
+              itBase->second.currentState.getValues()[0].mValue.get<int32_t>());
     // Value for key {{}, ON}
     EXPECT_EQ(0, it->first.getDimensionKeyInWhat().getValues().size());
     ASSERT_EQ(1, it->first.getStateValuesKey().getValues().size());
     EXPECT_EQ(BatterySaverModeStateChanged::ON,
-              it->first.getStateValuesKey().getValues()[0].mValue.int_value);
+              it->first.getStateValuesKey().getValues()[0].mValue.get<int32_t>());
     assertConditionTimer(it->second.conditionTimer, true, 0, bucketStartTimeNs + 10 * NS_PER_SEC);
 
     // Value for key {{}, -1}
@@ -5336,7 +5337,7 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithDataMissingInConditionCh
     EXPECT_EQ(0, it->first.getDimensionKeyInWhat().getValues().size());
     ASSERT_EQ(1, it->first.getStateValuesKey().getValues().size());
     EXPECT_EQ(-1 /*StateTracker::kUnknown*/,
-              it->first.getStateValuesKey().getValues()[0].mValue.int_value);
+              it->first.getStateValuesKey().getValues()[0].mValue.get<int32_t>());
     assertConditionTimer(it->second.conditionTimer, false, 0, 0);
 
     // Bucket status after condition change to false.
@@ -5349,12 +5350,12 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithDataMissingInConditionCh
     EXPECT_TRUE(itBase->second.hasCurrentState);
     ASSERT_EQ(1, itBase->second.currentState.getValues().size());
     EXPECT_EQ(BatterySaverModeStateChanged::ON,
-              itBase->second.currentState.getValues()[0].mValue.int_value);
+              itBase->second.currentState.getValues()[0].mValue.get<int32_t>());
     // Value for key {{}, ON}
     EXPECT_EQ(0, it->first.getDimensionKeyInWhat().getValues().size());
     ASSERT_EQ(1, it->first.getStateValuesKey().getValues().size());
     EXPECT_EQ(BatterySaverModeStateChanged::ON,
-              it->first.getStateValuesKey().getValues()[0].mValue.int_value);
+              it->first.getStateValuesKey().getValues()[0].mValue.get<int32_t>());
     assertConditionTimer(it->second.conditionTimer, false, 20 * NS_PER_SEC,
                          bucketStartTimeNs + 30 * NS_PER_SEC);
 
@@ -5363,7 +5364,7 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithDataMissingInConditionCh
     EXPECT_EQ(0, it->first.getDimensionKeyInWhat().getValues().size());
     ASSERT_EQ(1, it->first.getStateValuesKey().getValues().size());
     EXPECT_EQ(-1 /*StateTracker::kUnknown*/,
-              it->first.getStateValuesKey().getValues()[0].mValue.int_value);
+              it->first.getStateValuesKey().getValues()[0].mValue.get<int32_t>());
     assertConditionTimer(it->second.conditionTimer, false, 0, 0);
 
     unique_ptr<LogEvent> batterySaverOffEvent =
@@ -5382,7 +5383,7 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithDataMissingInConditionCh
     EXPECT_EQ(0, it->first.getDimensionKeyInWhat().getValues().size());
     ASSERT_EQ(1, it->first.getStateValuesKey().getValues().size());
     EXPECT_EQ(BatterySaverModeStateChanged::ON,
-              it->first.getStateValuesKey().getValues()[0].mValue.int_value);
+              it->first.getStateValuesKey().getValues()[0].mValue.get<int32_t>());
     assertConditionTimer(it->second.conditionTimer, false, 20 * NS_PER_SEC,
                          bucketStartTimeNs + 30 * NS_PER_SEC);
 
@@ -5391,7 +5392,7 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithDataMissingInConditionCh
     EXPECT_EQ(0, it->first.getDimensionKeyInWhat().getValues().size());
     ASSERT_EQ(1, it->first.getStateValuesKey().getValues().size());
     EXPECT_EQ(-1 /*StateTracker::kUnknown*/,
-              it->first.getStateValuesKey().getValues()[0].mValue.int_value);
+              it->first.getStateValuesKey().getValues()[0].mValue.get<int32_t>());
     assertConditionTimer(it->second.conditionTimer, false, 0, 0);
 
     batterySaverOnEvent =
@@ -5402,7 +5403,7 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithDataMissingInConditionCh
     EXPECT_TRUE(itBase->second.hasCurrentState);
     ASSERT_EQ(1, itBase->second.currentState.getValues().size());
     EXPECT_EQ(BatterySaverModeStateChanged::ON,
-              itBase->second.currentState.getValues()[0].mValue.int_value);
+              itBase->second.currentState.getValues()[0].mValue.get<int32_t>());
     ASSERT_EQ(2UL, valueProducer->mCurrentSlicedBucket.size());
 
     // Start dump report and check output.
@@ -5781,7 +5782,7 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithCondition) {
     EXPECT_TRUE(itBase->second.hasCurrentState);
     ASSERT_EQ(1, itBase->second.currentState.getValues().size());
     EXPECT_EQ(BatterySaverModeStateChanged::ON,
-              itBase->second.currentState.getValues()[0].mValue.int_value);
+              itBase->second.currentState.getValues()[0].mValue.get<int32_t>());
     // Value for key {{}, ON}
     ASSERT_EQ(2UL, valueProducer->mCurrentSlicedBucket.size());
     std::unordered_map<MetricDimensionKey, NumericValueMetricProducer::CurrentBucket>::iterator it =
@@ -5789,14 +5790,14 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithCondition) {
     EXPECT_EQ(0, it->first.getDimensionKeyInWhat().getValues().size());
     ASSERT_EQ(1, it->first.getStateValuesKey().getValues().size());
     EXPECT_EQ(BatterySaverModeStateChanged::ON,
-              it->first.getStateValuesKey().getValues()[0].mValue.int_value);
+              it->first.getStateValuesKey().getValues()[0].mValue.get<int32_t>());
     assertConditionTimer(it->second.conditionTimer, true, 0, bucketStartTimeNs + 20 * NS_PER_SEC);
     // Value for key {{}, -1}
     it++;
     EXPECT_EQ(0, it->first.getDimensionKeyInWhat().getValues().size());
     ASSERT_EQ(1, it->first.getStateValuesKey().getValues().size());
     EXPECT_EQ(-1 /*StateTracker::kUnknown*/,
-              it->first.getStateValuesKey().getValues()[0].mValue.int_value);
+              it->first.getStateValuesKey().getValues()[0].mValue.get<int32_t>());
     EXPECT_EQ(0, it->second.intervals[0].sampleSize);
     assertConditionTimer(it->second.conditionTimer, false, 0, 0);
 
@@ -5812,21 +5813,21 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithCondition) {
     EXPECT_TRUE(itBase->second.hasCurrentState);
     ASSERT_EQ(1, itBase->second.currentState.getValues().size());
     EXPECT_EQ(BatterySaverModeStateChanged::OFF,
-              itBase->second.currentState.getValues()[0].mValue.int_value);
+              itBase->second.currentState.getValues()[0].mValue.get<int32_t>());
     // Value for key {{}, OFF}
     ASSERT_EQ(3UL, valueProducer->mCurrentSlicedBucket.size());
     it = valueProducer->mCurrentSlicedBucket.begin();
     EXPECT_EQ(0, it->first.getDimensionKeyInWhat().getValues().size());
     ASSERT_EQ(1, it->first.getStateValuesKey().getValues().size());
     EXPECT_EQ(BatterySaverModeStateChanged::OFF,
-              it->first.getStateValuesKey().getValues()[0].mValue.int_value);
+              it->first.getStateValuesKey().getValues()[0].mValue.get<int32_t>());
     assertConditionTimer(it->second.conditionTimer, true, 0, bucketStartTimeNs + 30 * NS_PER_SEC);
     // Value for key {{}, ON}
     it++;
     EXPECT_EQ(0, it->first.getDimensionKeyInWhat().getValues().size());
     ASSERT_EQ(1, it->first.getStateValuesKey().getValues().size());
     EXPECT_EQ(BatterySaverModeStateChanged::ON,
-              it->first.getStateValuesKey().getValues()[0].mValue.int_value);
+              it->first.getStateValuesKey().getValues()[0].mValue.get<int32_t>());
     EXPECT_GT(it->second.intervals[0].sampleSize, 0);
     EXPECT_EQ(2, it->second.intervals[0].aggregate.getValue<int64_t>());
     assertConditionTimer(it->second.conditionTimer, false, 10 * NS_PER_SEC,
@@ -5852,7 +5853,7 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithCondition) {
     EXPECT_TRUE(itBase->second.hasCurrentState);
     ASSERT_EQ(1, itBase->second.currentState.getValues().size());
     EXPECT_EQ(BatterySaverModeStateChanged::OFF,
-              itBase->second.currentState.getValues()[0].mValue.int_value);
+              itBase->second.currentState.getValues()[0].mValue.get<int32_t>());
     // Value for key {{}, OFF}
     it = valueProducer->mCurrentSlicedBucket.begin();
     assertConditionTimer(it->second.conditionTimer, true, 0, bucket2StartTimeNs);
@@ -5866,14 +5867,14 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithCondition) {
     EXPECT_TRUE(itBase->second.hasCurrentState);
     ASSERT_EQ(1, itBase->second.currentState.getValues().size());
     EXPECT_EQ(BatterySaverModeStateChanged::OFF,
-              itBase->second.currentState.getValues()[0].mValue.int_value);
+              itBase->second.currentState.getValues()[0].mValue.get<int32_t>());
     // Value for key {{}, OFF}
     ASSERT_EQ(1UL, valueProducer->mCurrentSlicedBucket.size());
     it = valueProducer->mCurrentSlicedBucket.begin();
     EXPECT_EQ(0, it->first.getDimensionKeyInWhat().getValues().size());
     ASSERT_EQ(1, it->first.getStateValuesKey().getValues().size());
     EXPECT_EQ(BatterySaverModeStateChanged::OFF,
-              it->first.getStateValuesKey().getValues()[0].mValue.int_value);
+              it->first.getStateValuesKey().getValues()[0].mValue.get<int32_t>());
     EXPECT_GT(it->second.intervals[0].sampleSize, 0);
     EXPECT_EQ(4, it->second.intervals[0].aggregate.getValue<int64_t>());
     assertConditionTimer(it->second.conditionTimer, false, 10 * NS_PER_SEC,
@@ -7140,7 +7141,7 @@ TEST(NumericValueMetricProducerTest_ConditionCorrection, TestLateStateChangeSlic
     // Value for dimension, state key {{}, OFF}
     auto it = valueProducer->mCurrentSlicedBucket.begin();
     EXPECT_EQ(android::view::DisplayStateEnum::DISPLAY_STATE_OFF,
-              it->first.getStateValuesKey().getValues()[0].mValue.int_value);
+              it->first.getStateValuesKey().getValues()[0].mValue.get<int32_t>());
     assertConditionTimer(it->second.conditionTimer, true, 0, bucketStartTimeNs + 5 * NS_PER_SEC);
 
     // Bucket status after screen state change OFF->ON, forces bucket flush and new bucket start
@@ -7156,7 +7157,7 @@ TEST(NumericValueMetricProducerTest_ConditionCorrection, TestLateStateChangeSlic
     // Value for dimension, state key {{}, ON}
     it = valueProducer->mCurrentSlicedBucket.begin();
     EXPECT_EQ(android::view::DisplayStateEnum::DISPLAY_STATE_ON,
-              it->first.getStateValuesKey().getValues()[0].mValue.int_value);
+              it->first.getStateValuesKey().getValues()[0].mValue.get<int32_t>());
     assertConditionTimer(it->second.conditionTimer, true, 0, bucket2StartTimeNs + 10 * NS_PER_SEC);
 
     // Bucket status after screen state change ON->OFF, forces bucket flush and new bucket start
@@ -7170,7 +7171,7 @@ TEST(NumericValueMetricProducerTest_ConditionCorrection, TestLateStateChangeSlic
     // Value for dimension, state key {{}, OFF}
     it = valueProducer->mCurrentSlicedBucket.begin();
     EXPECT_EQ(android::view::DisplayStateEnum::DISPLAY_STATE_OFF,
-              it->first.getStateValuesKey().getValues()[0].mValue.int_value);
+              it->first.getStateValuesKey().getValues()[0].mValue.get<int32_t>());
     assertConditionTimer(it->second.conditionTimer, true, 0, bucket3StartTimeNs, 0);
 
     // Bucket status after screen state change OFF->ON, forces bucket flush and new bucket start
diff --git a/statsd/tests/metrics/parsing_utils/config_update_utils_test.cpp b/statsd/tests/metrics/parsing_utils/config_update_utils_test.cpp
index 08618125..cb0df8f0 100644
--- a/statsd/tests/metrics/parsing_utils/config_update_utils_test.cpp
+++ b/statsd/tests/metrics/parsing_utils/config_update_utils_test.cpp
@@ -2295,7 +2295,7 @@ TEST_F(ConfigUpdateTest, TestUpdateCountMetrics) {
     FieldValue screenState;
     StateManager::getInstance().getStateValue(util::SCREEN_STATE_CHANGED, DEFAULT_DIMENSION_KEY,
                                               &screenState);
-    EXPECT_EQ(screenState.mValue.int_value, android::view::DisplayStateEnum::DISPLAY_STATE_ON);
+    EXPECT_EQ(screenState.mValue.get<int32_t>(), android::view::DisplayStateEnum::DISPLAY_STATE_ON);
 }
 
 TEST_F(ConfigUpdateTest, TestUpdateGaugeMetrics) {
diff --git a/statsd/tests/state/StateTracker_test.cpp b/statsd/tests/state/StateTracker_test.cpp
index de53bd09..dc00998f 100644
--- a/statsd/tests/state/StateTracker_test.cpp
+++ b/statsd/tests/state/StateTracker_test.cpp
@@ -54,14 +54,14 @@ public:
     void onStateChanged(const int64_t eventTimeNs, const int32_t atomId,
                         const HashableDimensionKey& primaryKey, const FieldValue& oldState,
                         const FieldValue& newState) {
-        updates.emplace_back(primaryKey, newState.mValue.int_value);
+        updates.emplace_back(primaryKey, newState.mValue.get<int32_t>());
     }
 };
 
 int getStateInt(StateManager& mgr, int atomId, const HashableDimensionKey& queryKey) {
     FieldValue output;
     mgr.getStateValue(atomId, queryKey, &output);
-    return output.mValue.int_value;
+    return output.mValue.get<int32_t>();
 }
 
 // START: build event functions.
@@ -259,7 +259,7 @@ TEST(StateTrackerTest, TestStateChangeNested) {
                                                                   attributionTags1, "wakelockName");
     mgr.onLogEvent(*event1);
     ASSERT_EQ(1, listener->updates.size());
-    EXPECT_EQ(1000, listener->updates[0].mKey.getValues()[0].mValue.int_value);
+    EXPECT_EQ(1000, listener->updates[0].mKey.getValues()[0].mValue.get<int32_t>());
     EXPECT_EQ(1, listener->updates[0].mState);
     listener->updates.clear();
 
@@ -277,7 +277,7 @@ TEST(StateTrackerTest, TestStateChangeNested) {
             timestampNs + 3000, attributionUids1, attributionTags1, "wakelockName");
     mgr.onLogEvent(*event4);
     ASSERT_EQ(1, listener->updates.size());
-    EXPECT_EQ(1000, listener->updates[0].mKey.getValues()[0].mValue.int_value);
+    EXPECT_EQ(1000, listener->updates[0].mKey.getValues()[0].mValue.get<int32_t>());
     EXPECT_EQ(0, listener->updates[0].mState);
 }
 
@@ -301,11 +301,11 @@ TEST(StateTrackerTest, TestStateChangeReset) {
                                            BleScanStateChanged::ON, false, false, false);
     mgr.onLogEvent(*event1);
     ASSERT_EQ(1, listener->updates.size());
-    EXPECT_EQ(1000, listener->updates[0].mKey.getValues()[0].mValue.int_value);
+    EXPECT_EQ(1000, listener->updates[0].mKey.getValues()[0].mValue.get<int32_t>());
     EXPECT_EQ(BleScanStateChanged::ON, listener->updates[0].mState);
     FieldValue stateFieldValue;
     mgr.getStateValue(util::BLE_SCAN_STATE_CHANGED, listener->updates[0].mKey, &stateFieldValue);
-    EXPECT_EQ(BleScanStateChanged::ON, stateFieldValue.mValue.int_value);
+    EXPECT_EQ(BleScanStateChanged::ON, stateFieldValue.mValue.get<int32_t>());
     listener->updates.clear();
 
     std::unique_ptr<LogEvent> event2 =
@@ -313,10 +313,10 @@ TEST(StateTrackerTest, TestStateChangeReset) {
                                            BleScanStateChanged::ON, false, false, false);
     mgr.onLogEvent(*event2);
     ASSERT_EQ(1, listener->updates.size());
-    EXPECT_EQ(2000, listener->updates[0].mKey.getValues()[0].mValue.int_value);
+    EXPECT_EQ(2000, listener->updates[0].mKey.getValues()[0].mValue.get<int32_t>());
     EXPECT_EQ(BleScanStateChanged::ON, listener->updates[0].mState);
     mgr.getStateValue(util::BLE_SCAN_STATE_CHANGED, listener->updates[0].mKey, &stateFieldValue);
-    EXPECT_EQ(BleScanStateChanged::ON, stateFieldValue.mValue.int_value);
+    EXPECT_EQ(BleScanStateChanged::ON, stateFieldValue.mValue.get<int32_t>());
     listener->updates.clear();
 
     std::unique_ptr<LogEvent> event3 =
@@ -328,7 +328,7 @@ TEST(StateTrackerTest, TestStateChangeReset) {
         EXPECT_EQ(BleScanStateChanged::OFF, update.mState);
 
         mgr.getStateValue(util::BLE_SCAN_STATE_CHANGED, update.mKey, &stateFieldValue);
-        EXPECT_EQ(BleScanStateChanged::OFF, stateFieldValue.mValue.int_value);
+        EXPECT_EQ(BleScanStateChanged::OFF, stateFieldValue.mValue.get<int32_t>());
     }
 }
 
@@ -373,7 +373,7 @@ TEST(StateTrackerTest, TestStateChangeOnePrimaryField) {
 
     // check listener was updated
     ASSERT_EQ(1, listener1->updates.size());
-    EXPECT_EQ(1000, listener1->updates[0].mKey.getValues()[0].mValue.int_value);
+    EXPECT_EQ(1000, listener1->updates[0].mKey.getValues()[0].mValue.get<int32_t>());
     EXPECT_EQ(1002, listener1->updates[0].mState);
 
     // check StateTracker was updated by querying for state
@@ -401,9 +401,9 @@ TEST(StateTrackerTest, TestStateChangePrimaryFieldAttrChain) {
     // Check listener was updated.
     ASSERT_EQ(1, listener1->updates.size());
     ASSERT_EQ(3, listener1->updates[0].mKey.getValues().size());
-    EXPECT_EQ(1001, listener1->updates[0].mKey.getValues()[0].mValue.int_value);
-    EXPECT_EQ(1, listener1->updates[0].mKey.getValues()[1].mValue.int_value);
-    EXPECT_EQ("wakelockName", listener1->updates[0].mKey.getValues()[2].mValue.str_value);
+    EXPECT_EQ(1001, listener1->updates[0].mKey.getValues()[0].mValue.get<int32_t>());
+    EXPECT_EQ(1, listener1->updates[0].mKey.getValues()[1].mValue.get<int32_t>());
+    EXPECT_EQ("wakelockName", listener1->updates[0].mKey.getValues()[2].mValue.get<string>());
     EXPECT_EQ(WakelockStateChanged::ACQUIRE, listener1->updates[0].mState);
 
     // Check StateTracker was updated by querying for state.
@@ -442,7 +442,7 @@ TEST(StateTrackerTest, TestStateChangeMultiplePrimaryFields) {
 
     // check listener was updated
     ASSERT_EQ(1, listener1->updates.size());
-    EXPECT_EQ(1000, listener1->updates[0].mKey.getValues()[0].mValue.int_value);
+    EXPECT_EQ(1000, listener1->updates[0].mKey.getValues()[0].mValue.get<int32_t>());
     EXPECT_EQ(1, listener1->updates[0].mState);
 
     // check StateTracker was updated by querying for state
@@ -577,7 +577,7 @@ TEST(StateTrackerTest, TestMalformedStateEvent_ExistingStateValue) {
     EXPECT_EQ(BatteryPluggedStateEnum::BATTERY_PLUGGED_USB, listener->updates[0].mState);
     FieldValue stateFieldValue;
     mgr.getStateValue(util::PLUGGED_STATE_CHANGED, listener->updates[0].mKey, &stateFieldValue);
-    EXPECT_EQ(BatteryPluggedStateEnum::BATTERY_PLUGGED_USB, stateFieldValue.mValue.int_value);
+    EXPECT_EQ(BatteryPluggedStateEnum::BATTERY_PLUGGED_USB, stateFieldValue.mValue.get<int32_t>());
     listener->updates.clear();
 
     // Malformed event.
@@ -587,7 +587,7 @@ TEST(StateTrackerTest, TestMalformedStateEvent_ExistingStateValue) {
     EXPECT_EQ(kStateUnknown, listener->updates[0].mState);
     EXPECT_FALSE(mgr.getStateValue(util::PLUGGED_STATE_CHANGED, listener->updates[0].mKey,
                                    &stateFieldValue));
-    EXPECT_EQ(kStateUnknown, stateFieldValue.mValue.int_value);
+    EXPECT_EQ(kStateUnknown, stateFieldValue.mValue.get<int32_t>());
     listener->updates.clear();
 }
 
diff --git a/statsd/tests/statsd_test_util.cpp b/statsd/tests/statsd_test_util.cpp
index 6ffd6c33..01203c80 100644
--- a/statsd/tests/statsd_test_util.cpp
+++ b/statsd/tests/statsd_test_util.cpp
@@ -2440,6 +2440,20 @@ StatsdStatsReport getStatsdStatsReport(bool resetStats) {
     return getStatsdStatsReport(stats, resetStats);
 }
 
+optional<ConfigMetricsReportList> getReports(StatsLogProcessor& processor, int64_t dumpTimeNs,
+                                             const ConfigKey& cfgKey, bool includeCurrentBucket) {
+    ConfigMetricsReportList reports;
+    vector<uint8_t> buffer;
+    processor.onDumpReport(cfgKey, dumpTimeNs, includeCurrentBucket, true, ADB_DUMP, FAST, &buffer);
+    if (reports.ParseFromArray(&buffer[0], buffer.size())) {
+        backfillDimensionPath(&reports);
+        backfillStringInReport(&reports);
+        backfillStartEndTimestamp(&reports);
+        return reports;
+    }
+    return nullopt;
+}
+
 StatsdStatsReport getStatsdStatsReport(StatsdStats& stats, bool resetStats) {
     vector<uint8_t> statsBuffer;
     stats.dumpStats(&statsBuffer, resetStats);
diff --git a/statsd/tests/statsd_test_util.h b/statsd/tests/statsd_test_util.h
index 404d9e2a..8c9e0e5e 100644
--- a/statsd/tests/statsd_test_util.h
+++ b/statsd/tests/statsd_test_util.h
@@ -897,6 +897,10 @@ public:
 
 sp<MockConfigMetadataProvider> makeMockConfigMetadataProvider(bool enabled);
 
+std::optional<ConfigMetricsReportList> getReports(StatsLogProcessor& processor, int64_t dumpTimeNs,
+                                                  const ConfigKey& cfgKey,
+                                                  bool includeCurrentBucket);
+
 }  // namespace statsd
 }  // namespace os
 }  // namespace android
diff --git a/statsd/tools/localtools/src/com/android/statsd/shelltools/testdrive/TestDrive.java b/statsd/tools/localtools/src/com/android/statsd/shelltools/testdrive/TestDrive.java
index e3952d86..38cbee74 100644
--- a/statsd/tools/localtools/src/com/android/statsd/shelltools/testdrive/TestDrive.java
+++ b/statsd/tools/localtools/src/com/android/statsd/shelltools/testdrive/TestDrive.java
@@ -635,6 +635,11 @@ public class TestDrive {
                                     .setAtomId(ZramExtensionAtoms
                                             .ZRAM_BD_STAT_MMD_FIELD_NUMBER)
                                     .addPackages("AID_MMD"))
+                    .addPullAtomPackages(
+                            PullAtomPackages.newBuilder()
+                                    .setAtomId(ZramExtensionAtoms
+                                            .ZRAM_IO_STAT_MMD_FIELD_NUMBER)
+                                    .addPackages("AID_MMD"))
                     .setHashStringsInMetricReport(false);
         }
     }
diff --git a/tests/utils/src/android/util/AtomPayloadParser.java b/tests/utils/src/android/util/AtomPayloadParser.java
new file mode 100644
index 00000000..b6cce0a0
--- /dev/null
+++ b/tests/utils/src/android/util/AtomPayloadParser.java
@@ -0,0 +1,191 @@
+/*
+ * Copyright (C) 2023 The Android Open Source Project
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
+package android.util;
+
+import static android.util.StatsEvent.TYPE_ATTRIBUTION_CHAIN;
+import static android.util.StatsEvent.TYPE_BOOLEAN;
+import static android.util.StatsEvent.TYPE_BYTE_ARRAY;
+import static android.util.StatsEvent.TYPE_ERRORS;
+import static android.util.StatsEvent.TYPE_FLOAT;
+import static android.util.StatsEvent.TYPE_INT;
+import static android.util.StatsEvent.TYPE_LIST;
+import static android.util.StatsEvent.TYPE_LONG;
+import static android.util.StatsEvent.TYPE_STRING;
+import static android.util.proto.ProtoOutputStream.FIELD_COUNT_REPEATED;
+import static android.util.proto.ProtoOutputStream.FIELD_COUNT_SINGLE;
+import static android.util.proto.ProtoOutputStream.FIELD_TYPE_FLOAT;
+import static android.util.proto.ProtoOutputStream.FIELD_TYPE_INT32;
+import static android.util.proto.ProtoOutputStream.FIELD_TYPE_INT64;
+import static android.util.proto.ProtoOutputStream.FIELD_TYPE_MESSAGE;
+import static android.util.proto.ProtoOutputStream.FIELD_TYPE_STRING;
+import static java.nio.charset.StandardCharsets.UTF_8;
+
+import android.util.proto.ProtoOutputStream;
+import java.nio.ByteBuffer;
+import java.nio.ByteOrder;
+
+/** Provides utility methods for parsing logged atom payloads in tests. */
+final class AtomPayloadParser {
+    private static final int ATTRIBUTION_UID_FIELD = 1;
+    private static final int ATTRIBUTION_TAG_FIELD = 2;
+
+    private AtomPayloadParser() {} // no instances.
+
+    /**
+     * Converts an Atom event payload into a byte array representing a serialized {@link
+     * com.android.os.AtomsProto.Atom}.
+     */
+    static byte[] getProtoBytes(byte[] eventBytes, int numBytes) {
+        ByteBuffer buf = ByteBuffer.wrap(eventBytes).order(ByteOrder.LITTLE_ENDIAN);
+        buf.get(); // Payload starts with TYPE_OBJECT.
+
+        // Read number of elements at the root level.
+        byte fieldsRemaining = buf.get();
+        if (fieldsRemaining < 2) {
+            // Each StatsEvent should at least have a timestamp and atom ID.
+            throw new IllegalArgumentException("Event should have more than 2 elements.");
+        }
+
+        // Read timestamp.
+        if (buf.get() != TYPE_LONG) {
+            // Timestamp should be TYPE_LONG
+            throw new IllegalArgumentException("Event does not have timestamp.");
+        }
+        buf.getLong(); // Read elapsed timestamp.
+        fieldsRemaining--;
+
+        // Read atom ID.
+        FieldMetadata fieldMetadata = parseFieldMetadata(buf);
+        if (fieldMetadata.typeId != TYPE_INT) {
+            // atom ID should be an integer.
+            throw new IllegalArgumentException("Event does not have an atom ID.");
+        }
+        int atomId = buf.getInt();
+        skipAnnotations(buf, fieldMetadata.annotationCount);
+        fieldsRemaining--;
+
+        ProtoOutputStream proto = new ProtoOutputStream();
+        long atomToken = proto.start(FIELD_TYPE_MESSAGE | FIELD_COUNT_SINGLE | atomId);
+
+        // Read atom fields.
+        for (int tag = 1; tag <= fieldsRemaining; tag++) {
+            fieldMetadata = parseFieldMetadata(buf);
+            parseField(fieldMetadata.typeId, FIELD_COUNT_SINGLE, tag, buf, proto);
+            skipAnnotations(buf, fieldMetadata.annotationCount);
+        }
+
+        // We should have parsed all bytes at this point.
+        if (buf.position() != numBytes) {
+            throw new IllegalArgumentException("Unexpected bytes left in the array.");
+        }
+
+        proto.end(atomToken);
+        return proto.getBytes();
+    }
+
+    private static void parseField(
+            byte typeId, long fieldCount, int tag, ByteBuffer buf, ProtoOutputStream proto) {
+        switch (typeId) {
+            case TYPE_INT:
+                proto.write(FIELD_TYPE_INT32 | fieldCount | tag, buf.getInt());
+                break;
+            case TYPE_LONG:
+                proto.write(FIELD_TYPE_INT64 | fieldCount | tag, buf.getLong());
+                break;
+            case TYPE_STRING:
+                String value = new String(getByteArrayFromByteBuffer(buf), UTF_8);
+                proto.write(FIELD_TYPE_STRING | fieldCount | tag, value);
+                break;
+            case TYPE_FLOAT:
+                proto.write(FIELD_TYPE_FLOAT | fieldCount | tag, buf.getFloat());
+                break;
+            case TYPE_BOOLEAN:
+                proto.write(FIELD_TYPE_INT32 | fieldCount | tag, buf.get());
+                break;
+            case TYPE_ATTRIBUTION_CHAIN:
+                byte numNodes = buf.get();
+                for (byte i = 1; i <= numNodes; i++) {
+                    long token = proto.start(FIELD_TYPE_MESSAGE | FIELD_COUNT_REPEATED | tag);
+                    proto.write(
+                            FIELD_TYPE_INT32 | FIELD_COUNT_SINGLE | ATTRIBUTION_UID_FIELD,
+                            buf.getInt());
+                    String tagName = new String(getByteArrayFromByteBuffer(buf), UTF_8);
+                    proto.write(
+                            FIELD_TYPE_STRING | FIELD_COUNT_SINGLE | ATTRIBUTION_TAG_FIELD,
+                            tagName);
+                    proto.end(token);
+                }
+                break;
+            case TYPE_BYTE_ARRAY:
+                byte[] byteArray = getByteArrayFromByteBuffer(buf);
+                proto.write(FIELD_TYPE_MESSAGE | FIELD_COUNT_SINGLE | tag, byteArray);
+                break;
+            case TYPE_LIST:
+                byte numItems = buf.get();
+                byte listTypeId = buf.get();
+                for (byte i = 1; i <= numItems; i++) {
+                    parseField(listTypeId, FIELD_COUNT_REPEATED, tag, buf, proto);
+                }
+                break;
+            case TYPE_ERRORS:
+                int errorMask = buf.getInt();
+                throw new IllegalArgumentException("StatsEvent has error(s): " + errorMask);
+            default:
+                throw new IllegalArgumentException(
+                        "Invalid typeId encountered while parsing StatsEvent: " + typeId);
+        }
+    }
+
+    private static byte[] getByteArrayFromByteBuffer(ByteBuffer buf) {
+        final int numBytes = buf.getInt();
+        byte[] bytes = new byte[numBytes];
+        buf.get(bytes);
+        return bytes;
+    }
+
+    private static void skipAnnotations(ByteBuffer buf, int annotationCount) {
+        for (int i = 1; i <= annotationCount; i++) {
+            buf.get(); // read annotation ID.
+            byte annotationType = buf.get();
+            if (annotationType == TYPE_INT) {
+                buf.getInt(); // read and drop int annotation value.
+            } else if (annotationType == TYPE_BOOLEAN) {
+                buf.get(); // read and drop byte annotation value.
+            } else {
+                throw new IllegalArgumentException("StatsEvent has an invalid annotation.");
+            }
+        }
+    }
+
+    private static FieldMetadata parseFieldMetadata(ByteBuffer buf) {
+        byte typeId = buf.get();
+        byte annotationCount = (byte) (typeId >> 4);
+        typeId &= (byte) 0x0F;
+
+        return new FieldMetadata(typeId, annotationCount);
+    }
+
+    private static class FieldMetadata {
+        final byte typeId;
+        final byte annotationCount;
+
+        FieldMetadata(byte typeId, byte annotationCount) {
+            this.typeId = typeId;
+            this.annotationCount = annotationCount;
+        }
+    }
+}
diff --git a/tests/utils/src/android/util/StatsEventTestUtils.java b/tests/utils/src/android/util/StatsEventTestUtils.java
index 049f4158..5d46fd5d 100644
--- a/tests/utils/src/android/util/StatsEventTestUtils.java
+++ b/tests/utils/src/android/util/StatsEventTestUtils.java
@@ -16,182 +16,25 @@
 
 package android.util;
 
-import static android.util.StatsEvent.TYPE_ATTRIBUTION_CHAIN;
-import static android.util.StatsEvent.TYPE_BOOLEAN;
-import static android.util.StatsEvent.TYPE_BYTE_ARRAY;
-import static android.util.StatsEvent.TYPE_ERRORS;
-import static android.util.StatsEvent.TYPE_FLOAT;
-import static android.util.StatsEvent.TYPE_INT;
-import static android.util.StatsEvent.TYPE_LIST;
-import static android.util.StatsEvent.TYPE_LONG;
-import static android.util.StatsEvent.TYPE_STRING;
-import static android.util.proto.ProtoOutputStream.FIELD_COUNT_REPEATED;
-import static android.util.proto.ProtoOutputStream.FIELD_COUNT_SINGLE;
-import static android.util.proto.ProtoOutputStream.FIELD_TYPE_FLOAT;
-import static android.util.proto.ProtoOutputStream.FIELD_TYPE_INT32;
-import static android.util.proto.ProtoOutputStream.FIELD_TYPE_INT64;
-import static android.util.proto.ProtoOutputStream.FIELD_TYPE_MESSAGE;
-import static android.util.proto.ProtoOutputStream.FIELD_TYPE_STRING;
-import static java.nio.charset.StandardCharsets.UTF_8;
-
-import android.util.proto.ProtoOutputStream;
 import com.android.os.AtomsProto.Atom;
 import com.google.protobuf.InvalidProtocolBufferException;
-import java.nio.ByteBuffer;
-import java.nio.ByteOrder;
 
+/** Provides utility methods for parsing StatsEvent and StatsLogItem objects in tests. */
 public final class StatsEventTestUtils {
-    private static final int ATTRIBUTION_UID_FIELD = 1;
-    private static final int ATTRIBUTION_TAG_FIELD = 2;
-
-    private StatsEventTestUtils() {
-    } // no instances.
+    private StatsEventTestUtils() {} // no instances.
 
-    // Convert StatsEvent to MessageLite representation of Atom.
-    // Calls StatsEvent#release; No further actions should be taken on the StatsEvent
-    // object.
+    /**
+     * Converts StatsEvent to MessageLite representation of Atom. Calls StatsEvent#release; No
+     * further actions should be taken on the StatsEvent object.
+     */
     public static Atom convertToAtom(StatsEvent statsEvent) throws InvalidProtocolBufferException {
-        return Atom.parseFrom(getProtoBytes(statsEvent));
-    }
-
-    // Convert StatsEvent to serialized proto representation of Atom.
-    // Calls StatsEvent#release; No further actions should be taken on the StatsEvent
-    // object.
-    private static byte[] getProtoBytes(StatsEvent statsEvent) {
         try {
-            ByteBuffer buf = ByteBuffer.wrap(statsEvent.getBytes()).order(ByteOrder.LITTLE_ENDIAN);
-            buf.get(); // Payload starts with TYPE_OBJECT.
-
-            // Read number of elements at the root level.
-            byte fieldsRemaining = buf.get();
-            if (fieldsRemaining < 2) {
-                // Each StatsEvent should at least have a timestamp and atom ID.
-                throw new IllegalArgumentException("StatsEvent should have more than 2 elements.");
-            }
-
-            // Read timestamp.
-            if (buf.get() != TYPE_LONG) {
-                // Timestamp should be TYPE_LONG
-                throw new IllegalArgumentException("StatsEvent does not have timestamp.");
-            }
-            buf.getLong(); // Read elapsed timestamp.
-            fieldsRemaining--;
-
-            // Read atom ID.
-            FieldMetadata fieldMetadata = parseFieldMetadata(buf);
-            if (fieldMetadata.typeId != TYPE_INT) {
-                // atom ID should be an integer.
-                throw new IllegalArgumentException("StatsEvent does not have an atom ID.");
-            }
-            int atomId = buf.getInt();
-            skipAnnotations(buf, fieldMetadata.annotationCount);
-            fieldsRemaining--;
-
-            ProtoOutputStream proto = new ProtoOutputStream();
-            long atomToken = proto.start(FIELD_TYPE_MESSAGE | FIELD_COUNT_SINGLE | atomId);
-
-            // Read atom fields.
-            for (int tag = 1; tag <= fieldsRemaining; tag++) {
-                fieldMetadata = parseFieldMetadata(buf);
-                parseField(fieldMetadata.typeId, FIELD_COUNT_SINGLE, tag, buf, proto);
-                skipAnnotations(buf, fieldMetadata.annotationCount);
-            }
-
-            // We should have parsed all bytes in StatsEvent at this point.
-            if (buf.position() != statsEvent.getNumBytes()) {
-                throw new IllegalArgumentException("Unexpected bytes in StatsEvent");
-            }
-
-            proto.end(atomToken);
-            return proto.getBytes();
+            byte[] protoBytes =
+                    AtomPayloadParser.getProtoBytes(
+                            statsEvent.getBytes(), statsEvent.getNumBytes());
+            return Atom.parseFrom(protoBytes);
         } finally {
             statsEvent.release();
         }
     }
-
-    private static void parseField(
-            byte typeId, long fieldCount, int tag, ByteBuffer buf, ProtoOutputStream proto) {
-        switch (typeId) {
-            case TYPE_INT:
-                proto.write(FIELD_TYPE_INT32 | fieldCount | tag, buf.getInt());
-                break;
-            case TYPE_LONG:
-                proto.write(FIELD_TYPE_INT64 | fieldCount | tag, buf.getLong());
-                break;
-            case TYPE_STRING:
-                String value = new String(getByteArrayFromByteBuffer(buf), UTF_8);
-                proto.write(FIELD_TYPE_STRING | fieldCount | tag, value);
-                break;
-            case TYPE_FLOAT:
-                proto.write(FIELD_TYPE_FLOAT | fieldCount | tag, buf.getFloat());
-                break;
-            case TYPE_BOOLEAN:
-                proto.write(FIELD_TYPE_INT32 | fieldCount | tag, buf.get());
-                break;
-            case TYPE_ATTRIBUTION_CHAIN:
-                byte numNodes = buf.get();
-                for (byte i = 1; i <= numNodes; i++) {
-                    long token = proto.start(FIELD_TYPE_MESSAGE | FIELD_COUNT_REPEATED | tag);
-                    proto.write(FIELD_TYPE_INT32 | FIELD_COUNT_SINGLE | ATTRIBUTION_UID_FIELD,
-                            buf.getInt());
-                    String tagName = new String(getByteArrayFromByteBuffer(buf), UTF_8);
-                    proto.write(FIELD_TYPE_STRING | FIELD_COUNT_SINGLE | ATTRIBUTION_TAG_FIELD,
-                            tagName);
-                    proto.end(token);
-                }
-                break;
-            case TYPE_BYTE_ARRAY:
-                byte[] byteArray = getByteArrayFromByteBuffer(buf);
-                proto.write(FIELD_TYPE_MESSAGE | FIELD_COUNT_SINGLE | tag, byteArray);
-                break;
-            case TYPE_LIST:
-                byte numItems = buf.get();
-                byte listTypeId = buf.get();
-                for (byte i = 1; i <= numItems; i++) {
-                    parseField(listTypeId, FIELD_COUNT_REPEATED, tag, buf, proto);
-                }
-                break;
-            case TYPE_ERRORS:
-                int errorMask = buf.getInt();
-                throw new IllegalArgumentException("StatsEvent has error(s): " + errorMask);
-            default:
-                throw new IllegalArgumentException(
-                        "Invalid typeId encountered while parsing StatsEvent: " + typeId);
-        }
-    }
-
-    private static byte[] getByteArrayFromByteBuffer(ByteBuffer buf) {
-        final int numBytes = buf.getInt();
-        byte[] bytes = new byte[numBytes];
-        buf.get(bytes);
-        return bytes;
-    }
-
-    private static void skipAnnotations(ByteBuffer buf, int annotationCount) {
-        for (int i = 1; i <= annotationCount; i++) {
-            buf.get(); // read annotation ID.
-            byte annotationType = buf.get();
-            if (annotationType == TYPE_INT) {
-                buf.getInt(); // read and drop int annotation value.
-            } else if (annotationType == TYPE_BOOLEAN) {
-                buf.get(); // read and drop byte annotation value.
-            } else {
-                throw new IllegalArgumentException("StatsEvent has an invalid annotation.");
-            }
-        }
-    }
-
-    private static FieldMetadata parseFieldMetadata(ByteBuffer buf) {
-        FieldMetadata fieldMetadata = new FieldMetadata();
-        fieldMetadata.typeId = buf.get();
-        fieldMetadata.annotationCount = (byte) (fieldMetadata.typeId >> 4);
-        fieldMetadata.typeId &= (byte) 0x0F;
-
-        return fieldMetadata;
-    }
-
-    private static class FieldMetadata {
-        byte typeId;
-        byte annotationCount;
-    }
 }
```

