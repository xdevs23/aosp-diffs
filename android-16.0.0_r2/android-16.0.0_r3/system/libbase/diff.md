```diff
diff --git a/Android.bp b/Android.bp
index d132bc9..041cb58 100644
--- a/Android.bp
+++ b/Android.bp
@@ -38,6 +38,9 @@ cc_defaults {
         "-Werror",
         "-Wextra",
     ],
+    sanitize: {
+        misc_undefined: ["integer"],
+    },
     target: {
         android: {
             cflags: [
@@ -108,12 +111,6 @@ cc_defaults {
     cppflags: ["-Wexit-time-destructors"],
     shared_libs: ["liblog"],
     target: {
-        android: {
-            sanitize: {
-                misc_undefined: ["integer"],
-            },
-
-        },
         linux: {
             srcs: [
                 "errors_unix.cpp",
@@ -206,17 +203,13 @@ cc_test {
         "properties_test.cpp",
         "result_test.cpp",
         "scopeguard_test.cpp",
+        "stringify_test.cpp",
         "stringprintf_test.cpp",
         "strings_test.cpp",
         "test_main.cpp",
         "test_utils_test.cpp",
     ],
     target: {
-        android: {
-            sanitize: {
-                misc_undefined: ["integer"],
-            },
-        },
         linux: {
             srcs: ["chrono_utils_test.cpp"],
         },
diff --git a/include/android-base/logging.h b/include/android-base/logging.h
index 42b2538..7b6e599 100644
--- a/include/android-base/logging.h
+++ b/include/android-base/logging.h
@@ -92,6 +92,11 @@ enum LogSeverity {
   FATAL,
 };
 
+// Map from LogSeverity to the corresponding character.
+static constexpr char kSeverityChars[] = "VDIWEFF";
+static_assert(arraysize(kSeverityChars) - 1 == android::base::FATAL + 1,
+              "Mismatch in size of kSeverityChars and values in LogSeverity");
+
 enum LogId {
   DEFAULT,
   MAIN,
@@ -205,8 +210,10 @@ struct LogAbortAfterFullExpr {
 #define ABORT_AFTER_LOG_FATAL_EXPR(x) ABORT_AFTER_LOG_EXPR_IF(true, x)
 
 // Defines whether the given severity will be logged or silently swallowed.
-#define WOULD_LOG(severity)                                                              \
-  (UNLIKELY(::android::base::ShouldLog(SEVERITY_LAMBDA(severity), _LOG_TAG_INTERNAL)) || \
+#define WOULD_LOG(severity) WOULD_LOG_WITH_TAG(severity, _LOG_TAG_INTERNAL)
+
+#define WOULD_LOG_WITH_TAG(severity, tag)                                  \
+  (UNLIKELY(::android::base::ShouldLog(SEVERITY_LAMBDA(severity), tag)) || \
    MUST_LOG_MESSAGE(severity))
 
 // Get an ostream that can be used for logging at the given severity and to the default
diff --git a/include/android-base/stringify.h b/include/android-base/stringify.h
new file mode 100644
index 0000000..e188b2b
--- /dev/null
+++ b/include/android-base/stringify.h
@@ -0,0 +1,25 @@
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
+// Converts macro argument 'x' into a string constant without macro expansion.
+// So QUOTE(EINVAL) would be "EINVAL".
+#define QUOTE(x...) #x
+
+// Converts macro argument 'x' into a string constant after macro expansion.
+// So STRINGIFY(EINVAL) would be "22".
+#define STRINGIFY(x...) QUOTE(x)
diff --git a/include/android-base/strings.h b/include/android-base/strings.h
index db13045..a4ff3ae 100644
--- a/include/android-base/strings.h
+++ b/include/android-base/strings.h
@@ -60,7 +60,7 @@ constexpr bool always_false_v = false;
 }
 
 template <typename T>
-std::string Trim(T&& t) {
+[[nodiscard]] std::string Trim(T&& t) {
   std::string_view sv;
   std::string s;
   if constexpr (std::is_convertible_v<T, std::string_view>) {
diff --git a/logging.cpp b/logging.cpp
index 6ba8ea7..07ba382 100644
--- a/logging.cpp
+++ b/logging.cpp
@@ -486,7 +486,7 @@ LogMessage::LogMessage(const char* file, unsigned int line, LogSeverity severity
 
 LogMessage::~LogMessage() {
   // Check severity again. This is duplicate work wrt/ LOG macros, but not LOG_STREAM.
-  if (!WOULD_LOG(data_->GetSeverity())) {
+  if (!WOULD_LOG_WITH_TAG(data_->GetSeverity(), data_->GetTag())) {
     return;
   }
 
diff --git a/logging_splitters.h b/logging_splitters.h
index 4bee739..4021d1b 100644
--- a/logging_splitters.h
+++ b/logging_splitters.h
@@ -51,14 +51,26 @@ static void SplitByLogdChunks(LogId log_id, LogSeverity severity, const char* ta
   // The maximum size of a payload, after the log header that logd will accept is
   // LOGGER_ENTRY_MAX_PAYLOAD, so subtract the other elements in the payload to find the size of
   // the string that we can log in each pass.
-  // The protocol is documented in liblog/README.protocol.md.
-  // Specifically we subtract a byte for the priority, the length of the tag + its null terminator,
-  // and an additional byte for the null terminator on the payload.  We subtract an additional 32
-  // bytes for slack, similar to java/android/util/Log.java.
-  ptrdiff_t max_size = LOGGER_ENTRY_MAX_PAYLOAD - strlen(tag) - 35;
-  if (max_size <= 0) {
-    abort();
+  // (The protocol is documented in liblog/README.protocol.md.)
+  size_t max_size = LOGGER_ENTRY_MAX_PAYLOAD;
+  // Specifically we subtract a byte for the priority...
+  max_size -= 1;
+  // A byte for the null terminator on the tag...
+  max_size -= 1;
+  // A byte for the null terminator on the payload...
+  max_size -= 1;
+  // We subtract an additional 32 bytes for slack, similar to java/android/util/Log.java.
+  max_size -= 32;
+  // And finally the length of the tag.
+  // If the tag is unreasonable, we replace it with a constant.
+  // (It's possible that our definition of "unreasonable" should actually be max_size/2 instead.)
+  size_t tag_length = strlen(tag);
+  if (tag_length >= max_size) {
+    tag = "TAG_TOO_LONG";
+    tag_length = strlen(tag);
   }
+  max_size -= tag_length;
+
   // If we're logging a fatal message, we'll append the file and line numbers.
   bool add_file = file != nullptr && (severity == FATAL || severity == FATAL_WITHOUT_ABORT);
 
@@ -69,7 +81,7 @@ static void SplitByLogdChunks(LogId log_id, LogSeverity severity, const char* ta
   int file_header_size = file_header.size();
 
   __attribute__((uninitialized)) char logd_chunk[max_size + 1];
-  ptrdiff_t chunk_position = 0;
+  size_t chunk_position = 0;
 
   auto call_log_function = [&]() {
     log_function(log_id, severity, tag, logd_chunk);
@@ -112,8 +124,7 @@ static void SplitByLogdChunks(LogId log_id, LogSeverity severity, const char* ta
 
   // If we have left over data in the buffer and we can fit the rest of msg, add it to the buffer
   // then write the buffer.
-  if (chunk_position != 0 &&
-      chunk_position + static_cast<int>(strlen(msg)) + 1 + file_header_size <= max_size) {
+  if (chunk_position != 0 && chunk_position + strlen(msg) + 1 + file_header_size <= max_size) {
     write_to_logd_chunk(msg, -1);
     call_log_function();
   } else {
@@ -155,10 +166,7 @@ static std::string StderrOutputGenerator(const struct timespec& ts, int pid, uin
   size_t n = strftime(timestamp, sizeof(timestamp), "%m-%d %H:%M:%S", &now);
   snprintf(timestamp + n, sizeof(timestamp) - n, ".%03ld", ts.tv_nsec / (1000 * 1000));
 
-  static const char log_characters[] = "VDIWEFF";
-  static_assert(arraysize(log_characters) - 1 == FATAL + 1,
-                "Mismatch in size of log_characters and values in LogSeverity");
-  char severity_char = log_characters[severity];
+  char severity_char = kSeverityChars[severity];
   std::string line_prefix;
   const char* real_tag = tag ? tag : "nullptr";
   if (file != nullptr) {
diff --git a/logging_splitters_test.cpp b/logging_splitters_test.cpp
index 04e9625..bde1f6d 100644
--- a/logging_splitters_test.cpp
+++ b/logging_splitters_test.cpp
@@ -51,7 +51,7 @@ TEST(logging_splitters, NewlineSplitter_BasicString) {
   TestNewlineSplitter("normal string", std::vector<std::string>{"normal string"});
 }
 
-TEST(logging_splitters, NewlineSplitter_ormalBasicStringTrailingNewline) {
+TEST(logging_splitters, NewlineSplitter_NormalBasicStringTrailingNewline) {
   TestNewlineSplitter("normal string\n", std::vector<std::string>{"normal string", ""});
 }
 
@@ -234,14 +234,13 @@ TEST(logging_splitters, LogdChunkSplitter_WithFile) {
   TestLogdChunkSplitter(tag, file, long_strings, expected);
 }
 
-// We set max_size based off of tag, so if it's too large, the buffer will be sized wrong.
-// We could recover from this, but it's certainly an error for someone to attempt to use a tag this
-// large, so we abort instead.
-TEST_F(logging_splitters_DeathTest, LogdChunkSplitter_TooLongTag) {
+// It's an error for someone to use a tag so long it fills the entire buffer,
+// with no room for a message, so we substitute a short tag instead.
+TEST(logging_splitters, LogdChunkSplitter_TooLongTag) {
   auto long_tag = std::string(5000, 'x');
-  auto logger_function = [](LogId, LogSeverity, const char*, const char*) {};
-  ASSERT_DEATH(
-      SplitByLogdChunks(MAIN, ERROR, long_tag.c_str(), nullptr, 0, "message", logger_function), "");
+  std::string message = "the message";
+  std::vector<std::string> expected = { message };
+  TestLogdChunkSplitter(long_tag, "", message, expected);
 }
 
 // We do handle excessively large file names correctly however.
diff --git a/logging_test.cpp b/logging_test.cpp
index feb43eb..b4519bc 100644
--- a/logging_test.cpp
+++ b/logging_test.cpp
@@ -14,6 +14,7 @@
  * limitations under the License.
  */
 
+#define LOG_TAG "logging_test_tag"
 #include "android-base/logging.h"
 
 #include <libgen.h>
@@ -28,6 +29,7 @@
 #include <thread>
 
 #include "android-base/file.h"
+#include "android-base/properties.h"
 #include "android-base/scopeguard.h"
 #include "android-base/stringprintf.h"
 #include "android-base/test_utils.h"
@@ -127,32 +129,32 @@ TEST(logging, DCHECK) {
 }
 
 
-#define CHECK_WOULD_LOG_DISABLED(severity)                                               \
-  static_assert(android::base::severity < android::base::FATAL, "Bad input");            \
-  for (size_t i = static_cast<size_t>(android::base::severity) + 1;                      \
+#define CHECK_WOULD_LOG_DISABLED(SEVERITY)                                               \
+  static_assert(android::base::SEVERITY < android::base::FATAL, "Bad input");            \
+  for (size_t i = static_cast<size_t>(android::base::SEVERITY) + 1;                      \
        i <= static_cast<size_t>(android::base::FATAL);                                   \
        ++i) {                                                                            \
     {                                                                                    \
       android::base::ScopedLogSeverity sls2(static_cast<android::base::LogSeverity>(i)); \
-      EXPECT_FALSE(WOULD_LOG(severity)) << i;                                            \
+      EXPECT_FALSE(WOULD_LOG(SEVERITY)) << i;                                            \
     }                                                                                    \
     {                                                                                    \
       android::base::ScopedLogSeverity sls2(static_cast<android::base::LogSeverity>(i)); \
-      EXPECT_FALSE(WOULD_LOG(::android::base::severity)) << i;                           \
+      EXPECT_FALSE(WOULD_LOG(::android::base::SEVERITY)) << i;                           \
     }                                                                                    \
   }                                                                                      \
 
-#define CHECK_WOULD_LOG_ENABLED(severity)                                                \
+#define CHECK_WOULD_LOG_ENABLED(SEVERITY)                                                \
   for (size_t i = static_cast<size_t>(android::base::VERBOSE);                           \
-       i <= static_cast<size_t>(android::base::severity);                                \
+       i <= static_cast<size_t>(android::base::SEVERITY);                                \
        ++i) {                                                                            \
     {                                                                                    \
       android::base::ScopedLogSeverity sls2(static_cast<android::base::LogSeverity>(i)); \
-      EXPECT_TRUE(WOULD_LOG(severity)) << i;                                             \
+      EXPECT_TRUE(WOULD_LOG(SEVERITY)) << i;                                             \
     }                                                                                    \
     {                                                                                    \
       android::base::ScopedLogSeverity sls2(static_cast<android::base::LogSeverity>(i)); \
-      EXPECT_TRUE(WOULD_LOG(::android::base::severity)) << i;                            \
+      EXPECT_TRUE(WOULD_LOG(::android::base::SEVERITY)) << i;                            \
     }                                                                                    \
   }                                                                                      \
 
@@ -207,16 +209,9 @@ TEST(logging, WOULD_LOG_VERBOSE_enabled) {
 #undef CHECK_WOULD_LOG_DISABLED
 #undef CHECK_WOULD_LOG_ENABLED
 
-
 #if !defined(_WIN32)
 static std::string make_log_pattern(const char* expected_tag, android::base::LogSeverity severity,
                                     const char* message) {
-  static const char log_characters[] = "VDIWEFF";
-  static_assert(arraysize(log_characters) - 1 == android::base::FATAL + 1,
-                "Mismatch in size of log_characters and values in LogSeverity");
-  char log_char = log_characters[severity];
-  std::string holder(__FILE__);
-
   // `message` can have a function name like "TestBody()". The parentheses should be escaped,
   // otherwise it will be interpreted as a capturing group when it is used as a regex.  Below
   // replaces either '(' or ')' to '\(' or '\)', respectively.
@@ -224,9 +219,11 @@ static std::string make_log_pattern(const char* expected_tag, android::base::Log
   std::string message_escaped = std::regex_replace(message, parentheses, R"(\$&)");
 
   const char* tag_pattern = expected_tag != nullptr ? expected_tag : ".+";
+  std::string holder(__FILE__);
   return android::base::StringPrintf(
-      R"(\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3} \s*\d+ \s*\d+ %c %s\s*: %s:\d+ %s)", log_char,
-      tag_pattern, basename(&holder[0]), message_escaped.c_str());
+      R"(\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3} \s*\d+ \s*\d+ %c %s\s*: %s:\d+ %s)",
+      android::base::kSeverityChars[severity], tag_pattern, basename(&holder[0]),
+      message_escaped.c_str());
 }
 #endif
 
@@ -255,38 +252,38 @@ static void CheckMessage(CapturedStderr& cap, android::base::LogSeverity severit
   return CheckMessage(output, severity, expected, expected_tag);
 }
 
-#define CHECK_LOG_STREAM_DISABLED(severity)                      \
+#define CHECK_LOG_STREAM_DISABLED(SEVERITY)                      \
   {                                                              \
     android::base::ScopedLogSeverity sls1(android::base::FATAL); \
     CapturedStderr cap1;                                         \
-    LOG_STREAM(severity) << "foo bar";                           \
+    LOG_STREAM(SEVERITY) << "foo bar";                           \
     cap1.Stop();                                                 \
     ASSERT_EQ("", cap1.str());                                   \
   }                                                              \
   {                                                              \
     android::base::ScopedLogSeverity sls1(android::base::FATAL); \
     CapturedStderr cap1;                                         \
-    LOG_STREAM(::android::base::severity) << "foo bar";          \
+    LOG_STREAM(::android::base::SEVERITY) << "foo bar";          \
     cap1.Stop();                                                 \
     ASSERT_EQ("", cap1.str());                                   \
   }
 
-#define CHECK_LOG_STREAM_ENABLED(severity) \
+#define CHECK_LOG_STREAM_ENABLED(SEVERITY) \
   { \
-    android::base::ScopedLogSeverity sls2(android::base::severity); \
+    android::base::ScopedLogSeverity sls2(android::base::SEVERITY); \
     CapturedStderr cap2; \
-    LOG_STREAM(severity) << "foobar"; \
-    CheckMessage(cap2, android::base::severity, "foobar"); \
+    LOG_STREAM(SEVERITY) << "foobar"; \
+    CheckMessage(cap2, android::base::SEVERITY, "foobar"); \
   } \
   { \
-    android::base::ScopedLogSeverity sls2(android::base::severity); \
+    android::base::ScopedLogSeverity sls2(android::base::SEVERITY); \
     CapturedStderr cap2; \
-    LOG_STREAM(::android::base::severity) << "foobar"; \
-    CheckMessage(cap2, android::base::severity, "foobar"); \
+    LOG_STREAM(::android::base::SEVERITY) << "foobar"; \
+    CheckMessage(cap2, android::base::SEVERITY, "foobar"); \
   } \
 
 TEST(logging, LOG_STREAM_FATAL_WITHOUT_ABORT_enabled) {
-  ASSERT_NO_FATAL_FAILURE(CHECK_LOG_STREAM_ENABLED(FATAL_WITHOUT_ABORT));
+  CHECK_LOG_STREAM_ENABLED(FATAL_WITHOUT_ABORT);
 }
 
 TEST(logging, LOG_STREAM_ERROR_disabled) {
@@ -294,7 +291,7 @@ TEST(logging, LOG_STREAM_ERROR_disabled) {
 }
 
 TEST(logging, LOG_STREAM_ERROR_enabled) {
-  ASSERT_NO_FATAL_FAILURE(CHECK_LOG_STREAM_ENABLED(ERROR));
+  CHECK_LOG_STREAM_ENABLED(ERROR);
 }
 
 TEST(logging, LOG_STREAM_WARNING_disabled) {
@@ -302,7 +299,7 @@ TEST(logging, LOG_STREAM_WARNING_disabled) {
 }
 
 TEST(logging, LOG_STREAM_WARNING_enabled) {
-  ASSERT_NO_FATAL_FAILURE(CHECK_LOG_STREAM_ENABLED(WARNING));
+  CHECK_LOG_STREAM_ENABLED(WARNING);
 }
 
 TEST(logging, LOG_STREAM_INFO_disabled) {
@@ -310,7 +307,7 @@ TEST(logging, LOG_STREAM_INFO_disabled) {
 }
 
 TEST(logging, LOG_STREAM_INFO_enabled) {
-  ASSERT_NO_FATAL_FAILURE(CHECK_LOG_STREAM_ENABLED(INFO));
+  CHECK_LOG_STREAM_ENABLED(INFO);
 }
 
 TEST(logging, LOG_STREAM_DEBUG_disabled) {
@@ -318,7 +315,7 @@ TEST(logging, LOG_STREAM_DEBUG_disabled) {
 }
 
 TEST(logging, LOG_STREAM_DEBUG_enabled) {
-  ASSERT_NO_FATAL_FAILURE(CHECK_LOG_STREAM_ENABLED(DEBUG));
+  CHECK_LOG_STREAM_ENABLED(DEBUG);
 }
 
 TEST(logging, LOG_STREAM_VERBOSE_disabled) {
@@ -326,41 +323,60 @@ TEST(logging, LOG_STREAM_VERBOSE_disabled) {
 }
 
 TEST(logging, LOG_STREAM_VERBOSE_enabled) {
-  ASSERT_NO_FATAL_FAILURE(CHECK_LOG_STREAM_ENABLED(VERBOSE));
+  CHECK_LOG_STREAM_ENABLED(VERBOSE);
 }
 
 #undef CHECK_LOG_STREAM_DISABLED
 #undef CHECK_LOG_STREAM_ENABLED
 
-#define CHECK_LOG_DISABLED(severity)                             \
+#define CHECK_LOG_DISABLED(SEVERITY)                             \
   {                                                              \
     android::base::ScopedLogSeverity sls1(android::base::FATAL); \
     CapturedStderr cap1;                                         \
-    LOG(severity) << "foo bar";                                  \
+    LOG(SEVERITY) << "foo bar";                                  \
     cap1.Stop();                                                 \
     ASSERT_EQ("", cap1.str());                                   \
   }                                                              \
   {                                                              \
     android::base::ScopedLogSeverity sls1(android::base::FATAL); \
     CapturedStderr cap1;                                         \
-    LOG(::android::base::severity) << "foo bar";                 \
+    LOG(::android::base::SEVERITY) << "foo bar";                 \
     cap1.Stop();                                                 \
     ASSERT_EQ("", cap1.str());                                   \
   }
 
-#define CHECK_LOG_ENABLED(severity) \
-  { \
-    android::base::ScopedLogSeverity sls2(android::base::severity); \
-    CapturedStderr cap2; \
-    LOG(severity) << "foobar"; \
-    CheckMessage(cap2, android::base::severity, "foobar"); \
-  } \
-  { \
-    android::base::ScopedLogSeverity sls2(android::base::severity); \
-    CapturedStderr cap2; \
-    LOG(::android::base::severity) << "foobar"; \
-    CheckMessage(cap2, android::base::severity, "foobar"); \
-  } \
+#if defined(__ANDROID__)
+#define CHECK_LOG_ENABLED_WITH_PROPERTY(SEVERITY)                              \
+  {                                                                            \
+    android::base::ScopedLogSeverity sls1(android::base::FATAL);               \
+    auto log_tag_property = std::string("log.tag.") + LOG_TAG;                 \
+    EXPECT_TRUE(android::base::SetProperty(log_tag_property,                   \
+        std::string(1,                                                         \
+                    android::base::kSeverityChars[android::base::SEVERITY]))); \
+    auto reset_tag_property_guard = android::base::make_scope_guard(           \
+        [=] { android::base::SetProperty(log_tag_property, ""); });            \
+    CapturedStderr cap2;                                                       \
+    LOG(SEVERITY) << "foobar";                                                 \
+    CheckMessage(cap2, android::base::SEVERITY, "foobar", LOG_TAG);            \
+  }
+#else
+#define CHECK_LOG_ENABLED_WITH_PROPERTY(severity)
+#endif
+
+#define CHECK_LOG_ENABLED(SEVERITY)                                 \
+  {                                                                 \
+    android::base::ScopedLogSeverity sls2(android::base::SEVERITY); \
+    CapturedStderr cap2;                                            \
+    LOG(SEVERITY) << "foobar";                                      \
+    CheckMessage(cap2, android::base::SEVERITY, "foobar");          \
+  }                                                                 \
+  {                                                                 \
+    android::base::ScopedLogSeverity sls2(android::base::SEVERITY); \
+    CapturedStderr cap2;                                            \
+    LOG(::android::base::SEVERITY) << "foobar";                     \
+    CheckMessage(cap2, android::base::SEVERITY, "foobar");          \
+  }                                                                 \
+  CHECK_LOG_ENABLED_WITH_PROPERTY(SEVERITY)
 
 TEST(logging, LOG_FATAL) {
   ASSERT_DEATH({SuppressAbortUI(); LOG(FATAL) << "foobar";}, "foobar");
@@ -368,7 +384,7 @@ TEST(logging, LOG_FATAL) {
 }
 
 TEST(logging, LOG_FATAL_WITHOUT_ABORT_enabled) {
-  ASSERT_NO_FATAL_FAILURE(CHECK_LOG_ENABLED(FATAL_WITHOUT_ABORT));
+  CHECK_LOG_ENABLED(FATAL_WITHOUT_ABORT);
 }
 
 TEST(logging, LOG_ERROR_disabled) {
@@ -376,7 +392,7 @@ TEST(logging, LOG_ERROR_disabled) {
 }
 
 TEST(logging, LOG_ERROR_enabled) {
-  ASSERT_NO_FATAL_FAILURE(CHECK_LOG_ENABLED(ERROR));
+  CHECK_LOG_ENABLED(ERROR);
 }
 
 TEST(logging, LOG_WARNING_disabled) {
@@ -384,7 +400,7 @@ TEST(logging, LOG_WARNING_disabled) {
 }
 
 TEST(logging, LOG_WARNING_enabled) {
-  ASSERT_NO_FATAL_FAILURE(CHECK_LOG_ENABLED(WARNING));
+  CHECK_LOG_ENABLED(WARNING);
 }
 
 TEST(logging, LOG_INFO_disabled) {
@@ -392,7 +408,7 @@ TEST(logging, LOG_INFO_disabled) {
 }
 
 TEST(logging, LOG_INFO_enabled) {
-  ASSERT_NO_FATAL_FAILURE(CHECK_LOG_ENABLED(INFO));
+  CHECK_LOG_ENABLED(INFO);
 }
 
 TEST(logging, LOG_DEBUG_disabled) {
@@ -400,7 +416,7 @@ TEST(logging, LOG_DEBUG_disabled) {
 }
 
 TEST(logging, LOG_DEBUG_enabled) {
-  ASSERT_NO_FATAL_FAILURE(CHECK_LOG_ENABLED(DEBUG));
+  CHECK_LOG_ENABLED(DEBUG);
 }
 
 TEST(logging, LOG_VERBOSE_disabled) {
@@ -408,11 +424,12 @@ TEST(logging, LOG_VERBOSE_disabled) {
 }
 
 TEST(logging, LOG_VERBOSE_enabled) {
-  ASSERT_NO_FATAL_FAILURE(CHECK_LOG_ENABLED(VERBOSE));
+  CHECK_LOG_ENABLED(VERBOSE);
 }
 
 #undef CHECK_LOG_DISABLED
 #undef CHECK_LOG_ENABLED
+#undef CHECK_LOG_ENABLED_WITH_PROPERTY
 
 TEST(logging, LOG_complex_param) {
 #define CHECK_LOG_COMBINATION(use_scoped_log_severity_info, use_logging_severity_info)         \
@@ -447,7 +464,7 @@ TEST(logging, LOG_does_not_clobber_errno) {
   LOG(INFO) << (errno = 67890);
   EXPECT_EQ(12345, errno) << "errno was not restored";
 
-  ASSERT_NO_FATAL_FAILURE(CheckMessage(cap, android::base::INFO, "67890"));
+  CheckMessage(cap, android::base::INFO, "67890");
 }
 
 TEST(logging, PLOG_does_not_clobber_errno) {
@@ -456,7 +473,7 @@ TEST(logging, PLOG_does_not_clobber_errno) {
   PLOG(INFO) << (errno = 67890);
   EXPECT_EQ(12345, errno) << "errno was not restored";
 
-  ASSERT_NO_FATAL_FAILURE(CheckMessage(cap, android::base::INFO, "67890"));
+  CheckMessage(cap, android::base::INFO, "67890");
 }
 
 TEST(logging, LOG_does_not_have_dangling_if) {
@@ -482,36 +499,36 @@ TEST(logging, LOG_does_not_have_dangling_if) {
   EXPECT_FALSE(flag) << "LOG macro probably has a dangling if with no else";
 }
 
-#define CHECK_PLOG_DISABLED(severity)                            \
+#define CHECK_PLOG_DISABLED(SEVERITY)                            \
   {                                                              \
     android::base::ScopedLogSeverity sls1(android::base::FATAL); \
     CapturedStderr cap1;                                         \
-    PLOG(severity) << "foo bar";                                 \
+    PLOG(SEVERITY) << "foo bar";                                 \
     cap1.Stop();                                                 \
     ASSERT_EQ("", cap1.str());                                   \
   }                                                              \
   {                                                              \
     android::base::ScopedLogSeverity sls1(android::base::FATAL); \
     CapturedStderr cap1;                                         \
-    PLOG(severity) << "foo bar";                                 \
+    PLOG(SEVERITY) << "foo bar";                                 \
     cap1.Stop();                                                 \
     ASSERT_EQ("", cap1.str());                                   \
   }
 
-#define CHECK_PLOG_ENABLED(severity) \
+#define CHECK_PLOG_ENABLED(SEVERITY) \
   { \
-    android::base::ScopedLogSeverity sls2(android::base::severity); \
+    android::base::ScopedLogSeverity sls2(android::base::SEVERITY); \
     CapturedStderr cap2; \
     errno = ENOENT; \
-    PLOG(severity) << "foobar"; \
-    CheckMessage(cap2, android::base::severity, "foobar: No such file or directory"); \
+    PLOG(SEVERITY) << "foobar"; \
+    CheckMessage(cap2, android::base::SEVERITY, "foobar: No such file or directory"); \
   } \
   { \
-    android::base::ScopedLogSeverity sls2(android::base::severity); \
+    android::base::ScopedLogSeverity sls2(android::base::SEVERITY); \
     CapturedStderr cap2; \
     errno = ENOENT; \
-    PLOG(severity) << "foobar"; \
-    CheckMessage(cap2, android::base::severity, "foobar: No such file or directory"); \
+    PLOG(SEVERITY) << "foobar"; \
+    CheckMessage(cap2, android::base::SEVERITY, "foobar: No such file or directory"); \
   } \
 
 TEST(logging, PLOG_FATAL) {
@@ -520,7 +537,7 @@ TEST(logging, PLOG_FATAL) {
 }
 
 TEST(logging, PLOG_FATAL_WITHOUT_ABORT_enabled) {
-  ASSERT_NO_FATAL_FAILURE(CHECK_PLOG_ENABLED(FATAL_WITHOUT_ABORT));
+  CHECK_PLOG_ENABLED(FATAL_WITHOUT_ABORT);
 }
 
 TEST(logging, PLOG_ERROR_disabled) {
@@ -528,7 +545,7 @@ TEST(logging, PLOG_ERROR_disabled) {
 }
 
 TEST(logging, PLOG_ERROR_enabled) {
-  ASSERT_NO_FATAL_FAILURE(CHECK_PLOG_ENABLED(ERROR));
+  CHECK_PLOG_ENABLED(ERROR);
 }
 
 TEST(logging, PLOG_WARNING_disabled) {
@@ -536,7 +553,7 @@ TEST(logging, PLOG_WARNING_disabled) {
 }
 
 TEST(logging, PLOG_WARNING_enabled) {
-  ASSERT_NO_FATAL_FAILURE(CHECK_PLOG_ENABLED(WARNING));
+  CHECK_PLOG_ENABLED(WARNING);
 }
 
 TEST(logging, PLOG_INFO_disabled) {
@@ -544,7 +561,7 @@ TEST(logging, PLOG_INFO_disabled) {
 }
 
 TEST(logging, PLOG_INFO_enabled) {
-  ASSERT_NO_FATAL_FAILURE(CHECK_PLOG_ENABLED(INFO));
+  CHECK_PLOG_ENABLED(INFO);
 }
 
 TEST(logging, PLOG_DEBUG_disabled) {
@@ -552,7 +569,7 @@ TEST(logging, PLOG_DEBUG_disabled) {
 }
 
 TEST(logging, PLOG_DEBUG_enabled) {
-  ASSERT_NO_FATAL_FAILURE(CHECK_PLOG_ENABLED(DEBUG));
+  CHECK_PLOG_ENABLED(DEBUG);
 }
 
 TEST(logging, PLOG_VERBOSE_disabled) {
@@ -560,7 +577,7 @@ TEST(logging, PLOG_VERBOSE_disabled) {
 }
 
 TEST(logging, PLOG_VERBOSE_enabled) {
-  ASSERT_NO_FATAL_FAILURE(CHECK_PLOG_ENABLED(VERBOSE));
+  CHECK_PLOG_ENABLED(VERBOSE);
 }
 
 #undef CHECK_PLOG_DISABLED
@@ -573,7 +590,7 @@ TEST(logging, UNIMPLEMENTED) {
   CapturedStderr cap;
   errno = ENOENT;
   UNIMPLEMENTED(ERROR);
-  ASSERT_NO_FATAL_FAILURE(CheckMessage(cap, android::base::ERROR, expected.c_str()));
+  CheckMessage(cap, android::base::ERROR, expected.c_str());
 }
 
 static void NoopAborter(const char* msg ATTRIBUTE_UNUSED) {
diff --git a/properties.cpp b/properties.cpp
index e217c9e..9fd44a8 100644
--- a/properties.cpp
+++ b/properties.cpp
@@ -60,9 +60,9 @@ struct prop_info {
 
 struct prop_info_cmp {
   using is_transparent = void;
-  bool operator()(const prop_info& lhs, const prop_info& rhs) { return lhs.key < rhs.key; }
-  bool operator()(std::string_view lhs, const prop_info& rhs) { return lhs < rhs.key; }
-  bool operator()(const prop_info& lhs, std::string_view rhs) { return lhs.key < rhs; }
+  bool operator()(const prop_info& lhs, const prop_info& rhs) const { return lhs.key < rhs.key; }
+  bool operator()(std::string_view lhs, const prop_info& rhs) const { return lhs < rhs.key; }
+  bool operator()(const prop_info& lhs, std::string_view rhs) const { return lhs.key < rhs; }
 };
 
 static auto& g_properties_lock = *new std::mutex;
diff --git a/properties_test.cpp b/properties_test.cpp
index 7c1aca5..898a0af 100644
--- a/properties_test.cpp
+++ b/properties_test.cpp
@@ -294,9 +294,10 @@ void SetAfter(const std::string& key, const std::string& value, std::chrono::mil
 
 TEST(properties, CachedProperty_WaitForChange) {
 #if defined(__BIONIC__)
-  unsigned long now =
-      std::chrono::system_clock::now().time_since_epoch() / std::chrono::milliseconds(1);
-  std::string key = android::base::StringPrintf("debug.libbase.CachedProperty_test_%lu", now);
+  size_t now = static_cast<size_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
+                                       std::chrono::system_clock::now().time_since_epoch())
+                                       .count());
+  std::string key = android::base::StringPrintf("debug.libbase.CachedProperty_test_%zu", now);
   android::base::CachedProperty cached_property(key);
 
   // If the property doesn't exist yet, Get returns the empty string.
@@ -324,9 +325,10 @@ TEST(properties, CachedProperty_WaitForChange) {
 
 TEST(properties, CachedBoolProperty) {
 #if defined(__BIONIC__)
-  unsigned long now =
-      std::chrono::system_clock::now().time_since_epoch() / std::chrono::milliseconds(1);
-  std::string key = android::base::StringPrintf("debug.libbase.CachedBoolProperty_test_%lu", now);
+  size_t now = static_cast<size_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
+                                       std::chrono::system_clock::now().time_since_epoch())
+                                       .count());
+  std::string key = android::base::StringPrintf("debug.libbase.CachedBoolProperty_test_%zu", now);
   android::base::CachedBoolProperty cached_bool_property(key);
 
   // Not set yet.
diff --git a/stringify_test.cpp b/stringify_test.cpp
new file mode 100644
index 0000000..92bac5e
--- /dev/null
+++ b/stringify_test.cpp
@@ -0,0 +1,35 @@
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
+#include "android-base/stringify.h"
+
+#include <gtest/gtest.h>
+
+TEST(StringifyTest, quote) {
+  ASSERT_EQ("EINVAL", QUOTE(EINVAL));
+}
+
+TEST(StringifyTest, quote_commas) {
+  ASSERT_EQ("EINVAL,EINTR", QUOTE(EINVAL,EINTR));
+}
+
+TEST(StringifyTest, stringify) {
+  ASSERT_EQ("22", STRINGIFY(EINVAL));
+}
+
+TEST(StringifyTest, stringify_commas) {
+  ASSERT_EQ("22,4", STRINGIFY(EINVAL,EINTR));
+}
\ No newline at end of file
```

