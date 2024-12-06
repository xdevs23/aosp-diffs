```diff
diff --git a/include/android-base/errors.h b/include/android-base/errors.h
index ab584d4..cca4e88 100644
--- a/include/android-base/errors.h
+++ b/include/android-base/errors.h
@@ -45,7 +45,7 @@ std::string SystemErrorCodeToString(int error_code);
 }  // namespace android
 
 // Convenient macros for evaluating a statement, checking if the result is error, and returning it
-// to the caller.
+// to the caller. If it is ok then the inner value is unwrapped (if applicable) and returned.
 //
 // Usage with Result<T>:
 //
@@ -72,44 +72,49 @@ std::string SystemErrorCodeToString(int error_code);
 // If implicit conversion compilation errors occur involving a value type with a templated
 // forwarding ref ctor, compilation with cpp20 or explicitly converting to the desired
 // return type is required.
-#define OR_RETURN(expr)                                                                  \
-  ({                                                                                     \
-    decltype(expr)&& __or_return_expr = (expr);                                          \
-    typedef android::base::OkOrFail<std::remove_reference_t<decltype(__or_return_expr)>> \
-        ok_or_fail;                                                                      \
-    if (!ok_or_fail::IsOk(__or_return_expr)) {                                           \
-      return ok_or_fail::Fail(std::move(__or_return_expr));                              \
-    }                                                                                    \
-    ok_or_fail::Unwrap(std::move(__or_return_expr));                                     \
-  })
+#define OR_RETURN(expr) \
+  UNWRAP_OR_DO(__or_return_expr, expr, { return ok_or_fail::Fail(std::move(__or_return_expr)); })
 
 // Same as OR_RETURN, but aborts if expr is a failure.
 #if defined(__BIONIC__)
-#define OR_FATAL(expr)                                                                  \
-  ({                                                                                    \
-    decltype(expr)&& __or_fatal_expr = (expr);                                          \
-    typedef android::base::OkOrFail<std::remove_reference_t<decltype(__or_fatal_expr)>> \
-        ok_or_fail;                                                                     \
-    if (!ok_or_fail::IsOk(__or_fatal_expr)) {                                           \
-      __assert(__FILE__, __LINE__, ok_or_fail::ErrorMessage(__or_fatal_expr).c_str());  \
-    }                                                                                   \
-    ok_or_fail::Unwrap(std::move(__or_fatal_expr));                                     \
+#define OR_FATAL(expr)                                                               \
+  UNWRAP_OR_DO(__or_fatal_expr, expr, {                                              \
+    __assert(__FILE__, __LINE__, ok_or_fail::ErrorMessage(__or_fatal_expr).c_str()); \
   })
 #else
-#define OR_FATAL(expr)                                                                  \
-  ({                                                                                    \
-    decltype(expr)&& __or_fatal_expr = (expr);                                          \
-    typedef android::base::OkOrFail<std::remove_reference_t<decltype(__or_fatal_expr)>> \
-        ok_or_fail;                                                                     \
-    if (!ok_or_fail::IsOk(__or_fatal_expr)) {                                           \
-      fprintf(stderr, "%s:%d: assertion \"%s\" failed", __FILE__, __LINE__,             \
-              ok_or_fail::ErrorMessage(__or_fatal_expr).c_str());                       \
-      abort();                                                                          \
-    }                                                                                   \
-    ok_or_fail::Unwrap(std::move(__or_fatal_expr));                                     \
+#define OR_FATAL(expr)                                                    \
+  UNWRAP_OR_DO(__or_fatal_expr, expr, {                                   \
+    fprintf(stderr, "%s:%d: assertion \"%s\" failed", __FILE__, __LINE__, \
+            ok_or_fail::ErrorMessage(__or_fatal_expr).c_str());           \
+    abort();                                                              \
   })
 #endif
 
+// Variant for use in gtests, which aborts the test function with an assertion failure on error.
+// This is akin to ASSERT_OK_AND_ASSIGN for absl::Status, except the assignment is external. It
+// assumes the user depends on libgmock and includes gtest/gtest.h.
+#define OR_ASSERT_FAIL(expr)                                             \
+  UNWRAP_OR_DO(__or_assert_expr, expr, {                                 \
+    FAIL() << "Value of: " << #expr << "\n"                              \
+           << "  Actual: " << __or_assert_expr.error().message() << "\n" \
+           << "Expected: is ok\n";                                       \
+  })
+
+// Generic macro to execute any statement(s) on error. Execution should never reach the end of them.
+// result_var is assigned expr and is only visible to on_error_stmts.
+#define UNWRAP_OR_DO(result_var, expr, on_error_stmts)                                         \
+  ({                                                                                           \
+    decltype(expr)&& result_var = (expr);                                                      \
+    typedef android::base::OkOrFail<std::remove_reference_t<decltype(result_var)>> ok_or_fail; \
+    if (!ok_or_fail::IsOk(result_var)) {                                                       \
+      {                                                                                        \
+        on_error_stmts;                                                                        \
+      }                                                                                        \
+      __builtin_unreachable();                                                                 \
+    }                                                                                          \
+    ok_or_fail::Unwrap(std::move(result_var));                                                 \
+  })
+
 namespace android {
 namespace base {
 
diff --git a/include/android-base/logging.h b/include/android-base/logging.h
index 7ed0478..42b2538 100644
--- a/include/android-base/logging.h
+++ b/include/android-base/logging.h
@@ -212,10 +212,7 @@ struct LogAbortAfterFullExpr {
 // Get an ostream that can be used for logging at the given severity and to the default
 // destination.
 //
-// Notes:
-// 1) This will not check whether the severity is high enough. One should use WOULD_LOG to filter
-//    usage manually.
-// 2) This does not save and restore errno.
+// Note that this does not save and restore errno.
 #define LOG_STREAM(severity)                                                                    \
   ::android::base::LogMessage(__FILE__, __LINE__, SEVERITY_LAMBDA(severity), _LOG_TAG_INTERNAL, \
                               -1)                                                               \
@@ -227,6 +224,25 @@ struct LogAbortAfterFullExpr {
 //     LOG(FATAL) << "We didn't expect to reach here";
 #define LOG(severity) LOGGING_PREAMBLE(severity) && LOG_STREAM(severity)
 
+// Conditionally logs a message based on a specified severity level and a boolean condition.
+// Logs to logcat on Android, or to stderr on host. See also LOG(severity) above.
+//
+// The message will only be logged if:
+// 1. The provided 'cond' evaluates to true.
+// 2. The 'severity' level is enabled for the current log tag (as determined by the logging
+// configuration).
+//
+// Usage:
+//
+//   LOG_IF(INFO, some_condition) << "This message will be logged if 'some_condition' is true" <<
+//       " and INFO level is enabled.";
+//
+// @param severity The severity level of the log message (e.g., VERBOSE, DEBUG, INFO, WARNING,
+//      ERROR, FATAL).
+// @param cond The boolean condition that determines whether to log the message.
+#define LOG_IF(severity, cond) \
+  if (UNLIKELY(cond) && WOULD_LOG(severity)) LOG(severity)
+
 // Checks if we want to log something, and sets up appropriate RAII objects if
 // so.
 // Note: DO NOT USE DIRECTLY. This is an implementation detail.
diff --git a/include/android-base/result.h b/include/android-base/result.h
index c6cc9fd..6864a0a 100644
--- a/include/android-base/result.h
+++ b/include/android-base/result.h
@@ -467,9 +467,9 @@ public:
   static const std::string& ErrorMessage(const V& val) { return val.error().message(); }
 };
 
-// Macros for testing the results of functions that return android::base::Result.
-// These also work with base::android::expected.
-// For advanced matchers and customized error messages, see result-gtest.h.
+// Macros for testing the results of functions that return android::base::Result. These also work
+// with base::android::expected. They assume the user depends on libgmock and includes
+// gtest/gtest.h. For advanced matchers and customized error messages, see result-gmock.h.
 
 #define ASSERT_RESULT_OK(stmt)                            \
   if (const auto& tmp = (stmt); !tmp.ok())                \
diff --git a/properties.cpp b/properties.cpp
index a20db54..1970eb1 100644
--- a/properties.cpp
+++ b/properties.cpp
@@ -17,9 +17,7 @@
 #include "android-base/properties.h"
 
 #if defined(__BIONIC__)
-#define _REALLY_INCLUDE_SYS__SYSTEM_PROPERTIES_H_
 #include <sys/system_properties.h>
-#include <sys/_system_properties.h>
 #endif
 
 #include <algorithm>
diff --git a/result_test.cpp b/result_test.cpp
index b2cd303..abd34c2 100644
--- a/result_test.cpp
+++ b/result_test.cpp
@@ -246,6 +246,26 @@ TEST(result, constructor_forwarding) {
   EXPECT_EQ("aaaaa", *result);
 }
 
+TEST(result, unwrap_or_do) {
+  bool v = UNWRAP_OR_DO(res, Result<bool>(false), FAIL() << "Should not be reached");
+  EXPECT_FALSE(v);
+
+  []() -> void {
+    bool v = UNWRAP_OR_DO(res, Result<bool>(ResultError("foo", 17)), {
+      EXPECT_EQ(res.error().message(), "foo");
+      EXPECT_EQ(res.error().code(), 17);
+      return;
+    });
+    FAIL() << "Should not be reached";
+  }();
+}
+
+TEST(result, unwrap_or_assert_fail) {
+  bool s = OR_ASSERT_FAIL(Result<bool>(true));
+  EXPECT_TRUE(s);
+  // NB: There's no (stable) way to test that an assertion failed, so cannot test the error case.
+}
+
 TEST(result, unwrap_or_return) {
   auto f = [](bool success) -> Result<size_t, CustomError> {
     return OR_RETURN(success_or_fail(success)).size();
```

