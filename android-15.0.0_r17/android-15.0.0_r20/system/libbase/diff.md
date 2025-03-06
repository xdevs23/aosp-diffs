```diff
diff --git a/Android.bp b/Android.bp
index 6663bd9..0679889 100644
--- a/Android.bp
+++ b/Android.bp
@@ -324,3 +324,9 @@ cc_fuzz {
         componentid: 128577,
     },
 }
+
+dirgroup {
+    name: "trusty_dirgroup_system_libbase",
+    dirs: ["."],
+    visibility: ["//trusty/vendor/google/aosp/scripts"],
+}
diff --git a/include/android-base/format.h b/include/android-base/format.h
index 6db7b50..0650513 100644
--- a/include/android-base/format.h
+++ b/include/android-base/format.h
@@ -25,6 +25,7 @@
 #include <fmt/core.h>
 #include <fmt/format.h>
 #include <fmt/printf.h>
+#include <fmt/ranges.h>
 
 #ifndef _WIN32
 #include <fmt/ostream.h>
diff --git a/include/android-base/properties.h b/include/android-base/properties.h
index 1760ac7..067fbf4 100644
--- a/include/android-base/properties.h
+++ b/include/android-base/properties.h
@@ -170,4 +170,10 @@ static inline int HwTimeoutMultiplier() {
 extern "C" int __system_property_set(const char*, const char*);
 /** Implementation detail. */
 extern "C" int __system_property_get(const char*, char*);
+/** Implementation detail. */
+extern "C" const prop_info* __system_property_find(const char*);
+/** Implementation detail. */
+extern "C" void __system_property_read_callback(const prop_info*,
+                                                void (*)(void*, const char*, const char*, uint32_t),
+                                                void*);
 #endif
diff --git a/include/android-base/scopeguard.h b/include/android-base/scopeguard.h
index 8293b2c..d971d39 100644
--- a/include/android-base/scopeguard.h
+++ b/include/android-base/scopeguard.h
@@ -26,18 +26,19 @@ namespace base {
 template <typename F>
 class ScopeGuard {
  public:
-  constexpr ScopeGuard(F&& f) : f_(std::forward<F>(f)), active_(true) {}
+  constexpr ScopeGuard(F f) : f_(std::move(f)), active_(true) {}
 
   constexpr ScopeGuard(ScopeGuard&& that) noexcept : f_(std::move(that.f_)), active_(that.active_) {
     that.active_ = false;
   }
 
   template <typename Functor>
-  constexpr ScopeGuard(ScopeGuard<Functor>&& that) : f_(std::move(that.f_)), active_(that.active_) {
+  constexpr ScopeGuard(ScopeGuard<Functor>&& that) noexcept
+      : f_(std::move(that.f_)), active_(that.active_) {
     that.active_ = false;
   }
 
-  ~ScopeGuard() {
+  ~ScopeGuard() noexcept(noexcept(f_())) {
     if (active_) f_();
   }
 
@@ -46,9 +47,9 @@ class ScopeGuard {
   void operator=(const ScopeGuard&) = delete;
   void operator=(ScopeGuard&& that) = delete;
 
-  void Disable() { active_ = false; }
+  void Disable() noexcept { active_ = false; }
 
-  constexpr bool active() const { return active_; }
+  constexpr bool active() const noexcept { return active_; }
 
  private:
   template <typename Functor>
@@ -59,8 +60,8 @@ class ScopeGuard {
 };
 
 template <typename F>
-ScopeGuard<F> make_scope_guard(F&& f) {
-  return ScopeGuard<F>(std::forward<F>(f));
+auto make_scope_guard(F&& f) {
+  return ScopeGuard<std::remove_reference_t<F>>(std::forward<F>(f));
 }
 
 }  // namespace base
diff --git a/include/android-base/silent_death_test.h b/include/android-base/silent_death_test.h
index 261fa74..8151b42 100644
--- a/include/android-base/silent_death_test.h
+++ b/include/android-base/silent_death_test.h
@@ -98,22 +98,28 @@
 class ScopedSilentDeath {
  public:
   ScopedSilentDeath() {
+#if !defined(_WIN32)
     for (int signo : SUPPRESSED_SIGNALS) {
       struct sigaction64 action = {.sa_handler = SIG_DFL};
       sigaction64(signo, &action, &previous_);
     }
+#endif
   }
 
   ~ScopedSilentDeath() {
+#if !defined(_WIN32)
     for (int signo : SUPPRESSED_SIGNALS) {
       sigaction64(signo, &previous_, nullptr);
     }
+#endif
   }
 
  private:
+#if !defined(_WIN32)
   static constexpr std::array<int, 4> SUPPRESSED_SIGNALS = {SIGABRT, SIGBUS, SIGSEGV, SIGSYS};
 
   struct sigaction64 previous_;
+#endif
 };
 
 class SilentDeathTest : public testing::Test {
diff --git a/include/android-base/strings.h b/include/android-base/strings.h
index 9557fad..db13045 100644
--- a/include/android-base/strings.h
+++ b/include/android-base/strings.h
@@ -18,10 +18,14 @@
 
 #include <ctype.h>
 
+#include <iterator>
+#include <numeric>
+#include <set>
 #include <sstream>
 #include <string>
 #include <string_view>
 #include <type_traits>
+#include <unordered_set>
 #include <utility>
 #include <vector>
 
@@ -95,24 +99,78 @@ extern template std::string Trim(std::string_view&&);
 
 // Joins a container of things into a single string, using the given separator.
 template <typename ContainerT, typename SeparatorT>
-std::string Join(const ContainerT& things, SeparatorT separator) {
+std::string Join(ContainerT&& things, SeparatorT separator) {
+  using ElementType = typename std::remove_reference_t<ContainerT>::value_type;
+
   if (things.empty()) {
-    return "";
+    return {};
+  } else if (things.size() == 1) {
+    // Nothing to do! Return the first element if it's already a string-like type, otherwise
+    // fallthrough to the slower format-conversion case at the bottom of this function.
+
+    if constexpr (std::is_convertible_v<ElementType, std::string>) {
+      return *things.begin();
+    } else if constexpr (std::is_constructible_v<std::string, ElementType>) {
+      // std::string_view is not implicitly convertible to std::string so do it explicitly, making
+      // a copy in this case.
+      return std::string(*things.begin());
+    }
   }
 
-  std::ostringstream result;
-  result << *things.begin();
-  for (auto it = std::next(things.begin()); it != things.end(); ++it) {
-    result << separator << *it;
+  if constexpr (std::is_convertible_v<ElementType, std::string_view>) {
+    // String-like types are what the vast majority of callers use.
+    // Use a much faster implementation for these types.
+
+    // char separator types need special handling because they cannot be converted to
+    // std::string_view to determine their size, and they require a special std::string::append
+    // invocation below.
+    constexpr bool sepIsChar = std::is_same_v<std::remove_cv_t<SeparatorT>, char>;
+    std::string_view::size_type sepSize;
+    if constexpr (sepIsChar) sepSize = 1;
+    else                     sepSize = std::string_view(separator).size();
+
+    const std::string_view::size_type total = std::accumulate(
+        std::next(things.begin()), things.end(), std::string_view(*things.begin()).size(),
+        [&sepSize](std::string_view::size_type sum, std::string_view sv) {
+          return sum + sepSize + sv.size();
+        }
+    );
+
+    std::string result;
+    result.reserve(total);  // allocate once
+    result.append(*things.begin());
+    for(auto it = std::next(things.begin()); it != things.end(); ++it) {
+      if constexpr (sepIsChar) result.append(1, separator).append(*it);
+      else                     result.append(separator).append(*it);
+    }
+    return result;
+
+  } else {
+    // Some callers depend on the conversion performed by std::ostream:operator<< to get string
+    // representations from non-string types.
+
+    std::ostringstream result;
+    result << *things.begin();
+    for (auto it = std::next(things.begin()); it != things.end(); ++it) {
+      result << separator << *it;
+    }
+    return result.str();
   }
-  return result.str();
 }
 
-// We instantiate the common cases in strings.cpp.
+// These cases were measured either to be used during build by more than one binary, or during
+// runtime as a significant portion of total calls.
+// Instantiate them in strings.cpp to aid compile time and binary size.
+extern template std::string Join(std::vector<std::string>&, char);
+extern template std::string Join(std::vector<std::string>&, const char*);
+extern template std::string Join(std::vector<std::string>&&, const char*);
 extern template std::string Join(const std::vector<std::string>&, char);
-extern template std::string Join(const std::vector<const char*>&, char);
-extern template std::string Join(const std::vector<std::string>&, const std::string&);
-extern template std::string Join(const std::vector<const char*>&, const std::string&);
+extern template std::string Join(const std::vector<std::string>&, const char*);
+extern template std::string Join(const std::vector<std::string>&&, const char*);
+extern template std::string Join(std::set<std::string>&, const char*);
+extern template std::string Join(const std::set<std::string>&, char);
+extern template std::string Join(const std::set<std::string>&, const char*);
+extern template std::string Join(const std::unordered_set<std::string>&, const char*);
 
 // Tests whether 's' starts with 'prefix'.
 bool StartsWith(std::string_view s, std::string_view prefix);
diff --git a/logging_splitters_test.cpp b/logging_splitters_test.cpp
index 248b6a1..04e9625 100644
--- a/logging_splitters_test.cpp
+++ b/logging_splitters_test.cpp
@@ -19,9 +19,12 @@
 #include <string>
 #include <vector>
 
+#include <android-base/silent_death_test.h>
 #include <android-base/strings.h>
 #include <gtest/gtest.h>
 
+using logging_splitters_DeathTest = SilentDeathTest;
+
 namespace android {
 namespace base {
 
@@ -234,7 +237,7 @@ TEST(logging_splitters, LogdChunkSplitter_WithFile) {
 // We set max_size based off of tag, so if it's too large, the buffer will be sized wrong.
 // We could recover from this, but it's certainly an error for someone to attempt to use a tag this
 // large, so we abort instead.
-TEST(logging_splitters, LogdChunkSplitter_TooLongTag) {
+TEST_F(logging_splitters_DeathTest, LogdChunkSplitter_TooLongTag) {
   auto long_tag = std::string(5000, 'x');
   auto logger_function = [](LogId, LogSeverity, const char*, const char*) {};
   ASSERT_DEATH(
diff --git a/process.cpp b/process.cpp
index b8cabf6..09a93ff 100644
--- a/process.cpp
+++ b/process.cpp
@@ -16,6 +16,8 @@
 
 #include "android-base/process.h"
 
+#include <stdlib.h>
+
 namespace android {
 namespace base {
 
diff --git a/properties.cpp b/properties.cpp
index 1970eb1..e217c9e 100644
--- a/properties.cpp
+++ b/properties.cpp
@@ -23,45 +23,97 @@
 #include <algorithm>
 #include <chrono>
 #include <limits>
-#include <map>
+#include <set>
 #include <string>
 
 #include <android-base/parsebool.h>
 #include <android-base/parseint.h>
 #include <android-base/strings.h>
+#include <android-base/thread_annotations.h>
 
 #if !defined(__BIONIC__)
 
+// Here lies a rudimentary implementation of system properties for non-Bionic
+// platforms. We are using weak symbols here because we want to allow
+// downstream users of libbase to override with their own implementation.
+// For example, on Ravenwood (host-side testing for platform development)
+// we'd love to be able to fully control system properties exposed to tests,
+// so we reimplement the entire system properties API there.
+
+#if defined(__linux__)
+// Weak symbols are not supported on Windows, and to prevent unnecessary
+// complications, we strictly limit the use of weak symbols to Linux.
+#define SYSPROP_WEAK __attribute__((weak))
+#else
+#define SYSPROP_WEAK
+#endif
+
 #define PROP_VALUE_MAX 92
 
-static std::map<std::string, std::string>& g_properties = *new std::map<std::string, std::string>;
+struct prop_info {
+  std::string key;
+  mutable std::string value;
+  mutable uint32_t serial;
+
+  prop_info(const char* key, const char* value) : key(key), value(value), serial(0) {}
+};
+
+struct prop_info_cmp {
+  using is_transparent = void;
+  bool operator()(const prop_info& lhs, const prop_info& rhs) { return lhs.key < rhs.key; }
+  bool operator()(std::string_view lhs, const prop_info& rhs) { return lhs < rhs.key; }
+  bool operator()(const prop_info& lhs, std::string_view rhs) { return lhs.key < rhs; }
+};
+
+static auto& g_properties_lock = *new std::mutex;
+static auto& g_properties GUARDED_BY(g_properties_lock) = *new std::set<prop_info, prop_info_cmp>;
 
-int __system_property_set(const char* key, const char* value) {
+SYSPROP_WEAK int __system_property_set(const char* key, const char* value) {
   if (key == nullptr || *key == '\0') return -1;
   if (value == nullptr) value = "";
-
   bool read_only = !strncmp(key, "ro.", 3);
-  if (read_only) {
-    const auto [it, success] = g_properties.insert({key, value});
-    return success ? 0 : -1;
+  if (!read_only && strlen(value) >= PROP_VALUE_MAX) return -1;
+
+  std::lock_guard lock(g_properties_lock);
+  auto [it, success] = g_properties.emplace(key, value);
+  if (read_only) return success ? 0 : -1;
+  if (!success) {
+    it->value = value;
+    ++it->serial;
   }
-
-  if (strlen(value) >= 92) return -1;
-  g_properties[key] = value;
   return 0;
 }
 
-int __system_property_get(const char* key, char* value) {
+SYSPROP_WEAK int __system_property_get(const char* key, char* value) {
+  std::lock_guard lock(g_properties_lock);
   auto it = g_properties.find(key);
   if (it == g_properties.end()) {
     *value = '\0';
     return 0;
   }
-  snprintf(value, PROP_VALUE_MAX, "%s", it->second.c_str());
+  snprintf(value, PROP_VALUE_MAX, "%s", it->value.c_str());
   return strlen(value);
 }
 
-#endif
+SYSPROP_WEAK const prop_info* __system_property_find(const char* key) {
+  std::lock_guard lock(g_properties_lock);
+  auto it = g_properties.find(key);
+  if (it == g_properties.end()) {
+    return nullptr;
+  } else {
+    return &*it;
+  }
+}
+
+SYSPROP_WEAK void __system_property_read_callback(const prop_info* pi,
+                                                  void (*callback)(void*, const char*, const char*,
+                                                                   uint32_t),
+                                                  void* cookie) {
+  std::lock_guard lock(g_properties_lock);
+  callback(cookie, pi->key.c_str(), pi->value.c_str(), pi->serial);
+}
+
+#endif  // __BIONIC__
 
 namespace android {
 namespace base {
@@ -106,22 +158,16 @@ template uint64_t GetUintProperty(const std::string&, uint64_t, uint64_t);
 
 std::string GetProperty(const std::string& key, const std::string& default_value) {
   std::string property_value;
-#if defined(__BIONIC__)
   const prop_info* pi = __system_property_find(key.c_str());
   if (pi == nullptr) return default_value;
 
-  __system_property_read_callback(pi,
-                                  [](void* cookie, const char*, const char* value, unsigned) {
-                                    auto property_value = reinterpret_cast<std::string*>(cookie);
-                                    *property_value = value;
-                                  },
-                                  &property_value);
-#else
-  // TODO: implement host __system_property_find()/__system_property_read_callback()?
-  auto it = g_properties.find(key);
-  if (it == g_properties.end()) return default_value;
-  property_value = it->second;
-#endif
+  __system_property_read_callback(
+      pi,
+      [](void* cookie, const char*, const char* value, unsigned) {
+        auto property_value = reinterpret_cast<std::string*>(cookie);
+        *property_value = value;
+      },
+      &property_value);
   // If the property exists but is empty, also return the default value.
   // Since we can't remove system properties, "empty" is traditionally
   // the same as "missing" (this was true for cutils' property_get).
diff --git a/result_test.cpp b/result_test.cpp
index abd34c2..6934dea 100644
--- a/result_test.cpp
+++ b/result_test.cpp
@@ -251,7 +251,7 @@ TEST(result, unwrap_or_do) {
   EXPECT_FALSE(v);
 
   []() -> void {
-    bool v = UNWRAP_OR_DO(res, Result<bool>(ResultError("foo", 17)), {
+    UNWRAP_OR_DO(res, Result<bool>(ResultError("foo", 17)), {
       EXPECT_EQ(res.error().message(), "foo");
       EXPECT_EQ(res.error().code(), 17);
       return;
diff --git a/strings.cpp b/strings.cpp
index 5ff2a52..a776d22 100644
--- a/strings.cpp
+++ b/strings.cpp
@@ -69,11 +69,6 @@ std::vector<std::string> Tokenize(const std::string& s, const std::string& delim
   return result;
 }
 
-[[deprecated("Retained only for binary compatibility (symbol name)")]]
-std::string Trim(const std::string& s) {
-  return Trim(std::string_view(s));
-}
-
 template std::string Trim(const char*&);
 template std::string Trim(const char*&&);
 template std::string Trim(const std::string&);
@@ -81,19 +76,27 @@ template std::string Trim(const std::string&&);
 template std::string Trim(std::string_view&);
 template std::string Trim(std::string_view&&);
 
-// These cases are probably the norm, so we mark them extern in the header to
-// aid compile time and binary size.
+// These cases were measured either to be used during build by more than one binary, or during
+// runtime as a significant portion of total calls.
+// Instantiate them to aid compile time and binary size.
+template std::string Join(std::vector<std::string>&, char);
+template std::string Join(std::vector<std::string>&, const char*);
+template std::string Join(std::vector<std::string>&&, const char*);
 template std::string Join(const std::vector<std::string>&, char);
-template std::string Join(const std::vector<const char*>&, char);
-template std::string Join(const std::vector<std::string>&, const std::string&);
-template std::string Join(const std::vector<const char*>&, const std::string&);
+template std::string Join(const std::vector<std::string>&, const char*);
+template std::string Join(const std::vector<std::string>&&, const char*);
+template std::string Join(std::set<std::string>&, const char*);
+template std::string Join(const std::set<std::string>&, char);
+template std::string Join(const std::set<std::string>&, const char*);
+template std::string Join(const std::unordered_set<std::string>&, const char*);
+
 
 bool StartsWith(std::string_view s, std::string_view prefix) {
-  return s.substr(0, prefix.size()) == prefix;
+  return s.starts_with(prefix);
 }
 
 bool StartsWith(std::string_view s, char prefix) {
-  return !s.empty() && s.front() == prefix;
+  return s.starts_with(prefix);
 }
 
 bool StartsWithIgnoreCase(std::string_view s, std::string_view prefix) {
@@ -101,11 +104,11 @@ bool StartsWithIgnoreCase(std::string_view s, std::string_view prefix) {
 }
 
 bool EndsWith(std::string_view s, std::string_view suffix) {
-  return s.size() >= suffix.size() && s.substr(s.size() - suffix.size(), suffix.size()) == suffix;
+  return s.ends_with(suffix);
 }
 
 bool EndsWith(std::string_view s, char suffix) {
-  return !s.empty() && s.back() == suffix;
+  return s.ends_with(suffix);
 }
 
 bool EndsWithIgnoreCase(std::string_view s, std::string_view suffix) {
diff --git a/strings_test.cpp b/strings_test.cpp
index f92e39a..9348b60 100644
--- a/strings_test.cpp
+++ b/strings_test.cpp
@@ -193,6 +193,10 @@ TEST(strings, join_separator_in_vector) {
   ASSERT_EQ(",,,", android::base::Join(list, ','));
 }
 
+TEST(strings, join_single_int) {
+  ASSERT_EQ("42", android::base::Join(std::vector{42}, ','));
+}
+
 TEST(strings, join_simple_ints) {
   std::set<int> list = {1, 2, 3};
   ASSERT_EQ("1,2,3", android::base::Join(list, ','));
```

