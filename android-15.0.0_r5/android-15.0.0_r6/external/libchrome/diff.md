```diff
diff --git a/Android.bp b/Android.bp
index 340a194ac..fab2dbe4a 100644
--- a/Android.bp
+++ b/Android.bp
@@ -458,6 +458,7 @@ filegroup {
         "base/timer/hi_res_timer_manager.h",
         "base/timer/mock_timer.h",
         "base/timer/timer.h",
+        "base/token.h",
         "base/trace_event/common/trace_event_common.h",
         "base/trace_event/heap_profiler.h",
         "base/trace_event/trace_event.h",
@@ -736,6 +737,7 @@ libchromeCommonSrc = [
     "base/time/time_override.cc",
     "base/timer/elapsed_timer.cc",
     "base/timer/timer.cc",
+    "base/token.cc",
     "base/unguessable_token.cc",
     "base/value_iterators.cc",
     "base/values.cc",
@@ -882,6 +884,7 @@ cc_library {
         "//device/google/bertha:__subpackages__",
         "//device/google/cheets2/camera/v3",
         "//external/avb",
+        "//external/gsc-utils:__subpackages__",
         "//external/libbrillo",
         "//external/libpalmrejection",
         "//external/puffin",
@@ -891,6 +894,7 @@ cc_library {
         "//frameworks/base/services/core/jni",
         "//frameworks/native/libs/vr/libpdx_default_transport",
         "//frameworks/native/services/inputflinger:__subpackages__",
+        "//hardware/libhardware/modules/camera/3_4",
         "//hardware/interfaces/keymaster/4.0/vts/performance",
         "//hardware/interfaces/security/keymint/aidl/vts/performance",
         "//hardware/nxp/secure_element/snxxx:__subpackages__",
diff --git a/base/token.cc b/base/token.cc
new file mode 100644
index 000000000..e7ad89671
--- /dev/null
+++ b/base/token.cc
@@ -0,0 +1,28 @@
+// Copyright 2018 The Chromium Authors. All rights reserved.
+// Use of this source code is governed by a BSD-style license that can be
+// found in the LICENSE file.
+
+#include "base/token.h"
+
+#include <inttypes.h>
+
+#include "base/rand_util.h"
+#include "base/strings/stringprintf.h"
+
+namespace base {
+
+// static
+Token Token::CreateRandom() {
+  Token token;
+
+  // Use base::RandBytes instead of crypto::RandBytes, because crypto calls the
+  // base version directly, and to prevent the dependency from base/ to crypto/.
+  base::RandBytes(&token, sizeof(token));
+  return token;
+}
+
+std::string Token::ToString() const {
+  return base::StringPrintf("%016" PRIX64 "%016" PRIX64, high_, low_);
+}
+
+}  // namespace base
diff --git a/base/token.h b/base/token.h
new file mode 100644
index 000000000..f12277e11
--- /dev/null
+++ b/base/token.h
@@ -0,0 +1,72 @@
+// Copyright 2018 The Chromium Authors. All rights reserved.
+// Use of this source code is governed by a BSD-style license that can be
+// found in the LICENSE file.
+
+#ifndef BASE_TOKEN_H_
+#define BASE_TOKEN_H_
+
+#include <stdint.h>
+
+#include <iosfwd>
+#include <tuple>
+
+#include "base/base_export.h"
+#include "base/hash.h"
+
+namespace base {
+
+// A Token is a randomly chosen 128-bit integer. This class supports generation
+// from a cryptographically strong random source, or constexpr construction over
+// fixed values (e.g. to store a pre-generated constant value). Tokens are
+// similar in spirit and purpose to UUIDs, without many of the constraints and
+// expectations (such as byte layout and string representation) clasically
+// associated with UUIDs.
+class BASE_EXPORT Token {
+ public:
+  // Constructs a zero Token.
+  constexpr Token() : high_(0), low_(0) {}
+
+  // Constructs a Token with |high| and |low| as its contents.
+  constexpr Token(uint64_t high, uint64_t low) : high_(high), low_(low) {}
+
+  // Constructs a new Token with random |high| and |low| values taken from a
+  // cryptographically strong random source.
+  static Token CreateRandom();
+
+  // The high and low 64 bits of this Token.
+  uint64_t high() const { return high_; }
+  uint64_t low() const { return low_; }
+
+  bool is_zero() const { return high_ == 0 && low_ == 0; }
+
+  bool operator==(const Token& other) const {
+    return high_ == other.high_ && low_ == other.low_;
+  }
+
+  bool operator!=(const Token& other) const { return !(*this == other); }
+
+  bool operator<(const Token& other) const {
+    return std::tie(high_, low_) < std::tie(other.high_, other.low_);
+  }
+
+  // Generates a string representation of this Token useful for e.g. logging.
+  std::string ToString() const;
+
+ private:
+  // Note: Two uint64_t are used instead of uint8_t[16] in order to have a
+  // simpler implementation, paricularly for |ToString()|, |is_zero()|, and
+  // constexpr value construction.
+  uint64_t high_;
+  uint64_t low_;
+};
+
+// For use in std::unordered_map.
+struct TokenHash {
+  size_t operator()(const base::Token& token) const {
+    return base::HashInts64(token.high(), token.low());
+  }
+};
+
+}  // namespace base
+
+#endif  // BASE_TOKEN_H_
\ No newline at end of file
diff --git a/base/unguessable_token.cc b/base/unguessable_token.cc
index 0d8aad39c..973b4167b 100644
--- a/base/unguessable_token.cc
+++ b/base/unguessable_token.cc
@@ -5,25 +5,23 @@
 #include "base/unguessable_token.h"
 
 #include "base/format_macros.h"
+#include "base/no_destructor.h"
 #include "base/rand_util.h"
 #include "base/strings/stringprintf.h"
 
 namespace base {
 
-UnguessableToken::UnguessableToken(uint64_t high, uint64_t low)
-    : high_(high), low_(low) {}
+UnguessableToken::UnguessableToken(const base::Token& token) : token_(token) {}
 
-std::string UnguessableToken::ToString() const {
-  return base::StringPrintf("%016" PRIX64 "%016" PRIX64, high_, low_);
+// static
+UnguessableToken UnguessableToken::Create() {
+  return UnguessableToken(Token::CreateRandom());
 }
 
 // static
-UnguessableToken UnguessableToken::Create() {
-  UnguessableToken token;
-  // Use base::RandBytes instead of crypto::RandBytes, because crypto calls the
-  // base version directly, and to prevent the dependency from base/ to crypto/.
-  base::RandBytes(&token, sizeof(token));
-  return token;
+const UnguessableToken& UnguessableToken::Null() {
+  static const NoDestructor<UnguessableToken> null_token;
+  return *null_token;
 }
 
 // static
@@ -31,7 +29,7 @@ UnguessableToken UnguessableToken::Deserialize(uint64_t high, uint64_t low) {
   // Receiving a zeroed out UnguessableToken from another process means that it
   // was never initialized via Create(). Treat this case as a security issue.
   DCHECK(!(high == 0 && low == 0));
-  return UnguessableToken(high, low);
+  return UnguessableToken(Token{high, low});
 }
 
 std::ostream& operator<<(std::ostream& out, const UnguessableToken& token) {
diff --git a/base/unguessable_token.h b/base/unguessable_token.h
index 6858e22a4..7f7b59a3a 100644
--- a/base/unguessable_token.h
+++ b/base/unguessable_token.h
@@ -13,14 +13,17 @@
 #include "base/base_export.h"
 #include "base/hash.h"
 #include "base/logging.h"
+#include "base/token.h"
 
 namespace base {
 
 struct UnguessableTokenHash;
 
-// A UnguessableToken is an 128-bit token generated from a cryptographically
-// strong random source. It can be used as part of a larger aggregate type,
-// or as an ID in and of itself.
+// UnguessableToken is, like Token, a randomly chosen 128-bit value. Unlike
+// Token however, a new UnguessableToken must always be generated at runtime
+// from a cryptographically strong random source (or copied or serialized and
+// deserialized from another such UnguessableToken). It can be used as part of a
+// larger aggregate type, or as an ID in and of itself.
 //
 // UnguessableToken can be used to implement "Capability-Based Security".
 // In other words, UnguessableToken can be used when the resource associated
@@ -42,6 +45,12 @@ class BASE_EXPORT UnguessableToken {
   // Create a unique UnguessableToken.
   static UnguessableToken Create();
 
+  // Returns a reference to a global null UnguessableToken. This should only be
+  // used for functions that need to return a reference to an UnguessableToken,
+  // and should not be used as a general-purpose substitute for invoking the
+  // default constructor.
+  static const UnguessableToken& Null();
+
   // Return a UnguessableToken built from the high/low bytes provided.
   // It should only be used in deserialization scenarios.
   //
@@ -56,28 +65,28 @@ class BASE_EXPORT UnguessableToken {
   // NOTE: Serializing an empty UnguessableToken is an illegal operation.
   uint64_t GetHighForSerialization() const {
     DCHECK(!is_empty());
-    return high_;
+    return token_.high();
   }
 
   // NOTE: Serializing an empty UnguessableToken is an illegal operation.
   uint64_t GetLowForSerialization() const {
     DCHECK(!is_empty());
-    return low_;
+    return token_.low();
   }
 
-  bool is_empty() const { return high_ == 0 && low_ == 0; }
+  bool is_empty() const { return token_.is_zero(); }
 
   // Hex representation of the unguessable token.
-  std::string ToString() const;
+  std::string ToString() const { return token_.ToString(); }
 
   explicit operator bool() const { return !is_empty(); }
 
   bool operator<(const UnguessableToken& other) const {
-    return std::tie(high_, low_) < std::tie(other.high_, other.low_);
+    return token_ < other.token_;
   }
 
   bool operator==(const UnguessableToken& other) const {
-    return high_ == other.high_ && low_ == other.low_;
+    return token_ == other.token_;
   }
 
   bool operator!=(const UnguessableToken& other) const {
@@ -86,12 +95,9 @@ class BASE_EXPORT UnguessableToken {
 
  private:
   friend struct UnguessableTokenHash;
-  UnguessableToken(uint64_t high, uint64_t low);
+  explicit UnguessableToken(const Token& token);
 
-  // Note: Two uint64_t are used instead of uint8_t[16], in order to have a
-  // simpler ToString() and is_empty().
-  uint64_t high_ = 0;
-  uint64_t low_ = 0;
+  base::Token token_;
 };
 
 BASE_EXPORT std::ostream& operator<<(std::ostream& out,
@@ -101,7 +107,7 @@ BASE_EXPORT std::ostream& operator<<(std::ostream& out,
 struct UnguessableTokenHash {
   size_t operator()(const base::UnguessableToken& token) const {
     DCHECK(token);
-    return base::HashInts64(token.high_, token.low_);
+    return TokenHash()(token.token_);
   }
 };
 
diff --git a/libchrome_tools/patches/Add-base-Token-class.patch b/libchrome_tools/patches/Add-base-Token-class.patch
new file mode 100644
index 000000000..546d61a9a
--- /dev/null
+++ b/libchrome_tools/patches/Add-base-Token-class.patch
@@ -0,0 +1,306 @@
+From bd984b07c2672500cf1344ee16807e52a42cfe0c Mon Sep 17 00:00:00 2001
+From: Soshun Naito <soshun@google.com>
+Date: Tue, 6 Aug 2024 08:37:44 +0000
+Subject: [PATCH] base: Add base::Token class
+
+This CL is a cherry-pick of the following CL: https://crrev.com/c/1320190
+It adds token.h and token.cc introduced in the CL above. These files are
+requried to build ARC with [Uuid] attribute in Mojo enabled.
+This CL also replaces unguessable_token.h and unguessable_token.cc with
+those in the original CL to let base::UnguessableToken to inherit
+base::Token.
+
+Bug: b:357737923, b:41420830
+Test: m
+
+Change-Id: I93cc0a588a4268416d3a3ba28e170992794e479d
+---
+ Android.bp                |  2 ++
+ base/token.cc             | 28 +++++++++++++++
+ base/token.h              | 72 +++++++++++++++++++++++++++++++++++++++
+ base/unguessable_token.cc | 20 +++++------
+ base/unguessable_token.h  | 36 ++++++++++++--------
+ 5 files changed, 132 insertions(+), 26 deletions(-)
+ create mode 100644 base/token.cc
+ create mode 100644 base/token.h
+
+diff --git a/Android.bp b/Android.bp
+index 340a194ac..c9b031519 100644
+--- a/Android.bp
++++ b/Android.bp
+@@ -458,6 +458,7 @@ filegroup {
+         "base/timer/hi_res_timer_manager.h",
+         "base/timer/mock_timer.h",
+         "base/timer/timer.h",
++        "base/token.h",
+         "base/trace_event/common/trace_event_common.h",
+         "base/trace_event/heap_profiler.h",
+         "base/trace_event/trace_event.h",
+@@ -736,6 +737,7 @@ libchromeCommonSrc = [
+     "base/time/time_override.cc",
+     "base/timer/elapsed_timer.cc",
+     "base/timer/timer.cc",
++    "base/token.cc",
+     "base/unguessable_token.cc",
+     "base/value_iterators.cc",
+     "base/values.cc",
+diff --git a/base/token.cc b/base/token.cc
+new file mode 100644
+index 000000000..e7ad89671
+--- /dev/null
++++ b/base/token.cc
+@@ -0,0 +1,28 @@
++// Copyright 2018 The Chromium Authors. All rights reserved.
++// Use of this source code is governed by a BSD-style license that can be
++// found in the LICENSE file.
++
++#include "base/token.h"
++
++#include <inttypes.h>
++
++#include "base/rand_util.h"
++#include "base/strings/stringprintf.h"
++
++namespace base {
++
++// static
++Token Token::CreateRandom() {
++  Token token;
++
++  // Use base::RandBytes instead of crypto::RandBytes, because crypto calls the
++  // base version directly, and to prevent the dependency from base/ to crypto/.
++  base::RandBytes(&token, sizeof(token));
++  return token;
++}
++
++std::string Token::ToString() const {
++  return base::StringPrintf("%016" PRIX64 "%016" PRIX64, high_, low_);
++}
++
++}  // namespace base
+diff --git a/base/token.h b/base/token.h
+new file mode 100644
+index 000000000..f12277e11
+--- /dev/null
++++ b/base/token.h
+@@ -0,0 +1,72 @@
++// Copyright 2018 The Chromium Authors. All rights reserved.
++// Use of this source code is governed by a BSD-style license that can be
++// found in the LICENSE file.
++
++#ifndef BASE_TOKEN_H_
++#define BASE_TOKEN_H_
++
++#include <stdint.h>
++
++#include <iosfwd>
++#include <tuple>
++
++#include "base/base_export.h"
++#include "base/hash.h"
++
++namespace base {
++
++// A Token is a randomly chosen 128-bit integer. This class supports generation
++// from a cryptographically strong random source, or constexpr construction over
++// fixed values (e.g. to store a pre-generated constant value). Tokens are
++// similar in spirit and purpose to UUIDs, without many of the constraints and
++// expectations (such as byte layout and string representation) clasically
++// associated with UUIDs.
++class BASE_EXPORT Token {
++ public:
++  // Constructs a zero Token.
++  constexpr Token() : high_(0), low_(0) {}
++
++  // Constructs a Token with |high| and |low| as its contents.
++  constexpr Token(uint64_t high, uint64_t low) : high_(high), low_(low) {}
++
++  // Constructs a new Token with random |high| and |low| values taken from a
++  // cryptographically strong random source.
++  static Token CreateRandom();
++
++  // The high and low 64 bits of this Token.
++  uint64_t high() const { return high_; }
++  uint64_t low() const { return low_; }
++
++  bool is_zero() const { return high_ == 0 && low_ == 0; }
++
++  bool operator==(const Token& other) const {
++    return high_ == other.high_ && low_ == other.low_;
++  }
++
++  bool operator!=(const Token& other) const { return !(*this == other); }
++
++  bool operator<(const Token& other) const {
++    return std::tie(high_, low_) < std::tie(other.high_, other.low_);
++  }
++
++  // Generates a string representation of this Token useful for e.g. logging.
++  std::string ToString() const;
++
++ private:
++  // Note: Two uint64_t are used instead of uint8_t[16] in order to have a
++  // simpler implementation, paricularly for |ToString()|, |is_zero()|, and
++  // constexpr value construction.
++  uint64_t high_;
++  uint64_t low_;
++};
++
++// For use in std::unordered_map.
++struct TokenHash {
++  size_t operator()(const base::Token& token) const {
++    return base::HashInts64(token.high(), token.low());
++  }
++};
++
++}  // namespace base
++
++#endif  // BASE_TOKEN_H_
+\ No newline at end of file
+diff --git a/base/unguessable_token.cc b/base/unguessable_token.cc
+index 0d8aad39c..973b4167b 100644
+--- a/base/unguessable_token.cc
++++ b/base/unguessable_token.cc
+@@ -5,25 +5,23 @@
+ #include "base/unguessable_token.h"
+ 
+ #include "base/format_macros.h"
++#include "base/no_destructor.h"
+ #include "base/rand_util.h"
+ #include "base/strings/stringprintf.h"
+ 
+ namespace base {
+ 
+-UnguessableToken::UnguessableToken(uint64_t high, uint64_t low)
+-    : high_(high), low_(low) {}
++UnguessableToken::UnguessableToken(const base::Token& token) : token_(token) {}
+ 
+-std::string UnguessableToken::ToString() const {
+-  return base::StringPrintf("%016" PRIX64 "%016" PRIX64, high_, low_);
++// static
++UnguessableToken UnguessableToken::Create() {
++  return UnguessableToken(Token::CreateRandom());
+ }
+ 
+ // static
+-UnguessableToken UnguessableToken::Create() {
+-  UnguessableToken token;
+-  // Use base::RandBytes instead of crypto::RandBytes, because crypto calls the
+-  // base version directly, and to prevent the dependency from base/ to crypto/.
+-  base::RandBytes(&token, sizeof(token));
+-  return token;
++const UnguessableToken& UnguessableToken::Null() {
++  static const NoDestructor<UnguessableToken> null_token;
++  return *null_token;
+ }
+ 
+ // static
+@@ -31,7 +29,7 @@ UnguessableToken UnguessableToken::Deserialize(uint64_t high, uint64_t low) {
+   // Receiving a zeroed out UnguessableToken from another process means that it
+   // was never initialized via Create(). Treat this case as a security issue.
+   DCHECK(!(high == 0 && low == 0));
+-  return UnguessableToken(high, low);
++  return UnguessableToken(Token{high, low});
+ }
+ 
+ std::ostream& operator<<(std::ostream& out, const UnguessableToken& token) {
+diff --git a/base/unguessable_token.h b/base/unguessable_token.h
+index 6858e22a4..7f7b59a3a 100644
+--- a/base/unguessable_token.h
++++ b/base/unguessable_token.h
+@@ -13,14 +13,17 @@
+ #include "base/base_export.h"
+ #include "base/hash.h"
+ #include "base/logging.h"
++#include "base/token.h"
+ 
+ namespace base {
+ 
+ struct UnguessableTokenHash;
+ 
+-// A UnguessableToken is an 128-bit token generated from a cryptographically
+-// strong random source. It can be used as part of a larger aggregate type,
+-// or as an ID in and of itself.
++// UnguessableToken is, like Token, a randomly chosen 128-bit value. Unlike
++// Token however, a new UnguessableToken must always be generated at runtime
++// from a cryptographically strong random source (or copied or serialized and
++// deserialized from another such UnguessableToken). It can be used as part of a
++// larger aggregate type, or as an ID in and of itself.
+ //
+ // UnguessableToken can be used to implement "Capability-Based Security".
+ // In other words, UnguessableToken can be used when the resource associated
+@@ -42,6 +45,12 @@ class BASE_EXPORT UnguessableToken {
+   // Create a unique UnguessableToken.
+   static UnguessableToken Create();
+ 
++  // Returns a reference to a global null UnguessableToken. This should only be
++  // used for functions that need to return a reference to an UnguessableToken,
++  // and should not be used as a general-purpose substitute for invoking the
++  // default constructor.
++  static const UnguessableToken& Null();
++
+   // Return a UnguessableToken built from the high/low bytes provided.
+   // It should only be used in deserialization scenarios.
+   //
+@@ -56,28 +65,28 @@ class BASE_EXPORT UnguessableToken {
+   // NOTE: Serializing an empty UnguessableToken is an illegal operation.
+   uint64_t GetHighForSerialization() const {
+     DCHECK(!is_empty());
+-    return high_;
++    return token_.high();
+   }
+ 
+   // NOTE: Serializing an empty UnguessableToken is an illegal operation.
+   uint64_t GetLowForSerialization() const {
+     DCHECK(!is_empty());
+-    return low_;
++    return token_.low();
+   }
+ 
+-  bool is_empty() const { return high_ == 0 && low_ == 0; }
++  bool is_empty() const { return token_.is_zero(); }
+ 
+   // Hex representation of the unguessable token.
+-  std::string ToString() const;
++  std::string ToString() const { return token_.ToString(); }
+ 
+   explicit operator bool() const { return !is_empty(); }
+ 
+   bool operator<(const UnguessableToken& other) const {
+-    return std::tie(high_, low_) < std::tie(other.high_, other.low_);
++    return token_ < other.token_;
+   }
+ 
+   bool operator==(const UnguessableToken& other) const {
+-    return high_ == other.high_ && low_ == other.low_;
++    return token_ == other.token_;
+   }
+ 
+   bool operator!=(const UnguessableToken& other) const {
+@@ -86,12 +95,9 @@ class BASE_EXPORT UnguessableToken {
+ 
+  private:
+   friend struct UnguessableTokenHash;
+-  UnguessableToken(uint64_t high, uint64_t low);
++  explicit UnguessableToken(const Token& token);
+ 
+-  // Note: Two uint64_t are used instead of uint8_t[16], in order to have a
+-  // simpler ToString() and is_empty().
+-  uint64_t high_ = 0;
+-  uint64_t low_ = 0;
++  base::Token token_;
+ };
+ 
+ BASE_EXPORT std::ostream& operator<<(std::ostream& out,
+@@ -101,7 +107,7 @@ BASE_EXPORT std::ostream& operator<<(std::ostream& out,
+ struct UnguessableTokenHash {
+   size_t operator()(const base::UnguessableToken& token) const {
+     DCHECK(token);
+-    return base::HashInts64(token.high_, token.low_);
++    return TokenHash()(token.token_);
+   }
+ };
+ 
+-- 
+2.46.0.rc2.264.g509ed76dc8-goog
+
diff --git a/libchrome_tools/patches/Mojo-introduce-uuid-attribute.patch b/libchrome_tools/patches/Mojo-introduce-uuid-attribute.patch
new file mode 100644
index 000000000..08cdacb20
--- /dev/null
+++ b/libchrome_tools/patches/Mojo-introduce-uuid-attribute.patch
@@ -0,0 +1,137 @@
+From 9693d3707e16f783b97dcf0a7340ded0427aa3c0 Mon Sep 17 00:00:00 2001
+From: Soshun Naito <soshun@google.com>
+Date: Wed, 7 Aug 2024 03:47:23 +0000
+Subject: [PATCH] Mojo: Introduce [Uuid] attribute
+
+This is a cherry-pick of the CL: https://crrev.com/c/2462378
+It adds Uuid_ attribute to the corresponding cpp interface when we add
+[Uuid=<UUID>] to the mojo interface.
+
+Bug: b:357737923, b:40152372
+Test: m libmojo
+Change-Id: I927361da96eba66420f6c95777cba43b0055baec
+---
+ mojo/public/tools/bindings/README.md            |  7 +++++++
+ .../cpp_templates/interface_declaration.tmpl    |  4 ++++
+ .../cpp_templates/interface_definition.tmpl     |  3 +++
+ .../bindings/generators/mojom_cpp_generator.py  |  5 ++++-
+ .../bindings/pylib/mojom/generate/module.py     | 17 +++++++++++++++++
+ 5 files changed, 35 insertions(+), 1 deletion(-)
+
+diff --git a/mojo/public/tools/bindings/README.md b/mojo/public/tools/bindings/README.md
+index d1ffc448e..ce291ae0e 100644
+--- a/mojo/public/tools/bindings/README.md
++++ b/mojo/public/tools/bindings/README.md
+@@ -395,6 +395,13 @@ interesting attributes supported today.
+     field, enum value, interface method, or method parameter was introduced.
+     See [Versioning](#Versioning) for more details.
+ 
++**`[Uuid=<UUID>]`**
++:  Specifies a UUID to be associated with a given interface. The UUID is
++   intended to remain stable across all changes to the interface definition,
++   including name changes. The value given for this attribute should be a
++   standard UUID string representation as specified by RFC 4122. New UUIDs can
++   be generated with common tools such as `uuidgen`.
++
+ **`[EnableIf=value]`**
+ :   The `EnableIf` attribute is used to conditionally enable definitions when
+     the mojom is parsed. If the `mojom` target in the GN file does not include
+diff --git a/mojo/public/tools/bindings/generators/cpp_templates/interface_declaration.tmpl b/mojo/public/tools/bindings/generators/cpp_templates/interface_declaration.tmpl
+index 193d380e7..bd007ab2a 100644
+--- a/mojo/public/tools/bindings/generators/cpp_templates/interface_declaration.tmpl
++++ b/mojo/public/tools/bindings/generators/cpp_templates/interface_declaration.tmpl
+@@ -13,6 +13,10 @@ class {{export_attribute}} {{interface.name}}
+     : public {{interface.name}}InterfaceBase {
+  public:
+   static const char Name_[];
++{%-  if interface.uuid %}
++  static constexpr base::Token Uuid_{ {{interface.uuid[0]}}ULL,
++                                      {{interface.uuid[1]}}ULL };
++{%-  endif %}
+   static constexpr uint32_t Version_ = {{interface.version}};
+   static constexpr bool PassesAssociatedKinds_ = {% if interface|passes_associated_kinds %}true{% else %}false{% endif %};
+   static constexpr bool HasSyncMethods_ = {% if interface|has_sync_methods %}true{% else %}false{% endif %};
+diff --git a/mojo/public/tools/bindings/generators/cpp_templates/interface_definition.tmpl b/mojo/public/tools/bindings/generators/cpp_templates/interface_definition.tmpl
+index 72c3101c1..bc3200bf6 100644
+--- a/mojo/public/tools/bindings/generators/cpp_templates/interface_definition.tmpl
++++ b/mojo/public/tools/bindings/generators/cpp_templates/interface_definition.tmpl
+@@ -32,6 +32,9 @@ std::move(p_{{param.name}})
+ 
+ {#--- Begin #}
+ const char {{class_name}}::Name_[] = "{{namespace}}.{{class_name}}";
++{%-  if interface.uuid %}
++constexpr base::Token {{class_name}}::Uuid_;
++{%-  endif %}
+ 
+ {#--- Constants #}
+ {%-  for constant in interface.constants %}
+diff --git a/mojo/public/tools/bindings/generators/mojom_cpp_generator.py b/mojo/public/tools/bindings/generators/mojom_cpp_generator.py
+index 97bc827c9..b6519a80b 100644
+--- a/mojo/public/tools/bindings/generators/mojom_cpp_generator.py
++++ b/mojo/public/tools/bindings/generators/mojom_cpp_generator.py
+@@ -256,16 +256,19 @@ class Generator(generator.Generator):
+     return used_typemaps
+ 
+   def _GetExtraPublicHeaders(self):
++    headers = set()
++
+     all_enums = list(self.module.enums)
+     for struct in self.module.structs:
+       all_enums.extend(struct.enums)
+     for interface in self.module.interfaces:
+       all_enums.extend(interface.enums)
++      if interface.uuid:
++        headers.add('base/token.h')
+ 
+     types = set(self._GetFullMojomNameForKind(typename)
+                 for typename in
+                 self.module.structs + all_enums + self.module.unions)
+-    headers = set()
+     for typename, typemap in self.typemap.items():
+       if typename in types:
+         headers.update(typemap.get("public_headers", []))
+diff --git a/mojo/public/tools/bindings/pylib/mojom/generate/module.py b/mojo/public/tools/bindings/pylib/mojom/generate/module.py
+index aeeb4fce0..6a48791e5 100644
+--- a/mojo/public/tools/bindings/pylib/mojom/generate/module.py
++++ b/mojo/public/tools/bindings/pylib/mojom/generate/module.py
+@@ -12,6 +12,8 @@
+ # method = interface.AddMethod('Tat', 0)
+ # method.AddParameter('baz', 0, mojom.INT32)
+ 
++from uuid import UUID
++
+ # We use our own version of __repr__ when displaying the AST, as the
+ # AST currently doesn't capture which nodes are reference (e.g. to
+ # types) and which nodes are definitions. This allows us to e.g. print
+@@ -224,6 +226,7 @@ PRIMITIVES = (
+ ATTRIBUTE_MIN_VERSION = 'MinVersion'
+ ATTRIBUTE_EXTENSIBLE = 'Extensible'
+ ATTRIBUTE_SYNC = 'Sync'
++ATTRIBUTE_UUID = 'Uuid'
+ 
+ 
+ class NamedValue(object):
+@@ -642,6 +645,20 @@ class Interface(ReferenceKind):
+     for constant in self.constants:
+       constant.Stylize(stylizer)
+ 
++  @property
++  def uuid(self):
++    uuid_str = self.attributes.get(ATTRIBUTE_UUID) if self.attributes else None
++    if uuid_str is None:
++      return None
++
++    try:
++      u = UUID(uuid_str)
++    except:
++      raise ValueError('Invalid format for Uuid attribute on interface {}. '
++                       'Expected standard RFC 4122 string representation of '
++                       'a UUID.'.format(self.mojom_name))
++    return (int(u.hex[:16], 16), int(u.hex[16:], 16))
++
+ 
+ class AssociatedInterface(ReferenceKind):
+   ReferenceKind.AddSharedProperty('kind')
+-- 
+2.46.0.rc2.264.g509ed76dc8-goog
+
diff --git a/mojo/public/tools/bindings/README.md b/mojo/public/tools/bindings/README.md
index d1ffc448e..ce291ae0e 100644
--- a/mojo/public/tools/bindings/README.md
+++ b/mojo/public/tools/bindings/README.md
@@ -395,6 +395,13 @@ interesting attributes supported today.
     field, enum value, interface method, or method parameter was introduced.
     See [Versioning](#Versioning) for more details.
 
+**`[Uuid=<UUID>]`**
+:  Specifies a UUID to be associated with a given interface. The UUID is
+   intended to remain stable across all changes to the interface definition,
+   including name changes. The value given for this attribute should be a
+   standard UUID string representation as specified by RFC 4122. New UUIDs can
+   be generated with common tools such as `uuidgen`.
+
 **`[EnableIf=value]`**
 :   The `EnableIf` attribute is used to conditionally enable definitions when
     the mojom is parsed. If the `mojom` target in the GN file does not include
diff --git a/mojo/public/tools/bindings/generators/cpp_templates/interface_declaration.tmpl b/mojo/public/tools/bindings/generators/cpp_templates/interface_declaration.tmpl
index 193d380e7..bd007ab2a 100644
--- a/mojo/public/tools/bindings/generators/cpp_templates/interface_declaration.tmpl
+++ b/mojo/public/tools/bindings/generators/cpp_templates/interface_declaration.tmpl
@@ -13,6 +13,10 @@ class {{export_attribute}} {{interface.name}}
     : public {{interface.name}}InterfaceBase {
  public:
   static const char Name_[];
+{%-  if interface.uuid %}
+  static constexpr base::Token Uuid_{ {{interface.uuid[0]}}ULL,
+                                      {{interface.uuid[1]}}ULL };
+{%-  endif %}
   static constexpr uint32_t Version_ = {{interface.version}};
   static constexpr bool PassesAssociatedKinds_ = {% if interface|passes_associated_kinds %}true{% else %}false{% endif %};
   static constexpr bool HasSyncMethods_ = {% if interface|has_sync_methods %}true{% else %}false{% endif %};
diff --git a/mojo/public/tools/bindings/generators/cpp_templates/interface_definition.tmpl b/mojo/public/tools/bindings/generators/cpp_templates/interface_definition.tmpl
index 72c3101c1..bc3200bf6 100644
--- a/mojo/public/tools/bindings/generators/cpp_templates/interface_definition.tmpl
+++ b/mojo/public/tools/bindings/generators/cpp_templates/interface_definition.tmpl
@@ -32,6 +32,9 @@ std::move(p_{{param.name}})
 
 {#--- Begin #}
 const char {{class_name}}::Name_[] = "{{namespace}}.{{class_name}}";
+{%-  if interface.uuid %}
+constexpr base::Token {{class_name}}::Uuid_;
+{%-  endif %}
 
 {#--- Constants #}
 {%-  for constant in interface.constants %}
diff --git a/mojo/public/tools/bindings/generators/mojom_cpp_generator.py b/mojo/public/tools/bindings/generators/mojom_cpp_generator.py
index 97bc827c9..b6519a80b 100644
--- a/mojo/public/tools/bindings/generators/mojom_cpp_generator.py
+++ b/mojo/public/tools/bindings/generators/mojom_cpp_generator.py
@@ -256,16 +256,19 @@ class Generator(generator.Generator):
     return used_typemaps
 
   def _GetExtraPublicHeaders(self):
+    headers = set()
+
     all_enums = list(self.module.enums)
     for struct in self.module.structs:
       all_enums.extend(struct.enums)
     for interface in self.module.interfaces:
       all_enums.extend(interface.enums)
+      if interface.uuid:
+        headers.add('base/token.h')
 
     types = set(self._GetFullMojomNameForKind(typename)
                 for typename in
                 self.module.structs + all_enums + self.module.unions)
-    headers = set()
     for typename, typemap in self.typemap.items():
       if typename in types:
         headers.update(typemap.get("public_headers", []))
diff --git a/mojo/public/tools/bindings/pylib/mojom/generate/module.py b/mojo/public/tools/bindings/pylib/mojom/generate/module.py
index aeeb4fce0..6a48791e5 100644
--- a/mojo/public/tools/bindings/pylib/mojom/generate/module.py
+++ b/mojo/public/tools/bindings/pylib/mojom/generate/module.py
@@ -12,6 +12,8 @@
 # method = interface.AddMethod('Tat', 0)
 # method.AddParameter('baz', 0, mojom.INT32)
 
+from uuid import UUID
+
 # We use our own version of __repr__ when displaying the AST, as the
 # AST currently doesn't capture which nodes are reference (e.g. to
 # types) and which nodes are definitions. This allows us to e.g. print
@@ -224,6 +226,7 @@ PRIMITIVES = (
 ATTRIBUTE_MIN_VERSION = 'MinVersion'
 ATTRIBUTE_EXTENSIBLE = 'Extensible'
 ATTRIBUTE_SYNC = 'Sync'
+ATTRIBUTE_UUID = 'Uuid'
 
 
 class NamedValue(object):
@@ -642,6 +645,20 @@ class Interface(ReferenceKind):
     for constant in self.constants:
       constant.Stylize(stylizer)
 
+  @property
+  def uuid(self):
+    uuid_str = self.attributes.get(ATTRIBUTE_UUID) if self.attributes else None
+    if uuid_str is None:
+      return None
+
+    try:
+      u = UUID(uuid_str)
+    except:
+      raise ValueError('Invalid format for Uuid attribute on interface {}. '
+                       'Expected standard RFC 4122 string representation of '
+                       'a UUID.'.format(self.mojom_name))
+    return (int(u.hex[:16], 16), int(u.hex[16:], 16))
+
 
 class AssociatedInterface(ReferenceKind):
   ReferenceKind.AddSharedProperty('kind')
```

