```diff
diff --git a/base/BUILD.bazel b/base/BUILD.bazel
index e4969be..73044b9 100644
--- a/base/BUILD.bazel
+++ b/base/BUILD.bazel
@@ -149,6 +149,25 @@ cc_library(
     alwayslink = True,
 )
 
+cc_library(
+    name = "test-matchers",
+    srcs = [
+        "testing/ProtobufMatchers.cpp",
+    ],
+    visibility = [
+        "//visibility:public",
+    ],
+    deps = [
+        ":aemu-base",
+        ":aemu-base-headers",
+        "@com_google_absl//absl/log",
+        "@com_google_absl//absl/log:check",
+        "@com_google_googletest//:gtest",
+        "@com_google_protobuf//:protobuf",
+    ],
+    alwayslink = True,
+)
+
 cc_test(
     name = "aemu-base_unittests",
     srcs = [
diff --git a/base/Stream.cpp b/base/Stream.cpp
index dd67b50..1e1b91a 100644
--- a/base/Stream.cpp
+++ b/base/Stream.cpp
@@ -1,16 +1,7 @@
-// Copyright 2019 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-// http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
+/*
+ * Copyright 2019 Google
+ * SPDX-License-Identifier: MIT
+ */
 
 #include "aemu/base/files/Stream.h"
 
diff --git a/base/include/aemu/base/AlignedBuf.h b/base/include/aemu/base/AlignedBuf.h
index c0308b9..b056d7b 100644
--- a/base/include/aemu/base/AlignedBuf.h
+++ b/base/include/aemu/base/AlignedBuf.h
@@ -1,16 +1,7 @@
-// Copyright 2018 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-// http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
+/*
+ * Copyright 2018 Google
+ * SPDX-License-Identifier: MIT
+ */
 
 #pragma once
 
@@ -30,8 +21,25 @@
 
 namespace android {
 
+/**
+ * Do not abuse this by using any complicated T. Use it for POD or primitives
+ */
 template <class T, size_t align>
 class AlignedBuf {
+    constexpr static bool triviallyCopyable() {
+#if (defined(__GNUC__) && !defined(__clang__) && __GNUC__ <= 4) || \
+        defined(__OLD_STD_VERSION__)
+        // Older g++ doesn't support std::is_trivially_copyable.
+        constexpr bool triviallyCopyable =
+                std::has_trivial_copy_constructor<T>::value;
+#else
+        constexpr bool triviallyCopyable = std::is_trivially_copyable<T>::value;
+#endif
+        return triviallyCopyable;
+    }
+    static_assert(triviallyCopyable() && std::is_standard_layout<T>::value &&
+                  std::is_trivially_default_constructible<T>::value);
+
 public:
     explicit AlignedBuf(size_t size) {
         static_assert(align && ((align & (align - 1)) == 0),
@@ -68,17 +76,6 @@ public:
     ~AlignedBuf() { if (mBuffer) freeImpl(mBuffer); } // account for getting moved out
 
     void resize(size_t newSize) {
-#if (defined(__GNUC__) && !defined(__clang__) && __GNUC__ <= 4) || \
-        defined(__OLD_STD_VERSION__)
-        // Older g++ doesn't support std::is_trivially_copyable.
-        constexpr bool triviallyCopyable =
-                std::has_trivial_copy_constructor<T>::value;
-#else
-        constexpr bool triviallyCopyable = std::is_trivially_copyable<T>::value;
-#endif
-        static_assert(triviallyCopyable,
-                      "AlignedBuf can only resize trivially copyable values");
-
         resizeImpl(newSize);
     }
 
@@ -95,22 +92,27 @@ public:
     }
 
 private:
+    T* getNewBuffer(size_t newSize) {
+        if (newSize == 0) {
+            return nullptr;
+        }
+        size_t pad = std::max(align, sizeof(T));
+        size_t newSizeBytes =
+            ((align - 1 + newSize * sizeof(T) + pad) / align) * align;
+        return static_cast<T*>(reallocImpl(nullptr, newSizeBytes));
+    }
 
     void resizeImpl(size_t newSize) {
-        if (newSize) {
-            size_t pad = std::max(align, sizeof(T));
+        T* new_buffer = getNewBuffer(newSize);
+        if (new_buffer && mBuffer) {
             size_t keepSize = std::min(newSize, mSize);
-            size_t newSizeBytes = ((align - 1 + newSize * sizeof(T) + pad) / align) * align;
-
-            std::vector<T> temp(mBuffer, mBuffer + keepSize);
-            mBuffer = static_cast<T*>(reallocImpl(mBuffer, newSizeBytes));
-            std::copy(temp.data(), temp.data() + keepSize, mBuffer);
-        } else {
-            if (mBuffer) freeImpl(mBuffer);
-            mBuffer = nullptr;
+            std::copy(mBuffer, mBuffer + keepSize, new_buffer);
         }
-
-        mSize = newSize;
+        if (mBuffer) {
+            freeImpl(mBuffer);
+        }
+        mBuffer = new_buffer;
+        mSize = (new_buffer ? newSize : 0);
     }
 
     void* reallocImpl(void* oldPtr, size_t sizeBytes) {
diff --git a/base/include/aemu/base/Allocator.h b/base/include/aemu/base/Allocator.h
index d875de1..2127eb6 100644
--- a/base/include/aemu/base/Allocator.h
+++ b/base/include/aemu/base/Allocator.h
@@ -1,16 +1,7 @@
-// Copyright 2021 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-// http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
+/*
+ * Copyright 2021 Google
+ * SPDX-License-Identifier: MIT
+ */
 #pragma once
 
 #include <inttypes.h>
diff --git a/base/include/aemu/base/BumpPool.h b/base/include/aemu/base/BumpPool.h
index 929e350..0bb5c66 100644
--- a/base/include/aemu/base/BumpPool.h
+++ b/base/include/aemu/base/BumpPool.h
@@ -1,16 +1,7 @@
-// Copyright 2018 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-// http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
+/*
+ * Copyright 2019 Google
+ * SPDX-License-Identifier: MIT
+ */
 #pragma once
 
 #include "aemu/base/AlignedBuf.h"
diff --git a/base/include/aemu/base/LayoutResolver.h b/base/include/aemu/base/LayoutResolver.h
index 1474594..76590a8 100644
--- a/base/include/aemu/base/LayoutResolver.h
+++ b/base/include/aemu/base/LayoutResolver.h
@@ -19,6 +19,13 @@
 
 namespace android {
 namespace base {
+struct AutomotiveDisplay {
+    enum {
+        GENERIC_DISPLAY = 1 << 0,
+        DISTANT_DISPLAY = 1 << 1,
+        DYNAMIC_MULTI_DISPLAY = 1 << 2,
+    };
+};
 // rect: a mapping from display ID to a rectangle represented as pair of width
 // and height. 
 // monitorAspectRatio: current host monitor's aspect ratio.
@@ -30,6 +37,6 @@ std::unordered_map<uint32_t, std::pair<uint32_t, uint32_t>> resolveLayout(
 
 std::unordered_map<uint32_t, std::pair<uint32_t, uint32_t>> resolveStackedLayout(
         std::unordered_map<uint32_t, std::pair<uint32_t, uint32_t>> rectangles,
-        const bool isDistantDisplay);
+        uint32_t displayType);
 }  // namespace base
 }  // namespace android
diff --git a/base/include/aemu/base/async/AsyncSocket.h b/base/include/aemu/base/async/AsyncSocket.h
index 12ea8b1..55cd58a 100644
--- a/base/include/aemu/base/async/AsyncSocket.h
+++ b/base/include/aemu/base/async/AsyncSocket.h
@@ -71,7 +71,9 @@ class AsyncSocket : public AsyncSocketAdapter {
     ssize_t recv(char* buffer, uint64_t bufferSize) override;
 
     /**
-     * @brief Sends data over the socket.
+     * @brief Sends data over the socket, note these are send
+     *        asynchronously!
+     *
      *
      * @param buffer The buffer containing the data to send.
      * @param bufferSize The size of the data to send.
@@ -79,6 +81,12 @@ class AsyncSocket : public AsyncSocketAdapter {
      */
     ssize_t send(const char* buffer, uint64_t bufferSize) override;
 
+    // Number of bytes in the buffer (scheduled to be send)
+    size_t sendBuffer() { return mSendBuffer; };
+
+    // Wait at most duration for the send buffer to be cleared
+    bool waitForSend(const std::chrono::milliseconds& rel_time);
+
     /**
      * @brief Attempts to asynchronously connect the socket.
      *
@@ -127,9 +135,14 @@ class AsyncSocket : public AsyncSocketAdapter {
     void wantRead();
 
    private:
+    // Indicates that the socket is interested in writing data.
+    void wantWrite();
+
     // Attempts to connect to the specified port.
     void connectToPort();
 
+    void scheduleCallback(std::function<void()> callback);
+
     // Size of the write buffer.
     static const int WRITE_BUFFER_SIZE = 1024;
 
@@ -156,12 +169,22 @@ class AsyncSocket : public AsyncSocketAdapter {
     // Condition variable for signaling changes in FdWatch state.
     std::condition_variable mWatchLockCv;
 
+    // Condition variable for signaling changes in sendBuffer
+    std::mutex mSendBufferMutex;
+    std::condition_variable mSendBufferCv;
+    std::atomic<size_t> mSendBuffer{0};
+
     // Write buffer used by the async writer.
     std::string mWriteBuffer;
 
     // Mutex to track callback activity, this mutex will be taken
     // when a callback is active.
     std::recursive_mutex mListenerLock;
+
+    std::mutex mInflightMutex;
+    std::condition_variable mInflightCv;
+    int mInflight{0};
+    bool mClosing{false};
 };
 
 }  // namespace base
diff --git a/base/include/aemu/base/async/AsyncSocketAdapter.h b/base/include/aemu/base/async/AsyncSocketAdapter.h
index 4c99f9f..53bbb34 100644
--- a/base/include/aemu/base/async/AsyncSocketAdapter.h
+++ b/base/include/aemu/base/async/AsyncSocketAdapter.h
@@ -207,7 +207,10 @@ class SimpleAsyncSocket : public AsyncSocketEventListener {
         } while (true);
     };
 
-    void onClose(AsyncSocketAdapter* socket, int err) override { mOnClose(); };
+    void onClose(AsyncSocketAdapter* socket, int err) override {
+        if (mOnClose) mOnClose();
+    };
+
     void onConnected(AsyncSocketAdapter* socket) override {}
 
     /**
diff --git a/base/include/aemu/base/async/AsyncWriter.h b/base/include/aemu/base/async/AsyncWriter.h
index d203252..8ff73f4 100644
--- a/base/include/aemu/base/async/AsyncWriter.h
+++ b/base/include/aemu/base/async/AsyncWriter.h
@@ -35,6 +35,7 @@ public:
                Looper::FdWatch* watch);
 
     AsyncStatus run();
+    size_t written() { return mPos; }
 
 private:
     const uint8_t* mBuffer;
diff --git a/base/include/aemu/base/containers/EntityManager.h b/base/include/aemu/base/containers/EntityManager.h
index 775a1a9..05021c8 100644
--- a/base/include/aemu/base/containers/EntityManager.h
+++ b/base/include/aemu/base/containers/EntityManager.h
@@ -1,21 +1,9 @@
-// Copyright (C) 2019 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-// http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
+/*
+ * Copyright 2019 Google
+ * SPDX-License-Identifier: MIT
+ */
 #pragma once
 
-#include "aemu/base/containers/Lookup.h"
-#include "aemu/base/Optional.h"
-
 #include <functional>
 #include <unordered_map>
 #include <vector>
@@ -436,8 +424,12 @@ public:
 
     // If we didn't explicitly track, just fail.
     ComponentHandle getComponentHandle(EntityHandle h) const {
-        auto componentHandlePtr = android::base::find(mEntityToComponentMap, h);
-        if (!componentHandlePtr) return INVALID_COMPONENT_HANDLE;
+        const auto it = mEntityToComponentMap.find(h);
+        if (it == mEntityToComponentMap.end()) {
+            return INVALID_COMPONENT_HANDLE;
+        }
+
+        auto componentHandlePtr = &it->second;
         return *componentHandlePtr;
     }
 
diff --git a/base/include/aemu/base/files/Stream.h b/base/include/aemu/base/files/Stream.h
index 75196f0..dcc1d60 100644
--- a/base/include/aemu/base/files/Stream.h
+++ b/base/include/aemu/base/files/Stream.h
@@ -1,16 +1,7 @@
-// Copyright 2019 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-// http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
+/*
+ * Copyright 2019 Google
+ * SPDX-License-Identifier: MIT
+ */
 
 #pragma once
 
diff --git a/base/include/aemu/base/logging/Log.h b/base/include/aemu/base/logging/Log.h
index de8042f..ea7db33 100644
--- a/base/include/aemu/base/logging/Log.h
+++ b/base/include/aemu/base/logging/Log.h
@@ -11,9 +11,9 @@
 // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 // See the License for the specific language governing permissions and
 // limitations under the License.
-
 #pragma once
 
+#ifndef ABSL_LOG_LOG_H_
 #include <errno.h>   // for errno
 #include <stdio.h>   // for size_t, EOF
 #include <string.h>  // for strcmp
@@ -460,3 +460,4 @@ class LOGGING_API LogOutput {
 
 }  // namespace base
 }  // namespace android
+#endif
\ No newline at end of file
diff --git a/base/include/aemu/base/ring_buffer.h b/base/include/aemu/base/ring_buffer.h
index 2add565..f0f8f95 100644
--- a/base/include/aemu/base/ring_buffer.h
+++ b/base/include/aemu/base/ring_buffer.h
@@ -1,16 +1,7 @@
-// Copyright 2018 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-// http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
+/*
+ * Copyright 2018 Google
+ * SPDX-License-Identifier: MIT
+ */
 #pragma once
 
 #include "aemu/base/c_header.h"
diff --git a/base/include/aemu/base/testing/ProtobufMatchers.h b/base/include/aemu/base/testing/ProtobufMatchers.h
new file mode 100644
index 0000000..fa6df4c
--- /dev/null
+++ b/base/include/aemu/base/testing/ProtobufMatchers.h
@@ -0,0 +1,1010 @@
+/*
+ * Copyright 2018 Google Inc.
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
+// gMock matchers used to validate protocol buffer arguments.
+
+// WHAT THIS IS
+// ============
+//
+// This library defines the following matchers in the ::android namespace:
+//
+//   EqualsProto(pb)              The argument equals pb.
+//   EqualsInitializedProto(pb)   The argument is initialized and equals pb.
+//   EquivToProto(pb)             The argument is equivalent to pb.
+//   EquivToInitializedProto(pb)  The argument is initialized and equivalent
+//                                to pb.
+//   IsInitializedProto()         The argument is an initialized protobuf.
+//
+// where:
+//
+//   - pb can be either a protobuf value or a human-readable string
+//     representation of it.
+//   - When pb is a string, the matcher can optionally accept a
+//     template argument for the type of the protobuf,
+//     e.g. EqualsProto<Foo>("foo: 1").
+//   - "equals" is defined as the argument's Equals(pb) method returns true.
+//   - "equivalent to" is defined as the argument's Equivalent(pb) method
+//     returns true.
+//   - "initialized" means that the argument's IsInitialized() method returns
+//     true.
+//
+// These matchers can match either a protobuf value or a pointer to
+// it.  They make a copy of pb, and thus can out-live pb.  When the
+// match fails, the matchers print a detailed message (the value of
+// the actual protobuf, the value of the expected protobuf, and which
+// fields are different).
+//
+// This library also defines the following matcher transformer
+// functions in the ::android::proto namespace:
+//
+//   Approximately(m, margin, fraction)
+//                     The same as m, except that it compares
+//                     floating-point fields approximately (using
+//                     google::protobuf::util::MessageDifferencer's APPROXIMATE
+//                     comparison option).  m can be any of the
+//                     Equals* and EquivTo* protobuf matchers above. If margin
+//                     is specified, floats and doubles will be considered
+//                     approximately equal if they are within that margin, i.e.
+//                     abs(expected - actual) <= margin. If fraction is
+//                     specified, floats and doubles will be considered
+//                     approximately equal if they are within a fraction of
+//                     their magnitude, i.e. abs(expected - actual) <=
+//                     fraction * max(abs(expected), abs(actual)). Two fields
+//                     will be considered equal if they're within the fraction
+//                     _or_ within the margin, so omitting or setting the
+//                     fraction to 0.0 will only check against the margin.
+//                     Similarly, setting the margin to 0.0 will only check
+//                     using the fraction. If margin and fraction are omitted,
+//                     MathLimits<T>::kStdError for that type (T=float or
+//                     T=double) is used for both the margin and fraction.
+//   TreatingNaNsAsEqual(m)
+//                     The same as m, except that treats floating-point fields
+//                     that are NaN as equal. m can be any of the Equals* and
+//                     EquivTo* protobuf matchers above.
+//   IgnoringFields(fields, m)
+//                     The same as m, except the specified fields will be
+//                     ignored when matching (using
+//                     google::protobuf::util::MessageDifferencer::IgnoreField).
+//                     fields is represented as a container or an initializer
+//                     list of strings and each element is specified by their
+//                     fully qualified names, i.e., the names corresponding to
+//                     FieldDescriptor.full_name().  m can be
+//                     any of the Equals* and EquivTo* protobuf matchers above.
+//                     It can also be any of the transformer matchers listed
+//                     here (e.g. Approximately, TreatingNaNsAsEqual) as long as
+//                     the intent of the each concatenated matcher is mutually
+//                     exclusive (e.g. using IgnoringFields in conjunction with
+//                     Partially can have different results depending on whether
+//                     the fields specified in IgnoringFields is part of the
+//                     fields covered by Partially).
+//   IgnoringRepeatedFieldOrdering(m)
+//                     The same as m, except that it ignores the relative
+//                     ordering of elements within each repeated field in m.
+//                     See
+//                     google::protobuf::util::MessageDifferencer::TreatAsSet()
+//                     for more details.
+//   Partially(m)
+//                     The same as m, except that only fields present in
+//                     the expected protobuf are considered (using
+//                     google::protobuf::util::MessageDifferencer's PARTIAL
+//                     comparison option).   m can be any of the
+//                     Equals* and EquivTo* protobuf matchers above.
+//   WhenDeserialized(typed_pb_matcher)
+//                     The string argument is a serialization of a
+//                     protobuf that matches typed_pb_matcher.
+//                     typed_pb_matcher can be an Equals* or EquivTo*
+//                     protobuf matcher (possibly with Approximately()
+//                     or Partially() modifiers) where the type of the
+//                     protobuf is known at run time (e.g. it cannot
+//                     be EqualsProto("...") as it's unclear what type
+//                     the string represents).
+//   WhenDeserializedAs<PB>(pb_matcher)
+//                     Like WhenDeserialized(), except that the type
+//                     of the deserialized protobuf must be PB.  Since
+//                     the protobuf type is known, pb_matcher can be *any*
+//                     valid protobuf matcher, including EqualsProto("...").
+//
+// Approximately(), TreatingNaNsAsEqual(), Partially(), IgnoringFields(), and
+// IgnoringRepeatedFieldOrdering() can be combined (nested)
+// and the composition order is irrelevant:
+//
+//   Approximately(Partially(EquivToProto(pb)))
+// and
+//   Partially(Approximately(EquivToProto(pb)))
+// are the same thing.
+//
+// EXAMPLES
+// ========
+//
+//   using ::android::EqualsProto;
+//   using ::android::EquivToProto;
+//   using ::android::proto::Approximately;
+//   using ::android::proto::Partially;
+//   using ::android::proto::WhenDeserialized;
+//
+//   // my_pb.Equals(expected_pb).
+//   EXPECT_THAT(my_pb, EqualsProto(expected_pb));
+//
+//   // my_pb is equivalent to a protobuf whose foo field is 1 and
+//   // whose bar field is "x".
+//   EXPECT_THAT(my_pb, EquivToProto("foo: 1 "
+//                                   "bar: 'x'"));
+//
+//   // my_pb is equal to expected_pb, comparing all floating-point
+//   // fields approximately.
+//   EXPECT_THAT(my_pb, Approximately(EqualsProto(expected_pb)));
+//
+//   // my_pb is equivalent to expected_pb.  A field is ignored in the
+//   // comparison if it's present in my_pb but not in expected_pb.
+//   EXPECT_THAT(my_pb, Partially(EquivToProto(expected_pb)));
+//
+//   string data;
+//   my_pb.SerializeToString(&data);
+//   // data can be deserialized to a protobuf that equals expected_pb.
+//   EXPECT_THAT(data, WhenDeserialized(EqualsProto(expected_pb)));
+//   // The following line doesn't compile, as the matcher doesn't know
+//   // the type of the protobuf.
+//   // EXPECT_THAT(data, WhenDeserialized(EqualsProto("foo: 1")));
+
+#pragma once
+
+#include <initializer_list>
+#include <iostream>  // NOLINT
+#include <memory>
+#include <sstream>  // NOLINT
+#include <string>   // NOLINT
+#include <string_view>
+#include <vector>  // NOLINT
+
+#include "gmock/gmock-matchers.h"
+#include "gmock/gmock-more-matchers.h"
+#include "google/protobuf/descriptor.h"
+#include "google/protobuf/io/zero_copy_stream.h"
+#include "google/protobuf/io/zero_copy_stream_impl.h"
+#include "google/protobuf/io/zero_copy_stream_impl_lite.h"
+#include "google/protobuf/message.h"
+#include "google/protobuf/text_format.h"
+#include "google/protobuf/util/field_comparator.h"
+#include "google/protobuf/util/message_differencer.h"
+
+namespace android {
+
+namespace internal {
+
+// Utilities.
+
+// How to compare two fields (equal vs. equivalent).
+typedef google::protobuf::util::MessageDifferencer::MessageFieldComparison ProtoFieldComparison;
+
+// How to compare two floating-points (exact vs. approximate).
+typedef google::protobuf::util::DefaultFieldComparator::FloatComparison ProtoFloatComparison;
+
+// How to compare repeated fields (whether the order of elements matters).
+typedef google::protobuf::util::MessageDifferencer::RepeatedFieldComparison RepeatedFieldComparison;
+
+// Whether to compare all fields (full) or only fields present in the
+// expected protobuf (partial).
+typedef google::protobuf::util::MessageDifferencer::Scope ProtoComparisonScope;
+
+const ProtoFieldComparison kProtoEqual = google::protobuf::util::MessageDifferencer::EQUAL;
+const ProtoFieldComparison kProtoEquiv = google::protobuf::util::MessageDifferencer::EQUIVALENT;
+const ProtoFloatComparison kProtoExact = google::protobuf::util::DefaultFieldComparator::EXACT;
+const ProtoFloatComparison kProtoApproximate =
+    google::protobuf::util::DefaultFieldComparator::APPROXIMATE;
+const RepeatedFieldComparison kProtoCompareRepeatedFieldsRespectOrdering =
+    google::protobuf::util::MessageDifferencer::AS_LIST;
+const RepeatedFieldComparison kProtoCompareRepeatedFieldsIgnoringOrdering =
+    google::protobuf::util::MessageDifferencer::AS_SET;
+const ProtoComparisonScope kProtoFull = google::protobuf::util::MessageDifferencer::FULL;
+const ProtoComparisonScope kProtoPartial = google::protobuf::util::MessageDifferencer::PARTIAL;
+
+// Options for comparing two protobufs.
+struct ProtoComparison {
+    ProtoComparison()
+        : field_comp(kProtoEqual),
+          float_comp(kProtoExact),
+          treating_nan_as_equal(false),
+          has_custom_margin(false),
+          has_custom_fraction(false),
+          repeated_field_comp(kProtoCompareRepeatedFieldsRespectOrdering),
+          scope(kProtoFull),
+          float_margin(0.0),
+          float_fraction(0.0) {}
+
+    ProtoFieldComparison field_comp;
+    ProtoFloatComparison float_comp;
+    bool treating_nan_as_equal;
+    bool has_custom_margin;    // only used when float_comp = APPROXIMATE
+    bool has_custom_fraction;  // only used when float_comp = APPROXIMATE
+    RepeatedFieldComparison repeated_field_comp;
+    ProtoComparisonScope scope;
+    double float_margin;    // only used when has_custom_margin is set.
+    double float_fraction;  // only used when has_custom_fraction is set.
+    std::vector<std::string> ignore_fields;
+};
+
+// Whether the protobuf must be initialized.
+const bool kMustBeInitialized = true;
+const bool kMayBeUninitialized = false;
+
+// Parses the TextFormat representation of a protobuf, allowing required fields
+// to be missing.  Returns true iff successful.
+bool ParsePartialFromAscii(const std::string& pb_ascii, google::protobuf::Message* proto,
+                           std::string* error_text);
+
+// Returns a protobuf of type Proto by parsing the given TextFormat
+// representation of it.  Required fields can be missing, in which case the
+// returned protobuf will not be fully initialized.
+template <class Proto>
+Proto MakePartialProtoFromAscii(const std::string& str) {
+    Proto proto;
+    std::string error_text;
+    if (!ParsePartialFromAscii(str, &proto, &error_text)) {
+        std::cerr << "Failed to parse \"" << str << "\" as a " << proto.GetDescriptor()->full_name()
+                  << ":\n"
+                  << error_text;
+    }
+    return proto;
+}
+
+// Returns true iff p and q can be compared (i.e. have the same descriptor).
+bool ProtoComparable(const google::protobuf::Message& p, const google::protobuf::Message& q);
+
+// Returns true iff actual and expected are comparable and match.  The
+// comp argument specifies how the two are compared.
+bool ProtoCompare(const ProtoComparison& comp, const google::protobuf::Message& actual,
+                  const google::protobuf::Message& expected);
+
+// Overload for ProtoCompare where the expected message is specified as a text
+// proto.  If the text cannot be parsed as a message of the same type as the
+// actual message, a // DCHECK failure will cause the test to fail and no subsequent
+// tests will be run.
+template <typename Proto>
+inline bool ProtoCompare(const ProtoComparison& comp, const Proto& actual,
+                         const std::string& expected) {
+    return ProtoCompare(comp, actual, MakePartialProtoFromAscii<Proto>(expected));
+}
+
+// Describes the types of the expected and the actual protocol buffer.
+std::string DescribeTypes(const google::protobuf::Message& expected,
+                          const google::protobuf::Message& actual);
+
+// Prints the protocol buffer pointed to by proto.
+std::string PrintProtoPointee(const google::protobuf::Message* proto);
+
+// Describes the differences between the two protocol buffers.
+std::string DescribeDiff(const ProtoComparison& comp, const google::protobuf::Message& actual,
+                         const google::protobuf::Message& expected);
+
+// Common code for implementing EqualsProto, EquivToProto,
+// EqualsInitializedProto, and EquivToInitializedProto.
+class ProtoMatcherBase {
+   public:
+    ProtoMatcherBase(bool must_be_initialized,     // Must the argument be fully
+                                                   // initialized?
+                     const ProtoComparison& comp)  // How to compare the two protobufs.
+        : must_be_initialized_(must_be_initialized), comp_(new auto(comp)) {}
+
+    ProtoMatcherBase(const ProtoMatcherBase& other)
+        : must_be_initialized_(other.must_be_initialized_), comp_(new auto(*other.comp_)) {}
+
+    ProtoMatcherBase(ProtoMatcherBase&& other) = default;
+
+    virtual ~ProtoMatcherBase() {}
+
+    // Prints the expected protocol buffer.
+    virtual void PrintExpectedTo(::std::ostream* os) const = 0;
+
+    // Returns the expected value as a protobuf object; if the object
+    // cannot be created (e.g. in ProtoStringMatcher), explains why to
+    // 'listener' and returns NULL.  The caller must call
+    // DeleteExpectedProto() on the returned value later.
+    virtual const google::protobuf::Message* CreateExpectedProto(
+        const google::protobuf::Message& arg,  // For determining the type of the
+                                               // expected protobuf.
+        ::testing::MatchResultListener* listener) const = 0;
+
+    // Deletes the given expected protobuf, which must be obtained from
+    // a call to CreateExpectedProto() earlier.
+    virtual void DeleteExpectedProto(const google::protobuf::Message* expected) const = 0;
+
+    // Makes this matcher compare floating-points approximately.
+    void SetCompareApproximately() { comp_->float_comp = kProtoApproximate; }
+
+    // Makes this matcher treating NaNs as equal when comparing floating-points.
+    void SetCompareTreatingNaNsAsEqual() { comp_->treating_nan_as_equal = true; }
+
+    // Makes this matcher ignore string elements specified by their fully
+    // qualified names, i.e., names corresponding to
+    // FieldDescriptor.full_name().
+    template <class Iterator>
+    void AddCompareIgnoringFields(Iterator first, Iterator last) {
+        comp_->ignore_fields.insert(comp_->ignore_fields.end(), first, last);
+    }
+
+    // Makes this matcher compare repeated fields ignoring ordering of elements.
+    void SetCompareRepeatedFieldsIgnoringOrdering() {
+        comp_->repeated_field_comp = kProtoCompareRepeatedFieldsIgnoringOrdering;
+    }
+
+    // Sets the margin of error for approximate floating point comparison.
+    void SetMargin(double margin) {
+        comp_->has_custom_margin = true;
+        comp_->float_margin = margin;
+    }
+
+    // Sets the relative fraction of error for approximate floating point
+    // comparison.
+    void SetFraction(double fraction) {
+        comp_->has_custom_fraction = true;
+        comp_->float_fraction = fraction;
+    }
+
+    // Makes this matcher compare protobufs partially.
+    void SetComparePartially() { comp_->scope = kProtoPartial; }
+
+    bool MatchAndExplain(const google::protobuf::Message& arg,
+                         ::testing::MatchResultListener* listener) const {
+        return MatchAndExplain(arg, false, listener);
+    }
+
+    bool MatchAndExplain(const google::protobuf::Message* arg,
+                         ::testing::MatchResultListener* listener) const {
+        return (arg != NULL) && MatchAndExplain(*arg, true, listener);
+    }
+
+    // Describes the expected relation between the actual protobuf and
+    // the expected one.
+    void DescribeRelationToExpectedProto(::std::ostream* os) const {
+        if (comp_->repeated_field_comp == kProtoCompareRepeatedFieldsIgnoringOrdering) {
+            *os << "(ignoring repeated field ordering) ";
+        }
+        if (!comp_->ignore_fields.empty()) {
+            *os << "(ignoring fields: ";
+            const char* sep = "";
+            for (size_t i = 0; i < comp_->ignore_fields.size(); ++i, sep = ", ")
+                *os << sep << comp_->ignore_fields[i];
+            *os << ") ";
+        }
+        if (comp_->float_comp == kProtoApproximate) {
+            *os << "approximately ";
+            if (comp_->has_custom_margin || comp_->has_custom_fraction) {
+                *os << "(";
+                if (comp_->has_custom_margin) {
+                    std::stringstream ss;
+                    ss << std::setprecision(std::numeric_limits<double>::digits10 + 2)
+                       << comp_->float_margin;
+                    *os << "absolute error of float or double fields <= " << ss.str();
+                }
+                if (comp_->has_custom_margin && comp_->has_custom_fraction) {
+                    *os << " or ";
+                }
+                if (comp_->has_custom_fraction) {
+                    std::stringstream ss;
+                    ss << std::setprecision(std::numeric_limits<double>::digits10 + 2)
+                       << comp_->float_fraction;
+                    *os << "relative error of float or double fields <= " << ss.str();
+                }
+                *os << ") ";
+            }
+        }
+
+        *os << (comp_->scope == kProtoPartial ? "partially " : "")
+            << (comp_->field_comp == kProtoEqual ? "equal" : "equivalent")
+            << (comp_->treating_nan_as_equal ? " (treating NaNs as equal)" : "") << " to ";
+        PrintExpectedTo(os);
+    }
+
+    void DescribeTo(::std::ostream* os) const {
+        *os << "is " << (must_be_initialized_ ? "fully initialized and " : "");
+        DescribeRelationToExpectedProto(os);
+    }
+
+    void DescribeNegationTo(::std::ostream* os) const {
+        *os << "is " << (must_be_initialized_ ? "not fully initialized or " : "") << "not ";
+        DescribeRelationToExpectedProto(os);
+    }
+
+    bool must_be_initialized() const { return must_be_initialized_; }
+
+    const ProtoComparison& comp() const { return *comp_; }
+
+   private:
+    bool MatchAndExplain(const google::protobuf::Message& arg, bool is_matcher_for_pointer,
+                         ::testing::MatchResultListener* listener) const;
+
+    const bool must_be_initialized_;
+    std::unique_ptr<ProtoComparison> comp_;
+};
+
+// Returns a copy of the given proto2 message.
+inline google::protobuf::Message* CloneProto2(const google::protobuf::Message& src) {
+    google::protobuf::Message* clone = src.New();
+    clone->CopyFrom(src);
+    return clone;
+}
+
+// Implements EqualsProto, EquivToProto, EqualsInitializedProto, and
+// EquivToInitializedProto, where the matcher parameter is a protobuf.
+class ProtoMatcher : public ProtoMatcherBase {
+   public:
+    ProtoMatcher(const google::protobuf::Message& expected,  // The expected protobuf.
+                 bool must_be_initialized,                   // Must the argument be fully
+                                                             // initialized?
+                 const ProtoComparison& comp)                // How to compare the two protobufs.
+        : ProtoMatcherBase(must_be_initialized, comp), expected_(CloneProto2(expected)) {
+        if (must_be_initialized) {
+            if (expected.IsInitialized()) {
+                std::cerr << "The protocol buffer given to *InitializedProto() "
+                          << "must itself be initialized, but the following required "
+                             "fields "
+                          << "are missing: " << expected.InitializationErrorString() << ".";
+            }
+        }
+    }
+
+    virtual void PrintExpectedTo(::std::ostream* os) const {
+        *os << expected_->GetDescriptor()->full_name() << " ";
+        ::testing::internal::UniversalPrint(*expected_, os);
+    }
+
+    virtual const google::protobuf::Message* CreateExpectedProto(
+        const google::protobuf::Message& /* arg */,
+        ::testing::MatchResultListener* /* listener */) const {
+        return expected_.get();
+    }
+
+    virtual void DeleteExpectedProto(const google::protobuf::Message* expected) const {}
+
+    const std::shared_ptr<const google::protobuf::Message>& expected() const { return expected_; }
+
+   private:
+    const std::shared_ptr<const google::protobuf::Message> expected_;
+};
+
+// Implements EqualsProto, EquivToProto, EqualsInitializedProto, and
+// EquivToInitializedProto, where the matcher parameter is a string.
+class ProtoStringMatcher : public ProtoMatcherBase {
+   public:
+    ProtoStringMatcher(const std::string& expected,  // The text representing the expected protobuf.
+                       bool must_be_initialized,     // Must the argument be fully
+                                                     // initialized?
+                       const ProtoComparison comp)   // How to compare the two protobufs.
+        : ProtoMatcherBase(must_be_initialized, comp), expected_(expected) {}
+
+    // Parses the expected string as a protobuf of the same type as arg,
+    // and returns the parsed protobuf (or NULL when the parse fails).
+    // The caller must call DeleteExpectedProto() on the return value
+    // later.
+    virtual const google::protobuf::Message* CreateExpectedProto(
+        const google::protobuf::Message& arg, ::testing::MatchResultListener* listener) const {
+        google::protobuf::Message* expected_proto = arg.New();
+        // We don't insist that the expected string parses as an
+        // *initialized* protobuf.  Otherwise EqualsProto("...") may
+        // wrongfully fail when the actual protobuf is not fully
+        // initialized.  If the user wants to ensure that the actual
+        // protobuf is initialized, they should use
+        // EqualsInitializedProto("...") instead of EqualsProto("..."),
+        // and the MatchAndExplain() function in ProtoMatcherBase will
+        // enforce it.
+        std::string error_text;
+        if (ParsePartialFromAscii(expected_, expected_proto, &error_text)) {
+            return expected_proto;
+        } else {
+            delete expected_proto;
+            if (listener->IsInterested()) {
+                *listener << "where ";
+                PrintExpectedTo(listener->stream());
+                *listener << " doesn't parse as a " << arg.GetDescriptor()->full_name() << ":\n"
+                          << error_text;
+            }
+            return NULL;
+        }
+    }
+
+    virtual void DeleteExpectedProto(const google::protobuf::Message* expected) const {
+        delete expected;
+    }
+
+    virtual void PrintExpectedTo(::std::ostream* os) const { *os << "<" << expected_ << ">"; }
+
+   private:
+    const std::string expected_;
+};
+
+typedef ::testing::PolymorphicMatcher<ProtoMatcher> PolymorphicProtoMatcher;
+
+// Common code for implementing WhenDeserialized(proto_matcher) and
+// WhenDeserializedAs<PB>(proto_matcher).
+template <class Proto>
+class WhenDeserializedMatcherBase {
+   public:
+    typedef ::testing::Matcher<const Proto&> InnerMatcher;
+
+    explicit WhenDeserializedMatcherBase(const InnerMatcher& proto_matcher)
+        : proto_matcher_(proto_matcher) {}
+
+    virtual ~WhenDeserializedMatcherBase() {}
+
+    // Creates an empty protobuf with the expected type.
+    virtual Proto* MakeEmptyProto() const = 0;
+
+    // Type name of the expected protobuf.
+    virtual std::string ExpectedTypeName() const = 0;
+
+    // Name of the type argument given to WhenDeserializedAs<>(), or
+    // "protobuf" for WhenDeserialized().
+    virtual std::string TypeArgName() const = 0;
+
+    // Deserializes the string as a protobuf of the same type as the expected
+    // protobuf.
+    Proto* Deserialize(google::protobuf::io::ZeroCopyInputStream* input) const {
+        Proto* proto = MakeEmptyProto();
+        // ParsePartialFromString() parses a serialized representation of a
+        // protobuf, allowing required fields to be missing.  This means
+        // that we don't insist on the parsed protobuf being fully
+        // initialized.  This allows the user to choose whether it should
+        // be initialized using EqualsProto vs EqualsInitializedProto, for
+        // example.
+        if (proto->ParsePartialFromZeroCopyStream(input)) {
+            return proto;
+        } else {
+            delete proto;
+            return NULL;
+        }
+    }
+
+    void DescribeTo(::std::ostream* os) const {
+        *os << "can be deserialized as a " << TypeArgName() << " that ";
+        proto_matcher_.DescribeTo(os);
+    }
+
+    void DescribeNegationTo(::std::ostream* os) const {
+        *os << "cannot be deserialized as a " << TypeArgName() << " that ";
+        proto_matcher_.DescribeTo(os);
+    }
+
+    bool MatchAndExplain(google::protobuf::io::ZeroCopyInputStream* arg,
+                         ::testing::MatchResultListener* listener) const {
+        // Deserializes the string arg as a protobuf of the same type as the
+        // expected protobuf.
+        ::std::unique_ptr<const Proto> deserialized_arg(Deserialize(arg));
+        if (!listener->IsInterested()) {
+            // No need to explain the match result.
+            return (deserialized_arg != NULL) && proto_matcher_.Matches(*deserialized_arg);
+        }
+
+        ::std::ostream* const os = listener->stream();
+        if (deserialized_arg == NULL) {
+            *os << "which cannot be deserialized as a " << ExpectedTypeName();
+            return false;
+        }
+
+        *os << "which deserializes to ";
+        UniversalPrint(*deserialized_arg, os);
+
+        ::testing::StringMatchResultListener inner_listener;
+        const bool match = proto_matcher_.MatchAndExplain(*deserialized_arg, &inner_listener);
+        const std::string explain = inner_listener.str();
+        if (explain != "") {
+            *os << ",\n" << explain;
+        }
+
+        return match;
+    }
+
+    bool MatchAndExplain(const std::string& str, ::testing::MatchResultListener* listener) const {
+        google::protobuf::io::ArrayInputStream input(str.data(), str.size());
+        return MatchAndExplain(&input, listener);
+    }
+
+    bool MatchAndExplain(std::string_view sp, ::testing::MatchResultListener* listener) const {
+        google::protobuf::io::ArrayInputStream input(sp.data(), sp.size());
+        return MatchAndExplain(&input, listener);
+    }
+
+    bool MatchAndExplain(const char* str, ::testing::MatchResultListener* listener) const {
+        google::protobuf::io::ArrayInputStream input(str, strlen(str));
+        return MatchAndExplain(&input, listener);
+    }
+
+   private:
+    const InnerMatcher proto_matcher_;
+};
+
+// Implements WhenDeserialized(proto_matcher).
+class WhenDeserializedMatcher : public WhenDeserializedMatcherBase<google::protobuf::Message> {
+                                public
+    : explicit WhenDeserializedMatcher(const PolymorphicProtoMatcher& proto_matcher)
+    : WhenDeserializedMatcherBase<google::protobuf::Message>(proto_matcher),
+      expected_proto_(proto_matcher.impl().expected()) {}
+
+virtual google::protobuf::Message* MakeEmptyProto() const { return expected_proto_->New(); }
+
+virtual std::string ExpectedTypeName() const {
+    return expected_proto_->GetDescriptor()->full_name();
+}
+
+virtual std::string TypeArgName() const { return "protobuf"; }
+
+private:
+// The expected protobuf specified in the inner matcher
+// (proto_matcher_).  We only need a std::shared_ptr to it instead of
+// making a copy, as the expected protobuf will never be changed
+// once created.
+const std::shared_ptr<const google::protobuf::Message> expected_proto_;
+};
+
+// Implements WhenDeserializedAs<Proto>(proto_matcher).
+template <class Proto>
+class WhenDeserializedAsMatcher : public WhenDeserializedMatcherBase<Proto> {
+   public:
+    typedef ::testing::Matcher<const Proto&> InnerMatcher;
+
+    explicit WhenDeserializedAsMatcher(const InnerMatcher& inner_matcher)
+        : WhenDeserializedMatcherBase<Proto>(inner_matcher) {}
+
+    virtual Proto* MakeEmptyProto() const { return new Proto; }
+
+    virtual std::string ExpectedTypeName() const { return Proto().GetDescriptor()->full_name(); }
+
+    virtual std::string TypeArgName() const { return ExpectedTypeName(); }
+};
+
+// Implements the IsInitializedProto matcher, which is used to verify that a
+// protocol buffer is valid using the IsInitialized method.
+class IsInitializedProtoMatcher {
+   public:
+    void DescribeTo(::std::ostream* os) const { *os << "is a fully initialized protocol buffer"; }
+
+    void DescribeNegationTo(::std::ostream* os) const {
+        *os << "is not a fully initialized protocol buffer";
+    }
+
+    template <typename T>
+    bool MatchAndExplain(T& arg,  // NOLINT
+                         ::testing::MatchResultListener* listener) const {
+        if (!arg.IsInitialized()) {
+            *listener << "which is missing the following required fields: "
+                      << arg.InitializationErrorString();
+            return false;
+        }
+        return true;
+    }
+
+    // It's critical for this overload to take a T* instead of a const
+    // T*.  Otherwise the other version would be a better match when arg
+    // is a pointer to a non-const value.
+    template <typename T>
+    bool MatchAndExplain(T* arg, ::testing::MatchResultListener* listener) const {
+        if (listener->IsInterested() && arg != NULL) {
+            *listener << PrintProtoPointee(arg);
+        }
+        if (arg == NULL) {
+            *listener << "which is null";
+            return false;
+        } else if (!arg->IsInitialized()) {
+            *listener << ", which is missing the following required fields: "
+                      << arg->InitializationErrorString();
+            return false;
+        } else {
+            return true;
+        }
+    }
+};
+
+// Implements EqualsProto and EquivToProto for 2-tuple matchers.
+class TupleProtoMatcher {
+   public:
+    explicit TupleProtoMatcher(const ProtoComparison& comp) : comp_(new auto(comp)) {}
+
+    TupleProtoMatcher(const TupleProtoMatcher& other) : comp_(new auto(*other.comp_)) {}
+    TupleProtoMatcher(TupleProtoMatcher&& other) = default;
+
+    template <typename T1, typename T2>
+    operator ::testing::Matcher<::testing::tuple<T1, T2>>() const {
+        return MakeMatcher(new Impl<::testing::tuple<T1, T2>>(*comp_));
+    }
+    template <typename T1, typename T2>
+    operator ::testing::Matcher<const ::testing::tuple<T1, T2>&>() const {
+        return MakeMatcher(new Impl<const ::testing::tuple<T1, T2>&>(*comp_));
+    }
+
+    // Allows matcher transformers, e.g., Approximately(), Partially(), etc. to
+    // change the behavior of this 2-tuple matcher.
+    TupleProtoMatcher& mutable_impl() { return *this; }
+
+    // Makes this matcher compare floating-points approximately.
+    void SetCompareApproximately() { comp_->float_comp = kProtoApproximate; }
+
+    // Makes this matcher treating NaNs as equal when comparing floating-points.
+    void SetCompareTreatingNaNsAsEqual() { comp_->treating_nan_as_equal = true; }
+
+    // Makes this matcher ignore string elements specified by their fully
+    // qualified names, i.e., names corresponding to
+    // FieldDescriptor.full_name().
+    template <class Iterator>
+    void AddCompareIgnoringFields(Iterator first, Iterator last) {
+        comp_->ignore_fields.insert(comp_->ignore_fields.end(), first, last);
+    }
+
+    // Makes this matcher compare repeated fields ignoring ordering of elements.
+    void SetCompareRepeatedFieldsIgnoringOrdering() {
+        comp_->repeated_field_comp = kProtoCompareRepeatedFieldsIgnoringOrdering;
+    }
+
+    // Sets the margin of error for approximate floating point comparison.
+    void SetMargin(double margin) {
+        // DCHECK(margin >= 0.0) << "Using a negative margin for Approximately";
+        comp_->has_custom_margin = true;
+        comp_->float_margin = margin;
+    }
+
+    // Sets the relative fraction of error for approximate floating point
+    // comparison.
+    void SetFraction(double fraction) {
+        comp_->has_custom_fraction = true;
+        comp_->float_fraction = fraction;
+    }
+
+    // Makes this matcher compares protobufs partially.
+    void SetComparePartially() { comp_->scope = kProtoPartial; }
+
+   private:
+    template <typename Tuple>
+    class Impl : public ::testing::MatcherInterface<Tuple> {
+       public:
+        explicit Impl(const ProtoComparison& comp) : comp_(comp) {}
+        virtual bool MatchAndExplain(Tuple args,
+                                     ::testing::MatchResultListener* /* listener */) const {
+            using ::testing::get;
+            return ProtoCompare(comp_, get<0>(args), get<1>(args));
+        }
+        virtual void DescribeTo(::std::ostream* os) const {
+            *os << (comp_.field_comp == kProtoEqual ? "are equal" : "are equivalent");
+        }
+        virtual void DescribeNegationTo(::std::ostream* os) const {
+            *os << (comp_.field_comp == kProtoEqual ? "are not equal" : "are not equivalent");
+        }
+
+       private:
+        const ProtoComparison comp_;
+    };
+
+    std::unique_ptr<ProtoComparison> comp_;
+};
+
+}  // namespace internal
+
+// Creates a polymorphic matcher that matches a 2-tuple where
+// first.Equals(second) is true.
+inline internal::TupleProtoMatcher EqualsProto() {
+    internal::ProtoComparison comp;
+    comp.field_comp = internal::kProtoEqual;
+    return internal::TupleProtoMatcher(comp);
+}
+
+// Creates a polymorphic matcher that matches a 2-tuple where
+// first.Equivalent(second) is true.
+inline internal::TupleProtoMatcher EquivToProto() {
+    internal::ProtoComparison comp;
+    comp.field_comp = internal::kProtoEquiv;
+    return internal::TupleProtoMatcher(comp);
+}
+
+// Constructs a matcher that matches the argument if
+// argument.Equals(x) or argument->Equals(x) returns true.
+inline internal::PolymorphicProtoMatcher EqualsProto(const google::protobuf::Message& x) {
+    internal::ProtoComparison comp;
+    comp.field_comp = internal::kProtoEqual;
+    return ::testing::MakePolymorphicMatcher(
+        internal::ProtoMatcher(x, internal::kMayBeUninitialized, comp));
+}
+inline ::testing::PolymorphicMatcher<internal::ProtoStringMatcher> EqualsProto(
+    const std::string& x) {
+    internal::ProtoComparison comp;
+    comp.field_comp = internal::kProtoEqual;
+    return ::testing::MakePolymorphicMatcher(
+        internal::ProtoStringMatcher(x, internal::kMayBeUninitialized, comp));
+}
+template <class Proto>
+inline internal::PolymorphicProtoMatcher EqualsProto(const std::string& str) {
+    return EqualsProto(internal::MakePartialProtoFromAscii<Proto>(str));
+}
+
+// Constructs a matcher that matches the argument if
+// argument.Equivalent(x) or argument->Equivalent(x) returns true.
+inline internal::PolymorphicProtoMatcher EquivToProto(const google::protobuf::Message& x) {
+    internal::ProtoComparison comp;
+    comp.field_comp = internal::kProtoEquiv;
+    return ::testing::MakePolymorphicMatcher(
+        internal::ProtoMatcher(x, internal::kMayBeUninitialized, comp));
+}
+inline ::testing::PolymorphicMatcher<internal::ProtoStringMatcher> EquivToProto(
+    const std::string& x) {
+    internal::ProtoComparison comp;
+    comp.field_comp = internal::kProtoEquiv;
+    return ::testing::MakePolymorphicMatcher(
+        internal::ProtoStringMatcher(x, internal::kMayBeUninitialized, comp));
+}
+template <class Proto>
+inline internal::PolymorphicProtoMatcher EquivToProto(const std::string& str) {
+    return EquivToProto(internal::MakePartialProtoFromAscii<Proto>(str));
+}
+
+// Constructs a matcher that matches the argument if
+// argument.IsInitialized() or argument->IsInitialized() returns true.
+inline ::testing::PolymorphicMatcher<internal::IsInitializedProtoMatcher> IsInitializedProto() {
+    return ::testing::MakePolymorphicMatcher(internal::IsInitializedProtoMatcher());
+}
+
+// Constructs a matcher that matches an argument whose IsInitialized()
+// and Equals(x) methods both return true.  The argument can be either
+// a protocol buffer or a pointer to it.
+inline internal::PolymorphicProtoMatcher EqualsInitializedProto(
+    const google::protobuf::Message& x) {
+    internal::ProtoComparison comp;
+    comp.field_comp = internal::kProtoEqual;
+    return ::testing::MakePolymorphicMatcher(
+        internal::ProtoMatcher(x, internal::kMustBeInitialized, comp));
+}
+inline ::testing::PolymorphicMatcher<internal::ProtoStringMatcher> EqualsInitializedProto(
+    const std::string& x) {
+    internal::ProtoComparison comp;
+    comp.field_comp = internal::kProtoEqual;
+    return ::testing::MakePolymorphicMatcher(
+        internal::ProtoStringMatcher(x, internal::kMustBeInitialized, comp));
+}
+template <class Proto>
+inline internal::PolymorphicProtoMatcher EqualsInitializedProto(const std::string& str) {
+    return EqualsInitializedProto(internal::MakePartialProtoFromAscii<Proto>(str));
+}
+
+// Constructs a matcher that matches an argument whose IsInitialized()
+// and Equivalent(x) methods both return true.  The argument can be
+// either a protocol buffer or a pointer to it.
+inline internal::PolymorphicProtoMatcher EquivToInitializedProto(
+    const google::protobuf::Message& x) {
+    internal::ProtoComparison comp;
+    comp.field_comp = internal::kProtoEquiv;
+    return ::testing::MakePolymorphicMatcher(
+        internal::ProtoMatcher(x, internal::kMustBeInitialized, comp));
+}
+inline ::testing::PolymorphicMatcher<internal::ProtoStringMatcher> EquivToInitializedProto(
+    const std::string& x) {
+    internal::ProtoComparison comp;
+    comp.field_comp = internal::kProtoEquiv;
+    return ::testing::MakePolymorphicMatcher(
+        internal::ProtoStringMatcher(x, internal::kMustBeInitialized, comp));
+}
+template <class Proto>
+inline internal::PolymorphicProtoMatcher EquivToInitializedProto(const std::string& str) {
+    return EquivToInitializedProto(internal::MakePartialProtoFromAscii<Proto>(str));
+}
+
+namespace proto {
+
+// Approximately(m) returns a matcher that is the same as m, except
+// that it compares floating-point fields approximately (using
+// google::protobuf::util::MessageDifferencer's APPROXIMATE comparison option).
+// The inner matcher m can be any of the Equals* and EquivTo* protobuf
+// matchers above.
+template <class InnerProtoMatcher>
+inline InnerProtoMatcher Approximately(InnerProtoMatcher inner_proto_matcher) {
+    inner_proto_matcher.mutable_impl().SetCompareApproximately();
+    return inner_proto_matcher;
+}
+
+// Alternative version of Approximately which takes an explicit margin of error.
+template <class InnerProtoMatcher>
+inline InnerProtoMatcher Approximately(InnerProtoMatcher inner_proto_matcher, double margin) {
+    inner_proto_matcher.mutable_impl().SetCompareApproximately();
+    inner_proto_matcher.mutable_impl().SetMargin(margin);
+    return inner_proto_matcher;
+}
+
+// Alternative version of Approximately which takes an explicit margin of error
+// and a relative fraction of error and will match if either is satisfied.
+template <class InnerProtoMatcher>
+inline InnerProtoMatcher Approximately(InnerProtoMatcher inner_proto_matcher, double margin,
+                                       double fraction) {
+    inner_proto_matcher.mutable_impl().SetCompareApproximately();
+    inner_proto_matcher.mutable_impl().SetMargin(margin);
+    inner_proto_matcher.mutable_impl().SetFraction(fraction);
+    return inner_proto_matcher;
+}
+
+// TreatingNaNsAsEqual(m) returns a matcher that is the same as m, except that
+// it compares floating-point fields such that NaNs are equal.
+// The inner matcher m can be any of the Equals* and EquivTo* protobuf matchers
+// above.
+template <class InnerProtoMatcher>
+inline InnerProtoMatcher TreatingNaNsAsEqual(InnerProtoMatcher inner_proto_matcher) {
+    inner_proto_matcher.mutable_impl().SetCompareTreatingNaNsAsEqual();
+    return inner_proto_matcher;
+}
+
+// IgnoringFields(fields, m) returns a matcher that is the same as m, except the
+// specified fields will be ignored when matching
+// (using google::protobuf::util::MessageDifferencer::IgnoreField). Each element
+// in fields are specified by their fully qualified names, i.e., the names
+// corresponding to FieldDescriptor.full_name(). (e.g.
+// testing.internal.FooProto2.member). m can be any of the Equals* and EquivTo*
+// protobuf matchers above. It can also be any of the transformer matchers
+// listed here (e.g. Approximately, TreatingNaNsAsEqual) as long as the intent
+// of the each concatenated matcher is mutually exclusive (e.g. using
+// IgnoringFields in conjunction with Partially can have different results
+// depending on whether the fields specified in IgnoringFields is part of the
+// fields covered by Partially).
+template <class InnerProtoMatcher, class Container>
+inline InnerProtoMatcher IgnoringFields(const Container& ignore_fields,
+                                        InnerProtoMatcher inner_proto_matcher) {
+    inner_proto_matcher.mutable_impl().AddCompareIgnoringFields(ignore_fields.begin(),
+                                                                ignore_fields.end());
+    return inner_proto_matcher;
+}
+
+#ifdef LANG_CXX11
+template <class InnerProtoMatcher, class T>
+inline InnerProtoMatcher IgnoringFields(std::initializer_list<T> il,
+                                        InnerProtoMatcher inner_proto_matcher) {
+    inner_proto_matcher.mutable_impl().AddCompareIgnoringFields(il.begin(), il.end());
+    return inner_proto_matcher;
+}
+#endif  // LANG_CXX11
+
+// IgnoringRepeatedFieldOrdering(m) returns a matcher that is the same as m,
+// except that it ignores the relative ordering of elements within each repeated
+// field in m. See google::protobuf::MessageDifferencer::TreatAsSet() for more
+// details.
+template <class InnerProtoMatcher>
+inline InnerProtoMatcher IgnoringRepeatedFieldOrdering(InnerProtoMatcher inner_proto_matcher) {
+    inner_proto_matcher.mutable_impl().SetCompareRepeatedFieldsIgnoringOrdering();
+    return inner_proto_matcher;
+}
+
+// Partially(m) returns a matcher that is the same as m, except that
+// only fields present in the expected protobuf are considered (using
+// google::protobuf::util::MessageDifferencer's PARTIAL comparison option).  For
+// example, Partially(EqualsProto(p)) will ignore any field that's
+// not set in p when comparing the protobufs. The inner matcher m can
+// be any of the Equals* and EquivTo* protobuf matchers above.
+template <class InnerProtoMatcher>
+inline InnerProtoMatcher Partially(InnerProtoMatcher inner_proto_matcher) {
+    inner_proto_matcher.mutable_impl().SetComparePartially();
+    return inner_proto_matcher;
+}
+
+// WhenDeserialized(m) is a matcher that matches a string that can be
+// deserialized as a protobuf that matches m.  m must be a protobuf
+// matcher where the expected protobuf type is known at run time.
+inline ::testing::PolymorphicMatcher<internal::WhenDeserializedMatcher> WhenDeserialized(
+    const internal::PolymorphicProtoMatcher& proto_matcher) {
+    return ::testing::MakePolymorphicMatcher(internal::WhenDeserializedMatcher(proto_matcher));
+}
+
+// WhenDeserializedAs<Proto>(m) is a matcher that matches a string
+// that can be deserialized as a protobuf of type Proto that matches
+// m, which can be any valid protobuf matcher.
+template <class Proto, class InnerMatcher>
+inline ::testing::PolymorphicMatcher<internal::WhenDeserializedAsMatcher<Proto>> WhenDeserializedAs(
+    const InnerMatcher& inner_matcher) {
+    return MakePolymorphicMatcher(internal::WhenDeserializedAsMatcher<Proto>(
+        ::testing::SafeMatcherCast<const Proto&>(inner_matcher)));
+}
+
+}  // namespace proto
+}  // namespace android
diff --git a/base/ring_buffer.cpp b/base/ring_buffer.cpp
index afddc3f..96558c1 100644
--- a/base/ring_buffer.cpp
+++ b/base/ring_buffer.cpp
@@ -1,16 +1,7 @@
-// Copyright 2018 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-// http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
+/*
+ * Copyright 2018 Google
+ * SPDX-License-Identifier: MIT
+ */
 #include "aemu/base/ring_buffer.h"
 
 #include <errno.h>
diff --git a/base/testing/ProtobufMatchers.cpp b/base/testing/ProtobufMatchers.cpp
new file mode 100644
index 0000000..bad42da
--- /dev/null
+++ b/base/testing/ProtobufMatchers.cpp
@@ -0,0 +1,240 @@
+/*
+ * Copyright 2018 Google Inc.
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
+#include "aemu/base/testing/ProtobufMatchers.h"
+
+#include <algorithm>
+#include <regex>
+#include <string>
+#include <string_view>
+
+#include "absl/log/check.h"
+#include "gmock/gmock-matchers.h"
+#include "gmock/gmock-more-matchers.h"
+#include "google/protobuf/descriptor.h"
+#include "google/protobuf/io/tokenizer.h"
+#include "google/protobuf/message.h"
+#include "google/protobuf/text_format.h"
+#include "google/protobuf/util/message_differencer.h"
+
+namespace android {
+namespace internal {
+
+// Utilities.
+using google::protobuf::io::ColumnNumber;
+
+class StringErrorCollector : public google::protobuf::io::ErrorCollector {
+   public:
+    explicit StringErrorCollector(std::string* error_text) : error_text_(error_text) {}
+
+    void RecordError(int line, ColumnNumber column, absl::string_view message) override {
+        std::ostringstream ss;
+        ss << "ERROR: " << line << "(" << column << ")" << message << "\n";
+        *error_text_ += ss.str();
+    }
+
+    void RecordWarning(int line, ColumnNumber column, absl::string_view message) override {
+        std::ostringstream ss;
+        ss << "WARNING: " << line << "(" << column << ")" << message << "\n";
+        *error_text_ += ss.str();
+    }
+
+   private:
+    std::string* error_text_;
+    StringErrorCollector(const StringErrorCollector&) = delete;
+    StringErrorCollector& operator=(const StringErrorCollector&) = delete;
+};
+
+bool ParsePartialFromAscii(const std::string& pb_ascii, google::protobuf::Message* proto,
+                           std::string* error_text) {
+    google::protobuf::TextFormat::Parser parser;
+    StringErrorCollector collector(error_text);
+    parser.RecordErrorsTo(&collector);
+    parser.AllowPartialMessage(true);
+    return parser.ParseFromString(pb_ascii, proto);
+}
+
+// Returns true iff p and q can be compared (i.e. have the same descriptor).
+bool ProtoComparable(const google::protobuf::Message& p, const google::protobuf::Message& q) {
+    return p.GetDescriptor() == q.GetDescriptor();
+}
+
+template <typename Container>
+std::string JoinStringPieces(const Container& strings, std::string_view separator) {
+    std::stringstream stream;
+    std::string_view sep = "";
+    for (const std::string_view str : strings) {
+        stream << sep << str;
+        sep = separator;
+    }
+    return stream.str();
+}
+
+// Find all the descriptors for the ignore_fields.
+std::vector<const google::protobuf::FieldDescriptor*> GetFieldDescriptors(
+    const google::protobuf::Descriptor* proto_descriptor,
+    const std::vector<std::string>& ignore_fields) {
+    std::vector<const google::protobuf::FieldDescriptor*> ignore_descriptors;
+    std::vector<std::string_view> remaining_descriptors;
+
+    const google::protobuf::DescriptorPool* pool = proto_descriptor->file()->pool();
+    for (const std::string& name : ignore_fields) {
+        if (const google::protobuf::FieldDescriptor* field = pool->FindFieldByName(name)) {
+            ignore_descriptors.push_back(field);
+        } else {
+            remaining_descriptors.push_back(name);
+        }
+    }
+
+    DCHECK(remaining_descriptors.empty())
+        << "Could not find fields for proto " << proto_descriptor->full_name()
+        << " with fully qualified names: " << JoinStringPieces(remaining_descriptors, ",");
+    return ignore_descriptors;
+}
+
+// Sets the ignored fields corresponding to ignore_fields in differencer. Dies
+// if any is invalid.
+void SetIgnoredFieldsOrDie(const google::protobuf::Descriptor& root_descriptor,
+                           const std::vector<std::string>& ignore_fields,
+                           google::protobuf::util::MessageDifferencer* differencer) {
+    if (!ignore_fields.empty()) {
+        std::vector<const google::protobuf::FieldDescriptor*> ignore_descriptors =
+            GetFieldDescriptors(&root_descriptor, ignore_fields);
+        for (std::vector<const google::protobuf::FieldDescriptor*>::iterator it =
+                 ignore_descriptors.begin();
+             it != ignore_descriptors.end(); ++it) {
+            differencer->IgnoreField(*it);
+        }
+    }
+}
+
+// Configures a MessageDifferencer and DefaultFieldComparator to use the logic
+// described in comp. The configured differencer is the output of this function,
+// but a FieldComparator must be provided to keep ownership clear.
+void ConfigureDifferencer(const internal::ProtoComparison& comp,
+                          google::protobuf::util::DefaultFieldComparator* comparator,
+                          google::protobuf::util::MessageDifferencer* differencer,
+                          const google::protobuf::Descriptor* descriptor) {
+    differencer->set_message_field_comparison(comp.field_comp);
+    differencer->set_scope(comp.scope);
+    comparator->set_float_comparison(comp.float_comp);
+    comparator->set_treat_nan_as_equal(comp.treating_nan_as_equal);
+    differencer->set_repeated_field_comparison(comp.repeated_field_comp);
+    SetIgnoredFieldsOrDie(*descriptor, comp.ignore_fields, differencer);
+    if (comp.float_comp == internal::kProtoApproximate &&
+        (comp.has_custom_margin || comp.has_custom_fraction)) {
+        // Two fields will be considered equal if they're within the fraction
+        // _or_ within the margin. So setting the fraction to 0.0 makes this
+        // effectively a "SetMargin". Similarly, setting the margin to 0.0 makes
+        // this effectively a "SetFraction".
+        comparator->SetDefaultFractionAndMargin(comp.float_fraction, comp.float_margin);
+    }
+    differencer->set_field_comparator(comparator);
+}
+
+// Returns true iff actual and expected are comparable and match.  The
+// comp argument specifies how two are compared.
+bool ProtoCompare(const internal::ProtoComparison& comp, const google::protobuf::Message& actual,
+                  const google::protobuf::Message& expected) {
+    if (!ProtoComparable(actual, expected)) return false;
+
+    google::protobuf::util::MessageDifferencer differencer;
+    google::protobuf::util::DefaultFieldComparator field_comparator;
+    ConfigureDifferencer(comp, &field_comparator, &differencer, actual.GetDescriptor());
+
+    // It's important for 'expected' to be the first argument here, as
+    // Compare() is not symmetric.  When we do a partial comparison,
+    // only fields present in the first argument of Compare() are
+    // considered.
+    return differencer.Compare(expected, actual);
+}
+
+// Describes the types of the expected and the actual protocol buffer.
+std::string DescribeTypes(const google::protobuf::Message& expected,
+                          const google::protobuf::Message& actual) {
+    return "whose type should be " + expected.GetDescriptor()->full_name() + " but actually is " +
+           actual.GetDescriptor()->full_name();
+}
+
+// Prints the protocol buffer pointed to by proto.
+std::string PrintProtoPointee(const google::protobuf::Message* proto) {
+    if (proto == NULL) return "";
+
+    return "which points to " + ::testing::PrintToString(*proto);
+}
+
+// Describes the differences between the two protocol buffers.
+std::string DescribeDiff(const internal::ProtoComparison& comp,
+                         const google::protobuf::Message& actual,
+                         const google::protobuf::Message& expected) {
+    google::protobuf::util::MessageDifferencer differencer;
+    google::protobuf::util::DefaultFieldComparator field_comparator;
+    ConfigureDifferencer(comp, &field_comparator, &differencer, actual.GetDescriptor());
+
+    std::string diff;
+    differencer.ReportDifferencesToString(&diff);
+
+    // We must put 'expected' as the first argument here, as Compare()
+    // reports the diff in terms of how the protobuf changes from the
+    // first argument to the second argument.
+    differencer.Compare(expected, actual);
+
+    // Removes the trailing '\n' in the diff to make the output look nicer.
+    if (diff.length() > 0 && *(diff.end() - 1) == '\n') {
+        diff.erase(diff.end() - 1);
+    }
+
+    return "with the difference:\n" + diff;
+}
+
+bool ProtoMatcherBase::MatchAndExplain(
+    const google::protobuf::Message& arg,
+    bool is_matcher_for_pointer,  // true iff this matcher is used to match
+                                  // a protobuf pointer.
+    ::testing::MatchResultListener* listener) const {
+    if (must_be_initialized_ && !arg.IsInitialized()) {
+        *listener << "which isn't fully initialized";
+        return false;
+    }
+
+    const google::protobuf::Message* const expected = CreateExpectedProto(arg, listener);
+    if (expected == NULL) return false;
+
+    // Protobufs of different types cannot be compared.
+    const bool comparable = ProtoComparable(arg, *expected);
+    const bool match = comparable && ProtoCompare(comp(), arg, *expected);
+
+    // Explaining the match result is expensive.  We don't want to waste
+    // time calculating an explanation if the listener isn't interested.
+    if (listener->IsInterested()) {
+        const char* sep = "";
+        if (is_matcher_for_pointer) {
+            *listener << PrintProtoPointee(&arg);
+            sep = ",\n";
+        }
+
+        if (!comparable) {
+            *listener << sep << DescribeTypes(*expected, arg);
+        } else if (!match) {
+            *listener << sep << DescribeDiff(comp(), arg, *expected);
+        }
+    }
+
+    DeleteExpectedProto(expected);
+    return match;
+}
+
+}  // namespace internal
+}  // namespace android
diff --git a/host-common/address_space_device.cpp b/host-common/address_space_device.cpp
index 73d7f63..1f852c9 100644
--- a/host-common/address_space_device.cpp
+++ b/host-common/address_space_device.cpp
@@ -248,6 +248,10 @@ public:
         }
     }
 
+    void setLoadResources(AddressSpaceDeviceLoadResources resources) {
+        mLoadResources = std::move(resources);
+    }
+
     bool load(Stream* stream) {
         // First destroy all contexts, because
         // this can be done while an emulator is running
@@ -262,8 +266,7 @@ public:
 
         asg::AddressSpaceGraphicsContext::init(get_address_space_device_control_ops());
 
-        if (!AddressSpaceGraphicsContext::globalStateLoad(
-                stream)) {
+        if (!AddressSpaceGraphicsContext::globalStateLoad(stream, mLoadResources)) {
             return false;
         }
 
@@ -447,6 +450,9 @@ private:
     };
 
     std::map<uint64_t, std::vector<DeallocationCallbackEntry>> mDeallocationCallbacks; // do not save/load, users re-register on load
+
+    // Not saved/loaded. Externally owned resources used during load.
+    std::optional<AddressSpaceDeviceLoadResources> mLoadResources;
 };
 
 static AddressSpaceDeviceState* sAddressSpaceDeviceState() {
@@ -579,6 +585,12 @@ const QAndroidVmOperations* goldfish_address_space_get_vm_operations() {
     return sVmOps;
 }
 
+int goldfish_address_space_memory_state_set_load_resources(
+    AddressSpaceDeviceLoadResources resources) {
+    sAddressSpaceDeviceState()->setLoadResources(std::move(resources));
+    return 0;
+}
+
 int goldfish_address_space_memory_state_load(android::base::Stream *stream) {
     return sAddressSpaceDeviceState()->load(stream) ? 0 : 1;
 }
diff --git a/host-common/address_space_device.hpp b/host-common/address_space_device.hpp
deleted file mode 100644
index 0067e70..0000000
--- a/host-common/address_space_device.hpp
+++ /dev/null
@@ -1,31 +0,0 @@
-// Copyright 2019 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-// http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-#pragma once
-
-#include "aemu/base/files/Stream.h"
-#include "aemu/base/export.h"
-
-struct QAndroidVmOperations;
-
-namespace android {
-namespace emulation {
-
-AEMU_EXPORT void goldfish_address_space_set_vm_operations(const QAndroidVmOperations* vmops);
-AEMU_EXPORT const QAndroidVmOperations* goldfish_address_space_get_vm_operations();
-
-int goldfish_address_space_memory_state_load(android::base::Stream *stream);
-int goldfish_address_space_memory_state_save(android::base::Stream *stream);
-
-}  // namespace emulation
-}  // namespace android
diff --git a/host-common/address_space_graphics.cpp b/host-common/address_space_graphics.cpp
index cf0a56d..d08de67 100644
--- a/host-common/address_space_graphics.cpp
+++ b/host-common/address_space_graphics.cpp
@@ -14,18 +14,19 @@
 
 #include "host-common/address_space_graphics.h"
 
-#include "host-common/address_space_device.hpp"
+#include <memory>
+#include <optional>
+
+#include "aemu/base/AlignedBuf.h"
+#include "aemu/base/SubAllocator.h"
+#include "aemu/base/synchronization/Lock.h"
+#include "host-common/GfxstreamFatalError.h"
 #include "host-common/address_space_device.h"
-#include "host-common/vm_operations.h"
+#include "host-common/address_space_device.hpp"
 #include "host-common/crash-handler.h"
 #include "host-common/crash_reporter.h"
-#include "host-common/GfxstreamFatalError.h"
 #include "host-common/globals.h"
-#include "aemu/base/AlignedBuf.h"
-#include "aemu/base/SubAllocator.h"
-#include "aemu/base/synchronization/Lock.h"
-
-#include <memory>
+#include "host-common/vm_operations.h"
 
 #define ASGFX_DEBUG 0
 
@@ -46,23 +47,22 @@ namespace emulation {
 namespace asg {
 
 struct AllocationCreateInfo {
-    bool dedicated;
     bool virtioGpu;
     bool hostmemRegisterFixed;
     bool fromLoad;
     uint64_t size;
     uint64_t hostmemId;
     void *externalAddr;
+    std::optional<uint32_t> dedicatedContextHandle;
 };
 
 struct Block {
     char* buffer = nullptr;
+    uint64_t bufferSize = 0;
     SubAllocator* subAlloc = nullptr;
     uint64_t offsetIntoPhys = 0; // guest claimShared/mmap uses this
-    // size: implicitly ADDRESS_SPACE_GRAPHICS_BLOCK_SIZE
     bool isEmpty = true;
-    bool dedicated = false;
-    size_t dedicatedSize = 0;
+    std::optional<uint32_t> dedicatedContextHandle;
     bool usesVirtioGpuHostmem = false;
     uint64_t hostmemId = 0;
     bool external = false;
@@ -143,18 +143,21 @@ public:
                 (unsigned long long)ADDRESS_SPACE_GRAPHICS_BLOCK_SIZE);
         }
 
-        size_t index = 0;
-
         Allocation res;
 
-        for (auto& block : existingBlocks) {
+        size_t index = 0;
+        for (index = 0; index < existingBlocks.size(); index++) {
+            auto& block = existingBlocks[index];
 
             if (block.isEmpty) {
                 fillBlockLocked(block, create);
             }
 
-            auto buf = block.subAlloc->alloc(create.size);
+            if (block.dedicatedContextHandle != create.dedicatedContextHandle) {
+                continue;
+            }
 
+            auto buf = block.subAlloc->alloc(create.size);
             if (buf) {
                 res.buffer = (char*)buf;
                 res.blockIndex = index;
@@ -162,14 +165,12 @@ public:
                     block.offsetIntoPhys +
                     block.subAlloc->getOffset(buf);
                 res.size = create.size;
-                res.dedicated = create.dedicated;
+                res.dedicatedContextHandle = create.dedicatedContextHandle;
                 res.hostmemId = create.hostmemId;
                 return res;
             } else {
                 // block full
             }
-
-            ++index;
         }
 
         Block newBlock;
@@ -192,7 +193,7 @@ public:
             newBlock.offsetIntoPhys +
             newBlock.subAlloc->getOffset(buf);
         res.size = create.size;
-        res.dedicated = create.dedicated;
+        res.dedicatedContextHandle = create.dedicatedContextHandle;
         res.hostmemId = create.hostmemId;
 
         return res;
@@ -211,7 +212,7 @@ public:
 
         auto& block = existingBlocks[alloc.blockIndex];
 
-        if (block.dedicated) {
+        if (block.external) {
             destroyBlockLocked(block);
             return;
         }
@@ -251,16 +252,19 @@ public:
     }
 
     Allocation allocRingAndBufferStorageDedicated(const struct AddressSpaceCreateInfo& asgCreate) {
+        if (!asgCreate.handle) {
+            crashhandler_die("Dedicated ASG allocation requested without dedicated handle.\n");
+        }
+
         struct AllocationCreateInfo create = {0};
         create.size = sizeof(struct asg_ring_storage) + mPerContextBufferSize;
-        create.dedicated = true;
+        create.dedicatedContextHandle = asgCreate.handle;
         create.virtioGpu = true;
         if (asgCreate.externalAddr) {
             create.externalAddr = asgCreate.externalAddr;
             if (asgCreate.externalAddrSize < static_cast<uint64_t>(create.size)) {
                 crashhandler_die("External address size too small\n");
             }
-
             create.size = asgCreate.externalAddrSize;
         }
 
@@ -313,7 +317,8 @@ public:
         // mConsumerInterface.globalPostSave();
     }
 
-    bool load(base::Stream* stream) {
+    bool load(base::Stream* stream,
+              const std::optional<AddressSpaceDeviceLoadResources>& resources) {
         clear();
         mConsumerInterface.globalPreLoad();
 
@@ -326,15 +331,15 @@ public:
         mCombinedBlocks.resize(combinedBlockCount);
 
         for (auto& block: mRingBlocks) {
-            loadBlockLocked(stream, block);
+            loadBlockLocked(stream, resources, block);
         }
 
         for (auto& block: mBufferBlocks) {
-            loadBlockLocked(stream, block);
+            loadBlockLocked(stream, resources, block);
         }
 
         for (auto& block: mCombinedBlocks) {
-            loadBlockLocked(stream, block);
+            loadBlockLocked(stream, resources, block);
         }
 
         return true;
@@ -375,22 +380,25 @@ private:
             stream->putBe32(1);
         }
 
+        stream->putBe64(block.bufferSize);
         stream->putBe64(block.offsetIntoPhys);
-        stream->putBe32(block.dedicated);
-        stream->putBe64(block.dedicatedSize);
+        if (block.dedicatedContextHandle) {
+            stream->putBe32(1);
+            stream->putBe32(*block.dedicatedContextHandle);
+        } else {
+            stream->putBe32(0);
+        }
         stream->putBe32(block.usesVirtioGpuHostmem);
         stream->putBe64(block.hostmemId);
-
         block.subAlloc->save(stream);
-
-        stream->putBe64(ADDRESS_SPACE_GRAPHICS_BLOCK_SIZE);
-        stream->write(block.buffer, ADDRESS_SPACE_GRAPHICS_BLOCK_SIZE);
+        if (!block.external) {
+            stream->write(block.buffer, block.bufferSize);
+        }
     }
 
-    void loadBlockLocked(
-        base::Stream* stream,
-        Block& block) {
-
+    void loadBlockLocked(base::Stream* stream,
+                         const std::optional<AddressSpaceDeviceLoadResources>& resources,
+                         Block& block) {
         uint32_t filled = stream->getBe32();
         struct AllocationCreateInfo create = {0};
 
@@ -401,11 +409,40 @@ private:
             block.isEmpty = false;
         }
 
+        create.size = stream->getBe64(); // `bufferSize`
         block.offsetIntoPhys = stream->getBe64();
-
-        create.dedicated = stream->getBe32();
-        create.size = stream->getBe64();
+        if (stream->getBe32() == 1) {
+            create.dedicatedContextHandle = stream->getBe32();
+        }
         create.virtioGpu = stream->getBe32();
+
+        if (create.virtioGpu) {
+            if (!create.dedicatedContextHandle) {
+                crashhandler_die(
+                    "Failed to load ASG context global block: "
+                    "Virtio GPU backed blocks are expected to have dedicated context.\n");
+            }
+
+            // Blocks whose memory are backed Virtio GPU resource do not own the external
+            // memory. The external memory must be re-loaded outside of ASG and provided via
+            // `resources`.
+            if (!resources) {
+                crashhandler_die(
+                    "Failed to load ASG context global block: "
+                    "Virtio GPU backed blocks need external memory resources for loading.\n");
+            }
+
+            const auto externalMemoryIt =
+                resources->contextExternalMemoryMap.find(*create.dedicatedContextHandle);
+            if (externalMemoryIt == resources->contextExternalMemoryMap.end()) {
+                crashhandler_die(
+                    "Failed to load ASG context global block: "
+                    "Virtio GPU backed blocks an need external memory replacement.\n");
+            }
+            const auto& externalMemory = externalMemoryIt->second;
+            create.externalAddr = externalMemory.externalAddress;
+        }
+
         create.hostmemRegisterFixed = true;
         create.fromLoad = true;
         create.hostmemId = stream->getBe64();
@@ -414,52 +451,38 @@ private:
 
         block.subAlloc->load(stream);
 
-        stream->getBe64();
-        stream->read(block.buffer, ADDRESS_SPACE_GRAPHICS_BLOCK_SIZE);
+        if (!block.external) {
+            stream->read(block.buffer, block.bufferSize);
+        }
     }
 
     void fillAllocFromLoad(const Block& block, Allocation& alloc) {
         alloc.buffer = block.buffer + (alloc.offsetIntoPhys - block.offsetIntoPhys);
-        alloc.dedicated = block.dedicated;
+        alloc.dedicatedContextHandle = block.dedicatedContextHandle;
         alloc.hostmemId = block.hostmemId;
     }
 
     void fillBlockLocked(Block& block, struct AllocationCreateInfo& create) {
-        if (create.dedicated) {
-            if (create.virtioGpu) {
-                void* buf;
-
-                if (create.externalAddr) {
-                    buf = create.externalAddr;
-                    block.external = true;
-                } else {
-                    buf = aligned_buf_alloc(ADDRESS_SPACE_GRAPHICS_PAGE_SIZE, create.size);
-
-                    struct MemEntry entry = { 0 };
-                    entry.hva = buf;
-                    entry.size = create.size;
-                    entry.register_fixed = create.hostmemRegisterFixed;
-                    entry.fixed_id = create.hostmemId ? create.hostmemId : 0;
-                    entry.caching = MAP_CACHE_CACHED;
-
-                    create.hostmemId = mControlOps->hostmem_register(&entry);
-                }
-
-                block.buffer = (char*)buf;
-                block.subAlloc =
-                    new SubAllocator(buf, create.size, ADDRESS_SPACE_GRAPHICS_PAGE_SIZE);
-                block.offsetIntoPhys = 0;
-
-                block.isEmpty = false;
-                block.usesVirtioGpuHostmem = create.virtioGpu;
-                block.hostmemId = create.hostmemId;
-                block.dedicated = create.dedicated;
-                block.dedicatedSize = create.size;
+        if (create.dedicatedContextHandle) {
+            if (!create.virtioGpu) {
+                crashhandler_die("Cannot use dedicated allocation without virtio-gpu hostmem id");
+            }
 
-            } else {
+            if (!create.externalAddr) {
                 crashhandler_die(
                     "Cannot use dedicated allocation without virtio-gpu hostmem id");
             }
+
+            block.external = true;
+            block.buffer = (char*)create.externalAddr;
+            block.bufferSize = create.size;
+            block.subAlloc =
+                new SubAllocator(block.buffer, block.bufferSize, ADDRESS_SPACE_GRAPHICS_PAGE_SIZE);
+            block.offsetIntoPhys = 0;
+            block.isEmpty = false;
+            block.usesVirtioGpuHostmem = create.virtioGpu;
+            block.hostmemId = create.hostmemId;
+            block.dedicatedContextHandle = create.dedicatedContextHandle;
         } else {
             if (create.virtioGpu) {
                 crashhandler_die(
@@ -499,12 +522,12 @@ private:
                     ADDRESS_SPACE_GRAPHICS_BLOCK_SIZE);
 
                 block.buffer = (char*)buf;
+                block.bufferSize = ADDRESS_SPACE_GRAPHICS_BLOCK_SIZE;
                 block.subAlloc =
                     new SubAllocator(
                         buf, ADDRESS_SPACE_GRAPHICS_BLOCK_SIZE,
                         ADDRESS_SPACE_GRAPHICS_PAGE_SIZE);
                 block.offsetIntoPhys = offsetIntoPhys;
-
                 block.isEmpty = false;
             }
         }
@@ -574,15 +597,21 @@ AddressSpaceGraphicsContext::AddressSpaceGraphicsContext(
           [this] { return onUnavailableRead(); },
           [](uint64_t physAddr) { return (char*)sGlobals()->controlOps()->get_host_ptr(physAddr); },
       }),
-      mConsumerInterface(sGlobals()->getConsumerInterface()),
-      mIsVirtio(false) {
-    mIsVirtio = (create.type == AddressSpaceDeviceType::VirtioGpuGraphics);
+      mConsumerInterface(sGlobals()->getConsumerInterface()) {
     if (create.fromSnapshot) {
         // Use load() instead to initialize
         return;
     }
 
-    if (mIsVirtio) {
+    const bool isVirtio = (create.type == AddressSpaceDeviceType::VirtioGpuGraphics);
+    if (isVirtio) {
+        VirtioGpuInfo& info = mVirtioGpuInfo.emplace();
+        info.contextId = create.virtioGpuContextId;
+        info.capsetId = create.virtioGpuCapsetId;
+        if (create.contextNameSize) {
+            info.name = std::string(create.contextName, create.contextNameSize);
+        }
+
         mCombinedAllocation = sGlobals()->allocRingAndBufferStorageDedicated(create);
         mRingAllocation = sGlobals()->allocRingViewIntoCombined(mCombinedAllocation);
         mBufferAllocation = sGlobals()->allocBufferViewIntoCombined(mCombinedAllocation);
@@ -617,16 +646,12 @@ AddressSpaceGraphicsContext::AddressSpaceGraphicsContext(
 
     mSavedConfig = *mHostContext.ring_config;
 
-    std::optional<std::string> nameOpt;
-    if (create.contextNameSize) {
-        std::string name(create.contextName, create.contextNameSize);
-        nameOpt = name;
-    }
-
     if (create.createRenderThread) {
-        mCurrentConsumer = mConsumerInterface.create(
-            mHostContext, nullptr, mConsumerCallbacks, create.virtioGpuContextId, create.virtioGpuCapsetId,
-            std::move(nameOpt));
+        mCurrentConsumer =
+            mConsumerInterface.create(mHostContext, nullptr, mConsumerCallbacks,
+                                      mVirtioGpuInfo ? mVirtioGpuInfo->contextId : 0,
+                                      mVirtioGpuInfo ? mVirtioGpuInfo->capsetId : 0,
+                                      mVirtioGpuInfo ? mVirtioGpuInfo->name : std::nullopt);
     }
 }
 
@@ -661,7 +686,7 @@ void AddressSpaceGraphicsContext::perform(AddressSpaceDevicePingInfo* info) {
             mHostContext, nullptr /* no load stream */, mConsumerCallbacks, 0, 0,
             std::nullopt);
 
-        if (mIsVirtio) {
+        if (mVirtioGpuInfo) {
             info->metadata = mCombinedAllocation.hostmemId;
         }
         break;
@@ -733,7 +758,21 @@ void AddressSpaceGraphicsContext::preSave() const {
 }
 
 void AddressSpaceGraphicsContext::save(base::Stream* stream) const {
-    stream->putBe32(mIsVirtio);
+    if (mVirtioGpuInfo) {
+        const VirtioGpuInfo& info = *mVirtioGpuInfo;
+        stream->putBe32(1);
+        stream->putBe32(info.contextId);
+        stream->putBe32(info.capsetId);
+        if (info.name) {
+            stream->putBe32(1);
+            stream->putString(*info.name);
+        } else {
+            stream->putBe32(0);
+        }
+    } else {
+        stream->putBe32(0);
+    }
+
     stream->putBe32(mVersion);
     stream->putBe32(mExiting);
     stream->putBe32(mUnavailableReadCount);
@@ -760,14 +799,33 @@ void AddressSpaceGraphicsContext::postSave() const {
 }
 
 bool AddressSpaceGraphicsContext::load(base::Stream* stream) {
-    mIsVirtio = stream->getBe32();
+    const bool hasVirtioGpuInfo = (stream->getBe32() == 1);
+    if (hasVirtioGpuInfo) {
+        VirtioGpuInfo& info = mVirtioGpuInfo.emplace();
+        info.contextId = stream->getBe32();
+        info.capsetId = stream->getBe32();
+        const bool hasName = (stream->getBe32() == 1);
+        if (hasName) {
+            info.name = stream->getString();
+        }
+    }
+
     mVersion = stream->getBe32();
     mExiting = stream->getBe32();
     mUnavailableReadCount = stream->getBe32();
 
-    loadAllocation(stream, mRingAllocation, AllocType::AllocTypeRing);
-    loadAllocation(stream, mBufferAllocation, AllocType::AllocTypeBuffer);
-    loadAllocation(stream, mCombinedAllocation, AllocType::AllocTypeCombined);
+    loadAllocation(stream, mRingAllocation);
+    loadAllocation(stream, mBufferAllocation);
+    loadAllocation(stream, mCombinedAllocation);
+
+    if (mVirtioGpuInfo) {
+        sGlobals()->fillAllocFromLoad(mCombinedAllocation, AllocType::AllocTypeCombined);
+        mRingAllocation = sGlobals()->allocRingViewIntoCombined(mCombinedAllocation);
+        mBufferAllocation = sGlobals()->allocBufferViewIntoCombined(mCombinedAllocation);
+    } else {
+        sGlobals()->fillAllocFromLoad(mRingAllocation, AllocType::AllocTypeRing);
+        sGlobals()->fillAllocFromLoad(mBufferAllocation, AllocType::AllocTypeBuffer);
+    }
 
     mHostContext = asg_context_create(
         mRingAllocation.buffer,
@@ -787,11 +845,13 @@ bool AddressSpaceGraphicsContext::load(base::Stream* stream) {
 
     loadRingConfig(stream, mSavedConfig);
 
-    uint32_t consumerExists = stream->getBe32();
-
-    if (consumerExists) {
-        mCurrentConsumer = mConsumerInterface.create(
-            mHostContext, stream, mConsumerCallbacks, 0, 0, std::nullopt);
+    const bool hasConsumer = stream->getBe32() == 1;
+    if (hasConsumer) {
+        mCurrentConsumer =
+            mConsumerInterface.create(mHostContext, stream, mConsumerCallbacks,
+                                      mVirtioGpuInfo ? mVirtioGpuInfo->contextId : 0,
+                                      mVirtioGpuInfo ? mVirtioGpuInfo->capsetId : 0,
+                                      mVirtioGpuInfo ? mVirtioGpuInfo->name : std::nullopt);
         mConsumerInterface.postLoad(mCurrentConsumer);
     }
 
@@ -810,8 +870,9 @@ void AddressSpaceGraphicsContext::globalStatePostSave() {
     sGlobals()->postSave();
 }
 
-bool AddressSpaceGraphicsContext::globalStateLoad(base::Stream* stream) {
-    return sGlobals()->load(stream);
+bool AddressSpaceGraphicsContext::globalStateLoad(
+    base::Stream* stream, const std::optional<AddressSpaceDeviceLoadResources>& resources) {
+    return sGlobals()->load(stream, resources);
 }
 
 void AddressSpaceGraphicsContext::saveRingConfig(base::Stream* stream, const struct asg_ring_config& config) const {
@@ -841,13 +902,11 @@ void AddressSpaceGraphicsContext::loadRingConfig(base::Stream* stream, struct as
     config.in_error = stream->getBe32();
 }
 
-void AddressSpaceGraphicsContext::loadAllocation(base::Stream* stream, Allocation& alloc, AddressSpaceGraphicsContext::AllocType type) {
+void AddressSpaceGraphicsContext::loadAllocation(base::Stream* stream, Allocation& alloc) {
     alloc.blockIndex = stream->getBe64();
     alloc.offsetIntoPhys = stream->getBe64();
     alloc.size = stream->getBe64();
     alloc.isView = stream->getBe32();
-
-    sGlobals()->fillAllocFromLoad(alloc, type);
 }
 
 }  // namespace asg
diff --git a/host-common/include/host-common/FeatureControlDefHost.h b/host-common/include/host-common/FeatureControlDefHost.h
index 2376448..144a58c 100644
--- a/host-common/include/host-common/FeatureControlDefHost.h
+++ b/host-common/include/host-common/FeatureControlDefHost.h
@@ -83,3 +83,7 @@ FEATURE_CONTROL_ITEM(WiFiPacketStream, 95)
 FEATURE_CONTROL_ITEM(VulkanAllocateDeviceMemoryOnly, 98)
 FEATURE_CONTROL_ITEM(VulkanAllocateHostMemory, 99)
 FEATURE_CONTROL_ITEM(QtRawKeyboardInput, 100)
+FEATURE_CONTROL_ITEM(BypassVulkanDeviceFeatureOverrides, 107)
+FEATURE_CONTROL_ITEM(VulkanDebugUtils, 108)
+FEATURE_CONTROL_ITEM(VulkanCommandBufferCheckpoints, 109)
+FEATURE_CONTROL_ITEM(VulkanVirtualQueue, 110)
diff --git a/host-common/include/host-common/MultiDisplay.h b/host-common/include/host-common/MultiDisplay.h
index 879ecf2..e2fa861 100644
--- a/host-common/include/host-common/MultiDisplay.h
+++ b/host-common/include/host-common/MultiDisplay.h
@@ -119,6 +119,8 @@ public:
     int setDisplayColorBuffer(uint32_t displayId, uint32_t colorBuffer);
     void getCombinedDisplaySize(uint32_t* w, uint32_t* h);
     bool isMultiDisplayWindow();
+    bool isDisplayPipeReady();
+    bool startDisplayPipe();
     bool isPixelFold();
     void loadConfig();
     void onSave(base::Stream* stream);
diff --git a/host-common/include/host-common/address_space_device.h b/host-common/include/host-common/address_space_device.h
index ae5f58f..9594572 100644
--- a/host-common/include/host-common/address_space_device.h
+++ b/host-common/include/host-common/address_space_device.h
@@ -20,7 +20,7 @@ extern "C" {
 struct AddressSpaceHwFuncs;
 
 struct AddressSpaceCreateInfo {
-    uint32_t handle;
+    uint32_t handle = 0;
     uint32_t type;
     uint64_t physAddr;
     bool fromSnapshot;
@@ -88,7 +88,7 @@ struct AddressSpaceHwFuncs {
      * or when loading a snapshot while the emulator is running.
      * Returns 0 if successful, -errno otherwise. */
     int (*freeSharedHostRegion)(uint64_t offset);
-    
+
     /* Versions of the above but when the state is already locked. */
     int (*allocSharedHostRegionLocked)(uint64_t page_aligned_size, uint64_t* offset);
     int (*freeSharedHostRegionLocked)(uint64_t offset);
diff --git a/host-common/include/host-common/address_space_device.hpp b/host-common/include/host-common/address_space_device.hpp
index 0067e70..5bc1f64 100644
--- a/host-common/include/host-common/address_space_device.hpp
+++ b/host-common/include/host-common/address_space_device.hpp
@@ -13,8 +13,10 @@
 // limitations under the License.
 #pragma once
 
-#include "aemu/base/files/Stream.h"
+#include <unordered_map>
+
 #include "aemu/base/export.h"
+#include "aemu/base/files/Stream.h"
 
 struct QAndroidVmOperations;
 
@@ -27,5 +29,25 @@ AEMU_EXPORT const QAndroidVmOperations* goldfish_address_space_get_vm_operations
 int goldfish_address_space_memory_state_load(android::base::Stream *stream);
 int goldfish_address_space_memory_state_save(android::base::Stream *stream);
 
+// Resources which can not be directly reloaded by ASG.
+struct AddressSpaceDeviceLoadResources {
+    // ASGs may use memory backed by an external memory allocation (e.g. a
+    // Virtio GPU blob resource with a host shmem allocation). These external
+    // memory allocations can not be directly saved and loaded via
+    // `android::base::Stream` and may not have the same `void*` across save
+    // and load.
+    struct ExternalMemory {
+        void* externalAddress = nullptr;
+        uint64_t externalAddressSize = 0;
+    };
+    // Maps ASG handle to the dedicated external memory.
+    std::unordered_map<uint32_t, ExternalMemory> contextExternalMemoryMap;
+};
+
+// Sets the resources that can be used during a load which can not be loaded
+// directly from by ASG.
+int goldfish_address_space_memory_state_set_load_resources(
+    AddressSpaceDeviceLoadResources resources);
+
 }  // namespace emulation
 }  // namespace android
diff --git a/host-common/include/host-common/address_space_graphics.h b/host-common/include/host-common/address_space_graphics.h
index 7402478..75f8642 100644
--- a/host-common/include/host-common/address_space_graphics.h
+++ b/host-common/include/host-common/address_space_graphics.h
@@ -13,16 +13,17 @@
 // limitations under the License.
 #pragma once
 
-#include "AddressSpaceService.h"
+#include <functional>
+#include <optional>
+#include <vector>
 
+#include "AddressSpaceService.h"
+#include "address_space_device.h"
+#include "address_space_device.hpp"
+#include "address_space_graphics_types.h"
 #include "aemu/base/ring_buffer.h"
 #include "aemu/base/synchronization/MessageChannel.h"
 #include "aemu/base/threads/FunctorThread.h"
-#include "address_space_device.h"
-#include "address_space_graphics_types.h"
-
-#include <functional>
-#include <vector>
 
 namespace android {
 namespace emulation {
@@ -33,7 +34,7 @@ struct Allocation {
     size_t blockIndex = 0;
     uint64_t offsetIntoPhys = 0;
     uint64_t size = 0;
-    bool dedicated = false;
+    std::optional<uint32_t> dedicatedContextHandle;
     uint64_t hostmemId = 0;
     bool isView = false;
 };
@@ -60,7 +61,8 @@ public:
  static void globalStateSave(base::Stream*);
  static void globalStatePostSave();
 
- static bool globalStateLoad(base::Stream*);
+ static bool globalStateLoad(base::Stream*,
+                             const std::optional<AddressSpaceDeviceLoadResources>& resources);
 
  enum AllocType {
      AllocTypeRing,
@@ -75,7 +77,7 @@ private:
 
     void loadRingConfig(base::Stream* stream, struct asg_ring_config& config);
 
-    void loadAllocation(base::Stream* stream, Allocation& alloc, AllocType type);
+    void loadAllocation(base::Stream* stream, Allocation& alloc);
 
     // For consumer communication
     enum ConsumerCommand {
@@ -107,7 +109,12 @@ private:
     // For onUnavailableRead
     uint32_t mUnavailableReadCount = 0;
 
-    bool mIsVirtio = false;
+    struct VirtioGpuInfo {
+        uint32_t contextId = 0;
+        uint32_t capsetId = 0;
+        std::optional<std::string> name;
+    };
+    std::optional<VirtioGpuInfo> mVirtioGpuInfo;
     // To save the ring config if it is cleared on hostmem map
     struct asg_ring_config mSavedConfig;
 };
diff --git a/host-common/logging_absl.cpp b/host-common/logging_absl.cpp
index a654e8a..3e5d6ba 100644
--- a/host-common/logging_absl.cpp
+++ b/host-common/logging_absl.cpp
@@ -30,6 +30,36 @@ void set_gfxstream_fine_logger(gfxstream_logger_t f) {}
 void set_gfxstream_enable_log_colors() {}
 void set_gfxstream_enable_verbose_logs() { sEnableVerbose = true; }
 
+void gfx_stream_logger(char severity, const char* file, unsigned int line, int64_t timestamp_us,
+                       const char* msg) {
+
+    switch (severity) {
+        case 'I':  // INFO
+            ABSL_LOG(INFO).AtLocation(file, line) << msg;
+            break;
+        case 'W':  // WARNING
+            ABSL_LOG(WARNING).AtLocation(file, line) << msg;
+            break;
+        case 'E':  // ERROR
+            ABSL_LOG(ERROR).AtLocation(file, line) << msg;
+            break;
+        case 'F':  // FATAL
+            ABSL_LOG(FATAL).AtLocation(file, line) << msg;
+            break;
+        case 'V':
+            VLOG(1).AtLocation(file, line) << msg;
+            break;
+        case 'D':
+            VLOG(2).AtLocation(file, line) << msg;
+            break;
+        default:
+            ABSL_LOG(INFO).AtLocation(file, line) << msg;
+            break;
+    };
+}
+
+gfxstream_logger_t get_gfx_stream_logger() { return gfx_stream_logger; };
+
 void OutputLog(FILE* stream, char severity, const char* file, unsigned int line,
                int64_t timestamp_us, const char* format, ...) {
     if (severity == 'V' && !sEnableVerbose) {
```

