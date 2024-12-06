```diff
diff --git a/Android.bp b/Android.bp
index 0bcbe48..447f977 100644
--- a/Android.bp
+++ b/Android.bp
@@ -30,11 +30,7 @@ cc_library {
     ],
     apex_available: [
         "//apex_available:platform",
-        "com.android.btservices",
-        "com.android.media.swcodec",
-        "com.android.neuralnetworks",
-        "test_com.android.media.swcodec",
-        "test_com.android.neuralnetworks",
+        "//apex_available:anyapex",
     ],
     export_include_dirs: ["include"],
     local_include_dirs: ["include"],
@@ -188,12 +184,15 @@ rust_test {
     ],
 }
 
-rust_library {
-    name: "libfmq_rust",
+rust_defaults {
+    name: "libfmq_rust_defaults",
     host_supported: true,
     vendor_available: true,
     product_available: true,
-    visibility: [":__subpackages__"],
+    visibility: [
+        ":__subpackages__",
+        "//system/software_defined_vehicle/core_services/sdv_comms:__subpackages__",
+    ],
     crate_name: "fmq",
     srcs: ["libfmq.rs"],
     edition: "2021",
@@ -204,3 +203,16 @@ rust_library {
     ],
     proc_macros: [],
 }
+
+rust_library {
+    name: "libfmq_rust",
+    defaults: ["libfmq_rust_defaults"],
+}
+
+rust_test {
+    name: "libfmq_rust_unit_test",
+    defaults: ["libfmq_rust_defaults"],
+    test_options: {
+        unit_test: true,
+    },
+}
diff --git a/ErasedMessageQueue.cpp b/ErasedMessageQueue.cpp
index 7fb03aa..bc1e5a8 100644
--- a/ErasedMessageQueue.cpp
+++ b/ErasedMessageQueue.cpp
@@ -23,7 +23,7 @@
 NativeHandle convertHandle(const int* fds, size_t n_fds, const int32_t* ints, size_t n_ints) {
     std::vector<ndk::ScopedFileDescriptor> fdv;
     for (size_t i = 0; i < n_fds; i++) {
-        fdv.push_back(std::move(ndk::ScopedFileDescriptor(fds[i])));
+        fdv.push_back(ndk::ScopedFileDescriptor(dup(fds[i])));
     }
     std::vector<int32_t> intv(ints, ints + n_ints);
 
@@ -112,6 +112,6 @@ bool ErasedMessageQueue::commitRead(size_t nMessages) {
     return inner->commitRead(nMessages);
 }
 
-ErasedMessageQueueDesc* ErasedMessageQueue::dupeDesc() {
+ErasedMessageQueueDesc* ErasedMessageQueue::dupeDesc() const {
     return new ErasedMessageQueueDesc(inner->dupeDesc());
 }
diff --git a/ErasedMessageQueue.hpp b/ErasedMessageQueue.hpp
index b3c4357..b4b5931 100644
--- a/ErasedMessageQueue.hpp
+++ b/ErasedMessageQueue.hpp
@@ -161,5 +161,5 @@ class ErasedMessageQueue {
      * @return ErasedMessageQueueDesc The copied descriptor, which must be freed
      * by passing it to freeDesc.
      */
-    ErasedMessageQueueDesc* dupeDesc();
+    ErasedMessageQueueDesc* dupeDesc() const;
 };
diff --git a/benchmarks/Android.bp b/benchmarks/Android.bp
new file mode 100644
index 0000000..edb6701
--- /dev/null
+++ b/benchmarks/Android.bp
@@ -0,0 +1,43 @@
+//
+// Copyright (C) 2016 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+//
+
+package {
+    // See: http://go/android-license-faq
+    default_applicable_licenses: [
+        "Android-Apache-2.0",
+    ],
+    default_team: "trendy_team_testing",
+}
+
+cc_test {
+    name: "mq_benchmark_client",
+    srcs: ["msgq_benchmark_client.cpp"],
+    cflags: [
+        "-Wall",
+        "-Werror",
+    ],
+    shared_libs: [
+        "android.hardware.tests.msgq@1.0",
+        "libbase",
+        "libcutils",
+        "libfmq",
+        "libhidlbase",
+        "libutils",
+    ],
+    required: [
+        "android.hardware.tests.msgq@1.0-impl",
+    ],
+}
diff --git a/benchmarks/Android.mk b/benchmarks/Android.mk
deleted file mode 100644
index 3cae117..0000000
--- a/benchmarks/Android.mk
+++ /dev/null
@@ -1,41 +0,0 @@
-#
-# Copyright (C) 2016 The Android Open Source Project
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#      http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-#
-
-LOCAL_PATH := $(call my-dir)
-
-include $(CLEAR_VARS)
-LOCAL_SRC_FILES := \
-    msgq_benchmark_client.cpp
-
-LOCAL_CFLAGS := -Wall -Werror
-
-LOCAL_SHARED_LIBRARIES := \
-    libbase \
-    libcutils \
-    libutils \
-    libhidlbase
-
-LOCAL_REQUIRED_MODULES := android.hardware.tests.msgq@1.0-impl
-
-ifneq ($(TARGET_2ND_ARCH),)
-LOCAL_REQUIRED_MODULES += android.hardware.tests.msgq@1.0-impl:32
-endif
-
-LOCAL_SHARED_LIBRARIES += android.hardware.tests.msgq@1.0 libfmq
-LOCAL_MODULE := mq_benchmark_client
-LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
-LOCAL_LICENSE_CONDITIONS := notice
-include $(BUILD_NATIVE_TEST)
diff --git a/include/fmq/AidlMessageQueue.h b/include/fmq/AidlMessageQueue.h
index 138760f..e4c3d84 100644
--- a/include/fmq/AidlMessageQueue.h
+++ b/include/fmq/AidlMessageQueue.h
@@ -115,7 +115,7 @@ struct AidlMessageQueue final
                      android::base::unique_fd bufferFd, size_t bufferSize,
                      std::enable_if_t<std::is_same_v<V, MQErased>, size_t> quantum);
 
-    MQDescriptor<T, U> dupeDesc();
+    MQDescriptor<T, U> dupeDesc() const;
 
   private:
     AidlMessageQueue(const AidlMessageQueue& other) = delete;
@@ -144,7 +144,7 @@ AidlMessageQueue<T, U>::AidlMessageQueue(
               quantum) {}
 
 template <typename T, typename U>
-MQDescriptor<T, U> AidlMessageQueue<T, U>::dupeDesc() {
+MQDescriptor<T, U> AidlMessageQueue<T, U>::dupeDesc() const {
     auto* shim = MessageQueueBase<AidlMQDescriptorShim, T, FlavorTypeToValue<U>::value>::getDesc();
     if (shim) {
         std::vector<aidl::android::hardware::common::fmq::GrantorDescriptor> grantors;
diff --git a/include/fmq/MessageQueueBase.h b/include/fmq/MessageQueueBase.h
index 41befee..8d65108 100644
--- a/include/fmq/MessageQueueBase.h
+++ b/include/fmq/MessageQueueBase.h
@@ -24,7 +24,7 @@
 #include <utils/Log.h>
 #include <utils/SystemClock.h>
 #include <atomic>
-#include <new>
+#include <functional>
 
 using android::hardware::kSynchronizedReadWrite;
 using android::hardware::kUnsynchronizedWrite;
@@ -46,6 +46,7 @@ struct MessageQueueBase {
         NONE,
         POINTER_CORRUPTION, /** Read/write pointers mismatch */
     };
+    using ErrorHandler = std::function<void(Error, std::string&&)>;
 
     /**
      * @param Desc MQDescriptor describing the FMQ.
@@ -86,28 +87,22 @@ struct MessageQueueBase {
                            0) {}
 
     /**
-     * @param errorDetected Optional output parameter which indicates
-     * any errors that the client might care about.
-     * @param errorMessage Optional output parameter for a human-readable
-     * error description.
-     *
+     * Set a client side error handler function which will be invoked when the FMQ detects
+     * one of the error situations defined by the 'Error' type.
+     */
+    void setErrorHandler(ErrorHandler&& handler) { mErrorHandler.swap(handler); }
+
+    /**
      * @return Number of items of type T that can be written into the FMQ
      * without a read.
      */
-    size_t availableToWrite(Error* errorDetected = nullptr,
-                            std::string* errorMessage = nullptr) const;
+    size_t availableToWrite() const;
 
     /**
-     * @param errorDetected Optional output parameter which indicates
-     * any errors that the client might care about.
-     * @param errorMessage Optional output parameter for a human-readable
-     * error description.
-     *
      * @return Number of items of type T that are waiting to be read from the
      * FMQ.
      */
-    size_t availableToRead(Error* errorDetected = nullptr,
-                           std::string* errorMessage = nullptr) const;
+    size_t availableToRead() const;
 
     /**
      * Returns the size of type T in bytes.
@@ -482,8 +477,8 @@ struct MessageQueueBase {
               typename std::enable_if<!std::is_same<U, MQErased>::value, bool>::type = true>
     static constexpr size_t kQuantumValue = sizeof(T);
     inline size_t quantum() const;
-    size_t availableToWriteBytes(Error* errorDetected, std::string* errorMessage) const;
-    size_t availableToReadBytes(Error* errorDetected, std::string* errorMessage) const;
+    size_t availableToWriteBytes() const;
+    size_t availableToReadBytes() const;
 
     MessageQueueBase(const MessageQueueBase& other) = delete;
     MessageQueueBase& operator=(const MessageQueueBase& other) = delete;
@@ -491,6 +486,7 @@ struct MessageQueueBase {
     void* mapGrantorDescr(uint32_t grantorIdx);
     void unmapGrantorDescr(void* address, uint32_t grantorIdx);
     void initMemory(bool resetPointers);
+    bool processOverflow(uint64_t readPtr, uint64_t writePtr) const;
 
     enum DefaultEventNotification : uint32_t {
         /*
@@ -516,6 +512,8 @@ struct MessageQueueBase {
      */
     android::hardware::EventFlag* mEventFlag = nullptr;
 
+    ErrorHandler mErrorHandler;
+
     const size_t kPageSize = getpagesize();
 };
 
@@ -1136,28 +1134,17 @@ inline size_t MessageQueueBase<MQDescriptorType, T, flavor>::quantum() const {
 }
 
 template <template <typename, MQFlavor> typename MQDescriptorType, typename T, MQFlavor flavor>
-size_t MessageQueueBase<MQDescriptorType, T, flavor>::availableToWriteBytes(
-        Error* errorDetected, std::string* errorMessage) const {
+size_t MessageQueueBase<MQDescriptorType, T, flavor>::availableToWriteBytes() const {
     size_t queueSizeBytes = mDesc->getSize();
-    Error localErrorDetected = Error::NONE;
-    size_t availableBytes = availableToReadBytes(&localErrorDetected, errorMessage);
-    if (localErrorDetected != Error::NONE) {
-        if (errorDetected != nullptr) {
-            *errorDetected = localErrorDetected;
-        }
-        return 0;
-    }
+    size_t availableBytes = availableToReadBytes();
     if (queueSizeBytes < availableBytes) {
         std::string errorMsg =
                 "The write or read pointer has become corrupted. Writing to the queue is no "
                 "longer possible. Queue size: " +
                 std::to_string(queueSizeBytes) + ", available: " + std::to_string(availableBytes);
         hardware::details::logError(errorMsg);
-        if (errorDetected != nullptr) {
-            *errorDetected = Error::POINTER_CORRUPTION;
-        }
-        if (errorMessage != nullptr) {
-            *errorMessage = std::move(errorMsg);
+        if (mErrorHandler) {
+            mErrorHandler(Error::POINTER_CORRUPTION, std::move(errorMsg));
         }
         return 0;
     }
@@ -1165,15 +1152,13 @@ size_t MessageQueueBase<MQDescriptorType, T, flavor>::availableToWriteBytes(
 }
 
 template <template <typename, MQFlavor> typename MQDescriptorType, typename T, MQFlavor flavor>
-size_t MessageQueueBase<MQDescriptorType, T, flavor>::availableToWrite(
-        Error* errorDetected, std::string* errorMessage) const {
-    return availableToWriteBytes(errorDetected, errorMessage) / quantum();
+size_t MessageQueueBase<MQDescriptorType, T, flavor>::availableToWrite() const {
+    return availableToWriteBytes() / quantum();
 }
 
 template <template <typename, MQFlavor> typename MQDescriptorType, typename T, MQFlavor flavor>
-size_t MessageQueueBase<MQDescriptorType, T, flavor>::availableToRead(
-        Error* errorDetected, std::string* errorMessage) const {
-    return availableToReadBytes(errorDetected, errorMessage) / quantum();
+size_t MessageQueueBase<MQDescriptorType, T, flavor>::availableToRead() const {
+    return availableToReadBytes() / quantum();
 }
 
 template <template <typename, MQFlavor> typename MQDescriptorType, typename T, MQFlavor flavor>
@@ -1192,10 +1177,15 @@ bool MessageQueueBase<MQDescriptorType, T, flavor>::beginWrite(size_t nMessages,
 
     auto writePtr = mWritePtr->load(std::memory_order_relaxed);
     if (writePtr % quantum() != 0) {
-        hardware::details::logError(
-                "The write pointer has become misaligned. Writing to the queue is no longer "
-                "possible.");
+        std::string errorMsg =
+                "The write pointer has become misaligned. Writing to the queue is not possible. "
+                "Pointer: " +
+                std::to_string(writePtr) + ", quantum: " + std::to_string(quantum());
+        hardware::details::logError(errorMsg);
         hardware::details::errorWriteLog(0x534e4554, "184963385");
+        if (mErrorHandler) {
+            mErrorHandler(Error::POINTER_CORRUPTION, std::move(errorMsg));
+        }
         return false;
     }
     size_t writeOffset = writePtr % mDesc->getSize();
@@ -1245,8 +1235,7 @@ MessageQueueBase<MQDescriptorType, T, flavor>::commitWrite(size_t nMessages) {
 }
 
 template <template <typename, MQFlavor> typename MQDescriptorType, typename T, MQFlavor flavor>
-size_t MessageQueueBase<MQDescriptorType, T, flavor>::availableToReadBytes(
-        Error* errorDetected, std::string* errorMessage) const {
+size_t MessageQueueBase<MQDescriptorType, T, flavor>::availableToReadBytes() const {
     /*
      * This method is invoked by implementations of both read() and write() and
      * hence requires a memory_order_acquired load for both mReadPtr and
@@ -1260,11 +1249,8 @@ size_t MessageQueueBase<MQDescriptorType, T, flavor>::availableToReadBytes(
                 "longer possible. Write pointer: " +
                 std::to_string(writePtr) + ", read pointer: " + std::to_string(readPtr);
         hardware::details::logError(errorMsg);
-        if (errorDetected != nullptr) {
-            *errorDetected = Error::POINTER_CORRUPTION;
-        }
-        if (errorMessage != nullptr) {
-            *errorMessage = std::move(errorMsg);
+        if (mErrorHandler) {
+            mErrorHandler(Error::POINTER_CORRUPTION, std::move(errorMsg));
         }
         return 0;
     }
@@ -1278,6 +1264,28 @@ bool MessageQueueBase<MQDescriptorType, T, flavor>::read(T* data, size_t nMessag
            tx.copyFromSized(data, 0 /* startIdx */, nMessages, quantum()) && commitRead(nMessages);
 }
 
+template <template <typename, MQFlavor> typename MQDescriptorType, typename T, MQFlavor flavor>
+/*
+ * Disable integer sanitization since integer overflow here is allowed
+ * and legal.
+ */
+__attribute__((no_sanitize("integer"))) bool
+MessageQueueBase<MQDescriptorType, T, flavor>::processOverflow(uint64_t readPtr,
+                                                               uint64_t writePtr) const {
+    if (writePtr - readPtr > mDesc->getSize()) {
+        /*
+         * Preserved history can be as big as mDesc->getSize() but we expose only half of that.
+         * Half of the buffer will be discarded to make space for fast writers and
+         * reduce chance of repeated overflows. The other half is available to read.
+         */
+        size_t historyOffset = getQuantumCount() / 2 * getQuantumSize();
+        mReadPtr->store(writePtr - historyOffset, std::memory_order_release);
+        hardware::details::logError("Read failed after an overflow. Resetting read pointer.");
+        return true;
+    }
+    return false;
+}
+
 template <template <typename, MQFlavor> typename MQDescriptorType, typename T, MQFlavor flavor>
 /*
  * Disable integer sanitization since integer overflow here is allowed
@@ -1308,8 +1316,7 @@ MessageQueueBase<MQDescriptorType, T, flavor>::beginRead(size_t nMessages,
         return false;
     }
 
-    if (writePtr - readPtr > mDesc->getSize()) {
-        mReadPtr->store(writePtr, std::memory_order_release);
+    if (processOverflow(readPtr, writePtr)) {
         return false;
     }
 
@@ -1358,12 +1365,12 @@ MessageQueueBase<MQDescriptorType, T, flavor>::commitRead(size_t nMessages) {
     // TODO: Use a local copy of readPtr to avoid relazed mReadPtr loads.
     auto readPtr = mReadPtr->load(std::memory_order_relaxed);
     auto writePtr = mWritePtr->load(std::memory_order_acquire);
+
     /*
      * If the flavor is unsynchronized, it is possible that a write overflow may
      * have occurred between beginRead() and commitRead().
      */
-    if (writePtr - readPtr > mDesc->getSize()) {
-        mReadPtr->store(writePtr, std::memory_order_release);
+    if (processOverflow(readPtr, writePtr)) {
         return false;
     }
 
diff --git a/libfmq.rs b/libfmq.rs
index a215a02..47c5c15 100644
--- a/libfmq.rs
+++ b/libfmq.rs
@@ -202,7 +202,7 @@ impl<T: Share> MessageQueue<T> {
 
     /// Obtain a copy of the MessageQueue's descriptor, which may be used to
     /// access it remotely.
-    pub fn dupe_desc(&mut self) -> MQDescriptor<T, SynchronizedReadWrite> {
+    pub fn dupe_desc(&self) -> MQDescriptor<T, SynchronizedReadWrite> {
         // SAFETY: dupeDesc may be called on any valid ErasedMessageQueue; it
         // simply forwards to dupeDesc on the inner AidlMessageQueue and wraps
         // in a heap allocation.
@@ -242,10 +242,18 @@ impl<T: Share> MessageQueue<T> {
         // Calls to the descFoo accessors on erased_desc are sound because we know inner.dupeDesc
         // returns a valid pointer to a new heap-allocated ErasedMessageQueueDesc.
         let (grantors, fds, ints, quantum, flags) = unsafe {
-            use std::slice::from_raw_parts;
-            let grantors = from_raw_parts(descGrantors(erased_desc), descNumGrantors(erased_desc));
-            let fds = from_raw_parts(descHandleFDs(erased_desc), descHandleNumFDs(erased_desc));
-            let ints = from_raw_parts(descHandleInts(erased_desc), descHandleNumInts(erased_desc));
+            let grantors = slice_from_raw_parts_or_empty(
+                descGrantors(erased_desc),
+                descNumGrantors(erased_desc),
+            );
+            let fds = slice_from_raw_parts_or_empty(
+                descHandleFDs(erased_desc),
+                descHandleNumFDs(erased_desc),
+            );
+            let ints = slice_from_raw_parts_or_empty(
+                descHandleInts(erased_desc),
+                descHandleNumInts(erased_desc),
+            );
             let quantum = descQuantum(erased_desc);
             let flags = descFlags(erased_desc);
             (grantors, fds, ints, quantum, flags)
@@ -290,6 +298,25 @@ impl<T: Share> MessageQueue<T> {
     }
 }
 
+/// Forms a slice from a pointer and a length.
+///
+/// Returns an empty slice when `data` is a null pointer and `len` is zero.
+///
+/// # Safety
+///
+/// This function has the same safety requirements as [`std::slice::from_raw_parts`],
+/// but unlike that function, does not exhibit undefined behavior when `data` is a
+/// null pointer and `len` is zero. In this case, it returns an empty slice.
+unsafe fn slice_from_raw_parts_or_empty<'a, T>(data: *const T, len: usize) -> &'a [T] {
+    if data.is_null() && len == 0 {
+        &[]
+    } else {
+        // SAFETY: The caller must guarantee to satisfy the safety requirements
+        // of the standard library function [`std::slice::from_raw_parts`].
+        unsafe { std::slice::from_raw_parts(data, len) }
+    }
+}
+
 #[inline(always)]
 fn ptr<T: Share>(txn: &MemTransaction, idx: usize) -> *mut T {
     let (base, region_idx) = if idx < txn.first.length {
@@ -433,3 +460,33 @@ impl<T: Share> MessageQueue<T> {
         unsafe { self.inner.beginRead(n, addr_of_mut!(txn)) }.then_some(txn)
     }
 }
+
+#[cfg(test)]
+mod test {
+    use super::*;
+
+    #[test]
+    fn slice_from_raw_parts_or_empty_with_nonempty() {
+        const SLICE: &[u8] = &[1, 2, 3, 4, 5, 6];
+        // SAFETY: We are constructing a slice from the pointer and length of valid slice.
+        let from_raw_parts = unsafe {
+            let ptr = SLICE.as_ptr();
+            let len = SLICE.len();
+            slice_from_raw_parts_or_empty(ptr, len)
+        };
+        assert_eq!(SLICE, from_raw_parts);
+    }
+
+    #[test]
+    fn slice_from_raw_parts_or_empty_with_null_pointer_zero_length() {
+        // SAFETY: Calling `slice_from_raw_parts_or_empty` with a null pointer
+        // and a zero length is explicitly allowed by its safety requirements.
+        // In this case, `std::slice::from_raw_parts` has undefined behavior.
+        let empty_from_raw_parts = unsafe {
+            let ptr: *const u8 = std::ptr::null();
+            let len = 0;
+            slice_from_raw_parts_or_empty(ptr, len)
+        };
+        assert_eq!(&[] as &[u8], empty_from_raw_parts);
+    }
+}
diff --git a/tests/aidl/android/fmq/test/EventFlagBits.aidl b/tests/aidl/android/fmq/test/EventFlagBits.aidl
index 202a67c..1a9e44d 100644
--- a/tests/aidl/android/fmq/test/EventFlagBits.aidl
+++ b/tests/aidl/android/fmq/test/EventFlagBits.aidl
@@ -4,6 +4,6 @@ package android.fmq.test;
 
 @Backing(type="int")
 enum EventFlagBits {
-    FMQ_NOT_EMPTY = 1 << 0,
-    FMQ_NOT_FULL = 1 << 1,
+    FMQ_NOT_FULL = 1 << 0,
+    FMQ_NOT_EMPTY = 1 << 1,
 }
diff --git a/tests/aidl/default/Android.bp b/tests/aidl/default/Android.bp
index 7e1cc5d..624acba 100644
--- a/tests/aidl/default/Android.bp
+++ b/tests/aidl/default/Android.bp
@@ -24,6 +24,8 @@ rust_library {
     srcs: ["TestAidlMsgQ.rs"],
 
     rustlibs: [
+        "android.fmq.test-rust",
+        "android.hardware.common.fmq-V1-rust",
         "libfmq_rust",
     ],
     shared_libs: [
@@ -31,10 +33,6 @@ rust_library {
         "libcutils",
         "libutils",
     ],
-    rlibs: [
-        "android.hardware.common.fmq-V1-rust",
-        "android.fmq.test-rust",
-    ],
 
     crate_name: "fmq_test_service_rust_impl",
     host_supported: true,
diff --git a/tests/aidl/default/TestAidlMsgQ.cpp b/tests/aidl/default/TestAidlMsgQ.cpp
index d230993..2d39abf 100644
--- a/tests/aidl/default/TestAidlMsgQ.cpp
+++ b/tests/aidl/default/TestAidlMsgQ.cpp
@@ -59,7 +59,7 @@ ndk::ScopedAStatus TestAidlMsgQ::getFmqUnsyncWrite(
         (mqDesc == nullptr)) {
         *_aidl_return = false;
     } else {
-        *mqDesc = std::move(mFmqUnsynchronized->dupeDesc());
+        *mqDesc = mFmqUnsynchronized->dupeDesc();
         // set write-protection so readers can't mmap and write
         int res = ashmem_set_prot_region(mqDesc->handle.fds[0].get(), PROT_READ);
         if (res == -1) {
diff --git a/tests/fmq_unit_tests.cpp b/tests/fmq_unit_tests.cpp
index 7abe74d..07ed0ce 100644
--- a/tests/fmq_unit_tests.cpp
+++ b/tests/fmq_unit_tests.cpp
@@ -35,8 +35,8 @@ using android::hardware::kSynchronizedReadWrite;
 using android::hardware::kUnsynchronizedWrite;
 
 enum EventFlagBits : uint32_t {
-    kFmqNotEmpty = 1 << 0,
-    kFmqNotFull = 1 << 1,
+    kFmqNotFull = 1 << 0,
+    kFmqNotEmpty = 1 << 1,
 };
 
 typedef android::AidlMessageQueue<uint8_t, SynchronizedReadWrite> AidlMessageQueueSync;
@@ -45,6 +45,8 @@ typedef android::hardware::MessageQueue<uint8_t, kSynchronizedReadWrite> Message
 typedef android::hardware::MessageQueue<uint8_t, kUnsynchronizedWrite> MessageQueueUnsync;
 typedef android::AidlMessageQueue<uint16_t, SynchronizedReadWrite> AidlMessageQueueSync16;
 typedef android::hardware::MessageQueue<uint16_t, kSynchronizedReadWrite> MessageQueueSync16;
+typedef android::AidlMessageQueue<uint16_t, UnsynchronizedWrite> AidlMessageQueueUnsync16;
+typedef android::hardware::MessageQueue<uint16_t, kUnsynchronizedWrite> MessageQueueUnsync16;
 
 typedef android::hardware::MessageQueue<uint8_t, kSynchronizedReadWrite> MessageQueueSync8;
 typedef android::hardware::MQDescriptor<uint8_t, kSynchronizedReadWrite> HidlMQDescSync8;
@@ -80,6 +82,11 @@ typedef ::testing::Types<TestParamTypes<AidlMessageQueueUnsync, SetupType::SINGL
                          TestParamTypes<AidlMessageQueueUnsync, SetupType::DOUBLE_FD>,
                          TestParamTypes<MessageQueueUnsync, SetupType::DOUBLE_FD>>
         UnsyncTypes;
+typedef ::testing::Types<TestParamTypes<AidlMessageQueueUnsync16, SetupType::SINGLE_FD>,
+                         TestParamTypes<MessageQueueUnsync16, SetupType::SINGLE_FD>,
+                         TestParamTypes<AidlMessageQueueUnsync16, SetupType::DOUBLE_FD>,
+                         TestParamTypes<MessageQueueUnsync16, SetupType::DOUBLE_FD>>
+        TwoByteUnsyncTypes;
 typedef ::testing::Types<TestParamTypes<AidlMessageQueueSync16, SetupType::SINGLE_FD>,
                          TestParamTypes<MessageQueueSync16, SetupType::SINGLE_FD>,
                          TestParamTypes<AidlMessageQueueSync16, SetupType::DOUBLE_FD>,
@@ -124,10 +131,10 @@ class SynchronizedReadWrites : public TestBase<T> {
     size_t mNumMessagesMax = 0;
 };
 
-TYPED_TEST_CASE(UnsynchronizedWriteTest, UnsyncTypes);
+TYPED_TEST_CASE(UnsynchronizedReadWriteTest, UnsyncTypes);
 
 template <typename T>
-class UnsynchronizedWriteTest : public TestBase<T> {
+class UnsynchronizedReadWriteTest : public TestBase<T> {
   protected:
     virtual void TearDown() {
         delete mQueue;
@@ -227,6 +234,64 @@ class QueueSizeOdd : public TestBase<T> {
 
 TYPED_TEST_CASE(BadQueueConfig, BadConfigTypes);
 
+TYPED_TEST_CASE(UnsynchronizedOverflowHistoryTest, TwoByteUnsyncTypes);
+
+template <typename T>
+class UnsynchronizedOverflowHistoryTest : public TestBase<T> {
+  protected:
+    virtual void TearDown() { delete mQueue; }
+
+    virtual void SetUp() {
+        static constexpr size_t kNumElementsInQueue = 2048;
+        static constexpr size_t kPayloadSizeBytes = 2;
+        if (T::Setup == SetupType::SINGLE_FD) {
+            mQueue = new (std::nothrow) typename T::MQType(kNumElementsInQueue);
+        } else {
+            android::base::unique_fd ringbufferFd(::ashmem_create_region(
+                    "UnsyncHistory", kNumElementsInQueue * kPayloadSizeBytes));
+            mQueue = new (std::nothrow)
+                    typename T::MQType(kNumElementsInQueue, false, std::move(ringbufferFd),
+                                       kNumElementsInQueue * kPayloadSizeBytes);
+        }
+        ASSERT_NE(nullptr, mQueue);
+        ASSERT_TRUE(mQueue->isValid());
+        mNumMessagesMax = mQueue->getQuantumCount();
+        ASSERT_EQ(kNumElementsInQueue, mNumMessagesMax);
+    }
+
+    typename T::MQType* mQueue = nullptr;
+    size_t mNumMessagesMax = 0;
+};
+
+TYPED_TEST_CASE(UnsynchronizedOverflowHistoryTestSingleElement, TwoByteUnsyncTypes);
+
+template <typename T>
+class UnsynchronizedOverflowHistoryTestSingleElement : public TestBase<T> {
+  protected:
+    virtual void TearDown() { delete mQueue; }
+
+    virtual void SetUp() {
+        static constexpr size_t kNumElementsInQueue = 1;
+        static constexpr size_t kPayloadSizeBytes = 2;
+        if (T::Setup == SetupType::SINGLE_FD) {
+            mQueue = new (std::nothrow) typename T::MQType(kNumElementsInQueue);
+        } else {
+            android::base::unique_fd ringbufferFd(::ashmem_create_region(
+                    "UnsyncHistory", kNumElementsInQueue * kPayloadSizeBytes));
+            mQueue = new (std::nothrow)
+                    typename T::MQType(kNumElementsInQueue, false, std::move(ringbufferFd),
+                                       kNumElementsInQueue * kPayloadSizeBytes);
+        }
+        ASSERT_NE(nullptr, mQueue);
+        ASSERT_TRUE(mQueue->isValid());
+        mNumMessagesMax = mQueue->getQuantumCount();
+        ASSERT_EQ(kNumElementsInQueue, mNumMessagesMax);
+    }
+
+    typename T::MQType* mQueue = nullptr;
+    size_t mNumMessagesMax = 0;
+};
+
 template <typename T>
 class BadQueueConfig : public TestBase<T> {};
 
@@ -238,7 +303,8 @@ class DoubleFdFailures : public ::testing::Test {};
 /*
  * Utility function to initialize data to be written to the FMQ
  */
-inline void initData(uint8_t* data, size_t count) {
+template <typename T>
+inline void initData(T* data, size_t count) {
     for (size_t i = 0; i < count; i++) {
         data[i] = i & 0xFF;
     }
@@ -381,6 +447,8 @@ long numFds() {
 }
 
 TEST_F(AidlOnlyBadQueueConfig, LookForLeakedFds) {
+    // Write a log msg first to open the pmsg FD and socket to logd.
+    LOG(INFO) << "Nothin' to see here...";
     // create/destroy a large number of queues that if we were leaking FDs
     // we could detect it by looking at the number of FDs opened by the this
     // test process.
@@ -1116,7 +1184,7 @@ TYPED_TEST(SynchronizedReadWrites, ReadWriteWrapAround2) {
 /*
  * Verify that a few bytes of data can be successfully written and read.
  */
-TYPED_TEST(UnsynchronizedWriteTest, SmallInputTest1) {
+TYPED_TEST(UnsynchronizedReadWriteTest, SmallInputTest1) {
     const size_t dataLen = 16;
     ASSERT_LE(dataLen, this->mNumMessagesMax);
     uint8_t data[dataLen];
@@ -1131,7 +1199,7 @@ TYPED_TEST(UnsynchronizedWriteTest, SmallInputTest1) {
 /*
  * Verify that read() returns false when trying to read from an empty queue.
  */
-TYPED_TEST(UnsynchronizedWriteTest, ReadWhenEmpty) {
+TYPED_TEST(UnsynchronizedReadWriteTest, ReadWhenEmpty) {
     ASSERT_EQ(0UL, this->mQueue->availableToRead());
     const size_t dataLen = 2;
     ASSERT_TRUE(dataLen < this->mNumMessagesMax);
@@ -1143,7 +1211,7 @@ TYPED_TEST(UnsynchronizedWriteTest, ReadWhenEmpty) {
  * Write the queue when full. Verify that a subsequent writes is succesful.
  * Verify that availableToWrite() returns 0 as expected.
  */
-TYPED_TEST(UnsynchronizedWriteTest, WriteWhenFull1) {
+TYPED_TEST(UnsynchronizedReadWriteTest, WriteWhenFull1) {
     ASSERT_EQ(0UL, this->mQueue->availableToRead());
     std::vector<uint8_t> data(this->mNumMessagesMax);
 
@@ -1161,7 +1229,7 @@ TYPED_TEST(UnsynchronizedWriteTest, WriteWhenFull1) {
  * using beginRead()/commitRead() is succesful.
  * Verify that the next read fails as expected for unsynchronized flavor.
  */
-TYPED_TEST(UnsynchronizedWriteTest, WriteWhenFull2) {
+TYPED_TEST(UnsynchronizedReadWriteTest, WriteWhenFull2) {
     ASSERT_EQ(0UL, this->mQueue->availableToRead());
     std::vector<uint8_t> data(this->mNumMessagesMax);
     ASSERT_TRUE(this->mQueue->write(&data[0], this->mNumMessagesMax));
@@ -1184,7 +1252,7 @@ TYPED_TEST(UnsynchronizedWriteTest, WriteWhenFull2) {
  * Verify that the write is successful and the subsequent read
  * returns the expected data.
  */
-TYPED_TEST(UnsynchronizedWriteTest, LargeInputTest1) {
+TYPED_TEST(UnsynchronizedReadWriteTest, LargeInputTest1) {
     std::vector<uint8_t> data(this->mNumMessagesMax);
     initData(&data[0], this->mNumMessagesMax);
     ASSERT_TRUE(this->mQueue->write(&data[0], this->mNumMessagesMax));
@@ -1198,7 +1266,7 @@ TYPED_TEST(UnsynchronizedWriteTest, LargeInputTest1) {
  * Verify that it fails. Verify that a subsequent read fails and
  * the queue is still empty.
  */
-TYPED_TEST(UnsynchronizedWriteTest, LargeInputTest2) {
+TYPED_TEST(UnsynchronizedReadWriteTest, LargeInputTest2) {
     ASSERT_EQ(0UL, this->mQueue->availableToRead());
     const size_t dataLen = 4096;
     ASSERT_GT(dataLen, this->mNumMessagesMax);
@@ -1216,7 +1284,7 @@ TYPED_TEST(UnsynchronizedWriteTest, LargeInputTest2) {
  * the attempt is succesful. Verify that the read fails
  * as expected.
  */
-TYPED_TEST(UnsynchronizedWriteTest, LargeInputTest3) {
+TYPED_TEST(UnsynchronizedReadWriteTest, LargeInputTest3) {
     std::vector<uint8_t> data(this->mNumMessagesMax);
     initData(&data[0], this->mNumMessagesMax);
     ASSERT_TRUE(this->mQueue->write(&data[0], this->mNumMessagesMax));
@@ -1228,7 +1296,7 @@ TYPED_TEST(UnsynchronizedWriteTest, LargeInputTest3) {
 /*
  * Verify that multiple reads one after the other return expected data.
  */
-TYPED_TEST(UnsynchronizedWriteTest, MultipleRead) {
+TYPED_TEST(UnsynchronizedReadWriteTest, MultipleRead) {
     const size_t chunkSize = 100;
     const size_t chunkNum = 5;
     const size_t dataLen = chunkSize * chunkNum;
@@ -1246,7 +1314,7 @@ TYPED_TEST(UnsynchronizedWriteTest, MultipleRead) {
 /*
  * Verify that multiple writes one after the other happens correctly.
  */
-TYPED_TEST(UnsynchronizedWriteTest, MultipleWrite) {
+TYPED_TEST(UnsynchronizedReadWriteTest, MultipleWrite) {
     const size_t chunkSize = 100;
     const size_t chunkNum = 5;
     const size_t dataLen = chunkSize * chunkNum;
@@ -1269,7 +1337,7 @@ TYPED_TEST(UnsynchronizedWriteTest, MultipleWrite) {
  * Write mNumMessagesMax messages into the queue. This will cause a
  * wrap around. Read and verify the data.
  */
-TYPED_TEST(UnsynchronizedWriteTest, ReadWriteWrapAround) {
+TYPED_TEST(UnsynchronizedReadWriteTest, ReadWriteWrapAround) {
     size_t numMessages = this->mNumMessagesMax - 1;
     std::vector<uint8_t> data(this->mNumMessagesMax);
     std::vector<uint8_t> readData(this->mNumMessagesMax);
@@ -1282,6 +1350,35 @@ TYPED_TEST(UnsynchronizedWriteTest, ReadWriteWrapAround) {
     ASSERT_EQ(data, readData);
 }
 
+/*
+ * Attempt to read more than the maximum number of messages in the queue.
+ */
+TYPED_TEST(UnsynchronizedReadWriteTest, ReadMoreThanNumMessagesMaxFails) {
+    // Fill the queue with data
+    std::vector<uint8_t> data(this->mNumMessagesMax);
+    initData(data.data(), data.size());
+    ASSERT_TRUE(this->mQueue->write(data.data(), data.size()));
+
+    // Attempt to read more than the maximum number of messages in the queue.
+    std::vector<uint8_t> readData(this->mNumMessagesMax + 1);
+    ASSERT_FALSE(this->mQueue->read(readData.data(), readData.size()));
+}
+
+/*
+ * Write some data to the queue and attempt to read more than the available data.
+ */
+TYPED_TEST(UnsynchronizedReadWriteTest, ReadMoreThanAvailableToReadFails) {
+    // Fill half of the queue with data.
+    size_t dataLen = this->mNumMessagesMax / 2;
+    std::vector<uint8_t> data(dataLen);
+    initData(data.data(), data.size());
+    ASSERT_TRUE(this->mQueue->write(data.data(), data.size()));
+
+    // Attempt to read more than the available data.
+    std::vector<uint8_t> readData(dataLen + 1);
+    ASSERT_FALSE(this->mQueue->read(readData.data(), readData.size()));
+}
+
 /*
  * Ensure that the template specialization of MessageQueueBase to element types
  * other than MQErased exposes its static knowledge of element size.
@@ -1299,3 +1396,96 @@ extern "C" uint8_t fmq_rust_test(void);
 TEST(RustInteropTest, Simple) {
     ASSERT_EQ(fmq_rust_test(), 1);
 }
+
+/*
+ * Verifies that after ring buffer overflow and first failed attempt to read
+ * the whole ring buffer is available to read and old values was discarded.
+ */
+TYPED_TEST(UnsynchronizedOverflowHistoryTest, ReadAfterOverflow) {
+    std::vector<uint16_t> data(this->mNumMessagesMax);
+
+    // Fill the queue with monotonic pattern
+    initData(&data[0], this->mNumMessagesMax);
+    ASSERT_TRUE(this->mQueue->write(&data[0], this->mNumMessagesMax));
+
+    // Write more data (first element of the same data) to cause a wrap around
+    ASSERT_TRUE(this->mQueue->write(&data[0], 1));
+
+    // Attempt a read (this should fail due to how UnsynchronizedWrite works)
+    uint16_t readDataPlaceholder;
+    ASSERT_FALSE(this->mQueue->read(&readDataPlaceholder, 1));
+
+    // Verify 1/2 of the ring buffer is available to read
+    ASSERT_EQ(this->mQueue->availableToRead(), this->mQueue->getQuantumCount() / 2);
+
+    // Next read should succeed as the queue read pointer have been reset in previous read.
+    std::vector<uint16_t> readData(this->mQueue->availableToRead());
+    ASSERT_TRUE(this->mQueue->read(readData.data(), readData.size()));
+
+    // Verify that the tail of the data is preserved in history after partial wrap around
+    // and followed by the new data.
+    std::rotate(data.begin(), data.begin() + 1, data.end());
+
+    // Compare in reverse to match tail of the data with readData
+    ASSERT_TRUE(std::equal(readData.rbegin(), readData.rend(), data.rbegin()));
+}
+
+/*
+ * Verifies that after ring buffer overflow between beginRead() and failed commitRead()
+ * the whole ring buffer is available to read and old values was discarded.
+ */
+TYPED_TEST(UnsynchronizedOverflowHistoryTest, CommitReadAfterOverflow) {
+    std::vector<uint16_t> data(this->mNumMessagesMax);
+
+    // Fill the queue with monotonic pattern
+    initData(&data[0], this->mNumMessagesMax);
+    ASSERT_TRUE(this->mQueue->write(&data[0], this->mNumMessagesMax));
+
+    typename TypeParam::MQType::MemTransaction tx;
+    ASSERT_TRUE(this->mQueue->beginRead(this->mNumMessagesMax, &tx));
+
+    // Write more data (first element of the same data) to cause a wrap around
+    ASSERT_TRUE(this->mQueue->write(&data[0], 1));
+
+    // Attempt to commit a read should fail due to ring buffer wrap around
+    ASSERT_FALSE(this->mQueue->commitRead(this->mNumMessagesMax));
+
+    // Verify 1/2 of the ring buffer is available to read
+    ASSERT_EQ(this->mQueue->availableToRead(), this->mQueue->getQuantumCount() / 2);
+
+    // Next read should succeed as the queue read pointer have been reset in previous commitRead.
+    std::vector<uint16_t> readData(this->mQueue->availableToRead());
+    ASSERT_TRUE(this->mQueue->read(readData.data(), readData.size()));
+
+    // Verify that the tail of the data is preserved in history after partial wrap around
+    // and followed by the new data.
+    std::rotate(data.begin(), data.begin() + 1, data.end());
+    ASSERT_TRUE(std::equal(readData.rbegin(), readData.rend(), data.rbegin()));
+}
+
+/*
+ * Verifies a queue of a single element will fail a read after a write overflow
+ * and then recover.
+ */
+TYPED_TEST(UnsynchronizedOverflowHistoryTestSingleElement, ReadAfterOverflow) {
+    constexpr uint16_t kValue = 4;
+    std::vector<uint16_t> data = {kValue};
+
+    // single write/read works normally
+    ASSERT_TRUE(this->mQueue->write(&data[0], 1));
+    uint16_t readDataPlaceholder;
+    ASSERT_TRUE(this->mQueue->read(&readDataPlaceholder, 1));
+    EXPECT_EQ(readDataPlaceholder, kValue);
+
+    // Write more data (first element of the same data) to cause a wrap around
+    ASSERT_TRUE(this->mQueue->write(&data[0], 1));
+    ASSERT_TRUE(this->mQueue->write(&data[0], 1));
+
+    // Attempt a read (this should fail due to how UnsynchronizedWrite works)
+    ASSERT_FALSE(this->mQueue->read(&readDataPlaceholder, 1));
+
+    // Subsequent write/reads should work again
+    ASSERT_TRUE(this->mQueue->write(&data[0], 1));
+    ASSERT_TRUE(this->mQueue->read(&readDataPlaceholder, 1));
+    EXPECT_EQ(readDataPlaceholder, kValue);
+}
diff --git a/tests/msgq_rust_test_client.rs b/tests/msgq_rust_test_client.rs
index bad57a7..a78000a 100644
--- a/tests/msgq_rust_test_client.rs
+++ b/tests/msgq_rust_test_client.rs
@@ -33,7 +33,7 @@ fn setup_test_service() -> (MessageQueue<i32>, Strong<dyn ITestAidlMsgQ>) {
     let num_elements_in_sync_queue: usize = (page_size - 16) / std::mem::size_of::<i32>();
 
     /* Create a queue on the client side. */
-    let mut mq = MessageQueue::<i32>::new(
+    let mq = MessageQueue::<i32>::new(
         num_elements_in_sync_queue,
         true, /* configure event flag word */
     );
diff --git a/tests/msgq_test_client.cpp b/tests/msgq_test_client.cpp
index 53a971e..22c91d1 100644
--- a/tests/msgq_test_client.cpp
+++ b/tests/msgq_test_client.cpp
@@ -42,6 +42,12 @@ using ::aidl::android::fmq::test::FixedParcelable;
 using ::aidl::android::fmq::test::FixedUnion;
 using ::aidl::android::fmq::test::ITestAidlMsgQ;
 using android::hardware::tests::msgq::V1_0::ITestMsgQ;
+static_assert(static_cast<uint32_t>(ITestMsgQ::EventFlagBits::FMQ_NOT_FULL) ==
+                      static_cast<uint32_t>(EventFlagBits::FMQ_NOT_FULL),
+              "The AIDL and HIDL test interfaces must use the same values!");
+static_assert(static_cast<uint32_t>(ITestMsgQ::EventFlagBits::FMQ_NOT_EMPTY) ==
+                      static_cast<uint32_t>(EventFlagBits::FMQ_NOT_EMPTY),
+              "The AIDL and HIDL test interfaces must use the same values!");
 
 // libhidl
 using android::hardware::isHidlSupported;
@@ -375,7 +381,6 @@ TYPED_TEST(UnsynchronizedWriteClientMultiProcess, MultipleReadersAfterOverflow)
 
         // Verify that the read is successful.
         ASSERT_TRUE(queue->read(&readData[0], dataLen));
-        ASSERT_TRUE(verifyData(&readData[0], dataLen));
 
         delete queue;
         exit(0);
@@ -409,7 +414,6 @@ TYPED_TEST(UnsynchronizedWriteClientMultiProcess, MultipleReadersAfterOverflow)
 
         // verify that the read is successful.
         ASSERT_TRUE(queue->read(&readData[0], dataLen));
-        ASSERT_TRUE(verifyData(&readData[0], dataLen));
 
         delete queue;
         exit(0);
@@ -747,6 +751,69 @@ TYPED_TEST(SynchronizedReadWriteClient, SmallInputWriterTest1) {
     ASSERT_EQ(originalCount, availableCount);
 }
 
+/*
+ * Write a message to the queue, get a pointer to the memory region for that
+ * first message. Set the write counter to the last byte in the ring buffer.
+ * Try another write, it should fail because the write address is misaligned.
+ */
+TYPED_TEST(SynchronizedReadWriteClient, MisalignedWriteCounterClientSide) {
+    if (TypeParam::UserFd) {
+        // When using the second FD for the ring buffer, we can't get to the read/write
+        // counters from a pointer to the ring buffer, so no sense in testing.
+        GTEST_SKIP();
+    }
+
+    bool errorCallbackTriggered = false;
+    auto errorHandler = [&errorCallbackTriggered](TypeParam::MQType::Error error, std::string&&) {
+        if (error == TypeParam::MQType::Error::POINTER_CORRUPTION) {
+            errorCallbackTriggered = true;
+        }
+    };
+    this->mQueue->setErrorHandler(errorHandler);
+    EXPECT_FALSE(errorCallbackTriggered);
+
+    const size_t dataLen = 1;
+    ASSERT_LE(dataLen, kNumElementsInSyncQueue);
+    int32_t data[dataLen];
+    initData(data, dataLen);
+    // begin write and get a MemTransaction object for the first object in the queue
+    typename TypeParam::MQType::MemTransaction tx;
+    ASSERT_TRUE(this->mQueue->beginWrite(dataLen, &tx));
+    EXPECT_FALSE(errorCallbackTriggered);
+
+    // get a pointer to the beginning of the ring buffer
+    const auto& region = tx.getFirstRegion();
+    int32_t* firstStart = region.getAddress();
+
+    // because this is the first location in the ring buffer, we can get
+    // access to the read and write pointer stored in the fd. 8 bytes back for the
+    // write counter and 16 bytes back for the read counter
+    uint64_t* writeCntr = (uint64_t*)((uint8_t*)firstStart - 8);
+
+    // set it to point to the very last byte in the ring buffer
+    *(writeCntr) = this->mQueue->getQuantumCount() * this->mQueue->getQuantumSize() - 1;
+    ASSERT_TRUE(*writeCntr % sizeof(int32_t) != 0);
+    EXPECT_FALSE(errorCallbackTriggered);
+
+    ASSERT_TRUE(this->mQueue->commitWrite(dataLen));
+    EXPECT_FALSE(errorCallbackTriggered);
+
+    // This next write will be misaligned and will overlap outside of the ring buffer.
+    // The write should fail.
+    EXPECT_FALSE(this->mQueue->write(data, dataLen));
+    EXPECT_TRUE(errorCallbackTriggered);
+
+    errorCallbackTriggered = false;
+    EXPECT_EQ(0, this->mQueue->availableToWrite());
+    EXPECT_TRUE(errorCallbackTriggered);
+
+    // Check that it is possible to reset the error handler.
+    errorCallbackTriggered = false;
+    this->mQueue->setErrorHandler(nullptr);
+    EXPECT_EQ(0, this->mQueue->availableToWrite());
+    EXPECT_FALSE(errorCallbackTriggered);
+}
+
 /*
  * Write a small number of messages to FMQ using the beginWrite()/CommitWrite()
  * APIs. Request mService to read and verify that the write was successful.
@@ -1042,21 +1109,25 @@ TYPED_TEST(UnsynchronizedWriteClient, LargeInputTest2) {
  * Write until FMQ is full.
  * Verify that another write attempt is successful.
  * Request this->mService to read. Verify that read is unsuccessful
- * because of the write rollover.
+ * because of the write overflow.
  * Perform another write and verify that the read is successful
  * to check if the reader process can recover from the error condition.
  */
 TYPED_TEST(UnsynchronizedWriteClient, LargeInputTest3) {
     ASSERT_TRUE(this->requestWriteFmqUnsync(this->mNumMessagesMax, this->mService));
     ASSERT_EQ(0UL, this->mQueue->availableToWrite());
+
+    int32_t readData;
     ASSERT_TRUE(this->requestWriteFmqUnsync(1, this->mService));
 
-    bool ret = this->requestReadFmqUnsync(this->mNumMessagesMax, this->mService);
-    ASSERT_FALSE(ret);
-    ASSERT_TRUE(this->requestWriteFmqUnsync(this->mNumMessagesMax, this->mService));
+    ASSERT_FALSE(this->mQueue->read(&readData, 1));
 
-    ret = this->requestReadFmqUnsync(this->mNumMessagesMax, this->mService);
-    ASSERT_TRUE(ret);
+    // Half of the buffer gets cleared on overflow so single item write will not
+    // cause another overflow.
+    ASSERT_TRUE(this->requestWriteFmqUnsync(1, this->mService));
+
+    // Half of the buffer plus a newly written element will be available.
+    ASSERT_TRUE(this->mQueue->read(&readData, 1));
 }
 
 /*
```

