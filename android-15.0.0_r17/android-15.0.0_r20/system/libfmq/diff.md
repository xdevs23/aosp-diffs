```diff
diff --git a/ErasedMessageQueue.cpp b/ErasedMessageQueue.cpp
index bc1e5a8..d31defa 100644
--- a/ErasedMessageQueue.cpp
+++ b/ErasedMessageQueue.cpp
@@ -87,8 +87,7 @@ ErasedMessageQueue::ErasedMessageQueue(size_t numElementsInQueue, bool configure
               numElementsInQueue, configureEventFlagWord, quantum)) {}
 
 bool ErasedMessageQueue::beginWrite(size_t nMessages, MemTransaction* memTx) const {
-    MessageQueueBase<AidlMQDescriptorShim, MQErased,
-                     FlavorTypeToValue<SynchronizedReadWrite>::value>::MemTransaction memTxInternal;
+    AidlMessageQueue<MQErased, SynchronizedReadWrite>::MemTransaction memTxInternal;
     auto result = inner->beginWrite(nMessages, &memTxInternal);
     memTx->first = memTxInternal.getFirstRegion();
     memTx->second = memTxInternal.getSecondRegion();
@@ -100,8 +99,7 @@ bool ErasedMessageQueue::commitWrite(size_t nMessages) {
 }
 
 bool ErasedMessageQueue::beginRead(size_t nMessages, MemTransaction* memTx) const {
-    MessageQueueBase<AidlMQDescriptorShim, MQErased,
-                     FlavorTypeToValue<SynchronizedReadWrite>::value>::MemTransaction memTxInternal;
+    AidlMessageQueue<MQErased, SynchronizedReadWrite>::MemTransaction memTxInternal;
     auto result = inner->beginRead(nMessages, &memTxInternal);
     memTx->first = memTxInternal.getFirstRegion();
     memTx->second = memTxInternal.getSecondRegion();
diff --git a/ErasedMessageQueue.hpp b/ErasedMessageQueue.hpp
index b4b5931..8f1c8c6 100644
--- a/ErasedMessageQueue.hpp
+++ b/ErasedMessageQueue.hpp
@@ -23,10 +23,8 @@ using aidl::android::hardware::common::fmq::SynchronizedReadWrite;
 using namespace android;
 
 struct MemTransaction {
-    MessageQueueBase<AidlMQDescriptorShim, MQErased,
-                     FlavorTypeToValue<SynchronizedReadWrite>::value>::MemRegion first;
-    MessageQueueBase<AidlMQDescriptorShim, MQErased,
-                     FlavorTypeToValue<SynchronizedReadWrite>::value>::MemRegion second;
+    AidlMessageQueue<MQErased, SynchronizedReadWrite>::MemRegion first;
+    AidlMessageQueue<MQErased, SynchronizedReadWrite>::MemRegion second;
 };
 
 typedef MQDescriptor<MQErased, SynchronizedReadWrite> ErasedMessageQueueDesc;
diff --git a/include/fmq/AidlMQDescriptorShim.h b/include/fmq/AidlMQDescriptorShim.h
index de175da..675a0e1 100644
--- a/include/fmq/AidlMQDescriptorShim.h
+++ b/include/fmq/AidlMQDescriptorShim.h
@@ -13,24 +13,31 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-
-#include <aidl/android/hardware/common/fmq/MQDescriptor.h>
+#pragma once
 #include <cutils/native_handle.h>
-#include <fmq/MQDescriptorBase.h>
 #include <limits>
 #include <type_traits>
 
+#include <aidl/android/hardware/common/fmq/MQDescriptor.h>
+#include <fmq/MQDescriptorBase.h>
+#include "AidlMQDescriptorShimBase.h"
+
 namespace android {
 namespace details {
-
-using aidl::android::hardware::common::fmq::GrantorDescriptor;
 using aidl::android::hardware::common::fmq::MQDescriptor;
 using aidl::android::hardware::common::fmq::SynchronizedReadWrite;
 using aidl::android::hardware::common::fmq::UnsynchronizedWrite;
 using android::hardware::MQFlavor;
 
+struct BackendTypesStore {
+    template <typename T, typename flavor>
+    using MQDescriptorType = aidl::android::hardware::common::fmq::MQDescriptor<T, flavor>;
+    using SynchronizedReadWriteType = aidl::android::hardware::common::fmq::SynchronizedReadWrite;
+    using UnsynchronizedWriteType = aidl::android::hardware::common::fmq::UnsynchronizedWrite;
+};
+
 template <typename T, MQFlavor flavor>
-struct AidlMQDescriptorShim {
+struct AidlMQDescriptorShim : public AidlMQDescriptorShimBase<T, flavor, BackendTypesStore> {
     // Takes ownership of handle
     AidlMQDescriptorShim(const std::vector<android::hardware::GrantorDescriptor>& grantors,
                          native_handle_t* nHandle, size_t size);
@@ -50,35 +57,6 @@ struct AidlMQDescriptorShim {
         : AidlMQDescriptorShim(0, nullptr, 0) {
         *this = other;
     }
-    AidlMQDescriptorShim& operator=(const AidlMQDescriptorShim& other);
-
-    ~AidlMQDescriptorShim();
-
-    size_t getSize() const;
-
-    size_t getQuantum() const;
-
-    uint32_t getFlags() const;
-
-    bool isHandleValid() const { return mHandle != nullptr; }
-    size_t countGrantors() const { return mGrantors.size(); }
-
-    inline const std::vector<android::hardware::GrantorDescriptor>& grantors() const {
-        return mGrantors;
-    }
-
-    inline const ::native_handle_t* handle() const { return mHandle; }
-
-    inline ::native_handle_t* handle() { return mHandle; }
-
-    static const size_t kOffsetOfGrantors;
-    static const size_t kOffsetOfHandle;
-
-  private:
-    std::vector<android::hardware::GrantorDescriptor> mGrantors;
-    native_handle_t* mHandle = nullptr;
-    uint32_t mQuantum = 0;
-    uint32_t mFlags = 0;
 };
 
 template <typename T, MQFlavor flavor>
@@ -86,181 +64,18 @@ AidlMQDescriptorShim<T, flavor>::AidlMQDescriptorShim(
         const MQDescriptor<T, typename std::conditional<flavor == hardware::kSynchronizedReadWrite,
                                                         SynchronizedReadWrite,
                                                         UnsynchronizedWrite>::type>& desc)
-    : mQuantum(desc.quantum), mFlags(desc.flags) {
-    if (desc.quantum < 0 || desc.flags < 0) {
-        // MQDescriptor uses signed integers, but the values must be positive.
-        hardware::details::logError("Invalid MQDescriptor. Values must be positive. quantum: " +
-                                    std::to_string(desc.quantum) +
-                                    ". flags: " + std::to_string(desc.flags));
-        return;
-    }
-
-    mGrantors.resize(desc.grantors.size());
-    for (size_t i = 0; i < desc.grantors.size(); ++i) {
-        if (desc.grantors[i].offset < 0 || desc.grantors[i].extent < 0 ||
-            desc.grantors[i].fdIndex < 0) {
-            // GrantorDescriptor uses signed integers, but the values must be positive.
-            // Return before setting up the native_handle to make this invalid.
-            hardware::details::logError(
-                    "Invalid MQDescriptor grantors. Values must be positive. Grantor index: " +
-                    std::to_string(i) + ". offset: " + std::to_string(desc.grantors[i].offset) +
-                    ". extent: " + std::to_string(desc.grantors[i].extent));
-            return;
-        }
-        mGrantors[i].flags = 0;
-        mGrantors[i].fdIndex = desc.grantors[i].fdIndex;
-        mGrantors[i].offset = desc.grantors[i].offset;
-        mGrantors[i].extent = desc.grantors[i].extent;
-    }
-
-    mHandle = native_handle_create(desc.handle.fds.size() /* num fds */,
-                                   desc.handle.ints.size() /* num ints */);
-    if (mHandle == nullptr) {
-        hardware::details::logError("Null native_handle_t");
-        return;
-    }
-    int data_index = 0;
-    for (const auto& fd : desc.handle.fds) {
-        mHandle->data[data_index] = dup(fd.get());
-        data_index++;
-    }
-    for (const auto& data_int : desc.handle.ints) {
-        mHandle->data[data_index] = data_int;
-        data_index++;
-    }
-}
+    : AidlMQDescriptorShimBase<T, flavor, BackendTypesStore>(desc) {}
 
 template <typename T, MQFlavor flavor>
 AidlMQDescriptorShim<T, flavor>::AidlMQDescriptorShim(
         const std::vector<android::hardware::GrantorDescriptor>& grantors, native_handle_t* nhandle,
         size_t size)
-    : mGrantors(grantors),
-      mHandle(nhandle),
-      mQuantum(static_cast<uint32_t>(size)),
-      mFlags(flavor) {}
-
-template <typename T, MQFlavor flavor>
-AidlMQDescriptorShim<T, flavor>& AidlMQDescriptorShim<T, flavor>::operator=(
-        const AidlMQDescriptorShim& other) {
-    mGrantors = other.mGrantors;
-    if (mHandle != nullptr) {
-        native_handle_close(mHandle);
-        native_handle_delete(mHandle);
-        mHandle = nullptr;
-    }
-    mQuantum = other.mQuantum;
-    mFlags = other.mFlags;
-
-    if (other.mHandle != nullptr) {
-        mHandle = native_handle_create(other.mHandle->numFds, other.mHandle->numInts);
-
-        for (int i = 0; i < other.mHandle->numFds; ++i) {
-            mHandle->data[i] = dup(other.mHandle->data[i]);
-        }
-
-        memcpy(&mHandle->data[other.mHandle->numFds], &other.mHandle->data[other.mHandle->numFds],
-               static_cast<size_t>(other.mHandle->numInts) * sizeof(int));
-    }
-
-    return *this;
-}
+    : AidlMQDescriptorShimBase<T, flavor, BackendTypesStore>(grantors, nhandle, size) {}
 
 template <typename T, MQFlavor flavor>
 AidlMQDescriptorShim<T, flavor>::AidlMQDescriptorShim(size_t bufferSize, native_handle_t* nHandle,
                                                       size_t messageSize, bool configureEventFlag)
-    : mHandle(nHandle), mQuantum(messageSize), mFlags(flavor) {
-    /*
-     * TODO(b/165674950) Since AIDL does not support unsigned integers, it can only support
-     * The offset of EventFlag word needs to fit into an int32_t in MQDescriptor. This word comes
-     * after the readPtr, writePtr, and dataBuffer.
-     */
-    bool overflow = bufferSize > std::numeric_limits<uint64_t>::max() -
-                                         (sizeof(hardware::details::RingBufferPosition) +
-                                          sizeof(hardware::details::RingBufferPosition));
-    uint64_t largestOffset = hardware::details::alignToWordBoundary(
-            sizeof(hardware::details::RingBufferPosition) +
-            sizeof(hardware::details::RingBufferPosition) + bufferSize);
-    if (overflow || largestOffset > std::numeric_limits<int32_t>::max() ||
-        messageSize > std::numeric_limits<int32_t>::max()) {
-        hardware::details::logError(
-                "Queue size is too large. Message size: " + std::to_string(messageSize) +
-                " bytes. Data buffer size: " + std::to_string(bufferSize) + " bytes. Max size: " +
-                std::to_string(std::numeric_limits<int32_t>::max()) + " bytes.");
-        return;
-    }
-
-    /*
-     * If configureEventFlag is true, allocate an additional spot in mGrantor
-     * for containing the fd and offset for mmapping the EventFlag word.
-     */
-    mGrantors.resize(configureEventFlag ? hardware::details::kMinGrantorCountForEvFlagSupport
-                                        : hardware::details::kMinGrantorCount);
-
-    size_t memSize[] = {
-            sizeof(hardware::details::RingBufferPosition), /* memory to be allocated for read
-                                                            * pointer counter
-                                                            */
-            sizeof(hardware::details::RingBufferPosition), /* memory to be allocated for write
-                                                     pointer counter */
-            bufferSize,                   /* memory to be allocated for data buffer */
-            sizeof(std::atomic<uint32_t>) /* memory to be allocated for EventFlag word */
-    };
-
-    /*
-     * Create a default grantor descriptor for read, write pointers and
-     * the data buffer. fdIndex parameter is set to 0 by default and
-     * the offset for each grantor is contiguous.
-     */
-    for (size_t grantorPos = 0, offset = 0; grantorPos < mGrantors.size();
-         offset += memSize[grantorPos++]) {
-        mGrantors[grantorPos] = {
-                0 /* grantor flags */, 0 /* fdIndex */,
-                static_cast<uint32_t>(hardware::details::alignToWordBoundary(offset)),
-                memSize[grantorPos]};
-    }
-}
-
-template <typename T, MQFlavor flavor>
-AidlMQDescriptorShim<T, flavor>::~AidlMQDescriptorShim() {
-    if (mHandle != nullptr) {
-        native_handle_close(mHandle);
-        native_handle_delete(mHandle);
-    }
-}
-
-template <typename T, MQFlavor flavor>
-size_t AidlMQDescriptorShim<T, flavor>::getSize() const {
-    if (mGrantors.size() > hardware::details::DATAPTRPOS) {
-        return mGrantors[hardware::details::DATAPTRPOS].extent;
-    } else {
-        return 0;
-    }
-}
-
-template <typename T, MQFlavor flavor>
-size_t AidlMQDescriptorShim<T, flavor>::getQuantum() const {
-    return mQuantum;
-}
-
-template <typename T, MQFlavor flavor>
-uint32_t AidlMQDescriptorShim<T, flavor>::getFlags() const {
-    return mFlags;
-}
-
-template <typename T, MQFlavor flavor>
-std::string toString(const AidlMQDescriptorShim<T, flavor>& q) {
-    std::string os;
-    if (flavor & hardware::kSynchronizedReadWrite) {
-        os += "fmq_sync";
-    }
-    if (flavor & hardware::kUnsynchronizedWrite) {
-        os += "fmq_unsync";
-    }
-    os += " {" + toString(q.grantors().size()) + " grantor(s), " +
-          "size = " + toString(q.getSize()) + ", .handle = " + toString(q.handle()) +
-          ", .quantum = " + toString(q.getQuantum()) + "}";
-    return os;
-}
-
+    : AidlMQDescriptorShimBase<T, flavor, BackendTypesStore>(bufferSize, nHandle, messageSize,
+                                                             configureEventFlag) {}
 }  // namespace details
 }  // namespace android
diff --git a/include/fmq/AidlMQDescriptorShimBase.h b/include/fmq/AidlMQDescriptorShimBase.h
new file mode 100644
index 0000000..bff5763
--- /dev/null
+++ b/include/fmq/AidlMQDescriptorShimBase.h
@@ -0,0 +1,267 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+#include <cutils/native_handle.h>
+#include <limits>
+#include <type_traits>
+
+#include <fmq/MQDescriptorBase.h>
+
+namespace android {
+namespace details {
+
+using hardware::MQFlavor;
+
+template <typename T, MQFlavor flavor, typename BackendTypes>
+struct AidlMQDescriptorShimBase {
+    typedef typename BackendTypes::SynchronizedReadWriteType SynchronizedReadWriteType;
+    typedef typename BackendTypes::UnsynchronizedWriteType UnsynchronizedWriteType;
+
+    // Takes ownership of handle
+    AidlMQDescriptorShimBase(const std::vector<android::hardware::GrantorDescriptor>& grantors,
+                             native_handle_t* nHandle, size_t size);
+
+    // Takes ownership of handle
+    AidlMQDescriptorShimBase(
+            const typename BackendTypes::template MQDescriptorType<
+                    T, typename std::conditional<flavor == hardware::kSynchronizedReadWrite,
+                                                 SynchronizedReadWriteType,
+                                                 UnsynchronizedWriteType>::type>& desc);
+
+    // Takes ownership of handle
+    AidlMQDescriptorShimBase(size_t bufferSize, native_handle_t* nHandle, size_t messageSize,
+                             bool configureEventFlag = false);
+
+    explicit AidlMQDescriptorShimBase(const AidlMQDescriptorShimBase& other)
+        : AidlMQDescriptorShimBase(0, nullptr, 0) {
+        *this = other;
+    }
+    AidlMQDescriptorShimBase& operator=(const AidlMQDescriptorShimBase& other);
+
+    ~AidlMQDescriptorShimBase();
+
+    size_t getSize() const;
+
+    size_t getQuantum() const;
+
+    uint32_t getFlags() const;
+
+    bool isHandleValid() const { return mHandle != nullptr; }
+    size_t countGrantors() const { return mGrantors.size(); }
+
+    inline const std::vector<android::hardware::GrantorDescriptor>& grantors() const {
+        return mGrantors;
+    }
+
+    inline const ::native_handle_t* handle() const { return mHandle; }
+
+    inline ::native_handle_t* handle() { return mHandle; }
+
+    static const size_t kOffsetOfGrantors;
+    static const size_t kOffsetOfHandle;
+
+  private:
+    std::vector<android::hardware::GrantorDescriptor> mGrantors;
+    native_handle_t* mHandle = nullptr;
+    uint32_t mQuantum = 0;
+    uint32_t mFlags = 0;
+};
+
+template <typename T, MQFlavor flavor, typename BackendTypes>
+AidlMQDescriptorShimBase<T, flavor, BackendTypes>::AidlMQDescriptorShimBase(
+        const typename BackendTypes::template MQDescriptorType<
+                T, typename std::conditional<flavor == hardware::kSynchronizedReadWrite,
+                                             SynchronizedReadWriteType,
+                                             UnsynchronizedWriteType>::type>& desc)
+    : mQuantum(desc.quantum), mFlags(desc.flags) {
+    if (desc.quantum < 0 || desc.flags < 0) {
+        // MQDescriptor uses signed integers, but the values must be positive.
+        hardware::details::logError("Invalid MQDescriptor. Values must be positive. quantum: " +
+                                    std::to_string(desc.quantum) +
+                                    ". flags: " + std::to_string(desc.flags));
+        return;
+    }
+
+    mGrantors.resize(desc.grantors.size());
+    for (size_t i = 0; i < desc.grantors.size(); ++i) {
+        if (desc.grantors[i].offset < 0 || desc.grantors[i].extent < 0 ||
+            desc.grantors[i].fdIndex < 0) {
+            // GrantorDescriptor uses signed integers, but the values must be positive.
+            // Return before setting up the native_handle to make this invalid.
+            hardware::details::logError(
+                    "Invalid MQDescriptor grantors. Values must be positive. Grantor index: " +
+                    std::to_string(i) + ". offset: " + std::to_string(desc.grantors[i].offset) +
+                    ". extent: " + std::to_string(desc.grantors[i].extent));
+            return;
+        }
+        mGrantors[i].flags = 0;
+        mGrantors[i].fdIndex = desc.grantors[i].fdIndex;
+        mGrantors[i].offset = desc.grantors[i].offset;
+        mGrantors[i].extent = desc.grantors[i].extent;
+    }
+
+    mHandle = native_handle_create(desc.handle.fds.size() /* num fds */,
+                                   desc.handle.ints.size() /* num ints */);
+    if (mHandle == nullptr) {
+        hardware::details::logError("Null native_handle_t");
+        return;
+    }
+    int data_index = 0;
+    for (const auto& fd : desc.handle.fds) {
+        mHandle->data[data_index] = dup(fd.get());
+        data_index++;
+    }
+    for (const auto& data_int : desc.handle.ints) {
+        mHandle->data[data_index] = data_int;
+        data_index++;
+    }
+}
+
+template <typename T, MQFlavor flavor, typename BackendTypes>
+AidlMQDescriptorShimBase<T, flavor, BackendTypes>::AidlMQDescriptorShimBase(
+        const std::vector<android::hardware::GrantorDescriptor>& grantors, native_handle_t* nhandle,
+        size_t size)
+    : mGrantors(grantors),
+      mHandle(nhandle),
+      mQuantum(static_cast<uint32_t>(size)),
+      mFlags(flavor) {}
+
+template <typename T, MQFlavor flavor, typename BackendTypes>
+AidlMQDescriptorShimBase<T, flavor, BackendTypes>&
+AidlMQDescriptorShimBase<T, flavor, BackendTypes>::operator=(
+        const AidlMQDescriptorShimBase& other) {
+    mGrantors = other.mGrantors;
+    if (mHandle != nullptr) {
+        native_handle_close(mHandle);
+        native_handle_delete(mHandle);
+        mHandle = nullptr;
+    }
+    mQuantum = other.mQuantum;
+    mFlags = other.mFlags;
+
+    if (other.mHandle != nullptr) {
+        mHandle = native_handle_create(other.mHandle->numFds, other.mHandle->numInts);
+
+        for (int i = 0; i < other.mHandle->numFds; ++i) {
+            mHandle->data[i] = dup(other.mHandle->data[i]);
+        }
+
+        memcpy(&mHandle->data[other.mHandle->numFds], &other.mHandle->data[other.mHandle->numFds],
+               static_cast<size_t>(other.mHandle->numInts) * sizeof(int));
+    }
+
+    return *this;
+}
+
+template <typename T, MQFlavor flavor, typename BackendTypes>
+AidlMQDescriptorShimBase<T, flavor, BackendTypes>::AidlMQDescriptorShimBase(
+        size_t bufferSize, native_handle_t* nHandle, size_t messageSize, bool configureEventFlag)
+    : mHandle(nHandle), mQuantum(messageSize), mFlags(flavor) {
+    /*
+     * TODO(b/165674950) Since AIDL does not support unsigned integers, it can only support
+     * The offset of EventFlag word needs to fit into an int32_t in MQDescriptor. This word comes
+     * after the readPtr, writePtr, and dataBuffer.
+     */
+    bool overflow = bufferSize > std::numeric_limits<uint64_t>::max() -
+                                         (sizeof(hardware::details::RingBufferPosition) +
+                                          sizeof(hardware::details::RingBufferPosition));
+    uint64_t largestOffset = hardware::details::alignToWordBoundary(
+            sizeof(hardware::details::RingBufferPosition) +
+            sizeof(hardware::details::RingBufferPosition) + bufferSize);
+    if (overflow || largestOffset > std::numeric_limits<int32_t>::max() ||
+        messageSize > std::numeric_limits<int32_t>::max()) {
+        hardware::details::logError(
+                "Queue size is too large. Message size: " + std::to_string(messageSize) +
+                " bytes. Data buffer size: " + std::to_string(bufferSize) + " bytes. Max size: " +
+                std::to_string(std::numeric_limits<int32_t>::max()) + " bytes.");
+        return;
+    }
+
+    /*
+     * If configureEventFlag is true, allocate an additional spot in mGrantor
+     * for containing the fd and offset for mmapping the EventFlag word.
+     */
+    mGrantors.resize(configureEventFlag ? hardware::details::kMinGrantorCountForEvFlagSupport
+                                        : hardware::details::kMinGrantorCount);
+
+    size_t memSize[] = {
+            sizeof(hardware::details::RingBufferPosition), /* memory to be allocated for read
+                                                            * pointer counter
+                                                            */
+            sizeof(hardware::details::RingBufferPosition), /* memory to be allocated for write
+                                                     pointer counter */
+            bufferSize,                   /* memory to be allocated for data buffer */
+            sizeof(std::atomic<uint32_t>) /* memory to be allocated for EventFlag word */
+    };
+
+    /*
+     * Create a default grantor descriptor for read, write pointers and
+     * the data buffer. fdIndex parameter is set to 0 by default and
+     * the offset for each grantor is contiguous.
+     */
+    for (size_t grantorPos = 0, offset = 0; grantorPos < mGrantors.size();
+         offset += memSize[grantorPos++]) {
+        mGrantors[grantorPos] = {
+                0 /* grantor flags */, 0 /* fdIndex */,
+                static_cast<uint32_t>(hardware::details::alignToWordBoundary(offset)),
+                memSize[grantorPos]};
+    }
+}
+
+template <typename T, MQFlavor flavor, typename BackendTypes>
+AidlMQDescriptorShimBase<T, flavor, BackendTypes>::~AidlMQDescriptorShimBase() {
+    if (mHandle != nullptr) {
+        native_handle_close(mHandle);
+        native_handle_delete(mHandle);
+    }
+}
+
+template <typename T, MQFlavor flavor, typename BackendTypes>
+size_t AidlMQDescriptorShimBase<T, flavor, BackendTypes>::getSize() const {
+    if (mGrantors.size() > hardware::details::DATAPTRPOS) {
+        return mGrantors[hardware::details::DATAPTRPOS].extent;
+    } else {
+        return 0;
+    }
+}
+
+template <typename T, MQFlavor flavor, typename BackendTypes>
+size_t AidlMQDescriptorShimBase<T, flavor, BackendTypes>::getQuantum() const {
+    return mQuantum;
+}
+
+template <typename T, MQFlavor flavor, typename BackendTypes>
+uint32_t AidlMQDescriptorShimBase<T, flavor, BackendTypes>::getFlags() const {
+    return mFlags;
+}
+
+template <typename T, MQFlavor flavor, typename BackendTypes>
+std::string toString(const AidlMQDescriptorShimBase<T, flavor, BackendTypes>& q) {
+    std::string os;
+    if (flavor & hardware::kSynchronizedReadWrite) {
+        os += "fmq_sync";
+    }
+    if (flavor & hardware::kUnsynchronizedWrite) {
+        os += "fmq_unsync";
+    }
+    os += " {" + toString(q.grantors().size()) + " grantor(s), " +
+          "size = " + toString(q.getSize()) + ", .handle = " + toString(q.handle()) +
+          ", .quantum = " + toString(q.getQuantum()) + "}";
+    return os;
+}
+
+}  // namespace details
+}  // namespace android
diff --git a/include/fmq/AidlMQDescriptorShimCpp.h b/include/fmq/AidlMQDescriptorShimCpp.h
new file mode 100644
index 0000000..a636fb8
--- /dev/null
+++ b/include/fmq/AidlMQDescriptorShimCpp.h
@@ -0,0 +1,86 @@
+/*
+ * Copyright (C) 2020 The Android Open Source Project
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
+#include <cutils/native_handle.h>
+#include <limits>
+#include <type_traits>
+
+#include <android/hardware/common/fmq/MQDescriptor.h>
+#include <fmq/MQDescriptorBase.h>
+
+#include "AidlMQDescriptorShimBase.h"
+
+namespace android {
+namespace details {
+
+using ::android::hardware::MQFlavor;
+
+struct BackendTypesStoreCpp {
+    template <typename T, typename flavor>
+    using MQDescriptorType = android::hardware::common::fmq::MQDescriptor<T, flavor>;
+    using SynchronizedReadWriteType = android::hardware::common::fmq::SynchronizedReadWrite;
+    using UnsynchronizedWriteType = android::hardware::common::fmq::UnsynchronizedWrite;
+};
+
+template <typename T, MQFlavor flavor>
+struct AidlMQDescriptorShimCpp : public AidlMQDescriptorShimBase<T, flavor, BackendTypesStoreCpp> {
+    // Takes ownership of handle
+    AidlMQDescriptorShimCpp(const std::vector<android::hardware::GrantorDescriptor>& grantors,
+                            native_handle_t* nHandle, size_t size);
+
+    // Takes ownership of handle
+    AidlMQDescriptorShimCpp(
+            const android::hardware::common::fmq::MQDescriptor<
+                    T, typename std::conditional<
+                               flavor == hardware::kSynchronizedReadWrite,
+                               android::hardware::common::fmq::SynchronizedReadWrite,
+                               android::hardware::common::fmq::UnsynchronizedWrite>::type>& desc);
+
+    // Takes ownership of handle
+    AidlMQDescriptorShimCpp(size_t bufferSize, native_handle_t* nHandle, size_t messageSize,
+                            bool configureEventFlag = false);
+
+    explicit AidlMQDescriptorShimCpp(const AidlMQDescriptorShimCpp& other)
+        : AidlMQDescriptorShimCpp(0, nullptr, 0) {
+        *this = other;
+    }
+};
+
+template <typename T, MQFlavor flavor>
+AidlMQDescriptorShimCpp<T, flavor>::AidlMQDescriptorShimCpp(
+        const android::hardware::common::fmq::MQDescriptor<
+                T, typename std::conditional<
+                           flavor == hardware::kSynchronizedReadWrite,
+                           android::hardware::common::fmq::SynchronizedReadWrite,
+                           android::hardware::common::fmq::UnsynchronizedWrite>::type>& desc)
+    : AidlMQDescriptorShimBase<T, flavor, BackendTypesStoreCpp>(desc) {}
+
+template <typename T, MQFlavor flavor>
+AidlMQDescriptorShimCpp<T, flavor>::AidlMQDescriptorShimCpp(
+        const std::vector<android::hardware::GrantorDescriptor>& grantors, native_handle_t* nhandle,
+        size_t size)
+    : AidlMQDescriptorShimBase<T, flavor, BackendTypesStoreCpp>(grantors, nhandle, size) {}
+
+template <typename T, MQFlavor flavor>
+AidlMQDescriptorShimCpp<T, flavor>::AidlMQDescriptorShimCpp(size_t bufferSize,
+                                                            native_handle_t* nHandle,
+                                                            size_t messageSize,
+                                                            bool configureEventFlag)
+    : AidlMQDescriptorShimBase<T, flavor, BackendTypesStoreCpp>(bufferSize, nHandle, messageSize,
+                                                                configureEventFlag) {}
+
+}  // namespace details
+}  // namespace android
diff --git a/include/fmq/AidlMessageQueue.h b/include/fmq/AidlMessageQueue.h
index e4c3d84..8424a20 100644
--- a/include/fmq/AidlMessageQueue.h
+++ b/include/fmq/AidlMessageQueue.h
@@ -13,73 +13,42 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-
 #pragma once
-
 #include <aidl/android/hardware/common/fmq/MQDescriptor.h>
 #include <aidl/android/hardware/common/fmq/SynchronizedReadWrite.h>
 #include <aidl/android/hardware/common/fmq/UnsynchronizedWrite.h>
-#include <cutils/native_handle.h>
-#include <fmq/AidlMQDescriptorShim.h>
-#include <fmq/MessageQueueBase.h>
-#include <utils/Log.h>
-#include <type_traits>
+#include "AidlMQDescriptorShim.h"
+#include "AidlMessageQueueBase.h"
 
 namespace android {
-
 using aidl::android::hardware::common::fmq::MQDescriptor;
 using aidl::android::hardware::common::fmq::SynchronizedReadWrite;
 using aidl::android::hardware::common::fmq::UnsynchronizedWrite;
 using android::details::AidlMQDescriptorShim;
 using android::hardware::MQFlavor;
 
-template <typename T>
-struct FlavorTypeToValue;
-
 template <>
-struct FlavorTypeToValue<SynchronizedReadWrite> {
+struct FlavorTypeToValue<aidl::android::hardware::common::fmq::SynchronizedReadWrite> {
     static constexpr MQFlavor value = hardware::kSynchronizedReadWrite;
 };
 
 template <>
-struct FlavorTypeToValue<UnsynchronizedWrite> {
+struct FlavorTypeToValue<aidl::android::hardware::common::fmq::UnsynchronizedWrite> {
     static constexpr MQFlavor value = hardware::kUnsynchronizedWrite;
 };
 
-typedef uint64_t RingBufferPosition;
-
-/*
- * AIDL parcelables will have the typedef fixed_size. It is std::true_type when the
- * parcelable is annotated with @FixedSize, and std::false_type when not. Other types
- * should not have the fixed_size typedef, so they will always resolve to std::false_type.
- */
-template <typename T, typename = void>
-struct has_typedef_fixed_size : std::false_type {};
-
-template <typename T>
-struct has_typedef_fixed_size<T, std::void_t<typename T::fixed_size>> : T::fixed_size {};
-
-#define STATIC_AIDL_TYPE_CHECK(T)                                                                  \
-    static_assert(has_typedef_fixed_size<T>::value == true || std::is_fundamental<T>::value ||     \
-                          std::is_enum<T>::value,                                                  \
-                  "Only fundamental types, enums, and AIDL parcelables annotated with @FixedSize " \
-                  "and built for the NDK backend are supported as payload types(T).");
+struct BackendTypesStore {
+    template <typename T, MQFlavor flavor>
+    using AidlMQDescriptorShimType = android::details::AidlMQDescriptorShim<T, flavor>;
+    using GrantorDescriptorType = aidl::android::hardware::common::fmq::GrantorDescriptor;
+    template <typename T, typename flavor>
+    using MQDescriptorType = aidl::android::hardware::common::fmq::MQDescriptor<T, flavor>;
+    using FileDescriptorType = ndk::ScopedFileDescriptor;
+    static FileDescriptorType createFromInt(int fd) { return FileDescriptorType(fd); }
+};
 
 template <typename T, typename U>
-struct AidlMessageQueue final
-    : public MessageQueueBase<AidlMQDescriptorShim, T, FlavorTypeToValue<U>::value> {
-    STATIC_AIDL_TYPE_CHECK(T);
-    typedef AidlMQDescriptorShim<T, FlavorTypeToValue<U>::value> Descriptor;
-    /**
-     * This constructor uses the external descriptor used with AIDL interfaces.
-     * It will create an FMQ based on the descriptor that was obtained from
-     * another FMQ instance for communication.
-     *
-     * @param desc Descriptor from another FMQ that contains all of the
-     * information required to create a new instance of that queue.
-     * @param resetPointers Boolean indicating whether the read/write pointers
-     * should be reset or not.
-     */
+struct AidlMessageQueue final : public AidlMessageQueueBase<T, U, BackendTypesStore> {
     AidlMessageQueue(const MQDescriptor<T, U>& desc, bool resetPointers = true);
     ~AidlMessageQueue() = default;
 
@@ -114,64 +83,24 @@ struct AidlMessageQueue final
     AidlMessageQueue(size_t numElementsInQueue, bool configureEventFlagWord,
                      android::base::unique_fd bufferFd, size_t bufferSize,
                      std::enable_if_t<std::is_same_v<V, MQErased>, size_t> quantum);
-
-    MQDescriptor<T, U> dupeDesc() const;
-
-  private:
-    AidlMessageQueue(const AidlMessageQueue& other) = delete;
-    AidlMessageQueue& operator=(const AidlMessageQueue& other) = delete;
-    AidlMessageQueue() = delete;
 };
 
 template <typename T, typename U>
 AidlMessageQueue<T, U>::AidlMessageQueue(const MQDescriptor<T, U>& desc, bool resetPointers)
-    : MessageQueueBase<AidlMQDescriptorShim, T, FlavorTypeToValue<U>::value>(Descriptor(desc),
-                                                                             resetPointers) {}
+    : AidlMessageQueueBase<T, U, BackendTypesStore>(desc, resetPointers) {}
 
 template <typename T, typename U>
 AidlMessageQueue<T, U>::AidlMessageQueue(size_t numElementsInQueue, bool configureEventFlagWord,
                                          android::base::unique_fd bufferFd, size_t bufferSize)
-    : MessageQueueBase<AidlMQDescriptorShim, T, FlavorTypeToValue<U>::value>(
-              numElementsInQueue, configureEventFlagWord, std::move(bufferFd), bufferSize) {}
+    : AidlMessageQueueBase<T, U, BackendTypesStore>(numElementsInQueue, configureEventFlagWord,
+                                                    std::move(bufferFd), bufferSize) {}
 
 template <typename T, typename U>
 template <typename V>
 AidlMessageQueue<T, U>::AidlMessageQueue(
         size_t numElementsInQueue, bool configureEventFlagWord, android::base::unique_fd bufferFd,
         size_t bufferSize, std::enable_if_t<std::is_same_v<V, MQErased>, size_t> quantum)
-    : MessageQueueBase<AidlMQDescriptorShim, T, FlavorTypeToValue<U>::value>(
-              numElementsInQueue, configureEventFlagWord, std::move(bufferFd), bufferSize,
-              quantum) {}
-
-template <typename T, typename U>
-MQDescriptor<T, U> AidlMessageQueue<T, U>::dupeDesc() const {
-    auto* shim = MessageQueueBase<AidlMQDescriptorShim, T, FlavorTypeToValue<U>::value>::getDesc();
-    if (shim) {
-        std::vector<aidl::android::hardware::common::fmq::GrantorDescriptor> grantors;
-        for (const auto& grantor : shim->grantors()) {
-            grantors.push_back(aidl::android::hardware::common::fmq::GrantorDescriptor{
-                    .fdIndex = static_cast<int32_t>(grantor.fdIndex),
-                    .offset = static_cast<int32_t>(grantor.offset),
-                    .extent = static_cast<int64_t>(grantor.extent)});
-        }
-        std::vector<ndk::ScopedFileDescriptor> fds;
-        std::vector<int> ints;
-        int data_index = 0;
-        for (; data_index < shim->handle()->numFds; data_index++) {
-            fds.push_back(ndk::ScopedFileDescriptor(dup(shim->handle()->data[data_index])));
-        }
-        for (; data_index < shim->handle()->numFds + shim->handle()->numInts; data_index++) {
-            ints.push_back(shim->handle()->data[data_index]);
-        }
-        return MQDescriptor<T, U>{
-                .grantors = grantors,
-                .handle = {std::move(fds), std::move(ints)},
-                .quantum = static_cast<int32_t>(shim->getQuantum()),
-                .flags = static_cast<int32_t>(shim->getFlags()),
-        };
-    } else {
-        return MQDescriptor<T, U>();
-    }
-}
+    : AidlMessageQueueBase<T, U, BackendTypesStore>(numElementsInQueue, configureEventFlagWord,
+                                                    std::move(bufferFd), bufferSize, quantum) {}
 
 }  // namespace android
diff --git a/include/fmq/AidlMessageQueueBase.h b/include/fmq/AidlMessageQueueBase.h
new file mode 100644
index 0000000..6b25266
--- /dev/null
+++ b/include/fmq/AidlMessageQueueBase.h
@@ -0,0 +1,176 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+#include <cutils/native_handle.h>
+#include <fmq/MessageQueueBase.h>
+#include <utils/Log.h>
+#include <type_traits>
+
+using android::hardware::MQFlavor;
+
+typedef uint64_t RingBufferPosition;
+
+namespace android {
+
+template <typename T>
+struct FlavorTypeToValue;
+
+/*
+ * AIDL parcelables will have the typedef fixed_size. It is std::true_type when the
+ * parcelable is annotated with @FixedSize, and std::false_type when not. Other types
+ * should not have the fixed_size typedef, so they will always resolve to std::false_type.
+ */
+template <typename T, typename = void>
+struct has_typedef_fixed_size : std::false_type {};
+
+template <typename T>
+struct has_typedef_fixed_size<T, std::void_t<typename T::fixed_size>> : T::fixed_size {};
+
+#define STATIC_AIDL_TYPE_CHECK(T)                                                                  \
+    static_assert(has_typedef_fixed_size<T>::value == true || std::is_fundamental<T>::value ||     \
+                          std::is_enum<T>::value,                                                  \
+                  "Only fundamental types, enums, and AIDL parcelables annotated with @FixedSize " \
+                  "and built for the NDK backend are supported as payload types(T).");
+
+template <template <typename> class C1>
+struct Base {};
+
+template <typename T, typename BaseTypes, typename U>
+struct Queue : Base<BaseTypes::template B> {};
+
+template <typename T, typename U, typename BackendTypes>
+struct AidlMessageQueueBase
+    : public MessageQueueBase<BackendTypes::template AidlMQDescriptorShimType, T,
+                              FlavorTypeToValue<U>::value> {
+    STATIC_AIDL_TYPE_CHECK(T);
+    typedef typename BackendTypes::FileDescriptorType FileDescriptorType;
+    typedef typename BackendTypes::GrantorDescriptorType GrantorDescriptorType;
+    typedef typename BackendTypes::template AidlMQDescriptorShimType<T, FlavorTypeToValue<U>::value>
+            Descriptor;
+    /**
+     * This constructor uses the external descriptor used with AIDL interfaces.
+     * It will create an FMQ based on the descriptor that was obtained from
+     * another FMQ instance for communication.
+     *
+     * @param desc Descriptor from another FMQ that contains all of the
+     * information required to create a new instance of that queue.
+     * @param resetPointers Boolean indicating whether the read/write pointers
+     * should be reset or not.
+     */
+    AidlMessageQueueBase(const typename BackendTypes::template MQDescriptorType<T, U>& desc,
+                         bool resetPointers = true);
+    ~AidlMessageQueueBase() = default;
+
+    /**
+     * This constructor uses Ashmem shared memory to create an FMQ
+     * that can contain a maximum of 'numElementsInQueue' elements of type T.
+     *
+     * @param numElementsInQueue Capacity of the AidlMessageQueueBase in terms of T.
+     * @param configureEventFlagWord Boolean that specifies if memory should
+     * also be allocated and mapped for an EventFlag word.
+     * @param bufferFd User-supplied file descriptor to map the memory for the ringbuffer
+     * By default, bufferFd=-1 means library will allocate ashmem region for ringbuffer.
+     * MessageQueue takes ownership of the file descriptor.
+     * @param bufferSize size of buffer in bytes that bufferFd represents. This
+     * size must be larger than or equal to (numElementsInQueue * sizeof(T)).
+     * Otherwise, operations will cause out-of-bounds memory access.
+     */
+    AidlMessageQueueBase(size_t numElementsInQueue, bool configureEventFlagWord,
+                         android::base::unique_fd bufferFd, size_t bufferSize);
+
+    AidlMessageQueueBase(size_t numElementsInQueue, bool configureEventFlagWord = false)
+        : AidlMessageQueueBase(numElementsInQueue, configureEventFlagWord,
+                               android::base::unique_fd(), 0) {}
+
+    template <typename V = T>
+    AidlMessageQueueBase(size_t numElementsInQueue, bool configureEventFlagWord = false,
+                         std::enable_if_t<std::is_same_v<V, MQErased>, size_t> quantum = sizeof(T))
+        : AidlMessageQueueBase(numElementsInQueue, configureEventFlagWord,
+                               android::base::unique_fd(), 0, quantum) {}
+
+    template <typename V = T>
+    AidlMessageQueueBase(size_t numElementsInQueue, bool configureEventFlagWord,
+                         android::base::unique_fd bufferFd, size_t bufferSize,
+                         std::enable_if_t<std::is_same_v<V, MQErased>, size_t> quantum);
+    typename BackendTypes::template MQDescriptorType<T, U> dupeDesc() const;
+
+  private:
+    AidlMessageQueueBase(const AidlMessageQueueBase& other) = delete;
+    AidlMessageQueueBase& operator=(const AidlMessageQueueBase& other) = delete;
+    AidlMessageQueueBase() = delete;
+};
+
+template <typename T, typename U, typename BackendTypes>
+AidlMessageQueueBase<T, U, BackendTypes>::AidlMessageQueueBase(
+        const typename BackendTypes::template MQDescriptorType<T, U>& desc, bool resetPointers)
+    : MessageQueueBase<BackendTypes::template AidlMQDescriptorShimType, T,
+                       FlavorTypeToValue<U>::value>(Descriptor(desc), resetPointers) {}
+
+template <typename T, typename U, typename BackendTypes>
+AidlMessageQueueBase<T, U, BackendTypes>::AidlMessageQueueBase(size_t numElementsInQueue,
+                                                               bool configureEventFlagWord,
+                                                               android::base::unique_fd bufferFd,
+                                                               size_t bufferSize)
+    : MessageQueueBase<BackendTypes::template AidlMQDescriptorShimType, T,
+                       FlavorTypeToValue<U>::value>(numElementsInQueue, configureEventFlagWord,
+                                                    std::move(bufferFd), bufferSize) {}
+
+template <typename T, typename U, typename BackendTypes>
+template <typename V>
+AidlMessageQueueBase<T, U, BackendTypes>::AidlMessageQueueBase(
+        size_t numElementsInQueue, bool configureEventFlagWord, android::base::unique_fd bufferFd,
+        size_t bufferSize, std::enable_if_t<std::is_same_v<V, MQErased>, size_t> quantum)
+    : MessageQueueBase<BackendTypes::template AidlMQDescriptorShimType, T,
+                       FlavorTypeToValue<U>::value>(numElementsInQueue, configureEventFlagWord,
+                                                    std::move(bufferFd), bufferSize, quantum) {}
+
+template <typename T, typename U, typename BackendTypes>
+typename BackendTypes::template MQDescriptorType<T, U>
+AidlMessageQueueBase<T, U, BackendTypes>::dupeDesc() const {
+    auto* shim = MessageQueueBase<BackendTypes::template AidlMQDescriptorShimType, T,
+                                  FlavorTypeToValue<U>::value>::getDesc();
+    if (shim) {
+        std::vector<GrantorDescriptorType> grantors;
+        for (const auto& grantor : shim->grantors()) {
+            GrantorDescriptorType gd;
+            gd.fdIndex = static_cast<int32_t>(grantor.fdIndex);
+            gd.offset = static_cast<int32_t>(grantor.offset);
+            gd.extent = static_cast<int64_t>(grantor.extent);
+            grantors.push_back(gd);
+        }
+        std::vector<FileDescriptorType> fds;
+        std::vector<int> ints;
+        int data_index = 0;
+        for (; data_index < shim->handle()->numFds; data_index++) {
+            fds.push_back(BackendTypes::createFromInt(dup(shim->handle()->data[data_index])));
+        }
+        for (; data_index < shim->handle()->numFds + shim->handle()->numInts; data_index++) {
+            ints.push_back(shim->handle()->data[data_index]);
+        }
+        typename BackendTypes::template MQDescriptorType<T, U> desc;
+
+        desc.grantors = grantors;
+        desc.handle.fds = std::move(fds);
+        desc.handle.ints = ints;
+        desc.quantum = static_cast<int32_t>(shim->getQuantum());
+        desc.flags = static_cast<int32_t>(shim->getFlags());
+        return desc;
+    } else {
+        return typename BackendTypes::template MQDescriptorType<T, U>();
+    }
+}
+
+}  // namespace android
diff --git a/include/fmq/AidlMessageQueueCpp.h b/include/fmq/AidlMessageQueueCpp.h
new file mode 100644
index 0000000..cde55e8
--- /dev/null
+++ b/include/fmq/AidlMessageQueueCpp.h
@@ -0,0 +1,107 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+#include <android/hardware/common/fmq/MQDescriptor.h>
+#include <android/hardware/common/fmq/SynchronizedReadWrite.h>
+#include <android/hardware/common/fmq/UnsynchronizedWrite.h>
+#include <fmq/MQDescriptorBase.h>
+#include "AidlMQDescriptorShimCpp.h"
+#include "AidlMessageQueueBase.h"
+namespace android {
+
+template <>
+struct FlavorTypeToValue<android::hardware::common::fmq::SynchronizedReadWrite> {
+    static constexpr MQFlavor value = hardware::kSynchronizedReadWrite;
+};
+
+template <>
+struct FlavorTypeToValue<android::hardware::common::fmq::UnsynchronizedWrite> {
+    static constexpr MQFlavor value = hardware::kUnsynchronizedWrite;
+};
+
+struct BackendTypesStoreCpp {
+    template <typename T, MQFlavor flavor>
+    using AidlMQDescriptorShimType = android::details::AidlMQDescriptorShimCpp<T, flavor>;
+    using GrantorDescriptorType = android::hardware::common::fmq::GrantorDescriptor;
+    template <typename T, typename flavor>
+    using MQDescriptorType = android::hardware::common::fmq::MQDescriptor<T, flavor>;
+    using FileDescriptorType = os::ParcelFileDescriptor;
+    static FileDescriptorType createFromInt(int fd) {
+        return FileDescriptorType(binder::unique_fd(fd));
+    }
+};
+
+template <typename T, typename U>
+struct AidlMessageQueueCpp final : public AidlMessageQueueBase<T, U, BackendTypesStoreCpp> {
+    AidlMessageQueueCpp(const android::hardware::common::fmq::MQDescriptor<T, U>& desc,
+                        bool resetPointers = true);
+    ~AidlMessageQueueCpp() = default;
+
+    /**
+     * This constructor uses Ashmem shared memory to create an FMQ
+     * that can contain a maximum of 'numElementsInQueue' elements of type T.
+     *
+     * @param numElementsInQueue Capacity of the AidlMessageQueueCpp in terms of T.
+     * @param configureEventFlagWord Boolean that specifies if memory should
+     * also be allocated and mapped for an EventFlag word.
+     * @param bufferFd User-supplied file descriptor to map the memory for the ringbuffer
+     * By default, bufferFd=-1 means library will allocate ashmem region for ringbuffer.
+     * MessageQueue takes ownership of the file descriptor.
+     * @param bufferSize size of buffer in bytes that bufferFd represents. This
+     * size must be larger than or equal to (numElementsInQueue * sizeof(T)).
+     * Otherwise, operations will cause out-of-bounds memory access.
+     */
+    AidlMessageQueueCpp(size_t numElementsInQueue, bool configureEventFlagWord,
+                        android::base::unique_fd bufferFd, size_t bufferSize);
+
+    AidlMessageQueueCpp(size_t numElementsInQueue, bool configureEventFlagWord = false)
+        : AidlMessageQueueCpp(numElementsInQueue, configureEventFlagWord,
+                              android::base::unique_fd(), 0) {}
+
+    template <typename V = T>
+    AidlMessageQueueCpp(size_t numElementsInQueue, bool configureEventFlagWord = false,
+                        std::enable_if_t<std::is_same_v<V, MQErased>, size_t> quantum = sizeof(T))
+        : AidlMessageQueueCpp(numElementsInQueue, configureEventFlagWord,
+                              android::base::unique_fd(), 0, quantum) {}
+
+    template <typename V = T>
+    AidlMessageQueueCpp(size_t numElementsInQueue, bool configureEventFlagWord,
+                        android::base::unique_fd bufferFd, size_t bufferSize,
+                        std::enable_if_t<std::is_same_v<V, MQErased>, size_t> quantum);
+};
+
+template <typename T, typename U>
+AidlMessageQueueCpp<T, U>::AidlMessageQueueCpp(
+        const android::hardware::common::fmq::MQDescriptor<T, U>& desc, bool resetPointers)
+    : AidlMessageQueueBase<T, U, BackendTypesStoreCpp>(desc, resetPointers) {}
+
+template <typename T, typename U>
+AidlMessageQueueCpp<T, U>::AidlMessageQueueCpp(size_t numElementsInQueue,
+                                               bool configureEventFlagWord,
+                                               android::base::unique_fd bufferFd, size_t bufferSize)
+    : AidlMessageQueueBase<T, U, BackendTypesStoreCpp>(numElementsInQueue, configureEventFlagWord,
+                                                       std::move(bufferFd), bufferSize) {}
+
+template <typename T, typename U>
+template <typename V>
+AidlMessageQueueCpp<T, U>::AidlMessageQueueCpp(
+        size_t numElementsInQueue, bool configureEventFlagWord, android::base::unique_fd bufferFd,
+        size_t bufferSize, std::enable_if_t<std::is_same_v<V, MQErased>, size_t> quantum)
+    : AidlMessageQueueBase<T, U, BackendTypesStoreCpp>(numElementsInQueue, configureEventFlagWord,
+                                                       std::move(bufferFd), bufferSize, quantum) {}
+
+}  // namespace android
\ No newline at end of file
diff --git a/tests/Android.bp b/tests/Android.bp
index 64e4ba5..6bb06d4 100644
--- a/tests/Android.bp
+++ b/tests/Android.bp
@@ -15,6 +15,7 @@
 //
 
 package {
+    default_team: "trendy_team_android_kernel",
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
@@ -93,15 +94,19 @@ cc_test {
         "libhidlbase",
         "liblog",
         "libutils",
+        "libbinder",
         "libbinder_ndk",
     ],
 
     // These are static libs only for testing purposes and portability. Shared
     // libs should be used on device.
     static_libs: [
+        "android.hardware.common-V2-cpp",
+        "android.hardware.common.fmq-V1-cpp",
         "android.hardware.common-V2-ndk",
         "android.hardware.common.fmq-V1-ndk",
         "android.hardware.tests.msgq@1.0",
+        "android.fmq.test-cpp",
         "android.fmq.test-ndk",
     ],
     whole_static_libs: [
@@ -162,6 +167,7 @@ cc_test {
     ],
     static_libs: [
         "android.hardware.common.fmq-V1-ndk",
+        "android.hardware.common.fmq-V1-cpp",
         "libfmq_rust_test",
     ],
 
diff --git a/tests/aidl/Android.bp b/tests/aidl/Android.bp
index 7345d3b..ec8f75e 100644
--- a/tests/aidl/Android.bp
+++ b/tests/aidl/Android.bp
@@ -23,7 +23,7 @@ aidl_interface {
             enabled: true,
         },
         cpp: {
-            enabled: false,
+            enabled: true,
         },
         rust: {
             enabled: true,
diff --git a/tests/fmq_test.py b/tests/fmq_test.py
index ce5de63..0ad8a12 100644
--- a/tests/fmq_test.py
+++ b/tests/fmq_test.py
@@ -82,9 +82,11 @@ if __name__ == '__main__':
             test_name = 'test_%s_to_%s' % (short_name(client), short_name(server))
             # Tests in the C++ test client that are fully supported by the Rust test server
             rust_tests = ":".join([
-                # Only run AIDL tests 0 and 2, not HIDL tests 1 and 3
+                # Only run AIDL tests 0,1, 3 ,4, not HIDL tests 2 and 5
                 "SynchronizedReadWriteClient/0.*",
-                "SynchronizedReadWriteClient/2.*",
+                "SynchronizedReadWriteClient/1.*",
+                "SynchronizedReadWriteClient/3.*",
+                "SynchronizedReadWriteClient/4.*",
                 # Skip blocking tests until the Rust FMQ interface supports them: TODO(b/339999649)
                 "-*Blocking*",
             ])
diff --git a/tests/fmq_unit_tests.cpp b/tests/fmq_unit_tests.cpp
index 07ed0ce..3839d80 100644
--- a/tests/fmq_unit_tests.cpp
+++ b/tests/fmq_unit_tests.cpp
@@ -17,6 +17,7 @@
 #include <android-base/logging.h>
 #include <asm-generic/mman.h>
 #include <fmq/AidlMessageQueue.h>
+#include <fmq/AidlMessageQueueCpp.h>
 #include <fmq/ConvertMQDescriptors.h>
 #include <fmq/EventFlag.h>
 #include <fmq/MessageQueue.h>
@@ -31,6 +32,9 @@
 
 using aidl::android::hardware::common::fmq::SynchronizedReadWrite;
 using aidl::android::hardware::common::fmq::UnsynchronizedWrite;
+using cppSynchronizedReadWrite = android::hardware::common::fmq::SynchronizedReadWrite;
+using cppUnSynchronizedWrite = android::hardware::common::fmq::UnsynchronizedWrite;
+
 using android::hardware::kSynchronizedReadWrite;
 using android::hardware::kUnsynchronizedWrite;
 
@@ -41,11 +45,16 @@ enum EventFlagBits : uint32_t {
 
 typedef android::AidlMessageQueue<uint8_t, SynchronizedReadWrite> AidlMessageQueueSync;
 typedef android::AidlMessageQueue<uint8_t, UnsynchronizedWrite> AidlMessageQueueUnsync;
+typedef android::AidlMessageQueueCpp<uint8_t, cppSynchronizedReadWrite> cppAidlMessageQueueSync;
+typedef android::AidlMessageQueueCpp<uint8_t, cppUnSynchronizedWrite> cppAidlMessageQueueUnsync;
 typedef android::hardware::MessageQueue<uint8_t, kSynchronizedReadWrite> MessageQueueSync;
 typedef android::hardware::MessageQueue<uint8_t, kUnsynchronizedWrite> MessageQueueUnsync;
+
 typedef android::AidlMessageQueue<uint16_t, SynchronizedReadWrite> AidlMessageQueueSync16;
+typedef android::AidlMessageQueueCpp<uint16_t, cppSynchronizedReadWrite> cppAidlMessageQueueSync16;
 typedef android::hardware::MessageQueue<uint16_t, kSynchronizedReadWrite> MessageQueueSync16;
 typedef android::AidlMessageQueue<uint16_t, UnsynchronizedWrite> AidlMessageQueueUnsync16;
+typedef android::AidlMessageQueueCpp<uint16_t, cppUnSynchronizedWrite> cppAidlMessageQueueUnsync16;
 typedef android::hardware::MessageQueue<uint16_t, kUnsynchronizedWrite> MessageQueueUnsync16;
 
 typedef android::hardware::MessageQueue<uint8_t, kSynchronizedReadWrite> MessageQueueSync8;
@@ -53,11 +62,18 @@ typedef android::hardware::MQDescriptor<uint8_t, kSynchronizedReadWrite> HidlMQD
 typedef android::AidlMessageQueue<int8_t, SynchronizedReadWrite> AidlMessageQueueSync8;
 typedef aidl::android::hardware::common::fmq::MQDescriptor<int8_t, SynchronizedReadWrite>
         AidlMQDescSync8;
+typedef android::AidlMessageQueueCpp<int8_t, cppSynchronizedReadWrite> cppAidlMessageQueueSync8;
+typedef android::hardware::common::fmq::MQDescriptor<int8_t, cppSynchronizedReadWrite>
+        cppAidlMQDescSync8;
+
 typedef android::hardware::MessageQueue<uint8_t, kUnsynchronizedWrite> MessageQueueUnsync8;
 typedef android::hardware::MQDescriptor<uint8_t, kUnsynchronizedWrite> HidlMQDescUnsync8;
 typedef android::AidlMessageQueue<int8_t, UnsynchronizedWrite> AidlMessageQueueUnsync8;
 typedef aidl::android::hardware::common::fmq::MQDescriptor<int8_t, UnsynchronizedWrite>
         AidlMQDescUnsync8;
+typedef android::AidlMessageQueueCpp<int8_t, cppUnSynchronizedWrite> cppAidlMessageQueueUnsync8;
+typedef android::hardware::common::fmq::MQDescriptor<int8_t, cppUnSynchronizedWrite>
+        cppAidlMQDescUnsync8;
 
 enum class SetupType {
     SINGLE_FD,
@@ -73,23 +89,31 @@ class TestParamTypes {
 
 // Run everything on both the AIDL and HIDL versions with one and two FDs
 typedef ::testing::Types<TestParamTypes<AidlMessageQueueSync, SetupType::SINGLE_FD>,
+                         TestParamTypes<cppAidlMessageQueueSync, SetupType::SINGLE_FD>,
                          TestParamTypes<MessageQueueSync, SetupType::SINGLE_FD>,
                          TestParamTypes<AidlMessageQueueSync, SetupType::DOUBLE_FD>,
+                         TestParamTypes<cppAidlMessageQueueSync, SetupType::DOUBLE_FD>,
                          TestParamTypes<MessageQueueSync, SetupType::DOUBLE_FD>>
         SyncTypes;
 typedef ::testing::Types<TestParamTypes<AidlMessageQueueUnsync, SetupType::SINGLE_FD>,
+                         TestParamTypes<cppAidlMessageQueueUnsync, SetupType::SINGLE_FD>,
                          TestParamTypes<MessageQueueUnsync, SetupType::SINGLE_FD>,
                          TestParamTypes<AidlMessageQueueUnsync, SetupType::DOUBLE_FD>,
+                         TestParamTypes<cppAidlMessageQueueUnsync, SetupType::DOUBLE_FD>,
                          TestParamTypes<MessageQueueUnsync, SetupType::DOUBLE_FD>>
         UnsyncTypes;
 typedef ::testing::Types<TestParamTypes<AidlMessageQueueUnsync16, SetupType::SINGLE_FD>,
+                         TestParamTypes<cppAidlMessageQueueUnsync16, SetupType::SINGLE_FD>,
                          TestParamTypes<MessageQueueUnsync16, SetupType::SINGLE_FD>,
                          TestParamTypes<AidlMessageQueueUnsync16, SetupType::DOUBLE_FD>,
+                         TestParamTypes<cppAidlMessageQueueUnsync16, SetupType::DOUBLE_FD>,
                          TestParamTypes<MessageQueueUnsync16, SetupType::DOUBLE_FD>>
         TwoByteUnsyncTypes;
 typedef ::testing::Types<TestParamTypes<AidlMessageQueueSync16, SetupType::SINGLE_FD>,
+                         TestParamTypes<cppAidlMessageQueueSync16, SetupType::SINGLE_FD>,
                          TestParamTypes<MessageQueueSync16, SetupType::SINGLE_FD>,
                          TestParamTypes<AidlMessageQueueSync16, SetupType::DOUBLE_FD>,
+                         TestParamTypes<cppAidlMessageQueueSync16, SetupType::DOUBLE_FD>,
                          TestParamTypes<MessageQueueSync16, SetupType::DOUBLE_FD>>
         BadConfigTypes;
 
diff --git a/tests/msgq_test_client.cpp b/tests/msgq_test_client.cpp
index 22c91d1..1618f8d 100644
--- a/tests/msgq_test_client.cpp
+++ b/tests/msgq_test_client.cpp
@@ -25,12 +25,18 @@
 #include <android-base/logging.h>
 #include <android/binder_manager.h>
 #include <android/binder_process.h>
+#include <android/fmq/test/FixedParcelable.h>
+#include <android/fmq/test/FixedUnion.h>
+#include <android/fmq/test/ITestAidlMsgQ.h>
 #include <android/hardware/tests/msgq/1.0/ITestMsgQ.h>
 #include <fmq/AidlMessageQueue.h>
+#include <fmq/AidlMessageQueueCpp.h>
 #include <fmq/EventFlag.h>
 #include <fmq/MessageQueue.h>
 #include <hidl/ServiceManagement.h>
 
+#include <binder/IServiceManager.h>
+
 // libutils:
 using android::OK;
 using android::sp;
@@ -41,6 +47,12 @@ using ::aidl::android::fmq::test::EventFlagBits;
 using ::aidl::android::fmq::test::FixedParcelable;
 using ::aidl::android::fmq::test::FixedUnion;
 using ::aidl::android::fmq::test::ITestAidlMsgQ;
+
+using cppEventFlagBits = ::android::fmq::test::EventFlagBits;
+using cppFixedParcelable = android::fmq::test::FixedParcelable;
+using cppFixedUnion = android::fmq::test::FixedUnion;
+using cppITestAidlMsgQ = ::android::fmq::test::ITestAidlMsgQ;
+
 using android::hardware::tests::msgq::V1_0::ITestMsgQ;
 static_assert(static_cast<uint32_t>(ITestMsgQ::EventFlagBits::FMQ_NOT_FULL) ==
                       static_cast<uint32_t>(EventFlagBits::FMQ_NOT_FULL),
@@ -60,14 +72,19 @@ using android::hardware::details::waitForHwService;
 
 using aidl::android::hardware::common::fmq::SynchronizedReadWrite;
 using aidl::android::hardware::common::fmq::UnsynchronizedWrite;
+using cppSynchronizedReadWrite = ::android::hardware::common::fmq::SynchronizedReadWrite;
+using cppUnSynchronizedWrite = android::hardware::common::fmq::UnsynchronizedWrite;
 using android::hardware::kSynchronizedReadWrite;
 using android::hardware::kUnsynchronizedWrite;
 
 typedef android::AidlMessageQueue<int32_t, SynchronizedReadWrite> AidlMessageQueueSync;
 typedef android::AidlMessageQueue<int32_t, UnsynchronizedWrite> AidlMessageQueueUnsync;
+
+typedef android::AidlMessageQueueCpp<int32_t, cppSynchronizedReadWrite> cppAidlMessageQueueSync;
+typedef android::AidlMessageQueueCpp<int32_t, cppUnSynchronizedWrite> cppAidlMessageQueueUnsync;
+
 typedef android::hardware::MessageQueue<int32_t, kSynchronizedReadWrite> MessageQueueSync;
 typedef android::hardware::MessageQueue<int32_t, kUnsynchronizedWrite> MessageQueueUnsync;
-static const std::string kServiceName = "BnTestAidlMsgQ";
 static const size_t kPageSize = getpagesize();
 static const size_t kNumElementsInSyncQueue = (kPageSize - 16) / sizeof(int32_t);
 
@@ -85,13 +102,17 @@ class TestParamTypes {
 
 // Run everything on both the AIDL and HIDL versions with one and two FDs
 typedef ::testing::Types<TestParamTypes<AidlMessageQueueSync, SetupType::SINGLE_FD>,
+                         TestParamTypes<cppAidlMessageQueueSync, SetupType::SINGLE_FD>,
                          TestParamTypes<MessageQueueSync, SetupType::SINGLE_FD>,
                          TestParamTypes<AidlMessageQueueSync, SetupType::DOUBLE_FD>,
+                         TestParamTypes<cppAidlMessageQueueSync, SetupType::DOUBLE_FD>,
                          TestParamTypes<MessageQueueSync, SetupType::DOUBLE_FD>>
         SyncTypes;
 typedef ::testing::Types<TestParamTypes<AidlMessageQueueUnsync, SetupType::SINGLE_FD>,
+                         TestParamTypes<cppAidlMessageQueueUnsync, SetupType::SINGLE_FD>,
                          TestParamTypes<MessageQueueUnsync, SetupType::SINGLE_FD>,
                          TestParamTypes<AidlMessageQueueUnsync, SetupType::DOUBLE_FD>,
+                         TestParamTypes<cppAidlMessageQueueUnsync, SetupType::DOUBLE_FD>,
                          TestParamTypes<MessageQueueUnsync, SetupType::DOUBLE_FD>>
         UnsyncTypes;
 
@@ -106,7 +127,9 @@ class ClientSyncTestBase<AidlMessageQueueSync> : public ::testing::Test {
         const std::string instance = std::string() + ITestAidlMsgQ::descriptor + "/default";
         ndk::SpAIBinder binder(AServiceManager_getService(instance.c_str()));
         CHECK(nullptr != binder);
-        return ITestAidlMsgQ::fromBinder(binder);
+        auto ret = ITestAidlMsgQ::fromBinder(binder);
+        CHECK(ret->isRemote() == true);
+        return ret;
     }
     bool configureFmqSyncReadWrite(AidlMessageQueueSync* mq) {
         bool result = false;
@@ -127,6 +150,40 @@ class ClientSyncTestBase<AidlMessageQueueSync> : public ::testing::Test {
     std::shared_ptr<ITestAidlMsgQ> mService;
 };
 
+// Specialize for AIDL cpp backend
+template <>
+class ClientSyncTestBase<cppAidlMessageQueueSync> : public ::testing::Test {
+  protected:
+    static sp<cppITestAidlMsgQ> waitGetTestService() {
+        const std::string instance = std::string() + ITestAidlMsgQ::descriptor + "/default";
+        const android::String16 instanceString16(instance.c_str());
+        sp<cppITestAidlMsgQ> binder;
+        status_t err = getService(instanceString16, &binder);
+        if (err != OK) {
+            return nullptr;
+        }
+        CHECK(nullptr != binder);
+        return binder;
+    }
+    bool configureFmqSyncReadWrite(cppAidlMessageQueueSync* mq) {
+        bool result = false;
+        auto ret = mService->configureFmqSyncReadWrite(mq->dupeDesc(), &result);
+        return result && ret.isOk();
+    }
+    bool requestReadFmqSync(size_t dataLen) {
+        bool result = false;
+        auto ret = mService->requestReadFmqSync(dataLen, &result);
+        return result && ret.isOk();
+    }
+    bool requestWriteFmqSync(size_t dataLen) {
+        bool result = false;
+        auto ret = mService->requestWriteFmqSync(dataLen, &result);
+        return result && ret.isOk();
+    }
+
+    sp<cppITestAidlMsgQ> mService;
+};
+
 // Specialize for HIDL
 template <>
 class ClientSyncTestBase<MessageQueueSync> : public ::testing::Test {
@@ -139,6 +196,7 @@ class ClientSyncTestBase<MessageQueueSync> : public ::testing::Test {
             waitForHwService(ITestMsgQ::descriptor, "default");
             sp<ITestMsgQ> service = ITestMsgQ::getService();
             CHECK(nullptr != service);
+            CHECK(service->isRemote() == true);
             return service;
         } else {
             return nullptr;
@@ -171,7 +229,9 @@ class ClientUnsyncTestBase<AidlMessageQueueUnsync> : public ::testing::Test {
         const std::string instance = std::string() + ITestAidlMsgQ::descriptor + "/default";
         ndk::SpAIBinder binder(AServiceManager_getService(instance.c_str()));
         CHECK(nullptr != binder);
-        return ITestAidlMsgQ::fromBinder(binder);
+        auto ret = ITestAidlMsgQ::fromBinder(binder);
+        CHECK(ret->isRemote() == true);
+        return ret;
     }
     bool getFmqUnsyncWrite(bool configureFmq, bool userFd, std::shared_ptr<ITestAidlMsgQ> service,
                            AidlMessageQueueUnsync** queue) {
@@ -211,6 +271,58 @@ class ClientUnsyncTestBase<AidlMessageQueueUnsync> : public ::testing::Test {
     AidlMessageQueueUnsync* mQueue = nullptr;
 };
 
+// Specialize for AIDL cpp backend
+template <>
+class ClientUnsyncTestBase<cppAidlMessageQueueUnsync> : public ::testing::Test {
+  protected:
+    static sp<cppITestAidlMsgQ> waitGetTestService() {
+        const std::string instance = std::string() + ITestAidlMsgQ::descriptor + "/default";
+        const android::String16 instanceString16(instance.c_str());
+        sp<cppITestAidlMsgQ> binder;
+        status_t err = getService(instanceString16, &binder);
+        if (err != OK) {
+            return nullptr;
+        }
+        CHECK(nullptr != binder);
+        return binder;
+    }
+    bool getFmqUnsyncWrite(bool configureFmq, bool userFd, sp<cppITestAidlMsgQ> service,
+                           cppAidlMessageQueueUnsync** queue) {
+        bool result = false;
+        android::hardware::common::fmq::MQDescriptor<int32_t, cppUnSynchronizedWrite> desc;
+        auto ret = service->getFmqUnsyncWrite(configureFmq, userFd, &desc, &result);
+        *queue = new (std::nothrow) cppAidlMessageQueueUnsync(desc, false);
+        return result && ret.isOk();
+    }
+
+    sp<cppITestAidlMsgQ> getQueue(cppAidlMessageQueueUnsync** fmq, bool setupQueue, bool userFd) {
+        sp<cppITestAidlMsgQ> service = waitGetTestService();
+        if (service == nullptr) return nullptr;
+        getFmqUnsyncWrite(setupQueue, userFd, service, fmq);
+        return service;
+    }
+
+    bool requestReadFmqUnsync(size_t dataLen, sp<cppITestAidlMsgQ> service) {
+        bool result = false;
+        auto ret = service->requestReadFmqUnsync(dataLen, &result);
+        return result && ret.isOk();
+    }
+    bool requestWriteFmqUnsync(size_t dataLen, sp<cppITestAidlMsgQ> service) {
+        bool result = false;
+        auto ret = service->requestWriteFmqUnsync(dataLen, &result);
+        return result && ret.isOk();
+    }
+    cppAidlMessageQueueUnsync* newQueue() {
+        if (mQueue->isValid())
+            return new (std::nothrow) cppAidlMessageQueueUnsync(mQueue->dupeDesc(), false);
+        else
+            return nullptr;
+    }
+
+    sp<cppITestAidlMsgQ> mService;
+    cppAidlMessageQueueUnsync* mQueue = nullptr;
+};
+
 // Specialize for HIDL
 template <>
 class ClientUnsyncTestBase<MessageQueueUnsync> : public ::testing::Test {
@@ -223,6 +335,7 @@ class ClientUnsyncTestBase<MessageQueueUnsync> : public ::testing::Test {
             waitForHwService(ITestMsgQ::descriptor, "default");
             sp<ITestMsgQ> service = ITestMsgQ::getService();
             CHECK(nullptr != service);
+            CHECK(service->isRemote() == true);
             return service;
         } else {
             return nullptr;
@@ -280,7 +393,6 @@ class SynchronizedReadWriteClient : public ClientSyncTestBase<typename T::MQType
     virtual void SetUp() {
         this->mService = this->waitGetTestService();
         if (this->mService == nullptr) GTEST_SKIP() << "HIDL is not supported";
-        ASSERT_TRUE(this->mService->isRemote());
         static constexpr size_t kSyncElementSizeBytes = sizeof(int32_t);
         android::base::unique_fd ringbufferFd;
         if (T::UserFd) {
@@ -311,7 +423,6 @@ class UnsynchronizedWriteClient : public ClientUnsyncTestBase<typename T::MQType
     virtual void SetUp() {
         this->mService = this->waitGetTestService();
         if (this->mService == nullptr) GTEST_SKIP() << "HIDL is not supported";
-        ASSERT_TRUE(this->mService->isRemote());
         this->getFmqUnsyncWrite(true, false, this->mService, &this->mQueue);
         ASSERT_NE(nullptr, this->mQueue);
         ASSERT_TRUE(this->mQueue->isValid());
@@ -354,7 +465,6 @@ TYPED_TEST(UnsynchronizedWriteClientMultiProcess, MultipleReadersAfterOverflow)
         auto service =
                 this->getQueue(&queue, true /* setupQueue */, TypeParam::UserFd /* userFd */);
         ASSERT_NE(service, nullptr);
-        ASSERT_TRUE(service->isRemote());
         ASSERT_NE(queue, nullptr);
         ASSERT_TRUE(queue->isValid());
 
@@ -397,7 +507,6 @@ TYPED_TEST(UnsynchronizedWriteClientMultiProcess, MultipleReadersAfterOverflow)
         typename TypeParam::MQType* queue = nullptr;
         auto service = this->getQueue(&queue, false /* setupQueue */, false /* userFd */);
         ASSERT_NE(service, nullptr);
-        ASSERT_TRUE(service->isRemote());
         ASSERT_NE(queue, nullptr);
         ASSERT_TRUE(queue->isValid());
 
```

