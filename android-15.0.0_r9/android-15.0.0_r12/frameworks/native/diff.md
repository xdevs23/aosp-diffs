```diff
diff --git a/libs/binder/Parcel.cpp b/libs/binder/Parcel.cpp
index 4b7af45739..923015a391 100644
--- a/libs/binder/Parcel.cpp
+++ b/libs/binder/Parcel.cpp
@@ -1211,6 +1211,10 @@ restart_write:
         //printf("Writing %ld bytes, padded to %ld\n", len, padded);
         uint8_t* const data = mData+mDataPos;
 
+        if (status_t status = validateReadData(mDataPos + padded); status != OK) {
+            return nullptr; // drops status
+        }
+
         // Need to pad at end?
         if (padded != len) {
 #if BYTE_ORDER == BIG_ENDIAN
@@ -1799,6 +1803,10 @@ status_t Parcel::writeObject(const flat_binder_object& val, bool nullMetaData)
     const bool enoughObjects = kernelFields->mObjectsSize < kernelFields->mObjectsCapacity;
     if (enoughData && enoughObjects) {
 restart_write:
+        if (status_t status = validateReadData(mDataPos + sizeof(val)); status != OK) {
+            return status;
+        }
+
         *reinterpret_cast<flat_binder_object*>(mData+mDataPos) = val;
 
         // remember if it's a file descriptor
@@ -2042,6 +2050,10 @@ status_t Parcel::writeAligned(T val) {
 
     if ((mDataPos+sizeof(val)) <= mDataCapacity) {
 restart_write:
+        if (status_t status = validateReadData(mDataPos + sizeof(val)); status != OK) {
+            return status;
+        }
+
         memcpy(mData + mDataPos, &val, sizeof(val));
         return finishWrite(sizeof(val));
     }
@@ -2678,14 +2690,14 @@ const flat_binder_object* Parcel::readObject(bool nullMetaData) const
 }
 #endif // BINDER_WITH_KERNEL_IPC
 
-void Parcel::closeFileDescriptors() {
+void Parcel::closeFileDescriptors(size_t newObjectsSize) {
     if (auto* kernelFields = maybeKernelFields()) {
 #ifdef BINDER_WITH_KERNEL_IPC
         size_t i = kernelFields->mObjectsSize;
         if (i > 0) {
             // ALOGI("Closing file descriptors for %zu objects...", i);
         }
-        while (i > 0) {
+        while (i > newObjectsSize) {
             i--;
             const flat_binder_object* flat =
                     reinterpret_cast<flat_binder_object*>(mData + kernelFields->mObjects[i]);
@@ -2696,6 +2708,7 @@ void Parcel::closeFileDescriptors() {
             }
         }
 #else  // BINDER_WITH_KERNEL_IPC
+        (void)newObjectsSize;
         LOG_ALWAYS_FATAL("Binder kernel driver disabled at build time");
 #endif // BINDER_WITH_KERNEL_IPC
     } else if (auto* rpcFields = maybeRpcFields()) {
@@ -2920,7 +2933,7 @@ void Parcel::freeDataNoInit()
         //ALOGI("Freeing data ref of %p (pid=%d)", this, getpid());
         auto* kernelFields = maybeKernelFields();
         // Close FDs before freeing, otherwise they will leak for kernel binder.
-        closeFileDescriptors();
+        closeFileDescriptors(/*newObjectsSize=*/0);
         mOwner(mData, mDataSize, kernelFields ? kernelFields->mObjects : nullptr,
                kernelFields ? kernelFields->mObjectsSize : 0);
     } else {
@@ -2948,6 +2961,14 @@ status_t Parcel::growData(size_t len)
         return BAD_VALUE;
     }
 
+    if (mDataPos > mDataSize) {
+        // b/370831157 - this case used to abort. We also don't expect mDataPos < mDataSize, but
+        // this would only waste a bit of memory, so it's okay.
+        ALOGE("growData only expected at the end of a Parcel. pos: %zu, size: %zu, capacity: %zu",
+              mDataPos, len, mDataCapacity);
+        return BAD_VALUE;
+    }
+
     if (len > SIZE_MAX - mDataSize) return NO_MEMORY; // overflow
     if (mDataSize + len > SIZE_MAX / 3) return NO_MEMORY; // overflow
     size_t newSize = ((mDataSize+len)*3)/2;
@@ -3049,13 +3070,38 @@ status_t Parcel::continueWrite(size_t desired)
             objectsSize = 0;
         } else {
             if (kernelFields) {
+#ifdef BINDER_WITH_KERNEL_IPC
+                validateReadData(mDataSize); // hack to sort the objects
                 while (objectsSize > 0) {
-                    if (kernelFields->mObjects[objectsSize - 1] < desired) break;
+                    if (kernelFields->mObjects[objectsSize - 1] + sizeof(flat_binder_object) <=
+                        desired)
+                        break;
                     objectsSize--;
                 }
+#endif // BINDER_WITH_KERNEL_IPC
             } else {
                 while (objectsSize > 0) {
-                    if (rpcFields->mObjectPositions[objectsSize - 1] < desired) break;
+                    // Object size varies by type.
+                    uint32_t pos = rpcFields->mObjectPositions[objectsSize - 1];
+                    size_t size = sizeof(RpcFields::ObjectType);
+                    uint32_t minObjectEnd;
+                    if (__builtin_add_overflow(pos, sizeof(RpcFields::ObjectType), &minObjectEnd) ||
+                        minObjectEnd > mDataSize) {
+                        return BAD_VALUE;
+                    }
+                    const auto type = *reinterpret_cast<const RpcFields::ObjectType*>(mData + pos);
+                    switch (type) {
+                        case RpcFields::TYPE_BINDER_NULL:
+                            break;
+                        case RpcFields::TYPE_BINDER:
+                            size += sizeof(uint64_t); // address
+                            break;
+                        case RpcFields::TYPE_NATIVE_FILE_DESCRIPTOR:
+                            size += sizeof(int32_t); // fd index
+                            break;
+                    }
+
+                    if (pos + size <= desired) break;
                     objectsSize--;
                 }
             }
@@ -3104,15 +3150,24 @@ status_t Parcel::continueWrite(size_t desired)
         if (mData) {
             memcpy(data, mData, mDataSize < desired ? mDataSize : desired);
         }
+#ifdef BINDER_WITH_KERNEL_IPC
         if (objects && kernelFields && kernelFields->mObjects) {
             memcpy(objects, kernelFields->mObjects, objectsSize * sizeof(binder_size_t));
+            // All FDs are owned when `mOwner`, even when `cookie == 0`. When
+            // we switch to `!mOwner`, we need to explicitly mark the FDs as
+            // owned.
+            for (size_t i = 0; i < objectsSize; i++) {
+                flat_binder_object* flat = reinterpret_cast<flat_binder_object*>(data + objects[i]);
+                if (flat->hdr.type == BINDER_TYPE_FD) {
+                    flat->cookie = 1;
+                }
+            }
         }
         // ALOGI("Freeing data ref of %p (pid=%d)", this, getpid());
         if (kernelFields) {
-            // TODO(b/239222407): This seems wrong. We should only free FDs when
-            // they are in a truncated section of the parcel.
-            closeFileDescriptors();
+            closeFileDescriptors(objectsSize);
         }
+#endif // BINDER_WITH_KERNEL_IPC
         mOwner(mData, mDataSize, kernelFields ? kernelFields->mObjects : nullptr,
                kernelFields ? kernelFields->mObjectsSize : 0);
         mOwner = nullptr;
@@ -3239,11 +3294,19 @@ status_t Parcel::truncateRpcObjects(size_t newObjectsSize) {
     }
     while (rpcFields->mObjectPositions.size() > newObjectsSize) {
         uint32_t pos = rpcFields->mObjectPositions.back();
-        rpcFields->mObjectPositions.pop_back();
+        uint32_t minObjectEnd;
+        if (__builtin_add_overflow(pos, sizeof(RpcFields::ObjectType), &minObjectEnd) ||
+            minObjectEnd > mDataSize) {
+            return BAD_VALUE;
+        }
         const auto type = *reinterpret_cast<const RpcFields::ObjectType*>(mData + pos);
         if (type == RpcFields::TYPE_NATIVE_FILE_DESCRIPTOR) {
-            const auto fdIndex =
-                    *reinterpret_cast<const int32_t*>(mData + pos + sizeof(RpcFields::ObjectType));
+            uint32_t objectEnd;
+            if (__builtin_add_overflow(minObjectEnd, sizeof(int32_t), &objectEnd) ||
+                objectEnd > mDataSize) {
+                return BAD_VALUE;
+            }
+            const auto fdIndex = *reinterpret_cast<const int32_t*>(mData + minObjectEnd);
             if (rpcFields->mFds == nullptr || fdIndex < 0 ||
                 static_cast<size_t>(fdIndex) >= rpcFields->mFds->size()) {
                 ALOGE("RPC Parcel contains invalid file descriptor index. index=%d fd_count=%zu",
@@ -3253,6 +3316,7 @@ status_t Parcel::truncateRpcObjects(size_t newObjectsSize) {
             // In practice, this always removes the last element.
             rpcFields->mFds->erase(rpcFields->mFds->begin() + fdIndex);
         }
+        rpcFields->mObjectPositions.pop_back();
     }
     return OK;
 }
diff --git a/libs/binder/include/binder/Parcel.h b/libs/binder/include/binder/Parcel.h
index 5cc0830c88..68c620c369 100644
--- a/libs/binder/include/binder/Parcel.h
+++ b/libs/binder/include/binder/Parcel.h
@@ -637,9 +637,6 @@ public:
 
     LIBBINDER_EXPORTED const flat_binder_object* readObject(bool nullMetaData) const;
 
-    // Explicitly close all file descriptors in the parcel.
-    LIBBINDER_EXPORTED void closeFileDescriptors();
-
     // Debugging: get metrics on current allocations.
     LIBBINDER_EXPORTED static size_t getGlobalAllocSize();
     LIBBINDER_EXPORTED static size_t getGlobalAllocCount();
@@ -652,6 +649,9 @@ public:
     LIBBINDER_EXPORTED void print(std::ostream& to, uint32_t flags = 0) const;
 
 private:
+    // Close all file descriptors in the parcel at object positions >= newObjectsSize.
+    void closeFileDescriptors(size_t newObjectsSize);
+
     // `objects` and `objectsSize` always 0 for RPC Parcels.
     typedef void (*release_func)(const uint8_t* data, size_t dataSize, const binder_size_t* objects,
                                  size_t objectsSize);
diff --git a/libs/binder/tests/binderLibTest.cpp b/libs/binder/tests/binderLibTest.cpp
index bcab6decca..e152763be1 100644
--- a/libs/binder/tests/binderLibTest.cpp
+++ b/libs/binder/tests/binderLibTest.cpp
@@ -46,6 +46,7 @@
 
 #include <linux/sched.h>
 #include <sys/epoll.h>
+#include <sys/mman.h>
 #include <sys/prctl.h>
 #include <sys/socket.h>
 #include <sys/un.h>
@@ -110,6 +111,8 @@ enum BinderLibTestTranscationCode {
     BINDER_LIB_TEST_LINK_DEATH_TRANSACTION,
     BINDER_LIB_TEST_WRITE_FILE_TRANSACTION,
     BINDER_LIB_TEST_WRITE_PARCEL_FILE_DESCRIPTOR_TRANSACTION,
+    BINDER_LIB_TEST_GET_FILE_DESCRIPTORS_OWNED_TRANSACTION,
+    BINDER_LIB_TEST_GET_FILE_DESCRIPTORS_UNOWNED_TRANSACTION,
     BINDER_LIB_TEST_EXIT_TRANSACTION,
     BINDER_LIB_TEST_DELAYED_EXIT_TRANSACTION,
     BINDER_LIB_TEST_GET_PTR_SIZE_TRANSACTION,
@@ -536,6 +539,30 @@ class TestDeathRecipient : public IBinder::DeathRecipient, public BinderLibTestE
         };
 };
 
+ssize_t countFds() {
+    return std::distance(std::filesystem::directory_iterator("/proc/self/fd"),
+                         std::filesystem::directory_iterator{});
+}
+
+struct FdLeakDetector {
+    int startCount;
+
+    FdLeakDetector() {
+        // This log statement is load bearing. We have to log something before
+        // counting FDs to make sure the logging system is initialized, otherwise
+        // the sockets it opens will look like a leak.
+        ALOGW("FdLeakDetector counting FDs.");
+        startCount = countFds();
+    }
+    ~FdLeakDetector() {
+        int endCount = countFds();
+        if (startCount != endCount) {
+            ADD_FAILURE() << "fd count changed (" << startCount << " -> " << endCount
+                          << ") fd leak?";
+        }
+    }
+};
+
 TEST_F(BinderLibTest, CannotUseBinderAfterFork) {
     // EXPECT_DEATH works by forking the process
     EXPECT_DEATH({ ProcessState::self(); }, "libbinder ProcessState can not be used after fork");
@@ -1175,6 +1202,100 @@ TEST_F(BinderLibTest, PassParcelFileDescriptor) {
     EXPECT_EQ(0, read(read_end.get(), readbuf.data(), datasize));
 }
 
+TEST_F(BinderLibTest, RecvOwnedFileDescriptors) {
+    FdLeakDetector fd_leak_detector;
+
+    Parcel data;
+    Parcel reply;
+    EXPECT_EQ(NO_ERROR,
+              m_server->transact(BINDER_LIB_TEST_GET_FILE_DESCRIPTORS_OWNED_TRANSACTION, data,
+                                 &reply));
+    unique_fd a, b;
+    EXPECT_EQ(OK, reply.readUniqueFileDescriptor(&a));
+    EXPECT_EQ(OK, reply.readUniqueFileDescriptor(&b));
+}
+
+// Used to trigger fdsan error (b/239222407).
+TEST_F(BinderLibTest, RecvOwnedFileDescriptorsAndWriteInt) {
+    GTEST_SKIP() << "triggers fdsan false positive: b/370824489";
+
+    FdLeakDetector fd_leak_detector;
+
+    Parcel data;
+    Parcel reply;
+    EXPECT_EQ(NO_ERROR,
+              m_server->transact(BINDER_LIB_TEST_GET_FILE_DESCRIPTORS_OWNED_TRANSACTION, data,
+                                 &reply));
+    reply.setDataPosition(reply.dataSize());
+    reply.writeInt32(0);
+    reply.setDataPosition(0);
+    unique_fd a, b;
+    EXPECT_EQ(OK, reply.readUniqueFileDescriptor(&a));
+    EXPECT_EQ(OK, reply.readUniqueFileDescriptor(&b));
+}
+
+// Used to trigger fdsan error (b/239222407).
+TEST_F(BinderLibTest, RecvOwnedFileDescriptorsAndTruncate) {
+    GTEST_SKIP() << "triggers fdsan false positive: b/370824489";
+
+    FdLeakDetector fd_leak_detector;
+
+    Parcel data;
+    Parcel reply;
+    EXPECT_EQ(NO_ERROR,
+              m_server->transact(BINDER_LIB_TEST_GET_FILE_DESCRIPTORS_OWNED_TRANSACTION, data,
+                                 &reply));
+    reply.setDataSize(reply.dataSize() - sizeof(flat_binder_object));
+    unique_fd a, b;
+    EXPECT_EQ(OK, reply.readUniqueFileDescriptor(&a));
+    EXPECT_EQ(BAD_TYPE, reply.readUniqueFileDescriptor(&b));
+}
+
+TEST_F(BinderLibTest, RecvUnownedFileDescriptors) {
+    FdLeakDetector fd_leak_detector;
+
+    Parcel data;
+    Parcel reply;
+    EXPECT_EQ(NO_ERROR,
+              m_server->transact(BINDER_LIB_TEST_GET_FILE_DESCRIPTORS_UNOWNED_TRANSACTION, data,
+                                 &reply));
+    unique_fd a, b;
+    EXPECT_EQ(OK, reply.readUniqueFileDescriptor(&a));
+    EXPECT_EQ(OK, reply.readUniqueFileDescriptor(&b));
+}
+
+// Used to trigger fdsan error (b/239222407).
+TEST_F(BinderLibTest, RecvUnownedFileDescriptorsAndWriteInt) {
+    FdLeakDetector fd_leak_detector;
+
+    Parcel data;
+    Parcel reply;
+    EXPECT_EQ(NO_ERROR,
+              m_server->transact(BINDER_LIB_TEST_GET_FILE_DESCRIPTORS_UNOWNED_TRANSACTION, data,
+                                 &reply));
+    reply.setDataPosition(reply.dataSize());
+    reply.writeInt32(0);
+    reply.setDataPosition(0);
+    unique_fd a, b;
+    EXPECT_EQ(OK, reply.readUniqueFileDescriptor(&a));
+    EXPECT_EQ(OK, reply.readUniqueFileDescriptor(&b));
+}
+
+// Used to trigger fdsan error (b/239222407).
+TEST_F(BinderLibTest, RecvUnownedFileDescriptorsAndTruncate) {
+    FdLeakDetector fd_leak_detector;
+
+    Parcel data;
+    Parcel reply;
+    EXPECT_EQ(NO_ERROR,
+              m_server->transact(BINDER_LIB_TEST_GET_FILE_DESCRIPTORS_UNOWNED_TRANSACTION, data,
+                                 &reply));
+    reply.setDataSize(reply.dataSize() - sizeof(flat_binder_object));
+    unique_fd a, b;
+    EXPECT_EQ(OK, reply.readUniqueFileDescriptor(&a));
+    EXPECT_EQ(BAD_TYPE, reply.readUniqueFileDescriptor(&b));
+}
+
 TEST_F(BinderLibTest, PromoteLocal) {
     sp<IBinder> strong = new BBinder();
     wp<IBinder> weak = strong;
@@ -2224,6 +2345,40 @@ public:
                 if (ret != size) return UNKNOWN_ERROR;
                 return NO_ERROR;
             }
+            case BINDER_LIB_TEST_GET_FILE_DESCRIPTORS_OWNED_TRANSACTION: {
+                unique_fd fd1(memfd_create("memfd1", MFD_CLOEXEC));
+                if (!fd1.ok()) {
+                    PLOGE("memfd_create failed");
+                    return UNKNOWN_ERROR;
+                }
+                unique_fd fd2(memfd_create("memfd2", MFD_CLOEXEC));
+                if (!fd2.ok()) {
+                    PLOGE("memfd_create failed");
+                    return UNKNOWN_ERROR;
+                }
+                status_t ret;
+                ret = reply->writeFileDescriptor(fd1.release(), true);
+                if (ret != NO_ERROR) {
+                    return ret;
+                }
+                ret = reply->writeFileDescriptor(fd2.release(), true);
+                if (ret != NO_ERROR) {
+                    return ret;
+                }
+                return NO_ERROR;
+            }
+            case BINDER_LIB_TEST_GET_FILE_DESCRIPTORS_UNOWNED_TRANSACTION: {
+                status_t ret;
+                ret = reply->writeFileDescriptor(STDOUT_FILENO, false);
+                if (ret != NO_ERROR) {
+                    return ret;
+                }
+                ret = reply->writeFileDescriptor(STDERR_FILENO, false);
+                if (ret != NO_ERROR) {
+                    return ret;
+                }
+                return NO_ERROR;
+            }
             case BINDER_LIB_TEST_DELAYED_EXIT_TRANSACTION:
                 alarm(10);
                 return NO_ERROR;
```

