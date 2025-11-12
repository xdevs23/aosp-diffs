```diff
diff --git a/src/gfxstream/aemu/Android.bp b/src/gfxstream/aemu/Android.bp
index 92a32d7a169..62ae9302d93 100644
--- a/src/gfxstream/aemu/Android.bp
+++ b/src/gfxstream/aemu/Android.bp
@@ -33,10 +33,15 @@ cc_library_static {
     vendor: true,
     host_supported: true,
     header_libs: [
+        "mesa_common_headers",
         "mesa_gfxstream_aemu_headers",
     ],
+    shared_libs: [
+        "liblog",
+    ],
     srcs: [
         "ring_buffer.cpp",
         "Stream.cpp",
+        "SubAllocator.cpp",
     ],
 }
diff --git a/src/gfxstream/aemu/SubAllocator.cpp b/src/gfxstream/aemu/SubAllocator.cpp
new file mode 100644
index 00000000000..bb613b25f77
--- /dev/null
+++ b/src/gfxstream/aemu/SubAllocator.cpp
@@ -0,0 +1,175 @@
+/*
+ * Copyright 2019 Google
+ * SPDX-License-Identifier: MIT
+ */
+
+#include "Stream.h"
+#include "SubAllocator.h"
+#include "address_space.h"
+#include "util/log.h"
+
+namespace gfxstream {
+namespace aemu {
+
+class SubAllocator::Impl {
+  public:
+   Impl(void* _buffer, uint64_t _totalSize, uint64_t _pageSize)
+       : buffer(_buffer),
+         totalSize(_totalSize),
+         pageSize(_pageSize),
+         startAddr((uintptr_t)buffer),
+         endAddr(startAddr + totalSize) {
+      address_space_allocator_init(&addr_alloc, totalSize, 32);
+   }
+
+   ~Impl() { address_space_allocator_destroy_nocleanup(&addr_alloc); }
+
+   void clear() {
+      address_space_allocator_destroy_nocleanup(&addr_alloc);
+      address_space_allocator_init(&addr_alloc, totalSize, 32);
+   }
+
+   bool save(Stream* stream) {
+      address_space_allocator_iter_func_t allocatorSaver =
+          [](void* context, struct address_space_allocator* allocator) {
+             Stream* stream = reinterpret_cast<Stream*>(context);
+             stream->putBe32(allocator->size);
+             stream->putBe32(allocator->capacity);
+             stream->putBe64(allocator->total_bytes);
+          };
+      address_block_iter_func_t allocatorBlockSaver =
+          [](void* context, struct address_block* block) {
+             Stream* stream = reinterpret_cast<Stream*>(context);
+             stream->putBe64(block->offset);
+             stream->putBe64(block->size_available);
+          };
+      address_space_allocator_run(&addr_alloc, (void*)stream, allocatorSaver,
+                                  allocatorBlockSaver);
+
+      stream->putBe64(pageSize);
+      stream->putBe64(totalSize);
+      stream->putBe32(allocCount);
+
+      return true;
+   }
+
+   bool load(Stream* stream) {
+      clear();
+      address_space_allocator_iter_func_t allocatorLoader =
+          [](void* context, struct address_space_allocator* allocator) {
+             Stream* stream = reinterpret_cast<Stream*>(context);
+             allocator->size = stream->getBe32();
+             allocator->capacity = stream->getBe32();
+             allocator->total_bytes = stream->getBe64();
+          };
+      address_block_iter_func_t allocatorBlockLoader =
+          [](void* context, struct address_block* block) {
+             Stream* stream = reinterpret_cast<Stream*>(context);
+             block->offset = stream->getBe64();
+             block->size_available = stream->getBe64();
+          };
+      address_space_allocator_run(&addr_alloc, (void*)stream, allocatorLoader,
+                                  allocatorBlockLoader);
+
+      pageSize = stream->getBe64();
+      totalSize = stream->getBe64();
+      allocCount = stream->getBe32();
+
+      return true;
+   }
+
+   bool postLoad(void* postLoadBuffer) {
+      buffer = postLoadBuffer;
+      startAddr = (uint64_t)(uintptr_t)postLoadBuffer;
+      return true;
+   }
+
+   void rangeCheck(const char* task, void* ptr) {
+      uint64_t addr = (uintptr_t)ptr;
+      if (addr < startAddr || addr > endAddr) {
+         mesa_loge(
+            "FATAL in SubAllocator: Task:%s ptr '0x%llx' is out of range! "
+            "Range:[0x%llx - 0x%llx]", task, addr, startAddr, endAddr);
+      }
+   }
+
+   uint64_t getOffset(void* checkedPtr) {
+      uint64_t addr = (uintptr_t)checkedPtr;
+      return addr - startAddr;
+   }
+
+   bool free(void* ptr) {
+      if (!ptr) return false;
+
+      rangeCheck("free", ptr);
+      if (EINVAL ==
+          address_space_allocator_deallocate(&addr_alloc, getOffset(ptr))) {
+         return false;
+      }
+
+      --allocCount;
+      return true;
+   }
+
+   void freeAll() {
+      address_space_allocator_reset(&addr_alloc);
+      allocCount = 0;
+   }
+
+   void* alloc(size_t wantedSize) {
+      if (wantedSize == 0) return nullptr;
+
+      uint64_t wantedSize64 = (uint64_t)wantedSize;
+
+      size_t toPageSize = pageSize * ((wantedSize + pageSize - 1) / pageSize);
+
+      uint64_t offset =
+          address_space_allocator_allocate(&addr_alloc, toPageSize);
+
+      if (offset == ANDROID_EMU_ADDRESS_SPACE_BAD_OFFSET) {
+         return nullptr;
+      }
+
+      ++allocCount;
+      return (void*)(uintptr_t)(startAddr + offset);
+   }
+
+   bool empty() const { return allocCount == 0; }
+
+   void* buffer;
+   uint64_t totalSize;
+   uint64_t pageSize;
+   uint64_t startAddr;
+   uint64_t endAddr;
+   struct address_space_allocator addr_alloc;
+   uint32_t allocCount = 0;
+};
+
+SubAllocator::SubAllocator(void* buffer, uint64_t totalSize, uint64_t pageSize)
+    : mImpl(new SubAllocator::Impl(buffer, totalSize, pageSize)) {}
+
+SubAllocator::~SubAllocator() { delete mImpl; }
+
+// Snapshotting
+bool SubAllocator::save(Stream* stream) { return mImpl->save(stream); }
+
+bool SubAllocator::load(Stream* stream) { return mImpl->load(stream); }
+
+bool SubAllocator::postLoad(void* postLoadBuffer) {
+   return mImpl->postLoad(postLoadBuffer);
+}
+
+void* SubAllocator::alloc(size_t wantedSize) {
+   return mImpl->alloc(wantedSize);
+}
+
+bool SubAllocator::free(void* ptr) { return mImpl->free(ptr); }
+
+void SubAllocator::freeAll() { mImpl->freeAll(); }
+
+uint64_t SubAllocator::getOffset(void* ptr) { return mImpl->getOffset(ptr); }
+
+bool SubAllocator::empty() const { return mImpl->empty(); }
+
+}  // namespace aemu
+}  // namespace gfxstream
diff --git a/src/gfxstream/aemu/include/SubAllocator.h b/src/gfxstream/aemu/include/SubAllocator.h
new file mode 100644
index 00000000000..c376664990b
--- /dev/null
+++ b/src/gfxstream/aemu/include/SubAllocator.h
@@ -0,0 +1,82 @@
+/*
+ * Copyright 2021 Google
+ * SPDX-License-Identifier: MIT
+ */
+#pragma once
+
+#include <inttypes.h>
+#include <stddef.h>
+#include <string.h>
+
+namespace gfxstream {
+namespace aemu {
+
+class Stream;
+
+// Class to create sub-allocations in an existing buffer. Similar interface to
+// Pool, but underlying mechanism is different as it's difficult to combine
+// same-size heaps in Pool with a preallocated buffer.
+class SubAllocator {
+  public:
+   // |pageSize| determines both the alignment of pointers returned
+   // and the multiples of space occupied.
+   SubAllocator(void* buffer, uint64_t totalSize, uint64_t pageSize);
+
+   // Memory is freed from the perspective of the user of
+   // SubAllocator, but the prealloced buffer is not freed.
+   ~SubAllocator();
+
+   // Snapshotting
+   bool save(Stream* stream);
+   bool load(Stream* stream);
+   bool postLoad(void* postLoadBuffer);
+
+   // returns null if the allocation cannot be satisfied.
+   void* alloc(size_t wantedSize);
+   // returns true if |ptr| came from alloc(), false otherwise
+   bool free(void* ptr);
+   void freeAll();
+   uint64_t getOffset(void* ptr);
+
+   bool empty() const;
+
+   // Convenience function to allocate an array
+   // of objects of type T.
+   template <class T>
+   T* allocArray(size_t count) {
+      size_t bytes = sizeof(T) * count;
+      void* res = alloc(bytes);
+      return (T*)res;
+   }
+
+   char* strDup(const char* toCopy) {
+      size_t bytes = strlen(toCopy) + 1;
+      void* res = alloc(bytes);
+      memset(res, 0x0, bytes);
+      memcpy(res, toCopy, bytes);
+      return (char*)res;
+   }
+
+   char** strDupArray(const char* const* arrayToCopy, size_t count) {
+      char** res = allocArray<char*>(count);
+
+      for (size_t i = 0; i < count; i++) {
+         res[i] = strDup(arrayToCopy[i]);
+      }
+
+      return res;
+   }
+
+   void* dupArray(const void* buf, size_t bytes) {
+      void* res = alloc(bytes);
+      memcpy(res, buf, bytes);
+      return res;
+   }
+
+  private:
+   class Impl;
+   Impl* mImpl = nullptr;
+};
+
+}  // namespace aemu
+}  // namespace gfxstream
\ No newline at end of file
diff --git a/src/gfxstream/aemu/include/address_space.h b/src/gfxstream/aemu/include/address_space.h
new file mode 100644
index 00000000000..1bdfd914443
--- /dev/null
+++ b/src/gfxstream/aemu/include/address_space.h
@@ -0,0 +1,355 @@
+/*
+ * Copyright 2021 Google
+ * SPDX-License-Identifier: MIT
+ */
+#pragma once
+
+#include <assert.h>
+#include <errno.h>
+#include <inttypes.h>
+#include <stdio.h>
+#include <stdlib.h>
+#include <string.h>
+
+namespace gfxstream {
+namespace aemu {
+
+// This is ported from goldfish_address_space, allowing it to be used for
+// general sub-allocations of any buffer range.
+// It is also a pure header library, so there are no compiler tricks needed
+// to use this in a particular implementation. please don't include this
+// in a file that is included everywhere else, though.
+
+/* Represents a continuous range of addresses and a flag if this block is
+ * available
+ */
+struct address_block {
+   uint64_t offset;
+   union {
+      uint64_t size_available; /* VMSTATE_x does not support bit fields */
+      struct {
+         uint64_t size : 63;
+         uint64_t available : 1;
+      };
+   };
+};
+
+/* A dynamic array of address blocks, with the following invariant:
+ * blocks[i].size > 0
+ * blocks[i+1].offset = blocks[i].offset + blocks[i].size
+ */
+struct address_space_allocator {
+   struct address_block *blocks;
+   int size;
+   int capacity;
+   uint64_t total_bytes;
+};
+
+#define ANDROID_EMU_ADDRESS_SPACE_BAD_OFFSET (~(uint64_t)0)
+
+/* The assert function to abort if something goes wrong. */
+static void address_space_assert(bool condition) {
+#ifdef ANDROID_EMU_ADDRESS_SPACE_ASSERT_FUNC
+   ANDROID_EMU_ADDRESS_SPACE_ASSERT_FUNC(condition);
+#else
+   (void)condition;
+   assert(condition);
+#endif
+}
+
+static void *address_space_malloc0(size_t size) {
+#ifdef ANDROID_EMU_ADDRESS_SPACE_MALLOC0_FUNC
+   return ANDROID_EMU_ADDRESS_SPACE_MALLOC0_FUNC(size);
+#else
+   void *res = malloc(size);
+   memset(res, 0, size);
+   return res;
+#endif
+}
+
+static void *address_space_realloc(void *ptr, size_t size) {
+#ifdef ANDROID_EMU_ADDRESS_SPACE_REALLOC_FUNC
+   return ANDROID_EMU_ADDRESS_SPACE_REALLOC_FUNC(ptr, size);
+#else
+   void *res = realloc(ptr, size);
+   return res;
+#endif
+}
+
+static void address_space_free(void *ptr) {
+#ifdef ANDROID_EMU_ADDRESS_SPACE_FREE_FUNC
+   return ANDROID_EMU_ADDRESS_SPACE_FREE_FUNC(ptr);
+#else
+   free(ptr);
+#endif
+}
+
+/* Looks for the smallest (to reduce fragmentation) available block with size to
+ * fit the requested amount and returns its index or -1 if none is available.
+ */
+static int address_space_allocator_find_available_block(
+    struct address_block *block, int n_blocks, uint64_t size_at_least) {
+   int index = -1;
+   uint64_t size_at_index = 0;
+   int i;
+
+   address_space_assert(n_blocks >= 1);
+
+   for (i = 0; i < n_blocks; ++i, ++block) {
+      uint64_t this_size = block->size;
+      address_space_assert(this_size > 0);
+
+      if (this_size >= size_at_least && block->available &&
+          (index < 0 || this_size < size_at_index)) {
+         index = i;
+         size_at_index = this_size;
+      }
+   }
+
+   return index;
+}
+
+static int address_space_allocator_grow_capacity(int old_capacity) {
+   address_space_assert(old_capacity >= 1);
+
+   return old_capacity + old_capacity;
+}
+
+/* Inserts one more address block right after i'th (by borrowing i'th size) and
+ * adjusts sizes:
+ * pre:
+ *   size > blocks[i].size
+ *
+ * post:
+ *   * might reallocate allocator->blocks if there is no capacity to insert one
+ *   * blocks[i].size -= size;
+ *   * blocks[i+1].size = size;
+ */
+static struct address_block *address_space_allocator_split_block(
+    struct address_space_allocator *allocator, int i, uint64_t size) {
+   address_space_assert(allocator->capacity >= 1);
+   address_space_assert(allocator->size >= 1);
+   address_space_assert(allocator->size <= allocator->capacity);
+   address_space_assert(i >= 0);
+   address_space_assert(i < allocator->size);
+   address_space_assert(size < allocator->blocks[i].size);
+
+   if (allocator->size == allocator->capacity) {
+      int new_capacity =
+          address_space_allocator_grow_capacity(allocator->capacity);
+      allocator->blocks = (struct address_block *)address_space_realloc(
+          allocator->blocks, sizeof(struct address_block) * new_capacity);
+      address_space_assert(allocator->blocks);
+      allocator->capacity = new_capacity;
+   }
+
+   struct address_block *blocks = allocator->blocks;
+
+   /*   size = 5, i = 1
+    *   [ 0 | 1 |  2  |  3  | 4 ]  =>  [ 0 | 1 | new |  2  | 3 | 4 ]
+    *         i  (i+1) (i+2)                 i  (i+1) (i+2)
+    */
+   memmove(&blocks[i + 2], &blocks[i + 1],
+           sizeof(struct address_block) * (allocator->size - i - 1));
+
+   struct address_block *to_borrow_from = &blocks[i];
+   struct address_block *new_block = to_borrow_from + 1;
+
+   uint64_t new_size = to_borrow_from->size - size;
+
+   to_borrow_from->size = new_size;
+
+   new_block->offset = to_borrow_from->offset + new_size;
+   new_block->size = size;
+   new_block->available = 1;
+
+   ++allocator->size;
+
+   return new_block;
+}
+
+/* Marks i'th block as available. If adjacent ((i-1) and (i+1)) blocks are also
+ * available, it merges i'th block with them.
+ * pre:
+ *   i < allocator->size
+ * post:
+ *   i'th block is merged with adjacent ones if they are available, blocks that
+ *   were merged from are removed. allocator->size is updated if blocks were
+ *   removed.
+ */
+static void address_space_allocator_release_block(
+    struct address_space_allocator *allocator, int i) {
+   struct address_block *blocks = allocator->blocks;
+   int before = i - 1;
+   int after = i + 1;
+   int size = allocator->size;
+
+   address_space_assert(i >= 0);
+   address_space_assert(i < size);
+
+   blocks[i].available = 1;
+
+   if (before >= 0 && blocks[before].available) {
+      if (after < size && blocks[after].available) {
+         // merge (before, i, after) into before
+         blocks[before].size += (blocks[i].size + blocks[after].size);
+
+         size -= 2;
+         memmove(&blocks[i], &blocks[i + 2],
+                 sizeof(struct address_block) * (size - i));
+         allocator->size = size;
+      } else {
+         // merge (before, i) into before
+         blocks[before].size += blocks[i].size;
+
+         --size;
+         memmove(&blocks[i], &blocks[i + 1],
+                 sizeof(struct address_block) * (size - i));
+         allocator->size = size;
+      }
+   } else if (after < size && blocks[after].available) {
+      // merge (i, after) into i
+      blocks[i].size += blocks[after].size;
+
+      --size;
+      memmove(&blocks[after], &blocks[after + 1],
+              sizeof(struct address_block) * (size - after));
+      allocator->size = size;
+   }
+}
+
+/* Takes a size to allocate an address block and returns an offset where this
+ * block is allocated. This block will not be available for other callers unless
+ * it is explicitly deallocated (see address_space_allocator_deallocate below).
+ */
+static uint64_t address_space_allocator_allocate(
+    struct address_space_allocator *allocator, uint64_t size) {
+   int i = address_space_allocator_find_available_block(allocator->blocks,
+                                                        allocator->size, size);
+   if (i < 0) {
+      return ANDROID_EMU_ADDRESS_SPACE_BAD_OFFSET;
+   } else {
+      address_space_assert(i < allocator->size);
+
+      struct address_block *block = &allocator->blocks[i];
+      address_space_assert(block->size >= size);
+
+      if (block->size > size) {
+         block = address_space_allocator_split_block(allocator, i, size);
+      }
+
+      address_space_assert(block->size == size);
+      block->available = 0;
+
+      return block->offset;
+   }
+}
+
+/* Takes an offset returned from address_space_allocator_allocate ealier
+ * (see above) and marks this block as available for further allocation.
+ */
+static uint32_t address_space_allocator_deallocate(
+    struct address_space_allocator *allocator, uint64_t offset) {
+   struct address_block *block = allocator->blocks;
+   int size = allocator->size;
+   int i;
+
+   address_space_assert(size >= 1);
+
+   for (i = 0; i < size; ++i, ++block) {
+      if (block->offset == offset) {
+         if (block->available) {
+            return EINVAL;
+         } else {
+            address_space_allocator_release_block(allocator, i);
+            return 0;
+         }
+      }
+   }
+
+   return EINVAL;
+}
+
+/* Creates a seed block. */
+static void address_space_allocator_init(
+    struct address_space_allocator *allocator, uint64_t size,
+    int initial_capacity) {
+   address_space_assert(initial_capacity >= 1);
+
+   allocator->blocks = (struct address_block *)malloc(
+       sizeof(struct address_block) * initial_capacity);
+   memset(allocator->blocks, 0,
+          sizeof(struct address_block) * initial_capacity);
+   address_space_assert(allocator->blocks);
+
+   struct address_block *block = allocator->blocks;
+
+   block->offset = 0;
+   block->size = size;
+   block->available = 1;
+
+   allocator->size = 1;
+   allocator->capacity = initial_capacity;
+   allocator->total_bytes = size;
+}
+
+/* At this point there should be no used blocks and all available blocks must
+ * have been merged into one block.
+ */
+static void address_space_allocator_destroy(
+    struct address_space_allocator *allocator) {
+   address_space_assert(allocator->size == 1);
+   address_space_assert(allocator->capacity >= allocator->size);
+   address_space_assert(allocator->blocks[0].available);
+   address_space_free(allocator->blocks);
+}
+
+/* Destroy function if we don't care what was previoulsy allocated.
+ * have been merged into one block.
+ */
+static void address_space_allocator_destroy_nocleanup(
+    struct address_space_allocator *allocator) {
+   address_space_free(allocator->blocks);
+}
+
+/* Resets the state of the allocator to the initial state without
+ * performing any dynamic memory management. */
+static void address_space_allocator_reset(
+    struct address_space_allocator *allocator) {
+   address_space_assert(allocator->size >= 1);
+
+   allocator->size = 1;
+
+   struct address_block *block = allocator->blocks;
+   block->offset = 0;
+   block->size = allocator->total_bytes;
+   block->available = 1;
+}
+
+typedef void (*address_block_iter_func_t)(void *context,
+                                          struct address_block *);
+typedef void (*address_space_allocator_iter_func_t)(
+    void *context, struct address_space_allocator *);
+
+static void address_space_allocator_run(
+    struct address_space_allocator *allocator, void *context,
+    address_space_allocator_iter_func_t allocator_func,
+    address_block_iter_func_t block_func) {
+   struct address_block *block = 0;
+   int size;
+   int i;
+
+   allocator_func(context, allocator);
+
+   block = allocator->blocks;
+   size = allocator->size;
+
+   address_space_assert(size >= 1);
+
+   for (i = 0; i < size; ++i, ++block) {
+      block_func(context, block);
+   }
+}
+
+}  // namespace aemu
+}  // namespace gfxstream
\ No newline at end of file
diff --git a/src/gfxstream/aemu/meson.build b/src/gfxstream/aemu/meson.build
index 36727a085be..a47e40c19dc 100644
--- a/src/gfxstream/aemu/meson.build
+++ b/src/gfxstream/aemu/meson.build
@@ -6,6 +6,7 @@ inc_aemu = include_directories('include')
 files_libaemu = files(
   'ring_buffer.cpp',
   'Stream.cpp',
+  'SubAllocator.cpp',
 )
 
 libaemu = static_library(
diff --git a/src/gfxstream/codegen/generate-gfxstream-vulkan.sh b/src/gfxstream/codegen/generate-gfxstream-vulkan.sh
index 4e9193212f9..e3ec568e2b3 100755
--- a/src/gfxstream/codegen/generate-gfxstream-vulkan.sh
+++ b/src/gfxstream/codegen/generate-gfxstream-vulkan.sh
@@ -21,7 +21,7 @@ export PREFIX_DIR="src/gfxstream"
 
 # We should use just use one vk.xml eventually..
 export VK_MESA_XML="$MESA_DIR/src/vulkan/registry/vk.xml"
-export VK_XML="$GFXSTREAM_DIR/codegen/vulkan/vulkan-docs-next/xml/vk.xml"
+export VK_XML="$GFXSTREAM_DIR/third_party/vulkan_docs/xml/vk.xml"
 
 export GFXSTREAM_GUEST_ENCODER_DIR="/tmp/"
 export GFXSTREAM_HOST_DECODER_DIR="$GFXSTREAM_DIR/host/vulkan"
diff --git a/src/gfxstream/codegen/scripts/cereal/common/codegen.py b/src/gfxstream/codegen/scripts/cereal/common/codegen.py
index 3ffc30c42c9..83e0f5c405d 100644
--- a/src/gfxstream/codegen/scripts/cereal/common/codegen.py
+++ b/src/gfxstream/codegen/scripts/cereal/common/codegen.py
@@ -821,7 +821,7 @@ class CodeGen(object):
         if variant == "guest":
             streamNamespace = "gfxstream::aemu"
         else:
-            streamNamespace = "android::base"
+            streamNamespace = "gfxstream"
 
         if direction == "read":
             self.stmt("memcpy((%s*)&%s, %s, %s)" %
diff --git a/src/gfxstream/codegen/scripts/cereal/decoder.py b/src/gfxstream/codegen/scripts/cereal/decoder.py
index 4a3464ea486..c83e6955162 100644
--- a/src/gfxstream/codegen/scripts/cereal/decoder.py
+++ b/src/gfxstream/codegen/scripts/cereal/decoder.py
@@ -36,7 +36,7 @@ GLOBAL_COMMANDS_WITHOUT_DISPATCH = [
     "vkEnumerateInstanceLayerProperties",
 ]
 
-SNAPSHOT_API_CALL_INFO_VARNAME = "snapshotApiCallInfo"
+SNAPSHOT_API_CALL_HANDLE_VARNAME = "snapshotApiCallHandle"
 
 global_state_prefix = "m_state->on_"
 
@@ -70,12 +70,12 @@ decoder_impl_preamble ="""
 namespace gfxstream {
 namespace vk {
 
-using android::base::MetricEventBadPacketLength;
-using android::base::MetricEventDuplicateSequenceNum;
+using gfxstream::base::MetricEventBadPacketLength;
+using gfxstream::base::MetricEventDuplicateSequenceNum;
 
 class VkDecoder::Impl {
 public:
-    Impl() : m_logCalls(android::base::getEnvironmentVariable("ANDROID_EMU_VK_LOG_CALLS") == "1"),
+    Impl() : m_logCalls(gfxstream::base::getEnvironmentVariable("ANDROID_EMU_VK_LOG_CALLS") == "1"),
              m_vk(vkDispatch()),
              m_state(VkDecoderGlobalState::get()),
              m_vkStream(nullptr, m_state->getFeatures()),
@@ -104,7 +104,7 @@ private:
     VulkanMemReadingStream m_vkMemReadingStream;
     BoxedHandleCreateMapping m_boxedHandleCreateMapping;
     BoxedHandleUnwrapMapping m_boxedHandleUnwrapMapping;
-    android::base::BumpPool m_pool;
+    gfxstream::base::BumpPool m_pool;
     std::optional<uint32_t> m_prevSeqno;
     bool m_queueSubmitWithCommandsEnabled = false;
     const bool m_snapshotsEnabled = false;
@@ -283,7 +283,7 @@ def emit_call_log(api, cgen):
         paramLogFormat += "0x%llx "
     for p in paramsToRead:
         paramLogArgs.append("(unsigned long long)%s" % (p.paramName))
-    cgen.stmt("fprintf(stderr, \"stream %%p: call %s %s\\n\", ioStream, %s)" % (api.name, paramLogFormat, ", ".join(paramLogArgs)))
+    cgen.stmt("GFXSTREAM_INFO(\"stream %%p: call %s %s\", ioStream, %s)" % (api.name, paramLogFormat, ", ".join(paramLogArgs)))
     cgen.endIf()
 
 def emit_decode_parameters(typeInfo: VulkanTypeInfo, api: VulkanAPI, cgen, globalWrapped=False):
@@ -376,9 +376,9 @@ def emit_global_state_wrapped_call(api, cgen, context):
     if delay:
         cgen.line("std::function<void()> delayed_remove_callback = [vk, %s]() {" % ", ".join(coreCustomParams))
         cgen.stmt("auto m_state = VkDecoderGlobalState::get()")
-        customParams = ["nullptr", "nullptr"] + coreCustomParams
+        customParams = ["nullptr", "kInvalidSnapshotApiCallHandle"] + coreCustomParams
     else:
-        customParams = ["&m_pool", SNAPSHOT_API_CALL_INFO_VARNAME] + coreCustomParams
+        customParams = ["&m_pool", SNAPSHOT_API_CALL_HANDLE_VARNAME] + coreCustomParams
 
     if context:
         customParams += ["context"]
@@ -489,8 +489,8 @@ def emit_seqno_incr(api, cgen):
 
 def emit_snapshot(typeInfo, api, cgen):
     additionalParams = [ \
-        makeVulkanTypeSimple(False, "android::base::BumpPool", 1, "&m_pool"),
-        makeVulkanTypeSimple(True, "VkSnapshotApiCallInfo", 1, SNAPSHOT_API_CALL_INFO_VARNAME),
+        makeVulkanTypeSimple(False, "gfxstream::base::BumpPool", 1, "&m_pool"),
+        makeVulkanTypeSimple(True, "VkSnapshotApiCallHandle", 1, SNAPSHOT_API_CALL_HANDLE_VARNAME),
         makeVulkanTypeSimple(True, "uint8_t", 1, "packet"),
         makeVulkanTypeSimple(False, "size_t", 0, "packetLen"),
     ]
@@ -575,7 +575,7 @@ def decode_vkFlushMappedMemoryRanges(typeInfo: VulkanTypeInfo, api, cgen):
     cgen.stmt("memcpy(&readStream, *readStreamPtrPtr, sizeof(uint64_t)); *readStreamPtrPtr += sizeof(uint64_t)")
     cgen.stmt("sizeLeft -= sizeof(uint64_t)")
     cgen.stmt("auto hostPtr = m_state->getMappedHostPointer(memory)")
-    cgen.stmt("if (!hostPtr && readStream > 0) GFXSTREAM_ABORT(::emugl::FatalError(::emugl::ABORT_REASON_OTHER))")
+    cgen.stmt("if (!hostPtr && readStream > 0) GFXSTREAM_FATAL(\"Unexpected\")")
     cgen.stmt("if (!hostPtr) continue")
     cgen.beginIf("sizeLeft < readStream")
     cgen.beginIf("m_prevSeqno")
@@ -837,6 +837,16 @@ custom_decodes = {
     # VK_KHR_device_group_creation / VK_VERSION_1_1
     "vkEnumeratePhysicalDeviceGroups" : emit_global_state_wrapped_decoding,
     "vkEnumeratePhysicalDeviceGroupsKHR" : emit_global_state_wrapped_decoding,
+
+    # Sparse binding and formats (Support can be disabled from the host)
+    "vkGetPhysicalDeviceSparseImageFormatProperties" : emit_global_state_wrapped_decoding,
+    "vkGetPhysicalDeviceSparseImageFormatProperties2" : emit_global_state_wrapped_decoding,
+    "vkGetPhysicalDeviceSparseImageFormatProperties2KHR" : emit_global_state_wrapped_decoding,
+
+    # Image requirements need to be adjusted for compressed textures
+    "vkGetDeviceImageMemoryRequirements" : emit_global_state_wrapped_decoding,
+    "vkGetDeviceImageMemoryRequirementsKHR" : emit_global_state_wrapped_decoding,
+
 }
 
 class VulkanDecoder(VulkanWrapperGenerator):
@@ -869,6 +879,7 @@ size_t VkDecoder::Impl::decode(void* buf, size_t len, IOStream* ioStream,
         self.cgen.stmt("auto& gfx_logger = *context.gfxApiLogger")
         self.cgen.stmt("auto* healthMonitor = context.healthMonitor")
         self.cgen.stmt("auto& metricsLogger = *context.metricsLogger")
+        self.cgen.stmt("auto& shouldExit = *context.shouldExit")
         self.cgen.stmt("if (len < 8) return 0")
         self.cgen.stmt("unsigned char *ptr = (unsigned char *)buf")
         self.cgen.stmt("const unsigned char* const end = (const unsigned char*)buf + len")
@@ -882,7 +893,7 @@ size_t VkDecoder::Impl::decode(void* buf, size_t len, IOStream* ioStream,
         self.cgen.line("""
         // packetLen should be at least 8 (op code and packet length) and should not be excessively large
         if (packetLen < 8 || packetLen > MAX_PACKET_LENGTH) {
-            WARN("Bad packet length %d detected, decode may fail", packetLen);
+            GFXSTREAM_WARNING("Bad packet length %d detected, decode may fail", packetLen);
             metricsLogger.logMetricEvent(MetricEventBadPacketLength{ .len = packetLen });
         }
         """)
@@ -919,7 +930,7 @@ size_t VkDecoder::Impl::decode(void* buf, size_t len, IOStream* ioStream,
             memcpy(&seqno, *readStreamPtrPtr, sizeof(uint32_t)); *readStreamPtrPtr += sizeof(uint32_t);
             if (healthMonitor) executionData->insert({{"seqno", std::to_string(seqno)}});
             if (m_prevSeqno  && seqno == m_prevSeqno.value()) {
-                WARN(
+                GFXSTREAM_WARNING(
                     "Seqno %d is the same as previously processed on thread %d. It might be a "
                     "duplicate command.",
                     seqno, getCurrentThreadId());
@@ -940,6 +951,11 @@ size_t VkDecoder::Impl::decode(void* buf, size_t len, IOStream* ioStream,
                             })
                             .build();
                     while ((seqno - seqnoPtr->load(std::memory_order_seq_cst) != 1)) {
+                        if (shouldExit.load(std::memory_order_relaxed)) {
+                            GFXSTREAM_WARNING("Process=%s is exitting. Skip processing seqno=%d on thread=0x%x.",
+                                 processName ? processName : "null", seqno, getCurrentThreadId());
+                            return 0;
+                        }
                         #if (defined(_MSC_VER) && (defined(_M_IX86) || defined(_M_X64)))
                         _mm_pause();
                         #elif (defined(__GNUC__) && (defined(__i386__) || defined(__x86_64__)))
@@ -953,11 +969,11 @@ size_t VkDecoder::Impl::decode(void* buf, size_t len, IOStream* ioStream,
         """)
 
         self.cgen.line("""
-        VkSnapshotApiCallInfo* %s = nullptr;
+        VkSnapshotApiCallHandle %s = kInvalidSnapshotApiCallHandle;
         if (m_snapshotsEnabled) {
             %s = m_state->snapshot()->createApiCallInfo();
         }
-        """ % (SNAPSHOT_API_CALL_INFO_VARNAME, SNAPSHOT_API_CALL_INFO_VARNAME))
+        """ % (SNAPSHOT_API_CALL_HANDLE_VARNAME, SNAPSHOT_API_CALL_HANDLE_VARNAME))
 
         self.cgen.line("""
         gfx_logger.recordCommandExecution();
@@ -1001,7 +1017,7 @@ size_t VkDecoder::Impl::decode(void* buf, size_t len, IOStream* ioStream,
         if (m_snapshotsEnabled) {
             m_state->snapshot()->destroyApiCallInfoIfUnused(%s);
         }
-        """ % (SNAPSHOT_API_CALL_INFO_VARNAME))
+        """ % (SNAPSHOT_API_CALL_HANDLE_VARNAME))
 
         self.cgen.stmt("m_pool.freeAll()")
         self.cgen.stmt("return ptr - (unsigned char *)buf")
@@ -1013,7 +1029,7 @@ size_t VkDecoder::Impl::decode(void* buf, size_t len, IOStream* ioStream,
         if (m_snapshotsEnabled) {
             m_state->snapshot()->destroyApiCallInfoIfUnused(%s);
         }
-        """ % (SNAPSHOT_API_CALL_INFO_VARNAME))
+        """ % (SNAPSHOT_API_CALL_HANDLE_VARNAME))
 
         self.cgen.stmt("ptr += packetLen")
         self.cgen.stmt("vkStream->clearPool()")
diff --git a/src/gfxstream/codegen/scripts/cereal/decodersnapshot.py b/src/gfxstream/codegen/scripts/cereal/decodersnapshot.py
index b67612f14b6..f3c7fe08650 100644
--- a/src/gfxstream/codegen/scripts/cereal/decodersnapshot.py
+++ b/src/gfxstream/codegen/scripts/cereal/decodersnapshot.py
@@ -16,12 +16,15 @@ from dataclasses import dataclass
 
 decoder_snapshot_decl_preamble = """
 
-namespace android {
+namespace gfxstream {
+class Stream;
+} // namespace gfxstream
+
+namespace gfxstream {
 namespace base {
 class BumpPool;
-class Stream;
-} // namespace base {
-} // namespace android {
+} // namespace base
+} // namespace gfxstream
 
 namespace gfxstream {
 namespace vk {
@@ -33,11 +36,16 @@ class VkDecoderSnapshot {
 
     void clear();
 
-    void saveReplayBuffers(android::base::Stream* stream);
-    static void loadReplayBuffers(android::base::Stream* stream, std::vector<uint64_t>* outHandleBuffer, std::vector<uint8_t>* outDecoderBuffer);
+    void saveReplayBuffers(gfxstream::Stream* stream);
+    static void loadReplayBuffers(gfxstream::Stream* stream, std::vector<uint64_t>* outHandleBuffer, std::vector<uint8_t>* outDecoderBuffer);
+
+    VkSnapshotApiCallHandle createApiCallInfo();
+    void destroyApiCallInfoIfUnused(VkSnapshotApiCallHandle handle);
 
-    VkSnapshotApiCallInfo* createApiCallInfo();
-    void destroyApiCallInfoIfUnused(VkSnapshotApiCallInfo* info);
+    // Performs bookkeeping to track that a given api call created the given VkObject handles.
+    // This is a public function so that `VkDecoderGlobalState` can inform snapshot of any
+    // additional handles created while emulating features.
+    void addOrderedBoxedHandlesCreatedByCall(VkSnapshotApiCallHandle apiCallHandle, VkObjectHandle* boxedHandles, uint32_t boxedHandlesCount);
 """
 
 decoder_snapshot_decl_postamble = """
@@ -53,9 +61,6 @@ decoder_snapshot_decl_postamble = """
 
 decoder_snapshot_impl_preamble ="""
 
-using emugl::GfxApiLogger;
-using emugl::HealthMonitor;
-
 namespace gfxstream {
 namespace vk {
 
@@ -68,24 +73,30 @@ class VkDecoderSnapshot::Impl {
         mReconstruction.clear();
     }
 
-    void saveReplayBuffers(android::base::Stream* stream) {
+    void saveReplayBuffers(gfxstream::Stream* stream) {
         std::lock_guard<std::mutex> lock(mReconstructionMutex);
         mReconstruction.saveReplayBuffers(stream);
     }
 
-    static void loadReplayBuffers(android::base::Stream* stream, std::vector<uint64_t>* outHandleBuffer, std::vector<uint8_t>* outDecoderBuffer) {
+    static void loadReplayBuffers(gfxstream::Stream* stream, std::vector<uint64_t>* outHandleBuffer, std::vector<uint8_t>* outDecoderBuffer) {
         VkReconstruction::loadReplayBuffers(stream, outHandleBuffer, outDecoderBuffer);
     }
 
-    VkSnapshotApiCallInfo* createApiCallInfo() {
+    VkSnapshotApiCallHandle createApiCallInfo() {
         std::lock_guard<std::mutex> lock(mReconstructionMutex);
         return mReconstruction.createApiCallInfo();
     }
 
-    void destroyApiCallInfoIfUnused(VkSnapshotApiCallInfo* info) {
+    void destroyApiCallInfoIfUnused(VkSnapshotApiCallHandle apiCallHandle) {
         std::lock_guard<std::mutex> lock(mReconstructionMutex);
-        return mReconstruction.destroyApiCallInfoIfUnused(info);
+        return mReconstruction.destroyApiCallInfoIfUnused(apiCallHandle);
     }
+
+    void addOrderedBoxedHandlesCreatedByCall(VkSnapshotApiCallHandle apiCallHandle, VkObjectHandle* boxedHandles, uint32_t boxedHandlesCount) {
+        std::lock_guard<std::mutex> lock(mReconstructionMutex);
+        return mReconstruction.addOrderedBoxedHandlesCreatedByCall(apiCallHandle, boxedHandles, boxedHandlesCount);
+    }
+
 """
 
 decoder_snapshot_impl_postamble = """
@@ -101,21 +112,25 @@ void VkDecoderSnapshot::clear() {
     mImpl->clear();
 }
 
-void VkDecoderSnapshot::saveReplayBuffers(android::base::Stream* stream) {
+void VkDecoderSnapshot::saveReplayBuffers(gfxstream::Stream* stream) {
     mImpl->saveReplayBuffers(stream);
 }
 
 /*static*/
-void VkDecoderSnapshot::loadReplayBuffers(android::base::Stream* stream, std::vector<uint64_t>* outHandleBuffer, std::vector<uint8_t>* outDecoderBuffer) {
+void VkDecoderSnapshot::loadReplayBuffers(gfxstream::Stream* stream, std::vector<uint64_t>* outHandleBuffer, std::vector<uint8_t>* outDecoderBuffer) {
     VkDecoderSnapshot::Impl::loadReplayBuffers(stream, outHandleBuffer, outDecoderBuffer);
 }
 
-VkSnapshotApiCallInfo* VkDecoderSnapshot::createApiCallInfo() {
+VkSnapshotApiCallHandle VkDecoderSnapshot::createApiCallInfo() {
     return mImpl->createApiCallInfo();
 }
 
-void VkDecoderSnapshot::destroyApiCallInfoIfUnused(VkSnapshotApiCallInfo* info) {
-    mImpl->destroyApiCallInfoIfUnused(info);
+void VkDecoderSnapshot::destroyApiCallInfoIfUnused(VkSnapshotApiCallHandle handle) {
+    mImpl->destroyApiCallInfoIfUnused(handle);
+}
+
+void VkDecoderSnapshot::addOrderedBoxedHandlesCreatedByCall(VkSnapshotApiCallHandle apiCallHandle, VkObjectHandle* boxedHandles, uint32_t boxedHandlesCount) {
+    mImpl->addOrderedBoxedHandlesCreatedByCall(apiCallHandle, boxedHandles, boxedHandlesCount);
 }
 
 VkDecoderSnapshot::~VkDecoderSnapshot() = default;
@@ -170,6 +185,7 @@ def extract_deps_vkAllocateDescriptorSets(param, access, lenExpr, api, cgen):
               (access, lenExpr, "unboxed_to_boxed_non_dispatchable_VkDescriptorPool(pAllocateInfo->descriptorPool)"))
 
 def extract_deps_vkUpdateDescriptorSets(param, access, lenExpr, api, cgen):
+    cgen.stmt("mReconstruction.addHandleDependency((const uint64_t*)(&handle), 1, (uint64_t)(uintptr_t)device)")
     cgen.beginFor("uint32_t i = 0", "i < descriptorWriteCount", "++i")
     cgen.stmt("mReconstruction.addHandleDependency((const uint64_t*)(&handle), 1, (uint64_t)(uintptr_t)unboxed_to_boxed_non_dispatchable_VkDescriptorSet( pDescriptorWrites[i].dstSet))")
     cgen.beginFor("uint32_t j = 0", "j < pDescriptorWrites[i].descriptorCount", "++j")
@@ -178,6 +194,9 @@ def extract_deps_vkUpdateDescriptorSets(param, access, lenExpr, api, cgen):
     cgen.stmt("mReconstruction.addHandleDependency((const uint64_t*)(&handle), 1, (uint64_t)(uintptr_t)unboxed_to_boxed_non_dispatchable_VkSampler( pDescriptorWrites[i].pImageInfo[j].sampler))")
     cgen.stmt("mReconstruction.addHandleDependency((const uint64_t*)(&handle), 1, (uint64_t)(uintptr_t)unboxed_to_boxed_non_dispatchable_VkImageView( pDescriptorWrites[i].pImageInfo[j].imageView))")
     cgen.endIf()
+    cgen.beginIf("pDescriptorWrites[i].pImageInfo[j].imageView")
+    cgen.stmt("mReconstruction.addHandleDependency((const uint64_t*)(&handle), 1, (uint64_t)(uintptr_t)unboxed_to_boxed_non_dispatchable_VkImageView( pDescriptorWrites[i].pImageInfo[j].imageView))")
+    cgen.endIf()
     cgen.beginIf("pDescriptorWrites[i].descriptorType == VK_DESCRIPTOR_TYPE_SAMPLER")
     cgen.stmt("mReconstruction.addHandleDependency((const uint64_t*)(&handle), 1, (uint64_t)(uintptr_t)unboxed_to_boxed_non_dispatchable_VkSampler( pDescriptorWrites[i].pImageInfo[j].sampler))")
     cgen.endIf()
@@ -191,7 +210,7 @@ def extract_deps_vkUpdateDescriptorSets(param, access, lenExpr, api, cgen):
     cgen.endFor()
 
 def extract_deps_vkCreateImageView(param, access, lenExpr, api, cgen):
-    cgen.stmt("mReconstruction.addHandleDependency((const uint64_t*)%s, %s, (uint64_t)(uintptr_t)%s, VkReconstruction::CREATED, VkReconstruction::BOUND_MEMORY)" % \
+    cgen.stmt("mReconstruction.addHandleDependency((const uint64_t*)%s, %s, (uint64_t)(uintptr_t)%s)" % \
               (access, lenExpr, "unboxed_to_boxed_non_dispatchable_VkImage(pCreateInfo->image)"))
 
 def extract_deps_vkCreateGraphicsPipelines(param, access, lenExpr, api, cgen):
@@ -231,8 +250,6 @@ specialCaseDependencyExtractors = {
     "vkCreateImageView" : extract_deps_vkCreateImageView,
     "vkCreateGraphicsPipelines" : extract_deps_vkCreateGraphicsPipelines,
     "vkCreateFramebuffer" : extract_deps_vkCreateFramebuffer,
-    "vkBindImageMemory": extract_deps_vkBindImageMemory,
-    "vkBindBufferMemory": extract_deps_vkBindBufferMemory,
     "vkUpdateDescriptorSets" : extract_deps_vkUpdateDescriptorSets,
 }
 
@@ -247,44 +264,135 @@ class VkObjectState:
 
 # TODO: add vkBindImageMemory2 and vkBindBufferMemory2 into this list
 apiChangeState = {
-    "vkBindImageMemory": VkObjectState("image", "VkReconstruction::BOUND_MEMORY"),
-    "vkBindBufferMemory": VkObjectState("buffer", "VkReconstruction::BOUND_MEMORY"),
 }
 
-def api_special_implementation_vkBindImageMemory2(api, cgen):
-    childType = "VkImage"
-    parentType = "VkDeviceMemory"
-    childObj = "boxed_%s" % childType
-    parentObj = "boxed_%s" % parentType
+def api_special_implementation_common(api, cgen, tag_vk):
+    cgen.line("// Note: special implementation");
     cgen.stmt("std::lock_guard<std::mutex> lock(mReconstructionMutex)")
-    cgen.beginFor("uint32_t i = 0", "i < bindInfoCount", "++i")
-    cgen.stmt("%s boxed_%s = unboxed_to_boxed_non_dispatchable_%s(pBindInfos[i].image)"
-              % (childType, childType, childType))
-    cgen.stmt("%s boxed_%s = unboxed_to_boxed_non_dispatchable_%s(pBindInfos[i].memory)"
-              % (parentType, parentType, parentType))
-    cgen.stmt("mReconstruction.addHandleDependency((const uint64_t*)&%s, %s, (uint64_t)(uintptr_t)%s, VkReconstruction::BOUND_MEMORY)" % \
-              (childObj, "1", parentObj))
-    cgen.stmt("mReconstruction.addHandleDependency((const uint64_t*)&%s, %s, (uint64_t)(uintptr_t)%s, VkReconstruction::BOUND_MEMORY)" % \
-              (childObj, "1", childObj))
+    cgen.stmt("VkDecoderGlobalState* m_state = VkDecoderGlobalState::get()")
+    cgen.stmt("uint64_t handle = m_state->newGlobalVkGenericHandle(%s)" % tag_vk)
+    cgen.stmt("mReconstruction.addHandles((const uint64_t*)(&handle), 1)")
+    cgen.stmt("mReconstruction.forEachHandleAddApi((const uint64_t*)(&handle), 1, apiCallHandle, VkReconstruction::CREATED)")
+    cgen.stmt("mReconstruction.setCreatedHandlesForApi(apiCallHandle, (const uint64_t*)(&handle), 1)")
+    cgen.stmt("mReconstruction.setApiTrace(apiCallHandle, apiCallPacket, apiCallPacketSize)")
+
+def api_special_implementation_vkCmdPipelineBarrier(api, cgen):
+    cgen.stmt("std::lock_guard<std::mutex> lock(mReconstructionMutex)")
+    cgen.beginFor("uint32_t i = 0", "i < bufferMemoryBarrierCount", "++i")
+    cgen.stmt("mReconstruction.addApiCallDependencyOnVkObject(apiCallHandle, (uint64_t)(uintptr_t)unboxed_to_boxed_non_dispatchable_VkBuffer( pBufferMemoryBarriers[i].buffer))")
+    cgen.endFor()
+    cgen.beginFor("uint32_t i = 0", "i < imageMemoryBarrierCount", "++i")
+    cgen.stmt("mReconstruction.addApiCallDependencyOnVkObject(apiCallHandle, (uint64_t)(uintptr_t)unboxed_to_boxed_non_dispatchable_VkImage( pImageMemoryBarriers[i].image))")
     cgen.endFor()
 
-    cgen.stmt("auto apiCallHandle = apiCallInfo->handle")
-    cgen.stmt("mReconstruction.setApiTrace(apiCallInfo, apiCallPacket, apiCallPacketSize)")
-    cgen.line("// Note: the implementation does not work with bindInfoCount > 1");
+def api_special_implementation_vkUpdateDescriptorSetWithTemplateSizedGOOGLE(api, cgen):
+    cgen.stmt("std::lock_guard<std::mutex> lock(mReconstructionMutex)")
+    cgen.stmt("VkDecoderGlobalState* m_state = VkDecoderGlobalState::get()")
+    cgen.beginIf("m_state->batchedDescriptorSetUpdateEnabled()")
+    cgen.stmt("return")
+    cgen.endIf();
+    cgen.stmt("uint64_t handle = m_state->newGlobalVkGenericHandle(Tag_VkUpdateDescriptorSets)")
+    cgen.stmt("mReconstruction.addHandles((const uint64_t*)(&handle), 1)")
+    cgen.stmt("mReconstruction.setApiTrace(apiCallHandle, apiCallPacket, apiCallPacketSize)")
+    cgen.stmt("mReconstruction.addHandleDependency( (const uint64_t*)(&handle), 1, (uint64_t)(uintptr_t)device)")
+    cgen.stmt("mReconstruction.forEachHandleAddApi((const uint64_t*)(&handle), 1, apiCallHandle, VkReconstruction::CREATED)")
+    cgen.stmt("mReconstruction.setCreatedHandlesForApi(apiCallHandle, (const uint64_t*)(&handle), 1)")
+
+def api_special_implementation_vkCmdBeginRenderPass(api, cgen):
+    cgen.stmt("std::lock_guard<std::mutex> lock(mReconstructionMutex)")
+    cgen.stmt("mReconstruction.addApiCallDependencyOnVkObject(apiCallHandle, (uint64_t)(uintptr_t)unboxed_to_boxed_non_dispatchable_VkFramebuffer( pRenderPassBegin->framebuffer))")
+
+def api_special_implementation_vkMapMemoryIntoAddressSpaceGOOGLE(api, cgen):
+    cgen.stmt("std::lock_guard<std::mutex> lock(mReconstructionMutex)")
+    cgen.stmt("VkDecoderGlobalState* m_state = VkDecoderGlobalState::get()")
+    cgen.stmt("uint64_t handle = m_state->newGlobalVkGenericHandle(Tag_VkMapMemory)")
+    cgen.stmt("mReconstruction.addHandles((const uint64_t*)(&handle), 1)")
+    cgen.stmt("mReconstruction.addHandleDependency((const uint64_t*)(&handle), 1, (uint64_t)(uintptr_t)unboxed_to_boxed_non_dispatchable_VkDeviceMemory(memory))")
+    cgen.stmt("mReconstruction.forEachHandleAddApi((const uint64_t*)(&handle), 1, apiCallHandle, VkReconstruction::CREATED)")
+    cgen.stmt("mReconstruction.setCreatedHandlesForApi(apiCallHandle, (const uint64_t*)(&handle), 1)")
+    cgen.stmt("mReconstruction.setApiTrace(apiCallHandle, apiCallPacket, apiCallPacketSize)")
+
+def api_special_implementation_vkCmdBeginRenderPass(api, cgen):
+    cgen.stmt("std::lock_guard<std::mutex> lock(mReconstructionMutex)")
+    cgen.stmt("mReconstruction.addApiCallDependencyOnVkObject(apiCallHandle, (uint64_t)(uintptr_t)unboxed_to_boxed_non_dispatchable_VkFramebuffer( pRenderPassBegin->framebuffer))")
+
+def api_special_implementation_vkCmdCopyBufferToImage(api, cgen):
+    cgen.stmt("std::lock_guard<std::mutex> lock(mReconstructionMutex)")
+    cgen.stmt("mReconstruction.addApiCallDependencyOnVkObject(apiCallHandle, (uint64_t)(uintptr_t)unboxed_to_boxed_non_dispatchable_VkBuffer(srcBuffer))")
+    cgen.stmt("mReconstruction.addApiCallDependencyOnVkObject(apiCallHandle, (uint64_t)(uintptr_t)unboxed_to_boxed_non_dispatchable_VkImage(dstImage))")
+
+def api_special_implementation_vkCmdCopyBuffer(api, cgen):
+    cgen.stmt("std::lock_guard<std::mutex> lock(mReconstructionMutex)")
+    cgen.stmt("mReconstruction.addApiCallDependencyOnVkObject(apiCallHandle, (uint64_t)(uintptr_t)unboxed_to_boxed_non_dispatchable_VkBuffer(srcBuffer))")
+    cgen.stmt("mReconstruction.addApiCallDependencyOnVkObject(apiCallHandle, (uint64_t)(uintptr_t)unboxed_to_boxed_non_dispatchable_VkBuffer(dstBuffer))")
+
+def api_special_implementation_vkCmdBindVertexBuffers(api, cgen):
+    cgen.stmt("std::lock_guard<std::mutex> lock(mReconstructionMutex)")
+    cgen.beginFor("uint32_t i = 0", "i < bindingCount", "++i")
+    cgen.stmt("mReconstruction.addApiCallDependencyOnVkObject(apiCallHandle, (uint64_t)(uintptr_t)unboxed_to_boxed_non_dispatchable_VkBuffer(pBuffers[i]))")
+    cgen.endFor()
+
+def api_special_implementation_vkCmdBindPipeline(api, cgen):
+    cgen.stmt("std::lock_guard<std::mutex> lock(mReconstructionMutex)")
+    cgen.stmt("mReconstruction.addApiCallDependencyOnVkObject(apiCallHandle, (uint64_t)(uintptr_t)unboxed_to_boxed_non_dispatchable_VkPipeline(pipeline))")
+
+def api_special_implementation_vkResetCommandPool(api, cgen):
+    cgen.line("// Note: special implementation");
+    cgen.stmt("std::lock_guard<std::mutex> lock(mReconstructionMutex)")
+    cgen.stmt("mReconstruction.removeGrandChildren((uint64_t)(uintptr_t)unboxed_to_boxed_non_dispatchable_VkCommandPool(commandPool))")
+
+def api_special_implementation_vkResetCommandBuffer(api, cgen):
+    cgen.line("// Note: special implementation");
+    cgen.stmt("std::lock_guard<std::mutex> lock(mReconstructionMutex)")
+    cgen.stmt("mReconstruction.removeDescendantsOfHandle((uint64_t)(uintptr_t)commandBuffer)")
+
+def api_special_implementation_vkQueueFlushCommandsGOOGLE(api, cgen):
+    api_special_implementation_common(api, cgen, "Tag_VkCmdOp")
+    cgen.stmt("mReconstruction.addHandleDependency((const uint64_t*)(&handle), 1, (uint64_t)(uintptr_t)commandBuffer)")
+
+    cgen.line("// Track that `handle` depends on previously tracked dependencies (e.g. the handle for this `vkQueueFlushCommandsGOOGLE()` call depends on the `VkPipeline` handle from `vkCmdBindPipeline()`).")
+    cgen.stmt("mReconstruction.addHandleDependenciesForApiCallDependencies(apiCallHandle, handle)")
+
+
+def api_special_implementation_vkBindBufferMemory(api, cgen):
+    api_special_implementation_common(api, cgen, "Tag_VkBindMemory")
+    cgen.stmt("mReconstruction.addHandleDependency( (const uint64_t*)(&handle), 1, (uint64_t)(uintptr_t)unboxed_to_boxed_non_dispatchable_VkDeviceMemory(memory))")
+    cgen.stmt("mReconstruction.addHandleDependency((const uint64_t*)(&handle), 1, (uint64_t)(uintptr_t)(unboxed_to_boxed_non_dispatchable_VkBuffer(buffer)))")
+
+def api_special_implementation_vkBindImageMemory(api, cgen):
+    api_special_implementation_common(api, cgen, "Tag_VkBindMemory")
+    cgen.stmt("mReconstruction.addHandleDependency( (const uint64_t*)(&handle), 1, (uint64_t)(uintptr_t)unboxed_to_boxed_non_dispatchable_VkDeviceMemory(memory))")
+    cgen.stmt("mReconstruction.addHandleDependency((const uint64_t*)(&handle), 1, (uint64_t)(uintptr_t)unboxed_to_boxed_non_dispatchable_VkImage(image))")
+
+def api_special_implementation_vkBindImageMemory2(api, cgen):
+    api_special_implementation_common(api, cgen, "Tag_VkBindMemory")
     cgen.beginFor("uint32_t i = 0", "i < bindInfoCount", "++i")
-    cgen.stmt("%s boxed_%s = unboxed_to_boxed_non_dispatchable_%s(pBindInfos[i].image)"
-              % (childType, childType, childType))
-    cgen.stmt(f"mReconstruction.forEachHandleAddApi((const uint64_t*)&{childObj}, {1}, apiCallHandle, VkReconstruction::BOUND_MEMORY)")
+    cgen.stmt("mReconstruction.addHandleDependency((const uint64_t*)&handle, 1, (uint64_t)(uintptr_t)unboxed_to_boxed_non_dispatchable_VkDeviceMemory(pBindInfos[i].memory))")
+    cgen.stmt("mReconstruction.addHandleDependency((const uint64_t*)&handle, 1, (uint64_t)(uintptr_t)unboxed_to_boxed_non_dispatchable_VkImage(pBindInfos[i].image))")
     cgen.endFor()
 
 apiSpecialImplementation = {
+    "vkBindBufferMemory": api_special_implementation_vkBindBufferMemory,
+    "vkBindImageMemory": api_special_implementation_vkBindImageMemory,
     "vkBindImageMemory2": api_special_implementation_vkBindImageMemory2,
     "vkBindImageMemory2KHR": api_special_implementation_vkBindImageMemory2,
+    "vkMapMemoryIntoAddressSpaceGOOGLE": api_special_implementation_vkMapMemoryIntoAddressSpaceGOOGLE,
+    "vkGetBlobGOOGLE": api_special_implementation_vkMapMemoryIntoAddressSpaceGOOGLE,
+    "vkQueueFlushCommandsGOOGLE": api_special_implementation_vkQueueFlushCommandsGOOGLE,
+    "vkResetCommandBuffer": api_special_implementation_vkResetCommandBuffer,
+    "vkResetCommandPool": api_special_implementation_vkResetCommandPool,
+    "vkCmdBindVertexBuffers": api_special_implementation_vkCmdBindVertexBuffers,
+    "vkCmdBindPipeline": api_special_implementation_vkCmdBindPipeline,
+    "vkCmdCopyBufferToImage": api_special_implementation_vkCmdCopyBufferToImage,
+    "vkCmdCopyBuffer": api_special_implementation_vkCmdCopyBuffer,
+    "vkCmdPipelineBarrier": api_special_implementation_vkCmdPipelineBarrier,
+    "vkCmdBeginRenderPass": api_special_implementation_vkCmdBeginRenderPass,
+    "vkCmdBeginRenderPass2": api_special_implementation_vkCmdBeginRenderPass,
+    "vkUpdateDescriptorSetWithTemplateSizedGOOGLE": api_special_implementation_vkUpdateDescriptorSetWithTemplateSizedGOOGLE,
+    "vkUpdateDescriptorSetWithTemplateSized2GOOGLE": api_special_implementation_vkUpdateDescriptorSetWithTemplateSizedGOOGLE,
 }
 
 apiModifies = {
-    "vkMapMemoryIntoAddressSpaceGOOGLE" : ["memory"],
-    "vkGetBlobGOOGLE" : ["memory"],
     "vkBeginCommandBuffer" : ["commandBuffer"],
     "vkEndCommandBuffer" : ["commandBuffer"],
 }
@@ -293,8 +401,11 @@ apiActions = {
     "vkUpdateDescriptorSets" : ["pDescriptorWrites"],
 }
 
+apiActionsTag = {
+    "vkUpdateDescriptorSets" : "Tag_VkUpdateDescriptorSets",
+}
+
 apiClearModifiers = {
-    "vkResetCommandBuffer" : ["commandBuffer"],
 }
 
 delayedDestroys = [
@@ -335,16 +446,8 @@ def is_modify_operation(api, param):
     if api.name in apiModifies:
         if param.paramName in apiModifies[api.name]:
             return True
-    if api.name.startswith('vkCmd') and param.paramName == 'commandBuffer':
-        return True
     return False
 
-def is_clear_modifier_operation(api, param):
-    if api.name in apiClearModifiers:
-        if param.paramName in apiClearModifiers[api.name]:
-            return True
-
-
 def emit_impl(typeInfo, api, cgen):
     if api.name in apiSpecialImplementation:
         apiSpecialImplementation[api.name](api, cgen)
@@ -373,6 +476,7 @@ def emit_impl(typeInfo, api, cgen):
                 boxed_access = "&boxed_%s" % p.typeName
             if p.pointerIndirectionLevels > 0:
                 cgen.stmt("if (!%s) return" % access)
+                cgen.stmt("if (input_result != VK_SUCCESS) return")
 
             cgen.stmt("std::lock_guard<std::mutex> lock(mReconstructionMutex)")
             cgen.line("// %s create" % p.paramName)
@@ -387,8 +491,7 @@ def emit_impl(typeInfo, api, cgen):
             if api.name in specialCaseDependencyExtractors:
                 specialCaseDependencyExtractors[api.name](p, boxed_access, lenExpr, api, cgen)
 
-            cgen.stmt("auto apiCallHandle = apiCallInfo->handle")
-            cgen.stmt("mReconstruction.setApiTrace(apiCallInfo, apiCallPacket, apiCallPacketSize)")
+            cgen.stmt("mReconstruction.setApiTrace(apiCallHandle, apiCallPacket, apiCallPacketSize)")
             if lenAccessGuard is not None:
                 cgen.beginIf(lenAccessGuard)
             cgen.stmt(f"mReconstruction.forEachHandleAddApi((const uint64_t*){boxed_access}, {lenExpr}, apiCallHandle, {get_target_state(api, p)})")
@@ -414,20 +517,18 @@ def emit_impl(typeInfo, api, cgen):
             cgen.beginIf("m_state->batchedDescriptorSetUpdateEnabled()")
             cgen.stmt("return")
             cgen.endIf();
-            cgen.stmt("uint64_t handle = m_state->newGlobalVkGenericHandle()")
+            cgen.stmt("uint64_t handle = m_state->newGlobalVkGenericHandle(%s)" % apiActionsTag[api.name])
             cgen.stmt("mReconstruction.addHandles((const uint64_t*)(&handle), 1)");
-            cgen.stmt("auto apiCallHandle = apiCallInfo->handle")
-            cgen.stmt("mReconstruction.setApiTrace(apiCallInfo, apiCallPacket, apiCallPacketSize)")
+            cgen.stmt("mReconstruction.setApiTrace(apiCallHandle, apiCallPacket, apiCallPacketSize)")
             if api.name in specialCaseDependencyExtractors:
                 specialCaseDependencyExtractors[api.name](p, None, None, api, cgen)
             cgen.stmt(f"mReconstruction.forEachHandleAddApi((const uint64_t*)(&handle), 1, apiCallHandle, {get_target_state(api, p)})")
             cgen.stmt("mReconstruction.setCreatedHandlesForApi(apiCallHandle, (const uint64_t*)(&handle), 1)")
 
-        elif is_modify_operation(api, p) or is_clear_modifier_operation(api, p):
+        elif is_modify_operation(api, p):
             cgen.stmt("std::lock_guard<std::mutex> lock(mReconstructionMutex)")
             cgen.line("// %s modify" % p.paramName)
-            cgen.stmt("auto apiCallHandle = apiCallInfo->handle")
-            cgen.stmt("mReconstruction.setApiTrace(apiCallInfo, apiCallPacket, apiCallPacketSize)")
+            cgen.stmt("mReconstruction.setApiTrace(apiCallHandle, apiCallPacket, apiCallPacketSize)")
             if lenAccessGuard is not None:
                 cgen.beginIf(lenAccessGuard)
             cgen.beginFor("uint32_t i = 0", "i < %s" % lenExpr, "++i")
@@ -476,8 +577,8 @@ class VulkanDecoderSnapshot(VulkanWrapperGenerator):
         api = self.typeInfo.apis[name]
 
         additionalParams = [ \
-            makeVulkanTypeSimple(False, "android::base::BumpPool", 1, "pool"),
-            makeVulkanTypeSimple(False, "VkSnapshotApiCallInfo", 1, "apiCallInfo"),
+            makeVulkanTypeSimple(False, "gfxstream::base::BumpPool", 1, "pool"),
+            makeVulkanTypeSimple(False, "VkSnapshotApiCallHandle", 0, "apiCallHandle"),
             makeVulkanTypeSimple(True, "uint8_t", 1, "apiCallPacket"),
             makeVulkanTypeSimple(False, "size_t", 0, "apiCallPacketSize"),
         ]
diff --git a/src/gfxstream/codegen/scripts/cereal/extensionstructs.py b/src/gfxstream/codegen/scripts/cereal/extensionstructs.py
index 0234805fb1c..752da92b17d 100644
--- a/src/gfxstream/codegen/scripts/cereal/extensionstructs.py
+++ b/src/gfxstream/codegen/scripts/cereal/extensionstructs.py
@@ -98,8 +98,8 @@ class VulkanExtensionStructs(VulkanWrapperGenerator):
             # emitForEachStructExtension and not accessible here. Consequently,
             # this is a copy-paste from there and must be updated accordingly.
             # NOTE: No need for %% if no substitution is made.
-            cgen.stmt("fprintf(stderr, \"Unhandled Vulkan structure type %s [%d], aborting.\\n\", string_VkStructureType(VkStructureType(structType)), structType)")
-            cgen.stmt("GFXSTREAM_ABORT(::emugl::FatalError(::emugl::ABORT_REASON_OTHER))")
+            cgen.stmt("const std::string structTypeString = string_VkStructureType(VkStructureType(structType))")
+            cgen.stmt("GFXSTREAM_FATAL(\"Unhandled Vulkan structure type %s [%d], aborting.\", structTypeString.c_str(), structType)")
             cgen.stmt("return static_cast<%s>(0)" % self.extensionStructSizeRetType.typeName)
 
         self.module.appendImpl(
diff --git a/src/gfxstream/codegen/scripts/cereal/functable.py b/src/gfxstream/codegen/scripts/cereal/functable.py
index 28916f0f821..c6bde830fab 100644
--- a/src/gfxstream/codegen/scripts/cereal/functable.py
+++ b/src/gfxstream/codegen/scripts/cereal/functable.py
@@ -83,6 +83,7 @@ RESOURCE_TRACKER_ENTRIES = [
     "vkQueueSignalReleaseImageANDROID",
     "vkCmdPipelineBarrier",
     "vkCreateGraphicsPipelines",
+    "vkCmdClearColorImage",
     # Fuchsia
     "vkGetMemoryZirconHandleFUCHSIA",
     "vkGetMemoryZirconHandlePropertiesFUCHSIA",
@@ -93,6 +94,14 @@ RESOURCE_TRACKER_ENTRIES = [
     "vkSetBufferCollectionImageConstraintsFUCHSIA",
     "vkSetBufferCollectionBufferConstraintsFUCHSIA",
     "vkGetBufferCollectionPropertiesFUCHSIA",
+    "vkSetPrivateData",
+    "vkSetPrivateDataKHR",
+    "vkGetPrivateData",
+    "vkGetPrivateDataKHR",
+    "vkCreatePrivateDataSlot",
+    "vkCreatePrivateDataSlotEXT",
+    "vkDestroyPrivateDataSlot",
+    "vkDestroyPrivateDataSlotEXT",
 ]
 
 SUCCESS_VAL = {
diff --git a/src/gfxstream/codegen/scripts/cereal/reservedmarshaling.py b/src/gfxstream/codegen/scripts/cereal/reservedmarshaling.py
index 58a93622318..32916bad251 100644
--- a/src/gfxstream/codegen/scripts/cereal/reservedmarshaling.py
+++ b/src/gfxstream/codegen/scripts/cereal/reservedmarshaling.py
@@ -117,7 +117,7 @@ class VulkanReservedMarshalingCodegen(VulkanTypeIterator):
             if self.variant == "guest":
                 streamNamespace = "gfxstream::aemu"
             else:
-                streamNamespace = "android::base"
+                streamNamespace = "gfxstream"
             if self.direction == "write":
                 self.cgen.stmt("%s::Stream::%s((uint8_t*)*%s)" % (streamNamespace, streamMethod, varname))
             else:
@@ -976,7 +976,7 @@ class VulkanReservedMarshaling(VulkanWrapperGenerator):
         if self.variant == "guest":
             streamNamespace = "gfxstream::aemu"
         else:
-            streamNamespace = "android::base"
+            streamNamespace = "gfxstream"
 
         if direction == "write":
             cgen.stmt("memcpy(*%s, &%s, sizeof(uint32_t));" % (self.ptrVarName, sizeVar))
diff --git a/src/gfxstream/codegen/scripts/cereal/subdecode.py b/src/gfxstream/codegen/scripts/cereal/subdecode.py
index 47c8e58f698..c1931ef0cc8 100644
--- a/src/gfxstream/codegen/scripts/cereal/subdecode.py
+++ b/src/gfxstream/codegen/scripts/cereal/subdecode.py
@@ -1,7 +1,8 @@
 # Copyright 2018 Google LLC
 # SPDX-License-Identifier: MIT
 from .common.codegen import CodeGen, VulkanWrapperGenerator
-from .common.vulkantypes import VulkanAPI, iterateVulkanType, VulkanType
+from .common.vulkantypes import VulkanAPI, makeVulkanTypeSimple, iterateVulkanType, VulkanTypeInfo,\
+    VulkanType
 
 from .reservedmarshaling import VulkanReservedMarshalingCodegen
 from .transform import TransformCodegen
@@ -22,6 +23,8 @@ global_state_prefix = "this->on_"
 READ_STREAM = "readStream"
 WRITE_STREAM = "vkStream"
 
+SNAPSHOT_API_CALL_HANDLE_VARNAME = "snapshotApiCallHandle"
+
 # Driver workarounds for APIs that don't work well multithreaded
 driver_workarounds_global_lock_apis = [
     "vkCreatePipelineLayout",
@@ -243,6 +246,19 @@ def emit_decode_parameters(typeInfo, api, cgen, globalWrapped=False):
 
     emit_call_log(api, cgen)
 
+def emit_snapshot_call(api, cgen):
+    apiForSnapshot = \
+        api.withCustomReturnType(makeVulkanTypeSimple(False, "void", 0, "void"))
+    customParamsSnapshot = ["pool", SNAPSHOT_API_CALL_HANDLE_VARNAME, "nullptr", "0"]
+    retTypeName = api.getRetTypeExpr()
+    if retTypeName != "void":
+        retVar = api.getRetVarExpr()
+        customParamsSnapshot.append(retVar)
+    customParamsSnapshot.append("(VkCommandBuffer)(boxed_dispatchHandle)")
+    customParamsSnapshot = customParamsSnapshot + list(map(lambda p: p.paramName, api.parameters[1:]))
+    cgen.beginIf("snapshotsEnabled()")
+    cgen.vkApiCall(apiForSnapshot, customPrefix="this->snapshot()->", customParameters=customParamsSnapshot)
+    cgen.endIf()
 
 def emit_dispatch_call(api, cgen):
 
@@ -263,18 +279,21 @@ def emit_dispatch_call(api, cgen):
                     checkForDeviceLost=True, globalStatePrefix=global_state_prefix,
                     checkForOutOfMemory=True, checkDispatcher="CC_LIKELY(vk)")
 
+    emit_snapshot_call(api, cgen)
+
     if api.name in driver_workarounds_global_lock_apis:
         cgen.stmt("unlock()")
 
 
 def emit_global_state_wrapped_call(api, cgen, context=False):
-    customParams = ["pool", "nullptr", "(VkCommandBuffer)(boxed_dispatchHandle)"] + \
+    customParams = ["pool", SNAPSHOT_API_CALL_HANDLE_VARNAME, "(VkCommandBuffer)(boxed_dispatchHandle)"] + \
         list(map(lambda p: p.paramName, api.parameters[1:]))
     if context:
         customParams += ["context"];
     cgen.vkApiCall(api, customPrefix=global_state_prefix,
                    customParameters=customParams, checkForDeviceLost=True,
                    checkForOutOfMemory=True, globalStatePrefix=global_state_prefix, checkDispatcher="CC_LIKELY(vk)")
+    emit_snapshot_call(api, cgen)
 
 
 def emit_default_decoding(typeInfo, api, cgen):
@@ -337,14 +356,14 @@ class VulkanSubDecoder(VulkanWrapperGenerator):
             "#define CC_UNLIKELY(exp)  (__builtin_expect( !!(exp), false ))\n")
 
         self.module.appendImpl(
-            "size_t subDecode(VulkanMemReadingStream* readStream, VulkanDispatch* vk, void* boxed_dispatchHandle, void* dispatchHandle, VkDeviceSize subDecodeDataSize, const void* pSubDecodeData, const VkDecoderContext& context)\n")
+            "size_t subDecode(VulkanMemReadingStream* readStream, VulkanDispatch* vk, VkSnapshotApiCallHandle %s, void* boxed_dispatchHandle, void* dispatchHandle, VkDeviceSize subDecodeDataSize, const void* pSubDecodeData, const VkDecoderContext& context)\n" % SNAPSHOT_API_CALL_HANDLE_VARNAME)
 
         self.cgen.beginBlock()  # function body
 
         self.cgen.stmt("auto& metricsLogger = *context.metricsLogger")
         self.cgen.stmt("uint32_t count = 0")
         self.cgen.stmt("unsigned char *buf = (unsigned char *)pSubDecodeData")
-        self.cgen.stmt("android::base::BumpPool* pool = readStream->pool()")
+        self.cgen.stmt("gfxstream::base::BumpPool* pool = readStream->pool()")
         self.cgen.stmt("unsigned char *ptr = (unsigned char *)pSubDecodeData")
         self.cgen.stmt(
             "const unsigned char* const end = (const unsigned char*)buf + subDecodeDataSize")
@@ -359,7 +378,7 @@ class VulkanSubDecoder(VulkanWrapperGenerator):
         self.cgen.line("""
         // packetLen should be at least 8 (op code and packet length) and should not be excessively large
         if (packetLen < 8 || packetLen > MAX_PACKET_LENGTH) {
-            WARN("Bad packet length %d detected, subdecode may fail", packetLen);
+            GFXSTREAM_WARNING("Bad packet length %d detected, subdecode may fail", packetLen);
             metricsLogger.logMetricEvent(MetricEventBadPacketLength{ .len = packetLen });
         }
         """)
@@ -399,7 +418,7 @@ class VulkanSubDecoder(VulkanWrapperGenerator):
         self.cgen.line("default:")
         self.cgen.beginBlock()
         self.cgen.stmt(
-            "GFXSTREAM_ABORT(::emugl::FatalError(::emugl::ABORT_REASON_OTHER)) << \"Unrecognized opcode \" << opcode")
+            "GFXSTREAM_FATAL(\"Unrecognized opcode %\" PRIu32, opcode)")
         self.cgen.endBlock()
 
         self.cgen.endBlock()  # switch stmt
diff --git a/src/gfxstream/codegen/scripts/cerealgenerator.py b/src/gfxstream/codegen/scripts/cerealgenerator.py
index c06aa45bffe..8fb89bbbe8a 100644
--- a/src/gfxstream/codegen/scripts/cerealgenerator.py
+++ b/src/gfxstream/codegen/scripts/cerealgenerator.py
@@ -168,7 +168,7 @@ SUPPORTED_MODULES = {
     "VK_EXT_swapchain_maintenance1" : HOST_MODULES,
     "VK_KHR_swapchain" : HOST_MODULES,
     "VK_NV_device_diagnostic_checkpoints": ["goldfish_vk_dispatch"],
-    "VK_KHR_ray_tracing_pipeline": HOST_MODULES,
+    "VK_KHR_ray_tracing_pipeline": ["goldfish_vk_dispatch"],
     "VK_KHR_pipeline_library": HOST_MODULES,
 }
 
@@ -204,6 +204,22 @@ copyrightHeader = """// Copyright (C) 2018 The Android Open Source Project
 // limitations under the License.
 """
 
+coprightHeaderPy = """# Copyright (C) 2025 The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+"""
+
 # We put the long generated commands in a separate paragraph, so that the formatter won't mess up
 # with other texts.
 autogeneratedHeaderTemplate = """
@@ -281,9 +297,6 @@ class CerealGenerator(OutputGenerator):
         self.featureSupported = False
         self.supportedModules = None
 
-        self.baseLibDirPrefix = "aemu/base"
-        self.utilsHeaderDirPrefix = "utils"
-
         # The cereal variant should be an environmental variable of one of
         # the following:
         #    - "guest"
@@ -395,15 +408,15 @@ class IOStream;
 #include "goldfish_vk_private_defs.h"
 
 #include "%s.h"
-#include "{self.baseLibDirPrefix}/files/StreamSerializing.h"
+#include "gfxstream/host/stream_utils.h"
 """ % VULKAN_STREAM_TYPE
 
         poolInclude = f"""
 {self.hostCommonExtraVulkanHeaders}
 #include "goldfish_vk_private_defs.h"
-#include "{self.baseLibDirPrefix}/BumpPool.h"
-using android::base::Allocator;
-using android::base::BumpPool;
+#include "gfxstream/BumpPool.h"
+using gfxstream::base::Allocator;
+using gfxstream::base::BumpPool;
 """
         transformIncludeGuest = """
 #include "goldfish_vk_private_defs.h"
@@ -422,6 +435,11 @@ using android::base::BumpPool;
         deepcopyInclude = """
 #include "vk_util.h"
 """
+
+        deepcopyHostInclude = """
+#include "VkUtils.h"
+"""
+
         poolIncludeGuest = f"""
 #include "goldfish_vk_private_defs.h"
 #include "BumpPool.h"
@@ -450,8 +468,8 @@ using DlSymFunc = void* (void*, const char*);
 
         extensionStructsInclude = f"""
 {self.hostCommonExtraVulkanHeaders}
+#include "gfxstream/common/logging.h"
 #include "goldfish_vk_private_defs.h"
-#include "host-common/GfxstreamFatalError.h"
 #include "vulkan/vk_enum_string_helper.h"
 """
 
@@ -493,9 +511,9 @@ using DlSymFunc = void* (void*, const char*);
         decoderSnapshotHeaderIncludes = f"""
 #include <memory>
 
-#include "VkSnapshotApiCall.h"
-#include "{self.utilsHeaderDirPrefix}/GfxApiLogger.h"
-#include "{self.baseLibDirPrefix}/HealthMonitor.h"
+#include "VkSnapshotHandles.h"
+#include "gfxstream/HealthMonitor.h"
+#include "gfxstream/host/GfxApiLogger.h"
 #include "goldfish_vk_private_defs.h"
 """
         decoderSnapshotImplIncludes = f"""
@@ -505,20 +523,20 @@ using DlSymFunc = void* (void*, const char*);
 #include "VulkanHandleMapping.h"
 #include "VkDecoderGlobalState.h"
 #include "VkReconstruction.h"
-#include "{self.baseLibDirPrefix}/ThreadAnnotations.h"
+#include "gfxstream/ThreadAnnotations.h"
 """
 
         decoderHeaderIncludes = f"""
 #include "VkDecoderContext.h"
-#include "ProcessResources.h"
+#include "gfxstream/host/ProcessResources.h"
 
 #include <memory>
 
-namespace android {{
+namespace gfxstream {{
 namespace base {{
 class BumpPool;
-}} // namespace android
 }} // namespace base
+}} // namespace gfxstream
 
 """
 
@@ -528,16 +546,13 @@ class BumpPool;
 #include "goldfish_vk_private_defs.h"
 #include "common/goldfish_vk_transform.h"
 
-#include "{self.baseLibDirPrefix}/BumpPool.h"
-#include "{self.baseLibDirPrefix}/system/System.h"
-#include "{self.baseLibDirPrefix}/Metrics.h"
-#include "render-utils/IOStream.h"
+#include "gfxstream/BumpPool.h"
+#include "gfxstream/system/System.h"
+#include "gfxstream/Metrics.h"
 #include "FrameBuffer.h"
 #include "gfxstream/host/Tracing.h"
-#include "host-common/feature_control.h"
-#include "host-common/GfxstreamFatalError.h"
-#include "host-common/logging.h"
-
+#include "gfxstream/host/iostream.h"
+#include "gfxstream/common/logging.h"
 #include "VkDecoderGlobalState.h"
 #include "VkDecoderSnapshot.h"
 
@@ -632,7 +647,7 @@ class BumpPool;
                            extraImpl=commonCerealImplIncludes + reservedMarshalingHostIncludes)
             self.addCppModule("common", "goldfish_vk_deepcopy",
                            extraHeader=poolInclude,
-                           extraImpl=commonCerealImplIncludes + deepcopyInclude)
+                           extraImpl=commonCerealImplIncludes + deepcopyHostInclude)
             self.addCppModule("common", "goldfish_vk_dispatch",
                            extraHeader=dispatchHeaderDefs,
                            extraImpl=dispatchImplIncludes)
@@ -654,7 +669,8 @@ class BumpPool;
                                implOnly=True)
 
             self.addModule(cereal.PyScript(self.host_tag, "vulkan_printer", customAbsDir=Path(
-                self.host_script_destination) / "print_gfx_logs"), moduleName="ApiLogDecoder")
+                self.host_script_destination) / "print_gfx_logs"), moduleName="ApiLogDecoder",
+                extraHeader=coprightHeaderPy)
             self.addHostModule(
                 "vulkan_gfxstream_structure_type", headerOnly=True, suppressFeatureGuards=True,
                 moduleName="vulkan_gfxstream_structure_type_host", useNamespace=False,
@@ -708,10 +724,12 @@ class BumpPool;
             suppressFeatureGuards=suppressFeatureGuards, moduleName=moduleName,
             suppressVulkanHeaders=suppressVulkanHeaders)
 
-    def addModule(self, module, moduleName=None):
+    def addModule(self, module, moduleName=None, extraHeader=None):
         if moduleName is None:
             moduleName = module.basename
         self.moduleList.append(moduleName)
+        if extraHeader:
+            module.preamble = extraHeader
         self.modules[moduleName] = module
 
     def addCppModule(
diff --git a/src/gfxstream/codegen/scripts/genvk.py b/src/gfxstream/codegen/scripts/genvk.py
index b8b24c9aeb6..cda8711b9df 100755
--- a/src/gfxstream/codegen/scripts/genvk.py
+++ b/src/gfxstream/codegen/scripts/genvk.py
@@ -57,6 +57,7 @@ def makeGenOpts(args):
     # The SPDX formatting below works around constraints of the 'reuse' tool
     prefixStrings = [
         '/*',
+        '** Copyright 2025 The Android Open Source Project',
         '** Copyright 2015-2023 The Khronos Group Inc.',
         '**',
         '** SPDX-License-Identifier' + ': Apache-2.0',
diff --git a/src/gfxstream/guest/android/GrallocEmulated.cpp b/src/gfxstream/guest/android/GrallocEmulated.cpp
index 66dadbdfbeb..590dd0ab940 100644
--- a/src/gfxstream/guest/android/GrallocEmulated.cpp
+++ b/src/gfxstream/guest/android/GrallocEmulated.cpp
@@ -443,7 +443,7 @@ int EmulatedGralloc::allocate(uint32_t width, uint32_t height, uint32_t ahbForma
 }
 
 AHardwareBuffer* EmulatedGralloc::allocate(uint32_t width, uint32_t height, uint32_t drmFormat) {
-    mesa_loge("Allocating AHB w:%u, h:%u, format %u", width, height, drmFormat);
+    mesa_logd("Allocating AHB w:%u, h:%u, format %u", width, height, drmFormat);
 
     const auto& formatInfosMap = GetDrmFormatInfoMap();
     auto formatInfoIt = formatInfosMap.find(drmFormat);
diff --git a/src/gfxstream/guest/android/include/gfxstream/guest/GfxStreamGralloc.h b/src/gfxstream/guest/android/include/gfxstream/guest/GfxStreamGralloc.h
index 26d10fb02fb..2dca6618cc8 100644
--- a/src/gfxstream/guest/android/include/gfxstream/guest/GfxStreamGralloc.h
+++ b/src/gfxstream/guest/android/include/gfxstream/guest/GfxStreamGralloc.h
@@ -177,7 +177,7 @@ class Gralloc {
 
     virtual bool treatBlobAsImage() { return false; }
 
-    virtual int32_t getDataspace(const AHardwareBuffer* ahb) {
+    virtual int32_t getDataspace(const AHardwareBuffer* /*ahb*/) {
         return GFXSTREAM_AHB_DATASPACE_UNKNOWN;
     }
 };
diff --git a/src/gfxstream/guest/iostream/include/gfxstream/guest/IOStream.h b/src/gfxstream/guest/iostream/include/gfxstream/guest/IOStream.h
index 05066541609..6749b6e3c30 100644
--- a/src/gfxstream/guest/iostream/include/gfxstream/guest/IOStream.h
+++ b/src/gfxstream/guest/iostream/include/gfxstream/guest/IOStream.h
@@ -39,7 +39,7 @@ public:
         return m_bufsize < len ? len : m_bufsize;
     }
 
-    virtual int connect(const char* serviceName = nullptr) { return 0; }
+    virtual int connect(const char* /*serviceName*/ = nullptr) { return 0; }
     virtual uint64_t processPipeInit() { return 0; }
 
     virtual void *allocBuffer(size_t minSize) = 0;
diff --git a/src/gfxstream/guest/vulkan_enc/HostVisibleMemoryVirtualization.cpp b/src/gfxstream/guest/vulkan_enc/HostVisibleMemoryVirtualization.cpp
index c56489980d7..f6c6bf60b38 100644
--- a/src/gfxstream/guest/vulkan_enc/HostVisibleMemoryVirtualization.cpp
+++ b/src/gfxstream/guest/vulkan_enc/HostVisibleMemoryVirtualization.cpp
@@ -17,45 +17,38 @@ namespace vk {
 CoherentMemory::CoherentMemory(VirtGpuResourceMappingPtr blobMapping, uint64_t size,
                                VkDevice device, VkDeviceMemory memory)
     : mSize(size), mBlobMapping(blobMapping), mDevice(device), mMemory(memory) {
-    mHeap = u_mmInit(0, kHostVisibleHeapSize);
-    mBaseAddr = blobMapping->asRawPtr();
+    mAllocator =
+        std::make_unique<gfxstream::aemu::SubAllocator>(blobMapping->asRawPtr(), mSize, 4096);
 }
 
 #if DETECT_OS_ANDROID
 CoherentMemory::CoherentMemory(GoldfishAddressSpaceBlockPtr block, uint64_t gpuAddr, uint64_t size,
                                VkDevice device, VkDeviceMemory memory)
     : mSize(size), mBlock(block), mDevice(device), mMemory(memory) {
-    mHeap = u_mmInit(0, kHostVisibleHeapSize);
-    mBaseAddr = (uint8_t*)block->mmap(gpuAddr);
+    void* address = block->mmap(gpuAddr);
+    mAllocator = std::make_unique<gfxstream::aemu::SubAllocator>(address, mSize, kLargestPageSize);
 }
 #endif  // DETECT_OS_ANDROID
 
 CoherentMemory::~CoherentMemory() {
     ResourceTracker::getThreadLocalEncoder()->vkFreeMemorySyncGOOGLE(mDevice, mMemory, nullptr,
                                                                      false);
-    u_mmDestroy(mHeap);
 }
 
 VkDeviceMemory CoherentMemory::getDeviceMemory() const { return mMemory; }
 
 bool CoherentMemory::subAllocate(uint64_t size, uint8_t** ptr, uint64_t& offset) {
-    auto block = u_mmAllocMem(mHeap, (int)size, 0, 0);
-    if (!block) return false;
+    auto address = mAllocator->alloc(size);
+    if (!address) return false;
 
-    *ptr = mBaseAddr + block->ofs;
-    offset = block->ofs;
+    *ptr = (uint8_t*)address;
+    offset = mAllocator->getOffset(address);
     return true;
 }
 
 bool CoherentMemory::release(uint8_t* ptr) {
-    int offset = ptr - mBaseAddr;
-    auto block = u_mmFindBlock(mHeap, offset);
-    if (block) {
-        u_mmFreeMem(block);
-        return true;
-    }
-
-    return false;
+    mAllocator->free(ptr);
+    return true;
 }
 
 }  // namespace vk
diff --git a/src/gfxstream/guest/vulkan_enc/HostVisibleMemoryVirtualization.h b/src/gfxstream/guest/vulkan_enc/HostVisibleMemoryVirtualization.h
index f6cf9e95b96..812862fe072 100644
--- a/src/gfxstream/guest/vulkan_enc/HostVisibleMemoryVirtualization.h
+++ b/src/gfxstream/guest/vulkan_enc/HostVisibleMemoryVirtualization.h
@@ -8,7 +8,7 @@
 
 #include "VirtGpu.h"
 #include "goldfish_address_space.h"
-#include "util/u_mm.h"
+#include "SubAllocator.h"
 #include "util/detect_os.h"
 
 constexpr uint64_t kMegaByte = 1048576;
@@ -26,6 +26,7 @@ namespace gfxstream {
 namespace vk {
 
 using GoldfishAddressSpaceBlockPtr = std::shared_ptr<GoldfishAddressSpaceBlock>;
+using SubAllocatorPtr = std::unique_ptr<gfxstream::aemu::SubAllocator>;
 
 class CoherentMemory {
    public:
@@ -53,9 +54,7 @@ class CoherentMemory {
     GoldfishAddressSpaceBlockPtr mBlock;
     VkDevice mDevice;
     VkDeviceMemory mMemory;
-
-    uint8_t* mBaseAddr = nullptr;
-    struct mem_block* mHeap = nullptr;
+    SubAllocatorPtr mAllocator;
 };
 
 using CoherentMemoryPtr = std::shared_ptr<CoherentMemory>;
diff --git a/src/gfxstream/guest/vulkan_enc/ResourceTracker.cpp b/src/gfxstream/guest/vulkan_enc/ResourceTracker.cpp
index 4e0dc43c892..b31f93dced5 100644
--- a/src/gfxstream/guest/vulkan_enc/ResourceTracker.cpp
+++ b/src/gfxstream/guest/vulkan_enc/ResourceTracker.cpp
@@ -14,6 +14,7 @@
 #include "goldfish_address_space.h"
 #include "goldfish_vk_private_defs.h"
 #include "util/anon_file.h"
+#include "util/log.h"
 #include "util/macros.h"
 #include "virtgpu_gfxstream_protocol.h"
 #include "vulkan/vulkan_core.h"
@@ -1058,6 +1059,13 @@ void ResourceTracker::unregister_VkSampler(VkSampler sampler) {
     info_VkSampler.erase(sampler);
 }
 
+void ResourceTracker::unregister_VkPrivateDataSlot(VkPrivateDataSlot privateSlot) {
+    if (!privateSlot) return;
+
+    std::lock_guard<std::recursive_mutex> lock(mLock);
+    info_VkPrivateDataSlot.erase(privateSlot);
+}
+
 void ResourceTracker::unregister_VkCommandBuffer(VkCommandBuffer commandBuffer) {
     resetCommandBufferStagingInfo(commandBuffer, true /* also reset primaries */,
                                   true /* also clear pending descriptor sets */);
@@ -1286,8 +1294,7 @@ void ResourceTracker::transformImpl_VkExternalMemoryProperties_fromhost(
     supportedHandleType |= VK_EXTERNAL_MEMORY_HANDLE_TYPE_ZIRCON_VMO_BIT_FUCHSIA;
 #endif  // VK_USE_PLATFORM_FUCHSIA
 #ifdef VK_USE_PLATFORM_ANDROID_KHR
-    supportedHandleType |= VK_EXTERNAL_MEMORY_HANDLE_TYPE_OPAQUE_FD_BIT |
-                           VK_EXTERNAL_MEMORY_HANDLE_TYPE_ANDROID_HARDWARE_BUFFER_BIT_ANDROID;
+    supportedHandleType |= VK_EXTERNAL_MEMORY_HANDLE_TYPE_ANDROID_HARDWARE_BUFFER_BIT_ANDROID;
 #endif  // VK_USE_PLATFORM_ANDROID_KHR
     if (supportedHandleType) {
         pProperties->compatibleHandleTypes &= supportedHandleType;
@@ -1576,9 +1583,15 @@ void ResourceTracker::deviceMemoryTransform_tohost(VkDeviceMemory* memory, uint3
 
         for (uint32_t i = 0; i < memoryCount; ++i) {
             VkDeviceMemory mem = memory[i];
+            if (!mem) {
+                return;
+            }
 
             auto it = info_VkDeviceMemory.find(mem);
-            if (it == info_VkDeviceMemory.end()) return;
+            if (it == info_VkDeviceMemory.end()) {
+                mesa_logw("%s cannot find memory %p!", __func__, mem);
+                return;
+            }
 
             const auto& info = it->second;
 
@@ -1593,11 +1606,6 @@ void ResourceTracker::deviceMemoryTransform_tohost(VkDeviceMemory* memory, uint3
             if (size && size[i] == VK_WHOLE_SIZE) {
                 size[i] = info.allocationSize;
             }
-
-            // TODO
-            (void)memory;
-            (void)offset;
-            (void)size;
         }
     }
 }
@@ -1750,11 +1758,7 @@ VkResult ResourceTracker::on_vkEnumerateDeviceExtensionProperties(
         "VK_KHR_get_memory_requirements2",
         "VK_KHR_sampler_ycbcr_conversion",
         "VK_KHR_shader_float16_int8",
-    // Timeline semaphores buggy in newer NVIDIA drivers
-    // (vkWaitSemaphoresKHR causes further vkCommandBuffer dispatches to deadlock)
-#ifndef VK_USE_PLATFORM_ANDROID_KHR
         "VK_KHR_timeline_semaphore",
-#endif
         "VK_AMD_gpu_shader_half_float",
         "VK_NV_shader_subgroup_partitioned",
         "VK_KHR_shader_subgroup_extended_types",
@@ -1785,20 +1789,71 @@ VkResult ResourceTracker::on_vkEnumerateDeviceExtensionProperties(
 #if defined(VK_USE_PLATFORM_ANDROID_KHR) || DETECT_OS_LINUX
         "VK_KHR_external_semaphore",
         "VK_KHR_external_semaphore_fd",
-        // "VK_KHR_external_semaphore_win32", not exposed because it's translated to fd
         "VK_KHR_external_memory",
         "VK_KHR_external_fence",
         "VK_KHR_external_fence_fd",
         "VK_EXT_device_memory_report",
 #endif
 #if DETECT_OS_LINUX && !defined(VK_USE_PLATFORM_ANDROID_KHR)
-        "VK_KHR_imageless_framebuffer",
+        "VK_KHR_external_memory_fd",
 #endif
         "VK_KHR_multiview",
+        "VK_EXT_color_write_enable",
+
+        // Vulkan 1.1
+        // "VK_KHR_16bit_storage",
+        "VK_KHR_device_group",
+        "VK_KHR_device_group_creation",
+        "VK_KHR_external_fence_capabilities",
+        "VK_KHR_external_memory_capabilities",
+        "VK_KHR_external_semaphore_capabilities",
+        "VK_KHR_get_physical_device_properties2",
+        "VK_KHR_relaxed_block_layout",
+        "VK_KHR_shader_draw_parameters",
+        "VK_KHR_storage_buffer_storage_class",
+        "VK_KHR_variable_pointers",
+
+        // Vulkan 1.2
+        "VK_KHR_8bit_storage",
+        "VK_KHR_depth_stencil_resolve",
+        "VK_KHR_draw_indirect_count",
+        "VK_KHR_driver_properties",
+        "VK_KHR_imageless_framebuffer",
+        "VK_KHR_sampler_mirror_clamp_to_edge",
+        "VK_KHR_separate_depth_stencil_layouts",
+        "VK_KHR_shader_atomic_int64",
+        "VK_KHR_shader_float16_int8",
+        "VK_KHR_shader_float_controls",
+        "VK_KHR_spirv_1_4",
+        "VK_KHR_uniform_buffer_standard_layout",
+        "VK_EXT_descriptor_indexing",
+        "VK_EXT_sampler_filter_minmax",
+        "VK_EXT_scalar_block_layout",
+        "VK_EXT_separate_stencil_usage",
+        "VK_EXT_shader_viewport_index_layer",
+
+
         // Vulkan 1.3
         "VK_KHR_synchronization2",
         "VK_EXT_private_data",
-        "VK_EXT_color_write_enable",
+        "VK_KHR_dynamic_rendering",
+        "VK_KHR_copy_commands2",
+        "VK_KHR_format_feature_flags2",
+        "VK_KHR_maintenance4",
+        "VK_KHR_shader_integer_dot_product",
+        "VK_KHR_shader_non_semantic_info",
+        "VK_KHR_zero_initialize_workgroup_memory",
+        "VK_EXT_4444_formats",
+        "VK_EXT_extended_dynamic_state",
+        "VK_EXT_extended_dynamic_state2",
+        "VK_EXT_inline_uniform_block",
+        "VK_EXT_pipeline_creation_cache_control",
+        "VK_EXT_pipeline_creation_feedback",
+        "VK_EXT_shader_demote_to_helper_invocation",
+        "VK_EXT_texel_buffer_alignment",
+        "VK_EXT_texture_compression_astc_hdr",
+        "VK_EXT_tooling_info",
+        "VK_EXT_ycbcr_2plane_444_formats",
     };
 
     VkEncoder* enc = (VkEncoder*)context;
@@ -4431,6 +4486,7 @@ VkResult ResourceTracker::on_vkCreateImage(void* context, VkResult, VkDevice dev
         info.hasExternalFormat = true;
         info.externalFourccFormat = extFormatAndroidPtr->externalFormat;
     }
+    info.hasAnb = (anbInfoPtr != nullptr);
 #endif  // VK_USE_PLATFORM_ANDROID_KHR
 
     if (supportsCreateResourcesWithRequirements()) {
@@ -4601,8 +4657,8 @@ VkResult ResourceTracker::on_vkCreateSampler(void* context, VkResult, VkDevice d
                                              VkSampler* pSampler) {
     VkSamplerCreateInfo localCreateInfo = vk_make_orphan_copy(*pCreateInfo);
 
-#if defined(VK_USE_PLATFORM_ANDROID_KHR) || defined(VK_USE_PLATFORM_FUCHSIA)
     vk_struct_chain_iterator structChainIter = vk_make_chain_iterator(&localCreateInfo);
+#if defined(VK_USE_PLATFORM_ANDROID_KHR) || defined(VK_USE_PLATFORM_FUCHSIA)
     VkSamplerYcbcrConversionInfo localVkSamplerYcbcrConversionInfo;
     const VkSamplerYcbcrConversionInfo* samplerYcbcrConversionInfo =
         vk_find_struct_const(pCreateInfo, SAMPLER_YCBCR_CONVERSION_INFO);
@@ -4623,6 +4679,15 @@ VkResult ResourceTracker::on_vkCreateSampler(void* context, VkResult, VkDevice d
     }
 #endif
 
+    VkSamplerReductionModeCreateInfo localVkSamplerReductionModeCreateInfo;
+    const VkSamplerReductionModeCreateInfo* samplerReductionModeCreateInfo =
+        vk_find_struct_const(pCreateInfo, SAMPLER_REDUCTION_MODE_CREATE_INFO);
+    if (samplerReductionModeCreateInfo) {
+        localVkSamplerReductionModeCreateInfo =
+            vk_make_orphan_copy(*samplerReductionModeCreateInfo);
+        vk_append_struct(&structChainIter, &localVkSamplerReductionModeCreateInfo);
+    }
+
     VkEncoder* enc = (VkEncoder*)context;
     return enc->vkCreateSampler(device, &localCreateInfo, pAllocator, pSampler, true /* do lock */);
 }
@@ -4985,6 +5050,91 @@ VkResult ResourceTracker::on_vkWaitForFences(void* context, VkResult, VkDevice d
 #endif
 }
 
+VkResult ResourceTracker::on_vkSetPrivateData(void* context, VkResult input_result, VkDevice device,
+                                              VkObjectType objectType, uint64_t objectHandle,
+                                              VkPrivateDataSlot privateDataSlot, uint64_t data) {
+    if (input_result != VK_SUCCESS) return input_result;
+
+    VkPrivateDataSlot_Info::PrivateDataKey key = std::make_pair(objectHandle, objectType);
+
+    std::lock_guard<std::recursive_mutex> lock(mLock);
+    auto it = info_VkPrivateDataSlot.find(privateDataSlot);
+
+    // Do not forward calls with invalid handles to host.
+    if (it == info_VkPrivateDataSlot.end()) {
+        return VK_ERROR_OUT_OF_HOST_MEMORY;
+    }
+
+    auto& slotInfoTable = it->second.privateDataTable;
+    slotInfoTable[key] = data;
+    return VK_SUCCESS;
+}
+
+VkResult ResourceTracker::on_vkSetPrivateDataEXT(void* context, VkResult input_result,
+                                                 VkDevice device, VkObjectType objectType,
+                                                 uint64_t objectHandle,
+                                                 VkPrivateDataSlot privateDataSlot, uint64_t data) {
+    return on_vkSetPrivateData(context, input_result, device, objectType, objectHandle,
+                               privateDataSlot, data);
+}
+
+void ResourceTracker::on_vkGetPrivateData(void* context, VkDevice device, VkObjectType objectType,
+                                          uint64_t objectHandle, VkPrivateDataSlot privateDataSlot,
+                                          uint64_t* pData) {
+    VkPrivateDataSlot_Info::PrivateDataKey key = std::make_pair(objectHandle, objectType);
+
+    std::lock_guard<std::recursive_mutex> lock(mLock);
+    auto it = info_VkPrivateDataSlot.find(privateDataSlot);
+
+    // Do not forward calls with invalid handles to host.
+    if (it == info_VkPrivateDataSlot.end()) {
+        return;
+    }
+
+    auto& slotInfoTable = it->second.privateDataTable;
+    *pData = slotInfoTable[key];
+}
+
+void ResourceTracker::on_vkGetPrivateDataEXT(void* context, VkDevice device,
+                                             VkObjectType objectType, uint64_t objectHandle,
+                                             VkPrivateDataSlot privateDataSlot, uint64_t* pData) {
+    return on_vkGetPrivateData(context, device, objectType, objectHandle, privateDataSlot, pData);
+}
+
+VkResult ResourceTracker::on_vkCreatePrivateDataSlot(void* context, VkResult input_result,
+                                                     VkDevice device,
+                                                     const VkPrivateDataSlotCreateInfo* pCreateInfo,
+                                                     const VkAllocationCallbacks* pAllocator,
+                                                     VkPrivateDataSlot* pPrivateDataSlot) {
+    if (input_result != VK_SUCCESS) {
+        return input_result;
+    }
+    VkEncoder* enc = (VkEncoder*)context;
+    return enc->vkCreatePrivateDataSlot(device, pCreateInfo, pAllocator, pPrivateDataSlot,
+                                        true /* do lock */);
+}
+VkResult ResourceTracker::on_vkCreatePrivateDataSlotEXT(
+    void* context, VkResult input_result, VkDevice device,
+    const VkPrivateDataSlotCreateInfo* pCreateInfo, const VkAllocationCallbacks* pAllocator,
+    VkPrivateDataSlot* pPrivateDataSlot) {
+    return on_vkCreatePrivateDataSlot(context, input_result, device, pCreateInfo, pAllocator,
+                                      pPrivateDataSlot);
+}
+
+void ResourceTracker::on_vkDestroyPrivateDataSlot(void* context, VkDevice device,
+                                                  VkPrivateDataSlot privateDataSlot,
+                                                  const VkAllocationCallbacks* pAllocator) {
+    if (!privateDataSlot) return;
+
+    VkEncoder* enc = (VkEncoder*)context;
+    enc->vkDestroyPrivateDataSlot(device, privateDataSlot, pAllocator, true /* do lock */);
+}
+void ResourceTracker::on_vkDestroyPrivateDataSlotEXT(void* context, VkDevice device,
+                                                     VkPrivateDataSlot privateDataSlot,
+                                                     const VkAllocationCallbacks* pAllocator) {
+    return on_vkDestroyPrivateDataSlot(context, device, privateDataSlot, pAllocator);
+}
+
 VkResult ResourceTracker::on_vkCreateDescriptorPool(void* context, VkResult, VkDevice device,
                                                     const VkDescriptorPoolCreateInfo* pCreateInfo,
                                                     const VkAllocationCallbacks* pAllocator,
@@ -6721,8 +6871,7 @@ VkResult ResourceTracker::on_vkGetPhysicalDeviceImageFormatProperties2_common(
 
 #ifdef VK_USE_PLATFORM_ANDROID_KHR
     VkAndroidHardwareBufferUsageANDROID* output_ahw_usage = vk_find_struct(pImageFormatProperties, ANDROID_HARDWARE_BUFFER_USAGE_ANDROID);
-    supportedHandleType |= VK_EXTERNAL_MEMORY_HANDLE_TYPE_OPAQUE_FD_BIT |
-                           VK_EXTERNAL_MEMORY_HANDLE_TYPE_ANDROID_HARDWARE_BUFFER_BIT_ANDROID;
+    supportedHandleType |= VK_EXTERNAL_MEMORY_HANDLE_TYPE_ANDROID_HARDWARE_BUFFER_BIT_ANDROID;
 #endif
     const VkPhysicalDeviceExternalImageFormatInfo* ext_img_info =
         vk_find_struct_const(pImageFormatInfo, PHYSICAL_DEVICE_EXTERNAL_IMAGE_FORMAT_INFO);
@@ -6863,8 +7012,7 @@ void ResourceTracker::on_vkGetPhysicalDeviceExternalBufferProperties_common(
     supportedHandleType |= VK_EXTERNAL_MEMORY_HANDLE_TYPE_ZIRCON_VMO_BIT_FUCHSIA;
 #endif
 #ifdef VK_USE_PLATFORM_ANDROID_KHR
-    supportedHandleType |= VK_EXTERNAL_MEMORY_HANDLE_TYPE_OPAQUE_FD_BIT |
-                           VK_EXTERNAL_MEMORY_HANDLE_TYPE_ANDROID_HARDWARE_BUFFER_BIT_ANDROID;
+    supportedHandleType |= VK_EXTERNAL_MEMORY_HANDLE_TYPE_ANDROID_HARDWARE_BUFFER_BIT_ANDROID;
 #endif
     if (supportedHandleType) {
         // 0 is a valid handleType so we can't check against 0
@@ -7220,6 +7368,41 @@ void ResourceTracker::on_vkCmdPipelineBarrier(
                               updatedImageMemoryBarriers.data(), true /* do lock */);
 }
 
+void ResourceTracker::on_vkCmdClearColorImage(void* context, VkCommandBuffer commandBuffer, VkImage image,
+                             VkImageLayout imageLayout, const VkClearColorValue* pColor,
+                             uint32_t rangeCount, const VkImageSubresourceRange* pRanges) {
+    VkEncoder* enc = (VkEncoder*)context;
+    if (!pColor) {
+        mesa_loge("%s: Null VkClearColorValue requested", __func__);
+        return;
+    }
+    auto imageInfoIt = info_VkImage.find(image);
+    if (imageInfoIt == info_VkImage.end()) {
+        mesa_loge("%s: Failed to find image required for vkCmdClearColorImage", __func__);
+        return;
+    }
+
+    auto& imageInfo = imageInfoIt->second;
+    VkFormat actualFormat = imageInfo.createInfo.format;
+    VkClearColorValue convertedColor = *pColor;
+
+#ifdef VK_USE_PLATFORM_ANDROID_KHR
+    // Color buffer image on the host will be created with UNORM format to ensure
+    // it'll have the identical parameters, so we need to convert the linearized
+    // clear color back to sRGB at this point.
+    // TODO(b/420857458): revise the allocation logic to support mutable formats better
+    if (imageInfo.hasAnb && srgbFormatNeedsConversionForClearColor(actualFormat)) {
+       // Perform linear to srgb conversion
+       // Backing image is UNORM for vkCmdClearColorImage so we convert pColor
+       convertedColor.float32[0] = linearChannelToSRGB(convertedColor.float32[0]);
+       convertedColor.float32[1] = linearChannelToSRGB(convertedColor.float32[1]);
+       convertedColor.float32[2] = linearChannelToSRGB(convertedColor.float32[2]);
+    }
+#endif
+    enc->vkCmdClearColorImage(commandBuffer, image, imageLayout, &convertedColor, rangeCount, pRanges, true);
+    return;
+}
+
 void ResourceTracker::on_vkDestroyDescriptorSetLayout(void* context, VkDevice device,
                                                       VkDescriptorSetLayout descriptorSetLayout,
                                                       const VkAllocationCallbacks* pAllocator) {
diff --git a/src/gfxstream/guest/vulkan_enc/ResourceTracker.h b/src/gfxstream/guest/vulkan_enc/ResourceTracker.h
index 1462a7bf02f..32220d7034d 100644
--- a/src/gfxstream/guest/vulkan_enc/ResourceTracker.h
+++ b/src/gfxstream/guest/vulkan_enc/ResourceTracker.h
@@ -24,6 +24,7 @@
 #include "goldfish_vk_transform_guest.h"
 #include "util/perf/cpu_trace.h"
 #include "util/detect_os.h"
+#include "vulkan/vulkan_core.h"
 
 /// Use installed headers or locally defined Fuchsia-specific bits
 #ifdef VK_USE_PLATFORM_FUCHSIA
@@ -385,6 +386,35 @@ class ResourceTracker {
                                 uint32_t fenceCount, const VkFence* pFences, VkBool32 waitAll,
                                 uint64_t timeout);
 
+    VkResult on_vkSetPrivateData(void* context, VkResult input_result, VkDevice device,
+                                 VkObjectType objectType, uint64_t objectHandle,
+                                 VkPrivateDataSlot privateDataSlot, uint64_t data);
+    VkResult on_vkSetPrivateDataEXT(void* context, VkResult input_result, VkDevice device,
+                                    VkObjectType objectType, uint64_t objectHandle,
+                                    VkPrivateDataSlot privateDataSlot, uint64_t data);
+
+    void on_vkGetPrivateData(void* context, VkDevice device, VkObjectType objectType,
+                             uint64_t objectHandle, VkPrivateDataSlot privateDataSlot,
+                             uint64_t* pData);
+    void on_vkGetPrivateDataEXT(void* context, VkDevice device, VkObjectType objectType,
+                                uint64_t objectHandle, VkPrivateDataSlot privateDataSlot,
+                                uint64_t* pData);
+
+    VkResult on_vkCreatePrivateDataSlot(void* context, VkResult input_result, VkDevice device,
+                                        const VkPrivateDataSlotCreateInfo* pCreateInfo,
+                                        const VkAllocationCallbacks* pAllocator,
+                                        VkPrivateDataSlot* pPrivateDataSlot);
+    VkResult on_vkCreatePrivateDataSlotEXT(void* context, VkResult input_result, VkDevice device,
+                                           const VkPrivateDataSlotCreateInfo* pCreateInfo,
+                                           const VkAllocationCallbacks* pAllocator,
+                                           VkPrivateDataSlot* pPrivateDataSlot);
+    void on_vkDestroyPrivateDataSlot(void* context, VkDevice device,
+                                     VkPrivateDataSlot privateDataSlot,
+                                     const VkAllocationCallbacks* pAllocator);
+    void on_vkDestroyPrivateDataSlotEXT(void* context, VkDevice device,
+                                        VkPrivateDataSlot privateDataSlot,
+                                        const VkAllocationCallbacks* pAllocator);
+
     VkResult on_vkCreateDescriptorPool(void* context, VkResult input_result, VkDevice device,
                                        const VkDescriptorPoolCreateInfo* pCreateInfo,
                                        const VkAllocationCallbacks* pAllocator,
@@ -515,6 +545,10 @@ class ResourceTracker {
         uint32_t bufferMemoryBarrierCount, const VkBufferMemoryBarrier* pBufferMemoryBarriers,
         uint32_t imageMemoryBarrierCount, const VkImageMemoryBarrier* pImageMemoryBarriers);
 
+    void on_vkCmdClearColorImage(void* context, VkCommandBuffer commandBuffer, VkImage image,
+                                 VkImageLayout imageLayout, const VkClearColorValue* pColor,
+                                 uint32_t rangeCount, const VkImageSubresourceRange* pRanges);
+
     void on_vkDestroyDescriptorSetLayout(void* context, VkDevice device,
                                          VkDescriptorSetLayout descriptorSetLayout,
                                          const VkAllocationCallbacks* pAllocator);
@@ -789,6 +823,7 @@ class ResourceTracker {
         bool hasExternalFormat = false;
         unsigned externalFourccFormat = 0;
         std::vector<int> pendingQsriSyncFds;
+        bool hasAnb = false;
 #endif
 #ifdef VK_USE_PLATFORM_FUCHSIA
         bool isSysmemBackedMemory = false;
@@ -869,6 +904,28 @@ class ResourceTracker {
         uint32_t unused;
     };
 
+    struct VkPrivateDataSlot_Info {
+        // We need special handling for device memory and swapchain object types for private data
+        // management. For memory, we can use a single handle on the host side, so setting a
+        // private data slot for guest handle can also set any other data set previously.
+        // For swapchains, we don't actually get create/destroy calls to keep track of object
+        // handles to be able to pass the call to the underlying host driver. Rather than handling
+        // the 2 cases separately, we handle all the private data management directly here with a
+        // single table, so vkSetPrivateData and vkGetPrivateData calls don't need to be encoded for
+        // the host.
+        typedef std::pair<uint64_t, VkObjectType> PrivateDataKey;
+        struct PrivateDataKeyHash {
+            template <class T1, class T2>
+            std::size_t operator()(const std::pair<T1, T2>& p) const {
+                std::size_t h1 = std::hash<T1>{}(p.first);
+                std::size_t h2 = std::hash<T2>{}(p.second);
+                return h1 ^ h2;
+            }
+        };
+
+        std::unordered_map<PrivateDataKey, uint64_t, PrivateDataKeyHash> privateDataTable;
+    };
+
     struct VkBufferCollectionFUCHSIA_Info {
 #ifdef VK_USE_PLATFORM_FUCHSIA
         std::optional<fuchsia_sysmem::wire::BufferCollectionConstraints> constraints;
diff --git a/src/gfxstream/guest/vulkan_enc/VulkanHandles.h b/src/gfxstream/guest/vulkan_enc/VulkanHandles.h
index 1400b9c5092..248073fbd11 100644
--- a/src/gfxstream/guest/vulkan_enc/VulkanHandles.h
+++ b/src/gfxstream/guest/vulkan_enc/VulkanHandles.h
@@ -104,7 +104,6 @@ namespace vk {
     f(VkValidationCacheEXT)                                                           \
     f(VkDebugReportCallbackEXT)                                                       \
     f(VkDebugUtilsMessengerEXT)                                                       \
-    f(VkPrivateDataSlot)                                                              \
     f(VkMicromapEXT)                                                                  \
     __GOLDFISH_VK_LIST_NON_DISPATCHABLE_HANDLE_TYPES_NVX_BINARY_IMPORT(f)             \
     __GOLDFISH_VK_LIST_NON_DISPATCHABLE_HANDLE_TYPES_NVX_DEVICE_GENERATED_COMMANDS(f) \
@@ -124,6 +123,7 @@ namespace vk {
     f(VkDescriptorSetLayout)                                    \
     f(VkCommandPool)                                            \
     f(VkSampler)                                                \
+    f(VkPrivateDataSlot)                                        \
     __GOLDFISH_VK_LIST_NON_DISPATCHABLE_HANDLE_TYPES_FUCHSIA(f) \
     GOLDFISH_VK_LIST_TRIVIAL_NON_DISPATCHABLE_HANDLE_TYPES(f)
 
@@ -150,6 +150,7 @@ namespace vk {
     f(VkDescriptorUpdateTemplate)                                            \
     f(VkCommandPool)                                                         \
     f(VkSampler)                                                             \
+    f(VkPrivateDataSlot)                                                     \
     __GOLDFISH_VK_LIST_NON_DISPATCHABLE_HANDLE_TYPES_FUCHSIA(f)              \
     GOLDFISH_VK_LIST_TRIVIAL_NON_DISPATCHABLE_HANDLE_TYPES(f)
 
diff --git a/src/gfxstream/guest/vulkan_enc/func_table.cpp b/src/gfxstream/guest/vulkan_enc/func_table.cpp
index 9e779120467..89585e064ba 100644
--- a/src/gfxstream/guest/vulkan_enc/func_table.cpp
+++ b/src/gfxstream/guest/vulkan_enc/func_table.cpp
@@ -1486,8 +1486,9 @@ void gfxstream_vk_CmdClearColorImage(VkCommandBuffer commandBuffer, VkImage imag
     {
         auto vkEnc = gfxstream::vk::ResourceTracker::getCommandBufferEncoder(
             gfxstream_commandBuffer->internal_object);
-        vkEnc->vkCmdClearColorImage(gfxstream_commandBuffer->internal_object, image, imageLayout,
-                                    pColor, rangeCount, pRanges, true /* do lock */);
+        auto resources = gfxstream::vk::ResourceTracker::get();
+        resources->on_vkCmdClearColorImage(vkEnc, gfxstream_commandBuffer->internal_object, image,
+                                           imageLayout, pColor, rangeCount, pRanges);
     }
 }
 void gfxstream_vk_CmdClearDepthStencilImage(VkCommandBuffer commandBuffer, VkImage image,
@@ -2278,9 +2279,10 @@ VkResult gfxstream_vk_CreatePrivateDataSlot(VkDevice device,
     VK_FROM_HANDLE(gfxstream_vk_device, gfxstream_device, device);
     {
         auto vkEnc = gfxstream::vk::ResourceTracker::getThreadLocalEncoder();
-        vkCreatePrivateDataSlot_VkResult_return =
-            vkEnc->vkCreatePrivateDataSlot(gfxstream_device->internal_object, pCreateInfo,
-                                           pAllocator, pPrivateDataSlot, true /* do lock */);
+        auto resources = gfxstream::vk::ResourceTracker::get();
+        vkCreatePrivateDataSlot_VkResult_return = resources->on_vkCreatePrivateDataSlot(
+            vkEnc, VK_SUCCESS, gfxstream_device->internal_object, pCreateInfo, pAllocator,
+            pPrivateDataSlot);
     }
     return vkCreatePrivateDataSlot_VkResult_return;
 }
@@ -2293,8 +2295,9 @@ void gfxstream_vk_DestroyPrivateDataSlot(VkDevice device, VkPrivateDataSlot priv
     VK_FROM_HANDLE(gfxstream_vk_device, gfxstream_device, device);
     {
         auto vkEnc = gfxstream::vk::ResourceTracker::getThreadLocalEncoder();
-        vkEnc->vkDestroyPrivateDataSlot(gfxstream_device->internal_object, privateDataSlot,
-                                        pAllocator, true /* do lock */);
+        auto resources = gfxstream::vk::ResourceTracker::get();
+        resources->on_vkDestroyPrivateDataSlot(vkEnc, gfxstream_device->internal_object,
+                                               privateDataSlot, pAllocator);
     }
 }
 VkResult gfxstream_vk_SetPrivateData(VkDevice device, VkObjectType objectType,
@@ -2305,9 +2308,10 @@ VkResult gfxstream_vk_SetPrivateData(VkDevice device, VkObjectType objectType,
     VK_FROM_HANDLE(gfxstream_vk_device, gfxstream_device, device);
     {
         auto vkEnc = gfxstream::vk::ResourceTracker::getThreadLocalEncoder();
+        auto resources = gfxstream::vk::ResourceTracker::get();
         vkSetPrivateData_VkResult_return =
-            vkEnc->vkSetPrivateData(gfxstream_device->internal_object, objectType, objectHandle,
-                                    privateDataSlot, data, true /* do lock */);
+            resources->on_vkSetPrivateData(vkEnc, VK_SUCCESS, gfxstream_device->internal_object,
+                                           objectType, objectHandle, privateDataSlot, data);
     }
     return vkSetPrivateData_VkResult_return;
 }
@@ -2317,8 +2321,9 @@ void gfxstream_vk_GetPrivateData(VkDevice device, VkObjectType objectType, uint6
     VK_FROM_HANDLE(gfxstream_vk_device, gfxstream_device, device);
     {
         auto vkEnc = gfxstream::vk::ResourceTracker::getThreadLocalEncoder();
-        vkEnc->vkGetPrivateData(gfxstream_device->internal_object, objectType, objectHandle,
-                                privateDataSlot, pData, true /* do lock */);
+        auto resources = gfxstream::vk::ResourceTracker::get();
+        resources->on_vkGetPrivateData(vkEnc, gfxstream_device->internal_object, objectType,
+                                       objectHandle, privateDataSlot, pData);
     }
 }
 void gfxstream_vk_CmdSetEvent2(VkCommandBuffer commandBuffer, VkEvent event,
@@ -4578,9 +4583,10 @@ VkResult gfxstream_vk_CreatePrivateDataSlotEXT(VkDevice device,
     VK_FROM_HANDLE(gfxstream_vk_device, gfxstream_device, device);
     {
         auto vkEnc = gfxstream::vk::ResourceTracker::getThreadLocalEncoder();
-        vkCreatePrivateDataSlotEXT_VkResult_return =
-            vkEnc->vkCreatePrivateDataSlotEXT(gfxstream_device->internal_object, pCreateInfo,
-                                              pAllocator, pPrivateDataSlot, true /* do lock */);
+        auto resources = gfxstream::vk::ResourceTracker::get();
+        vkCreatePrivateDataSlotEXT_VkResult_return = resources->on_vkCreatePrivateDataSlotEXT(
+            vkEnc, VK_SUCCESS, gfxstream_device->internal_object, pCreateInfo, pAllocator,
+            pPrivateDataSlot);
     }
     return vkCreatePrivateDataSlotEXT_VkResult_return;
 }
@@ -4590,8 +4596,9 @@ void gfxstream_vk_DestroyPrivateDataSlotEXT(VkDevice device, VkPrivateDataSlot p
     VK_FROM_HANDLE(gfxstream_vk_device, gfxstream_device, device);
     {
         auto vkEnc = gfxstream::vk::ResourceTracker::getThreadLocalEncoder();
-        vkEnc->vkDestroyPrivateDataSlotEXT(gfxstream_device->internal_object, privateDataSlot,
-                                           pAllocator, true /* do lock */);
+        auto resources = gfxstream::vk::ResourceTracker::get();
+        resources->on_vkDestroyPrivateDataSlotEXT(vkEnc, gfxstream_device->internal_object,
+                                                  privateDataSlot, pAllocator);
     }
 }
 VkResult gfxstream_vk_SetPrivateDataEXT(VkDevice device, VkObjectType objectType,
diff --git a/src/gfxstream/guest/vulkan_enc/gfxstream_vk_private.cpp b/src/gfxstream/guest/vulkan_enc/gfxstream_vk_private.cpp
index d1e0c8349b2..13078eba335 100644
--- a/src/gfxstream/guest/vulkan_enc/gfxstream_vk_private.cpp
+++ b/src/gfxstream/guest/vulkan_enc/gfxstream_vk_private.cpp
@@ -6,6 +6,7 @@
 #include "gfxstream_vk_private.h"
 
 #include "vk_sync_dummy.h"
+#include "vulkan/vulkan_core.h"
 
 /* Under the assumption that Mesa VK runtime queue submission is used, WSI flow
  * sets this temporary state to a dummy sync type (when no explicit dma-buf
@@ -58,3 +59,19 @@ std::vector<VkSemaphoreSubmitInfo> transformVkSemaphoreSubmitInfoList(
     }
     return outSemaphoreSubmitInfo;
 }
+
+float linearChannelToSRGB(float cl)
+{
+    if (cl <= 0.0f)
+        return 0.0f;
+    else if (cl < 0.0031308f)
+        return 12.92f * cl;
+    else if (cl < 1.0f)
+        return 1.055f * pow(cl, 0.41666f) - 0.055f;
+    else
+        return 1.0f;
+}
+
+float srgbFormatNeedsConversionForClearColor(const VkFormat& format) {
+    return format == VK_FORMAT_R8G8B8A8_SRGB;
+}
\ No newline at end of file
diff --git a/src/gfxstream/guest/vulkan_enc/gfxstream_vk_private.h b/src/gfxstream/guest/vulkan_enc/gfxstream_vk_private.h
index 164c227d6fb..e20e2a50d73 100644
--- a/src/gfxstream/guest/vulkan_enc/gfxstream_vk_private.h
+++ b/src/gfxstream/guest/vulkan_enc/gfxstream_vk_private.h
@@ -140,4 +140,7 @@ std::vector<VkFence> transformVkFenceList(const VkFence* pFences, uint32_t fence
 std::vector<VkSemaphoreSubmitInfo> transformVkSemaphoreSubmitInfoList(
     const VkSemaphoreSubmitInfo* pSemaphoreSubmitInfos, uint32_t semaphoreSubmitInfoCount);
 
+float linearChannelToSRGB(float cl);
+float srgbFormatNeedsConversionForClearColor(const VkFormat& format);
+
 #endif /* GFXSTREAM_VK_PRIVATE_H */
diff --git a/src/gfxstream/guest/vulkan_enc/vulkan_gfxstream.h b/src/gfxstream/guest/vulkan_enc/vulkan_gfxstream.h
index 9cf4fe00707..82a90d458e8 100644
--- a/src/gfxstream/guest/vulkan_enc/vulkan_gfxstream.h
+++ b/src/gfxstream/guest/vulkan_enc/vulkan_gfxstream.h
@@ -1,4 +1,5 @@
 /*
+** Copyright 2025 The Android Open Source Project
 ** Copyright 2015-2023 The Khronos Group Inc.
 **
 ** SPDX-License-Identifier: Apache-2.0
```

