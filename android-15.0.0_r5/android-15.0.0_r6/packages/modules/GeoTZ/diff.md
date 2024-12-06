```diff
diff --git a/apex/com.android.geotz/Android.bp b/apex/com.android.geotz/Android.bp
index 2f85269..3ae6655 100644
--- a/apex/com.android.geotz/Android.bp
+++ b/apex/com.android.geotz/Android.bp
@@ -20,7 +20,6 @@ package {
 apex_defaults {
     name: "com.android.geotz-defaults",
     updatable: true,
-    generate_hashtree: false,
     min_sdk_version: "31",
 
     // Explicit because the defaulting behavior only works for the real
diff --git a/s2storage/src/readonly/java/com/android/storage/block/read/Block.java b/s2storage/src/readonly/java/com/android/storage/block/read/Block.java
index 930785d..c931099 100644
--- a/s2storage/src/readonly/java/com/android/storage/block/read/Block.java
+++ b/s2storage/src/readonly/java/com/android/storage/block/read/Block.java
@@ -18,7 +18,6 @@ package com.android.storage.block.read;
 
 import com.android.storage.util.Visitor;
 
-import java.nio.ByteBuffer;
 import java.util.Objects;
 
 /**
@@ -32,11 +31,11 @@ public final class Block {
 
     private final BlockData mBlockData;
 
-    /** Creates a Block. The {@link ByteBuffer} must be read-only and is not copied. */
-    public Block(int id, int type, ByteBuffer dataBytes) {
+    /** Creates a Block. */
+    public Block(int id, int type, BlockData blockData) {
         mId = id;
         mType = type;
-        mBlockData = new BlockData(Objects.requireNonNull(dataBytes));
+        mBlockData = Objects.requireNonNull(blockData);
     }
 
     /** Returns the ID for this block. */
diff --git a/s2storage/src/readonly/java/com/android/storage/block/read/BlockData.java b/s2storage/src/readonly/java/com/android/storage/block/read/BlockData.java
index 4fe5bc4..c1eafaa 100644
--- a/s2storage/src/readonly/java/com/android/storage/block/read/BlockData.java
+++ b/s2storage/src/readonly/java/com/android/storage/block/read/BlockData.java
@@ -26,10 +26,9 @@ import java.util.Objects;
 /**
  * Provides typed, absolute position, random access to a block's data.
  *
- * <p>See also {@link TypedInputStream} for a streamed
- * equivalent.
+ * <p>See also {@link TypedInputStream} for a streamed equivalent.
  */
-public final class BlockData {
+public final class BlockData implements TypedData {
 
     private final ByteBuffer mDataBytes;
 
@@ -46,55 +45,82 @@ public final class BlockData {
 
     /** Returns a copy of the underlying {@link ByteBuffer}. */
     public ByteBuffer getByteBuffer() {
-        return mDataBytes.duplicate();
+        ByteBuffer buffer = mDataBytes.duplicate();
+
+        // mDataBytes shouldn't have a position set, but make sure the duplicate doesn't anyway.
+        buffer.position(0);
+
+        return buffer;
+    }
+
+    @Override
+    public TypedData slice(int startPos, int length) {
+        // None of this code is thread safe, but this is especially not thread safe because
+        // it uses position / limit as part of the slicing, so synchronize.
+        int newLimit = startPos + length;
+
+        synchronized (mDataBytes) {
+            // mDataBytes shouldn't have a position or mark, but preserve and reset them
+            // again afterwards just in case.
+            int oldPosition = mDataBytes.position();
+            int oldLimit = mDataBytes.limit();
+
+            // Avoid creating a new slice that could fail when accessed, e.g. because its limit
+            // is outside of the original buffer.
+            if (newLimit > oldLimit) {
+                throw new IllegalArgumentException(
+                        "startPos(" + startPos + ") + length(" + length + ") > size()");
+            }
+
+            mDataBytes.position(startPos);
+            mDataBytes.limit(newLimit);
+            ByteBuffer sliceByteBuffer = mDataBytes.slice();
+
+            mDataBytes.limit(oldLimit);
+            mDataBytes.position(oldPosition);
+
+            return new BlockData(sliceByteBuffer);
+        }
     }
 
-    /** Returns the value of the byte at the specified position. */
+    @Override
     public byte getByte(int byteOffset) {
         return mDataBytes.get(byteOffset);
     }
 
-    /** Returns the value of the byte at the specified position as an unsigned value. */
+    @Override
     public int getUnsignedByte(int byteOffset) {
         return mDataBytes.get(byteOffset) & 0xFF;
     }
 
-    /** Returns the value of the 16-bit char at the specified position as an unsigned value. */
+    @Override
     public char getChar(int byteOffset) {
         return mDataBytes.getChar(byteOffset);
     }
 
-    /** Returns the value of the 32-bit int at the specified position as an signed value. */
+    @Override
     public int getInt(int byteOffset) {
         return mDataBytes.getInt(byteOffset);
     }
 
-    /** Returns the value of the 64-bit long at the specified position as an signed value. */
+    @Override
     public long getLong(int byteOffset) {
         return mDataBytes.getLong(byteOffset);
     }
 
-    /**
-     * Returns a tiny (<= 255 entries) array of signed bytes starting at the specified position,
-     * where the length is encoded in the data.
-     */
+    @Override
     public byte[] getTinyByteArray(int byteOffset) {
         int size = getUnsignedByte(byteOffset);
         return getBytes(byteOffset + 1, size);
     }
 
-    /**
-     * Returns an array of signed bytes starting at the specified position, where the 4-byte length
-     * is encoded in the data.
-     */
+    @Override
     public byte[] getByteArray(int byteOffset) {
         int size = getInt(byteOffset);
         return getBytes(byteOffset + Integer.BYTES, size);
     }
 
-    /**
-     * Returns an array of signed bytes starting at the specified position.
-     */
+    @Override
     public byte[] getBytes(int byteOffset, int byteCount) {
         byte[] bytes = new byte[byteCount];
         for (int i = 0; i < byteCount; i++) {
@@ -103,18 +129,13 @@ public final class BlockData {
         return bytes;
     }
 
-    /**
-     * Returns a tiny (<= 255 entries) array of chars starting at the specified position, where the
-     * length is encoded in the data.
-     */
+    @Override
     public char[] getTinyCharArray(int byteOffset) {
         int size = getUnsignedByte(byteOffset);
         return getChars(byteOffset + 1, size);
     }
 
-    /**
-     * Returns an array of chars starting at the specified position.
-     */
+    @Override
     public char[] getChars(int byteOffset, int charCount) {
         char[] array = new char[charCount];
         for (int i = 0; i < charCount; i++) {
@@ -124,11 +145,7 @@ public final class BlockData {
         return array;
     }
 
-    /**
-     * Returns 1-8 bytes ({@code valueSizeBytes}) starting as the specified position as a
-     * {@code long}. The value can be interpreted as signed or unsigned depending on
-     * {@code signExtend}.
-     */
+    @Override
     public long getValueAsLong(int valueSizeBytes, int byteOffset, boolean signExtend) {
         if (valueSizeBytes < 0 || valueSizeBytes > Long.BYTES) {
             throw new IllegalArgumentException("valueSizeBytes must be <= 8 bytes");
@@ -136,7 +153,7 @@ public final class BlockData {
         return getValueInternal(valueSizeBytes, byteOffset, signExtend);
     }
 
-    /** Returns the size of the block data. */
+    @Override
     public int getSize() {
         return mDataBytes.limit();
     }
diff --git a/s2storage/src/readonly/java/com/android/storage/block/read/BlockFileReader.java b/s2storage/src/readonly/java/com/android/storage/block/read/BlockFileReader.java
index 4395bfd..62117d1 100644
--- a/s2storage/src/readonly/java/com/android/storage/block/read/BlockFileReader.java
+++ b/s2storage/src/readonly/java/com/android/storage/block/read/BlockFileReader.java
@@ -32,6 +32,7 @@ import java.nio.channels.FileChannel;
 public final class BlockFileReader implements AutoCloseable {
 
     private static final ByteBuffer EMPTY_BYTE_BUFFER = ByteBuffer.allocate(0).asReadOnlyBuffer();
+    private static final BlockData EMPTY_BLOCK_DATA = new BlockData(EMPTY_BYTE_BUFFER);
 
     private Character mRequiredMagic;
 
@@ -146,7 +147,7 @@ public final class BlockFileReader implements AutoCloseable {
 
         BlockInfo blockInfo = mBlockInfos[blockId];
         if (blockInfo.getBlockSizeBytes() == 0) {
-            return new Block(blockId, blockInfo.getType(), EMPTY_BYTE_BUFFER);
+            return new Block(blockId, blockInfo.getType(), EMPTY_BLOCK_DATA);
         }
 
         ByteBuffer allBlockBuffer;
@@ -193,8 +194,8 @@ public final class BlockFileReader implements AutoCloseable {
         }
 
         // The part of the block that holds the data.
-        ByteBuffer blockDataBytes = allBlockBuffer.slice();
-        return new Block(actualId, actualType, blockDataBytes);
+        BlockData blockData = new BlockData(allBlockBuffer.slice());
+        return new Block(actualId, actualType, blockData);
     }
 
     /** Returns the number of blocks in the file. */
diff --git a/s2storage/src/readonly/java/com/android/storage/block/read/TypedData.java b/s2storage/src/readonly/java/com/android/storage/block/read/TypedData.java
new file mode 100644
index 0000000..c394a80
--- /dev/null
+++ b/s2storage/src/readonly/java/com/android/storage/block/read/TypedData.java
@@ -0,0 +1,88 @@
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
+package com.android.storage.block.read;
+
+import com.android.storage.io.read.TypedInputStream;
+
+/**
+ * Provides typed, absolute position, random access to data.
+ *
+ * <p>See also {@link TypedInputStream} for a streamed equivalent.
+ */
+public interface TypedData {
+
+    /**
+     * Returns a new read-only view into the data.
+     *
+     * @param startPos the start of the slice
+     * @param length the length of the slice to create
+     */
+    TypedData slice(int startPos, int length);
+
+    /** Returns the value of the byte at the specified position. */
+    byte getByte(int byteOffset);
+
+    /** Returns the value of the byte at the specified position as an unsigned value. */
+    int getUnsignedByte(int byteOffset);
+
+    /** Returns the value of the 16-bit char at the specified position as an unsigned value. */
+    char getChar(int byteOffset);
+
+    /** Returns the value of the 32-bit int at the specified position as an signed value. */
+    int getInt(int byteOffset);
+
+    /** Returns the value of the 64-bit long at the specified position as an signed value. */
+    long getLong(int byteOffset);
+
+    /**
+     * Returns a tiny (<= 255 entries) array of signed bytes starting at the specified position,
+     * where the length is encoded in the data.
+     */
+    byte[] getTinyByteArray(int byteOffset);
+
+    /**
+     * Returns an array of signed bytes starting at the specified position, where the 4-byte length
+     * is encoded in the data.
+     */
+    byte[] getByteArray(int byteOffset);
+
+    /**
+     * Returns an array of signed bytes starting at the specified position.
+     */
+    byte[] getBytes(int byteOffset, int byteCount);
+
+    /**
+     * Returns a tiny (<= 255 entries) array of chars starting at the specified position, where the
+     * length is encoded in the data.
+     */
+    char[] getTinyCharArray(int byteOffset);
+
+    /**
+     * Returns an array of chars starting at the specified position.
+     */
+    char[] getChars(int byteOffset, int charCount);
+
+    /**
+     * Returns 1-8 bytes ({@code valueSizeBytes}) starting as the specified position as a
+     * {@code long}. The value can be interpreted as signed or unsigned depending on
+     * {@code signExtend}.
+     */
+    long getValueAsLong(int valueSizeBytes, int byteOffset, boolean signExtend);
+
+    /** Returns the size of the block data. */
+    int getSize();
+}
diff --git a/s2storage/src/readonly/java/com/android/storage/table/packed/read/BaseTypedPackedTable.java b/s2storage/src/readonly/java/com/android/storage/table/packed/read/BaseTypedPackedTable.java
index 9a61c3c..6a530ab 100644
--- a/s2storage/src/readonly/java/com/android/storage/table/packed/read/BaseTypedPackedTable.java
+++ b/s2storage/src/readonly/java/com/android/storage/table/packed/read/BaseTypedPackedTable.java
@@ -17,6 +17,7 @@
 package com.android.storage.table.packed.read;
 
 import com.android.storage.block.read.BlockData;
+import com.android.storage.block.read.TypedData;
 import com.android.storage.table.reader.Table;
 
 import java.util.Objects;
@@ -50,6 +51,11 @@ abstract class BaseTypedPackedTable<E extends Table.TableEntry<E>> implements Ta
         return mTableReader.getSharedData();
     }
 
+    @Override
+    public TypedData getSharedDataAsTyped() {
+        return mTableReader.getSharedDataAsTyped();
+    }
+
     @Override
     public E getEntryByIndex(int i) {
         return createEntry(mTableReader.getEntryByIndex(i));
diff --git a/s2storage/src/readonly/java/com/android/storage/table/packed/read/PackedTableReader.java b/s2storage/src/readonly/java/com/android/storage/table/packed/read/PackedTableReader.java
index d4354d1..9a02734 100644
--- a/s2storage/src/readonly/java/com/android/storage/table/packed/read/PackedTableReader.java
+++ b/s2storage/src/readonly/java/com/android/storage/table/packed/read/PackedTableReader.java
@@ -17,6 +17,7 @@
 package com.android.storage.table.packed.read;
 
 import com.android.storage.block.read.BlockData;
+import com.android.storage.block.read.TypedData;
 import com.android.storage.table.reader.IntValueTable.IntValueEntryMatcher;
 import com.android.storage.table.reader.LongValueTable.LongValueEntryMatcher;
 import com.android.storage.util.BitwiseUtils;
@@ -58,7 +59,7 @@ public final class PackedTableReader {
     private final int mEntryCount;
 
     /** Domain-specific data that should be common to all entries. */
-    private final byte[] mSharedData;
+    private final TypedData mSharedData;
 
     /**
      * True if the value is to be treated as a signed value, i.e. whether its sign should be
@@ -81,13 +82,16 @@ public final class PackedTableReader {
 
         int offset = 0;
 
+        int sharedDataLength;
         if (useBigSharedData) {
-            mSharedData = blockData.getByteArray(offset);
-            offset += Integer.BYTES + mSharedData.length;
+            sharedDataLength = blockData.getInt(offset);
+            offset += Integer.BYTES;
         } else {
-            mSharedData = blockData.getTinyByteArray(offset);
-            offset += Byte.BYTES + mSharedData.length;
+            sharedDataLength = blockData.getByte(offset);
+            offset += Byte.BYTES;
         }
+        mSharedData = blockData.slice(offset, sharedDataLength);
+        offset += sharedDataLength;
 
         // Boolean properties are extracted from a 32-bit bit field.
         int bitField = blockData.getUnsignedByte(offset);
@@ -147,8 +151,25 @@ public final class PackedTableReader {
         return mValueSizeBits;
     }
 
-    /** Returns the table's shared data. */
+    /**
+     * Returns the table's unstructured shared data that can be used, for example, to hold
+     * information shared by all entries in the table.
+     *
+     * <p>See {@link #getSharedDataAsTyped()} for an alternative that consumes less memory for
+     * large shared data and provides type conversions.
+     */
     public byte[] getSharedData() {
+        return mSharedData.getBytes(0, mSharedData.getSize());
+    }
+
+    /**
+     * Returns the table's unstructured shared data that can be used, for example, to hold
+     * information shared by all entries in the table.
+     *
+     * <p>Unlike {@link #getSharedData()}, this method will not allocate a byte array, which
+     * can save memory if the shared data is large.
+     */
+    public TypedData getSharedDataAsTyped() {
         return mSharedData;
     }
 
diff --git a/s2storage/src/readonly/java/com/android/storage/table/reader/Table.java b/s2storage/src/readonly/java/com/android/storage/table/reader/Table.java
index 2caf5d0..6b886b4 100644
--- a/s2storage/src/readonly/java/com/android/storage/table/reader/Table.java
+++ b/s2storage/src/readonly/java/com/android/storage/table/reader/Table.java
@@ -16,6 +16,8 @@
 
 package com.android.storage.table.reader;
 
+import com.android.storage.block.read.TypedData;
+
 /**
  * A table containing entries with a signed, int key. A table can also have an array of shared data
  * that can be used, for example, to hold information shared by all entries in the table.
@@ -27,9 +29,21 @@ public interface Table<E extends Table.TableEntry> {
     /**
      * Returns the table's unstructured shared data that can be used, for example, to hold
      * information shared by all entries in the table.
+     *
+     * <p>See {@link #getSharedDataAsTyped()} for an alternative that consumes less memory for
+     * large shared data and provides type conversions.
      */
     byte[] getSharedData();
 
+    /**
+     * Returns the table's unstructured shared data that can be used, for example, to hold
+     * information shared by all entries in the table.
+     *
+     * <p>Unlike {@link #getSharedData()}, this method will not allocate a byte array, which
+     * can save memory if the shared data is large.
+     */
+    TypedData getSharedDataAsTyped();
+
     /**
      * Returns a table entry associated with the key, or {@code null} if there isn't one. If
      * multiple entries have the key, then an arbitrary entry with the key is returned.
diff --git a/s2storage/src/test/java/com/android/storage/block/read/BlockDataTest.java b/s2storage/src/test/java/com/android/storage/block/read/BlockDataTest.java
index af56bae..7624cf0 100644
--- a/s2storage/src/test/java/com/android/storage/block/read/BlockDataTest.java
+++ b/s2storage/src/test/java/com/android/storage/block/read/BlockDataTest.java
@@ -19,6 +19,7 @@ package com.android.storage.block.read;
 import static org.junit.Assert.assertArrayEquals;
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertNotSame;
+import static org.junit.Assert.assertThrows;
 
 import com.android.storage.io.write.TypedOutputStream;
 
@@ -69,6 +70,65 @@ public class BlockDataTest {
         assertEquals(blockDataBytes.length, byteBuffer.capacity());
     }
 
+    @Test
+    public void slice() throws IOException {
+        ByteArrayOutputStream baos = new ByteArrayOutputStream();
+        TypedOutputStream typedOutputStream = new TypedOutputStream(baos);
+        byte[] tinyByteArray = "Tiny Byte Array".getBytes(StandardCharsets.UTF_8);
+        typedOutputStream.writeTinyByteArray(tinyByteArray);
+        typedOutputStream.close();
+
+        byte[] blockDataBytes = baos.toByteArray();
+        ByteBuffer originalByteBuffer = ByteBuffer.wrap(blockDataBytes).asReadOnlyBuffer();
+        BlockData blockData = new BlockData(originalByteBuffer);
+
+        assertSliceEmptyBehavior(blockData, 0, 0);
+        assertSliceNonEmptyBehavior(blockData, 0, 1);
+        assertSliceNonEmptyBehavior(blockData, 0, blockData.getSize());
+
+        assertSliceEmptyBehavior(blockData, 1, 0);
+        assertSliceNonEmptyBehavior(blockData, 1, 1);
+        assertSliceNonEmptyBehavior(blockData, 1, blockData.getSize() - 1);
+
+        assertSliceEmptyBehavior(blockData, blockData.getSize() - 2, 0);
+        assertSliceNonEmptyBehavior(blockData, blockData.getSize() - 2, 1);
+        assertSliceNonEmptyBehavior(blockData, blockData.getSize() - 2, 2);
+
+        assertSliceEmptyBehavior(blockData, blockData.getSize() - 1, 0);
+        assertSliceNonEmptyBehavior(blockData, blockData.getSize() - 1, 1);
+
+        assertSliceEmptyBehavior(blockData, blockData.getSize(), 0);
+
+        // Edge cases: length of slice puts the top of the new slice outside of the original buffer.
+        assertSliceTypedDataBadArguments(blockData, -1, 0);
+        assertSliceTypedDataBadArguments(blockData, 0, blockData.getSize() + 1);
+        assertSliceTypedDataBadArguments(blockData, 0, blockData.getSize() * 2);
+        assertSliceTypedDataBadArguments(blockData, 1, blockData.getSize());
+        assertSliceTypedDataBadArguments(blockData, blockData.getSize() - 2, 3);
+        assertSliceTypedDataBadArguments(blockData, blockData.getSize() - 1, 2);
+        assertSliceTypedDataBadArguments(blockData, blockData.getSize(), 1);
+    }
+
+    private static void assertSliceEmptyBehavior(BlockData blockData, int offset, int length) {
+        TypedData slice = blockData.slice(offset, length);
+        assertEquals(0, slice.getSize());
+        assertThrows(IndexOutOfBoundsException.class, () -> slice.getInt(0));
+    }
+
+    private static void assertSliceNonEmptyBehavior(BlockData blockData, int offset, int length) {
+        TypedData slice = blockData.slice(offset, length);
+        assertEquals(length, slice.getSize());
+        for (int i = 0; i < length; i++) {
+            assertEquals(blockData.getByte(offset + i), slice.getByte(i));
+        }
+        assertThrows(IndexOutOfBoundsException.class, () -> slice.getInt(length));
+    }
+
+    private static void assertSliceTypedDataBadArguments(
+            BlockData blockData, int offset, int length) {
+        assertThrows(IllegalArgumentException.class, () -> blockData.slice(offset, length));
+    }
+
     @Test
     public void typedRandomAccess() throws IOException {
         ByteArrayOutputStream baos = new ByteArrayOutputStream();
diff --git a/s2storage/src/test/java/com/android/storage/block/read/BlockTest.java b/s2storage/src/test/java/com/android/storage/block/read/BlockTest.java
index b79e1cb..b94d640 100644
--- a/s2storage/src/test/java/com/android/storage/block/read/BlockTest.java
+++ b/s2storage/src/test/java/com/android/storage/block/read/BlockTest.java
@@ -32,8 +32,8 @@ public class BlockTest {
     public void visit() throws Exception {
         int id = 1234;
         int type = 2345;
-        ByteBuffer blockData = ByteBuffer.wrap("Data Bytes".getBytes()).asReadOnlyBuffer();
-        Block block = new Block(id, type, blockData);
+        ByteBuffer blockDataBuffer = ByteBuffer.wrap("Data Bytes".getBytes()).asReadOnlyBuffer();
+        Block block = new Block(id, type, new BlockData(blockDataBuffer));
         Block.BlockVisitor mockVisitor = mock(Block.BlockVisitor.class);
         block.visit(mockVisitor);
 
diff --git a/s2storage/src/test/java/com/android/storage/table/packed/PackedTableReaderWriterTest.java b/s2storage/src/test/java/com/android/storage/table/packed/PackedTableReaderWriterTest.java
index ab51f36..079dd73 100644
--- a/s2storage/src/test/java/com/android/storage/table/packed/PackedTableReaderWriterTest.java
+++ b/s2storage/src/test/java/com/android/storage/table/packed/PackedTableReaderWriterTest.java
@@ -91,6 +91,8 @@ public class PackedTableReaderWriterTest {
         assertEquals(keyBits, tableReader.getKeySizeBits());
         assertEquals(signedValue, tableReader.isValueSigned());
         assertArrayEquals(sharedData, tableReader.getSharedData());
+        assertArrayEquals(
+                sharedData, tableReader.getSharedDataAsTyped().getBytes(0, sharedData.length));
         assertEquals((entrySizeBytes * Byte.SIZE) - keyBits, tableReader.getValueSizeBits());
         assertEquals(0, tableReader.getEntryCount());
     }
@@ -229,6 +231,8 @@ public class PackedTableReaderWriterTest {
         BlockData blockData = new BlockData(createByteBuffer(baos.toByteArray()));
         PackedTableReader tableReader = new PackedTableReader(blockData, useBigSharedData);
         assertArrayEquals(sharedData, tableReader.getSharedData());
+        assertArrayEquals(
+                sharedData, tableReader.getSharedDataAsTyped().getBytes(0, sharedData.length));
     }
 
     @Test
@@ -279,6 +283,7 @@ public class PackedTableReaderWriterTest {
         BlockData blockData = new BlockData(createByteBuffer(baos.toByteArray()));
         PackedTableReader tableReader = new PackedTableReader(blockData);
         assertArrayEquals(new byte[0], tableReader.getSharedData());
+        assertEquals(0, tableReader.getSharedDataAsTyped().getSize());
 
         assertNull(tableReader.getEntry(12));
     }
@@ -294,6 +299,7 @@ public class PackedTableReaderWriterTest {
         BlockData blockData = new BlockData(createByteBuffer(baos.toByteArray()));
         PackedTableReader tableReader = new PackedTableReader(blockData);
         assertArrayEquals(new byte[0], tableReader.getSharedData());
+        assertEquals(0, tableReader.getSharedDataAsTyped().getSize());
 
         int negativeKey = -1;
         assertThrows(IllegalArgumentException.class, () -> tableReader.getEntry(negativeKey));
```

