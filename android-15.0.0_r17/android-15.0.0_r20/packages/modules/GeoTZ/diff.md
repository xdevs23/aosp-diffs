```diff
diff --git a/s2storage/src/test/java/com/android/storage/io/TypedStreamsTest.java b/s2storage/src/test/java/com/android/storage/io/TypedStreamsTest.java
index 27b8a35..635b80c 100644
--- a/s2storage/src/test/java/com/android/storage/io/TypedStreamsTest.java
+++ b/s2storage/src/test/java/com/android/storage/io/TypedStreamsTest.java
@@ -200,4 +200,108 @@ public class TypedStreamsTest {
 
         assertEquals(0, baos.toByteArray().length);
     }
+
+    @Test
+    public void writeReadLargeBufferOk() throws Exception {
+        int bufferSizeInBytes = (int) Math.pow(2, 20);
+        int chunkSizeInBytes = 104; // 8 + 1 + 2 + 4 + 8 + 8 + 60 + 5 + 8 = 104 bytes
+
+        ByteArrayOutputStream baos = new ByteArrayOutputStream();
+        TypedOutputStream tos = new TypedOutputStream(baos, bufferSizeInBytes);
+
+        // Loop to fill the buffer with chunks until it's full.
+        for (int i = 0; i < bufferSizeInBytes / chunkSizeInBytes; i++) {
+            tos.writeChar(Character.MIN_VALUE);
+            tos.writeChar('\u1234');
+            tos.writeChar('\u5678');
+            tos.writeChar(Character.MAX_VALUE);
+
+            tos.writeUnsignedByte(i % 256);
+
+            tos.writeByte(Byte.MIN_VALUE);
+            tos.writeByte(Byte.MAX_VALUE);
+
+            tos.writeBytes(new byte[] { 0x11, 0x00, 0x7F, -0x80 });
+
+            tos.writeInt(Integer.MIN_VALUE);
+            tos.writeInt(Integer.MAX_VALUE);
+
+            tos.writeLong(0x5555555555555555L);
+
+            tos.writeVarByteValue(1, 0x0000000000000012L);
+            tos.writeVarByteValue(2, 0x0000000000002223L);
+            tos.writeVarByteValue(3, 0x0000000000333334L);
+            tos.writeVarByteValue(4, 0x0000000044444445L);
+            tos.writeVarByteValue(5, 0x0000005555555556L);
+            tos.writeVarByteValue(6, 0x0000666666666667L);
+            tos.writeVarByteValue(7, 0x0077777777777778L);
+            tos.writeVarByteValue(8, 0x8888888888888889L);
+
+            tos.writeTinyByteArray(new byte[0]);
+            tos.writeTinyByteArray(new byte[] { (byte) 0xAA, (byte) 0xBB, 0 });
+
+            tos.writeTinyCharArray(new char[0]);
+            tos.writeTinyCharArray(new char[] { 0xAAAA, 0xBBBB, 0 });
+        }
+
+        // Fill TypedOutputStream buffer with max size + 10 bytes to check out of bound case.
+        for (int i = 0; i < bufferSizeInBytes % chunkSizeInBytes + 10; i++) {
+            tos.writeUnsignedByte(i % 256);
+        }
+
+        tos.flush();
+        byte[] bytes = baos.toByteArray();
+        baos.reset();
+        TypedInputStream tis = new TypedInputStream(new ByteArrayInputStream(bytes));
+
+        for (int i = 0; i < bufferSizeInBytes / chunkSizeInBytes; i++) {
+            assertEquals(Character.MIN_VALUE, tis.readChar());
+            assertEquals('\u1234', tis.readChar());
+            assertEquals('\u5678', tis.readChar());
+            assertEquals(Character.MAX_VALUE, tis.readChar());
+
+            assertEquals(i % 256, tis.readUnsignedByte());
+
+            assertEquals(Byte.MIN_VALUE, tis.readSignedByte());
+            assertEquals(Byte.MAX_VALUE, tis.readSignedByte());
+
+            assertEquals(0x11, tis.readSignedByte());
+            assertEquals(0x00, tis.readSignedByte());
+            assertEquals(0x7F, tis.readSignedByte());
+            assertEquals(-0x80, tis.readSignedByte());
+
+            assertEquals(Integer.MIN_VALUE, tis.readInt());
+            assertEquals(Integer.MAX_VALUE, tis.readInt());
+
+            assertEquals(0x5555555555555555L, tis.readLong());
+
+            expectBytes(tis, 1, 0x12);
+            expectBytes(tis, 1, 0x22);
+            expectBytes(tis, 1, 0x23);
+            expectBytes(tis, 2, 0x33);
+            expectBytes(tis, 1, 0x34);
+            expectBytes(tis, 3, 0x44);
+            expectBytes(tis, 1, 0x45);
+            expectBytes(tis, 4, 0x55);
+            expectBytes(tis, 1, 0x56);
+            expectBytes(tis, 5, 0x66);
+            expectBytes(tis, 1, 0x67);
+            expectBytes(tis, 6, 0x77);
+            expectBytes(tis, 1, 0x78);
+            expectBytes(tis, 7, 0x88);
+            expectBytes(tis, 1, 0x89);
+
+            assertArrayEquals(new byte[0], tis.readTinyVarByteArray());
+            assertArrayEquals(new byte[]{(byte) 0xAA, (byte) 0xBB, 0}, tis.readTinyVarByteArray());
+
+            assertArrayEquals(new char[0], tis.readTinyVarCharArray());
+            assertArrayEquals(new char[]{0xAAAA, 0xBBBB, 0}, tis.readTinyVarCharArray());
+        }
+
+        // Even if you write more than the allocated size to the buffer,
+        // the entire data is preserved because it flushes whenever the size is exceeded.
+        for (int i = 0; i < bufferSizeInBytes % chunkSizeInBytes + 10; i++) {
+            assertEquals(i % 256, tis.readUnsignedByte());
+        }
+    }
 }
diff --git a/s2storage/src/write/java/com/android/storage/io/write/TypedOutputStream.java b/s2storage/src/write/java/com/android/storage/io/write/TypedOutputStream.java
index c5269ad..68dd9b6 100644
--- a/s2storage/src/write/java/com/android/storage/io/write/TypedOutputStream.java
+++ b/s2storage/src/write/java/com/android/storage/io/write/TypedOutputStream.java
@@ -37,7 +37,12 @@ public final class TypedOutputStream implements Flushable, Closeable {
 
     /** Creates an instance, wrapping the supplied stream. */
     public TypedOutputStream(OutputStream out) {
-        mDataOutputStream = new DataOutputStream(new BufferedOutputStream(out, 8192));
+        this(out, /* bufferSize= */ 8192);
+    }
+
+    /** Creates an instance with specified buffer size, wrapping the supplied stream. */
+    public TypedOutputStream(OutputStream out, int bufferSize) {
+        mDataOutputStream = new DataOutputStream(new BufferedOutputStream(out, bufferSize));
     }
 
     /**
```

