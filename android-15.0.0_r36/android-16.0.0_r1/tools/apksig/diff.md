```diff
diff --git a/OWNERS b/OWNERS
index 4f9b08d..23cab0b 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,3 +1,2 @@
 cbrubaker@google.com
-dcashman@google.com
 mpgroover@google.com
diff --git a/src/main/java/com/android/apksig/internal/zip/CentralDirectoryRecord.java b/src/main/java/com/android/apksig/internal/zip/CentralDirectoryRecord.java
index d2f444d..0437710 100644
--- a/src/main/java/com/android/apksig/internal/zip/CentralDirectoryRecord.java
+++ b/src/main/java/com/android/apksig/internal/zip/CentralDirectoryRecord.java
@@ -16,7 +16,14 @@
 
 package com.android.apksig.internal.zip;
 
+import static com.android.apksig.internal.zip.ZipUtils.UINT32_MAX_VALUE;
+import static com.android.apksig.internal.zip.ZipUtils.ZIP64_COMPRESSED_SIZE_FIELD_NAME;
+import static com.android.apksig.internal.zip.ZipUtils.ZIP64_LFH_OFFSET_FIELD_NAME;
+import static com.android.apksig.internal.zip.ZipUtils.ZIP64_UNCOMPRESSED_SIZE_FIELD_NAME;
+
+import com.android.apksig.internal.zip.ZipUtils.Zip64Fields;
 import com.android.apksig.zip.ZipFormatException;
+
 import java.nio.BufferUnderflowException;
 import java.nio.ByteBuffer;
 import java.nio.ByteOrder;
@@ -40,6 +47,7 @@ public class CentralDirectoryRecord {
 
     private static final int GP_FLAGS_OFFSET = 8;
     private static final int LOCAL_FILE_HEADER_OFFSET_OFFSET = 42;
+    private static final int EXTRA_FIELD_OFFSET = 46;
     private static final int NAME_OFFSET = HEADER_SIZE_BYTES;
 
     private final ByteBuffer mData;
@@ -164,6 +172,39 @@ public class CentralDirectoryRecord {
                     new BufferUnderflowException());
         }
         String name = getName(buf, originalPosition + NAME_OFFSET, nameSize);
+        // If the record contains an extra field and any of the other fields subject to the 32-bit
+        // limitation indicate the presence of a ZIP64 block, then check the extra field for this
+        // block to obtain the actual values of the affected fields.
+        if (extraSize > 0
+                && (uncompressedSize == UINT32_MAX_VALUE
+                        || compressedSize == UINT32_MAX_VALUE
+                        || localFileHeaderOffset == UINT32_MAX_VALUE)) {
+            buf.position(originalPosition + EXTRA_FIELD_OFFSET + nameSize);
+            int originalLimit = buf.limit();
+            ByteBuffer extra = buf.slice();
+            buf.limit(originalLimit);
+            Zip64Fields zip64Fields =
+                    new Zip64Fields(uncompressedSize, compressedSize, localFileHeaderOffset);
+            ZipUtils.parseExtraField(extra, zip64Fields);
+            uncompressedSize =
+                    ZipUtils.checkAndReturnZip64Value(
+                            uncompressedSize,
+                            zip64Fields.uncompressedSize,
+                            name,
+                            ZIP64_UNCOMPRESSED_SIZE_FIELD_NAME);
+            compressedSize =
+                    ZipUtils.checkAndReturnZip64Value(
+                            compressedSize,
+                            zip64Fields.compressedSize,
+                            name,
+                            ZIP64_COMPRESSED_SIZE_FIELD_NAME);
+            localFileHeaderOffset =
+                    ZipUtils.checkAndReturnZip64Value(
+                            localFileHeaderOffset,
+                            zip64Fields.localFileHeaderOffset,
+                            name,
+                            ZIP64_LFH_OFFSET_FIELD_NAME);
+        }
         buf.position(originalPosition);
         int originalLimit = buf.limit();
         int recordEndInBuf = originalPosition + recordSize;
diff --git a/src/main/java/com/android/apksig/internal/zip/LocalFileRecord.java b/src/main/java/com/android/apksig/internal/zip/LocalFileRecord.java
index 50ce386..9496f41 100644
--- a/src/main/java/com/android/apksig/internal/zip/LocalFileRecord.java
+++ b/src/main/java/com/android/apksig/internal/zip/LocalFileRecord.java
@@ -16,10 +16,16 @@
 
 package com.android.apksig.internal.zip;
 
+import static com.android.apksig.internal.zip.ZipUtils.UINT32_MAX_VALUE;
+import static com.android.apksig.internal.zip.ZipUtils.ZIP64_COMPRESSED_SIZE_FIELD_NAME;
+import static com.android.apksig.internal.zip.ZipUtils.ZIP64_UNCOMPRESSED_SIZE_FIELD_NAME;
+
 import com.android.apksig.internal.util.ByteBufferSink;
+import com.android.apksig.internal.zip.ZipUtils.Zip64Fields;
 import com.android.apksig.util.DataSink;
 import com.android.apksig.util.DataSource;
 import com.android.apksig.zip.ZipFormatException;
+
 import java.io.Closeable;
 import java.io.IOException;
 import java.nio.ByteBuffer;
@@ -86,7 +92,9 @@ public class LocalFileRecord {
     }
 
     public ByteBuffer getExtra() {
-        return (mExtra.capacity() > 0) ? mExtra.slice() : mExtra;
+        ByteBuffer result = (mExtra.capacity() > 0) ? mExtra.slice() : mExtra;
+        result.order(ByteOrder.LITTLE_ENDIAN);
+        return result;
     }
 
     public int getExtraFieldStartOffsetInsideRecord() {
@@ -185,29 +193,6 @@ public class LocalFileRecord {
         long uncompressedDataCrc32FromCdRecord = cdRecord.getCrc32();
         long compressedDataSizeFromCdRecord = cdRecord.getCompressedSize();
         long uncompressedDataSizeFromCdRecord = cdRecord.getUncompressedSize();
-        if (!dataDescriptorUsed) {
-            long crc32 = ZipUtils.getUnsignedInt32(header, CRC32_OFFSET);
-            if (crc32 != uncompressedDataCrc32FromCdRecord) {
-                throw new ZipFormatException(
-                        "CRC-32 mismatch between Local File Header and Central Directory for entry "
-                                + entryName + ". LFH: " + crc32
-                                + ", CD: " + uncompressedDataCrc32FromCdRecord);
-            }
-            long compressedSize = ZipUtils.getUnsignedInt32(header, COMPRESSED_SIZE_OFFSET);
-            if (compressedSize != compressedDataSizeFromCdRecord) {
-                throw new ZipFormatException(
-                        "Compressed size mismatch between Local File Header and Central Directory"
-                                + " for entry " + entryName + ". LFH: " + compressedSize
-                                + ", CD: " + compressedDataSizeFromCdRecord);
-            }
-            long uncompressedSize = ZipUtils.getUnsignedInt32(header, UNCOMPRESSED_SIZE_OFFSET);
-            if (uncompressedSize != uncompressedDataSizeFromCdRecord) {
-                throw new ZipFormatException(
-                        "Uncompressed size mismatch between Local File Header and Central Directory"
-                                + " for entry " + entryName + ". LFH: " + uncompressedSize
-                                + ", CD: " + uncompressedDataSizeFromCdRecord);
-            }
-        }
         int nameLength = ZipUtils.getUnsignedInt16(header, NAME_LENGTH_OFFSET);
         if (nameLength > cdRecordEntryNameSizeBytes) {
             throw new ZipFormatException(
@@ -243,6 +228,75 @@ public class LocalFileRecord {
         if ((extraFieldContentsNeeded) && (extraLength > 0)) {
             extra = apk.getByteBuffer(
                     headerStartOffset + HEADER_SIZE_BYTES + nameLength, extraLength);
+            extra.order(ByteOrder.LITTLE_ENDIAN);
+        }
+
+        if (!dataDescriptorUsed) {
+            long crc32 = ZipUtils.getUnsignedInt32(header, CRC32_OFFSET);
+            if (crc32 != uncompressedDataCrc32FromCdRecord) {
+                throw new ZipFormatException(
+                        "CRC-32 mismatch between Local File Header and Central Directory for entry "
+                                + entryName
+                                + ". LFH: "
+                                + crc32
+                                + ", CD: "
+                                + uncompressedDataCrc32FromCdRecord);
+            }
+            long compressedSize = ZipUtils.getUnsignedInt32(header, COMPRESSED_SIZE_OFFSET);
+            long uncompressedSize = ZipUtils.getUnsignedInt32(header, UNCOMPRESSED_SIZE_OFFSET);
+
+            // If the record contains an extra field and any of the other fields subject to the
+            // 32-bit limitation indicate the presence of a ZIP64 block, then check the extra field
+            // for this block to obtain the actual values of the affected fields.
+            if (extraLength > 0
+                    && (compressedSize == UINT32_MAX_VALUE
+                            || uncompressedSize == UINT32_MAX_VALUE)) {
+                // If the extra buffer was not previously obtained due to the flag not being set,
+                // get the extra buffer now.
+                if (!extraFieldContentsNeeded) {
+                    extra =
+                            apk.getByteBuffer(
+                                    headerStartOffset + HEADER_SIZE_BYTES + nameLength,
+                                    extraLength);
+                    extra.order(ByteOrder.LITTLE_ENDIAN);
+                }
+                Zip64Fields zip64Fields = new Zip64Fields(uncompressedSize, compressedSize);
+                ZipUtils.parseExtraField(extra, zip64Fields);
+                extra.position(0);
+                uncompressedSize =
+                        ZipUtils.checkAndReturnZip64Value(
+                                uncompressedSize,
+                                zip64Fields.uncompressedSize,
+                                entryName,
+                                ZIP64_UNCOMPRESSED_SIZE_FIELD_NAME);
+                compressedSize =
+                        ZipUtils.checkAndReturnZip64Value(
+                                compressedSize,
+                                zip64Fields.compressedSize,
+                                entryName,
+                                ZIP64_COMPRESSED_SIZE_FIELD_NAME);
+            }
+            if (compressedSize != compressedDataSizeFromCdRecord) {
+                throw new ZipFormatException(
+                        "Compressed size mismatch between Local File Header and Central Directory"
+                                + " for entry "
+                                + entryName
+                                + ". LFH: "
+                                + compressedSize
+                                + ", CD: "
+                                + compressedDataSizeFromCdRecord);
+            }
+
+            if (uncompressedSize != uncompressedDataSizeFromCdRecord) {
+                throw new ZipFormatException(
+                        "Uncompressed size mismatch between Local File Header and Central Directory"
+                                + " for entry "
+                                + entryName
+                                + ". LFH: "
+                                + uncompressedSize
+                                + ", CD: "
+                                + uncompressedDataSizeFromCdRecord);
+            }
         }
 
         long recordEndOffset = dataEndOffset;
diff --git a/src/main/java/com/android/apksig/internal/zip/ZipUtils.java b/src/main/java/com/android/apksig/internal/zip/ZipUtils.java
index 1c2e82c..87f4006 100644
--- a/src/main/java/com/android/apksig/internal/zip/ZipUtils.java
+++ b/src/main/java/com/android/apksig/internal/zip/ZipUtils.java
@@ -53,7 +53,13 @@ public abstract class ZipUtils {
     private static final int ZIP_EOCD_CENTRAL_DIR_OFFSET_FIELD_OFFSET = 16;
     private static final int ZIP_EOCD_COMMENT_LENGTH_FIELD_OFFSET = 20;
 
-    private static final int UINT16_MAX_VALUE = 0xffff;
+    public static final int ZIP64_RECORD_ID = 0x1;
+    public static final String ZIP64_UNCOMPRESSED_SIZE_FIELD_NAME = "uncompressedSize";
+    public static final String ZIP64_COMPRESSED_SIZE_FIELD_NAME = "compressedSize";
+    public static final String ZIP64_LFH_OFFSET_FIELD_NAME = "localFileHeaderOffset";
+
+    public static final int UINT16_MAX_VALUE = 0xffff;
+    public static final long UINT32_MAX_VALUE = 0xffffffffL;
 
     /**
      * Sets the offset of the start of the ZIP Central Directory in the archive.
@@ -253,6 +259,104 @@ public abstract class ZipUtils {
         return -1;
     }
 
+    /**
+     * Parses the provided extra field for the ZIP64 block and sets the fields in the provided
+     * {@code zip64Fields} that were affected by the 32-bit limit.
+     *
+     * <p>Since the ZIP64 block only includes those fields that exceed the limit, the specified
+     * {@code zip64Fields} is used to determine which fields should be read and updated from the
+     * ZIP64 block.
+     */
+    static void parseExtraField(ByteBuffer extra, Zip64Fields zip64Fields)
+            throws ZipFormatException {
+        extra.order(ByteOrder.LITTLE_ENDIAN);
+        // Each record within the extra field must contain at least a UINT16 headerId and size
+        // FORMAT:
+        // * uint16: headerId
+        // * uint16: size
+        //   * Payload of the specified size
+        while (extra.remaining() > 4) {
+            int headerId = getUnsignedInt16(extra);
+            int extraRecordSize = getUnsignedInt16(extra);
+            if (extraRecordSize > extra.remaining()) {
+                throw new ZipFormatException(
+                        "Extra field record with ID "
+                                + Long.toHexString(headerId)
+                                + " exceeds size of field; size of block: "
+                                + extraRecordSize
+                                + ", remaining extra buffer: "
+                                + extra.remaining());
+            }
+            if (headerId == ZIP64_RECORD_ID) {
+                // Each field in the ZIP64 record only exists if the corresponding field in the
+                // local file header / central directory with the UINT32 max value; the fields must
+                // always be in the order uncompressedSize, compressedSize, and
+                // localFileHeaderOffset, where applicable.
+                // ZIP64 FORMAT:
+                // * uint64: uncompressed size (if the base uncompressed value is 0xffffffff)
+                // * uint64: compressed size (if the base compressed value is 0xffffffff)
+                // * uint64: local file header offset (if the base LFH offset value is 0xffffffff)
+                if (zip64Fields.uncompressedSize == UINT32_MAX_VALUE) {
+                    if (extraRecordSize >= 8) {
+                        zip64Fields.uncompressedSize = extra.getLong();
+                        extraRecordSize -= 8;
+                    } else {
+                        throw new ZipFormatException(
+                                "Expected an uncompressed size value in the ZIP64 record, "
+                                        + "remaining size of record: "
+                                        + extraRecordSize);
+                    }
+                }
+                if (zip64Fields.compressedSize == UINT32_MAX_VALUE) {
+                    if (extraRecordSize >= 8) {
+                        zip64Fields.compressedSize = extra.getLong();
+                        extraRecordSize -= 8;
+                    } else {
+                        throw new ZipFormatException(
+                                "Expected a compressed size value in the ZIP64 record, "
+                                        + "remaining size of record: "
+                                        + extraRecordSize);
+                    }
+                }
+                if (zip64Fields.localFileHeaderOffset == UINT32_MAX_VALUE) {
+                    if (extraRecordSize >= 8) {
+                        zip64Fields.localFileHeaderOffset = extra.getLong();
+                    } else {
+                        throw new ZipFormatException(
+                                "Expected a LFH offset in the ZIP64 record, "
+                                        + "remaining size of record: "
+                                        + extraRecordSize);
+                    }
+                }
+                // Once the ZIP64 record is found, no further parsing is required.
+                break;
+            } else {
+                // Skip over the unexpected record and check subsequent records.
+                extra.position(extra.position() + extraRecordSize);
+            }
+        }
+    }
+
+    /**
+     * Checks whether the provided {@code headerValue} from the LFH / CD Record exceeds the 32-bit
+     * limit and must be obtained from the Zip64 record; if so, then the specified {@code
+     * zip64Value} is verified and returned to the caller.
+     */
+    static long checkAndReturnZip64Value(
+            long headerValue, long zip64Value, String name, String fieldName)
+            throws ZipFormatException {
+        // If the value in the header does not indicate that the value exceeds the 32-bit
+        // limitation and must be in the Zip64 record, then return the provided value.
+        if (headerValue != UINT32_MAX_VALUE) {
+            return headerValue;
+        }
+        if (zip64Value == UINT32_MAX_VALUE) {
+            throw new ZipFormatException(
+                    "Unable to obtain ZIP64 " + fieldName + " field for record: " + name);
+        }
+        return zip64Value;
+    }
+
     static void assertByteOrderLittleEndian(ByteBuffer buffer) {
         if (buffer.order() != ByteOrder.LITTLE_ENDIAN) {
             throw new IllegalArgumentException("ByteBuffer byte order must be little endian");
@@ -382,4 +486,27 @@ public abstract class ZipUtils {
             this.output = output;
         }
     }
+
+    /**
+     * Class containing the file header / central directory fields that can be affected by the 32-
+     * bit limit. In the case that any of these fields exceed this limit, the value will be set to
+     * 0xffffffff, and the value can be found in the extra field. This class can be used with {@link
+     * #parseExtraField(ByteBuffer, Zip64Fields)} to obtain the corresponding values for each
+     * affected field.
+     */
+    static class Zip64Fields {
+        public long uncompressedSize;
+        public long compressedSize;
+        public long localFileHeaderOffset;
+
+        Zip64Fields(long uncompressedSize, long compressedSize) {
+            this(uncompressedSize, compressedSize, -1);
+        }
+
+        Zip64Fields(long uncompressedSize, long compressedSize, long localFileHeaderOffset) {
+            this.uncompressedSize = uncompressedSize;
+            this.compressedSize = compressedSize;
+            this.localFileHeaderOffset = localFileHeaderOffset;
+        }
+    }
 }
\ No newline at end of file
diff --git a/src/test/java/com/android/apksig/ApkSignerTest.java b/src/test/java/com/android/apksig/ApkSignerTest.java
index a2ecf8d..14b2a70 100644
--- a/src/test/java/com/android/apksig/ApkSignerTest.java
+++ b/src/test/java/com/android/apksig/ApkSignerTest.java
@@ -1865,6 +1865,33 @@ public class ApkSignerTest {
             resourceZipFileContains("golden-pinsapp-signed.apk", "pinlist.meta"));
     }
 
+    @Test
+    public void testSignApk_apkWithZip64Records_signsAndVerifiesSuccessfully() throws Exception {
+        // When any of the fields in the Local File Header or Central Directory Record exceed
+        // the value that can be stored in 32-bits, then the value is written as 0xffffffff and
+        // the actual value is written to the Zip64 record within the extra field of the current
+        // block; for APKs, these fields are uncompressed size, compressed size, and local file
+        // header offset. This test uses an APK with assets records that have been modified to
+        // write the 0xffffffff values for combinations of these fields in both the local file
+        // header as well as the central directory record; the actual size of these fields is then
+        // written in the corresponding field in the Zip64 record. During signing, all of these
+        // fields need to be read and preserved when writing the records back to the APK.
+        List<ApkSigner.SignerConfig> rsa2048SignerConfig =
+                Collections.singletonList(
+                        getDefaultSignerConfigFromResources(FIRST_RSA_2048_SIGNER_RESOURCE_NAME));
+
+        File signedApk =
+                sign(
+                        "v1v2v3-with-zip64-records.apk",
+                        new ApkSigner.Builder(rsa2048SignerConfig)
+                                .setV1SigningEnabled(true)
+                                .setV2SigningEnabled(true)
+                                .setV3SigningEnabled(true));
+
+        ApkVerifier.Result result = verify(signedApk, null);
+        assertVerified(result);
+    }
+
     @Test
     public void testOtherSignersSignaturesPreserved_extraSigBlock_signatureAppended()
             throws Exception {
diff --git a/src/test/java/com/android/apksig/ApkVerifierTest.java b/src/test/java/com/android/apksig/ApkVerifierTest.java
index 9677d4e..e28c98a 100644
--- a/src/test/java/com/android/apksig/ApkVerifierTest.java
+++ b/src/test/java/com/android/apksig/ApkVerifierTest.java
@@ -1881,6 +1881,21 @@ public class ApkVerifierTest {
         verify("invalid_manifest.apk");
     }
 
+    @Test
+    public void verify_apkWithZip64Records_verifiesSuccessfully() throws Exception {
+        // When any of the fields in the Local File Header or Central Directory Record exceed
+        // the value that can be stored in 32-bits, then the value is written as 0xffffffff and
+        // the actual value is written to the Zip64 record within the extra field of the current
+        // block; for APKs, these fields are uncompressed size, compressed size, and local file
+        // header offset. This test uses an APK with assets records that have been modified to
+        // write the 0xffffffff values for combinations of these fields in both the local file
+        // header as well as the central directory record; the actual size of these fields is then
+        // written in the corresponding field in the Zip64 record.
+        ApkVerifier.Result result = verify("v1v2v3-with-zip64-records.apk");
+
+        assertVerified(result);
+    }
+
     @Test
     public void compareMatchingDigests() throws Exception {
         Map<ContentDigestAlgorithm, byte[]> firstDigest = new HashMap<>();
diff --git a/src/test/java/com/android/apksig/internal/zip/ZipUtilsTest.java b/src/test/java/com/android/apksig/internal/zip/ZipUtilsTest.java
new file mode 100644
index 0000000..0a0f86c
--- /dev/null
+++ b/src/test/java/com/android/apksig/internal/zip/ZipUtilsTest.java
@@ -0,0 +1,347 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+package com.android.apksig.internal.zip;
+
+import static com.android.apksig.internal.zip.ZipUtils.UINT16_MAX_VALUE;
+import static com.android.apksig.internal.zip.ZipUtils.UINT32_MAX_VALUE;
+import static com.android.apksig.internal.zip.ZipUtils.ZIP64_COMPRESSED_SIZE_FIELD_NAME;
+import static com.android.apksig.internal.zip.ZipUtils.ZIP64_LFH_OFFSET_FIELD_NAME;
+import static com.android.apksig.internal.zip.ZipUtils.ZIP64_RECORD_ID;
+import static com.android.apksig.internal.zip.ZipUtils.ZIP64_UNCOMPRESSED_SIZE_FIELD_NAME;
+
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertThrows;
+
+import com.android.apksig.internal.zip.ZipUtils.Zip64Fields;
+import com.android.apksig.zip.ZipFormatException;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
+import java.nio.ByteBuffer;
+import java.nio.ByteOrder;
+
+@RunWith(JUnit4.class)
+public class ZipUtilsTest {
+    private static final long EXPECTED_UNCOMPRESSED_VALUE = 0x80008000L;
+    private static final long EXPECTED_COMPRESSED_VALUE = 0x80004000L;
+    private static final long EXPECTED_LFH_OFFSET_VALUE = 0x80002000L;
+
+    @Test
+    public void parseExtraField_onlyZip64RecordAllValuesInZip64_correctValuesReturned()
+            throws Exception {
+        // This test verifies that all the fields affected by the 32-bit limitation can be parsed
+        // in the Zip64 record when it is the only record in the extra field.
+        Zip64Fields zip64Fields =
+                new Zip64Fields(UINT32_MAX_VALUE, UINT32_MAX_VALUE, UINT32_MAX_VALUE);
+        ByteBuffer extra =
+                new ExtraBufferBuilder()
+                        .setUncompressedSize(EXPECTED_UNCOMPRESSED_VALUE)
+                        .setCompressedSize(EXPECTED_COMPRESSED_VALUE)
+                        .setLfhOffset(EXPECTED_LFH_OFFSET_VALUE)
+                        .build();
+
+        ZipUtils.parseExtraField(extra, zip64Fields);
+
+        assertEquals(EXPECTED_UNCOMPRESSED_VALUE, zip64Fields.uncompressedSize);
+        assertEquals(EXPECTED_COMPRESSED_VALUE, zip64Fields.compressedSize);
+        assertEquals(EXPECTED_LFH_OFFSET_VALUE, zip64Fields.localFileHeaderOffset);
+    }
+
+    @Test
+    public void parseExtraField_zip64AndPriorRecordAllValuesInZip64_correctValuesReturned()
+            throws Exception {
+        // This test verifies that all the fields affected by the 32-bit limitation can be parsed
+        // in the Zip64 record when it is preceded by another record in the extra field.
+        Zip64Fields zip64Fields =
+                new Zip64Fields(UINT32_MAX_VALUE, UINT32_MAX_VALUE, UINT32_MAX_VALUE);
+        ByteBuffer extra =
+                new ExtraBufferBuilder()
+                        .setPriorRecordSize(12)
+                        .setUncompressedSize(EXPECTED_UNCOMPRESSED_VALUE)
+                        .setCompressedSize(EXPECTED_COMPRESSED_VALUE)
+                        .setLfhOffset(EXPECTED_LFH_OFFSET_VALUE)
+                        .build();
+
+        ZipUtils.parseExtraField(extra, zip64Fields);
+
+        assertEquals(EXPECTED_UNCOMPRESSED_VALUE, zip64Fields.uncompressedSize);
+        assertEquals(EXPECTED_COMPRESSED_VALUE, zip64Fields.compressedSize);
+        assertEquals(EXPECTED_LFH_OFFSET_VALUE, zip64Fields.localFileHeaderOffset);
+    }
+
+    @Test
+    public void parseExtraField_zip64PriorAndNextRecordsAllValuesInZip64_correctValuesReturned()
+            throws Exception {
+        // This test verifies that all the fields affected by the 32-bit limitation can be parsed
+        // in the Zip64 record when there is both a prior and subsequent record.
+        Zip64Fields zip64Fields =
+                new Zip64Fields(UINT32_MAX_VALUE, UINT32_MAX_VALUE, UINT32_MAX_VALUE);
+        ByteBuffer extra =
+                new ExtraBufferBuilder()
+                        .setPriorRecordSize(12)
+                        .setUncompressedSize(EXPECTED_UNCOMPRESSED_VALUE)
+                        .setCompressedSize(EXPECTED_COMPRESSED_VALUE)
+                        .setLfhOffset(EXPECTED_LFH_OFFSET_VALUE)
+                        .setNextRecordSize(8)
+                        .build();
+
+        ZipUtils.parseExtraField(extra, zip64Fields);
+
+        assertEquals(EXPECTED_UNCOMPRESSED_VALUE, zip64Fields.uncompressedSize);
+        assertEquals(EXPECTED_COMPRESSED_VALUE, zip64Fields.compressedSize);
+        assertEquals(EXPECTED_LFH_OFFSET_VALUE, zip64Fields.localFileHeaderOffset);
+    }
+
+    @Test
+    public void parseExtraField_uncompressedInZip64_correctValuesReturned() throws Exception {
+        // This test verifies that the uncompressed size can be parsed in the Zip64 record when
+        // it is the only field in the record.
+        Zip64Fields zip64Fields =
+                new Zip64Fields(
+                        UINT32_MAX_VALUE, EXPECTED_COMPRESSED_VALUE, EXPECTED_LFH_OFFSET_VALUE);
+        ByteBuffer extra =
+                new ExtraBufferBuilder()
+                        .setPriorRecordSize(12)
+                        .setUncompressedSize(EXPECTED_UNCOMPRESSED_VALUE)
+                        .setNextRecordSize(8)
+                        .build();
+
+        ZipUtils.parseExtraField(extra, zip64Fields);
+
+        assertEquals(EXPECTED_UNCOMPRESSED_VALUE, zip64Fields.uncompressedSize);
+        assertEquals(EXPECTED_COMPRESSED_VALUE, zip64Fields.compressedSize);
+        assertEquals(EXPECTED_LFH_OFFSET_VALUE, zip64Fields.localFileHeaderOffset);
+    }
+
+    @Test
+    public void parseExtraField_bothSizeFieldsInZip64_correctValuesReturned() throws Exception {
+        // This test verifies that the uncompressed and compressed sizes can be parsed in the Zip64
+        // record when they are the only two fields in the record.
+        Zip64Fields zip64Fields =
+                new Zip64Fields(UINT32_MAX_VALUE, UINT32_MAX_VALUE, EXPECTED_LFH_OFFSET_VALUE);
+        ByteBuffer extra =
+                new ExtraBufferBuilder()
+                        .setPriorRecordSize(12)
+                        .setUncompressedSize(EXPECTED_UNCOMPRESSED_VALUE)
+                        .setCompressedSize(EXPECTED_COMPRESSED_VALUE)
+                        .setNextRecordSize(8)
+                        .build();
+
+        ZipUtils.parseExtraField(extra, zip64Fields);
+
+        assertEquals(EXPECTED_UNCOMPRESSED_VALUE, zip64Fields.uncompressedSize);
+        assertEquals(EXPECTED_COMPRESSED_VALUE, zip64Fields.compressedSize);
+        assertEquals(EXPECTED_LFH_OFFSET_VALUE, zip64Fields.localFileHeaderOffset);
+    }
+
+    @Test
+    public void parseExtraField_lfhOffsetInZip64_correctValuesReturned() throws Exception {
+        // This test verifies that the LFH offset can be parsed in the Zip64 record when
+        // it is the only field in the Zip64 record.
+        Zip64Fields zip64Fields =
+                new Zip64Fields(
+                        EXPECTED_UNCOMPRESSED_VALUE, EXPECTED_COMPRESSED_VALUE, UINT32_MAX_VALUE);
+        ByteBuffer extra =
+                new ExtraBufferBuilder()
+                        .setPriorRecordSize(12)
+                        .setLfhOffset(EXPECTED_LFH_OFFSET_VALUE)
+                        .setNextRecordSize(8)
+                        .build();
+
+        ZipUtils.parseExtraField(extra, zip64Fields);
+
+        assertEquals(EXPECTED_UNCOMPRESSED_VALUE, zip64Fields.uncompressedSize);
+        assertEquals(EXPECTED_COMPRESSED_VALUE, zip64Fields.compressedSize);
+        assertEquals(EXPECTED_LFH_OFFSET_VALUE, zip64Fields.localFileHeaderOffset);
+    }
+
+    @Test
+    public void parseExtraField_notAllFieldsInZip64_throwsException() throws Exception {
+        // This test verifies that if multiple fields are expected in the Zip64 record, but the
+        // record doesn't have enough space for all the data, the method throws an exception to
+        // report the invalid zip format.
+        Zip64Fields zip64Fields =
+                new Zip64Fields(UINT32_MAX_VALUE, UINT32_MAX_VALUE, UINT32_MAX_VALUE);
+        ByteBuffer extra =
+                new ExtraBufferBuilder()
+                        .setPriorRecordSize(12)
+                        .setUncompressedSize(EXPECTED_UNCOMPRESSED_VALUE)
+                        .setCompressedSize(EXPECTED_COMPRESSED_VALUE)
+                        .setNextRecordSize(8)
+                        .build();
+
+        assertThrows(ZipFormatException.class, () -> ZipUtils.parseExtraField(extra, zip64Fields));
+    }
+
+    @Test
+    public void parseExtraField_noZip64RecordOtherRecords_valuesNotChanged() throws Exception {
+        // This test verifies that if there is no Zip64 record in the extra field, then the
+        // original values in the zip64Fields remain unchanged.
+        Zip64Fields zip64Fields =
+                new Zip64Fields(UINT32_MAX_VALUE, UINT32_MAX_VALUE, UINT32_MAX_VALUE);
+        ByteBuffer extra =
+                new ExtraBufferBuilder().setPriorRecordSize(12).setNextRecordSize(8).build();
+
+        ZipUtils.parseExtraField(extra, zip64Fields);
+
+        assertEquals(UINT32_MAX_VALUE, zip64Fields.uncompressedSize);
+        assertEquals(UINT32_MAX_VALUE, zip64Fields.compressedSize);
+        assertEquals(UINT32_MAX_VALUE, zip64Fields.localFileHeaderOffset);
+    }
+
+    @Test
+    public void checkAndReturnZip64Value_headerValueNotInZip64_returnsExpectedValue()
+            throws Exception {
+        // This test verifies when a header value does not need to be stored in the Zip64 record,
+        // then the original value for the header field is returned.
+        long result =
+                ZipUtils.checkAndReturnZip64Value(
+                        EXPECTED_UNCOMPRESSED_VALUE,
+                        -1,
+                        "testRecord",
+                        ZIP64_UNCOMPRESSED_SIZE_FIELD_NAME);
+
+        assertEquals(EXPECTED_UNCOMPRESSED_VALUE, result);
+    }
+
+    @Test
+    public void checkAndReturnZip64Value_allValuesInZip64_returnsExpectedValues() throws Exception {
+        // This test simulates the behavior when all of the header fields are expected to be in the
+        // Zip64 record by checking and obtaining all values from the specified Zip64 value.
+        final String recordName = "testRecord";
+        long uncompressedSize =
+                ZipUtils.checkAndReturnZip64Value(
+                        UINT32_MAX_VALUE,
+                        EXPECTED_UNCOMPRESSED_VALUE,
+                        recordName,
+                        ZIP64_UNCOMPRESSED_SIZE_FIELD_NAME);
+        long compressedSize =
+                ZipUtils.checkAndReturnZip64Value(
+                        UINT32_MAX_VALUE,
+                        EXPECTED_COMPRESSED_VALUE,
+                        recordName,
+                        ZIP64_COMPRESSED_SIZE_FIELD_NAME);
+        long lfhOffset =
+                ZipUtils.checkAndReturnZip64Value(
+                        UINT32_MAX_VALUE,
+                        EXPECTED_LFH_OFFSET_VALUE,
+                        recordName,
+                        ZIP64_LFH_OFFSET_FIELD_NAME);
+
+        assertEquals(EXPECTED_UNCOMPRESSED_VALUE, uncompressedSize);
+        assertEquals(EXPECTED_COMPRESSED_VALUE, compressedSize);
+        assertEquals(EXPECTED_LFH_OFFSET_VALUE, lfhOffset);
+    }
+
+    @Test
+    public void checkAndReturnZip64Value_valueNotObtainedFromZip64Record_throwsException()
+            throws Exception {
+        // If a header field indicates the value should be stored in the Zip64 record, but a value
+        // cannot be obtained from this record, then an exception should be thrown to notify the
+        // caller.
+        assertThrows(
+                ZipFormatException.class,
+                () ->
+                        ZipUtils.checkAndReturnZip64Value(
+                                UINT32_MAX_VALUE,
+                                UINT32_MAX_VALUE,
+                                "testRecord",
+                                ZIP64_UNCOMPRESSED_SIZE_FIELD_NAME));
+    }
+
+    private static class ExtraBufferBuilder {
+        private int mPriorRecordSize = 0;
+        private int mNextRecordSize = 0;
+        private long mUncompressedSize = 0;
+        private long mCompressedSize = 0;
+        private long mLfhOffset = 0;
+
+        ByteBuffer build() {
+            int bufferCapacity = mPriorRecordSize + mNextRecordSize;
+            // If any of the Zip64 fields are set, then include the headers and specified blocks
+            // in the capacity.
+            short zip64PayloadSize = 0;
+            if (mUncompressedSize != 0 || mCompressedSize != 0 || mLfhOffset != 0) {
+                bufferCapacity += 4;
+                if (mUncompressedSize != 0) zip64PayloadSize += 8;
+                if (mCompressedSize != 0) zip64PayloadSize += 8;
+                if (mLfhOffset != 0) zip64PayloadSize += 8;
+            }
+            ByteBuffer extra = ByteBuffer.allocate(bufferCapacity + zip64PayloadSize);
+            extra.order(ByteOrder.LITTLE_ENDIAN);
+            if (mPriorRecordSize != 0) {
+                short priorRecordPayloadSize = (short) (mPriorRecordSize - 4);
+                extra.putShort((short) 0xabcd);
+                extra.putShort(priorRecordPayloadSize);
+                byte[] priorRecordPayload = new byte[priorRecordPayloadSize];
+                extra.put(priorRecordPayload);
+            }
+            if (zip64PayloadSize > 0) {
+                extra.putShort((short) ZIP64_RECORD_ID);
+                extra.putShort(zip64PayloadSize);
+                if (mUncompressedSize != 0) extra.putLong(mUncompressedSize);
+                if (mCompressedSize != 0) extra.putLong(mCompressedSize);
+                if (mLfhOffset != 0) extra.putLong(mLfhOffset);
+            }
+            if (mNextRecordSize != 0) {
+                short nextRecordPayloadSize = (short) (mNextRecordSize - 4);
+                // ApkSigner defines a header for alignment of the extra field; use that as the
+                // last field here since it will likely be seen in most APKs signed by apksig.
+                extra.putShort((short) 0xd935);
+                extra.putShort(nextRecordPayloadSize);
+                byte[] nextRecordPayload = new byte[nextRecordPayloadSize];
+                extra.put(nextRecordPayload);
+            }
+            extra.position(0);
+            return extra;
+        }
+
+        ExtraBufferBuilder setPriorRecordSize(int priorRecordSize) {
+            if (priorRecordSize < 4 || priorRecordSize > UINT16_MAX_VALUE) {
+                throw new RuntimeException(
+                        "A prior record size must be between 4 and " + UINT16_MAX_VALUE + " bytes");
+            }
+            mPriorRecordSize = priorRecordSize;
+            return this;
+        }
+
+        ExtraBufferBuilder setNextRecordSize(int nextRecordSize) {
+            if (nextRecordSize < 4 || nextRecordSize > UINT16_MAX_VALUE) {
+                throw new RuntimeException(
+                        "A next record size must be between 4 and " + UINT16_MAX_VALUE + " bytes");
+            }
+            mNextRecordSize = nextRecordSize;
+            return this;
+        }
+
+        ExtraBufferBuilder setUncompressedSize(long uncompressedSize) {
+            mUncompressedSize = uncompressedSize;
+            return this;
+        }
+
+        ExtraBufferBuilder setCompressedSize(long compressedSize) {
+            mCompressedSize = compressedSize;
+            return this;
+        }
+
+        ExtraBufferBuilder setLfhOffset(long lfhOffset) {
+            mLfhOffset = lfhOffset;
+            return this;
+        }
+    }
+}
diff --git a/src/test/resources/com/android/apksig/v1v2v3-with-zip64-records.apk b/src/test/resources/com/android/apksig/v1v2v3-with-zip64-records.apk
new file mode 100644
index 0000000..e4b3aae
Binary files /dev/null and b/src/test/resources/com/android/apksig/v1v2v3-with-zip64-records.apk differ
```

