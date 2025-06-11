```diff
diff --git a/EXPECTED_UPSTREAM b/EXPECTED_UPSTREAM
index 17a6c092f75..56b60ddc102 100644
--- a/EXPECTED_UPSTREAM
+++ b/EXPECTED_UPSTREAM
@@ -167,6 +167,7 @@ ojluni/src/main/java/java/lang/Integer.java,jdk21u/jdk-21.0.4-ga,src/java.base/s
 ojluni/src/main/java/java/lang/InternalError.java,jdk21u/jdk-21.0.4-ga,src/java.base/share/classes/java/lang/InternalError.java
 ojluni/src/main/java/java/lang/InterruptedException.java,jdk17u/jdk-17.0.6-ga,src/java.base/share/classes/java/lang/InterruptedException.java
 ojluni/src/main/java/java/lang/Iterable.java,jdk21u/jdk-21.0.4-ga,src/java.base/share/classes/java/lang/Iterable.java
+ojluni/src/main/java/java/lang/JavaLangAccess.java,jdk21u/jdk-21.0.6-ga,src/java.base/share/classes/jdk/internal/access/JavaLangAccess.java
 ojluni/src/main/java/java/lang/LinkageError.java,jdk21u/jdk-21.0.4-ga,src/java.base/share/classes/java/lang/LinkageError.java
 ojluni/src/main/java/java/lang/LiveStackFrame.java,jdk17u/jdk-17.0.6-ga,src/java.base/share/classes/java/lang/LiveStackFrame.java
 ojluni/src/main/java/java/lang/LiveStackFrameInfo.java,jdk21u/jdk-21.0.4-ga,src/java.base/share/classes/java/lang/LiveStackFrameInfo.java
@@ -311,6 +312,7 @@ ojluni/src/main/java/java/lang/reflect/UndeclaredThrowableException.java,jdk11u/
 ojluni/src/main/java/java/lang/reflect/WeakCache.java,jdk8u/jdk8u121-b13,jdk/src/share/classes/java/lang/reflect/WeakCache.java
 ojluni/src/main/java/java/lang/reflect/WildcardType.java,jdk11u/jdk-11.0.13-ga,src/java.base/share/classes/java/lang/reflect/WildcardType.java
 ojluni/src/main/java/java/lang/reflect/package-info.java,jdk8u/jdk8u121-b13,jdk/src/share/classes/java/lang/reflect/package-info.java
+ojluni/src/main/java/java/lang/runtime/ObjectMethods.java,jdk17u/jdk-17.0.10-ga,src/java.base/share/classes/java/lang/runtime/ObjectMethods.java
 ojluni/src/main/java/java/lang/runtime/SwitchBootstraps.java,jdk21u/jdk-21.0.4-ga,src/java.base/share/classes/java/lang/runtime/SwitchBootstraps.java
 ojluni/src/main/java/java/math/BigDecimal.java,jdk17u/jdk-17.0.6-ga,src/java.base/share/classes/java/math/BigDecimal.java
 ojluni/src/main/java/java/math/BigInteger.java,jdk17u/jdk-17.0.6-ga,src/java.base/share/classes/java/math/BigInteger.java
@@ -1411,7 +1413,6 @@ ojluni/src/main/java/javax/sql/StatementEventListener.java,jdk7u/jdk7u40-b60,jdk
 ojluni/src/main/java/jdk/internal/HotSpotIntrinsicCandidate.java,jdk11u/jdk-11.0.13-ga,src/java.base/share/classes/jdk/internal/HotSpotIntrinsicCandidate.java
 ojluni/src/main/java/jdk/internal/ValueBased.java,jdk21u/jdk-21.0.4-ga,src/java.base/share/classes/jdk/internal/ValueBased.java
 ojluni/src/main/java/jdk/internal/access/JavaIOFileDescriptorAccess.java,jdk21u/jdk-21.0.4-ga,src/java.base/share/classes/jdk/internal/access/JavaIOFileDescriptorAccess.java
-ojluni/src/main/java/jdk/internal/access/JavaLangAccess.java,jdk21u/jdk-21.0.4-ga,src/java.base/share/classes/jdk/internal/access/JavaLangAccess.java
 ojluni/src/main/java/jdk/internal/access/JavaObjectInputStreamAccess.java,jdk17u/jdk-17.0.6-ga,src/java.base/share/classes/jdk/internal/access/JavaObjectInputStreamAccess.java
 ojluni/src/main/java/jdk/internal/access/JavaUtilCollectionAccess.java,jdk21u/jdk-21.0.4-ga,src/java.base/share/classes/jdk/internal/access/JavaUtilCollectionAccess.java
 ojluni/src/main/java/jdk/internal/access/SharedSecrets.java,jdk17u/jdk-17.0.6-ga,src/java.base/share/classes/jdk/internal/access/SharedSecrets.java
@@ -1453,9 +1454,13 @@ ojluni/src/main/java/jdk/internal/util/StrongReferenceKey.java,jdk21u/jdk-21.0.4
 ojluni/src/main/java/jdk/internal/util/WeakReferenceKey.java,jdk21u/jdk-21.0.4-ga,src/java.base/share/classes/jdk/internal/util/WeakReferenceKey.java
 ojluni/src/main/java/jdk/internal/util/jar/JarIndex.java,jdk17u/jdk-17.0.5-ga,src/java.base/share/classes/jdk/internal/util/jar/JarIndex.java
 ojluni/src/main/java/jdk/internal/util/random/RandomSupport.java,jdk17u/jdk-17.0.6-ga,src/java.base/share/classes/jdk/internal/util/random/RandomSupport.java
+ojluni/src/main/java/jdk/internal/vm/Continuation.java,jdk21u/jdk-21.0.6-ga,src/java.base/share/classes/jdk/internal/vm/Continuation.java
+ojluni/src/main/java/jdk/internal/vm/ContinuationScope.java,jdk21u/jdk-21.0.6-ga,src/java.base/share/classes/jdk/internal/vm/ContinuationScope.java
 ojluni/src/main/java/jdk/internal/vm/StackChunk.java,jdk21u/jdk-21.0.4-ga,src/java.base/share/classes/jdk/internal/vm/StackChunk.java
 ojluni/src/main/java/jdk/internal/vm/annotation/Contended.java,jdk21u/jdk-21.0.4-ga,src/java.base/share/classes/jdk/internal/vm/annotation/Contended.java
+ojluni/src/main/java/jdk/internal/vm/annotation/DontInline.java,jdk21u/jdk-21.0.6-ga,src/java.base/share/classes/jdk/internal/vm/annotation/DontInline.java
 ojluni/src/main/java/jdk/internal/vm/annotation/ForceInline.java,jdk21u/jdk-21.0.4-ga,src/java.base/share/classes/jdk/internal/vm/annotation/ForceInline.java
+ojluni/src/main/java/jdk/internal/vm/annotation/Hidden.java,jdk21u/jdk-21.0.6-ga,src/java.base/share/classes/jdk/internal/vm/annotation/Hidden.java
 ojluni/src/main/java/jdk/internal/vm/annotation/IntrinsicCandidate.java,jdk21u/jdk-21.0.4-ga,src/java.base/share/classes/jdk/internal/vm/annotation/IntrinsicCandidate.java
 ojluni/src/main/java/jdk/internal/vm/annotation/ReservedStackAccess.java,jdk21u/jdk-21.0.4-ga,src/java.base/share/classes/jdk/internal/vm/annotation/ReservedStackAccess.java
 ojluni/src/main/java/jdk/internal/vm/annotation/Stable.java,jdk21u/jdk-21.0.4-ga,src/java.base/share/classes/jdk/internal/vm/annotation/Stable.java
@@ -1490,7 +1495,6 @@ ojluni/src/main/java/sun/misc/FpUtils.java,jdk8u/jdk8u121-b13,jdk/src/share/clas
 ojluni/src/main/java/sun/misc/HexDumpEncoder.java,jdk8u/jdk8u121-b13,jdk/src/share/classes/sun/misc/HexDumpEncoder.java
 ojluni/src/main/java/sun/misc/IOUtils.java,jdk8u/jdk8u121-b13,jdk/src/share/classes/sun/misc/IOUtils.java
 ojluni/src/main/java/sun/misc/InvalidJarIndexException.java,jdk8u/jdk8u121-b13,jdk/src/share/classes/sun/misc/InvalidJarIndexException.java
-ojluni/src/main/java/sun/misc/JavaIOFileDescriptorAccess.java,jdk8u/jdk8u121-b13,jdk/src/share/classes/sun/misc/JavaIOFileDescriptorAccess.java
 ojluni/src/main/java/sun/misc/LRUCache.java,jdk8u/jdk8u121-b13,jdk/src/share/classes/sun/misc/LRUCache.java
 ojluni/src/main/java/sun/misc/MessageUtils.java,jdk8u/jdk8u121-b13,jdk/src/share/classes/sun/misc/MessageUtils.java
 ojluni/src/main/java/sun/misc/Resource.java,jdk8u/jdk8u121-b13,jdk/src/share/classes/sun/misc/Resource.java
@@ -2082,6 +2086,8 @@ ojluni/src/test/java/lang/invoke/VarHandles/generate-vh-tests.sh,jdk11u/jdk-11.0
 ojluni/src/test/java/lang/ref/CleanerTest.java,jdk21u/jdk-21.0.4-ga,test/jdk/java/lang/ref/CleanerTest.java
 ojluni/src/test/java/lang/reflect/records/CheckEqualityIsBasedOnFields.java,jdk21u/jdk-21.0.4-ga,test/jdk/java/lang/reflect/records/CheckEqualityIsBasedOnFields.java
 ojluni/src/test/java/lang/reflect/records/RecordReflectionTest.java,jdk17u/jdk-17.0.6-ga,test/jdk/java/lang/reflect/records/RecordReflectionTest.java
+ojluni/src/test/java/lang/runtime/ObjectMethodsTest.java,jdk21u/jdk-21.0.4-ga,test/jdk/java/lang/runtime/ObjectMethodsTest.java
+ojluni/src/test/java/lang/runtime/SwitchBootstrapsTest.java,jdk21u/jdk-21.0.4-ga,test/jdk/java/lang/runtime/SwitchBootstrapsTest.java
 ojluni/src/test/java/math/BigDecimal/AddTests.java,jdk21u/jdk-21.0.4-ga,test/jdk/java/math/BigDecimal/AddTests.java
 ojluni/src/test/java/math/BigDecimal/CompareToTests.java,jdk21u/jdk-21.0.4-ga,test/jdk/java/math/BigDecimal/CompareToTests.java
 ojluni/src/test/java/math/BigDecimal/Constructor.java,jdk21u/jdk-21.0.4-ga,test/jdk/java/math/BigDecimal/Constructor.java
diff --git a/JavaLibrary.bp b/JavaLibrary.bp
index e8e3ccf4f90..a7e23325c53 100644
--- a/JavaLibrary.bp
+++ b/JavaLibrary.bp
@@ -182,7 +182,6 @@ java_defaults {
             "-Xep:GetClassOnClass:WARN",
             "-Xep:NullableOnContainingClass:WARN",
             "-Xep:GetClassOnAnnotation:WARN",
-            "-Xep:DoNotCall:WARN",
         ],
     },
     lint: {
@@ -214,6 +213,9 @@ java_library {
         ":core_libart_java_files",
         // framework-api-annotations contain API annotations, e.g. @SystemApi.
         ":framework-api-annotations",
+        // framework-metalava-annotations contain annotations output by Metalava
+        // in stubs, e.g. @android.annotation.Nullable.
+        ":framework-metalava-annotations",
         ":openjdk_lambda_stub_files",
         ":app-compat-annotations-source",
 
diff --git a/NativeCode.bp b/NativeCode.bp
index a1752b77d40..08e98a4fe25 100644
--- a/NativeCode.bp
+++ b/NativeCode.bp
@@ -75,7 +75,7 @@ cc_library_shared {
         "libz",
     ],
     static_libs: [
-        "libcrypto_for_art",
+        "libcrypto_static", // Not FIPS tested - for bignums only.
         "libziparchive",
     ],
     version_script: "libjavacore.map",
@@ -135,7 +135,7 @@ cc_defaults {
         "libz",
     ],
     static_libs: [
-        "libcrypto_for_art",
+        "libcrypto_static", // Not FIPS tested - for bignums only.
         "libfdlibm",
     ],
 
diff --git a/api/current.txt b/api/current.txt
index f11ad7dc659..3d62805a232 100644
--- a/api/current.txt
+++ b/api/current.txt
@@ -1,6 +1,22 @@
 // Signature format: 2.0
 package android.crypto.hpke {
 
+  @FlaggedApi("com.android.libcore.hpke_public_api") public class AeadParameterSpec extends java.security.spec.NamedParameterSpec {
+    field public static final android.crypto.hpke.AeadParameterSpec AES_128_GCM;
+    field public static final android.crypto.hpke.AeadParameterSpec AES_256_GCM;
+    field public static final android.crypto.hpke.AeadParameterSpec CHACHA20POLY1305;
+  }
+
+  @FlaggedApi("com.android.libcore.hpke_public_api") public class Hpke {
+    method @NonNull public static android.crypto.hpke.Hpke getInstance(@NonNull String) throws java.security.NoSuchAlgorithmException;
+    method @NonNull public static android.crypto.hpke.Hpke getInstance(@NonNull String, @NonNull String) throws java.security.NoSuchAlgorithmException, java.security.NoSuchProviderException;
+    method @NonNull public static android.crypto.hpke.Hpke getInstance(@NonNull String, @NonNull java.security.Provider) throws java.security.NoSuchAlgorithmException, java.security.NoSuchProviderException;
+    method @NonNull public java.security.Provider getProvider();
+    method @NonNull public static String getSuiteName(@NonNull android.crypto.hpke.KemParameterSpec, @NonNull android.crypto.hpke.KdfParameterSpec, @NonNull android.crypto.hpke.AeadParameterSpec);
+    method @NonNull public byte[] open(@NonNull java.security.PrivateKey, @Nullable byte[], @NonNull android.crypto.hpke.Message, @Nullable byte[]) throws java.security.GeneralSecurityException, java.security.InvalidKeyException;
+    method @NonNull public android.crypto.hpke.Message seal(@NonNull java.security.PublicKey, @Nullable byte[], @NonNull byte[], @Nullable byte[]) throws java.security.InvalidKeyException;
+  }
+
   public interface HpkeSpi {
     method @NonNull public byte[] engineExport(int, @Nullable byte[]);
     method public void engineInitRecipient(@NonNull byte[], @NonNull java.security.PrivateKey, @Nullable byte[], @Nullable java.security.PublicKey, @Nullable byte[], @Nullable byte[]) throws java.security.InvalidKeyException;
@@ -11,6 +27,57 @@ package android.crypto.hpke {
     method @NonNull public byte[] getEncapsulated();
   }
 
+  @FlaggedApi("com.android.libcore.hpke_public_api") public class KdfParameterSpec extends java.security.spec.NamedParameterSpec {
+    field public static final android.crypto.hpke.KdfParameterSpec HKDF_SHA256;
+    field public static final android.crypto.hpke.KdfParameterSpec HKDF_SHA384;
+    field public static final android.crypto.hpke.KdfParameterSpec HKDF_SHA512;
+  }
+
+  @FlaggedApi("com.android.libcore.hpke_public_api") public class KemParameterSpec extends java.security.spec.NamedParameterSpec {
+    field public static final android.crypto.hpke.KemParameterSpec DHKEM_P256_HKDF_SHA256;
+    field public static final android.crypto.hpke.KemParameterSpec DHKEM_P384_HKDF_SHA384;
+    field public static final android.crypto.hpke.KemParameterSpec DHKEM_P521_HKDF_SHA256;
+    field public static final android.crypto.hpke.KemParameterSpec DHKEM_X25519_HKDF_SHA256;
+    field public static final android.crypto.hpke.KemParameterSpec DHKEM_X448_HKDF_SHA512;
+  }
+
+  @FlaggedApi("com.android.libcore.hpke_public_api") public class Message {
+    ctor public Message(@NonNull byte[], @NonNull byte[]);
+    method @NonNull public byte[] getCiphertext();
+    method @NonNull public byte[] getEncapsulated();
+  }
+
+  @FlaggedApi("com.android.libcore.hpke_public_api") public class Recipient {
+    method @NonNull public byte[] export(int, @Nullable byte[]);
+    method @NonNull public java.security.Provider getProvider();
+    method @NonNull public android.crypto.hpke.HpkeSpi getSpi();
+    method @NonNull public byte[] open(@NonNull byte[], @Nullable byte[]) throws java.security.GeneralSecurityException;
+  }
+
+  @FlaggedApi("com.android.libcore.hpke_public_api") public static class Recipient.Builder {
+    ctor public Recipient.Builder(@NonNull android.crypto.hpke.Hpke, @NonNull byte[], @NonNull java.security.PrivateKey);
+    method @NonNull public android.crypto.hpke.Recipient build() throws java.security.InvalidKeyException;
+    method @NonNull public android.crypto.hpke.Recipient.Builder setApplicationInfo(@NonNull byte[]);
+    method @NonNull public android.crypto.hpke.Recipient.Builder setPsk(@NonNull byte[], @NonNull byte[]);
+    method @NonNull public android.crypto.hpke.Recipient.Builder setSenderKey(@NonNull java.security.PublicKey);
+  }
+
+  @FlaggedApi("com.android.libcore.hpke_public_api") public class Sender {
+    method @NonNull public byte[] export(int, @Nullable byte[]);
+    method @NonNull public byte[] getEncapsulated();
+    method @NonNull public java.security.Provider getProvider();
+    method @NonNull public android.crypto.hpke.HpkeSpi getSpi();
+    method @NonNull public byte[] seal(@NonNull byte[], @Nullable byte[]);
+  }
+
+  @FlaggedApi("com.android.libcore.hpke_public_api") public static class Sender.Builder {
+    ctor public Sender.Builder(@NonNull android.crypto.hpke.Hpke, @NonNull java.security.PublicKey);
+    method @NonNull public android.crypto.hpke.Sender build() throws java.security.InvalidKeyException;
+    method @NonNull public android.crypto.hpke.Sender.Builder setApplicationInfo(@NonNull byte[]);
+    method @NonNull public android.crypto.hpke.Sender.Builder setPsk(@NonNull byte[], @NonNull byte[]);
+    method @NonNull public android.crypto.hpke.Sender.Builder setSenderKey(@NonNull java.security.PrivateKey);
+  }
+
   public final class XdhKeySpec extends java.security.spec.EncodedKeySpec {
     ctor public XdhKeySpec(@NonNull byte[]);
     method @NonNull public String getFormat();
@@ -81,6 +148,7 @@ package android.system {
     method public static String[] listxattr(String) throws android.system.ErrnoException;
     method public static long lseek(java.io.FileDescriptor, long, int) throws android.system.ErrnoException;
     method public static android.system.StructStat lstat(String) throws android.system.ErrnoException;
+    method @FlaggedApi("com.android.libcore.madvise_api") public static void madvise(long, long, int) throws android.system.ErrnoException;
     method @NonNull public static java.io.FileDescriptor memfd_create(@NonNull String, int) throws android.system.ErrnoException;
     method public static void mincore(long, long, byte[]) throws android.system.ErrnoException;
     method public static void mkdir(String, int) throws android.system.ErrnoException;
@@ -386,6 +454,30 @@ package android.system {
     field public static final int IP_MULTICAST_TTL;
     field public static final int IP_TOS;
     field public static final int IP_TTL;
+    field @FlaggedApi("com.android.libcore.madvise_api") public static final int MADV_COLD;
+    field @FlaggedApi("com.android.libcore.madvise_api") public static final int MADV_COLLAPSE;
+    field @FlaggedApi("com.android.libcore.madvise_api") public static final int MADV_DODUMP;
+    field @FlaggedApi("com.android.libcore.madvise_api") public static final int MADV_DOFORK;
+    field @FlaggedApi("com.android.libcore.madvise_api") public static final int MADV_DONTDUMP;
+    field @FlaggedApi("com.android.libcore.madvise_api") public static final int MADV_DONTFORK;
+    field @FlaggedApi("com.android.libcore.madvise_api") public static final int MADV_DONTNEED;
+    field @FlaggedApi("com.android.libcore.madvise_api") public static final int MADV_FREE;
+    field @FlaggedApi("com.android.libcore.madvise_api") public static final int MADV_HUGEPAGE;
+    field @FlaggedApi("com.android.libcore.madvise_api") public static final int MADV_HWPOISON;
+    field @FlaggedApi("com.android.libcore.madvise_api") public static final int MADV_KEEPONFORK;
+    field @FlaggedApi("com.android.libcore.madvise_api") public static final int MADV_MERGEABLE;
+    field @FlaggedApi("com.android.libcore.madvise_api") public static final int MADV_NOHUGEPAGE;
+    field @FlaggedApi("com.android.libcore.madvise_api") public static final int MADV_NORMAL;
+    field @FlaggedApi("com.android.libcore.madvise_api") public static final int MADV_PAGEOUT;
+    field @FlaggedApi("com.android.libcore.madvise_api") public static final int MADV_POPULATE_READ;
+    field @FlaggedApi("com.android.libcore.madvise_api") public static final int MADV_POPULATE_WRITE;
+    field @FlaggedApi("com.android.libcore.madvise_api") public static final int MADV_RANDOM;
+    field @FlaggedApi("com.android.libcore.madvise_api") public static final int MADV_REMOVE;
+    field @FlaggedApi("com.android.libcore.madvise_api") public static final int MADV_SEQUENTIAL;
+    field @FlaggedApi("com.android.libcore.madvise_api") public static final int MADV_SOFT_OFFLINE;
+    field @FlaggedApi("com.android.libcore.madvise_api") public static final int MADV_UNMERGEABLE;
+    field @FlaggedApi("com.android.libcore.madvise_api") public static final int MADV_WILLNEED;
+    field @FlaggedApi("com.android.libcore.madvise_api") public static final int MADV_WIPEONFORK;
     field public static final int MAP_ANONYMOUS;
     field public static final int MAP_FIXED;
     field public static final int MAP_PRIVATE;
@@ -3355,6 +3447,8 @@ package java.lang {
     method public static int compare(float, float);
     method public int compareTo(@NonNull Float);
     method public double doubleValue();
+    method @FlaggedApi("com.android.libcore.openjdk_21_v1_apis") public static float float16ToFloat(short);
+    method @FlaggedApi("com.android.libcore.openjdk_21_v1_apis") public static short floatToFloat16(float);
     method public static int floatToIntBits(float);
     method public static int floatToRawIntBits(float);
     method public float floatValue();
@@ -3460,9 +3554,11 @@ package java.lang {
     method public static int compare(int, int);
     method public int compareTo(@NonNull Integer);
     method public static int compareUnsigned(int, int);
+    method @FlaggedApi("com.android.libcore.openjdk_21_v1_apis") public static int compress(int, int);
     method @NonNull public static Integer decode(@NonNull String) throws java.lang.NumberFormatException;
     method public static int divideUnsigned(int, int);
     method public double doubleValue();
+    method @FlaggedApi("com.android.libcore.openjdk_21_v1_apis") public static int expand(int, int);
     method public float floatValue();
     method @Nullable public static Integer getInteger(@NonNull String);
     method @Nullable public static Integer getInteger(@NonNull String, int);
@@ -3538,9 +3634,11 @@ package java.lang {
     method public static int compare(long, long);
     method public int compareTo(@NonNull Long);
     method public static int compareUnsigned(long, long);
+    method @FlaggedApi("com.android.libcore.openjdk_21_v1_apis") public static long compress(long, long);
     method @NonNull public static Long decode(@NonNull String) throws java.lang.NumberFormatException;
     method public static long divideUnsigned(long, long);
     method public double doubleValue();
+    method @FlaggedApi("com.android.libcore.openjdk_21_v1_apis") public static long expand(long, long);
     method public float floatValue();
     method @Nullable public static Long getLong(@NonNull String);
     method @Nullable public static Long getLong(@NonNull String, long);
@@ -4407,9 +4505,7 @@ package java.lang {
     ctor public Thread(@Nullable ThreadGroup, @Nullable Runnable, @NonNull String, long, boolean);
     method public static int activeCount();
     method @Deprecated @FlaggedApi("com.android.libcore.openjdk_21_v1_apis") public final void checkAccess();
-    method @Deprecated public int countStackFrames();
     method @NonNull public static Thread currentThread();
-    method @Deprecated public void destroy();
     method public static void dumpStack();
     method public static int enumerate(Thread[]);
     method @NonNull public static java.util.Map<java.lang.Thread,java.lang.StackTraceElement[]> getAllStackTraces();
@@ -4433,7 +4529,6 @@ package java.lang {
     method public final void join(long, int) throws java.lang.InterruptedException;
     method public final void join() throws java.lang.InterruptedException;
     method public static void onSpinWait();
-    method @Deprecated public final void resume();
     method public void run();
     method public void setContextClassLoader(@Nullable ClassLoader);
     method public final void setDaemon(boolean);
@@ -4445,8 +4540,6 @@ package java.lang {
     method public static void sleep(long, int) throws java.lang.InterruptedException;
     method public void start();
     method @Deprecated public final void stop();
-    method @Deprecated public final void stop(@Nullable Throwable);
-    method @Deprecated public final void suspend();
     method @FlaggedApi("com.android.libcore.openjdk_21_v1_apis") public final long threadId();
     method public static void yield();
     field public static final int MAX_PRIORITY = 10; // 0xa
@@ -5273,6 +5366,11 @@ package java.lang.runtime {
     method @NonNull public static Object bootstrap(@NonNull java.lang.invoke.MethodHandles.Lookup, @NonNull String, @NonNull java.lang.invoke.TypeDescriptor, @NonNull Class<?>, @Nullable String, @NonNull java.lang.invoke.MethodHandle...) throws java.lang.Throwable;
   }
 
+  @FlaggedApi("com.android.libcore.openjdk_21_v1_apis") public class SwitchBootstraps {
+    method public static java.lang.invoke.CallSite enumSwitch(java.lang.invoke.MethodHandles.Lookup, String, java.lang.invoke.MethodType, java.lang.Object...);
+    method public static java.lang.invoke.CallSite typeSwitch(java.lang.invoke.MethodHandles.Lookup, String, java.lang.invoke.MethodType, java.lang.Object...);
+  }
+
 }
 
 package java.math {
@@ -11470,6 +11568,7 @@ package java.time {
     method public long getSeconds();
     method public java.util.List<java.time.temporal.TemporalUnit> getUnits();
     method public boolean isNegative();
+    method @FlaggedApi("com.android.libcore.openjdk_21_v2_apis") public boolean isPositive();
     method public boolean isZero();
     method public java.time.Duration minus(java.time.Duration);
     method public java.time.Duration minus(long, java.time.temporal.TemporalUnit);
diff --git a/api/module-lib-current.txt b/api/module-lib-current.txt
index 951e0f5df26..064d35bc17f 100644
--- a/api/module-lib-current.txt
+++ b/api/module-lib-current.txt
@@ -276,6 +276,7 @@ package dalvik.system {
     method public static void dumpReferenceTables();
     method public static int getAllocCount(int);
     method @FlaggedApi("com.android.art.flags.executable_method_file_offsets") @Nullable public static dalvik.system.VMDebug.ExecutableMethodFileOffsets getExecutableMethodFileOffsets(@NonNull java.lang.reflect.Method);
+    method @FlaggedApi("com.android.art.flags.executable_method_file_offsets_v2") @Nullable public static dalvik.system.VMDebug.ExecutableMethodFileOffsets getExecutableMethodFileOffsets(@NonNull java.lang.reflect.Executable);
     method public static int getLoadedClassCount();
     method public static int getMethodTracingMode();
     method public static String getRuntimeStat(String);
@@ -292,7 +293,8 @@ package dalvik.system {
     method @FlaggedApi("com.android.libcore.appinfo") public static void setUserId(int);
     method @FlaggedApi("com.android.libcore.appinfo") public static void setWaitingForDebugger(boolean);
     method public static void startAllocCounting();
-    method @FlaggedApi("com.android.art.flags.always_enable_profile_code") public static void startLowOverheadTrace();
+    method @FlaggedApi("com.android.art.flags.always_enable_profile_code") public static void startLowOverheadTraceForAllMethods();
+    method @FlaggedApi("com.android.art.flags.always_enable_profile_code") public static void startLowOverheadTraceForLongRunningMethods(long);
     method public static void startMethodTracing(String, int, int, boolean, int);
     method public static void startMethodTracing(String, java.io.FileDescriptor, int, int, boolean, int, boolean);
     method public static void startMethodTracingDdms(int, int, boolean, int);
diff --git a/api/removed.txt b/api/removed.txt
index 9c70cefdd27..927c5724d62 100644
--- a/api/removed.txt
+++ b/api/removed.txt
@@ -6,5 +6,13 @@ package java.lang {
     method @Deprecated public java.io.OutputStream getLocalizedOutputStream(java.io.OutputStream);
   }
 
+  public class Thread implements java.lang.Runnable {
+    method @Deprecated public int countStackFrames();
+    method @Deprecated public void destroy();
+    method @Deprecated public final void resume();
+    method @Deprecated public final void stop(@Nullable Throwable);
+    method @Deprecated public final void suspend();
+  }
+
 }
 
diff --git a/benchmarks/Android.bp b/benchmarks/Android.bp
index ad8aaa5470a..0e652dd21e5 100644
--- a/benchmarks/Android.bp
+++ b/benchmarks/Android.bp
@@ -40,6 +40,10 @@ java_test {
             "-Xep:UnnecessaryStringBuilder:OFF",
         ],
     },
+    visibility: [
+        "//libcore:__subpackages__",
+        "//platform_testing:__subpackages__",
+    ],
 }
 
 android_test {
diff --git a/benchmarks/src_androidx/libcore/benchmark/MethodHandlesTest.java b/benchmarks/src_androidx/libcore/benchmark/MethodHandlesTest.java
index f5bcb544d95..c9b22a97c3e 100644
--- a/benchmarks/src_androidx/libcore/benchmark/MethodHandlesTest.java
+++ b/benchmarks/src_androidx/libcore/benchmark/MethodHandlesTest.java
@@ -38,12 +38,22 @@ public class MethodHandlesTest {
 
     private static final MethodHandle MH_1;
     private static final MethodHandle MH_0;
+    private static final MethodHandle FIELD_GETTER;
+    private static final MethodHandle FIELD_SETTER;
+    private static final MethodHandle STATIC_METHOD;
+
     static {
         try {
             MH_1 = MethodHandles.lookup()
                     .findVirtual(A.class, "identity", MethodType.methodType(int.class, int.class));
             MH_0 = MethodHandles.lookup()
                     .findVirtual(A.class, "constant", MethodType.methodType(int.class));
+            FIELD_GETTER = MethodHandles.lookup()
+                    .findGetter(A.class, "fField", long.class);
+            FIELD_SETTER = MethodHandles.lookup()
+                    .findSetter(A.class, "mField", long.class);
+            STATIC_METHOD = MethodHandles.lookup()
+                    .findStatic(A.class, "staticMethod", MethodType.methodType(int.class));
         } catch (ReflectiveOperationException ex) {
             throw new RuntimeException(ex);
         }
@@ -53,7 +63,7 @@ public class MethodHandlesTest {
     private int x1 = 10;
 
     @Test
-    public void directCall_noArguments() {
+    public void virtualCall_noArguments() {
         final BenchmarkState state = benchmarkRule.getState();
         while (state.keepRunning()) {
             a.constant();
@@ -61,7 +71,7 @@ public class MethodHandlesTest {
     }
 
     @Test
-    public void directCall_singleArgument() {
+    public void virtualCall_singleArgument() {
         final BenchmarkState state = benchmarkRule.getState();
         while (state.keepRunning()) {
             a.identity(x1);
@@ -69,23 +79,100 @@ public class MethodHandlesTest {
     }
 
     @Test
-    public void methodHandles_noArguments() throws Throwable {
+    public void staticCall() {
+        final BenchmarkState state = benchmarkRule.getState();
+        while (state.keepRunning()) {
+            A.staticMethod();
+        }
+    }
+
+    @Test
+    public void methodHandles_staticMethodCall() throws Throwable {
+        final BenchmarkState state = benchmarkRule.getState();
+        while (state.keepRunning()) {
+            int ignored = (int) STATIC_METHOD.invokeExact();
+        }
+    }
+
+    @Test
+    public void methodHandles_virtualMethod_noArguments() throws Throwable {
+        final BenchmarkState state = benchmarkRule.getState();
+        while (state.keepRunning()) {
+            int ignored = (int) MH_0.invokeExact(a);
+        }
+    }
+
+    @Test
+    public void methodHandles_virtualMethod_singleArgument() throws Throwable {
+        final BenchmarkState state = benchmarkRule.getState();
+        while (state.keepRunning()) {
+            int ignored = (int) MH_1.invokeExact(a, x1);
+        }
+    }
+
+    @Test
+    public void methodHandles_finalFieldGetter() throws Throwable {
+        final BenchmarkState state = benchmarkRule.getState();
+        while (state.keepRunning()) {
+            long ignored = (long) FIELD_GETTER.invokeExact(a);
+        }
+    }
+
+    @NeverInline
+    private long getter() {
+        return a.fField;
+    }
+
+    @Test
+    public void finalFieldGetter() throws Throwable {
         final BenchmarkState state = benchmarkRule.getState();
         while (state.keepRunning()) {
-            MH_0.invoke(a);
+            getter();
         }
     }
 
+    @NeverInline
+    private void setterMh() throws Throwable {
+        FIELD_SETTER.invokeExact(a, 10L);
+    }
+
     @Test
-    public void methodHandles_singleArgument() throws Throwable {
+    public void methodHandles_fieldSetter() throws Throwable {
         final BenchmarkState state = benchmarkRule.getState();
         while (state.keepRunning()) {
-            MH_1.invoke(a, x1);
+            setterMh();
+        }
+    }
+
+    @NeverInline
+    private void setter() {
+        a.mField = 10;
+    }
+
+    @Test
+    public void fieldSetter() throws Throwable {
+        final BenchmarkState state = benchmarkRule.getState();
+        while (state.keepRunning()) {
+            setter();
+        }
+    }
+
+    @NeverInline
+    private void noop() {}
+
+    @Test
+    public void testNoop() {
+        final BenchmarkState state = benchmarkRule.getState();
+        while (state.keepRunning()) {
+            noop();
         }
     }
 
     static class A {
 
+        final long fField = 42;
+        long mField = 0;
+
         @NeverInline
         public int constant() {
             return 42;
@@ -96,6 +183,11 @@ public class MethodHandlesTest {
             return a;
         }
 
+        @NeverInline
+        public static int staticMethod() {
+            return 1001;
+        }
+
     }
 
 }
diff --git a/dalvik/src/main/java/dalvik/annotation/compat/VersionCodes.java b/dalvik/src/main/java/dalvik/annotation/compat/VersionCodes.java
index 49b167983ac..47fc838c275 100644
--- a/dalvik/src/main/java/dalvik/annotation/compat/VersionCodes.java
+++ b/dalvik/src/main/java/dalvik/annotation/compat/VersionCodes.java
@@ -95,4 +95,10 @@ public class VersionCodes {
      */
     @IntraCoreApi
     public static final int VANILLA_ICE_CREAM = 35;
+
+    /**
+     * Baklava.
+     */
+    @IntraCoreApi
+    public static final int BAKLAVA = 36;
 }
diff --git a/dalvik/src/main/java/dalvik/system/DexFile.java b/dalvik/src/main/java/dalvik/system/DexFile.java
index 8d73604e000..039767941e6 100644
--- a/dalvik/src/main/java/dalvik/system/DexFile.java
+++ b/dalvik/src/main/java/dalvik/system/DexFile.java
@@ -591,17 +591,6 @@ public final class DexFile {
             boolean newProfile, boolean downgrade)
             throws FileNotFoundException, IOException;
 
-    /**
-     * Returns the status of the dex file {@code fileName}. The returned string is
-     * an opaque, human readable representation of the current status. The output
-     * is only meant for debugging and is not guaranteed to be stable across
-     * releases and/or devices.
-     *
-     * @hide
-     */
-    public static native String getDexFileStatus(String fileName, String instructionSet)
-        throws FileNotFoundException;
-
     /**
      * Encapsulates information about the optimizations performed on a dex file.
      *
diff --git a/dalvik/src/main/java/dalvik/system/VMDebug.java b/dalvik/src/main/java/dalvik/system/VMDebug.java
index fa7c206c5d2..04bb8cb3d8d 100644
--- a/dalvik/src/main/java/dalvik/system/VMDebug.java
+++ b/dalvik/src/main/java/dalvik/system/VMDebug.java
@@ -27,6 +27,7 @@ import libcore.util.Nullable;
 
 import java.io.FileDescriptor;
 import java.io.IOException;
+import java.lang.reflect.Executable;
 import java.lang.reflect.Method;
 import java.util.HashMap;
 import java.util.Map;
@@ -454,7 +455,7 @@ public final class VMDebug {
     }
 
     private static native @Nullable ExecutableMethodFileOffsets
-        getExecutableMethodFileOffsetsNative(Method javaMethod);
+        getExecutableMethodFileOffsetsNative(Executable javaMethod);
 
     /**
      * Fetches offset information about the location of the native executable code within the
@@ -473,6 +474,23 @@ public final class VMDebug {
         return getExecutableMethodFileOffsetsNative(javaMethod);
     }
 
+    /**
+     * Fetches offset information about the location of the native executable code within the
+     * running process' memory.
+     *
+     * @param javaExecutable executable for which info is to be identified.
+     * @return {@link ExecutableMethodFileOffsets} containing offset information for the specified
+     *         method, or null if the method is not AOT compiled.
+     * @throws RuntimeException for unexpected failures in ART retrieval of info.
+     *
+     * @hide
+     */
+    @SystemApi(client = MODULE_LIBRARIES)
+    public static @Nullable ExecutableMethodFileOffsets getExecutableMethodFileOffsets(
+            @NonNull Executable javaExecutable) {
+        return getExecutableMethodFileOffsetsNative(javaExecutable);
+    }
+
     /**
      * This method exists for binary compatibility.  It was part of
      * the allocation limits API which was removed in Android 3.0 (Honeycomb).
@@ -821,7 +839,11 @@ public final class VMDebug {
 
         /** @hide */
         public int getFd() {
-            return fd.getInt$();
+            if (fd != null) {
+                return fd.getInt$();
+            } else {
+                return -1;
+            }
         }
 
         /** @hide */
@@ -857,15 +879,15 @@ public final class VMDebug {
      * so it will only hold the most recently executed ones. The tracing is not precise.
      * If a low overhead tracing is already in progress then this request is ignored but an error
      * will be logged. The ongoing trace will not be impacted. For example, if there are two calls
-     * to {@link #startLowOverheadTrace} without a {@link #stopLowOverheadTrace} in between, the
-     * second request is ignored after logging an error. The first one will continue to trace until
-     * the next {@link #stopLowOverheadTrace} call.
+     * to {@link #startLowOverheadTraceForAllMethods} without a {@link #stopLowOverheadTrace} in
+     * between, the second request is ignored after logging an error. The first one will continue to
+     * trace until the next {@link #stopLowOverheadTrace} call.
      *
      * @hide
      */
     @SystemApi(client = MODULE_LIBRARIES)
-    public static void startLowOverheadTrace() {
-        startLowOverheadTraceImpl();
+    public static void startLowOverheadTraceForAllMethods() {
+        startLowOverheadTraceForAllMethodsImpl();
     }
 
     /**
@@ -900,9 +922,26 @@ public final class VMDebug {
         }
     }
 
-    private static native void startLowOverheadTraceImpl();
+    /**
+     * Start an ART trace of executed dex methods that execute longer than a set threshold.
+     * The threshold is defined by ART and isn't configurable. The tracing will be active
+     * for a maximum of trace_duration_ns passed to this function. If another trace (started by
+     * {@link #startLowOverheadTraceForAllMethods} /
+     * {@link #startLowOverheadTraceForLongRunningMethods} / {@link #startMethodTracing}) is running
+     * then this request is ignored and an error is logged.
+     *
+     * @hide
+     */
+    @SystemApi(client = MODULE_LIBRARIES)
+    public static void startLowOverheadTraceForLongRunningMethods(long traceDurationNs) {
+        startLowOverheadTraceForLongRunningMethodsImpl(traceDurationNs);
+    }
+
+
+    private static native void startLowOverheadTraceForAllMethodsImpl();
     private static native void stopLowOverheadTraceImpl();
     private static native void dumpLowOverheadTraceImpl(String traceFileName);
     private static native void dumpLowOverheadTraceFdImpl(int fd);
+    private static native void startLowOverheadTraceForLongRunningMethodsImpl(long traceDuration);
 
 }
diff --git a/dalvik/src/main/java/dalvik/system/ZygoteHooks.java b/dalvik/src/main/java/dalvik/system/ZygoteHooks.java
index f1de769e528..69c220710f3 100644
--- a/dalvik/src/main/java/dalvik/system/ZygoteHooks.java
+++ b/dalvik/src/main/java/dalvik/system/ZygoteHooks.java
@@ -21,19 +21,24 @@ import static android.annotation.SystemApi.Client.MODULE_LIBRARIES;
 import android.annotation.SystemApi;
 import android.icu.util.ULocale;
 
+import dalvik.annotation.compat.VersionCodes;
+
 import libcore.icu.DecimalFormatData;
 import libcore.icu.ICU;
+import libcore.icu.SimpleDateFormatData;
 
 import java.io.File;
 import java.io.FileDescriptor;
+import java.lang.reflect.Field;
+import java.lang.reflect.InvocationTargetException;
 import java.lang.reflect.Method;
 import java.lang.ClassNotFoundException;
 import java.lang.NoSuchMethodException;
 import java.lang.ReflectiveOperationException;
-import libcore.icu.SimpleDateFormatData;
+import java.text.Collator;
+import java.util.Locale;
 
 import sun.util.locale.BaseLocale;
-import java.util.Locale;
 
 /**
  * Provides hooks for the zygote to call back into the runtime to perform
@@ -72,6 +77,7 @@ public final class ZygoteHooks {
         ICU.initializeCacheInZygote();
         DecimalFormatData.initializeCacheInZygote();
         SimpleDateFormatData.initializeCacheInZygote();
+        Collator.getInstance();
 
         // Look up JaCoCo on the boot classpath, if it exists. This will be used later for enabling
         // memory-mapped Java coverage.
@@ -94,6 +100,36 @@ public final class ZygoteHooks {
      */
     @SystemApi(client = MODULE_LIBRARIES)
     public static void onEndPreload() {
+        // TODO(b/395108129): Switch to individual modules profile for preloading HttpEngine for
+        // devices from S -> V. This should be a cleaner way to do preloading without having the
+        // code live in libcore.
+        // This should not exist here but there's no other place to preload HttpEngine for devices
+        // predating Android B.
+        // SdkExtensionLevel 16 is where `preload` API was introduced to HttpEngine.
+        // Explicitly avoid calling this for B+ as it will be called in the ZygoteInit code.
+        if (VMRuntime.getSdkExtensionSLevel() >= 16
+                && VMRuntime.getSdkVersion() <= VersionCodes.VANILLA_ICE_CREAM) {
+            try {
+                // Reflection is used here because libcore must not depend explicitly on
+                // the connectivity module as this will create a cyclic dependency in the build
+                // graph. It's fine to call this method via reflection as it's a single static
+                // method.
+                Class.forName("android.net.http.HttpEngine").getMethod("preload").invoke(null);
+            } catch (ClassNotFoundException
+                    | NoSuchMethodException
+                    | IllegalAccessException
+                    | InvocationTargetException e) {
+                // ClassNotFoundException, NoSuchMethodException and IllegalAccessException should
+                // in theory never be thrown as we'll make sure that the method exists in the
+                // specified class and it's accessible always. Still, we swallow the exception as we
+                // don't want to crash the device on this. InvocationTargetException
+                // will be thrown as preloading HttpEngine more than once throws an exception.
+                // And this should never happen but at the moment, this will keep happening as
+                // HttpEngine is being preloaded twice from B+ path and this code path.
+                // This should go away once the SdkVersion gets bumped and the codepaths become
+                // disjoint.
+            }
+        }
         com.android.i18n.system.ZygoteHooks.onEndPreload();
 
         // Clone standard descriptors as originals closed / rebound during zygote post fork.
diff --git a/expectations/skippedCtsTest.txt b/expectations/skippedCtsTest.txt
index ef24a987e00..e44771a914f 100644
--- a/expectations/skippedCtsTest.txt
+++ b/expectations/skippedCtsTest.txt
@@ -65,6 +65,7 @@
     "description": "Test for internal APIs.",
     "names": [
       "libcore.jdk.internal.access.SharedSecretsTest",
+      "libcore.jdk.internal.misc.UnsafeTest",
       "libcore.libcore.icu.DateIntervalFormatTest",
       "libcore.libcore.icu.ICUTest",
       "libcore.libcore.icu.LocaleDataTest"
@@ -146,5 +147,27 @@
       "libcore.java.util.zip.ZipFileTest#test_FileNotFound",
       "org.apache.harmony.tests.java.util.zip.DeflaterTest#test_finalize"
     ]
+  },
+  {
+    "bug": 383977133,
+    "description": "The test asserts buggy or non-breaking behaviors, but the behavior has been fixed in a new mainline module version.",
+    "names": [
+      "libcore.java.util.TimeZoneTest#testPreHistoricInDaylightTime",
+      "org.apache.harmony.tests.java.text.SimpleDateFormatTest#test_formatLjava_util_DateLjava_lang_StringBufferLjava_text_FieldPosition",
+      "org.apache.harmony.tests.java.text.SimpleDateFormatTest#test_formatToCharacterIteratorLjava_lang_Object",
+      "org.apache.harmony.tests.java.text.SimpleDateFormatTest#test_format_time_zones",
+      "org.apache.harmony.tests.java.text.SimpleDateFormatTest#test_timeZoneFormatting",
+      "org.apache.harmony.tests.java.util.DateTest#test_parseLjava_lang_String",
+      "test.java.time.format.TestUnicodeExtension#test_shortTZID"
+    ]
+  },
+  {
+    "bug": 401130471,
+    "description": "The test asserts buggy or non-breaking behaviors, but the behavior has been fixed in a new mainline module version.",
+    "names": [
+      "libcore.java.lang.invoke.MethodHandlesTest#test_findConstructor",
+      "libcore.java.util.TimeZoneTest#testCustomZoneIds",
+      "libcore.libcore.io.BlockGuardOsTest#test_checkNewMethodsInPosix"
+    ]
   }
 ]
\ No newline at end of file
diff --git a/harmony-tests/src/test/java/org/apache/harmony/tests/java/nio/DirectByteBufferTest.java b/harmony-tests/src/test/java/org/apache/harmony/tests/java/nio/DirectByteBufferTest.java
index c754c7f0238..315ebc80dc4 100644
--- a/harmony-tests/src/test/java/org/apache/harmony/tests/java/nio/DirectByteBufferTest.java
+++ b/harmony-tests/src/test/java/org/apache/harmony/tests/java/nio/DirectByteBufferTest.java
@@ -128,4 +128,16 @@ public class DirectByteBufferTest extends ByteBufferTest {
         buf.setAccessible(true);
         buf.get(0);
     }
+
+    public void testAbsoluteBulkGet() {
+        buf = ByteBuffer.allocateDirect(1000);
+        for (int i = 0; i < buf.capacity(); i++) {
+            buf.put(i, (byte) i);
+        }
+        byte[] array = new byte[buf.capacity()];
+        buf.get(0, array, 0, array.length);
+        for (int i = 0; i < array.length; i++) {
+            assertEquals(array[i], (byte) i);
+        }
+    }
 }
diff --git a/harmony-tests/src/test/java/org/apache/harmony/tests/java/text/SimpleDateFormatTest.java b/harmony-tests/src/test/java/org/apache/harmony/tests/java/text/SimpleDateFormatTest.java
index c02b56e0266..beae449d065 100644
--- a/harmony-tests/src/test/java/org/apache/harmony/tests/java/text/SimpleDateFormatTest.java
+++ b/harmony-tests/src/test/java/org/apache/harmony/tests/java/text/SimpleDateFormatTest.java
@@ -16,6 +16,11 @@
  */
 package org.apache.harmony.tests.java.text;
 
+import libcore.test.annotation.NonCts;
+import libcore.test.annotation.NonMts;
+import libcore.test.reasons.NonCtsReasons;
+import libcore.test.reasons.NonMtsReasons;
+
 import java.text.DateFormat;
 import java.text.DateFormatSymbols;
 import java.text.FieldPosition;
@@ -230,6 +235,8 @@ public class SimpleDateFormatTest extends junit.framework.TestCase {
         assertFalse("objects has equal hash code", format2.hashCode() == format.hashCode());
     }
 
+    @NonCts(bug = 383977133, reason = NonCtsReasons.NON_BREAKING_BEHAVIOR_FIX)
+    @NonMts(bug = 383977133, reason = NonMtsReasons.TZDATA_VERSION_DEPENDENCY)
     public void test_formatToCharacterIteratorLjava_lang_Object() {
         try {
             // Regression for HARMONY-466
@@ -244,6 +251,8 @@ public class SimpleDateFormatTest extends junit.framework.TestCase {
                 .t_formatToCharacterIterator();
     }
 
+    @NonCts(bug = 383977133, reason = NonCtsReasons.NON_BREAKING_BEHAVIOR_FIX)
+    @NonMts(bug = 383977133, reason = NonMtsReasons.TZDATA_VERSION_DEPENDENCY)
     public void test_formatLjava_util_DateLjava_lang_StringBufferLjava_text_FieldPosition() {
         // Test for method java.lang.StringBuffer
         // java.text.SimpleDateFormat.format(java.util.Date,
@@ -406,19 +415,21 @@ public class SimpleDateFormatTest extends junit.framework.TestCase {
                 position.getEndIndex() == result.length());
     }
 
+    @NonCts(bug = 383977133, reason = NonCtsReasons.NON_BREAKING_BEHAVIOR_FIX)
+    @NonMts(bug = 383977133, reason = NonMtsReasons.TZDATA_VERSION_DEPENDENCY)
     public void test_format_time_zones() throws Exception {
         Calendar cal = new GregorianCalendar(1999, Calendar.JUNE, 2, 15, 3, 6);
 
         SimpleDateFormat format = new SimpleDateFormat("", Locale.ENGLISH);
         format.setTimeZone(TimeZone.getTimeZone("EST"));
-        assertFormat(format, " z", cal, " GMT-05:00", DateFormat.TIMEZONE_FIELD);
+        assertFormat(format, " z", cal, " EST", DateFormat.TIMEZONE_FIELD);
         Calendar temp2 = new GregorianCalendar(1999, Calendar.JANUARY, 12);
-        assertFormat(format, " z", temp2, " GMT-05:00", DateFormat.TIMEZONE_FIELD);
-        assertFormat(format, " zz", cal, " GMT-05:00", DateFormat.TIMEZONE_FIELD);
-        assertFormat(format, " zzz", cal, " GMT-05:00", DateFormat.TIMEZONE_FIELD);
-        assertFormat(format, " zzzz", cal, " GMT-05:00", DateFormat.TIMEZONE_FIELD);
-        assertFormat(format, " zzzz", temp2, " GMT-05:00", DateFormat.TIMEZONE_FIELD);
-        assertFormat(format, " zzzzz", cal, " GMT-05:00", DateFormat.TIMEZONE_FIELD);
+        assertFormat(format, " z", temp2, " EST", DateFormat.TIMEZONE_FIELD);
+        assertFormat(format, " zz", cal, " EST", DateFormat.TIMEZONE_FIELD);
+        assertFormat(format, " zzz", cal, " EST", DateFormat.TIMEZONE_FIELD);
+        assertFormat(format, " zzzz", cal, " Eastern Standard Time", DateFormat.TIMEZONE_FIELD);
+        assertFormat(format, " zzzz", temp2, " Eastern Standard Time", DateFormat.TIMEZONE_FIELD);
+        assertFormat(format, " zzzzz", cal, " Eastern Standard Time", DateFormat.TIMEZONE_FIELD);
 
         format.setTimeZone(TimeZone.getTimeZone("America/New_York"));
         assertFormat(format, " z", cal, " EDT", DateFormat.TIMEZONE_FIELD);
@@ -451,6 +462,8 @@ public class SimpleDateFormatTest extends junit.framework.TestCase {
         assertFormat(format, " z", cal, " GMT-01:30", DateFormat.TIMEZONE_FIELD);
     }
 
+    @NonCts(bug = 383977133, reason = NonCtsReasons.NON_BREAKING_BEHAVIOR_FIX)
+    @NonMts(bug = 383977133, reason = NonMtsReasons.TZDATA_VERSION_DEPENDENCY)
     public void test_timeZoneFormatting() {
         // tests specific to formatting of timezones
         Date summerDate = new GregorianCalendar(1999, Calendar.JUNE, 2, 15, 3, 6).getTime();
@@ -483,8 +496,8 @@ public class SimpleDateFormatTest extends junit.framework.TestCase {
                 "Pacific/Kiritimati", "GMT+14:00, Line Islands Time", "+1400, GMT+14:00",
                 winterDate);
 
-        verifyFormatTimezone("EST", "GMT-05:00, GMT-05:00", "-0500, GMT-05:00", summerDate);
-        verifyFormatTimezone("EST", "GMT-05:00, GMT-05:00", "-0500, GMT-05:00", winterDate);
+        verifyFormatTimezone("EST", "EST, Eastern Standard Time", "-0500, GMT-05:00", summerDate);
+        verifyFormatTimezone("EST", "EST, Eastern Standard Time", "-0500, GMT-05:00", winterDate);
 
         verifyFormatTimezone("GMT+14", "GMT+14:00, GMT+14:00", "+1400, GMT+14:00", summerDate);
         verifyFormatTimezone("GMT+14", "GMT+14:00, GMT+14:00", "+1400, GMT+14:00", winterDate);
diff --git a/harmony-tests/src/test/java/org/apache/harmony/tests/java/text/Support_SimpleDateFormat.java b/harmony-tests/src/test/java/org/apache/harmony/tests/java/text/Support_SimpleDateFormat.java
index b4e33de5f23..b479be32fc1 100644
--- a/harmony-tests/src/test/java/org/apache/harmony/tests/java/text/Support_SimpleDateFormat.java
+++ b/harmony-tests/src/test/java/org/apache/harmony/tests/java/text/Support_SimpleDateFormat.java
@@ -65,7 +65,7 @@ public class Support_SimpleDateFormat extends Support_Format {
     textBuffer.append("AD AD 1999 99 1999 9 09 Sep September 13 13 013 ");
     textBuffer.append("17 17 017 17 17 017 5 05 005 19 019 1 01 001 0 00 000 Mon Monday ");
     textBuffer.append("256 256 256 2 02 38 038 3 003 ");
-    textBuffer.append("PM  PM  5 005 GMT-05:00 GMT-05:00 -0500 GMT-05:00");
+    textBuffer.append("PM  PM  5 005 EST Eastern Standard Time -0500 GMT-05:00");
 
     // to avoid passing the huge StringBuffer each time.
     super.text = textBuffer.toString();
@@ -89,7 +89,7 @@ public class Support_SimpleDateFormat extends Support_Format {
     t_FormatWithField(14, format, date, null, Field.WEEK_OF_MONTH, 137, 138);
     t_FormatWithField(15, format, date, null, Field.AM_PM, 143, 145);
     t_FormatWithField(16, format, date, null, Field.HOUR0, 151, 152);
-    t_FormatWithField(17, format, date, null, Field.TIME_ZONE, 157, 166);
+    t_FormatWithField(17, format, date, null, Field.TIME_ZONE, 157, 160);
 
     // test fields that are not included in the formatted text
     t_FormatWithField(18, format, date, null, NumberFormat.Field.EXPONENT_SIGN, 0, 0);
@@ -97,10 +97,10 @@ public class Support_SimpleDateFormat extends Support_Format {
     // test with simple example
     format.applyPattern("h:m z");
 
-    super.text = "5:19 GMT-05:00";
+    super.text = "5:19 EST";
     t_FormatWithField(21, format, date, null, Field.HOUR1, 0, 1);
     t_FormatWithField(22, format, date, null, Field.MINUTE, 2, 4);
-    t_FormatWithField(23, format, date, null, Field.TIME_ZONE, 5, 14);
+    t_FormatWithField(23, format, date, null, Field.TIME_ZONE, 5, 8);
 
     // test fields that are not included in the formatted text
     t_FormatWithField(24, format, date, null, Field.ERA, 0, 0);
@@ -123,7 +123,7 @@ public class Support_SimpleDateFormat extends Support_Format {
 
     // test with simple example with pattern char Z
     format.applyPattern("h:m Z z");
-    super.text = "5:19 -0500 GMT-05:00";
+    super.text = "5:19 -0500 EST";
     t_FormatWithField(40, format, date, null, Field.HOUR1, 0, 1);
     t_FormatWithField(41, format, date, null, Field.MINUTE, 2, 4);
     t_FormatWithField(42, format, date, null, Field.TIME_ZONE, 5, 10);
@@ -184,7 +184,7 @@ public class Support_SimpleDateFormat extends Support_Format {
     Vector<FieldContainer> v = new Vector<FieldContainer>();
     v.add(new FieldContainer(0, 1, Field.HOUR1));
     v.add(new FieldContainer(2, 4, Field.MINUTE));
-    v.add(new FieldContainer(5, 14, Field.TIME_ZONE));
+    v.add(new FieldContainer(5, 8, Field.TIME_ZONE));
     return v;
   }
 
@@ -249,10 +249,10 @@ public class Support_SimpleDateFormat extends Support_Format {
     v.add(new FieldContainer(147, 149, Field.AM_PM));
     v.add(new FieldContainer(151, 152, Field.HOUR0));
     v.add(new FieldContainer(153, 156, Field.HOUR0));
-    v.add(new FieldContainer(157, 166, Field.TIME_ZONE));
-    v.add(new FieldContainer(167, 176, Field.TIME_ZONE));
-    v.add(new FieldContainer(177, 182, Field.TIME_ZONE));
-    v.add(new FieldContainer(183, 192, Field.TIME_ZONE));
+    v.add(new FieldContainer(157, 160, Field.TIME_ZONE));
+    v.add(new FieldContainer(161, 182, Field.TIME_ZONE));
+    v.add(new FieldContainer(183, 188, Field.TIME_ZONE));
+    v.add(new FieldContainer(189, 198, Field.TIME_ZONE));
     return v;
   }
 }
diff --git a/harmony-tests/src/test/java/org/apache/harmony/tests/java/util/DateTest.java b/harmony-tests/src/test/java/org/apache/harmony/tests/java/util/DateTest.java
index da25b960ecf..7a3e689ee64 100644
--- a/harmony-tests/src/test/java/org/apache/harmony/tests/java/util/DateTest.java
+++ b/harmony-tests/src/test/java/org/apache/harmony/tests/java/util/DateTest.java
@@ -19,6 +19,9 @@ package org.apache.harmony.tests.java.util;
 
 import android.icu.util.VersionInfo;
 
+import libcore.test.annotation.NonCts;
+import libcore.test.reasons.NonCtsReasons;
+
 import java.text.DateFormat;
 import java.util.Calendar;
 import java.util.Date;
@@ -300,6 +303,7 @@ public class DateTest extends junit.framework.TestCase {
     /**
      * java.util.Date#parse(java.lang.String)
      */
+    @NonCts(bug = 383977133, reason = NonCtsReasons.NON_BREAKING_BEHAVIOR_FIX)
     public void test_parseLjava_lang_String() {
         // Test for method long java.util.Date.parse(java.lang.String)
         Date d = new Date(Date.parse("13 October 1998"));
@@ -320,11 +324,11 @@ public class DateTest extends junit.framework.TestCase {
         cal.clear();
         cal.set(1969, Calendar.JANUARY, 12, 1, 0);
         assertTrue("Wrong parsed date 3", d.equals(cal.getTime()));
-        d = new Date(Date.parse("6:45:13 3/2/1200 MST"));
+        d = new Date(Date.parse("6:45:13 3/2/1900 MST"));
         cal.setTimeZone(TimeZone.getTimeZone("MST"));
         cal.clear();
-        cal.set(1200, 2, 2, 6, 45, 13);
-        assertTrue("Wrong parsed date 4", d.equals(cal.getTime()));
+        cal.set(1900, 2, 2, 6, 45, 13);
+        assertEquals("Wrong parsed date 4", d, cal.getTime());
         d = new Date(Date.parse("Mon, 22 Nov 1999 12:52:06 GMT"));
         cal.setTimeZone(TimeZone.getTimeZone("GMT"));
         cal.clear();
diff --git a/harmony-tests/src/test/java/org/apache/harmony/tests/org/apache/harmony/kernel/dalvik/ThreadsTest.java b/harmony-tests/src/test/java/org/apache/harmony/tests/org/apache/harmony/kernel/dalvik/ThreadsTest.java
index e8f1bc5d209..215ac970029 100644
--- a/harmony-tests/src/test/java/org/apache/harmony/tests/org/apache/harmony/kernel/dalvik/ThreadsTest.java
+++ b/harmony-tests/src/test/java/org/apache/harmony/tests/org/apache/harmony/kernel/dalvik/ThreadsTest.java
@@ -21,7 +21,7 @@ import java.util.concurrent.CyclicBarrier;
 import java.util.concurrent.TimeUnit;
 import junit.framework.Assert;
 import junit.framework.TestCase;
-import sun.misc.Unsafe;
+import jdk.internal.misc.Unsafe;
 
 /**
  * Tests for the <code>park()</code> functionality of {@link Unsafe}.
diff --git a/libart/src/main/java/dalvik/system/VMRuntime.java b/libart/src/main/java/dalvik/system/VMRuntime.java
index f03cb819abb..88cf8a3d30e 100644
--- a/libart/src/main/java/dalvik/system/VMRuntime.java
+++ b/libart/src/main/java/dalvik/system/VMRuntime.java
@@ -419,6 +419,8 @@ public final class VMRuntime {
     private static class SdkVersionContainer {
         // Similar to android.os.Build.VERSION.SDK_INT in the boot classpath, the default sdk is 0.
         private static final int sdkVersion = getSdkVersionNative(/*default_sdk_value=*/0);
+        private static final int sdkExtensionS =
+                getIntSystemProperty("build.version.extensions.s", /* defaultValue= */ 0);
     }
 
     /**
@@ -439,6 +441,23 @@ public final class VMRuntime {
         return SdkVersionContainer.sdkVersion;
     }
 
+    /**
+     * Gets the SDK extension for S of the software currently running on this hardware
+     * device. This value never changes while a device is booted, but it may
+     * increase when the hardware manufacturer provides an OTA update.
+     * <p>
+     *
+     * For use by the ART module. Please use android.os.ext.SdkExtensions if
+     * the usage is not in the ART module.
+     *
+     * @implNote This returns {@code "build.version.extensions.s"} system property on Android
+     *
+     * @hide
+     */
+    public static int getSdkExtensionSLevel() {
+        return SdkVersionContainer.sdkExtensionS;
+    }
+
     /**
      * Gets the target SDK version. See {@link #setTargetSdkVersion} for
      * special values.
@@ -453,6 +472,9 @@ public final class VMRuntime {
     }
 
     private native void setTargetSdkVersionNative(int targetSdkVersion);
+
+    @FastNative
+    private static native int getIntSystemProperty(String sdkExtensionName, int defaultValue);
     private native void setDisabledCompatChangesNative(long[] disabledCompatChanges);
 
     /**
diff --git a/libart/src/main/java/java/lang/invoke/StaticFieldVarHandle.java b/libart/src/main/java/java/lang/invoke/StaticFieldVarHandle.java
index c834d76b6a6..3b06df2e0a5 100644
--- a/libart/src/main/java/java/lang/invoke/StaticFieldVarHandle.java
+++ b/libart/src/main/java/java/lang/invoke/StaticFieldVarHandle.java
@@ -33,7 +33,7 @@ final class StaticFieldVarHandle extends FieldVarHandle {
 
     static StaticFieldVarHandle create(Field staticField) {
         assert Modifier.isStatic(staticField.getModifiers());
-        // TODO(b/379259800): should this be handled at the invocation?
+        // TODO(b/399619087): Make initialization lazy.
         MethodHandleStatics.UNSAFE.ensureClassInitialized(staticField.getDeclaringClass());
         return new StaticFieldVarHandle(staticField);
     }
diff --git a/libcore.aconfig b/libcore.aconfig
index df56a98948a..51c49b71a1e 100644
--- a/libcore.aconfig
+++ b/libcore.aconfig
@@ -48,6 +48,15 @@ flag {
     is_fixed_read_only: true
 }
 
+flag {
+    namespace: "core_libraries"
+    name: "openjdk_21_v2_apis"
+    is_exported: true
+    description: "This flag includes OpenJDK APIs released after 25Q2."
+    bug: "292585625"
+    is_fixed_read_only: true
+}
+
 flag {
     namespace: "core_libraries"
     name: "openjdk21_stringconcat"
@@ -116,3 +125,13 @@ flag {
     # APIs provided by a mainline module can only use a frozen flag.
     is_fixed_read_only: true
 }
+
+flag {
+    namespace: "core_libraries"
+    name: "madvise_api"
+    is_exported: true
+    description: "Java APIs to access madvise()"
+    bug: "383173082"
+    # APIs provided by a mainline module can only use a frozen flag.
+    is_fixed_read_only: true
+}
diff --git a/luni/annotations/flagged_api/dalvik/system/VMDebug.annotated.java b/luni/annotations/flagged_api/dalvik/system/VMDebug.annotated.java
index 1d2f19a8077..04e34a1ce82 100644
--- a/luni/annotations/flagged_api/dalvik/system/VMDebug.annotated.java
+++ b/luni/annotations/flagged_api/dalvik/system/VMDebug.annotated.java
@@ -103,7 +103,7 @@ public static class TraceDestination {
 }
 
 @android.annotation.FlaggedApi(com.android.art.flags.Flags.FLAG_ALWAYS_ENABLE_PROFILE_CODE)
-public static void startLowOverheadTrace();
+public static void startLowOverheadTraceForAllMethods();
 
 @android.annotation.FlaggedApi(com.android.art.flags.Flags.FLAG_ALWAYS_ENABLE_PROFILE_CODE)
 public static void stopLowOverheadTrace();
@@ -111,6 +111,9 @@ public static void stopLowOverheadTrace();
 @android.annotation.FlaggedApi(com.android.art.flags.Flags.FLAG_ALWAYS_ENABLE_PROFILE_CODE)
 public static void dumpLowOverheadTrace(@NonNull VMDebug.TraceDestination traceFileName);
 
+@android.annotation.FlaggedApi(com.android.art.flags.Flags.FLAG_ALWAYS_ENABLE_PROFILE_CODE)
+public static void startLowOverheadTraceForLongRunningMethods(long traceDuration);
+
 @android.annotation.FlaggedApi(com.android.art.flags.Flags.FLAG_EXECUTABLE_METHOD_FILE_OFFSETS)
 public static class ExecutableMethodFileOffsets {
   @android.annotation.FlaggedApi(com.android.art.flags.Flags.FLAG_EXECUTABLE_METHOD_FILE_OFFSETS)
@@ -125,6 +128,10 @@ public static class ExecutableMethodFileOffsets {
 public static VMDebug.ExecutableMethodFileOffsets getExecutableMethodFileOffsets(
         @NonNull java.lang.reflect.Method javaMethod);
 
+@android.annotation.FlaggedApi(com.android.art.flags.Flags.FLAG_EXECUTABLE_METHOD_FILE_OFFSETS_V2)
+public static VMDebug.ExecutableMethodFileOffsets getExecutableMethodFileOffsets(
+        @NonNull java.lang.reflect.Executable javaExecutable);
+
 public static final int KIND_ALL_COUNTS = -1; // 0xffffffff
 
 public static final int KIND_GLOBAL_ALLOCATED_BYTES = 2; // 0x2
diff --git a/luni/src/main/java/android/crypto/hpke/AeadParameterSpec.java b/luni/src/main/java/android/crypto/hpke/AeadParameterSpec.java
new file mode 100644
index 00000000000..49ad4b373b6
--- /dev/null
+++ b/luni/src/main/java/android/crypto/hpke/AeadParameterSpec.java
@@ -0,0 +1,50 @@
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
+package android.crypto.hpke;
+
+import android.annotation.FlaggedApi;
+
+import libcore.util.NonNull;
+
+import java.security.spec.NamedParameterSpec;
+
+/**
+ * Specifies algorithm parameters for the AEAD component of an HPKE suite
+ * which are determined by standard names as per RFC 9180.
+ * <p>
+ * These parameters can be composed into a full HKPE suite name using
+ * {@link Hpke#getSuiteName(KemParameterSpec, KdfParameterSpec, AeadParameterSpec)}.
+ *
+ * @see <a href="https://www.rfc-editor.org/rfc/rfc9180.html#section-7.3">RFC 9180 Section 7.3</a>
+ * @see NamedParameterSpec
+ */
+@FlaggedApi(com.android.libcore.Flags.FLAG_HPKE_PUBLIC_API)
+public class AeadParameterSpec extends NamedParameterSpec {
+    /**
+     * @see NamedParameterSpec
+     */
+    private AeadParameterSpec(@NonNull String stdName) {
+        super(stdName);
+    }
+
+    public static final AeadParameterSpec AES_128_GCM
+            = new AeadParameterSpec("AES_128_GCM");
+    public static final AeadParameterSpec AES_256_GCM
+            = new AeadParameterSpec("AES_256_GCM");
+    public static final AeadParameterSpec CHACHA20POLY1305
+            = new AeadParameterSpec("CHACHA20POLY1305");
+}
diff --git a/luni/src/main/java/android/crypto/hpke/DuckTypedHpkeSpi.java b/luni/src/main/java/android/crypto/hpke/DuckTypedHpkeSpi.java
new file mode 100644
index 00000000000..ee34e9e14d7
--- /dev/null
+++ b/luni/src/main/java/android/crypto/hpke/DuckTypedHpkeSpi.java
@@ -0,0 +1,176 @@
+/*
+ * Copyright (C) 2023 The Android Open Source Project
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
+ * limitations under the License
+ */
+
+package android.crypto.hpke;
+
+import java.lang.reflect.InvocationTargetException;
+import java.lang.reflect.Method;
+import java.security.GeneralSecurityException;
+import java.security.InvalidKeyException;
+import java.security.PrivateKey;
+import java.security.PublicKey;
+import java.util.HashMap;
+import java.util.Map;
+
+import libcore.util.NonNull;
+import libcore.util.Nullable;
+
+/**
+ * Duck typed implementation of {@link HpkeSpi}.
+ * <p>
+ * Will wrap any Object which implements all of the methods in HpkeSpi and delegate to them
+ * by reflection.
+ *
+ * @hide
+ */
+class DuckTypedHpkeSpi implements HpkeSpi {
+    private final Object delegate;
+    private final Map<String, Method> methods = new HashMap<>();
+
+    private DuckTypedHpkeSpi(Object delegate) throws NoSuchMethodException {
+        this.delegate = delegate;
+
+        Class<?> sourceClass = delegate.getClass();
+        for (Method targetMethod : HpkeSpi.class.getMethods()) {
+            if (targetMethod.isSynthetic()) {
+                continue;
+            }
+            if (targetMethod.getName().equals("engineInitSenderWithSeed")) {
+                // TODO(prb): resolve version skew here.  Non-urgent as we don't provide this
+                // test API from the Android platform HPKE API.
+                continue;
+            }
+
+            Method sourceMethod =
+                    sourceClass.getMethod(targetMethod.getName(), targetMethod.getParameterTypes());
+            // Check that the return types match too.
+            Class<?> sourceReturnType = sourceMethod.getReturnType();
+            Class<?> targetReturnType = targetMethod.getReturnType();
+            if (!targetReturnType.isAssignableFrom(sourceReturnType)) {
+                throw new NoSuchMethodException(sourceMethod + " return value (" + sourceReturnType
+                        + ") incompatible with target return value (" + targetReturnType + ")");
+            }
+            methods.put(sourceMethod.getName(), sourceMethod);
+        }
+    }
+
+    public static DuckTypedHpkeSpi newInstance(Object delegate) {
+        try {
+            return new DuckTypedHpkeSpi(delegate);
+        } catch (Exception ignored) {
+            return null;
+        }
+    }
+
+    private Object invoke(String methodName, Object... args) throws InvocationTargetException {
+        Method method = methods.get(methodName);
+        if (method == null) {
+            throw new IllegalStateException("DuckTypedHpkSpi internal error");
+        }
+        try {
+            return method.invoke(delegate, args);
+        } catch (IllegalAccessException e) {
+            throw new IllegalStateException("DuckTypedHpkSpi internal error", e);
+        } catch (InvocationTargetException e) {
+            if (e.getCause() instanceof RuntimeException){
+                throw (RuntimeException) e.getCause();
+            }
+            throw e;
+        }
+    }
+
+    private void invokeWithPossibleInvalidKey(String methodName, Object... args)
+            throws InvalidKeyException {
+        try {
+            invoke(methodName, args);
+        } catch (InvocationTargetException e) {
+            Throwable cause = e.getCause();
+            if (cause instanceof InvalidKeyException){
+                throw (InvalidKeyException) cause;
+            }
+            throw new IllegalStateException(cause);
+        }
+    }
+
+    private Object invokeWithPossibleGeneralSecurity(String methodName, Object... args)
+            throws GeneralSecurityException {
+        try {
+            return invoke(methodName, args);
+        } catch (InvocationTargetException e) {
+            Throwable cause = e.getCause();
+            if (cause instanceof GeneralSecurityException){
+                throw (GeneralSecurityException) cause;
+            }
+            throw new IllegalStateException(cause);
+        }
+    }
+
+    private Object invokeNoChecked(String methodName, Object... args) {
+        try {
+            return invoke(methodName, args);
+        } catch (InvocationTargetException e) {
+            throw new IllegalStateException(e.getCause());
+        }
+    }
+
+    // Visible for testing
+    public Object getDelegate() {
+        return delegate;
+    }
+
+    @Override
+    public void engineInitSender(
+            PublicKey recipientKey, byte[] info, PrivateKey senderKey, byte[] psk, byte[] pskId)
+            throws InvalidKeyException {
+        invokeWithPossibleInvalidKey("engineInitSender", recipientKey, info, senderKey, psk, pskId);
+    }
+
+    @Override
+    public void engineInitSenderWithSeed(
+            PublicKey recipientKey, @Nullable byte[] info, PrivateKey senderKey, @Nullable byte[] psk,
+            @Nullable byte[] psk_id, @NonNull byte[] seed) throws InvalidKeyException {
+        invokeWithPossibleInvalidKey("engineInitSenderForTesting",
+                recipientKey, info, senderKey, psk, psk_id, seed);
+
+    }
+
+    @Override
+    public void engineInitRecipient(byte[] encapsulated, PrivateKey key, byte[] info,
+            PublicKey senderKey, byte[] psk, byte[] psk_id) throws InvalidKeyException {
+        invokeWithPossibleInvalidKey(
+                "engineInitRecipient", encapsulated, key, info, senderKey, psk, psk_id);
+    }
+
+    @Override
+    public byte[] engineSeal(byte[] plaintext, byte[] aad) {
+        return (byte[]) invokeNoChecked("engineSeal", plaintext, aad);
+    }
+
+    @Override
+    public byte[] engineExport(int length, byte[] exporterContext) {
+        return (byte[]) invokeNoChecked("engineExport", length, exporterContext);
+    }
+
+    @Override
+    public byte[] engineOpen(byte[] ciphertext, byte[] aad) throws GeneralSecurityException {
+        return (byte[]) invokeWithPossibleGeneralSecurity("engineOpen", ciphertext, aad);
+    }
+
+    @Override
+    public byte[] getEncapsulated() {
+        return (byte[]) invokeNoChecked("getEncapsulated");
+    }
+}
diff --git a/luni/src/main/java/android/crypto/hpke/Hpke.java b/luni/src/main/java/android/crypto/hpke/Hpke.java
new file mode 100644
index 00000000000..11eb8ed08f3
--- /dev/null
+++ b/luni/src/main/java/android/crypto/hpke/Hpke.java
@@ -0,0 +1,252 @@
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
+package android.crypto.hpke;
+
+import android.annotation.FlaggedApi;
+
+import libcore.util.NonNull;
+import libcore.util.Nullable;
+
+import java.security.GeneralSecurityException;
+import java.security.InvalidKeyException;
+import java.security.NoSuchAlgorithmException;
+import java.security.NoSuchProviderException;
+import java.security.PrivateKey;
+import java.security.Provider;
+import java.security.PublicKey;
+import java.security.Security;
+
+/**
+ * Provides access to implementations of HPKE hybrid cryptography as per RFC 9180.
+ * <p>
+ * Provider and HPKE suite selection are done via the {@code getInstance}
+ * methods, and then instances of senders and receivers can be created using
+ * {@code newSender} or {newReceiver}.  Each sender and receiver is independent, i.e. does
+ * not share any encapsulated state with other senders or receivers created via this
+ * {@code Hpke}.
+ * <p>
+ * HPKE suites are composed of a key encapsulation mechanism (KEM), a key derivation
+ * function (KDF) and an authenticated cipher algorithm (AEAD) as defined in
+ * RFC 9180 section 7. {@link java.security.spec.NamedParameterSpec NamedParameterSpecs} for
+ * these can be found in {@link KemParameterSpec}, {@link KdfParameterSpec} and
+ * {@link AeadParameterSpec}.  These can be composed into a full HPKE suite name used to
+ * request a particular implementation using
+ * {@link Hpke#getSuiteName(KemParameterSpec, KdfParameterSpec, AeadParameterSpec)}.
+ *
+ * @see KemParameterSpec
+ * @see KdfParameterSpec
+ * @see AeadParameterSpec
+ */
+@SuppressWarnings("NewApi") // Public HPKE classes are always all present together.
+@FlaggedApi(com.android.libcore.Flags.FLAG_HPKE_PUBLIC_API)
+public class Hpke {
+    private static final String SERVICE_NAME = "ConscryptHpke";
+    static final byte[] DEFAULT_PSK = new byte[0];
+    static final byte[] DEFAULT_PSK_ID = DEFAULT_PSK;
+    private final Provider provider;
+    private final Provider.Service service;
+
+    private Hpke(@NonNull String suiteName, @NonNull Provider provider)
+            throws NoSuchAlgorithmException {
+        this.provider = provider;
+        service = getService(provider, suiteName);
+        if (service == null) {
+            throw new NoSuchAlgorithmException("No such HPKE suite: " + suiteName);
+        }
+    }
+
+    private static @NonNull Provider findFirstProvider(@NonNull String suiteName)
+            throws NoSuchAlgorithmException {
+        for (Provider provider : Security.getProviders()) {
+            if (getService(provider, suiteName) != null) {
+                return provider;
+            }
+        }
+        throw new NoSuchAlgorithmException("No Provider found for HPKE suite: " + suiteName);
+    }
+
+    @SuppressWarnings("InlinedApi") // For SERVICE_NAME field which belongs to this class
+    private static Provider.Service getService(Provider provider, String suiteName)
+            throws NoSuchAlgorithmException {
+        if (suiteName == null || suiteName.isEmpty()) {
+            throw new NoSuchAlgorithmException();
+        }
+        return provider.getService(SERVICE_NAME, suiteName);
+    }
+
+    @NonNull HpkeSpi findSpi() {
+        Object instance;
+        try {
+            instance = service.newInstance(null);
+        } catch (NoSuchAlgorithmException e) {
+            throw new IllegalStateException("Initialisation error", e);
+        }
+        if (instance instanceof HpkeSpi) {
+            return (HpkeSpi) instance;
+        } else {
+            DuckTypedHpkeSpi spi = DuckTypedHpkeSpi.newInstance(instance);
+            if (spi != null) {
+                return spi;
+            }
+        }
+        throw new IllegalStateException(
+                String.format("Provider %s is incorrectly configured", provider.getName()));
+    }
+
+    /**
+     * Returns the {@link Provider} being used by this Hpke instance.
+     * <p>
+     *
+     * @return the Provider
+     */
+    public @NonNull Provider getProvider() {
+        return provider;
+    }
+
+    /**
+     * Returns an Hpke instance configured for the requested HPKE suite, using the
+     * highest priority {@link Provider} which implements it.
+     * <p>
+     * Use {@link Hpke#getSuiteName(KemParameterSpec, KdfParameterSpec, AeadParameterSpec)} for
+     * generating HPKE suite names from {@link java.security.spec.NamedParameterSpec
+     * NamedParameterSpecs}
+     *
+     * @param suiteName the HPKE suite to use
+     * @return an Hpke instance configured for the requested suite
+     * @throws NoSuchAlgorithmException if no Providers can be found for the requested suite
+     */
+    public static @NonNull Hpke getInstance(@NonNull String suiteName)
+            throws NoSuchAlgorithmException {
+        return new Hpke(suiteName, findFirstProvider(suiteName));
+    }
+
+    /**
+     * Returns an Hpke instance configured for the requested HPKE suite, using the
+     * requested {@link Provider} by name.
+     *
+     * @param suiteName    the HPKE suite to use
+     * @param providerName the name of the provider to use
+     * @return an Hpke instance configured for the requested suite and Provider
+     * @throws NoSuchAlgorithmException if the named Provider does not implement this suite
+     * @throws NoSuchProviderException  if no Provider with the requested name can be found
+     * @throws IllegalArgumentException if providerName is null or empty
+     */
+    public static @NonNull Hpke getInstance(@NonNull String suiteName, @NonNull String providerName)
+            throws NoSuchAlgorithmException, NoSuchProviderException {
+        if (providerName == null || providerName.isEmpty()) {
+            throw new IllegalArgumentException("Invalid Provider Name");
+        }
+        Provider provider = Security.getProvider(providerName);
+        if (provider == null) {
+            throw new NoSuchProviderException();
+        }
+        return new Hpke(suiteName, provider);
+    }
+
+    /**
+     * Returns an Hpke instance configured for the requested HPKE suite, using the
+     * requested {@link Provider}.
+     *
+     * @param suiteName the HPKE suite to use
+     * @param provider  the provider to use
+     * @return an Hpke instance configured for the requested suite and Provider
+     * @throws NoSuchAlgorithmException if the Provider does not implement this suite
+     * @throws IllegalArgumentException if provider is null
+     */
+    public static @NonNull Hpke getInstance(@NonNull String suiteName, @NonNull Provider provider)
+            throws NoSuchAlgorithmException, NoSuchProviderException {
+        if (provider == null) {
+            throw new IllegalArgumentException("Null Provider");
+        }
+        return new Hpke(suiteName, provider);
+    }
+
+    /**
+     * Generates a full HPKE suite name from the named parameter specifications of its components,
+     * which have names reflecting their usage in RFC 9180.
+     * <p>
+     * HPKE suites are composed of a key encapsulation mechanism (KEM), a key derivation
+     * function (KDF) and an authenticated cipher algorithm (AEAD) as defined in
+     * RFC 9180 section 7. {@link java.security.spec.NamedParameterSpec NamedParameterSpecs} for
+     * these can be foundu in {@link KemParameterSpec}, {@link KdfParameterSpec} and
+     * {@link AeadParameterSpec}.
+     *
+     * @see <a href="https://www.rfc-editor.org/rfc/rfc9180.html#section-7">RFC 9180 Section 7</a>
+     * @see KemParameterSpec
+     * @see KdfParameterSpec
+     * @see AeadParameterSpec
+     *
+     * @param kem  the key encapsulation mechanism to use
+     * @param kdf  the key derivation function to use
+     * @param aead the AEAD cipher to use
+     * @return a fully composed HPKE suite name
+     */
+    public static @NonNull String getSuiteName(@NonNull KemParameterSpec kem,
+            @NonNull KdfParameterSpec kdf, @NonNull AeadParameterSpec aead) {
+        return kem.getName() + "/" + kdf.getName() + "/" + aead.getName();
+    }
+
+    /**
+     * One shot API to seal a single message using BASE mode (no authentication).
+     *
+     * @see <a href="https://www.rfc-editor.org/rfc/rfc9180.html#name-encryption-and-decryption-2">
+     *     Opening and sealing</a>
+     * @param recipientKey public key of the recipient
+     * @param info         additional application-supplied information, may be null or empty
+     * @param plaintext    the message to send
+     * @param aad          optional additional authenticated data, may be null or empty
+     * @return a Message object containing the encapsulated key, ciphertext and aad
+     * @throws InvalidKeyException      if recipientKey is null or an unsupported key format
+     */
+    public @NonNull Message seal(@NonNull PublicKey recipientKey, @Nullable byte[] info,
+            @NonNull byte[] plaintext, @Nullable byte[] aad)
+            throws InvalidKeyException {
+        Sender.Builder senderBuilder = new Sender.Builder(this, recipientKey);
+        if (info != null) {
+            senderBuilder.setApplicationInfo(info);
+        }
+        Sender sender = senderBuilder.build();
+        byte[] encapsulated = sender.getEncapsulated();
+        byte[] ciphertext = sender.seal(plaintext, aad);
+        return new Message(encapsulated, ciphertext);
+    }
+
+    /**
+     * One shot API to open a single ciphertext using BASE mode (no authentication).
+     *
+     * @see <a href="https://www.rfc-editor.org/rfc/rfc9180.html#name-encryption-and-decryption-2">
+     *     Opening and sealing</a>
+     * @param recipientKey private key of the recipient
+     * @param info         application-supplied information, may be null or empty
+     * @param message      the Message to open
+     * @param aad          optional additional authenticated data, may be null or empty
+     * @return decrypted plaintext
+     * @throws InvalidKeyException      if recipientKey is null or an unsupported key format
+     * @throws GeneralSecurityException if the decryption fails
+     */
+    public @NonNull byte[] open(
+            @NonNull PrivateKey recipientKey, @Nullable byte[] info, @NonNull Message message,
+            @Nullable byte[] aad)
+            throws GeneralSecurityException, InvalidKeyException {
+        Recipient.Builder recipientBuilder
+                = new Recipient.Builder(this, message.getEncapsulated(), recipientKey);
+        if (info != null) {
+            recipientBuilder.setApplicationInfo(info);
+        }
+        return recipientBuilder.build().open(message.getCiphertext(), aad);
+    }
+}
diff --git a/luni/src/main/java/android/crypto/hpke/KdfParameterSpec.java b/luni/src/main/java/android/crypto/hpke/KdfParameterSpec.java
new file mode 100644
index 00000000000..08afaf60493
--- /dev/null
+++ b/luni/src/main/java/android/crypto/hpke/KdfParameterSpec.java
@@ -0,0 +1,51 @@
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
+package android.crypto.hpke;
+
+import android.annotation.FlaggedApi;
+
+import libcore.util.NonNull;
+
+import java.security.spec.NamedParameterSpec;
+
+/**
+ * Specifies algorithm parameters for the KDF component of an HPKE suite
+ * which are determined by standard names as per RFC 9180.
+ * <p>
+ * These parameters can be composed into a full HKPE suite name using
+ * {@link Hpke#getSuiteName(KemParameterSpec, KdfParameterSpec, AeadParameterSpec)}.
+ * <p>
+ * Note that currently only {@code HKDF_SHA256} is implemented.
+ *
+ * @see <a href="https://www.rfc-editor.org/rfc/rfc9180.html#section-7.2">RFC 9180 Section 7.2</a>
+ * @see NamedParameterSpec
+ */
+@FlaggedApi(com.android.libcore.Flags.FLAG_HPKE_PUBLIC_API)
+public class KdfParameterSpec extends NamedParameterSpec {
+    /**
+     * @see NamedParameterSpec
+     */
+    private KdfParameterSpec(@NonNull String stdName) {
+        super(stdName);
+    }
+
+    public static final KdfParameterSpec HKDF_SHA256 = new KdfParameterSpec("HKDF_SHA256");
+
+    public static final KdfParameterSpec HKDF_SHA384 = new KdfParameterSpec("HKDF_SHA384");
+
+    public static final KdfParameterSpec HKDF_SHA512 = new KdfParameterSpec("HKDF_SHA512");
+}
diff --git a/luni/src/main/java/android/crypto/hpke/KemParameterSpec.java b/luni/src/main/java/android/crypto/hpke/KemParameterSpec.java
new file mode 100644
index 00000000000..7c39673271a
--- /dev/null
+++ b/luni/src/main/java/android/crypto/hpke/KemParameterSpec.java
@@ -0,0 +1,61 @@
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
+package android.crypto.hpke;
+
+import android.annotation.FlaggedApi;
+
+import libcore.util.NonNull;
+
+import java.security.spec.NamedParameterSpec;
+
+/**
+ * Specifies algorithm parameters for the KEM component of an HPKE suite
+ * which are determined by standard names as per RFC 9180.
+ * <p>
+ * These parameters can be composed into a full HKPE suite name using
+ * {@link Hpke#getSuiteName(KemParameterSpec, KdfParameterSpec, AeadParameterSpec)}.
+ * <p>
+ * Note that currently only {@code DHKEM_X25519_HKDF_SHA256} is implemented.
+ *
+ * @see <a href="https://www.rfc-editor.org/rfc/rfc9180.html#section-7.1">RFC 9180 Section 7.1</a>
+ * @see NamedParameterSpec
+ */
+@FlaggedApi(com.android.libcore.Flags.FLAG_HPKE_PUBLIC_API)
+public class KemParameterSpec extends NamedParameterSpec {
+    /**
+     * @see NamedParameterSpec
+     */
+    private KemParameterSpec(@NonNull String stdName) {
+        super(stdName);
+    }
+
+    public static final KemParameterSpec DHKEM_P256_HKDF_SHA256
+            = new KemParameterSpec("DHKEM_P256_HKDF_SHA256");
+
+    public static final KemParameterSpec DHKEM_P384_HKDF_SHA384
+            = new KemParameterSpec("DHKEM_P384_HKDF_SHA384");
+
+    public static final KemParameterSpec DHKEM_P521_HKDF_SHA256
+            = new KemParameterSpec("DHKEM_P521_HKDF_SHA256");
+
+    public static final KemParameterSpec DHKEM_X25519_HKDF_SHA256
+            = new KemParameterSpec("DHKEM_X25519_HKDF_SHA256");
+
+    public static final KemParameterSpec DHKEM_X448_HKDF_SHA512
+            = new KemParameterSpec("DHKEM_X448_HKDF_SHA512");
+
+}
diff --git a/luni/src/main/java/android/crypto/hpke/Message.java b/luni/src/main/java/android/crypto/hpke/Message.java
new file mode 100644
index 00000000000..16c009b5b65
--- /dev/null
+++ b/luni/src/main/java/android/crypto/hpke/Message.java
@@ -0,0 +1,41 @@
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
+package android.crypto.hpke;
+
+import android.annotation.FlaggedApi;
+
+import libcore.util.NonNull;
+
+@FlaggedApi(com.android.libcore.Flags.FLAG_HPKE_PUBLIC_API)
+public class Message {
+    private final byte[] encapsulated;
+    private final byte[] ciphertext;
+
+    public Message(
+            @NonNull byte[] encapsulated, @NonNull byte[] ciphertext) {
+        this.encapsulated = encapsulated;
+        this.ciphertext = ciphertext;
+    }
+
+    public @NonNull byte[] getEncapsulated() {
+        return encapsulated;
+    }
+
+    public @NonNull byte[] getCiphertext() {
+        return ciphertext;
+    }
+}
diff --git a/luni/src/main/java/android/crypto/hpke/Recipient.java b/luni/src/main/java/android/crypto/hpke/Recipient.java
new file mode 100644
index 00000000000..e85a8b815bd
--- /dev/null
+++ b/luni/src/main/java/android/crypto/hpke/Recipient.java
@@ -0,0 +1,174 @@
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
+package android.crypto.hpke;
+
+import android.annotation.FlaggedApi;
+
+import libcore.util.NonNull;
+import libcore.util.Nullable;
+
+import java.security.GeneralSecurityException;
+import java.security.InvalidKeyException;
+import java.security.PrivateKey;
+import java.security.Provider;
+import java.security.PublicKey;
+import java.util.Objects;
+
+/**
+ * A class for receiving HPKE messages.
+ */
+@SuppressWarnings("NewApi") // Public HPKE classes are always all present together.
+@FlaggedApi(com.android.libcore.Flags.FLAG_HPKE_PUBLIC_API)
+public class Recipient {
+    private final Hpke hpke;
+    private final HpkeSpi spi;
+
+    Recipient(@NonNull Hpke hpke, @NonNull HpkeSpi spi) {
+        this.hpke = hpke;
+        this.spi = spi;
+    }
+
+    /**
+     * Opens a message, using the internal key schedule maintained by this Recipient.
+     *
+     * @see <a href="https://www.rfc-editor.org/rfc/rfc9180.html#name-encryption-and-decryption-2">
+     *     Opening and sealing</a>
+     * @param ciphertext the ciphertext
+     * @param aad        optional additional authenticated data, may be null or empty
+     * @return the plaintext
+     * @throws GeneralSecurityException on decryption failures
+     */
+    public @NonNull byte[] open(@NonNull byte[] ciphertext, @Nullable byte[] aad)
+            throws GeneralSecurityException {
+        return spi.engineOpen(ciphertext, aad);
+    }
+
+    /**
+     * Exports secret key material from this Recipient as described in RFC 9180.
+     *
+     * @param length  expected output length
+     * @param context optional exporter context string, may be null or empty
+     * @return exported value
+     * @throws IllegalArgumentException if the length is not valid for the KDF in use
+     */
+    public @NonNull byte[] export(int length, @Nullable byte[] context) {
+        return spi.engineExport(length, context);
+    }
+
+    /**
+     * Returns the {@link HpkeSpi} being used by this Recipient.
+     *
+     * @return the SPI
+     */
+    public @NonNull HpkeSpi getSpi() {
+        return spi;
+    }
+
+    /**
+     * Returns the {@link Provider} being used by this Recipient.
+     *
+     * @return the Provider
+     */
+    public @NonNull Provider getProvider() {
+        return hpke.getProvider();
+    }
+
+    /**
+     * A builder for HPKE Recipient objects.
+     */
+    @FlaggedApi(com.android.libcore.Flags.FLAG_HPKE_PUBLIC_API)
+    public static class Builder {
+        private final Hpke hpke;
+        private final byte[] encapsulated ;
+        private final PrivateKey recipientKey;
+        private byte[] applicationInfo = null;
+        private PublicKey senderKey = null;
+        private byte[] psk = Hpke.DEFAULT_PSK;
+        private byte[] pskId = Hpke.DEFAULT_PSK_ID;
+
+        /**
+         * Creates the builder.
+         *
+         * @param encapsulated encapsulated ephemeral key from an {@link Sender}
+         * @param recipientKey private key of the recipient
+         */
+        public Builder(@NonNull Hpke hpke,
+                @NonNull byte[] encapsulated, @NonNull PrivateKey recipientKey) {
+            Objects.requireNonNull(hpke);
+            Objects.requireNonNull(encapsulated);
+            Objects.requireNonNull(recipientKey);
+            this.hpke = hpke;
+            this.encapsulated = encapsulated;
+            this.recipientKey = recipientKey;
+        }
+
+        /**
+         * Adds optional application-related data which will be used during the key generation
+         * process.
+         *
+         * @param applicationInfo application-specific information
+         *
+         * @return the Builder
+         */
+        public @NonNull Builder setApplicationInfo(@NonNull byte[] applicationInfo) {
+            Objects.requireNonNull(applicationInfo);
+            this.applicationInfo = applicationInfo;
+            return this;
+        }
+
+        /**
+         * Sets the sender key to be used by the recipient for message authentication.
+         *
+         * @param senderKey the sender's public key
+         * @return the Builder
+         */
+        public @NonNull Builder setSenderKey(@NonNull PublicKey senderKey) {
+            Objects.requireNonNull(senderKey);
+            this.senderKey = senderKey;
+            return this;
+        }
+
+        /**
+         * Sets pre-shared key information to be used for message authentication.
+         *
+         * @param psk          the pre-shared secret key
+         * @param pskId       the id of the pre-shared key
+         * @return the Builder
+         */
+        public @NonNull Builder setPsk(@NonNull byte[] psk, @NonNull byte[] pskId) {
+            Objects.requireNonNull(psk);
+            Objects.requireNonNull(pskId);
+            this.psk = psk;
+            this.pskId = pskId;
+            return this;
+        }
+
+        /**
+         * Builds the {@link Recipient}.
+         *
+         * @return the Recipient
+         * @throws InvalidKeyException           if the sender or recipient key are unsupported
+         * @throws UnsupportedOperationException if this Provider does not support the expected mode
+         */
+        public @NonNull Recipient build() throws InvalidKeyException {
+            HpkeSpi spi = hpke.findSpi();
+            spi.engineInitRecipient(encapsulated, recipientKey, applicationInfo, senderKey, psk,
+                    pskId);
+            return new Recipient(hpke, spi);
+        }
+    }
+}
diff --git a/luni/src/main/java/android/crypto/hpke/Sender.java b/luni/src/main/java/android/crypto/hpke/Sender.java
new file mode 100644
index 00000000000..ccc462a011c
--- /dev/null
+++ b/luni/src/main/java/android/crypto/hpke/Sender.java
@@ -0,0 +1,171 @@
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
+package android.crypto.hpke;
+
+import android.annotation.FlaggedApi;
+
+import libcore.util.NonNull;
+import libcore.util.Nullable;
+
+import java.security.InvalidKeyException;
+import java.security.PrivateKey;
+import java.security.Provider;
+import java.security.PublicKey;
+import java.util.Objects;
+
+/**
+ * A class for sending HPKE messages.
+ */
+@SuppressWarnings("NewApi") // Public HPKE classes are always all present together.
+@FlaggedApi(com.android.libcore.Flags.FLAG_HPKE_PUBLIC_API)
+public class Sender {
+    private final Hpke hpke;
+    private final HpkeSpi spi;
+
+    @SuppressWarnings("NewApi") // Public HPKE classes are always all present together.
+    Sender(@NonNull Hpke hpke, @NonNull HpkeSpi spi) {
+        this.hpke = hpke;
+        this.spi = spi;
+    }
+
+    /**
+     * Returns the encapsulated ephemeral key created for this Sender.
+     *
+     * @return the encapsulated key
+     */
+    public @NonNull byte[] getEncapsulated() {
+        return spi.getEncapsulated();
+    }
+
+    /**
+     * Seals a message, using the internal key schedule maintained by this Sender.
+     *
+     * @see <a href="https://www.rfc-editor.org/rfc/rfc9180.html#name-encryption-and-decryption-2">
+     *     Opening and sealing</a>
+     * @param plaintext the plaintext
+     * @param aad       optional additional authenticated data, may be null or empty
+     * @return the ciphertext
+     */
+    public @NonNull byte[] seal(@NonNull byte[] plaintext, @Nullable byte[] aad) {
+        Objects.requireNonNull(plaintext);
+        return spi.engineSeal(plaintext, aad);
+    }
+
+    /**
+     * Exports secret key material from this Sender as described in RFC 9180.
+     *
+     * @param length  expected output length
+     * @param context optional exporter context string, may be null or empty
+     * @return the exported value
+     * @throws IllegalArgumentException if the length is not valid for the Sender's KDF
+     */
+    public @NonNull byte[] export(int length, @Nullable byte[] context) {
+        return spi.engineExport(length, context);
+    }
+
+    /**
+     * Returns the {@link HpkeSpi} being used by this Sender.
+     *
+     * @return the SPI
+     */
+    public @NonNull HpkeSpi getSpi() {
+        return spi;
+    }
+
+    /**
+     * Returns the {@link Provider} being used by this Sender.
+     *
+     * @return the Provider
+     */
+    public @NonNull Provider getProvider() {
+        return hpke.getProvider();
+    }
+
+    /**
+     * A builder for HPKE Sender objects.
+     */
+    @FlaggedApi(com.android.libcore.Flags.FLAG_HPKE_PUBLIC_API)
+    public static class Builder {
+        private final Hpke hpke;
+        private final PublicKey recipientKey;
+        private byte[] applicationInfo = null;
+        private PrivateKey senderKey = null;
+        private byte[] psk = Hpke.DEFAULT_PSK;
+        private byte[] pskId = Hpke.DEFAULT_PSK_ID;
+
+        /**
+         * Creates the Builder.
+         *
+         * @param recipientKey public key of the recipient
+         */
+        public Builder(@NonNull Hpke hpke, @NonNull PublicKey recipientKey) {
+            Objects.requireNonNull(hpke);
+            Objects.requireNonNull(recipientKey);
+            this.hpke = hpke;
+            this.recipientKey = recipientKey;
+        }
+
+        /**
+         * Adds optional application-related data which will be used during the key generation
+         * process.
+         *
+         * @param applicationInfo application-specific information
+         *
+         * @return the Builder
+         */
+        public @NonNull Builder setApplicationInfo(@NonNull byte[] applicationInfo) {
+            this.applicationInfo = applicationInfo;
+            return this;
+        }
+
+        /**
+         * Sets the sender key to be used by the recipient for message authentication.
+         *
+         * @param senderKey the sender's public key
+         * @return the Builder
+         */
+        public @NonNull Builder setSenderKey(@NonNull PrivateKey senderKey) {
+            this.senderKey = senderKey;
+            return this;
+        }
+
+        /**
+         * Sets pre-shared key information to be used for message authentication.
+         *
+         * @param psk          the pre-shared secret key
+         * @param pskId       the id of the pre-shared key
+         * @return the Builder
+         */
+        public @NonNull Builder setPsk(@NonNull byte[] psk, @NonNull byte[] pskId) {
+            this.psk = psk;
+            this.pskId = pskId;
+            return this;
+        }
+
+        /**
+         * Created the {@link Sender} object.
+         *
+         * @throws InvalidKeyException           if the sender or recipient key are unsupported
+         * @throws UnsupportedOperationException if this Provider does not support the expected mode
+         */
+        public @NonNull Sender build() throws InvalidKeyException {
+            HpkeSpi spi = hpke.findSpi();
+            spi.engineInitSender(recipientKey, applicationInfo, senderKey, psk, pskId);
+            return new Sender(hpke, spi);
+        }
+    }
+}
diff --git a/luni/src/main/java/android/system/Os.java b/luni/src/main/java/android/system/Os.java
index f96f811d1a8..cd16bfb5774 100644
--- a/luni/src/main/java/android/system/Os.java
+++ b/luni/src/main/java/android/system/Os.java
@@ -443,6 +443,12 @@ public final class Os {
      */
     public static StructStat lstat(String path) throws ErrnoException { return Libcore.os.lstat(path); }
 
+    /**
+     * See <a href="http://man7.org/linux/man-pages/man2/madvise.2.html">mlock(2)</a>.
+     */
+    @android.annotation.FlaggedApi(com.android.libcore.Flags.FLAG_MADVISE_API)
+    public static void madvise(long address, long byteCount, int advice) throws ErrnoException { Libcore.os.madvise(address, byteCount, advice); }
+
     /**
      * See <a href="http://man7.org/linux/man-pages/man2/memfd_create.2.html">memfd_create(2)</a>.
      */
diff --git a/luni/src/main/java/android/system/OsConstants.java b/luni/src/main/java/android/system/OsConstants.java
index a44dff65b36..807f2761222 100644
--- a/luni/src/main/java/android/system/OsConstants.java
+++ b/luni/src/main/java/android/system/OsConstants.java
@@ -425,6 +425,56 @@ public final class OsConstants {
     public static final int IP_RECVTOS = placeholder();
     public static final int IP_TOS = placeholder();
     public static final int IP_TTL = placeholder();
+
+    @android.annotation.FlaggedApi(com.android.libcore.Flags.FLAG_MADVISE_API)
+    public static final int MADV_NORMAL = placeholder();
+    @android.annotation.FlaggedApi(com.android.libcore.Flags.FLAG_MADVISE_API)
+    public static final int MADV_RANDOM = placeholder();
+    @android.annotation.FlaggedApi(com.android.libcore.Flags.FLAG_MADVISE_API)
+    public static final int MADV_SEQUENTIAL = placeholder();
+    @android.annotation.FlaggedApi(com.android.libcore.Flags.FLAG_MADVISE_API)
+    public static final int MADV_WILLNEED = placeholder();
+    @android.annotation.FlaggedApi(com.android.libcore.Flags.FLAG_MADVISE_API)
+    public static final int MADV_DONTNEED = placeholder();
+    @android.annotation.FlaggedApi(com.android.libcore.Flags.FLAG_MADVISE_API)
+    public static final int MADV_REMOVE = placeholder();
+    @android.annotation.FlaggedApi(com.android.libcore.Flags.FLAG_MADVISE_API)
+    public static final int MADV_DONTFORK = placeholder();
+    @android.annotation.FlaggedApi(com.android.libcore.Flags.FLAG_MADVISE_API)
+    public static final int MADV_DOFORK = placeholder();
+    @android.annotation.FlaggedApi(com.android.libcore.Flags.FLAG_MADVISE_API)
+    public static final int MADV_HWPOISON = placeholder();
+    @android.annotation.FlaggedApi(com.android.libcore.Flags.FLAG_MADVISE_API)
+    public static final int MADV_MERGEABLE = placeholder();
+    @android.annotation.FlaggedApi(com.android.libcore.Flags.FLAG_MADVISE_API)
+    public static final int MADV_UNMERGEABLE = placeholder();
+    @android.annotation.FlaggedApi(com.android.libcore.Flags.FLAG_MADVISE_API)
+    public static final int MADV_SOFT_OFFLINE = placeholder();
+    @android.annotation.FlaggedApi(com.android.libcore.Flags.FLAG_MADVISE_API)
+    public static final int MADV_HUGEPAGE = placeholder();
+    @android.annotation.FlaggedApi(com.android.libcore.Flags.FLAG_MADVISE_API)
+    public static final int MADV_NOHUGEPAGE = placeholder();
+    @android.annotation.FlaggedApi(com.android.libcore.Flags.FLAG_MADVISE_API)
+    public static final int MADV_COLLAPSE = placeholder();
+    @android.annotation.FlaggedApi(com.android.libcore.Flags.FLAG_MADVISE_API)
+    public static final int MADV_DONTDUMP = placeholder();
+    @android.annotation.FlaggedApi(com.android.libcore.Flags.FLAG_MADVISE_API)
+    public static final int MADV_DODUMP = placeholder();
+    @android.annotation.FlaggedApi(com.android.libcore.Flags.FLAG_MADVISE_API)
+    public static final int MADV_FREE = placeholder();
+    @android.annotation.FlaggedApi(com.android.libcore.Flags.FLAG_MADVISE_API)
+    public static final int MADV_WIPEONFORK = placeholder();
+    @android.annotation.FlaggedApi(com.android.libcore.Flags.FLAG_MADVISE_API)
+    public static final int MADV_KEEPONFORK = placeholder();
+    @android.annotation.FlaggedApi(com.android.libcore.Flags.FLAG_MADVISE_API)
+    public static final int MADV_COLD = placeholder();
+    @android.annotation.FlaggedApi(com.android.libcore.Flags.FLAG_MADVISE_API)
+    public static final int MADV_PAGEOUT = placeholder();
+    @android.annotation.FlaggedApi(com.android.libcore.Flags.FLAG_MADVISE_API)
+    public static final int MADV_POPULATE_READ = placeholder();
+    @android.annotation.FlaggedApi(com.android.libcore.Flags.FLAG_MADVISE_API)
+    public static final int MADV_POPULATE_WRITE = placeholder();
+
     /**
      * Version constant to be used in {@link StructCapUserHeader} with
      * {@link Os#capset(StructCapUserHeader, StructCapUserData[])} and
diff --git a/luni/src/main/java/libcore/io/ForwardingOs.java b/luni/src/main/java/libcore/io/ForwardingOs.java
index fd5655d0600..91fb57661b8 100644
--- a/luni/src/main/java/libcore/io/ForwardingOs.java
+++ b/luni/src/main/java/libcore/io/ForwardingOs.java
@@ -474,6 +474,11 @@ public class ForwardingOs implements Os {
     @UnsupportedAppUsage
     public StructStat lstat(String path) throws ErrnoException { return os.lstat(path); }
 
+    /**
+     * @hide
+     */
+    public void madvise(long address, long byteCount, int advice) throws ErrnoException { os.madvise(address, byteCount, advice); }
+
     /**
      * @hide
      */
diff --git a/luni/src/main/java/libcore/io/Linux.java b/luni/src/main/java/libcore/io/Linux.java
index 7b96c4e120e..6c759376dc9 100644
--- a/luni/src/main/java/libcore/io/Linux.java
+++ b/luni/src/main/java/libcore/io/Linux.java
@@ -160,6 +160,7 @@ public final class Linux implements Os {
     public native String[] listxattr(String path) throws ErrnoException;
     public native long lseek(FileDescriptor fd, long offset, int whence) throws ErrnoException;
     public native StructStat lstat(String path) throws ErrnoException;
+    public native void madvise(long address, long byteCount, int advice) throws ErrnoException;
     public native FileDescriptor memfd_create(String name, int flags) throws ErrnoException;
     public native void mincore(long address, long byteCount, byte[] vector) throws ErrnoException;
     public native void mkdir(String path, int mode) throws ErrnoException;
diff --git a/luni/src/main/java/libcore/io/Os.java b/luni/src/main/java/libcore/io/Os.java
index 092de59d97c..7a6b69b581b 100644
--- a/luni/src/main/java/libcore/io/Os.java
+++ b/luni/src/main/java/libcore/io/Os.java
@@ -412,6 +412,11 @@ public interface Os {
      */
     public StructStat lstat(String path) throws ErrnoException;
 
+    /**
+     * @hide
+     */
+    public void madvise(long addr, long byteCount, int advice) throws ErrnoException;
+
     /**
      * @hide
      */
diff --git a/luni/src/main/java/libcore/util/NativeAllocationRegistry.java b/luni/src/main/java/libcore/util/NativeAllocationRegistry.java
index 5dea80e3000..ed1053d1f45 100644
--- a/luni/src/main/java/libcore/util/NativeAllocationRegistry.java
+++ b/luni/src/main/java/libcore/util/NativeAllocationRegistry.java
@@ -27,8 +27,9 @@ import sun.misc.Cleaner;
 import java.lang.invoke.MethodHandles;
 import java.lang.invoke.VarHandle;
 import java.lang.ref.Reference;
+import java.util.ArrayList;
 import java.util.Collection;
-import java.util.HashMap;
+import java.util.List;
 import java.util.Map;
 import java.util.Objects;
 import java.util.WeakHashMap;
@@ -364,9 +365,9 @@ public class NativeAllocationRegistry {
     @FlaggedApi(com.android.libcore.Flags.FLAG_NATIVE_METRICS)
     public static final class Metrics {
         private String className;
-        private long mallocedCount;
+        private int mallocedCount;
         private long mallocedBytes;
-        private long nonmallocedCount;
+        private int nonmallocedCount;
         private long nonmallocedBytes;
 
         private Metrics(@NonNull String className) {
@@ -374,7 +375,7 @@ public class NativeAllocationRegistry {
         }
 
         private void add(NativeAllocationRegistry r) {
-            long count = r.counter;
+            int count = r.counter;
             long bytes = count * (r.size & ~IS_MALLOCED);
             if (r.isMalloced()) {
                 mallocedCount += count;
@@ -421,6 +422,8 @@ public class NativeAllocationRegistry {
         }
     }
 
+    private static int numClasses = 3;  /* default number of classes with aggregated metrics */
+
     /**
      * Returns per-class metrics in a Collection.
      *
@@ -430,22 +433,36 @@ public class NativeAllocationRegistry {
      * Metrics of the registries with no class explictily specified will be aggregated
      * under the class name of `libcore.util.NativeAllocationRegistry` by default.
      *
+     * NOTE:
+     *   1) ArrayList is used here for both memory and performance given
+     *   the number of classes with aggregated metrics is typically small,
+     *   a linear search will be fast enough here
+     *   2) Use the previous number of aggregated classes + 1 to minimize
+     *   memory usage, assuming the number doesn't jump much from last time.
+     *
      * @hide
      */
     @SystemApi(client = MODULE_LIBRARIES)
     @FlaggedApi(com.android.libcore.Flags.FLAG_NATIVE_METRICS)
     public static synchronized @NonNull Collection<Metrics> getMetrics() {
-        Map<String, Metrics> result = new HashMap<>();
+        List<Metrics> result = new ArrayList<>(numClasses + 1);
         for (NativeAllocationRegistry r : registries.keySet()) {
             String className = r.clazz.getName();
-            Metrics m = result.get(className);
+            Metrics m = null;
+            for (int i = 0; i < result.size(); i++) {
+                if (result.get(i).className == className) {
+                    m = result.get(i);
+                    break;
+                }
+            }
             if (m == null) {
                 m = new Metrics(className);
-                result.put(className, m);
+                result.add(m);
             }
             m.add(r);
         }
-        return result.values();
+        numClasses = result.size();
+        return result;
     }
 
     /**
diff --git a/luni/src/main/java/libcore/util/NonNull.java b/luni/src/main/java/libcore/util/NonNull.java
index db3cd8ed712..1153a77d5c9 100644
--- a/luni/src/main/java/libcore/util/NonNull.java
+++ b/luni/src/main/java/libcore/util/NonNull.java
@@ -35,14 +35,4 @@ import java.lang.annotation.Target;
 @Retention(SOURCE)
 @Target({FIELD, METHOD, PARAMETER, TYPE_USE})
 @libcore.api.IntraCoreApi
-public @interface NonNull {
-   /**
-    * Min Android API level (inclusive) to which this annotation is applied.
-    */
-   int from() default Integer.MIN_VALUE;
-
-   /**
-    * Max Android API level to which this annotation is applied.
-    */
-   int to() default Integer.MAX_VALUE;
-}
+public @interface NonNull {}
diff --git a/luni/src/main/java/libcore/util/Nullable.java b/luni/src/main/java/libcore/util/Nullable.java
index 3371978b056..295f083426f 100644
--- a/luni/src/main/java/libcore/util/Nullable.java
+++ b/luni/src/main/java/libcore/util/Nullable.java
@@ -35,14 +35,4 @@ import java.lang.annotation.Target;
 @Retention(SOURCE)
 @Target({FIELD, METHOD, PARAMETER, TYPE_USE})
 @libcore.api.IntraCoreApi
-public @interface Nullable {
-   /**
-    * Min Android API level (inclusive) to which this annotation is applied.
-    */
-   int from() default Integer.MIN_VALUE;
-
-   /**
-    * Max Android API level to which this annotation is applied.
-    */
-   int to() default Integer.MAX_VALUE;
-}
+public @interface Nullable {}
diff --git a/luni/src/main/native/android_system_OsConstants.cpp b/luni/src/main/native/android_system_OsConstants.cpp
index c2b6848e4cd..cb3ac21abbd 100644
--- a/luni/src/main/native/android_system_OsConstants.cpp
+++ b/luni/src/main/native/android_system_OsConstants.cpp
@@ -20,12 +20,18 @@
 #include <fcntl.h>
 #include <netdb.h>
 #include <netinet/icmp6.h>
+#include <netinet/if_ether.h>
 #include <netinet/in.h>
 #include <netinet/ip_icmp.h>
 #include <netinet/tcp.h>
+#include <netinet/udp.h>
+#include <netpacket/packet.h>
+#include <net/if.h>
+#include <net/if_arp.h>
 #include <poll.h>
 #include <signal.h>
 #include <stdlib.h>
+#include <sys/capability.h>
 #include <sys/ioctl.h>
 #include <sys/mman.h>
 #include <sys/prctl.h>
@@ -37,25 +43,17 @@
 #include <sys/xattr.h>
 #include <unistd.h>
 
-#include <net/if_arp.h>
-#include <linux/if_ether.h>
-
-// After the others because these are not necessarily self-contained in glibc.
 #include <linux/if_addr.h>
 #include <linux/rtnetlink.h>
 
-// Include linux socket constants for setting sockopts
-#include <linux/udp.h>
-
-#include <net/if.h> // After <sys/socket.h> to work around a Mac header file bug.
-
-#if defined(__BIONIC__)
-#include <linux/capability.h>
-#endif
-
 #include <nativehelper/JNIHelp.h>
 #include <nativehelper/jni_macros.h>
 
+#if defined(__GLIBC__)
+// MADV_SOFT_OFFLINE is otherwise unavailable from glibc.
+#include <asm-generic/mman-common.h>
+#endif
+
 #include "Portability.h"
 
 static void initConstant(JNIEnv* env, jclass c, const char* fieldName, int value) {
@@ -75,9 +73,7 @@ static void OsConstants_initConstants(JNIEnv* env, jclass c) {
     initConstant(env, c, "AI_ALL", AI_ALL);
     initConstant(env, c, "AI_CANONNAME", AI_CANONNAME);
     initConstant(env, c, "AI_NUMERICHOST", AI_NUMERICHOST);
-#if defined(AI_NUMERICSERV)
     initConstant(env, c, "AI_NUMERICSERV", AI_NUMERICSERV);
-#endif
     initConstant(env, c, "AI_PASSIVE", AI_PASSIVE);
     initConstant(env, c, "AI_V4MAPPED", AI_V4MAPPED);
     initConstant(env, c, "ARPHRD_ETHER", ARPHRD_ETHER);
@@ -86,7 +82,6 @@ static void OsConstants_initConstants(JNIEnv* env, jclass c) {
     initConstant(env, c, "VMADDR_CID_LOCAL", VMADDR_CID_LOCAL);
     initConstant(env, c, "VMADDR_CID_HOST", VMADDR_CID_HOST);
     initConstant(env, c, "ARPHRD_LOOPBACK", ARPHRD_LOOPBACK);
-#if defined(CAP_LAST_CAP)
     initConstant(env, c, "CAP_AUDIT_CONTROL", CAP_AUDIT_CONTROL);
     initConstant(env, c, "CAP_AUDIT_WRITE", CAP_AUDIT_WRITE);
     initConstant(env, c, "CAP_BLOCK_SUSPEND", CAP_BLOCK_SUSPEND);
@@ -125,7 +120,6 @@ static void OsConstants_initConstants(JNIEnv* env, jclass c) {
     initConstant(env, c, "CAP_SYS_TIME", CAP_SYS_TIME);
     initConstant(env, c, "CAP_SYS_TTY_CONFIG", CAP_SYS_TTY_CONFIG);
     initConstant(env, c, "CAP_WAKE_ALARM", CAP_WAKE_ALARM);
-#endif
     initConstant(env, c, "E2BIG", E2BIG);
     initConstant(env, c, "EACCES", EACCES);
     initConstant(env, c, "EADDRINUSE", EADDRINUSE);
@@ -139,9 +133,7 @@ static void OsConstants_initConstants(JNIEnv* env, jclass c) {
     initConstant(env, c, "EAI_MEMORY", EAI_MEMORY);
     initConstant(env, c, "EAI_NODATA", EAI_NODATA);
     initConstant(env, c, "EAI_NONAME", EAI_NONAME);
-#if defined(EAI_OVERFLOW)
     initConstant(env, c, "EAI_OVERFLOW", EAI_OVERFLOW);
-#endif
     initConstant(env, c, "EAI_SERVICE", EAI_SERVICE);
     initConstant(env, c, "EAI_SOCKTYPE", EAI_SOCKTYPE);
     initConstant(env, c, "EAI_SYSTEM", EAI_SYSTEM);
@@ -222,9 +214,6 @@ static void OsConstants_initConstants(JNIEnv* env, jclass c) {
     initConstant(env, c, "ETIMEDOUT", ETIMEDOUT);
     initConstant(env, c, "ETXTBSY", ETXTBSY);
     initConstant(env, c, "EUSERS", EUSERS);
-#if EWOULDBLOCK != EAGAIN
-#error EWOULDBLOCK != EAGAIN
-#endif
     initConstant(env, c, "EXDEV", EXDEV);
     initConstant(env, c, "EXIT_FAILURE", EXIT_FAILURE);
     initConstant(env, c, "EXIT_SUCCESS", EXIT_SUCCESS);
@@ -235,22 +224,16 @@ static void OsConstants_initConstants(JNIEnv* env, jclass c) {
     initConstant(env, c, "F_GETFD", F_GETFD);
     initConstant(env, c, "F_GETFL", F_GETFL);
     initConstant(env, c, "F_GETLK", F_GETLK);
-#if defined(F_GETLK64)
     initConstant(env, c, "F_GETLK64", F_GETLK64);
-#endif
     initConstant(env, c, "F_GETOWN", F_GETOWN);
     initConstant(env, c, "F_OK", F_OK);
     initConstant(env, c, "F_RDLCK", F_RDLCK);
     initConstant(env, c, "F_SETFD", F_SETFD);
     initConstant(env, c, "F_SETFL", F_SETFL);
     initConstant(env, c, "F_SETLK", F_SETLK);
-#if defined(F_SETLK64)
     initConstant(env, c, "F_SETLK64", F_SETLK64);
-#endif
     initConstant(env, c, "F_SETLKW", F_SETLKW);
-#if defined(F_SETLKW64)
     initConstant(env, c, "F_SETLKW64", F_SETLKW64);
-#endif
     initConstant(env, c, "F_SETOWN", F_SETOWN);
     initConstant(env, c, "F_UNLCK", F_UNLCK);
     initConstant(env, c, "F_WRLCK", F_WRLCK);
@@ -258,64 +241,32 @@ static void OsConstants_initConstants(JNIEnv* env, jclass c) {
     initConstant(env, c, "ICMP_ECHOREPLY", ICMP_ECHOREPLY);
     initConstant(env, c, "ICMP6_ECHO_REQUEST", ICMP6_ECHO_REQUEST);
     initConstant(env, c, "ICMP6_ECHO_REPLY", ICMP6_ECHO_REPLY);
-#if defined(IFA_F_DADFAILED)
     initConstant(env, c, "IFA_F_DADFAILED", IFA_F_DADFAILED);
-#endif
-#if defined(IFA_F_DEPRECATED)
     initConstant(env, c, "IFA_F_DEPRECATED", IFA_F_DEPRECATED);
-#endif
-#if defined(IFA_F_HOMEADDRESS)
     initConstant(env, c, "IFA_F_HOMEADDRESS", IFA_F_HOMEADDRESS);
-#endif
-#if defined(IFA_F_MANAGETEMPADDR)
     initConstant(env, c, "IFA_F_MANAGETEMPADDR", IFA_F_MANAGETEMPADDR);
-#endif
-#if defined(IFA_F_NODAD)
     initConstant(env, c, "IFA_F_NODAD", IFA_F_NODAD);
-#endif
-#if defined(IFA_F_NOPREFIXROUTE)
     initConstant(env, c, "IFA_F_NOPREFIXROUTE", IFA_F_NOPREFIXROUTE);
-#endif
-#if defined(IFA_F_OPTIMISTIC)
     initConstant(env, c, "IFA_F_OPTIMISTIC", IFA_F_OPTIMISTIC);
-#endif
-#if defined(IFA_F_PERMANENT)
     initConstant(env, c, "IFA_F_PERMANENT", IFA_F_PERMANENT);
-#endif
-#if defined(IFA_F_SECONDARY)
     initConstant(env, c, "IFA_F_SECONDARY", IFA_F_SECONDARY);
-#endif
-#if defined(IFA_F_TEMPORARY)
     initConstant(env, c, "IFA_F_TEMPORARY", IFA_F_TEMPORARY);
-#endif
-#if defined(IFA_F_TENTATIVE)
     initConstant(env, c, "IFA_F_TENTATIVE", IFA_F_TENTATIVE);
-#endif
     initConstant(env, c, "IFF_ALLMULTI", IFF_ALLMULTI);
-#if defined(IFF_AUTOMEDIA)
     initConstant(env, c, "IFF_AUTOMEDIA", IFF_AUTOMEDIA);
-#endif
     initConstant(env, c, "IFF_BROADCAST", IFF_BROADCAST);
     initConstant(env, c, "IFF_DEBUG", IFF_DEBUG);
-#if defined(IFF_DYNAMIC)
     initConstant(env, c, "IFF_DYNAMIC", IFF_DYNAMIC);
-#endif
     initConstant(env, c, "IFF_LOOPBACK", IFF_LOOPBACK);
-#if defined(IFF_MASTER)
     initConstant(env, c, "IFF_MASTER", IFF_MASTER);
-#endif
     initConstant(env, c, "IFF_MULTICAST", IFF_MULTICAST);
     initConstant(env, c, "IFF_NOARP", IFF_NOARP);
     initConstant(env, c, "IFF_NOTRAILERS", IFF_NOTRAILERS);
     initConstant(env, c, "IFF_POINTOPOINT", IFF_POINTOPOINT);
-#if defined(IFF_PORTSEL)
     initConstant(env, c, "IFF_PORTSEL", IFF_PORTSEL);
-#endif
     initConstant(env, c, "IFF_PROMISC", IFF_PROMISC);
     initConstant(env, c, "IFF_RUNNING", IFF_RUNNING);
-#if defined(IFF_SLAVE)
     initConstant(env, c, "IFF_SLAVE", IFF_SLAVE);
-#endif
     initConstant(env, c, "IFF_UP", IFF_UP);
     initConstant(env, c, "IPPROTO_ICMP", IPPROTO_ICMP);
     initConstant(env, c, "IPPROTO_ICMPV6", IPPROTO_ICMPV6);
@@ -329,30 +280,14 @@ static void OsConstants_initConstants(JNIEnv* env, jclass c) {
     initConstant(env, c, "IPV6_MULTICAST_HOPS", IPV6_MULTICAST_HOPS);
     initConstant(env, c, "IPV6_MULTICAST_IF", IPV6_MULTICAST_IF);
     initConstant(env, c, "IPV6_MULTICAST_LOOP", IPV6_MULTICAST_LOOP);
-#if defined(IPV6_PKTINFO)
     initConstant(env, c, "IPV6_PKTINFO", IPV6_PKTINFO);
-#endif
-#if defined(IPV6_RECVDSTOPTS)
     initConstant(env, c, "IPV6_RECVDSTOPTS", IPV6_RECVDSTOPTS);
-#endif
-#if defined(IPV6_RECVHOPLIMIT)
     initConstant(env, c, "IPV6_RECVHOPLIMIT", IPV6_RECVHOPLIMIT);
-#endif
-#if defined(IPV6_RECVHOPOPTS)
     initConstant(env, c, "IPV6_RECVHOPOPTS", IPV6_RECVHOPOPTS);
-#endif
-#if defined(IPV6_RECVPKTINFO)
     initConstant(env, c, "IPV6_RECVPKTINFO", IPV6_RECVPKTINFO);
-#endif
-#if defined(IPV6_RECVRTHDR)
     initConstant(env, c, "IPV6_RECVRTHDR", IPV6_RECVRTHDR);
-#endif
-#if defined(IPV6_RECVTCLASS)
     initConstant(env, c, "IPV6_RECVTCLASS", IPV6_RECVTCLASS);
-#endif
-#if defined(IPV6_TCLASS)
     initConstant(env, c, "IPV6_TCLASS", IPV6_TCLASS);
-#endif
     initConstant(env, c, "IPV6_UNICAST_HOPS", IPV6_UNICAST_HOPS);
     initConstant(env, c, "IPV6_V6ONLY", IPV6_V6ONLY);
     initConstant(env, c, "IP_MULTICAST_ALL", IP_MULTICAST_ALL);
@@ -362,37 +297,45 @@ static void OsConstants_initConstants(JNIEnv* env, jclass c) {
     initConstant(env, c, "IP_RECVTOS", IP_RECVTOS);
     initConstant(env, c, "IP_TOS", IP_TOS);
     initConstant(env, c, "IP_TTL", IP_TTL);
-#if defined(_LINUX_CAPABILITY_VERSION_3)
     initConstant(env, c, "_LINUX_CAPABILITY_VERSION_3", _LINUX_CAPABILITY_VERSION_3);
-#endif
+    initConstant(env, c, "MADV_NORMAL", MADV_NORMAL);
+    initConstant(env, c, "MADV_RANDOM", MADV_RANDOM);
+    initConstant(env, c, "MADV_SEQUENTIAL", MADV_SEQUENTIAL);
+    initConstant(env, c, "MADV_WILLNEED", MADV_WILLNEED);
+    initConstant(env, c, "MADV_DONTNEED", MADV_DONTNEED);
+    initConstant(env, c, "MADV_REMOVE", MADV_REMOVE);
+    initConstant(env, c, "MADV_DONTFORK", MADV_DONTFORK);
+    initConstant(env, c, "MADV_DOFORK", MADV_DOFORK);
+    initConstant(env, c, "MADV_HWPOISON", MADV_HWPOISON);
+    initConstant(env, c, "MADV_MERGEABLE", MADV_MERGEABLE);
+    initConstant(env, c, "MADV_UNMERGEABLE", MADV_UNMERGEABLE);
+    initConstant(env, c, "MADV_SOFT_OFFLINE", MADV_SOFT_OFFLINE);
+    initConstant(env, c, "MADV_HUGEPAGE", MADV_HUGEPAGE);
+    initConstant(env, c, "MADV_NOHUGEPAGE", MADV_NOHUGEPAGE);
+    initConstant(env, c, "MADV_COLLAPSE", MADV_COLLAPSE);
+    initConstant(env, c, "MADV_DONTDUMP", MADV_DONTDUMP);
+    initConstant(env, c, "MADV_DODUMP", MADV_DODUMP);
+    initConstant(env, c, "MADV_FREE", MADV_FREE);
+    initConstant(env, c, "MADV_WIPEONFORK", MADV_WIPEONFORK);
+    initConstant(env, c, "MADV_KEEPONFORK", MADV_KEEPONFORK);
+    initConstant(env, c, "MADV_COLD", MADV_COLD);
+    initConstant(env, c, "MADV_PAGEOUT", MADV_PAGEOUT);
+    initConstant(env, c, "MADV_POPULATE_READ", MADV_POPULATE_READ);
+    initConstant(env, c, "MADV_POPULATE_WRITE", MADV_POPULATE_WRITE);
     initConstant(env, c, "MAP_FIXED", MAP_FIXED);
     initConstant(env, c, "MAP_ANONYMOUS", MAP_ANONYMOUS);
     initConstant(env, c, "MAP_POPULATE", MAP_POPULATE);
     initConstant(env, c, "MAP_PRIVATE", MAP_PRIVATE);
     initConstant(env, c, "MAP_SHARED", MAP_SHARED);
-#if defined(MCAST_JOIN_GROUP)
     initConstant(env, c, "MCAST_JOIN_GROUP", MCAST_JOIN_GROUP);
-#endif
-#if defined(MCAST_LEAVE_GROUP)
     initConstant(env, c, "MCAST_LEAVE_GROUP", MCAST_LEAVE_GROUP);
-#endif
-#if defined(MCAST_JOIN_SOURCE_GROUP)
     initConstant(env, c, "MCAST_JOIN_SOURCE_GROUP", MCAST_JOIN_SOURCE_GROUP);
-#endif
-#if defined(MCAST_LEAVE_SOURCE_GROUP)
     initConstant(env, c, "MCAST_LEAVE_SOURCE_GROUP", MCAST_LEAVE_SOURCE_GROUP);
-#endif
-#if defined(MCAST_BLOCK_SOURCE)
     initConstant(env, c, "MCAST_BLOCK_SOURCE", MCAST_BLOCK_SOURCE);
-#endif
-#if defined(MCAST_UNBLOCK_SOURCE)
     initConstant(env, c, "MCAST_UNBLOCK_SOURCE", MCAST_UNBLOCK_SOURCE);
-#endif
     initConstant(env, c, "MCL_CURRENT", MCL_CURRENT);
     initConstant(env, c, "MCL_FUTURE", MCL_FUTURE);
-#if defined(MFD_CLOEXEC)
     initConstant(env, c, "MFD_CLOEXEC", MFD_CLOEXEC);
-#endif
     initConstant(env, c, "MSG_CTRUNC", MSG_CTRUNC);
     initConstant(env, c, "MSG_DONTROUTE", MSG_DONTROUTE);
     initConstant(env, c, "MSG_EOR", MSG_EOR);
@@ -437,21 +380,11 @@ static void OsConstants_initConstants(JNIEnv* env, jclass c) {
     initConstant(env, c, "POLLRDNORM", POLLRDNORM);
     initConstant(env, c, "POLLWRBAND", POLLWRBAND);
     initConstant(env, c, "POLLWRNORM", POLLWRNORM);
-#if defined(PR_CAP_AMBIENT)
     initConstant(env, c, "PR_CAP_AMBIENT", PR_CAP_AMBIENT);
-#endif
-#if defined(PR_CAP_AMBIENT_RAISE)
     initConstant(env, c, "PR_CAP_AMBIENT_RAISE", PR_CAP_AMBIENT_RAISE);
-#endif
-#if defined(PR_GET_DUMPABLE)
     initConstant(env, c, "PR_GET_DUMPABLE", PR_GET_DUMPABLE);
-#endif
-#if defined(PR_SET_DUMPABLE)
     initConstant(env, c, "PR_SET_DUMPABLE", PR_SET_DUMPABLE);
-#endif
-#if defined(PR_SET_NO_NEW_PRIVS)
     initConstant(env, c, "PR_SET_NO_NEW_PRIVS", PR_SET_NO_NEW_PRIVS);
-#endif
     initConstant(env, c, "PROT_EXEC", PROT_EXEC);
     initConstant(env, c, "PROT_NONE", PROT_NONE);
     initConstant(env, c, "PROT_READ", PROT_READ);
@@ -459,10 +392,6 @@ static void OsConstants_initConstants(JNIEnv* env, jclass c) {
     initConstant(env, c, "R_OK", R_OK);
     initConstant(env, c, "RLIMIT_NOFILE", RLIMIT_NOFILE);
     initConstant(env, c, "RLIMIT_RTPRIO", RLIMIT_RTPRIO);
-// NOTE: The RT_* constants are not preprocessor defines, they're enum
-// members. The best we can do (barring UAPI / kernel version checks) is
-// to hope they exist on all host linuxes we're building on. These
-// constants have been around since 2.6.35 at least, so we should be ok.
     initConstant(env, c, "RT_SCOPE_HOST", RT_SCOPE_HOST);
     initConstant(env, c, "RT_SCOPE_LINK", RT_SCOPE_LINK);
     initConstant(env, c, "RT_SCOPE_NOWHERE", RT_SCOPE_NOWHERE);
@@ -500,20 +429,12 @@ static void OsConstants_initConstants(JNIEnv* env, jclass c) {
     initConstant(env, c, "SIGKILL", SIGKILL);
     initConstant(env, c, "SIGPIPE", SIGPIPE);
     initConstant(env, c, "SIGPROF", SIGPROF);
-#if defined(SIGPWR)
     initConstant(env, c, "SIGPWR", SIGPWR);
-#endif
     initConstant(env, c, "SIGQUIT", SIGQUIT);
-#if defined(SIGRTMAX)
     initConstant(env, c, "SIGRTMAX", SIGRTMAX);
-#endif
-#if defined(SIGRTMIN)
     initConstant(env, c, "SIGRTMIN", SIGRTMIN);
-#endif
     initConstant(env, c, "SIGSEGV", SIGSEGV);
-#if defined(SIGSTKFLT)
     initConstant(env, c, "SIGSTKFLT", SIGSTKFLT);
-#endif
     initConstant(env, c, "SIGSTOP", SIGSTOP);
     initConstant(env, c, "SIGSYS", SIGSYS);
     initConstant(env, c, "SIGTERM", SIGTERM);
@@ -539,32 +460,20 @@ static void OsConstants_initConstants(JNIEnv* env, jclass c) {
     initConstant(env, c, "SOCK_SEQPACKET", SOCK_SEQPACKET);
     initConstant(env, c, "SOCK_STREAM", SOCK_STREAM);
     initConstant(env, c, "SOL_SOCKET", SOL_SOCKET);
-#if defined(SOL_UDP)
     initConstant(env, c, "SOL_UDP", SOL_UDP);
-#endif
     initConstant(env, c, "SOL_PACKET", SOL_PACKET);
-#if defined(SO_BINDTODEVICE)
     initConstant(env, c, "SO_BINDTODEVICE", SO_BINDTODEVICE);
-#endif
     initConstant(env, c, "SO_BROADCAST", SO_BROADCAST);
     initConstant(env, c, "SO_DEBUG", SO_DEBUG);
-#if defined(SO_DOMAIN)
     initConstant(env, c, "SO_DOMAIN", SO_DOMAIN);
-#endif
     initConstant(env, c, "SO_DONTROUTE", SO_DONTROUTE);
     initConstant(env, c, "SO_ERROR", SO_ERROR);
     initConstant(env, c, "SO_KEEPALIVE", SO_KEEPALIVE);
     initConstant(env, c, "SO_LINGER", SO_LINGER);
     initConstant(env, c, "SO_OOBINLINE", SO_OOBINLINE);
-#if defined(SO_PASSCRED)
     initConstant(env, c, "SO_PASSCRED", SO_PASSCRED);
-#endif
-#if defined(SO_PEERCRED)
     initConstant(env, c, "SO_PEERCRED", SO_PEERCRED);
-#endif
-#if defined(SO_PROTOCOL)
     initConstant(env, c, "SO_PROTOCOL", SO_PROTOCOL);
-#endif
     initConstant(env, c, "SO_RCVBUF", SO_RCVBUF);
     initConstant(env, c, "SO_RCVLOWAT", SO_RCVLOWAT);
     initConstant(env, c, "SO_RCVTIMEO", SO_RCVTIMEO);
@@ -573,9 +482,7 @@ static void OsConstants_initConstants(JNIEnv* env, jclass c) {
     initConstant(env, c, "SO_SNDLOWAT", SO_SNDLOWAT);
     initConstant(env, c, "SO_SNDTIMEO", SO_SNDTIMEO);
     initConstant(env, c, "SO_TYPE", SO_TYPE);
-#if defined(PACKET_IGNORE_OUTGOING)
     initConstant(env, c, "PACKET_IGNORE_OUTGOING", PACKET_IGNORE_OUTGOING);
-#endif
     initConstant(env, c, "SPLICE_F_MOVE", SPLICE_F_MOVE);
     initConstant(env, c, "SPLICE_F_NONBLOCK", SPLICE_F_NONBLOCK);
     initConstant(env, c, "SPLICE_F_MORE", SPLICE_F_MORE);
@@ -615,19 +522,13 @@ static void OsConstants_initConstants(JNIEnv* env, jclass c) {
     initConstant(env, c, "S_IXOTH", S_IXOTH);
     initConstant(env, c, "S_IXUSR", S_IXUSR);
     initConstant(env, c, "TCP_NODELAY", TCP_NODELAY);
-#if defined(TCP_USER_TIMEOUT)
     initConstant(env, c, "TCP_USER_TIMEOUT", TCP_USER_TIMEOUT);
-#endif
     initConstant(env, c, "TIOCOUTQ", TIOCOUTQ);
     initConstant(env, c, "UDP_ENCAP", UDP_ENCAP);
     initConstant(env, c, "UDP_ENCAP_ESPINUDP_NON_IKE", UDP_ENCAP_ESPINUDP_NON_IKE);
     initConstant(env, c, "UDP_ENCAP_ESPINUDP", UDP_ENCAP_ESPINUDP);
-#if defined(UDP_GRO)
     initConstant(env, c, "UDP_GRO", UDP_GRO);
-#endif
-#if defined(UDP_SEGMENT)
     initConstant(env, c, "UDP_SEGMENT", UDP_SEGMENT);
-#endif
     // UNIX_PATH_MAX is mentioned in some versions of unix(7), but not actually declared.
     initConstant(env, c, "UNIX_PATH_MAX", sizeof(sockaddr_un::sun_path));
     initConstant(env, c, "WCONTINUED", WCONTINUED);
@@ -643,9 +544,7 @@ static void OsConstants_initConstants(JNIEnv* env, jclass c) {
     initConstant(env, c, "_SC_2_CHAR_TERM", _SC_2_CHAR_TERM);
     initConstant(env, c, "_SC_2_C_BIND", _SC_2_C_BIND);
     initConstant(env, c, "_SC_2_C_DEV", _SC_2_C_DEV);
-#if defined(_SC_2_C_VERSION)
     initConstant(env, c, "_SC_2_C_VERSION", _SC_2_C_VERSION);
-#endif
     initConstant(env, c, "_SC_2_FORT_DEV", _SC_2_FORT_DEV);
     initConstant(env, c, "_SC_2_FORT_RUN", _SC_2_FORT_RUN);
     initConstant(env, c, "_SC_2_LOCALEDEF", _SC_2_LOCALEDEF);
@@ -658,9 +557,7 @@ static void OsConstants_initConstants(JNIEnv* env, jclass c) {
     initConstant(env, c, "_SC_ARG_MAX", _SC_ARG_MAX);
     initConstant(env, c, "_SC_ASYNCHRONOUS_IO", _SC_ASYNCHRONOUS_IO);
     initConstant(env, c, "_SC_ATEXIT_MAX", _SC_ATEXIT_MAX);
-#if defined(_SC_AVPHYS_PAGES)
     initConstant(env, c, "_SC_AVPHYS_PAGES", _SC_AVPHYS_PAGES);
-#endif
     initConstant(env, c, "_SC_BC_BASE_MAX", _SC_BC_BASE_MAX);
     initConstant(env, c, "_SC_BC_DIM_MAX", _SC_BC_DIM_MAX);
     initConstant(env, c, "_SC_BC_SCALE_MAX", _SC_BC_SCALE_MAX);
@@ -691,9 +588,7 @@ static void OsConstants_initConstants(JNIEnv* env, jclass c) {
     initConstant(env, c, "_SC_PAGESIZE", _SC_PAGESIZE);
     initConstant(env, c, "_SC_PAGE_SIZE", _SC_PAGE_SIZE);
     initConstant(env, c, "_SC_PASS_MAX", _SC_PASS_MAX);
-#if defined(_SC_PHYS_PAGES)
     initConstant(env, c, "_SC_PHYS_PAGES", _SC_PHYS_PAGES);
-#endif
     initConstant(env, c, "_SC_PRIORITIZED_IO", _SC_PRIORITIZED_IO);
     initConstant(env, c, "_SC_PRIORITY_SCHEDULING", _SC_PRIORITY_SCHEDULING);
     initConstant(env, c, "_SC_REALTIME_SIGNALS", _SC_REALTIME_SIGNALS);
diff --git a/luni/src/main/native/libcore_io_Linux.cpp b/luni/src/main/native/libcore_io_Linux.cpp
index 5a4de35ccb2..78b1788981c 100644
--- a/luni/src/main/native/libcore_io_Linux.cpp
+++ b/luni/src/main/native/libcore_io_Linux.cpp
@@ -93,14 +93,6 @@ jfieldID int64RefValueFid;
 
 }  // namespace
 
-struct addrinfo_deleter {
-    void operator()(addrinfo* p) const {
-        if (p != NULL) { // bionic's freeaddrinfo(3) crashes when passed NULL.
-            freeaddrinfo(p);
-        }
-    }
-};
-
 struct c_deleter {
     void operator()(void* p) const {
         free(p);
@@ -1386,7 +1378,7 @@ static jobjectArray Linux_android_getaddrinfo(JNIEnv* env, jobject, jstring java
     addrinfo* addressList = NULL;
     errno = 0;
     int rc = android_getaddrinfofornet(node.c_str(), NULL, &hints, netId, 0, &addressList);
-    std::unique_ptr<addrinfo, addrinfo_deleter> addressListDeleter(addressList);
+    std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> addressListDeleter(addressList, freeaddrinfo);
     if (rc != 0) {
         throwGaiException(env, "android_getaddrinfo", rc);
         return NULL;
@@ -1903,19 +1895,18 @@ static jobject Linux_lstat(JNIEnv* env, jobject, jstring javaPath) {
     return doStat(env, javaPath, true);
 }
 
+static void Linux_madvise(JNIEnv* env, jobject, jlong address, jlong byteCount, jint advice) {
+    void* ptr = reinterpret_cast<void*>(static_cast<uintptr_t>(address));
+    throwIfMinusOne(env, "madvise", TEMP_FAILURE_RETRY(madvise(ptr, byteCount, advice)));
+}
+
 static jobject Linux_memfd_create(JNIEnv* env, jobject, jstring javaName, jint flags) {
-#if defined(__BIONIC__)
     ScopedUtfChars name(env, javaName);
     if (name.c_str() == NULL) {
         return NULL;
     }
-
-    int fd = throwIfMinusOne(env, "memfd_create", memfd_create(name.c_str(), flags));
+    int fd = throwIfMinusOne(env, "memfd_create", syscall(__NR_memfd_create, name.c_str(), flags));
     return createFileDescriptorIfOpen(env, fd);
-#else
-    UNUSED(env, javaName, flags);
-    return NULL;
-#endif
 }
 
 static void Linux_mincore(JNIEnv* env, jobject, jlong address, jlong byteCount, jbyteArray javaVector) {
@@ -2284,14 +2275,13 @@ static void Linux_rename(JNIEnv* env, jobject, jstring javaOldPath, jstring java
 static jlong Linux_sendfile(JNIEnv* env, jobject, jobject javaOutFd, jobject javaInFd, jobject javaOffset, jlong byteCount) {
     int outFd = jniGetFDFromFileDescriptor(env, javaOutFd);
     int inFd = jniGetFDFromFileDescriptor(env, javaInFd);
-    off_t offset = 0;
-    off_t* offsetPtr = NULL;
+    off64_t offset = 0;
+    off64_t* offsetPtr = NULL;
     if (javaOffset != NULL) {
-        // TODO: fix bionic so we can have a 64-bit off_t!
         offset = env->GetLongField(javaOffset, int64RefValueFid);
         offsetPtr = &offset;
     }
-    jlong result = throwIfMinusOne(env, "sendfile", TEMP_FAILURE_RETRY(sendfile(outFd, inFd, offsetPtr, byteCount)));
+    jlong result = throwIfMinusOne(env, "sendfile", TEMP_FAILURE_RETRY(sendfile64(outFd, inFd, offsetPtr, byteCount)));
     if (result == -1) {
         return -1;
     }
@@ -2833,6 +2823,7 @@ static JNINativeMethod gMethods[] = {
     NATIVE_METHOD(Linux, listxattr, "(Ljava/lang/String;)[Ljava/lang/String;"),
     NATIVE_METHOD(Linux, lseek, "(Ljava/io/FileDescriptor;JI)J"),
     NATIVE_METHOD(Linux, lstat, "(Ljava/lang/String;)Landroid/system/StructStat;"),
+    NATIVE_METHOD(Linux, madvise, "(JJI)V"),
     NATIVE_METHOD(Linux, memfd_create, "(Ljava/lang/String;I)Ljava/io/FileDescriptor;"),
     NATIVE_METHOD(Linux, mincore, "(JJ[B)V"),
     NATIVE_METHOD(Linux, mkdir, "(Ljava/lang/String;I)V"),
diff --git a/luni/src/test/java/crossvmtest/java/lang/RecordComponentTest.java b/luni/src/test/java/crossvmtest/java/lang/RecordComponentTest.java
index 01f6d19d089..46d829cf7f8 100644
--- a/luni/src/test/java/crossvmtest/java/lang/RecordComponentTest.java
+++ b/luni/src/test/java/crossvmtest/java/lang/RecordComponentTest.java
@@ -33,7 +33,9 @@ import java.lang.reflect.RecordComponent;
 import java.math.BigInteger;
 import java.util.AbstractMap;
 import java.util.Arrays;
+import java.util.HashMap;
 import java.util.List;
+import java.util.Objects;
 
 public class RecordComponentTest {
 
@@ -53,7 +55,24 @@ public class RecordComponentTest {
     record RecordString(String s) {}
 
     record GenericRecord<A, B extends AbstractMap<String, BigInteger>> (
-            A a, B b, List<String> c) {}
+            A a, B b, List<String> c) {
+        @SuppressWarnings("SelfAssignment")
+        GenericRecord { // compact canonical constructor
+            c = Objects.requireNonNull(c);
+        }
+
+        // The following constructors are useful when the definition of a record evolves,
+        // and more record components are added into the record.
+        GenericRecord(A a) {
+            this(a, null, List.of());
+        }
+
+        GenericRecord(A a, B b) {
+            this(a, b, List.of());
+        }
+
+
+    }
 
     @Test
     public void testBasic() {
@@ -147,6 +166,31 @@ public class RecordComponentTest {
         assertEquals("java.util.List<java.lang.String>", components[2].getGenericType().getTypeName());
     }
 
+    @Test
+    public void testSecondaryConstructors() {
+        var r = new GenericRecord<String, HashMap<String, BigInteger>>("abc");
+        assertEquals("abc", r.a);
+        assertNull(r.b);
+        assertEquals(List.of(), r.c);
+
+        HashMap<String, BigInteger> map = HashMap.newHashMap(1);
+        map.put("123", BigInteger.valueOf(5L));
+        r = new GenericRecord<>("abc", map);
+        assertEquals("abc", r.a);
+        assertEquals(BigInteger.valueOf(5L), r.b.get("123"));
+        assertEquals(List.of(), r.c);
+    }
+
+    @Test
+    public void testCanonicalConstructors() {
+        GenericRecord<String, HashMap<String, BigInteger>> r = new GenericRecord<>(null, null,
+                List.of());
+        assertEquals(List.of(), r.c);
+
+        Assert.assertThrows(NullPointerException.class,
+                () -> new GenericRecord<>(null, null, null));
+    }
+
     @Test
     public void testGetGenericSingature() {
         RecordComponent[] components = RecordInteger.class.getRecordComponents();
diff --git a/luni/src/test/java/crossvmtest/java/lang/RecordTest.java b/luni/src/test/java/crossvmtest/java/lang/RecordTest.java
index fc0cac3dfde..c440c2704b3 100644
--- a/luni/src/test/java/crossvmtest/java/lang/RecordTest.java
+++ b/luni/src/test/java/crossvmtest/java/lang/RecordTest.java
@@ -42,6 +42,8 @@ import java.lang.invoke.VarHandle;
 import java.lang.reflect.Constructor;
 import java.lang.reflect.Field;
 import java.util.Arrays;
+import java.util.function.IntFunction;
+import java.util.function.Supplier;
 
 public class RecordTest {
 
@@ -237,4 +239,61 @@ public class RecordTest {
             assertEquals("abc", r.s());
         }
     }
+
+    @Test
+    public void testLocalRecord() {
+        record Point(int x, int y) {
+            @Override
+            public int y() {
+                return Math.abs(y);
+            }
+
+            public long sum() {
+                return (long) x + y;
+            }
+        }
+        var r = new Point(3, 4);
+        assertEquals(3, r.x);
+        assertEquals(4, r.y());
+        assertEquals(7, r.sum());
+        r = new Point(-6, -7);
+        assertEquals(-6, r.x);
+        assertEquals(-6, r.x());
+        assertEquals(-7, r.y);
+        assertEquals(7, r.y());
+        assertEquals(-13, r.sum());
+    }
+
+    record SupplierRecord(int x)  implements Supplier<String> {
+
+        private static int A = 9;
+
+        static void setStatic(int a) {
+            A = a;
+        }
+
+        static int getStatic() {
+            return A;
+        }
+
+        @Override
+        public String get() {
+            return String.valueOf(x);
+        }
+    }
+
+    @Test
+    public void testOverriddenInterfaceMethod() {
+        var r = new SupplierRecord(5);
+        assertEquals(5, r.x);
+        assertEquals("5", r.get());
+    }
+
+    @Test
+    public void testStaticMethods() {
+        SupplierRecord.setStatic(5);
+        assertEquals(5, SupplierRecord.getStatic());
+        SupplierRecord.setStatic(3);
+        assertEquals(3, SupplierRecord.getStatic());
+    }
 }
diff --git a/luni/src/test/java/libcore/android/crypto/hpke/HpkeTest.java b/luni/src/test/java/libcore/android/crypto/hpke/HpkeTest.java
new file mode 100644
index 00000000000..3aba21da00e
--- /dev/null
+++ b/luni/src/test/java/libcore/android/crypto/hpke/HpkeTest.java
@@ -0,0 +1,306 @@
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
+package libcore.android.crypto.hpke;
+
+import static android.crypto.hpke.AeadParameterSpec.AES_128_GCM;
+import static android.crypto.hpke.AeadParameterSpec.AES_256_GCM;
+import static android.crypto.hpke.AeadParameterSpec.CHACHA20POLY1305;
+import static android.crypto.hpke.KdfParameterSpec.HKDF_SHA256;
+import static android.crypto.hpke.KemParameterSpec.DHKEM_X25519_HKDF_SHA256;
+
+import static org.junit.Assert.assertArrayEquals;
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertNotEquals;
+import static org.junit.Assert.assertNotNull;
+import static org.junit.Assert.assertThrows;
+
+import android.crypto.hpke.AeadParameterSpec;
+import android.crypto.hpke.Hpke;
+import android.crypto.hpke.Message;
+import android.crypto.hpke.Recipient;
+import android.crypto.hpke.Sender;
+
+import libcore.util.NonNull;
+
+import org.junit.Before;
+import org.junit.Test;
+import org.junit.experimental.runners.Enclosed;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+import org.junit.runners.Parameterized;
+import org.junit.runners.Parameterized.Parameter;
+import org.junit.runners.Parameterized.Parameters;
+
+import java.nio.charset.StandardCharsets;
+import java.security.InvalidKeyException;
+import java.security.KeyPair;
+import java.security.KeyPairGenerator;
+import java.security.NoSuchAlgorithmException;
+import java.security.NoSuchProviderException;
+import java.security.PrivateKey;
+import java.security.Provider;
+import java.security.PublicKey;
+import java.security.Security;
+import java.util.List;
+
+@RunWith(Enclosed.class)
+public class HpkeTest {
+
+    @RunWith(Parameterized.class)
+    public static class SendReceiveTests {
+        private PublicKey publicKey;
+        private PrivateKey privateKey;
+
+        private static final byte[] EMPTY = new byte[0];
+        private static final byte[] MESSAGE = "This is only a test".getBytes(StandardCharsets.US_ASCII);
+        private static final byte[] INFO = "App info".getBytes(StandardCharsets.US_ASCII);
+        private static final byte[] AAD = "Additional data".getBytes(StandardCharsets.US_ASCII);
+
+        @Parameters
+        public static Object[][] data() {
+            Object[] aads = new Object[]{null, EMPTY, AAD};
+            Object[] infos = new Object[]{null, EMPTY, INFO};
+            Object[] messages = new Object[]{EMPTY, MESSAGE};
+            Object[][] ciphers = new Object[][]{
+                    {AES_128_GCM},
+                    {AES_256_GCM},
+                    {CHACHA20POLY1305}
+            };
+            return permute(aads, permute(infos, permute(messages, ciphers)));
+        }
+
+        @Parameter()
+        public byte[] aad;
+
+        @Parameter(1)
+        public byte[] info;
+
+        @Parameter(2)
+        public byte[] plaintext;
+
+        @Parameter(3)
+        public AeadParameterSpec aead;
+
+        private String suiteName;
+
+        @Before
+        public void before() throws Exception {
+            KeyPairGenerator generator = KeyPairGenerator.getInstance("XDH");
+            KeyPair pair = generator.generateKeyPair();
+            publicKey = pair.getPublic();
+            privateKey = pair.getPrivate();
+            suiteName = Hpke.getSuiteName(DHKEM_X25519_HKDF_SHA256, HKDF_SHA256, aead);
+            assertNotNull(suiteName);
+        }
+
+        @Test
+        public void sendMessage() throws Exception {
+            Hpke hpke = Hpke.getInstance(suiteName);
+            assertNotNull(hpke);
+            Sender.Builder senderBuilder = new Sender.Builder(hpke, publicKey);
+            if (info != null) {
+                senderBuilder.setApplicationInfo(info);
+            }
+            Sender sender = senderBuilder.build();
+            byte[] ciphertext = sender.seal(plaintext, aad);
+            byte[] encapsulated = sender.getEncapsulated();
+            assertNotNull(encapsulated);
+
+            Recipient.Builder recipientBuilder =
+                    new Recipient.Builder(hpke, encapsulated, privateKey);
+            if (info != null) {
+                recipientBuilder.setApplicationInfo(info);
+            }
+            Recipient recipient = recipientBuilder.build();
+            byte[] decoded = recipient.open(ciphertext, aad);
+            assertNotNull(decoded);
+
+            assertArrayEquals(plaintext, decoded);
+        }
+
+        @Test
+        public void oneshot() throws Exception {
+            Hpke hpke = Hpke.getInstance(suiteName);
+            Message message = hpke.seal(publicKey, info, plaintext, aad);
+            byte[] decoded = hpke.open(privateKey, info, message, aad);
+            assertArrayEquals(plaintext, decoded);
+        }
+
+        // Permute a new set of values into an existing Parameters array, i.e. one new row
+        // is created for every combination of each new value and existing row.
+        private static Object[][] permute(Object[] newValues, Object[][] existing) {
+            int newSize = newValues.length * existing.length;
+            int rowSize = existing[0].length + 1;
+            Object[][] result = new Object[newSize][];
+            for (int i = 0; i < newSize; i++) {
+                Object[] row = new Object[rowSize];
+                result[i] = row;
+                row[0] = newValues[i % newValues.length];
+                System.arraycopy(existing[i / newValues.length], 0, row, 1, rowSize - 1);
+            }
+            return result;
+        }
+    }
+
+    @RunWith(JUnit4.class)
+    public static class OtherTests {
+        private static final String SUITE_NAME = "DHKEM_X25519_HKDF_SHA256/HKDF_SHA256/AES_128_GCM";
+        private static final int EXPORT_LENGTH = 16;
+        private static final String CONSCRYPT_NAME = "AndroidOpenSSL";
+        private final Provider conscrypt = Security.getProvider(CONSCRYPT_NAME);
+
+        private PublicKey publicKey;
+        private PrivateKey privateKey;
+
+        @Before
+        public void before() throws Exception {
+            KeyPairGenerator generator = KeyPairGenerator.getInstance("XDH");
+            KeyPair pair = generator.generateKeyPair();
+            publicKey = pair.getPublic();
+            privateKey = pair.getPrivate();
+        }
+
+        @Test
+        public void init_Errors() {
+            assertThrows(NoSuchAlgorithmException.class,
+                    () ->Hpke.getInstance("No such"));
+            assertThrows(NoSuchAlgorithmException.class,
+                    () ->Hpke.getInstance(""));
+            assertThrows(NoSuchAlgorithmException.class,
+                    () ->Hpke.getInstance(null));
+
+            assertThrows(IllegalArgumentException.class,
+                    () ->Hpke.getInstance(SUITE_NAME, (String) null));
+            assertThrows(IllegalArgumentException.class,
+                    () ->Hpke.getInstance(SUITE_NAME, ""));
+            assertThrows(NoSuchProviderException.class,
+                    () ->Hpke.getInstance(SUITE_NAME, "No such"));
+            assertThrows(NoSuchAlgorithmException.class,
+                    () ->Hpke.getInstance("No such", CONSCRYPT_NAME));
+            assertThrows(NoSuchAlgorithmException.class,
+                    () ->Hpke.getInstance("", CONSCRYPT_NAME));
+            assertThrows(NoSuchAlgorithmException.class,
+                    () ->Hpke.getInstance(null, CONSCRYPT_NAME));
+
+            assertThrows(IllegalArgumentException.class,
+                    () ->Hpke.getInstance(SUITE_NAME, (Provider) null));
+            assertThrows(NoSuchAlgorithmException.class,
+                    () ->Hpke.getInstance("No such", conscrypt));
+            assertThrows(NoSuchAlgorithmException.class,
+                    () ->Hpke.getInstance("", conscrypt));
+            assertThrows(NoSuchAlgorithmException.class,
+                    () ->Hpke.getInstance(null, conscrypt));
+        }
+
+        @Test
+        public void keyType() throws Exception {
+            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
+            KeyPair pair = generator.generateKeyPair();
+            PublicKey publicRsa = pair.getPublic();
+            PrivateKey privateRsa = pair.getPrivate();
+            Hpke hpke = Hpke.getInstance(SUITE_NAME);
+
+            assertThrows(InvalidKeyException.class,
+                    () -> new Sender.Builder(hpke, publicRsa).build());
+            assertThrows(InvalidKeyException.class,
+                    () -> new Recipient.Builder(hpke, new byte[16], privateRsa).build());
+        }
+
+        @Test
+        public void suiteNames() throws Exception {
+            List<AeadParameterSpec> aeads = List.of(AES_128_GCM, AES_256_GCM, CHACHA20POLY1305);
+            for (AeadParameterSpec aead : aeads) {
+                String suiteName
+                        = Hpke.getSuiteName(DHKEM_X25519_HKDF_SHA256, HKDF_SHA256, aead);
+                assertNotNull(suiteName);
+                assertNotNull(Hpke.getInstance(suiteName));
+                // Also check Tink-compatible names
+                // TODO(prb) enable after https://github.com/google/conscrypt/pull/1258 lands
+                // String altName = suiteName.replaceAll("/", "_");
+                // assertNotNull(Hpke.getInstance(altName));
+            }
+        }
+
+        // Note API test only, implementation tests are in Conscrypt.
+        @Test
+        public void export() throws Exception {
+            byte[] context = "Hello".getBytes(StandardCharsets.UTF_8);
+            Hpke hpke = Hpke.getInstance(SUITE_NAME);
+            assertNotNull(hpke);
+            Sender sender = new Sender.Builder(hpke, publicKey).build();
+            Recipient recipient =
+                    new Recipient.Builder(hpke, sender.getEncapsulated(), privateKey).build();
+            assertNotNull(recipient);
+
+            byte[] senderData = sender.export(EXPORT_LENGTH, context);
+            assertNotNull(senderData);
+            assertEquals(EXPORT_LENGTH, senderData.length);
+            int sum = 0;
+            for (byte b : senderData) {
+                sum += b;
+            }
+            // Check data isn't all zeroes.
+            assertNotEquals(0, sum);
+
+            byte[] recipientData = recipient.export(EXPORT_LENGTH, context);
+            assertArrayEquals(senderData, recipientData);
+        }
+
+        @Test
+        public void spiAndProvider() throws Exception{
+            Hpke hpke = Hpke.getInstance(SUITE_NAME);
+            assertNotNull(hpke);
+            assertNotNull(hpke.getProvider());
+
+            Sender sender = new Sender.Builder(hpke, publicKey).build();
+            Recipient recipient =
+                    new Recipient.Builder(hpke, sender.getEncapsulated(), privateKey).build();
+            assertNotNull(recipient);
+
+            assertNotNull(sender.getProvider());
+            assertNotNull(sender.getSpi());
+            assertNotNull(recipient.getProvider());
+            assertNotNull(recipient.getSpi());
+        }
+
+        // Note API test only.  Implementation not yet present.
+        @Test
+        public void futureBuilderMethods() throws Exception {
+            byte[] appInfo = "App Info".getBytes(StandardCharsets.UTF_8);
+            byte[] psk = "Very Secret Key".getBytes(StandardCharsets.UTF_8);
+            byte[] pskId = "ID".getBytes(StandardCharsets.UTF_8);
+
+            Hpke hpke = Hpke.getInstance(SUITE_NAME);
+            assertNotNull(hpke);
+
+            Sender.Builder senderBuilder = new Sender.Builder(hpke, publicKey)
+                    .setApplicationInfo(appInfo)
+                    .setSenderKey(privateKey)
+                    .setPsk(psk, pskId);
+            assertThrows(UnsupportedOperationException.class, senderBuilder::build);
+
+            Sender sender = new Sender.Builder(hpke, publicKey).build();
+            assertNotNull(sender);
+
+            Recipient.Builder recipientBuilder =
+                    new Recipient.Builder(hpke, sender.getEncapsulated(), privateKey)
+                            .setApplicationInfo(appInfo)
+                            .setSenderKey(publicKey)
+                            .setPsk(psk, pskId);
+            assertThrows(UnsupportedOperationException.class, recipientBuilder::build);
+        }
+    }
+}
\ No newline at end of file
diff --git a/luni/src/test/java/libcore/android/system/NetlinkSocketAddressTest.java b/luni/src/test/java/libcore/android/system/NetlinkSocketAddressTest.java
new file mode 100644
index 00000000000..7f756c92740
--- /dev/null
+++ b/luni/src/test/java/libcore/android/system/NetlinkSocketAddressTest.java
@@ -0,0 +1,35 @@
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
+
+package libcore.android.system;
+
+import static org.junit.Assert.assertEquals;
+
+import android.system.NetlinkSocketAddress;
+
+import org.junit.Test;
+
+public class NetlinkSocketAddressTest {
+
+    @Test
+    public void test_constructor() {
+        NetlinkSocketAddress address = new NetlinkSocketAddress(100, 200);
+
+        assertEquals(100, address.getPortId());
+        assertEquals(200, address.getGroupsMask());
+    }
+
+}
diff --git a/luni/src/test/java/libcore/android/system/OsConstantsTest.java b/luni/src/test/java/libcore/android/system/OsConstantsTest.java
index f795d455444..f95011de679 100644
--- a/luni/src/test/java/libcore/android/system/OsConstantsTest.java
+++ b/luni/src/test/java/libcore/android/system/OsConstantsTest.java
@@ -438,4 +438,9 @@ public class OsConstantsTest {
         assertFalse(WIFSIGNALED(0));
         assertTrue(WIFSIGNALED(1));
     }
+
+    @Test
+    public void errno_returnsNull_onUnknown() {
+        assertNull(OsConstants.errnoName(99999999));
+    }
 }
diff --git a/luni/src/test/java/libcore/android/system/OsTest.java b/luni/src/test/java/libcore/android/system/OsTest.java
index 209f30bec27..f78d1a17163 100644
--- a/luni/src/test/java/libcore/android/system/OsTest.java
+++ b/luni/src/test/java/libcore/android/system/OsTest.java
@@ -2306,6 +2306,34 @@ public class OsTest {
         Os.munmap(address, size);
     }
 
+    @Test
+    public void testMadvise() throws Exception {
+        final long size = 4096;
+        final long address = Os.mmap(0, size, PROT_READ,
+                MAP_PRIVATE | MAP_ANONYMOUS, new FileDescriptor(), 0);
+        try {
+            // madvise just gives advice to the kernel.
+            // The kernel chooses whether and when to act on it.
+            // We can't directly observe the effect of the advice.
+            // So we just try the common values and make sure we don't crash.
+            Os.madvise(address, size, OsConstants.MADV_NORMAL);
+            Os.madvise(address, size, OsConstants.MADV_RANDOM);
+            Os.madvise(address, size, OsConstants.MADV_SEQUENTIAL);
+            Os.madvise(address, size, OsConstants.MADV_WILLNEED);
+            Os.madvise(address, size, OsConstants.MADV_DONTNEED);
+
+            Os.mlock(address, size);
+            expectException(
+                    () -> Os.madvise(address, size, OsConstants.MADV_DONTNEED),
+                    ErrnoException.class,
+                    OsConstants.EINVAL,
+                    "MADV_DONTNEED on mlock'ed memory should fail");
+            Os.munlock(address, size);
+        } finally {
+            Os.munmap(address, size);
+        }
+    }
+
     /*
      * Checks that all ways of accessing the environment are consistent by collecting:
      * osEnvironment      - The environment returned by Os.environ()
diff --git a/luni/src/test/java/libcore/dalvik/system/VMRuntimeTest.java b/luni/src/test/java/libcore/dalvik/system/VMRuntimeTest.java
index 4c1a080e137..605d4e7ad15 100644
--- a/luni/src/test/java/libcore/dalvik/system/VMRuntimeTest.java
+++ b/luni/src/test/java/libcore/dalvik/system/VMRuntimeTest.java
@@ -155,11 +155,7 @@ public final class VMRuntimeTest {
 
     @Test
     public void testIsArtTestFlagEnabled() {
-        boolean b = VMRuntime.isArtTestFlagEnabled();
-        // TODO(b/352723620): The flag value depends on the release
-        // configurations. Don't assert the value until the flag is turned on in
-        // all configurations.
-        Assume.assumeTrue(b);
+        assertTrue(VMRuntime.isArtTestFlagEnabled());
     }
 
     @Test
diff --git a/luni/src/test/java/libcore/java/lang/StackWalkerTest.java b/luni/src/test/java/libcore/java/lang/StackWalkerTest.java
index d24cbca74a2..6228b33e81c 100644
--- a/luni/src/test/java/libcore/java/lang/StackWalkerTest.java
+++ b/luni/src/test/java/libcore/java/lang/StackWalkerTest.java
@@ -16,7 +16,6 @@
 
 package libcore.java.lang;
 
-import org.junit.Assert;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.junit.runners.JUnit4;
@@ -25,18 +24,27 @@ import java.io.IOException;
 import java.io.InputStream;
 import java.lang.StackWalker.Option;
 import java.lang.StackWalker.StackFrame;
+import java.lang.reflect.InvocationHandler;
+import java.lang.reflect.Method;
+import java.lang.reflect.Proxy;
 import java.nio.ByteBuffer;
 import java.util.Arrays;
 import java.util.List;
+import java.util.stream.Collectors;
+
 import libcore.io.Streams;
 
 import dalvik.system.InMemoryDexClassLoader;
 
 import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertNotEquals;
+import static org.junit.Assert.assertNotNull;
 import static org.junit.Assert.assertSame;
 import static org.junit.Assert.assertTrue;
 import static org.junit.Assert.fail;
 
+import static java.util.stream.Collectors.toList;
+
 @RunWith(JUnit4.class)
 public class StackWalkerTest {
 
@@ -109,4 +117,82 @@ public class StackWalkerTest {
         fail("fail to find " + expected + " in " + Arrays.toString(options));
     }
 
+    public interface ProxiedInterface {
+        void run();
+    }
+
+    // regression test for b/404180956
+    @Test
+    public void testProxy_withTestInterface() {
+        String[][] expectedFrame = new String[][] {
+                new String[] {MyInvocationHandler.class.getName(), "invoke"},
+                // The new RI doesn't have this java.lang.reflect.Proxy frame.
+                new String[] {"java.lang.reflect.Proxy", "invoke"},
+                // Ensure that the interface name isn't returned.
+                new String[] {"~" + ProxiedInterface.class.getName(), "run"},
+                new String[] {StackWalkerTest.class.getName(), "testProxy_withTestInterface"},
+
+        };
+        InvocationHandler handler = new MyInvocationHandler(expectedFrame);
+
+        ProxiedInterface proxy = (ProxiedInterface) Proxy.newProxyInstance(
+                ProxiedInterface.class.getClassLoader(),
+                new Class[] {ProxiedInterface.class}, handler);
+        proxy.run();
+    }
+
+    @Test
+    public void testProxy_withRunnable() {
+        String[][] expectedFrame = new String[][] {
+                new String[] {MyInvocationHandler.class.getName(), "invoke"},
+                // The new RI doesn't have this java.lang.reflect.Proxy frame.
+                new String[] {"java.lang.reflect.Proxy", "invoke"},
+                // Ensure that the interface name isn't returned.
+                new String[] {"~" + Runnable.class.getName(), "run"},
+                new String[] {StackWalkerTest.class.getName(), "testProxy_withRunnable"},
+
+        };
+        InvocationHandler handler = new MyInvocationHandler(expectedFrame);
+
+        Runnable proxy = (Runnable) Proxy.newProxyInstance(Runnable.class.getClassLoader(),
+                new Class[] {Runnable.class}, handler);
+        proxy.run();
+    }
+
+    private static class MyInvocationHandler implements InvocationHandler {
+
+        private final String[][] expectedTopClassAndMethodNames;
+
+        public MyInvocationHandler(String[][] expectedTopClassAndMethodNames) {
+            this.expectedTopClassAndMethodNames = expectedTopClassAndMethodNames;
+        }
+
+        @Override
+        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
+            if (!"run".equals(method.getName())) {
+                throw new AssertionError("Only run() method can be invoked.");
+            }
+
+            // The bottom frames are not verified, but reading all frames ensures not crashing.
+            List<StackFrame> frames = StackWalker.getInstance().walk(
+                    stackFrameStream -> stackFrameStream.collect(toList()));
+
+            for (int i = 0; i < expectedTopClassAndMethodNames.length; i++) {
+                String[] classAndMethodName = expectedTopClassAndMethodNames[i];
+                assertTrue("stack size should be larger than " + i, frames.size() > i);
+                StackFrame frame = frames.get(i);
+                assertNotNull("The frame is null at index " + i, frame);
+                String expectedClassName = classAndMethodName[0];
+                if (expectedClassName.startsWith("~")) {
+                    String unexpectedClassName = expectedClassName.substring(1);
+                    assertNotEquals(unexpectedClassName, frame.getClassName());
+                } else {
+                    assertEquals(expectedClassName, frame.getClassName());
+                }
+                assertEquals(classAndMethodName[1], frame.getMethodName());
+            }
+            return null;
+        }
+    }
+
 }
\ No newline at end of file
diff --git a/luni/src/test/java/libcore/java/lang/invoke/MHCollectArgumentsTest.java b/luni/src/test/java/libcore/java/lang/invoke/MHCollectArgumentsTest.java
new file mode 100644
index 00000000000..17613803c63
--- /dev/null
+++ b/luni/src/test/java/libcore/java/lang/invoke/MHCollectArgumentsTest.java
@@ -0,0 +1,96 @@
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
+
+package libcore.java.lang.invoke;
+
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertThrows;
+
+import static java.lang.invoke.MethodType.methodType;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
+import java.lang.invoke.MethodHandle;
+import java.lang.invoke.MethodHandles;
+import java.lang.invoke.MethodType;
+
+@RunWith(JUnit4.class)
+@SuppressWarnings("UnusedMethod") // Methods are used by MethodHandles
+public class MHCollectArgumentsTest {
+
+    private static int INT_FIELD = 0;
+
+    @Test
+    public void noArgs_voidFilter() throws Throwable {
+        MethodHandle sum = MethodHandles.lookup()
+            .findStatic(
+                    MHCollectArgumentsTest.class,
+                    "sum",
+                    methodType(int.class, int.class, int.class));
+
+        MethodHandle filter = MethodHandles.lookup()
+            .findStatic(
+                    MHCollectArgumentsTest.class,
+                    "sideEffect",
+                    methodType(void.class));
+
+        int result = (int) MethodHandles.collectArguments(sum, 0, filter).invokeExact(1, 2);
+        assertEquals(3, result);
+        assertEquals(42, INT_FIELD);
+
+        result = (int) MethodHandles.collectArguments(sum, 1, filter).invokeExact(1, 2);
+        assertEquals(3, result);
+        assertEquals(42 * 2, INT_FIELD);
+
+        result = (int) MethodHandles.collectArguments(sum, 2, filter).invokeExact(1, 2);
+        assertEquals(3, result);
+        assertEquals(42 * 3, INT_FIELD);
+    }
+
+    @Test
+    public void voidFilter_invalidPos() throws Throwable {
+        MethodHandle sum = MethodHandles.lookup()
+                .findStatic(
+                        MHCollectArgumentsTest.class,
+                        "sum",
+                        methodType(int.class, int.class, int.class));
+
+        MethodHandle filter = MethodHandles.lookup()
+                .findStatic(
+                        MHCollectArgumentsTest.class,
+                        "sideEffect",
+                        methodType(void.class));
+
+        assertThrows(
+                IllegalArgumentException.class,
+                () -> MethodHandles.collectArguments(sum, -1, filter));
+
+        assertThrows(
+                IllegalArgumentException.class,
+                () -> MethodHandles.collectArguments(sum, 3, filter));
+    }
+
+    private static int sum(int a, int b) {
+        return a + b;
+    }
+
+    private static void sideEffect() {
+        INT_FIELD += 42;
+    }
+
+}
diff --git a/luni/src/test/java/libcore/java/lang/invoke/MethodHandleAccessorsTest.java b/luni/src/test/java/libcore/java/lang/invoke/MethodHandleAccessorsTest.java
index 50363cffbd1..546537549fe 100644
--- a/luni/src/test/java/libcore/java/lang/invoke/MethodHandleAccessorsTest.java
+++ b/luni/src/test/java/libcore/java/lang/invoke/MethodHandleAccessorsTest.java
@@ -16,8 +16,6 @@
 
 package libcore.java.lang.invoke;
 
-import junit.framework.TestCase;
-
 import java.lang.invoke.MethodHandle;
 import java.lang.invoke.MethodHandles;
 import java.lang.invoke.WrongMethodTypeException;
@@ -26,7 +24,12 @@ import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertTrue;
 import static org.junit.Assert.fail;
 
-public class MethodHandleAccessorsTest extends junit.framework.TestCase {
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
+@RunWith(JUnit4.class)
+public class MethodHandleAccessorsTest {
     public static class ValueHolder {
         public boolean m_z = false;
         public byte m_b = 0;
@@ -38,6 +41,16 @@ public class MethodHandleAccessorsTest extends junit.framework.TestCase {
         public long m_j = 0;
         public String m_l = "a";
 
+        public volatile boolean m_v_z = false;
+        public volatile byte m_v_b = 0;
+        public volatile char m_v_c = 'a';
+        public volatile short m_v_s = 0;
+        public volatile int m_v_i = 0;
+        public volatile float m_v_f = 0.0f;
+        public volatile double m_v_d = 0.0;
+        public volatile long m_v_j = 0;
+        public volatile String m_v_l = "a";
+
         public static boolean s_z;
         public static byte s_b;
         public static char s_c;
@@ -48,6 +61,17 @@ public class MethodHandleAccessorsTest extends junit.framework.TestCase {
         public static long s_j;
         public static String s_l;
 
+        public static boolean s_v_z;
+        public static byte s_v_b;
+        public static char s_v_c;
+        public static short s_v_s;
+        public static int s_v_i;
+        public static float s_v_f;
+        public static double s_v_d;
+        public static long s_v_j;
+        public static String s_v_l;
+
+
         public final int m_fi = 0xa5a5a5a5;
         public static final int s_fi = 0x5a5a5a5a;
     }
@@ -533,6 +557,7 @@ public class MethodHandleAccessorsTest extends junit.framework.TestCase {
                 resultFor(primitive, PrimitiveType.String, accessor, AccessorType.SGET));
     }
 
+    @Test
     public void testBooleanSettersAndGetters() throws Throwable {
         ValueHolder valueHolder = new ValueHolder();
         MethodHandles.Lookup lookup = MethodHandles.lookup();
@@ -540,19 +565,34 @@ public class MethodHandleAccessorsTest extends junit.framework.TestCase {
         boolean[] booleans = {false, true, false};
         for (boolean b : booleans) {
             Boolean boxed = Boolean.valueOf(b);
+
             tryAccessor(lookup.findSetter(ValueHolder.class, "m_z", boolean.class),
                 valueHolder, PrimitiveType.Boolean, boxed, AccessorType.IPUT);
             tryAccessor(lookup.findGetter(ValueHolder.class, "m_z", boolean.class),
                 valueHolder, PrimitiveType.Boolean, boxed, AccessorType.IGET);
             assertTrue(valueHolder.m_z == b);
+
+            tryAccessor(lookup.findSetter(ValueHolder.class, "m_v_z", boolean.class),
+                valueHolder, PrimitiveType.Boolean, boxed, AccessorType.IPUT);
+            tryAccessor(lookup.findGetter(ValueHolder.class, "m_v_z", boolean.class),
+                valueHolder, PrimitiveType.Boolean, boxed, AccessorType.IGET);
+            assertTrue(valueHolder.m_v_z == b);
+
             tryAccessor(lookup.findStaticSetter(ValueHolder.class, "s_z", boolean.class),
                 valueHolder, PrimitiveType.Boolean, boxed, AccessorType.SPUT);
             tryAccessor(lookup.findStaticGetter(ValueHolder.class, "s_z", boolean.class),
                 valueHolder, PrimitiveType.Boolean, boxed, AccessorType.SGET);
             assertTrue(ValueHolder.s_z == b);
+
+            tryAccessor(lookup.findStaticSetter(ValueHolder.class, "s_v_z", boolean.class),
+                valueHolder, PrimitiveType.Boolean, boxed, AccessorType.SPUT);
+            tryAccessor(lookup.findStaticGetter(ValueHolder.class, "s_v_z", boolean.class),
+                valueHolder, PrimitiveType.Boolean, boxed, AccessorType.SGET);
+            assertTrue(ValueHolder.s_v_z == b);
         }
     }
 
+    @Test
     public void testByteSettersAndGetters() throws Throwable {
         ValueHolder valueHolder = new ValueHolder();
         MethodHandles.Lookup lookup = MethodHandles.lookup();
@@ -560,19 +600,33 @@ public class MethodHandleAccessorsTest extends junit.framework.TestCase {
         byte[] bytes = {(byte) 0x73, (byte) 0xfe};
         for (byte b : bytes) {
             Byte boxed = Byte.valueOf(b);
+
             tryAccessor(lookup.findSetter(ValueHolder.class, "m_b", byte.class),
                 valueHolder, PrimitiveType.Byte, boxed, AccessorType.IPUT);
             tryAccessor(lookup.findGetter(ValueHolder.class, "m_b", byte.class),
                 valueHolder, PrimitiveType.Byte, boxed, AccessorType.IGET);
             assertTrue(valueHolder.m_b == b);
+
+            tryAccessor(lookup.findSetter(ValueHolder.class, "m_v_b", byte.class),
+                valueHolder, PrimitiveType.Byte, boxed, AccessorType.IPUT);
+            tryAccessor(lookup.findGetter(ValueHolder.class, "m_v_b", byte.class),
+                valueHolder, PrimitiveType.Byte, boxed, AccessorType.IGET);
+            assertTrue(valueHolder.m_v_b == b);
+
             tryAccessor(lookup.findStaticSetter(ValueHolder.class, "s_b", byte.class),
                 valueHolder, PrimitiveType.Byte, boxed, AccessorType.SPUT);
             tryAccessor(lookup.findStaticGetter(ValueHolder.class, "s_b", byte.class),
                 valueHolder, PrimitiveType.Byte, boxed, AccessorType.SGET);
             assertTrue(ValueHolder.s_b == b);
-        }
+
+            tryAccessor(lookup.findStaticSetter(ValueHolder.class, "s_v_b", byte.class),
+                valueHolder, PrimitiveType.Byte, boxed, AccessorType.SPUT);
+            tryAccessor(lookup.findStaticGetter(ValueHolder.class, "s_v_b", byte.class),
+                valueHolder, PrimitiveType.Byte, boxed, AccessorType.SGET);
+            assertTrue(ValueHolder.s_v_b == b);        }
     }
 
+    @Test
     public void testCharSettersAndGetters() throws Throwable {
         ValueHolder valueHolder = new ValueHolder();
         MethodHandles.Lookup lookup = MethodHandles.lookup();
@@ -580,19 +634,34 @@ public class MethodHandleAccessorsTest extends junit.framework.TestCase {
         char[] chars = {'a', 'b', 'c'};
         for (char c : chars) {
             Character boxed = Character.valueOf(c);
+
             tryAccessor(lookup.findSetter(ValueHolder.class, "m_c", char.class),
                 valueHolder, PrimitiveType.Char, boxed, AccessorType.IPUT);
             tryAccessor(lookup.findGetter(ValueHolder.class, "m_c", char.class),
                 valueHolder, PrimitiveType.Char, boxed, AccessorType.IGET);
             assertTrue(valueHolder.m_c == c);
+
+            tryAccessor(lookup.findSetter(ValueHolder.class, "m_v_c", char.class),
+                valueHolder, PrimitiveType.Char, boxed, AccessorType.IPUT);
+            tryAccessor(lookup.findGetter(ValueHolder.class, "m_v_c", char.class),
+                valueHolder, PrimitiveType.Char, boxed, AccessorType.IGET);
+            assertTrue(valueHolder.m_v_c == c);
+
             tryAccessor(lookup.findStaticSetter(ValueHolder.class, "s_c", char.class),
                 valueHolder, PrimitiveType.Char, boxed, AccessorType.SPUT);
             tryAccessor(lookup.findStaticGetter(ValueHolder.class, "s_c", char.class),
                 valueHolder, PrimitiveType.Char, boxed, AccessorType.SGET);
             assertTrue(ValueHolder.s_c == c);
+
+            tryAccessor(lookup.findStaticSetter(ValueHolder.class, "s_v_c", char.class),
+                valueHolder, PrimitiveType.Char, boxed, AccessorType.SPUT);
+            tryAccessor(lookup.findStaticGetter(ValueHolder.class, "s_v_c", char.class),
+                valueHolder, PrimitiveType.Char, boxed, AccessorType.SGET);
+            assertTrue(ValueHolder.s_v_c == c);
         }
     }
 
+    @Test
     public void testShortSettersAndGetters() throws Throwable {
         ValueHolder valueHolder = new ValueHolder();
         MethodHandles.Lookup lookup = MethodHandles.lookup();
@@ -600,19 +669,34 @@ public class MethodHandleAccessorsTest extends junit.framework.TestCase {
         short[] shorts = {(short) 0x1234, (short) 0x4321};
         for (short s : shorts) {
             Short boxed = Short.valueOf(s);
+
             tryAccessor(lookup.findSetter(ValueHolder.class, "m_s", short.class),
                 valueHolder, PrimitiveType.Short, boxed, AccessorType.IPUT);
             tryAccessor(lookup.findGetter(ValueHolder.class, "m_s", short.class),
                 valueHolder, PrimitiveType.Short, boxed, AccessorType.IGET);
             assertTrue(valueHolder.m_s == s);
+
+            tryAccessor(lookup.findSetter(ValueHolder.class, "m_v_s", short.class),
+                valueHolder, PrimitiveType.Short, boxed, AccessorType.IPUT);
+            tryAccessor(lookup.findGetter(ValueHolder.class, "m_v_s", short.class),
+                valueHolder, PrimitiveType.Short, boxed, AccessorType.IGET);
+            assertTrue(valueHolder.m_v_s == s);
+
             tryAccessor(lookup.findStaticSetter(ValueHolder.class, "s_s", short.class),
                 valueHolder, PrimitiveType.Short, boxed, AccessorType.SPUT);
             tryAccessor(lookup.findStaticGetter(ValueHolder.class, "s_s", short.class),
                 valueHolder, PrimitiveType.Short, boxed, AccessorType.SGET);
             assertTrue(ValueHolder.s_s == s);
+
+            tryAccessor(lookup.findStaticSetter(ValueHolder.class, "s_v_s", short.class),
+                valueHolder, PrimitiveType.Short, boxed, AccessorType.SPUT);
+            tryAccessor(lookup.findStaticGetter(ValueHolder.class, "s_v_s", short.class),
+                valueHolder, PrimitiveType.Short, boxed, AccessorType.SGET);
+            assertTrue(ValueHolder.s_v_s == s);
         }
     }
 
+    @Test
     public void testIntSettersAndGetters() throws Throwable {
         ValueHolder valueHolder = new ValueHolder();
         MethodHandles.Lookup lookup = MethodHandles.lookup();
@@ -620,19 +704,34 @@ public class MethodHandleAccessorsTest extends junit.framework.TestCase {
         int[] ints = {-100000000, 10000000};
         for (int i : ints) {
             Integer boxed = Integer.valueOf(i);
+
             tryAccessor(lookup.findSetter(ValueHolder.class, "m_i", int.class),
                 valueHolder, PrimitiveType.Int, boxed, AccessorType.IPUT);
             tryAccessor(lookup.findGetter(ValueHolder.class, "m_i", int.class),
                 valueHolder, PrimitiveType.Int, boxed, AccessorType.IGET);
             assertTrue(valueHolder.m_i == i);
+
+            tryAccessor(lookup.findSetter(ValueHolder.class, "m_v_i", int.class),
+                valueHolder, PrimitiveType.Int, boxed, AccessorType.IPUT);
+            tryAccessor(lookup.findGetter(ValueHolder.class, "m_v_i", int.class),
+                valueHolder, PrimitiveType.Int, boxed, AccessorType.IGET);
+            assertTrue(valueHolder.m_v_i == i);
+
             tryAccessor(lookup.findStaticSetter(ValueHolder.class, "s_i", int.class),
                 valueHolder, PrimitiveType.Int, boxed, AccessorType.SPUT);
             tryAccessor(lookup.findStaticGetter(ValueHolder.class, "s_i", int.class),
                 valueHolder, PrimitiveType.Int, boxed, AccessorType.SGET);
             assertTrue(ValueHolder.s_i == i);
+
+            tryAccessor(lookup.findStaticSetter(ValueHolder.class, "s_v_i", int.class),
+                valueHolder, PrimitiveType.Int, boxed, AccessorType.SPUT);
+            tryAccessor(lookup.findStaticGetter(ValueHolder.class, "s_v_i", int.class),
+                valueHolder, PrimitiveType.Int, boxed, AccessorType.SGET);
+            assertTrue(ValueHolder.s_v_i == i);
         }
     }
 
+    @Test
     public void testFloatSettersAndGetters() throws Throwable {
         ValueHolder valueHolder = new ValueHolder();
         MethodHandles.Lookup lookup = MethodHandles.lookup();
@@ -640,19 +739,34 @@ public class MethodHandleAccessorsTest extends junit.framework.TestCase {
         float[] floats = {0.99f, -1.23e-17f};
         for (float f : floats) {
             Float boxed = Float.valueOf(f);
+
             tryAccessor(lookup.findSetter(ValueHolder.class, "m_f", float.class),
                 valueHolder, PrimitiveType.Float, boxed, AccessorType.IPUT);
             tryAccessor(lookup.findGetter(ValueHolder.class, "m_f", float.class),
                 valueHolder, PrimitiveType.Float, boxed, AccessorType.IGET);
             assertTrue(valueHolder.m_f == f);
+
+            tryAccessor(lookup.findSetter(ValueHolder.class, "m_v_f", float.class),
+                    valueHolder, PrimitiveType.Float, boxed, AccessorType.IPUT);
+            tryAccessor(lookup.findGetter(ValueHolder.class, "m_v_f", float.class),
+                    valueHolder, PrimitiveType.Float, boxed, AccessorType.IGET);
+            assertTrue(valueHolder.m_v_f == f);
+
             tryAccessor(lookup.findStaticSetter(ValueHolder.class, "s_f", float.class),
                 valueHolder, PrimitiveType.Float, boxed, AccessorType.SPUT);
             tryAccessor(lookup.findStaticGetter(ValueHolder.class, "s_f", float.class),
                 valueHolder, PrimitiveType.Float, boxed, AccessorType.SGET);
             assertTrue(ValueHolder.s_f == f);
+
+            tryAccessor(lookup.findStaticSetter(ValueHolder.class, "s_v_f", float.class),
+                    valueHolder, PrimitiveType.Float, boxed, AccessorType.SPUT);
+            tryAccessor(lookup.findStaticGetter(ValueHolder.class, "s_v_f", float.class),
+                    valueHolder, PrimitiveType.Float, boxed, AccessorType.SGET);
+            assertTrue(ValueHolder.s_v_f == f);
         }
     }
 
+    @Test
     public void testDoubleSettersAndGetters() throws Throwable {
         ValueHolder valueHolder = new ValueHolder();
         MethodHandles.Lookup lookup = MethodHandles.lookup();
@@ -665,14 +779,28 @@ public class MethodHandleAccessorsTest extends junit.framework.TestCase {
             tryAccessor(lookup.findGetter(ValueHolder.class, "m_d", double.class),
                 valueHolder, PrimitiveType.Double, boxed, AccessorType.IGET);
             assertTrue(valueHolder.m_d == d);
+
+            tryAccessor(lookup.findSetter(ValueHolder.class, "m_v_d", double.class),
+                    valueHolder, PrimitiveType.Double, boxed, AccessorType.IPUT);
+            tryAccessor(lookup.findGetter(ValueHolder.class, "m_v_d", double.class),
+                    valueHolder, PrimitiveType.Double, boxed, AccessorType.IGET);
+            assertTrue(valueHolder.m_v_d == d);
+
             tryAccessor(lookup.findStaticSetter(ValueHolder.class, "s_d", double.class),
                 valueHolder, PrimitiveType.Double, boxed, AccessorType.SPUT);
             tryAccessor(lookup.findStaticGetter(ValueHolder.class, "s_d", double.class),
                 valueHolder, PrimitiveType.Double, boxed, AccessorType.SGET);
             assertTrue(ValueHolder.s_d == d);
+
+            tryAccessor(lookup.findStaticSetter(ValueHolder.class, "s_v_d", double.class),
+                    valueHolder, PrimitiveType.Double, boxed, AccessorType.SPUT);
+            tryAccessor(lookup.findStaticGetter(ValueHolder.class, "s_v_d", double.class),
+                    valueHolder, PrimitiveType.Double, boxed, AccessorType.SGET);
+            assertTrue(ValueHolder.s_v_d == d);
         }
     }
 
+    @Test
     public void testLongSettersAndGetters() throws Throwable {
         ValueHolder valueHolder = new ValueHolder();
         MethodHandles.Lookup lookup = MethodHandles.lookup();
@@ -680,19 +808,34 @@ public class MethodHandleAccessorsTest extends junit.framework.TestCase {
         long[] longs = {0x0123456789abcdefl, 0xfedcba9876543210l};
         for (long j : longs) {
             Long boxed = Long.valueOf(j);
+
             tryAccessor(lookup.findSetter(ValueHolder.class, "m_j", long.class),
                 valueHolder, PrimitiveType.Long, boxed, AccessorType.IPUT);
             tryAccessor(lookup.findGetter(ValueHolder.class, "m_j", long.class),
                 valueHolder, PrimitiveType.Long, boxed, AccessorType.IGET);
             assertTrue(valueHolder.m_j == j);
+
+            tryAccessor(lookup.findSetter(ValueHolder.class, "m_v_j", long.class),
+                    valueHolder, PrimitiveType.Long, boxed, AccessorType.IPUT);
+            tryAccessor(lookup.findGetter(ValueHolder.class, "m_v_j", long.class),
+                    valueHolder, PrimitiveType.Long, boxed, AccessorType.IGET);
+            assertTrue(valueHolder.m_v_j == j);
+
             tryAccessor(lookup.findStaticSetter(ValueHolder.class, "s_j", long.class),
                 valueHolder, PrimitiveType.Long, boxed, AccessorType.SPUT);
             tryAccessor(lookup.findStaticGetter(ValueHolder.class, "s_j", long.class),
                 valueHolder, PrimitiveType.Long, boxed, AccessorType.SGET);
             assertTrue(ValueHolder.s_j == j);
+
+            tryAccessor(lookup.findStaticSetter(ValueHolder.class, "s_v_j", long.class),
+                    valueHolder, PrimitiveType.Long, boxed, AccessorType.SPUT);
+            tryAccessor(lookup.findStaticGetter(ValueHolder.class, "s_v_j", long.class),
+                    valueHolder, PrimitiveType.Long, boxed, AccessorType.SGET);
+            assertTrue(ValueHolder.s_v_j == j);
         }
     }
 
+    @Test
     public void testStringSettersAndGetters() throws Throwable {
         ValueHolder valueHolder = new ValueHolder();
         MethodHandles.Lookup lookup = MethodHandles.lookup();
@@ -704,14 +847,28 @@ public class MethodHandleAccessorsTest extends junit.framework.TestCase {
             tryAccessor(lookup.findGetter(ValueHolder.class, "m_l", String.class),
                     valueHolder, PrimitiveType.String, s, AccessorType.IGET);
             assertTrue(s.equals(valueHolder.m_l));
+
+            tryAccessor(lookup.findSetter(ValueHolder.class, "m_v_l", String.class),
+                    valueHolder, PrimitiveType.String, s, AccessorType.IPUT);
+            tryAccessor(lookup.findGetter(ValueHolder.class, "m_v_l", String.class),
+                    valueHolder, PrimitiveType.String, s, AccessorType.IGET);
+            assertTrue(s.equals(valueHolder.m_v_l));
+
             tryAccessor(lookup.findStaticSetter(ValueHolder.class, "s_l", String.class),
                     valueHolder, PrimitiveType.String, s, AccessorType.SPUT);
             tryAccessor(lookup.findStaticGetter(ValueHolder.class, "s_l", String.class),
                     valueHolder, PrimitiveType.String, s, AccessorType.SGET);
             assertTrue(s.equals(ValueHolder.s_l));
+
+            tryAccessor(lookup.findStaticSetter(ValueHolder.class, "s_v_l", String.class),
+                    valueHolder, PrimitiveType.String, s, AccessorType.SPUT);
+            tryAccessor(lookup.findStaticGetter(ValueHolder.class, "s_v_l", String.class),
+                    valueHolder, PrimitiveType.String, s, AccessorType.SGET);
+            assertTrue(s.equals(ValueHolder.s_v_l));
         }
     }
 
+    @Test
     public void testLookup() throws Throwable {
         // NB having a static field test here is essential for
         // this test. MethodHandles need to ensure the class
@@ -755,6 +912,7 @@ public class MethodHandleAccessorsTest extends junit.framework.TestCase {
         } catch (IllegalAccessException e) {}
     }
 
+    @Test
     public void testStaticGetter() throws Throwable {
         MethodHandles.Lookup lookup = MethodHandles.lookup();
         MethodHandle h0 = lookup.findStaticGetter(ValueHolder.class, "s_fi", int.class);
@@ -777,6 +935,7 @@ public class MethodHandleAccessorsTest extends junit.framework.TestCase {
         } catch (WrongMethodTypeException e) {}
     }
 
+    @Test
     public void testMemberGetter() throws Throwable {
         ValueHolder valueHolder = new ValueHolder();
         MethodHandles.Lookup lookup = MethodHandles.lookup();
@@ -810,6 +969,7 @@ public class MethodHandleAccessorsTest extends junit.framework.TestCase {
         return Float.valueOf(-7.77f);
     }
 
+    @Test
     public void testMemberSetter() throws Throwable {
         ValueHolder valueHolder = new ValueHolder();
         MethodHandles.Lookup lookup = MethodHandles.lookup();
@@ -866,6 +1026,7 @@ public class MethodHandleAccessorsTest extends junit.framework.TestCase {
         } catch (WrongMethodTypeException e) {}
     }
 
+    @Test
     public void testStaticSetter() throws Throwable {
         MethodHandles.Lookup lookup = MethodHandles.lookup();
         MethodHandle h0 = lookup.findStaticSetter(ValueHolder.class, "s_f", float.class);
@@ -919,4 +1080,40 @@ public class MethodHandleAccessorsTest extends junit.framework.TestCase {
             fail();
         } catch (WrongMethodTypeException e) {}
     }
+
+    @Test
+    public void throws_wmte_when_too_many_arguments_are_supplied() throws Throwable {
+        MethodHandles.Lookup lookup = MethodHandles.lookup();
+        MethodHandle setter = lookup.findStaticSetter(ValueHolder.class, "s_f", float.class);
+
+        try {
+            setter.invokeExact(0f, 1);
+            fail("Should throw WMTE");
+        } catch (WrongMethodTypeException ignored) {}
+
+        try {
+            setter.invokeExact(0f, 1, 2);
+            fail("Should throw WMTE");
+        } catch (WrongMethodTypeException ignored) {}
+
+        try {
+            setter.invokeExact(0f, 1, 2, 3);
+            fail("Should throw WMTE");
+        } catch (WrongMethodTypeException ignored) {}
+
+        try {
+            setter.invokeExact(0f, 1, 2, 3, 4);
+            fail("Should throw WMTE");
+        } catch (WrongMethodTypeException ignored) {}
+
+        try {
+            setter.invokeExact(0f, 1, 2, 3, 4, 5);
+            fail("Should throw WMTE");
+        } catch (WrongMethodTypeException ignored) {}
+
+        try {
+            setter.invokeExact(0f, 1, 2, 3, 4, 5, "str");
+            fail("Should throw WMTE");
+        } catch (WrongMethodTypeException ignored) {}
+    }
 }
diff --git a/luni/src/test/java/libcore/java/lang/invoke/MethodHandleCombinersTest.java b/luni/src/test/java/libcore/java/lang/invoke/MethodHandleCombinersTest.java
index f5652515a92..16b2e73042e 100644
--- a/luni/src/test/java/libcore/java/lang/invoke/MethodHandleCombinersTest.java
+++ b/luni/src/test/java/libcore/java/lang/invoke/MethodHandleCombinersTest.java
@@ -26,6 +26,7 @@ import java.util.Arrays;
 
 import junit.framework.TestCase;
 
+@SuppressWarnings("EmptyCatch") // Old thrown exception testing pattern.
 public class MethodHandleCombinersTest extends TestCase {
 
     static final int TEST_THREAD_ITERATIONS = 1000;
@@ -464,6 +465,42 @@ public class MethodHandleCombinersTest extends TestCase {
             assertEquals("42", array[0]);
             assertEquals("48", array[1]);
             assertEquals("54", array[2]);
+
+            setter.invokeExact(array, 0, "43");
+            setter.invokeExact(array, 1, "49");
+            setter.invokeExact(array, 2, "55");
+            assertEquals("43", array[0]);
+            assertEquals("49", array[1]);
+            assertEquals("55", array[2]);
+
+            try {
+                setter.invoke(array, 0, new Object());
+                fail("ClassCastException is expected");
+            } catch (ClassCastException ignored) {}
+
+            try {
+                setter.invoke(array, 0, 10);
+                fail("WMTE is expected");
+            } catch (WrongMethodTypeException ignored) {}
+
+            try {
+                setter.invokeExact(array, 1, new Object());
+                fail("WMTE is expected");
+            } catch (WrongMethodTypeException ignored) {}
+
+            CharSequence[] charSequences = new CharSequence[3];
+            MethodHandle charSeqSetter = MethodHandles.arrayElementSetter(CharSequence[].class);
+
+            charSeqSetter.invoke(charSequences, 0, "");
+            assertEquals("", charSequences[0]);
+
+            charSeqSetter.invokeExact(charSequences, 1, (CharSequence) "non-empty");
+            assertEquals("non-empty", charSequences[1]);
+
+            try {
+                charSeqSetter.invokeExact(charSequences, 2, "str");
+                fail("Should throw WMTE");
+            } catch (WrongMethodTypeException ignored) {}
         }
     }
 
@@ -1564,7 +1601,7 @@ public class MethodHandleCombinersTest extends TestCase {
         try {
             adapter = MethodHandles.collectArguments(target, 3, filter);
             fail();
-        } catch (IndexOutOfBoundsException expected) {
+        } catch (IllegalArgumentException expected) {
         }
 
         // Mismatch in filter return type.
diff --git a/luni/src/test/java/libcore/java/lang/invoke/MethodHandlesTest.java b/luni/src/test/java/libcore/java/lang/invoke/MethodHandlesTest.java
index c5c359d7f2b..9984f1e522c 100644
--- a/luni/src/test/java/libcore/java/lang/invoke/MethodHandlesTest.java
+++ b/luni/src/test/java/libcore/java/lang/invoke/MethodHandlesTest.java
@@ -38,6 +38,9 @@ import java.util.Vector;
 import static java.lang.invoke.MethodHandles.Lookup.*;
 import static java.lang.invoke.MethodType.methodType;
 
+import libcore.test.annotation.NonCts;
+import libcore.test.reasons.NonCtsReasons;
+
 public class MethodHandlesTest extends TestCase {
     private static final int ALL_LOOKUP_MODES = (PUBLIC | PRIVATE | PACKAGE | PROTECTED);
 
@@ -176,6 +179,7 @@ public class MethodHandlesTest extends TestCase {
         }
     }
 
+    @NonCts(bug = 401130471, reason = NonCtsReasons.NON_BREAKING_BEHAVIOR_FIX)
     public void test_findConstructor() throws Exception {
         MethodHandles.Lookup defaultLookup = MethodHandles.lookup();
 
diff --git a/luni/src/test/java/libcore/java/lang/invoke/StringConcatExceptionTest.java b/luni/src/test/java/libcore/java/lang/invoke/StringConcatExceptionTest.java
new file mode 100644
index 00000000000..2613529714c
--- /dev/null
+++ b/luni/src/test/java/libcore/java/lang/invoke/StringConcatExceptionTest.java
@@ -0,0 +1,48 @@
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
+
+package libcore.java.lang.invoke;
+
+import static org.junit.Assert.assertEquals;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
+import java.lang.invoke.StringConcatException;
+
+@RunWith(JUnit4.class)
+public class StringConcatExceptionTest {
+
+    @Test
+    public void constructor_LString() {
+        String msg = "message";
+        StringConcatException exception = new StringConcatException(msg);
+
+        assertEquals(msg, exception.getMessage());
+    }
+
+    @Test
+    public void constructor_LStringLThrowable() {
+        String msg = "message";
+        Throwable cause = new Exception();
+        StringConcatException exception = new StringConcatException(msg, cause);
+
+        assertEquals(msg, exception.getMessage());
+        assertEquals(cause, exception.getCause());
+    }
+
+}
diff --git a/luni/src/test/java/libcore/java/lang/invoke/VarHandleTest.java b/luni/src/test/java/libcore/java/lang/invoke/VarHandleTest.java
index 34576db3190..6bd5b01a60d 100644
--- a/luni/src/test/java/libcore/java/lang/invoke/VarHandleTest.java
+++ b/luni/src/test/java/libcore/java/lang/invoke/VarHandleTest.java
@@ -19,18 +19,136 @@ package libcore.java.lang.invoke;
 import static org.junit.Assert.assertTrue;
 import static org.junit.Assert.assertEquals;
 
+import static java.util.Objects.requireNonNull;
+import static java.util.stream.Collectors.toMap;
+
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.junit.runners.JUnit4;
 
 import java.lang.invoke.MethodHandles;
 import java.lang.invoke.VarHandle;
+import java.lang.reflect.Field;
+import java.util.Arrays;
+import java.util.Set;
+import java.util.function.Function;
 
 @RunWith(JUnit4.class)
 public class VarHandleTest {
 
     private int field = 0;
 
+    private static int getField(String name) {
+        try {
+            Field f = VarHandle.class.getDeclaredField(name);
+            if (f.getType() != int.class) {
+                throw new AssertionError(name +
+                    " expected to be int, but was: " + f.getType());
+            }
+            f.setAccessible(true);
+            return (int) f.get(null);
+        } catch (NoSuchFieldException | IllegalAccessException e) {
+            throw new RuntimeException(e);
+        }
+    }
+
+    // Reflectively fetched values of otherwise inaccessible VarHandle.AccessType enum.
+    static class AccessType {
+        static final Object GET;
+        static final Object SET;
+        static final Object COMPARE_AND_SET;
+        static final Object COMPARE_AND_EXCHANGE;
+        static final Object GET_AND_UPDATE;
+        static final Object GET_AND_UPDATE_BITWISE;
+        static final Object GET_AND_UPDATE_NUMERIC;
+
+        static {
+            try {
+                Class accessTypeClass = Class.forName("java.lang.invoke.VarHandle$AccessType");
+                var accessTypes = Arrays.stream(accessTypeClass.getEnumConstants())
+                        .collect(toMap(Object::toString, Function.identity()));
+                GET = requireNonNull(accessTypes.get("GET"));
+                SET = requireNonNull(accessTypes.get("SET"));
+                COMPARE_AND_SET = requireNonNull(accessTypes.get("COMPARE_AND_SET"));
+                COMPARE_AND_EXCHANGE = requireNonNull(accessTypes.get("COMPARE_AND_EXCHANGE"));
+                GET_AND_UPDATE = requireNonNull(accessTypes.get("GET_AND_UPDATE"));
+                GET_AND_UPDATE_BITWISE = requireNonNull(accessTypes.get("GET_AND_UPDATE_BITWISE"));
+                GET_AND_UPDATE_NUMERIC = requireNonNull(accessTypes.get("GET_AND_UPDATE_NUMERIC"));
+            } catch (ClassNotFoundException e) {
+                throw new AssertionError(e);
+            }
+        }
+    }
+
+    @Test
+    public void constantsAreConsistent() {
+        {
+            int READ_ACCESS_MODES_BIT_MASK = getField("READ_ACCESS_MODES_BIT_MASK");
+            int expected = accessTypesToBitMask(Set.of(AccessType.GET));
+            String msg = "READ_ACCESS_MODES_BIT_MASK";
+            assertEquals(msg, expected, READ_ACCESS_MODES_BIT_MASK);
+        }
+        {
+            int WRITE_ACCESS_MODES_BIT_MASK = getField("WRITE_ACCESS_MODES_BIT_MASK");
+            int expected = accessTypesToBitMask(Set.of(AccessType.SET));
+            String msg = "WRITE_ACCESS_MODES_BIT_MASK";
+            assertEquals(msg, expected, WRITE_ACCESS_MODES_BIT_MASK);
+        }
+        {
+            int ATOMIC_UPDATE_ACCESS_MODES_BIT_MASK =
+                getField("ATOMIC_UPDATE_ACCESS_MODES_BIT_MASK");
+            int expected = accessTypesToBitMask(
+                    Set.of(
+                            AccessType.COMPARE_AND_EXCHANGE,
+                            AccessType.COMPARE_AND_SET,
+                            AccessType.GET_AND_UPDATE));
+            String msg = "ATOMIC_UPDATE_ACCESS_MODES_BIT_MASK";
+            assertEquals(msg, expected, ATOMIC_UPDATE_ACCESS_MODES_BIT_MASK);
+        }
+        {
+            int NUMERIC_ATOMIC_UPDATE_ACCESS_MODES_BIT_MASK =
+                getField("NUMERIC_ATOMIC_UPDATE_ACCESS_MODES_BIT_MASK");
+            int expected = accessTypesToBitMask(Set.of(AccessType.GET_AND_UPDATE_NUMERIC));
+            String msg = "NUMERIC_ATOMIC_UPDATE_ACCESS_MODES_BIT_MASK";
+            assertEquals(msg, expected, NUMERIC_ATOMIC_UPDATE_ACCESS_MODES_BIT_MASK);
+        }
+        {
+            int BITWISE_ATOMIC_UPDATE_ACCESS_MODES_BIT_MASK =
+                getField("BITWISE_ATOMIC_UPDATE_ACCESS_MODES_BIT_MASK");
+            int expected = accessTypesToBitMask(
+                    Set.of(AccessType.GET_AND_UPDATE_BITWISE));
+            String msg = "BITWISE_ATOMIC_UPDATE_ACCESS_MODES_BIT_MASK";
+            assertEquals(msg, expected, BITWISE_ATOMIC_UPDATE_ACCESS_MODES_BIT_MASK);
+        }
+    }
+
+    private static Object getAtField(VarHandle.AccessMode accessMode) {
+        try {
+            Field atField = VarHandle.AccessMode.class.getDeclaredField("at");
+            atField.setAccessible(true);
+            return atField.get(accessMode);
+        } catch (Throwable t) {
+            throw new RuntimeException(t);
+        }
+    }
+
+    static int accessTypesToBitMask(final Set<?> accessTypes) {
+        int m = 0;
+        for (VarHandle.AccessMode accessMode : VarHandle.AccessMode.values()) {
+            if (accessTypes.contains(getAtField(accessMode))) {
+                m |= 1 << accessMode.ordinal();
+            }
+        }
+        return m;
+    }
+
+    @Test
+    public void accessMode_shouldNotOverflow() {
+        // Check we're not about to overflow the storage of the
+        // bitmasks here and in the accessModesBitMask field.
+        assertTrue(VarHandle.AccessMode.values().length <= Integer.SIZE);
+    }
+
     @Test
     public void fences() {
         // In theory, these should log coverage for these fences, but they are implemented
diff --git a/luni/src/test/java/libcore/java/net/InetAddressTest.java b/luni/src/test/java/libcore/java/net/InetAddressTest.java
index eeaaece92d5..70498e7f812 100644
--- a/luni/src/test/java/libcore/java/net/InetAddressTest.java
+++ b/luni/src/test/java/libcore/java/net/InetAddressTest.java
@@ -285,8 +285,10 @@ public class InetAddressTest {
         for (InetAddress ia : inetAddresses) {
             // ICMP is not reliable, allow 5 attempts to each IP address before failing.
             // If any address is reachable then that's sufficient.
-            if (ia.isReachableByICMP(5 * 1000 /* ICMP timeout */)) {
-                return;
+            for (int i = 0; i < 5; i++) {
+                if (ia.isReachableByICMP(25 * 1000 /* ICMP timeout */)) {
+                    return;
+                }
             }
         }
         fail("Addresses not reachable by ICMP: " + Arrays.toString(inetAddresses));
diff --git a/luni/src/test/java/libcore/java/text/DateFormatSymbolsTest.java b/luni/src/test/java/libcore/java/text/DateFormatSymbolsTest.java
index baa3344efe5..eaa5df0484e 100644
--- a/luni/src/test/java/libcore/java/text/DateFormatSymbolsTest.java
+++ b/luni/src/test/java/libcore/java/text/DateFormatSymbolsTest.java
@@ -16,6 +16,9 @@
 
 package libcore.java.text;
 
+import libcore.test.annotation.NonMts;
+import libcore.test.reasons.NonMtsReasons;
+
 import java.io.ByteArrayInputStream;
 import java.io.ByteArrayOutputStream;
 import java.io.ObjectInputStream;
@@ -156,6 +159,7 @@ public class DateFormatSymbolsTest extends junit.framework.TestCase {
     }
 
     // http://b/7955614
+    @NonMts(reason = NonMtsReasons.ICU_VERSION_DEPENDENCY)
     public void test_getZoneStrings_Apia() {
         String[][] array = DateFormatSymbols.getInstance(Locale.US).getZoneStrings();
 
@@ -165,9 +169,9 @@ public class DateFormatSymbolsTest extends junit.framework.TestCase {
             // "GMT" strings for the short names.
             if (row[0].equals("Pacific/Apia")) {
                 TimeZone apiaTz = TimeZone.getTimeZone("Pacific/Apia");
-                assertEquals("Apia Standard Time", row[1]);
+                assertEquals("Samoa Standard Time", row[1]);
                 assertEquals(formattedStandardTimeOffset(apiaTz), row[2]);
-                assertEquals("Apia Daylight Time", row[3]);
+                assertEquals("Samoa Daylight Time", row[3]);
                 assertEquals(formattedDstOffset(apiaTz), row[4]);
             }
         }
diff --git a/luni/src/test/java/libcore/java/text/DecimalFormatSymbolsTest.java b/luni/src/test/java/libcore/java/text/DecimalFormatSymbolsTest.java
index 74ef9bfaf4f..96d259abf58 100644
--- a/luni/src/test/java/libcore/java/text/DecimalFormatSymbolsTest.java
+++ b/luni/src/test/java/libcore/java/text/DecimalFormatSymbolsTest.java
@@ -123,7 +123,7 @@ public class DecimalFormatSymbolsTest extends junit.framework.TestCase {
         //
         // It is expected that the symbols may change with future CLDR updates.
 
-        dfs = new DecimalFormatSymbols(Locale.forLanguageTag("ar"));
+        dfs = new DecimalFormatSymbols(Locale.forLanguageTag("ar-EG"));
         assertEquals('٪', dfs.getPercent());
         assertEquals('-', dfs.getMinusSign());
 
diff --git a/luni/src/test/java/libcore/java/text/DecimalFormatTest.java b/luni/src/test/java/libcore/java/text/DecimalFormatTest.java
index 847f7ae0cae..fe9ec5a513a 100644
--- a/luni/src/test/java/libcore/java/text/DecimalFormatTest.java
+++ b/luni/src/test/java/libcore/java/text/DecimalFormatTest.java
@@ -530,7 +530,7 @@ public class DecimalFormatTest extends junit.framework.TestCase {
         assertEquals("100;", new DecimalFormat(pattern, dfs).format(number));
 
         // Confirm ICU and java.text agree. Test PerMill is localized.
-        locale = new Locale("ar");
+        locale = new Locale("ar", "EG");
         {
             android.icu.text.DecimalFormat df = new android.icu.text.DecimalFormat(pattern,
                     new android.icu.text.DecimalFormatSymbols(locale));
@@ -587,7 +587,7 @@ public class DecimalFormatTest extends junit.framework.TestCase {
         assertEquals("10;", new DecimalFormat(pattern, dfs).format(number));
 
         // Confirm ICU and java.text disagree because java.text strips out bidi marker
-        locale = new Locale("ar");
+        locale = new Locale("ar", "EG");
         {
             android.icu.text.DecimalFormat df = new android.icu.text.DecimalFormat(pattern,
                     new android.icu.text.DecimalFormatSymbols(locale));
@@ -635,7 +635,7 @@ public class DecimalFormatTest extends junit.framework.TestCase {
         }
 
         // Confirm ICU and java.text disagree because java.text strips out bidi marker
-        locale = new Locale("ar");
+        locale = new Locale("ar", "EG");
         {
             android.icu.text.DecimalFormat df = new android.icu.text.DecimalFormat(pattern,
                     new android.icu.text.DecimalFormatSymbols(locale));
@@ -660,7 +660,7 @@ public class DecimalFormatTest extends junit.framework.TestCase {
                 .format(123));
 
         // Confirm ICU and java.text disagree because java.text doesn't localize plus sign.
-        Locale locale = new Locale("ar");
+        Locale locale = new Locale("ar", "EG");
         {
             android.icu.text.DecimalFormat df = new android.icu.text.DecimalFormat(pattern,
                     new android.icu.text.DecimalFormatSymbols(locale));
diff --git a/luni/src/test/java/libcore/java/text/NumberFormatTest.java b/luni/src/test/java/libcore/java/text/NumberFormatTest.java
index 599630bf442..054a15fed33 100644
--- a/luni/src/test/java/libcore/java/text/NumberFormatTest.java
+++ b/luni/src/test/java/libcore/java/text/NumberFormatTest.java
@@ -78,7 +78,7 @@ public class NumberFormatTest extends junit.framework.TestCase {
     }
 
     public void test_numberLocalization() throws Exception {
-        Locale arabic = new Locale("ar");
+        Locale arabic = new Locale("ar", "EG");
         NumberFormat nf = NumberFormat.getNumberInstance(arabic);
         assertEquals('\u0660', new DecimalFormatSymbols(arabic).getZeroDigit());
         assertEquals("١٬٢٣٤٬٥٦٧٬٨٩٠", nf.format(1234567890));
diff --git a/luni/src/test/java/libcore/java/time/format/DateTimeFormatterTest.java b/luni/src/test/java/libcore/java/time/format/DateTimeFormatterTest.java
index 07ea4f02c58..7b4103ec2a0 100644
--- a/luni/src/test/java/libcore/java/time/format/DateTimeFormatterTest.java
+++ b/luni/src/test/java/libcore/java/time/format/DateTimeFormatterTest.java
@@ -52,7 +52,7 @@ public class DateTimeFormatterTest {
 
     @Test
     public void test_getDecimalStyle() {
-        Locale arLocale = Locale.forLanguageTag("ar");
+        Locale arLocale = Locale.forLanguageTag("ar-EG");
         DateTimeFormatter[] formatters = new DateTimeFormatter[] {
                 DateTimeFormatter.ISO_DATE,
                 DateTimeFormatter.RFC_1123_DATE_TIME,
diff --git a/luni/src/test/java/libcore/java/util/FormatterTest.java b/luni/src/test/java/libcore/java/util/FormatterTest.java
index abca282a564..65d2ef664f5 100644
--- a/luni/src/test/java/libcore/java/util/FormatterTest.java
+++ b/luni/src/test/java/libcore/java/util/FormatterTest.java
@@ -83,7 +83,7 @@ public class FormatterTest {
         disabledUntilSdk = VersionCodes.VANILLA_ICE_CREAM)
     @Test
     public void test_numberLocalization() throws Exception {
-        Locale arabic = new Locale("ar");
+        Locale arabic = new Locale("ar", "EG");
 
         // Check the fast path for %d:
         assertEquals("12 \u0661\u0662\u0663\u0664\u0665\u0666\u0667\u0668\u0669\u0660 34",
@@ -121,8 +121,8 @@ public class FormatterTest {
         assertEquals("1E+02", String.format(Locale.ENGLISH, "%.0E", 100.0));
         assertEquals("1e+02", String.format(Locale.ENGLISH, "%.0e", 100.0));
 
-        assertEquals("\u0661\u0623\u0633+\u0660\u0662", String.format(new Locale("ar"), "%.0E", 100.0));
-        assertEquals("\u0661\u0623\u0633+\u0660\u0662", String.format(new Locale("ar"), "%.0e", 100.0));
+        assertEquals("\u0661\u0623\u0633+\u0660\u0662", String.format(new Locale("ar", "EG"), "%.0E", 100.0));
+        assertEquals("\u0661\u0623\u0633+\u0660\u0662", String.format(new Locale("ar", "EG"), "%.0e", 100.0));
 
         assertEquals("1\u00d710^+02", String.format(new Locale("et"), "%.0E", 100.0));
         assertEquals("1\u00d710^+02", String.format(new Locale("et"), "%.0e", 100.0));
diff --git a/luni/src/test/java/libcore/java/util/TimeZoneTest.java b/luni/src/test/java/libcore/java/util/TimeZoneTest.java
index a1a71a75df0..f4bcc80812d 100644
--- a/luni/src/test/java/libcore/java/util/TimeZoneTest.java
+++ b/luni/src/test/java/libcore/java/util/TimeZoneTest.java
@@ -28,6 +28,11 @@ import java.util.function.Supplier;
 import libcore.junit.junit3.TestCaseWithRules;
 import libcore.junit.util.SwitchTargetSdkVersionRule;
 import libcore.junit.util.SwitchTargetSdkVersionRule.TargetSdkVersion;
+import libcore.test.annotation.NonCts;
+import libcore.test.annotation.NonMts;
+import libcore.test.reasons.NonCtsReasons;
+import libcore.test.reasons.NonMtsReasons;
+
 import org.junit.Rule;
 import org.junit.rules.TestRule;
 
@@ -68,12 +73,14 @@ public class TimeZoneTest extends TestCaseWithRules {
     }
 
     // http://code.google.com/p/android/issues/detail?id=14395
+    @NonCts(bug = 383977133, reason = NonCtsReasons.NON_BREAKING_BEHAVIOR_FIX)
+    @NonMts(bug = 383977133, reason = NonMtsReasons.TZDATA_VERSION_DEPENDENCY)
     public void testPreHistoricInDaylightTime() {
         // A replacement for testPreHistoricInDaylightTime_old() using a zone that lacks an
         // explicit transition at Integer.MIN_VALUE with zic 2019a and 2019a data.
         TimeZone tz = TimeZone.getTimeZone("CET");
 
-        long firstTransitionTimeMillis = -1693706400000L; // Apr 30, 1916 22:00:00 GMT
+        long firstTransitionTimeMillis = -1693702800000L; // Apr 30, 1916 23:00:00 GMT
         assertEquals(7200000L, tz.getOffset(firstTransitionTimeMillis));
         assertTrue(tz.inDaylightTime(new Date(firstTransitionTimeMillis)));
 
@@ -206,6 +213,7 @@ public class TimeZoneTest extends TestCaseWithRules {
     }
 
     // http://b.corp.google.com/issue?id=6556561
+    @NonCts(bug = 401130471, reason = NonCtsReasons.NON_BREAKING_BEHAVIOR_FIX)
     public void testCustomZoneIds() throws Exception {
         // These are all okay (and equivalent).
         assertEquals("GMT+05:00", TimeZone.getTimeZone("GMT+05:00").getID());
@@ -367,10 +375,11 @@ public class TimeZoneTest extends TestCaseWithRules {
     }
 
     // http://b/7955614
+    @NonMts(reason = NonMtsReasons.ICU_VERSION_DEPENDENCY)
     public void testApia() {
         TimeZone tz = TimeZone.getTimeZone("Pacific/Apia");
-        assertEquals("Apia Daylight Time", tz.getDisplayName(true, TimeZone.LONG, Locale.US));
-        assertEquals("Apia Standard Time", tz.getDisplayName(false, TimeZone.LONG, Locale.US));
+        assertEquals("Samoa Daylight Time", tz.getDisplayName(true, TimeZone.LONG, Locale.US));
+        assertEquals("Samoa Standard Time", tz.getDisplayName(false, TimeZone.LONG, Locale.US));
 
         long samoaStandardTime = 1630315635000L; // 30 Aug 2021
         long samoaDst = 1614504435000L; // 28 Feb 2021
diff --git a/luni/src/test/java/libcore/jdk/internal/vm/ContinuationTest.java b/luni/src/test/java/libcore/jdk/internal/vm/ContinuationTest.java
new file mode 100644
index 00000000000..b6f9feb3d44
--- /dev/null
+++ b/luni/src/test/java/libcore/jdk/internal/vm/ContinuationTest.java
@@ -0,0 +1,25 @@
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
+package libcore.jdk.internal.vm;
+
+import jdk.internal.vm.Continuation;
+
+public class ContinuationTest {
+    @org.junit.Test
+    public void test_clinit() throws ClassNotFoundException {
+        Class.forName(Continuation.class.getName());
+    }
+}
diff --git a/luni/src/test/java/libcore/libcore/io/BlockGuardOsTest.java b/luni/src/test/java/libcore/libcore/io/BlockGuardOsTest.java
index 8338d46f575..e8d6e4222ee 100644
--- a/luni/src/test/java/libcore/libcore/io/BlockGuardOsTest.java
+++ b/luni/src/test/java/libcore/libcore/io/BlockGuardOsTest.java
@@ -58,6 +58,10 @@ import libcore.io.BlockGuardOs;
 import libcore.io.IoUtils;
 import libcore.io.Libcore;
 import libcore.io.Os;
+import libcore.test.annotation.NonCts;
+import libcore.test.annotation.NonMts;
+import libcore.test.reasons.NonCtsReasons;
+import libcore.test.reasons.NonMtsReasons;
 
 import dalvik.system.BlockGuard;
 
@@ -225,6 +229,7 @@ public class BlockGuardOsTest {
      * calls to BlockGuard (if the calls can block).
      */
     @Test
+    @NonCts(bug = 401130471, reason = NonCtsReasons.NON_BREAKING_BEHAVIOR_FIX)
     public void test_checkNewMethodsInPosix() {
         List<String> methodsNotRequireBlockGuardChecks = Arrays.asList(
                 "android_fdsan_exchange_owner_tag(java.io.FileDescriptor,long,long)",
@@ -275,6 +280,7 @@ public class BlockGuardOsTest {
                 "kill(int,int)",
                 "listen(java.io.FileDescriptor,int)",
                 "listxattr(java.lang.String)",
+                "madvise(long,long,int)",
                 "memfd_create(java.lang.String,int)",
                 "mincore(long,long,byte[])",
                 "mlock(long,long)",
diff --git a/mmodules/intracoreapi/Android.bp b/mmodules/intracoreapi/Android.bp
index be0f388354e..4f7ca2a54f4 100644
--- a/mmodules/intracoreapi/Android.bp
+++ b/mmodules/intracoreapi/Android.bp
@@ -64,12 +64,26 @@ java_sdk_library {
     srcs: [
         ":art_module_api_files",
     ],
+    stub_only_libs: [
+        "stub-annotations",
+    ],
     api_dir: "api/intra",
     api_only: true,
+    annotations_enabled: true,
     droiddoc_options: [
         "--hide-annotation libcore.api.Hide",
         "--show-single-annotation libcore.api.IntraCoreApi",
+        // Exclude FlaggedApi as Metalava cannot resolve the flags reference
+        // because this is not given the flags library on the classpath as
+        // doing so creates a cycle.
+        "--exclude-annotation android.annotation.FlaggedApi",
     ],
+
+    public: {
+        // Select api-surface defined in build/soong/java/metalava/main-config.xml
+        api_surface: "intra-core",
+    },
+
     merge_inclusion_annotations_dirs: ["ojluni-annotated-mmodule-stubs"],
 
     sdk_version: "none",
diff --git a/mmodules/intracoreapi/api/intra/current.txt b/mmodules/intracoreapi/api/intra/current.txt
index 80ecce3ecfa..68438bb5225 100644
--- a/mmodules/intracoreapi/api/intra/current.txt
+++ b/mmodules/intracoreapi/api/intra/current.txt
@@ -30,6 +30,7 @@ package android.system {
 package dalvik.annotation.compat {
 
   @libcore.api.IntraCoreApi public class VersionCodes {
+    field @libcore.api.IntraCoreApi public static final int BAKLAVA = 36; // 0x24
     field @libcore.api.IntraCoreApi public static final int CUR_DEVELOPMENT = 10000; // 0x2710
     field @libcore.api.IntraCoreApi public static final int O = 26; // 0x1a
     field @libcore.api.IntraCoreApi public static final int P = 28; // 0x1c
diff --git a/non_openjdk_java_files.bp b/non_openjdk_java_files.bp
index 3f6bb4138d1..a08f1a3c261 100644
--- a/non_openjdk_java_files.bp
+++ b/non_openjdk_java_files.bp
@@ -137,8 +137,7 @@ filegroup {
     name: "non_openjdk_javadoc_luni_files",
     srcs: [
         "luni/src/main/java/android/compat/Compatibility.java",
-        "luni/src/main/java/android/crypto/hpke/HpkeSpi.java",
-        "luni/src/main/java/android/crypto/hpke/XdhKeySpec.java",
+        "luni/src/main/java/android/crypto/hpke/*.java",
         "luni/src/main/java/android/system/ErrnoException.java",
         "luni/src/main/java/android/system/GaiException.java",
         "luni/src/main/java/android/system/IcmpHeaders.java",
diff --git a/ojluni/annotations/flagged_api/java/lang/Float.annotated.java b/ojluni/annotations/flagged_api/java/lang/Float.annotated.java
index f5381f52bb9..7382c1cf119 100644
--- a/ojluni/annotations/flagged_api/java/lang/Float.annotated.java
+++ b/ojluni/annotations/flagged_api/java/lang/Float.annotated.java
@@ -48,6 +48,12 @@ public double doubleValue() { throw new RuntimeException("Stub!"); }
 
 public boolean equals(java.lang.Object obj) { throw new RuntimeException("Stub!"); }
 
+@android.annotation.FlaggedApi(com.android.libcore.Flags.FLAG_OPENJDK_21_V1_APIS)
+public static float float16ToFloat(short floatBinary16) { throw new RuntimeException("Stub!"); }
+
+@android.annotation.FlaggedApi(com.android.libcore.Flags.FLAG_OPENJDK_21_V1_APIS)
+public static short floatToFloat16(float f) { throw new RuntimeException("Stub!"); }
+
 public static int floatToIntBits(float value) { throw new RuntimeException("Stub!"); }
 
 public static native int floatToRawIntBits(float value);
diff --git a/ojluni/annotations/flagged_api/java/lang/Integer.annotated.java b/ojluni/annotations/flagged_api/java/lang/Integer.annotated.java
index 25e79d31f6b..0f819ccc0aa 100644
--- a/ojluni/annotations/flagged_api/java/lang/Integer.annotated.java
+++ b/ojluni/annotations/flagged_api/java/lang/Integer.annotated.java
@@ -45,6 +45,9 @@ public int compareTo(java.lang.Integer anotherInteger) { throw new RuntimeExcept
 
 public static int compareUnsigned(int x, int y) { throw new RuntimeException("Stub!"); }
 
+@android.annotation.FlaggedApi(com.android.libcore.Flags.FLAG_OPENJDK_21_V1_APIS)
+public static int compress(int i, int mask) { throw new RuntimeException("Stub!"); }
+
 public static java.lang.Integer decode(java.lang.String nm) throws java.lang.NumberFormatException { throw new RuntimeException("Stub!"); }
 
 public static int divideUnsigned(int dividend, int divisor) { throw new RuntimeException("Stub!"); }
@@ -53,6 +56,9 @@ public double doubleValue() { throw new RuntimeException("Stub!"); }
 
 public boolean equals(java.lang.Object obj) { throw new RuntimeException("Stub!"); }
 
+@android.annotation.FlaggedApi(com.android.libcore.Flags.FLAG_OPENJDK_21_V1_APIS)
+public static int expand(int i, int mask) { throw new RuntimeException("Stub!"); }
+
 public float floatValue() { throw new RuntimeException("Stub!"); }
 
 public static java.lang.Integer getInteger(java.lang.String nm) { throw new RuntimeException("Stub!"); }
diff --git a/ojluni/annotations/flagged_api/java/lang/Long.annotated.java b/ojluni/annotations/flagged_api/java/lang/Long.annotated.java
index 93d99486447..b73527f18d4 100644
--- a/ojluni/annotations/flagged_api/java/lang/Long.annotated.java
+++ b/ojluni/annotations/flagged_api/java/lang/Long.annotated.java
@@ -45,6 +45,9 @@ public int compareTo(java.lang.Long anotherLong) { throw new RuntimeException("S
 
 public static int compareUnsigned(long x, long y) { throw new RuntimeException("Stub!"); }
 
+@android.annotation.FlaggedApi(com.android.libcore.Flags.FLAG_OPENJDK_21_V1_APIS)
+public static long compress(long i, long mask) { throw new RuntimeException("Stub!"); }
+
 public static java.lang.Long decode(java.lang.String nm) throws java.lang.NumberFormatException { throw new RuntimeException("Stub!"); }
 
 public static long divideUnsigned(long dividend, long divisor) { throw new RuntimeException("Stub!"); }
@@ -53,6 +56,9 @@ public double doubleValue() { throw new RuntimeException("Stub!"); }
 
 public boolean equals(java.lang.Object obj) { throw new RuntimeException("Stub!"); }
 
+@android.annotation.FlaggedApi(com.android.libcore.Flags.FLAG_OPENJDK_21_V1_APIS)
+public static long expand(long i, long mask) { throw new RuntimeException("Stub!"); }
+
 public float floatValue() { throw new RuntimeException("Stub!"); }
 
 public static java.lang.Long getLong(java.lang.String nm) { throw new RuntimeException("Stub!"); }
diff --git a/ojluni/annotations/flagged_api/java/lang/runtime/SwitchBootstraps.annotated.java b/ojluni/annotations/flagged_api/java/lang/runtime/SwitchBootstraps.annotated.java
new file mode 100644
index 00000000000..c7fd27fe09b
--- /dev/null
+++ b/ojluni/annotations/flagged_api/java/lang/runtime/SwitchBootstraps.annotated.java
@@ -0,0 +1,35 @@
+/*
+ * Copyright (c) 2017, 2023, Oracle and/or its affiliates. All rights reserved.
+ * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
+ *
+ * This code is free software; you can redistribute it and/or modify it
+ * under the terms of the GNU General Public License version 2 only, as
+ * published by the Free Software Foundation.  Oracle designates this
+ * particular file as subject to the "Classpath" exception as provided
+ * by Oracle in the LICENSE file that accompanied this code.
+ *
+ * This code is distributed in the hope that it will be useful, but WITHOUT
+ * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
+ * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
+ * version 2 for more details (a copy is included in the LICENSE file that
+ * accompanied this code).
+ *
+ * You should have received a copy of the GNU General Public License version
+ * 2 along with this work; if not, write to the Free Software Foundation,
+ * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
+ *
+ * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
+ * or visit www.oracle.com if you need additional information or have any
+ * questions.
+ */
+
+
+package java.lang.runtime;
+
+@SuppressWarnings({"unchecked", "deprecation", "all"})
+@android.annotation.FlaggedApi(com.android.libcore.Flags.FLAG_OPENJDK_21_V1_APIS)
+public class SwitchBootstraps {
+
+SwitchBootstraps() { throw new RuntimeException("Stub!"); }
+}
+
diff --git a/ojluni/annotations/flagged_api/java/time/Duration.annotated.java b/ojluni/annotations/flagged_api/java/time/Duration.annotated.java
new file mode 100644
index 00000000000..86116743d1b
--- /dev/null
+++ b/ojluni/annotations/flagged_api/java/time/Duration.annotated.java
@@ -0,0 +1,195 @@
+/*
+ * Copyright (c) 2012, 2019, Oracle and/or its affiliates. All rights reserved.
+ * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
+ *
+ * This code is free software; you can redistribute it and/or modify it
+ * under the terms of the GNU General Public License version 2 only, as
+ * published by the Free Software Foundation.  Oracle designates this
+ * particular file as subject to the "Classpath" exception as provided
+ * by Oracle in the LICENSE file that accompanied this code.
+ *
+ * This code is distributed in the hope that it will be useful, but WITHOUT
+ * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
+ * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
+ * version 2 for more details (a copy is included in the LICENSE file that
+ * accompanied this code).
+ *
+ * You should have received a copy of the GNU General Public License version
+ * 2 along with this work; if not, write to the Free Software Foundation,
+ * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
+ *
+ * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
+ * or visit www.oracle.com if you need additional information or have any
+ * questions.
+ */
+
+/*
+ * This file is available under and governed by the GNU General Public
+ * License version 2 only, as published by the Free Software Foundation.
+ * However, the following notice accompanied the original version of this
+ * file:
+ *
+ * Copyright (c) 2007-2012, Stephen Colebourne & Michael Nascimento Santos
+ *
+ * All rights reserved.
+ *
+ * Redistribution and use in source and binary forms, with or without
+ * modification, are permitted provided that the following conditions are met:
+ *
+ *  * Redistributions of source code must retain the above copyright notice,
+ *    this list of conditions and the following disclaimer.
+ *
+ *  * Redistributions in binary form must reproduce the above copyright notice,
+ *    this list of conditions and the following disclaimer in the documentation
+ *    and/or other materials provided with the distribution.
+ *
+ *  * Neither the name of JSR-310 nor the names of its contributors
+ *    may be used to endorse or promote products derived from this software
+ *    without specific prior written permission.
+ *
+ * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+ * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+ * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
+ * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
+ * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
+ * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
+ * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
+ * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
+ * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
+ * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
+ * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
+ */
+
+package java.time;
+
+@SuppressWarnings({"unchecked", "deprecation", "all"})
+public final class Duration implements java.lang.Comparable<java.time.Duration>, java.io.Serializable, java.time.temporal.TemporalAmount {
+
+Duration() { throw new RuntimeException("Stub!"); }
+
+public java.time.Duration abs() { throw new RuntimeException("Stub!"); }
+
+public java.time.temporal.Temporal addTo(java.time.temporal.Temporal temporal) { throw new RuntimeException("Stub!"); }
+
+public static java.time.Duration between(java.time.temporal.Temporal startInclusive, java.time.temporal.Temporal endExclusive) { throw new RuntimeException("Stub!"); }
+
+public int compareTo(java.time.Duration otherDuration) { throw new RuntimeException("Stub!"); }
+
+public long dividedBy(java.time.Duration divisor) { throw new RuntimeException("Stub!"); }
+
+public java.time.Duration dividedBy(long divisor) { throw new RuntimeException("Stub!"); }
+
+public boolean equals(java.lang.Object other) { throw new RuntimeException("Stub!"); }
+
+public static java.time.Duration from(java.time.temporal.TemporalAmount amount) { throw new RuntimeException("Stub!"); }
+
+public long get(java.time.temporal.TemporalUnit unit) { throw new RuntimeException("Stub!"); }
+
+public int getNano() { throw new RuntimeException("Stub!"); }
+
+public long getSeconds() { throw new RuntimeException("Stub!"); }
+
+public java.util.List<java.time.temporal.TemporalUnit> getUnits() { throw new RuntimeException("Stub!"); }
+
+public int hashCode() { throw new RuntimeException("Stub!"); }
+
+public boolean isNegative() { throw new RuntimeException("Stub!"); }
+
+
+@android.annotation.FlaggedApi(com.android.libcore.Flags.FLAG_OPENJDK_21_V2_APIS)
+public boolean isPositive() { throw new RuntimeException("Stub!"); }
+
+public boolean isZero() { throw new RuntimeException("Stub!"); }
+
+public java.time.Duration minus(java.time.Duration duration) { throw new RuntimeException("Stub!"); }
+
+public java.time.Duration minus(long amountToSubtract, java.time.temporal.TemporalUnit unit) { throw new RuntimeException("Stub!"); }
+
+public java.time.Duration minusDays(long daysToSubtract) { throw new RuntimeException("Stub!"); }
+
+public java.time.Duration minusHours(long hoursToSubtract) { throw new RuntimeException("Stub!"); }
+
+public java.time.Duration minusMillis(long millisToSubtract) { throw new RuntimeException("Stub!"); }
+
+public java.time.Duration minusMinutes(long minutesToSubtract) { throw new RuntimeException("Stub!"); }
+
+public java.time.Duration minusNanos(long nanosToSubtract) { throw new RuntimeException("Stub!"); }
+
+public java.time.Duration minusSeconds(long secondsToSubtract) { throw new RuntimeException("Stub!"); }
+
+public java.time.Duration multipliedBy(long multiplicand) { throw new RuntimeException("Stub!"); }
+
+public java.time.Duration negated() { throw new RuntimeException("Stub!"); }
+
+public static java.time.Duration of(long amount, java.time.temporal.TemporalUnit unit) { throw new RuntimeException("Stub!"); }
+
+public static java.time.Duration ofDays(long days) { throw new RuntimeException("Stub!"); }
+
+public static java.time.Duration ofHours(long hours) { throw new RuntimeException("Stub!"); }
+
+public static java.time.Duration ofMillis(long millis) { throw new RuntimeException("Stub!"); }
+
+public static java.time.Duration ofMinutes(long minutes) { throw new RuntimeException("Stub!"); }
+
+public static java.time.Duration ofNanos(long nanos) { throw new RuntimeException("Stub!"); }
+
+public static java.time.Duration ofSeconds(long seconds) { throw new RuntimeException("Stub!"); }
+
+public static java.time.Duration ofSeconds(long seconds, long nanoAdjustment) { throw new RuntimeException("Stub!"); }
+
+public static java.time.Duration parse(java.lang.CharSequence text) { throw new RuntimeException("Stub!"); }
+
+public java.time.Duration plus(java.time.Duration duration) { throw new RuntimeException("Stub!"); }
+
+public java.time.Duration plus(long amountToAdd, java.time.temporal.TemporalUnit unit) { throw new RuntimeException("Stub!"); }
+
+public java.time.Duration plusDays(long daysToAdd) { throw new RuntimeException("Stub!"); }
+
+public java.time.Duration plusHours(long hoursToAdd) { throw new RuntimeException("Stub!"); }
+
+public java.time.Duration plusMillis(long millisToAdd) { throw new RuntimeException("Stub!"); }
+
+public java.time.Duration plusMinutes(long minutesToAdd) { throw new RuntimeException("Stub!"); }
+
+public java.time.Duration plusNanos(long nanosToAdd) { throw new RuntimeException("Stub!"); }
+
+public java.time.Duration plusSeconds(long secondsToAdd) { throw new RuntimeException("Stub!"); }
+
+public java.time.temporal.Temporal subtractFrom(java.time.temporal.Temporal temporal) { throw new RuntimeException("Stub!"); }
+
+public long toDays() { throw new RuntimeException("Stub!"); }
+
+public long toDaysPart() { throw new RuntimeException("Stub!"); }
+
+public long toHours() { throw new RuntimeException("Stub!"); }
+
+public int toHoursPart() { throw new RuntimeException("Stub!"); }
+
+public long toMillis() { throw new RuntimeException("Stub!"); }
+
+public int toMillisPart() { throw new RuntimeException("Stub!"); }
+
+public long toMinutes() { throw new RuntimeException("Stub!"); }
+
+public int toMinutesPart() { throw new RuntimeException("Stub!"); }
+
+public long toNanos() { throw new RuntimeException("Stub!"); }
+
+public int toNanosPart() { throw new RuntimeException("Stub!"); }
+
+public long toSeconds() { throw new RuntimeException("Stub!"); }
+
+public int toSecondsPart() { throw new RuntimeException("Stub!"); }
+
+public java.lang.String toString() { throw new RuntimeException("Stub!"); }
+
+public java.time.Duration truncatedTo(java.time.temporal.TemporalUnit unit) { throw new RuntimeException("Stub!"); }
+
+public java.time.Duration withNanos(int nanoOfSecond) { throw new RuntimeException("Stub!"); }
+
+public java.time.Duration withSeconds(long seconds) { throw new RuntimeException("Stub!"); }
+
+public static final java.time.Duration ZERO;
+static { ZERO = null; }
+}
+
diff --git a/ojluni/src/main/java/java/io/File.java b/ojluni/src/main/java/java/io/File.java
index ba90a3f6095..3b921a34fdc 100644
--- a/ojluni/src/main/java/java/io/File.java
+++ b/ojluni/src/main/java/java/io/File.java
@@ -2176,10 +2176,10 @@ public class File
 
     private static final long PATH_OFFSET;
     private static final long PREFIX_LENGTH_OFFSET;
-    private static final sun.misc.Unsafe UNSAFE;
+    private static final jdk.internal.misc.Unsafe UNSAFE;
     static {
         try {
-            sun.misc.Unsafe unsafe = sun.misc.Unsafe.getUnsafe();
+            jdk.internal.misc.Unsafe unsafe = jdk.internal.misc.Unsafe.getUnsafe();
             PATH_OFFSET = unsafe.objectFieldOffset(
                     File.class.getDeclaredField("path"));
             PREFIX_LENGTH_OFFSET = unsafe.objectFieldOffset(
diff --git a/ojluni/src/main/java/java/io/FileOutputStream.java b/ojluni/src/main/java/java/io/FileOutputStream.java
index fb44a3ef275..f070a0f29ba 100644
--- a/ojluni/src/main/java/java/io/FileOutputStream.java
+++ b/ojluni/src/main/java/java/io/FileOutputStream.java
@@ -295,6 +295,10 @@ public class FileOutputStream extends OutputStream
      * is {@link java.io.FileDescriptor#valid() invalid}.
      * However, if the methods are invoked on the resulting stream to attempt
      * I/O on the stream, an {@code IOException} is thrown.
+     * <p>
+     * Android-specific warning: {@link #close()} method doesn't close the {@code fdObj} provided,
+     * because this object doesn't own the file descriptor, but the caller does. The caller can
+     * call {@link android.system.Os#close(FileDescriptor)} to close the fd.
      *
      * @param      fdObj   the file descriptor to be opened for writing
      * @throws     SecurityException  if a security manager exists and its
diff --git a/ojluni/src/main/java/java/io/ObjectStreamClass.java b/ojluni/src/main/java/java/io/ObjectStreamClass.java
index d3a015f09f6..fc7d9bde6d8 100644
--- a/ojluni/src/main/java/java/io/ObjectStreamClass.java
+++ b/ojluni/src/main/java/java/io/ObjectStreamClass.java
@@ -55,7 +55,7 @@ import java.util.Map;
 import java.util.Set;
 import java.util.concurrent.ConcurrentHashMap;
 import java.util.concurrent.ConcurrentMap;
-import sun.misc.Unsafe;
+import jdk.internal.misc.Unsafe;
 import sun.reflect.CallerSensitive;
 import sun.reflect.Reflection;
 import sun.reflect.misc.ReflectUtil;
@@ -2503,7 +2503,7 @@ public class ObjectStreamClass implements Serializable {
         if (targetSdkVersion > 0 && targetSdkVersion <= 24) {
             System.logE("WARNING: ObjectStreamClass.newInstance(Class<?>, long) is private API and" +
                         "will be removed in a future Android release.");
-            return sun.misc.Unsafe.getUnsafe().allocateInstance(clazz);
+            return jdk.internal.misc.Unsafe.getUnsafe().allocateInstance(clazz);
         }
 
         throw new UnsupportedOperationException("ObjectStreamClass.newInstance(Class<?>, long) " +
diff --git a/ojluni/src/main/java/java/lang/Class.java b/ojluni/src/main/java/java/lang/Class.java
index 89b9bb42cf2..2b263dc7fa5 100644
--- a/ojluni/src/main/java/java/lang/Class.java
+++ b/ojluni/src/main/java/java/lang/Class.java
@@ -249,22 +249,12 @@ public final class Class<T> implements java.io.Serializable,
      */
     private transient Object vtable;
 
-    /**
-     * Instance fields. These describe the layout of the contents of an Object. Note that only the
-     * fields directly declared by this class are listed in iFields; fields declared by a
-     * superclass are listed in the superclass's Class.iFields.
-     *
-     * All instance fields that refer to objects are guaranteed to be at the beginning of the field
-     * list.  {@link Class#numReferenceInstanceFields} specifies the number of reference fields.
-     */
-    private transient long iFields;
+    /** Declared fields. */
+    private transient long fields;
 
     /** All methods with this class as the base for virtual dispatch. */
     private transient long methods;
 
-    /** Static fields */
-    private transient long sFields;
-
     /** access flags; low 16 bits are defined by VM spec */
     private transient int accessFlags;
 
diff --git a/ojluni/src/main/java/java/lang/Enum.java b/ojluni/src/main/java/java/lang/Enum.java
index 3cda35e84b6..1df020e4560 100644
--- a/ojluni/src/main/java/java/lang/Enum.java
+++ b/ojluni/src/main/java/java/lang/Enum.java
@@ -267,7 +267,7 @@ public abstract class Enum<E extends Enum<E>>
      *         is null
      * @since 1.5
      */
-    // BEGIN Android-changed: Use a static BasicLruCache mapping Enum class -> Enum instance array.
+    // BEGIN Android-changed: Use a ClassValue mapping Enum class -> Enum instance array.
     // This change was made to fix a performance regression. See b/4087759 and b/109791362 for more
     // background information.
     /*
@@ -314,10 +314,10 @@ public abstract class Enum<E extends Enum<E>>
         }
     }
 
-    private static final BasicLruCache<Class<? extends Enum>, Object[]> sharedConstantsCache
-            = new BasicLruCache<Class<? extends Enum>, Object[]>(64) {
-        @Override protected Object[] create(Class<? extends Enum> enumType) {
-            return enumValues(enumType);
+    private static final ClassValue<Object[]> sharedConstants = new ClassValue<>() {
+        @Override
+        protected Object[] computeValue(Class<?> enumType) {
+            return enumValues((Class<? extends Enum>) enumType);
         }
     };
 
@@ -329,9 +329,9 @@ public abstract class Enum<E extends Enum<E>>
      */
     @SuppressWarnings("unchecked") // the cache always returns the type matching enumType
     public static <T extends Enum<T>> T[] getSharedConstants(Class<T> enumType) {
-        return (T[]) sharedConstantsCache.get(enumType);
+        return (T[]) sharedConstants.get(enumType);
     }
-    // END Android-changed: Use a static BasicLruCache mapping Enum class -> Enum instance array.
+    // END Android-changed: Use a ClassValue mapping Enum class -> Enum instance array.
 
     /**
      * enum classes cannot have finalize methods.
diff --git a/ojluni/src/main/java/java/lang/Float.java b/ojluni/src/main/java/java/lang/Float.java
index 6b1a044877f..81420d36daf 100644
--- a/ojluni/src/main/java/java/lang/Float.java
+++ b/ojluni/src/main/java/java/lang/Float.java
@@ -1018,7 +1018,6 @@ public final class Float extends Number
      *
      * @param floatBinary16 the binary16 value to convert to {@code float}
      * @since 20
-     * @hide
      */
     @IntrinsicCandidate
     public static float float16ToFloat(short floatBinary16) {
@@ -1095,7 +1094,6 @@ public final class Float extends Number
      *
      * @param f the {@code float} value to convert to binary16
      * @since 20
-     * @hide
      */
     @IntrinsicCandidate
     public static short floatToFloat16(float f) {
diff --git a/ojluni/src/main/java/java/lang/Integer.java b/ojluni/src/main/java/java/lang/Integer.java
index c85ef69781c..5ec393748d1 100644
--- a/ojluni/src/main/java/java/lang/Integer.java
+++ b/ojluni/src/main/java/java/lang/Integer.java
@@ -1966,7 +1966,6 @@ public final class Integer extends Number
      * @return the compressed value
      * @see #expand
      * @since 19
-     * @hide
      */
     @IntrinsicCandidate
     public static int compress(int i, int mask) {
@@ -2056,7 +2055,6 @@ public final class Integer extends Number
      * @return the expanded value
      * @see #compress
      * @since 19
-     * @hide
      */
     @IntrinsicCandidate
     public static int expand(int i, int mask) {
diff --git a/ojluni/src/main/java/jdk/internal/access/JavaLangAccess.java b/ojluni/src/main/java/java/lang/JavaLangAccess.java
similarity index 97%
rename from ojluni/src/main/java/jdk/internal/access/JavaLangAccess.java
rename to ojluni/src/main/java/java/lang/JavaLangAccess.java
index 23f33014b28..e1b87683592 100644
--- a/ojluni/src/main/java/jdk/internal/access/JavaLangAccess.java
+++ b/ojluni/src/main/java/java/lang/JavaLangAccess.java
@@ -23,9 +23,11 @@
  * questions.
  */
 
-package jdk.internal.access;
+package java.lang;
 
-public interface JavaLangAccess {
+// Android-changed: Make JavaLangAccess a final class. http://b/399374716
+// public interface JavaLangAccess {
+public final class JavaLangAccess {
 
     // BEGIN Android-removed: Not used in Android.
     /*
@@ -83,7 +85,9 @@ public interface JavaLangAccess {
      * Class object does not represent an enum type;
      * the result is uncloned, cached, and shared by all callers.
      */
-    <E extends Enum<E>> E[] getEnumConstantsShared(Class<E> klass);
+    public <E extends Enum<E>> E[] getEnumConstantsShared(Class<E> klass) {
+        return klass.getEnumConstantsShared();
+    }
 
     // BEGIN Android-removed: Not used in Android.
     /*
@@ -562,6 +566,12 @@ public interface JavaLangAccess {
      * explicitly set otherwise <qualified-class-name> @<id>
      * /
     String getLoaderNameID(ClassLoader loader);
+
+    /**
+     * Is a security manager already set or allowed to be set
+     * (using -Djava.security.manager=allow)?
+     * /
+    boolean allowSecurityManager();
      */
-    // END Android-removed: Not used in Android.
+     // END Android-removed: Not used in Android.
 }
diff --git a/ojluni/src/main/java/java/lang/Long.java b/ojluni/src/main/java/java/lang/Long.java
index 9dbe47fd8b0..0fdd57bead8 100644
--- a/ojluni/src/main/java/java/lang/Long.java
+++ b/ojluni/src/main/java/java/lang/Long.java
@@ -2015,7 +2015,6 @@ public final class Long extends Number
      * @return the compressed value
      * @see #expand
      * @since 19
-     * @hide
      */
     @IntrinsicCandidate
     public static long compress(long i, long mask) {
@@ -2104,8 +2103,6 @@ public final class Long extends Number
      * @param mask the bit mask
      * @return the expanded value
      * @see #compress
-     * @since 19
-     * @hide
      */
     @IntrinsicCandidate
     public static long expand(long i, long mask) {
diff --git a/ojluni/src/main/java/java/lang/Runtime.java b/ojluni/src/main/java/java/lang/Runtime.java
index c56cde0aa63..90a06568d8b 100644
--- a/ojluni/src/main/java/java/lang/Runtime.java
+++ b/ojluni/src/main/java/java/lang/Runtime.java
@@ -26,42 +26,30 @@
 
 package java.lang;
 
+import static android.system.OsConstants._SC_NPROCESSORS_CONF;
+
 import com.android.libcore.Flags;
 
 import dalvik.annotation.compat.VersionCodes;
 import dalvik.annotation.optimization.FastNative;
-import java.io.*;
-import java.math.BigInteger;
-import java.util.ArrayList;
-import java.util.regex.Matcher;
-import java.util.regex.Pattern;
-import java.util.stream.Collectors;
-import java.util.Collections;
-import java.util.List;
-import java.util.Optional;
-import java.util.StringTokenizer;
-
 import dalvik.system.BlockGuard;
-import sun.reflect.CallerSensitive;
-import java.lang.ref.FinalizerReference;
-import java.util.ArrayList;
-import java.util.List;
 import dalvik.system.DelegateLastClassLoader;
 import dalvik.system.PathClassLoader;
-import dalvik.system.VMDebug;
 import dalvik.system.VMRuntime;
-import sun.reflect.Reflection;
 
-import libcore.io.IoUtils;
 import libcore.io.Libcore;
 import libcore.util.EmptyArray;
-import static android.system.OsConstants._SC_NPROCESSORS_CONF;
 
-import android.compat.Compatibility;
-import android.compat.annotation.ChangeId;
-import android.compat.annotation.Disabled;
-import android.compat.annotation.EnabledSince;
-import android.compat.annotation.Overridable;
+import java.io.File;
+import java.io.IOException;
+import java.io.InputStream;
+import java.io.OutputStream;
+import java.util.ArrayList;
+import java.util.List;
+import java.util.StringTokenizer;
+
+import sun.reflect.CallerSensitive;
+import sun.reflect.Reflection;
 
 /**
  * Every Java application has a single instance of class
@@ -98,15 +86,6 @@ public class Runtime {
      */
     private boolean shuttingDown;
 
-    // Android-added: flag
-    /**
-     * Throw UnsatisfiedLinkError if loading a writable library using {@link Runtime#load(String)}.
-     * @hide
-     */
-    @ChangeId
-    @Disabled
-    public static final long RO_DCL_CHANGE_ID = 354921003L;
-
     private static native void nativeExit(int code);
 
     /**
@@ -950,9 +929,7 @@ public class Runtime {
         }
         if (Flags.readOnlyDynamicCodeLoad()) {
             if (!file.toPath().getFileSystem().isReadOnly() && file.canWrite()) {
-                if (Compatibility.isChangeEnabled(RO_DCL_CHANGE_ID)) {
-                    throw new UnsatisfiedLinkError("Attempt to load writable file: " + filename);
-                } else if (VMRuntime.getSdkVersion() >= VersionCodes.VANILLA_ICE_CREAM){
+                if (VMRuntime.getSdkVersion() >= VersionCodes.VANILLA_ICE_CREAM) {
                     System.logW("Attempt to load writable file: " + filename
                             + ". This will throw on a future Android version");
                 }
diff --git a/ojluni/src/main/java/java/lang/Thread.java b/ojluni/src/main/java/java/lang/Thread.java
index 257e4dd3934..effb7c8ff0a 100644
--- a/ojluni/src/main/java/java/lang/Thread.java
+++ b/ojluni/src/main/java/java/lang/Thread.java
@@ -1199,6 +1199,7 @@ class Thread implements Runnable {
      *        For more information, see
      *        <a href="{@docRoot}/../technotes/guides/concurrency/threadPrimitiveDeprecation.html">Why
      *        are Thread.stop, Thread.suspend and Thread.resume Deprecated?</a>.
+     * @removed
      */
     @Deprecated
     public final synchronized void stop(Throwable obj) {
@@ -1343,6 +1344,7 @@ class Thread implements Runnable {
      *     "frozen" processes. For more information, see
      *     <a href="{@docRoot}/../technotes/guides/concurrency/threadPrimitiveDeprecation.html">
      *     Why are Thread.stop, Thread.suspend and Thread.resume Deprecated?</a>.
+     * @removed
      * @throws UnsupportedOperationException always
      */
     @Deprecated
@@ -1378,6 +1380,7 @@ class Thread implements Runnable {
      *   For more information, see
      *   <a href="{@docRoot}/../technotes/guides/concurrency/threadPrimitiveDeprecation.html">Why
      *   are Thread.stop, Thread.suspend and Thread.resume Deprecated?</a>.
+     * @removed
      * @throws UnsupportedOperationException always
      */
     @Deprecated(since="1.2")
@@ -1398,6 +1401,7 @@ class Thread implements Runnable {
      *     For more information, see
      *     <a href="{@docRoot}/../technotes/guides/concurrency/threadPrimitiveDeprecation.html">Why
      *     are Thread.stop, Thread.suspend and Thread.resume Deprecated?</a>.
+     * @removed
      * @throws UnsupportedOperationException always
      */
     @Deprecated(since="1.2")
@@ -1582,6 +1586,7 @@ class Thread implements Runnable {
      *             which is deprecated.  Further, the results of this call
      *             were never well-defined.
      *             This method is subject to removal in a future version of Java SE.
+     * @removed
      */
     @Deprecated(since="1.2", forRemoval=true)
     // Android-changed: Provide non-native implementation of countStackFrames().
diff --git a/ojluni/src/main/java/java/lang/invoke/DirectMethodHandle.java b/ojluni/src/main/java/java/lang/invoke/DirectMethodHandle.java
new file mode 100644
index 00000000000..2495b124ade
--- /dev/null
+++ b/ojluni/src/main/java/java/lang/invoke/DirectMethodHandle.java
@@ -0,0 +1,572 @@
+/*
+ * Copyright (c) 2008, 2022, Oracle and/or its affiliates. All rights reserved.
+ * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
+ *
+ * This code is free software; you can redistribute it and/or modify it
+ * under the terms of the GNU General Public License version 2 only, as
+ * published by the Free Software Foundation.  Oracle designates this
+ * particular file as subject to the "Classpath" exception as provided
+ * by Oracle in the LICENSE file that accompanied this code.
+ *
+ * This code is distributed in the hope that it will be useful, but WITHOUT
+ * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
+ * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
+ * version 2 for more details (a copy is included in the LICENSE file that
+ * accompanied this code).
+ *
+ * You should have received a copy of the GNU General Public License version
+ * 2 along with this work; if not, write to the Free Software Foundation,
+ * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
+ *
+ * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
+ * or visit www.oracle.com if you need additional information or have any
+ * questions.
+ */
+
+package java.lang.invoke;
+
+import static java.lang.invoke.MethodHandleStatics.UNSAFE;
+
+import java.lang.reflect.Method;
+import java.util.Arrays;
+import java.util.Collections;
+import java.util.HashMap;
+import java.util.List;
+import java.util.Map;
+import java.util.Objects;
+
+import jdk.internal.vm.annotation.ForceInline;
+
+// Android-changed: currently only 4 methods and the Holder class are needed, hence not importing
+// entire file.
+/**
+ * The flavor of method handle which implements a constant reference
+ * to a class member.
+ * @author jrose
+ */
+class DirectMethodHandle {
+
+    @ForceInline
+    /*non-public*/
+    static long fieldOffset(Object accessorObj) {
+        // Note: We return a long because that is what Unsafe.getObject likes.
+        // We store a plain int because it is more compact.
+        // Android-changed: there is only MethodHandleImpl.
+        // return ((Accessor)accessorObj).fieldOffset;
+        return ((MethodHandleImpl) accessorObj).field.getOffset();
+    }
+
+    @ForceInline
+    /*non-public*/
+    static Object checkBase(Object obj) {
+        // Note that the object's class has already been verified,
+        // since the parameter type of the Accessor method handle
+        // is either member.getDeclaringClass or a subclass.
+        // This was verified in DirectMethodHandle.make.
+        // Therefore, the only remaining check is for null.
+        // Since this check is *not* guaranteed by Unsafe.getInt
+        // and its siblings, we need to make an explicit one here.
+        return Objects.requireNonNull(obj);
+    }
+
+
+    @ForceInline
+    /*non-public*/
+    static Object staticBase(Object accessorObj) {
+        // Android-changed: there is only MethodHandleImpl.
+        // return ((StaticAccessor)accessorObj).staticBase;
+        return ((MethodHandleImpl) accessorObj).field.getDeclaringClass();
+    }
+
+    @ForceInline
+    /*non-public*/
+    static long staticOffset(Object accessorObj) {
+        // Android-changed: there is only MethodHandleImpl.
+        // return ((StaticAccessor)accessorObj).staticOffset;
+        return ((MethodHandleImpl) accessorObj).field.getOffset();
+    }
+
+    // BEGIN Android-added: different mechanism to tie actual implementation to a MethodHandle.
+    static Method getImplementation(String name, List<Class<?>> parameters) {
+        return ACCESSOR_IMPLEMENTATIONS.get(new MethodKey(name, parameters));
+    }
+
+    private static final Map<MethodKey, Method> ACCESSOR_IMPLEMENTATIONS;
+
+    static {
+        UNSAFE.ensureClassInitialized(Holder.class);
+
+        // 4 access kinds, 9 basic types and fields can be volatile or non-volatile.
+        HashMap<MethodKey, Method> accessorMethods = HashMap.newHashMap(4 * 9 * 2);
+
+        for (Method m : Holder.class.getDeclaredMethods()) {
+            accessorMethods.put(
+                    new MethodKey(m.getName(), Arrays.asList(m.getParameterTypes())), m);
+        }
+
+        ACCESSOR_IMPLEMENTATIONS = Collections.unmodifiableMap(accessorMethods);
+    }
+
+    private static final class MethodKey {
+        private final String name;
+        private final List<Class<?>> arguments;
+
+        MethodKey(String name, List<Class<?>> arguments) {
+            this.name = Objects.requireNonNull(name);
+            this.arguments = Objects.requireNonNull(arguments);
+        }
+
+        @Override
+        public int hashCode() {
+            return 31 * name.hashCode() + arguments.hashCode();
+        }
+
+        @Override
+        public boolean equals(Object obj) {
+            if (obj instanceof MethodKey methodKey) {
+                return name.equals(methodKey.name) && arguments.equals(methodKey.arguments);
+            }
+
+            return false;
+        }
+    }
+    // END Android-added: different mechanism to tie actual implementation to a MethodHandle.
+
+    // Android-changed: upstream inserts implementation at the link time (straight to bytecode, w/o
+    // compilation).
+    // Do not change this class manually: check AccessorMethodHandlesGenerator.
+    /* Placeholder class for DirectMethodHandles generated ahead of time */
+    static final class Holder {
+        static void putBoolean(Object base, boolean value, MethodHandleImpl mh) {
+            checkBase(base);
+            long offset = fieldOffset(mh);
+            UNSAFE.putBoolean(base, offset, value);
+        }
+
+        static void putBooleanVolatile(Object base, boolean value, MethodHandleImpl mh) {
+            checkBase(base);
+            long offset = fieldOffset(mh);
+            UNSAFE.putBooleanVolatile(base, offset, value);
+        }
+
+        static void putByte(Object base, byte value, MethodHandleImpl mh) {
+            checkBase(base);
+            long offset = fieldOffset(mh);
+            UNSAFE.putByte(base, offset, value);
+        }
+
+        static void putByteVolatile(Object base, byte value, MethodHandleImpl mh) {
+            checkBase(base);
+            long offset = fieldOffset(mh);
+            UNSAFE.putByteVolatile(base, offset, value);
+        }
+
+        static void putChar(Object base, char value, MethodHandleImpl mh) {
+            checkBase(base);
+            long offset = fieldOffset(mh);
+            UNSAFE.putChar(base, offset, value);
+        }
+
+        static void putCharVolatile(Object base, char value, MethodHandleImpl mh) {
+            checkBase(base);
+            long offset = fieldOffset(mh);
+            UNSAFE.putCharVolatile(base, offset, value);
+        }
+
+        static void putShort(Object base, short value, MethodHandleImpl mh) {
+            checkBase(base);
+            long offset = fieldOffset(mh);
+            UNSAFE.putShort(base, offset, value);
+        }
+
+        static void putShortVolatile(Object base, short value, MethodHandleImpl mh) {
+            checkBase(base);
+            long offset = fieldOffset(mh);
+            UNSAFE.putShortVolatile(base, offset, value);
+        }
+
+        static void putInt(Object base, int value, MethodHandleImpl mh) {
+            checkBase(base);
+            long offset = fieldOffset(mh);
+            UNSAFE.putInt(base, offset, value);
+        }
+
+        static void putIntVolatile(Object base, int value, MethodHandleImpl mh) {
+            checkBase(base);
+            long offset = fieldOffset(mh);
+            UNSAFE.putIntVolatile(base, offset, value);
+        }
+
+        static void putLong(Object base, long value, MethodHandleImpl mh) {
+            checkBase(base);
+            long offset = fieldOffset(mh);
+            UNSAFE.putLong(base, offset, value);
+        }
+
+        static void putLongVolatile(Object base, long value, MethodHandleImpl mh) {
+            checkBase(base);
+            long offset = fieldOffset(mh);
+            UNSAFE.putLongVolatile(base, offset, value);
+        }
+
+        static void putDouble(Object base, double value, MethodHandleImpl mh) {
+            checkBase(base);
+            long offset = fieldOffset(mh);
+            UNSAFE.putDouble(base, offset, value);
+        }
+
+        static void putDoubleVolatile(Object base, double value, MethodHandleImpl mh) {
+            checkBase(base);
+            long offset = fieldOffset(mh);
+            UNSAFE.putDoubleVolatile(base, offset, value);
+        }
+
+        static void putFloat(Object base, float value, MethodHandleImpl mh) {
+            checkBase(base);
+            long offset = fieldOffset(mh);
+            UNSAFE.putFloat(base, offset, value);
+        }
+
+        static void putFloatVolatile(Object base, float value, MethodHandleImpl mh) {
+            checkBase(base);
+            long offset = fieldOffset(mh);
+            UNSAFE.putFloatVolatile(base, offset, value);
+        }
+
+        static void putReference(Object base, Object value, MethodHandleImpl mh) {
+            checkBase(base);
+            long offset = fieldOffset(mh);
+            UNSAFE.putReference(base, offset, value);
+        }
+
+        static void putReferenceVolatile(Object base, Object value, MethodHandleImpl mh) {
+            checkBase(base);
+            long offset = fieldOffset(mh);
+            UNSAFE.putReferenceVolatile(base, offset, value);
+        }
+
+        static boolean getBoolean(Object base, MethodHandleImpl mh) {
+            checkBase(base);
+            long offset = fieldOffset(mh);
+            return UNSAFE.getBoolean(base, offset);
+        }
+
+        static boolean getBooleanVolatile(Object base, MethodHandleImpl mh) {
+            checkBase(base);
+            long offset = fieldOffset(mh);
+            return UNSAFE.getBooleanVolatile(base, offset);
+        }
+
+        static byte getByte(Object base, MethodHandleImpl mh) {
+            checkBase(base);
+            long offset = fieldOffset(mh);
+            return UNSAFE.getByte(base, offset);
+        }
+
+        static byte getByteVolatile(Object base, MethodHandleImpl mh) {
+            checkBase(base);
+            long offset = fieldOffset(mh);
+            return UNSAFE.getByteVolatile(base, offset);
+        }
+
+        static char getChar(Object base, MethodHandleImpl mh) {
+            checkBase(base);
+            long offset = fieldOffset(mh);
+            return UNSAFE.getChar(base, offset);
+        }
+
+        static char getCharVolatile(Object base, MethodHandleImpl mh) {
+            checkBase(base);
+            long offset = fieldOffset(mh);
+            return UNSAFE.getCharVolatile(base, offset);
+        }
+
+        static short getShort(Object base, MethodHandleImpl mh) {
+            checkBase(base);
+            long offset = fieldOffset(mh);
+            return UNSAFE.getShort(base, offset);
+        }
+
+        static short getShortVolatile(Object base, MethodHandleImpl mh) {
+            checkBase(base);
+            long offset = fieldOffset(mh);
+            return UNSAFE.getShortVolatile(base, offset);
+        }
+
+        static int getInt(Object base, MethodHandleImpl mh) {
+            checkBase(base);
+            long offset = fieldOffset(mh);
+            return UNSAFE.getInt(base, offset);
+        }
+
+        static int getIntVolatile(Object base, MethodHandleImpl mh) {
+            checkBase(base);
+            long offset = fieldOffset(mh);
+            return UNSAFE.getIntVolatile(base, offset);
+        }
+
+        static long getLong(Object base, MethodHandleImpl mh) {
+            checkBase(base);
+            long offset = fieldOffset(mh);
+            return UNSAFE.getLong(base, offset);
+        }
+
+        static long getLongVolatile(Object base, MethodHandleImpl mh) {
+            checkBase(base);
+            long offset = fieldOffset(mh);
+            return UNSAFE.getLongVolatile(base, offset);
+        }
+
+        static double getDouble(Object base, MethodHandleImpl mh) {
+            checkBase(base);
+            long offset = fieldOffset(mh);
+            return UNSAFE.getDouble(base, offset);
+        }
+
+        static double getDoubleVolatile(Object base, MethodHandleImpl mh) {
+            checkBase(base);
+            long offset = fieldOffset(mh);
+            return UNSAFE.getDoubleVolatile(base, offset);
+        }
+
+        static float getFloat(Object base, MethodHandleImpl mh) {
+            checkBase(base);
+            long offset = fieldOffset(mh);
+            return UNSAFE.getFloat(base, offset);
+        }
+
+        static float getFloatVolatile(Object base, MethodHandleImpl mh) {
+            checkBase(base);
+            long offset = fieldOffset(mh);
+            return UNSAFE.getFloatVolatile(base, offset);
+        }
+
+        static Object getReference(Object base, MethodHandleImpl mh) {
+            checkBase(base);
+            long offset = fieldOffset(mh);
+            return UNSAFE.getReference(base, offset);
+        }
+
+        static Object getReferenceVolatile(Object base, MethodHandleImpl mh) {
+            checkBase(base);
+            long offset = fieldOffset(mh);
+            return UNSAFE.getReferenceVolatile(base, offset);
+        }
+
+        static void putBoolean(boolean value, MethodHandleImpl mh) {
+            Object base = staticBase(mh);
+            long offset = staticOffset(mh);
+            UNSAFE.putBoolean(base, offset, value);
+        }
+
+        static void putBooleanVolatile(boolean value, MethodHandleImpl mh) {
+            Object base = staticBase(mh);
+            long offset = staticOffset(mh);
+            UNSAFE.putBooleanVolatile(base, offset, value);
+        }
+
+        static void putByte(byte value, MethodHandleImpl mh) {
+            Object base = staticBase(mh);
+            long offset = staticOffset(mh);
+            UNSAFE.putByte(base, offset, value);
+        }
+
+        static void putByteVolatile(byte value, MethodHandleImpl mh) {
+            Object base = staticBase(mh);
+            long offset = staticOffset(mh);
+            UNSAFE.putByteVolatile(base, offset, value);
+        }
+
+        static void putChar(char value, MethodHandleImpl mh) {
+            Object base = staticBase(mh);
+            long offset = staticOffset(mh);
+            UNSAFE.putChar(base, offset, value);
+        }
+
+        static void putCharVolatile(char value, MethodHandleImpl mh) {
+            Object base = staticBase(mh);
+            long offset = staticOffset(mh);
+            UNSAFE.putCharVolatile(base, offset, value);
+        }
+
+        static void putShort(short value, MethodHandleImpl mh) {
+            Object base = staticBase(mh);
+            long offset = staticOffset(mh);
+            UNSAFE.putShort(base, offset, value);
+        }
+
+        static void putShortVolatile(short value, MethodHandleImpl mh) {
+            Object base = staticBase(mh);
+            long offset = staticOffset(mh);
+            UNSAFE.putShortVolatile(base, offset, value);
+        }
+
+        static void putInt(int value, MethodHandleImpl mh) {
+            Object base = staticBase(mh);
+            long offset = staticOffset(mh);
+            UNSAFE.putInt(base, offset, value);
+        }
+
+        static void putIntVolatile(int value, MethodHandleImpl mh) {
+            Object base = staticBase(mh);
+            long offset = staticOffset(mh);
+            UNSAFE.putIntVolatile(base, offset, value);
+        }
+
+        static void putLong(long value, MethodHandleImpl mh) {
+            Object base = staticBase(mh);
+            long offset = staticOffset(mh);
+            UNSAFE.putLong(base, offset, value);
+        }
+
+        static void putLongVolatile(long value, MethodHandleImpl mh) {
+            Object base = staticBase(mh);
+            long offset = staticOffset(mh);
+            UNSAFE.putLongVolatile(base, offset, value);
+        }
+
+        static void putDouble(double value, MethodHandleImpl mh) {
+            Object base = staticBase(mh);
+            long offset = staticOffset(mh);
+            UNSAFE.putDouble(base, offset, value);
+        }
+
+        static void putDoubleVolatile(double value, MethodHandleImpl mh) {
+            Object base = staticBase(mh);
+            long offset = staticOffset(mh);
+            UNSAFE.putDoubleVolatile(base, offset, value);
+        }
+
+        static void putFloat(float value, MethodHandleImpl mh) {
+            Object base = staticBase(mh);
+            long offset = staticOffset(mh);
+            UNSAFE.putFloat(base, offset, value);
+        }
+
+        static void putFloatVolatile(float value, MethodHandleImpl mh) {
+            Object base = staticBase(mh);
+            long offset = staticOffset(mh);
+            UNSAFE.putFloatVolatile(base, offset, value);
+        }
+
+        static void putReference(Object value, MethodHandleImpl mh) {
+            Object base = staticBase(mh);
+            long offset = staticOffset(mh);
+            UNSAFE.putReference(base, offset, value);
+        }
+
+        static void putReferenceVolatile(Object value, MethodHandleImpl mh) {
+            Object base = staticBase(mh);
+            long offset = staticOffset(mh);
+            UNSAFE.putReferenceVolatile(base, offset, value);
+        }
+
+        static boolean getBoolean(MethodHandleImpl mh) {
+            Object base = staticBase(mh);
+            long offset = staticOffset(mh);
+            return UNSAFE.getBoolean(base, offset);
+        }
+
+        static boolean getBooleanVolatile(MethodHandleImpl mh) {
+            Object base = staticBase(mh);
+            long offset = staticOffset(mh);
+            return UNSAFE.getBooleanVolatile(base, offset);
+        }
+
+        static byte getByte(MethodHandleImpl mh) {
+            Object base = staticBase(mh);
+            long offset = staticOffset(mh);
+            return UNSAFE.getByte(base, offset);
+        }
+
+        static byte getByteVolatile(MethodHandleImpl mh) {
+            Object base = staticBase(mh);
+            long offset = staticOffset(mh);
+            return UNSAFE.getByteVolatile(base, offset);
+        }
+
+        static char getChar(MethodHandleImpl mh) {
+            Object base = staticBase(mh);
+            long offset = staticOffset(mh);
+            return UNSAFE.getChar(base, offset);
+        }
+
+        static char getCharVolatile(MethodHandleImpl mh) {
+            Object base = staticBase(mh);
+            long offset = staticOffset(mh);
+            return UNSAFE.getCharVolatile(base, offset);
+        }
+
+        static short getShort(MethodHandleImpl mh) {
+            Object base = staticBase(mh);
+            long offset = staticOffset(mh);
+            return UNSAFE.getShort(base, offset);
+        }
+
+        static short getShortVolatile(MethodHandleImpl mh) {
+            Object base = staticBase(mh);
+            long offset = staticOffset(mh);
+            return UNSAFE.getShortVolatile(base, offset);
+        }
+
+        static int getInt(MethodHandleImpl mh) {
+            Object base = staticBase(mh);
+            long offset = staticOffset(mh);
+            return UNSAFE.getInt(base, offset);
+        }
+
+        static int getIntVolatile(MethodHandleImpl mh) {
+            Object base = staticBase(mh);
+            long offset = staticOffset(mh);
+            return UNSAFE.getIntVolatile(base, offset);
+        }
+
+        static long getLong(MethodHandleImpl mh) {
+            Object base = staticBase(mh);
+            long offset = staticOffset(mh);
+            return UNSAFE.getLong(base, offset);
+        }
+
+        static long getLongVolatile(MethodHandleImpl mh) {
+            Object base = staticBase(mh);
+            long offset = staticOffset(mh);
+            return UNSAFE.getLongVolatile(base, offset);
+        }
+
+        static double getDouble(MethodHandleImpl mh) {
+            Object base = staticBase(mh);
+            long offset = staticOffset(mh);
+            return UNSAFE.getDouble(base, offset);
+        }
+
+        static double getDoubleVolatile(MethodHandleImpl mh) {
+            Object base = staticBase(mh);
+            long offset = staticOffset(mh);
+            return UNSAFE.getDoubleVolatile(base, offset);
+        }
+
+        static float getFloat(MethodHandleImpl mh) {
+            Object base = staticBase(mh);
+            long offset = staticOffset(mh);
+            return UNSAFE.getFloat(base, offset);
+        }
+
+        static float getFloatVolatile(MethodHandleImpl mh) {
+            Object base = staticBase(mh);
+            long offset = staticOffset(mh);
+            return UNSAFE.getFloatVolatile(base, offset);
+        }
+
+        static Object getReference(MethodHandleImpl mh) {
+            Object base = staticBase(mh);
+            long offset = staticOffset(mh);
+            return UNSAFE.getReference(base, offset);
+        }
+
+        static Object getReferenceVolatile(MethodHandleImpl mh) {
+            Object base = staticBase(mh);
+            long offset = staticOffset(mh);
+            return UNSAFE.getReferenceVolatile(base, offset);
+        }
+    }
+}
diff --git a/ojluni/src/main/java/java/lang/invoke/MethodHandleImpl.java b/ojluni/src/main/java/java/lang/invoke/MethodHandleImpl.java
index ad09f3e6c24..8a2fa8bf622 100644
--- a/ojluni/src/main/java/java/lang/invoke/MethodHandleImpl.java
+++ b/ojluni/src/main/java/java/lang/invoke/MethodHandleImpl.java
@@ -22,9 +22,12 @@
 package java.lang.invoke;
 
 import java.lang.reflect.Constructor;
+import java.lang.reflect.Field;
 import java.lang.reflect.Member;
 import java.lang.reflect.Method;
 import java.lang.reflect.Modifier;
+import java.util.ArrayList;
+import java.util.List;
 
 // Android-changed: Android specific implementation.
 // The whole class was implemented from scratch for the Android runtime based
@@ -37,11 +40,71 @@ import java.lang.reflect.Modifier;
  * @hide
  */
 public class MethodHandleImpl extends MethodHandle implements Cloneable {
+    // TODO(b/297147201): create separate AccessorMethodHandle class and move target and field
+    // into it.
+    // Used by runtime only.
+    private final long target;
     private Object targetClassOrMethodHandleInfo;
+    Field field;
 
     MethodHandleImpl(long artFieldOrMethod, int handleKind, MethodType type) {
         super(artFieldOrMethod, handleKind, type);
         this.targetClassOrMethodHandleInfo = getMemberInternal().getDeclaringClass();
+        this.target = 0;
+    }
+
+    MethodHandleImpl(Field field, int handleKind, MethodType type) {
+        super(field.getArtField(), handleKind, type);
+        // To make sure that we won't operate on uninitialized fields.
+        // TODO (b/399619087): make initialization lazy.
+        MethodHandleStatics.UNSAFE.ensureClassInitialized(field.getDeclaringClass());
+        this.targetClassOrMethodHandleInfo = getMemberInternal().getDeclaringClass();
+        this.field = field;
+        this.target = resolveTarget(handleKind, field);
+    }
+
+    private static long resolveTarget(int handleKind, Field field) {
+        StringBuilder name = new StringBuilder();
+
+        if (handleKind == MethodHandle.SGET || handleKind == MethodHandle.IGET) {
+            name.append("get");
+        } else if (handleKind == MethodHandle.SPUT || handleKind == MethodHandle.IPUT) {
+            name.append("put");
+        } else {
+            throw new AssertionError("Unexpected handleKind: " + handleKind);
+        }
+
+        Class<?> type = field.getType();
+
+        if (type.isPrimitive()) {
+            String fieldTypeName = type.getName();
+            name.append(Character.toUpperCase(fieldTypeName.charAt(0)));
+            name.append(fieldTypeName.substring(1));
+        } else {
+            name.append("Reference");
+        }
+
+        if (Modifier.isVolatile(field.getModifiers())) {
+            name.append("Volatile");
+        }
+
+        List<Class<?>> signature = new ArrayList<>(3);
+        if (!Modifier.isStatic(field.getModifiers())) {
+            signature.add(Object.class);
+        }
+        if (handleKind == MethodHandle.SPUT || handleKind == MethodHandle.IPUT) {
+            if (type.isPrimitive()) {
+                signature.add(type);
+            } else {
+                signature.add(Object.class);
+            }
+        }
+        signature.add(MethodHandleImpl.class);
+        Method target = DirectMethodHandle.getImplementation(name.toString(), signature);
+        if (target == null) {
+            throw new InternalError("DirectMethodHandle$Holder is missing a method");
+        }
+        return target.getArtMethod();
     }
 
     @Override
diff --git a/ojluni/src/main/java/java/lang/invoke/MethodHandles.java b/ojluni/src/main/java/java/lang/invoke/MethodHandles.java
index 250009ec37f..7bd59b2de6b 100644
--- a/ojluni/src/main/java/java/lang/invoke/MethodHandles.java
+++ b/ojluni/src/main/java/java/lang/invoke/MethodHandles.java
@@ -746,6 +746,7 @@ public class MethodHandles {
                             && !name.equals("java.util.HashMap")
                             && !name.equals("java.util.HashSet")
                             && !name.equals("java.util.WeakHashMap")
+                            && !name.equals("java.lang.runtime.SwitchBootstraps")
                             && !name.startsWith("java.util.stream.")) ||
                         (name.startsWith("sun.")
                                 && !name.startsWith("sun.invoke.")
@@ -1544,7 +1545,7 @@ assertEquals(""+l, (String) MH_this.invokeExact(subl)); // Listie method
                 default:
                     throw new IllegalArgumentException("Invalid kind " + kind);
             }
-            return new MethodHandleImpl(field.getArtField(), kind, methodType);
+            return new MethodHandleImpl(field, kind, methodType);
         }
 
         /**
@@ -2346,12 +2347,25 @@ return mh1;
      */
     public static
     MethodHandle arrayLength(Class<?> arrayClass) throws IllegalArgumentException {
-        // Android-changed: transformer based implementation.
+        // Android-changed: calling static function directly.
         // return MethodHandleImpl.makeArrayElementAccessor(arrayClass, MethodHandleImpl.ArrayAccess.LENGTH);
         if (!arrayClass.isArray()) {
             throw newIllegalArgumentException("not an array class: " + arrayClass.getName());
         }
-        return new Transformers.ArrayLength(arrayClass);
+        Class<?> componentType = arrayClass.getComponentType();
+        Class<?> reducedArrayType = componentType.isPrimitive() ? arrayClass : Object[].class;
+
+        try {
+            Method arrayLength =
+                MethodHandles.class.getDeclaredMethod("arrayLength", reducedArrayType);
+
+            return new MethodHandleImpl(
+                    arrayLength.getArtMethod(),
+                    MethodHandle.INVOKE_STATIC,
+                    MethodType.methodType(int.class, arrayClass));
+        } catch (NoSuchMethodException nsme) {
+            throw new AssertionError(nsme);
+        }
     }
 
     // BEGIN Android-added: method to check if a class is an array.
@@ -2361,6 +2375,16 @@ return mh1;
         }
     }
 
+    private static int arrayLength(byte[] array) { return array.length; }
+    private static int arrayLength(boolean[] array) { return array.length; }
+    private static int arrayLength(char[] array) { return array.length; }
+    private static int arrayLength(short[] array) { return array.length; }
+    private static int arrayLength(int[] array) { return array.length; }
+    private static int arrayLength(long[] array) { return array.length; }
+    private static int arrayLength(float[] array) { return array.length; }
+    private static int arrayLength(double[] array) { return array.length; }
+    private static int arrayLength(Object[] array) { return array.length; }
+
     private static void checkTypeIsViewable(Class<?> componentType) {
         if (componentType == short.class ||
             componentType == char.class ||
@@ -2398,7 +2422,19 @@ return mh1;
             }
         }
 
-        return new Transformers.ReferenceArrayElementGetter(arrayClass);
+        try {
+            // MethodHandle objects can be cached.
+            Method arrayElementGetter =
+                MethodHandles.class.getDeclaredMethod(
+                        "arrayElementGetter", Object[].class, int.class);
+
+            return new MethodHandleImpl(
+                    arrayElementGetter.getArtMethod(),
+                    MethodHandle.INVOKE_STATIC,
+                    MethodType.methodType(componentType, arrayClass, int.class));
+        } catch (NoSuchMethodException nsme) {
+            throw new AssertionError(nsme);
+        }
     }
 
     /** @hide */ public static byte arrayElementGetter(byte[] array, int i) { return array[i]; }
@@ -2409,6 +2445,7 @@ return mh1;
     /** @hide */ public static long arrayElementGetter(long[] array, int i) { return array[i]; }
     /** @hide */ public static float arrayElementGetter(float[] array, int i) { return array[i]; }
     /** @hide */ public static double arrayElementGetter(double[] array, int i) { return array[i]; }
+    private static Object arrayElementGetter(Object[] array, int i) { return array[i]; }
 
     /**
      * Produces a method handle giving write access to elements of an array.
@@ -2434,7 +2471,18 @@ return mh1;
             }
         }
 
-        return new Transformers.ReferenceArrayElementSetter(arrayClass);
+        try {
+            Method arrayElementSetter =
+                MethodHandles.class.getDeclaredMethod(
+                        "arrayElementSetter", Object[].class, int.class, Object.class);
+
+            return new MethodHandleImpl(
+                    arrayElementSetter.getArtMethod(),
+                    MethodHandle.INVOKE_STATIC,
+                    MethodType.methodType(void.class, arrayClass, int.class, componentType));
+        } catch (NoSuchMethodException nsme) {
+            throw new AssertionError(nsme);
+        }
     }
 
     /** @hide */
@@ -2453,6 +2501,7 @@ return mh1;
     public static void arrayElementSetter(float[] array, int i, float val) { array[i] = val; }
     /** @hide */
     public static void arrayElementSetter(double[] array, int i, double val) { array[i] = val; }
+    private static void arrayElementSetter(Object[] array, int i, Object val) { array[i] = val; }
 
     // BEGIN Android-changed: OpenJDK 9+181 VarHandle API factory methods.
     /**
@@ -3821,14 +3870,18 @@ assertEquals("[top, [[up, down, strange], charm], bottom]",
         MethodType targetType = target.type();
         MethodType filterType = filter.type();
         Class<?> rtype = filterType.returnType();
-        List<Class<?>> filterArgs = filterType.parameterList();
+        Class<?>[] filterArgs = filterType.ptypes();
+        if (pos < 0 || (rtype == void.class && pos > targetType.parameterCount()) ||
+                       (rtype != void.class && pos >= targetType.parameterCount())) {
+            throw newIllegalArgumentException("position is out of range for target", target, pos);
+        }
         if (rtype == void.class) {
             return targetType.insertParameterTypes(pos, filterArgs);
         }
         if (rtype != targetType.parameterType(pos)) {
             throw newIllegalArgumentException("target and filter types do not match", targetType, filterType);
         }
-        return targetType.dropParameterTypes(pos, pos+1).insertParameterTypes(pos, filterArgs);
+        return targetType.dropParameterTypes(pos, pos + 1).insertParameterTypes(pos, filterArgs);
     }
 
     /**
diff --git a/ojluni/src/main/java/java/lang/invoke/Transformers.java b/ojluni/src/main/java/java/lang/invoke/Transformers.java
index 57e0967c0a4..82124bf08b5 100644
--- a/ojluni/src/main/java/java/lang/invoke/Transformers.java
+++ b/ojluni/src/main/java/java/lang/invoke/Transformers.java
@@ -32,8 +32,8 @@ import dalvik.system.EmulatedStackFrame.StackFrameAccessor;
 import dalvik.system.EmulatedStackFrame.StackFrameReader;
 import dalvik.system.EmulatedStackFrame.StackFrameWriter;
 
+import jdk.internal.misc.Unsafe;
 import sun.invoke.util.Wrapper;
-import sun.misc.Unsafe;
 
 import java.lang.reflect.Array;
 import java.lang.reflect.Method;
@@ -313,60 +313,6 @@ public class Transformers {
         }
     }
 
-    /** Implements {@code MethodHandles.arrayElementGetter}. */
-    static class ReferenceArrayElementGetter extends Transformer {
-        private final Class<?> arrayClass;
-
-        ReferenceArrayElementGetter(Class<?> arrayClass) {
-            super(
-                    MethodType.methodType(
-                            arrayClass.getComponentType(), new Class<?>[] {arrayClass, int.class}));
-            this.arrayClass = arrayClass;
-        }
-
-        @Override
-        public void transform(EmulatedStackFrame emulatedStackFrame) throws Throwable {
-            final StackFrameReader reader = new StackFrameReader();
-            reader.attach(emulatedStackFrame);
-
-            // Read the array object and the index from the stack frame.
-            final Object[] array = (Object[]) reader.nextReference(arrayClass);
-            final int index = reader.nextInt();
-
-            // Write the array element back to the stack frame.
-            final StackFrameWriter writer = new StackFrameWriter();
-            writer.attach(emulatedStackFrame);
-            writer.makeReturnValueAccessor();
-            writer.putNextReference(array[index], arrayClass.getComponentType());
-        }
-    }
-
-    /** Implements {@code MethodHandles.arrayElementSetter}. */
-    static class ReferenceArrayElementSetter extends Transformer {
-        private final Class<?> arrayClass;
-
-        ReferenceArrayElementSetter(Class<?> arrayClass) {
-            super(
-                    MethodType.methodType(
-                            void.class,
-                            new Class<?>[] {arrayClass, int.class, arrayClass.getComponentType()}));
-            this.arrayClass = arrayClass;
-        }
-
-        @Override
-        public void transform(EmulatedStackFrame emulatedStackFrame) throws Throwable {
-            final StackFrameReader reader = new StackFrameReader();
-            reader.attach(emulatedStackFrame);
-
-            // Read the array object, index and the value to write from the stack frame.
-            final Object[] array = (Object[]) reader.nextReference(arrayClass);
-            final int index = reader.nextInt();
-            final Object value = reader.nextReference(arrayClass.getComponentType());
-
-            array[index] = value;
-        }
-    }
-
     /** Implements {@code MethodHandles.identity}. */
     static class ReferenceIdentity extends Transformer {
         private final Class<?> type;
@@ -419,60 +365,6 @@ public class Transformers {
         }
     }
 
-    /** Implements {@code MethodHandles.arrayLength}. */
-    static class ArrayLength extends Transformer {
-        private final Class<?> arrayType;
-
-        ArrayLength(Class<?> arrayType) {
-            super(MethodType.methodType(int.class, arrayType));
-            this.arrayType = arrayType;
-        }
-
-        @Override
-        public void transform(EmulatedStackFrame emulatedStackFrame) throws Throwable {
-            final StackFrameReader reader = new StackFrameReader();
-            reader.attach(emulatedStackFrame);
-            final Object arrayObject = reader.nextReference(arrayType);
-
-            int length;
-            switch (Wrapper.basicTypeChar(arrayType.getComponentType())) {
-                case 'L':
-                    length = ((Object[]) arrayObject).length;
-                    break;
-                case 'Z':
-                    length = ((boolean[]) arrayObject).length;
-                    break;
-                case 'B':
-                    length = ((byte[]) arrayObject).length;
-                    break;
-                case 'C':
-                    length = ((char[]) arrayObject).length;
-                    break;
-                case 'S':
-                    length = ((short[]) arrayObject).length;
-                    break;
-                case 'I':
-                    length = ((int[]) arrayObject).length;
-                    break;
-                case 'J':
-                    length = ((long[]) arrayObject).length;
-                    break;
-                case 'F':
-                    length = ((float[]) arrayObject).length;
-                    break;
-                case 'D':
-                    length = ((double[]) arrayObject).length;
-                    break;
-                default:
-                    throw new IllegalStateException("Unsupported type: " + arrayType);
-            }
-
-            final StackFrameWriter writer = new StackFrameWriter();
-            writer.attach(emulatedStackFrame).makeReturnValueAccessor();
-            writer.putNextInt(length);
-        }
-    }
-
     /** Implements {@code MethodHandles.createMethodHandleForConstructor}. */
     static class Construct extends Transformer {
         private final MethodHandle constructorHandle;
diff --git a/ojluni/src/main/java/java/lang/invoke/VarHandle.java b/ojluni/src/main/java/java/lang/invoke/VarHandle.java
index 9bd81b4563a..befbc05d75a 100644
--- a/ojluni/src/main/java/java/lang/invoke/VarHandle.java
+++ b/ojluni/src/main/java/java/lang/invoke/VarHandle.java
@@ -440,8 +440,8 @@ import java.util.Objects;
  * @since 9
  */
 public abstract class VarHandle {
-    // Android-added: Using sun.misc.Unsafe for fence implementation.
-    private static final sun.misc.Unsafe UNSAFE = sun.misc.Unsafe.getUnsafe();
+    // Android-added: Using jdk.internal.misc.Unsafe for fence implementation.
+    private static final jdk.internal.misc.Unsafe UNSAFE = jdk.internal.misc.Unsafe.getUnsafe();
 
     // BEGIN Android-removed: No VarForm in Android implementation.
     /*
@@ -2238,10 +2238,16 @@ public abstract class VarHandle {
     // END Android-added: package private constructors.
 
     // BEGIN Android-added: helper state for VarHandle properties.
+    /*
+     * Shift values belows are ordinals of AccessMode enum values. They are inlined to break
+     * initialization cycle: Enum uses ClassValue, which uses AtomicInteger class, which is
+     * implemented on top of VarHandles.
+     * See VarHandleTest.
+     */
 
     /** BitMask of access modes that do not change the memory referenced by a VarHandle.
      * An example being a read of a variable with volatile ordering effects. */
-    private final static int READ_ACCESS_MODES_BIT_MASK;
+    private final static int READ_ACCESS_MODES_BIT_MASK = 1 << 0 | 1 << 2 | 1 << 4 | 1 << 6;
 
     /** BitMask of access modes that write to the memory referenced by
      * a VarHandle.  This does not include any compare and update
@@ -2249,65 +2255,52 @@ public abstract class VarHandle {
      * example being a write to variable with release ordering
      * effects.
      */
-    private final static int WRITE_ACCESS_MODES_BIT_MASK;
+    private final static int WRITE_ACCESS_MODES_BIT_MASK = 1 << 1 | 1 << 3 | 1 << 5 | 1 << 7;
 
     /** BitMask of access modes that are applicable to types
      * supporting for atomic updates.  This includes access modes that
      * both read and write a variable such as compare-and-set.
      */
-    private final static int ATOMIC_UPDATE_ACCESS_MODES_BIT_MASK;
+    private final static int ATOMIC_UPDATE_ACCESS_MODES_BIT_MASK =
+        1 << 8  |
+        1 << 9  |
+        1 << 10 |
+        1 << 11 |
+        1 << 12 |
+        1 << 13 |
+        1 << 14 |
+        1 << 15 |
+        1 << 16 |
+        1 << 17 |
+        1 << 18;
 
     /** BitMask of access modes that are applicable to types
      * supporting numeric atomic update operations. */
-    private final static int NUMERIC_ATOMIC_UPDATE_ACCESS_MODES_BIT_MASK;
+    private final static int NUMERIC_ATOMIC_UPDATE_ACCESS_MODES_BIT_MASK =
+        1 << 19 |
+        1 << 20 |
+        1 << 21;
 
     /** BitMask of access modes that are applicable to types
      * supporting bitwise atomic update operations. */
-    private final static int BITWISE_ATOMIC_UPDATE_ACCESS_MODES_BIT_MASK;
+    private final static int BITWISE_ATOMIC_UPDATE_ACCESS_MODES_BIT_MASK =
+        1 << 22 |
+        1 << 23 |
+        1 << 24 |
+        1 << 25 |
+        1 << 26 |
+        1 << 27 |
+        1 << 28 |
+        1 << 29 |
+        1 << 30;
 
     /** BitMask of all access modes. */
-    private final static int ALL_MODES_BIT_MASK;
-
-    static {
-        // Check we're not about to overflow the storage of the
-        // bitmasks here and in the accessModesBitMask field.
-        if (AccessMode.values().length > Integer.SIZE) {
-            throw new InternalError("accessModes overflow");
-        }
-
-        // Access modes bit mask declarations and initialization order
-        // follows the presentation order in JEP193.
-        READ_ACCESS_MODES_BIT_MASK = accessTypesToBitMask(EnumSet.of(AccessType.GET));
-
-        WRITE_ACCESS_MODES_BIT_MASK = accessTypesToBitMask(EnumSet.of(AccessType.SET));
-
-        ATOMIC_UPDATE_ACCESS_MODES_BIT_MASK =
-                accessTypesToBitMask(EnumSet.of(AccessType.COMPARE_AND_EXCHANGE,
-                                                AccessType.COMPARE_AND_SET,
-                                                AccessType.GET_AND_UPDATE));
-
-        NUMERIC_ATOMIC_UPDATE_ACCESS_MODES_BIT_MASK =
-                accessTypesToBitMask(EnumSet.of(AccessType.GET_AND_UPDATE_NUMERIC));
-
-        BITWISE_ATOMIC_UPDATE_ACCESS_MODES_BIT_MASK =
-                accessTypesToBitMask(EnumSet.of(AccessType.GET_AND_UPDATE_BITWISE));
-
-        ALL_MODES_BIT_MASK = (READ_ACCESS_MODES_BIT_MASK |
-                              WRITE_ACCESS_MODES_BIT_MASK |
-                              ATOMIC_UPDATE_ACCESS_MODES_BIT_MASK |
-                              NUMERIC_ATOMIC_UPDATE_ACCESS_MODES_BIT_MASK |
-                              BITWISE_ATOMIC_UPDATE_ACCESS_MODES_BIT_MASK);
-    }
-
-    static int accessTypesToBitMask(final EnumSet<AccessType> accessTypes) {
-        int m = 0;
-        for (AccessMode accessMode : AccessMode.values()) {
-            if (accessTypes.contains(accessMode.at)) {
-                m |= 1 << accessMode.ordinal();
-            }
-        }
-        return m;
-    }
+    private final static int ALL_MODES_BIT_MASK =
+            READ_ACCESS_MODES_BIT_MASK |
+            WRITE_ACCESS_MODES_BIT_MASK |
+            ATOMIC_UPDATE_ACCESS_MODES_BIT_MASK |
+            NUMERIC_ATOMIC_UPDATE_ACCESS_MODES_BIT_MASK |
+            BITWISE_ATOMIC_UPDATE_ACCESS_MODES_BIT_MASK;
 
     static int alignedAccessModesBitMask(Class<?> varType, boolean isFinal) {
         // For aligned accesses, the supported access modes are described in:
diff --git a/ojluni/src/main/java/java/lang/runtime/ObjectMethods.java b/ojluni/src/main/java/java/lang/runtime/ObjectMethods.java
index baad8fa8c08..c8ba19ba65e 100644
--- a/ojluni/src/main/java/java/lang/runtime/ObjectMethods.java
+++ b/ojluni/src/main/java/java/lang/runtime/ObjectMethods.java
@@ -37,6 +37,8 @@ import java.util.HashMap;
 import java.util.List;
 import java.util.Objects;
 
+import static java.util.Objects.requireNonNull;
+
 /**
  * Bootstrap methods for state-driven implementations of core methods,
  * including {@link Object#equals(Object)}, {@link Object#hashCode()}, and
@@ -334,6 +336,13 @@ public class ObjectMethods {
                                    Class<?> recordClass,
                                    String names,
                                    MethodHandle... getters) throws Throwable {
+        // Android-changed: nullchecks are from Java 21.
+        requireNonNull(lookup);
+        requireNonNull(methodName);
+        requireNonNull(type);
+        requireNonNull(recordClass);
+        requireNonNull(names);
+        requireNonNull(getters);
         MethodType methodType;
         if (type instanceof MethodType)
             methodType = (MethodType) type;
diff --git a/ojluni/src/main/java/java/lang/runtime/SwitchBootstraps.java b/ojluni/src/main/java/java/lang/runtime/SwitchBootstraps.java
index 092c728e156..6810fa6222d 100644
--- a/ojluni/src/main/java/java/lang/runtime/SwitchBootstraps.java
+++ b/ojluni/src/main/java/java/lang/runtime/SwitchBootstraps.java
@@ -46,8 +46,6 @@ import static java.util.Objects.requireNonNull;
  * of the {@code switch}, implicitly numbered sequentially from {@code [0..N)}.
  *
  * @since 21
- *
- * @hide
  */
 public class SwitchBootstraps {
 
@@ -142,8 +140,6 @@ public class SwitchBootstraps {
      * {@code Integer}, {@code Class} or {@code EnumDesc}.
      * @jvms 4.4.6 The CONSTANT_NameAndType_info Structure
      * @jvms 4.4.10 The CONSTANT_Dynamic_info and CONSTANT_InvokeDynamic_info Structures
-     *
-     * @hide
      */
     public static CallSite typeSwitch(MethodHandles.Lookup lookup,
                                       String invocationName,
@@ -309,8 +305,6 @@ public class SwitchBootstraps {
      * {@code Class} of the target enum type.
      * @jvms 4.4.6 The CONSTANT_NameAndType_info Structure
      * @jvms 4.4.10 The CONSTANT_Dynamic_info and CONSTANT_InvokeDynamic_info Structures
-     *
-     * @hide
      */
     public static CallSite enumSwitch(MethodHandles.Lookup lookup,
                                       String invocationName,
diff --git a/ojluni/src/main/java/java/math/BigDecimal.java b/ojluni/src/main/java/java/math/BigDecimal.java
index fe33c5f55d7..48859fdcbdc 100644
--- a/ojluni/src/main/java/java/math/BigDecimal.java
+++ b/ojluni/src/main/java/java/math/BigDecimal.java
@@ -4276,13 +4276,13 @@ public class BigDecimal extends Number implements Comparable<BigDecimal> {
     }
 
     private static class UnsafeHolder {
-        private static final sun.misc.Unsafe unsafe;
+        private static final jdk.internal.misc.Unsafe unsafe;
         private static final long intCompactOffset;
         private static final long intValOffset;
         private static final long scaleOffset;
         static {
             try {
-                unsafe = sun.misc.Unsafe.getUnsafe();
+                unsafe = jdk.internal.misc.Unsafe.getUnsafe();
                 intCompactOffset = unsafe.objectFieldOffset
                     (BigDecimal.class.getDeclaredField("intCompact"));
                 intValOffset = unsafe.objectFieldOffset
diff --git a/ojluni/src/main/java/java/math/BigInteger.java b/ojluni/src/main/java/java/math/BigInteger.java
index 20fee1d589b..3e04f892b28 100644
--- a/ojluni/src/main/java/java/math/BigInteger.java
+++ b/ojluni/src/main/java/java/math/BigInteger.java
@@ -4912,12 +4912,12 @@ public class BigInteger extends Number implements Comparable<BigInteger> {
 
     // Support for resetting final fields while deserializing
     private static class UnsafeHolder {
-        private static final sun.misc.Unsafe unsafe;
+        private static final jdk.internal.misc.Unsafe unsafe;
         private static final long signumOffset;
         private static final long magOffset;
         static {
             try {
-                unsafe = sun.misc.Unsafe.getUnsafe();
+                unsafe = jdk.internal.misc.Unsafe.getUnsafe();
                 signumOffset = unsafe.objectFieldOffset
                     (BigInteger.class.getDeclaredField("signum"));
                 magOffset = unsafe.objectFieldOffset
diff --git a/ojluni/src/main/java/java/net/Inet6Address.java b/ojluni/src/main/java/java/net/Inet6Address.java
index a8c751005d8..41138ed836b 100644
--- a/ojluni/src/main/java/java/net/Inet6Address.java
+++ b/ojluni/src/main/java/java/net/Inet6Address.java
@@ -608,11 +608,11 @@ class Inet6Address extends InetAddress {
     };
 
     private static final long FIELDS_OFFSET;
-    private static final sun.misc.Unsafe UNSAFE;
+    private static final jdk.internal.misc.Unsafe UNSAFE;
 
     static {
         try {
-            sun.misc.Unsafe unsafe = sun.misc.Unsafe.getUnsafe();
+            jdk.internal.misc.Unsafe unsafe = jdk.internal.misc.Unsafe.getUnsafe();
             FIELDS_OFFSET = unsafe.objectFieldOffset(
                     Inet6Address.class.getDeclaredField("holder6"));
             UNSAFE = unsafe;
diff --git a/ojluni/src/main/java/java/nio/DirectByteBuffer.java b/ojluni/src/main/java/java/nio/DirectByteBuffer.java
index 40923eaae4d..717c2f4dc36 100644
--- a/ojluni/src/main/java/java/nio/DirectByteBuffer.java
+++ b/ojluni/src/main/java/java/nio/DirectByteBuffer.java
@@ -272,6 +272,18 @@ public class DirectByteBuffer extends MappedByteBuffer implements DirectBuffer {
         return this;
     }
 
+    @Override
+    public ByteBuffer get(int index, byte[] dst, int dstOffset, int length) {
+        if (!memoryRef.isAccessible) {
+            throw new IllegalStateException("buffer is inaccessible");
+        }
+        checkBounds(index, length, limit());
+        checkBounds(dstOffset, length, dst.length);
+        Memory.peekByteArray(ix(index),
+                dst, dstOffset, length);
+        return this;
+    }
+
     private ByteBuffer put(long a, byte x) {
         Memory.pokeByte(a, x);
         return this;
diff --git a/ojluni/src/main/java/java/time/Duration.java b/ojluni/src/main/java/java/time/Duration.java
index 48f46ffa596..78fe631d47a 100644
--- a/ojluni/src/main/java/java/time/Duration.java
+++ b/ojluni/src/main/java/java/time/Duration.java
@@ -563,6 +563,20 @@ public final class Duration
     }
 
     //-----------------------------------------------------------------------
+    /**
+     * Checks if this duration is positive, excluding zero.
+     * <p>
+     * A {@code Duration} represents a directed distance between two points on
+     * the time-line and can therefore be positive, zero or negative.
+     * This method checks whether the length is greater than zero.
+     *
+     * @return true if this duration has a total length greater than zero
+     * @since 18
+     */
+    public boolean isPositive() {
+        return (seconds | nanos) > 0;
+    }
+
     /**
      * Checks if this duration is zero length.
      * <p>
diff --git a/ojluni/src/main/java/java/util/ReverseOrderSortedMapView.java b/ojluni/src/main/java/java/util/ReverseOrderSortedMapView.java
index 404950e8fd5..4da5b697b15 100644
--- a/ojluni/src/main/java/java/util/ReverseOrderSortedMapView.java
+++ b/ojluni/src/main/java/java/util/ReverseOrderSortedMapView.java
@@ -158,10 +158,12 @@ class ReverseOrderSortedMapView<K, V> extends AbstractMap<K, V> implements Sorte
         return base.pollFirstEntry();
     }
 
+    @SuppressWarnings("DoNotCall")
     public V putFirst(K k, V v) {
         return base.putLast(k, v);
     }
 
+    @SuppressWarnings("DoNotCall")
     public V putLast(K k, V v) {
         return base.putFirst(k, v);
     }
diff --git a/ojluni/src/main/java/java/util/zip/ZipCoder.java b/ojluni/src/main/java/java/util/zip/ZipCoder.java
index 450d7a6f451..12dc02186e4 100644
--- a/ojluni/src/main/java/java/util/zip/ZipCoder.java
+++ b/ojluni/src/main/java/java/util/zip/ZipCoder.java
@@ -27,6 +27,7 @@ package java.util.zip;
 
 import java.nio.ByteBuffer;
 import java.nio.CharBuffer;
+import java.nio.DirectByteBuffer;
 import java.nio.charset.Charset;
 import java.nio.charset.CharsetDecoder;
 import java.nio.charset.CharsetEncoder;
@@ -74,6 +75,15 @@ class ZipCoder {
         return toString(ba, 0, ba.length);
     }
 
+    // Android-changed: don't keep CEN bytes in heap memory after initialization.
+    String toString(DirectByteBuffer bb, int off, int length) {
+        try {
+            return decoder().decode(bb.slice(off, length)).toString();
+        } catch (CharacterCodingException x) {
+            throw new IllegalArgumentException(x);
+        }
+    }
+
     byte[] getBytes(String s) {
         try {
             ByteBuffer bb = encoder().encode(CharBuffer.wrap(s));
@@ -143,6 +153,18 @@ class ZipCoder {
             Arrays.mismatch(a, end - slashBytes.length, end, slashBytes, 0, slashBytes.length) == -1;
     }
 
+    // Android-changed: don't keep CEN bytes in heap memory after initialization.
+    boolean hasTrailingSlash(DirectByteBuffer bb, int end) {
+        byte[] slashBytes = slashBytes();
+        for (int i = end - slashBytes.length; i < end; i++) {
+            byte b = bb.get(i);
+            if (b != slashBytes[i - end + slashBytes.length]) {
+                return false;
+            }
+        }
+        return true;
+    }
+
     private byte[] slashBytes;
     private final Charset cs;
     protected CharsetDecoder dec;
@@ -205,6 +227,16 @@ class ZipCoder {
             return new String(ba, off, length, StandardCharsets.UTF_8);
         }
 
+        // Android-changed: don't keep CEN bytes in heap memory after initialization.
+        @Override
+        String toString(DirectByteBuffer bb, int off, int length) {
+            byte[] bytes = new byte[length];
+            bb.get(off, bytes, 0, length);
+            // Android-changed: JLA is not yet available.
+            // return JLA.newStringUTF8NoRepl(ba, off, length);
+            return new String(bytes, 0, length, StandardCharsets.UTF_8);
+        }
+
         @Override
         byte[] getBytes(String s) {
             // Android-changed: JLA is not yet available.
@@ -248,5 +280,11 @@ class ZipCoder {
         boolean hasTrailingSlash(byte[] a, int end) {
             return end > 0 && a[end - 1] == '/';
         }
+
+        // Android-changed: don't keep CEN bytes in heap memory after initialization.
+        @Override
+        boolean hasTrailingSlash(DirectByteBuffer bb, int end) {
+            return end > 0 && bb.get(end - 1) == '/';
+        }
     }
 }
diff --git a/ojluni/src/main/java/java/util/zip/ZipFile.java b/ojluni/src/main/java/java/util/zip/ZipFile.java
index 9991b31bd50..8f60561b1bd 100644
--- a/ojluni/src/main/java/java/util/zip/ZipFile.java
+++ b/ojluni/src/main/java/java/util/zip/ZipFile.java
@@ -35,6 +35,10 @@ import java.io.FileNotFoundException;
 import java.io.RandomAccessFile;
 import java.io.UncheckedIOException;
 import java.lang.ref.Cleaner.Cleanable;
+import java.nio.DirectByteBuffer;
+import java.nio.ByteOrder;
+import java.nio.channels.FileChannel;
+import java.nio.channels.FileChannel.MapMode;
 import java.nio.charset.CharacterCodingException;
 import java.nio.charset.Charset;
 import java.nio.charset.StandardCharsets;
@@ -69,6 +73,7 @@ import jdk.internal.access.SharedSecrets;
 import jdk.internal.misc.VM;
 import jdk.internal.ref.CleanerFactory;
 import jdk.internal.vm.annotation.Stable;
+import sun.misc.Cleaner;
 import sun.security.util.SignatureFileVerifier;
 
 import dalvik.system.CloseGuard;
@@ -631,7 +636,9 @@ public class ZipFile implements ZipConstants, Closeable {
     }
 
     private String getEntryName(int pos) {
-        byte[] cen = res.zsrc.cen;
+        // Android-changed: don't keep CEN bytes in heap memory after initialization.
+        //byte[] cen = res.zsrc.cen;
+        DirectByteBuffer cen = res.zsrc.cen;
         int nlen = CENNAM(cen, pos);
         ZipCoder zc = res.zsrc.zipCoderForPos(pos);
         return zc.toString(cen, pos + CENHDR, nlen);
@@ -678,7 +685,9 @@ public class ZipFile implements ZipConstants, Closeable {
 
     /* Check ensureOpen() before invoking this method */
     private ZipEntry getZipEntry(String name, int pos) {
-        byte[] cen = res.zsrc.cen;
+        // Android-changed: don't keep CEN bytes in heap memory after initialization.
+        //byte[] cen = res.zsrc.cen;
+        DirectByteBuffer cen = res.zsrc.cen;
         int nlen = CENNAM(cen, pos);
         int elen = CENEXT(cen, pos);
         int clen = CENCOM(cen, pos);
@@ -718,7 +727,12 @@ public class ZipFile implements ZipConstants, Closeable {
 
         if (elen != 0) {
             int start = pos + CENHDR + nlen;
-            e.setExtra0(Arrays.copyOfRange(cen, start, start + elen), true, false);
+            // BEGIN Android-changed: don't keep CEN bytes in heap memory after initialization.
+            //e.setExtra0(Arrays.copyOfRange(cen, start, start + elen), true, false);
+            byte[] bytes = new byte[elen];
+            cen.get(start, bytes, 0, elen);
+            e.setExtra0(bytes, true, false);
+            // END Android-changed: don't keep CEN bytes in heap memory after initialization.
         }
         if (clen != 0) {
             int start = pos + CENHDR + nlen + elen;
@@ -918,7 +932,9 @@ public class ZipFile implements ZipConstants, Closeable {
         protected long rem;     // number of remaining bytes within entry
         protected long size;    // uncompressed size of this entry
 
-        ZipFileInputStream(byte[] cen, int cenpos) {
+        // Android-changed: don't keep CEN bytes in heap memory after initialization.
+        //ZipFileInputStream(byte[] cen, int cenpos) {
+        ZipFileInputStream(DirectByteBuffer cen, int cenpos) {
             rem = CENSIZ(cen, cenpos);
             size = CENLEN(cen, cenpos);
             pos = CENOFF(cen, cenpos);
@@ -931,7 +947,9 @@ public class ZipFile implements ZipConstants, Closeable {
             pos = - (pos + ZipFile.this.res.zsrc.locpos);
         }
 
-        private void checkZIP64(byte[] cen, int cenpos) {
+        // Android-changed: don't keep CEN bytes in heap memory after initialization.
+        //private void checkZIP64(byte[] cen, int cenpos) {
+        private void checkZIP64(DirectByteBuffer cen, int cenpos) {
             int off = cenpos + CENHDR + CENNAM(cen, cenpos);
             int end = off + CENEXT(cen, cenpos);
             while (off + 4 < end) {
@@ -1228,7 +1246,9 @@ public class ZipFile implements ZipConstants, Closeable {
         private int refs = 1;
 
         private RandomAccessFile zfile;      // zfile of the underlying zip file
-        private byte[] cen;                  // CEN & ENDHDR
+        private DirectByteBuffer cen;        // CEN & ENDHDR
+        private int cenlen;                  // length of CEN & ENDHDR
+        private long cenpos;                 // position of CEN & ENDHDR
         private long locpos;                 // position of first LOC header (usually 0)
         private byte[] comment;              // zip file comment
                                              // list of meta entries in META-INF dir
@@ -1260,10 +1280,13 @@ public class ZipFile implements ZipConstants, Closeable {
 
         // Checks the entry at offset pos in the CEN, calculates the Entry values as per above,
         // then returns the length of the entry name.
-        private int checkAndAddEntry(int pos, int index)
+        // Android-changed: don't keep CEN bytes in heap memory after initialization.
+        //private int checkAndAddEntry(int pos, int index)
+        private int checkAndAddEntry(byte[] cen, int pos, int index)
             throws ZipException
         {
-            byte[] cen = this.cen;
+            // Android-changed: don't keep CEN bytes in heap memory after initialization.
+            //byte[] cen = this.cen;
             if (CENSIG(cen, pos) != CENSIG) {
                 zerror("invalid CEN header (bad signature)");
             }
@@ -1281,7 +1304,7 @@ public class ZipFile implements ZipConstants, Closeable {
                 zerror("invalid CEN header (bad header size)");
             }
             try {
-                ZipCoder zcp = zipCoderForPos(pos);
+                ZipCoder zcp = zipCoderForPos(cen, pos);
                 int hash = zcp.checkedHash(cen, entryPos, nlen);
                 int hsh = (hash & 0x7fffffff) % tablelen;
                 int next = table[hsh];
@@ -1435,7 +1458,7 @@ public class ZipFile implements ZipConstants, Closeable {
                 this.zfile = new RandomAccessFile(key.file, "r", /* setCloExecFlag= */ true);
             }
             try {
-                initCEN(-1);
+                initCEN(null, -1);
                 byte[] buf = new byte[4];
                 readFullyAt(buf, 0, 4, 0);
                 // BEGIN Android-changed: do not accept files with invalid header
@@ -1461,7 +1484,13 @@ public class ZipFile implements ZipConstants, Closeable {
         private void close() throws IOException {
             zfile.close();
             zfile = null;
-            cen = null;
+            if (cen != null) {
+                Cleaner cleaner = cen.cleaner();
+                if (cleaner != null) {
+                    cleaner.clean();
+                }
+                cen = null;
+            }
             entries = null;
             table = null;
             manifestPos = -1;
@@ -1604,9 +1633,12 @@ public class ZipFile implements ZipConstants, Closeable {
         }
 
         // Reads zip file central directory.
-        private void initCEN(int knownTotal) throws IOException {
+        // BEGIN Android-changed: don't keep CEN bytes in heap memory after initialization.
+        //private void initCEN(int knownTotal) throws IOException {
+        private void initCEN(byte[] cen, int knownTotal) throws IOException {
             // Prefer locals for better performance during startup
-            byte[] cen;
+            //byte[] cen;
+            // END Android-changed: don't keep CEN bytes in heap memory after initialization.
             if (knownTotal == -1) {
                 End end = findEND();
                 if (end.endpos == 0) {
@@ -1618,7 +1650,8 @@ public class ZipFile implements ZipConstants, Closeable {
                 }
                 if (end.cenlen > end.endpos)
                     zerror("invalid END header (bad central directory size)");
-                long cenpos = end.endpos - end.cenlen;     // position of CEN table
+                // Android-changed: don't keep CEN bytes in heap memory after initialization.
+                /*long */cenpos = end.endpos - end.cenlen;     // position of CEN table
                 // Get position of first local file (LOC) header, taking into
                 // account that there may be a stub prefixed to the zip file.
                 locpos = cenpos - end.cenoff;
@@ -1626,13 +1659,19 @@ public class ZipFile implements ZipConstants, Closeable {
                     zerror("invalid END header (bad central directory offset)");
                 }
                 // read in the CEN and END
-                cen = this.cen = new byte[(int)(end.cenlen + ENDHDR)];
-                if (readFullyAt(cen, 0, cen.length, cenpos) != end.cenlen + ENDHDR) {
-                    zerror("read CEN tables failed");
-                }
+                // BEGIN Android-changed: don't keep CEN bytes in heap memory after initialization.
+                // cen = this.cen = new byte[(int)(end.cenlen + ENDHDR)];
+                cenlen = (int) (end.cenlen + ENDHDR);
+                DirectByteBuffer cenBuf = this.cen = (DirectByteBuffer) zfile.getChannel()
+                        .map(MapMode.READ_ONLY, cenpos, cenlen);
+                cenBuf.order(ByteOrder.LITTLE_ENDIAN);
+                cen = new byte[cenlen];
+                cenBuf.get(0, cen, 0, cenlen);
+                // END Android-changed: don't keep CEN bytes in heap memory after initialization.
                 this.total = end.centot;
             } else {
-                cen = this.cen;
+                // Android-changed: don't keep CEN bytes in heap memory after initialization.
+                //cen = this.cen;
                 this.total = knownTotal;
             }
             // hash table for entries
@@ -1656,7 +1695,9 @@ public class ZipFile implements ZipConstants, Closeable {
             int idx = 0; // Index into the entries array
             int pos = 0;
             int entryPos = CENHDR;
-            int limit = cen.length - ENDHDR;
+            // Android-changed: don't keep CEN bytes in heap memory after initialization.
+            //int limit = cen.length - ENDHDR;
+            int limit = cenlen - ENDHDR;
             manifestNum = 0;
             // Android-added: duplicate entries are not allowed. See CVE-2013-4787 and b/8219321
             Set<String> entriesNames = new HashSet<>();
@@ -1665,17 +1706,17 @@ public class ZipFile implements ZipConstants, Closeable {
                     // This will only happen if the zip file has an incorrect
                     // ENDTOT field, which usually means it contains more than
                     // 65535 entries.
-                    initCEN(countCENHeaders(cen, limit));
+                    initCEN(cen, countCENHeaders(cen, limit));
                     return;
                 }
 
                 // Checks the entry and adds values to entries[idx ... idx+2]
-                int nlen = checkAndAddEntry(pos, idx);
+                int nlen = checkAndAddEntry(cen, pos, idx);
 
                 // BEGIN Android-added: duplicate entries are not allowed. See CVE-2013-4787
                 // and b/8219321.
                 // zipCoderForPos takes USE_UTF8 flag into account.
-                ZipCoder zcp = zipCoderForPos(entryPos);
+                ZipCoder zcp = zipCoderForPos(cen, entryPos);
                 String name = zcp.toString(cen, pos + CENHDR, nlen);
                 if (!entriesNames.add(name)) {
                     zerror("Duplicate entry name: " + name);
@@ -1702,11 +1743,11 @@ public class ZipFile implements ZipConstants, Closeable {
                 // Adds name to metanames.
                 if (isMetaName(cen, entryPos, nlen)) {
                     // nlen is at least META_INF_LENGTH
-                    if (isManifestName(entryPos + META_INF_LEN, nlen - META_INF_LEN)) {
+                    if (isManifestName(cen, entryPos + META_INF_LEN, nlen - META_INF_LEN)) {
                         manifestPos = pos;
                         manifestNum++;
                     } else {
-                        if (isSignatureRelated(entryPos, nlen)) {
+                        if (isSignatureRelated(cen, entryPos, nlen)) {
                             if (signatureNames == null)
                                 signatureNames = new ArrayList<>(4);
                             signatureNames.add(pos);
@@ -1715,7 +1756,7 @@ public class ZipFile implements ZipConstants, Closeable {
                         // If this is a versioned entry, parse the version
                         // and store it for later. This optimizes lookup
                         // performance in multi-release jar files
-                        int version = getMetaVersion(entryPos + META_INF_LEN, nlen - META_INF_LEN);
+                        int version = getMetaVersion(cen, entryPos + META_INF_LEN, nlen - META_INF_LEN);
                         if (version > 0) {
                             if (metaVersionsSet == null)
                                 metaVersionsSet = new TreeSet<>();
@@ -1724,7 +1765,7 @@ public class ZipFile implements ZipConstants, Closeable {
                     }
                 }
                 // skip to the start of the next entry
-                pos = nextEntryPos(pos, entryPos, nlen);
+                pos = nextEntryPos(cen, pos, entryPos, nlen);
                 entryPos = pos + CENHDR;
             }
 
@@ -1752,7 +1793,9 @@ public class ZipFile implements ZipConstants, Closeable {
             }
         }
 
-        private int nextEntryPos(int pos, int entryPos, int nlen) {
+        // Android-changed: don't keep CEN bytes in heap memory after initialization.
+        //private int nextEntryPos(byte[] cen, int pos, int entryPos, int nlen) {
+        private int nextEntryPos(byte[] cen, int pos, int entryPos, int nlen) {
             return entryPos + nlen + CENCOM(cen, pos) + CENEXT(cen, pos);
         }
 
@@ -1814,6 +1857,17 @@ public class ZipFile implements ZipConstants, Closeable {
             return zc;
         }
 
+        // Android-changed: don't keep CEN bytes in heap memory after initialization.
+        private ZipCoder zipCoderForPos(byte[] cen, int pos) {
+            if (zc.isUTF8()) {
+                return zc;
+            }
+            if ((CENFLG(cen, pos) & USE_UTF8) != 0) {
+                return ZipCoder.UTF8;
+            }
+            return zc;
+        }
+
         /**
          * Returns true if the bytes represent a non-directory name
          * beginning with "META-INF/", disregarding ASCII case.
@@ -1837,8 +1891,9 @@ public class ZipFile implements ZipConstants, Closeable {
         /*
          * Check if the bytes represents a name equals to MANIFEST.MF
          */
-        private boolean isManifestName(int off, int len) {
-            byte[] name = cen;
+        // Android-changed: don't keep CEN bytes in heap memory after initialization.
+        //private boolean isManifestName(int off, int len) {
+        private boolean isManifestName(byte[] name, int off, int len) {
             return (len == 11 // "MANIFEST.MF".length()
                     && (name[off++] | 0x20) == 'm'
                     && (name[off++] | 0x20) == 'a'
@@ -1853,12 +1908,15 @@ public class ZipFile implements ZipConstants, Closeable {
                     && (name[off]   | 0x20) == 'f');
         }
 
-        private boolean isSignatureRelated(int off, int len) {
+        // Android-changed: don't keep CEN bytes in heap memory after initialization.
+        //private boolean isSignatureRelated(int off, int len) {
+        private boolean isSignatureRelated(byte[] name, int off, int len) {
             // Only called when isMetaName(name, off, len) is true, which means
             // len is at least META_INF_LENGTH
             // assert isMetaName(name, off, len)
             boolean signatureRelated = false;
-            byte[] name = cen;
+            // Android-changed: don't keep CEN bytes in heap memory after initialization.
+            //byte[] name = cen;
             if (name[off + len - 3] == '.') {
                 // Check if entry ends with .EC and .SF
                 int b1 = name[off + len - 2] | 0x20;
@@ -1890,8 +1948,11 @@ public class ZipFile implements ZipConstants, Closeable {
          * followed by a '/', then return that integer value.
          * Otherwise, return 0
          */
-        private int getMetaVersion(int off, int len) {
-            byte[] name = cen;
+        // BEGIN Android-changed: don't keep CEN bytes in heap memory after initialization.
+        //private int getMetaVersion(int off, int len) {
+        private int getMetaVersion(byte[] name, int off, int len) {
+            //byte[] name = cen;
+            // END Android-changed: don't keep CEN bytes in heap memory after initialization.
             int nend = off + len;
             if (!(len > 10                         // "versions//".length()
                     && name[off + len - 1] != '/'  // non-directory
diff --git a/ojluni/src/main/java/java/util/zip/ZipUtils.java b/ojluni/src/main/java/java/util/zip/ZipUtils.java
index dd5106eebd5..e9db6e8b679 100644
--- a/ojluni/src/main/java/java/util/zip/ZipUtils.java
+++ b/ojluni/src/main/java/java/util/zip/ZipUtils.java
@@ -26,6 +26,7 @@
 package java.util.zip;
 
 import java.nio.ByteBuffer;
+import java.nio.DirectByteBuffer;
 import java.nio.file.attribute.FileTime;
 import java.time.DateTimeException;
 import java.time.Instant;
@@ -169,6 +170,14 @@ class ZipUtils {
         return (b[off] & 0xff) | ((b[off + 1] & 0xff) << 8);
     }
 
+    // Android-changed: don't keep CEN bytes in heap memory after initialization.
+    /**
+     * Fetches unsigned 16-bit value from buffer at current position.
+     */
+    public static final int get16(DirectByteBuffer bb, int pos) {
+        return bb.getShort(pos) & 0xffff;
+    }
+
     /**
      * Fetches unsigned 32-bit value from byte array at specified offset.
      * The bytes are assumed to be in Intel (little-endian) byte order.
@@ -177,6 +186,14 @@ class ZipUtils {
         return (get16(b, off) | ((long)get16(b, off+2) << 16)) & 0xffffffffL;
     }
 
+    // Android-changed: don't keep CEN bytes in heap memory after initialization.
+    /**
+     * Fetches unsigned 32-bit value from buffer at current position.
+     */
+    public static final long get32(DirectByteBuffer bb, int pos) {
+        return bb.getInt(pos) & 0xffffffffL;
+    }
+
     /**
      * Fetches signed 64-bit value from byte array at specified offset.
      * The bytes are assumed to be in Intel (little-endian) byte order.
@@ -185,6 +202,15 @@ class ZipUtils {
         return get32(b, off) | (get32(b, off+4) << 32);
     }
 
+    // Android-changed: don't keep CEN bytes in heap memory after initialization.
+    /**
+     * Fetches signed 64-bit value from byte array at specified offset.
+     * The bytes are assumed to be in Intel (little-endian) byte order.
+     */
+    public static final long get64(DirectByteBuffer bb, int pos) {
+        return bb.getLong(pos) & 0xffffffffffffffffL;
+    }
+
     /**
      * Fetches signed 32-bit value from byte array at specified offset.
      * The bytes are assumed to be in Intel (little-endian) byte order.
@@ -259,24 +285,38 @@ class ZipUtils {
     static final long ZIP64_LOCOFF(byte[] b) { return LL(b, 8);}   // zip64 end offset
 
     // central directory header (CEN) fields
+    // BEGIN Android-changed: don't keep CEN bytes in heap memory after initialization.
     static final long CENSIG(byte[] b, int pos) { return LG(b, pos + 0); }
     static final int  CENVEM(byte[] b, int pos) { return SH(b, pos + 4); }
     static final int  CENVEM_FA(byte[] b, int pos) { return CH(b, pos + 5); } // file attribute compatibility
+    static final int  CENVEM_FA(DirectByteBuffer b, int pos) { return b.get(pos + 5); } // file attribute compatibility
     static final int  CENVER(byte[] b, int pos) { return SH(b, pos + 6); }
     static final int  CENFLG(byte[] b, int pos) { return SH(b, pos + 8); }
+    static final int  CENFLG(DirectByteBuffer b, int pos) { return get16(b, pos + 8); }
     static final int  CENHOW(byte[] b, int pos) { return SH(b, pos + 10);}
+    static final int  CENHOW(DirectByteBuffer b, int pos) { return get16(b, pos + 10);}
     static final long CENTIM(byte[] b, int pos) { return LG(b, pos + 12);}
+    static final long CENTIM(DirectByteBuffer b, int pos) { return get32(b, pos + 12);}
     static final long CENCRC(byte[] b, int pos) { return LG(b, pos + 16);}
+    static final long CENCRC(DirectByteBuffer b, int pos) { return get32(b, pos + 16);}
     static final long CENSIZ(byte[] b, int pos) { return LG(b, pos + 20);}
+    static final long CENSIZ(DirectByteBuffer b, int pos) { return get32(b, pos + 20);}
     static final long CENLEN(byte[] b, int pos) { return LG(b, pos + 24);}
+    static final long CENLEN(DirectByteBuffer b, int pos) { return get32(b, pos + 24);}
     static final int  CENNAM(byte[] b, int pos) { return SH(b, pos + 28);}
+    static final int  CENNAM(DirectByteBuffer b, int pos) { return get16(b, pos + 28);}
     static final int  CENEXT(byte[] b, int pos) { return SH(b, pos + 30);}
+    static final int  CENEXT(DirectByteBuffer b, int pos) { return get16(b, pos + 30);}
     static final int  CENCOM(byte[] b, int pos) { return SH(b, pos + 32);}
+    static final int  CENCOM(DirectByteBuffer b, int pos) { return get16(b, pos + 32);}
     static final int  CENDSK(byte[] b, int pos) { return SH(b, pos + 34);}
     static final int  CENATT(byte[] b, int pos) { return SH(b, pos + 36);}
     static final long CENATX(byte[] b, int pos) { return LG(b, pos + 38);}
     static final int  CENATX_PERMS(byte[] b, int pos) { return SH(b, pos + 40);} // posix permission data
+    static final int  CENATX_PERMS(DirectByteBuffer b, int pos) { return get16(b, pos + 40);} // posix permission data
     static final long CENOFF(byte[] b, int pos) { return LG(b, pos + 42);}
+    static final long CENOFF(DirectByteBuffer b, int pos) { return get32(b, pos + 42);}
+    // END Android-changed: don't keep CEN bytes in heap memory after initialization.
 
     // The END header is followed by a variable length comment of size < 64k.
     static final long END_MAXLEN = 0xFFFF + ENDHDR;
diff --git a/ojluni/src/main/java/javax/net/ssl/SSLContext.java b/ojluni/src/main/java/javax/net/ssl/SSLContext.java
index eb7322c445f..064c48795e0 100644
--- a/ojluni/src/main/java/javax/net/ssl/SSLContext.java
+++ b/ojluni/src/main/java/javax/net/ssl/SSLContext.java
@@ -62,11 +62,11 @@ import sun.security.jca.GetInstance;
  *       <td>TLS</td>
  *       <td>1+</td>
  *     </tr>
- *     <tr>
+ *     <tr class="deprecated">
  *       <td>TLSv1</td>
  *       <td>10+</td>
  *     </tr>
- *     <tr>
+ *     <tr class="deprecated">
  *       <td>TLSv1.1</td>
  *       <td>16+</td>
  *     </tr>
diff --git a/ojluni/src/main/java/jdk/internal/access/SharedSecrets.java b/ojluni/src/main/java/jdk/internal/access/SharedSecrets.java
index 22c5aa85be3..3b1bf48a69f 100644
--- a/ojluni/src/main/java/jdk/internal/access/SharedSecrets.java
+++ b/ojluni/src/main/java/jdk/internal/access/SharedSecrets.java
@@ -23,6 +23,7 @@
  * questions.
  */
 package jdk.internal.access;
+
 import jdk.internal.misc.Unsafe;
 import java.io.ObjectInputStream;
 import java.io.FileDescriptor;
@@ -45,7 +46,7 @@ public class SharedSecrets {
     private static JavaBeansAccess javaBeansAccess;
     */
     // END Android-removed: Pruned unused access interfaces.
-    private static JavaLangAccess javaLangAccess;
+    private static final JavaLangAccess javaLangAccess = new JavaLangAccess();
     // BEGIN Android-removed: Pruned unused access interfaces.
     /*
     private static JavaLangInvokeAccess javaLangInvokeAccess;
@@ -115,11 +116,11 @@ public class SharedSecrets {
     public static void setJavaUtilJarAccess(JavaUtilJarAccess access) {
         javaUtilJarAccess = access;
     }
-    */
-    // END Android-removed: Pruned unused access interfaces.
     public static void setJavaLangAccess(JavaLangAccess jla) {
         javaLangAccess = jla;
     }
+    */
+    // END Android-removed: Pruned unused access interfaces.
     public static JavaLangAccess getJavaLangAccess() {
         return javaLangAccess;
     }
diff --git a/ojluni/src/main/java/jdk/internal/vm/Continuation.java b/ojluni/src/main/java/jdk/internal/vm/Continuation.java
new file mode 100644
index 00000000000..3b40cfe5bd0
--- /dev/null
+++ b/ojluni/src/main/java/jdk/internal/vm/Continuation.java
@@ -0,0 +1,537 @@
+/*
+ * Copyright (c) 2018, 2023, Oracle and/or its affiliates. All rights reserved.
+ * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
+ *
+ * This code is free software; you can redistribute it and/or modify it
+ * under the terms of the GNU General Public License version 2 only, as
+ * published by the Free Software Foundation.  Oracle designates this
+ * particular file as subject to the "Classpath" exception as provided
+ * by Oracle in the LICENSE file that accompanied this code.
+ *
+ * This code is distributed in the hope that it will be useful, but WITHOUT
+ * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
+ * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
+ * version 2 for more details (a copy is included in the LICENSE file that
+ * accompanied this code).
+ *
+ * You should have received a copy of the GNU General Public License version
+ * 2 along with this work; if not, write to the Free Software Foundation,
+ * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
+ *
+ * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
+ * or visit www.oracle.com if you need additional information or have any
+ * questions.
+ */
+
+package jdk.internal.vm;
+
+import jdk.internal.misc.Unsafe;
+import jdk.internal.vm.annotation.DontInline;
+import jdk.internal.vm.annotation.IntrinsicCandidate;
+import sun.security.action.GetPropertyAction;
+
+import java.util.EnumSet;
+import java.util.Set;
+import java.util.function.Supplier;
+import jdk.internal.access.SharedSecrets;
+import jdk.internal.vm.annotation.Hidden;
+
+/**
+ * A one-shot delimited continuation.
+ */
+public class Continuation {
+    private static final Unsafe U = Unsafe.getUnsafe();
+    private static final long MOUNTED_OFFSET = U.objectFieldOffset(Continuation.class, "mounted");
+    private static final boolean PRESERVE_SCOPED_VALUE_CACHE;
+    private static final JavaLangAccess JLA = SharedSecrets.getJavaLangAccess();
+    static {
+        // Android-removed: This check during startup isn't necessary on ART.
+        // ContinuationSupport.ensureSupported();
+
+        StackChunk.init(); // ensure StackChunk class is initialized
+
+        // Android-changed: Remove ScopedValue until the feature is finalized.
+        // String value = GetPropertyAction.privilegedGetProperty("jdk.preserveScopedValueCache");
+        // PRESERVE_SCOPED_VALUE_CACHE = (value == null) || Boolean.parseBoolean(value);
+        PRESERVE_SCOPED_VALUE_CACHE = false;
+    }
+
+    /** Reason for pinning */
+    public enum Pinned {
+        /** Native frame on stack */ NATIVE,
+        /** Monitor held */          MONITOR,
+        /** In critical section */   CRITICAL_SECTION }
+
+    /** Preemption attempt result */
+    public enum PreemptStatus {
+        /** Success */                                                      SUCCESS(null),
+        /** Permanent failure */                                            PERM_FAIL_UNSUPPORTED(null),
+        /** Permanent failure: continuation already yielding */             PERM_FAIL_YIELDING(null),
+        /** Permanent failure: continuation not mounted on the thread */    PERM_FAIL_NOT_MOUNTED(null),
+        /** Transient failure: continuation pinned due to a held CS */      TRANSIENT_FAIL_PINNED_CRITICAL_SECTION(Pinned.CRITICAL_SECTION),
+        /** Transient failure: continuation pinned due to native frame */   TRANSIENT_FAIL_PINNED_NATIVE(Pinned.NATIVE),
+        /** Transient failure: continuation pinned due to a held monitor */ TRANSIENT_FAIL_PINNED_MONITOR(Pinned.MONITOR);
+
+        final Pinned pinned;
+        private PreemptStatus(Pinned reason) { this.pinned = reason; }
+        /**
+         * Whether or not the continuation is pinned.
+         * @return whether or not the continuation is pinned
+         **/
+        public Pinned pinned() { return pinned; }
+    }
+
+    private static Pinned pinnedReason(int reason) {
+        return switch (reason) {
+            case 2 -> Pinned.CRITICAL_SECTION;
+            case 3 -> Pinned.NATIVE;
+            case 4 -> Pinned.MONITOR;
+            default -> throw new AssertionError("Unknown pinned reason: " + reason);
+        };
+    }
+
+    private static Thread currentCarrierThread() {
+        // TODO: Get it from java.lang.Thread.
+        // return JLA.currentCarrierThread();
+        return null;
+    }
+
+    static {
+        try {
+            // Android-removed: Not needed on Android.
+            // registerNatives();
+
+            // init Pinned to avoid classloading during mounting
+            pinnedReason(2);
+        } catch (Exception e) {
+            throw new InternalError(e);
+        }
+    }
+
+    private final Runnable target;
+
+    /* While the native JVM code is aware that every continuation has a scope, it is, for the most part,
+     * oblivious to the continuation hierarchy. The only time this hierarchy is traversed in native code
+     * is when a hierarchy of continuations is mounted on the native stack.
+     */
+    private final ContinuationScope scope;
+    private Continuation parent; // null for native stack
+    private Continuation child; // non-null when we're yielded in a child continuation
+
+    private StackChunk tail;
+
+    private boolean done;
+    private volatile boolean mounted;
+    private Object yieldInfo;
+    private boolean preempted;
+
+    private Object[] scopedValueCache;
+
+    /**
+     * Constructs a continuation
+     * @param scope the continuation's scope, used in yield
+     * @param target the continuation's body
+     */
+    public Continuation(ContinuationScope scope, Runnable target) {
+        this.scope = scope;
+        this.target = target;
+    }
+
+    @Override
+    public String toString() {
+        return super.toString() + " scope: " + scope;
+    }
+
+    public ContinuationScope getScope() {
+        return scope;
+    }
+
+    public Continuation getParent() {
+        return parent;
+    }
+
+    /**
+     * Returns the current innermost continuation with the given scope
+     * @param scope the scope
+     * @return the continuation
+     */
+    public static Continuation getCurrentContinuation(ContinuationScope scope) {
+        // TODO: Implement this.
+        // Continuation cont = JLA.getContinuation(currentCarrierThread());
+        Continuation cont = null;
+        while (cont != null && cont.scope != scope)
+            cont = cont.parent;
+        return cont;
+    }
+
+    /**
+     * Creates a StackWalker for this continuation
+     * @return a new StackWalker
+     */
+    public StackWalker stackWalker() {
+        return stackWalker(EnumSet.noneOf(StackWalker.Option.class));
+    }
+
+    /**
+     * Creates a StackWalker for this continuation
+     * @param options the StackWalker's configuration options
+     * @return a new StackWalker
+     */
+    public StackWalker stackWalker(Set<StackWalker.Option> options) {
+        return stackWalker(options, this.scope);
+    }
+
+    /**
+     * Creates a StackWalker for this continuation and enclosing ones up to the given scope
+     * @param options the StackWalker's configuration options
+     * @param scope the delimiting continuation scope for the stack
+     * @return a new StackWalker
+     */
+    public StackWalker stackWalker(Set<StackWalker.Option> options, ContinuationScope scope) {
+        // TODO: Implement this.
+        // return JLA.newStackWalkerInstance(options, scope, innermost());
+        return null;
+    }
+
+    /**
+     * Obtains a stack trace for this unmounted continuation
+     * @return the stack trace
+     * @throws IllegalStateException if the continuation is mounted
+     */
+    public StackTraceElement[] getStackTrace() {
+        return stackWalker(EnumSet.of(StackWalker.Option.SHOW_REFLECT_FRAMES))
+            .walk(s -> s.map(StackWalker.StackFrame::toStackTraceElement)
+            .toArray(StackTraceElement[]::new));
+    }
+
+    /// Support for StackWalker
+    public static <R> R wrapWalk(Continuation inner, ContinuationScope scope, Supplier<R> walk) {
+        try {
+            for (Continuation c = inner; c != null && c.scope != scope; c = c.parent)
+                c.mount();
+            return walk.get();
+        } finally {
+            for (Continuation c = inner; c != null && c.scope != scope; c = c.parent)
+                c.unmount();
+        }
+    }
+
+    private Continuation innermost() {
+        Continuation c = this;
+        while (c.child != null)
+            c = c.child;
+        return c;
+    }
+
+    private void mount() {
+        if (!compareAndSetMounted(false, true))
+            throw new IllegalStateException("Mounted!!!!");
+    }
+
+    private void unmount() {
+        setMounted(false);
+    }
+
+    /**
+     * Mounts and runs the continuation body. If suspended, continues it from the last suspend point.
+     */
+    public final void run() {
+        while (true) {
+            mount();
+            // Android-removed: Remove ScopedValue until the feature is finalized.
+            // JLA.setScopedValueCache(scopedValueCache);
+
+            if (done)
+                throw new IllegalStateException("Continuation terminated");
+
+            Thread t = currentCarrierThread();
+            // TODO: Implement this.
+            /*
+            if (parent != null) {
+                if (parent != JLA.getContinuation(t))
+                    throw new IllegalStateException();
+            } else
+                this.parent = JLA.getContinuation(t);
+            JLA.setContinuation(t, this);
+            */
+
+            try {
+                // TODO: Implement this.
+                // boolean isVirtualThread = (scope == JLA.virtualThreadContinuationScope());
+                boolean isVirtualThread = true;
+                if (!isStarted()) { // is this the first run? (at this point we know !done)
+                    enterSpecial(this, false, isVirtualThread);
+                } else {
+                    assert !isEmpty();
+                    enterSpecial(this, true, isVirtualThread);
+                }
+            } finally {
+                fence();
+                try {
+                    assert isEmpty() == done : "empty: " + isEmpty() + " done: " + done + " cont: " + Integer.toHexString(System.identityHashCode(this));
+                    // TODO: Implement this.
+                    // JLA.setContinuation(currentCarrierThread(), this.parent);
+                    if (parent != null)
+                        parent.child = null;
+
+                    postYieldCleanup();
+
+                    unmount();
+                    // Android-removed: Remove ScopedValue until the feature is finalized.
+                    /*
+                    if (PRESERVE_SCOPED_VALUE_CACHE) {
+                        scopedValueCache = JLA.scopedValueCache();
+                    } else {
+                        scopedValueCache = null;
+                    }
+                    JLA.setScopedValueCache(null);
+                    */
+                } catch (Throwable e) { e.printStackTrace(); System.exit(1); }
+            }
+            // we're now in the parent continuation
+
+            assert yieldInfo == null || yieldInfo instanceof ContinuationScope;
+            if (yieldInfo == null || yieldInfo == scope) {
+                this.parent = null;
+                this.yieldInfo = null;
+                return;
+            } else {
+                parent.child = this;
+                parent.yield0((ContinuationScope)yieldInfo, this);
+                parent.child = null;
+            }
+        }
+    }
+
+    private void postYieldCleanup() {
+        if (done) {
+            this.tail = null;
+        }
+    }
+
+    private void finish() {
+        done = true;
+        assert isEmpty();
+    }
+
+    @IntrinsicCandidate
+    private native static int doYield();
+
+    @IntrinsicCandidate
+    private native static void enterSpecial(Continuation c, boolean isContinue, boolean isVirtualThread);
+
+
+    @Hidden
+    @DontInline
+    @IntrinsicCandidate
+    private static void enter(Continuation c, boolean isContinue) {
+        // This method runs in the "entry frame".
+        // A yield jumps to this method's caller as if returning from this method.
+        try {
+            c.enter0();
+        } finally {
+            c.finish();
+        }
+    }
+
+    @Hidden
+    private void enter0() {
+        target.run();
+    }
+
+    private boolean isStarted() {
+        return tail != null;
+    }
+
+    private boolean isEmpty() {
+        for (StackChunk c = tail; c != null; c = c.parent()) {
+            if (!c.isEmpty())
+                return false;
+        }
+        return true;
+    }
+
+    /**
+     * Suspends the current continuations up to the given scope
+     *
+     * @param scope The {@link ContinuationScope} to suspend
+     * @return {@code true} for success; {@code false} for failure
+     * @throws IllegalStateException if not currently in the given {@code scope},
+     */
+    @Hidden
+    public static boolean yield(ContinuationScope scope) {
+        // TODO: Implement this.
+        // Continuation cont = JLA.getContinuation(currentCarrierThread());
+        Continuation cont = null;
+        Continuation c;
+        for (c = cont; c != null && c.scope != scope; c = c.parent)
+            ;
+        if (c == null)
+            throw new IllegalStateException("Not in scope " + scope);
+
+        return cont.yield0(scope, null);
+    }
+
+    @Hidden
+    private boolean yield0(ContinuationScope scope, Continuation child) {
+        preempted = false;
+
+        if (scope != this.scope)
+            this.yieldInfo = scope;
+        int res = doYield();
+        U.storeFence(); // needed to prevent certain transformations by the compiler
+
+        assert scope != this.scope || yieldInfo == null : "scope: " + scope + " this.scope: " + this.scope + " yieldInfo: " + yieldInfo + " res: " + res;
+        assert yieldInfo == null || scope == this.scope || yieldInfo instanceof Integer : "scope: " + scope + " this.scope: " + this.scope + " yieldInfo: " + yieldInfo + " res: " + res;
+
+        if (child != null) { // TODO: ugly
+            if (res != 0) {
+                child.yieldInfo = res;
+            } else if (yieldInfo != null) {
+                assert yieldInfo instanceof Integer;
+                child.yieldInfo = yieldInfo;
+            } else {
+                child.yieldInfo = res;
+            }
+            this.yieldInfo = null;
+        } else {
+            if (res == 0 && yieldInfo != null) {
+                res = (Integer)yieldInfo;
+            }
+            this.yieldInfo = null;
+
+            if (res == 0)
+                onContinue();
+            else
+                onPinned0(res);
+        }
+        assert yieldInfo == null;
+
+        return res == 0;
+    }
+
+    private void onPinned0(int reason) {
+        onPinned(pinnedReason(reason));
+    }
+
+    /**
+     * Called when suspending if the continuation is pinned
+     * @param reason the reason for pinning
+     */
+    protected void onPinned(Pinned reason) {
+        throw new IllegalStateException("Pinned: " + reason);
+    }
+
+    /**
+     * Called when the continuation continues
+     */
+    protected void onContinue() {
+    }
+
+    /**
+     * Tests whether this continuation is completed
+     * @return whether this continuation is completed
+     */
+    public boolean isDone() {
+        return done;
+    }
+
+    /**
+     * Tests whether this unmounted continuation was unmounted by forceful preemption (a successful tryPreempt)
+     * @return whether this unmounted continuation was unmounted by forceful preemption
+     */
+    public boolean isPreempted() {
+        return preempted;
+    }
+
+    /**
+     * Pins the current continuation (enters a critical section).
+     * This increments an internal semaphore that, when greater than 0, pins the continuation.
+     */
+    // Android-removed: unused
+    // public static native void pin();
+
+    /**
+     * Unpins the current continuation (exits a critical section).
+     * This decrements an internal semaphore that, when equal 0, unpins the current continuation
+     * if pinned with {@link #pin()}.
+     */
+    // public static native void unpin();
+
+    /**
+     * Tests whether the given scope is pinned.
+     * This method is slow.
+     *
+     * @param scope the continuation scope
+     * @return {@code} true if we're in the give scope and are pinned; {@code false otherwise}
+     */
+    public static boolean isPinned(ContinuationScope scope) {
+        int res = isPinned0(scope);
+        return res != 0;
+    }
+
+    static private native int isPinned0(ContinuationScope scope);
+
+    private boolean fence() {
+        U.storeFence(); // needed to prevent certain transformations by the compiler
+        return true;
+    }
+
+    private boolean compareAndSetMounted(boolean expectedValue, boolean newValue) {
+        // TODO: Implement Unsafe.compareAndSetBoolean or replace it with VarHandle.
+        // return U.compareAndSetBoolean(this, MOUNTED_OFFSET, expectedValue, newValue);
+        return false;
+    }
+
+    private void setMounted(boolean newValue) {
+        mounted = newValue; // MOUNTED.setVolatile(this, newValue);
+    }
+
+    // Android-removed: unused.
+    /*
+    private String id() {
+        return Integer.toHexString(System.identityHashCode(this))
+                + " [" + currentCarrierThread().threadId() + "]";
+    }
+    */
+
+    /**
+     * Tries to forcefully preempt this continuation if it is currently mounted on the given thread
+     * Subclasses may throw an {@link UnsupportedOperationException}, but this does not prevent
+     * the continuation from being preempted on a parent scope.
+     *
+     * @param thread the thread on which to forcefully preempt this continuation
+     * @return the result of the attempt
+     * @throws UnsupportedOperationException if this continuation does not support preemption
+     */
+    public PreemptStatus tryPreempt(Thread thread) {
+        throw new UnsupportedOperationException("Not implemented");
+    }
+
+    // native method
+    // Android-removed: Not needed on Android.
+    // private static native void registerNatives();
+
+    // Android-removed: unused.
+    /*
+    private void dump() {
+        System.out.println("Continuation@" + Long.toHexString(System.identityHashCode(this)));
+        System.out.println("\tparent: " + parent);
+        int i = 0;
+        for (StackChunk c = tail; c != null; c = c.parent()) {
+            System.out.println("\tChunk " + i);
+            System.out.println(c);
+        }
+    }
+    */
+
+    // Android-removed: unused.
+    /*
+    private static boolean isEmptyOrTrue(String property) {
+        String value = GetPropertyAction.privilegedGetProperty(property);
+        if (value == null)
+            return false;
+        return value.isEmpty() || Boolean.parseBoolean(value);
+    }
+    */
+}
diff --git a/ojluni/src/main/java/jdk/internal/vm/ContinuationScope.java b/ojluni/src/main/java/jdk/internal/vm/ContinuationScope.java
new file mode 100644
index 00000000000..a101ba96bd8
--- /dev/null
+++ b/ojluni/src/main/java/jdk/internal/vm/ContinuationScope.java
@@ -0,0 +1,73 @@
+/*
+ * Copyright (c) 2018, 2022, Oracle and/or its affiliates. All rights reserved.
+ * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
+ *
+ * This code is free software; you can redistribute it and/or modify it
+ * under the terms of the GNU General Public License version 2 only, as
+ * published by the Free Software Foundation.  Oracle designates this
+ * particular file as subject to the "Classpath" exception as provided
+ * by Oracle in the LICENSE file that accompanied this code.
+ *
+ * This code is distributed in the hope that it will be useful, but WITHOUT
+ * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
+ * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
+ * version 2 for more details (a copy is included in the LICENSE file that
+ * accompanied this code).
+ *
+ * You should have received a copy of the GNU General Public License version
+ * 2 along with this work; if not, write to the Free Software Foundation,
+ * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
+ *
+ * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
+ * or visit www.oracle.com if you need additional information or have any
+ * questions.
+ */
+
+package jdk.internal.vm;
+
+import java.util.Objects;
+
+/**
+ * A Continuation scope.
+ */
+public class ContinuationScope {
+    final String name;
+
+    /**
+     * Constructs a new scope.
+     * @param name The scope's name
+     */
+    public ContinuationScope(String name) {
+        this.name = Objects.requireNonNull(name);
+    }
+
+    /**
+     * A constructor providing no name is available to subclasses.
+     */
+    protected ContinuationScope() {
+        this.name = getClass().getName();
+    }
+
+    /**
+     * Returns this scope's name.
+     * @return this scope's name
+     */
+    public final String getName() {
+        return name;
+    }
+
+    @Override
+    public final String toString() {
+        return name;
+    }
+
+    @Override
+    public final int hashCode() {
+        return super.hashCode();
+    }
+
+    @Override
+    public final boolean equals(Object obj) {
+        return super.equals(obj);
+    }
+}
diff --git a/ojluni/src/main/java/jdk/internal/vm/annotation/DontInline.java b/ojluni/src/main/java/jdk/internal/vm/annotation/DontInline.java
new file mode 100644
index 00000000000..d39dccffbad
--- /dev/null
+++ b/ojluni/src/main/java/jdk/internal/vm/annotation/DontInline.java
@@ -0,0 +1,50 @@
+/*
+ * Copyright (c) 2012, Oracle and/or its affiliates. All rights reserved.
+ * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
+ *
+ * This code is free software; you can redistribute it and/or modify it
+ * under the terms of the GNU General Public License version 2 only, as
+ * published by the Free Software Foundation.  Oracle designates this
+ * particular file as subject to the "Classpath" exception as provided
+ * by Oracle in the LICENSE file that accompanied this code.
+ *
+ * This code is distributed in the hope that it will be useful, but WITHOUT
+ * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
+ * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
+ * version 2 for more details (a copy is included in the LICENSE file that
+ * accompanied this code).
+ *
+ * You should have received a copy of the GNU General Public License version
+ * 2 along with this work; if not, write to the Free Software Foundation,
+ * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
+ *
+ * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
+ * or visit www.oracle.com if you need additional information or have any
+ * questions.
+ */
+
+package jdk.internal.vm.annotation;
+
+import java.lang.annotation.*;
+
+/**
+ * A method or constructor may be annotated as "don't inline" if the inlining of
+ * this method should not be performed by the HotSpot VM.
+ * <p>
+ * This annotation must be used sparingly.  It is useful when the only
+ * reasonable alternative is to bind the name of a specific method or
+ * constructor into the HotSpot VM for special handling by the inlining policy.
+ * This annotation must not be relied on as an alternative to avoid tuning the
+ * VM's inlining policy.  In a few cases, it may act as a temporary workaround
+ * until the profiling and inlining performed by the HotSpot VM is sufficiently
+ * improved.
+ *
+ * @implNote
+ * This annotation only takes effect for methods or constructors of classes
+ * loaded by the boot loader.  Annotations on methods or constructors of classes
+ * loaded outside of the boot loader are ignored.
+ */
+@Target({ElementType.METHOD, ElementType.CONSTRUCTOR})
+@Retention(RetentionPolicy.RUNTIME)
+public @interface DontInline {
+}
diff --git a/ojluni/src/main/java/jdk/internal/vm/annotation/Hidden.java b/ojluni/src/main/java/jdk/internal/vm/annotation/Hidden.java
new file mode 100644
index 00000000000..d7c4925266e
--- /dev/null
+++ b/ojluni/src/main/java/jdk/internal/vm/annotation/Hidden.java
@@ -0,0 +1,45 @@
+/*
+ * Copyright (c) 2019, Oracle and/or its affiliates. All rights reserved.
+ * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
+ *
+ * This code is free software; you can redistribute it and/or modify it
+ * under the terms of the GNU General Public License version 2 only, as
+ * published by the Free Software Foundation.  Oracle designates this
+ * particular file as subject to the "Classpath" exception as provided
+ * by Oracle in the LICENSE file that accompanied this code.
+ *
+ * This code is distributed in the hope that it will be useful, but WITHOUT
+ * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
+ * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
+ * version 2 for more details (a copy is included in the LICENSE file that
+ * accompanied this code).
+ *
+ * You should have received a copy of the GNU General Public License version
+ * 2 along with this work; if not, write to the Free Software Foundation,
+ * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
+ *
+ * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
+ * or visit www.oracle.com if you need additional information or have any
+ * questions.
+ */
+
+package jdk.internal.vm.annotation;
+
+import java.lang.annotation.*;
+
+/**
+ * A method or constructor may be annotated as "hidden" to hint it is desirable
+ * to omit it from stack traces.
+ *
+ * @implNote
+ * This annotation only takes effect for methods or constructors of classes
+ * loaded by the boot loader.  Annotations on methods or constructors of classes
+ * loaded outside of the boot loader are ignored.
+ *
+ * <p>HotSpot JVM provides diagnostic option {@code -XX:+ShowHiddenFrames} to
+ * always show "hidden" frames.
+ */
+@Target({ElementType.METHOD, ElementType.CONSTRUCTOR})
+@Retention(RetentionPolicy.RUNTIME)
+public @interface Hidden {
+}
diff --git a/ojluni/src/main/java/sun/nio/ch/EPoll.java b/ojluni/src/main/java/sun/nio/ch/EPoll.java
index 0e99c4f9366..26ecfe915dc 100644
--- a/ojluni/src/main/java/sun/nio/ch/EPoll.java
+++ b/ojluni/src/main/java/sun/nio/ch/EPoll.java
@@ -26,7 +26,7 @@
 package sun.nio.ch;
 
 import java.io.IOException;
-import sun.misc.Unsafe;
+import jdk.internal.misc.Unsafe;
 
 /**
  * Provides access to the Linux epoll facility.
diff --git a/ojluni/src/main/java/sun/nio/ch/NativeObject.java b/ojluni/src/main/java/sun/nio/ch/NativeObject.java
index e4e4366289a..839b64df8ad 100644
--- a/ojluni/src/main/java/sun/nio/ch/NativeObject.java
+++ b/ojluni/src/main/java/sun/nio/ch/NativeObject.java
@@ -29,7 +29,7 @@
 package sun.nio.ch;                                     // Formerly in sun.misc
 
 import java.nio.ByteOrder;
-import sun.misc.Unsafe;
+import jdk.internal.misc.Unsafe;
 
 
 // ## In the fullness of time, this class will be eliminated
diff --git a/ojluni/src/main/java/sun/nio/ch/Util.java b/ojluni/src/main/java/sun/nio/ch/Util.java
index fa0b631b26b..6d1b167ed4f 100644
--- a/ojluni/src/main/java/sun/nio/ch/Util.java
+++ b/ojluni/src/main/java/sun/nio/ch/Util.java
@@ -30,7 +30,7 @@ import java.nio.ByteBuffer;
 import java.security.AccessController;
 import java.security.PrivilegedAction;
 import java.util.*;
-import sun.misc.Unsafe;
+import jdk.internal.misc.Unsafe;
 import sun.misc.Cleaner;
 import sun.security.action.GetPropertyAction;
 
diff --git a/ojluni/src/main/java/sun/nio/fs/Cancellable.java b/ojluni/src/main/java/sun/nio/fs/Cancellable.java
index 0aa6521f19b..d386f016cd2 100644
--- a/ojluni/src/main/java/sun/nio/fs/Cancellable.java
+++ b/ojluni/src/main/java/sun/nio/fs/Cancellable.java
@@ -25,7 +25,7 @@
 
 package sun.nio.fs;
 
-import sun.misc.Unsafe;
+import jdk.internal.misc.Unsafe;
 import java.util.concurrent.ExecutionException;
 
 /**
diff --git a/ojluni/src/main/java/sun/nio/fs/LinuxDosFileAttributeView.java b/ojluni/src/main/java/sun/nio/fs/LinuxDosFileAttributeView.java
index 7bee2fb3640..5673f5632c3 100644
--- a/ojluni/src/main/java/sun/nio/fs/LinuxDosFileAttributeView.java
+++ b/ojluni/src/main/java/sun/nio/fs/LinuxDosFileAttributeView.java
@@ -29,7 +29,7 @@ import java.nio.file.attribute.*;
 import java.util.Map;
 import java.util.Set;
 import java.io.IOException;
-import sun.misc.Unsafe;
+import jdk.internal.misc.Unsafe;
 
 import static sun.nio.fs.UnixNativeDispatcher.*;
 import static sun.nio.fs.UnixConstants.*;
diff --git a/ojluni/src/main/java/sun/nio/fs/LinuxUserDefinedFileAttributeView.java b/ojluni/src/main/java/sun/nio/fs/LinuxUserDefinedFileAttributeView.java
index a3953700e85..873cf802f77 100644
--- a/ojluni/src/main/java/sun/nio/fs/LinuxUserDefinedFileAttributeView.java
+++ b/ojluni/src/main/java/sun/nio/fs/LinuxUserDefinedFileAttributeView.java
@@ -29,7 +29,7 @@ import java.nio.file.*;
 import java.nio.ByteBuffer;
 import java.io.IOException;
 import java.util.*;
-import sun.misc.Unsafe;
+import jdk.internal.misc.Unsafe;
 
 import static sun.nio.fs.UnixConstants.*;
 import static sun.nio.fs.LinuxNativeDispatcher.*;
diff --git a/ojluni/src/main/java/sun/nio/fs/LinuxWatchService.java b/ojluni/src/main/java/sun/nio/fs/LinuxWatchService.java
index db61c8d8b1b..6c917859dea 100644
--- a/ojluni/src/main/java/sun/nio/fs/LinuxWatchService.java
+++ b/ojluni/src/main/java/sun/nio/fs/LinuxWatchService.java
@@ -33,7 +33,7 @@ import java.io.IOException;
 
 import dalvik.annotation.optimization.ReachabilitySensitive;
 import dalvik.system.CloseGuard;
-import sun.misc.Unsafe;
+import jdk.internal.misc.Unsafe;
 
 import static sun.nio.fs.UnixNativeDispatcher.*;
 import static sun.nio.fs.UnixConstants.*;
diff --git a/ojluni/src/main/java/sun/nio/fs/NativeBuffer.java b/ojluni/src/main/java/sun/nio/fs/NativeBuffer.java
index 0c6de1d465e..d2c4a828426 100644
--- a/ojluni/src/main/java/sun/nio/fs/NativeBuffer.java
+++ b/ojluni/src/main/java/sun/nio/fs/NativeBuffer.java
@@ -25,7 +25,7 @@
 
 package sun.nio.fs;
 
-import sun.misc.Unsafe;
+import jdk.internal.misc.Unsafe;
 import sun.misc.Cleaner;
 
 /**
diff --git a/ojluni/src/main/java/sun/nio/fs/NativeBuffers.java b/ojluni/src/main/java/sun/nio/fs/NativeBuffers.java
index dcdfdf22dc2..d42a5e7e077 100644
--- a/ojluni/src/main/java/sun/nio/fs/NativeBuffers.java
+++ b/ojluni/src/main/java/sun/nio/fs/NativeBuffers.java
@@ -25,7 +25,7 @@
 
 package sun.nio.fs;
 
-import sun.misc.Unsafe;
+import jdk.internal.misc.Unsafe;
 
 /**
  * Factory for native buffers.
diff --git a/ojluni/src/main/native/net_util_md.c b/ojluni/src/main/native/net_util_md.c
index 23c4d2446de..b03dfec991a 100644
--- a/ojluni/src/main/native/net_util_md.c
+++ b/ojluni/src/main/native/net_util_md.c
@@ -39,9 +39,6 @@
 #ifndef MAXINT
 #define MAXINT INT_MAX
 #endif
-#ifdef __BIONIC__
-#include <linux/ipv6_route.h>
-#endif
 
 #ifdef __solaris__
 #include <sys/sockio.h>
diff --git a/ojluni/src/test/java/lang/runtime/ObjectMethodsTest.java b/ojluni/src/test/java/lang/runtime/ObjectMethodsTest.java
new file mode 100644
index 00000000000..d0864ef0a03
--- /dev/null
+++ b/ojluni/src/test/java/lang/runtime/ObjectMethodsTest.java
@@ -0,0 +1,179 @@
+/*
+ * Copyright (c) 2019, 2020, Oracle and/or its affiliates. All rights reserved.
+ * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
+ *
+ * This code is free software; you can redistribute it and/or modify it
+ * under the terms of the GNU General Public License version 2 only, as
+ * published by the Free Software Foundation.
+ *
+ * This code is distributed in the hope that it will be useful, but WITHOUT
+ * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
+ * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
+ * version 2 for more details (a copy is included in the LICENSE file that
+ * accompanied this code).
+ *
+ * You should have received a copy of the GNU General Public License version
+ * 2 along with this work; if not, write to the Free Software Foundation,
+ * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
+ *
+ * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
+ * or visit www.oracle.com if you need additional information or have any
+ * questions.
+ */
+
+/*
+ * @test
+ * @bug 8246774
+ * @summary Basic tests for ObjectMethods
+ * @run testng ObjectMethodsTest
+ * @run testng/othervm/java.security.policy=empty.policy ObjectMethodsTest
+ */
+
+package test.java.lang.runtime;
+
+import java.util.List;
+import java.lang.invoke.CallSite;
+import java.lang.invoke.MethodHandle;
+import java.lang.invoke.MethodHandles;
+import java.lang.invoke.MethodType;
+import java.lang.runtime.ObjectMethods;
+import org.testng.annotations.Test;
+import static java.lang.invoke.MethodType.methodType;
+import static org.testng.Assert.assertEquals;
+import static org.testng.Assert.assertThrows;
+import static org.testng.Assert.assertFalse;
+import static org.testng.Assert.assertTrue;
+
+@Test
+public class ObjectMethodsTest {
+
+    public static class C {
+        static final MethodType EQUALS_DESC = methodType(boolean.class, C.class, Object.class);
+        static final MethodType HASHCODE_DESC = methodType(int.class, C.class);
+        static final MethodType TO_STRING_DESC = methodType(String.class, C.class);
+
+        static final MethodHandle[] ACCESSORS = accessors();
+        static final String NAME_LIST = "x;y";
+        private static MethodHandle[] accessors() {
+            try {
+                return  new MethodHandle[]{
+                        MethodHandles.lookup().findGetter(C.class, "x", int.class),
+                        MethodHandles.lookup().findGetter(C.class, "y", int.class),
+                };
+            } catch (Exception e) {
+                throw new AssertionError(e);
+            }
+        }
+
+        private final int x;
+        private final int y;
+        C (int x, int y) { this.x = x; this.y = y; }
+        public int x() { return x; }
+        public int y() { return y; }
+    }
+
+    static class Empty {
+        static final MethodType EQUALS_DESC = methodType(boolean.class, Empty.class, Object.class);
+        static final MethodType HASHCODE_DESC = methodType(int.class, Empty.class);
+        static final MethodType TO_STRING_DESC = methodType(String.class, Empty.class);
+        static final MethodHandle[] ACCESSORS = new MethodHandle[] { };
+        static final String NAME_LIST = "";
+        Empty () {  }
+    }
+
+    static final MethodHandles.Lookup LOOKUP = MethodHandles.lookup();
+
+    public void testEqualsC() throws Throwable {
+        CallSite cs = (CallSite)ObjectMethods.bootstrap(LOOKUP, "equals", C.EQUALS_DESC, C.class, C.NAME_LIST, C.ACCESSORS);
+        MethodHandle handle = cs.dynamicInvoker();
+        C c = new C(5, 5);
+        assertTrue((boolean)handle.invokeExact(c, (Object)c));
+        assertTrue((boolean)handle.invokeExact(c, (Object)new C(5, 5)));
+        assertFalse((boolean)handle.invokeExact(c, (Object)new C(5, 4)));
+        assertFalse((boolean)handle.invokeExact(c, (Object)new C(4, 5)));
+        assertFalse((boolean)handle.invokeExact(c, (Object)null));
+        assertFalse((boolean)handle.invokeExact(c, new Object()));
+    }
+
+    public void testEqualsEmpty() throws Throwable {
+        CallSite cs = (CallSite)ObjectMethods.bootstrap(LOOKUP, "equals", Empty.EQUALS_DESC, Empty.class, Empty.NAME_LIST, Empty.ACCESSORS);
+        MethodHandle handle = cs.dynamicInvoker();
+        Empty e = new Empty();
+        assertTrue((boolean)handle.invokeExact(e, (Object)e));
+        assertTrue((boolean)handle.invokeExact(e, (Object)new Empty()));
+        assertFalse((boolean)handle.invokeExact(e, (Object)null));
+        assertFalse((boolean)handle.invokeExact(e, new Object()));
+    }
+
+    public void testHashCodeC() throws Throwable {
+        CallSite cs = (CallSite)ObjectMethods.bootstrap(LOOKUP, "hashCode", C.HASHCODE_DESC, C.class, "x;y", C.ACCESSORS);
+        MethodHandle handle = cs.dynamicInvoker();
+        C c = new C(6, 7);
+        int hc = (int)handle.invokeExact(c);
+        assertEquals(hc, hashCombiner(c.x(), c.y()));
+
+        assertEquals((int)handle.invokeExact(new C(100, 1)),  hashCombiner(100, 1));
+        assertEquals((int)handle.invokeExact(new C(0, 0)),    hashCombiner(0, 0));
+        assertEquals((int)handle.invokeExact(new C(-1, 100)), hashCombiner(-1, 100));
+        assertEquals((int)handle.invokeExact(new C(100, 1)),  hashCombiner(100, 1));
+        assertEquals((int)handle.invokeExact(new C(100, -1)), hashCombiner(100, -1));
+    }
+
+    public void testHashCodeEmpty() throws Throwable {
+        CallSite cs = (CallSite)ObjectMethods.bootstrap(LOOKUP, "hashCode", Empty.HASHCODE_DESC, Empty.class, "", Empty.ACCESSORS);
+        MethodHandle handle = cs.dynamicInvoker();
+        Empty e = new Empty();
+        assertEquals((int)handle.invokeExact(e), 0);
+    }
+
+    public void testToStringC() throws Throwable {
+        CallSite cs = (CallSite)ObjectMethods.bootstrap(LOOKUP, "toString", C.TO_STRING_DESC, C.class, C.NAME_LIST, C.ACCESSORS);
+        MethodHandle handle = cs.dynamicInvoker();
+        assertEquals((String)handle.invokeExact(new C(8, 9)),    "C[x=8, y=9]"   );
+        assertEquals((String)handle.invokeExact(new C(10, 11)),  "C[x=10, y=11]" );
+        assertEquals((String)handle.invokeExact(new C(100, -9)), "C[x=100, y=-9]");
+        assertEquals((String)handle.invokeExact(new C(0, 0)),    "C[x=0, y=0]"   );
+    }
+
+    public void testToStringEmpty() throws Throwable {
+        CallSite cs = (CallSite)ObjectMethods.bootstrap(LOOKUP, "toString", Empty.TO_STRING_DESC, Empty.class, Empty.NAME_LIST, Empty.ACCESSORS);
+        MethodHandle handle = cs.dynamicInvoker();
+        assertEquals((String)handle.invokeExact(new Empty()),    "Empty[]");
+    }
+
+    Class<NullPointerException> NPE = NullPointerException.class;
+    Class<IllegalArgumentException> IAE = IllegalArgumentException.class;
+
+    public void exceptions()  {
+        assertThrows(IAE, () -> ObjectMethods.bootstrap(LOOKUP, "badName",  C.EQUALS_DESC,    C.class,         C.NAME_LIST, C.ACCESSORS));
+        assertThrows(IAE, () -> ObjectMethods.bootstrap(LOOKUP, "toString", C.TO_STRING_DESC, C.class,         "x;y;z",     C.ACCESSORS));
+        assertThrows(IAE, () -> ObjectMethods.bootstrap(LOOKUP, "toString", C.TO_STRING_DESC, C.class,         "x;y",       new MethodHandle[]{}));
+        assertThrows(IAE, () -> ObjectMethods.bootstrap(LOOKUP, "toString", C.TO_STRING_DESC, this.getClass(), "x;y",       C.ACCESSORS));
+
+        assertThrows(IAE, () -> ObjectMethods.bootstrap(LOOKUP, "toString", C.EQUALS_DESC,    C.class, "x;y", C.ACCESSORS));
+        assertThrows(IAE, () -> ObjectMethods.bootstrap(LOOKUP, "hashCode", C.TO_STRING_DESC, C.class, "x;y", C.ACCESSORS));
+        assertThrows(IAE, () -> ObjectMethods.bootstrap(LOOKUP, "equals",   C.HASHCODE_DESC,  C.class, "x;y", C.ACCESSORS));
+
+        record NamePlusType(String mn, MethodType mt) {}
+        List<NamePlusType> namePlusTypeList = List.of(
+                new NamePlusType("toString", C.TO_STRING_DESC),
+                new NamePlusType("equals", C.EQUALS_DESC),
+                new NamePlusType("hashCode", C.HASHCODE_DESC)
+        );
+
+        for (NamePlusType npt : namePlusTypeList) {
+            assertThrows(NPE, () -> ObjectMethods.bootstrap(LOOKUP, npt.mn(), npt.mt(), C.class, "x;y", null));
+            assertThrows(NPE, () -> ObjectMethods.bootstrap(LOOKUP, npt.mn(), npt.mt(), C.class, "x;y", new MethodHandle[]{null}));
+            assertThrows(NPE, () -> ObjectMethods.bootstrap(LOOKUP, npt.mn(), npt.mt(), C.class, null,  C.ACCESSORS));
+            assertThrows(NPE, () -> ObjectMethods.bootstrap(LOOKUP, npt.mn(), npt.mt(), null,    "x;y", C.ACCESSORS));
+            assertThrows(NPE, () -> ObjectMethods.bootstrap(LOOKUP, npt.mn(), null,     C.class, "x;y", C.ACCESSORS));
+            assertThrows(NPE, () -> ObjectMethods.bootstrap(LOOKUP, null,     npt.mt(), C.class, "x;y", C.ACCESSORS));
+            assertThrows(NPE, () -> ObjectMethods.bootstrap(null, npt.mn(),     npt.mt(), C.class, "x;y", C.ACCESSORS));
+        }
+    }
+
+    // Based on the ObjectMethods internal implementation
+    private static int hashCombiner(int x, int y) {
+        return x*31 + y;
+    }
+}
diff --git a/ojluni/src/test/java/lang/runtime/SwitchBootstrapsTest.java b/ojluni/src/test/java/lang/runtime/SwitchBootstrapsTest.java
new file mode 100644
index 00000000000..9e308d963d5
--- /dev/null
+++ b/ojluni/src/test/java/lang/runtime/SwitchBootstrapsTest.java
@@ -0,0 +1,354 @@
+/*
+ * Copyright (c) 2021, Oracle and/or its affiliates. All rights reserved.
+ * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
+ *
+ * This code is free software; you can redistribute it and/or modify it
+ * under the terms of the GNU General Public License version 2 only, as
+ * published by the Free Software Foundation.  Oracle designates this
+ * particular file as subject to the "Classpath" exception as provided
+ * by Oracle in the LICENSE file that accompanied this code.
+ *
+ * This code is distributed in the hope that it will be useful, but WITHOUT
+ * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
+ * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
+ * version 2 for more details (a copy is included in the LICENSE file that
+ * accompanied this code).
+ *
+ * You should have received a copy of the GNU General Public License version
+ * 2 along with this work; if not, write to the Free Software Foundation,
+ * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
+ *
+ * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
+ * or visit www.oracle.com if you need additional information or have any
+ * questions.
+ */
+
+package test.java.lang.runtime;
+
+import java.io.Serializable;
+import java.lang.Enum.EnumDesc;
+import java.lang.constant.ClassDesc;
+import java.lang.invoke.CallSite;
+import java.lang.invoke.MethodHandle;
+import java.lang.invoke.MethodHandles;
+import java.lang.invoke.MethodType;
+import java.lang.runtime.SwitchBootstraps;
+import java.util.concurrent.atomic.AtomicBoolean;
+
+import org.testng.annotations.Test;
+
+
+import static org.testng.Assert.assertEquals;
+import static org.testng.Assert.assertFalse;
+import static org.testng.Assert.assertTrue;
+import static org.testng.Assert.fail;
+
+/**
+ * @test
+ * @bug 8318144
+ * @enablePreview
+ * @compile SwitchBootstrapsTest.java
+ * @run testng/othervm SwitchBootstrapsTest
+ */
+@Test
+public class SwitchBootstrapsTest {
+
+    public static final MethodHandle BSM_TYPE_SWITCH;
+    public static final MethodHandle BSM_ENUM_SWITCH;
+
+    static {
+        try {
+            BSM_TYPE_SWITCH = MethodHandles.lookup().findStatic(SwitchBootstraps.class, "typeSwitch",
+                                                                MethodType.methodType(CallSite.class, MethodHandles.Lookup.class, String.class, MethodType.class, Object[].class));
+            BSM_ENUM_SWITCH = MethodHandles.lookup().findStatic(SwitchBootstraps.class, "enumSwitch",
+                                                                MethodType.methodType(CallSite.class, MethodHandles.Lookup.class, String.class, MethodType.class, Object[].class));
+        }
+        catch (ReflectiveOperationException e) {
+            throw new AssertionError("Should not happen", e);
+        }
+    }
+
+    private void testType(Object target, int start, int result, Object... labels) throws Throwable {
+        MethodType switchType = MethodType.methodType(int.class, Object.class, int.class);
+        MethodHandle indy = ((CallSite) BSM_TYPE_SWITCH.invoke(MethodHandles.lookup(), "", switchType, labels)).dynamicInvoker();
+        assertEquals((int) indy.invoke(target, start), result);
+        assertEquals(-1, (int) indy.invoke(null, start));
+    }
+
+    private void testEnum(Enum<?> target, int start, int result, Object... labels) throws Throwable {
+        testEnum(target.getClass(), target, start, result, labels);
+    }
+
+    private void testEnum(Class<?> targetClass, Enum<?> target, int start, int result, Object... labels) throws Throwable {
+        MethodType switchType = MethodType.methodType(int.class, targetClass, int.class);
+        MethodHandle indy = ((CallSite) BSM_ENUM_SWITCH.invoke(MethodHandles.lookup(), "", switchType, labels)).dynamicInvoker();
+        assertEquals((int) indy.invoke(target, start), result);
+        assertEquals(-1, (int) indy.invoke(null, start));
+    }
+
+    public enum E1 {
+        A,
+        B;
+    }
+
+    public enum E2 {
+        C;
+    }
+
+    public void testTypes() throws Throwable {
+        testType("", 0, 0, String.class, Object.class);
+        testType("", 0, 0, Object.class);
+        testType("", 0, 1, Integer.class);
+        testType("", 0, 1, Integer.class, Serializable.class);
+        testType(E1.A, 0, 0, E1.class, Object.class);
+        testType(E2.C, 0, 1, E1.class, Object.class);
+        testType(new Serializable() { }, 0, 1, Comparable.class, Serializable.class);
+        testType("", 0, 0, "", String.class);
+        testType("", 1, 1, "", String.class);
+        testType("a", 0, 1, "", String.class);
+        testType(1, 0, 0, 1, Integer.class);
+        testType(2, 0, 1, 1, Integer.class);
+        testType(Byte.valueOf((byte) 1), 0, 0, 1, Integer.class);
+        testType(Short.valueOf((short) 1), 0, 0, 1, Integer.class);
+        testType(Character.valueOf((char) 1), 0, 0, 1, Integer.class);
+        testType(Integer.valueOf((int) 1), 0, 0, 1, Integer.class);
+        try {
+            testType(1, 0, 1, 1.0, Integer.class);
+            fail("Didn't get the expected exception.");
+        } catch (IllegalArgumentException ex) {
+            //OK
+        }
+        testType("", 0, 0, String.class, String.class, String.class);
+        testType("", 1, 1, String.class, String.class, String.class);
+        testType("", 2, 2, String.class, String.class, String.class);
+        testType("", 0, 0);
+    }
+
+    public void testEnums() throws Throwable {
+        testEnum(E1.A, 0, 2, "B", "C", "A", E1.class);
+        testEnum(E1.B, 0, 0, "B", "C", "A", E1.class);
+        testEnum(E1.B, 1, 3, "B", "C", "A", E1.class);
+        try {
+            testEnum(E1.B, 1, 3, "B", "C", "A", E2.class);
+            fail("Didn't get the expected exception.");
+        } catch (IllegalArgumentException ex) {
+            //OK
+        }
+        try {
+            testEnum(E1.B, 1, 3, "B", "C", "A", String.class);
+            fail("Didn't get the expected exception.");
+        } catch (IllegalArgumentException ex) {
+            //OK
+        }
+        testEnum(E1.B, 0, 0, "B", "A");
+        testEnum(E1.A, 0, 1, "B", "A");
+        testEnum(E1.A, 0, 0, "A", "A", "B");
+        testEnum(E1.A, 1, 1, "A", "A", "B");
+        testEnum(E1.A, 2, 3, "A", "A", "B");
+        testEnum(E1.A, 0, 0);
+    }
+
+    public void testEnumsWithConstants() throws Throwable {
+        enum E {
+            A {},
+            B {},
+            C {}
+        }
+        ClassDesc eDesc = E.class.describeConstable().get();
+        Object[] typeParams = new Object[] {
+            EnumDesc.of(eDesc, "A"),
+            EnumDesc.of(eDesc, "B"),
+            EnumDesc.of(eDesc, "C"),
+            "a",
+            String.class
+        };
+        testType(E.A, 0, 0, typeParams);
+        testType(E.B, 0, 1, typeParams);
+        testType(E.C, 0, 2, typeParams);
+        testType("a", 0, 3, typeParams);
+        testType("x", 0, 4, typeParams);
+        testType('a', 0, 5, typeParams);
+        testEnum(E.class, E.A, 0, 0, "A", "B", "C");
+        testEnum(E.class, E.B, 0, 1, "A", "B", "C");
+        testEnum(E.class, E.C, 0, 2, "A", "B", "C");
+    }
+
+    public void testWrongSwitchTypes() throws Throwable {
+        MethodType[] switchTypes = new MethodType[] {
+            MethodType.methodType(int.class, Object.class),
+            MethodType.methodType(int.class, double.class, int.class),
+            MethodType.methodType(int.class, Object.class, Integer.class)
+        };
+        for (MethodType switchType : switchTypes) {
+            try {
+                BSM_TYPE_SWITCH.invoke(MethodHandles.lookup(), "", switchType);
+                fail("Didn't get the expected exception.");
+            } catch (IllegalArgumentException ex) {
+                //OK, expected
+            }
+        }
+        MethodType[] enumSwitchTypes = new MethodType[] {
+            MethodType.methodType(int.class, Enum.class),
+            MethodType.methodType(int.class, Object.class, int.class),
+            MethodType.methodType(int.class, double.class, int.class),
+            MethodType.methodType(int.class, Enum.class, Integer.class)
+        };
+        for (MethodType enumSwitchType : enumSwitchTypes) {
+            try {
+                BSM_ENUM_SWITCH.invoke(MethodHandles.lookup(), "", enumSwitchType);
+                fail("Didn't get the expected exception.");
+            } catch (IllegalArgumentException ex) {
+                //OK, expected
+            }
+        }
+    }
+
+    public void testSwitchLabelTypes() throws Throwable {
+        enum E {A}
+        try {
+            testType(E.A, 0, -1, E.A);
+            fail("Didn't get the expected exception.");
+        } catch (IllegalArgumentException ex) {
+            //OK, expected
+        }
+    }
+
+    public void testSwitchQualifiedEnum() throws Throwable {
+        enum E {A, B, C}
+        Object[] labels = new Object[] {
+            EnumDesc.of(ClassDesc.of(E.class.getName()), "A"),
+            EnumDesc.of(ClassDesc.of(E.class.getName()), "B"),
+            EnumDesc.of(ClassDesc.of(E.class.getName()), "C")
+        };
+        testType(E.A, 0, 0, labels);
+        testType(E.B, 0, 1, labels);
+        testType(E.C, 0, 2, labels);
+    }
+
+    public void testNullLabels() throws Throwable {
+        MethodType switchType = MethodType.methodType(int.class, Object.class, int.class);
+        try {
+            BSM_TYPE_SWITCH.invoke(MethodHandles.lookup(), "", switchType, (Object[]) null);
+            fail("Didn't get the expected exception.");
+        } catch (NullPointerException ex) {
+            //OK
+        }
+        try {
+            BSM_TYPE_SWITCH.invoke(MethodHandles.lookup(), "", switchType,
+                                   new Object[] {1, null, String.class});
+            fail("Didn't get the expected exception.");
+        } catch (IllegalArgumentException ex) {
+            //OK
+        }
+        MethodType enumSwitchType = MethodType.methodType(int.class, E1.class, int.class);
+        try {
+            BSM_TYPE_SWITCH.invoke(MethodHandles.lookup(), "", enumSwitchType, (Object[]) null);
+            fail("Didn't get the expected exception.");
+        } catch (NullPointerException ex) {
+            //OK
+        }
+        try {
+            BSM_TYPE_SWITCH.invoke(MethodHandles.lookup(), "", enumSwitchType,
+                                   new Object[] {1, null, String.class});
+            fail("Didn't get the expected exception.");
+        } catch (IllegalArgumentException ex) {
+            //OK
+        }
+    }
+
+    private static AtomicBoolean enumInitialized = new AtomicBoolean();
+    public void testEnumInitialization1() throws Throwable {
+        enumInitialized.set(false);
+
+        enum E {
+            A;
+
+            static {
+                enumInitialized.set(true);
+            }
+        }
+
+        MethodType enumSwitchType = MethodType.methodType(int.class, E.class, int.class);
+
+        CallSite invocation = (CallSite) BSM_ENUM_SWITCH.invoke(MethodHandles.lookup(), "", enumSwitchType, new Object[] {"A"});
+        assertFalse(enumInitialized.get());
+        assertEquals(invocation.dynamicInvoker().invoke(null, 0), -1);
+        assertFalse(enumInitialized.get());
+        E e = E.A;
+        assertTrue(enumInitialized.get());
+        assertEquals(invocation.dynamicInvoker().invoke(e, 0), 0);
+    }
+
+    public void testEnumInitialization2() throws Throwable {
+        enumInitialized.set(false);
+
+        enum E {
+            A;
+
+            static {
+                enumInitialized.set(true);
+            }
+        }
+
+        MethodType switchType = MethodType.methodType(int.class, Object.class, int.class);
+        Object[] labels = new Object[] {
+            EnumDesc.of(ClassDesc.of(E.class.getName()), "A"),
+            "test"
+        };
+        CallSite invocation = (CallSite) BSM_TYPE_SWITCH.invoke(MethodHandles.lookup(), "", switchType, labels);
+        assertFalse(enumInitialized.get());
+        assertEquals(invocation.dynamicInvoker().invoke(null, 0), -1);
+        assertFalse(enumInitialized.get());
+        assertEquals(invocation.dynamicInvoker().invoke("test", 0), 1);
+        assertFalse(enumInitialized.get());
+        E e = E.A;
+        assertTrue(enumInitialized.get());
+        assertEquals(invocation.dynamicInvoker().invoke(e, 0), 0);
+    }
+
+    public void testIncorrectEnumLabels() throws Throwable {
+        try {
+            testEnum(E1.B, 0, -1, "B", 1);
+            fail("Didn't get the expected exception.");
+        } catch (IllegalArgumentException ex) {
+            //OK
+        }
+        try {
+            testEnum(E1.B, 0, -1, "B", null);
+            fail("Didn't get the expected exception.");
+        } catch (IllegalArgumentException ex) {
+            //OK
+        }
+    }
+
+    public void testIncorrectEnumStartIndex() throws Throwable {
+        try {
+            testEnum(E1.B, -1, -1, "B");
+            fail("Didn't get the expected exception.");
+        } catch (IndexOutOfBoundsException ex) {
+            //OK
+        }
+        try {
+            testEnum(E1.B, 2, -1, "B");
+            fail("Didn't get the expected exception.");
+        } catch (IndexOutOfBoundsException ex) {
+            //OK
+        }
+    }
+
+    public void testIncorrectTypeStartIndex() throws Throwable {
+        try {
+            testType("", -1, -1, "");
+            fail("Didn't get the expected exception.");
+        } catch (IndexOutOfBoundsException ex) {
+            //OK
+        }
+        try {
+            testType("", 2, -1, "");
+            fail("Didn't get the expected exception.");
+        } catch (IndexOutOfBoundsException ex) {
+            //OK
+        }
+    }
+
+}
diff --git a/ojluni/src/test/java/time/tck/java/time/TCKDuration.java b/ojluni/src/test/java/time/tck/java/time/TCKDuration.java
index d72e4a64eb8..b870c7ea948 100644
--- a/ojluni/src/test/java/time/tck/java/time/TCKDuration.java
+++ b/ojluni/src/test/java/time/tck/java/time/TCKDuration.java
@@ -912,6 +912,20 @@ public class TCKDuration extends AbstractTCKTest {
         assertEquals(Duration.ofSeconds(-1, -1).isZero(), false);
     }
 
+    @Test
+    public void test_isPositive() {
+        assertEquals(Duration.ofNanos(0).isPositive(), false);
+        assertEquals(Duration.ofSeconds(0).isPositive(), false);
+        assertEquals(Duration.ofNanos(1).isPositive(), true);
+        assertEquals(Duration.ofSeconds(1).isPositive(), true);
+        assertEquals(Duration.ofSeconds(1, 1).isPositive(), true);
+        assertEquals(Duration.ofSeconds(Long.MAX_VALUE, 999_999_999).isPositive(), true);
+        assertEquals(Duration.ofNanos(-1).isPositive(), false);
+        assertEquals(Duration.ofSeconds(-1).isPositive(), false);
+        assertEquals(Duration.ofSeconds(-1, -1).isPositive(), false);
+        assertEquals(Duration.ofSeconds(Long.MIN_VALUE).isPositive(), false);
+    }
+
     @Test
     public void test_isNegative() {
         assertEquals(Duration.ofNanos(0).isNegative(), false);
diff --git a/ojluni/src/test/java/time/tck/java/time/format/TCKFormatStyle.java b/ojluni/src/test/java/time/tck/java/time/format/TCKFormatStyle.java
index 7de2083a358..767f00774ba 100644
--- a/ojluni/src/test/java/time/tck/java/time/format/TCKFormatStyle.java
+++ b/ojluni/src/test/java/time/tck/java/time/format/TCKFormatStyle.java
@@ -99,20 +99,19 @@ public class TCKFormatStyle {
     Object[][] data_formatStyle() {
         return new Object[][] {
                 // Android-changed: date/time patterns changed in new CLDR; adapt to UK locale.
-                {ZonedDateTime.of(LocalDateTime.of(2001, 10, 2, 1, 2, 3), ZONEID_PARIS), FormatStyle.FULL, "Tuesday 2 October 2001 at 01:02:03 Central European Summer Time Europe/Paris"},
+                {ZonedDateTime.of(LocalDateTime.of(2001, 10, 2, 1, 2, 3), ZONEID_PARIS), FormatStyle.FULL, "Tuesday, 2 October 2001 at 01:02:03 Central European Summer Time Europe/Paris"},
                 {ZonedDateTime.of(LocalDateTime.of(2001, 10, 2, 1, 2, 3), ZONEID_PARIS), FormatStyle.LONG, "2 October 2001 at 01:02:03 CEST Europe/Paris"},
                 {ZonedDateTime.of(LocalDateTime.of(2001, 10, 2, 1, 2, 3), ZONEID_PARIS), FormatStyle.MEDIUM, "2 Oct 2001, 01:02:03 Europe/Paris"},
                 {ZonedDateTime.of(LocalDateTime.of(2001, 10, 2, 1, 2, 3), ZONEID_PARIS), FormatStyle.SHORT, "02/10/2001, 01:02 Europe/Paris"},
 
-                {ZonedDateTime.of(LocalDateTime.of(2001, 10, 2, 1, 2, 3), OFFSET_PTWO), FormatStyle.FULL, "Tuesday 2 October 2001 at 01:02:03 +02:00 +02:00"},
+                {ZonedDateTime.of(LocalDateTime.of(2001, 10, 2, 1, 2, 3), OFFSET_PTWO), FormatStyle.FULL, "Tuesday, 2 October 2001 at 01:02:03 +02:00 +02:00"},
                 {ZonedDateTime.of(LocalDateTime.of(2001, 10, 2, 1, 2, 3), OFFSET_PTWO), FormatStyle.LONG, "2 October 2001 at 01:02:03 +02:00 +02:00"},
                 {ZonedDateTime.of(LocalDateTime.of(2001, 10, 2, 1, 2, 3), OFFSET_PTWO), FormatStyle.MEDIUM, "2 Oct 2001, 01:02:03 +02:00"},
                 {ZonedDateTime.of(LocalDateTime.of(2001, 10, 2, 1, 2, 3), OFFSET_PTWO), FormatStyle.SHORT, "02/10/2001, 01:02 +02:00"},
         };
     }
 
-    @NonMts(reason = NonMtsReasons.ICU_VERSION_DEPENDENCY,
-        disabledUntilSdk = VersionCodes.VANILLA_ICE_CREAM)
+    @NonMts(reason = NonMtsReasons.ICU_VERSION_DEPENDENCY)
     @Test(dataProvider = "formatStyle")
     public void test_formatStyle(Temporal temporal, FormatStyle style, String formattedStr) {
         DateTimeFormatterBuilder builder = new DateTimeFormatterBuilder();
diff --git a/ojluni/src/test/java/time/test/java/time/format/TestNonIsoFormatter.java b/ojluni/src/test/java/time/test/java/time/format/TestNonIsoFormatter.java
index 7622b904d0c..ffeb624e2b4 100644
--- a/ojluni/src/test/java/time/test/java/time/format/TestNonIsoFormatter.java
+++ b/ojluni/src/test/java/time/test/java/time/format/TestNonIsoFormatter.java
@@ -76,7 +76,9 @@ public class TestNonIsoFormatter {
 
     private static final LocalDate IsoDate = LocalDate.of(2013, 2, 11);
 
-    private static final Locale ARABIC = new Locale("ar");
+    // Android-changed: Android uses CLDR data.
+    // private static final Locale ARABIC = new Locale("ar");
+    private static final Locale ARABIC = new Locale("ar", "EG");
     private static final Locale thTH = new Locale("th", "TH");
     private static final Locale thTHTH = Locale.forLanguageTag("th-TH-u-nu-thai");
     private static final Locale jaJPJP = Locale.forLanguageTag("ja-JP-u-ca-japanese");
diff --git a/ojluni/src/test/java/time/test/java/time/format/TestUnicodeExtension.java b/ojluni/src/test/java/time/test/java/time/format/TestUnicodeExtension.java
index b0e84c1ee11..90b6b432dc8 100644
--- a/ojluni/src/test/java/time/test/java/time/format/TestUnicodeExtension.java
+++ b/ojluni/src/test/java/time/test/java/time/format/TestUnicodeExtension.java
@@ -35,7 +35,9 @@ import static org.testng.Assert.assertEquals;
 import android.icu.util.VersionInfo;
 
 import libcore.test.annotation.NonCts;
+import libcore.test.annotation.NonMts;
 import libcore.test.reasons.NonCtsReasons;
+import libcore.test.reasons.NonMtsReasons;
 
 import java.time.DayOfWeek;
 import java.time.ZonedDateTime;
@@ -486,7 +488,7 @@ public class TestUnicodeExtension {
             {"cnurc", "Asia/Urumqi"},
             {"cobog", "America/Bogota"},
             {"crsjo", "America/Costa_Rica"},
-            {"cst6cdt", "CST6CDT"},
+            {"cst6cdt", "America/Chicago"},
             {"cuhav", "America/Havana"},
             {"cvrai", "Atlantic/Cape_Verde"},
             {"cxxch", "Indian/Christmas"},
@@ -508,7 +510,7 @@ public class TestUnicodeExtension {
             {"esceu", "Africa/Ceuta"},
             {"eslpa", "Atlantic/Canary"},
             {"esmad", "Europe/Madrid"},
-            {"est5edt", "EST5EDT"},
+            {"est5edt", "America/New_York"},
             {"etadd", "Africa/Addis_Ababa"},
             {"fihel", "Europe/Helsinki"},
             {"fimhq", "Europe/Mariehamn"},
@@ -605,7 +607,7 @@ public class TestUnicodeExtension {
             {"mkskp", "Europe/Skopje"},
             {"mlbko", "Africa/Bamako"},
             {"mmrgn", "Asia/Rangoon"},
-            {"mncoq", "Asia/Choibalsan"},
+            {"mncoq", "Asia/Ulaanbaatar"},
             {"mnhvd", "Asia/Hovd"},
             {"mnuln", "Asia/Ulaanbaatar"},
             {"momfm", "Asia/Macau"},
@@ -613,7 +615,7 @@ public class TestUnicodeExtension {
             {"mqfdf", "America/Martinique"},
             {"mrnkc", "Africa/Nouakchott"},
             {"msmni", "America/Montserrat"},
-            {"mst7mdt", "MST7MDT"},
+            {"mst7mdt", "America/Denver"},
             {"mtmla", "Europe/Malta"},
             {"muplu", "Indian/Mauritius"},
             {"mvmle", "Indian/Maldives"},
@@ -659,7 +661,7 @@ public class TestUnicodeExtension {
             {"pmmqc", "America/Miquelon"},
             {"pnpcn", "Pacific/Pitcairn"},
             {"prsju", "America/Puerto_Rico"},
-            {"pst8pdt", "PST8PDT"},
+            {"pst8pdt", "America/Los_Angeles"},
             {"ptfnc", "Atlantic/Madeira"},
             {"ptlis", "Europe/Lisbon"},
             {"ptpdl", "Atlantic/Azores"},
@@ -927,6 +929,8 @@ public class TestUnicodeExtension {
             zoneExpected != null ? ZDT.withZoneSameInstant(zoneExpected) : ZDT);
     }
 
+    @NonCts(bug = 383977133, reason = NonCtsReasons.NON_BREAKING_BEHAVIOR_FIX)
+    @NonMts(bug = 383977133, reason = NonMtsReasons.TZDATA_VERSION_DEPENDENCY)
     @Test(dataProvider="shortTZID")
     public void test_shortTZID(String shortID, String expectedZone) {
         Locale l = Locale.forLanguageTag("en-US-u-tz-" + shortID);
diff --git a/openjdk_java_files.bp b/openjdk_java_files.bp
index 499f95febd2..b8057dee4a8 100644
--- a/openjdk_java_files.bp
+++ b/openjdk_java_files.bp
@@ -262,6 +262,7 @@ filegroup {
         "ojluni/src/main/java/java/lang/invoke/LambdaConversionException.java",
         "ojluni/src/main/java/java/lang/invoke/CallSite.java",
         "ojluni/src/main/java/java/lang/invoke/ConstantCallSite.java",
+        "ojluni/src/main/java/java/lang/invoke/DirectMethodHandle.java",
         "ojluni/src/main/java/java/lang/invoke/MethodHandle.java",
         "ojluni/src/main/java/java/lang/invoke/MethodHandles.java",
         "ojluni/src/main/java/java/lang/invoke/MethodHandleImpl.java",
@@ -1507,6 +1508,7 @@ filegroup {
         "ojluni/src/main/java/com/sun/nio/file/SensitivityWatchEventModifier.java",
         "ojluni/src/main/java/java/beans/ChangeListenerMap.java",
         "ojluni/src/main/java/java/lang/BaseVirtualThread.java",
+        "ojluni/src/main/java/java/lang/JavaLangAccess.java",
         "ojluni/src/main/java/java/lang/StringLatin1.java",
         "ojluni/src/main/java/java/lang/StringUTF16.java",
         // Hide the java.lang.constant APIs until master switches away from Android UDC. b/270028670
@@ -1544,7 +1546,6 @@ filegroup {
         "ojluni/src/main/java/jdk/internal/HotSpotIntrinsicCandidate.java",
         "ojluni/src/main/java/jdk/internal/ValueBased.java",
         "ojluni/src/main/java/jdk/internal/access/JavaIOFileDescriptorAccess.java",
-        "ojluni/src/main/java/jdk/internal/access/JavaLangAccess.java",
         "ojluni/src/main/java/jdk/internal/access/JavaObjectInputStreamAccess.java",
         "ojluni/src/main/java/jdk/internal/access/JavaUtilCollectionAccess.java",
         "ojluni/src/main/java/jdk/internal/access/SharedSecrets.java",
@@ -1566,10 +1567,14 @@ filegroup {
         "ojluni/src/main/java/jdk/internal/reflect/CallerSensitive.java",
         "ojluni/src/main/java/jdk/internal/reflect/Reflection.java",
         "ojluni/src/main/java/jdk/internal/vm/annotation/Contended.java",
+        "ojluni/src/main/java/jdk/internal/vm/annotation/DontInline.java",
         "ojluni/src/main/java/jdk/internal/vm/annotation/ForceInline.java",
+        "ojluni/src/main/java/jdk/internal/vm/annotation/Hidden.java",
         "ojluni/src/main/java/jdk/internal/vm/annotation/IntrinsicCandidate.java",
         "ojluni/src/main/java/jdk/internal/vm/annotation/ReservedStackAccess.java",
         "ojluni/src/main/java/jdk/internal/vm/annotation/Stable.java",
+        "ojluni/src/main/java/jdk/internal/vm/Continuation.java",
+        "ojluni/src/main/java/jdk/internal/vm/ContinuationScope.java",
         "ojluni/src/main/java/jdk/internal/vm/StackChunk.java",
         "ojluni/src/main/java/jdk/internal/util/ArraysSupport.java",
         "ojluni/src/main/java/jdk/internal/util/NullableKeyValueHolder.java",
diff --git a/test-rules/src/main/java/libcore/test/annotation/NonCts.java b/test-rules/src/main/java/libcore/test/annotation/NonCts.java
index c280bd48766..f028ee47d43 100644
--- a/test-rules/src/main/java/libcore/test/annotation/NonCts.java
+++ b/test-rules/src/main/java/libcore/test/annotation/NonCts.java
@@ -27,13 +27,9 @@ import java.lang.annotation.Target;
  * Note that every annotation element below should be associated to a field in
  * {@link vogar.expect.Expectation}, because it will be de- and serialized by
  * {@link vogar.expect.ExpectationStore} for back-porting to an older branch.
- *
- * @deprecated All CTS modules supporting @NonCts annotations are expected to migrate to MCTS.
- * Please use {@link NonMts} to skip test in the MCTS instead.
  */
 @Retention(RetentionPolicy.RUNTIME)
 @Target({ElementType.TYPE, ElementType.METHOD})
-@Deprecated
 public @interface NonCts {
     /**
      * Optional bug id showing why this test fails / shouldn't run in MTS.
diff --git a/test-rules/src/main/java/libcore/test/reasons/NonMtsReasons.java b/test-rules/src/main/java/libcore/test/reasons/NonMtsReasons.java
index cd46120819c..e42cc178e9b 100644
--- a/test-rules/src/main/java/libcore/test/reasons/NonMtsReasons.java
+++ b/test-rules/src/main/java/libcore/test/reasons/NonMtsReasons.java
@@ -28,6 +28,13 @@ public class NonMtsReasons {
     public static final String ICU_VERSION_DEPENDENCY = "The API behavior depends on the "
            + "platform version. The test only passes above a certain API level.";
 
+    /**
+     * If the test depends on the tzdata APEX version and version-specific data,
+     * you can use this reason.
+     */
+    public static final String TZDATA_VERSION_DEPENDENCY = "The API behavior depends on the "
+            + "tzdata APEX version.";
+
     /**
      * If the test only passes above a certain API level.
      */
diff --git a/tools/codegen/Android.bp b/tools/codegen/Android.bp
new file mode 100644
index 00000000000..a7fb857e759
--- /dev/null
+++ b/tools/codegen/Android.bp
@@ -0,0 +1,28 @@
+// Copyright (C) 2025 The Android Open Source Project
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
+
+package {
+    // See: http://go/android-license-faq
+    // A large-scale-change added 'default_applicable_licenses' to import
+    // all of the 'license_kinds' from "libcore_license"
+    // to get the below license kinds:
+    //   SPDX-license-identifier-Apache-2.0
+    default_applicable_licenses: ["libcore_license"],
+}
+
+java_binary_host {
+    name: "libcore-methodhandles-accessors-codegen",
+    srcs: ["src/**/*.java"],
+    manifest: "src/manifest.txt",
+}
diff --git a/tools/codegen/src/libcore/codegen/AccessorMethodHandlesGenerator.java b/tools/codegen/src/libcore/codegen/AccessorMethodHandlesGenerator.java
new file mode 100644
index 00000000000..1814f9d528f
--- /dev/null
+++ b/tools/codegen/src/libcore/codegen/AccessorMethodHandlesGenerator.java
@@ -0,0 +1,153 @@
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
+
+package libcore.codegen;
+
+import java.util.ArrayList;
+import java.util.List;
+import java.util.Locale;
+import java.util.StringJoiner;
+
+/**
+ * Generates methods of {@link DirectMethodHandle.Holder} class.
+ */
+public class AccessorMethodHandlesGenerator {
+
+    static String capitalize(String str) {
+        if (str.isEmpty()) {
+            throw new IllegalArgumentException("Can't capitalize empty string");
+        }
+        return Character.toUpperCase(str.charAt(0)) + str.substring(1);
+    }
+
+    enum HandleKind {
+        IPUT,
+        IGET,
+        SPUT,
+        SGET;
+
+        public boolean isStatic() {
+            return this == SGET || this == SPUT;
+        }
+        public boolean isPut() {
+            return this == IPUT || this == SPUT;
+        }
+        public boolean isGet() {
+            return !isPut();
+        }
+
+        /* Prefix of a method in Holder class implementing this HandleKind. */
+        public String prefix() {
+            if (isPut()) {
+                return "put";
+            } else {
+                return "get";
+            }
+        }
+    }
+
+    enum BasicType {
+        BOOLEAN,
+        BYTE,
+        CHAR,
+        SHORT,
+        INT,
+        LONG,
+        DOUBLE,
+        FLOAT,
+        REFERENCE;
+
+        public String typeName() {
+            return this == REFERENCE ? "Object" : name().toLowerCase(Locale.ROOT);
+        }
+
+        /* Returns a string corresponding to a method parameter of this type named as paramName,
+         * for example "int paramName".
+         */
+        public String param(String paramName) {
+            return typeName() + " " + paramName;
+        }
+    }
+
+    static String parameters(HandleKind kind, BasicType actingUpon) {
+        var params = new ArrayList<String>();
+        if (!kind.isStatic()) {
+            params.add(BasicType.REFERENCE.param("base"));
+        }
+
+        if (kind.isPut()) {
+            params.add(actingUpon.param("value"));
+        }
+
+        // There is always MethodHandle object.
+        params.add("MethodHandleImpl mh");
+
+        return String.join(", ", params);
+    }
+
+    static String function(HandleKind kind, BasicType actingUpon, boolean isVolatile) {
+        var sb = new StringBuilder();
+        var modifiersAndReturnType = new StringJoiner(" ");
+        modifiersAndReturnType.add("static");
+        if (kind.isPut()) {
+            modifiersAndReturnType.add("void");
+        } else {
+            modifiersAndReturnType.add(actingUpon.typeName());
+        }
+        sb.append(modifiersAndReturnType).append(" ");
+        sb.append(kind.prefix()).append(capitalize(actingUpon.name().toLowerCase(Locale.ROOT)));
+        if (isVolatile) {
+            sb.append("Volatile");
+        }
+        sb.append("(").append(parameters(kind, actingUpon)).append(") {\n");
+
+        if (kind.isStatic()) {
+            sb.append("  ").append("Object base = staticBase(mh);\n");
+            sb.append("  ").append("long offset = staticOffset(mh);\n");
+        } else {
+            sb.append("  ").append("checkBase(base);\n");
+            sb.append("  ").append("long offset = fieldOffset(mh);\n");
+        }
+        var accessMode = isVolatile ? "Volatile" : "";
+        sb.append("  ");
+        if (kind.isGet()) {
+            sb.append("return UNSAFE.")
+                .append(kind.prefix())
+                .append(capitalize(actingUpon.name().toLowerCase(Locale.ROOT)))
+                .append(accessMode)
+                .append("(base, offset);");
+        } else {
+            sb.append("UNSAFE.")
+                .append(kind.prefix())
+                .append(capitalize(actingUpon.name().toLowerCase(Locale.ROOT)))
+                .append(accessMode)
+                .append("(base, offset, value);");
+        }
+
+        sb.append("\n}\n");
+        return sb.toString();
+    }
+
+    public static void main(String[] args) {
+        for (HandleKind kind : HandleKind.values()) {
+            for (BasicType name : BasicType.values()) {
+                for (boolean isVolatile : List.of(false, true)) {
+                    System.out.println(function(kind, name, isVolatile));
+                }
+            }
+        }
+    }
+}
\ No newline at end of file
diff --git a/tools/codegen/src/manifest.txt b/tools/codegen/src/manifest.txt
new file mode 100644
index 00000000000..452cead9942
--- /dev/null
+++ b/tools/codegen/src/manifest.txt
@@ -0,0 +1 @@
+Main-Class: libcore.codegen.AccessorMethodHandlesGenerator
\ No newline at end of file
```

