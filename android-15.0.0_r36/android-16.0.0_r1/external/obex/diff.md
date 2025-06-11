```diff
diff --git a/Android.bp b/Android.bp
index 50f0832..05b2a45 100644
--- a/Android.bp
+++ b/Android.bp
@@ -1,6 +1,6 @@
 // OBEX library
 package {
-  default_applicable_licenses: ["obex_license"],
+    default_applicable_licenses: ["obex_license"],
 }
 
 // Added automatically by a large-scale-change that took the approach of
@@ -18,24 +18,101 @@ package {
 // used in the current project.
 // See: http://go/android-license-faq
 license {
-  name: "obex_license",
-  visibility: [":__subpackages__"],
-  license_kinds: [
-    "SPDX-license-identifier-Apache-2.0",
-    "SPDX-license-identifier-BSD",
-  ],
-  license_text: [
-    "LICENSE",
-  ],
+    name: "obex_license",
+    visibility: [":__subpackages__"],
+    license_kinds: [
+        "SPDX-license-identifier-Apache-2.0",
+        "SPDX-license-identifier-BSD",
+    ],
+    license_text: [
+        "LICENSE",
+    ],
 }
 
 java_library {
-  name: "com.android.obex",
+    name: "com.android.obex",
 
-  srcs: ["**/*.java"],
-  apex_available: [
-        "com.android.btservices",
-  ],
-  sdk_version: "module_current",
-  min_sdk_version: "Tiramisu",
+    srcs: ["**/*.java"],
+    apex_available: ["com.android.bt"],
+    sdk_version: "module_current",
+    min_sdk_version: "Tiramisu",
+
+    errorprone: {
+        enabled: true,
+        javacflags: [
+            "-Xep:AlmostJavadoc:ERROR",
+            "-Xep:AlreadyChecked:ERROR",
+            "-Xep:BadImport:ERROR",
+            "-Xep:CatchAndPrintStackTrace:ERROR",
+            "-Xep:CatchFail:ERROR",
+            "-Xep:CheckReturnValue:ERROR",
+            "-Xep:ClassCanBeStatic:ERROR",
+            "-Xep:DateFormatConstant:ERROR",
+            "-Xep:DirectInvocationOnMock:ERROR",
+            "-Xep:DuplicateBranches:ERROR",
+            "-Xep:EmptyBlockTag:ERROR",
+            "-Xep:EmptyCatch:ERROR",
+            "-Xep:EnumOrdinal:ERROR",
+            "-Xep:EqualsGetClass:ERROR",
+            "-Xep:EqualsHashCode:ERROR",
+            "-Xep:EqualsIncompatibleType:ERROR",
+            "-Xep:FallThrough:ERROR",
+            "-Xep:Finalize:ERROR",
+            "-Xep:ForEachIterable:ERROR",
+            "-Xep:FutureReturnValueIgnored:ERROR",
+            "-Xep:GuardedBy:ERROR",
+            "-Xep:HidingField:ERROR",
+            "-Xep:InconsistentHashCode:ERROR",
+            "-Xep:InlineFormatString:ERROR",
+            "-Xep:InlineMeInliner:ERROR",
+            "-Xep:InvalidBlockTag:ERROR",
+            "-Xep:InvalidInlineTag:ERROR",
+            "-Xep:InvalidParam:ERROR",
+            "-Xep:JavaUtilDate:ERROR",
+            "-Xep:JdkObsolete:ERROR",
+            "-Xep:LockOnNonEnclosingClassLiteral:ERROR",
+            "-Xep:LongFloatConversion:ERROR",
+            "-Xep:LoopOverCharArray:ERROR",
+            "-Xep:MethodCanBeStatic:ERROR",
+            "-Xep:MissingCasesInEnumSwitch:ERROR",
+            "-Xep:MixedMutabilityReturnType:ERROR",
+            "-Xep:MockNotUsedInProduction:ERROR",
+            "-Xep:ModifiedButNotUsed:ERROR",
+            "-Xep:ModifyCollectionInEnhancedForLoop:ERROR",
+            "-Xep:NarrowCalculation:ERROR",
+            "-Xep:NarrowingCompoundAssignment:ERROR",
+            "-Xep:NonApiType:ERROR",
+            "-Xep:NonAtomicVolatileUpdate:ERROR",
+            "-Xep:NonCanonicalType:ERROR",
+            "-Xep:NotJavadoc:ERROR",
+            "-Xep:NullablePrimitive:ERROR",
+            "-Xep:NullableVoid:ERROR",
+            "-Xep:ObjectEqualsForPrimitives:ERROR",
+            "-Xep:OperatorPrecedence:ERROR",
+            "-Xep:RedundantControlFlow:ERROR",
+            "-Xep:ReferenceEquality:ERROR",
+            "-Xep:ReturnAtTheEndOfVoidFunction:ERROR",
+            "-Xep:ReturnFromVoid:ERROR",
+            "-Xep:StaticAssignmentInConstructor:ERROR",
+            "-Xep:StaticGuardedByInstance:ERROR",
+            "-Xep:StringCaseLocaleUsage:ERROR",
+            "-Xep:StringCharset:ERROR",
+            "-Xep:SynchronizeOnNonFinalField:ERROR",
+            "-Xep:ThreadJoinLoop:ERROR",
+            "-Xep:ToStringReturnsNull:ERROR",
+            "-Xep:TruthConstantAsserts:ERROR",
+            "-Xep:TruthIncompatibleType:ERROR",
+            "-Xep:UndefinedEquals:ERROR",
+            "-Xep:UnnecessaryAssignment:ERROR",
+            "-Xep:UnnecessaryAsync:ERROR",
+            "-Xep:UnnecessaryStringBuilder:ERROR",
+            "-Xep:UnrecognisedJavadocTag:ERROR",
+            "-Xep:UnusedMethod:ERROR",
+            "-Xep:UnusedNestedClass:ERROR",
+            "-Xep:UnusedVariable:ERROR",
+            "-Xep:VariableNameSameAsType:ERROR",
+            "-Xep:WaitNotInLoop:ERROR",
+            "-Xep:WakelockReleasedDangerously:ERROR",
+        ],
+    },
 }
diff --git a/OWNERS b/OWNERS
index 0c632a5..5320981 100644
--- a/OWNERS
+++ b/OWNERS
@@ -2,3 +2,5 @@
 
 klhyun@google.com
 siyuanh@google.com
+
+# No janitors here because there is no upstream; this code came from frameworks/base/.
diff --git a/PREUPLOAD.cfg b/PREUPLOAD.cfg
new file mode 100644
index 0000000..412016a
--- /dev/null
+++ b/PREUPLOAD.cfg
@@ -0,0 +1,27 @@
+[Options]
+ignore_merged_commits = true
+
+[Builtin Hooks]
+bpfmt = true
+commit_msg_changeid_field = true
+commit_msg_bug_field = true
+google_java_format = true
+ktfmt = true
+
+[Builtin Hooks Options]
+bpfmt = -s
+ktfmt = --kotlinlang-style
+
+[Hook Scripts]
+aosp_first = ${REPO_ROOT}/frameworks/base/tools/aosp/aosp_sha.sh ${PREUPLOAD_COMMIT} ${PREUPLOAD_FILES}
+# google_java_format only fixes indentation. This has Android specific checks like "m" prefix.
+checkstyle_hook = ${REPO_ROOT}/prebuilts/checkstyle/checkstyle.py --sha ${PREUPLOAD_COMMIT}
+                  --config_xml checkstyle.xml
+                  -fw android/app/src/com/android/bluetooth/
+                      android/app/lib/mapapi/com/android/bluetooth/mapapi/
+                      android/app/tests/src/com/android/bluetooth/
+                      framework/
+                      service/
+
+[Tool Paths]
+ktfmt = ${REPO_ROOT}/packages/modules/Bluetooth/tools/ktfmt
diff --git a/TEST_MAPPING b/TEST_MAPPING
new file mode 100644
index 0000000..f337913
--- /dev/null
+++ b/TEST_MAPPING
@@ -0,0 +1,7 @@
+{
+  "imports": [
+    {
+      "path": "packages/modules/Bluetooth"
+    }
+  ]
+}
diff --git a/checkstyle.xml b/checkstyle.xml
new file mode 100644
index 0000000..54ddf34
--- /dev/null
+++ b/checkstyle.xml
@@ -0,0 +1,19 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!DOCTYPE module PUBLIC "-//Puppy Crawl//DTD Check Configuration 1.3//EN" "http://www.puppycrawl.com/dtds/configuration_1_3.dtd" [
+  <!ENTITY defaultCopyrightCheck SYSTEM "../../prebuilts/checkstyle/default-copyright-check.xml">
+  <!ENTITY defaultJavadocChecks SYSTEM "../../prebuilts/checkstyle/default-javadoc-checks.xml">
+  <!ENTITY defaultTreewalkerChecks SYSTEM "../../prebuilts/checkstyle/default-treewalker-checks.xml">
+  <!ENTITY defaultModuleChecks SYSTEM "../../prebuilts/checkstyle/default-module-checks.xml">
+]>
+
+<module name="Checker">
+  &defaultModuleChecks;
+  &defaultCopyrightCheck;
+  <module name="TreeWalker">
+    &defaultJavadocChecks;
+    &defaultTreewalkerChecks;
+  </module>
+  <module name="SuppressionFilter">
+    <property name="file" value="checkstyle_suppressions.xml" />
+  </module>
+</module>
diff --git a/checkstyle_suppressions.xml b/checkstyle_suppressions.xml
new file mode 100644
index 0000000..d5319b8
--- /dev/null
+++ b/checkstyle_suppressions.xml
@@ -0,0 +1,6 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!DOCTYPE suppressions PUBLIC "-//Puppy Crawl//DTD Suppressions 1.1//EN" "http://www.puppycrawl.com/dtds/suppressions_1_1.dtd">
+<suppressions>
+    <!-- Let google-java-format handle the ImportOrder. -->
+    <suppress files=".*" checks="ImportOrder" />
+</suppressions>
diff --git a/src/com/android/obex/ApplicationParameter.java b/src/com/android/obex/ApplicationParameter.java
index 138f9a3..f1fa9c6 100644
--- a/src/com/android/obex/ApplicationParameter.java
+++ b/src/com/android/obex/ApplicationParameter.java
@@ -32,9 +32,7 @@
 
 package com.android.obex;
 
-/**
- * Represents an Application Parameter header for OBEX as defined by the IrDA specification.
- */
+/** Represents an Application Parameter header for OBEX as defined by the IrDA specification. */
 public final class ApplicationParameter {
 
     private byte[] mArray;
@@ -43,9 +41,7 @@ public final class ApplicationParameter {
 
     private int mMaxLength = 1000;
 
-    /**
-     * Possible values for the tag field in the Application Parameter header.
-     */
+    /** Possible values for the tag field in the Application Parameter header. */
     public static class TRIPLET_TAGID {
         public static final byte ORDER_TAGID = 0x01;
 
@@ -83,9 +79,7 @@ public final class ApplicationParameter {
         public static final byte RESET_NEW_MISSED_CALLS_TAGID = 0x0F;
     }
 
-    /**
-     * Possible values for the value field in the Application Parameter header.
-     */
+    /** Possible values for the value field in the Application Parameter header. */
     public static class TRIPLET_VALUE {
         public static class ORDER {
             public static final byte ORDER_BY_INDEX = 0x00;
@@ -110,9 +104,7 @@ public final class ApplicationParameter {
         }
     }
 
-    /**
-     * Possible values for the length field in the Application Parameter header.
-     */
+    /** Possible values for the length field in the Application Parameter header. */
     public static class TRIPLET_LENGTH {
         public static final byte ORDER_LENGTH = 1;
 
@@ -145,17 +137,15 @@ public final class ApplicationParameter {
         public static final byte RESETNEWMISSEDCALLS_LENGTH = 1;
     }
 
-    /**
-     * Constructs an ApplicationParameter header
-     */
+    /** Constructs an ApplicationParameter header */
     public ApplicationParameter() {
         mArray = new byte[mMaxLength];
         mLength = 0;
     }
 
     /**
-     * Adds a triplet of tag, length, and value to this application parameter header as per the
-     * IrDA specifications.
+     * Adds a triplet of tag, length, and value to this application parameter header as per the IrDA
+     * specifications.
      *
      * @param tag one of {@link TRIPLET_TAGID}
      * @param len one of {@link TRIPLET_LENGTH}
diff --git a/src/com/android/obex/Authenticator.java b/src/com/android/obex/Authenticator.java
index 0d028e8..1080400 100644
--- a/src/com/android/obex/Authenticator.java
+++ b/src/com/android/obex/Authenticator.java
@@ -33,82 +33,71 @@
 package com.android.obex;
 
 /**
- * This interface provides a way to respond to authentication challenge and
- * authentication response headers. When a client or server receives an
- * authentication challenge or authentication response header, the
- * <code>onAuthenticationChallenge()</code> or
- * <code>onAuthenticationResponse()</code> will be called, respectively, by the
- * implementation.
- * <P>
- * For more information on how the authentication procedure works in OBEX,
- * please review the IrOBEX specification at <A
- * HREF="http://www.irda.org">http://www.irda.org</A>.
- * <P>
- * <STRONG>Authentication Challenges</STRONG>
- * <P>
- * When a client or server receives an authentication challenge header, the
- * <code>onAuthenticationChallenge()</code> method will be invoked by the OBEX
- * API implementation. The application will then return the user name (if
- * needed) and password via a <code>PasswordAuthentication</code> object. The
- * password in this object is not sent in the authentication response. Instead,
- * the 16-byte challenge received in the authentication challenge is combined
- * with the password returned from the <code>onAuthenticationChallenge()</code>
- * method and passed through the MD5 hash algorithm. The resulting value is sent
- * in the authentication response along with the user name if it was provided.
- * <P>
- * <STRONG>Authentication Responses</STRONG>
- * <P>
- * When a client or server receives an authentication response header, the
- * <code>onAuthenticationResponse()</code> method is invoked by the API
- * implementation with the user name received in the authentication response
- * header. (The user name will be <code>null</code> if no user name was provided
- * in the authentication response header.) The application must determine the
- * correct password. This value should be returned from the
- * <code>onAuthenticationResponse()</code> method. If the authentication request
- * should fail without the implementation checking the password,
- * <code>null</code> should be returned by the application. (This is needed for
- * reasons like not recognizing the user name, etc.) If the returned value is
- * not <code>null</code>, the OBEX API implementation will combine the password
- * returned from the <code>onAuthenticationResponse()</code> method and
- * challenge sent via the authentication challenge, apply the MD5 hash
- * algorithm, and compare the result to the response hash received in the
- * authentication response header. If the values are not equal, an
- * <code>IOException</code> will be thrown if the client requested
- * authentication. If the server requested authentication, the
- * <code>onAuthenticationFailure()</code> method will be called on the
- * <code>ServerRequestHandler</code> that failed authentication. The connection
- * is <B>not</B> closed if authentication failed.
+ * This interface provides a way to respond to authentication challenge and authentication response
+ * headers. When a client or server receives an authentication challenge or authentication response
+ * header, the <code>onAuthenticationChallenge()</code> or <code>onAuthenticationResponse()</code>
+ * will be called, respectively, by the implementation.
+ *
+ * <p>For more information on how the authentication procedure works in OBEX, please review the
+ * IrOBEX specification at <A HREF="http://www.irda.org">http://www.irda.org</A>.
+ *
+ * <p><STRONG>Authentication Challenges</STRONG>
+ *
+ * <p>When a client or server receives an authentication challenge header, the <code>
+ * onAuthenticationChallenge()</code> method will be invoked by the OBEX API implementation. The
+ * application will then return the user name (if needed) and password via a <code>
+ * PasswordAuthentication</code> object. The password in this object is not sent in the
+ * authentication response. Instead, the 16-byte challenge received in the authentication challenge
+ * is combined with the password returned from the <code>onAuthenticationChallenge()</code> method
+ * and passed through the MD5 hash algorithm. The resulting value is sent in the authentication
+ * response along with the user name if it was provided.
+ *
+ * <p><STRONG>Authentication Responses</STRONG>
+ *
+ * <p>When a client or server receives an authentication response header, the <code>
+ * onAuthenticationResponse()</code> method is invoked by the API implementation with the user name
+ * received in the authentication response header. (The user name will be <code>null</code> if no
+ * user name was provided in the authentication response header.) The application must determine the
+ * correct password. This value should be returned from the <code>onAuthenticationResponse()</code>
+ * method. If the authentication request should fail without the implementation checking the
+ * password, <code>null</code> should be returned by the application. (This is needed for reasons
+ * like not recognizing the user name, etc.) If the returned value is not <code>null</code>, the
+ * OBEX API implementation will combine the password returned from the <code>
+ * onAuthenticationResponse()</code> method and challenge sent via the authentication challenge,
+ * apply the MD5 hash algorithm, and compare the result to the response hash received in the
+ * authentication response header. If the values are not equal, an <code>IOException</code> will be
+ * thrown if the client requested authentication. If the server requested authentication, the <code>
+ * onAuthenticationFailure()</code> method will be called on the <code>ServerRequestHandler</code>
+ * that failed authentication. The connection is <B>not</B> closed if authentication failed.
  */
 public interface Authenticator {
 
     /**
-     * Called when a client or a server receives an authentication challenge
-     * header. It should respond to the challenge with a
-     * <code>PasswordAuthentication</code> that contains the correct user name
-     * and password for the challenge.
-     * @param description the description of which user name and password should
-     *        be used; if no description is provided in the authentication
-     *        challenge or the description is encoded in an encoding scheme that
-     *        is not supported, an empty string will be provided
-     * @param isUserIdRequired <code>true</code> if the user ID is required;
-     *        <code>false</code> if the user ID is not required
-     * @param isFullAccess <code>true</code> if full access to the server will
-     *        be granted; <code>false</code> if read only access will be granted
-     * @return a <code>PasswordAuthentication</code> object containing the user
-     *         name and password used for authentication
+     * Called when a client or a server receives an authentication challenge header. It should
+     * respond to the challenge with a <code>PasswordAuthentication</code> that contains the correct
+     * user name and password for the challenge.
+     *
+     * @param description the description of which user name and password should be used; if no
+     *     description is provided in the authentication challenge or the description is encoded in
+     *     an encoding scheme that is not supported, an empty string will be provided
+     * @param isUserIdRequired <code>true</code> if the user ID is required; <code>false</code> if
+     *     the user ID is not required
+     * @param isFullAccess <code>true</code> if full access to the server will be granted; <code>
+     *     false</code> if read only access will be granted
+     * @return a <code>PasswordAuthentication</code> object containing the user name and password
+     *     used for authentication
      */
-    PasswordAuthentication onAuthenticationChallenge(String description, boolean isUserIdRequired,
-            boolean isFullAccess);
+    PasswordAuthentication onAuthenticationChallenge(
+            String description, boolean isUserIdRequired, boolean isFullAccess);
 
     /**
-     * Called when a client or server receives an authentication response
-     * header. This method will provide the user name and expect the correct
-     * password to be returned.
-     * @param userName the user name provided in the authentication response; may
-     *        be <code>null</code>
-     * @return the correct password for the user name provided; if
-     *         <code>null</code> is returned then the authentication request
-     *         failed
+     * Called when a client or server receives an authentication response header. This method will
+     * provide the user name and expect the correct password to be returned.
+     *
+     * @param userName the user name provided in the authentication response; may be <code>null
+     *     </code>
+     * @return the correct password for the user name provided; if <code>null</code> is returned
+     *     then the authentication request failed
      */
     byte[] onAuthenticationResponse(byte[] userName);
 }
diff --git a/src/com/android/obex/BaseStream.java b/src/com/android/obex/BaseStream.java
index f656a67..23b57cc 100644
--- a/src/com/android/obex/BaseStream.java
+++ b/src/com/android/obex/BaseStream.java
@@ -35,40 +35,42 @@ package com.android.obex;
 import java.io.IOException;
 
 /**
- * This interface defines the methods needed by a parent that uses the
- * PrivateInputStream and PrivateOutputStream objects defined in this package.
+ * This interface defines the methods needed by a parent that uses the PrivateInputStream and
+ * PrivateOutputStream objects defined in this package.
  */
 public interface BaseStream {
 
     /**
      * Verifies that this object is still open.
+     *
      * @throws IOException if the object is closed
      */
     void ensureOpen() throws IOException;
 
     /**
-     * Verifies that additional information may be sent. In other words, the
-     * operation is not done.
+     * Verifies that additional information may be sent. In other words, the operation is not done.
+     *
      * @throws IOException if the operation is completed
      */
     void ensureNotDone() throws IOException;
 
     /**
      * Continues the operation since there is no data to read.
-     * @param sendEmpty <code>true</code> if the operation should send an empty
-     *        packet or not send anything if there is no data to send
-     * @param inStream <code>true</code> if the stream is input stream or is
-     *        output stream
-     * @return <code>true</code> if the operation was completed;
-     *         <code>false</code> if no operation took place
+     *
+     * @param sendEmpty <code>true</code> if the operation should send an empty packet or not send
+     *     anything if there is no data to send
+     * @param inStream <code>true</code> if the stream is input stream or is output stream
+     * @return <code>true</code> if the operation was completed; <code>false</code> if no operation
+     *     took place
      * @throws IOException if an IO error occurs
      */
     boolean continueOperation(boolean sendEmpty, boolean inStream) throws IOException;
 
     /**
      * Called when the output or input stream is closed.
-     * @param inStream <code>true</code> if the input stream is closed;
-     *        <code>false</code> if the output stream is closed
+     *
+     * @param inStream <code>true</code> if the input stream is closed; <code>false</code> if the
+     *     output stream is closed
      * @throws IOException if an IO error occurs
      */
     void streamClosed(boolean inStream) throws IOException;
diff --git a/src/com/android/obex/ClientOperation.java b/src/com/android/obex/ClientOperation.java
index 8aa15c3..a72f929 100644
--- a/src/com/android/obex/ClientOperation.java
+++ b/src/com/android/obex/ClientOperation.java
@@ -46,39 +46,22 @@ import java.io.OutputStream;
  * gets.
  */
 public final class ClientOperation implements Operation, BaseStream {
-
     private static final String TAG = "ClientOperation";
 
-    private static final boolean V = ObexHelper.VDBG;
-
     private ClientSession mParent;
-
     private boolean mInputOpen;
-
     private PrivateInputStream mPrivateInput;
-
     private boolean mPrivateInputOpen;
-
     private PrivateOutputStream mPrivateOutput;
-
     private boolean mPrivateOutputOpen;
-
     private String mExceptionMessage;
-
     private int mMaxPacketSize;
-
     private boolean mOperationDone;
-
     private boolean mGetOperation;
-
     private boolean mGetFinalFlag;
-
     private HeaderSet mRequestHeader;
-
     private HeaderSet mReplyHeader;
-
     private boolean mEndOfBodySent;
-
     private boolean mSendBodyHeader = true;
     // A latch - when triggered, there is not way back ;-)
     private boolean mSrmActive = false;
@@ -91,14 +74,13 @@ public final class ClientOperation implements Operation, BaseStream {
     // a different OBEX packet than the SRMP header.
     private boolean mSrmWaitingForRemote = true;
 
-
     /**
      * Creates new OperationImpl to read and write data to a server.
      *
      * @param maxSize the maximum packet size
      * @param p the parent to this object
-     * @param type <code>true</code> if this is a get request;
-     *        <code>false</code>. if this is a put request
+     * @param type <code>true</code> if this is a get request; <code>false</code>. if this is a put
+     *     request
      * @param header the header to set in the initial request
      * @throws IOException if an IO error occurred
      */
@@ -133,22 +115,23 @@ public final class ClientOperation implements Operation, BaseStream {
 
         if ((header).mAuthChall != null) {
             mRequestHeader.mAuthChall = new byte[(header).mAuthChall.length];
-            System.arraycopy((header).mAuthChall, 0, mRequestHeader.mAuthChall, 0,
+            System.arraycopy(
+                    (header).mAuthChall,
+                    0,
+                    mRequestHeader.mAuthChall,
+                    0,
                     (header).mAuthChall.length);
         }
 
         if ((header).mAuthResp != null) {
             mRequestHeader.mAuthResp = new byte[(header).mAuthResp.length];
-            System.arraycopy((header).mAuthResp, 0, mRequestHeader.mAuthResp, 0,
-                    (header).mAuthResp.length);
-
+            System.arraycopy(
+                    (header).mAuthResp, 0, mRequestHeader.mAuthResp, 0, (header).mAuthResp.length);
         }
 
         if ((header).mConnectionID != null) {
             mRequestHeader.mConnectionID = new byte[4];
-            System.arraycopy((header).mConnectionID, 0, mRequestHeader.mConnectionID, 0,
-                    4);
-
+            System.arraycopy((header).mConnectionID, 0, mRequestHeader.mConnectionID, 0, 4);
         }
     }
 
@@ -168,11 +151,11 @@ public final class ClientOperation implements Operation, BaseStream {
      * output streams will be closed along with this object.
      *
      * @throws IOException if the transaction has already ended or if an OBEX server called this
-     *                     method
+     *     method
      */
     public synchronized void abort() throws IOException {
         ensureOpen();
-        //no compatible with sun-ri
+        // no compatible with sun-ri
         if ((mOperationDone) && (mReplyHeader.responseCode != ResponseCodes.OBEX_HTTP_CONTINUE)) {
             throw new IOException("Operation has already ended");
         }
@@ -197,14 +180,13 @@ public final class ClientOperation implements Operation, BaseStream {
     }
 
     /**
-     * Retrieves the response code retrieved from the server. Response codes are
-     * defined in the <code>ResponseCodes</code> interface.
+     * Retrieves the response code retrieved from the server. Response codes are defined in the
+     * <code>ResponseCodes</code> interface.
+     *
      * @return the response code retrieved from the server
-     * @throws IOException if an error occurred in the transport layer during
-     *         the transaction; if this method is called on a
-     *         <code>HeaderSet</code> object created by calling
-     *         <code>createHeaderSet</code> in a <code>ClientSession</code>
-     *         object
+     * @throws IOException if an error occurred in the transport layer during the transaction; if
+     *     this method is called on a <code>HeaderSet</code> object created by calling <code>
+     *     createHeaderSet</code> in a <code>ClientSession</code> object
      */
     public synchronized int getResponseCode() throws IOException {
         if ((mReplyHeader.responseCode == -1)
@@ -217,6 +199,7 @@ public final class ClientOperation implements Operation, BaseStream {
 
     /**
      * Open and return an input stream for a connection.
+     *
      * @return an input stream
      * @throws IOException if an I/O error occurs
      */
@@ -224,8 +207,7 @@ public final class ClientOperation implements Operation, BaseStream {
 
         ensureOpen();
 
-        if (mPrivateInputOpen)
-            throw new IOException("no more input streams available");
+        if (mPrivateInputOpen) throw new IOException("no more input streams available");
         if (mGetOperation) {
             // send the GET request here
             validateConnection();
@@ -242,9 +224,9 @@ public final class ClientOperation implements Operation, BaseStream {
 
     /**
      * Open and return a data input stream for a connection.
+     *
      * @return an input stream
      * @throws IOException if an I/O error occurs
-     *
      * @hide
      */
     public DataInputStream openDataInputStream() throws IOException {
@@ -253,6 +235,7 @@ public final class ClientOperation implements Operation, BaseStream {
 
     /**
      * Open and return an output stream for a connection.
+     *
      * @return an output stream
      * @throws IOException if an I/O error occurs
      */
@@ -261,8 +244,7 @@ public final class ClientOperation implements Operation, BaseStream {
         ensureOpen();
         ensureNotDone();
 
-        if (mPrivateOutputOpen)
-            throw new IOException("no more output streams available");
+        if (mPrivateOutputOpen) throw new IOException("no more output streams available");
 
         if (mPrivateOutput == null) {
             // there are 3 bytes operation headers and 3 bytes body headers //
@@ -287,6 +269,7 @@ public final class ClientOperation implements Operation, BaseStream {
 
     /**
      * Open and return a data output stream for a connection.
+     *
      * @return an output stream
      * @throws IOException if an I/O error occurs
      */
@@ -296,6 +279,7 @@ public final class ClientOperation implements Operation, BaseStream {
 
     /**
      * Closes the connection and ends the transaction
+     *
      * @throws IOException if the operation has already ended or is closed
      */
     public void close() throws IOException {
@@ -306,9 +290,9 @@ public final class ClientOperation implements Operation, BaseStream {
     }
 
     /**
-     * Returns the headers that have been received during the operation.
-     * Modifying the object returned has no effect on the headers that are sent
-     * or retrieved.
+     * Returns the headers that have been received during the operation. Modifying the object
+     * returned has no effect on the headers that are sent or retrieved.
+     *
      * @return the headers received during this <code>Operation</code>
      * @throws IOException if this <code>Operation</code> has been closed
      */
@@ -319,15 +303,14 @@ public final class ClientOperation implements Operation, BaseStream {
     }
 
     /**
-     * Specifies the headers that should be sent in the next OBEX message that
-     * is sent.
+     * Specifies the headers that should be sent in the next OBEX message that is sent.
+     *
      * @param headers the headers to send in the next message
-     * @throws IOException if this <code>Operation</code> has been closed or the
-     *         transaction has ended and no further messages will be exchanged
-     * @throws IllegalArgumentException if <code>headers</code> was not created
-     *         by a call to <code>ServerRequestHandler.createHeaderSet()</code>
+     * @throws IOException if this <code>Operation</code> has been closed or the transaction has
+     *     ended and no further messages will be exchanged
+     * @throws IllegalArgumentException if <code>headers</code> was not created by a call to <code>
+     *     ServerRequestHandler.createHeaderSet()</code>
      * @throws NullPointerException if <code>headers</code> is <code>null</code>
-     *
      * @hide
      */
     public void sendHeaders(HeaderSet headers) throws IOException {
@@ -349,10 +332,9 @@ public final class ClientOperation implements Operation, BaseStream {
     }
 
     /**
-     * Verifies that additional information may be sent. In other words, the
-     * operation is not done.
-     * @throws IOException if the operation is completed
+     * Verifies that additional information may be sent. In other words, the operation is not done.
      *
+     * @throws IOException if the operation is completed
      * @hide
      */
     public void ensureNotDone() throws IOException {
@@ -363,8 +345,8 @@ public final class ClientOperation implements Operation, BaseStream {
 
     /**
      * Verifies that the connection is open and no exceptions should be thrown.
-     * @throws IOException if an exception needs to be thrown
      *
+     * @throws IOException if an exception needs to be thrown
      * @hide
      */
     public void ensureOpen() throws IOException {
@@ -380,6 +362,7 @@ public final class ClientOperation implements Operation, BaseStream {
 
     /**
      * Verifies that the connection is open and the proper data has been read.
+     *
      * @throws IOException if an IO error occurs
      */
     private void validateConnection() throws IOException {
@@ -393,12 +376,12 @@ public final class ClientOperation implements Operation, BaseStream {
     }
 
     /**
-     * Sends a request to the client of the specified type.
-     * This function will enable SRM and set SRM active if the server
-     * response allows this.
+     * Sends a request to the client of the specified type. This function will enable SRM and set
+     * SRM active if the server response allows this.
+     *
      * @param opCode the request code to send to the client
-     * @return <code>true</code> if there is more data to send;
-     *         <code>false</code> if there is no more data to send
+     * @return <code>true</code> if there is more data to send; <code>false</code> if there is no
+     *     more data to send
      * @throws IOException if an IO error occurs
      */
     private boolean sendRequest(int opCode) throws IOException {
@@ -426,10 +409,11 @@ public final class ClientOperation implements Operation, BaseStream {
             // split & send the headerArray in multiple packets.
 
             while (end != headerArray.length) {
-                //split the headerArray
+                // split the headerArray
 
-                end = ObexHelper.findHeaderEnd(headerArray, start, mMaxPacketSize
-                        - ObexHelper.BASE_PACKET_LENGTH);
+                end =
+                        ObexHelper.findHeaderEnd(
+                                headerArray, start, mMaxPacketSize - ObexHelper.BASE_PACKET_LENGTH);
                 // can not split
                 if (end == -1) {
                     mOperationDone = true;
@@ -470,7 +454,7 @@ public final class ClientOperation implements Operation, BaseStream {
             }
         } else {
             /* All headers will fit into a single package */
-            if(mSendBodyHeader == false) {
+            if (mSendBodyHeader == false) {
                 /* As we are not to send any body data, set the FINAL_BIT */
                 opCode |= ObexHelper.OBEX_OPCODE_FINAL_BIT_MASK;
             }
@@ -496,7 +480,9 @@ public final class ClientOperation implements Operation, BaseStream {
              * the output stream is closed we need to send the 0x49
              * (End of Body) otherwise, we need to send 0x48 (Body)
              */
-            if ((mPrivateOutput.isClosed()) && (!returnValue) && (!mEndOfBodySent)
+            if ((mPrivateOutput.isClosed())
+                    && (!returnValue)
+                    && (!mEndOfBodySent)
                     && ((opCode & ObexHelper.OBEX_OPCODE_FINAL_BIT_MASK) != 0)) {
                 out.write(HeaderSet.END_OF_BODY);
                 mEndOfBodySent = true;
@@ -505,8 +491,8 @@ public final class ClientOperation implements Operation, BaseStream {
             }
 
             bodyLength += 3;
-            out.write((byte)(bodyLength >> 8));
-            out.write((byte)bodyLength);
+            out.write((byte) (bodyLength >> 8));
+            out.write((byte) bodyLength);
 
             if (body != null) {
                 out.write(body);
@@ -523,8 +509,8 @@ public final class ClientOperation implements Operation, BaseStream {
             }
 
             bodyLength = 3;
-            out.write((byte)(bodyLength >> 8));
-            out.write((byte)bodyLength);
+            out.write((byte) (bodyLength >> 8));
+            out.write((byte) bodyLength);
         }
 
         if (out.size() == 0) {
@@ -536,8 +522,8 @@ public final class ClientOperation implements Operation, BaseStream {
             return returnValue;
         }
         if ((out.size() > 0)
-                && (!mParent.sendRequest(opCode, out.toByteArray(),
-                        mReplyHeader, mPrivateInput, mSrmActive))) {
+                && (!mParent.sendRequest(
+                        opCode, out.toByteArray(), mReplyHeader, mPrivateInput, mSrmActive))) {
             return false;
         }
         // Enable SRM if it should be enabled
@@ -545,45 +531,42 @@ public final class ClientOperation implements Operation, BaseStream {
 
         // send all of the output data in 0x48,
         // send 0x49 with empty body
-        if ((mPrivateOutput != null) && (mPrivateOutput.size() > 0))
-            returnValue = true;
+        if ((mPrivateOutput != null) && (mPrivateOutput.size() > 0)) returnValue = true;
 
         return returnValue;
     }
 
     private void checkForSrm() throws IOException {
-        Byte srmMode = (Byte)mReplyHeader.getHeader(HeaderSet.SINGLE_RESPONSE_MODE);
-        if(mParent.isSrmSupported() == true && srmMode != null
+        Byte srmMode = (Byte) mReplyHeader.getHeader(HeaderSet.SINGLE_RESPONSE_MODE);
+        if (mParent.isSrmSupported() == true
+                && srmMode != null
                 && srmMode == ObexHelper.OBEX_SRM_ENABLE) {
             mSrmEnabled = true;
         }
-        /**
-         * Call this only when a complete obex packet have been received.
-         * (This is not optimal, but the current design is not really suited to
-         * the way SRM is specified.)
-         * The BT usage of SRM is not really safe - it assumes that the SRMP will fit
-         * into every OBEX packet, hence if another header occupies the entire packet,
-         * the scheme will not work - unlikely though.
-         */
-        if(mSrmEnabled) {
+
+        // Call this only when a complete obex packet have been received. (This is not optimal, but
+        // the current design is not really suited to the way SRM is specified.) The BT usage of SRM
+        // is not really safe - it assumes that the SRMP will fit into every OBEX packet, hence if
+        // another header occupies the entire packet, the scheme will not work - unlikely though.
+        if (mSrmEnabled) {
             mSrmWaitingForRemote = false;
-            Byte srmp = (Byte)mReplyHeader.getHeader(HeaderSet.SINGLE_RESPONSE_MODE_PARAMETER);
-            if(srmp != null && srmp == ObexHelper.OBEX_SRMP_WAIT) {
+            Byte srmp = (Byte) mReplyHeader.getHeader(HeaderSet.SINGLE_RESPONSE_MODE_PARAMETER);
+            if (srmp != null && srmp == ObexHelper.OBEX_SRMP_WAIT) {
                 mSrmWaitingForRemote = true;
                 // Clear the wait header, as the absence of the header in the next packet
                 // indicates don't wait anymore.
                 mReplyHeader.setHeader(HeaderSet.SINGLE_RESPONSE_MODE_PARAMETER, null);
             }
         }
-        if((mSrmWaitingForRemote == false) && (mSrmEnabled == true)) {
+        if ((mSrmWaitingForRemote == false) && (mSrmEnabled == true)) {
             mSrmActive = true;
         }
     }
 
     /**
-     * This method starts the processing thread results. It will send the
-     * initial request. If the response takes more than one packet, a thread
-     * will be started to handle additional requests
+     * This method starts the processing thread results. It will send the initial request. If the
+     * response takes more than one packet, a thread will be started to handle additional requests
+     *
      * @throws IOException if an IO error occurs
      */
     private synchronized void startProcessing() throws IOException {
@@ -597,16 +580,20 @@ public final class ClientOperation implements Operation, BaseStream {
             if (!mOperationDone) {
                 if (!mGetFinalFlag) {
                     mReplyHeader.responseCode = ResponseCodes.OBEX_HTTP_CONTINUE;
-                    while ((more) && (mReplyHeader.responseCode ==
-                            ResponseCodes.OBEX_HTTP_CONTINUE)) {
+                    while ((more)
+                            && (mReplyHeader.responseCode == ResponseCodes.OBEX_HTTP_CONTINUE)) {
                         more = sendRequest(ObexHelper.OBEX_OPCODE_GET);
                     }
                     // For GET we need to loop until all headers have been sent,
                     // And then we wait for the first continue package with the
                     // reply.
                     if (mReplyHeader.responseCode == ResponseCodes.OBEX_HTTP_CONTINUE) {
-                        mParent.sendRequest(ObexHelper.OBEX_OPCODE_GET_FINAL,
-                                null, mReplyHeader, mPrivateInput, mSrmActive);
+                        mParent.sendRequest(
+                                ObexHelper.OBEX_OPCODE_GET_FINAL,
+                                null,
+                                mReplyHeader,
+                                mPrivateInput,
+                                mSrmActive);
                     }
                     if (mReplyHeader.responseCode != ResponseCodes.OBEX_HTTP_CONTINUE) {
                         mOperationDone = true;
@@ -633,8 +620,12 @@ public final class ClientOperation implements Operation, BaseStream {
             }
 
             if (mReplyHeader.responseCode == ResponseCodes.OBEX_HTTP_CONTINUE) {
-                mParent.sendRequest(ObexHelper.OBEX_OPCODE_PUT_FINAL,
-                        null, mReplyHeader, mPrivateInput, mSrmActive);
+                mParent.sendRequest(
+                        ObexHelper.OBEX_OPCODE_PUT_FINAL,
+                        null,
+                        mReplyHeader,
+                        mPrivateInput,
+                        mSrmActive);
             }
 
             if (mReplyHeader.responseCode != ResponseCodes.OBEX_HTTP_CONTINUE) {
@@ -645,10 +636,10 @@ public final class ClientOperation implements Operation, BaseStream {
 
     /**
      * Continues the operation since there is no data to read.
-     * @param sendEmpty <code>true</code> if the operation should send an empty
-     *        packet or not send anything if there is no data to send
-     * @param inStream <code>true</code> if the stream is input stream or is
-     *        output stream
+     *
+     * @param sendEmpty <code>true</code> if the operation should send an empty packet or not send
+     *     anything if there is no data to send
+     * @param inStream <code>true</code> if the stream is input stream or is output stream
      * @throws IOException if an IO error occurs
      */
     public synchronized boolean continueOperation(boolean sendEmpty, boolean inStream)
@@ -660,11 +651,15 @@ public final class ClientOperation implements Operation, BaseStream {
         if (mGetOperation) {
             if ((inStream) && (!mOperationDone)) {
                 // to deal with inputstream in get operation
-                mParent.sendRequest(ObexHelper.OBEX_OPCODE_GET_FINAL,
-                        null, mReplyHeader, mPrivateInput, mSrmActive);
+                mParent.sendRequest(
+                        ObexHelper.OBEX_OPCODE_GET_FINAL,
+                        null,
+                        mReplyHeader,
+                        mPrivateInput,
+                        mSrmActive);
                 /*
-                  * Determine if that was not the last packet in the operation
-                  */
+                 * Determine if that was not the last packet in the operation
+                 */
                 if (mReplyHeader.responseCode != ResponseCodes.OBEX_HTTP_CONTINUE) {
                     mOperationDone = true;
                 } else {
@@ -710,17 +705,16 @@ public final class ClientOperation implements Operation, BaseStream {
             } else if (mOperationDone) {
                 return false;
             }
-
         }
         return false;
     }
 
     /**
      * Called when the output or input stream is closed.
-     * @param inStream <code>true</code> if the input stream is closed;
-     *        <code>false</code> if the output stream is closed
-     * @throws IOException if an IO error occurs
      *
+     * @param inStream <code>true</code> if the input stream is closed; <code>false</code> if the
+     *     output stream is closed
+     * @throws IOException if an IO error occurs
      * @hide
      */
     public void streamClosed(boolean inStream) throws IOException {
@@ -732,8 +726,7 @@ public final class ClientOperation implements Operation, BaseStream {
 
                 if ((mPrivateOutput != null) && (mPrivateOutput.size() <= 0)) {
                     byte[] headerArray = ObexHelper.createHeader(mRequestHeader, false);
-                    if (headerArray.length <= 0)
-                        more = false;
+                    if (headerArray.length <= 0) more = false;
                 }
                 // If have not sent any data so send  all now
                 if (mReplyHeader.responseCode == -1) {
@@ -776,8 +769,12 @@ public final class ClientOperation implements Operation, BaseStream {
                 }
                 while (mReplyHeader.responseCode == ResponseCodes.OBEX_HTTP_CONTINUE
                         && !mOperationDone) {
-                    mParent.sendRequest(ObexHelper.OBEX_OPCODE_GET_FINAL, null,
-                            mReplyHeader, mPrivateInput, false);
+                    mParent.sendRequest(
+                            ObexHelper.OBEX_OPCODE_GET_FINAL,
+                            null,
+                            mReplyHeader,
+                            mPrivateInput,
+                            false);
                     // Regardless of the SRM state, wait for the response.
                 }
                 mOperationDone = true;
@@ -789,15 +786,13 @@ public final class ClientOperation implements Operation, BaseStream {
 
                 if ((mPrivateOutput != null) && (mPrivateOutput.size() <= 0)) {
                     byte[] headerArray = ObexHelper.createHeader(mRequestHeader, false);
-                    if (headerArray.length <= 0)
-                        more = false;
+                    if (headerArray.length <= 0) more = false;
                 }
 
                 if (mPrivateInput == null) {
                     mPrivateInput = new PrivateInputStream(this);
                 }
-                if ((mPrivateOutput != null) && (mPrivateOutput.size() <= 0))
-                    more = false;
+                if ((mPrivateOutput != null) && (mPrivateOutput.size() <= 0)) more = false;
 
                 mReplyHeader.responseCode = ResponseCodes.OBEX_HTTP_CONTINUE;
                 while ((more) && (mReplyHeader.responseCode == ResponseCodes.OBEX_HTTP_CONTINUE)) {
@@ -813,7 +808,7 @@ public final class ClientOperation implements Operation, BaseStream {
     }
 
     /** @hide */
-    public void noBodyHeader(){
+    public void noBodyHeader() {
         mSendBodyHeader = false;
     }
 }
diff --git a/src/com/android/obex/ClientSession.java b/src/com/android/obex/ClientSession.java
index c3d876f..870987a 100644
--- a/src/com/android/obex/ClientSession.java
+++ b/src/com/android/obex/ClientSession.java
@@ -41,9 +41,7 @@ import java.io.IOException;
 import java.io.InputStream;
 import java.io.OutputStream;
 
-/**
- * This class in an implementation of the OBEX ClientSession.
- */
+/** This class in an implementation of the OBEX ClientSession. */
 public final class ClientSession extends ObexSession {
 
     private static final String TAG = "ClientSession";
@@ -90,10 +88,9 @@ public final class ClientSession extends ObexSession {
      * Create a ClientSession.
      *
      * @param transport the transport to use for OBEX transactions
-     * @param supportsSrm true if Single Response Mode should be used e.g. if the
-     *        supplied transport is a TCP or l2cap channel
+     * @param supportsSrm true if Single Response Mode should be used e.g. if the supplied transport
+     *     is a TCP or l2cap channel
      * @throws IOException if it occurs while opening the transport streams
-     *
      * @hide
      */
     public ClientSession(final ObexTransport transport, final boolean supportsSrm)
@@ -126,22 +123,22 @@ public final class ClientSession extends ObexSession {
             totalLength += head.length;
         }
         /*
-        * Write the OBEX CONNECT packet to the server.
-        * Byte 0: 0x80
-        * Byte 1&2: Connect Packet Length
-        * Byte 3: OBEX Version Number (Presently, 0x10)
-        * Byte 4: Flags (For TCP 0x00)
-        * Byte 5&6: Max OBEX Packet Length (Defined in MAX_PACKET_SIZE)
-        * Byte 7 to n: headers
-        */
+         * Write the OBEX CONNECT packet to the server.
+         * Byte 0: 0x80
+         * Byte 1&2: Connect Packet Length
+         * Byte 3: OBEX Version Number (Presently, 0x10)
+         * Byte 4: Flags (For TCP 0x00)
+         * Byte 5&6: Max OBEX Packet Length (Defined in MAX_PACKET_SIZE)
+         * Byte 7 to n: headers
+         */
         byte[] requestPacket = new byte[totalLength];
         int maxRxPacketSize = ObexHelper.getMaxRxPacketSize(mTransport);
         // We just need to start at  byte 3 since the sendRequest() method will
         // handle the length and 0x80.
-        requestPacket[0] = (byte)0x10;
-        requestPacket[1] = (byte)0x00;
-        requestPacket[2] = (byte)(maxRxPacketSize >> 8);
-        requestPacket[3] = (byte)(maxRxPacketSize & 0xFF);
+        requestPacket[0] = (byte) 0x10;
+        requestPacket[1] = (byte) 0x00;
+        requestPacket[2] = (byte) (maxRxPacketSize >> 8);
+        requestPacket[3] = (byte) (maxRxPacketSize & 0xFF);
         if (head != null) {
             System.arraycopy(head, 0, requestPacket, 4, head.length);
         }
@@ -156,14 +153,14 @@ public final class ClientSession extends ObexSession {
         sendRequest(ObexHelper.OBEX_OPCODE_CONNECT, requestPacket, returnHeaderSet, null, false);
 
         /*
-        * Read the response from the OBEX server.
-        * Byte 0: Response Code (If successful then OBEX_HTTP_OK)
-        * Byte 1&2: Packet Length
-        * Byte 3: OBEX Version Number
-        * Byte 4: Flags3
-        * Byte 5&6: Max OBEX packet Length
-        * Byte 7 to n: Optional HeaderSet
-        */
+         * Read the response from the OBEX server.
+         * Byte 0: Response Code (If successful then OBEX_HTTP_OK)
+         * Byte 1&2: Packet Length
+         * Byte 3: OBEX Version Number
+         * Byte 4: Flags3
+         * Byte 5&6: Max OBEX packet Length
+         * Byte 7 to n: Optional HeaderSet
+         */
         if (returnHeaderSet.responseCode == ResponseCodes.OBEX_HTTP_OK) {
             mObexConnected = true;
         }
@@ -197,7 +194,7 @@ public final class ClientSession extends ObexSession {
             System.arraycopy(mConnectionId, 0, head.mConnectionID, 0, 4);
         }
 
-        if(mLocalSrmSupported) {
+        if (mLocalSrmSupported) {
             head.setHeader(HeaderSet.SINGLE_RESPONSE_MODE, ObexHelper.OBEX_SRM_ENABLE);
             /* TODO: Consider creating an interface to get the wait state.
              * On an android system, I cannot see when this is to be used.
@@ -262,7 +259,7 @@ public final class ClientSession extends ObexSession {
             // Add the connection ID if one exists
             if (mConnectionId != null) {
                 head = new byte[5];
-                head[0] = (byte)HeaderSet.CONNECTION_ID;
+                head[0] = (byte) HeaderSet.CONNECTION_ID;
                 System.arraycopy(mConnectionId, 0, head, 1, 4);
             }
         }
@@ -324,7 +321,7 @@ public final class ClientSession extends ObexSession {
             System.arraycopy(mConnectionId, 0, head.mConnectionID, 0, 4);
         }
 
-        if(mLocalSrmSupported) {
+        if (mLocalSrmSupported) {
             head.setHeader(HeaderSet.SINGLE_RESPONSE_MODE, ObexHelper.OBEX_SRM_ENABLE);
             /* TODO: Consider creating an interface to get the wait state.
              * On an android system, I cannot see when this is to be used.
@@ -352,7 +349,6 @@ public final class ClientSession extends ObexSession {
         ensureOpen();
 
         int totalLength = 2;
-        byte[] head = null;
         HeaderSet headset;
         if (header == null) {
             headset = new HeaderSet();
@@ -376,7 +372,7 @@ public final class ClientSession extends ObexSession {
             System.arraycopy(mConnectionId, 0, headset.mConnectionID, 0, 4);
         }
 
-        head = ObexHelper.createHeader(headset, false);
+        byte[] head = ObexHelper.createHeader(headset, false);
         totalLength += head.length;
 
         if (totalLength > mMaxTxPacketSize) {
@@ -406,8 +402,8 @@ public final class ClientSession extends ObexSession {
          * Byte 6 & up: headers
          */
         byte[] packet = new byte[totalLength];
-        packet[0] = (byte)flags;
-        packet[1] = (byte)0x00;
+        packet[0] = (byte) flags;
+        packet[1] = (byte) 0x00;
         if (headset != null) {
             System.arraycopy(head, 0, packet, 2, head.length);
         }
@@ -429,8 +425,8 @@ public final class ClientSession extends ObexSession {
 
     /**
      * Verifies that the connection is open.
-     * @throws IOException if the connection is closed
      *
+     * @throws IOException if the connection is closed
      * @hide
      */
     public synchronized void ensureOpen() throws IOException {
@@ -440,15 +436,16 @@ public final class ClientSession extends ObexSession {
     }
 
     /**
-     * Set request inactive. Allows Put and get operation objects to tell this
-     * object when they are done.
+     * Set request inactive. Allows Put and get operation objects to tell this object when they are
+     * done.
      */
-    /*package*/synchronized void setRequestInactive() {
+    /*package*/ synchronized void setRequestInactive() {
         mRequestActive = false;
     }
 
     /**
      * Set request to active.
+     *
      * @throws IOException if already active
      */
     private synchronized void setRequestActive() throws IOException {
@@ -459,25 +456,28 @@ public final class ClientSession extends ObexSession {
     }
 
     /**
-     * Sends a standard request to the client. It will then wait for the reply
-     * and update the header set object provided. If any authentication headers
-     * (i.e. authentication challenge or authentication response) are received,
-     * they will be processed.
+     * Sends a standard request to the client. It will then wait for the reply and update the header
+     * set object provided. If any authentication headers (i.e. authentication challenge or
+     * authentication response) are received, they will be processed.
+     *
      * @param opCode the type of request to send to the client
      * @param head the headers to send to the client
      * @param header the header object to update with the response
-     * @param privateInput the input stream used by the Operation object; null
-     *        if this is called on a CONNECT, SETPATH or DISCONNECT
-     * @return
-     *        <code>true</code> if the operation completed successfully;
-     *        <code>false</code> if an authentication response failed to pass
+     * @param privateInput the input stream used by the Operation object; null if this is called on
+     *     a CONNECT, SETPATH or DISCONNECT
+     * @return <code>true</code> if the operation completed successfully; <code>false</code> if an
+     *     authentication response failed to pass
      * @throws IOException if an IO error occurs
-     *
      * @hide
      */
-    public boolean sendRequest(int opCode, byte[] head, HeaderSet header,
-            PrivateInputStream privateInput, boolean srmActive) throws IOException {
-        //check header length with local max size
+    public boolean sendRequest(
+            int opCode,
+            byte[] head,
+            HeaderSet header,
+            PrivateInputStream privateInput,
+            boolean srmActive)
+            throws IOException {
+        // check header length with local max size
         if (head != null) {
             if ((head.length + 3) > ObexHelper.MAX_PACKET_SIZE_INT) {
                 // TODO: This is an implementation limit - not a specification requirement.
@@ -500,20 +500,19 @@ public final class ClientSession extends ObexSession {
                 // sending continue.
                 skipSend = true;
             }
-
         }
 
         int bytesReceived;
         ByteArrayOutputStream out = new ByteArrayOutputStream();
-        out.write((byte)opCode);
+        out.write((byte) opCode);
 
         // Determine if there are any headers to send
         if (head == null) {
             out.write(0x00);
             out.write(0x03);
         } else {
-            out.write((byte)((head.length + 3) >> 8));
-            out.write((byte)(head.length + 3));
+            out.write((byte) ((head.length + 3) >> 8));
+            out.write((byte) (head.length + 3));
             out.write(head);
         }
 
@@ -544,19 +543,23 @@ public final class ClientSession extends ObexSession {
                     int flags = mInput.read();
                     mMaxTxPacketSize = (mInput.read() << 8) + mInput.read();
 
-                    //check with local max size
+                    // check with local max size
                     if (mMaxTxPacketSize > ObexHelper.MAX_CLIENT_PACKET_SIZE) {
                         mMaxTxPacketSize = ObexHelper.MAX_CLIENT_PACKET_SIZE;
                     }
 
                     // check with transport maximum size
-                    if(mMaxTxPacketSize > ObexHelper.getMaxTxPacketSize(mTransport)) {
+                    if (mMaxTxPacketSize > ObexHelper.getMaxTxPacketSize(mTransport)) {
                         // To increase this size, increase the buffer size in L2CAP layer
                         // in Bluedroid.
-                        Log.w(TAG, "An OBEX packet size of " + mMaxTxPacketSize + "was"
-                                + " requested. Transport only allows: "
-                                + ObexHelper.getMaxTxPacketSize(mTransport)
-                                + " Lowering limit to this value.");
+                        Log.w(
+                                TAG,
+                                "An OBEX packet size of "
+                                        + mMaxTxPacketSize
+                                        + "was"
+                                        + " requested. Transport only allows: "
+                                        + ObexHelper.getMaxTxPacketSize(mTransport)
+                                        + " Lowering limit to this value.");
                         mMaxTxPacketSize = ObexHelper.getMaxTxPacketSize(mTransport);
                     }
 
@@ -565,8 +568,8 @@ public final class ClientSession extends ObexSession {
 
                         bytesReceived = mInput.read(data);
                         while (bytesReceived != (length - 7)) {
-                            bytesReceived += mInput.read(data, bytesReceived, data.length
-                                    - bytesReceived);
+                            bytesReceived +=
+                                    mInput.read(data, bytesReceived, data.length - bytesReceived);
                         }
                     } else {
                         return true;
@@ -576,8 +579,8 @@ public final class ClientSession extends ObexSession {
                     bytesReceived = mInput.read(data);
 
                     while (bytesReceived != (length - 3)) {
-                        bytesReceived += mInput.read(data, bytesReceived,
-                                data.length - bytesReceived);
+                        bytesReceived +=
+                                mInput.read(data, bytesReceived, data.length - bytesReceived);
                     }
                     if (opCode == ObexHelper.OBEX_OPCODE_ABORT) {
                         return true;
@@ -605,9 +608,9 @@ public final class ClientSession extends ObexSession {
                         && (header.mAuthChall != null)) {
 
                     if (handleAuthChall(header)) {
-                        out.write((byte)HeaderSet.AUTH_RESPONSE);
-                        out.write((byte)((header.mAuthResp.length + 3) >> 8));
-                        out.write((byte)(header.mAuthResp.length + 3));
+                        out.write((byte) HeaderSet.AUTH_RESPONSE);
+                        out.write((byte) ((header.mAuthResp.length + 3) >> 8));
+                        out.write((byte) (header.mAuthResp.length + 3));
                         out.write(header.mAuthResp);
                         header.mAuthChall = null;
                         header.mAuthResp = null;
diff --git a/src/com/android/obex/HeaderSet.java b/src/com/android/obex/HeaderSet.java
index 4df71ec..f1a9899 100644
--- a/src/com/android/obex/HeaderSet.java
+++ b/src/com/android/obex/HeaderSet.java
@@ -40,87 +40,84 @@ import java.util.Arrays;
 import java.util.Calendar;
 
 /**
- * This class implements the com.android.obex.HeaderSet interface for OBEX over
- * RFCOMM or OBEX over l2cap.
+ * This class implements the com.android.obex.HeaderSet interface for OBEX over RFCOMM or OBEX over
+ * l2cap.
  */
 public final class HeaderSet {
 
     /**
-     * Represents the OBEX Count header. This allows the connection statement to
-     * tell the server how many objects it plans to send or retrieve.
-     * <P>
-     * The value of <code>COUNT</code> is 0xC0 (192).
+     * Represents the OBEX Count header. This allows the connection statement to tell the server how
+     * many objects it plans to send or retrieve.
+     *
+     * <p>The value of <code>COUNT</code> is 0xC0 (192).
      */
     public static final int COUNT = 0xC0;
 
     /**
      * Represents the OBEX Name header. This specifies the name of the object.
-     * <P>
-     * The value of <code>NAME</code> is 0x01 (1).
+     *
+     * <p>The value of <code>NAME</code> is 0x01 (1).
      */
     public static final int NAME = 0x01;
 
     /**
-     * Represents the OBEX Type header. This allows a request to specify the
-     * type of the object (e.g. text, html, binary, etc.).
-     * <P>
-     * The value of <code>TYPE</code> is 0x42 (66).
+     * Represents the OBEX Type header. This allows a request to specify the type of the object
+     * (e.g. text, html, binary, etc.).
+     *
+     * <p>The value of <code>TYPE</code> is 0x42 (66).
      */
     public static final int TYPE = 0x42;
 
     /**
-     * Represents the OBEX Length header. This is the length of the object in
-     * bytes.
-     * <P>
-     * The value of <code>LENGTH</code> is 0xC3 (195).
+     * Represents the OBEX Length header. This is the length of the object in bytes.
+     *
+     * <p>The value of <code>LENGTH</code> is 0xC3 (195).
      */
     public static final int LENGTH = 0xC3;
 
     /**
-     * Represents the OBEX Time header using the ISO 8601 standards. This is the
-     * preferred time header.
-     * <P>
-     * The value of <code>TIME_ISO_8601</code> is 0x44 (68).
+     * Represents the OBEX Time header using the ISO 8601 standards. This is the preferred time
+     * header.
+     *
+     * <p>The value of <code>TIME_ISO_8601</code> is 0x44 (68).
      */
     public static final int TIME_ISO_8601 = 0x44;
 
     /**
-     * Represents the OBEX Time header using the 4 byte representation. This is
-     * only included for backwards compatibility. It represents the number of
-     * seconds since January 1, 1970.
-     * <P>
-     * The value of <code>TIME_4_BYTE</code> is 0xC4 (196).
+     * Represents the OBEX Time header using the 4 byte representation. This is only included for
+     * backwards compatibility. It represents the number of seconds since January 1, 1970.
+     *
+     * <p>The value of <code>TIME_4_BYTE</code> is 0xC4 (196).
      */
     public static final int TIME_4_BYTE = 0xC4;
 
     /**
-     * Represents the OBEX Description header. This is a text description of the
-     * object.
-     * <P>
-     * The value of <code>DESCRIPTION</code> is 0x05 (5).
+     * Represents the OBEX Description header. This is a text description of the object.
+     *
+     * <p>The value of <code>DESCRIPTION</code> is 0x05 (5).
      */
     public static final int DESCRIPTION = 0x05;
 
     /**
-     * Represents the OBEX Target header. This is the name of the service an
-     * operation is targeted to.
-     * <P>
-     * The value of <code>TARGET</code> is 0x46 (70).
+     * Represents the OBEX Target header. This is the name of the service an operation is targeted
+     * to.
+     *
+     * <p>The value of <code>TARGET</code> is 0x46 (70).
      */
     public static final int TARGET = 0x46;
 
     /**
-     * Represents the OBEX HTTP header. This allows an HTTP 1.X header to be
-     * included in a request or reply.
-     * <P>
-     * The value of <code>HTTP</code> is 0x47 (71).
+     * Represents the OBEX HTTP header. This allows an HTTP 1.X header to be included in a request
+     * or reply.
+     *
+     * <p>The value of <code>HTTP</code> is 0x47 (71).
      */
     public static final int HTTP = 0x47;
 
     /**
      * Represents the OBEX BODY header.
-     * <P>
-     * The value of <code>BODY</code> is 0x48 (72).
+     *
+     * <p>The value of <code>BODY</code> is 0x48 (72).
      *
      * @hide
      */
@@ -128,43 +125,42 @@ public final class HeaderSet {
 
     /**
      * Represents the OBEX End of BODY header.
-     * <P>
-     * The value of <code>BODY</code> is 0x49 (73).
+     *
+     * <p>The value of <code>BODY</code> is 0x49 (73).
      *
      * @hide
      */
     public static final int END_OF_BODY = 0x49;
 
     /**
-     * Represents the OBEX Who header. Identifies the OBEX application to
-     * determine if the two peers are talking to each other.
-     * <P>
-     * The value of <code>WHO</code> is 0x4A (74).
+     * Represents the OBEX Who header. Identifies the OBEX application to determine if the two peers
+     * are talking to each other.
+     *
+     * <p>The value of <code>WHO</code> is 0x4A (74).
      */
     public static final int WHO = 0x4A;
 
     /**
-     * Represents the OBEX Connection ID header. Identifies used for OBEX
-     * connection multiplexing.
-     * <P>
-     * The value of <code>CONNECTION_ID</code> is 0xCB (203).
+     * Represents the OBEX Connection ID header. Identifies used for OBEX connection multiplexing.
+     *
+     * <p>The value of <code>CONNECTION_ID</code> is 0xCB (203).
      *
      * @hide
      */
     public static final int CONNECTION_ID = 0xCB;
 
     /**
-     * Represents the OBEX Application Parameter header. This header specifies
-     * additional application request and response information.
-     * <P>
-     * The value of <code>APPLICATION_PARAMETER</code> is 0x4C (76).
+     * Represents the OBEX Application Parameter header. This header specifies additional
+     * application request and response information.
+     *
+     * <p>The value of <code>APPLICATION_PARAMETER</code> is 0x4C (76).
      */
     public static final int APPLICATION_PARAMETER = 0x4C;
 
     /**
      * Represents the OBEX authentication digest-challenge.
-     * <P>
-     * The value of <code>AUTH_CHALLENGE</code> is 0x4D (77).
+     *
+     * <p>The value of <code>AUTH_CHALLENGE</code> is 0x4D (77).
      *
      * @hide
      */
@@ -172,36 +168,36 @@ public final class HeaderSet {
 
     /**
      * Represents the OBEX authentication digest-response.
-     * <P>
-     * The value of <code>AUTH_RESPONSE</code> is 0x4E (78).
+     *
+     * <p>The value of <code>AUTH_RESPONSE</code> is 0x4E (78).
      *
      * @hide
      */
     public static final int AUTH_RESPONSE = 0x4E;
 
     /**
-     * Represents the OBEX Object Class header. This header specifies the OBEX
-     * object class of the object.
-     * <P>
-     * The value of <code>OBJECT_CLASS</code> is 0x4F (79).
+     * Represents the OBEX Object Class header. This header specifies the OBEX object class of the
+     * object.
+     *
+     * <p>The value of <code>OBJECT_CLASS</code> is 0x4F (79).
      */
     public static final int OBJECT_CLASS = 0x4F;
 
     /**
-     * Represents the OBEX Single Response Mode (SRM). This header is used
-     * for Single response mode, introduced in OBEX 1.5.
-     * <P>
-     * The value of <code>SINGLE_RESPONSE_MODE</code> is 0x97 (151).
+     * Represents the OBEX Single Response Mode (SRM). This header is used for Single response mode,
+     * introduced in OBEX 1.5.
+     *
+     * <p>The value of <code>SINGLE_RESPONSE_MODE</code> is 0x97 (151).
      *
      * @hide
      */
     public static final int SINGLE_RESPONSE_MODE = 0x97;
 
     /**
-     * Represents the OBEX Single Response Mode Parameters. This header is used
-     * for Single response mode, introduced in OBEX 1.5.
-     * <P>
-     * The value of <code>SINGLE_RESPONSE_MODE_PARAMETER</code> is 0x98 (152).
+     * Represents the OBEX Single Response Mode Parameters. This header is used for Single response
+     * mode, introduced in OBEX 1.5.
+     *
+     * <p>The value of <code>SINGLE_RESPONSE_MODE_PARAMETER</code> is 0x98 (152).
      *
      * @hide
      */
@@ -246,7 +242,7 @@ public final class HeaderSet {
     private Byte mSingleResponseMode; // byte to indicate enable/disable/support for SRM
 
     private Byte mSrmParam; // byte representing the SRM parameters - only "wait"
-                            // is supported by Bluetooth
+    // is supported by Bluetooth
 
     /*package*/ byte[] nonce;
 
@@ -258,9 +254,7 @@ public final class HeaderSet {
 
     public int responseCode;
 
-    /**
-     * Creates new <code>HeaderSet</code> object.
-     */
+    /** Creates new <code>HeaderSet</code> object. */
     public HeaderSet() {
         mUnicodeUserDefined = new String[16];
         mSequenceUserDefined = new byte[16][];
@@ -270,10 +264,9 @@ public final class HeaderSet {
     }
 
     /**
-     * Sets flag for special "value" of NAME header which should be empty. This
-     * is not the same as NAME header with empty string in which case it will
-     * have length of 5 bytes. It should be 3 bytes with only header id and
-     * length field.
+     * Sets flag for special "value" of NAME header which should be empty. This is not the same as
+     * NAME header with empty string in which case it will have length of 5 bytes. It should be 3
+     * bytes with only header id and length field.
      */
     public void setEmptyNameHeader() {
         mName = null;
@@ -281,8 +274,7 @@ public final class HeaderSet {
     }
 
     /**
-     * Gets flag for special "value" of NAME header which should be empty. See
-     * above.
+     * Gets flag for special "value" of NAME header which should be empty. See above.
      *
      * @hide
      */
@@ -291,17 +283,16 @@ public final class HeaderSet {
     }
 
     /**
-     * Sets the value of the header identifier to the value provided. The type
-     * of object must correspond to the Java type defined in the description of
-     * this interface. If <code>null</code> is passed as the
-     * <code>headerValue</code> then the header will be removed from the set of
-     * headers to include in the next request.
+     * Sets the value of the header identifier to the value provided. The type of object must
+     * correspond to the Java type defined in the description of this interface. If <code>null
+     * </code> is passed as the <code>headerValue</code> then the header will be removed from the
+     * set of headers to include in the next request.
+     *
      * @param headerID the identifier to include in the message
      * @param headerValue the value of the header identifier
-     * @throws IllegalArgumentException if the header identifier provided is not
-     *         one defined in this interface or a user-defined header; if the
-     *         type of <code>headerValue</code> is not the correct Java type as
-     *         defined in the description of this interface\
+     * @throws IllegalArgumentException if the header identifier provided is not one defined in this
+     *     interface or a user-defined header; if the type of <code>headerValue</code> is not the
+     *     correct Java type as defined in the description of this interface\
      */
     public void setHeader(int headerID, Object headerValue) {
         long temp = -1;
@@ -315,24 +306,24 @@ public final class HeaderSet {
                     }
                     throw new IllegalArgumentException("Count must be a Long");
                 }
-                temp = ((Long)headerValue).longValue();
+                temp = ((Long) headerValue).longValue();
                 if ((temp < 0L) || (temp > 0xFFFFFFFFL)) {
                     throw new IllegalArgumentException("Count must be between 0 and 0xFFFFFFFF");
                 }
-                mCount = (Long)headerValue;
+                mCount = (Long) headerValue;
                 break;
             case NAME:
                 if ((headerValue != null) && (!(headerValue instanceof String))) {
                     throw new IllegalArgumentException("Name must be a String");
                 }
                 mEmptyName = false;
-                mName = (String)headerValue;
+                mName = (String) headerValue;
                 break;
             case TYPE:
                 if ((headerValue != null) && (!(headerValue instanceof String))) {
                     throw new IllegalArgumentException("Type must be a String");
                 }
-                mType = (String)headerValue;
+                mType = (String) headerValue;
                 break;
             case LENGTH:
                 if (!(headerValue instanceof Long)) {
@@ -342,29 +333,29 @@ public final class HeaderSet {
                     }
                     throw new IllegalArgumentException("Length must be a Long");
                 }
-                temp = ((Long)headerValue).longValue();
+                temp = ((Long) headerValue).longValue();
                 if ((temp < 0L) || (temp > 0xFFFFFFFFL)) {
                     throw new IllegalArgumentException("Length must be between 0 and 0xFFFFFFFF");
                 }
-                mLength = (Long)headerValue;
+                mLength = (Long) headerValue;
                 break;
             case TIME_ISO_8601:
                 if ((headerValue != null) && (!(headerValue instanceof Calendar))) {
                     throw new IllegalArgumentException("Time ISO 8601 must be a Calendar");
                 }
-                mIsoTime = (Calendar)headerValue;
+                mIsoTime = (Calendar) headerValue;
                 break;
             case TIME_4_BYTE:
                 if ((headerValue != null) && (!(headerValue instanceof Calendar))) {
                     throw new IllegalArgumentException("Time 4 Byte must be a Calendar");
                 }
-                mByteTime = (Calendar)headerValue;
+                mByteTime = (Calendar) headerValue;
                 break;
             case DESCRIPTION:
                 if ((headerValue != null) && (!(headerValue instanceof String))) {
                     throw new IllegalArgumentException("Description must be a String");
                 }
-                mDescription = (String)headerValue;
+                mDescription = (String) headerValue;
                 break;
             case TARGET:
                 if (headerValue == null) {
@@ -373,7 +364,7 @@ public final class HeaderSet {
                     if (!(headerValue instanceof byte[])) {
                         throw new IllegalArgumentException("Target must be a byte array");
                     } else {
-                        mTarget = new byte[((byte[])headerValue).length];
+                        mTarget = new byte[((byte[]) headerValue).length];
                         System.arraycopy(headerValue, 0, mTarget, 0, mTarget.length);
                     }
                 }
@@ -385,7 +376,7 @@ public final class HeaderSet {
                     if (!(headerValue instanceof byte[])) {
                         throw new IllegalArgumentException("HTTP must be a byte array");
                     } else {
-                        mHttpHeader = new byte[((byte[])headerValue).length];
+                        mHttpHeader = new byte[((byte[]) headerValue).length];
                         System.arraycopy(headerValue, 0, mHttpHeader, 0, mHttpHeader.length);
                     }
                 }
@@ -397,7 +388,7 @@ public final class HeaderSet {
                     if (!(headerValue instanceof byte[])) {
                         throw new IllegalArgumentException("WHO must be a byte array");
                     } else {
-                        mWho = new byte[((byte[])headerValue).length];
+                        mWho = new byte[((byte[]) headerValue).length];
                         System.arraycopy(headerValue, 0, mWho, 0, mWho.length);
                     }
                 }
@@ -409,7 +400,7 @@ public final class HeaderSet {
                     if (!(headerValue instanceof byte[])) {
                         throw new IllegalArgumentException("Object Class must be a byte array");
                     } else {
-                        mObjectClass = new byte[((byte[])headerValue).length];
+                        mObjectClass = new byte[((byte[]) headerValue).length];
                         System.arraycopy(headerValue, 0, mObjectClass, 0, mObjectClass.length);
                     }
                 }
@@ -422,7 +413,7 @@ public final class HeaderSet {
                         throw new IllegalArgumentException(
                                 "Application Parameter must be a byte array");
                     } else {
-                        mAppParam = new byte[((byte[])headerValue).length];
+                        mAppParam = new byte[((byte[]) headerValue).length];
                         System.arraycopy(headerValue, 0, mAppParam, 0, mAppParam.length);
                     }
                 }
@@ -432,10 +423,9 @@ public final class HeaderSet {
                     mSingleResponseMode = null;
                 } else {
                     if (!(headerValue instanceof Byte)) {
-                        throw new IllegalArgumentException(
-                                "Single Response Mode must be a Byte");
+                        throw new IllegalArgumentException("Single Response Mode must be a Byte");
                     } else {
-                        mSingleResponseMode = (Byte)headerValue;
+                        mSingleResponseMode = (Byte) headerValue;
                     }
                 }
                 break;
@@ -447,7 +437,7 @@ public final class HeaderSet {
                         throw new IllegalArgumentException(
                                 "Single Response Mode Parameter must be a Byte");
                     } else {
-                        mSrmParam = (Byte)headerValue;
+                        mSrmParam = (Byte) headerValue;
                     }
                 }
                 break;
@@ -458,7 +448,7 @@ public final class HeaderSet {
                         throw new IllegalArgumentException(
                                 "Unicode String User Defined must be a String");
                     }
-                    mUnicodeUserDefined[headerID - 0x30] = (String)headerValue;
+                    mUnicodeUserDefined[headerID - 0x30] = (String) headerValue;
 
                     break;
                 }
@@ -472,10 +462,14 @@ public final class HeaderSet {
                             throw new IllegalArgumentException(
                                     "Byte Sequence User Defined must be a byte array");
                         } else {
-                            mSequenceUserDefined[headerID - 0x70]
-                                    = new byte[((byte[])headerValue).length];
-                            System.arraycopy(headerValue, 0, mSequenceUserDefined[headerID - 0x70],
-                                    0, mSequenceUserDefined[headerID - 0x70].length);
+                            mSequenceUserDefined[headerID - 0x70] =
+                                    new byte[((byte[]) headerValue).length];
+                            System.arraycopy(
+                                    headerValue,
+                                    0,
+                                    mSequenceUserDefined[headerID - 0x70],
+                                    0,
+                                    mSequenceUserDefined[headerID - 0x70].length);
                         }
                     }
                     break;
@@ -485,7 +479,7 @@ public final class HeaderSet {
                     if ((headerValue != null) && (!(headerValue instanceof Byte))) {
                         throw new IllegalArgumentException("ByteUser Defined must be a Byte");
                     }
-                    mByteUserDefined[headerID - 0xB0] = (Byte)headerValue;
+                    mByteUserDefined[headerID - 0xB0] = (Byte) headerValue;
 
                     break;
                 }
@@ -499,12 +493,12 @@ public final class HeaderSet {
                         }
                         throw new IllegalArgumentException("Integer User Defined must be a Long");
                     }
-                    temp = ((Long)headerValue).longValue();
+                    temp = ((Long) headerValue).longValue();
                     if ((temp < 0L) || (temp > 0xFFFFFFFFL)) {
                         throw new IllegalArgumentException(
                                 "Integer User Defined must be between 0 and 0xFFFFFFFF");
                     }
-                    mIntegerUserDefined[headerID - 0xF0] = (Long)headerValue;
+                    mIntegerUserDefined[headerID - 0xF0] = (Long) headerValue;
                     break;
                 }
                 throw new IllegalArgumentException("Invalid Header Identifier: " + headerID);
@@ -512,19 +506,16 @@ public final class HeaderSet {
     }
 
     /**
-     * Retrieves the value of the header identifier provided. The type of the
-     * Object returned is defined in the description of this interface.
+     * Retrieves the value of the header identifier provided. The type of the Object returned is
+     * defined in the description of this interface.
+     *
      * @param headerID the header identifier whose value is to be returned
-     * @return the value of the header provided or <code>null</code> if the
-     *         header identifier specified is not part of this
-     *         <code>HeaderSet</code> object
-     * @throws IllegalArgumentException if the <code>headerID</code> is not one
-     *         defined in this interface or any of the user-defined headers
-     * @throws IOException if an error occurred in the transport layer during
-     *         the operation or if the connection has been closed
+     * @return the value of the header provided or <code>null</code> if the header identifier
+     *     specified is not part of this <code>HeaderSet</code> object
+     * @throws IllegalArgumentException if the <code>headerID</code> is not one defined in this
+     *     interface or any of the user-defined headers
      */
-    public Object getHeader(int headerID) throws IOException {
-
+    public Object getHeader(int headerID) {
         switch (headerID) {
             case COUNT:
                 return mCount;
@@ -578,16 +569,15 @@ public final class HeaderSet {
     }
 
     /**
-     * Retrieves the list of headers that may be retrieved via the
-     * <code>getHeader</code> method that will not return <code>null</code>. In
-     * other words, this method returns all the headers that are available in
-     * this object.
-     * @see #getHeader
-     * @return the array of headers that are set in this object or
-     *         <code>null</code> if no headers are available
-     * @throws IOException if an error occurred in the transport layer during
-     *         the operation or the connection has been closed
+     * Retrieves the list of headers that may be retrieved via the <code>getHeader</code> method
+     * that will not return <code>null</code>. In other words, this method returns all the headers
+     * that are available in this object.
      *
+     * @see #getHeader
+     * @return the array of headers that are set in this object or <code>null</code> if no headers
+     *     are available
+     * @throws IOException if an error occurred in the transport layer during the operation or the
+     *     connection has been closed
      * @hide
      */
     public int[] getHeaderList() throws IOException {
@@ -629,10 +619,10 @@ public final class HeaderSet {
         if (mObjectClass != null) {
             out.write(OBJECT_CLASS);
         }
-        if(mSingleResponseMode != null) {
+        if (mSingleResponseMode != null) {
             out.write(SINGLE_RESPONSE_MODE);
         }
-        if(mSrmParam != null) {
+        if (mSrmParam != null) {
             out.write(SINGLE_RESPONSE_MODE_PARAMETER);
         }
 
@@ -678,46 +668,42 @@ public final class HeaderSet {
     }
 
     /**
-     * Sets the authentication challenge header. The <code>realm</code> will be
-     * encoded based upon the default encoding scheme used by the implementation
-     * to encode strings. Therefore, the encoding scheme used to encode the
-     * <code>realm</code> is application dependent.
-     * @param realm a short description that describes what password to use; if
-     *        <code>null</code> no realm will be sent in the authentication
-     *        challenge header
-     * @param userID if <code>true</code>, a user ID is required in the reply;
-     *        if <code>false</code>, no user ID is required
-     * @param access if <code>true</code> then full access will be granted if
-     *        successful; if <code>false</code> then read-only access will be
-     *        granted if successful
-     * @throws IOException
+     * Sets the authentication challenge header. The <code>realm</code> will be encoded based upon
+     * the default encoding scheme used by the implementation to encode strings. Therefore, the
+     * encoding scheme used to encode the <code>realm</code> is application dependent.
      *
+     * @param realm a short description that describes what password to use; if <code>null</code> no
+     *     realm will be sent in the authentication challenge header
+     * @param userID if <code>true</code>, a user ID is required in the reply; if <code>false</code>
+     *     , no user ID is required
+     * @param access if <code>true</code> then full access will be granted if successful; if <code>
+     *     false</code> then read-only access will be granted if successful
      * @hide
      */
     public void createAuthenticationChallenge(String realm, boolean userID, boolean access)
             throws IOException {
 
         nonce = new byte[16];
-        if(mRandom == null) {
+        if (mRandom == null) {
             mRandom = new SecureRandom();
         }
         for (int i = 0; i < 16; i++) {
-            nonce[i] = (byte)mRandom.nextInt();
+            nonce[i] = (byte) mRandom.nextInt();
         }
 
         mAuthChall = ObexHelper.computeAuthenticationChallenge(nonce, realm, access, userID);
     }
 
     /**
-     * Returns the response code received from the server. Response codes are
-     * defined in the <code>ResponseCodes</code> class.
+     * Returns the response code received from the server. Response codes are defined in the <code>
+     * ResponseCodes</code> class.
+     *
      * @see ResponseCodes
      * @return the response code retrieved from the server
-     * @throws IOException if an error occurred in the transport layer during
-     *         the transaction; if this method is called on a
-     *         <code>HeaderSet</code> object created by calling
-     *         <code>createHeaderSet()</code> in a <code>ClientSession</code>
-     *         object; if this object was created by an OBEX server
+     * @throws IOException if an error occurred in the transport layer during the transaction; if
+     *     this method is called on a <code>HeaderSet</code> object created by calling <code>
+     *     createHeaderSet()</code> in a <code>ClientSession</code> object; if this object was
+     *     created by an OBEX server
      */
     public int getResponseCode() throws IOException {
         if (responseCode == -1) {
@@ -733,13 +719,20 @@ public final class HeaderSet {
     }
 
     public String dump() {
-        return "Dumping HeaderSet " + this
-            + "\n\tCONNECTION_ID : " + Arrays.toString(mConnectionID)
-            + "\n\tNAME : " + mName
-            + "\n\tTYPE : " + mType
-            + "\n\tTARGET : " + Arrays.toString(mTarget)
-            + "\n\tWHO : " + Arrays.toString(mWho)
-            + "\n\tAPPLICATION_PARAMETER : " + Arrays.toString(mAppParam)
-            + "\n\tDumping HeaderSet END";
+        return "Dumping HeaderSet "
+                + this
+                + "\n\tCONNECTION_ID : "
+                + Arrays.toString(mConnectionID)
+                + "\n\tNAME : "
+                + mName
+                + "\n\tTYPE : "
+                + mType
+                + "\n\tTARGET : "
+                + Arrays.toString(mTarget)
+                + "\n\tWHO : "
+                + Arrays.toString(mWho)
+                + "\n\tAPPLICATION_PARAMETER : "
+                + Arrays.toString(mAppParam)
+                + "\n\tDumping HeaderSet END";
     }
 }
diff --git a/src/com/android/obex/ObexHelper.java b/src/com/android/obex/ObexHelper.java
index 5b61cd0..6d6b830 100644
--- a/src/com/android/obex/ObexHelper.java
+++ b/src/com/android/obex/ObexHelper.java
@@ -38,39 +38,35 @@ import android.util.Log;
 
 import java.io.ByteArrayOutputStream;
 import java.io.IOException;
-import java.io.UnsupportedEncodingException;
+import java.nio.charset.StandardCharsets;
 import java.security.MessageDigest;
 import java.security.NoSuchAlgorithmException;
 import java.util.Calendar;
 import java.util.Date;
 import java.util.TimeZone;
 
-
-/**
- * This class defines a set of helper methods for the implementation of Obex.
- */
+/** This class defines a set of helper methods for the implementation of Obex. */
 public final class ObexHelper {
 
     private static final String TAG = "ObexHelper";
     public static final boolean VDBG = false;
+
     /**
-     * Defines the basic packet length used by OBEX. Every OBEX packet has the
-     * same basic format:<BR>
+     * Defines the basic packet length used by OBEX. Every OBEX packet has the same basic format:
+     * <br>
      * Byte 0: Request or Response Code Byte 1&2: Length of the packet.
      */
     public static final int BASE_PACKET_LENGTH = 3;
 
     /** Prevent object construction of helper class */
-    private ObexHelper() {
-    }
+    private ObexHelper() {}
 
     /**
-     * The maximum packet size for OBEX packets that this client can handle. At
-     * present, this must be changed for each port. TODO: The max packet size
-     * should be the Max incoming MTU minus TODO: L2CAP package headers and
-     * RFCOMM package headers. TODO: Retrieve the max incoming MTU from TODO:
-     * LocalDevice.getProperty().
-     * NOTE: This value must be larger than or equal to the L2CAP SDU
+     * The maximum packet size for OBEX packets that this client can handle. At present, this must
+     * be changed for each port. TODO: The max packet size should be the Max incoming MTU minus
+     * TODO: L2CAP package headers and RFCOMM package headers. TODO: Retrieve the max incoming MTU
+     * from TODO: LocalDevice.getProperty(). NOTE: This value must be larger than or equal to the
+     * L2CAP SDU
      */
     /*
      * android note set as 0xFFFE to match remote MPS
@@ -84,8 +80,8 @@ public final class ObexHelper {
     public static final int OBEX_BYTE_SEQ_HEADER_LEN = 0x03;
 
     /**
-     * Temporary workaround to be able to push files to Windows 7.
-     * TODO: Should be removed as soon as Microsoft updates their driver.
+     * Temporary workaround to be able to push files to Windows 7. TODO: Should be removed as soon
+     * as Microsoft updates their driver.
      */
     public static final int MAX_CLIENT_PACKET_SIZE = 0xFC00;
 
@@ -133,18 +129,19 @@ public final class ObexHelper {
 
     public static final int OBEX_AUTH_REALM_CHARSET_UNICODE = 0xFF;
 
-    public static final byte OBEX_SRM_ENABLE         = 0x01; // For BT we only need enable/disable
-    public static final byte OBEX_SRM_DISABLE        = 0x00;
-    public static final byte OBEX_SRM_SUPPORT        = 0x02; // Unused for now
+    public static final byte OBEX_SRM_ENABLE = 0x01; // For BT we only need enable/disable
+    public static final byte OBEX_SRM_DISABLE = 0x00;
+    public static final byte OBEX_SRM_SUPPORT = 0x02; // Unused for now
 
-    public static final byte OBEX_SRMP_WAIT          = 0x01; // Only SRMP value used by BT
+    public static final byte OBEX_SRMP_WAIT = 0x01; // Only SRMP value used by BT
 
     /**
-     * Updates the HeaderSet with the headers received in the byte array
-     * provided. Invalid headers are ignored.
-     * <P>
-     * The first two bits of an OBEX Header specifies the type of object that is
-     * being sent. The table below specifies the meaning of the high bits.
+     * Updates the HeaderSet with the headers received in the byte array provided. Invalid headers
+     * are ignored.
+     *
+     * <p>The first two bits of an OBEX Header specifies the type of object that is being sent. The
+     * table below specifies the meaning of the high bits.
+     *
      * <TABLE>
      * <TR>
      * <TH>Bits 8 and 7</TH>
@@ -172,17 +169,18 @@ public final class ObexHelper {
      * <TD>4 byte quantity - transmitted in network byte order (high byte first</TD>
      * </TR>
      * </TABLE>
-     * This method uses the information in this table to determine the type of
-     * Java object to create and passes that object with the full header to
-     * setHeader() to update the HeaderSet object. Invalid headers will cause an
-     * exception to be thrown. When it is thrown, it is ignored.
+     *
+     * This method uses the information in this table to determine the type of Java object to create
+     * and passes that object with the full header to setHeader() to update the HeaderSet object.
+     * Invalid headers will cause an exception to be thrown. When it is thrown, it is ignored.
+     *
      * @param header the HeaderSet to update
      * @param headerArray the byte array containing headers
-     * @return the result of the last start body or end body header provided;
-     *         the first byte in the result will specify if a body or end of
-     *         body is received
+     * @return the result of the last start body or end body header provided; the first byte in the
+     *     result will specify if a body or end of body is received
      * @throws IOException if an invalid header was found
      */
+    @SuppressWarnings("JavaUtilDate")
     public static byte[] updateHeaderSet(HeaderSet header, byte[] headerArray) throws IOException {
         int index = 0;
         int length = 0;
@@ -200,16 +198,17 @@ public final class ObexHelper {
                      * two bytes after the header identifier being the length
                      */
                     case 0x00:
-                        // Fall through
-                        /*
-                         * 0x40 is a byte sequence with the first
-                         * two bytes after the header identifier being the length
-                         */
+                    // Fall through
+                    /*
+                     * 0x40 is a byte sequence with the first
+                     * two bytes after the header identifier being the length
+                     */
                     case 0x40:
                         boolean trimTail = true;
                         index++;
-                        length = ((0xFF & headerArray[index]) << 8) +
-                                 (0xFF & headerArray[index + 1]);
+                        length =
+                                ((0xFF & headerArray[index]) << 8)
+                                        + (0xFF & headerArray[index + 1]);
                         index += 2;
 
                         // An empty Name header
@@ -219,13 +218,19 @@ public final class ObexHelper {
                         }
 
                         if (length <= OBEX_BYTE_SEQ_HEADER_LEN) {
-                            Log.e(TAG, "Remote sent an OBEX packet with " +
-                                    "incorrect header length = " + length);
+                            Log.e(
+                                    TAG,
+                                    "Remote sent an OBEX packet with "
+                                            + "incorrect header length = "
+                                            + length);
                             break;
                         }
                         if (length - OBEX_BYTE_SEQ_HEADER_LEN > headerArray.length - index) {
-                            Log.e(TAG, "Remote sent an OBEX packet with " +
-                                    "incorrect header length = " + length);
+                            Log.e(
+                                    TAG,
+                                    "Remote sent an OBEX packet with "
+                                            + "incorrect header length = "
+                                            + length);
                             throw new IOException("Incorrect header length");
                         }
                         length -= OBEX_BYTE_SEQ_HEADER_LEN;
@@ -236,70 +241,77 @@ public final class ObexHelper {
                         }
                         switch (headerID) {
                             case HeaderSet.TYPE:
-                                try {
-                                    // Remove trailing null
-                                    if (trimTail == false) {
-                                        headerImpl.setHeader(headerID, new String(value, 0,
-                                                value.length, "ISO8859_1"));
-                                    } else {
-                                        headerImpl.setHeader(headerID, new String(value, 0,
-                                                value.length - 1, "ISO8859_1"));
-                                    }
-                                } catch (UnsupportedEncodingException e) {
-                                    throw e;
+                                // Remove trailing null
+                                if (trimTail == false) {
+                                    headerImpl.setHeader(
+                                            headerID,
+                                            new String(
+                                                    value,
+                                                    0,
+                                                    value.length,
+                                                    StandardCharsets.ISO_8859_1));
+                                } else {
+                                    headerImpl.setHeader(
+                                            headerID,
+                                            new String(
+                                                    value,
+                                                    0,
+                                                    value.length - 1,
+                                                    StandardCharsets.ISO_8859_1));
                                 }
                                 break;
 
                             case HeaderSet.AUTH_CHALLENGE:
                                 headerImpl.mAuthChall = new byte[length];
-                                System.arraycopy(headerArray, index, headerImpl.mAuthChall, 0,
-                                        length);
+                                System.arraycopy(
+                                        headerArray, index, headerImpl.mAuthChall, 0, length);
                                 break;
 
                             case HeaderSet.AUTH_RESPONSE:
                                 headerImpl.mAuthResp = new byte[length];
-                                System.arraycopy(headerArray, index, headerImpl.mAuthResp, 0,
-                                        length);
+                                System.arraycopy(
+                                        headerArray, index, headerImpl.mAuthResp, 0, length);
                                 break;
 
                             case HeaderSet.BODY:
-                                /* Fall Through */
+                            /* Fall Through */
                             case HeaderSet.END_OF_BODY:
                                 body = new byte[length + 1];
-                                body[0] = (byte)headerID;
+                                body[0] = (byte) headerID;
                                 System.arraycopy(headerArray, index, body, 1, length);
                                 break;
 
                             case HeaderSet.TIME_ISO_8601:
-                                try {
-                                    String dateString = new String(value, "ISO8859_1");
-                                    Calendar temp = Calendar.getInstance();
-                                    if ((dateString.length() == 16)
-                                            && (dateString.charAt(15) == 'Z')) {
-                                        temp.setTimeZone(TimeZone.getTimeZone("UTC"));
-                                    }
-                                    temp.set(Calendar.YEAR, Integer.parseInt(dateString.substring(
-                                            0, 4)));
-                                    temp.set(Calendar.MONTH, Integer.parseInt(dateString.substring(
-                                            4, 6)));
-                                    temp.set(Calendar.DAY_OF_MONTH, Integer.parseInt(dateString
-                                            .substring(6, 8)));
-                                    temp.set(Calendar.HOUR_OF_DAY, Integer.parseInt(dateString
-                                            .substring(9, 11)));
-                                    temp.set(Calendar.MINUTE, Integer.parseInt(dateString
-                                            .substring(11, 13)));
-                                    temp.set(Calendar.SECOND, Integer.parseInt(dateString
-                                            .substring(13, 15)));
-                                    headerImpl.setHeader(HeaderSet.TIME_ISO_8601, temp);
-                                } catch (UnsupportedEncodingException e) {
-                                    throw e;
+                                String dateString = new String(value, StandardCharsets.ISO_8859_1);
+                                Calendar temp = Calendar.getInstance();
+                                if ((dateString.length() == 16) && (dateString.charAt(15) == 'Z')) {
+                                    temp.setTimeZone(TimeZone.getTimeZone("UTC"));
                                 }
+                                temp.set(
+                                        Calendar.YEAR,
+                                        Integer.parseInt(dateString.substring(0, 4)));
+                                temp.set(
+                                        Calendar.MONTH,
+                                        Integer.parseInt(dateString.substring(4, 6)));
+                                temp.set(
+                                        Calendar.DAY_OF_MONTH,
+                                        Integer.parseInt(dateString.substring(6, 8)));
+                                temp.set(
+                                        Calendar.HOUR_OF_DAY,
+                                        Integer.parseInt(dateString.substring(9, 11)));
+                                temp.set(
+                                        Calendar.MINUTE,
+                                        Integer.parseInt(dateString.substring(11, 13)));
+                                temp.set(
+                                        Calendar.SECOND,
+                                        Integer.parseInt(dateString.substring(13, 15)));
+                                headerImpl.setHeader(HeaderSet.TIME_ISO_8601, temp);
                                 break;
 
                             default:
                                 if ((headerID & 0xC0) == 0x00) {
-                                    headerImpl.setHeader(headerID, ObexHelper.convertToUnicode(
-                                            value, true));
+                                    headerImpl.setHeader(
+                                            headerID, ObexHelper.convertToUnicode(value, true));
                                 } else {
                                     headerImpl.setHeader(headerID, value);
                                 }
@@ -339,8 +351,8 @@ public final class ObexHelper {
                                     headerImpl.mConnectionID = new byte[4];
                                     System.arraycopy(value, 0, headerImpl.mConnectionID, 0, 4);
                                 } else {
-                                    headerImpl.setHeader(headerID, Long
-                                            .valueOf(convertToLong(value)));
+                                    headerImpl.setHeader(
+                                            headerID, Long.valueOf(convertToLong(value)));
                                 }
                             } else {
                                 Calendar temp = Calendar.getInstance();
@@ -354,7 +366,6 @@ public final class ObexHelper {
                         index += 4;
                         break;
                 }
-
             }
         } catch (IOException e) {
             throw new IOException("Header was not formatted properly", e);
@@ -364,29 +375,28 @@ public final class ObexHelper {
     }
 
     /**
-     * Creates the header part of OBEX packet based on the header provided.
-     * TODO: Could use getHeaderList() to get the array of headers to include
-     * and then use the high two bits to determine the type of the object
-     * and construct the byte array from that. This will make the size smaller.
+     * Creates the header part of OBEX packet based on the header provided. TODO: Could use
+     * getHeaderList() to get the array of headers to include and then use the high two bits to
+     * determine the type of the object and construct the byte array from that. This will make the
+     * size smaller.
+     *
      * @param head the header used to construct the byte array
-     * @param nullOut <code>true</code> if the header should be set to
-     *        <code>null</code> once it is added to the array or
-     *        <code>false</code> if it should not be nulled out
+     * @param nullOut <code>true</code> if the header should be set to <code>null</code> once it is
+     *     added to the array or <code>false</code> if it should not be nulled out
      * @return the header of an OBEX packet
      */
+    @SuppressWarnings("JavaUtilDate")
     public static byte[] createHeader(HeaderSet head, boolean nullOut) {
         Long intHeader = null;
         String stringHeader = null;
         Calendar dateHeader = null;
         Byte byteHeader = null;
-        StringBuffer buffer = null;
         byte[] value = null;
         byte[] result = null;
         byte[] lengthArray = new byte[2];
         int length;
-        HeaderSet headImpl = null;
+        HeaderSet headImpl = head;
         ByteArrayOutputStream out = new ByteArrayOutputStream();
-        headImpl = head;
 
         try {
             /*
@@ -396,14 +406,14 @@ public final class ObexHelper {
             if ((headImpl.mConnectionID != null)
                     && (headImpl.getHeader(HeaderSet.TARGET) == null)) {
 
-                out.write((byte)HeaderSet.CONNECTION_ID);
+                out.write((byte) HeaderSet.CONNECTION_ID);
                 out.write(headImpl.mConnectionID);
             }
 
             // Count Header
-            intHeader = (Long)headImpl.getHeader(HeaderSet.COUNT);
+            intHeader = (Long) headImpl.getHeader(HeaderSet.COUNT);
             if (intHeader != null) {
-                out.write((byte)HeaderSet.COUNT);
+                out.write((byte) HeaderSet.COUNT);
                 value = ObexHelper.convertToByteArray(intHeader.longValue());
                 out.write(value);
                 if (nullOut) {
@@ -412,13 +422,13 @@ public final class ObexHelper {
             }
 
             // Name Header
-            stringHeader = (String)headImpl.getHeader(HeaderSet.NAME);
+            stringHeader = (String) headImpl.getHeader(HeaderSet.NAME);
             if (stringHeader != null) {
-                out.write((byte)HeaderSet.NAME);
+                out.write((byte) HeaderSet.NAME);
                 value = ObexHelper.convertToUnicodeByteArray(stringHeader);
                 length = value.length + 3;
-                lengthArray[0] = (byte)(0xFF & (length >> 8));
-                lengthArray[1] = (byte)(0xFF & length);
+                lengthArray[0] = (byte) (0xFF & (length >> 8));
+                lengthArray[1] = (byte) (0xFF & length);
                 out.write(lengthArray);
                 out.write(value);
                 if (nullOut) {
@@ -432,18 +442,14 @@ public final class ObexHelper {
             }
 
             // Type Header
-            stringHeader = (String)headImpl.getHeader(HeaderSet.TYPE);
+            stringHeader = (String) headImpl.getHeader(HeaderSet.TYPE);
             if (stringHeader != null) {
-                out.write((byte)HeaderSet.TYPE);
-                try {
-                    value = stringHeader.getBytes("ISO8859_1");
-                } catch (UnsupportedEncodingException e) {
-                    throw e;
-                }
+                out.write((byte) HeaderSet.TYPE);
+                value = stringHeader.getBytes(StandardCharsets.ISO_8859_1);
 
                 length = value.length + 4;
-                lengthArray[0] = (byte)(255 & (length >> 8));
-                lengthArray[1] = (byte)(255 & length);
+                lengthArray[0] = (byte) (255 & (length >> 8));
+                lengthArray[1] = (byte) (255 & length);
                 out.write(lengthArray);
                 out.write(value);
                 out.write(0x00);
@@ -453,9 +459,9 @@ public final class ObexHelper {
             }
 
             // Length Header
-            intHeader = (Long)headImpl.getHeader(HeaderSet.LENGTH);
+            intHeader = (Long) headImpl.getHeader(HeaderSet.LENGTH);
             if (intHeader != null) {
-                out.write((byte)HeaderSet.LENGTH);
+                out.write((byte) HeaderSet.LENGTH);
                 value = ObexHelper.convertToByteArray(intHeader.longValue());
                 out.write(value);
                 if (nullOut) {
@@ -464,14 +470,14 @@ public final class ObexHelper {
             }
 
             // Time ISO Header
-            dateHeader = (Calendar)headImpl.getHeader(HeaderSet.TIME_ISO_8601);
+            dateHeader = (Calendar) headImpl.getHeader(HeaderSet.TIME_ISO_8601);
             if (dateHeader != null) {
 
                 /*
                  * The ISO Header should take the form YYYYMMDDTHHMMSSZ.  The
                  * 'Z' will only be included if it is a UTC time.
                  */
-                buffer = new StringBuffer();
+                StringBuilder buffer = new StringBuilder();
                 int temp = dateHeader.get(Calendar.YEAR);
                 for (int i = temp; i < 1000; i = i * 10) {
                     buffer.append("0");
@@ -508,15 +514,11 @@ public final class ObexHelper {
                     buffer.append("Z");
                 }
 
-                try {
-                    value = buffer.toString().getBytes("ISO8859_1");
-                } catch (UnsupportedEncodingException e) {
-                    throw e;
-                }
+                value = buffer.toString().getBytes(StandardCharsets.ISO_8859_1);
 
                 length = value.length + 3;
-                lengthArray[0] = (byte)(255 & (length >> 8));
-                lengthArray[1] = (byte)(255 & length);
+                lengthArray[0] = (byte) (255 & (length >> 8));
+                lengthArray[1] = (byte) (255 & length);
                 out.write(HeaderSet.TIME_ISO_8601);
                 out.write(lengthArray);
                 out.write(value);
@@ -526,7 +528,7 @@ public final class ObexHelper {
             }
 
             // Time 4 Byte Header
-            dateHeader = (Calendar)headImpl.getHeader(HeaderSet.TIME_4_BYTE);
+            dateHeader = (Calendar) headImpl.getHeader(HeaderSet.TIME_4_BYTE);
             if (dateHeader != null) {
                 out.write(HeaderSet.TIME_4_BYTE);
 
@@ -545,13 +547,13 @@ public final class ObexHelper {
             }
 
             // Description Header
-            stringHeader = (String)headImpl.getHeader(HeaderSet.DESCRIPTION);
+            stringHeader = (String) headImpl.getHeader(HeaderSet.DESCRIPTION);
             if (stringHeader != null) {
-                out.write((byte)HeaderSet.DESCRIPTION);
+                out.write((byte) HeaderSet.DESCRIPTION);
                 value = ObexHelper.convertToUnicodeByteArray(stringHeader);
                 length = value.length + 3;
-                lengthArray[0] = (byte)(255 & (length >> 8));
-                lengthArray[1] = (byte)(255 & length);
+                lengthArray[0] = (byte) (255 & (length >> 8));
+                lengthArray[1] = (byte) (255 & length);
                 out.write(lengthArray);
                 out.write(value);
                 if (nullOut) {
@@ -560,12 +562,12 @@ public final class ObexHelper {
             }
 
             // Target Header
-            value = (byte[])headImpl.getHeader(HeaderSet.TARGET);
+            value = (byte[]) headImpl.getHeader(HeaderSet.TARGET);
             if (value != null) {
-                out.write((byte)HeaderSet.TARGET);
+                out.write((byte) HeaderSet.TARGET);
                 length = value.length + 3;
-                lengthArray[0] = (byte)(255 & (length >> 8));
-                lengthArray[1] = (byte)(255 & length);
+                lengthArray[0] = (byte) (255 & (length >> 8));
+                lengthArray[1] = (byte) (255 & length);
                 out.write(lengthArray);
                 out.write(value);
                 if (nullOut) {
@@ -574,12 +576,12 @@ public final class ObexHelper {
             }
 
             // HTTP Header
-            value = (byte[])headImpl.getHeader(HeaderSet.HTTP);
+            value = (byte[]) headImpl.getHeader(HeaderSet.HTTP);
             if (value != null) {
-                out.write((byte)HeaderSet.HTTP);
+                out.write((byte) HeaderSet.HTTP);
                 length = value.length + 3;
-                lengthArray[0] = (byte)(255 & (length >> 8));
-                lengthArray[1] = (byte)(255 & length);
+                lengthArray[0] = (byte) (255 & (length >> 8));
+                lengthArray[1] = (byte) (255 & length);
                 out.write(lengthArray);
                 out.write(value);
                 if (nullOut) {
@@ -588,12 +590,12 @@ public final class ObexHelper {
             }
 
             // Who Header
-            value = (byte[])headImpl.getHeader(HeaderSet.WHO);
+            value = (byte[]) headImpl.getHeader(HeaderSet.WHO);
             if (value != null) {
-                out.write((byte)HeaderSet.WHO);
+                out.write((byte) HeaderSet.WHO);
                 length = value.length + 3;
-                lengthArray[0] = (byte)(255 & (length >> 8));
-                lengthArray[1] = (byte)(255 & length);
+                lengthArray[0] = (byte) (255 & (length >> 8));
+                lengthArray[1] = (byte) (255 & length);
                 out.write(lengthArray);
                 out.write(value);
                 if (nullOut) {
@@ -602,12 +604,12 @@ public final class ObexHelper {
             }
 
             // Connection ID Header
-            value = (byte[])headImpl.getHeader(HeaderSet.APPLICATION_PARAMETER);
+            value = (byte[]) headImpl.getHeader(HeaderSet.APPLICATION_PARAMETER);
             if (value != null) {
-                out.write((byte)HeaderSet.APPLICATION_PARAMETER);
+                out.write((byte) HeaderSet.APPLICATION_PARAMETER);
                 length = value.length + 3;
-                lengthArray[0] = (byte)(255 & (length >> 8));
-                lengthArray[1] = (byte)(255 & length);
+                lengthArray[0] = (byte) (255 & (length >> 8));
+                lengthArray[1] = (byte) (255 & length);
                 out.write(lengthArray);
                 out.write(value);
                 if (nullOut) {
@@ -616,12 +618,12 @@ public final class ObexHelper {
             }
 
             // Object Class Header
-            value = (byte[])headImpl.getHeader(HeaderSet.OBJECT_CLASS);
+            value = (byte[]) headImpl.getHeader(HeaderSet.OBJECT_CLASS);
             if (value != null) {
-                out.write((byte)HeaderSet.OBJECT_CLASS);
+                out.write((byte) HeaderSet.OBJECT_CLASS);
                 length = value.length + 3;
-                lengthArray[0] = (byte)(255 & (length >> 8));
-                lengthArray[1] = (byte)(255 & length);
+                lengthArray[0] = (byte) (255 & (length >> 8));
+                lengthArray[1] = (byte) (255 & length);
                 out.write(lengthArray);
                 out.write(value);
                 if (nullOut) {
@@ -632,14 +634,14 @@ public final class ObexHelper {
             // Check User Defined Headers
             for (int i = 0; i < 16; i++) {
 
-                //Unicode String Header
-                stringHeader = (String)headImpl.getHeader(i + 0x30);
+                // Unicode String Header
+                stringHeader = (String) headImpl.getHeader(i + 0x30);
                 if (stringHeader != null) {
-                    out.write((byte)i + 0x30);
+                    out.write((byte) i + 0x30);
                     value = ObexHelper.convertToUnicodeByteArray(stringHeader);
                     length = value.length + 3;
-                    lengthArray[0] = (byte)(255 & (length >> 8));
-                    lengthArray[1] = (byte)(255 & length);
+                    lengthArray[0] = (byte) (255 & (length >> 8));
+                    lengthArray[1] = (byte) (255 & length);
                     out.write(lengthArray);
                     out.write(value);
                     if (nullOut) {
@@ -648,12 +650,12 @@ public final class ObexHelper {
                 }
 
                 // Byte Sequence Header
-                value = (byte[])headImpl.getHeader(i + 0x70);
+                value = (byte[]) headImpl.getHeader(i + 0x70);
                 if (value != null) {
-                    out.write((byte)i + 0x70);
+                    out.write((byte) i + 0x70);
                     length = value.length + 3;
-                    lengthArray[0] = (byte)(255 & (length >> 8));
-                    lengthArray[1] = (byte)(255 & length);
+                    lengthArray[0] = (byte) (255 & (length >> 8));
+                    lengthArray[1] = (byte) (255 & length);
                     out.write(lengthArray);
                     out.write(value);
                     if (nullOut) {
@@ -662,9 +664,9 @@ public final class ObexHelper {
                 }
 
                 // Byte Header
-                byteHeader = (Byte)headImpl.getHeader(i + 0xB0);
+                byteHeader = (Byte) headImpl.getHeader(i + 0xB0);
                 if (byteHeader != null) {
-                    out.write((byte)i + 0xB0);
+                    out.write((byte) i + 0xB0);
                     out.write(byteHeader.byteValue());
                     if (nullOut) {
                         headImpl.setHeader(i + 0xB0, null);
@@ -672,9 +674,9 @@ public final class ObexHelper {
                 }
 
                 // Integer header
-                intHeader = (Long)headImpl.getHeader(i + 0xF0);
+                intHeader = (Long) headImpl.getHeader(i + 0xF0);
                 if (intHeader != null) {
-                    out.write((byte)i + 0xF0);
+                    out.write((byte) i + 0xF0);
                     out.write(ObexHelper.convertToByteArray(intHeader.longValue()));
                     if (nullOut) {
                         headImpl.setHeader(i + 0xF0, null);
@@ -684,10 +686,10 @@ public final class ObexHelper {
 
             // Add the authentication challenge header
             if (headImpl.mAuthChall != null) {
-                out.write((byte)HeaderSet.AUTH_CHALLENGE);
+                out.write((byte) HeaderSet.AUTH_CHALLENGE);
                 length = headImpl.mAuthChall.length + 3;
-                lengthArray[0] = (byte)(255 & (length >> 8));
-                lengthArray[1] = (byte)(255 & length);
+                lengthArray[0] = (byte) (255 & (length >> 8));
+                lengthArray[1] = (byte) (255 & length);
                 out.write(lengthArray);
                 out.write(headImpl.mAuthChall);
                 if (nullOut) {
@@ -697,10 +699,10 @@ public final class ObexHelper {
 
             // Add the authentication response header
             if (headImpl.mAuthResp != null) {
-                out.write((byte)HeaderSet.AUTH_RESPONSE);
+                out.write((byte) HeaderSet.AUTH_RESPONSE);
                 length = headImpl.mAuthResp.length + 3;
-                lengthArray[0] = (byte)(255 & (length >> 8));
-                lengthArray[1] = (byte)(255 & length);
+                lengthArray[0] = (byte) (255 & (length >> 8));
+                lengthArray[1] = (byte) (255 & length);
                 out.write(lengthArray);
                 out.write(headImpl.mAuthResp);
                 if (nullOut) {
@@ -716,9 +718,9 @@ public final class ObexHelper {
             // transferring non-body headers
 
             // Add the SRM header
-            byteHeader = (Byte)headImpl.getHeader(HeaderSet.SINGLE_RESPONSE_MODE);
+            byteHeader = (Byte) headImpl.getHeader(HeaderSet.SINGLE_RESPONSE_MODE);
             if (byteHeader != null) {
-                out.write((byte)HeaderSet.SINGLE_RESPONSE_MODE);
+                out.write((byte) HeaderSet.SINGLE_RESPONSE_MODE);
                 out.write(byteHeader.byteValue());
                 if (nullOut) {
                     headImpl.setHeader(HeaderSet.SINGLE_RESPONSE_MODE, null);
@@ -726,37 +728,37 @@ public final class ObexHelper {
             }
 
             // Add the SRM parameter header
-            byteHeader = (Byte)headImpl.getHeader(HeaderSet.SINGLE_RESPONSE_MODE_PARAMETER);
+            byteHeader = (Byte) headImpl.getHeader(HeaderSet.SINGLE_RESPONSE_MODE_PARAMETER);
             if (byteHeader != null) {
-                out.write((byte)HeaderSet.SINGLE_RESPONSE_MODE_PARAMETER);
+                out.write((byte) HeaderSet.SINGLE_RESPONSE_MODE_PARAMETER);
                 out.write(byteHeader.byteValue());
                 if (nullOut) {
                     headImpl.setHeader(HeaderSet.SINGLE_RESPONSE_MODE_PARAMETER, null);
                 }
             }
-
         } catch (IOException e) {
+            // Impossible in a ByteArrayOutputStream
         } finally {
             result = out.toByteArray();
             try {
                 out.close();
             } catch (Exception ex) {
+                // Preventing exception propagation during closing
             }
         }
 
         return result;
-
     }
 
     /**
-     * Determines where the maximum divide is between headers. This method is
-     * used by put and get operations to separate headers to a size that meets
-     * the max packet size allowed.
+     * Determines where the maximum divide is between headers. This method is used by put and get
+     * operations to separate headers to a size that meets the max packet size allowed.
+     *
      * @param headerArray the headers to separate
      * @param start the starting index to search
      * @param maxSize the maximum size of a packet
-     * @return the index of the end of the header block to send or -1 if the
-     *         header could not be divided because the header is too large
+     * @return the index of the end of the header block to send or -1 if the header could not be
+     *     divided because the header is too large
      */
     public static int findHeaderEnd(byte[] headerArray, int start, int maxSize) {
 
@@ -772,18 +774,20 @@ public final class ObexHelper {
             lastLength = fullLength;
 
             switch (headerID & (0xC0)) {
-
                 case 0x00:
-                    // Fall through
+                // Fall through
                 case 0x40:
-
                     index++;
-                    length = (headerArray[index] < 0 ? headerArray[index] + 256
-                            : headerArray[index]);
+                    length =
+                            (headerArray[index] < 0
+                                    ? headerArray[index] + 256
+                                    : headerArray[index]);
                     length = length << 8;
                     index++;
-                    length += (headerArray[index] < 0 ? headerArray[index] + 256
-                            : headerArray[index]);
+                    length +=
+                            (headerArray[index] < 0
+                                    ? headerArray[index] + 256
+                                    : headerArray[index]);
                     length -= 3;
                     index++;
                     index += length;
@@ -791,20 +795,16 @@ public final class ObexHelper {
                     break;
 
                 case 0x80:
-
                     index++;
                     index++;
                     fullLength += 2;
                     break;
 
                 case 0xC0:
-
                     index += 5;
                     fullLength += 5;
                     break;
-
             }
-
         }
 
         /*
@@ -829,6 +829,7 @@ public final class ObexHelper {
 
     /**
      * Converts the byte array to a long.
+     *
      * @param b the byte array to convert to a long
      * @return the byte array as a long
      */
@@ -852,23 +853,25 @@ public final class ObexHelper {
 
     /**
      * Converts the long to a 4 byte array. The long must be non negative.
+     *
      * @param l the long to convert
      * @return a byte array that is the same as the long
      */
     public static byte[] convertToByteArray(long l) {
         byte[] b = new byte[4];
 
-        b[0] = (byte)(255 & (l >> 24));
-        b[1] = (byte)(255 & (l >> 16));
-        b[2] = (byte)(255 & (l >> 8));
-        b[3] = (byte)(255 & l);
+        b[0] = (byte) (255 & (l >> 24));
+        b[1] = (byte) (255 & (l >> 16));
+        b[2] = (byte) (255 & (l >> 8));
+        b[3] = (byte) (255 & l);
 
         return b;
     }
 
     /**
-     * Converts the String to a UNICODE byte array. It will also add the ending
-     * null characters to the end of the string.
+     * Converts the String to a UNICODE byte array. It will also add the ending null characters to
+     * the end of the string.
+     *
      * @param s the string to convert
      * @return the unicode byte array of the string
      */
@@ -880,8 +883,8 @@ public final class ObexHelper {
         char c[] = s.toCharArray();
         byte[] result = new byte[(c.length * 2) + 2];
         for (int i = 0; i < c.length; i++) {
-            result[(i * 2)] = (byte)(c[i] >> 8);
-            result[((i * 2) + 1)] = (byte)c[i];
+            result[(i * 2)] = (byte) (c[i] >> 8);
+            result[((i * 2) + 1)] = (byte) c[i];
         }
 
         // Add the UNICODE null character
@@ -892,8 +895,9 @@ public final class ObexHelper {
     }
 
     /**
-     * Retrieves the value from the byte array for the tag value specified. The
-     * array should be of the form Tag - Length - Value triplet.
+     * Retrieves the value from the byte array for the tag value specified. The array should be of
+     * the form Tag - Length - Value triplet.
+     *
      * @param tag the tag to retrieve from the byte array
      * @param triplet the byte sequence containing the tag length value form
      * @return the value of the specified tag
@@ -917,6 +921,7 @@ public final class ObexHelper {
 
     /**
      * Finds the index that starts the tag value pair in the byte array provide.
+     *
      * @param tag the tag to look for
      * @param value the byte array to search
      * @return the starting index of the tag or -1 if the tag could not be found
@@ -944,10 +949,10 @@ public final class ObexHelper {
 
     /**
      * Converts the byte array provided to a unicode string.
+     *
      * @param b the byte array to convert to a string
-     * @param includesNull determine if the byte string provided contains the
-     *        UNICODE null character at the end or not; if it does, it will be
-     *        removed
+     * @param includesNull determine if the byte string provided contains the UNICODE null character
+     *     at the end or not; if it does, it will be removed
      * @return a Unicode string
      * @throws IllegalArgumentException if the byte array has an odd length
      */
@@ -980,15 +985,15 @@ public final class ObexHelper {
                 return new String(c, 0, i);
             }
 
-            c[i] = (char)((upper << 8) | lower);
+            c[i] = (char) ((upper << 8) | lower);
         }
 
         return new String(c);
     }
 
     /**
-     * Compute the MD5 hash of the byte array provided. Does not accumulate
-     * input.
+     * Compute the MD5 hash of the byte array provided. Does not accumulate input.
+     *
      * @param in the byte array to hash
      * @return the MD5 hash of the byte array
      */
@@ -1003,20 +1008,20 @@ public final class ObexHelper {
 
     /**
      * Computes an authentication challenge header.
-     * @param nonce the challenge that will be provided to the peer; the
-     *        challenge must be 16 bytes long
+     *
+     * @param nonce the challenge that will be provided to the peer; the challenge must be 16 bytes
+     *     long
      * @param realm a short description that describes what password to use
-     * @param access if <code>true</code> then full access will be granted if
-     *        successful; if <code>false</code> then read only access will be
-     *        granted if successful
-     * @param userID if <code>true</code>, a user ID is required in the reply;
-     *        if <code>false</code>, no user ID is required
-     * @throws IllegalArgumentException if the challenge is not 16 bytes long;
-     *         if the realm can not be encoded in less than 255 bytes
+     * @param access if <code>true</code> then full access will be granted if successful; if <code>
+     *     false</code> then read only access will be granted if successful
+     * @param userID if <code>true</code>, a user ID is required in the reply; if <code>false</code>
+     *     , no user ID is required
+     * @throws IllegalArgumentException if the challenge is not 16 bytes long; if the realm can not
+     *     be encoded in less than 255 bytes
      * @throws IOException if the encoding scheme ISO 8859-1 is not supported
      */
-    public static byte[] computeAuthenticationChallenge(byte[] nonce, String realm, boolean access,
-            boolean userID) throws IOException {
+    public static byte[] computeAuthenticationChallenge(
+            byte[] nonce, String realm, boolean access, boolean userID) throws IOException {
         byte[] authChall = null;
 
         if (nonce.length != 16) {
@@ -1049,9 +1054,10 @@ public final class ObexHelper {
             }
             authChall = new byte[24 + realm.length()];
             authChall[21] = 0x02;
-            authChall[22] = (byte)(realm.length() + 1);
+            authChall[22] = (byte) (realm.length() + 1);
             authChall[23] = 0x01; // ISO 8859-1 Encoding
-            System.arraycopy(realm.getBytes("ISO8859_1"), 0, authChall, 24, realm.length());
+            System.arraycopy(
+                    realm.getBytes(StandardCharsets.ISO_8859_1), 0, authChall, 24, realm.length());
         }
 
         // Include the nonce field in the header
@@ -1065,18 +1071,19 @@ public final class ObexHelper {
         authChall[20] = 0x00;
 
         if (!access) {
-            authChall[20] = (byte)(authChall[20] | 0x02);
+            authChall[20] = (byte) (authChall[20] | 0x02);
         }
         if (userID) {
-            authChall[20] = (byte)(authChall[20] | 0x01);
+            authChall[20] = (byte) (authChall[20] | 0x01);
         }
 
         return authChall;
     }
 
     /**
-     * Return the maximum allowed OBEX packet to transmit.
-     * OBEX packets transmitted must be smaller than this value.
+     * Return the maximum allowed OBEX packet to transmit. OBEX packets transmitted must be smaller
+     * than this value.
+     *
      * @param transport Reference to the ObexTransport in use.
      * @return the maximum allowed OBEX packet to transmit
      */
@@ -1087,7 +1094,7 @@ public final class ObexHelper {
 
     /**
      * Return the maximum allowed OBEX packet to receive - used in OBEX connect.
-     * @param transport
+     *
      * @return the maximum allowed OBEX packet to receive
      */
     public static int getMaxRxPacketSize(ObexTransport transport) {
@@ -1097,13 +1104,18 @@ public final class ObexHelper {
 
     private static int validateMaxPacketSize(int size) {
         if (VDBG && (size > MAX_PACKET_SIZE_INT)) {
-            Log.w(TAG, "The packet size supported for the connection (" + size + ") is larger"
-                    + " than the configured OBEX packet size: " + MAX_PACKET_SIZE_INT);
+            Log.w(
+                    TAG,
+                    "The packet size supported for the connection ("
+                            + size
+                            + ") is larger"
+                            + " than the configured OBEX packet size: "
+                            + MAX_PACKET_SIZE_INT);
         }
         if (size != -1 && size < MAX_PACKET_SIZE_INT) {
             if (size < LOWER_LIMIT_MAX_PACKET_SIZE) {
-                throw new IllegalArgumentException(size + " is less that the lower limit: "
-                        + LOWER_LIMIT_MAX_PACKET_SIZE);
+                throw new IllegalArgumentException(
+                        size + " is less that the lower limit: " + LOWER_LIMIT_MAX_PACKET_SIZE);
             }
             return size;
         }
diff --git a/src/com/android/obex/ObexPacket.java b/src/com/android/obex/ObexPacket.java
index be8446a..fc2d613 100644
--- a/src/com/android/obex/ObexPacket.java
+++ b/src/com/android/obex/ObexPacket.java
@@ -32,6 +32,7 @@ public class ObexPacket {
 
     /**
      * Create a complete OBEX packet by reading data from an InputStream.
+     *
      * @param is the input stream to read from.
      * @return the OBEX packet read.
      * @throws IOException if an IO exception occurs during read.
@@ -43,10 +44,10 @@ public class ObexPacket {
 
     /**
      * Read the remainder of an OBEX packet, with a specified headerId.
+     *
      * @param headerId the headerId already read from the stream.
      * @param is the stream to read from, assuming 1 byte have already been read.
      * @return the OBEX packet read.
-     * @throws IOException
      */
     public static ObexPacket read(int headerId, InputStream is) throws IOException {
         // Read the 2 byte length field from the stream
diff --git a/src/com/android/obex/ObexSession.java b/src/com/android/obex/ObexSession.java
index a3abc19..e99330b 100644
--- a/src/com/android/obex/ObexSession.java
+++ b/src/com/android/obex/ObexSession.java
@@ -35,16 +35,16 @@ package com.android.obex;
 import android.util.Log;
 
 import java.io.IOException;
+import java.nio.charset.StandardCharsets;
 
 /**
- * The <code>ObexSession</code> interface characterizes the term
- * "OBEX Connection" as defined in the IrDA Object Exchange Protocol v1.2, which
- * could be the server-side view of an OBEX connection, or the client-side view
- * of the same connection, which is established by server's accepting of a
+ * The <code>ObexSession</code> interface characterizes the term "OBEX Connection" as defined in the
+ * IrDA Object Exchange Protocol v1.2, which could be the server-side view of an OBEX connection, or
+ * the client-side view of the same connection, which is established by server's accepting of a
  * client issued "CONNECT".
- * <P>
- * This interface serves as the common super class for
- * <CODE>ClientSession</CODE> and <CODE>ServerSession</CODE>.
+ *
+ * <p>This interface serves as the common super class for <CODE>ClientSession</CODE> and <CODE>
+ * ServerSession</CODE>.
  */
 public class ObexSession {
 
@@ -56,12 +56,12 @@ public class ObexSession {
     protected byte[] mChallengeDigest;
 
     /**
-     * Called when the server received an authentication challenge header. This
-     * will cause the authenticator to handle the authentication challenge.
+     * Called when the server received an authentication challenge header. This will cause the
+     * authenticator to handle the authentication challenge.
+     *
      * @param header the header with the authentication challenge
-     * @return <code>true</code> if the last request should be resent;
-     *         <code>false</code> if the last request should not be resent
-     * @throws IOException
+     * @return <code>true</code> if the last request should be resent; <code>false</code> if the
+     *     last request should not be resent
      */
     public boolean handleAuthChall(HeaderSet header) throws IOException {
         if (mAuthenticator == null) {
@@ -77,9 +77,9 @@ public class ObexSession {
          * 0x02 is the realm, which provides a description of which user name
          * and password to use.
          */
-        byte[] challenge = ObexHelper.getTagValue((byte)0x00, header.mAuthChall);
-        byte[] option = ObexHelper.getTagValue((byte)0x01, header.mAuthChall);
-        byte[] description = ObexHelper.getTagValue((byte)0x02, header.mAuthChall);
+        byte[] challenge = ObexHelper.getTagValue((byte) 0x00, header.mAuthChall);
+        byte[] option = ObexHelper.getTagValue((byte) 0x01, header.mAuthChall);
+        byte[] description = ObexHelper.getTagValue((byte) 0x02, header.mAuthChall);
 
         String realm = null;
         if (description != null) {
@@ -87,17 +87,11 @@ public class ObexSession {
             System.arraycopy(description, 1, realmString, 0, realmString.length);
 
             switch (description[0] & 0xFF) {
-
                 case ObexHelper.OBEX_AUTH_REALM_CHARSET_ASCII:
-                    // ASCII encoding
-                    // Fall through
+                // ASCII encoding
+                // Fall through
                 case ObexHelper.OBEX_AUTH_REALM_CHARSET_ISO_8859_1:
-                    // ISO-8859-1 encoding
-                    try {
-                        realm = new String(realmString, "ISO8859_1");
-                    } catch (Exception e) {
-                        throw new IOException("Unsupported Encoding Scheme");
-                    }
+                    realm = new String(realmString, StandardCharsets.ISO_8859_1);
                     break;
 
                 case ObexHelper.OBEX_AUTH_REALM_CHARSET_UNICODE:
@@ -126,8 +120,8 @@ public class ObexSession {
         header.mAuthChall = null;
 
         try {
-            result = mAuthenticator
-                    .onAuthenticationChallenge(realm, isUserIDRequired, isFullAccess);
+            result =
+                    mAuthenticator.onAuthenticationChallenge(realm, isUserIDRequired, isFullAccess);
         } catch (Exception e) {
             if (V) Log.d(TAG, "Exception occurred - returning false", e);
             return false;
@@ -157,8 +151,8 @@ public class ObexSession {
          */
         if (userName != null) {
             header.mAuthResp = new byte[38 + userName.length];
-            header.mAuthResp[36] = (byte)0x01;
-            header.mAuthResp[37] = (byte)userName.length;
+            header.mAuthResp[36] = (byte) 0x01;
+            header.mAuthResp[37] = (byte) userName.length;
             System.arraycopy(userName, 0, header.mAuthResp, 38, userName.length);
         } else {
             header.mAuthResp = new byte[36];
@@ -168,37 +162,38 @@ public class ObexSession {
         byte[] digest = new byte[challenge.length + password.length + 1];
         System.arraycopy(challenge, 0, digest, 0, challenge.length);
         // Insert colon between challenge and password
-        digest[challenge.length] = (byte)0x3A;
+        digest[challenge.length] = (byte) 0x3A;
         System.arraycopy(password, 0, digest, challenge.length + 1, password.length);
 
         // Add the Response Digest
-        header.mAuthResp[0] = (byte)0x00;
-        header.mAuthResp[1] = (byte)0x10;
+        header.mAuthResp[0] = (byte) 0x00;
+        header.mAuthResp[1] = (byte) 0x10;
 
         System.arraycopy(ObexHelper.computeMd5Hash(digest), 0, header.mAuthResp, 2, 16);
 
         // Add the challenge
-        header.mAuthResp[18] = (byte)0x02;
-        header.mAuthResp[19] = (byte)0x10;
+        header.mAuthResp[18] = (byte) 0x02;
+        header.mAuthResp[19] = (byte) 0x10;
         System.arraycopy(challenge, 0, header.mAuthResp, 20, 16);
 
         return true;
     }
 
     /**
-     * Called when the server received an authentication response header. This
-     * will cause the authenticator to handle the authentication response.
+     * Called when the server received an authentication response header. This will cause the
+     * authenticator to handle the authentication response.
+     *
      * @param authResp the authentication response
-     * @return <code>true</code> if the response passed; <code>false</code> if
-     *         the response failed
+     * @return <code>true</code> if the response passed; <code>false</code> if the response failed
      */
     public boolean handleAuthResp(byte[] authResp) {
         if (mAuthenticator == null) {
             return false;
         }
         // get the correct password from the application
-        byte[] correctPassword = mAuthenticator.onAuthenticationResponse(ObexHelper.getTagValue(
-                (byte)0x01, authResp));
+        byte[] correctPassword =
+                mAuthenticator.onAuthenticationResponse(
+                        ObexHelper.getTagValue((byte) 0x01, authResp));
         if (correctPassword == null) {
             return false;
         }
@@ -209,7 +204,7 @@ public class ObexSession {
         System.arraycopy(correctPassword, 0, temp, 16, correctPassword.length);
 
         byte[] correctResponse = ObexHelper.computeMd5Hash(temp);
-        byte[] actualResponse = ObexHelper.getTagValue((byte)0x00, authResp);
+        byte[] actualResponse = ObexHelper.getTagValue((byte) 0x00, authResp);
 
         // compare the MD5 hash array .
         for (int i = 0; i < 16; i++) {
diff --git a/src/com/android/obex/ObexTransport.java b/src/com/android/obex/ObexTransport.java
index f3090dc..cffcac0 100644
--- a/src/com/android/obex/ObexTransport.java
+++ b/src/com/android/obex/ObexTransport.java
@@ -39,18 +39,17 @@ import java.io.InputStream;
 import java.io.OutputStream;
 
 /**
- * The <code>ObexTransport</code> interface defines the underlying transport
- * connection which carries the OBEX protocol( such as TCP, RFCOMM device file
- * exposed by Bluetooth or USB in kernel, RFCOMM socket emulated in Android
- * platform, Irda). This interface provides an abstract layer to be used by the
- * <code>ObexConnection</code>. Each kind of medium shall have its own
- * implementation to wrap and follow the same interface.
- * <P>
- * See section 1.2.2 of IrDA Object Exchange Protocol specification.
- * <P>
- * Different kind of medium may have different construction - for example, the
- * RFCOMM device file medium may be constructed from a file descriptor or simply
- * a string while the TCP medium usually from a socket.
+ * The <code>ObexTransport</code> interface defines the underlying transport connection which
+ * carries the OBEX protocol( such as TCP, RFCOMM device file exposed by Bluetooth or USB in kernel,
+ * RFCOMM socket emulated in Android platform, Irda). This interface provides an abstract layer to
+ * be used by the <code>ObexConnection</code>. Each kind of medium shall have its own implementation
+ * to wrap and follow the same interface.
+ *
+ * <p>See section 1.2.2 of IrDA Object Exchange Protocol specification.
+ *
+ * <p>Different kind of medium may have different construction - for example, the RFCOMM device file
+ * medium may be constructed from a file descriptor or simply a string while the TCP medium usually
+ * from a socket.
  */
 public interface ObexTransport {
 
@@ -73,40 +72,34 @@ public interface ObexTransport {
     DataOutputStream openDataOutputStream() throws IOException;
 
     /**
-     * Must return the maximum allowed OBEX packet that can be sent over
-     * the transport. For L2CAP this will be the Max SDU reported by the
-     * peer device.
-     * The returned value will be used to set the outgoing OBEX packet
-     * size. Therefore this value shall not change.
-     * For RFCOMM or other transport types where the OBEX packets size
-     * is unrelated to the transport packet size, return -1;
-     * Exception can be made (like PBAP transport) with a smaller value
-     * to avoid bad effect on other profiles using the RFCOMM;
-     * @return the maximum allowed OBEX packet that can be send over
-     *         the transport. Or -1 in case of don't care.
+     * Must return the maximum allowed OBEX packet that can be sent over the transport. For L2CAP
+     * this will be the Max SDU reported by the peer device. The returned value will be used to set
+     * the outgoing OBEX packet size. Therefore this value shall not change. For RFCOMM or other
+     * transport types where the OBEX packets size is unrelated to the transport packet size, return
+     * -1; Exception can be made (like PBAP transport) with a smaller value to avoid bad effect on
+     * other profiles using the RFCOMM;
+     *
+     * @return the maximum allowed OBEX packet that can be send over the transport. Or -1 in case of
+     *     don't care.
      */
     int getMaxTransmitPacketSize();
 
     /**
-     * Must return the maximum allowed OBEX packet that can be received over
-     * the transport. For L2CAP this will be the Max SDU configured for the
-     * L2CAP channel.
-     * The returned value will be used to validate the incoming packet size
-     * values.
-     * For RFCOMM or other transport types where the OBEX packets size
-     * is unrelated to the transport packet size, return -1;
-     * @return the maximum allowed OBEX packet that can be send over
-     *         the transport. Or -1 in case of don't care.
+     * Must return the maximum allowed OBEX packet that can be received over the transport. For
+     * L2CAP this will be the Max SDU configured for the L2CAP channel. The returned value will be
+     * used to validate the incoming packet size values. For RFCOMM or other transport types where
+     * the OBEX packets size is unrelated to the transport packet size, return -1;
+     *
+     * @return the maximum allowed OBEX packet that can be send over the transport. Or -1 in case of
+     *     don't care.
      */
     int getMaxReceivePacketSize();
 
     /**
      * Shall return true if the transport in use supports SRM.
-     * @return
-     *        <code>true</code> if SRM operation is supported, and is to be enabled.
-     *        <code>false</code> if SRM operations are not supported, or should not be used.
+     *
+     * @return <code>true</code> if SRM operation is supported, and is to be enabled. <code>false
+     *     </code> if SRM operations are not supported, or should not be used.
      */
     boolean isSrmSupported();
-
-
 }
diff --git a/src/com/android/obex/Operation.java b/src/com/android/obex/Operation.java
index 03ca603..954c901 100644
--- a/src/com/android/obex/Operation.java
+++ b/src/com/android/obex/Operation.java
@@ -39,21 +39,22 @@ import java.io.InputStream;
 import java.io.OutputStream;
 
 /**
- * The <code>Operation</code> interface provides ways to manipulate a single
- * OBEX PUT or GET operation. The implementation of this interface sends OBEX
- * packets as they are built. If during the operation the peer in the operation
- * ends the operation, an <code>IOException</code> is thrown on the next read
- * from the input stream, write to the output stream, or call to
- * <code>sendHeaders()</code>.
- * <P>
- * <STRONG>How Headers are Handled</STRONG>
- * <P>
- * As headers are received, they may be retrieved through the
- * <code>getReceivedHeaders()</code> method. If new headers are set during the
- * operation, the new headers will be sent during the next packet exchange.
- * <P>
- * <STRONG>PUT example</STRONG>
- * <P>
+ * The <code>Operation</code> interface provides ways to manipulate a single OBEX PUT or GET
+ * operation. The implementation of this interface sends OBEX packets as they are built. If during
+ * the operation the peer in the operation ends the operation, an <code>IOException</code> is thrown
+ * on the next read from the input stream, write to the output stream, or call to <code>
+ * sendHeaders()</code>.
+ *
+ * <p><STRONG>How Headers are Handled</STRONG>
+ *
+ * <p>As headers are received, they may be retrieved through the <code>getReceivedHeaders()</code>
+ * method. If new headers are set during the operation, the new headers will be sent during the next
+ * packet exchange.
+ *
+ * <p><STRONG>PUT example</STRONG>
+ *
+ * <p>
+ *
  * <PRE>
  * void putObjectViaOBEX(ClientSession conn, HeaderSet head, byte[] obj) throws IOException {
  *     // Include the length header
@@ -69,9 +70,11 @@ import java.io.OutputStream;
  *     op.close();
  * }
  * </PRE>
- * <P>
- * <STRONG>GET example</STRONG>
- * <P>
+ *
+ * <p><STRONG>GET example</STRONG>
+ *
+ * <p>
+ *
  * <PRE>
  * byte[] getObjectViaOBEX(ClientSession conn, HeaderSet head) throws IOException {
  *     // Send the initial GET request to the server
@@ -90,62 +93,65 @@ import java.io.OutputStream;
  * }
  * </PRE>
  *
- * <H3>Client PUT Operation Flow</H3> For PUT operations, a call to
- * <code>close()</code> the <code>OutputStream</code> returned from
- * <code>openOutputStream()</code> or <code>openDataOutputStream()</code> will
- * signal that the request is done. (In OBEX terms, the End-Of-Body header
- * should be sent and the final bit in the request will be set.) At this point,
- * the reply from the server may begin to be processed. A call to
- * <code>getResponseCode()</code> will do an implicit close on the
- * <code>OutputStream</code> and therefore signal that the request is done.
- * <H3>Client GET Operation Flow</H3> For GET operation, a call to
- * <code>openInputStream()</code> or <code>openDataInputStream()</code> will
- * signal that the request is done. (In OBEX terms, the final bit in the request
- * will be set.) A call to <code>getResponseCode()</code> will cause an implicit
- * close on the <code>InputStream</code>. No further data may be read at this
- * point.
+ * <H3>Client PUT Operation Flow</H3>
+ *
+ * For PUT operations, a call to <code>close()</code> the <code>OutputStream</code> returned from
+ * <code>openOutputStream()</code> or <code>openDataOutputStream()</code> will signal that the
+ * request is done. (In OBEX terms, the End-Of-Body header should be sent and the final bit in the
+ * request will be set.) At this point, the reply from the server may begin to be processed. A call
+ * to <code>getResponseCode()</code> will do an implicit close on the <code>OutputStream</code> and
+ * therefore signal that the request is done.
+ *
+ * <H3>Client GET Operation Flow</H3>
+ *
+ * For GET operation, a call to <code>openInputStream()</code> or <code>openDataInputStream()</code>
+ * will signal that the request is done. (In OBEX terms, the final bit in the request will be set.)
+ * A call to <code>getResponseCode()</code> will cause an implicit close on the <code>InputStream
+ * </code>. No further data may be read at this point.
  */
 public interface Operation {
 
     /**
-     * Sends an ABORT message to the server. By calling this method, the
-     * corresponding input and output streams will be closed along with this
-     * object. No headers are sent in the abort request. This will end the
-     * operation since <code>close()</code> will be called by this method.
-     * @throws IOException if the transaction has already ended or if an OBEX
-     *         server calls this method
+     * Sends an ABORT message to the server. By calling this method, the corresponding input and
+     * output streams will be closed along with this object. No headers are sent in the abort
+     * request. This will end the operation since <code>close()</code> will be called by this
+     * method.
+     *
+     * @throws IOException if the transaction has already ended or if an OBEX server calls this
+     *     method
      */
     void abort() throws IOException;
 
     /**
-     * Returns the headers that have been received during the operation.
-     * Modifying the object returned has no effect on the headers that are sent
-     * or retrieved.
+     * Returns the headers that have been received during the operation. Modifying the object
+     * returned has no effect on the headers that are sent or retrieved.
+     *
      * @return the headers received during this <code>Operation</code>
      * @throws IOException if this <code>Operation</code> has been closed
      */
     HeaderSet getReceivedHeader() throws IOException;
 
     /**
-     * Specifies the headers that should be sent in the next OBEX message that
-     * is sent.
+     * Specifies the headers that should be sent in the next OBEX message that is sent.
+     *
      * @param headers the headers to send in the next message
-     * @throws IOException if this <code>Operation</code> has been closed or the
-     *         transaction has ended and no further messages will be exchanged
-     * @throws IllegalArgumentException if <code>headers</code> was not created
-     *         by a call to <code>ServerRequestHandler.createHeaderSet()</code>
-     *         or <code>ClientSession.createHeaderSet()</code>
+     * @throws IOException if this <code>Operation</code> has been closed or the transaction has
+     *     ended and no further messages will be exchanged
+     * @throws IllegalArgumentException if <code>headers</code> was not created by a call to <code>
+     *     ServerRequestHandler.createHeaderSet()</code> or <code>ClientSession.createHeaderSet()
+     *     </code>
      * @throws NullPointerException if <code>headers</code> if <code>null</code>
      */
     void sendHeaders(HeaderSet headers) throws IOException;
 
     /**
-     * Returns the response code received from the server. Response codes are
-     * defined in the <code>ResponseCodes</code> class.
+     * Returns the response code received from the server. Response codes are defined in the <code>
+     * ResponseCodes</code> class.
+     *
      * @see ResponseCodes
      * @return the response code retrieved from the server
-     * @throws IOException if an error occurred in the transport layer during
-     *         the transaction; if this object was created by an OBEX server
+     * @throws IOException if an error occurred in the transport layer during the transaction; if
+     *     this object was created by an OBEX server
      */
     int getResponseCode() throws IOException;
 
diff --git a/src/com/android/obex/PasswordAuthentication.java b/src/com/android/obex/PasswordAuthentication.java
index 4c464d0..484d398 100644
--- a/src/com/android/obex/PasswordAuthentication.java
+++ b/src/com/android/obex/PasswordAuthentication.java
@@ -32,9 +32,7 @@
 
 package com.android.obex;
 
-/**
- * This class holds user name and password combinations.
- */
+/** This class holds user name and password combinations. */
 public final class PasswordAuthentication {
 
     private byte[] mUserName;
@@ -42,12 +40,11 @@ public final class PasswordAuthentication {
     private final byte[] mPassword;
 
     /**
-     * Creates a new <code>PasswordAuthentication</code> with the user name and
-     * password provided.
+     * Creates a new <code>PasswordAuthentication</code> with the user name and password provided.
+     *
      * @param userName the user name to include; this may be <code>null</code>
      * @param password the password to include in the response
-     * @throws NullPointerException if <code>password</code> is
-     *         <code>null</code>
+     * @throws NullPointerException if <code>password</code> is <code>null</code>
      */
     public PasswordAuthentication(final byte[] userName, final byte[] password) {
         if (userName != null) {
@@ -60,10 +57,10 @@ public final class PasswordAuthentication {
     }
 
     /**
-     * Retrieves the user name that was specified in the constructor. The user
-     * name may be <code>null</code>.
-     * @return the user name
+     * Retrieves the user name that was specified in the constructor. The user name may be <code>
+     * null</code>.
      *
+     * @return the user name
      * @hide
      */
     public byte[] getUserName() {
@@ -72,8 +69,8 @@ public final class PasswordAuthentication {
 
     /**
      * Retrieves the password.
-     * @return the password
      *
+     * @return the password
      * @hide
      */
     public byte[] getPassword() {
diff --git a/src/com/android/obex/PrivateInputStream.java b/src/com/android/obex/PrivateInputStream.java
index b5ea71c..507086e 100644
--- a/src/com/android/obex/PrivateInputStream.java
+++ b/src/com/android/obex/PrivateInputStream.java
@@ -35,10 +35,7 @@ package com.android.obex;
 import java.io.IOException;
 import java.io.InputStream;
 
-/**
- * This object provides an input stream to the Operation objects used in this
- * package.
- */
+/** This object provides an input stream to the Operation objects used in this package. */
 public final class PrivateInputStream extends InputStream {
 
     private BaseStream mParent;
@@ -51,6 +48,7 @@ public final class PrivateInputStream extends InputStream {
 
     /**
      * Creates an input stream for the <code>Operation</code> to read from
+     *
      * @param p the connection this input stream is for
      */
     public PrivateInputStream(BaseStream p) {
@@ -61,12 +59,11 @@ public final class PrivateInputStream extends InputStream {
     }
 
     /**
-     * Returns the number of bytes that can be read (or skipped over) from this
-     * input stream without blocking by the next caller of a method for this
-     * input stream. The next caller might be the same thread or or another
-     * thread.
-     * @return the number of bytes that can be read from this input stream
-     *         without blocking
+     * Returns the number of bytes that can be read (or skipped over) from this input stream without
+     * blocking by the next caller of a method for this input stream. The next caller might be the
+     * same thread or or another thread.
+     *
+     * @return the number of bytes that can be read from this input stream without blocking
      * @throws IOException if an I/O error occurs
      */
     @Override
@@ -76,13 +73,12 @@ public final class PrivateInputStream extends InputStream {
     }
 
     /**
-     * Reads the next byte of data from the input stream. The value byte is
-     * returned as an int in the range 0 to 255. If no byte is available because
-     * the end of the stream has been reached, the value -1 is returned. This
-     * method blocks until input data is available, the end of the stream is
-     * detected, or an exception is thrown.
-     * @return the byte read from the input stream or -1 if it reaches the end of
-     *         stream
+     * Reads the next byte of data from the input stream. The value byte is returned as an int in
+     * the range 0 to 255. If no byte is available because the end of the stream has been reached,
+     * the value -1 is returned. This method blocks until input data is available, the end of the
+     * stream is detected, or an exception is thrown.
+     *
+     * @return the byte read from the input stream or -1 if it reaches the end of stream
      * @throws IOException if an I/O error occurs
      */
     @Override
@@ -138,8 +134,8 @@ public final class PrivateInputStream extends InputStream {
     }
 
     /**
-     * Allows the <code>OperationImpl</code> thread to add body data to the
-     * input stream.
+     * Allows the <code>OperationImpl</code> thread to add body data to the input stream.
+     *
      * @param body the data to add to the stream
      * @param start the start of the body to array to copy
      */
@@ -158,6 +154,7 @@ public final class PrivateInputStream extends InputStream {
 
     /**
      * Verifies that this stream is open
+     *
      * @throws IOException if the stream is not open
      */
     private void ensureOpen() throws IOException {
@@ -168,8 +165,8 @@ public final class PrivateInputStream extends InputStream {
     }
 
     /**
-     * Closes the input stream. If the input stream is already closed, do
-     * nothing.
+     * Closes the input stream. If the input stream is already closed, do nothing.
+     *
      * @throws IOException this will never happen
      */
     @Override
diff --git a/src/com/android/obex/PrivateOutputStream.java b/src/com/android/obex/PrivateOutputStream.java
index 5bda078..d19b5d9 100644
--- a/src/com/android/obex/PrivateOutputStream.java
+++ b/src/com/android/obex/PrivateOutputStream.java
@@ -36,10 +36,7 @@ import java.io.ByteArrayOutputStream;
 import java.io.IOException;
 import java.io.OutputStream;
 
-/**
- * This object provides an output stream to the Operation objects used in this
- * package.
- */
+/** This object provides an output stream to the Operation objects used in this package. */
 public final class PrivateOutputStream extends OutputStream {
 
     private BaseStream mParent;
@@ -52,6 +49,7 @@ public final class PrivateOutputStream extends OutputStream {
 
     /**
      * Creates an empty <code>PrivateOutputStream</code> to write to.
+     *
      * @param p the connection that this stream runs over
      */
     public PrivateOutputStream(BaseStream p, int maxSize) {
@@ -63,6 +61,7 @@ public final class PrivateOutputStream extends OutputStream {
 
     /**
      * Determines how many bytes have been written to the output stream.
+     *
      * @return the number of bytes written to the output stream
      */
     public int size() {
@@ -70,10 +69,10 @@ public final class PrivateOutputStream extends OutputStream {
     }
 
     /**
-     * Writes the specified byte to this output stream. The general contract for
-     * write is that one byte is written to the output stream. The byte to be
-     * written is the eight low-order bits of the argument b. The 24 high-order
-     * bits of b are ignored.
+     * Writes the specified byte to this output stream. The general contract for write is that one
+     * byte is written to the output stream. The byte to be written is the eight low-order bits of
+     * the argument b. The 24 high-order bits of b are ignored.
+     *
      * @param b the byte to write
      * @throws IOException if an I/O error occurs
      */
@@ -120,6 +119,7 @@ public final class PrivateOutputStream extends OutputStream {
 
     /**
      * Reads the bytes that have been written to this stream.
+     *
      * @param size the size of the array to return
      * @return the byte array that is written
      */
@@ -140,6 +140,7 @@ public final class PrivateOutputStream extends OutputStream {
 
     /**
      * Verifies that this stream is open
+     *
      * @throws IOException if the stream is not open
      */
     private void ensureOpen() throws IOException {
@@ -150,8 +151,8 @@ public final class PrivateOutputStream extends OutputStream {
     }
 
     /**
-     * Closes the output stream. If the input stream is already closed, do
-     * nothing.
+     * Closes the output stream. If the input stream is already closed, do nothing.
+     *
      * @throws IOException this will never happen
      */
     @Override
@@ -162,8 +163,9 @@ public final class PrivateOutputStream extends OutputStream {
 
     /**
      * Determines if the connection is closed
-     * @return <code>true</code> if the connection is closed; <code>false</code>
-     *         if the connection is open
+     *
+     * @return <code>true</code> if the connection is closed; <code>false</code> if the connection
+     *     is open
      */
     public boolean isClosed() {
         return !mOpen;
diff --git a/src/com/android/obex/ResponseCodes.java b/src/com/android/obex/ResponseCodes.java
index 796bf29..5bb2dfb 100644
--- a/src/com/android/obex/ResponseCodes.java
+++ b/src/com/android/obex/ResponseCodes.java
@@ -33,42 +33,40 @@
 package com.android.obex;
 
 /**
- * The <code>ResponseCodes</code> class contains the list of valid response
- * codes a server may send to a client.
- * <P>
- * <STRONG>IMPORTANT NOTE</STRONG>
- * <P>
- * The values in this interface represent the values defined in the IrOBEX
- * specification, which is different with the HTTP specification.
- * <P>
- * <code>OBEX_DATABASE_FULL</code> and <code>OBEX_DATABASE_LOCKED</code> require
- * further description since they are not defined in HTTP. The server will send
- * an <code>OBEX_DATABASE_FULL</code> message when the client requests that
- * something be placed into a database but the database is full (cannot take
- * more data). <code>OBEX_DATABASE_LOCKED</code> will be returned when the
- * client wishes to access a database, database table, or database record that
- * has been locked.
+ * The <code>ResponseCodes</code> class contains the list of valid response codes a server may send
+ * to a client.
+ *
+ * <p><STRONG>IMPORTANT NOTE</STRONG>
+ *
+ * <p>The values in this interface represent the values defined in the IrOBEX specification, which
+ * is different with the HTTP specification.
+ *
+ * <p><code>OBEX_DATABASE_FULL</code> and <code>OBEX_DATABASE_LOCKED</code> require further
+ * description since they are not defined in HTTP. The server will send an <code>OBEX_DATABASE_FULL
+ * </code> message when the client requests that something be placed into a database but the
+ * database is full (cannot take more data). <code>OBEX_DATABASE_LOCKED</code> will be returned when
+ * the client wishes to access a database, database table, or database record that has been locked.
  */
 public final class ResponseCodes {
 
     /**
      * Defines the OBEX CONTINUE response code.
-     * <P>
-     * The value of <code>OBEX_HTTP_CONTINUE</code> is 0x90 (144).
+     *
+     * <p>The value of <code>OBEX_HTTP_CONTINUE</code> is 0x90 (144).
      */
     public static final int OBEX_HTTP_CONTINUE = 0x90;
 
     /**
      * Defines the OBEX SUCCESS response code.
-     * <P>
-     * The value of <code>OBEX_HTTP_OK</code> is 0xA0 (160).
+     *
+     * <p>The value of <code>OBEX_HTTP_OK</code> is 0xA0 (160).
      */
     public static final int OBEX_HTTP_OK = 0xA0;
 
     /**
      * Defines the OBEX CREATED response code.
-     * <P>
-     * The value of <code>OBEX_HTTP_CREATED</code> is 0xA1 (161).
+     *
+     * <p>The value of <code>OBEX_HTTP_CREATED</code> is 0xA1 (161).
      *
      * @hide
      */
@@ -76,8 +74,8 @@ public final class ResponseCodes {
 
     /**
      * Defines the OBEX ACCEPTED response code.
-     * <P>
-     * The value of <code>OBEX_HTTP_ACCEPTED</code> is 0xA2 (162).
+     *
+     * <p>The value of <code>OBEX_HTTP_ACCEPTED</code> is 0xA2 (162).
      *
      * @hide
      */
@@ -85,8 +83,8 @@ public final class ResponseCodes {
 
     /**
      * Defines the OBEX NON-AUTHORITATIVE INFORMATION response code.
-     * <P>
-     * The value of <code>OBEX_HTTP_NOT_AUTHORITATIVE</code> is 0xA3 (163).
+     *
+     * <p>The value of <code>OBEX_HTTP_NOT_AUTHORITATIVE</code> is 0xA3 (163).
      *
      * @hide
      */
@@ -94,8 +92,8 @@ public final class ResponseCodes {
 
     /**
      * Defines the OBEX NO CONTENT response code.
-     * <P>
-     * The value of <code>OBEX_HTTP_NO_CONTENT</code> is 0xA4 (164).
+     *
+     * <p>The value of <code>OBEX_HTTP_NO_CONTENT</code> is 0xA4 (164).
      *
      * @hide
      */
@@ -103,8 +101,8 @@ public final class ResponseCodes {
 
     /**
      * Defines the OBEX RESET CONTENT response code.
-     * <P>
-     * The value of <code>OBEX_HTTP_RESET</code> is 0xA5 (165).
+     *
+     * <p>The value of <code>OBEX_HTTP_RESET</code> is 0xA5 (165).
      *
      * @hide
      */
@@ -112,8 +110,8 @@ public final class ResponseCodes {
 
     /**
      * Defines the OBEX PARTIAL CONTENT response code.
-     * <P>
-     * The value of <code>OBEX_HTTP_PARTIAL</code> is 0xA6 (166).
+     *
+     * <p>The value of <code>OBEX_HTTP_PARTIAL</code> is 0xA6 (166).
      *
      * @hide
      */
@@ -121,8 +119,8 @@ public final class ResponseCodes {
 
     /**
      * Defines the OBEX MULTIPLE_CHOICES response code.
-     * <P>
-     * The value of <code>OBEX_HTTP_MULT_CHOICE</code> is 0xB0 (176).
+     *
+     * <p>The value of <code>OBEX_HTTP_MULT_CHOICE</code> is 0xB0 (176).
      *
      * @hide
      */
@@ -130,8 +128,8 @@ public final class ResponseCodes {
 
     /**
      * Defines the OBEX MOVED PERMANENTLY response code.
-     * <P>
-     * The value of <code>OBEX_HTTP_MOVED_PERM</code> is 0xB1 (177).
+     *
+     * <p>The value of <code>OBEX_HTTP_MOVED_PERM</code> is 0xB1 (177).
      *
      * @hide
      */
@@ -139,8 +137,8 @@ public final class ResponseCodes {
 
     /**
      * Defines the OBEX MOVED TEMPORARILY response code.
-     * <P>
-     * The value of <code>OBEX_HTTP_MOVED_TEMP</code> is 0xB2 (178).
+     *
+     * <p>The value of <code>OBEX_HTTP_MOVED_TEMP</code> is 0xB2 (178).
      *
      * @hide
      */
@@ -148,8 +146,8 @@ public final class ResponseCodes {
 
     /**
      * Defines the OBEX SEE OTHER response code.
-     * <P>
-     * The value of <code>OBEX_HTTP_SEE_OTHER</code> is 0xB3 (179).
+     *
+     * <p>The value of <code>OBEX_HTTP_SEE_OTHER</code> is 0xB3 (179).
      *
      * @hide
      */
@@ -157,8 +155,8 @@ public final class ResponseCodes {
 
     /**
      * Defines the OBEX NOT MODIFIED response code.
-     * <P>
-     * The value of <code>OBEX_HTTP_NOT_MODIFIED</code> is 0xB4 (180).
+     *
+     * <p>The value of <code>OBEX_HTTP_NOT_MODIFIED</code> is 0xB4 (180).
      *
      * @hide
      */
@@ -166,8 +164,8 @@ public final class ResponseCodes {
 
     /**
      * Defines the OBEX USE PROXY response code.
-     * <P>
-     * The value of <code>OBEX_HTTP_USE_PROXY</code> is 0xB5 (181).
+     *
+     * <p>The value of <code>OBEX_HTTP_USE_PROXY</code> is 0xB5 (181).
      *
      * @hide
      */
@@ -175,15 +173,15 @@ public final class ResponseCodes {
 
     /**
      * Defines the OBEX BAD REQUEST response code.
-     * <P>
-     * The value of <code>OBEX_HTTP_BAD_REQUEST</code> is 0xC0 (192).
+     *
+     * <p>The value of <code>OBEX_HTTP_BAD_REQUEST</code> is 0xC0 (192).
      */
     public static final int OBEX_HTTP_BAD_REQUEST = 0xC0;
 
     /**
      * Defines the OBEX UNAUTHORIZED response code.
-     * <P>
-     * The value of <code>OBEX_HTTP_UNAUTHORIZED</code> is 0xC1 (193).
+     *
+     * <p>The value of <code>OBEX_HTTP_UNAUTHORIZED</code> is 0xC1 (193).
      *
      * @hide
      */
@@ -191,8 +189,8 @@ public final class ResponseCodes {
 
     /**
      * Defines the OBEX PAYMENT REQUIRED response code.
-     * <P>
-     * The value of <code>OBEX_HTTP_PAYMENT_REQUIRED</code> is 0xC2 (194).
+     *
+     * <p>The value of <code>OBEX_HTTP_PAYMENT_REQUIRED</code> is 0xC2 (194).
      *
      * @hide
      */
@@ -200,22 +198,22 @@ public final class ResponseCodes {
 
     /**
      * Defines the OBEX FORBIDDEN response code.
-     * <P>
-     * The value of <code>OBEX_HTTP_FORBIDDEN</code> is 0xC3 (195).
+     *
+     * <p>The value of <code>OBEX_HTTP_FORBIDDEN</code> is 0xC3 (195).
      */
     public static final int OBEX_HTTP_FORBIDDEN = 0xC3;
 
     /**
      * Defines the OBEX NOT FOUND response code.
-     * <P>
-     * The value of <code>OBEX_HTTP_NOT_FOUND</code> is 0xC4 (196).
+     *
+     * <p>The value of <code>OBEX_HTTP_NOT_FOUND</code> is 0xC4 (196).
      */
     public static final int OBEX_HTTP_NOT_FOUND = 0xC4;
 
     /**
      * Defines the OBEX METHOD NOT ALLOWED response code.
-     * <P>
-     * The value of <code>OBEX_HTTP_BAD_METHOD</code> is 0xC5 (197).
+     *
+     * <p>The value of <code>OBEX_HTTP_BAD_METHOD</code> is 0xC5 (197).
      *
      * @hide
      */
@@ -223,15 +221,15 @@ public final class ResponseCodes {
 
     /**
      * Defines the OBEX NOT ACCEPTABLE response code.
-     * <P>
-     * The value of <code>OBEX_HTTP_NOT_ACCEPTABLE</code> is 0xC6 (198).
+     *
+     * <p>The value of <code>OBEX_HTTP_NOT_ACCEPTABLE</code> is 0xC6 (198).
      */
     public static final int OBEX_HTTP_NOT_ACCEPTABLE = 0xC6;
 
     /**
      * Defines the OBEX PROXY AUTHENTICATION REQUIRED response code.
-     * <P>
-     * The value of <code>OBEX_HTTP_PROXY_AUTH</code> is 0xC7 (199).
+     *
+     * <p>The value of <code>OBEX_HTTP_PROXY_AUTH</code> is 0xC7 (199).
      *
      * @hide
      */
@@ -239,8 +237,8 @@ public final class ResponseCodes {
 
     /**
      * Defines the OBEX REQUEST TIME OUT response code.
-     * <P>
-     * The value of <code>OBEX_HTTP_TIMEOUT</code> is 0xC8 (200).
+     *
+     * <p>The value of <code>OBEX_HTTP_TIMEOUT</code> is 0xC8 (200).
      *
      * @hide
      */
@@ -248,8 +246,8 @@ public final class ResponseCodes {
 
     /**
      * Defines the OBEX METHOD CONFLICT response code.
-     * <P>
-     * The value of <code>OBEX_HTTP_CONFLICT</code> is 0xC9 (201).
+     *
+     * <p>The value of <code>OBEX_HTTP_CONFLICT</code> is 0xC9 (201).
      *
      * @hide
      */
@@ -257,8 +255,8 @@ public final class ResponseCodes {
 
     /**
      * Defines the OBEX METHOD GONE response code.
-     * <P>
-     * The value of <code>OBEX_HTTP_GONE</code> is 0xCA (202).
+     *
+     * <p>The value of <code>OBEX_HTTP_GONE</code> is 0xCA (202).
      *
      * @hide
      */
@@ -266,22 +264,22 @@ public final class ResponseCodes {
 
     /**
      * Defines the OBEX METHOD LENGTH REQUIRED response code.
-     * <P>
-     * The value of <code>OBEX_HTTP_LENGTH_REQUIRED</code> is 0xCB (203).
+     *
+     * <p>The value of <code>OBEX_HTTP_LENGTH_REQUIRED</code> is 0xCB (203).
      */
     public static final int OBEX_HTTP_LENGTH_REQUIRED = 0xCB;
 
     /**
      * Defines the OBEX PRECONDITION FAILED response code.
-     * <P>
-     * The value of <code>OBEX_HTTP_PRECON_FAILED</code> is 0xCC (204).
+     *
+     * <p>The value of <code>OBEX_HTTP_PRECON_FAILED</code> is 0xCC (204).
      */
     public static final int OBEX_HTTP_PRECON_FAILED = 0xCC;
 
     /**
      * Defines the OBEX REQUESTED ENTITY TOO LARGE response code.
-     * <P>
-     * The value of <code>OBEX_HTTP_ENTITY_TOO_LARGE</code> is 0xCD (205).
+     *
+     * <p>The value of <code>OBEX_HTTP_ENTITY_TOO_LARGE</code> is 0xCD (205).
      *
      * @hide
      */
@@ -289,8 +287,8 @@ public final class ResponseCodes {
 
     /**
      * Defines the OBEX REQUESTED URL TOO LARGE response code.
-     * <P>
-     * The value of <code>OBEX_HTTP_REQ_TOO_LARGE</code> is 0xCE (206).
+     *
+     * <p>The value of <code>OBEX_HTTP_REQ_TOO_LARGE</code> is 0xCE (206).
      *
      * @hide
      */
@@ -298,29 +296,29 @@ public final class ResponseCodes {
 
     /**
      * Defines the OBEX UNSUPPORTED MEDIA TYPE response code.
-     * <P>
-     * The value of <code>OBEX_HTTP_UNSUPPORTED_TYPE</code> is 0xCF (207).
+     *
+     * <p>The value of <code>OBEX_HTTP_UNSUPPORTED_TYPE</code> is 0xCF (207).
      */
     public static final int OBEX_HTTP_UNSUPPORTED_TYPE = 0xCF;
 
     /**
      * Defines the OBEX INTERNAL SERVER ERROR response code.
-     * <P>
-     * The value of <code>OBEX_HTTP_INTERNAL_ERROR</code> is 0xD0 (208).
+     *
+     * <p>The value of <code>OBEX_HTTP_INTERNAL_ERROR</code> is 0xD0 (208).
      */
     public static final int OBEX_HTTP_INTERNAL_ERROR = 0xD0;
 
     /**
      * Defines the OBEX NOT IMPLEMENTED response code.
-     * <P>
-     * The value of <code>OBEX_HTTP_NOT_IMPLEMENTED</code> is 0xD1 (209).
+     *
+     * <p>The value of <code>OBEX_HTTP_NOT_IMPLEMENTED</code> is 0xD1 (209).
      */
     public static final int OBEX_HTTP_NOT_IMPLEMENTED = 0xD1;
 
     /**
      * Defines the OBEX BAD GATEWAY response code.
-     * <P>
-     * The value of <code>OBEX_HTTP_BAD_GATEWAY</code> is 0xD2 (210).
+     *
+     * <p>The value of <code>OBEX_HTTP_BAD_GATEWAY</code> is 0xD2 (210).
      *
      * @hide
      */
@@ -328,15 +326,15 @@ public final class ResponseCodes {
 
     /**
      * Defines the OBEX SERVICE UNAVAILABLE response code.
-     * <P>
-     * The value of <code>OBEX_HTTP_UNAVAILABLE</code> is 0xD3 (211).
+     *
+     * <p>The value of <code>OBEX_HTTP_UNAVAILABLE</code> is 0xD3 (211).
      */
     public static final int OBEX_HTTP_UNAVAILABLE = 0xD3;
 
     /**
      * Defines the OBEX GATEWAY TIMEOUT response code.
-     * <P>
-     * The value of <code>OBEX_HTTP_GATEWAY_TIMEOUT</code> is 0xD4 (212).
+     *
+     * <p>The value of <code>OBEX_HTTP_GATEWAY_TIMEOUT</code> is 0xD4 (212).
      *
      * @hide
      */
@@ -344,8 +342,8 @@ public final class ResponseCodes {
 
     /**
      * Defines the OBEX HTTP VERSION NOT SUPPORTED response code.
-     * <P>
-     * The value of <code>OBEX_HTTP_VERSION</code> is 0xD5 (213).
+     *
+     * <p>The value of <code>OBEX_HTTP_VERSION</code> is 0xD5 (213).
      *
      * @hide
      */
@@ -353,8 +351,8 @@ public final class ResponseCodes {
 
     /**
      * Defines the OBEX DATABASE FULL response code.
-     * <P>
-     * The value of <code>OBEX_DATABASE_FULL</code> is 0xE0 (224).
+     *
+     * <p>The value of <code>OBEX_DATABASE_FULL</code> is 0xE0 (224).
      *
      * @hide
      */
@@ -362,16 +360,13 @@ public final class ResponseCodes {
 
     /**
      * Defines the OBEX DATABASE LOCKED response code.
-     * <P>
-     * The value of <code>OBEX_DATABASE_LOCKED</code> is 0xE1 (225).
+     *
+     * <p>The value of <code>OBEX_DATABASE_LOCKED</code> is 0xE1 (225).
      *
      * @hide
      */
     public static final int OBEX_DATABASE_LOCKED = 0xE1;
 
-    /**
-     * Constructor does nothing.
-     */
-    private ResponseCodes() {
-    }
+    /** Constructor does nothing. */
+    private ResponseCodes() {}
 }
diff --git a/src/com/android/obex/ServerOperation.java b/src/com/android/obex/ServerOperation.java
index 43b7138..84e5337 100644
--- a/src/com/android/obex/ServerOperation.java
+++ b/src/com/android/obex/ServerOperation.java
@@ -44,15 +44,14 @@ import java.io.OutputStream;
 
 /**
  * This class implements the Operation interface for server side connections.
- * <P>
- * <STRONG>Request Codes</STRONG> There are four different request codes that
- * are in this class. 0x02 is a PUT request that signals that the request is not
- * complete and requires an additional OBEX packet. 0x82 is a PUT request that
- * says that request is complete. In this case, the server can begin sending the
- * response. The 0x03 is a GET request that signals that the request is not
- * finished. When the server receives a 0x83, the client is signaling the server
- * that it is done with its request. TODO: Extend the ClientOperation and reuse
- * the methods defined TODO: in that class.
+ *
+ * <p><STRONG>Request Codes</STRONG> There are four different request codes that are in this class.
+ * 0x02 is a PUT request that signals that the request is not complete and requires an additional
+ * OBEX packet. 0x82 is a PUT request that says that request is complete. In this case, the server
+ * can begin sending the response. The 0x03 is a GET request that signals that the request is not
+ * finished. When the server receives a 0x83, the client is signaling the server that it is done
+ * with its request. TODO: Extend the ClientOperation and reuse the methods defined TODO: in that
+ * class.
  */
 public final class ServerOperation implements Operation, BaseStream {
 
@@ -116,17 +115,18 @@ public final class ServerOperation implements Operation, BaseStream {
 
     /**
      * Creates new ServerOperation
+     *
      * @param p the parent that created this object
      * @param in the input stream to read from
      * @param request the initial request that was received from the client
      * @param maxSize the max packet size that the client will accept
      * @param listen the listener that is responding to the request
      * @throws IOException if an IO error occurs
-     *
      * @hide
      */
-    public ServerOperation(ServerSession p, InputStream in, int request, int maxSize,
-            ServerRequestHandler listen) throws IOException {
+    public ServerOperation(
+            ServerSession p, InputStream in, int request, int maxSize, ServerRequestHandler listen)
+            throws IOException {
 
         mAborted = false;
         mParent = p;
@@ -147,8 +147,8 @@ public final class ServerOperation implements Operation, BaseStream {
         /*
          * Determine if this is a PUT request
          */
-        if ((request == ObexHelper.OBEX_OPCODE_PUT) ||
-                (request == ObexHelper.OBEX_OPCODE_PUT_FINAL)) {
+        if ((request == ObexHelper.OBEX_OPCODE_PUT)
+                || (request == ObexHelper.OBEX_OPCODE_PUT_FINAL)) {
             /*
              * It is a PUT request.
              */
@@ -163,8 +163,8 @@ public final class ServerOperation implements Operation, BaseStream {
                 finalBitSet = true;
                 mRequestFinished = true;
             }
-        } else if ((request == ObexHelper.OBEX_OPCODE_GET) ||
-                (request == ObexHelper.OBEX_OPCODE_GET_FINAL)) {
+        } else if ((request == ObexHelper.OBEX_OPCODE_GET)
+                || (request == ObexHelper.OBEX_OPCODE_GET_FINAL)) {
             /*
              * It is a GET request.
              */
@@ -187,22 +187,30 @@ public final class ServerOperation implements Operation, BaseStream {
          */
         if (packet.mLength > ObexHelper.getMaxRxPacketSize(mTransport)) {
             mParent.sendResponse(ResponseCodes.OBEX_HTTP_REQ_TOO_LARGE, null);
-            throw new IOException("Packet received was too large. Length: "
-                    + packet.mLength + " maxLength: " + ObexHelper.getMaxRxPacketSize(mTransport));
+            throw new IOException(
+                    "Packet received was too large. Length: "
+                            + packet.mLength
+                            + " maxLength: "
+                            + ObexHelper.getMaxRxPacketSize(mTransport));
         }
 
         /*
          * Determine if any headers were sent in the initial request
          */
         if (packet.mLength > 3) {
-            if(!handleObexPacket(packet)) {
+            if (!handleObexPacket(packet)) {
                 return;
             }
             /* Don't Pre-Send continue when Remote requested for SRM
              * Let the Application confirm.
              */
-            if (V) Log.v(TAG, "Get App confirmation if SRM ENABLED case: " + mSrmEnabled
-                    + " not hasBody case: " + mHasBody);
+            if (V)
+                Log.v(
+                        TAG,
+                        "Get App confirmation if SRM ENABLED case: "
+                                + mSrmEnabled
+                                + " not hasBody case: "
+                                + mHasBody);
             if (!mHasBody && !mSrmEnabled) {
                 while ((!mGetOperation) && (!finalBitSet)) {
                     sendReply(ResponseCodes.OBEX_HTTP_CONTINUE);
@@ -213,11 +221,20 @@ public final class ServerOperation implements Operation, BaseStream {
             }
         }
         /* Don't Pre-Send continue when Remote requested for SRM
-          * Let the Application confirm.
-          */
-        if (V) Log.v(TAG, "Get App confirmation if SRM ENABLED case: " + mSrmEnabled
-            + " not finalPacket: " + finalBitSet + " not GETOp Case: " + mGetOperation);
-        while ((!mSrmEnabled) && (!mGetOperation) && (!finalBitSet)
+         * Let the Application confirm.
+         */
+        if (V)
+            Log.v(
+                    TAG,
+                    "Get App confirmation if SRM ENABLED case: "
+                            + mSrmEnabled
+                            + " not finalPacket: "
+                            + finalBitSet
+                            + " not GETOp Case: "
+                            + mGetOperation);
+        while ((!mSrmEnabled)
+                && (!mGetOperation)
+                && (!finalBitSet)
                 && (mPrivateInput.available() == 0)) {
             sendReply(ResponseCodes.OBEX_HTTP_CONTINUE);
             if (mPrivateInput.available() > 0) {
@@ -233,10 +250,10 @@ public final class ServerOperation implements Operation, BaseStream {
 
     /**
      * Parse headers and update member variables
+     *
      * @param packet the received obex packet
-     * @return false for failing authentication - and a OBEX_HTTP_UNAUTHORIZED
-     * response have been send. Else true.
-     * @throws IOException
+     * @return false for failing authentication - and a OBEX_HTTP_UNAUTHORIZED response have been
+     *     send. Else true.
      */
     private boolean handleObexPacket(ObexPacket packet) throws IOException {
         byte[] body = updateRequestHeaders(packet);
@@ -245,8 +262,7 @@ public final class ServerOperation implements Operation, BaseStream {
             mHasBody = true;
         }
         if (mListener.getConnectionId() != -1 && requestHeader.mConnectionID != null) {
-            mListener.setConnectionId(ObexHelper
-                    .convertToLong(requestHeader.mConnectionID));
+            mListener.setConnectionId(ObexHelper.convertToLong(requestHeader.mConnectionID));
         } else {
             mListener.setConnectionId(1);
         }
@@ -266,7 +282,11 @@ public final class ServerOperation implements Operation, BaseStream {
             mParent.handleAuthChall(requestHeader);
             // send the auhtResp to the client
             replyHeader.mAuthResp = new byte[requestHeader.mAuthResp.length];
-            System.arraycopy(requestHeader.mAuthResp, 0, replyHeader.mAuthResp, 0,
+            System.arraycopy(
+                    requestHeader.mAuthResp,
+                    0,
+                    replyHeader.mAuthResp,
+                    0,
                     replyHeader.mAuthResp.length);
             requestHeader.mAuthResp = null;
             requestHeader.mAuthChall = null;
@@ -280,48 +300,47 @@ public final class ServerOperation implements Operation, BaseStream {
 
     /**
      * Update the request header set, and sniff on SRM headers to update local state.
-     * @param data the OBEX packet data
+     *
+     * @param packet the OBEX packet data
      * @return any bytes in a body/end-of-body header returned by {@link ObexHelper.updateHeaderSet}
-     * @throws IOException
      */
     private byte[] updateRequestHeaders(ObexPacket packet) throws IOException {
         byte[] body = null;
         if (packet.mPayload != null) {
             body = ObexHelper.updateHeaderSet(requestHeader, packet.mPayload);
         }
-        Byte srmMode = (Byte)requestHeader.getHeader(HeaderSet.SINGLE_RESPONSE_MODE);
-        if(mTransport.isSrmSupported() && srmMode != null
+        Byte srmMode = (Byte) requestHeader.getHeader(HeaderSet.SINGLE_RESPONSE_MODE);
+        if (mTransport.isSrmSupported()
+                && srmMode != null
                 && srmMode == ObexHelper.OBEX_SRM_ENABLE) {
             mSrmEnabled = true;
-            if(V) Log.d(TAG,"SRM is now ENABLED (but not active) for this operation");
+            if (V) Log.d(TAG, "SRM is now ENABLED (but not active) for this operation");
         }
         checkForSrmWait(packet.mHeaderId);
-        if((!mSrmWaitingForRemote) && (mSrmEnabled)) {
-            if(V) Log.d(TAG,"SRM is now ACTIVE for this operation");
+        if ((!mSrmWaitingForRemote) && (mSrmEnabled)) {
+            if (V) Log.d(TAG, "SRM is now ACTIVE for this operation");
             mSrmActive = true;
         }
         return body;
     }
 
     /**
-     * Call this only when a complete request have been received.
-     * (This is not optimal, but the current design is not really suited to
-     * the way SRM is specified.)
+     * Call this only when a complete request have been received. (This is not optimal, but the
+     * current design is not really suited to the way SRM is specified.)
      */
-    private void checkForSrmWait(int headerId){
-        if (mSrmEnabled && (headerId == ObexHelper.OBEX_OPCODE_GET
-                || headerId == ObexHelper.OBEX_OPCODE_GET_FINAL
-                || headerId == ObexHelper.OBEX_OPCODE_PUT)) {
-            try {
-                mSrmWaitingForRemote = false;
-                Byte srmp = (Byte)requestHeader.getHeader(HeaderSet.SINGLE_RESPONSE_MODE_PARAMETER);
-                if(srmp != null && srmp == ObexHelper.OBEX_SRMP_WAIT) {
-                    mSrmWaitingForRemote = true;
-                    // Clear the wait header, as the absents of the header when the final bit is set
-                    // indicates don't wait.
-                    requestHeader.setHeader(HeaderSet.SINGLE_RESPONSE_MODE_PARAMETER, null);
-                }
-            } catch (IOException e) {if(V){Log.w(TAG,"Exception while extracting header",e);}}
+    private void checkForSrmWait(int headerId) {
+        if (mSrmEnabled
+                && (headerId == ObexHelper.OBEX_OPCODE_GET
+                        || headerId == ObexHelper.OBEX_OPCODE_GET_FINAL
+                        || headerId == ObexHelper.OBEX_OPCODE_PUT)) {
+            mSrmWaitingForRemote = false;
+            Byte srmp = (Byte) requestHeader.getHeader(HeaderSet.SINGLE_RESPONSE_MODE_PARAMETER);
+            if (srmp != null && srmp == ObexHelper.OBEX_SRMP_WAIT) {
+                mSrmWaitingForRemote = true;
+                // Clear the wait header, as the absents of the header when the final bit is set
+                // indicates don't wait.
+                requestHeader.setHeader(HeaderSet.SINGLE_RESPONSE_MODE_PARAMETER, null);
+            }
         }
     }
 
@@ -331,17 +350,15 @@ public final class ServerOperation implements Operation, BaseStream {
     }
 
     /**
-     * Determines if the operation should continue or should wait. If it should
-     * continue, this method will continue the operation.
-     * @param sendEmpty if <code>true</code> then this will continue the
-     *        operation even if no headers will be sent; if <code>false</code>
-     *        then this method will only continue the operation if there are
-     *        headers to send
-     * @param inStream if<code>true</code> the stream is input stream, otherwise
-     *        output stream
-     * @return <code>true</code> if the operation was completed;
-     *         <code>false</code> if no operation took place
+     * Determines if the operation should continue or should wait. If it should continue, this
+     * method will continue the operation.
      *
+     * @param sendEmpty if <code>true</code> then this will continue the operation even if no
+     *     headers will be sent; if <code>false</code> then this method will only continue the
+     *     operation if there are headers to send
+     * @param inStream if<code>true</code> the stream is input stream, otherwise output stream
+     * @return <code>true</code> if the operation was completed; <code>false</code> if no operation
+     *     took place
      * @hide
      */
     public synchronized boolean continueOperation(boolean sendEmpty, boolean inStream)
@@ -369,15 +386,14 @@ public final class ServerOperation implements Operation, BaseStream {
     }
 
     /**
-     * Sends a reply to the client. If the reply is a OBEX_HTTP_CONTINUE, it
-     * will wait for a response from the client before ending unless SRM is active.
+     * Sends a reply to the client. If the reply is a OBEX_HTTP_CONTINUE, it will wait for a
+     * response from the client before ending unless SRM is active.
+     *
      * @param type the response code to send back to the client
-     * @return <code>true</code> if the final bit was not set on the reply;
-     *         <code>false</code> if no reply was received because the operation
-     *         ended, an abort was received, the final bit was set in the
-     *         reply or SRM is active.
+     * @return <code>true</code> if the final bit was not set on the reply; <code>false</code> if no
+     *     reply was received because the operation ended, an abort was received, the final bit was
+     *     set in the reply or SRM is active.
      * @throws IOException if an IO error occurs
-     *
      * @hide
      */
     public synchronized boolean sendReply(int type) throws IOException {
@@ -393,16 +409,17 @@ public final class ServerOperation implements Operation, BaseStream {
             replyHeader.mConnectionID = ObexHelper.convertToByteArray(id);
         }
 
-        if(mSrmEnabled && !mSrmResponseSent) {
+        if (mSrmEnabled && !mSrmResponseSent) {
             // As we are not ensured that the SRM enable is in the first OBEX packet
             // We must check for each reply.
-            if(V)Log.v(TAG, "mSrmEnabled==true, sending SRM enable response.");
-            replyHeader.setHeader(HeaderSet.SINGLE_RESPONSE_MODE, (byte)ObexHelper.OBEX_SRM_ENABLE);
+            if (V) Log.v(TAG, "mSrmEnabled==true, sending SRM enable response.");
+            replyHeader.setHeader(
+                    HeaderSet.SINGLE_RESPONSE_MODE, (byte) ObexHelper.OBEX_SRM_ENABLE);
             srmRespSendPending = true;
         }
 
-        if(mSrmEnabled && !mGetOperation && mSrmLocalWait) {
-            replyHeader.setHeader(HeaderSet.SINGLE_RESPONSE_MODE, (byte)ObexHelper.OBEX_SRMP_WAIT);
+        if (mSrmEnabled && !mGetOperation && mSrmLocalWait) {
+            replyHeader.setHeader(HeaderSet.SINGLE_RESPONSE_MODE, (byte) ObexHelper.OBEX_SRMP_WAIT);
         }
 
         byte[] headerArray = ObexHelper.createHeader(replyHeader, true); // This clears the headers
@@ -420,8 +437,11 @@ public final class ServerOperation implements Operation, BaseStream {
             int start = 0;
 
             while (end != headerArray.length) {
-                end = ObexHelper.findHeaderEnd(headerArray, start, mMaxPacketLength
-                        - ObexHelper.BASE_PACKET_LENGTH);
+                end =
+                        ObexHelper.findHeaderEnd(
+                                headerArray,
+                                start,
+                                mMaxPacketLength - ObexHelper.BASE_PACKET_LENGTH);
                 if (end == -1) {
 
                     mClosed = true;
@@ -459,25 +479,33 @@ public final class ServerOperation implements Operation, BaseStream {
             finalBitSet = true;
         }
 
-        if(mSrmActive) {
-            if(!mGetOperation && type == ResponseCodes.OBEX_HTTP_CONTINUE &&
-                    mSrmResponseSent == true) {
+        if (mSrmActive) {
+            if (!mGetOperation
+                    && type == ResponseCodes.OBEX_HTTP_CONTINUE
+                    && mSrmResponseSent == true) {
                 // we are in the middle of a SRM PUT operation, don't send a continue.
                 skipSend = true;
-            } else if(mGetOperation && mRequestFinished == false && mSrmResponseSent == true) {
+            } else if (mGetOperation && mRequestFinished == false && mSrmResponseSent == true) {
                 // We are still receiving the get request, receive, but don't send continue.
                 skipSend = true;
-            } else if(mGetOperation && mRequestFinished == true) {
+            } else if (mGetOperation && mRequestFinished == true) {
                 // All done receiving the GET request, send data to the client, without
                 // expecting a continue.
                 skipReceive = true;
             }
-            if(V)Log.v(TAG, "type==" + type + " skipSend==" + skipSend
-                    + " skipReceive==" + skipReceive);
-        }
-        if(srmRespSendPending) {
-            if(V)Log.v(TAG,
-                    "SRM Enabled (srmRespSendPending == true)- sending SRM Enable response");
+            if (V)
+                Log.v(
+                        TAG,
+                        "type=="
+                                + type
+                                + " skipSend=="
+                                + skipSend
+                                + " skipReceive=="
+                                + skipReceive);
+        }
+        if (srmRespSendPending) {
+            if (V)
+                Log.v(TAG, "SRM Enabled (srmRespSendPending == true)- sending SRM Enable response");
             mSrmResponseSent = true;
         }
 
@@ -500,43 +528,42 @@ public final class ServerOperation implements Operation, BaseStream {
                  * (End of Body) otherwise, we need to send 0x48 (Body)
                  */
                 if ((finalBitSet) || (mPrivateOutput.isClosed())) {
-                    if(mSendBodyHeader == true) {
+                    if (mSendBodyHeader == true) {
                         out.write(0x49);
                         bodyLength += 3;
-                        out.write((byte)(bodyLength >> 8));
-                        out.write((byte)bodyLength);
+                        out.write((byte) (bodyLength >> 8));
+                        out.write((byte) bodyLength);
                         out.write(body);
                     }
                 } else {
-                    if(mSendBodyHeader == true) {
-                    out.write(0x48);
-                    bodyLength += 3;
-                    out.write((byte)(bodyLength >> 8));
-                    out.write((byte)bodyLength);
-                    out.write(body);
+                    if (mSendBodyHeader == true) {
+                        out.write(0x48);
+                        bodyLength += 3;
+                        out.write((byte) (bodyLength >> 8));
+                        out.write((byte) bodyLength);
+                        out.write(body);
                     }
                 }
-
             }
         }
 
         if ((finalBitSet) && (type == ResponseCodes.OBEX_HTTP_OK) && (originalBodyLength <= 0)) {
-            if(mSendBodyHeader) {
+            if (mSendBodyHeader) {
                 out.write(0x49);
                 originalBodyLength = 3;
-                out.write((byte)(originalBodyLength >> 8));
-                out.write((byte)originalBodyLength);
+                out.write((byte) (originalBodyLength >> 8));
+                out.write((byte) originalBodyLength);
             }
         }
 
-        if(skipSend == false) {
+        if (skipSend == false) {
             mResponseSize = 3;
             mParent.sendResponse(type, out.toByteArray());
         }
 
         if (type == ResponseCodes.OBEX_HTTP_CONTINUE) {
 
-            if(mGetOperation && skipReceive) {
+            if (mGetOperation && skipReceive) {
                 // Here we need to check for and handle abort (throw an exception).
                 // Any other signal received should be discarded silently (only on server side)
                 checkSrmRemoteAbort();
@@ -583,12 +610,11 @@ public final class ServerOperation implements Operation, BaseStream {
                      * Determine if any headers were sent in the initial request
                      */
                     if (packet.mLength > 3 || (mSrmEnabled && packet.mLength == 3)) {
-                        if(handleObexPacket(packet) == false) {
+                        if (handleObexPacket(packet) == false) {
                             return false;
                         }
                     }
                 }
-
             }
             return true;
         } else {
@@ -597,23 +623,21 @@ public final class ServerOperation implements Operation, BaseStream {
     }
 
     /**
-     * This method will look for an abort from the peer during a SRM transfer.
-     * The function will not block if no data has been received from the remote device.
-     * If data have been received, the function will block while reading the incoming
-     * OBEX package.
-     * An Abort request will be handled, and cause an IOException("Abort Received").
-     * Other messages will be discarded silently as per GOEP specification.
-     * @throws IOException if an abort request have been received.
-     * TODO: I think this is an error in the specification. If we discard other messages,
-     *       the peer device will most likely stall, as it will not receive the expected
-     *       response for the message...
-     *       I'm not sure how to understand "Receipt of invalid or unexpected SRM or SRMP
-     *       header values shall be ignored by the receiving device."
-     *       If any signal is received during an active SRM transfer it is unexpected regardless
-     *       whether or not it contains SRM/SRMP headers...
+     * This method will look for an abort from the peer during a SRM transfer. The function will not
+     * block if no data has been received from the remote device. If data have been received, the
+     * function will block while reading the incoming OBEX package. An Abort request will be
+     * handled, and cause an IOException("Abort Received"). Other messages will be discarded
+     * silently as per GOEP specification.
+     *
+     * @throws IOException if an abort request have been received. TODO: I think this is an error in
+     *     the specification. If we discard other messages, the peer device will most likely stall,
+     *     as it will not receive the expected response for the message... I'm not sure how to
+     *     understand "Receipt of invalid or unexpected SRM or SRMP header values shall be ignored
+     *     by the receiving device." If any signal is received during an active SRM transfer it is
+     *     unexpected regardless whether or not it contains SRM/SRMP headers...
      */
     private void checkSrmRemoteAbort() throws IOException {
-        if(mInput.available() > 0) {
+        if (mInput.available() > 0) {
             ObexPacket packet = ObexPacket.read(mInput);
             /*
              * Determine if an ABORT was sent as the reply
@@ -624,8 +648,13 @@ public final class ServerOperation implements Operation, BaseStream {
                 // TODO: should we throw an exception here anyway? - don't see how to
                 //       ignore SRM/SRMP headers without ignoring the complete signal
                 //       (in this particular case).
-                Log.w(TAG, "Received unexpected request from client - discarding...\n"
-                        + "   headerId: " + packet.mHeaderId + " length: " + packet.mLength);
+                Log.w(
+                        TAG,
+                        "Received unexpected request from client - discarding...\n"
+                                + "   headerId: "
+                                + packet.mHeaderId
+                                + " length: "
+                                + packet.mLength);
             }
         }
     }
@@ -644,12 +673,11 @@ public final class ServerOperation implements Operation, BaseStream {
     }
 
     /**
-     * Sends an ABORT message to the server. By calling this method, the
-     * corresponding input and output streams will be closed along with this
-     * object.
-     * @throws IOException if the transaction has already ended or if an OBEX
-     *         server called this method
+     * Sends an ABORT message to the server. By calling this method, the corresponding input and
+     * output streams will be closed along with this object.
      *
+     * @throws IOException if the transaction has already ended or if an OBEX server called this
+     *     method
      * @hide
      */
     public void abort() throws IOException {
@@ -657,12 +685,11 @@ public final class ServerOperation implements Operation, BaseStream {
     }
 
     /**
-     * Returns the headers that have been received during the operation.
-     * Modifying the object returned has no effect on the headers that are sent
-     * or retrieved.
+     * Returns the headers that have been received during the operation. Modifying the object
+     * returned has no effect on the headers that are sent or retrieved.
+     *
      * @return the headers received during this <code>Operation</code>
      * @throws IOException if this <code>Operation</code> has been closed
-     *
      * @hide
      */
     public HeaderSet getReceivedHeader() throws IOException {
@@ -671,14 +698,13 @@ public final class ServerOperation implements Operation, BaseStream {
     }
 
     /**
-     * Specifies the headers that should be sent in the next OBEX message that
-     * is sent.
-     * @param headers the headers to send in the next message
-     * @throws IOException if this <code>Operation</code> has been closed or the
-     *         transaction has ended and no further messages will be exchanged
-     * @throws IllegalArgumentException if <code>headers</code> was not created
-     *         by a call to <code>ServerRequestHandler.createHeaderSet()</code>
+     * Specifies the headers that should be sent in the next OBEX message that is sent.
      *
+     * @param headers the headers to send in the next message
+     * @throws IOException if this <code>Operation</code> has been closed or the transaction has
+     *     ended and no further messages will be exchanged
+     * @throws IllegalArgumentException if <code>headers</code> was not created by a call to <code>
+     *     ServerRequestHandler.createHeaderSet()</code>
      * @hide
      */
     public void sendHeaders(HeaderSet headers) throws IOException {
@@ -693,20 +719,18 @@ public final class ServerOperation implements Operation, BaseStream {
             for (int i = 0; i < headerList.length; i++) {
                 replyHeader.setHeader(headerList[i], headers.getHeader(headerList[i]));
             }
-
         }
     }
 
     /**
-     * Retrieves the response code retrieved from the server. Response codes are
-     * defined in the <code>ResponseCodes</code> interface.
-     * @return the response code retrieved from the server
-     * @throws IOException if an error occurred in the transport layer during
-     *         the transaction; if this method is called on a
-     *         <code>HeaderSet</code> object created by calling
-     *         <code>createHeaderSet</code> in a <code>ClientSession</code>
-     *         object; if this is called from a server
+     * Retrieves the response code retrieved from the server. Response codes are defined in the
+     * <code>ResponseCodes</code> interface.
      *
+     * @return the response code retrieved from the server
+     * @throws IOException if an error occurred in the transport layer during the transaction; if
+     *     this method is called on a <code>HeaderSet</code> object created by calling <code>
+     *     createHeaderSet</code> in a <code>ClientSession</code> object; if this is called from a
+     *     server
      * @hide
      */
     public int getResponseCode() throws IOException {
@@ -734,9 +758,9 @@ public final class ServerOperation implements Operation, BaseStream {
 
     /**
      * Open and return an input stream for a connection.
+     *
      * @return an input stream
      * @throws IOException if an I/O error occurs
-     *
      * @hide
      */
     public InputStream openInputStream() throws IOException {
@@ -746,9 +770,9 @@ public final class ServerOperation implements Operation, BaseStream {
 
     /**
      * Open and return a data input stream for a connection.
+     *
      * @return an input stream
      * @throws IOException if an I/O error occurs
-     *
      * @hide
      */
     public DataInputStream openDataInputStream() throws IOException {
@@ -757,9 +781,9 @@ public final class ServerOperation implements Operation, BaseStream {
 
     /**
      * Open and return an output stream for a connection.
+     *
      * @return an output stream
      * @throws IOException if an I/O error occurs
-     *
      * @hide
      */
     public OutputStream openOutputStream() throws IOException {
@@ -782,9 +806,9 @@ public final class ServerOperation implements Operation, BaseStream {
 
     /**
      * Open and return a data output stream for a connection.
+     *
      * @return an output stream
      * @throws IOException if an I/O error occurs
-     *
      * @hide
      */
     public DataOutputStream openDataOutputStream() throws IOException {
@@ -793,8 +817,8 @@ public final class ServerOperation implements Operation, BaseStream {
 
     /**
      * Closes the connection and ends the transaction
-     * @throws IOException if the operation has already ended or is closed
      *
+     * @throws IOException if the operation has already ended or is closed
      * @hide
      */
     public void close() throws IOException {
@@ -804,8 +828,8 @@ public final class ServerOperation implements Operation, BaseStream {
 
     /**
      * Verifies that the connection is open and no exceptions should be thrown.
-     * @throws IOException if an exception needs to be thrown
      *
+     * @throws IOException if an exception needs to be thrown
      * @hide
      */
     public void ensureOpen() throws IOException {
@@ -818,41 +842,35 @@ public final class ServerOperation implements Operation, BaseStream {
     }
 
     /**
-     * Verifies that additional information may be sent. In other words, the
-     * operation is not done.
-     * <P>
-     * Included to implement the BaseStream interface only. It does not do
-     * anything on the server side since the operation of the Operation object
-     * is not done until after the handler returns from its method.
-     * @throws IOException if the operation is completed
+     * Verifies that additional information may be sent. In other words, the operation is not done.
+     *
+     * <p>Included to implement the BaseStream interface only. It does not do anything on the server
+     * side since the operation of the Operation object is not done until after the handler returns
+     * from its method.
      *
+     * @throws IOException if the operation is completed
      * @hide
      */
-    public void ensureNotDone() throws IOException {
-    }
+    public void ensureNotDone() throws IOException {}
 
     /**
-     * Called when the output or input stream is closed. It does not do anything
-     * on the server side since the operation of the Operation object is not
-     * done until after the handler returns from its method.
-     * @param inStream <code>true</code> if the input stream is closed;
-     *        <code>false</code> if the output stream is closed
-     * @throws IOException if an IO error occurs
+     * Called when the output or input stream is closed. It does not do anything on the server side
+     * since the operation of the Operation object is not done until after the handler returns from
+     * its method.
      *
+     * @param inStream <code>true</code> if the input stream is closed; <code>false</code> if the
+     *     output stream is closed
+     * @throws IOException if an IO error occurs
      * @hide
      */
-    public void streamClosed(boolean inStream) throws IOException {
-
-    }
+    public void streamClosed(boolean inStream) throws IOException {}
 
     /** @hide */
-    public void noBodyHeader(){
+    public void noBodyHeader() {
         mSendBodyHeader = false;
     }
 
-    /**
-     * Returns whether the operation is aborted.
-     */
+    /** Returns whether the operation is aborted. */
     public boolean isAborted() {
         return mAborted;
     }
diff --git a/src/com/android/obex/ServerRequestHandler.java b/src/com/android/obex/ServerRequestHandler.java
index 95cd31f..2295ca2 100644
--- a/src/com/android/obex/ServerRequestHandler.java
+++ b/src/com/android/obex/ServerRequestHandler.java
@@ -33,46 +33,40 @@
 package com.android.obex;
 
 /**
- * The <code>ServerRequestHandler</code> class defines an event listener that
- * will respond to OBEX requests made to the server.
- * <P>
- * The <code>onConnect()</code>, <code>onSetPath()</code>,
- * <code>onDelete()</code>, <code>onGet()</code>, and <code>onPut()</code>
- * methods may return any response code defined in the
- * <code>ResponseCodes</code> class except for <code>OBEX_HTTP_CONTINUE</code>.
- * If <code>OBEX_HTTP_CONTINUE</code> or a value not defined in the
- * <code>ResponseCodes</code> class is returned, the server implementation will
- * send an <code>OBEX_HTTP_INTERNAL_ERROR</code> response to the client.
- * <P>
- * <STRONG>Connection ID and Target Headers</STRONG>
- * <P>
- * According to the IrOBEX specification, a packet may not contain a Connection
- * ID and Target header. Since the Connection ID header is managed by the
- * implementation, it will not send a Connection ID header, if a Connection ID
- * was specified, in a packet that has a Target header. In other words, if an
- * application adds a Target header to a <code>HeaderSet</code> object used in
- * an OBEX operation and a Connection ID was specified, no Connection ID will be
- * sent in the packet containing the Target header.
- * <P>
- * <STRONG>CREATE-EMPTY Requests</STRONG>
- * <P>
- * A CREATE-EMPTY request allows clients to create empty objects on the server.
- * When a CREATE-EMPTY request is received, the <code>onPut()</code> method will
- * be called by the implementation. To differentiate between a normal PUT
- * request and a CREATE-EMPTY request, an application must open the
- * <code>InputStream</code> from the <code>Operation</code> object passed to the
- * <code>onPut()</code> method. For a PUT request, the application will be able
- * to read Body data from this <code>InputStream</code>. For a CREATE-EMPTY
- * request, there will be no Body data to read. Therefore, a call to
- * <code>InputStream.read()</code> will return -1.
+ * The <code>ServerRequestHandler</code> class defines an event listener that will respond to OBEX
+ * requests made to the server.
+ *
+ * <p>The <code>onConnect()</code>, <code>onSetPath()</code>, <code>onDelete()</code>, <code>onGet()
+ * </code>, and <code>onPut()</code> methods may return any response code defined in the <code>
+ * ResponseCodes</code> class except for <code>OBEX_HTTP_CONTINUE</code>. If <code>
+ * OBEX_HTTP_CONTINUE</code> or a value not defined in the <code>ResponseCodes</code> class is
+ * returned, the server implementation will send an <code>OBEX_HTTP_INTERNAL_ERROR</code> response
+ * to the client.
+ *
+ * <p><STRONG>Connection ID and Target Headers</STRONG>
+ *
+ * <p>According to the IrOBEX specification, a packet may not contain a Connection ID and Target
+ * header. Since the Connection ID header is managed by the implementation, it will not send a
+ * Connection ID header, if a Connection ID was specified, in a packet that has a Target header. In
+ * other words, if an application adds a Target header to a <code>HeaderSet</code> object used in an
+ * OBEX operation and a Connection ID was specified, no Connection ID will be sent in the packet
+ * containing the Target header.
+ *
+ * <p><STRONG>CREATE-EMPTY Requests</STRONG>
+ *
+ * <p>A CREATE-EMPTY request allows clients to create empty objects on the server. When a
+ * CREATE-EMPTY request is received, the <code>onPut()</code> method will be called by the
+ * implementation. To differentiate between a normal PUT request and a CREATE-EMPTY request, an
+ * application must open the <code>InputStream</code> from the <code>Operation</code> object passed
+ * to the <code>onPut()</code> method. For a PUT request, the application will be able to read Body
+ * data from this <code>InputStream</code>. For a CREATE-EMPTY request, there will be no Body data
+ * to read. Therefore, a call to <code>InputStream.read()</code> will return -1.
  */
 public class ServerRequestHandler {
 
     private long mConnectionId;
 
-    /**
-     * Creates a <code>ServerRequestHandler</code>.
-     */
+    /** Creates a <code>ServerRequestHandler</code>. */
     protected ServerRequestHandler() {
         /*
          * A connection ID of -1 implies there is no connection ID
@@ -82,11 +76,10 @@ public class ServerRequestHandler {
 
     /**
      * Sets the connection ID header to include in the reply packets.
-     * @param connectionId the connection ID to use; -1 if no connection ID
-     *        should be sent
-     * @throws IllegalArgumentException if <code>id</code> is not in the range
-     *         -1 to 2<sup>32</sup>-1
      *
+     * @param connectionId the connection ID to use; -1 if no connection ID should be sent
+     * @throws IllegalArgumentException if <code>id</code> is not in the range -1 to
+     *     2<sup>32</sup>-1
      * @hide
      */
     public void setConnectionId(final long connectionId) {
@@ -97,11 +90,10 @@ public class ServerRequestHandler {
     }
 
     /**
-     * Retrieves the connection ID that is being used in the present connection.
-     * This method will return -1 if no connection ID is being used.
-     * @return the connection id being used or -1 if no connection ID is being
-     *         used
+     * Retrieves the connection ID that is being used in the present connection. This method will
+     * return -1 if no connection ID is being used.
      *
+     * @return the connection id being used or -1 if no connection ID is being used
      * @hide
      */
     public long getConnectionId() {
@@ -110,22 +102,21 @@ public class ServerRequestHandler {
 
     /**
      * Called when a CONNECT request is received.
-     * <P>
-     * If this method is not implemented by the class that extends this class,
-     * <code>onConnect()</code> will always return an <code>OBEX_HTTP_OK</code>
-     * response code.
-     * <P>
-     * The headers received in the request can be retrieved from the
-     * <code>request</code> argument. The headers that should be sent in the
-     * reply must be specified in the <code>reply</code> argument.
-     * @param request contains the headers sent by the client;
-     *        <code>request</code> will never be <code>null</code>
-     * @param reply the headers that should be sent in the reply;
-     *        <code>reply</code> will never be <code>null</code>
-     * @return a response code defined in <code>ResponseCodes</code> that will
-     *         be returned to the client; if an invalid response code is
-     *         provided, the <code>OBEX_HTTP_INTERNAL_ERROR</code> response code
-     *         will be used
+     *
+     * <p>If this method is not implemented by the class that extends this class, <code>onConnect()
+     * </code> will always return an <code>OBEX_HTTP_OK</code> response code.
+     *
+     * <p>The headers received in the request can be retrieved from the <code>request</code>
+     * argument. The headers that should be sent in the reply must be specified in the <code>reply
+     * </code> argument.
+     *
+     * @param request contains the headers sent by the client; <code>request</code> will never be
+     *     <code>null</code>
+     * @param reply the headers that should be sent in the reply; <code>reply</code> will never be
+     *     <code>null</code>
+     * @return a response code defined in <code>ResponseCodes</code> that will be returned to the
+     *     client; if an invalid response code is provided, the <code>OBEX_HTTP_INTERNAL_ERROR
+     *     </code> response code will be used
      */
     public int onConnect(HeaderSet request, HeaderSet reply) {
         return ResponseCodes.OBEX_HTTP_OK;
@@ -133,43 +124,41 @@ public class ServerRequestHandler {
 
     /**
      * Called when a DISCONNECT request is received.
-     * <P>
-     * The headers received in the request can be retrieved from the
-     * <code>request</code> argument. The headers that should be sent in the
-     * reply must be specified in the <code>reply</code> argument.
-     * @param request contains the headers sent by the client;
-     *        <code>request</code> will never be <code>null</code>
-     * @param reply the headers that should be sent in the reply;
-     *        <code>reply</code> will never be <code>null</code>
+     *
+     * <p>The headers received in the request can be retrieved from the <code>request</code>
+     * argument. The headers that should be sent in the reply must be specified in the <code>reply
+     * </code> argument.
+     *
+     * @param request contains the headers sent by the client; <code>request</code> will never be
+     *     <code>null</code>
+     * @param reply the headers that should be sent in the reply; <code>reply</code> will never be
+     *     <code>null</code>
      */
-    public void onDisconnect(HeaderSet request, HeaderSet reply) {
-    }
+    public void onDisconnect(HeaderSet request, HeaderSet reply) {}
 
     /**
      * Called when a SETPATH request is received.
-     * <P>
-     * If this method is not implemented by the class that extends this class,
-     * <code>onSetPath()</code> will always return an
-     * <code>OBEX_HTTP_NOT_IMPLEMENTED</code> response code.
-     * <P>
-     * The headers received in the request can be retrieved from the
-     * <code>request</code> argument. The headers that should be sent in the
-     * reply must be specified in the <code>reply</code> argument.
-     * @param request contains the headers sent by the client;
-     *        <code>request</code> will never be <code>null</code>
-     * @param reply the headers that should be sent in the reply;
-     *        <code>reply</code> will never be <code>null</code>
-     * @param backup <code>true</code> if the client requests that the server
-     *        back up one directory before changing to the path described by
-     *        <code>name</code>; <code>false</code> to apply the request to the
-     *        present path
-     * @param create <code>true</code> if the path should be created if it does
-     *        not already exist; <code>false</code> if the path should not be
-     *        created if it does not exist and an error code should be returned
-     * @return a response code defined in <code>ResponseCodes</code> that will
-     *         be returned to the client; if an invalid response code is
-     *         provided, the <code>OBEX_HTTP_INTERNAL_ERROR</code> response code
-     *         will be used
+     *
+     * <p>If this method is not implemented by the class that extends this class, <code>onSetPath()
+     * </code> will always return an <code>OBEX_HTTP_NOT_IMPLEMENTED</code> response code.
+     *
+     * <p>The headers received in the request can be retrieved from the <code>request</code>
+     * argument. The headers that should be sent in the reply must be specified in the <code>reply
+     * </code> argument.
+     *
+     * @param request contains the headers sent by the client; <code>request</code> will never be
+     *     <code>null</code>
+     * @param reply the headers that should be sent in the reply; <code>reply</code> will never be
+     *     <code>null</code>
+     * @param backup <code>true</code> if the client requests that the server back up one directory
+     *     before changing to the path described by <code>name</code>; <code>false</code> to apply
+     *     the request to the present path
+     * @param create <code>true</code> if the path should be created if it does not already exist;
+     *     <code>false</code> if the path should not be created if it does not exist and an error
+     *     code should be returned
+     * @return a response code defined in <code>ResponseCodes</code> that will be returned to the
+     *     client; if an invalid response code is provided, the <code>OBEX_HTTP_INTERNAL_ERROR
+     *     </code> response code will be used
      */
     public int onSetPath(HeaderSet request, HeaderSet reply, boolean backup, boolean create) {
 
@@ -178,50 +167,45 @@ public class ServerRequestHandler {
 
     /**
      * Called when a DELETE request is received.
-     * <P>
-     * If this method is not implemented by the class that extends this class,
-     * <code>onDelete()</code> will always return an
-     * <code>OBEX_HTTP_NOT_IMPLEMENTED</code> response code.
-     * <P>
-     * The headers received in the request can be retrieved from the
-     * <code>request</code> argument. The headers that should be sent in the
-     * reply must be specified in the <code>reply</code> argument.
-     * @param request contains the headers sent by the client;
-     *        <code>request</code> will never be <code>null</code>
-     * @param reply the headers that should be sent in the reply;
-     *        <code>reply</code> will never be <code>null</code>
-     * @return a response code defined in <code>ResponseCodes</code> that will
-     *         be returned to the client; if an invalid response code is
-     *         provided, the <code>OBEX_HTTP_INTERNAL_ERROR</code> response code
-     *         will be used
+     *
+     * <p>If this method is not implemented by the class that extends this class, <code>onDelete()
+     * </code> will always return an <code>OBEX_HTTP_NOT_IMPLEMENTED</code> response code.
+     *
+     * <p>The headers received in the request can be retrieved from the <code>request</code>
+     * argument. The headers that should be sent in the reply must be specified in the <code>reply
+     * </code> argument.
+     *
+     * @param request contains the headers sent by the client; <code>request</code> will never be
+     *     <code>null</code>
+     * @param reply the headers that should be sent in the reply; <code>reply</code> will never be
+     *     <code>null</code>
+     * @return a response code defined in <code>ResponseCodes</code> that will be returned to the
+     *     client; if an invalid response code is provided, the <code>OBEX_HTTP_INTERNAL_ERROR
+     *     </code> response code will be used
      */
     public int onDelete(HeaderSet request, HeaderSet reply) {
         return ResponseCodes.OBEX_HTTP_NOT_IMPLEMENTED;
     }
 
-    /**
-     * Called when a ABORT request is received.
-     */
+    /** Called when a ABORT request is received. */
     public int onAbort(HeaderSet request, HeaderSet reply) {
         return ResponseCodes.OBEX_HTTP_NOT_IMPLEMENTED;
     }
 
     /**
      * Called when a PUT request is received.
-     * <P>
-     * If this method is not implemented by the class that extends this class,
-     * <code>onPut()</code> will always return an
-     * <code>OBEX_HTTP_NOT_IMPLEMENTED</code> response code.
-     * <P>
-     * If an ABORT request is received during the processing of a PUT request,
-     * <code>op</code> will be closed by the implementation.
-     * @param operation contains the headers sent by the client and allows new
-     *        headers to be sent in the reply; <code>op</code> will never be
-     *        <code>null</code>
-     * @return a response code defined in <code>ResponseCodes</code> that will
-     *         be returned to the client; if an invalid response code is
-     *         provided, the <code>OBEX_HTTP_INTERNAL_ERROR</code> response code
-     *         will be used
+     *
+     * <p>If this method is not implemented by the class that extends this class, <code>onPut()
+     * </code> will always return an <code>OBEX_HTTP_NOT_IMPLEMENTED</code> response code.
+     *
+     * <p>If an ABORT request is received during the processing of a PUT request, <code>op</code>
+     * will be closed by the implementation.
+     *
+     * @param operation contains the headers sent by the client and allows new headers to be sent in
+     *     the reply; <code>op</code> will never be <code>null</code>
+     * @return a response code defined in <code>ResponseCodes</code> that will be returned to the
+     *     client; if an invalid response code is provided, the <code>OBEX_HTTP_INTERNAL_ERROR
+     *     </code> response code will be used
      */
     public int onPut(Operation operation) {
         return ResponseCodes.OBEX_HTTP_NOT_IMPLEMENTED;
@@ -229,59 +213,54 @@ public class ServerRequestHandler {
 
     /**
      * Called when a GET request is received.
-     * <P>
-     * If this method is not implemented by the class that extends this class,
-     * <code>onGet()</code> will always return an
-     * <code>OBEX_HTTP_NOT_IMPLEMENTED</code> response code.
-     * <P>
-     * If an ABORT request is received during the processing of a GET request,
-     * <code>op</code> will be closed by the implementation.
-     * @param operation contains the headers sent by the client and allows new
-     *        headers to be sent in the reply; <code>op</code> will never be
-     *        <code>null</code>
-     * @return a response code defined in <code>ResponseCodes</code> that will
-     *         be returned to the client; if an invalid response code is
-     *         provided, the <code>OBEX_HTTP_INTERNAL_ERROR</code> response code
-     *         will be used
+     *
+     * <p>If this method is not implemented by the class that extends this class, <code>onGet()
+     * </code> will always return an <code>OBEX_HTTP_NOT_IMPLEMENTED</code> response code.
+     *
+     * <p>If an ABORT request is received during the processing of a GET request, <code>op</code>
+     * will be closed by the implementation.
+     *
+     * @param operation contains the headers sent by the client and allows new headers to be sent in
+     *     the reply; <code>op</code> will never be <code>null</code>
+     * @return a response code defined in <code>ResponseCodes</code> that will be returned to the
+     *     client; if an invalid response code is provided, the <code>OBEX_HTTP_INTERNAL_ERROR
+     *     </code> response code will be used
      */
     public int onGet(Operation operation) {
         return ResponseCodes.OBEX_HTTP_NOT_IMPLEMENTED;
     }
 
     /**
-     * Called when this object attempts to authenticate a client and the
-     * authentication request fails because the response digest in the
-     * authentication response header was wrong.
-     * <P>
-     * If this method is not implemented by the class that extends this class,
-     * this method will do nothing.
-     * @param userName the user name returned in the authentication response;
-     *        <code>null</code> if no user name was provided in the response
+     * Called when this object attempts to authenticate a client and the authentication request
+     * fails because the response digest in the authentication response header was wrong.
+     *
+     * <p>If this method is not implemented by the class that extends this class, this method will
+     * do nothing.
+     *
+     * @param userName the user name returned in the authentication response; <code>null</code> if
+     *     no user name was provided in the response
      */
-    public void onAuthenticationFailure(byte[] userName) {
-    }
+    public void onAuthenticationFailure(byte[] userName) {}
 
     /**
      * Called by ServerSession to update the status of current transaction
-     * <P>
-     * If this method is not implemented by the class that extends this class,
-     * this method will do nothing.
+     *
+     * <p>If this method is not implemented by the class that extends this class, this method will
+     * do nothing.
      */
-    public void updateStatus(String message) {
-    }
+    public void updateStatus(String message) {}
 
     /**
      * Called when session is closed.
-     * <P>
-     * If this method is not implemented by the class that extends this class,
-     * this method will do nothing.
+     *
+     * <p>If this method is not implemented by the class that extends this class, this method will
+     * do nothing.
      */
-    public void onClose() {
-    }
+    public void onClose() {}
 
     /**
-     * Override to add Single Response Mode support - e.g. if the supplied
-     * transport is l2cap.
+     * Override to add Single Response Mode support - e.g. if the supplied transport is l2cap.
+     *
      * @return True if SRM is supported, else False
      */
     public boolean isSrmSupported() {
diff --git a/src/com/android/obex/ServerSession.java b/src/com/android/obex/ServerSession.java
index 41adcbe..6a11aea 100644
--- a/src/com/android/obex/ServerSession.java
+++ b/src/com/android/obex/ServerSession.java
@@ -40,9 +40,7 @@ import java.io.IOException;
 import java.io.InputStream;
 import java.io.OutputStream;
 
-/**
- * This class in an implementation of the OBEX ServerSession.
- */
+/** This class in an implementation of the OBEX ServerSession. */
 public final class ServerSession extends ObexSession implements Runnable {
 
     private static final String TAG = "Obex ServerSession";
@@ -68,8 +66,7 @@ public final class ServerSession extends ObexSession implements Runnable {
      * @param transport the connection to the client
      * @param handler the event listener that will process requests
      * @param auth the authenticator to use with this connection
-     * @throws IOException if an error occurred while opening the input and
-     *         output streams
+     * @throws IOException if an error occurred while opening the input and output streams
      */
     public ServerSession(ObexTransport transport, ServerRequestHandler handler, Authenticator auth)
             throws IOException {
@@ -86,8 +83,7 @@ public final class ServerSession extends ObexSession implements Runnable {
     }
 
     /**
-     * Processes requests made to the server and forwards them to the
-     * appropriate event listener.
+     * Processes requests made to the server and forwards them to the appropriate event listener.
      *
      * @hide
      */
@@ -96,9 +92,9 @@ public final class ServerSession extends ObexSession implements Runnable {
 
             boolean done = false;
             while (!done && !mClosed) {
-                if(V) Log.v(TAG, "Waiting for incoming request...");
+                if (V) Log.v(TAG, "Waiting for incoming request...");
                 int requestType = mInput.read();
-                if(V) Log.v(TAG, "Read request: " + requestType);
+                if (V) Log.v(TAG, "Read request: " + requestType);
                 switch (requestType) {
                     case ObexHelper.OBEX_OPCODE_CONNECT:
                         handleConnectRequest();
@@ -154,11 +150,10 @@ public final class ServerSession extends ObexSession implements Runnable {
     }
 
     /**
-     * Handles a ABORT request from a client. This method will read the rest of
-     * the request from the client. Assuming the request is valid, it will
-     * create a <code>HeaderSet</code> object to pass to the
-     * <code>ServerRequestHandler</code> object. After the handler processes the
-     * request, this method will create a reply message to send to the server.
+     * Handles a ABORT request from a client. This method will read the rest of the request from the
+     * client. Assuming the request is valid, it will create a <code>HeaderSet</code> object to pass
+     * to the <code>ServerRequestHandler</code> object. After the handler processes the request,
+     * this method will create a reply message to send to the server.
      *
      * @throws IOException if an error occurred at the transport layer
      */
@@ -183,15 +178,13 @@ public final class ServerSession extends ObexSession implements Runnable {
     }
 
     /**
-     * Handles a PUT request from a client. This method will provide a
-     * <code>ServerOperation</code> object to the request handler. The
-     * <code>ServerOperation</code> object will handle the rest of the request.
-     * It will also send replies and receive requests until the final reply
-     * should be sent. When the final reply should be sent, this method will get
-     * the response code to use and send the reply. The
-     * <code>ServerOperation</code> object will always reply with a
-     * OBEX_HTTP_CONTINUE reply. It will only reply if further information is
-     * needed.
+     * Handles a PUT request from a client. This method will provide a <code>ServerOperation</code>
+     * object to the request handler. The <code>ServerOperation</code> object will handle the rest
+     * of the request. It will also send replies and receive requests until the final reply should
+     * be sent. When the final reply should be sent, this method will get the response code to use
+     * and send the reply. The <code>ServerOperation</code> object will always reply with a
+     * OBEX_HTTP_CONTINUE reply. It will only reply if further information is needed.
+     *
      * @param type the type of request received; either 0x02 or 0x82
      * @throws IOException if an error occurred at the transport layer
      */
@@ -201,8 +194,8 @@ public final class ServerSession extends ObexSession implements Runnable {
             int response = -1;
 
             if ((op.finalBitSet) && !op.isValidBody()) {
-                response = validateResponseCode(mListener
-                        .onDelete(op.requestHeader, op.replyHeader));
+                response =
+                        validateResponseCode(mListener.onDelete(op.requestHeader, op.replyHeader));
             } else {
                 response = validateResponseCode(mListener.onPut(op));
             }
@@ -221,7 +214,7 @@ public final class ServerSession extends ObexSession implements Runnable {
              *internal error should not be sent because server has already replied with
              *OK response in "sendReply")
              */
-            if(V) Log.d(TAG,"Exception occurred - sending OBEX_HTTP_INTERNAL_ERROR reply",e);
+            if (V) Log.d(TAG, "Exception occurred - sending OBEX_HTTP_INTERNAL_ERROR reply", e);
             if (!op.isAborted()) {
                 sendResponse(ResponseCodes.OBEX_HTTP_INTERNAL_ERROR, null);
             }
@@ -229,15 +222,13 @@ public final class ServerSession extends ObexSession implements Runnable {
     }
 
     /**
-     * Handles a GET request from a client. This method will provide a
-     * <code>ServerOperation</code> object to the request handler. The
-     * <code>ServerOperation</code> object will handle the rest of the request.
-     * It will also send replies and receive requests until the final reply
-     * should be sent. When the final reply should be sent, this method will get
-     * the response code to use and send the reply. The
-     * <code>ServerOperation</code> object will always reply with a
-     * OBEX_HTTP_CONTINUE reply. It will only reply if further information is
-     * needed.
+     * Handles a GET request from a client. This method will provide a <code>ServerOperation</code>
+     * object to the request handler. The <code>ServerOperation</code> object will handle the rest
+     * of the request. It will also send replies and receive requests until the final reply should
+     * be sent. When the final reply should be sent, this method will get the response code to use
+     * and send the reply. The <code>ServerOperation</code> object will always reply with a
+     * OBEX_HTTP_CONTINUE reply. It will only reply if further information is needed.
+     *
      * @param type the type of request received; either 0x03 or 0x83
      * @throws IOException if an error occurred at the transport layer
      */
@@ -250,17 +241,17 @@ public final class ServerSession extends ObexSession implements Runnable {
                 op.sendReply(response);
             }
         } catch (Exception e) {
-            if(V) Log.d(TAG,"Exception occurred - sending OBEX_HTTP_INTERNAL_ERROR reply",e);
+            if (V) Log.d(TAG, "Exception occurred - sending OBEX_HTTP_INTERNAL_ERROR reply", e);
             sendResponse(ResponseCodes.OBEX_HTTP_INTERNAL_ERROR, null);
         }
     }
 
     /**
      * Send standard response.
+     *
      * @param code the response code to send
      * @param header the headers to include in the response
      * @throws IOException if an IO error occurs
-     *
      * @hide
      */
     public void sendResponse(int code, byte[] header) throws IOException {
@@ -274,27 +265,27 @@ public final class ServerSession extends ObexSession implements Runnable {
         if (header != null) {
             totalLength += header.length;
             data = new byte[totalLength];
-            data[0] = (byte)code;
-            data[1] = (byte)(totalLength >> 8);
-            data[2] = (byte)totalLength;
+            data[0] = (byte) code;
+            data[1] = (byte) (totalLength >> 8);
+            data[2] = (byte) totalLength;
             System.arraycopy(header, 0, data, 3, header.length);
         } else {
             data = new byte[totalLength];
-            data[0] = (byte)code;
-            data[1] = (byte)0x00;
-            data[2] = (byte)totalLength;
+            data[0] = (byte) code;
+            data[1] = (byte) 0x00;
+            data[2] = (byte) totalLength;
         }
         op.write(data);
         op.flush(); // TODO: Do we need to flush?
     }
 
     /**
-     * Handles a SETPATH request from a client. This method will read the rest
-     * of the request from the client. Assuming the request is valid, it will
-     * create a <code>HeaderSet</code> object to pass to the
-     * <code>ServerRequestHandler</code> object. After the handler processes the
-     * request, this method will create a reply message to send to the server
-     * with the response code provided.
+     * Handles a SETPATH request from a client. This method will read the rest of the request from
+     * the client. Assuming the request is valid, it will create a <code>HeaderSet</code> object to
+     * pass to the <code>ServerRequestHandler</code> object. After the handler processes the
+     * request, this method will create a reply message to send to the server with the response code
+     * provided.
+     *
      * @throws IOException if an error occurred at the transport layer
      */
     private void handleSetPathRequest() throws IOException {
@@ -323,8 +314,8 @@ public final class ServerSession extends ObexSession implements Runnable {
                 bytesReceived = mInput.read(headers);
 
                 while (bytesReceived != headers.length) {
-                    bytesReceived += mInput.read(headers, bytesReceived, headers.length
-                            - bytesReceived);
+                    bytesReceived +=
+                            mInput.read(headers, bytesReceived, headers.length - bytesReceived);
                 }
 
                 ObexHelper.updateHeaderSet(request, headers);
@@ -338,8 +329,8 @@ public final class ServerSession extends ObexSession implements Runnable {
                 if (request.mAuthResp != null) {
                     if (!handleAuthResp(request.mAuthResp)) {
                         code = ResponseCodes.OBEX_HTTP_UNAUTHORIZED;
-                        mListener.onAuthenticationFailure(ObexHelper.getTagValue((byte)0x01,
-                                request.mAuthResp));
+                        mListener.onAuthenticationFailure(
+                                ObexHelper.getTagValue((byte) 0x01, request.mAuthResp));
                     }
                     request.mAuthResp = null;
                 }
@@ -351,8 +342,8 @@ public final class ServerSession extends ObexSession implements Runnable {
                 if (request.mAuthChall != null) {
                     handleAuthChall(request);
                     reply.mAuthResp = new byte[request.mAuthResp.length];
-                    System.arraycopy(request.mAuthResp, 0, reply.mAuthResp, 0,
-                            reply.mAuthResp.length);
+                    System.arraycopy(
+                            request.mAuthResp, 0, reply.mAuthResp, 0, reply.mAuthResp.length);
                     request.mAuthChall = null;
                     request.mAuthResp = null;
                 }
@@ -368,8 +359,11 @@ public final class ServerSession extends ObexSession implements Runnable {
                 try {
                     code = mListener.onSetPath(request, reply, backup, create);
                 } catch (Exception e) {
-                    if(V) Log.d(TAG,"Exception occurred - sending OBEX_HTTP_INTERNAL_ERROR reply",
-                            e);
+                    if (V)
+                        Log.d(
+                                TAG,
+                                "Exception occurred - sending OBEX_HTTP_INTERNAL_ERROR reply",
+                                e);
                     sendResponse(ResponseCodes.OBEX_HTTP_INTERNAL_ERROR, null);
                     return;
                 }
@@ -403,9 +397,9 @@ public final class ServerSession extends ObexSession implements Runnable {
 
         // Compute Length of OBEX SETPATH packet
         byte[] replyData = new byte[totalLength];
-        replyData[0] = (byte)code;
-        replyData[1] = (byte)(totalLength >> 8);
-        replyData[2] = (byte)totalLength;
+        replyData[0] = (byte) code;
+        replyData[1] = (byte) (totalLength >> 8);
+        replyData[2] = (byte) totalLength;
         if (head != null) {
             System.arraycopy(head, 0, replyData, 3, head.length);
         }
@@ -418,11 +412,11 @@ public final class ServerSession extends ObexSession implements Runnable {
     }
 
     /**
-     * Handles a disconnect request from a client. This method will read the
-     * rest of the request from the client. Assuming the request is valid, it
-     * will create a <code>HeaderSet</code> object to pass to the
-     * <code>ServerRequestHandler</code> object. After the handler processes the
-     * request, this method will create a reply message to send to the server.
+     * Handles a disconnect request from a client. This method will read the rest of the request
+     * from the client. Assuming the request is valid, it will create a <code>HeaderSet</code>
+     * object to pass to the <code>ServerRequestHandler</code> object. After the handler processes
+     * the request, this method will create a reply message to send to the server.
+     *
      * @throws IOException if an error occurred at the transport layer
      */
     private void handleDisconnectRequest() throws IOException {
@@ -446,8 +440,8 @@ public final class ServerSession extends ObexSession implements Runnable {
                 bytesReceived = mInput.read(headers);
 
                 while (bytesReceived != headers.length) {
-                    bytesReceived += mInput.read(headers, bytesReceived, headers.length
-                            - bytesReceived);
+                    bytesReceived +=
+                            mInput.read(headers, bytesReceived, headers.length - bytesReceived);
                 }
 
                 ObexHelper.updateHeaderSet(request, headers);
@@ -462,8 +456,8 @@ public final class ServerSession extends ObexSession implements Runnable {
             if (request.mAuthResp != null) {
                 if (!handleAuthResp(request.mAuthResp)) {
                     code = ResponseCodes.OBEX_HTTP_UNAUTHORIZED;
-                    mListener.onAuthenticationFailure(ObexHelper.getTagValue((byte)0x01,
-                            request.mAuthResp));
+                    mListener.onAuthenticationFailure(
+                            ObexHelper.getTagValue((byte) 0x01, request.mAuthResp));
                 }
                 request.mAuthResp = null;
             }
@@ -478,8 +472,11 @@ public final class ServerSession extends ObexSession implements Runnable {
                 try {
                     mListener.onDisconnect(request, reply);
                 } catch (Exception e) {
-                    if(V) Log.d(TAG,"Exception occurred - sending OBEX_HTTP_INTERNAL_ERROR reply",
-                            e);
+                    if (V)
+                        Log.d(
+                                TAG,
+                                "Exception occurred - sending OBEX_HTTP_INTERNAL_ERROR reply",
+                                e);
                     sendResponse(ResponseCodes.OBEX_HTTP_INTERNAL_ERROR, null);
                     return;
                 }
@@ -509,9 +506,9 @@ public final class ServerSession extends ObexSession implements Runnable {
         } else {
             replyData = new byte[3];
         }
-        replyData[0] = (byte)code;
-        replyData[1] = (byte)(totalLength >> 8);
-        replyData[2] = (byte)totalLength;
+        replyData[0] = (byte) code;
+        replyData[1] = (byte) (totalLength >> 8);
+        replyData[2] = (byte) totalLength;
         if (head != null) {
             System.arraycopy(head, 0, replyData, 3, head.length);
         }
@@ -524,12 +521,12 @@ public final class ServerSession extends ObexSession implements Runnable {
     }
 
     /**
-     * Handles a connect request from a client. This method will read the rest
-     * of the request from the client. Assuming the request is valid, it will
-     * create a <code>HeaderSet</code> object to pass to the
-     * <code>ServerRequestHandler</code> object. After the handler processes the
-     * request, this method will create a reply message to send to the server
-     * with the response code provided.
+     * Handles a connect request from a client. This method will read the rest of the request from
+     * the client. Assuming the request is valid, it will create a <code>HeaderSet</code> object to
+     * pass to the <code>ServerRequestHandler</code> object. After the handler processes the
+     * request, this method will create a reply message to send to the server with the response code
+     * provided.
+     *
      * @throws IOException if an error occurred at the transport layer
      */
     private void handleConnectRequest() throws IOException {
@@ -545,7 +542,7 @@ public final class ServerSession extends ObexSession implements Runnable {
         HeaderSet reply = new HeaderSet();
         int bytesReceived;
 
-        if(V) Log.v(TAG,"handleConnectRequest()");
+        if (V) Log.v(TAG, "handleConnectRequest()");
 
         /*
          * Read in the length of the OBEX packet, OBEX version, flags, and max
@@ -553,26 +550,36 @@ public final class ServerSession extends ObexSession implements Runnable {
          */
         packetLength = mInput.read();
         packetLength = (packetLength << 8) + mInput.read();
-        if(V) Log.v(TAG,"handleConnectRequest() - packetLength: " + packetLength);
+        if (V) Log.v(TAG, "handleConnectRequest() - packetLength: " + packetLength);
 
         version = mInput.read();
         flags = mInput.read();
         mMaxPacketLength = mInput.read();
         mMaxPacketLength = (mMaxPacketLength << 8) + mInput.read();
 
-        if(V) Log.v(TAG,"handleConnectRequest() - version: " + version
-                + " MaxLength: " + mMaxPacketLength + " flags: " + flags);
+        if (V)
+            Log.v(
+                    TAG,
+                    "handleConnectRequest() - version: "
+                            + version
+                            + " MaxLength: "
+                            + mMaxPacketLength
+                            + " flags: "
+                            + flags);
 
         // should we check it?
         if (mMaxPacketLength > ObexHelper.MAX_PACKET_SIZE_INT) {
             mMaxPacketLength = ObexHelper.MAX_PACKET_SIZE_INT;
         }
 
-        if(mMaxPacketLength > ObexHelper.getMaxTxPacketSize(mTransport)) {
-            Log.w(TAG, "Requested MaxObexPacketSize " + mMaxPacketLength
-                    + " is larger than the max size supported by the transport: "
-                    + ObexHelper.getMaxTxPacketSize(mTransport)
-                    + " Reducing to this size.");
+        if (mMaxPacketLength > ObexHelper.getMaxTxPacketSize(mTransport)) {
+            Log.w(
+                    TAG,
+                    "Requested MaxObexPacketSize "
+                            + mMaxPacketLength
+                            + " is larger than the max size supported by the transport: "
+                            + ObexHelper.getMaxTxPacketSize(mTransport)
+                            + " Reducing to this size.");
             mMaxPacketLength = ObexHelper.getMaxTxPacketSize(mTransport);
         }
 
@@ -585,8 +592,8 @@ public final class ServerSession extends ObexSession implements Runnable {
                 bytesReceived = mInput.read(headers);
 
                 while (bytesReceived != headers.length) {
-                    bytesReceived += mInput.read(headers, bytesReceived, headers.length
-                            - bytesReceived);
+                    bytesReceived +=
+                            mInput.read(headers, bytesReceived, headers.length - bytesReceived);
                 }
 
                 ObexHelper.updateHeaderSet(request, headers);
@@ -601,8 +608,8 @@ public final class ServerSession extends ObexSession implements Runnable {
             if (request.mAuthResp != null) {
                 if (!handleAuthResp(request.mAuthResp)) {
                     code = ResponseCodes.OBEX_HTTP_UNAUTHORIZED;
-                    mListener.onAuthenticationFailure(ObexHelper.getTagValue((byte)0x01,
-                            request.mAuthResp));
+                    mListener.onAuthenticationFailure(
+                            ObexHelper.getTagValue((byte) 0x01, request.mAuthResp));
                 }
                 request.mAuthResp = null;
             }
@@ -611,8 +618,8 @@ public final class ServerSession extends ObexSession implements Runnable {
                 if (request.mAuthChall != null) {
                     handleAuthChall(request);
                     reply.mAuthResp = new byte[request.mAuthResp.length];
-                    System.arraycopy(request.mAuthResp, 0, reply.mAuthResp, 0,
-                            reply.mAuthResp.length);
+                    System.arraycopy(
+                            request.mAuthResp, 0, reply.mAuthResp, 0, reply.mAuthResp.length);
                     request.mAuthChall = null;
                     request.mAuthResp = null;
                 }
@@ -643,13 +650,15 @@ public final class ServerSession extends ObexSession implements Runnable {
                         code = ResponseCodes.OBEX_HTTP_INTERNAL_ERROR;
                     }
                 } catch (Exception e) {
-                    if(V) Log.d(TAG,"Exception occurred - sending OBEX_HTTP_INTERNAL_ERROR reply",
-                            e);
+                    if (V)
+                        Log.d(
+                                TAG,
+                                "Exception occurred - sending OBEX_HTTP_INTERNAL_ERROR reply",
+                                e);
                     totalLength = 7;
                     head = null;
                     code = ResponseCodes.OBEX_HTTP_INTERNAL_ERROR;
                 }
-
             }
         }
 
@@ -665,17 +674,22 @@ public final class ServerSession extends ObexSession implements Runnable {
         byte[] sendData = new byte[totalLength];
         int maxRxLength = ObexHelper.getMaxRxPacketSize(mTransport);
         if (maxRxLength > mMaxPacketLength) {
-            if(V) Log.v(TAG,"Set maxRxLength to min of maxRxServrLen:" + maxRxLength +
-                    " and MaxNegotiated from Client: " + mMaxPacketLength);
+            if (V)
+                Log.v(
+                        TAG,
+                        "Set maxRxLength to min of maxRxServrLen:"
+                                + maxRxLength
+                                + " and MaxNegotiated from Client: "
+                                + mMaxPacketLength);
             maxRxLength = mMaxPacketLength;
         }
-        sendData[0] = (byte)code;
+        sendData[0] = (byte) code;
         sendData[1] = length[2];
         sendData[2] = length[3];
-        sendData[3] = (byte)0x10;
-        sendData[4] = (byte)0x00;
-        sendData[5] = (byte)(maxRxLength >> 8);
-        sendData[6] = (byte)(maxRxLength & 0xFF);
+        sendData[3] = (byte) 0x10;
+        sendData[4] = (byte) 0x00;
+        sendData[5] = (byte) (maxRxLength >> 8);
+        sendData[6] = (byte) (maxRxLength & 0xFF);
 
         if (head != null) {
             System.arraycopy(head, 0, sendData, 7, head.length);
@@ -686,9 +700,8 @@ public final class ServerSession extends ObexSession implements Runnable {
     }
 
     /**
-     * Closes the server session - in detail close I/O streams and the
-     * underlying transport layer. Internal flag is also set so that later
-     * attempt to read/write will throw an exception.
+     * Closes the server session - in detail close I/O streams and the underlying transport layer.
+     * Internal flag is also set so that later attempt to read/write will throw an exception.
      */
     public synchronized void close() {
         if (mListener != null) {
@@ -697,14 +710,11 @@ public final class ServerSession extends ObexSession implements Runnable {
         try {
             /* Set state to closed before interrupting the thread by closing the streams */
             mClosed = true;
-            if(mInput != null)
-                mInput.close();
-            if(mOutput != null)
-                mOutput.close();
-            if(mTransport != null)
-                mTransport.close();
+            if (mInput != null) mInput.close();
+            if (mOutput != null) mOutput.close();
+            if (mTransport != null) mTransport.close();
         } catch (Exception e) {
-            if(V) Log.d(TAG,"Exception occurred during close() - ignore",e);
+            if (V) Log.d(TAG, "Exception occurred during close() - ignore", e);
         }
         mTransport = null;
         mInput = null;
@@ -713,13 +723,14 @@ public final class ServerSession extends ObexSession implements Runnable {
     }
 
     /**
-     * Verifies that the response code is valid. If it is not valid, it will
-     * return the <code>OBEX_HTTP_INTERNAL_ERROR</code> response code.
+     * Verifies that the response code is valid. If it is not valid, it will return the <code>
+     * OBEX_HTTP_INTERNAL_ERROR</code> response code.
+     *
      * @param code the response code to check
-     * @return the valid response code or <code>OBEX_HTTP_INTERNAL_ERROR</code>
-     *         if <code>code</code> is not valid
+     * @return the valid response code or <code>OBEX_HTTP_INTERNAL_ERROR</code> if <code>code</code>
+     *     is not valid
      */
-    private int validateResponseCode(int code) {
+    private static int validateResponseCode(int code) {
 
         if ((code >= ResponseCodes.OBEX_HTTP_OK) && (code <= ResponseCodes.OBEX_HTTP_PARTIAL)) {
             return code;
diff --git a/src/com/android/obex/SessionNotifier.java b/src/com/android/obex/SessionNotifier.java
index b0f10de..638b42a 100644
--- a/src/com/android/obex/SessionNotifier.java
+++ b/src/com/android/obex/SessionNotifier.java
@@ -35,49 +35,48 @@ package com.android.obex;
 import java.io.IOException;
 
 /**
- * The <code>SessionNotifier</code> interface defines a connection notifier for
- * server-side OBEX connections. When a <code>SessionNotifier</code> is created
- * and calls <code>acceptAndOpen()</code>, it will begin listening for clients
- * to create a connection at the transport layer. When the transport layer
- * connection is received, the <code>acceptAndOpen()</code> method will return a
- * <code>javax.microedition.io.Connection</code> that is the connection to the
- * client. The <code>acceptAndOpen()</code> method also takes a
- * <code>ServerRequestHandler</code> argument that will process the requests
- * from the client that connects to the server.
+ * The <code>SessionNotifier</code> interface defines a connection notifier for server-side OBEX
+ * connections. When a <code>SessionNotifier</code> is created and calls <code>acceptAndOpen()
+ * </code>, it will begin listening for clients to create a connection at the transport layer. When
+ * the transport layer connection is received, the <code>acceptAndOpen()</code> method will return a
+ * <code>javax.microedition.io.Connection</code> that is the connection to the client. The <code>
+ * acceptAndOpen()</code> method also takes a <code>ServerRequestHandler</code> argument that will
+ * process the requests from the client that connects to the server.
  */
 public interface SessionNotifier {
 
     /**
-     * Waits for a transport layer connection to be established and specifies
-     * the handler to handle the requests from the client. No authenticator is
-     * associated with this connection, therefore, it is implementation
-     * dependent as to how an authentication challenge and authentication
+     * Waits for a transport layer connection to be established and specifies the handler to handle
+     * the requests from the client. No authenticator is associated with this connection, therefore,
+     * it is implementation dependent as to how an authentication challenge and authentication
      * response header will be received and processed.
-     * <P>
-     * <H4>Additional Note for OBEX over Bluetooth</H4> If this method is called
-     * on a <code>SessionNotifier</code> object that does not have a
-     * <code>ServiceRecord</code> in the SDDB, the <code>ServiceRecord</code>
-     * for this object will be added to the SDDB. This method requests the BCC
-     * to put the local device in connectable mode so that it will respond to
-     * connection attempts by clients.
-     * <P>
-     * The following checks are done to verify that the service record provided
-     * is valid. If any of these checks fail, then a
-     * <code>ServiceRegistrationException</code> is thrown.
+     *
+     * <p>
+     *
+     * <H4>Additional Note for OBEX over Bluetooth</H4>
+     *
+     * If this method is called on a <code>SessionNotifier</code> object that does not have a <code>
+     * ServiceRecord</code> in the SDDB, the <code>ServiceRecord</code> for this object will be
+     * added to the SDDB. This method requests the BCC to put the local device in connectable mode
+     * so that it will respond to connection attempts by clients.
+     *
+     * <p>The following checks are done to verify that the service record provided is valid. If any
+     * of these checks fail, then a <code>ServiceRegistrationException</code> is thrown.
+     *
      * <UL>
-     * <LI>ServiceClassIDList and ProtocolDescriptorList, the mandatory service
-     * attributes for a <code>btgoep</code> service record, must be present in
-     * the <code>ServiceRecord</code> associated with this notifier.
-     * <LI>L2CAP, RFCOMM and OBEX must all be in the ProtocolDescriptorList
-     * <LI>The <code>ServiceRecord</code> associated with this notifier must not
-     * have changed the RFCOMM server channel number
+     *   <LI>ServiceClassIDList and ProtocolDescriptorList, the mandatory service attributes for a
+     *       <code>btgoep</code> service record, must be present in the <code>ServiceRecord</code>
+     *       associated with this notifier.
+     *   <LI>L2CAP, RFCOMM and OBEX must all be in the ProtocolDescriptorList
+     *   <LI>The <code>ServiceRecord</code> associated with this notifier must not have changed the
+     *       RFCOMM server channel number
      * </UL>
-     * <P>
-     * This method will not ensure that <code>ServiceRecord</code> associated
-     * with this notifier is a completely valid service record. It is the
-     * responsibility of the application to ensure that the service record
-     * follows all of the applicable syntactic and semantic rules for service
-     * record correctness.
+     *
+     * <p>This method will not ensure that <code>ServiceRecord</code> associated with this notifier
+     * is a completely valid service record. It is the responsibility of the application to ensure
+     * that the service record follows all of the applicable syntactic and semantic rules for
+     * service record correctness.
+     *
      * @param handler the request handler that will respond to OBEX requests
      * @return the connection to the client
      * @throws IOException if an error occurs in the transport layer
@@ -86,39 +85,39 @@ public interface SessionNotifier {
     ObexSession acceptAndOpen(ServerRequestHandler handler) throws IOException;
 
     /**
-     * Waits for a transport layer connection to be established and specifies
-     * the handler to handle the requests from the client and the
-     * <code>Authenticator</code> to use to respond to authentication challenge
-     * and authentication response headers.
-     * <P>
-     * <H4>Additional Note for OBEX over Bluetooth</H4> If this method is called
-     * on a <code>SessionNotifier</code> object that does not have a
-     * <code>ServiceRecord</code> in the SDDB, the <code>ServiceRecord</code>
-     * for this object will be added to the SDDB. This method requests the BCC
-     * to put the local device in connectable mode so that it will respond to
-     * connection attempts by clients.
-     * <P>
-     * The following checks are done to verify that the service record provided
-     * is valid. If any of these checks fail, then a
-     * <code>ServiceRegistrationException</code> is thrown.
+     * Waits for a transport layer connection to be established and specifies the handler to handle
+     * the requests from the client and the <code>Authenticator</code> to use to respond to
+     * authentication challenge and authentication response headers.
+     *
+     * <p>
+     *
+     * <H4>Additional Note for OBEX over Bluetooth</H4>
+     *
+     * If this method is called on a <code>SessionNotifier</code> object that does not have a <code>
+     * ServiceRecord</code> in the SDDB, the <code>ServiceRecord</code> for this object will be
+     * added to the SDDB. This method requests the BCC to put the local device in connectable mode
+     * so that it will respond to connection attempts by clients.
+     *
+     * <p>The following checks are done to verify that the service record provided is valid. If any
+     * of these checks fail, then a <code>ServiceRegistrationException</code> is thrown.
+     *
      * <UL>
-     * <LI>ServiceClassIDList and ProtocolDescriptorList, the mandatory service
-     * attributes for a <code>btgoep</code> service record, must be present in
-     * the <code>ServiceRecord</code> associated with this notifier.
-     * <LI>L2CAP, RFCOMM and OBEX must all be in the ProtocolDescriptorList
-     * <LI>The <code>ServiceRecord</code> associated with this notifier must not
-     * have changed the RFCOMM server channel number
+     *   <LI>ServiceClassIDList and ProtocolDescriptorList, the mandatory service attributes for a
+     *       <code>btgoep</code> service record, must be present in the <code>ServiceRecord</code>
+     *       associated with this notifier.
+     *   <LI>L2CAP, RFCOMM and OBEX must all be in the ProtocolDescriptorList
+     *   <LI>The <code>ServiceRecord</code> associated with this notifier must not have changed the
+     *       RFCOMM server channel number
      * </UL>
-     * <P>
-     * This method will not ensure that <code>ServiceRecord</code> associated
-     * with this notifier is a completely valid service record. It is the
-     * responsibility of the application to ensure that the service record
-     * follows all of the applicable syntactic and semantic rules for service
-     * record correctness.
+     *
+     * <p>This method will not ensure that <code>ServiceRecord</code> associated with this notifier
+     * is a completely valid service record. It is the responsibility of the application to ensure
+     * that the service record follows all of the applicable syntactic and semantic rules for
+     * service record correctness.
+     *
      * @param handler the request handler that will respond to OBEX requests
-     * @param auth the <code>Authenticator</code> to use with this connection;
-     *        if <code>null</code> then no <code>Authenticator</code> will be
-     *        used
+     * @param auth the <code>Authenticator</code> to use with this connection; if <code>null</code>
+     *     then no <code>Authenticator</code> will be used
      * @return the connection to the client
      * @throws IOException if an error occurs in the transport layer
      * @throws NullPointerException if <code>handler</code> is <code>null</code>
```

