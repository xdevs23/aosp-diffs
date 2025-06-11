```diff
diff --git a/Changelog b/Changelog
index a372879..8a46e03 100644
--- a/Changelog
+++ b/Changelog
@@ -1,3 +1,12 @@
+Fix options added in 1.15.0 (those were not usable)
+
+1.15.0
+Add
+- setConnectTimeout
+- setReadTimeout
+- callWithOverridenTimeout
+
+1.14.0
 Fix security issue CWE-611
 Add support for CDATA section in the server response
 
diff --git a/METADATA b/METADATA
index 0bd968f..28bf21d 100644
--- a/METADATA
+++ b/METADATA
@@ -1,16 +1,21 @@
-name: "gturri-aXMLRPC"
-description:
-    "XML-RPC client library used by DTS suite."
+# This project was upgraded with external_updater.
+# Usage: tools/external_updater/updater.sh update external/gturri-aXMLRPC
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
+name: "gturri-aXMLRPC"
+description: "XML-RPC client library used by DTS suite."
 third_party {
-homepage: "https://github.com/gturri/aXMLRPC"
+  license_type: NOTICE
+  last_upgrade_date {
+    year: 2024
+    month: 12
+    day: 23
+  }
+  homepage: "https://github.com/gturri/aXMLRPC"
   identifier {
     type: "Git"
     value: "https://github.com/gturri/aXMLRPC.git"
+    version: "aXMLRPC-1.16.0"
     primary_source: true
-    version: "aXMLRPC-1.14.0"
   }
-  version: "aXMLRPC-1.14.0"
-  last_upgrade_date { year: 2024 month: 8 day: 7 }
-  license_type: NOTICE
 }
diff --git a/OWNERS b/OWNERS
index 2e8f086..a2a4268 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1 +1,2 @@
 include platform/system/core:main:/janitors/OWNERS
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/README.md b/README.md
index 7e11d08..ff1ea81 100644
--- a/README.md
+++ b/README.md
@@ -1,8 +1,3 @@
-Beware, this library contains a nasty vulnerability
-===================================================
-
-As long as the vulnerability described in https://github.com/gturri/aXMLRPC/issues/143 is not fixed, you should probably not use aXMLRPC in your projects. :(
-
 What is aXMLRPC?
 ================
 
@@ -10,10 +5,6 @@ aXMLRPC is a Java library with a leightweight XML-RPC client. XML-RPC is
 a specification for making remote procedure calls over the HTTP protocol
 in an XML format. The specificationc can be found under http://www.xmlrpc.com/spec.
 
-The library was developed for the use with Android. Since it has no dependencies to 
-any Android library or any other 3rd-party library, it is fully functional in any
-common java virtual machine (not only on Android).
-
 You can control the client with some flags to extend its functionality. See the section
 about flags.
 
diff --git a/pom.xml b/pom.xml
index df322b6..7012b8e 100644
--- a/pom.xml
+++ b/pom.xml
@@ -3,7 +3,7 @@
 	<modelVersion>4.0.0</modelVersion>
 	<groupId>fr.turri</groupId>
 	<artifactId>aXMLRPC</artifactId>
-	<version>1.14.0</version>
+	<version>1.16.0</version>
 	<packaging>jar</packaging>
 	<name>aXMLRPC</name>
 	<description>Lightweight Java XML-RPC working also on Android.</description>
@@ -58,7 +58,7 @@
         <connection>scm:git:https://github.com/gturri/aXMLRPC.git</connection>
         <developerConnection>scm:git:git@github.com:gturri/aXMLRPC.git</developerConnection>
         <url>https://github.com/gturri/aXMLRPC</url>
-        <tag>aXMLRPC-1.14.0</tag>
+        <tag>aXMLRPC-1.16.0</tag>
 	</scm>
     <build>
       <pluginManagement>
diff --git a/src/main/java/de/timroes/axmlrpc/XMLRPCClient.java b/src/main/java/de/timroes/axmlrpc/XMLRPCClient.java
index efcf0f4..99d3979 100644
--- a/src/main/java/de/timroes/axmlrpc/XMLRPCClient.java
+++ b/src/main/java/de/timroes/axmlrpc/XMLRPCClient.java
@@ -196,7 +196,8 @@ public class XMLRPCClient {
 
 	private Proxy proxy;
 
-	private int timeout;
+	private int connectTimeout;
+	private int readTimeout;
 	private final SerializerHandler serializerHandler;
 
 	/**
@@ -296,7 +297,7 @@ public class XMLRPCClient {
 	}
 
 	/**
-	 * Sets the time in seconds after which a call should timeout.
+	 * Set both the connect timeout and the read timeout.
 	 * If {@code timeout} will be zero or less the connection will never timeout.
 	 * In case the connection times out an {@link XMLRPCTimeoutException} will
 	 * be thrown for calls made by {@link #call(java.lang.String, java.lang.Object[])}.
@@ -307,7 +308,16 @@ public class XMLRPCClient {
 	 * @param timeout The timeout for connections in seconds.
 	 */
 	public void setTimeout(int timeout) {
-		this.timeout = timeout;
+		this.connectTimeout = timeout;
+		this.readTimeout = timeout;
+	}
+
+	public void setConnectTimeout(int timeout) {
+		this.connectTimeout = timeout;
+	}
+
+	public void setReadTimeout(int timeout) {
+		this.readTimeout = timeout;
 	}
 
 	/**
@@ -460,11 +470,31 @@ public class XMLRPCClient {
 	 *
 	 * @param method A method name to call.
 	 * @param params An array of parameters for the method.
-	 * @return The result of the server.
+	 * @return The result of the call.
 	 * @throws XMLRPCException Will be thrown if an error occurred during the call.
 	 */
 	public Object call(String method, Object... params) throws XMLRPCException {
-		return new Caller().call(method, params);
+		return callWithOverriddenTimeout(method, connectTimeout, readTimeout, params);
+	}
+
+	/**
+	 * Call a remote procedure on the server. The method must be described by
+	 * a method name. If the method requires parameters, this must be set.
+	 * The type of the return object depends on the server. You should consult
+	 * the server documentation and then cast the return value according to that.
+	 * This method will block until the server returned a result (or an error occurred).
+	 * Read the README file delivered with the source code of this library for more
+	 * information.
+	 *
+	 * @param method A method name to call.
+	 * @param connectTimeout The connect timeout to use for this call.
+	 * @param readTimeout The read timeout to use for this call.
+	 * @param params An array of parameters for the method.
+	 * @return The result of the call.
+	 * @throws XMLRPCException Will be thrown if an error occurred during the call.
+	 */
+	public Object callWithOverriddenTimeout(String method, int connectTimeout, int readTimeout, Object[] params) throws XMLRPCException {
+		return new Caller().call(method, connectTimeout, readTimeout, params);
 	}
 
 	/**
@@ -483,8 +513,33 @@ public class XMLRPCClient {
 	 * @return The id of the current request.
 	 */
 	public long callAsync(XMLRPCCallback listener, String methodName, Object... params) {
+		return callAsyncWithOverriddenTimeout(listener, methodName, connectTimeout, readTimeout, params);
+	}
+
+	/**
+	 * Asynchronously call a remote procedure on the server. The method must be
+	 * described by a method name. If the method requires parameters, this must
+	 * be set. When the server returns a response the onResponse method is called
+	 * on the listener. If the server returns an error the onServerError method
+	 * is called on the listener. The onError method is called whenever something
+	 * fails. This method returns immediately and returns an identifier for the
+	 * request. All listener methods get this id as a parameter to distinguish
+	 * between
+	 * multiple requests.
+	 *
+	 * @param listener       A listener, which will be notified about the server
+	 *                       response or errors.
+	 * @param methodName     A method name to call on the server.
+	 * @param connectTimeout The connect timeout to use for this call.
+	 * @param readTimeout    The read timeout to use for this call.
+	 * @param params         An array of parameters for the method.
+	 * @return The id of the current request.
+	 */
+	public long callAsyncWithOverriddenTimeout(
+		XMLRPCCallback listener, String methodName, int connectTimeout, int readTimeout,
+		Object... params) {
 		long id = System.currentTimeMillis();
-		new Caller(listener, id, methodName, params).start();
+		new Caller(listener, id, methodName, connectTimeout, readTimeout, params).start();
 		return id;
 	}
 
@@ -549,6 +604,8 @@ public class XMLRPCClient {
 		private long threadId;
 		private String methodName;
 		private Object[] params;
+		private int connectTimeout;
+		private int readTimeout;
 
 		private volatile boolean canceled;
 		private HttpURLConnection http;
@@ -559,13 +616,18 @@ public class XMLRPCClient {
 		 * @param listener The listener to notice about the response or an error.
 		 * @param threadId An id that will be send to the listener.
 		 * @param methodName The method name to call.
+		 * @param connectTimeout The connect timeout to use for this call.
+		 * @param readTimeout The read timeout to use for this call.
 		 * @param params The parameters of the call or null.
 		 */
-		public Caller(XMLRPCCallback listener, long threadId, String methodName, Object[] params) {
+		public Caller(XMLRPCCallback listener, long threadId, String methodName,
+			int connectTimeout, int readTimeout, Object[] params) {
 			this.listener = listener;
 			this.threadId = threadId;
 			this.methodName = methodName;
 			this.params = params;
+			this.connectTimeout = connectTimeout;
+			this.readTimeout = readTimeout;
 		}
 
 		/**
@@ -589,7 +651,7 @@ public class XMLRPCClient {
 
 			try {
 				backgroundCalls.put(threadId, this);
-				Object o = this.call(methodName, params);
+				Object o = this.call(methodName, connectTimeout, readTimeout, params);
 				listener.onResponse(threadId, o);
 			} catch(CancelException ex) {
 				// Don't notify the listener, if the call has been canceled.
@@ -624,11 +686,12 @@ public class XMLRPCClient {
 		 *
 		 * @param methodName A method name to call.
 		 * @param params An array of parameters for the method.
-		 * @return The result of the server.
+		 * @param connectTimeout The connect timeout to use for this call.
+		 * @param readTimeout The read timeout to use for this call.
+		 * @return The result of the call.
 		 * @throws XMLRPCException Will be thrown if an error occurred during the call.
 		 */
-		public Object call(String methodName, Object[] params) throws XMLRPCException {
-
+		public Object call(String methodName, int connectTimeout, int readTimeout, Object[] params) throws XMLRPCException {
 			try {
 
 				Call c = createCall(methodName, params);
@@ -647,9 +710,11 @@ public class XMLRPCClient {
 				http.setDoInput(true);
 
 				// Set timeout
-				if(timeout > 0) {
-					http.setConnectTimeout(timeout * 1000);
-					http.setReadTimeout(timeout * 1000);
+				if(connectTimeout > 0) {
+					http.setConnectTimeout(connectTimeout * 1000);
+				}
+				if (readTimeout > 0) {
+					http.setReadTimeout(readTimeout * 1000);
 				}
 
 				// Set the request parameters
@@ -715,7 +780,7 @@ public class XMLRPCClient {
 						URL oldURL = url;
 						url = new URL(newLocation);
 						http.disconnect();
-						Object forwardedResult = call(methodName, params);
+						Object forwardedResult = call(methodName, connectTimeout, readTimeout, params);
 
 						// In case of temporary forward, restore original URL again for next call.
 						if(temporaryForward) {
diff --git a/src/main/java/de/timroes/axmlrpc/serializer/SerializerHandler.java b/src/main/java/de/timroes/axmlrpc/serializer/SerializerHandler.java
index af067ea..1f4643f 100644
--- a/src/main/java/de/timroes/axmlrpc/serializer/SerializerHandler.java
+++ b/src/main/java/de/timroes/axmlrpc/serializer/SerializerHandler.java
@@ -183,7 +183,7 @@ public class SerializerHandler {
 			byte[] old = (byte[])object;
 			Byte[] boxed = new Byte[old.length];
 			for(int i = 0; i < boxed.length; i++) {
-				boxed[i] = new Byte(old[i]);
+				boxed[i] = Byte.valueOf(old[i]);
 			}
 			object = boxed;
 			s = base64;
```

