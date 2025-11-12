```diff
diff --git a/METADATA b/METADATA
index 28bf21d..03c9b26 100644
--- a/METADATA
+++ b/METADATA
@@ -7,15 +7,15 @@ description: "XML-RPC client library used by DTS suite."
 third_party {
   license_type: NOTICE
   last_upgrade_date {
-    year: 2024
-    month: 12
-    day: 23
+    year: 2025
+    month: 4
+    day: 3
   }
   homepage: "https://github.com/gturri/aXMLRPC"
   identifier {
     type: "Git"
     value: "https://github.com/gturri/aXMLRPC.git"
-    version: "aXMLRPC-1.16.0"
+    version: "aXMLRPC-1.17.0"
     primary_source: true
   }
 }
diff --git a/pom.xml b/pom.xml
index 7012b8e..9df544c 100644
--- a/pom.xml
+++ b/pom.xml
@@ -3,7 +3,7 @@
 	<modelVersion>4.0.0</modelVersion>
 	<groupId>fr.turri</groupId>
 	<artifactId>aXMLRPC</artifactId>
-	<version>1.16.0</version>
+	<version>1.17.0</version>
 	<packaging>jar</packaging>
 	<name>aXMLRPC</name>
 	<description>Lightweight Java XML-RPC working also on Android.</description>
@@ -58,7 +58,7 @@
         <connection>scm:git:https://github.com/gturri/aXMLRPC.git</connection>
         <developerConnection>scm:git:git@github.com:gturri/aXMLRPC.git</developerConnection>
         <url>https://github.com/gturri/aXMLRPC</url>
-        <tag>aXMLRPC-1.16.0</tag>
+        <tag>aXMLRPC-1.17.0</tag>
 	</scm>
     <build>
       <pluginManagement>
diff --git a/src/main/java/de/timroes/axmlrpc/XMLRPCClient.java b/src/main/java/de/timroes/axmlrpc/XMLRPCClient.java
index 99d3979..780b722 100644
--- a/src/main/java/de/timroes/axmlrpc/XMLRPCClient.java
+++ b/src/main/java/de/timroes/axmlrpc/XMLRPCClient.java
@@ -812,7 +812,7 @@ public class XMLRPCClient {
 				return responseParser.parse(serializerHandler, istream, isFlagSet(FLAGS_DEBUG));
 
 			} catch(SocketTimeoutException ex) {
-				throw new XMLRPCTimeoutException("The XMLRPC call timed out.");
+				throw new XMLRPCTimeoutException("The XMLRPC call timed out.", ex);
 			} catch (IOException ex) {
 				// If the thread has been canceled this exception will be thrown.
 				// So only throw an exception if the thread hasnt been canceled
diff --git a/src/main/java/de/timroes/axmlrpc/XMLRPCTimeoutException.java b/src/main/java/de/timroes/axmlrpc/XMLRPCTimeoutException.java
index 64e7e21..df19573 100644
--- a/src/main/java/de/timroes/axmlrpc/XMLRPCTimeoutException.java
+++ b/src/main/java/de/timroes/axmlrpc/XMLRPCTimeoutException.java
@@ -7,9 +7,11 @@ package de.timroes.axmlrpc;
  * @author Tim Roes
  */
 public class XMLRPCTimeoutException extends XMLRPCException {
-
 	XMLRPCTimeoutException(String ex) {
 		super(ex);
 	}
 
+	XMLRPCTimeoutException(String message, Exception cause) {
+		super(message, cause);
+	}
 }
```

