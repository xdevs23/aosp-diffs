```diff
diff --git a/src/main/com/tonicsystems/jarjar/util/IoUtil.java b/src/main/com/tonicsystems/jarjar/util/IoUtil.java
index e26b485..e3588e5 100644
--- a/src/main/com/tonicsystems/jarjar/util/IoUtil.java
+++ b/src/main/com/tonicsystems/jarjar/util/IoUtil.java
@@ -16,6 +16,7 @@
 
 package com.tonicsystems.jarjar.util;
 
+import java.io.BufferedOutputStream;
 import java.io.ByteArrayOutputStream;
 import java.io.File;
 import java.io.FileInputStream;
@@ -46,7 +47,7 @@ class IoUtil {
 
   public static void copy(File from, File to, byte[] buf) throws IOException {
     try (InputStream in = new FileInputStream(from);
-        OutputStream out = new FileOutputStream(to)) {
+        OutputStream out = new BufferedOutputStream(new FileOutputStream(to))) {
       pipe(in, out, buf);
     }
   }
@@ -63,7 +64,7 @@ class IoUtil {
     final byte[] buf = new byte[0x2000];
 
     final ZipFile inputZip = new ZipFile(inputFile);
-    final ZipOutputStream outputStream = new ZipOutputStream(new FileOutputStream(outputFile));
+    final ZipOutputStream outputStream = new ZipOutputStream(new BufferedOutputStream(new FileOutputStream(outputFile)));
     try {
       // read a the entries of the input zip file and sort them
       final Enumeration<? extends ZipEntry> e = inputZip.entries();
diff --git a/src/main/com/tonicsystems/jarjar/util/StandaloneJarProcessor.java b/src/main/com/tonicsystems/jarjar/util/StandaloneJarProcessor.java
index 2e87104..ecc50e7 100644
--- a/src/main/com/tonicsystems/jarjar/util/StandaloneJarProcessor.java
+++ b/src/main/com/tonicsystems/jarjar/util/StandaloneJarProcessor.java
@@ -16,6 +16,7 @@
 
 package com.tonicsystems.jarjar.util;
 
+import java.io.BufferedOutputStream;
 import java.io.ByteArrayOutputStream;
 import java.io.File;
 import java.io.FileOutputStream;
@@ -33,7 +34,7 @@ public final class StandaloneJarProcessor {
 
     JarFile in = new JarFile(from);
     final File tmpTo = File.createTempFile("jarjar", ".jar");
-    JarOutputStream out = new JarOutputStream(new FileOutputStream(tmpTo));
+    JarOutputStream out = new JarOutputStream(new BufferedOutputStream(new FileOutputStream(tmpTo)));
     Map<String, EntryStruct> entries = new HashMap<>();
     try {
       EntryStruct struct = new EntryStruct();
```

