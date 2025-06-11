```diff
diff --git a/OWNERS b/OWNERS
index 87a5dbe..41bd4fe 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1 +1,2 @@
 include platform/libcore:/OWNERS
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/src/main/com/tonicsystems/jarjar/Main.java b/src/main/com/tonicsystems/jarjar/Main.java
index aa78836..f17da6b 100644
--- a/src/main/com/tonicsystems/jarjar/Main.java
+++ b/src/main/com/tonicsystems/jarjar/Main.java
@@ -91,7 +91,9 @@ public class Main {
     w.flush();
   }
 
-  public void process(File rulesFile, File inJar, File outJar) throws IOException {
+  // ANDROID-BEGIN: b/383559945 Support sharding
+  public void process(File rulesFile, File inJar, File outJar, Integer totalShards, Integer shardIndex) throws IOException {
+  // ANDROID-END: b/383559945 Support sharding
     if (rulesFile == null || inJar == null || outJar == null) {
       throw new IllegalArgumentException("rulesFile, inJar, and outJar are required");
     }
@@ -103,7 +105,28 @@ public class Main {
     MainProcessor proc =
         new MainProcessor(rules, verbose, skipManifest, removeAndroidCompatAnnotations);
     // ANDROID-END: b/146418363 Add an Android-specific transformer to strip compat annotation
-    StandaloneJarProcessor.run(inJar, outJar, proc);
+
+    // ANDROID-BEGIN: b/383559945 Support sharding
+    if ((totalShards == null) != (shardIndex == null)) {
+      throw new IllegalArgumentException(
+              "4th and 5th arguments should be either both specified or omitted");
+    }
+    if (totalShards == null) {
+      totalShards = 1;
+    }
+    if (shardIndex == null) {
+      shardIndex = 0;
+    }
+    if (totalShards < 1) {
+      throw new IllegalArgumentException("4th argument (# of shards) should be a positive integer");
+    }
+    if (shardIndex < 0 || shardIndex >= totalShards) {
+      throw new IllegalArgumentException("Shard index (5th argument) should be" +
+              " >=0 and < # of shards (4th argument)" );
+    }
+
+    StandaloneJarProcessor.run(inJar, outJar, proc, totalShards, shardIndex);
+    // ANDROID-END: b/383559945 Support sharding
     proc.strip(outJar);
   }
 }
diff --git a/src/main/com/tonicsystems/jarjar/util/StandaloneJarProcessor.java b/src/main/com/tonicsystems/jarjar/util/StandaloneJarProcessor.java
index ecc50e7..e15d681 100644
--- a/src/main/com/tonicsystems/jarjar/util/StandaloneJarProcessor.java
+++ b/src/main/com/tonicsystems/jarjar/util/StandaloneJarProcessor.java
@@ -29,18 +29,40 @@ import java.util.jar.JarFile;
 import java.util.jar.JarOutputStream;
 
 public final class StandaloneJarProcessor {
+  // ANDROID-BEGIN: b/383559945 Support sharding
   public static void run(File from, File to, JarProcessor proc) throws IOException {
+    run(from, to, proc, 1, 0);
+  }
+
+  public static void run(File from, File to, JarProcessor proc, int totalShards, int shardIndex) throws IOException {
+  // ANDROID-END: b/383559945 Support sharding
     byte[] buf = new byte[0x2000];
 
     JarFile in = new JarFile(from);
     final File tmpTo = File.createTempFile("jarjar", ".jar");
     JarOutputStream out = new JarOutputStream(new BufferedOutputStream(new FileOutputStream(tmpTo)));
     Map<String, EntryStruct> entries = new HashMap<>();
+
+    // ANDROID-BEGIN: b/383559945 Support sharding
+    final int numItems = in.size();
+    final int shardStart = numItems * shardIndex / totalShards;
+    final int shardNextStart = numItems * (shardIndex + 1) / totalShards;
+    int index = -1;
+    // ANDROID-END: b/383559945 Support sharding
+
     try {
       EntryStruct struct = new EntryStruct();
       Enumeration<JarEntry> e = in.entries();
       while (e.hasMoreElements()) {
         JarEntry entry = e.nextElement();
+
+        // ANDROID-BEGIN: b/383559945 Support sharding
+        index++;
+        if (index < shardStart || index >= shardNextStart) {
+          continue;
+        }
+        // ANDROID-END: b/383559945 Support sharding
+
         struct.name = entry.getName();
         struct.time = entry.getTime();
         ByteArrayOutputStream baos = new ByteArrayOutputStream();
```

