```diff
diff --git a/Changes.md b/Changes.md
index 9f2449c2c3..eddec04a6c 100644
--- a/Changes.md
+++ b/Changes.md
@@ -40,14 +40,8 @@ within a product configuration .mk file, board config .mk file, or buildspec.mk.
 
 ## Python 2 to 3 migration
 
-The path set when running builds now makes the `python` executable point to python 3,
-whereas on previous versions it pointed to python 2. If you still have python 2 scripts,
-you can change the shebang line to use `python2` explicitly. This only applies for
-scripts run directly from makefiles, or from soong genrules.
-
-In addition, `python_*` soong modules no longer allow python 2.
-
-Python 2 is slated for complete removal in V.
+Python 2 has been completely removed from the build. Please migrate any remaining usages to
+Python 3, and remove any version-specific properties from bp files.
 
 ## Stop referencing sysprop_library directly from cc modules
 
diff --git a/backported_fixes/Android.bp b/backported_fixes/Android.bp
index a20f3fc5f0..0caea56a57 100644
--- a/backported_fixes/Android.bp
+++ b/backported_fixes/Android.bp
@@ -19,20 +19,26 @@ package {
 
 genrule {
     name: "applied_backported_fixes",
-    tools: ["applied_backported_fixes_main"],
+    tools: ["applied_backported_fixes_property_writer"],
     srcs: [":applied_backported_fix_binpbs"],
     out: ["applied_backported_fixes.prop"],
-    cmd: "$(location applied_backported_fixes_main)" +
+    cmd: "$(location applied_backported_fixes_property_writer)" +
         " -p $(location applied_backported_fixes.prop)" +
         " $(in)",
 }
 
-java_library {
-    name: "backported_fixes_proto",
+filegroup {
+    name: "backported_fixes_proto_file",
     srcs: [
         "backported_fixes.proto",
     ],
+}
+
+java_library {
+    name: "backported_fixes_proto",
+    srcs: ["backported_fixes.proto"],
     host_supported: true,
+    sdk_version: "current",
 }
 
 java_library {
@@ -63,7 +69,7 @@ java_test_host {
 }
 
 java_library {
-    name: "applied_backported_fixes_lib",
+    name: "backported_fixes_main_lib",
     srcs: ["src/java/com/android/build/backportedfixes/*.java"],
     static_libs: [
         "backported_fixes_common",
@@ -75,18 +81,35 @@ java_library {
 }
 
 java_binary_host {
-    name: "applied_backported_fixes_main",
-    main_class: "com.android.build.backportedfixes.Main",
+    name: "applied_backported_fixes_property_writer",
+    main_class: "com.android.build.backportedfixes.WriteBackportedFixesPropFile",
     static_libs: [
-        "applied_backported_fixes_lib",
+        "backported_fixes_main_lib",
     ],
 }
 
+java_binary_host {
+    name: "backported_fixes_combiner",
+    main_class: "com.android.build.backportedfixes.CombineBackportedFixes",
+    static_libs: [
+        "backported_fixes_main_lib",
+    ],
+}
+
+// Combines BackportedFix binary proto files into a single BackportedFixes binary proto file.
+genrule_defaults {
+    name: "default_backported_fixes_combiner",
+    tools: ["backported_fixes_combiner"],
+    cmd: "$(location backported_fixes_combiner)" +
+        " -o $(out)" +
+        " $(in)",
+}
+
 java_test_host {
-    name: "applied_backported_fixes_test",
+    name: "backported_fixes_main_lib_test",
     srcs: ["tests/java/com/android/build/backportedfixes/*.java"],
     static_libs: [
-        "applied_backported_fixes_lib",
+        "backported_fixes_main_lib",
         "backported_fixes_proto",
         "junit",
         "truth",
@@ -97,19 +120,25 @@ java_test_host {
     test_suites: ["general-tests"],
 }
 
-gensrcs {
-    name: "applied_backported_fix_binpbs",
+// Converts BackprotedFix text protos to binary protos
+genrule_defaults {
+    name: "default_backported_fix_binpbs",
     tools: ["aprotoc"],
-    srcs: [
-        "applied_fixes/*.txtpb",
-    ],
     tool_files: [
-        "backported_fixes.proto",
+        ":backported_fixes_proto_file",
     ],
-    output_extension: "binpb",
     cmd: "$(location aprotoc)  " +
         " --encode=com.android.build.backportedfixes.BackportedFix" +
-        "  $(location backported_fixes.proto)" +
+        "  $(location :backported_fixes_proto_file)" +
         " < $(in)" +
         " > $(out); echo $(out)",
 }
+
+gensrcs {
+    name: "applied_backported_fix_binpbs",
+    defaults: ["default_backported_fix_binpbs"],
+    output_extension: "binpb",
+    srcs: [
+        "applied_fixes/*.txtpb",
+    ],
+}
diff --git a/core/BUILD.bazel b/backported_fixes/applied_fixes/ki385124056.txtpb
similarity index 57%
rename from core/BUILD.bazel
rename to backported_fixes/applied_fixes/ki385124056.txtpb
index f4869d4833..e2d4545b65 100644
--- a/core/BUILD.bazel
+++ b/backported_fixes/applied_fixes/ki385124056.txtpb
@@ -1,4 +1,4 @@
-# Copyright (C) 2023 The Android Open Source Project
+# Copyright (C) 2024 The Android Open Source Project
 #
 # Licensed under the Apache License, Version 2.0 (the "License");
 # you may not use this file except in compliance with the License.
@@ -10,19 +10,10 @@
 # distributed under the License is distributed on an "AS IS" BASIS,
 # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 # See the License for the specific language governing permissions and
-# limitations under the License
-
-# Export tradefed templates for tests.
-exports_files(
-    glob(["*.xml"]),
-)
+# limitations under the License.
+#
+# proto-file: ../backported_fixes.proto
+# proto-message: BackportedFix
 
-# Export proguard flag files for r8.
-filegroup(
-    name = "global_proguard_flags",
-    srcs = [
-        "proguard.flags",
-        "proguard_basic_keeps.flags",
-    ],
-    visibility = ["//visibility:public"],
-)
+known_issue: 385124056
+alias: 4
diff --git a/backported_fixes/src/java/com/android/build/backportedfixes/CombineBackportedFixes.java b/backported_fixes/src/java/com/android/build/backportedfixes/CombineBackportedFixes.java
new file mode 100644
index 0000000000..0592cc187b
--- /dev/null
+++ b/backported_fixes/src/java/com/android/build/backportedfixes/CombineBackportedFixes.java
@@ -0,0 +1,65 @@
+
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
+package com.android.build.backportedfixes;
+
+import com.android.build.backportedfixes.common.Parser;
+
+import com.beust.jcommander.JCommander;
+import com.beust.jcommander.Parameter;
+import com.beust.jcommander.converters.FileConverter;
+
+import java.io.File;
+import java.io.FileOutputStream;
+import java.io.IOException;
+import java.io.OutputStream;
+import java.util.List;
+
+
+/** Creates a BackportedFixes binary proto file from a list of BackportedFix proto binary files. */
+public final class CombineBackportedFixes {
+
+    @Parameter(description = "BackportedFix proto binary files",
+            converter = FileConverter.class,
+            required = true)
+    List<File> fixFiles;
+    @Parameter(description = "Write the BackportedFixes proto binary to this file",
+            names = {"--out","-o"},
+            converter = FileConverter.class,
+            required = true)
+    File outFile;
+
+    public static void main(String... argv) throws Exception {
+        CombineBackportedFixes main = new CombineBackportedFixes();
+        JCommander.newBuilder().addObject(main).build().parse(argv);
+        main.run();
+    }
+
+    CombineBackportedFixes() {
+    }
+
+    private void run() throws Exception {
+        try (var out = new FileOutputStream(outFile)) {
+            var fixes = Parser.parseBackportedFixFiles(fixFiles);
+            writeBackportedFixes(fixes, out);
+        }
+    }
+
+    static void writeBackportedFixes(BackportedFixes fixes, OutputStream out)
+            throws IOException {
+        fixes.writeTo(out);
+    }
+}
diff --git a/backported_fixes/src/java/com/android/build/backportedfixes/Main.java b/backported_fixes/src/java/com/android/build/backportedfixes/WriteBackportedFixesPropFile.java
similarity index 74%
rename from backported_fixes/src/java/com/android/build/backportedfixes/Main.java
rename to backported_fixes/src/java/com/android/build/backportedfixes/WriteBackportedFixesPropFile.java
index 79148cc838..0ffb4ac904 100644
--- a/backported_fixes/src/java/com/android/build/backportedfixes/Main.java
+++ b/backported_fixes/src/java/com/android/build/backportedfixes/WriteBackportedFixesPropFile.java
@@ -18,7 +18,6 @@ package com.android.build.backportedfixes;
 
 import static java.nio.charset.StandardCharsets.UTF_8;
 
-import com.android.build.backportedfixes.common.ClosableCollection;
 import com.android.build.backportedfixes.common.Parser;
 
 import com.beust.jcommander.JCommander;
@@ -33,27 +32,38 @@ import java.util.Arrays;
 import java.util.List;
 import java.util.stream.Collectors;
 
-public final class Main {
-    @Parameter(description = "BackportedFix proto binary files", converter = FileConverter.class,
+
+/**
+ * Creates backported fix properties file.
+ *
+ * <p>Writes BitSet of backported fix aliases from a list of BackportedFix proto binary files and
+ * writes the property {@value PROPERTY_NAME} to a file.
+ */
+public final class WriteBackportedFixesPropFile {
+
+    private static final String PROPERTY_NAME = "ro.build.backported_fixes.alias_bitset.long_list";
+    @Parameter(description = "BackportedFix proto binary files",
+            converter = FileConverter.class,
             required = true)
     List<File> fixFiles;
     @Parameter(description = "The file to write the property value to.",
-            names = {"--property_file", "-p"}, converter = FileConverter.class, required = true)
+            names = {"--property_file", "-p"},
+            converter = FileConverter.class,
+            required = true)
     File propertyFile;
 
     public static void main(String... argv) throws Exception {
-        Main main = new Main();
+        WriteBackportedFixesPropFile main = new WriteBackportedFixesPropFile();
         JCommander.newBuilder().addObject(main).build().parse(argv);
         main.run();
     }
 
-    Main() {
+    WriteBackportedFixesPropFile() {
     }
 
     private void run() throws Exception {
-        try (var fixStreams = ClosableCollection.wrap(Parser.getFileInputStreams(fixFiles));
-             var out = Files.newWriter(propertyFile, UTF_8)) {
-            var fixes = Parser.parseBackportedFixes(fixStreams.getCollection());
+        try (var out = Files.newWriter(propertyFile, UTF_8)) {
+            var fixes = Parser.parseBackportedFixFiles(fixFiles);
             writeFixesAsAliasBitSet(fixes, out);
         }
     }
@@ -70,7 +80,7 @@ public final class Main {
                 fixes.getFixesList().stream().mapToInt(BackportedFix::getAlias).toArray());
         String bsString = Arrays.stream(bsArray).mapToObj(Long::toString).collect(
                 Collectors.joining(","));
-        printWriter.printf("ro.build.backported_fixes.alias_bitset.long_list=%s", bsString);
+        printWriter.printf("%s=%s", PROPERTY_NAME, bsString);
         printWriter.println();
         if (printWriter.checkError()) {
             throw new RuntimeException("There was an error writing to " + out.toString());
diff --git a/backported_fixes/src/java/com/android/build/backportedfixes/common/ClosableCollection.java b/backported_fixes/src/java/com/android/build/backportedfixes/common/ClosableCollection.java
deleted file mode 100644
index 75b6730c88..0000000000
--- a/backported_fixes/src/java/com/android/build/backportedfixes/common/ClosableCollection.java
+++ /dev/null
@@ -1,67 +0,0 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-package com.android.build.backportedfixes.common;
-
-import com.google.common.collect.ImmutableList;
-
-import java.util.ArrayList;
-import java.util.Collection;
-
-/** An AutoCloseable holder for a collection of AutoCloseables. */
-public final class ClosableCollection<T extends AutoCloseable, C extends Collection<T>> implements
-        AutoCloseable {
-    C source;
-
-    /** Makes the collection AutoCloseable. */
-    public static <T extends AutoCloseable, C extends Collection<T>> ClosableCollection<T, C> wrap(
-            C source) {
-        return new ClosableCollection<>(source);
-    }
-
-    private ClosableCollection(C source) {
-        this.source = source;
-    }
-
-    /** Get the source collection. */
-    public C getCollection() {
-        return source;
-    }
-
-    /**
-     * Closes each item in the collection.
-     *
-     * @throws Exception if any close throws an an exception, a new exception is thrown with
-     *                   all the exceptions thrown closing the streams added as a suppressed
-     *                   exceptions.
-     */
-    @Override
-    public void close() throws Exception {
-        var failures = new ArrayList<Exception>();
-        for (T t : source) {
-            try {
-                t.close();
-            } catch (Exception e) {
-                failures.add(e);
-            }
-        }
-        if (!failures.isEmpty()) {
-            Exception e = new Exception(
-                    "%d of %d failed while closing".formatted(failures.size(), source.size()));
-            failures.forEach(e::addSuppressed);
-            throw e;
-        }
-    }
-}
diff --git a/backported_fixes/src/java/com/android/build/backportedfixes/common/Parser.java b/backported_fixes/src/java/com/android/build/backportedfixes/common/Parser.java
index 6b08b8f3b3..6180fdc3da 100644
--- a/backported_fixes/src/java/com/android/build/backportedfixes/common/Parser.java
+++ b/backported_fixes/src/java/com/android/build/backportedfixes/common/Parser.java
@@ -15,9 +15,12 @@
  */
 package com.android.build.backportedfixes.common;
 
+import static com.google.common.base.Preconditions.checkNotNull;
+
 import com.android.build.backportedfixes.BackportedFix;
 import com.android.build.backportedfixes.BackportedFixes;
 
+import com.google.common.base.Throwables;
 import com.google.common.collect.ImmutableList;
 
 import java.io.File;
@@ -26,7 +29,10 @@ import java.io.FileNotFoundException;
 import java.io.IOException;
 import java.io.InputStream;
 import java.util.BitSet;
+import java.util.Comparator;
 import java.util.List;
+import java.util.stream.Collector;
+import java.util.stream.Collectors;
 
 
 /** Static utilities for working with {@link BackportedFixes}. */
@@ -54,16 +60,79 @@ public final class Parser {
     /**
      * Creates a {@link BackportedFixes} from a list of {@link BackportedFix} binary proto streams.
      */
-    public static BackportedFixes parseBackportedFixes(List<? extends InputStream> fixStreams)
-            throws
-            IOException {
-        var fixes = BackportedFixes.newBuilder();
-        for (var s : fixStreams) {
-            BackportedFix fix = BackportedFix.parseFrom(s);
-            fixes.addFixes(fix);
+    public static BackportedFixes parseBackportedFixFiles(List<File> fixFiles)
+            throws IOException {
+        try {
+            return fixFiles.stream().map(Parser::tunelFileInputStream)
+                    .map(Parser::tunnelParse)
+                    .sorted(Comparator.comparing(BackportedFix::getKnownIssue))
+                    .collect(fixCollector());
+
+        } catch (TunnelException e) {
+            throw e.rethrow(FileNotFoundException.class, IOException.class);
+        }
+    }
+
+
+    private static Collector<BackportedFix, ?, BackportedFixes> fixCollector() {
+        return Collectors.collectingAndThen(Collectors.toList(), fixList -> {
+            var result = BackportedFixes.newBuilder();
+            result.addAllFixes(fixList);
+            return result.build();
+        });
+    }
+
+    private static FileInputStream tunelFileInputStream(File file) throws TunnelException {
+        try {
+            return new FileInputStream(file);
+        } catch (FileNotFoundException e) {
+            throw new TunnelException(e);
+        }
+    }
+
+    private static BackportedFix tunnelParse(InputStream s) throws TunnelException {
+        try {
+            var fix = BackportedFix.parseFrom(s);
             s.close();
+            return fix;
+        } catch (IOException e) {
+            throw new TunnelException(e);
         }
-        return fixes.build();
+    }
+
+    private static class TunnelException extends RuntimeException {
+        TunnelException(Exception cause) {
+            super("If you see this TunnelException something went wrong.  It should always be rethrown as the cause.", cause);
+        }
+
+        <X extends Exception> RuntimeException rethrow(Class<X> exceptionClazz) throws X {
+            checkNotNull(exceptionClazz);
+            Throwables.throwIfInstanceOf(getCause(), exceptionClazz);
+            throw exception(
+                    getCause(),
+                    "rethrow(%s) doesn't match underlying exception", exceptionClazz);
+        }
+
+        public <X1 extends Exception, X2 extends Exception> RuntimeException rethrow(
+                Class<X1> exceptionClazz1, Class<X2> exceptionClazz2) throws X1, X2 {
+            checkNotNull(exceptionClazz1);
+            checkNotNull(exceptionClazz2);
+            Throwables.throwIfInstanceOf(getCause(), exceptionClazz1);
+            Throwables.throwIfInstanceOf(getCause(), exceptionClazz2);
+            throw exception(
+                    getCause(),
+                    "rethrow(%s, %s) doesn't match underlying exception",
+                    exceptionClazz1,
+                    exceptionClazz2);
+        }
+
+        private static ClassCastException exception(
+                Throwable cause, String message, Object... formatArgs) {
+            ClassCastException result = new ClassCastException(String.format(message, formatArgs));
+            result.initCause(cause);
+            return result;
+        }
+
     }
 
     private Parser() {
diff --git a/backported_fixes/tests/java/com/android/build/backportedfixes/CombineBackportedFixesTest.java b/backported_fixes/tests/java/com/android/build/backportedfixes/CombineBackportedFixesTest.java
new file mode 100644
index 0000000000..21d5f1e676
--- /dev/null
+++ b/backported_fixes/tests/java/com/android/build/backportedfixes/CombineBackportedFixesTest.java
@@ -0,0 +1,41 @@
+
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
+package com.android.build.backportedfixes;
+
+import com.google.common.truth.Truth;
+
+import org.junit.Test;
+
+import java.io.ByteArrayOutputStream;
+import java.io.IOException;
+
+/** Tests for {@link CombineBackportedFixes}. */
+public class CombineBackportedFixesTest {
+
+
+    @Test
+    public void writeBackportedFixes_default() throws IOException {
+        // Not much of a test, but there is not much to test.
+        BackportedFixes fixes = BackportedFixes.newBuilder()
+                .addFixes(BackportedFix.newBuilder().setKnownIssue(123).build())
+                .build();
+        var result = new ByteArrayOutputStream();
+        CombineBackportedFixes.writeBackportedFixes(fixes, result);
+        Truth.assertThat(BackportedFixes.parseFrom(result.toByteArray()))
+                .isEqualTo(fixes);
+    }
+}
diff --git a/backported_fixes/tests/java/com/android/build/backportedfixes/MainTest.java b/backported_fixes/tests/java/com/android/build/backportedfixes/WriteBackportedFixesPropFileTest.java
similarity index 88%
rename from backported_fixes/tests/java/com/android/build/backportedfixes/MainTest.java
rename to backported_fixes/tests/java/com/android/build/backportedfixes/WriteBackportedFixesPropFileTest.java
index 84061e1698..3209c15911 100644
--- a/backported_fixes/tests/java/com/android/build/backportedfixes/MainTest.java
+++ b/backported_fixes/tests/java/com/android/build/backportedfixes/WriteBackportedFixesPropFileTest.java
@@ -23,8 +23,8 @@ import org.junit.Test;
 import java.io.PrintWriter;
 import java.io.StringWriter;
 
-/** Tests for {@link Main}. */
-public class MainTest {
+/** Tests for {@link WriteBackportedFixesPropFile}. */
+public class WriteBackportedFixesPropFileTest {
 
 
     @Test
@@ -32,7 +32,7 @@ public class MainTest {
         BackportedFixes fixes = BackportedFixes.newBuilder().build();
         var result = new StringWriter();
 
-        Main.writeFixesAsAliasBitSet(fixes, new PrintWriter(result));
+        WriteBackportedFixesPropFile.writeFixesAsAliasBitSet(fixes, new PrintWriter(result));
 
         Truth.assertThat(result.toString())
                 .isEqualTo("""
@@ -50,7 +50,7 @@ public class MainTest {
                 .build();
         var result = new StringWriter();
 
-        Main.writeFixesAsAliasBitSet(fixes, new PrintWriter(result));
+        WriteBackportedFixesPropFile.writeFixesAsAliasBitSet(fixes, new PrintWriter(result));
 
         Truth.assertThat(result.toString())
                 .isEqualTo("""
diff --git a/backported_fixes/tests/java/com/android/build/backportedfixes/common/CloseableCollectionTest.java b/backported_fixes/tests/java/com/android/build/backportedfixes/common/CloseableCollectionTest.java
deleted file mode 100644
index d3d84a8d63..0000000000
--- a/backported_fixes/tests/java/com/android/build/backportedfixes/common/CloseableCollectionTest.java
+++ /dev/null
@@ -1,91 +0,0 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-package com.android.build.backportedfixes.common;
-
-import com.google.common.collect.ImmutableSet;
-import com.google.common.truth.Correspondence;
-import com.google.common.truth.Truth;
-
-import org.junit.Test;
-
-/** Tests for {@link ClosableCollection}. */
-public class CloseableCollectionTest {
-
-    private static class FakeCloseable implements AutoCloseable {
-        private final boolean throwOnClose;
-        private final String name;
-
-
-        private boolean isClosed = false;
-
-        private FakeCloseable(String name, boolean throwOnClose) {
-            this.name = name;
-            this.throwOnClose = throwOnClose;
-
-        }
-
-        private static FakeCloseable named(String name) {
-            return new FakeCloseable(name, false);
-        }
-
-        private static FakeCloseable failing(String name) {
-            return new FakeCloseable(name, true);
-        }
-
-        public boolean isClosed() {
-            return isClosed;
-        }
-
-        @Override
-        public void close() throws Exception {
-            if (throwOnClose) {
-                throw new Exception(name + " close failed");
-            }
-            isClosed = true;
-        }
-    }
-
-
-    @Test
-    public void bothClosed() throws Exception {
-        var c = ImmutableSet.of(FakeCloseable.named("foo"), FakeCloseable.named("bar"));
-        try (var cc = ClosableCollection.wrap(c);) {
-            Truth.assertThat(cc.getCollection()).isSameInstanceAs(c);
-        }
-        Truth.assertThat(c)
-                .comparingElementsUsing(
-                        Correspondence.transforming(FakeCloseable::isClosed, "is closed"))
-                .containsExactly(true, true);
-    }
-
-    @Test
-    public void bothFailed() {
-        var c = ImmutableSet.of(FakeCloseable.failing("foo"), FakeCloseable.failing("bar"));
-
-        try {
-            try (var cc = ClosableCollection.wrap(c);) {
-                Truth.assertThat(cc.getCollection()).isSameInstanceAs(c);
-            }
-        } catch (Exception e) {
-            Truth.assertThat(e).hasMessageThat().isEqualTo("2 of 2 failed while closing");
-            Truth.assertThat(e.getSuppressed())
-                    .asList()
-                    .comparingElementsUsing(
-                            Correspondence.transforming(Exception::getMessage, "has a message of "))
-                    .containsExactly("foo close failed", "bar close failed");
-        }
-    }
-}
diff --git a/backported_fixes/tests/java/com/android/build/backportedfixes/common/ParserTest.java b/backported_fixes/tests/java/com/android/build/backportedfixes/common/ParserTest.java
index 444e6942b3..57a0a40b90 100644
--- a/backported_fixes/tests/java/com/android/build/backportedfixes/common/ParserTest.java
+++ b/backported_fixes/tests/java/com/android/build/backportedfixes/common/ParserTest.java
@@ -23,15 +23,21 @@ import com.android.build.backportedfixes.BackportedFixes;
 
 import com.google.common.collect.ImmutableList;
 
+import org.junit.Rule;
 import org.junit.Test;
+import org.junit.rules.TemporaryFolder;
 
-import java.io.ByteArrayInputStream;
+import java.io.File;
+import java.io.FileOutputStream;
 import java.io.IOException;
 import java.nio.file.Files;
 
 /** Tests for {@link Parser}.*/
 public class ParserTest {
 
+    @Rule
+    public TemporaryFolder mTempFolder = new TemporaryFolder();
+
     @Test
     public void getFileInputStreams() throws IOException {
         var results = Parser.getFileInputStreams(
@@ -53,15 +59,15 @@ public class ParserTest {
     }
 
     @Test
-    public void parseBackportedFixes_empty() throws IOException {
-        var result = Parser.parseBackportedFixes(ImmutableList.of());
+    public void parseBackportedFixFiles_empty() throws IOException {
+        var result = Parser.parseBackportedFixFiles(ImmutableList.of());
         assertThat(result).isEqualTo(BackportedFixes.getDefaultInstance());
     }
 
+
     @Test
-    public void parseBackportedFixes_oneBlank() throws IOException {
-        var result = Parser.parseBackportedFixes(
-                ImmutableList.of(inputStream(BackportedFix.getDefaultInstance())));
+    public void parseBackportedFixFiles_oneBlank() throws IOException {
+        var result = Parser.parseBackportedFixFiles(ImmutableList.of(mTempFolder.newFile()));
 
         assertThat(result).isEqualTo(
                 BackportedFixes.newBuilder()
@@ -70,7 +76,7 @@ public class ParserTest {
     }
 
     @Test
-    public void parseBackportedFixes_two() throws IOException {
+    public void parseBackportedFixFiles_two() throws IOException {
         BackportedFix ki123 = BackportedFix.newBuilder()
                 .setKnownIssue(123)
                 .setAlias(1)
@@ -79,8 +85,8 @@ public class ParserTest {
                 .setKnownIssue(456)
                 .setAlias(2)
                 .build();
-        var result = Parser.parseBackportedFixes(
-                ImmutableList.of(inputStream(ki123), inputStream(ki456)));
+        var result = Parser.parseBackportedFixFiles(
+                ImmutableList.of(tempFile(ki456), tempFile(ki123)));
         assertThat(result).isEqualTo(
                 BackportedFixes.newBuilder()
                         .addFixes(ki123)
@@ -88,7 +94,11 @@ public class ParserTest {
                         .build());
     }
 
-    private static ByteArrayInputStream inputStream(BackportedFix f) {
-        return new ByteArrayInputStream(f.toByteArray());
+    private File tempFile(BackportedFix fix) throws IOException {
+        File f = mTempFolder.newFile();
+        try (FileOutputStream out = new FileOutputStream(f)) {
+            fix.writeTo(out);
+            return f;
+        }
     }
 }
diff --git a/ci/Android.bp b/ci/Android.bp
index 3f28be4494..757767c4dc 100644
--- a/ci/Android.bp
+++ b/ci/Android.bp
@@ -35,11 +35,6 @@ python_test_host {
     data: [
         ":py3-cmd",
     ],
-    version: {
-        py3: {
-            embedded_launcher: true,
-        },
-    },
 }
 
 // This test is only intended to be run locally since it's slow, not hermetic,
@@ -64,11 +59,6 @@ python_test_host {
     test_options: {
         unit_test: false,
     },
-    version: {
-        py3: {
-            embedded_launcher: true,
-        },
-    },
 }
 
 python_test_host {
@@ -88,11 +78,6 @@ python_test_host {
     data: [
         ":py3-cmd",
     ],
-    version: {
-        py3: {
-            embedded_launcher: true,
-        },
-    },
 }
 
 python_binary_host {
diff --git a/ci/build_metadata b/ci/build_metadata
index cd011c8679..3e9218f200 100755
--- a/ci/build_metadata
+++ b/ci/build_metadata
@@ -14,15 +14,31 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 
-set -ex
+set -x
+
+source build/make/shell_utils.sh
 
 export TARGET_PRODUCT=aosp_arm64
 export TARGET_RELEASE=trunk_staging
 export TARGET_BUILD_VARIANT=eng
 
+import_build_vars \
+        OUT_DIR \
+        DIST_DIR \
+        HOST_OUT_EXECUTABLES \
+    || exit $?
+
 TARGETS=(
     all_teams
+    source_tree_size
     release_config_metadata
 )
 
-build/soong/bin/m dist ${TARGETS[@]}
+# Build modules
+build/soong/bin/m dist ${TARGETS[@]} || exit $?
+
+# List all source files in the tree
+( \
+    $HOST_OUT_EXECUTABLES/source_tree_size -o $DIST_DIR/all_source_tree_files.pb \
+        && gzip -fn $DIST_DIR/all_source_tree_files.pb \
+) || exit $?
diff --git a/ci/build_test_suites b/ci/build_test_suites
index 74470a8e16..a63f3fcde1 100755
--- a/ci/build_test_suites
+++ b/ci/build_test_suites
@@ -15,5 +15,5 @@
 # limitations under the License.
 set -euo pipefail
 
-build/soong/soong_ui.bash --make-mode build_test_suites
-$(build/soong/soong_ui.bash --dumpvar-mode HOST_OUT)/bin/build_test_suites $@
+build/soong/soong_ui.bash --make-mode dist build_test_suites general-tests-files-list test_mapping || exit $?
+$(build/soong/soong_ui.bash --dumpvar-mode HOST_OUT)/bin/build_test_suites $@ || exit $?
diff --git a/ci/build_test_suites.py b/ci/build_test_suites.py
index b67ecec09a..7636f6a44b 100644
--- a/ci/build_test_suites.py
+++ b/ci/build_test_suites.py
@@ -16,6 +16,7 @@
 
 import argparse
 from dataclasses import dataclass
+from collections import defaultdict
 import json
 import logging
 import os
@@ -33,7 +34,9 @@ import test_discovery_agent
 REQUIRED_ENV_VARS = frozenset(['TARGET_PRODUCT', 'TARGET_RELEASE', 'TOP', 'DIST_DIR'])
 SOONG_UI_EXE_REL_PATH = 'build/soong/soong_ui.bash'
 LOG_PATH = 'logs/build_test_suites.log'
-REQUIRED_BUILD_TARGETS = frozenset(['dist'])
+# Currently, this prevents the removal of those tags when they exist. In the future we likely
+# want the script to supply 'dist directly
+REQUIRED_BUILD_TARGETS = frozenset(['dist', 'droid', 'checkbuild'])
 
 
 class Error(Exception):
@@ -66,52 +69,33 @@ class BuildPlanner:
     self.build_context = build_context
     self.args = args
     self.target_optimizations = target_optimizations
+    self.target_to_test_infos = defaultdict(list)
 
   def create_build_plan(self):
 
     if 'optimized_build' not in self.build_context.enabled_build_features:
       return BuildPlan(set(self.args.extra_targets), set())
 
+    if not self.build_context.test_infos:
+      logging.warning('Build context has no test infos, skipping optimizations.')
+      for target in self.args.extra_targets:
+        get_metrics_agent().report_unoptimized_target(target, 'BUILD_CONTEXT has no test infos.')
+      return BuildPlan(set(self.args.extra_targets), set())
+
     build_targets = set()
     packaging_commands_getters = []
     # In order to roll optimizations out differently between test suites and
     # device builds, we have separate flags.
-    if (
-        'test_suites_zip_test_discovery'
+    enable_discovery = (('test_suites_zip_test_discovery'
         in self.build_context.enabled_build_features
         and not self.args.device_build
     ) or (
         'device_zip_test_discovery'
         in self.build_context.enabled_build_features
         and self.args.device_build
-    ):
-      preliminary_build_targets = self._collect_preliminary_build_targets()
-    else:
-      preliminary_build_targets = self._legacy_collect_preliminary_build_targets()
-
-      # Keep reporting metrics when test discovery is disabled.
-      # To be removed once test discovery is fully rolled out.
-      optimization_rationale = ''
-      test_discovery_zip_regexes = set()
-      try:
-        test_discovery_zip_regexes = self._get_test_discovery_zip_regexes()
-        logging.info(f'Discovered test discovery regexes: {test_discovery_zip_regexes}')
-      except test_discovery_agent.TestDiscoveryError as e:
-        optimization_rationale = e.message
-        logging.warning(f'Unable to perform test discovery: {optimization_rationale}')
-
-      for target in self.args.extra_targets:
-        if optimization_rationale:
-          get_metrics_agent().report_unoptimized_target(target, optimization_rationale)
-          continue
-        try:
-          regex = r'\b(%s.*)\b' % re.escape(target)
-          if any(re.search(regex, opt) for opt in test_discovery_zip_regexes):
-            get_metrics_agent().report_unoptimized_target(target, 'Test artifact used.')
-            continue
-          get_metrics_agent().report_optimized_target(target)
-        except Exception as e:
-          logging.error(f'unable to parse test discovery output: {repr(e)}')
+    )) and not self.args.test_discovery_info_mode
+    logging.info(f'Discovery mode is enabled= {enable_discovery}')
+    preliminary_build_targets = self._collect_preliminary_build_targets(enable_discovery)
 
     for target in preliminary_build_targets:
       target_optimizer_getter = self.target_optimizations.get(target, None)
@@ -120,7 +104,7 @@ class BuildPlanner:
         continue
 
       target_optimizer = target_optimizer_getter(
-          target, self.build_context, self.args
+          target, self.build_context, self.args, self.target_to_test_infos[target]
       )
       build_targets.update(target_optimizer.get_build_targets())
       packaging_commands_getters.append(
@@ -129,7 +113,7 @@ class BuildPlanner:
 
     return BuildPlan(build_targets, packaging_commands_getters)
 
-  def _collect_preliminary_build_targets(self):
+  def _collect_preliminary_build_targets(self, enable_discovery: bool):
     build_targets = set()
     try:
       test_discovery_zip_regexes = self._get_test_discovery_zip_regexes()
@@ -145,6 +129,11 @@ class BuildPlanner:
     for target in self.args.extra_targets:
       if target in REQUIRED_BUILD_TARGETS:
         build_targets.add(target)
+        get_metrics_agent().report_unoptimized_target(target, 'Required build target.')
+        continue
+      # If nothing is discovered without error, that means nothing is needed.
+      if not test_discovery_zip_regexes:
+        get_metrics_agent().report_optimized_target(target)
         continue
 
       regex = r'\b(%s.*)\b' % re.escape(target)
@@ -153,13 +142,18 @@ class BuildPlanner:
           if re.search(regex, opt):
             get_metrics_agent().report_unoptimized_target(target, 'Test artifact used.')
             build_targets.add(target)
-            continue
+            # proceed to next target evaluation
+            break
           get_metrics_agent().report_optimized_target(target)
         except Exception as e:
           # In case of exception report as unoptimized
           build_targets.add(target)
           get_metrics_agent().report_unoptimized_target(target, f'Error in parsing test discovery output for {target}: {repr(e)}')
           logging.error(f'unable to parse test discovery output: {repr(e)}')
+          break
+    # If discovery is not enabled, return the original list
+    if not enable_discovery:
+      return self._legacy_collect_preliminary_build_targets()
 
     return build_targets
 
@@ -186,6 +180,10 @@ class BuildPlanner:
       tf_command = self._build_tf_command(test_info)
       discovery_agent = test_discovery_agent.TestDiscoveryAgent(tradefed_args=tf_command)
       for regex in discovery_agent.discover_test_zip_regexes():
+        for target in self.args.extra_targets:
+          target_regex = r'\b(%s.*)\b' % re.escape(target)
+          if re.search(target_regex, regex):
+            self.target_to_test_infos[target].append(test_info)
         build_target_regexes.add(regex)
     return build_target_regexes
 
@@ -260,6 +258,11 @@ def parse_args(argv: list[str]) -> argparse.Namespace:
       action='store_true',
       help='Flag to indicate running a device build.',
   )
+  argparser.add_argument(
+      '--test_discovery_info_mode',
+      action='store_true',
+      help='Flag to enable running test discovery in info only mode.',
+  )
 
   return argparser.parse_args(argv)
 
@@ -301,7 +304,7 @@ def execute_build_plan(build_plan: BuildPlan):
   build_command.append(get_top().joinpath(SOONG_UI_EXE_REL_PATH))
   build_command.append('--make-mode')
   build_command.extend(build_plan.build_targets)
-
+  logging.info(f'Running build command: {build_command}')
   try:
     run_command(build_command)
   except subprocess.CalledProcessError as e:
diff --git a/ci/build_test_suites_test.py b/ci/build_test_suites_test.py
index 29d268e994..e4501d38c6 100644
--- a/ci/build_test_suites_test.py
+++ b/ci/build_test_suites_test.py
@@ -257,9 +257,9 @@ class BuildPlannerTest(unittest.TestCase):
   class TestOptimizedBuildTarget(optimized_targets.OptimizedBuildTarget):
 
     def __init__(
-        self, target, build_context, args, output_targets, packaging_commands
+        self, target, build_context, args, test_infos, output_targets, packaging_commands
     ):
-      super().__init__(target, build_context, args)
+      super().__init__(target, build_context, args, test_infos)
       self.output_targets = output_targets
       self.packaging_commands = packaging_commands
 
@@ -306,7 +306,8 @@ class BuildPlannerTest(unittest.TestCase):
     build_planner = self.create_build_planner(
         build_targets=build_targets,
         build_context=self.create_build_context(
-            enabled_build_features=[{'name': self.get_target_flag('target_1')}]
+            enabled_build_features=[{'name': self.get_target_flag('target_1')}],
+            test_context=self.get_test_context('target_1'),
         ),
     )
 
@@ -322,7 +323,8 @@ class BuildPlannerTest(unittest.TestCase):
     build_planner = self.create_build_planner(
         build_targets=build_targets,
         build_context=self.create_build_context(
-            enabled_build_features=[{'name': self.get_target_flag('target_1')}]
+            enabled_build_features=[{'name': self.get_target_flag('target_1')}],
+            test_context=self.get_test_context('target_1'),
         ),
         packaging_commands=packaging_commands,
     )
diff --git a/ci/metrics_agent.py b/ci/metrics_agent.py
index bc2479eab6..85cdcbd2e5 100644
--- a/ci/metrics_agent.py
+++ b/ci/metrics_agent.py
@@ -92,15 +92,15 @@ class MetricsAgent:
       size: int,
       included_modules: set[str],
   ):
-    target_result = self.target_results.get(target_name)
+    target_result = self._target_results.get(target_name)
     artifact = (
         metrics_pb2.OptimizedBuildMetrics.TargetOptimizationResult.OutputArtifact()
     )
     artifact.name = artifact_name
     artifact.size = size
     for module in included_modules:
-      artifact.included_modules.add(module)
-    target_result.output_artifacts.add(artifact)
+      artifact.included_modules.append(module)
+    target_result.output_artifact.append(artifact)
 
   def end_reporting(self):
     for target_result in self._target_results.values():
diff --git a/ci/optimized_targets.py b/ci/optimized_targets.py
index 688bdd8370..548e34273d 100644
--- a/ci/optimized_targets.py
+++ b/ci/optimized_targets.py
@@ -23,7 +23,9 @@ import pathlib
 import subprocess
 
 from build_context import BuildContext
+import metrics_agent
 import test_mapping_module_retriever
+import test_discovery_agent
 
 
 class OptimizedBuildTarget(ABC):
@@ -42,10 +44,12 @@ class OptimizedBuildTarget(ABC):
       target: str,
       build_context: BuildContext,
       args: argparse.Namespace,
+      test_infos,
   ):
     self.target = target
     self.build_context = build_context
     self.args = args
+    self.test_infos = test_infos
 
   def get_build_targets(self) -> set[str]:
     features = self.build_context.enabled_build_features
@@ -53,6 +57,8 @@ class OptimizedBuildTarget(ABC):
       self.modules_to_build = self.get_build_targets_impl()
       return self.modules_to_build
 
+    if self.target == 'general-tests':
+      self._report_info_metrics_silently('general-tests.zip')
     self.modules_to_build = {self.target}
     return {self.target}
 
@@ -161,6 +167,16 @@ class OptimizedBuildTarget(ABC):
         f'{dist_dir / name}',
     ]
 
+  def _report_info_metrics_silently(self, artifact_name):
+    try:
+      metrics_agent_instance = metrics_agent.MetricsAgent.instance()
+      targets = self.get_build_targets_impl()
+      metrics_agent_instance.report_optimized_target(self.target)
+      metrics_agent_instance.add_target_artifact(self.target, artifact_name, 0, targets)
+    except Exception as e:
+      logging.error(f'error while silently reporting metrics: {e}')
+
+
 
 class NullOptimizer(OptimizedBuildTarget):
   """No-op target optimizer.
@@ -191,6 +207,19 @@ class ChangeInfo:
 
     self._change_info_contents = change_info_contents
 
+  def get_changed_paths(self) -> set[str]:
+    changed_paths = set()
+    for change in self._change_info_contents['changes']:
+      project_path = change.get('projectPath') + '/'
+
+      for revision in change.get('revisions'):
+        for file_info in revision.get('fileInfos'):
+          file_path = file_info.get('path')
+          dir_path = os.path.dirname(file_path)
+          changed_paths.add(project_path + dir_path)
+
+    return changed_paths
+
   def find_changed_files(self) -> set[str]:
     changed_files = set()
 
@@ -207,11 +236,7 @@ class ChangeInfo:
 class GeneralTestsOptimizer(OptimizedBuildTarget):
   """general-tests optimizer
 
-  This optimizer reads in the list of changed files from the file located in
-  env[CHANGE_INFO] and uses this list alongside the normal TEST MAPPING logic to
-  determine what test mapping modules will run for the given changes. It then
-  builds those modules and packages them in the same way general-tests.zip is
-  normally built.
+  This optimizer uses test discovery to build a list of modules that are needed by all tests configured for the build. These modules are then build and packaged by the optimizer in the same way as they are in a normal build.
   """
 
   # List of modules that are built alongside general-tests as dependencies.
@@ -219,93 +244,105 @@ class GeneralTestsOptimizer(OptimizedBuildTarget):
       'cts-tradefed',
       'vts-tradefed',
       'compatibility-host-util',
-      'general-tests-shared-libs',
   ])
 
   def get_build_targets_impl(self) -> set[str]:
-    change_info_file_path = os.environ.get('CHANGE_INFO')
-    if not change_info_file_path:
-      logging.info(
-          'No CHANGE_INFO env var found, general-tests optimization disabled.'
-      )
-      return {'general-tests'}
-
-    test_infos = self.build_context.test_infos
-    test_mapping_test_groups = set()
-    for test_info in test_infos:
-      is_test_mapping = test_info.is_test_mapping
-      current_test_mapping_test_groups = test_info.test_mapping_test_groups
-      uses_general_tests = test_info.build_target_used('general-tests')
-
-      if uses_general_tests and not is_test_mapping:
-        logging.info(
-            'Test uses general-tests.zip but is not test-mapping, general-tests'
-            ' optimization disabled.'
-        )
-        return {'general-tests'}
-
-      if is_test_mapping:
-        test_mapping_test_groups.update(current_test_mapping_test_groups)
-
-    change_info = ChangeInfo(change_info_file_path)
-    changed_files = change_info.find_changed_files()
-
-    test_mappings = test_mapping_module_retriever.GetTestMappings(
-        changed_files, set()
-    )
+    self._general_tests_outputs = self._get_general_tests_outputs()
+    test_modules = self._get_test_discovery_modules()
 
     modules_to_build = set(self._REQUIRED_MODULES)
-
-    modules_to_build.update(
-        test_mapping_module_retriever.FindAffectedModules(
-            test_mappings, changed_files, test_mapping_test_groups
-        )
-    )
+    self._build_outputs = []
+    for module in test_modules:
+      module_outputs = [output for output in self._general_tests_outputs if module in output]
+      if module_outputs:
+        modules_to_build.add(module)
+        self._build_outputs.extend(module_outputs)
 
     return modules_to_build
 
+  def _get_general_tests_outputs(self) -> list[str]:
+    src_top = pathlib.Path(os.environ.get('TOP', os.getcwd()))
+    soong_vars = self._query_soong_vars(
+        src_top,
+        [
+            'PRODUCT_OUT',
+        ],
+    )
+    product_out = pathlib.Path(soong_vars.get('PRODUCT_OUT'))
+    with open(f'{product_out / "general-tests_files"}') as general_tests_list_file:
+      general_tests_list = general_tests_list_file.readlines()
+    with open(f'{product_out / "general-tests_host_files"}') as general_tests_list_file:
+      self._general_tests_host_outputs = general_tests_list_file.readlines()
+    with open(f'{product_out / "general-tests_target_files"}') as general_tests_list_file:
+      self._general_tests_target_outputs = general_tests_list_file.readlines()
+    return general_tests_list
+
+
+  def _get_test_discovery_modules(self) -> set[str]:
+    change_info = ChangeInfo(os.environ.get('CHANGE_INFO'))
+    change_paths = change_info.get_changed_paths()
+    test_modules = set()
+    for test_info in self.test_infos:
+      tf_command = self._build_tf_command(test_info, change_paths)
+      discovery_agent = test_discovery_agent.TestDiscoveryAgent(tradefed_args=tf_command, test_mapping_zip_path=os.environ.get('DIST_DIR')+'/test_mappings.zip')
+      modules, dependencies = discovery_agent.discover_test_mapping_test_modules()
+      for regex in modules:
+        test_modules.add(regex)
+    return test_modules
+
+
+  def _build_tf_command(self, test_info, change_paths) -> list[str]:
+    command = [test_info.command]
+    for extra_option in test_info.extra_options:
+      if not extra_option.get('key'):
+        continue
+      arg_key = '--' + extra_option.get('key')
+      if arg_key == '--build-id':
+        command.append(arg_key)
+        command.append(os.environ.get('BUILD_NUMBER'))
+        continue
+      if extra_option.get('values'):
+        for value in extra_option.get('values'):
+          command.append(arg_key)
+          command.append(value)
+      else:
+        command.append(arg_key)
+    if test_info.is_test_mapping:
+      for change_path in change_paths:
+        command.append('--test-mapping-path')
+        command.append(change_path)
+
+    return command
+
   def get_package_outputs_commands_impl(self):
     src_top = pathlib.Path(os.environ.get('TOP', os.getcwd()))
     dist_dir = pathlib.Path(os.environ.get('DIST_DIR'))
-
+    tmp_dir = pathlib.Path(os.environ.get('TMPDIR'))
+    print(f'modules: {self.modules_to_build}')
+
+    host_outputs = [str(src_top) + '/' + file for file in self._general_tests_host_outputs if any('/'+module+'/' in file for module in self.modules_to_build)]
+    target_outputs = [str(src_top) + '/' + file for file in self._general_tests_target_outputs if any('/'+module+'/' in file for module in self.modules_to_build)]
+    host_config_files = [file for file in host_outputs if file.endswith('.config\n')]
+    target_config_files = [file for file in target_outputs if file.endswith('.config\n')]
+    logging.info(host_outputs)
+    logging.info(target_outputs)
+    with open(f"{tmp_dir / 'host.list'}", 'w') as host_list_file:
+      for output in host_outputs:
+        host_list_file.write(output)
+    with open(f"{tmp_dir / 'target.list'}", 'w') as target_list_file:
+      for output in target_outputs:
+        target_list_file.write(output)
     soong_vars = self._query_soong_vars(
         src_top,
         [
-            'HOST_OUT_TESTCASES',
-            'TARGET_OUT_TESTCASES',
             'PRODUCT_OUT',
             'SOONG_HOST_OUT',
             'HOST_OUT',
         ],
     )
-    host_out_testcases = pathlib.Path(soong_vars.get('HOST_OUT_TESTCASES'))
-    target_out_testcases = pathlib.Path(soong_vars.get('TARGET_OUT_TESTCASES'))
     product_out = pathlib.Path(soong_vars.get('PRODUCT_OUT'))
     soong_host_out = pathlib.Path(soong_vars.get('SOONG_HOST_OUT'))
     host_out = pathlib.Path(soong_vars.get('HOST_OUT'))
-
-    host_paths = []
-    target_paths = []
-    host_config_files = []
-    target_config_files = []
-    for module in self.modules_to_build:
-      # The required modules are handled separately, no need to package.
-      if module in self._REQUIRED_MODULES:
-        continue
-
-      host_path = host_out_testcases / module
-      if os.path.exists(host_path):
-        host_paths.append(host_path)
-        self._collect_config_files(src_top, host_path, host_config_files)
-
-      target_path = target_out_testcases / module
-      if os.path.exists(target_path):
-        target_paths.append(target_path)
-        self._collect_config_files(src_top, target_path, target_config_files)
-
-      if not os.path.exists(host_path) and not os.path.exists(target_path):
-        logging.info(f'No host or target build outputs found for {module}.')
-
     zip_commands = []
 
     zip_commands.extend(
@@ -320,24 +357,23 @@ class GeneralTestsOptimizer(OptimizedBuildTarget):
     )
 
     zip_command = self._base_zip_command(src_top, dist_dir, 'general-tests.zip')
-
     # Add host testcases.
-    if host_paths:
+    if host_outputs:
       zip_command.extend(
           self._generate_zip_options_for_items(
               prefix='host',
-              relative_root=f'{src_top / soong_host_out}',
-              directories=host_paths,
+              relative_root=str(host_out),
+              list_files=[f"{tmp_dir / 'host.list'}"],
           )
       )
 
     # Add target testcases.
-    if target_paths:
+    if target_outputs:
       zip_command.extend(
           self._generate_zip_options_for_items(
               prefix='target',
-              relative_root=f'{src_top / product_out}',
-              directories=target_paths,
+              relative_root=str(product_out),
+              list_files=[f"{tmp_dir / 'target.list'}"],
           )
       )
 
@@ -357,20 +393,11 @@ class GeneralTestsOptimizer(OptimizedBuildTarget):
         )
     )
 
+    zip_command.append('-sha256')
+
     zip_commands.append(zip_command)
     return zip_commands
 
-  def _collect_config_files(
-      self,
-      src_top: pathlib.Path,
-      root_dir: pathlib.Path,
-      config_files: list[str],
-  ):
-    for root, dirs, files in os.walk(src_top / root_dir):
-      for file in files:
-        if file.endswith('.config'):
-          config_files.append(root_dir / file)
-
   def _get_zip_test_configs_zips_commands(
       self,
       src_top: pathlib.Path,
diff --git a/ci/optimized_targets_test.py b/ci/optimized_targets_test.py
index 0b0c0ec087..2935c83cc5 100644
--- a/ci/optimized_targets_test.py
+++ b/ci/optimized_targets_test.py
@@ -26,6 +26,7 @@ from unittest import mock
 from build_context import BuildContext
 import optimized_targets
 from pyfakefs import fake_filesystem_unittest
+import test_discovery_agent
 
 
 class GeneralTestsOptimizerTest(fake_filesystem_unittest.TestCase):
@@ -38,14 +39,12 @@ class GeneralTestsOptimizerTest(fake_filesystem_unittest.TestCase):
     self.mock_os_environ = os_environ_patcher.start()
 
     self._setup_working_build_env()
-    self._write_change_info_file()
     test_mapping_dir = pathlib.Path('/project/path/file/path')
     test_mapping_dir.mkdir(parents=True)
-    self._write_test_mapping_file()
 
   def _setup_working_build_env(self):
-    self.change_info_file = pathlib.Path('/tmp/change_info')
     self._write_soong_ui_file()
+    self._write_change_info_file()
     self._host_out_testcases = pathlib.Path('/tmp/top/host_out_testcases')
     self._host_out_testcases.mkdir(parents=True)
     self._target_out_testcases = pathlib.Path('/tmp/top/target_out_testcases')
@@ -56,58 +55,109 @@ class GeneralTestsOptimizerTest(fake_filesystem_unittest.TestCase):
     self._soong_host_out.mkdir(parents=True)
     self._host_out = pathlib.Path('/tmp/top/host_out')
     self._host_out.mkdir(parents=True)
+    self._write_general_tests_files_outputs()
 
     self._dist_dir = pathlib.Path('/tmp/top/out/dist')
     self._dist_dir.mkdir(parents=True)
 
     self.mock_os_environ.update({
-        'CHANGE_INFO': str(self.change_info_file),
         'TOP': '/tmp/top',
         'DIST_DIR': '/tmp/top/out/dist',
+        'TMPDIR': '/tmp/',
+        'CHANGE_INFO': '/tmp/top/change_info'
     })
 
+  def _write_change_info_file(self):
+    change_info_path = pathlib.Path('/tmp/top/')
+    with open(os.path.join(change_info_path, 'change_info'), 'w') as f:
+      f.write("""
+    {
+      "changes": [
+        {
+          "projectPath": "build/ci",
+          "revisions": [
+            {
+              "revisionNumber": 1,
+              "fileInfos": [
+                {
+                  "path": "src/main/java/com/example/MyClass.java",
+                  "action": "MODIFIED"
+                },
+                {
+                  "path": "src/test/java/com/example/MyClassTest.java",
+                  "action": "ADDED"
+                }
+              ]
+            },
+            {
+              "revisionNumber": 2,
+              "fileInfos": [
+                {
+                  "path": "src/main/java/com/example/AnotherClass.java",
+                  "action": "MODIFIED"
+                }
+              ]
+            }
+          ]
+        }
+      ]
+    }
+    """)
+
   def _write_soong_ui_file(self):
     soong_path = pathlib.Path('/tmp/top/build/soong')
     soong_path.mkdir(parents=True)
     with open(os.path.join(soong_path, 'soong_ui.bash'), 'w') as f:
       f.write("""
               #/bin/bash
-              echo HOST_OUT_TESTCASES='/tmp/top/host_out_testcases'
-              echo TARGET_OUT_TESTCASES='/tmp/top/target_out_testcases'
               echo PRODUCT_OUT='/tmp/top/product_out'
               echo SOONG_HOST_OUT='/tmp/top/soong_host_out'
               echo HOST_OUT='/tmp/top/host_out'
               """)
     os.chmod(os.path.join(soong_path, 'soong_ui.bash'), 0o666)
 
-  def _write_change_info_file(self):
-    change_info_contents = {
-        'changes': [{
-            'projectPath': '/project/path',
-            'revisions': [{
-                'fileInfos': [{
-                    'path': 'file/path/file_name',
-                }],
-            }],
-        }]
-    }
-
-    with open(self.change_info_file, 'w') as f:
-      json.dump(change_info_contents, f)
+  def _write_general_tests_files_outputs(self):
+    with open(os.path.join(self._product_out, 'general-tests_files'), 'w') as f:
+      f.write("""
+              path/to/module_1/general-tests-host-file
+              path/to/module_1/general-tests-host-file.config
+              path/to/module_1/general-tests-target-file
+              path/to/module_1/general-tests-target-file.config
+              path/to/module_2/general-tests-host-file
+              path/to/module_2/general-tests-host-file.config
+              path/to/module_2/general-tests-target-file
+              path/to/module_2/general-tests-target-file.config
+              path/to/module_1/general-tests-host-file
+              path/to/module_1/general-tests-host-file.config
+              path/to/module_1/general-tests-target-file
+              path/to/module_1/general-tests-target-file.config
+              """)
+    with open(os.path.join(self._product_out, 'general-tests_host_files'), 'w') as f:
+      f.write("""
+              path/to/module_1/general-tests-host-file
+              path/to/module_1/general-tests-host-file.config
+              path/to/module_2/general-tests-host-file
+              path/to/module_2/general-tests-host-file.config
+              path/to/module_1/general-tests-host-file
+              path/to/module_1/general-tests-host-file.config
+              """)
+    with open(os.path.join(self._product_out, 'general-tests_target_files'), 'w') as f:
+      f.write("""
+              path/to/module_1/general-tests-target-file
+              path/to/module_1/general-tests-target-file.config
+              path/to/module_2/general-tests-target-file
+              path/to/module_2/general-tests-target-file.config
+              path/to/module_1/general-tests-target-file
+              path/to/module_1/general-tests-target-file.config
+              """)
 
-  def _write_test_mapping_file(self):
-    test_mapping_contents = {
-        'test-mapping-group': [
-            {
-                'name': 'test_mapping_module',
-            },
-        ],
-    }
 
-    with open('/project/path/file/path/TEST_MAPPING', 'w') as f:
-      json.dump(test_mapping_contents, f)
+  @mock.patch('subprocess.run')
+  @mock.patch.object(test_discovery_agent.TestDiscoveryAgent, 'discover_test_mapping_test_modules')
+  def test_general_tests_optimized(self, discover_modules, subprocess_run):
+    subprocess_run.return_value = self._get_soong_vars_output()
+    discover_modules.return_value = (['module_1'], ['dependency_1'])
 
-  def test_general_tests_optimized(self):
     optimizer = self._create_general_tests_optimizer()
 
     build_targets = optimizer.get_build_targets()
@@ -115,84 +165,37 @@ class GeneralTestsOptimizerTest(fake_filesystem_unittest.TestCase):
     expected_build_targets = set(
         optimized_targets.GeneralTestsOptimizer._REQUIRED_MODULES
     )
-    expected_build_targets.add('test_mapping_module')
+    expected_build_targets.add('module_1')
 
     self.assertSetEqual(build_targets, expected_build_targets)
 
-  def test_no_change_info_no_optimization(self):
-    del os.environ['CHANGE_INFO']
+  @mock.patch('subprocess.run')
+  @mock.patch.object(test_discovery_agent.TestDiscoveryAgent, 'discover_test_mapping_test_modules')
+  def test_module_unused_module_not_built(self, discover_modules, subprocess_run):
+    subprocess_run.return_value = self._get_soong_vars_output()
+    discover_modules.return_value = (['no_module'], ['dependency_1'])
 
     optimizer = self._create_general_tests_optimizer()
 
     build_targets = optimizer.get_build_targets()
 
-    self.assertSetEqual(build_targets, {'general-tests'})
-
-  def test_mapping_groups_unused_module_not_built(self):
-    test_context = self._create_test_context()
-    test_context['testInfos'][0]['extraOptions'] = [
-        {
-            'key': 'additional-files-filter',
-            'values': ['general-tests.zip'],
-        },
-        {
-            'key': 'test-mapping-test-group',
-            'values': ['unused-test-mapping-group'],
-        },
-    ]
-    optimizer = self._create_general_tests_optimizer(
-        build_context=self._create_build_context(test_context=test_context)
-    )
-
-    build_targets = optimizer.get_build_targets()
-
     expected_build_targets = set(
         optimized_targets.GeneralTestsOptimizer._REQUIRED_MODULES
     )
     self.assertSetEqual(build_targets, expected_build_targets)
 
-  def test_general_tests_used_by_non_test_mapping_test_no_optimization(self):
-    test_context = self._create_test_context()
-    test_context['testInfos'][0]['extraOptions'] = [{
-        'key': 'additional-files-filter',
-        'values': ['general-tests.zip'],
-    }]
-    optimizer = self._create_general_tests_optimizer(
-        build_context=self._create_build_context(test_context=test_context)
-    )
-
-    build_targets = optimizer.get_build_targets()
-
-    self.assertSetEqual(build_targets, {'general-tests'})
-
-  def test_malformed_change_info_raises(self):
-    with open(self.change_info_file, 'w') as f:
-      f.write('not change info')
-
-    optimizer = self._create_general_tests_optimizer()
-
-    with self.assertRaises(json.decoder.JSONDecodeError):
-      build_targets = optimizer.get_build_targets()
-
-  def test_malformed_test_mapping_raises(self):
-    with open('/project/path/file/path/TEST_MAPPING', 'w') as f:
-      f.write('not test mapping')
-
-    optimizer = self._create_general_tests_optimizer()
-
-    with self.assertRaises(json.decoder.JSONDecodeError):
-      build_targets = optimizer.get_build_targets()
-
   @mock.patch('subprocess.run')
-  def test_packaging_outputs_success(self, subprocess_run):
+  @mock.patch.object(test_discovery_agent.TestDiscoveryAgent, 'discover_test_mapping_test_modules')
+  def test_packaging_outputs_success(self, discover_modules, subprocess_run):
     subprocess_run.return_value = self._get_soong_vars_output()
+    discover_modules.return_value = (['module_1'], ['dependency_1'])
     optimizer = self._create_general_tests_optimizer()
     self._set_up_build_outputs(['test_mapping_module'])
 
     targets = optimizer.get_build_targets()
     package_commands = optimizer.get_package_outputs_commands()
 
-    self._verify_soong_zip_commands(package_commands, ['test_mapping_module'])
+    self._verify_soong_zip_commands(package_commands, ['module_1'])
 
   @mock.patch('subprocess.run')
   def test_get_soong_dumpvars_fails_raises(self, subprocess_run):
@@ -200,10 +203,8 @@ class GeneralTestsOptimizerTest(fake_filesystem_unittest.TestCase):
     optimizer = self._create_general_tests_optimizer()
     self._set_up_build_outputs(['test_mapping_module'])
 
-    targets = optimizer.get_build_targets()
-
     with self.assertRaisesRegex(RuntimeError, 'Soong dumpvars failed!'):
-      package_commands = optimizer.get_package_outputs_commands()
+      targets = optimizer.get_build_targets()
 
   @mock.patch('subprocess.run')
   def test_get_soong_dumpvars_bad_output_raises(self, subprocess_run):
@@ -213,18 +214,16 @@ class GeneralTestsOptimizerTest(fake_filesystem_unittest.TestCase):
     optimizer = self._create_general_tests_optimizer()
     self._set_up_build_outputs(['test_mapping_module'])
 
-    targets = optimizer.get_build_targets()
-
     with self.assertRaisesRegex(
         RuntimeError, 'Error parsing soong dumpvars output'
     ):
-      package_commands = optimizer.get_package_outputs_commands()
+      targets = optimizer.get_build_targets()
 
   def _create_general_tests_optimizer(self, build_context: BuildContext = None):
     if not build_context:
       build_context = self._create_build_context()
     return optimized_targets.GeneralTestsOptimizer(
-        'general-tests', build_context, None
+        'general-tests', build_context, None, build_context.test_infos
     )
 
   def _create_build_context(
@@ -274,11 +273,10 @@ class GeneralTestsOptimizerTest(fake_filesystem_unittest.TestCase):
     return_value = subprocess.CompletedProcess(args=[], returncode=return_code)
     if not stdout:
       stdout = textwrap.dedent(f"""\
-                               HOST_OUT_TESTCASES='{self._host_out_testcases}'
-                               TARGET_OUT_TESTCASES='{self._target_out_testcases}'
                                PRODUCT_OUT='{self._product_out}'
                                SOONG_HOST_OUT='{self._soong_host_out}'
-                               HOST_OUT='{self._host_out}'""")
+                               HOST_OUT='{self._host_out}'
+                               """)
 
     return_value.stdout = stdout
     return return_value
diff --git a/ci/test_discovery_agent.py b/ci/test_discovery_agent.py
index 008ee47f8e..3c1caf45d9 100644
--- a/ci/test_discovery_agent.py
+++ b/ci/test_discovery_agent.py
@@ -30,6 +30,10 @@ class TestDiscoveryAgent:
 
   _TRADEFED_TEST_ZIP_REGEXES_LIST_KEY = "TestZipRegexes"
 
+  _TRADEFED_TEST_MODULES_LIST_KEY = "TestModules"
+
+  _TRADEFED_TEST_DEPENDENCIES_LIST_KEY = "TestDependencies"
+
   _TRADEFED_DISCOVERY_OUTPUT_FILE_NAME = "test_discovery_agent.txt"
 
   def __init__(
@@ -49,7 +53,7 @@ class TestDiscoveryAgent:
       A list of test zip regexes that TF is going to try to pull files from.
     """
     test_discovery_output_file_name = os.path.join(
-        os.environ.get('TOP'), 'out', self._TRADEFED_DISCOVERY_OUTPUT_FILE_NAME
+        os.environ.get("TOP"), "out", self._TRADEFED_DISCOVERY_OUTPUT_FILE_NAME
     )
     with open(
         test_discovery_output_file_name, mode="w+t"
@@ -89,14 +93,61 @@ class TestDiscoveryAgent:
         raise TestDiscoveryError("No test zip regexes returned")
       return data[self._TRADEFED_TEST_ZIP_REGEXES_LIST_KEY]
 
-  def discover_test_modules(self) -> list[str]:
-    """Discover test modules from TradeFed.
+  def discover_test_mapping_test_modules(self) -> (list[str], list[str]):
+    """Discover test mapping test modules and dependencies from TradeFed.
 
     Returns:
-      A list of test modules that TradeFed is going to execute based on the
+      A tuple that contains a list of test modules and a list of test
+      dependencies that TradeFed is going to execute based on the
       TradeFed test args.
     """
-    return []
+    test_discovery_output_file_name = os.path.join(
+        os.environ.get("TOP"), "out", self._TRADEFED_DISCOVERY_OUTPUT_FILE_NAME
+    )
+    with open(
+        test_discovery_output_file_name, mode="w+t"
+    ) as test_discovery_output_file:
+      java_args = []
+      java_args.append("prebuilts/jdk/jdk21/linux-x86/bin/java")
+      java_args.append("-cp")
+      java_args.append(
+          self.create_classpath(self.tradefed_jar_relevant_files_path)
+      )
+      java_args.append(
+          "com.android.tradefed.observatory.TestMappingDiscoveryAgent"
+      )
+      java_args.extend(self.tradefed_args)
+      env = os.environ.copy()
+      env.update({"SKIP_JAVA_QUERY": "1"})
+      env.update({"ALLOW_EMPTY_TEST_MAPPING": "1"})
+      env.update({"TF_TEST_MAPPING_ZIP_FILE": self.test_mapping_zip_path})
+      env.update({"DISCOVERY_OUTPUT_FILE": test_discovery_output_file.name})
+      logging.info(f"Calling test discovery with args: {java_args}")
+      try:
+        result = subprocess.run(args=java_args, env=env, text=True, check=True, stdout = subprocess.PIPE,
+    stderr = subprocess.PIPE)
+        logging.info(f"Test discovery agent output: {result.stdout}")
+      except subprocess.CalledProcessError as e:
+        raise TestDiscoveryError(
+            f"Failed to run test discovery, stdout: {e.stdout}, stderr:"
+            f" {e.stderr}, returncode: {e.returncode}"
+        )
+      data = json.loads(test_discovery_output_file.read())
+      logging.info(f"Test discovery result file content: {data}")
+      if (
+          self._TRADEFED_NO_POSSIBLE_TEST_DISCOVERY_KEY in data
+          and data[self._TRADEFED_NO_POSSIBLE_TEST_DISCOVERY_KEY]
+      ):
+        raise TestDiscoveryError("No possible test discovery")
+      if (
+          data[self._TRADEFED_TEST_MODULES_LIST_KEY] is None
+          or data[self._TRADEFED_TEST_MODULES_LIST_KEY] is []
+      ):
+        raise TestDiscoveryError("No test modules returned")
+      return (
+          data[self._TRADEFED_TEST_MODULES_LIST_KEY],
+          data[self._TRADEFED_TEST_DEPENDENCIES_LIST_KEY],
+      )
 
   def create_classpath(self, directory):
     """Creates a classpath string from all .jar files in the given directory.
diff --git a/common/math.mk b/common/math.mk
index 829ceb5e6f..0444631571 100644
--- a/common/math.mk
+++ b/common/math.mk
@@ -89,6 +89,11 @@ define math_is_number
 $(strip $(if $(call math_is_number_in_100,$(1)),true,$(call _math_ext_is_number,$(1))))
 endef
 
+# Returns true if $(1) is a positive or negative integer.
+define math_is_int
+$(call math_is_number,$(patsubst -%,%,$(1)))
+endef
+
 define math_is_zero
 $(strip \
   $(if $(word 2,$(1)),$(call math-error,Multiple words in a single argument: $(1))) \
@@ -100,6 +105,12 @@ $(call math-expect-true,(call math_is_number,2))
 $(call math-expect-true,(call math_is_number,202412))
 $(call math-expect-false,(call math_is_number,foo))
 $(call math-expect-false,(call math_is_number,-1))
+$(call math-expect-true,(call math_is_int,50))
+$(call math-expect-true,(call math_is_int,-1))
+$(call math-expect-true,(call math_is_int,-528))
+$(call math-expect-true,(call math_is_int,-0))
+$(call math-expect-false,(call math_is_int,--1))
+$(call math-expect-false,(call math_is_int,-))
 $(call math-expect-error,(call math_is_number,1 2),Multiple words in a single argument: 1 2)
 $(call math-expect-error,(call math_is_number,no 2),Multiple words in a single argument: no 2)
 
diff --git a/core/Makefile b/core/Makefile
index a7ab4425de..1448572d46 100644
--- a/core/Makefile
+++ b/core/Makefile
@@ -84,21 +84,6 @@ ifneq ($(BUILDING_VENDOR_KERNEL_BOOT_IMAGE),)
 endif
 
 
-###########################################################
-# Get the module names suitable for ALL_MODULES.* variables that are installed
-# for a given partition
-#
-# $(1): Partition
-###########################################################
-define register-names-for-partition
-$(sort $(foreach m,$(product_MODULES),\
-	$(if $(filter $(PRODUCT_OUT)/$(strip $(1))/%, $(ALL_MODULES.$(m).INSTALLED)), \
-		$(m)
-	) \
-))
-endef
-
-
 # Release & Aconfig Flags
 # -----------------------------------------------------------------
 include $(BUILD_SYSTEM)/packaging/flags.mk
@@ -169,7 +154,7 @@ $(foreach cf,$(unique_product_copy_files_pairs), \
             $(eval $(call copy-xml-file-checked,$(_src),$(_fulldest))),\
             $(if $(and $(filter %.jar,$(_dest)),$(filter $(basename $(notdir $(_dest))),$(PRODUCT_LOADED_BY_PRIVILEGED_MODULES))),\
                 $(eval $(call copy-and-uncompress-dexs,$(_src),$(_fulldest))), \
-                $(if $(filter init%rc,$(notdir $(_dest)))$(filter %/etc/init,$(dir $(_dest))),\
+                $(if $(filter init%rc,$(notdir $(_dest)))$(filter %/etc/init/,$(dir $(_dest))),\
                     $(eval $(call copy-init-script-file-checked,$(_src),$(_fulldest))),\
                     $(if $(and $(filter true,$(check_elf_prebuilt_product_copy_files)), \
                                $(filter bin lib lib64,$(subst /,$(space),$(_dest)))), \
@@ -295,11 +280,6 @@ ndk-docs: $(ndk_doxygen_out)/index.html
 .PHONY: ndk-docs
 endif
 
-ifeq ($(HOST_OS),linux)
-$(call dist-for-goals,sdk,$(API_FINGERPRINT))
-$(call dist-for-goals,droidcore,$(API_FINGERPRINT))
-endif
-
 INSTALLED_RECOVERYIMAGE_TARGET :=
 # Build recovery image if
 # BUILDING_RECOVERY_IMAGE && !BOARD_USES_RECOVERY_AS_BOOT && !BOARD_MOVE_RECOVERY_RESOURCES_TO_VENDOR_BOOT.
@@ -773,10 +753,7 @@ endif
 # $5 partition tag
 # $6 output file
 define _apkcerts_write_line
-$(hide) echo -n 'name="$(1).apk" certificate="$2" private_key="$3"' >> $6
-$(if $(4), $(hide) echo -n ' compressed="$4"' >> $6)
-$(if $(5), $(hide) echo -n ' partition="$5"' >> $6)
-$(hide) echo '' >> $6
+$(hide) echo 'name="$(1).apk" certificate="$2" private_key="$3"$(if $(4), compressed="$4")$(if $(5), partition="$5")' >> $6
 
 endef
 
@@ -798,7 +775,13 @@ name := $(name)-apkcerts
 intermediates := \
 	$(call intermediates-dir-for,PACKAGING,apkcerts)
 APKCERTS_FILE := $(intermediates)/$(name).txt
-all_apkcerts_files := $(sort $(foreach p,$(PACKAGES),$(PACKAGES.$(p).APKCERTS_FILE)))
+ifeq ($(RELEASE_APKCERTS_INSTALL_ONLY), true)
+  all_apkcerts_packages := $(filter $(call product-installed-modules,$(INTERNAL_PRODUCT)),$(PACKAGES))
+else
+  all_apkcerts_packages := $(PACKAGES)
+endif
+all_apkcerts_files := $(sort $(foreach p,$(all_apkcerts_packages),$(PACKAGES.$(p).APKCERTS_FILE)))
+
 $(APKCERTS_FILE): $(all_apkcerts_files)
 # We don't need to really build all the modules.
 # TODO: rebuild APKCERTS_FILE if any app change its cert.
@@ -806,7 +789,7 @@ $(APKCERTS_FILE):
 	@echo APK certs list: $@
 	@mkdir -p $(dir $@)
 	@rm -f $@
-	$(foreach p,$(sort $(PACKAGES)),\
+	$(foreach p,$(sort $(all_apkcerts_packages)),\
 	  $(if $(PACKAGES.$(p).APKCERTS_FILE),\
 	    $(call _apkcerts_merge,$(PACKAGES.$(p).APKCERTS_FILE), $@),\
 	    $(if $(PACKAGES.$(p).EXTERNAL_KEY),\
@@ -817,7 +800,7 @@ $(APKCERTS_FILE):
 	  $(if $(filter true,$(BUILDING_SYSTEM_EXT_IMAGE)),\
             $(call _apkcerts_write_line,BuildManifestSystemExt,$(FSVERITY_APK_KEY_PATH).x509.pem,$(FSVERITY_APK_KEY_PATH).pk8,,system_ext,$@)))
 	# In case value of PACKAGES is empty.
-	$(hide) touch $@
+	$(hide) touch $@ && sort -u -o $@ $@
 
 $(call declare-0p-target,$(APKCERTS_FILE))
 
@@ -846,16 +829,6 @@ ifneq (,$(TARGET_BUILD_APPS))
 endif
 
 
-# -----------------------------------------------------------------
-# build system stats
-BUILD_SYSTEM_STATS := $(PRODUCT_OUT)/build_system_stats.txt
-$(BUILD_SYSTEM_STATS):
-	@rm -f $@
-	@$(foreach s,$(STATS.MODULE_TYPE),echo "modules_type_make,$(s),$(words $(STATS.MODULE_TYPE.$(s)))" >>$@;)
-	@$(foreach s,$(STATS.SOONG_MODULE_TYPE),echo "modules_type_soong,$(s),$(STATS.SOONG_MODULE_TYPE.$(s))" >>$@;)
-$(call declare-1p-target,$(BUILD_SYSTEM_STATS),build)
-$(call dist-for-goals,droidcore-unbundled,$(BUILD_SYSTEM_STATS))
-
 # -----------------------------------------------------------------
 # build /product/etc/security/avb/system_other.avbpubkey if needed
 ifdef BUILDING_SYSTEM_OTHER_IMAGE
@@ -885,11 +858,6 @@ $(SOONG_TO_CONVERT): $(SOONG_CONV_DATA) $(SOONG_TO_CONVERT_SCRIPT)
 $(call declare-1p-target,$(SOONG_TO_CONVERT),build)
 $(call dist-for-goals,droidcore-unbundled,$(SOONG_TO_CONVERT))
 
-$(PRODUCT_OUT)/product_packages.txt:
-	@rm -f $@
-	echo "" > $@
-	$(foreach x,$(PRODUCT_PACKAGES),echo $(x) >> $@$(newline))
-
 MK2BP_CATALOG_SCRIPT := build/make/tools/mk2bp_catalog.py
 PRODUCT_PACKAGES_TXT := $(PRODUCT_OUT)/product_packages.txt
 MK2BP_REMAINING_HTML := $(PRODUCT_OUT)/mk2bp_remaining.html
@@ -936,18 +904,6 @@ $(call declare-0p-target,$(WALL_WERROR))
 
 $(call dist-for-goals,droidcore-unbundled,$(WALL_WERROR))
 
-# -----------------------------------------------------------------
-# Modules missing profile files
-PGO_PROFILE_MISSING := $(PRODUCT_OUT)/pgo_profile_file_missing.txt
-$(PGO_PROFILE_MISSING):
-	@rm -f $@
-	echo "# Modules missing PGO profile files" >> $@
-	for m in $(SOONG_MODULES_MISSING_PGO_PROFILE_FILE); do echo $$m >> $@; done
-
-$(call declare-0p-target,$(PGO_PROFILE_MISSING))
-
-$(call dist-for-goals,droidcore,$(PGO_PROFILE_MISSING))
-
 CERTIFICATE_VIOLATION_MODULES_FILENAME := $(PRODUCT_OUT)/certificate_violation_modules.txt
 $(CERTIFICATE_VIOLATION_MODULES_FILENAME):
 	rm -f $@
@@ -970,27 +926,12 @@ systemimage:
 
 # -----------------------------------------------------------------
 
-.PHONY: event-log-tags
-
-# Produce an event logs tag file for everything we know about, in order
-# to properly allocate numbers.  Then produce a file that's filtered
-# for what's going to be installed.
-
-all_event_log_tags_file := $(TARGET_OUT_COMMON_INTERMEDIATES)/all-event-log-tags.txt
-
 event_log_tags_file := $(TARGET_OUT)/etc/event-log-tags
 
 # Include tags from all packages that we know about
 all_event_log_tags_src := \
     $(sort $(foreach m, $(ALL_MODULES), $(ALL_MODULES.$(m).EVENT_LOG_TAGS)))
 
-$(all_event_log_tags_file): PRIVATE_SRC_FILES := $(all_event_log_tags_src)
-$(all_event_log_tags_file): $(all_event_log_tags_src) $(MERGETAGS) build/make/tools/event_log_tags.py
-	$(hide) mkdir -p $(dir $@)
-	$(hide) $(MERGETAGS) -o $@ $(PRIVATE_SRC_FILES)
-
-$(call declare-0p-target,$(all_event_log_tags_file))
-
 # Include tags from all packages included in this product, plus all
 # tags that are part of the system (ie, not in a vendor/ or device/
 # directory).
@@ -1002,13 +943,13 @@ event_log_tags_src := \
       $(filter-out vendor/% device/% out/%,$(all_event_log_tags_src)))
 
 $(event_log_tags_file): PRIVATE_SRC_FILES := $(event_log_tags_src)
-$(event_log_tags_file): PRIVATE_MERGED_FILE := $(all_event_log_tags_file)
-$(event_log_tags_file): $(event_log_tags_src) $(all_event_log_tags_file) $(MERGETAGS) build/make/tools/event_log_tags.py
+$(event_log_tags_file): $(event_log_tags_src) $(MERGETAGS)
 	$(hide) mkdir -p $(dir $@)
-	$(hide) $(MERGETAGS) -o $@ -m $(PRIVATE_MERGED_FILE) $(PRIVATE_SRC_FILES)
+	$(hide) $(MERGETAGS) -o $@ $(PRIVATE_SRC_FILES)
 
 $(eval $(call declare-0p-target,$(event_log_tags_file)))
 
+.PHONY: event-log-tags
 event-log-tags: $(event_log_tags_file)
 
 ALL_DEFAULT_INSTALLED_MODULES += $(event_log_tags_file)
@@ -1248,55 +1189,6 @@ endif
 endif # BOARD_PREBUILT_DTBOIMAGE_16KB
 
 
-ifneq ($(BOARD_KERNEL_PATH_16K),)
-BUILT_KERNEL_16K_TARGET := $(PRODUCT_OUT)/kernel_16k
-
-$(eval $(call copy-one-file,$(BOARD_KERNEL_PATH_16K),$(BUILT_KERNEL_16K_TARGET)))
-
-# Copies BOARD_KERNEL_PATH_16K to output directory as is
-kernel_16k: $(BUILT_KERNEL_16K_TARGET)
-.PHONY: kernel_16k
-
-BUILT_BOOTIMAGE_16K_TARGET := $(PRODUCT_OUT)/boot_16k.img
-
-BOARD_KERNEL_16K_BOOTIMAGE_PARTITION_SIZE := $(BOARD_BOOTIMAGE_PARTITION_SIZE)
-
-$(BUILT_BOOTIMAGE_16K_TARGET): $(MKBOOTIMG) $(AVBTOOL) $(INTERNAL_BOOTIMAGE_FILES) $(BOARD_AVB_BOOT_KEY_PATH) $(BUILT_KERNEL_16K_TARGET)
-	$(call pretty,"Target boot 16k image: $@")
-	$(call build_boot_from_kernel_avb_enabled,$@,$(BUILT_KERNEL_16K_TARGET))
-
-
-bootimage_16k: $(BUILT_BOOTIMAGE_16K_TARGET)
-.PHONY: bootimage_16k
-
-BUILT_BOOT_OTA_PACKAGE_16K := $(PRODUCT_OUT)/boot_ota_16k.zip
-$(BUILT_BOOT_OTA_PACKAGE_16K):  $(OTA_FROM_RAW_IMG) \
-                                $(BUILT_BOOTIMAGE_16K_TARGET) \
-                                $(INSTALLED_BOOTIMAGE_TARGET) \
-                                $(DEFAULT_SYSTEM_DEV_CERTIFICATE).pk8 \
-                                $(INSTALLED_DTBOIMAGE_16KB_TARGET) \
-                                $(INSTALLED_DTBOIMAGE_TARGET)
-	$(OTA_FROM_RAW_IMG) --package_key $(DEFAULT_SYSTEM_DEV_CERTIFICATE) \
-                      --max_timestamp `cat $(BUILD_DATETIME_FILE)` \
-                      --path $(HOST_OUT) \
-                      --partition_name $(if $(and $(INSTALLED_DTBOIMAGE_TARGET),\
-                          $(INSTALLED_DTBOIMAGE_16KB_TARGET)),\
-                        boot$(comma)dtbo,\
-                        boot) \
-                      --output $@ \
-                      $(if $(BOARD_16K_OTA_USE_INCREMENTAL),\
-                        $(INSTALLED_BOOTIMAGE_TARGET):$(BUILT_BOOTIMAGE_16K_TARGET),\
-                        $(BUILT_BOOTIMAGE_16K_TARGET)\
-                      )\
-                      $(if $(and $(INSTALLED_DTBOIMAGE_TARGET),$(INSTALLED_DTBOIMAGE_16KB_TARGET)),\
-                        $(INSTALLED_DTBOIMAGE_16KB_TARGET))
-
-boototapackage_16k: $(BUILT_BOOT_OTA_PACKAGE_16K)
-.PHONY: boototapackage_16k
-
-endif
-
-
 ramdisk_intermediates :=$= $(call intermediates-dir-for,PACKAGING,ramdisk)
 $(eval $(call write-partition-file-list,$(ramdisk_intermediates)/file_list.txt,$(TARGET_RAMDISK_OUT),$(INTERNAL_RAMDISK_FILES)))
 
@@ -1533,6 +1425,55 @@ endif # BOARD_PREBUILT_BOOTIMAGE
 endif # my_installed_prebuilt_gki_apex not defined
 
 ifneq ($(BOARD_KERNEL_PATH_16K),)
+
+BUILT_KERNEL_16K_TARGET := $(PRODUCT_OUT)/kernel_16k
+
+$(eval $(call copy-one-file,$(BOARD_KERNEL_PATH_16K),$(BUILT_KERNEL_16K_TARGET)))
+
+# Copies BOARD_KERNEL_PATH_16K to output directory as is
+kernel_16k: $(BUILT_KERNEL_16K_TARGET)
+.PHONY: kernel_16k
+
+BUILT_BOOTIMAGE_16K_TARGET := $(PRODUCT_OUT)/boot_16k.img
+
+BOARD_KERNEL_16K_BOOTIMAGE_PARTITION_SIZE := $(BOARD_BOOTIMAGE_PARTITION_SIZE)
+
+$(BUILT_BOOTIMAGE_16K_TARGET): $(MKBOOTIMG) $(AVBTOOL) $(INTERNAL_BOOTIMAGE_FILES) $(BOARD_AVB_BOOT_KEY_PATH) $(BUILT_KERNEL_16K_TARGET)
+	$(call pretty,"Target boot 16k image: $@")
+	$(call build_boot_from_kernel_avb_enabled,$@,$(BUILT_KERNEL_16K_TARGET))
+
+
+bootimage_16k: $(BUILT_BOOTIMAGE_16K_TARGET)
+.PHONY: bootimage_16k
+
+BUILT_BOOT_OTA_PACKAGE_16K := $(PRODUCT_OUT)/boot_ota_16k.zip
+$(BUILT_BOOT_OTA_PACKAGE_16K): PRIVATE_BOOTIMAGE_TARGET := $(INSTALLED_BOOTIMAGE_TARGET)
+$(BUILT_BOOT_OTA_PACKAGE_16K): PRIVATE_BOOTIMAGE_16KB_TARGET := $(BUILT_BOOTIMAGE_16K_TARGET)
+$(BUILT_BOOT_OTA_PACKAGE_16K):  $(OTA_FROM_RAW_IMG) \
+                                $(DEFAULT_SYSTEM_DEV_CERTIFICATE).pk8 \
+                                $(INSTALLED_BOOTIMAGE_TARGET) \
+                                $(BUILT_BOOTIMAGE_16K_TARGET) \
+                                $(INSTALLED_DTBOIMAGE_16KB_TARGET) \
+                                $(INSTALLED_DTBOIMAGE_TARGET)
+	$(OTA_FROM_RAW_IMG) --package_key $(DEFAULT_SYSTEM_DEV_CERTIFICATE) \
+                      --max_timestamp `cat $(BUILD_DATETIME_FILE)` \
+                      --path $(HOST_OUT) \
+                      --partition_name $(if $(and $(INSTALLED_DTBOIMAGE_TARGET),\
+                          $(INSTALLED_DTBOIMAGE_16KB_TARGET)),\
+                        boot$(comma)dtbo,\
+                        boot) \
+                      --output $@ \
+                      $(if $(BOARD_16K_OTA_USE_INCREMENTAL),\
+                        $(PRIVATE_BOOTIMAGE_TARGET):$(PRIVATE_BOOTIMAGE_16KB_TARGET),\
+                        $(PRIVATE_BOOTIMAGE_16KB_TARGET)\
+                      )\
+                      $(if $(and $(INSTALLED_DTBOIMAGE_TARGET),$(INSTALLED_DTBOIMAGE_16KB_TARGET)),\
+                        $(INSTALLED_DTBOIMAGE_16KB_TARGET))
+
+boototapackage_16k: $(BUILT_BOOT_OTA_PACKAGE_16K)
+.PHONY: boototapackage_16k
+
+
 BUILT_BOOT_OTA_PACKAGE_4K := $(PRODUCT_OUT)/boot_ota_4k.zip
 $(BUILT_BOOT_OTA_PACKAGE_4K): $(OTA_FROM_RAW_IMG) \
                               $(INSTALLED_BOOTIMAGE_TARGET) \
@@ -1561,11 +1502,26 @@ boototapackage_4k: $(BUILT_BOOT_OTA_PACKAGE_4K)
 ifeq ($(BOARD_16K_OTA_MOVE_VENDOR),true)
 $(eval $(call copy-one-file,$(BUILT_BOOT_OTA_PACKAGE_4K),$(TARGET_OUT_VENDOR)/boot_otas/boot_ota_4k.zip))
 $(eval $(call copy-one-file,$(BUILT_BOOT_OTA_PACKAGE_16K),$(TARGET_OUT_VENDOR)/boot_otas/boot_ota_16k.zip))
+
 ALL_DEFAULT_INSTALLED_MODULES += $(TARGET_OUT_VENDOR)/boot_otas/boot_ota_4k.zip
 ALL_DEFAULT_INSTALLED_MODULES += $(TARGET_OUT_VENDOR)/boot_otas/boot_ota_16k.zip
+
+ifneq ($(BOARD_VENDOR_KERNEL_MODULES_2ND_STAGE_16KB_MODE),)
+# Add the modules that need to be loaded in the Second Boot Stage
+# to /vendor_dlkm/lib/modules/16k-mode
+VENDOR_DLKM_16K_MODE_DIR := lib/modules/16k-mode
+$(foreach module,$(BOARD_VENDOR_KERNEL_MODULES_2ND_STAGE_16KB_MODE), \
+    $(eval $(call copy-one-file,$(TARGET_KERNEL_DIR_16K)/$(module),\
+                                $(TARGET_OUT_VENDOR_DLKM)/$(VENDOR_DLKM_16K_MODE_DIR)/$(module))))
+
+ALL_DEFAULT_INSTALLED_MODULES += $(foreach module,$(BOARD_VENDOR_KERNEL_MODULES_2ND_STAGE_16KB_MODE),\
+    $(TARGET_OUT_VENDOR_DLKM)/$(VENDOR_DLKM_16K_MODE_DIR)/$(module))
+endif # BOARD_VENDOR_KERNEL_MODULES_2ND_STAGE_16KB_MODE not empty
+
 else
 $(eval $(call copy-one-file,$(BUILT_BOOT_OTA_PACKAGE_4K),$(TARGET_OUT)/boot_otas/boot_ota_4k.zip))
 $(eval $(call copy-one-file,$(BUILT_BOOT_OTA_PACKAGE_16K),$(TARGET_OUT)/boot_otas/boot_ota_16k.zip))
+
 ALL_DEFAULT_INSTALLED_MODULES += $(TARGET_OUT)/boot_otas/boot_ota_4k.zip
 ALL_DEFAULT_INSTALLED_MODULES += $(TARGET_OUT)/boot_otas/boot_ota_16k.zip
 endif # BOARD_16K_OTA_MOVE_VENDOR == true
@@ -1822,6 +1778,7 @@ INTERNAL_VENDOR_KERNEL_RAMDISK_FILES := $(filter $(TARGET_VENDOR_KERNEL_RAMDISK_
 INTERNAL_VENDOR_KERNEL_RAMDISK_TARGET := $(call intermediates-dir-for,PACKAGING,vendor_kernel_boot)/vendor_kernel_ramdisk.cpio$(RAMDISK_EXT)
 
 $(INTERNAL_VENDOR_KERNEL_RAMDISK_TARGET): $(MKBOOTFS) $(INTERNAL_VENDOR_KERNEL_RAMDISK_FILES) | $(COMPRESSION_COMMAND_DEPS)
+	$(hide) : $(words $(INTERNAL_VENDOR_KERNEL_RAMDISK_FILES))
 	$(MKBOOTFS) -d $(TARGET_OUT) $(TARGET_VENDOR_KERNEL_RAMDISK_OUT) | $(COMPRESSION_COMMAND) > $@
 
 INSTALLED_VENDOR_KERNEL_RAMDISK_TARGET := $(PRODUCT_OUT)/vendor_kernel_ramdisk.img
@@ -1960,15 +1917,6 @@ kernel_notice_file := $(TARGET_OUT_NOTICE_FILES)/src/kernel.txt
 # need no associated notice file on the device UI.
 exclude_target_dirs := apex
 
-# TODO(b/69865032): Make PRODUCT_NOTICE_SPLIT the default behavior.
-ifneq ($(PRODUCT_NOTICE_SPLIT),true)
-#target_notice_file_html := $(TARGET_OUT_INTERMEDIATES)/NOTICE.html
-target_notice_file_html_gz := $(TARGET_OUT_INTERMEDIATES)/NOTICE.html.gz
-installed_notice_html_or_xml_gz := $(TARGET_OUT)/etc/NOTICE.html.gz
-
-$(call declare-0p-target,$(target_notice_file_html_gz))
-$(call declare-0p-target,$(installed_notice_html_or_xml_gz))
-else
 # target_notice_file_xml := $(TARGET_OUT_INTERMEDIATES)/NOTICE.xml
 target_notice_file_xml_gz := $(TARGET_OUT_INTERMEDIATES)/NOTICE.xml.gz
 installed_notice_html_or_xml_gz := $(TARGET_OUT)/etc/NOTICE.xml.gz
@@ -2002,7 +1950,7 @@ target_system_dlkm_notice_file_xml_gz := $(TARGET_OUT_INTERMEDIATES)/NOTICE_SYST
 installed_system_dlkm_notice_xml_gz := $(TARGET_OUT_SYSTEM_DLKM)/etc/NOTICE.xml.gz
 
 ALL_INSTALLED_NOTICE_FILES := \
-  $(if $(USE_SOONG_DEFINED_SYSTEM_IMAGE),,$(installed_notice_html_or_xml_gz)) \
+  $(installed_notice_html_or_xml_gz) \
   $(installed_vendor_notice_xml_gz) \
   $(installed_product_notice_xml_gz) \
   $(installed_system_ext_notice_xml_gz) \
@@ -2013,7 +1961,8 @@ ALL_INSTALLED_NOTICE_FILES := \
 
 # $1 installed file path, e.g. out/target/product/vsoc_x86_64/system_ext/etc/NOTICE.xml.gz
 define is-notice-file
-$(if $(findstring $1,$(ALL_INSTALLED_NOTICE_FILES)),Y)
+$(if $(filter true,$(PRODUCT_USE_SOONG_NOTICE_XML)),, \
+  $(if $(findstring $1,$(ALL_INSTALLED_NOTICE_FILES)),Y))
 endef
 
 # Notice files are copied to TARGET_OUT_NOTICE_FILES as a side-effect of their module
@@ -2087,11 +2036,7 @@ system_xml_directories := xml_system
 system_notice_file_message := "Notices for files contained in the system filesystem image in this directory:"
 endif
 
-endif # PRODUCT_NOTICE_SPLIT
-
-ifneq ($(USE_SOONG_DEFINED_SYSTEM_IMAGE),true)
 ALL_DEFAULT_INSTALLED_MODULES += $(installed_notice_html_or_xml_gz)
-endif
 
 need_vendor_notice:=false
 ifeq ($(BUILDING_VENDOR_BOOT_IMAGE),true)
@@ -2418,7 +2363,7 @@ $(if $(filter true,$(BOARD_USES_RECOVERY_AS_BOOT)),\
 $(hide) echo "root_dir=$(TARGET_ROOT_OUT)" >> $(1)
 $(if $(filter true,$(PRODUCT_USE_DYNAMIC_PARTITION_SIZE)),\
     $(hide) echo "use_dynamic_partition_size=true" >> $(1))
-$(if $(COPY_IMAGES_FOR_TARGET_FILES_ZIP),\
+$(if $(USE_FIXED_TIMESTAMP_IMG_FILES)$(COPY_IMAGES_FOR_TARGET_FILES_ZIP),\
     $(hide) echo "use_fixed_timestamp=true" >> $(1))
 $(if $(3),$(hide) $(foreach kv,$(3),echo "$(kv)" >> $(1);))
 $(hide) sort -o $(1) $(1)
@@ -2664,7 +2609,7 @@ ifndef TARGET_PRIVATE_RES_DIRS
 TARGET_PRIVATE_RES_DIRS := $(wildcard $(TARGET_DEVICE_DIR)/recovery/res)
 endif
 recovery_resource_deps := $(shell find $(recovery_resources_common) \
-  $(TARGET_PRIVATE_RES_DIRS) -type f)
+  $(TARGET_PRIVATE_RES_DIRS) -type f -not -name "*.bp")
 recovery_resource_deps += $(generated_recovery_text_files)
 
 
@@ -3519,18 +3464,20 @@ ifdef BUILDING_SYSTEM_IMAGE
 # Collect all available stub libraries installed in system and install with predefined linker configuration
 # Also append LLNDK libraries in the APEX as required libs
 SYSTEM_LINKER_CONFIG := $(TARGET_OUT)/etc/linker.config.pb
-SYSTEM_LINKER_CONFIG_SOURCE := $(call intermediates-dir-for,ETC,system_linker_config)/system_linker_config
+SYSTEM_LINKER_CONFIG_SOURCE := system/core/rootdir/etc/linker.config.json
 $(SYSTEM_LINKER_CONFIG): PRIVATE_SYSTEM_LINKER_CONFIG_SOURCE := $(SYSTEM_LINKER_CONFIG_SOURCE)
 $(SYSTEM_LINKER_CONFIG): $(INTERNAL_SYSTEMIMAGE_FILES) $(SYSTEM_LINKER_CONFIG_SOURCE) | conv_linker_config
 	@echo Creating linker config: $@
 	@mkdir -p $(dir $@)
-	@rm -f $@
-	$(HOST_OUT_EXECUTABLES)/conv_linker_config systemprovide --source $(PRIVATE_SYSTEM_LINKER_CONFIG_SOURCE) \
+	@rm -f $@ $@.step1
+	$(HOST_OUT_EXECUTABLES)/conv_linker_config proto --force -s $(PRIVATE_SYSTEM_LINKER_CONFIG_SOURCE) -o $@.step1
+	$(HOST_OUT_EXECUTABLES)/conv_linker_config systemprovide --source $@.step1 \
 		--output $@ --value "$(STUB_LIBRARIES)" --system "$(TARGET_OUT)"
 	$(HOST_OUT_EXECUTABLES)/conv_linker_config append --source $@ --output $@ --key requireLibs \
 		--value "$(foreach lib,$(LLNDK_MOVED_TO_APEX_LIBRARIES), $(lib).so)"
 	$(HOST_OUT_EXECUTABLES)/conv_linker_config append --source $@ --output $@ --key provideLibs \
 		--value "$(foreach lib,$(PRODUCT_EXTRA_STUB_LIBRARIES), $(lib).so)"
+	rm -f $@.step1
 
 $(call declare-1p-target,$(SYSTEM_LINKER_CONFIG),)
 $(call declare-license-deps,$(SYSTEM_LINKER_CONFIG),$(INTERNAL_SYSTEMIMAGE_FILES) $(SYSTEM_LINKER_CONFIG_SOURCE))
@@ -3618,9 +3565,8 @@ ifeq ($(USE_SOONG_DEFINED_SYSTEM_IMAGE),true)
 ifeq ($(PRODUCT_SOONG_DEFINED_SYSTEM_IMAGE),)
 $(error PRODUCT_SOONG_DEFINED_SYSTEM_IMAGE must be set if USE_SOONG_DEFINED_SYSTEM_IMAGE is true)
 endif
-SOONG_DEFINED_SYSTEM_IMAGE_PATH := $(call intermediates-dir-for,ETC,$(PRODUCT_SOONG_DEFINED_SYSTEM_IMAGE))/$(PRODUCT_SOONG_DEFINED_SYSTEM_IMAGE)
 SOONG_DEFINED_SYSTEM_IMAGE_BASE := $(dir $(ALL_MODULES.$(PRODUCT_SOONG_DEFINED_SYSTEM_IMAGE).FILESYSTEM_FILELIST))
-$(BUILT_SYSTEMIMAGE): $(INSTALLED_FILES_FILE) $(systemimage_intermediates)/file_list.txt $(SOONG_DEFINED_SYSTEM_IMAGE_PATH)
+$(BUILT_SYSTEMIMAGE): $(FULL_SYSTEMIMAGE_DEPS) $(INSTALLED_FILES_FILE) $(systemimage_intermediates)/file_list.txt $(SOONG_DEFINED_SYSTEM_IMAGE_PATH)
 $(eval $(call copy-one-file, $(SOONG_DEFINED_SYSTEM_IMAGE_PATH), $(BUILT_SYSTEMIMAGE)))
 else
 $(BUILT_SYSTEMIMAGE): $(FULL_SYSTEMIMAGE_DEPS) $(INSTALLED_FILES_FILE) $(systemimage_intermediates)/file_list.txt
@@ -4482,6 +4428,25 @@ INTERNAL_PVMFWIMAGE_FILES := $(call module-target-built-files,pvmfw_img)
 INTERNAL_PVMFW_EMBEDDED_AVBKEY := $(call module-target-built-files,pvmfw_embedded_key_pub_bin)
 INTERNAL_PVMFW_SYMBOL := $(TARGET_OUT_EXECUTABLES_UNSTRIPPED)/pvmfw
 
+# If pvmfw target is not available and there is a prebuilt available use prebuilt
+# NOTE: This is only a temporary feature for x86_64 and is not meant to be supported for long.
+# TODO(b/391333413): Don't allow use of pvmfw prebuilts as soon as it is possible
+ifeq ($(INTERNAL_PVMFWIMAGE_FILES),)
+ifneq ($(PRODUCT_PVMFW_IMAGE_PREBUILT),)
+INTERNAL_PVMFWIMAGE_FILES := $(call module-target-built-files,$(PRODUCT_PVMFW_IMAGE_PREBUILT))
+INTERNAL_PVMFW_SYMBOL :=
+
+ifneq ($(PRODUCT_PVMFW_BIN_PREBUILT),)
+INSTALLED_PVMFW_BINARY_TARGET := $(call module-target-built-files,$(PRODUCT_PVMFW_BIN_PREBUILT))
+endif # PRODUCT_PVMFW_BIN_PREBUILT
+
+ifneq ($(PRODUCT_PVMFW_EMBEDDED_AVBKEY_PREBUILT),)
+INTERNAL_PVMFW_EMBEDDED_AVBKEY := $(call module-target-built-files,$(PRODUCT_PVMFW_EMBEDDED_AVBKEY_PREBUILT))
+endif # PRODUCT_PVMFW_EMBEDDED_AVBKEY_PREBUILT
+
+endif # PRODUCT_PVMFW_IMAGE_PREBUILT
+endif # INTERNAL_PVMFWIMAGE_FILES
+
 $(call declare-1p-container,$(INSTALLED_PVMFWIMAGE_TARGET),)
 $(call declare-container-license-deps,$(INSTALLED_PVMFWIMAGE_TARGET),$(INTERNAL_PVMFWIMAGE_FILES),$(PRODUCT_OUT)/:/)
 
@@ -5052,6 +5017,10 @@ define build-chained-vbmeta-image
 	    $(foreach image,$(BOARD_AVB_$(call to-upper,$(1))), \
 	        --include_descriptors_from_image $(call images-for-partitions,$(image))) \
 	    --output $@
+      # libavb expects to be able to read the maximum vbmeta size, so we must provide a partition
+      # which matches this or the read will fail.
+      # See external/avb/libavb/avb_slot_verify.c#VBMETA_MAX_SIZE
+      truncate -s 65536 $@
 endef
 
 ifdef BUILDING_SYSTEM_IMAGE
@@ -5110,6 +5079,10 @@ define build-vbmetaimage-target
     $(PRIVATE_AVB_VBMETA_SIGNING_ARGS) \
     $(BOARD_AVB_MAKE_VBMETA_IMAGE_ARGS) \
     --output $@
+    # libavb expects to be able to read the maximum vbmeta size, so we must provide a partition
+    # which matches this or the read will fail.
+    # See external/avb/libavb/avb_slot_verify.c#VBMETA_MAX_SIZE
+    truncate -s 65536 $@
   $(hide) rm -rf $(AVB_CHAIN_KEY_DIR)
 endef
 
@@ -5177,8 +5150,7 @@ INTERNAL_ALLIMAGES_FILES := \
 # Run apex_sepolicy_tests for all installed APEXes
 
 ifeq (,$(TARGET_BUILD_UNBUNDLED))
-# TODO(b/353896817) apex_sepolicy_tests supports only ext4
-ifeq (ext4,$(PRODUCT_DEFAULT_APEX_PAYLOAD_TYPE))
+ifneq (,$(filter ext4 erofs,$(PRODUCT_DEFAULT_APEX_PAYLOAD_TYPE)))
 intermediate := $(call intermediates-dir-for,PACKAGING,apex_sepolicy_tests)
 apex_dirs := \
   $(TARGET_OUT)/apex/% \
@@ -5195,11 +5167,10 @@ apex_dirs :=
 define _run_apex_sepolicy_tests
 $2: $1 \
     $(HOST_OUT_EXECUTABLES)/apex_sepolicy_tests \
-    $(HOST_OUT_EXECUTABLES)/deapexer \
-    $(HOST_OUT_EXECUTABLES)/debugfs_static
+    $(HOST_OUT_EXECUTABLES)/apex-ls
 	@rm -rf $$@
 	@mkdir -p $(dir $$@)
-	$(HOST_OUT_EXECUTABLES)/apex_sepolicy_tests --all -f <($(HOST_OUT_EXECUTABLES)/deapexer --debugfs_path $(HOST_OUT_EXECUTABLES)/debugfs_static list -Z $$<)
+	$(HOST_OUT_EXECUTABLES)/apex_sepolicy_tests --all -f <($(HOST_OUT_EXECUTABLES)/apex-ls -Z $$<)
 	@touch $$@
 endef
 
@@ -5248,7 +5219,9 @@ APEX_INFO_FILE := $(APEX_OUT)/apex-info-list.xml
 # apexd_host scans/activates APEX files and writes /apex/apex-info-list.xml
 # Note that `@echo $(PRIVATE_APEX_FILES)` line is added to trigger the rule when the APEX list is changed.
 $(APEX_INFO_FILE): PRIVATE_APEX_FILES := $(apex_files)
-$(APEX_INFO_FILE): $(HOST_OUT_EXECUTABLES)/apexd_host $(apex_files)
+$(APEX_INFO_FILE): $(HOST_OUT_EXECUTABLES)/apexd_host \
+    $(HOST_OUT_EXECUTABLES)/deapexer $(HOST_OUT_EXECUTABLES)/debugfs $(HOST_OUT_EXECUTABLES)/fsck.erofs \
+    $(apex_files)
 	@echo "Extracting apexes..."
 	@echo $(PRIVATE_APEX_FILES) > /dev/null
 	@rm -rf $(APEX_OUT)
@@ -5363,7 +5336,7 @@ my_decompress_tools := \
     lz4:$(HOST_OUT_EXECUTABLES)/lz4 \
 
 
-# BOARD_KERNEL_CONFIG_FILE and BOARD_KERNEL_VERSION can be used to override the values extracted
+# BOARD_KERNEL_VERSION can be used to override the values extracted
 # from INSTALLED_KERNEL_TARGET.
 ifdef BOARD_KERNEL_VERSION
 $(BUILT_KERNEL_VERSION_FILE): PRIVATE_DECOMPRESS_TOOLS := $(my_decompress_tools)
@@ -5375,15 +5348,8 @@ $(BUILT_KERNEL_VERSION_FILE): $(EXTRACT_KERNEL) $(firstword $(INSTALLED_KERNEL_T
     echo "Specified kernel version '$(BOARD_KERNEL_VERSION)' does not match actual kernel version '$$KERNEL_RELEASE' " ; exit 1; fi;
 	echo '$(BOARD_KERNEL_VERSION)' > $@
 
-ifdef BOARD_KERNEL_CONFIG_FILE
-$(BUILT_KERNEL_CONFIGS_FILE): $(BOARD_KERNEL_CONFIG_FILE)
-	cp $< $@
-
-$(call declare-license-metadata,$(BUILT_KERNEL_CONFIGS_FILE),SPDX-license-identifier-GPL-2.0-only,restricted,$(BUILD_SYSTEM)/LINUX_KERNEL_COPYING,"Kernel",kernel)
 $(call declare-license-metadata,$(BUILT_KERNEL_VERSION_FILE),SPDX-license-identifier-GPL-2.0-only,restricted,$(BUILD_SYSTEM)/LINUX_KERNEL_COPYING,"Kernel",kernel)
 
-my_board_extracted_kernel := true
-endif # BOARD_KERNEL_CONFIG_FILE
 endif # BOARD_KERNEL_VERSION
 
 
@@ -5453,7 +5419,8 @@ ifeq (default,$(ENABLE_UFFD_GC))
 ifneq (,$(BUILT_KERNEL_VERSION_FILE))
 $(BUILT_KERNEL_VERSION_FILE_FOR_UFFD_GC): $(BUILT_KERNEL_VERSION_FILE)
 $(BUILT_KERNEL_VERSION_FILE_FOR_UFFD_GC):
-	cp $(BUILT_KERNEL_VERSION_FILE) $(BUILT_KERNEL_VERSION_FILE_FOR_UFFD_GC)
+	if ! cmp -s $(BUILT_KERNEL_VERSION_FILE) $@ ; then cp $(BUILT_KERNEL_VERSION_FILE) $@; fi
+.KATI_RESTAT: $(BUILT_KERNEL_VERSION_FILE_FOR_UFFD_GC)
 else
 # We make this a warning rather than an error to avoid breaking too many builds. When it happens,
 # we use a placeholder as the kernel version, which is consumed by uffd_gc_utils.py.
@@ -5662,7 +5629,9 @@ else
       endif
     endif # INSTALLED_BOOTIMAGE_TARGET == ""
     ifeq ($(recovery_fstab),)
-      build_ota_package := false
+      ifeq ($(filter $(TARGET_RECOVERY_ROOT_OUT)/system/etc/recovery.fstab,$(INTERNAL_RECOVERYIMAGE_FILES)),)
+        build_ota_package := false
+      endif
     endif
   endif # PRODUCT_BUILD_GENERIC_OTA_PACKAGE
 
@@ -5891,7 +5860,10 @@ endif
 endif # BOARD_AVB_ENABLE
 ifneq (,$(strip $(BOARD_CUSTOMIMAGES_PARTITION_LIST)))
 	$(hide) $(foreach partition,$(BOARD_CUSTOMIMAGES_PARTITION_LIST), \
-	  echo "flash $(partition)" >> $@;)
+		$(if $(BOARD_$(call to-upper,$(partition))_IMAGE_NO_FLASHALL),, \
+	      echo "flash $(partition)" >> $@; \
+		) \
+	)
 endif
 	$(hide) echo "reboot fastboot" >> $@
 	$(hide) echo "update-super" >> $@
@@ -6076,7 +6048,7 @@ ifneq (,$(strip $(BOARD_AVB_VBMETA_VENDOR)))
 	$(hide) echo "avb_vbmeta_vendor_rollback_index_location=$(BOARD_AVB_VBMETA_VENDOR_ROLLBACK_INDEX_LOCATION)" >> $@
 endif # BOARD_AVB_VBMETA_VENDOR_KEY_PATH
 ifneq (,$(strip $(BOARD_AVB_VBMETA_CUSTOM_PARTITIONS)))
-	$(hide) echo "avb_custom_vbmeta_images_partition_list=$(BOARD_AVB_VBMETA_CUSTOM_PARTITIONS)" >> $@
+	$(hide) echo "avb_custom_vbmeta_images_partition_list=$(sort $(BOARD_AVB_VBMETA_CUSTOM_PARTITIONS))" >> $@
 	$(hide) $(foreach partition,$(BOARD_AVB_VBMETA_CUSTOM_PARTITIONS),\
 	echo "avb_vbmeta_$(partition)=$(BOARD_AVB_VBMETA_$(call to-upper,$(partition)))" >> $@ ;\
 	echo "avb_vbmeta_$(partition)_args=$(BOARD_AVB_MAKE_VBMETA_$(call to-upper,$(partition))_IMAGE_ARGS)" >> $@ ;\
@@ -6147,9 +6119,7 @@ endif
 ifneq ($(BOARD_PARTIAL_OTA_UPDATE_PARTITIONS_LIST),)
 	$(hide) echo "partial_ota_update_partitions_list=$(BOARD_PARTIAL_OTA_UPDATE_PARTITIONS_LIST)" >> $@
 endif
-ifeq ($(BUILDING_WITH_VSDK),true)
-	$(hide) echo "building_with_vsdk=true" >> $@
-endif
+	$(hide) sort -o $@ $@
 
 $(call declare-0p-target,$(INSTALLED_FASTBOOT_INFO_TARGET))
 
@@ -6199,11 +6169,14 @@ endef
 
 built_ota_tools :=
 
+
 # We can't build static executables when SANITIZE_TARGET=address
 ifeq (,$(filter address, $(SANITIZE_TARGET)))
+ifeq (false,$(AB_OTA_UPDATER))
 built_ota_tools += \
     $(call intermediates-dir-for,EXECUTABLES,updater)/updater
 endif
+endif
 
 $(BUILT_TARGET_FILES_DIR): PRIVATE_OTA_TOOLS := $(built_ota_tools)
 
@@ -6304,13 +6277,13 @@ define dump-dynamic-partitions-info
   $(foreach device,$(BOARD_SUPER_PARTITION_BLOCK_DEVICES), \
     echo "super_$(device)_device_size=$(BOARD_SUPER_PARTITION_$(call to-upper,$(device))_DEVICE_SIZE)" >> $(1);)
   $(if $(BOARD_SUPER_PARTITION_PARTITION_LIST), \
-    echo "dynamic_partition_list=$(call filter-out-missing-partitions,$(BOARD_SUPER_PARTITION_PARTITION_LIST))" >> $(1))
+    echo "dynamic_partition_list=$(sort $(call filter-out-missing-partitions,$(BOARD_SUPER_PARTITION_PARTITION_LIST)))" >> $(1))
   $(if $(BOARD_SUPER_PARTITION_GROUPS),
     echo "super_partition_groups=$(BOARD_SUPER_PARTITION_GROUPS)" >> $(1))
   $(foreach group,$(BOARD_SUPER_PARTITION_GROUPS), \
     echo "super_$(group)_group_size=$(BOARD_$(call to-upper,$(group))_SIZE)" >> $(1); \
     $(if $(BOARD_$(call to-upper,$(group))_PARTITION_LIST), \
-      echo "super_$(group)_partition_list=$(call filter-out-missing-partitions,$(BOARD_$(call to-upper,$(group))_PARTITION_LIST))" >> $(1);))
+      echo "super_$(group)_partition_list=$(strip $(call filter-out-missing-partitions,$(BOARD_$(call to-upper,$(group))_PARTITION_LIST)))" >> $(1);))
   $(if $(filter true,$(TARGET_USERIMAGES_SPARSE_EXT_DISABLED)), \
     echo "build_non_sparse_super_partition=true" >> $(1))
   $(if $(filter true,$(TARGET_USERIMAGES_SPARSE_F2FS_DISABLED)), \
@@ -6678,7 +6651,7 @@ ifdef BUILDING_SYSTEM_IMAGE
 	@# Contents of the system image
 ifneq ($(SOONG_DEFINED_SYSTEM_IMAGE_PATH),)
 	$(hide) $(call package_files-copy-root, \
-	    $(SOONG_DEFINED_SYSTEM_IMAGE_BASE)/root/system,$(zip_root)/SYSTEM)
+	    $(SOONG_DEFINED_SYSTEM_IMAGE_BASE)/system/system,$(zip_root)/SYSTEM)
 else
 	$(hide) $(call package_files-copy-root, \
 	    $(SYSTEMIMAGE_SOURCE_DIR),$(zip_root)/SYSTEM)
@@ -7181,22 +7154,6 @@ $(APPCOMPAT_ZIP): $(SOONG_ZIP)
 	$(hide) find $(PRODUCT_OUT)/appcompat | sort >$(PRIVATE_LIST_FILE)
 	$(hide) $(SOONG_ZIP) -d -o $@ -C $(PRODUCT_OUT)/appcompat -l $(PRIVATE_LIST_FILE)
 
-# The mac build doesn't build dex2oat, so create the zip file only if the build OS is linux.
-ifeq ($(BUILD_OS),linux)
-ifneq ($(DEX2OAT),)
-dexpreopt_tools_deps := $(DEXPREOPT_GEN_DEPS) $(DEXPREOPT_GEN)
-dexpreopt_tools_deps += $(HOST_OUT_EXECUTABLES)/dexdump
-dexpreopt_tools_deps += $(HOST_OUT_EXECUTABLES)/oatdump
-DEXPREOPT_TOOLS_ZIP := $(PRODUCT_OUT)/dexpreopt_tools.zip
-$(DEXPREOPT_TOOLS_ZIP): $(dexpreopt_tools_deps)
-$(DEXPREOPT_TOOLS_ZIP): PRIVATE_DEXPREOPT_TOOLS_DEPS := $(dexpreopt_tools_deps)
-$(DEXPREOPT_TOOLS_ZIP): $(SOONG_ZIP)
-	$(hide) mkdir -p $(dir $@)
-	$(hide) $(SOONG_ZIP) -d -o $@ -j $(addprefix -f ,$(PRIVATE_DEXPREOPT_TOOLS_DEPS)) -f $$(realpath $(DEX2OAT))
-$(call declare-1p-target,$(DEXPREOPT_TOOLS_ZIP),)
-endif # DEX2OAT is set
-endif # BUILD_OS == linux
-
 DEXPREOPT_CONFIG_ZIP := $(PRODUCT_OUT)/dexpreopt_config.zip
 
 $(DEXPREOPT_CONFIG_ZIP): $(INSTALLED_SYSTEMIMAGE_TARGET) \
@@ -7229,6 +7186,12 @@ dexpreopt_config_zip: $(DEXPREOPT_CONFIG_ZIP)
 
 $(call declare-1p-target,$(DEXPREOPT_CONFIG_ZIP),)
 
+# -----------------------------------------------------------------
+# Zips of the symbols directory per test suites
+#
+
+$(foreach suite,$(ALL_COMPATIBILITY_SUITES),$(eval $(call create-suite-symbols-map,$(suite))))
+
 # -----------------------------------------------------------------
 # A zip of the symbols directory.  Keep the full paths to make it
 # more obvious where these files came from.
@@ -7247,29 +7210,37 @@ SYMBOLS_ZIP := $(PRODUCT_OUT)/$(name)-symbols.zip
 # The path to a file containing mappings from elf IDs to filenames.
 SYMBOLS_MAPPING := $(PRODUCT_OUT)/$(name)-symbols-mapping.textproto
 .KATI_READONLY := SYMBOLS_ZIP SYMBOLS_MAPPING
-# For apps_only build we'll establish the dependency later in build/make/core/main.mk.
+
 ifeq (,$(TARGET_BUILD_UNBUNDLED))
-$(SYMBOLS_ZIP): $(INTERNAL_ALLIMAGES_FILES) $(updater_dep)
+  _symbols_zip_modules := $(call product-installed-modules,$(INTERNAL_PRODUCT))
+  $(SYMBOLS_ZIP): $(updater_dep)
+else
+  _symbols_zip_modules := $(unbundled_build_modules)
 endif
-$(SYMBOLS_ZIP): PRIVATE_LIST_FILE := $(call intermediates-dir-for,PACKAGING,symbols)/filelist
-$(SYMBOLS_ZIP): PRIVATE_MAPPING_PACKAGING_DIR := $(call intermediates-dir-for,PACKAGING,elf_symbol_mapping)
-$(SYMBOLS_ZIP): $(SOONG_ZIP) $(SYMBOLS_MAP)
+
+_symbols_zip_modules_symbols_files := $(foreach m,$(_symbols_zip_modules),$(ALL_MODULES.$(m).SYMBOLIC_OUTPUT_PATH))
+_symbols_zip_modules_mapping_files := $(foreach m,$(_symbols_zip_modules),$(ALL_MODULES.$(m).ELF_SYMBOL_MAPPING_PATH))
+
+$(SYMBOLS_ZIP): PRIVATE_SYMBOLS_MODULES_FILES := $(_symbols_zip_modules_symbols_files)
+$(SYMBOLS_ZIP): PRIVATE_SYMBOLS_MODULES_MAPPING_FILES := $(_symbols_zip_modules_mapping_files)
+$(SYMBOLS_ZIP): $(SOONG_ZIP) $(SYMBOLS_MAP) $(_symbols_zip_modules_symbols_files) $(_symbols_zip_modules_mapping_files)
 	@echo "Package symbols: $@"
-	$(hide) rm -rf $@ $(PRIVATE_LIST_FILE)
-	$(hide) mkdir -p $(TARGET_OUT_UNSTRIPPED) $(dir $(PRIVATE_LIST_FILE)) $(PRIVATE_MAPPING_PACKAGING_DIR)
-	# Find all of the files in the symbols directory and zip them into the symbols zip.
-	$(hide) find -L $(TARGET_OUT_UNSTRIPPED) -type f | sort >$(PRIVATE_LIST_FILE)
-	$(hide) $(SOONG_ZIP) --ignore_missing_files -d -o $@ -C $(OUT_DIR)/.. -l $(PRIVATE_LIST_FILE)
-	# Find all of the files in the symbols mapping directory and merge them into the symbols mapping textproto.
-	$(hide) find -L $(PRIVATE_MAPPING_PACKAGING_DIR) -type f | sort >$(PRIVATE_LIST_FILE)
-	$(hide) $(SYMBOLS_MAP) -merge $(SYMBOLS_MAPPING) -ignore_missing_files @$(PRIVATE_LIST_FILE)
+	$(hide) rm -rf $@ $@.symbols_list $@.mapping_list
+	# Find all installed files in the symbols directory and zip them into the symbols zip.
+	echo "$(PRIVATE_SYMBOLS_MODULES_FILES)" | tr " " "\n" | sort > $@.symbols_list
+	$(hide) $(SOONG_ZIP) -d -o $@ -l $@.symbols_list
+	# Find all installed files in the symbols mapping directory and merge them into the symbols mapping textproto.
+	echo "$(PRIVATE_SYMBOLS_MODULES_MAPPING_FILES)" | tr " " "\n" | sort > $@.mapping_list
+	$(hide) $(SYMBOLS_MAP) -merge $(SYMBOLS_MAPPING) @$@.mapping_list
 $(SYMBOLS_ZIP): .KATI_IMPLICIT_OUTPUTS := $(SYMBOLS_MAPPING)
 
 $(call declare-1p-container,$(SYMBOLS_ZIP),)
 ifeq (,$(TARGET_BUILD_UNBUNDLED))
-$(call declare-container-license-deps,$(SYMBOLS_ZIP),$(INTERNAL_ALLIMAGES_FILES) $(updater_dep),$(PRODUCT_OUT)/:/)
+$(call declare-container-license-deps,$(SYMBOLS_ZIP),$(PRIVATE_SYMBOLS_MODULES_FILES) $(updater_dep),$(PRODUCT_OUT)/:/)
 endif
 
+_symbols_zip_modules_symbols_files :=
+_symbols_zip_modules_mapping_files :=
 # -----------------------------------------------------------------
 # A zip of the coverage directory.
 #
@@ -7312,29 +7283,6 @@ ifeq (true,$(CLANG_COVERAGE))
   $(call dist-for-goals,droidcore-unbundled apps_only,$(LLVM_COVERAGE_TOOLS_ZIP))
 endif
 
-# -----------------------------------------------------------------
-# A zip of the Android Apps. Not keeping full path so that we don't
-# include product names when distributing
-#
-name := $(TARGET_PRODUCT)
-ifeq ($(TARGET_BUILD_TYPE),debug)
-  name := $(name)_debug
-endif
-name := $(name)-apps
-
-APPS_ZIP := $(PRODUCT_OUT)/$(name).zip
-$(APPS_ZIP): $(FULL_SYSTEMIMAGE_DEPS)
-	@echo "Package apps: $@"
-	$(hide) rm -rf $@
-	$(hide) mkdir -p $(dir $@)
-	$(hide) apps_to_zip=`find $(TARGET_OUT_APPS) $(TARGET_OUT_APPS_PRIVILEGED) -mindepth 2 -maxdepth 3 -name "*.apk"`; \
-	if [ -z "$$apps_to_zip" ]; then \
-	    echo "No apps to zip up. Generating empty apps archive." ; \
-	    a=$$(mktemp /tmp/XXXXXXX) && touch $$a && zip $@ $$a && zip -d $@ $$a; \
-	else \
-	    zip -qjX $@ $$apps_to_zip; \
-	fi
-
 ifeq (true,$(EMMA_INSTRUMENT))
 #------------------------------------------------------------------
 # An archive of classes for use in generating code-coverage reports
@@ -7384,6 +7332,72 @@ else
   _proguard_dict_zip_modules := $(unbundled_build_modules)
 endif
 
+# Filter out list to avoid uncessary proguard related file generation
+ifeq (,$(TARGET_BUILD_UNBUNDLED))
+filter_out_proguard_dict_zip_modules :=
+# product.img
+ifndef BUILDING_PRODUCT_IMAGE
+filter_out_proguard_dict_zip_modules += $(PRODUCT_OUT)/product/%
+endif
+# system.img
+ifndef BUILDING_SYSTEM_IMAGE
+filter_out_proguard_dict_zip_modules += $(PRODUCT_OUT)/system/%
+endif
+# system_dlkm.img
+ifndef BUILDING_SYSTEM_DLKM_IMAGE
+filter_out_proguard_dict_zip_modules += $(PRODUCT_OUT)/system_dlkm/%
+endif
+# system_ext.img
+ifndef BUILDING_SYSTEM_EXT_IMAGE
+filter_out_proguard_dict_zip_modules += $(PRODUCT_OUT)/system_ext/%
+endif
+# system_other.img
+ifndef BUILDING_SYSTEM_OTHER_IMAGE
+filter_out_proguard_dict_zip_modules += $(PRODUCT_OUT)/system_other/%
+endif
+# odm.img
+ifndef BUILDING_ODM_IMAGE
+filter_out_proguard_dict_zip_modules += $(PRODUCT_OUT)/odm/%
+endif
+# odm_dlkm.img
+ifndef BUILDING_ODM_DLKM_IMAGE
+filter_out_proguard_dict_zip_modules += $(PRODUCT_OUT)/odm_dlkm/%
+endif
+# vendor.img
+ifndef BUILDING_VENDOR_IMAGE
+filter_out_proguard_dict_zip_modules += $(PRODUCT_OUT)/vendor/%
+endif
+# vendor_dlkm.img
+ifndef BUILDING_VENDOR_DLKM_IMAGE
+filter_out_proguard_dict_zip_modules += $(PRODUCT_OUT)/vendor_dlkm/%
+endif
+# cache.img
+ifndef BUILDING_CACHE_IMAGE
+filter_out_proguard_dict_zip_modules += $(PRODUCT_OUT)/cache/%
+endif
+# ramdisk.img
+ifndef BUILDING_RAMDISK_IMAGE
+filter_out_proguard_dict_zip_modules += $(PRODUCT_OUT)/ramdisk/%
+endif
+# recovery.img
+ifndef INSTALLED_RECOVERYIMAGE_TARGET
+filter_out_proguard_dict_zip_modules += $(PRODUCT_OUT)/recovery/%
+endif
+# userdata.img
+ifndef BUILDING_USERDATA_IMAGE
+filter_out_proguard_dict_zip_modules += $(PRODUCT_OUT)/data/%
+endif
+
+# Check the installed files of each module and return the module name
+# or return empty if none of the files remain to be installed
+define filter-out-proguard-modules
+$(if $(filter-out $(filter_out_proguard_dict_zip_modules),$(call module-installed-files,$(1))),$(1))
+endef
+
+# Filter out proguard dict zip modules those are not installed at the built image
+_proguard_dict_zip_modules := $(foreach m,$(_proguard_dict_zip_modules),$(strip $(call filter-out-proguard-modules,$(m))))
+endif
+
 # The path to the zip file containing proguard dictionaries.
 PROGUARD_DICT_ZIP :=$= $(PRODUCT_OUT)/$(TARGET_PRODUCT)-proguard-dict.zip
 $(PROGUARD_DICT_ZIP): PRIVATE_SOONG_ZIP_ARGUMENTS := $(foreach m,$(_proguard_dict_zip_modules),$(ALL_MODULES.$(m).PROGUARD_DICTIONARY_SOONG_ZIP_ARGUMENTS))
@@ -7589,6 +7603,12 @@ $(INTERNAL_UPDATE_PACKAGE_TARGET): $(BUILT_TARGET_FILES_PACKAGE) $(IMG_FROM_TARG
 	PATH=$(INTERNAL_USERIMAGES_BINARY_PATHS):$(dir $(ZIP2ZIP)):$$PATH \
 	    $(IMG_FROM_TARGET_FILES) \
 	        --additional IMAGES/VerifiedBootParams.textproto:VerifiedBootParams.textproto \
+			$(foreach partition,$(BOARD_CUSTOMIMAGES_PARTITION_LIST), \
+					$(if $(BOARD_$(call to-upper,$(partition))_IMAGE_NO_FLASHALL), \
+						--exclude IMAGES/$(partition).img \
+						--exclude IMAGES/$(partition).map \
+					) \
+			) \
 	        --build_super_image $(BUILD_SUPER_IMAGE) \
 	        $(BUILT_TARGET_FILES_PACKAGE) $@
 
@@ -7865,6 +7885,7 @@ $(INTERNAL_SDK_TARGET): $(deps)
 	        -I $(HOST_OUT) \
 	        -I $(TARGET_COMMON_OUT_ROOT) \
 	        -v "PLATFORM_NAME=$(PRIVATE_PLATFORM_NAME)" \
+	        -v "PLATFORM_SDK_API_VERSION=$(PLATFORM_SDK_VERSION_FULL)" \
 	        -v "OUT_DIR=$(OUT_DIR)" \
 	        -v "HOST_OUT=$(HOST_OUT)" \
 	        -v "TARGET_ARCH=$(TARGET_ARCH)" \
@@ -7975,6 +7996,18 @@ IMAGES := $(INSTALLED_BOOTIMAGE_TARGET) \
 	$(INSTALLED_VBMETAIMAGE_TARGET) \
 	$(INSTALLED_USERDATAIMAGE_TARGET)
 
+# -----------------------------------------------------------------
+# Desktop generated firmware filesystem.
+TARGET_PRODUCT_FW_IMAGE_PACKAGE := prebuilt-$(TARGET_PRODUCT)-firmware-image
+GENERATED_FW_IMAGE := $(PRODUCT_OUT)/product/etc/$(TARGET_PRODUCT)-firmware.img
+
+generated_fw_image_found := $(strip $(foreach pp,$(PRODUCT_PACKAGES),\
+	$(if $(findstring $(TARGET_PRODUCT_FW_IMAGE_PACKAGE),$(pp)),$(pp))))
+
+ifneq (,$(generated_fw_image_found))
+$(call dist-for-goals,dist_files,$(GENERATED_FW_IMAGE))
+endif
+
 # -----------------------------------------------------------------
 # Desktop pack image hook.
 ifneq (,$(strip $(PACK_DESKTOP_FILESYSTEM_IMAGES)))
@@ -8067,6 +8100,46 @@ pack-migration-image: $(PACK_MIGRATION_IMAGE_TARGET)
 
 endif # ANDROID_DESKTOP_MIGRATION_IMAGE
 
+ifdef SOONG_ONLY_ALL_IMAGES_ZIP
+
+allimages_soong_zip_args :=
+allimages_deps :=
+
+define include_image
+$(if $(1), \
+  $(eval allimages_soong_zip_args += -e $(notdir $(1)) -f $(1)) \
+  $(eval allimages_deps += $(1)))
+endef
+
+$(call include_image,$(INSTALLED_SUPERIMAGE_TARGET))
+$(call include_image,$(INSTALLED_BOOTIMAGE_TARGET))
+$(call include_image,$(INSTALLED_INIT_BOOT_IMAGE_TARGET))
+$(call include_image,$(INSTALLED_VENDOR_BOOTIMAGE_TARGET))
+$(call include_image,$(INSTALLED_USERDATAIMAGE_TARGET))
+$(call include_image,$(INSTALLED_RECOVERYIMAGE_TARGET))
+$(call include_image,$(INSTALLED_VBMETAIMAGE_TARGET))
+$(call include_image,$(INSTALLED_VBMETA_SYSTEMIMAGE_TARGET))
+$(call include_image,$(INSTALLED_VBMETA_VENDORIMAGE_TARGET))
+$(foreach partition,$(call to-upper,$(BOARD_AVB_VBMETA_CUSTOM_PARTITIONS)), \
+  $(call include_image,$(INSTALLED_VBMETA_$(partition)IMAGE_TARGET)))
+
+allimages_zip := $(PRODUCT_OUT)/all_images.zip
+$(allimages_zip): PRIVATE_SOONG_ZIP_ARGUMENTS := $(allimages_soong_zip_args)
+$(allimages_zip): $(SOONG_ZIP) $(allimages_deps)
+	$(SOONG_ZIP) -o $@ $(PRIVATE_SOONG_ZIP_ARGUMENTS)
+
+.PHONY: soong_only_diff_test
+soong_only_diff_test: PRIVATE_ALLIMAGES_ZIP := $(allimages_zip)
+soong_only_diff_test: $(allimages_zip) $(SOONG_ONLY_ALL_IMAGES_ZIP)
+	diff $(PRIVATE_ALLIMAGES_ZIP) $(SOONG_ONLY_ALL_IMAGES_ZIP)
+
+allimages_soong_zip_args :=
+allimages_deps :=
+allimages_zip :=
+include_image :=
+
+endif # ifdef SOONG_ONLY_ALL_IMAGES_ZIP
+
 # -----------------------------------------------------------------
 # OS Licensing
 
diff --git a/core/OWNERS b/core/OWNERS
index 35ea83d2fe..d8aa2372c1 100644
--- a/core/OWNERS
+++ b/core/OWNERS
@@ -9,5 +9,5 @@ per-file version_defaults.mk = ankurbakshi@google.com,bkhalife@google.com,jainne
 per-file version_defaults.mk = amhk@google.com,gurpreetgs@google.com,mkhokhlova@google.com,robertogil@google.com
 
 # For Ravenwood test configs
-per-file ravenwood_test_config_template.xml = jsharkey@google.com,omakoto@google.com
+per-file ravenwood_test_config_template.xml =omakoto@google.com
 
diff --git a/core/android_soong_config_vars.mk b/core/android_soong_config_vars.mk
index 44e2398ae1..59b6467b47 100644
--- a/core/android_soong_config_vars.mk
+++ b/core/android_soong_config_vars.mk
@@ -39,9 +39,16 @@ $(call soong_config_set_bool,ANDROID,RELEASE_BOARD_API_LEVEL_FROZEN,$(RELEASE_BO
 $(call add_soong_config_var,ANDROID,TARGET_DYNAMIC_64_32_DRMSERVER)
 $(call add_soong_config_var,ANDROID,TARGET_ENABLE_MEDIADRM_64)
 $(call add_soong_config_var,ANDROID,TARGET_DYNAMIC_64_32_MEDIASERVER)
+$(call soong_config_set_bool,ANDROID,TARGET_SUPPORTS_32_BIT_APPS,$(if $(filter true,$(TARGET_SUPPORTS_32_BIT_APPS)),true,false))
+$(call soong_config_set_bool,ANDROID,TARGET_SUPPORTS_64_BIT_APPS,$(if $(filter true,$(TARGET_SUPPORTS_64_BIT_APPS)),true,false))
 $(call add_soong_config_var,ANDROID,BOARD_GENFS_LABELS_VERSION)
+$(call soong_config_set_bool,ANDROID,PRODUCT_FSVERITY_GENERATE_METADATA,$(if $(filter true,$(PRODUCT_FSVERITY_GENERATE_METADATA)),true,false))
 
 $(call add_soong_config_var,ANDROID,ADDITIONAL_M4DEFS,$(if $(BOARD_SEPOLICY_M4DEFS),$(addprefix -D,$(BOARD_SEPOLICY_M4DEFS))))
+$(call add_soong_config_var,ANDROID,TARGET_ADD_ROOT_EXTRA_VENDOR_SYMLINKS)
+
+# For BUILDING_GSI
+$(call soong_config_set_bool,gsi,building_gsi,$(if $(filter true,$(BUILDING_GSI)),true,false))
 
 # For bootable/recovery
 RECOVERY_API_VERSION := 3
@@ -78,9 +85,11 @@ endif
 $(call soong_config_set_bool,art_module,art_build_host_debug,$(if $(filter false,$(ART_BUILD_HOST_DEBUG)),false,true))
 
 # For chre
-$(call soong_config_set_bool,chre,chre_daemon_lama_enabled,$(if $(filter true,$(CHRE_DAEMON_LPMA_ENABLED)),true,false))
+$(call soong_config_set_bool,chre,chre_daemon_lpma_enabled,$(if $(filter true,$(CHRE_DAEMON_LPMA_ENABLED)),true,false))
 $(call soong_config_set_bool,chre,chre_dedicated_transport_channel_enabled,$(if $(filter true,$(CHRE_DEDICATED_TRANSPORT_CHANNEL_ENABLED)),true,false))
 $(call soong_config_set_bool,chre,chre_log_atom_extension_enabled,$(if $(filter true,$(CHRE_LOG_ATOM_EXTENSION_ENABLED)),true,false))
+$(call soong_config_set_bool,chre,building_vendor_image,$(if $(filter true,$(BUILDING_VENDOR_IMAGE)),true,false))
+$(call soong_config_set_bool,chre,chre_usf_daemon_enabled,$(if $(filter true,$(CHRE_USF_DAEMON_ENABLED)),true,false))
 
 ifdef TARGET_BOARD_AUTO
   $(call add_soong_config_var_value, ANDROID, target_board_auto, $(TARGET_BOARD_AUTO))
@@ -123,12 +132,10 @@ ifdef TARGET_BOOTS_16K
 $(call soong_config_set_bool,ANDROID,target_boots_16k,$(filter true,$(TARGET_BOOTS_16K)))
 endif
 
-ifdef PRODUCT_MEMCG_V2_FORCE_ENABLED
-$(call add_soong_config_var_value,ANDROID,memcg_v2_force_enabled,$(PRODUCT_MEMCG_V2_FORCE_ENABLED))
-endif
-
 ifdef PRODUCT_CGROUP_V2_SYS_APP_ISOLATION_ENABLED
 $(call add_soong_config_var_value,ANDROID,cgroup_v2_sys_app_isolation,$(PRODUCT_CGROUP_V2_SYS_APP_ISOLATION_ENABLED))
+else
+$(call add_soong_config_var_value,ANDROID,cgroup_v2_sys_app_isolation,true)
 endif
 
 $(call add_soong_config_var_value,ANDROID,release_avf_allow_preinstalled_apps,$(RELEASE_AVF_ALLOW_PREINSTALLED_APPS))
@@ -150,8 +157,6 @@ $(call add_soong_config_var_value,ANDROID,release_binder_death_recipient_weak_fr
 
 $(call add_soong_config_var_value,ANDROID,release_libpower_no_lock_binder_txn,$(RELEASE_LIBPOWER_NO_LOCK_BINDER_TXN))
 
-$(call add_soong_config_var_value,ANDROID,release_package_libandroid_runtime_punch_holes,$(RELEASE_PACKAGE_LIBANDROID_RUNTIME_PUNCH_HOLES))
-
 $(call add_soong_config_var_value,ANDROID,release_selinux_data_data_ignore,$(RELEASE_SELINUX_DATA_DATA_IGNORE))
 ifneq (,$(filter eng userdebug,$(TARGET_BUILD_VARIANT)))
     # write appcompat system properties on userdebug and eng builds
@@ -169,6 +174,7 @@ ifeq (true,$(PRODUCT_BROKEN_SUBOPTIMAL_ORDER_OF_SYSTEM_SERVER_JARS))
 else ifneq (platform:services,$(lastword $(PRODUCT_SYSTEM_SERVER_JARS)))
   # If services is not the final jar in the dependency ordering, don't assume
   # it can be safely optimized in isolation, as there may be dependent jars.
+  # TODO(b/212737576): Remove this exception after integrating use of `$(system_server_trace_refs)`.
   SYSTEM_OPTIMIZE_JAVA ?= false
 else
   SYSTEM_OPTIMIZE_JAVA ?= true
@@ -181,6 +187,20 @@ endif
 $(call add_soong_config_var,ANDROID,SYSTEM_OPTIMIZE_JAVA)
 $(call add_soong_config_var,ANDROID,FULL_SYSTEM_OPTIMIZE_JAVA)
 
+ifeq (true, $(SYSTEM_OPTIMIZE_JAVA))
+  # Create a list of (non-prefixed) system server jars that follow `services` in
+  # the classpath. This can be used when optimizing `services` to trace any
+  # downstream references that need keeping.
+  # Example: "foo:service1 platform:services bar:services2" -> "services2"
+  system_server_jars_dependent_on_services := $(shell \
+      echo "$(PRODUCT_SYSTEM_SERVER_JARS)" | \
+      awk '{found=0; for(i=1;i<=NF;i++){if($$i=="platform:services"){found=1; continue} if(found){split($$i,a,":"); print a[2]}}}' | \
+      xargs)
+  ifneq ($(strip $(system_server_jars_dependent_on_services)),)
+    $(call soong_config_set_string_list,ANDROID,system_server_trace_refs,$(system_server_jars_dependent_on_services))
+  endif
+endif
+
 # TODO(b/319697968): Remove this build flag support when metalava fully supports flagged api
 $(call soong_config_set,ANDROID,release_hidden_api_exportable_stubs,$(RELEASE_HIDDEN_API_EXPORTABLE_STUBS))
 
@@ -191,6 +211,14 @@ else
 $(call add_soong_config_var_value,ANDROID,include_nonpublic_framework_api,true)
 endif
 
+# Add nfc build flag to soong
+ifneq ($(RELEASE_PACKAGE_NFC_STACK),NfcNci)
+  $(call soong_config_set,bootclasspath,nfc_apex_bootclasspath_fragment,true)
+endif
+
+# Add uwb build flag to soong
+$(call soong_config_set,bootclasspath,release_ranging_stack,$(RELEASE_RANGING_STACK))
+
 # Add crashrecovery build flag to soong
 $(call soong_config_set,ANDROID,release_crashrecovery_module,$(RELEASE_CRASHRECOVERY_MODULE))
 # Add crashrecovery file move flags to soong, for both platform and module
@@ -232,6 +260,9 @@ endif
 $(call soong_config_set,ANDROID,release_package_profiling_module,$(RELEASE_PACKAGE_PROFILING_MODULE))
 $(call soong_config_set,bootclasspath,release_package_profiling_module,$(RELEASE_PACKAGE_PROFILING_MODULE))
 
+# Move VCN from platform to the Tethering module; used by both platform and module
+$(call soong_config_set,ANDROID,is_vcn_in_mainline,$(RELEASE_MOVE_VCN_TO_MAINLINE))
+
 # Add perf-setup build flag to soong
 # Note: BOARD_PERFSETUP_SCRIPT location must be under platform_testing/scripts/perf-setup/.
 ifdef BOARD_PERFSETUP_SCRIPT
@@ -302,3 +333,46 @@ $(call soong_config_set_bool,fs_config,system_dlkm,$(if $(BOARD_USES_SYSTEM_DLKM
 $(call soong_config_set_bool,telephony,sec_cp_secure_boot,$(if $(filter true,$(SEC_CP_SECURE_BOOT)),true,false))
 $(call soong_config_set_bool,telephony,cbd_protocol_sit,$(if $(filter true,$(CBD_PROTOCOL_SIT)),true,false))
 $(call soong_config_set_bool,telephony,use_radioexternal_hal_aidl,$(if $(filter true,$(USE_RADIOEXTERNAL_HAL_AIDL)),true,false))
+
+# Variables for hwcomposer.$(TARGET_BOARD_PLATFORM)
+$(call soong_config_set_bool,google_graphics,board_uses_hwc_services,$(if $(filter true,$(BOARD_USES_HWC_SERVICES)),true,false))
+
+# Variables for controlling android.hardware.composer.hwc3-service.pixel
+$(call soong_config_set,google_graphics,board_hwc_version,$(BOARD_HWC_VERSION))
+
+# Flag ExcludeExtractApk is to support "extract_apk" property for the following conditions.
+ifneq ($(WITH_DEXPREOPT),true)
+  $(call soong_config_set_bool,PrebuiltGmsCore,ExcludeExtractApk,true)
+endif
+ifeq ($(DONT_DEXPREOPT_PREBUILTS),true)
+  $(call soong_config_set_bool,PrebuiltGmsCore,ExcludeExtractApk,true)
+endif
+ifeq ($(WITH_DEXPREOPT_BOOT_IMG_AND_SYSTEM_SERVER_ONLY),true)
+  $(call soong_config_set_bool,PrebuiltGmsCore,ExcludeExtractApk,true)
+endif
+
+# Variables for extra branches
+# TODO(b/383238397): Use bootstrap_go_package to enable extra flags.
+-include vendor/google/build/extra_soong_config_vars.mk
+
+# Variable for CI test packages
+ifneq ($(filter arm x86 true,$(TARGET_ARCH) $(TARGET_2ND_ARCH) $(TARGET_ENABLE_MEDIADRM_64)),)
+  $(call soong_config_set_bool,ci_tests,uses_widevine_tests, true)
+endif
+
+# Flags used in GTVS prebuilt apps
+$(call soong_config_set_bool,GTVS,GTVS_COMPRESSED_PREBUILTS,$(if $(findstring $(GTVS_COMPRESSED_PREBUILTS),true yes),true,false))
+$(call soong_config_set_bool,GTVS,GTVS_GMSCORE_BETA,$(if $(findstring $(GTVS_GMSCORE_BETA),true yes),true,false))
+$(call soong_config_set_bool,GTVS,GTVS_SETUPWRAITH_BETA,$(if $(findstring $(GTVS_SETUPWRAITH_BETA),true yes),true,false))
+$(call soong_config_set_bool,GTVS,PRODUCT_USE_PREBUILT_GTVS,$(if $(findstring $(PRODUCT_USE_PREBUILT_GTVS),true yes),true,false))
+
+# Flags used in GTVS_GTV prebuilt apps
+$(call soong_config_set_bool,GTVS_GTV,PRODUCT_USE_PREBUILT_GTVS_GTV,$(if $(findstring $(PRODUCT_USE_PREBUILT_GTVS_GTV),true yes),true,false))
+
+# Check modules to be built in "otatools-package".
+ifneq ($(wildcard vendor/google/tools/build_mixed_kernels_ramdisk),)
+  $(call soong_config_set_bool,otatools,use_build_mixed_kernels_ramdisk,true)
+endif
+ifneq ($(wildcard bootable/deprecated-ota/applypatch),)
+  $(call soong_config_set_bool,otatools,use_bootable_deprecated_ota_applypatch,true)
+endif
diff --git a/core/base_rules.mk b/core/base_rules.mk
index 5363e0fbf9..604fe06667 100644
--- a/core/base_rules.mk
+++ b/core/base_rules.mk
@@ -214,6 +214,22 @@ else
   actual_partition_tag := $(if $(partition_tag),data,system)
 endif
 endif
+
+# if this is a soong module, verify that LOCAL_COMPATIBILITY_SUITE (legacy) matches
+# LOCAL_SOONG_PROVIDER_TEST_SUITES (new, via TestSuiteInfoProvider instead of AndroidMk stuff),
+# modulo "null-sute", "mts", and "mcts". mts/mcts are automatically added if there's a different
+# suite starting with "m(c)ts-". null-suite seems useless and is sometimes automatically added
+# if no other suites are added.
+ifneq (,$(filter $(LOCAL_MODULE_MAKEFILE),$(SOONG_ANDROID_MK)))
+  a := $(filter-out null-suite mts mcts,$(sort $(LOCAL_COMPATIBILITY_SUITE)))
+  b := $(filter-out null-suite mts mcts,$(sort $(LOCAL_SOONG_PROVIDER_TEST_SUITES)))
+  ifneq ($(a),$(b))
+    $(error $(LOCAL_MODULE): LOCAL_COMPATIBILITY_SUITE did not match LOCAL_SOONG_PROVIDER_TEST_SUITES$(newline)  LOCAL_COMPATIBILITY_SUITE: $(a)$(newline)  LOCAL_SOONG_PROVIDER_TEST_SUITES: $(b)$(newline))
+  endif
+  a :=
+  b :=
+endif
+
 # For test modules that lack a suite tag, set null-suite as the default.
 # We only support adding a default suite to native tests, native benchmarks, and instrumentation tests.
 # This is because they are the only tests we currently auto-generate test configs for.
@@ -861,13 +877,6 @@ else
       $(eval my_compat_dist_config_$(suite) += $(foreach dir, $(call compatibility_suite_dirs,$(suite)), \
         $(LOCAL_PATH)/DynamicConfig.xml:$(dir)/$(LOCAL_MODULE).dynamic)))
   endif
-
-  ifneq (,$(wildcard $(LOCAL_PATH)/$(LOCAL_MODULE)_*.config))
-  $(foreach extra_config, $(wildcard $(LOCAL_PATH)/$(LOCAL_MODULE)_*.config), \
-    $(foreach suite, $(LOCAL_COMPATIBILITY_SUITE), \
-      $(eval my_compat_dist_config_$(suite) += $(foreach dir, $(call compatibility_suite_dirs,$(suite)), \
-        $(extra_config):$(dir)/$(notdir $(extra_config))))))
-  endif
 endif # $(my_prefix)$(LOCAL_MODULE_CLASS)_$(LOCAL_MODULE)_compat_files
 
 
@@ -938,12 +947,6 @@ else
     my_supported_variant := DEVICE
   endif
 endif
-###########################################################
-## Add test module to ALL_DISABLED_PRESUBMIT_TESTS if LOCAL_PRESUBMIT_DISABLED is set to true.
-###########################################################
-ifeq ($(LOCAL_PRESUBMIT_DISABLED),true)
-  ALL_DISABLED_PRESUBMIT_TESTS += $(LOCAL_MODULE)
-endif  # LOCAL_PRESUBMIT_DISABLED
 
 ###########################################################
 ## Register with ALL_MODULES
diff --git a/core/board_config.mk b/core/board_config.mk
index 859a6b2984..cf01c8416c 100644
--- a/core/board_config.mk
+++ b/core/board_config.mk
@@ -290,9 +290,10 @@ $(foreach var,$(_board_true_false_vars), \
     $(error Valid values of $(var) are "true", "false", and "". Not "$($(var))")))
 
 include $(BUILD_SYSTEM)/board_config_wifi.mk
-include $(BUILD_SYSTEM)/board_config_wpa_supplicant.mk
+-include external/wpa_supplicant_8/board_config_wpa_supplicant.mk
 
 # Set up soong config for "soong_config_value_variable".
+-include hardware/interfaces/configstore/1.1/default/surfaceflinger.mk
 -include vendor/google/build/soong/soong_config_namespace/camera.mk
 
 # Default *_CPU_VARIANT_RUNTIME to CPU_VARIANT if unspecified.
diff --git a/core/board_config_wpa_supplicant.mk b/core/board_config_wpa_supplicant.mk
deleted file mode 100644
index 9ef438e794..0000000000
--- a/core/board_config_wpa_supplicant.mk
+++ /dev/null
@@ -1,88 +0,0 @@
-#
-# Copyright (C) 2024 The Android Open Source Project
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#      http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-#
-
-# ###############################################################
-# This file adds wpa_supplicant_8 variables into soong config namespace (`wpa_supplicant_8`)
-# ###############################################################
-
-ifdef BOARD_HOSTAPD_DRIVER
-$(call soong_config_set_bool,wpa_supplicant_8,wpa_build_hostapd,true)
-ifneq ($(BOARD_HOSTAPD_DRIVER),NL80211)
-    $(error BOARD_HOSTAPD_DRIVER set to $(BOARD_HOSTAPD_DRIVER) but current soong expected it should be NL80211 only!)
-endif
-endif
-
-ifdef BOARD_WPA_SUPPLICANT_DRIVER
-ifneq ($(BOARD_WPA_SUPPLICANT_DRIVER),NL80211)
-    $(error BOARD_WPA_SUPPLICANT_DRIVER set to $(BOARD_WPA_SUPPLICANT_DRIVER) but current soong expected it should be NL80211 only!)
-endif
-endif
-
-# This is for CONFIG_DRIVER_NL80211_BRCM, CONFIG_DRIVER_NL80211_SYNA, CONFIG_DRIVER_NL80211_QCA
-# And it is only used for a cflags setting in driver.
-$(call soong_config_set,wpa_supplicant_8,board_wlan_device,$(BOARD_WLAN_DEVICE))
-
-# Belong to CONFIG_IEEE80211AX definition
-ifeq ($(WIFI_FEATURE_HOSTAPD_11AX),true)
-$(call soong_config_set_bool,wpa_supplicant_8,hostapd_11ax,true)
-endif
-
-# Belong to CONFIG_IEEE80211BE definition
-ifeq ($(WIFI_FEATURE_HOSTAPD_11BE),true)
-$(call soong_config_set_bool,wpa_supplicant_8,hostapd_11be,true)
-endif
-
-# PLATFORM_VERSION
-$(call soong_config_set,wpa_supplicant_8,platform_version,$(PLATFORM_VERSION))
-
-# BOARD_HOSTAPD_PRIVATE_LIB
-ifeq ($(BOARD_HOSTAPD_PRIVATE_LIB),)
-$(call soong_config_set_bool,wpa_supplicant_8,hostapd_use_stub_lib,true)
-else
-$(call soong_config_set,wpa_supplicant_8,board_hostapd_private_lib,$(BOARD_HOSTAPD_PRIVATE_LIB))
-endif
-
-ifeq ($(BOARD_HOSTAPD_CONFIG_80211W_MFP_OPTIONAL),true)
-$(call soong_config_set_bool,wpa_supplicant_8,board_hostapd_config_80211w_mfp_optional,true)
-endif
-
-ifneq ($(BOARD_HOSTAPD_PRIVATE_LIB_EVENT),)
-$(call soong_config_set_bool,wpa_supplicant_8,board_hostapd_private_lib_event,true)
-endif
-
-# BOARD_WPA_SUPPLICANT_PRIVATE_LIB
-ifeq ($(BOARD_WPA_SUPPLICANT_PRIVATE_LIB),)
-$(call soong_config_set_bool,wpa_supplicant_8,wpa_supplicant_use_stub_lib,true)
-else
-$(call soong_config_set,wpa_supplicant_8,board_wpa_supplicant_private_lib,$(BOARD_WPA_SUPPLICANT_PRIVATE_LIB))
-endif
-
-ifneq ($(BOARD_WPA_SUPPLICANT_PRIVATE_LIB_EVENT),)
-$(call soong_config_set_bool,wpa_supplicant_8,board_wpa_supplicant_private_lib_event,true)
-endif
-
-ifeq ($(WIFI_PRIV_CMD_UPDATE_MBO_CELL_STATUS), enabled)
-$(call soong_config_set_bool,wpa_supplicant_8,wifi_priv_cmd_update_mbo_cell_status,true)
-endif
-
-ifeq ($(WIFI_HIDL_UNIFIED_SUPPLICANT_SERVICE_RC_ENTRY), true)
-$(call soong_config_set_bool,wpa_supplicant_8,wifi_hidl_unified_supplicant_service_rc_entry,true)
-endif
-
-# New added in internal main
-ifeq ($(WIFI_BRCM_OPEN_SOURCE_MULTI_AKM), enabled)
-$(call soong_config_set_bool,wpa_supplicant_8,wifi_brcm_open_source_multi_akm,true)
-endif
diff --git a/core/build_id.mk b/core/build_id.mk
index 8ad16633ae..9067611279 100644
--- a/core/build_id.mk
+++ b/core/build_id.mk
@@ -18,4 +18,4 @@
 # (like "CRB01").  It must be a single word, and is
 # capitalized by convention.
 
-BUILD_ID=BP1A.250505.005.D1
+BUILD_ID=BP2A.250605.031.A2
diff --git a/core/clear_vars.mk b/core/clear_vars.mk
index fed19e6d45..8a98c13b1d 100644
--- a/core/clear_vars.mk
+++ b/core/clear_vars.mk
@@ -204,7 +204,6 @@ LOCAL_PREBUILT_OBJ_FILES:=
 LOCAL_PREBUILT_STATIC_JAVA_LIBRARIES:=
 LOCAL_USE_EMBEDDED_DEX:=
 LOCAL_USE_EMBEDDED_NATIVE_LIBS:=
-LOCAL_PRESUBMIT_DISABLED:=
 LOCAL_PRIVATE_PLATFORM_APIS:=
 LOCAL_PRIVILEGED_MODULE:=
 LOCAL_PROC_MACRO_LIBRARIES:=
@@ -272,6 +271,7 @@ LOCAL_SOONG_MODULE_INFO_JSON :=
 LOCAL_SOONG_MODULE_TYPE :=
 LOCAL_SOONG_PROGUARD_DICT :=
 LOCAL_SOONG_PROGUARD_USAGE_ZIP :=
+LOCAL_SOONG_PROVIDER_TEST_SUITES :=
 LOCAL_SOONG_RESOURCE_EXPORT_PACKAGE :=
 LOCAL_SOONG_TRANSITIVE_RES_PACKAGES :=
 LOCAL_SOONG_DEVICE_RRO_DIRS :=
diff --git a/core/tasks/mke2fs-dist.mk b/core/combo/arch/arm64/armv9-3a.mk
similarity index 53%
rename from core/tasks/mke2fs-dist.mk
rename to core/combo/arch/arm64/armv9-3a.mk
index 3540c1f985..0f2c620eeb 100644
--- a/core/tasks/mke2fs-dist.mk
+++ b/core/combo/arch/arm64/armv9-3a.mk
@@ -1,4 +1,5 @@
-# Copyright (C) 2024 Google Inc.
+#
+# Copyright (C) 2025 The Android Open Source Project
 #
 # Licensed under the Apache License, Version 2.0 (the "License");
 # you may not use this file except in compliance with the License.
@@ -11,12 +12,7 @@
 # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 # See the License for the specific language governing permissions and
 # limitations under the License.
+#
 
-# TODO: After Soong's recovery partition variation can be set to selectable
-#       and the meta_lic file duplication issue is resolved, move it to the
-#       dist section of the corresponding module's Android.bp.
-my_dist_files := $(HOST_OUT_EXECUTABLES)/mke2fs
-my_dist_files += $(HOST_OUT_EXECUTABLES)/make_f2fs
-my_dist_files += $(HOST_OUT_EXECUTABLES)/make_f2fs_casefold
-$(call dist-for-goals,dist_files sdk,$(my_dist_files))
-my_dist_files :=
+# .mk file required to support build for the ARMv9.3-A arch variant.
+# The file just needs to be present, it does not need to contain anything.
diff --git a/core/combo/arch/arm64/armv9-4a.mk b/core/combo/arch/arm64/armv9-4a.mk
new file mode 100644
index 0000000000..6ab3bed875
--- /dev/null
+++ b/core/combo/arch/arm64/armv9-4a.mk
@@ -0,0 +1,18 @@
+#
+# Copyright (C) 2025 The Android Open Source Project
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
+#
+
+# .mk file required to support build for the ARMv9.4-A arch variant.
+# The file just needs to be present, it does not need to contain anything.
diff --git a/core/config.mk b/core/config.mk
index d62b86dda5..38f3f5b802 100644
--- a/core/config.mk
+++ b/core/config.mk
@@ -330,6 +330,19 @@ $(eval SOONG_CONFIG_$(strip $1)_$(strip $2):=$(filter true,$3))
 $(eval SOONG_CONFIG_TYPE_$(strip $1)_$(strip $2):=bool)
 endef
 
+# soong_config_set_int is the same as soong_config_set, but it will
+# also type the variable as an integer, so that when using select() expressions
+# in blueprint files they can use integer values instead of strings.
+# It will error out if a non-integer is supplied
+# $1 is the namespace. $2 is the variable name. $3 is the variable value.
+# Ex: $(call soong_config_set_bool,acme,COOL_FEATURE,34)
+define soong_config_set_int
+$(call soong_config_define_internal,$1,$2) \
+$(if $(call math_is_int,$3),,$(error soong_config_set_int called with non-integer value $(3)))
+$(eval SOONG_CONFIG_$(strip $1)_$(strip $2):=$(strip $3))
+$(eval SOONG_CONFIG_TYPE_$(strip $1)_$(strip $2):=int)
+endef
+
 # soong_config_set_string_list is the same as soong_config_set, but it will
 # also type the variable as a list of strings, so that when using select() expressions
 # in blueprint files they can use list values instead of strings.
@@ -598,10 +611,7 @@ DISABLE_PREOPT :=
 DISABLE_PREOPT_BOOT_IMAGES :=
 ifneq (,$(TARGET_BUILD_APPS)$(TARGET_BUILD_UNBUNDLED_IMAGE))
   DISABLE_PREOPT := true
-  # VSDK builds perform dexpreopt during merge_target_files build step.
-  ifneq (true,$(BUILDING_WITH_VSDK))
-    DISABLE_PREOPT_BOOT_IMAGES := true
-  endif
+  DISABLE_PREOPT_BOOT_IMAGES := true
 endif
 ifeq (true,$(TARGET_BUILD_UNBUNDLED))
   ifneq (true,$(UNBUNDLED_BUILD_SDKS_FROM_SOURCE))
@@ -730,8 +740,8 @@ SYMBOLS_MAP := $(HOST_OUT_EXECUTABLES)/symbols_map
 PROGUARD_HOME := external/proguard
 PROGUARD := $(PROGUARD_HOME)/bin/proguard.sh
 PROGUARD_DEPS := $(PROGUARD) $(PROGUARD_HOME)/lib/proguard.jar
-JAVATAGS := build/make/tools/java-event-log-tags.py
-MERGETAGS := build/make/tools/merge-event-log-tags.py
+JAVATAGS := $(HOST_OUT_EXECUTABLES)/java-event-log-tags
+MERGETAGS := $(HOST_OUT_EXECUTABLES)/merge-event-log-tags
 APPEND2SIMG := $(HOST_OUT_EXECUTABLES)/append2simg
 VERITY_SIGNER := $(HOST_OUT_EXECUTABLES)/verity_signer
 BUILD_VERITY_METADATA := $(HOST_OUT_EXECUTABLES)/build_verity_metadata
@@ -763,50 +773,21 @@ endif
 .KATI_READONLY := \
     PRODUCT_COMPATIBLE_PROPERTY
 
-# Boolean variable determining if Treble is fully enabled
-PRODUCT_FULL_TREBLE := false
-ifneq ($(PRODUCT_FULL_TREBLE_OVERRIDE),)
-  PRODUCT_FULL_TREBLE := $(PRODUCT_FULL_TREBLE_OVERRIDE)
-else ifeq ($(PRODUCT_SHIPPING_API_LEVEL),)
-  #$(warning no product shipping level defined)
-else ifneq ($(call math_gt_or_eq,$(PRODUCT_SHIPPING_API_LEVEL),26),)
-  PRODUCT_FULL_TREBLE := true
-endif
-
-requirements := \
-    PRODUCT_TREBLE_LINKER_NAMESPACES \
-    PRODUCT_ENFORCE_VINTF_MANIFEST
-
-# If it is overriden, then the requirement override is taken, otherwise it's
-# PRODUCT_FULL_TREBLE
-$(foreach req,$(requirements),$(eval \
-    $(req) := $(if $($(req)_OVERRIDE),$($(req)_OVERRIDE),$(PRODUCT_FULL_TREBLE))))
-# If the requirement is false for any reason, then it's not PRODUCT_FULL_TREBLE
-$(foreach req,$(requirements),$(eval \
-    PRODUCT_FULL_TREBLE := $(if $(filter false,$($(req))),false,$(PRODUCT_FULL_TREBLE))))
-
-PRODUCT_FULL_TREBLE_OVERRIDE ?=
-$(foreach req,$(requirements),$(eval $(req)_OVERRIDE ?=))
-
-# used to be a part of PRODUCT_FULL_TREBLE, but now always set it
-PRODUCT_NOTICE_SPLIT := true
+# TODO: remove all code referencing these, and remove override variables
+PRODUCT_FULL_TREBLE := true
+PRODUCT_TREBLE_LINKER_NAMESPACES := true
+PRODUCT_ENFORCE_VINTF_MANIFEST := true
 
 # TODO(b/114488870): disallow PRODUCT_FULL_TREBLE_OVERRIDE from being used.
 .KATI_READONLY := \
-    PRODUCT_FULL_TREBLE_OVERRIDE \
-    $(foreach req,$(requirements),$(req)_OVERRIDE) \
-    $(requirements) \
     PRODUCT_FULL_TREBLE \
-    PRODUCT_NOTICE_SPLIT \
-
-ifneq ($(PRODUCT_FULL_TREBLE),true)
-    $(warning This device does not have Treble enabled. This is unsafe.)
-endif
-
-$(KATI_obsolete_var $(foreach req,$(requirements),$(req)_OVERRIDE) \
-    ,This should be referenced without the _OVERRIDE suffix.)
+    PRODUCT_TREBLE_LINKER_NAMESPACES \
+    PRODUCT_ENFORCE_VINTF_MANIFEST \
 
-requirements :=
+# TODO(b/114488870): remove all sets of these everwhere, and disallow them to be used
+$(KATI_obsolete_var PRODUCT_TREBLE_LINKER_NAMESPACES_OVERRIDE,Deprecated.)
+$(KATI_obsolete_var PRODUCT_ENFORCE_VINTF_MANIFEST_OVERRIDE,Deprecated.)
+$(KATI_obsolete_var PRODUCT_FULL_TREBLE_OVERRIDE,Deprecated.)
 
 # BOARD_PROPERTY_OVERRIDES_SPLIT_ENABLED can be true only if early-mount of
 # partitions is supported. But the early-mount must be supported for full
@@ -892,15 +873,18 @@ BOARD_SEPOLICY_VERS := $(PLATFORM_SEPOLICY_VERSION)
 .KATI_READONLY := PLATFORM_SEPOLICY_VERSION BOARD_SEPOLICY_VERS
 
 # A list of SEPolicy versions, besides PLATFORM_SEPOLICY_VERSION, that the framework supports.
-PLATFORM_SEPOLICY_COMPAT_VERSIONS := $(filter-out $(PLATFORM_SEPOLICY_VERSION), \
+PLATFORM_SEPOLICY_COMPAT_VERSIONS := \
     29.0 \
     30.0 \
     31.0 \
     32.0 \
     33.0 \
     34.0 \
+
+PLATFORM_SEPOLICY_COMPAT_VERSIONS += $(foreach ver,\
     202404 \
-    )
+    202504 \
+    ,$(if $(filter true,$(call math_gt,$(PLATFORM_SEPOLICY_VERSION),$(ver))),$(ver)))
 
 .KATI_READONLY := \
     PLATFORM_SEPOLICY_COMPAT_VERSIONS \
@@ -1333,3 +1317,58 @@ ifeq (false,$(SYSTEM_OPTIMIZE_JAVA))
 $(error SYSTEM_OPTIMIZE_JAVA must be enabled when FULL_SYSTEM_OPTIMIZE_JAVA is enabled)
 endif
 endif
+
+# -----------------------------------------------------------------
+# Define fingerprint, thumbprint, and version tags for the current build
+#
+# BUILD_VERSION_TAGS is a comma-separated list of tags chosen by the device
+# implementer that further distinguishes the build. It's basically defined
+# by the device implementer. Here, we are adding a mandatory tag that
+# identifies the signing config of the build.
+BUILD_VERSION_TAGS := $(BUILD_VERSION_TAGS)
+ifeq ($(TARGET_BUILD_TYPE),debug)
+  BUILD_VERSION_TAGS += debug
+endif
+# The "test-keys" tag marks builds signed with the old test keys,
+# which are available in the SDK.  "dev-keys" marks builds signed with
+# non-default dev keys (usually private keys from a vendor directory).
+# Both of these tags will be removed and replaced with "release-keys"
+# when the target-files is signed in a post-build step.
+ifeq ($(DEFAULT_SYSTEM_DEV_CERTIFICATE),build/make/target/product/security/testkey)
+BUILD_KEYS := test-keys
+else
+BUILD_KEYS := dev-keys
+endif
+BUILD_VERSION_TAGS += $(BUILD_KEYS)
+BUILD_VERSION_TAGS := $(subst $(space),$(comma),$(sort $(BUILD_VERSION_TAGS)))
+
+# BUILD_FINGERPRINT is used used to uniquely identify the combined build and
+# product; used by the OTA server.
+ifeq (,$(strip $(BUILD_FINGERPRINT)))
+  BUILD_FINGERPRINT := $(PRODUCT_BRAND)/$(TARGET_PRODUCT)/$(TARGET_DEVICE):$(PLATFORM_VERSION)/$(BUILD_ID)/$(BUILD_NUMBER_FROM_FILE):$(TARGET_BUILD_VARIANT)/$(BUILD_VERSION_TAGS)
+endif
+
+BUILD_FINGERPRINT_FILE := $(PRODUCT_OUT)/build_fingerprint.txt
+ifneq (,$(shell mkdir -p $(PRODUCT_OUT) && echo $(BUILD_FINGERPRINT) >$(BUILD_FINGERPRINT_FILE).tmp && (if ! cmp -s $(BUILD_FINGERPRINT_FILE).tmp $(BUILD_FINGERPRINT_FILE); then mv $(BUILD_FINGERPRINT_FILE).tmp $(BUILD_FINGERPRINT_FILE); else rm $(BUILD_FINGERPRINT_FILE).tmp; fi) && grep " " $(BUILD_FINGERPRINT_FILE)))
+  $(error BUILD_FINGERPRINT cannot contain spaces: "$(file <$(BUILD_FINGERPRINT_FILE))")
+endif
+BUILD_FINGERPRINT_FROM_FILE := $$(cat $(BUILD_FINGERPRINT_FILE))
+# unset it for safety.
+BUILD_FINGERPRINT :=
+
+# BUILD_THUMBPRINT is used to uniquely identify the system build; used by the
+# OTA server. This purposefully excludes any product-specific variables.
+ifeq (,$(strip $(BUILD_THUMBPRINT)))
+  BUILD_THUMBPRINT := $(PLATFORM_VERSION)/$(BUILD_ID)/$(BUILD_NUMBER_FROM_FILE):$(TARGET_BUILD_VARIANT)/$(BUILD_VERSION_TAGS)
+endif
+
+BUILD_THUMBPRINT_FILE := $(PRODUCT_OUT)/build_thumbprint.txt
+ifeq ($(strip $(HAS_BUILD_NUMBER)),true)
+$(BUILD_THUMBPRINT_FILE): $(BUILD_NUMBER_FILE)
+endif
+ifneq (,$(shell mkdir -p $(PRODUCT_OUT) && echo $(BUILD_THUMBPRINT) >$(BUILD_THUMBPRINT_FILE) && grep " " $(BUILD_THUMBPRINT_FILE)))
+  $(error BUILD_THUMBPRINT cannot contain spaces: "$(file <$(BUILD_THUMBPRINT_FILE))")
+endif
+# unset it for safety.
+BUILD_THUMBPRINT_FILE :=
+BUILD_THUMBPRINT :=
diff --git a/core/config_sanitizers.mk b/core/config_sanitizers.mk
index ab2d5c1ddf..c0f2c6893f 100644
--- a/core/config_sanitizers.mk
+++ b/core/config_sanitizers.mk
@@ -284,9 +284,9 @@ endif
 ifneq ($(filter memtag_stack,$(my_sanitize)),)
   my_cflags += -fsanitize=memtag-stack
   my_ldflags += -fsanitize=memtag-stack
-  my_cflags += -march=armv8a+memtag
-  my_ldflags += -march=armv8a+memtag
-  my_asflags += -march=armv8a+memtag
+  my_cflags += -Xclang -target-feature -Xclang +mte
+  my_ldflags += -Xclang -target-feature -Xclang +mte
+  my_asflags += -Xclang -target-feature -Xclang +mte
   my_sanitize := $(filter-out memtag_stack,$(my_sanitize))
 endif
 
diff --git a/core/cxx_stl_setup.mk b/core/cxx_stl_setup.mk
index 0d557c7d36..5e8ca7f643 100644
--- a/core/cxx_stl_setup.mk
+++ b/core/cxx_stl_setup.mk
@@ -78,7 +78,7 @@ ifneq ($(filter $(my_cxx_stl),libc++ libc++_static),)
         my_static_libraries += libc++demangle
 
         ifeq ($(my_link_type),static)
-            my_static_libraries += libm libc libunwind
+            my_static_libraries += libm libc libunwind libstatic_rustlibs_for_make
         endif
     endif
 else ifeq ($(my_cxx_stl),ndk)
diff --git a/core/definitions.mk b/core/definitions.mk
index adb35e07ca..ea151fac37 100644
--- a/core/definitions.mk
+++ b/core/definitions.mk
@@ -90,9 +90,6 @@ ALL_INIT_RC_INSTALLED_PAIRS :=
 # All installed vintf manifest fragments for a partition at
 ALL_VINTF_MANIFEST_FRAGMENTS_LIST:=
 
-# All tests that should be skipped in presubmit check.
-ALL_DISABLED_PRESUBMIT_TESTS :=
-
 # All compatibility suites mentioned in LOCAL_COMPATIBILITY_SUITE
 ALL_COMPATIBILITY_SUITES :=
 
@@ -838,18 +835,6 @@ $(strip \
 )
 endef
 
-###########################################################
-## Declare that non-module targets copied from project $(1) and
-## optionally ending in $(2) are non-copyrightable files.
-##
-## e.g. an information-only file merely listing other files.
-###########################################################
-define declare-0p-copy-files
-$(strip \
-  $(foreach _pair,$(filter $(1)%$(2),$(PRODUCT_COPY_FILES)),$(eval $(call declare-0p-target,$(PRODUCT_OUT)/$(call word-colon,2,$(_pair))))) \
-)
-endef
-
 ###########################################################
 ## Declare non-module target $(1) to have a first-party license
 ## (Android Apache 2.0)
@@ -1555,7 +1540,7 @@ endef
 define transform-logtags-to-java
 @mkdir -p $(dir $@)
 @echo "logtags: $@ <= $<"
-$(hide) $(JAVATAGS) -o $@ $< $(PRIVATE_MERGED_TAG)
+$(hide) $(JAVATAGS) -o $@ $<
 endef
 
 
@@ -3286,7 +3271,7 @@ $(check_non_elf_file_timestamp): $(1) $(LLVM_READOBJ)
 	$(hide) mkdir -p "$$(dir $$@)"
 	$(hide) rm -f "$$@"
 	$(hide) \
-	    if $(LLVM_READOBJ) -h "$$<" >/dev/null 2>&1; then \
+	    if $(LLVM_READOBJ) -h "$$<" 2>/dev/null | grep -q "^Format: elf"; then \
 	        $(call echo-error,$(2),$(3)); \
 	        $(call echo-error,$(2),found ELF file: $$<); \
 	        false; \
@@ -3437,9 +3422,9 @@ endef
 # a hash mapping to the mapping directory.
 # $(1): unstripped intermediates file
 # $(2): path in symbols directory
+# $(3): path in elf_symbol_mapping packaging directory
 define copy-unstripped-elf-file-with-mapping
-$(call _copy-symbols-file-with-mapping,$(1),$(2),\
-  elf,$(patsubst $(TARGET_OUT_UNSTRIPPED)/%,$(call intermediates-dir-for,PACKAGING,elf_symbol_mapping)/%,$(2).textproto))
+$(call _copy-symbols-file-with-mapping,$(1),$(2),elf,$(3))
 endef
 
 # Copy an R8 dictionary to the packaging directory while also extracting
@@ -3704,6 +3689,32 @@ $(eval $(my_all_targets) : \
     $(sort $(foreach suite,$(LOCAL_COMPATIBILITY_SUITE),$(my_compat_dist_config_$(suite))))))
 endef
 
+# Define symbols.zip and symbols-mapping.textproto build rule per test suite
+#
+# $(1): Name of the test suite to create the zip and mapping build rules
+define create-suite-symbols-map
+_suite_symbols_zip := $$(subst -tests-,-tests_-,$$(PRODUCT_OUT)/$(1)-symbols.zip)
+_suite_symbols_mapping := $$(subst -tests-,-tests_-,$$(PRODUCT_OUT)/$(1)-symbols-mapping.textproto)
+_suite_modules_symbols_files := $$(foreach m,$$(COMPATIBILITY.$(1).MODULES),$$(ALL_MODULES.$$(m).SYMBOLIC_OUTPUT_PATH))
+_suite_modules_mapping_files := $$(foreach m,$$(COMPATIBILITY.$(1).MODULES),$$(ALL_MODULES.$$(m).ELF_SYMBOL_MAPPING_PATH))
+
+$$(_suite_symbols_zip): PRIVATE_SUITE_SYMBOLS_MAPPING := $$(_suite_symbols_mapping)
+$$(_suite_symbols_zip): PRIVATE_SUITE_MODULES_SYMBOLS_FILES := $$(_suite_modules_symbols_files)
+$$(_suite_symbols_zip): PRIVATE_SUITE_MODULES_MAPPING_FILES := $$(_suite_modules_mapping_files)
+$$(_suite_symbols_zip): $$(SOONG_ZIP) $$(SYMBOLS_MAP) $$(_suite_modules_symbols_files) $$(_suite_modules_mapping_files)
+	@echo "Package $(1) symbols: $$@"
+	$(hide) rm -rf $$@ $$@.symbols_list $$@.mapping_list
+	echo "$$(PRIVATE_SUITE_MODULES_SYMBOLS_FILES)" | tr " " "\n" | sort > $$@.symbols_list
+	$(hide) $$(SOONG_ZIP) -d -o $$@ -l $$@.symbols_list
+	echo "$$(PRIVATE_SUITE_MODULES_MAPPING_FILES)" | tr " " "\n" | sort > $$@.mapping_list
+	$(hide) $$(SYMBOLS_MAP) -merge $$(PRIVATE_SUITE_SYMBOLS_MAPPING) @$$@.mapping_list
+$$(_suite_symbols_zip): .KATI_IMPLICIT_OUTPUTS := $$(_suite_symbols_mapping)
+
+.PHONY: $(1)
+$(1): $$(_suite_symbols_zip) $$(_suite_symbols_mapping)
+$$(call dist-for-goals-with-filenametag,$(1), $$(_suite_symbols_zip) $$(_suite_symbols_mapping))
+endef
+
 ###########################################################
 ## Path Cleaning
 ###########################################################
diff --git a/core/dex_preopt.mk b/core/dex_preopt.mk
index 88e0cc7452..b78c10cc0a 100644
--- a/core/dex_preopt.mk
+++ b/core/dex_preopt.mk
@@ -13,34 +13,10 @@ else
 install-on-system-other = $(filter-out $(PRODUCT_DEXPREOPT_SPEED_APPS) $(PRODUCT_SYSTEM_SERVER_APPS),$(basename $(notdir $(filter $(foreach f,$(SYSTEM_OTHER_ODEX_FILTER),$(TARGET_OUT)/$(f)),$(1)))))
 endif
 
-# Build the boot.zip which contains the boot jars and their compilation output
-# We can do this only if preopt is enabled and if the product uses libart config (which sets the
-# default properties for preopting).
-# At the time of writing, this is only for ART Cloud.
 ifeq ($(WITH_DEXPREOPT), true)
 ifneq ($(WITH_DEXPREOPT_ART_BOOT_IMG_ONLY), true)
 ifeq ($(PRODUCT_USES_DEFAULT_ART_CONFIG), true)
 
-boot_zip := $(PRODUCT_OUT)/boot.zip
-bootclasspath_jars := $(DEXPREOPT_BOOTCLASSPATH_DEX_FILES)
-
-# TODO remove system_server_jars usages from boot.zip and depend directly on system_server.zip file.
-
-# Use "/system" path for JARs with "platform:" prefix.
-# These JARs counterintuitively use "platform" prefix but they will
-# be actually installed to /system partition.
-platform_system_server_jars = $(filter platform:%, $(PRODUCT_SYSTEM_SERVER_JARS))
-system_server_jars := \
-  $(foreach m,$(platform_system_server_jars),\
-    $(PRODUCT_OUT)/system/framework/$(call word-colon,2,$(m)).jar)
-
-# For the remaining system server JARs use the partition signified by the prefix.
-# For example, prefix "system_ext:" will use "/system_ext" path.
-other_system_server_jars = $(filter-out $(platform_system_server_jars), $(PRODUCT_SYSTEM_SERVER_JARS))
-system_server_jars += \
-  $(foreach m,$(other_system_server_jars),\
-    $(PRODUCT_OUT)/$(call word-colon,1,$(m))/framework/$(call word-colon,2,$(m)).jar)
-
 # Infix can be 'art' (ART image for testing), 'boot' (primary), or 'mainline' (mainline extension).
 # Soong creates a set of variables for Make, one or each boot image. The only reason why the ART
 # image is exposed to Make is testing (art gtests) and benchmarking (art golem benchmarks). Install
@@ -48,76 +24,6 @@ system_server_jars += \
 # is always 'boot' or 'mainline'.
 DEXPREOPT_INFIX := $(if $(filter true,$(DEX_PREOPT_WITH_UPDATABLE_BCP)),mainline,boot)
 
-# The input variables are written by build/soong/java/dexpreopt_bootjars.go. Examples can be found
-# at the bottom of build/soong/java/dexpreopt_config_testing.go.
-dexpreopt_root_dir := $(dir $(patsubst %/,%,$(dir $(firstword $(bootclasspath_jars)))))
-bootclasspath_arg := $(subst $(space),:,$(patsubst $(dexpreopt_root_dir)%,%,$(DEXPREOPT_BOOTCLASSPATH_DEX_FILES)))
-bootclasspath_locations_arg := $(subst $(space),:,$(DEXPREOPT_BOOTCLASSPATH_DEX_LOCATIONS))
-boot_images := $(subst :,$(space),$(DEXPREOPT_IMAGE_LOCATIONS_ON_DEVICE$(DEXPREOPT_INFIX)))
-boot_image_arg := $(subst $(space),:,$(patsubst /%,%,$(boot_images)))
-uffd_gc_flag_txt := $(OUT_DIR)/soong/dexpreopt/uffd_gc_flag.txt
-
-boot_zip_metadata_txt := $(dir $(boot_zip))boot_zip/METADATA.txt
-$(boot_zip_metadata_txt): $(uffd_gc_flag_txt)
-$(boot_zip_metadata_txt):
-	rm -f $@
-	echo "bootclasspath = $(bootclasspath_arg)" >> $@
-	echo "bootclasspath-locations = $(bootclasspath_locations_arg)" >> $@
-	echo "boot-image = $(boot_image_arg)" >> $@
-	echo "extra-args = `cat $(uffd_gc_flag_txt)`" >> $@
-
-$(call dist-for-goals, droidcore, $(boot_zip_metadata_txt))
-
-$(boot_zip): PRIVATE_BOOTCLASSPATH_JARS := $(bootclasspath_jars)
-$(boot_zip): PRIVATE_SYSTEM_SERVER_JARS := $(system_server_jars)
-$(boot_zip): $(bootclasspath_jars) $(system_server_jars) $(SOONG_ZIP) $(MERGE_ZIPS) $(DEXPREOPT_IMAGE_ZIP_boot) $(DEXPREOPT_IMAGE_ZIP_art) $(DEXPREOPT_IMAGE_ZIP_mainline) $(boot_zip_metadata_txt)
-	@echo "Create boot package: $@"
-	rm -f $@
-	$(SOONG_ZIP) -o $@.tmp \
-	  -C $(dir $(firstword $(PRIVATE_BOOTCLASSPATH_JARS)))/.. $(addprefix -f ,$(PRIVATE_BOOTCLASSPATH_JARS)) \
-	  -C $(PRODUCT_OUT) $(addprefix -f ,$(PRIVATE_SYSTEM_SERVER_JARS)) \
-	  -j -f $(boot_zip_metadata_txt)
-	$(MERGE_ZIPS) $@ $@.tmp $(DEXPREOPT_IMAGE_ZIP_boot) $(DEXPREOPT_IMAGE_ZIP_art) $(DEXPREOPT_IMAGE_ZIP_mainline)
-	rm -f $@.tmp
-
-$(call dist-for-goals, droidcore, $(boot_zip))
-
-# Build the system_server.zip which contains the Apex system server jars and standalone system server jars
-system_server_dex2oat_dir := $(SOONG_OUT_DIR)/system_server_dexjars
-system_server_zip := $(PRODUCT_OUT)/system_server.zip
-# non_updatable_system_server_jars contains jars in /system and /system_ext that are not part of an apex.
-non_updatable_system_server_jars := \
-  $(foreach m,$(PRODUCT_SYSTEM_SERVER_JARS),\
-    $(system_server_dex2oat_dir)/$(call word-colon,2,$(m)).jar)
-
-apex_system_server_jars := \
-  $(foreach m,$(PRODUCT_APEX_SYSTEM_SERVER_JARS),\
-    $(system_server_dex2oat_dir)/$(call word-colon,2,$(m)).jar)
-
-apex_standalone_system_server_jars := \
-  $(foreach m,$(PRODUCT_APEX_STANDALONE_SYSTEM_SERVER_JARS),\
-    $(system_server_dex2oat_dir)/$(call word-colon,2,$(m)).jar)
-
-standalone_system_server_jars := \
-  $(foreach m,$(PRODUCT_STANDALONE_SYSTEM_SERVER_JARS),\
-    $(system_server_dex2oat_dir)/$(call word-colon,2,$(m)).jar)
-
-$(system_server_zip): PRIVATE_SYSTEM_SERVER_DEX2OAT_DIR := $(system_server_dex2oat_dir)
-$(system_server_zip): PRIVATE_SYSTEM_SERVER_JARS := $(non_updatable_system_server_jars)
-$(system_server_zip): PRIVATE_APEX_SYSTEM_SERVER_JARS := $(apex_system_server_jars)
-$(system_server_zip): PRIVATE_APEX_STANDALONE_SYSTEM_SERVER_JARS := $(apex_standalone_system_server_jars)
-$(system_server_zip): PRIVATE_STANDALONE_SYSTEM_SERVER_JARS := $(standalone_system_server_jars)
-$(system_server_zip): $(system_server_jars) $(apex_system_server_jars) $(apex_standalone_system_server_jars) $(standalone_system_server_jars) $(SOONG_ZIP)
-	@echo "Create system server package: $@"
-	rm -f $@
-	$(SOONG_ZIP) -o $@ \
-	  -C $(PRIVATE_SYSTEM_SERVER_DEX2OAT_DIR) $(addprefix -f ,$(PRIVATE_SYSTEM_SERVER_JARS)) \
-	  -C $(PRIVATE_SYSTEM_SERVER_DEX2OAT_DIR) $(addprefix -f ,$(PRIVATE_APEX_SYSTEM_SERVER_JARS)) \
-	  -C $(PRIVATE_SYSTEM_SERVER_DEX2OAT_DIR) $(addprefix -f ,$(PRIVATE_APEX_STANDALONE_SYSTEM_SERVER_JARS)) \
-	  -C $(PRIVATE_SYSTEM_SERVER_DEX2OAT_DIR) $(addprefix -f ,$(PRIVATE_STANDALONE_SYSTEM_SERVER_JARS))
-
-$(call dist-for-goals, droidcore, $(system_server_zip))
-
 endif  #PRODUCT_USES_DEFAULT_ART_CONFIG
 endif  #WITH_DEXPREOPT_ART_BOOT_IMG_ONLY
 endif  #WITH_DEXPREOPT
diff --git a/core/dex_preopt_odex_install.mk b/core/dex_preopt_odex_install.mk
index e7086b7e4e..6fe9d38a36 100644
--- a/core/dex_preopt_odex_install.mk
+++ b/core/dex_preopt_odex_install.mk
@@ -152,7 +152,7 @@ my_dexpreopt_libs_all := $(sort $(my_dexpreopt_libs) $(my_dexpreopt_libs_compat)
 # this dexpreopt.config is generated. So it's necessary to add file-level
 # dependencies between dexpreopt.config files.
 my_dexpreopt_dep_configs := $(foreach lib, \
-  $(filter-out $(my_dexpreopt_libs_compat),$(LOCAL_USES_LIBRARIES) $(my_filtered_optional_uses_libraries)), \
+  $(filter-out $(my_dexpreopt_libs_compat) $(FRAMEWORK_LIBRARIES),$(LOCAL_USES_LIBRARIES) $(my_filtered_optional_uses_libraries)), \
   $(call intermediates-dir-for,JAVA_LIBRARIES,$(lib),,)/dexpreopt.config)
 
 # 1: SDK version
diff --git a/core/dynamic_binary.mk b/core/dynamic_binary.mk
index 0d2cd7f067..878989d635 100644
--- a/core/dynamic_binary.mk
+++ b/core/dynamic_binary.mk
@@ -55,7 +55,12 @@ my_unstripped_path := $(LOCAL_UNSTRIPPED_PATH)
 endif
 symbolic_input := $(inject_module)
 symbolic_output := $(my_unstripped_path)/$(my_installed_module_stem)
-$(eval $(call copy-unstripped-elf-file-with-mapping,$(symbolic_input),$(symbolic_output)))
+elf_mapping_path := $(patsubst $(TARGET_OUT_UNSTRIPPED)/%,$(call intermediates-dir-for,PACKAGING,elf_symbol_mapping)/%,$(symbolic_output).textproto)
+
+ALL_MODULES.$(my_register_name).SYMBOLIC_OUTPUT_PATH := $(symbolic_output)
+ALL_MODULES.$(my_register_name).ELF_SYMBOL_MAPPING_PATH := $(elf_mapping_path)
+
+$(eval $(call copy-unstripped-elf-file-with-mapping,$(symbolic_input),$(symbolic_output),$(elf_mapping_path)))
 
 ###########################################################
 ## Store breakpad symbols
diff --git a/core/java.mk b/core/java.mk
index 5fbc916859..41a1b1ba84 100644
--- a/core/java.mk
+++ b/core/java.mk
@@ -140,8 +140,7 @@ ifneq ($(strip $(logtags_sources)),)
 logtags_java_sources := $(patsubst %.logtags,%.java,$(addprefix $(intermediates.COMMON)/logtags/, $(logtags_sources)))
 logtags_sources := $(addprefix $(LOCAL_PATH)/, $(logtags_sources))
 
-$(logtags_java_sources): PRIVATE_MERGED_TAG := $(TARGET_OUT_COMMON_INTERMEDIATES)/all-event-log-tags.txt
-$(logtags_java_sources): $(intermediates.COMMON)/logtags/%.java: $(LOCAL_PATH)/%.logtags $(TARGET_OUT_COMMON_INTERMEDIATES)/all-event-log-tags.txt $(JAVATAGS) build/make/tools/event_log_tags.py
+$(logtags_java_sources): $(intermediates.COMMON)/logtags/%.java: $(LOCAL_PATH)/%.logtags $(JAVATAGS)
 	$(transform-logtags-to-java)
 
 else
diff --git a/core/layoutlib_data.mk b/core/layoutlib_data.mk
index f228ef65b6..5dde50f7a8 100644
--- a/core/layoutlib_data.mk
+++ b/core/layoutlib_data.mk
@@ -77,15 +77,23 @@ $(call dist-for-goals,layoutlib,$(LAYOUTLIB_BUILD_PROP)/layoutlib-build.prop:lay
 LAYOUTLIB_RES := $(call intermediates-dir-for,PACKAGING,layoutlib-res,HOST,COMMON)
 LAYOUTLIB_RES_FILES := $(shell find frameworks/base/core/res/res -type f -not -path 'frameworks/base/core/res/res/values-m[nc]c*' | sort)
 EMULATED_OVERLAYS_FILES := $(shell find frameworks/base/packages/overlays/*/res/ | sort)
-DEVICE_OVERLAYS_FILES := $(shell find device/generic/goldfish/phone/overlay/frameworks/base/packages/overlays/*/AndroidOverlay/res/ | sort)
-$(LAYOUTLIB_RES)/layoutlib-res.zip: $(SOONG_ZIP) $(HOST_OUT_EXECUTABLES)/aapt2 $(LAYOUTLIB_RES_FILES) $(EMULATED_OVERLAYS_FILES) $(DEVICE_OVERLAYS_FILES)
+LAYOUTLIB_SUPPORTED_DEVICES := raviole/oriole raviole/raven bluejay/bluejay pantah/panther pantah/cheetah lynx/lynx felix/felix shusky/shiba shusky/husky akita/akita caimito/tokay caimito/caiman caimito/komodo comet/comet tangorpro/tangorpro
+LAYOUTLIB_DEVICE_OVERLAYS_FILES := $(addsuffix /overlay/frameworks/base/core/res/res/values/*, $(addprefix device/google/, $(LAYOUTLIB_SUPPORTED_DEVICES)))
+LAYOUTLIB_DEVICE_OVERLAYS_FILES := $(shell find $(LAYOUTLIB_DEVICE_OVERLAYS_FILES) | sort)
+$(LAYOUTLIB_RES)/layoutlib-res.zip: $(SOONG_ZIP) $(HOST_OUT_EXECUTABLES)/aapt2 $(LAYOUTLIB_RES_FILES) $(EMULATED_OVERLAYS_FILES) $(LAYOUTLIB_DEVICE_OVERLAYS_FILES) frameworks/layoutlib/overlay_codenames.txt
 	rm -rf $@
 	echo $(LAYOUTLIB_RES_FILES) > $(LAYOUTLIB_RES)/filelist_res.txt
 	$(SOONG_ZIP) -C frameworks/base/core/res -l $(LAYOUTLIB_RES)/filelist_res.txt -o $(LAYOUTLIB_RES)/temp_res.zip
 	echo $(EMULATED_OVERLAYS_FILES) > $(LAYOUTLIB_RES)/filelist_emulated_overlays.txt
 	$(SOONG_ZIP) -C frameworks/base/packages -l $(LAYOUTLIB_RES)/filelist_emulated_overlays.txt -o $(LAYOUTLIB_RES)/temp_emulated_overlays.zip
-	echo $(DEVICE_OVERLAYS_FILES) > $(LAYOUTLIB_RES)/filelist_device_overlays.txt
-	$(SOONG_ZIP) -C device/generic/goldfish/phone/overlay/frameworks/base/packages -l $(LAYOUTLIB_RES)/filelist_device_overlays.txt -o $(LAYOUTLIB_RES)/temp_device_overlays.zip
+	for line in $$(cut -f 1 frameworks/layoutlib/overlay_codenames.txt); \
+	  do splitLine=($${line//:/ }) \
+	  origin_dir=device/google/*/$${splitLine[0]}/overlay/frameworks/base/core/res/res/values; \
+	  target_dir=$(LAYOUTLIB_RES)/overlays/$${splitLine[1]}/res/; \
+	  mkdir -p $$target_dir; \
+	  cp -r $$origin_dir $$target_dir; \
+	done
+	$(SOONG_ZIP) -C $(LAYOUTLIB_RES) -D $(LAYOUTLIB_RES)/overlays/ -o $(LAYOUTLIB_RES)/temp_device_overlays.zip
 	rm -rf $(LAYOUTLIB_RES)/data && unzip -q -d $(LAYOUTLIB_RES)/data $(LAYOUTLIB_RES)/temp_res.zip
 	unzip -q -d $(LAYOUTLIB_RES)/data $(LAYOUTLIB_RES)/temp_emulated_overlays.zip
 	unzip -q -d $(LAYOUTLIB_RES)/data $(LAYOUTLIB_RES)/temp_device_overlays.zip
@@ -163,14 +171,18 @@ $(LAYOUTLIB_SBOM)/sbom-metadata.csv:
 	  echo $(_path),,,,,,Y,$f,,, >> $@; \
 	)
 
-	$(foreach f,$(DEVICE_OVERLAYS_FILES), \
-	  $(eval _path := $(subst device/generic/goldfish/phone/overlay/frameworks/base/packages,data,$f)) \
-	  echo $(_path),,,,,,Y,$f,,, >> $@; \
-	)
+	for line in $$(cut -f 1 frameworks/layoutlib/overlay_codenames.txt); do \
+	  splitLine=($${line//:/ }); \
+	  for f in $(LAYOUTLIB_DEVICE_OVERLAYS_FILES); do \
+	    if [[ $$f == */$${splitLine[0]}/* ]]; then \
+	      echo data/overlays/$${splitLine[1]}/res/values/$$(basename $$f),,,,,,Y,$$f,,, >> $@; \
+	    fi \
+	  done \
+	done
 
 .PHONY: layoutlib-sbom
 layoutlib-sbom: $(LAYOUTLIB_SBOM)/layoutlib.spdx.json
-$(LAYOUTLIB_SBOM)/layoutlib.spdx.json: $(PRODUCT_OUT)/always_dirty_file.txt $(GEN_SBOM) $(LAYOUTLIB_SBOM)/sbom-metadata.csv $(_layoutlib_font_config_files) $(_layoutlib_fonts_files) $(LAYOUTLIB_BUILD_PROP)/layoutlib-build.prop $(_layoutlib_keyboard_files) $(_layoutlib_hyphen_files) $(LAYOUTLIB_RES_FILES) $(EMULATED_OVERLAYS_FILES) $(DEVICE_OVERLAYS_FILES)
+$(LAYOUTLIB_SBOM)/layoutlib.spdx.json: $(PRODUCT_OUT)/always_dirty_file.txt $(GEN_SBOM) $(LAYOUTLIB_SBOM)/sbom-metadata.csv $(_layoutlib_font_config_files) $(_layoutlib_fonts_files) $(LAYOUTLIB_BUILD_PROP)/layoutlib-build.prop $(_layoutlib_keyboard_files) $(_layoutlib_hyphen_files) $(LAYOUTLIB_RES_FILES) $(EMULATED_OVERLAYS_FILES) $(LAYOUTLIB_DEVICE_OVERLAYS_FILES) frameworks/layoutlib/overlay_codenames.txt
 	rm -rf $@
 	$(GEN_SBOM) --output_file $@ --metadata $(LAYOUTLIB_SBOM)/sbom-metadata.csv --build_version $(BUILD_FINGERPRINT_FROM_FILE) --product_mfr "$(PRODUCT_MANUFACTURER)" --module_name "layoutlib" --json
 
diff --git a/core/main.mk b/core/main.mk
index 7c07f9d107..aed3fa2fd9 100644
--- a/core/main.mk
+++ b/core/main.mk
@@ -45,11 +45,6 @@ BUILD_HOSTNAME_FILE := $(SOONG_OUT_DIR)/build_hostname.txt
 $(KATI_obsolete_var BUILD_HOSTNAME,Use BUILD_HOSTNAME_FROM_FILE instead)
 $(KATI_obsolete_var FILE_NAME_TAG,https://android.googlesource.com/platform/build/+/master/Changes.md#FILE_NAME_TAG)
 
-$(BUILD_NUMBER_FILE):
-	# empty rule to prevent dangling rule error for a file that is written by soong_ui
-$(BUILD_HOSTNAME_FILE):
-	# empty rule to prevent dangling rule error for a file that is written by soong_ui
-
 .KATI_RESTAT: $(BUILD_NUMBER_FILE)
 .KATI_RESTAT: $(BUILD_HOSTNAME_FILE)
 
@@ -304,6 +299,8 @@ subdir_makefiles_total := $(words int $(subdir_makefiles) post finish)
 
 $(foreach mk,$(subdir_makefiles),$(info [$(call inc_and_print,subdir_makefiles_inc)/$(subdir_makefiles_total)] including $(mk) ...)$(eval include $(mk)))
 
+-include device/generic/goldfish/tasks/emu_img_zip.mk
+
 # Build bootloader.img/radio.img, and unpack the partitions.
 -include vendor/google_devices/$(TARGET_SOC)/prebuilts/misc_bins/update_bootloader_radio_image.mk
 
@@ -998,6 +995,7 @@ endef
 define auto-included-modules
   $(foreach vndk_ver,$(PRODUCT_EXTRA_VNDK_VERSIONS),com.android.vndk.v$(vndk_ver)) \
   llndk.libraries.txt \
+  $(if $(DEVICE_MANIFEST_FILE),vendor_manifest.xml) \
   $(if $(DEVICE_MANIFEST_SKUS),$(foreach sku, $(DEVICE_MANIFEST_SKUS),vendor_manifest_$(sku).xml)) \
   $(if $(ODM_MANIFEST_FILES),odm_manifest.xml) \
   $(if $(ODM_MANIFEST_SKUS),$(foreach sku, $(ODM_MANIFEST_SKUS),odm_manifest_$(sku).xml)) \
@@ -1200,8 +1198,9 @@ endif
 ifneq ($(TARGET_BUILD_APPS),)
   # If this build is just for apps, only build apps and not the full system by default.
   ifneq ($(filter all,$(TARGET_BUILD_APPS)),)
-    # If they used the magic goal "all" then build all apps in the source tree.
-    unbundled_build_modules := $(foreach m,$(sort $(ALL_MODULES)),$(if $(filter APPS,$(ALL_MODULES.$(m).CLASS)),$(m)))
+    # The magic goal "all" used to build all apps in the source tree. This was deprecated
+    # so that we can know all TARGET_BUILD_APPS apps are built with soong for soong-only builds.
+    $(error TARGET_BUILD_APPS=all is deprecated)
   else
     unbundled_build_modules := $(sort $(TARGET_BUILD_APPS))
   endif
@@ -1471,7 +1470,6 @@ droidcore: droidcore-unbundled
 # dist_files only for putting your library into the dist directory with a full build.
 .PHONY: dist_files
 
-$(call dist-for-goals, dist_files, $(SOONG_OUT_DIR)/module_bp_java_deps.json)
 $(call dist-for-goals, dist_files, $(PRODUCT_OUT)/module-info.json)
 
 .PHONY: apps_only
@@ -1560,7 +1558,6 @@ else ifeq ($(TARGET_BUILD_UNBUNDLED),$(TARGET_BUILD_UNBUNDLED_IMAGE))
   $(call dist-for-goals, droidcore, \
     $(BUILT_OTATOOLS_PACKAGE) \
     $(APPCOMPAT_ZIP) \
-    $(DEXPREOPT_TOOLS_ZIP) \
   )
 
   # We dist the following targets for droidcore-unbundled (and droidcore since
@@ -1607,12 +1604,7 @@ else ifeq ($(TARGET_BUILD_UNBUNDLED),$(TARGET_BUILD_UNBUNDLED_IMAGE))
     $(INSTALLED_FILES_JSON_SYSTEMOTHER) \
     $(INSTALLED_FILES_FILE_RECOVERY) \
     $(INSTALLED_FILES_JSON_RECOVERY) \
-    $(if $(BUILDING_SYSTEM_IMAGE), $(INSTALLED_BUILD_PROP_TARGET):build.prop) \
     $(if $(BUILDING_VENDOR_IMAGE), $(INSTALLED_VENDOR_BUILD_PROP_TARGET):build.prop-vendor) \
-    $(if $(BUILDING_PRODUCT_IMAGE), $(INSTALLED_PRODUCT_BUILD_PROP_TARGET):build.prop-product) \
-    $(if $(BUILDING_ODM_IMAGE), $(INSTALLED_ODM_BUILD_PROP_TARGET):build.prop-odm) \
-    $(if $(BUILDING_SYSTEM_EXT_IMAGE), $(INSTALLED_SYSTEM_EXT_BUILD_PROP_TARGET):build.prop-system_ext) \
-    $(if $(BUILDING_RAMDISK_IMAGE), $(INSTALLED_RAMDISK_BUILD_PROP_TARGET):build.prop-ramdisk) \
     $(INSTALLED_ANDROID_INFO_TXT_TARGET) \
     $(INSTALLED_MISC_INFO_TARGET) \
     $(INSTALLED_RAMDISK_TARGET) \
@@ -1625,7 +1617,6 @@ else ifeq ($(TARGET_BUILD_UNBUNDLED),$(TARGET_BUILD_UNBUNDLED_IMAGE))
 
   ifneq ($(ANDROID_BUILD_EMBEDDED),true)
     $(call dist-for-goals-with-filenametag, droidcore, \
-      $(APPS_ZIP) \
       $(INTERNAL_EMULATOR_PACKAGE_TARGET) \
     )
   endif
@@ -1672,24 +1663,6 @@ else ifeq ($(TARGET_BUILD_UNBUNDLED),$(TARGET_BUILD_UNBUNDLED_IMAGE))
     $(call dist-for-goals, dist_files, $(JACOCO_REPORT_CLASSES_ALL))
   endif
 
-  # Put XML formatted API files in the dist dir.
-  $(TARGET_OUT_COMMON_INTERMEDIATES)/api.xml: $(call java-lib-files,$(ANDROID_PUBLIC_STUBS)) $(APICHECK)
-  $(TARGET_OUT_COMMON_INTERMEDIATES)/system-api.xml: $(call java-lib-files,$(ANDROID_SYSTEM_STUBS)) $(APICHECK)
-  $(TARGET_OUT_COMMON_INTERMEDIATES)/module-lib-api.xml: $(call java-lib-files,$(ANDROID_MODULE_LIB_STUBS)) $(APICHECK)
-  $(TARGET_OUT_COMMON_INTERMEDIATES)/system-server-api.xml: $(call java-lib-files,$(ANDROID_SYSTEM_SERVER_STUBS)) $(APICHECK)
-  $(TARGET_OUT_COMMON_INTERMEDIATES)/test-api.xml: $(call java-lib-files,$(ANDROID_TEST_STUBS)) $(APICHECK)
-
-  api_xmls := $(addprefix $(TARGET_OUT_COMMON_INTERMEDIATES)/,api.xml system-api.xml module-lib-api.xml system-server-api.xml test-api.xml)
-  $(api_xmls):
-	$(hide) echo "Converting API file to XML: $@"
-	$(hide) mkdir -p $(dir $@)
-	$(hide) $(APICHECK_COMMAND) jar-to-jdiff $< $@
-
-  $(foreach xml,$(sort $(api_xmls)),$(call declare-1p-target,$(xml),))
-
-  $(call dist-for-goals, dist_files, $(api_xmls))
-  api_xmls :=
-
   ifdef CLANG_COVERAGE
     $(foreach f,$(SOONG_NDK_API_XML), \
         $(call dist-for-goals,droidcore,$(f):ndk_apis/$(notdir $(f))))
@@ -1725,7 +1698,6 @@ ifeq ($(HOST_OS),linux)
 ALL_SDK_TARGETS := $(INTERNAL_SDK_TARGET)
 sdk: $(ALL_SDK_TARGETS)
 $(call dist-for-goals-with-filenametag,sdk,$(ALL_SDK_TARGETS))
-$(call dist-for-goals,sdk,$(INSTALLED_BUILD_PROP_TARGET))
 endif
 
 # umbrella targets to assit engineers in verifying builds
@@ -1759,10 +1731,6 @@ dump-files:
 	@echo $(sort $(patsubst $(PRODUCT_OUT)/%,%,$(filter $(PRODUCT_OUT)/%,$(modules_to_install)))) | tr -s ' ' '\n'
 	@echo Successfully dumped product target file list.
 
-.PHONY: nothing
-nothing:
-	@echo Successfully read the makefiles.
-
 .PHONY: tidy_only
 tidy_only:
 	@echo Successfully make tidy_only.
@@ -1920,14 +1888,15 @@ $(SOONG_OUT_DIR)/compliance-metadata/$(TARGET_PRODUCT)/make-metadata.csv:
 	  $(eval _is_system_other_odex_marker := $(if $(findstring $f,$(INSTALLED_SYSTEM_OTHER_ODEX_MARKER)),Y)) \
 	  $(eval _is_kernel_modules_blocklist := $(if $(findstring $f,$(ALL_KERNEL_MODULES_BLOCKLIST)),Y)) \
 	  $(eval _is_fsverity_build_manifest_apk := $(if $(findstring $f,$(ALL_FSVERITY_BUILD_MANIFEST_APK)),Y)) \
-	  $(eval _is_linker_config := $(if $(findstring $f,$(SYSTEM_LINKER_CONFIG) $(vendor_linker_config_file)),Y)) \
+	  $(eval _is_linker_config := $(if $(findstring $f,$(SYSTEM_LINKER_CONFIG) $(vendor_linker_config_file) $(product_linker_config_file)),Y)) \
 	  $(eval _is_partition_compat_symlink := $(if $(findstring $f,$(PARTITION_COMPAT_SYMLINKS)),Y)) \
 	  $(eval _is_flags_file := $(if $(findstring $f, $(ALL_FLAGS_FILES)),Y)) \
 	  $(eval _is_rootdir_symlink := $(if $(findstring $f, $(ALL_ROOTDIR_SYMLINKS)),Y)) \
-	  $(eval _is_platform_generated := $(_is_build_prop)$(_is_notice_file)$(_is_product_system_other_avbkey)$(_is_event_log_tags_file)$(_is_system_other_odex_marker)$(_is_kernel_modules_blocklist)$(_is_fsverity_build_manifest_apk)$(_is_linker_config)$(_is_partition_compat_symlink)$(_is_flags_file)$(_is_rootdir_symlink)) \
+	  $(eval _is_platform_generated := $(if $(_is_soong_module),,$(_is_build_prop)$(_is_notice_file)$(_is_product_system_other_avbkey)$(_is_event_log_tags_file)$(_is_system_other_odex_marker)$(_is_kernel_modules_blocklist)$(_is_fsverity_build_manifest_apk)$(_is_linker_config)$(_is_partition_compat_symlink)$(_is_flags_file)$(_is_rootdir_symlink))) \
 	  $(eval _static_libs := $(if $(_is_soong_module),,$(ALL_INSTALLED_FILES.$f.STATIC_LIBRARIES))) \
 	  $(eval _whole_static_libs := $(if $(_is_soong_module),,$(ALL_INSTALLED_FILES.$f.WHOLE_STATIC_LIBRARIES))) \
-	  $(eval _license_text := $(if $(filter $(_build_output_path),$(ALL_NON_MODULES)),$(ALL_NON_MODULES.$(_build_output_path).NOTICES))) \
+	  $(eval _license_text := $(if $(filter $(_build_output_path),$(ALL_NON_MODULES)),$(ALL_NON_MODULES.$(_build_output_path).NOTICES),\
+	                          $(if $(_is_partition_compat_symlink),build/soong/licenses/LICENSE))) \
 	  echo '$(_build_output_path),$(_module_path),$(_is_soong_module),$(_is_prebuilt_make_module),$(_product_copy_files),$(_kernel_module_copy_files),$(_is_platform_generated),$(_static_libs),$(_whole_static_libs),$(_license_text)' >> $@; \
 	)
 
diff --git a/core/misc_prebuilt_internal.mk b/core/misc_prebuilt_internal.mk
index a56220772c..b14b9ce032 100644
--- a/core/misc_prebuilt_internal.mk
+++ b/core/misc_prebuilt_internal.mk
@@ -25,7 +25,7 @@ endif
 
 include $(BUILD_SYSTEM)/base_rules.mk
 
-ifneq ($(filter init%rc,$(notdir $(LOCAL_INSTALLED_MODULE)))$(filter %/etc/init,$(dir $(LOCAL_INSTALLED_MODULE))),)
+ifneq ($(filter init%rc,$(notdir $(LOCAL_INSTALLED_MODULE)))$(filter %/etc/init/,$(dir $(LOCAL_INSTALLED_MODULE))),)
   $(eval $(call copy-init-script-file-checked,$(my_prebuilt_src_file),$(LOCAL_BUILT_MODULE)))
 else
 $(LOCAL_BUILT_MODULE) : $(my_prebuilt_src_file)
diff --git a/core/ninja_config.mk b/core/ninja_config.mk
index d4b7c6df11..27b4190145 100644
--- a/core/ninja_config.mk
+++ b/core/ninja_config.mk
@@ -19,9 +19,6 @@ PARSE_TIME_MAKE_GOALS := \
 	build-art% \
 	build_kernel-nodeps \
 	clean-oat% \
-	continuous_instrumentation_tests \
-	continuous_native_tests \
-	cts \
 	custom_images \
 	dicttool_aosp \
 	docs \
diff --git a/core/os_licensing.mk b/core/os_licensing.mk
index d15a3d0715..bebaca1c17 100644
--- a/core/os_licensing.mk
+++ b/core/os_licensing.mk
@@ -7,24 +7,17 @@ ifneq (,$(SYSTEM_NOTICE_DEPS))
 
 SYSTEM_NOTICE_DEPS += $(UNMOUNTED_NOTICE_DEPS) $(UNMOUNTED_NOTICE_VENDOR_DEPS)
 
-ifneq ($(PRODUCT_NOTICE_SPLIT),true)
-$(eval $(call html-notice-rule,$(target_notice_file_html_gz),"System image",$(system_notice_file_message),$(SYSTEM_NOTICE_DEPS),$(SYSTEM_NOTICE_DEPS)))
-
-$(installed_notice_html_or_xml_gz): $(target_notice_file_html_gz)
-	$(copy-file-to-target)
-else
 $(eval $(call xml-notice-rule,$(target_notice_file_xml_gz),"System image",$(system_notice_file_message),$(SYSTEM_NOTICE_DEPS),$(SYSTEM_NOTICE_DEPS)))
 
 $(eval $(call text-notice-rule,$(target_notice_file_txt),"System image",$(system_notice_file_message),$(SYSTEM_NOTICE_DEPS),$(SYSTEM_NOTICE_DEPS)))
 
-ifneq ($(USE_SOONG_DEFINED_SYSTEM_IMAGE),true)
+ifneq ($(PRODUCT_USE_SOONG_NOTICE_XML),true)
 $(installed_notice_html_or_xml_gz): $(target_notice_file_xml_gz)
 	$(copy-file-to-target)
 endif
-endif
 
 $(call declare-1p-target,$(target_notice_file_xml_gz))
-ifneq ($(USE_SOONG_DEFINED_SYSTEM_IMAGE),true)
+ifneq ($(PRODUCT_USE_SOONG_NOTICE_XML),true)
 $(call declare-1p-target,$(installed_notice_html_or_xml_gz))
 endif
 endif
@@ -44,12 +37,16 @@ $(eval $(call xml-notice-rule,$(target_vendor_notice_file_xml_gz),"Vendor image"
          "Notices for files contained in all filesystem images except system/system_ext/product/odm/vendor_dlkm/odm_dlkm in this directory:", \
          $(VENDOR_NOTICE_DEPS),$(VENDOR_NOTICE_DEPS)))
 
+ifneq ($(PRODUCT_USE_SOONG_NOTICE_XML),true)
 $(installed_vendor_notice_xml_gz): $(target_vendor_notice_file_xml_gz)
 	$(copy-file-to-target)
+endif
 
 $(call declare-1p-target,$(target_vendor_notice_file_xml_gz))
+ifneq ($(PRODUCT_USE_SOONG_NOTICE_XML),true)
 $(call declare-1p-target,$(installed_vendor_notice_xml_gz))
 endif
+endif
 
 .PHONY: odmlicense
 odmlicense: $(call corresponding-license-metadata, $(ODM_NOTICE_DEPS)) reportmissinglicenses
@@ -63,12 +60,16 @@ $(eval $(call xml-notice-rule,$(target_odm_notice_file_xml_gz),"ODM filesystem i
          "Notices for files contained in the odm filesystem image in this directory:", \
          $(ODM_NOTICE_DEPS),$(ODM_NOTICE_DEPS)))
 
+ifneq ($(PRODUCT_USE_SOONG_NOTICE_XML),true)
 $(installed_odm_notice_xml_gz): $(target_odm_notice_file_xml_gz)
 	$(copy-file-to-target)
+endif
 
 $(call declare-1p-target,$(target_odm_notice_file_xml_gz))
+ifneq ($(PRODUCT_USE_SOONG_NOTICE_XML),true)
 $(call declare-1p-target,$(installed_odm_notice_xml_gz))
 endif
+endif
 
 .PHONY: oemlicense
 oemlicense: $(call corresponding-license-metadata, $(OEM_NOTICE_DEPS)) reportmissinglicenses
@@ -85,12 +86,16 @@ $(eval $(call xml-notice-rule,$(target_product_notice_file_xml_gz),"Product imag
          "Notices for files contained in the product filesystem image in this directory:", \
          $(PRODUCT_NOTICE_DEPS),$(PRODUCT_NOTICE_DEPS)))
 
+ifneq ($(PRODUCT_USE_SOONG_NOTICE_XML),true)
 $(installed_product_notice_xml_gz): $(target_product_notice_file_xml_gz)
 	$(copy-file-to-target)
+endif
 
 $(call declare-1p-target,$(target_product_notice_file_xml_gz))
+ifneq ($(PRODUCT_USE_SOONG_NOTICE_XML),true)
 $(call declare-1p-target,$(installed_product_notice_xml_gz))
 endif
+endif
 
 .PHONY: systemextlicense
 systemextlicense: $(call corresponding-license-metadata, $(SYSTEM_EXT_NOTICE_DEPS)) reportmissinglicenses
@@ -104,12 +109,16 @@ $(eval $(call xml-notice-rule,$(target_system_ext_notice_file_xml_gz),"System_ex
          "Notices for files contained in the system_ext filesystem image in this directory:", \
          $(SYSTEM_EXT_NOTICE_DEPS),$(SYSTEM_EXT_NOTICE_DEPS)))
 
+ifneq ($(PRODUCT_USE_SOONG_NOTICE_XML),true)
 $(installed_system_ext_notice_xml_gz): $(target_system_ext_notice_file_xml_gz)
 	$(copy-file-to-target)
+endif
 
 $(call declare-1p-target,$(target_system_ext_notice_file_xml_gz))
+ifneq ($(PRODUCT_USE_SOONG_NOTICE_XML),true)
 $(call declare-1p-target,$(installed_system_ext_notice_xml_gz))
 endif
+endif
 
 .PHONY: vendor_dlkmlicense
 vendor_dlkmlicense: $(call corresponding-license-metadata, $(VENDOR_DLKM_NOTICE_DEPS)) reportmissinglicenses
@@ -123,12 +132,16 @@ $(eval $(call xml-notice-rule,$(target_vendor_dlkm_notice_file_xml_gz),"Vendor_d
          "Notices for files contained in the vendor_dlkm filesystem image in this directory:", \
          $(VENDOR_DLKM_NOTICE_DEPS),$(VENDOR_DLKM_NOTICE_DEPS)))
 
+ifneq ($(PRODUCT_USE_SOONG_NOTICE_XML),true)
 $(installed_vendor_dlkm_notice_xml_gz): $(target_vendor_dlkm_notice_file_xml_gz)
 	$(copy-file-to-target)
+endif
 
 $(call declare-1p-target,$(target_vendor_dlkm_notice_file_xml_gz))
+ifneq ($(PRODUCT_USE_SOONG_NOTICE_XML),true)
 $(call declare-1p-target,$(installed_vendor_dlkm_notice_xml_gz))
 endif
+endif
 
 .PHONY: odm_dlkmlicense
 odm_dlkmlicense: $(call corresponding-license-metadata, $(ODM_DLKM_NOTICE_DEPS)) reportmissinglicenses
@@ -142,12 +155,16 @@ $(eval $(call xml-notice-rule,$(target_odm_dlkm_notice_file_xml_gz),"ODM_dlkm fi
          "Notices for files contained in the odm_dlkm filesystem image in this directory:", \
          $(ODM_DLKM_NOTICE_DEPS),$(ODM_DLKM_NOTICE_DEPS)))
 
+ifneq ($(PRODUCT_USE_SOONG_NOTICE_XML),true)
 $(installed_odm_dlkm_notice_xml_gz): $(target_odm_dlkm_notice_file_xml_gz)
 	$(copy-file-to-target)
+endif
 
 $(call declare-1p-target,$(target_odm_dlkm_notice_file_xml_gz))
+ifneq ($(PRODUCT_USE_SOONG_NOTICE_XML),true)
 $(call declare-1p-target,$(installed_odm_dlkm_notice_xml_gz))
 endif
+endif
 
 .PHONY: system_dlkmlicense
 system_dlkmlicense: $(call corresponding-license-metadata, $(SYSTEM_DLKM_NOTICE_DEPS)) reportmissinglicenses
@@ -161,11 +178,15 @@ $(eval $(call xml-notice-rule,$(target_system_dlkm_notice_file_xml_gz),"System_d
          "Notices for files contained in the system_dlkm filesystem image in this directory:", \
          $(SYSTEM_DLKM_NOTICE_DEPS),$(SYSTEM_DLKM_NOTICE_DEPS)))
 
+ifneq ($(PRODUCT_USE_SOONG_NOTICE_XML),true)
 $(installed_system_dlkm_notice_xml_gz): $(target_system_dlkm_notice_file_xml_gz)
 	$(copy-file-to-target)
+endif
 
 $(call declare-1p-target,$(target_system_dlkm_notice_file_xml_gz))
+ifneq ($(PRODUCT_USE_SOONG_NOTICE_XML),true)
 $(call declare-1p-target,$(installed_sysetm_dlkm_notice_xml_gz))
 endif
+endif
 
 endif # not TARGET_BUILD_APPS
diff --git a/core/packaging/flags.mk b/core/packaging/flags.mk
index fd9dc9b847..19068f4a0a 100644
--- a/core/packaging/flags.mk
+++ b/core/packaging/flags.mk
@@ -17,9 +17,8 @@
 # the combined flags files.
 #
 
-# TODO: Should we do all of the images in $(IMAGES_TO_BUILD)?
-_FLAG_PARTITIONS := product system vendor
-
+# TODO: Should we do all of the images?
+_FLAG_PARTITIONS := product system system_ext vendor
 
 # -----------------------------------------------------------------
 # Aconfig Flags
@@ -62,28 +61,38 @@ $(strip $(1)): $(ACONFIG) $(strip $(3))
 $(call copy-one-file, $(1), $(2))
 endef
 
+define out-dir-for-partition
+$(TARGET_COPY_OUT_$(call to-upper,$(1)))
+endef
+
+# Get the module names suitable for ALL_MODULES.* variables that are installed
+# for a given container
+# $(1): container
+define register-names-for-container
+$(sort $(foreach m,$(product_MODULES),\
+	$(if $(filter $(PRODUCT_OUT)/$(call out-dir-for-partition,$(strip $(1)))/%, $(ALL_MODULES.$(m).INSTALLED)), \
+		$(m)
+	) \
+))
+endef
+
 $(foreach partition, $(_FLAG_PARTITIONS), \
-	$(eval aconfig_flag_summaries_protobuf.$(partition) := $(PRODUCT_OUT)/$(partition)/etc/aconfig_flags.pb) \
+	$(eval aconfig_flag_summaries_protobuf.$(partition) := $(PRODUCT_OUT)/$(call out-dir-for-partition,$(partition))/etc/aconfig_flags.pb) \
 	$(eval $(call generate-partition-aconfig-flag-file, \
 			$(TARGET_OUT_FLAGS)/$(partition)/aconfig_flags.pb, \
 			$(aconfig_flag_summaries_protobuf.$(partition)), \
 			$(partition), \
 			$(sort \
-				$(foreach m, $(call register-names-for-partition, $(partition)), \
+				$(foreach m, $(call register-names-for-container, $(partition)), \
 					$(ALL_MODULES.$(m).ACONFIG_FILES) \
 				) \
-				$(if $(filter system, $(partition)), \
-					$(foreach m, $(call register-names-for-partition, system_ext), \
-						$(ALL_MODULES.$(m).ACONFIG_FILES) \
-					) \
-				) \
 			) \
 	)) \
 )
 
 # Collect the on-device flags into a single file, similar to all_aconfig_declarations.
 required_aconfig_flags_files := \
-		$(sort $(foreach partition, $(filter $(IMAGES_TO_BUILD), $(_FLAG_PARTITIONS)), \
+		$(sort $(foreach partition, $(_FLAG_PARTITIONS), \
 			$(aconfig_flag_summaries_protobuf.$(partition)) \
 		))
 
@@ -109,10 +118,17 @@ $(eval $(call generate-global-aconfig-flag-file, \
 define generate-partition-aconfig-storage-file
 $(eval $(strip $(1)): PRIVATE_OUT := $(strip $(1)))
 $(eval $(strip $(1)): PRIVATE_IN := $(strip $(9)))
+
+ifneq (,$(RELEASE_FINGERPRINT_ACONFIG_PACKAGES))
+STORAGE_FILE_VERSION := 2
+else
+STORAGE_FILE_VERSION := 1
+endif
+
 $(strip $(1)): $(ACONFIG) $(strip $(9))
 	mkdir -p $$(dir $$(PRIVATE_OUT))
 	$$(if $$(PRIVATE_IN), \
-		$$(ACONFIG) create-storage --container $(10) --file package_map --out $$(PRIVATE_OUT) \
+		$$(ACONFIG) create-storage --container $(10) --file package_map --out $$(PRIVATE_OUT) --version $$(STORAGE_FILE_VERSION) \
 			$$(addprefix --cache ,$$(PRIVATE_IN)), \
 	)
 	touch $$(PRIVATE_OUT)
@@ -121,7 +137,7 @@ $(eval $(strip $(2)): PRIVATE_IN := $(strip $(9)))
 $(strip $(2)): $(ACONFIG) $(strip $(9))
 	mkdir -p $$(dir $$(PRIVATE_OUT))
 	$$(if $$(PRIVATE_IN), \
-		$$(ACONFIG) create-storage --container $(10) --file flag_map --out $$(PRIVATE_OUT) \
+		$$(ACONFIG) create-storage --container $(10) --file flag_map --out $$(PRIVATE_OUT) --version $$(STORAGE_FILE_VERSION) \
 			$$(addprefix --cache ,$$(PRIVATE_IN)), \
 	)
 	touch $$(PRIVATE_OUT)
@@ -130,7 +146,7 @@ $(eval $(strip $(3)): PRIVATE_IN := $(strip $(9)))
 $(strip $(3)): $(ACONFIG) $(strip $(9))
 	mkdir -p $$(dir $$(PRIVATE_OUT))
 	$$(if $$(PRIVATE_IN), \
-		$$(ACONFIG) create-storage --container $(10) --file flag_val --out $$(PRIVATE_OUT) \
+		$$(ACONFIG) create-storage --container $(10) --file flag_val --out $$(PRIVATE_OUT) --version $$(STORAGE_FILE_VERSION) \
 		$$(addprefix --cache ,$$(PRIVATE_IN)), \
 	)
 	touch $$(PRIVATE_OUT)
@@ -139,7 +155,7 @@ $(eval $(strip $(4)): PRIVATE_IN := $(strip $(9)))
 $(strip $(4)): $(ACONFIG) $(strip $(9))
 	mkdir -p $$(dir $$(PRIVATE_OUT))
 	$$(if $$(PRIVATE_IN), \
-		$$(ACONFIG) create-storage --container $(10) --file flag_info --out $$(PRIVATE_OUT) \
+		$$(ACONFIG) create-storage --container $(10) --file flag_info --out $$(PRIVATE_OUT) --version $$(STORAGE_FILE_VERSION) \
 		$$(addprefix --cache ,$$(PRIVATE_IN)), \
 	)
 	touch $$(PRIVATE_OUT)
@@ -151,10 +167,10 @@ endef
 
 ifeq ($(RELEASE_CREATE_ACONFIG_STORAGE_FILE),true)
 $(foreach partition, $(_FLAG_PARTITIONS), \
-	$(eval aconfig_storage_package_map.$(partition) := $(PRODUCT_OUT)/$(partition)/etc/aconfig/package.map) \
-	$(eval aconfig_storage_flag_map.$(partition) := $(PRODUCT_OUT)/$(partition)/etc/aconfig/flag.map) \
-	$(eval aconfig_storage_flag_val.$(partition) := $(PRODUCT_OUT)/$(partition)/etc/aconfig/flag.val) \
-	$(eval aconfig_storage_flag_info.$(partition) := $(PRODUCT_OUT)/$(partition)/etc/aconfig/flag.info) \
+	$(eval aconfig_storage_package_map.$(partition) := $(PRODUCT_OUT)/$(call out-dir-for-partition,$(partition))/etc/aconfig/package.map) \
+	$(eval aconfig_storage_flag_map.$(partition) := $(PRODUCT_OUT)/$(call out-dir-for-partition,$(partition))/etc/aconfig/flag.map) \
+	$(eval aconfig_storage_flag_val.$(partition) := $(PRODUCT_OUT)/$(call out-dir-for-partition,$(partition))/etc/aconfig/flag.val) \
+	$(eval aconfig_storage_flag_info.$(partition) := $(PRODUCT_OUT)/$(call out-dir-for-partition,$(partition))/etc/aconfig/flag.info) \
 	$(eval $(call generate-partition-aconfig-storage-file, \
 				$(TARGET_OUT_FLAGS)/$(partition)/package.map, \
 				$(TARGET_OUT_FLAGS)/$(partition)/flag.map, \
@@ -173,7 +189,7 @@ endif
 # -----------------------------------------------------------------
 # Install the ones we need for the configured product
 required_flags_files := \
-		$(sort $(foreach partition, $(filter $(IMAGES_TO_BUILD), $(_FLAG_PARTITIONS)), \
+		$(sort $(foreach partition, $(_FLAG_PARTITIONS), \
 			$(build_flag_summaries.$(partition)) \
 			$(aconfig_flag_summaries_protobuf.$(partition)) \
 			$(aconfig_storage_package_map.$(partition)) \
@@ -191,6 +207,8 @@ flag-files: $(required_flags_files)
 
 
 # Clean up
+out-dir-for-partition:=
+register-names-for-container:=
 required_flags_files:=
 required_aconfig_flags_files:=
 $(foreach partition, $(_FLAG_PARTITIONS), \
diff --git a/core/prebuilt_internal.mk b/core/prebuilt_internal.mk
index d5261f4cfc..5dfc6c1951 100644
--- a/core/prebuilt_internal.mk
+++ b/core/prebuilt_internal.mk
@@ -39,6 +39,11 @@ endif
 
 LOCAL_CHECKED_MODULE := $(my_prebuilt_src_file)
 
+ifneq (,$(LOCAL_APKCERTS_FILE))
+  PACKAGES := $(PACKAGES) $(LOCAL_MODULE)
+  PACKAGES.$(LOCAL_MODULE).APKCERTS_FILE := $(LOCAL_APKCERTS_FILE)
+endif
+
 ifneq (APPS,$(LOCAL_MODULE_CLASS))
 ifdef LOCAL_COMPRESSED_MODULE
 $(error $(LOCAL_MODULE) : LOCAL_COMPRESSED_MODULE can only be defined for module class APPS)
diff --git a/core/product.mk b/core/product.mk
index 1b336b050f..1fbc3eef51 100644
--- a/core/product.mk
+++ b/core/product.mk
@@ -501,6 +501,12 @@ _product_single_value_vars += PRODUCT_IGNORE_ALL_ANDROIDMK
 _product_list_vars += PRODUCT_ALLOWED_ANDROIDMK_FILES
 # When PRODUCT_IGNORE_ALL_ANDROIDMK is set to true, path of file that contains a list of allowed Android.mk files
 _product_single_value_vars += PRODUCT_ANDROIDMK_ALLOWLIST_FILE
+# Setting PRODUCT_SOONG_ONLY will cause the build to default to --soong-only mode, and the main
+# kati invocation will not be run.
+_product_single_value_vars += PRODUCT_SOONG_ONLY
+
+# If set to true, use NOTICE.xml.gz generated by soong
+_product_single_value_vars += PRODUCT_USE_SOONG_NOTICE_XML
 
 .KATI_READONLY := _product_single_value_vars _product_list_vars
 _product_var_list :=$= $(_product_single_value_vars) $(_product_list_vars)
diff --git a/core/product_config.mk b/core/product_config.mk
index f93b63c6dc..13907f095e 100644
--- a/core/product_config.mk
+++ b/core/product_config.mk
@@ -485,9 +485,7 @@ endif
 
 # Show a warning wall of text if non-compliance-GSI products set this option.
 ifdef PRODUCT_INSTALL_DEBUG_POLICY_TO_SYSTEM_EXT
-  ifeq (,$(filter gsi_arm gsi_arm64 gsi_arm64_soong_system gsi_x86 gsi_x86_64 \
-                  gsi_x86_64_soong_system gsi_car_arm64 gsi_car_x86_64 \
-                  gsi_tv_arm gsi_tv_arm64,$(PRODUCT_NAME)))
+  ifeq (,$(filter gsi_arm gsi_arm64 gsi_x86 gsi_x86_64 gsi_car_arm64 gsi_car_x86_64 gsi_tv_arm gsi_tv_arm64 clockwork_gsi_google_arm,$(PRODUCT_NAME)))
     $(warning PRODUCT_INSTALL_DEBUG_POLICY_TO_SYSTEM_EXT is set but \
       PRODUCT_NAME ($(PRODUCT_NAME)) doesn't look like a GSI for compliance \
       testing. This is a special configuration for compliance GSI, so do make \
@@ -701,4 +699,12 @@ $(foreach image, \
 
 product-build-image-config :=
 
+ifdef PRODUCT_SOONG_ONLY
+  ifneq ($(PRODUCT_SOONG_ONLY),true)
+    ifneq ($(PRODUCT_SOONG_ONLY),false)
+      $(error PRODUCT_SOONG_ONLY can only be true, false or unset)
+    endif
+  endif
+endif
+
 $(call readonly-product-vars)
diff --git a/core/proguard.flags b/core/proguard.flags
index 5148e56407..76655ca6aa 100644
--- a/core/proguard.flags
+++ b/core/proguard.flags
@@ -1,14 +1,3 @@
-# We have moved -dontobfuscate and -dontoptimize to the makefiles.
-# dex does not like code run through proguard optimize and preverify steps.
-# -dontoptimize
--dontpreverify
-
-# Don't obfuscate. We only need dead code striping.
-# -dontobfuscate
-
-# Add this flag in your package's own configuration if it's needed.
-#-flattenpackagehierarchy
-
 # Keep classes and members with the platform-defined @VisibleForTesting annotation.
 -keep @com.android.internal.annotations.VisibleForTesting class *
 -keepclassmembers class * {
@@ -41,12 +30,12 @@
 # Needed to ensure callback field references are kept in their respective
 # owning classes when the downstream callback registrars only store weak refs.
 -if @com.android.internal.annotations.WeaklyReferencedCallback class *
--keepclassmembers,allowaccessmodification class * {
-  <1> *;
+-keepclassmembers,allowaccessmodification,allowobfuscation,allowshrinking class * {
+  !synthetic <1> *;
 }
 -if class * extends @com.android.internal.annotations.WeaklyReferencedCallback **
--keepclassmembers,allowaccessmodification class * {
-  <1> *;
+-keepclassmembers,allowaccessmodification,allowobfuscation,allowshrinking class * {
+  !synthetic <1> *;
 }
 
 # Understand the common @Keep annotation from various Android packages:
diff --git a/core/proguard/checknotnull.flags b/core/proguard/checknotnull.flags
new file mode 100644
index 0000000000..1e1e5ce46c
--- /dev/null
+++ b/core/proguard/checknotnull.flags
@@ -0,0 +1,25 @@
+# Tell R8 that the following methods are check not null methods, and to
+# replace invocations to them with a more concise nullness check that produces
+# (slightly) less informative error messages
+
+-convertchecknotnull class com.google.common.base.Preconditions {
+  ** checkNotNull(...);
+}
+
+-convertchecknotnull class java.util.Objects {
+  ** requireNonNull(...);
+}
+
+-convertchecknotnull class kotlin.jvm.internal.Intrinsics {
+  void checkNotNull(...);
+  void checkExpressionValueIsNotNull(...);
+  void checkNotNullExpressionValue(...);
+  void checkReturnedValueIsNotNull(...);
+  void checkFieldIsNotNull(...);
+  void checkParameterIsNotNull(...);
+  void checkNotNullParameter(...);
+}
+
+-convertchecknotnull class dagger.internal.Preconditions {
+  ** checkNotNull*(...);
+}
diff --git a/core/proguard_basic_keeps.flags b/core/proguard_basic_keeps.flags
index f6b34b8217..a9416d5df0 100644
--- a/core/proguard_basic_keeps.flags
+++ b/core/proguard_basic_keeps.flags
@@ -1,7 +1,3 @@
-# Some classes in the libraries extend package private classes to chare common functionality
-# that isn't explicitly part of the API
--dontskipnonpubliclibraryclasses -dontskipnonpubliclibraryclassmembers
-
 # Preserve line number information for debugging stack traces.
 -keepattributes SourceFile,LineNumberTable
 
diff --git a/core/project_definitions.mk b/core/project_definitions.mk
index 184b03e019..5728b677e7 100644
--- a/core/project_definitions.mk
+++ b/core/project_definitions.mk
@@ -22,6 +22,3 @@
 # Include definitions for prebuilt SDK, if present.
 #
 -include prebuilts/sdk/current/definitions.mk
-
-# SDV-specific config.
--include system/software_defined_vehicle/platform/config.mk
diff --git a/core/release_config.mk b/core/release_config.mk
index fe2170ede4..c6986c704e 100644
--- a/core/release_config.mk
+++ b/core/release_config.mk
@@ -146,6 +146,9 @@ ifneq (,$(_use_protobuf))
         # This will also set ALL_RELEASE_CONFIGS_FOR_PRODUCT and _used_files for us.
         $(eval include $(_flags_file))
         $(KATI_extra_file_deps $(OUT_DIR)/release-config $(protobuf_map_files) $(_flags_file))
+        ifneq (,$(_disallow_lunch_use))
+            $(error Release config ${TARGET_RELEASE} is disallowed for build.  Please use one of: $(ALL_RELEASE_CONFIGS_FOR_PRODUCT))
+        endif
     else
         # This is the first pass of product config.
         $(eval include $(_flags_varmk))
@@ -153,20 +156,6 @@ ifneq (,$(_use_protobuf))
     _used_files :=
     ifeq (,$(_must_protobuf)$(RELEASE_BUILD_FLAGS_IN_PROTOBUF))
         _use_protobuf :=
-    else
-        _base_all_release := all_release_configs-$(TARGET_PRODUCT)
-        $(call dist-for-goals,droid,\
-            $(_flags_dir)/$(_base_all_release).pb:build_flags/all_release_configs.pb \
-            $(_flags_dir)/$(_base_all_release).textproto:build_flags/all_release_configs.textproto \
-            $(_flags_dir)/$(_base_all_release).json:build_flags/all_release_configs.json \
-            $(_flags_dir)/inheritance_graph-$(TARGET_PRODUCT).dot:build_flags/inheritance_graph-$(TARGET_PRODUCT).dot \
-        )
-# These are always created, add an empty rule for them to keep ninja happy.
-$(_flags_dir)/inheritance_graph-$(TARGET_PRODUCT).dot:
-	: created by $(OUT_DIR)/release-config
-$(_flags_dir)/$(_base_all_release).pb $(_flags_dir)/$(_base_all_release).textproto $(_flags_dir)/$(_base_all_release).json:
-	: created by $(OUT_DIR)/release-config
-        _base_all_release :=
     endif
     _flags_dir:=
     _flags_file:=
diff --git a/core/robolectric_test_config_template.xml b/core/robolectric_test_config_template.xml
index 1956b6eddf..509ac7bfba 100644
--- a/core/robolectric_test_config_template.xml
+++ b/core/robolectric_test_config_template.xml
@@ -18,7 +18,6 @@
     <option name="test-suite-tag" value="robolectric" />
     <option name="test-suite-tag" value="robolectric-tests" />
 
-    <option name="java-folder" value="prebuilts/jdk/jdk21/linux-x86/" />
     <option name="exclude-paths" value="java" />
     <option name="use-robolectric-resources" value="true" />
 
@@ -32,6 +31,9 @@
     {EXTRA_CONFIGS}
 
     <test class="com.android.tradefed.testtype.IsolatedHostTest" >
+
+        {EXTRA_TEST_RUNNER_CONFIGS}
+
         <option name="jar" value="{MODULE}.jar" />
         <option name="java-flags" value="--add-modules=jdk.compiler"/>
         <option name="java-flags" value="--add-opens=java.base/java.lang=ALL-UNNAMED"/>
diff --git a/core/soong_app_prebuilt.mk b/core/soong_app_prebuilt.mk
index ab9227f676..62b5d5bab1 100644
--- a/core/soong_app_prebuilt.mk
+++ b/core/soong_app_prebuilt.mk
@@ -142,7 +142,21 @@ endif
 # install symbol files of JNI libraries
 my_jni_lib_symbols_copy_files := $(foreach f,$(LOCAL_SOONG_JNI_LIBS_SYMBOLS),\
   $(call word-colon,1,$(f)):$(patsubst $(PRODUCT_OUT)/%,$(TARGET_OUT_UNSTRIPPED)/%,$(call word-colon,2,$(f))))
-$(LOCAL_BUILT_MODULE): | $(call copy-many-files, $(my_jni_lib_symbols_copy_files))
+
+$(foreach f, $(my_jni_lib_symbols_copy_files), \
+  $(eval $(call copy-unstripped-elf-file-with-mapping, \
+    $(call word-colon,1,$(f)), \
+    $(call word-colon,2,$(f)), \
+    $(patsubst $(TARGET_OUT_UNSTRIPPED)/%,$(call intermediates-dir-for,PACKAGING,elf_symbol_mapping)/%,$(call word-colon,2,$(f)).textproto)\
+  ))\
+)
+
+symbolic_outputs := $(foreach f,$(my_jni_lib_symbols_copy_files),$(call word-colon,2,$(f)))
+symbolic_mappings := $(foreach f,$(symbolic_outputs),$(patsubst $(TARGET_OUT_UNSTRIPPED)/%,$(call intermediates-dir-for,PACKAGING,elf_symbol_mapping)/%,$(f).textproto))
+ALL_MODULES.$(my_register_name).SYMBOLIC_OUTPUT_PATH := $(symbolic_outputs)
+ALL_MODULES.$(my_register_name).ELF_SYMBOL_MAPPING_PATH := $(symbolic_mappings)
+
+$(LOCAL_BUILT_MODULE): | $(symbolic_outputs)
 
 # embedded JNI will already have been handled by soong
 my_embed_jni :=
diff --git a/core/soong_cc_rust_prebuilt.mk b/core/soong_cc_rust_prebuilt.mk
index da608322f2..9ea24f7e46 100644
--- a/core/soong_cc_rust_prebuilt.mk
+++ b/core/soong_cc_rust_prebuilt.mk
@@ -190,7 +190,12 @@ ifndef LOCAL_IS_HOST_MODULE
       # drop /root as /root is mounted as /
       my_unstripped_path := $(patsubst $(TARGET_OUT_UNSTRIPPED)/root/%,$(TARGET_OUT_UNSTRIPPED)/%, $(my_unstripped_path))
       symbolic_output := $(my_unstripped_path)/$(my_installed_module_stem)
-      $(eval $(call copy-unstripped-elf-file-with-mapping,$(LOCAL_SOONG_UNSTRIPPED_BINARY),$(symbolic_output)))
+      elf_symbol_mapping_path := $(patsubst $(TARGET_OUT_UNSTRIPPED)/%,$(call intermediates-dir-for,PACKAGING,elf_symbol_mapping)/%,$(symbolic_output).textproto)
+
+      ALL_MODULES.$(my_register_name).SYMBOLIC_OUTPUT_PATH := $(symbolic_output)
+      ALL_MODULES.$(my_register_name).ELF_SYMBOL_MAPPING_PATH := $(elf_symbol_mapping_path)
+
+      $(eval $(call copy-unstripped-elf-file-with-mapping,$(LOCAL_SOONG_UNSTRIPPED_BINARY),$(symbolic_output),$(elf_symbol_mapping_path)))
       $(LOCAL_BUILT_MODULE): | $(symbolic_output)
 
       ifeq ($(BREAKPAD_GENERATE_SYMBOLS),true)
diff --git a/core/soong_config.mk b/core/soong_config.mk
index a007888b61..dcfe9ff6b3 100644
--- a/core/soong_config.mk
+++ b/core/soong_config.mk
@@ -38,6 +38,7 @@ $(call add_json_bool, DisplayBuildNumber,                $(filter true,$(DISPLAY
 $(call add_json_str,  Platform_display_version_name,     $(PLATFORM_DISPLAY_VERSION))
 $(call add_json_str,  Platform_version_name,             $(PLATFORM_VERSION))
 $(call add_json_val,  Platform_sdk_version,              $(PLATFORM_SDK_VERSION))
+$(call add_json_val,  Platform_sdk_version_full,         $(PLATFORM_SDK_VERSION_FULL))
 $(call add_json_str,  Platform_sdk_codename,             $(PLATFORM_VERSION_CODENAME))
 $(call add_json_bool, Platform_sdk_final,                $(filter REL,$(PLATFORM_VERSION_CODENAME)))
 $(call add_json_val,  Platform_sdk_extension_version,    $(PLATFORM_SDK_EXTENSION_VERSION))
@@ -196,6 +197,8 @@ $(call add_json_str,  OemPath,                           $(TARGET_COPY_OUT_OEM))
 $(call add_json_bool, MinimizeJavaDebugInfo,             $(filter true,$(PRODUCT_MINIMIZE_JAVA_DEBUG_INFO)))
 $(call add_json_str,  RecoveryPath,                      $(TARGET_COPY_OUT_RECOVERY))
 $(call add_json_bool, BuildingRecoveryImage,             $(BUILDING_RECOVERY_IMAGE))
+$(call add_json_str,  UserdataPath,                      $(TARGET_COPY_OUT_DATA))
+$(call add_json_bool, BuildingUserdataImage,             $(BUILDING_USERDATA_IMAGE))
 
 $(call add_json_bool, UseGoma,                           $(filter-out false,$(USE_GOMA)))
 $(call add_json_bool, UseRBE,                            $(filter-out false,$(USE_RBE)))
@@ -252,6 +255,8 @@ $(call add_json_list, TargetFSConfigGen,                 $(TARGET_FS_CONFIG_GEN)
 $(call add_json_bool, UseSoongSystemImage,               $(filter true,$(USE_SOONG_DEFINED_SYSTEM_IMAGE)))
 $(call add_json_str,  ProductSoongDefinedSystemImage,    $(PRODUCT_SOONG_DEFINED_SYSTEM_IMAGE))
 
+$(call add_json_bool, UseSoongNoticeXML, $(filter true,$(PRODUCT_USE_SOONG_NOTICE_XML)))
+
 $(call add_json_map, VendorVars)
 $(foreach namespace,$(sort $(SOONG_CONFIG_NAMESPACES)),\
   $(call add_json_map, $(namespace))\
@@ -358,8 +363,6 @@ $(call add_json_list, ProductPropFiles, $(TARGET_PRODUCT_PROP))
 $(call add_json_list, OdmPropFiles, $(TARGET_ODM_PROP))
 $(call add_json_list, VendorPropFiles, $(TARGET_VENDOR_PROP))
 
-$(call add_json_str, ExtraAllowedDepsTxt, $(EXTRA_ALLOWED_DEPS_TXT))
-
 # Do not set ArtTargetIncludeDebugBuild into any value if PRODUCT_ART_TARGET_INCLUDE_DEBUG_BUILD is not set,
 # to have the same behavior from runtime_libart.mk.
 ifneq ($(PRODUCT_ART_TARGET_INCLUDE_DEBUG_BUILD),)
@@ -370,6 +373,7 @@ _config_enable_uffd_gc := \
   $(firstword $(OVERRIDE_ENABLE_UFFD_GC) $(PRODUCT_ENABLE_UFFD_GC) default)
 $(call add_json_str, EnableUffdGc, $(_config_enable_uffd_gc))
 _config_enable_uffd_gc :=
+$(call add_json_str, BoardKernelVersion, $(BOARD_KERNEL_VERSION))
 
 $(call add_json_list, DeviceFrameworkCompatibilityMatrixFile, $(DEVICE_FRAMEWORK_COMPATIBILITY_MATRIX_FILE))
 $(call add_json_list, DeviceProductCompatibilityMatrixFile, $(DEVICE_PRODUCT_COMPATIBILITY_MATRIX_FILE))
@@ -382,9 +386,10 @@ $(call add_json_map, PartitionVarsForSoongMigrationOnlyDoNotUse)
   $(call add_json_str,  ProductDirectory,    $(dir $(INTERNAL_PRODUCT)))
 
   $(call add_json_map,PartitionQualifiedVariables)
-  $(foreach image_type,INIT_BOOT BOOT VENDOR_BOOT SYSTEM VENDOR CACHE USERDATA PRODUCT SYSTEM_EXT OEM ODM VENDOR_DLKM ODM_DLKM SYSTEM_DLKM, \
+  $(foreach image_type,INIT_BOOT BOOT VENDOR_BOOT SYSTEM VENDOR CACHE USERDATA PRODUCT SYSTEM_EXT OEM ODM VENDOR_DLKM ODM_DLKM SYSTEM_DLKM VBMETA VBMETA_SYSTEM VBMETA_SYSTEM_DLKM VBMETA_VENDOR_DLKM, \
     $(call add_json_map,$(call to-lower,$(image_type))) \
     $(call add_json_bool, BuildingImage, $(filter true,$(BUILDING_$(image_type)_IMAGE))) \
+    $(call add_json_bool, PrebuiltImage, $(filter true,$(BOARD_PREBUILT_$(image_type)IMAGE))) \
     $(call add_json_str, BoardErofsCompressor, $(BOARD_$(image_type)IMAGE_EROFS_COMPRESSOR)) \
     $(call add_json_str, BoardErofsCompressHints, $(BOARD_$(image_type)IMAGE_EROFS_COMPRESS_HINTS)) \
     $(call add_json_str, BoardErofsPclusterSize, $(BOARD_$(image_type)IMAGE_EROFS_PCLUSTER_SIZE)) \
@@ -440,6 +445,7 @@ $(call add_json_map, PartitionVarsForSoongMigrationOnlyDoNotUse)
   $(call add_json_str, BoardPrebuiltBootimage, $(BOARD_PREBUILT_BOOT_IMAGE))
   $(call add_json_str, BoardPrebuiltInitBootimage, $(BOARD_PREBUILT_INIT_BOOT_IMAGE))
   $(call add_json_str, BoardBootimagePartitionSize, $(BOARD_BOOTIMAGE_PARTITION_SIZE))
+  $(call add_json_str, BoardVendorBootimagePartitionSize, $(BOARD_VENDOR_BOOTIMAGE_PARTITION_SIZE))
   $(call add_json_str, BoardInitBootimagePartitionSize, $(BOARD_INIT_BOOT_IMAGE_PARTITION_SIZE))
   $(call add_json_str, BoardBootHeaderVersion, $(BOARD_BOOT_HEADER_VERSION))
   $(call add_json_str, TargetKernelPath, $(TARGET_KERNEL_PATH))
@@ -447,15 +453,22 @@ $(call add_json_map, PartitionVarsForSoongMigrationOnlyDoNotUse)
   $(call add_json_str, BootSecurityPatch, $(BOOT_SECURITY_PATCH))
   $(call add_json_str, InitBootSecurityPatch, $(INIT_BOOT_SECURITY_PATCH))
   $(call add_json_str, VendorSecurityPatch, $(VENDOR_SECURITY_PATCH))
+  $(call add_json_str, OdmSecurityPatch, $(ODM_SECURITY_PATCH))
+  $(call add_json_str, SystemDlkmSecurityPatch, $(SYSTEM_DLKM_SECURITY_PATCH))
+  $(call add_json_str, VendorDlkmSecurityPatch, $(VENDOR_DLKM_SECURITY_PATCH))
+  $(call add_json_str, OdmDlkmSecurityPatch, $(ODM_DLKM_SECURITY_PATCH))
   $(call add_json_bool, BoardIncludeDtbInBootimg, $(BOARD_INCLUDE_DTB_IN_BOOTIMG))
   $(call add_json_list, InternalKernelCmdline, $(INTERNAL_KERNEL_CMDLINE))
   $(call add_json_list, InternalBootconfig, $(INTERNAL_BOOTCONFIG))
   $(call add_json_str, InternalBootconfigFile, $(INTERNAL_BOOTCONFIG_FILE))
 
+  $(call add_json_bool, BuildingSystemOtherImage, $(BUILDING_SYSTEM_OTHER_IMAGE))
+
   # super image stuff
   $(call add_json_bool, ProductUseDynamicPartitions, $(filter true,$(PRODUCT_USE_DYNAMIC_PARTITIONS)))
   $(call add_json_bool, ProductRetrofitDynamicPartitions, $(filter true,$(PRODUCT_RETROFIT_DYNAMIC_PARTITIONS)))
   $(call add_json_bool, ProductBuildSuperPartition, $(filter true,$(PRODUCT_BUILD_SUPER_PARTITION)))
+  $(call add_json_bool, BuildingSuperEmptyImage, $(filter true,$(BUILDING_SUPER_EMPTY_IMAGE)))
   $(call add_json_str, BoardSuperPartitionSize, $(BOARD_SUPER_PARTITION_SIZE))
   $(call add_json_str, BoardSuperPartitionMetadataDevice, $(BOARD_SUPER_PARTITION_METADATA_DEVICE))
   $(call add_json_list, BoardSuperPartitionBlockDevices, $(BOARD_SUPER_PARTITION_BLOCK_DEVICES))
@@ -469,7 +482,15 @@ $(call add_json_map, PartitionVarsForSoongMigrationOnlyDoNotUse)
     $(call end_json_map)
   $(call add_json_bool, ProductVirtualAbOta, $(filter true,$(PRODUCT_VIRTUAL_AB_OTA)))
   $(call add_json_bool, ProductVirtualAbOtaRetrofit, $(filter true,$(PRODUCT_VIRTUAL_AB_OTA_RETROFIT)))
+  $(call add_json_bool, ProductVirtualAbCompression, $(filter true,$(PRODUCT_VIRTUAL_AB_COMPRESSION)))
+  $(call add_json_str, ProductVirtualAbCompressionMethod, $(PRODUCT_VIRTUAL_AB_COMPRESSION_METHOD))
+  $(call add_json_str, ProductVirtualAbCompressionFactor, $(PRODUCT_VIRTUAL_AB_COMPRESSION_FACTOR))
+  $(call add_json_str, ProductVirtualAbCowVersion, $(PRODUCT_VIRTUAL_AB_COW_VERSION))
   $(call add_json_bool, AbOtaUpdater, $(filter true,$(AB_OTA_UPDATER)))
+  $(call add_json_list, AbOtaPartitions, $(AB_OTA_PARTITIONS))
+  $(call add_json_list, AbOtaKeys, $(PRODUCT_OTA_PUBLIC_KEYS))
+  $(call add_json_list, AbOtaPostInstallConfig, $(AB_OTA_POSTINSTALL_CONFIG))
+  $(call add_json_bool, BoardSuperImageInUpdatePackage, $(filter true,$(BOARD_SUPER_IMAGE_IN_UPDATE_PACKAGE)))
 
   # Avb (android verified boot) stuff
   $(call add_json_bool, BoardAvbEnable, $(filter true,$(BOARD_AVB_ENABLE)))
@@ -525,6 +546,38 @@ $(call add_json_map, PartitionVarsForSoongMigrationOnlyDoNotUse)
   # Used to generate recovery partition
   $(call add_json_str, TargetScreenDensity, $(TARGET_SCREEN_DENSITY))
 
+  # Used to generate /recovery/root/build.prop
+  $(call add_json_map, PrivateRecoveryUiProperties)
+    $(call add_json_str, animation_fps, $(TARGET_RECOVERY_UI_ANIMATION_FPS))
+    $(call add_json_str, margin_height, $(TARGET_RECOVERY_UI_MARGIN_HEIGHT))
+    $(call add_json_str, margin_width, $(TARGET_RECOVERY_UI_MARGIN_WIDTH))
+    $(call add_json_str, menu_unusable_rows, $(TARGET_RECOVERY_UI_MENU_UNUSABLE_ROWS))
+    $(call add_json_str, progress_bar_baseline, $(TARGET_RECOVERY_UI_PROGRESS_BAR_BASELINE))
+    $(call add_json_str, touch_low_threshold, $(TARGET_RECOVERY_UI_TOUCH_LOW_THRESHOLD))
+    $(call add_json_str, touch_high_threshold, $(TARGET_RECOVERY_UI_TOUCH_HIGH_THRESHOLD))
+    $(call add_json_str, vr_stereo_offset, $(TARGET_RECOVERY_UI_VR_STEREO_OFFSET))
+    $(call add_json_str, brightness_file, $(TARGET_RECOVERY_UI_BRIGHTNESS_FILE))
+    $(call add_json_str, max_brightness_file, $(TARGET_RECOVERY_UI_MAX_BRIGHTNESS_FILE))
+    $(call add_json_str, brightness_normal_percent, $(TARGET_RECOVERY_UI_BRIGHTNESS_NORMAL))
+    $(call add_json_str, brightness_dimmed_percent, $(TARGET_RECOVERY_UI_BRIGHTNESS_DIMMED))
+  $(call end_json_map)
+
+  $(call add_json_str, PrebuiltBootloader, $(BOARD_PREBUILT_BOOTLOADER))
+
+  # Used to generate userdata partition
+  $(call add_json_str, ProductFsCasefold, $(PRODUCT_FS_CASEFOLD))
+  $(call add_json_str, ProductQuotaProjid, $(PRODUCT_QUOTA_PROJID))
+  $(call add_json_str, ProductFsCompression, $(PRODUCT_FS_COMPRESSION))
+
+  $(call add_json_str, ReleaseToolsExtensionDir, $(firstword $(TARGET_RELEASETOOLS_EXTENSIONS) $($(TARGET_DEVICE_DIR)/../common)))
+
+  $(call add_json_list, BoardPartialOtaUpdatePartitionsList, $(BOARD_PARTIAL_OTA_UPDATE_PARTITIONS_LIST))
+  $(call add_json_str, BoardFlashBlockSize, $(BOARD_FLASH_BLOCK_SIZE))
+  $(call add_json_bool, BootloaderInUpdatePackage, $(BOARD_BOOTLOADER_IN_UPDATE_PACKAGE))
+
+  # Fastboot
+  $(call add_json_str, BoardFastbootInfoFile, $(TARGET_BOARD_FASTBOOT_INFO_FILE))
+
 $(call end_json_map)
 
 # For converting vintf_data
diff --git a/core/soong_extra_config.mk b/core/soong_extra_config.mk
index 2ff83a1b77..8eee50ae00 100644
--- a/core/soong_extra_config.mk
+++ b/core/soong_extra_config.mk
@@ -80,7 +80,7 @@ $(call add_json_bool, PropertySplitEnabled, $(filter true,$(BOARD_PROPERTY_OVERR
 
 $(call add_json_str, ScreenDensity, $(TARGET_SCREEN_DENSITY))
 
-$(call add_json_bool, UsesVulkan, $(filter true,$(TARGET_USES_VULKAN)))
+$(call add_json_str, UsesVulkan, $(TARGET_USES_VULKAN))
 
 $(call add_json_bool, ZygoteForce64, $(filter true,$(ZYGOTE_FORCE_64)))
 
diff --git a/core/sysprop.mk b/core/sysprop.mk
index dcde71bd1e..4c040e497e 100644
--- a/core/sysprop.mk
+++ b/core/sysprop.mk
@@ -79,7 +79,7 @@ define generate-common-build-props
     echo "ro.$(1).build.version.release=$(PLATFORM_VERSION_LAST_STABLE)" >> $(2);\
     echo "ro.$(1).build.version.release_or_codename=$(PLATFORM_VERSION)" >> $(2);\
     echo "ro.$(1).build.version.sdk=$(PLATFORM_SDK_VERSION)" >> $(2);\
-    echo "ro.$(1).build.version.sdk_minor=$(PLATFORM_SDK_MINOR_VERSION)" >> $(2);\
+    echo "ro.$(1).build.version.sdk_full=$(PLATFORM_SDK_VERSION_FULL)" >> $(2);\
 
 endef
 
@@ -123,11 +123,19 @@ $(2): $(POST_PROCESS_PROPS) $(INTERNAL_BUILD_ID_MAKEFILE) $(3) $(6) $(BUILT_KERN
 ifneq ($(strip $(7)), true)
 	$(hide) $$(call generate-common-build-props,$(call to-lower,$(strip $(1))),$$@)
 endif
+        # Make and Soong use different intermediate files to build vendor/build.prop.
+        # Although the sysprop contents are same, the absolute paths of android-info.prop are different.
+        # Print the filename for the intermediate files (files in OUT_DIR).
+        # This helps with validating mk->soong migration of android partitions.
 	$(hide) $(foreach file,$(strip $(3)),\
 	    if [ -f "$(file)" ]; then\
 	        echo "" >> $$@;\
 	        echo "####################################" >> $$@;\
-	        echo "# from $(file)" >> $$@;\
+	        $(if $(filter $(OUT_DIR)/%,$(file)), \
+		echo "# from $(notdir $(file))" >> $$@;\
+		,\
+		echo "# from $(file)" >> $$@;\
+		)\
 	        echo "####################################" >> $$@;\
 	        cat $(file) >> $$@;\
 	    fi;)
@@ -153,61 +161,6 @@ endif
 $(call declare-1p-target,$(2))
 endef
 
-# -----------------------------------------------------------------
-# Define fingerprint, thumbprint, and version tags for the current build
-#
-# BUILD_VERSION_TAGS is a comma-separated list of tags chosen by the device
-# implementer that further distinguishes the build. It's basically defined
-# by the device implementer. Here, we are adding a mandatory tag that
-# identifies the signing config of the build.
-BUILD_VERSION_TAGS := $(BUILD_VERSION_TAGS)
-ifeq ($(TARGET_BUILD_TYPE),debug)
-  BUILD_VERSION_TAGS += debug
-endif
-# The "test-keys" tag marks builds signed with the old test keys,
-# which are available in the SDK.  "dev-keys" marks builds signed with
-# non-default dev keys (usually private keys from a vendor directory).
-# Both of these tags will be removed and replaced with "release-keys"
-# when the target-files is signed in a post-build step.
-ifeq ($(DEFAULT_SYSTEM_DEV_CERTIFICATE),build/make/target/product/security/testkey)
-BUILD_KEYS := test-keys
-else
-BUILD_KEYS := dev-keys
-endif
-BUILD_VERSION_TAGS += $(BUILD_KEYS)
-BUILD_VERSION_TAGS := $(subst $(space),$(comma),$(sort $(BUILD_VERSION_TAGS)))
-
-# BUILD_FINGERPRINT is used used to uniquely identify the combined build and
-# product; used by the OTA server.
-ifeq (,$(strip $(BUILD_FINGERPRINT)))
-  BUILD_FINGERPRINT := $(PRODUCT_BRAND)/$(TARGET_PRODUCT)/$(TARGET_DEVICE):$(PLATFORM_VERSION)/$(BUILD_ID)/$(BUILD_NUMBER_FROM_FILE):$(TARGET_BUILD_VARIANT)/$(BUILD_VERSION_TAGS)
-endif
-
-BUILD_FINGERPRINT_FILE := $(PRODUCT_OUT)/build_fingerprint.txt
-ifneq (,$(shell mkdir -p $(PRODUCT_OUT) && echo $(BUILD_FINGERPRINT) >$(BUILD_FINGERPRINT_FILE).tmp && (if ! cmp -s $(BUILD_FINGERPRINT_FILE).tmp $(BUILD_FINGERPRINT_FILE); then mv $(BUILD_FINGERPRINT_FILE).tmp $(BUILD_FINGERPRINT_FILE); else rm $(BUILD_FINGERPRINT_FILE).tmp; fi) && grep " " $(BUILD_FINGERPRINT_FILE)))
-  $(error BUILD_FINGERPRINT cannot contain spaces: "$(file <$(BUILD_FINGERPRINT_FILE))")
-endif
-BUILD_FINGERPRINT_FROM_FILE := $$(cat $(BUILD_FINGERPRINT_FILE))
-# unset it for safety.
-BUILD_FINGERPRINT :=
-
-# BUILD_THUMBPRINT is used to uniquely identify the system build; used by the
-# OTA server. This purposefully excludes any product-specific variables.
-ifeq (,$(strip $(BUILD_THUMBPRINT)))
-  BUILD_THUMBPRINT := $(PLATFORM_VERSION)/$(BUILD_ID)/$(BUILD_NUMBER_FROM_FILE):$(TARGET_BUILD_VARIANT)/$(BUILD_VERSION_TAGS)
-endif
-
-BUILD_THUMBPRINT_FILE := $(PRODUCT_OUT)/build_thumbprint.txt
-ifeq ($(strip $(HAS_BUILD_NUMBER)),true)
-$(BUILD_THUMBPRINT_FILE): $(BUILD_NUMBER_FILE)
-endif
-ifneq (,$(shell mkdir -p $(PRODUCT_OUT) && echo $(BUILD_THUMBPRINT) >$(BUILD_THUMBPRINT_FILE) && grep " " $(BUILD_THUMBPRINT_FILE)))
-  $(error BUILD_THUMBPRINT cannot contain spaces: "$(file <$(BUILD_THUMBPRINT_FILE))")
-endif
-# unset it for safety.
-BUILD_THUMBPRINT_FILE :=
-BUILD_THUMBPRINT :=
-
 KNOWN_OEM_THUMBPRINT_PROPERTIES := \
     ro.product.brand \
     ro.product.name \
@@ -231,7 +184,7 @@ _prop_files_ := $(if $(TARGET_VENDOR_PROP),\
     $(TARGET_VENDOR_PROP),\
     $(wildcard $(TARGET_DEVICE_DIR)/vendor.prop))
 
-android_info_prop := $(call intermediates-dir-for,ETC,android_info_prop)/android_info.prop
+android_info_prop := $(call intermediates-dir-for,ETC,android_info_prop)/android-info.prop
 $(android_info_prop): $(INSTALLED_ANDROID_INFO_TXT_TARGET)
 	cat $< | grep 'require version-' | sed -e 's/require version-/ro.build.expect./g' > $@
 
diff --git a/core/tasks/cts-v-host.mk b/core/tasks/cts-v-host.mk
new file mode 100644
index 0000000000..67cc0f21e4
--- /dev/null
+++ b/core/tasks/cts-v-host.mk
@@ -0,0 +1,29 @@
+# Copyright (C) 2024 The Android Open Source Project
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
+# cts-v-host includes host-side interactive and multi-device CTS tests that
+# cannot be fully automated. It is part of CTS Verifier.
+ifneq ($(wildcard cts/tools/cts-v-host/README),)
+test_suite_name := cts-v-host
+test_suite_tradefed := cts-v-host-tradefed
+test_suite_readme := cts/tools/cts-v-host/README
+test_suite_tools := $(HOST_OUT_JAVA_LIBRARIES)/ats_console_deploy.jar \
+  $(HOST_OUT_JAVA_LIBRARIES)/ats_olc_server_local_mode_deploy.jar
+
+include $(BUILD_SYSTEM)/tasks/tools/compatibility.mk
+
+.PHONY: cts-v-host
+cts-v-host: $(compatibility_zip) $(compatibility_tests_list_zip)
+$(call dist-for-goals, cts-v-host, $(compatibility_zip) $(compatibility_tests_list_zip))
+endif
diff --git a/core/tasks/cts.mk b/core/tasks/cts.mk
index 294cb577e2..c7b5cad5eb 100644
--- a/core/tasks/cts.mk
+++ b/core/tasks/cts.mk
@@ -78,14 +78,28 @@ verifier-dir-name := android-cts-verifier
 verifier-dir := $(cts-dir)/$(verifier-dir-name)
 verifier-zip-name := $(verifier-dir-name).zip
 verifier-zip := $(cts-dir)/$(verifier-zip-name)
+cts-v-host-zip := $(HOST_OUT)/cts-v-host/android-cts-v-host.zip
 
 cts : $(verifier-zip)
+ifeq ($(wildcard cts/tools/cts-v-host/README),)
 $(verifier-zip): PRIVATE_DIR := $(cts-dir)
 $(verifier-zip): $(SOONG_ANDROID_CTS_VERIFIER_ZIP)
 	rm -rf $(PRIVATE_DIR)
 	mkdir -p $(PRIVATE_DIR)
 	unzip -q -d $(PRIVATE_DIR) $<
 	$(copy-file-to-target)
+else
+$(verifier-zip): PRIVATE_DIR := $(cts-dir)
+$(verifier-zip): PRIVATE_verifier_dir := $(verifier-dir)
+$(verifier-zip): PRIVATE_host_zip := $(cts-v-host-zip)
+$(verifier-zip): $(SOONG_ANDROID_CTS_VERIFIER_ZIP) $(cts-v-host-zip) $(SOONG_ZIP)
+	rm -rf $(PRIVATE_DIR)
+	mkdir -p $(PRIVATE_DIR)
+	unzip -q -d $(PRIVATE_DIR) $<
+	unzip -q -d $(PRIVATE_verifier_dir) $(PRIVATE_host_zip)
+	$(SOONG_ZIP) -d -o $@ -C $(PRIVATE_DIR) -D $(PRIVATE_verifier_dir)
+endif
+$(call dist-for-goals, cts, $(verifier-zip))
 
 # For producing CTS coverage reports.
 # Run "make cts-test-coverage" in the $ANDROID_BUILD_TOP directory.
@@ -97,12 +111,28 @@ cts_api_map_exe := $(HOST_OUT_EXECUTABLES)/cts-api-map
 coverage_out := $(HOST_OUT)/cts-api-coverage
 api_map_out := $(HOST_OUT)/cts-api-map
 
-cts_jar_files := $(api_map_out)/api_map_files.txt
+cts_jar_files := $(api_map_out)/cts_jar_files.txt
+cts_v_host_jar_files := $(api_map_out)/cts_v_host_jar_files.txt
+cts_all_jar_files := $(api_map_out)/cts_all_jar_files.txt
+
 $(cts_jar_files): PRIVATE_API_MAP_FILES := $(sort $(COMPATIBILITY.cts.API_MAP_FILES))
 $(cts_jar_files):
 	mkdir -p $(dir $@)
 	echo $(PRIVATE_API_MAP_FILES) > $@
 
+$(cts_v_host_jar_files): PRIVATE_API_MAP_FILES := $(sort $(COMPATIBILITY.cts-v-host.API_MAP_FILES))
+$(cts_v_host_jar_files): $(SOONG_ANDROID_CTS_VERIFIER_APP_LIST)
+	mkdir -p $(dir $@)
+	cp $< $@
+	echo $(PRIVATE_API_MAP_FILES) >> $@
+
+$(cts_all_jar_files): PRIVATE_API_MAP_FILES := $(sort $(COMPATIBILITY.cts.API_MAP_FILES) \
+                                                      $(COMPATIBILITY.cts-v-host.API_MAP_FILES))
+$(cts_all_jar_files): $(SOONG_ANDROID_CTS_VERIFIER_APP_LIST)
+	mkdir -p $(dir $@)
+	cp $< $@
+	echo $(PRIVATE_API_MAP_FILES) >> $@
+
 api_xml_description := $(TARGET_OUT_COMMON_INTERMEDIATES)/api.xml
 
 napi_text_description := cts/tools/cts-api-coverage/etc/ndk-api.xml
@@ -113,6 +143,13 @@ $(napi_xml_description) : $(napi_text_description) $(ACP)
 		$(hide) $(ACP)  $< $@
 
 system_api_xml_description := $(TARGET_OUT_COMMON_INTERMEDIATES)/system-api.xml
+module_lib_api_xml_description := $(TARGET_OUT_COMMON_INTERMEDIATES)/module-lib-api.xml
+system_service_api_description := $(TARGET_OUT_COMMON_INTERMEDIATES)/system-server-api.xml
+
+combined_api_xml_description := $(api_xml_description) \
+  $(system_api_xml_description) \
+  $(module_lib_api_xml_description) \
+  $(system_service_api_description)
 
 cts-test-coverage-report := $(coverage_out)/test-coverage.html
 cts-system-api-coverage-report := $(coverage_out)/system-api-coverage.html
@@ -124,13 +161,15 @@ cts-combined-xml-coverage-report := $(coverage_out)/combined-coverage.xml
 cts_api_coverage_dependencies := $(cts_api_coverage_exe) $(dexdeps_exe) $(api_xml_description) $(napi_xml_description)
 cts_system_api_coverage_dependencies := $(cts_api_coverage_exe) $(dexdeps_exe) $(system_api_xml_description)
 
-cts-api-xml-api-map-report := $(api_map_out)/api-map.xml
-cts-api-html-api-map-report := $(api_map_out)/api-map.html
-cts-system-api-xml-api-map-report := $(api_map_out)/system-api-map.xml
-cts-system-api-html-api-map-report := $(api_map_out)/system-api-map.html
+cts-api-map-xml-report := $(api_map_out)/cts-api-map.xml
+cts-v-host-api-map-xml-report := $(api_map_out)/cts-v-host-api-map.xml
+cts-combined-api-map-xml-report := $(api_map_out)/cts-combined-api-map.xml
+cts-combined-api-map-html-report := $(api_map_out)/cts-combined-api-map.html
+cts-combined-api-inherit-xml-report := $(api_map_out)/cts-combined-api-inherit.xml
 
-cts_system_api_map_dependencies := $(cts_api_map_exe) $(system_api_xml_description) $(cts_jar_files)
-cts_api_map_dependencies := $(cts_api_map_exe) $(api_xml_description) $(cts_jar_files)
+cts_api_map_dependencies := $(cts_api_map_exe) $(combined_api_xml_description) $(cts_jar_files)
+cts_v_host_api_map_dependencies := $(cts_api_map_exe) $(combined_api_xml_description) $(cts_v_host_jar_files)
+cts_combined_api_map_dependencies := $(cts_api_map_exe) $(combined_api_xml_description) $(cts_all_jar_files)
 
 android_cts_zip := $(HOST_OUT)/cts/android-cts.zip
 cts_verifier_apk := $(call intermediates-dir-for,APPS,CtsVerifier)/package.apk
@@ -210,54 +249,57 @@ cts-combined-xml-coverage : $(cts-combined-xml-coverage-report)
 .PHONY: cts-coverage-report-all cts-api-coverage
 cts-coverage-report-all: cts-test-coverage cts-verifier-coverage cts-combined-coverage cts-combined-xml-coverage
 
-$(cts-system-api-xml-api-map-report): PRIVATE_CTS_API_MAP_EXE := $(cts_api_map_exe)
-$(cts-system-api-xml-api-map-report): PRIVATE_API_XML_DESC := $(system_api_xml_description)
-$(cts-system-api-xml-api-map-report): PRIVATE_JAR_FILES := $(cts_jar_files)
-$(cts-system-api-xml-api-map-report) : $(android_cts_zip) $(cts_system_api_map_dependencies) | $(ACP)
-	$(call generate-api-map-report-cts,"CTS System API MAP Report - XML",\
+$(cts-api-map-xml-report): PRIVATE_CTS_API_MAP_EXE := $(cts_api_map_exe)
+$(cts-api-map-xml-report): PRIVATE_API_XML_DESC := $(combined_api_xml_description)
+$(cts-api-map-xml-report): PRIVATE_JAR_FILES := $(cts_jar_files)
+$(cts-api-map-xml-report) : $(android_cts_zip) $(cts_api_map_dependencies) | $(ACP)
+	$(call generate-api-map-report-cts,"CTS API MAP Report - XML",\
 			$(PRIVATE_JAR_FILES),xml)
 
-$(cts-system-api-html-api-map-report): PRIVATE_CTS_API_MAP_EXE := $(cts_api_map_exe)
-$(cts-system-api-html-api-map-report): PRIVATE_API_XML_DESC := $(system_api_xml_description)
-$(cts-system-api-html-api-map-report): PRIVATE_JAR_FILES := $(cts_jar_files)
-$(cts-system-api-html-api-map-report) : $(android_cts_zip) $(cts_system_api_map_dependencies) | $(ACP)
-	$(call generate-api-map-report-cts,"CTS System API MAP Report - HTML",\
-			$(PRIVATE_JAR_FILES),html)
+$(cts-v-host-api-map-xml-report): PRIVATE_CTS_API_MAP_EXE := $(cts_api_map_exe)
+$(cts-v-host-api-map-xml-report): PRIVATE_API_XML_DESC := $(combined_api_xml_description)
+$(cts-v-host-api-map-xml-report): PRIVATE_JAR_FILES := $(cts_v_host_jar_files)
+$(cts-v-host-api-map-xml-report) : $(verifier_zip) $(cts_v_host_api_map_dependencies) | $(ACP)
+	$(call generate-api-map-report-cts,"CTS-V-HOST API MAP Report - XML",\
+			$(PRIVATE_JAR_FILES),xml)
 
-$(cts-api-xml-api-map-report): PRIVATE_CTS_API_MAP_EXE := $(cts_api_map_exe)
-$(cts-api-xml-api-map-report): PRIVATE_API_XML_DESC := $(api_xml_description)
-$(cts-api-xml-api-map-report): PRIVATE_JAR_FILES := $(cts_jar_files)
-$(cts-api-xml-api-map-report) : $(android_cts_zip) $(cts_api_map_dependencies) | $(ACP)
-	$(call generate-api-map-report-cts,"CTS API MAP Report - XML",\
+$(cts-combined-api-map-xml-report): PRIVATE_CTS_API_MAP_EXE := $(cts_api_map_exe)
+$(cts-combined-api-map-xml-report): PRIVATE_API_XML_DESC := $(combined_api_xml_description)
+$(cts-combined-api-map-xml-report): PRIVATE_JAR_FILES := $(cts_all_jar_files)
+$(cts-combined-api-map-xml-report) : $(verifier_zip) $(android_cts_zip) $(cts_combined_api_map_dependencies) | $(ACP)
+	$(call generate-api-map-report-cts,"CTS Combined API MAP Report - XML",\
 			$(PRIVATE_JAR_FILES),xml)
 
-$(cts-api-html-api-map-report): PRIVATE_CTS_API_MAP_EXE := $(cts_api_map_exe)
-$(cts-api-html-api-map-report): PRIVATE_API_XML_DESC := $(api_xml_description)
-$(cts-api-html-api-map-report): PRIVATE_JAR_FILES := $(cts_jar_files)
-$(cts-api-html-api-map-report) : $(android_cts_zip) $(cts_api_map_dependencies) | $(ACP)
-	$(call generate-api-map-report-cts,"CTS API MAP Report - HTML",\
+$(cts-combined-api-map-html-report): PRIVATE_CTS_API_MAP_EXE := $(cts_api_map_exe)
+$(cts-combined-api-map-html-report): PRIVATE_API_XML_DESC := $(combined_api_xml_description)
+$(cts-combined-api-map-html-report): PRIVATE_JAR_FILES := $(cts_all_jar_files)
+$(cts-combined-api-map-html-report) : $(verifier_zip) $(android_cts_zip) $(cts_combined_api_map_dependencies) | $(ACP)
+	$(call generate-api-map-report-cts,"CTS Combined API MAP Report - HTML",\
 			$(PRIVATE_JAR_FILES),html)
 
-.PHONY: cts-system-api-xml-api-map
-cts-system-api-xml-api-map : $(cts-system-api-xml-api-map-report)
+$(cts-combined-api-inherit-xml-report): PRIVATE_CTS_API_MAP_EXE := $(cts_api_map_exe)
+$(cts-combined-api-inherit-xml-report): PRIVATE_API_XML_DESC := $(combined_api_xml_description)
+$(cts-combined-api-inherit-xml-report): PRIVATE_JAR_FILES := $(cts_all_jar_files)
+$(cts-combined-api-inherit-xml-report) : $(verifier_zip) $(android_cts_zip) $(cts_combined_api_map_dependencies) | $(ACP)
+	$(call generate-api-inherit-report-cts,"CTS Combined API Inherit Report - XML",\
+			$(PRIVATE_JAR_FILES),xml)
+
+.PHONY: cts-api-map-xml
+cts-api-map-xml : $(cts-api-map-xml-report)
 
-.PHONY: cts-system-api-html-api-map
-cts-system-api-html-api-map : $(cts-system-api-html-api-map-report)
+.PHONY: cts-v-host-api-map-xml
+cts-v-host-api-map-xml: $(cts-v-host-api-map-xml-report)
 
-.PHONY: cts-api-xml-api-map
-cts-api-xml-api-map : $(cts-api-xml-api-map-report)
+.PHONY: cts-combined-api-map-xml
+cts-combined-api-map-xml : $(cts-combined-api-map-xml-report)
 
-.PHONY: cts-api-html-api-map
-cts-api-html-api-map : $(cts-api-html-api-map-report)
+.PHONY: cts-combined-api-inherit-xml
+cts-combined-api-inherit-xml : $(cts-combined-api-inherit-xml-report)
 
 .PHONY: cts-api-map-all
 
 # Put the test coverage report in the dist dir if "cts-api-coverage" is among the build goals.
-$(call dist-for-goals, cts-api-coverage, $(cts-test-coverage-report):cts-test-coverage-report.html)
-$(call dist-for-goals, cts-api-coverage, $(cts-system-api-coverage-report):cts-system-api-coverage-report.html)
 $(call dist-for-goals, cts-api-coverage, $(cts-system-api-xml-coverage-report):cts-system-api-coverage-report.xml)
-$(call dist-for-goals, cts-api-coverage, $(cts-verifier-coverage-report):cts-verifier-coverage-report.html)
-$(call dist-for-goals, cts-api-coverage, $(cts-combined-coverage-report):cts-combined-coverage-report.html)
 $(call dist-for-goals, cts-api-coverage, $(cts-combined-xml-coverage-report):cts-combined-coverage-report.xml)
 
 ALL_TARGETS.$(cts-test-coverage-report).META_LIC:=$(module_license_metadata)
@@ -268,15 +310,14 @@ ALL_TARGETS.$(cts-combined-coverage-report).META_LIC:=$(module_license_metadata)
 ALL_TARGETS.$(cts-combined-xml-coverage-report).META_LIC:=$(module_license_metadata)
 
 # Put the test api map report in the dist dir if "cts-api-map-all" is among the build goals.
-$(call dist-for-goals, cts-api-map-all, $(cts-system-api-xml-api-map-report):cts-system-api-xml-api-map-report.xml)
-$(call dist-for-goals, cts-api-map-all, $(cts-system-api-html-api-map-report):cts-system-api-html-api-map-report.html)
-$(call dist-for-goals, cts-api-map-all, $(cts-api-xml-api-map-report):cts-api-xml-api-map-report.xml)
-$(call dist-for-goals, cts-api-map-all, $(cts-api-html-api-map-report):cts-api-html-api-map-report.html)
+$(call dist-for-goals, cts-api-map-all, $(cts-combined-api-map-xml-report):cts-api-map-report.xml)
+$(call dist-for-goals, cts-api-map-all, $(cts-combined-api-inherit-xml-report):cts-api-inherit-report.xml)
 
-ALL_TARGETS.$(cts-system-api-xml-api-map-report).META_LIC:=$(module_license_metadata)
-ALL_TARGETS.$(cts-system-api-html-api-map-report).META_LIC:=$(module_license_metadata)
-ALL_TARGETS.$(cts-api-xml-api-map-report).META_LIC:=$(module_license_metadata)
-ALL_TARGETS.$(cts-api-html-api-map-report).META_LIC:=$(module_license_metadata)
+ALL_TARGETS.$(cts-api-map-xml-report).META_LIC:=$(module_license_metadata)
+ALL_TARGETS.$(cts-v-host-api-map-xml-report).META_LIC:=$(module_license_metadata)
+ALL_TARGETS.$(cts-combined-api-map-xml-report).META_LIC:=$(module_license_metadata)
+ALL_TARGETS.$(cts-combined-api-map-html-report).META_LIC:=$(module_license_metadata)
+ALL_TARGETS.$(cts-combined-api-map-inherit-report).META_LIC:=$(module_license_metadata)
 
 # Arguments;
 #  1 - Name of the report printed out on the screen
@@ -294,7 +335,18 @@ endef
 #  3 - Format of the report
 define generate-api-map-report-cts
 	$(hide) mkdir -p $(dir $@)
-	$(hide) $(PRIVATE_CTS_API_MAP_EXE) -j 8 -a $(PRIVATE_API_XML_DESC) -i $(2) -f $(3) -o $@
+	$(hide) $(PRIVATE_CTS_API_MAP_EXE) -j 8 -m api_map -m xts_annotation -a $(shell echo "$(PRIVATE_API_XML_DESC)" | tr ' ' ',') -i $(2) -f $(3) -o $@
+	@ echo $(1): file://$$(cd $(dir $@); pwd)/$(notdir $@)
+endef
+
+
+# Arguments;
+#  1 - Name of the report printed out on the screen
+#  2 - A file containing list of files that to be analyzed
+#  3 - Format of the report
+define generate-api-inherit-report-cts
+	$(hide) mkdir -p $(dir $@)
+	$(hide) $(PRIVATE_CTS_API_MAP_EXE) -j 8 -m xts_api_inherit -a $(shell echo "$(PRIVATE_API_XML_DESC)" | tr ' ' ',') -i $(2) -f $(3) -o $@
 	@ echo $(1): file://$$(cd $(dir $@); pwd)/$(notdir $@)
 endef
 
@@ -302,20 +354,23 @@ endef
 cts_api_coverage_dependencies :=
 cts_system_api_coverage_dependencies :=
 cts_api_map_dependencies :=
-cts_system_api_map_dependencies :=
+cts_v_host_api_map_dependencies :=
+cts_combined_api_map_dependencies :=
 cts-combined-coverage-report :=
 cts-combined-xml-coverage-report :=
 cts-verifier-coverage-report :=
 cts-test-coverage-report :=
 cts-system-api-coverage-report :=
 cts-system-api-xml-coverage-report :=
-cts-api-xml-api-map-report :=
-cts-api-html-api-map-report :=
-cts-system-api-xml-api-map-report :=
-cts-system-api-html-api-map-report :=
+cts-api-map-xml-report :=
+cts-v-host-api-map-xml-report :=
+cts-combined-api-map-xml-report :=
+cts-combined-api-map-html-report :=
+cts-combined-api-map-inherit-report :=
 api_xml_description :=
 api_text_description :=
 system_api_xml_description :=
+combined_api_xml_description :=
 napi_xml_description :=
 napi_text_description :=
 coverage_out :=
@@ -331,3 +386,4 @@ verifier-dir-name :=
 verifier-dir :=
 verifier-zip-name :=
 verifier-zip :=
+cts-v-host-zip :=
diff --git a/core/tasks/device-tests.mk b/core/tasks/device-tests.mk
index 6164c2e94b..209bd3e28a 100644
--- a/core/tasks/device-tests.mk
+++ b/core/tasks/device-tests.mk
@@ -14,7 +14,7 @@
 
 
 .PHONY: device-tests
-.PHONY: device-tests-host-shared-libs
+.PHONY: device-tests-files-list
 
 device-tests-zip := $(PRODUCT_OUT)/device-tests.zip
 # Create an artifact to include a list of test config files in device-tests.
@@ -22,7 +22,7 @@ device-tests-list-zip := $(PRODUCT_OUT)/device-tests_list.zip
 # Create an artifact to include all test config files in device-tests.
 device-tests-configs-zip := $(PRODUCT_OUT)/device-tests_configs.zip
 my_host_shared_lib_for_device_tests := $(call copy-many-files,$(COMPATIBILITY.device-tests.HOST_SHARED_LIBRARY.FILES))
-device_tests_host_shared_libs_zip := $(PRODUCT_OUT)/device-tests_host-shared-libs.zip
+device_tests_files_list := $(PRODUCT_OUT)/device-tests_files
 
 $(device-tests-zip) : .KATI_IMPLICIT_OUTPUTS := $(device-tests-list-zip) $(device-tests-configs-zip)
 $(device-tests-zip) : PRIVATE_device_tests_list := $(PRODUCT_OUT)/device-tests_list
@@ -47,22 +47,16 @@ $(device-tests-zip) : $(COMPATIBILITY.device-tests.FILES) $(COMPATIBILITY.device
 	rm -f $@.list $@-host.list $@-target.list $@-host-test-configs.list $@-target-test-configs.list \
 		$(PRIVATE_device_tests_list)
 
-$(device_tests_host_shared_libs_zip) : PRIVATE_device_host_shared_libs_zip := $(device_tests_host_shared_libs_zip)
-$(device_tests_host_shared_libs_zip) : PRIVATE_HOST_SHARED_LIBS := $(my_host_shared_lib_for_device_tests)
-$(device_tests_host_shared_libs_zip) : $(my_host_shared_lib_for_device_tests) $(SOONG_ZIP)
-	rm -f $@-shared-libs.list
-	$(hide) for shared_lib in $(PRIVATE_HOST_SHARED_LIBS); do \
-	  echo $$shared_lib >> $@-shared-libs.list; \
-	done
-	grep $(HOST_OUT_TESTCASES) $@-shared-libs.list > $@-host-shared-libs.list || true
-	$(SOONG_ZIP) -d -o $(PRIVATE_device_host_shared_libs_zip) \
-	  -P host -C $(HOST_OUT) -l $@-host-shared-libs.list
+$(device_tests_files_list) : PRIVATE_HOST_SHARED_LIBS := $(my_host_shared_lib_for_device_tests)
+$(device_tests_files_list) :
+	echo $(sort $(COMPATIBILITY.device-tests.FILES) $(COMPATIBILITY.device-tests.SOONG_INSTALLED_COMPATIBILITY_SUPPORT_FILES)) | tr " " "\n" > $@.full_list
+	grep $(HOST_OUT_TESTCASES) $@.full_list > $@ || true
+	grep $(TARGET_OUT_TESTCASES) $@.full_list >> $@ || true
 
 device-tests: $(device-tests-zip)
-device-tests-host-shared-libs: $(device_tests_host_shared_libs_zip)
+device-tests-files-list: $(device_tests_files_list)
 
-$(call dist-for-goals, device-tests, $(device-tests-zip) $(device-tests-list-zip) $(device-tests-configs-zip) $(device_tests_host_shared_libs_zip))
-$(call dist-for-goals, device-tests-host-shared-libs, $(device_tests_host_shared_libs_zip))
+$(call dist-for-goals, device-tests, $(device-tests-zip) $(device-tests-list-zip) $(device-tests-configs-zip))
 
 $(call declare-1p-container,$(device-tests-zip),)
 $(call declare-container-license-deps,$(device-tests-zip),$(COMPATIBILITY.device-tests.FILES) $(my_host_shared_lib_for_device_tests),$(PRODUCT_OUT)/:/)
diff --git a/core/tasks/general-tests-shared-libs.mk b/core/tasks/general-tests-shared-libs.mk
deleted file mode 100644
index 240514073e..0000000000
--- a/core/tasks/general-tests-shared-libs.mk
+++ /dev/null
@@ -1,52 +0,0 @@
-# Copyright (C) 2024 The Android Open Source Project
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#      http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-
-.PHONY: general-tests-shared-libs
-
-intermediates_dir := $(call intermediates-dir-for,PACKAGING,general-tests-shared-libs)
-
-general_tests_shared_libs_zip := $(PRODUCT_OUT)/general-tests_host-shared-libs.zip
-
-# Filter shared entries between general-tests and device-tests's HOST_SHARED_LIBRARY.FILES,
-# to avoid warning about overriding commands.
-my_host_shared_lib_for_general_tests := \
-  $(foreach m,$(filter $(COMPATIBILITY.device-tests.HOST_SHARED_LIBRARY.FILES),\
-	   $(COMPATIBILITY.general-tests.HOST_SHARED_LIBRARY.FILES)),$(call word-colon,2,$(m)))
-my_general_tests_shared_lib_files := \
-  $(filter-out $(COMPATIBILITY.device-tests.HOST_SHARED_LIBRARY.FILES),\
-	 $(COMPATIBILITY.general-tests.HOST_SHARED_LIBRARY.FILES))
-
-my_host_shared_lib_for_general_tests += $(call copy-many-files,$(my_general_tests_shared_lib_files))
-
-$(general_tests_shared_libs_zip) : PRIVATE_INTERMEDIATES_DIR := $(intermediates_dir)
-$(general_tests_shared_libs_zip) : PRIVATE_HOST_SHARED_LIBS := $(my_host_shared_lib_for_general_tests)
-$(general_tests_shared_libs_zip) : PRIVATE_general_host_shared_libs_zip := $(general_tests_shared_libs_zip)
-$(general_tests_shared_libs_zip) : $(my_host_shared_lib_for_general_tests) $(SOONG_ZIP)
-	rm -rf $(PRIVATE_INTERMEDIATES_DIR)
-	mkdir -p $(PRIVATE_INTERMEDIATES_DIR) $(PRIVATE_INTERMEDIATES_DIR)/tools
-	$(hide) for shared_lib in $(PRIVATE_HOST_SHARED_LIBS); do \
-	  echo $$shared_lib >> $(PRIVATE_INTERMEDIATES_DIR)/shared-libs.list; \
-	done
-	grep $(HOST_OUT_TESTCASES) $(PRIVATE_INTERMEDIATES_DIR)/shared-libs.list > $(PRIVATE_INTERMEDIATES_DIR)/host-shared-libs.list || true
-	$(SOONG_ZIP) -d -o $(PRIVATE_general_host_shared_libs_zip) \
-	  -P host -C $(HOST_OUT) -l $(PRIVATE_INTERMEDIATES_DIR)/host-shared-libs.list
-
-general-tests-shared-libs: $(general_tests_shared_libs_zip)
-$(call dist-for-goals, general-tests-shared-libs, $(general_tests_shared_libs_zip))
-
-$(call declare-1p-container,$(general_tests_shared_libs_zip),)
-$(call declare-container-license-deps,$(general_tests_shared_libs_zip),$(my_host_shared_lib_for_general_tests),$(PRODUCT_OUT)/:/)
-
-intermediates_dir :=
-general_tests_shared_libs_zip :=
diff --git a/core/tasks/general-tests.mk b/core/tasks/general-tests.mk
index 1901ed5658..44476cb178 100644
--- a/core/tasks/general-tests.mk
+++ b/core/tasks/general-tests.mk
@@ -13,6 +13,7 @@
 # limitations under the License.
 
 .PHONY: general-tests
+.PHONY: general-tests-files-list
 
 general_tests_tools := \
     $(HOST_OUT_JAVA_LIBRARIES)/cts-tradefed.jar \
@@ -27,19 +28,65 @@ general_tests_list_zip := $(PRODUCT_OUT)/general-tests_list.zip
 # Create an artifact to include all test config files in general-tests.
 general_tests_configs_zip := $(PRODUCT_OUT)/general-tests_configs.zip
 
-general_tests_shared_libs_zip := $(PRODUCT_OUT)/general-tests_host-shared-libs.zip
+# Filter shared entries between general-tests and device-tests's HOST_SHARED_LIBRARY.FILES,
+# to avoid warning about overriding commands.
+my_host_shared_lib_for_general_tests := \
+  $(foreach m,$(filter $(COMPATIBILITY.device-tests.HOST_SHARED_LIBRARY.FILES),\
+	   $(COMPATIBILITY.general-tests.HOST_SHARED_LIBRARY.FILES)),$(call word-colon,2,$(m)))
+my_general_tests_shared_lib_files := \
+  $(filter-out $(COMPATIBILITY.device-tests.HOST_SHARED_LIBRARY.FILES),\
+	 $(COMPATIBILITY.general-tests.HOST_SHARED_LIBRARY.FILES))
+
+my_host_shared_lib_for_general_tests += $(call copy-many-files,$(my_general_tests_shared_lib_files))
+
+my_host_shared_lib_symlinks := \
+    $(filter $(COMPATIBILITY.host-unit-tests.SYMLINKS),\
+	$(COMPATIBILITY.general-tests.SYMLINKS))
+
+my_general_tests_symlinks := \
+    $(filter-out $(COMPATIBILITY.camera-hal-tests.SYMLINKS),\
+    $(filter-out $(COMPATIBILITY.host-unit-tests.SYMLINKS),\
+	 $(COMPATIBILITY.general-tests.SYMLINKS)))
+
+my_symlinks_for_general_tests := $(foreach f,$(my_general_tests_symlinks),\
+	$(strip $(eval _cmf_tuple := $(subst :, ,$(f))) \
+	$(eval _cmf_dep := $(word 1,$(_cmf_tuple))) \
+	$(eval _cmf_src := $(word 2,$(_cmf_tuple))) \
+	$(eval _cmf_dest := $(word 3,$(_cmf_tuple))) \
+	$(call symlink-file,$(_cmf_dep),$(_cmf_src),$(_cmf_dest)) \
+	$(_cmf_dest)))
+
+# In this one directly take the overlap into the zip since we can't rewrite rules
+my_symlinks_for_general_tests += $(foreach f,$(my_host_shared_lib_symlinks),\
+        $(strip $(eval _cmf_tuple := $(subst :, ,$(f))) \
+        $(eval _cmf_dep := $(word 1,$(_cmf_tuple))) \
+        $(eval _cmf_src := $(word 2,$(_cmf_tuple))) \
+        $(eval _cmf_dest := $(word 3,$(_cmf_tuple))) \
+        $(_cmf_dest)))
+
+general_tests_files_list := $(PRODUCT_OUT)/general-tests_files
+general_tests_host_files_list := $(PRODUCT_OUT)/general-tests_host_files
+general_tests_target_files_list := $(PRODUCT_OUT)/general-tests_target_files
 
-$(general_tests_zip) : $(general_tests_shared_libs_zip)
 $(general_tests_zip) : PRIVATE_general_tests_list_zip := $(general_tests_list_zip)
 $(general_tests_zip) : .KATI_IMPLICIT_OUTPUTS := $(general_tests_list_zip) $(general_tests_configs_zip)
 $(general_tests_zip) : PRIVATE_TOOLS := $(general_tests_tools)
 $(general_tests_zip) : PRIVATE_INTERMEDIATES_DIR := $(intermediates_dir)
+$(general_tests_zip) : PRIVATE_HOST_SHARED_LIBS := $(my_host_shared_lib_for_general_tests)
+$(general_tests_zip) : PRIVATE_SYMLINKS := $(my_symlinks_for_general_tests)
 $(general_tests_zip) : PRIVATE_general_tests_configs_zip := $(general_tests_configs_zip)
-$(general_tests_zip) : $(COMPATIBILITY.general-tests.FILES) $(COMPATIBILITY.general-tests.SOONG_INSTALLED_COMPATIBILITY_SUPPORT_FILES) $(general_tests_tools) $(SOONG_ZIP)
+$(general_tests_zip) : $(COMPATIBILITY.general-tests.FILES) $(my_host_shared_lib_for_general_tests) $(COMPATIBILITY.general-tests.SOONG_INSTALLED_COMPATIBILITY_SUPPORT_FILES) $(general_tests_tools) $(my_symlinks_for_general_tests) $(SOONG_ZIP)
 	rm -rf $(PRIVATE_INTERMEDIATES_DIR)
 	rm -f $@ $(PRIVATE_general_tests_list_zip)
 	mkdir -p $(PRIVATE_INTERMEDIATES_DIR) $(PRIVATE_INTERMEDIATES_DIR)/tools
 	echo $(sort $(COMPATIBILITY.general-tests.FILES) $(COMPATIBILITY.general-tests.SOONG_INSTALLED_COMPATIBILITY_SUPPORT_FILES)) | tr " " "\n" > $(PRIVATE_INTERMEDIATES_DIR)/list
+	for symlink in $(PRIVATE_SYMLINKS); do \
+	  echo $$symlink >> $(PRIVATE_INTERMEDIATES_DIR)/list; \
+	done
+	$(hide) for shared_lib in $(PRIVATE_HOST_SHARED_LIBS); do \
+	  echo $$shared_lib >> $(PRIVATE_INTERMEDIATES_DIR)/shared-libs.list; \
+	done
+	grep $(HOST_OUT_TESTCASES) $(PRIVATE_INTERMEDIATES_DIR)/shared-libs.list > $(PRIVATE_INTERMEDIATES_DIR)/host-shared-libs.list || true
 	grep $(HOST_OUT_TESTCASES) $(PRIVATE_INTERMEDIATES_DIR)/list > $(PRIVATE_INTERMEDIATES_DIR)/host.list || true
 	grep $(TARGET_OUT_TESTCASES) $(PRIVATE_INTERMEDIATES_DIR)/list > $(PRIVATE_INTERMEDIATES_DIR)/target.list || true
 	grep -e .*\\.config$$ $(PRIVATE_INTERMEDIATES_DIR)/host.list > $(PRIVATE_INTERMEDIATES_DIR)/host-test-configs.list || true
@@ -49,6 +96,7 @@ $(general_tests_zip) : $(COMPATIBILITY.general-tests.FILES) $(COMPATIBILITY.gene
 	  -P host -C $(PRIVATE_INTERMEDIATES_DIR) -D $(PRIVATE_INTERMEDIATES_DIR)/tools \
 	  -P host -C $(HOST_OUT) -l $(PRIVATE_INTERMEDIATES_DIR)/host.list \
 	  -P target -C $(PRODUCT_OUT) -l $(PRIVATE_INTERMEDIATES_DIR)/target.list \
+	  -P host -C $(HOST_OUT) -l $(PRIVATE_INTERMEDIATES_DIR)/host-shared-libs.list \
 	  -sha256
 	$(SOONG_ZIP) -d -o $(PRIVATE_general_tests_configs_zip) \
 	  -P host -C $(HOST_OUT) -l $(PRIVATE_INTERMEDIATES_DIR)/host-test-configs.list \
@@ -57,7 +105,16 @@ $(general_tests_zip) : $(COMPATIBILITY.general-tests.FILES) $(COMPATIBILITY.gene
 	grep -e .*\\.config$$ $(PRIVATE_INTERMEDIATES_DIR)/target.list | sed s%$(PRODUCT_OUT)%target%g >> $(PRIVATE_INTERMEDIATES_DIR)/general-tests_list
 	$(SOONG_ZIP) -d -o $(PRIVATE_general_tests_list_zip) -C $(PRIVATE_INTERMEDIATES_DIR) -f $(PRIVATE_INTERMEDIATES_DIR)/general-tests_list
 
+$(general_tests_files_list) : PRIVATE_INTERMEDIATES_DIR := $(intermediates_dir)
+$(general_tests_files_list) : PRIVATE_general_tests_host_files_list := $(general_tests_host_files_list)
+$(general_tests_files_list) : PRIVATE_general_tests_target_files_list := $(general_tests_target_files_list)
+$(general_tests_files_list) :
+	echo $(sort $(COMPATIBILITY.general-tests.FILES) $(COMPATIBILITY.device-tests.SOONG_INSTALLED_COMPATIBILITY_SUPPORT_FILES)) | tr " " "\n" > $@
+	grep $(HOST_OUT_TESTCASES) $@ > $(PRIVATE_general_tests_host_files_list) || true
+	grep $(TARGET_OUT_TESTCASES) $@ >> $(PRIVATE_general_tests_target_files_list) || true
+
 general-tests: $(general_tests_zip)
+general-tests-files-list: $(general_tests_files_list)
 $(call dist-for-goals, general-tests, $(general_tests_zip) $(general_tests_list_zip) $(general_tests_configs_zip) $(general_tests_shared_libs_zip))
 
 $(call declare-1p-container,$(general_tests_zip),)
@@ -69,3 +126,8 @@ general_tests_zip :=
 general_tests_list_zip :=
 general_tests_configs_zip :=
 general_tests_shared_libs_zip :=
+my_host_shared_lib_for_general_tests :=
+my_symlinks_for_general_tests :=
+my_general_tests_shared_lib_files :=
+my_general_tests_symlinks :=
+my_host_shared_lib_symlinks :=
diff --git a/core/tasks/meta-lic.mk b/core/tasks/meta-lic.mk
index 620b1e29ae..0675a901c2 100644
--- a/core/tasks/meta-lic.mk
+++ b/core/tasks/meta-lic.mk
@@ -30,59 +30,6 @@ $(eval $(call declare-1p-copy-files,device/google_car/common,))
 $(eval $(call declare-1p-copy-files,device/google/atv,atv-component-overrides.xml))
 $(eval $(call declare-1p-copy-files,device/google/atv,tv_core_hardware.xml))
 
-# Moved here from device/google/bramble/Android.mk
-$(eval $(call declare-copy-files-license-metadata,device/google/bramble,default-permissions.xml,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/bramble,libnfc-nci.conf,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/bramble,fstab.postinstall,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/bramble,ueventd.rc,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/bramble,wpa_supplicant.conf,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/bramble,hals.conf,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/bramble,media_profiles_V1_0.xml,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/bramble,media_codecs_performance.xml,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/bramble,device_state_configuration.xml,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/bramble,task_profiles.json,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/bramble,p2p_supplicant.conf,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/bramble,wpa_supplicant.conf,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/bramble,wpa_supplicant_overlay.conf,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-
-$(eval $(call declare-1p-copy-files,device/google/bramble,audio_policy_configuration.xml))
-
-# Moved here from device/google/barbet/Android.mk
-$(eval $(call declare-copy-files-license-metadata,device/google/barbet,default-permissions.xml,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/barbet,libnfc-nci.conf,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/barbet,fstab.postinstall,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/barbet,ueventd.rc,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/barbet,wpa_supplicant.conf,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/barbet,hals.conf,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/barbet,media_profiles_V1_0.xml,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/barbet,media_codecs_performance.xml,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/barbet,device_state_configuration.xml,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/barbet,task_profiles.json,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/barbet,p2p_supplicant.conf,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/barbet,wpa_supplicant.conf,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/barbet,wpa_supplicant_overlay.conf,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-
-$(eval $(call declare-1p-copy-files,device/google/barbet,audio_policy_configuration.xml))
-
-# Moved here from device/google/coral/Android.mk
-$(eval $(call declare-copy-files-license-metadata,device/google/coral,default-permissions.xml,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/coral,libnfc-nci.conf,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/coral,fstab.postinstall,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/coral,ueventd.rc,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/coral,wpa_supplicant.conf,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/coral,hals.conf,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/coral,media_profiles_V1_0.xml,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/coral,media_codecs_performance.xml,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/coral,device_state_configuration.xml,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/coral,task_profiles.json,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/coral,p2p_supplicant.conf,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/coral,wpa_supplicant.conf,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/coral,wpa_supplicant_overlay.conf,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/coral,display_19261132550654593.xml,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-
-$(eval $(call declare-1p-copy-files,device/google/coral,audio_policy_configuration.xml))
-$(eval $(call declare-1p-copy-files,device/google/coral,display_19260504575090817.xml))
-
 # Moved here from device/google/cuttlefish/Android.mk
 $(eval $(call declare-copy-files-license-metadata,device/google/cuttlefish,.idc,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
 $(eval $(call declare-copy-files-license-metadata,device/google/cuttlefish,default-permissions.xml,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
@@ -152,23 +99,6 @@ $(eval $(call declare-copy-files-license-metadata,device/google/raviole,wpa_supp
 
 $(eval $(call declare-1p-copy-files,device/google/raviole,audio_policy_configuration.xml))
 
-# Moved here from device/google/redfin/Android.mk
-$(eval $(call declare-copy-files-license-metadata,device/google/redfin,default-permissions.xml,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/redfin,libnfc-nci.conf,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/redfin,fstab.postinstall,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/redfin,ueventd.rc,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/redfin,wpa_supplicant.conf,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/redfin,hals.conf,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/redfin,media_profiles_V1_0.xml,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/redfin,media_codecs_performance.xml,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/redfin,device_state_configuration.xml,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/redfin,task_profiles.json,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/redfin,p2p_supplicant.conf,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/redfin,wpa_supplicant.conf,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/redfin,wpa_supplicant_overlay.conf,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-
-$(eval $(call declare-1p-copy-files,device/google/redfin,audio_policy_configuration.xml))
-
 # Moved here from device/sample/Android.mk
 $(eval $(call declare-1p-copy-files,device/sample,))
 
diff --git a/core/tasks/module-info.mk b/core/tasks/module-info.mk
index 0ca27d8222..dd01f9667c 100644
--- a/core/tasks/module-info.mk
+++ b/core/tasks/module-info.mk
@@ -50,6 +50,8 @@ $(MODULE_INFO_JSON): $(SOONG_MODULE_INFO)
 			$(call write-optional-json-list, "host_dependencies", $(sort $(ALL_MODULES.$(m).HOST_REQUIRED_FROM_TARGET))) \
 			$(call write-optional-json-list, "target_dependencies", $(sort $(ALL_MODULES.$(m).TARGET_REQUIRED_FROM_HOST))) \
 			$(call write-optional-json-bool, "test_module_config_base", $(ALL_MODULES.$(m).TEST_MODULE_CONFIG_BASE)) \
+			$(call write-optional-json-bool, "make", $(if $(ALL_MODULES.$(m).IS_SOONG_MODULE),,true)) \
+			$(call write-optional-json-bool, "make_generated_module_info", true) \
 		'}')'\n}\n' >> $@.tmp
 	$(PRIVATE_MERGE_JSON_OBJECTS) -o $@ $(PRIVATE_SOONG_MODULE_INFO) $@.tmp
 	rm $@.tmp
diff --git a/core/tasks/test_mapping.mk b/core/tasks/test_mapping.mk
deleted file mode 100644
index eb2a585880..0000000000
--- a/core/tasks/test_mapping.mk
+++ /dev/null
@@ -1,40 +0,0 @@
-# Copyright (C) 2017 The Android Open Source Project
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#      http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-
-# Create an artifact to include TEST_MAPPING files in source tree. Also include
-# a file (out/disabled-presubmit-tests) containing the tests that should be
-# skipped in presubmit check.
-
-.PHONY: test_mapping
-
-intermediates := $(call intermediates-dir-for,PACKAGING,test_mapping)
-test_mappings_zip := $(intermediates)/test_mappings.zip
-test_mapping_list := $(OUT_DIR)/.module_paths/TEST_MAPPING.list
-$(test_mappings_zip) : PRIVATE_all_disabled_presubmit_tests := $(ALL_DISABLED_PRESUBMIT_TESTS)
-$(test_mappings_zip) : PRIVATE_test_mapping_list := $(test_mapping_list)
-
-$(test_mappings_zip) : .KATI_DEPFILE := $(test_mappings_zip).d
-$(test_mappings_zip) : $(test_mapping_list) $(SOONG_ZIP)
-	@echo "Building artifact to include TEST_MAPPING files and tests to skip in presubmit check."
-	rm -rf $@ $(dir $@)/disabled-presubmit-tests
-	echo $(sort $(PRIVATE_all_disabled_presubmit_tests)) | tr " " "\n" > $(dir $@)/disabled-presubmit-tests
-	$(SOONG_ZIP) -o $@ -C . -l $(PRIVATE_test_mapping_list) -C $(dir $@) -f $(dir $@)/disabled-presubmit-tests
-	echo "$@ : " $$(cat $(PRIVATE_test_mapping_list)) > $@.d
-	rm -f $(dir $@)/disabled-presubmit-tests
-
-test_mapping : $(test_mappings_zip)
-
-$(call dist-for-goals, dist_files test_mapping,$(test_mappings_zip))
-
-$(call declare-1p-target,$(test_mappings_zip),)
diff --git a/core/tasks/tools/package-modules.mk b/core/tasks/tools/package-modules.mk
index 4ec552047a..4d7b0ee787 100644
--- a/core/tasks/tools/package-modules.mk
+++ b/core/tasks/tools/package-modules.mk
@@ -96,7 +96,7 @@ endif
 $(my_package_zip): PRIVATE_COPY_PAIRS := $(my_copy_pairs)
 $(my_package_zip): PRIVATE_STAGING_DIR := $(my_staging_dir)
 $(my_package_zip): PRIVATE_PICKUP_FILES := $(my_pickup_files)
-$(my_package_zip) : $(my_built_modules)
+$(my_package_zip) : $(my_built_modules) $(SOONG_ZIP)
 	@echo "Package $@"
 	@rm -rf $(PRIVATE_STAGING_DIR) && mkdir -p $(PRIVATE_STAGING_DIR)
 	$(foreach p, $(PRIVATE_COPY_PAIRS),\
@@ -105,7 +105,7 @@ $(my_package_zip) : $(my_built_modules)
 	  cp -Rf $(word 1,$(pair)) $(word 2,$(pair)) && ) true
 	$(hide) $(foreach f, $(PRIVATE_PICKUP_FILES),\
 	  cp -RfL $(f) $(PRIVATE_STAGING_DIR) && ) true
-	$(hide) cd $(PRIVATE_STAGING_DIR) && zip -rqX ../$(notdir $@) *
+	$(hide) $(SOONG_ZIP) -o $@ -C $(PRIVATE_STAGING_DIR) -D $(PRIVATE_STAGING_DIR)
 	rm -rf $(PRIVATE_STAGING_DIR)
 
 my_makefile :=
diff --git a/core/tasks/tradefed-tests-list.mk b/core/tasks/tradefed-tests-list.mk
index 47c360de52..e437f894dc 100644
--- a/core/tasks/tradefed-tests-list.mk
+++ b/core/tasks/tradefed-tests-list.mk
@@ -18,11 +18,19 @@
 COMPATIBILITY.tradefed_tests_dir := \
   $(COMPATIBILITY.tradefed_tests_dir) \
   tools/tradefederation/core/res/config \
-  tools/tradefederation/core/javatests/res/config
+  tools/tradefederation/core/javatests/res/config \
+  vendor/google_tradefederation/contrib/res/config \
+  vendor/google_tradefederation/core/res/config \
+  vendor/google_tradefederation/core/javatests/res/config \
+  vendor/google_tradefederation/core/prod_tests/res/config
 
 tradefed_tests :=
 $(foreach dir, $(COMPATIBILITY.tradefed_tests_dir), \
-  $(eval tradefed_tests += $(shell find $(dir) -type f -name "*.xml")))
+  $(if $(wildcard $(dir)/*), \
+    $(eval tradefed_tests += $(shell find $(dir) -type f -name "*.xml")) \
+  ) \
+)
+
 tradefed_tests_list_intermediates := $(call intermediates-dir-for,PACKAGING,tradefed_tests_list,HOST,COMMON)
 tradefed_tests_list_zip := $(tradefed_tests_list_intermediates)/tradefed-tests_list.zip
 all_tests :=
diff --git a/core/version_util.mk b/core/version_util.mk
index ddcbda2cdc..cc94063bbe 100644
--- a/core/version_util.mk
+++ b/core/version_util.mk
@@ -22,6 +22,7 @@
 #     PLATFORM_VERSION
 #     PLATFORM_DISPLAY_VERSION
 #     PLATFORM_SDK_VERSION
+#     PLATFORM_SDK_VERSION_FULL
 #     PLATFORM_SDK_EXTENSION_VERSION
 #     PLATFORM_BASE_SDK_EXTENSION_VERSION
 #     PLATFORM_VERSION_CODENAME
@@ -62,11 +63,18 @@ endif
 PLATFORM_SDK_VERSION := $(RELEASE_PLATFORM_SDK_VERSION)
 .KATI_READONLY := PLATFORM_SDK_VERSION
 
-ifdef PLATFORM_SDK_MINOR_VERSION
-  $(error Do not set PLATFORM_SDK_MINOR_VERSION directly. Use RELEASE_PLATFORM_SDK_MINOR_VERSION. value: $(PLATFORM_SDK_MINOR_VERSION))
+ifdef PLATFORM_SDK_VERSION_FULL
+  $(error Do not set PLATFORM_SDK_VERSION_FULL directly. Use RELEASE_PLATFORM_SDK_VERSION_FULL. value: $(PLATFORM_SDK_VERSION_FULL))
 endif
-PLATFORM_SDK_MINOR_VERSION := $(RELEASE_PLATFORM_SDK_MINOR_VERSION)
-.KATI_READONLY := PLATFORM_SDK_MINOR_VERSION
+ifeq ($(RELEASE_PLATFORM_SDK_VERSION_FULL),)
+  PLATFORM_SDK_VERSION_FULL := "$(PLATFORM_SDK_VERSION).0"
+else
+  ifneq ($(RELEASE_PLATFORM_SDK_VERSION),$(word 1,$(subst ., ,$(RELEASE_PLATFORM_SDK_VERSION_FULL))))
+    $(error if RELEASE_PLATFORM_SDK_VERSION_FULL ($(RELEASE_PLATFORM_SDK_VERSION_FULL)) is set, its major version must match RELEASE_PLATFORM_SDK_VERSION ($(RELEASE_PLATFORM_SDK_VERSION)))
+  endif
+  PLATFORM_SDK_VERSION_FULL := "$(RELEASE_PLATFORM_SDK_VERSION_FULL)"
+endif
+.KATI_READONLY := PLATFORM_SDK_VERSION_FULL
 
 ifdef PLATFORM_SDK_EXTENSION_VERSION
   $(error Do not set PLATFORM_SDK_EXTENSION_VERSION directly. Use RELEASE_PLATFORM_SDK_EXTENSION_VERSION. value: $(PLATFORM_SDK_EXTENSION_VERSION))
diff --git a/envsetup.sh b/envsetup.sh
index 554a220f1d..c04031186e 100644
--- a/envsetup.sh
+++ b/envsetup.sh
@@ -438,68 +438,6 @@ function print_lunch_menu()
     echo
 }
 
-function lunch()
-{
-    local answer
-    setup_cog_env_if_needed
-
-    if [[ $# -gt 1 ]]; then
-        echo "usage: lunch [target]" >&2
-        return 1
-    fi
-
-    local used_lunch_menu=0
-
-    if [ "$1" ]; then
-        answer=$1
-    else
-        print_lunch_menu
-        echo "Which would you like? [aosp_cf_x86_64_phone-trunk_staging-eng]"
-        echo -n "Pick from common choices above (e.g. 13) or specify your own (e.g. aosp_barbet-trunk_staging-eng): "
-        read answer
-        used_lunch_menu=1
-    fi
-
-    local selection=
-
-    if [ -z "$answer" ]
-    then
-        selection=aosp_cf_x86_64_phone-trunk_staging-eng
-    elif (echo -n $answer | grep -q -e "^[0-9][0-9]*$")
-    then
-        local choices=($(TARGET_BUILD_APPS= TARGET_PRODUCT= TARGET_RELEASE= TARGET_BUILD_VARIANT= _get_build_var_cached COMMON_LUNCH_CHOICES 2>/dev/null))
-        if [ $answer -le ${#choices[@]} ]
-        then
-            # array in zsh starts from 1 instead of 0.
-            if [ -n "$ZSH_VERSION" ]
-            then
-                selection=${choices[$(($answer))]}
-            else
-                selection=${choices[$(($answer-1))]}
-            fi
-        fi
-    else
-        selection=$answer
-    fi
-
-    export TARGET_BUILD_APPS=
-
-    # This must be <product>-<release>-<variant>
-    local product release variant
-    # Split string on the '-' character.
-    IFS="-" read -r product release variant <<< "$selection"
-
-    if [[ -z "$product" ]] || [[ -z "$release" ]] || [[ -z "$variant" ]]
-    then
-        echo
-        echo "Invalid lunch combo: $selection"
-        echo "Valid combos must be of the form <product>-<release>-<variant>"
-        return 1
-    fi
-
-    _lunch_meat $product $release $variant
-}
-
 function _lunch_meat()
 {
     local product=$1
@@ -582,13 +520,13 @@ function _lunch_usage()
         echo "Note that the previous interactive menu and list of hard-coded"
         echo "list of curated targets has been removed. If you would like the"
         echo "list of products, release configs for a particular product, or"
-        echo "variants, run list_products, list_release_configs, list_variants"
+        echo "variants, run list_products list_releases or list_variants"
         echo "respectively."
         echo
     ) 1>&2
 }
 
-function lunch2()
+function lunch()
 {
     if [[ $# -eq 1 && $1 = "--help" ]]; then
         _lunch_usage
diff --git a/packaging/distdir.mk b/packaging/distdir.mk
index 153ecf65b1..97ed95a569 100644
--- a/packaging/distdir.mk
+++ b/packaging/distdir.mk
@@ -45,5 +45,3 @@ ifeq ($(DIST),true)
 endif
 
 copy-one-dist-file :=
-DIST_GOAL_OUTPUT_PAIRS :=
-DIST_SRC_DST_PAIRS :=
diff --git a/packaging/main_soong_only.mk b/packaging/main_soong_only.mk
new file mode 100644
index 0000000000..f29e5f6f0d
--- /dev/null
+++ b/packaging/main_soong_only.mk
@@ -0,0 +1,60 @@
+# Copyright (C) 2025 The Android Open Source Project
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
+ifndef KATI
+$(error Only Kati is supported.)
+endif
+
+$(info [1/4] initializing packaging system ...)
+
+.KATI_READONLY := KATI_PACKAGE_MK_DIR
+
+include build/make/common/core.mk
+include build/make/common/strings.mk
+
+# Define well-known goals and their dependency graph that they've
+# traditionally had in make builds. Also it's important to define
+# droid first so that it's built by default.
+
+.PHONY: droid
+droid: droid_targets
+
+.PHONY: droid_targets
+droid_targets: droidcore dist_files
+
+.PHONY: dist_files
+dist_files:
+
+.PHONY: droidcore
+droidcore: droidcore-unbundled
+
+.PHONY: droidcore-unbundled
+droidcore-unbundled:
+
+$(info [2/4] including distdir.mk ...)
+
+include build/make/packaging/distdir.mk
+
+$(info [3/4] defining phony modules ...)
+
+include $(OUT_DIR)/soong/soong_phony_targets.mk
+
+goals := $(sort $(foreach pair,$(DIST_GOAL_OUTPUT_PAIRS),$(call word-colon,1,$(pair))))
+$(foreach goal,$(goals), \
+  $(eval .PHONY: $$(goal)) \
+  $(eval $$(goal):) \
+  $(if $(call streq,$(DIST),true),\
+    $(eval $$(goal): _dist_$$(goal))))
+
+$(info [4/4] writing packaging rules ...)
diff --git a/shell_utils.sh b/shell_utils.sh
index 9053c42e75..61b0ebcb55 100644
--- a/shell_utils.sh
+++ b/shell_utils.sh
@@ -97,8 +97,11 @@ function setup_cog_symlink() {
   local out_dir=$(getoutdir)
   local top=$(gettop)
 
-  # return early if out dir is already a symlink
+  # return early if out dir is already a symlink.
   if [[ -L "$out_dir" ]]; then
+    destination=$(readlink "$out_dir")
+    # ensure the destination exists.
+    mkdir -p "$destination"
     return 0
   fi
 
@@ -214,3 +217,19 @@ function log_tool_invocation()
     ' SIGINT SIGTERM SIGQUIT EXIT
 }
 
+# Import the build variables supplied as arguments into this shell's environment.
+# For absolute variables, prefix the variable name with a '/'. For example:
+#    import_build_vars OUT_DIR DIST_DIR /HOST_OUT_EXECUTABLES
+# Returns nonzero if the build command failed. Stderr is passed through.
+function import_build_vars()
+{
+    require_top
+    local script
+    script=$(cd $TOP && build/soong/bin/get_build_vars "$@")
+    local ret=$?
+    if [ $ret -ne 0 ] ; then
+        return $ret
+    fi
+    eval "$script"
+    return $?
+}
diff --git a/target/board/BoardConfigGsiCommon.mk b/target/board/BoardConfigGsiCommon.mk
index 67e31dfa5f..8a62796e51 100644
--- a/target/board/BoardConfigGsiCommon.mk
+++ b/target/board/BoardConfigGsiCommon.mk
@@ -69,6 +69,11 @@ BOARD_SUPER_PARTITION_SIZE := 3229614080
 BOARD_SUPER_PARTITION_GROUPS := gsi_dynamic_partitions
 BOARD_GSI_DYNAMIC_PARTITIONS_PARTITION_LIST := system
 BOARD_GSI_DYNAMIC_PARTITIONS_SIZE := 3221225472
+
+# Build pvmfw with GSI: b/376363989
+ifeq (true,$(PRODUCT_BUILD_PVMFW_IMAGE))
+BOARD_PVMFWIMAGE_PARTITION_SIZE := 0x00100000
+endif
 endif
 
 # TODO(b/123695868, b/146149698):
diff --git a/target/board/generic_64bitonly_x86_64/device.mk b/target/board/generic_64bitonly_x86_64/device.mk
index bb49057abf..5edf5e0822 100644
--- a/target/board/generic_64bitonly_x86_64/device.mk
+++ b/target/board/generic_64bitonly_x86_64/device.mk
@@ -17,8 +17,3 @@
 ifdef NET_ETH0_STARTONBOOT
   PRODUCT_PROPERTY_OVERRIDES += net.eth0.startonboot=1
 endif
-
-# Ensure we package the BIOS files too.
-PRODUCT_HOST_PACKAGES += \
-    bios.bin \
-    vgabios-cirrus.bin \
diff --git a/target/board/generic_arm64/BoardConfig.mk b/target/board/generic_arm64/BoardConfig.mk
index e2d5fb4df8..1a05549193 100644
--- a/target/board/generic_arm64/BoardConfig.mk
+++ b/target/board/generic_arm64/BoardConfig.mk
@@ -23,14 +23,14 @@ TARGET_2ND_ARCH := arm
 TARGET_2ND_CPU_ABI := armeabi-v7a
 TARGET_2ND_CPU_ABI2 := armeabi
 
-ifneq ($(TARGET_BUILD_APPS)$(filter cts sdk,$(MAKECMDGOALS)),)
+ifneq ($(TARGET_BUILD_APPS)$(filter sdk,$(MAKECMDGOALS)),)
 # DO NOT USE
 # DO NOT USE
 #
 # This architecture / CPU variant must NOT be used for any 64 bit
 # platform builds. It is the lowest common denominator required
 # to build an unbundled application or cts for all supported 32 and 64 bit
-# platforms.
+# platforms. It now recommended to use generic_arm64_plus_armv7 to achieve this.
 #
 # If you're building a 64 bit platform (and not an application) the
 # ARM-v8 specification allows you to assume all the features available in an
@@ -66,6 +66,8 @@ include build/make/target/board/BoardConfigGsiCommon.mk
 BOARD_ROOT_EXTRA_SYMLINKS += /vendor/lib/dsp:/dsp
 BOARD_ROOT_EXTRA_SYMLINKS += /mnt/vendor/persist:/persist
 BOARD_ROOT_EXTRA_SYMLINKS += /vendor/firmware_mnt:/firmware
+# for Android.bp
+TARGET_ADD_ROOT_EXTRA_VENDOR_SYMLINKS := true
 
 # TODO(b/36764215): remove this setting when the generic system image
 # no longer has QCOM-specific directories under /.
diff --git a/target/board/generic_arm64_plus_armv7/BoardConfig.mk b/target/board/generic_arm64_plus_armv7/BoardConfig.mk
new file mode 100644
index 0000000000..2dca04f707
--- /dev/null
+++ b/target/board/generic_arm64_plus_armv7/BoardConfig.mk
@@ -0,0 +1,55 @@
+# Copyright (C) 2025 The Android Open Source Project
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
+#
+
+# arm64 emulator specific definitions
+TARGET_ARCH := arm64
+TARGET_ARCH_VARIANT := armv8-a
+TARGET_CPU_VARIANT := generic
+TARGET_CPU_ABI := arm64-v8a
+
+TARGET_2ND_ARCH := arm
+TARGET_2ND_CPU_ABI := armeabi-v7a
+TARGET_2ND_CPU_ABI2 := armeabi
+
+# DO NOT USE
+# DO NOT USE
+#
+# This architecture / CPU variant must NOT be used for any 64 bit
+# platform builds. It is the lowest common denominator required
+# to build an unbundled application or cts for all supported 32 and 64 bit
+# platforms.
+#
+# If you're building a 64 bit platform (and not an application) the
+# ARM-v8 specification allows you to assume all the features available in an
+# armv7-a-neon CPU. You should set the following as 2nd arch/cpu variant:
+#
+# TARGET_2ND_ARCH_VARIANT := armv8-a
+# TARGET_2ND_CPU_VARIANT := generic
+#
+# DO NOT USE
+# DO NOT USE
+TARGET_2ND_ARCH_VARIANT := armv7-a-neon
+# DO NOT USE
+# DO NOT USE
+TARGET_2ND_CPU_VARIANT := generic
+# DO NOT USE
+# DO NOT USE
+
+# Include 64-bit mediaserver to support 64-bit only devices
+TARGET_DYNAMIC_64_32_MEDIASERVER := true
+# Include 64-bit drmserver to support 64-bit only devices
+TARGET_DYNAMIC_64_32_DRMSERVER := true
+
+include build/make/target/board/BoardConfigGsiCommon.mk
diff --git a/target/board/generic_arm64_plus_armv7/README.txt b/target/board/generic_arm64_plus_armv7/README.txt
new file mode 100644
index 0000000000..284bdc254c
--- /dev/null
+++ b/target/board/generic_arm64_plus_armv7/README.txt
@@ -0,0 +1,7 @@
+The "generic_arm64_plus_armv7" product defines a non-hardware-specific arm64
+target with armv7 compatible arm32.  It is used for building CTS and other
+test suites for which the 32-bit binaries may be run on older devices with
+armv7 CPUs.
+
+It is not a product "base class"; no other products inherit
+from it or use it in any way.
diff --git a/target/board/generic_arm64_plus_armv7/device.mk b/target/board/generic_arm64_plus_armv7/device.mk
new file mode 100644
index 0000000000..a9586f3c16
--- /dev/null
+++ b/target/board/generic_arm64_plus_armv7/device.mk
@@ -0,0 +1,15 @@
+#
+# Copyright (C) 2025 The Android Open Source Project
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
+#
diff --git a/target/board/generic_x86/device.mk b/target/board/generic_x86/device.mk
index 60f0cc33f1..27fb310c2c 100644
--- a/target/board/generic_x86/device.mk
+++ b/target/board/generic_x86/device.mk
@@ -17,8 +17,3 @@
 ifdef NET_ETH0_STARTONBOOT
   PRODUCT_VENDOR_PROPERTIES += net.eth0.startonboot=1
 endif
-
-# Ensure we package the BIOS files too.
-PRODUCT_HOST_PACKAGES += \
-	bios.bin \
-	vgabios-cirrus.bin \
diff --git a/target/product/AndroidProducts.mk b/target/product/AndroidProducts.mk
index 07eb96db2a..5a7414e49f 100644
--- a/target/product/AndroidProducts.mk
+++ b/target/product/AndroidProducts.mk
@@ -36,6 +36,7 @@ ifneq ($(TARGET_BUILD_APPS),)
 PRODUCT_MAKEFILES := \
     $(LOCAL_DIR)/aosp_arm64.mk \
     $(LOCAL_DIR)/aosp_arm64_fullmte.mk \
+    $(LOCAL_DIR)/aosp_arm64_plus_armv7.mk \
     $(LOCAL_DIR)/aosp_arm.mk \
     $(LOCAL_DIR)/aosp_riscv64.mk \
     $(LOCAL_DIR)/aosp_x86_64.mk \
@@ -48,6 +49,7 @@ PRODUCT_MAKEFILES := \
     $(LOCAL_DIR)/aosp_64bitonly_x86_64.mk \
     $(LOCAL_DIR)/aosp_arm64.mk \
     $(LOCAL_DIR)/aosp_arm64_fullmte.mk \
+    $(LOCAL_DIR)/aosp_arm64_plus_armv7.mk \
     $(LOCAL_DIR)/aosp_arm.mk \
     $(LOCAL_DIR)/aosp_riscv64.mk \
     $(LOCAL_DIR)/aosp_x86_64.mk \
diff --git a/target/product/OWNERS b/target/product/OWNERS
index 48d3f2a33c..276c885280 100644
--- a/target/product/OWNERS
+++ b/target/product/OWNERS
@@ -8,3 +8,6 @@ per-file developer_gsi_keys.mk = file:/target/product/gsi/OWNERS
 per-file go_defaults.mk = gkaiser@google.com, kushg@google.com, rajekumar@google.com
 per-file go_defaults_512.mk = gkaiser@google.com, kushg@google.com, rajekumar@google.com
 per-file go_defaults_common.mk = gkaiser@google.com, kushg@google.com, rajekumar@google.com
+
+# Translation
+per-file languages_default.mk = aapple@google.com
diff --git a/target/product/aosp_arm.mk b/target/product/aosp_arm.mk
index d9c362eb56..595c3dbb0f 100644
--- a/target/product/aosp_arm.mk
+++ b/target/product/aosp_arm.mk
@@ -60,8 +60,12 @@ ifeq (aosp_arm,$(TARGET_PRODUCT))
 MODULE_BUILD_FROM_SOURCE ?= true
 
 $(call inherit-product, $(SRC_TARGET_DIR)/product/gsi_release.mk)
-endif
 
+PRODUCT_SOONG_DEFINED_SYSTEM_IMAGE := aosp_system_image
+USE_SOONG_DEFINED_SYSTEM_IMAGE := true
+PRODUCT_USE_SOONG_NOTICE_XML := true
+
+endif
 
 PRODUCT_NAME := aosp_arm
 PRODUCT_DEVICE := generic
diff --git a/target/product/aosp_arm64.mk b/target/product/aosp_arm64.mk
index 7a9325dae3..cd3de51bd8 100644
--- a/target/product/aosp_arm64.mk
+++ b/target/product/aosp_arm64.mk
@@ -66,8 +66,12 @@ ifeq (aosp_arm64,$(TARGET_PRODUCT))
 MODULE_BUILD_FROM_SOURCE ?= true
 
 $(call inherit-product, $(SRC_TARGET_DIR)/product/gsi_release.mk)
-endif
 
+PRODUCT_SOONG_DEFINED_SYSTEM_IMAGE := aosp_system_image
+USE_SOONG_DEFINED_SYSTEM_IMAGE := true
+PRODUCT_USE_SOONG_NOTICE_XML := true
+
+endif
 
 PRODUCT_NAME := aosp_arm64
 PRODUCT_DEVICE := generic_arm64
diff --git a/target/product/aosp_arm64_plus_armv7.mk b/target/product/aosp_arm64_plus_armv7.mk
new file mode 100644
index 0000000000..7322629ee5
--- /dev/null
+++ b/target/product/aosp_arm64_plus_armv7.mk
@@ -0,0 +1,64 @@
+#
+# Copyright (C) 2025 The Android Open-Source Project
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
+#
+
+# aosp_arm64_plus_armv7 is for building CTS and other test suites with
+# arm64 as the primary architecture and armv7 arm32 as the secondary
+# architecture.
+
+#
+# All components inherited here go to system image
+#
+$(call inherit-product, $(SRC_TARGET_DIR)/product/core_64_bit.mk)
+$(call inherit-product, $(SRC_TARGET_DIR)/product/generic_system.mk)
+
+PRODUCT_ENFORCE_ARTIFACT_PATH_REQUIREMENTS := relaxed
+
+#
+# All components inherited here go to system_ext image
+#
+$(call inherit-product, $(SRC_TARGET_DIR)/product/handheld_system_ext.mk)
+$(call inherit-product, $(SRC_TARGET_DIR)/product/telephony_system_ext.mk)
+
+# pKVM
+$(call inherit-product-if-exists, packages/modules/Virtualization/apex/product_packages.mk)
+
+#
+# All components inherited here go to product image
+#
+$(call inherit-product, $(SRC_TARGET_DIR)/product/aosp_product.mk)
+
+#
+# All components inherited here go to vendor or vendor_boot image
+#
+$(call inherit-product, $(SRC_TARGET_DIR)/board/generic_arm64/device.mk)
+AB_OTA_UPDATER := true
+AB_OTA_PARTITIONS ?= system
+
+#
+# Special settings for GSI releasing
+#
+# Build modules from source if this has not been pre-configured
+MODULE_BUILD_FROM_SOURCE ?= true
+
+$(call inherit-product, $(SRC_TARGET_DIR)/product/gsi_release.mk)
+
+
+PRODUCT_NAME := aosp_arm64_plus_armv7
+PRODUCT_DEVICE := generic_arm64_plus_armv7
+PRODUCT_BRAND := Android
+PRODUCT_MODEL := AOSP on ARM64 with ARMV7
+
+PRODUCT_NO_BIONIC_PAGE_SIZE_MACRO := true
diff --git a/target/product/aosp_x86.mk b/target/product/aosp_x86.mk
index c26a8bf45c..d14abc26df 100644
--- a/target/product/aosp_x86.mk
+++ b/target/product/aosp_x86.mk
@@ -58,8 +58,12 @@ ifeq (aosp_x86,$(TARGET_PRODUCT))
 MODULE_BUILD_FROM_SOURCE ?= true
 
 $(call inherit-product, $(SRC_TARGET_DIR)/product/gsi_release.mk)
-endif
 
+PRODUCT_SOONG_DEFINED_SYSTEM_IMAGE := aosp_system_image
+USE_SOONG_DEFINED_SYSTEM_IMAGE := true
+PRODUCT_USE_SOONG_NOTICE_XML := true
+
+endif
 
 PRODUCT_NAME := aosp_x86
 PRODUCT_DEVICE := generic_x86
diff --git a/target/product/aosp_x86_64.mk b/target/product/aosp_x86_64.mk
index 595940d9d1..bd121e3712 100644
--- a/target/product/aosp_x86_64.mk
+++ b/target/product/aosp_x86_64.mk
@@ -68,8 +68,12 @@ ifeq (aosp_x86_64,$(TARGET_PRODUCT))
 MODULE_BUILD_FROM_SOURCE ?= true
 
 $(call inherit-product, $(SRC_TARGET_DIR)/product/gsi_release.mk)
-endif
 
+PRODUCT_SOONG_DEFINED_SYSTEM_IMAGE := aosp_system_image
+USE_SOONG_DEFINED_SYSTEM_IMAGE := true
+PRODUCT_USE_SOONG_NOTICE_XML := true
+
+endif
 
 PRODUCT_NAME := aosp_x86_64
 PRODUCT_DEVICE := generic_x86_64
diff --git a/target/product/base_system.mk b/target/product/base_system.mk
index a78c023a36..5c4ef33284 100644
--- a/target/product/base_system.mk
+++ b/target/product/base_system.mk
@@ -52,7 +52,7 @@ PRODUCT_PACKAGES += \
     com.android.adbd \
     com.android.adservices \
     com.android.appsearch \
-    com.android.btservices \
+    com.android.bt \
     com.android.configinfrastructure \
     com.android.conscrypt \
     com.android.devicelock \
@@ -96,7 +96,6 @@ PRODUCT_PACKAGES += \
     enhanced-confirmation.xml \
     ExtShared \
     flags_health_check \
-    framework-connectivity-b \
     framework-graphics \
     framework-location \
     framework-minus-apex \
@@ -242,6 +241,7 @@ PRODUCT_PACKAGES += \
     PackageInstaller \
     package-shareduid-allowlist.xml \
     passwd_system \
+    pbtombstone \
     perfetto \
     perfetto-extras \
     ping \
@@ -253,7 +253,6 @@ PRODUCT_PACKAGES += \
     preinstalled-packages-asl-files.xml \
     preinstalled-packages-platform.xml \
     preinstalled-packages-strict-signature.xml \
-    printflags \
     privapp-permissions-platform.xml \
     prng_seeder \
     recovery-persist \
@@ -371,6 +370,13 @@ ifeq ($(RELEASE_USE_WEBVIEW_BOOTSTRAP_MODULE),true)
         com.android.webview.bootstrap
 endif
 
+# Only add the jar when it is not in the Tethering module. Otherwise,
+# it will be added via com.android.tethering
+ifneq ($(RELEASE_MOVE_VCN_TO_MAINLINE),true)
+    PRODUCT_PACKAGES += \
+        framework-connectivity-b
+endif
+
 ifneq (,$(RELEASE_RANGING_STACK))
     PRODUCT_PACKAGES += \
         com.android.ranging
@@ -379,6 +385,9 @@ endif
 ifeq ($(RELEASE_MEMORY_MANAGEMENT_DAEMON),true)
   PRODUCT_PACKAGES += \
         mm_daemon
+else
+  PRODUCT_PACKAGES += \
+        init-mmd-prop.rc
 endif
 
 # VINTF data for system image
@@ -386,10 +395,6 @@ PRODUCT_PACKAGES += \
     system_manifest.xml \
     system_compatibility_matrix.xml \
 
-# Base modules when shipping api level is less than or equal to 34
-PRODUCT_PACKAGES_SHIPPING_API_LEVEL_34 += \
-    android.hidl.memory@1.0-impl \
-
 # hwservicemanager is now installed on system_ext, but apexes might be using
 # old libraries that are expecting it to be installed on system. This allows
 # those apexes to continue working. The symlink can be removed once we are sure
@@ -494,6 +499,7 @@ PRODUCT_VENDOR_PROPERTIES += ro.zygote?=zygote32
 
 PRODUCT_SYSTEM_PROPERTIES += debug.atrace.tags.enableflags=0
 PRODUCT_SYSTEM_PROPERTIES += persist.traced.enable=1
+PRODUCT_SYSTEM_PROPERTIES += ro.surface_flinger.game_default_frame_rate_override=60
 
 # Include kernel configs.
 PRODUCT_PACKAGES += \
@@ -517,6 +523,7 @@ PRODUCT_PACKAGES_DEBUG := \
     logtagd.rc \
     ot-cli-ftd \
     ot-ctl \
+    overlay_remounter \
     procrank \
     profcollectd \
     profcollectctl \
@@ -571,3 +578,7 @@ $(call inherit-product,$(SRC_TARGET_DIR)/product/updatable_apex.mk)
 $(call soong_config_set, bionic, large_system_property_node, $(RELEASE_LARGE_SYSTEM_PROPERTY_NODE))
 $(call soong_config_set, Aconfig, read_from_new_storage, $(RELEASE_READ_FROM_NEW_STORAGE))
 $(call soong_config_set, SettingsLib, legacy_avatar_picker_app_enabled, $(if $(RELEASE_AVATAR_PICKER_APP),,true))
+$(call soong_config_set, appsearch, enable_isolated_storage, $(RELEASE_APPSEARCH_ENABLE_ISOLATED_STORAGE))
+
+# Enable AppSearch Isolated Storage per BUILD flag
+PRODUCT_PRODUCT_PROPERTIES += ro.appsearch.feature.enable_isolated_storage=$(RELEASE_APPSEARCH_ENABLE_ISOLATED_STORAGE)
diff --git a/target/product/base_system_ext.mk b/target/product/base_system_ext.mk
index 6767b9a3a9..ad6828a40e 100644
--- a/target/product/base_system_ext.mk
+++ b/target/product/base_system_ext.mk
@@ -30,6 +30,7 @@ PRODUCT_PACKAGES += \
 PRODUCT_PACKAGES_SHIPPING_API_LEVEL_34 += \
     hwservicemanager \
     android.hidl.allocator@1.0-service \
+    android.hidl.memory@1.0-impl \
 
 # AppFunction Extensions
 ifneq (,$(RELEASE_APPFUNCTION_SIDECAR))
diff --git a/target/product/base_vendor.mk b/target/product/base_vendor.mk
index 16fc7fd906..b4e450e076 100644
--- a/target/product/base_vendor.mk
+++ b/target/product/base_vendor.mk
@@ -106,7 +106,6 @@ PRODUCT_PACKAGES_SHIPPING_API_LEVEL_29 += \
 # VINTF data for vendor image
 PRODUCT_PACKAGES += \
     vendor_compatibility_matrix.xml \
-    vendor_manifest.xml \
 
 # Base modules and settings for the debug ramdisk, which is then packed
 # into a boot-debug.img and a vendor_boot-debug.img.
diff --git a/target/product/build_variables.mk b/target/product/build_variables.mk
index c9369112aa..7c54258eef 100644
--- a/target/product/build_variables.mk
+++ b/target/product/build_variables.mk
@@ -32,5 +32,8 @@ $(call soong_config_set, libsqlite3, release_package_libsqlite3, $(RELEASE_PACKA
 # Use the configured MessageQueue implementation
 $(call soong_config_set, messagequeue, release_package_messagequeue_implementation, $(RELEASE_PACKAGE_MESSAGEQUEUE_IMPLEMENTATION))
 
+# Use the configured version of Cronet
+$(call soong_config_set,cronet,enable_cronet_tot,$(RELEASE_ENABLE_TOT_CRONET))
+
 # Use the configured version of WebView
 $(call soong_config_set, webview, release_package_webview_version, $(RELEASE_PACKAGE_WEBVIEW_VERSION))
diff --git a/target/product/default_art_config.mk b/target/product/default_art_config.mk
index 33891d77f1..f91cb07849 100644
--- a/target/product/default_art_config.mk
+++ b/target/product/default_art_config.mk
@@ -51,7 +51,6 @@ PRODUCT_BOOT_JARS += \
     framework-minus-apex \
     framework-graphics \
     framework-location \
-    framework-connectivity-b \
     ext \
     telephony-common \
     voip-common \
@@ -66,7 +65,7 @@ PRODUCT_APEX_BOOT_JARS := \
     com.android.adservices:framework-adservices \
     com.android.adservices:framework-sdksandbox \
     com.android.appsearch:framework-appsearch \
-    com.android.btservices:framework-bluetooth \
+    com.android.bt:framework-bluetooth \
     com.android.configinfrastructure:framework-configinfrastructure \
     com.android.conscrypt:conscrypt \
     com.android.devicelock:framework-devicelock \
@@ -137,6 +136,17 @@ ifneq (,$(RELEASE_RANGING_STACK))
     $(call soong_config_set,bootclasspath,release_ranging_stack,true)
 endif
 
+# Check if VCN should be built into the tethering module or not
+ifeq ($(RELEASE_MOVE_VCN_TO_MAINLINE),true)
+    PRODUCT_APEX_BOOT_JARS += \
+        com.android.tethering:framework-connectivity-b \
+
+else
+    PRODUCT_BOOT_JARS += \
+        framework-connectivity-b \
+
+endif
+
 # List of system_server classpath jars delivered via apex.
 # Keep the list sorted by module names and then library names.
 # Note: For modules available in Q, DO NOT add new entries here.
@@ -184,7 +194,7 @@ PRODUCT_STANDALONE_SYSTEM_SERVER_JARS := \
 # Keep the list sorted by module names and then library names.
 # Note: For modules available in Q, DO NOT add new entries here.
 PRODUCT_APEX_STANDALONE_SYSTEM_SERVER_JARS := \
-    com.android.btservices:service-bluetooth \
+    com.android.bt:service-bluetooth \
     com.android.devicelock:service-devicelock \
     com.android.os.statsd:service-statsd \
     com.android.scheduling:service-scheduling \
diff --git a/target/product/full_x86.mk b/target/product/full_x86.mk
index 07f6472844..a1b71caaed 100644
--- a/target/product/full_x86.mk
+++ b/target/product/full_x86.mk
@@ -32,11 +32,6 @@ ifdef NET_ETH0_STARTONBOOT
   PRODUCT_VENDOR_PROPERTIES += net.eth0.startonboot=1
 endif
 
-# Ensure we package the BIOS files too.
-PRODUCT_HOST_PACKAGES += \
-	bios.bin \
-	vgabios-cirrus.bin \
-
 # Enable dynamic partition size
 PRODUCT_USE_DYNAMIC_PARTITION_SIZE := true
 
diff --git a/target/product/fullmte.mk b/target/product/fullmte.mk
index b62249601e..fed66e7ef2 100644
--- a/target/product/fullmte.mk
+++ b/target/product/fullmte.mk
@@ -20,7 +20,7 @@
 # For more details, see:
 # https://source.android.com/docs/security/test/memory-safety/arm-mte
 ifeq ($(filter memtag_heap,$(SANITIZE_TARGET)),)
-  SANITIZE_TARGET := $(strip $(SANITIZE_TARGET) memtag_heap memtag_stack)
+  SANITIZE_TARGET := $(strip $(SANITIZE_TARGET) memtag_heap memtag_stack memtag_globals)
   SANITIZE_TARGET_DIAG := $(strip $(SANITIZE_TARGET_DIAG) memtag_heap)
 endif
 PRODUCT_PRODUCT_PROPERTIES += persist.arm64.memtag.default=sync
diff --git a/target/product/generic/Android.bp b/target/product/generic/Android.bp
index a4a20b49f4..0a32a55b6b 100644
--- a/target/product/generic/Android.bp
+++ b/target/product/generic/Android.bp
@@ -1,5 +1,4 @@
 generic_rootdirs = [
-    "acct",
     "apex",
     "bootstrap-apex",
     "config",
@@ -125,6 +124,31 @@ android_symlinks = [
         target: "/data/cache",
         name: "cache",
     },
+    {
+        target: "/odm/odm_dlkm/etc",
+        name: "odm_dlkm/etc",
+    },
+    {
+        target: "/vendor/vendor_dlkm/etc",
+        name: "vendor_dlkm/etc",
+    },
+]
+
+extra_vendor_symlinks = [
+    // Some vendors still haven't cleaned up all device specific directories under root!
+    // TODO(b/111434759, b/111287060) SoC specific hacks
+    {
+        target: "/vendor/lib/dsp",
+        name: "dsp",
+    },
+    {
+        target: "/mnt/vendor/persist",
+        name: "persist",
+    },
+    {
+        target: "/vendor/firmware_mnt",
+        name: "firmware",
+    },
 ]
 
 filegroup {
@@ -347,27 +371,149 @@ phony {
 }
 
 android_filesystem_defaults {
+    name: "system_ext_image_defaults",
+    deps: [
+        ///////////////////////////////////////////
+        // base_system_ext
+        ///////////////////////////////////////////
+        "build_flag_system_ext",
+        "fs_config_dirs_system_ext",
+        "fs_config_files_system_ext",
+        "group_system_ext",
+        "passwd_system_ext",
+        "SatelliteClient",
+        "selinux_policy_system_ext",
+        "system_ext_manifest.xml",
+        "system_ext-build.prop",
+        // Base modules when shipping api level is less than or equal to 34
+        "hwservicemanager",
+        "android.hidl.allocator@1.0-service",
+
+        ///////////////////////////////////////////
+        // media_system_ext
+        ///////////////////////////////////////////
+        "StatementService",
+
+        ///////////////////////////////////////////
+        // window_extensions_base
+        ///////////////////////////////////////////
+        "androidx.window.extensions",
+        "androidx.window.sidecar",
+
+        ///////////////////////////////////////////
+        // base_system
+        ///////////////////////////////////////////
+        "charger",
+    ] + select(release_flag("RELEASE_APPFUNCTION_SIDECAR"), {
+        true: [
+            "com.android.extensions.appfunctions",
+            "appfunctions.extension.xml",
+        ],
+        default: [],
+    }),
+}
+
+android_filesystem_defaults {
+    name: "product_image_defaults",
+    deps: [
+        ///////////////////////////////////////////
+        // media_product
+        ///////////////////////////////////////////
+        "webview",
+
+        ///////////////////////////////////////////
+        // base_product
+        ///////////////////////////////////////////
+
+        // Base modules and settings for the product partition.
+        "build_flag_product",
+        "fs_config_dirs_product",
+        "fs_config_files_product",
+        "group_product",
+        "ModuleMetadata",
+        "passwd_product",
+        "product_compatibility_matrix.xml",
+        "product_manifest.xml",
+        "selinux_policy_product",
+        "product-build.prop",
+
+        // AUDIO
+        "frameworks_sounds",
+    ] + select(product_variable("debuggable"), {
+        // Packages included only for eng or userdebug builds, previously debug tagged
+        true: ["adb_keys"],
+        default: [],
+    }),
+}
+
+system_image_fsverity_default = {
+    inputs: [
+        "etc/boot-image.prof",
+        "etc/classpaths/*.pb",
+        "etc/dirty-image-objects",
+        "etc/preloaded-classes",
+        "framework/*",
+        "framework/*/*", // framework/{arch}
+        "framework/oat/*/*", // framework/oat/{arch}
+    ],
+    libs: [":framework-res{.export-package.apk}"],
+}
+
+soong_config_module_type {
+    name: "system_image_defaults",
+    module_type: "android_filesystem_defaults",
+    config_namespace: "ANDROID",
+    bool_variables: ["TARGET_ADD_ROOT_EXTRA_VENDOR_SYMLINKS"],
+    properties: ["symlinks"],
+}
+
+genrule {
+    name: "plat_and_vendor_file_contexts",
+    device_common_srcs: [
+        ":plat_file_contexts",
+        ":vendor_file_contexts",
+    ],
+    out: ["file_contexts"],
+    cmd: "cat $(in) > $(out)",
+}
+
+system_image_defaults {
     name: "system_image_defaults",
     partition_name: "system",
     base_dir: "system",
+    stem: "system.img",
+    no_full_install: true,
     dirs: generic_rootdirs,
-    symlinks: generic_symlinks,
-    file_contexts: ":plat_file_contexts",
+    soong_config_variables: {
+        TARGET_ADD_ROOT_EXTRA_VENDOR_SYMLINKS: {
+            symlinks: generic_symlinks + extra_vendor_symlinks,
+            conditions_default: {
+                symlinks: generic_symlinks,
+            },
+        },
+    },
+    file_contexts: ":plat_and_vendor_file_contexts",
     linker_config: {
         gen_linker_config: true,
         linker_config_srcs: [":system_linker_config_json_file"],
     },
     fsverity: {
-        inputs: [
-            "etc/boot-image.prof",
-            "etc/classpaths/*.pb",
-            "etc/dirty-image-objects",
-            "etc/preloaded-classes",
-            "framework/*",
-            "framework/*/*", // framework/{arch}
-            "framework/oat/*/*", // framework/oat/{arch}
-        ],
-        libs: [":framework-res{.export-package.apk}"],
+        inputs: select(soong_config_variable("ANDROID", "PRODUCT_FSVERITY_GENERATE_METADATA"), {
+            true: [
+                "etc/boot-image.prof",
+                "etc/classpaths/*.pb",
+                "etc/dirty-image-objects",
+                "etc/preloaded-classes",
+                "framework/*",
+                "framework/*/*", // framework/{arch}
+                "framework/oat/*/*", // framework/oat/{arch}
+            ],
+            default: [],
+        }),
+        libs: select(soong_config_variable("ANDROID", "PRODUCT_FSVERITY_GENERATE_METADATA"), {
+            true: [":framework-res{.export-package.apk}"],
+            default: [],
+        }),
     },
     build_logtags: true,
     gen_aconfig_flags_pb: true,
@@ -378,6 +524,7 @@ android_filesystem_defaults {
     avb_private_key: ":generic_system_sign_key",
     avb_algorithm: "SHA256_RSA4096",
     avb_hash_algorithm: "sha256",
+    rollback_index_location: 1,
 
     deps: [
         "abx",
@@ -471,7 +618,6 @@ android_filesystem_defaults {
         "locksettings", // base_system
         "logcat", // base_system
         "logd", // base_system
-        "logpersist.start",
         "lpdump", // base_system
         "lshal", // base_system
         "make_f2fs", // media_system
@@ -493,6 +639,7 @@ android_filesystem_defaults {
         "otapreopt_script", // generic_system
         "package-shareduid-allowlist.xml", // base_system
         "passwd_system", // base_system
+        "pbtombstone", // base_system
         "perfetto", // base_system
         "ping", // base_system
         "ping6", // base_system
@@ -506,7 +653,6 @@ android_filesystem_defaults {
         "preinstalled-packages-platform.xml", // base_system
         "preinstalled-packages-strict-signature.xml", // base_system
         "preloaded-classes", // ok
-        "printflags", // base_system
         "privapp-permissions-platform.xml", // base_system
         "prng_seeder", // base_system
         "public.libraries.android.txt",
@@ -528,7 +674,6 @@ android_filesystem_defaults {
         "sfdo", // base_system
         "sgdisk", // base_system
         "sm", // base_system
-        "snapshotctl", // base_system
         "snapuserd", // base_system
         "storaged", // base_system
         "surfaceflinger", // base_system
@@ -566,9 +711,12 @@ android_filesystem_defaults {
         true: [
             "mm_daemon", // base_system (RELEASE_MEMORY_MANAGEMENT_DAEMON)
         ],
-        default: [],
+        default: [
+            "init-mmd-prop.rc", // base_system
+        ],
     }) + select(product_variable("debuggable"), {
         true: [
+            "alloctop",
             "adevice_fingerprint",
             "arping",
             "avbctl",
@@ -581,9 +729,11 @@ android_filesystem_defaults {
             "iperf3",
             "iw",
             "layertracegenerator",
+            "logpersist.start",
             "logtagd.rc",
             "ot-cli-ftd",
             "ot-ctl",
+            "overlay_remounter",
             "procrank",
             "profcollectctl",
             "profcollectd",
@@ -591,6 +741,7 @@ android_filesystem_defaults {
             "sanitizer-status",
             "servicedispatcher",
             "showmap",
+            "snapshotctl",
             "sqlite3",
             "ss",
             "start_with_lockagent",
@@ -610,6 +761,11 @@ android_filesystem_defaults {
             "update_engine_client",
         ],
         default: [],
+    }) + select(release_flag("RELEASE_UPROBESTATS_MODULE"), {
+        true: [],
+        default: [
+            "uprobestats", // base_system internal
+        ],
     }),
     multilib: {
         common: {
@@ -666,7 +822,6 @@ android_filesystem_defaults {
                 "Shell", // base_system
                 "SimAppDialog", // handheld_system
                 "SoundPicker", // not installed by anyone
-                "StatementService", // media_system
                 "Stk", // generic_system
                 "Tag", // generic_system
                 "TeleService", // handheld_system
@@ -700,7 +855,6 @@ android_filesystem_defaults {
                 "framework-graphics", // base_system
                 "framework-location", // base_system
                 "framework-minus-apex-install-dependencies", // base_system
-                "framework-connectivity-b", // base_system
                 "framework_compatibility_matrix.device.xml",
                 "generic_system_fonts", // ok
                 "hwservicemanager_compat_symlink_module", // base_system
@@ -738,11 +892,11 @@ android_filesystem_defaults {
                     "com.android.profiling", // base_system (RELEASE_PACKAGE_PROFILING_MODULE)
                 ],
                 default: [],
-            }) + select(release_flag("RELEASE_AVATAR_PICKER_APP"), {
-                true: [
-                    "AvatarPicker", // generic_system (RELEASE_AVATAR_PICKER_APP)
+            }) + select(release_flag("RELEASE_MOVE_VCN_TO_MAINLINE"), {
+                true: [],
+                default: [
+                    "framework-connectivity-b", // base_system
                 ],
-                default: [],
             }) + select(release_flag("RELEASE_UPROBESTATS_MODULE"), {
                 true: [
                     "com.android.uprobestats", // base_system (RELEASE_UPROBESTATS_MODULE)
@@ -762,12 +916,7 @@ android_filesystem_defaults {
                 "android.system.virtualizationservice-ndk",
                 "libgsi",
                 "servicemanager",
-            ] + select(release_flag("RELEASE_UPROBESTATS_MODULE"), {
-                true: [],
-                default: [
-                    "uprobestats", // base_system internal
-                ],
-            }),
+            ],
         },
         both: {
             deps: [
@@ -912,4 +1061,9 @@ android_system_image {
         compressor: "lz4hc,9",
         compress_hints: "erofs_compress_hints.txt",
     },
+    deps: [
+        // DO NOT update this list. Instead, update the system_image_defaults to
+        // sync with the base_system.mk
+        "logpersist.start", // cf only
+    ],
 }
diff --git a/target/product/generic_ramdisk.mk b/target/product/generic_ramdisk.mk
index 5ecb55fca8..32277ece03 100644
--- a/target/product/generic_ramdisk.mk
+++ b/target/product/generic_ramdisk.mk
@@ -24,6 +24,7 @@ PRODUCT_PACKAGES += \
     init_first_stage \
     snapuserd_ramdisk \
     ramdisk-build.prop \
+    toolbox_ramdisk \
 
 # Debug ramdisk
 PRODUCT_PACKAGES += \
diff --git a/target/product/generic_system.mk b/target/product/generic_system.mk
index b9a623dcd3..2482afccc6 100644
--- a/target/product/generic_system.mk
+++ b/target/product/generic_system.mk
@@ -36,11 +36,6 @@ PRODUCT_PACKAGES += \
     Stk \
     Tag \
 
-ifeq ($(RELEASE_AVATAR_PICKER_APP),true)
-  PRODUCT_PACKAGES += \
-    AvatarPicker
-endif
-
 # OTA support
 PRODUCT_PACKAGES += \
     recovery-refresh \
diff --git a/target/product/gsi/Android.bp b/target/product/gsi/Android.bp
index 9e8946d6e8..8c200a1dcb 100644
--- a/target/product/gsi/Android.bp
+++ b/target/product/gsi/Android.bp
@@ -81,9 +81,13 @@ gsi_symlinks = [
     },
 ]
 
-android_system_image {
-    name: "android_gsi",
-    defaults: ["system_image_defaults"],
+android_filesystem_defaults {
+    name: "android_gsi_defaults",
+    defaults: [
+        "system_image_defaults",
+        "system_ext_image_defaults",
+        "product_image_defaults",
+    ],
     symlinks: gsi_symlinks,
     dirs: ["cache"],
     deps: [
@@ -101,33 +105,6 @@ android_system_image {
         // telephony packages
         "CarrierConfig",
 
-        // Install a copy of the debug policy to the system_ext partition, and allow
-        // init-second-stage to load debug policy from system_ext.
-        // This option is only meant to be set by compliance GSI targets.
-        "system_ext_userdebug_plat_sepolicy.cil",
-
-        ///////////////////////////////////////////
-        // base_system_ext
-        ///////////////////////////////////////////
-        "build_flag_system_ext",
-        "fs_config_dirs_system_ext",
-        "fs_config_files_system_ext",
-        "group_system_ext",
-        "passwd_system_ext",
-        "SatelliteClient",
-        "selinux_policy_system_ext",
-        "system_ext_manifest.xml",
-        "system_ext-build.prop",
-        // Base modules when shipping api level is less than or equal to 34
-        "hwservicemanager",
-        "android.hidl.allocator@1.0-service",
-
-        ///////////////////////////////////////////
-        // window_extensions_base
-        ///////////////////////////////////////////
-        "androidx.window.extensions",
-        "androidx.window.sidecar",
-
         ///////////////////////////////////////////
         // gsi_release
         ///////////////////////////////////////////
@@ -147,12 +124,6 @@ android_system_image {
         "com.android.vndk.v33",
         "com.android.vndk.v34",
 
-        ///////////////////////////////////////////
-        // AVF
-        ///////////////////////////////////////////
-        "com.android.compos",
-        "features_com.android.virt.xml",
-
         ///////////////////////////////////////////
         // gsi_product
         ///////////////////////////////////////////
@@ -161,49 +132,91 @@ android_system_image {
         "Dialer",
         "LatinIME",
         "apns-full-conf.xml",
-
-        ///////////////////////////////////////////
-        // media_product
-        ///////////////////////////////////////////
-        "webview",
-
-        ///////////////////////////////////////////
-        // base_product
-        ///////////////////////////////////////////
-
-        // Base modules and settings for the product partition.
-        "build_flag_product",
-        "fs_config_dirs_product",
-        "fs_config_files_product",
-        "group_product",
-        "ModuleMetadata",
-        "passwd_product",
-        "product_compatibility_matrix.xml",
-        "product_manifest.xml",
-        "selinux_policy_product",
-        "product-build.prop",
-
-        // AUDIO
-        "frameworks_sounds",
-
-        ///////////////////////////////////////////
-        // base_system
-        ///////////////////////////////////////////
-        "charger",
-    ] + select(product_variable("debuggable"), {
-        // Packages included only for eng or userdebug builds, previously debug tagged
-        true: ["adb_keys"],
-        default: [],
-    }),
+        "frameworks-base-overlays",
+    ],
     multilib: {
+        lib64: {
+            deps: [
+                ///////////////////////////////////////////
+                // AVF
+                ///////////////////////////////////////////
+                "com.android.compos",
+                "features_com.android.virt.xml",
+            ],
+        },
         both: {
             // PRODUCT_PACKAGES_SHIPPING_API_LEVEL_34
             deps: ["android.hidl.memory@1.0-impl"],
         },
     },
+    type: "ext4",
+}
+
+// system.img for gsi_{arch} targets
+android_system_image {
+    name: "android_gsi",
+    defaults: ["android_gsi_defaults"],
     enabled: select(soong_config_variable("ANDROID", "PRODUCT_INSTALL_DEBUG_POLICY_TO_SYSTEM_EXT"), {
         "true": true,
         default: false,
     }),
-    type: "ext4",
+    deps: [
+        // Install a copy of the debug policy to the system_ext partition, and allow
+        // init-second-stage to load debug policy from system_ext.
+        // This option is only meant to be set by compliance GSI targets.
+        "system_ext_userdebug_plat_sepolicy.cil",
+    ],
+}
+
+// system.img for aosp_{arch} targets
+android_system_image {
+    name: "aosp_system_image",
+    defaults: ["android_gsi_defaults"],
+    deps: [
+        // handheld_system_ext
+        "AccessibilityMenu",
+        "WallpaperCropper",
+
+        // telephony_system_ext
+        "EmergencyInfo",
+
+        // handheld_product
+        "Calendar",
+        "Contacts",
+        "DeskClock",
+        "Gallery2",
+        "Music",
+        "preinstalled-packages-platform-handheld-product.xml",
+        "QuickSearchBox",
+        "SettingsIntelligence",
+        "frameworks-base-overlays",
+
+        // telephony_product
+        "ImsServiceEntitlement",
+        "preinstalled-packages-platform-telephony-product.xml",
+
+        // more AOSP packages
+        "initial-package-stopped-states-aosp.xml",
+        "messaging",
+        "PhotoTable",
+        "preinstalled-packages-platform-aosp-product.xml",
+        "ThemePicker",
+    ] + select(product_variable("debuggable"), {
+        true: ["frameworks-base-overlays-debug"],
+        default: [],
+    }),
+    enabled: select(soong_config_variable("gsi", "building_gsi"), {
+        true: true,
+        default: false,
+    }),
+    multilib: {
+        common: {
+            deps: select(release_flag("RELEASE_AVATAR_PICKER_APP"), {
+                true: [
+                    "AvatarPicker", // handheld_system_ext (RELEASE_AVATAR_PICKER_APP)
+                ],
+                default: [],
+            }),
+        },
+    },
 }
diff --git a/target/product/gsi_release.mk b/target/product/gsi_release.mk
index f00c38cedf..115b355920 100644
--- a/target/product/gsi_release.mk
+++ b/target/product/gsi_release.mk
@@ -79,6 +79,11 @@ PRODUCT_BUILD_SUPER_EMPTY_IMAGE := false
 PRODUCT_BUILD_SYSTEM_DLKM_IMAGE := false
 PRODUCT_EXPORT_BOOT_IMAGE_TO_DIST := true
 
+# Build pvmfw with GSI: b/376363989, pvmfw currently only supports AArch64
+ifneq (,$(filter %_arm64,$(TARGET_PRODUCT)))
+PRODUCT_BUILD_PVMFW_IMAGE := true
+endif
+
 # Additional settings used in all GSI builds
 PRODUCT_PRODUCT_PROPERTIES += \
     ro.crypto.metadata_init_delete_all_keys.enabled=false \
diff --git a/target/product/handheld_system_ext.mk b/target/product/handheld_system_ext.mk
index 187b6275bb..6d686c554f 100644
--- a/target/product/handheld_system_ext.mk
+++ b/target/product/handheld_system_ext.mk
@@ -23,6 +23,7 @@ $(call inherit-product, $(SRC_TARGET_DIR)/product/media_system_ext.mk)
 # /system_ext packages
 PRODUCT_PACKAGES += \
     AccessibilityMenu \
+    $(if $(RELEASE_AVATAR_PICKER_APP), AvatarPicker,) \
     Launcher3QuickStep \
     Provision \
     Settings \
diff --git a/target/product/media_system.mk b/target/product/media_system.mk
index af3857ebc1..4df71516ab 100644
--- a/target/product/media_system.mk
+++ b/target/product/media_system.mk
@@ -35,7 +35,6 @@ PRODUCT_PACKAGES += \
     libwebviewchromium_plat_support \
     make_f2fs \
     requestsync \
-    StatementService \
 
 PRODUCT_HOST_PACKAGES += \
     fsck.f2fs \
diff --git a/target/product/media_system_ext.mk b/target/product/media_system_ext.mk
index e79a7eb5d1..455a253436 100644
--- a/target/product/media_system_ext.mk
+++ b/target/product/media_system_ext.mk
@@ -20,5 +20,8 @@
 # base_system_ext.mk.
 $(call inherit-product, $(SRC_TARGET_DIR)/product/base_system_ext.mk)
 
+PRODUCT_PACKAGES += \
+    StatementService \
+
 # Window Extensions
 $(call inherit-product, $(SRC_TARGET_DIR)/product/window_extensions_base.mk)
diff --git a/target/product/runtime_libart.mk b/target/product/runtime_libart.mk
index 9e8afa85a4..71138ac560 100644
--- a/target/product/runtime_libart.mk
+++ b/target/product/runtime_libart.mk
@@ -142,6 +142,7 @@ ifneq (,$(filter true,$(OVERRIDE_DISABLE_DEXOPT_ALL)))
   # be too much of a problem for platform developers because a change to framework code should not
   # trigger dexpreopt for the ART boot image.
   WITH_DEXPREOPT_ART_BOOT_IMG_ONLY := true
+  $(call soong_config_set_bool,PrebuiltGmsCore,ExcludeExtractApk,true)
 endif
 
 # Enable resolution of startup const strings.
@@ -157,15 +158,14 @@ PRODUCT_SYSTEM_PROPERTIES += \
     dalvik.vm.minidebuginfo=true \
     dalvik.vm.dex2oat-minidebuginfo=true
 
-# Enable Madvising of the whole art, odex and vdex files to MADV_WILLNEED.
+# Enable Madvising of the whole odex and vdex files to MADV_WILLNEED.
 # The size specified here is the size limit of how much of the file
 # (in bytes) is madvised.
-# We madvise the whole .art file to MADV_WILLNEED with UINT_MAX limit.
 # For odex and vdex files, we limit madvising to 100MB.
+# For art files, we defer to the runtime for default behavior.
 PRODUCT_SYSTEM_PROPERTIES += \
     dalvik.vm.madvise.vdexfile.size=104857600 \
-    dalvik.vm.madvise.odexfile.size=104857600 \
-    dalvik.vm.madvise.artfile.size=4294967295
+    dalvik.vm.madvise.odexfile.size=104857600
 
 # Properties for the Unspecialized App Process Pool
 PRODUCT_SYSTEM_PROPERTIES += \
diff --git a/target/product/security/Android.bp b/target/product/security/Android.bp
index ffbec0616e..214c009ec8 100644
--- a/target/product/security/Android.bp
+++ b/target/product/security/Android.bp
@@ -33,7 +33,13 @@ prebuilt_etc {
 // image
 otacerts_zip {
     name: "otacerts",
-    recovery_available: true,
+    relative_install_path: "security",
+    filename: "otacerts.zip",
+}
+
+otacerts_zip {
+    name: "otacerts.recovery",
+    recovery: true,
     relative_install_path: "security",
     filename: "otacerts.zip",
 }
diff --git a/target/product/security/BUILD.bazel b/target/product/security/BUILD.bazel
deleted file mode 100644
index c12be79833..0000000000
--- a/target/product/security/BUILD.bazel
+++ /dev/null
@@ -1,8 +0,0 @@
-filegroup(
-    name = "android_certificate_directory",
-    srcs = glob([
-        "*.pk8",
-        "*.pem",
-    ]),
-    visibility = ["//visibility:public"],
-)
diff --git a/target/product/virtual_ab_ota/vabc_features.mk b/target/product/virtual_ab_ota/vabc_features.mk
index d092699a47..0339ebddb8 100644
--- a/target/product/virtual_ab_ota/vabc_features.mk
+++ b/target/product/virtual_ab_ota/vabc_features.mk
@@ -42,6 +42,7 @@ PRODUCT_VENDOR_PROPERTIES += ro.virtual_ab.compression.xor.enabled?=true
 # device's .mk file improve performance for low mem devices.
 #
 # PRODUCT_VENDOR_PROPERTIES += ro.virtual_ab.read_ahead_size=16
+# warning: enabling o_direct on devices with low CMA could lead to failures
 # PRODUCT_VENDOR_PROPERTIES += ro.virtual_ab.o_direct.enabled=true
 # PRODUCT_VENDOR_PROPERTIES += ro.virtual_ab.merge_thread_priority=19
 # PRODUCT_VENDOR_PROPERTIES += ro.virtual_ab.worker_thread_priority=0
@@ -52,6 +53,16 @@ PRODUCT_VENDOR_PROPERTIES += ro.virtual_ab.compression.xor.enabled?=true
 # PRODUCT_VENDOR_PROPERTIES += ro.virtual_ab.verify_threshold_size=1073741824
 # PRODUCT_VENDOR_PROPERTIES += ro.virtual_ab.verify_block_size=1048576
 
+
+# Enabling this property will skip verification post OTA reboot.
+# Verification allows the device to safely roll back if any boot failures
+# are detected.  If the verification is disabled, update_verifier to will
+# try to verify using bufferred read if care_map.pb is present in
+# /metadata/ota/. This will increase the boot time and may also impact
+# memory usage as all the blocks in dynamic partitions are read into page-cache.
+# If care_map.pb isn't present, update-verifier will skip the verification.
+# PRODUCT_VENDOR_PROPERTIES += ro.virtual_ab.skip_verification =true
+
 # Enabling this property, will improve OTA install time
 # but will use an additional CPU core
 # PRODUCT_VENDOR_PROPERTIES += ro.virtual_ab.compression.threads=true
diff --git a/teams/Android.bp b/teams/Android.bp
index a2b0d1467f..7946a3d21a 100644
--- a/teams/Android.bp
+++ b/teams/Android.bp
@@ -931,7 +931,7 @@ team {
 }
 
 team {
-    name: "trendy_team_camerax",
+    name: "trendy_team_android_camera_innovation_team",
 
     // go/trendy/manage/engineers/5272590669479936
     trendy_team_id: "5272590669479936",
@@ -2520,7 +2520,7 @@ team {
 }
 
 team {
-    name: "trendy_team_xr_framework",
+    name: "trendy_team_virtual_device_framework",
 
     // go/trendy/manage/engineers/4798040542445568
     trendy_team_id: "4798040542445568",
@@ -3331,6 +3331,13 @@ team {
     trendy_team_id: "5407847298793472",
 }
 
+team {
+    name: "trendy_team_wear_partner_engineering",
+
+    // go/trendy/manage/engineers/5098351636676608
+    trendy_team_id: "5098351636676608",
+}
+
 team {
     name: "trendy_team_framework_android_multiuser",
 
@@ -4402,5 +4409,12 @@ team {
     trendy_team_id: "5440764114206720",
 }
 
+team {
+    name: "trendy_team_desktop_wifi",
+
+    // go/trendy/manage/engineers/6463689697099776
+    trendy_team_id: "6463689697099776",
+}
+
 // DON'T ADD NEW RULES HERE. For more details refer to
 // go/new-android-ownership-model
diff --git a/teams/OWNERS b/teams/OWNERS
index 85e69f356b..02846eb16a 100644
--- a/teams/OWNERS
+++ b/teams/OWNERS
@@ -1,3 +1,2 @@
 dariofreni@google.com
 ronish@google.com
-caditya@google.com
diff --git a/tools/Android.bp b/tools/Android.bp
index 59831a61ec..f1ff1c4719 100644
--- a/tools/Android.bp
+++ b/tools/Android.bp
@@ -85,11 +85,6 @@ python_binary_host {
     srcs: [
         "list_files.py",
     ],
-    version: {
-        py3: {
-            embedded_launcher: true,
-        },
-    },
 }
 
 python_test_host {
@@ -109,11 +104,6 @@ python_test_host {
 python_binary_host {
     name: "characteristics_rro_generator",
     srcs: ["characteristics_rro_generator.py"],
-    version: {
-        py3: {
-            embedded_launcher: true,
-        },
-    },
 }
 
 python_binary_host {
@@ -123,3 +113,11 @@ python_binary_host {
         "merge-event-log-tags.py",
     ],
 }
+
+python_binary_host {
+    name: "java-event-log-tags",
+    srcs: [
+        "event_log_tags.py",
+        "java-event-log-tags.py",
+    ],
+}
diff --git a/tools/BUILD.bazel b/tools/BUILD.bazel
deleted file mode 100644
index 9ec0dcef85..0000000000
--- a/tools/BUILD.bazel
+++ /dev/null
@@ -1,35 +0,0 @@
-py_library(
-    name = "event_log_tags",
-    srcs = ["event_log_tags.py"],
-    imports = ["."],
-)
-
-py_binary(
-    name = "java-event-log-tags",
-    srcs = ["java-event-log-tags.py"],
-    python_version = "PY3",
-    visibility = ["//visibility:public"],
-    deps = [":event_log_tags"],
-)
-
-py_binary(
-    name = "merge-event-log-tags",
-    srcs = ["merge-event-log-tags.py"],
-    python_version = "PY3",
-    visibility = ["//visibility:public"],
-    deps = [":event_log_tags"],
-)
-
-py_binary(
-    name = "check_elf_file",
-    srcs = ["check_elf_file.py"],
-    python_version = "PY3",
-    visibility = ["//visibility:public"],
-)
-
-py_binary(
-    name = "auto_gen_test_config",
-    srcs = ["auto_gen_test_config.py"],
-    python_version = "PY3",
-    visibility = ["//visibility:public"],
-)
diff --git a/tools/aconfig/Cargo.toml b/tools/aconfig/Cargo.toml
index bf5e1a9bc4..cb8377e64c 100644
--- a/tools/aconfig/Cargo.toml
+++ b/tools/aconfig/Cargo.toml
@@ -8,7 +8,8 @@ members = [
     "aconfig_storage_read_api",
     "aconfig_storage_write_api",
     "aflags",
-    "printflags"
+    "convert_finalized_flags",
+    "exported_flag_check",
 ]
 
 resolver = "2"
diff --git a/tools/aconfig/OWNERS b/tools/aconfig/OWNERS
index c92fc7cda3..0c31938d63 100644
--- a/tools/aconfig/OWNERS
+++ b/tools/aconfig/OWNERS
@@ -1,6 +1,5 @@
 dzshen@google.com
 opg@google.com
-tedbauer@google.com
 zhidou@google.com
 
 amhk@google.com  #{LAST_RESORT_SUGGESTION}
diff --git a/tools/aconfig/TEST_MAPPING b/tools/aconfig/TEST_MAPPING
index a7f0a4fa79..b1cc6025e2 100644
--- a/tools/aconfig/TEST_MAPPING
+++ b/tools/aconfig/TEST_MAPPING
@@ -42,10 +42,6 @@
       // aflags CLI unit tests
       "name": "aflags.test"
     },
-    {
-      // printflags unit tests
-      "name": "printflags.test"
-    },
     {
       // aconfig_protos unit tests
       "name": "aconfig_protos.test"
@@ -106,10 +102,6 @@
     {
       // aconfig_storage read functional test
       "name": "aconfig_storage_read_functional"
-    },
-    {
-      // aconfig_storage read unit test
-      "name": "aconfig_storage_read_unit"
     }
   ]
 }
diff --git a/tools/aconfig/aconfig/Android.bp b/tools/aconfig/aconfig/Android.bp
index 5e3eb12f3b..7bdec58004 100644
--- a/tools/aconfig/aconfig/Android.bp
+++ b/tools/aconfig/aconfig/Android.bp
@@ -7,7 +7,10 @@ rust_defaults {
     edition: "2021",
     clippy_lints: "android",
     lints: "android",
-    srcs: ["src/main.rs"],
+    srcs: [
+        "src/main.rs",
+        ":finalized_flags_record.json",
+    ],
     rustlibs: [
         "libaconfig_protos",
         "libaconfig_storage_file",
@@ -18,6 +21,7 @@ rust_defaults {
         "libserde",
         "libserde_json",
         "libtinytemplate",
+        "libconvert_finalized_flags",
     ],
 }
 
@@ -243,6 +247,11 @@ rust_aconfig_library {
     crate_name: "aconfig_test_rust_library",
     aconfig_declarations: "aconfig.test.flags",
     host_supported: true,
+    apex_available: [
+        "//apex_available:platform",
+        "com.android.configinfrastructure",
+    ],
+    min_sdk_version: "34",
 }
 
 rust_test {
diff --git a/tools/aconfig/aconfig/Cargo.toml b/tools/aconfig/aconfig/Cargo.toml
index abd3ee01e8..7e4bdf2f7d 100644
--- a/tools/aconfig/aconfig/Cargo.toml
+++ b/tools/aconfig/aconfig/Cargo.toml
@@ -17,3 +17,11 @@ serde_json = "1.0.93"
 tinytemplate = "1.2.1"
 aconfig_protos = { path = "../aconfig_protos" }
 aconfig_storage_file = { path = "../aconfig_storage_file" }
+convert_finalized_flags = { path = "../convert_finalized_flags" }
+
+[build-dependencies]
+anyhow = "1.0.69"
+itertools = "0.10.5"
+serde = { version = "1.0.152", features = ["derive"] }
+serde_json = "1.0.93"
+convert_finalized_flags = { path = "../convert_finalized_flags" }
diff --git a/tools/aconfig/aconfig/build.rs b/tools/aconfig/aconfig/build.rs
new file mode 100644
index 0000000000..8aaec3c43b
--- /dev/null
+++ b/tools/aconfig/aconfig/build.rs
@@ -0,0 +1,93 @@
+use anyhow::{anyhow, Result};
+use std::env;
+use std::fs;
+use std::fs::File;
+use std::io::Write;
+use std::path::{Path, PathBuf};
+
+use convert_finalized_flags::read_files_to_map_using_path;
+use convert_finalized_flags::FinalizedFlagMap;
+
+// This fn makes assumptions about the working directory which we should not rely
+// on for actual (Soong) builds. It is reasonable to assume that this is being
+// called from the aconfig directory as cargo is used for local development and
+// the cargo workspace for our project is build/make/tools/aconfig.
+// This is meant to get the list of finalized flag
+// files provided by the filegroup + "locations" in soong.
+// Cargo-only usage is asserted via implementation of
+// read_files_to_map_using_env, the only public cargo-only fn.
+fn read_files_to_map_using_env() -> Result<FinalizedFlagMap> {
+    let mut current_dir = std::env::current_dir()?;
+
+    // Path of aconfig from the top of tree.
+    let aconfig_path = PathBuf::from("build/make/tools/aconfig");
+
+    // Path of SDK files from the top of tree.
+    let sdk_dir_path = PathBuf::from("prebuilts/sdk");
+
+    // Iterate up the directory structure until we have the base aconfig dir.
+    while !current_dir.canonicalize()?.ends_with(&aconfig_path) {
+        if let Some(parent) = current_dir.parent() {
+            current_dir = parent.to_path_buf();
+        } else {
+            return Err(anyhow!("Cannot execute outside of aconfig."));
+        }
+    }
+
+    // Remove the aconfig path, leaving the top of the tree.
+    for _ in 0..aconfig_path.components().count() {
+        current_dir.pop();
+    }
+
+    // Get the absolute path of the sdk files.
+    current_dir.push(sdk_dir_path);
+
+    let mut flag_files = Vec::new();
+
+    // Search all sub-dirs in prebuilts/sdk for finalized-flags.txt files.
+    // The files are in prebuilts/sdk/<api level>/finalized-flags.txt.
+    let api_level_dirs = fs::read_dir(current_dir)?;
+    for api_level_dir in api_level_dirs {
+        if api_level_dir.is_err() {
+            eprintln!("Error opening directory: {}", api_level_dir.err().unwrap());
+            continue;
+        }
+
+        // Skip non-directories.
+        let api_level_dir_path = api_level_dir.unwrap().path();
+        if !api_level_dir_path.is_dir() {
+            continue;
+        }
+
+        // Some directories were created before trunk stable and don't have
+        // flags, or aren't api level directories at all.
+        let flag_file_path = api_level_dir_path.join("finalized-flags.txt");
+        if !flag_file_path.exists() {
+            continue;
+        }
+
+        if let Some(path) = flag_file_path.to_str() {
+            flag_files.push(path.to_string());
+        } else {
+            eprintln!("Error converting path to string: {:?}", flag_file_path);
+        }
+    }
+
+    read_files_to_map_using_path(flag_files)
+}
+
+fn main() {
+    let out_dir = env::var_os("OUT_DIR").unwrap();
+    let dest_path = Path::new(&out_dir).join("finalized_flags_record.json");
+
+    let finalized_flags_map: Result<FinalizedFlagMap> = read_files_to_map_using_env();
+    if finalized_flags_map.is_err() {
+        return;
+    }
+    let json_str = serde_json::to_string(&finalized_flags_map.unwrap()).unwrap();
+
+    let mut f = File::create(&dest_path).unwrap();
+    f.write_all(json_str.as_bytes()).unwrap();
+
+    //println!("cargo:rerun-if-changed=input.txt");
+}
diff --git a/tools/aconfig/aconfig/src/codegen/cpp.rs b/tools/aconfig/aconfig/src/codegen/cpp.rs
index ae18679f62..b855d78602 100644
--- a/tools/aconfig/aconfig/src/codegen/cpp.rs
+++ b/tools/aconfig/aconfig/src/codegen/cpp.rs
@@ -24,14 +24,13 @@ use aconfig_protos::{ProtoFlagPermission, ProtoFlagState, ProtoParsedFlag};
 
 use crate::codegen;
 use crate::codegen::CodegenMode;
-use crate::commands::OutputFile;
+use crate::commands::{should_include_flag, OutputFile};
 
 pub fn generate_cpp_code<I>(
     package: &str,
     parsed_flags_iter: I,
     codegen_mode: CodegenMode,
     flag_ids: HashMap<String, u16>,
-    allow_instrumentation: bool,
 ) -> Result<Vec<OutputFile>>
 where
     I: Iterator<Item = ProtoParsedFlag>,
@@ -59,7 +58,6 @@ where
         is_test_mode: codegen_mode == CodegenMode::Test,
         class_elements,
         container,
-        allow_instrumentation,
     };
 
     let files = [
@@ -104,7 +102,6 @@ pub struct Context<'a> {
     pub is_test_mode: bool,
     pub class_elements: Vec<ClassElement>,
     pub container: String,
-    pub allow_instrumentation: bool,
 }
 
 #[derive(Serialize)]
@@ -127,10 +124,7 @@ fn create_class_element(
     flag_ids: HashMap<String, u16>,
     rw_count: &mut i32,
 ) -> ClassElement {
-    let no_assigned_offset =
-        (pf.container() == "system" || pf.container() == "vendor" || pf.container() == "product")
-            && pf.permission() == ProtoFlagPermission::READ_ONLY
-            && pf.state() == ProtoFlagState::DISABLED;
+    let no_assigned_offset = !should_include_flag(pf);
 
     let flag_offset = match flag_ids.get(pf.name()) {
         Some(offset) => offset,
@@ -240,11 +234,11 @@ inline bool disabled_rw_in_other_namespace() {
     return provider_->disabled_rw_in_other_namespace();
 }
 
-inline bool enabled_fixed_ro() {
+constexpr inline bool enabled_fixed_ro() {
     return COM_ANDROID_ACONFIG_TEST_ENABLED_FIXED_RO;
 }
 
-inline bool enabled_fixed_ro_exported() {
+constexpr inline bool enabled_fixed_ro_exported() {
     return COM_ANDROID_ACONFIG_TEST_ENABLED_FIXED_RO_EXPORTED;
 }
 
@@ -452,56 +446,6 @@ void com_android_aconfig_test_reset_flags();
 #endif
 
 
-"#;
-
-    const EXPORTED_EXPORTED_HEADER_EXPECTED: &str = r#"
-#pragma once
-
-#ifdef __cplusplus
-
-#include <memory>
-
-namespace com::android::aconfig::test {
-
-class flag_provider_interface {
-public:
-    virtual ~flag_provider_interface() = default;
-
-    virtual bool disabled_rw_exported() = 0;
-
-    virtual bool enabled_fixed_ro_exported() = 0;
-
-    virtual bool enabled_ro_exported() = 0;
-};
-
-extern std::unique_ptr<flag_provider_interface> provider_;
-
-inline bool disabled_rw_exported() {
-    return provider_->disabled_rw_exported();
-}
-
-inline bool enabled_fixed_ro_exported() {
-    return provider_->enabled_fixed_ro_exported();
-}
-
-inline bool enabled_ro_exported() {
-    return provider_->enabled_ro_exported();
-}
-
-}
-
-extern "C" {
-#endif // __cplusplus
-
-bool com_android_aconfig_test_disabled_rw_exported();
-
-bool com_android_aconfig_test_enabled_fixed_ro_exported();
-
-bool com_android_aconfig_test_enabled_ro_exported();
-
-#ifdef __cplusplus
-} // extern "C"
-#endif
 "#;
 
     const EXPORTED_FORCE_READ_ONLY_HEADER_EXPECTED: &str = r#"
@@ -552,7 +496,7 @@ inline bool disabled_rw_in_other_namespace() {
     return false;
 }
 
-inline bool enabled_fixed_ro() {
+constexpr inline bool enabled_fixed_ro() {
     return COM_ANDROID_ACONFIG_TEST_ENABLED_FIXED_RO;
 }
 
@@ -588,7 +532,13 @@ bool com_android_aconfig_test_enabled_rw();
 
     const PROD_SOURCE_FILE_EXPECTED: &str = r#"
 #include "com_android_aconfig_test.h"
-#include <server_configurable_flags/get_flags.h>
+
+#include <unistd.h>
+#include "aconfig_storage/aconfig_storage_read_api.hpp"
+#include <android/log.h>
+#define LOG_TAG "aconfig_cpp_codegen"
+#define ALOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
+
 #include <vector>
 
 namespace com::android::aconfig::test {
@@ -596,36 +546,116 @@ namespace com::android::aconfig::test {
     class flag_provider : public flag_provider_interface {
         public:
 
+            flag_provider()
+                : cache_(4, -1)
+                , boolean_start_index_()
+                , flag_value_file_(nullptr)
+                , package_exists_in_storage_(true) {
+
+                auto package_map_file = aconfig_storage::get_mapped_file(
+                    "system",
+                    aconfig_storage::StorageFileType::package_map);
+                if (!package_map_file.ok()) {
+                    ALOGE("error: failed to get package map file: %s", package_map_file.error().c_str());
+                    package_exists_in_storage_ = false;
+                    return;
+                }
+
+                auto context = aconfig_storage::get_package_read_context(
+                    **package_map_file, "com.android.aconfig.test");
+                if (!context.ok()) {
+                    ALOGE("error: failed to get package read context: %s", context.error().c_str());
+                    package_exists_in_storage_ = false;
+                    return;
+                }
+
+                if (!(context->package_exists)) {
+                    package_exists_in_storage_ = false;
+                    return;
+                }
+
+                // cache package boolean flag start index
+                boolean_start_index_ = context->boolean_start_index;
+
+                // unmap package map file and free memory
+                delete *package_map_file;
+
+                auto flag_value_file = aconfig_storage::get_mapped_file(
+                    "system",
+                    aconfig_storage::StorageFileType::flag_val);
+                if (!flag_value_file.ok()) {
+                    ALOGE("error: failed to get flag value file: %s", flag_value_file.error().c_str());
+                    package_exists_in_storage_ = false;
+                    return;
+                }
+
+                // cache flag value file
+                flag_value_file_ = std::unique_ptr<aconfig_storage::MappedStorageFile>(
+                    *flag_value_file);
+
+            }
+
+
             virtual bool disabled_ro() override {
                 return false;
             }
 
             virtual bool disabled_rw() override {
                 if (cache_[0] == -1) {
-                    cache_[0] = server_configurable_flags::GetServerConfigurableFlag(
-                        "aconfig_flags.aconfig_test",
-                        "com.android.aconfig.test.disabled_rw",
-                        "false") == "true";
+                    if (!package_exists_in_storage_) {
+                        return false;
+                    }
+
+                    auto value = aconfig_storage::get_boolean_flag_value(
+                        *flag_value_file_,
+                        boolean_start_index_ + 0);
+
+                    if (!value.ok()) {
+                        ALOGE("error: failed to read flag value: %s", value.error().c_str());
+                        return false;
+                    }
+
+                    cache_[0] = *value;
                 }
                 return cache_[0];
             }
 
             virtual bool disabled_rw_exported() override {
                 if (cache_[1] == -1) {
-                    cache_[1] = server_configurable_flags::GetServerConfigurableFlag(
-                        "aconfig_flags.aconfig_test",
-                        "com.android.aconfig.test.disabled_rw_exported",
-                        "false") == "true";
+                    if (!package_exists_in_storage_) {
+                        return false;
+                    }
+
+                    auto value = aconfig_storage::get_boolean_flag_value(
+                        *flag_value_file_,
+                        boolean_start_index_ + 1);
+
+                    if (!value.ok()) {
+                        ALOGE("error: failed to read flag value: %s", value.error().c_str());
+                        return false;
+                    }
+
+                    cache_[1] = *value;
                 }
                 return cache_[1];
             }
 
             virtual bool disabled_rw_in_other_namespace() override {
                 if (cache_[2] == -1) {
-                    cache_[2] = server_configurable_flags::GetServerConfigurableFlag(
-                        "aconfig_flags.other_namespace",
-                        "com.android.aconfig.test.disabled_rw_in_other_namespace",
-                        "false") == "true";
+                    if (!package_exists_in_storage_) {
+                        return false;
+                    }
+
+                    auto value = aconfig_storage::get_boolean_flag_value(
+                        *flag_value_file_,
+                        boolean_start_index_ + 2);
+
+                    if (!value.ok()) {
+                        ALOGE("error: failed to read flag value: %s", value.error().c_str());
+                        return false;
+                    }
+
+                    cache_[2] = *value;
                 }
                 return cache_[2];
             }
@@ -648,16 +678,32 @@ namespace com::android::aconfig::test {
 
             virtual bool enabled_rw() override {
                 if (cache_[3] == -1) {
-                    cache_[3] = server_configurable_flags::GetServerConfigurableFlag(
-                        "aconfig_flags.aconfig_test",
-                        "com.android.aconfig.test.enabled_rw",
-                        "true") == "true";
+                    if (!package_exists_in_storage_) {
+                        return true;
+                    }
+
+                    auto value = aconfig_storage::get_boolean_flag_value(
+                        *flag_value_file_,
+                        boolean_start_index_ + 7);
+
+                    if (!value.ok()) {
+                        ALOGE("error: failed to read flag value: %s", value.error().c_str());
+                        return true;
+                    }
+
+                    cache_[3] = *value;
                 }
                 return cache_[3];
             }
 
     private:
         std::vector<int8_t> cache_ = std::vector<int8_t>(4, -1);
+
+        uint32_t boolean_start_index_;
+
+        std::unique_ptr<aconfig_storage::MappedStorageFile> flag_value_file_;
+
+        bool package_exists_in_storage_;
     };
 
     std::unique_ptr<flag_provider_interface> provider_ =
@@ -704,7 +750,13 @@ bool com_android_aconfig_test_enabled_rw() {
 
     const TEST_SOURCE_FILE_EXPECTED: &str = r#"
 #include "com_android_aconfig_test.h"
-#include <server_configurable_flags/get_flags.h>
+
+#include <unistd.h>
+#include "aconfig_storage/aconfig_storage_read_api.hpp"
+#include <android/log.h>
+#define LOG_TAG "aconfig_cpp_codegen"
+#define ALOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
+
 #include <unordered_map>
 #include <string>
 
@@ -714,10 +766,63 @@ namespace com::android::aconfig::test {
         private:
             std::unordered_map<std::string, bool> overrides_;
 
+            uint32_t boolean_start_index_;
+
+            std::unique_ptr<aconfig_storage::MappedStorageFile> flag_value_file_;
+
+            bool package_exists_in_storage_;
+
         public:
             flag_provider()
                 : overrides_()
-            {}
+                , boolean_start_index_()
+                , flag_value_file_(nullptr)
+                , package_exists_in_storage_(true) {
+
+                auto package_map_file = aconfig_storage::get_mapped_file(
+                     "system",
+                    aconfig_storage::StorageFileType::package_map);
+
+                if (!package_map_file.ok()) {
+                    ALOGE("error: failed to get package map file: %s", package_map_file.error().c_str());
+                    package_exists_in_storage_ = false;
+                    return;
+                }
+
+                auto context = aconfig_storage::get_package_read_context(
+                    **package_map_file, "com.android.aconfig.test");
+
+                if (!context.ok()) {
+                    ALOGE("error: failed to get package read context: %s", context.error().c_str());
+                    package_exists_in_storage_ = false;
+                    return;
+                }
+
+                if (!(context->package_exists)) {
+                    package_exists_in_storage_ = false;
+                    return;
+                }
+
+                // cache package boolean flag start index
+                boolean_start_index_ = context->boolean_start_index;
+
+                // unmap package map file and free memory
+                delete *package_map_file;
+
+                auto flag_value_file = aconfig_storage::get_mapped_file(
+                    "system",
+                aconfig_storage::StorageFileType::flag_val);
+                if (!flag_value_file.ok()) {
+                    ALOGE("error: failed to get flag value file: %s", flag_value_file.error().c_str());
+                    package_exists_in_storage_ = false;
+                    return;
+                }
+
+                // cache flag value file
+                flag_value_file_ = std::unique_ptr<aconfig_storage::MappedStorageFile>(
+                *flag_value_file);
+
+            }
 
             virtual bool disabled_ro() override {
                 auto it = overrides_.find("disabled_ro");
@@ -737,10 +842,20 @@ namespace com::android::aconfig::test {
                   if (it != overrides_.end()) {
                       return it->second;
                 } else {
-                  return server_configurable_flags::GetServerConfigurableFlag(
-                      "aconfig_flags.aconfig_test",
-                      "com.android.aconfig.test.disabled_rw",
-                      "false") == "true";
+                    if (!package_exists_in_storage_) {
+                        return false;
+                    }
+
+                    auto value = aconfig_storage::get_boolean_flag_value(
+                        *flag_value_file_,
+                        boolean_start_index_ + 0);
+
+                    if (!value.ok()) {
+                        ALOGE("error: failed to read flag value: %s", value.error().c_str());
+                        return false;
+                    } else {
+                        return *value;
+                    }
                 }
             }
 
@@ -753,10 +868,20 @@ namespace com::android::aconfig::test {
                   if (it != overrides_.end()) {
                       return it->second;
                 } else {
-                  return server_configurable_flags::GetServerConfigurableFlag(
-                      "aconfig_flags.aconfig_test",
-                      "com.android.aconfig.test.disabled_rw_exported",
-                      "false") == "true";
+                    if (!package_exists_in_storage_) {
+                        return false;
+                    }
+
+                    auto value = aconfig_storage::get_boolean_flag_value(
+                        *flag_value_file_,
+                        boolean_start_index_ + 1);
+
+                    if (!value.ok()) {
+                        ALOGE("error: failed to read flag value: %s", value.error().c_str());
+                        return false;
+                    } else {
+                        return *value;
+                    }
                 }
             }
 
@@ -769,10 +894,20 @@ namespace com::android::aconfig::test {
                   if (it != overrides_.end()) {
                       return it->second;
                 } else {
-                  return server_configurable_flags::GetServerConfigurableFlag(
-                      "aconfig_flags.other_namespace",
-                      "com.android.aconfig.test.disabled_rw_in_other_namespace",
-                      "false") == "true";
+                    if (!package_exists_in_storage_) {
+                        return false;
+                    }
+
+                    auto value = aconfig_storage::get_boolean_flag_value(
+                        *flag_value_file_,
+                        boolean_start_index_ + 2);
+
+                    if (!value.ok()) {
+                        ALOGE("error: failed to read flag value: %s", value.error().c_str());
+                        return false;
+                    } else {
+                        return *value;
+                    }
                 }
             }
 
@@ -837,10 +972,20 @@ namespace com::android::aconfig::test {
                   if (it != overrides_.end()) {
                       return it->second;
                 } else {
-                  return server_configurable_flags::GetServerConfigurableFlag(
-                      "aconfig_flags.aconfig_test",
-                      "com.android.aconfig.test.enabled_rw",
-                      "true") == "true";
+                    if (!package_exists_in_storage_) {
+                        return true;
+                    }
+
+                    auto value = aconfig_storage::get_boolean_flag_value(
+                        *flag_value_file_,
+                        boolean_start_index_ + 7);
+
+                    if (!value.ok()) {
+                        ALOGE("error: failed to read flag value: %s", value.error().c_str());
+                        return true;
+                    } else {
+                        return *value;
+                    }
                 }
             }
 
@@ -943,68 +1088,6 @@ void com_android_aconfig_test_reset_flags() {
      com::android::aconfig::test::reset_flags();
 }
 
-"#;
-
-    const EXPORTED_SOURCE_FILE_EXPECTED: &str = r#"
-#include "com_android_aconfig_test.h"
-#include <server_configurable_flags/get_flags.h>
-#include <vector>
-
-namespace com::android::aconfig::test {
-
-    class flag_provider : public flag_provider_interface {
-        public:
-            virtual bool disabled_rw_exported() override {
-                if (cache_[0] == -1) {
-                    cache_[0] = server_configurable_flags::GetServerConfigurableFlag(
-                        "aconfig_flags.aconfig_test",
-                        "com.android.aconfig.test.disabled_rw_exported",
-                        "false") == "true";
-                }
-                return cache_[0];
-            }
-
-            virtual bool enabled_fixed_ro_exported() override {
-                if (cache_[1] == -1) {
-                    cache_[1] = server_configurable_flags::GetServerConfigurableFlag(
-                        "aconfig_flags.aconfig_test",
-                        "com.android.aconfig.test.enabled_fixed_ro_exported",
-                        "false") == "true";
-                }
-                return cache_[1];
-            }
-
-            virtual bool enabled_ro_exported() override {
-                if (cache_[2] == -1) {
-                    cache_[2] = server_configurable_flags::GetServerConfigurableFlag(
-                        "aconfig_flags.aconfig_test",
-                        "com.android.aconfig.test.enabled_ro_exported",
-                        "false") == "true";
-                }
-                return cache_[2];
-            }
-
-    private:
-        std::vector<int8_t> cache_ = std::vector<int8_t>(3, -1);
-    };
-
-    std::unique_ptr<flag_provider_interface> provider_ =
-        std::make_unique<flag_provider>();
-}
-
-bool com_android_aconfig_test_disabled_rw_exported() {
-    return com::android::aconfig::test::disabled_rw_exported();
-}
-
-bool com_android_aconfig_test_enabled_fixed_ro_exported() {
-    return com::android::aconfig::test::enabled_fixed_ro_exported();
-}
-
-bool com_android_aconfig_test_enabled_ro_exported() {
-    return com::android::aconfig::test::enabled_ro_exported();
-}
-
-
 "#;
 
     const FORCE_READ_ONLY_SOURCE_FILE_EXPECTED: &str = r#"
@@ -1106,7 +1189,7 @@ public:
 
 extern std::unique_ptr<flag_provider_interface> provider_;
 
-inline bool disabled_fixed_ro() {
+constexpr inline bool disabled_fixed_ro() {
     return COM_ANDROID_ACONFIG_TEST_DISABLED_FIXED_RO;
 }
 
@@ -1114,7 +1197,7 @@ inline bool disabled_ro() {
     return false;
 }
 
-inline bool enabled_fixed_ro() {
+constexpr inline bool enabled_fixed_ro() {
     return COM_ANDROID_ACONFIG_TEST_ENABLED_FIXED_RO;
 }
 
@@ -1191,7 +1274,6 @@ bool com_android_aconfig_test_enabled_ro() {
         mode: CodegenMode,
         expected_header: &str,
         expected_src: &str,
-        allow_instrumentation: bool,
     ) {
         let modified_parsed_flags =
             crate::commands::modify_parsed_flags_based_on_mode(parsed_flags, mode).unwrap();
@@ -1202,7 +1284,6 @@ bool com_android_aconfig_test_enabled_ro() {
             modified_parsed_flags.into_iter(),
             mode,
             flag_ids,
-            allow_instrumentation,
         )
         .unwrap();
         let mut generated_files_map = HashMap::new();
@@ -1242,7 +1323,6 @@ bool com_android_aconfig_test_enabled_ro() {
             CodegenMode::Production,
             EXPORTED_PROD_HEADER_EXPECTED,
             PROD_SOURCE_FILE_EXPECTED,
-            false,
         );
     }
 
@@ -1254,19 +1334,6 @@ bool com_android_aconfig_test_enabled_ro() {
             CodegenMode::Test,
             EXPORTED_TEST_HEADER_EXPECTED,
             TEST_SOURCE_FILE_EXPECTED,
-            false,
-        );
-    }
-
-    #[test]
-    fn test_generate_cpp_code_for_exported() {
-        let parsed_flags = crate::test::parse_test_flags();
-        test_generate_cpp_code(
-            parsed_flags,
-            CodegenMode::Exported,
-            EXPORTED_EXPORTED_HEADER_EXPECTED,
-            EXPORTED_SOURCE_FILE_EXPECTED,
-            false,
         );
     }
 
@@ -1278,7 +1345,6 @@ bool com_android_aconfig_test_enabled_ro() {
             CodegenMode::ForceReadOnly,
             EXPORTED_FORCE_READ_ONLY_HEADER_EXPECTED,
             FORCE_READ_ONLY_SOURCE_FILE_EXPECTED,
-            false,
         );
     }
 
@@ -1290,7 +1356,6 @@ bool com_android_aconfig_test_enabled_ro() {
             CodegenMode::Production,
             READ_ONLY_EXPORTED_PROD_HEADER_EXPECTED,
             READ_ONLY_PROD_SOURCE_FILE_EXPECTED,
-            false,
         );
     }
 }
diff --git a/tools/aconfig/aconfig/src/codegen/java.rs b/tools/aconfig/aconfig/src/codegen/java.rs
index 7aff4e918a..e9c95fd766 100644
--- a/tools/aconfig/aconfig/src/codegen/java.rs
+++ b/tools/aconfig/aconfig/src/codegen/java.rs
@@ -22,32 +22,45 @@ use tinytemplate::TinyTemplate;
 
 use crate::codegen;
 use crate::codegen::CodegenMode;
-use crate::commands::OutputFile;
+use crate::commands::{should_include_flag, OutputFile};
 use aconfig_protos::{ProtoFlagPermission, ProtoFlagState, ProtoParsedFlag};
+use convert_finalized_flags::{FinalizedFlag, FinalizedFlagMap};
 use std::collections::HashMap;
 
+// Arguments to configure codegen for generate_java_code.
+pub struct JavaCodegenConfig {
+    pub codegen_mode: CodegenMode,
+    pub flag_ids: HashMap<String, u16>,
+    pub allow_instrumentation: bool,
+    pub package_fingerprint: u64,
+    pub new_exported: bool,
+    pub single_exported_file: bool,
+    pub finalized_flags: FinalizedFlagMap,
+}
+
 pub fn generate_java_code<I>(
     package: &str,
     parsed_flags_iter: I,
-    codegen_mode: CodegenMode,
-    flag_ids: HashMap<String, u16>,
-    allow_instrumentation: bool,
-    package_fingerprint: u64,
+    config: JavaCodegenConfig,
 ) -> Result<Vec<OutputFile>>
 where
     I: Iterator<Item = ProtoParsedFlag>,
 {
-    let flag_elements: Vec<FlagElement> =
-        parsed_flags_iter.map(|pf| create_flag_element(package, &pf, flag_ids.clone())).collect();
+    let flag_elements: Vec<FlagElement> = parsed_flags_iter
+        .map(|pf| {
+            create_flag_element(package, &pf, config.flag_ids.clone(), &config.finalized_flags)
+        })
+        .collect();
     let namespace_flags = gen_flags_by_namespace(&flag_elements);
     let properties_set: BTreeSet<String> =
         flag_elements.iter().map(|fe| format_property_name(&fe.device_config_namespace)).collect();
-    let is_test_mode = codegen_mode == CodegenMode::Test;
-    let library_exported = codegen_mode == CodegenMode::Exported;
+    let is_test_mode = config.codegen_mode == CodegenMode::Test;
+    let library_exported = config.codegen_mode == CodegenMode::Exported;
     let runtime_lookup_required =
         flag_elements.iter().any(|elem| elem.is_read_write) || library_exported;
     let container = (flag_elements.first().expect("zero template flags").container).to_string();
-    let is_platform_container = matches!(container.as_str(), "system" | "product" | "vendor");
+    let is_platform_container =
+        matches!(container.as_str(), "system" | "system_ext" | "product" | "vendor");
     let context = Context {
         flag_elements,
         namespace_flags,
@@ -56,17 +69,22 @@ where
         properties_set,
         package_name: package.to_string(),
         library_exported,
-        allow_instrumentation,
+        allow_instrumentation: config.allow_instrumentation,
         container,
         is_platform_container,
-        package_fingerprint: format!("0x{:X}L", package_fingerprint),
+        package_fingerprint: format!("0x{:X}L", config.package_fingerprint),
+        new_exported: config.new_exported,
+        single_exported_file: config.single_exported_file,
     };
     let mut template = TinyTemplate::new();
+    if library_exported && config.single_exported_file {
+        template.add_template(
+            "ExportedFlags.java",
+            include_str!("../../templates/ExportedFlags.java.template"),
+        )?;
+    }
     template.add_template("Flags.java", include_str!("../../templates/Flags.java.template"))?;
-    template.add_template(
-        "FeatureFlagsImpl.java",
-        include_str!("../../templates/FeatureFlagsImpl.java.template"),
-    )?;
+    add_feature_flags_impl_template(&context, &mut template)?;
     template.add_template(
         "FeatureFlags.java",
         include_str!("../../templates/FeatureFlags.java.template"),
@@ -81,18 +99,25 @@ where
     )?;
 
     let path: PathBuf = package.split('.').collect();
-    [
+    let mut files = vec![
         "Flags.java",
         "FeatureFlags.java",
         "FeatureFlagsImpl.java",
         "CustomFeatureFlags.java",
         "FakeFeatureFlagsImpl.java",
-    ]
-    .iter()
-    .map(|file| {
-        Ok(OutputFile { contents: template.render(file, &context)?.into(), path: path.join(file) })
-    })
-    .collect::<Result<Vec<OutputFile>>>()
+    ];
+    if library_exported && config.single_exported_file {
+        files.push("ExportedFlags.java");
+    }
+    files
+        .iter()
+        .map(|file| {
+            Ok(OutputFile {
+                contents: template.render(file, &context)?.into(),
+                path: path.join(file),
+            })
+        })
+        .collect::<Result<Vec<OutputFile>>>()
 }
 
 fn gen_flags_by_namespace(flags: &[FlagElement]) -> Vec<NamespaceFlags> {
@@ -129,6 +154,8 @@ struct Context {
     pub container: String,
     pub is_platform_container: bool,
     pub package_fingerprint: String,
+    pub new_exported: bool,
+    pub single_exported_file: bool,
 }
 
 #[derive(Serialize, Debug)]
@@ -149,20 +176,20 @@ struct FlagElement {
     pub is_read_write: bool,
     pub method_name: String,
     pub properties: String,
+    pub finalized_sdk_present: bool,
+    pub finalized_sdk_value: i32,
 }
 
 fn create_flag_element(
     package: &str,
     pf: &ProtoParsedFlag,
     flag_offsets: HashMap<String, u16>,
+    finalized_flags: &FinalizedFlagMap,
 ) -> FlagElement {
     let device_config_flag = codegen::create_device_config_ident(package, pf.name())
         .expect("values checked at flag parse time");
 
-    let no_assigned_offset =
-        (pf.container() == "system" || pf.container() == "vendor" || pf.container() == "product")
-            && pf.permission() == ProtoFlagPermission::READ_ONLY
-            && pf.state() == ProtoFlagState::DISABLED;
+    let no_assigned_offset = !should_include_flag(pf);
 
     let flag_offset = match flag_offsets.get(pf.name()) {
         Some(offset) => offset,
@@ -179,6 +206,18 @@ fn create_flag_element(
         }
     };
 
+    // An empty map is provided if check_api_level is disabled.
+    let mut finalized_sdk_present: bool = false;
+    let mut finalized_sdk_value: i32 = 0;
+    if !finalized_flags.is_empty() {
+        let finalized_sdk = finalized_flags.get_finalized_level(&FinalizedFlag {
+            flag_name: pf.name().to_string(),
+            package_name: package.to_string(),
+        });
+        finalized_sdk_present = finalized_sdk.is_some();
+        finalized_sdk_value = finalized_sdk.map(|f| f.0).unwrap_or_default();
+    }
+
     FlagElement {
         container: pf.container().to_string(),
         default_value: pf.state() == ProtoFlagState::ENABLED,
@@ -190,6 +229,8 @@ fn create_flag_element(
         is_read_write: pf.permission() == ProtoFlagPermission::READ_WRITE,
         method_name: format_java_method_name(pf.name()),
         properties: format_property_name(pf.namespace()),
+        finalized_sdk_present,
+        finalized_sdk_value,
     }
 }
 
@@ -219,8 +260,62 @@ fn format_property_name(property_name: &str) -> String {
     format!("mProperties{}{}", &name[0..1].to_ascii_uppercase(), &name[1..])
 }
 
+fn add_feature_flags_impl_template(
+    context: &Context,
+    template: &mut TinyTemplate,
+) -> Result<(), tinytemplate::error::Error> {
+    if context.is_test_mode {
+        // Test mode has its own template, so use regardless of any other settings.
+        template.add_template(
+            "FeatureFlagsImpl.java",
+            include_str!("../../templates/FeatureFlagsImpl.test_mode.java.template"),
+        )?;
+        return Ok(());
+    }
+
+    match (context.library_exported, context.new_exported, context.allow_instrumentation) {
+        // Exported library with new_exported enabled, use new storage exported template.
+        (true, true, _) => {
+            template.add_template(
+                "FeatureFlagsImpl.java",
+                include_str!("../../templates/FeatureFlagsImpl.exported.java.template"),
+            )?;
+        }
+
+        // Exported library with new_exported NOT enabled, use legacy (device
+        // config) template, because regardless of allow_instrumentation, we use
+        // device config for exported libs if new_exported isn't enabled.
+        // Remove once new_exported is fully rolled out.
+        (true, false, _) => {
+            template.add_template(
+                "FeatureFlagsImpl.java",
+                include_str!("../../templates/FeatureFlagsImpl.deviceConfig.java.template"),
+            )?;
+        }
+
+        // New storage internal mode.
+        (false, _, true) => {
+            template.add_template(
+                "FeatureFlagsImpl.java",
+                include_str!("../../templates/FeatureFlagsImpl.new_storage.java.template"),
+            )?;
+        }
+
+        // Device config internal mode. Use legacy (device config) template.
+        (false, _, false) => {
+            template.add_template(
+                "FeatureFlagsImpl.java",
+                include_str!("../../templates/FeatureFlagsImpl.deviceConfig.java.template"),
+            )?;
+        }
+    };
+    Ok(())
+}
+
 #[cfg(test)]
 mod tests {
+    use convert_finalized_flags::ApiLevel;
+
     use super::*;
     use crate::commands::assign_flag_ids;
     use std::collections::HashMap;
@@ -523,13 +618,19 @@ mod tests {
             crate::commands::modify_parsed_flags_based_on_mode(parsed_flags, mode).unwrap();
         let flag_ids =
             assign_flag_ids(crate::test::TEST_PACKAGE, modified_parsed_flags.iter()).unwrap();
+        let config = JavaCodegenConfig {
+            codegen_mode: mode,
+            flag_ids,
+            allow_instrumentation: true,
+            package_fingerprint: 5801144784618221668,
+            new_exported: false,
+            single_exported_file: false,
+            finalized_flags: FinalizedFlagMap::new(),
+        };
         let generated_files = generate_java_code(
             crate::test::TEST_PACKAGE,
             modified_parsed_flags.into_iter(),
-            mode,
-            flag_ids,
-            true,
-            5801144784618221668,
+            config,
         )
         .unwrap();
         let expect_flags_content = EXPECTED_FLAG_COMMON_CONTENT.to_string()
@@ -541,12 +642,11 @@ mod tests {
         package com.android.aconfig.test;
         // TODO(b/303773055): Remove the annotation after access issue is resolved.
         import android.compat.annotation.UnsupportedAppUsage;
-        import android.os.Build;
         import android.os.flagging.PlatformAconfigPackageInternal;
         import android.util.Log;
         /** @hide */
         public final class FeatureFlagsImpl implements FeatureFlags {
-            private static final String TAG = "com.android.aconfig.test.FeatureFlagsImpl";
+            private static final String TAG = "FeatureFlagsImpl";
             private static volatile boolean isCached = false;
             private static boolean disabledRw = false;
             private static boolean disabledRwExported = false;
@@ -554,14 +654,14 @@ mod tests {
             private static boolean enabledRw = true;
             private void init() {
                 try {
-                    PlatformAconfigPackageInternal reader = PlatformAconfigPackageInternal.load("system", "com.android.aconfig.test", 0x5081CE7221C77064L);
+                    PlatformAconfigPackageInternal reader = PlatformAconfigPackageInternal.load("com.android.aconfig.test", 0x5081CE7221C77064L);
                     disabledRw = reader.getBooleanFlagValue(0);
                     disabledRwExported = reader.getBooleanFlagValue(1);
                     enabledRw = reader.getBooleanFlagValue(7);
                     disabledRwInOtherNamespace = reader.getBooleanFlagValue(2);
                 } catch (Exception e) {
                     Log.e(TAG, e.toString());
-                } catch (NoClassDefFoundError e) {
+                } catch (LinkageError e) {
                     // for mainline module running on older devices.
                     // This should be replaces to version check, after the version bump.
                     Log.e(TAG, e.toString());
@@ -678,18 +778,25 @@ mod tests {
             crate::commands::modify_parsed_flags_based_on_mode(parsed_flags, mode).unwrap();
         let flag_ids =
             assign_flag_ids(crate::test::TEST_PACKAGE, modified_parsed_flags.iter()).unwrap();
+        let config = JavaCodegenConfig {
+            codegen_mode: mode,
+            flag_ids,
+            allow_instrumentation: true,
+            package_fingerprint: 5801144784618221668,
+            new_exported: false,
+            single_exported_file: false,
+            finalized_flags: FinalizedFlagMap::new(),
+        };
         let generated_files = generate_java_code(
             crate::test::TEST_PACKAGE,
             modified_parsed_flags.into_iter(),
-            mode,
-            flag_ids,
-            true,
-            5801144784618221668,
+            config,
         )
         .unwrap();
 
         let expect_flags_content = r#"
         package com.android.aconfig.test;
+        import android.os.Build;
         /** @hide */
         public final class Flags {
             /** @hide */
@@ -786,12 +893,16 @@ mod tests {
         package com.android.aconfig.test;
 
         import java.util.Arrays;
+        import java.util.HashMap;
+        import java.util.Map;
         import java.util.HashSet;
         import java.util.List;
         import java.util.Set;
         import java.util.function.BiPredicate;
         import java.util.function.Predicate;
 
+        import android.os.Build;
+
         /** @hide */
         public class CustomFeatureFlags implements FeatureFlags {
 
@@ -834,6 +945,19 @@ mod tests {
                     ""
                 )
             );
+
+            private Map<String, Integer> mFinalizedFlags = new HashMap<>(
+                Map.ofEntries(
+                    Map.entry("", Integer.MAX_VALUE)
+                )
+            );
+
+            public boolean isFlagFinalized(String flagName) {
+                if (!mFinalizedFlags.containsKey(flagName)) {
+                    return false;
+                }
+                return Build.VERSION.SDK_INT >= mFinalizedFlags.get(flagName);
+            }
         }
     "#;
 
@@ -869,6 +993,492 @@ mod tests {
         assert!(file_set.is_empty());
     }
 
+    #[test]
+    fn test_generate_java_code_new_exported() {
+        let parsed_flags = crate::test::parse_test_flags();
+        let mode = CodegenMode::Exported;
+        let modified_parsed_flags =
+            crate::commands::modify_parsed_flags_based_on_mode(parsed_flags, mode).unwrap();
+        let flag_ids =
+            assign_flag_ids(crate::test::TEST_PACKAGE, modified_parsed_flags.iter()).unwrap();
+        let config = JavaCodegenConfig {
+            codegen_mode: mode,
+            flag_ids,
+            allow_instrumentation: true,
+            package_fingerprint: 5801144784618221668,
+            new_exported: true,
+            single_exported_file: false,
+            finalized_flags: FinalizedFlagMap::new(),
+        };
+        let generated_files = generate_java_code(
+            crate::test::TEST_PACKAGE,
+            modified_parsed_flags.into_iter(),
+            config,
+        )
+        .unwrap();
+
+        let expect_flags_content = r#"
+        package com.android.aconfig.test;
+        import android.os.Build;
+        /** @hide */
+        public final class Flags {
+            /** @hide */
+            public static final String FLAG_DISABLED_RW_EXPORTED = "com.android.aconfig.test.disabled_rw_exported";
+            /** @hide */
+            public static final String FLAG_ENABLED_FIXED_RO_EXPORTED = "com.android.aconfig.test.enabled_fixed_ro_exported";
+            /** @hide */
+            public static final String FLAG_ENABLED_RO_EXPORTED = "com.android.aconfig.test.enabled_ro_exported";
+            public static boolean disabledRwExported() {
+                return FEATURE_FLAGS.disabledRwExported();
+            }
+            public static boolean enabledFixedRoExported() {
+                return FEATURE_FLAGS.enabledFixedRoExported();
+            }
+            public static boolean enabledRoExported() {
+                return FEATURE_FLAGS.enabledRoExported();
+            }
+            private static FeatureFlags FEATURE_FLAGS = new FeatureFlagsImpl();
+        }
+        "#;
+
+        let expect_feature_flags_content = r#"
+        package com.android.aconfig.test;
+        /** @hide */
+        public interface FeatureFlags {
+            boolean disabledRwExported();
+            boolean enabledFixedRoExported();
+            boolean enabledRoExported();
+        }
+        "#;
+
+        let expect_feature_flags_impl_content = r#"
+        package com.android.aconfig.test;
+        import android.os.Build;
+        import android.os.flagging.AconfigPackage;
+        import android.util.Log;
+        /** @hide */
+        public final class FeatureFlagsImpl implements FeatureFlags {
+            private static final String TAG = "FeatureFlagsImplExport";
+            private static volatile boolean isCached = false;
+            private static boolean disabledRwExported = false;
+            private static boolean enabledFixedRoExported = false;
+            private static boolean enabledRoExported = false;
+            private void init() {
+                try {
+                    AconfigPackage reader = AconfigPackage.load("com.android.aconfig.test");
+                    disabledRwExported = reader.getBooleanFlagValue("disabled_rw_exported", false);
+                    enabledFixedRoExported = reader.getBooleanFlagValue("enabled_fixed_ro_exported", false);
+                    enabledRoExported = reader.getBooleanFlagValue("enabled_ro_exported", false);
+                } catch (Exception e) {
+                    // pass
+                    Log.e(TAG, e.toString());
+                } catch (LinkageError e) {
+                    // for mainline module running on older devices.
+                    // This should be replaces to version check, after the version bump.
+                    Log.w(TAG, e.toString());
+                }
+                isCached = true;
+            }
+            @Override
+            public boolean disabledRwExported() {
+                if (!isCached) {
+                    init();
+                }
+                return disabledRwExported;
+            }
+            @Override
+            public boolean enabledFixedRoExported() {
+                if (!isCached) {
+                    init();
+                }
+                return enabledFixedRoExported;
+            }
+            @Override
+            public boolean enabledRoExported() {
+                if (!isCached) {
+                    init();
+                }
+                return enabledRoExported;
+            }
+        }"#;
+
+        let expect_custom_feature_flags_content = r#"
+        package com.android.aconfig.test;
+
+        import java.util.Arrays;
+        import java.util.HashMap;
+        import java.util.Map;
+        import java.util.HashSet;
+        import java.util.List;
+        import java.util.Set;
+        import java.util.function.BiPredicate;
+        import java.util.function.Predicate;
+        import android.os.Build;
+
+        /** @hide */
+        public class CustomFeatureFlags implements FeatureFlags {
+
+            private BiPredicate<String, Predicate<FeatureFlags>> mGetValueImpl;
+
+            public CustomFeatureFlags(BiPredicate<String, Predicate<FeatureFlags>> getValueImpl) {
+                mGetValueImpl = getValueImpl;
+            }
+
+            @Override
+            public boolean disabledRwExported() {
+                return getValue(Flags.FLAG_DISABLED_RW_EXPORTED,
+                    FeatureFlags::disabledRwExported);
+            }
+            @Override
+            public boolean enabledFixedRoExported() {
+                return getValue(Flags.FLAG_ENABLED_FIXED_RO_EXPORTED,
+                    FeatureFlags::enabledFixedRoExported);
+            }
+            @Override
+            public boolean enabledRoExported() {
+                return getValue(Flags.FLAG_ENABLED_RO_EXPORTED,
+                    FeatureFlags::enabledRoExported);
+            }
+
+            protected boolean getValue(String flagName, Predicate<FeatureFlags> getter) {
+                return mGetValueImpl.test(flagName, getter);
+            }
+
+            public List<String> getFlagNames() {
+                return Arrays.asList(
+                    Flags.FLAG_DISABLED_RW_EXPORTED,
+                    Flags.FLAG_ENABLED_FIXED_RO_EXPORTED,
+                    Flags.FLAG_ENABLED_RO_EXPORTED
+                );
+            }
+
+            private Set<String> mReadOnlyFlagsSet = new HashSet<>(
+                Arrays.asList(
+                    ""
+                )
+            );
+
+            private Map<String, Integer> mFinalizedFlags = new HashMap<>(
+                Map.ofEntries(
+                    Map.entry("", Integer.MAX_VALUE)
+                )
+            );
+
+            public boolean isFlagFinalized(String flagName) {
+                if (!mFinalizedFlags.containsKey(flagName)) {
+                    return false;
+                }
+                return Build.VERSION.SDK_INT >= mFinalizedFlags.get(flagName);
+            }
+        }
+    "#;
+
+        let mut file_set = HashMap::from([
+            ("com/android/aconfig/test/Flags.java", expect_flags_content),
+            ("com/android/aconfig/test/FeatureFlags.java", expect_feature_flags_content),
+            ("com/android/aconfig/test/FeatureFlagsImpl.java", expect_feature_flags_impl_content),
+            (
+                "com/android/aconfig/test/CustomFeatureFlags.java",
+                expect_custom_feature_flags_content,
+            ),
+            (
+                "com/android/aconfig/test/FakeFeatureFlagsImpl.java",
+                EXPECTED_FAKEFEATUREFLAGSIMPL_CONTENT,
+            ),
+        ]);
+
+        for file in generated_files {
+            let file_path = file.path.to_str().unwrap();
+            assert!(file_set.contains_key(file_path), "Cannot find {}", file_path);
+            assert_eq!(
+                None,
+                crate::test::first_significant_code_diff(
+                    file_set.get(file_path).unwrap(),
+                    &String::from_utf8(file.contents).unwrap()
+                ),
+                "File {} content is not correct",
+                file_path
+            );
+            file_set.remove(file_path);
+        }
+
+        assert!(file_set.is_empty());
+    }
+
+    #[test]
+    fn test_generate_java_code_new_exported_with_sdk_check() {
+        let parsed_flags = crate::test::parse_test_flags();
+        let mode = CodegenMode::Exported;
+        let modified_parsed_flags =
+            crate::commands::modify_parsed_flags_based_on_mode(parsed_flags, mode).unwrap();
+        let flag_ids =
+            assign_flag_ids(crate::test::TEST_PACKAGE, modified_parsed_flags.iter()).unwrap();
+        let mut finalized_flags = FinalizedFlagMap::new();
+        finalized_flags.insert_if_new(
+            ApiLevel(36),
+            FinalizedFlag {
+                flag_name: "disabled_rw_exported".to_string(),
+                package_name: "com.android.aconfig.test".to_string(),
+            },
+        );
+        let config = JavaCodegenConfig {
+            codegen_mode: mode,
+            flag_ids,
+            allow_instrumentation: true,
+            package_fingerprint: 5801144784618221668,
+            new_exported: true,
+            single_exported_file: false,
+            finalized_flags,
+        };
+        let generated_files = generate_java_code(
+            crate::test::TEST_PACKAGE,
+            modified_parsed_flags.into_iter(),
+            config,
+        )
+        .unwrap();
+
+        let expect_flags_content = r#"
+        package com.android.aconfig.test;
+        import android.os.Build;
+        /** @hide */
+        public final class Flags {
+            /** @hide */
+            public static final String FLAG_DISABLED_RW_EXPORTED = "com.android.aconfig.test.disabled_rw_exported";
+            /** @hide */
+            public static final String FLAG_ENABLED_FIXED_RO_EXPORTED = "com.android.aconfig.test.enabled_fixed_ro_exported";
+            /** @hide */
+            public static final String FLAG_ENABLED_RO_EXPORTED = "com.android.aconfig.test.enabled_ro_exported";
+            public static boolean disabledRwExported() {
+                if (Build.VERSION.SDK_INT >= 36) {
+                  return true;
+                }
+                return FEATURE_FLAGS.disabledRwExported();
+            }
+            public static boolean enabledFixedRoExported() {
+                return FEATURE_FLAGS.enabledFixedRoExported();
+            }
+            public static boolean enabledRoExported() {
+                return FEATURE_FLAGS.enabledRoExported();
+            }
+            private static FeatureFlags FEATURE_FLAGS = new FeatureFlagsImpl();
+        }
+        "#;
+
+        let expect_feature_flags_content = r#"
+        package com.android.aconfig.test;
+        /** @hide */
+        public interface FeatureFlags {
+            boolean disabledRwExported();
+            boolean enabledFixedRoExported();
+            boolean enabledRoExported();
+        }
+        "#;
+
+        let expect_feature_flags_impl_content = r#"
+        package com.android.aconfig.test;
+        import android.os.Build;
+        import android.os.flagging.AconfigPackage;
+        import android.util.Log;
+        /** @hide */
+        public final class FeatureFlagsImpl implements FeatureFlags {
+            private static final String TAG = "FeatureFlagsImplExport";
+            private static volatile boolean isCached = false;
+            private static boolean disabledRwExported = false;
+            private static boolean enabledFixedRoExported = false;
+            private static boolean enabledRoExported = false;
+            private void init() {
+                try {
+                    AconfigPackage reader = AconfigPackage.load("com.android.aconfig.test");
+                    disabledRwExported = Build.VERSION.SDK_INT >= 36 ? true : reader.getBooleanFlagValue("disabled_rw_exported", false);
+                    enabledFixedRoExported = reader.getBooleanFlagValue("enabled_fixed_ro_exported", false);
+                    enabledRoExported = reader.getBooleanFlagValue("enabled_ro_exported", false);
+                } catch (Exception e) {
+                    // pass
+                    Log.e(TAG, e.toString());
+                } catch (LinkageError e) {
+                    // for mainline module running on older devices.
+                    // This should be replaces to version check, after the version bump.
+                    Log.w(TAG, e.toString());
+                }
+                isCached = true;
+            }
+            @Override
+            public boolean disabledRwExported() {
+                if (!isCached) {
+                    init();
+                }
+                return disabledRwExported;
+            }
+            @Override
+            public boolean enabledFixedRoExported() {
+                if (!isCached) {
+                    init();
+                }
+                return enabledFixedRoExported;
+            }
+            @Override
+            public boolean enabledRoExported() {
+                if (!isCached) {
+                    init();
+                }
+                return enabledRoExported;
+            }
+        }"#;
+
+        let expect_custom_feature_flags_content = r#"
+        package com.android.aconfig.test;
+
+        import java.util.Arrays;
+        import java.util.HashMap;
+        import java.util.Map;
+        import java.util.HashSet;
+        import java.util.List;
+        import java.util.Set;
+        import java.util.function.BiPredicate;
+        import java.util.function.Predicate;
+        import android.os.Build;
+
+        /** @hide */
+        public class CustomFeatureFlags implements FeatureFlags {
+
+            private BiPredicate<String, Predicate<FeatureFlags>> mGetValueImpl;
+
+            public CustomFeatureFlags(BiPredicate<String, Predicate<FeatureFlags>> getValueImpl) {
+                mGetValueImpl = getValueImpl;
+            }
+
+            @Override
+            public boolean disabledRwExported() {
+                return getValue(Flags.FLAG_DISABLED_RW_EXPORTED,
+                    FeatureFlags::disabledRwExported);
+            }
+            @Override
+            public boolean enabledFixedRoExported() {
+                return getValue(Flags.FLAG_ENABLED_FIXED_RO_EXPORTED,
+                    FeatureFlags::enabledFixedRoExported);
+            }
+            @Override
+            public boolean enabledRoExported() {
+                return getValue(Flags.FLAG_ENABLED_RO_EXPORTED,
+                    FeatureFlags::enabledRoExported);
+            }
+
+            protected boolean getValue(String flagName, Predicate<FeatureFlags> getter) {
+                return mGetValueImpl.test(flagName, getter);
+            }
+
+            public List<String> getFlagNames() {
+                return Arrays.asList(
+                    Flags.FLAG_DISABLED_RW_EXPORTED,
+                    Flags.FLAG_ENABLED_FIXED_RO_EXPORTED,
+                    Flags.FLAG_ENABLED_RO_EXPORTED
+                );
+            }
+
+            private Set<String> mReadOnlyFlagsSet = new HashSet<>(
+                Arrays.asList(
+                    ""
+                )
+            );
+
+            private Map<String, Integer> mFinalizedFlags = new HashMap<>(
+                Map.ofEntries(
+                    Map.entry(Flags.FLAG_DISABLED_RW_EXPORTED, 36),
+                    Map.entry("", Integer.MAX_VALUE)
+                )
+            );
+
+            public boolean isFlagFinalized(String flagName) {
+                if (!mFinalizedFlags.containsKey(flagName)) {
+                    return false;
+                }
+                return Build.VERSION.SDK_INT >= mFinalizedFlags.get(flagName);
+            }
+        }
+    "#;
+
+        let mut file_set = HashMap::from([
+            ("com/android/aconfig/test/Flags.java", expect_flags_content),
+            ("com/android/aconfig/test/FeatureFlags.java", expect_feature_flags_content),
+            ("com/android/aconfig/test/FeatureFlagsImpl.java", expect_feature_flags_impl_content),
+            (
+                "com/android/aconfig/test/CustomFeatureFlags.java",
+                expect_custom_feature_flags_content,
+            ),
+            (
+                "com/android/aconfig/test/FakeFeatureFlagsImpl.java",
+                EXPECTED_FAKEFEATUREFLAGSIMPL_CONTENT,
+            ),
+        ]);
+
+        for file in generated_files {
+            let file_path = file.path.to_str().unwrap();
+            assert!(file_set.contains_key(file_path), "Cannot find {}", file_path);
+            assert_eq!(
+                None,
+                crate::test::first_significant_code_diff(
+                    file_set.get(file_path).unwrap(),
+                    &String::from_utf8(file.contents).unwrap()
+                ),
+                "File {} content is not correct",
+                file_path
+            );
+            file_set.remove(file_path);
+        }
+
+        assert!(file_set.is_empty());
+    }
+
+    // Test that the SDK check isn't added unless the library is exported (even
+    // if the flag is present in finalized_flags).
+    #[test]
+    fn test_generate_java_code_flags_with_sdk_check() {
+        let parsed_flags = crate::test::parse_test_flags();
+        let mode = CodegenMode::Production;
+        let modified_parsed_flags =
+            crate::commands::modify_parsed_flags_based_on_mode(parsed_flags, mode).unwrap();
+        let flag_ids =
+            assign_flag_ids(crate::test::TEST_PACKAGE, modified_parsed_flags.iter()).unwrap();
+        let mut finalized_flags = FinalizedFlagMap::new();
+        finalized_flags.insert_if_new(
+            ApiLevel(36),
+            FinalizedFlag {
+                flag_name: "disabled_rw".to_string(),
+                package_name: "com.android.aconfig.test".to_string(),
+            },
+        );
+        let config = JavaCodegenConfig {
+            codegen_mode: mode,
+            flag_ids,
+            allow_instrumentation: true,
+            package_fingerprint: 5801144784618221668,
+            new_exported: true,
+            single_exported_file: false,
+            finalized_flags,
+        };
+        let generated_files = generate_java_code(
+            crate::test::TEST_PACKAGE,
+            modified_parsed_flags.into_iter(),
+            config,
+        )
+        .unwrap();
+
+        let expect_flags_content = EXPECTED_FLAG_COMMON_CONTENT.to_string()
+            + r#"
+        private static FeatureFlags FEATURE_FLAGS = new FeatureFlagsImpl();
+        }"#;
+
+        let file = generated_files.iter().find(|f| f.path.ends_with("Flags.java")).unwrap();
+        assert_eq!(
+            None,
+            crate::test::first_significant_code_diff(
+                &expect_flags_content,
+                &String::from_utf8(file.contents.clone()).unwrap()
+            ),
+            "Flags content is not correct"
+        );
+    }
+
     #[test]
     fn test_generate_java_code_test() {
         let parsed_flags = crate::test::parse_test_flags();
@@ -877,13 +1487,19 @@ mod tests {
             crate::commands::modify_parsed_flags_based_on_mode(parsed_flags, mode).unwrap();
         let flag_ids =
             assign_flag_ids(crate::test::TEST_PACKAGE, modified_parsed_flags.iter()).unwrap();
+        let config = JavaCodegenConfig {
+            codegen_mode: mode,
+            flag_ids,
+            allow_instrumentation: true,
+            package_fingerprint: 5801144784618221668,
+            new_exported: false,
+            single_exported_file: false,
+            finalized_flags: FinalizedFlagMap::new(),
+        };
         let generated_files = generate_java_code(
             crate::test::TEST_PACKAGE,
             modified_parsed_flags.into_iter(),
-            mode,
-            flag_ids,
-            true,
-            5801144784618221668,
+            config,
         )
         .unwrap();
 
@@ -999,13 +1615,19 @@ mod tests {
             crate::commands::modify_parsed_flags_based_on_mode(parsed_flags, mode).unwrap();
         let flag_ids =
             assign_flag_ids(crate::test::TEST_PACKAGE, modified_parsed_flags.iter()).unwrap();
+        let config = JavaCodegenConfig {
+            codegen_mode: mode,
+            flag_ids,
+            allow_instrumentation: true,
+            package_fingerprint: 5801144784618221668,
+            new_exported: false,
+            single_exported_file: false,
+            finalized_flags: FinalizedFlagMap::new(),
+        };
         let generated_files = generate_java_code(
             crate::test::TEST_PACKAGE,
             modified_parsed_flags.into_iter(),
-            mode,
-            flag_ids,
-            true,
-            5801144784618221668,
+            config,
         )
         .unwrap();
         let expect_featureflags_content = r#"
@@ -1271,6 +1893,109 @@ mod tests {
         assert!(file_set.is_empty());
     }
 
+    #[test]
+    fn test_generate_java_code_exported_flags() {
+        let parsed_flags = crate::test::parse_test_flags();
+        let mode = CodegenMode::Exported;
+        let modified_parsed_flags =
+            crate::commands::modify_parsed_flags_based_on_mode(parsed_flags, mode).unwrap();
+        let flag_ids =
+            assign_flag_ids(crate::test::TEST_PACKAGE, modified_parsed_flags.iter()).unwrap();
+        let mut finalized_flags = FinalizedFlagMap::new();
+        finalized_flags.insert_if_new(
+            ApiLevel(36),
+            FinalizedFlag {
+                flag_name: "disabled_rw_exported".to_string(),
+                package_name: "com.android.aconfig.test".to_string(),
+            },
+        );
+        let config = JavaCodegenConfig {
+            codegen_mode: mode,
+            flag_ids,
+            allow_instrumentation: true,
+            package_fingerprint: 5801144784618221668,
+            new_exported: true,
+            single_exported_file: true,
+            finalized_flags,
+        };
+        let generated_files = generate_java_code(
+            crate::test::TEST_PACKAGE,
+            modified_parsed_flags.into_iter(),
+            config,
+        )
+        .unwrap();
+
+        let expect_exported_flags_content = r#"
+        package com.android.aconfig.test;
+
+        import android.os.Build;
+        import android.os.flagging.AconfigPackage;
+        import android.util.Log;
+        public final class ExportedFlags {
+
+            public static final String FLAG_DISABLED_RW_EXPORTED = "com.android.aconfig.test.disabled_rw_exported";
+            public static final String FLAG_ENABLED_FIXED_RO_EXPORTED = "com.android.aconfig.test.enabled_fixed_ro_exported";
+            public static final String FLAG_ENABLED_RO_EXPORTED = "com.android.aconfig.test.enabled_ro_exported";
+            private static final String TAG = "ExportedFlags";
+            private static volatile boolean isCached = false;
+
+            private static boolean disabledRwExported = false;
+            private static boolean enabledFixedRoExported = false;
+            private static boolean enabledRoExported = false;
+            private ExportedFlags() {}
+
+            private void init() {
+                try {
+                    AconfigPackage reader = AconfigPackage.load("com.android.aconfig.test");
+                    disabledRwExported = reader.getBooleanFlagValue("disabled_rw_exported", false);
+                    enabledFixedRoExported = reader.getBooleanFlagValue("enabled_fixed_ro_exported", false);
+                    enabledRoExported = reader.getBooleanFlagValue("enabled_ro_exported", false);
+                } catch (Exception e) {
+                    // pass
+                    Log.e(TAG, e.toString());
+                } catch (LinkageError e) {
+                    // for mainline module running on older devices.
+                    // This should be replaces to version check, after the version bump.
+                    Log.w(TAG, e.toString());
+                }
+                isCached = true;
+            }
+            public static boolean disabledRwExported() {
+                if (Build.VERSION.SDK_INT >= 36) {
+                  return true;
+                }
+
+                if (!featureFlags.isCached) {
+                    featureFlags.init();
+                }
+                return featureFlags.disabledRwExported;
+            }
+            public static boolean enabledFixedRoExported() {
+                if (!featureFlags.isCached) {
+                    featureFlags.init();
+                }
+                return featureFlags.enabledFixedRoExported;
+            }
+            public static boolean enabledRoExported() {
+                if (!featureFlags.isCached) {
+                    featureFlags.init();
+                }
+                return featureFlags.enabledRoExported;
+            }
+            private static ExportedFlags featureFlags = new ExportedFlags();
+        }"#;
+
+        let file = generated_files.iter().find(|f| f.path.ends_with("ExportedFlags.java")).unwrap();
+        assert_eq!(
+            None,
+            crate::test::first_significant_code_diff(
+                expect_exported_flags_content,
+                &String::from_utf8(file.contents.clone()).unwrap()
+            ),
+            "ExportedFlags content is not correct"
+        );
+    }
+
     #[test]
     fn test_format_java_method_name() {
         let expected = "someSnakeName";
diff --git a/tools/aconfig/aconfig/src/codegen/mod.rs b/tools/aconfig/aconfig/src/codegen/mod.rs
index 1ea3b37849..9ed66dbd03 100644
--- a/tools/aconfig/aconfig/src/codegen/mod.rs
+++ b/tools/aconfig/aconfig/src/codegen/mod.rs
@@ -50,67 +50,6 @@ impl std::fmt::Display for CodegenMode {
 #[cfg(test)]
 mod tests {
     use super::*;
-    use aconfig_protos::is_valid_container_ident;
-
-    #[test]
-    fn test_is_valid_name_ident() {
-        assert!(is_valid_name_ident("foo"));
-        assert!(is_valid_name_ident("foo_bar_123"));
-        assert!(is_valid_name_ident("foo_"));
-
-        assert!(!is_valid_name_ident(""));
-        assert!(!is_valid_name_ident("123_foo"));
-        assert!(!is_valid_name_ident("foo-bar"));
-        assert!(!is_valid_name_ident("foo-b\u{00e5}r"));
-        assert!(!is_valid_name_ident("foo__bar"));
-        assert!(!is_valid_name_ident("_foo"));
-    }
-
-    #[test]
-    fn test_is_valid_package_ident() {
-        assert!(is_valid_package_ident("foo.bar"));
-        assert!(is_valid_package_ident("foo.bar_baz"));
-        assert!(is_valid_package_ident("foo.bar.a123"));
-
-        assert!(!is_valid_package_ident("foo_bar_123"));
-        assert!(!is_valid_package_ident("foo"));
-        assert!(!is_valid_package_ident("foo._bar"));
-        assert!(!is_valid_package_ident(""));
-        assert!(!is_valid_package_ident("123_foo"));
-        assert!(!is_valid_package_ident("foo-bar"));
-        assert!(!is_valid_package_ident("foo-b\u{00e5}r"));
-        assert!(!is_valid_package_ident("foo.bar.123"));
-        assert!(!is_valid_package_ident(".foo.bar"));
-        assert!(!is_valid_package_ident("foo.bar."));
-        assert!(!is_valid_package_ident("."));
-        assert!(!is_valid_package_ident(".."));
-        assert!(!is_valid_package_ident("foo..bar"));
-        assert!(!is_valid_package_ident("foo.__bar"));
-    }
-
-    #[test]
-    fn test_is_valid_container_ident() {
-        assert!(is_valid_container_ident("foo.bar"));
-        assert!(is_valid_container_ident("foo.bar_baz"));
-        assert!(is_valid_container_ident("foo.bar.a123"));
-        assert!(is_valid_container_ident("foo"));
-        assert!(is_valid_container_ident("foo_bar_123"));
-
-        assert!(!is_valid_container_ident(""));
-        assert!(!is_valid_container_ident("foo._bar"));
-        assert!(!is_valid_container_ident("_foo"));
-        assert!(!is_valid_container_ident("123_foo"));
-        assert!(!is_valid_container_ident("foo-bar"));
-        assert!(!is_valid_container_ident("foo-b\u{00e5}r"));
-        assert!(!is_valid_container_ident("foo.bar.123"));
-        assert!(!is_valid_container_ident(".foo.bar"));
-        assert!(!is_valid_container_ident("foo.bar."));
-        assert!(!is_valid_container_ident("."));
-        assert!(!is_valid_container_ident(".."));
-        assert!(!is_valid_container_ident("foo..bar"));
-        assert!(!is_valid_container_ident("foo.__bar"));
-    }
-
     #[test]
     fn test_create_device_config_ident() {
         assert_eq!(
diff --git a/tools/aconfig/aconfig/src/codegen/rust.rs b/tools/aconfig/aconfig/src/codegen/rust.rs
index 2bf565a81c..2ee5f36822 100644
--- a/tools/aconfig/aconfig/src/codegen/rust.rs
+++ b/tools/aconfig/aconfig/src/codegen/rust.rs
@@ -24,14 +24,13 @@ use std::collections::HashMap;
 
 use crate::codegen;
 use crate::codegen::CodegenMode;
-use crate::commands::OutputFile;
+use crate::commands::{should_include_flag, OutputFile};
 
 pub fn generate_rust_code<I>(
     package: &str,
     flag_ids: HashMap<String, u16>,
     parsed_flags_iter: I,
     codegen_mode: CodegenMode,
-    allow_instrumentation: bool,
 ) -> Result<OutputFile>
 where
     I: Iterator<Item = ProtoParsedFlag>,
@@ -46,7 +45,6 @@ where
         template_flags,
         modules: package.split('.').map(|s| s.to_string()).collect::<Vec<_>>(),
         has_readwrite,
-        allow_instrumentation,
         container,
     };
     let mut template = TinyTemplate::new();
@@ -70,7 +68,6 @@ struct TemplateContext {
     pub template_flags: Vec<TemplateParsedFlag>,
     pub modules: Vec<String>,
     pub has_readwrite: bool,
-    pub allow_instrumentation: bool,
     pub container: String,
 }
 
@@ -88,18 +85,12 @@ struct TemplateParsedFlag {
 impl TemplateParsedFlag {
     #[allow(clippy::nonminimal_bool)]
     fn new(package: &str, flag_offsets: HashMap<String, u16>, pf: &ProtoParsedFlag) -> Self {
-        let no_assigned_offset = (pf.container() == "system"
-            || pf.container() == "vendor"
-            || pf.container() == "product")
-            && pf.permission() == ProtoFlagPermission::READ_ONLY
-            && pf.state() == ProtoFlagState::DISABLED;
-
         let flag_offset = match flag_offsets.get(pf.name()) {
             Some(offset) => offset,
             None => {
                 // System/vendor/product RO+disabled flags have no offset in storage files.
                 // Assign placeholder value.
-                if no_assigned_offset {
+                if !should_include_flag(pf) {
                     &0
                 }
                 // All other flags _must_ have an offset.
@@ -137,146 +128,6 @@ use std::io::Write;
 use std::sync::LazyLock;
 use log::{log, LevelFilter, Level};
 
-/// flag provider
-pub struct FlagProvider;
-
-    /// flag value cache for disabled_rw
-    static CACHED_disabled_rw: LazyLock<bool> = LazyLock::new(|| flags_rust::GetServerConfigurableFlag(
-        "aconfig_flags.aconfig_test",
-        "com.android.aconfig.test.disabled_rw",
-        "false") == "true");
-
-    /// flag value cache for disabled_rw_exported
-    static CACHED_disabled_rw_exported: LazyLock<bool> = LazyLock::new(|| flags_rust::GetServerConfigurableFlag(
-        "aconfig_flags.aconfig_test",
-        "com.android.aconfig.test.disabled_rw_exported",
-        "false") == "true");
-
-    /// flag value cache for disabled_rw_in_other_namespace
-    static CACHED_disabled_rw_in_other_namespace: LazyLock<bool> = LazyLock::new(|| flags_rust::GetServerConfigurableFlag(
-        "aconfig_flags.other_namespace",
-        "com.android.aconfig.test.disabled_rw_in_other_namespace",
-        "false") == "true");
-
-    /// flag value cache for enabled_rw
-    static CACHED_enabled_rw: LazyLock<bool> = LazyLock::new(|| flags_rust::GetServerConfigurableFlag(
-        "aconfig_flags.aconfig_test",
-        "com.android.aconfig.test.enabled_rw",
-        "true") == "true");
-
-impl FlagProvider {
-    /// query flag disabled_ro
-    pub fn disabled_ro(&self) -> bool {
-        false
-    }
-
-    /// query flag disabled_rw
-    pub fn disabled_rw(&self) -> bool {
-        *CACHED_disabled_rw
-    }
-
-    /// query flag disabled_rw_exported
-    pub fn disabled_rw_exported(&self) -> bool {
-        *CACHED_disabled_rw_exported
-    }
-
-    /// query flag disabled_rw_in_other_namespace
-    pub fn disabled_rw_in_other_namespace(&self) -> bool {
-        *CACHED_disabled_rw_in_other_namespace
-    }
-
-    /// query flag enabled_fixed_ro
-    pub fn enabled_fixed_ro(&self) -> bool {
-        true
-    }
-
-    /// query flag enabled_fixed_ro_exported
-    pub fn enabled_fixed_ro_exported(&self) -> bool {
-        true
-    }
-
-    /// query flag enabled_ro
-    pub fn enabled_ro(&self) -> bool {
-        true
-    }
-
-    /// query flag enabled_ro_exported
-    pub fn enabled_ro_exported(&self) -> bool {
-        true
-    }
-
-    /// query flag enabled_rw
-    pub fn enabled_rw(&self) -> bool {
-        *CACHED_enabled_rw
-    }
-}
-
-/// flag provider
-pub static PROVIDER: FlagProvider = FlagProvider;
-
-/// query flag disabled_ro
-#[inline(always)]
-pub fn disabled_ro() -> bool {
-    false
-}
-
-/// query flag disabled_rw
-#[inline(always)]
-pub fn disabled_rw() -> bool {
-    PROVIDER.disabled_rw()
-}
-
-/// query flag disabled_rw_exported
-#[inline(always)]
-pub fn disabled_rw_exported() -> bool {
-    PROVIDER.disabled_rw_exported()
-}
-
-/// query flag disabled_rw_in_other_namespace
-#[inline(always)]
-pub fn disabled_rw_in_other_namespace() -> bool {
-    PROVIDER.disabled_rw_in_other_namespace()
-}
-
-/// query flag enabled_fixed_ro
-#[inline(always)]
-pub fn enabled_fixed_ro() -> bool {
-    true
-}
-
-/// query flag enabled_fixed_ro_exported
-#[inline(always)]
-pub fn enabled_fixed_ro_exported() -> bool {
-    true
-}
-
-/// query flag enabled_ro
-#[inline(always)]
-pub fn enabled_ro() -> bool {
-    true
-}
-
-/// query flag enabled_ro_exported
-#[inline(always)]
-pub fn enabled_ro_exported() -> bool {
-    true
-}
-
-/// query flag enabled_rw
-#[inline(always)]
-pub fn enabled_rw() -> bool {
-    PROVIDER.enabled_rw()
-}
-"#;
-
-    const PROD_INSTRUMENTED_EXPECTED: &str = r#"
-//! codegenerated rust flag lib
-use aconfig_storage_read_api::{Mmap, AconfigStorageError, StorageFileType, PackageReadContext, get_mapped_storage_file, get_boolean_flag_value, get_package_read_context};
-use std::path::Path;
-use std::io::Write;
-use std::sync::LazyLock;
-use log::{log, LevelFilter, Level};
-
 /// flag provider
 pub struct FlagProvider;
 
@@ -563,15 +414,189 @@ pub fn enabled_rw() -> bool {
 
     const TEST_EXPECTED: &str = r#"
 //! codegenerated rust flag lib
-
+use aconfig_storage_read_api::{Mmap, AconfigStorageError, StorageFileType, PackageReadContext, get_mapped_storage_file, get_boolean_flag_value, get_package_read_context};
 use std::collections::BTreeMap;
-use std::sync::Mutex;
+use std::path::Path;
+use std::io::Write;
+use std::sync::{LazyLock, Mutex};
+use log::{log, LevelFilter, Level};
 
 /// flag provider
 pub struct FlagProvider {
     overrides: BTreeMap<&'static str, bool>,
 }
 
+static PACKAGE_OFFSET: LazyLock<Result<Option<u32>, AconfigStorageError>> = LazyLock::new(|| unsafe {
+    get_mapped_storage_file("system", StorageFileType::PackageMap)
+    .and_then(|package_map| get_package_read_context(&package_map, "com.android.aconfig.test"))
+    .map(|context| context.map(|c| c.boolean_start_index))
+});
+
+static FLAG_VAL_MAP: LazyLock<Result<Mmap, AconfigStorageError>> = LazyLock::new(|| unsafe {
+    get_mapped_storage_file("system", StorageFileType::FlagVal)
+});
+
+/// flag value cache for disabled_rw
+static CACHED_disabled_rw: LazyLock<bool> = LazyLock::new(|| {
+    // This will be called multiple times. Subsequent calls after the first are noops.
+    logger::init(
+        logger::Config::default()
+            .with_tag_on_device("aconfig_rust_codegen")
+            .with_max_level(LevelFilter::Info));
+
+    let flag_value_result = FLAG_VAL_MAP
+        .as_ref()
+        .map_err(|err| format!("failed to get flag val map: {err}"))
+        .and_then(|flag_val_map| {
+            PACKAGE_OFFSET
+               .as_ref()
+               .map_err(|err| format!("failed to get package read offset: {err}"))
+               .and_then(|package_offset| {
+                   match package_offset {
+                       Some(offset) => {
+                           get_boolean_flag_value(&flag_val_map, offset + 0)
+                               .map_err(|err| format!("failed to get flag: {err}"))
+                       },
+                       None => {
+                           log!(Level::Error, "no context found for package com.android.aconfig.test");
+                           Err(format!("failed to flag package com.android.aconfig.test"))
+                       }
+                    }
+                })
+            });
+
+    match flag_value_result {
+        Ok(flag_value) => {
+            return flag_value;
+        },
+        Err(err) => {
+            log!(Level::Error, "aconfig_rust_codegen: error: {err}");
+            return false;
+        }
+    }
+});
+
+/// flag value cache for disabled_rw_exported
+static CACHED_disabled_rw_exported: LazyLock<bool> = LazyLock::new(|| {
+        // This will be called multiple times. Subsequent calls after the first are noops.
+        logger::init(
+            logger::Config::default()
+                .with_tag_on_device("aconfig_rust_codegen")
+                .with_max_level(LevelFilter::Info));
+
+        let flag_value_result = FLAG_VAL_MAP
+            .as_ref()
+            .map_err(|err| format!("failed to get flag val map: {err}"))
+            .and_then(|flag_val_map| {
+                PACKAGE_OFFSET
+                    .as_ref()
+                    .map_err(|err| format!("failed to get package read offset: {err}"))
+                    .and_then(|package_offset| {
+                        match package_offset {
+                            Some(offset) => {
+                                get_boolean_flag_value(&flag_val_map, offset + 1)
+                                    .map_err(|err| format!("failed to get flag: {err}"))
+                            },
+                            None => {
+                                log!(Level::Error, "no context found for package com.android.aconfig.test");
+                                Err(format!("failed to flag package com.android.aconfig.test"))
+                            }
+                        }
+                    })
+                });
+
+        match flag_value_result {
+            Ok(flag_value) => {
+                 return flag_value;
+            },
+            Err(err) => {
+                log!(Level::Error, "aconfig_rust_codegen: error: {err}");
+                return false;
+            }
+        }
+});
+
+/// flag value cache for disabled_rw_in_other_namespace
+static CACHED_disabled_rw_in_other_namespace: LazyLock<bool> = LazyLock::new(|| {
+        // This will be called multiple times. Subsequent calls after the first are noops.
+        logger::init(
+            logger::Config::default()
+                .with_tag_on_device("aconfig_rust_codegen")
+                .with_max_level(LevelFilter::Info));
+
+        let flag_value_result = FLAG_VAL_MAP
+            .as_ref()
+            .map_err(|err| format!("failed to get flag val map: {err}"))
+            .and_then(|flag_val_map| {
+                PACKAGE_OFFSET
+                    .as_ref()
+                    .map_err(|err| format!("failed to get package read offset: {err}"))
+                    .and_then(|package_offset| {
+                        match package_offset {
+                            Some(offset) => {
+                                get_boolean_flag_value(&flag_val_map, offset + 2)
+                                    .map_err(|err| format!("failed to get flag: {err}"))
+                            },
+                            None => {
+                                log!(Level::Error, "no context found for package com.android.aconfig.test");
+                                Err(format!("failed to flag package com.android.aconfig.test"))
+                            }
+                        }
+                    })
+                });
+
+        match flag_value_result {
+            Ok(flag_value) => {
+                 return flag_value;
+            },
+            Err(err) => {
+                log!(Level::Error, "aconfig_rust_codegen: error: {err}");
+                return false;
+            }
+        }
+});
+
+
+/// flag value cache for enabled_rw
+static CACHED_enabled_rw: LazyLock<bool> = LazyLock::new(|| {
+        // This will be called multiple times. Subsequent calls after the first are noops.
+        logger::init(
+            logger::Config::default()
+                .with_tag_on_device("aconfig_rust_codegen")
+                .with_max_level(LevelFilter::Info));
+
+        let flag_value_result = FLAG_VAL_MAP
+            .as_ref()
+            .map_err(|err| format!("failed to get flag val map: {err}"))
+            .and_then(|flag_val_map| {
+                PACKAGE_OFFSET
+                    .as_ref()
+                    .map_err(|err| format!("failed to get package read offset: {err}"))
+                    .and_then(|package_offset| {
+                        match package_offset {
+                            Some(offset) => {
+                                get_boolean_flag_value(&flag_val_map, offset + 7)
+                                    .map_err(|err| format!("failed to get flag: {err}"))
+                            },
+                            None => {
+                                log!(Level::Error, "no context found for package com.android.aconfig.test");
+                                Err(format!("failed to flag package com.android.aconfig.test"))
+                            }
+                        }
+                    })
+                });
+
+        match flag_value_result {
+            Ok(flag_value) => {
+                 return flag_value;
+            },
+            Err(err) => {
+                log!(Level::Error, "aconfig_rust_codegen: error: {err}");
+                return true;
+            }
+        }
+});
+
 impl FlagProvider {
     /// query flag disabled_ro
     pub fn disabled_ro(&self) -> bool {
@@ -588,10 +613,7 @@ impl FlagProvider {
     /// query flag disabled_rw
     pub fn disabled_rw(&self) -> bool {
         self.overrides.get("disabled_rw").copied().unwrap_or(
-            flags_rust::GetServerConfigurableFlag(
-                "aconfig_flags.aconfig_test",
-                "com.android.aconfig.test.disabled_rw",
-                "false") == "true"
+            *CACHED_disabled_rw
         )
     }
 
@@ -603,10 +625,7 @@ impl FlagProvider {
     /// query flag disabled_rw_exported
     pub fn disabled_rw_exported(&self) -> bool {
         self.overrides.get("disabled_rw_exported").copied().unwrap_or(
-            flags_rust::GetServerConfigurableFlag(
-                "aconfig_flags.aconfig_test",
-                "com.android.aconfig.test.disabled_rw_exported",
-                "false") == "true"
+            *CACHED_disabled_rw_exported
         )
     }
 
@@ -618,10 +637,7 @@ impl FlagProvider {
     /// query flag disabled_rw_in_other_namespace
     pub fn disabled_rw_in_other_namespace(&self) -> bool {
         self.overrides.get("disabled_rw_in_other_namespace").copied().unwrap_or(
-            flags_rust::GetServerConfigurableFlag(
-                "aconfig_flags.other_namespace",
-                "com.android.aconfig.test.disabled_rw_in_other_namespace",
-                "false") == "true"
+            *CACHED_disabled_rw_in_other_namespace
         )
     }
 
@@ -681,10 +697,7 @@ impl FlagProvider {
     /// query flag enabled_rw
     pub fn enabled_rw(&self) -> bool {
         self.overrides.get("enabled_rw").copied().unwrap_or(
-            flags_rust::GetServerConfigurableFlag(
-                "aconfig_flags.aconfig_test",
-                "com.android.aconfig.test.enabled_rw",
-                "true") == "true"
+            *CACHED_enabled_rw
         )
     }
 
@@ -816,74 +829,6 @@ pub fn set_enabled_rw(val: bool) {
 pub fn reset_flags() {
     PROVIDER.lock().unwrap().reset_flags()
 }
-"#;
-
-    const EXPORTED_EXPECTED: &str = r#"
-//! codegenerated rust flag lib
-use aconfig_storage_read_api::{Mmap, AconfigStorageError, StorageFileType, PackageReadContext, get_mapped_storage_file, get_boolean_flag_value, get_package_read_context};
-use std::path::Path;
-use std::io::Write;
-use std::sync::LazyLock;
-use log::{log, LevelFilter, Level};
-
-/// flag provider
-pub struct FlagProvider;
-
-    /// flag value cache for disabled_rw_exported
-    static CACHED_disabled_rw_exported: LazyLock<bool> = LazyLock::new(|| flags_rust::GetServerConfigurableFlag(
-        "aconfig_flags.aconfig_test",
-        "com.android.aconfig.test.disabled_rw_exported",
-        "false") == "true");
-
-    /// flag value cache for enabled_fixed_ro_exported
-    static CACHED_enabled_fixed_ro_exported: LazyLock<bool> = LazyLock::new(|| flags_rust::GetServerConfigurableFlag(
-        "aconfig_flags.aconfig_test",
-        "com.android.aconfig.test.enabled_fixed_ro_exported",
-        "false") == "true");
-
-    /// flag value cache for enabled_ro_exported
-    static CACHED_enabled_ro_exported: LazyLock<bool> = LazyLock::new(|| flags_rust::GetServerConfigurableFlag(
-        "aconfig_flags.aconfig_test",
-        "com.android.aconfig.test.enabled_ro_exported",
-        "false") == "true");
-
-impl FlagProvider {
-    /// query flag disabled_rw_exported
-    pub fn disabled_rw_exported(&self) -> bool {
-        *CACHED_disabled_rw_exported
-    }
-
-    /// query flag enabled_fixed_ro_exported
-    pub fn enabled_fixed_ro_exported(&self) -> bool {
-        *CACHED_enabled_fixed_ro_exported
-    }
-
-    /// query flag enabled_ro_exported
-    pub fn enabled_ro_exported(&self) -> bool {
-        *CACHED_enabled_ro_exported
-    }
-}
-
-/// flag provider
-pub static PROVIDER: FlagProvider = FlagProvider;
-
-/// query flag disabled_rw_exported
-#[inline(always)]
-pub fn disabled_rw_exported() -> bool {
-    PROVIDER.disabled_rw_exported()
-}
-
-/// query flag enabled_fixed_ro_exported
-#[inline(always)]
-pub fn enabled_fixed_ro_exported() -> bool {
-    PROVIDER.enabled_fixed_ro_exported()
-}
-
-/// query flag enabled_ro_exported
-#[inline(always)]
-pub fn enabled_ro_exported() -> bool {
-    PROVIDER.enabled_ro_exported()
-}
 "#;
 
     const FORCE_READ_ONLY_EXPECTED: &str = r#"
@@ -970,7 +915,7 @@ pub fn enabled_rw() -> bool {
 "#;
     use crate::commands::assign_flag_ids;
 
-    fn test_generate_rust_code(mode: CodegenMode, allow_instrumentation: bool, expected: &str) {
+    fn test_generate_rust_code(mode: CodegenMode, expected: &str) {
         let parsed_flags = crate::test::parse_test_flags();
         let modified_parsed_flags =
             crate::commands::modify_parsed_flags_based_on_mode(parsed_flags, mode).unwrap();
@@ -981,7 +926,6 @@ pub fn enabled_rw() -> bool {
             flag_ids,
             modified_parsed_flags.into_iter(),
             mode,
-            allow_instrumentation,
         )
         .unwrap();
         assert_eq!("src/lib.rs", format!("{}", generated.path.display()));
@@ -996,26 +940,16 @@ pub fn enabled_rw() -> bool {
 
     #[test]
     fn test_generate_rust_code_for_prod() {
-        test_generate_rust_code(CodegenMode::Production, false, PROD_EXPECTED);
-    }
-
-    #[test]
-    fn test_generate_rust_code_for_prod_instrumented() {
-        test_generate_rust_code(CodegenMode::Production, true, PROD_INSTRUMENTED_EXPECTED);
+        test_generate_rust_code(CodegenMode::Production, PROD_EXPECTED);
     }
 
     #[test]
     fn test_generate_rust_code_for_test() {
-        test_generate_rust_code(CodegenMode::Test, false, TEST_EXPECTED);
-    }
-
-    #[test]
-    fn test_generate_rust_code_for_exported() {
-        test_generate_rust_code(CodegenMode::Exported, false, EXPORTED_EXPECTED);
+        test_generate_rust_code(CodegenMode::Test, TEST_EXPECTED);
     }
 
     #[test]
     fn test_generate_rust_code_for_force_read_only() {
-        test_generate_rust_code(CodegenMode::ForceReadOnly, false, FORCE_READ_ONLY_EXPECTED);
+        test_generate_rust_code(CodegenMode::ForceReadOnly, FORCE_READ_ONLY_EXPECTED);
     }
 }
diff --git a/tools/aconfig/aconfig/src/commands.rs b/tools/aconfig/aconfig/src/commands.rs
index 5036bc1bf8..14a98f0ba2 100644
--- a/tools/aconfig/aconfig/src/commands.rs
+++ b/tools/aconfig/aconfig/src/commands.rs
@@ -15,6 +15,7 @@
  */
 
 use anyhow::{bail, ensure, Context, Result};
+use convert_finalized_flags::FinalizedFlagMap;
 use itertools::Itertools;
 use protobuf::Message;
 use std::collections::HashMap;
@@ -23,7 +24,7 @@ use std::io::Read;
 use std::path::PathBuf;
 
 use crate::codegen::cpp::generate_cpp_code;
-use crate::codegen::java::generate_java_code;
+use crate::codegen::java::{generate_java_code, JavaCodegenConfig};
 use crate::codegen::rust::generate_rust_code;
 use crate::codegen::CodegenMode;
 use crate::dump::{DumpFormat, DumpPredicate};
@@ -80,18 +81,8 @@ pub fn parse_flags(
             .read_to_string(&mut contents)
             .with_context(|| format!("failed to read {}", input.source))?;
 
-        let mut flag_declarations =
-            aconfig_protos::flag_declarations::try_from_text_proto(&contents)
-                .with_context(|| input.error_context())?;
-
-        // system_ext flags should be treated as system flags as we are combining /system_ext
-        // and /system as one container
-        // TODO: remove this logic when we start enforcing that system_ext cannot be set as
-        // container in aconfig declaration files.
-        if flag_declarations.container() == "system_ext" {
-            flag_declarations.set_container(String::from("system"));
-        }
-
+        let flag_declarations = aconfig_protos::flag_declarations::try_from_text_proto(&contents)
+            .with_context(|| input.error_context())?;
         ensure!(
             package == flag_declarations.package(),
             "failed to parse {}: expected package {}, got {}",
@@ -218,32 +209,33 @@ pub fn create_java_lib(
     mut input: Input,
     codegen_mode: CodegenMode,
     allow_instrumentation: bool,
+    new_exported: bool,
+    single_exported_file: bool,
+    finalized_flags: FinalizedFlagMap,
 ) -> Result<Vec<OutputFile>> {
     let parsed_flags = input.try_parse_flags()?;
-    let modified_parsed_flags = modify_parsed_flags_based_on_mode(parsed_flags, codegen_mode)?;
+    let modified_parsed_flags =
+        modify_parsed_flags_based_on_mode(parsed_flags.clone(), codegen_mode)?;
     let Some(package) = find_unique_package(&modified_parsed_flags) else {
         bail!("no parsed flags, or the parsed flags use different packages");
     };
     let package = package.to_string();
-    let mut flag_names =
-        modified_parsed_flags.iter().map(|pf| pf.name().to_string()).collect::<Vec<_>>();
+    let mut flag_names = extract_flag_names(parsed_flags)?;
     let package_fingerprint = compute_flags_fingerprint(&mut flag_names);
     let flag_ids = assign_flag_ids(&package, modified_parsed_flags.iter())?;
-    generate_java_code(
-        &package,
-        modified_parsed_flags.into_iter(),
+    let config = JavaCodegenConfig {
         codegen_mode,
         flag_ids,
         allow_instrumentation,
         package_fingerprint,
-    )
+        new_exported,
+        single_exported_file,
+        finalized_flags,
+    };
+    generate_java_code(&package, modified_parsed_flags.into_iter(), config)
 }
 
-pub fn create_cpp_lib(
-    mut input: Input,
-    codegen_mode: CodegenMode,
-    allow_instrumentation: bool,
-) -> Result<Vec<OutputFile>> {
+pub fn create_cpp_lib(mut input: Input, codegen_mode: CodegenMode) -> Result<Vec<OutputFile>> {
     // TODO(327420679): Enable export mode for native flag library
     ensure!(
         codegen_mode != CodegenMode::Exported,
@@ -256,20 +248,10 @@ pub fn create_cpp_lib(
     };
     let package = package.to_string();
     let flag_ids = assign_flag_ids(&package, modified_parsed_flags.iter())?;
-    generate_cpp_code(
-        &package,
-        modified_parsed_flags.into_iter(),
-        codegen_mode,
-        flag_ids,
-        allow_instrumentation,
-    )
+    generate_cpp_code(&package, modified_parsed_flags.into_iter(), codegen_mode, flag_ids)
 }
 
-pub fn create_rust_lib(
-    mut input: Input,
-    codegen_mode: CodegenMode,
-    allow_instrumentation: bool,
-) -> Result<OutputFile> {
+pub fn create_rust_lib(mut input: Input, codegen_mode: CodegenMode) -> Result<OutputFile> {
     // // TODO(327420679): Enable export mode for native flag library
     ensure!(
         codegen_mode != CodegenMode::Exported,
@@ -282,13 +264,7 @@ pub fn create_rust_lib(
     };
     let package = package.to_string();
     let flag_ids = assign_flag_ids(&package, modified_parsed_flags.iter())?;
-    generate_rust_code(
-        &package,
-        flag_ids,
-        modified_parsed_flags.into_iter(),
-        codegen_mode,
-        allow_instrumentation,
-    )
+    generate_rust_code(&package, flag_ids, modified_parsed_flags.into_iter(), codegen_mode)
 }
 
 pub fn create_storage(
@@ -434,14 +410,7 @@ where
             return Err(anyhow::anyhow!("the number of flags in a package cannot exceed 65535"));
         }
 
-        // Exclude system/vendor/product flags that are RO+disabled.
-        let should_filter_container = pf.container == Some("vendor".to_string())
-            || pf.container == Some("system".to_string())
-            || pf.container == Some("product".to_string());
-        if !(should_filter_container
-            && pf.state == Some(ProtoFlagState::DISABLED.into())
-            && pf.permission == Some(ProtoFlagPermission::READ_ONLY.into()))
-        {
+        if should_include_flag(pf) {
             flag_ids.insert(pf.name().to_string(), flag_idx as u16);
             flag_idx += 1;
         }
@@ -449,10 +418,8 @@ where
     Ok(flag_ids)
 }
 
-#[allow(dead_code)] // TODO: b/316357686 - Use fingerprint in codegen to
-                    // protect hardcoded offset reads.
-                    // Creates a fingerprint of the flag names (which requires sorting the vector).
-                    // Fingerprint is used by both codegen and storage files.
+// Creates a fingerprint of the flag names (which requires sorting the vector).
+// Fingerprint is used by both codegen and storage files.
 pub fn compute_flags_fingerprint(flag_names: &mut Vec<String>) -> u64 {
     flag_names.sort();
 
@@ -463,11 +430,9 @@ pub fn compute_flags_fingerprint(flag_names: &mut Vec<String>) -> u64 {
     hasher.finish()
 }
 
-#[allow(dead_code)] // TODO: b/316357686 - Use fingerprint in codegen to
-                    // protect hardcoded offset reads.
-                    // Converts ProtoParsedFlags into a vector of strings containing all of the flag
-                    // names. Helper fn for creating fingerprint for codegen files. Flags must all
-                    // belong to the same package.
+// Converts ProtoParsedFlags into a vector of strings containing all of the flag
+// names. Helper fn for creating fingerprint for codegen files. Flags must all
+// belong to the same package.
 fn extract_flag_names(flags: ProtoParsedFlags) -> Result<Vec<String>> {
     let separated_flags: Vec<ProtoParsedFlag> = flags.parsed_flag.into_iter().collect::<Vec<_>>();
 
@@ -476,7 +441,24 @@ fn extract_flag_names(flags: ProtoParsedFlags) -> Result<Vec<String>> {
         bail!("No parsed flags, or the parsed flags use different packages.");
     };
 
-    Ok(separated_flags.into_iter().map(|flag| flag.name.unwrap()).collect::<Vec<_>>())
+    Ok(separated_flags
+        .into_iter()
+        .filter(should_include_flag)
+        .map(|flag| flag.name.unwrap())
+        .collect::<Vec<_>>())
+}
+
+// Exclude system/vendor/product flags that are RO+disabled.
+pub fn should_include_flag(pf: &ProtoParsedFlag) -> bool {
+    let should_filter_container = pf.container == Some("vendor".to_string())
+        || pf.container == Some("system".to_string())
+        || pf.container == Some("system_ext".to_string())
+        || pf.container == Some("product".to_string());
+
+    let disabled_ro = pf.state == Some(ProtoFlagState::DISABLED.into())
+        && pf.permission == Some(ProtoFlagPermission::READ_ONLY.into());
+
+    !should_filter_container || !disabled_ro
 }
 
 #[cfg(test)]
@@ -487,7 +469,7 @@ mod tests {
     #[test]
     fn test_offset_fingerprint() {
         let parsed_flags = crate::test::parse_test_flags();
-        let expected_fingerprint: u64 = 5801144784618221668;
+        let expected_fingerprint: u64 = 11551379960324242360;
 
         let mut extracted_flags = extract_flag_names(parsed_flags).unwrap();
         let hash_result = compute_flags_fingerprint(&mut extracted_flags);
@@ -507,6 +489,7 @@ mod tests {
             .parsed_flag
             .clone()
             .into_iter()
+            .filter(should_include_flag)
             .map(|flag| flag.name.unwrap())
             .map(String::from)
             .collect::<Vec<_>>();
diff --git a/tools/aconfig/aconfig/src/main.rs b/tools/aconfig/aconfig/src/main.rs
index c3902884f6..6b294239e9 100644
--- a/tools/aconfig/aconfig/src/main.rs
+++ b/tools/aconfig/aconfig/src/main.rs
@@ -33,6 +33,7 @@ mod storage;
 
 use aconfig_storage_file::StorageFileType;
 use codegen::CodegenMode;
+use convert_finalized_flags::FinalizedFlagMap;
 use dump::DumpFormat;
 
 #[cfg(test)]
@@ -40,9 +41,86 @@ mod test;
 
 use commands::{Input, OutputFile};
 
+const HELP_DUMP_CACHE: &str = r#"
+An aconfig cache file, created via `aconfig create-cache`.
+"#;
+
+const HELP_DUMP_FORMAT: &str = r#"
+Change the output format for each flag.
+
+The argument to --format is a format string. Each flag will be a copy of this string, with certain
+placeholders replaced by attributes of the flag. The placeholders are
+
+  {package}
+  {name}
+  {namespace}
+  {description}
+  {bug}
+  {state}
+  {state:bool}
+  {permission}
+  {trace}
+  {trace:paths}
+  {is_fixed_read_only}
+  {is_exported}
+  {container}
+  {metadata}
+  {fully_qualified_name}
+
+Note: the format strings "textproto" and "protobuf" are handled in a special way: they output all
+flag attributes in text or binary protobuf format.
+
+Examples:
+
+  # See which files were read to determine the value of a flag; the files were read in the order
+  # listed.
+  --format='{fully_qualified_name} {trace}'
+
+  # Trace the files read for a specific flag. Useful during debugging.
+  --filter=fully_qualified_name:com.foo.flag_name --format='{trace}'
+
+  # Print a somewhat human readable description of each flag.
+  --format='The flag {name} in package {package} is {state} and has permission {permission}.'
+"#;
+
 const HELP_DUMP_FILTER: &str = r#"
-Limit which flags to output. If multiple --filter arguments are provided, the output will be
-limited to flags that match any of the filters.
+Limit which flags to output. If --filter is omitted, all flags will be printed. If multiple
+--filter options are provided, the output will be limited to flags that match any of the filters.
+
+The argument to --filter is a search query. Multiple queries can be AND-ed together by
+concatenating them with a plus sign.
+
+Valid queries are:
+
+  package:<string>
+  name:<string>
+  namespace:<string>
+  bug:<string>
+  state:ENABLED|DISABLED
+  permission:READ_ONLY|READ_WRITE
+  is_fixed_read_only:true|false
+  is_exported:true|false
+  container:<string>
+  fully_qualified_name:<string>
+
+Note: there is currently no support for filtering based on these flag attributes: description,
+trace, metadata.
+
+Examples:
+
+  # Print a single flag:
+  --filter=fully_qualified_name:com.foo.flag_name
+
+  # Print all known information about a single flag:
+  --filter=fully_qualified_name:com.foo.flag_name --format=textproto
+
+  # Print all flags in the com.foo package, and all enabled flags in the com.bar package:
+  --filter=package:com.foo --filter=package.com.bar+state:ENABLED
+"#;
+
+const HELP_DUMP_DEDUP: &str = r#"
+Allow the same flag to be present in multiple cache files; if duplicates are found, collapse into
+a single instance.
 "#;
 
 fn cli() -> Command {
@@ -80,11 +158,35 @@ fn cli() -> Command {
                         .value_parser(EnumValueParser::<CodegenMode>::new())
                         .default_value("production"),
                 )
+                .arg(
+                    Arg::new("single-exported-file")
+                        .long("single-exported-file")
+                        .value_parser(clap::value_parser!(bool))
+                        .default_value("false"),
+                )
+                // TODO: b/395899938 - clean up flags for switching to new storage
                 .arg(
                     Arg::new("allow-instrumentation")
                         .long("allow-instrumentation")
                         .value_parser(clap::value_parser!(bool))
                         .default_value("false"),
+                )
+                // TODO: b/395899938 - clean up flags for switching to new storage
+                .arg(
+                    Arg::new("new-exported")
+                        .long("new-exported")
+                        .value_parser(clap::value_parser!(bool))
+                        .default_value("false"),
+                )
+                // Allows build flag toggling of checking API level in exported
+                // flag lib for finalized API flags.
+                // TODO: b/378936061 - Remove once build flag for API level
+                // check is fully enabled.
+                .arg(
+                    Arg::new("check-api-level")
+                        .long("check-api-level")
+                        .value_parser(clap::value_parser!(bool))
+                        .default_value("false"),
                 ),
         )
         .subcommand(
@@ -134,22 +236,34 @@ fn cli() -> Command {
         .subcommand(
             Command::new("dump-cache")
                 .alias("dump")
-                .arg(Arg::new("cache").long("cache").action(ArgAction::Append))
+                .arg(
+                    Arg::new("cache")
+                        .long("cache")
+                        .action(ArgAction::Append)
+                        .long_help(HELP_DUMP_CACHE.trim()),
+                )
                 .arg(
                     Arg::new("format")
                         .long("format")
                         .value_parser(|s: &str| DumpFormat::try_from(s))
                         .default_value(
                             "{fully_qualified_name} [{container}]: {permission} + {state}",
-                        ),
+                        )
+                        .long_help(HELP_DUMP_FORMAT.trim()),
                 )
                 .arg(
                     Arg::new("filter")
                         .long("filter")
                         .action(ArgAction::Append)
-                        .help(HELP_DUMP_FILTER.trim()),
+                        .long_help(HELP_DUMP_FILTER.trim()),
+                )
+                .arg(
+                    Arg::new("dedup")
+                        .long("dedup")
+                        .num_args(0)
+                        .action(ArgAction::SetTrue)
+                        .long_help(HELP_DUMP_DEDUP.trim()),
                 )
-                .arg(Arg::new("dedup").long("dedup").num_args(0).action(ArgAction::SetTrue))
                 .arg(Arg::new("out").long("out").default_value("-")),
         )
         .subcommand(
@@ -235,6 +349,12 @@ fn write_output_to_file_or_stdout(path: &str, data: &[u8]) -> Result<()> {
     Ok(())
 }
 
+fn load_finalized_flags() -> Result<FinalizedFlagMap> {
+    let json_str = include_str!(concat!(env!("OUT_DIR"), "/finalized_flags_record.json"));
+    let map = serde_json::from_str(json_str)?;
+    Ok(map)
+}
+
 fn main() -> Result<()> {
     let matches = cli().get_matches();
     match matches.subcommand() {
@@ -267,8 +387,23 @@ fn main() -> Result<()> {
             let mode = get_required_arg::<CodegenMode>(sub_matches, "mode")?;
             let allow_instrumentation =
                 get_required_arg::<bool>(sub_matches, "allow-instrumentation")?;
-            let generated_files = commands::create_java_lib(cache, *mode, *allow_instrumentation)
-                .context("failed to create java lib")?;
+            let new_exported = get_required_arg::<bool>(sub_matches, "new-exported")?;
+            let single_exported_file =
+                get_required_arg::<bool>(sub_matches, "single-exported-file")?;
+
+            let check_api_level = get_required_arg::<bool>(sub_matches, "check-api-level")?;
+            let finalized_flags: FinalizedFlagMap =
+                if *check_api_level { load_finalized_flags()? } else { FinalizedFlagMap::new() };
+
+            let generated_files = commands::create_java_lib(
+                cache,
+                *mode,
+                *allow_instrumentation,
+                *new_exported,
+                *single_exported_file,
+                finalized_flags,
+            )
+            .context("failed to create java lib")?;
             let dir = PathBuf::from(get_required_arg::<String>(sub_matches, "out")?);
             generated_files
                 .iter()
@@ -277,10 +412,8 @@ fn main() -> Result<()> {
         Some(("create-cpp-lib", sub_matches)) => {
             let cache = open_single_file(sub_matches, "cache")?;
             let mode = get_required_arg::<CodegenMode>(sub_matches, "mode")?;
-            let allow_instrumentation =
-                get_required_arg::<bool>(sub_matches, "allow-instrumentation")?;
-            let generated_files = commands::create_cpp_lib(cache, *mode, *allow_instrumentation)
-                .context("failed to create cpp lib")?;
+            let generated_files =
+                commands::create_cpp_lib(cache, *mode).context("failed to create cpp lib")?;
             let dir = PathBuf::from(get_required_arg::<String>(sub_matches, "out")?);
             generated_files
                 .iter()
@@ -289,10 +422,8 @@ fn main() -> Result<()> {
         Some(("create-rust-lib", sub_matches)) => {
             let cache = open_single_file(sub_matches, "cache")?;
             let mode = get_required_arg::<CodegenMode>(sub_matches, "mode")?;
-            let allow_instrumentation =
-                get_required_arg::<bool>(sub_matches, "allow-instrumentation")?;
-            let generated_file = commands::create_rust_lib(cache, *mode, *allow_instrumentation)
-                .context("failed to create rust lib")?;
+            let generated_file =
+                commands::create_rust_lib(cache, *mode).context("failed to create rust lib")?;
             let dir = PathBuf::from(get_required_arg::<String>(sub_matches, "out")?);
             write_output_file_realtive_to_dir(&dir, &generated_file)?;
         }
diff --git a/tools/aconfig/aconfig/src/storage/flag_table.rs b/tools/aconfig/aconfig/src/storage/flag_table.rs
index 3b245a76f2..a3b4e8fe1e 100644
--- a/tools/aconfig/aconfig/src/storage/flag_table.rs
+++ b/tools/aconfig/aconfig/src/storage/flag_table.rs
@@ -14,9 +14,9 @@
  * limitations under the License.
  */
 
-use crate::commands::assign_flag_ids;
+use crate::commands::{assign_flag_ids, should_include_flag};
 use crate::storage::FlagPackage;
-use aconfig_protos::{ProtoFlagPermission, ProtoFlagState};
+use aconfig_protos::ProtoFlagPermission;
 use aconfig_storage_file::{
     get_table_size, FlagTable, FlagTableHeader, FlagTableNode, StorageFileType, StoredFlagType,
 };
@@ -64,13 +64,7 @@ impl FlagTableNodeWrapper {
     fn create_nodes(package: &FlagPackage, num_buckets: u32) -> Result<Vec<Self>> {
         // Exclude system/vendor/product flags that are RO+disabled.
         let mut filtered_package = package.clone();
-        filtered_package.boolean_flags.retain(|f| {
-            !((f.container == Some("system".to_string())
-                || f.container == Some("vendor".to_string())
-                || f.container == Some("product".to_string()))
-                && f.permission == Some(ProtoFlagPermission::READ_ONLY.into())
-                && f.state == Some(ProtoFlagState::DISABLED.into()))
-        });
+        filtered_package.boolean_flags.retain(|pf| should_include_flag(pf));
 
         let flag_ids =
             assign_flag_ids(package.package_name, filtered_package.boolean_flags.iter().copied())?;
diff --git a/tools/aconfig/aconfig/templates/CustomFeatureFlags.java.template b/tools/aconfig/aconfig/templates/CustomFeatureFlags.java.template
index b82b9cb827..c702c9b1e5 100644
--- a/tools/aconfig/aconfig/templates/CustomFeatureFlags.java.template
+++ b/tools/aconfig/aconfig/templates/CustomFeatureFlags.java.template
@@ -5,13 +5,26 @@ package {package_name};
 import android.compat.annotation.UnsupportedAppUsage;
 {{ -endif }}
 import java.util.Arrays;
+{{ -if library_exported }}
+import java.util.HashMap;
+import java.util.Map;
+{{ -endif }}
 import java.util.HashSet;
 import java.util.List;
 import java.util.Set;
 import java.util.function.BiPredicate;
 import java.util.function.Predicate;
+{{ -if library_exported }}
+import android.os.Build;
+{{ -endif }}
 
+{{ -if single_exported_file }}
+{{ -if library_exported }}
+@Deprecated {#- PREFER ExportedFlags #}
+{{ -endif }}
+{{ -else }}
 /** @hide */
+{{ -endif }}
 public class CustomFeatureFlags implements FeatureFlags \{
 
     private BiPredicate<String, Predicate<FeatureFlags>> mGetValueImpl;
@@ -67,4 +80,24 @@ public class CustomFeatureFlags implements FeatureFlags \{
             ""{# The empty string here is to resolve the ending comma #}
         )
     );
+
+{{ -if library_exported }}
+    private Map<String, Integer> mFinalizedFlags = new HashMap<>(
+        Map.ofEntries(
+            {{ -for item in flag_elements }}
+            {{ -if item.finalized_sdk_present }}
+            Map.entry(Flags.FLAG_{item.flag_name_constant_suffix}, {item.finalized_sdk_value}),
+            {{ -endif }}
+            {{ -endfor }}
+            Map.entry("", Integer.MAX_VALUE){# The empty entry to avoid empty entries #}
+        )
+    );
+
+    public boolean isFlagFinalized(String flagName) \{
+        if (!mFinalizedFlags.containsKey(flagName)) \{
+            return false;
+        }
+        return Build.VERSION.SDK_INT >= mFinalizedFlags.get(flagName);
+    }
+{{ -endif }}
 }
diff --git a/tools/aconfig/aconfig/templates/ExportedFlags.java.template b/tools/aconfig/aconfig/templates/ExportedFlags.java.template
new file mode 100644
index 0000000000..176da18186
--- /dev/null
+++ b/tools/aconfig/aconfig/templates/ExportedFlags.java.template
@@ -0,0 +1,51 @@
+package {package_name}; {#- CODEGEN FOR EXPORTED MODE FOR NEW STORAGE SINGLE EXPORTED FILE#}
+
+import android.os.Build;
+import android.os.flagging.AconfigPackage;
+import android.util.Log;
+public final class ExportedFlags \{
+{{ -for item in flag_elements}}
+    public static final String FLAG_{item.flag_name_constant_suffix} = "{item.device_config_flag}";
+{{- endfor }}
+    private static final String TAG = "ExportedFlags";
+    private static volatile boolean isCached = false;
+{{ for flag in flag_elements }}
+    private static boolean {flag.method_name} = false;
+{{ -endfor }} {#- end flag_elements #}
+    private ExportedFlags() \{}
+
+    private void init() \{
+        try \{
+            AconfigPackage reader = AconfigPackage.load("{package_name}");
+            {{ -for namespace_with_flags in namespace_flags }}
+            {{ -for flag in namespace_with_flags.flags }}
+            {flag.method_name} = reader.getBooleanFlagValue("{flag.flag_name}", {flag.default_value});
+
+            {{ -endfor }} {#- end namespace_with_flags.flags #}
+            {{ -endfor }} {#- end namespace_flags #}
+        } catch (Exception e) \{
+            // pass
+            Log.e(TAG, e.toString());
+        } catch (LinkageError e) \{
+            // for mainline module running on older devices.
+            // This should be replaces to version check, after the version bump.
+            Log.w(TAG, e.toString());
+        }
+        isCached = true;
+    }
+
+{{ -for flag in flag_elements }}
+    public static boolean {flag.method_name}() \{
+        {{ -if flag.finalized_sdk_present }}
+        if (Build.VERSION.SDK_INT >= {flag.finalized_sdk_value}) \{
+          return true;
+        }
+        {{ -endif}}  {#- end finalized_sdk_present#}
+        if (!featureFlags.isCached) \{
+            featureFlags.init();
+        }
+        return featureFlags.{flag.method_name};
+    }
+{{ -endfor }}
+    private static ExportedFlags featureFlags = new ExportedFlags();
+}
diff --git a/tools/aconfig/aconfig/templates/FakeFeatureFlagsImpl.java.template b/tools/aconfig/aconfig/templates/FakeFeatureFlagsImpl.java.template
index 290d2c4b24..ed277ae27d 100644
--- a/tools/aconfig/aconfig/templates/FakeFeatureFlagsImpl.java.template
+++ b/tools/aconfig/aconfig/templates/FakeFeatureFlagsImpl.java.template
@@ -4,7 +4,13 @@ import java.util.HashMap;
 import java.util.Map;
 import java.util.function.Predicate;
 
+{{ -if single_exported_file }}
+{{ -if library_exported }}
+@Deprecated {#- PREFER ExportedFlags #}
+{{ -endif }}
+{{ -else }}
 /** @hide */
+{{ -endif }}
 public class FakeFeatureFlagsImpl extends CustomFeatureFlags \{
     private final Map<String, Boolean> mFlagMap = new HashMap<>();
     private final FeatureFlags mDefaults;
diff --git a/tools/aconfig/aconfig/templates/FeatureFlags.java.template b/tools/aconfig/aconfig/templates/FeatureFlags.java.template
index d2799b2474..c8b9b7f263 100644
--- a/tools/aconfig/aconfig/templates/FeatureFlags.java.template
+++ b/tools/aconfig/aconfig/templates/FeatureFlags.java.template
@@ -3,7 +3,16 @@ package {package_name};
 // TODO(b/303773055): Remove the annotation after access issue is resolved.
 import android.compat.annotation.UnsupportedAppUsage;
 {{ -endif }}
+{{ -if single_exported_file }}
+{{ -if library_exported }}
+/**
+ * @deprecated Use \{@link ExportedFlags} instead.
+ */
+@Deprecated {#- PREFER ExportedFlags #}
+{{ -endif }}
+{{ -else }}
 /** @hide */
+{{ -endif }}
 public interface FeatureFlags \{
 {{ for item in flag_elements }}
 {{ -if not item.is_read_write }}
diff --git a/tools/aconfig/aconfig/templates/FeatureFlagsImpl.deviceConfig.java.template b/tools/aconfig/aconfig/templates/FeatureFlagsImpl.deviceConfig.java.template
new file mode 100644
index 0000000000..44d5cc019b
--- /dev/null
+++ b/tools/aconfig/aconfig/templates/FeatureFlagsImpl.deviceConfig.java.template
@@ -0,0 +1,68 @@
+package {package_name};
+{{ if not library_exported- }}
+// TODO(b/303773055): Remove the annotation after access issue is resolved.
+import android.compat.annotation.UnsupportedAppUsage;
+{{ -endif }} {#- end of not library_exported#}
+{{ -if runtime_lookup_required }}
+import android.os.Binder;
+import android.provider.DeviceConfig;
+import android.provider.DeviceConfig.Properties;
+{{ -endif }}  {#- end of runtime_lookup_required#}
+/** @hide */
+public final class FeatureFlagsImpl implements FeatureFlags \{
+{{ -if runtime_lookup_required }}
+{{ -for namespace_with_flags in namespace_flags }}
+    private static volatile boolean {namespace_with_flags.namespace}_is_cached = false;
+{{ -endfor- }}
+{{ for flag in flag_elements }}
+{{- if flag.is_read_write }}
+    private static boolean {flag.method_name} = {flag.default_value};
+{{ -endif }} {#- end of is_read_write#}
+{{ -endfor }}
+{{ for namespace_with_flags in namespace_flags }}
+    private void load_overrides_{namespace_with_flags.namespace}() \{
+        final long ident = Binder.clearCallingIdentity();
+        try \{
+            Properties properties = DeviceConfig.getProperties("{namespace_with_flags.namespace}");
+{{ -for flag in namespace_with_flags.flags }}
+{{ -if flag.is_read_write }}
+            {flag.method_name} =
+                properties.getBoolean(Flags.FLAG_{flag.flag_name_constant_suffix}, {flag.default_value});
+{{ -endif }} {#- end of is_read_write#}
+{{ -endfor }}
+        } catch (NullPointerException e) \{
+            throw new RuntimeException(
+                "Cannot read value from namespace {namespace_with_flags.namespace} "
+                + "from DeviceConfig. It could be that the code using flag "
+                + "executed before SettingsProvider initialization. Please use "
+                + "fixed read-only flag by adding is_fixed_read_only: true in "
+                + "flag declaration.",
+                e
+            );
+        } catch (SecurityException e) \{
+            // for isolated process case, skip loading flag value from the storage, use the default
+        } finally \{
+            Binder.restoreCallingIdentity(ident);
+        }
+        {namespace_with_flags.namespace}_is_cached = true;
+}
+{{ endfor- }}
+{{ -endif }}{#- end of runtime_lookup_required #}
+{{ -for flag in flag_elements }}
+    @Override
+{{ -if not library_exported }}
+    @com.android.aconfig.annotations.AconfigFlagAccessor
+    @UnsupportedAppUsage
+{{ -endif }}{#- end of not library_exported #}
+    public boolean {flag.method_name}() \{
+{{ -if flag.is_read_write }}
+        if (!{flag.device_config_namespace}_is_cached) \{
+            load_overrides_{flag.device_config_namespace}();
+        }
+        return {flag.method_name};
+{{ -else }} {#- else is_read_write #}
+        return {flag.default_value};
+{{ -endif }}{#- end of is_read_write #}
+    }
+{{ endfor }}
+}
diff --git a/tools/aconfig/aconfig/templates/FeatureFlagsImpl.exported.java.template b/tools/aconfig/aconfig/templates/FeatureFlagsImpl.exported.java.template
new file mode 100644
index 0000000000..b843ec2441
--- /dev/null
+++ b/tools/aconfig/aconfig/templates/FeatureFlagsImpl.exported.java.template
@@ -0,0 +1,53 @@
+package {package_name}; {#- CODEGEN FOR EXPORTED MODE FOR NEW STORAGE #}
+
+import android.os.Build;
+import android.os.flagging.AconfigPackage;
+import android.util.Log;
+{{ -if single_exported_file }}
+{{ -if library_exported }}
+/**
+ * @deprecated Use \{@link ExportedFlags} instead.
+ */
+@Deprecated {#- PREFER ExportedFlags #}
+{{ -endif }}
+{{ -else }}
+/** @hide */
+{{ -endif }}
+public final class FeatureFlagsImpl implements FeatureFlags \{
+    private static final String TAG = "FeatureFlagsImplExport";
+    private static volatile boolean isCached = false;
+{{ for flag in flag_elements }}
+    private static boolean {flag.method_name} = false;
+{{ -endfor }} {#- end flag_elements #}
+    private void init() \{
+        try \{
+            AconfigPackage reader = AconfigPackage.load("{package_name}");
+            {{ -for namespace_with_flags in namespace_flags }}
+            {{ -for flag in namespace_with_flags.flags }}
+            {{ -if flag.finalized_sdk_present }}
+            {flag.method_name} = Build.VERSION.SDK_INT >= {flag.finalized_sdk_value} ? true : reader.getBooleanFlagValue("{flag.flag_name}", {flag.default_value});
+            {{ - else }} {#- else finalized_sdk_present #}
+            {flag.method_name} = reader.getBooleanFlagValue("{flag.flag_name}", {flag.default_value});
+            {{ -endif}}  {#- end finalized_sdk_present#}
+            {{ -endfor }} {#- end namespace_with_flags.flags #}
+            {{ -endfor }} {#- end namespace_flags #}
+        } catch (Exception e) \{
+            // pass
+            Log.e(TAG, e.toString());
+        } catch (LinkageError e) \{
+            // for mainline module running on older devices.
+            // This should be replaces to version check, after the version bump.
+            Log.w(TAG, e.toString());
+        }
+        isCached = true;
+    }
+{{ -for flag in flag_elements }}
+    @Override
+    public boolean {flag.method_name}() \{
+        if (!isCached) \{
+            init();
+        }
+        return {flag.method_name};
+    }
+{{ endfor }} {#- end flag_elements #}
+}
diff --git a/tools/aconfig/aconfig/templates/FeatureFlagsImpl.java.template b/tools/aconfig/aconfig/templates/FeatureFlagsImpl.java.template
deleted file mode 100644
index b605e72a78..0000000000
--- a/tools/aconfig/aconfig/templates/FeatureFlagsImpl.java.template
+++ /dev/null
@@ -1,203 +0,0 @@
-package {package_name};
-{{ -if not is_test_mode }}
-{{ -if allow_instrumentation }}
-{{ if not library_exported- }}{#- only new storage for prod mode #}
-// TODO(b/303773055): Remove the annotation after access issue is resolved.
-import android.compat.annotation.UnsupportedAppUsage;
-{{ -if runtime_lookup_required }}
-import android.os.Build;
-{{ if is_platform_container }}
-import android.os.flagging.PlatformAconfigPackageInternal;
-{{ -else }}
-import android.os.flagging.AconfigPackageInternal;
-{{ -endif }}
-import android.util.Log;
-{{ -endif }}
-/** @hide */
-public final class FeatureFlagsImpl implements FeatureFlags \{
-{{ -if runtime_lookup_required }}
-    private static final String TAG = "{package_name}.FeatureFlagsImpl";
-    private static volatile boolean isCached = false;
-{{ for flag in flag_elements }}
-{{ -if flag.is_read_write }}
-    private static boolean {flag.method_name} = {flag.default_value};
-{{ -endif }}
-{{ -endfor }}
-
-    private void init() \{
-        try \{
-{{ if is_platform_container }}
-            PlatformAconfigPackageInternal reader = PlatformAconfigPackageInternal.load("{container}", "{package_name}", {package_fingerprint});
-{{ -else }}
-            AconfigPackageInternal reader = AconfigPackageInternal.load("{container}", "{package_name}", {package_fingerprint});
-{{ -endif }}
-        {{ -for namespace_with_flags in namespace_flags }}
-        {{ -for flag in namespace_with_flags.flags }}
-        {{ -if flag.is_read_write }}
-            {flag.method_name} = reader.getBooleanFlagValue({flag.flag_offset});
-        {{ -endif }}
-        {{ -endfor }}
-        {{ -endfor }}
-        } catch (Exception e) \{
-            Log.e(TAG, e.toString());
-        } catch (NoClassDefFoundError e) \{
-            // for mainline module running on older devices.
-            // This should be replaces to version check, after the version bump.
-            Log.e(TAG, e.toString());
-        }
-        isCached = true;
-    }
-{{ -endif }}{#- end of runtime_lookup_required #}
-{{ -for flag in flag_elements }}
-    @Override
-    @com.android.aconfig.annotations.AconfigFlagAccessor
-    @UnsupportedAppUsage
-    public boolean {flag.method_name}() \{
-{{ -if flag.is_read_write }}
-        if (!isCached) \{
-            init();
-        }
-        return {flag.method_name};
-{{ -else }}
-        return {flag.default_value};
-{{ -endif }}
-    }
-{{ endfor }}
-}
-{{ -else- }}{#- device config for exproted mode #}
-import android.os.Binder;
-import android.provider.DeviceConfig;
-import android.provider.DeviceConfig.Properties;
-/** @hide */
-public final class FeatureFlagsImpl implements FeatureFlags \{
-{{ -for namespace_with_flags in namespace_flags }}
-    private static volatile boolean {namespace_with_flags.namespace}_is_cached = false;
-{{ -endfor- }}
-{{ for flag in flag_elements }}
-{{ -if flag.is_read_write }}
-    private static boolean {flag.method_name} = {flag.default_value};
-{{ -endif }}
-{{ -endfor }}
-{{ for namespace_with_flags in namespace_flags }}
-    private void load_overrides_{namespace_with_flags.namespace}() \{
-        final long ident = Binder.clearCallingIdentity();
-        try \{
-            Properties properties = DeviceConfig.getProperties("{namespace_with_flags.namespace}");
-{{ -for flag in namespace_with_flags.flags }}
-{{ -if flag.is_read_write }}
-            {flag.method_name} =
-                properties.getBoolean(Flags.FLAG_{flag.flag_name_constant_suffix}, {flag.default_value});
-{{ -endif }}
-{{ -endfor }}
-        } catch (NullPointerException e) \{
-            throw new RuntimeException(
-                "Cannot read value from namespace {namespace_with_flags.namespace} "
-                + "from DeviceConfig. It could be that the code using flag "
-                + "executed before SettingsProvider initialization. Please use "
-                + "fixed read-only flag by adding is_fixed_read_only: true in "
-                + "flag declaration.",
-                e
-            );
-        } catch (SecurityException e) \{
-            // for isolated process case, skip loading flag value from the storage, use the default
-        } finally \{
-            Binder.restoreCallingIdentity(ident);
-        }
-        {namespace_with_flags.namespace}_is_cached = true;
-    }
-{{ endfor- }}
-{{ -for flag in flag_elements }}
-    @Override
-    public boolean {flag.method_name}() \{
-        if (!{flag.device_config_namespace}_is_cached) \{
-            load_overrides_{flag.device_config_namespace}();
-        }
-        return {flag.method_name};
-    }
-{{ endfor }}
-}
-{{ -endif- }} {#- end exported mode #}
-{{ else }} {#- else for allow_instrumentation is not enabled #}
-{{ if not library_exported- }}
-// TODO(b/303773055): Remove the annotation after access issue is resolved.
-import android.compat.annotation.UnsupportedAppUsage;
-{{ -endif }}
-
-{{ -if runtime_lookup_required }}
-import android.os.Binder;
-import android.provider.DeviceConfig;
-import android.provider.DeviceConfig.Properties;
-{{ -endif }}
-/** @hide */
-public final class FeatureFlagsImpl implements FeatureFlags \{
-{{ -if runtime_lookup_required }}
-{{ -for namespace_with_flags in namespace_flags }}
-    private static volatile boolean {namespace_with_flags.namespace}_is_cached = false;
-{{ -endfor- }}
-
-{{ for flag in flag_elements }}
-{{- if flag.is_read_write }}
-    private static boolean {flag.method_name} = {flag.default_value};
-{{ -endif }}
-{{ -endfor }}
-{{ for namespace_with_flags in namespace_flags }}
-    private void load_overrides_{namespace_with_flags.namespace}() \{
-        final long ident = Binder.clearCallingIdentity();
-        try \{
-            Properties properties = DeviceConfig.getProperties("{namespace_with_flags.namespace}");
-{{ -for flag in namespace_with_flags.flags }}
-{{ -if flag.is_read_write }}
-            {flag.method_name} =
-                properties.getBoolean(Flags.FLAG_{flag.flag_name_constant_suffix}, {flag.default_value});
-{{ -endif }}
-{{ -endfor }}
-        } catch (NullPointerException e) \{
-            throw new RuntimeException(
-                "Cannot read value from namespace {namespace_with_flags.namespace} "
-                + "from DeviceConfig. It could be that the code using flag "
-                + "executed before SettingsProvider initialization. Please use "
-                + "fixed read-only flag by adding is_fixed_read_only: true in "
-                + "flag declaration.",
-                e
-            );
-        } finally \{
-            Binder.restoreCallingIdentity(ident);
-        }
-        {namespace_with_flags.namespace}_is_cached = true;
-}
-{{ endfor- }}
-{{ -endif }}{#- end of runtime_lookup_required #}
-{{ -for flag in flag_elements }}
-    @Override
-{{ -if not library_exported }}
-    @com.android.aconfig.annotations.AconfigFlagAccessor
-    @UnsupportedAppUsage
-{{ -endif }}
-    public boolean {flag.method_name}() \{
-{{ -if flag.is_read_write }}
-        if (!{flag.device_config_namespace}_is_cached) \{
-            load_overrides_{flag.device_config_namespace}();
-        }
-        return {flag.method_name};
-{{ -else }}
-        return {flag.default_value};
-{{ -endif }}
-    }
-{{ endfor }}
-}
-{{ endif}} {#- endif for allow_instrumentation #}
-{{ else }} {#- Generate only stub if in test mode #}
-/** @hide */
-public final class FeatureFlagsImpl implements FeatureFlags \{
-{{ for flag in flag_elements }}
-    @Override
-{{ -if not library_exported }}
-    @com.android.aconfig.annotations.AconfigFlagAccessor
-{{ -endif }}
-    public boolean {flag.method_name}() \{
-        throw new UnsupportedOperationException(
-            "Method is not implemented.");
-    }
-{{ endfor- }}
-}
-{{ endif }}
diff --git a/tools/aconfig/aconfig/templates/FeatureFlagsImpl.new_storage.java.template b/tools/aconfig/aconfig/templates/FeatureFlagsImpl.new_storage.java.template
new file mode 100644
index 0000000000..8dc7581193
--- /dev/null
+++ b/tools/aconfig/aconfig/templates/FeatureFlagsImpl.new_storage.java.template
@@ -0,0 +1,62 @@
+package {package_name}; {#- CODEGEN FOR INTERNAL MODE FOR NEW STORAGE #}
+// TODO(b/303773055): Remove the annotation after access issue is resolved.
+import android.compat.annotation.UnsupportedAppUsage;
+{{ -if runtime_lookup_required }}
+{{ if is_platform_container }}
+import android.os.flagging.PlatformAconfigPackageInternal;
+{{ -else }} {#- else is_platform_container #}
+import android.os.flagging.AconfigPackageInternal;
+{{ -endif }} {#- end of is_platform_container#}
+import android.util.Log;
+{{ -endif }} {#- end of runtime_lookup_required#}
+/** @hide */
+public final class FeatureFlagsImpl implements FeatureFlags \{
+{{ -if runtime_lookup_required }}
+    private static final String TAG = "FeatureFlagsImpl";
+    private static volatile boolean isCached = false;
+{{ for flag in flag_elements }}
+{{ -if flag.is_read_write }}
+    private static boolean {flag.method_name} = {flag.default_value};
+{{ -endif }} {#- end of is_read_write#}
+{{ -endfor }} {#- else flag_elements #}
+
+    private void init() \{
+        try \{
+{{ if is_platform_container }}
+            PlatformAconfigPackageInternal reader = PlatformAconfigPackageInternal.load("{package_name}", {package_fingerprint});
+{{ -else }} {#- else is_platform_container #}
+            AconfigPackageInternal reader = AconfigPackageInternal.load("{package_name}", {package_fingerprint});
+{{ -endif }} {#- end of is_platform_container#}
+        {{ -for namespace_with_flags in namespace_flags }}
+        {{ -for flag in namespace_with_flags.flags }}
+        {{ -if flag.is_read_write }}
+            {flag.method_name} = reader.getBooleanFlagValue({flag.flag_offset});
+        {{ -endif }} {#- is_read_write#}
+        {{ -endfor }} {#- else namespace_with_flags.flags #}
+        {{ -endfor }}  {#- else namespace_flags #}
+        } catch (Exception e) \{
+            Log.e(TAG, e.toString());
+        } catch (LinkageError e) \{
+            // for mainline module running on older devices.
+            // This should be replaces to version check, after the version bump.
+            Log.e(TAG, e.toString());
+        }
+        isCached = true;
+    }
+{{ -endif }}{#- end of runtime_lookup_required #}
+{{ -for flag in flag_elements }}
+    @Override
+    @com.android.aconfig.annotations.AconfigFlagAccessor
+    @UnsupportedAppUsage
+    public boolean {flag.method_name}() \{
+{{ -if flag.is_read_write }}
+        if (!isCached) \{
+            init();
+        }
+        return {flag.method_name};
+{{ -else }}{#- else is_read_write #}
+        return {flag.default_value};
+{{ -endif }}  {#- end of is_read_write#}
+    }
+{{ endfor }} {#- else flag_elements #}
+}
diff --git a/tools/aconfig/aconfig/templates/FeatureFlagsImpl.test_mode.java.template b/tools/aconfig/aconfig/templates/FeatureFlagsImpl.test_mode.java.template
new file mode 100644
index 0000000000..8eda26310e
--- /dev/null
+++ b/tools/aconfig/aconfig/templates/FeatureFlagsImpl.test_mode.java.template
@@ -0,0 +1,14 @@
+package {package_name}; {#- CODEGEN FOR TEST MODE #}
+/** @hide */
+public final class FeatureFlagsImpl implements FeatureFlags \{
+{{ for flag in flag_elements }}
+    @Override
+{{ -if not library_exported }}
+    @com.android.aconfig.annotations.AconfigFlagAccessor
+{{ -endif }}
+    public boolean {flag.method_name}() \{
+        throw new UnsupportedOperationException(
+            "Method is not implemented.");
+    }
+{{ endfor- }}
+}
diff --git a/tools/aconfig/aconfig/templates/Flags.java.template b/tools/aconfig/aconfig/templates/Flags.java.template
index e2f70b95fa..0cdc2692ca 100644
--- a/tools/aconfig/aconfig/templates/Flags.java.template
+++ b/tools/aconfig/aconfig/templates/Flags.java.template
@@ -2,8 +2,19 @@ package {package_name};
 {{ if not library_exported- }}
 // TODO(b/303773055): Remove the annotation after access issue is resolved.
 import android.compat.annotation.UnsupportedAppUsage;
+{{ else }}
+import android.os.Build;
+{{ -endif }} {#- end not library_exported#}
+{{ -if single_exported_file }}
+{{ -if library_exported }}
+/**
+ * @deprecated Use \{@link ExportedFlags} instead.
+ */
+@Deprecated {#- PREFER ExportedFlags #}
 {{ -endif }}
+{{ -else }}
 /** @hide */
+{{ -endif }}
 public final class Flags \{
 {{ -for item in flag_elements}}
     /** @hide */
@@ -22,6 +33,13 @@ public final class Flags \{
     @UnsupportedAppUsage
 {{ -endif }}
     public static boolean {item.method_name}() \{
+        {{ if library_exported- }}
+        {{ -if item.finalized_sdk_present }}
+        if (Build.VERSION.SDK_INT >= {item.finalized_sdk_value}) \{
+          return true;
+        }
+        {{ -endif}}  {#- end finalized_sdk_present#}
+        {{ -endif}}  {#- end library_exported#}
         return FEATURE_FLAGS.{item.method_name}();
     }
 {{ -endfor }}
diff --git a/tools/aconfig/aconfig/templates/cpp_exported_header.template b/tools/aconfig/aconfig/templates/cpp_exported_header.template
index 4643c9775c..f6f576a29e 100644
--- a/tools/aconfig/aconfig/templates/cpp_exported_header.template
+++ b/tools/aconfig/aconfig/templates/cpp_exported_header.template
@@ -41,6 +41,7 @@ public:
 extern std::unique_ptr<flag_provider_interface> provider_;
 
 {{ for item in class_elements}}
+{{ if not is_test_mode }}{{ if item.is_fixed_read_only }}constexpr {{ endif }}{{ endif -}}
 inline bool {item.flag_name}() \{
     {{ -if is_test_mode }}
     return provider_->{item.flag_name}();
diff --git a/tools/aconfig/aconfig/templates/cpp_source_file.template b/tools/aconfig/aconfig/templates/cpp_source_file.template
index 9be59e0877..36ab774f54 100644
--- a/tools/aconfig/aconfig/templates/cpp_source_file.template
+++ b/tools/aconfig/aconfig/templates/cpp_source_file.template
@@ -1,6 +1,5 @@
 #include "{header}.h"
 
-{{ if allow_instrumentation }}
 {{ if readwrite- }}
 #include <unistd.h>
 #include "aconfig_storage/aconfig_storage_read_api.hpp"
@@ -8,11 +7,7 @@
 #define LOG_TAG "aconfig_cpp_codegen"
 #define ALOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
 {{ -endif }}
-{{ endif }}
 
-{{ if readwrite- }}
-#include <server_configurable_flags/get_flags.h>
-{{ endif }}
 {{ if is_test_mode }}
 #include <unordered_map>
 #include <string>
@@ -29,32 +24,103 @@ namespace {cpp_namespace} \{
     private:
         std::unordered_map<std::string, bool> overrides_;
 
+    {{ if readwrite- }}
+        uint32_t boolean_start_index_;
+
+        std::unique_ptr<aconfig_storage::MappedStorageFile> flag_value_file_;
+
+        bool package_exists_in_storage_;
+    {{ -endif }}
+
     public:
+    {{ if readwrite- }}
+        flag_provider()
+            : overrides_()
+            , boolean_start_index_()
+            , flag_value_file_(nullptr)
+            , package_exists_in_storage_(true) \{
+
+            auto package_map_file = aconfig_storage::get_mapped_file(
+                 "{container}",
+                 aconfig_storage::StorageFileType::package_map);
+
+            if (!package_map_file.ok()) \{
+                ALOGE("error: failed to get package map file: %s", package_map_file.error().c_str());
+                package_exists_in_storage_ = false;
+                return;
+            }
+
+            auto context = aconfig_storage::get_package_read_context(
+                **package_map_file, "{package}");
+
+            if (!context.ok()) \{
+                ALOGE("error: failed to get package read context: %s", context.error().c_str());
+                package_exists_in_storage_ = false;
+                return;
+            }
+
+            if (!(context->package_exists)) \{
+                package_exists_in_storage_ = false;
+                return;
+            }
+
+            // cache package boolean flag start index
+            boolean_start_index_ = context->boolean_start_index;
+
+            // unmap package map file and free memory
+            delete *package_map_file;
+
+            auto flag_value_file = aconfig_storage::get_mapped_file(
+                "{container}",
+                aconfig_storage::StorageFileType::flag_val);
+            if (!flag_value_file.ok()) \{
+                ALOGE("error: failed to get flag value file: %s", flag_value_file.error().c_str());
+                package_exists_in_storage_ = false;
+                return;
+            }
+
+            // cache flag value file
+            flag_value_file_ = std::unique_ptr<aconfig_storage::MappedStorageFile>(
+                *flag_value_file);
+
+        }
+    {{ -else }}
         flag_provider()
             : overrides_()
         \{}
+    {{ -endif }}
 
-{{ for item in class_elements }}
+    {{ for item in class_elements }}
         virtual bool {item.flag_name}() override \{
             auto it = overrides_.find("{item.flag_name}");
-              if (it != overrides_.end()) \{
-                  return it->second;
+            if (it != overrides_.end()) \{
+                return it->second;
             } else \{
-              {{ if item.readwrite- }}
-              return server_configurable_flags::GetServerConfigurableFlag(
-                  "aconfig_flags.{item.device_config_namespace}",
-                  "{item.device_config_flag}",
-                  "{item.default_value}") == "true";
-              {{ -else }}
-                  return {item.default_value};
-              {{ -endif }}
+                {{ if item.readwrite- }}
+                if (!package_exists_in_storage_) \{
+                    return {item.default_value};
+                }
+
+                auto value = aconfig_storage::get_boolean_flag_value(
+                    *flag_value_file_,
+                    boolean_start_index_ + {item.flag_offset});
+
+                if (!value.ok()) \{
+                    ALOGE("error: failed to read flag value: %s", value.error().c_str());
+                    return {item.default_value};
+                } else \{
+                    return *value;
+                }
+                {{ -else }}
+                return {item.default_value};
+                {{ -endif }}
             }
         }
 
         virtual void {item.flag_name}(bool val) override \{
             overrides_["{item.flag_name}"] = val;
         }
-{{ endfor }}
+    {{ endfor }}
 
         virtual void reset_flags() override \{
             overrides_.clear();
@@ -66,15 +132,10 @@ namespace {cpp_namespace} \{
     class flag_provider : public flag_provider_interface \{
     public:
 
-        {{ if allow_instrumentation- }}
         {{ if readwrite- }}
         flag_provider()
-            {{ if readwrite- }}
             : cache_({readwrite_count}, -1)
             , boolean_start_index_()
-            {{ -else- }}
-            : boolean_start_index_()
-            {{ -endif }}
             , flag_value_file_(nullptr)
             , package_exists_in_storage_(true) \{
 
@@ -121,13 +182,11 @@ namespace {cpp_namespace} \{
 
         }
         {{ -endif }}
-        {{ -endif }}
 
         {{ -for item in class_elements }}
         virtual bool {item.flag_name}() override \{
             {{ -if item.readwrite }}
             if (cache_[{item.readwrite_idx}] == -1) \{
-            {{ if allow_instrumentation- }}
                 if (!package_exists_in_storage_) \{
                     return {item.default_value};
                 }
@@ -138,15 +197,10 @@ namespace {cpp_namespace} \{
 
                 if (!value.ok()) \{
                     ALOGE("error: failed to read flag value: %s", value.error().c_str());
+                    return {item.default_value};
                 }
 
                 cache_[{item.readwrite_idx}] = *value;
-            {{ -else- }}
-                cache_[{item.readwrite_idx}] = server_configurable_flags::GetServerConfigurableFlag(
-                    "aconfig_flags.{item.device_config_namespace}",
-                    "{item.device_config_flag}",
-                    "{item.default_value}") == "true";
-            {{ -endif }}
             }
             return cache_[{item.readwrite_idx}];
             {{ -else }}
@@ -162,14 +216,13 @@ namespace {cpp_namespace} \{
     {{ if readwrite- }}
     private:
         std::vector<int8_t> cache_ = std::vector<int8_t>({readwrite_count}, -1);
-    {{ if allow_instrumentation- }}
+
         uint32_t boolean_start_index_;
 
         std::unique_ptr<aconfig_storage::MappedStorageFile> flag_value_file_;
 
         bool package_exists_in_storage_;
     {{ -endif }}
-    {{ -endif }}
 
     };
 
diff --git a/tools/aconfig/aconfig/templates/rust.template b/tools/aconfig/aconfig/templates/rust.template
index e9e1032686..56323e25ca 100644
--- a/tools/aconfig/aconfig/templates/rust.template
+++ b/tools/aconfig/aconfig/templates/rust.template
@@ -9,7 +9,6 @@ use log::\{log, LevelFilter, Level};
 pub struct FlagProvider;
 
 {{ if has_readwrite- }}
-{{ if allow_instrumentation }}
 static PACKAGE_OFFSET: LazyLock<Result<Option<u32>, AconfigStorageError>> = LazyLock::new(|| unsafe \{
     get_mapped_storage_file("{container}", StorageFileType::PackageMap)
     .and_then(|package_map| get_package_read_context(&package_map, "{package}"))
@@ -19,12 +18,10 @@ static PACKAGE_OFFSET: LazyLock<Result<Option<u32>, AconfigStorageError>> = Lazy
 static FLAG_VAL_MAP: LazyLock<Result<Mmap, AconfigStorageError>> = LazyLock::new(|| unsafe \{
     get_mapped_storage_file("{container}", StorageFileType::FlagVal)
 });
-{{ -endif }}
 {{ -for flag in template_flags }}
 
 {{ -if flag.readwrite }}
 /// flag value cache for {flag.name}
-{{ if allow_instrumentation }}
 static CACHED_{flag.name}: LazyLock<bool> = LazyLock::new(|| \{
 
     // This will be called multiple times. Subsequent calls after the first are noops.
@@ -65,12 +62,6 @@ static CACHED_{flag.name}: LazyLock<bool> = LazyLock::new(|| \{
     }
 
 });
-{{ else }}
-static CACHED_{flag.name}: LazyLock<bool> = LazyLock::new(|| flags_rust::GetServerConfigurableFlag(
-    "aconfig_flags.{flag.device_config_namespace}",
-    "{flag.device_config_flag}",
-    "{flag.default_value}") == "true");
-{{ endif }}
 {{ -endif }}
 {{ -endfor }}
 {{ -endif }}
diff --git a/tools/aconfig/aconfig/templates/rust_test.template b/tools/aconfig/aconfig/templates/rust_test.template
index d01f40aab7..139a5ec62a 100644
--- a/tools/aconfig/aconfig/templates/rust_test.template
+++ b/tools/aconfig/aconfig/templates/rust_test.template
@@ -1,23 +1,81 @@
 //! codegenerated rust flag lib
-
+use aconfig_storage_read_api::\{Mmap, AconfigStorageError, StorageFileType, PackageReadContext, get_mapped_storage_file, get_boolean_flag_value, get_package_read_context};
 use std::collections::BTreeMap;
-use std::sync::Mutex;
+use std::path::Path;
+use std::io::Write;
+use std::sync::\{LazyLock, Mutex};
+use log::\{log, LevelFilter, Level};
 
 /// flag provider
 pub struct FlagProvider \{
     overrides: BTreeMap<&'static str, bool>,
 }
 
+{{ if has_readwrite- }}
+static PACKAGE_OFFSET: LazyLock<Result<Option<u32>, AconfigStorageError>> = LazyLock::new(|| unsafe \{
+    get_mapped_storage_file("{container}", StorageFileType::PackageMap)
+    .and_then(|package_map| get_package_read_context(&package_map, "{package}"))
+    .map(|context| context.map(|c| c.boolean_start_index))
+});
+
+static FLAG_VAL_MAP: LazyLock<Result<Mmap, AconfigStorageError>> = LazyLock::new(|| unsafe \{
+    get_mapped_storage_file("{container}", StorageFileType::FlagVal)
+});
+
+{{ -for flag in template_flags }}
+{{ -if flag.readwrite }}
+/// flag value cache for {flag.name}
+static CACHED_{flag.name}: LazyLock<bool> = LazyLock::new(|| \{
+
+    // This will be called multiple times. Subsequent calls after the first are noops.
+    logger::init(
+        logger::Config::default()
+            .with_tag_on_device("aconfig_rust_codegen")
+            .with_max_level(LevelFilter::Info));
+
+    let flag_value_result = FLAG_VAL_MAP
+        .as_ref()
+        .map_err(|err| format!("failed to get flag val map: \{err}"))
+        .and_then(|flag_val_map| \{
+            PACKAGE_OFFSET
+                .as_ref()
+                .map_err(|err| format!("failed to get package read offset: \{err}"))
+                .and_then(|package_offset| \{
+                    match package_offset \{
+                        Some(offset) => \{
+                            get_boolean_flag_value(&flag_val_map, offset + {flag.flag_offset})
+                                .map_err(|err| format!("failed to get flag: \{err}"))
+                        },
+                        None => \{
+                            log!(Level::Error, "no context found for package {package}");
+                            Err(format!("failed to flag package {package}"))
+                        }
+                    }
+                })
+            });
+
+    match flag_value_result \{
+        Ok(flag_value) => \{
+            return flag_value;
+        },
+        Err(err) => \{
+            log!(Level::Error, "aconfig_rust_codegen: error: \{err}");
+            return {flag.default_value};
+        }
+    }
+
+});
+{{ -endif }}
+{{ -endfor }}
+{{ -endif }}
+
 impl FlagProvider \{
 {{ for flag in template_flags }}
     /// query flag {flag.name}
     pub fn {flag.name}(&self) -> bool \{
         self.overrides.get("{flag.name}").copied().unwrap_or(
         {{ if flag.readwrite -}}
-          flags_rust::GetServerConfigurableFlag(
-            "aconfig_flags.{flag.device_config_namespace}",
-            "{flag.device_config_flag}",
-            "{flag.default_value}") == "true"
+           *CACHED_{flag.name}
         {{ -else- }}
            {flag.default_value}
         {{ -endif }}
diff --git a/tools/aconfig/aconfig_device_paths/Android.bp b/tools/aconfig/aconfig_device_paths/Android.bp
index bdf96ed896..3531450e49 100644
--- a/tools/aconfig/aconfig_device_paths/Android.bp
+++ b/tools/aconfig/aconfig_device_paths/Android.bp
@@ -26,7 +26,6 @@ rust_defaults {
         "libaconfig_protos",
         "libanyhow",
         "libprotobuf",
-        "libregex",
     ],
 }
 
@@ -35,6 +34,11 @@ rust_library {
     crate_name: "aconfig_device_paths",
     host_supported: true,
     defaults: ["libaconfig_device_paths.defaults"],
+    apex_available: [
+        "//apex_available:platform",
+        "com.android.configinfrastructure",
+    ],
+    min_sdk_version: "34",
 }
 
 genrule {
@@ -54,7 +58,9 @@ java_library {
     sdk_version: "core_platform",
     apex_available: [
         "//apex_available:platform",
+        "com.android.configinfrastructure",
     ],
+    min_sdk_version: "34",
 }
 
 genrule {
@@ -73,3 +79,23 @@ java_library_host {
     name: "aconfig_host_device_paths_java",
     srcs: [":libaconfig_java_host_device_paths_src"],
 }
+
+genrule {
+    name: "java_device_paths_test_util_src",
+    srcs: ["src/DeviceProtosTestUtilTemplate.java"],
+    out: ["DeviceProtosTestUtil.java"],
+    tool_files: ["partition_aconfig_flags_paths.txt"],
+    cmd: "sed -e '/TEMPLATE/{r$(location partition_aconfig_flags_paths.txt)' -e 'd}' $(in) > $(out)",
+}
+
+java_library {
+    name: "aconfig_device_paths_java_util",
+    srcs: [":java_device_paths_test_util_src"],
+    static_libs: [
+        "libaconfig_java_proto_nano",
+    ],
+    sdk_version: "core_platform",
+    apex_available: [
+        "//apex_available:platform",
+    ],
+}
diff --git a/tools/aconfig/aconfig_device_paths/mainline_aconfig_flags_paths.txt b/tools/aconfig/aconfig_device_paths/mainline_aconfig_flags_paths.txt
index af73a842b9..aad2b23896 100644
--- a/tools/aconfig/aconfig_device_paths/mainline_aconfig_flags_paths.txt
+++ b/tools/aconfig/aconfig_device_paths/mainline_aconfig_flags_paths.txt
@@ -1,7 +1,7 @@
 "/apex/com.android.adservices/etc/aconfig_flags.pb",
 "/apex/com.android.appsearch/etc/aconfig_flags.pb",
 "/apex/com.android.art/etc/aconfig_flags.pb",
-"/apex/com.android.btservices/etc/aconfig_flags.pb",
+"/apex/com.android.bt/etc/aconfig_flags.pb",
 "/apex/com.android.cellbroadcast/etc/aconfig_flags.pb",
 "/apex/com.android.configinfrastructure/etc/aconfig_flags.pb",
 "/apex/com.android.conscrypt/etc/aconfig_flags.pb",
diff --git a/tools/aconfig/aconfig_device_paths/partition_aconfig_flags_paths.txt b/tools/aconfig/aconfig_device_paths/partition_aconfig_flags_paths.txt
index e997e3ddfa..140cd21ac8 100644
--- a/tools/aconfig/aconfig_device_paths/partition_aconfig_flags_paths.txt
+++ b/tools/aconfig/aconfig_device_paths/partition_aconfig_flags_paths.txt
@@ -1,3 +1,4 @@
 "/system/etc/aconfig_flags.pb",
+"/system_ext/etc/aconfig_flags.pb",
 "/product/etc/aconfig_flags.pb",
 "/vendor/etc/aconfig_flags.pb",
diff --git a/tools/aconfig/aconfig_device_paths/src/DeviceProtosTestUtilTemplate.java b/tools/aconfig/aconfig_device_paths/src/DeviceProtosTestUtilTemplate.java
new file mode 100644
index 0000000000..45d67663ef
--- /dev/null
+++ b/tools/aconfig/aconfig_device_paths/src/DeviceProtosTestUtilTemplate.java
@@ -0,0 +1,93 @@
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
+package android.aconfig;
+
+import android.aconfig.nano.Aconfig.parsed_flag;
+import android.aconfig.nano.Aconfig.parsed_flags;
+
+import java.io.File;
+import java.io.FileInputStream;
+import java.io.IOException;
+import java.util.ArrayList;
+import java.util.Arrays;
+import java.util.List;
+
+/** @hide */
+public class DeviceProtosTestUtil {
+    public static final String[] PATHS = {
+        TEMPLATE
+    };
+
+    private static final String APEX_DIR = "/apex/";
+    private static final String APEX_ACONFIG_PATH_SUFFIX = "/etc/aconfig_flags.pb";
+    private static final String SYSTEM_APEX_DIR = "/system/apex";
+
+    /**
+     * Returns a list of all on-device aconfig protos.
+     *
+     * <p>May throw an exception if the protos can't be read at the call site. For example, some of
+     * the protos are in the apex/ partition, which is mounted somewhat late in the boot process.
+     *
+     * @throws IOException if we can't read one of the protos yet
+     * @return a list of all on-device aconfig protos
+     */
+    public static List<parsed_flag> loadAndParseFlagProtos() throws IOException {
+        ArrayList<parsed_flag> result = new ArrayList();
+
+        for (String path : parsedFlagsProtoPaths()) {
+            try (FileInputStream inputStream = new FileInputStream(path)) {
+                parsed_flags parsedFlags = parsed_flags.parseFrom(inputStream.readAllBytes());
+                for (parsed_flag flag : parsedFlags.parsedFlag) {
+                    result.add(flag);
+                }
+            }
+        }
+
+        return result;
+    }
+
+    /**
+     * Returns the list of all on-device aconfig protos paths.
+     *
+     * @hide
+     */
+    public static List<String> parsedFlagsProtoPaths() {
+        ArrayList<String> paths = new ArrayList(Arrays.asList(PATHS));
+
+        File apexDirectory = new File(SYSTEM_APEX_DIR);
+        if (!apexDirectory.isDirectory()) {
+            return paths;
+        }
+
+        File[] subdirs = apexDirectory.listFiles();
+        if (subdirs == null) {
+            return paths;
+        }
+
+        for (File prefix : subdirs) {
+            String apexName = prefix.getName().replace("com.google", "com");
+            apexName = apexName.substring(0, apexName.lastIndexOf('.'));
+
+            File protoPath = new File(APEX_DIR + apexName + APEX_ACONFIG_PATH_SUFFIX);
+            if (!protoPath.exists()) {
+                continue;
+            }
+
+            paths.add(protoPath.getAbsolutePath());
+        }
+        return paths;
+    }
+}
diff --git a/tools/aconfig/aconfig_device_paths/src/lib.rs b/tools/aconfig/aconfig_device_paths/src/lib.rs
index 8871b4f8ac..9ab9cea267 100644
--- a/tools/aconfig/aconfig_device_paths/src/lib.rs
+++ b/tools/aconfig/aconfig_device_paths/src/lib.rs
@@ -62,12 +62,13 @@ mod tests {
 
     #[test]
     fn test_read_partition_paths() {
-        assert_eq!(read_partition_paths().len(), 3);
+        assert_eq!(read_partition_paths().len(), 4);
 
         assert_eq!(
             read_partition_paths(),
             vec![
                 PathBuf::from("/system/etc/aconfig_flags.pb"),
+                PathBuf::from("/system_ext/etc/aconfig_flags.pb"),
                 PathBuf::from("/product/etc/aconfig_flags.pb"),
                 PathBuf::from("/vendor/etc/aconfig_flags.pb")
             ]
diff --git a/tools/aconfig/aconfig_device_paths/test/Android.bp b/tools/aconfig/aconfig_device_paths/test/Android.bp
new file mode 100644
index 0000000000..37f561ff81
--- /dev/null
+++ b/tools/aconfig/aconfig_device_paths/test/Android.bp
@@ -0,0 +1,35 @@
+// Copyright (C) 2024 The Android Open Source Project
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
+    default_team: "trendy_team_android_core_experiments",
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+android_test {
+    name: "aconfig_device_paths_java_test",
+    srcs: [
+        "src/**/*.java",
+    ],
+    static_libs: [
+        "androidx.test.runner",
+        "junit",
+        "aconfig_device_paths_java_util",
+    ],
+    test_suites: [
+        "general-tests",
+    ],
+    platform_apis: true,
+    certificate: "platform",
+}
diff --git a/tools/aconfig/aconfig_device_paths/test/AndroidManifest.xml b/tools/aconfig/aconfig_device_paths/test/AndroidManifest.xml
new file mode 100644
index 0000000000..5e01879157
--- /dev/null
+++ b/tools/aconfig/aconfig_device_paths/test/AndroidManifest.xml
@@ -0,0 +1,27 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2024 The Android Open Source Project
+  ~
+  ~ Licensed under the Apache License, Version 2.0 (the "License");
+  ~ you may not use this file except in compliance with the License.
+  ~ You may obtain a copy of the License at
+  ~
+  ~      http://www.apache.org/licenses/LICENSE-2.0
+  ~
+  ~ Unless required by applicable law or agreed to in writing, software
+  ~ distributed under the License is distributed on an "AS IS" BASIS,
+  ~ WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+  ~ See the License for the specific language governing permissions and
+  ~ limitations under the License.
+  -->
+
+<manifest xmlns:android="http://schemas.android.com/apk/res/android"
+    package="android.aconfig.storage.test">
+    <application>
+        <uses-library android:name="android.test.runner" />
+    </application>
+
+    <instrumentation android:name="androidx.test.runner.AndroidJUnitRunner"
+                     android:targetPackage="android.aconfig.storage.test" />
+
+</manifest>
diff --git a/tools/aconfig/aconfig_device_paths/test/src/DeviceProtosTestUtilTest.java b/tools/aconfig/aconfig_device_paths/test/src/DeviceProtosTestUtilTest.java
new file mode 100644
index 0000000000..8dd0fd0065
--- /dev/null
+++ b/tools/aconfig/aconfig_device_paths/test/src/DeviceProtosTestUtilTest.java
@@ -0,0 +1,52 @@
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
+package android.aconfig.test;
+
+import static org.junit.Assert.assertTrue;
+
+import android.aconfig.DeviceProtosTestUtil;
+import android.aconfig.nano.Aconfig.parsed_flag;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
+import java.util.List;
+import java.util.Set;
+
+@RunWith(JUnit4.class)
+public class DeviceProtosTestUtilTest {
+
+    private static final Set<String> PLATFORM_CONTAINERS = Set.of("system", "vendor", "product");
+
+    @Test
+    public void testDeviceProtos_loadAndParseFlagProtos() throws Exception {
+        List<parsed_flag> flags = DeviceProtosTestUtil.loadAndParseFlagProtos();
+        int platformFlags = 0;
+        int mainlineFlags = 0;
+        for (parsed_flag pf : flags) {
+            if (PLATFORM_CONTAINERS.contains(pf.container)) {
+                platformFlags++;
+            } else {
+                mainlineFlags++;
+            }
+        }
+
+        assertTrue(platformFlags > 3);
+        assertTrue(mainlineFlags > 3);
+    }
+}
diff --git a/tools/aconfig/aconfig_flags/Android.bp b/tools/aconfig/aconfig_flags/Android.bp
index 4c1fd4efcf..1b4e148ce3 100644
--- a/tools/aconfig/aconfig_flags/Android.bp
+++ b/tools/aconfig/aconfig_flags/Android.bp
@@ -24,6 +24,11 @@ rust_library {
         "libaconfig_flags_rust",
     ],
     host_supported: true,
+    apex_available: [
+        "//apex_available:platform",
+        "com.android.configinfrastructure",
+    ],
+    min_sdk_version: "34",
 }
 
 aconfig_declarations {
@@ -38,6 +43,11 @@ rust_aconfig_library {
     crate_name: "aconfig_flags_rust",
     aconfig_declarations: "aconfig_flags",
     host_supported: true,
+    apex_available: [
+        "//apex_available:platform",
+        "com.android.configinfrastructure",
+    ],
+    min_sdk_version: "34",
 }
 
 cc_aconfig_library {
diff --git a/tools/aconfig/aconfig_flags/flags.aconfig b/tools/aconfig/aconfig_flags/flags.aconfig
index 0a004ca4e1..2488b5c8ab 100644
--- a/tools/aconfig/aconfig_flags/flags.aconfig
+++ b/tools/aconfig/aconfig_flags/flags.aconfig
@@ -14,3 +14,30 @@ flag {
   bug: "369808805"
   description: "When enabled, launch aconfigd from config infra module."
 }
+
+flag {
+  name: "tools_read_from_new_storage"
+  namespace: "core_experiments_team_internal"
+  bug: "370499640"
+  description: "When enabled, tools read directly from the new aconfig storage."
+}
+
+flag {
+  name: "tools_read_from_new_storage_bugfix"
+  namespace: "core_experiments_team_internal"
+  bug: "370499640"
+  description: "When enabled, tools read directly from the new aconfig storage."
+  metadata {
+    purpose: PURPOSE_BUGFIX
+  }
+}
+
+flag {
+  name: "invoke_updatable_aflags"
+  namespace: "core_experiments_team_internal"
+  bug: "385383899"
+  description: "When enabled, the system aflags binary invokes the updatable aflags."
+  metadata {
+    purpose: PURPOSE_BUGFIX
+  }
+}
diff --git a/tools/aconfig/aconfig_flags/src/lib.rs b/tools/aconfig/aconfig_flags/src/lib.rs
index 2e891273ed..dc507aef6f 100644
--- a/tools/aconfig/aconfig_flags/src/lib.rs
+++ b/tools/aconfig/aconfig_flags/src/lib.rs
@@ -39,6 +39,11 @@ pub mod auto_generated {
     pub fn enable_aconfigd_from_mainline() -> bool {
         aconfig_flags_rust::enable_only_new_storage()
     }
+
+    /// Returns the value for the invoke_updatable_aflags flag.
+    pub fn invoke_updatable_aflags() -> bool {
+        aconfig_flags_rust::invoke_updatable_aflags()
+    }
 }
 
 /// Module used when building with cargo
@@ -55,4 +60,10 @@ pub mod auto_generated {
         // Used only to enable typechecking and testing with cargo
         true
     }
+
+    /// Returns the value for the invoke_updatable_aflags flag.
+    pub fn invoke_updatable_aflags() -> bool {
+        // Used only to enable typechecking and testing with cargo
+        true
+    }
 }
diff --git a/tools/aconfig/aconfig_protos/Android.bp b/tools/aconfig/aconfig_protos/Android.bp
index d24199443c..080688ebbc 100644
--- a/tools/aconfig/aconfig_protos/Android.bp
+++ b/tools/aconfig/aconfig_protos/Android.bp
@@ -58,6 +58,11 @@ rust_protobuf {
     crate_name: "aconfig_rust_proto",
     source_stem: "aconfig_rust_proto",
     host_supported: true,
+    apex_available: [
+        "//apex_available:platform",
+        "com.android.configinfrastructure",
+    ],
+    min_sdk_version: "34",
 }
 
 rust_defaults {
@@ -81,6 +86,11 @@ rust_library {
     crate_name: "aconfig_protos",
     host_supported: true,
     defaults: ["aconfig_protos.defaults"],
+    apex_available: [
+        "//apex_available:platform",
+        "com.android.configinfrastructure",
+    ],
+    min_sdk_version: "34",
 }
 
 rust_test_host {
@@ -88,3 +98,13 @@ rust_test_host {
     test_suites: ["general-tests"],
     defaults: ["aconfig_protos.defaults"],
 }
+
+// Internal protos
+
+python_library_host {
+    name: "aconfig_internal_proto_python",
+    srcs: ["protos/aconfig_internal.proto"],
+    proto: {
+        canonical_path_from_root: false,
+    },
+}
diff --git a/tools/aconfig/aconfig_protos/protos/aconfig_internal.proto b/tools/aconfig/aconfig_protos/protos/aconfig_internal.proto
new file mode 100644
index 0000000000..7930f568fc
--- /dev/null
+++ b/tools/aconfig/aconfig_protos/protos/aconfig_internal.proto
@@ -0,0 +1,42 @@
+// Copyright (C) 2023 The Android Open Source Project
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
+// limitations under the License
+
+// This is the schema definition for protos intended for internal aconfig
+// use ONLY. There are no guarantees regarding backwards compatibility.
+// Do not put protos here intended for storage or communication.
+
+syntax = "proto2";
+
+package android.aconfig_internal;
+
+
+// This protobuf defines messages used to store data about flags used to guard
+// APIs which are finalized for a given SDK.
+message finalized_flag {
+  // Name of the flag (required). Does not include package name.
+  // Must match flag name in the aconfig declaration header.
+  optional string name = 1;
+
+  // Package the flag belongs to (required).  Must match package in the aconfig declaration header.
+  optional string package = 2;
+
+  // SDK level in which the flag was finalized.
+  optional int32 min_sdk = 3;
+
+  // TODO - b/378936061: Add support for minor SDK version & SDK extension.
+};
+
+message finalized_flags {
+  repeated finalized_flag finalized_flag = 1;
+}
diff --git a/tools/aconfig/aconfig_protos/src/lib.rs b/tools/aconfig/aconfig_protos/src/lib.rs
index 81bbd7e130..64b82d6796 100644
--- a/tools/aconfig/aconfig_protos/src/lib.rs
+++ b/tools/aconfig/aconfig_protos/src/lib.rs
@@ -1073,4 +1073,63 @@ parsed_flag {
         // two identical flags with dedup enabled
         assert_eq!(first, parsed_flags::merge(vec![first.clone(), first.clone()], true).unwrap());
     }
+
+    #[test]
+    fn test_is_valid_name_ident() {
+        assert!(is_valid_name_ident("foo"));
+        assert!(is_valid_name_ident("foo_bar_123"));
+        assert!(is_valid_name_ident("foo_"));
+
+        assert!(!is_valid_name_ident(""));
+        assert!(!is_valid_name_ident("123_foo"));
+        assert!(!is_valid_name_ident("foo-bar"));
+        assert!(!is_valid_name_ident("foo-b\u{00e5}r"));
+        assert!(!is_valid_name_ident("foo__bar"));
+        assert!(!is_valid_name_ident("_foo"));
+    }
+
+    #[test]
+    fn test_is_valid_package_ident() {
+        assert!(is_valid_package_ident("foo.bar"));
+        assert!(is_valid_package_ident("foo.bar_baz"));
+        assert!(is_valid_package_ident("foo.bar.a123"));
+
+        assert!(!is_valid_package_ident("foo_bar_123"));
+        assert!(!is_valid_package_ident("foo"));
+        assert!(!is_valid_package_ident("foo._bar"));
+        assert!(!is_valid_package_ident(""));
+        assert!(!is_valid_package_ident("123_foo"));
+        assert!(!is_valid_package_ident("foo-bar"));
+        assert!(!is_valid_package_ident("foo-b\u{00e5}r"));
+        assert!(!is_valid_package_ident("foo.bar.123"));
+        assert!(!is_valid_package_ident(".foo.bar"));
+        assert!(!is_valid_package_ident("foo.bar."));
+        assert!(!is_valid_package_ident("."));
+        assert!(!is_valid_package_ident(".."));
+        assert!(!is_valid_package_ident("foo..bar"));
+        assert!(!is_valid_package_ident("foo.__bar"));
+    }
+
+    #[test]
+    fn test_is_valid_container_ident() {
+        assert!(is_valid_container_ident("foo.bar"));
+        assert!(is_valid_container_ident("foo.bar_baz"));
+        assert!(is_valid_container_ident("foo.bar.a123"));
+        assert!(is_valid_container_ident("foo"));
+        assert!(is_valid_container_ident("foo_bar_123"));
+
+        assert!(!is_valid_container_ident(""));
+        assert!(!is_valid_container_ident("foo._bar"));
+        assert!(!is_valid_container_ident("_foo"));
+        assert!(!is_valid_container_ident("123_foo"));
+        assert!(!is_valid_container_ident("foo-bar"));
+        assert!(!is_valid_container_ident("foo-b\u{00e5}r"));
+        assert!(!is_valid_container_ident("foo.bar.123"));
+        assert!(!is_valid_container_ident(".foo.bar"));
+        assert!(!is_valid_container_ident("foo.bar."));
+        assert!(!is_valid_container_ident("."));
+        assert!(!is_valid_container_ident(".."));
+        assert!(!is_valid_container_ident("foo..bar"));
+        assert!(!is_valid_container_ident("foo.__bar"));
+    }
 }
diff --git a/tools/aconfig/aconfig_storage_file/src/flag_info.rs b/tools/aconfig/aconfig_storage_file/src/flag_info.rs
index cf16834be2..a39b7edf90 100644
--- a/tools/aconfig/aconfig_storage_file/src/flag_info.rs
+++ b/tools/aconfig/aconfig_storage_file/src/flag_info.rs
@@ -199,49 +199,28 @@ mod tests {
     };
 
     // this test point locks down the value list serialization
-    // TODO: b/376108268 - Use parameterized tests.
     #[test]
-    fn test_serialization_default() {
-        let flag_info_list = create_test_flag_info_list(DEFAULT_FILE_VERSION);
-
-        let header: &FlagInfoHeader = &flag_info_list.header;
-        let reinterpreted_header = FlagInfoHeader::from_bytes(&header.into_bytes());
-        assert!(reinterpreted_header.is_ok());
-        assert_eq!(header, &reinterpreted_header.unwrap());
-
-        let nodes: &Vec<FlagInfoNode> = &flag_info_list.nodes;
-        for node in nodes.iter() {
-            let reinterpreted_node = FlagInfoNode::from_bytes(&node.into_bytes()).unwrap();
-            assert_eq!(node, &reinterpreted_node);
+    fn test_serialization() {
+        for file_version in 1..=MAX_SUPPORTED_FILE_VERSION {
+            let flag_info_list = create_test_flag_info_list(file_version);
+
+            let header: &FlagInfoHeader = &flag_info_list.header;
+            let reinterpreted_header = FlagInfoHeader::from_bytes(&header.into_bytes());
+            assert!(reinterpreted_header.is_ok());
+            assert_eq!(header, &reinterpreted_header.unwrap());
+
+            let nodes: &Vec<FlagInfoNode> = &flag_info_list.nodes;
+            for node in nodes.iter() {
+                let reinterpreted_node = FlagInfoNode::from_bytes(&node.into_bytes()).unwrap();
+                assert_eq!(node, &reinterpreted_node);
+            }
+
+            let flag_info_bytes = flag_info_list.into_bytes();
+            let reinterpreted_info_list = FlagInfoList::from_bytes(&flag_info_bytes);
+            assert!(reinterpreted_info_list.is_ok());
+            assert_eq!(&flag_info_list, &reinterpreted_info_list.unwrap());
+            assert_eq!(flag_info_bytes.len() as u32, header.file_size);
         }
-
-        let flag_info_bytes = flag_info_list.into_bytes();
-        let reinterpreted_info_list = FlagInfoList::from_bytes(&flag_info_bytes);
-        assert!(reinterpreted_info_list.is_ok());
-        assert_eq!(&flag_info_list, &reinterpreted_info_list.unwrap());
-        assert_eq!(flag_info_bytes.len() as u32, header.file_size);
-    }
-
-    #[test]
-    fn test_serialization_max() {
-        let flag_info_list = create_test_flag_info_list(MAX_SUPPORTED_FILE_VERSION);
-
-        let header: &FlagInfoHeader = &flag_info_list.header;
-        let reinterpreted_header = FlagInfoHeader::from_bytes(&header.into_bytes());
-        assert!(reinterpreted_header.is_ok());
-        assert_eq!(header, &reinterpreted_header.unwrap());
-
-        let nodes: &Vec<FlagInfoNode> = &flag_info_list.nodes;
-        for node in nodes.iter() {
-            let reinterpreted_node = FlagInfoNode::from_bytes(&node.into_bytes()).unwrap();
-            assert_eq!(node, &reinterpreted_node);
-        }
-
-        let flag_info_bytes = flag_info_list.into_bytes();
-        let reinterpreted_info_list = FlagInfoList::from_bytes(&flag_info_bytes);
-        assert!(reinterpreted_info_list.is_ok());
-        assert_eq!(&flag_info_list, &reinterpreted_info_list.unwrap());
-        assert_eq!(flag_info_bytes.len() as u32, header.file_size);
     }
 
     // this test point locks down that version number should be at the top of serialized
diff --git a/tools/aconfig/aconfig_storage_file/src/flag_table.rs b/tools/aconfig/aconfig_storage_file/src/flag_table.rs
index 6fbee023ce..1b70c494a6 100644
--- a/tools/aconfig/aconfig_storage_file/src/flag_table.rs
+++ b/tools/aconfig/aconfig_storage_file/src/flag_table.rs
@@ -225,49 +225,28 @@ mod tests {
     };
 
     // this test point locks down the table serialization
-    // TODO: b/376108268 - Use parameterized tests.
     #[test]
-    fn test_serialization_default() {
-        let flag_table = create_test_flag_table(DEFAULT_FILE_VERSION);
-
-        let header: &FlagTableHeader = &flag_table.header;
-        let reinterpreted_header = FlagTableHeader::from_bytes(&header.into_bytes());
-        assert!(reinterpreted_header.is_ok());
-        assert_eq!(header, &reinterpreted_header.unwrap());
-
-        let nodes: &Vec<FlagTableNode> = &flag_table.nodes;
-        for node in nodes.iter() {
-            let reinterpreted_node = FlagTableNode::from_bytes(&node.into_bytes()).unwrap();
-            assert_eq!(node, &reinterpreted_node);
-        }
+    fn test_serialization() {
+        for file_version in 1..=MAX_SUPPORTED_FILE_VERSION {
+            let flag_table = create_test_flag_table(file_version);
 
-        let flag_table_bytes = flag_table.into_bytes();
-        let reinterpreted_table = FlagTable::from_bytes(&flag_table_bytes);
-        assert!(reinterpreted_table.is_ok());
-        assert_eq!(&flag_table, &reinterpreted_table.unwrap());
-        assert_eq!(flag_table_bytes.len() as u32, header.file_size);
-    }
-
-    #[test]
-    fn test_serialization_max() {
-        let flag_table = create_test_flag_table(MAX_SUPPORTED_FILE_VERSION);
+            let header: &FlagTableHeader = &flag_table.header;
+            let reinterpreted_header = FlagTableHeader::from_bytes(&header.into_bytes());
+            assert!(reinterpreted_header.is_ok());
+            assert_eq!(header, &reinterpreted_header.unwrap());
 
-        let header: &FlagTableHeader = &flag_table.header;
-        let reinterpreted_header = FlagTableHeader::from_bytes(&header.into_bytes());
-        assert!(reinterpreted_header.is_ok());
-        assert_eq!(header, &reinterpreted_header.unwrap());
+            let nodes: &Vec<FlagTableNode> = &flag_table.nodes;
+            for node in nodes.iter() {
+                let reinterpreted_node = FlagTableNode::from_bytes(&node.into_bytes()).unwrap();
+                assert_eq!(node, &reinterpreted_node);
+            }
 
-        let nodes: &Vec<FlagTableNode> = &flag_table.nodes;
-        for node in nodes.iter() {
-            let reinterpreted_node = FlagTableNode::from_bytes(&node.into_bytes()).unwrap();
-            assert_eq!(node, &reinterpreted_node);
+            let flag_table_bytes = flag_table.into_bytes();
+            let reinterpreted_table = FlagTable::from_bytes(&flag_table_bytes);
+            assert!(reinterpreted_table.is_ok());
+            assert_eq!(&flag_table, &reinterpreted_table.unwrap());
+            assert_eq!(flag_table_bytes.len() as u32, header.file_size);
         }
-
-        let flag_table_bytes = flag_table.into_bytes();
-        let reinterpreted_table = FlagTable::from_bytes(&flag_table_bytes);
-        assert!(reinterpreted_table.is_ok());
-        assert_eq!(&flag_table, &reinterpreted_table.unwrap());
-        assert_eq!(flag_table_bytes.len() as u32, header.file_size);
     }
 
     // this test point locks down that version number should be at the top of serialized
diff --git a/tools/aconfig/aconfig_storage_file/src/flag_value.rs b/tools/aconfig/aconfig_storage_file/src/flag_value.rs
index 9a14bec7de..d73bcfb262 100644
--- a/tools/aconfig/aconfig_storage_file/src/flag_value.rs
+++ b/tools/aconfig/aconfig_storage_file/src/flag_value.rs
@@ -138,37 +138,21 @@ mod tests {
 
     #[test]
     // this test point locks down the value list serialization
-    // TODO: b/376108268 - Use parameterized tests.
-    fn test_serialization_default() {
-        let flag_value_list = create_test_flag_value_list(DEFAULT_FILE_VERSION);
-
-        let header: &FlagValueHeader = &flag_value_list.header;
-        let reinterpreted_header = FlagValueHeader::from_bytes(&header.into_bytes());
-        assert!(reinterpreted_header.is_ok());
-        assert_eq!(header, &reinterpreted_header.unwrap());
-
-        let flag_value_bytes = flag_value_list.into_bytes();
-        let reinterpreted_value_list = FlagValueList::from_bytes(&flag_value_bytes);
-        assert!(reinterpreted_value_list.is_ok());
-        assert_eq!(&flag_value_list, &reinterpreted_value_list.unwrap());
-        assert_eq!(flag_value_bytes.len() as u32, header.file_size);
-    }
-
-    #[test]
-    // this test point locks down the value list serialization
-    fn test_serialization_max() {
-        let flag_value_list = create_test_flag_value_list(MAX_SUPPORTED_FILE_VERSION);
-
-        let header: &FlagValueHeader = &flag_value_list.header;
-        let reinterpreted_header = FlagValueHeader::from_bytes(&header.into_bytes());
-        assert!(reinterpreted_header.is_ok());
-        assert_eq!(header, &reinterpreted_header.unwrap());
-
-        let flag_value_bytes = flag_value_list.into_bytes();
-        let reinterpreted_value_list = FlagValueList::from_bytes(&flag_value_bytes);
-        assert!(reinterpreted_value_list.is_ok());
-        assert_eq!(&flag_value_list, &reinterpreted_value_list.unwrap());
-        assert_eq!(flag_value_bytes.len() as u32, header.file_size);
+    fn test_serialization() {
+        for file_version in 1..=MAX_SUPPORTED_FILE_VERSION {
+            let flag_value_list = create_test_flag_value_list(file_version);
+
+            let header: &FlagValueHeader = &flag_value_list.header;
+            let reinterpreted_header = FlagValueHeader::from_bytes(&header.into_bytes());
+            assert!(reinterpreted_header.is_ok());
+            assert_eq!(header, &reinterpreted_header.unwrap());
+
+            let flag_value_bytes = flag_value_list.into_bytes();
+            let reinterpreted_value_list = FlagValueList::from_bytes(&flag_value_bytes);
+            assert!(reinterpreted_value_list.is_ok());
+            assert_eq!(&flag_value_list, &reinterpreted_value_list.unwrap());
+            assert_eq!(flag_value_bytes.len() as u32, header.file_size);
+        }
     }
 
     #[test]
diff --git a/tools/aconfig/aconfig_storage_file/src/package_table.rs b/tools/aconfig/aconfig_storage_file/src/package_table.rs
index 21357c7e4a..4d6bd91675 100644
--- a/tools/aconfig/aconfig_storage_file/src/package_table.rs
+++ b/tools/aconfig/aconfig_storage_file/src/package_table.rs
@@ -287,50 +287,28 @@ mod tests {
 
     #[test]
     // this test point locks down the table serialization
-    // TODO: b/376108268 - Use parameterized tests.
-    fn test_serialization_default() {
-        let package_table = create_test_package_table(DEFAULT_FILE_VERSION);
-        let header: &PackageTableHeader = &package_table.header;
-        let reinterpreted_header = PackageTableHeader::from_bytes(&header.into_bytes());
-        assert!(reinterpreted_header.is_ok());
-        assert_eq!(header, &reinterpreted_header.unwrap());
-
-        let nodes: &Vec<PackageTableNode> = &package_table.nodes;
-        for node in nodes.iter() {
-            let reinterpreted_node =
-                PackageTableNode::from_bytes(&node.into_bytes(header.version), header.version)
-                    .unwrap();
-            assert_eq!(node, &reinterpreted_node);
-        }
-
-        let package_table_bytes = package_table.into_bytes();
-        let reinterpreted_table = PackageTable::from_bytes(&package_table_bytes);
-        assert!(reinterpreted_table.is_ok());
-        assert_eq!(&package_table, &reinterpreted_table.unwrap());
-        assert_eq!(package_table_bytes.len() as u32, header.file_size);
-    }
+    fn test_serialization() {
+        for file_version in 1..=MAX_SUPPORTED_FILE_VERSION {
+            let package_table = create_test_package_table(file_version);
+            let header: &PackageTableHeader = &package_table.header;
+            let reinterpreted_header = PackageTableHeader::from_bytes(&header.into_bytes());
+            assert!(reinterpreted_header.is_ok());
+            assert_eq!(header, &reinterpreted_header.unwrap());
+
+            let nodes: &Vec<PackageTableNode> = &package_table.nodes;
+            for node in nodes.iter() {
+                let reinterpreted_node =
+                    PackageTableNode::from_bytes(&node.into_bytes(header.version), header.version)
+                        .unwrap();
+                assert_eq!(node, &reinterpreted_node);
+            }
 
-    #[test]
-    fn test_serialization_max() {
-        let package_table = create_test_package_table(MAX_SUPPORTED_FILE_VERSION);
-        let header: &PackageTableHeader = &package_table.header;
-        let reinterpreted_header = PackageTableHeader::from_bytes(&header.into_bytes());
-        assert!(reinterpreted_header.is_ok());
-        assert_eq!(header, &reinterpreted_header.unwrap());
-
-        let nodes: &Vec<PackageTableNode> = &package_table.nodes;
-        for node in nodes.iter() {
-            let reinterpreted_node =
-                PackageTableNode::from_bytes(&node.into_bytes(header.version), header.version)
-                    .unwrap();
-            assert_eq!(node, &reinterpreted_node);
+            let package_table_bytes = package_table.into_bytes();
+            let reinterpreted_table = PackageTable::from_bytes(&package_table_bytes);
+            assert!(reinterpreted_table.is_ok());
+            assert_eq!(&package_table, &reinterpreted_table.unwrap());
+            assert_eq!(package_table_bytes.len() as u32, header.file_size);
         }
-
-        let package_table_bytes = package_table.into_bytes();
-        let reinterpreted_table = PackageTable::from_bytes(&package_table_bytes);
-        assert!(reinterpreted_table.is_ok());
-        assert_eq!(&package_table, &reinterpreted_table.unwrap());
-        assert_eq!(package_table_bytes.len() as u32, header.file_size);
     }
 
     #[test]
diff --git a/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/ByteBufferReader.java b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/ByteBufferReader.java
index 957156876d..14fc468f11 100644
--- a/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/ByteBufferReader.java
+++ b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/ByteBufferReader.java
@@ -19,10 +19,12 @@ package android.aconfig.storage;
 import java.nio.ByteBuffer;
 import java.nio.ByteOrder;
 import java.nio.charset.StandardCharsets;
+import java.util.Objects;
 
 public class ByteBufferReader {
 
     private ByteBuffer mByteBuffer;
+    private int mPosition;
 
     public ByteBufferReader(ByteBuffer byteBuffer) {
         this.mByteBuffer = byteBuffer;
@@ -30,19 +32,19 @@ public class ByteBufferReader {
     }
 
     public int readByte() {
-        return Byte.toUnsignedInt(mByteBuffer.get());
+        return Byte.toUnsignedInt(mByteBuffer.get(nextGetIndex(1)));
     }
 
     public int readShort() {
-        return Short.toUnsignedInt(mByteBuffer.getShort());
+        return Short.toUnsignedInt(mByteBuffer.getShort(nextGetIndex(2)));
     }
 
     public int readInt() {
-        return this.mByteBuffer.getInt();
+        return this.mByteBuffer.getInt(nextGetIndex(4));
     }
 
     public long readLong() {
-        return this.mByteBuffer.getLong();
+        return this.mByteBuffer.getLong(nextGetIndex(8));
     }
 
     public String readString() {
@@ -52,7 +54,7 @@ public class ByteBufferReader {
                     "String length exceeds maximum allowed size (1024 bytes): " + length);
         }
         byte[] bytes = new byte[length];
-        mByteBuffer.get(bytes, 0, length);
+        getArray(nextGetIndex(length), bytes, 0, length);
         return new String(bytes, StandardCharsets.UTF_8);
     }
 
@@ -61,6 +63,26 @@ public class ByteBufferReader {
     }
 
     public void position(int newPosition) {
-        mByteBuffer.position(newPosition);
+        mPosition = newPosition;
+    }
+
+    public int position() {
+        return mPosition;
+    }
+
+    private int nextGetIndex(int nb) {
+        int p = mPosition;
+        mPosition += nb;
+        return p;
+    }
+
+    private void getArray(int index, byte[] dst, int offset, int length) {
+        Objects.checkFromIndexSize(index, length, mByteBuffer.limit());
+        Objects.checkFromIndexSize(offset, length, dst.length);
+
+        int end = offset + length;
+        for (int i = offset, j = index; i < end; i++, j++) {
+            dst[i] = mByteBuffer.get(j);
+        }
     }
 }
diff --git a/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/FlagTable.java b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/FlagTable.java
index 757844a603..ee60b18dcb 100644
--- a/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/FlagTable.java
+++ b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/FlagTable.java
@@ -24,12 +24,12 @@ import java.util.Objects;
 public class FlagTable {
 
     private Header mHeader;
-    private ByteBufferReader mReader;
+    private ByteBuffer mBuffer;
 
     public static FlagTable fromBytes(ByteBuffer bytes) {
         FlagTable flagTable = new FlagTable();
-        flagTable.mReader = new ByteBufferReader(bytes);
-        flagTable.mHeader = Header.fromBytes(flagTable.mReader);
+        flagTable.mBuffer = bytes;
+        flagTable.mHeader = Header.fromBytes(new ByteBufferReader(bytes));
 
         return flagTable;
     }
@@ -41,16 +41,16 @@ public class FlagTable {
         if (newPosition >= mHeader.mNodeOffset) {
             return null;
         }
-
-        mReader.position(newPosition);
-        int nodeIndex = mReader.readInt();
+        ByteBufferReader reader = new ByteBufferReader(mBuffer) ;
+        reader.position(newPosition);
+        int nodeIndex = reader.readInt();
         if (nodeIndex < mHeader.mNodeOffset || nodeIndex >= mHeader.mFileSize) {
             return null;
         }
 
         while (nodeIndex != -1) {
-            mReader.position(nodeIndex);
-            Node node = Node.fromBytes(mReader);
+            reader.position(nodeIndex);
+            Node node = Node.fromBytes(reader);
             if (Objects.equals(flagName, node.mFlagName) && packageId == node.mPackageId) {
                 return node;
             }
diff --git a/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/PackageTable.java b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/PackageTable.java
index a45d12a0b3..215616e781 100644
--- a/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/PackageTable.java
+++ b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/PackageTable.java
@@ -19,17 +19,23 @@ package android.aconfig.storage;
 import static java.nio.charset.StandardCharsets.UTF_8;
 
 import java.nio.ByteBuffer;
+import java.util.ArrayList;
+import java.util.List;
 import java.util.Objects;
 
 public class PackageTable {
 
+    private static final int FINGERPRINT_BYTES = 8;
+    // int: mPackageId + int: mBooleanStartIndex + int: mNextOffset
+    private static final int NODE_SKIP_BYTES = 12;
+
     private Header mHeader;
-    private ByteBufferReader mReader;
+    private ByteBuffer mBuffer;
 
     public static PackageTable fromBytes(ByteBuffer bytes) {
         PackageTable packageTable = new PackageTable();
-        packageTable.mReader = new ByteBufferReader(bytes);
-        packageTable.mHeader = Header.fromBytes(packageTable.mReader);
+        packageTable.mBuffer = bytes;
+        packageTable.mHeader = Header.fromBytes(new ByteBufferReader(bytes));
 
         return packageTable;
     }
@@ -41,16 +47,17 @@ public class PackageTable {
         if (newPosition >= mHeader.mNodeOffset) {
             return null;
         }
-        mReader.position(newPosition);
-        int nodeIndex = mReader.readInt();
+        ByteBufferReader reader = new ByteBufferReader(mBuffer);
+        reader.position(newPosition);
+        int nodeIndex = reader.readInt();
 
         if (nodeIndex < mHeader.mNodeOffset || nodeIndex >= mHeader.mFileSize) {
             return null;
         }
 
         while (nodeIndex != -1) {
-            mReader.position(nodeIndex);
-            Node node = Node.fromBytes(mReader, mHeader.mVersion);
+            reader.position(nodeIndex);
+            Node node = Node.fromBytes(reader, mHeader.mVersion);
             if (Objects.equals(packageName, node.mPackageName)) {
                 return node;
             }
@@ -60,6 +67,19 @@ public class PackageTable {
         return null;
     }
 
+    public List<String> getPackageList() {
+        List<String> list = new ArrayList<>(mHeader.mNumPackages);
+        ByteBufferReader reader = new ByteBufferReader(mBuffer);
+        reader.position(mHeader.mNodeOffset);
+        int fingerprintBytes = mHeader.mVersion == 1 ? 0 : FINGERPRINT_BYTES;
+        int skipBytes = fingerprintBytes + NODE_SKIP_BYTES;
+        for (int i = 0; i < mHeader.mNumPackages; i++) {
+            list.add(reader.readString());
+            reader.position(reader.position() + skipBytes);
+        }
+        return list;
+    }
+
     public Header getHeader() {
         return mHeader;
     }
diff --git a/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/StorageFileProvider.java b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/StorageFileProvider.java
index f1a4e269a0..f75ac36f7d 100644
--- a/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/StorageFileProvider.java
+++ b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/StorageFileProvider.java
@@ -39,13 +39,15 @@ public class StorageFileProvider {
     private static final String PMAP_FILE_EXT = ".package.map";
     private static final String FMAP_FILE_EXT = ".flag.map";
     private static final String VAL_FILE_EXT = ".val";
+    private static final StorageFileProvider DEFAULT_INSTANCE =
+            new StorageFileProvider(DEFAULT_MAP_PATH, DEFAULT_BOOT_PATH);
 
     private final String mMapPath;
     private final String mBootPath;
 
     /** @hide */
     public static StorageFileProvider getDefaultProvider() {
-        return new StorageFileProvider(DEFAULT_MAP_PATH, DEFAULT_BOOT_PATH);
+        return DEFAULT_INSTANCE;
     }
 
     /** @hide */
@@ -82,7 +84,9 @@ public class StorageFileProvider {
 
     /** @hide */
     public PackageTable getPackageTable(String container) {
-        return getPackageTable(Paths.get(mMapPath, container + PMAP_FILE_EXT));
+        return PackageTable.fromBytes(
+                mapStorageFile(
+                        Paths.get(mMapPath, container + PMAP_FILE_EXT), FileType.PACKAGE_MAP));
     }
 
     /** @hide */
@@ -97,11 +101,6 @@ public class StorageFileProvider {
                 mapStorageFile(Paths.get(mBootPath, container + VAL_FILE_EXT), FileType.FLAG_VAL));
     }
 
-    /** @hide */
-    public static PackageTable getPackageTable(Path path) {
-        return PackageTable.fromBytes(mapStorageFile(path, FileType.PACKAGE_MAP));
-    }
-
     // Map a storage file given file path
     private static MappedByteBuffer mapStorageFile(Path file, FileType type) {
         FileChannel channel = null;
diff --git a/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/TableUtils.java b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/TableUtils.java
index 81168f538e..d4269dac3f 100644
--- a/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/TableUtils.java
+++ b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/TableUtils.java
@@ -63,4 +63,16 @@ public class TableUtils {
         long hashVal = SipHasher13.hash(val);
         return (int) Long.remainderUnsigned(hashVal, numBuckets);
     }
+
+     public static class StorageFilesBundle {
+        public final PackageTable packageTable;
+        public final FlagTable flagTable;
+        public final FlagValueList flagValueList;
+
+        public StorageFilesBundle (PackageTable pTable, FlagTable fTable, FlagValueList fValueList) {
+            this.packageTable = pTable;
+            this.flagTable = fTable;
+            this.flagValueList = fValueList;
+        }
+     }
 }
diff --git a/tools/aconfig/aconfig_storage_file/tests/srcs/FlagTableTest.java b/tools/aconfig/aconfig_storage_file/tests/srcs/FlagTableTest.java
index dc465b658d..213f158617 100644
--- a/tools/aconfig/aconfig_storage_file/tests/srcs/FlagTableTest.java
+++ b/tools/aconfig/aconfig_storage_file/tests/srcs/FlagTableTest.java
@@ -26,6 +26,9 @@ import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.junit.runners.JUnit4;
 
+import java.util.Objects;
+import java.util.concurrent.CyclicBarrier;
+
 @RunWith(JUnit4.class)
 public class FlagTableTest {
 
@@ -100,4 +103,53 @@ public class FlagTableTest {
         assertEquals(-1, node7.getNextOffset());
         assertEquals(-1, node8.getNextOffset());
     }
+
+    @Test
+    public void testFlagTable_multithreadsRead() throws Exception {
+        FlagTable flagTable = FlagTable.fromBytes(TestDataUtils.getTestFlagMapByteBuffer(2));
+
+        int numberOfThreads = 8;
+        Thread[] threads = new Thread[numberOfThreads];
+        final CyclicBarrier gate = new CyclicBarrier(numberOfThreads + 1);
+        String[] expects = {
+            "enabled_ro",
+            "enabled_rw",
+            "enabled_rw",
+            "disabled_rw",
+            "enabled_fixed_ro",
+            "enabled_ro",
+            "enabled_fixed_ro",
+            "disabled_rw"
+        };
+        int[] packageIds = {0, 0, 2, 1, 1, 1, 2, 0};
+
+        for (int i = 0; i < numberOfThreads; i++) {
+            String expectRet = expects[i];
+            int packageId = packageIds[i];
+            threads[i] =
+                    new Thread() {
+                        @Override
+                        public void run() {
+                            try {
+                                gate.await();
+                            } catch (Exception e) {
+                            }
+                            for (int j = 0; j < 10; j++) {
+                                if (!Objects.equals(
+                                        expectRet,
+                                        flagTable.get(packageId, expectRet).getFlagName())) {
+                                    throw new RuntimeException();
+                                }
+                            }
+                        }
+                    };
+            threads[i].start();
+        }
+
+        gate.await();
+
+        for (int i = 0; i < numberOfThreads; i++) {
+            threads[i].join();
+        }
+    }
 }
diff --git a/tools/aconfig/aconfig_storage_file/tests/srcs/FlagValueListTest.java b/tools/aconfig/aconfig_storage_file/tests/srcs/FlagValueListTest.java
index 306df7da5f..6311c1994d 100644
--- a/tools/aconfig/aconfig_storage_file/tests/srcs/FlagValueListTest.java
+++ b/tools/aconfig/aconfig_storage_file/tests/srcs/FlagValueListTest.java
@@ -28,6 +28,9 @@ import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.junit.runners.JUnit4;
 
+import java.util.Objects;
+import java.util.concurrent.CyclicBarrier;
+
 @RunWith(JUnit4.class)
 public class FlagValueListTest {
 
@@ -74,4 +77,43 @@ public class FlagValueListTest {
         fNode = flagTable.get(pNode.getPackageId(), "enabled_fixed_ro");
         assertTrue(flagValueList.getBoolean(pNode.getBooleanStartIndex() + fNode.getFlagIndex()));
     }
+
+    @Test
+    public void testFlagValueList_multithreadsRead() throws Exception {
+        FlagValueList flagValueList =
+                FlagValueList.fromBytes(TestDataUtils.getTestFlagValByteBuffer(2));
+
+        int numberOfThreads = 8;
+        Thread[] threads = new Thread[numberOfThreads];
+        final CyclicBarrier gate = new CyclicBarrier(numberOfThreads + 1);
+        boolean[] expects = {false, true, true, false, true, true, true, true};
+
+        for (int i = 0; i < numberOfThreads; i++) {
+            boolean expectRet = expects[i];
+            int position = i;
+            threads[i] =
+                    new Thread() {
+                        @Override
+                        public void run() {
+                            try {
+                                gate.await();
+                            } catch (Exception e) {
+                            }
+                            for (int j = 0; j < 10; j++) {
+                                if (!Objects.equals(
+                                        expectRet, flagValueList.getBoolean(position))) {
+                                    throw new RuntimeException();
+                                }
+                            }
+                        }
+                    };
+            threads[i].start();
+        }
+
+        gate.await();
+
+        for (int i = 0; i < numberOfThreads; i++) {
+            threads[i].join();
+        }
+    }
 }
diff --git a/tools/aconfig/aconfig_storage_file/tests/srcs/PackageTableTest.java b/tools/aconfig/aconfig_storage_file/tests/srcs/PackageTableTest.java
index 5906d8b469..4b68e5bb92 100644
--- a/tools/aconfig/aconfig_storage_file/tests/srcs/PackageTableTest.java
+++ b/tools/aconfig/aconfig_storage_file/tests/srcs/PackageTableTest.java
@@ -27,6 +27,11 @@ import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.junit.runners.JUnit4;
 
+import java.util.HashSet;
+import java.util.Objects;
+import java.util.Set;
+import java.util.concurrent.CyclicBarrier;
+
 @RunWith(JUnit4.class)
 public class PackageTableTest {
 
@@ -121,4 +126,64 @@ public class PackageTableTest {
         assertEquals(4431940502274857964L, node2.getPackageFingerprint());
         assertEquals(-2213514155997929241L, node4.getPackageFingerprint());
     }
+
+    @Test
+    public void testPackageTable_getPackageList() throws Exception {
+        PackageTable packageTable =
+                PackageTable.fromBytes(TestDataUtils.getTestPackageMapByteBuffer(2));
+        Set<String> packages = new HashSet<>(packageTable.getPackageList());
+        assertEquals(3, packages.size());
+        assertTrue(packages.contains("com.android.aconfig.storage.test_1"));
+        assertTrue(packages.contains("com.android.aconfig.storage.test_2"));
+        assertTrue(packages.contains("com.android.aconfig.storage.test_4"));
+
+        packageTable = PackageTable.fromBytes(TestDataUtils.getTestPackageMapByteBuffer(1));
+        packages = new HashSet<>(packageTable.getPackageList());
+        assertEquals(3, packages.size());
+        assertTrue(packages.contains("com.android.aconfig.storage.test_1"));
+        assertTrue(packages.contains("com.android.aconfig.storage.test_2"));
+        assertTrue(packages.contains("com.android.aconfig.storage.test_4"));
+    }
+
+    @Test
+    public void testPackageTable_multithreadsRead() throws Exception {
+        PackageTable packageTable =
+                PackageTable.fromBytes(TestDataUtils.getTestPackageMapByteBuffer(2));
+        int numberOfThreads = 3;
+        Thread[] threads = new Thread[numberOfThreads];
+        final CyclicBarrier gate = new CyclicBarrier(numberOfThreads + 1);
+        String[] expects = {
+            "com.android.aconfig.storage.test_1",
+            "com.android.aconfig.storage.test_2",
+            "com.android.aconfig.storage.test_4"
+        };
+
+        for (int i = 0; i < numberOfThreads; i++) {
+            final String packageName = expects[i];
+            threads[i] =
+                    new Thread() {
+                        @Override
+                        public void run() {
+                            try {
+                                gate.await();
+                            } catch (Exception e) {
+                            }
+                            for (int j = 0; j < 10; j++) {
+                                if (!Objects.equals(
+                                        packageName,
+                                        packageTable.get(packageName).getPackageName())) {
+                                    throw new RuntimeException();
+                                }
+                            }
+                        }
+                    };
+            threads[i].start();
+        }
+
+        gate.await();
+
+        for (int i = 0; i < numberOfThreads; i++) {
+            threads[i].join();
+        }
+    }
 }
diff --git a/tools/aconfig/aconfig_storage_read_api/Android.bp b/tools/aconfig/aconfig_storage_read_api/Android.bp
index 6214e2ce03..16341b9273 100644
--- a/tools/aconfig/aconfig_storage_read_api/Android.bp
+++ b/tools/aconfig/aconfig_storage_read_api/Android.bp
@@ -154,19 +154,15 @@ java_library {
 java_library {
     name: "aconfig_storage_reader_java",
     srcs: [
-        "srcs/android/aconfig/storage/StorageInternalReader.java",
-        "srcs/android/os/flagging/PlatformAconfigPackageInternal.java",
+        "srcs/android/os/flagging/*.java",
     ],
     libs: [
         "unsupportedappusage",
-        "strict_mode_stub",
-        "aconfig_storage_stub",
     ],
     static_libs: [
         "aconfig_storage_file_java",
     ],
-    sdk_version: "core_current",
-    host_supported: true,
+    sdk_version: "current",
     visibility: [
         "//frameworks/base",
         "//build/make/tools/aconfig/aconfig_storage_read_api/tests",
diff --git a/tools/aconfig/aconfig_storage_read_api/srcs/android/aconfig/storage/StorageInternalReader.java b/tools/aconfig/aconfig_storage_read_api/srcs/android/aconfig/storage/StorageInternalReader.java
deleted file mode 100644
index 6fbcdb354a..0000000000
--- a/tools/aconfig/aconfig_storage_read_api/srcs/android/aconfig/storage/StorageInternalReader.java
+++ /dev/null
@@ -1,94 +0,0 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-package android.aconfig.storage;
-
-import android.compat.annotation.UnsupportedAppUsage;
-import android.os.StrictMode;
-
-import java.io.Closeable;
-import java.nio.MappedByteBuffer;
-import java.nio.channels.FileChannel;
-import java.nio.file.Paths;
-import java.nio.file.StandardOpenOption;
-
-/** @hide */
-public class StorageInternalReader {
-
-    private static final String MAP_PATH = "/metadata/aconfig/maps/";
-    private static final String BOOT_PATH = "/metadata/aconfig/boot/";
-
-    private PackageTable mPackageTable;
-    private FlagValueList mFlagValueList;
-
-    private int mPackageBooleanStartOffset;
-
-    @UnsupportedAppUsage
-    public StorageInternalReader(String container, String packageName) {
-        this(packageName, MAP_PATH + container + ".package.map", BOOT_PATH + container + ".val");
-    }
-
-    @UnsupportedAppUsage
-    public StorageInternalReader(String packageName, String packageMapFile, String flagValueFile) {
-        StrictMode.ThreadPolicy oldPolicy = StrictMode.allowThreadDiskReads();
-        mPackageTable = PackageTable.fromBytes(mapStorageFile(packageMapFile));
-        mFlagValueList = FlagValueList.fromBytes(mapStorageFile(flagValueFile));
-        StrictMode.setThreadPolicy(oldPolicy);
-        mPackageBooleanStartOffset = getPackageBooleanStartOffset(packageName);
-    }
-
-    @UnsupportedAppUsage
-    public boolean getBooleanFlagValue(int index) {
-        index += mPackageBooleanStartOffset;
-        return mFlagValueList.getBoolean(index);
-    }
-
-    private int getPackageBooleanStartOffset(String packageName) {
-        PackageTable.Node pNode = mPackageTable.get(packageName);
-        if (pNode == null) {
-            PackageTable.Header header = mPackageTable.getHeader();
-            throw new AconfigStorageException(
-                    String.format(
-                            "Fail to get package %s from container %s",
-                            packageName, header.getContainer()));
-        }
-        return pNode.getBooleanStartIndex();
-    }
-
-    // Map a storage file given file path
-    private static MappedByteBuffer mapStorageFile(String file) {
-        FileChannel channel = null;
-        try {
-            channel = FileChannel.open(Paths.get(file), StandardOpenOption.READ);
-            return channel.map(FileChannel.MapMode.READ_ONLY, 0, channel.size());
-        } catch (Exception e) {
-            throw new AconfigStorageException(
-                    String.format("Fail to mmap storage file %s", file), e);
-        } finally {
-            quietlyDispose(channel);
-        }
-    }
-
-    private static void quietlyDispose(Closeable closable) {
-        try {
-            if (closable != null) {
-                closable.close();
-            }
-        } catch (Exception e) {
-            // no need to care, at least as of now
-        }
-    }
-}
diff --git a/tools/aconfig/aconfig_storage_read_api/srcs/android/os/flagging/PlatformAconfigPackage.java b/tools/aconfig/aconfig_storage_read_api/srcs/android/os/flagging/PlatformAconfigPackage.java
new file mode 100644
index 0000000000..3dd24b211a
--- /dev/null
+++ b/tools/aconfig/aconfig_storage_read_api/srcs/android/os/flagging/PlatformAconfigPackage.java
@@ -0,0 +1,178 @@
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
+package android.os.flagging;
+
+import static android.aconfig.storage.TableUtils.StorageFilesBundle;
+
+import android.aconfig.storage.AconfigStorageException;
+import android.aconfig.storage.FlagTable;
+import android.aconfig.storage.FlagValueList;
+import android.aconfig.storage.PackageTable;
+import android.compat.annotation.UnsupportedAppUsage;
+import android.util.Log;
+
+import java.io.Closeable;
+import java.nio.MappedByteBuffer;
+import java.nio.channels.FileChannel;
+import java.nio.file.Paths;
+import java.nio.file.StandardOpenOption;
+import java.util.HashMap;
+import java.util.Map;
+import java.util.Set;
+
+/**
+ * An {@code aconfig} package containing the enabled state of its flags.
+ *
+ * <p><strong>Note: this is intended only to be used by generated code. To determine if a given flag
+ * is enabled in app code, the generated android flags should be used.</strong>
+ *
+ * <p>This class is used to read the flag from platform Aconfig Package.Each instance of this class
+ * will cache information related to one package. To read flags from a different package, a new
+ * instance of this class should be {@link #load loaded}.
+ *
+ * @hide
+ */
+public class PlatformAconfigPackage {
+    private static final String TAG = "PlatformAconfigPackage";
+    private static final String MAP_PATH = "/metadata/aconfig/maps/";
+    private static final String BOOT_PATH = "/metadata/aconfig/boot/";
+
+    private FlagTable mFlagTable;
+    private FlagValueList mFlagValueList;
+
+    private int mPackageBooleanStartOffset = -1;
+    private int mPackageId = -1;
+
+    private PlatformAconfigPackage() {}
+
+    /** @hide */
+    static final Map<String, StorageFilesBundle> sStorageFilesCache = new HashMap<>();
+
+    /** @hide */
+    @UnsupportedAppUsage
+    public static final Set<String> PLATFORM_PACKAGE_MAP_FILES =
+            Set.of(
+                    "system.package.map",
+                    "system_ext.package.map",
+                    "vendor.package.map",
+                    "product.package.map");
+
+    static {
+        for (String pf : PLATFORM_PACKAGE_MAP_FILES) {
+            try {
+                PackageTable pTable = PackageTable.fromBytes(mapStorageFile(MAP_PATH + pf));
+                String container = pTable.getHeader().getContainer();
+                FlagTable fTable =
+                        FlagTable.fromBytes(mapStorageFile(MAP_PATH + container + ".flag.map"));
+                FlagValueList fValueList =
+                        FlagValueList.fromBytes(mapStorageFile(BOOT_PATH + container + ".val"));
+                StorageFilesBundle files = new StorageFilesBundle(pTable, fTable, fValueList);
+                for (String packageName : pTable.getPackageList()) {
+                    sStorageFilesCache.put(packageName, files);
+                }
+            } catch (Exception e) {
+                // pass
+                Log.w(TAG, e.toString());
+            }
+        }
+    }
+
+    /**
+     * Loads a platform Aconfig Package from Aconfig Storage.
+     *
+     * <p>This method attempts to load the specified platform Aconfig package.
+     *
+     * @param packageName The name of the Aconfig package to load.
+     * @return An instance of {@link PlatformAconfigPackage}, which may be empty if the package is
+     *     not found in the container. Null if the package is not found in platform partitions.
+     * @throws AconfigStorageReadException if there is an error reading from Aconfig Storage, such
+     *     as if the storage system is not found, or there is an error reading the storage file. The
+     *     specific error code can be got using {@link AconfigStorageReadException#getErrorCode()}.
+     * @hide
+     */
+    @UnsupportedAppUsage
+    public static PlatformAconfigPackage load(String packageName) {
+        try {
+            PlatformAconfigPackage aconfigPackage = new PlatformAconfigPackage();
+            StorageFilesBundle files = sStorageFilesCache.get(packageName);
+            if (files == null) {
+                return null;
+            }
+            PackageTable.Node pNode = files.packageTable.get(packageName);
+            aconfigPackage.mFlagTable = files.flagTable;
+            aconfigPackage.mFlagValueList = files.flagValueList;
+            aconfigPackage.mPackageBooleanStartOffset = pNode.getBooleanStartIndex();
+            aconfigPackage.mPackageId = pNode.getPackageId();
+            return aconfigPackage;
+        } catch (AconfigStorageException e) {
+            throw new AconfigStorageReadException(
+                    e.getErrorCode(), "Fail to create PlatformAconfigPackage: " + packageName, e);
+        } catch (Exception e) {
+            throw new AconfigStorageReadException(
+                    AconfigStorageReadException.ERROR_GENERIC,
+                    "Fail to create PlatformAconfigPackage: " + packageName,
+                    e);
+        }
+    }
+
+    /**
+     * Retrieves the value of a boolean flag.
+     *
+     * <p>This method retrieves the value of the specified flag. If the flag exists within the
+     * loaded Aconfig Package, its value is returned. Otherwise, the provided `defaultValue` is
+     * returned.
+     *
+     * @param flagName The name of the flag (excluding any package name prefix).
+     * @param defaultValue The value to return if the flag is not found.
+     * @return The boolean value of the flag, or `defaultValue` if the flag is not found.
+     * @hide
+     */
+    @UnsupportedAppUsage
+    public boolean getBooleanFlagValue(String flagName, boolean defaultValue) {
+        FlagTable.Node fNode = mFlagTable.get(mPackageId, flagName);
+        if (fNode == null) {
+            return defaultValue;
+        }
+        return mFlagValueList.getBoolean(fNode.getFlagIndex() + mPackageBooleanStartOffset);
+    }
+
+    // Map a storage file given file path
+    private static MappedByteBuffer mapStorageFile(String file) {
+        FileChannel channel = null;
+        try {
+            channel = FileChannel.open(Paths.get(file), StandardOpenOption.READ);
+            return channel.map(FileChannel.MapMode.READ_ONLY, 0, channel.size());
+        } catch (Exception e) {
+            throw new AconfigStorageReadException(
+                    AconfigStorageReadException.ERROR_CANNOT_READ_STORAGE_FILE,
+                    "Fail to mmap storage",
+                    e);
+        } finally {
+            quietlyDispose(channel);
+        }
+    }
+
+    private static void quietlyDispose(Closeable closable) {
+        try {
+            if (closable != null) {
+                closable.close();
+            }
+        } catch (Exception e) {
+            // no need to care, at least as of now
+        }
+    }
+}
diff --git a/tools/aconfig/aconfig_storage_read_api/srcs/android/os/flagging/PlatformAconfigPackageInternal.java b/tools/aconfig/aconfig_storage_read_api/srcs/android/os/flagging/PlatformAconfigPackageInternal.java
index d73d9eb3ae..da18fb9fe0 100644
--- a/tools/aconfig/aconfig_storage_read_api/srcs/android/os/flagging/PlatformAconfigPackageInternal.java
+++ b/tools/aconfig/aconfig_storage_read_api/srcs/android/os/flagging/PlatformAconfigPackageInternal.java
@@ -16,12 +16,12 @@
 
 package android.os.flagging;
 
+import static android.aconfig.storage.TableUtils.StorageFilesBundle;
+
 import android.aconfig.storage.AconfigStorageException;
 import android.aconfig.storage.FlagValueList;
 import android.aconfig.storage.PackageTable;
-import android.aconfig.storage.StorageFileProvider;
 import android.compat.annotation.UnsupportedAppUsage;
-import android.os.StrictMode;
 
 /**
  * An {@code aconfig} package containing the enabled state of its flags.
@@ -55,7 +55,6 @@ public class PlatformAconfigPackageInternal {
      * <p>This method is intended for internal use only and may be changed or removed without
      * notice.
      *
-     * @param container The name of the container.
      * @param packageName The name of the Aconfig package.
      * @param packageFingerprint The expected fingerprint of the package.
      * @return An instance of {@link PlatformAconfigPackageInternal} representing the loaded
@@ -63,53 +62,20 @@ public class PlatformAconfigPackageInternal {
      * @hide
      */
     @UnsupportedAppUsage
-    public static PlatformAconfigPackageInternal load(
-            String container, String packageName, long packageFingerprint) {
-        return load(
-                container,
-                packageName,
-                packageFingerprint,
-                StorageFileProvider.getDefaultProvider());
-    }
-
-    /** @hide */
-    public static PlatformAconfigPackageInternal load(
-            String container,
-            String packageName,
-            long packageFingerprint,
-            StorageFileProvider fileProvider) {
-        StrictMode.ThreadPolicy oldPolicy = StrictMode.allowThreadDiskReads();
-        PackageTable.Node pNode = null;
-        FlagValueList vList = null;
-        try {
-            pNode = fileProvider.getPackageTable(container).get(packageName);
-            vList = fileProvider.getFlagValueList(container);
-        } catch (AconfigStorageException e) {
-            throw new AconfigStorageReadException(e.getErrorCode(), e.toString());
-        } finally {
-            StrictMode.setThreadPolicy(oldPolicy);
-        }
-
-        if (pNode == null || vList == null) {
-            throw new AconfigStorageReadException(
-                    AconfigStorageReadException.ERROR_PACKAGE_NOT_FOUND,
-                    String.format(
-                            "package "
-                                    + packageName
-                                    + " in container "
-                                    + container
-                                    + " cannot be found on the device"));
+    public static PlatformAconfigPackageInternal load(String packageName, long packageFingerprint) {
+        StorageFilesBundle files = PlatformAconfigPackage.sStorageFilesCache.get(packageName);
+        if (files == null) {
+            throw new AconfigStorageException(
+                    AconfigStorageException.ERROR_PACKAGE_NOT_FOUND,
+                    "package " + packageName + " cannot be found on the device");
         }
+        PackageTable.Node pNode = files.packageTable.get(packageName);
+        FlagValueList vList = files.flagValueList;
 
         if (pNode.hasPackageFingerprint() && packageFingerprint != pNode.getPackageFingerprint()) {
-            throw new AconfigStorageReadException(
-                    5, // AconfigStorageReadException.ERROR_FILE_FINGERPRINT_MISMATCH,
-                    String.format(
-                            "package "
-                                    + packageName
-                                    + " in container "
-                                    + container
-                                    + " cannot be found on the device"));
+            throw new AconfigStorageException(
+                    AconfigStorageException.ERROR_FILE_FINGERPRINT_MISMATCH,
+                    "package " + packageName + "fingerprint doesn't match the one on device");
         }
 
         return new PlatformAconfigPackageInternal(vList, pNode.getBooleanStartIndex());
diff --git a/tools/aconfig/aconfig_storage_read_api/tests/AconfigStorageReadUnitTest.xml b/tools/aconfig/aconfig_storage_read_api/tests/AconfigStorageReadUnitTest.xml
deleted file mode 100644
index e528dd54f9..0000000000
--- a/tools/aconfig/aconfig_storage_read_api/tests/AconfigStorageReadUnitTest.xml
+++ /dev/null
@@ -1,34 +0,0 @@
-<?xml version="1.0" encoding="utf-8"?>
-<!--
-  ~ Copyright (C) 2024 The Android Open Source Project
-  ~
-  ~ Licensed under the Apache License, Version 2.0 (the "License");
-  ~ you may not use this file except in compliance with the License.
-  ~ You may obtain a copy of the License at
-  ~
-  ~      http://www.apache.org/licenses/LICENSE-2.0
-  ~
-  ~ Unless required by applicable law or agreed to in writing, software
-  ~ distributed under the License is distributed on an "AS IS" BASIS,
-  ~ WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-  ~ See the License for the specific language governing permissions and
-  ~ limitations under the License.
-  -->
-<configuration description="Test aconfig storage java tests">
-    <target_preparer class="com.android.tradefed.targetprep.suite.SuiteApkInstaller">
-        <option name="cleanup-apks" value="true" />
-        <option name="test-file-name" value="aconfig_storage_read_unit.apk" />
-    </target_preparer>
-    <target_preparer class="com.android.compatibility.common.tradefed.targetprep.FilePusher">
-        <option name="cleanup" value="true" />
-        <option name="push" value="package_v2.map->/data/local/tmp/aconfig_storage_read_unit/testdata/mockup.package.map" />
-        <option name="push" value="flag_v2.map->/data/local/tmp/aconfig_storage_read_unit/testdata/mockup.flag.map" />
-        <option name="push" value="flag_v2.val->/data/local/tmp/aconfig_storage_read_unit/testdata/mockup.val" />
-        <option name="push" value="flag_v2.info->/data/local/tmp/aconfig_storage_read_unit/testdata/mockup.info" />
-        <option name="post-push" value="chmod +r /data/local/tmp/aconfig_storage_read_unit/testdata/" />
-    </target_preparer>
-    <test class="com.android.tradefed.testtype.AndroidJUnitTest" >
-        <option name="package" value="android.aconfig.storage.test" />
-        <option name="runtime-hint" value="1m" />
-    </test>
-</configuration>
diff --git a/tools/aconfig/aconfig_storage_read_api/tests/Android.bp b/tools/aconfig/aconfig_storage_read_api/tests/Android.bp
index 702325da5d..c071f7cd88 100644
--- a/tools/aconfig/aconfig_storage_read_api/tests/Android.bp
+++ b/tools/aconfig/aconfig_storage_read_api/tests/Android.bp
@@ -55,7 +55,7 @@ android_test {
         "functional/srcs/**/*.java",
     ],
     static_libs: [
-        "aconfig_device_paths_java",
+        "aconfig_device_paths_java_util",
         "aconfig_storage_file_java",
         "androidx.test.rules",
         "libaconfig_storage_read_api_java",
@@ -75,25 +75,3 @@ android_test {
     test_config: "AconfigStorageReadFunctionalTest.xml",
     team: "trendy_team_android_core_experiments",
 }
-
-android_test {
-    name: "aconfig_storage_read_unit",
-    team: "trendy_team_android_core_experiments",
-    srcs: [
-        "unit/srcs/**/*.java",
-    ],
-    static_libs: [
-        "androidx.test.runner",
-        "junit",
-        "aconfig_storage_reader_java",
-    ],
-    sdk_version: "test_current",
-    data: [
-        ":read_api_test_storage_files",
-    ],
-    test_suites: [
-        "general-tests",
-    ],
-    test_config: "AconfigStorageReadUnitTest.xml",
-    jarjar_rules: "jarjar.txt",
-}
diff --git a/tools/aconfig/aconfig_storage_read_api/tests/functional/srcs/AconfigStorageReadAPITest.java b/tools/aconfig/aconfig_storage_read_api/tests/functional/srcs/AconfigStorageReadAPITest.java
index 6dd1bce94e..0587e9d4c5 100644
--- a/tools/aconfig/aconfig_storage_read_api/tests/functional/srcs/AconfigStorageReadAPITest.java
+++ b/tools/aconfig/aconfig_storage_read_api/tests/functional/srcs/AconfigStorageReadAPITest.java
@@ -19,14 +19,13 @@ package android.aconfig.storage.test;
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertTrue;
 
-import android.aconfig.DeviceProtos;
+import android.aconfig.DeviceProtosTestUtil;
 import android.aconfig.nano.Aconfig.parsed_flag;
 import android.aconfig.storage.AconfigStorageReadAPI;
 import android.aconfig.storage.FlagReadContext;
 import android.aconfig.storage.FlagReadContext.StoredFlagType;
 import android.aconfig.storage.PackageReadContext;
 import android.aconfig.storage.SipHasher13;
-import android.aconfig.storage.StorageInternalReader;
 
 import org.junit.Test;
 import org.junit.runner.RunWith;
@@ -211,7 +210,7 @@ public class AconfigStorageReadAPITest {
 
     @Test
     public void testRustJavaEqualHash() throws IOException {
-        List<parsed_flag> flags = DeviceProtos.loadAndParseFlagProtos();
+        List<parsed_flag> flags = DeviceProtosTestUtil.loadAndParseFlagProtos();
         for (parsed_flag flag : flags) {
             String packageName = flag.package_;
             String flagName = flag.name;
@@ -225,46 +224,4 @@ public class AconfigStorageReadAPITest {
             assertEquals(rHash, jHash);
         }
     }
-
-    @Test
-    public void testRustJavaEqualFlag() throws IOException {
-        List<parsed_flag> flags = DeviceProtos.loadAndParseFlagProtos();
-
-        String mapPath = "/metadata/aconfig/maps/";
-        String flagsPath = "/metadata/aconfig/boot/";
-
-        for (parsed_flag flag : flags) {
-
-            String container = flag.container;
-            String packageName = flag.package_;
-            String flagName = flag.name;
-            String fullFlagName = packageName + "/" + flagName;
-
-            MappedByteBuffer packageMap =
-                    AconfigStorageReadAPI.mapStorageFile(mapPath + container + ".package.map");
-            MappedByteBuffer flagMap =
-                    AconfigStorageReadAPI.mapStorageFile(mapPath + container + ".flag.map");
-            MappedByteBuffer flagValList =
-                    AconfigStorageReadAPI.mapStorageFile(flagsPath + container + ".val");
-
-            PackageReadContext packageContext =
-                    AconfigStorageReadAPI.getPackageReadContext(packageMap, packageName);
-
-            FlagReadContext flagContext =
-                    AconfigStorageReadAPI.getFlagReadContext(
-                            flagMap, packageContext.mPackageId, flagName);
-
-            boolean rVal =
-                    AconfigStorageReadAPI.getBooleanFlagValue(
-                            flagValList,
-                            packageContext.mBooleanStartIndex + flagContext.mFlagIndex);
-
-            StorageInternalReader reader = new StorageInternalReader(container, packageName);
-            boolean jVal = reader.getBooleanFlagValue(flagContext.mFlagIndex);
-
-            long rHash = AconfigStorageReadAPI.hash(packageName);
-            long jHash = SipHasher13.hash(packageName.getBytes());
-            assertEquals(rVal, jVal);
-        }
-    }
-}
\ No newline at end of file
+}
diff --git a/tools/aconfig/aconfig_storage_read_api/tests/functional/srcs/PlatformAconfigPackageInternalTest.java b/tools/aconfig/aconfig_storage_read_api/tests/functional/srcs/PlatformAconfigPackageInternalTest.java
index 69e224b5a6..0c5bc1c2c7 100644
--- a/tools/aconfig/aconfig_storage_read_api/tests/functional/srcs/PlatformAconfigPackageInternalTest.java
+++ b/tools/aconfig/aconfig_storage_read_api/tests/functional/srcs/PlatformAconfigPackageInternalTest.java
@@ -19,14 +19,14 @@ package android.aconfig.storage.test;
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertThrows;
 
-import android.aconfig.DeviceProtos;
+import android.aconfig.DeviceProtosTestUtil;
 import android.aconfig.nano.Aconfig;
 import android.aconfig.nano.Aconfig.parsed_flag;
 import android.aconfig.storage.FlagTable;
 import android.aconfig.storage.FlagValueList;
 import android.aconfig.storage.PackageTable;
 import android.aconfig.storage.StorageFileProvider;
-import android.os.flagging.AconfigStorageReadException;
+import android.internal.aconfig.storage.AconfigStorageException;
 import android.os.flagging.PlatformAconfigPackageInternal;
 
 import org.junit.Test;
@@ -42,11 +42,12 @@ import java.util.Set;
 @RunWith(JUnit4.class)
 public class PlatformAconfigPackageInternalTest {
 
-    private static final Set<String> PLATFORM_CONTAINERS = Set.of("system", "vendor", "product");
+    private static final Set<String> PLATFORM_CONTAINERS =
+            Set.of("system", "system_ext", "vendor", "product");
 
     @Test
-    public void testAconfigPackageInternal_load() throws IOException {
-        List<parsed_flag> flags = DeviceProtos.loadAndParseFlagProtos();
+    public void testPlatformAconfigPackageInternal_load() throws IOException {
+        List<parsed_flag> flags = DeviceProtosTestUtil.loadAndParseFlagProtos();
         Map<String, PlatformAconfigPackageInternal> readerMap = new HashMap<>();
         StorageFileProvider fp = StorageFileProvider.getDefaultProvider();
 
@@ -72,7 +73,7 @@ public class PlatformAconfigPackageInternalTest {
 
             PlatformAconfigPackageInternal reader = readerMap.get(packageName);
             if (reader == null) {
-                reader = PlatformAconfigPackageInternal.load(container, packageName, fingerprint);
+                reader = PlatformAconfigPackageInternal.load(packageName, fingerprint);
                 readerMap.put(packageName, reader);
             }
             boolean jVal = reader.getBooleanFlagValue(fNode.getFlagIndex());
@@ -82,25 +83,16 @@ public class PlatformAconfigPackageInternalTest {
     }
 
     @Test
-    public void testAconfigPackage_load_withError() throws IOException {
-        // container not found fake_container
-        AconfigStorageReadException e =
-                assertThrows(
-                        AconfigStorageReadException.class,
-                        () ->
-                                PlatformAconfigPackageInternal.load(
-                                        "fake_container", "fake_package", 0));
-        assertEquals(AconfigStorageReadException.ERROR_CANNOT_READ_STORAGE_FILE, e.getErrorCode());
-
+    public void testPlatformAconfigPackage_load_withError() throws IOException {
         // package not found
-        e =
+        AconfigStorageException e =
                 assertThrows(
-                        AconfigStorageReadException.class,
-                        () -> PlatformAconfigPackageInternal.load("system", "fake_container", 0));
-        assertEquals(AconfigStorageReadException.ERROR_PACKAGE_NOT_FOUND, e.getErrorCode());
+                        AconfigStorageException.class,
+                        () -> PlatformAconfigPackageInternal.load("fake_package", 0));
+        assertEquals(AconfigStorageException.ERROR_PACKAGE_NOT_FOUND, e.getErrorCode());
 
         // fingerprint doesn't match
-        List<parsed_flag> flags = DeviceProtos.loadAndParseFlagProtos();
+        List<parsed_flag> flags = DeviceProtosTestUtil.loadAndParseFlagProtos();
         StorageFileProvider fp = StorageFileProvider.getDefaultProvider();
 
         parsed_flag flag = flags.get(0);
@@ -116,13 +108,11 @@ public class PlatformAconfigPackageInternalTest {
             long fingerprint = pNode.getPackageFingerprint();
             e =
                     assertThrows(
-                            AconfigStorageReadException.class,
+                            AconfigStorageException.class,
                             () ->
                                     PlatformAconfigPackageInternal.load(
-                                            container, packageName, fingerprint + 1));
-            assertEquals(
-                    // AconfigStorageException.ERROR_FILE_FINGERPRINT_MISMATCH,
-                    5, e.getErrorCode());
+                                            packageName, fingerprint + 1));
+            assertEquals(AconfigStorageException.ERROR_FILE_FINGERPRINT_MISMATCH, e.getErrorCode());
         }
     }
 }
diff --git a/tools/aconfig/aconfig_storage_read_api/tests/functional/srcs/PlatformAconfigPackageTest.java b/tools/aconfig/aconfig_storage_read_api/tests/functional/srcs/PlatformAconfigPackageTest.java
new file mode 100644
index 0000000000..2b4ead8777
--- /dev/null
+++ b/tools/aconfig/aconfig_storage_read_api/tests/functional/srcs/PlatformAconfigPackageTest.java
@@ -0,0 +1,104 @@
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
+package android.aconfig.storage.test;
+
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertNotNull;
+import static org.junit.Assert.assertNull;
+
+import android.aconfig.DeviceProtosTestUtil;
+import android.aconfig.nano.Aconfig;
+import android.aconfig.nano.Aconfig.parsed_flag;
+import android.aconfig.storage.FlagTable;
+import android.aconfig.storage.FlagValueList;
+import android.aconfig.storage.PackageTable;
+import android.aconfig.storage.StorageFileProvider;
+import android.os.flagging.PlatformAconfigPackage;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
+import java.io.IOException;
+import java.util.HashMap;
+import java.util.List;
+import java.util.Map;
+import java.util.Set;
+
+@RunWith(JUnit4.class)
+public class PlatformAconfigPackageTest {
+
+    private static final Set<String> PLATFORM_CONTAINERS =
+            Set.of("system", "system_ext", "vendor", "product");
+
+    @Test
+    public void testPlatformAconfigPackage_StorageFilesCache() throws IOException {
+        List<parsed_flag> flags = DeviceProtosTestUtil.loadAndParseFlagProtos();
+        for (parsed_flag flag : flags) {
+            if (flag.permission == Aconfig.READ_ONLY && flag.state == Aconfig.DISABLED) {
+                continue;
+            }
+            String container = flag.container;
+            String packageName = flag.package_;
+            if (!PLATFORM_CONTAINERS.contains(container)) continue;
+            assertNotNull(PlatformAconfigPackage.load(packageName));
+        }
+    }
+
+    @Test
+    public void testPlatformAconfigPackage_load() throws IOException {
+        List<parsed_flag> flags = DeviceProtosTestUtil.loadAndParseFlagProtos();
+        Map<String, PlatformAconfigPackage> readerMap = new HashMap<>();
+        StorageFileProvider fp = StorageFileProvider.getDefaultProvider();
+
+        for (parsed_flag flag : flags) {
+            if (flag.permission == Aconfig.READ_ONLY && flag.state == Aconfig.DISABLED) {
+                continue;
+            }
+            String container = flag.container;
+            String packageName = flag.package_;
+            String flagName = flag.name;
+            if (!PLATFORM_CONTAINERS.contains(container)) continue;
+
+            PackageTable pTable = fp.getPackageTable(container);
+            PackageTable.Node pNode = pTable.get(packageName);
+            FlagTable fTable = fp.getFlagTable(container);
+            FlagTable.Node fNode = fTable.get(pNode.getPackageId(), flagName);
+            FlagValueList fList = fp.getFlagValueList(container);
+
+            int index = pNode.getBooleanStartIndex() + fNode.getFlagIndex();
+            boolean rVal = fList.getBoolean(index);
+
+            long fingerprint = pNode.getPackageFingerprint();
+
+            PlatformAconfigPackage reader = readerMap.get(packageName);
+            if (reader == null) {
+                reader = PlatformAconfigPackage.load(packageName);
+                readerMap.put(packageName, reader);
+            }
+            boolean jVal = reader.getBooleanFlagValue(flagName, !rVal);
+
+            assertEquals(rVal, jVal);
+        }
+    }
+
+    @Test
+    public void testPlatformAconfigPackage_load_withError() throws IOException {
+        // package not found
+        assertNull(PlatformAconfigPackage.load("fake_container"));
+    }
+}
diff --git a/tools/aconfig/aconfig_storage_read_api/tests/functional/srcs/StorageInternalReaderTest.java b/tools/aconfig/aconfig_storage_read_api/tests/functional/srcs/StorageInternalReaderTest.java
deleted file mode 100644
index 8a8f054d63..0000000000
--- a/tools/aconfig/aconfig_storage_read_api/tests/functional/srcs/StorageInternalReaderTest.java
+++ /dev/null
@@ -1,45 +0,0 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-package android.aconfig.storage.test;
-
-import static org.junit.Assert.assertFalse;
-import static org.junit.Assert.assertTrue;
-
-import android.aconfig.storage.StorageInternalReader;
-
-import org.junit.Test;
-import org.junit.runner.RunWith;
-import org.junit.runners.JUnit4;
-
-@RunWith(JUnit4.class)
-public class StorageInternalReaderTest {
-
-    private String mStorageDir = "/data/local/tmp/aconfig_java_api_test";
-
-    @Test
-    public void testStorageInternalReader_getFlag() {
-
-        String packageMapFile = mStorageDir + "/maps/mockup.package.map";
-        String flagValueFile = mStorageDir + "/boot/mockup.val";
-
-        StorageInternalReader reader =
-                new StorageInternalReader(
-                        "com.android.aconfig.storage.test_1", packageMapFile, flagValueFile);
-        assertFalse(reader.getBooleanFlagValue(0));
-        assertTrue(reader.getBooleanFlagValue(1));
-    }
-}
\ No newline at end of file
diff --git a/tools/aconfig/aconfig_storage_read_api/tests/jarjar.txt b/tools/aconfig/aconfig_storage_read_api/tests/jarjar.txt
deleted file mode 100644
index 49250d4202..0000000000
--- a/tools/aconfig/aconfig_storage_read_api/tests/jarjar.txt
+++ /dev/null
@@ -1,19 +0,0 @@
-rule android.aconfig.storage.AconfigStorageException android.aconfig.storage.test.AconfigStorageException
-rule android.aconfig.storage.FlagTable android.aconfig.storage.test.FlagTable
-rule android.aconfig.storage.PackageTable android.aconfig.storage.test.PackageTable
-rule android.aconfig.storage.ByteBufferReader android.aconfig.storage.test.ByteBufferReader
-rule android.aconfig.storage.FlagType android.aconfig.storage.test.FlagType
-rule android.aconfig.storage.SipHasher13 android.aconfig.storage.test.SipHasher13
-rule android.aconfig.storage.FileType android.aconfig.storage.test.FileType
-rule android.aconfig.storage.FlagValueList android.aconfig.storage.test.FlagValueList
-rule android.aconfig.storage.TableUtils android.aconfig.storage.test.TableUtils
-rule android.aconfig.storage.AconfigPackageImpl android.aconfig.storage.test.AconfigPackageImpl
-rule android.aconfig.storage.StorageFileProvider android.aconfig.storage.test.StorageFileProvider
-
-
-rule android.aconfig.storage.FlagTable$* android.aconfig.storage.test.FlagTable$@1
-rule android.aconfig.storage.PackageTable$* android.aconfig.storage.test.PackageTable$@1
-rule android.aconfig.storage.FlagValueList$* android.aconfig.storage.test.FlagValueList@1
-rule android.aconfig.storage.SipHasher13$* android.aconfig.storage.test.SipHasher13@1
-
-rule android.os.flagging.PlatformAconfigPackageInternal android.aconfig.storage.test.PlatformAconfigPackageInternal
diff --git a/tools/aconfig/aconfig_storage_read_api/tests/unit/srcs/PlatformAconfigPackageInternalTest.java b/tools/aconfig/aconfig_storage_read_api/tests/unit/srcs/PlatformAconfigPackageInternalTest.java
deleted file mode 100644
index 961f0ea7ff..0000000000
--- a/tools/aconfig/aconfig_storage_read_api/tests/unit/srcs/PlatformAconfigPackageInternalTest.java
+++ /dev/null
@@ -1,152 +0,0 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-package android.aconfig.storage.test;
-
-import static org.junit.Assert.assertEquals;
-import static org.junit.Assert.assertFalse;
-import static org.junit.Assert.assertThrows;
-import static org.junit.Assert.assertTrue;
-
-import android.aconfig.storage.PackageTable;
-import android.aconfig.storage.StorageFileProvider;
-import android.os.flagging.AconfigStorageReadException;
-import android.os.flagging.PlatformAconfigPackageInternal;
-
-import org.junit.Before;
-import org.junit.Test;
-import org.junit.runner.RunWith;
-import org.junit.runners.JUnit4;
-
-@RunWith(JUnit4.class)
-public class PlatformAconfigPackageInternalTest {
-
-    public static final String TESTDATA_PATH =
-            "/data/local/tmp/aconfig_storage_read_unit/testdata/";
-
-    private StorageFileProvider pr;
-
-    @Before
-    public void setup() {
-        pr = new StorageFileProvider(TESTDATA_PATH, TESTDATA_PATH);
-    }
-
-    @Test
-    public void testLoad_container_package() throws Exception {
-        PackageTable packageTable = pr.getPackageTable("mockup");
-
-        PackageTable.Node node1 = packageTable.get("com.android.aconfig.storage.test_1");
-
-        long fingerprint = node1.getPackageFingerprint();
-        PlatformAconfigPackageInternal p =
-                PlatformAconfigPackageInternal.load(
-                        "mockup", "com.android.aconfig.storage.test_1", fingerprint, pr);
-    }
-
-    @Test
-    public void testLoad_container_package_error() throws Exception {
-        PackageTable packageTable = pr.getPackageTable("mockup");
-        PackageTable.Node node1 = packageTable.get("com.android.aconfig.storage.test_1");
-        long fingerprint = node1.getPackageFingerprint();
-        // cannot find package
-        AconfigStorageReadException e =
-                assertThrows(
-                        AconfigStorageReadException.class,
-                        () ->
-                                PlatformAconfigPackageInternal.load(
-                                        "mockup",
-                                        "com.android.aconfig.storage.test_10",
-                                        fingerprint,
-                                        pr));
-        assertEquals(AconfigStorageReadException.ERROR_PACKAGE_NOT_FOUND, e.getErrorCode());
-
-        // cannot find container
-        e =
-                assertThrows(
-                        AconfigStorageReadException.class,
-                        () ->
-                                PlatformAconfigPackageInternal.load(
-                                        null,
-                                        "com.android.aconfig.storage.test_1",
-                                        fingerprint,
-                                        pr));
-        assertEquals(AconfigStorageReadException.ERROR_CANNOT_READ_STORAGE_FILE, e.getErrorCode());
-
-        e =
-                assertThrows(
-                        AconfigStorageReadException.class,
-                        () ->
-                                PlatformAconfigPackageInternal.load(
-                                        "test",
-                                        "com.android.aconfig.storage.test_1",
-                                        fingerprint,
-                                        pr));
-        assertEquals(AconfigStorageReadException.ERROR_CANNOT_READ_STORAGE_FILE, e.getErrorCode());
-
-        // fingerprint doesn't match
-        e =
-                assertThrows(
-                        AconfigStorageReadException.class,
-                        () ->
-                                PlatformAconfigPackageInternal.load(
-                                        "mockup",
-                                        "com.android.aconfig.storage.test_1",
-                                        fingerprint + 1,
-                                        pr));
-        assertEquals(
-                // AconfigStorageException.ERROR_FILE_FINGERPRINT_MISMATCH,
-                5, e.getErrorCode());
-
-        // new storage doesn't exist
-        pr = new StorageFileProvider("fake/path/", "fake/path/");
-        e =
-                assertThrows(
-                        AconfigStorageReadException.class,
-                        () ->
-                                PlatformAconfigPackageInternal.load(
-                                        "mockup",
-                                        "com.android.aconfig.storage.test_1",
-                                        fingerprint,
-                                        pr));
-        assertEquals(AconfigStorageReadException.ERROR_CANNOT_READ_STORAGE_FILE, e.getErrorCode());
-
-        // file read issue
-        pr = new StorageFileProvider(TESTDATA_PATH, "fake/path/");
-        e =
-                assertThrows(
-                        AconfigStorageReadException.class,
-                        () ->
-                                PlatformAconfigPackageInternal.load(
-                                        "mockup",
-                                        "com.android.aconfig.storage.test_1",
-                                        fingerprint,
-                                        pr));
-        assertEquals(AconfigStorageReadException.ERROR_CANNOT_READ_STORAGE_FILE, e.getErrorCode());
-    }
-
-    @Test
-    public void testGetBooleanFlagValue_index() throws Exception {
-        PackageTable packageTable = pr.getPackageTable("mockup");
-        PackageTable.Node node1 = packageTable.get("com.android.aconfig.storage.test_1");
-        long fingerprint = node1.getPackageFingerprint();
-        PlatformAconfigPackageInternal p =
-                PlatformAconfigPackageInternal.load(
-                        "mockup", "com.android.aconfig.storage.test_1", fingerprint, pr);
-        assertFalse(p.getBooleanFlagValue(0));
-        assertTrue(p.getBooleanFlagValue(1));
-        assertTrue(p.getBooleanFlagValue(2));
-    }
-}
diff --git a/tools/aconfig/aflags/Android.bp b/tools/aconfig/aflags/Android.bp
index a7aceeebad..341975daa4 100644
--- a/tools/aconfig/aflags/Android.bp
+++ b/tools/aconfig/aflags/Android.bp
@@ -31,6 +31,9 @@ rust_binary {
     name: "aflags",
     host_supported: true,
     defaults: ["aflags.defaults"],
+    apex_available: [
+        "//apex_available:platform",
+    ],
 }
 
 rust_test_host {
diff --git a/tools/aconfig/aflags/src/aconfig_storage_source.rs b/tools/aconfig/aflags/src/aconfig_storage_source.rs
index aef7d7e6ab..766807acef 100644
--- a/tools/aconfig/aflags/src/aconfig_storage_source.rs
+++ b/tools/aconfig/aflags/src/aconfig_storage_source.rs
@@ -17,6 +17,23 @@ use std::os::unix::net::UnixStream;
 
 pub struct AconfigStorageSource {}
 
+static ACONFIGD_SYSTEM_SOCKET_NAME: &str = "/dev/socket/aconfigd_system";
+static ACONFIGD_MAINLINE_SOCKET_NAME: &str = "/dev/socket/aconfigd_mainline";
+
+enum AconfigdSocket {
+    System,
+    Mainline,
+}
+
+impl AconfigdSocket {
+    pub fn name(&self) -> &str {
+        match self {
+            AconfigdSocket::System => ACONFIGD_SYSTEM_SOCKET_NAME,
+            AconfigdSocket::Mainline => ACONFIGD_MAINLINE_SOCKET_NAME,
+        }
+    }
+}
+
 fn load_flag_to_container() -> Result<HashMap<String, String>> {
     Ok(load_protos::load()?.into_iter().map(|p| (p.qualified_name(), p.container)).collect())
 }
@@ -81,7 +98,7 @@ fn convert(msg: ProtoFlagQueryReturnMessage, containers: &HashMap<String, String
     })
 }
 
-fn read_from_socket() -> Result<Vec<ProtoFlagQueryReturnMessage>> {
+fn read_from_socket(socket: AconfigdSocket) -> Result<Vec<ProtoFlagQueryReturnMessage>> {
     let messages = ProtoStorageRequestMessages {
         msgs: vec![ProtoStorageRequestMessage {
             msg: Some(ProtoStorageRequestMessageMsg::ListStorageMessage(ProtoListStorageMessage {
@@ -93,8 +110,7 @@ fn read_from_socket() -> Result<Vec<ProtoFlagQueryReturnMessage>> {
         special_fields: SpecialFields::new(),
     };
 
-    let socket_name = "/dev/socket/aconfigd_system";
-    let mut socket = UnixStream::connect(socket_name)?;
+    let mut socket = UnixStream::connect(socket.name())?;
 
     let message_buffer = messages.write_to_bytes()?;
     let mut message_length_buffer: [u8; 4] = [0; 4];
@@ -128,14 +144,20 @@ fn read_from_socket() -> Result<Vec<ProtoFlagQueryReturnMessage>> {
 impl FlagSource for AconfigStorageSource {
     fn list_flags() -> Result<Vec<Flag>> {
         let containers = load_flag_to_container()?;
-        read_from_socket()
-            .map(|query_messages| {
-                query_messages
-                    .iter()
-                    .map(|message| convert(message.clone(), &containers))
-                    .collect::<Vec<_>>()
-            })?
+        let system_messages = read_from_socket(AconfigdSocket::System);
+        let mainline_messages = read_from_socket(AconfigdSocket::Mainline);
+
+        let mut all_messages = vec![];
+        if let Ok(system_messages) = system_messages {
+            all_messages.extend_from_slice(&system_messages);
+        }
+        if let Ok(mainline_messages) = mainline_messages {
+            all_messages.extend_from_slice(&mainline_messages);
+        }
+
+        all_messages
             .into_iter()
+            .map(|query_message| convert(query_message.clone(), &containers))
             .collect()
     }
 
diff --git a/tools/aconfig/aflags/src/main.rs b/tools/aconfig/aflags/src/main.rs
index 8173bc24da..568ad999e0 100644
--- a/tools/aconfig/aflags/src/main.rs
+++ b/tools/aconfig/aflags/src/main.rs
@@ -16,6 +16,9 @@
 
 //! `aflags` is a device binary to read and write aconfig flags.
 
+use std::env;
+use std::process::{Command as OsCommand, Stdio};
+
 use anyhow::{anyhow, ensure, Result};
 use clap::Parser;
 
@@ -298,7 +301,37 @@ fn display_which_backing() -> String {
     }
 }
 
+fn invoke_updatable_aflags() {
+    let updatable_command = "/apex/com.android.configinfrastructure/bin/aflags_updatable";
+
+    let args: Vec<String> = env::args().collect();
+    let command_args = if args.len() >= 2 { &args[1..] } else { &["--help".to_string()] };
+
+    let mut child = OsCommand::new(updatable_command);
+    for arg in command_args {
+        child.arg(arg);
+    }
+
+    let output = child
+        .stdin(Stdio::piped())
+        .stdout(Stdio::piped())
+        .spawn()
+        .expect("failed to execute child")
+        .wait_with_output()
+        .expect("failed to execute command");
+
+    let output_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
+    if !output_str.is_empty() {
+        println!("{}", output_str);
+    }
+}
+
 fn main() -> Result<()> {
+    if aconfig_flags::auto_generated::invoke_updatable_aflags() {
+        invoke_updatable_aflags();
+        return Ok(());
+    }
+
     ensure!(nix::unistd::Uid::current().is_root(), "must be root");
 
     let cli = Cli::parse();
diff --git a/tools/aconfig/convert_finalized_flags/Android.bp b/tools/aconfig/convert_finalized_flags/Android.bp
new file mode 100644
index 0000000000..9ace80597a
--- /dev/null
+++ b/tools/aconfig/convert_finalized_flags/Android.bp
@@ -0,0 +1,60 @@
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+rust_defaults {
+    name: "convert_finalized_flags.defaults",
+    edition: "2021",
+    clippy_lints: "android",
+    lints: "android",
+    rustlibs: [
+        "libanyhow",
+        "libclap",
+        "libitertools",
+        "libprotobuf",
+        "libserde",
+        "libserde_json",
+        "libtempfile",
+        "libtinytemplate",
+    ],
+}
+
+rust_library_host {
+    name: "libconvert_finalized_flags",
+    crate_name: "convert_finalized_flags",
+    defaults: ["convert_finalized_flags.defaults"],
+    srcs: [
+        "src/lib.rs",
+    ],
+}
+
+rust_binary_host {
+    name: "convert_finalized_flags",
+    defaults: ["convert_finalized_flags.defaults"],
+    srcs: ["src/main.rs"],
+    rustlibs: [
+        "libconvert_finalized_flags",
+        "libserde_json",
+    ],
+}
+
+rust_test_host {
+    name: "convert_finalized_flags.test",
+    defaults: ["convert_finalized_flags.defaults"],
+    test_suites: ["general-tests"],
+    srcs: ["src/lib.rs"],
+}
+
+genrule {
+    name: "finalized_flags_record.json",
+    srcs: [
+        "//prebuilts/sdk:finalized-api-flags",
+    ],
+    tool_files: ["extended_flags_list_35.txt"],
+    out: ["finalized_flags_record.json"],
+    tools: ["convert_finalized_flags"],
+    cmd: "args=\"\" && " +
+        "for f in $(locations //prebuilts/sdk:finalized-api-flags); " +
+        " do args=\"$$args --flag_file_path $$f\"; done && " +
+        "$(location convert_finalized_flags) $$args  --extended-flag-file-path $(location extended_flags_list_35.txt) > $(out)",
+}
diff --git a/tools/aconfig/convert_finalized_flags/Cargo.toml b/tools/aconfig/convert_finalized_flags/Cargo.toml
new file mode 100644
index 0000000000..e34e030841
--- /dev/null
+++ b/tools/aconfig/convert_finalized_flags/Cargo.toml
@@ -0,0 +1,15 @@
+[package]
+name = "convert_finalized_flags"
+version = "0.1.0"
+edition = "2021"
+
+[features]
+default = ["cargo"]
+cargo = []
+
+[dependencies]
+anyhow = "1.0.69"
+clap = { version = "4.1.8", features = ["derive"] }
+serde = { version = "1.0.152", features = ["derive"] }
+serde_json = "1.0.93"
+tempfile = "3.13.0"
diff --git a/tools/aconfig/convert_finalized_flags/extended_flags_list_35.txt b/tools/aconfig/convert_finalized_flags/extended_flags_list_35.txt
new file mode 100644
index 0000000000..0b506bae41
--- /dev/null
+++ b/tools/aconfig/convert_finalized_flags/extended_flags_list_35.txt
@@ -0,0 +1,129 @@
+android.app.admin.flags.permission_migration_for_zero_trust_api_enabled
+android.app.app_restrictions_api
+android.app.pinner_service_client_api
+android.car.feature.android_vic_vehicle_properties
+android.car.feature.area_id_config_access
+android.car.feature.batched_subscriptions
+android.car.feature.car_app_card
+android.car.feature.car_audio_dynamic_devices
+android.car.feature.car_audio_fade_manager_configuration
+android.car.feature.car_audio_min_max_activation_volume
+android.car.feature.car_audio_mute_ambiguity
+android.car.feature.car_evs_query_service_status
+android.car.feature.car_evs_stream_management
+android.car.feature.car_night_global_setting
+android.car.feature.car_property_detailed_error_codes
+android.car.feature.car_property_value_property_status
+android.car.feature.cluster_health_monitoring
+android.car.feature.display_compatibility
+android.car.feature.persist_ap_settings
+android.car.feature.projection_query_bt_profile_inhibit
+android.car.feature.serverless_remote_access
+android.car.feature.subscription_with_resolution
+android.car.feature.switch_user_ignoring_uxr
+android.car.feature.variable_update_rate
+android.companion.new_association_builder
+android.companion.virtual.flags.impulse_velocity_strategy_for_touch_navigation
+android.companion.virtual.flags.interactive_screen_mirror
+android.companion.virtual.flags.intercept_intents_before_applying_policy
+android.content.pm.get_package_storage_stats
+android.credentials.flags.settings_activity_enabled
+android.graphics.pdf.flags.enable_form_filling
+android.graphics.pdf.flags.enable_pdf_viewer
+android.hardware.devicestate.feature.flags.device_state_requester_cancel_state
+android.hardware.usb.flags.enable_is_mode_change_supported_api
+android.media.audio.focus_exclusive_with_recording
+android.media.audio.focus_freeze_test_api
+android.media.audio.ro_foreground_audio_control
+android.media.audiopolicy.audio_mix_test_api
+android.multiuser.enable_biometrics_to_unlock_private_space
+android.nfc.enable_nfc_reader_option
+android.nfc.enable_nfc_set_discovery_tech
+android.nfc.nfc_vendor_cmd
+android.os.bugreport_mode_max_value
+android.os.profiling.redaction_enabled
+android.os.profiling.telemetry_apis
+android.permission.flags.device_aware_permissions_enabled
+android.permission.flags.sensitive_notification_app_protection
+android.permission.flags.system_server_role_controller_enabled
+android.service.chooser.fix_resolver_memory_leak
+android.service.notification.redact_sensitive_notifications_big_text_style
+android.service.notification.redact_sensitive_notifications_from_untrusted_listeners
+android.view.accessibility.motion_event_observing
+android.webkit.update_service_v2
+com.android.aconfig.test.enabled_fixed_ro_exported
+com.android.aconfig.test.enabled_ro_exported
+com.android.adservices.ondevicepersonalization.flags.on_device_personalization_apis_enabled
+com.android.appsearch.flags.enable_enterprise_global_search_session
+com.android.appsearch.flags.enable_generic_document_builder_hidden_methods
+com.android.appsearch.flags.enable_generic_document_copy_constructor
+com.android.appsearch.flags.enable_get_parent_types_and_indexable_nested_properties
+com.android.appsearch.flags.enable_grouping_type_per_schema
+com.android.appsearch.flags.enable_list_filter_has_property_function
+com.android.appsearch.flags.enable_put_documents_request_add_taken_actions
+com.android.appsearch.flags.enable_safe_parcelable_2
+com.android.appsearch.flags.enable_search_spec_filter_properties
+com.android.appsearch.flags.enable_search_spec_set_search_source_log_tag
+com.android.appsearch.flags.enable_set_publicly_visible_schema
+com.android.appsearch.flags.enable_set_schema_visible_to_configs
+com.android.bluetooth.flags.a2dp_offload_codec_extensibility
+com.android.bluetooth.flags.allow_switching_hid_and_hogp
+com.android.bluetooth.flags.auto_on_feature
+com.android.bluetooth.flags.channel_sounding
+com.android.bluetooth.flags.enumerate_gatt_errors
+com.android.bluetooth.flags.get_address_type_api
+com.android.bluetooth.flags.key_missing_broadcast
+com.android.bluetooth.flags.leaudio_add_sampling_frequencies
+com.android.bluetooth.flags.leaudio_broadcast_monitor_source_sync_status
+com.android.bluetooth.flags.leaudio_broadcast_volume_control_for_connected_devices
+com.android.bluetooth.flags.leaudio_callback_on_group_stream_status
+com.android.bluetooth.flags.leaudio_multiple_vocs_instances_api
+com.android.bluetooth.flags.metadata_api_inactive_audio_device_upon_connection
+com.android.bluetooth.flags.mfi_has_uuid
+com.android.bluetooth.flags.settings_can_control_hap_preset
+com.android.bluetooth.flags.support_exclusive_manager
+com.android.bluetooth.flags.unix_file_socket_creation_failure
+com.android.healthconnect.flags.read_exercise_routes_all_enabled
+com.android.healthconnect.flags.skin_temperature
+com.android.healthconnect.flags.training_plans
+com.android.icu.icu_v_api
+com.android.ipsec.flags.dpd_disable_api
+com.android.ipsec.flags.dumpsys_api
+com.android.ipsec.flags.enabled_ike_options_api
+com.android.ipsec.flags.liveness_check_api
+com.android.libcore.hpke_v_apis
+com.android.libcore.v_apis
+com.android.media.flags.enable_cross_user_routing_in_media_router2
+com.android.media.mainline.flags.enable_pid_to_media_session_2
+com.android.nearby.flags.powered_off_finding
+com.android.net.flags.basic_background_restrictions_enabled
+com.android.net.flags.ipsec_transform_state
+com.android.net.flags.net_capability_local_network
+com.android.net.flags.nsd_subtypes_support_enabled
+com.android.net.flags.register_nsd_offload_engine_api
+com.android.net.flags.request_restricted_wifi
+com.android.net.flags.set_data_saver_via_cm
+com.android.net.flags.support_is_uid_networking_blocked
+com.android.net.flags.support_transport_satellite
+com.android.net.flags.tethering_request_with_soft_ap_config
+com.android.net.thread.flags.thread_enabled
+com.android.permission.flags.private_profile_supported
+com.android.permission.flags.private_profile_title_api
+com.android.permission.flags.wear_privacy_dashboard_enabled_read_only
+com.android.providers.contactkeys.flags.contactkeys_strip_fix
+com.android.providers.media.flags.access_media_owner_package_name_permission
+com.android.providers.media.flags.pick_ordered_images
+com.android.providers.media.flags.picker_accent_color
+com.android.providers.media.flags.picker_default_tab
+com.android.providers.media.flags.picker_recent_selection
+com.android.system.virtualmachine.flags.avf_v_test_apis
+com.android.uwb.flags.data_transfer_phase_config
+com.android.uwb.flags.hw_state
+com.android.uwb.flags.hybrid_session_support
+com.android.uwb.flags.query_timestamp_micros
+com.android.uwb.flags.reason_inband_session_stop
+com.android.wifi.flags.android_v_wifi_api
+com.android.wifi.flags.network_provider_battery_charging_status
+com.android.wifi.flags.shared_connectivity_broadcast_receiver_test_api
+com.android.window.flags.untrusted_embedding_state_sharing
+com.google.android.haptics.flags.vendor_vibration_control
diff --git a/tools/aconfig/convert_finalized_flags/src/lib.rs b/tools/aconfig/convert_finalized_flags/src/lib.rs
new file mode 100644
index 0000000000..335a31b046
--- /dev/null
+++ b/tools/aconfig/convert_finalized_flags/src/lib.rs
@@ -0,0 +1,563 @@
+/*
+* Copyright (C) 2025 The Android Open Source Project
+*
+* Licensed under the Apache License, Version 2.0 (the "License");
+* you may not use this file except in compliance with the License.
+* You may obtain a copy of the License at
+*
+*      http://www.apache.org/licenses/LICENSE-2.0
+*
+* Unless required by applicable law or agreed to in writing, software
+* distributed under the License is distributed on an "AS IS" BASIS,
+* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+* See the License for the specific language governing permissions and
+* limitations under the License.
+*/
+//! Functions to extract finalized flag information from
+//! /prebuilts/sdk/#/finalized-flags.txt.
+//! These functions are very specific to that file setup as well as the format
+//! of the files (just a list of the fully-qualified flag names).
+//! There are also some helper functions for local building using cargo. These
+//! functions are only invoked via cargo for quick local testing and will not
+//! be used during actual soong building. They are marked as such.
+use anyhow::{anyhow, Result};
+use serde::{Deserialize, Serialize};
+use std::collections::{HashMap, HashSet};
+use std::fs;
+use std::io::{self, BufRead};
+
+const SDK_INT_MULTIPLIER: u32 = 100_000;
+
+/// Just the fully qualified flag name (package_name.flag_name).
+#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
+pub struct FinalizedFlag {
+    /// Name of the flag.
+    pub flag_name: String,
+    /// Name of the package.
+    pub package_name: String,
+}
+
+/// API level in which the flag was finalized.
+#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
+pub struct ApiLevel(pub i32);
+
+/// API level of the extended flags file of version 35
+pub const EXTENDED_FLAGS_35_APILEVEL: ApiLevel = ApiLevel(35);
+
+/// Contains all flags finalized for a given API level.
+#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
+pub struct FinalizedFlagMap(HashMap<ApiLevel, HashSet<FinalizedFlag>>);
+
+impl FinalizedFlagMap {
+    /// Creates a new, empty instance.
+    pub fn new() -> Self {
+        Self(HashMap::new())
+    }
+
+    /// Convenience method for is_empty on the underlying map.
+    pub fn is_empty(&self) -> bool {
+        self.0.is_empty()
+    }
+
+    /// Returns the API level in which the flag was finalized .
+    pub fn get_finalized_level(&self, flag: &FinalizedFlag) -> Option<ApiLevel> {
+        for (api_level, flags_for_level) in &self.0 {
+            if flags_for_level.contains(flag) {
+                return Some(*api_level);
+            }
+        }
+        None
+    }
+
+    /// Insert the flag into the map for the given level if the flag is not
+    /// present in the map already - for *any* level (not just the one given).
+    pub fn insert_if_new(&mut self, level: ApiLevel, flag: FinalizedFlag) {
+        if self.contains(&flag) {
+            return;
+        }
+        self.0.entry(level).or_default().insert(flag);
+    }
+
+    fn contains(&self, flag: &FinalizedFlag) -> bool {
+        self.0.values().any(|flags_set| flags_set.contains(flag))
+    }
+}
+
+#[allow(dead_code)] // TODO: b/378936061: Use with SDK_INT_FULL check.
+fn parse_full_version(version: String) -> Result<u32> {
+    let (major, minor) = if let Some(decimal_index) = version.find('.') {
+        (version[..decimal_index].parse::<u32>()?, version[decimal_index + 1..].parse::<u32>()?)
+    } else {
+        (version.parse::<u32>()?, 0)
+    };
+
+    if major >= 21474 {
+        return Err(anyhow!("Major version too large, must be less than 21474."));
+    }
+    if minor >= SDK_INT_MULTIPLIER {
+        return Err(anyhow!("Minor version too large, must be less than {}.", SDK_INT_MULTIPLIER));
+    }
+
+    Ok(major * SDK_INT_MULTIPLIER + minor)
+}
+
+const EXTENDED_FLAGS_LIST_35: &str = "extended_flags_list_35.txt";
+
+/// Converts a string to an int. Will parse to int even if the string is "X.0".
+/// Returns error for "X.1".
+fn str_to_api_level(numeric_string: &str) -> Result<ApiLevel> {
+    let float_value = numeric_string.parse::<f64>()?;
+
+    if float_value.fract() == 0.0 {
+        Ok(ApiLevel(float_value as i32))
+    } else {
+        Err(anyhow!("Numeric string is float, can't parse to int."))
+    }
+}
+
+/// For each file, extracts the qualified flag names into a FinalizedFlag, then
+/// enters them in a map at the API level corresponding to their directory.
+/// Ex: /prebuilts/sdk/35/finalized-flags.txt -> {36, [flag1, flag2]}.
+pub fn read_files_to_map_using_path(flag_files: Vec<String>) -> Result<FinalizedFlagMap> {
+    let mut data_map = FinalizedFlagMap::new();
+
+    for flag_file in flag_files {
+        // Split /path/sdk/<int.int>/finalized-flags.txt -> ['/path/sdk', 'int.int', 'finalized-flags.txt'].
+        let flag_file_split: Vec<String> =
+            flag_file.clone().rsplitn(3, '/').map(|s| s.to_string()).collect();
+
+        if &flag_file_split[0] != "finalized-flags.txt" {
+            return Err(anyhow!("Provided incorrect file, must be finalized-flags.txt"));
+        }
+
+        let api_level_string = &flag_file_split[1];
+
+        // For now, skip any directory with full API level, e.g. "36.1". The
+        // finalized flag files each contain all flags finalized *up to* that
+        // level (including prior levels), so skipping intermediate levels means
+        // the flags will be included at the next full number.
+        // TODO: b/378936061 - Support full SDK version.
+        // In the future, we should error if provided a non-numeric directory.
+        let Ok(api_level) = str_to_api_level(api_level_string) else {
+            continue;
+        };
+
+        let file = fs::File::open(&flag_file)?;
+
+        io::BufReader::new(file).lines().for_each(|flag| {
+            let flag =
+                flag.unwrap_or_else(|_| panic!("Failed to read line from file {}", flag_file));
+            let finalized_flag = build_finalized_flag(&flag)
+                .unwrap_or_else(|_| panic!("cannot build finalized flag {}", flag));
+            data_map.insert_if_new(api_level, finalized_flag);
+        });
+    }
+
+    Ok(data_map)
+}
+
+/// Read the qualified flag names into a FinalizedFlag set
+pub fn read_extend_file_to_map_using_path(extened_file: String) -> Result<HashSet<FinalizedFlag>> {
+    let (_, file_name) =
+        extened_file.rsplit_once('/').ok_or(anyhow!("Invalid file: '{}'", extened_file))?;
+    if file_name != EXTENDED_FLAGS_LIST_35 {
+        return Err(anyhow!("Provided incorrect file, must be {}", EXTENDED_FLAGS_LIST_35));
+    }
+    let file = fs::File::open(extened_file)?;
+    let extended_flags = io::BufReader::new(file)
+        .lines()
+        .map(|flag| {
+            let flag = flag.expect("Failed to read line from extended file");
+            build_finalized_flag(&flag)
+                .unwrap_or_else(|_| panic!("cannot build finalized flag {}", flag))
+        })
+        .collect::<HashSet<FinalizedFlag>>();
+    Ok(extended_flags)
+}
+
+fn build_finalized_flag(qualified_flag_name: &String) -> Result<FinalizedFlag> {
+    // Split the qualified flag name into package and flag name:
+    // com.my.package.name.my_flag_name -> ('com.my.package.name', 'my_flag_name')
+    let (package_name, flag_name) = qualified_flag_name
+        .rsplit_once('.')
+        .ok_or(anyhow!("Invalid qualified flag name format: '{}'", qualified_flag_name))?;
+
+    Ok(FinalizedFlag { flag_name: flag_name.to_string(), package_name: package_name.to_string() })
+}
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use std::fs::File;
+    use std::io::Write;
+    use tempfile::tempdir;
+
+    const FLAG_FILE_NAME: &str = "finalized-flags.txt";
+
+    // Creates some flags for testing.
+    fn create_test_flags() -> Vec<FinalizedFlag> {
+        vec![
+            FinalizedFlag { flag_name: "name1".to_string(), package_name: "package1".to_string() },
+            FinalizedFlag { flag_name: "name2".to_string(), package_name: "package2".to_string() },
+            FinalizedFlag { flag_name: "name3".to_string(), package_name: "package3".to_string() },
+        ]
+    }
+
+    // Writes the fully qualified flag names in the given file.
+    fn add_flags_to_file(flag_file: &mut File, flags: &[FinalizedFlag]) {
+        for flag in flags {
+            let _unused = writeln!(flag_file, "{}.{}", flag.package_name, flag.flag_name);
+        }
+    }
+
+    #[test]
+    fn test_read_flags_one_file() {
+        let flags = create_test_flags();
+
+        // Create the file <temp_dir>/35/finalized-flags.txt.
+        let temp_dir = tempdir().unwrap();
+        let mut file_path = temp_dir.path().to_path_buf();
+        file_path.push("35");
+        fs::create_dir_all(&file_path).unwrap();
+        file_path.push(FLAG_FILE_NAME);
+        let mut file = File::create(&file_path).unwrap();
+
+        // Write all flags to the file.
+        add_flags_to_file(&mut file, &[flags[0].clone(), flags[1].clone()]);
+        let flag_file_path = file_path.to_string_lossy().to_string();
+
+        // Convert to map.
+        let map = read_files_to_map_using_path(vec![flag_file_path]).unwrap();
+
+        assert_eq!(map.0.len(), 1);
+        assert!(map.0.get(&ApiLevel(35)).unwrap().contains(&flags[0]));
+        assert!(map.0.get(&ApiLevel(35)).unwrap().contains(&flags[1]));
+    }
+
+    #[test]
+    fn test_read_flags_two_files() {
+        let flags = create_test_flags();
+
+        // Create the file <temp_dir>/35/finalized-flags.txt and for 36.
+        let temp_dir = tempdir().unwrap();
+        let mut file_path1 = temp_dir.path().to_path_buf();
+        file_path1.push("35");
+        fs::create_dir_all(&file_path1).unwrap();
+        file_path1.push(FLAG_FILE_NAME);
+        let mut file1 = File::create(&file_path1).unwrap();
+
+        let mut file_path2 = temp_dir.path().to_path_buf();
+        file_path2.push("36");
+        fs::create_dir_all(&file_path2).unwrap();
+        file_path2.push(FLAG_FILE_NAME);
+        let mut file2 = File::create(&file_path2).unwrap();
+
+        // Write all flags to the files.
+        add_flags_to_file(&mut file1, &[flags[0].clone()]);
+        add_flags_to_file(&mut file2, &[flags[0].clone(), flags[1].clone(), flags[2].clone()]);
+        let flag_file_path1 = file_path1.to_string_lossy().to_string();
+        let flag_file_path2 = file_path2.to_string_lossy().to_string();
+
+        // Convert to map.
+        let map = read_files_to_map_using_path(vec![flag_file_path1, flag_file_path2]).unwrap();
+
+        // Assert there are two API levels, 35 and 36.
+        assert_eq!(map.0.len(), 2);
+        assert!(map.0.get(&ApiLevel(35)).unwrap().contains(&flags[0]));
+
+        // 36 should not have the first flag in the set, as it was finalized in
+        // an earlier API level.
+        assert!(map.0.get(&ApiLevel(36)).unwrap().contains(&flags[1]));
+        assert!(map.0.get(&ApiLevel(36)).unwrap().contains(&flags[2]));
+    }
+
+    #[test]
+    fn test_read_flags_full_numbers() {
+        let flags = create_test_flags();
+
+        // Create the file <temp_dir>/35/finalized-flags.txt and for 36.
+        let temp_dir = tempdir().unwrap();
+        let mut file_path1 = temp_dir.path().to_path_buf();
+        file_path1.push("35.0");
+        fs::create_dir_all(&file_path1).unwrap();
+        file_path1.push(FLAG_FILE_NAME);
+        let mut file1 = File::create(&file_path1).unwrap();
+
+        let mut file_path2 = temp_dir.path().to_path_buf();
+        file_path2.push("36.0");
+        fs::create_dir_all(&file_path2).unwrap();
+        file_path2.push(FLAG_FILE_NAME);
+        let mut file2 = File::create(&file_path2).unwrap();
+
+        // Write all flags to the files.
+        add_flags_to_file(&mut file1, &[flags[0].clone()]);
+        add_flags_to_file(&mut file2, &[flags[0].clone(), flags[1].clone(), flags[2].clone()]);
+        let flag_file_path1 = file_path1.to_string_lossy().to_string();
+        let flag_file_path2 = file_path2.to_string_lossy().to_string();
+
+        // Convert to map.
+        let map = read_files_to_map_using_path(vec![flag_file_path1, flag_file_path2]).unwrap();
+
+        assert_eq!(map.0.len(), 2);
+        assert!(map.0.get(&ApiLevel(35)).unwrap().contains(&flags[0]));
+        assert!(map.0.get(&ApiLevel(36)).unwrap().contains(&flags[1]));
+        assert!(map.0.get(&ApiLevel(36)).unwrap().contains(&flags[2]));
+    }
+
+    #[test]
+    fn test_read_flags_fractions_round_up() {
+        let flags = create_test_flags();
+
+        // Create the file <temp_dir>/35/finalized-flags.txt and for 36.
+        let temp_dir = tempdir().unwrap();
+        let mut file_path1 = temp_dir.path().to_path_buf();
+        file_path1.push("35.1");
+        fs::create_dir_all(&file_path1).unwrap();
+        file_path1.push(FLAG_FILE_NAME);
+        let mut file1 = File::create(&file_path1).unwrap();
+
+        let mut file_path2 = temp_dir.path().to_path_buf();
+        file_path2.push("36.0");
+        fs::create_dir_all(&file_path2).unwrap();
+        file_path2.push(FLAG_FILE_NAME);
+        let mut file2 = File::create(&file_path2).unwrap();
+
+        // Write all flags to the files.
+        add_flags_to_file(&mut file1, &[flags[0].clone()]);
+        add_flags_to_file(&mut file2, &[flags[0].clone(), flags[1].clone(), flags[2].clone()]);
+        let flag_file_path1 = file_path1.to_string_lossy().to_string();
+        let flag_file_path2 = file_path2.to_string_lossy().to_string();
+
+        // Convert to map.
+        let map = read_files_to_map_using_path(vec![flag_file_path1, flag_file_path2]).unwrap();
+
+        // No flags were added in 35. All 35.1 flags were rolled up to 36.
+        assert_eq!(map.0.len(), 1);
+        assert!(!map.0.contains_key(&ApiLevel(35)));
+        assert!(map.0.get(&ApiLevel(36)).unwrap().contains(&flags[0]));
+        assert!(map.0.get(&ApiLevel(36)).unwrap().contains(&flags[1]));
+        assert!(map.0.get(&ApiLevel(36)).unwrap().contains(&flags[2]));
+    }
+
+    #[test]
+    fn test_read_flags_non_numeric() {
+        let flags = create_test_flags();
+
+        // Create the file <temp_dir>/35/finalized-flags.txt.
+        let temp_dir = tempdir().unwrap();
+        let mut file_path = temp_dir.path().to_path_buf();
+        file_path.push("35");
+        fs::create_dir_all(&file_path).unwrap();
+        file_path.push(FLAG_FILE_NAME);
+        let mut flag_file = File::create(&file_path).unwrap();
+
+        let mut invalid_path = temp_dir.path().to_path_buf();
+        invalid_path.push("sdk-annotations");
+        fs::create_dir_all(&invalid_path).unwrap();
+        invalid_path.push(FLAG_FILE_NAME);
+        File::create(&invalid_path).unwrap();
+
+        // Write all flags to the file.
+        add_flags_to_file(&mut flag_file, &[flags[0].clone(), flags[1].clone()]);
+        let flag_file_path = file_path.to_string_lossy().to_string();
+
+        // Convert to map.
+        let map = read_files_to_map_using_path(vec![
+            flag_file_path,
+            invalid_path.to_string_lossy().to_string(),
+        ])
+        .unwrap();
+
+        // No set should be created for sdk-annotations.
+        assert_eq!(map.0.len(), 1);
+        assert!(map.0.get(&ApiLevel(35)).unwrap().contains(&flags[0]));
+        assert!(map.0.get(&ApiLevel(35)).unwrap().contains(&flags[1]));
+    }
+
+    #[test]
+    fn test_read_flags_wrong_file_err() {
+        let flags = create_test_flags();
+
+        // Create the file <temp_dir>/35/finalized-flags.txt.
+        let temp_dir = tempdir().unwrap();
+        let mut file_path = temp_dir.path().to_path_buf();
+        file_path.push("35");
+        fs::create_dir_all(&file_path).unwrap();
+        file_path.push(FLAG_FILE_NAME);
+        let mut flag_file = File::create(&file_path).unwrap();
+
+        let mut pre_flag_path = temp_dir.path().to_path_buf();
+        pre_flag_path.push("18");
+        fs::create_dir_all(&pre_flag_path).unwrap();
+        pre_flag_path.push("some_random_file.txt");
+        File::create(&pre_flag_path).unwrap();
+
+        // Write all flags to the file.
+        add_flags_to_file(&mut flag_file, &[flags[0].clone(), flags[1].clone()]);
+        let flag_file_path = file_path.to_string_lossy().to_string();
+
+        // Convert to map.
+        let map = read_files_to_map_using_path(vec![
+            flag_file_path,
+            pre_flag_path.to_string_lossy().to_string(),
+        ]);
+
+        assert!(map.is_err());
+    }
+
+    #[test]
+    fn test_flags_map_insert_if_new() {
+        let flags = create_test_flags();
+        let mut map = FinalizedFlagMap::new();
+        let l35 = ApiLevel(35);
+        let l36 = ApiLevel(36);
+
+        map.insert_if_new(l35, flags[0].clone());
+        map.insert_if_new(l35, flags[1].clone());
+        map.insert_if_new(l35, flags[2].clone());
+        map.insert_if_new(l36, flags[0].clone());
+
+        assert!(map.0.get(&l35).unwrap().contains(&flags[0]));
+        assert!(map.0.get(&l35).unwrap().contains(&flags[1]));
+        assert!(map.0.get(&l35).unwrap().contains(&flags[2]));
+        assert!(!map.0.contains_key(&l36));
+    }
+
+    #[test]
+    fn test_flags_map_get_level() {
+        let flags = create_test_flags();
+        let mut map = FinalizedFlagMap::new();
+        let l35 = ApiLevel(35);
+        let l36 = ApiLevel(36);
+
+        map.insert_if_new(l35, flags[0].clone());
+        map.insert_if_new(l36, flags[1].clone());
+
+        assert_eq!(map.get_finalized_level(&flags[0]).unwrap(), l35);
+        assert_eq!(map.get_finalized_level(&flags[1]).unwrap(), l36);
+    }
+
+    #[test]
+    fn test_read_flag_from_extended_file() {
+        let flags = create_test_flags();
+
+        // Create the file <temp_dir>/35/extended_flags_list_35.txt
+        let temp_dir = tempdir().unwrap();
+        let mut file_path = temp_dir.path().to_path_buf();
+        file_path.push("35");
+        fs::create_dir_all(&file_path).unwrap();
+        file_path.push(EXTENDED_FLAGS_LIST_35);
+        let mut file = File::create(&file_path).unwrap();
+
+        // Write all flags to the file.
+        add_flags_to_file(&mut file, &[flags[0].clone(), flags[1].clone()]);
+
+        let flags_set =
+            read_extend_file_to_map_using_path(file_path.to_string_lossy().to_string()).unwrap();
+        assert_eq!(flags_set.len(), 2);
+        assert!(flags_set.contains(&flags[0]));
+        assert!(flags_set.contains(&flags[1]));
+    }
+
+    #[test]
+    fn test_read_flag_from_wrong_extended_file_err() {
+        let flags = create_test_flags();
+
+        // Create the file <temp_dir>/35/extended_flags_list.txt
+        let temp_dir = tempdir().unwrap();
+        let mut file_path = temp_dir.path().to_path_buf();
+        file_path.push("35");
+        fs::create_dir_all(&file_path).unwrap();
+        file_path.push("extended_flags_list.txt");
+        let mut file = File::create(&file_path).unwrap();
+
+        // Write all flags to the file.
+        add_flags_to_file(&mut file, &[flags[0].clone(), flags[1].clone()]);
+
+        let err = read_extend_file_to_map_using_path(file_path.to_string_lossy().to_string())
+            .unwrap_err();
+        assert_eq!(
+            format!("{:?}", err),
+            "Provided incorrect file, must be extended_flags_list_35.txt"
+        );
+    }
+
+    #[test]
+    fn test_parse_full_version_correct_input_major_dot_minor() {
+        let version = parse_full_version("12.34".to_string());
+
+        assert!(version.is_ok());
+        assert_eq!(version.unwrap(), 1_200_034);
+    }
+
+    #[test]
+    fn test_parse_full_version_correct_input_omit_dot_minor() {
+        let version = parse_full_version("1234".to_string());
+
+        assert!(version.is_ok());
+        assert_eq!(version.unwrap(), 123_400_000);
+    }
+
+    #[test]
+    fn test_parse_full_version_incorrect_input_empty_string() {
+        let version = parse_full_version("".to_string());
+
+        assert!(version.is_err());
+    }
+
+    #[test]
+    fn test_parse_full_version_incorrect_input_no_numbers_in_string() {
+        let version = parse_full_version("hello".to_string());
+
+        assert!(version.is_err());
+    }
+
+    #[test]
+    fn test_parse_full_version_incorrect_input_unexpected_patch_version() {
+        let version = parse_full_version("1.2.3".to_string());
+
+        assert!(version.is_err());
+    }
+
+    #[test]
+    fn test_parse_full_version_incorrect_input_leading_dot_missing_major_version() {
+        let version = parse_full_version(".1234".to_string());
+
+        assert!(version.is_err());
+    }
+
+    #[test]
+    fn test_parse_full_version_incorrect_input_trailing_dot_missing_minor_version() {
+        let version = parse_full_version("1234.".to_string());
+
+        assert!(version.is_err());
+    }
+
+    #[test]
+    fn test_parse_full_version_incorrect_input_negative_major_version() {
+        let version = parse_full_version("-12.34".to_string());
+
+        assert!(version.is_err());
+    }
+
+    #[test]
+    fn test_parse_full_version_incorrect_input_negative_minor_version() {
+        let version = parse_full_version("12.-34".to_string());
+
+        assert!(version.is_err());
+    }
+
+    #[test]
+    fn test_parse_full_version_incorrect_input_major_version_too_large() {
+        let version = parse_full_version("40000.1".to_string());
+
+        assert!(version.is_err());
+    }
+
+    #[test]
+    fn test_parse_full_version_incorrect_input_minor_version_too_large() {
+        let version = parse_full_version("3.99999999".to_string());
+
+        assert!(version.is_err());
+    }
+}
diff --git a/tools/aconfig/convert_finalized_flags/src/main.rs b/tools/aconfig/convert_finalized_flags/src/main.rs
new file mode 100644
index 0000000000..605e964d7e
--- /dev/null
+++ b/tools/aconfig/convert_finalized_flags/src/main.rs
@@ -0,0 +1,66 @@
+/*
+* Copyright (C) 2025 The Android Open Source Project
+*
+* Licensed under the Apache License, Version 2.0 (the "License");
+* you may not use this file except in compliance with the License.
+* You may obtain a copy of the License at
+*
+*      http://www.apache.org/licenses/LICENSE-2.0
+*
+* Unless required by applicable law or agreed to in writing, software
+* distributed under the License is distributed on an "AS IS" BASIS,
+* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+* See the License for the specific language governing permissions and
+* limitations under the License.
+*/
+//! convert_finalized_flags is a build time tool used to convert the finalized
+//! flags text files under prebuilts/sdk into structured data (FinalizedFlag
+//! struct).
+//! This binary is intended to run as part of a genrule to create a json file
+//! which is provided to the aconfig binary that creates the codegen.
+//! Usage:
+//! cargo run -- --flag-files-path path/to/prebuilts/sdk/finalized-flags.txt file2.txt etc
+use anyhow::Result;
+use clap::Parser;
+
+use convert_finalized_flags::{
+    read_extend_file_to_map_using_path, read_files_to_map_using_path, EXTENDED_FLAGS_35_APILEVEL,
+};
+
+const ABOUT_TEXT: &str = "Tool for processing finalized-flags.txt files.
+
+These files contain the list of qualified flag names that have been finalized,
+each on a newline. The directory of the flag file is the finalized API level.
+
+The output is a json map of API level to set of FinalizedFlag objects. The only
+supported use case for this tool is via a genrule at build time for aconfig
+codegen.
+
+Args:
+* `flag-files-path`: Space-separated list of absolute paths for the finalized
+flags files.
+";
+
+#[derive(Parser, Debug)]
+#[clap(long_about=ABOUT_TEXT, bin_name="convert-finalized-flags")]
+struct Cli {
+    /// Flags files.
+    #[arg(long = "flag_file_path")]
+    flag_file_path: Vec<String>,
+
+    #[arg(long)]
+    extended_flag_file_path: String,
+}
+
+fn main() -> Result<()> {
+    let cli = Cli::parse();
+    let mut finalized_flags_map = read_files_to_map_using_path(cli.flag_file_path)?;
+    let extended_flag_set = read_extend_file_to_map_using_path(cli.extended_flag_file_path)?;
+    for flag in extended_flag_set {
+        finalized_flags_map.insert_if_new(EXTENDED_FLAGS_35_APILEVEL, flag);
+    }
+
+    let json_str = serde_json::to_string(&finalized_flags_map)?;
+    println!("{}", json_str);
+    Ok(())
+}
diff --git a/tools/aconfig/printflags/Android.bp b/tools/aconfig/exported_flag_check/Android.bp
similarity index 57%
rename from tools/aconfig/printflags/Android.bp
rename to tools/aconfig/exported_flag_check/Android.bp
index d50a77d072..184149adac 100644
--- a/tools/aconfig/printflags/Android.bp
+++ b/tools/aconfig/exported_flag_check/Android.bp
@@ -3,7 +3,7 @@ package {
 }
 
 rust_defaults {
-    name: "printflags.defaults",
+    name: "exported-flag-check-defaults",
     edition: "2021",
     clippy_lints: "android",
     lints: "android",
@@ -11,18 +11,18 @@ rust_defaults {
     rustlibs: [
         "libaconfig_protos",
         "libanyhow",
-        "libprotobuf",
+        "libclap",
         "libregex",
     ],
 }
 
-rust_binary {
-    name: "printflags",
-    defaults: ["printflags.defaults"],
+rust_binary_host {
+    name: "exported-flag-check",
+    defaults: ["record-finalized-flags-defaults"],
 }
 
 rust_test_host {
-    name: "printflags.test",
-    defaults: ["printflags.defaults"],
+    name: "exported-flag-check-test",
+    defaults: ["record-finalized-flags-defaults"],
     test_suites: ["general-tests"],
 }
diff --git a/tools/aconfig/printflags/Cargo.toml b/tools/aconfig/exported_flag_check/Cargo.toml
similarity index 63%
rename from tools/aconfig/printflags/Cargo.toml
rename to tools/aconfig/exported_flag_check/Cargo.toml
index 7313f5d044..6bc07c5410 100644
--- a/tools/aconfig/printflags/Cargo.toml
+++ b/tools/aconfig/exported_flag_check/Cargo.toml
@@ -1,5 +1,5 @@
 [package]
-name = "printflags"
+name = "exported-flag-check"
 version = "0.1.0"
 edition = "2021"
 
@@ -8,8 +8,7 @@ default = ["cargo"]
 cargo = []
 
 [dependencies]
-anyhow = "1.0.69"
-paste = "1.0.11"
-protobuf = "3.2.0"
-regex = "1.10.3"
 aconfig_protos = { path = "../aconfig_protos" }
+anyhow = "1.0.69"
+clap = { version = "4.1.8", features = ["derive"] }
+regex = "1.11.1"
diff --git a/tools/aconfig/exported_flag_check/allow_flag_list.txt b/tools/aconfig/exported_flag_check/allow_flag_list.txt
new file mode 100644
index 0000000000..9c314c27d5
--- /dev/null
+++ b/tools/aconfig/exported_flag_check/allow_flag_list.txt
@@ -0,0 +1,400 @@
+android.adpf.adpf_viewrootimpl_action_down_boost
+android.app.admin.flags.coexistence_migration_for_supervision_enabled
+android.app.admin.flags.enable_supervision_service_sync
+android.app.admin.flags.lock_now_coexistence
+android.app.admin.flags.permission_migration_for_zero_trust_api_enabled
+android.app.admin.flags.reset_password_with_token_coexistence
+android.app.admin.flags.set_application_restrictions_coexistence
+android.app.admin.flags.set_backup_service_enabled_coexistence
+android.app.admin.flags.set_keyguard_disabled_features_coexistence
+android.app.admin.flags.set_permission_grant_state_coexistence
+android.app.app_restrictions_api
+android.app.enforce_pic_testmode_protocol
+android.app.job.backup_jobs_exemption
+android.app.pic_uses_shared_memory
+android.app.pinner_service_client_api
+android.app.supervision.flags.deprecate_dpm_supervision_apis
+android.app.supervision.flags.enable_sync_with_dpm
+android.app.supervision.flags.supervision_api
+android.app.supervision.flags.supervision_api_on_wear
+android.app.ui_rich_ongoing
+android.appwidget.flags.use_smaller_app_widget_system_radius
+android.car.feature.always_send_initial_value_event
+android.car.feature.android_b_vehicle_properties
+android.car.feature.android_vic_vehicle_properties
+android.car.feature.area_id_config_access
+android.car.feature.async_audio_service_init
+android.car.feature.audio_control_hal_configuration
+android.car.feature.audio_legacy_mode_navigation_volume
+android.car.feature.audio_vendor_freeze_improvements
+android.car.feature.batched_subscriptions
+android.car.feature.car_app_card
+android.car.feature.car_audio_dynamic_devices
+android.car.feature.car_audio_fade_manager_configuration
+android.car.feature.car_audio_min_max_activation_volume
+android.car.feature.car_audio_mute_ambiguity
+android.car.feature.car_evs_query_service_status
+android.car.feature.car_evs_stream_management
+android.car.feature.car_night_global_setting
+android.car.feature.car_power_cancel_shell_command
+android.car.feature.car_property_detailed_error_codes
+android.car.feature.car_property_supported_value
+android.car.feature.car_property_value_property_status
+android.car.feature.cluster_health_monitoring
+android.car.feature.display_compatibility
+android.car.feature.handle_property_events_in_binder_thread
+android.car.feature.persist_ap_settings
+android.car.feature.projection_query_bt_profile_inhibit
+android.car.feature.serverless_remote_access
+android.car.feature.subscription_with_resolution
+android.car.feature.supports_secure_passenger_users
+android.car.feature.switch_user_ignoring_uxr
+android.car.feature.variable_update_rate
+android.car.feature.visible_background_user_restrictions
+android.companion.new_association_builder
+android.companion.ongoing_perm_sync
+android.companion.virtualdevice.flags.camera_multiple_input_streams
+android.companion.virtualdevice.flags.notifications_for_device_streaming
+android.content.pm.get_package_storage_stats
+android.content.res.layout_readwrite_flags
+android.content.res.resources_minor_version_support
+android.content.res.rro_control_for_android_no_overlayable
+android.content.res.self_targeting_android_resource_frro
+android.content.res.system_context_handle_app_info_changed
+android.credentials.flags.settings_activity_enabled
+android.hardware.biometrics.screen_off_unlock_udfps
+android.hardware.devicestate.feature.flags.device_state_property_migration
+android.hardware.devicestate.feature.flags.device_state_rdm_v2
+android.hardware.devicestate.feature.flags.device_state_requester_cancel_state
+android.hardware.usb.flags.enable_interface_name_device_filter
+android.hardware.usb.flags.enable_is_mode_change_supported_api
+android.media.audio.focus_exclusive_with_recording
+android.media.audio.focus_freeze_test_api
+android.media.audio.foreground_audio_control
+android.media.audio.hardening_permission_api
+android.media.audio.hardening_permission_spa
+android.media.audio.ro_foreground_audio_control
+android.media.audiopolicy.audio_mix_test_api
+android.media.codec.aidl_hal_input_surface
+android.media.swcodec.flags.apv_software_codec
+android.media.swcodec.flags.mpeg2_keep_threads_active
+android.media.tv.flags.enable_le_audio_broadcast_ui
+android.media.tv.flags.enable_le_audio_unicast_ui
+android.media.tv.flags.hdmi_control_collect_physical_address
+android.media.tv.flags.hdmi_control_enhanced_behavior
+android.media.tv.flags.tif_unbind_inactive_tis
+android.multiuser.enable_biometrics_to_unlock_private_space
+android.net.platform.flags.mdns_improvement_for_25q2
+android.nfc.nfc_persist_log
+android.nfc.nfc_watchdog
+android.os.adpf_graphics_pipeline
+android.os.android_os_build_vanilla_ice_cream
+android.os.battery_saver_supported_check_api
+android.os.network_time_uses_shared_memory
+android.os.profiling.persist_queue
+android.os.profiling.redaction_enabled
+android.permission.flags.allow_host_permission_dialogs_on_virtual_devices
+android.permission.flags.device_aware_permissions_enabled
+android.permission.flags.device_policy_management_role_split_create_managed_profile_enabled
+android.permission.flags.enable_aiai_proxied_text_classifiers
+android.permission.flags.enable_otp_in_text_classifiers
+android.permission.flags.enable_sqlite_appops_accesses
+android.permission.flags.location_bypass_privacy_dashboard_enabled
+android.permission.flags.note_op_batching_enabled
+android.permission.flags.permission_request_short_circuit_enabled
+android.permission.flags.rate_limit_batched_note_op_async_callbacks_enabled
+android.permission.flags.sensitive_notification_app_protection
+android.permission.flags.supervision_role_permission_update_enabled
+android.permission.flags.unknown_call_package_install_blocking_enabled
+android.permission.flags.updatable_text_classifier_for_otp_detection_enabled
+android.permission.flags.use_profile_labels_for_default_app_section_titles
+android.permission.flags.wallet_role_cross_user_enabled
+android.provider.allow_config_maximum_call_log_entries_per_sim
+android.provider.backup_tasks_settings_screen
+android.provider.flags.new_storage_writer_system_api
+android.service.autofill.fill_dialog_improvements_impl
+android.service.chooser.fix_resolver_memory_leak
+android.service.notification.redact_sensitive_notifications_big_text_style
+android.service.notification.redact_sensitive_notifications_from_untrusted_listeners
+android.view.accessibility.motion_event_observing
+android.view.flags.expected_presentation_time_api
+android.view.flags.toolkit_frame_rate_touch_boost_25q1
+android.view.inputmethod.concurrent_input_methods
+android.view.inputmethod.ime_switcher_revamp
+android.view.inputmethod.imm_userhandle_hostsidetests
+android.webkit.mainline_apis
+android.widget.flags.use_wear_material3_ui
+com.android.aconfig.test.disabled_rw_exported
+com.android.aconfig.test.enabled_fixed_ro_exported
+com.android.aconfig.test.enabled_ro_exported
+com.android.aconfig.test.exported.exported_flag
+com.android.aconfig.test.forcereadonly.fro_exported
+com.android.adservices.ondevicepersonalization.flags.on_device_personalization_apis_enabled
+com.android.appsearch.flags.app_open_event_indexer_enabled
+com.android.appsearch.flags.apps_indexer_enabled
+com.android.appsearch.flags.enable_app_functions_schema_parser
+com.android.appsearch.flags.enable_apps_indexer_incremental_put
+com.android.appsearch.flags.enable_contacts_index_first_middle_and_last_names
+com.android.appsearch.flags.enable_document_limiter_replace_tracking
+com.android.appsearch.flags.enable_enterprise_empty_batch_result_fix
+com.android.bluetooth.flags.allow_switching_hid_and_hogp
+com.android.bluetooth.flags.bt_offload_socket_api
+com.android.bluetooth.flags.channel_sounding
+com.android.bluetooth.flags.fix_started_module_race
+com.android.bluetooth.flags.le_subrate_api
+com.android.bluetooth.flags.leaudio_broadcast_monitor_source_sync_status
+com.android.bluetooth.flags.leaudio_broadcast_volume_control_for_connected_devices
+com.android.bluetooth.flags.leaudio_multiple_vocs_instances_api
+com.android.bluetooth.flags.metadata_api_inactive_audio_device_upon_connection
+com.android.bluetooth.flags.settings_can_control_hap_preset
+com.android.bluetooth.flags.unix_file_socket_creation_failure
+com.android.graphics.flags.icon_load_drawable_return_null_when_uri_decode_fails
+com.android.graphics.hwui.flags.animated_image_drawable_filter_bitmap
+com.android.hardware.input.manage_key_gestures
+com.android.healthfitness.flags.activity_intensity_db
+com.android.healthfitness.flags.add_missing_access_logs
+com.android.healthfitness.flags.architecture_improvement
+com.android.healthfitness.flags.cloud_backup_and_restore
+com.android.healthfitness.flags.cycle_phases
+com.android.healthfitness.flags.d2d_file_deletion_bug_fix
+com.android.healthfitness.flags.dependency_injection
+com.android.healthfitness.flags.development_database
+com.android.healthfitness.flags.ecosystem_metrics
+com.android.healthfitness.flags.ecosystem_metrics_db_changes
+com.android.healthfitness.flags.export_import
+com.android.healthfitness.flags.export_import_fast_follow
+com.android.healthfitness.flags.export_import_nice_to_have
+com.android.healthfitness.flags.expressive_theming_enabled
+com.android.healthfitness.flags.health_connect_mappings
+com.android.healthfitness.flags.immediate_export
+com.android.healthfitness.flags.logcat_censor_iae
+com.android.healthfitness.flags.new_information_architecture
+com.android.healthfitness.flags.onboarding
+com.android.healthfitness.flags.permission_metrics
+com.android.healthfitness.flags.permission_tracker_fix_mapping_init
+com.android.healthfitness.flags.personal_health_record_database
+com.android.healthfitness.flags.personal_health_record_disable_d2d
+com.android.healthfitness.flags.personal_health_record_disable_export_import
+com.android.healthfitness.flags.personal_health_record_enable_d2d_and_export_import
+com.android.healthfitness.flags.personal_health_record_entries_screen
+com.android.healthfitness.flags.personal_health_record_lock_screen_banner
+com.android.healthfitness.flags.personal_health_record_telemetry
+com.android.healthfitness.flags.personal_health_record_telemetry_private_ww
+com.android.healthfitness.flags.personal_health_record_ui_telemetry
+com.android.healthfitness.flags.phr_fhir_basic_complex_type_validation
+com.android.healthfitness.flags.phr_fhir_complex_type_validation
+com.android.healthfitness.flags.phr_fhir_oneof_validation
+com.android.healthfitness.flags.phr_fhir_primitive_type_validation
+com.android.healthfitness.flags.phr_fhir_structural_validation
+com.android.healthfitness.flags.phr_read_medical_resources_fix_query_limit
+com.android.healthfitness.flags.phr_upsert_fix_parcel_size_calculation
+com.android.healthfitness.flags.phr_upsert_fix_use_shared_memory
+com.android.icu.icu_v_api
+com.android.internal.telephony.flags.async_init_carrier_privileges_tracker
+com.android.internal.telephony.flags.cleanup_carrier_app_update_enabled_state_logic
+com.android.internal.telephony.flags.oem_enabled_satellite_phase_2
+com.android.internal.telephony.flags.remap_disconnect_cause_sip_request_cancelled
+com.android.libcore.hpke_v_apis
+com.android.libcore.read_only_dynamic_code_load
+com.android.libcore.v_apis
+com.android.media.audio.hardening_impl
+com.android.media.audio.hardening_strict
+com.android.media.extractor.flags.extractor_mp4_enable_apv
+com.android.media.extractor.flags.extractor_sniff_midi_optimizations
+com.android.media.flags.enable_cross_user_routing_in_media_router2
+com.android.media.flags.enable_notifying_activity_manager_with_media_session_status_change
+com.android.media.metrics.flags.mediametrics_to_module
+com.android.media.projection.flags.media_projection_connected_display
+com.android.media.projection.flags.media_projection_connected_display_no_virtual_device
+com.android.net.ct.flags.certificate_transparency_job
+com.android.net.ct.flags.certificate_transparency_service
+com.android.net.flags.restrict_local_network
+com.android.net.flags.tethering_active_sessions_metrics
+com.android.net.thread.flags.thread_mobile_enabled
+com.android.nfc.module.flags.nfc_hce_latency_events
+com.android.org.conscrypt.flags.certificate_transparency_checkservertrusted_api
+com.android.permission.flags.add_banners_to_privacy_sensitive_apps_for_aaos
+com.android.permission.flags.app_permission_fragment_uses_preferences
+com.android.permission.flags.archiving_read_only
+com.android.permission.flags.decluttered_permission_manager_enabled
+com.android.permission.flags.enable_coarse_fine_location_prompt_for_aaos
+com.android.permission.flags.enhanced_confirmation_backport_enabled
+com.android.permission.flags.expressive_design_enabled
+com.android.permission.flags.livedata_refactor_permission_timeline_enabled
+com.android.permission.flags.odad_notifications_supported
+com.android.permission.flags.permission_timeline_attribution_label_fix
+com.android.permission.flags.private_profile_supported
+com.android.permission.flags.safety_center_enabled_no_device_config
+com.android.permission.flags.safety_center_issue_only_affects_group_status
+com.android.permission.flags.wear_compose_material3
+com.android.permission.flags.wear_privacy_dashboard_enabled_read_only
+com.android.providers.contactkeys.flags.contactkeys_strip_fix
+com.android.providers.media.flags.enable_backup_and_restore
+com.android.providers.media.flags.enable_malicious_app_detector
+com.android.providers.media.flags.enable_mark_media_as_favorite_api
+com.android.providers.media.flags.enable_modern_photopicker
+com.android.providers.media.flags.enable_photopicker_search
+com.android.providers.media.flags.enable_photopicker_transcoding
+com.android.providers.media.flags.enable_stable_uris_for_external_primary_volume
+com.android.providers.media.flags.enable_stable_uris_for_public_volume
+com.android.providers.media.flags.enable_unicode_check
+com.android.providers.media.flags.index_media_latitude_longitude
+com.android.providers.media.flags.version_lockdown
+com.android.ranging.flags.ranging_stack_updates_25q4
+com.android.server.backup.enable_read_all_external_storage_files
+com.android.server.telecom.flags.allow_system_apps_resolve_voip_calls
+com.android.server.telecom.flags.telecom_app_label_proxy_hsum_aware
+com.android.server.telecom.flags.telecom_main_user_in_block_check
+com.android.server.telecom.flags.telecom_main_user_in_get_respond_message_app
+com.android.server.updates.certificate_transparency_installer
+com.android.system.virtualmachine.flags.terminal_gui_support
+com.android.tradeinmode.flags.enable_trade_in_mode
+com.android.update_engine.minor_changes_2025q4
+com.android.uwb.flags.uwb_fira_3_0_25q4
+com.android.wifi.flags.network_provider_battery_charging_status
+com.android.wifi.flags.p2p_dialog2
+com.android.wifi.flags.shared_connectivity_broadcast_receiver_test_api
+com.android.wifi.flags.wep_disabled_in_apm
+com.android.window.flags.untrusted_embedding_state_sharing
+vendor.vibrator.hal.flags.enable_pwle_v2
+vendor.vibrator.hal.flags.remove_capo
+
+android.app.supervision.flags.enable_app_approval
+android.app.supervision.flags.enable_supervision_app_service
+android.app.supervision.flags.enable_supervision_pin_recovery_screen
+android.app.supervision.flags.enable_supervision_settings_screen
+android.app.supervision.flags.enable_web_content_filters_screen
+android.car.feature.display_compatibility_caption_bar
+android.companion.virtualdevice.flags.viewconfiguration_apis
+android.content.pm.always_load_past_certs_v4
+android.content.res.always_false
+android.content.res.use_new_aconfig_storage
+android.credentials.flags.propagate_user_context_for_intent_creation
+android.database.sqlite.concurrent_open_helper
+android.hardware.devicestate.feature.flags.device_state_configuration_flag
+android.media.audio.ringtone_user_uri_check
+android.media.soundtrigger.detection_service_paused_resumed_api
+android.media.tv.flags.tif_extension_standardization
+android.os.allow_thermal_hal_skin_forecast
+android.os.force_concurrent_message_queue
+android.permission.flags.enable_all_sqlite_appops_accesses
+android.permission.flags.grant_read_blocked_numbers_to_system_ui_intelligence
+android.permission.flags.record_all_runtime_appops_sqlite
+android.permission.flags.unknown_call_setting_blocked_logging_enabled
+android.server.wear_gesture_api
+android.view.accessibility.a11y_is_visited_api
+android.view.accessibility.request_rectangle_with_source
+android.view.contentcapture.flags.flush_after_each_frame
+com.android.adservices.flags.ad_id_cache_enabled
+com.android.adservices.flags.adservices_enablement_check_enabled
+com.android.adservices.flags.adservices_outcomereceiver_r_api_enabled
+com.android.adservices.flags.enable_adservices_api_enabled
+com.android.adservices.flags.sdksandbox_invalidate_effective_target_sdk_version_cache
+com.android.adservices.flags.sdksandbox_use_effective_target_sdk_version_for_restrictions
+com.android.appsearch.flags.enable_all_package_indexing_on_indexer_update
+com.android.appsearch.flags.enable_app_functions
+com.android.appsearch.flags.enable_app_open_events_indexer_check_prior_attempt
+com.android.appsearch.flags.enable_app_search_manage_blob_files
+com.android.appsearch.flags.enable_apps_indexer_check_prior_attempt
+com.android.appsearch.flags.enable_batch_put
+com.android.appsearch.flags.enable_calculate_time_since_last_attempted_optimize
+com.android.appsearch.flags.enable_check_contacts_indexer_delta_timestamps
+com.android.appsearch.flags.enable_check_contacts_indexer_update_job_params
+com.android.appsearch.flags.enable_four_hour_min_time_optimize_threshold
+com.android.appsearch.flags.enable_isolated_storage
+com.android.appsearch.flags.enable_marker_file_for_optimize
+com.android.appsearch.flags.enable_qualified_id_join_index_v3
+com.android.appsearch.flags.enable_recovery_proof_persistence
+com.android.appsearch.flags.enable_release_backup_schema_file_if_overlay_present
+com.android.appsearch.flags.enable_soft_index_restoration
+com.android.clockwork.flags.support_paired_device_none
+com.android.gms.flags.enable_deleted_gms
+com.android.gms.flags.enable_new_gms
+com.android.gms.flags.enable_optional_gms
+com.android.hardware.input.key_event_activity_detection
+com.android.healthfitness.flags.cloud_backup_and_restore_db
+com.android.healthfitness.flags.exercise_segment_weight
+com.android.healthfitness.flags.exercise_segment_weight_db
+com.android.healthfitness.flags.extend_export_import_telemetry
+com.android.healthfitness.flags.launch_onboarding_activity
+com.android.healthfitness.flags.personal_health_record_enable_export_import
+com.android.healthfitness.flags.phr_change_logs
+com.android.healthfitness.flags.phr_change_logs_db
+com.android.healthfitness.flags.phr_fhir_extension_validation
+com.android.healthfitness.flags.phr_fhir_resource_validator_use_weak_reference
+com.android.healthfitness.flags.phr_fhir_validation_disallow_empty_objects_arrays
+com.android.healthfitness.flags.refactor_aggregations
+com.android.healthfitness.flags.single_user_permission_intent_tracker
+com.android.healthfitness.flags.smoking
+com.android.healthfitness.flags.smoking_db
+com.android.healthfitness.flags.step_tracking_enabled
+com.android.healthfitness.flags.symptoms
+com.android.healthfitness.flags.symptoms_db
+com.android.icu.telephony_lookup_mcc_extension
+com.android.internal.telephony.flags.pass_copied_call_state_list
+com.android.internal.telephony.flags.robust_number_verification
+com.android.internal.telephony.flags.satellite_exit_p2p_session_outside_geofence
+com.android.internal.telephony.flags.starlink_data_bugfix
+com.android.media.audio.hardening_partial
+com.android.media.flags.enable_suggested_device_api
+com.android.media.flags.enable_use_of_singleton_audio_manager_route_controller
+com.android.media.projection.flags.app_content_sharing
+com.android.media.projection.flags.show_stop_dialog_post_call_end
+com.android.permission.flags.cross_user_role_ux_bugfix_enabled
+com.android.permission.flags.default_apps_recommendation_enabled
+com.android.permission.flags.fix_safety_center_touch_target
+com.android.providers.media.flags.enable_exclusion_list_for_default_folders
+com.android.providers.media.flags.enable_mime_type_fix_for_android_15
+com.android.providers.media.flags.exclude_unreliable_volumes
+com.android.providers.media.flags.revoke_access_owned_photos
+com.android.sdksandbox.flags.sandbox_activity_sdk_based_context
+com.android.sdksandbox.flags.selinux_input_selector
+com.android.sdksandbox.flags.selinux_sdk_sandbox_audit
+com.android.settings.flags.enable_remove_association_bt_unpair
+com.android.settingslib.widget.theme.flags.is_expressive_design_enabled
+com.android.window.flags.fix_hide_overlay_api
+com.android.window.flags.update_host_input_transfer_token
+com.fuchsia.bluetooth.flags.a2dp_lhdc_api
+com.fuchsia.bluetooth.flags.aics_api
+com.fuchsia.bluetooth.flags.allow_switching_hid_and_hogp
+com.fuchsia.bluetooth.flags.bt_offload_socket_api
+com.fuchsia.bluetooth.flags.bt_socket_api_l2cap_cid
+com.fuchsia.bluetooth.flags.channel_sounding
+com.fuchsia.bluetooth.flags.channel_sounding_25q2_apis
+com.fuchsia.bluetooth.flags.directed_advertising_api
+com.fuchsia.bluetooth.flags.encryption_change_broadcast
+com.fuchsia.bluetooth.flags.hci_vendor_specific_extension
+com.fuchsia.bluetooth.flags.identity_address_type_api
+com.fuchsia.bluetooth.flags.key_missing_public
+com.fuchsia.bluetooth.flags.leaudio_add_opus_codec_type
+com.fuchsia.bluetooth.flags.leaudio_broadcast_api_get_local_metadata
+com.fuchsia.bluetooth.flags.leaudio_broadcast_api_manage_primary_group
+com.fuchsia.bluetooth.flags.leaudio_broadcast_monitor_source_sync_status
+com.fuchsia.bluetooth.flags.leaudio_broadcast_volume_control_for_connected_devices
+com.fuchsia.bluetooth.flags.leaudio_mono_location_errata_api
+com.fuchsia.bluetooth.flags.leaudio_multiple_vocs_instances_api
+com.fuchsia.bluetooth.flags.metadata_api_inactive_audio_device_upon_connection
+com.fuchsia.bluetooth.flags.metadata_api_microphone_for_call_enabled
+com.fuchsia.bluetooth.flags.settings_can_control_hap_preset
+com.fuchsia.bluetooth.flags.socket_settings_api
+com.fuchsia.bluetooth.flags.support_bluetooth_quality_report_v6
+com.fuchsia.bluetooth.flags.support_exclusive_manager
+com.fuchsia.bluetooth.flags.support_metadata_device_types_apis
+com.fuchsia.bluetooth.flags.support_remote_device_metadata
+com.fuchsia.bluetooth.flags.unix_file_socket_creation_failure
+com.google.android.clockwork.pele.flags.koru_feature_cached_views
+com.google.android.clockwork.pele.flags.koru_origami
+com.google.android.device.pixel.watch.flags.pdms_flag_1
+com.google.android.haptics.flags.vendor_vibration_control
+com.google.clockwork.flags.prevent_ime_startup
+vendor.gc2.flags.mse_report
+vendor.google.plat_security.flags.enable_service
+vendor.google.plat_security.flags.enable_trusty_service
+vendor.google.wireless_charger.service.flags.enable_service
+
+android.hardware.biometrics.move_fm_api_to_bm
+android.hardware.serial.flags.enable_serial_api
+com.android.providers.media.flags.enable_local_media_provider_capabilities
+com.android.providers.media.flags.enable_photopicker_datescrubber
+com.android.system.virtualmachine.flags.terminal_storage_balloon
+com.android.tradeinmode.flags.trade_in_mode_2025q4
diff --git a/tools/aconfig/exported_flag_check/allow_package_list.txt b/tools/aconfig/exported_flag_check/allow_package_list.txt
new file mode 100644
index 0000000000..e76472b7ae
--- /dev/null
+++ b/tools/aconfig/exported_flag_check/allow_package_list.txt
@@ -0,0 +1,2 @@
+com.google.wear.sdk
+com.google.wear.services.infra.flags
diff --git a/tools/aconfig/exported_flag_check/src/main.rs b/tools/aconfig/exported_flag_check/src/main.rs
new file mode 100644
index 0000000000..866a700d02
--- /dev/null
+++ b/tools/aconfig/exported_flag_check/src/main.rs
@@ -0,0 +1,117 @@
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
+//! `exported-flag-check` is a tool to ensures that exported flags are used as intended
+use anyhow::{ensure, Result};
+use clap::Parser;
+use std::{collections::HashSet, fs::File, path::PathBuf};
+
+mod utils;
+
+use utils::{
+    check_all_exported_flags, extract_flagged_api_flags, get_exported_flags_from_binary_proto,
+    read_finalized_flags,
+};
+
+const ABOUT: &str = "CCheck Exported Flags
+
+This tool ensures that exported flags are used as intended. Exported flags, marked with
+`is_exported: true` in their declaration, are designed to control access to specific API
+features. This tool identifies and reports any exported flags that are not currently
+associated with an API feature, preventing unnecessary flag proliferation and maintaining
+a clear API design.
+
+This tool works as follows:
+
+  - Read API signature files from source tree (*current.txt files) [--api-signature-file]
+  - Read the current aconfig flag values from source tree [--parsed-flags-file]
+  - Read the previous finalized-flags.txt files from prebuilts/sdk [--finalized-flags-file]
+  - Extract the flags slated for API by scanning through the API signature files
+  - Merge the found flags with the recorded flags from previous API finalizations
+  - Error if exported flags are not in the set
+";
+
+#[derive(Parser, Debug)]
+#[clap(about=ABOUT)]
+struct Cli {
+    #[arg(long)]
+    parsed_flags_file: PathBuf,
+
+    #[arg(long)]
+    api_signature_file: Vec<PathBuf>,
+
+    #[arg(long)]
+    finalized_flags_file: PathBuf,
+}
+
+fn main() -> Result<()> {
+    let args = Cli::parse();
+
+    let mut flags_used_with_flaggedapi_annotation = HashSet::new();
+    for path in &args.api_signature_file {
+        let file = File::open(path)?;
+        let flags = extract_flagged_api_flags(file)?;
+        flags_used_with_flaggedapi_annotation.extend(flags);
+    }
+
+    let file = File::open(args.parsed_flags_file)?;
+    let all_flags = get_exported_flags_from_binary_proto(file)?;
+
+    let file = File::open(args.finalized_flags_file)?;
+    let already_finalized_flags = read_finalized_flags(file)?;
+
+    let exported_flags = check_all_exported_flags(
+        &flags_used_with_flaggedapi_annotation,
+        &all_flags,
+        &already_finalized_flags,
+    )?;
+
+    println!("{}", exported_flags.join("\n"));
+
+    ensure!(
+        exported_flags.is_empty(),
+        "Flags {} are exported but not used to guard any API. \
+    Exported flag should be used to guard API",
+        exported_flags.join(",")
+    );
+    Ok(())
+}
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+
+    #[test]
+    fn test() {
+        let input = include_bytes!("../tests/api-signature-file.txt");
+        let flags_used_with_flaggedapi_annotation = extract_flagged_api_flags(&input[..]).unwrap();
+
+        let input = include_bytes!("../tests/flags.protobuf");
+        let all_flags_to_be_finalized = get_exported_flags_from_binary_proto(&input[..]).unwrap();
+
+        let input = include_bytes!("../tests/finalized-flags.txt");
+        let already_finalized_flags = read_finalized_flags(&input[..]).unwrap();
+
+        let exported_flags = check_all_exported_flags(
+            &flags_used_with_flaggedapi_annotation,
+            &all_flags_to_be_finalized,
+            &already_finalized_flags,
+        )
+        .unwrap();
+
+        assert_eq!(1, exported_flags.len());
+    }
+}
diff --git a/tools/aconfig/exported_flag_check/src/utils.rs b/tools/aconfig/exported_flag_check/src/utils.rs
new file mode 100644
index 0000000000..3686fec739
--- /dev/null
+++ b/tools/aconfig/exported_flag_check/src/utils.rs
@@ -0,0 +1,149 @@
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
+use aconfig_protos::ParsedFlagExt;
+use anyhow::{anyhow, Context, Result};
+use regex::Regex;
+use std::{
+    collections::HashSet,
+    io::{BufRead, BufReader, Read},
+};
+
+pub(crate) type FlagId = String;
+
+/// Grep for all flags used with @FlaggedApi annotations in an API signature file (*current.txt
+/// file).
+pub(crate) fn extract_flagged_api_flags<R: Read>(mut reader: R) -> Result<HashSet<FlagId>> {
+    let mut haystack = String::new();
+    reader.read_to_string(&mut haystack)?;
+    let regex = Regex::new(r#"(?ms)@FlaggedApi\("(.*?)"\)"#).unwrap();
+    let iter = regex.captures_iter(&haystack).map(|cap| cap[1].to_owned());
+    Ok(HashSet::from_iter(iter))
+}
+
+/// Read a list of flag names. The input is expected to be plain text, with each line containing
+/// the name of a single flag.
+pub(crate) fn read_finalized_flags<R: Read>(reader: R) -> Result<HashSet<FlagId>> {
+    BufReader::new(reader)
+        .lines()
+        .map(|line_result| line_result.context("Failed to read line from finalized flags file"))
+        .collect()
+}
+
+/// Parse a ProtoParsedFlags binary protobuf blob and return the fully qualified names of flags
+/// have is_exported as true.
+pub(crate) fn get_exported_flags_from_binary_proto<R: Read>(
+    mut reader: R,
+) -> Result<HashSet<FlagId>> {
+    let mut buffer = Vec::new();
+    reader.read_to_end(&mut buffer)?;
+    let parsed_flags = aconfig_protos::parsed_flags::try_from_binary_proto(&buffer)
+        .map_err(|_| anyhow!("failed to parse binary proto"))?;
+    let iter = parsed_flags
+        .parsed_flag
+        .into_iter()
+        .filter(|flag| flag.is_exported())
+        .map(|flag| flag.fully_qualified_name());
+    Ok(HashSet::from_iter(iter))
+}
+
+fn get_allow_flag_list() -> Result<HashSet<FlagId>> {
+    let allow_list: HashSet<FlagId> =
+        include_str!("../allow_flag_list.txt").lines().map(|x| x.into()).collect();
+    Ok(allow_list)
+}
+
+fn get_allow_package_list() -> Result<HashSet<FlagId>> {
+    let allow_list: HashSet<FlagId> =
+        include_str!("../allow_package_list.txt").lines().map(|x| x.into()).collect();
+    Ok(allow_list)
+}
+
+/// Filter out the flags have is_exported as true but not used with @FlaggedApi annotations
+/// in the source tree, or in the previously finalized flags set.
+pub(crate) fn check_all_exported_flags(
+    flags_used_with_flaggedapi_annotation: &HashSet<FlagId>,
+    all_flags: &HashSet<FlagId>,
+    already_finalized_flags: &HashSet<FlagId>,
+) -> Result<Vec<FlagId>> {
+    let allow_flag_list = get_allow_flag_list()?;
+    let allow_package_list = get_allow_package_list()?;
+
+    let new_flags: Vec<FlagId> = all_flags
+        .difference(flags_used_with_flaggedapi_annotation)
+        .cloned()
+        .collect::<HashSet<_>>()
+        .difference(already_finalized_flags)
+        .cloned()
+        .collect::<HashSet<_>>()
+        .difference(&allow_flag_list)
+        .filter(|flag| {
+            if let Some(last_dot_index) = flag.rfind('.') {
+                let package_name = &flag[..last_dot_index];
+                !allow_package_list.contains(package_name)
+            } else {
+                true
+            }
+        })
+        .cloned()
+        .collect();
+
+    Ok(new_flags)
+}
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+
+    #[test]
+    fn test_extract_flagged_api_flags() {
+        let api_signature_file = include_bytes!("../tests/api-signature-file.txt");
+        let flags = extract_flagged_api_flags(&api_signature_file[..]).unwrap();
+        assert_eq!(
+            flags,
+            HashSet::from_iter(vec![
+                "record_finalized_flags.test.foo".to_string(),
+                "this.flag.is.not.used".to_string(),
+            ])
+        );
+    }
+
+    #[test]
+    fn test_read_finalized_flags() {
+        let input = include_bytes!("../tests/finalized-flags.txt");
+        let flags = read_finalized_flags(&input[..]).unwrap();
+        assert_eq!(
+            flags,
+            HashSet::from_iter(vec![
+                "record_finalized_flags.test.bar".to_string(),
+                "record_finalized_flags.test.baz".to_string(),
+            ])
+        );
+    }
+
+    #[test]
+    fn test_disabled_or_read_write_flags_are_ignored() {
+        let bytes = include_bytes!("../tests/flags.protobuf");
+        let flags = get_exported_flags_from_binary_proto(&bytes[..]).unwrap();
+        assert_eq!(
+            flags,
+            HashSet::from_iter(vec![
+                "record_finalized_flags.test.foo".to_string(),
+                "record_finalized_flags.test.not_enabled".to_string()
+            ])
+        );
+    }
+}
diff --git a/tools/aconfig/exported_flag_check/tests/api-signature-file.txt b/tools/aconfig/exported_flag_check/tests/api-signature-file.txt
new file mode 100644
index 0000000000..2ad559f0ad
--- /dev/null
+++ b/tools/aconfig/exported_flag_check/tests/api-signature-file.txt
@@ -0,0 +1,15 @@
+// Signature format: 2.0
+package android {
+
+  public final class C {
+    ctor public C();
+  }
+
+  public static final class C.inner {
+    ctor public C.inner();
+    field @FlaggedApi("record_finalized_flags.test.foo") public static final String FOO = "foo";
+    field @FlaggedApi("this.flag.is.not.used") public static final String BAR = "bar";
+  }
+
+}
+
diff --git a/tools/aconfig/exported_flag_check/tests/finalized-flags.txt b/tools/aconfig/exported_flag_check/tests/finalized-flags.txt
new file mode 100644
index 0000000000..7fbcb3dc65
--- /dev/null
+++ b/tools/aconfig/exported_flag_check/tests/finalized-flags.txt
@@ -0,0 +1,2 @@
+record_finalized_flags.test.bar
+record_finalized_flags.test.baz
diff --git a/tools/aconfig/exported_flag_check/tests/flags.declarations b/tools/aconfig/exported_flag_check/tests/flags.declarations
new file mode 100644
index 0000000000..f86dbfafbb
--- /dev/null
+++ b/tools/aconfig/exported_flag_check/tests/flags.declarations
@@ -0,0 +1,18 @@
+package: "record_finalized_flags.test"
+container: "system"
+
+flag {
+    name: "foo"
+    namespace: "test"
+    description: "FIXME"
+    bug: ""
+    is_exported:true
+}
+
+flag {
+    name: "not_enabled"
+    namespace: "test"
+    description: "FIXME"
+    bug: ""
+    is_exported:true
+}
diff --git a/tools/aconfig/exported_flag_check/tests/flags.protobuf b/tools/aconfig/exported_flag_check/tests/flags.protobuf
new file mode 100644
index 0000000000..be64ef9927
Binary files /dev/null and b/tools/aconfig/exported_flag_check/tests/flags.protobuf differ
diff --git a/tools/aconfig/exported_flag_check/tests/flags.values b/tools/aconfig/exported_flag_check/tests/flags.values
new file mode 100644
index 0000000000..ff6225d822
--- /dev/null
+++ b/tools/aconfig/exported_flag_check/tests/flags.values
@@ -0,0 +1,13 @@
+flag_value {
+    package: "record_finalized_flags.test"
+    name: "foo"
+    state: ENABLED
+    permission: READ_ONLY
+}
+
+flag_value {
+    package: "record_finalized_flags.test"
+    name: "not_enabled"
+    state: DISABLED
+    permission: READ_ONLY
+}
diff --git a/tools/aconfig/exported_flag_check/tests/generate-flags-protobuf.sh b/tools/aconfig/exported_flag_check/tests/generate-flags-protobuf.sh
new file mode 100755
index 0000000000..701189cd5c
--- /dev/null
+++ b/tools/aconfig/exported_flag_check/tests/generate-flags-protobuf.sh
@@ -0,0 +1,7 @@
+#!/bin/bash
+aconfig create-cache \
+    --package record_finalized_flags.test \
+    --container system \
+    --declarations flags.declarations \
+    --values flags.values \
+    --cache flags.protobuf
diff --git a/tools/aconfig/fake_device_config/Android.bp b/tools/aconfig/fake_device_config/Android.bp
index 1c5b7c5967..bf98058895 100644
--- a/tools/aconfig/fake_device_config/Android.bp
+++ b/tools/aconfig/fake_device_config/Android.bp
@@ -23,16 +23,6 @@ java_library {
     is_stubs_module: true,
 }
 
-java_library {
-    name: "strict_mode_stub",
-    srcs: [
-        "src/android/os/StrictMode.java",
-    ],
-    sdk_version: "core_current",
-    host_supported: true,
-    is_stubs_module: true,
-}
-
 java_library {
     name: "aconfig_storage_stub",
     srcs: [
diff --git a/tools/aconfig/fake_device_config/src/android/os/Build.java b/tools/aconfig/fake_device_config/src/android/os/Build.java
index 8ec72fb2dc..790ff82ad1 100644
--- a/tools/aconfig/fake_device_config/src/android/os/Build.java
+++ b/tools/aconfig/fake_device_config/src/android/os/Build.java
@@ -18,6 +18,9 @@ package android.os;
 
 public class Build {
     public static class VERSION {
-        public static final int SDK_INT = 0;
+        public static final int SDK_INT = placeholder();
+        private static int placeholder() {
+            throw new UnsupportedOperationException("Stub!");
+        }
     }
 }
diff --git a/tools/aconfig/fake_device_config/src/android/os/flagging/AconfigPackageInternal.java b/tools/aconfig/fake_device_config/src/android/os/flagging/AconfigPackageInternal.java
index d084048165..46058b664f 100644
--- a/tools/aconfig/fake_device_config/src/android/os/flagging/AconfigPackageInternal.java
+++ b/tools/aconfig/fake_device_config/src/android/os/flagging/AconfigPackageInternal.java
@@ -21,8 +21,7 @@ package android.os.flagging;
  */
 public class AconfigPackageInternal {
 
-    public static AconfigPackageInternal load(
-            String container, String packageName, long packageFingerprint) {
+    public static AconfigPackageInternal load(String packageName, long packageFingerprint) {
         throw new UnsupportedOperationException("Stub!");
     }
 
diff --git a/tools/aconfig/fake_device_config/src/android/os/flagging/AconfigStorageReadException.java b/tools/aconfig/fake_device_config/src/android/os/flagging/AconfigStorageReadException.java
deleted file mode 100644
index bfec98ccb1..0000000000
--- a/tools/aconfig/fake_device_config/src/android/os/flagging/AconfigStorageReadException.java
+++ /dev/null
@@ -1,61 +0,0 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-package android.os.flagging;
-
-public class AconfigStorageReadException extends RuntimeException {
-
-    /** Generic error code indicating an unspecified Aconfig Storage error. */
-    public static final int ERROR_GENERIC = 0;
-
-    /** Error code indicating that the Aconfig Storage system is not found on the device. */
-    public static final int ERROR_STORAGE_SYSTEM_NOT_FOUND = 1;
-
-    /** Error code indicating that the requested configuration package is not found. */
-    public static final int ERROR_PACKAGE_NOT_FOUND = 2;
-
-    /** Error code indicating that the specified container is not found. */
-    public static final int ERROR_CONTAINER_NOT_FOUND = 3;
-
-    /** Error code indicating that there was an error reading the Aconfig Storage file. */
-    public static final int ERROR_CANNOT_READ_STORAGE_FILE = 4;
-
-    public static final int ERROR_FILE_FINGERPRINT_MISMATCH = 5;
-
-    public AconfigStorageReadException(int errorCode, String msg) {
-        super(msg);
-        throw new UnsupportedOperationException("Stub!");
-    }
-
-    public AconfigStorageReadException(int errorCode, String msg, Throwable cause) {
-        super(msg, cause);
-        throw new UnsupportedOperationException("Stub!");
-    }
-
-    public AconfigStorageReadException(int errorCode, Throwable cause) {
-        super(cause);
-        throw new UnsupportedOperationException("Stub!");
-    }
-
-    public int getErrorCode() {
-        throw new UnsupportedOperationException("Stub!");
-    }
-
-    @Override
-    public String getMessage() {
-        throw new UnsupportedOperationException("Stub!");
-    }
-}
diff --git a/tools/aconfig/fake_device_config/src/android/os/flagging/PlatformAconfigPackage.java b/tools/aconfig/fake_device_config/src/android/os/flagging/PlatformAconfigPackage.java
new file mode 100644
index 0000000000..c06a532dc3
--- /dev/null
+++ b/tools/aconfig/fake_device_config/src/android/os/flagging/PlatformAconfigPackage.java
@@ -0,0 +1,40 @@
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
+package android.os.flagging;
+
+import java.util.Set;
+
+/*
+ * This class allows generated aconfig code to compile independently of the framework.
+ */
+public class PlatformAconfigPackage {
+
+    public static final Set<String> PLATFORM_PACKAGE_MAP_FILES =
+            Set.of(
+                    "system.package.map",
+                    "system_ext.package.map",
+                    "vendor.package.map",
+                    "product.package.map");
+
+    public static PlatformAconfigPackage load(String packageName) {
+        throw new UnsupportedOperationException("Stub!");
+    }
+
+    public boolean getBooleanFlagValue(String flagName, boolean defaultValue) {
+        throw new UnsupportedOperationException("Stub!");
+    }
+}
diff --git a/tools/aconfig/fake_device_config/src/android/os/flagging/PlatformAconfigPackageInternal.java b/tools/aconfig/fake_device_config/src/android/os/flagging/PlatformAconfigPackageInternal.java
index 283b251010..378c963ba4 100644
--- a/tools/aconfig/fake_device_config/src/android/os/flagging/PlatformAconfigPackageInternal.java
+++ b/tools/aconfig/fake_device_config/src/android/os/flagging/PlatformAconfigPackageInternal.java
@@ -21,8 +21,7 @@ package android.os.flagging;
  */
 public class PlatformAconfigPackageInternal {
 
-    public static PlatformAconfigPackageInternal load(
-            String container, String packageName, long packageFingerprint) {
+    public static PlatformAconfigPackageInternal load(String packageName, long packageFingerprint) {
         throw new UnsupportedOperationException("Stub!");
     }
 
diff --git a/tools/aconfig/fake_device_config/src/android/util/Log.java b/tools/aconfig/fake_device_config/src/android/util/Log.java
index 79de68060e..e40790a432 100644
--- a/tools/aconfig/fake_device_config/src/android/util/Log.java
+++ b/tools/aconfig/fake_device_config/src/android/util/Log.java
@@ -2,18 +2,18 @@ package android.util;
 
 public final class Log {
     public static int i(String tag, String msg) {
-        return 0;
+        throw new UnsupportedOperationException("Stub!");
     }
 
     public static int w(String tag, String msg) {
-        return 0;
+        throw new UnsupportedOperationException("Stub!");
     }
 
     public static int e(String tag, String msg) {
-        return 0;
+        throw new UnsupportedOperationException("Stub!");
     }
 
     public static int e(String tag, String msg, Throwable tr) {
-        return 0;
+        throw new UnsupportedOperationException("Stub!");
     }
 }
diff --git a/tools/aconfig/printflags/src/main.rs b/tools/aconfig/printflags/src/main.rs
deleted file mode 100644
index 7838b51e62..0000000000
--- a/tools/aconfig/printflags/src/main.rs
+++ /dev/null
@@ -1,152 +0,0 @@
-/*
- * Copyright (C) 2023 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-//! `printflags` is a device binary to print feature flags.
-
-use aconfig_protos::ProtoFlagState as State;
-use aconfig_protos::ProtoParsedFlags;
-use anyhow::{bail, Context, Result};
-use regex::Regex;
-use std::collections::BTreeMap;
-use std::collections::HashMap;
-use std::process::Command;
-use std::{fs, str};
-
-fn parse_device_config(raw: &str) -> HashMap<String, String> {
-    let mut flags = HashMap::new();
-    let regex = Regex::new(r"(?m)^([[[:alnum:]]_]+/[[[:alnum:]]_\.]+)=(true|false)$").unwrap();
-    for capture in regex.captures_iter(raw) {
-        let key = capture.get(1).unwrap().as_str().to_string();
-        let value = match capture.get(2).unwrap().as_str() {
-            "true" => format!("{:?} (device_config)", State::ENABLED),
-            "false" => format!("{:?} (device_config)", State::DISABLED),
-            _ => panic!(),
-        };
-        flags.insert(key, value);
-    }
-    flags
-}
-
-fn xxd(bytes: &[u8]) -> String {
-    let n = 8.min(bytes.len());
-    let mut v = Vec::with_capacity(n);
-    for byte in bytes.iter().take(n) {
-        v.push(format!("{:02x}", byte));
-    }
-    let trailer = match bytes.len() {
-        0..=8 => "",
-        _ => " ..",
-    };
-    format!("[{}{}]", v.join(" "), trailer)
-}
-
-fn main() -> Result<()> {
-    // read device_config
-    let output = Command::new("/system/bin/device_config").arg("list").output()?;
-    if !output.status.success() {
-        let reason = match output.status.code() {
-            Some(code) => format!("exit code {}", code),
-            None => "terminated by signal".to_string(),
-        };
-        bail!("failed to execute device_config: {}", reason);
-    }
-    let dc_stdout = str::from_utf8(&output.stdout)?;
-    let device_config_flags = parse_device_config(dc_stdout);
-
-    // read aconfig_flags.pb files
-    let apex_pattern = Regex::new(r"^/apex/[^@]+\.[^@]+$").unwrap();
-    let mut mount_points = vec![
-        "system".to_string(),
-        "system_ext".to_string(),
-        "product".to_string(),
-        "vendor".to_string(),
-    ];
-    for apex in fs::read_dir("/apex")? {
-        let path_name = apex?.path().display().to_string();
-        if let Some(canonical_path) = apex_pattern.captures(&path_name) {
-            mount_points.push(canonical_path.get(0).unwrap().as_str().to_owned());
-        }
-    }
-
-    let mut flags: BTreeMap<String, Vec<String>> = BTreeMap::new();
-    for mount_point in mount_points {
-        let path = format!("/{}/etc/aconfig_flags.pb", mount_point);
-        let Ok(bytes) = fs::read(&path) else {
-            eprintln!("warning: failed to read {}", path);
-            continue;
-        };
-        let parsed_flags: ProtoParsedFlags = protobuf::Message::parse_from_bytes(&bytes)
-            .with_context(|| {
-                format!("failed to parse {} ({}, {} byte(s))", path, xxd(&bytes), bytes.len())
-            })?;
-        for flag in parsed_flags.parsed_flag {
-            let key = format!("{}/{}.{}", flag.namespace(), flag.package(), flag.name());
-            let value = format!("{:?} + {:?} ({})", flag.permission(), flag.state(), mount_point);
-            flags.entry(key).or_default().push(value);
-        }
-    }
-
-    // print flags
-    for (key, mut value) in flags {
-        if let Some(dc_value) = device_config_flags.get(&key) {
-            value.push(dc_value.to_string());
-        }
-        println!("{}: {}", key, value.join(", "));
-    }
-
-    Ok(())
-}
-
-#[cfg(test)]
-mod tests {
-    use super::*;
-
-    #[test]
-    fn test_parse_device_config() {
-        let input = r#"
-namespace_one/com.foo.bar.flag_one=true
-namespace_one/com.foo.bar.flag_two=false
-random_noise;
-namespace_two/android.flag_one=true
-namespace_two/android.flag_two=nonsense
-"#;
-        let expected = HashMap::from([
-            (
-                "namespace_one/com.foo.bar.flag_one".to_string(),
-                "ENABLED (device_config)".to_string(),
-            ),
-            (
-                "namespace_one/com.foo.bar.flag_two".to_string(),
-                "DISABLED (device_config)".to_string(),
-            ),
-            ("namespace_two/android.flag_one".to_string(), "ENABLED (device_config)".to_string()),
-        ]);
-        let actual = parse_device_config(input);
-        assert_eq!(expected, actual);
-    }
-
-    #[test]
-    fn test_xxd() {
-        let input = [0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9];
-        assert_eq!("[]", &xxd(&input[0..0]));
-        assert_eq!("[00]", &xxd(&input[0..1]));
-        assert_eq!("[00 01]", &xxd(&input[0..2]));
-        assert_eq!("[00 01 02 03 04 05 06]", &xxd(&input[0..7]));
-        assert_eq!("[00 01 02 03 04 05 06 07]", &xxd(&input[0..8]));
-        assert_eq!("[00 01 02 03 04 05 06 07 ..]", &xxd(&input[0..9]));
-        assert_eq!("[00 01 02 03 04 05 06 07 ..]", &xxd(&input));
-    }
-}
diff --git a/tools/check-flagged-apis/src/com/android/checkflaggedapis/CheckFlaggedApisTest.kt b/tools/check-flagged-apis/src/com/android/checkflaggedapis/CheckFlaggedApisTest.kt
index e07ac1dfd4..5acb54a082 100644
--- a/tools/check-flagged-apis/src/com/android/checkflaggedapis/CheckFlaggedApisTest.kt
+++ b/tools/check-flagged-apis/src/com/android/checkflaggedapis/CheckFlaggedApisTest.kt
@@ -34,7 +34,7 @@ private val API_SIGNATURE =
           ctor @FlaggedApi("android.flag.foo") public Clazz();
           field @FlaggedApi("android.flag.foo") public static final int FOO = 1; // 0x1
           method @FlaggedApi("android.flag.foo") public int getErrorCode();
-          method @FlaggedApi("android.flag.foo") public boolean setData(int, int[][], @NonNull android.util.Utility<T, U>);
+          method @FlaggedApi("android.flag.foo") public <T,U> boolean setData(int, int[][], @NonNull android.util.Utility<T, U>);
           method @FlaggedApi("android.flag.foo") public boolean setVariableData(int, android.util.Atom...);
           method @FlaggedApi("android.flag.foo") public boolean innerClassArg(android.Clazz.Builder);
         }
diff --git a/tools/check-flagged-apis/src/com/android/checkflaggedapis/Main.kt b/tools/check-flagged-apis/src/com/android/checkflaggedapis/Main.kt
index d323c200da..25cba9ce4a 100644
--- a/tools/check-flagged-apis/src/com/android/checkflaggedapis/Main.kt
+++ b/tools/check-flagged-apis/src/com/android/checkflaggedapis/Main.kt
@@ -282,7 +282,8 @@ internal fun parseApiSignature(path: String, input: InputStream): Set<Pair<Symbo
               callable.parameters().joinTo(this, separator = "") { it.type().internalName() }
               append(")")
             }
-            val symbol = Symbol.createMethod(callable.containingClass().qualifiedName(), callableSignature)
+            val symbol =
+                Symbol.createMethod(callable.containingClass().qualifiedName(), callableSignature)
             output.add(Pair(symbol, flag))
           }
         }
@@ -291,7 +292,7 @@ internal fun parseApiSignature(path: String, input: InputStream): Set<Pair<Symbo
           return item.modifiers
               .findAnnotation("android.annotation.FlaggedApi")
               ?.findAttribute("value")
-              ?.value
+              ?.legacyValue
               ?.let { Flag(it.value() as String) }
         }
       }
@@ -468,8 +469,7 @@ internal fun findErrors(
         val classFlagValue =
             flaggedSymbolsInSource
                 .find { it.first.toPrettyString() == symbol.clazz }
-                ?.let { flags.getValue(it.second) }
-                ?: true
+                ?.let { flags.getValue(it.second) } ?: true
         return classFlagValue
       }
     }
diff --git a/tools/check_elf_file.py b/tools/check_elf_file.py
index 1fd7950bfe..064004179e 100755
--- a/tools/check_elf_file.py
+++ b/tools/check_elf_file.py
@@ -42,8 +42,9 @@ _EM_ARM = 40
 _EM_X86_64 = 62
 _EM_AARCH64 = 183
 
-_KNOWN_MACHINES = {_EM_386, _EM_ARM, _EM_X86_64, _EM_AARCH64}
-
+_32_BIT_MACHINES = {_EM_386, _EM_ARM}
+_64_BIT_MACHINES = {_EM_X86_64, _EM_AARCH64}
+_KNOWN_MACHINES = _32_BIT_MACHINES | _64_BIT_MACHINES
 
 # ELF header struct
 _ELF_HEADER_STRUCT = (
@@ -483,6 +484,11 @@ class Checker(object):
       sys.exit(2)
 
   def check_max_page_size(self, max_page_size):
+    if self._file_under_test.header.e_machine in _32_BIT_MACHINES:
+      # Skip test on 32-bit machines. 16 KB pages is an arm64 feature
+      # and no 32-bit systems in Android use it.
+      return
+
     for alignment in self._file_under_test.alignments:
       if alignment % max_page_size != 0:
         self._error(f'Load segment has alignment {alignment} but '
diff --git a/tools/compliance/Android.bp b/tools/compliance/Android.bp
index ef5c760cfc..33f515b4a3 100644
--- a/tools/compliance/Android.bp
+++ b/tools/compliance/Android.bp
@@ -38,16 +38,6 @@ blueprint_go_binary {
     testSrcs: ["cmd/checkshare/checkshare_test.go"],
 }
 
-blueprint_go_binary {
-    name: "compliancenotice_bom",
-    srcs: ["cmd/bom/bom.go"],
-    deps: [
-        "compliance-module",
-        "soong-response",
-    ],
-    testSrcs: ["cmd/bom/bom_test.go"],
-}
-
 blueprint_go_binary {
     name: "compliancenotice_shippedlibs",
     srcs: ["cmd/shippedlibs/shippedlibs.go"],
@@ -131,22 +121,6 @@ blueprint_go_binary {
     testSrcs: ["cmd/xmlnotice/xmlnotice_test.go"],
 }
 
-blueprint_go_binary {
-    name: "compliance_sbom",
-    srcs: ["cmd/sbom/sbom.go"],
-    deps: [
-        "compliance-module",
-        "blueprint-deptools",
-        "soong-response",
-        "spdx-tools-spdxv2_2",
-        "spdx-tools-builder2v2",
-        "spdx-tools-spdxcommon",
-        "spdx-tools-spdx-json",
-        "spdx-tools-spdxlib",
-    ],
-    testSrcs: ["cmd/sbom/sbom_test.go"],
-}
-
 bootstrap_go_package {
     name: "compliance-module",
     srcs: [
diff --git a/tools/compliance/cmd/bom/bom.go b/tools/compliance/cmd/bom/bom.go
deleted file mode 100644
index 187f828057..0000000000
--- a/tools/compliance/cmd/bom/bom.go
+++ /dev/null
@@ -1,189 +0,0 @@
-// Copyright 2021 Google LLC
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-package main
-
-import (
-	"bytes"
-	"flag"
-	"fmt"
-	"io"
-	"io/fs"
-	"os"
-	"path/filepath"
-	"strings"
-
-	"android/soong/response"
-	"android/soong/tools/compliance"
-)
-
-var (
-	failNoneRequested = fmt.Errorf("\nNo license metadata files requested")
-	failNoLicenses    = fmt.Errorf("No licenses found")
-)
-
-type context struct {
-	stdout      io.Writer
-	stderr      io.Writer
-	rootFS      fs.FS
-	stripPrefix []string
-}
-
-func (ctx context) strip(installPath string) string {
-	for _, prefix := range ctx.stripPrefix {
-		if strings.HasPrefix(installPath, prefix) {
-			p := strings.TrimPrefix(installPath, prefix)
-			if 0 == len(p) {
-				continue
-			}
-			return p
-		}
-	}
-	return installPath
-}
-
-// newMultiString creates a flag that allows multiple values in an array.
-func newMultiString(flags *flag.FlagSet, name, usage string) *multiString {
-	var f multiString
-	flags.Var(&f, name, usage)
-	return &f
-}
-
-// multiString implements the flag `Value` interface for multiple strings.
-type multiString []string
-
-func (ms *multiString) String() string     { return strings.Join(*ms, ", ") }
-func (ms *multiString) Set(s string) error { *ms = append(*ms, s); return nil }
-
-func main() {
-	var expandedArgs []string
-	for _, arg := range os.Args[1:] {
-		if strings.HasPrefix(arg, "@") {
-			f, err := os.Open(strings.TrimPrefix(arg, "@"))
-			if err != nil {
-				fmt.Fprintln(os.Stderr, err.Error())
-				os.Exit(1)
-			}
-
-			respArgs, err := response.ReadRspFile(f)
-			f.Close()
-			if err != nil {
-				fmt.Fprintln(os.Stderr, err.Error())
-				os.Exit(1)
-			}
-			expandedArgs = append(expandedArgs, respArgs...)
-		} else {
-			expandedArgs = append(expandedArgs, arg)
-		}
-	}
-
-	flags := flag.NewFlagSet("flags", flag.ExitOnError)
-
-	flags.Usage = func() {
-		fmt.Fprintf(os.Stderr, `Usage: %s {options} file.meta_lic {file.meta_lic...}
-
-Outputs a bill of materials. i.e. the list of installed paths.
-
-Options:
-`, filepath.Base(os.Args[0]))
-		flags.PrintDefaults()
-	}
-
-	outputFile := flags.String("o", "-", "Where to write the bill of materials. (default stdout)")
-	stripPrefix := newMultiString(flags, "strip_prefix", "Prefix to remove from paths. i.e. path to root (multiple allowed)")
-
-	flags.Parse(expandedArgs)
-
-	// Must specify at least one root target.
-	if flags.NArg() == 0 {
-		flags.Usage()
-		os.Exit(2)
-	}
-
-	if len(*outputFile) == 0 {
-		flags.Usage()
-		fmt.Fprintf(os.Stderr, "must specify file for -o; use - for stdout\n")
-		os.Exit(2)
-	} else {
-		dir, err := filepath.Abs(filepath.Dir(*outputFile))
-		if err != nil {
-			fmt.Fprintf(os.Stderr, "cannot determine path to %q: %s\n", *outputFile, err)
-			os.Exit(1)
-		}
-		fi, err := os.Stat(dir)
-		if err != nil {
-			fmt.Fprintf(os.Stderr, "cannot read directory %q of %q: %s\n", dir, *outputFile, err)
-			os.Exit(1)
-		}
-		if !fi.IsDir() {
-			fmt.Fprintf(os.Stderr, "parent %q of %q is not a directory\n", dir, *outputFile)
-			os.Exit(1)
-		}
-	}
-
-	var ofile io.Writer
-	ofile = os.Stdout
-	if *outputFile != "-" {
-		ofile = &bytes.Buffer{}
-	}
-
-	ctx := &context{ofile, os.Stderr, compliance.FS, *stripPrefix}
-
-	err := billOfMaterials(ctx, flags.Args()...)
-	if err != nil {
-		if err == failNoneRequested {
-			flags.Usage()
-		}
-		fmt.Fprintf(os.Stderr, "%s\n", err.Error())
-		os.Exit(1)
-	}
-	if *outputFile != "-" {
-		err := os.WriteFile(*outputFile, ofile.(*bytes.Buffer).Bytes(), 0666)
-		if err != nil {
-			fmt.Fprintf(os.Stderr, "could not write output to %q: %s\n", *outputFile, err)
-			os.Exit(1)
-		}
-	}
-	os.Exit(0)
-}
-
-// billOfMaterials implements the bom utility.
-func billOfMaterials(ctx *context, files ...string) error {
-	// Must be at least one root file.
-	if len(files) < 1 {
-		return failNoneRequested
-	}
-
-	// Read the license graph from the license metadata files (*.meta_lic).
-	licenseGraph, err := compliance.ReadLicenseGraph(ctx.rootFS, ctx.stderr, files)
-	if err != nil {
-		return fmt.Errorf("Unable to read license metadata file(s) %q: %v\n", files, err)
-	}
-	if licenseGraph == nil {
-		return failNoLicenses
-	}
-
-	// rs contains all notice resolutions.
-	rs := compliance.ResolveNotices(licenseGraph)
-
-	ni, err := compliance.IndexLicenseTexts(ctx.rootFS, licenseGraph, rs)
-	if err != nil {
-		return fmt.Errorf("Unable to read license text file(s) for %q: %v\n", files, err)
-	}
-
-	for path := range ni.InstallPaths() {
-		fmt.Fprintln(ctx.stdout, ctx.strip(path))
-	}
-	return nil
-}
diff --git a/tools/compliance/cmd/bom/bom_test.go b/tools/compliance/cmd/bom/bom_test.go
deleted file mode 100644
index 87a3b50ac7..0000000000
--- a/tools/compliance/cmd/bom/bom_test.go
+++ /dev/null
@@ -1,322 +0,0 @@
-// Copyright 2021 Google LLC
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-package main
-
-import (
-	"bufio"
-	"bytes"
-	"fmt"
-	"os"
-	"strings"
-	"testing"
-
-	"android/soong/tools/compliance"
-)
-
-func TestMain(m *testing.M) {
-	// Change into the parent directory before running the tests
-	// so they can find the testdata directory.
-	if err := os.Chdir(".."); err != nil {
-		fmt.Printf("failed to change to testdata directory: %s\n", err)
-		os.Exit(1)
-	}
-	os.Exit(m.Run())
-}
-
-func Test(t *testing.T) {
-	tests := []struct {
-		condition   string
-		name        string
-		outDir      string
-		roots       []string
-		stripPrefix string
-		expectedOut []string
-	}{
-		{
-			condition:   "firstparty",
-			name:        "apex",
-			roots:       []string{"highest.apex.meta_lic"},
-			stripPrefix: "out/target/product/fictional",
-			expectedOut: []string{
-				"/system/apex/highest.apex",
-				"/system/apex/highest.apex/bin/bin1",
-				"/system/apex/highest.apex/bin/bin2",
-				"/system/apex/highest.apex/lib/liba.so",
-				"/system/apex/highest.apex/lib/libb.so",
-			},
-		},
-		{
-			condition:   "firstparty",
-			name:        "container",
-			roots:       []string{"container.zip.meta_lic"},
-			stripPrefix: "out/target/product/fictional/data/",
-			expectedOut: []string{
-				"container.zip",
-				"container.zip/bin1",
-				"container.zip/bin2",
-				"container.zip/liba.so",
-				"container.zip/libb.so",
-			},
-		},
-		{
-			condition:   "firstparty",
-			name:        "application",
-			roots:       []string{"application.meta_lic"},
-			stripPrefix: "out/target/product/fictional/bin/",
-			expectedOut: []string{"application"},
-		},
-		{
-			condition:   "firstparty",
-			name:        "binary",
-			roots:       []string{"bin/bin1.meta_lic"},
-			stripPrefix: "out/target/product/fictional/system/",
-			expectedOut: []string{"bin/bin1"},
-		},
-		{
-			condition:   "firstparty",
-			name:        "library",
-			roots:       []string{"lib/libd.so.meta_lic"},
-			stripPrefix: "out/target/product/fictional/system/",
-			expectedOut: []string{"lib/libd.so"},
-		},
-		{
-			condition: "notice",
-			name:      "apex",
-			roots:     []string{"highest.apex.meta_lic"},
-			expectedOut: []string{
-				"out/target/product/fictional/system/apex/highest.apex",
-				"out/target/product/fictional/system/apex/highest.apex/bin/bin1",
-				"out/target/product/fictional/system/apex/highest.apex/bin/bin2",
-				"out/target/product/fictional/system/apex/highest.apex/lib/liba.so",
-				"out/target/product/fictional/system/apex/highest.apex/lib/libb.so",
-			},
-		},
-		{
-			condition: "notice",
-			name:      "container",
-			roots:     []string{"container.zip.meta_lic"},
-			expectedOut: []string{
-				"out/target/product/fictional/data/container.zip",
-				"out/target/product/fictional/data/container.zip/bin1",
-				"out/target/product/fictional/data/container.zip/bin2",
-				"out/target/product/fictional/data/container.zip/liba.so",
-				"out/target/product/fictional/data/container.zip/libb.so",
-			},
-		},
-		{
-			condition:   "notice",
-			name:        "application",
-			roots:       []string{"application.meta_lic"},
-			expectedOut: []string{"out/target/product/fictional/bin/application"},
-		},
-		{
-			condition:   "notice",
-			name:        "binary",
-			roots:       []string{"bin/bin1.meta_lic"},
-			expectedOut: []string{"out/target/product/fictional/system/bin/bin1"},
-		},
-		{
-			condition:   "notice",
-			name:        "library",
-			roots:       []string{"lib/libd.so.meta_lic"},
-			expectedOut: []string{"out/target/product/fictional/system/lib/libd.so"},
-		},
-		{
-			condition:   "reciprocal",
-			name:        "apex",
-			roots:       []string{"highest.apex.meta_lic"},
-			stripPrefix: "out/target/product/fictional/system/apex/",
-			expectedOut: []string{
-				"highest.apex",
-				"highest.apex/bin/bin1",
-				"highest.apex/bin/bin2",
-				"highest.apex/lib/liba.so",
-				"highest.apex/lib/libb.so",
-			},
-		},
-		{
-			condition:   "reciprocal",
-			name:        "container",
-			roots:       []string{"container.zip.meta_lic"},
-			stripPrefix: "out/target/product/fictional/data/",
-			expectedOut: []string{
-				"container.zip",
-				"container.zip/bin1",
-				"container.zip/bin2",
-				"container.zip/liba.so",
-				"container.zip/libb.so",
-			},
-		},
-		{
-			condition:   "reciprocal",
-			name:        "application",
-			roots:       []string{"application.meta_lic"},
-			stripPrefix: "out/target/product/fictional/bin/",
-			expectedOut: []string{"application"},
-		},
-		{
-			condition:   "reciprocal",
-			name:        "binary",
-			roots:       []string{"bin/bin1.meta_lic"},
-			stripPrefix: "out/target/product/fictional/system/",
-			expectedOut: []string{"bin/bin1"},
-		},
-		{
-			condition:   "reciprocal",
-			name:        "library",
-			roots:       []string{"lib/libd.so.meta_lic"},
-			stripPrefix: "out/target/product/fictional/system/",
-			expectedOut: []string{"lib/libd.so"},
-		},
-		{
-			condition:   "restricted",
-			name:        "apex",
-			roots:       []string{"highest.apex.meta_lic"},
-			stripPrefix: "out/target/product/fictional/system/apex/",
-			expectedOut: []string{
-				"highest.apex",
-				"highest.apex/bin/bin1",
-				"highest.apex/bin/bin2",
-				"highest.apex/lib/liba.so",
-				"highest.apex/lib/libb.so",
-			},
-		},
-		{
-			condition:   "restricted",
-			name:        "container",
-			roots:       []string{"container.zip.meta_lic"},
-			stripPrefix: "out/target/product/fictional/data/",
-			expectedOut: []string{
-				"container.zip",
-				"container.zip/bin1",
-				"container.zip/bin2",
-				"container.zip/liba.so",
-				"container.zip/libb.so",
-			},
-		},
-		{
-			condition:   "restricted",
-			name:        "application",
-			roots:       []string{"application.meta_lic"},
-			stripPrefix: "out/target/product/fictional/bin/",
-			expectedOut: []string{"application"},
-		},
-		{
-			condition:   "restricted",
-			name:        "binary",
-			roots:       []string{"bin/bin1.meta_lic"},
-			stripPrefix: "out/target/product/fictional/system/",
-			expectedOut: []string{"bin/bin1"},
-		},
-		{
-			condition:   "restricted",
-			name:        "library",
-			roots:       []string{"lib/libd.so.meta_lic"},
-			stripPrefix: "out/target/product/fictional/system/",
-			expectedOut: []string{"lib/libd.so"},
-		},
-		{
-			condition:   "proprietary",
-			name:        "apex",
-			roots:       []string{"highest.apex.meta_lic"},
-			stripPrefix: "out/target/product/fictional/system/apex/",
-			expectedOut: []string{
-				"highest.apex",
-				"highest.apex/bin/bin1",
-				"highest.apex/bin/bin2",
-				"highest.apex/lib/liba.so",
-				"highest.apex/lib/libb.so",
-			},
-		},
-		{
-			condition:   "proprietary",
-			name:        "container",
-			roots:       []string{"container.zip.meta_lic"},
-			stripPrefix: "out/target/product/fictional/data/",
-			expectedOut: []string{
-				"container.zip",
-				"container.zip/bin1",
-				"container.zip/bin2",
-				"container.zip/liba.so",
-				"container.zip/libb.so",
-			},
-		},
-		{
-			condition:   "proprietary",
-			name:        "application",
-			roots:       []string{"application.meta_lic"},
-			stripPrefix: "out/target/product/fictional/bin/",
-			expectedOut: []string{"application"},
-		},
-		{
-			condition:   "proprietary",
-			name:        "binary",
-			roots:       []string{"bin/bin1.meta_lic"},
-			stripPrefix: "out/target/product/fictional/system/",
-			expectedOut: []string{"bin/bin1"},
-		},
-		{
-			condition:   "proprietary",
-			name:        "library",
-			roots:       []string{"lib/libd.so.meta_lic"},
-			stripPrefix: "out/target/product/fictional/system/",
-			expectedOut: []string{"lib/libd.so"},
-		},
-	}
-	for _, tt := range tests {
-		t.Run(tt.condition+" "+tt.name, func(t *testing.T) {
-			stdout := &bytes.Buffer{}
-			stderr := &bytes.Buffer{}
-
-			rootFiles := make([]string, 0, len(tt.roots))
-			for _, r := range tt.roots {
-				rootFiles = append(rootFiles, "testdata/"+tt.condition+"/"+r)
-			}
-
-			ctx := context{stdout, stderr, compliance.GetFS(tt.outDir), []string{tt.stripPrefix}}
-
-			err := billOfMaterials(&ctx, rootFiles...)
-			if err != nil {
-				t.Fatalf("bom: error = %v, stderr = %v", err, stderr)
-				return
-			}
-			if stderr.Len() > 0 {
-				t.Errorf("bom: gotStderr = %v, want none", stderr)
-			}
-
-			t.Logf("got stdout: %s", stdout.String())
-
-			t.Logf("want stdout: %s", strings.Join(tt.expectedOut, "\n"))
-
-			out := bufio.NewScanner(stdout)
-			lineno := 0
-			for out.Scan() {
-				line := out.Text()
-				if strings.TrimLeft(line, " ") == "" {
-					continue
-				}
-				if len(tt.expectedOut) <= lineno {
-					t.Errorf("bom: unexpected output at line %d: got %q, want nothing (wanted %d lines)", lineno+1, line, len(tt.expectedOut))
-				} else if tt.expectedOut[lineno] != line {
-					t.Errorf("bom: unexpected output at line %d: got %q, want %q", lineno+1, line, tt.expectedOut[lineno])
-				}
-				lineno++
-			}
-			for ; lineno < len(tt.expectedOut); lineno++ {
-				t.Errorf("bom: missing output line %d: ended early, want %q", lineno+1, tt.expectedOut[lineno])
-			}
-		})
-	}
-}
diff --git a/tools/compliance/cmd/sbom/sbom.go b/tools/compliance/cmd/sbom/sbom.go
deleted file mode 100644
index a53741ffb2..0000000000
--- a/tools/compliance/cmd/sbom/sbom.go
+++ /dev/null
@@ -1,547 +0,0 @@
-// Copyright 2022 Google LLC
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-package main
-
-import (
-	"bytes"
-	"crypto/sha1"
-	"encoding/hex"
-	"flag"
-	"fmt"
-	"io"
-	"io/fs"
-	"os"
-	"path/filepath"
-	"sort"
-	"strings"
-	"time"
-
-	"android/soong/response"
-	"android/soong/tools/compliance"
-	"android/soong/tools/compliance/projectmetadata"
-
-	"github.com/google/blueprint/deptools"
-
-	"github.com/spdx/tools-golang/builder/builder2v2"
-	spdx_json "github.com/spdx/tools-golang/json"
-	"github.com/spdx/tools-golang/spdx/common"
-	spdx "github.com/spdx/tools-golang/spdx/v2_2"
-	"github.com/spdx/tools-golang/spdxlib"
-)
-
-var (
-	failNoneRequested = fmt.Errorf("\nNo license metadata files requested")
-	failNoLicenses    = fmt.Errorf("No licenses found")
-)
-
-const NOASSERTION = "NOASSERTION"
-
-type context struct {
-	stdout       io.Writer
-	stderr       io.Writer
-	rootFS       fs.FS
-	product      string
-	stripPrefix  []string
-	creationTime creationTimeGetter
-	buildid      string
-}
-
-func (ctx context) strip(installPath string) string {
-	for _, prefix := range ctx.stripPrefix {
-		if strings.HasPrefix(installPath, prefix) {
-			p := strings.TrimPrefix(installPath, prefix)
-			if 0 == len(p) {
-				p = ctx.product
-			}
-			if 0 == len(p) {
-				continue
-			}
-			return p
-		}
-	}
-	return installPath
-}
-
-// newMultiString creates a flag that allows multiple values in an array.
-func newMultiString(flags *flag.FlagSet, name, usage string) *multiString {
-	var f multiString
-	flags.Var(&f, name, usage)
-	return &f
-}
-
-// multiString implements the flag `Value` interface for multiple strings.
-type multiString []string
-
-func (ms *multiString) String() string     { return strings.Join(*ms, ", ") }
-func (ms *multiString) Set(s string) error { *ms = append(*ms, s); return nil }
-
-func main() {
-	var expandedArgs []string
-	for _, arg := range os.Args[1:] {
-		if strings.HasPrefix(arg, "@") {
-			f, err := os.Open(strings.TrimPrefix(arg, "@"))
-			if err != nil {
-				fmt.Fprintln(os.Stderr, err.Error())
-				os.Exit(1)
-			}
-
-			respArgs, err := response.ReadRspFile(f)
-			f.Close()
-			if err != nil {
-				fmt.Fprintln(os.Stderr, err.Error())
-				os.Exit(1)
-			}
-			expandedArgs = append(expandedArgs, respArgs...)
-		} else {
-			expandedArgs = append(expandedArgs, arg)
-		}
-	}
-
-	flags := flag.NewFlagSet("flags", flag.ExitOnError)
-
-	flags.Usage = func() {
-		fmt.Fprintf(os.Stderr, `Usage: %s {options} file.meta_lic {file.meta_lic...}
-
-Outputs an SBOM.spdx.
-
-Options:
-`, filepath.Base(os.Args[0]))
-		flags.PrintDefaults()
-	}
-
-	outputFile := flags.String("o", "-", "Where to write the SBOM spdx file. (default stdout)")
-	depsFile := flags.String("d", "", "Where to write the deps file")
-	product := flags.String("product", "", "The name of the product for which the notice is generated.")
-	stripPrefix := newMultiString(flags, "strip_prefix", "Prefix to remove from paths. i.e. path to root (multiple allowed)")
-	buildid := flags.String("build_id", "", "Uniquely identifies the build. (default timestamp)")
-
-	flags.Parse(expandedArgs)
-
-	// Must specify at least one root target.
-	if flags.NArg() == 0 {
-		flags.Usage()
-		os.Exit(2)
-	}
-
-	if len(*outputFile) == 0 {
-		flags.Usage()
-		fmt.Fprintf(os.Stderr, "must specify file for -o; use - for stdout\n")
-		os.Exit(2)
-	} else {
-		dir, err := filepath.Abs(filepath.Dir(*outputFile))
-		if err != nil {
-			fmt.Fprintf(os.Stderr, "cannot determine path to %q: %s\n", *outputFile, err)
-			os.Exit(1)
-		}
-		fi, err := os.Stat(dir)
-		if err != nil {
-			fmt.Fprintf(os.Stderr, "cannot read directory %q of %q: %s\n", dir, *outputFile, err)
-			os.Exit(1)
-		}
-		if !fi.IsDir() {
-			fmt.Fprintf(os.Stderr, "parent %q of %q is not a directory\n", dir, *outputFile)
-			os.Exit(1)
-		}
-	}
-
-	var ofile io.Writer
-	ofile = os.Stdout
-	var obuf *bytes.Buffer
-	if *outputFile != "-" {
-		obuf = &bytes.Buffer{}
-		ofile = obuf
-	}
-
-	ctx := &context{ofile, os.Stderr, compliance.FS, *product, *stripPrefix, actualTime, *buildid}
-
-	spdxDoc, deps, err := sbomGenerator(ctx, flags.Args()...)
-
-	if err != nil {
-		if err == failNoneRequested {
-			flags.Usage()
-		}
-		fmt.Fprintf(os.Stderr, "%s\n", err.Error())
-		os.Exit(1)
-	}
-
-	// writing the spdx Doc created
-	if err := spdx_json.Save2_2(spdxDoc, ofile); err != nil {
-		fmt.Fprintf(os.Stderr, "failed to write document to %v: %v", *outputFile, err)
-		os.Exit(1)
-	}
-
-	if *outputFile != "-" {
-		err := os.WriteFile(*outputFile, obuf.Bytes(), 0666)
-		if err != nil {
-			fmt.Fprintf(os.Stderr, "could not write output to %q: %s\n", *outputFile, err)
-			os.Exit(1)
-		}
-	}
-
-	if *depsFile != "" {
-		err := deptools.WriteDepFile(*depsFile, *outputFile, deps)
-		if err != nil {
-			fmt.Fprintf(os.Stderr, "could not write deps to %q: %s\n", *depsFile, err)
-			os.Exit(1)
-		}
-	}
-	os.Exit(0)
-}
-
-type creationTimeGetter func() string
-
-// actualTime returns current time in UTC
-func actualTime() string {
-	t := time.Now().UTC()
-	return t.UTC().Format("2006-01-02T15:04:05Z")
-}
-
-// replaceSlashes replaces "/" by "-" for the library path to be used for packages & files SPDXID
-func replaceSlashes(x string) string {
-	return strings.ReplaceAll(x, "/", "-")
-}
-
-// stripDocName removes the outdir prefix and meta_lic suffix from a target Name
-func stripDocName(name string) string {
-	// remove outdir prefix
-	if strings.HasPrefix(name, "out/") {
-		name = name[4:]
-	}
-
-	// remove suffix
-	if strings.HasSuffix(name, ".meta_lic") {
-		name = name[:len(name)-9]
-	} else if strings.HasSuffix(name, "/meta_lic") {
-		name = name[:len(name)-9] + "/"
-	}
-
-	return name
-}
-
-// getPackageName returns a package name of a target Node
-func getPackageName(_ *context, tn *compliance.TargetNode) string {
-	return replaceSlashes(tn.Name())
-}
-
-// getDocumentName returns a package name of a target Node
-func getDocumentName(ctx *context, tn *compliance.TargetNode, pm *projectmetadata.ProjectMetadata) string {
-	if len(ctx.product) > 0 {
-		return replaceSlashes(ctx.product)
-	}
-	if len(tn.ModuleName()) > 0 {
-		if pm != nil {
-			return replaceSlashes(pm.Name() + ":" + tn.ModuleName())
-		}
-		return replaceSlashes(tn.ModuleName())
-	}
-
-	return stripDocName(replaceSlashes(tn.Name()))
-}
-
-// getDownloadUrl returns the download URL if available (GIT, SVN, etc..),
-// or NOASSERTION if not available, none determined or ambiguous
-func getDownloadUrl(_ *context, pm *projectmetadata.ProjectMetadata) string {
-	if pm == nil {
-		return NOASSERTION
-	}
-
-	urlsByTypeName := pm.UrlsByTypeName()
-	if urlsByTypeName == nil {
-		return NOASSERTION
-	}
-
-	url := urlsByTypeName.DownloadUrl()
-	if url == "" {
-		return NOASSERTION
-	}
-	return url
-}
-
-// getProjectMetadata returns the optimal project metadata for the target node
-func getProjectMetadata(_ *context, pmix *projectmetadata.Index,
-	tn *compliance.TargetNode) (*projectmetadata.ProjectMetadata, error) {
-	pms, err := pmix.MetadataForProjects(tn.Projects()...)
-	if err != nil {
-		return nil, fmt.Errorf("Unable to read projects for %q: %w\n", tn.Name(), err)
-	}
-	if len(pms) == 0 {
-		return nil, nil
-	}
-
-	// Getting the project metadata that contains most of the info needed for sbomGenerator
-	score := -1
-	index := -1
-	for i := 0; i < len(pms); i++ {
-		tempScore := 0
-		if pms[i].Name() != "" {
-			tempScore += 1
-		}
-		if pms[i].Version() != "" {
-			tempScore += 1
-		}
-		if pms[i].UrlsByTypeName().DownloadUrl() != "" {
-			tempScore += 1
-		}
-
-		if tempScore == score {
-			if pms[i].Project() < pms[index].Project() {
-				index = i
-			}
-		} else if tempScore > score {
-			score = tempScore
-			index = i
-		}
-	}
-	return pms[index], nil
-}
-
-// inputFiles returns the complete list of files read
-func inputFiles(lg *compliance.LicenseGraph, pmix *projectmetadata.Index, licenseTexts []string) []string {
-	projectMeta := pmix.AllMetadataFiles()
-	targets := lg.TargetNames()
-	files := make([]string, 0, len(licenseTexts)+len(targets)+len(projectMeta))
-	files = append(files, licenseTexts...)
-	files = append(files, targets...)
-	files = append(files, projectMeta...)
-	return files
-}
-
-// generateSPDXNamespace generates a unique SPDX Document Namespace using a SHA1 checksum
-func generateSPDXNamespace(buildid string, created string, files ...string) string {
-
-	seed := strings.Join(files, "")
-
-	if buildid == "" {
-		seed += created
-	} else {
-		seed += buildid
-	}
-
-	// Compute a SHA1 checksum of the seed.
-	hash := sha1.Sum([]byte(seed))
-	uuid := hex.EncodeToString(hash[:])
-
-	namespace := fmt.Sprintf("SPDXRef-DOCUMENT-%s", uuid)
-
-	return namespace
-}
-
-// sbomGenerator implements the spdx bom utility
-
-// SBOM is part of the new government regulation issued to improve national cyber security
-// and enhance software supply chain and transparency, see https://www.cisa.gov/sbom
-
-// sbomGenerator uses the SPDX standard, see the SPDX specification (https://spdx.github.io/spdx-spec/)
-// sbomGenerator is also following the internal google SBOM styleguide (http://goto.google.com/spdx-style-guide)
-func sbomGenerator(ctx *context, files ...string) (*spdx.Document, []string, error) {
-	// Must be at least one root file.
-	if len(files) < 1 {
-		return nil, nil, failNoneRequested
-	}
-
-	pmix := projectmetadata.NewIndex(ctx.rootFS)
-
-	lg, err := compliance.ReadLicenseGraph(ctx.rootFS, ctx.stderr, files)
-
-	if err != nil {
-		return nil, nil, fmt.Errorf("Unable to read license text file(s) for %q: %v\n", files, err)
-	}
-
-	// creating the packages section
-	pkgs := []*spdx.Package{}
-
-	// creating the relationship section
-	relationships := []*spdx.Relationship{}
-
-	// creating the license section
-	otherLicenses := []*spdx.OtherLicense{}
-
-	// spdx document name
-	var docName string
-
-	// main package name
-	var mainPkgName string
-
-	// implementing the licenses references for the packages
-	licenses := make(map[string]string)
-	concludedLicenses := func(licenseTexts []string) string {
-		licenseRefs := make([]string, 0, len(licenseTexts))
-		for _, licenseText := range licenseTexts {
-			license := strings.SplitN(licenseText, ":", 2)[0]
-			if _, ok := licenses[license]; !ok {
-				licenseRef := "LicenseRef-" + replaceSlashes(license)
-				licenses[license] = licenseRef
-			}
-
-			licenseRefs = append(licenseRefs, licenses[license])
-		}
-		if len(licenseRefs) > 1 {
-			return "(" + strings.Join(licenseRefs, " AND ") + ")"
-		} else if len(licenseRefs) == 1 {
-			return licenseRefs[0]
-		}
-		return "NONE"
-	}
-
-	isMainPackage := true
-	visitedNodes := make(map[*compliance.TargetNode]struct{})
-
-	// performing a Breadth-first top down walk of licensegraph and building package information
-	compliance.WalkTopDownBreadthFirst(nil, lg,
-		func(lg *compliance.LicenseGraph, tn *compliance.TargetNode, path compliance.TargetEdgePath) bool {
-			if err != nil {
-				return false
-			}
-			var pm *projectmetadata.ProjectMetadata
-			pm, err = getProjectMetadata(ctx, pmix, tn)
-			if err != nil {
-				return false
-			}
-
-			if isMainPackage {
-				docName = getDocumentName(ctx, tn, pm)
-				mainPkgName = replaceSlashes(getPackageName(ctx, tn))
-				isMainPackage = false
-			}
-
-			if len(path) == 0 {
-				// Add the describe relationship for the main package
-				rln := &spdx.Relationship{
-					RefA:         common.MakeDocElementID("" /* this document */, "DOCUMENT"),
-					RefB:         common.MakeDocElementID("", mainPkgName),
-					Relationship: "DESCRIBES",
-				}
-				relationships = append(relationships, rln)
-
-			} else {
-				// Check parent and identify annotation
-				parent := path[len(path)-1]
-				targetEdge := parent.Edge()
-				if targetEdge.IsRuntimeDependency() {
-					// Adding the dynamic link annotation RUNTIME_DEPENDENCY_OF relationship
-					rln := &spdx.Relationship{
-						RefA:         common.MakeDocElementID("", replaceSlashes(getPackageName(ctx, tn))),
-						RefB:         common.MakeDocElementID("", replaceSlashes(getPackageName(ctx, targetEdge.Target()))),
-						Relationship: "RUNTIME_DEPENDENCY_OF",
-					}
-					relationships = append(relationships, rln)
-
-				} else if targetEdge.IsDerivation() {
-					// Adding the  derivation annotation as a CONTAINS relationship
-					rln := &spdx.Relationship{
-						RefA:         common.MakeDocElementID("", replaceSlashes(getPackageName(ctx, targetEdge.Target()))),
-						RefB:         common.MakeDocElementID("", replaceSlashes(getPackageName(ctx, tn))),
-						Relationship: "CONTAINS",
-					}
-					relationships = append(relationships, rln)
-
-				} else if targetEdge.IsBuildTool() {
-					// Adding the toolchain annotation as a BUILD_TOOL_OF relationship
-					rln := &spdx.Relationship{
-						RefA:         common.MakeDocElementID("", replaceSlashes(getPackageName(ctx, tn))),
-						RefB:         common.MakeDocElementID("", replaceSlashes(getPackageName(ctx, targetEdge.Target()))),
-						Relationship: "BUILD_TOOL_OF",
-					}
-					relationships = append(relationships, rln)
-
-				} else {
-					panic(fmt.Errorf("Unknown dependency type: %v", targetEdge.Annotations()))
-				}
-			}
-
-			if _, alreadyVisited := visitedNodes[tn]; alreadyVisited {
-				return false
-			}
-			visitedNodes[tn] = struct{}{}
-			pkgName := getPackageName(ctx, tn)
-
-			// Making an spdx package and adding it to pkgs
-			pkg := &spdx.Package{
-				PackageName:             replaceSlashes(pkgName),
-				PackageDownloadLocation: getDownloadUrl(ctx, pm),
-				PackageSPDXIdentifier:   common.ElementID(replaceSlashes(pkgName)),
-				PackageLicenseConcluded: concludedLicenses(tn.LicenseTexts()),
-			}
-
-			if pm != nil && pm.Version() != "" {
-				pkg.PackageVersion = pm.Version()
-			} else {
-				pkg.PackageVersion = NOASSERTION
-			}
-
-			pkgs = append(pkgs, pkg)
-
-			return true
-		})
-
-	// Adding Non-standard licenses
-
-	licenseTexts := make([]string, 0, len(licenses))
-
-	for licenseText := range licenses {
-		licenseTexts = append(licenseTexts, licenseText)
-	}
-
-	sort.Strings(licenseTexts)
-
-	for _, licenseText := range licenseTexts {
-		// open the file
-		f, err := ctx.rootFS.Open(filepath.Clean(licenseText))
-		if err != nil {
-			return nil, nil, fmt.Errorf("error opening license text file %q: %w", licenseText, err)
-		}
-
-		// read the file
-		text, err := io.ReadAll(f)
-		if err != nil {
-			return nil, nil, fmt.Errorf("error reading license text file %q: %w", licenseText, err)
-		}
-		// Making an spdx License and adding it to otherLicenses
-		otherLicenses = append(otherLicenses, &spdx.OtherLicense{
-			LicenseName:       strings.Replace(licenses[licenseText], "LicenseRef-", "", -1),
-			LicenseIdentifier: string(licenses[licenseText]),
-			ExtractedText:     string(text),
-		})
-	}
-
-	deps := inputFiles(lg, pmix, licenseTexts)
-	sort.Strings(deps)
-
-	// Making the SPDX doc
-	ci, err := builder2v2.BuildCreationInfoSection2_2("Organization", "Google LLC", nil)
-	if err != nil {
-		return nil, nil, fmt.Errorf("Unable to build creation info section for SPDX doc: %v\n", err)
-	}
-
-	ci.Created = ctx.creationTime()
-
-	doc := &spdx.Document{
-		SPDXVersion:       "SPDX-2.2",
-		DataLicense:       "CC0-1.0",
-		SPDXIdentifier:    "DOCUMENT",
-		DocumentName:      docName,
-		DocumentNamespace: generateSPDXNamespace(ctx.buildid, ci.Created, files...),
-		CreationInfo:      ci,
-		Packages:          pkgs,
-		Relationships:     relationships,
-		OtherLicenses:     otherLicenses,
-	}
-
-	if err := spdxlib.ValidateDocument2_2(doc); err != nil {
-		return nil, nil, fmt.Errorf("Unable to validate the SPDX doc: %v\n", err)
-	}
-
-	return doc, deps, nil
-}
diff --git a/tools/compliance/cmd/sbom/sbom_test.go b/tools/compliance/cmd/sbom/sbom_test.go
deleted file mode 100644
index 13ba66db99..0000000000
--- a/tools/compliance/cmd/sbom/sbom_test.go
+++ /dev/null
@@ -1,2558 +0,0 @@
-// Copyright 2022 Google LLC
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-package main
-
-import (
-	"bytes"
-	"encoding/json"
-	"fmt"
-	"os"
-	"reflect"
-	"strings"
-	"testing"
-	"time"
-
-	"android/soong/tools/compliance"
-
-	"github.com/spdx/tools-golang/builder/builder2v2"
-	"github.com/spdx/tools-golang/spdx/common"
-	spdx "github.com/spdx/tools-golang/spdx/v2_2"
-)
-
-func TestMain(m *testing.M) {
-	// Change into the parent directory before running the tests
-	// so they can find the testdata directory.
-	if err := os.Chdir(".."); err != nil {
-		fmt.Printf("failed to change to testdata directory: %s\n", err)
-		os.Exit(1)
-	}
-	os.Exit(m.Run())
-}
-
-func Test(t *testing.T) {
-	tests := []struct {
-		condition    string
-		name         string
-		outDir       string
-		roots        []string
-		stripPrefix  string
-		expectedOut  *spdx.Document
-		expectedDeps []string
-	}{
-		{
-			condition: "firstparty",
-			name:      "apex",
-			roots:     []string{"highest.apex.meta_lic"},
-			expectedOut: &spdx.Document{
-				SPDXVersion:       "SPDX-2.2",
-				DataLicense:       "CC0-1.0",
-				SPDXIdentifier:    "DOCUMENT",
-				DocumentName:      "testdata-firstparty-highest.apex",
-				DocumentNamespace: generateSPDXNamespace("", "1970-01-01T00:00:00Z", "testdata/firstparty/highest.apex.meta_lic"),
-				CreationInfo:      getCreationInfo(t),
-				Packages: []*spdx.Package{
-					{
-						PackageName:             "testdata-firstparty-highest.apex.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-firstparty-highest.apex.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						PackageName:             "testdata-firstparty-bin-bin1.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-firstparty-bin-bin1.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						PackageName:             "testdata-firstparty-bin-bin2.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-firstparty-bin-bin2.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						PackageName:             "testdata-firstparty-lib-liba.so.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-firstparty-lib-liba.so.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						PackageName:             "testdata-firstparty-lib-libb.so.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-firstparty-lib-libb.so.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						PackageName:             "testdata-firstparty-lib-libc.a.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-firstparty-lib-libc.a.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						PackageName:             "testdata-firstparty-lib-libd.so.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-firstparty-lib-libd.so.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-				},
-				Relationships: []*spdx.Relationship{
-					{
-						RefA:         common.MakeDocElementID("", "DOCUMENT"),
-						RefB:         common.MakeDocElementID("", "testdata-firstparty-highest.apex.meta_lic"),
-						Relationship: "DESCRIBES",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-firstparty-highest.apex.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-firstparty-bin-bin1.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-firstparty-highest.apex.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-firstparty-bin-bin2.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-firstparty-highest.apex.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-firstparty-lib-liba.so.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-firstparty-highest.apex.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-firstparty-lib-libb.so.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-firstparty-bin-bin1.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-firstparty-lib-liba.so.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-firstparty-bin-bin1.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-firstparty-lib-libc.a.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-firstparty-lib-libb.so.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-firstparty-bin-bin2.meta_lic"),
-						Relationship: "RUNTIME_DEPENDENCY_OF",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-firstparty-lib-libd.so.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-firstparty-bin-bin2.meta_lic"),
-						Relationship: "RUNTIME_DEPENDENCY_OF",
-					},
-				},
-				OtherLicenses: []*spdx.OtherLicense{
-					{
-						LicenseIdentifier: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-						ExtractedText:     "&&&First Party License&&&\n",
-						LicenseName:       "testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-				},
-			},
-			expectedDeps: []string{
-				"testdata/firstparty/FIRST_PARTY_LICENSE",
-				"testdata/firstparty/bin/bin1.meta_lic",
-				"testdata/firstparty/bin/bin2.meta_lic",
-				"testdata/firstparty/highest.apex.meta_lic",
-				"testdata/firstparty/lib/liba.so.meta_lic",
-				"testdata/firstparty/lib/libb.so.meta_lic",
-				"testdata/firstparty/lib/libc.a.meta_lic",
-				"testdata/firstparty/lib/libd.so.meta_lic",
-			},
-		},
-		{
-			condition: "firstparty",
-			name:      "application",
-			roots:     []string{"application.meta_lic"},
-			expectedOut: &spdx.Document{
-				SPDXVersion:       "SPDX-2.2",
-				DataLicense:       "CC0-1.0",
-				SPDXIdentifier:    "DOCUMENT",
-				DocumentName:      "testdata-firstparty-application",
-				DocumentNamespace: generateSPDXNamespace("", "1970-01-01T00:00:00Z", "testdata/firstparty/application.meta_lic"),
-				CreationInfo:      getCreationInfo(t),
-				Packages: []*spdx.Package{
-					{
-						PackageName:             "testdata-firstparty-application.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-firstparty-application.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						PackageName:             "testdata-firstparty-bin-bin3.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-firstparty-bin-bin3.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						PackageName:             "testdata-firstparty-lib-liba.so.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-firstparty-lib-liba.so.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						PackageName:             "testdata-firstparty-lib-libb.so.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-firstparty-lib-libb.so.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-				},
-				Relationships: []*spdx.Relationship{
-					{
-						RefA:         common.MakeDocElementID("", "DOCUMENT"),
-						RefB:         common.MakeDocElementID("", "testdata-firstparty-application.meta_lic"),
-						Relationship: "DESCRIBES",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-firstparty-bin-bin3.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-firstparty-application.meta_lic"),
-						Relationship: "BUILD_TOOL_OF",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-firstparty-application.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-firstparty-lib-liba.so.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-firstparty-lib-libb.so.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-firstparty-application.meta_lic"),
-						Relationship: "RUNTIME_DEPENDENCY_OF",
-					},
-				},
-				OtherLicenses: []*spdx.OtherLicense{
-					{
-						LicenseIdentifier: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-						ExtractedText:     "&&&First Party License&&&\n",
-						LicenseName:       "testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-				},
-			},
-			expectedDeps: []string{
-				"testdata/firstparty/FIRST_PARTY_LICENSE",
-				"testdata/firstparty/application.meta_lic",
-				"testdata/firstparty/bin/bin3.meta_lic",
-				"testdata/firstparty/lib/liba.so.meta_lic",
-				"testdata/firstparty/lib/libb.so.meta_lic",
-			},
-		},
-		{
-			condition: "firstparty",
-			name:      "container",
-			roots:     []string{"container.zip.meta_lic"},
-			expectedOut: &spdx.Document{
-				SPDXVersion:       "SPDX-2.2",
-				DataLicense:       "CC0-1.0",
-				SPDXIdentifier:    "DOCUMENT",
-				DocumentName:      "testdata-firstparty-container.zip",
-				DocumentNamespace: generateSPDXNamespace("", "1970-01-01T00:00:00Z", "testdata/firstparty/container.zip.meta_lic"),
-				CreationInfo:      getCreationInfo(t),
-				Packages: []*spdx.Package{
-					{
-						PackageName:             "testdata-firstparty-container.zip.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-firstparty-container.zip.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						PackageName:             "testdata-firstparty-bin-bin1.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-firstparty-bin-bin1.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						PackageName:             "testdata-firstparty-bin-bin2.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-firstparty-bin-bin2.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						PackageName:             "testdata-firstparty-lib-liba.so.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-firstparty-lib-liba.so.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						PackageName:             "testdata-firstparty-lib-libb.so.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-firstparty-lib-libb.so.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						PackageName:             "testdata-firstparty-lib-libc.a.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-firstparty-lib-libc.a.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						PackageName:             "testdata-firstparty-lib-libd.so.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-firstparty-lib-libd.so.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-				},
-				Relationships: []*spdx.Relationship{
-					{
-						RefA:         common.MakeDocElementID("", "DOCUMENT"),
-						RefB:         common.MakeDocElementID("", "testdata-firstparty-container.zip.meta_lic"),
-						Relationship: "DESCRIBES",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-firstparty-container.zip.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-firstparty-bin-bin1.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-firstparty-container.zip.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-firstparty-bin-bin2.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-firstparty-container.zip.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-firstparty-lib-liba.so.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-firstparty-container.zip.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-firstparty-lib-libb.so.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-firstparty-bin-bin1.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-firstparty-lib-liba.so.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-firstparty-bin-bin1.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-firstparty-lib-libc.a.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-firstparty-lib-libb.so.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-firstparty-bin-bin2.meta_lic"),
-						Relationship: "RUNTIME_DEPENDENCY_OF",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-firstparty-lib-libd.so.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-firstparty-bin-bin2.meta_lic"),
-						Relationship: "RUNTIME_DEPENDENCY_OF",
-					},
-				},
-				OtherLicenses: []*spdx.OtherLicense{
-					{
-						LicenseIdentifier: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-						ExtractedText:     "&&&First Party License&&&\n",
-						LicenseName:       "testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-				},
-			},
-			expectedDeps: []string{
-				"testdata/firstparty/FIRST_PARTY_LICENSE",
-				"testdata/firstparty/bin/bin1.meta_lic",
-				"testdata/firstparty/bin/bin2.meta_lic",
-				"testdata/firstparty/container.zip.meta_lic",
-				"testdata/firstparty/lib/liba.so.meta_lic",
-				"testdata/firstparty/lib/libb.so.meta_lic",
-				"testdata/firstparty/lib/libc.a.meta_lic",
-				"testdata/firstparty/lib/libd.so.meta_lic",
-			},
-		},
-		{
-			condition: "firstparty",
-			name:      "binary",
-			roots:     []string{"bin/bin1.meta_lic"},
-			expectedOut: &spdx.Document{
-				SPDXVersion:       "SPDX-2.2",
-				DataLicense:       "CC0-1.0",
-				SPDXIdentifier:    "DOCUMENT",
-				DocumentName:      "testdata-firstparty-bin-bin1",
-				DocumentNamespace: generateSPDXNamespace("", "1970-01-01T00:00:00Z", "testdata/firstparty/bin/bin1.meta_lic"),
-				CreationInfo:      getCreationInfo(t),
-				Packages: []*spdx.Package{
-					{
-						PackageName:             "testdata-firstparty-bin-bin1.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-firstparty-bin-bin1.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						PackageName:             "testdata-firstparty-lib-liba.so.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-firstparty-lib-liba.so.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						PackageName:             "testdata-firstparty-lib-libc.a.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-firstparty-lib-libc.a.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-				},
-				Relationships: []*spdx.Relationship{
-					{
-						RefA:         common.MakeDocElementID("", "DOCUMENT"),
-						RefB:         common.MakeDocElementID("", "testdata-firstparty-bin-bin1.meta_lic"),
-						Relationship: "DESCRIBES",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-firstparty-bin-bin1.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-firstparty-lib-liba.so.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-firstparty-bin-bin1.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-firstparty-lib-libc.a.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-				},
-				OtherLicenses: []*spdx.OtherLicense{
-					{
-						LicenseIdentifier: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-						ExtractedText:     "&&&First Party License&&&\n",
-						LicenseName:       "testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-				},
-			},
-			expectedDeps: []string{
-				"testdata/firstparty/FIRST_PARTY_LICENSE",
-				"testdata/firstparty/bin/bin1.meta_lic",
-				"testdata/firstparty/lib/liba.so.meta_lic",
-				"testdata/firstparty/lib/libc.a.meta_lic",
-			},
-		},
-		{
-			condition: "firstparty",
-			name:      "library",
-			roots:     []string{"lib/libd.so.meta_lic"},
-			expectedOut: &spdx.Document{
-				SPDXVersion:       "SPDX-2.2",
-				DataLicense:       "CC0-1.0",
-				SPDXIdentifier:    "DOCUMENT",
-				DocumentName:      "testdata-firstparty-lib-libd.so",
-				DocumentNamespace: generateSPDXNamespace("", "1970-01-01T00:00:00Z", "testdata/firstparty/lib/libd.so.meta_lic"),
-				CreationInfo:      getCreationInfo(t),
-				Packages: []*spdx.Package{
-					{
-						PackageName:             "testdata-firstparty-lib-libd.so.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-firstparty-lib-libd.so.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-				},
-				Relationships: []*spdx.Relationship{
-					{
-						RefA:         common.MakeDocElementID("", "DOCUMENT"),
-						RefB:         common.MakeDocElementID("", "testdata-firstparty-lib-libd.so.meta_lic"),
-						Relationship: "DESCRIBES",
-					},
-				},
-				OtherLicenses: []*spdx.OtherLicense{
-					{
-						LicenseIdentifier: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-						ExtractedText:     "&&&First Party License&&&\n",
-						LicenseName:       "testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-				},
-			},
-			expectedDeps: []string{
-				"testdata/firstparty/FIRST_PARTY_LICENSE",
-				"testdata/firstparty/lib/libd.so.meta_lic",
-			},
-		},
-		{
-			condition: "notice",
-			name:      "apex",
-			roots:     []string{"highest.apex.meta_lic"},
-			expectedOut: &spdx.Document{
-				SPDXVersion:       "SPDX-2.2",
-				DataLicense:       "CC0-1.0",
-				SPDXIdentifier:    "DOCUMENT",
-				DocumentName:      "testdata-notice-highest.apex",
-				DocumentNamespace: generateSPDXNamespace("", "1970-01-01T00:00:00Z", "testdata/notice/highest.apex.meta_lic"),
-				CreationInfo:      getCreationInfo(t),
-				Packages: []*spdx.Package{
-					{
-						PackageName:             "testdata-notice-highest.apex.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-notice-highest.apex.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						PackageName:             "testdata-notice-bin-bin1.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-notice-bin-bin1.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						PackageName:             "testdata-notice-bin-bin2.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-notice-bin-bin2.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						PackageName:             "testdata-notice-lib-liba.so.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-notice-lib-liba.so.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-notice-NOTICE_LICENSE",
-					},
-					{
-						PackageName:             "testdata-notice-lib-libb.so.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-notice-lib-libb.so.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						PackageName:             "testdata-notice-lib-libc.a.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-notice-lib-libc.a.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-notice-NOTICE_LICENSE",
-					},
-					{
-						PackageName:             "testdata-notice-lib-libd.so.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-notice-lib-libd.so.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-notice-NOTICE_LICENSE",
-					},
-				},
-				Relationships: []*spdx.Relationship{
-					{
-						RefA:         common.MakeDocElementID("", "DOCUMENT"),
-						RefB:         common.MakeDocElementID("", "testdata-notice-highest.apex.meta_lic"),
-						Relationship: "DESCRIBES",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-notice-highest.apex.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-notice-bin-bin1.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-notice-highest.apex.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-notice-bin-bin2.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-notice-highest.apex.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-notice-lib-liba.so.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-notice-highest.apex.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-notice-lib-libb.so.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-notice-bin-bin1.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-notice-lib-liba.so.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-notice-bin-bin1.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-notice-lib-libc.a.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-notice-lib-libb.so.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-notice-bin-bin2.meta_lic"),
-						Relationship: "RUNTIME_DEPENDENCY_OF",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-notice-lib-libd.so.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-notice-bin-bin2.meta_lic"),
-						Relationship: "RUNTIME_DEPENDENCY_OF",
-					},
-				},
-				OtherLicenses: []*spdx.OtherLicense{
-					{
-						LicenseIdentifier: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-						ExtractedText:     "&&&First Party License&&&\n",
-						LicenseName:       "testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						LicenseIdentifier: "LicenseRef-testdata-notice-NOTICE_LICENSE",
-						ExtractedText:     "%%%Notice License%%%\n",
-						LicenseName:       "testdata-notice-NOTICE_LICENSE",
-					},
-				},
-			},
-			expectedDeps: []string{
-				"testdata/firstparty/FIRST_PARTY_LICENSE",
-				"testdata/notice/NOTICE_LICENSE",
-				"testdata/notice/bin/bin1.meta_lic",
-				"testdata/notice/bin/bin2.meta_lic",
-				"testdata/notice/highest.apex.meta_lic",
-				"testdata/notice/lib/liba.so.meta_lic",
-				"testdata/notice/lib/libb.so.meta_lic",
-				"testdata/notice/lib/libc.a.meta_lic",
-				"testdata/notice/lib/libd.so.meta_lic",
-			},
-		},
-		{
-			condition: "notice",
-			name:      "container",
-			roots:     []string{"container.zip.meta_lic"},
-			expectedOut: &spdx.Document{
-				SPDXVersion:       "SPDX-2.2",
-				DataLicense:       "CC0-1.0",
-				SPDXIdentifier:    "DOCUMENT",
-				DocumentName:      "testdata-notice-container.zip",
-				DocumentNamespace: generateSPDXNamespace("", "1970-01-01T00:00:00Z", "testdata/notice/container.zip.meta_lic"),
-				CreationInfo:      getCreationInfo(t),
-				Packages: []*spdx.Package{
-					{
-						PackageName:             "testdata-notice-container.zip.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-notice-container.zip.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						PackageName:             "testdata-notice-bin-bin1.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-notice-bin-bin1.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						PackageName:             "testdata-notice-bin-bin2.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-notice-bin-bin2.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						PackageName:             "testdata-notice-lib-liba.so.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-notice-lib-liba.so.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-notice-NOTICE_LICENSE",
-					},
-					{
-						PackageName:             "testdata-notice-lib-libb.so.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-notice-lib-libb.so.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						PackageName:             "testdata-notice-lib-libc.a.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-notice-lib-libc.a.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-notice-NOTICE_LICENSE",
-					},
-					{
-						PackageName:             "testdata-notice-lib-libd.so.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-notice-lib-libd.so.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-notice-NOTICE_LICENSE",
-					},
-				},
-				Relationships: []*spdx.Relationship{
-					{
-						RefA:         common.MakeDocElementID("", "DOCUMENT"),
-						RefB:         common.MakeDocElementID("", "testdata-notice-container.zip.meta_lic"),
-						Relationship: "DESCRIBES",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-notice-container.zip.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-notice-bin-bin1.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-notice-container.zip.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-notice-bin-bin2.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-notice-container.zip.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-notice-lib-liba.so.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-notice-container.zip.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-notice-lib-libb.so.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-notice-bin-bin1.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-notice-lib-liba.so.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-notice-bin-bin1.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-notice-lib-libc.a.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-notice-lib-libb.so.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-notice-bin-bin2.meta_lic"),
-						Relationship: "RUNTIME_DEPENDENCY_OF",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-notice-lib-libd.so.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-notice-bin-bin2.meta_lic"),
-						Relationship: "RUNTIME_DEPENDENCY_OF",
-					},
-				},
-				OtherLicenses: []*spdx.OtherLicense{
-					{
-						LicenseIdentifier: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-						ExtractedText:     "&&&First Party License&&&\n",
-						LicenseName:       "testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						LicenseIdentifier: "LicenseRef-testdata-notice-NOTICE_LICENSE",
-						ExtractedText:     "%%%Notice License%%%\n",
-						LicenseName:       "testdata-notice-NOTICE_LICENSE",
-					},
-				},
-			},
-			expectedDeps: []string{
-				"testdata/firstparty/FIRST_PARTY_LICENSE",
-				"testdata/notice/NOTICE_LICENSE",
-				"testdata/notice/bin/bin1.meta_lic",
-				"testdata/notice/bin/bin2.meta_lic",
-				"testdata/notice/container.zip.meta_lic",
-				"testdata/notice/lib/liba.so.meta_lic",
-				"testdata/notice/lib/libb.so.meta_lic",
-				"testdata/notice/lib/libc.a.meta_lic",
-				"testdata/notice/lib/libd.so.meta_lic",
-			},
-		},
-		{
-			condition: "notice",
-			name:      "application",
-			roots:     []string{"application.meta_lic"},
-			expectedOut: &spdx.Document{
-				SPDXVersion:       "SPDX-2.2",
-				DataLicense:       "CC0-1.0",
-				SPDXIdentifier:    "DOCUMENT",
-				DocumentName:      "testdata-notice-application",
-				DocumentNamespace: generateSPDXNamespace("", "1970-01-01T00:00:00Z", "testdata/notice/application.meta_lic"),
-				CreationInfo:      getCreationInfo(t),
-				Packages: []*spdx.Package{
-					{
-						PackageName:             "testdata-notice-application.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-notice-application.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						PackageName:             "testdata-notice-bin-bin3.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-notice-bin-bin3.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-notice-NOTICE_LICENSE",
-					},
-					{
-						PackageName:             "testdata-notice-lib-liba.so.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-notice-lib-liba.so.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-notice-NOTICE_LICENSE",
-					},
-					{
-						PackageName:             "testdata-notice-lib-libb.so.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-notice-lib-libb.so.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-				},
-				Relationships: []*spdx.Relationship{
-					{
-						RefA:         common.MakeDocElementID("", "DOCUMENT"),
-						RefB:         common.MakeDocElementID("", "testdata-notice-application.meta_lic"),
-						Relationship: "DESCRIBES",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-notice-bin-bin3.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-notice-application.meta_lic"),
-						Relationship: "BUILD_TOOL_OF",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-notice-application.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-notice-lib-liba.so.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-notice-lib-libb.so.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-notice-application.meta_lic"),
-						Relationship: "RUNTIME_DEPENDENCY_OF",
-					},
-				},
-				OtherLicenses: []*spdx.OtherLicense{
-					{
-						LicenseIdentifier: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-						ExtractedText:     "&&&First Party License&&&\n",
-						LicenseName:       "testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						LicenseIdentifier: "LicenseRef-testdata-notice-NOTICE_LICENSE",
-						ExtractedText:     "%%%Notice License%%%\n",
-						LicenseName:       "testdata-notice-NOTICE_LICENSE",
-					},
-				},
-			},
-			expectedDeps: []string{
-				"testdata/firstparty/FIRST_PARTY_LICENSE",
-				"testdata/notice/NOTICE_LICENSE",
-				"testdata/notice/application.meta_lic",
-				"testdata/notice/bin/bin3.meta_lic",
-				"testdata/notice/lib/liba.so.meta_lic",
-				"testdata/notice/lib/libb.so.meta_lic",
-			},
-		},
-		{
-			condition: "notice",
-			name:      "binary",
-			roots:     []string{"bin/bin1.meta_lic"},
-			expectedOut: &spdx.Document{
-				SPDXVersion:       "SPDX-2.2",
-				DataLicense:       "CC0-1.0",
-				SPDXIdentifier:    "DOCUMENT",
-				DocumentName:      "testdata-notice-bin-bin1",
-				DocumentNamespace: generateSPDXNamespace("", "1970-01-01T00:00:00Z", "testdata/notice/bin/bin1.meta_lic"),
-				CreationInfo:      getCreationInfo(t),
-				Packages: []*spdx.Package{
-					{
-						PackageName:             "testdata-notice-bin-bin1.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-notice-bin-bin1.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						PackageName:             "testdata-notice-lib-liba.so.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-notice-lib-liba.so.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-notice-NOTICE_LICENSE",
-					},
-					{
-						PackageName:             "testdata-notice-lib-libc.a.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-notice-lib-libc.a.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-notice-NOTICE_LICENSE",
-					},
-				},
-				Relationships: []*spdx.Relationship{
-					{
-						RefA:         common.MakeDocElementID("", "DOCUMENT"),
-						RefB:         common.MakeDocElementID("", "testdata-notice-bin-bin1.meta_lic"),
-						Relationship: "DESCRIBES",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-notice-bin-bin1.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-notice-lib-liba.so.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-notice-bin-bin1.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-notice-lib-libc.a.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-				},
-				OtherLicenses: []*spdx.OtherLicense{
-					{
-						LicenseIdentifier: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-						ExtractedText:     "&&&First Party License&&&\n",
-						LicenseName:       "testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						LicenseIdentifier: "LicenseRef-testdata-notice-NOTICE_LICENSE",
-						ExtractedText:     "%%%Notice License%%%\n",
-						LicenseName:       "testdata-notice-NOTICE_LICENSE",
-					},
-				},
-			},
-			expectedDeps: []string{
-				"testdata/firstparty/FIRST_PARTY_LICENSE",
-				"testdata/notice/NOTICE_LICENSE",
-				"testdata/notice/bin/bin1.meta_lic",
-				"testdata/notice/lib/liba.so.meta_lic",
-				"testdata/notice/lib/libc.a.meta_lic",
-			},
-		},
-		{
-			condition: "notice",
-			name:      "library",
-			roots:     []string{"lib/libd.so.meta_lic"},
-			expectedOut: &spdx.Document{
-				SPDXVersion:       "SPDX-2.2",
-				DataLicense:       "CC0-1.0",
-				SPDXIdentifier:    "DOCUMENT",
-				DocumentName:      "testdata-notice-lib-libd.so",
-				DocumentNamespace: generateSPDXNamespace("", "1970-01-01T00:00:00Z", "testdata/notice/lib/libd.so.meta_lic"),
-				CreationInfo:      getCreationInfo(t),
-				Packages: []*spdx.Package{
-					{
-						PackageName:             "testdata-notice-lib-libd.so.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-notice-lib-libd.so.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-notice-NOTICE_LICENSE",
-					},
-				},
-				Relationships: []*spdx.Relationship{
-					{
-						RefA:         common.MakeDocElementID("", "DOCUMENT"),
-						RefB:         common.MakeDocElementID("", "testdata-notice-lib-libd.so.meta_lic"),
-						Relationship: "DESCRIBES",
-					},
-				},
-				OtherLicenses: []*spdx.OtherLicense{
-					{
-						LicenseIdentifier: "LicenseRef-testdata-notice-NOTICE_LICENSE",
-						ExtractedText:     "%%%Notice License%%%\n",
-						LicenseName:       "testdata-notice-NOTICE_LICENSE",
-					},
-				},
-			},
-			expectedDeps: []string{
-				"testdata/notice/NOTICE_LICENSE",
-				"testdata/notice/lib/libd.so.meta_lic",
-			},
-		},
-		{
-			condition: "reciprocal",
-			name:      "apex",
-			roots:     []string{"highest.apex.meta_lic"},
-			expectedOut: &spdx.Document{
-				SPDXVersion:       "SPDX-2.2",
-				DataLicense:       "CC0-1.0",
-				SPDXIdentifier:    "DOCUMENT",
-				DocumentName:      "testdata-reciprocal-highest.apex",
-				DocumentNamespace: generateSPDXNamespace("", "1970-01-01T00:00:00Z", "testdata/reciprocal/highest.apex.meta_lic"),
-				CreationInfo:      getCreationInfo(t),
-				Packages: []*spdx.Package{
-					{
-						PackageName:             "testdata-reciprocal-highest.apex.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-reciprocal-highest.apex.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						PackageName:             "testdata-reciprocal-bin-bin1.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-reciprocal-bin-bin1.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						PackageName:             "testdata-reciprocal-bin-bin2.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-reciprocal-bin-bin2.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						PackageName:             "testdata-reciprocal-lib-liba.so.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-reciprocal-lib-liba.so.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-reciprocal-RECIPROCAL_LICENSE",
-					},
-					{
-						PackageName:             "testdata-reciprocal-lib-libb.so.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-reciprocal-lib-libb.so.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						PackageName:             "testdata-reciprocal-lib-libc.a.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-reciprocal-lib-libc.a.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-reciprocal-RECIPROCAL_LICENSE",
-					},
-					{
-						PackageName:             "testdata-reciprocal-lib-libd.so.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-reciprocal-lib-libd.so.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-notice-NOTICE_LICENSE",
-					},
-				},
-				Relationships: []*spdx.Relationship{
-					{
-						RefA:         common.MakeDocElementID("", "DOCUMENT"),
-						RefB:         common.MakeDocElementID("", "testdata-reciprocal-highest.apex.meta_lic"),
-						Relationship: "DESCRIBES",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-reciprocal-highest.apex.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-reciprocal-bin-bin1.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-reciprocal-highest.apex.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-reciprocal-bin-bin2.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-reciprocal-highest.apex.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-reciprocal-lib-liba.so.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-reciprocal-highest.apex.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-reciprocal-lib-libb.so.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-reciprocal-bin-bin1.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-reciprocal-lib-liba.so.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-reciprocal-bin-bin1.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-reciprocal-lib-libc.a.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-reciprocal-lib-libb.so.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-reciprocal-bin-bin2.meta_lic"),
-						Relationship: "RUNTIME_DEPENDENCY_OF",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-reciprocal-lib-libd.so.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-reciprocal-bin-bin2.meta_lic"),
-						Relationship: "RUNTIME_DEPENDENCY_OF",
-					},
-				},
-				OtherLicenses: []*spdx.OtherLicense{
-					{
-						LicenseIdentifier: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-						ExtractedText:     "&&&First Party License&&&\n",
-						LicenseName:       "testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						LicenseIdentifier: "LicenseRef-testdata-notice-NOTICE_LICENSE",
-						ExtractedText:     "%%%Notice License%%%\n",
-						LicenseName:       "testdata-notice-NOTICE_LICENSE",
-					},
-					{
-						LicenseIdentifier: "LicenseRef-testdata-reciprocal-RECIPROCAL_LICENSE",
-						ExtractedText:     "$$$Reciprocal License$$$\n",
-						LicenseName:       "testdata-reciprocal-RECIPROCAL_LICENSE",
-					},
-				},
-			},
-			expectedDeps: []string{
-				"testdata/firstparty/FIRST_PARTY_LICENSE",
-				"testdata/notice/NOTICE_LICENSE",
-				"testdata/reciprocal/RECIPROCAL_LICENSE",
-				"testdata/reciprocal/bin/bin1.meta_lic",
-				"testdata/reciprocal/bin/bin2.meta_lic",
-				"testdata/reciprocal/highest.apex.meta_lic",
-				"testdata/reciprocal/lib/liba.so.meta_lic",
-				"testdata/reciprocal/lib/libb.so.meta_lic",
-				"testdata/reciprocal/lib/libc.a.meta_lic",
-				"testdata/reciprocal/lib/libd.so.meta_lic",
-			},
-		},
-		{
-			condition: "reciprocal",
-			name:      "application",
-			roots:     []string{"application.meta_lic"},
-			expectedOut: &spdx.Document{
-				SPDXVersion:       "SPDX-2.2",
-				DataLicense:       "CC0-1.0",
-				SPDXIdentifier:    "DOCUMENT",
-				DocumentName:      "testdata-reciprocal-application",
-				DocumentNamespace: generateSPDXNamespace("", "1970-01-01T00:00:00Z", "testdata/reciprocal/application.meta_lic"),
-				CreationInfo:      getCreationInfo(t),
-				Packages: []*spdx.Package{
-					{
-						PackageName:             "testdata-reciprocal-application.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-reciprocal-application.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						PackageName:             "testdata-reciprocal-bin-bin3.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-reciprocal-bin-bin3.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-notice-NOTICE_LICENSE",
-					},
-					{
-						PackageName:             "testdata-reciprocal-lib-liba.so.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-reciprocal-lib-liba.so.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-reciprocal-RECIPROCAL_LICENSE",
-					},
-					{
-						PackageName:             "testdata-reciprocal-lib-libb.so.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-reciprocal-lib-libb.so.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-				},
-				Relationships: []*spdx.Relationship{
-					{
-						RefA:         common.MakeDocElementID("", "DOCUMENT"),
-						RefB:         common.MakeDocElementID("", "testdata-reciprocal-application.meta_lic"),
-						Relationship: "DESCRIBES",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-reciprocal-bin-bin3.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-reciprocal-application.meta_lic"),
-						Relationship: "BUILD_TOOL_OF",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-reciprocal-application.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-reciprocal-lib-liba.so.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-reciprocal-lib-libb.so.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-reciprocal-application.meta_lic"),
-						Relationship: "RUNTIME_DEPENDENCY_OF",
-					},
-				},
-				OtherLicenses: []*spdx.OtherLicense{
-					{
-						LicenseIdentifier: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-						ExtractedText:     "&&&First Party License&&&\n",
-						LicenseName:       "testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						LicenseIdentifier: "LicenseRef-testdata-notice-NOTICE_LICENSE",
-						ExtractedText:     "%%%Notice License%%%\n",
-						LicenseName:       "testdata-notice-NOTICE_LICENSE",
-					},
-					{
-						LicenseIdentifier: "LicenseRef-testdata-reciprocal-RECIPROCAL_LICENSE",
-						ExtractedText:     "$$$Reciprocal License$$$\n",
-						LicenseName:       "testdata-reciprocal-RECIPROCAL_LICENSE",
-					},
-				},
-			},
-			expectedDeps: []string{
-				"testdata/firstparty/FIRST_PARTY_LICENSE",
-				"testdata/notice/NOTICE_LICENSE",
-				"testdata/reciprocal/RECIPROCAL_LICENSE",
-				"testdata/reciprocal/application.meta_lic",
-				"testdata/reciprocal/bin/bin3.meta_lic",
-				"testdata/reciprocal/lib/liba.so.meta_lic",
-				"testdata/reciprocal/lib/libb.so.meta_lic",
-			},
-		},
-		{
-			condition: "reciprocal",
-			name:      "binary",
-			roots:     []string{"bin/bin1.meta_lic"},
-			expectedOut: &spdx.Document{
-				SPDXVersion:       "SPDX-2.2",
-				DataLicense:       "CC0-1.0",
-				SPDXIdentifier:    "DOCUMENT",
-				DocumentName:      "testdata-reciprocal-bin-bin1",
-				DocumentNamespace: generateSPDXNamespace("", "1970-01-01T00:00:00Z", "testdata/reciprocal/bin/bin1.meta_lic"),
-				CreationInfo:      getCreationInfo(t),
-				Packages: []*spdx.Package{
-					{
-						PackageName:             "testdata-reciprocal-bin-bin1.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-reciprocal-bin-bin1.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						PackageName:             "testdata-reciprocal-lib-liba.so.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-reciprocal-lib-liba.so.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-reciprocal-RECIPROCAL_LICENSE",
-					},
-					{
-						PackageName:             "testdata-reciprocal-lib-libc.a.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-reciprocal-lib-libc.a.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-reciprocal-RECIPROCAL_LICENSE",
-					},
-				},
-				Relationships: []*spdx.Relationship{
-					{
-						RefA:         common.MakeDocElementID("", "DOCUMENT"),
-						RefB:         common.MakeDocElementID("", "testdata-reciprocal-bin-bin1.meta_lic"),
-						Relationship: "DESCRIBES",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-reciprocal-bin-bin1.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-reciprocal-lib-liba.so.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-reciprocal-bin-bin1.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-reciprocal-lib-libc.a.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-				},
-				OtherLicenses: []*spdx.OtherLicense{
-					{
-						LicenseIdentifier: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-						ExtractedText:     "&&&First Party License&&&\n",
-						LicenseName:       "testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						LicenseIdentifier: "LicenseRef-testdata-reciprocal-RECIPROCAL_LICENSE",
-						ExtractedText:     "$$$Reciprocal License$$$\n",
-						LicenseName:       "testdata-reciprocal-RECIPROCAL_LICENSE",
-					},
-				},
-			},
-			expectedDeps: []string{
-				"testdata/firstparty/FIRST_PARTY_LICENSE",
-				"testdata/reciprocal/RECIPROCAL_LICENSE",
-				"testdata/reciprocal/bin/bin1.meta_lic",
-				"testdata/reciprocal/lib/liba.so.meta_lic",
-				"testdata/reciprocal/lib/libc.a.meta_lic",
-			},
-		},
-		{
-			condition: "reciprocal",
-			name:      "library",
-			roots:     []string{"lib/libd.so.meta_lic"},
-			expectedOut: &spdx.Document{
-				SPDXVersion:       "SPDX-2.2",
-				DataLicense:       "CC0-1.0",
-				SPDXIdentifier:    "DOCUMENT",
-				DocumentName:      "testdata-reciprocal-lib-libd.so",
-				DocumentNamespace: generateSPDXNamespace("", "1970-01-01T00:00:00Z", "testdata/reciprocal/lib/libd.so.meta_lic"),
-				CreationInfo:      getCreationInfo(t),
-				Packages: []*spdx.Package{
-					{
-						PackageName:             "testdata-reciprocal-lib-libd.so.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-reciprocal-lib-libd.so.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-notice-NOTICE_LICENSE",
-					},
-				},
-				Relationships: []*spdx.Relationship{
-					{
-						RefA:         common.MakeDocElementID("", "DOCUMENT"),
-						RefB:         common.MakeDocElementID("", "testdata-reciprocal-lib-libd.so.meta_lic"),
-						Relationship: "DESCRIBES",
-					},
-				},
-				OtherLicenses: []*spdx.OtherLicense{
-					{
-						LicenseIdentifier: "LicenseRef-testdata-notice-NOTICE_LICENSE",
-						ExtractedText:     "%%%Notice License%%%\n",
-						LicenseName:       "testdata-notice-NOTICE_LICENSE",
-					},
-				},
-			},
-			expectedDeps: []string{
-				"testdata/notice/NOTICE_LICENSE",
-				"testdata/reciprocal/lib/libd.so.meta_lic",
-			},
-		},
-		{
-			condition: "restricted",
-			name:      "apex",
-			roots:     []string{"highest.apex.meta_lic"},
-			expectedOut: &spdx.Document{
-				SPDXVersion:       "SPDX-2.2",
-				DataLicense:       "CC0-1.0",
-				SPDXIdentifier:    "DOCUMENT",
-				DocumentName:      "testdata-restricted-highest.apex",
-				DocumentNamespace: generateSPDXNamespace("", "1970-01-01T00:00:00Z", "testdata/restricted/highest.apex.meta_lic"),
-				CreationInfo:      getCreationInfo(t),
-				Packages: []*spdx.Package{
-					{
-						PackageName:             "testdata-restricted-highest.apex.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-restricted-highest.apex.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						PackageName:             "testdata-restricted-bin-bin1.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-restricted-bin-bin1.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						PackageName:             "testdata-restricted-bin-bin2.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-restricted-bin-bin2.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						PackageName:             "testdata-restricted-lib-liba.so.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-restricted-lib-liba.so.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-restricted-RESTRICTED_LICENSE",
-					},
-					{
-						PackageName:             "testdata-restricted-lib-libb.so.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-restricted-lib-libb.so.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-restricted-RESTRICTED_LICENSE",
-					},
-					{
-						PackageName:             "testdata-restricted-lib-libc.a.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-restricted-lib-libc.a.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-reciprocal-RECIPROCAL_LICENSE",
-					},
-					{
-						PackageName:             "testdata-restricted-lib-libd.so.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-restricted-lib-libd.so.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-notice-NOTICE_LICENSE",
-					},
-				},
-				Relationships: []*spdx.Relationship{
-					{
-						RefA:         common.MakeDocElementID("", "DOCUMENT"),
-						RefB:         common.MakeDocElementID("", "testdata-restricted-highest.apex.meta_lic"),
-						Relationship: "DESCRIBES",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-restricted-highest.apex.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-restricted-bin-bin1.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-restricted-highest.apex.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-restricted-bin-bin2.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-restricted-highest.apex.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-restricted-lib-liba.so.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-restricted-highest.apex.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-restricted-lib-libb.so.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-restricted-bin-bin1.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-restricted-lib-liba.so.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-restricted-bin-bin1.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-restricted-lib-libc.a.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-restricted-lib-libb.so.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-restricted-bin-bin2.meta_lic"),
-						Relationship: "RUNTIME_DEPENDENCY_OF",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-restricted-lib-libd.so.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-restricted-bin-bin2.meta_lic"),
-						Relationship: "RUNTIME_DEPENDENCY_OF",
-					},
-				},
-				OtherLicenses: []*spdx.OtherLicense{
-					{
-						LicenseIdentifier: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-						ExtractedText:     "&&&First Party License&&&\n",
-						LicenseName:       "testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						LicenseIdentifier: "LicenseRef-testdata-notice-NOTICE_LICENSE",
-						ExtractedText:     "%%%Notice License%%%\n",
-						LicenseName:       "testdata-notice-NOTICE_LICENSE",
-					},
-					{
-						LicenseIdentifier: "LicenseRef-testdata-reciprocal-RECIPROCAL_LICENSE",
-						ExtractedText:     "$$$Reciprocal License$$$\n",
-						LicenseName:       "testdata-reciprocal-RECIPROCAL_LICENSE",
-					},
-					{
-						LicenseIdentifier: "LicenseRef-testdata-restricted-RESTRICTED_LICENSE",
-						ExtractedText:     "###Restricted License###\n",
-						LicenseName:       "testdata-restricted-RESTRICTED_LICENSE",
-					},
-				},
-			},
-			expectedDeps: []string{
-				"testdata/firstparty/FIRST_PARTY_LICENSE",
-				"testdata/notice/NOTICE_LICENSE",
-				"testdata/reciprocal/RECIPROCAL_LICENSE",
-				"testdata/restricted/RESTRICTED_LICENSE",
-				"testdata/restricted/bin/bin1.meta_lic",
-				"testdata/restricted/bin/bin2.meta_lic",
-				"testdata/restricted/highest.apex.meta_lic",
-				"testdata/restricted/lib/liba.so.meta_lic",
-				"testdata/restricted/lib/libb.so.meta_lic",
-				"testdata/restricted/lib/libc.a.meta_lic",
-				"testdata/restricted/lib/libd.so.meta_lic",
-			},
-		},
-		{
-			condition: "restricted",
-			name:      "container",
-			roots:     []string{"container.zip.meta_lic"},
-			expectedOut: &spdx.Document{
-				SPDXVersion:       "SPDX-2.2",
-				DataLicense:       "CC0-1.0",
-				SPDXIdentifier:    "DOCUMENT",
-				DocumentName:      "testdata-restricted-container.zip",
-				DocumentNamespace: generateSPDXNamespace("", "1970-01-01T00:00:00Z", "testdata/restricted/container.zip.meta_lic"),
-				CreationInfo:      getCreationInfo(t),
-				Packages: []*spdx.Package{
-					{
-						PackageName:             "testdata-restricted-container.zip.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-restricted-container.zip.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						PackageName:             "testdata-restricted-bin-bin1.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-restricted-bin-bin1.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						PackageName:             "testdata-restricted-bin-bin2.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-restricted-bin-bin2.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						PackageName:             "testdata-restricted-lib-liba.so.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-restricted-lib-liba.so.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-restricted-RESTRICTED_LICENSE",
-					},
-					{
-						PackageName:             "testdata-restricted-lib-libb.so.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-restricted-lib-libb.so.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-restricted-RESTRICTED_LICENSE",
-					},
-					{
-						PackageName:             "testdata-restricted-lib-libc.a.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-restricted-lib-libc.a.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-reciprocal-RECIPROCAL_LICENSE",
-					},
-					{
-						PackageName:             "testdata-restricted-lib-libd.so.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-restricted-lib-libd.so.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-notice-NOTICE_LICENSE",
-					},
-				},
-				Relationships: []*spdx.Relationship{
-					{
-						RefA:         common.MakeDocElementID("", "DOCUMENT"),
-						RefB:         common.MakeDocElementID("", "testdata-restricted-container.zip.meta_lic"),
-						Relationship: "DESCRIBES",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-restricted-container.zip.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-restricted-bin-bin1.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-restricted-container.zip.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-restricted-bin-bin2.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-restricted-container.zip.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-restricted-lib-liba.so.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-restricted-container.zip.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-restricted-lib-libb.so.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-restricted-bin-bin1.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-restricted-lib-liba.so.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-restricted-bin-bin1.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-restricted-lib-libc.a.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-restricted-lib-libb.so.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-restricted-bin-bin2.meta_lic"),
-						Relationship: "RUNTIME_DEPENDENCY_OF",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-restricted-lib-libd.so.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-restricted-bin-bin2.meta_lic"),
-						Relationship: "RUNTIME_DEPENDENCY_OF",
-					},
-				},
-				OtherLicenses: []*spdx.OtherLicense{
-					{
-						LicenseIdentifier: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-						ExtractedText:     "&&&First Party License&&&\n",
-						LicenseName:       "testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						LicenseIdentifier: "LicenseRef-testdata-notice-NOTICE_LICENSE",
-						ExtractedText:     "%%%Notice License%%%\n",
-						LicenseName:       "testdata-notice-NOTICE_LICENSE",
-					},
-					{
-						LicenseIdentifier: "LicenseRef-testdata-reciprocal-RECIPROCAL_LICENSE",
-						ExtractedText:     "$$$Reciprocal License$$$\n",
-						LicenseName:       "testdata-reciprocal-RECIPROCAL_LICENSE",
-					},
-					{
-						LicenseIdentifier: "LicenseRef-testdata-restricted-RESTRICTED_LICENSE",
-						ExtractedText:     "###Restricted License###\n",
-						LicenseName:       "testdata-restricted-RESTRICTED_LICENSE",
-					},
-				},
-			},
-			expectedDeps: []string{
-				"testdata/firstparty/FIRST_PARTY_LICENSE",
-				"testdata/notice/NOTICE_LICENSE",
-				"testdata/reciprocal/RECIPROCAL_LICENSE",
-				"testdata/restricted/RESTRICTED_LICENSE",
-				"testdata/restricted/bin/bin1.meta_lic",
-				"testdata/restricted/bin/bin2.meta_lic",
-				"testdata/restricted/container.zip.meta_lic",
-				"testdata/restricted/lib/liba.so.meta_lic",
-				"testdata/restricted/lib/libb.so.meta_lic",
-				"testdata/restricted/lib/libc.a.meta_lic",
-				"testdata/restricted/lib/libd.so.meta_lic",
-			},
-		},
-		{
-			condition: "restricted",
-			name:      "binary",
-			roots:     []string{"bin/bin1.meta_lic"},
-			expectedOut: &spdx.Document{
-				SPDXVersion:       "SPDX-2.2",
-				DataLicense:       "CC0-1.0",
-				SPDXIdentifier:    "DOCUMENT",
-				DocumentName:      "testdata-restricted-bin-bin1",
-				DocumentNamespace: generateSPDXNamespace("", "1970-01-01T00:00:00Z", "testdata/restricted/bin/bin1.meta_lic"),
-				CreationInfo:      getCreationInfo(t),
-				Packages: []*spdx.Package{
-					{
-						PackageName:             "testdata-restricted-bin-bin1.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-restricted-bin-bin1.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						PackageName:             "testdata-restricted-lib-liba.so.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-restricted-lib-liba.so.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-restricted-RESTRICTED_LICENSE",
-					},
-					{
-						PackageName:             "testdata-restricted-lib-libc.a.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-restricted-lib-libc.a.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-reciprocal-RECIPROCAL_LICENSE",
-					},
-				},
-				Relationships: []*spdx.Relationship{
-					{
-						RefA:         common.MakeDocElementID("", "DOCUMENT"),
-						RefB:         common.MakeDocElementID("", "testdata-restricted-bin-bin1.meta_lic"),
-						Relationship: "DESCRIBES",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-restricted-bin-bin1.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-restricted-lib-liba.so.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-restricted-bin-bin1.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-restricted-lib-libc.a.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-				},
-				OtherLicenses: []*spdx.OtherLicense{
-					{
-						LicenseIdentifier: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-						ExtractedText:     "&&&First Party License&&&\n",
-						LicenseName:       "testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						LicenseIdentifier: "LicenseRef-testdata-reciprocal-RECIPROCAL_LICENSE",
-						ExtractedText:     "$$$Reciprocal License$$$\n",
-						LicenseName:       "testdata-reciprocal-RECIPROCAL_LICENSE",
-					},
-					{
-						LicenseIdentifier: "LicenseRef-testdata-restricted-RESTRICTED_LICENSE",
-						ExtractedText:     "###Restricted License###\n",
-						LicenseName:       "testdata-restricted-RESTRICTED_LICENSE",
-					},
-				},
-			},
-			expectedDeps: []string{
-				"testdata/firstparty/FIRST_PARTY_LICENSE",
-				"testdata/reciprocal/RECIPROCAL_LICENSE",
-				"testdata/restricted/RESTRICTED_LICENSE",
-				"testdata/restricted/bin/bin1.meta_lic",
-				"testdata/restricted/lib/liba.so.meta_lic",
-				"testdata/restricted/lib/libc.a.meta_lic",
-			},
-		},
-		{
-			condition: "restricted",
-			name:      "library",
-			roots:     []string{"lib/libd.so.meta_lic"},
-			expectedOut: &spdx.Document{
-				SPDXVersion:       "SPDX-2.2",
-				DataLicense:       "CC0-1.0",
-				SPDXIdentifier:    "DOCUMENT",
-				DocumentName:      "testdata-restricted-lib-libd.so",
-				DocumentNamespace: generateSPDXNamespace("", "1970-01-01T00:00:00Z", "testdata/restricted/lib/libd.so.meta_lic"),
-				CreationInfo:      getCreationInfo(t),
-				Packages: []*spdx.Package{
-					{
-						PackageName:             "testdata-restricted-lib-libd.so.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-restricted-lib-libd.so.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-notice-NOTICE_LICENSE",
-					},
-				},
-				Relationships: []*spdx.Relationship{
-					{
-						RefA:         common.MakeDocElementID("", "DOCUMENT"),
-						RefB:         common.MakeDocElementID("", "testdata-restricted-lib-libd.so.meta_lic"),
-						Relationship: "DESCRIBES",
-					},
-				},
-				OtherLicenses: []*spdx.OtherLicense{
-					{
-						LicenseIdentifier: "LicenseRef-testdata-notice-NOTICE_LICENSE",
-						ExtractedText:     "%%%Notice License%%%\n",
-						LicenseName:       "testdata-notice-NOTICE_LICENSE",
-					},
-				},
-			},
-			expectedDeps: []string{
-				"testdata/notice/NOTICE_LICENSE",
-				"testdata/restricted/lib/libd.so.meta_lic",
-			},
-		},
-		{
-			condition: "proprietary",
-			name:      "apex",
-			roots:     []string{"highest.apex.meta_lic"},
-			expectedOut: &spdx.Document{
-				SPDXVersion:       "SPDX-2.2",
-				DataLicense:       "CC0-1.0",
-				SPDXIdentifier:    "DOCUMENT",
-				DocumentName:      "testdata-proprietary-highest.apex",
-				DocumentNamespace: generateSPDXNamespace("", "1970-01-01T00:00:00Z", "testdata/proprietary/highest.apex.meta_lic"),
-				CreationInfo:      getCreationInfo(t),
-				Packages: []*spdx.Package{
-					{
-						PackageName:             "testdata-proprietary-highest.apex.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-proprietary-highest.apex.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						PackageName:             "testdata-proprietary-bin-bin1.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-proprietary-bin-bin1.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						PackageName:             "testdata-proprietary-bin-bin2.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-proprietary-bin-bin2.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-proprietary-PROPRIETARY_LICENSE",
-					},
-					{
-						PackageName:             "testdata-proprietary-lib-liba.so.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-proprietary-lib-liba.so.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-proprietary-PROPRIETARY_LICENSE",
-					},
-					{
-						PackageName:             "testdata-proprietary-lib-libb.so.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-proprietary-lib-libb.so.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-restricted-RESTRICTED_LICENSE",
-					},
-					{
-						PackageName:             "testdata-proprietary-lib-libc.a.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-proprietary-lib-libc.a.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-proprietary-PROPRIETARY_LICENSE",
-					},
-					{
-						PackageName:             "testdata-proprietary-lib-libd.so.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-proprietary-lib-libd.so.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-notice-NOTICE_LICENSE",
-					},
-				},
-				Relationships: []*spdx.Relationship{
-					{
-						RefA:         common.MakeDocElementID("", "DOCUMENT"),
-						RefB:         common.MakeDocElementID("", "testdata-proprietary-highest.apex.meta_lic"),
-						Relationship: "DESCRIBES",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-proprietary-highest.apex.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-proprietary-bin-bin1.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-proprietary-highest.apex.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-proprietary-bin-bin2.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-proprietary-highest.apex.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-proprietary-lib-liba.so.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-proprietary-highest.apex.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-proprietary-lib-libb.so.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-proprietary-bin-bin1.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-proprietary-lib-liba.so.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-proprietary-bin-bin1.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-proprietary-lib-libc.a.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-proprietary-lib-libb.so.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-proprietary-bin-bin2.meta_lic"),
-						Relationship: "RUNTIME_DEPENDENCY_OF",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-proprietary-lib-libd.so.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-proprietary-bin-bin2.meta_lic"),
-						Relationship: "RUNTIME_DEPENDENCY_OF",
-					},
-				},
-				OtherLicenses: []*spdx.OtherLicense{
-					{
-						LicenseIdentifier: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-						ExtractedText:     "&&&First Party License&&&\n",
-						LicenseName:       "testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						LicenseIdentifier: "LicenseRef-testdata-notice-NOTICE_LICENSE",
-						ExtractedText:     "%%%Notice License%%%\n",
-						LicenseName:       "testdata-notice-NOTICE_LICENSE",
-					},
-					{
-						LicenseIdentifier: "LicenseRef-testdata-proprietary-PROPRIETARY_LICENSE",
-						ExtractedText:     "@@@Proprietary License@@@\n",
-						LicenseName:       "testdata-proprietary-PROPRIETARY_LICENSE",
-					},
-					{
-						LicenseIdentifier: "LicenseRef-testdata-restricted-RESTRICTED_LICENSE",
-						ExtractedText:     "###Restricted License###\n",
-						LicenseName:       "testdata-restricted-RESTRICTED_LICENSE",
-					},
-				},
-			},
-			expectedDeps: []string{
-				"testdata/firstparty/FIRST_PARTY_LICENSE",
-				"testdata/notice/NOTICE_LICENSE",
-				"testdata/proprietary/PROPRIETARY_LICENSE",
-				"testdata/proprietary/bin/bin1.meta_lic",
-				"testdata/proprietary/bin/bin2.meta_lic",
-				"testdata/proprietary/highest.apex.meta_lic",
-				"testdata/proprietary/lib/liba.so.meta_lic",
-				"testdata/proprietary/lib/libb.so.meta_lic",
-				"testdata/proprietary/lib/libc.a.meta_lic",
-				"testdata/proprietary/lib/libd.so.meta_lic",
-				"testdata/restricted/RESTRICTED_LICENSE",
-			},
-		},
-		{
-			condition: "proprietary",
-			name:      "container",
-			roots:     []string{"container.zip.meta_lic"},
-			expectedOut: &spdx.Document{
-				SPDXVersion:       "SPDX-2.2",
-				DataLicense:       "CC0-1.0",
-				SPDXIdentifier:    "DOCUMENT",
-				DocumentName:      "testdata-proprietary-container.zip",
-				DocumentNamespace: generateSPDXNamespace("", "1970-01-01T00:00:00Z", "testdata/proprietary/container.zip.meta_lic"),
-				CreationInfo:      getCreationInfo(t),
-				Packages: []*spdx.Package{
-					{
-						PackageName:             "testdata-proprietary-container.zip.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-proprietary-container.zip.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						PackageName:             "testdata-proprietary-bin-bin1.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-proprietary-bin-bin1.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						PackageName:             "testdata-proprietary-bin-bin2.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-proprietary-bin-bin2.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-proprietary-PROPRIETARY_LICENSE",
-					},
-					{
-						PackageName:             "testdata-proprietary-lib-liba.so.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-proprietary-lib-liba.so.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-proprietary-PROPRIETARY_LICENSE",
-					},
-					{
-						PackageName:             "testdata-proprietary-lib-libb.so.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-proprietary-lib-libb.so.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-restricted-RESTRICTED_LICENSE",
-					},
-					{
-						PackageName:             "testdata-proprietary-lib-libc.a.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-proprietary-lib-libc.a.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-proprietary-PROPRIETARY_LICENSE",
-					},
-					{
-						PackageName:             "testdata-proprietary-lib-libd.so.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-proprietary-lib-libd.so.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-notice-NOTICE_LICENSE",
-					},
-				},
-				Relationships: []*spdx.Relationship{
-					{
-						RefA:         common.MakeDocElementID("", "DOCUMENT"),
-						RefB:         common.MakeDocElementID("", "testdata-proprietary-container.zip.meta_lic"),
-						Relationship: "DESCRIBES",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-proprietary-container.zip.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-proprietary-bin-bin1.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-proprietary-container.zip.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-proprietary-bin-bin2.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-proprietary-container.zip.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-proprietary-lib-liba.so.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-proprietary-container.zip.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-proprietary-lib-libb.so.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-proprietary-bin-bin1.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-proprietary-lib-liba.so.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-proprietary-bin-bin1.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-proprietary-lib-libc.a.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-proprietary-lib-libb.so.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-proprietary-bin-bin2.meta_lic"),
-						Relationship: "RUNTIME_DEPENDENCY_OF",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-proprietary-lib-libd.so.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-proprietary-bin-bin2.meta_lic"),
-						Relationship: "RUNTIME_DEPENDENCY_OF",
-					},
-				},
-				OtherLicenses: []*spdx.OtherLicense{
-					{
-						LicenseIdentifier: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-						ExtractedText:     "&&&First Party License&&&\n",
-						LicenseName:       "testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						LicenseIdentifier: "LicenseRef-testdata-notice-NOTICE_LICENSE",
-						ExtractedText:     "%%%Notice License%%%\n",
-						LicenseName:       "testdata-notice-NOTICE_LICENSE",
-					},
-					{
-						LicenseIdentifier: "LicenseRef-testdata-proprietary-PROPRIETARY_LICENSE",
-						ExtractedText:     "@@@Proprietary License@@@\n",
-						LicenseName:       "testdata-proprietary-PROPRIETARY_LICENSE",
-					},
-					{
-						LicenseIdentifier: "LicenseRef-testdata-restricted-RESTRICTED_LICENSE",
-						ExtractedText:     "###Restricted License###\n",
-						LicenseName:       "testdata-restricted-RESTRICTED_LICENSE",
-					},
-				},
-			},
-			expectedDeps: []string{
-				"testdata/firstparty/FIRST_PARTY_LICENSE",
-				"testdata/notice/NOTICE_LICENSE",
-				"testdata/proprietary/PROPRIETARY_LICENSE",
-				"testdata/proprietary/bin/bin1.meta_lic",
-				"testdata/proprietary/bin/bin2.meta_lic",
-				"testdata/proprietary/container.zip.meta_lic",
-				"testdata/proprietary/lib/liba.so.meta_lic",
-				"testdata/proprietary/lib/libb.so.meta_lic",
-				"testdata/proprietary/lib/libc.a.meta_lic",
-				"testdata/proprietary/lib/libd.so.meta_lic",
-				"testdata/restricted/RESTRICTED_LICENSE",
-			},
-		},
-		{
-			condition: "proprietary",
-			name:      "application",
-			roots:     []string{"application.meta_lic"},
-			expectedOut: &spdx.Document{
-				SPDXVersion:       "SPDX-2.2",
-				DataLicense:       "CC0-1.0",
-				SPDXIdentifier:    "DOCUMENT",
-				DocumentName:      "testdata-proprietary-application",
-				DocumentNamespace: generateSPDXNamespace("", "1970-01-01T00:00:00Z", "testdata/proprietary/application.meta_lic"),
-				CreationInfo:      getCreationInfo(t),
-				Packages: []*spdx.Package{
-					{
-						PackageName:             "testdata-proprietary-application.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-proprietary-application.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						PackageName:             "testdata-proprietary-bin-bin3.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-proprietary-bin-bin3.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-restricted-RESTRICTED_LICENSE",
-					},
-					{
-						PackageName:             "testdata-proprietary-lib-liba.so.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-proprietary-lib-liba.so.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-proprietary-PROPRIETARY_LICENSE",
-					},
-					{
-						PackageName:             "testdata-proprietary-lib-libb.so.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-proprietary-lib-libb.so.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-restricted-RESTRICTED_LICENSE",
-					},
-				},
-				Relationships: []*spdx.Relationship{
-					{
-						RefA:         common.MakeDocElementID("", "DOCUMENT"),
-						RefB:         common.MakeDocElementID("", "testdata-proprietary-application.meta_lic"),
-						Relationship: "DESCRIBES",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-proprietary-bin-bin3.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-proprietary-application.meta_lic"),
-						Relationship: "BUILD_TOOL_OF",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-proprietary-application.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-proprietary-lib-liba.so.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-proprietary-lib-libb.so.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-proprietary-application.meta_lic"),
-						Relationship: "RUNTIME_DEPENDENCY_OF",
-					},
-				},
-				OtherLicenses: []*spdx.OtherLicense{
-					{
-						LicenseIdentifier: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-						ExtractedText:     "&&&First Party License&&&\n",
-						LicenseName:       "testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						LicenseIdentifier: "LicenseRef-testdata-proprietary-PROPRIETARY_LICENSE",
-						ExtractedText:     "@@@Proprietary License@@@\n",
-						LicenseName:       "testdata-proprietary-PROPRIETARY_LICENSE",
-					},
-					{
-						LicenseIdentifier: "LicenseRef-testdata-restricted-RESTRICTED_LICENSE",
-						ExtractedText:     "###Restricted License###\n",
-						LicenseName:       "testdata-restricted-RESTRICTED_LICENSE",
-					},
-				},
-			},
-			expectedDeps: []string{
-				"testdata/firstparty/FIRST_PARTY_LICENSE",
-				"testdata/proprietary/PROPRIETARY_LICENSE",
-				"testdata/proprietary/application.meta_lic",
-				"testdata/proprietary/bin/bin3.meta_lic",
-				"testdata/proprietary/lib/liba.so.meta_lic",
-				"testdata/proprietary/lib/libb.so.meta_lic",
-				"testdata/restricted/RESTRICTED_LICENSE",
-			},
-		},
-		{
-			condition: "proprietary",
-			name:      "binary",
-			roots:     []string{"bin/bin1.meta_lic"},
-			expectedOut: &spdx.Document{
-				SPDXVersion:       "SPDX-2.2",
-				DataLicense:       "CC0-1.0",
-				SPDXIdentifier:    "DOCUMENT",
-				DocumentName:      "testdata-proprietary-bin-bin1",
-				DocumentNamespace: generateSPDXNamespace("", "1970-01-01T00:00:00Z", "testdata/proprietary/bin/bin1.meta_lic"),
-				CreationInfo:      getCreationInfo(t),
-				Packages: []*spdx.Package{
-					{
-						PackageName:             "testdata-proprietary-bin-bin1.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-proprietary-bin-bin1.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						PackageName:             "testdata-proprietary-lib-liba.so.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-proprietary-lib-liba.so.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-proprietary-PROPRIETARY_LICENSE",
-					},
-					{
-						PackageName:             "testdata-proprietary-lib-libc.a.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-proprietary-lib-libc.a.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-proprietary-PROPRIETARY_LICENSE",
-					},
-				},
-				Relationships: []*spdx.Relationship{
-					{
-						RefA:         common.MakeDocElementID("", "DOCUMENT"),
-						RefB:         common.MakeDocElementID("", "testdata-proprietary-bin-bin1.meta_lic"),
-						Relationship: "DESCRIBES",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-proprietary-bin-bin1.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-proprietary-lib-liba.so.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-					{
-						RefA:         common.MakeDocElementID("", "testdata-proprietary-bin-bin1.meta_lic"),
-						RefB:         common.MakeDocElementID("", "testdata-proprietary-lib-libc.a.meta_lic"),
-						Relationship: "CONTAINS",
-					},
-				},
-				OtherLicenses: []*spdx.OtherLicense{
-					{
-						LicenseIdentifier: "LicenseRef-testdata-firstparty-FIRST_PARTY_LICENSE",
-						ExtractedText:     "&&&First Party License&&&\n",
-						LicenseName:       "testdata-firstparty-FIRST_PARTY_LICENSE",
-					},
-					{
-						LicenseIdentifier: "LicenseRef-testdata-proprietary-PROPRIETARY_LICENSE",
-						ExtractedText:     "@@@Proprietary License@@@\n",
-						LicenseName:       "testdata-proprietary-PROPRIETARY_LICENSE",
-					},
-				},
-			},
-			expectedDeps: []string{
-				"testdata/firstparty/FIRST_PARTY_LICENSE",
-				"testdata/proprietary/PROPRIETARY_LICENSE",
-				"testdata/proprietary/bin/bin1.meta_lic",
-				"testdata/proprietary/lib/liba.so.meta_lic",
-				"testdata/proprietary/lib/libc.a.meta_lic",
-			},
-		},
-		{
-			condition: "proprietary",
-			name:      "library",
-			roots:     []string{"lib/libd.so.meta_lic"},
-			expectedOut: &spdx.Document{
-				SPDXVersion:       "SPDX-2.2",
-				DataLicense:       "CC0-1.0",
-				SPDXIdentifier:    "DOCUMENT",
-				DocumentName:      "testdata-proprietary-lib-libd.so",
-				DocumentNamespace: generateSPDXNamespace("", "1970-01-01T00:00:00Z", "testdata/proprietary/lib/libd.so.meta_lic"),
-				CreationInfo:      getCreationInfo(t),
-				Packages: []*spdx.Package{
-					{
-						PackageName:             "testdata-proprietary-lib-libd.so.meta_lic",
-						PackageVersion:          "NOASSERTION",
-						PackageDownloadLocation: "NOASSERTION",
-						PackageSPDXIdentifier:   common.ElementID("testdata-proprietary-lib-libd.so.meta_lic"),
-						PackageLicenseConcluded: "LicenseRef-testdata-notice-NOTICE_LICENSE",
-					},
-				},
-				Relationships: []*spdx.Relationship{
-					{
-						RefA:         common.MakeDocElementID("", "DOCUMENT"),
-						RefB:         common.MakeDocElementID("", "testdata-proprietary-lib-libd.so.meta_lic"),
-						Relationship: "DESCRIBES",
-					},
-				},
-				OtherLicenses: []*spdx.OtherLicense{
-					{
-						LicenseIdentifier: "LicenseRef-testdata-notice-NOTICE_LICENSE",
-						ExtractedText:     "%%%Notice License%%%\n",
-						LicenseName:       "testdata-notice-NOTICE_LICENSE",
-					},
-				},
-			},
-			expectedDeps: []string{
-				"testdata/notice/NOTICE_LICENSE",
-				"testdata/proprietary/lib/libd.so.meta_lic",
-			},
-		},
-	}
-	for _, tt := range tests {
-		t.Run(tt.condition+" "+tt.name, func(t *testing.T) {
-			stdout := &bytes.Buffer{}
-			stderr := &bytes.Buffer{}
-
-			rootFiles := make([]string, 0, len(tt.roots))
-			for _, r := range tt.roots {
-				rootFiles = append(rootFiles, "testdata/"+tt.condition+"/"+r)
-			}
-
-			ctx := context{stdout, stderr, compliance.GetFS(tt.outDir), "", []string{tt.stripPrefix}, fakeTime, ""}
-
-			spdxDoc, deps, err := sbomGenerator(&ctx, rootFiles...)
-			if err != nil {
-				t.Fatalf("sbom: error = %v, stderr = %v", err, stderr)
-				return
-			}
-			if stderr.Len() > 0 {
-				t.Errorf("sbom: gotStderr = %v, want none", stderr)
-			}
-
-			if err := validate(spdxDoc); err != nil {
-				t.Fatalf("sbom: document fails to validate: %v", err)
-			}
-
-			gotData, err := json.Marshal(spdxDoc)
-			if err != nil {
-				t.Fatalf("sbom: failed to marshal spdx doc: %v", err)
-				return
-			}
-
-			t.Logf("Got SPDX Doc: %s", string(gotData))
-
-			expectedData, err := json.Marshal(tt.expectedOut)
-			if err != nil {
-				t.Fatalf("sbom: failed to marshal spdx doc: %v", err)
-				return
-			}
-
-			t.Logf("Want SPDX Doc: %s", string(expectedData))
-
-			// compare the spdx Docs
-			compareSpdxDocs(t, spdxDoc, tt.expectedOut)
-
-			// compare deps
-			t.Logf("got deps: %q", deps)
-
-			t.Logf("want deps: %q", tt.expectedDeps)
-
-			if g, w := deps, tt.expectedDeps; !reflect.DeepEqual(g, w) {
-				t.Errorf("unexpected deps, wanted:\n%s\ngot:\n%s\n",
-					strings.Join(w, "\n"), strings.Join(g, "\n"))
-			}
-		})
-	}
-}
-
-func TestGenerateSPDXNamespace(t *testing.T) {
-
-	buildID1 := "example-1"
-	buildID2 := "example-2"
-	files1 := "file1"
-	timestamp1 := "2022-05-01"
-	timestamp2 := "2022-05-02"
-	files2 := "file2"
-
-	// Test case 1: different timestamps, same files
-	nsh1 := generateSPDXNamespace("", timestamp1, files1)
-	nsh2 := generateSPDXNamespace("", timestamp2, files1)
-
-	if nsh1 == "" {
-		t.Errorf("generateSPDXNamespace(%s, %s, %s): expected non-empty string, but got empty string", "", timestamp1, files1)
-	}
-
-	if nsh2 == "" {
-		t.Errorf("generateSPDXNamespace(%s, %s, %s): expected non-empty string, but got empty string", "", timestamp2, files1)
-	}
-
-	if nsh1 == nsh2 {
-		t.Errorf("generateSPDXNamespace(%s, %s, %s) and generateSPDXNamespace(%s, %s, %s): expected different namespace hashes, but got the same", "", timestamp1, files1, "", timestamp2, files1)
-	}
-
-	// Test case 2: different build ids, same timestamps and files
-	nsh1 = generateSPDXNamespace(buildID1, timestamp1, files1)
-	nsh2 = generateSPDXNamespace(buildID2, timestamp1, files1)
-
-	if nsh1 == "" {
-		t.Errorf("generateSPDXNamespace(%s, %s, %s): expected non-empty string, but got empty string", buildID1, timestamp1, files1)
-	}
-
-	if nsh2 == "" {
-		t.Errorf("generateSPDXNamespace(%s, %s, %s): expected non-empty string, but got empty string", buildID2, timestamp1, files1)
-	}
-
-	if nsh1 == nsh2 {
-		t.Errorf("generateSPDXNamespace(%s, %s, %s) and generateSPDXNamespace(%s, %s, %s): expected different namespace hashes, but got the same", buildID1, timestamp1, files1, buildID2, timestamp1, files1)
-	}
-
-	// Test case 3: same build ids and files, different timestamps
-	nsh1 = generateSPDXNamespace(buildID1, timestamp1, files1)
-	nsh2 = generateSPDXNamespace(buildID1, timestamp2, files1)
-
-	if nsh1 == "" {
-		t.Errorf("generateSPDXNamespace(%s, %s, %s): expected non-empty string, but got empty string", buildID1, timestamp1, files1)
-	}
-
-	if nsh2 == "" {
-		t.Errorf("generateSPDXNamespace(%s, %s, %s): expected non-empty string, but got empty string", buildID1, timestamp2, files1)
-	}
-
-	if nsh1 != nsh2 {
-		t.Errorf("generateSPDXNamespace(%s, %s, %s) and generateSPDXNamespace(%s, %s, %s): expected same namespace hashes, but got different: %s and %s", buildID1, timestamp1, files1, buildID2, timestamp1, files1, nsh1, nsh2)
-	}
-
-	// Test case 4: same build ids and timestamps, different files
-	nsh1 = generateSPDXNamespace(buildID1, timestamp1, files1)
-	nsh2 = generateSPDXNamespace(buildID1, timestamp1, files2)
-
-	if nsh1 == "" {
-		t.Errorf("generateSPDXNamespace(%s, %s, %s): expected non-empty string, but got empty string", buildID1, timestamp1, files1)
-	}
-
-	if nsh2 == "" {
-		t.Errorf("generateSPDXNamespace(%s, %s, %s): expected non-empty string, but got empty string", buildID1, timestamp1, files2)
-	}
-
-	if nsh1 == nsh2 {
-		t.Errorf("generateSPDXNamespace(%s, %s, %s) and generateSPDXNamespace(%s, %s, %s): expected different namespace hashes, but got the same", buildID1, timestamp1, files1, buildID1, timestamp1, files2)
-	}
-
-	// Test case 5: empty build ids, same timestamps and different files
-	nsh1 = generateSPDXNamespace("", timestamp1, files1)
-	nsh2 = generateSPDXNamespace("", timestamp1, files2)
-
-	if nsh1 == "" {
-		t.Errorf("generateSPDXNamespace(%s, %s, %s): expected non-empty string, but got empty string", "", timestamp1, files1)
-	}
-
-	if nsh2 == "" {
-		t.Errorf("generateSPDXNamespace(%s, %s, %s): expected non-empty string, but got empty string", "", timestamp1, files2)
-	}
-
-	if nsh1 == nsh2 {
-		t.Errorf("generateSPDXNamespace(%s, %s, %s) and generateSPDXNamespace(%s, %s, %s): expected different namespace hashes, but got the same", "", timestamp1, files1, "", timestamp1, files2)
-	}
-}
-
-func getCreationInfo(t *testing.T) *spdx.CreationInfo {
-	ci, err := builder2v2.BuildCreationInfoSection2_2("Organization", "Google LLC", nil)
-	if err != nil {
-		t.Errorf("Unable to get creation info: %v", err)
-		return nil
-	}
-	return ci
-}
-
-// validate returns an error if the Document is found to be invalid
-func validate(doc *spdx.Document) error {
-	if doc.SPDXVersion == "" {
-		return fmt.Errorf("SPDXVersion: got nothing, want spdx version")
-	}
-	if doc.DataLicense == "" {
-		return fmt.Errorf("DataLicense: got nothing, want Data License")
-	}
-	if doc.SPDXIdentifier == "" {
-		return fmt.Errorf("SPDXIdentifier: got nothing, want SPDX Identifier")
-	}
-	if doc.DocumentName == "" {
-		return fmt.Errorf("DocumentName: got nothing, want Document Name")
-	}
-	if c := fmt.Sprintf("%v", doc.CreationInfo.Creators[1].Creator); c != "Google LLC" {
-		return fmt.Errorf("Creator: got %v, want  'Google LLC'", c)
-	}
-	_, err := time.Parse(time.RFC3339, doc.CreationInfo.Created)
-	if err != nil {
-		return fmt.Errorf("Invalid time spec: %q: got error %q, want no error", doc.CreationInfo.Created, err)
-	}
-
-	for _, license := range doc.OtherLicenses {
-		if license.ExtractedText == "" {
-			return fmt.Errorf("License file: %q: got nothing, want license text", license.LicenseName)
-		}
-	}
-	return nil
-}
-
-// compareSpdxDocs deep-compares two spdx docs by going through the info section, packages, relationships and licenses
-func compareSpdxDocs(t *testing.T, actual, expected *spdx.Document) {
-
-	if actual == nil || expected == nil {
-		t.Errorf("SBOM: SPDX Doc is nil! Got %v: Expected %v", actual, expected)
-	}
-
-	if actual.DocumentName != expected.DocumentName {
-		t.Errorf("sbom: unexpected SPDX Document Name got %q, want %q", actual.DocumentName, expected.DocumentName)
-	}
-
-	if actual.SPDXVersion != expected.SPDXVersion {
-		t.Errorf("sbom: unexpected SPDX Version got %s, want %s", actual.SPDXVersion, expected.SPDXVersion)
-	}
-
-	if actual.DataLicense != expected.DataLicense {
-		t.Errorf("sbom: unexpected SPDX DataLicense got %s, want %s", actual.DataLicense, expected.DataLicense)
-	}
-
-	if actual.SPDXIdentifier != expected.SPDXIdentifier {
-		t.Errorf("sbom: unexpected SPDX Identified got %s, want %s", actual.SPDXIdentifier, expected.SPDXIdentifier)
-	}
-
-	if actual.DocumentNamespace != expected.DocumentNamespace {
-		t.Errorf("sbom: unexpected SPDX Document Namespace got %s, want %s", actual.DocumentNamespace, expected.DocumentNamespace)
-	}
-
-	// compare creation info
-	compareSpdxCreationInfo(t, actual.CreationInfo, expected.CreationInfo)
-
-	// compare packages
-	if len(actual.Packages) != len(expected.Packages) {
-		t.Errorf("SBOM: Number of Packages is different! Got %d: Expected %d", len(actual.Packages), len(expected.Packages))
-	}
-
-	for i, pkg := range actual.Packages {
-		if !compareSpdxPackages(t, i, pkg, expected.Packages[i]) {
-			break
-		}
-	}
-
-	// compare licenses
-	if len(actual.OtherLicenses) != len(expected.OtherLicenses) {
-		t.Errorf("SBOM: Number of Licenses in actual is different! Got %d: Expected %d", len(actual.OtherLicenses), len(expected.OtherLicenses))
-	}
-	for i, license := range actual.OtherLicenses {
-		if !compareLicenses(t, i, license, expected.OtherLicenses[i]) {
-			break
-		}
-	}
-
-	//compare Relationships
-	if len(actual.Relationships) != len(expected.Relationships) {
-		t.Errorf("SBOM: Number of Licenses in actual is different! Got %d: Expected %d", len(actual.Relationships), len(expected.Relationships))
-	}
-	for i, rl := range actual.Relationships {
-		if !compareRelationShips(t, i, rl, expected.Relationships[i]) {
-			break
-		}
-	}
-}
-
-func compareSpdxCreationInfo(t *testing.T, actual, expected *spdx.CreationInfo) {
-	if actual == nil || expected == nil {
-		t.Errorf("SBOM: Creation info is nil! Got %q: Expected %q", actual, expected)
-	}
-
-	if actual.LicenseListVersion != expected.LicenseListVersion {
-		t.Errorf("SBOM: Creation info license version Error! Got %s: Expected %s", actual.LicenseListVersion, expected.LicenseListVersion)
-	}
-
-	if len(actual.Creators) != len(expected.Creators) {
-		t.Errorf("SBOM: Creation info creators Error! Got %d: Expected %d", len(actual.Creators), len(expected.Creators))
-	}
-
-	for i, info := range actual.Creators {
-		if info != expected.Creators[i] {
-			t.Errorf("SBOM: Creation info creators Error! Got %q: Expected %q", info, expected.Creators[i])
-		}
-	}
-}
-
-func compareSpdxPackages(t *testing.T, i int, actual, expected *spdx.Package) bool {
-	if actual == nil || expected == nil {
-		t.Errorf("SBOM: Packages are nil at index %d! Got %v: Expected %v", i, actual, expected)
-		return false
-	}
-	if actual.PackageName != expected.PackageName {
-		t.Errorf("SBOM: Package name Error at index %d! Got %s: Expected %s", i, actual.PackageName, expected.PackageName)
-		return false
-	}
-
-	if actual.PackageVersion != expected.PackageVersion {
-		t.Errorf("SBOM: Package version Error at index %d! Got %s: Expected %s", i, actual.PackageVersion, expected.PackageVersion)
-		return false
-	}
-
-	if actual.PackageSPDXIdentifier != expected.PackageSPDXIdentifier {
-		t.Errorf("SBOM: Package identifier Error at index %d! Got %s: Expected %s", i, actual.PackageSPDXIdentifier, expected.PackageSPDXIdentifier)
-		return false
-	}
-
-	if actual.PackageDownloadLocation != expected.PackageDownloadLocation {
-		t.Errorf("SBOM: Package download location Error at index %d! Got %s: Expected %s", i, actual.PackageDownloadLocation, expected.PackageDownloadLocation)
-		return false
-	}
-
-	if actual.PackageLicenseConcluded != expected.PackageLicenseConcluded {
-		t.Errorf("SBOM: Package license concluded Error at index %d! Got %s: Expected %s", i, actual.PackageLicenseConcluded, expected.PackageLicenseConcluded)
-		return false
-	}
-	return true
-}
-
-func compareRelationShips(t *testing.T, i int, actual, expected *spdx.Relationship) bool {
-	if actual == nil || expected == nil {
-		t.Errorf("SBOM: Relationships is nil at index %d! Got %v: Expected %v", i, actual, expected)
-		return false
-	}
-
-	if actual.RefA != expected.RefA {
-		t.Errorf("SBOM: Relationship RefA Error at index %d! Got %s: Expected %s", i, actual.RefA, expected.RefA)
-		return false
-	}
-
-	if actual.RefB != expected.RefB {
-		t.Errorf("SBOM: Relationship RefB Error at index %d! Got %s: Expected %s", i, actual.RefB, expected.RefB)
-		return false
-	}
-
-	if actual.Relationship != expected.Relationship {
-		t.Errorf("SBOM: Relationship type Error at index %d! Got %s: Expected %s", i, actual.Relationship, expected.Relationship)
-		return false
-	}
-	return true
-}
-
-func compareLicenses(t *testing.T, i int, actual, expected *spdx.OtherLicense) bool {
-	if actual == nil || expected == nil {
-		t.Errorf("SBOM: Licenses is nil at index %d! Got %v: Expected %v", i, actual, expected)
-		return false
-	}
-
-	if actual.LicenseName != expected.LicenseName {
-		t.Errorf("SBOM: License Name Error at index %d! Got %s: Expected %s", i, actual.LicenseName, expected.LicenseName)
-		return false
-	}
-
-	if actual.LicenseIdentifier != expected.LicenseIdentifier {
-		t.Errorf("SBOM: License Identifier Error at index %d! Got %s: Expected %s", i, actual.LicenseIdentifier, expected.LicenseIdentifier)
-		return false
-	}
-
-	if actual.ExtractedText != expected.ExtractedText {
-		t.Errorf("SBOM: License Extracted Text Error at index %d! Got: %q want: %q", i, actual.ExtractedText, expected.ExtractedText)
-		return false
-	}
-	return true
-}
-
-func fakeTime() string {
-	t := time.UnixMicro(0)
-	return t.UTC().Format("2006-01-02T15:04:05Z")
-}
diff --git a/tools/dependency_mapper/Android.bp b/tools/dependency_mapper/Android.bp
new file mode 100644
index 0000000000..6763c0e106
--- /dev/null
+++ b/tools/dependency_mapper/Android.bp
@@ -0,0 +1,45 @@
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+    default_team: "trendy_team_android_crumpet",
+}
+
+java_binary_host {
+    name: "dependency-mapper",
+    main_class: "com.android.dependencymapper.Main",
+    static_libs: [
+        "dependency-mapper-host-lib",
+    ],
+    visibility: ["//visibility:public"],
+}
+
+java_library_host {
+    name: "dependency-mapper-host-lib",
+    srcs: [
+        "src/**/*.java",
+        "proto/**/*.proto",
+    ],
+    static_libs: [
+        "gson",
+        "ow2-asm",
+    ],
+}
+
+java_test_host {
+    name: "dependency-mapper-tests",
+    srcs: ["tests/src/**/*.java"],
+    static_libs: [
+        "junit",
+        "dependency-mapper-host-lib",
+    ],
+    data: [
+        "tests/res/**/*",
+    ],
+    test_options: {
+        unit_test: true,
+    },
+}
+
+java_library {
+    name: "dependency-mapper-test-data",
+    srcs: ["tests/res/**/*.java"],
+}
diff --git a/tools/dependency_mapper/OWNERS b/tools/dependency_mapper/OWNERS
new file mode 100644
index 0000000000..44772698c4
--- /dev/null
+++ b/tools/dependency_mapper/OWNERS
@@ -0,0 +1 @@
+himanshuz@google.com
\ No newline at end of file
diff --git a/tools/dependency_mapper/README.md b/tools/dependency_mapper/README.md
new file mode 100644
index 0000000000..475aef24fe
--- /dev/null
+++ b/tools/dependency_mapper/README.md
@@ -0,0 +1,26 @@
+# Dependency Mapper
+
+[dependency-mapper] command line tool. This tool finds the usage based dependencies between java
+files by utilizing byte-code and java file analysis.
+
+# Getting Started
+
+## Inputs
+* rsp file, containing list of java files separated by whitespace.
+* jar file, containing class files generated after compiling the contents of rsp file.
+
+## Output
+* proto file, representing the list of dependencies for each java file present in input rsp file,
+represented by [proto/usage.proto]
+
+## Usage
+```
+dependency-mapper --src-path [src-list.rsp] --jar-path [classes.jar] --usage-map-path [usage-map.proto]"
+```
+
+# Notes
+## Dependencies enlisted are only within the java files present in input.
+## Ensure that [SourceFile] is present in the classes present in the jar.
+## To ensure dependencies are listed correctly
+* Classes jar should only contain class files generated from the source rsp files.
+* Classes jar should not exclude any class file that was generated from source rsp files.
\ No newline at end of file
diff --git a/tools/dependency_mapper/proto/dependency.proto b/tools/dependency_mapper/proto/dependency.proto
new file mode 100644
index 0000000000..60a88f8f40
--- /dev/null
+++ b/tools/dependency_mapper/proto/dependency.proto
@@ -0,0 +1,46 @@
+/*
+ * Copyright (C) 2019 The Android Open Source Project
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
+syntax = "proto2";
+
+package com.android.dependencymapper;
+option java_package = "com.android.dependencymapper";
+option java_outer_classname = "DependencyProto";
+
+/**
+ * A com.android.dependencymapper.DependencyProto.FileDependency object.
+ */
+
+message FileDependency {
+
+  // java file path on disk
+  optional string file_path = 1;
+  // if a change in this file warrants recompiling all files
+  optional bool is_dependency_to_all = 2;
+  // class files generated when this java file is compiled
+  repeated string generated_classes = 3;
+  // dependencies of this file.
+  repeated string file_dependencies = 4;
+}
+
+/**
+ * A com.android.dependencymapper.DependencyProto.FileDependencyList object.
+ */
+message FileDependencyList {
+
+  // List of java file usages
+  repeated FileDependency fileDependency = 1;
+}
\ No newline at end of file
diff --git a/tools/dependency_mapper/src/com/android/dependencymapper/ClassDependenciesVisitor.java b/tools/dependency_mapper/src/com/android/dependencymapper/ClassDependenciesVisitor.java
new file mode 100644
index 0000000000..ba6514586e
--- /dev/null
+++ b/tools/dependency_mapper/src/com/android/dependencymapper/ClassDependenciesVisitor.java
@@ -0,0 +1,316 @@
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
+package com.android.dependencymapper;
+
+import org.objectweb.asm.signature.SignatureReader;
+import org.objectweb.asm.signature.SignatureVisitor;
+import org.objectweb.asm.ClassReader;
+import org.objectweb.asm.ClassVisitor;
+import org.objectweb.asm.Label;
+import org.objectweb.asm.Opcodes;
+import org.objectweb.asm.Type;
+import org.objectweb.asm.TypePath;
+
+import java.lang.annotation.RetentionPolicy;
+import java.util.HashSet;
+import java.util.Set;
+
+/**
+ * An ASM based class visitor to analyze and club all dependencies of a java file.
+ * Most of the logic of this class is inspired from
+ * <a href="https://github.com/gradle/gradle/blob/master/platforms/jvm/language-java/src/main/java/org/gradle/api/internal/tasks/compile/incremental/asm/ClassDependenciesVisitor.java">gradle incremental compilation</a>
+ */
+public class ClassDependenciesVisitor extends ClassVisitor {
+
+    private final static int API = Opcodes.ASM9;
+
+    private final Set<String> mClassTypes;
+    private final Set<Object> mConstantsDefined;
+    private final Set<Object> mInlinedUsages;
+    private String mSource;
+    private boolean isAnnotationType;
+    private boolean mIsDependencyToAll;
+    private final RetentionPolicyVisitor retentionPolicyVisitor;
+
+    private final ClassRelevancyFilter mClassFilter;
+
+    private ClassDependenciesVisitor(ClassReader reader, ClassRelevancyFilter filter) {
+        super(API);
+        this.mClassTypes = new HashSet<>();
+        this.mConstantsDefined = new HashSet<>();
+        this.mInlinedUsages =  new HashSet<>();
+        this.retentionPolicyVisitor = new RetentionPolicyVisitor();
+        this.mClassFilter = filter;
+        collectRemainingClassDependencies(reader);
+    }
+
+    public static ClassDependencyData analyze(
+            String className, ClassReader reader, ClassRelevancyFilter filter) {
+        ClassDependenciesVisitor visitor = new ClassDependenciesVisitor(reader, filter);
+        reader.accept(visitor, ClassReader.SKIP_FRAMES);
+        // Sometimes a class may contain references to the same class, we remove such cases to
+        // prevent circular dependency.
+        visitor.getClassTypes().remove(className);
+        return new ClassDependencyData(Utils.buildPackagePrependedClassSource(
+                className, visitor.getSource()), className, visitor.getClassTypes(),
+                visitor.isDependencyToAll(), visitor.getConstantsDefined(),
+                visitor.getInlinedUsages());
+    }
+
+    @Override
+    public void visitSource(String source, String debug) {
+        mSource = source;
+    }
+
+    @Override
+    public void visit(int version, int access, String name, String signature, String superName,
+            String[] interfaces) {
+        isAnnotationType = isAnnotationType(interfaces);
+        maybeAddClassTypesFromSignature(signature, mClassTypes);
+        if (superName != null) {
+            // superName can be null if what we are analyzing is `java.lang.Object`
+            // which can happen when a custom Java SDK is on classpath (typically, android.jar)
+            Type type = Type.getObjectType(superName);
+            maybeAddClassType(mClassTypes, type);
+        }
+        for (String s : interfaces) {
+            Type interfaceType = Type.getObjectType(s);
+            maybeAddClassType(mClassTypes, interfaceType);
+        }
+    }
+
+    // performs a fast analysis of classes referenced in bytecode (method bodies)
+    // avoiding us to implement a costly visitor and potentially missing edge cases
+    private void collectRemainingClassDependencies(ClassReader reader) {
+        char[] charBuffer = new char[reader.getMaxStringLength()];
+        for (int i = 1; i < reader.getItemCount(); i++) {
+            int itemOffset = reader.getItem(i);
+            // see https://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.4
+            if (itemOffset > 0 && reader.readByte(itemOffset - 1) == 7) {
+                // A CONSTANT_Class entry, read the class descriptor
+                String classDescriptor = reader.readUTF8(itemOffset, charBuffer);
+                Type type = Type.getObjectType(classDescriptor);
+                maybeAddClassType(mClassTypes, type);
+            }
+        }
+    }
+
+    private void maybeAddClassTypesFromSignature(String signature, Set<String> types) {
+        if (signature != null) {
+            SignatureReader signatureReader = new SignatureReader(signature);
+            signatureReader.accept(new SignatureVisitor(API) {
+                @Override
+                public void visitClassType(String className) {
+                    Type type = Type.getObjectType(className);
+                    maybeAddClassType(types, type);
+                }
+            });
+        }
+    }
+
+    protected void maybeAddClassType(Set<String> types, Type type) {
+        while (type.getSort() == Type.ARRAY) {
+            type = type.getElementType();
+        }
+        if (type.getSort() != Type.OBJECT) {
+            return;
+        }
+        //String name = Utils.classPackageToFilePath(type.getClassName());
+        String name = type.getClassName();
+        if (mClassFilter.test(name)) {
+            types.add(name);
+        }
+    }
+
+    public String getSource() {
+        return mSource;
+    }
+
+    public Set<String> getClassTypes() {
+        return mClassTypes;
+    }
+
+    public Set<Object> getConstantsDefined() {
+        return mConstantsDefined;
+    }
+
+    public Set<Object> getInlinedUsages() {
+        return mInlinedUsages;
+    }
+
+    private boolean isAnnotationType(String[] interfaces) {
+        return interfaces.length == 1 && interfaces[0].equals("java/lang/annotation/Annotation");
+    }
+
+    @Override
+    public FieldVisitor visitField(
+            int access, String name, String desc, String signature, Object value) {
+        maybeAddClassTypesFromSignature(signature, mClassTypes);
+        maybeAddClassType(mClassTypes, Type.getType(desc));
+        if (isAccessibleConstant(access, value)) {
+            mConstantsDefined.add(value);
+        }
+        return new FieldVisitor(mClassTypes);
+    }
+
+    @Override
+    public MethodVisitor visitMethod(
+            int access, String name, String desc, String signature, String[] exceptions) {
+        maybeAddClassTypesFromSignature(signature, mClassTypes);
+        Type methodType = Type.getMethodType(desc);
+        maybeAddClassType(mClassTypes, methodType.getReturnType());
+        for (Type argType : methodType.getArgumentTypes()) {
+            maybeAddClassType(mClassTypes, argType);
+        }
+        return new MethodVisitor(mClassTypes);
+    }
+
+    @Override
+    public org.objectweb.asm.AnnotationVisitor visitAnnotation(String desc, boolean visible) {
+        if (isAnnotationType && "Ljava/lang/annotation/Retention;".equals(desc)) {
+            return retentionPolicyVisitor;
+        } else {
+            maybeAddClassType(mClassTypes, Type.getType(desc));
+            return new AnnotationVisitor(mClassTypes);
+        }
+    }
+
+    private static boolean isAccessible(int access) {
+        return (access & Opcodes.ACC_PRIVATE) == 0;
+    }
+
+    private static boolean isAccessibleConstant(int access, Object value) {
+        return isConstant(access) && isAccessible(access) && value != null;
+    }
+
+    private static boolean isConstant(int access) {
+        return (access & Opcodes.ACC_FINAL) != 0 && (access & Opcodes.ACC_STATIC) != 0;
+    }
+
+    public boolean isDependencyToAll() {
+        return mIsDependencyToAll;
+    }
+
+    private class FieldVisitor extends org.objectweb.asm.FieldVisitor {
+        private final Set<String> types;
+
+        public FieldVisitor(Set<String> types) {
+            super(API);
+            this.types = types;
+        }
+
+        @Override
+        public org.objectweb.asm.AnnotationVisitor visitAnnotation(
+                String descriptor, boolean visible) {
+            maybeAddClassType(types, Type.getType(descriptor));
+            return new AnnotationVisitor(types);
+        }
+
+        @Override
+        public org.objectweb.asm.AnnotationVisitor visitTypeAnnotation(int typeRef,
+                TypePath typePath, String descriptor, boolean visible) {
+            maybeAddClassType(types, Type.getType(descriptor));
+            return new AnnotationVisitor(types);
+        }
+    }
+
+    private class MethodVisitor extends org.objectweb.asm.MethodVisitor {
+        private final Set<String> types;
+
+        protected MethodVisitor(Set<String> types) {
+            super(API);
+            this.types = types;
+        }
+
+        @Override
+        public void visitLdcInsn(Object value) {
+            mInlinedUsages.add(value);
+            super.visitLdcInsn(value);
+        }
+
+        @Override
+        public void visitLocalVariable(
+                String name, String desc, String signature, Label start, Label end, int index) {
+            maybeAddClassTypesFromSignature(signature, mClassTypes);
+            maybeAddClassType(mClassTypes, Type.getType(desc));
+            super.visitLocalVariable(name, desc, signature, start, end, index);
+        }
+
+        @Override
+        public org.objectweb.asm.AnnotationVisitor visitAnnotation(
+                String descriptor, boolean visible) {
+            maybeAddClassType(types, Type.getType(descriptor));
+            return new AnnotationVisitor(types);
+        }
+
+        @Override
+        public org.objectweb.asm.AnnotationVisitor visitParameterAnnotation(
+                int parameter, String descriptor, boolean visible) {
+            maybeAddClassType(types, Type.getType(descriptor));
+            return new AnnotationVisitor(types);
+        }
+
+        @Override
+        public org.objectweb.asm.AnnotationVisitor visitTypeAnnotation(
+                int typeRef, TypePath typePath, String descriptor, boolean visible) {
+            maybeAddClassType(types, Type.getType(descriptor));
+            return new AnnotationVisitor(types);
+        }
+    }
+
+    private class RetentionPolicyVisitor extends org.objectweb.asm.AnnotationVisitor {
+        public RetentionPolicyVisitor() {
+            super(ClassDependenciesVisitor.API);
+        }
+
+        @Override
+        public void visitEnum(String name, String desc, String value) {
+            if ("Ljava/lang/annotation/RetentionPolicy;".equals(desc)) {
+                RetentionPolicy policy = RetentionPolicy.valueOf(value);
+                if (policy == RetentionPolicy.SOURCE) {
+                    mIsDependencyToAll = true;
+                }
+            }
+        }
+    }
+
+    private class AnnotationVisitor extends org.objectweb.asm.AnnotationVisitor {
+        private final Set<String> types;
+
+        public AnnotationVisitor(Set<String> types) {
+            super(ClassDependenciesVisitor.API);
+            this.types = types;
+        }
+
+        @Override
+        public void visit(String name, Object value) {
+            if (value instanceof Type) {
+                maybeAddClassType(types, (Type) value);
+            }
+        }
+
+        @Override
+        public org.objectweb.asm.AnnotationVisitor visitArray(String name) {
+            return this;
+        }
+
+        @Override
+        public org.objectweb.asm.AnnotationVisitor visitAnnotation(String name, String descriptor) {
+            maybeAddClassType(types, Type.getType(descriptor));
+            return this;
+        }
+    }
+}
\ No newline at end of file
diff --git a/tools/dependency_mapper/src/com/android/dependencymapper/ClassDependencyAnalyzer.java b/tools/dependency_mapper/src/com/android/dependencymapper/ClassDependencyAnalyzer.java
new file mode 100644
index 0000000000..4a37b41ffe
--- /dev/null
+++ b/tools/dependency_mapper/src/com/android/dependencymapper/ClassDependencyAnalyzer.java
@@ -0,0 +1,56 @@
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
+package com.android.dependencymapper;
+
+import org.objectweb.asm.ClassReader;
+
+import java.io.IOException;
+import java.io.InputStream;
+import java.nio.file.Path;
+import java.util.ArrayList;
+import java.util.Enumeration;
+import java.util.List;
+import java.util.jar.JarEntry;
+import java.util.jar.JarFile;
+
+/**
+ * An utility class that reads each class file present in the classes jar, then analyzes the same,
+ * collecting the dependencies in {@link List<ClassDependencyData>}
+ */
+public class ClassDependencyAnalyzer {
+
+    public static List<ClassDependencyData> analyze(Path classJar, ClassRelevancyFilter classFilter) {
+        List<ClassDependencyData> classAnalysisList = new ArrayList<>();
+        try (JarFile jarFile = new JarFile(classJar.toFile())) {
+            Enumeration<JarEntry> entries = jarFile.entries();
+            while (entries.hasMoreElements()) {
+                JarEntry entry = entries.nextElement();
+                if (entry.getName().endsWith(".class")) {
+                    try (InputStream inputStream = jarFile.getInputStream(entry)) {
+                        String name = Utils.trimAndConvertToPackageBasedPath(entry.getName());
+                        ClassDependencyData classAnalysis = ClassDependenciesVisitor.analyze(name,
+                                new ClassReader(inputStream), classFilter);
+                        classAnalysisList.add(classAnalysis);
+                    }
+                }
+            }
+        } catch (IOException e) {
+            System.err.println("Error reading the jar file at: " + classJar);
+            throw new RuntimeException(e);
+        }
+        return classAnalysisList;
+    }
+}
diff --git a/tools/dependency_mapper/src/com/android/dependencymapper/ClassDependencyData.java b/tools/dependency_mapper/src/com/android/dependencymapper/ClassDependencyData.java
new file mode 100644
index 0000000000..58e388faa0
--- /dev/null
+++ b/tools/dependency_mapper/src/com/android/dependencymapper/ClassDependencyData.java
@@ -0,0 +1,65 @@
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
+package com.android.dependencymapper;
+
+import java.util.Set;
+
+/**
+ * Represents the Class Dependency Data collected via ASM analysis.
+ */
+public class ClassDependencyData {
+    private final String mPackagePrependedClassSource;
+    private final String mQualifiedName;
+    private final Set<String> mClassDependencies;
+    private final boolean mIsDependencyToAll;
+    private final Set<Object> mConstantsDefined;
+    private final Set<Object> mInlinedUsages;
+
+    public ClassDependencyData(String packagePrependedClassSource, String className,
+            Set<String> classDependencies, boolean isDependencyToAll, Set<Object> constantsDefined,
+            Set<Object> inlinedUsages) {
+        this.mPackagePrependedClassSource = packagePrependedClassSource;
+        this.mQualifiedName = className;
+        this.mClassDependencies = classDependencies;
+        this.mIsDependencyToAll = isDependencyToAll;
+        this.mConstantsDefined = constantsDefined;
+        this.mInlinedUsages = inlinedUsages;
+    }
+
+    public String getPackagePrependedClassSource() {
+        return mPackagePrependedClassSource;
+    }
+
+    public String getQualifiedName() {
+        return mQualifiedName;
+    }
+
+    public Set<String> getClassDependencies() {
+        return mClassDependencies;
+    }
+
+    public Set<Object> getConstantsDefined() {
+        return mConstantsDefined;
+    }
+
+    public Set<Object> inlinedUsages() {
+        return mInlinedUsages;
+    }
+
+    public boolean isDependencyToAll() {
+        return mIsDependencyToAll;
+    }
+}
diff --git a/tools/dependency_mapper/src/com/android/dependencymapper/ClassRelevancyFilter.java b/tools/dependency_mapper/src/com/android/dependencymapper/ClassRelevancyFilter.java
new file mode 100644
index 0000000000..c46b53f6d1
--- /dev/null
+++ b/tools/dependency_mapper/src/com/android/dependencymapper/ClassRelevancyFilter.java
@@ -0,0 +1,36 @@
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
+package com.android.dependencymapper;
+
+import java.util.Set;
+import java.util.function.Predicate;
+
+/**
+ * A filter representing the list of class files which are relevant for dependency analysis.
+ */
+public class ClassRelevancyFilter implements Predicate<String> {
+
+    private final Set<String> mAllowlistedClassNames;
+
+    public ClassRelevancyFilter(Set<String> allowlistedClassNames) {
+        this.mAllowlistedClassNames = allowlistedClassNames;
+    }
+
+    @Override
+    public boolean test(String className) {
+        return mAllowlistedClassNames.contains(className);
+    }
+}
diff --git a/tools/dependency_mapper/src/com/android/dependencymapper/DependencyMapper.java b/tools/dependency_mapper/src/com/android/dependencymapper/DependencyMapper.java
new file mode 100644
index 0000000000..ecf520c7d8
--- /dev/null
+++ b/tools/dependency_mapper/src/com/android/dependencymapper/DependencyMapper.java
@@ -0,0 +1,165 @@
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
+package com.android.dependencymapper;
+
+import com.android.dependencymapper.DependencyProto;
+
+import java.util.ArrayList;
+import java.util.HashMap;
+import java.util.HashSet;
+import java.util.List;
+import java.util.Map;
+import java.util.Set;
+
+/**
+ * This class binds {@link List<ClassDependencyData>} and {@link List<JavaSourceData>} together as a
+ * flat map, which represents dependency related attributes of a java file.
+ */
+public class DependencyMapper {
+    private final List<ClassDependencyData> mClassAnalysisList;
+    private final List<JavaSourceData> mJavaSourceDataList;
+    private final Map<String, String> mClassToSourceMap = new HashMap<>();
+    private final Map<String, Set<String>> mFileDependencies = new HashMap<>();
+    private final Set<String> mDependencyToAll = new HashSet<>();
+    private final Map<String, Set<String>> mSourceToClasses = new HashMap<>();
+
+    public DependencyMapper(List<ClassDependencyData> classAnalysisList, List<JavaSourceData> javaSourceDataList) {
+        this.mClassAnalysisList = classAnalysisList;
+        this.mJavaSourceDataList = javaSourceDataList;
+    }
+
+    public DependencyProto.FileDependencyList buildDependencyMaps() {
+        buildClassDependencyMaps();
+        buildSourceToClassMap();
+        return createFileDependencies();
+    }
+
+    private void buildClassDependencyMaps() {
+        // Create a map between package appended file names and file paths.
+        Map<String, String> sourcePaths = generateSourcePaths();
+        // A map between qualified className and its dependencies
+        Map<String, Set<String>> classDependencies = new HashMap<>();
+        // A map between constant values and the their declarations.
+        Map<Object, Set<String>> constantRegistry = new HashMap<>();
+        // A map between constant values and the their inlined usages.
+        Map<Object, Set<String>> inlinedUsages = new HashMap<>();
+
+        for (ClassDependencyData analysis : mClassAnalysisList) {
+            String className = analysis.getQualifiedName();
+
+            // Compute qualified class name to source path map.
+            String sourceKey = analysis.getPackagePrependedClassSource();
+            String sourcePath = sourcePaths.get(sourceKey);
+            mClassToSourceMap.put(className, sourcePath);
+
+            // compute classDependencies
+            classDependencies.computeIfAbsent(className, k ->
+                    new HashSet<>()).addAll(analysis.getClassDependencies());
+
+            // Compute constantRegistry
+            analysis.getConstantsDefined().forEach(c ->
+                    constantRegistry.computeIfAbsent(c, k -> new HashSet<>()).add(className));
+            // Compute inlinedUsages map.
+            analysis.inlinedUsages().forEach(u ->
+                    inlinedUsages.computeIfAbsent(u, k -> new HashSet<>()).add(className));
+
+            if (analysis.isDependencyToAll()) {
+                mDependencyToAll.add(sourcePath);
+            }
+        }
+        // Finally build file dependencies
+        buildFileDependencies(
+                combineDependencies(classDependencies, inlinedUsages, constantRegistry));
+    }
+
+    private Map<String, String> generateSourcePaths() {
+        Map<String, String> sourcePaths = new HashMap<>();
+        mJavaSourceDataList.forEach(data ->
+                sourcePaths.put(data.getPackagePrependedFileName(), data.getFilePath()));
+        return sourcePaths;
+    }
+
+    private Map<String, Set<String>> combineDependencies(Map<String, Set<String>> classDependencies,
+            Map<Object, Set<String>> inlinedUsages,
+            Map<Object, Set<String>> constantRegistry) {
+        Map<String, Set<String>> combined = new HashMap<>(
+                buildConstantDependencies(inlinedUsages, constantRegistry));
+        classDependencies.forEach((k, v) ->
+                combined.computeIfAbsent(k, key -> new HashSet<>()).addAll(v));
+        return combined;
+    }
+
+    private Map<String, Set<String>> buildConstantDependencies(
+            Map<Object, Set<String>> inlinedUsages, Map<Object, Set<String>> constantRegistry) {
+        Map<String, Set<String>> constantDependencies = new HashMap<>();
+        for (Map.Entry<Object, Set<String>> usageEntry : inlinedUsages.entrySet()) {
+            Object usage = usageEntry.getKey();
+            Set<String> usageClasses = usageEntry.getValue();
+            if (constantRegistry.containsKey(usage)) {
+                Set<String> declarationClasses = constantRegistry.get(usage);
+                for (String usageClass : usageClasses) {
+                    // Sometimes Usage and Declarations are in the same file, we remove such cases
+                    // to prevent circular dependency.
+                    declarationClasses.remove(usageClass);
+                    constantDependencies.computeIfAbsent(usageClass, k ->
+                            new HashSet<>()).addAll(declarationClasses);
+                }
+            }
+        }
+
+        return constantDependencies;
+    }
+
+    private void buildFileDependencies(Map<String, Set<String>> combinedClassDependencies) {
+        combinedClassDependencies.forEach((className, dependencies) -> {
+            String sourceFile = mClassToSourceMap.get(className);
+            if (sourceFile == null) {
+                throw new IllegalArgumentException("Class '" + className
+                        + "' does not have a corresponding source file.");
+            }
+            mFileDependencies.computeIfAbsent(sourceFile, k -> new HashSet<>());
+            dependencies.forEach(dependency -> {
+                String dependencySource = mClassToSourceMap.get(dependency);
+                if (dependencySource == null) {
+                    throw new IllegalArgumentException("Dependency '" + dependency
+                            + "' does not have a corresponding source file.");
+                }
+                mFileDependencies.get(sourceFile).add(dependencySource);
+            });
+        });
+    }
+
+    private void buildSourceToClassMap() {
+        mClassToSourceMap.forEach((className, sourceFile) ->
+                mSourceToClasses.computeIfAbsent(sourceFile, k ->
+                        new HashSet<>()).add(className));
+    }
+
+    private DependencyProto.FileDependencyList createFileDependencies() {
+        List<DependencyProto.FileDependency> fileDependencies = new ArrayList<>();
+        mFileDependencies.forEach((file, dependencies) -> {
+            DependencyProto.FileDependency dependency = DependencyProto.FileDependency.newBuilder()
+                    .setFilePath(file)
+                    .setIsDependencyToAll(mDependencyToAll.contains(file))
+                    .addAllGeneratedClasses(mSourceToClasses.get(file))
+                    .addAllFileDependencies(dependencies)
+                    .build();
+            fileDependencies.add(dependency);
+        });
+        return DependencyProto.FileDependencyList.newBuilder()
+                .addAllFileDependency(fileDependencies).build();
+    }
+}
diff --git a/tools/dependency_mapper/src/com/android/dependencymapper/JavaSourceAnalyzer.java b/tools/dependency_mapper/src/com/android/dependencymapper/JavaSourceAnalyzer.java
new file mode 100644
index 0000000000..3a4efadd77
--- /dev/null
+++ b/tools/dependency_mapper/src/com/android/dependencymapper/JavaSourceAnalyzer.java
@@ -0,0 +1,81 @@
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
+package com.android.dependencymapper;
+
+import java.io.BufferedReader;
+import java.io.FileReader;
+import java.io.IOException;
+import java.nio.file.Path;
+import java.nio.file.Paths;
+import java.util.ArrayList;
+import java.util.List;
+import java.util.regex.Matcher;
+import java.util.regex.Pattern;
+
+/**
+ * An utility class that reads each java file present in the rsp content then analyzes the same,
+ * collecting the analysis in {@link List<JavaSourceData>}
+ */
+public class JavaSourceAnalyzer {
+
+    // Regex that matches against "package abc.xyz.lmn;" declarations in a java file.
+    private static final String PACKAGE_REGEX = "^package\\s+([a-zA-Z_][a-zA-Z0-9_.]*);";
+
+    public static List<JavaSourceData> analyze(Path srcRspFile) {
+        List<JavaSourceData> javaSourceDataList = new ArrayList<>();
+        try (BufferedReader reader = new BufferedReader(new FileReader(srcRspFile.toFile()))) {
+            String line;
+            while ((line = reader.readLine()) != null) {
+                // Split the line by spaces, tabs, multiple java files can be on a single line.
+                String[] files = line.trim().split("\\s+");
+                for (String file : files) {
+                    Path p = Paths.get("", file);
+                    System.out.println(p.toAbsolutePath().toString());
+                    javaSourceDataList
+                            .add(new JavaSourceData(file, constructPackagePrependedFileName(file)));
+                }
+            }
+        } catch (IOException e) {
+            System.err.println("Error reading rsp file at: " + srcRspFile);
+            throw new RuntimeException(e);
+        }
+        return javaSourceDataList;
+    }
+
+    private static String constructPackagePrependedFileName(String filePath) {
+        String packageAppendedFileName = null;
+        // if the file path is abc/def/ghi/JavaFile.java we extract JavaFile.java
+        String javaFileName = filePath.substring(filePath.lastIndexOf("/") + 1);
+        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
+            String line;
+            // Process each line and match against the package regex pattern.
+            while ((line = reader.readLine()) != null) {
+                Pattern pattern = Pattern.compile(PACKAGE_REGEX);
+                Matcher matcher = pattern.matcher(line);
+                if (matcher.find()) {
+                    packageAppendedFileName = matcher.group(1) + "." + javaFileName;
+                    break;
+                }
+            }
+        } catch (IOException e) {
+            System.err.println("Error reading java file at: " + filePath);
+            throw new RuntimeException(e);
+        }
+        // Should not be null
+        assert packageAppendedFileName != null;
+        return packageAppendedFileName;
+    }
+}
diff --git a/tools/dependency_mapper/src/com/android/dependencymapper/JavaSourceData.java b/tools/dependency_mapper/src/com/android/dependencymapper/JavaSourceData.java
new file mode 100644
index 0000000000..89453d0abe
--- /dev/null
+++ b/tools/dependency_mapper/src/com/android/dependencymapper/JavaSourceData.java
@@ -0,0 +1,38 @@
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
+package com.android.dependencymapper;
+
+/**
+ * POJO representing the data collected from Java Source file analysis.
+ */
+public class JavaSourceData {
+
+    private final String mFilePath;
+    private final String mPackagePrependedFileName;
+
+    public JavaSourceData(String filePath, String packagePrependedFileName) {
+        mFilePath = filePath;
+        mPackagePrependedFileName = packagePrependedFileName;
+    }
+
+    public String getFilePath() {
+        return mFilePath;
+    }
+
+    public String getPackagePrependedFileName() {
+        return mPackagePrependedFileName;
+    }
+}
diff --git a/tools/dependency_mapper/src/com/android/dependencymapper/Main.java b/tools/dependency_mapper/src/com/android/dependencymapper/Main.java
new file mode 100644
index 0000000000..131c931098
--- /dev/null
+++ b/tools/dependency_mapper/src/com/android/dependencymapper/Main.java
@@ -0,0 +1,123 @@
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
+package com.android.dependencymapper;
+
+import static com.android.dependencymapper.Utils.listClassesInJar;
+
+import com.android.dependencymapper.DependencyProto;
+
+import java.io.IOException;
+import java.nio.file.Files;
+import java.nio.file.Path;
+import java.util.List;
+import java.util.Set;
+
+public class Main {
+
+    public static void main(String[] args) throws IOException, InterruptedException {
+        try {
+            InputData input = parseAndValidateInput(args);
+            generateDependencyMap(input);
+        } catch (IllegalArgumentException e) {
+            System.err.println("Error: " + e.getMessage());
+            showUsage();
+        }
+    }
+
+    private static class InputData {
+        public Path srcList;
+        public Path classesJar;
+        public Path dependencyMapProto;
+
+        public InputData(Path srcList, Path classesJar, Path dependencyMapProto) {
+            this.srcList = srcList;
+            this.classesJar = classesJar;
+            this.dependencyMapProto = dependencyMapProto;
+        }
+    }
+
+    private static InputData parseAndValidateInput(String[] args) {
+        for (String arg : args) {
+            if ("--help".equals(arg)) {
+                showUsage();
+                System.exit(0); // Indicate successful exit after showing help
+            }
+        }
+
+        if (args.length != 6) { // Explicitly check for the correct number of arguments
+            throw new IllegalArgumentException("Incorrect number of arguments");
+        }
+
+        Path srcList = null;
+        Path classesJar = null;
+        Path dependencyMapProto = null;
+
+        for (int i = 0; i < args.length; i += 2) {
+            String arg = args[i].trim();
+            String argValue = args[i + 1].trim();
+
+            switch (arg) {
+                case "--src-path" -> srcList = Path.of(argValue);
+                case "--jar-path" -> classesJar = Path.of(argValue);
+                case "--dependency-map-path" -> dependencyMapProto = Path.of(argValue);
+                default -> throw new IllegalArgumentException("Unknown argument: " + arg);
+            }
+        }
+
+        // Validate file existence and readability
+        validateFile(srcList, "--src-path");
+        validateFile(classesJar, "--jar-path");
+
+        return new InputData(srcList, classesJar, dependencyMapProto);
+    }
+
+    private static void validateFile(Path path, String argName) {
+        if (path == null) {
+            throw new IllegalArgumentException(argName + " is required");
+        }
+        if (!Files.exists(path)) {
+            throw new IllegalArgumentException(argName + " does not exist: " + path);
+        }
+        if (!Files.isReadable(path)) {
+            throw new IllegalArgumentException(argName + " is not readable: " + path);
+        }
+    }
+
+    private static void generateDependencyMap(InputData input) {
+        // First collect all classes in the jar.
+        Set<String> classesInJar = listClassesInJar(input.classesJar);
+        // Perform dependency analysis.
+        List<ClassDependencyData> classDependencyDataList = ClassDependencyAnalyzer
+                .analyze(input.classesJar, new ClassRelevancyFilter(classesInJar));
+        // Perform java source analysis.
+        List<JavaSourceData> javaSourceDataList = JavaSourceAnalyzer.analyze(input.srcList);
+        // Collect all dependencies and map them as DependencyProto.FileDependencyList
+        DependencyMapper dp = new DependencyMapper(classDependencyDataList, javaSourceDataList);
+        DependencyProto.FileDependencyList dependencyList =  dp.buildDependencyMaps();
+
+        // Write the proto to output file
+        Utils.writeContentsToProto(dependencyList, input.dependencyMapProto);
+    }
+
+    private static void showUsage() {
+        System.err.println(
+                "Usage: dependency-mapper "
+                        + "--src-path [src-list.rsp] "
+                        + "--jar-path [classes.jar] "
+                        + "--dependency-map-path [dependency-map.proto]");
+    }
+
+}
\ No newline at end of file
diff --git a/tools/dependency_mapper/src/com/android/dependencymapper/Utils.java b/tools/dependency_mapper/src/com/android/dependencymapper/Utils.java
new file mode 100644
index 0000000000..5dd5f35bb9
--- /dev/null
+++ b/tools/dependency_mapper/src/com/android/dependencymapper/Utils.java
@@ -0,0 +1,94 @@
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
+package com.android.dependencymapper;
+
+import com.android.dependencymapper.DependencyProto;
+
+import com.google.gson.Gson;
+import com.google.gson.GsonBuilder;
+
+import java.io.FileWriter;
+import java.io.IOException;
+import java.io.OutputStream;
+import java.nio.file.Files;
+import java.nio.file.Path;
+import java.util.Enumeration;
+import java.util.HashMap;
+import java.util.HashSet;
+import java.util.Map;
+import java.util.Set;
+import java.util.jar.JarEntry;
+import java.util.jar.JarFile;
+
+public class Utils {
+
+    public static String trimAndConvertToPackageBasedPath(String fileBasedPath) {
+        // Remove ".class" from the fileBasedPath, then replace "/" with "."
+        return fileBasedPath.replaceAll("\\..*", "").replaceAll("/", ".");
+    }
+
+    public static String buildPackagePrependedClassSource(String qualifiedClassPath,
+            String classSource) {
+        // Find the location of the start of classname in the qualifiedClassPath
+        int classNameSt = qualifiedClassPath.lastIndexOf(".") + 1;
+        // Replace the classname in qualifiedClassPath with classSource
+        return qualifiedClassPath.substring(0, classNameSt) + classSource;
+    }
+
+    public static void writeContentsToJson(DependencyProto.FileDependencyList contents, Path jsonOut) {
+        Gson gson = new GsonBuilder().setPrettyPrinting().create();
+        Map<String, Set<String>> jsonMap = new HashMap<>();
+        for (DependencyProto.FileDependency fileDependency : contents.getFileDependencyList()) {
+            jsonMap.putIfAbsent(fileDependency.getFilePath(),
+                    Set.copyOf(fileDependency.getFileDependenciesList()));
+        }
+        String json = gson.toJson(jsonMap);
+        try (FileWriter file = new FileWriter(jsonOut.toFile())) {
+            file.write(json);
+        } catch (IOException e) {
+            System.err.println("Error writing json output to: " + jsonOut);
+            throw new RuntimeException(e);
+        }
+    }
+
+    public static void writeContentsToProto(DependencyProto.FileDependencyList usages, Path protoOut) {
+        try {
+            OutputStream outputStream = Files.newOutputStream(protoOut);
+            usages.writeDelimitedTo(outputStream);
+        } catch (IOException e) {
+            System.err.println("Error writing proto output to: " + protoOut);
+            throw new RuntimeException(e);
+        }
+    }
+
+    public static Set<String> listClassesInJar(Path classesJarPath) {
+        Set<String> classes = new HashSet<>();
+        try (JarFile jarFile = new JarFile(classesJarPath.toFile())) {
+            Enumeration<JarEntry> entries = jarFile.entries();
+            while (entries.hasMoreElements()) {
+                JarEntry entry = entries.nextElement();
+                if (entry.getName().endsWith(".class")) {
+                    String name = Utils.trimAndConvertToPackageBasedPath(entry.getName());
+                    classes.add(name);
+                }
+            }
+        } catch (IOException e) {
+            System.err.println("Error reading the jar file at: " + classesJarPath);
+            throw new RuntimeException(e);
+        }
+        return classes;
+    }
+}
diff --git a/tools/aconfig/fake_device_config/src/android/provider/DeviceConfig.java b/tools/dependency_mapper/tests/res/testdata/annotation/AnnotationUsage.java
similarity index 51%
rename from tools/aconfig/fake_device_config/src/android/provider/DeviceConfig.java
rename to tools/dependency_mapper/tests/res/testdata/annotation/AnnotationUsage.java
index dbb07ac983..bb40776966 100644
--- a/tools/aconfig/fake_device_config/src/android/provider/DeviceConfig.java
+++ b/tools/dependency_mapper/tests/res/testdata/annotation/AnnotationUsage.java
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2023 The Android Open Source Project
+ * Copyright (C) 2025 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -13,27 +13,18 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
+package res.testdata.annotation;
 
-package android.provider;
+@res.testdata.annotation.RuntimeAnnotation
+public class AnnotationUsage {
 
-/*
- * This class allows generated aconfig code to compile independently of the framework.
- */
-public class DeviceConfig {
-	private DeviceConfig() {
-	}
-
-	public static boolean getBoolean(String ns, String name, boolean def) {
-		return false;
-	}
+    private final int mSourceAnnField;
 
-	public static Properties getProperties(String namespace, String... names) {
-		return new Properties();
-	}
+    public AnnotationUsage(@res.testdata.annotation.SourceAnnotation int sourceAnnField) {
+        mSourceAnnField = sourceAnnField;
+    }
 
-	public static class Properties {
-		public boolean getBoolean(String name, boolean def) {
-			return false;
-		}
-	}
+    public @res.testdata.annotation.SourceAnnotation int getSourceAnnField() {
+        return mSourceAnnField;
+    }
 }
diff --git a/tools/dependency_mapper/tests/res/testdata/annotation/RuntimeAnnotation.java b/tools/dependency_mapper/tests/res/testdata/annotation/RuntimeAnnotation.java
new file mode 100644
index 0000000000..99a60745a4
--- /dev/null
+++ b/tools/dependency_mapper/tests/res/testdata/annotation/RuntimeAnnotation.java
@@ -0,0 +1,23 @@
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
+package res.testdata.annotation;
+
+import java.lang.annotation.Retention;
+import java.lang.annotation.RetentionPolicy;
+
+@Retention(RetentionPolicy.RUNTIME)
+public @interface RuntimeAnnotation {
+}
diff --git a/tools/dependency_mapper/tests/res/testdata/annotation/SourceAnnotation.java b/tools/dependency_mapper/tests/res/testdata/annotation/SourceAnnotation.java
new file mode 100644
index 0000000000..dec3e834de
--- /dev/null
+++ b/tools/dependency_mapper/tests/res/testdata/annotation/SourceAnnotation.java
@@ -0,0 +1,23 @@
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
+package res.testdata.annotation;
+
+import java.lang.annotation.Retention;
+import java.lang.annotation.RetentionPolicy;
+
+@Retention(RetentionPolicy.SOURCE)
+public @interface SourceAnnotation {
+}
diff --git a/tools/dependency_mapper/tests/res/testdata/constants/ConstantDefinition.java b/tools/dependency_mapper/tests/res/testdata/constants/ConstantDefinition.java
new file mode 100644
index 0000000000..3f0a7898d2
--- /dev/null
+++ b/tools/dependency_mapper/tests/res/testdata/constants/ConstantDefinition.java
@@ -0,0 +1,20 @@
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
+package res.testdata.constants;
+
+public class ConstantDefinition {
+    public static final String TEST_CONSTANT = "test_constant";
+}
diff --git a/tools/aconfig/fake_device_config/src/android/os/StrictMode.java b/tools/dependency_mapper/tests/res/testdata/constants/ConstantUsage.java
similarity index 59%
rename from tools/aconfig/fake_device_config/src/android/os/StrictMode.java
rename to tools/dependency_mapper/tests/res/testdata/constants/ConstantUsage.java
index 641625206c..852e4d5c7b 100644
--- a/tools/aconfig/fake_device_config/src/android/os/StrictMode.java
+++ b/tools/dependency_mapper/tests/res/testdata/constants/ConstantUsage.java
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2024 The Android Open Source Project
+ * Copyright (C) 2025 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -13,17 +13,13 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
+package res.testdata.constants;
 
-package android.os;
+public class ConstantUsage {
 
-public class StrictMode {
-    public static ThreadPolicy allowThreadDiskReads() {
-        throw new UnsupportedOperationException("Stub!");
-    }
+    public ConstantUsage(){}
 
-    public static void setThreadPolicy(final ThreadPolicy policy) {
-        throw new UnsupportedOperationException("Stub!");
+    public String useConstantInMethodBody() {
+        return res.testdata.constants.ConstantDefinition.TEST_CONSTANT;
     }
-
-    public static final class ThreadPolicy {}
 }
diff --git a/tools/dependency_mapper/tests/res/testdata/inheritance/BaseClass.java b/tools/dependency_mapper/tests/res/testdata/inheritance/BaseClass.java
new file mode 100644
index 0000000000..3b11eb1be8
--- /dev/null
+++ b/tools/dependency_mapper/tests/res/testdata/inheritance/BaseClass.java
@@ -0,0 +1,19 @@
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
+package res.testdata.inheritance;
+
+public class BaseClass {
+}
diff --git a/tools/dependency_mapper/tests/res/testdata/inheritance/BaseImpl.java b/tools/dependency_mapper/tests/res/testdata/inheritance/BaseImpl.java
new file mode 100644
index 0000000000..7c2698bb2e
--- /dev/null
+++ b/tools/dependency_mapper/tests/res/testdata/inheritance/BaseImpl.java
@@ -0,0 +1,21 @@
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
+package res.testdata.inheritance;
+
+public interface BaseImpl {
+
+    void baseImpl();
+}
diff --git a/tools/dependency_mapper/tests/res/testdata/inheritance/InheritanceUsage.java b/tools/dependency_mapper/tests/res/testdata/inheritance/InheritanceUsage.java
new file mode 100644
index 0000000000..f8924791a1
--- /dev/null
+++ b/tools/dependency_mapper/tests/res/testdata/inheritance/InheritanceUsage.java
@@ -0,0 +1,24 @@
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
+package res.testdata.inheritance;
+
+public class InheritanceUsage extends res.testdata.inheritance.BaseClass implements
+        res.testdata.inheritance.BaseImpl {
+    @Override
+    public void baseImpl() {
+
+    }
+}
diff --git a/tools/dependency_mapper/tests/res/testdata/methods/FieldUsage.java b/tools/dependency_mapper/tests/res/testdata/methods/FieldUsage.java
new file mode 100644
index 0000000000..0d97312f69
--- /dev/null
+++ b/tools/dependency_mapper/tests/res/testdata/methods/FieldUsage.java
@@ -0,0 +1,21 @@
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
+package res.testdata.methods;
+
+public class FieldUsage {
+
+    private res.testdata.methods.ReferenceClass1 mReferenceClass1;
+}
diff --git a/tools/dependency_mapper/tests/res/testdata/methods/MethodUsage.java b/tools/dependency_mapper/tests/res/testdata/methods/MethodUsage.java
new file mode 100644
index 0000000000..9dd0223e69
--- /dev/null
+++ b/tools/dependency_mapper/tests/res/testdata/methods/MethodUsage.java
@@ -0,0 +1,24 @@
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
+package res.testdata.methods;
+
+public class MethodUsage {
+
+    public void methodReferences(res.testdata.methods.ReferenceClass1 mReferenceClass1) {
+        res.testdata.methods.ReferenceClass2 referenceClass2 =
+                new res.testdata.methods.ReferenceClass2();
+    }
+}
diff --git a/tools/dependency_mapper/tests/res/testdata/methods/ReferenceClass1.java b/tools/dependency_mapper/tests/res/testdata/methods/ReferenceClass1.java
new file mode 100644
index 0000000000..f56c0a9fa6
--- /dev/null
+++ b/tools/dependency_mapper/tests/res/testdata/methods/ReferenceClass1.java
@@ -0,0 +1,21 @@
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
+package res.testdata.methods;
+
+public class ReferenceClass1 {
+
+    public ReferenceClass1(){}
+}
diff --git a/tools/dependency_mapper/tests/res/testdata/methods/ReferenceClass2.java b/tools/dependency_mapper/tests/res/testdata/methods/ReferenceClass2.java
new file mode 100644
index 0000000000..09e742248e
--- /dev/null
+++ b/tools/dependency_mapper/tests/res/testdata/methods/ReferenceClass2.java
@@ -0,0 +1,20 @@
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
+package res.testdata.methods;
+
+public class ReferenceClass2 {
+    public ReferenceClass2(){}
+}
diff --git a/tools/dependency_mapper/tests/res/testfiles/dependency-mapper-test-data.jar b/tools/dependency_mapper/tests/res/testfiles/dependency-mapper-test-data.jar
new file mode 100644
index 0000000000..98f5893d68
Binary files /dev/null and b/tools/dependency_mapper/tests/res/testfiles/dependency-mapper-test-data.jar differ
diff --git a/tools/dependency_mapper/tests/res/testfiles/sources.rsp b/tools/dependency_mapper/tests/res/testfiles/sources.rsp
new file mode 100644
index 0000000000..d895033c06
--- /dev/null
+++ b/tools/dependency_mapper/tests/res/testfiles/sources.rsp
@@ -0,0 +1,12 @@
+tests/res/testdata/annotation/AnnotationUsage.java
+tests/res/testdata/annotation/SourceAnnotation.java
+tests/res/testdata/annotation/RuntimeAnnotation.java
+tests/res/testdata/constants/ConstantDefinition.java
+tests/res/testdata/constants/ConstantUsage.java
+tests/res/testdata/inheritance/InheritanceUsage.java
+tests/res/testdata/inheritance/BaseClass.java
+tests/res/testdata/inheritance/BaseImpl.java
+tests/res/testdata/methods/FieldUsage.java
+tests/res/testdata/methods/MethodUsage.java
+tests/res/testdata/methods/ReferenceClass1.java
+tests/res/testdata/methods/ReferenceClass2.java
\ No newline at end of file
diff --git a/tools/dependency_mapper/tests/src/com/android/dependencymapper/ClassDependencyAnalyzerTest.java b/tools/dependency_mapper/tests/src/com/android/dependencymapper/ClassDependencyAnalyzerTest.java
new file mode 100644
index 0000000000..95492c8501
--- /dev/null
+++ b/tools/dependency_mapper/tests/src/com/android/dependencymapper/ClassDependencyAnalyzerTest.java
@@ -0,0 +1,133 @@
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
+package com.android.dependencymapper;
+
+import static com.android.dependencymapper.Utils.listClassesInJar;
+
+import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.assertTrue;
+
+import org.junit.BeforeClass;
+import org.junit.Test;
+
+import java.net.URISyntaxException;
+import java.nio.file.Path;
+import java.nio.file.Paths;
+import java.util.HashSet;
+import java.util.List;
+import java.util.Set;
+
+public class ClassDependencyAnalyzerTest {
+
+    private static List<ClassDependencyData> mClassDependencyDataList;
+
+    private static final String CLASSES_JAR_PATH =
+            "tests/res/testfiles/dependency-mapper-test-data.jar";
+
+    @BeforeClass
+    public static void beforeClass() throws URISyntaxException {
+        Path path = Paths.get(CLASSES_JAR_PATH);
+        Set<String> classesInJar = listClassesInJar(path);
+        // Perform dependency analysis.
+        mClassDependencyDataList = ClassDependencyAnalyzer.analyze(path,
+                new ClassRelevancyFilter(classesInJar));
+    }
+
+    @Test
+    public void testAnnotationDeps(){
+        String annoClass = "res.testdata.annotation.AnnotationUsage";
+        String sourceAnno = "res.testdata.annotation.SourceAnnotation";
+        String runTimeAnno = "res.testdata.annotation.RuntimeAnnotation";
+
+        dependencyVerifier(annoClass,
+                new HashSet<>(List.of(runTimeAnno)), new HashSet<>(List.of(sourceAnno)));
+
+        for (ClassDependencyData dep : mClassDependencyDataList) {
+            if (dep.getQualifiedName().equals(sourceAnno)) {
+                assertTrue(sourceAnno + " is not dependencyToAll ", dep.isDependencyToAll());
+            }
+            if (dep.getQualifiedName().equals(runTimeAnno)) {
+                assertFalse(runTimeAnno + " is dependencyToAll ", dep.isDependencyToAll());
+            }
+        }
+    }
+
+    @Test
+    public void testConstantsDeps(){
+        String constDefined = "test_constant";
+        String constDefClass = "res.testdata.constants.ConstantDefinition";
+        String constUsageClass = "res.testdata.constants.ConstantUsage";
+
+        boolean constUsageClassFound = false;
+        boolean constDefClassFound = false;
+        for (ClassDependencyData dep : mClassDependencyDataList) {
+            if (dep.getQualifiedName().equals(constUsageClass)) {
+                constUsageClassFound = true;
+                assertTrue("InlinedUsage of : " + constDefined + " not found",
+                        dep.inlinedUsages().contains(constDefined));
+            }
+            if (dep.getQualifiedName().equals(constDefClass)) {
+                constDefClassFound = true;
+                assertTrue("Constant " + constDefined + " not defined",
+                        dep.getConstantsDefined().contains(constDefined));
+            }
+        }
+        assertTrue("Class " + constUsageClass + " not found", constUsageClassFound);
+        assertTrue("Class " + constDefClass + " not found", constDefClassFound);
+    }
+
+    @Test
+    public void testInheritanceDeps(){
+        String sourceClass = "res.testdata.inheritance.InheritanceUsage";
+        String baseClass = "res.testdata.inheritance.BaseClass";
+        String baseImpl = "res.testdata.inheritance.BaseImpl";
+
+        dependencyVerifier(sourceClass,
+                new HashSet<>(List.of(baseClass, baseImpl)), new HashSet<>());
+    }
+
+
+    @Test
+    public void testMethodDeps(){
+        String fieldUsage = "res.testdata.methods.FieldUsage";
+        String methodUsage = "res.testdata.methods.MethodUsage";
+        String ref1 = "res.testdata.methods.ReferenceClass1";
+        String ref2 = "res.testdata.methods.ReferenceClass2";
+
+        dependencyVerifier(fieldUsage,
+                new HashSet<>(List.of(ref1)), new HashSet<>(List.of(ref2)));
+        dependencyVerifier(methodUsage,
+                new HashSet<>(List.of(ref1, ref2)), new HashSet<>());
+    }
+
+    private void dependencyVerifier(String qualifiedName, Set<String> deps, Set<String> nonDeps) {
+        boolean depFound = false;
+        for (ClassDependencyData classDependencyData : mClassDependencyDataList) {
+            if (classDependencyData.getQualifiedName().equals(qualifiedName)) {
+                depFound = true;
+                for (String dep : deps) {
+                    assertTrue(qualifiedName + " does not depends on " + dep,
+                            classDependencyData.getClassDependencies().contains(dep));
+                }
+                for (String nonDep : nonDeps) {
+                    assertFalse(qualifiedName + " depends on " + nonDep,
+                            classDependencyData.getClassDependencies().contains(nonDep));
+                }
+            }
+        }
+        assertTrue("Class " + qualifiedName + " not found", depFound);
+    }
+}
diff --git a/tools/dependency_mapper/tests/src/com/android/dependencymapper/ClassRelevancyFilterTest.java b/tools/dependency_mapper/tests/src/com/android/dependencymapper/ClassRelevancyFilterTest.java
new file mode 100644
index 0000000000..9a80c4bd80
--- /dev/null
+++ b/tools/dependency_mapper/tests/src/com/android/dependencymapper/ClassRelevancyFilterTest.java
@@ -0,0 +1,60 @@
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
+package com.android.dependencymapper;
+
+import static com.android.dependencymapper.Utils.listClassesInJar;
+
+import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.assertNotEquals;
+
+import com.android.dependencymapper.ClassDependencyAnalyzer;
+import com.android.dependencymapper.ClassDependencyData;
+import com.android.dependencymapper.ClassRelevancyFilter;
+
+import org.junit.Test;
+
+import java.nio.file.Path;
+import java.nio.file.Paths;
+import java.util.List;
+import java.util.Set;
+
+public class ClassRelevancyFilterTest {
+
+    private static final String CLASSES_JAR_PATH =
+            "tests/res/testfiles/dependency-mapper-test-data.jar";
+
+    @Test
+    public void testClassRelevancyFilter() {
+        Path path = Paths.get(CLASSES_JAR_PATH);
+        Set<String> classesInJar = listClassesInJar(path);
+
+        // Add a relevancy filter that skips a class.
+        String skippedClass = "res.testdata.BaseClass";
+        classesInJar.remove(skippedClass);
+
+        // Perform dependency analysis.
+        List<ClassDependencyData> classDependencyDataList =
+                ClassDependencyAnalyzer.analyze(path, new ClassRelevancyFilter(classesInJar));
+
+        // check that the skipped class is not present in classDepsList
+        for (ClassDependencyData dep : classDependencyDataList) {
+            assertNotEquals("SkippedClass " + skippedClass + " is present",
+                    skippedClass, dep.getQualifiedName());
+            assertFalse("SkippedClass " + skippedClass + " is present as dependency of " + dep,
+                    dep.getClassDependencies().contains(skippedClass));
+        }
+    }
+}
diff --git a/tools/dependency_mapper/tests/src/com/android/dependencymapper/DependencyMapperTest.java b/tools/dependency_mapper/tests/src/com/android/dependencymapper/DependencyMapperTest.java
new file mode 100644
index 0000000000..9c08e796c3
--- /dev/null
+++ b/tools/dependency_mapper/tests/src/com/android/dependencymapper/DependencyMapperTest.java
@@ -0,0 +1,201 @@
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
+package com.android.dependencymapper;
+
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.assertNotNull;
+import static org.junit.Assert.assertTrue;
+
+import org.junit.BeforeClass;
+import org.junit.Test;
+
+import java.util.ArrayList;
+import java.util.HashMap;
+import java.util.HashSet;
+import java.util.List;
+import java.util.Map;
+
+public class DependencyMapperTest {
+
+    private static final List<JavaSourceData> mJavaSourceData = new ArrayList<>();
+    private static final List<ClassDependencyData> mClassDependencyData = new ArrayList<>();
+
+    private static Map<String, DependencyProto.FileDependency>  mFileDependencyMap;
+
+    public static String AUDIO_CONS = "AUDIO_CONS";
+    public static String AUDIO_CONS_PATH = "frameworks/base/audio/AudioPermission.java";
+    public static String AUDIO_CONS_PACKAGE = "com.android.audio.AudioPermission";
+
+    public static String AUDIO_TONE_CONS_1 = "AUDIO_TONE_CONS_1";
+    public static String AUDIO_TONE_CONS_2 = "AUDIO_TONE_CONS_2";
+    public static String AUDIO_TONE_CONS_PATH = "frameworks/base/audio/Audio$Tones.java";
+    public static String AUDIO_TONE_CONS_PACKAGE = "com.android.audio.Audio$Tones";
+
+    public static String ST_MANAGER_PATH = "frameworks/base/core/storage/StorageManager.java";
+    public static String ST_MANAGER_PACKAGE = "com.android.storage.StorageManager";
+
+    public static String CONST_OUTSIDE_SCOPE = "CONST_OUTSIDE_SCOPE";
+    public static String PERM_MANAGER_PATH =  "frameworks/base/core/permission/PermissionManager.java";
+    public static String PERM_MANAGER_PACKAGE =  "com.android.permission.PermissionManager";
+
+    public static String SOURCE_ANNO_PATH = "frameworks/base/anno/SourceAnno.java";
+    public static String SOURCE_ANNO_PACKAGE = "com.android.anno.SourceAnno";
+
+    public static String PERM_SOURCE_PATH = "frameworks/base/core/permission/PermissionSources.java";
+    public static String PERM_SOURCE_PACKAGE = "com.android.permission.PermissionSources";
+
+    public static String PERM_DATA_PATH = "frameworks/base/core/permission/PermissionSources$Data.java";
+    public static String PERM_DATA_PACKAGE = "com.android.permission.PermissionSources$Data";
+
+    static {
+        JavaSourceData audioConstants = new JavaSourceData(AUDIO_CONS_PATH, AUDIO_CONS_PACKAGE + ".java");
+        JavaSourceData audioToneConstants =
+                new JavaSourceData(AUDIO_TONE_CONS_PATH, AUDIO_TONE_CONS_PACKAGE + ".java"); //f2
+        JavaSourceData stManager = new JavaSourceData( ST_MANAGER_PATH, ST_MANAGER_PACKAGE + ".java");
+        JavaSourceData permManager = new JavaSourceData(PERM_MANAGER_PATH, PERM_MANAGER_PACKAGE + ".java");
+        JavaSourceData permSource = new JavaSourceData(PERM_SOURCE_PATH, PERM_SOURCE_PACKAGE + ".java");
+        JavaSourceData permSourceData = new JavaSourceData(PERM_DATA_PATH, PERM_DATA_PACKAGE + ".java");
+
+        JavaSourceData sourceNotPresentInClass =
+                new JavaSourceData(SOURCE_ANNO_PATH, SOURCE_ANNO_PACKAGE);
+
+        mJavaSourceData.addAll(List.of(audioConstants, audioToneConstants, stManager,
+                permManager, permSource, permSourceData, sourceNotPresentInClass));
+
+        ClassDependencyData audioConstantsDeps =
+                new ClassDependencyData(AUDIO_CONS_PACKAGE + ".java",
+                        AUDIO_CONS_PACKAGE, new HashSet<>(), false,
+                        new HashSet<>(List.of(AUDIO_CONS)), new HashSet<>());
+
+        ClassDependencyData audioToneConstantsDeps =
+                new ClassDependencyData(AUDIO_TONE_CONS_PACKAGE + ".java",
+                        AUDIO_TONE_CONS_PACKAGE, new HashSet<>(), false,
+                        new HashSet<>(List.of(AUDIO_TONE_CONS_1, AUDIO_TONE_CONS_2)),
+                        new HashSet<>());
+
+        ClassDependencyData stManagerDeps =
+                new ClassDependencyData(ST_MANAGER_PACKAGE + ".java",
+                        ST_MANAGER_PACKAGE, new HashSet<>(List.of(PERM_SOURCE_PACKAGE)), false,
+                        new HashSet<>(), new HashSet<>(List.of(AUDIO_CONS, AUDIO_TONE_CONS_1)));
+
+        ClassDependencyData permManagerDeps =
+                new ClassDependencyData(PERM_MANAGER_PACKAGE + ".java", PERM_MANAGER_PACKAGE,
+                        new HashSet<>(List.of(PERM_SOURCE_PACKAGE, PERM_DATA_PACKAGE)), false,
+                        new HashSet<>(), new HashSet<>(List.of(CONST_OUTSIDE_SCOPE)));
+
+        ClassDependencyData permSourceDeps =
+                new ClassDependencyData(PERM_SOURCE_PACKAGE + ".java",
+                        PERM_SOURCE_PACKAGE, new HashSet<>(), false,
+                        new HashSet<>(), new HashSet<>());
+
+        ClassDependencyData permSourceDataDeps =
+                new ClassDependencyData(PERM_DATA_PACKAGE + ".java",
+                        PERM_DATA_PACKAGE, new HashSet<>(), false,
+                        new HashSet<>(), new HashSet<>());
+
+        mClassDependencyData.addAll(List.of(audioConstantsDeps, audioToneConstantsDeps,
+                stManagerDeps, permManagerDeps, permSourceDeps, permSourceDataDeps));
+    }
+
+    @BeforeClass
+    public static void beforeAll(){
+        mFileDependencyMap = buildActualDepsMap(
+                new DependencyMapper(mClassDependencyData, mJavaSourceData).buildDependencyMaps());
+    }
+
+    @Test
+    public void testFileDependencies() {
+        // Test for AUDIO_CONS_PATH
+        DependencyProto.FileDependency audioDepsActual = mFileDependencyMap.get(AUDIO_CONS_PATH);
+        assertNotNull(AUDIO_CONS_PATH + " not found in dependencyList", audioDepsActual);
+        // This file should have 0 dependencies.
+        validateDependencies(audioDepsActual, AUDIO_CONS_PATH, 0, new ArrayList<>());
+
+        // Test for AUDIO_TONE_CONS_PATH
+        DependencyProto.FileDependency audioToneDepsActual =
+                mFileDependencyMap.get(AUDIO_TONE_CONS_PATH);
+        assertNotNull(AUDIO_TONE_CONS_PATH + " not found in dependencyList", audioDepsActual);
+        // This file should have 0 dependencies.
+        validateDependencies(audioToneDepsActual, AUDIO_TONE_CONS_PATH, 0, new ArrayList<>());
+
+        // Test for ST_MANAGER_PATH
+        DependencyProto.FileDependency stManagerDepsActual =
+                mFileDependencyMap.get(ST_MANAGER_PATH);
+        assertNotNull(ST_MANAGER_PATH + " not found in dependencyList", audioDepsActual);
+        // This file should have 3 dependencies.
+        validateDependencies(stManagerDepsActual, ST_MANAGER_PATH, 3,
+                new ArrayList<>(List.of(AUDIO_CONS_PATH, AUDIO_TONE_CONS_PATH, PERM_SOURCE_PATH)));
+
+        // Test for PERM_MANAGER_PATH
+        DependencyProto.FileDependency permManagerDepsActual =
+                mFileDependencyMap.get(PERM_MANAGER_PATH);
+        assertNotNull(PERM_MANAGER_PATH + " not found in dependencyList", audioDepsActual);
+        // This file should have 2 dependencies.
+        validateDependencies(permManagerDepsActual, PERM_MANAGER_PATH, 2,
+                new ArrayList<>(List.of(PERM_SOURCE_PATH, PERM_DATA_PATH)));
+
+        // Test for PERM_SOURCE_PATH
+        DependencyProto.FileDependency permSourceDepsActual =
+                mFileDependencyMap.get(PERM_SOURCE_PATH);
+        assertNotNull(PERM_SOURCE_PATH + " not found in dependencyList", audioDepsActual);
+        // This file should have 0 dependencies.
+        validateDependencies(permSourceDepsActual, PERM_SOURCE_PATH, 0, new ArrayList<>());
+
+        // Test for PERM_DATA_PATH
+        DependencyProto.FileDependency permDataDepsActual =
+                mFileDependencyMap.get(PERM_DATA_PATH);
+        assertNotNull(PERM_DATA_PATH + " not found in dependencyList", audioDepsActual);
+        // This file should have 0 dependencies.
+        validateDependencies(permDataDepsActual, PERM_DATA_PATH, 0, new ArrayList<>());
+    }
+
+    private void validateDependencies(DependencyProto.FileDependency dependency, String fileName, int fileDepsCount, List<String> fileDeps) {
+        assertEquals(fileName + " does not have expected dependencies", fileDepsCount, dependency.getFileDependenciesCount());
+        assertTrue(fileName + " does not have expected dependencies", dependency.getFileDependenciesList().containsAll(fileDeps));
+    }
+
+    private static Map<String, DependencyProto.FileDependency> buildActualDepsMap(
+            DependencyProto.FileDependencyList fileDependencyList) {
+        Map<String, DependencyProto.FileDependency> dependencyMap = new HashMap<>();
+        for (DependencyProto.FileDependency fileDependency : fileDependencyList.getFileDependencyList()) {
+            if (fileDependency.getFilePath().equals(AUDIO_CONS_PATH)) {
+                dependencyMap.put(AUDIO_CONS_PATH, fileDependency);
+            }
+            if (fileDependency.getFilePath().equals(AUDIO_TONE_CONS_PATH)) {
+                dependencyMap.put(AUDIO_TONE_CONS_PATH, fileDependency);
+            }
+            if (fileDependency.getFilePath().equals(ST_MANAGER_PATH)) {
+                dependencyMap.put(ST_MANAGER_PATH, fileDependency);
+            }
+            if (fileDependency.getFilePath().equals(PERM_MANAGER_PATH)) {
+                dependencyMap.put(PERM_MANAGER_PATH, fileDependency);
+            }
+            if (fileDependency.getFilePath().equals(PERM_SOURCE_PATH)) {
+                dependencyMap.put(PERM_SOURCE_PATH, fileDependency);
+            }
+            if (fileDependency.getFilePath().equals(PERM_DATA_PATH)) {
+                dependencyMap.put(PERM_DATA_PATH, fileDependency);
+            }
+            if (fileDependency.getFilePath().equals(SOURCE_ANNO_PATH)) {
+                dependencyMap.put(SOURCE_ANNO_PATH, fileDependency);
+            }
+        }
+        assertFalse(SOURCE_ANNO_PATH + " found in dependencyList",
+                dependencyMap.containsKey(SOURCE_ANNO_PATH));
+        return dependencyMap;
+    }
+}
diff --git a/tools/dependency_mapper/tests/src/com/android/dependencymapper/JavaSourceAnalyzerTest.java b/tools/dependency_mapper/tests/src/com/android/dependencymapper/JavaSourceAnalyzerTest.java
new file mode 100644
index 0000000000..1ca2b2a899
--- /dev/null
+++ b/tools/dependency_mapper/tests/src/com/android/dependencymapper/JavaSourceAnalyzerTest.java
@@ -0,0 +1,71 @@
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
+package com.android.dependencymapper;
+
+import static org.junit.Assert.assertEquals;
+
+import org.junit.BeforeClass;
+import org.junit.Test;
+
+import java.net.URISyntaxException;
+import java.nio.file.Path;
+import java.nio.file.Paths;
+import java.util.HashMap;
+import java.util.List;
+import java.util.Map;
+
+public class JavaSourceAnalyzerTest {
+    private static List<JavaSourceData> mJavaSourceDataList;
+
+    private static final String SOURCES_RSP_PATH =
+            "tests/res/testfiles/sources.rsp";
+
+    @BeforeClass
+    public static void beforeClass() throws URISyntaxException {
+        Path path = Paths.get(SOURCES_RSP_PATH);
+        // Perform source analysis.
+        mJavaSourceDataList = JavaSourceAnalyzer.analyze(path);
+    }
+
+    @Test
+    public void validateSourceData() {
+        Map<String, String> expectedSourceData = expectedSourceData();
+        int expectedFileCount = expectedSourceData.size();
+        int actualFileCount = 0;
+        for (JavaSourceData javaSourceData : mJavaSourceDataList) {
+            String file =  javaSourceData.getFilePath();
+            if (expectedSourceData.containsKey(file)) {
+                actualFileCount++;
+                assertEquals("Source Data not generated correctly for " + file,
+                        expectedSourceData.get(file), javaSourceData.getPackagePrependedFileName());
+            }
+        }
+        assertEquals("Not all source files processed", expectedFileCount, actualFileCount);
+    }
+
+    private Map<String, String> expectedSourceData() {
+        Map<String, String> expectedSourceData = new HashMap<>();
+        expectedSourceData.put("tests/res/testdata/annotation/AnnotationUsage.java",
+                "res.testdata.annotation.AnnotationUsage.java");
+        expectedSourceData.put("tests/res/testdata/constants/ConstantUsage.java",
+                "res.testdata.constants.ConstantUsage.java");
+        expectedSourceData.put("tests/res/testdata/inheritance/BaseClass.java",
+                "res.testdata.inheritance.BaseClass.java");
+        expectedSourceData.put("tests/res/testdata/methods/FieldUsage.java",
+                "res.testdata.methods.FieldUsage.java");
+        return expectedSourceData;
+    }
+}
diff --git a/tools/dependency_mapper/tests/src/com/android/dependencymapper/UtilsTest.java b/tools/dependency_mapper/tests/src/com/android/dependencymapper/UtilsTest.java
new file mode 100644
index 0000000000..39c5190b97
--- /dev/null
+++ b/tools/dependency_mapper/tests/src/com/android/dependencymapper/UtilsTest.java
@@ -0,0 +1,64 @@
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
+package com.android.dependencymapper;
+
+import org.junit.Test;
+
+import static org.junit.Assert.assertEquals;
+
+import com.android.dependencymapper.Utils;
+
+public class UtilsTest {
+
+    @Test
+    public void testTrimAndConvertToPackageBasedPath() {
+        String testPath1 = "com/android/storage/StorageManager.class";
+        String testPath2 = "com/android/package/PackageManager$Package.class";
+
+        String expectedPackageBasedPath1 = "com.android.storage.StorageManager";
+        String expectedPackageBasedPath2 = "com.android.package.PackageManager$Package";
+
+        assertEquals("Package Based Path not constructed correctly",
+                expectedPackageBasedPath1, Utils.trimAndConvertToPackageBasedPath(testPath1));
+        assertEquals("Package Based Path not constructed correctly",
+                expectedPackageBasedPath2, Utils.trimAndConvertToPackageBasedPath(testPath2));
+    }
+
+    @Test
+    public void testBuildPackagePrependedClassSource() {
+        String qualifiedClassPath1 = "com.android.storage.StorageManager";
+        String sourcePath1 = "StorageManager.java";
+        String qualifiedClassPath2 = "com.android.package.PackageManager$Package";
+        String sourcePath2 = "PackageManager.java";
+        String qualifiedClassPath3 = "com.android.storage.StorageManager$Storage";
+        String sourcePath3 = "StorageManager$Storage.java";
+
+
+        String expectedPackagePrependedPath1 = "com.android.storage.StorageManager.java";
+        String expectedPackagePrependedPath2 = "com.android.package.PackageManager.java";
+        String expectedPackagePrependedPath3 = "com.android.storage.StorageManager$Storage.java";
+
+        assertEquals("Package Prepended Class Source not constructed correctly",
+                expectedPackagePrependedPath1,
+                Utils.buildPackagePrependedClassSource(qualifiedClassPath1, sourcePath1));
+        assertEquals("Package Prepended Class Source not constructed correctly",
+                expectedPackagePrependedPath2,
+                Utils.buildPackagePrependedClassSource(qualifiedClassPath2, sourcePath2));
+        assertEquals("Package Prepended Class Source not constructed correctly",
+                expectedPackagePrependedPath3,
+                Utils.buildPackagePrependedClassSource(qualifiedClassPath3, sourcePath3));
+    }
+}
diff --git a/tools/edit_monitor/daemon_manager_test.py b/tools/edit_monitor/daemon_manager_test.py
index be28965c9e..a7c175dbca 100644
--- a/tools/edit_monitor/daemon_manager_test.py
+++ b/tools/edit_monitor/daemon_manager_test.py
@@ -494,8 +494,8 @@ class DaemonManagerTest(unittest.TestCase):
 
   def _assert_error_event_logged(self, fake_cclient, error_type):
     error_events = fake_cclient.get_sent_events()
-    self.assertEquals(len(error_events), 1)
-    self.assertEquals(
+    self.assertEqual(len(error_events), 1)
+    self.assertEqual(
         edit_event_pb2.EditEvent.FromString(
             error_events[0].source_extension
         ).edit_monitor_error_event.error_type,
diff --git a/tools/edit_monitor/edit_monitor_test.py b/tools/edit_monitor/edit_monitor_test.py
index 64a3871b22..deb73e724b 100644
--- a/tools/edit_monitor/edit_monitor_test.py
+++ b/tools/edit_monitor/edit_monitor_test.py
@@ -260,7 +260,7 @@ class EditMonitorTest(unittest.TestCase):
 
     # Wait until observer started.
     received_data = receiver.recv()
-    self.assertEquals(received_data, 'Observer started.')
+    self.assertEqual(received_data, 'Observer started.')
 
     receiver.close()
     return p
diff --git a/tools/event_log_tags.py b/tools/event_log_tags.py
index a6ae9f193e..e859b6b3b1 100644
--- a/tools/event_log_tags.py
+++ b/tools/event_log_tags.py
@@ -14,21 +14,21 @@
 
 """A module for reading and parsing event-log-tags files."""
 
+import dataclasses
 import re
 import sys
+from typing import Optional
 
-class Tag(object):
-  __slots__ = ["tagnum", "tagname", "description", "filename", "linenum"]
-
-  def __init__(self, tagnum, tagname, description, filename, linenum):
-    self.tagnum = tagnum
-    self.tagname = tagname
-    self.description = description
-    self.filename = filename
-    self.linenum = linenum
+@dataclasses.dataclass
+class Tag:
+  tagnum: int
+  tagname: str
+  description: Optional[str]
+  filename: str
+  linenum: int
 
 
-class TagFile(object):
+class TagFile:
   """Read an input event-log-tags file."""
   def AddError(self, msg, linenum=None):
     if linenum is None:
@@ -76,14 +76,11 @@ class TagFile(object):
           self.options[parts[1]] = parts[2:]
           continue
 
-        if parts[0] == "?":
-          tag = None
-        else:
-          try:
-            tag = int(parts[0])
-          except ValueError:
-            self.AddError("\"%s\" isn't an integer tag or '?'" % (parts[0],))
-            continue
+        try:
+          tag = int(parts[0])
+        except ValueError:
+          self.AddError("\"%s\" isn't an integer tag" % (parts[0],))
+          continue
 
         tagname = parts[1]
         if len(parts) == 3:
@@ -128,8 +125,8 @@ def WriteOutput(output_file, data):
       out = sys.stdout
       output_file = "<stdout>"
     else:
-      out = open(output_file, "wb")
-    out.write(str.encode(data))
+      out = open(output_file, "w")
+    out.write(data)
     out.close()
   except (IOError, OSError) as e:
     print("failed to write %s: %s" % (output_file, e), file=sys.stderr)
diff --git a/tools/filelistdiff/allowlist b/tools/filelistdiff/allowlist
index eb785872cf..d8979d6983 100644
--- a/tools/filelistdiff/allowlist
+++ b/tools/filelistdiff/allowlist
@@ -1,5 +1,3 @@
 # Known diffs that are installed in either system image with the configuration
 # b/353429422
 init.environ.rc
-# b/338342381
-etc/NOTICE.xml.gz
diff --git a/tools/filelistdiff/allowlist_next b/tools/filelistdiff/allowlist_next
index 8f91c9f3e4..9cc7f34aec 100644
--- a/tools/filelistdiff/allowlist_next
+++ b/tools/filelistdiff/allowlist_next
@@ -1,9 +1,3 @@
 # Allowlist only for the next release configuration.
 # TODO(b/369678122): The list will be cleared when the trunk configurations are
 # available to the next.
-
-# KATI only installed files
-framework/oat/x86_64/apex@com.android.compos@javalib@service-compos.jar@classes.odex
-framework/oat/x86_64/apex@com.android.compos@javalib@service-compos.jar@classes.odex.fsv_meta
-framework/oat/x86_64/apex@com.android.compos@javalib@service-compos.jar@classes.vdex
-framework/oat/x86_64/apex@com.android.compos@javalib@service-compos.jar@classes.vdex.fsv_meta
diff --git a/tools/finalization/OWNERS b/tools/finalization/OWNERS
index b00b774b72..4df009448e 100644
--- a/tools/finalization/OWNERS
+++ b/tools/finalization/OWNERS
@@ -1,7 +1,5 @@
 include platform/build/soong:/OWNERS
-amhk@google.com
-gurpreetgs@google.com
-michaelwr@google.com
+include platform/frameworks/base:/SDK_OWNERS
 patb@google.com
 smoreland@google.com
 zyy@google.com
diff --git a/tools/finalization/build-step-0.sh b/tools/finalization/build-step-0.sh
index 8826b35c0f..bc41a196e8 100755
--- a/tools/finalization/build-step-0.sh
+++ b/tools/finalization/build-step-0.sh
@@ -25,8 +25,8 @@ RELEASE_BOARD_API_LEVEL='$FINAL_BOARD_API_LEVEL'"
     fi;
 
     if [ "$need_vintf_finalize" = true ] ; then        # VINTF finalization
-        source $top/build/make/tools/finalization/finalize-vintf-resources.sh
+        source $top/build/make/tools/finalization/finalize-vintf-resources.sh $@
     fi;
 }
 
-finalize_main_step0
+finalize_main_step0 $@
diff --git a/tools/finalization/command-line-options.sh b/tools/finalization/command-line-options.sh
index d9397c2699..3a1e0491f3 100644
--- a/tools/finalization/command-line-options.sh
+++ b/tools/finalization/command-line-options.sh
@@ -3,6 +3,7 @@ eval set -- "$ARGV"
 while true; do
     case "$1" in
         --dry-run) repo_upload_dry_run_arg="--dry-run"; repo_branch="finalization-dry-run"; shift ;;
+        --) shift; break;;
         *) break
     esac
 done
diff --git a/tools/finalization/environment.sh b/tools/finalization/environment.sh
index 9a287c4666..c76980d90f 100755
--- a/tools/finalization/environment.sh
+++ b/tools/finalization/environment.sh
@@ -30,8 +30,8 @@ export BUILD_FROM_SOURCE_STUB=true
 # TODO(b/323985297): The version must match with that from the release configuration.
 # Instead of hardcoding the version here, read it from a release configuration.
 export FINAL_BOARD_API_LEVEL='202504'
-export FINAL_CORRESPONDING_VERSION_LETTER='W'
+export FINAL_CORRESPONDING_VERSION_LETTER='B'
 export FINAL_CORRESPONDING_PLATFORM_VERSION='16'
 export FINAL_NEXT_BOARD_API_LEVEL='202604'
-export FINAL_NEXT_CORRESPONDING_VERSION_LETTER='X'
+export FINAL_NEXT_CORRESPONDING_VERSION_LETTER='C'
 export FINAL_NEXT_CORRESPONDING_SDK_VERSION='37'
diff --git a/tools/finalization/finalize-vintf-resources.sh b/tools/finalization/finalize-vintf-resources.sh
index 45efc104db..9660e3fc8c 100755
--- a/tools/finalization/finalize-vintf-resources.sh
+++ b/tools/finalization/finalize-vintf-resources.sh
@@ -3,6 +3,21 @@
 set -ex
 
 function finalize_vintf_resources() {
+    if [ $# -gt 1 ]; then
+        echo "No argument or '--steps_for_build_test_only' is allowed"
+        exit 1
+    fi
+    if [ $# -eq 1 ]; then
+        if [ "$1" == "--steps_for_build_test_only" ]; then
+            echo "This is only to verify building a target."
+            echo "Skip LLNDK ABI dump and VINTF check."
+            local build_test_only=true
+        else
+            echo "Unknown argument $1"
+            exit 1
+        fi
+    fi
+
     local top="$(dirname "$0")"/../../../..
     source $top/build/make/tools/finalization/environment.sh
     # environment needed to build dependencies and run scripts
@@ -26,37 +41,30 @@ function finalize_vintf_resources() {
     # system/sepolicy
     "$top/system/sepolicy/tools/finalize-vintf-resources.sh" "$top" "$FINAL_BOARD_API_LEVEL"
 
-    create_new_compat_matrix_and_kernel_configs
-
-    # pre-finalization build target (trunk)
     local aidl_m="$top/build/soong/soong_ui.bash --make-mode"
     AIDL_TRANSITIVE_FREEZE=true $aidl_m aidl-freeze-api create_reference_dumps
 
-    # Generate LLNDK ABI dumps
-    # This command depends on ANDROID_BUILD_TOP
-    "$ANDROID_HOST_OUT/bin/create_reference_dumps" -release "$TARGET_RELEASE" --build-variant "$TARGET_BUILD_VARIANT" --lib-variant LLNDK
+    finalize_compat_matrix $build_test_only
+
+    if ! [ "$build_test_only" = "true" ]; then
+        # Generate LLNDK ABI dumps
+        # This command depends on ANDROID_BUILD_TOP
+        "$ANDROID_HOST_OUT/bin/create_reference_dumps" -release "$TARGET_RELEASE" --build-variant "$TARGET_BUILD_VARIANT" --lib-variant LLNDK
+    fi
 }
 
-function create_new_compat_matrix_and_kernel_configs() {
-    # The compatibility matrix versions are bumped during vFRC
-    # These will change every time we have a new vFRC
+function finalize_compat_matrix() {
+    local build_test_only=$1
     local CURRENT_COMPATIBILITY_MATRIX_LEVEL="$FINAL_BOARD_API_LEVEL"
-    local NEXT_COMPATIBILITY_MATRIX_LEVEL="$FINAL_NEXT_BOARD_API_LEVEL"
-    # The kernel configs need the letter of the Android release
-    local CURRENT_RELEASE_LETTER="$FINAL_CORRESPONDING_VERSION_LETTER"
-    local NEXT_RELEASE_LETTER="$FINAL_NEXT_CORRESPONDING_VERSION_LETTER"
-
 
-    # build the targets required before touching the Android.bp/Android.mk files
-    local build_cmd="$top/build/soong/soong_ui.bash --make-mode"
-    $build_cmd bpmodify
+    "$top/prebuilts/build-tools/path/linux-x86/python3" "$top/hardware/interfaces/compatibility_matrices/finalize.py" "$CURRENT_COMPATIBILITY_MATRIX_LEVEL"
 
-    "$top/prebuilts/build-tools/path/linux-x86/python3" "$top/hardware/interfaces/compatibility_matrices/bump.py" "$CURRENT_COMPATIBILITY_MATRIX_LEVEL" "$NEXT_COMPATIBILITY_MATRIX_LEVEL" "$CURRENT_RELEASE_LETTER" "$NEXT_RELEASE_LETTER" "$FINAL_CORRESPONDING_PLATFORM_VERSION"
-
-    # Freeze the current framework manifest file. This relies on the
-    # aosp_cf_x86_64-trunk_staging build target to get the right manifest
-    # fragments installed.
-    "$top/system/libhidl/vintfdata/freeze.sh" "$CURRENT_COMPATIBILITY_MATRIX_LEVEL"
+    if ! [ "$build_test_only" = "true" ]; then
+        # Freeze the current framework manifest file. This relies on the
+        # interfaces already being frozen because we are building with fina_0 which
+        # inherits from `next` where RELEASE_AIDL_USE_UNFROZEN=false
+        "$top/system/libhidl/vintfdata/freeze.sh" "$CURRENT_COMPATIBILITY_MATRIX_LEVEL"
+    fi
 }
 
 function freeze_framework_manifest() {
@@ -65,5 +73,5 @@ function freeze_framework_manifest() {
 }
 
 
-finalize_vintf_resources
+finalize_vintf_resources $@
 
diff --git a/tools/ide_query/cc_analyzer/README.md b/tools/ide_query/cc_analyzer/README.md
new file mode 100644
index 0000000000..7b822d205f
--- /dev/null
+++ b/tools/ide_query/cc_analyzer/README.md
@@ -0,0 +1,3 @@
+See instructions in
+[Android Clang/LLVM-based Tools Readme Doc](https://android.googlesource.com/platform/prebuilts/clang-tools/+/main/README.md)
+for cutting a new release.
diff --git a/tools/ide_query/cc_analyzer/include_scanner.cc b/tools/ide_query/cc_analyzer/include_scanner.cc
index 8916a3edd6..1d3f26e737 100644
--- a/tools/ide_query/cc_analyzer/include_scanner.cc
+++ b/tools/ide_query/cc_analyzer/include_scanner.cc
@@ -94,6 +94,11 @@ class IncludeScanningAction final : public clang::PreprocessOnlyAction {
       std::unordered_map<std::string, std::string> &abs_paths)
       : abs_paths_(abs_paths) {}
   bool BeginSourceFileAction(clang::CompilerInstance &ci) override {
+    // Be more resilient against all warnings/errors, as we want
+    // include-scanning to work even on incomplete sources.
+    ci.getDiagnostics().setEnableAllWarnings(false);
+    ci.getDiagnostics().setSeverityForAll(clang::diag::Flavor::WarningOrError,
+                                          clang::diag::Severity::Ignored);
     std::string cwd;
     auto cwd_or_err = ci.getVirtualFileSystem().getCurrentWorkingDirectory();
     if (!cwd_or_err || cwd_or_err.get().empty()) return false;
@@ -154,6 +159,8 @@ llvm::Expected<std::vector<std::pair<std::string, std::string>>> ScanIncludes(
                         main_file.get()->getBuffer().str());
 
   std::vector<std::string> argv = cmd.CommandLine;
+  // Disable all warnings to be more robust in analysis.
+  argv.insert(llvm::find(argv, "--"), {"-Wno-error", "-w"});
   fs = OverlayBuiltinHeaders(argv, std::move(fs));
 
   llvm::IntrusiveRefCntPtr<clang::FileManager> files(
diff --git a/tools/ide_query/ide_query.go b/tools/ide_query/ide_query.go
index c7cf5ed49a..6caa29c1f3 100644
--- a/tools/ide_query/ide_query.go
+++ b/tools/ide_query/ide_query.go
@@ -116,8 +116,8 @@ func main() {
 
 	var targets []string
 	javaTargetsByFile := findJavaModules(javaFiles, javaModules)
-	for _, t := range javaTargetsByFile {
-		targets = append(targets, t)
+	for _, target := range javaTargetsByFile {
+		targets = append(targets, javaModules[target].Jars...)
 	}
 
 	ccTargets, err := getCCTargets(ctx, env, ccFiles)
@@ -306,6 +306,10 @@ func findJavaModules(paths []string, modules map[string]*javaModule) map[string]
 		}
 
 		module := modules[name]
+		if len(module.Jars) == 0 {
+			continue
+		}
+
 		for i, p := range paths {
 			if slices.Contains(module.Srcs, p) {
 				ret[p] = name
@@ -317,6 +321,7 @@ func findJavaModules(paths []string, modules map[string]*javaModule) map[string]
 			break
 		}
 	}
+
 	return ret
 }
 
diff --git a/tools/ide_query/prober_scripts/cpp/general.cc b/tools/ide_query/prober_scripts/cpp/general.cc
index 0f0639be5e..ac882829c0 100644
--- a/tools/ide_query/prober_scripts/cpp/general.cc
+++ b/tools/ide_query/prober_scripts/cpp/general.cc
@@ -56,7 +56,7 @@ void TestCompletion() {
 
 void TestNavigation() {
   std::vector<int> ints;
-  //               |   | ints
+  //               ^   ^ ints
   //      ^
 
   // step
diff --git a/tools/aconfig/fake_device_config/src/android/os/Binder.java b/tools/ide_query/prober_scripts/jvm/Android.bp
similarity index 68%
rename from tools/aconfig/fake_device_config/src/android/os/Binder.java
rename to tools/ide_query/prober_scripts/jvm/Android.bp
index 8a2313dfda..84d00b52fd 100644
--- a/tools/aconfig/fake_device_config/src/android/os/Binder.java
+++ b/tools/ide_query/prober_scripts/jvm/Android.bp
@@ -14,13 +14,15 @@
  * limitations under the License.
  */
 
-package android.os;
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
 
-public class Binder {
-    public static final long clearCallingIdentity() {
-        throw new UnsupportedOperationException("Stub!");
-    }
-    public static final void restoreCallingIdentity(long token) {
-        throw new UnsupportedOperationException("Stub!");
-    }
+java_library {
+    name: "ide_query_proberscript_jvm",
+    srcs: [
+        "Foo.java",
+        "Bar.java",
+        "other/Other.java",
+    ],
 }
diff --git a/tools/ide_query/prober_scripts/jvm/Bar.java b/tools/ide_query/prober_scripts/jvm/Bar.java
new file mode 100644
index 0000000000..8d51576901
--- /dev/null
+++ b/tools/ide_query/prober_scripts/jvm/Bar.java
@@ -0,0 +1,32 @@
+/*
+ * Copyright 2014 The Android Open Source Project
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
+package jvm;
+
+/** Bar class. The class for testing code assist within the same build module. */
+class Bar<K extends Number, V extends Number> {
+  Bar() {
+    foo(new Foo());
+  }
+
+  void foo(Foo f) {}
+
+  void foo(Object o) {}
+
+  void bar(Foo f) {}
+
+  void baz(Object o) {}
+}
\ No newline at end of file
diff --git a/tools/ide_query/prober_scripts/jvm/Foo.java b/tools/ide_query/prober_scripts/jvm/Foo.java
index a043f72e32..2c8ceb62db 100644
--- a/tools/ide_query/prober_scripts/jvm/Foo.java
+++ b/tools/ide_query/prober_scripts/jvm/Foo.java
@@ -16,22 +16,109 @@
 
 package jvm;
 
-import java.util.ArrayList;
-import java.util.HashSet;
+import jvm.other.Other;
 
 /** Foo class. */
 public final class Foo {
+//               ^  ^ foo_def
+
+  void testParameterInfo() {
+    // Test signature help for type parameters.
+
+    Bar<Integer, Double> b = new Bar<>();
+    //                               ^ ctor
+    //     ^ decl_1
+    //              ^ decl_2
+    System.out.println(b);
+
+    // step at ctor
+    // workspace.waitForReady()
+    // paraminfo.trigger()
+    // assert paraminfo.items.filter(
+    //  label="K extends Number, V extends Number",
+    //  selection="K extends Number",
+    // )
+
+    // step at decl_1
+    // workspace.waitForReady()
+    // paraminfo.trigger()
+    // assert paraminfo.items.filter(
+    //  label="K extends Number, V extends Number",
+    //  selection="K extends Number",
+    // )
+
+    // step at decl_2
+    // workspace.waitForReady()
+    // paraminfo.trigger()
+    // assert paraminfo.items.filter(
+    //  label="K extends Number, V extends Number",
+    //  selection="V extends Number",
+    // )
+
+    // Test signature help for constructor parameters.
+
+    Other other = new Other(123, "foo");
+    //                       ^ param_1
+    //                             ^ param_2
+    System.out.println(other);
+
+    // step at param_1
+    // workspace.waitForReady()
+    // paraminfo.trigger()
+    // assert paraminfo.items.filter(
+    //  label="\\(int first, String second\\)",
+    //  selection="int first",
+    // )
+
+    // step at param_2
+    // workspace.waitForReady()
+    // paraminfo.trigger()
+    // assert paraminfo.items.empty()
+  }
 
   void testCompletion() {
-    ArrayList<Integer> list = new ArrayList<>();
-    System.out.println(list);
+    Bar<Integer, Double> b = new Bar<>();
+    System.out.println(b);
 
     // ^
 
     // step
-    // ; Test completion on the standard types.
-    // type("list.")
+    // ; Test completion on types from the same package.
+    // workspace.waitForReady()
+    // type("b.")
     // completion.trigger()
-    // assert completion.items.filter(label="add.*")
+    // assert completion.items.filter(label="foo.*")
+    // delline()
+
+    Other other = new Other(1, "foo");
+    System.out.println(other);
+
+    // ^
+
+    // step
+    // ; Test completion on types from a different package.
+    // workspace.waitForReady()
+    // type("other.")
+    // completion.trigger()
+    // apply(completion.items.filter(label="other.*").first())
+    // type(".")
+    // completion.trigger()
+    // apply(completion.items.filter(label="other.*").first())
+    // delline()
+  }
+
+  void testDiagnostics() {
+
+    // ^
+
+    // step
+    // ; Test diagnostics about wrong type argument bounds.
+    // workspace.waitForReady()
+    // type("Bar<String, Double> b;")
+    // assert diagnostics.items.filter(
+    //  message="type argument .* is not within bounds .*",
+    //  code="compiler.err.not.within.bounds",
+    // )
+    // delline()
   }
 }
diff --git a/tools/ide_query/prober_scripts/jvm/ide_query.out b/tools/ide_query/prober_scripts/jvm/ide_query.out
new file mode 100644
index 0000000000..af9fb86e83
--- /dev/null
+++ b/tools/ide_query/prober_scripts/jvm/ide_query.out
@@ -0,0 +1,4 @@
+
+out2X
+6build/make/tools/ide_query/prober_scripts/jvm/Foo.javaide_query_proberscript_jvm:Î
+ide_query_proberscript_jvm6build/make/tools/ide_query/prober_scripts/jvm/Foo.java6build/make/tools/ide_query/prober_scripts/jvm/Bar.java>build/make/tools/ide_query/prober_scripts/jvm/other/Other.java
\ No newline at end of file
diff --git a/tools/ide_query/prober_scripts/jvm/other/Other.java b/tools/ide_query/prober_scripts/jvm/other/Other.java
new file mode 100644
index 0000000000..822662a66e
--- /dev/null
+++ b/tools/ide_query/prober_scripts/jvm/other/Other.java
@@ -0,0 +1,26 @@
+/*
+ * Copyright 2014 The Android Open Source Project
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
+package jvm.other;
+
+/** Other class */
+public class Other {
+  public Other(int first, String second) {}
+
+  public Other other() {
+    return new Other(0, "");
+  }
+}
diff --git a/tools/java-event-log-tags.py b/tools/java-event-log-tags.py
index bbd65fa4bf..e3dc07e4ab 100755
--- a/tools/java-event-log-tags.py
+++ b/tools/java-event-log-tags.py
@@ -15,16 +15,12 @@
 # limitations under the License.
 
 """
-Usage: java-event-log-tags.py [-o output_file] <input_file> <merged_tags_file>
-
 Generate a java class containing constants for each of the event log
 tags in the given input file.
-
--h to display this usage message and exit.
 """
 
 from io import StringIO
-import getopt
+import argparse
 import os
 import os.path
 import re
@@ -32,57 +28,14 @@ import sys
 
 import event_log_tags
 
-output_file = None
-
-try:
-  opts, args = getopt.getopt(sys.argv[1:], "ho:")
-except getopt.GetoptError as err:
-  print(str(err))
-  print(__doc__)
-  sys.exit(2)
-
-for o, a in opts:
-  if o == "-h":
-    print(__doc__)
-    sys.exit(2)
-  elif o == "-o":
-    output_file = a
-  else:
-    print("unhandled option %s" % (o,), file=sys.stderr)
-    sys.exit(1)
-
-if len(args) != 1 and len(args) != 2:
-  print("need one or two input files, not %d" % (len(args),))
-  print(__doc__)
-  sys.exit(1)
+parser = argparse.ArgumentParser(description=__doc__)
+parser.add_argument('-o', dest='output_file')
+parser.add_argument('file')
+args = parser.parse_args()
 
-fn = args[0]
+fn = args.file
 tagfile = event_log_tags.TagFile(fn)
 
-if len(args) > 1:
-  # Load the merged tag file (which should have numbers assigned for all
-  # tags.  Use the numbers from the merged file to fill in any missing
-  # numbers from the input file.
-  merged_fn = args[1]
-  merged_tagfile = event_log_tags.TagFile(merged_fn)
-  merged_by_name = dict([(t.tagname, t) for t in merged_tagfile.tags])
-  for t in tagfile.tags:
-    if t.tagnum is None:
-      if t.tagname in merged_by_name:
-        t.tagnum = merged_by_name[t.tagname].tagnum
-      else:
-        # We're building something that's not being included in the
-        # product, so its tags don't appear in the merged file.  Assign
-        # them all an arbitrary number so we can emit the java and
-        # compile the (unused) package.
-        t.tagnum = 999999
-else:
-  # Not using the merged tag file, so all tags must have manually assigned
-  # numbers
-  for t in tagfile.tags:
-    if t.tagnum is None:
-      tagfilef.AddError("tag \"%s\" has no number" % (tagname,), tag.linenum)
-
 if "java_package" not in tagfile.options:
   tagfile.AddError("java_package option not specified", linenum=0)
 
@@ -141,11 +94,11 @@ javaTypes = ["ERROR", "int", "long", "String", "Object[]", "float"]
 for t in tagfile.tags:
   methodName = javaName("write_" + t.tagname)
   if t.description:
-    args = [arg.strip("() ").split("|") for arg in t.description.split(",")]
+    fn_args = [arg.strip("() ").split("|") for arg in t.description.split(",")]
   else:
-    args = []
-  argTypesNames = ", ".join([javaTypes[int(arg[1])] + " " + javaName(arg[0]) for arg in args])
-  argNames = "".join([", " + javaName(arg[0]) for arg in args])
+    fn_args = []
+  argTypesNames = ", ".join([javaTypes[int(arg[1])] + " " + javaName(arg[0]) for arg in fn_args])
+  argNames = "".join([", " + javaName(arg[0]) for arg in fn_args])
   buffer.write("\n  public static void %s(%s) {" % (methodName, argTypesNames))
   buffer.write("\n    android.util.EventLog.writeEvent(%s%s);" % (t.tagname.upper(), argNames))
   buffer.write("\n  }\n")
@@ -153,8 +106,8 @@ for t in tagfile.tags:
 
 buffer.write("}\n");
 
-output_dir = os.path.dirname(output_file)
+output_dir = os.path.dirname(args.output_file)
 if not os.path.exists(output_dir):
   os.makedirs(output_dir)
 
-event_log_tags.WriteOutput(output_file, buffer)
+event_log_tags.WriteOutput(args.output_file, buffer)
diff --git a/tools/merge-event-log-tags.py b/tools/merge-event-log-tags.py
index 292604c469..5730c11c43 100755
--- a/tools/merge-event-log-tags.py
+++ b/tools/merge-event-log-tags.py
@@ -15,22 +15,13 @@
 # limitations under the License.
 
 """
-Usage: merge-event-log-tags.py [-o output_file] [input_files...]
-
 Merge together zero or more event-logs-tags files to produce a single
 output file, stripped of comments.  Checks that no tag numbers conflict
 and fails if they do.
-
--h to display this usage message and exit.
 """
 
 from io import StringIO
-import getopt
-try:
-  import hashlib
-except ImportError:
-  import md5 as hashlib
-import struct
+import argparse
 import sys
 
 import event_log_tags
@@ -38,32 +29,10 @@ import event_log_tags
 errors = []
 warnings = []
 
-output_file = None
-pre_merged_file = None
-
-# Tags with a tag number of ? are assigned a tag in the range
-# [ASSIGN_START, ASSIGN_LIMIT).
-ASSIGN_START = 900000
-ASSIGN_LIMIT = 1000000
-
-try:
-  opts, args = getopt.getopt(sys.argv[1:], "ho:m:")
-except getopt.GetoptError as err:
-  print(str(err))
-  print(__doc__)
-  sys.exit(2)
-
-for o, a in opts:
-  if o == "-h":
-    print(__doc__)
-    sys.exit(2)
-  elif o == "-o":
-    output_file = a
-  elif o == "-m":
-    pre_merged_file = a
-  else:
-    print("unhandled option %s" % (o,), file=sys.stderr)
-    sys.exit(1)
+parser = argparse.ArgumentParser(description=__doc__)
+parser.add_argument('-o', dest='output_file')
+parser.add_argument('files', nargs='*')
+args = parser.parse_args()
 
 # Restrictions on tags:
 #
@@ -77,12 +46,7 @@ for o, a in opts:
 by_tagname = {}
 by_tagnum = {}
 
-pre_merged_tags = {}
-if pre_merged_file:
-  for t in event_log_tags.TagFile(pre_merged_file).tags:
-    pre_merged_tags[t.tagname] = t
-
-for fn in args:
+for fn in args.files:
   tagfile = event_log_tags.TagFile(fn)
 
   for t in tagfile.tags:
@@ -93,12 +57,6 @@ for fn in args:
     if t.tagname in by_tagname:
       orig = by_tagname[t.tagname]
 
-      # Allow an explicit tag number to define an implicit tag number
-      if orig.tagnum is None:
-        orig.tagnum = t.tagnum
-      elif t.tagnum is None:
-        t.tagnum = orig.tagnum
-
       if (t.tagnum == orig.tagnum and
           t.description == orig.description):
         # if the name and description are identical, issue a warning
@@ -114,7 +72,7 @@ for fn in args:
             linenum=t.linenum)
       continue
 
-    if t.tagnum is not None and t.tagnum in by_tagnum:
+    if t.tagnum in by_tagnum:
       orig = by_tagnum[t.tagnum]
 
       if t.tagname != orig.tagname:
@@ -125,8 +83,7 @@ for fn in args:
         continue
 
     by_tagname[t.tagname] = t
-    if t.tagnum is not None:
-      by_tagnum[t.tagnum] = t
+    by_tagnum[t.tagnum] = t
 
   errors.extend(tagfile.errors)
   warnings.extend(tagfile.warnings)
@@ -140,38 +97,6 @@ if warnings:
   for fn, ln, msg in warnings:
     print("%s:%d: warning: %s" % (fn, ln, msg), file=sys.stderr)
 
-# Python's hash function (a) isn't great and (b) varies between
-# versions of python.  Using md5 is overkill here but is the same from
-# platform to platform and speed shouldn't matter in practice.
-def hashname(str):
-  d = hashlib.md5(str).digest()[:4]
-  return struct.unpack("!I", d)[0]
-
-# Assign a tag number to all the entries that say they want one
-# assigned.  We do this based on a hash of the tag name so that the
-# numbers should stay relatively stable as tags are added.
-
-# If we were provided pre-merged tags (w/ the -m option), then don't
-# ever try to allocate one, just fail if we don't have a number
-
-for name, t in sorted(by_tagname.items()):
-  if t.tagnum is None:
-    if pre_merged_tags:
-      try:
-        t.tagnum = pre_merged_tags[t.tagname]
-      except KeyError:
-        print("Error: Tag number not defined for tag `%s'. Have you done a full build?" % t.tagname,
-              file=sys.stderr)
-        sys.exit(1)
-    else:
-      while True:
-        x = (hashname(name) % (ASSIGN_LIMIT - ASSIGN_START - 1)) + ASSIGN_START
-        if x not in by_tagnum:
-          t.tagnum = x
-          by_tagnum[x] = t
-          break
-        name = "_" + name
-
 # by_tagnum should be complete now; we've assigned numbers to all tags.
 
 buffer = StringIO()
@@ -181,4 +106,4 @@ for n, t in sorted(by_tagnum.items()):
   else:
     buffer.write("%d %s\n" % (t.tagnum, t.tagname))
 
-event_log_tags.WriteOutput(output_file, buffer)
+event_log_tags.WriteOutput(args.output_file, buffer)
diff --git a/tools/missing_soong_module_info.py b/tools/missing_soong_module_info.py
new file mode 100755
index 0000000000..6fa7f2bccb
--- /dev/null
+++ b/tools/missing_soong_module_info.py
@@ -0,0 +1,53 @@
+#!/usr/bin/env python3
+#
+# Copyright (C) 2016 The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the 'License');
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an 'AS IS' BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+import json
+import os
+import sys
+
+def main():
+    try:
+        product_out = os.environ["ANDROID_PRODUCT_OUT"]
+    except KeyError:
+        sys.stderr.write("Can't get ANDROID_PRODUCT_OUT. Run lunch first.\n")
+        sys.exit(1)
+
+    filename = os.path.join(product_out, "module-info.json")
+    try:
+        with open(filename) as f:
+            modules = json.load(f)
+    except FileNotFoundError:
+        sys.stderr.write(f"File not found: {filename}\n")
+        sys.exit(1)
+    except json.JSONDecodeError:
+        sys.stderr.write(f"Invalid json: {filename}\n")
+        return None
+
+    classes = {}
+
+    for name, info in modules.items():
+        make = info.get("make")
+        make_gen = info.get("make_generated_module_info")
+        if not make and make_gen:
+            classes.setdefault(frozenset(info.get("class")), []).append(name)
+
+    for cl, names in classes.items():
+        print(" ".join(cl))
+        for name in names:
+            print(" ", name)
+
+if __name__ == "__main__":
+    main()
diff --git a/tools/otatools_package/Android.bp b/tools/otatools_package/Android.bp
new file mode 100644
index 0000000000..80e1e7d964
--- /dev/null
+++ b/tools/otatools_package/Android.bp
@@ -0,0 +1,213 @@
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
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+java_genrule_host {
+    name: "otatools_package_dep_jars",
+    tools: ["soong_zip"],
+    compile_multilib: "first",
+    cmd: "mkdir -p $(genDir)/framework && " +
+        "cp $(in) $(genDir)/framework && " +
+        "$(location soong_zip) -o $(out) -C $(genDir) -D $(genDir)/framework",
+    srcs: [
+        ":apksigner",
+        ":boot_signer",
+        ":signapk",
+        ":verity_signer",
+    ],
+    out: ["otatools_package_dep_jars.zip"],
+}
+
+cc_genrule {
+    name: "otatools_package_dep_libs",
+    host_supported: true,
+    device_supported: false,
+    compile_multilib: "first",
+    tools: ["soong_zip"],
+    cmd: "mkdir -p $(genDir)/$$CC_MULTILIB &&" +
+        "cp $(in) $(genDir)/$$CC_MULTILIB && " +
+        "$(location soong_zip) -o $(out) -C $(genDir) -D $(genDir)/$$CC_MULTILIB",
+    srcs: [
+        ":libbase",
+        ":libbrillo",
+        ":libbrillo-stream",
+        ":libc++",
+        "//external/libchrome:libchrome",
+        ":libconscrypt_openjdk_jni",
+        ":libcrypto",
+        ":libcrypto_utils",
+        ":libcutils",
+        ":libevent",
+        ":libext2_blkid",
+        ":libext2_com_err",
+        ":libext2_e2p",
+        ":libext2_quota",
+        ":libext2_uuid",
+        ":libext2fs",
+        ":libext4_utils",
+        ":libfec",
+        ":libhidl-gen-utils",
+        ":libhidlmetadata",
+        ":libicui18n",
+        ":libicuuc",
+        ":liblog",
+        ":liblp",
+        ":liblz4",
+        ":libpcre2",
+        ":libprocessgroup",
+        ":libprotobuf-cpp-lite",
+        ":libselinux",
+        ":libsparse",
+        ":libsqlite",
+        ":libsquashfs_utils",
+        ":libssl",
+        ":libz",
+        ":libziparchive",
+    ],
+    out: ["otatools_package_dep_libs.zip"],
+}
+
+cc_genrule {
+    name: "otatools_package_dep_bins",
+    host_supported: true,
+    device_supported: false,
+    compile_multilib: "first",
+    tools: [
+        "apksigner",
+        "boot_signer",
+        "merge_zips",
+        "signapk",
+        "verity_signer",
+    ],
+    cmd: "mkdir -p $(genDir)/bin && " +
+        "cp $(in) $(genDir)/bin && " +
+        "cp $(location apksigner) $(location boot_signer) $(location merge_zips) $(location signapk) $(location verity_signer) $(genDir)/bin && " +
+        "$(location :soong_zip) -o $(out) -C $(genDir) -D $(genDir)/bin",
+    srcs: [
+        ":aapt2",
+        ":add_img_to_target_files",
+        ":apex_compression_tool",
+        ":apexd_host",
+        ":apexer",
+        ":append2simg",
+        ":avbtool",
+        ":blk_alloc_to_base_fs",
+        ":brillo_update_payload",
+        ":brotli",
+        ":bsdiff",
+        ":build_image",
+        ":build_super_image",
+        ":build_verity_metadata",
+        ":build_verity_tree",
+        ":care_map_generator",
+        ":check_ota_package_signature",
+        ":check_target_files_signatures",
+        ":check_target_files_vintf",
+        ":checkvintf",
+        ":create_brick_ota",
+        ":deapexer",
+        ":debugfs_static",
+        ":delta_generator",
+        ":e2fsck",
+        ":e2fsdroid",
+        ":fc_sort",
+        ":fec",
+        ":fs_config",
+        ":fsck.erofs",
+        ":fsck.f2fs",
+        ":generate_verity_key",
+        ":host_init_verifier",
+        ":img2simg",
+        ":img_from_target_files",
+        ":initrd_bootconfig",
+        ":lpmake",
+        ":lpunpack",
+        ":lz4",
+        ":make_f2fs",
+        ":make_f2fs_casefold",
+        ":merge_ota",
+        ":merge_target_files",
+        "//device/generic/goldfish:mk_combined_img",
+        ":mkbootfs",
+        ":mkbootimg",
+        ":mke2fs",
+        ":mkf2fsuserimg",
+        ":mkfs.erofs",
+        ":mksquashfs",
+        ":mksquashfsimage",
+        ":mkuserimg_mke2fs",
+        ":ota_extractor",
+        ":ota_from_target_files",
+        ":repack_bootimg",
+        ":resize2fs",
+        ":secilc",
+        ":sefcontext_compile",
+        ":sgdisk",
+        ":shflags",
+        ":sign_apex",
+        ":sign_target_files_apks",
+        ":sign_virt_apex",
+        ":simg2img",
+        ":sload_f2fs",
+        ":soong_zip",
+        ":toybox",
+        ":tune2fs",
+        ":unpack_bootimg",
+        ":update_device",
+        ":validate_target_files",
+        ":verity_verifier",
+        ":zip2zip",
+        ":zipalign",
+        ":zucchini",
+    ] + select(soong_config_variable("otatools", "use_build_mixed_kernels_ramdisk"), {
+        true: [":build_mixed_kernels_ramdisk_host"],
+        default: [],
+    }) + select(soong_config_variable("otatools", "use_bootable_deprecated_ota_applypatch"), {
+        true: [
+            ":imgdiff",
+            ":update_host_simulator",
+        ],
+        default: [],
+    }),
+    out: ["otatools_package_dep_bins.zip"],
+}
+
+java_genrule_host {
+    name: "otatools_package",
+    tools: ["merge_zips"],
+    compile_multilib: "first",
+    cmd: "$(location merge_zips) $(out) $(in)",
+    srcs: [
+        ":otatools_package_cert_files",
+        ":otatools_package_dep_bins",
+        ":otatools_package_dep_jars",
+        ":otatools_package_dep_libs",
+        ":otatools_package_releasetools",
+    ],
+    // TODO: Rename as "otatools.zip" when the rest files are ready.
+    out: ["otatools_temp.zip"],
+    dist: {
+        targets: [
+            "otatools-package-temp",
+        ],
+    },
+}
+
+otatools_package_cert_files {
+    name: "otatools_package_cert_files",
+}
diff --git a/tools/perf/benchmarks b/tools/perf/benchmarks
index 6998ecd5c2..38715ea8ea 100755
--- a/tools/perf/benchmarks
+++ b/tools/perf/benchmarks
@@ -202,6 +202,16 @@ def Clean():
     return Change(label="Remove out", change=remove_out, undo=lambda: None)
 
 
+def CleanNinja():
+    """Remove the out directory, and then run lunch to initialize soong"""
+    def clean_ninja():
+        returncode = subprocess.call("rm out/*.ninja out/soong/*.ninja", shell=True)
+        if returncode != 0:
+            report_error(f"Build failed: {' '.join(cmd)}")
+            raise FatalError()
+    return Change(label="Remove ninja files", change=clean_ninja, undo=lambda: None)
+
+
 def NoChange():
     """No change to the source tree."""
     return Change(label="No change", change=lambda: None, undo=lambda: None)
@@ -337,6 +347,12 @@ class Runner():
 
     def Run(self):
         """Run all of the user-selected benchmarks."""
+
+        # With `--list`, just list the benchmarks available.
+        if self._options.List():
+            print(" ".join(self._options.BenchmarkIds()))
+            return
+
         # Clean out the log dir or create it if necessary
         prepare_log_dir(self._options.LogDir())
 
@@ -410,7 +426,7 @@ class Runner():
         """Builds the modules.  Saves interesting log files to log_dir.  Raises FatalError
         if the build fails.
         """
-        sys.stderr.write(f"STARTING BUILD {benchmark.build_description()}\n")
+        sys.stderr.write(f"STARTING BUILD {benchmark.build_description()} Logs to: {build_log_dir}\n")
 
         before_ns = time.perf_counter_ns()
         if not self._options.DryRun():
@@ -546,6 +562,8 @@ benchmarks:
         parser.add_argument("--benchmark", nargs="*", default=[b.id for b in self._benchmarks],
                             metavar="BENCHMARKS",
                             help="Benchmarks to run.  Default suite will be run if omitted.")
+        parser.add_argument("--list", action="store_true",
+                            help="list the available benchmarks.  No benchmark is run.")
         parser.add_argument("--dist-one", action="store_true",
                             help="Copy logs and metrics to the given dist dir. Requires that only"
                                 + " one benchmark be supplied. Postroll steps will be skipped.")
@@ -565,7 +583,7 @@ benchmarks:
 
         # --dist-one requires that only one benchmark be supplied
         if self._args.dist_one and len(self.Benchmarks()) != 1:
-            self._error("--dist-one requires that exactly one --benchmark.")
+            self._error("--dist-one requires exactly one --benchmark.")
 
         if self._had_error:
             raise FatalError()
@@ -615,6 +633,12 @@ benchmarks:
     def DryRun(self):
         return self._args.dry_run
 
+    def List(self):
+        return self._args.list
+
+    def BenchmarkIds(self) :
+        return [benchmark.id for benchmark in self._benchmarks]
+
     def _lunches(self):
         def parse_lunch(lunch):
             parts = lunch.split("-")
@@ -699,6 +723,13 @@ benchmarks:
                       preroll=1,
                       postroll=3,
                       ),
+            Benchmark(id="full_analysis",
+                      title="Full Analysis",
+                      change=CleanNinja(),
+                      modules=["nothing"],
+                      preroll=1,
+                      postroll=3,
+                      ),
             Benchmark(id="modify_stdio",
                       title="Modify stdio.cpp",
                       change=Modify("bionic/libc/stdio/stdio.cpp", Comment("//")),
@@ -786,6 +817,32 @@ benchmarks:
                       preroll=1,
                       postroll=2,
                       ),
+            Benchmark(id="add_systemui_field_with_tests",
+                      title="Add SystemUI field with tests",
+                      change=AddJavaField("frameworks/base/packages/SystemUI/src/com/android/systemui/wmshell/WMShell.java",
+                                    "public"),
+                      modules=["SystemUiRavenTests"],
+                      preroll=1,
+                      postroll=2,
+                      ),
+            Benchmark(id="systemui_flicker_add_log_call",
+                      title="Add a Log call to flicker",
+                      change=Modify("platform_testing/libraries/flicker/src/android/tools/flicker/FlickerServiceResultsCollector.kt",
+                                    lambda: f'Log.v(LOG_TAG, "BENCHMARK = {random.randint(0, 1000000)}");\n',
+                                    before="Log.v(LOG_TAG,"),
+                      modules=["WMShellFlickerTestsPip"],
+                      preroll=1,
+                      postroll=2,
+                      ),
+            Benchmark(id="systemui_core_add_log_call",
+                      title="Add a Log call SystemUIApplication",
+                      change=Modify("frameworks/base/packages/SystemUI/src/com/android/systemui/SystemUIApplication.java",
+                                    lambda: f'Log.v(TAG, "BENCHMARK = {random.randint(0, 1000000)}");\n',
+                                    before="Log.wtf(TAG,"),
+                      modules=["SystemUI-core"],
+                      preroll=1,
+                      postroll=2,
+                      ),
         ]
 
     def _error(self, message):
diff --git a/tools/product_config/TEST_MAPPING b/tools/product_config/TEST_MAPPING
deleted file mode 100644
index d3568f134e..0000000000
--- a/tools/product_config/TEST_MAPPING
+++ /dev/null
@@ -1,7 +0,0 @@
-{
-  "presubmit": [
-    {
-      "name": "product_config_test"
-    }
-  ]
-}
diff --git a/tools/protos/Android.bp b/tools/protos/Android.bp
index c6ad19e644..65f13cb0d3 100644
--- a/tools/protos/Android.bp
+++ b/tools/protos/Android.bp
@@ -18,11 +18,6 @@ package {
 
 python_library_host {
     name: "metadata_file_proto_py",
-    version: {
-        py3: {
-            enabled: true,
-        },
-    },
     srcs: [
         "metadata_file.proto",
     ],
diff --git a/tools/record-finalized-flags/.gitignore b/tools/record-finalized-flags/.gitignore
new file mode 100644
index 0000000000..1e7caa9ea8
--- /dev/null
+++ b/tools/record-finalized-flags/.gitignore
@@ -0,0 +1,2 @@
+Cargo.lock
+target/
diff --git a/tools/record-finalized-flags/Android.bp b/tools/record-finalized-flags/Android.bp
new file mode 100644
index 0000000000..55a3a389e0
--- /dev/null
+++ b/tools/record-finalized-flags/Android.bp
@@ -0,0 +1,28 @@
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+rust_defaults {
+    name: "record-finalized-flags-defaults",
+    edition: "2021",
+    clippy_lints: "android",
+    lints: "android",
+    srcs: ["src/main.rs"],
+    rustlibs: [
+        "libaconfig_protos",
+        "libanyhow",
+        "libclap",
+        "libregex",
+    ],
+}
+
+rust_binary_host {
+    name: "record-finalized-flags",
+    defaults: ["record-finalized-flags-defaults"],
+}
+
+rust_test_host {
+    name: "record-finalized-flags-test",
+    defaults: ["record-finalized-flags-defaults"],
+    test_suites: ["general-tests"],
+}
diff --git a/tools/record-finalized-flags/Cargo.toml b/tools/record-finalized-flags/Cargo.toml
new file mode 100644
index 0000000000..0fc795363f
--- /dev/null
+++ b/tools/record-finalized-flags/Cargo.toml
@@ -0,0 +1,15 @@
+# Cargo.toml file to allow rapid development of record-finalized-flags using
+# cargo. Soong is the official Android build system, and the only system
+# guaranteed to support record-finalized-flags. If there is ever any issue with
+# the cargo setup, support for cargo will be dropped and this file removed.
+
+[package]
+name = "record-finalized-flags"
+version = "0.1.0"
+edition = "2021"
+
+[dependencies]
+aconfig_protos = { path = "../aconfig/aconfig_protos" }
+anyhow = { path = "../../../../external/rust/android-crates-io/crates/anyhow" }
+clap = { path = "../../../../external/rust/android-crates-io/crates/clap", features = ["derive"] }
+regex = { path = "../../../../external/rust/android-crates-io/crates/regex" }
diff --git a/tools/record-finalized-flags/OWNERS b/tools/record-finalized-flags/OWNERS
new file mode 100644
index 0000000000..2864a2c23c
--- /dev/null
+++ b/tools/record-finalized-flags/OWNERS
@@ -0,0 +1 @@
+include platform/frameworks/base:/SDK_OWNERS
diff --git a/tools/record-finalized-flags/src/api_signature_files.rs b/tools/record-finalized-flags/src/api_signature_files.rs
new file mode 100644
index 0000000000..af8f4d1957
--- /dev/null
+++ b/tools/record-finalized-flags/src/api_signature_files.rs
@@ -0,0 +1,49 @@
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
+use anyhow::Result;
+use regex::Regex;
+use std::{collections::HashSet, io::Read};
+
+use crate::FlagId;
+
+/// Grep for all flags used with @FlaggedApi annotations in an API signature file (*current.txt
+/// file).
+pub(crate) fn extract_flagged_api_flags<R: Read>(mut reader: R) -> Result<HashSet<FlagId>> {
+    let mut haystack = String::new();
+    reader.read_to_string(&mut haystack)?;
+    let regex = Regex::new(r#"(?ms)@FlaggedApi\("(.*?)"\)"#).unwrap();
+    let iter = regex.captures_iter(&haystack).map(|cap| cap[1].to_owned());
+    Ok(HashSet::from_iter(iter))
+}
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+
+    #[test]
+    fn test() {
+        let api_signature_file = include_bytes!("../tests/api-signature-file.txt");
+        let flags = extract_flagged_api_flags(&api_signature_file[..]).unwrap();
+        assert_eq!(
+            flags,
+            HashSet::from_iter(vec![
+                "record_finalized_flags.test.foo".to_string(),
+                "this.flag.is.not.used".to_string(),
+            ])
+        );
+    }
+}
diff --git a/tools/record-finalized-flags/src/finalized_flags.rs b/tools/record-finalized-flags/src/finalized_flags.rs
new file mode 100644
index 0000000000..1ae4c4d789
--- /dev/null
+++ b/tools/record-finalized-flags/src/finalized_flags.rs
@@ -0,0 +1,47 @@
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
+use anyhow::Result;
+use std::{collections::HashSet, io::Read};
+
+use crate::FlagId;
+
+/// Read a list of flag names. The input is expected to be plain text, with each line containing
+/// the name of a single flag.
+pub(crate) fn read_finalized_flags<R: Read>(mut reader: R) -> Result<HashSet<FlagId>> {
+    let mut contents = String::new();
+    reader.read_to_string(&mut contents)?;
+    let iter = contents.lines().map(|s| s.to_owned());
+    Ok(HashSet::from_iter(iter))
+}
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+
+    #[test]
+    fn test() {
+        let input = include_bytes!("../tests/finalized-flags.txt");
+        let flags = read_finalized_flags(&input[..]).unwrap();
+        assert_eq!(
+            flags,
+            HashSet::from_iter(vec![
+                "record_finalized_flags.test.bar".to_string(),
+                "record_finalized_flags.test.baz".to_string(),
+            ])
+        );
+    }
+}
diff --git a/tools/record-finalized-flags/src/flag_values.rs b/tools/record-finalized-flags/src/flag_values.rs
new file mode 100644
index 0000000000..cc16d12f3c
--- /dev/null
+++ b/tools/record-finalized-flags/src/flag_values.rs
@@ -0,0 +1,53 @@
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
+use aconfig_protos::{ParsedFlagExt, ProtoFlagPermission, ProtoFlagState};
+use anyhow::{anyhow, Result};
+use std::{collections::HashSet, io::Read};
+
+use crate::FlagId;
+
+/// Parse a ProtoParsedFlags binary protobuf blob and return the fully qualified names of flags
+/// that are slated for API finalization (i.e. are both ENABLED and READ_ONLY).
+pub(crate) fn get_relevant_flags_from_binary_proto<R: Read>(
+    mut reader: R,
+) -> Result<HashSet<FlagId>> {
+    let mut buffer = Vec::new();
+    reader.read_to_end(&mut buffer)?;
+    let parsed_flags = aconfig_protos::parsed_flags::try_from_binary_proto(&buffer)
+        .map_err(|_| anyhow!("failed to parse binary proto"))?;
+    let iter = parsed_flags
+        .parsed_flag
+        .into_iter()
+        .filter(|flag| {
+            flag.state() == ProtoFlagState::ENABLED
+                && flag.permission() == ProtoFlagPermission::READ_ONLY
+        })
+        .map(|flag| flag.fully_qualified_name());
+    Ok(HashSet::from_iter(iter))
+}
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+
+    #[test]
+    fn test_disabled_or_read_write_flags_are_ignored() {
+        let bytes = include_bytes!("../tests/flags.protobuf");
+        let flags = get_relevant_flags_from_binary_proto(&bytes[..]).unwrap();
+        assert_eq!(flags, HashSet::from_iter(vec!["record_finalized_flags.test.foo".to_string()]));
+    }
+}
diff --git a/tools/record-finalized-flags/src/main.rs b/tools/record-finalized-flags/src/main.rs
new file mode 100644
index 0000000000..efdbc9be8e
--- /dev/null
+++ b/tools/record-finalized-flags/src/main.rs
@@ -0,0 +1,134 @@
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
+//! `record-finalized-flags` is a tool to create a snapshot (intended to be stored in
+//! prebuilts/sdk) of the flags used with @FlaggedApi APIs
+use anyhow::Result;
+use clap::Parser;
+use std::{collections::HashSet, fs::File, path::PathBuf};
+
+mod api_signature_files;
+mod finalized_flags;
+mod flag_values;
+
+pub(crate) type FlagId = String;
+
+const ABOUT: &str = "Create a new prebuilts/sdk/<version>/finalized-flags.txt file
+
+The prebuilts/sdk/<version>/finalized-flags.txt files list all aconfig flags that have been used
+with @FlaggedApi annotations on APIs that have been finalized. These files are used to prevent
+flags from being re-used for new, unfinalized, APIs, and by the aconfig code generation.
+
+This tool works as follows:
+
+  - Read API signature files from source tree (*current.txt files) [--api-signature-file]
+  - Read the current aconfig flag values from source tree [--parsed-flags-file]
+  - Read the previous finalized-flags.txt files from prebuilts/sdk [--finalized-flags-file]
+  - Extract the flags slated for API finalization by scanning through the API signature files for
+    flags that are ENABLED and READ_ONLY
+  - Merge the found flags with the recorded flags from previous API finalizations
+  - Print the set of flags to stdout
+";
+
+#[derive(Parser, Debug)]
+#[clap(about=ABOUT)]
+struct Cli {
+    #[arg(long)]
+    parsed_flags_file: PathBuf,
+
+    #[arg(long)]
+    api_signature_file: Vec<PathBuf>,
+
+    #[arg(long)]
+    finalized_flags_file: PathBuf,
+}
+
+/// Filter out the ENABLED and READ_ONLY flags used with @FlaggedApi annotations in the source
+/// tree, and add those flags to the set of previously finalized flags.
+fn calculate_new_finalized_flags(
+    flags_used_with_flaggedapi_annotation: &HashSet<FlagId>,
+    all_flags_to_be_finalized: &HashSet<FlagId>,
+    already_finalized_flags: &HashSet<FlagId>,
+) -> HashSet<FlagId> {
+    let new_flags: HashSet<_> = flags_used_with_flaggedapi_annotation
+        .intersection(all_flags_to_be_finalized)
+        .map(|s| s.to_owned())
+        .collect();
+    already_finalized_flags.union(&new_flags).map(|s| s.to_owned()).collect()
+}
+
+fn main() -> Result<()> {
+    let args = Cli::parse();
+
+    let mut flags_used_with_flaggedapi_annotation = HashSet::new();
+    for path in args.api_signature_file {
+        let file = File::open(path)?;
+        for flag in api_signature_files::extract_flagged_api_flags(file)?.drain() {
+            flags_used_with_flaggedapi_annotation.insert(flag);
+        }
+    }
+
+    let file = File::open(args.parsed_flags_file)?;
+    let all_flags_to_be_finalized = flag_values::get_relevant_flags_from_binary_proto(file)?;
+
+    let file = File::open(args.finalized_flags_file)?;
+    let already_finalized_flags = finalized_flags::read_finalized_flags(file)?;
+
+    let mut new_finalized_flags = Vec::from_iter(calculate_new_finalized_flags(
+        &flags_used_with_flaggedapi_annotation,
+        &all_flags_to_be_finalized,
+        &already_finalized_flags,
+    ));
+    new_finalized_flags.sort();
+
+    println!("{}", new_finalized_flags.join("\n"));
+
+    Ok(())
+}
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+
+    #[test]
+    fn test() {
+        let input = include_bytes!("../tests/api-signature-file.txt");
+        let flags_used_with_flaggedapi_annotation =
+            api_signature_files::extract_flagged_api_flags(&input[..]).unwrap();
+
+        let input = include_bytes!("../tests/flags.protobuf");
+        let all_flags_to_be_finalized =
+            flag_values::get_relevant_flags_from_binary_proto(&input[..]).unwrap();
+
+        let input = include_bytes!("../tests/finalized-flags.txt");
+        let already_finalized_flags = finalized_flags::read_finalized_flags(&input[..]).unwrap();
+
+        let new_finalized_flags = calculate_new_finalized_flags(
+            &flags_used_with_flaggedapi_annotation,
+            &all_flags_to_be_finalized,
+            &already_finalized_flags,
+        );
+
+        assert_eq!(
+            new_finalized_flags,
+            HashSet::from_iter(vec![
+                "record_finalized_flags.test.foo".to_string(),
+                "record_finalized_flags.test.bar".to_string(),
+                "record_finalized_flags.test.baz".to_string(),
+            ])
+        );
+    }
+}
diff --git a/tools/record-finalized-flags/tests/api-signature-file.txt b/tools/record-finalized-flags/tests/api-signature-file.txt
new file mode 100644
index 0000000000..2ad559f0ad
--- /dev/null
+++ b/tools/record-finalized-flags/tests/api-signature-file.txt
@@ -0,0 +1,15 @@
+// Signature format: 2.0
+package android {
+
+  public final class C {
+    ctor public C();
+  }
+
+  public static final class C.inner {
+    ctor public C.inner();
+    field @FlaggedApi("record_finalized_flags.test.foo") public static final String FOO = "foo";
+    field @FlaggedApi("this.flag.is.not.used") public static final String BAR = "bar";
+  }
+
+}
+
diff --git a/tools/record-finalized-flags/tests/finalized-flags.txt b/tools/record-finalized-flags/tests/finalized-flags.txt
new file mode 100644
index 0000000000..7fbcb3dc65
--- /dev/null
+++ b/tools/record-finalized-flags/tests/finalized-flags.txt
@@ -0,0 +1,2 @@
+record_finalized_flags.test.bar
+record_finalized_flags.test.baz
diff --git a/tools/record-finalized-flags/tests/flags.declarations b/tools/record-finalized-flags/tests/flags.declarations
new file mode 100644
index 0000000000..b45ef62523
--- /dev/null
+++ b/tools/record-finalized-flags/tests/flags.declarations
@@ -0,0 +1,16 @@
+package: "record_finalized_flags.test"
+container: "system"
+
+flag {
+    name: "foo"
+    namespace: "test"
+    description: "FIXME"
+    bug: ""
+}
+
+flag {
+    name: "not_enabled"
+    namespace: "test"
+    description: "FIXME"
+    bug: ""
+}
diff --git a/tools/record-finalized-flags/tests/flags.protobuf b/tools/record-finalized-flags/tests/flags.protobuf
new file mode 100644
index 0000000000..7c6e63eca8
Binary files /dev/null and b/tools/record-finalized-flags/tests/flags.protobuf differ
diff --git a/tools/record-finalized-flags/tests/flags.values b/tools/record-finalized-flags/tests/flags.values
new file mode 100644
index 0000000000..ff6225d822
--- /dev/null
+++ b/tools/record-finalized-flags/tests/flags.values
@@ -0,0 +1,13 @@
+flag_value {
+    package: "record_finalized_flags.test"
+    name: "foo"
+    state: ENABLED
+    permission: READ_ONLY
+}
+
+flag_value {
+    package: "record_finalized_flags.test"
+    name: "not_enabled"
+    state: DISABLED
+    permission: READ_ONLY
+}
diff --git a/tools/record-finalized-flags/tests/generate-flags-protobuf.sh b/tools/record-finalized-flags/tests/generate-flags-protobuf.sh
new file mode 100755
index 0000000000..701189cd5c
--- /dev/null
+++ b/tools/record-finalized-flags/tests/generate-flags-protobuf.sh
@@ -0,0 +1,7 @@
+#!/bin/bash
+aconfig create-cache \
+    --package record_finalized_flags.test \
+    --container system \
+    --declarations flags.declarations \
+    --values flags.values \
+    --cache flags.protobuf
diff --git a/tools/releasetools/Android.bp b/tools/releasetools/Android.bp
index e371b2354c..2232385c6c 100644
--- a/tools/releasetools/Android.bp
+++ b/tools/releasetools/Android.bp
@@ -296,11 +296,6 @@ python_library_host {
 
 python_defaults {
     name: "releasetools_binary_defaults",
-    version: {
-        py3: {
-            embedded_launcher: true,
-        },
-    },
     // TODO (b/140144201) Build imgdiff from releasetools_common
     required: [
         "aapt2",
@@ -338,11 +333,6 @@ python_library_host {
 
 python_binary_host {
     name: "merge_ota",
-    version: {
-        py3: {
-            embedded_launcher: true,
-        },
-    },
     srcs: [
         "merge_ota.py",
     ],
@@ -357,11 +347,6 @@ python_binary_host {
 
 python_binary_host {
     name: "create_brick_ota",
-    version: {
-        py3: {
-            embedded_launcher: true,
-        },
-    },
     srcs: [
         "create_brick_ota.py",
     ],
@@ -665,3 +650,12 @@ python_test_host {
         unit_test: true,
     },
 }
+
+genrule {
+    name: "otatools_package_releasetools",
+    tools: ["soong_zip"],
+    srcs: ["**/*"],
+    cmd: "find build/make/tools/releasetools -name '*.pyc' -prune -o \\( -type f -o -type l \\) -print | sort > $(genDir)/files.txt && " +
+        "$(location soong_zip) -o $(out) -C build/make/tools -l $(genDir)/files.txt",
+    out: ["otatools_package_releasetools.zip"],
+}
diff --git a/tools/releasetools/add_img_to_target_files.py b/tools/releasetools/add_img_to_target_files.py
index 30a6accf32..180bf159a1 100644
--- a/tools/releasetools/add_img_to_target_files.py
+++ b/tools/releasetools/add_img_to_target_files.py
@@ -572,7 +572,7 @@ def AddCustomImages(output_zip, partition_name, image_list):
 
   default = os.path.join(OPTIONS.input_tmp, "IMAGES", partition_name + ".img")
   assert os.path.exists(default), \
-      "There should be one %s.img" % (partition_name)
+      "Can't find %s for image %s" % (default, partition_name)
   return default
 
 
diff --git a/tools/releasetools/build_image.py b/tools/releasetools/build_image.py
index 464ad9b4cc..08b4d6aa50 100755
--- a/tools/releasetools/build_image.py
+++ b/tools/releasetools/build_image.py
@@ -49,8 +49,8 @@ BYTES_IN_MB = 1024 * 1024
 # Use a fixed timestamp (01/01/2009 00:00:00 UTC) for files when packaging
 # images. (b/24377993, b/80600931)
 FIXED_FILE_TIMESTAMP = int((
-    datetime.datetime(2009, 1, 1, 0, 0, 0, 0, None) -
-    datetime.datetime.utcfromtimestamp(0)).total_seconds())
+    datetime.datetime(2009, 1, 1, 0, 0, 0, 0, datetime.UTC) -
+    datetime.datetime.fromtimestamp(0, datetime.UTC)).total_seconds())
 
 
 class BuildImageError(Exception):
@@ -677,24 +677,31 @@ def TryParseFingerprint(glob_dict: dict):
       glob_dict["fingerprint"] = fingerprint
       return
 
-
-def ImagePropFromGlobalDict(glob_dict, mount_point):
-  """Build an image property dictionary from the global dictionary.
+def TryParseFingerprintAndTimestamp(glob_dict):
+  """Helper function that parses fingerprint and timestamp from the global dictionary.
 
   Args:
     glob_dict: the global dictionary from the build system.
-    mount_point: such as "system", "data" etc.
   """
-  d = {}
   TryParseFingerprint(glob_dict)
 
   # Set fixed timestamp for building the OTA package.
   if "use_fixed_timestamp" in glob_dict:
-    d["timestamp"] = FIXED_FILE_TIMESTAMP
+    glob_dict["timestamp"] = FIXED_FILE_TIMESTAMP
   if "build.prop" in glob_dict:
     timestamp = glob_dict["build.prop"].GetProp("ro.build.date.utc")
     if timestamp:
-      d["timestamp"] = timestamp
+      glob_dict["timestamp"] = timestamp
+
+def ImagePropFromGlobalDict(glob_dict, mount_point):
+  """Build an image property dictionary from the global dictionary.
+
+  Args:
+    glob_dict: the global dictionary from the build system.
+    mount_point: such as "system", "data" etc.
+  """
+  d = {}
+  TryParseFingerprintAndTimestamp(glob_dict)
 
   def copy_prop(src_p, dest_p):
     """Copy a property from the global dictionary.
@@ -730,6 +737,7 @@ def ImagePropFromGlobalDict(glob_dict, mount_point):
       "avb_avbtool",
       "use_dynamic_partition_size",
       "fingerprint",
+      "timestamp",
   )
   for p in common_props:
     copy_prop(p, p)
@@ -992,6 +1000,7 @@ def main(argv):
     # The caller knows the mount point and provides a dictionary needed by
     # BuildImage().
     image_properties = glob_dict
+    TryParseFingerprintAndTimestamp(image_properties)
   else:
     image_filename = os.path.basename(args.out_file)
     mount_point = ""
diff --git a/tools/releasetools/check_partition_sizes.py b/tools/releasetools/check_partition_sizes.py
index 738d77d63e..b469d460b0 100644
--- a/tools/releasetools/check_partition_sizes.py
+++ b/tools/releasetools/check_partition_sizes.py
@@ -58,6 +58,9 @@ class Expression(object):
                   *format_args)
     else:
       msg = "{} is greater than {}:\n{} == {} > {} == {}".format(*format_args)
+      if "SOONG_RUSTC_INCREMENTAL" in os.environ:
+        msg = ("If setting \"SOONG_RUSTC_INCREMENTAL\" try building without it. "
+               + msg)
       if level == logging.ERROR:
         raise RuntimeError(msg)
       else:
diff --git a/tools/releasetools/common.py b/tools/releasetools/common.py
index f04dfb703d..3fc08c668e 100644
--- a/tools/releasetools/common.py
+++ b/tools/releasetools/common.py
@@ -23,7 +23,7 @@ import fnmatch
 import getopt
 import getpass
 import gzip
-import imp
+import importlib.util
 import json
 import logging
 import logging.config
@@ -1410,7 +1410,22 @@ def SharedUidPartitionViolations(uid_dict, partition_groups):
   return errors
 
 
-def RunHostInitVerifier(product_out, partition_map):
+def RunVendoredHostInitVerifier(product_out, partition_map):
+  """Runs vendor host_init_verifier on the init rc files within selected partitions.
+
+  host_init_verifier searches the etc/init path within each selected partition.
+
+  Args:
+    product_out: PRODUCT_OUT directory, containing partition directories.
+    partition_map: A map of partition name -> relative path within product_out.
+  """
+  return RunHostInitVerifier(
+      product_out,
+      partition_map,
+      tool=os.path.join(OPTIONS.vendor_otatools, 'bin', 'host_init_verifier'))
+
+
+def RunHostInitVerifier(product_out, partition_map, tool="host_init_verifier"):
   """Runs host_init_verifier on the init rc files within partitions.
 
   host_init_verifier searches the etc/init path within each partition.
@@ -1418,9 +1433,10 @@ def RunHostInitVerifier(product_out, partition_map):
   Args:
     product_out: PRODUCT_OUT directory, containing partition directories.
     partition_map: A map of partition name -> relative path within product_out.
+    tool: Full path to host_init_verifier or binary name
   """
   allowed_partitions = ("system", "system_ext", "product", "vendor", "odm")
-  cmd = ["host_init_verifier"]
+  cmd = [tool]
   for partition, path in partition_map.items():
     if partition not in allowed_partitions:
       raise ExternalError("Unable to call host_init_verifier for partition %s" %
@@ -2993,7 +3009,7 @@ def ZipWrite(zip_file, filename, arcname=None, perms=0o644,
     os.chmod(filename, perms)
 
     # Use a fixed timestamp so the output is repeatable.
-    # Note: Use of fromtimestamp rather than utcfromtimestamp here is
+    # Note: Use of fromtimestamp without specifying a timezone here is
     # intentional. zip stores datetimes in local time without a time zone
     # attached, so we need "epoch" but in the local time zone to get 2009/01/01
     # in the zip archive.
@@ -3132,16 +3148,19 @@ class DeviceSpecificParams(object):
         return
       try:
         if os.path.isdir(path):
-          info = imp.find_module("releasetools", [path])
-        else:
-          d, f = os.path.split(path)
-          b, x = os.path.splitext(f)
-          if x == ".py":
-            f = b
-          info = imp.find_module(f, [d])
+          path = os.path.join(path, "releasetools")
+          if os.path.isdir(path):
+            path = os.path.join(path, "__init__.py")
+        if not os.path.exists(path) and os.path.exists(path + ".py"):
+          path = path + ".py"
+        spec = importlib.util.spec_from_file_location("device_specific", path)
+        if not spec:
+          raise FileNotFoundError(path)
         logger.info("loaded device-specific extensions from %s", path)
-        self.module = imp.load_module("device_specific", *info)
-      except ImportError:
+        module = importlib.util.module_from_spec(spec)
+        spec.loader.exec_module(module)
+        self.module = module
+      except (ImportError, FileNotFoundError):
         logger.info("unable to load device-specific module; assuming none")
 
   def _DoCall(self, function_name, *args, **kwargs):
diff --git a/tools/releasetools/fsverity_metadata_generator.py b/tools/releasetools/fsverity_metadata_generator.py
index fa7cd3934a..e531cca7db 100644
--- a/tools/releasetools/fsverity_metadata_generator.py
+++ b/tools/releasetools/fsverity_metadata_generator.py
@@ -104,16 +104,13 @@ class FSVerityMetadataGenerator:
     out = subprocess.check_output(cmd, universal_newlines=True).strip()
     return bytes(bytearray.fromhex(out))
 
-  def generate(self, input_file, output_file=None):
+  def generate(self, input_file, output_file):
     if self._signature != 'none':
       if not self._key:
         raise RuntimeError("key must be specified.")
       if not self._cert:
         raise RuntimeError("cert must be specified.")
 
-    if not output_file:
-      output_file = input_file + '.fsv_meta'
-
     with TempDirectory() as temp_dir:
       self._do_generate(input_file, output_file, temp_dir)
 
@@ -229,6 +226,21 @@ if __name__ == '__main__':
       required=True)
   args = p.parse_args(sys.argv[1:])
 
+  output_file = args.output
+  if not output_file:
+    output_file = input_file + '.fsv_meta'
+
+  # remove the output file first, as switching between a file and a symlink can be complicated
+  try:
+    os.remove(output_file)
+  except FileNotFoundError:
+    pass
+
+  if os.path.islink(args.input):
+    target = os.readlink(args.input) + '.fsv_meta'
+    os.symlink(target, output_file)
+    sys.exit(0)
+
   generator = FSVerityMetadataGenerator(args.fsverity_path)
   generator.set_signature(args.signature)
   if args.signature == 'none':
@@ -241,4 +253,4 @@ if __name__ == '__main__':
     generator.set_cert(args.cert)
   generator.set_key_format(args.key_format)
   generator.set_hash_alg(args.hash_alg)
-  generator.generate(args.input, args.output)
+  generator.generate(args.input, output_file)
diff --git a/tools/releasetools/img_from_target_files.py b/tools/releasetools/img_from_target_files.py
index b7a5ad8b74..186257786a 100755
--- a/tools/releasetools/img_from_target_files.py
+++ b/tools/releasetools/img_from_target_files.py
@@ -35,6 +35,10 @@ Flags:
       `filespec` arg in zip2zip's help message). The option can be repeated to
       include multiple entries.
 
+  --exclude <filespec>
+      Don't include these files. If the file is in --additional and --exclude,
+      the file will not be included.
+
 """
 
 from __future__ import print_function
@@ -56,6 +60,7 @@ logger = logging.getLogger(__name__)
 OPTIONS = common.OPTIONS
 
 OPTIONS.additional_entries = []
+OPTIONS.excluded_entries = []
 OPTIONS.bootable_only = False
 OPTIONS.put_super = None
 OPTIONS.put_bootloader = None
@@ -245,6 +250,9 @@ def ImgFromTargetFiles(input_file, output_file):
   # Any additional entries provided by caller.
   entries += OPTIONS.additional_entries
 
+  # Remove any excluded entries
+  entries = [e for e in entries if e not in OPTIONS.excluded_entries]
+
   CopyZipEntries(input_file, output_file, entries)
 
   if rebuild_super:
@@ -258,6 +266,8 @@ def main(argv):
       OPTIONS.bootable_only = True
     elif o == '--additional':
       OPTIONS.additional_entries.append(a)
+    elif o == '--exclude':
+      OPTIONS.excluded_entries.append(a)
     elif o == '--build_super_image':
       OPTIONS.build_super_image = a
     else:
@@ -268,6 +278,7 @@ def main(argv):
                              extra_opts='z',
                              extra_long_opts=[
                                  'additional=',
+                                 'exclude=',
                                  'bootable_zip',
                                  'build_super_image=',
                              ],
diff --git a/tools/releasetools/merge/merge_compatibility_checks.py b/tools/releasetools/merge/merge_compatibility_checks.py
index 8c9993f2e2..80b5caa156 100644
--- a/tools/releasetools/merge/merge_compatibility_checks.py
+++ b/tools/releasetools/merge/merge_compatibility_checks.py
@@ -95,8 +95,19 @@ def CheckShareduidViolation(target_files_dir, partition_map):
 def CheckInitRcFiles(target_files_dir, partition_map):
   """Check for any init.rc issues using host_init_verifier."""
   try:
+    vendor_partitions = set()
+    if OPTIONS.vendor_otatools:
+      vendor_partitions = {"vendor", "odm"}
+      common.RunVendoredHostInitVerifier(
+          product_out=target_files_dir,
+          partition_map={p: partition_map[p] for p in vendor_partitions})
+
     common.RunHostInitVerifier(
-        product_out=target_files_dir, partition_map=partition_map)
+        product_out=target_files_dir,
+        partition_map={
+            p: partition_map[p]
+            for p in partition_map.keys() - vendor_partitions
+        })
   except RuntimeError as err:
     return [str(err)]
   return []
diff --git a/tools/releasetools/merge/merge_target_files.py b/tools/releasetools/merge/merge_target_files.py
index fdba927db9..de4d9a8cc7 100755
--- a/tools/releasetools/merge/merge_target_files.py
+++ b/tools/releasetools/merge/merge_target_files.py
@@ -87,8 +87,8 @@ Usage: merge_target_files [args]
       If provided, rebuilds odm.img or vendor.img to include merged sepolicy
       files. If odm is present then odm is preferred.
 
-  --vendor-otatools otatools.zip
-      If provided, use this otatools.zip when recompiling the odm or vendor
+  --vendor-otatools otatools.zip or directory
+      If provided, use these otatools when recompiling the odm or vendor
       image to include sepolicy.
 
   --keep-tmp
@@ -312,12 +312,9 @@ def rebuild_image_with_sepolicy(target_files_dir):
       '%s recompilation will be performed using the vendor otatools.zip',
       partition_img)
 
-  # Unzip the vendor build's otatools.zip and target-files archive.
-  vendor_otatools_dir = common.MakeTempDir(
-      prefix='merge_target_files_vendor_otatools_')
+  # Unzip the vendor build's target-files archive.
   vendor_target_files_dir = common.MakeTempDir(
       prefix='merge_target_files_vendor_target_files_')
-  common.UnzipToDir(OPTIONS.vendor_otatools, vendor_otatools_dir)
   merge_utils.CollectTargetFiles(
       input_zipfile_or_dir=OPTIONS.vendor_target_files,
       output_dir=vendor_target_files_dir,
@@ -335,7 +332,7 @@ def rebuild_image_with_sepolicy(target_files_dir):
   remove_file_if_exists(
       os.path.join(vendor_target_files_dir, 'IMAGES', partition_img))
   rebuild_partition_command = [
-      os.path.join(vendor_otatools_dir, 'bin', 'add_img_to_target_files'),
+      os.path.join(OPTIONS.vendor_otatools, 'bin', 'add_img_to_target_files'),
       '--verbose',
       '--add_missing',
   ]
@@ -669,6 +666,12 @@ def main():
   if OPTIONS.output_item_list:
     OPTIONS.output_item_list = common.LoadListFromFile(OPTIONS.output_item_list)
 
+  if OPTIONS.vendor_otatools and zipfile.is_zipfile(OPTIONS.vendor_otatools):
+    vendor_otatools_dir = common.MakeTempDir(
+        prefix='merge_target_files_vendor_otatools_')
+    common.UnzipToDir(OPTIONS.vendor_otatools, vendor_otatools_dir)
+    OPTIONS.vendor_otatools = vendor_otatools_dir
+
   if not merge_utils.ValidateConfigLists():
     sys.exit(1)
 
diff --git a/tools/releasetools/merge_ota.py b/tools/releasetools/merge_ota.py
index fb5957a857..e8732a2c52 100644
--- a/tools/releasetools/merge_ota.py
+++ b/tools/releasetools/merge_ota.py
@@ -226,9 +226,21 @@ def main(argv):
     logger.setLevel(logging.INFO)
 
   logger.info(args)
+  if args.java_path:
+    common.OPTIONS.java_path = args.java_path
+
   if args.search_path:
     common.OPTIONS.search_path = args.search_path
 
+  if args.signapk_path:
+    common.OPTIONS.signapk_path = args.signapk_path
+
+  if args.extra_signapk_args:
+    common.OPTIONS.extra_signapk_args = args.extra_signapk_args
+
+  if args.signapk_shared_library_path:
+    common.OPTIONS.signapk_shared_library_path = args.signapk_shared_library_path
+
   metadata_ota = args.packages[-1]
   if args.metadata_ota is not None:
     metadata_ota = args.metadata_ota
diff --git a/tools/releasetools/ota_signing_utils.py b/tools/releasetools/ota_signing_utils.py
index 60c8c94f91..9d04c3bbb5 100644
--- a/tools/releasetools/ota_signing_utils.py
+++ b/tools/releasetools/ota_signing_utils.py
@@ -23,10 +23,18 @@ def ParseSignerArgs(args):
 
 
 def AddSigningArgumentParse(parser: argparse.ArgumentParser):
+  parser.add_argument('--java_path', type=str,
+                      help='Path to JVM if other than default')
   parser.add_argument('--package_key', type=str,
                       help='Paths to private key for signing payload')
   parser.add_argument('--search_path', '--path', type=str,
                       help='Search path for framework/signapk.jar')
+  parser.add_argument('--signapk_path', type=str,
+                      help='Path to signapk.jar, relative to search_path')
+  parser.add_argument('--extra_signapk_args', type=ParseSignerArgs,
+                      help='Extra arguments for signapk.jar')
+  parser.add_argument('--signapk_shared_library_path', type=str,
+                      help='Path to lib64 libraries used by signapk.jar')
   parser.add_argument('--payload_signer', type=str,
                       help='Path to custom payload signer')
   parser.add_argument('--payload_signer_args', type=ParseSignerArgs,
diff --git a/tools/releasetools/sign_target_files_apks.py b/tools/releasetools/sign_target_files_apks.py
index 4ad97e0108..2fa3fb5e89 100755
--- a/tools/releasetools/sign_target_files_apks.py
+++ b/tools/releasetools/sign_target_files_apks.py
@@ -378,6 +378,37 @@ def GetApexKeys(keys_info, key_map):
   return keys_info
 
 
+def GetMicrodroidVbmetaKey(virt_apex_path, avbtool_path):
+  """Extracts the AVB public key from microdroid_vbmeta.img within a virt apex.
+
+  Args:
+    virt_apex_path: The path to the com.android.virt.apex file.
+    avbtool_path: The path to the avbtool executable.
+
+  Returns:
+    The AVB public key (bytes).
+  """
+  # Creates an ApexApkSigner to extract microdroid_vbmeta.img.
+  # No need to set key_passwords/codename_to_api_level_map since
+  # we won't do signing here.
+  apex_signer = apex_utils.ApexApkSigner(
+      virt_apex_path,
+      None,  # key_passwords
+      None)  # codename_to_api_level_map
+  payload_dir = apex_signer.ExtractApexPayload(virt_apex_path)
+  microdroid_vbmeta_image = os.path.join(
+      payload_dir, 'etc', 'fs', 'microdroid_vbmeta.img')
+
+  # Extracts the avb public key from microdroid_vbmeta.img.
+  with tempfile.NamedTemporaryFile() as microdroid_pubkey:
+    common.RunAndCheckOutput([
+        avbtool_path, 'info_image',
+        '--image', microdroid_vbmeta_image,
+        '--output_pubkey', microdroid_pubkey.name])
+    with open(microdroid_pubkey.name, 'rb') as f:
+      return f.read()
+
+
 def GetApkFileInfo(filename, compressed_extension, skipped_prefixes):
   """Returns the APK info based on the given filename.
 
@@ -862,21 +893,34 @@ def ProcessTargetFiles(input_tf_zip: zipfile.ZipFile, output_tf_zip: zipfile.Zip
 
     # Updates pvmfw embedded public key with the virt APEX payload key.
     elif filename == "PREBUILT_IMAGES/pvmfw.img":
-      # Find the name of the virt APEX in the target files.
+      # Find the path of the virt APEX in the target files.
       namelist = input_tf_zip.namelist()
-      apex_gen = (GetApexFilename(f) for f in namelist if IsApexFile(f))
-      virt_apex_re = re.compile("^com\.([^\.]+\.)?android\.virt\.apex$")
-      virt_apex = next((a for a in apex_gen if virt_apex_re.match(a)), None)
-      if not virt_apex:
+      apex_gen = (f for f in namelist if IsApexFile(f))
+      virt_apex_re = re.compile("^.*com\.([^\.]+\.)?android\.virt\.apex$")
+      virt_apex_path = next(
+        (a for a in apex_gen if virt_apex_re.match(a)), None)
+      if not virt_apex_path:
         print("Removing %s from ramdisk: virt APEX not found" % filename)
       else:
-        print("Replacing %s embedded key with %s key" % (filename, virt_apex))
+        print("Replacing %s embedded key with %s key" % (filename,
+                                                         virt_apex_path))
         # Get the current and new embedded keys.
+        virt_apex = GetApexFilename(virt_apex_path)
         payload_key, container_key, sign_tool = apex_keys[virt_apex]
-        new_pubkey_path = common.ExtractAvbPublicKey(
-            misc_info['avb_avbtool'], payload_key)
-        with open(new_pubkey_path, 'rb') as f:
-          new_pubkey = f.read()
+
+        # b/384813199: handles the pre-signed com.android.virt.apex in GSI.
+        if payload_key == 'PRESIGNED':
+          with tempfile.NamedTemporaryFile() as virt_apex_temp_file:
+            virt_apex_temp_file.write(input_tf_zip.read(virt_apex_path))
+            virt_apex_temp_file.flush()
+            new_pubkey = GetMicrodroidVbmetaKey(virt_apex_temp_file.name,
+                                                misc_info['avb_avbtool'])
+        else:
+          new_pubkey_path = common.ExtractAvbPublicKey(
+              misc_info['avb_avbtool'], payload_key)
+          with open(new_pubkey_path, 'rb') as f:
+            new_pubkey = f.read()
+
         pubkey_info = copy.copy(
             input_tf_zip.getinfo("PREBUILT_IMAGES/pvmfw_embedded.avbpubkey"))
         old_pubkey = input_tf_zip.read(pubkey_info.filename)
diff --git a/tools/releasetools/test_common.py b/tools/releasetools/test_common.py
index 89933a00fc..62f425ae6e 100644
--- a/tools/releasetools/test_common.py
+++ b/tools/releasetools/test_common.py
@@ -2157,3 +2157,11 @@ class PartitionBuildPropsTest(test_utils.ReleaseToolsTestCase):
         'google/coral/coral:10/RP1A.200325.001/6337676:user/dev-keys',
         'ro.product.odm.device': 'coral',
     }, copied_props.build_props)
+
+
+class DeviceSpecificParamsTest(test_utils.ReleaseToolsTestCase):
+
+  def test_missingSource(self):
+    common.OPTIONS.device_specific = '/does_not_exist'
+    ds = DeviceSpecificParams()
+    self.assertIsNone(ds.module)
diff --git a/tools/sbom/Android.bp b/tools/sbom/Android.bp
index 4f6d3b7863..d2e6b55189 100644
--- a/tools/sbom/Android.bp
+++ b/tools/sbom/Android.bp
@@ -21,11 +21,6 @@ python_binary_host {
     srcs: [
         "generate-sbom.py",
     ],
-    version: {
-        py3: {
-            embedded_launcher: true,
-        },
-    },
     libs: [
         "metadata_file_proto_py",
         "libprotobuf-python",
@@ -45,11 +40,6 @@ python_binary_host {
     srcs: [
         "gen_sbom.py",
     ],
-    version: {
-        py3: {
-            embedded_launcher: true,
-        },
-    },
     libs: [
         "compliance_metadata",
         "metadata_file_proto_py",
@@ -78,11 +68,6 @@ python_test_host {
     libs: [
         "sbom_lib",
     ],
-    version: {
-        py3: {
-            embedded_launcher: true,
-        },
-    },
     test_suites: ["general-tests"],
 }
 
@@ -95,11 +80,6 @@ python_test_host {
     libs: [
         "sbom_lib",
     ],
-    version: {
-        py3: {
-            embedded_launcher: true,
-        },
-    },
     test_suites: ["general-tests"],
 }
 
@@ -108,11 +88,6 @@ python_binary_host {
     srcs: [
         "generate-sbom-framework_res.py",
     ],
-    version: {
-        py3: {
-            embedded_launcher: true,
-        },
-    },
     libs: [
         "sbom_lib",
     ],
@@ -123,11 +98,8 @@ python_binary_host {
     srcs: [
         "gen_notice_xml.py",
     ],
-    version: {
-        py3: {
-            embedded_launcher: true,
-        },
-    },
     libs: [
+        "compliance_metadata",
+        "metadata_file_proto_py",
     ],
 }
diff --git a/tools/sbom/compliance_metadata.py b/tools/sbom/compliance_metadata.py
index 9910217bbe..2f0b180b0d 100644
--- a/tools/sbom/compliance_metadata.py
+++ b/tools/sbom/compliance_metadata.py
@@ -18,7 +18,7 @@ import sqlite3
 
 class MetadataDb:
   def __init__(self, db):
-    self.conn = sqlite3.connect(':memory')
+    self.conn = sqlite3.connect(':memory:')
     self.conn.row_factory = sqlite3.Row
     with sqlite3.connect(db) as c:
       c.backup(self.conn)
@@ -94,7 +94,7 @@ class MetadataDb:
     cursor.close()
     rows = []
     for m in multi_built_file_modules:
-      built_files = m['installed_file'].strip().split(' ')
+      built_files = m['built_file'].strip().split(' ')
       for f in built_files:
         rows.append((m['module_id'], m['module_name'], m['package'], f))
     self.conn.executemany('insert into module_built_file values (?, ?, ?, ?)', rows)
@@ -123,7 +123,22 @@ class MetadataDb:
 
   def get_installed_files(self):
     # Get all records from table make_metadata, which contains all installed files and corresponding make modules' metadata
-    cursor = self.conn.execute('select installed_file, module_path, is_prebuilt_make_module, product_copy_files, kernel_module_copy_files, is_platform_generated, license_text from make_metadata')
+    cursor = self.conn.execute('select installed_file, module_path, is_soong_module, is_prebuilt_make_module, product_copy_files, kernel_module_copy_files, is_platform_generated, license_text from make_metadata')
+    rows = cursor.fetchall()
+    cursor.close()
+    installed_files_metadata = []
+    for row in rows:
+      metadata = dict(zip(row.keys(), row))
+      installed_files_metadata.append(metadata)
+    return installed_files_metadata
+
+  def get_installed_file_in_dir(self, dir):
+    dir = dir.removesuffix('/')
+    cursor = self.conn.execute(
+        'select installed_file, module_path, is_soong_module, is_prebuilt_make_module, product_copy_files, '
+        '       kernel_module_copy_files, is_platform_generated, license_text '
+        'from make_metadata '
+        'where installed_file like ?', (dir + '/%',))
     rows = cursor.fetchall()
     cursor.close()
     installed_files_metadata = []
diff --git a/tools/sbom/gen_notice_xml.py b/tools/sbom/gen_notice_xml.py
index eaa6e5a74d..8478b1fdd4 100644
--- a/tools/sbom/gen_notice_xml.py
+++ b/tools/sbom/gen_notice_xml.py
@@ -25,6 +25,14 @@ Usage example:
 """
 
 import argparse
+import compliance_metadata
+import google.protobuf.text_format as text_format
+import gzip
+import hashlib
+import metadata_file_pb2
+import os
+import queue
+import xml.sax.saxutils
 
 
 FILE_HEADER = '''\
@@ -39,7 +47,7 @@ FILE_FOOTER = '''\
 def get_args():
   parser = argparse.ArgumentParser()
   parser.add_argument('-v', '--verbose', action='store_true', default=False, help='Print more information.')
-  parser.add_argument('-d', '--debug', action='store_true', default=True, help='Debug mode')
+  parser.add_argument('-d', '--debug', action='store_true', default=False, help='Debug mode')
   parser.add_argument('--output_file', required=True, help='The path of the generated NOTICE.xml.gz file.')
   parser.add_argument('--partition', required=True, help='The name of partition for which the NOTICE.xml.gz is generated.')
   parser.add_argument('--metadata', required=True, help='The path of compliance metadata DB file.')
@@ -55,27 +63,162 @@ def log(*info):
       print(i)
 
 
-def new_file_name_tag(file_metadata, package_name):
+def new_file_name_tag(file_metadata, package_name, content_id):
   file_path = file_metadata['installed_file'].removeprefix(args.product_out)
   lib = 'Android'
   if package_name:
     lib = package_name
-  return f'<file-name contentId="" lib="{lib}">{file_path}</file-name>\n'
-
-
-def new_file_content_tag():
-  pass
-
+  return f'<file-name contentId="{content_id}" lib="{lib}">{file_path}</file-name>\n'
+
+
+def new_file_content_tag(content_id, license_text):
+  escaped_license_text = xml.sax.saxutils.escape(license_text, {'\t': '&#x9;', '\n': '&#xA;', '\r': '&#xD;'})
+  return f'<file-content contentId="{content_id}"><![CDATA[{escaped_license_text}]]></file-content>\n\n'
+
+def get_metadata_file_path(file_metadata):
+  """Search for METADATA file of a package and return its path."""
+  metadata_path = ''
+  if file_metadata['module_path']:
+    metadata_path = file_metadata['module_path']
+  elif file_metadata['kernel_module_copy_files']:
+    metadata_path = os.path.dirname(file_metadata['kernel_module_copy_files'].split(':')[0])
+
+  while metadata_path and not os.path.exists(metadata_path + '/METADATA'):
+    metadata_path = os.path.dirname(metadata_path)
+
+  return metadata_path
+
+def md5_file_content(filepath):
+  h = hashlib.md5()
+  with open(filepath, 'rb') as f:
+    h.update(f.read())
+  return h.hexdigest()
+
+def get_transitive_static_dep_modules(installed_file_metadata, db):
+  # Find all transitive static dep files of the installed files
+  q = queue.Queue()
+  if installed_file_metadata['static_dep_files']:
+    for f in installed_file_metadata['static_dep_files'].split(' '):
+      q.put(f)
+  if installed_file_metadata['whole_static_dep_files']:
+    for f in installed_file_metadata['whole_static_dep_files'].split(' '):
+      q.put(f)
+
+  static_dep_files = {}
+  while not q.empty():
+    dep_file = q.get()
+    if dep_file in static_dep_files:
+      # It has been processed
+      continue
+
+    soong_module = db.get_soong_module_of_built_file(dep_file)
+    if not soong_module:
+      continue
+
+    static_dep_files[dep_file] = soong_module
+
+    if soong_module['static_dep_files']:
+      for f in soong_module['static_dep_files'].split(' '):
+        if f not in static_dep_files:
+          q.put(f)
+    if soong_module['whole_static_dep_files']:
+      for f in soong_module['whole_static_dep_files'].split(' '):
+        if f not in static_dep_files:
+          q.put(f)
+
+  return static_dep_files.values()
 
 def main():
   global args
   args = get_args()
   log('Args:', vars(args))
 
-  with open(args.output_file, 'w', encoding="utf-8") as notice_xml_file:
+  global db
+  db = compliance_metadata.MetadataDb(args.metadata)
+  if args.debug:
+    db.dump_debug_db(os.path.dirname(args.output_file) + '/compliance-metadata-debug.db')
+
+  # NOTICE.xml
+  notice_xml_file_path = os.path.dirname(args.output_file) + '/NOTICE.xml'
+  with open(notice_xml_file_path, 'w', encoding="utf-8") as notice_xml_file:
     notice_xml_file.write(FILE_HEADER)
+
+    all_license_files = {}
+    for metadata in db.get_installed_file_in_dir(args.product_out + '/' + args.partition):
+      soong_module = db.get_soong_module_of_installed_file(metadata['installed_file'])
+      if soong_module:
+        metadata.update(soong_module)
+      else:
+        # For make modules soong_module_type should be empty
+        metadata['soong_module_type'] = ''
+        metadata['static_dep_files'] = ''
+        metadata['whole_static_dep_files'] = ''
+
+      installed_file_metadata_list = [metadata]
+      if args.partition in ('vendor', 'product', 'system_ext'):
+        # For transitive static dependencies of an installed file, make it as if an installed file are
+        # also created from static dependency modules whose licenses are also collected
+        static_dep_modules = get_transitive_static_dep_modules(metadata, db)
+        for dep in static_dep_modules:
+          dep['installed_file'] = metadata['installed_file']
+          installed_file_metadata_list.append(dep)
+
+      for installed_file_metadata in installed_file_metadata_list:
+        package_name = 'Android'
+        licenses = {}
+        if installed_file_metadata['module_path']:
+          metadata_file_path = get_metadata_file_path(installed_file_metadata)
+          if metadata_file_path:
+            proto = metadata_file_pb2.Metadata()
+            with open(metadata_file_path + '/METADATA', 'rt') as f:
+              text_format.Parse(f.read(), proto)
+            if proto.name:
+              package_name = proto.name
+              if proto.third_party and proto.third_party.version:
+                if proto.third_party.version.startswith('v'):
+                  package_name = package_name + '_' + proto.third_party.version
+                else:
+                  package_name = package_name + '_v_' + proto.third_party.version
+            else:
+              package_name = metadata_file_path
+              if metadata_file_path.startswith('external/'):
+                package_name = metadata_file_path.removeprefix('external/')
+
+          # Every license file is in a <file-content> element
+          licenses = db.get_module_licenses(installed_file_metadata.get('name', ''), installed_file_metadata['module_path'])
+
+        # Installed file is from PRODUCT_COPY_FILES
+        elif metadata['product_copy_files']:
+          licenses['unused_name'] = metadata['license_text']
+
+        # Installed file is generated by the platform in builds
+        elif metadata['is_platform_generated']:
+          licenses['unused_name'] = metadata['license_text']
+
+        if licenses:
+          # Each value is a space separated filepath list
+          for license_files in licenses.values():
+            if not license_files:
+              continue
+            for filepath in license_files.split(' '):
+              if filepath not in all_license_files:
+                all_license_files[filepath] = md5_file_content(filepath)
+              md5 = all_license_files[filepath]
+              notice_xml_file.write(new_file_name_tag(installed_file_metadata, package_name, md5))
+
+    # Licenses
+    processed_md5 = []
+    for filepath, md5 in all_license_files.items():
+      if md5 not in processed_md5:
+        processed_md5.append(md5)
+        with open(filepath, 'rt', errors='backslashreplace') as f:
+          notice_xml_file.write(new_file_content_tag(md5, f.read()))
+
     notice_xml_file.write(FILE_FOOTER)
 
+  # NOTICE.xml.gz
+  with open(notice_xml_file_path, 'rb') as notice_xml_file, gzip.open(args.output_file, 'wb') as gz_file:
+    gz_file.writelines(notice_xml_file)
 
 if __name__ == '__main__':
   main()
diff --git a/tools/sbom/gen_sbom.py b/tools/sbom/gen_sbom.py
index 9c3a8be9ef..e875ddb6a7 100644
--- a/tools/sbom/gen_sbom.py
+++ b/tools/sbom/gen_sbom.py
@@ -92,6 +92,7 @@ THIRD_PARTY_IDENTIFIER_TYPES = [
     'SVN',
     'Hg',
     'Darcs',
+    'Piper',
     'VCS',
     'Archive',
     'PrebuiltByAlphabet',
@@ -414,11 +415,13 @@ def save_report(report_file_path, report):
 def installed_file_has_metadata(installed_file_metadata, report):
   installed_file = installed_file_metadata['installed_file']
   module_path = installed_file_metadata['module_path']
+  is_soong_module = installed_file_metadata['is_soong_module']
   product_copy_files = installed_file_metadata['product_copy_files']
   kernel_module_copy_files = installed_file_metadata['kernel_module_copy_files']
   is_platform_generated = installed_file_metadata['is_platform_generated']
 
   if (not module_path and
+      not is_soong_module and
       not product_copy_files and
       not kernel_module_copy_files and
       not is_platform_generated and
@@ -708,8 +711,17 @@ def main():
         'installed_file': dep_file,
         'is_prebuilt_make_module': False
     }
-    file_metadata.update(db.get_soong_module_of_built_file(dep_file))
-    add_package_of_file(file_id, file_metadata, doc, report)
+    soong_module = db.get_soong_module_of_built_file(dep_file)
+    if not soong_module:
+      continue
+    file_metadata.update(soong_module)
+    if is_source_package(file_metadata) or is_prebuilt_package(file_metadata):
+      add_package_of_file(file_id, file_metadata, doc, report)
+    else:
+      # Other static lib files are generated from the platform
+      doc.add_relationship(sbom_data.Relationship(id1=file_id,
+                                                  relationship=sbom_data.RelationshipType.GENERATED_FROM,
+                                                  id2=sbom_data.SPDXID_PLATFORM))
 
     # Add relationships for static deps of static libraries
     add_static_deps_of_file(file_id, file_metadata, doc)
diff --git a/tools/tool_event_logger/Android.bp b/tools/tool_event_logger/Android.bp
index 7a1d2aaa71..d242db8990 100644
--- a/tools/tool_event_logger/Android.bp
+++ b/tools/tool_event_logger/Android.bp
@@ -58,10 +58,4 @@ python_test_host {
         "asuite_cc_client",
         "tool_event_proto",
     ],
-    version: {
-        py3: {
-            embedded_launcher: true,
-            enabled: true,
-        },
-    },
 }
diff --git a/tools/tool_event_logger/OWNERS b/tools/tool_event_logger/OWNERS
index b692c9edf3..e93d20f126 100644
--- a/tools/tool_event_logger/OWNERS
+++ b/tools/tool_event_logger/OWNERS
@@ -1,4 +1,3 @@
 include platform/tools/asuite:/OWNERS
 
 zhuoyao@google.com
-hzalek@google.com
\ No newline at end of file
diff --git a/tools/warn/OWNERS b/tools/warn/OWNERS
index 8551802693..93ccd28b1c 100644
--- a/tools/warn/OWNERS
+++ b/tools/warn/OWNERS
@@ -1 +1 @@
-per-file * = chh@google.com,srhines@google.com
+per-file * =srhines@google.com
```

