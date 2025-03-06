```diff
diff --git a/backported_fixes/Android.bp b/backported_fixes/Android.bp
new file mode 100644
index 0000000000..a20f3fc5f0
--- /dev/null
+++ b/backported_fixes/Android.bp
@@ -0,0 +1,115 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+    default_team: "trendy_team_android_media_reliability",
+}
+
+genrule {
+    name: "applied_backported_fixes",
+    tools: ["applied_backported_fixes_main"],
+    srcs: [":applied_backported_fix_binpbs"],
+    out: ["applied_backported_fixes.prop"],
+    cmd: "$(location applied_backported_fixes_main)" +
+        " -p $(location applied_backported_fixes.prop)" +
+        " $(in)",
+}
+
+java_library {
+    name: "backported_fixes_proto",
+    srcs: [
+        "backported_fixes.proto",
+    ],
+    host_supported: true,
+}
+
+java_library {
+    name: "backported_fixes_common",
+    srcs: ["src/java/com/android/build/backportedfixes/common/*.java"],
+    static_libs: [
+        "backported_fixes_proto",
+        "guava",
+    ],
+    host_supported: true,
+}
+
+java_test_host {
+    name: "backported_fixes_common_test",
+    srcs: ["tests/java/com/android/build/backportedfixes/common/*.java"],
+    static_libs: [
+        "backported_fixes_common",
+        "backported_fixes_proto",
+        "junit",
+        "truth",
+        "truth-liteproto-extension",
+        "truth-proto-extension",
+    ],
+    test_options: {
+        unit_test: true,
+    },
+    test_suites: ["general-tests"],
+}
+
+java_library {
+    name: "applied_backported_fixes_lib",
+    srcs: ["src/java/com/android/build/backportedfixes/*.java"],
+    static_libs: [
+        "backported_fixes_common",
+        "backported_fixes_proto",
+        "jcommander",
+        "guava",
+    ],
+    host_supported: true,
+}
+
+java_binary_host {
+    name: "applied_backported_fixes_main",
+    main_class: "com.android.build.backportedfixes.Main",
+    static_libs: [
+        "applied_backported_fixes_lib",
+    ],
+}
+
+java_test_host {
+    name: "applied_backported_fixes_test",
+    srcs: ["tests/java/com/android/build/backportedfixes/*.java"],
+    static_libs: [
+        "applied_backported_fixes_lib",
+        "backported_fixes_proto",
+        "junit",
+        "truth",
+    ],
+    test_options: {
+        unit_test: true,
+    },
+    test_suites: ["general-tests"],
+}
+
+gensrcs {
+    name: "applied_backported_fix_binpbs",
+    tools: ["aprotoc"],
+    srcs: [
+        "applied_fixes/*.txtpb",
+    ],
+    tool_files: [
+        "backported_fixes.proto",
+    ],
+    output_extension: "binpb",
+    cmd: "$(location aprotoc)  " +
+        " --encode=com.android.build.backportedfixes.BackportedFix" +
+        "  $(location backported_fixes.proto)" +
+        " < $(in)" +
+        " > $(out); echo $(out)",
+}
diff --git a/backported_fixes/OWNERS b/backported_fixes/OWNERS
new file mode 100644
index 0000000000..ac176bf0b4
--- /dev/null
+++ b/backported_fixes/OWNERS
@@ -0,0 +1,3 @@
+essick@google.com
+nchalko@google.com
+portmannc@google.com
diff --git a/core/tasks/tools/update_bootloader_radio_image.mk b/backported_fixes/applied_fixes/ki350037023.txtpb
similarity index 74%
rename from core/tasks/tools/update_bootloader_radio_image.mk
rename to backported_fixes/applied_fixes/ki350037023.txtpb
index 0ebf247213..456a7aec35 100644
--- a/core/tasks/tools/update_bootloader_radio_image.mk
+++ b/backported_fixes/applied_fixes/ki350037023.txtpb
@@ -4,14 +4,16 @@
 # you may not use this file except in compliance with the License.
 # You may obtain a copy of the License at
 #
-#      http:#www.apache.org/licenses/LICENSE-2.0
+#     http://www.apache.org/licenses/LICENSE-2.0
 #
 # Unless required by applicable law or agreed to in writing, software
 # distributed under the License is distributed on an "AS IS" BASIS,
 # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 # See the License for the specific language governing permissions and
 # limitations under the License.
+#
+# proto-file: ../backported_fixes.proto
+# proto-message: BackportedFix
 
-ifeq ($(USES_DEVICE_GOOGLE_ZUMA),true)
-    -include vendor/google_devices/zuma/prebuilts/misc_bins/update_bootloader_radio_image.mk
-endif
+known_issue: 350037023
+alias: 1
diff --git a/backported_fixes/backported_fixes.proto b/backported_fixes/backported_fixes.proto
new file mode 100644
index 0000000000..91618eebd9
--- /dev/null
+++ b/backported_fixes/backported_fixes.proto
@@ -0,0 +1,37 @@
+// Copyright (C) 2024 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+syntax = "proto2";
+
+package com.android.build.backportedfixes;
+
+option java_multiple_files = true;
+
+// A list of backported fixes.
+message BackportedFixes {
+  repeated BackportedFix fixes = 1;
+}
+
+// A known issue approved for reporting Build.getBackportedFixStatus
+message BackportedFix {
+
+  // The issue id from the public bug tracker
+  // https://issuetracker.google.com/issues/{known_issue}
+  optional int64 known_issue = 1;
+  // The alias for the known issue.
+  // 1 - 1023 are valid aliases
+  // Must be unique across all backported fixes.
+  optional int32 alias = 2;
+}
+
diff --git a/backported_fixes/src/java/com/android/build/backportedfixes/Main.java b/backported_fixes/src/java/com/android/build/backportedfixes/Main.java
new file mode 100644
index 0000000000..79148cc838
--- /dev/null
+++ b/backported_fixes/src/java/com/android/build/backportedfixes/Main.java
@@ -0,0 +1,79 @@
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
+import static java.nio.charset.StandardCharsets.UTF_8;
+
+import com.android.build.backportedfixes.common.ClosableCollection;
+import com.android.build.backportedfixes.common.Parser;
+
+import com.beust.jcommander.JCommander;
+import com.beust.jcommander.Parameter;
+import com.beust.jcommander.converters.FileConverter;
+import com.google.common.io.Files;
+
+import java.io.File;
+import java.io.PrintWriter;
+import java.io.Writer;
+import java.util.Arrays;
+import java.util.List;
+import java.util.stream.Collectors;
+
+public final class Main {
+    @Parameter(description = "BackportedFix proto binary files", converter = FileConverter.class,
+            required = true)
+    List<File> fixFiles;
+    @Parameter(description = "The file to write the property value to.",
+            names = {"--property_file", "-p"}, converter = FileConverter.class, required = true)
+    File propertyFile;
+
+    public static void main(String... argv) throws Exception {
+        Main main = new Main();
+        JCommander.newBuilder().addObject(main).build().parse(argv);
+        main.run();
+    }
+
+    Main() {
+    }
+
+    private void run() throws Exception {
+        try (var fixStreams = ClosableCollection.wrap(Parser.getFileInputStreams(fixFiles));
+             var out = Files.newWriter(propertyFile, UTF_8)) {
+            var fixes = Parser.parseBackportedFixes(fixStreams.getCollection());
+            writeFixesAsAliasBitSet(fixes, out);
+        }
+    }
+
+    static void writeFixesAsAliasBitSet(BackportedFixes fixes, Writer out) {
+        PrintWriter printWriter = new PrintWriter(out);
+        printWriter.println("# The following backported fixes have been applied");
+        for (var f : fixes.getFixesList()) {
+            printWriter.printf("# https://issuetracker.google.com/issues/%d with alias %d",
+                    f.getKnownIssue(), f.getAlias());
+            printWriter.println();
+        }
+        var bsArray = Parser.getBitSetArray(
+                fixes.getFixesList().stream().mapToInt(BackportedFix::getAlias).toArray());
+        String bsString = Arrays.stream(bsArray).mapToObj(Long::toString).collect(
+                Collectors.joining(","));
+        printWriter.printf("ro.build.backported_fixes.alias_bitset.long_list=%s", bsString);
+        printWriter.println();
+        if (printWriter.checkError()) {
+            throw new RuntimeException("There was an error writing to " + out.toString());
+        }
+    }
+}
diff --git a/backported_fixes/src/java/com/android/build/backportedfixes/common/ClosableCollection.java b/backported_fixes/src/java/com/android/build/backportedfixes/common/ClosableCollection.java
new file mode 100644
index 0000000000..75b6730c88
--- /dev/null
+++ b/backported_fixes/src/java/com/android/build/backportedfixes/common/ClosableCollection.java
@@ -0,0 +1,67 @@
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
+package com.android.build.backportedfixes.common;
+
+import com.google.common.collect.ImmutableList;
+
+import java.util.ArrayList;
+import java.util.Collection;
+
+/** An AutoCloseable holder for a collection of AutoCloseables. */
+public final class ClosableCollection<T extends AutoCloseable, C extends Collection<T>> implements
+        AutoCloseable {
+    C source;
+
+    /** Makes the collection AutoCloseable. */
+    public static <T extends AutoCloseable, C extends Collection<T>> ClosableCollection<T, C> wrap(
+            C source) {
+        return new ClosableCollection<>(source);
+    }
+
+    private ClosableCollection(C source) {
+        this.source = source;
+    }
+
+    /** Get the source collection. */
+    public C getCollection() {
+        return source;
+    }
+
+    /**
+     * Closes each item in the collection.
+     *
+     * @throws Exception if any close throws an an exception, a new exception is thrown with
+     *                   all the exceptions thrown closing the streams added as a suppressed
+     *                   exceptions.
+     */
+    @Override
+    public void close() throws Exception {
+        var failures = new ArrayList<Exception>();
+        for (T t : source) {
+            try {
+                t.close();
+            } catch (Exception e) {
+                failures.add(e);
+            }
+        }
+        if (!failures.isEmpty()) {
+            Exception e = new Exception(
+                    "%d of %d failed while closing".formatted(failures.size(), source.size()));
+            failures.forEach(e::addSuppressed);
+            throw e;
+        }
+    }
+}
diff --git a/backported_fixes/src/java/com/android/build/backportedfixes/common/Parser.java b/backported_fixes/src/java/com/android/build/backportedfixes/common/Parser.java
new file mode 100644
index 0000000000..6b08b8f3b3
--- /dev/null
+++ b/backported_fixes/src/java/com/android/build/backportedfixes/common/Parser.java
@@ -0,0 +1,71 @@
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
+package com.android.build.backportedfixes.common;
+
+import com.android.build.backportedfixes.BackportedFix;
+import com.android.build.backportedfixes.BackportedFixes;
+
+import com.google.common.collect.ImmutableList;
+
+import java.io.File;
+import java.io.FileInputStream;
+import java.io.FileNotFoundException;
+import java.io.IOException;
+import java.io.InputStream;
+import java.util.BitSet;
+import java.util.List;
+
+
+/** Static utilities for working with {@link BackportedFixes}. */
+public final class Parser {
+
+    /** Creates list of FileInputStreams for a list of files. */
+    public static ImmutableList<FileInputStream> getFileInputStreams(List<File> fixFiles) throws
+            FileNotFoundException {
+        var streams = ImmutableList.<FileInputStream>builder();
+        for (var f : fixFiles) {
+            streams.add(new FileInputStream(f));
+        }
+        return streams.build();
+    }
+
+    /** Converts a list of backported fix aliases into a long array representing a {@link BitSet} */
+    public static long[] getBitSetArray(int[] aliases) {
+        BitSet bs = new BitSet();
+        for (int a : aliases) {
+            bs.set(a);
+        }
+        return bs.toLongArray();
+    }
+
+    /**
+     * Creates a {@link BackportedFixes} from a list of {@link BackportedFix} binary proto streams.
+     */
+    public static BackportedFixes parseBackportedFixes(List<? extends InputStream> fixStreams)
+            throws
+            IOException {
+        var fixes = BackportedFixes.newBuilder();
+        for (var s : fixStreams) {
+            BackportedFix fix = BackportedFix.parseFrom(s);
+            fixes.addFixes(fix);
+            s.close();
+        }
+        return fixes.build();
+    }
+
+    private Parser() {
+    }
+}
diff --git a/backported_fixes/tests/java/com/android/build/backportedfixes/MainTest.java b/backported_fixes/tests/java/com/android/build/backportedfixes/MainTest.java
new file mode 100644
index 0000000000..84061e1698
--- /dev/null
+++ b/backported_fixes/tests/java/com/android/build/backportedfixes/MainTest.java
@@ -0,0 +1,64 @@
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
+import java.io.PrintWriter;
+import java.io.StringWriter;
+
+/** Tests for {@link Main}. */
+public class MainTest {
+
+
+    @Test
+    public void writeFixesAsAliasBitSet_default() {
+        BackportedFixes fixes = BackportedFixes.newBuilder().build();
+        var result = new StringWriter();
+
+        Main.writeFixesAsAliasBitSet(fixes, new PrintWriter(result));
+
+        Truth.assertThat(result.toString())
+                .isEqualTo("""
+                        # The following backported fixes have been applied
+                        ro.build.backported_fixes.alias_bitset.long_list=
+                        """);
+    }
+
+    @Test
+    public void writeFixesAsAliasBitSet_some() {
+        BackportedFixes fixes = BackportedFixes.newBuilder()
+                .addFixes(BackportedFix.newBuilder().setKnownIssue(1234L).setAlias(1))
+                .addFixes(BackportedFix.newBuilder().setKnownIssue(3L).setAlias(65))
+                .addFixes(BackportedFix.newBuilder().setKnownIssue(4L).setAlias(67))
+                .build();
+        var result = new StringWriter();
+
+        Main.writeFixesAsAliasBitSet(fixes, new PrintWriter(result));
+
+        Truth.assertThat(result.toString())
+                .isEqualTo("""
+                        # The following backported fixes have been applied
+                        # https://issuetracker.google.com/issues/1234 with alias 1
+                        # https://issuetracker.google.com/issues/3 with alias 65
+                        # https://issuetracker.google.com/issues/4 with alias 67
+                        ro.build.backported_fixes.alias_bitset.long_list=2,10
+                        """);
+    }
+}
diff --git a/backported_fixes/tests/java/com/android/build/backportedfixes/common/CloseableCollectionTest.java b/backported_fixes/tests/java/com/android/build/backportedfixes/common/CloseableCollectionTest.java
new file mode 100644
index 0000000000..d3d84a8d63
--- /dev/null
+++ b/backported_fixes/tests/java/com/android/build/backportedfixes/common/CloseableCollectionTest.java
@@ -0,0 +1,91 @@
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
+package com.android.build.backportedfixes.common;
+
+import com.google.common.collect.ImmutableSet;
+import com.google.common.truth.Correspondence;
+import com.google.common.truth.Truth;
+
+import org.junit.Test;
+
+/** Tests for {@link ClosableCollection}. */
+public class CloseableCollectionTest {
+
+    private static class FakeCloseable implements AutoCloseable {
+        private final boolean throwOnClose;
+        private final String name;
+
+
+        private boolean isClosed = false;
+
+        private FakeCloseable(String name, boolean throwOnClose) {
+            this.name = name;
+            this.throwOnClose = throwOnClose;
+
+        }
+
+        private static FakeCloseable named(String name) {
+            return new FakeCloseable(name, false);
+        }
+
+        private static FakeCloseable failing(String name) {
+            return new FakeCloseable(name, true);
+        }
+
+        public boolean isClosed() {
+            return isClosed;
+        }
+
+        @Override
+        public void close() throws Exception {
+            if (throwOnClose) {
+                throw new Exception(name + " close failed");
+            }
+            isClosed = true;
+        }
+    }
+
+
+    @Test
+    public void bothClosed() throws Exception {
+        var c = ImmutableSet.of(FakeCloseable.named("foo"), FakeCloseable.named("bar"));
+        try (var cc = ClosableCollection.wrap(c);) {
+            Truth.assertThat(cc.getCollection()).isSameInstanceAs(c);
+        }
+        Truth.assertThat(c)
+                .comparingElementsUsing(
+                        Correspondence.transforming(FakeCloseable::isClosed, "is closed"))
+                .containsExactly(true, true);
+    }
+
+    @Test
+    public void bothFailed() {
+        var c = ImmutableSet.of(FakeCloseable.failing("foo"), FakeCloseable.failing("bar"));
+
+        try {
+            try (var cc = ClosableCollection.wrap(c);) {
+                Truth.assertThat(cc.getCollection()).isSameInstanceAs(c);
+            }
+        } catch (Exception e) {
+            Truth.assertThat(e).hasMessageThat().isEqualTo("2 of 2 failed while closing");
+            Truth.assertThat(e.getSuppressed())
+                    .asList()
+                    .comparingElementsUsing(
+                            Correspondence.transforming(Exception::getMessage, "has a message of "))
+                    .containsExactly("foo close failed", "bar close failed");
+        }
+    }
+}
diff --git a/backported_fixes/tests/java/com/android/build/backportedfixes/common/ParserTest.java b/backported_fixes/tests/java/com/android/build/backportedfixes/common/ParserTest.java
new file mode 100644
index 0000000000..444e6942b3
--- /dev/null
+++ b/backported_fixes/tests/java/com/android/build/backportedfixes/common/ParserTest.java
@@ -0,0 +1,94 @@
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
+package com.android.build.backportedfixes.common;
+
+import static com.google.common.truth.Truth.assertThat;
+import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
+
+import com.android.build.backportedfixes.BackportedFix;
+import com.android.build.backportedfixes.BackportedFixes;
+
+import com.google.common.collect.ImmutableList;
+
+import org.junit.Test;
+
+import java.io.ByteArrayInputStream;
+import java.io.IOException;
+import java.nio.file.Files;
+
+/** Tests for {@link Parser}.*/
+public class ParserTest {
+
+    @Test
+    public void getFileInputStreams() throws IOException {
+        var results = Parser.getFileInputStreams(
+                ImmutableList.of(Files.createTempFile("test", null).toFile()));
+        assertThat(results).isNotEmpty();
+    }
+
+
+    @Test
+    public void getBitSetArray_empty() {
+        var results = Parser.getBitSetArray(new int[]{});
+        assertThat(results).isEmpty();
+    }
+
+    @Test
+    public void getBitSetArray_2_3_64() {
+        var results = Parser.getBitSetArray(new int[]{2,3,64});
+        assertThat(results).asList().containsExactly(12L,1L).inOrder();
+    }
+
+    @Test
+    public void parseBackportedFixes_empty() throws IOException {
+        var result = Parser.parseBackportedFixes(ImmutableList.of());
+        assertThat(result).isEqualTo(BackportedFixes.getDefaultInstance());
+    }
+
+    @Test
+    public void parseBackportedFixes_oneBlank() throws IOException {
+        var result = Parser.parseBackportedFixes(
+                ImmutableList.of(inputStream(BackportedFix.getDefaultInstance())));
+
+        assertThat(result).isEqualTo(
+                BackportedFixes.newBuilder()
+                        .addFixes(BackportedFix.getDefaultInstance())
+                        .build());
+    }
+
+    @Test
+    public void parseBackportedFixes_two() throws IOException {
+        BackportedFix ki123 = BackportedFix.newBuilder()
+                .setKnownIssue(123)
+                .setAlias(1)
+                .build();
+        BackportedFix ki456 = BackportedFix.newBuilder()
+                .setKnownIssue(456)
+                .setAlias(2)
+                .build();
+        var result = Parser.parseBackportedFixes(
+                ImmutableList.of(inputStream(ki123), inputStream(ki456)));
+        assertThat(result).isEqualTo(
+                BackportedFixes.newBuilder()
+                        .addFixes(ki123)
+                        .addFixes(ki456)
+                        .build());
+    }
+
+    private static ByteArrayInputStream inputStream(BackportedFix f) {
+        return new ByteArrayInputStream(f.toByteArray());
+    }
+}
diff --git a/ci/Android.bp b/ci/Android.bp
index 6d4ac35517..3f28be4494 100644
--- a/ci/Android.bp
+++ b/ci/Android.bp
@@ -25,7 +25,7 @@ python_test_host {
         "build_test_suites_test.py",
     ],
     libs: [
-        "build_test_suites",
+        "build_test_suites_lib",
         "pyfakefs",
         "ci_test_lib",
     ],
@@ -56,7 +56,7 @@ python_test_host {
         "build_test_suites_local_test.py",
     ],
     libs: [
-        "build_test_suites",
+        "build_test_suites_lib",
         "pyfakefs",
         "ci_test_lib",
     ],
@@ -79,7 +79,7 @@ python_test_host {
         "optimized_targets_test.py",
     ],
     libs: [
-        "build_test_suites",
+        "build_test_suites_lib",
         "pyfakefs",
     ],
     test_options: {
@@ -95,13 +95,36 @@ python_test_host {
     },
 }
 
-python_library_host {
+python_binary_host {
     name: "build_test_suites",
     srcs: [
         "build_test_suites.py",
         "optimized_targets.py",
         "test_mapping_module_retriever.py",
         "build_context.py",
+        "test_discovery_agent.py",
+        "metrics_agent.py",
+        "buildbot.py",
+    ],
+    main: "build_test_suites.py",
+    libs: [
+        "soong-metrics-proto-py",
+    ],
+}
+
+python_library_host {
+    name: "build_test_suites_lib",
+    srcs: [
+        "build_test_suites.py",
+        "optimized_targets.py",
+        "test_mapping_module_retriever.py",
+        "build_context.py",
+        "test_discovery_agent.py",
+        "metrics_agent.py",
+        "buildbot.py",
+    ],
+    libs: [
+        "soong-metrics-proto-py",
     ],
 }
 
diff --git a/ci/build_context.py b/ci/build_context.py
index cc48d53992..c7a1defb57 100644
--- a/ci/build_context.py
+++ b/ci/build_context.py
@@ -47,6 +47,9 @@ class BuildContext:
       self.is_test_mapping = False
       self.test_mapping_test_groups = set()
       self.file_download_options = set()
+      self.name = test_info_dict.get('name')
+      self.command = test_info_dict.get('command')
+      self.extra_options = test_info_dict.get('extraOptions')
       for opt in test_info_dict.get('extraOptions', []):
         key = opt.get('key')
         if key == 'test-mapping-test-group':
diff --git a/ci/build_device_and_tests b/ci/build_device_and_tests
new file mode 100755
index 0000000000..63d3ce3519
--- /dev/null
+++ b/ci/build_device_and_tests
@@ -0,0 +1,19 @@
+#!/usr/bin/env bash
+#
+# Copyright 2024, The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+set -euo pipefail
+
+build/soong/soong_ui.bash --make-mode build_test_suites
+$(build/soong/soong_ui.bash --dumpvar-mode HOST_OUT)/bin/build_test_suites --device-build $@
diff --git a/ci/build_metadata b/ci/build_metadata
index a8eb65dd36..cd011c8679 100755
--- a/ci/build_metadata
+++ b/ci/build_metadata
@@ -20,6 +20,9 @@ export TARGET_PRODUCT=aosp_arm64
 export TARGET_RELEASE=trunk_staging
 export TARGET_BUILD_VARIANT=eng
 
-build/soong/bin/m dist \
+TARGETS=(
     all_teams
+    release_config_metadata
+)
 
+build/soong/bin/m dist ${TARGETS[@]}
diff --git a/ci/build_test_suites b/ci/build_test_suites
index 5aaf2f49b7..74470a8e16 100755
--- a/ci/build_test_suites
+++ b/ci/build_test_suites
@@ -1,4 +1,4 @@
-#!prebuilts/build-tools/linux-x86/bin/py3-cmd -B
+#!/usr/bin/env bash
 #
 # Copyright 2024, The Android Open Source Project
 #
@@ -13,8 +13,7 @@
 # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 # See the License for the specific language governing permissions and
 # limitations under the License.
+set -euo pipefail
 
-import build_test_suites
-import sys
-
-build_test_suites.main(sys.argv[1:])
+build/soong/soong_ui.bash --make-mode build_test_suites
+$(build/soong/soong_ui.bash --dumpvar-mode HOST_OUT)/bin/build_test_suites $@
diff --git a/ci/build_test_suites.py b/ci/build_test_suites.py
index b8c4a385e0..b67ecec09a 100644
--- a/ci/build_test_suites.py
+++ b/ci/build_test_suites.py
@@ -20,16 +20,20 @@ import json
 import logging
 import os
 import pathlib
+import re
 import subprocess
 import sys
 from typing import Callable
 from build_context import BuildContext
 import optimized_targets
+import metrics_agent
+import test_discovery_agent
 
 
-REQUIRED_ENV_VARS = frozenset(['TARGET_PRODUCT', 'TARGET_RELEASE', 'TOP'])
+REQUIRED_ENV_VARS = frozenset(['TARGET_PRODUCT', 'TARGET_RELEASE', 'TOP', 'DIST_DIR'])
 SOONG_UI_EXE_REL_PATH = 'build/soong/soong_ui.bash'
 LOG_PATH = 'logs/build_test_suites.log'
+REQUIRED_BUILD_TARGETS = frozenset(['dist'])
 
 
 class Error(Exception):
@@ -70,12 +74,46 @@ class BuildPlanner:
 
     build_targets = set()
     packaging_commands_getters = []
-    for target in self.args.extra_targets:
-      if self._unused_target_exclusion_enabled(
-          target
-      ) and not self.build_context.build_target_used(target):
-        continue
-
+    # In order to roll optimizations out differently between test suites and
+    # device builds, we have separate flags.
+    if (
+        'test_suites_zip_test_discovery'
+        in self.build_context.enabled_build_features
+        and not self.args.device_build
+    ) or (
+        'device_zip_test_discovery'
+        in self.build_context.enabled_build_features
+        and self.args.device_build
+    ):
+      preliminary_build_targets = self._collect_preliminary_build_targets()
+    else:
+      preliminary_build_targets = self._legacy_collect_preliminary_build_targets()
+
+      # Keep reporting metrics when test discovery is disabled.
+      # To be removed once test discovery is fully rolled out.
+      optimization_rationale = ''
+      test_discovery_zip_regexes = set()
+      try:
+        test_discovery_zip_regexes = self._get_test_discovery_zip_regexes()
+        logging.info(f'Discovered test discovery regexes: {test_discovery_zip_regexes}')
+      except test_discovery_agent.TestDiscoveryError as e:
+        optimization_rationale = e.message
+        logging.warning(f'Unable to perform test discovery: {optimization_rationale}')
+
+      for target in self.args.extra_targets:
+        if optimization_rationale:
+          get_metrics_agent().report_unoptimized_target(target, optimization_rationale)
+          continue
+        try:
+          regex = r'\b(%s.*)\b' % re.escape(target)
+          if any(re.search(regex, opt) for opt in test_discovery_zip_regexes):
+            get_metrics_agent().report_unoptimized_target(target, 'Test artifact used.')
+            continue
+          get_metrics_agent().report_optimized_target(target)
+        except Exception as e:
+          logging.error(f'unable to parse test discovery output: {repr(e)}')
+
+    for target in preliminary_build_targets:
       target_optimizer_getter = self.target_optimizations.get(target, None)
       if not target_optimizer_getter:
         build_targets.add(target)
@@ -91,12 +129,85 @@ class BuildPlanner:
 
     return BuildPlan(build_targets, packaging_commands_getters)
 
+  def _collect_preliminary_build_targets(self):
+    build_targets = set()
+    try:
+      test_discovery_zip_regexes = self._get_test_discovery_zip_regexes()
+      logging.info(f'Discovered test discovery regexes: {test_discovery_zip_regexes}')
+    except test_discovery_agent.TestDiscoveryError as e:
+      optimization_rationale = e.message
+      logging.warning(f'Unable to perform test discovery: {optimization_rationale}')
+
+      for target in self.args.extra_targets:
+        get_metrics_agent().report_unoptimized_target(target, optimization_rationale)
+      return self._legacy_collect_preliminary_build_targets()
+
+    for target in self.args.extra_targets:
+      if target in REQUIRED_BUILD_TARGETS:
+        build_targets.add(target)
+        continue
+
+      regex = r'\b(%s.*)\b' % re.escape(target)
+      for opt in test_discovery_zip_regexes:
+        try:
+          if re.search(regex, opt):
+            get_metrics_agent().report_unoptimized_target(target, 'Test artifact used.')
+            build_targets.add(target)
+            continue
+          get_metrics_agent().report_optimized_target(target)
+        except Exception as e:
+          # In case of exception report as unoptimized
+          build_targets.add(target)
+          get_metrics_agent().report_unoptimized_target(target, f'Error in parsing test discovery output for {target}: {repr(e)}')
+          logging.error(f'unable to parse test discovery output: {repr(e)}')
+
+    return build_targets
+
+  def _legacy_collect_preliminary_build_targets(self):
+    build_targets = set()
+    for target in self.args.extra_targets:
+      if self._unused_target_exclusion_enabled(
+          target
+      ) and not self.build_context.build_target_used(target):
+        continue
+
+      build_targets.add(target)
+    return build_targets
+
   def _unused_target_exclusion_enabled(self, target: str) -> bool:
     return (
         f'{target}_unused_exclusion'
         in self.build_context.enabled_build_features
     )
 
+  def _get_test_discovery_zip_regexes(self) -> set[str]:
+    build_target_regexes = set()
+    for test_info in self.build_context.test_infos:
+      tf_command = self._build_tf_command(test_info)
+      discovery_agent = test_discovery_agent.TestDiscoveryAgent(tradefed_args=tf_command)
+      for regex in discovery_agent.discover_test_zip_regexes():
+        build_target_regexes.add(regex)
+    return build_target_regexes
+
+
+  def _build_tf_command(self, test_info) -> list[str]:
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
+
+    return command
 
 @dataclass(frozen=True)
 class BuildPlan:
@@ -113,19 +224,27 @@ def build_test_suites(argv: list[str]) -> int:
   Returns:
     The exit code of the build.
   """
-  args = parse_args(argv)
-  check_required_env()
-  build_context = BuildContext(load_build_context())
-  build_planner = BuildPlanner(
-      build_context, args, optimized_targets.OPTIMIZED_BUILD_TARGETS
-  )
-  build_plan = build_planner.create_build_plan()
+  get_metrics_agent().analysis_start()
+  try:
+    args = parse_args(argv)
+    check_required_env()
+    build_context = BuildContext(load_build_context())
+    build_planner = BuildPlanner(
+        build_context, args, optimized_targets.OPTIMIZED_BUILD_TARGETS
+    )
+    build_plan = build_planner.create_build_plan()
+  except:
+    raise
+  finally:
+    get_metrics_agent().analysis_end()
 
   try:
     execute_build_plan(build_plan)
   except BuildFailureError as e:
     logging.error('Build command failed! Check build_log for details.')
     return e.return_code
+  finally:
+    get_metrics_agent().end_reporting()
 
   return 0
 
@@ -136,6 +255,11 @@ def parse_args(argv: list[str]) -> argparse.Namespace:
   argparser.add_argument(
       'extra_targets', nargs='*', help='Extra test suites to build.'
   )
+  argparser.add_argument(
+      '--device-build',
+      action='store_true',
+      help='Flag to indicate running a device build.',
+  )
 
   return argparser.parse_args(argv)
 
@@ -183,12 +307,15 @@ def execute_build_plan(build_plan: BuildPlan):
   except subprocess.CalledProcessError as e:
     raise BuildFailureError(e.returncode) from e
 
-  for packaging_commands_getter in build_plan.packaging_commands_getters:
-    try:
+  get_metrics_agent().packaging_start()
+  try:
+    for packaging_commands_getter in build_plan.packaging_commands_getters:
       for packaging_command in packaging_commands_getter():
         run_command(packaging_command)
-    except subprocess.CalledProcessError as e:
-      raise BuildFailureError(e.returncode) from e
+  except subprocess.CalledProcessError as e:
+    raise BuildFailureError(e.returncode) from e
+  finally:
+    get_metrics_agent().packaging_end()
 
 
 def get_top() -> pathlib.Path:
@@ -199,6 +326,10 @@ def run_command(args: list[str], stdout=None):
   subprocess.run(args=args, check=True, stdout=stdout)
 
 
+def get_metrics_agent():
+  return metrics_agent.MetricsAgent.instance()
+
+
 def main(argv):
   dist_dir = os.environ.get('DIST_DIR')
   if dist_dir:
@@ -209,3 +340,7 @@ def main(argv):
         filename=log_file,
     )
   sys.exit(build_test_suites(argv))
+
+
+if __name__ == '__main__':
+  main(sys.argv[1:])
diff --git a/ci/build_test_suites_test.py b/ci/build_test_suites_test.py
index 2afaab7711..29d268e994 100644
--- a/ci/build_test_suites_test.py
+++ b/ci/build_test_suites_test.py
@@ -37,6 +37,8 @@ import build_test_suites
 import ci_test_lib
 import optimized_targets
 from pyfakefs import fake_filesystem_unittest
+import metrics_agent
+import test_discovery_agent
 
 
 class BuildTestSuitesTest(fake_filesystem_unittest.TestCase):
@@ -52,6 +54,10 @@ class BuildTestSuitesTest(fake_filesystem_unittest.TestCase):
     self.addCleanup(subprocess_run_patcher.stop)
     self.mock_subprocess_run = subprocess_run_patcher.start()
 
+    metrics_agent_finalize_patcher = mock.patch('metrics_agent.MetricsAgent.end_reporting')
+    self.addCleanup(metrics_agent_finalize_patcher.stop)
+    self.mock_metrics_agent_end = metrics_agent_finalize_patcher.start()
+
     self._setup_working_build_env()
 
   def test_missing_target_release_env_var_raises(self):
@@ -72,6 +78,12 @@ class BuildTestSuitesTest(fake_filesystem_unittest.TestCase):
     with self.assert_raises_word(build_test_suites.Error, 'TOP'):
       build_test_suites.main([])
 
+  def test_missing_dist_dir_env_var_raises(self):
+    del os.environ['DIST_DIR']
+
+    with self.assert_raises_word(build_test_suites.Error, 'DIST_DIR'):
+      build_test_suites.main([])
+
   def test_invalid_arg_raises(self):
     invalid_args = ['--invalid_arg']
 
@@ -108,6 +120,9 @@ class BuildTestSuitesTest(fake_filesystem_unittest.TestCase):
     self.soong_ui_dir = self.fake_top.joinpath('build/soong')
     self.soong_ui_dir.mkdir(parents=True, exist_ok=True)
 
+    self.logs_dir = self.fake_top.joinpath('dist/logs')
+    self.logs_dir.mkdir(parents=True, exist_ok=True)
+
     self.soong_ui = self.soong_ui_dir.joinpath('soong_ui.bash')
     self.soong_ui.touch()
 
@@ -115,6 +130,7 @@ class BuildTestSuitesTest(fake_filesystem_unittest.TestCase):
         'TARGET_RELEASE': 'release',
         'TARGET_PRODUCT': 'product',
         'TOP': str(self.fake_top),
+        'DIST_DIR': str(self.fake_top.joinpath('dist')),
     })
 
     self.mock_subprocess_run.return_value = 0
@@ -256,6 +272,12 @@ class BuildPlannerTest(unittest.TestCase):
     def get_enabled_flag(self):
       return f'{self.target}_enabled'
 
+  def setUp(self):
+    test_discovery_agent_patcher = mock.patch('test_discovery_agent.TestDiscoveryAgent.discover_test_zip_regexes')
+    self.addCleanup(test_discovery_agent_patcher.stop)
+    self.mock_test_discovery_agent_end = test_discovery_agent_patcher.start()
+
+
   def test_build_optimization_off_builds_everything(self):
     build_targets = {'target_1', 'target_2'}
     build_planner = self.create_build_planner(
diff --git a/ci/metrics_agent.py b/ci/metrics_agent.py
new file mode 100644
index 0000000000..bc2479eab6
--- /dev/null
+++ b/ci/metrics_agent.py
@@ -0,0 +1,116 @@
+# Copyright 2024, The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+"""MetricsAgent is a singleton class that collects metrics for optimized build."""
+
+from enum import Enum
+import time
+import metrics_pb2
+import os
+import logging
+
+
+class MetricsAgent:
+  _SOONG_METRICS_PATH = 'logs/soong_metrics'
+  _DIST_DIR = 'DIST_DIR'
+  _instance = None
+
+  def __init__(self):
+    raise RuntimeError(
+        'MetricsAgent cannot be instantialized, use instance() instead'
+    )
+
+  @classmethod
+  def instance(cls):
+    if not cls._instance:
+      cls._instance = cls.__new__(cls)
+      cls._instance._proto = metrics_pb2.OptimizedBuildMetrics()
+      cls._instance._init_proto()
+      cls._instance._target_results = dict()
+
+    return cls._instance
+
+  def _init_proto(self):
+    self._proto.analysis_perf.name = 'Optimized build analysis time.'
+    self._proto.packaging_perf.name = 'Optimized build total packaging time.'
+
+  def analysis_start(self):
+    self._proto.analysis_perf.start_time = time.time_ns()
+
+  def analysis_end(self):
+    self._proto.analysis_perf.real_time = (
+        time.time_ns() - self._proto.analysis_perf.start_time
+    )
+
+  def packaging_start(self):
+    self._proto.packaging_perf.start_time = time.time_ns()
+
+  def packaging_end(self):
+    self._proto.packaging_perf.real_time = (
+        time.time_ns() - self._proto.packaging_perf.start_time
+    )
+
+  def report_optimized_target(self, name: str):
+    target_result = metrics_pb2.OptimizedBuildMetrics.TargetOptimizationResult()
+    target_result.name = name
+    target_result.optimized = True
+    self._target_results[name] = target_result
+
+  def report_unoptimized_target(self, name: str, optimization_rationale: str):
+    target_result = metrics_pb2.OptimizedBuildMetrics.TargetOptimizationResult()
+    target_result.name = name
+    target_result.optimization_rationale = optimization_rationale
+    target_result.optimized = False
+    self._target_results[name] = target_result
+
+  def target_packaging_start(self, name: str):
+    target_result = self._target_results.get(name)
+    target_result.packaging_perf.start_time = time.time_ns()
+    self._target_results[name] = target_result
+
+  def target_packaging_end(self, name: str):
+    target_result = self._target_results.get(name)
+    target_result.packaging_perf.real_time = (
+        time.time_ns() - target_result.packaging_perf.start_time
+    )
+
+  def add_target_artifact(
+      self,
+      target_name: str,
+      artifact_name: str,
+      size: int,
+      included_modules: set[str],
+  ):
+    target_result = self.target_results.get(target_name)
+    artifact = (
+        metrics_pb2.OptimizedBuildMetrics.TargetOptimizationResult.OutputArtifact()
+    )
+    artifact.name = artifact_name
+    artifact.size = size
+    for module in included_modules:
+      artifact.included_modules.add(module)
+    target_result.output_artifacts.add(artifact)
+
+  def end_reporting(self):
+    for target_result in self._target_results.values():
+      self._proto.target_result.append(target_result)
+    soong_metrics_proto = metrics_pb2.MetricsBase()
+    # Read in existing metrics that should have been written out by the soong
+    # build command so that we don't overwrite them.
+    with open(os.path.join(os.environ[self._DIST_DIR], self._SOONG_METRICS_PATH), 'rb') as f:
+      soong_metrics_proto.ParseFromString(f.read())
+    soong_metrics_proto.optimized_build_metrics.CopyFrom(self._proto)
+    logging.info(soong_metrics_proto)
+    with open(os.path.join(os.environ[self._DIST_DIR], self._SOONG_METRICS_PATH), 'wb') as f:
+      f.write(soong_metrics_proto.SerializeToString())
diff --git a/ci/test_discovery_agent.py b/ci/test_discovery_agent.py
new file mode 100644
index 0000000000..008ee47f8e
--- /dev/null
+++ b/ci/test_discovery_agent.py
@@ -0,0 +1,120 @@
+# Copyright 2024, The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+"""Test discovery agent that uses TradeFed to discover test artifacts."""
+import glob
+import json
+import logging
+import os
+import subprocess
+
+
+class TestDiscoveryAgent:
+  """Test discovery agent."""
+
+  _TRADEFED_PREBUILT_JAR_RELATIVE_PATH = (
+      "vendor/google_tradefederation/prebuilts/filegroups/google-tradefed/"
+  )
+
+  _TRADEFED_NO_POSSIBLE_TEST_DISCOVERY_KEY = "NoPossibleTestDiscovery"
+
+  _TRADEFED_TEST_ZIP_REGEXES_LIST_KEY = "TestZipRegexes"
+
+  _TRADEFED_DISCOVERY_OUTPUT_FILE_NAME = "test_discovery_agent.txt"
+
+  def __init__(
+      self,
+      tradefed_args: list[str],
+      test_mapping_zip_path: str = "",
+      tradefed_jar_revelant_files_path: str = _TRADEFED_PREBUILT_JAR_RELATIVE_PATH,
+  ):
+    self.tradefed_args = tradefed_args
+    self.test_mapping_zip_path = test_mapping_zip_path
+    self.tradefed_jar_relevant_files_path = tradefed_jar_revelant_files_path
+
+  def discover_test_zip_regexes(self) -> list[str]:
+    """Discover test zip regexes from TradeFed.
+
+    Returns:
+      A list of test zip regexes that TF is going to try to pull files from.
+    """
+    test_discovery_output_file_name = os.path.join(
+        os.environ.get('TOP'), 'out', self._TRADEFED_DISCOVERY_OUTPUT_FILE_NAME
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
+          "com.android.tradefed.observatory.TestZipDiscoveryExecutor"
+      )
+      java_args.extend(self.tradefed_args)
+      env = os.environ.copy()
+      env.update({"DISCOVERY_OUTPUT_FILE": test_discovery_output_file.name})
+      logging.info(f"Calling test discovery with args: {java_args}")
+      try:
+        result = subprocess.run(args=java_args, env=env, text=True, check=True)
+        logging.info(f"Test zip discovery output: {result.stdout}")
+      except subprocess.CalledProcessError as e:
+        raise TestDiscoveryError(
+            f"Failed to run test discovery, strout: {e.stdout}, strerr:"
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
+          data[self._TRADEFED_TEST_ZIP_REGEXES_LIST_KEY] is None
+          or data[self._TRADEFED_TEST_ZIP_REGEXES_LIST_KEY] is []
+      ):
+        raise TestDiscoveryError("No test zip regexes returned")
+      return data[self._TRADEFED_TEST_ZIP_REGEXES_LIST_KEY]
+
+  def discover_test_modules(self) -> list[str]:
+    """Discover test modules from TradeFed.
+
+    Returns:
+      A list of test modules that TradeFed is going to execute based on the
+      TradeFed test args.
+    """
+    return []
+
+  def create_classpath(self, directory):
+    """Creates a classpath string from all .jar files in the given directory.
+
+    Args:
+      directory: The directory to search for .jar files.
+
+    Returns:
+      A string representing the classpath, with jar files separated by the
+      OS-specific path separator (e.g., ':' on Linux/macOS, ';' on Windows).
+    """
+    jar_files = glob.glob(os.path.join(directory, "*.jar"))
+    return os.pathsep.join(jar_files)
+
+
+class TestDiscoveryError(Exception):
+  """A TestDiscoveryErrorclass."""
+
+  def __init__(self, message):
+    super().__init__(message)
+    self.message = message
diff --git a/cogsetup.sh b/cogsetup.sh
deleted file mode 100644
index 5c64a068e0..0000000000
--- a/cogsetup.sh
+++ /dev/null
@@ -1,71 +0,0 @@
-#
-# Copyright (C) 2023 The Android Open Source Project
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
-# This file is executed by build/envsetup.sh, and can use anything
-# defined in envsetup.sh.
-function _create_out_symlink_for_cog() {
-  if [[ "${OUT_DIR}" == "" ]]; then
-    OUT_DIR="out"
-  fi
-
-  # getoutdir ensures paths are absolute. envsetup could be called from a
-  # directory other than the root of the source tree
-  local outdir=$(getoutdir)
-  if [[ -L "${outdir}" ]]; then
-    return
-  fi
-  if [ -d "${outdir}" ]; then
-    echo -e "\tOutput directory ${outdir} cannot be present in a Cog workspace."
-    echo -e "\tDelete \"${outdir}\" or create a symlink from \"${outdir}\" to a directory outside your workspace."
-    return 1
-  fi
-
-  DEFAULT_OUTPUT_DIR="${HOME}/.cog/android-build-out"
-  mkdir -p ${DEFAULT_OUTPUT_DIR}
-  ln -s ${DEFAULT_OUTPUT_DIR} ${outdir}
-}
-
-# This function sets up the build environment to be appropriate for Cog.
-function _setup_cog_env() {
-  _create_out_symlink_for_cog
-  if [ "$?" -eq "1" ]; then
-    echo -e "\e[0;33mWARNING:\e[00m Cog environment setup failed!"
-    return 1
-  fi
-
-  export ANDROID_BUILD_ENVIRONMENT_CONFIG="googler-cog"
-
-  # Running repo command within Cog workspaces is not supported, so override
-  # it with this function. If the user is running repo within a Cog workspace,
-  # we'll fail with an error, otherwise, we run the original repo command with
-  # the given args.
-  if ! ORIG_REPO_PATH=`which repo`; then
-    return 0
-  fi
-  function repo {
-    if [[ "${PWD}" == /google/cog/* ]]; then
-      echo -e "\e[01;31mERROR:\e[0mrepo command is disallowed within Cog workspaces."
-      return 1
-    fi
-    ${ORIG_REPO_PATH} "$@"
-  }
-}
-
-if [[ "${PWD}" != /google/cog/* ]]; then
-  echo -e "\e[01;31mERROR:\e[0m This script must be run from a Cog workspace."
-fi
-
-_setup_cog_env
diff --git a/core/Makefile b/core/Makefile
index 2cdb24f9b0..a7ab4425de 100644
--- a/core/Makefile
+++ b/core/Makefile
@@ -192,6 +192,34 @@ product_copy_files_ignored :=
 unique_product_copy_files_pairs :=
 unique_product_copy_files_destinations :=
 
+
+# Returns a list of EXTRA_INSTALL_ZIPS trios whose primary file is contained within $(1)
+# The trios will contain the primary installed file : the directory to unzip the zip to : the zip
+define relevant-extra-install-zips
+$(strip $(foreach p,$(EXTRA_INSTALL_ZIPS), \
+  $(if $(filter $(call word-colon,1,$(p)),$(1)), \
+    $(p))))
+endef
+
+# Writes a text file that contains all of the files that will be inside a partition.
+# All the file paths will be relative to the partition's staging directory.
+# It will also take into account files inside zips listed in EXTRA_INSTALL_ZIPS.
+#
+# Arguments:
+#   $(1): Output file
+#   $(2): The partition's staging directory
+#   $(3): Files to include in the partition
+define write-partition-file-list
+$(1): PRIVATE_FILES := $(subst $(2)/,,$(filter $(2)/%,$(3)))
+$(1): PRIVATE_EXTRA_INSTALL_ZIPS := $(call relevant-extra-install-zips,$(filter $(2)/%,$(3)))
+$(1): $$(HOST_OUT_EXECUTABLES)/extra_install_zips_file_list $(foreach p,$(call relevant-extra-install-zips,$(filter $(2)/%,$(3))),$(call word-colon,3,$(p)))
+	@echo Writing $$@
+	rm -f $$@
+	echo -n > $$@
+	$$(foreach f,$$(PRIVATE_FILES),echo "$$(f)" >> $$@$$(newline))
+	$$(HOST_OUT_EXECUTABLES)/extra_install_zips_file_list $(2) $$(PRIVATE_EXTRA_INSTALL_ZIPS) >> $$@
+endef
+
 # -----------------------------------------------------------------
 # Returns the max allowed size for an image suitable for hash verification
 # (e.g., boot.img, recovery.img, etc).
@@ -692,7 +720,7 @@ endif
 
 BOARD_KERNEL_MODULE_DIRS += top
 
-# Default to not generating modules.dep for kernel modules on system
+# Default to not generating modules.load for kernel modules on system
 # side. We should only load these modules if they are depended by vendor
 # side modules.
 ifeq ($(BOARD_SYSTEM_KERNEL_MODULES_LOAD),)
@@ -844,6 +872,7 @@ SOONG_CONV := $(sort $(SOONG_CONV))
 SOONG_CONV_DATA := $(call intermediates-dir-for,PACKAGING,soong_conversion)/soong_conv_data
 $(SOONG_CONV_DATA):
 	@rm -f $@
+	@touch $@ # This file must be present even if SOONG_CONV is empty.
 	@$(foreach s,$(SOONG_CONV),echo "$(s),$(SOONG_CONV.$(s).TYPE),$(sort $(SOONG_CONV.$(s).PROBLEMS)),$(sort $(filter-out $(SOONG_ALREADY_CONV),$(SOONG_CONV.$(s).DEPS))),$(sort $(SOONG_CONV.$(s).MAKEFILES)),$(sort $(SOONG_CONV.$(s).INSTALLED))" >>$@;)
 
 $(call declare-1p-target,$(SOONG_CONV_DATA),build)
@@ -1267,6 +1296,10 @@ boototapackage_16k: $(BUILT_BOOT_OTA_PACKAGE_16K)
 
 endif
 
+
+ramdisk_intermediates :=$= $(call intermediates-dir-for,PACKAGING,ramdisk)
+$(eval $(call write-partition-file-list,$(ramdisk_intermediates)/file_list.txt,$(TARGET_RAMDISK_OUT),$(INTERNAL_RAMDISK_FILES)))
+
 # The value of RAMDISK_NODE_LIST is defined in system/core/rootdir/Android.bp.
 # This file contains /dev nodes description added to the generic ramdisk
 
@@ -1564,6 +1597,7 @@ $(INSTALLED_INIT_BOOT_IMAGE_TARGET): $(AVBTOOL) $(BOARD_AVB_INIT_BOOT_KEY_PATH)
 	$(AVBTOOL) add_hash_footer \
            --image $@ \
 	   $(call get-partition-size-argument,$(BOARD_INIT_BOOT_IMAGE_PARTITION_SIZE)) \
+	   --salt $$(sha256sum $(BUILD_NUMBER_FILE) $(BUILD_DATETIME_FILE) | cut -d " " -f 1 | tr -d '\n') \
 	   --partition_name init_boot $(INTERNAL_AVB_INIT_BOOT_SIGNING_ARGS) \
 	   $(BOARD_AVB_INIT_BOOT_ADD_HASH_FOOTER_ARGS)
 
@@ -1622,6 +1656,8 @@ INTERNAL_VENDOR_RAMDISK_FILES := $(filter $(TARGET_VENDOR_RAMDISK_OUT)/%, \
     $(ALL_DEFAULT_INSTALLED_MODULES))
 
 INTERNAL_VENDOR_RAMDISK_TARGET := $(call intermediates-dir-for,PACKAGING,vendor_boot)/vendor_ramdisk.cpio$(RAMDISK_EXT)
+vendor_ramdisk_intermediates :=$= $(call intermediates-dir-for,PACKAGING,vendor_ramdisk)
+$(eval $(call write-partition-file-list,$(vendor_ramdisk_intermediates)/file_list.txt,$(TARGET_VENDOR_RAMDISK_OUT),$(INTERNAL_VENDOR_RAMDISK_FILES)))
 
 # Exclude recovery files in the default vendor ramdisk if including a standalone
 # recovery ramdisk in vendor_boot.
@@ -1676,12 +1712,13 @@ ifdef INTERNAL_KERNEL_CMDLINE
   INTERNAL_VENDOR_BOOTIMAGE_ARGS += --vendor_cmdline "$(INTERNAL_KERNEL_CMDLINE)"
 endif
 
-ifdef INTERNAL_BOOTCONFIG
+ifneq (, $(INTERNAL_BOOTCONFIG)$(INTERNAL_BOOTCONFIG_FILE))
   INTERNAL_VENDOR_BOOTCONFIG_TARGET := $(PRODUCT_OUT)/vendor-bootconfig.img
   $(INTERNAL_VENDOR_BOOTCONFIG_TARGET):
 	rm -f $@
 	$(foreach param,$(INTERNAL_BOOTCONFIG), \
 	 printf "%s\n" $(param) >> $@;)
+	cat $(INTERNAL_BOOTCONFIG_FILE) >> $@
   INTERNAL_VENDOR_BOOTIMAGE_ARGS += --vendor_bootconfig $(INTERNAL_VENDOR_BOOTCONFIG_TARGET)
 endif
 
@@ -1736,6 +1773,7 @@ $(INSTALLED_VENDOR_BOOTIMAGE_TARGET): $(AVBTOOL) $(BOARD_AVB_VENDOR_BOOTIMAGE_KE
 	$(AVBTOOL) add_hash_footer \
            --image $@ \
 	   $(call get-partition-size-argument,$(BOARD_VENDOR_BOOTIMAGE_PARTITION_SIZE)) \
+	   --salt $$(sha256sum $(BUILD_NUMBER_FILE) $(BUILD_DATETIME_FILE) | cut -d " " -f 1 | tr -d '\n') \
 	   --partition_name vendor_boot $(INTERNAL_AVB_VENDOR_BOOT_SIGNING_ARGS) \
 	   $(BOARD_AVB_VENDOR_BOOT_ADD_HASH_FOOTER_ARGS)
 else
@@ -2899,6 +2937,9 @@ ifneq ($(BOARD_NAND_SPARE_SIZE),)
 $(error MTD device is no longer supported and thus BOARD_NAND_SPARE_SIZE is deprecated.)
 endif
 
+recovery_intermediates := $(call intermediates-dir-for,PACKAGING,recovery)
+$(eval $(call write-partition-file-list,$(recovery_intermediates)/file_list.txt,$(TARGET_RECOVERY_OUT),$(INTERNAL_RECOVERYIMAGE_FILES)))
+
 
 # -----------------------------------------------------------------
 # Build debug ramdisk and debug boot image.
@@ -3471,31 +3512,6 @@ endif
 
 FULL_SYSTEMIMAGE_DEPS += $(INTERNAL_ROOT_FILES) $(INSTALLED_FILES_FILE_ROOT)
 
-# Returns a list of EXTRA_INSTALL_ZIPS trios whose primary file is contained within $(1)
-# The trios will contain the primary installed file : the directory to unzip the zip to : the zip
-define relevant-extra-install-zips
-$(strip $(foreach p,$(EXTRA_INSTALL_ZIPS), \
-  $(if $(filter $(call word-colon,1,$(p)),$(1)), \
-    $(p))))
-endef
-
-# Writes a text file that contains all of the files that will be inside a partition.
-# All the file paths will be relative to the partition's staging directory.
-# It will also take into account files inside zips listed in EXTRA_INSTALL_ZIPS.
-#
-# Arguments:
-#   $(1): Output file
-#   $(2): The partition's staging directory
-#   $(3): Files to include in the partition
-define write-partition-file-list
-$(1): $$(HOST_OUT_EXECUTABLES)/extra_install_zips_file_list $(foreach p,$(call relevant-extra-install-zips,$(filter $(2)/%,$(3))),$(call word-colon,3,$(p)))
-	@echo Writing $$@
-	rm -f $$@
-	echo -n > $$@
-	$$(foreach f,$(subst $(2)/,,$(filter $(2)/%,$(3))),echo "$$(f)" >> $$@$$(newline))
-	$$(HOST_OUT_EXECUTABLES)/extra_install_zips_file_list $(2) $(call relevant-extra-install-zips,$(filter $(2)/%,$(3))) >> $$@
-endef
-
 # -----------------------------------------------------------------
 ifdef BUILDING_SYSTEM_IMAGE
 
@@ -3567,14 +3583,24 @@ ifneq ($(PRODUCT_SOONG_DEFINED_SYSTEM_IMAGE),)
 file_list_diff := $(HOST_OUT_EXECUTABLES)/file_list_diff$(HOST_EXECUTABLE_SUFFIX)
 system_file_diff_timestamp := $(systemimage_intermediates)/file_diff.timestamp
 
+# The build configuration to build the REL version may have more files to allow.
+# Use allowlist_next in addition to the allowlist in this case.
+system_file_diff_allowlist_next :=
+ifeq (REL,$(PLATFORM_VERSION_CODENAME))
+system_file_diff_allowlist_next := $(ALL_MODULES.system_image_diff_allowlist_next.INSTALLED)
+$(system_file_diff_timestamp): PRIVATE_ALLOWLIST_NEXT := $(system_file_diff_allowlist_next)
+endif
 $(system_file_diff_timestamp): \
 	    $(systemimage_intermediates)/file_list.txt \
 	    $(ALL_MODULES.$(PRODUCT_SOONG_DEFINED_SYSTEM_IMAGE).FILESYSTEM_FILELIST) \
 	    $(ALL_MODULES.system_image_diff_allowlist.INSTALLED) \
+	    $(system_file_diff_allowlist_next) \
 	    $(file_list_diff)
 	$(file_list_diff) $(systemimage_intermediates)/file_list.txt \
 	  $(ALL_MODULES.$(PRODUCT_SOONG_DEFINED_SYSTEM_IMAGE).FILESYSTEM_FILELIST) \
-	  $(ALL_MODULES.system_image_diff_allowlist.INSTALLED) $(PRODUCT_SOONG_DEFINED_SYSTEM_IMAGE)
+	  $(PRODUCT_SOONG_DEFINED_SYSTEM_IMAGE) \
+	  --allowlists $(ALL_MODULES.system_image_diff_allowlist.INSTALLED) \
+	  $(PRIVATE_ALLOWLIST_NEXT)
 	touch $@
 
 $(BUILT_SYSTEMIMAGE): $(system_file_diff_timestamp)
@@ -4000,6 +4026,21 @@ INTERNAL_PRODUCTIMAGE_FILES := \
     $(filter $(TARGET_OUT_PRODUCT)/%,\
       $(ALL_DEFAULT_INSTALLED_MODULES))
 
+# Install product/etc/linker.config.pb with PRODUCT_PRODUCT_LINKER_CONFIG_FRAGMENTS
+product_linker_config_file := $(TARGET_OUT_PRODUCT)/etc/linker.config.pb
+$(product_linker_config_file): private_linker_config_fragments := $(PRODUCT_PRODUCT_LINKER_CONFIG_FRAGMENTS)
+$(product_linker_config_file): $(INTERNAL_PRODUCTIMAGE_FILES) | $(HOST_OUT_EXECUTABLES)/conv_linker_config
+	@echo Creating linker config: $@
+	@mkdir -p $(dir $@)
+	@rm -f $@
+	$(HOST_OUT_EXECUTABLES)/conv_linker_config proto \
+		--source $(call normalize-path-list,$(private_linker_config_fragments)) \
+		--output $@
+$(call define declare-1p-target,$(product_linker_config_file),)
+INTERNAL_PRODUCTIMAGE_FILES += $(product_linker_config_file)
+ALL_DEFAULT_INSTALLED_MODULES += $(product_linker_config_file)
+
+
 INSTALLED_FILES_FILE_PRODUCT := $(PRODUCT_OUT)/installed-files-product.txt
 INSTALLED_FILES_JSON_PRODUCT := $(INSTALLED_FILES_FILE_PRODUCT:.txt=.json)
 $(INSTALLED_FILES_FILE_PRODUCT): .KATI_IMPLICIT_OUTPUTS := $(INSTALLED_FILES_JSON_PRODUCT)
@@ -5136,6 +5177,8 @@ INTERNAL_ALLIMAGES_FILES := \
 # Run apex_sepolicy_tests for all installed APEXes
 
 ifeq (,$(TARGET_BUILD_UNBUNDLED))
+# TODO(b/353896817) apex_sepolicy_tests supports only ext4
+ifeq (ext4,$(PRODUCT_DEFAULT_APEX_PAYLOAD_TYPE))
 intermediate := $(call intermediates-dir-for,PACKAGING,apex_sepolicy_tests)
 apex_dirs := \
   $(TARGET_OUT)/apex/% \
@@ -5175,6 +5218,7 @@ droid_targets: run_apex_sepolicy_tests
 
 apex_files :=
 intermediate :=
+endif # PRODUCT_DEFAULT_APEX_PAYLOAD_TYPE
 endif # TARGET_BUILD_UNBUNDLED
 
 # -----------------------------------------------------------------
@@ -5270,7 +5314,7 @@ $(vintffm_log): $(HOST_OUT_EXECUTABLES)/vintffm $(check_vintf_system_deps) $(APE
 	  --dirmap /system_ext:$(TARGET_OUT_SYSTEM_EXT) \
 	  --dirmap /product:$(TARGET_OUT_PRODUCT) \
 	  --dirmap /apex:$(APEX_OUT) \
-	  $(VINTF_FRAMEWORK_MANIFEST_FROZEN_DIR) > $@ 2>&1 ) || ( cat $@ && exit 1 )
+	  system/libhidl/vintfdata/frozen > $@ 2>&1 ) || ( cat $@ && exit 1 )
 
 $(call declare-1p-target,$(vintffm_log))
 
@@ -5643,6 +5687,7 @@ INTERNAL_OTATOOLS_MODULES := \
   brotli \
   bsdiff \
   build_image \
+  build_mixed_kernels_ramdisk_host \
   build_super_image \
   build_verity_metadata \
   build_verity_tree \
@@ -6355,6 +6400,10 @@ ifdef BUILDING_VENDOR_BOOT_IMAGE
   endif
 endif
 
+ifdef BUILDING_VENDOR_KERNEL_BOOT_IMAGE
+  $(BUILT_TARGET_FILES_DIR): $(INTERNAL_VENDOR_KERNEL_RAMDISK_FILES)
+endif
+
 ifdef BUILDING_RECOVERY_IMAGE
   # TODO(b/30414428): Can't depend on INTERNAL_RECOVERYIMAGE_FILES alone like other
   # BUILT_TARGET_FILES_PACKAGE dependencies because currently there're cp/rsync/rm
@@ -7948,11 +7997,16 @@ endif # PACK_DESKTOP_FILESYSTEM_IMAGES
 
 # -----------------------------------------------------------------
 # Desktop pack recovery image hook.
-ifneq (,$(strip $(PACK_DESKTOP_RECOVERY_IMAGE)))
+ifeq ($(BOARD_USES_DESKTOP_RECOVERY_IMAGE),true)
 PACK_RECOVERY_IMAGE_TARGET := $(PRODUCT_OUT)/android-desktop_recovery_image.bin
+PACK_RECOVERY_IMAGE_ARGS := --noarchive --recovery
+
+ifneq (,$(strip $(PACK_RECOVERY_IMAGE_EXPERIMENTAL)))
+PACK_RECOVERY_IMAGE_ARGS += --experimental
+endif # PACK_RECOVERY_IMAGE_EXPERIMENTAL
 
 $(PACK_RECOVERY_IMAGE_TARGET): $(IMAGES) $(PACK_IMAGE_SCRIPT)
-	$(PACK_IMAGE_SCRIPT) --out_dir $(PRODUCT_OUT) --noarchive --recovery
+	$(PACK_IMAGE_SCRIPT) --out_dir $(PRODUCT_OUT) $(PACK_RECOVERY_IMAGE_ARGS)
 
 PACKED_RECOVERY_IMAGE_ARCHIVE_TARGET := $(PACK_RECOVERY_IMAGE_TARGET).gz
 
@@ -7964,15 +8018,20 @@ $(call dist-for-goals,dist_files,$(PACKED_RECOVERY_IMAGE_ARCHIVE_TARGET))
 .PHONY: pack-recovery-image
 pack-recovery-image: $(PACK_RECOVERY_IMAGE_TARGET)
 
-endif # PACK_DESKTOP_RECOVERY_IMAGE
+endif # BOARD_USES_DESKTOP_RECOVERY_IMAGE
 
 # -----------------------------------------------------------------
 # Desktop pack update image hook.
-ifneq (,$(strip $(PACK_DESKTOP_UPDATE_IMAGE)))
+ifeq ($(BOARD_USES_DESKTOP_UPDATE_IMAGE),true)
 PACK_UPDATE_IMAGE_TARGET := $(PRODUCT_OUT)/android-desktop_update_image.bin
+PACK_UPDATE_IMAGE_ARGS := --noarchive --update
+
+ifneq (,$(strip $(PACK_UPDATE_IMAGE_EXPERIMENTAL)))
+PACK_UPDATE_IMAGE_ARGS += --experimental
+endif # PACK_UPDATE_IMAGE_EXPERIMENTAL
 
 $(PACK_UPDATE_IMAGE_TARGET): $(IMAGES) $(PACK_IMAGE_SCRIPT)
-	$(PACK_IMAGE_SCRIPT) --out_dir $(PRODUCT_OUT) --noarchive --update
+	$(PACK_IMAGE_SCRIPT) --out_dir $(PRODUCT_OUT) $(PACK_UPDATE_IMAGE_ARGS)
 
 PACKED_UPDATE_IMAGE_ARCHIVE_TARGET := $(PACK_UPDATE_IMAGE_TARGET).gz
 
@@ -7984,7 +8043,29 @@ $(call dist-for-goals,dist_files,$(PACKED_UPDATE_IMAGE_ARCHIVE_TARGET))
 .PHONY: pack-update-image
 pack-update-image: $(PACK_UPDATE_IMAGE_TARGET)
 
-endif # PACK_DESKTOP_UPDATE_IMAGE
+endif # BOARD_USES_DESKTOP_UPDATE_IMAGE
+
+PACK_MIGRATION_IMAGE_SCRIPT := $(HOST_OUT_EXECUTABLES)/pack_migration_image
+
+# -----------------------------------------------------------------
+# Desktop pack migration image hook.
+ifeq ($(ANDROID_DESKTOP_MIGRATION_IMAGE),true)
+PACK_MIGRATION_IMAGE_TARGET := $(PRODUCT_OUT)/android-desktop_migration_image.bin
+
+$(PACK_MIGRATION_IMAGE_TARGET): $(IMAGES) $(PACK_MIGRATION_IMAGE_SCRIPT)
+	$(PACK_MIGRATION_IMAGE_SCRIPT) --out_dir $(PRODUCT_OUT) --noarchive
+
+PACKED_MIGRATION_IMAGE_ARCHIVE_TARGET := $(PACK_MIGRATION_IMAGE_TARGET).gz
+
+$(PACKED_MIGRATION_IMAGE_ARCHIVE_TARGET): $(PACK_MIGRATION_IMAGE_TARGET) | $(GZIP)
+	$(GZIP) -fk $(PACK_MIGRATION_IMAGE_TARGET)
+
+$(call dist-for-goals,dist_files,$(PACKED_MIGRATION_IMAGE_ARCHIVE_TARGET))
+
+.PHONY: pack-migration-image
+pack-migration-image: $(PACK_MIGRATION_IMAGE_TARGET)
+
+endif # ANDROID_DESKTOP_MIGRATION_IMAGE
 
 # -----------------------------------------------------------------
 # OS Licensing
diff --git a/core/android_soong_config_vars.mk b/core/android_soong_config_vars.mk
index 7ba186b73b..44e2398ae1 100644
--- a/core/android_soong_config_vars.mk
+++ b/core/android_soong_config_vars.mk
@@ -30,12 +30,29 @@ $(call add_soong_config_var,ANDROID,BOARD_USES_ODMIMAGE)
 $(call soong_config_set_bool,ANDROID,BOARD_USES_RECOVERY_AS_BOOT,$(BOARD_USES_RECOVERY_AS_BOOT))
 $(call soong_config_set_bool,ANDROID,BOARD_MOVE_GSI_AVB_KEYS_TO_VENDOR_BOOT,$(BOARD_MOVE_GSI_AVB_KEYS_TO_VENDOR_BOOT))
 $(call add_soong_config_var,ANDROID,CHECK_DEV_TYPE_VIOLATIONS)
+$(call soong_config_set_bool,ANDROID,HAS_BOARD_SYSTEM_EXT_PREBUILT_DIR,$(if $(BOARD_SYSTEM_EXT_PREBUILT_DIR),true,false))
+$(call soong_config_set_bool,ANDROID,HAS_BOARD_PRODUCT_PREBUILT_DIR,$(if $(BOARD_PRODUCT_PREBUILT_DIR),true,false))
 $(call add_soong_config_var,ANDROID,PLATFORM_SEPOLICY_VERSION)
 $(call add_soong_config_var,ANDROID,PLATFORM_SEPOLICY_COMPAT_VERSIONS)
 $(call add_soong_config_var,ANDROID,PRODUCT_INSTALL_DEBUG_POLICY_TO_SYSTEM_EXT)
+$(call soong_config_set_bool,ANDROID,RELEASE_BOARD_API_LEVEL_FROZEN,$(RELEASE_BOARD_API_LEVEL_FROZEN))
 $(call add_soong_config_var,ANDROID,TARGET_DYNAMIC_64_32_DRMSERVER)
 $(call add_soong_config_var,ANDROID,TARGET_ENABLE_MEDIADRM_64)
 $(call add_soong_config_var,ANDROID,TARGET_DYNAMIC_64_32_MEDIASERVER)
+$(call add_soong_config_var,ANDROID,BOARD_GENFS_LABELS_VERSION)
+
+$(call add_soong_config_var,ANDROID,ADDITIONAL_M4DEFS,$(if $(BOARD_SEPOLICY_M4DEFS),$(addprefix -D,$(BOARD_SEPOLICY_M4DEFS))))
+
+# For bootable/recovery
+RECOVERY_API_VERSION := 3
+RECOVERY_FSTAB_VERSION := 2
+$(call soong_config_set, recovery, recovery_api_version, $(RECOVERY_API_VERSION))
+$(call soong_config_set, recovery, recovery_fstab_version, $(RECOVERY_FSTAB_VERSION))
+$(call soong_config_set_bool, recovery ,target_userimages_use_f2fs ,$(if $(TARGET_USERIMAGES_USE_F2FS),true,false))
+$(call soong_config_set_bool, recovery ,has_board_cacheimage_partition_size ,$(if $(BOARD_CACHEIMAGE_PARTITION_SIZE),true,false))
+ifdef TARGET_RECOVERY_UI_LIB
+  $(call soong_config_set_string_list, recovery, target_recovery_ui_lib, $(TARGET_RECOVERY_UI_LIB))
+endif
 
 # For Sanitizers
 $(call soong_config_set_bool,ANDROID,ASAN_ENABLED,$(if $(filter address,$(SANITIZE_TARGET)),true,false))
@@ -60,6 +77,11 @@ endif
 # The default value of ART_BUILD_HOST_DEBUG is true
 $(call soong_config_set_bool,art_module,art_build_host_debug,$(if $(filter false,$(ART_BUILD_HOST_DEBUG)),false,true))
 
+# For chre
+$(call soong_config_set_bool,chre,chre_daemon_lama_enabled,$(if $(filter true,$(CHRE_DAEMON_LPMA_ENABLED)),true,false))
+$(call soong_config_set_bool,chre,chre_dedicated_transport_channel_enabled,$(if $(filter true,$(CHRE_DEDICATED_TRANSPORT_CHANNEL_ENABLED)),true,false))
+$(call soong_config_set_bool,chre,chre_log_atom_extension_enabled,$(if $(filter true,$(CHRE_LOG_ATOM_EXTENSION_ENABLED)),true,false))
+
 ifdef TARGET_BOARD_AUTO
   $(call add_soong_config_var_value, ANDROID, target_board_auto, $(TARGET_BOARD_AUTO))
 endif
@@ -77,6 +99,9 @@ endif
 SYSTEMUI_OPTIMIZE_JAVA ?= true
 $(call add_soong_config_var,ANDROID,SYSTEMUI_OPTIMIZE_JAVA)
 
+# Flag to use baseline profile for SystemUI.
+$(call soong_config_set,ANDROID,release_systemui_use_speed_profile,$(RELEASE_SYSTEMUI_USE_SPEED_PROFILE))
+
 # Flag for enabling compose for Launcher.
 $(call soong_config_set,ANDROID,release_enable_compose_in_launcher,$(RELEASE_ENABLE_COMPOSE_IN_LAUNCHER))
 
@@ -94,6 +119,10 @@ ifdef PRODUCT_AVF_MICRODROID_GUEST_GKI_VERSION
 $(call add_soong_config_var_value,ANDROID,avf_microdroid_guest_gki_version,$(PRODUCT_AVF_MICRODROID_GUEST_GKI_VERSION))
 endif
 
+ifdef TARGET_BOOTS_16K
+$(call soong_config_set_bool,ANDROID,target_boots_16k,$(filter true,$(TARGET_BOOTS_16K)))
+endif
+
 ifdef PRODUCT_MEMCG_V2_FORCE_ENABLED
 $(call add_soong_config_var_value,ANDROID,memcg_v2_force_enabled,$(PRODUCT_MEMCG_V2_FORCE_ENABLED))
 endif
@@ -175,6 +204,19 @@ endif
 # Required as platform_bootclasspath is using this namespace
 $(call soong_config_set,bootclasspath,release_crashrecovery_module,$(RELEASE_CRASHRECOVERY_MODULE))
 
+
+# Add ondeviceintelligence module build flag to soong
+ifeq (true,$(RELEASE_ONDEVICE_INTELLIGENCE_MODULE))
+    $(call soong_config_set,ANDROID,release_ondevice_intelligence_module,true)
+    # Required as platform_bootclasspath is using this namespace
+    $(call soong_config_set,bootclasspath,release_ondevice_intelligence_module,true)
+
+else
+    $(call soong_config_set,ANDROID,release_ondevice_intelligence_platform,true)
+    $(call soong_config_set,bootclasspath,release_ondevice_intelligence_platform,true)
+
+endif
+
 # Add uprobestats build flag to soong
 $(call soong_config_set,ANDROID,release_uprobestats_module,$(RELEASE_UPROBESTATS_MODULE))
 # Add uprobestats file move flags to soong, for both platform and module
@@ -201,3 +243,62 @@ $(call soong_config_set_bool,gralloc,target_use_pan_display,$(if $(filter true,$
 
 # Add use_camera_v4l2_hal flag for hardware/libhardware/modules/camera/3_4:camera.v4l2
 $(call soong_config_set_bool,camera,use_camera_v4l2_hal,$(if $(filter true,$(USE_CAMERA_V4L2_HAL)),true,false))
+
+# Add audioserver_multilib flag for hardware/interfaces/soundtrigger/2.0/default:android.hardware.soundtrigger@2.0-impl
+ifneq ($(strip $(AUDIOSERVER_MULTILIB)),)
+  $(call soong_config_set,soundtrigger,audioserver_multilib,$(AUDIOSERVER_MULTILIB))
+endif
+
+# Add sim_count, disable_rild_oem_hook, and use_aosp_rild flag for ril related modules
+$(call soong_config_set,ril,sim_count,$(SIM_COUNT))
+ifneq ($(DISABLE_RILD_OEM_HOOK), false)
+  $(call soong_config_set_bool,ril,disable_rild_oem_hook,true)
+endif
+ifneq ($(ENABLE_VENDOR_RIL_SERVICE), true)
+  $(call soong_config_set_bool,ril,use_aosp_rild,true)
+endif
+
+# Export target_board_platform to soong for hardware/google/graphics/common/libmemtrack:memtrack.$(TARGET_BOARD_PLATFORM)
+$(call soong_config_set,ANDROID,target_board_platform,$(TARGET_BOARD_PLATFORM))
+
+# Export board_uses_scaler_m2m1shot and board_uses_align_restriction to soong for hardware/google/graphics/common/libscaler:libexynosscaler
+$(call soong_config_set_bool,google_graphics,board_uses_scaler_m2m1shot,$(if $(filter true,$(BOARD_USES_SCALER_M2M1SHOT)),true,false))
+$(call soong_config_set_bool,google_graphics,board_uses_align_restriction,$(if $(filter true,$(BOARD_USES_ALIGN_RESTRICTION)),true,false))
+
+# Export related variables to soong for hardware/google/graphics/common/libacryl:libacryl
+ifdef BOARD_LIBACRYL_DEFAULT_COMPOSITOR
+  $(call soong_config_set,acryl,libacryl_default_compositor,$(BOARD_LIBACRYL_DEFAULT_COMPOSITOR))
+endif
+ifdef BOARD_LIBACRYL_DEFAULT_SCALER
+  $(call soong_config_set,acryl,libacryl_default_scaler,$(BOARD_LIBACRYL_DEFAULT_SCALER))
+endif
+ifdef BOARD_LIBACRYL_DEFAULT_BLTER
+  $(call soong_config_set,acryl,libacryl_default_blter,$(BOARD_LIBACRYL_DEFAULT_BLTER))
+endif
+ifdef BOARD_LIBACRYL_G2D_HDR_PLUGIN
+  #BOARD_LIBACRYL_G2D_HDR_PLUGIN is set in each board config
+  $(call soong_config_set_bool,acryl,libacryl_use_g2d_hdr_plugin,true)
+endif
+
+# Export related variables to soong for hardware/google/graphics/common/BoardConfigCFlags.mk
+$(call soong_config_set_bool,google_graphics,hwc_no_support_skip_validate,$(if $(filter true,$(HWC_NO_SUPPORT_SKIP_VALIDATE)),true,false))
+$(call soong_config_set_bool,google_graphics,hwc_support_color_transform,$(if $(filter true,$(HWC_SUPPORT_COLOR_TRANSFORM)),true,false))
+$(call soong_config_set_bool,google_graphics,hwc_support_render_intent,$(if $(filter true,$(HWC_SUPPORT_RENDER_INTENT)),true,false))
+$(call soong_config_set_bool,google_graphics,board_uses_virtual_display,$(if $(filter true,$(BOARD_USES_VIRTUAL_DISPLAY)),true,false))
+$(call soong_config_set_bool,google_graphics,board_uses_dt,$(if $(filter true,$(BOARD_USES_DT)),true,false))
+$(call soong_config_set_bool,google_graphics,board_uses_decon_64bit_address,$(if $(filter true,$(BOARD_USES_DECON_64BIT_ADDRESS)),true,false))
+$(call soong_config_set_bool,google_graphics,board_uses_hdrui_gles_conversion,$(if $(filter true,$(BOARD_USES_HDRUI_GLES_CONVERSION)),true,false))
+$(call soong_config_set_bool,google_graphics,uses_idisplay_intf_sec,$(if $(filter true,$(USES_IDISPLAY_INTF_SEC)),true,false))
+
+# Variables for fs_config
+$(call soong_config_set_bool,fs_config,vendor,$(if $(BOARD_USES_VENDORIMAGE)$(BOARD_VENDORIMAGE_FILE_SYSTEM_TYPE),true,false))
+$(call soong_config_set_bool,fs_config,oem,$(if $(BOARD_USES_OEMIMAGE)$(BOARD_OEMIMAGE_FILE_SYSTEM_TYPE),true,false))
+$(call soong_config_set_bool,fs_config,odm,$(if $(BOARD_USES_ODMIMAGE)$(BOARD_ODMIMAGE_FILE_SYSTEM_TYPE),true,false))
+$(call soong_config_set_bool,fs_config,vendor_dlkm,$(if $(BOARD_USES_VENDOR_DLKMIMAGE)$(BOARD_VENDOR_DLKMIMAGE_FILE_SYSTEM_TYPE),true,false))
+$(call soong_config_set_bool,fs_config,odm_dlkm,$(if $(BOARD_USES_ODM_DLKMIMAGE)$(BOARD_ODM_DLKMIMAGE_FILE_SYSTEM_TYPE),true,false))
+$(call soong_config_set_bool,fs_config,system_dlkm,$(if $(BOARD_USES_SYSTEM_DLKMIMAGE)$(BOARD_SYSTEM_DLKMIMAGE_FILE_SYSTEM_TYPE),true,false))
+
+# Variables for telephony
+$(call soong_config_set_bool,telephony,sec_cp_secure_boot,$(if $(filter true,$(SEC_CP_SECURE_BOOT)),true,false))
+$(call soong_config_set_bool,telephony,cbd_protocol_sit,$(if $(filter true,$(CBD_PROTOCOL_SIT)),true,false))
+$(call soong_config_set_bool,telephony,use_radioexternal_hal_aidl,$(if $(filter true,$(USE_RADIOEXTERNAL_HAL_AIDL)),true,false))
diff --git a/core/binary.mk b/core/binary.mk
index 1e98bc08fb..ea862be6b4 100644
--- a/core/binary.mk
+++ b/core/binary.mk
@@ -174,7 +174,7 @@ my_allow_undefined_symbols := true
 endif
 endif
 
-my_ndk_sysroot_include :=
+my_ndk_sysroot :=
 my_ndk_sysroot_lib :=
 my_api_level := 10000
 
@@ -207,11 +207,9 @@ ifneq ($(LOCAL_SDK_VERSION),)
 
   my_built_ndk := $(SOONG_OUT_DIR)/ndk
   my_ndk_triple := $($(LOCAL_2ND_ARCH_VAR_PREFIX)TARGET_NDK_TRIPLE)
-  my_ndk_sysroot_include := \
-      $(my_built_ndk)/sysroot/usr/include \
-      $(my_built_ndk)/sysroot/usr/include/$(my_ndk_triple) \
+  my_ndk_sysroot := $(my_built_ndk)/sysroot
 
-  my_ndk_sysroot_lib := $(my_built_ndk)/sysroot/usr/lib/$(my_ndk_triple)/$(my_ndk_api)
+  my_ndk_sysroot_lib := $(my_ndk_sysroot)/usr/lib/$(my_ndk_triple)/$(my_ndk_api)
 
   # The bionic linker now has support for packed relocations and gnu style
   # hashes (which are much faster!), but shipping to older devices requires
@@ -330,18 +328,20 @@ ifneq ($(call module-in-vendor-or-product),)
   ifneq ($(LOCAL_IN_VENDOR),)
     # Vendor modules have LOCAL_IN_VENDOR
     my_cflags += -D__ANDROID_VENDOR__
-
-    ifeq ($(BOARD_API_LEVEL),)
-      # TODO(b/314036847): This is a fallback for UDC targets.
-      # This must be a build failure when UDC is no longer built from this source tree.
-      my_cflags += -D__ANDROID_VENDOR_API__=$(PLATFORM_SDK_VERSION)
-    else
-      my_cflags += -D__ANDROID_VENDOR_API__=$(BOARD_API_LEVEL)
-    endif
   else ifneq ($(LOCAL_IN_PRODUCT),)
     # Product modules have LOCAL_IN_PRODUCT
     my_cflags += -D__ANDROID_PRODUCT__
   endif
+
+  # Define __ANDROID_VENDOR_API__ for both product and vendor variants because
+  # they both use the same LLNDK libraries.
+  ifeq ($(BOARD_API_LEVEL),)
+    # TODO(b/314036847): This is a fallback for UDC targets.
+    # This must be a build failure when UDC is no longer built from this source tree.
+    my_cflags += -D__ANDROID_VENDOR_API__=$(PLATFORM_SDK_VERSION)
+  else
+    my_cflags += -D__ANDROID_VENDOR_API__=$(BOARD_API_LEVEL)
+  endif
 endif
 
 ifndef LOCAL_IS_HOST_MODULE
@@ -1626,19 +1626,6 @@ my_ldlibs += $(my_cxx_ldlibs)
 ###########################################################
 ifndef LOCAL_IS_HOST_MODULE
 
-ifeq ($(call module-in-vendor-or-product),true)
-  my_target_global_c_includes :=
-  my_target_global_c_system_includes := $(TARGET_OUT_HEADERS)
-else ifdef LOCAL_SDK_VERSION
-  my_target_global_c_includes :=
-  my_target_global_c_system_includes := $(my_ndk_stl_include_path) $(my_ndk_sysroot_include)
-else
-  my_target_global_c_includes := $(SRC_HEADERS) \
-    $($(LOCAL_2ND_ARCH_VAR_PREFIX)$(my_prefix)C_INCLUDES)
-  my_target_global_c_system_includes := $(SRC_SYSTEM_HEADERS) \
-    $($(LOCAL_2ND_ARCH_VAR_PREFIX)$(my_prefix)C_SYSTEM_INCLUDES)
-endif
-
 my_target_global_cflags := $($(LOCAL_2ND_ARCH_VAR_PREFIX)CLANG_$(my_prefix)GLOBAL_CFLAGS)
 my_target_global_conlyflags := $($(LOCAL_2ND_ARCH_VAR_PREFIX)CLANG_$(my_prefix)GLOBAL_CONLYFLAGS) $(my_c_std_conlyflags)
 my_target_global_cppflags := $($(LOCAL_2ND_ARCH_VAR_PREFIX)CLANG_$(my_prefix)GLOBAL_CPPFLAGS) $(my_cpp_std_cppflags)
@@ -1654,6 +1641,22 @@ else
   my_target_global_ldflags := $($(LOCAL_2ND_ARCH_VAR_PREFIX)CLANG_$(my_prefix)GLOBAL_LDFLAGS)
 endif # my_use_clang_lld
 
+ifeq ($(call module-in-vendor-or-product),true)
+  my_target_global_c_includes :=
+  my_target_global_c_system_includes := $(TARGET_OUT_HEADERS)
+  my_target_global_cflags += -nostdlibinc
+else ifdef LOCAL_SDK_VERSION
+  my_target_global_c_includes :=
+  my_target_global_c_system_includes := $(my_ndk_stl_include_path)
+  my_target_global_cflags += --sysroot $(my_ndk_sysroot)
+else
+  my_target_global_c_includes := $(SRC_HEADERS) \
+    $($(LOCAL_2ND_ARCH_VAR_PREFIX)$(my_prefix)C_INCLUDES)
+  my_target_global_c_system_includes := $(SRC_SYSTEM_HEADERS) \
+    $($(LOCAL_2ND_ARCH_VAR_PREFIX)$(my_prefix)C_SYSTEM_INCLUDES)
+  my_target_global_cflags += -nostdlibinc
+endif
+
 my_target_triple := $($(LOCAL_2ND_ARCH_VAR_PREFIX)CLANG_$(my_prefix)TRIPLE)
 ifndef LOCAL_IS_HOST_MODULE
   my_target_triple_flag := -target $(my_target_triple)$(my_api_level)
diff --git a/core/board_config.mk b/core/board_config.mk
index 5606964950..859a6b2984 100644
--- a/core/board_config.mk
+++ b/core/board_config.mk
@@ -27,6 +27,7 @@ _board_strip_readonly_list += BOARD_INSTALLER_CMDLINE
 _board_strip_readonly_list += BOARD_KERNEL_CMDLINE
 _board_strip_readonly_list += BOARD_BOOT_HEADER_VERSION
 _board_strip_readonly_list += BOARD_BOOTCONFIG
+_board_strip_readonly_list += BOARD_BOOTCONFIG_FILE
 _board_strip_readonly_list += BOARD_KERNEL_BASE
 _board_strip_readonly_list += BOARD_USES_GENERIC_AUDIO
 _board_strip_readonly_list += BOARD_USES_RECOVERY_AS_BOOT
@@ -224,6 +225,7 @@ else
       $(SRC_TARGET_DIR)/board/$(TARGET_DEVICE)/BoardConfig.mk \
       device/generic/goldfish/board/$(TARGET_DEVICE)/BoardConfig.mk \
       device/google/cuttlefish/board/$(TARGET_DEVICE)/BoardConfig.mk \
+      vendor/google/products/cuttlefish/pixel_watch/board/$(TARGET_DEVICE)/BoardConfig.mk \
       $(shell test -d device && find -L device -maxdepth 4 -path '*/$(TARGET_DEVICE)/BoardConfig.mk') \
       $(shell test -d vendor && find -L vendor -maxdepth 4 -path '*/$(TARGET_DEVICE)/BoardConfig.mk') \
     )))
@@ -288,6 +290,7 @@ $(foreach var,$(_board_true_false_vars), \
     $(error Valid values of $(var) are "true", "false", and "". Not "$($(var))")))
 
 include $(BUILD_SYSTEM)/board_config_wifi.mk
+include $(BUILD_SYSTEM)/board_config_wpa_supplicant.mk
 
 # Set up soong config for "soong_config_value_variable".
 -include vendor/google/build/soong/soong_config_namespace/camera.mk
@@ -311,9 +314,10 @@ endif
 .KATI_READONLY := $(_board_strip_readonly_list)
 
 INTERNAL_KERNEL_CMDLINE := $(BOARD_KERNEL_CMDLINE)
-ifneq (,$(BOARD_BOOTCONFIG))
+ifneq (,$(BOARD_BOOTCONFIG)$(BOARD_BOOTCONFIG_FILE))
   INTERNAL_KERNEL_CMDLINE += bootconfig
   INTERNAL_BOOTCONFIG := $(BOARD_BOOTCONFIG)
+  INTERNAL_BOOTCONFIG_FILE := $(BOARD_BOOTCONFIG_FILE)
 endif
 
 ifneq ($(filter %64,$(TARGET_ARCH)),)
@@ -922,6 +926,18 @@ ifeq ($(PRODUCT_BUILD_PVMFW_IMAGE),true)
 endif
 .KATI_READONLY := BOARD_USES_PVMFWIMAGE
 
+BOARD_USES_DESKTOP_RECOVERY_IMAGE :=
+ifeq ($(PRODUCT_BUILD_DESKTOP_RECOVERY_IMAGE),true)
+  BOARD_USES_DESKTOP_RECOVERY_IMAGE := true
+endif
+.KATI_READONLY := BOARD_USES_DESKTOP_RECOVERY_IMAGE
+
+BOARD_USES_DESKTOP_UPDATE_IMAGE :=
+ifeq ($(PRODUCT_BUILD_DESKTOP_UPDATE_IMAGE),true)
+  BOARD_USES_DESKTOP_UPDATE_IMAGE := true
+endif
+.KATI_READONLY := BOARD_USES_DESKTOP_UPDATE_IMAGE
+
 ###########################################
 # Ensure consistency among TARGET_RECOVERY_UPDATER_LIBS, AB_OTA_UPDATER, and PRODUCT_OTA_FORCE_NON_AB_PACKAGE.
 TARGET_RECOVERY_UPDATER_LIBS ?=
diff --git a/core/board_config_wpa_supplicant.mk b/core/board_config_wpa_supplicant.mk
new file mode 100644
index 0000000000..9ef438e794
--- /dev/null
+++ b/core/board_config_wpa_supplicant.mk
@@ -0,0 +1,88 @@
+#
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
+#
+
+# ###############################################################
+# This file adds wpa_supplicant_8 variables into soong config namespace (`wpa_supplicant_8`)
+# ###############################################################
+
+ifdef BOARD_HOSTAPD_DRIVER
+$(call soong_config_set_bool,wpa_supplicant_8,wpa_build_hostapd,true)
+ifneq ($(BOARD_HOSTAPD_DRIVER),NL80211)
+    $(error BOARD_HOSTAPD_DRIVER set to $(BOARD_HOSTAPD_DRIVER) but current soong expected it should be NL80211 only!)
+endif
+endif
+
+ifdef BOARD_WPA_SUPPLICANT_DRIVER
+ifneq ($(BOARD_WPA_SUPPLICANT_DRIVER),NL80211)
+    $(error BOARD_WPA_SUPPLICANT_DRIVER set to $(BOARD_WPA_SUPPLICANT_DRIVER) but current soong expected it should be NL80211 only!)
+endif
+endif
+
+# This is for CONFIG_DRIVER_NL80211_BRCM, CONFIG_DRIVER_NL80211_SYNA, CONFIG_DRIVER_NL80211_QCA
+# And it is only used for a cflags setting in driver.
+$(call soong_config_set,wpa_supplicant_8,board_wlan_device,$(BOARD_WLAN_DEVICE))
+
+# Belong to CONFIG_IEEE80211AX definition
+ifeq ($(WIFI_FEATURE_HOSTAPD_11AX),true)
+$(call soong_config_set_bool,wpa_supplicant_8,hostapd_11ax,true)
+endif
+
+# Belong to CONFIG_IEEE80211BE definition
+ifeq ($(WIFI_FEATURE_HOSTAPD_11BE),true)
+$(call soong_config_set_bool,wpa_supplicant_8,hostapd_11be,true)
+endif
+
+# PLATFORM_VERSION
+$(call soong_config_set,wpa_supplicant_8,platform_version,$(PLATFORM_VERSION))
+
+# BOARD_HOSTAPD_PRIVATE_LIB
+ifeq ($(BOARD_HOSTAPD_PRIVATE_LIB),)
+$(call soong_config_set_bool,wpa_supplicant_8,hostapd_use_stub_lib,true)
+else
+$(call soong_config_set,wpa_supplicant_8,board_hostapd_private_lib,$(BOARD_HOSTAPD_PRIVATE_LIB))
+endif
+
+ifeq ($(BOARD_HOSTAPD_CONFIG_80211W_MFP_OPTIONAL),true)
+$(call soong_config_set_bool,wpa_supplicant_8,board_hostapd_config_80211w_mfp_optional,true)
+endif
+
+ifneq ($(BOARD_HOSTAPD_PRIVATE_LIB_EVENT),)
+$(call soong_config_set_bool,wpa_supplicant_8,board_hostapd_private_lib_event,true)
+endif
+
+# BOARD_WPA_SUPPLICANT_PRIVATE_LIB
+ifeq ($(BOARD_WPA_SUPPLICANT_PRIVATE_LIB),)
+$(call soong_config_set_bool,wpa_supplicant_8,wpa_supplicant_use_stub_lib,true)
+else
+$(call soong_config_set,wpa_supplicant_8,board_wpa_supplicant_private_lib,$(BOARD_WPA_SUPPLICANT_PRIVATE_LIB))
+endif
+
+ifneq ($(BOARD_WPA_SUPPLICANT_PRIVATE_LIB_EVENT),)
+$(call soong_config_set_bool,wpa_supplicant_8,board_wpa_supplicant_private_lib_event,true)
+endif
+
+ifeq ($(WIFI_PRIV_CMD_UPDATE_MBO_CELL_STATUS), enabled)
+$(call soong_config_set_bool,wpa_supplicant_8,wifi_priv_cmd_update_mbo_cell_status,true)
+endif
+
+ifeq ($(WIFI_HIDL_UNIFIED_SUPPLICANT_SERVICE_RC_ENTRY), true)
+$(call soong_config_set_bool,wpa_supplicant_8,wifi_hidl_unified_supplicant_service_rc_entry,true)
+endif
+
+# New added in internal main
+ifeq ($(WIFI_BRCM_OPEN_SOURCE_MULTI_AKM), enabled)
+$(call soong_config_set_bool,wpa_supplicant_8,wifi_brcm_open_source_multi_akm,true)
+endif
diff --git a/core/build_id.mk b/core/build_id.mk
index 2985f87658..427c4526f3 100644
--- a/core/build_id.mk
+++ b/core/build_id.mk
@@ -18,4 +18,4 @@
 # (like "CRB01").  It must be a single word, and is
 # capitalized by convention.
 
-BUILD_ID=AP4A.250205.002.C1
+BUILD_ID=BP1A.250305.019
diff --git a/core/combo/arch/x86/alderlake.mk b/core/combo/arch/x86/alderlake.mk
new file mode 100644
index 0000000000..a7ae6ed679
--- /dev/null
+++ b/core/combo/arch/x86/alderlake.mk
@@ -0,0 +1,6 @@
+# Configuration for Linux on x86.
+# Generating binaries for processors
+# that have AVX2 feature flag
+#
+
+ARCH_X86_HAVE_SSE4_1 := true
diff --git a/core/combo/arch/x86_64/alderlake.mk b/core/combo/arch/x86_64/alderlake.mk
new file mode 100644
index 0000000000..a7ae6ed679
--- /dev/null
+++ b/core/combo/arch/x86_64/alderlake.mk
@@ -0,0 +1,6 @@
+# Configuration for Linux on x86.
+# Generating binaries for processors
+# that have AVX2 feature flag
+#
+
+ARCH_X86_HAVE_SSE4_1 := true
diff --git a/core/config.mk b/core/config.mk
index 192c8b28c8..d62b86dda5 100644
--- a/core/config.mk
+++ b/core/config.mk
@@ -330,6 +330,18 @@ $(eval SOONG_CONFIG_$(strip $1)_$(strip $2):=$(filter true,$3))
 $(eval SOONG_CONFIG_TYPE_$(strip $1)_$(strip $2):=bool)
 endef
 
+# soong_config_set_string_list is the same as soong_config_set, but it will
+# also type the variable as a list of strings, so that when using select() expressions
+# in blueprint files they can use list values instead of strings.
+# The values of the list must be space-separated.
+# $1 is the namespace. $2 is the variable name. $3 is the variable value.
+# Ex: $(call soong_config_set_string_list,acme,COOL_LIBS,a b)
+define soong_config_set_string_list
+$(call soong_config_define_internal,$1,$2) \
+$(eval SOONG_CONFIG_$(strip $1)_$(strip $2):=$(strip $3))
+$(eval SOONG_CONFIG_TYPE_$(strip $1)_$(strip $2):=string_list)
+endef
+
 # soong_config_append appends to the value of the variable in the given Soong
 # config namespace. If the variable does not exist, it will be defined. If the
 # namespace does not  exist, it will be defined.
@@ -432,13 +444,6 @@ else
 endif
 .KATI_READONLY := TARGET_MAX_PAGE_SIZE_SUPPORTED
 
-ifdef PRODUCT_CHECK_PREBUILT_MAX_PAGE_SIZE
-  TARGET_CHECK_PREBUILT_MAX_PAGE_SIZE := $(PRODUCT_CHECK_PREBUILT_MAX_PAGE_SIZE)
-else
-  TARGET_CHECK_PREBUILT_MAX_PAGE_SIZE := false
-endif
-.KATI_READONLY := TARGET_CHECK_PREBUILT_MAX_PAGE_SIZE
-
 # Boolean variable determining if AOSP relies on bionic's PAGE_SIZE macro.
 ifdef PRODUCT_NO_BIONIC_PAGE_SIZE_MACRO
   TARGET_NO_BIONIC_PAGE_SIZE_MACRO := $(PRODUCT_NO_BIONIC_PAGE_SIZE_MACRO)
@@ -817,6 +822,18 @@ ifneq ($(call math_gt_or_eq,$(PRODUCT_SHIPPING_API_LEVEL),36),)
   endif
 endif
 
+ifdef PRODUCT_CHECK_PREBUILT_MAX_PAGE_SIZE
+  TARGET_CHECK_PREBUILT_MAX_PAGE_SIZE := $(PRODUCT_CHECK_PREBUILT_MAX_PAGE_SIZE)
+else ifeq (true,$(TARGET_BUILD_UNBUNDLED))
+  # unbundled builds may not have updated build sources
+  TARGET_CHECK_PREBUILT_MAX_PAGE_SIZE := false
+else ifneq ($(call math_gt_or_eq,$(PRODUCT_SHIPPING_API_LEVEL),36),)
+  TARGET_CHECK_PREBUILT_MAX_PAGE_SIZE := true
+else
+  TARGET_CHECK_PREBUILT_MAX_PAGE_SIZE := false
+endif
+.KATI_READONLY := TARGET_CHECK_PREBUILT_MAX_PAGE_SIZE
+
 # Set BOARD_SYSTEMSDK_VERSIONS to the latest SystemSDK version starting from P-launching
 # devices if unset.
 ifndef BOARD_SYSTEMSDK_VERSIONS
@@ -839,12 +856,6 @@ endif
 .KATI_READONLY := BOARD_CURRENT_API_LEVEL_FOR_VENDOR_MODULES
 
 ifdef PRODUCT_SHIPPING_API_LEVEL
-  board_api_level := $(firstword $(BOARD_API_LEVEL) $(BOARD_SHIPPING_API_LEVEL))
-  ifneq (,$(board_api_level))
-    min_systemsdk_version := $(call math_min,$(board_api_level),$(PRODUCT_SHIPPING_API_LEVEL))
-  else
-    min_systemsdk_version := $(PRODUCT_SHIPPING_API_LEVEL)
-  endif
   ifneq ($(call math_gt_or_eq,$(PRODUCT_SHIPPING_API_LEVEL),29),)
     ifneq ($(BOARD_OTA_FRAMEWORK_VBMETA_VERSION_OVERRIDE),)
       $(error When PRODUCT_SHIPPING_API_LEVEL >= 29, BOARD_OTA_FRAMEWORK_VBMETA_VERSION_OVERRIDE cannot be set)
@@ -895,6 +906,11 @@ PLATFORM_SEPOLICY_COMPAT_VERSIONS := $(filter-out $(PLATFORM_SEPOLICY_VERSION),
     PLATFORM_SEPOLICY_COMPAT_VERSIONS \
     PLATFORM_SEPOLICY_VERSION \
 
+BOARD_GENFS_LABELS_VERSION ?= $(BOARD_API_LEVEL)
+ifeq ($(call math_gt,$(BOARD_API_LEVEL),$(BOARD_GENFS_LABELS_VERSION)),true)
+  $(error BOARD_GENFS_LABELS_VERSION ($(BOARD_GENFS_LABELS_VERSION)) must be greater than or equal to BOARD_API_LEVEL ($(BOARD_API_LEVEL)))
+endif
+
 ifeq ($(PRODUCT_RETROFIT_DYNAMIC_PARTITIONS),true)
   ifneq ($(PRODUCT_USE_DYNAMIC_PARTITIONS),true)
     $(error PRODUCT_USE_DYNAMIC_PARTITIONS must be true when PRODUCT_RETROFIT_DYNAMIC_PARTITIONS \
@@ -1303,10 +1319,6 @@ endif
 SOONG_VARIABLES :=
 SOONG_EXTRA_VARIABLES :=
 
--include external/ltp/android/ltp_package_list.mk
-DEFAULT_DATA_OUT_MODULES := ltp $(ltp_packages)
-.KATI_READONLY := DEFAULT_DATA_OUT_MODULES
-
 include $(BUILD_SYSTEM)/dumpvar.mk
 
 ifdef BOARD_VNDK_VERSION
diff --git a/core/definitions.mk b/core/definitions.mk
index cd1b36e4c7..adb35e07ca 100644
--- a/core/definitions.mk
+++ b/core/definitions.mk
@@ -2605,7 +2605,87 @@ define dump-words-to-file
         @$(call emit-line,$(wordlist 108501,109000,$(1)),$(2))
         @$(call emit-line,$(wordlist 109001,109500,$(1)),$(2))
         @$(call emit-line,$(wordlist 109501,110000,$(1)),$(2))
-        @$(if $(wordlist 110001,110002,$(1)),$(error dump-words-to-file: Too many words ($(words $(1)))))
+        @$(call emit-line,$(wordlist 110001,110500,$(1)),$(2))
+        @$(call emit-line,$(wordlist 110501,111000,$(1)),$(2))
+        @$(call emit-line,$(wordlist 111001,111500,$(1)),$(2))
+        @$(call emit-line,$(wordlist 111501,112000,$(1)),$(2))
+        @$(call emit-line,$(wordlist 112001,112500,$(1)),$(2))
+        @$(call emit-line,$(wordlist 112501,113000,$(1)),$(2))
+        @$(call emit-line,$(wordlist 113001,113500,$(1)),$(2))
+        @$(call emit-line,$(wordlist 113501,114000,$(1)),$(2))
+        @$(call emit-line,$(wordlist 114001,114500,$(1)),$(2))
+        @$(call emit-line,$(wordlist 114501,115000,$(1)),$(2))
+        @$(call emit-line,$(wordlist 115001,115500,$(1)),$(2))
+        @$(call emit-line,$(wordlist 115501,116000,$(1)),$(2))
+        @$(call emit-line,$(wordlist 116001,116500,$(1)),$(2))
+        @$(call emit-line,$(wordlist 116501,117000,$(1)),$(2))
+        @$(call emit-line,$(wordlist 117001,117500,$(1)),$(2))
+        @$(call emit-line,$(wordlist 117501,118000,$(1)),$(2))
+        @$(call emit-line,$(wordlist 118001,118500,$(1)),$(2))
+        @$(call emit-line,$(wordlist 118501,119000,$(1)),$(2))
+        @$(call emit-line,$(wordlist 119001,119500,$(1)),$(2))
+        @$(call emit-line,$(wordlist 119501,120000,$(1)),$(2))
+        @$(call emit-line,$(wordlist 120001,120500,$(1)),$(2))
+        @$(call emit-line,$(wordlist 120501,121000,$(1)),$(2))
+        @$(call emit-line,$(wordlist 121001,121500,$(1)),$(2))
+        @$(call emit-line,$(wordlist 121501,122000,$(1)),$(2))
+        @$(call emit-line,$(wordlist 122001,122500,$(1)),$(2))
+        @$(call emit-line,$(wordlist 122501,123000,$(1)),$(2))
+        @$(call emit-line,$(wordlist 123001,123500,$(1)),$(2))
+        @$(call emit-line,$(wordlist 123501,124000,$(1)),$(2))
+        @$(call emit-line,$(wordlist 124001,124500,$(1)),$(2))
+        @$(call emit-line,$(wordlist 124501,125000,$(1)),$(2))
+        @$(call emit-line,$(wordlist 125001,125500,$(1)),$(2))
+        @$(call emit-line,$(wordlist 125501,126000,$(1)),$(2))
+        @$(call emit-line,$(wordlist 126001,126500,$(1)),$(2))
+        @$(call emit-line,$(wordlist 126501,127000,$(1)),$(2))
+        @$(call emit-line,$(wordlist 127001,127500,$(1)),$(2))
+        @$(call emit-line,$(wordlist 127501,128000,$(1)),$(2))
+        @$(call emit-line,$(wordlist 128001,128500,$(1)),$(2))
+        @$(call emit-line,$(wordlist 128501,129000,$(1)),$(2))
+        @$(call emit-line,$(wordlist 129001,129500,$(1)),$(2))
+        @$(call emit-line,$(wordlist 129501,130000,$(1)),$(2))
+        @$(call emit-line,$(wordlist 130001,130500,$(1)),$(2))
+        @$(call emit-line,$(wordlist 130501,131000,$(1)),$(2))
+        @$(call emit-line,$(wordlist 131001,131500,$(1)),$(2))
+        @$(call emit-line,$(wordlist 131501,132000,$(1)),$(2))
+        @$(call emit-line,$(wordlist 132001,132500,$(1)),$(2))
+        @$(call emit-line,$(wordlist 132501,133000,$(1)),$(2))
+        @$(call emit-line,$(wordlist 133001,133500,$(1)),$(2))
+        @$(call emit-line,$(wordlist 133501,134000,$(1)),$(2))
+        @$(call emit-line,$(wordlist 134001,134500,$(1)),$(2))
+        @$(call emit-line,$(wordlist 134501,135000,$(1)),$(2))
+        @$(call emit-line,$(wordlist 135001,135500,$(1)),$(2))
+        @$(call emit-line,$(wordlist 135501,136000,$(1)),$(2))
+        @$(call emit-line,$(wordlist 136001,136500,$(1)),$(2))
+        @$(call emit-line,$(wordlist 136501,137000,$(1)),$(2))
+        @$(call emit-line,$(wordlist 137001,137500,$(1)),$(2))
+        @$(call emit-line,$(wordlist 137501,138000,$(1)),$(2))
+        @$(call emit-line,$(wordlist 138001,138500,$(1)),$(2))
+        @$(call emit-line,$(wordlist 138501,139000,$(1)),$(2))
+        @$(call emit-line,$(wordlist 139001,139500,$(1)),$(2))
+        @$(call emit-line,$(wordlist 139501,140000,$(1)),$(2))
+        @$(call emit-line,$(wordlist 140001,140500,$(1)),$(2))
+        @$(call emit-line,$(wordlist 140501,141000,$(1)),$(2))
+        @$(call emit-line,$(wordlist 141001,141500,$(1)),$(2))
+        @$(call emit-line,$(wordlist 141501,142000,$(1)),$(2))
+        @$(call emit-line,$(wordlist 142001,142500,$(1)),$(2))
+        @$(call emit-line,$(wordlist 142501,143000,$(1)),$(2))
+        @$(call emit-line,$(wordlist 143001,143500,$(1)),$(2))
+        @$(call emit-line,$(wordlist 143501,144000,$(1)),$(2))
+        @$(call emit-line,$(wordlist 144001,144500,$(1)),$(2))
+        @$(call emit-line,$(wordlist 144501,145000,$(1)),$(2))
+        @$(call emit-line,$(wordlist 145001,145500,$(1)),$(2))
+        @$(call emit-line,$(wordlist 145501,146000,$(1)),$(2))
+        @$(call emit-line,$(wordlist 146001,146500,$(1)),$(2))
+        @$(call emit-line,$(wordlist 146501,147000,$(1)),$(2))
+        @$(call emit-line,$(wordlist 147001,147500,$(1)),$(2))
+        @$(call emit-line,$(wordlist 147501,148000,$(1)),$(2))
+        @$(call emit-line,$(wordlist 148001,148500,$(1)),$(2))
+        @$(call emit-line,$(wordlist 148501,149000,$(1)),$(2))
+        @$(call emit-line,$(wordlist 149001,149500,$(1)),$(2))
+        @$(call emit-line,$(wordlist 149501,150000,$(1)),$(2))
+        @$(if $(wordlist 150001,150002,$(1)),$(error dump-words-to-file: Too many words ($(words $(1)))))
 endef
 # Return jar arguments to compress files in a given directory
 # $(1): directory
diff --git a/core/dex_preopt.mk b/core/dex_preopt.mk
index 906d7f0163..88e0cc7452 100644
--- a/core/dex_preopt.mk
+++ b/core/dex_preopt.mk
@@ -13,28 +13,6 @@ else
 install-on-system-other = $(filter-out $(PRODUCT_DEXPREOPT_SPEED_APPS) $(PRODUCT_SYSTEM_SERVER_APPS),$(basename $(notdir $(filter $(foreach f,$(SYSTEM_OTHER_ODEX_FILTER),$(TARGET_OUT)/$(f)),$(1)))))
 endif
 
-# Install boot images for testing on host. We exclude framework image as it is not part of art manifest.
-my_boot_image_arch := HOST_ARCH
-my_boot_image_out := $(HOST_OUT)
-my_boot_image_syms := $(HOST_OUT)/symbols
-HOST_BOOT_IMAGE_MODULE := \
-  $(foreach my_boot_image_name,art_host,$(strip \
-    $(eval include $(BUILD_SYSTEM)/dex_preopt_libart.mk) \
-    $(my_boot_image_module)))
-HOST_BOOT_IMAGE := $(call module-installed-files,$(HOST_BOOT_IMAGE_MODULE))
-ifdef HOST_2ND_ARCH
-  my_boot_image_arch := HOST_2ND_ARCH
-  2ND_HOST_BOOT_IMAGE_MODULE := \
-    $(foreach my_boot_image_name,art_host,$(strip \
-      $(eval include $(BUILD_SYSTEM)/dex_preopt_libart.mk) \
-      $(my_boot_image_module)))
-  2ND_HOST_BOOT_IMAGE := $(call module-installed-files,$(2ND_HOST_BOOT_IMAGE_MODULE))
-endif
-my_boot_image_arch :=
-my_boot_image_out :=
-my_boot_image_syms :=
-my_boot_image_module :=
-
 # Build the boot.zip which contains the boot jars and their compilation output
 # We can do this only if preopt is enabled and if the product uses libart config (which sets the
 # default properties for preopting).
diff --git a/core/dex_preopt_libart.mk b/core/dex_preopt_libart.mk
deleted file mode 100644
index a2c9942a41..0000000000
--- a/core/dex_preopt_libart.mk
+++ /dev/null
@@ -1,109 +0,0 @@
-####################################
-# ART boot image installation
-# Input variables:
-#   my_boot_image_name: the boot image to install
-#   my_boot_image_arch: the architecture to install (e.g. TARGET_ARCH, not expanded)
-#   my_boot_image_out:  the install directory (e.g. $(PRODUCT_OUT))
-#   my_boot_image_syms: the symbols director (e.g. $(TARGET_OUT_UNSTRIPPED))
-#
-# Output variables:
-#   my_boot_image_module: the created module name. Empty if no module is created.
-#
-# Install the boot images compiled by Soong.
-# Create a module named dexpreopt_bootjar.$(my_boot_image_name)_$($(my_boot_image_arch))
-# that installs all of boot image files.
-# If there is no file to install for $(my_boot_image_name), for example when
-# building an unbundled build, then no module is created.
-#
-####################################
-
-# Takes a list of src:dest install pairs and returns a new list with a path
-# prefixed to each dest value.
-# $(1): list of src:dest install pairs
-# $(2): path to prefix to each dest value
-define prefix-copy-many-files-dest
-$(foreach v,$(1),$(call word-colon,1,$(v)):$(2)$(call word-colon,2,$(v)))
-endef
-
-# Converts an architecture-specific vdex path into a location that can be shared
-# between architectures.
-define vdex-shared-install-path
-$(dir $(patsubst %/,%,$(dir $(1))))$(notdir $(1))
-endef
-
-# Takes a list of src:dest install pairs of vdex files and returns a new list
-# where each dest has been rewritten to the shared location for vdex files.
-define vdex-copy-many-files-shared-dest
-$(foreach v,$(1),$(call word-colon,1,$(v)):$(call vdex-shared-install-path,$(call word-colon,2,$(v))))
-endef
-
-# Creates a rule to symlink an architecture specific vdex file to the shared
-# location for that vdex file.
-define symlink-vdex-file
-$(strip \
-  $(call symlink-file,\
-    $(call vdex-shared-install-path,$(1)),\
-    ../$(notdir $(1)),\
-    $(1))\
-  $(1))
-endef
-
-# Takes a list of src:dest install pairs of vdex files and creates rules to
-# symlink each dest to the shared location for that vdex file.
-define symlink-vdex-files
-$(foreach v,$(1),$(call symlink-vdex-file,$(call word-colon,2,$(v))))
-endef
-
-my_boot_image_module :=
-
-my_suffix := $(my_boot_image_name)_$($(my_boot_image_arch))
-my_copy_pairs := $(call prefix-copy-many-files-dest,$(DEXPREOPT_IMAGE_BUILT_INSTALLED_$(my_suffix)),$(my_boot_image_out))
-my_vdex_copy_pairs := $(call prefix-copy-many-files-dest,$(DEXPREOPT_IMAGE_VDEX_BUILT_INSTALLED_$(my_suffix)),$(my_boot_image_out))
-my_vdex_copy_shared_pairs := $(call vdex-copy-many-files-shared-dest,$(my_vdex_copy_pairs))
-ifeq (,$(filter %_2ND_ARCH,$(my_boot_image_arch)))
-  # Only install the vdex to the shared location for the primary architecture.
-  my_copy_pairs += $(my_vdex_copy_shared_pairs)
-endif
-
-my_unstripped_copy_pairs := $(call prefix-copy-many-files-dest,$(DEXPREOPT_IMAGE_UNSTRIPPED_BUILT_INSTALLED_$(my_suffix)),$(my_boot_image_syms))
-
-# Generate the boot image module only if there is any file to install.
-ifneq (,$(strip $(my_copy_pairs)))
-  my_first_pair := $(firstword $(my_copy_pairs))
-  my_rest_pairs := $(wordlist 2,$(words $(my_copy_pairs)),$(my_copy_pairs))
-
-  my_first_src := $(call word-colon,1,$(my_first_pair))
-  my_first_dest := $(call word-colon,2,$(my_first_pair))
-
-  my_installed := $(call copy-many-files,$(my_copy_pairs))
-  my_unstripped_installed := $(call copy-many-files,$(my_unstripped_copy_pairs))
-
-  my_symlinks := $(call symlink-vdex-files,$(my_vdex_copy_pairs))
-
-  # We don't have a LOCAL_PATH for the auto-generated modules, so let it be the $(BUILD_SYSTEM).
-  LOCAL_PATH := $(BUILD_SYSTEM)
-  # Hack to let these pseudo-modules wrapped around Soong modules use LOCAL_SOONG_INSTALLED_MODULE.
-  LOCAL_MODULE_MAKEFILE := $(SOONG_ANDROID_MK)
-
-  include $(CLEAR_VARS)
-  LOCAL_MODULE := dexpreopt_bootjar.$(my_suffix)
-  LOCAL_PREBUILT_MODULE_FILE := $(my_first_src)
-  LOCAL_MODULE_PATH := $(dir $(my_first_dest))
-  LOCAL_MODULE_STEM := $(notdir $(my_first_dest))
-  LOCAL_SOONG_INSTALL_PAIRS := $(my_copy_pairs)
-  LOCAL_SOONG_INSTALL_SYMLINKS := $(my_symlinks)
-  LOCAL_SOONG_INSTALLED_MODULE := $(my_first_dest)
-  LOCAL_SOONG_LICENSE_METADATA := $(DEXPREOPT_IMAGE_LICENSE_METADATA_$(my_suffix))
-  ifneq (,$(strip $(filter HOST_%,$(my_boot_image_arch))))
-    LOCAL_IS_HOST_MODULE := true
-  endif
-  LOCAL_MODULE_CLASS := ETC
-  include $(BUILD_PREBUILT)
-  $(LOCAL_BUILT_MODULE): | $(my_unstripped_installed)
-  # Installing boot.art causes all boot image bits to be installed.
-  # Keep this old behavior in case anyone still needs it.
-  $(LOCAL_INSTALLED_MODULE): $(wordlist 2,$(words $(my_installed)),$(my_installed)) $(my_symlinks)
-  $(my_all_targets): $(my_installed) $(my_symlinks)
-
-  my_boot_image_module := $(LOCAL_MODULE)
-endif  # my_copy_pairs != empty
diff --git a/core/java_common.mk b/core/java_common.mk
index a21f062029..f574b7623e 100644
--- a/core/java_common.mk
+++ b/core/java_common.mk
@@ -32,7 +32,7 @@ ifeq (,$(LOCAL_JAVA_LANGUAGE_VERSION))
     else ifneq (,$(LOCAL_SDK_VERSION)$(TARGET_BUILD_USE_PREBUILT_SDKS))
       # TODO(ccross): allow 1.9 for current and unbundled once we have SDK system modules
       LOCAL_JAVA_LANGUAGE_VERSION := 1.8
-    else ifeq ($(EXPERIMENTAL_TARGET_JAVA_VERSION_21),true)
+    else ifeq ($(RELEASE_TARGET_JAVA_21),true)
       LOCAL_JAVA_LANGUAGE_VERSION := 21
     else
       LOCAL_JAVA_LANGUAGE_VERSION := 17
diff --git a/core/layoutlib_data.mk b/core/layoutlib_data.mk
index e420a004de..f228ef65b6 100644
--- a/core/layoutlib_data.mk
+++ b/core/layoutlib_data.mk
@@ -3,11 +3,10 @@
 FONT_TEMP := $(call intermediates-dir-for,PACKAGING,fonts,HOST,COMMON)
 
 # The font configuration files - system_fonts.xml, fallback_fonts.xml etc.
-font_config := $(sort $(wildcard frameworks/base/data/fonts/*.xml))
+font_config := $(filter $(TARGET_OUT)/etc/font%.xml, $(INTERNAL_SYSTEMIMAGE_FILES))
 font_config := $(addprefix $(FONT_TEMP)/, $(notdir $(font_config)))
 
-$(font_config): $(FONT_TEMP)/%.xml: \
-			frameworks/base/data/fonts/%.xml
+$(font_config): $(FONT_TEMP)/%: $(TARGET_OUT)/etc/%
 	$(hide) mkdir -p $(dir $@)
 	$(hide) cp -vf $< $@
 
@@ -31,8 +30,18 @@ $(keyboards): $(KEYBOARD_TEMP)/%.kcm: frameworks/base/data/keyboards/%.kcm
 	$(hide) mkdir -p $(dir $@)
 	$(hide) cp -vf $< $@
 
-# List of all data files - font files, font configuration files, key character map files
-LAYOUTLIB_FILES := $(fonts_device) $(font_config) $(keyboards)
+HYPHEN_TEMP := $(call intermediates-dir-for,PACKAGING,hyphen,HOST,COMMON)
+
+# The hyphenation pattern files needed to support text hyphenation
+hyphen := $(filter $(TARGET_OUT)/usr/hyphen-data/%.hyb, $(INTERNAL_SYSTEMIMAGE_FILES))
+hyphen := $(addprefix $(HYPHEN_TEMP)/, $(notdir $(hyphen)))
+
+$(hyphen): $(HYPHEN_TEMP)/%: $(TARGET_OUT)/usr/hyphen-data/%
+	$(hide) mkdir -p $(dir $@)
+	$(hide) cp -vf $< $@
+
+# List of all data files - font files, font configuration files, key character map files, hyphenation pattern files
+LAYOUTLIB_FILES := $(fonts_device) $(font_config) $(keyboards) $(hyphen)
 
 .PHONY: layoutlib layoutlib-tests
 layoutlib layoutlib-tests: $(LAYOUTLIB_FILES)
@@ -40,6 +49,7 @@ layoutlib layoutlib-tests: $(LAYOUTLIB_FILES)
 $(call dist-for-goals, layoutlib, $(foreach m,$(fonts_device), $(m):layoutlib_native/fonts/$(notdir $(m))))
 $(call dist-for-goals, layoutlib, $(foreach m,$(font_config), $(m):layoutlib_native/fonts/$(notdir $(m))))
 $(call dist-for-goals, layoutlib, $(foreach m,$(keyboards), $(m):layoutlib_native/keyboards/$(notdir $(m))))
+$(call dist-for-goals, layoutlib, $(foreach m,$(hyphen), $(m):layoutlib_native/hyphen-data/$(notdir $(m))))
 
 FONT_TEMP :=
 font_config :=
@@ -95,6 +105,7 @@ LAYOUTLIB_SBOM := $(call intermediates-dir-for,PACKAGING,layoutlib-sbom,HOST)
 _layoutlib_font_config_files := $(sort $(wildcard frameworks/base/data/fonts/*.xml))
 _layoutlib_fonts_files := $(filter $(TARGET_OUT)/fonts/%.ttf $(TARGET_OUT)/fonts/%.ttc $(TARGET_OUT)/fonts/%.otf, $(INTERNAL_SYSTEMIMAGE_FILES))
 _layoutlib_keyboard_files := $(sort $(wildcard frameworks/base/data/keyboards/*.kcm))
+_layoutlib_hyphen_files := $(filter $(TARGET_OUT)/usr/hyphen-data/%.hyb, $(INTERNAL_SYSTEMIMAGE_FILES))
 
 # Find out files disted with layoutlib in Soong.
 ### Filter out static libraries for Windows and files already handled in make.
@@ -124,6 +135,13 @@ $(LAYOUTLIB_SBOM)/sbom-metadata.csv:
 	  echo data/keyboards/$(notdir $f),frameworks/base/data/keyboards,prebuilt_etc,,,,,$f,,, >> $@; \
 	)
 
+	$(foreach f,$(_layoutlib_hyphen_files), \
+	  $(eval _module_name := $(ALL_INSTALLED_FILES.$f)) \
+	  $(eval _module_path := $(strip $(sort $(ALL_MODULES.$(_module_name).PATH)))) \
+	  $(eval _soong_module_type := $(strip $(sort $(ALL_MODULES.$(_module_name).SOONG_MODULE_TYPE)))) \
+	  echo data/hyphen-data/$(notdir $f),$(_module_path),$(_soong_module_type),,,,,$f,,, >> $@; \
+	)
+
 	$(foreach f,$(_layoutlib_files_disted_by_soong), \
 	  $(eval _prebuilt_module_file := $(call word-colon,1,$f)) \
 	  $(eval _dist_file := $(call word-colon,2,$f)) \
@@ -152,7 +170,7 @@ $(LAYOUTLIB_SBOM)/sbom-metadata.csv:
 
 .PHONY: layoutlib-sbom
 layoutlib-sbom: $(LAYOUTLIB_SBOM)/layoutlib.spdx.json
-$(LAYOUTLIB_SBOM)/layoutlib.spdx.json: $(PRODUCT_OUT)/always_dirty_file.txt $(GEN_SBOM) $(LAYOUTLIB_SBOM)/sbom-metadata.csv $(_layoutlib_font_config_files) $(_layoutlib_fonts_files) $(LAYOUTLIB_BUILD_PROP)/layoutlib-build.prop $(_layoutlib_keyboard_files) $(LAYOUTLIB_RES_FILES) $(EMULATED_OVERLAYS_FILES) $(DEVICE_OVERLAYS_FILES)
+$(LAYOUTLIB_SBOM)/layoutlib.spdx.json: $(PRODUCT_OUT)/always_dirty_file.txt $(GEN_SBOM) $(LAYOUTLIB_SBOM)/sbom-metadata.csv $(_layoutlib_font_config_files) $(_layoutlib_fonts_files) $(LAYOUTLIB_BUILD_PROP)/layoutlib-build.prop $(_layoutlib_keyboard_files) $(_layoutlib_hyphen_files) $(LAYOUTLIB_RES_FILES) $(EMULATED_OVERLAYS_FILES) $(DEVICE_OVERLAYS_FILES)
 	rm -rf $@
 	$(GEN_SBOM) --output_file $@ --metadata $(LAYOUTLIB_SBOM)/sbom-metadata.csv --build_version $(BUILD_FINGERPRINT_FROM_FILE) --product_mfr "$(PRODUCT_MANUFACTURER)" --module_name "layoutlib" --json
 
diff --git a/core/main.mk b/core/main.mk
index e5f5b9d2c6..7c07f9d107 100644
--- a/core/main.mk
+++ b/core/main.mk
@@ -83,6 +83,8 @@ $(shell mkdir -p $(EMPTY_DIRECTORY) && rm -rf $(EMPTY_DIRECTORY)/*)
 -include test/cts-root/tools/build/config.mk
 # WVTS-specific config.
 -include test/wvts/tools/build/config.mk
+# DTS-specific config.
+-include test/dts/tools/build/config.mk
 
 
 # Clean rules
@@ -275,11 +277,24 @@ FULL_BUILD := true
 # Include all of the makefiles in the system
 #
 
-subdir_makefiles := $(SOONG_OUT_DIR)/installs-$(TARGET_PRODUCT)$(COVERAGE_SUFFIX).mk $(SOONG_ANDROID_MK)
+subdir_makefiles := \
+    $(SOONG_OUT_DIR)/installs-$(TARGET_PRODUCT)$(COVERAGE_SUFFIX).mk \
+    $(SOONG_ANDROID_MK) \
+    build/make/target/board/android-info.mk
 
 # Android.mk files are only used on Linux builds, Mac only supports Android.bp
 ifeq ($(HOST_OS),linux)
-  subdir_makefiles += $(file <$(OUT_DIR)/.module_paths/Android.mk.list)
+  ifeq ($(PRODUCT_IGNORE_ALL_ANDROIDMK),true)
+    allowed_androidmk_files :=
+    ifdef PRODUCT_ANDROIDMK_ALLOWLIST_FILE
+      -include $(PRODUCT_ANDROIDMK_ALLOWLIST_FILE)
+    endif
+    allowed_androidmk_files += $(PRODUCT_ALLOWED_ANDROIDMK_FILES)
+    subdir_makefiles += $(filter $(allowed_androidmk_files),$(file <$(OUT_DIR)/.module_paths/Android.mk.list))
+    allowed_androidmk_files :=
+  else
+    subdir_makefiles += $(file <$(OUT_DIR)/.module_paths/Android.mk.list)
+  endif
 endif
 
 subdir_makefiles += $(SOONG_OUT_DIR)/late-$(TARGET_PRODUCT)$(COVERAGE_SUFFIX).mk
@@ -290,7 +305,7 @@ subdir_makefiles_total := $(words int $(subdir_makefiles) post finish)
 $(foreach mk,$(subdir_makefiles),$(info [$(call inc_and_print,subdir_makefiles_inc)/$(subdir_makefiles_total)] including $(mk) ...)$(eval include $(mk)))
 
 # Build bootloader.img/radio.img, and unpack the partitions.
-include $(BUILD_SYSTEM)/tasks/tools/update_bootloader_radio_image.mk
+-include vendor/google_devices/$(TARGET_SOC)/prebuilts/misc_bins/update_bootloader_radio_image.mk
 
 # For an unbundled image, we can skip blueprint_tools because unbundled image
 # aims to remove a large number framework projects from the manifest, the
@@ -981,8 +996,8 @@ endef
 # Returns modules included automatically as a result of certain BoardConfig
 # variables being set.
 define auto-included-modules
-  llndk_in_system \
-  $(if $(DEVICE_MANIFEST_FILE),vendor_manifest.xml) \
+  $(foreach vndk_ver,$(PRODUCT_EXTRA_VNDK_VERSIONS),com.android.vndk.v$(vndk_ver)) \
+  llndk.libraries.txt \
   $(if $(DEVICE_MANIFEST_SKUS),$(foreach sku, $(DEVICE_MANIFEST_SKUS),vendor_manifest_$(sku).xml)) \
   $(if $(ODM_MANIFEST_FILES),odm_manifest.xml) \
   $(if $(ODM_MANIFEST_SKUS),$(foreach sku, $(ODM_MANIFEST_SKUS),odm_manifest_$(sku).xml)) \
@@ -1384,6 +1399,7 @@ droidcore-unbundled: $(filter $(HOST_OUT_ROOT)/%,$(modules_to_install)) \
     $(INSTALLED_RAMDISK_TARGET) \
     $(INSTALLED_BOOTIMAGE_TARGET) \
     $(INSTALLED_INIT_BOOT_IMAGE_TARGET) \
+    $(INSTALLED_DTBOIMAGE_TARGET) \
     $(INSTALLED_RADIOIMAGE_TARGET) \
     $(INSTALLED_DEBUG_RAMDISK_TARGET) \
     $(INSTALLED_DEBUG_BOOTIMAGE_TARGET) \
@@ -1899,7 +1915,6 @@ $(SOONG_OUT_DIR)/compliance-metadata/$(TARGET_PRODUCT)/make-metadata.csv:
 	  $(eval _kernel_module_copy_files := $(sort $(filter %$(_path_on_device),$(KERNEL_MODULE_COPY_FILES)))) \
 	  $(eval _is_build_prop := $(call is-build-prop,$f)) \
 	  $(eval _is_notice_file := $(call is-notice-file,$f)) \
-	  $(eval _is_dexpreopt_image_profile := $(if $(filter %:/$(_path_on_device),$(DEXPREOPT_IMAGE_PROFILE_BUILT_INSTALLED)),Y)) \
 	  $(eval _is_product_system_other_avbkey := $(if $(findstring $f,$(INSTALLED_PRODUCT_SYSTEM_OTHER_AVBKEY_TARGET)),Y)) \
 	  $(eval _is_event_log_tags_file := $(if $(findstring $f,$(event_log_tags_file)),Y)) \
 	  $(eval _is_system_other_odex_marker := $(if $(findstring $f,$(INSTALLED_SYSTEM_OTHER_ODEX_MARKER)),Y)) \
@@ -1909,7 +1924,7 @@ $(SOONG_OUT_DIR)/compliance-metadata/$(TARGET_PRODUCT)/make-metadata.csv:
 	  $(eval _is_partition_compat_symlink := $(if $(findstring $f,$(PARTITION_COMPAT_SYMLINKS)),Y)) \
 	  $(eval _is_flags_file := $(if $(findstring $f, $(ALL_FLAGS_FILES)),Y)) \
 	  $(eval _is_rootdir_symlink := $(if $(findstring $f, $(ALL_ROOTDIR_SYMLINKS)),Y)) \
-	  $(eval _is_platform_generated := $(_is_build_prop)$(_is_notice_file)$(_is_dexpreopt_image_profile)$(_is_product_system_other_avbkey)$(_is_event_log_tags_file)$(_is_system_other_odex_marker)$(_is_kernel_modules_blocklist)$(_is_fsverity_build_manifest_apk)$(_is_linker_config)$(_is_partition_compat_symlink)$(_is_flags_file)$(_is_rootdir_symlink)) \
+	  $(eval _is_platform_generated := $(_is_build_prop)$(_is_notice_file)$(_is_product_system_other_avbkey)$(_is_event_log_tags_file)$(_is_system_other_odex_marker)$(_is_kernel_modules_blocklist)$(_is_fsverity_build_manifest_apk)$(_is_linker_config)$(_is_partition_compat_symlink)$(_is_flags_file)$(_is_rootdir_symlink)) \
 	  $(eval _static_libs := $(if $(_is_soong_module),,$(ALL_INSTALLED_FILES.$f.STATIC_LIBRARIES))) \
 	  $(eval _whole_static_libs := $(if $(_is_soong_module),,$(ALL_INSTALLED_FILES.$f.WHOLE_STATIC_LIBRARIES))) \
 	  $(eval _license_text := $(if $(filter $(_build_output_path),$(ALL_NON_MODULES)),$(ALL_NON_MODULES.$(_build_output_path).NOTICES))) \
diff --git a/core/packaging/flags.mk b/core/packaging/flags.mk
index 4693bcd6d8..fd9dc9b847 100644
--- a/core/packaging/flags.mk
+++ b/core/packaging/flags.mk
@@ -24,10 +24,11 @@ _FLAG_PARTITIONS := product system vendor
 # -----------------------------------------------------------------
 # Aconfig Flags
 
-# Create a summary file of build flags for each partition
+# Create a summary file of build flags for a single partition
 # $(1): built aconfig flags file (out)
 # $(2): installed aconfig flags file (out)
 # $(3): the partition (in)
+# $(4): input aconfig files for the partition (in)
 define generate-partition-aconfig-flag-file
 $(eval $(strip $(1)): PRIVATE_OUT := $(strip $(1)))
 $(eval $(strip $(1)): PRIVATE_IN := $(strip $(4)))
@@ -35,7 +36,8 @@ $(strip $(1)): $(ACONFIG) $(strip $(4))
 	mkdir -p $$(dir $$(PRIVATE_OUT))
 	$$(if $$(PRIVATE_IN), \
 		$$(ACONFIG) dump --dedup --format protobuf --out $$(PRIVATE_OUT) \
-			--filter container:$(strip $(3)) \
+			--filter container:$(strip $(3))+state:ENABLED \
+			--filter container:$(strip $(3))+permission:READ_WRITE \
 			$$(addprefix --cache ,$$(PRIVATE_IN)), \
 		echo -n > $$(PRIVATE_OUT) \
 	)
@@ -97,42 +99,54 @@ $(eval $(call generate-global-aconfig-flag-file, \
 # $(1): built aconfig flags storage package map file (out)
 # $(2): built aconfig flags storage flag map file (out)
 # $(3): built aconfig flags storage flag val file (out)
-# $(4): installed aconfig flags storage package map file (out)
-# $(5): installed aconfig flags storage flag map file (out)
-# $(6): installed aconfig flags storage flag value file (out)
-# $(7): input aconfig files for the partition (in)
-# $(8): partition name
+# $(4): built aconfig flags storage flag info file (out)
+# $(5): installed aconfig flags storage package map file (out)
+# $(6): installed aconfig flags storage flag map file (out)
+# $(7): installed aconfig flags storage flag value file (out)
+# $(8): installed aconfig flags storage flag info file (out)
+# $(9): input aconfig files for the partition (in)
+# $(10): partition name
 define generate-partition-aconfig-storage-file
 $(eval $(strip $(1)): PRIVATE_OUT := $(strip $(1)))
-$(eval $(strip $(1)): PRIVATE_IN := $(strip $(7)))
-$(strip $(1)): $(ACONFIG) $(strip $(7))
+$(eval $(strip $(1)): PRIVATE_IN := $(strip $(9)))
+$(strip $(1)): $(ACONFIG) $(strip $(9))
 	mkdir -p $$(dir $$(PRIVATE_OUT))
 	$$(if $$(PRIVATE_IN), \
-		$$(ACONFIG) create-storage --container $(8) --file package_map --out $$(PRIVATE_OUT) \
+		$$(ACONFIG) create-storage --container $(10) --file package_map --out $$(PRIVATE_OUT) \
 			$$(addprefix --cache ,$$(PRIVATE_IN)), \
 	)
 	touch $$(PRIVATE_OUT)
 $(eval $(strip $(2)): PRIVATE_OUT := $(strip $(2)))
-$(eval $(strip $(2)): PRIVATE_IN := $(strip $(7)))
-$(strip $(2)): $(ACONFIG) $(strip $(7))
+$(eval $(strip $(2)): PRIVATE_IN := $(strip $(9)))
+$(strip $(2)): $(ACONFIG) $(strip $(9))
 	mkdir -p $$(dir $$(PRIVATE_OUT))
 	$$(if $$(PRIVATE_IN), \
-		$$(ACONFIG) create-storage --container $(8) --file flag_map --out $$(PRIVATE_OUT) \
+		$$(ACONFIG) create-storage --container $(10) --file flag_map --out $$(PRIVATE_OUT) \
 			$$(addprefix --cache ,$$(PRIVATE_IN)), \
 	)
 	touch $$(PRIVATE_OUT)
 $(eval $(strip $(3)): PRIVATE_OUT := $(strip $(3)))
-$(eval $(strip $(3)): PRIVATE_IN := $(strip $(7)))
-$(strip $(3)): $(ACONFIG) $(strip $(7))
+$(eval $(strip $(3)): PRIVATE_IN := $(strip $(9)))
+$(strip $(3)): $(ACONFIG) $(strip $(9))
+	mkdir -p $$(dir $$(PRIVATE_OUT))
+	$$(if $$(PRIVATE_IN), \
+		$$(ACONFIG) create-storage --container $(10) --file flag_val --out $$(PRIVATE_OUT) \
+		$$(addprefix --cache ,$$(PRIVATE_IN)), \
+	)
+	touch $$(PRIVATE_OUT)
+$(eval $(strip $(4)): PRIVATE_OUT := $(strip $(4)))
+$(eval $(strip $(4)): PRIVATE_IN := $(strip $(9)))
+$(strip $(4)): $(ACONFIG) $(strip $(9))
 	mkdir -p $$(dir $$(PRIVATE_OUT))
 	$$(if $$(PRIVATE_IN), \
-		$$(ACONFIG) create-storage --container $(8) --file flag_val --out $$(PRIVATE_OUT) \
+		$$(ACONFIG) create-storage --container $(10) --file flag_info --out $$(PRIVATE_OUT) \
 		$$(addprefix --cache ,$$(PRIVATE_IN)), \
 	)
 	touch $$(PRIVATE_OUT)
-$(call copy-one-file, $(strip $(1)), $(4))
-$(call copy-one-file, $(strip $(2)), $(5))
-$(call copy-one-file, $(strip $(3)), $(6))
+$(call copy-one-file, $(strip $(1)), $(5))
+$(call copy-one-file, $(strip $(2)), $(6))
+$(call copy-one-file, $(strip $(3)), $(7))
+$(call copy-one-file, $(strip $(4)), $(8))
 endef
 
 ifeq ($(RELEASE_CREATE_ACONFIG_STORAGE_FILE),true)
@@ -140,13 +154,16 @@ $(foreach partition, $(_FLAG_PARTITIONS), \
 	$(eval aconfig_storage_package_map.$(partition) := $(PRODUCT_OUT)/$(partition)/etc/aconfig/package.map) \
 	$(eval aconfig_storage_flag_map.$(partition) := $(PRODUCT_OUT)/$(partition)/etc/aconfig/flag.map) \
 	$(eval aconfig_storage_flag_val.$(partition) := $(PRODUCT_OUT)/$(partition)/etc/aconfig/flag.val) \
+	$(eval aconfig_storage_flag_info.$(partition) := $(PRODUCT_OUT)/$(partition)/etc/aconfig/flag.info) \
 	$(eval $(call generate-partition-aconfig-storage-file, \
 				$(TARGET_OUT_FLAGS)/$(partition)/package.map, \
 				$(TARGET_OUT_FLAGS)/$(partition)/flag.map, \
 				$(TARGET_OUT_FLAGS)/$(partition)/flag.val, \
+				$(TARGET_OUT_FLAGS)/$(partition)/flag.info, \
 				$(aconfig_storage_package_map.$(partition)), \
 				$(aconfig_storage_flag_map.$(partition)), \
 				$(aconfig_storage_flag_val.$(partition)), \
+				$(aconfig_storage_flag_info.$(partition)), \
 				$(aconfig_flag_summaries_protobuf.$(partition)), \
 				$(partition), \
 	)) \
@@ -162,6 +179,7 @@ required_flags_files := \
 			$(aconfig_storage_package_map.$(partition)) \
 			$(aconfig_storage_flag_map.$(partition)) \
 			$(aconfig_storage_flag_val.$(partition)) \
+			$(aconfig_storage_flag_info.$(partition)) \
 		))
 
 ALL_DEFAULT_INSTALLED_MODULES += $(required_flags_files)
@@ -181,4 +199,5 @@ $(foreach partition, $(_FLAG_PARTITIONS), \
 	$(eval aconfig_storage_package_map.$(partition):=) \
 	$(eval aconfig_storage_flag_map.$(partition):=) \
 	$(eval aconfig_storage_flag_val.$(partition):=) \
+	$(eval aconfig_storage_flag_info.$(partition):=) \
 )
diff --git a/core/product.mk b/core/product.mk
index b07e6e0dc4..1b336b050f 100644
--- a/core/product.mk
+++ b/core/product.mk
@@ -284,6 +284,9 @@ _product_list_vars += PRODUCT_EXTRA_VNDK_VERSIONS
 # Whether APEX should be compressed or not
 _product_single_value_vars += PRODUCT_COMPRESSED_APEX
 
+# Default fs type for APEX payload image (apex_payload.img)
+_product_single_value_vars += PRODUCT_DEFAULT_APEX_PAYLOAD_TYPE
+
 # VNDK version of product partition. It can be 'current' if the product
 # partitions uses PLATFORM_VNDK_VERSION.
 _product_single_value_vars += PRODUCT_PRODUCT_VNDK_VERSION
@@ -366,6 +369,8 @@ _product_single_value_vars += PRODUCT_BUILD_DEBUG_VENDOR_BOOT_IMAGE
 _product_single_value_vars += PRODUCT_BUILD_VBMETA_IMAGE
 _product_single_value_vars += PRODUCT_BUILD_SUPER_EMPTY_IMAGE
 _product_single_value_vars += PRODUCT_BUILD_PVMFW_IMAGE
+_product_single_value_vars += PRODUCT_BUILD_DESKTOP_RECOVERY_IMAGE
+_product_single_value_vars += PRODUCT_BUILD_DESKTOP_UPDATE_IMAGE
 
 # List of boot jars delivered via updatable APEXes, following the same format as
 # PRODUCT_BOOT_JARS.
@@ -390,20 +395,6 @@ _product_single_value_vars += PRODUCT_OTA_FORCE_NON_AB_PACKAGE
 # If set, Java module in product partition cannot use hidden APIs.
 _product_single_value_vars += PRODUCT_ENFORCE_PRODUCT_PARTITION_INTERFACE
 
-# If set, only java_sdk_library can be used at inter-partition dependency.
-# Note: Build error if BOARD_VNDK_VERSION is not set while
-#       PRODUCT_ENFORCE_INTER_PARTITION_JAVA_SDK_LIBRARY is true, because
-#       PRODUCT_ENFORCE_INTER_PARTITION_JAVA_SDK_LIBRARY has no meaning if
-#       BOARD_VNDK_VERSION is not set.
-# Note: When PRODUCT_ENFORCE_PRODUCT_PARTITION_INTERFACE is not set, there are
-#       no restrictions at dependency between system and product partition.
-_product_single_value_vars += PRODUCT_ENFORCE_INTER_PARTITION_JAVA_SDK_LIBRARY
-
-# Allowlist for PRODUCT_ENFORCE_INTER_PARTITION_JAVA_SDK_LIBRARY option.
-# Listed modules are allowed at inter-partition dependency even if it isn't
-# a java_sdk_library module.
-_product_list_vars += PRODUCT_INTER_PARTITION_JAVA_LIBRARY_ALLOWLIST
-
 # Install a copy of the debug policy to the system_ext partition, and allow
 # init-second-stage to load debug policy from system_ext.
 # This option is only meant to be set by compliance GSI targets.
@@ -436,8 +427,9 @@ _product_single_value_vars += PRODUCT_MEMCG_V2_FORCE_ENABLED
 # If true, the cgroup v2 hierarchy will be split into apps/system subtrees
 _product_single_value_vars += PRODUCT_CGROUP_V2_SYS_APP_ISOLATION_ENABLED
 
-# List of .json files to be merged/compiled into vendor/etc/linker.config.pb
+# List of .json files to be merged/compiled into vendor/etc/linker.config.pb and product/etc/linker.config.pb
 _product_list_vars += PRODUCT_VENDOR_LINKER_CONFIG_FRAGMENTS
+_product_list_vars += PRODUCT_PRODUCT_LINKER_CONFIG_FRAGMENTS
 
 # Whether to use userfaultfd GC.
 # Possible values are:
@@ -503,6 +495,13 @@ _product_single_value_vars += PRODUCT_SOONG_DEFINED_SYSTEM_IMAGE
 # should be included in the system_linker_config.
 _product_list_vars += PRODUCT_EXTRA_STUB_LIBRARIES
 
+# If set to true, all Android.mk files will be ignored.
+_product_single_value_vars += PRODUCT_IGNORE_ALL_ANDROIDMK
+# When PRODUCT_IGNORE_ALL_ANDROIDMK is set to true, this variable will be used to allow some Android.mk files.
+_product_list_vars += PRODUCT_ALLOWED_ANDROIDMK_FILES
+# When PRODUCT_IGNORE_ALL_ANDROIDMK is set to true, path of file that contains a list of allowed Android.mk files
+_product_single_value_vars += PRODUCT_ANDROIDMK_ALLOWLIST_FILE
+
 .KATI_READONLY := _product_single_value_vars _product_list_vars
 _product_var_list :=$= $(_product_single_value_vars) $(_product_list_vars)
 
diff --git a/core/product_config.mk b/core/product_config.mk
index 738d4cff58..f93b63c6dc 100644
--- a/core/product_config.mk
+++ b/core/product_config.mk
@@ -424,10 +424,12 @@ ifdef PRODUCT_DEFAULT_DEV_CERTIFICATE
   endif
 endif
 
-$(foreach pair,$(PRODUCT_APEX_BOOT_JARS), \
-  $(eval jar := $(call word-colon,2,$(pair))) \
-  $(if $(findstring $(jar), $(PRODUCT_BOOT_JARS)), \
-    $(error A jar in PRODUCT_APEX_BOOT_JARS must not be in PRODUCT_BOOT_JARS, but $(jar) is)))
+$(foreach apexpair,$(PRODUCT_APEX_BOOT_JARS), \
+  $(foreach platformpair,$(PRODUCT_BOOT_JARS), \
+    $(eval apexjar := $(call word-colon,2,$(apexpair))) \
+    $(eval platformjar := $(call word-colon,2,$(platformpair))) \
+    $(if $(filter $(apexjar), $(platformjar)), \
+      $(error A jar in PRODUCT_APEX_BOOT_JARS must not be in PRODUCT_BOOT_JARS, but $(apexjar) is))))
 
 ENFORCE_SYSTEM_CERTIFICATE := $(PRODUCT_ENFORCE_ARTIFACT_SYSTEM_CERTIFICATE_REQUIREMENT)
 ENFORCE_SYSTEM_CERTIFICATE_ALLOW_LIST := $(PRODUCT_ARTIFACT_SYSTEM_CERTIFICATE_REQUIREMENT_ALLOW_LIST)
@@ -466,17 +468,26 @@ $(foreach c,$(PRODUCT_SANITIZER_MODULE_CONFIGS),\
     $(eval SANITIZER.$(TARGET_PRODUCT).$(m).CONFIG := $(cf))))
 _psmc_modules :=
 
-# Reset ADB keys for non-debuggable builds
-ifeq (,$(filter eng userdebug,$(TARGET_BUILD_VARIANT)))
+# Reset ADB keys. If RELEASE_BUILD_USE_VARIANT_FLAGS is set look for
+# the value of a dedicated flag. Otherwise check if build variant is
+# non-debuggable.
+ifneq (,$(RELEASE_BUILD_USE_VARIANT_FLAGS))
+ifneq (,$(RELEASE_BUILD_PURGE_PRODUCT_ADB_KEYS))
   PRODUCT_ADB_KEYS :=
 endif
+else ifeq (,$(filter eng userdebug,$(TARGET_BUILD_VARIANT)))
+  PRODUCT_ADB_KEYS :=
+endif
+
 ifneq ($(filter-out 0 1,$(words $(PRODUCT_ADB_KEYS))),)
   $(error Only one file may be in PRODUCT_ADB_KEYS: $(PRODUCT_ADB_KEYS))
 endif
 
 # Show a warning wall of text if non-compliance-GSI products set this option.
 ifdef PRODUCT_INSTALL_DEBUG_POLICY_TO_SYSTEM_EXT
-  ifeq (,$(filter gsi_arm gsi_arm64 gsi_x86 gsi_x86_64 gsi_car_arm64 gsi_car_x86_64 gsi_tv_arm gsi_tv_arm64,$(PRODUCT_NAME)))
+  ifeq (,$(filter gsi_arm gsi_arm64 gsi_arm64_soong_system gsi_x86 gsi_x86_64 \
+                  gsi_x86_64_soong_system gsi_car_arm64 gsi_car_x86_64 \
+                  gsi_tv_arm gsi_tv_arm64,$(PRODUCT_NAME)))
     $(warning PRODUCT_INSTALL_DEBUG_POLICY_TO_SYSTEM_EXT is set but \
       PRODUCT_NAME ($(PRODUCT_NAME)) doesn't look like a GSI for compliance \
       testing. This is a special configuration for compliance GSI, so do make \
@@ -532,6 +543,17 @@ ifdef OVERRIDE_PRODUCT_COMPRESSED_APEX
   PRODUCT_COMPRESSED_APEX := $(OVERRIDE_PRODUCT_COMPRESSED_APEX)
 endif
 
+ifdef OVERRIDE_PRODUCT_DEFAULT_APEX_PAYLOAD_TYPE
+  PRODUCT_DEFAULT_APEX_PAYLOAD_TYPE := $(OVERRIDE_PRODUCT_DEFAULT_APEX_PAYLOAD_TYPE)
+else ifeq ($(PRODUCT_DEFAULT_APEX_PAYLOAD_TYPE),)
+  # Use ext4 as a default payload fs type
+  PRODUCT_DEFAULT_APEX_PAYLOAD_TYPE := ext4
+endif
+ifeq ($(filter ext4 erofs,$(PRODUCT_DEFAULT_APEX_PAYLOAD_TYPE)),)
+  $(error PRODUCT_DEFAULT_APEX_PAYLOAD_TYPE should be either erofs or ext4,\
+    not $(PRODUCT_DEFAULT_APEX_PAYLOAD_TYPE).)
+endif
+
 $(KATI_obsolete_var OVERRIDE_PRODUCT_EXTRA_VNDK_VERSIONS \
     ,Use PRODUCT_EXTRA_VNDK_VERSIONS instead)
 
@@ -602,7 +624,12 @@ else
     # Vendors with GRF must define BOARD_SHIPPING_API_LEVEL for the vendor API level.
     # In this case, the VSR API level is the minimum of the PRODUCT_SHIPPING_API_LEVEL
     # and RELEASE_BOARD_API_LEVEL
-    VSR_VENDOR_API_LEVEL := $(call math_min,$(VSR_VENDOR_API_LEVEL),$(RELEASE_BOARD_API_LEVEL))
+    board_api_level := $(RELEASE_BOARD_API_LEVEL)
+    ifdef BOARD_API_LEVEL_PROP_OVERRIDE
+      board_api_level := $(BOARD_API_LEVEL_PROP_OVERRIDE)
+    endif
+    VSR_VENDOR_API_LEVEL := $(call math_min,$(VSR_VENDOR_API_LEVEL),$(board_api_level))
+    board_api_level :=
   endif
 endif
 .KATI_READONLY := VSR_VENDOR_API_LEVEL
diff --git a/core/proguard.flags b/core/proguard.flags
index aa406b983e..5148e56407 100644
--- a/core/proguard.flags
+++ b/core/proguard.flags
@@ -38,6 +38,17 @@
   @com.android.internal.annotations.KeepForWeakReference <fields>;
 }
 
+# Needed to ensure callback field references are kept in their respective
+# owning classes when the downstream callback registrars only store weak refs.
+-if @com.android.internal.annotations.WeaklyReferencedCallback class *
+-keepclassmembers,allowaccessmodification class * {
+  <1> *;
+}
+-if class * extends @com.android.internal.annotations.WeaklyReferencedCallback **
+-keepclassmembers,allowaccessmodification class * {
+  <1> *;
+}
+
 # Understand the common @Keep annotation from various Android packages:
 #  * android.support.annotation
 #  * androidx.annotation
diff --git a/core/project_definitions.mk b/core/project_definitions.mk
index 5728b677e7..184b03e019 100644
--- a/core/project_definitions.mk
+++ b/core/project_definitions.mk
@@ -22,3 +22,6 @@
 # Include definitions for prebuilt SDK, if present.
 #
 -include prebuilts/sdk/current/definitions.mk
+
+# SDV-specific config.
+-include system/software_defined_vehicle/platform/config.mk
diff --git a/core/ravenwood_test_config_template.xml b/core/ravenwood_test_config_template.xml
index 2f21baedf7..9e9dd762ff 100644
--- a/core/ravenwood_test_config_template.xml
+++ b/core/ravenwood_test_config_template.xml
@@ -22,6 +22,7 @@
     <option name="use-ravenwood-resources" value="true" />
     <option name="exclude-paths" value="java" />
     <option name="null-device" value="true" />
+    <option name="do-not-swallow-runner-errors" value="true" />
 
     {EXTRA_CONFIGS}
 
diff --git a/core/robolectric_test_config_template.xml b/core/robolectric_test_config_template.xml
index b1d0c2f4fa..1956b6eddf 100644
--- a/core/robolectric_test_config_template.xml
+++ b/core/robolectric_test_config_template.xml
@@ -22,6 +22,13 @@
     <option name="exclude-paths" value="java" />
     <option name="use-robolectric-resources" value="true" />
 
+    <!-- attempt to always show Tradefed errors -->
+    <option name="do-not-swallow-runner-errors" value="true" />
+
+    <!-- prevent Tradefed from hanging indefinitely in CI -->
+    <option name="socket-timeout" value="600000" />
+    <option name="test-case-timeout" value="2m" />
+
     {EXTRA_CONFIGS}
 
     <test class="com.android.tradefed.testtype.IsolatedHostTest" >
@@ -33,5 +40,15 @@
         <option name="java-flags" value="--add-opens=java.base/jdk.internal.util.random=ALL-UNNAMED"/>
         <!-- b/251387255 -->
         <option name="java-flags" value="--add-opens=java.base/java.io=ALL-UNNAMED"/>
+        <option name="java-flags" value="--add-opens=java.base/java.net=ALL-UNNAMED"/>
+        <option name="java-flags" value="--add-opens=java.base/java.nio=ALL-UNNAMED"/> <!-- required for ShadowVMRuntime -->
+        <option name="java-flags" value="--add-opens=java.base/java.security=ALL-UNNAMED"/>
+        <option name="java-flags" value="--add-opens=java.base/java.text=ALL-UNNAMED"/>
+        <option name="java-flags" value="--add-opens=java.base/java.util=ALL-UNNAMED"/>
+        <option name="java-flags" value="--add-opens=java.base/jdk.internal.access=ALL-UNNAMED"/>
+        <option name="java-flags" value="--add-opens=java.desktop/java.awt.font=ALL-UNNAMED"/>
+        <option name="java-flags" value="--add-opens=jdk.compiler/com.sun.tools.javac.api=ALL-UNNAMED"/>
+        <option name="java-flags" value="--add-opens=jdk.compiler/com.sun.tools.javac.main=ALL-UNNAMED"/>
+        <option name="java-flags" value="--add-opens=jdk.compiler/com.sun.tools.javac.util=ALL-UNNAMED"/>
     </test>
 </configuration>
diff --git a/core/soong_app_prebuilt.mk b/core/soong_app_prebuilt.mk
index df1cf2d369..ab9227f676 100644
--- a/core/soong_app_prebuilt.mk
+++ b/core/soong_app_prebuilt.mk
@@ -224,30 +224,6 @@ my_common := COMMON
 include $(BUILD_SYSTEM)/link_type.mk
 endif # !LOCAL_IS_HOST_MODULE
 
-ifeq (,$(filter tests,$(LOCAL_MODULE_TAGS)))
-  ifdef LOCAL_SOONG_DEVICE_RRO_DIRS
-    $(call append_enforce_rro_sources, \
-        $(my_register_name), \
-        false, \
-        $(LOCAL_FULL_MANIFEST_FILE), \
-        $(if $(LOCAL_EXPORT_PACKAGE_RESOURCES),true,false), \
-        $(LOCAL_SOONG_DEVICE_RRO_DIRS), \
-        vendor \
-    )
-  endif
-
-  ifdef LOCAL_SOONG_PRODUCT_RRO_DIRS
-    $(call append_enforce_rro_sources, \
-        $(my_register_name), \
-        false, \
-        $(LOCAL_FULL_MANIFEST_FILE), \
-        $(if $(LOCAL_EXPORT_PACKAGE_RESOURCES),true,false), \
-        $(LOCAL_SOONG_PRODUCT_RRO_DIRS), \
-        product \
-    )
-  endif
-endif
-
 ifdef LOCAL_PREBUILT_COVERAGE_ARCHIVE
   my_coverage_dir := $(TARGET_OUT_COVERAGE)/$(patsubst $(PRODUCT_OUT)/%,%,$(my_module_path))
   my_coverage_copy_pairs := $(foreach f,$(LOCAL_PREBUILT_COVERAGE_ARCHIVE),$(f):$(my_coverage_dir)/$(notdir  $(f)))
diff --git a/core/soong_config.mk b/core/soong_config.mk
index 1e6388a5ba..a007888b61 100644
--- a/core/soong_config.mk
+++ b/core/soong_config.mk
@@ -150,6 +150,7 @@ $(call add_json_bool, ArtUseReadBarrier,                 $(call invert_bool,$(fi
 $(call add_json_str,  BtConfigIncludeDir,                $(BOARD_BLUETOOTH_BDROID_BUILDCFG_INCLUDE_DIR))
 $(call add_json_list, DeviceKernelHeaders,               $(TARGET_DEVICE_KERNEL_HEADERS) $(TARGET_BOARD_KERNEL_HEADERS) $(TARGET_PRODUCT_KERNEL_HEADERS))
 $(call add_json_str,  VendorApiLevel,                    $(BOARD_API_LEVEL))
+$(call add_json_str,  VendorApiLevelPropOverride,        $(BOARD_API_LEVEL_PROP_OVERRIDE))
 $(call add_json_list, ExtraVndkVersions,                 $(PRODUCT_EXTRA_VNDK_VERSIONS))
 $(call add_json_list, DeviceSystemSdkVersions,           $(BOARD_SYSTEMSDK_VERSIONS))
 $(call add_json_list, Platform_systemsdk_versions,       $(PLATFORM_SYSTEMSDK_VERSIONS))
@@ -182,10 +183,19 @@ $(call add_json_bool, Enforce_vintf_manifest,            $(filter true,$(PRODUCT
 
 $(call add_json_bool, Uml,                               $(filter true,$(TARGET_USER_MODE_LINUX)))
 $(call add_json_str,  VendorPath,                        $(TARGET_COPY_OUT_VENDOR))
+$(call add_json_str,  VendorDlkmPath,                    $(TARGET_COPY_OUT_VENDOR_DLKM))
+$(call add_json_bool, BuildingVendorImage,               $(BUILDING_VENDOR_IMAGE))
 $(call add_json_str,  OdmPath,                           $(TARGET_COPY_OUT_ODM))
+$(call add_json_bool, BuildingOdmImage,                  $(BUILDING_ODM_IMAGE))
+$(call add_json_str,  OdmDlkmPath,                       $(TARGET_COPY_OUT_ODM_DLKM))
 $(call add_json_str,  ProductPath,                       $(TARGET_COPY_OUT_PRODUCT))
+$(call add_json_bool, BuildingProductImage,              $(BUILDING_PRODUCT_IMAGE))
 $(call add_json_str,  SystemExtPath,                     $(TARGET_COPY_OUT_SYSTEM_EXT))
+$(call add_json_str,  SystemDlkmPath,                    $(TARGET_COPY_OUT_SYSTEM_DLKM))
+$(call add_json_str,  OemPath,                           $(TARGET_COPY_OUT_OEM))
 $(call add_json_bool, MinimizeJavaDebugInfo,             $(filter true,$(PRODUCT_MINIMIZE_JAVA_DEBUG_INFO)))
+$(call add_json_str,  RecoveryPath,                      $(TARGET_COPY_OUT_RECOVERY))
+$(call add_json_bool, BuildingRecoveryImage,             $(BUILDING_RECOVERY_IMAGE))
 
 $(call add_json_bool, UseGoma,                           $(filter-out false,$(USE_GOMA)))
 $(call add_json_bool, UseRBE,                            $(filter-out false,$(USE_RBE)))
@@ -265,14 +275,8 @@ $(call end_json_map)
 $(call add_json_bool, EnforceProductPartitionInterface,  $(filter true,$(PRODUCT_ENFORCE_PRODUCT_PARTITION_INTERFACE)))
 $(call add_json_str,  DeviceCurrentApiLevelForVendorModules,  $(BOARD_CURRENT_API_LEVEL_FOR_VENDOR_MODULES))
 
-$(call add_json_bool, EnforceInterPartitionJavaSdkLibrary, $(filter true,$(PRODUCT_ENFORCE_INTER_PARTITION_JAVA_SDK_LIBRARY)))
-$(call add_json_list, InterPartitionJavaLibraryAllowList, $(PRODUCT_INTER_PARTITION_JAVA_LIBRARY_ALLOWLIST))
-
 $(call add_json_bool, CompressedApex, $(filter true,$(PRODUCT_COMPRESSED_APEX)))
-
-ifndef APEX_BUILD_FOR_PRE_S_DEVICES
-$(call add_json_bool, TrimmedApex, $(filter true,$(PRODUCT_TRIMMED_APEX)))
-endif
+$(call add_json_str, DefaultApexPayloadType, $(PRODUCT_DEFAULT_APEX_PAYLOAD_TYPE))
 
 $(call add_json_bool, BoardUsesRecoveryAsBoot, $(filter true,$(BOARD_USES_RECOVERY_AS_BOOT)))
 
@@ -319,6 +323,8 @@ $(call add_json_list, AfdoProfiles,                $(ALL_AFDO_PROFILES))
 
 $(call add_json_str,  ProductManufacturer, $(PRODUCT_MANUFACTURER))
 $(call add_json_str,  ProductBrand,        $(PRODUCT_BRAND))
+$(call add_json_str,  ProductDevice,       $(PRODUCT_DEVICE))
+$(call add_json_str,  ProductModel,        $(PRODUCT_MODEL))
 
 $(call add_json_str, ReleaseVersion,    $(_RELEASE_VERSION))
 $(call add_json_list, ReleaseAconfigValueSets,    $(RELEASE_ACONFIG_VALUE_SETS))
@@ -350,6 +356,9 @@ $(call add_json_list, SystemPropFiles, $(TARGET_SYSTEM_PROP))
 $(call add_json_list, SystemExtPropFiles, $(TARGET_SYSTEM_EXT_PROP))
 $(call add_json_list, ProductPropFiles, $(TARGET_PRODUCT_PROP))
 $(call add_json_list, OdmPropFiles, $(TARGET_ODM_PROP))
+$(call add_json_list, VendorPropFiles, $(TARGET_VENDOR_PROP))
+
+$(call add_json_str, ExtraAllowedDepsTxt, $(EXTRA_ALLOWED_DEPS_TXT))
 
 # Do not set ArtTargetIncludeDebugBuild into any value if PRODUCT_ART_TARGET_INCLUDE_DEBUG_BUILD is not set,
 # to have the same behavior from runtime_libart.mk.
@@ -367,6 +376,179 @@ $(call add_json_list, DeviceProductCompatibilityMatrixFile, $(DEVICE_PRODUCT_COM
 $(call add_json_list, BoardAvbSystemAddHashtreeFooterArgs, $(BOARD_AVB_SYSTEM_ADD_HASHTREE_FOOTER_ARGS))
 $(call add_json_bool, BoardAvbEnable, $(filter true,$(BOARD_AVB_ENABLE)))
 
+$(call add_json_str, AdbKeys, $(PRODUCT_ADB_KEYS))
+
+$(call add_json_map, PartitionVarsForSoongMigrationOnlyDoNotUse)
+  $(call add_json_str,  ProductDirectory,    $(dir $(INTERNAL_PRODUCT)))
+
+  $(call add_json_map,PartitionQualifiedVariables)
+  $(foreach image_type,INIT_BOOT BOOT VENDOR_BOOT SYSTEM VENDOR CACHE USERDATA PRODUCT SYSTEM_EXT OEM ODM VENDOR_DLKM ODM_DLKM SYSTEM_DLKM, \
+    $(call add_json_map,$(call to-lower,$(image_type))) \
+    $(call add_json_bool, BuildingImage, $(filter true,$(BUILDING_$(image_type)_IMAGE))) \
+    $(call add_json_str, BoardErofsCompressor, $(BOARD_$(image_type)IMAGE_EROFS_COMPRESSOR)) \
+    $(call add_json_str, BoardErofsCompressHints, $(BOARD_$(image_type)IMAGE_EROFS_COMPRESS_HINTS)) \
+    $(call add_json_str, BoardErofsPclusterSize, $(BOARD_$(image_type)IMAGE_EROFS_PCLUSTER_SIZE)) \
+    $(call add_json_str, BoardExtfsInodeCount, $(BOARD_$(image_type)IMAGE_EXTFS_INODE_COUNT)) \
+    $(call add_json_str, BoardExtfsRsvPct, $(BOARD_$(image_type)IMAGE_EXTFS_RSV_PCT)) \
+    $(call add_json_str, BoardF2fsSloadCompressFlags, $(BOARD_$(image_type)IMAGE_F2FS_SLOAD_COMPRESS_FLAGS)) \
+    $(call add_json_str, BoardFileSystemCompress, $(BOARD_$(image_type)IMAGE_FILE_SYSTEM_COMPRESS)) \
+    $(call add_json_str, BoardFileSystemType, $(BOARD_$(image_type)IMAGE_FILE_SYSTEM_TYPE)) \
+    $(call add_json_str, BoardJournalSize, $(BOARD_$(image_type)IMAGE_JOURNAL_SIZE)) \
+    $(call add_json_str, BoardPartitionReservedSize, $(BOARD_$(image_type)IMAGE_PARTITION_RESERVED_SIZE)) \
+    $(call add_json_str, BoardPartitionSize, $(BOARD_$(image_type)IMAGE_PARTITION_SIZE)) \
+    $(call add_json_str, BoardSquashfsBlockSize, $(BOARD_$(image_type)IMAGE_SQUASHFS_BLOCK_SIZE)) \
+    $(call add_json_str, BoardSquashfsCompressor, $(BOARD_$(image_type)IMAGE_SQUASHFS_COMPRESSOR)) \
+    $(call add_json_str, BoardSquashfsCompressorOpt, $(BOARD_$(image_type)IMAGE_SQUASHFS_COMPRESSOR_OPT)) \
+    $(call add_json_str, BoardSquashfsDisable4kAlign, $(BOARD_$(image_type)IMAGE_SQUASHFS_DISABLE_4K_ALIGN)) \
+    $(call add_json_str, BoardAvbKeyPath, $(BOARD_AVB_$(image_type)_KEY_PATH)) \
+    $(call add_json_str, BoardAvbAlgorithm, $(BOARD_AVB_$(image_type)_ALGORITHM)) \
+    $(call add_json_str, BoardAvbRollbackIndex, $(BOARD_AVB_$(image_type)_ROLLBACK_INDEX)) \
+    $(call add_json_str, BoardAvbRollbackIndexLocation, $(BOARD_AVB_$(image_type)_ROLLBACK_INDEX_LOCATION)) \
+    $(call add_json_str, BoardAvbAddHashtreeFooterArgs, $(BOARD_AVB_$(image_type)_ADD_HASHTREE_FOOTER_ARGS)) \
+    $(call add_json_str, ProductBaseFsPath, $(PRODUCT_$(image_type)_BASE_FS_PATH)) \
+    $(call add_json_str, ProductHeadroom, $(PRODUCT_$(image_type)_HEADROOM)) \
+    $(call add_json_str, ProductVerityPartition, $(PRODUCT_$(image_type)_VERITY_PARTITION)) \
+    $(call end_json_map) \
+  )
+  $(call end_json_map)
+
+  $(call add_json_bool, TargetUserimagesUseExt2, $(filter true,$(TARGET_USERIMAGES_USE_EXT2)))
+  $(call add_json_bool, TargetUserimagesUseExt3, $(filter true,$(TARGET_USERIMAGES_USE_EXT3)))
+  $(call add_json_bool, TargetUserimagesUseExt4, $(filter true,$(TARGET_USERIMAGES_USE_EXT4)))
+
+  $(call add_json_bool, TargetUserimagesSparseExtDisabled, $(filter true,$(TARGET_USERIMAGES_SPARSE_EXT_DISABLED)))
+  $(call add_json_bool, TargetUserimagesSparseErofsDisabled, $(filter true,$(TARGET_USERIMAGES_SPARSE_EROFS_DISABLED)))
+  $(call add_json_bool, TargetUserimagesSparseSquashfsDisabled, $(filter true,$(TARGET_USERIMAGES_SPARSE_SQUASHFS_DISABLED)))
+  $(call add_json_bool, TargetUserimagesSparseF2fsDisabled, $(filter true,$(TARGET_USERIMAGES_SPARSE_F2FS_DISABLED)))
+
+  $(call add_json_str, BoardErofsCompressor, $(BOARD_EROFS_COMPRESSOR))
+  $(call add_json_str, BoardErofsCompressorHints, $(BOARD_EROFS_COMPRESS_HINTS))
+  $(call add_json_str, BoardErofsPclusterSize, $(BOARD_EROFS_PCLUSTER_SIZE))
+  $(call add_json_str, BoardErofsShareDupBlocks, $(BOARD_EROFS_SHARE_DUP_BLOCKS))
+  $(call add_json_str, BoardErofsUseLegacyCompression, $(BOARD_EROFS_USE_LEGACY_COMPRESSION))
+  $(call add_json_str, BoardExt4ShareDupBlocks, $(BOARD_EXT4_SHARE_DUP_BLOCKS))
+  $(call add_json_str, BoardFlashLogicalBlockSize, $(BOARD_FLASH_LOGICAL_BLOCK_SIZE))
+  $(call add_json_str, BoardFlashEraseBlockSize, $(BOARD_FLASH_ERASE_BLOCK_SIZE))
+  $(call add_json_bool, BuildingVbmetaImage, $(BUILDING_VBMETA_IMAGE))
+
+  # boot image stuff
+  $(call add_json_bool, BuildingRamdiskImage, $(filter true,$(BUILDING_RAMDISK_IMAGE)))
+  $(call add_json_bool, ProductBuildBootImage, $(filter true,$(PRODUCT_BUILD_BOOT_IMAGE)))
+  $(call add_json_str, ProductBuildVendorBootImage, $(PRODUCT_BUILD_VENDOR_BOOT_IMAGE))
+  $(call add_json_bool, ProductBuildInitBootImage, $(filter true,$(PRODUCT_BUILD_INIT_BOOT_IMAGE)))
+  $(call add_json_bool, BoardUsesRecoveryAsBoot, $(filter true,$(BOARD_USES_RECOVERY_AS_BOOT)))
+  $(call add_json_str, BoardPrebuiltBootimage, $(BOARD_PREBUILT_BOOT_IMAGE))
+  $(call add_json_str, BoardPrebuiltInitBootimage, $(BOARD_PREBUILT_INIT_BOOT_IMAGE))
+  $(call add_json_str, BoardBootimagePartitionSize, $(BOARD_BOOTIMAGE_PARTITION_SIZE))
+  $(call add_json_str, BoardInitBootimagePartitionSize, $(BOARD_INIT_BOOT_IMAGE_PARTITION_SIZE))
+  $(call add_json_str, BoardBootHeaderVersion, $(BOARD_BOOT_HEADER_VERSION))
+  $(call add_json_str, TargetKernelPath, $(TARGET_KERNEL_PATH))
+  $(call add_json_bool, BoardUsesGenericKernelImage, $(BOARD_USES_GENERIC_KERNEL_IMAGE))
+  $(call add_json_str, BootSecurityPatch, $(BOOT_SECURITY_PATCH))
+  $(call add_json_str, InitBootSecurityPatch, $(INIT_BOOT_SECURITY_PATCH))
+  $(call add_json_str, VendorSecurityPatch, $(VENDOR_SECURITY_PATCH))
+  $(call add_json_bool, BoardIncludeDtbInBootimg, $(BOARD_INCLUDE_DTB_IN_BOOTIMG))
+  $(call add_json_list, InternalKernelCmdline, $(INTERNAL_KERNEL_CMDLINE))
+  $(call add_json_list, InternalBootconfig, $(INTERNAL_BOOTCONFIG))
+  $(call add_json_str, InternalBootconfigFile, $(INTERNAL_BOOTCONFIG_FILE))
+
+  # super image stuff
+  $(call add_json_bool, ProductUseDynamicPartitions, $(filter true,$(PRODUCT_USE_DYNAMIC_PARTITIONS)))
+  $(call add_json_bool, ProductRetrofitDynamicPartitions, $(filter true,$(PRODUCT_RETROFIT_DYNAMIC_PARTITIONS)))
+  $(call add_json_bool, ProductBuildSuperPartition, $(filter true,$(PRODUCT_BUILD_SUPER_PARTITION)))
+  $(call add_json_str, BoardSuperPartitionSize, $(BOARD_SUPER_PARTITION_SIZE))
+  $(call add_json_str, BoardSuperPartitionMetadataDevice, $(BOARD_SUPER_PARTITION_METADATA_DEVICE))
+  $(call add_json_list, BoardSuperPartitionBlockDevices, $(BOARD_SUPER_PARTITION_BLOCK_DEVICES))
+  $(call add_json_map, BoardSuperPartitionGroups)
+    $(foreach group, $(BOARD_SUPER_PARTITION_GROUPS), \
+      $(call add_json_map, $(group)) \
+        $(call add_json_str, GroupSize, $(BOARD_$(call to-upper,$(group))_SIZE)) \
+        $(if $(BOARD_$(call to-upper,$(group))_PARTITION_LIST), \
+          $(call add_json_list, PartitionList, $(BOARD_$(call to-upper,$(group))_PARTITION_LIST))) \
+      $(call end_json_map))
+    $(call end_json_map)
+  $(call add_json_bool, ProductVirtualAbOta, $(filter true,$(PRODUCT_VIRTUAL_AB_OTA)))
+  $(call add_json_bool, ProductVirtualAbOtaRetrofit, $(filter true,$(PRODUCT_VIRTUAL_AB_OTA_RETROFIT)))
+  $(call add_json_bool, AbOtaUpdater, $(filter true,$(AB_OTA_UPDATER)))
+
+  # Avb (android verified boot) stuff
+  $(call add_json_bool, BoardAvbEnable, $(filter true,$(BOARD_AVB_ENABLE)))
+  $(call add_json_str, BoardAvbAlgorithm, $(BOARD_AVB_ALGORITHM))
+  $(call add_json_str, BoardAvbKeyPath, $(BOARD_AVB_KEY_PATH))
+  $(call add_json_str, BoardAvbRollbackIndex, $(BOARD_AVB_ROLLBACK_INDEX))
+  $(call add_json_map, ChainedVbmetaPartitions)
+  $(foreach partition,system vendor $(BOARD_AVB_VBMETA_CUSTOM_PARTITIONS),\
+    $(call add_json_map, $(partition)) \
+      $(call add_json_list,Partitions,$(BOARD_AVB_VBMETA_$(call to-upper,$(partition)))) \
+      $(call add_json_str,Key,$(BOARD_AVB_VBMETA_$(call to-upper,$(partition))_KEY_PATH)) \
+      $(call add_json_str,Algorithm,$(BOARD_AVB_VBMETA_$(call to-upper,$(partition))_ALGORITHM)) \
+      $(call add_json_str,RollbackIndex,$(BOARD_AVB_VBMETA_$(call to-upper,$(partition))_ROLLBACK_INDEX)) \
+      $(call add_json_str,RollbackIndexLocation,$(BOARD_AVB_VBMETA_$(call to-upper,$(partition))_ROLLBACK_INDEX_LOCATION)) \
+    $(call end_json_map))
+  $(call end_json_map)
+
+  $(call add_json_bool, ProductUseDynamicPartitionSize, $(filter true,$(PRODUCT_USE_DYNAMIC_PARTITION_SIZE)))
+  $(call add_json_bool, CopyImagesForTargetFilesZip, $(filter true,$(COPY_IMAGES_FOR_TARGET_FILES_ZIP)))
+
+  $(call add_json_list, ProductPackages, $(PRODUCT_PACKAGES))
+  $(call add_json_list, ProductPackagesDebug, $(PRODUCT_PACKAGES_DEBUG))
+
+  # Used to generate /vendor/linker.config.pb
+  $(call add_json_list, VendorLinkerConfigSrcs, $(PRODUCT_VENDOR_LINKER_CONFIG_FRAGMENTS))
+  $(call add_json_list, ProductLinkerConfigSrcs, $(PRODUCT_PRODUCT_LINKER_CONFIG_FRAGMENTS))
+
+  # Used to generate _dlkm partitions
+  $(call add_json_bool, BuildingSystemDlkmImage,               $(BUILDING_SYSTEM_DLKM_IMAGE))
+  $(call add_json_list, SystemKernelModules, $(BOARD_SYSTEM_KERNEL_MODULES))
+  $(call add_json_str, SystemKernelBlocklistFile, $(BOARD_SYSTEM_KERNEL_MODULES_BLOCKLIST_FILE))
+  $(call add_json_list, SystemKernelLoadModules, $(BOARD_SYSTEM_KERNEL_MODULES_LOAD))
+  $(call add_json_bool, BuildingVendorDlkmImage,               $(BUILDING_VENDOR_DLKM_IMAGE))
+  $(call add_json_list, VendorKernelModules, $(BOARD_VENDOR_KERNEL_MODULES))
+  $(call add_json_str, VendorKernelBlocklistFile, $(BOARD_VENDOR_KERNEL_MODULES_BLOCKLIST_FILE))
+  $(call add_json_bool, BuildingOdmDlkmImage,               $(BUILDING_ODM_DLKM_IMAGE))
+  $(call add_json_list, OdmKernelModules, $(BOARD_ODM_KERNEL_MODULES))
+  $(call add_json_str, OdmKernelBlocklistFile, $(BOARD_ODM_KERNEL_MODULES_BLOCKLIST_FILE))
+  $(call add_json_list, VendorRamdiskKernelModules, $(BOARD_VENDOR_RAMDISK_KERNEL_MODULES))
+  $(call add_json_str, VendorRamdiskKernelBlocklistFile, $(BOARD_VENDOR_RAMDISK_KERNEL_MODULES_BLOCKLIST_FILE))
+  $(call add_json_list, VendorRamdiskKernelLoadModules, $(BOARD_VENDOR_RAMDISK_KERNEL_MODULES_LOAD))
+  $(call add_json_str, VendorRamdiskKernelOptionsFile, $(BOARD_VENDOR_RAMDISK_KERNEL_MODULES_OPTIONS_FILE))
+
+  # Used to generate /vendor/build.prop
+  $(call add_json_list, BoardInfoFiles, $(if $(TARGET_BOARD_INFO_FILES),$(TARGET_BOARD_INFO_FILES),$(firstword $(TARGET_BOARD_INFO_FILE) $(wildcard $(TARGET_DEVICE_DIR)/board-info.txt))))
+  $(call add_json_str, BootLoaderBoardName, $(TARGET_BOOTLOADER_BOARD_NAME))
+
+  $(call add_json_list, ProductCopyFiles, $(PRODUCT_COPY_FILES))
+
+  # Used to generate fsv meta
+  $(call add_json_bool, ProductFsverityGenerateMetadata,               $(PRODUCT_FSVERITY_GENERATE_METADATA))
+
+  # Used to generate recovery partition
+  $(call add_json_str, TargetScreenDensity, $(TARGET_SCREEN_DENSITY))
+
+$(call end_json_map)
+
+# For converting vintf_data
+$(call add_json_list, DeviceMatrixFile, $(DEVICE_MATRIX_FILE))
+$(call add_json_list, ProductManifestFiles, $(PRODUCT_MANIFEST_FILES))
+$(call add_json_list, SystemManifestFile, $(DEVICE_FRAMEWORK_MANIFEST_FILE))
+SYSTEM_EXT_HWSERVICE_FILES :=
+ifeq ($(PRODUCT_HIDL_ENABLED),true)
+  ifneq ($(filter hwservicemanager,$(PRODUCT_PACKAGES)),)
+    SYSTEM_EXT_HWSERVICE_FILES += system/hwservicemanager/hwservicemanager_no_max.xml
+  else
+    $(error If PRODUCT_HIDL_ENABLED is set, hwservicemanager must be added to PRODUCT_PACKAGES explicitly)
+  endif
+else
+  ifneq ($(filter hwservicemanager,$(PRODUCT_PACKAGES)),)
+    SYSTEM_EXT_HWSERVICE_FILES += system/hwservicemanager/hwservicemanager.xml
+  else ifneq ($(filter hwservicemanager,$(PRODUCT_PACKAGES_SHIPPING_API_LEVEL_34)),)
+    SYSTEM_EXT_HWSERVICE_FILES += system/hwservicemanager/hwservicemanager.xml
+  endif
+endif
+$(call add_json_list, SystemExtManifestFiles, $(SYSTEM_EXT_MANIFEST_FILES) $(SYSTEM_EXT_HWSERVICE_FILES))
+$(call add_json_list, DeviceManifestFiles, $(DEVICE_MANIFEST_FILE))
+$(call add_json_list, OdmManifestFiles, $(ODM_MANIFEST_FILES))
+
 $(call json_end)
 
 $(file >$(SOONG_VARIABLES).tmp,$(json_contents))
diff --git a/core/soong_extra_config.mk b/core/soong_extra_config.mk
index 00b5c0fd63..2ff83a1b77 100644
--- a/core/soong_extra_config.mk
+++ b/core/soong_extra_config.mk
@@ -43,6 +43,7 @@ $(call add_json_list, PRODUCT_VENDOR_PROPERTIES,         $(call collapse-prop-pa
 $(call add_json_list, PRODUCT_PRODUCT_PROPERTIES,        $(call collapse-prop-pairs,PRODUCT_PRODUCT_PROPERTIES))
 $(call add_json_list, PRODUCT_ODM_PROPERTIES,            $(call collapse-prop-pairs,PRODUCT_ODM_PROPERTIES))
 $(call add_json_list, PRODUCT_PROPERTY_OVERRIDES,        $(call collapse-prop-pairs,PRODUCT_PROPERTY_OVERRIDES))
+$(call add_json_list, PRODUCT_DEFAULT_PROPERTY_OVERRIDES,        $(call collapse-prop-pairs,PRODUCT_DEFAULT_PROPERTY_OVERRIDES))
 
 $(call add_json_str, BootloaderBoardName, $(TARGET_BOOTLOADER_BOARD_NAME))
 
diff --git a/core/sysprop.mk b/core/sysprop.mk
index dc6f2c4ac6..dcde71bd1e 100644
--- a/core/sysprop.mk
+++ b/core/sysprop.mk
@@ -79,6 +79,7 @@ define generate-common-build-props
     echo "ro.$(1).build.version.release=$(PLATFORM_VERSION_LAST_STABLE)" >> $(2);\
     echo "ro.$(1).build.version.release_or_codename=$(PLATFORM_VERSION)" >> $(2);\
     echo "ro.$(1).build.version.sdk=$(PLATFORM_SDK_VERSION)" >> $(2);\
+    echo "ro.$(1).build.version.sdk_minor=$(PLATFORM_SDK_MINOR_VERSION)" >> $(2);\
 
 endef
 
@@ -183,7 +184,7 @@ ifeq (,$(strip $(BUILD_FINGERPRINT)))
 endif
 
 BUILD_FINGERPRINT_FILE := $(PRODUCT_OUT)/build_fingerprint.txt
-ifneq (,$(shell mkdir -p $(PRODUCT_OUT) && echo $(BUILD_FINGERPRINT) >$(BUILD_FINGERPRINT_FILE) && grep " " $(BUILD_FINGERPRINT_FILE)))
+ifneq (,$(shell mkdir -p $(PRODUCT_OUT) && echo $(BUILD_FINGERPRINT) >$(BUILD_FINGERPRINT_FILE).tmp && (if ! cmp -s $(BUILD_FINGERPRINT_FILE).tmp $(BUILD_FINGERPRINT_FILE); then mv $(BUILD_FINGERPRINT_FILE).tmp $(BUILD_FINGERPRINT_FILE); else rm $(BUILD_FINGERPRINT_FILE).tmp; fi) && grep " " $(BUILD_FINGERPRINT_FILE)))
   $(error BUILD_FINGERPRINT cannot contain spaces: "$(file <$(BUILD_FINGERPRINT_FILE))")
 endif
 BUILD_FINGERPRINT_FROM_FILE := $$(cat $(BUILD_FINGERPRINT_FILE))
@@ -281,51 +282,17 @@ INSTALLED_ODM_BUILD_PROP_TARGET := $(TARGET_OUT_ODM)/etc/build.prop
 
 # ----------------------------------------------------------------
 # vendor_dlkm/etc/build.prop
-#
-
-INSTALLED_VENDOR_DLKM_BUILD_PROP_TARGET := $(TARGET_OUT_VENDOR_DLKM)/etc/build.prop
-$(eval $(call build-properties,\
-    vendor_dlkm,\
-    $(INSTALLED_VENDOR_DLKM_BUILD_PROP_TARGET),\
-    $(empty),\
-    $(empty),\
-    $(empty),\
-    $(empty),\
-    $(empty)))
-
-$(eval $(call declare-1p-target,$(INSTALLED_VENDOR_DLKM_BUILD_PROP_TARGET)))
-
-# ----------------------------------------------------------------
 # odm_dlkm/etc/build.prop
-#
-
-INSTALLED_ODM_DLKM_BUILD_PROP_TARGET := $(TARGET_OUT_ODM_DLKM)/etc/build.prop
-$(eval $(call build-properties,\
-    odm_dlkm,\
-    $(INSTALLED_ODM_DLKM_BUILD_PROP_TARGET),\
-    $(empty),\
-    $(empty),\
-    $(empty),\
-    $(empty),\
-    $(empty)))
-
-$(eval $(call declare-1p-target,$(INSTALLED_ODM_DLKM_BUILD_PROP_TARGET)))
-
-# ----------------------------------------------------------------
 # system_dlkm/build.prop
-#
+# These are built by Soong. See build/soong/Android.bp
 
+INSTALLED_VENDOR_DLKM_BUILD_PROP_TARGET := $(TARGET_OUT_VENDOR_DLKM)/etc/build.prop
+INSTALLED_ODM_DLKM_BUILD_PROP_TARGET := $(TARGET_OUT_ODM_DLKM)/etc/build.prop
 INSTALLED_SYSTEM_DLKM_BUILD_PROP_TARGET := $(TARGET_OUT_SYSTEM_DLKM)/etc/build.prop
-$(eval $(call build-properties,\
-    system_dlkm,\
-    $(INSTALLED_SYSTEM_DLKM_BUILD_PROP_TARGET),\
-    $(empty),\
-    $(empty),\
-    $(empty),\
-    $(empty),\
-    $(empty)))
-
-$(eval $(call declare-1p-target,$(INSTALLED_SYSTEM_DLKM_BUILD_PROP_TARGET)))
+ALL_DEFAULT_INSTALLED_MODULES += \
+  $(INSTALLED_VENDOR_DLKM_BUILD_PROP_TARGET) \
+  $(INSTALLED_ODM_DLKM_BUILD_PROP_TARGET) \
+  $(INSTALLED_SYSTEM_DLKM_BUILD_PROP_TARGET) \
 
 # -----------------------------------------------------------------
 # system_ext/etc/build.prop
@@ -335,22 +302,12 @@ $(eval $(call declare-1p-target,$(INSTALLED_SYSTEM_DLKM_BUILD_PROP_TARGET)))
 
 INSTALLED_SYSTEM_EXT_BUILD_PROP_TARGET := $(TARGET_OUT_SYSTEM_EXT)/etc/build.prop
 
-# ----------------------------------------------------------------
-# ramdisk/boot/etc/build.prop
-#
-
 RAMDISK_BUILD_PROP_REL_PATH := system/etc/ramdisk/build.prop
+ifeq (true,$(BOARD_USES_RECOVERY_AS_BOOT))
+INSTALLED_RAMDISK_BUILD_PROP_TARGET := $(TARGET_RECOVERY_ROOT_OUT)/first_stage_ramdisk/$(RAMDISK_BUILD_PROP_REL_PATH)
+else
 INSTALLED_RAMDISK_BUILD_PROP_TARGET := $(TARGET_RAMDISK_OUT)/$(RAMDISK_BUILD_PROP_REL_PATH)
-$(eval $(call build-properties,\
-    bootimage,\
-    $(INSTALLED_RAMDISK_BUILD_PROP_TARGET),\
-    $(empty),\
-    $(empty),\
-    $(empty),\
-    $(empty),\
-    $(empty)))
-
-$(eval $(call declare-1p-target,$(INSTALLED_RAMDISK_BUILD_PROP_TARGET)))
+endif
 
 ALL_INSTALLED_BUILD_PROP_FILES := \
   $(INSTALLED_BUILD_PROP_TARGET) \
diff --git a/core/sysprop_config.mk b/core/sysprop_config.mk
index 69066117a3..199150347c 100644
--- a/core/sysprop_config.mk
+++ b/core/sysprop_config.mk
@@ -91,8 +91,12 @@ endif
 # Build system set BOARD_API_LEVEL to show the api level of the vendor API surface.
 # This must not be altered outside of build system.
 ifdef BOARD_API_LEVEL
-ADDITIONAL_VENDOR_PROPERTIES += \
-    ro.board.api_level=$(BOARD_API_LEVEL)
+  ADDITIONAL_VENDOR_PROPERTIES += \
+    ro.board.api_level?=$(BOARD_API_LEVEL)
+  ifdef BOARD_API_LEVEL_PROP_OVERRIDE
+    ADDITIONAL_VENDOR_PROPERTIES += \
+      ro.board.api_level=$(BOARD_API_LEVEL_PROP_OVERRIDE)
+  endif
 endif
 # RELEASE_BOARD_API_LEVEL_FROZEN is true when the vendor API surface is frozen.
 ifdef RELEASE_BOARD_API_LEVEL_FROZEN
diff --git a/core/tasks/autorepro.mk b/core/tasks/autorepro.mk
new file mode 100644
index 0000000000..2f81f9bf85
--- /dev/null
+++ b/core/tasks/autorepro.mk
@@ -0,0 +1,39 @@
+# Copyright (C) 2022 The Android Open Source Project
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
+ifneq ($(wildcard test/sts/README-autorepro.md),)
+test_suite_name := autorepro
+test_suite_tradefed := sts-tradefed
+test_suite_readme := test/sts/README-autorepro.md
+autorepro_zip := $(HOST_OUT)/$(test_suite_name)/autorepro.zip
+
+include $(BUILD_SYSTEM)/tasks/tools/compatibility.mk
+
+autorepro_plugin_skel := $(call intermediates-dir-for,ETC,autorepro-plugin-skel.zip)/autorepro-plugin-skel.zip
+
+$(autorepro_zip): AUTOREPRO_ZIP := $(compatibility_zip)
+$(autorepro_zip): AUTOREPRO_PLUGIN_SKEL := $(autorepro_plugin_skel)
+$(autorepro_zip): $(MERGE_ZIPS) $(ZIP2ZIP) $(compatibility_zip) $(autorepro_plugin_skel)
+	rm -f $@ $(AUTOREPRO_ZIP)_filtered
+	$(ZIP2ZIP) -i $(AUTOREPRO_ZIP) -o $(AUTOREPRO_ZIP)_filtered \
+		-x android-autorepro/tools/sts-tradefed-tests.jar \
+		'android-autorepro/tools/*:autorepro/src/main/resources/sts-tradefed-tools/'
+	$(MERGE_ZIPS) $@ $(AUTOREPRO_ZIP)_filtered $(AUTOREPRO_PLUGIN_SKEL)
+	rm -f $(AUTOREPRO_ZIP)_filtered
+
+.PHONY: autorepro
+autorepro: $(autorepro_zip)
+$(call dist-for-goals, autorepro, $(autorepro_zip))
+
+endif
diff --git a/target/product/gsi/Android.mk b/core/tasks/check-abi-dump-list.mk
similarity index 72%
rename from target/product/gsi/Android.mk
rename to core/tasks/check-abi-dump-list.mk
index 36897fef8e..81d549e46f 100644
--- a/target/product/gsi/Android.mk
+++ b/core/tasks/check-abi-dump-list.mk
@@ -1,4 +1,16 @@
-LOCAL_PATH:= $(call my-dir)
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
 
 #####################################################################
 # Check the generate list against the latest list stored in the
@@ -109,60 +121,3 @@ $(check-abi-dump-list-timestamp):
 	$(if $(added_vndk_abi_dumps)$(added_platform_abi_dumps),exit 1)
 	$(hide) mkdir -p $(dir $@)
 	$(hide) touch $@
-
-#####################################################################
-# VNDK package and snapshot.
-
-include $(CLEAR_VARS)
-
-LOCAL_MODULE := vndk_apex_snapshot_package
-LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
-LOCAL_LICENSE_CONDITIONS := notice
-LOCAL_NOTICE_FILE := build/soong/licenses/LICENSE
-LOCAL_REQUIRED_MODULES := $(foreach vndk_ver,$(PRODUCT_EXTRA_VNDK_VERSIONS),com.android.vndk.v$(vndk_ver))
-include $(BUILD_PHONY_PACKAGE)
-
-#####################################################################
-# Define Phony module to install LLNDK modules which are installed in
-# the system image
-include $(CLEAR_VARS)
-LOCAL_MODULE := llndk_in_system
-LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
-LOCAL_LICENSE_CONDITIONS := notice
-LOCAL_NOTICE_FILE := build/soong/licenses/LICENSE
-
-# Filter LLNDK libs moved to APEX to avoid pulling them into /system/LIB
-LOCAL_REQUIRED_MODULES := \
-    $(filter-out $(LLNDK_MOVED_TO_APEX_LIBRARIES),$(LLNDK_LIBRARIES)) \
-    llndk.libraries.txt
-
-
-include $(BUILD_PHONY_PACKAGE)
-
-#####################################################################
-# init.gsi.rc, GSI-specific init script.
-
-include $(CLEAR_VARS)
-LOCAL_MODULE := init.gsi.rc
-LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
-LOCAL_LICENSE_CONDITIONS := notice
-LOCAL_NOTICE_FILE := build/soong/licenses/LICENSE
-LOCAL_SRC_FILES := $(LOCAL_MODULE)
-LOCAL_MODULE_CLASS := ETC
-LOCAL_SYSTEM_EXT_MODULE := true
-LOCAL_MODULE_RELATIVE_PATH := init
-
-include $(BUILD_PREBUILT)
-
-
-include $(CLEAR_VARS)
-LOCAL_MODULE := init.vndk-nodef.rc
-LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
-LOCAL_LICENSE_CONDITIONS := notice
-LOCAL_NOTICE_FILE := build/soong/licenses/LICENSE
-LOCAL_SRC_FILES := $(LOCAL_MODULE)
-LOCAL_MODULE_CLASS := ETC
-LOCAL_SYSTEM_EXT_MODULE := true
-LOCAL_MODULE_RELATIVE_PATH := gsi
-
-include $(BUILD_PREBUILT)
diff --git a/core/tasks/dts.mk b/core/tasks/dts.mk
new file mode 100644
index 0000000000..8f090828d9
--- /dev/null
+++ b/core/tasks/dts.mk
@@ -0,0 +1,28 @@
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
+# Desktop test suite
+ifneq ($(wildcard test/dts/tools/dts-tradefed/README),)
+test_suite_name := dts
+test_suite_tradefed := dts-tradefed
+test_suite_readme := test/dts/tools/dts-tradefed/README
+test_suite_tools := $(HOST_OUT_JAVA_LIBRARIES)/ats_console_deploy.jar \
+  $(HOST_OUT_JAVA_LIBRARIES)/ats_olc_server_local_mode_deploy.jar
+
+include $(BUILD_SYSTEM)/tasks/tools/compatibility.mk
+
+.PHONY: dts
+dts: $(compatibility_zip) $(compatibility_tests_list_zip)
+$(call dist-for-goals, dts, $(compatibility_zip) $(compatibility_tests_list_zip))
+endif
diff --git a/core/tasks/general-tests.mk b/core/tasks/general-tests.mk
index d6fc0722ef..1901ed5658 100644
--- a/core/tasks/general-tests.mk
+++ b/core/tasks/general-tests.mk
@@ -27,21 +27,9 @@ general_tests_list_zip := $(PRODUCT_OUT)/general-tests_list.zip
 # Create an artifact to include all test config files in general-tests.
 general_tests_configs_zip := $(PRODUCT_OUT)/general-tests_configs.zip
 
-# Copy kernel test modules to testcases directories
-include $(BUILD_SYSTEM)/tasks/tools/vts-kernel-tests.mk
-ltp_copy_pairs := \
-  $(call target-native-copy-pairs,$(kernel_ltp_modules),$(kernel_ltp_host_out))
-copy_ltp_tests := $(call copy-many-files,$(ltp_copy_pairs))
-
-# PHONY target to be used to build and test `vts_ltp_tests` without building full vts
-.PHONY: vts_kernel_ltp_tests
-vts_kernel_ltp_tests: $(copy_ltp_tests)
-
 general_tests_shared_libs_zip := $(PRODUCT_OUT)/general-tests_host-shared-libs.zip
 
 $(general_tests_zip) : $(general_tests_shared_libs_zip)
-$(general_tests_zip) : $(copy_ltp_tests)
-$(general_tests_zip) : PRIVATE_KERNEL_LTP_HOST_OUT := $(kernel_ltp_host_out)
 $(general_tests_zip) : PRIVATE_general_tests_list_zip := $(general_tests_list_zip)
 $(general_tests_zip) : .KATI_IMPLICIT_OUTPUTS := $(general_tests_list_zip) $(general_tests_configs_zip)
 $(general_tests_zip) : PRIVATE_TOOLS := $(general_tests_tools)
@@ -52,7 +40,6 @@ $(general_tests_zip) : $(COMPATIBILITY.general-tests.FILES) $(COMPATIBILITY.gene
 	rm -f $@ $(PRIVATE_general_tests_list_zip)
 	mkdir -p $(PRIVATE_INTERMEDIATES_DIR) $(PRIVATE_INTERMEDIATES_DIR)/tools
 	echo $(sort $(COMPATIBILITY.general-tests.FILES) $(COMPATIBILITY.general-tests.SOONG_INSTALLED_COMPATIBILITY_SUPPORT_FILES)) | tr " " "\n" > $(PRIVATE_INTERMEDIATES_DIR)/list
-	find $(PRIVATE_KERNEL_LTP_HOST_OUT) >> $(PRIVATE_INTERMEDIATES_DIR)/list
 	grep $(HOST_OUT_TESTCASES) $(PRIVATE_INTERMEDIATES_DIR)/list > $(PRIVATE_INTERMEDIATES_DIR)/host.list || true
 	grep $(TARGET_OUT_TESTCASES) $(PRIVATE_INTERMEDIATES_DIR)/list > $(PRIVATE_INTERMEDIATES_DIR)/target.list || true
 	grep -e .*\\.config$$ $(PRIVATE_INTERMEDIATES_DIR)/host.list > $(PRIVATE_INTERMEDIATES_DIR)/host-test-configs.list || true
diff --git a/core/tasks/tools/vts-kernel-tests.mk b/core/tasks/prebuilt_tradefed.mk
similarity index 55%
rename from core/tasks/tools/vts-kernel-tests.mk
rename to core/tasks/prebuilt_tradefed.mk
index e727dc1f55..96c57d5633 100644
--- a/core/tasks/tools/vts-kernel-tests.mk
+++ b/core/tasks/prebuilt_tradefed.mk
@@ -1,4 +1,4 @@
-# Copyright (C) 2022 The Android Open Source Project
+# Copyright (C) 2020 The Android Open Source Project
 #
 # Licensed under the Apache License, Version 2.0 (the "License");
 # you may not use this file except in compliance with the License.
@@ -12,13 +12,11 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 
--include external/ltp/android/ltp_package_list.mk
+ifeq (,$(wildcard tools/tradefederation/core))
+.PHONY: tradefed-core
+tradefed-core: tradefed atest_tradefed.sh
+.PHONY: tradefed-all
+tradefed-all: tradefed atest_tradefed.sh
 
-include $(BUILD_SYSTEM)/tasks/tools/vts_package_utils.mk
-
-# Copy kernel test modules to testcases directories
-kernel_ltp_host_out := $(HOST_OUT_TESTCASES)/vts_kernel_ltp_tests
-kernel_ltp_vts_out := $(HOST_OUT)/$(test_suite_name)/android-$(test_suite_name)/testcases/vts_kernel_ltp_tests
-kernel_ltp_modules := \
-    ltp \
-    $(ltp_packages)
+$(call dist-for-goals, tradefed, $(HOST_OUT)/etc/tradefed.zip)
+endif
diff --git a/core/tasks/sts-sdk.mk b/core/tasks/sts-sdk.mk
deleted file mode 100644
index 4abbc29c5e..0000000000
--- a/core/tasks/sts-sdk.mk
+++ /dev/null
@@ -1,39 +0,0 @@
-# Copyright (C) 2022 The Android Open Source Project
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
-ifneq ($(wildcard test/sts/README-sts-sdk.md),)
-test_suite_name := sts-sdk
-test_suite_tradefed := sts-tradefed
-test_suite_readme := test/sts/README-sts-sdk.md
-sts_sdk_zip := $(HOST_OUT)/$(test_suite_name)/sts-sdk.zip
-
-include $(BUILD_SYSTEM)/tasks/tools/compatibility.mk
-
-sts_sdk_plugin_skel := $(call intermediates-dir-for,ETC,sts-sdk-plugin-skel.zip)/sts-sdk-plugin-skel.zip
-
-$(sts_sdk_zip): STS_SDK_ZIP := $(compatibility_zip)
-$(sts_sdk_zip): STS_SDK_PLUGIN_SKEL := $(sts_sdk_plugin_skel)
-$(sts_sdk_zip): $(MERGE_ZIPS) $(ZIP2ZIP) $(compatibility_zip) $(sts_sdk_plugin_skel)
-	rm -f $@ $(STS_SDK_ZIP)_filtered
-	$(ZIP2ZIP) -i $(STS_SDK_ZIP) -o $(STS_SDK_ZIP)_filtered \
-		-x android-sts-sdk/tools/sts-tradefed-tests.jar \
-		'android-sts-sdk/tools/*:sts-sdk/src/main/resources/sts-tradefed-tools/'
-	$(MERGE_ZIPS) $@ $(STS_SDK_ZIP)_filtered $(STS_SDK_PLUGIN_SKEL)
-	rm -f $(STS_SDK_ZIP)_filtered
-
-.PHONY: sts-sdk
-sts-sdk: $(sts_sdk_zip)
-$(call dist-for-goals, sts-sdk, $(sts_sdk_zip))
-
-endif
diff --git a/core/tasks/tools/vts_package_utils.mk b/core/tasks/tools/vts_package_utils.mk
deleted file mode 100644
index 1a819f2172..0000000000
--- a/core/tasks/tools/vts_package_utils.mk
+++ /dev/null
@@ -1,34 +0,0 @@
-#
-# Copyright (C) 2020 The Android Open Source Project
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
-# $(1): List of target native files to copy.
-# $(2): Copy destination directory.
-# Evaluates to a list of ":"-separated pairs src:dst.
-define target-native-copy-pairs
-$(foreach m,$(1),\
-  $(eval _built_files := $(strip $(ALL_MODULES.$(m).BUILT_INSTALLED)\
-  $(ALL_MODULES.$(m)$(TARGET_2ND_ARCH_MODULE_SUFFIX).BUILT_INSTALLED)))\
-  $(foreach i, $(sort $(_built_files)),\
-    $(eval bui_ins := $(subst :,$(space),$(i)))\
-    $(eval ins := $(word 2,$(bui_ins)))\
-    $(if $(filter $(TARGET_OUT_ROOT)/%,$(ins)),\
-      $(eval bui := $(word 1,$(bui_ins)))\
-      $(eval my_copy_dest := $(patsubst data/%,DATA/%,\
-                               $(patsubst system/%,DATA/%,\
-                                   $(patsubst $(PRODUCT_OUT)/%,%,$(ins)))))\
-      $(call declare-copy-target-license-metadata,$(2)/$(my_copy_dest),$(bui))\
-      $(bui):$(2)/$(my_copy_dest))))
-endef
diff --git a/core/tasks/vts-core-tests.mk b/core/tasks/vts-core-tests.mk
index 1eeb0789ec..11bb932f7d 100644
--- a/core/tasks/vts-core-tests.mk
+++ b/core/tasks/vts-core-tests.mk
@@ -16,15 +16,6 @@ test_suite_name := vts
 test_suite_tradefed := vts-tradefed
 test_suite_readme := test/vts/tools/vts-core-tradefed/README
 
-include $(BUILD_SYSTEM)/tasks/tools/vts-kernel-tests.mk
-
-ltp_copy_pairs := \
-  $(call target-native-copy-pairs,$(kernel_ltp_modules),$(kernel_ltp_vts_out))
-
-copy_ltp_tests := $(call copy-many-files,$(ltp_copy_pairs))
-
-test_suite_extra_deps := $(copy_ltp_tests)
-
 include $(BUILD_SYSTEM)/tasks/tools/compatibility.mk
 
 .PHONY: vts
diff --git a/core/version_util.mk b/core/version_util.mk
index 0e346347bb..ddcbda2cdc 100644
--- a/core/version_util.mk
+++ b/core/version_util.mk
@@ -23,6 +23,7 @@
 #     PLATFORM_DISPLAY_VERSION
 #     PLATFORM_SDK_VERSION
 #     PLATFORM_SDK_EXTENSION_VERSION
+#     PLATFORM_BASE_SDK_EXTENSION_VERSION
 #     PLATFORM_VERSION_CODENAME
 #     DEFAULT_APP_TARGET_SDK
 #     BUILD_ID
@@ -61,14 +62,28 @@ endif
 PLATFORM_SDK_VERSION := $(RELEASE_PLATFORM_SDK_VERSION)
 .KATI_READONLY := PLATFORM_SDK_VERSION
 
+ifdef PLATFORM_SDK_MINOR_VERSION
+  $(error Do not set PLATFORM_SDK_MINOR_VERSION directly. Use RELEASE_PLATFORM_SDK_MINOR_VERSION. value: $(PLATFORM_SDK_MINOR_VERSION))
+endif
+PLATFORM_SDK_MINOR_VERSION := $(RELEASE_PLATFORM_SDK_MINOR_VERSION)
+.KATI_READONLY := PLATFORM_SDK_MINOR_VERSION
+
 ifdef PLATFORM_SDK_EXTENSION_VERSION
   $(error Do not set PLATFORM_SDK_EXTENSION_VERSION directly. Use RELEASE_PLATFORM_SDK_EXTENSION_VERSION. value: $(PLATFORM_SDK_EXTENSION_VERSION))
 endif
 PLATFORM_SDK_EXTENSION_VERSION := $(RELEASE_PLATFORM_SDK_EXTENSION_VERSION)
 .KATI_READONLY := PLATFORM_SDK_EXTENSION_VERSION
 
-# This is the sdk extension version that PLATFORM_SDK_VERSION ships with.
-PLATFORM_BASE_SDK_EXTENSION_VERSION := $(PLATFORM_SDK_EXTENSION_VERSION)
+ifdef PLATFORM_BASE_SDK_EXTENSION_VERSION
+  $(error Do not set PLATFORM_BASE_SDK_EXTENSION_VERSION directly. Use RELEASE_PLATFORM_BASE_SDK_EXTENSION_VERSION. value: $(PLATFORM_BASE_SDK_EXTENSION_VERSION))
+endif
+ifdef RELEASE_PLATFORM_BASE_SDK_EXTENSION_VERSION
+  # This is the sdk extension version that PLATFORM_SDK_VERSION ships with.
+  PLATFORM_BASE_SDK_EXTENSION_VERSION := $(RELEASE_PLATFORM_BASE_SDK_EXTENSION_VERSION)
+else
+  # Fallback to PLATFORM_SDK_EXTENSION_VERSION if RELEASE_PLATFORM_BASE_SDK_EXTENSION_VERSION is undefined.
+  PLATFORM_BASE_SDK_EXTENSION_VERSION := $(PLATFORM_SDK_EXTENSION_VERSION)
+endif
 .KATI_READONLY := PLATFORM_BASE_SDK_EXTENSION_VERSION
 
 ifdef PLATFORM_VERSION_CODENAME
diff --git a/envsetup.sh b/envsetup.sh
index 06dadd3f38..554a220f1d 100644
--- a/envsetup.sh
+++ b/envsetup.sh
@@ -362,7 +362,6 @@ function addcompletions()
       packages/modules/adb/adb.bash
       system/core/fastboot/fastboot.bash
       tools/asuite/asuite.sh
-      prebuilts/bazel/common/bazel-complete.bash
     )
     # Completion can be disabled selectively to allow users to use non-standard completion.
     # e.g.
@@ -442,6 +441,7 @@ function print_lunch_menu()
 function lunch()
 {
     local answer
+    setup_cog_env_if_needed
 
     if [[ $# -gt 1 ]]; then
         echo "usage: lunch [target]" >&2
@@ -1079,10 +1079,7 @@ function source_vendorsetup() {
         done
     done
 
-    if [[ "${PWD}" == /google/cog/* ]]; then
-        f="build/make/cogsetup.sh"
-        echo "including $f"; . "$T/$f"
-    fi
+    setup_cog_env_if_needed
 }
 
 function showcommands() {
diff --git a/shell_utils.sh b/shell_utils.sh
index 86f3f49f50..9053c42e75 100644
--- a/shell_utils.sh
+++ b/shell_utils.sh
@@ -63,6 +63,70 @@ function require_lunch
 }
 fi
 
+# This function sets up the build environment to be appropriate for Cog.
+function setup_cog_env_if_needed() {
+  local top=$(gettop)
+
+  # return early if not in a cog workspace
+  if [[ ! "$top" =~ ^/google/cog ]]; then
+    return 0
+  fi
+
+  setup_cog_symlink
+
+  export ANDROID_BUILD_ENVIRONMENT_CONFIG="googler-cog"
+
+  # Running repo command within Cog workspaces is not supported, so override
+  # it with this function. If the user is running repo within a Cog workspace,
+  # we'll fail with an error, otherwise, we run the original repo command with
+  # the given args.
+  if ! ORIG_REPO_PATH=`which repo`; then
+    return 0
+  fi
+  function repo {
+    if [[ "${PWD}" == /google/cog/* ]]; then
+      echo -e "\e[01;31mERROR:\e[0mrepo command is disallowed within Cog workspaces."
+      kill -INT $$ # exits the script without exiting the user's shell
+    fi
+    ${ORIG_REPO_PATH} "$@"
+  }
+}
+
+# creates a symlink for the out/ dir when inside a cog workspace.
+function setup_cog_symlink() {
+  local out_dir=$(getoutdir)
+  local top=$(gettop)
+
+  # return early if out dir is already a symlink
+  if [[ -L "$out_dir" ]]; then
+    return 0
+  fi
+
+  # return early if out dir is not in the workspace
+  if [[ ! "$out_dir" =~ ^$top/ ]]; then
+    return 0
+  fi
+
+  local link_destination="${HOME}/.cog/android-build-out"
+
+  # remove existing out/ dir if it exists
+  if [[ -d "$out_dir" ]]; then
+    echo "Detected existing out/ directory in the Cog workspace which is not supported. Repairing workspace by removing it and creating the symlink to ~/.cog/android-build-out"
+    if ! rm -rf "$out_dir"; then
+      echo "Failed to remove existing out/ directory: $out_dir" >&2
+      kill -INT $$ # exits the script without exiting the user's shell
+    fi
+  fi
+
+  # create symlink
+  echo "Creating symlink: $out_dir -> $link_destination"
+  mkdir -p ${link_destination}
+  if ! ln -s "$link_destination" "$out_dir"; then
+    echo "Failed to create cog symlink: $out_dir -> $link_destination" >&2
+    kill -INT $$ # exits the script without exiting the user's shell
+  fi
+}
+
 function getoutdir
 {
     local top=$(gettop)
@@ -114,11 +178,11 @@ function _wrap_build()
         echo -n "${color_failed}#### failed to build some targets "
     fi
     if [ $hours -gt 0 ] ; then
-        printf "(%02g:%02g:%02g (hh:mm:ss))" $hours $mins $secs
+        printf "(%02d:%02d:%02d (hh:mm:ss))" $hours $mins $secs
     elif [ $mins -gt 0 ] ; then
-        printf "(%02g:%02g (mm:ss))" $mins $secs
+        printf "(%02d:%02d (mm:ss))" $mins $secs
     elif [ $secs -gt 0 ] ; then
-        printf "(%s seconds)" $secs
+        printf "(%d seconds)" $secs
     fi
     echo " ####${color_reset}"
     echo
diff --git a/target/board/Android.mk b/target/board/android-info.mk
similarity index 71%
rename from target/board/Android.mk
rename to target/board/android-info.mk
index 8133af9a7f..36be0025ad 100644
--- a/target/board/Android.mk
+++ b/target/board/android-info.mk
@@ -51,29 +51,6 @@ $(call declare-0p-target,$(INSTALLED_ANDROID_INFO_TXT_TARGET))
 
 # Copy compatibility metadata to the device.
 
-# Device Manifest
-ifdef DEVICE_MANIFEST_FILE
-# $(DEVICE_MANIFEST_FILE) can be a list of files
-include $(CLEAR_VARS)
-LOCAL_MODULE        := vendor_manifest.xml
-LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0 legacy_not_a_contribution
-LOCAL_LICENSE_CONDITIONS := by_exception_only not_allowed notice
-LOCAL_MODULE_STEM   := manifest.xml
-LOCAL_MODULE_CLASS  := ETC
-LOCAL_MODULE_PATH   := $(TARGET_OUT_VENDOR)/etc/vintf
-
-GEN := $(local-generated-sources-dir)/manifest.xml
-$(GEN): PRIVATE_DEVICE_MANIFEST_FILE := $(DEVICE_MANIFEST_FILE)
-$(GEN): $(DEVICE_MANIFEST_FILE) $(HOST_OUT_EXECUTABLES)/assemble_vintf
-	BOARD_SEPOLICY_VERS=$(BOARD_SEPOLICY_VERS) \
-	PRODUCT_ENFORCE_VINTF_MANIFEST=$(PRODUCT_ENFORCE_VINTF_MANIFEST) \
-	$(HOST_OUT_EXECUTABLES)/assemble_vintf -o $@ \
-		-i $(call normalize-path-list,$(PRIVATE_DEVICE_MANIFEST_FILE))
-
-LOCAL_PREBUILT_MODULE_FILE := $(GEN)
-include $(BUILD_PREBUILT)
-endif
-
 # DEVICE_MANIFEST_SKUS: a list of SKUS where DEVICE_MANIFEST_<sku>_FILES is defined.
 ifdef DEVICE_MANIFEST_SKUS
 
@@ -112,30 +89,6 @@ _add_device_sku_manifest :=
 
 endif # DEVICE_MANIFEST_SKUS
 
-# ODM manifest
-ifdef ODM_MANIFEST_FILES
-# ODM_MANIFEST_FILES is a list of files that is combined and installed as the default ODM manifest.
-include $(CLEAR_VARS)
-LOCAL_MODULE := odm_manifest.xml
-LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0 legacy_not_a_contribution
-LOCAL_LICENSE_CONDITIONS := by_exception_only not_allowed notice
-LOCAL_MODULE_STEM := manifest.xml
-LOCAL_MODULE_CLASS := ETC
-LOCAL_MODULE_RELATIVE_PATH := vintf
-LOCAL_ODM_MODULE := true
-
-GEN := $(local-generated-sources-dir)/manifest.xml
-$(GEN): PRIVATE_SRC_FILES := $(ODM_MANIFEST_FILES)
-$(GEN): $(ODM_MANIFEST_FILES) $(HOST_OUT_EXECUTABLES)/assemble_vintf
-	# Set VINTF_IGNORE_TARGET_FCM_VERSION to true because it should only be in device manifest.
-	VINTF_IGNORE_TARGET_FCM_VERSION=true \
-	$(HOST_OUT_EXECUTABLES)/assemble_vintf -o $@ \
-		-i $(call normalize-path-list,$(PRIVATE_SRC_FILES))
-
-LOCAL_PREBUILT_MODULE_FILE := $(GEN)
-include $(BUILD_PREBUILT)
-endif # ODM_MANIFEST_FILES
-
 # ODM_MANIFEST_SKUS: a list of SKUS where ODM_MANIFEST_<sku>_FILES are defined.
 ifdef ODM_MANIFEST_SKUS
 
diff --git a/target/product/app_function_extensions.mk b/target/product/app_function_extensions.mk
index a61afdc5ab..e601fd7ca3 100644
--- a/target/product/app_function_extensions.mk
+++ b/target/product/app_function_extensions.mk
@@ -18,5 +18,5 @@
 
 # /system_ext packages
 PRODUCT_PACKAGES += \
-    com.google.android.appfunctions.sidecar \
-    appfunctions.sidecar.xml
+    com.android.extensions.appfunctions \
+    appfunctions.extension.xml
diff --git a/target/product/base_system.mk b/target/product/base_system.mk
index 586d2b896b..a78c023a36 100644
--- a/target/product/base_system.mk
+++ b/target/product/base_system.mk
@@ -17,7 +17,7 @@
 # Base modules and settings for the system partition.
 PRODUCT_PACKAGES += \
     abx \
-    aconfigd \
+    aconfigd-system \
     adbd_system_api \
     aflags \
     am \
@@ -96,6 +96,7 @@ PRODUCT_PACKAGES += \
     enhanced-confirmation.xml \
     ExtShared \
     flags_health_check \
+    framework-connectivity-b \
     framework-graphics \
     framework-location \
     framework-minus-apex \
@@ -205,7 +206,6 @@ PRODUCT_PACKAGES += \
     libstdc++ \
     libsysutils \
     libui \
-    libuprobestats_client \
     libusbhost \
     libutils \
     libvintf_jni \
@@ -213,6 +213,7 @@ PRODUCT_PACKAGES += \
     libwilhelm \
     linker \
     llkd \
+    llndk_libs \
     lmkd \
     LocalTransport \
     locksettings \
@@ -248,6 +249,7 @@ PRODUCT_PACKAGES += \
     pintool \
     platform.xml \
     pm \
+    prefetch \
     preinstalled-packages-asl-files.xml \
     preinstalled-packages-platform.xml \
     preinstalled-packages-strict-signature.xml \
@@ -276,7 +278,6 @@ PRODUCT_PACKAGES += \
     Shell \
     shell_and_utilities_system \
     sm \
-    snapshotctl \
     snapuserd \
     storaged \
     surfaceflinger \
@@ -289,6 +290,7 @@ PRODUCT_PACKAGES += \
     tombstoned \
     traced \
     traced_probes \
+    tradeinmode \
     tune2fs \
     uiautomator \
     uinput \
@@ -308,8 +310,20 @@ ifeq ($(RELEASE_CRASHRECOVERY_MODULE),true)
   PRODUCT_PACKAGES += \
         com.android.crashrecovery \
 
+else
+  PRODUCT_PACKAGES += \
+    framework-platformcrashrecovery \
+
 endif
 
+# When we release ondeviceintelligence in neuralnetworks module
+ifneq ($(RELEASE_ONDEVICE_INTELLIGENCE_MODULE),true)
+  PRODUCT_PACKAGES += \
+        framework-ondeviceintelligence-platform
+
+endif
+
+
 # When we release uprobestats module
 ifeq ($(RELEASE_UPROBESTATS_MODULE),true)
     PRODUCT_PACKAGES += \
@@ -318,6 +332,7 @@ ifeq ($(RELEASE_UPROBESTATS_MODULE),true)
 else
     PRODUCT_PACKAGES += \
         uprobestats \
+        libuprobestats_client \
 
 endif
 
@@ -348,8 +363,7 @@ endif
 # Check if the build supports Profiling module
 ifeq ($(RELEASE_PACKAGE_PROFILING_MODULE),true)
     PRODUCT_PACKAGES += \
-       com.android.profiling \
-       trace_redactor
+       com.android.profiling
 endif
 
 ifeq ($(RELEASE_USE_WEBVIEW_BOOTSTRAP_MODULE),true)
@@ -362,6 +376,11 @@ ifneq (,$(RELEASE_RANGING_STACK))
         com.android.ranging
 endif
 
+ifeq ($(RELEASE_MEMORY_MANAGEMENT_DAEMON),true)
+  PRODUCT_PACKAGES += \
+        mm_daemon
+endif
+
 # VINTF data for system image
 PRODUCT_PACKAGES += \
     system_manifest.xml \
@@ -436,6 +455,7 @@ PRODUCT_HOST_PACKAGES += \
     lpdump \
     mke2fs \
     mkfs.erofs \
+    pbtombstone \
     resize2fs \
     sgdisk \
     sqlite3 \
@@ -503,6 +523,7 @@ PRODUCT_PACKAGES_DEBUG := \
     record_binder \
     servicedispatcher \
     showmap \
+    snapshotctl \
     sqlite3 \
     ss \
     start_with_lockagent \
diff --git a/target/product/base_system_ext.mk b/target/product/base_system_ext.mk
index febe5378b5..6767b9a3a9 100644
--- a/target/product/base_system_ext.mk
+++ b/target/product/base_system_ext.mk
@@ -30,3 +30,8 @@ PRODUCT_PACKAGES += \
 PRODUCT_PACKAGES_SHIPPING_API_LEVEL_34 += \
     hwservicemanager \
     android.hidl.allocator@1.0-service \
+
+# AppFunction Extensions
+ifneq (,$(RELEASE_APPFUNCTION_SIDECAR))
+    $(call inherit-product, $(SRC_TARGET_DIR)/product/app_function_extensions.mk)
+endif
\ No newline at end of file
diff --git a/target/product/base_vendor.mk b/target/product/base_vendor.mk
index a80e0b31b6..16fc7fd906 100644
--- a/target/product/base_vendor.mk
+++ b/target/product/base_vendor.mk
@@ -17,7 +17,6 @@
 # Base modules and settings for recovery.
 PRODUCT_PACKAGES += \
     adbd.recovery \
-    android.hardware.health@2.0-impl-default.recovery \
     build_flag_vendor \
     cgroups.recovery.json \
     charger.recovery \
@@ -72,6 +71,8 @@ PRODUCT_PACKAGES += \
     passwd_odm \
     passwd_vendor \
     selinux_policy_nonsystem \
+    selinux_policy_vendor \
+    selinux_policy_odm \
     shell_and_utilities_vendor \
     odm-build.prop \
 
@@ -105,6 +106,7 @@ PRODUCT_PACKAGES_SHIPPING_API_LEVEL_29 += \
 # VINTF data for vendor image
 PRODUCT_PACKAGES += \
     vendor_compatibility_matrix.xml \
+    vendor_manifest.xml \
 
 # Base modules and settings for the debug ramdisk, which is then packed
 # into a boot-debug.img and a vendor_boot-debug.img.
diff --git a/target/product/build_variables.mk b/target/product/build_variables.mk
index 7661e063a7..c9369112aa 100644
--- a/target/product/build_variables.mk
+++ b/target/product/build_variables.mk
@@ -20,8 +20,17 @@
 # Control libbinder client caching
 $(call soong_config_set, libbinder, release_libbinder_client_cache, $(RELEASE_LIBBINDER_CLIENT_CACHE))
 
+# Control caching while adding service in libbinder cache
+$(call soong_config_set, libbinder, release_libbinder_addservice_cache, $(RELEASE_LIBBINDER_ADDSERVICE_CACHE))
+
+# Remove static list in libbinder cache
+$(call soong_config_set, libbinder, release_libbinder_remove_cache_static_list, $(RELEASE_LIBBINDER_REMOVE_CACHE_STATIC_LIST))
+
 # Use the configured release of sqlite
 $(call soong_config_set, libsqlite3, release_package_libsqlite3, $(RELEASE_PACKAGE_LIBSQLITE3))
 
 # Use the configured MessageQueue implementation
 $(call soong_config_set, messagequeue, release_package_messagequeue_implementation, $(RELEASE_PACKAGE_MESSAGEQUEUE_IMPLEMENTATION))
+
+# Use the configured version of WebView
+$(call soong_config_set, webview, release_package_webview_version, $(RELEASE_PACKAGE_WEBVIEW_VERSION))
diff --git a/target/product/default_art_config.mk b/target/product/default_art_config.mk
index 668f054773..33891d77f1 100644
--- a/target/product/default_art_config.mk
+++ b/target/product/default_art_config.mk
@@ -51,6 +51,7 @@ PRODUCT_BOOT_JARS += \
     framework-minus-apex \
     framework-graphics \
     framework-location \
+    framework-connectivity-b \
     ext \
     telephony-common \
     voip-common \
@@ -90,11 +91,27 @@ PRODUCT_APEX_BOOT_JARS := \
     com.android.virt:framework-virtualization \
     com.android.wifi:framework-wifi \
 
-# When we release crashrecovery module
+# When crashrecovery module is ready use apex jar
+# else put the platform jar in system
 ifeq ($(RELEASE_CRASHRECOVERY_MODULE),true)
-  PRODUCT_APEX_BOOT_JARS += \
+    PRODUCT_APEX_BOOT_JARS += \
         com.android.crashrecovery:framework-crashrecovery \
 
+else
+    PRODUCT_BOOT_JARS += \
+        framework-platformcrashrecovery \
+
+endif
+
+# When we release ondeviceintelligence in NeuralNetworks module
+ifeq ($(RELEASE_ONDEVICE_INTELLIGENCE_MODULE),true)
+    PRODUCT_APEX_BOOT_JARS += \
+    com.android.neuralnetworks:framework-ondeviceintelligence \
+
+else
+    PRODUCT_BOOT_JARS += \
+        framework-ondeviceintelligence-platform \
+
 endif
 
 # Check if the build supports NFC apex or not
@@ -142,6 +159,13 @@ ifeq ($(RELEASE_CRASHRECOVERY_MODULE),true)
 
 endif
 
+# When we release ondeviceintelligence in NeuralNetworks module
+ifeq ($(RELEASE_ONDEVICE_INTELLIGENCE_MODULE),true)
+    PRODUCT_APEX_SYSTEM_SERVER_JARS += \
+        com.android.neuralnetworks:service-ondeviceintelligence
+
+endif
+
 ifeq ($(RELEASE_AVF_ENABLE_LLPVM_CHANGES),true)
   PRODUCT_APEX_SYSTEM_SERVER_JARS += com.android.virt:service-virtualization
 endif
diff --git a/target/product/generic/Android.bp b/target/product/generic/Android.bp
new file mode 100644
index 0000000000..a4a20b49f4
--- /dev/null
+++ b/target/product/generic/Android.bp
@@ -0,0 +1,915 @@
+generic_rootdirs = [
+    "acct",
+    "apex",
+    "bootstrap-apex",
+    "config",
+    "data",
+    "data_mirror",
+    "debug_ramdisk",
+    "dev",
+    "linkerconfig",
+    "metadata",
+    "mnt",
+    "odm",
+    "odm_dlkm",
+    "oem",
+    "postinstall",
+    "proc",
+    "second_stage_resources",
+    "storage",
+    "sys",
+    "system",
+    "system_dlkm",
+    "tmp",
+    "vendor",
+    "vendor_dlkm",
+]
+
+android_rootdirs = [
+    "system_ext",
+    "product",
+]
+
+generic_symlinks = [
+    {
+        target: "/system/bin/init",
+        name: "init",
+    },
+    {
+        target: "/system/etc",
+        name: "etc",
+    },
+    {
+        target: "/system/bin",
+        name: "bin",
+    },
+    {
+        target: "/vendor",
+        name: "system/vendor",
+    },
+    {
+        target: "/system_dlkm/lib/modules",
+        name: "system/lib/modules",
+    },
+    {
+        target: "/data/user_de/0/com.android.shell/files/bugreports",
+        name: "bugreports",
+    },
+    {
+        target: "/sys/kernel/debug",
+        name: "d",
+    },
+    {
+        target: "/storage/self/primary",
+        name: "sdcard",
+    },
+    {
+        target: "/product/etc/security/adb_keys",
+        name: "adb_keys",
+    },
+    // For Treble Generic System Image (GSI), system-as-root GSI needs to work on both devices with
+    // and without /odm partition. Those symlinks are for devices without /odm partition. For
+    // devices with /odm partition, mount odm.img under /odm will hide those symlinks.
+    {
+        target: "/vendor/odm/app",
+        name: "odm/app",
+    },
+    {
+        target: "/vendor/odm/bin",
+        name: "odm/bin",
+    },
+    {
+        target: "/vendor/odm/etc",
+        name: "odm/etc",
+    },
+    {
+        target: "/vendor/odm/firmware",
+        name: "odm/firmware",
+    },
+    {
+        target: "/vendor/odm/framework",
+        name: "odm/framework",
+    },
+    {
+        target: "/vendor/odm/lib",
+        name: "odm/lib",
+    },
+    {
+        target: "/vendor/odm/lib64",
+        name: "odm/lib64",
+    },
+    {
+        target: "/vendor/odm/overlay",
+        name: "odm/overlay",
+    },
+    {
+        target: "/vendor/odm/priv-app",
+        name: "odm/priv-app",
+    },
+    {
+        target: "/vendor/odm/usr",
+        name: "odm/usr",
+    },
+]
+
+android_symlinks = [
+    {
+        target: "/product",
+        name: "system/product",
+    },
+    {
+        target: "/system_ext",
+        name: "system/system_ext",
+    },
+    {
+        target: "/data/cache",
+        name: "cache",
+    },
+]
+
+filegroup {
+    name: "generic_system_sign_key",
+    srcs: [":avb_testkey_rsa4096"],
+}
+
+phony {
+    name: "generic_system_fonts",
+    required: [
+        "AndroidClock.ttf",
+        "CarroisGothicSC-Regular.ttf",
+        "ComingSoon.ttf",
+        "CutiveMono.ttf",
+        "DancingScript-Regular.ttf",
+        "DroidSansMono.ttf",
+        "NotoColorEmoji.ttf",
+        "NotoColorEmojiFlags.ttf",
+        "NotoNaskhArabic-Bold.ttf",
+        "NotoNaskhArabic-Regular.ttf",
+        "NotoNaskhArabicUI-Bold.ttf",
+        "NotoNaskhArabicUI-Regular.ttf",
+        "NotoSansAdlam-VF.ttf",
+        "NotoSansAhom-Regular.otf",
+        "NotoSansAnatolianHieroglyphs-Regular.otf",
+        "NotoSansArmenian-VF.ttf",
+        "NotoSansAvestan-Regular.ttf",
+        "NotoSansBalinese-Regular.ttf",
+        "NotoSansBamum-Regular.ttf",
+        "NotoSansBassaVah-Regular.otf",
+        "NotoSansBatak-Regular.ttf",
+        "NotoSansBengali-VF.ttf",
+        "NotoSansBengaliUI-VF.ttf",
+        "NotoSansBhaiksuki-Regular.otf",
+        "NotoSansBrahmi-Regular.ttf",
+        "NotoSansBuginese-Regular.ttf",
+        "NotoSansBuhid-Regular.ttf",
+        "NotoSansCJK-Regular.ttc",
+        "NotoSansCanadianAboriginal-Regular.ttf",
+        "NotoSansCarian-Regular.ttf",
+        "NotoSansChakma-Regular.otf",
+        "NotoSansCham-Bold.ttf",
+        "NotoSansCham-Regular.ttf",
+        "NotoSansCherokee-Regular.ttf",
+        "NotoSansCoptic-Regular.ttf",
+        "NotoSansCuneiform-Regular.ttf",
+        "NotoSansCypriot-Regular.ttf",
+        "NotoSansDeseret-Regular.ttf",
+        "NotoSansDevanagari-VF.ttf",
+        "NotoSansDevanagariUI-VF.ttf",
+        "NotoSansEgyptianHieroglyphs-Regular.ttf",
+        "NotoSansElbasan-Regular.otf",
+        "NotoSansEthiopic-VF.ttf",
+        "NotoSansGeorgian-VF.ttf",
+        "NotoSansGlagolitic-Regular.ttf",
+        "NotoSansGothic-Regular.ttf",
+        "NotoSansGrantha-Regular.ttf",
+        "NotoSansGujarati-Bold.ttf",
+        "NotoSansGujarati-Regular.ttf",
+        "NotoSansGujaratiUI-Bold.ttf",
+        "NotoSansGujaratiUI-Regular.ttf",
+        "NotoSansGunjalaGondi-Regular.otf",
+        "NotoSansGurmukhi-VF.ttf",
+        "NotoSansGurmukhiUI-VF.ttf",
+        "NotoSansHanifiRohingya-Regular.otf",
+        "NotoSansHanunoo-Regular.ttf",
+        "NotoSansHatran-Regular.otf",
+        "NotoSansHebrew-Bold.ttf",
+        "NotoSansHebrew-Regular.ttf",
+        "NotoSansImperialAramaic-Regular.ttf",
+        "NotoSansInscriptionalPahlavi-Regular.ttf",
+        "NotoSansInscriptionalParthian-Regular.ttf",
+        "NotoSansJavanese-Regular.otf",
+        "NotoSansKaithi-Regular.ttf",
+        "NotoSansKannada-VF.ttf",
+        "NotoSansKannadaUI-VF.ttf",
+        "NotoSansKayahLi-Regular.ttf",
+        "NotoSansKharoshthi-Regular.ttf",
+        "NotoSansKhmer-VF.ttf",
+        "NotoSansKhmerUI-Bold.ttf",
+        "NotoSansKhmerUI-Regular.ttf",
+        "NotoSansKhojki-Regular.otf",
+        "NotoSansLao-Bold.ttf",
+        "NotoSansLao-Regular.ttf",
+        "NotoSansLaoUI-Bold.ttf",
+        "NotoSansLaoUI-Regular.ttf",
+        "NotoSansLepcha-Regular.ttf",
+        "NotoSansLimbu-Regular.ttf",
+        "NotoSansLinearA-Regular.otf",
+        "NotoSansLinearB-Regular.ttf",
+        "NotoSansLisu-Regular.ttf",
+        "NotoSansLycian-Regular.ttf",
+        "NotoSansLydian-Regular.ttf",
+        "NotoSansMalayalam-VF.ttf",
+        "NotoSansMalayalamUI-VF.ttf",
+        "NotoSansMandaic-Regular.ttf",
+        "NotoSansManichaean-Regular.otf",
+        "NotoSansMarchen-Regular.otf",
+        "NotoSansMasaramGondi-Regular.otf",
+        "NotoSansMedefaidrin-VF.ttf",
+        "NotoSansMeeteiMayek-Regular.ttf",
+        "NotoSansMeroitic-Regular.otf",
+        "NotoSansMiao-Regular.otf",
+        "NotoSansModi-Regular.ttf",
+        "NotoSansMongolian-Regular.ttf",
+        "NotoSansMro-Regular.otf",
+        "NotoSansMultani-Regular.otf",
+        "NotoSansMyanmar-Bold.otf",
+        "NotoSansMyanmar-Medium.otf",
+        "NotoSansMyanmar-Regular.otf",
+        "NotoSansMyanmarUI-Bold.otf",
+        "NotoSansMyanmarUI-Medium.otf",
+        "NotoSansMyanmarUI-Regular.otf",
+        "NotoSansNKo-Regular.ttf",
+        "NotoSansNabataean-Regular.otf",
+        "NotoSansNewTaiLue-Regular.ttf",
+        "NotoSansNewa-Regular.otf",
+        "NotoSansOgham-Regular.ttf",
+        "NotoSansOlChiki-Regular.ttf",
+        "NotoSansOldItalic-Regular.ttf",
+        "NotoSansOldNorthArabian-Regular.otf",
+        "NotoSansOldPermic-Regular.otf",
+        "NotoSansOldPersian-Regular.ttf",
+        "NotoSansOldSouthArabian-Regular.ttf",
+        "NotoSansOldTurkic-Regular.ttf",
+        "NotoSansOriya-Bold.ttf",
+        "NotoSansOriya-Regular.ttf",
+        "NotoSansOriyaUI-Bold.ttf",
+        "NotoSansOriyaUI-Regular.ttf",
+        "NotoSansOsage-Regular.ttf",
+        "NotoSansOsmanya-Regular.ttf",
+        "NotoSansPahawhHmong-Regular.otf",
+        "NotoSansPalmyrene-Regular.otf",
+        "NotoSansPauCinHau-Regular.otf",
+        "NotoSansPhagsPa-Regular.ttf",
+        "NotoSansPhoenician-Regular.ttf",
+        "NotoSansRejang-Regular.ttf",
+        "NotoSansRunic-Regular.ttf",
+        "NotoSansSamaritan-Regular.ttf",
+        "NotoSansSaurashtra-Regular.ttf",
+        "NotoSansSharada-Regular.otf",
+        "NotoSansShavian-Regular.ttf",
+        "NotoSansSinhala-VF.ttf",
+        "NotoSansSinhalaUI-VF.ttf",
+        "NotoSansSoraSompeng-Regular.otf",
+        "NotoSansSoyombo-VF.ttf",
+        "NotoSansSundanese-Regular.ttf",
+        "NotoSansSylotiNagri-Regular.ttf",
+        "NotoSansSymbols-Regular-Subsetted.ttf",
+        "NotoSansSymbols-Regular-Subsetted2.ttf",
+        "NotoSansSyriacEastern-Regular.ttf",
+        "NotoSansSyriacEstrangela-Regular.ttf",
+        "NotoSansSyriacWestern-Regular.ttf",
+        "NotoSansTagalog-Regular.ttf",
+        "NotoSansTagbanwa-Regular.ttf",
+        "NotoSansTaiLe-Regular.ttf",
+        "NotoSansTaiTham-Regular.ttf",
+        "NotoSansTaiViet-Regular.ttf",
+        "NotoSansTakri-VF.ttf",
+        "NotoSansTamil-VF.ttf",
+        "NotoSansTamilUI-VF.ttf",
+        "NotoSansTelugu-VF.ttf",
+        "NotoSansTeluguUI-VF.ttf",
+        "NotoSansThaana-Bold.ttf",
+        "NotoSansThaana-Regular.ttf",
+        "NotoSansThai-Bold.ttf",
+        "NotoSansThai-Regular.ttf",
+        "NotoSansThaiUI-Bold.ttf",
+        "NotoSansThaiUI-Regular.ttf",
+        "NotoSansTifinagh-Regular.otf",
+        "NotoSansUgaritic-Regular.ttf",
+        "NotoSansVai-Regular.ttf",
+        "NotoSansWancho-Regular.otf",
+        "NotoSansWarangCiti-Regular.otf",
+        "NotoSansYi-Regular.ttf",
+        "NotoSerif-Bold.ttf",
+        "NotoSerif-BoldItalic.ttf",
+        "NotoSerif-Italic.ttf",
+        "NotoSerif-Regular.ttf",
+        "NotoSerifArmenian-VF.ttf",
+        "NotoSerifBengali-VF.ttf",
+        "NotoSerifCJK-Regular.ttc",
+        "NotoSerifDevanagari-VF.ttf",
+        "NotoSerifDogra-Regular.ttf",
+        "NotoSerifEthiopic-VF.ttf",
+        "NotoSerifGeorgian-VF.ttf",
+        "NotoSerifGujarati-VF.ttf",
+        "NotoSerifGurmukhi-VF.ttf",
+        "NotoSerifHebrew-Bold.ttf",
+        "NotoSerifHebrew-Regular.ttf",
+        "NotoSerifHentaigana.ttf",
+        "NotoSerifKannada-VF.ttf",
+        "NotoSerifKhmer-Bold.otf",
+        "NotoSerifKhmer-Regular.otf",
+        "NotoSerifLao-Bold.ttf",
+        "NotoSerifLao-Regular.ttf",
+        "NotoSerifMalayalam-VF.ttf",
+        "NotoSerifMyanmar-Bold.otf",
+        "NotoSerifMyanmar-Regular.otf",
+        "NotoSerifNyiakengPuachueHmong-VF.ttf",
+        "NotoSerifSinhala-VF.ttf",
+        "NotoSerifTamil-VF.ttf",
+        "NotoSerifTelugu-VF.ttf",
+        "NotoSerifThai-Bold.ttf",
+        "NotoSerifThai-Regular.ttf",
+        "NotoSerifTibetan-VF.ttf",
+        "NotoSerifYezidi-VF.ttf",
+        "Roboto-Regular.ttf",
+        "RobotoFlex-Regular.ttf",
+        "RobotoStatic-Regular.ttf",
+        "SourceSansPro-Bold.ttf",
+        "SourceSansPro-BoldItalic.ttf",
+        "SourceSansPro-Italic.ttf",
+        "SourceSansPro-Regular.ttf",
+        "SourceSansPro-SemiBold.ttf",
+        "SourceSansPro-SemiBoldItalic.ttf",
+        "font_fallback.xml",
+        "fonts.xml",
+    ],
+}
+
+android_filesystem_defaults {
+    name: "system_image_defaults",
+    partition_name: "system",
+    base_dir: "system",
+    dirs: generic_rootdirs,
+    symlinks: generic_symlinks,
+    file_contexts: ":plat_file_contexts",
+    linker_config: {
+        gen_linker_config: true,
+        linker_config_srcs: [":system_linker_config_json_file"],
+    },
+    fsverity: {
+        inputs: [
+            "etc/boot-image.prof",
+            "etc/classpaths/*.pb",
+            "etc/dirty-image-objects",
+            "etc/preloaded-classes",
+            "framework/*",
+            "framework/*/*", // framework/{arch}
+            "framework/oat/*/*", // framework/oat/{arch}
+        ],
+        libs: [":framework-res{.export-package.apk}"],
+    },
+    build_logtags: true,
+    gen_aconfig_flags_pb: true,
+
+    compile_multilib: "both",
+
+    use_avb: true,
+    avb_private_key: ":generic_system_sign_key",
+    avb_algorithm: "SHA256_RSA4096",
+    avb_hash_algorithm: "sha256",
+
+    deps: [
+        "abx",
+        "aconfigd-system",
+        "aflags",
+        "am",
+        "android.software.credentials.prebuilt.xml", // generic_system
+        "android.software.webview.prebuilt.xml", // media_system
+        "android.software.window_magnification.prebuilt.xml", // handheld_system
+        "android.system.suspend-service",
+        "apexd",
+        "appops",
+        "approved-ogki-builds.xml", // base_system
+        "appwidget",
+        "atrace",
+        "audioserver",
+        "bcc",
+        "blank_screen",
+        "blkid",
+        "bmgr",
+        "bootanimation",
+        "bootstat",
+        "bpfloader",
+        "bu",
+        "bugreport",
+        "bugreportz",
+        "cameraserver",
+        "cgroups.json",
+        "cmd",
+        "content",
+        "cppreopts.sh", // generic_system
+        "credstore",
+        "debuggerd",
+        "device_config",
+        "dirty-image-objects",
+        "dmctl",
+        "dmesgd",
+        "dnsmasq",
+        "dpm",
+        "dump.erofs",
+        "dumpstate",
+        "dumpsys",
+        "e2fsck",
+        "enhanced-confirmation.xml", // base_system
+        "etc_hosts",
+        "flags_health_check",
+        "framework-audio_effects.xml", // for handheld // handheld_system
+        "framework-sysconfig.xml",
+        "fs_config_dirs_system",
+        "fs_config_files_system",
+        "fsck.erofs",
+        "fsck.f2fs", // for media_system
+        "fsck_msdos",
+        "fsverity-release-cert-der",
+        "gatekeeperd",
+        "gpu_counter_producer",
+        "gpuservice",
+        "group_system",
+        "gsi_tool",
+        "gsid",
+        "heapprofd",
+        "hid",
+        "hiddenapi-package-whitelist.xml", // from runtime_libart
+        "idc_data",
+        "idmap2",
+        "idmap2d",
+        "ime",
+        "incident",
+        "incident-helper-cmd",
+        "incident_helper",
+        "incidentd",
+        "init.environ.rc-soong",
+        "init.usb.configfs.rc",
+        "init.usb.rc",
+        "init.zygote32.rc",
+        "init.zygote64.rc",
+        "init.zygote64_32.rc",
+        "initial-package-stopped-states.xml",
+        "input",
+        "installd",
+        "ip", // base_system
+        "iptables",
+        "kcmdlinectrl",
+        "kernel-lifetimes.xml", // base_system
+        "keychars_data",
+        "keylayout_data",
+        "keystore2",
+        "ld.mc",
+        "llkd", // base_system
+        "lmkd", // base_system
+        "locksettings", // base_system
+        "logcat", // base_system
+        "logd", // base_system
+        "logpersist.start",
+        "lpdump", // base_system
+        "lshal", // base_system
+        "make_f2fs", // media_system
+        "mdnsd", // base_system
+        "media_profiles_V1_0.dtd", // base_system
+        "mediacodec.policy", // base_system
+        "mediaextractor", // base_system
+        "mediametrics", // base_system
+        "misctrl", // from base_system
+        "mke2fs", // base_system
+        "mkfs.erofs", // base_system
+        "monkey", // base_system
+        "mtectrl", // base_system
+        "ndc", // base_system
+        "netd", // base_system
+        "netutils-wrapper-1.0", // full_base
+        "notice_xml_system",
+        "odsign", // base_system
+        "otapreopt_script", // generic_system
+        "package-shareduid-allowlist.xml", // base_system
+        "passwd_system", // base_system
+        "perfetto", // base_system
+        "ping", // base_system
+        "ping6", // base_system
+        "pintool", // base_system
+        "platform.xml", // base_system
+        "pm", // base_system
+        "prefetch", //base_system
+        "preinstalled-packages-asl-files.xml", // base_system
+        "preinstalled-packages-platform-generic-system.xml", // generic_system
+        "preinstalled-packages-platform-handheld-system.xml", // handheld_system
+        "preinstalled-packages-platform.xml", // base_system
+        "preinstalled-packages-strict-signature.xml", // base_system
+        "preloaded-classes", // ok
+        "printflags", // base_system
+        "privapp-permissions-platform.xml", // base_system
+        "prng_seeder", // base_system
+        "public.libraries.android.txt",
+        "recovery-persist", // base_system
+        "recovery-refresh", // generic_system
+        "requestsync", // media_system
+        "resize2fs", // base_system
+        "rss_hwm_reset", // base_system
+        "run-as", // base_system
+        "schedtest", // base_system
+        "screencap", // base_system
+        "screenrecord", // handheld_system
+        "sdcard", // base_system
+        "secdiscard", // base_system
+        "sensorservice", // base_system
+        "service", // base_system
+        "servicemanager", // base_system
+        "settings", // base_system
+        "sfdo", // base_system
+        "sgdisk", // base_system
+        "sm", // base_system
+        "snapshotctl", // base_system
+        "snapuserd", // base_system
+        "storaged", // base_system
+        "surfaceflinger", // base_system
+        "svc", // base_system
+        "system_manifest.xml", // base_system
+        "task_profiles.json", // base_system
+        "tc", // base_system
+        "telecom", // base_system
+        "tombstoned", // base_system
+        "traced", // base_system
+        "traced_probes", // base_system
+        "tradeinmode", // base_system
+        "tune2fs", // base_system
+        "uiautomator", // base_system
+        "uinput", // base_system
+        "uncrypt", // base_system
+        "update_engine", // generic_system
+        "update_engine_sideload", // recovery
+        "update_verifier", // generic_system
+        "usbd", // base_system
+        "vdc", // base_system
+        "virtual_camera", // handheld_system // release_package_virtual_camera
+        "vold", // base_system
+        "vr", // handheld_system
+        "watchdogd", // base_system
+        "wifi.rc", // base_system
+        "wificond", // base_system
+        "wm", // base_system
+    ] + select(release_flag("RELEASE_PLATFORM_VERSION_CODENAME"), {
+        "REL": [],
+        default: [
+            "android.software.preview_sdk.prebuilt.xml", // media_system
+        ],
+    }) + select(release_flag("RELEASE_MEMORY_MANAGEMENT_DAEMON"), {
+        true: [
+            "mm_daemon", // base_system (RELEASE_MEMORY_MANAGEMENT_DAEMON)
+        ],
+        default: [],
+    }) + select(product_variable("debuggable"), {
+        true: [
+            "adevice_fingerprint",
+            "arping",
+            "avbctl",
+            "bootctl",
+            "dmuserd",
+            "evemu-record",
+            "idlcli",
+            "init-debug.rc",
+            "iotop",
+            "iperf3",
+            "iw",
+            "layertracegenerator",
+            "logtagd.rc",
+            "ot-cli-ftd",
+            "ot-ctl",
+            "procrank",
+            "profcollectctl",
+            "profcollectd",
+            "record_binder",
+            "sanitizer-status",
+            "servicedispatcher",
+            "showmap",
+            "sqlite3",
+            "ss",
+            "start_with_lockagent",
+            "strace",
+            "su",
+            "tinycap",
+            "tinyhostless",
+            "tinymix",
+            "tinypcminfo",
+            "tinyplay", // host
+            "tracepath",
+            "tracepath6",
+            "traceroute6",
+            "unwind_info",
+            "unwind_reg_info",
+            "unwind_symbols",
+            "update_engine_client",
+        ],
+        default: [],
+    }),
+    multilib: {
+        common: {
+            deps: [
+                "BackupRestoreConfirmation", // base_system
+                "BasicDreams", // handheld_system
+                "BlockedNumberProvider", // handheld_system
+                "BluetoothMidiService", // handheld_system
+                "BookmarkProvider", // handheld_system
+                "BuiltInPrintService", // handheld_system
+                "CalendarProvider", // handheld_system
+                "CallLogBackup", // telephony_system
+                "CameraExtensionsProxy", // handheld_system
+                "CaptivePortalLogin", // handheld_system
+                "CarrierDefaultApp", // telephony_system
+                "CellBroadcastLegacyApp", // telephony_system
+                "CertInstaller", // handheld_system
+                "CompanionDeviceManager", // media_system
+                "ContactsProvider", // base_system
+                "CredentialManager", // handheld_system
+                "DeviceAsWebcam", // handheld_system
+                "DeviceDiagnostics", // handheld_system - internal
+                "DocumentsUI", // handheld_system
+                "DownloadProvider", // base_system
+                "DownloadProviderUi", // handheld_system
+                "DynamicSystemInstallationService", // base_system
+                "E2eeContactKeysProvider", // base_system
+                "EasterEgg", // handheld_system
+                "ExtShared", // base_system
+                "ExternalStorageProvider", // handheld_system
+                "FusedLocation", // handheld_system
+                "HTMLViewer", // media_system
+                "InputDevices", // handheld_system
+                "IntentResolver", // base_system
+                "KeyChain", // handheld_system
+                "LiveWallpapersPicker", // generic_system, full_base
+                "LocalTransport", // base_system
+                "ManagedProvisioning", // handheld_system
+                "MediaProviderLegacy", // base_system
+                "MmsService", // handheld_system
+                "MtpService", // handheld_system
+                "MusicFX", // handheld_system
+                "NetworkStack", // base_system
+                "ONS", // telephony_system
+                "PacProcessor", // handheld_system
+                "PackageInstaller", // base_system
+                "PartnerBookmarksProvider", // generic_system
+                "PrintRecommendationService", // handheld_system
+                "PrintSpooler", // handheld_system
+                "ProxyHandler", // handheld_system
+                "SecureElement", // handheld_system
+                "SettingsProvider", // base_system
+                "SharedStorageBackup", // handheld_system
+                "Shell", // base_system
+                "SimAppDialog", // handheld_system
+                "SoundPicker", // not installed by anyone
+                "StatementService", // media_system
+                "Stk", // generic_system
+                "Tag", // generic_system
+                "TeleService", // handheld_system
+                "Telecom", // handheld_system
+                "TelephonyProvider", // handheld_system
+                "Traceur", // handheld_system
+                "UserDictionaryProvider", // handheld_system
+                "VpnDialogs", // handheld_system
+                "WallpaperBackup", // base_system
+                "adbd_system_api", // base_system
+                "android.hidl.base-V1.0-java", // base_system
+                "android.hidl.manager-V1.0-java", // base_system
+                "android.test.base", // from runtime_libart
+                "android.test.mock", // base_system
+                "android.test.runner", // base_system
+                "aosp_mainline_modules", // ok
+                "build_flag_system", // base_system
+                "charger_res_images", // generic_system
+                "com.android.apex.cts.shim.v1_prebuilt", // ok
+                "com.android.cellbroadcast", // telephony_system
+                "com.android.future.usb.accessory", // media_system
+                "com.android.location.provider", // base_system
+                "com.android.media.remotedisplay", // media_system
+                "com.android.media.remotedisplay.xml", // media_system
+                "com.android.mediadrm.signer", // media_system
+                "com.android.nfc_extras", // ok
+                "com.android.nfcservices", // base_system (RELEASE_PACKAGE_NFC_STACK != NfcNci)
+                "com.android.runtime", // ok
+                "dex_bootjars",
+                "ext", // from runtime_libart
+                "framework-graphics", // base_system
+                "framework-location", // base_system
+                "framework-minus-apex-install-dependencies", // base_system
+                "framework-connectivity-b", // base_system
+                "framework_compatibility_matrix.device.xml",
+                "generic_system_fonts", // ok
+                "hwservicemanager_compat_symlink_module", // base_system
+                "hyph-data",
+                "ims-common", // base_system
+                "init_system", // base_system
+                "javax.obex", // base_system
+                "llndk.libraries.txt", //ok
+                "org.apache.http.legacy", // base_system
+                "perfetto-extras", // system
+                "sanitizer.libraries.txt", // base_system
+                "selinux_policy_system_soong", // ok
+                "services", // base_system
+                "shell_and_utilities_system", // ok
+                "system-build.prop",
+                "system_compatibility_matrix.xml", //base_system
+                "telephony-common", // libs from TeleService
+                "voip-common", // base_system
+            ] + select(soong_config_variable("ANDROID", "release_crashrecovery_module"), {
+                "true": [
+                    "com.android.crashrecovery", // base_system (RELEASE_CRASHRECOVERY_MODULE)
+                ],
+                default: [
+                    "framework-platformcrashrecovery", // base_system
+                ],
+            }) + select(release_flag("RELEASE_ONDEVICE_INTELLIGENCE_MODULE"), {
+                true: [
+                    "com.android.neuralnetworks", // base_system (RELEASE_ONDEVICE_INTELLIGENCE_MODULE)
+                ],
+                default: [
+                    "framework-ondeviceintelligence-platform", // base_system
+                ],
+            }) + select(soong_config_variable("ANDROID", "release_package_profiling_module"), {
+                "true": [
+                    "com.android.profiling", // base_system (RELEASE_PACKAGE_PROFILING_MODULE)
+                ],
+                default: [],
+            }) + select(release_flag("RELEASE_AVATAR_PICKER_APP"), {
+                true: [
+                    "AvatarPicker", // generic_system (RELEASE_AVATAR_PICKER_APP)
+                ],
+                default: [],
+            }) + select(release_flag("RELEASE_UPROBESTATS_MODULE"), {
+                true: [
+                    "com.android.uprobestats", // base_system (RELEASE_UPROBESTATS_MODULE)
+                ],
+                default: [],
+            }),
+        },
+        prefer32: {
+            deps: [
+                "drmserver", // media_system
+                "mediaserver", // base_system
+            ],
+        },
+        lib64: {
+            deps: [
+                "android.system.virtualizationcommon-ndk",
+                "android.system.virtualizationservice-ndk",
+                "libgsi",
+                "servicemanager",
+            ] + select(release_flag("RELEASE_UPROBESTATS_MODULE"), {
+                true: [],
+                default: [
+                    "uprobestats", // base_system internal
+                ],
+            }),
+        },
+        both: {
+            deps: [
+                "android.hardware.biometrics.fingerprint@2.1", // generic_system
+                "android.hardware.radio.config@1.0", // generic_system
+                "android.hardware.radio.deprecated@1.0", // generic_system
+                "android.hardware.radio@1.0", // generic_system
+                "android.hardware.radio@1.1", // generic_system
+                "android.hardware.radio@1.2", // generic_system
+                "android.hardware.radio@1.3", // generic_system
+                "android.hardware.radio@1.4", // generic_system
+                "android.hardware.secure_element@1.0", // generic_system
+                "app_process", // base_system
+                "boringssl_self_test", // base_system
+                "heapprofd_client", // base_system
+                "libEGL", // base_system
+                "libEGL_angle", // base_system
+                "libETC1", // base_system
+                "libFFTEm", // base_system
+                "libGLESv1_CM", // base_system
+                "libGLESv1_CM_angle", // base_system
+                "libGLESv2", // base_system
+                "libGLESv2_angle", // base_system
+                "libGLESv3", // base_system
+                "libOpenMAXAL", // base_system
+                "libOpenSLES", // base_system
+                "libaaudio", // base_system
+                "libalarm_jni", // base_system
+                "libamidi", // base_system
+                "libandroid",
+                "libandroid_runtime",
+                "libandroid_servers",
+                "libandroidfw",
+                "libartpalette-system",
+                "libaudio-resampler", // generic-system
+                "libaudioeffect_jni",
+                "libaudiohal", // generic-system
+                "libaudiopolicyengineconfigurable", // generic-system
+                "libbinder",
+                "libbinder_ndk",
+                "libbinder_rpc_unstable",
+                "libcamera2ndk",
+                "libcgrouprc", // llndk library
+                "libclang_rt.asan",
+                "libcompiler_rt",
+                "libcutils", // used by many libs
+                "libdmabufheap", // used by many libs
+                "libdrm", // used by many libs // generic_system
+                "libdrmframework", // base_system
+                "libdrmframework_jni", // base_system
+                "libfdtrack", // base_system
+                "libfilterfw", // base_system
+                "libfilterpack_imageproc", // media_system
+                "libfwdlockengine", // generic_system
+                "libgatekeeper", // base_system
+                "libgui", // base_system
+                "libhardware", // base_system
+                "libhardware_legacy", // base_system
+                "libhidltransport", // generic_system
+                "libhwbinder", // generic_system
+                "libinput", // base_system
+                "libinputflinger", // base_system
+                "libiprouteutil", // base_system
+                "libjnigraphics", // base_system
+                "libjpeg", // base_system
+                "liblog", // base_system
+                "liblogwrap", // generic_system
+                "liblz4", // generic_system
+                "libmedia", // base_system
+                "libmedia_jni", // base_system
+                "libmediandk", // base_system
+                "libminui", // generic_system
+                "libmonkey_jni", // base_system - internal
+                "libmtp", // base_system
+                "libnetd_client", // base_system
+                "libnetlink", // base_system
+                "libnetutils", // base_system
+                "libneuralnetworks_packageinfo", // base_system
+                "libnl", // generic_system
+                "libpdfium", // base_system
+                "libpolicy-subsystem", // generic_system
+                "libpower", // base_system
+                "libpowermanager", // base_system
+                "libprotobuf-cpp-full", // generic_system
+                "libradio_metadata", // base_system
+                "librs_jni", // handheld_system
+                "librtp_jni", // base_system
+                "libsensorservice", // base_system
+                "libsfplugin_ccodec", // base_system
+                "libskia", // base_system
+                "libsonic", // base_system
+                "libsonivox", // base_system
+                "libsoundpool", // base_system
+                "libspeexresampler", // base_system
+                "libsqlite", // base_system
+                "libstagefright", // base_system
+                "libstagefright_foundation", // base_system
+                "libstagefright_omx", // base_system
+                "libstdc++", // base_system
+                "libsysutils", // base_system
+                "libui", // base_system
+                "libusbhost", // base_system
+                "libutils", // base_system
+                "libvendorsupport", // llndk library
+                "libvintf_jni", // base_system
+                "libvulkan", // base_system
+                "libwebviewchromium_loader", // media_system
+                "libwebviewchromium_plat_support", // media_system
+                "libwilhelm", // base_system
+                "linker", // base_system
+            ] + select(soong_config_variable("ANDROID", "TARGET_DYNAMIC_64_32_DRMSERVER"), {
+                "true": ["drmserver"],
+                default: [],
+            }) + select(soong_config_variable("ANDROID", "TARGET_DYNAMIC_64_32_MEDIASERVER"), {
+                "true": ["mediaserver"],
+                default: [],
+            }) + select(release_flag("RELEASE_UPROBESTATS_MODULE"), {
+                true: [],
+                default: [
+                    "libuprobestats_client", // base_system internal
+                ],
+            }),
+        },
+    },
+    arch: {
+        arm64: {
+            deps: [
+                "libclang_rt.hwasan",
+                "libc_hwasan",
+            ],
+        },
+    },
+}
+
+android_system_image {
+    name: "aosp_shared_system_image",
+    defaults: ["system_image_defaults"],
+    dirs: android_rootdirs,
+    symlinks: android_symlinks,
+    type: "erofs",
+    erofs: {
+        compressor: "lz4hc,9",
+        compress_hints: "erofs_compress_hints.txt",
+    },
+}
diff --git a/target/product/generic/OWNERS b/target/product/generic/OWNERS
new file mode 100644
index 0000000000..6d1446f099
--- /dev/null
+++ b/target/product/generic/OWNERS
@@ -0,0 +1,6 @@
+# Bug component: 1322713
+inseob@google.com
+jeongik@google.com
+jiyong@google.com
+justinyun@google.com
+kiyoungkim@google.com
diff --git a/target/product/generic/erofs_compress_hints.txt b/target/product/generic/erofs_compress_hints.txt
new file mode 100644
index 0000000000..8b2a711b8f
--- /dev/null
+++ b/target/product/generic/erofs_compress_hints.txt
@@ -0,0 +1 @@
+0 .*\.apex$
\ No newline at end of file
diff --git a/target/product/generic_ramdisk.mk b/target/product/generic_ramdisk.mk
index ebac62fd6b..5ecb55fca8 100644
--- a/target/product/generic_ramdisk.mk
+++ b/target/product/generic_ramdisk.mk
@@ -23,6 +23,7 @@
 PRODUCT_PACKAGES += \
     init_first_stage \
     snapuserd_ramdisk \
+    ramdisk-build.prop \
 
 # Debug ramdisk
 PRODUCT_PACKAGES += \
@@ -35,8 +36,6 @@ PRODUCT_PACKAGES += \
 _my_paths := \
     $(TARGET_COPY_OUT_RAMDISK)/ \
     $(TARGET_COPY_OUT_DEBUG_RAMDISK)/ \
-    system/usr/share/zoneinfo/tz_version \
-    system/usr/share/zoneinfo/tzdata \
     $(TARGET_COPY_OUT_RECOVERY)/root/first_stage_ramdisk/system \
 
 
diff --git a/target/product/go_defaults_common.mk b/target/product/go_defaults_common.mk
index fd4047a65b..0fcf16b753 100644
--- a/target/product/go_defaults_common.mk
+++ b/target/product/go_defaults_common.mk
@@ -24,11 +24,6 @@ PRODUCT_VENDOR_PROPERTIES += \
 # Speed profile services and wifi-service to reduce RAM and storage.
 PRODUCT_SYSTEM_SERVER_COMPILER_FILTER := speed-profile
 
-# Use a profile based boot image for this device. Note that this is currently a
-# generic profile and not Android Go optimized.
-PRODUCT_USE_PROFILE_FOR_BOOT_IMAGE := true
-PRODUCT_DEX_PREOPT_BOOT_IMAGE_PROFILE_LOCATION := frameworks/base/config/boot-image-profile.txt
-
 # Do not generate libartd.
 PRODUCT_ART_TARGET_INCLUDE_DEBUG_BUILD := false
 
diff --git a/target/product/gsi/Android.bp b/target/product/gsi/Android.bp
index 45ba14331b..9e8946d6e8 100644
--- a/target/product/gsi/Android.bp
+++ b/target/product/gsi/Android.bp
@@ -46,3 +46,164 @@ install_symlink {
     installed_location: "etc/init/config",
     symlink_target: "/system/system_ext/etc/init/config",
 }
+
+// init.gsi.rc, GSI-specific init script.
+prebuilt_etc {
+    name: "init.gsi.rc",
+    src: "init.gsi.rc",
+    system_ext_specific: true,
+    relative_install_path: "init",
+}
+
+prebuilt_etc {
+    name: "init.vndk-nodef.rc",
+    src: "init.vndk-nodef.rc",
+    system_ext_specific: true,
+    relative_install_path: "gsi",
+}
+
+gsi_symlinks = [
+    {
+        target: "/system/system_ext",
+        name: "system_ext",
+    },
+    {
+        target: "/system/product",
+        name: "product",
+    },
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
+android_system_image {
+    name: "android_gsi",
+    defaults: ["system_image_defaults"],
+    symlinks: gsi_symlinks,
+    dirs: ["cache"],
+    deps: [
+        ///////////////////////////////////////////
+        // gsi_system_ext
+        ///////////////////////////////////////////
+
+        // handheld packages
+        "Launcher3QuickStep",
+        "Provision",
+        "Settings",
+        "StorageManager",
+        "SystemUI",
+
+        // telephony packages
+        "CarrierConfig",
+
+        // Install a copy of the debug policy to the system_ext partition, and allow
+        // init-second-stage to load debug policy from system_ext.
+        // This option is only meant to be set by compliance GSI targets.
+        "system_ext_userdebug_plat_sepolicy.cil",
+
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
+        // window_extensions_base
+        ///////////////////////////////////////////
+        "androidx.window.extensions",
+        "androidx.window.sidecar",
+
+        ///////////////////////////////////////////
+        // gsi_release
+        ///////////////////////////////////////////
+        "gsi_skip_mount.cfg",
+        "init.gsi.rc",
+        "init.vndk-nodef.rc",
+        // Overlay the GSI specific setting for framework and SystemUI
+        "gsi_overlay_framework",
+        "gsi_overlay_systemui",
+
+        ///////////////////////////////////////////
+        // VNDK
+        ///////////////////////////////////////////
+        "com.android.vndk.v30",
+        "com.android.vndk.v31",
+        "com.android.vndk.v32",
+        "com.android.vndk.v33",
+        "com.android.vndk.v34",
+
+        ///////////////////////////////////////////
+        // AVF
+        ///////////////////////////////////////////
+        "com.android.compos",
+        "features_com.android.virt.xml",
+
+        ///////////////////////////////////////////
+        // gsi_product
+        ///////////////////////////////////////////
+        "Browser2",
+        "Camera2",
+        "Dialer",
+        "LatinIME",
+        "apns-full-conf.xml",
+
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
+
+        ///////////////////////////////////////////
+        // base_system
+        ///////////////////////////////////////////
+        "charger",
+    ] + select(product_variable("debuggable"), {
+        // Packages included only for eng or userdebug builds, previously debug tagged
+        true: ["adb_keys"],
+        default: [],
+    }),
+    multilib: {
+        both: {
+            // PRODUCT_PACKAGES_SHIPPING_API_LEVEL_34
+            deps: ["android.hidl.memory@1.0-impl"],
+        },
+    },
+    enabled: select(soong_config_variable("ANDROID", "PRODUCT_INSTALL_DEBUG_POLICY_TO_SYSTEM_EXT"), {
+        "true": true,
+        default: false,
+    }),
+    type: "ext4",
+}
diff --git a/target/product/gsi/current.txt b/target/product/gsi/current.txt
index f771916f7a..cbb8a0e8cd 100644
--- a/target/product/gsi/current.txt
+++ b/target/product/gsi/current.txt
@@ -24,7 +24,7 @@ LLNDK: libvulkan.so
 VNDK-SP: android.hardware.common-V2-ndk.so
 VNDK-SP: android.hardware.common.fmq-V1-ndk.so
 VNDK-SP: android.hardware.graphics.allocator-V2-ndk.so
-VNDK-SP: android.hardware.graphics.common-V5-ndk.so
+VNDK-SP: android.hardware.graphics.common-V6-ndk.so
 VNDK-SP: android.hardware.graphics.common@1.0.so
 VNDK-SP: android.hardware.graphics.common@1.1.so
 VNDK-SP: android.hardware.graphics.common@1.2.so
diff --git a/target/product/gsi_release.mk b/target/product/gsi_release.mk
index 39428d2cfe..f00c38cedf 100644
--- a/target/product/gsi_release.mk
+++ b/target/product/gsi_release.mk
@@ -82,6 +82,7 @@ PRODUCT_EXPORT_BOOT_IMAGE_TO_DIST := true
 # Additional settings used in all GSI builds
 PRODUCT_PRODUCT_PROPERTIES += \
     ro.crypto.metadata_init_delete_all_keys.enabled=false \
+    debug.codec2.bqpool_dealloc_after_stop=1 \
 
 # Window Extensions
 ifneq ($(PRODUCT_IS_ATV),true)
diff --git a/target/product/media_system_ext.mk b/target/product/media_system_ext.mk
index 34d8de3f32..e79a7eb5d1 100644
--- a/target/product/media_system_ext.mk
+++ b/target/product/media_system_ext.mk
@@ -20,14 +20,5 @@
 # base_system_ext.mk.
 $(call inherit-product, $(SRC_TARGET_DIR)/product/base_system_ext.mk)
 
-# /system_ext packages
-PRODUCT_PACKAGES += \
-    vndk_apex_snapshot_package \
-
 # Window Extensions
 $(call inherit-product, $(SRC_TARGET_DIR)/product/window_extensions_base.mk)
-
-# AppFunction Extensions
-ifneq (,$(RELEASE_APPFUNCTION_SIDECAR))
-    $(call inherit-product, $(SRC_TARGET_DIR)/product/app_function_extensions.mk)
-endif
diff --git a/target/product/security/Android.bp b/target/product/security/Android.bp
index 0d7b35e1c9..ffbec0616e 100644
--- a/target/product/security/Android.bp
+++ b/target/product/security/Android.bp
@@ -37,3 +37,8 @@ otacerts_zip {
     relative_install_path: "security",
     filename: "otacerts.zip",
 }
+
+adb_keys {
+    name: "adb_keys",
+    product_specific: true,
+}
diff --git a/target/product/security/Android.mk b/target/product/security/Android.mk
deleted file mode 100644
index 138e5bbe31..0000000000
--- a/target/product/security/Android.mk
+++ /dev/null
@@ -1,17 +0,0 @@
-LOCAL_PATH:= $(call my-dir)
-
-#######################################
-# adb key, if configured via PRODUCT_ADB_KEYS
-ifdef PRODUCT_ADB_KEYS
-  ifneq ($(filter eng userdebug,$(TARGET_BUILD_VARIANT)),)
-    include $(CLEAR_VARS)
-    LOCAL_MODULE := adb_keys
-    LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
-    LOCAL_LICENSE_CONDITIONS := notice
-    LOCAL_NOTICE_FILE := build/soong/licenses/LICENSE
-    LOCAL_MODULE_CLASS := ETC
-    LOCAL_MODULE_PATH := $(TARGET_OUT_PRODUCT_ETC)/security
-    LOCAL_PREBUILT_MODULE_FILE := $(PRODUCT_ADB_KEYS)
-    include $(BUILD_PREBUILT)
-  endif
-endif
diff --git a/target/product/virtual_ab_ota/compression.mk b/target/product/virtual_ab_ota/compression.mk
index dc1ee3e028..e77c36fb78 100644
--- a/target/product/virtual_ab_ota/compression.mk
+++ b/target/product/virtual_ab_ota/compression.mk
@@ -18,9 +18,12 @@ $(call inherit-product, $(SRC_TARGET_DIR)/product/virtual_ab_ota/launch_with_ven
 
 PRODUCT_VENDOR_PROPERTIES += ro.virtual_ab.compression.enabled=true
 PRODUCT_VENDOR_PROPERTIES += ro.virtual_ab.userspace.snapshots.enabled=true
-PRODUCT_VENDOR_PROPERTIES += ro.virtual_ab.io_uring.enabled=true
 PRODUCT_VENDOR_PROPERTIES += ro.virtual_ab.batch_writes=true
 
+# Optional assignment. On low memory devices, disabling io_uring can relieve cpu and memory
+# pressure during an OTA.
+PRODUCT_VENDOR_PROPERTIES += ro.virtual_ab.io_uring.enabled?=true
+
 # Enabling this property, will improve OTA install time
 # but will use an additional CPU core
 # PRODUCT_VENDOR_PROPERTIES += ro.virtual_ab.compression.threads=true
diff --git a/target/product/virtual_ab_ota/vabc_features.mk b/target/product/virtual_ab_ota/vabc_features.mk
index e2745a1356..d092699a47 100644
--- a/target/product/virtual_ab_ota/vabc_features.mk
+++ b/target/product/virtual_ab_ota/vabc_features.mk
@@ -31,14 +31,15 @@ PRODUCT_VENDOR_PROPERTIES += ro.virtual_ab.enabled=true
 
 PRODUCT_VENDOR_PROPERTIES += ro.virtual_ab.compression.enabled=true
 PRODUCT_VENDOR_PROPERTIES += ro.virtual_ab.userspace.snapshots.enabled=true
-PRODUCT_VENDOR_PROPERTIES += ro.virtual_ab.io_uring.enabled=true
-PRODUCT_VENDOR_PROPERTIES += ro.virtual_ab.compression.xor.enabled=true
 PRODUCT_VENDOR_PROPERTIES += ro.virtual_ab.batch_writes=true
+
+# Optional assignments, low memory devices may benefit from overriding these.
+PRODUCT_VENDOR_PROPERTIES += ro.virtual_ab.io_uring.enabled?=true
+PRODUCT_VENDOR_PROPERTIES += ro.virtual_ab.compression.xor.enabled?=true
+
 # Low memory device configurations. If memory usage and cpu utilization is
 # a bottleneck during OTA, the below configurations can be added to a
-# device's .mk file improve performance for low mem devices. Disabling
-# ro.virtual_ab.compression.xor.enabled and ro.virtual_ab.io_uring.enabled
-# is also recommended
+# device's .mk file improve performance for low mem devices.
 #
 # PRODUCT_VENDOR_PROPERTIES += ro.virtual_ab.read_ahead_size=16
 # PRODUCT_VENDOR_PROPERTIES += ro.virtual_ab.o_direct.enabled=true
diff --git a/teams/Android.bp b/teams/Android.bp
index 0f5b47529b..a2b0d1467f 100644
--- a/teams/Android.bp
+++ b/teams/Android.bp
@@ -13,6 +13,9 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
+// DON'T ADD NEW RULES HERE. For more details refer to
+// go/new-android-ownership-model
+
 package {
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
@@ -66,13 +69,6 @@ team {
     trendy_team_id: "6213135020228608",
 }
 
-team {
-    name: "trendy_team_wear_wear_cloud_platform",
-
-    // go/trendy/manage/engineers/5917762526281728
-    trendy_team_id: "5917762526281728",
-}
-
 team {
     name: "trendy_team_pixel_system_software",
 
@@ -514,13 +510,6 @@ team {
     trendy_team_id: "5489236125581312",
 }
 
-team {
-    name: "trendy_team_wear_wear_notifications_alerts_attention_management",
-
-    // go/trendy/manage/engineers/6267643681996800
-    trendy_team_id: "6267643681996800",
-}
-
 team {
     name: "trendy_team_fwk_nfc",
 
@@ -528,13 +517,6 @@ team {
     trendy_team_id: "5962312512864256",
 }
 
-team {
-    name: "trendy_team_wear_personalization_developer_surfaces",
-
-    // go/trendy/manage/engineers/4819890988810240
-    trendy_team_id: "4819890988810240",
-}
-
 team {
     name: "trendy_team_srajkumar_team",
 
@@ -689,13 +671,6 @@ team {
     trendy_team_id: "6585564972875776",
 }
 
-team {
-    name: "trendy_team_test_eng_android_wear",
-
-    // go/trendy/manage/engineers/4979150422933504
-    trendy_team_id: "4979150422933504",
-}
-
 team {
     name: "trendy_team_mesch_team",
 
@@ -717,13 +692,6 @@ team {
     trendy_team_id: "4667861043412992",
 }
 
-team {
-    name: "trendy_team_wear_wear_developer_devx",
-
-    // go/trendy/manage/engineers/4894890764697600
-    trendy_team_id: "4894890764697600",
-}
-
 team {
     name: "trendy_team_android_rust",
 
@@ -927,13 +895,6 @@ team {
     trendy_team_id: "4834972524511232",
 }
 
-team {
-    name: "trendy_team_wear_wallet_on_wear",
-
-    // go/trendy/manage/engineers/5724960437731328
-    trendy_team_id: "5724960437731328",
-}
-
 team {
     name: "trendy_team_glanceables",
 
@@ -1067,13 +1028,6 @@ team {
     trendy_team_id: "6547794223333376",
 }
 
-team {
-    name: "trendy_team_wear_3xp",
-
-    // go/trendy/manage/engineers/5692317612539904
-    trendy_team_id: "5692317612539904",
-}
-
 team {
     name: "trendy_team_clockwork",
 
@@ -1207,13 +1161,6 @@ team {
     trendy_team_id: "4786635551309824",
 }
 
-team {
-    name: "trendy_team_wear_software_nti",
-
-    // go/trendy/manage/engineers/5164973558759424
-    trendy_team_id: "5164973558759424",
-}
-
 team {
     name: "trendy_team_machine_learning",
 
@@ -1305,13 +1252,6 @@ team {
     trendy_team_id: "5098012529295360",
 }
 
-team {
-    name: "trendy_team_wear_wear_power_emulator",
-
-    // go/trendy/manage/engineers/5160338936725504
-    trendy_team_id: "5160338936725504",
-}
-
 team {
     name: "trendy_team_deprecated_framework_svetoslavganov",
 
@@ -1326,13 +1266,6 @@ team {
     trendy_team_id: "5702018510520320",
 }
 
-team {
-    name: "trendy_team_wear_opus",
-
-    // go/trendy/manage/engineers/5098351636676608
-    trendy_team_id: "5098351636676608",
-}
-
 team {
     name: "trendy_team_text_to_speech",
 
@@ -1438,13 +1371,6 @@ team {
     trendy_team_id: "4999436357238784",
 }
 
-team {
-    name: "trendy_team_wear_developer_foundation",
-
-    // go/trendy/manage/engineers/5239127108648960
-    trendy_team_id: "5239127108648960",
-}
-
 team {
     name: "trendy_team_tpm_tvc",
 
@@ -1452,13 +1378,6 @@ team {
     trendy_team_id: "5390683333230592",
 }
 
-team {
-    name: "trendy_team_wear_wear_ux",
-
-    // go/trendy/manage/engineers/5782097411080192
-    trendy_team_id: "5782097411080192",
-}
-
 team {
     name: "trendy_team_lse_desktop_os_experience",
 
@@ -1669,13 +1588,6 @@ team {
     trendy_team_id: "5401362887999488",
 }
 
-team {
-    name: "trendy_team_wear_wear_assistant",
-
-    // go/trendy/manage/engineers/5848075306172416
-    trendy_team_id: "5848075306172416",
-}
-
 team {
     name: "trendy_team_android_power_and_comms_infra",
 
@@ -3454,6 +3366,13 @@ team {
     trendy_team_id: "5770798794932224",
 }
 
+team {
+    name: "trendy_team_aaos_display_safety_triage",
+
+    // go/trendy/manage/engineers/6522093663780864
+    trendy_team_id: "6522093663780864",
+}
+
 team {
     name: "trendy_team_camera_htc_lg_qualcomm",
 
@@ -4447,3 +4366,41 @@ team {
     // go/trendy/manage/engineers/5787938454863872
     trendy_team_id: "5787938454863872",
 }
+
+team {
+    name: "trendy_team_art_cloud",
+
+    // go/trendy/manage/engineers/5121440647577600
+    trendy_team_id: "5121440647577600",
+}
+
+team {
+    name: "trendy_team_ravenwood",
+
+    // go/trendy/manage/engineers/6027181500497920
+    trendy_team_id: "6027181500497920",
+}
+
+team {
+    name: "trendy_team_automotive_cast",
+
+    // go/trendy/manage/engineers/5293683026264064
+    trendy_team_id: "5293683026264064",
+}
+
+team {
+    name: "trendy_team_wear_standalone_kids",
+
+    // go/trendy/manage/engineers/6303298703949824
+    trendy_team_id: "6303298703949824",
+}
+
+team {
+    name: "trendy_team_desktop_stats",
+
+    // go/trendy/manage/engineers/5440764114206720
+    trendy_team_id: "5440764114206720",
+}
+
+// DON'T ADD NEW RULES HERE. For more details refer to
+// go/new-android-ownership-model
diff --git a/tools/aconfig/OWNERS b/tools/aconfig/OWNERS
index 9a76279cce..c92fc7cda3 100644
--- a/tools/aconfig/OWNERS
+++ b/tools/aconfig/OWNERS
@@ -1,7 +1,8 @@
-amhk@google.com
 dzshen@google.com
-jham@google.com
-joeo@google.com
 opg@google.com
 tedbauer@google.com
 zhidou@google.com
+
+amhk@google.com  #{LAST_RESORT_SUGGESTION}
+jham@google.com  #{LAST_RESORT_SUGGESTION}
+joeo@google.com  #{LAST_RESORT_SUGGESTION}
diff --git a/tools/aconfig/TEST_MAPPING b/tools/aconfig/TEST_MAPPING
index 15e41876cf..a7f0a4fa79 100644
--- a/tools/aconfig/TEST_MAPPING
+++ b/tools/aconfig/TEST_MAPPING
@@ -102,12 +102,14 @@
     {
       // aconfig_storage file java integration tests
       "name": "aconfig_storage_file.test.java"
-    }
-  ],
-  "postsubmit": [
+    },
+    {
+      // aconfig_storage read functional test
+      "name": "aconfig_storage_read_functional"
+    },
     {
-      // aconfig_storage read api java integration tests
-      "name": "aconfig_storage_read_api.test.java"
+      // aconfig_storage read unit test
+      "name": "aconfig_storage_read_unit"
     }
   ]
 }
diff --git a/tools/aconfig/aconfig/Android.bp b/tools/aconfig/aconfig/Android.bp
index 68521af91f..5e3eb12f3b 100644
--- a/tools/aconfig/aconfig/Android.bp
+++ b/tools/aconfig/aconfig/Android.bp
@@ -68,6 +68,14 @@ aconfig_values {
     ],
 }
 
+aconfig_values {
+    name: "aconfig.test.flag.second_values",
+    package: "com.android.aconfig.test",
+    srcs: [
+        "tests/third.values",
+    ],
+}
+
 aconfig_value_set {
     name: "aconfig.test.flag.value_set",
     values: [
@@ -234,6 +242,7 @@ rust_aconfig_library {
     name: "libaconfig_test_rust_library",
     crate_name: "aconfig_test_rust_library",
     aconfig_declarations: "aconfig.test.flags",
+    host_supported: true,
 }
 
 rust_test {
diff --git a/tools/aconfig/aconfig/src/codegen/cpp.rs b/tools/aconfig/aconfig/src/codegen/cpp.rs
index 7a9c382bc7..ae18679f62 100644
--- a/tools/aconfig/aconfig/src/codegen/cpp.rs
+++ b/tools/aconfig/aconfig/src/codegen/cpp.rs
@@ -127,6 +127,26 @@ fn create_class_element(
     flag_ids: HashMap<String, u16>,
     rw_count: &mut i32,
 ) -> ClassElement {
+    let no_assigned_offset =
+        (pf.container() == "system" || pf.container() == "vendor" || pf.container() == "product")
+            && pf.permission() == ProtoFlagPermission::READ_ONLY
+            && pf.state() == ProtoFlagState::DISABLED;
+
+    let flag_offset = match flag_ids.get(pf.name()) {
+        Some(offset) => offset,
+        None => {
+            // System/vendor/product RO+disabled flags have no offset in storage files.
+            // Assign placeholder value.
+            if no_assigned_offset {
+                &0
+            }
+            // All other flags _must_ have an offset.
+            else {
+                panic!("{}", format!("missing flag offset for {}", pf.name()));
+            }
+        }
+    };
+
     ClassElement {
         readwrite_idx: if pf.permission() == ProtoFlagPermission::READ_WRITE {
             let index = *rw_count;
@@ -144,7 +164,7 @@ fn create_class_element(
         },
         flag_name: pf.name().to_string(),
         flag_macro: pf.name().to_uppercase(),
-        flag_offset: *flag_ids.get(pf.name()).expect("values checked at flag parse time"),
+        flag_offset: *flag_offset,
         device_config_namespace: pf.namespace().to_string(),
         device_config_flag: codegen::create_device_config_ident(package, pf.name())
             .expect("values checked at flag parse time"),
diff --git a/tools/aconfig/aconfig/src/codegen/java.rs b/tools/aconfig/aconfig/src/codegen/java.rs
index 1ac58c1b84..7aff4e918a 100644
--- a/tools/aconfig/aconfig/src/codegen/java.rs
+++ b/tools/aconfig/aconfig/src/codegen/java.rs
@@ -32,6 +32,7 @@ pub fn generate_java_code<I>(
     codegen_mode: CodegenMode,
     flag_ids: HashMap<String, u16>,
     allow_instrumentation: bool,
+    package_fingerprint: u64,
 ) -> Result<Vec<OutputFile>>
 where
     I: Iterator<Item = ProtoParsedFlag>,
@@ -46,6 +47,7 @@ where
     let runtime_lookup_required =
         flag_elements.iter().any(|elem| elem.is_read_write) || library_exported;
     let container = (flag_elements.first().expect("zero template flags").container).to_string();
+    let is_platform_container = matches!(container.as_str(), "system" | "product" | "vendor");
     let context = Context {
         flag_elements,
         namespace_flags,
@@ -56,6 +58,8 @@ where
         library_exported,
         allow_instrumentation,
         container,
+        is_platform_container,
+        package_fingerprint: format!("0x{:X}L", package_fingerprint),
     };
     let mut template = TinyTemplate::new();
     template.add_template("Flags.java", include_str!("../../templates/Flags.java.template"))?;
@@ -123,6 +127,8 @@ struct Context {
     pub library_exported: bool,
     pub allow_instrumentation: bool,
     pub container: String,
+    pub is_platform_container: bool,
+    pub package_fingerprint: String,
 }
 
 #[derive(Serialize, Debug)]
@@ -137,6 +143,7 @@ struct FlagElement {
     pub default_value: bool,
     pub device_config_namespace: String,
     pub device_config_flag: String,
+    pub flag_name: String,
     pub flag_name_constant_suffix: String,
     pub flag_offset: u16,
     pub is_read_write: bool,
@@ -151,13 +158,35 @@ fn create_flag_element(
 ) -> FlagElement {
     let device_config_flag = codegen::create_device_config_ident(package, pf.name())
         .expect("values checked at flag parse time");
+
+    let no_assigned_offset =
+        (pf.container() == "system" || pf.container() == "vendor" || pf.container() == "product")
+            && pf.permission() == ProtoFlagPermission::READ_ONLY
+            && pf.state() == ProtoFlagState::DISABLED;
+
+    let flag_offset = match flag_offsets.get(pf.name()) {
+        Some(offset) => offset,
+        None => {
+            // System/vendor/product RO+disabled flags have no offset in storage files.
+            // Assign placeholder value.
+            if no_assigned_offset {
+                &0
+            }
+            // All other flags _must_ have an offset.
+            else {
+                panic!("{}", format!("missing flag offset for {}", pf.name()));
+            }
+        }
+    };
+
     FlagElement {
         container: pf.container().to_string(),
         default_value: pf.state() == ProtoFlagState::ENABLED,
         device_config_namespace: pf.namespace().to_string(),
         device_config_flag,
+        flag_name: pf.name().to_string(),
         flag_name_constant_suffix: pf.name().to_ascii_uppercase(),
-        flag_offset: *flag_offsets.get(pf.name()).expect("didnt find package offset :("),
+        flag_offset: *flag_offset,
         is_read_write: pf.permission() == ProtoFlagPermission::READ_WRITE,
         method_name: format_java_method_name(pf.name()),
         properties: format_property_name(pf.namespace()),
@@ -499,7 +528,8 @@ mod tests {
             modified_parsed_flags.into_iter(),
             mode,
             flag_ids,
-            false,
+            true,
+            5801144784618221668,
         )
         .unwrap();
         let expect_flags_content = EXPECTED_FLAG_COMMON_CONTENT.to_string()
@@ -507,25 +537,38 @@ mod tests {
             private static FeatureFlags FEATURE_FLAGS = new FeatureFlagsImpl();
         }"#;
 
-        let expected_featureflagsmpl_content_0 = r#"
+        let expected_featureflagsmpl_content = r#"
         package com.android.aconfig.test;
         // TODO(b/303773055): Remove the annotation after access issue is resolved.
         import android.compat.annotation.UnsupportedAppUsage;
-        import android.provider.DeviceConfig;
-        import android.provider.DeviceConfig.Properties;
-        "#;
-
-        let expected_featureflagsmpl_content_1 = r#"
+        import android.os.Build;
+        import android.os.flagging.PlatformAconfigPackageInternal;
+        import android.util.Log;
         /** @hide */
         public final class FeatureFlagsImpl implements FeatureFlags {
-            private static volatile boolean aconfig_test_is_cached = false;
-            private static volatile boolean other_namespace_is_cached = false;
+            private static final String TAG = "com.android.aconfig.test.FeatureFlagsImpl";
+            private static volatile boolean isCached = false;
             private static boolean disabledRw = false;
             private static boolean disabledRwExported = false;
             private static boolean disabledRwInOtherNamespace = false;
             private static boolean enabledRw = true;
-        "#;
-        let expected_featureflagsmpl_content_2 = r#"
+            private void init() {
+                try {
+                    PlatformAconfigPackageInternal reader = PlatformAconfigPackageInternal.load("system", "com.android.aconfig.test", 0x5081CE7221C77064L);
+                    disabledRw = reader.getBooleanFlagValue(0);
+                    disabledRwExported = reader.getBooleanFlagValue(1);
+                    enabledRw = reader.getBooleanFlagValue(7);
+                    disabledRwInOtherNamespace = reader.getBooleanFlagValue(2);
+                } catch (Exception e) {
+                    Log.e(TAG, e.toString());
+                } catch (NoClassDefFoundError e) {
+                    // for mainline module running on older devices.
+                    // This should be replaces to version check, after the version bump.
+                    Log.e(TAG, e.toString());
+                }
+                isCached = true;
+            }
+
             @Override
             @com.android.aconfig.annotations.AconfigFlagAccessor
             @UnsupportedAppUsage
@@ -536,8 +579,8 @@ mod tests {
             @com.android.aconfig.annotations.AconfigFlagAccessor
             @UnsupportedAppUsage
             public boolean disabledRw() {
-                if (!aconfig_test_is_cached) {
-                    load_overrides_aconfig_test();
+                if (!isCached) {
+                    init();
                 }
                 return disabledRw;
             }
@@ -545,8 +588,8 @@ mod tests {
             @com.android.aconfig.annotations.AconfigFlagAccessor
             @UnsupportedAppUsage
             public boolean disabledRwExported() {
-                if (!aconfig_test_is_cached) {
-                    load_overrides_aconfig_test();
+                if (!isCached) {
+                    init();
                 }
                 return disabledRwExported;
             }
@@ -554,8 +597,8 @@ mod tests {
             @com.android.aconfig.annotations.AconfigFlagAccessor
             @UnsupportedAppUsage
             public boolean disabledRwInOtherNamespace() {
-                if (!other_namespace_is_cached) {
-                    load_overrides_other_namespace();
+                if (!isCached) {
+                    init();
                 }
                 return disabledRwInOtherNamespace;
             }
@@ -587,237 +630,17 @@ mod tests {
             @com.android.aconfig.annotations.AconfigFlagAccessor
             @UnsupportedAppUsage
             public boolean enabledRw() {
-                if (!aconfig_test_is_cached) {
-                    load_overrides_aconfig_test();
+                if (!isCached) {
+                    init();
                 }
                 return enabledRw;
             }
         }
         "#;
 
-        let expect_featureflagsimpl_content_old = expected_featureflagsmpl_content_0.to_owned()
-            + expected_featureflagsmpl_content_1
-            + r#"
-            private void load_overrides_aconfig_test() {
-                try {
-                    Properties properties = DeviceConfig.getProperties("aconfig_test");
-                    disabledRw =
-                        properties.getBoolean(Flags.FLAG_DISABLED_RW, false);
-                    disabledRwExported =
-                        properties.getBoolean(Flags.FLAG_DISABLED_RW_EXPORTED, false);
-                    enabledRw =
-                        properties.getBoolean(Flags.FLAG_ENABLED_RW, true);
-                } catch (NullPointerException e) {
-                    throw new RuntimeException(
-                        "Cannot read value from namespace aconfig_test "
-                        + "from DeviceConfig. It could be that the code using flag "
-                        + "executed before SettingsProvider initialization. Please use "
-                        + "fixed read-only flag by adding is_fixed_read_only: true in "
-                        + "flag declaration.",
-                        e
-                    );
-                }
-                aconfig_test_is_cached = true;
-            }
-
-            private void load_overrides_other_namespace() {
-                try {
-                    Properties properties = DeviceConfig.getProperties("other_namespace");
-                    disabledRwInOtherNamespace =
-                        properties.getBoolean(Flags.FLAG_DISABLED_RW_IN_OTHER_NAMESPACE, false);
-                } catch (NullPointerException e) {
-                    throw new RuntimeException(
-                        "Cannot read value from namespace other_namespace "
-                        + "from DeviceConfig. It could be that the code using flag "
-                        + "executed before SettingsProvider initialization. Please use "
-                        + "fixed read-only flag by adding is_fixed_read_only: true in "
-                        + "flag declaration.",
-                        e
-                    );
-                }
-                other_namespace_is_cached = true;
-            }"#
-            + expected_featureflagsmpl_content_2;
-
         let mut file_set = HashMap::from([
             ("com/android/aconfig/test/Flags.java", expect_flags_content.as_str()),
-            (
-                "com/android/aconfig/test/FeatureFlagsImpl.java",
-                &expect_featureflagsimpl_content_old,
-            ),
-            ("com/android/aconfig/test/FeatureFlags.java", EXPECTED_FEATUREFLAGS_COMMON_CONTENT),
-            (
-                "com/android/aconfig/test/CustomFeatureFlags.java",
-                EXPECTED_CUSTOMFEATUREFLAGS_CONTENT,
-            ),
-            (
-                "com/android/aconfig/test/FakeFeatureFlagsImpl.java",
-                EXPECTED_FAKEFEATUREFLAGSIMPL_CONTENT,
-            ),
-        ]);
-
-        for file in generated_files {
-            let file_path = file.path.to_str().unwrap();
-            assert!(file_set.contains_key(file_path), "Cannot find {}", file_path);
-            assert_eq!(
-                None,
-                crate::test::first_significant_code_diff(
-                    file_set.get(file_path).unwrap(),
-                    &String::from_utf8(file.contents).unwrap()
-                ),
-                "File {} content is not correct",
-                file_path
-            );
-            file_set.remove(file_path);
-        }
-
-        assert!(file_set.is_empty());
-
-        let parsed_flags = crate::test::parse_test_flags();
-        let mode = CodegenMode::Production;
-        let modified_parsed_flags =
-            crate::commands::modify_parsed_flags_based_on_mode(parsed_flags, mode).unwrap();
-        let flag_ids =
-            assign_flag_ids(crate::test::TEST_PACKAGE, modified_parsed_flags.iter()).unwrap();
-        let generated_files = generate_java_code(
-            crate::test::TEST_PACKAGE,
-            modified_parsed_flags.into_iter(),
-            mode,
-            flag_ids,
-            true,
-        )
-        .unwrap();
-
-        let expect_featureflagsimpl_content_new = expected_featureflagsmpl_content_0.to_owned()
-            + r#"
-            import android.aconfig.storage.StorageInternalReader;
-            import android.util.Log;
-            "#
-            + expected_featureflagsmpl_content_1
-            + r#"
-        StorageInternalReader reader;
-        boolean readFromNewStorage;
-
-        boolean useNewStorageValueAndDiscardOld = false;
-
-        private final static String TAG = "AconfigJavaCodegen";
-        private final static String SUCCESS_LOG = "success: %s value matches";
-        private final static String MISMATCH_LOG = "error: %s value mismatch, new storage value is %s, old storage value is %s";
-        private final static String ERROR_LOG = "error: failed to read flag value";
-
-        private void init() {
-            if (reader != null) return;
-            if (DeviceConfig.getBoolean("core_experiments_team_internal", "com.android.providers.settings.storage_test_mission_1", false)) {
-                readFromNewStorage = true;
-                try {
-                    reader = new StorageInternalReader("system", "com.android.aconfig.test");
-                } catch (Exception e) {
-                    reader = null;
-                }
-            }
-
-            useNewStorageValueAndDiscardOld =
-                DeviceConfig.getBoolean("core_experiments_team_internal", "com.android.providers.settings.use_new_storage_value", false);
-        }
-
-        private void load_overrides_aconfig_test() {
-            try {
-                Properties properties = DeviceConfig.getProperties("aconfig_test");
-                disabledRw =
-                    properties.getBoolean(Flags.FLAG_DISABLED_RW, false);
-                disabledRwExported =
-                    properties.getBoolean(Flags.FLAG_DISABLED_RW_EXPORTED, false);
-                enabledRw =
-                    properties.getBoolean(Flags.FLAG_ENABLED_RW, true);
-            } catch (NullPointerException e) {
-                throw new RuntimeException(
-                    "Cannot read value from namespace aconfig_test "
-                    + "from DeviceConfig. It could be that the code using flag "
-                    + "executed before SettingsProvider initialization. Please use "
-                    + "fixed read-only flag by adding is_fixed_read_only: true in "
-                    + "flag declaration.",
-                    e
-                );
-            }
-            aconfig_test_is_cached = true;
-            init();
-            if (readFromNewStorage && reader != null) {
-                boolean val;
-                try {
-                    val = reader.getBooleanFlagValue(1);
-                    if (val != disabledRw) {
-                        Log.w(TAG, String.format(MISMATCH_LOG, "disabledRw", val, disabledRw));
-                    }
-
-                    if (useNewStorageValueAndDiscardOld) {
-                        disabledRw = val;
-                    }
-
-                    val = reader.getBooleanFlagValue(2);
-                    if (val != disabledRwExported) {
-                        Log.w(TAG, String.format(MISMATCH_LOG, "disabledRwExported", val, disabledRwExported));
-                    }
-
-                    if (useNewStorageValueAndDiscardOld) {
-                        disabledRwExported = val;
-                    }
-
-                    val = reader.getBooleanFlagValue(8);
-                    if (val != enabledRw) {
-                        Log.w(TAG, String.format(MISMATCH_LOG, "enabledRw", val, enabledRw));
-                    }
-
-                    if (useNewStorageValueAndDiscardOld) {
-                        enabledRw = val;
-                    }
-
-                } catch (Exception e) {
-                    Log.e(TAG, ERROR_LOG, e);
-                }
-            }
-        }
-
-        private void load_overrides_other_namespace() {
-            try {
-                Properties properties = DeviceConfig.getProperties("other_namespace");
-                disabledRwInOtherNamespace =
-                    properties.getBoolean(Flags.FLAG_DISABLED_RW_IN_OTHER_NAMESPACE, false);
-            } catch (NullPointerException e) {
-                throw new RuntimeException(
-                    "Cannot read value from namespace other_namespace "
-                    + "from DeviceConfig. It could be that the code using flag "
-                    + "executed before SettingsProvider initialization. Please use "
-                    + "fixed read-only flag by adding is_fixed_read_only: true in "
-                    + "flag declaration.",
-                    e
-                );
-            }
-            other_namespace_is_cached = true;
-            init();
-            if (readFromNewStorage && reader != null) {
-                boolean val;
-                try {
-                    val = reader.getBooleanFlagValue(3);
-                    if (val != disabledRwInOtherNamespace) {
-                        Log.w(TAG, String.format(MISMATCH_LOG, "disabledRwInOtherNamespace", val, disabledRwInOtherNamespace));
-                    }
-
-                    if (useNewStorageValueAndDiscardOld) {
-                        disabledRwInOtherNamespace = val;
-                    }
-
-                } catch (Exception e) {
-                    Log.e(TAG, ERROR_LOG, e);
-                }
-            }
-        }"# + expected_featureflagsmpl_content_2;
-
-        let mut file_set = HashMap::from([
-            ("com/android/aconfig/test/Flags.java", expect_flags_content.as_str()),
-            (
-                "com/android/aconfig/test/FeatureFlagsImpl.java",
-                &expect_featureflagsimpl_content_new,
-            ),
+            ("com/android/aconfig/test/FeatureFlagsImpl.java", expected_featureflagsmpl_content),
             ("com/android/aconfig/test/FeatureFlags.java", EXPECTED_FEATUREFLAGS_COMMON_CONTENT),
             (
                 "com/android/aconfig/test/CustomFeatureFlags.java",
@@ -861,6 +684,7 @@ mod tests {
             mode,
             flag_ids,
             true,
+            5801144784618221668,
         )
         .unwrap();
 
@@ -899,6 +723,7 @@ mod tests {
 
         let expect_feature_flags_impl_content = r#"
         package com.android.aconfig.test;
+        import android.os.Binder;
         import android.provider.DeviceConfig;
         import android.provider.DeviceConfig.Properties;
         /** @hide */
@@ -908,8 +733,8 @@ mod tests {
             private static boolean enabledFixedRoExported = false;
             private static boolean enabledRoExported = false;
 
-
             private void load_overrides_aconfig_test() {
+                final long ident = Binder.clearCallingIdentity();
                 try {
                     Properties properties = DeviceConfig.getProperties("aconfig_test");
                     disabledRwExported =
@@ -927,27 +752,31 @@ mod tests {
                         + "flag declaration.",
                         e
                     );
+                } catch (SecurityException e) {
+                    // for isolated process case, skip loading flag value from the storage, use the default
+                } finally {
+                    Binder.restoreCallingIdentity(ident);
                 }
                 aconfig_test_is_cached = true;
             }
             @Override
             public boolean disabledRwExported() {
                 if (!aconfig_test_is_cached) {
-                    load_overrides_aconfig_test();
+                        load_overrides_aconfig_test();
                 }
                 return disabledRwExported;
             }
             @Override
             public boolean enabledFixedRoExported() {
                 if (!aconfig_test_is_cached) {
-                    load_overrides_aconfig_test();
+                        load_overrides_aconfig_test();
                 }
                 return enabledFixedRoExported;
             }
             @Override
             public boolean enabledRoExported() {
                 if (!aconfig_test_is_cached) {
-                    load_overrides_aconfig_test();
+                        load_overrides_aconfig_test();
                 }
                 return enabledRoExported;
             }
@@ -1054,6 +883,7 @@ mod tests {
             mode,
             flag_ids,
             true,
+            5801144784618221668,
         )
         .unwrap();
 
@@ -1175,6 +1005,7 @@ mod tests {
             mode,
             flag_ids,
             true,
+            5801144784618221668,
         )
         .unwrap();
         let expect_featureflags_content = r#"
diff --git a/tools/aconfig/aconfig/src/codegen/rust.rs b/tools/aconfig/aconfig/src/codegen/rust.rs
index 7bc34d6cfe..2bf565a81c 100644
--- a/tools/aconfig/aconfig/src/codegen/rust.rs
+++ b/tools/aconfig/aconfig/src/codegen/rust.rs
@@ -88,6 +88,27 @@ struct TemplateParsedFlag {
 impl TemplateParsedFlag {
     #[allow(clippy::nonminimal_bool)]
     fn new(package: &str, flag_offsets: HashMap<String, u16>, pf: &ProtoParsedFlag) -> Self {
+        let no_assigned_offset = (pf.container() == "system"
+            || pf.container() == "vendor"
+            || pf.container() == "product")
+            && pf.permission() == ProtoFlagPermission::READ_ONLY
+            && pf.state() == ProtoFlagState::DISABLED;
+
+        let flag_offset = match flag_offsets.get(pf.name()) {
+            Some(offset) => offset,
+            None => {
+                // System/vendor/product RO+disabled flags have no offset in storage files.
+                // Assign placeholder value.
+                if no_assigned_offset {
+                    &0
+                }
+                // All other flags _must_ have an offset.
+                else {
+                    panic!("{}", format!("missing flag offset for {}", pf.name()));
+                }
+            }
+        };
+
         Self {
             readwrite: pf.permission() == ProtoFlagPermission::READ_WRITE,
             default_value: match pf.state() {
@@ -96,7 +117,7 @@ impl TemplateParsedFlag {
             },
             name: pf.name().to_string(),
             container: pf.container().to_string(),
-            flag_offset: *flag_offsets.get(pf.name()).expect("didnt find package offset :("),
+            flag_offset: *flag_offset,
             device_config_namespace: pf.namespace().to_string(),
             device_config_flag: codegen::create_device_config_ident(package, pf.name())
                 .expect("values checked at flag parse time"),
@@ -259,10 +280,6 @@ use log::{log, LevelFilter, Level};
 /// flag provider
 pub struct FlagProvider;
 
-static READ_FROM_NEW_STORAGE: LazyLock<bool> = LazyLock::new(|| unsafe {
-    Path::new("/metadata/aconfig/boot/enable_only_new_storage").exists()
-});
-
 static PACKAGE_OFFSET: LazyLock<Result<Option<u32>, AconfigStorageError>> = LazyLock::new(|| unsafe {
     get_mapped_storage_file("system", StorageFileType::PackageMap)
     .and_then(|package_map| get_package_read_context(&package_map, "com.android.aconfig.test"))
@@ -275,51 +292,46 @@ static FLAG_VAL_MAP: LazyLock<Result<Mmap, AconfigStorageError>> = LazyLock::new
 
 /// flag value cache for disabled_rw
 static CACHED_disabled_rw: LazyLock<bool> = LazyLock::new(|| {
-    if *READ_FROM_NEW_STORAGE {
-        // This will be called multiple times. Subsequent calls after the first are noops.
-        logger::init(
-            logger::Config::default()
-                .with_tag_on_device("aconfig_rust_codegen")
-                .with_max_level(LevelFilter::Info));
-
-        let flag_value_result = FLAG_VAL_MAP
-            .as_ref()
-            .map_err(|err| format!("failed to get flag val map: {err}"))
-            .and_then(|flag_val_map| {
-                PACKAGE_OFFSET
-                    .as_ref()
-                    .map_err(|err| format!("failed to get package read offset: {err}"))
-                    .and_then(|package_offset| {
-                        match package_offset {
-                            Some(offset) => {
-                                get_boolean_flag_value(&flag_val_map, offset + 1)
-                                    .map_err(|err| format!("failed to get flag: {err}"))
-                            },
-                            None => Err("no context found for package 'com.android.aconfig.test'".to_string())
-                        }
-                    })
-                });
-
-        match flag_value_result {
-            Ok(flag_value) => {
-                 return flag_value;
-            },
-            Err(err) => {
-                log!(Level::Error, "aconfig_rust_codegen: error: {err}");
-                panic!("failed to read flag value: {err}");
-            }
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
         }
-    } else {
-        flags_rust::GetServerConfigurableFlag(
-            "aconfig_flags.aconfig_test",
-            "com.android.aconfig.test.disabled_rw",
-            "false") == "true"
     }
 });
 
 /// flag value cache for disabled_rw_exported
 static CACHED_disabled_rw_exported: LazyLock<bool> = LazyLock::new(|| {
-    if *READ_FROM_NEW_STORAGE {
         // This will be called multiple times. Subsequent calls after the first are noops.
         logger::init(
             logger::Config::default()
@@ -336,10 +348,13 @@ static CACHED_disabled_rw_exported: LazyLock<bool> = LazyLock::new(|| {
                     .and_then(|package_offset| {
                         match package_offset {
                             Some(offset) => {
-                                get_boolean_flag_value(&flag_val_map, offset + 2)
+                                get_boolean_flag_value(&flag_val_map, offset + 1)
                                     .map_err(|err| format!("failed to get flag: {err}"))
                             },
-                            None => Err("no context found for package 'com.android.aconfig.test'".to_string())
+                            None => {
+                                log!(Level::Error, "no context found for package com.android.aconfig.test");
+                                Err(format!("failed to flag package com.android.aconfig.test"))
+                            }
                         }
                     })
                 });
@@ -350,20 +365,13 @@ static CACHED_disabled_rw_exported: LazyLock<bool> = LazyLock::new(|| {
             },
             Err(err) => {
                 log!(Level::Error, "aconfig_rust_codegen: error: {err}");
-                panic!("failed to read flag value: {err}");
+                return false;
             }
         }
-    } else {
-        flags_rust::GetServerConfigurableFlag(
-            "aconfig_flags.aconfig_test",
-            "com.android.aconfig.test.disabled_rw_exported",
-            "false") == "true"
-    }
 });
 
 /// flag value cache for disabled_rw_in_other_namespace
 static CACHED_disabled_rw_in_other_namespace: LazyLock<bool> = LazyLock::new(|| {
-    if *READ_FROM_NEW_STORAGE {
         // This will be called multiple times. Subsequent calls after the first are noops.
         logger::init(
             logger::Config::default()
@@ -380,10 +388,13 @@ static CACHED_disabled_rw_in_other_namespace: LazyLock<bool> = LazyLock::new(||
                     .and_then(|package_offset| {
                         match package_offset {
                             Some(offset) => {
-                                get_boolean_flag_value(&flag_val_map, offset + 3)
+                                get_boolean_flag_value(&flag_val_map, offset + 2)
                                     .map_err(|err| format!("failed to get flag: {err}"))
                             },
-                            None => Err("no context found for package 'com.android.aconfig.test'".to_string())
+                            None => {
+                                log!(Level::Error, "no context found for package com.android.aconfig.test");
+                                Err(format!("failed to flag package com.android.aconfig.test"))
+                            }
                         }
                     })
                 });
@@ -394,21 +405,14 @@ static CACHED_disabled_rw_in_other_namespace: LazyLock<bool> = LazyLock::new(||
             },
             Err(err) => {
                 log!(Level::Error, "aconfig_rust_codegen: error: {err}");
-                panic!("failed to read flag value: {err}");
+                return false;
             }
         }
-    } else {
-        flags_rust::GetServerConfigurableFlag(
-            "aconfig_flags.other_namespace",
-            "com.android.aconfig.test.disabled_rw_in_other_namespace",
-            "false") == "true"
-    }
 });
 
 
 /// flag value cache for enabled_rw
 static CACHED_enabled_rw: LazyLock<bool> = LazyLock::new(|| {
-    if *READ_FROM_NEW_STORAGE {
         // This will be called multiple times. Subsequent calls after the first are noops.
         logger::init(
             logger::Config::default()
@@ -425,10 +429,13 @@ static CACHED_enabled_rw: LazyLock<bool> = LazyLock::new(|| {
                     .and_then(|package_offset| {
                         match package_offset {
                             Some(offset) => {
-                                get_boolean_flag_value(&flag_val_map, offset + 8)
+                                get_boolean_flag_value(&flag_val_map, offset + 7)
                                     .map_err(|err| format!("failed to get flag: {err}"))
                             },
-                            None => Err("no context found for package 'com.android.aconfig.test'".to_string())
+                            None => {
+                                log!(Level::Error, "no context found for package com.android.aconfig.test");
+                                Err(format!("failed to flag package com.android.aconfig.test"))
+                            }
                         }
                     })
                 });
@@ -439,15 +446,9 @@ static CACHED_enabled_rw: LazyLock<bool> = LazyLock::new(|| {
             },
             Err(err) => {
                 log!(Level::Error, "aconfig_rust_codegen: error: {err}");
-                panic!("failed to read flag value: {err}");
+                return true;
             }
         }
-    } else {
-        flags_rust::GetServerConfigurableFlag(
-            "aconfig_flags.aconfig_test",
-            "com.android.aconfig.test.enabled_rw",
-            "true") == "true"
-    }
 });
 
 impl FlagProvider {
diff --git a/tools/aconfig/aconfig/src/commands.rs b/tools/aconfig/aconfig/src/commands.rs
index 797a893ff1..5036bc1bf8 100644
--- a/tools/aconfig/aconfig/src/commands.rs
+++ b/tools/aconfig/aconfig/src/commands.rs
@@ -17,7 +17,7 @@
 use anyhow::{bail, ensure, Context, Result};
 use itertools::Itertools;
 use protobuf::Message;
-use std::collections::{BTreeMap, HashMap};
+use std::collections::HashMap;
 use std::hash::Hasher;
 use std::io::Read;
 use std::path::PathBuf;
@@ -69,6 +69,7 @@ pub fn parse_flags(
     declarations: Vec<Input>,
     values: Vec<Input>,
     default_permission: ProtoFlagPermission,
+    allow_read_write: bool,
 ) -> Result<Vec<u8>> {
     let mut parsed_flags = ProtoParsedFlags::new();
 
@@ -195,6 +196,16 @@ pub fn parse_flags(
         }
     }
 
+    if !allow_read_write {
+        if let Some(pf) = parsed_flags
+            .parsed_flag
+            .iter()
+            .find(|pf| pf.permission() == ProtoFlagPermission::READ_WRITE)
+        {
+            bail!("flag {} has permission READ_WRITE, but allow_read_write is false", pf.name());
+        }
+    }
+
     // Create a sorted parsed_flags
     aconfig_protos::parsed_flags::sort_parsed_flags(&mut parsed_flags);
     aconfig_protos::parsed_flags::verify_fields(&parsed_flags)?;
@@ -214,6 +225,9 @@ pub fn create_java_lib(
         bail!("no parsed flags, or the parsed flags use different packages");
     };
     let package = package.to_string();
+    let mut flag_names =
+        modified_parsed_flags.iter().map(|pf| pf.name().to_string()).collect::<Vec<_>>();
+    let package_fingerprint = compute_flags_fingerprint(&mut flag_names);
     let flag_ids = assign_flag_ids(&package, modified_parsed_flags.iter())?;
     generate_java_code(
         &package,
@@ -221,6 +235,7 @@ pub fn create_java_lib(
         codegen_mode,
         flag_ids,
         allow_instrumentation,
+        package_fingerprint,
     )
 }
 
@@ -280,10 +295,11 @@ pub fn create_storage(
     caches: Vec<Input>,
     container: &str,
     file: &StorageFileType,
+    version: u32,
 ) -> Result<Vec<u8>> {
     let parsed_flags_vec: Vec<ProtoParsedFlags> =
         caches.into_iter().map(|mut input| input.try_parse_flags()).collect::<Result<Vec<_>>>()?;
-    generate_storage_file(container, parsed_flags_vec.iter(), file)
+    generate_storage_file(container, parsed_flags_vec.iter(), file, version)
 }
 
 pub fn create_device_config_defaults(mut input: Input) -> Result<Vec<u8>> {
@@ -407,38 +423,60 @@ where
 {
     assert!(parsed_flags_iter.clone().tuple_windows().all(|(a, b)| a.name() <= b.name()));
     let mut flag_ids = HashMap::new();
-    for (id_to_assign, pf) in (0_u32..).zip(parsed_flags_iter) {
+    let mut flag_idx = 0;
+    for pf in parsed_flags_iter {
         if package != pf.package() {
             return Err(anyhow::anyhow!("encountered a flag not in current package"));
         }
 
         // put a cap on how many flags a package can contain to 65535
-        if id_to_assign > u16::MAX as u32 {
+        if flag_idx > u16::MAX as u32 {
             return Err(anyhow::anyhow!("the number of flags in a package cannot exceed 65535"));
         }
 
-        flag_ids.insert(pf.name().to_string(), id_to_assign as u16);
+        // Exclude system/vendor/product flags that are RO+disabled.
+        let should_filter_container = pf.container == Some("vendor".to_string())
+            || pf.container == Some("system".to_string())
+            || pf.container == Some("product".to_string());
+        if !(should_filter_container
+            && pf.state == Some(ProtoFlagState::DISABLED.into())
+            && pf.permission == Some(ProtoFlagPermission::READ_ONLY.into()))
+        {
+            flag_ids.insert(pf.name().to_string(), flag_idx as u16);
+            flag_idx += 1;
+        }
     }
     Ok(flag_ids)
 }
 
 #[allow(dead_code)] // TODO: b/316357686 - Use fingerprint in codegen to
                     // protect hardcoded offset reads.
-pub fn compute_flag_offsets_fingerprint(flags_map: &HashMap<String, u16>) -> Result<u64> {
-    let mut hasher = SipHasher13::new();
-
-    // Need to sort to ensure the data is added to the hasher in the same order
-    // each run.
-    let sorted_map: BTreeMap<&String, &u16> = flags_map.iter().collect();
+                    // Creates a fingerprint of the flag names (which requires sorting the vector).
+                    // Fingerprint is used by both codegen and storage files.
+pub fn compute_flags_fingerprint(flag_names: &mut Vec<String>) -> u64 {
+    flag_names.sort();
 
-    for (flag, offset) in sorted_map {
-        // See https://docs.rs/siphasher/latest/siphasher/#note for use of write
-        // over write_i16. Similarly, use to_be_bytes rather than to_ne_bytes to
-        // ensure consistency.
+    let mut hasher = SipHasher13::new();
+    for flag in flag_names {
         hasher.write(flag.as_bytes());
-        hasher.write(&offset.to_be_bytes());
     }
-    Ok(hasher.finish())
+    hasher.finish()
+}
+
+#[allow(dead_code)] // TODO: b/316357686 - Use fingerprint in codegen to
+                    // protect hardcoded offset reads.
+                    // Converts ProtoParsedFlags into a vector of strings containing all of the flag
+                    // names. Helper fn for creating fingerprint for codegen files. Flags must all
+                    // belong to the same package.
+fn extract_flag_names(flags: ProtoParsedFlags) -> Result<Vec<String>> {
+    let separated_flags: Vec<ProtoParsedFlag> = flags.parsed_flag.into_iter().collect::<Vec<_>>();
+
+    // All flags must belong to the same package as the fingerprint is per-package.
+    let Some(_package) = find_unique_package(&separated_flags) else {
+        bail!("No parsed flags, or the parsed flags use different packages.");
+    };
+
+    Ok(separated_flags.into_iter().map(|flag| flag.name.unwrap()).collect::<Vec<_>>())
 }
 
 #[cfg(test)]
@@ -449,13 +487,48 @@ mod tests {
     #[test]
     fn test_offset_fingerprint() {
         let parsed_flags = crate::test::parse_test_flags();
-        let package = find_unique_package(&parsed_flags.parsed_flag).unwrap().to_string();
-        let flag_ids = assign_flag_ids(&package, parsed_flags.parsed_flag.iter()).unwrap();
-        let expected_fingerprint = 10709892481002252132u64;
+        let expected_fingerprint: u64 = 5801144784618221668;
 
-        let hash_result = compute_flag_offsets_fingerprint(&flag_ids);
+        let mut extracted_flags = extract_flag_names(parsed_flags).unwrap();
+        let hash_result = compute_flags_fingerprint(&mut extracted_flags);
 
-        assert_eq!(hash_result.unwrap(), expected_fingerprint);
+        assert_eq!(hash_result, expected_fingerprint);
+    }
+
+    #[test]
+    fn test_offset_fingerprint_matches_from_package() {
+        let parsed_flags: ProtoParsedFlags = crate::test::parse_test_flags();
+
+        // All test flags are in the same package, so fingerprint from all of them.
+        let mut extracted_flags = extract_flag_names(parsed_flags.clone()).unwrap();
+        let result_from_parsed_flags = compute_flags_fingerprint(&mut extracted_flags);
+
+        let mut flag_names_vec = parsed_flags
+            .parsed_flag
+            .clone()
+            .into_iter()
+            .map(|flag| flag.name.unwrap())
+            .map(String::from)
+            .collect::<Vec<_>>();
+        let result_from_names = compute_flags_fingerprint(&mut flag_names_vec);
+
+        // Assert the same hash is generated for each case.
+        assert_eq!(result_from_parsed_flags, result_from_names);
+    }
+
+    #[test]
+    fn test_offset_fingerprint_different_packages_does_not_match() {
+        // Parse flags from two packages.
+        let parsed_flags: ProtoParsedFlags = crate::test::parse_test_flags();
+        let second_parsed_flags = crate::test::parse_second_package_flags();
+
+        let mut extracted_flags = extract_flag_names(parsed_flags).unwrap();
+        let result_from_parsed_flags = compute_flags_fingerprint(&mut extracted_flags);
+        let mut second_extracted_flags = extract_flag_names(second_parsed_flags).unwrap();
+        let second_result = compute_flags_fingerprint(&mut second_extracted_flags);
+
+        // Different flags should have a different fingerprint.
+        assert_ne!(result_from_parsed_flags, second_result);
     }
 
     #[test]
@@ -529,6 +602,7 @@ mod tests {
             declaration,
             value,
             ProtoFlagPermission::READ_ONLY,
+            true,
         )
         .unwrap();
         let parsed_flags =
@@ -562,6 +636,7 @@ mod tests {
             declaration,
             value,
             ProtoFlagPermission::READ_WRITE,
+            true,
         )
         .unwrap_err();
         assert_eq!(
@@ -593,6 +668,7 @@ mod tests {
             declaration,
             value,
             ProtoFlagPermission::READ_WRITE,
+            true,
         )
         .unwrap_err();
         assert_eq!(
@@ -600,6 +676,121 @@ mod tests {
             "failed to parse memory: expected container argument.container, got declaration.container"
         );
     }
+    #[test]
+    fn test_parse_flags_no_allow_read_write_default_error() {
+        let first_flag = r#"
+        package: "com.first"
+        container: "com.first.container"
+        flag {
+            name: "first"
+            namespace: "first_ns"
+            description: "This is the description of the first flag."
+            bug: "123"
+        }
+        "#;
+        let declaration =
+            vec![Input { source: "memory".to_string(), reader: Box::new(first_flag.as_bytes()) }];
+
+        let error = crate::commands::parse_flags(
+            "com.first",
+            Some("com.first.container"),
+            declaration,
+            vec![],
+            ProtoFlagPermission::READ_WRITE,
+            false,
+        )
+        .unwrap_err();
+        assert_eq!(
+            format!("{:?}", error),
+            "flag first has permission READ_WRITE, but allow_read_write is false"
+        );
+    }
+
+    #[test]
+    fn test_parse_flags_no_allow_read_write_value_error() {
+        let first_flag = r#"
+        package: "com.first"
+        container: "com.first.container"
+        flag {
+            name: "first"
+            namespace: "first_ns"
+            description: "This is the description of the first flag."
+            bug: "123"
+        }
+        "#;
+        let declaration =
+            vec![Input { source: "memory".to_string(), reader: Box::new(first_flag.as_bytes()) }];
+
+        let first_flag_value = r#"
+        flag_value {
+            package: "com.first"
+            name: "first"
+            state: DISABLED
+            permission: READ_WRITE
+        }
+        "#;
+        let value = vec![Input {
+            source: "memory".to_string(),
+            reader: Box::new(first_flag_value.as_bytes()),
+        }];
+        let error = crate::commands::parse_flags(
+            "com.first",
+            Some("com.first.container"),
+            declaration,
+            value,
+            ProtoFlagPermission::READ_ONLY,
+            false,
+        )
+        .unwrap_err();
+        assert_eq!(
+            format!("{:?}", error),
+            "flag first has permission READ_WRITE, but allow_read_write is false"
+        );
+    }
+
+    #[test]
+    fn test_parse_flags_no_allow_read_write_success() {
+        let first_flag = r#"
+        package: "com.first"
+        container: "com.first.container"
+        flag {
+            name: "first"
+            namespace: "first_ns"
+            description: "This is the description of the first flag."
+            bug: "123"
+        }
+        "#;
+        let declaration =
+            vec![Input { source: "memory".to_string(), reader: Box::new(first_flag.as_bytes()) }];
+
+        let first_flag_value = r#"
+        flag_value {
+            package: "com.first"
+            name: "first"
+            state: DISABLED
+            permission: READ_ONLY
+        }
+        "#;
+        let value = vec![Input {
+            source: "memory".to_string(),
+            reader: Box::new(first_flag_value.as_bytes()),
+        }];
+        let flags_bytes = crate::commands::parse_flags(
+            "com.first",
+            Some("com.first.container"),
+            declaration,
+            value,
+            ProtoFlagPermission::READ_ONLY,
+            false,
+        )
+        .unwrap();
+        let parsed_flags =
+            aconfig_protos::parsed_flags::try_from_binary_proto(&flags_bytes).unwrap();
+        assert_eq!(1, parsed_flags.parsed_flag.len());
+        let parsed_flag = parsed_flags.parsed_flag.first().unwrap();
+        assert_eq!(ProtoFlagState::DISABLED, parsed_flag.state());
+        assert_eq!(ProtoFlagPermission::READ_ONLY, parsed_flag.permission());
+    }
 
     #[test]
     fn test_parse_flags_override_fixed_read_only() {
@@ -635,6 +826,7 @@ mod tests {
             declaration,
             value,
             ProtoFlagPermission::READ_WRITE,
+            true,
         )
         .unwrap_err();
         assert_eq!(
@@ -669,6 +861,7 @@ mod tests {
             declaration,
             value,
             ProtoFlagPermission::READ_ONLY,
+            true,
         )
         .unwrap();
         let parsed_flags =
@@ -708,6 +901,30 @@ mod tests {
         assert!(text.contains("com.android.aconfig.test.disabled_ro"));
     }
 
+    #[test]
+    fn test_dump_multiple_filters() {
+        let input = parse_test_flags_as_input();
+        let bytes = dump_parsed_flags(
+            vec![input],
+            DumpFormat::Custom("{fully_qualified_name}".to_string()),
+            &["container:system+state:ENABLED", "container:system+permission:READ_WRITE"],
+            false,
+        )
+        .unwrap();
+        let text = std::str::from_utf8(&bytes).unwrap();
+        let expected_flag_list = &[
+            "com.android.aconfig.test.disabled_rw",
+            "com.android.aconfig.test.disabled_rw_exported",
+            "com.android.aconfig.test.disabled_rw_in_other_namespace",
+            "com.android.aconfig.test.enabled_fixed_ro",
+            "com.android.aconfig.test.enabled_fixed_ro_exported",
+            "com.android.aconfig.test.enabled_ro",
+            "com.android.aconfig.test.enabled_ro_exported",
+            "com.android.aconfig.test.enabled_rw",
+        ];
+        assert_eq!(expected_flag_list.map(|s| format!("{}\n", s)).join(""), text);
+    }
+
     #[test]
     fn test_dump_textproto_format_dedup() {
         let input = parse_test_flags_as_input();
@@ -770,15 +987,14 @@ mod tests {
         let package = find_unique_package(&parsed_flags.parsed_flag).unwrap().to_string();
         let flag_ids = assign_flag_ids(&package, parsed_flags.parsed_flag.iter()).unwrap();
         let expected_flag_ids = HashMap::from([
-            (String::from("disabled_ro"), 0_u16),
-            (String::from("disabled_rw"), 1_u16),
-            (String::from("disabled_rw_exported"), 2_u16),
-            (String::from("disabled_rw_in_other_namespace"), 3_u16),
-            (String::from("enabled_fixed_ro"), 4_u16),
-            (String::from("enabled_fixed_ro_exported"), 5_u16),
-            (String::from("enabled_ro"), 6_u16),
-            (String::from("enabled_ro_exported"), 7_u16),
-            (String::from("enabled_rw"), 8_u16),
+            (String::from("disabled_rw"), 0_u16),
+            (String::from("disabled_rw_exported"), 1_u16),
+            (String::from("disabled_rw_in_other_namespace"), 2_u16),
+            (String::from("enabled_fixed_ro"), 3_u16),
+            (String::from("enabled_fixed_ro_exported"), 4_u16),
+            (String::from("enabled_ro"), 5_u16),
+            (String::from("enabled_ro_exported"), 6_u16),
+            (String::from("enabled_rw"), 7_u16),
         ]);
         assert_eq!(flag_ids, expected_flag_ids);
     }
diff --git a/tools/aconfig/aconfig/src/main.rs b/tools/aconfig/aconfig/src/main.rs
index 1fb64f9c56..c3902884f6 100644
--- a/tools/aconfig/aconfig/src/main.rs
+++ b/tools/aconfig/aconfig/src/main.rs
@@ -16,6 +16,8 @@
 
 //! `aconfig` is a build time tool to manage build time configurations, such as feature flags.
 
+use aconfig_storage_file::DEFAULT_FILE_VERSION;
+use aconfig_storage_file::MAX_SUPPORTED_FILE_VERSION;
 use anyhow::{anyhow, bail, Context, Result};
 use clap::{builder::ArgAction, builder::EnumValueParser, Arg, ArgMatches, Command};
 use core::any::Any;
@@ -49,8 +51,7 @@ fn cli() -> Command {
         .subcommand(
             Command::new("create-cache")
                 .arg(Arg::new("package").long("package").required(true))
-                // TODO(b/312769710): Make this argument required.
-                .arg(Arg::new("container").long("container"))
+                .arg(Arg::new("container").long("container").required(true))
                 .arg(Arg::new("declarations").long("declarations").action(ArgAction::Append))
                 .arg(Arg::new("values").long("values").action(ArgAction::Append))
                 .arg(
@@ -61,6 +62,12 @@ fn cli() -> Command {
                             &commands::DEFAULT_FLAG_PERMISSION,
                         )),
                 )
+                .arg(
+                    Arg::new("allow-read-write")
+                        .long("allow-read-write")
+                        .value_parser(clap::value_parser!(bool))
+                        .default_value("true"),
+                )
                 .arg(Arg::new("cache").long("cache").required(true)),
         )
         .subcommand(
@@ -159,7 +166,13 @@ fn cli() -> Command {
                         .value_parser(|s: &str| StorageFileType::try_from(s)),
                 )
                 .arg(Arg::new("cache").long("cache").action(ArgAction::Append).required(true))
-                .arg(Arg::new("out").long("out").required(true)),
+                .arg(Arg::new("out").long("out").required(true))
+                .arg(
+                    Arg::new("version")
+                        .long("version")
+                        .required(false)
+                        .value_parser(|s: &str| s.parse::<u32>()),
+                ),
         )
 }
 
@@ -235,12 +248,15 @@ fn main() -> Result<()> {
                 sub_matches,
                 "default-permission",
             )?;
+            let allow_read_write = get_optional_arg::<bool>(sub_matches, "allow-read-write")
+                .expect("failed to parse allow-read-write");
             let output = commands::parse_flags(
                 package,
                 container,
                 declarations,
                 values,
                 *default_permission,
+                *allow_read_write,
             )
             .context("failed to create cache")?;
             let path = get_required_arg::<String>(sub_matches, "cache")?;
@@ -309,12 +325,18 @@ fn main() -> Result<()> {
             write_output_to_file_or_stdout(path, &output)?;
         }
         Some(("create-storage", sub_matches)) => {
+            let version =
+                get_optional_arg::<u32>(sub_matches, "version").unwrap_or(&DEFAULT_FILE_VERSION);
+            if *version > MAX_SUPPORTED_FILE_VERSION {
+                bail!("Invalid version selected ({})", version);
+            }
             let file = get_required_arg::<StorageFileType>(sub_matches, "file")
                 .context("Invalid storage file selection")?;
             let cache = open_zero_or_more_files(sub_matches, "cache")?;
             let container = get_required_arg::<String>(sub_matches, "container")?;
             let path = get_required_arg::<String>(sub_matches, "out")?;
-            let output = commands::create_storage(cache, container, file)
+
+            let output = commands::create_storage(cache, container, file, *version)
                 .context("failed to create storage files")?;
             write_output_to_file_or_stdout(path, &output)?;
         }
diff --git a/tools/aconfig/aconfig/src/storage/flag_info.rs b/tools/aconfig/aconfig/src/storage/flag_info.rs
new file mode 100644
index 0000000000..0943daa86c
--- /dev/null
+++ b/tools/aconfig/aconfig/src/storage/flag_info.rs
@@ -0,0 +1,99 @@
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
+use crate::commands::assign_flag_ids;
+use crate::storage::FlagPackage;
+use aconfig_protos::{ProtoFlagPermission, ProtoFlagState};
+use aconfig_storage_file::{FlagInfoHeader, FlagInfoList, FlagInfoNode, StorageFileType};
+use anyhow::{anyhow, Result};
+
+fn new_header(container: &str, num_flags: u32, version: u32) -> FlagInfoHeader {
+    FlagInfoHeader {
+        version,
+        container: String::from(container),
+        file_type: StorageFileType::FlagInfo as u8,
+        file_size: 0,
+        num_flags,
+        boolean_flag_offset: 0,
+    }
+}
+
+pub fn create_flag_info(
+    container: &str,
+    packages: &[FlagPackage],
+    version: u32,
+) -> Result<FlagInfoList> {
+    // Exclude system/vendor/product flags that are RO+disabled.
+    let mut filtered_packages = packages.to_vec();
+    if container == "system" || container == "vendor" || container == "product" {
+        for package in filtered_packages.iter_mut() {
+            package.boolean_flags.retain(|b| {
+                !(b.state == Some(ProtoFlagState::DISABLED.into())
+                    && b.permission == Some(ProtoFlagPermission::READ_ONLY.into()))
+            });
+        }
+    }
+
+    let num_flags = filtered_packages.iter().map(|pkg| pkg.boolean_flags.len() as u32).sum();
+
+    let mut is_flag_rw = vec![false; num_flags as usize];
+    for pkg in filtered_packages {
+        let start_index = pkg.boolean_start_index as usize;
+        let flag_ids = assign_flag_ids(pkg.package_name, pkg.boolean_flags.iter().copied())?;
+        for pf in pkg.boolean_flags {
+            let fid = flag_ids
+                .get(pf.name())
+                .ok_or(anyhow!(format!("missing flag id for {}", pf.name())))?;
+            is_flag_rw[start_index + (*fid as usize)] =
+                pf.permission() == ProtoFlagPermission::READ_WRITE;
+        }
+    }
+
+    let mut list = FlagInfoList {
+        header: new_header(container, num_flags, version),
+        nodes: is_flag_rw.iter().map(|&rw| FlagInfoNode::create(rw)).collect(),
+    };
+
+    // initialize all header fields
+    list.header.boolean_flag_offset = list.header.into_bytes().len() as u32;
+    let bytes_per_node = FlagInfoNode::create(false).into_bytes().len() as u32;
+    list.header.file_size = list.header.boolean_flag_offset + num_flags * bytes_per_node;
+
+    Ok(list)
+}
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use crate::storage::{group_flags_by_package, tests::parse_all_test_flags};
+    use aconfig_storage_file::DEFAULT_FILE_VERSION;
+
+    pub fn create_test_flag_info_list_from_source() -> Result<FlagInfoList> {
+        let caches = parse_all_test_flags();
+        let packages = group_flags_by_package(caches.iter(), DEFAULT_FILE_VERSION);
+        create_flag_info("mockup", &packages, DEFAULT_FILE_VERSION)
+    }
+
+    #[test]
+    // this test point locks down the flag info creation and each field
+    fn test_list_contents() {
+        let flag_info_list = create_test_flag_info_list_from_source();
+        assert!(flag_info_list.is_ok());
+        let expected_flag_info_list =
+            aconfig_storage_file::test_utils::create_test_flag_info_list(DEFAULT_FILE_VERSION);
+        assert_eq!(flag_info_list.unwrap(), expected_flag_info_list);
+    }
+}
diff --git a/tools/aconfig/aconfig/src/storage/flag_table.rs b/tools/aconfig/aconfig/src/storage/flag_table.rs
index a9712119bf..3b245a76f2 100644
--- a/tools/aconfig/aconfig/src/storage/flag_table.rs
+++ b/tools/aconfig/aconfig/src/storage/flag_table.rs
@@ -16,16 +16,15 @@
 
 use crate::commands::assign_flag_ids;
 use crate::storage::FlagPackage;
-use aconfig_protos::ProtoFlagPermission;
+use aconfig_protos::{ProtoFlagPermission, ProtoFlagState};
 use aconfig_storage_file::{
     get_table_size, FlagTable, FlagTableHeader, FlagTableNode, StorageFileType, StoredFlagType,
-    FILE_VERSION,
 };
 use anyhow::{anyhow, Result};
 
-fn new_header(container: &str, num_flags: u32) -> FlagTableHeader {
+fn new_header(container: &str, num_flags: u32, version: u32) -> FlagTableHeader {
     FlagTableHeader {
-        version: FILE_VERSION,
+        version,
         container: String::from(container),
         file_type: StorageFileType::FlagMap as u8,
         file_size: 0,
@@ -63,9 +62,19 @@ impl FlagTableNodeWrapper {
     }
 
     fn create_nodes(package: &FlagPackage, num_buckets: u32) -> Result<Vec<Self>> {
+        // Exclude system/vendor/product flags that are RO+disabled.
+        let mut filtered_package = package.clone();
+        filtered_package.boolean_flags.retain(|f| {
+            !((f.container == Some("system".to_string())
+                || f.container == Some("vendor".to_string())
+                || f.container == Some("product".to_string()))
+                && f.permission == Some(ProtoFlagPermission::READ_ONLY.into())
+                && f.state == Some(ProtoFlagState::DISABLED.into()))
+        });
+
         let flag_ids =
-            assign_flag_ids(package.package_name, package.boolean_flags.iter().copied())?;
-        package
+            assign_flag_ids(package.package_name, filtered_package.boolean_flags.iter().copied())?;
+        filtered_package
             .boolean_flags
             .iter()
             .map(|&pf| {
@@ -86,12 +95,16 @@ impl FlagTableNodeWrapper {
     }
 }
 
-pub fn create_flag_table(container: &str, packages: &[FlagPackage]) -> Result<FlagTable> {
+pub fn create_flag_table(
+    container: &str,
+    packages: &[FlagPackage],
+    version: u32,
+) -> Result<FlagTable> {
     // create table
     let num_flags = packages.iter().map(|pkg| pkg.boolean_flags.len() as u32).sum();
     let num_buckets = get_table_size(num_flags)?;
 
-    let mut header = new_header(container, num_flags);
+    let mut header = new_header(container, num_flags, version);
     let mut buckets = vec![None; num_buckets as usize];
     let mut node_wrappers = packages
         .iter()
@@ -138,13 +151,15 @@ pub fn create_flag_table(container: &str, packages: &[FlagPackage]) -> Result<Fl
 
 #[cfg(test)]
 mod tests {
+    use aconfig_storage_file::DEFAULT_FILE_VERSION;
+
     use super::*;
     use crate::storage::{group_flags_by_package, tests::parse_all_test_flags};
 
     fn create_test_flag_table_from_source() -> Result<FlagTable> {
         let caches = parse_all_test_flags();
-        let packages = group_flags_by_package(caches.iter());
-        create_flag_table("mockup", &packages)
+        let packages = group_flags_by_package(caches.iter(), DEFAULT_FILE_VERSION);
+        create_flag_table("mockup", &packages, DEFAULT_FILE_VERSION)
     }
 
     #[test]
@@ -152,7 +167,8 @@ mod tests {
     fn test_table_contents() {
         let flag_table = create_test_flag_table_from_source();
         assert!(flag_table.is_ok());
-        let expected_flag_table = aconfig_storage_file::test_utils::create_test_flag_table();
+        let expected_flag_table =
+            aconfig_storage_file::test_utils::create_test_flag_table(DEFAULT_FILE_VERSION);
         assert_eq!(flag_table.unwrap(), expected_flag_table);
     }
 }
diff --git a/tools/aconfig/aconfig/src/storage/flag_value.rs b/tools/aconfig/aconfig/src/storage/flag_value.rs
index c15ba54112..3cfa447098 100644
--- a/tools/aconfig/aconfig/src/storage/flag_value.rs
+++ b/tools/aconfig/aconfig/src/storage/flag_value.rs
@@ -16,13 +16,13 @@
 
 use crate::commands::assign_flag_ids;
 use crate::storage::FlagPackage;
-use aconfig_protos::ProtoFlagState;
-use aconfig_storage_file::{FlagValueHeader, FlagValueList, StorageFileType, FILE_VERSION};
+use aconfig_protos::{ProtoFlagPermission, ProtoFlagState};
+use aconfig_storage_file::{FlagValueHeader, FlagValueList, StorageFileType};
 use anyhow::{anyhow, Result};
 
-fn new_header(container: &str, num_flags: u32) -> FlagValueHeader {
+fn new_header(container: &str, num_flags: u32, version: u32) -> FlagValueHeader {
     FlagValueHeader {
-        version: FILE_VERSION,
+        version,
         container: String::from(container),
         file_type: StorageFileType::FlagVal as u8,
         file_size: 0,
@@ -31,16 +31,27 @@ fn new_header(container: &str, num_flags: u32) -> FlagValueHeader {
     }
 }
 
-pub fn create_flag_value(container: &str, packages: &[FlagPackage]) -> Result<FlagValueList> {
-    // create list
-    let num_flags = packages.iter().map(|pkg| pkg.boolean_flags.len() as u32).sum();
-
+pub fn create_flag_value(
+    container: &str,
+    packages: &[FlagPackage],
+    version: u32,
+) -> Result<FlagValueList> {
+    // Exclude system/vendor/product flags that are RO+disabled.
+    let mut filtered_packages = packages.to_vec();
+    if container == "system" || container == "vendor" || container == "product" {
+        for package in filtered_packages.iter_mut() {
+            package.boolean_flags.retain(|b| {
+                !(b.state == Some(ProtoFlagState::DISABLED.into())
+                    && b.permission == Some(ProtoFlagPermission::READ_ONLY.into()))
+            });
+        }
+    }
+    let num_flags = filtered_packages.iter().map(|pkg| pkg.boolean_flags.len() as u32).sum();
     let mut list = FlagValueList {
-        header: new_header(container, num_flags),
+        header: new_header(container, num_flags, version),
         booleans: vec![false; num_flags as usize],
     };
-
-    for pkg in packages.iter() {
+    for pkg in filtered_packages {
         let start_index = pkg.boolean_start_index as usize;
         let flag_ids = assign_flag_ids(pkg.package_name, pkg.boolean_flags.iter().copied())?;
         for pf in pkg.boolean_flags.iter() {
@@ -61,13 +72,15 @@ pub fn create_flag_value(container: &str, packages: &[FlagPackage]) -> Result<Fl
 
 #[cfg(test)]
 mod tests {
+    use aconfig_storage_file::DEFAULT_FILE_VERSION;
+
     use super::*;
     use crate::storage::{group_flags_by_package, tests::parse_all_test_flags};
 
     pub fn create_test_flag_value_list_from_source() -> Result<FlagValueList> {
         let caches = parse_all_test_flags();
-        let packages = group_flags_by_package(caches.iter());
-        create_flag_value("mockup", &packages)
+        let packages = group_flags_by_package(caches.iter(), DEFAULT_FILE_VERSION);
+        create_flag_value("mockup", &packages, DEFAULT_FILE_VERSION)
     }
 
     #[test]
@@ -76,7 +89,7 @@ mod tests {
         let flag_value_list = create_test_flag_value_list_from_source();
         assert!(flag_value_list.is_ok());
         let expected_flag_value_list =
-            aconfig_storage_file::test_utils::create_test_flag_value_list();
+            aconfig_storage_file::test_utils::create_test_flag_value_list(DEFAULT_FILE_VERSION);
         assert_eq!(flag_value_list.unwrap(), expected_flag_value_list);
     }
 }
diff --git a/tools/aconfig/aconfig/src/storage/mod.rs b/tools/aconfig/aconfig/src/storage/mod.rs
index 73339f24b3..61e65d1dfc 100644
--- a/tools/aconfig/aconfig/src/storage/mod.rs
+++ b/tools/aconfig/aconfig/src/storage/mod.rs
@@ -14,23 +14,27 @@
  * limitations under the License.
  */
 
+pub mod flag_info;
 pub mod flag_table;
 pub mod flag_value;
 pub mod package_table;
 
-use anyhow::{anyhow, Result};
+use anyhow::Result;
 use std::collections::{HashMap, HashSet};
 
+use crate::commands::compute_flags_fingerprint;
 use crate::storage::{
-    flag_table::create_flag_table, flag_value::create_flag_value,
+    flag_info::create_flag_info, flag_table::create_flag_table, flag_value::create_flag_value,
     package_table::create_package_table,
 };
-use aconfig_protos::{ProtoParsedFlag, ProtoParsedFlags};
+use aconfig_protos::{ProtoFlagPermission, ProtoFlagState, ProtoParsedFlag, ProtoParsedFlags};
 use aconfig_storage_file::StorageFileType;
 
+#[derive(Clone)]
 pub struct FlagPackage<'a> {
     pub package_name: &'a str,
     pub package_id: u32,
+    pub fingerprint: u64,
     pub flag_names: HashSet<&'a str>,
     pub boolean_flags: Vec<&'a ProtoParsedFlag>,
     // The index of the first boolean flag in this aconfig package among all boolean
@@ -43,6 +47,7 @@ impl<'a> FlagPackage<'a> {
         FlagPackage {
             package_name,
             package_id,
+            fingerprint: 0,
             flag_names: HashSet::new(),
             boolean_flags: vec![],
             boolean_start_index: 0,
@@ -56,7 +61,7 @@ impl<'a> FlagPackage<'a> {
     }
 }
 
-pub fn group_flags_by_package<'a, I>(parsed_flags_vec_iter: I) -> Vec<FlagPackage<'a>>
+pub fn group_flags_by_package<'a, I>(parsed_flags_vec_iter: I, version: u32) -> Vec<FlagPackage<'a>>
 where
     I: Iterator<Item = &'a ProtoParsedFlags>,
 {
@@ -69,15 +74,33 @@ where
             if index == packages.len() {
                 packages.push(FlagPackage::new(parsed_flag.package(), index as u32));
             }
+
+            // Exclude system/vendor/product flags that are RO+disabled.
+            if (parsed_flag.container == Some("system".to_string())
+                || parsed_flag.container == Some("vendor".to_string())
+                || parsed_flag.container == Some("product".to_string()))
+                && parsed_flag.permission == Some(ProtoFlagPermission::READ_ONLY.into())
+                && parsed_flag.state == Some(ProtoFlagState::DISABLED.into())
+            {
+                continue;
+            }
+
             packages[index].insert(parsed_flag);
         }
     }
 
-    // cacluate boolean flag start index for each package
+    // Calculate boolean flag start index for each package
     let mut boolean_start_index = 0;
     for p in packages.iter_mut() {
         p.boolean_start_index = boolean_start_index;
         boolean_start_index += p.boolean_flags.len() as u32;
+
+        if version >= 2 {
+            let mut flag_names_vec =
+                p.flag_names.clone().into_iter().map(String::from).collect::<Vec<_>>();
+            let fingerprint = compute_flags_fingerprint(&mut flag_names_vec);
+            p.fingerprint = fingerprint;
+        }
     }
 
     packages
@@ -87,31 +110,37 @@ pub fn generate_storage_file<'a, I>(
     container: &str,
     parsed_flags_vec_iter: I,
     file: &StorageFileType,
+    version: u32,
 ) -> Result<Vec<u8>>
 where
     I: Iterator<Item = &'a ProtoParsedFlags>,
 {
-    let packages = group_flags_by_package(parsed_flags_vec_iter);
+    let packages = group_flags_by_package(parsed_flags_vec_iter, version);
 
     match file {
         StorageFileType::PackageMap => {
-            let package_table = create_package_table(container, &packages)?;
+            let package_table = create_package_table(container, &packages, version)?;
             Ok(package_table.into_bytes())
         }
         StorageFileType::FlagMap => {
-            let flag_table = create_flag_table(container, &packages)?;
+            let flag_table = create_flag_table(container, &packages, version)?;
             Ok(flag_table.into_bytes())
         }
         StorageFileType::FlagVal => {
-            let flag_value = create_flag_value(container, &packages)?;
+            let flag_value = create_flag_value(container, &packages, version)?;
             Ok(flag_value.into_bytes())
         }
-        _ => Err(anyhow!("aconfig does not support the creation of this storage file type")),
+        StorageFileType::FlagInfo => {
+            let flag_info = create_flag_info(container, &packages, version)?;
+            Ok(flag_info.into_bytes())
+        }
     }
 }
 
 #[cfg(test)]
 mod tests {
+    use aconfig_storage_file::DEFAULT_FILE_VERSION;
+
     use super::*;
     use crate::Input;
 
@@ -154,6 +183,7 @@ mod tests {
                         reader: Box::new(value_content),
                     }],
                     crate::commands::DEFAULT_FLAG_PERMISSION,
+                    true,
                 )
                 .unwrap();
                 aconfig_protos::parsed_flags::try_from_binary_proto(&bytes).unwrap()
@@ -164,7 +194,50 @@ mod tests {
     #[test]
     fn test_flag_package() {
         let caches = parse_all_test_flags();
-        let packages = group_flags_by_package(caches.iter());
+        let packages = group_flags_by_package(caches.iter(), DEFAULT_FILE_VERSION);
+
+        for pkg in packages.iter() {
+            let pkg_name = pkg.package_name;
+            assert_eq!(pkg.flag_names.len(), pkg.boolean_flags.len());
+            for pf in pkg.boolean_flags.iter() {
+                assert!(pkg.flag_names.contains(pf.name()));
+                assert_eq!(pf.package(), pkg_name);
+            }
+        }
+
+        assert_eq!(packages.len(), 3);
+
+        assert_eq!(packages[0].package_name, "com.android.aconfig.storage.test_1");
+        assert_eq!(packages[0].package_id, 0);
+        assert_eq!(packages[0].flag_names.len(), 3);
+        assert!(packages[0].flag_names.contains("enabled_rw"));
+        assert!(packages[0].flag_names.contains("disabled_rw"));
+        assert!(packages[0].flag_names.contains("enabled_ro"));
+        assert_eq!(packages[0].boolean_start_index, 0);
+        assert_eq!(packages[0].fingerprint, 0);
+
+        assert_eq!(packages[1].package_name, "com.android.aconfig.storage.test_2");
+        assert_eq!(packages[1].package_id, 1);
+        assert_eq!(packages[1].flag_names.len(), 3);
+        assert!(packages[1].flag_names.contains("enabled_ro"));
+        assert!(packages[1].flag_names.contains("disabled_rw"));
+        assert!(packages[1].flag_names.contains("enabled_fixed_ro"));
+        assert_eq!(packages[1].boolean_start_index, 3);
+        assert_eq!(packages[0].fingerprint, 0);
+
+        assert_eq!(packages[2].package_name, "com.android.aconfig.storage.test_4");
+        assert_eq!(packages[2].package_id, 2);
+        assert_eq!(packages[2].flag_names.len(), 2);
+        assert!(packages[2].flag_names.contains("enabled_rw"));
+        assert!(packages[2].flag_names.contains("enabled_fixed_ro"));
+        assert_eq!(packages[2].boolean_start_index, 6);
+        assert_eq!(packages[2].fingerprint, 0);
+    }
+
+    #[test]
+    fn test_flag_package_with_fingerprint() {
+        let caches = parse_all_test_flags();
+        let packages = group_flags_by_package(caches.iter(), 2);
 
         for pkg in packages.iter() {
             let pkg_name = pkg.package_name;
@@ -184,6 +257,7 @@ mod tests {
         assert!(packages[0].flag_names.contains("disabled_rw"));
         assert!(packages[0].flag_names.contains("enabled_ro"));
         assert_eq!(packages[0].boolean_start_index, 0);
+        assert_eq!(packages[0].fingerprint, 15248948510590158086u64);
 
         assert_eq!(packages[1].package_name, "com.android.aconfig.storage.test_2");
         assert_eq!(packages[1].package_id, 1);
@@ -192,6 +266,7 @@ mod tests {
         assert!(packages[1].flag_names.contains("disabled_rw"));
         assert!(packages[1].flag_names.contains("enabled_fixed_ro"));
         assert_eq!(packages[1].boolean_start_index, 3);
+        assert_eq!(packages[1].fingerprint, 4431940502274857964u64);
 
         assert_eq!(packages[2].package_name, "com.android.aconfig.storage.test_4");
         assert_eq!(packages[2].package_id, 2);
@@ -199,5 +274,6 @@ mod tests {
         assert!(packages[2].flag_names.contains("enabled_rw"));
         assert!(packages[2].flag_names.contains("enabled_fixed_ro"));
         assert_eq!(packages[2].boolean_start_index, 6);
+        assert_eq!(packages[2].fingerprint, 16233229917711622375u64);
     }
 }
diff --git a/tools/aconfig/aconfig/src/storage/package_table.rs b/tools/aconfig/aconfig/src/storage/package_table.rs
index c53602f9cb..53daa7ff2a 100644
--- a/tools/aconfig/aconfig/src/storage/package_table.rs
+++ b/tools/aconfig/aconfig/src/storage/package_table.rs
@@ -18,14 +18,13 @@ use anyhow::Result;
 
 use aconfig_storage_file::{
     get_table_size, PackageTable, PackageTableHeader, PackageTableNode, StorageFileType,
-    FILE_VERSION,
 };
 
 use crate::storage::FlagPackage;
 
-fn new_header(container: &str, num_packages: u32) -> PackageTableHeader {
+fn new_header(container: &str, num_packages: u32, version: u32) -> PackageTableHeader {
     PackageTableHeader {
-        version: FILE_VERSION,
+        version,
         container: String::from(container),
         file_type: StorageFileType::PackageMap as u8,
         file_size: 0,
@@ -48,6 +47,7 @@ impl PackageTableNodeWrapper {
         let node = PackageTableNode {
             package_name: String::from(package.package_name),
             package_id: package.package_id,
+            fingerprint: package.fingerprint,
             boolean_start_index: package.boolean_start_index,
             next_offset: None,
         };
@@ -56,20 +56,26 @@ impl PackageTableNodeWrapper {
     }
 }
 
-pub fn create_package_table(container: &str, packages: &[FlagPackage]) -> Result<PackageTable> {
+pub fn create_package_table(
+    container: &str,
+    packages: &[FlagPackage],
+    version: u32,
+) -> Result<PackageTable> {
     // create table
     let num_packages = packages.len() as u32;
     let num_buckets = get_table_size(num_packages)?;
-    let mut header = new_header(container, num_packages);
+    let mut header = new_header(container, num_packages, version);
     let mut buckets = vec![None; num_buckets as usize];
-    let mut node_wrappers: Vec<_> =
-        packages.iter().map(|pkg| PackageTableNodeWrapper::new(pkg, num_buckets)).collect();
+    let mut node_wrappers: Vec<_> = packages
+        .iter()
+        .map(|pkg: &FlagPackage<'_>| PackageTableNodeWrapper::new(pkg, num_buckets))
+        .collect();
 
     // initialize all header fields
     header.bucket_offset = header.into_bytes().len() as u32;
     header.node_offset = header.bucket_offset + num_buckets * 4;
     header.file_size = header.node_offset
-        + node_wrappers.iter().map(|x| x.node.into_bytes().len()).sum::<usize>() as u32;
+        + node_wrappers.iter().map(|x| x.node.into_bytes(version).len()).sum::<usize>() as u32;
 
     // sort node_wrappers by bucket index for efficiency
     node_wrappers.sort_by(|a, b| a.bucket_index.cmp(&b.bucket_index));
@@ -87,7 +93,7 @@ pub fn create_package_table(container: &str, packages: &[FlagPackage]) -> Result
         if buckets[node_bucket_idx as usize].is_none() {
             buckets[node_bucket_idx as usize] = Some(offset);
         }
-        offset += node_wrappers[i].node.into_bytes().len() as u32;
+        offset += node_wrappers[i].node.into_bytes(version).len() as u32;
 
         if let Some(index) = next_node_bucket_idx {
             if index == node_bucket_idx {
@@ -106,21 +112,59 @@ pub fn create_package_table(container: &str, packages: &[FlagPackage]) -> Result
 
 #[cfg(test)]
 mod tests {
+    use aconfig_storage_file::{DEFAULT_FILE_VERSION, MAX_SUPPORTED_FILE_VERSION};
+
     use super::*;
     use crate::storage::{group_flags_by_package, tests::parse_all_test_flags};
 
-    pub fn create_test_package_table_from_source() -> Result<PackageTable> {
+    pub fn create_test_package_table_from_source(version: u32) -> Result<PackageTable> {
         let caches = parse_all_test_flags();
-        let packages = group_flags_by_package(caches.iter());
-        create_package_table("mockup", &packages)
+        let packages = group_flags_by_package(caches.iter(), version);
+        create_package_table("mockup", &packages, version)
     }
 
     #[test]
     // this test point locks down the table creation and each field
-    fn test_table_contents() {
-        let package_table = create_test_package_table_from_source();
-        assert!(package_table.is_ok());
-        let expected_package_table = aconfig_storage_file::test_utils::create_test_package_table();
-        assert_eq!(package_table.unwrap(), expected_package_table);
+    fn test_table_contents_default_version() {
+        let package_table_result = create_test_package_table_from_source(DEFAULT_FILE_VERSION);
+        assert!(package_table_result.is_ok());
+        let package_table = package_table_result.unwrap();
+
+        let expected_package_table =
+            aconfig_storage_file::test_utils::create_test_package_table(DEFAULT_FILE_VERSION);
+
+        assert_eq!(package_table.header, expected_package_table.header);
+        assert_eq!(package_table.buckets, expected_package_table.buckets);
+        for (node, expected_node) in
+            package_table.nodes.iter().zip(expected_package_table.nodes.iter())
+        {
+            assert_eq!(node.package_name, expected_node.package_name);
+            assert_eq!(node.package_id, expected_node.package_id);
+            assert_eq!(node.boolean_start_index, expected_node.boolean_start_index);
+            assert_eq!(node.next_offset, expected_node.next_offset);
+        }
+    }
+
+    #[test]
+    // this test point locks down the table creation and each field
+    fn test_table_contents_max_version() {
+        let package_table_result =
+            create_test_package_table_from_source(MAX_SUPPORTED_FILE_VERSION);
+        assert!(package_table_result.is_ok());
+        let package_table = package_table_result.unwrap();
+
+        let expected_package_table =
+            aconfig_storage_file::test_utils::create_test_package_table(MAX_SUPPORTED_FILE_VERSION);
+
+        assert_eq!(package_table.header, expected_package_table.header);
+        assert_eq!(package_table.buckets, expected_package_table.buckets);
+        for (node, expected_node) in
+            package_table.nodes.iter().zip(expected_package_table.nodes.iter())
+        {
+            assert_eq!(node.package_name, expected_node.package_name);
+            assert_eq!(node.package_id, expected_node.package_id);
+            assert_eq!(node.boolean_start_index, expected_node.boolean_start_index);
+            assert_eq!(node.next_offset, expected_node.next_offset);
+        }
     }
 }
diff --git a/tools/aconfig/aconfig/src/test.rs b/tools/aconfig/aconfig/src/test.rs
index 7409cda6e8..10da252ceb 100644
--- a/tools/aconfig/aconfig/src/test.rs
+++ b/tools/aconfig/aconfig/src/test.rs
@@ -266,6 +266,7 @@ parsed_flag {
                 reader: Box::new(include_bytes!("../tests/read_only_test.values").as_slice()),
             }],
             crate::commands::DEFAULT_FLAG_PERMISSION,
+            true,
         )
         .unwrap();
         aconfig_protos::parsed_flags::try_from_binary_proto(&bytes).unwrap()
@@ -290,6 +291,26 @@ parsed_flag {
                 },
             ],
             crate::commands::DEFAULT_FLAG_PERMISSION,
+            true,
+        )
+        .unwrap();
+        aconfig_protos::parsed_flags::try_from_binary_proto(&bytes).unwrap()
+    }
+
+    pub fn parse_second_package_flags() -> ProtoParsedFlags {
+        let bytes = crate::commands::parse_flags(
+            "com.android.aconfig.second_test",
+            Some("system"),
+            vec![Input {
+                source: "tests/test_second_package.aconfig".to_string(),
+                reader: Box::new(include_bytes!("../tests/test_second_package.aconfig").as_slice()),
+            }],
+            vec![Input {
+                source: "tests/third.values".to_string(),
+                reader: Box::new(include_bytes!("../tests/third.values").as_slice()),
+            }],
+            crate::commands::DEFAULT_FLAG_PERMISSION,
+            true,
         )
         .unwrap();
         aconfig_protos::parsed_flags::try_from_binary_proto(&bytes).unwrap()
diff --git a/tools/aconfig/aconfig/templates/FeatureFlags.java.template b/tools/aconfig/aconfig/templates/FeatureFlags.java.template
index 38c8f13aaf..d2799b2474 100644
--- a/tools/aconfig/aconfig/templates/FeatureFlags.java.template
+++ b/tools/aconfig/aconfig/templates/FeatureFlags.java.template
@@ -19,4 +19,4 @@ public interface FeatureFlags \{
 {{ -endif }}
     boolean {item.method_name}();
 {{ -endfor }}
-}
\ No newline at end of file
+}
diff --git a/tools/aconfig/aconfig/templates/FeatureFlagsImpl.java.template b/tools/aconfig/aconfig/templates/FeatureFlagsImpl.java.template
index bc01aa4bab..b605e72a78 100644
--- a/tools/aconfig/aconfig/templates/FeatureFlagsImpl.java.template
+++ b/tools/aconfig/aconfig/templates/FeatureFlagsImpl.java.template
@@ -1,66 +1,86 @@
 package {package_name};
 {{ -if not is_test_mode }}
-{{ if not library_exported- }}
+{{ -if allow_instrumentation }}
+{{ if not library_exported- }}{#- only new storage for prod mode #}
 // TODO(b/303773055): Remove the annotation after access issue is resolved.
 import android.compat.annotation.UnsupportedAppUsage;
-{{ -endif }}
-
 {{ -if runtime_lookup_required }}
-import android.provider.DeviceConfig;
-import android.provider.DeviceConfig.Properties;
-
-
-{{ -if not library_exported }}
-{{ -if allow_instrumentation }}
-import android.aconfig.storage.StorageInternalReader;
-import android.util.Log;
-{{ -endif }}
+import android.os.Build;
+{{ if is_platform_container }}
+import android.os.flagging.PlatformAconfigPackageInternal;
+{{ -else }}
+import android.os.flagging.AconfigPackageInternal;
 {{ -endif }}
-
+import android.util.Log;
 {{ -endif }}
 /** @hide */
 public final class FeatureFlagsImpl implements FeatureFlags \{
 {{ -if runtime_lookup_required }}
-{{ -for namespace_with_flags in namespace_flags }}
-    private static volatile boolean {namespace_with_flags.namespace}_is_cached = false;
-{{ -endfor- }}
-
+    private static final String TAG = "{package_name}.FeatureFlagsImpl";
+    private static volatile boolean isCached = false;
 {{ for flag in flag_elements }}
-{{- if flag.is_read_write }}
+{{ -if flag.is_read_write }}
     private static boolean {flag.method_name} = {flag.default_value};
 {{ -endif }}
 {{ -endfor }}
-{{ -if not library_exported }}
-{{ -if allow_instrumentation }}
-    StorageInternalReader reader;
-    boolean readFromNewStorage;
-
-    boolean useNewStorageValueAndDiscardOld = false;
-
-    private final static String TAG = "AconfigJavaCodegen";
-    private final static String SUCCESS_LOG = "success: %s value matches";
-    private final static String MISMATCH_LOG = "error: %s value mismatch, new storage value is %s, old storage value is %s";
-    private final static String ERROR_LOG = "error: failed to read flag value";
 
     private void init() \{
-        if (reader != null) return;
-        if (DeviceConfig.getBoolean("core_experiments_team_internal", "com.android.providers.settings.storage_test_mission_1", false)) \{
-            readFromNewStorage = true;
-            try \{
-                reader = new StorageInternalReader("{container}", "{package_name}");
-            } catch (Exception e) \{
-                reader = null;
-            }
+        try \{
+{{ if is_platform_container }}
+            PlatformAconfigPackageInternal reader = PlatformAconfigPackageInternal.load("{container}", "{package_name}", {package_fingerprint});
+{{ -else }}
+            AconfigPackageInternal reader = AconfigPackageInternal.load("{container}", "{package_name}", {package_fingerprint});
+{{ -endif }}
+        {{ -for namespace_with_flags in namespace_flags }}
+        {{ -for flag in namespace_with_flags.flags }}
+        {{ -if flag.is_read_write }}
+            {flag.method_name} = reader.getBooleanFlagValue({flag.flag_offset});
+        {{ -endif }}
+        {{ -endfor }}
+        {{ -endfor }}
+        } catch (Exception e) \{
+            Log.e(TAG, e.toString());
+        } catch (NoClassDefFoundError e) \{
+            // for mainline module running on older devices.
+            // This should be replaces to version check, after the version bump.
+            Log.e(TAG, e.toString());
         }
-
-        useNewStorageValueAndDiscardOld =
-            DeviceConfig.getBoolean("core_experiments_team_internal", "com.android.providers.settings.use_new_storage_value", false);
+        isCached = true;
     }
-
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
+{{ -else }}
+        return {flag.default_value};
 {{ -endif }}
+    }
+{{ endfor }}
+}
+{{ -else- }}{#- device config for exproted mode #}
+import android.os.Binder;
+import android.provider.DeviceConfig;
+import android.provider.DeviceConfig.Properties;
+/** @hide */
+public final class FeatureFlagsImpl implements FeatureFlags \{
+{{ -for namespace_with_flags in namespace_flags }}
+    private static volatile boolean {namespace_with_flags.namespace}_is_cached = false;
+{{ -endfor- }}
+{{ for flag in flag_elements }}
+{{ -if flag.is_read_write }}
+    private static boolean {flag.method_name} = {flag.default_value};
 {{ -endif }}
+{{ -endfor }}
 {{ for namespace_with_flags in namespace_flags }}
     private void load_overrides_{namespace_with_flags.namespace}() \{
+        final long ident = Binder.clearCallingIdentity();
         try \{
             Properties properties = DeviceConfig.getProperties("{namespace_with_flags.namespace}");
 {{ -for flag in namespace_with_flags.flags }}
@@ -78,35 +98,73 @@ public final class FeatureFlagsImpl implements FeatureFlags \{
                 + "flag declaration.",
                 e
             );
+        } catch (SecurityException e) \{
+            // for isolated process case, skip loading flag value from the storage, use the default
+        } finally \{
+            Binder.restoreCallingIdentity(ident);
         }
         {namespace_with_flags.namespace}_is_cached = true;
-{{ -if not library_exported }}
-{{ -if allow_instrumentation }}
-        init();
-        if (readFromNewStorage && reader != null) \{
-            boolean val;
-            try \{
-{{ -for flag in namespace_with_flags.flags }}
-{{ -if flag.is_read_write }}
-
-                val = reader.getBooleanFlagValue({flag.flag_offset});
-                if (val != {flag.method_name}) \{
-                    Log.w(TAG, String.format(MISMATCH_LOG, "{flag.method_name}", val, {flag.method_name}));
-                }
+    }
+{{ endfor- }}
+{{ -for flag in flag_elements }}
+    @Override
+    public boolean {flag.method_name}() \{
+        if (!{flag.device_config_namespace}_is_cached) \{
+            load_overrides_{flag.device_config_namespace}();
+        }
+        return {flag.method_name};
+    }
+{{ endfor }}
+}
+{{ -endif- }} {#- end exported mode #}
+{{ else }} {#- else for allow_instrumentation is not enabled #}
+{{ if not library_exported- }}
+// TODO(b/303773055): Remove the annotation after access issue is resolved.
+import android.compat.annotation.UnsupportedAppUsage;
+{{ -endif }}
 
-                if (useNewStorageValueAndDiscardOld) \{
-                    {flag.method_name} = val;
-                }
+{{ -if runtime_lookup_required }}
+import android.os.Binder;
+import android.provider.DeviceConfig;
+import android.provider.DeviceConfig.Properties;
+{{ -endif }}
+/** @hide */
+public final class FeatureFlagsImpl implements FeatureFlags \{
+{{ -if runtime_lookup_required }}
+{{ -for namespace_with_flags in namespace_flags }}
+    private static volatile boolean {namespace_with_flags.namespace}_is_cached = false;
+{{ -endfor- }}
 
+{{ for flag in flag_elements }}
+{{- if flag.is_read_write }}
+    private static boolean {flag.method_name} = {flag.default_value};
 {{ -endif }}
 {{ -endfor }}
-            } catch (Exception e) \{
-                    Log.e(TAG, ERROR_LOG, e);
-            }
-        }
-{{ -endif }}
+{{ for namespace_with_flags in namespace_flags }}
+    private void load_overrides_{namespace_with_flags.namespace}() \{
+        final long ident = Binder.clearCallingIdentity();
+        try \{
+            Properties properties = DeviceConfig.getProperties("{namespace_with_flags.namespace}");
+{{ -for flag in namespace_with_flags.flags }}
+{{ -if flag.is_read_write }}
+            {flag.method_name} =
+                properties.getBoolean(Flags.FLAG_{flag.flag_name_constant_suffix}, {flag.default_value});
 {{ -endif }}
-    }
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
+        } finally \{
+            Binder.restoreCallingIdentity(ident);
+        }
+        {namespace_with_flags.namespace}_is_cached = true;
+}
 {{ endfor- }}
 {{ -endif }}{#- end of runtime_lookup_required #}
 {{ -for flag in flag_elements }}
@@ -127,8 +185,8 @@ public final class FeatureFlagsImpl implements FeatureFlags \{
     }
 {{ endfor }}
 }
-{{ else }}
-{#- Generate only stub if in test mode #}
+{{ endif}} {#- endif for allow_instrumentation #}
+{{ else }} {#- Generate only stub if in test mode #}
 /** @hide */
 public final class FeatureFlagsImpl implements FeatureFlags \{
 {{ for flag in flag_elements }}
diff --git a/tools/aconfig/aconfig/templates/cpp_source_file.template b/tools/aconfig/aconfig/templates/cpp_source_file.template
index 852b905f32..9be59e0877 100644
--- a/tools/aconfig/aconfig/templates/cpp_source_file.template
+++ b/tools/aconfig/aconfig/templates/cpp_source_file.template
@@ -76,27 +76,28 @@ namespace {cpp_namespace} \{
             : boolean_start_index_()
             {{ -endif }}
             , flag_value_file_(nullptr)
-            , read_from_new_storage_(false) \{
-
-            if (access("/metadata/aconfig/boot/enable_only_new_storage", F_OK) == 0) \{
-               read_from_new_storage_ = true;
-            }
-
-            if (!read_from_new_storage_) \{
-               return;
-            }
+            , package_exists_in_storage_(true) \{
 
             auto package_map_file = aconfig_storage::get_mapped_file(
                  "{container}",
                  aconfig_storage::StorageFileType::package_map);
             if (!package_map_file.ok()) \{
                 ALOGE("error: failed to get package map file: %s", package_map_file.error().c_str());
+                package_exists_in_storage_ = false;
+                return;
             }
 
             auto context = aconfig_storage::get_package_read_context(
                 **package_map_file, "{package}");
             if (!context.ok()) \{
                 ALOGE("error: failed to get package read context: %s", context.error().c_str());
+                package_exists_in_storage_ = false;
+                return;
+            }
+
+            if (!(context->package_exists)) \{
+                package_exists_in_storage_ = false;
+                return;
             }
 
             // cache package boolean flag start index
@@ -110,6 +111,8 @@ namespace {cpp_namespace} \{
                 aconfig_storage::StorageFileType::flag_val);
             if (!flag_value_file.ok()) \{
                 ALOGE("error: failed to get flag value file: %s", flag_value_file.error().c_str());
+                package_exists_in_storage_ = false;
+                return;
             }
 
             // cache flag value file
@@ -125,22 +128,19 @@ namespace {cpp_namespace} \{
             {{ -if item.readwrite }}
             if (cache_[{item.readwrite_idx}] == -1) \{
             {{ if allow_instrumentation- }}
-                if (read_from_new_storage_) \{
-                    auto value = aconfig_storage::get_boolean_flag_value(
-                        *flag_value_file_,
-                        boolean_start_index_ + {item.flag_offset});
-
-                    if (!value.ok()) \{
-                        ALOGE("error: failed to read flag value: %s", value.error().c_str());
-                    }
-
-                    cache_[{item.readwrite_idx}] = *value;
-                } else \{
-                    cache_[{item.readwrite_idx}] = server_configurable_flags::GetServerConfigurableFlag(
-                        "aconfig_flags.{item.device_config_namespace}",
-                        "{item.device_config_flag}",
-                        "{item.default_value}") == "true";
+                if (!package_exists_in_storage_) \{
+                    return {item.default_value};
                 }
+
+                auto value = aconfig_storage::get_boolean_flag_value(
+                    *flag_value_file_,
+                    boolean_start_index_ + {item.flag_offset});
+
+                if (!value.ok()) \{
+                    ALOGE("error: failed to read flag value: %s", value.error().c_str());
+                }
+
+                cache_[{item.readwrite_idx}] = *value;
             {{ -else- }}
                 cache_[{item.readwrite_idx}] = server_configurable_flags::GetServerConfigurableFlag(
                     "aconfig_flags.{item.device_config_namespace}",
@@ -167,7 +167,7 @@ namespace {cpp_namespace} \{
 
         std::unique_ptr<aconfig_storage::MappedStorageFile> flag_value_file_;
 
-        bool read_from_new_storage_;
+        bool package_exists_in_storage_;
     {{ -endif }}
     {{ -endif }}
 
diff --git a/tools/aconfig/aconfig/templates/rust.template b/tools/aconfig/aconfig/templates/rust.template
index c2f162fcc8..e9e1032686 100644
--- a/tools/aconfig/aconfig/templates/rust.template
+++ b/tools/aconfig/aconfig/templates/rust.template
@@ -10,10 +10,6 @@ pub struct FlagProvider;
 
 {{ if has_readwrite- }}
 {{ if allow_instrumentation }}
-static READ_FROM_NEW_STORAGE: LazyLock<bool> = LazyLock::new(|| unsafe \{
-    Path::new("/metadata/aconfig/boot/enable_only_new_storage").exists()
-});
-
 static PACKAGE_OFFSET: LazyLock<Result<Option<u32>, AconfigStorageError>> = LazyLock::new(|| unsafe \{
     get_mapped_storage_file("{container}", StorageFileType::PackageMap)
     .and_then(|package_map| get_package_read_context(&package_map, "{package}"))
@@ -31,45 +27,41 @@ static FLAG_VAL_MAP: LazyLock<Result<Mmap, AconfigStorageError>> = LazyLock::new
 {{ if allow_instrumentation }}
 static CACHED_{flag.name}: LazyLock<bool> = LazyLock::new(|| \{
 
-    if *READ_FROM_NEW_STORAGE \{
-        // This will be called multiple times. Subsequent calls after the first are noops.
-        logger::init(
-            logger::Config::default()
-                .with_tag_on_device("aconfig_rust_codegen")
-                .with_max_level(LevelFilter::Info));
+    // This will be called multiple times. Subsequent calls after the first are noops.
+    logger::init(
+        logger::Config::default()
+            .with_tag_on_device("aconfig_rust_codegen")
+            .with_max_level(LevelFilter::Info));
 
-        let flag_value_result = FLAG_VAL_MAP
-            .as_ref()
-            .map_err(|err| format!("failed to get flag val map: \{err}"))
-            .and_then(|flag_val_map| \{
-                PACKAGE_OFFSET
-                    .as_ref()
-                    .map_err(|err| format!("failed to get package read offset: \{err}"))
-                    .and_then(|package_offset| \{
-                        match package_offset \{
-                            Some(offset) => \{
-                                get_boolean_flag_value(&flag_val_map, offset + {flag.flag_offset})
-                                    .map_err(|err| format!("failed to get flag: \{err}"))
-                            },
-                            None => Err("no context found for package '{package}'".to_string())
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
                         }
-                    })
-                });
+                    }
+                })
+            });
 
-        match flag_value_result \{
-            Ok(flag_value) => \{
-                return flag_value;
-            },
-            Err(err) => \{
-                log!(Level::Error, "aconfig_rust_codegen: error: \{err}");
-                panic!("failed to read flag value: \{err}");
-            }
+    match flag_value_result \{
+        Ok(flag_value) => \{
+            return flag_value;
+        },
+        Err(err) => \{
+            log!(Level::Error, "aconfig_rust_codegen: error: \{err}");
+            return {flag.default_value};
         }
-    } else \{
-        flags_rust::GetServerConfigurableFlag(
-            "aconfig_flags.{flag.device_config_namespace}",
-            "{flag.device_config_flag}",
-            "{flag.default_value}") == "true"
     }
 
 });
diff --git a/tools/aconfig/aconfig/tests/test_second_package.aconfig b/tools/aconfig/aconfig/tests/test_second_package.aconfig
new file mode 100644
index 0000000000..188bc96cfb
--- /dev/null
+++ b/tools/aconfig/aconfig/tests/test_second_package.aconfig
@@ -0,0 +1,10 @@
+package: "com.android.aconfig.second_test"
+container: "system"
+
+flag {
+    name: "testing_flag"
+    namespace: "another_namespace"
+    description: "This is a flag for testing."
+    bug: "123"
+}
+
diff --git a/tools/aconfig/aconfig/tests/third.values b/tools/aconfig/aconfig/tests/third.values
new file mode 100644
index 0000000000..675832a4bc
--- /dev/null
+++ b/tools/aconfig/aconfig/tests/third.values
@@ -0,0 +1,6 @@
+flag_value {
+    package: "com.android.aconfig.second_test"
+    name: "testing_flag"
+    state: DISABLED
+    permission: READ_WRITE
+}
diff --git a/tools/aconfig/aconfig_device_paths/Android.bp b/tools/aconfig/aconfig_device_paths/Android.bp
index dda7a55903..bdf96ed896 100644
--- a/tools/aconfig/aconfig_device_paths/Android.bp
+++ b/tools/aconfig/aconfig_device_paths/Android.bp
@@ -61,8 +61,12 @@ genrule {
     name: "libaconfig_java_host_device_paths_src",
     srcs: ["src/HostDeviceProtosTemplate.java"],
     out: ["HostDeviceProtos.java"],
-    tool_files: ["partition_aconfig_flags_paths.txt"],
-    cmd: "sed -e '/TEMPLATE/{r$(location partition_aconfig_flags_paths.txt)' -e 'd}' $(in) > $(out)",
+    tool_files: [
+        "partition_aconfig_flags_paths.txt",
+        "mainline_aconfig_flags_paths.txt",
+    ],
+    cmd: "sed -e '/TEMPLATE/{r$(location partition_aconfig_flags_paths.txt)' -e 'd}' $(in) > $(out).tmp && " +
+    "sed -e '/MAINLINE_T/{r$(location mainline_aconfig_flags_paths.txt)' -e 'd}' $(out).tmp > $(out)",
 }
 
 java_library_host {
diff --git a/tools/aconfig/aconfig_device_paths/mainline_aconfig_flags_paths.txt b/tools/aconfig/aconfig_device_paths/mainline_aconfig_flags_paths.txt
new file mode 100644
index 0000000000..af73a842b9
--- /dev/null
+++ b/tools/aconfig/aconfig_device_paths/mainline_aconfig_flags_paths.txt
@@ -0,0 +1,20 @@
+"/apex/com.android.adservices/etc/aconfig_flags.pb",
+"/apex/com.android.appsearch/etc/aconfig_flags.pb",
+"/apex/com.android.art/etc/aconfig_flags.pb",
+"/apex/com.android.btservices/etc/aconfig_flags.pb",
+"/apex/com.android.cellbroadcast/etc/aconfig_flags.pb",
+"/apex/com.android.configinfrastructure/etc/aconfig_flags.pb",
+"/apex/com.android.conscrypt/etc/aconfig_flags.pb",
+"/apex/com.android.devicelock/etc/aconfig_flags.pb",
+"/apex/com.android.healthfitness/etc/aconfig_flags.pb",
+"/apex/com.android.ipsec/etc/aconfig_flags.pb",
+"/apex/com.android.media/etc/aconfig_flags.pb",
+"/apex/com.android.mediaprovider/etc/aconfig_flags.pb",
+"/apex/com.android.ondevicepersonalization/etc/aconfig_flags.pb",
+"/apex/com.android.os.statsd/etc/aconfig_flags.pb",
+"/apex/com.android.permission/etc/aconfig_flags.pb",
+"/apex/com.android.profiling/etc/aconfig_flags.pb",
+"/apex/com.android.tethering/etc/aconfig_flags.pb",
+"/apex/com.android.uwb/etc/aconfig_flags.pb",
+"/apex/com.android.virt/etc/aconfig_flags.pb",
+"/apex/com.android.wifi/etc/aconfig_flags.pb",
diff --git a/tools/aconfig/aconfig_device_paths/partition_aconfig_flags_paths.txt b/tools/aconfig/aconfig_device_paths/partition_aconfig_flags_paths.txt
index 140cd21ac8..e997e3ddfa 100644
--- a/tools/aconfig/aconfig_device_paths/partition_aconfig_flags_paths.txt
+++ b/tools/aconfig/aconfig_device_paths/partition_aconfig_flags_paths.txt
@@ -1,4 +1,3 @@
 "/system/etc/aconfig_flags.pb",
-"/system_ext/etc/aconfig_flags.pb",
 "/product/etc/aconfig_flags.pb",
 "/vendor/etc/aconfig_flags.pb",
diff --git a/tools/aconfig/aconfig_device_paths/src/HostDeviceProtosTemplate.java b/tools/aconfig/aconfig_device_paths/src/HostDeviceProtosTemplate.java
index 844232b9e1..e7d0a76a8a 100644
--- a/tools/aconfig/aconfig_device_paths/src/HostDeviceProtosTemplate.java
+++ b/tools/aconfig/aconfig_device_paths/src/HostDeviceProtosTemplate.java
@@ -25,6 +25,7 @@ import java.util.stream.Collectors;
 
 /**
  * A host lib that can read all aconfig proto file paths on a given device.
+ * This lib is only available on device with root access (userdebug/eng).
  */
 public class HostDeviceProtos {
     /**
@@ -39,8 +40,13 @@ public class HostDeviceProtos {
         TEMPLATE
     };
 
+    static final String[] MAINLINE_PATHS = {
+        MAINLINE_T
+    };
+
     private static final String APEX_DIR = "/apex";
-    private static final String RECURSIVELY_LIST_APEX_DIR_COMMAND = "shell find /apex | grep aconfig_flags";
+    private static final String RECURSIVELY_LIST_APEX_DIR_COMMAND =
+        "shell su 0 find /apex | grep aconfig_flags";
     private static final String APEX_ACONFIG_PATH_SUFFIX = "/etc/aconfig_flags.pb";
 
 
@@ -53,7 +59,8 @@ public class HostDeviceProtos {
         String adbCommandOutput = adbCommandExecutor.executeAdbCommand(
             RECURSIVELY_LIST_APEX_DIR_COMMAND);
 
-        if (adbCommandOutput == null) {
+        if (adbCommandOutput == null || adbCommandOutput.isEmpty()) {
+            paths.addAll(Arrays.asList(MAINLINE_PATHS));
             return paths;
         }
 
diff --git a/tools/aconfig/aconfig_device_paths/src/lib.rs b/tools/aconfig/aconfig_device_paths/src/lib.rs
index 9ab9cea267..8871b4f8ac 100644
--- a/tools/aconfig/aconfig_device_paths/src/lib.rs
+++ b/tools/aconfig/aconfig_device_paths/src/lib.rs
@@ -62,13 +62,12 @@ mod tests {
 
     #[test]
     fn test_read_partition_paths() {
-        assert_eq!(read_partition_paths().len(), 4);
+        assert_eq!(read_partition_paths().len(), 3);
 
         assert_eq!(
             read_partition_paths(),
             vec![
                 PathBuf::from("/system/etc/aconfig_flags.pb"),
-                PathBuf::from("/system_ext/etc/aconfig_flags.pb"),
                 PathBuf::from("/product/etc/aconfig_flags.pb"),
                 PathBuf::from("/vendor/etc/aconfig_flags.pb")
             ]
diff --git a/tools/aconfig/aconfig_flags/Android.bp b/tools/aconfig/aconfig_flags/Android.bp
index e327ced26c..4c1fd4efcf 100644
--- a/tools/aconfig/aconfig_flags/Android.bp
+++ b/tools/aconfig/aconfig_flags/Android.bp
@@ -44,3 +44,8 @@ cc_aconfig_library {
     name: "libaconfig_flags_cc",
     aconfig_declarations: "aconfig_flags",
 }
+
+java_aconfig_library {
+    name: "aconfig_flags_java",
+    aconfig_declarations: "aconfig_flags",
+}
diff --git a/tools/aconfig/aconfig_flags/flags.aconfig b/tools/aconfig/aconfig_flags/flags.aconfig
index db8b1b7904..0a004ca4e1 100644
--- a/tools/aconfig/aconfig_flags/flags.aconfig
+++ b/tools/aconfig/aconfig_flags/flags.aconfig
@@ -7,3 +7,10 @@ flag {
   bug: "312235596"
   description: "When enabled, aconfig flags are read from the new aconfig storage only."
 }
+
+flag {
+  name: "enable_aconfigd_from_mainline"
+  namespace: "core_experiments_team_internal"
+  bug: "369808805"
+  description: "When enabled, launch aconfigd from config infra module."
+}
diff --git a/tools/aconfig/aconfig_flags/src/lib.rs b/tools/aconfig/aconfig_flags/src/lib.rs
index a607efb7d4..2e891273ed 100644
--- a/tools/aconfig/aconfig_flags/src/lib.rs
+++ b/tools/aconfig/aconfig_flags/src/lib.rs
@@ -34,6 +34,11 @@ pub mod auto_generated {
     pub fn enable_only_new_storage() -> bool {
         aconfig_flags_rust::enable_only_new_storage()
     }
+
+    /// Returns the value for the enable_aconfigd_from_mainline flag.
+    pub fn enable_aconfigd_from_mainline() -> bool {
+        aconfig_flags_rust::enable_only_new_storage()
+    }
 }
 
 /// Module used when building with cargo
@@ -44,4 +49,10 @@ pub mod auto_generated {
         // Used only to enable typechecking and testing with cargo
         true
     }
+
+    /// Returns a placeholder value for the enable_aconfigd_from_mainline flag.
+    pub fn enable_aconfigd_from_mainline() -> bool {
+        // Used only to enable typechecking and testing with cargo
+        true
+    }
 }
diff --git a/tools/aconfig/aconfig_storage_file/src/flag_info.rs b/tools/aconfig/aconfig_storage_file/src/flag_info.rs
index f090396901..cf16834be2 100644
--- a/tools/aconfig/aconfig_storage_file/src/flag_info.rs
+++ b/tools/aconfig/aconfig_storage_file/src/flag_info.rs
@@ -194,12 +194,15 @@ impl FlagInfoList {
 #[cfg(test)]
 mod tests {
     use super::*;
-    use crate::test_utils::create_test_flag_info_list;
+    use crate::{
+        test_utils::create_test_flag_info_list, DEFAULT_FILE_VERSION, MAX_SUPPORTED_FILE_VERSION,
+    };
 
-    #[test]
     // this test point locks down the value list serialization
-    fn test_serialization() {
-        let flag_info_list = create_test_flag_info_list();
+    // TODO: b/376108268 - Use parameterized tests.
+    #[test]
+    fn test_serialization_default() {
+        let flag_info_list = create_test_flag_info_list(DEFAULT_FILE_VERSION);
 
         let header: &FlagInfoHeader = &flag_info_list.header;
         let reinterpreted_header = FlagInfoHeader::from_bytes(&header.into_bytes());
@@ -220,20 +223,42 @@ mod tests {
     }
 
     #[test]
+    fn test_serialization_max() {
+        let flag_info_list = create_test_flag_info_list(MAX_SUPPORTED_FILE_VERSION);
+
+        let header: &FlagInfoHeader = &flag_info_list.header;
+        let reinterpreted_header = FlagInfoHeader::from_bytes(&header.into_bytes());
+        assert!(reinterpreted_header.is_ok());
+        assert_eq!(header, &reinterpreted_header.unwrap());
+
+        let nodes: &Vec<FlagInfoNode> = &flag_info_list.nodes;
+        for node in nodes.iter() {
+            let reinterpreted_node = FlagInfoNode::from_bytes(&node.into_bytes()).unwrap();
+            assert_eq!(node, &reinterpreted_node);
+        }
+
+        let flag_info_bytes = flag_info_list.into_bytes();
+        let reinterpreted_info_list = FlagInfoList::from_bytes(&flag_info_bytes);
+        assert!(reinterpreted_info_list.is_ok());
+        assert_eq!(&flag_info_list, &reinterpreted_info_list.unwrap());
+        assert_eq!(flag_info_bytes.len() as u32, header.file_size);
+    }
+
     // this test point locks down that version number should be at the top of serialized
     // bytes
+    #[test]
     fn test_version_number() {
-        let flag_info_list = create_test_flag_info_list();
+        let flag_info_list = create_test_flag_info_list(DEFAULT_FILE_VERSION);
         let bytes = &flag_info_list.into_bytes();
         let mut head = 0;
-        let version = read_u32_from_bytes(bytes, &mut head).unwrap();
-        assert_eq!(version, 1);
+        let version_from_file = read_u32_from_bytes(bytes, &mut head).unwrap();
+        assert_eq!(version_from_file, DEFAULT_FILE_VERSION);
     }
 
-    #[test]
     // this test point locks down file type check
+    #[test]
     fn test_file_type_check() {
-        let mut flag_info_list = create_test_flag_info_list();
+        let mut flag_info_list = create_test_flag_info_list(DEFAULT_FILE_VERSION);
         flag_info_list.header.file_type = 123u8;
         let error = FlagInfoList::from_bytes(&flag_info_list.into_bytes()).unwrap_err();
         assert_eq!(
diff --git a/tools/aconfig/aconfig_storage_file/src/flag_table.rs b/tools/aconfig/aconfig_storage_file/src/flag_table.rs
index 0588fe5039..6fbee023ce 100644
--- a/tools/aconfig/aconfig_storage_file/src/flag_table.rs
+++ b/tools/aconfig/aconfig_storage_file/src/flag_table.rs
@@ -220,12 +220,15 @@ impl FlagTable {
 #[cfg(test)]
 mod tests {
     use super::*;
-    use crate::test_utils::create_test_flag_table;
+    use crate::{
+        test_utils::create_test_flag_table, DEFAULT_FILE_VERSION, MAX_SUPPORTED_FILE_VERSION,
+    };
 
-    #[test]
     // this test point locks down the table serialization
-    fn test_serialization() {
-        let flag_table = create_test_flag_table();
+    // TODO: b/376108268 - Use parameterized tests.
+    #[test]
+    fn test_serialization_default() {
+        let flag_table = create_test_flag_table(DEFAULT_FILE_VERSION);
 
         let header: &FlagTableHeader = &flag_table.header;
         let reinterpreted_header = FlagTableHeader::from_bytes(&header.into_bytes());
@@ -246,20 +249,42 @@ mod tests {
     }
 
     #[test]
+    fn test_serialization_max() {
+        let flag_table = create_test_flag_table(MAX_SUPPORTED_FILE_VERSION);
+
+        let header: &FlagTableHeader = &flag_table.header;
+        let reinterpreted_header = FlagTableHeader::from_bytes(&header.into_bytes());
+        assert!(reinterpreted_header.is_ok());
+        assert_eq!(header, &reinterpreted_header.unwrap());
+
+        let nodes: &Vec<FlagTableNode> = &flag_table.nodes;
+        for node in nodes.iter() {
+            let reinterpreted_node = FlagTableNode::from_bytes(&node.into_bytes()).unwrap();
+            assert_eq!(node, &reinterpreted_node);
+        }
+
+        let flag_table_bytes = flag_table.into_bytes();
+        let reinterpreted_table = FlagTable::from_bytes(&flag_table_bytes);
+        assert!(reinterpreted_table.is_ok());
+        assert_eq!(&flag_table, &reinterpreted_table.unwrap());
+        assert_eq!(flag_table_bytes.len() as u32, header.file_size);
+    }
+
     // this test point locks down that version number should be at the top of serialized
     // bytes
+    #[test]
     fn test_version_number() {
-        let flag_table = create_test_flag_table();
+        let flag_table = create_test_flag_table(DEFAULT_FILE_VERSION);
         let bytes = &flag_table.into_bytes();
         let mut head = 0;
-        let version = read_u32_from_bytes(bytes, &mut head).unwrap();
-        assert_eq!(version, 1);
+        let version_from_file = read_u32_from_bytes(bytes, &mut head).unwrap();
+        assert_eq!(version_from_file, DEFAULT_FILE_VERSION);
     }
 
-    #[test]
     // this test point locks down file type check
+    #[test]
     fn test_file_type_check() {
-        let mut flag_table = create_test_flag_table();
+        let mut flag_table = create_test_flag_table(DEFAULT_FILE_VERSION);
         flag_table.header.file_type = 123u8;
         let error = FlagTable::from_bytes(&flag_table.into_bytes()).unwrap_err();
         assert_eq!(
diff --git a/tools/aconfig/aconfig_storage_file/src/flag_value.rs b/tools/aconfig/aconfig_storage_file/src/flag_value.rs
index b64c10ecdd..9a14bec7de 100644
--- a/tools/aconfig/aconfig_storage_file/src/flag_value.rs
+++ b/tools/aconfig/aconfig_storage_file/src/flag_value.rs
@@ -132,12 +132,32 @@ impl FlagValueList {
 #[cfg(test)]
 mod tests {
     use super::*;
-    use crate::test_utils::create_test_flag_value_list;
+    use crate::{
+        test_utils::create_test_flag_value_list, DEFAULT_FILE_VERSION, MAX_SUPPORTED_FILE_VERSION,
+    };
 
     #[test]
     // this test point locks down the value list serialization
-    fn test_serialization() {
-        let flag_value_list = create_test_flag_value_list();
+    // TODO: b/376108268 - Use parameterized tests.
+    fn test_serialization_default() {
+        let flag_value_list = create_test_flag_value_list(DEFAULT_FILE_VERSION);
+
+        let header: &FlagValueHeader = &flag_value_list.header;
+        let reinterpreted_header = FlagValueHeader::from_bytes(&header.into_bytes());
+        assert!(reinterpreted_header.is_ok());
+        assert_eq!(header, &reinterpreted_header.unwrap());
+
+        let flag_value_bytes = flag_value_list.into_bytes();
+        let reinterpreted_value_list = FlagValueList::from_bytes(&flag_value_bytes);
+        assert!(reinterpreted_value_list.is_ok());
+        assert_eq!(&flag_value_list, &reinterpreted_value_list.unwrap());
+        assert_eq!(flag_value_bytes.len() as u32, header.file_size);
+    }
+
+    #[test]
+    // this test point locks down the value list serialization
+    fn test_serialization_max() {
+        let flag_value_list = create_test_flag_value_list(MAX_SUPPORTED_FILE_VERSION);
 
         let header: &FlagValueHeader = &flag_value_list.header;
         let reinterpreted_header = FlagValueHeader::from_bytes(&header.into_bytes());
@@ -155,17 +175,17 @@ mod tests {
     // this test point locks down that version number should be at the top of serialized
     // bytes
     fn test_version_number() {
-        let flag_value_list = create_test_flag_value_list();
+        let flag_value_list = create_test_flag_value_list(DEFAULT_FILE_VERSION);
         let bytes = &flag_value_list.into_bytes();
         let mut head = 0;
-        let version = read_u32_from_bytes(bytes, &mut head).unwrap();
-        assert_eq!(version, 1);
+        let version_from_file = read_u32_from_bytes(bytes, &mut head).unwrap();
+        assert_eq!(version_from_file, DEFAULT_FILE_VERSION);
     }
 
     #[test]
     // this test point locks down file type check
     fn test_file_type_check() {
-        let mut flag_value_list = create_test_flag_value_list();
+        let mut flag_value_list = create_test_flag_value_list(DEFAULT_FILE_VERSION);
         flag_value_list.header.file_type = 123u8;
         let error = FlagValueList::from_bytes(&flag_value_list.into_bytes()).unwrap_err();
         assert_eq!(
diff --git a/tools/aconfig/aconfig_storage_file/src/lib.rs b/tools/aconfig/aconfig_storage_file/src/lib.rs
index cf52bc017d..e99132092d 100644
--- a/tools/aconfig/aconfig_storage_file/src/lib.rs
+++ b/tools/aconfig/aconfig_storage_file/src/lib.rs
@@ -57,8 +57,13 @@ use crate::AconfigStorageError::{
     BytesParseFail, HashTableSizeLimit, InvalidFlagValueType, InvalidStoredFlagType,
 };
 
-/// Storage file version
-pub const FILE_VERSION: u32 = 1;
+/// The max storage file version from which we can safely read/write. May be
+/// experimental.
+pub const MAX_SUPPORTED_FILE_VERSION: u32 = 2;
+
+/// The newest fully-released version. Unless otherwise specified, this is the
+/// version we will write.
+pub const DEFAULT_FILE_VERSION: u32 = 1;
 
 /// Good hash table prime number
 pub(crate) const HASH_PRIMES: [u32; 29] = [
@@ -244,6 +249,11 @@ pub(crate) fn read_u16_from_bytes(
     Ok(val)
 }
 
+/// Read and parse the first 4 bytes of buf as u32.
+pub fn read_u32_from_start_of_bytes(buf: &[u8]) -> Result<u32, AconfigStorageError> {
+    read_u32_from_bytes(buf, &mut 0)
+}
+
 /// Read and parse bytes as u32
 pub fn read_u32_from_bytes(buf: &[u8], head: &mut usize) -> Result<u32, AconfigStorageError> {
     let val =
@@ -254,6 +264,16 @@ pub fn read_u32_from_bytes(buf: &[u8], head: &mut usize) -> Result<u32, AconfigS
     Ok(val)
 }
 
+// Read and parse bytes as u64
+pub fn read_u64_from_bytes(buf: &[u8], head: &mut usize) -> Result<u64, AconfigStorageError> {
+    let val =
+        u64::from_le_bytes(buf[*head..*head + 8].try_into().map_err(|errmsg| {
+            BytesParseFail(anyhow!("fail to parse u64 from bytes: {}", errmsg))
+        })?);
+    *head += 8;
+    Ok(val)
+}
+
 /// Read and parse bytes as string
 pub(crate) fn read_str_from_bytes(
     buf: &[u8],
@@ -516,10 +536,15 @@ mod tests {
     // this test point locks down the flag list api
     fn test_list_flag() {
         let package_table =
-            write_bytes_to_temp_file(&create_test_package_table().into_bytes()).unwrap();
-        let flag_table = write_bytes_to_temp_file(&create_test_flag_table().into_bytes()).unwrap();
-        let flag_value_list =
-            write_bytes_to_temp_file(&create_test_flag_value_list().into_bytes()).unwrap();
+            write_bytes_to_temp_file(&create_test_package_table(DEFAULT_FILE_VERSION).into_bytes())
+                .unwrap();
+        let flag_table =
+            write_bytes_to_temp_file(&create_test_flag_table(DEFAULT_FILE_VERSION).into_bytes())
+                .unwrap();
+        let flag_value_list = write_bytes_to_temp_file(
+            &create_test_flag_value_list(DEFAULT_FILE_VERSION).into_bytes(),
+        )
+        .unwrap();
 
         let package_table_path = package_table.path().display().to_string();
         let flag_table_path = flag_table.path().display().to_string();
@@ -584,12 +609,19 @@ mod tests {
     // this test point locks down the flag list with info api
     fn test_list_flag_with_info() {
         let package_table =
-            write_bytes_to_temp_file(&create_test_package_table().into_bytes()).unwrap();
-        let flag_table = write_bytes_to_temp_file(&create_test_flag_table().into_bytes()).unwrap();
-        let flag_value_list =
-            write_bytes_to_temp_file(&create_test_flag_value_list().into_bytes()).unwrap();
-        let flag_info_list =
-            write_bytes_to_temp_file(&create_test_flag_info_list().into_bytes()).unwrap();
+            write_bytes_to_temp_file(&create_test_package_table(DEFAULT_FILE_VERSION).into_bytes())
+                .unwrap();
+        let flag_table =
+            write_bytes_to_temp_file(&create_test_flag_table(DEFAULT_FILE_VERSION).into_bytes())
+                .unwrap();
+        let flag_value_list = write_bytes_to_temp_file(
+            &create_test_flag_value_list(DEFAULT_FILE_VERSION).into_bytes(),
+        )
+        .unwrap();
+        let flag_info_list = write_bytes_to_temp_file(
+            &create_test_flag_info_list(DEFAULT_FILE_VERSION).into_bytes(),
+        )
+        .unwrap();
 
         let package_table_path = package_table.path().display().to_string();
         let flag_table_path = flag_table.path().display().to_string();
diff --git a/tools/aconfig/aconfig_storage_file/src/package_table.rs b/tools/aconfig/aconfig_storage_file/src/package_table.rs
index a5bd9e6446..21357c7e4a 100644
--- a/tools/aconfig/aconfig_storage_file/src/package_table.rs
+++ b/tools/aconfig/aconfig_storage_file/src/package_table.rs
@@ -17,7 +17,10 @@
 //! package table module defines the package table file format and methods for serialization
 //! and deserialization
 
-use crate::{get_bucket_index, read_str_from_bytes, read_u32_from_bytes, read_u8_from_bytes};
+use crate::{
+    get_bucket_index, read_str_from_bytes, read_u32_from_bytes, read_u64_from_bytes,
+    read_u8_from_bytes,
+};
 use crate::{AconfigStorageError, StorageFileType};
 use anyhow::anyhow;
 use serde::{Deserialize, Serialize};
@@ -97,6 +100,7 @@ impl PackageTableHeader {
 pub struct PackageTableNode {
     pub package_name: String,
     pub package_id: u32,
+    pub fingerprint: u64,
     // The index of the first boolean flag in this aconfig package among all boolean
     // flags in this container.
     pub boolean_start_index: u32,
@@ -108,8 +112,12 @@ impl fmt::Debug for PackageTableNode {
     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
         writeln!(
             f,
-            "Package: {}, Id: {}, Boolean flag start index: {}, Next: {:?}",
-            self.package_name, self.package_id, self.boolean_start_index, self.next_offset
+            "Package: {}, Id: {}, Fingerprint: {}, Boolean flag start index: {}, Next: {:?}",
+            self.package_name,
+            self.package_id,
+            self.fingerprint,
+            self.boolean_start_index,
+            self.next_offset
         )?;
         Ok(())
     }
@@ -117,7 +125,16 @@ impl fmt::Debug for PackageTableNode {
 
 impl PackageTableNode {
     /// Serialize to bytes
-    pub fn into_bytes(&self) -> Vec<u8> {
+    pub fn into_bytes(&self, version: u32) -> Vec<u8> {
+        match version {
+            1 => Self::into_bytes_v1(self),
+            2 => Self::into_bytes_v2(self),
+            // TODO(b/316357686): into_bytes should return a Result.
+            _ => Self::into_bytes_v2(&self),
+        }
+    }
+
+    fn into_bytes_v1(&self) -> Vec<u8> {
         let mut result = Vec::new();
         let name_bytes = self.package_name.as_bytes();
         result.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
@@ -128,18 +145,60 @@ impl PackageTableNode {
         result
     }
 
-    /// Deserialize from bytes
-    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AconfigStorageError> {
+    fn into_bytes_v2(&self) -> Vec<u8> {
+        let mut result = Vec::new();
+        let name_bytes = self.package_name.as_bytes();
+        result.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
+        result.extend_from_slice(name_bytes);
+        result.extend_from_slice(&self.package_id.to_le_bytes());
+        result.extend_from_slice(&self.fingerprint.to_le_bytes());
+        result.extend_from_slice(&self.boolean_start_index.to_le_bytes());
+        result.extend_from_slice(&self.next_offset.unwrap_or(0).to_le_bytes());
+        result
+    }
+
+    /// Deserialize from bytes based on file version.
+    pub fn from_bytes(bytes: &[u8], version: u32) -> Result<Self, AconfigStorageError> {
+        match version {
+            1 => Self::from_bytes_v1(bytes),
+            2 => Self::from_bytes_v2(bytes),
+            _ => {
+                return Err(AconfigStorageError::BytesParseFail(anyhow!(
+                    "Binary file is an unsupported version: {}",
+                    version
+                )))
+            }
+        }
+    }
+
+    fn from_bytes_v1(bytes: &[u8]) -> Result<Self, AconfigStorageError> {
         let mut head = 0;
-        let node = Self {
-            package_name: read_str_from_bytes(bytes, &mut head)?,
-            package_id: read_u32_from_bytes(bytes, &mut head)?,
-            boolean_start_index: read_u32_from_bytes(bytes, &mut head)?,
-            next_offset: match read_u32_from_bytes(bytes, &mut head)? {
-                0 => None,
-                val => Some(val),
-            },
+        let package_name = read_str_from_bytes(bytes, &mut head)?;
+        let package_id = read_u32_from_bytes(bytes, &mut head)?;
+        // v1 does not have fingerprint, so just set to 0.
+        let fingerprint: u64 = 0;
+        let boolean_start_index = read_u32_from_bytes(bytes, &mut head)?;
+        let next_offset = match read_u32_from_bytes(bytes, &mut head)? {
+            0 => None,
+            val => Some(val),
+        };
+
+        let node = Self { package_name, package_id, fingerprint, boolean_start_index, next_offset };
+        Ok(node)
+    }
+
+    fn from_bytes_v2(bytes: &[u8]) -> Result<Self, AconfigStorageError> {
+        let mut head = 0;
+        let package_name = read_str_from_bytes(bytes, &mut head)?;
+        let package_id = read_u32_from_bytes(bytes, &mut head)?;
+        let fingerprint = read_u64_from_bytes(bytes, &mut head)?;
+        let boolean_start_index = read_u32_from_bytes(bytes, &mut head)?;
+        let next_offset = match read_u32_from_bytes(bytes, &mut head)? {
+            0 => None,
+            val => Some(val),
         };
+
+        let node = Self { package_name, package_id, fingerprint, boolean_start_index, next_offset };
         Ok(node)
     }
 
@@ -180,7 +239,11 @@ impl PackageTable {
         [
             self.header.into_bytes(),
             self.buckets.iter().map(|v| v.unwrap_or(0).to_le_bytes()).collect::<Vec<_>>().concat(),
-            self.nodes.iter().map(|v| v.into_bytes()).collect::<Vec<_>>().concat(),
+            self.nodes
+                .iter()
+                .map(|v| v.into_bytes(self.header.version))
+                .collect::<Vec<_>>()
+                .concat(),
         ]
         .concat()
     }
@@ -199,8 +262,8 @@ impl PackageTable {
             .collect();
         let nodes = (0..num_packages)
             .map(|_| {
-                let node = PackageTableNode::from_bytes(&bytes[head..])?;
-                head += node.into_bytes().len();
+                let node = PackageTableNode::from_bytes(&bytes[head..], header.version)?;
+                head += node.into_bytes(header.version).len();
                 Ok(node)
             })
             .collect::<Result<Vec<_>, AconfigStorageError>>()
@@ -220,11 +283,13 @@ impl PackageTable {
 mod tests {
     use super::*;
     use crate::test_utils::create_test_package_table;
+    use crate::{read_u32_from_start_of_bytes, DEFAULT_FILE_VERSION, MAX_SUPPORTED_FILE_VERSION};
 
     #[test]
     // this test point locks down the table serialization
-    fn test_serialization() {
-        let package_table = create_test_package_table();
+    // TODO: b/376108268 - Use parameterized tests.
+    fn test_serialization_default() {
+        let package_table = create_test_package_table(DEFAULT_FILE_VERSION);
         let header: &PackageTableHeader = &package_table.header;
         let reinterpreted_header = PackageTableHeader::from_bytes(&header.into_bytes());
         assert!(reinterpreted_header.is_ok());
@@ -232,7 +297,32 @@ mod tests {
 
         let nodes: &Vec<PackageTableNode> = &package_table.nodes;
         for node in nodes.iter() {
-            let reinterpreted_node = PackageTableNode::from_bytes(&node.into_bytes()).unwrap();
+            let reinterpreted_node =
+                PackageTableNode::from_bytes(&node.into_bytes(header.version), header.version)
+                    .unwrap();
+            assert_eq!(node, &reinterpreted_node);
+        }
+
+        let package_table_bytes = package_table.into_bytes();
+        let reinterpreted_table = PackageTable::from_bytes(&package_table_bytes);
+        assert!(reinterpreted_table.is_ok());
+        assert_eq!(&package_table, &reinterpreted_table.unwrap());
+        assert_eq!(package_table_bytes.len() as u32, header.file_size);
+    }
+
+    #[test]
+    fn test_serialization_max() {
+        let package_table = create_test_package_table(MAX_SUPPORTED_FILE_VERSION);
+        let header: &PackageTableHeader = &package_table.header;
+        let reinterpreted_header = PackageTableHeader::from_bytes(&header.into_bytes());
+        assert!(reinterpreted_header.is_ok());
+        assert_eq!(header, &reinterpreted_header.unwrap());
+
+        let nodes: &Vec<PackageTableNode> = &package_table.nodes;
+        for node in nodes.iter() {
+            let reinterpreted_node =
+                PackageTableNode::from_bytes(&node.into_bytes(header.version), header.version)
+                    .unwrap();
             assert_eq!(node, &reinterpreted_node);
         }
 
@@ -247,17 +337,36 @@ mod tests {
     // this test point locks down that version number should be at the top of serialized
     // bytes
     fn test_version_number() {
-        let package_table = create_test_package_table();
+        let package_table = create_test_package_table(DEFAULT_FILE_VERSION);
         let bytes = &package_table.into_bytes();
-        let mut head = 0;
-        let version = read_u32_from_bytes(bytes, &mut head).unwrap();
-        assert_eq!(version, 1);
+        let unpacked_version = read_u32_from_start_of_bytes(bytes).unwrap();
+        assert_eq!(unpacked_version, DEFAULT_FILE_VERSION);
+    }
+
+    #[test]
+    fn test_round_trip_default() {
+        let table: PackageTable = create_test_package_table(DEFAULT_FILE_VERSION);
+        let table_bytes = table.into_bytes();
+
+        let reinterpreted_table = PackageTable::from_bytes(&table_bytes).unwrap();
+
+        assert_eq!(table, reinterpreted_table);
+    }
+
+    #[test]
+    fn test_round_trip_max() {
+        let table: PackageTable = create_test_package_table(MAX_SUPPORTED_FILE_VERSION);
+        let table_bytes = table.into_bytes();
+
+        let reinterpreted_table = PackageTable::from_bytes(&table_bytes).unwrap();
+
+        assert_eq!(table, reinterpreted_table);
     }
 
     #[test]
     // this test point locks down file type check
     fn test_file_type_check() {
-        let mut package_table = create_test_package_table();
+        let mut package_table = create_test_package_table(DEFAULT_FILE_VERSION);
         package_table.header.file_type = 123u8;
         let error = PackageTable::from_bytes(&package_table.into_bytes()).unwrap_err();
         assert_eq!(
diff --git a/tools/aconfig/aconfig_storage_file/src/test_utils.rs b/tools/aconfig/aconfig_storage_file/src/test_utils.rs
index 106666c47f..7c603df40e 100644
--- a/tools/aconfig/aconfig_storage_file/src/test_utils.rs
+++ b/tools/aconfig/aconfig_storage_file/src/test_utils.rs
@@ -24,32 +24,59 @@ use anyhow::anyhow;
 use std::io::Write;
 use tempfile::NamedTempFile;
 
-pub fn create_test_package_table() -> PackageTable {
+pub fn create_test_package_table(version: u32) -> PackageTable {
     let header = PackageTableHeader {
-        version: 1,
+        version: version,
         container: String::from("mockup"),
         file_type: StorageFileType::PackageMap as u8,
-        file_size: 209,
+        file_size: match version {
+            1 => 209,
+            2 => 233,
+            _ => panic!("Unsupported version."),
+        },
         num_packages: 3,
         bucket_offset: 31,
         node_offset: 59,
     };
-    let buckets: Vec<Option<u32>> = vec![Some(59), None, None, Some(109), None, None, None];
+    let buckets: Vec<Option<u32>> = match version {
+        1 => vec![Some(59), None, None, Some(109), None, None, None],
+        2 => vec![Some(59), None, None, Some(117), None, None, None],
+        _ => panic!("Unsupported version."),
+    };
     let first_node = PackageTableNode {
         package_name: String::from("com.android.aconfig.storage.test_2"),
         package_id: 1,
+        fingerprint: match version {
+            1 => 0,
+            2 => 4431940502274857964u64,
+            _ => panic!("Unsupported version."),
+        },
         boolean_start_index: 3,
         next_offset: None,
     };
     let second_node = PackageTableNode {
         package_name: String::from("com.android.aconfig.storage.test_1"),
         package_id: 0,
+        fingerprint: match version {
+            1 => 0,
+            2 => 15248948510590158086u64,
+            _ => panic!("Unsupported version."),
+        },
         boolean_start_index: 0,
-        next_offset: Some(159),
+        next_offset: match version {
+            1 => Some(159),
+            2 => Some(175),
+            _ => panic!("Unsupported version."),
+        },
     };
     let third_node = PackageTableNode {
         package_name: String::from("com.android.aconfig.storage.test_4"),
         package_id: 2,
+        fingerprint: match version {
+            1 => 0,
+            2 => 16233229917711622375u64,
+            _ => panic!("Unsupported version."),
+        },
         boolean_start_index: 6,
         next_offset: None,
     };
@@ -76,9 +103,9 @@ impl FlagTableNode {
     }
 }
 
-pub fn create_test_flag_table() -> FlagTable {
+pub fn create_test_flag_table(version: u32) -> FlagTable {
     let header = FlagTableHeader {
-        version: 1,
+        version: version,
         container: String::from("mockup"),
         file_type: StorageFileType::FlagMap as u8,
         file_size: 321,
@@ -118,9 +145,9 @@ pub fn create_test_flag_table() -> FlagTable {
     FlagTable { header, buckets, nodes }
 }
 
-pub fn create_test_flag_value_list() -> FlagValueList {
+pub fn create_test_flag_value_list(version: u32) -> FlagValueList {
     let header = FlagValueHeader {
-        version: 1,
+        version: version,
         container: String::from("mockup"),
         file_type: StorageFileType::FlagVal as u8,
         file_size: 35,
@@ -131,9 +158,9 @@ pub fn create_test_flag_value_list() -> FlagValueList {
     FlagValueList { header, booleans }
 }
 
-pub fn create_test_flag_info_list() -> FlagInfoList {
+pub fn create_test_flag_info_list(version: u32) -> FlagInfoList {
     let header = FlagInfoHeader {
-        version: 1,
+        version: version,
         container: String::from("mockup"),
         file_type: StorageFileType::FlagInfo as u8,
         file_size: 35,
diff --git a/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/AconfigStorageException.java b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/AconfigStorageException.java
index 86a75f2f65..324c55d57d 100644
--- a/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/AconfigStorageException.java
+++ b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/AconfigStorageException.java
@@ -16,12 +16,122 @@
 
 package android.aconfig.storage;
 
+/**
+ * Exception thrown when an error occurs while accessing Aconfig Storage.
+ *
+ * <p>This exception indicates a general problem with Aconfig Storage, such as an inability to read
+ * or write data.
+ */
 public class AconfigStorageException extends RuntimeException {
+
+    /** Generic error code indicating an unspecified Aconfig Storage error. */
+    public static final int ERROR_GENERIC = 0;
+
+    /** Error code indicating that the Aconfig Storage system is not found on the device. */
+    public static final int ERROR_STORAGE_SYSTEM_NOT_FOUND = 1;
+
+    /** Error code indicating that the requested configuration package is not found. */
+    public static final int ERROR_PACKAGE_NOT_FOUND = 2;
+
+    /** Error code indicating that the specified container is not found. */
+    public static final int ERROR_CONTAINER_NOT_FOUND = 3;
+
+    /** Error code indicating that there was an error reading the Aconfig Storage file. */
+    public static final int ERROR_CANNOT_READ_STORAGE_FILE = 4;
+
+    public static final int ERROR_FILE_FINGERPRINT_MISMATCH = 5;
+
+    private final int mErrorCode;
+
+    /**
+     * Constructs a new {@code AconfigStorageException} with a generic error code and the specified
+     * detail message.
+     *
+     * @param msg The detail message for this exception.
+     */
     public AconfigStorageException(String msg) {
         super(msg);
+        mErrorCode = ERROR_GENERIC;
     }
 
+    /**
+     * Constructs a new {@code AconfigStorageException} with a generic error code, the specified
+     * detail message, and cause.
+     *
+     * @param msg The detail message for this exception.
+     * @param cause The cause of this exception.
+     */
     public AconfigStorageException(String msg, Throwable cause) {
         super(msg, cause);
+        mErrorCode = ERROR_GENERIC;
+    }
+
+    /**
+     * Constructs a new {@code AconfigStorageException} with the specified error code and detail
+     * message.
+     *
+     * @param errorCode The error code for this exception.
+     * @param msg The detail message for this exception.
+     */
+    public AconfigStorageException(int errorCode, String msg) {
+        super(msg);
+        mErrorCode = errorCode;
+    }
+
+    /**
+     * Constructs a new {@code AconfigStorageException} with the specified error code, detail
+     * message, and cause.
+     *
+     * @param errorCode The error code for this exception.
+     * @param msg The detail message for this exception.
+     * @param cause The cause of this exception.
+     */
+    public AconfigStorageException(int errorCode, String msg, Throwable cause) {
+        super(msg, cause);
+        mErrorCode = errorCode;
+    }
+
+    /**
+     * Returns the error code associated with this exception.
+     *
+     * @return The error code.
+     */
+    public int getErrorCode() {
+        return mErrorCode;
+    }
+
+    /**
+     * Returns the error message for this exception, including the error code and the original
+     * message.
+     *
+     * @return The error message.
+     */
+    @Override
+    public String getMessage() {
+        return errorString() + ": " + super.getMessage();
+    }
+
+    /**
+     * Returns a string representation of the error code.
+     *
+     * @return The error code string.
+     */
+    private String errorString() {
+        switch (mErrorCode) {
+            case ERROR_GENERIC:
+                return "ERROR_GENERIC";
+            case ERROR_STORAGE_SYSTEM_NOT_FOUND:
+                return "ERROR_STORAGE_SYSTEM_NOT_FOUND";
+            case ERROR_PACKAGE_NOT_FOUND:
+                return "ERROR_PACKAGE_NOT_FOUND";
+            case ERROR_CONTAINER_NOT_FOUND:
+                return "ERROR_CONTAINER_NOT_FOUND";
+            case ERROR_CANNOT_READ_STORAGE_FILE:
+                return "ERROR_CANNOT_READ_STORAGE_FILE";
+            case ERROR_FILE_FINGERPRINT_MISMATCH:
+                return "ERROR_FILE_FINGERPRINT_MISMATCH";
+            default:
+                return "<Unknown error code " + mErrorCode + ">";
+        }
     }
 }
diff --git a/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/ByteBufferReader.java b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/ByteBufferReader.java
index 4bea0836f0..957156876d 100644
--- a/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/ByteBufferReader.java
+++ b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/ByteBufferReader.java
@@ -41,8 +41,16 @@ public class ByteBufferReader {
         return this.mByteBuffer.getInt();
     }
 
+    public long readLong() {
+        return this.mByteBuffer.getLong();
+    }
+
     public String readString() {
         int length = readInt();
+        if (length > 1024) {
+            throw new AconfigStorageException(
+                    "String length exceeds maximum allowed size (1024 bytes): " + length);
+        }
         byte[] bytes = new byte[length];
         mByteBuffer.get(bytes, 0, length);
         return new String(bytes, StandardCharsets.UTF_8);
diff --git a/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/FileType.java b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/FileType.java
index b0b1b9b186..c35487358d 100644
--- a/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/FileType.java
+++ b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/FileType.java
@@ -42,4 +42,20 @@ public enum FileType {
                 return null;
         }
     }
+
+    @Override
+    public String toString() {
+        switch (type) {
+            case 0:
+                return "PACKAGE_MAP";
+            case 1:
+                return "FLAG_MAP";
+            case 2:
+                return "FLAG_VAL";
+            case 3:
+                return "FLAG_INFO";
+            default:
+                return "unrecognized type";
+        }
+    }
 }
diff --git a/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/FlagTable.java b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/FlagTable.java
index 9838a7c780..757844a603 100644
--- a/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/FlagTable.java
+++ b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/FlagTable.java
@@ -37,9 +37,16 @@ public class FlagTable {
     public Node get(int packageId, String flagName) {
         int numBuckets = (mHeader.mNodeOffset - mHeader.mBucketOffset) / 4;
         int bucketIndex = TableUtils.getBucketIndex(makeKey(packageId, flagName), numBuckets);
+        int newPosition = mHeader.mBucketOffset + bucketIndex * 4;
+        if (newPosition >= mHeader.mNodeOffset) {
+            return null;
+        }
 
-        mReader.position(mHeader.mBucketOffset + bucketIndex * 4);
+        mReader.position(newPosition);
         int nodeIndex = mReader.readInt();
+        if (nodeIndex < mHeader.mNodeOffset || nodeIndex >= mHeader.mFileSize) {
+            return null;
+        }
 
         while (nodeIndex != -1) {
             mReader.position(nodeIndex);
@@ -50,7 +57,7 @@ public class FlagTable {
             nodeIndex = node.mNextOffset;
         }
 
-        throw new AconfigStorageException("get cannot find flag: " + flagName);
+        return null;
     }
 
     public Header getHeader() {
diff --git a/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/PackageTable.java b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/PackageTable.java
index 773b882f4a..a45d12a0b3 100644
--- a/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/PackageTable.java
+++ b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/PackageTable.java
@@ -35,23 +35,29 @@ public class PackageTable {
     }
 
     public Node get(String packageName) {
-
         int numBuckets = (mHeader.mNodeOffset - mHeader.mBucketOffset) / 4;
         int bucketIndex = TableUtils.getBucketIndex(packageName.getBytes(UTF_8), numBuckets);
-
-        mReader.position(mHeader.mBucketOffset + bucketIndex * 4);
+        int newPosition = mHeader.mBucketOffset + bucketIndex * 4;
+        if (newPosition >= mHeader.mNodeOffset) {
+            return null;
+        }
+        mReader.position(newPosition);
         int nodeIndex = mReader.readInt();
 
+        if (nodeIndex < mHeader.mNodeOffset || nodeIndex >= mHeader.mFileSize) {
+            return null;
+        }
+
         while (nodeIndex != -1) {
             mReader.position(nodeIndex);
-            Node node = Node.fromBytes(mReader);
+            Node node = Node.fromBytes(mReader, mHeader.mVersion);
             if (Objects.equals(packageName, node.mPackageName)) {
                 return node;
             }
             nodeIndex = node.mNextOffset;
         }
 
-        throw new AconfigStorageException("get cannot find package: " + packageName);
+        return null;
     }
 
     public Header getHeader() {
@@ -68,7 +74,7 @@ public class PackageTable {
         private int mBucketOffset;
         private int mNodeOffset;
 
-        public static Header fromBytes(ByteBufferReader reader) {
+        private static Header fromBytes(ByteBufferReader reader) {
             Header header = new Header();
             header.mVersion = reader.readInt();
             header.mContainer = reader.readString();
@@ -118,16 +124,42 @@ public class PackageTable {
 
         private String mPackageName;
         private int mPackageId;
+        private long mPackageFingerprint;
         private int mBooleanStartIndex;
         private int mNextOffset;
+        private boolean mHasPackageFingerprint;
+
+        private static Node fromBytes(ByteBufferReader reader, int version) {
+            switch (version) {
+                case 1:
+                    return fromBytesV1(reader);
+                case 2:
+                    return fromBytesV2(reader);
+                default:
+                    // Do we want to throw here?
+                    return new Node();
+            }
+        }
+
+        private static Node fromBytesV1(ByteBufferReader reader) {
+            Node node = new Node();
+            node.mPackageName = reader.readString();
+            node.mPackageId = reader.readInt();
+            node.mBooleanStartIndex = reader.readInt();
+            node.mNextOffset = reader.readInt();
+            node.mNextOffset = node.mNextOffset == 0 ? -1 : node.mNextOffset;
+            return node;
+        }
 
-        public static Node fromBytes(ByteBufferReader reader) {
+        private static Node fromBytesV2(ByteBufferReader reader) {
             Node node = new Node();
             node.mPackageName = reader.readString();
             node.mPackageId = reader.readInt();
+            node.mPackageFingerprint = reader.readLong();
             node.mBooleanStartIndex = reader.readInt();
             node.mNextOffset = reader.readInt();
             node.mNextOffset = node.mNextOffset == 0 ? -1 : node.mNextOffset;
+            node.mHasPackageFingerprint = true;
             return node;
         }
 
@@ -161,6 +193,10 @@ public class PackageTable {
             return mPackageId;
         }
 
+        public long getPackageFingerprint() {
+            return mPackageFingerprint;
+        }
+
         public int getBooleanStartIndex() {
             return mBooleanStartIndex;
         }
@@ -168,5 +204,9 @@ public class PackageTable {
         public int getNextOffset() {
             return mNextOffset;
         }
+
+        public boolean hasPackageFingerprint() {
+            return mHasPackageFingerprint;
+        }
     }
 }
diff --git a/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/StorageFileProvider.java b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/StorageFileProvider.java
new file mode 100644
index 0000000000..f1a4e269a0
--- /dev/null
+++ b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/StorageFileProvider.java
@@ -0,0 +1,130 @@
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
+package android.aconfig.storage;
+
+import java.io.Closeable;
+import java.nio.MappedByteBuffer;
+import java.nio.channels.FileChannel;
+import java.nio.file.DirectoryStream;
+import java.nio.file.Files;
+import java.nio.file.NoSuchFileException;
+import java.nio.file.Path;
+import java.nio.file.Paths;
+import java.nio.file.StandardOpenOption;
+import java.util.ArrayList;
+import java.util.Arrays;
+import java.util.HashSet;
+import java.util.List;
+import java.util.Set;
+
+/** @hide */
+public class StorageFileProvider {
+
+    private static final String DEFAULT_MAP_PATH = "/metadata/aconfig/maps/";
+    private static final String DEFAULT_BOOT_PATH = "/metadata/aconfig/boot/";
+    private static final String PMAP_FILE_EXT = ".package.map";
+    private static final String FMAP_FILE_EXT = ".flag.map";
+    private static final String VAL_FILE_EXT = ".val";
+
+    private final String mMapPath;
+    private final String mBootPath;
+
+    /** @hide */
+    public static StorageFileProvider getDefaultProvider() {
+        return new StorageFileProvider(DEFAULT_MAP_PATH, DEFAULT_BOOT_PATH);
+    }
+
+    /** @hide */
+    public StorageFileProvider(String mapPath, String bootPath) {
+        mMapPath = mapPath;
+        mBootPath = bootPath;
+    }
+
+    /** @hide */
+    public List<String> listContainers(String[] excludes) {
+        List<String> result = new ArrayList<>();
+        Set<String> set = new HashSet<>(Arrays.asList(excludes));
+
+        try {
+            DirectoryStream<Path> stream =
+                    Files.newDirectoryStream(Paths.get(mMapPath), "*" + PMAP_FILE_EXT);
+            for (Path entry : stream) {
+                String fileName = entry.getFileName().toString();
+                String container =
+                        fileName.substring(0, fileName.length() - PMAP_FILE_EXT.length());
+                if (!set.contains(container)) {
+                    result.add(container);
+                }
+            }
+        } catch (NoSuchFileException e) {
+            return result;
+        } catch (Exception e) {
+            throw new AconfigStorageException(
+                    String.format("Fail to list map files in path %s", mMapPath), e);
+        }
+
+        return result;
+    }
+
+    /** @hide */
+    public PackageTable getPackageTable(String container) {
+        return getPackageTable(Paths.get(mMapPath, container + PMAP_FILE_EXT));
+    }
+
+    /** @hide */
+    public FlagTable getFlagTable(String container) {
+        return FlagTable.fromBytes(
+                mapStorageFile(Paths.get(mMapPath, container + FMAP_FILE_EXT), FileType.FLAG_MAP));
+    }
+
+    /** @hide */
+    public FlagValueList getFlagValueList(String container) {
+        return FlagValueList.fromBytes(
+                mapStorageFile(Paths.get(mBootPath, container + VAL_FILE_EXT), FileType.FLAG_VAL));
+    }
+
+    /** @hide */
+    public static PackageTable getPackageTable(Path path) {
+        return PackageTable.fromBytes(mapStorageFile(path, FileType.PACKAGE_MAP));
+    }
+
+    // Map a storage file given file path
+    private static MappedByteBuffer mapStorageFile(Path file, FileType type) {
+        FileChannel channel = null;
+        try {
+            channel = FileChannel.open(file, StandardOpenOption.READ);
+            return channel.map(FileChannel.MapMode.READ_ONLY, 0, channel.size());
+        } catch (Exception e) {
+            throw new AconfigStorageException(
+                    AconfigStorageException.ERROR_CANNOT_READ_STORAGE_FILE,
+                    String.format("Fail to mmap storage %s file %s", type.toString(), file),
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
diff --git a/tools/aconfig/aconfig_storage_file/tests/Android.bp b/tools/aconfig/aconfig_storage_file/tests/Android.bp
index 12e4acad1b..bd46d5f0ab 100644
--- a/tools/aconfig/aconfig_storage_file/tests/Android.bp
+++ b/tools/aconfig/aconfig_storage_file/tests/Android.bp
@@ -10,10 +10,14 @@ cc_test {
         "libbase",
     ],
     data: [
-        "package.map",
-        "flag.map",
-        "flag.val",
-        "flag.info",
+        "data/v1/package_v1.map",
+        "data/v1/flag_v1.map",
+        "data/v1/flag_v1.val",
+        "data/v1/flag_v1.info",
+        "data/v2/package_v2.map",
+        "data/v2/flag_v2.map",
+        "data/v2/flag_v2.val",
+        "data/v2/flag_v2.info",
     ],
     test_suites: [
         "device-tests",
@@ -35,10 +39,14 @@ android_test {
     test_config: "AndroidStorageJaveTest.xml",
     sdk_version: "test_current",
     data: [
-        "package.map",
-        "flag.map",
-        "flag.val",
-        "flag.info",
+        "data/v1/package_v1.map",
+        "data/v1/flag_v1.map",
+        "data/v1/flag_v1.val",
+        "data/v1/flag_v1.info",
+        "data/v2/package_v2.map",
+        "data/v2/flag_v2.map",
+        "data/v2/flag_v2.val",
+        "data/v2/flag_v2.info",
     ],
     test_suites: [
         "general-tests",
diff --git a/tools/aconfig/aconfig_storage_file/tests/AndroidStorageJaveTest.xml b/tools/aconfig/aconfig_storage_file/tests/AndroidStorageJaveTest.xml
index 2d52d44c57..bfc238e320 100644
--- a/tools/aconfig/aconfig_storage_file/tests/AndroidStorageJaveTest.xml
+++ b/tools/aconfig/aconfig_storage_file/tests/AndroidStorageJaveTest.xml
@@ -21,13 +21,18 @@
     </target_preparer>
     <target_preparer class="com.android.compatibility.common.tradefed.targetprep.FilePusher">
         <option name="cleanup" value="true" />
-        <option name="push" value="package.map->/data/local/tmp/aconfig_storage_file_test_java/testdata/package.map" />
-        <option name="push" value="flag.map->/data/local/tmp/aconfig_storage_file_test_java/testdata/flag.map" />
-        <option name="push" value="flag.val->/data/local/tmp/aconfig_storage_file_test_java/testdata/flag.val" />
-        <option name="push" value="flag.info->/data/local/tmp/aconfig_storage_file_test_java/testdata/flag.info" />
+        <option name="push" value="package_v1.map->/data/local/tmp/aconfig_storage_file_test_java/testdata/mock.v1.package.map" />
+        <option name="push" value="flag_v1.map->/data/local/tmp/aconfig_storage_file_test_java/testdata/mock.v1.flag.map" />
+        <option name="push" value="flag_v1.val->/data/local/tmp/aconfig_storage_file_test_java/testdata/mock.v1.val" />
+        <option name="push" value="flag_v1.info->/data/local/tmp/aconfig_storage_file_test_java/testdata/mock.v1.info" />
+        <option name="push" value="package_v2.map->/data/local/tmp/aconfig_storage_file_test_java/testdata/mock.v2.package.map" />
+        <option name="push" value="flag_v2.map->/data/local/tmp/aconfig_storage_file_test_java/testdata/mock.v2.flag.map" />
+        <option name="push" value="flag_v2.val->/data/local/tmp/aconfig_storage_file_test_java/testdata/mock.v2.val" />
+        <option name="push" value="flag_v2.info->/data/local/tmp/aconfig_storage_file_test_java/testdata/mock.v2.info" />
+        <option name="post-push" value="chmod +r /data/local/tmp/aconfig_storage_file_test_java/testdata/" />
     </target_preparer>
     <test class="com.android.tradefed.testtype.AndroidJUnitTest" >
         <option name="package" value="android.aconfig.storage.test" />
         <option name="runtime-hint" value="1m" />
     </test>
-</configuration>
\ No newline at end of file
+</configuration>
diff --git a/tools/aconfig/aconfig_storage_file/tests/flag.info b/tools/aconfig/aconfig_storage_file/tests/data/v1/flag_v1.info
similarity index 100%
rename from tools/aconfig/aconfig_storage_file/tests/flag.info
rename to tools/aconfig/aconfig_storage_file/tests/data/v1/flag_v1.info
diff --git a/tools/aconfig/aconfig_storage_file/tests/flag.map b/tools/aconfig/aconfig_storage_file/tests/data/v1/flag_v1.map
similarity index 100%
rename from tools/aconfig/aconfig_storage_file/tests/flag.map
rename to tools/aconfig/aconfig_storage_file/tests/data/v1/flag_v1.map
diff --git a/tools/aconfig/aconfig_storage_file/tests/flag.val b/tools/aconfig/aconfig_storage_file/tests/data/v1/flag_v1.val
similarity index 100%
rename from tools/aconfig/aconfig_storage_file/tests/flag.val
rename to tools/aconfig/aconfig_storage_file/tests/data/v1/flag_v1.val
diff --git a/tools/aconfig/aconfig_storage_file/tests/package.map b/tools/aconfig/aconfig_storage_file/tests/data/v1/package_v1.map
similarity index 100%
rename from tools/aconfig/aconfig_storage_file/tests/package.map
rename to tools/aconfig/aconfig_storage_file/tests/data/v1/package_v1.map
diff --git a/tools/aconfig/aconfig_storage_file/tests/data/v2/flag_v2.info b/tools/aconfig/aconfig_storage_file/tests/data/v2/flag_v2.info
new file mode 100644
index 0000000000..9db7fde7ae
Binary files /dev/null and b/tools/aconfig/aconfig_storage_file/tests/data/v2/flag_v2.info differ
diff --git a/tools/aconfig/aconfig_storage_file/tests/data/v2/flag_v2.map b/tools/aconfig/aconfig_storage_file/tests/data/v2/flag_v2.map
new file mode 100644
index 0000000000..cf4685ceb4
Binary files /dev/null and b/tools/aconfig/aconfig_storage_file/tests/data/v2/flag_v2.map differ
diff --git a/tools/aconfig/aconfig_storage_file/tests/data/v2/flag_v2.val b/tools/aconfig/aconfig_storage_file/tests/data/v2/flag_v2.val
new file mode 100644
index 0000000000..37d4750206
Binary files /dev/null and b/tools/aconfig/aconfig_storage_file/tests/data/v2/flag_v2.val differ
diff --git a/tools/aconfig/aconfig_storage_file/tests/data/v2/package_v2.map b/tools/aconfig/aconfig_storage_file/tests/data/v2/package_v2.map
new file mode 100644
index 0000000000..0a9f95ec85
Binary files /dev/null and b/tools/aconfig/aconfig_storage_file/tests/data/v2/package_v2.map differ
diff --git a/tools/aconfig/aconfig_storage_file/tests/jarjar.txt b/tools/aconfig/aconfig_storage_file/tests/jarjar.txt
index a6c17fa476..24952ecfdf 100644
--- a/tools/aconfig/aconfig_storage_file/tests/jarjar.txt
+++ b/tools/aconfig/aconfig_storage_file/tests/jarjar.txt
@@ -7,6 +7,8 @@ rule android.aconfig.storage.SipHasher13 android.aconfig.storage.test.SipHasher1
 rule android.aconfig.storage.FileType android.aconfig.storage.test.FileType
 rule android.aconfig.storage.FlagValueList android.aconfig.storage.test.FlagValueList
 rule android.aconfig.storage.TableUtils android.aconfig.storage.test.TableUtils
+rule android.aconfig.storage.AconfigPackageImpl android.aconfig.storage.test.AconfigPackageImpl
+rule android.aconfig.storage.StorageFileProvider android.aconfig.storage.test.StorageFileProvider
 
 
 rule android.aconfig.storage.FlagTable$* android.aconfig.storage.test.FlagTable$@1
diff --git a/tools/aconfig/aconfig_storage_file/tests/srcs/FlagTableTest.java b/tools/aconfig/aconfig_storage_file/tests/srcs/FlagTableTest.java
index fd40d4c4ef..dc465b658d 100644
--- a/tools/aconfig/aconfig_storage_file/tests/srcs/FlagTableTest.java
+++ b/tools/aconfig/aconfig_storage_file/tests/srcs/FlagTableTest.java
@@ -31,7 +31,7 @@ public class FlagTableTest {
 
     @Test
     public void testFlagTable_rightHeader() throws Exception {
-        FlagTable flagTable = FlagTable.fromBytes(TestDataUtils.getTestFlagMapByteBuffer());
+        FlagTable flagTable = FlagTable.fromBytes(TestDataUtils.getTestFlagMapByteBuffer(1));
         FlagTable.Header header = flagTable.getHeader();
         assertEquals(1, header.getVersion());
         assertEquals("mockup", header.getContainer());
@@ -44,7 +44,7 @@ public class FlagTableTest {
 
     @Test
     public void testFlagTable_rightNode() throws Exception {
-        FlagTable flagTable = FlagTable.fromBytes(TestDataUtils.getTestFlagMapByteBuffer());
+        FlagTable flagTable = FlagTable.fromBytes(TestDataUtils.getTestFlagMapByteBuffer(1));
 
         FlagTable.Node node1 = flagTable.get(0, "enabled_ro");
         FlagTable.Node node2 = flagTable.get(0, "enabled_rw");
diff --git a/tools/aconfig/aconfig_storage_file/tests/srcs/FlagValueListTest.java b/tools/aconfig/aconfig_storage_file/tests/srcs/FlagValueListTest.java
index 1b0de630c7..306df7da5f 100644
--- a/tools/aconfig/aconfig_storage_file/tests/srcs/FlagValueListTest.java
+++ b/tools/aconfig/aconfig_storage_file/tests/srcs/FlagValueListTest.java
@@ -34,7 +34,7 @@ public class FlagValueListTest {
     @Test
     public void testFlagValueList_rightHeader() throws Exception {
         FlagValueList flagValueList =
-                FlagValueList.fromBytes(TestDataUtils.getTestFlagValByteBuffer());
+                FlagValueList.fromBytes(TestDataUtils.getTestFlagValByteBuffer(1));
         FlagValueList.Header header = flagValueList.getHeader();
         assertEquals(1, header.getVersion());
         assertEquals("mockup", header.getContainer());
@@ -47,7 +47,7 @@ public class FlagValueListTest {
     @Test
     public void testFlagValueList_rightNode() throws Exception {
         FlagValueList flagValueList =
-                FlagValueList.fromBytes(TestDataUtils.getTestFlagValByteBuffer());
+                FlagValueList.fromBytes(TestDataUtils.getTestFlagValByteBuffer(1));
 
         boolean[] expected = new boolean[] {false, true, true, false, true, true, true, true};
         assertEquals(expected.length, flagValueList.size());
@@ -60,11 +60,11 @@ public class FlagValueListTest {
     @Test
     public void testFlagValueList_getValue() throws Exception {
         PackageTable packageTable =
-                PackageTable.fromBytes(TestDataUtils.getTestPackageMapByteBuffer());
-        FlagTable flagTable = FlagTable.fromBytes(TestDataUtils.getTestFlagMapByteBuffer());
+                PackageTable.fromBytes(TestDataUtils.getTestPackageMapByteBuffer(1));
+        FlagTable flagTable = FlagTable.fromBytes(TestDataUtils.getTestFlagMapByteBuffer(1));
 
         FlagValueList flagValueList =
-                FlagValueList.fromBytes(TestDataUtils.getTestFlagValByteBuffer());
+                FlagValueList.fromBytes(TestDataUtils.getTestFlagValByteBuffer(1));
 
         PackageTable.Node pNode = packageTable.get("com.android.aconfig.storage.test_1");
         FlagTable.Node fNode = flagTable.get(pNode.getPackageId(), "enabled_rw");
diff --git a/tools/aconfig/aconfig_storage_file/tests/srcs/PackageTableTest.java b/tools/aconfig/aconfig_storage_file/tests/srcs/PackageTableTest.java
index e7e19d8d51..5906d8b469 100644
--- a/tools/aconfig/aconfig_storage_file/tests/srcs/PackageTableTest.java
+++ b/tools/aconfig/aconfig_storage_file/tests/srcs/PackageTableTest.java
@@ -17,6 +17,8 @@
 package android.aconfig.storage.test;
 
 import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.assertTrue;
 
 import android.aconfig.storage.FileType;
 import android.aconfig.storage.PackageTable;
@@ -31,7 +33,7 @@ public class PackageTableTest {
     @Test
     public void testPackageTable_rightHeader() throws Exception {
         PackageTable packageTable =
-                PackageTable.fromBytes(TestDataUtils.getTestPackageMapByteBuffer());
+                PackageTable.fromBytes(TestDataUtils.getTestPackageMapByteBuffer(1));
         PackageTable.Header header = packageTable.getHeader();
         assertEquals(1, header.getVersion());
         assertEquals("mockup", header.getContainer());
@@ -42,10 +44,24 @@ public class PackageTableTest {
         assertEquals(59, header.getNodeOffset());
     }
 
+    @Test
+    public void testPackageTable_rightHeader_v2() throws Exception {
+        PackageTable packageTable =
+                PackageTable.fromBytes(TestDataUtils.getTestPackageMapByteBuffer(2));
+        PackageTable.Header header = packageTable.getHeader();
+        assertEquals(2, header.getVersion());
+        assertEquals("mockup", header.getContainer());
+        assertEquals(FileType.PACKAGE_MAP, header.getFileType());
+        assertEquals(233, header.getFileSize());
+        assertEquals(3, header.getNumPackages());
+        assertEquals(31, header.getBucketOffset());
+        assertEquals(59, header.getNodeOffset());
+    }
+
     @Test
     public void testPackageTable_rightNode() throws Exception {
         PackageTable packageTable =
-                PackageTable.fromBytes(TestDataUtils.getTestPackageMapByteBuffer());
+                PackageTable.fromBytes(TestDataUtils.getTestPackageMapByteBuffer(1));
 
         PackageTable.Node node1 = packageTable.get("com.android.aconfig.storage.test_1");
         PackageTable.Node node2 = packageTable.get("com.android.aconfig.storage.test_2");
@@ -66,5 +82,43 @@ public class PackageTableTest {
         assertEquals(159, node1.getNextOffset());
         assertEquals(-1, node2.getNextOffset());
         assertEquals(-1, node4.getNextOffset());
+
+        assertFalse(node1.hasPackageFingerprint());
+        assertFalse(node2.hasPackageFingerprint());
+        assertFalse(node4.hasPackageFingerprint());
+    }
+
+    @Test
+    public void testPackageTable_rightNode_v2() throws Exception {
+        PackageTable packageTable =
+                PackageTable.fromBytes(TestDataUtils.getTestPackageMapByteBuffer(2));
+
+        PackageTable.Node node1 = packageTable.get("com.android.aconfig.storage.test_1");
+        PackageTable.Node node2 = packageTable.get("com.android.aconfig.storage.test_2");
+        PackageTable.Node node4 = packageTable.get("com.android.aconfig.storage.test_4");
+
+        assertEquals("com.android.aconfig.storage.test_1", node1.getPackageName());
+        assertEquals("com.android.aconfig.storage.test_2", node2.getPackageName());
+        assertEquals("com.android.aconfig.storage.test_4", node4.getPackageName());
+
+        assertEquals(0, node1.getPackageId());
+        assertEquals(1, node2.getPackageId());
+        assertEquals(2, node4.getPackageId());
+
+        assertEquals(0, node1.getBooleanStartIndex());
+        assertEquals(3, node2.getBooleanStartIndex());
+        assertEquals(6, node4.getBooleanStartIndex());
+
+        assertEquals(175, node1.getNextOffset());
+        assertEquals(-1, node2.getNextOffset());
+        assertEquals(-1, node4.getNextOffset());
+
+        assertTrue(node1.hasPackageFingerprint());
+        assertTrue(node2.hasPackageFingerprint());
+        assertTrue(node4.hasPackageFingerprint());
+
+        assertEquals(-3197795563119393530L, node1.getPackageFingerprint());
+        assertEquals(4431940502274857964L, node2.getPackageFingerprint());
+        assertEquals(-2213514155997929241L, node4.getPackageFingerprint());
     }
 }
diff --git a/tools/aconfig/aconfig_storage_file/tests/srcs/StorageFileProviderTest.java b/tools/aconfig/aconfig_storage_file/tests/srcs/StorageFileProviderTest.java
new file mode 100644
index 0000000000..c2720f9544
--- /dev/null
+++ b/tools/aconfig/aconfig_storage_file/tests/srcs/StorageFileProviderTest.java
@@ -0,0 +1,66 @@
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
+import static org.junit.Assert.assertTrue;
+
+import android.aconfig.storage.FlagTable;
+import android.aconfig.storage.FlagValueList;
+import android.aconfig.storage.PackageTable;
+import android.aconfig.storage.StorageFileProvider;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
+import java.nio.file.Paths;
+import java.util.List;
+
+@RunWith(JUnit4.class)
+public class StorageFileProviderTest {
+
+    @Test
+    public void testlistContainers() throws Exception {
+        StorageFileProvider p =
+                new StorageFileProvider(TestDataUtils.TESTDATA_PATH, TestDataUtils.TESTDATA_PATH);
+        String[] excludes = {};
+        List<String> containers = p.listContainers(excludes);
+        assertEquals(2, containers.size());
+
+        excludes = new String[] {"mock.v1"};
+        containers = p.listContainers(excludes);
+        assertEquals(1, containers.size());
+
+        p = new StorageFileProvider("fake/path/", "fake/path/");
+        containers = p.listContainers(excludes);
+        assertTrue(containers.isEmpty());
+    }
+
+    @Test
+    public void testLoadFiles() throws Exception {
+        StorageFileProvider p =
+                new StorageFileProvider(TestDataUtils.TESTDATA_PATH, TestDataUtils.TESTDATA_PATH);
+        PackageTable pt = p.getPackageTable("mock.v1");
+        assertNotNull(pt);
+        FlagTable f = p.getFlagTable("mock.v1");
+        assertNotNull(f);
+        FlagValueList v = p.getFlagValueList("mock.v1");
+        assertNotNull(v);
+    }
+}
diff --git a/tools/aconfig/aconfig_storage_file/tests/srcs/TestDataUtils.java b/tools/aconfig/aconfig_storage_file/tests/srcs/TestDataUtils.java
index f35952d392..388971e28b 100644
--- a/tools/aconfig/aconfig_storage_file/tests/srcs/TestDataUtils.java
+++ b/tools/aconfig/aconfig_storage_file/tests/srcs/TestDataUtils.java
@@ -21,28 +21,27 @@ import java.io.InputStream;
 import java.nio.ByteBuffer;
 
 public final class TestDataUtils {
-    private static final String TEST_PACKAGE_MAP_PATH = "package.map";
-    private static final String TEST_FLAG_MAP_PATH = "flag.map";
-    private static final String TEST_FLAG_VAL_PATH = "flag.val";
-    private static final String TEST_FLAG_INFO_PATH = "flag.info";
+    private static final String TEST_PACKAGE_MAP_PATH = "mock.v%d.package.map";
+    private static final String TEST_FLAG_MAP_PATH = "mock.v%d.flag.map";
+    private static final String TEST_FLAG_VAL_PATH = "mock.v%d.val";
+    private static final String TEST_FLAG_INFO_PATH = "mock.v%d.info";
 
-    private static final String TESTDATA_PATH =
-            "/data/local/tmp/aconfig_storage_file_test_java/testdata/";
+    public static final String TESTDATA_PATH = "/data/local/tmp/aconfig_storage_file_test_java/testdata/";
 
-    public static ByteBuffer getTestPackageMapByteBuffer() throws Exception {
-        return readFile(TESTDATA_PATH + TEST_PACKAGE_MAP_PATH);
+    public static ByteBuffer getTestPackageMapByteBuffer(int version) throws Exception {
+        return readFile(TESTDATA_PATH + String.format(TEST_PACKAGE_MAP_PATH, version));
     }
 
-    public static ByteBuffer getTestFlagMapByteBuffer() throws Exception {
-        return readFile(TESTDATA_PATH + TEST_FLAG_MAP_PATH);
+    public static ByteBuffer getTestFlagMapByteBuffer(int version) throws Exception {
+        return readFile(TESTDATA_PATH + String.format(TEST_FLAG_MAP_PATH, version));
     }
 
-    public static ByteBuffer getTestFlagValByteBuffer() throws Exception {
-        return readFile(TESTDATA_PATH + TEST_FLAG_VAL_PATH);
+    public static ByteBuffer getTestFlagValByteBuffer(int version) throws Exception {
+        return readFile(TESTDATA_PATH + String.format(TEST_FLAG_VAL_PATH, version));
     }
 
-    public static ByteBuffer getTestFlagInfoByteBuffer() throws Exception {
-        return readFile(TESTDATA_PATH + TEST_FLAG_INFO_PATH);
+    public static ByteBuffer getTestFlagInfoByteBuffer(int version) throws Exception {
+        return readFile(TESTDATA_PATH + String.format(TEST_FLAG_INFO_PATH, version));
     }
 
     private static ByteBuffer readFile(String fileName) throws Exception {
diff --git a/tools/aconfig/aconfig_storage_file/tests/storage_file_test.cpp b/tools/aconfig/aconfig_storage_file/tests/storage_file_test.cpp
index ebd1dd89bd..5c008afbf1 100644
--- a/tools/aconfig/aconfig_storage_file/tests/storage_file_test.cpp
+++ b/tools/aconfig/aconfig_storage_file/tests/storage_file_test.cpp
@@ -24,10 +24,8 @@
 using namespace android::base;
 using namespace aconfig_storage;
 
-void verify_value(const FlagValueSummary& flag,
-                  const std::string& package_name,
-                  const std::string& flag_name,
-                  const std::string& flag_val,
+void verify_value(const FlagValueSummary& flag, const std::string& package_name,
+                  const std::string& flag_name, const std::string& flag_val,
                   const std::string& value_type) {
   ASSERT_EQ(flag.package_name, package_name);
   ASSERT_EQ(flag.flag_name, flag_name);
@@ -39,10 +37,8 @@ void verify_value_info(const FlagValueAndInfoSummary& flag,
                        const std::string& package_name,
                        const std::string& flag_name,
                        const std::string& flag_val,
-                       const std::string& value_type,
-                       bool is_readwrite,
-                       bool has_server_override,
-                       bool has_local_override) {
+                       const std::string& value_type, bool is_readwrite,
+                       bool has_server_override, bool has_local_override) {
   ASSERT_EQ(flag.package_name, package_name);
   ASSERT_EQ(flag.flag_name, flag_name);
   ASSERT_EQ(flag.flag_value, flag_val);
@@ -52,61 +48,137 @@ void verify_value_info(const FlagValueAndInfoSummary& flag,
   ASSERT_EQ(flag.has_local_override, has_local_override);
 }
 
+Result<std::vector<FlagValueSummary>> get_flag_list_result(
+    const std::string version) {
+  auto const test_base_dir = GetExecutableDirectory();
+  auto const test_dir = test_base_dir + "/data/v" + version;
+  auto const package_map = test_dir + "/package_v" + version + ".map";
+  auto const flag_map = test_dir + "/flag_v" + version + ".map";
+  auto const flag_val = test_dir + "/flag_v" + version + ".val";
+  return aconfig_storage::list_flags(package_map, flag_map, flag_val);
+}
+
+Result<std::vector<FlagValueAndInfoSummary>> get_flag_list_result_with_info(
+    const std::string version) {
+  auto const test_base_dir = GetExecutableDirectory();
+  auto const test_dir = test_base_dir + "/data/v" + version;
+  auto const package_map = test_dir + "/package_v" + version + ".map";
+  auto const flag_map = test_dir + "/flag_v" + version + ".map";
+  auto const flag_val = test_dir + "/flag_v" + version + ".val";
+  auto const flag_info = test_dir + "/flag_v" + version + ".info";
+  return aconfig_storage::list_flags_with_info(package_map, flag_map, flag_val,
+                                               flag_info);
+}
+
 TEST(AconfigStorageFileTest, test_list_flag) {
-  auto const test_dir = GetExecutableDirectory();
-  auto const package_map = test_dir + "/package.map";
-  auto const flag_map = test_dir + "/flag.map";
-  auto const flag_val = test_dir + "/flag.val";
-  auto flag_list_result = aconfig_storage::list_flags(
-      package_map, flag_map, flag_val);
+  auto flag_list_result = get_flag_list_result("1");
+  ASSERT_TRUE(flag_list_result.ok());
+
+  auto const& flag_list = *flag_list_result;
+  ASSERT_EQ(flag_list.size(), 8);
+  verify_value(flag_list[0], "com.android.aconfig.storage.test_1",
+               "disabled_rw", "false", "ReadWriteBoolean");
+  verify_value(flag_list[1], "com.android.aconfig.storage.test_1", "enabled_ro",
+               "true", "ReadOnlyBoolean");
+  verify_value(flag_list[2], "com.android.aconfig.storage.test_1", "enabled_rw",
+               "true", "ReadWriteBoolean");
+  verify_value(flag_list[3], "com.android.aconfig.storage.test_2",
+               "disabled_rw", "false", "ReadWriteBoolean");
+  verify_value(flag_list[4], "com.android.aconfig.storage.test_2",
+               "enabled_fixed_ro", "true", "FixedReadOnlyBoolean");
+  verify_value(flag_list[5], "com.android.aconfig.storage.test_2", "enabled_ro",
+               "true", "ReadOnlyBoolean");
+  verify_value(flag_list[6], "com.android.aconfig.storage.test_4",
+               "enabled_fixed_ro", "true", "FixedReadOnlyBoolean");
+  verify_value(flag_list[7], "com.android.aconfig.storage.test_4", "enabled_rw",
+               "true", "ReadWriteBoolean");
+}
+
+// TODO: b/376256472 - Use parameterized tests.
+TEST(AconfigStorageFileTest, test_list_flag_v2) {
+  auto flag_list_result = get_flag_list_result("2");
   ASSERT_TRUE(flag_list_result.ok());
 
   auto const& flag_list = *flag_list_result;
   ASSERT_EQ(flag_list.size(), 8);
-  verify_value(flag_list[0], "com.android.aconfig.storage.test_1", "disabled_rw",
-               "false", "ReadWriteBoolean");
+  verify_value(flag_list[0], "com.android.aconfig.storage.test_1",
+               "disabled_rw", "false", "ReadWriteBoolean");
   verify_value(flag_list[1], "com.android.aconfig.storage.test_1", "enabled_ro",
                "true", "ReadOnlyBoolean");
   verify_value(flag_list[2], "com.android.aconfig.storage.test_1", "enabled_rw",
                "true", "ReadWriteBoolean");
-  verify_value(flag_list[3], "com.android.aconfig.storage.test_2", "disabled_rw",
-               "false", "ReadWriteBoolean");
-  verify_value(flag_list[4], "com.android.aconfig.storage.test_2", "enabled_fixed_ro",
-               "true", "FixedReadOnlyBoolean");
+  verify_value(flag_list[3], "com.android.aconfig.storage.test_2",
+               "disabled_rw", "false", "ReadWriteBoolean");
+  verify_value(flag_list[4], "com.android.aconfig.storage.test_2",
+               "enabled_fixed_ro", "true", "FixedReadOnlyBoolean");
   verify_value(flag_list[5], "com.android.aconfig.storage.test_2", "enabled_ro",
                "true", "ReadOnlyBoolean");
-  verify_value(flag_list[6], "com.android.aconfig.storage.test_4", "enabled_fixed_ro",
-               "true", "FixedReadOnlyBoolean");
+  verify_value(flag_list[6], "com.android.aconfig.storage.test_4",
+               "enabled_fixed_ro", "true", "FixedReadOnlyBoolean");
   verify_value(flag_list[7], "com.android.aconfig.storage.test_4", "enabled_rw",
                "true", "ReadWriteBoolean");
 }
 
 TEST(AconfigStorageFileTest, test_list_flag_with_info) {
-  auto const test_dir = GetExecutableDirectory();
-  auto const package_map = test_dir + "/package.map";
-  auto const flag_map = test_dir + "/flag.map";
-  auto const flag_val = test_dir + "/flag.val";
-  auto const flag_info = test_dir + "/flag.info";
-  auto flag_list_result = aconfig_storage::list_flags_with_info(
-      package_map, flag_map, flag_val, flag_info);
+  auto flag_list_result = get_flag_list_result_with_info("1");
+  ASSERT_TRUE(flag_list_result.ok());
+
+  auto const& flag_list = *flag_list_result;
+  ASSERT_EQ(flag_list.size(), 8);
+  verify_value_info(flag_list[0], "com.android.aconfig.storage.test_1",
+                    "disabled_rw", "false", "ReadWriteBoolean", true, false,
+                    false);
+  verify_value_info(flag_list[1], "com.android.aconfig.storage.test_1",
+                    "enabled_ro", "true", "ReadOnlyBoolean", false, false,
+                    false);
+  verify_value_info(flag_list[2], "com.android.aconfig.storage.test_1",
+                    "enabled_rw", "true", "ReadWriteBoolean", true, false,
+                    false);
+  verify_value_info(flag_list[3], "com.android.aconfig.storage.test_2",
+                    "disabled_rw", "false", "ReadWriteBoolean", true, false,
+                    false);
+  verify_value_info(flag_list[4], "com.android.aconfig.storage.test_2",
+                    "enabled_fixed_ro", "true", "FixedReadOnlyBoolean", false,
+                    false, false);
+  verify_value_info(flag_list[5], "com.android.aconfig.storage.test_2",
+                    "enabled_ro", "true", "ReadOnlyBoolean", false, false,
+                    false);
+  verify_value_info(flag_list[6], "com.android.aconfig.storage.test_4",
+                    "enabled_fixed_ro", "true", "FixedReadOnlyBoolean", false,
+                    false, false);
+  verify_value_info(flag_list[7], "com.android.aconfig.storage.test_4",
+                    "enabled_rw", "true", "ReadWriteBoolean", true, false,
+                    false);
+}
+
+TEST(AconfigStorageFileTest, test_list_flag_with_info_v2) {
+  auto flag_list_result = get_flag_list_result_with_info("2");
   ASSERT_TRUE(flag_list_result.ok());
 
   auto const& flag_list = *flag_list_result;
   ASSERT_EQ(flag_list.size(), 8);
-  verify_value_info(flag_list[0], "com.android.aconfig.storage.test_1", "disabled_rw",
-                    "false", "ReadWriteBoolean", true, false, false);
-  verify_value_info(flag_list[1], "com.android.aconfig.storage.test_1", "enabled_ro",
-                    "true", "ReadOnlyBoolean", false, false, false);
-  verify_value_info(flag_list[2], "com.android.aconfig.storage.test_1", "enabled_rw",
-                    "true", "ReadWriteBoolean", true, false, false);
-  verify_value_info(flag_list[3], "com.android.aconfig.storage.test_2", "disabled_rw",
-                    "false", "ReadWriteBoolean", true, false, false);
-  verify_value_info(flag_list[4], "com.android.aconfig.storage.test_2", "enabled_fixed_ro",
-                    "true", "FixedReadOnlyBoolean", false, false, false);
-  verify_value_info(flag_list[5], "com.android.aconfig.storage.test_2", "enabled_ro",
-                    "true", "ReadOnlyBoolean", false, false, false);
-  verify_value_info(flag_list[6], "com.android.aconfig.storage.test_4", "enabled_fixed_ro",
-                    "true", "FixedReadOnlyBoolean", false, false, false);
-  verify_value_info(flag_list[7], "com.android.aconfig.storage.test_4", "enabled_rw",
-                    "true", "ReadWriteBoolean", true, false, false);
+  verify_value_info(flag_list[0], "com.android.aconfig.storage.test_1",
+                    "disabled_rw", "false", "ReadWriteBoolean", true, false,
+                    false);
+  verify_value_info(flag_list[1], "com.android.aconfig.storage.test_1",
+                    "enabled_ro", "true", "ReadOnlyBoolean", false, false,
+                    false);
+  verify_value_info(flag_list[2], "com.android.aconfig.storage.test_1",
+                    "enabled_rw", "true", "ReadWriteBoolean", true, false,
+                    false);
+  verify_value_info(flag_list[3], "com.android.aconfig.storage.test_2",
+                    "disabled_rw", "false", "ReadWriteBoolean", true, false,
+                    false);
+  verify_value_info(flag_list[4], "com.android.aconfig.storage.test_2",
+                    "enabled_fixed_ro", "true", "FixedReadOnlyBoolean", false,
+                    false, false);
+  verify_value_info(flag_list[5], "com.android.aconfig.storage.test_2",
+                    "enabled_ro", "true", "ReadOnlyBoolean", false, false,
+                    false);
+  verify_value_info(flag_list[6], "com.android.aconfig.storage.test_4",
+                    "enabled_fixed_ro", "true", "FixedReadOnlyBoolean", false,
+                    false, false);
+  verify_value_info(flag_list[7], "com.android.aconfig.storage.test_4",
+                    "enabled_rw", "true", "ReadWriteBoolean", true, false,
+                    false);
 }
diff --git a/tools/aconfig/aconfig_storage_read_api/Android.bp b/tools/aconfig/aconfig_storage_read_api/Android.bp
index f96b2230d1..6214e2ce03 100644
--- a/tools/aconfig/aconfig_storage_read_api/Android.bp
+++ b/tools/aconfig/aconfig_storage_read_api/Android.bp
@@ -36,10 +36,10 @@ rust_test_host {
         "librand",
     ],
     data: [
-        "tests/package.map",
-        "tests/flag.map",
-        "tests/flag.val",
-        "tests/flag.info",
+        "tests/data/v1/package_v1.map",
+        "tests/data/v1/flag_v1.map",
+        "tests/data/v1/flag_v1.val",
+        "tests/data/v1/flag_v1.info",
     ],
 }
 
@@ -107,31 +107,12 @@ cc_library {
     afdo: true,
 }
 
-soong_config_module_type {
-    name: "aconfig_lib_cc_shared_link_defaults",
-    module_type: "cc_defaults",
-    config_namespace: "Aconfig",
-    bool_variables: [
-        "read_from_new_storage",
-    ],
-    properties: [
-        "shared_libs",
-    ],
-}
-
-soong_config_bool_variable {
-    name: "read_from_new_storage",
-}
-
-aconfig_lib_cc_shared_link_defaults {
+cc_defaults {
     name: "aconfig_lib_cc_shared_link.defaults",
-    soong_config_variables: {
-        read_from_new_storage: {
-            shared_libs: [
-                "libaconfig_storage_read_api_cc",
-            ],
-        },
-    },
+    shared_libs: select(release_flag("RELEASE_READ_FROM_NEW_STORAGE"), {
+        true: ["libaconfig_storage_read_api_cc"],
+        default: [],
+    }),
 }
 
 cc_defaults {
@@ -174,36 +155,20 @@ java_library {
     name: "aconfig_storage_reader_java",
     srcs: [
         "srcs/android/aconfig/storage/StorageInternalReader.java",
+        "srcs/android/os/flagging/PlatformAconfigPackageInternal.java",
     ],
     libs: [
         "unsupportedappusage",
         "strict_mode_stub",
+        "aconfig_storage_stub",
     ],
     static_libs: [
         "aconfig_storage_file_java",
     ],
     sdk_version: "core_current",
     host_supported: true,
-    min_sdk_version: "29",
-    apex_available: [
-        "//apex_available:platform",
-        "//apex_available:anyapex",
-    ],
-}
-
-java_library {
-    name: "aconfig_storage_reader_java_none",
-    srcs: [
-        "srcs/android/aconfig/storage/StorageInternalReader.java",
-    ],
-    libs: [
-        "unsupportedappusage-sdk-none",
-        "fake_device_config",
+    visibility: [
+        "//frameworks/base",
+        "//build/make/tools/aconfig/aconfig_storage_read_api/tests",
     ],
-    static_libs: [
-        "aconfig_storage_file_java_none",
-    ],
-    sdk_version: "none",
-    system_modules: "core-all-system-modules",
-    host_supported: true,
 }
diff --git a/tools/aconfig/aconfig_storage_read_api/src/flag_info_query.rs b/tools/aconfig/aconfig_storage_read_api/src/flag_info_query.rs
index 6d03377683..68b6193079 100644
--- a/tools/aconfig/aconfig_storage_read_api/src/flag_info_query.rs
+++ b/tools/aconfig/aconfig_storage_read_api/src/flag_info_query.rs
@@ -16,8 +16,10 @@
 
 //! flag value query module defines the flag value file read from mapped bytes
 
-use crate::{AconfigStorageError, FILE_VERSION};
-use aconfig_storage_file::{flag_info::FlagInfoHeader, read_u8_from_bytes, FlagValueType};
+use crate::AconfigStorageError;
+use aconfig_storage_file::{
+    flag_info::FlagInfoHeader, read_u8_from_bytes, FlagValueType, MAX_SUPPORTED_FILE_VERSION,
+};
 use anyhow::anyhow;
 
 /// Get flag attribute bitfield
@@ -27,11 +29,11 @@ pub fn find_flag_attribute(
     flag_index: u32,
 ) -> Result<u8, AconfigStorageError> {
     let interpreted_header = FlagInfoHeader::from_bytes(buf)?;
-    if interpreted_header.version > crate::FILE_VERSION {
+    if interpreted_header.version > MAX_SUPPORTED_FILE_VERSION {
         return Err(AconfigStorageError::HigherStorageFileVersion(anyhow!(
             "Cannot read storage file with a higher version of {} with lib version {}",
             interpreted_header.version,
-            FILE_VERSION
+            MAX_SUPPORTED_FILE_VERSION
         )));
     }
 
@@ -53,12 +55,14 @@ pub fn find_flag_attribute(
 #[cfg(test)]
 mod tests {
     use super::*;
-    use aconfig_storage_file::{test_utils::create_test_flag_info_list, FlagInfoBit};
+    use aconfig_storage_file::{
+        test_utils::create_test_flag_info_list, FlagInfoBit, DEFAULT_FILE_VERSION,
+    };
 
     #[test]
     // this test point locks down query if flag has server override
     fn test_is_flag_sticky() {
-        let flag_info_list = create_test_flag_info_list().into_bytes();
+        let flag_info_list = create_test_flag_info_list(DEFAULT_FILE_VERSION).into_bytes();
         for offset in 0..8 {
             let attribute =
                 find_flag_attribute(&flag_info_list[..], FlagValueType::Boolean, offset).unwrap();
@@ -69,7 +73,7 @@ mod tests {
     #[test]
     // this test point locks down query if flag is readwrite
     fn test_is_flag_readwrite() {
-        let flag_info_list = create_test_flag_info_list().into_bytes();
+        let flag_info_list = create_test_flag_info_list(DEFAULT_FILE_VERSION).into_bytes();
         let baseline: Vec<bool> = vec![true, false, true, true, false, false, false, true];
         for offset in 0..8 {
             let attribute =
@@ -84,7 +88,7 @@ mod tests {
     #[test]
     // this test point locks down query if flag has local override
     fn test_flag_has_override() {
-        let flag_info_list = create_test_flag_info_list().into_bytes();
+        let flag_info_list = create_test_flag_info_list(DEFAULT_FILE_VERSION).into_bytes();
         for offset in 0..8 {
             let attribute =
                 find_flag_attribute(&flag_info_list[..], FlagValueType::Boolean, offset).unwrap();
@@ -95,7 +99,7 @@ mod tests {
     #[test]
     // this test point locks down query beyond the end of boolean section
     fn test_boolean_out_of_range() {
-        let flag_info_list = create_test_flag_info_list().into_bytes();
+        let flag_info_list = create_test_flag_info_list(DEFAULT_FILE_VERSION).into_bytes();
         let error =
             find_flag_attribute(&flag_info_list[..], FlagValueType::Boolean, 8).unwrap_err();
         assert_eq!(
@@ -107,16 +111,16 @@ mod tests {
     #[test]
     // this test point locks down query error when file has a higher version
     fn test_higher_version_storage_file() {
-        let mut info_list = create_test_flag_info_list();
-        info_list.header.version = crate::FILE_VERSION + 1;
+        let mut info_list = create_test_flag_info_list(DEFAULT_FILE_VERSION);
+        info_list.header.version = MAX_SUPPORTED_FILE_VERSION + 1;
         let flag_info = info_list.into_bytes();
         let error = find_flag_attribute(&flag_info[..], FlagValueType::Boolean, 4).unwrap_err();
         assert_eq!(
             format!("{:?}", error),
             format!(
                 "HigherStorageFileVersion(Cannot read storage file with a higher version of {} with lib version {})",
-                crate::FILE_VERSION + 1,
-                crate::FILE_VERSION
+                MAX_SUPPORTED_FILE_VERSION + 1,
+                MAX_SUPPORTED_FILE_VERSION
             )
         );
     }
diff --git a/tools/aconfig/aconfig_storage_read_api/src/flag_table_query.rs b/tools/aconfig/aconfig_storage_read_api/src/flag_table_query.rs
index a1a4793bc2..3e87acc43b 100644
--- a/tools/aconfig/aconfig_storage_read_api/src/flag_table_query.rs
+++ b/tools/aconfig/aconfig_storage_read_api/src/flag_table_query.rs
@@ -16,9 +16,10 @@
 
 //! flag table query module defines the flag table file read from mapped bytes
 
-use crate::{AconfigStorageError, FILE_VERSION};
+use crate::AconfigStorageError;
 use aconfig_storage_file::{
     flag_table::FlagTableHeader, flag_table::FlagTableNode, read_u32_from_bytes, StoredFlagType,
+    MAX_SUPPORTED_FILE_VERSION,
 };
 use anyhow::anyhow;
 
@@ -36,11 +37,11 @@ pub fn find_flag_read_context(
     flag: &str,
 ) -> Result<Option<FlagReadContext>, AconfigStorageError> {
     let interpreted_header = FlagTableHeader::from_bytes(buf)?;
-    if interpreted_header.version > crate::FILE_VERSION {
+    if interpreted_header.version > MAX_SUPPORTED_FILE_VERSION {
         return Err(AconfigStorageError::HigherStorageFileVersion(anyhow!(
             "Cannot read storage file with a higher version of {} with lib version {}",
             interpreted_header.version,
-            FILE_VERSION
+            MAX_SUPPORTED_FILE_VERSION
         )));
     }
 
@@ -73,12 +74,12 @@ pub fn find_flag_read_context(
 #[cfg(test)]
 mod tests {
     use super::*;
-    use aconfig_storage_file::test_utils::create_test_flag_table;
+    use aconfig_storage_file::{test_utils::create_test_flag_table, DEFAULT_FILE_VERSION};
 
     #[test]
     // this test point locks down table query
     fn test_flag_query() {
-        let flag_table = create_test_flag_table().into_bytes();
+        let flag_table = create_test_flag_table(DEFAULT_FILE_VERSION).into_bytes();
         let baseline = vec![
             (0, "enabled_ro", StoredFlagType::ReadOnlyBoolean, 1u16),
             (0, "enabled_rw", StoredFlagType::ReadWriteBoolean, 2u16),
@@ -100,7 +101,7 @@ mod tests {
     #[test]
     // this test point locks down table query of a non exist flag
     fn test_not_existed_flag_query() {
-        let flag_table = create_test_flag_table().into_bytes();
+        let flag_table = create_test_flag_table(DEFAULT_FILE_VERSION).into_bytes();
         let flag_context = find_flag_read_context(&flag_table[..], 1, "disabled_fixed_ro").unwrap();
         assert_eq!(flag_context, None);
         let flag_context = find_flag_read_context(&flag_table[..], 2, "disabled_rw").unwrap();
@@ -110,16 +111,16 @@ mod tests {
     #[test]
     // this test point locks down query error when file has a higher version
     fn test_higher_version_storage_file() {
-        let mut table = create_test_flag_table();
-        table.header.version = crate::FILE_VERSION + 1;
+        let mut table = create_test_flag_table(DEFAULT_FILE_VERSION);
+        table.header.version = MAX_SUPPORTED_FILE_VERSION + 1;
         let flag_table = table.into_bytes();
         let error = find_flag_read_context(&flag_table[..], 0, "enabled_ro").unwrap_err();
         assert_eq!(
             format!("{:?}", error),
             format!(
                 "HigherStorageFileVersion(Cannot read storage file with a higher version of {} with lib version {})",
-                crate::FILE_VERSION + 1,
-                crate::FILE_VERSION
+                MAX_SUPPORTED_FILE_VERSION + 1,
+                MAX_SUPPORTED_FILE_VERSION
             )
         );
     }
diff --git a/tools/aconfig/aconfig_storage_read_api/src/flag_value_query.rs b/tools/aconfig/aconfig_storage_read_api/src/flag_value_query.rs
index 9d32a16ac8..35f56929a9 100644
--- a/tools/aconfig/aconfig_storage_read_api/src/flag_value_query.rs
+++ b/tools/aconfig/aconfig_storage_read_api/src/flag_value_query.rs
@@ -16,18 +16,20 @@
 
 //! flag value query module defines the flag value file read from mapped bytes
 
-use crate::{AconfigStorageError, FILE_VERSION};
-use aconfig_storage_file::{flag_value::FlagValueHeader, read_u8_from_bytes};
+use crate::AconfigStorageError;
+use aconfig_storage_file::{
+    flag_value::FlagValueHeader, read_u8_from_bytes, MAX_SUPPORTED_FILE_VERSION,
+};
 use anyhow::anyhow;
 
 /// Query flag value
 pub fn find_boolean_flag_value(buf: &[u8], flag_index: u32) -> Result<bool, AconfigStorageError> {
     let interpreted_header = FlagValueHeader::from_bytes(buf)?;
-    if interpreted_header.version > crate::FILE_VERSION {
+    if interpreted_header.version > MAX_SUPPORTED_FILE_VERSION {
         return Err(AconfigStorageError::HigherStorageFileVersion(anyhow!(
             "Cannot read storage file with a higher version of {} with lib version {}",
             interpreted_header.version,
-            FILE_VERSION
+            MAX_SUPPORTED_FILE_VERSION
         )));
     }
 
@@ -46,12 +48,12 @@ pub fn find_boolean_flag_value(buf: &[u8], flag_index: u32) -> Result<bool, Acon
 #[cfg(test)]
 mod tests {
     use super::*;
-    use aconfig_storage_file::test_utils::create_test_flag_value_list;
+    use aconfig_storage_file::{test_utils::create_test_flag_value_list, DEFAULT_FILE_VERSION};
 
     #[test]
     // this test point locks down flag value query
     fn test_flag_value_query() {
-        let flag_value_list = create_test_flag_value_list().into_bytes();
+        let flag_value_list = create_test_flag_value_list(DEFAULT_FILE_VERSION).into_bytes();
         let baseline: Vec<bool> = vec![false, true, true, false, true, true, true, true];
         for (offset, expected_value) in baseline.into_iter().enumerate() {
             let flag_value = find_boolean_flag_value(&flag_value_list[..], offset as u32).unwrap();
@@ -62,7 +64,7 @@ mod tests {
     #[test]
     // this test point locks down query beyond the end of boolean section
     fn test_boolean_out_of_range() {
-        let flag_value_list = create_test_flag_value_list().into_bytes();
+        let flag_value_list = create_test_flag_value_list(DEFAULT_FILE_VERSION).into_bytes();
         let error = find_boolean_flag_value(&flag_value_list[..], 8).unwrap_err();
         assert_eq!(
             format!("{:?}", error),
@@ -73,16 +75,16 @@ mod tests {
     #[test]
     // this test point locks down query error when file has a higher version
     fn test_higher_version_storage_file() {
-        let mut value_list = create_test_flag_value_list();
-        value_list.header.version = crate::FILE_VERSION + 1;
+        let mut value_list = create_test_flag_value_list(DEFAULT_FILE_VERSION);
+        value_list.header.version = MAX_SUPPORTED_FILE_VERSION + 1;
         let flag_value = value_list.into_bytes();
         let error = find_boolean_flag_value(&flag_value[..], 4).unwrap_err();
         assert_eq!(
             format!("{:?}", error),
             format!(
                 "HigherStorageFileVersion(Cannot read storage file with a higher version of {} with lib version {})",
-                crate::FILE_VERSION + 1,
-                crate::FILE_VERSION
+                MAX_SUPPORTED_FILE_VERSION + 1,
+                MAX_SUPPORTED_FILE_VERSION
             )
         );
     }
diff --git a/tools/aconfig/aconfig_storage_read_api/src/lib.rs b/tools/aconfig/aconfig_storage_read_api/src/lib.rs
index d76cf3fe4e..d3cc9d427d 100644
--- a/tools/aconfig/aconfig_storage_read_api/src/lib.rs
+++ b/tools/aconfig/aconfig_storage_read_api/src/lib.rs
@@ -44,9 +44,10 @@ pub mod package_table_query;
 
 pub use aconfig_storage_file::{AconfigStorageError, FlagValueType, StorageFileType};
 pub use flag_table_query::FlagReadContext;
+pub use mapped_file::map_file;
 pub use package_table_query::PackageReadContext;
 
-use aconfig_storage_file::{read_u32_from_bytes, FILE_VERSION};
+use aconfig_storage_file::read_u32_from_bytes;
 use flag_info_query::find_flag_attribute;
 use flag_table_query::find_flag_read_context;
 use flag_value_query::find_boolean_flag_value;
@@ -114,13 +115,13 @@ pub fn get_flag_read_context(
 
 /// Get the boolean flag value.
 ///
-/// \input file: mapped flag file
+/// \input file: a byte slice, can be either &Mmap or &MapMut
 /// \input index: boolean flag offset
 ///
 /// \return
 /// If the provide offset is valid, it returns the boolean flag value, otherwise it
 /// returns the error message.
-pub fn get_boolean_flag_value(file: &Mmap, index: u32) -> Result<bool, AconfigStorageError> {
+pub fn get_boolean_flag_value(file: &[u8], index: u32) -> Result<bool, AconfigStorageError> {
     find_boolean_flag_value(file, index)
 }
 
@@ -148,7 +149,7 @@ pub fn get_storage_file_version(file_path: &str) -> Result<u32, AconfigStorageEr
 
 /// Get the flag attribute.
 ///
-/// \input file: mapped flag info file
+/// \input file: a byte slice, can be either &Mmap or &MapMut
 /// \input flag_type: flag value type
 /// \input flag_index: flag index
 ///
@@ -156,7 +157,7 @@ pub fn get_storage_file_version(file_path: &str) -> Result<u32, AconfigStorageEr
 /// If the provide offset is valid, it returns the flag attribute bitfiled, otherwise it
 /// returns the error message.
 pub fn get_flag_attribute(
-    file: &Mmap,
+    file: &[u8],
     flag_type: FlagValueType,
     flag_index: u32,
 ) -> Result<u8, AconfigStorageError> {
@@ -412,10 +413,10 @@ mod tests {
         let flag_map = storage_dir.clone() + "/maps/mockup.flag.map";
         let flag_val = storage_dir.clone() + "/boot/mockup.val";
         let flag_info = storage_dir.clone() + "/boot/mockup.info";
-        fs::copy("./tests/package.map", &package_map).unwrap();
-        fs::copy("./tests/flag.map", &flag_map).unwrap();
-        fs::copy("./tests/flag.val", &flag_val).unwrap();
-        fs::copy("./tests/flag.info", &flag_info).unwrap();
+        fs::copy("./tests/data/v1/package_v1.map", &package_map).unwrap();
+        fs::copy("./tests/data/v1/flag_v1.map", &flag_map).unwrap();
+        fs::copy("./tests/data/v1/flag_v1.val", &flag_val).unwrap();
+        fs::copy("./tests/data/v1/flag_v1.info", &flag_info).unwrap();
 
         return storage_dir;
     }
@@ -432,21 +433,24 @@ mod tests {
             get_package_read_context(&package_mapped_file, "com.android.aconfig.storage.test_1")
                 .unwrap()
                 .unwrap();
-        let expected_package_context = PackageReadContext { package_id: 0, boolean_start_index: 0 };
+        let expected_package_context =
+            PackageReadContext { package_id: 0, boolean_start_index: 0, fingerprint: 0 };
         assert_eq!(package_context, expected_package_context);
 
         let package_context =
             get_package_read_context(&package_mapped_file, "com.android.aconfig.storage.test_2")
                 .unwrap()
                 .unwrap();
-        let expected_package_context = PackageReadContext { package_id: 1, boolean_start_index: 3 };
+        let expected_package_context =
+            PackageReadContext { package_id: 1, boolean_start_index: 3, fingerprint: 0 };
         assert_eq!(package_context, expected_package_context);
 
         let package_context =
             get_package_read_context(&package_mapped_file, "com.android.aconfig.storage.test_4")
                 .unwrap()
                 .unwrap();
-        let expected_package_context = PackageReadContext { package_id: 2, boolean_start_index: 6 };
+        let expected_package_context =
+            PackageReadContext { package_id: 2, boolean_start_index: 6, fingerprint: 0 };
         assert_eq!(package_context, expected_package_context);
     }
 
@@ -507,9 +511,9 @@ mod tests {
     #[test]
     // this test point locks down flag storage file version number query api
     fn test_storage_version_query() {
-        assert_eq!(get_storage_file_version("./tests/package.map").unwrap(), 1);
-        assert_eq!(get_storage_file_version("./tests/flag.map").unwrap(), 1);
-        assert_eq!(get_storage_file_version("./tests/flag.val").unwrap(), 1);
-        assert_eq!(get_storage_file_version("./tests/flag.info").unwrap(), 1);
+        assert_eq!(get_storage_file_version("./tests/data/v1/package_v1.map").unwrap(), 1);
+        assert_eq!(get_storage_file_version("./tests/data/v1/flag_v1.map").unwrap(), 1);
+        assert_eq!(get_storage_file_version("./tests/data/v1/flag_v1.val").unwrap(), 1);
+        assert_eq!(get_storage_file_version("./tests/data/v1/flag_v1.info").unwrap(), 1);
     }
 }
diff --git a/tools/aconfig/aconfig_storage_read_api/src/mapped_file.rs b/tools/aconfig/aconfig_storage_read_api/src/mapped_file.rs
index 5a1664535f..f4e269e68b 100644
--- a/tools/aconfig/aconfig_storage_read_api/src/mapped_file.rs
+++ b/tools/aconfig/aconfig_storage_read_api/src/mapped_file.rs
@@ -28,7 +28,7 @@ use crate::StorageFileType;
 /// The memory mapped file may have undefined behavior if there are writes to this
 /// file after being mapped. Ensure no writes can happen to this file while this
 /// mapping stays alive.
-unsafe fn map_file(file_path: &str) -> Result<Mmap, AconfigStorageError> {
+pub unsafe fn map_file(file_path: &str) -> Result<Mmap, AconfigStorageError> {
     let file = File::open(file_path)
         .map_err(|errmsg| FileReadFail(anyhow!("Failed to open file {}: {}", file_path, errmsg)))?;
     unsafe {
@@ -97,10 +97,10 @@ mod tests {
         let flag_map = storage_dir.clone() + "/maps/mockup.flag.map";
         let flag_val = storage_dir.clone() + "/boot/mockup.val";
         let flag_info = storage_dir.clone() + "/boot/mockup.info";
-        fs::copy("./tests/package.map", &package_map).unwrap();
-        fs::copy("./tests/flag.map", &flag_map).unwrap();
-        fs::copy("./tests/flag.val", &flag_val).unwrap();
-        fs::copy("./tests/flag.info", &flag_info).unwrap();
+        fs::copy("./tests/data/v1/package_v1.map", &package_map).unwrap();
+        fs::copy("./tests/data/v1/flag_v1.map", &flag_map).unwrap();
+        fs::copy("./tests/data/v1/flag_v1.val", &flag_val).unwrap();
+        fs::copy("./tests/data/v1/flag_v1.info", &flag_info).unwrap();
 
         return storage_dir;
     }
@@ -108,9 +108,9 @@ mod tests {
     #[test]
     fn test_mapped_file_contents() {
         let storage_dir = create_test_storage_files();
-        map_and_verify(&storage_dir, StorageFileType::PackageMap, "./tests/package.map");
-        map_and_verify(&storage_dir, StorageFileType::FlagMap, "./tests/flag.map");
-        map_and_verify(&storage_dir, StorageFileType::FlagVal, "./tests/flag.val");
-        map_and_verify(&storage_dir, StorageFileType::FlagInfo, "./tests/flag.info");
+        map_and_verify(&storage_dir, StorageFileType::PackageMap, "./tests/data/v1/package_v1.map");
+        map_and_verify(&storage_dir, StorageFileType::FlagMap, "./tests/data/v1/flag_v1.map");
+        map_and_verify(&storage_dir, StorageFileType::FlagVal, "./tests/data/v1/flag_v1.val");
+        map_and_verify(&storage_dir, StorageFileType::FlagInfo, "./tests/data/v1/flag_v1.info");
     }
 }
diff --git a/tools/aconfig/aconfig_storage_read_api/src/package_table_query.rs b/tools/aconfig/aconfig_storage_read_api/src/package_table_query.rs
index 2cb854b1b1..b20668f9c2 100644
--- a/tools/aconfig/aconfig_storage_read_api/src/package_table_query.rs
+++ b/tools/aconfig/aconfig_storage_read_api/src/package_table_query.rs
@@ -16,9 +16,10 @@
 
 //! package table query module defines the package table file read from mapped bytes
 
-use crate::{AconfigStorageError, FILE_VERSION};
+use crate::AconfigStorageError;
 use aconfig_storage_file::{
     package_table::PackageTableHeader, package_table::PackageTableNode, read_u32_from_bytes,
+    MAX_SUPPORTED_FILE_VERSION,
 };
 use anyhow::anyhow;
 
@@ -27,6 +28,7 @@ use anyhow::anyhow;
 pub struct PackageReadContext {
     pub package_id: u32,
     pub boolean_start_index: u32,
+    pub fingerprint: u64,
 }
 
 /// Query package read context: package id and start index
@@ -35,11 +37,11 @@ pub fn find_package_read_context(
     package: &str,
 ) -> Result<Option<PackageReadContext>, AconfigStorageError> {
     let interpreted_header = PackageTableHeader::from_bytes(buf)?;
-    if interpreted_header.version > FILE_VERSION {
+    if interpreted_header.version > MAX_SUPPORTED_FILE_VERSION {
         return Err(AconfigStorageError::HigherStorageFileVersion(anyhow!(
             "Cannot read storage file with a higher version of {} with lib version {}",
             interpreted_header.version,
-            FILE_VERSION
+            MAX_SUPPORTED_FILE_VERSION
         )));
     }
 
@@ -55,11 +57,13 @@ pub fn find_package_read_context(
     }
 
     loop {
-        let interpreted_node = PackageTableNode::from_bytes(&buf[package_node_offset..])?;
+        let interpreted_node =
+            PackageTableNode::from_bytes(&buf[package_node_offset..], interpreted_header.version)?;
         if interpreted_node.package_name == package {
             return Ok(Some(PackageReadContext {
                 package_id: interpreted_node.package_id,
                 boolean_start_index: interpreted_node.boolean_start_index,
+                fingerprint: interpreted_node.fingerprint,
             }));
         }
         match interpreted_node.next_offset {
@@ -72,29 +76,68 @@ pub fn find_package_read_context(
 #[cfg(test)]
 mod tests {
     use super::*;
-    use aconfig_storage_file::test_utils::create_test_package_table;
+    use aconfig_storage_file::{test_utils::create_test_package_table, DEFAULT_FILE_VERSION};
 
     #[test]
     // this test point locks down table query
     fn test_package_query() {
-        let package_table = create_test_package_table().into_bytes();
+        let package_table = create_test_package_table(DEFAULT_FILE_VERSION).into_bytes();
         let package_context =
             find_package_read_context(&package_table[..], "com.android.aconfig.storage.test_1")
                 .unwrap()
                 .unwrap();
-        let expected_package_context = PackageReadContext { package_id: 0, boolean_start_index: 0 };
+        let expected_package_context =
+            PackageReadContext { package_id: 0, boolean_start_index: 0, fingerprint: 0 };
         assert_eq!(package_context, expected_package_context);
         let package_context =
             find_package_read_context(&package_table[..], "com.android.aconfig.storage.test_2")
                 .unwrap()
                 .unwrap();
-        let expected_package_context = PackageReadContext { package_id: 1, boolean_start_index: 3 };
+        let expected_package_context =
+            PackageReadContext { package_id: 1, boolean_start_index: 3, fingerprint: 0 };
         assert_eq!(package_context, expected_package_context);
         let package_context =
             find_package_read_context(&package_table[..], "com.android.aconfig.storage.test_4")
                 .unwrap()
                 .unwrap();
-        let expected_package_context = PackageReadContext { package_id: 2, boolean_start_index: 6 };
+        let expected_package_context =
+            PackageReadContext { package_id: 2, boolean_start_index: 6, fingerprint: 0 };
+        assert_eq!(package_context, expected_package_context);
+    }
+
+    #[test]
+    // this test point locks down table query
+    fn test_package_query_v2() {
+        let package_table = create_test_package_table(2).into_bytes();
+        let package_context =
+            find_package_read_context(&package_table[..], "com.android.aconfig.storage.test_1")
+                .unwrap()
+                .unwrap();
+        let expected_package_context = PackageReadContext {
+            package_id: 0,
+            boolean_start_index: 0,
+            fingerprint: 15248948510590158086u64,
+        };
+        assert_eq!(package_context, expected_package_context);
+        let package_context =
+            find_package_read_context(&package_table[..], "com.android.aconfig.storage.test_2")
+                .unwrap()
+                .unwrap();
+        let expected_package_context = PackageReadContext {
+            package_id: 1,
+            boolean_start_index: 3,
+            fingerprint: 4431940502274857964u64,
+        };
+        assert_eq!(package_context, expected_package_context);
+        let package_context =
+            find_package_read_context(&package_table[..], "com.android.aconfig.storage.test_4")
+                .unwrap()
+                .unwrap();
+        let expected_package_context = PackageReadContext {
+            package_id: 2,
+            boolean_start_index: 6,
+            fingerprint: 16233229917711622375u64,
+        };
         assert_eq!(package_context, expected_package_context);
     }
 
@@ -102,7 +145,7 @@ mod tests {
     // this test point locks down table query of a non exist package
     fn test_not_existed_package_query() {
         // this will land at an empty bucket
-        let package_table = create_test_package_table().into_bytes();
+        let package_table = create_test_package_table(DEFAULT_FILE_VERSION).into_bytes();
         let package_context =
             find_package_read_context(&package_table[..], "com.android.aconfig.storage.test_3")
                 .unwrap();
@@ -117,8 +160,8 @@ mod tests {
     #[test]
     // this test point locks down query error when file has a higher version
     fn test_higher_version_storage_file() {
-        let mut table = create_test_package_table();
-        table.header.version = crate::FILE_VERSION + 1;
+        let mut table = create_test_package_table(DEFAULT_FILE_VERSION);
+        table.header.version = MAX_SUPPORTED_FILE_VERSION + 1;
         let package_table = table.into_bytes();
         let error =
             find_package_read_context(&package_table[..], "com.android.aconfig.storage.test_1")
@@ -127,8 +170,8 @@ mod tests {
             format!("{:?}", error),
             format!(
                 "HigherStorageFileVersion(Cannot read storage file with a higher version of {} with lib version {})",
-                crate::FILE_VERSION + 1,
-                crate::FILE_VERSION
+                MAX_SUPPORTED_FILE_VERSION + 1,
+                MAX_SUPPORTED_FILE_VERSION
             )
         );
     }
diff --git a/tools/aconfig/aconfig_storage_read_api/srcs/android/aconfig/storage/StorageInternalReader.java b/tools/aconfig/aconfig_storage_read_api/srcs/android/aconfig/storage/StorageInternalReader.java
index 29ebee5ab4..6fbcdb354a 100644
--- a/tools/aconfig/aconfig_storage_read_api/srcs/android/aconfig/storage/StorageInternalReader.java
+++ b/tools/aconfig/aconfig_storage_read_api/srcs/android/aconfig/storage/StorageInternalReader.java
@@ -53,9 +53,6 @@ public class StorageInternalReader {
     @UnsupportedAppUsage
     public boolean getBooleanFlagValue(int index) {
         index += mPackageBooleanStartOffset;
-        if (index >= mFlagValueList.size()) {
-            throw new AconfigStorageException("Fail to get boolean flag value");
-        }
         return mFlagValueList.getBoolean(index);
     }
 
diff --git a/tools/aconfig/aconfig_storage_read_api/srcs/android/os/flagging/PlatformAconfigPackageInternal.java b/tools/aconfig/aconfig_storage_read_api/srcs/android/os/flagging/PlatformAconfigPackageInternal.java
new file mode 100644
index 0000000000..d73d9eb3ae
--- /dev/null
+++ b/tools/aconfig/aconfig_storage_read_api/srcs/android/os/flagging/PlatformAconfigPackageInternal.java
@@ -0,0 +1,135 @@
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
+import android.aconfig.storage.AconfigStorageException;
+import android.aconfig.storage.FlagValueList;
+import android.aconfig.storage.PackageTable;
+import android.aconfig.storage.StorageFileProvider;
+import android.compat.annotation.UnsupportedAppUsage;
+import android.os.StrictMode;
+
+/**
+ * An {@code aconfig} package containing the enabled state of its flags.
+ *
+ * <p><strong>Note: this is intended only to be used by generated code. To determine if a given flag
+ * is enabled in app code, the generated android flags should be used.</strong>
+ *
+ * <p>This class is not part of the public API and should be used by Acnofig Flag internally </b> It
+ * is intended for internal use only and will be changed or removed without notice.
+ *
+ * <p>This class is used to read the flag from Aconfig Package.Each instance of this class will
+ * cache information related to one package. To read flags from a different package, a new instance
+ * of this class should be {@link #load loaded}.
+ *
+ * @hide
+ */
+public class PlatformAconfigPackageInternal {
+
+    private final FlagValueList mFlagValueList;
+    private final int mPackageBooleanStartOffset;
+
+    private PlatformAconfigPackageInternal(
+            FlagValueList flagValueList, int packageBooleanStartOffset) {
+        this.mFlagValueList = flagValueList;
+        this.mPackageBooleanStartOffset = packageBooleanStartOffset;
+    }
+
+    /**
+     * Loads an Aconfig package from the specified container and verifies its fingerprint.
+     *
+     * <p>This method is intended for internal use only and may be changed or removed without
+     * notice.
+     *
+     * @param container The name of the container.
+     * @param packageName The name of the Aconfig package.
+     * @param packageFingerprint The expected fingerprint of the package.
+     * @return An instance of {@link PlatformAconfigPackageInternal} representing the loaded
+     *     package.
+     * @hide
+     */
+    @UnsupportedAppUsage
+    public static PlatformAconfigPackageInternal load(
+            String container, String packageName, long packageFingerprint) {
+        return load(
+                container,
+                packageName,
+                packageFingerprint,
+                StorageFileProvider.getDefaultProvider());
+    }
+
+    /** @hide */
+    public static PlatformAconfigPackageInternal load(
+            String container,
+            String packageName,
+            long packageFingerprint,
+            StorageFileProvider fileProvider) {
+        StrictMode.ThreadPolicy oldPolicy = StrictMode.allowThreadDiskReads();
+        PackageTable.Node pNode = null;
+        FlagValueList vList = null;
+        try {
+            pNode = fileProvider.getPackageTable(container).get(packageName);
+            vList = fileProvider.getFlagValueList(container);
+        } catch (AconfigStorageException e) {
+            throw new AconfigStorageReadException(e.getErrorCode(), e.toString());
+        } finally {
+            StrictMode.setThreadPolicy(oldPolicy);
+        }
+
+        if (pNode == null || vList == null) {
+            throw new AconfigStorageReadException(
+                    AconfigStorageReadException.ERROR_PACKAGE_NOT_FOUND,
+                    String.format(
+                            "package "
+                                    + packageName
+                                    + " in container "
+                                    + container
+                                    + " cannot be found on the device"));
+        }
+
+        if (pNode.hasPackageFingerprint() && packageFingerprint != pNode.getPackageFingerprint()) {
+            throw new AconfigStorageReadException(
+                    5, // AconfigStorageReadException.ERROR_FILE_FINGERPRINT_MISMATCH,
+                    String.format(
+                            "package "
+                                    + packageName
+                                    + " in container "
+                                    + container
+                                    + " cannot be found on the device"));
+        }
+
+        return new PlatformAconfigPackageInternal(vList, pNode.getBooleanStartIndex());
+    }
+
+    /**
+     * Retrieves the value of a boolean flag using its index.
+     *
+     * <p>This method is intended for internal use only and may be changed or removed without
+     * notice.
+     *
+     * <p>This method retrieves the value of a flag within the loaded Aconfig package using its
+     * index. The index is generated at build time and may vary between builds.
+     *
+     * @param index The index of the flag within the package.
+     * @return The boolean value of the flag.
+     * @hide
+     */
+    @UnsupportedAppUsage
+    public boolean getBooleanFlagValue(int index) {
+        return mFlagValueList.getBoolean(index + mPackageBooleanStartOffset);
+    }
+}
diff --git a/tools/aconfig/aconfig_storage_read_api/tests/java/AndroidTest.xml b/tools/aconfig/aconfig_storage_read_api/tests/AconfigStorageReadFunctionalTest.xml
similarity index 89%
rename from tools/aconfig/aconfig_storage_read_api/tests/java/AndroidTest.xml
rename to tools/aconfig/aconfig_storage_read_api/tests/AconfigStorageReadFunctionalTest.xml
index 99c9e2566e..ee50060208 100644
--- a/tools/aconfig/aconfig_storage_read_api/tests/java/AndroidTest.xml
+++ b/tools/aconfig/aconfig_storage_read_api/tests/AconfigStorageReadFunctionalTest.xml
@@ -26,7 +26,7 @@
     </target_preparer>
 
     <target_preparer class="com.android.tradefed.targetprep.TestAppInstallSetup">
-        <option name="test-file-name" value="aconfig_storage_read_api.test.java.apk" />
+        <option name="test-file-name" value="aconfig_storage_read_functional.apk" />
     </target_preparer>
 
     <target_preparer class="com.android.tradefed.targetprep.DisableSELinuxTargetPreparer" />
@@ -35,17 +35,17 @@
     <target_preparer class="com.android.tradefed.targetprep.PushFilePreparer">
         <option name="cleanup" value="true" />
         <option name="abort-on-push-failure" value="true" />
-        <option name="push-file" key="package.map"
+        <option name="push-file" key="package_v1.map"
                 value="/data/local/tmp/aconfig_java_api_test/maps/mockup.package.map" />
-        <option name="push-file" key="flag.map"
+        <option name="push-file" key="flag_v1.map"
                 value="/data/local/tmp/aconfig_java_api_test/maps/mockup.flag.map" />
-        <option name="push-file" key="flag.val"
+        <option name="push-file" key="flag_v1.val"
                 value="/data/local/tmp/aconfig_java_api_test/boot/mockup.val" />
     </target_preparer>
 
     <test class="com.android.tradefed.testtype.AndroidJUnitTest" >
         <option name="runner" value="androidx.test.runner.AndroidJUnitRunner" />
-        <option name="package" value="android.aconfig_storage.test" />
+        <option name="package" value="android.aconfig.storage.test" />
         <option name="runtime-hint" value="1m" />
     </test>
-</configuration>
+</configuration>
\ No newline at end of file
diff --git a/tools/aconfig/aconfig_storage_read_api/tests/AconfigStorageReadUnitTest.xml b/tools/aconfig/aconfig_storage_read_api/tests/AconfigStorageReadUnitTest.xml
new file mode 100644
index 0000000000..e528dd54f9
--- /dev/null
+++ b/tools/aconfig/aconfig_storage_read_api/tests/AconfigStorageReadUnitTest.xml
@@ -0,0 +1,34 @@
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
+<configuration description="Test aconfig storage java tests">
+    <target_preparer class="com.android.tradefed.targetprep.suite.SuiteApkInstaller">
+        <option name="cleanup-apks" value="true" />
+        <option name="test-file-name" value="aconfig_storage_read_unit.apk" />
+    </target_preparer>
+    <target_preparer class="com.android.compatibility.common.tradefed.targetprep.FilePusher">
+        <option name="cleanup" value="true" />
+        <option name="push" value="package_v2.map->/data/local/tmp/aconfig_storage_read_unit/testdata/mockup.package.map" />
+        <option name="push" value="flag_v2.map->/data/local/tmp/aconfig_storage_read_unit/testdata/mockup.flag.map" />
+        <option name="push" value="flag_v2.val->/data/local/tmp/aconfig_storage_read_unit/testdata/mockup.val" />
+        <option name="push" value="flag_v2.info->/data/local/tmp/aconfig_storage_read_unit/testdata/mockup.info" />
+        <option name="post-push" value="chmod +r /data/local/tmp/aconfig_storage_read_unit/testdata/" />
+    </target_preparer>
+    <test class="com.android.tradefed.testtype.AndroidJUnitTest" >
+        <option name="package" value="android.aconfig.storage.test" />
+        <option name="runtime-hint" value="1m" />
+    </test>
+</configuration>
diff --git a/tools/aconfig/aconfig_storage_read_api/tests/Android.bp b/tools/aconfig/aconfig_storage_read_api/tests/Android.bp
index ed0c728215..702325da5d 100644
--- a/tools/aconfig/aconfig_storage_read_api/tests/Android.bp
+++ b/tools/aconfig/aconfig_storage_read_api/tests/Android.bp
@@ -1,9 +1,14 @@
 filegroup {
     name: "read_api_test_storage_files",
-    srcs: ["package.map",
-        "flag.map",
-        "flag.val",
-        "flag.info"
+    srcs: [
+        "data/v1/package_v1.map",
+        "data/v1/flag_v1.map",
+        "data/v1/flag_v1.val",
+        "data/v1/flag_v1.info",
+        "data/v2/package_v2.map",
+        "data/v2/flag_v2.map",
+        "data/v2/flag_v2.val",
+        "data/v2/flag_v2.info",
     ],
 }
 
@@ -43,3 +48,52 @@ cc_test {
         "general-tests",
     ],
 }
+
+android_test {
+    name: "aconfig_storage_read_functional",
+    srcs: [
+        "functional/srcs/**/*.java",
+    ],
+    static_libs: [
+        "aconfig_device_paths_java",
+        "aconfig_storage_file_java",
+        "androidx.test.rules",
+        "libaconfig_storage_read_api_java",
+        "junit",
+    ],
+    jni_libs: [
+        "libaconfig_storage_read_api_rust_jni",
+    ],
+    data: [
+        ":read_api_test_storage_files",
+    ],
+    platform_apis: true,
+    certificate: "platform",
+    test_suites: [
+        "general-tests",
+    ],
+    test_config: "AconfigStorageReadFunctionalTest.xml",
+    team: "trendy_team_android_core_experiments",
+}
+
+android_test {
+    name: "aconfig_storage_read_unit",
+    team: "trendy_team_android_core_experiments",
+    srcs: [
+        "unit/srcs/**/*.java",
+    ],
+    static_libs: [
+        "androidx.test.runner",
+        "junit",
+        "aconfig_storage_reader_java",
+    ],
+    sdk_version: "test_current",
+    data: [
+        ":read_api_test_storage_files",
+    ],
+    test_suites: [
+        "general-tests",
+    ],
+    test_config: "AconfigStorageReadUnitTest.xml",
+    jarjar_rules: "jarjar.txt",
+}
diff --git a/tools/aconfig/aconfig_storage_read_api/tests/java/AndroidManifest.xml b/tools/aconfig/aconfig_storage_read_api/tests/AndroidManifest.xml
similarity index 89%
rename from tools/aconfig/aconfig_storage_read_api/tests/java/AndroidManifest.xml
rename to tools/aconfig/aconfig_storage_read_api/tests/AndroidManifest.xml
index 78bfb37dc9..5e01879157 100644
--- a/tools/aconfig/aconfig_storage_read_api/tests/java/AndroidManifest.xml
+++ b/tools/aconfig/aconfig_storage_read_api/tests/AndroidManifest.xml
@@ -15,12 +15,13 @@
   ~ limitations under the License.
   -->
 
-<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="android.aconfig_storage.test">
+<manifest xmlns:android="http://schemas.android.com/apk/res/android"
+    package="android.aconfig.storage.test">
     <application>
         <uses-library android:name="android.test.runner" />
     </application>
 
     <instrumentation android:name="androidx.test.runner.AndroidJUnitRunner"
-                     android:targetPackage="android.aconfig_storage.test" />
+                     android:targetPackage="android.aconfig.storage.test" />
 
 </manifest>
diff --git a/tools/aconfig/aconfig_storage_read_api/tests/flag.info b/tools/aconfig/aconfig_storage_read_api/tests/data/v1/flag_v1.info
similarity index 100%
rename from tools/aconfig/aconfig_storage_read_api/tests/flag.info
rename to tools/aconfig/aconfig_storage_read_api/tests/data/v1/flag_v1.info
diff --git a/tools/aconfig/aconfig_storage_read_api/tests/flag.map b/tools/aconfig/aconfig_storage_read_api/tests/data/v1/flag_v1.map
similarity index 100%
rename from tools/aconfig/aconfig_storage_read_api/tests/flag.map
rename to tools/aconfig/aconfig_storage_read_api/tests/data/v1/flag_v1.map
diff --git a/tools/aconfig/aconfig_storage_read_api/tests/flag.val b/tools/aconfig/aconfig_storage_read_api/tests/data/v1/flag_v1.val
similarity index 100%
rename from tools/aconfig/aconfig_storage_read_api/tests/flag.val
rename to tools/aconfig/aconfig_storage_read_api/tests/data/v1/flag_v1.val
diff --git a/tools/aconfig/aconfig_storage_read_api/tests/package.map b/tools/aconfig/aconfig_storage_read_api/tests/data/v1/package_v1.map
similarity index 100%
rename from tools/aconfig/aconfig_storage_read_api/tests/package.map
rename to tools/aconfig/aconfig_storage_read_api/tests/data/v1/package_v1.map
diff --git a/tools/aconfig/aconfig_storage_read_api/tests/data/v2/flag_v2.info b/tools/aconfig/aconfig_storage_read_api/tests/data/v2/flag_v2.info
new file mode 100644
index 0000000000..9db7fde7ae
Binary files /dev/null and b/tools/aconfig/aconfig_storage_read_api/tests/data/v2/flag_v2.info differ
diff --git a/tools/aconfig/aconfig_storage_read_api/tests/data/v2/flag_v2.map b/tools/aconfig/aconfig_storage_read_api/tests/data/v2/flag_v2.map
new file mode 100644
index 0000000000..cf4685ceb4
Binary files /dev/null and b/tools/aconfig/aconfig_storage_read_api/tests/data/v2/flag_v2.map differ
diff --git a/tools/aconfig/aconfig_storage_read_api/tests/data/v2/flag_v2.val b/tools/aconfig/aconfig_storage_read_api/tests/data/v2/flag_v2.val
new file mode 100644
index 0000000000..37d4750206
Binary files /dev/null and b/tools/aconfig/aconfig_storage_read_api/tests/data/v2/flag_v2.val differ
diff --git a/tools/aconfig/aconfig_storage_read_api/tests/data/v2/package_v2.map b/tools/aconfig/aconfig_storage_read_api/tests/data/v2/package_v2.map
new file mode 100644
index 0000000000..0a9f95ec85
Binary files /dev/null and b/tools/aconfig/aconfig_storage_read_api/tests/data/v2/package_v2.map differ
diff --git a/tools/aconfig/aconfig_storage_read_api/tests/java/AconfigStorageReadAPITest.java b/tools/aconfig/aconfig_storage_read_api/tests/functional/srcs/AconfigStorageReadAPITest.java
similarity index 99%
rename from tools/aconfig/aconfig_storage_read_api/tests/java/AconfigStorageReadAPITest.java
rename to tools/aconfig/aconfig_storage_read_api/tests/functional/srcs/AconfigStorageReadAPITest.java
index 191741ef51..6dd1bce94e 100644
--- a/tools/aconfig/aconfig_storage_read_api/tests/java/AconfigStorageReadAPITest.java
+++ b/tools/aconfig/aconfig_storage_read_api/tests/functional/srcs/AconfigStorageReadAPITest.java
@@ -267,4 +267,4 @@ public class AconfigStorageReadAPITest {
             assertEquals(rVal, jVal);
         }
     }
-}
+}
\ No newline at end of file
diff --git a/tools/aconfig/aconfig_storage_read_api/tests/functional/srcs/PlatformAconfigPackageInternalTest.java b/tools/aconfig/aconfig_storage_read_api/tests/functional/srcs/PlatformAconfigPackageInternalTest.java
new file mode 100644
index 0000000000..69e224b5a6
--- /dev/null
+++ b/tools/aconfig/aconfig_storage_read_api/tests/functional/srcs/PlatformAconfigPackageInternalTest.java
@@ -0,0 +1,128 @@
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
+import static org.junit.Assert.assertThrows;
+
+import android.aconfig.DeviceProtos;
+import android.aconfig.nano.Aconfig;
+import android.aconfig.nano.Aconfig.parsed_flag;
+import android.aconfig.storage.FlagTable;
+import android.aconfig.storage.FlagValueList;
+import android.aconfig.storage.PackageTable;
+import android.aconfig.storage.StorageFileProvider;
+import android.os.flagging.AconfigStorageReadException;
+import android.os.flagging.PlatformAconfigPackageInternal;
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
+public class PlatformAconfigPackageInternalTest {
+
+    private static final Set<String> PLATFORM_CONTAINERS = Set.of("system", "vendor", "product");
+
+    @Test
+    public void testAconfigPackageInternal_load() throws IOException {
+        List<parsed_flag> flags = DeviceProtos.loadAndParseFlagProtos();
+        Map<String, PlatformAconfigPackageInternal> readerMap = new HashMap<>();
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
+            PlatformAconfigPackageInternal reader = readerMap.get(packageName);
+            if (reader == null) {
+                reader = PlatformAconfigPackageInternal.load(container, packageName, fingerprint);
+                readerMap.put(packageName, reader);
+            }
+            boolean jVal = reader.getBooleanFlagValue(fNode.getFlagIndex());
+
+            assertEquals(rVal, jVal);
+        }
+    }
+
+    @Test
+    public void testAconfigPackage_load_withError() throws IOException {
+        // container not found fake_container
+        AconfigStorageReadException e =
+                assertThrows(
+                        AconfigStorageReadException.class,
+                        () ->
+                                PlatformAconfigPackageInternal.load(
+                                        "fake_container", "fake_package", 0));
+        assertEquals(AconfigStorageReadException.ERROR_CANNOT_READ_STORAGE_FILE, e.getErrorCode());
+
+        // package not found
+        e =
+                assertThrows(
+                        AconfigStorageReadException.class,
+                        () -> PlatformAconfigPackageInternal.load("system", "fake_container", 0));
+        assertEquals(AconfigStorageReadException.ERROR_PACKAGE_NOT_FOUND, e.getErrorCode());
+
+        // fingerprint doesn't match
+        List<parsed_flag> flags = DeviceProtos.loadAndParseFlagProtos();
+        StorageFileProvider fp = StorageFileProvider.getDefaultProvider();
+
+        parsed_flag flag = flags.get(0);
+
+        String container = flag.container;
+        String packageName = flag.package_;
+        boolean value = flag.state == Aconfig.ENABLED;
+
+        PackageTable pTable = fp.getPackageTable(container);
+        PackageTable.Node pNode = pTable.get(packageName);
+
+        if (pNode.hasPackageFingerprint()) {
+            long fingerprint = pNode.getPackageFingerprint();
+            e =
+                    assertThrows(
+                            AconfigStorageReadException.class,
+                            () ->
+                                    PlatformAconfigPackageInternal.load(
+                                            container, packageName, fingerprint + 1));
+            assertEquals(
+                    // AconfigStorageException.ERROR_FILE_FINGERPRINT_MISMATCH,
+                    5, e.getErrorCode());
+        }
+    }
+}
diff --git a/tools/aconfig/aconfig_storage_read_api/tests/java/StorageInternalReaderTest.java b/tools/aconfig/aconfig_storage_read_api/tests/functional/srcs/StorageInternalReaderTest.java
similarity index 99%
rename from tools/aconfig/aconfig_storage_read_api/tests/java/StorageInternalReaderTest.java
rename to tools/aconfig/aconfig_storage_read_api/tests/functional/srcs/StorageInternalReaderTest.java
index 3a1bba0fad..8a8f054d63 100644
--- a/tools/aconfig/aconfig_storage_read_api/tests/java/StorageInternalReaderTest.java
+++ b/tools/aconfig/aconfig_storage_read_api/tests/functional/srcs/StorageInternalReaderTest.java
@@ -42,4 +42,4 @@ public class StorageInternalReaderTest {
         assertFalse(reader.getBooleanFlagValue(0));
         assertTrue(reader.getBooleanFlagValue(1));
     }
-}
+}
\ No newline at end of file
diff --git a/tools/aconfig/aconfig_storage_read_api/tests/jarjar.txt b/tools/aconfig/aconfig_storage_read_api/tests/jarjar.txt
new file mode 100644
index 0000000000..49250d4202
--- /dev/null
+++ b/tools/aconfig/aconfig_storage_read_api/tests/jarjar.txt
@@ -0,0 +1,19 @@
+rule android.aconfig.storage.AconfigStorageException android.aconfig.storage.test.AconfigStorageException
+rule android.aconfig.storage.FlagTable android.aconfig.storage.test.FlagTable
+rule android.aconfig.storage.PackageTable android.aconfig.storage.test.PackageTable
+rule android.aconfig.storage.ByteBufferReader android.aconfig.storage.test.ByteBufferReader
+rule android.aconfig.storage.FlagType android.aconfig.storage.test.FlagType
+rule android.aconfig.storage.SipHasher13 android.aconfig.storage.test.SipHasher13
+rule android.aconfig.storage.FileType android.aconfig.storage.test.FileType
+rule android.aconfig.storage.FlagValueList android.aconfig.storage.test.FlagValueList
+rule android.aconfig.storage.TableUtils android.aconfig.storage.test.TableUtils
+rule android.aconfig.storage.AconfigPackageImpl android.aconfig.storage.test.AconfigPackageImpl
+rule android.aconfig.storage.StorageFileProvider android.aconfig.storage.test.StorageFileProvider
+
+
+rule android.aconfig.storage.FlagTable$* android.aconfig.storage.test.FlagTable$@1
+rule android.aconfig.storage.PackageTable$* android.aconfig.storage.test.PackageTable$@1
+rule android.aconfig.storage.FlagValueList$* android.aconfig.storage.test.FlagValueList@1
+rule android.aconfig.storage.SipHasher13$* android.aconfig.storage.test.SipHasher13@1
+
+rule android.os.flagging.PlatformAconfigPackageInternal android.aconfig.storage.test.PlatformAconfigPackageInternal
diff --git a/tools/aconfig/aconfig_storage_read_api/tests/java/Android.bp b/tools/aconfig/aconfig_storage_read_api/tests/java/Android.bp
deleted file mode 100644
index 3d4e9ad218..0000000000
--- a/tools/aconfig/aconfig_storage_read_api/tests/java/Android.bp
+++ /dev/null
@@ -1,24 +0,0 @@
-android_test {
-    name: "aconfig_storage_read_api.test.java",
-    srcs: ["./**/*.java"],
-    static_libs: [
-        "aconfig_device_paths_java",
-        "aconfig_storage_file_java",
-        "aconfig_storage_reader_java",
-        "androidx.test.rules",
-        "libaconfig_storage_read_api_java",
-        "junit",
-    ],
-    jni_libs: [
-        "libaconfig_storage_read_api_rust_jni",
-    ],
-    data: [
-        ":read_api_test_storage_files",
-    ],
-    platform_apis: true,
-    certificate: "platform",
-    test_suites: [
-        "general-tests",
-    ],
-    team: "trendy_team_android_core_experiments",
-}
diff --git a/tools/aconfig/aconfig_storage_read_api/tests/storage_read_api_test.cpp b/tools/aconfig/aconfig_storage_read_api/tests/storage_read_api_test.cpp
index 6d29045efe..5289faa6de 100644
--- a/tools/aconfig/aconfig_storage_read_api/tests/storage_read_api_test.cpp
+++ b/tools/aconfig/aconfig_storage_read_api/tests/storage_read_api_test.cpp
@@ -45,7 +45,8 @@ class AconfigStorageTest : public ::testing::Test {
   }
 
   void SetUp() override {
-    auto const test_dir = android::base::GetExecutableDirectory();
+    auto const test_base_dir = android::base::GetExecutableDirectory();
+    auto const test_dir = test_base_dir + "/data/v1";
     storage_dir = std::string(root_dir.path);
     auto maps_dir = storage_dir + "/maps";
     auto boot_dir = storage_dir + "/boot";
@@ -55,10 +56,10 @@ class AconfigStorageTest : public ::testing::Test {
     flag_map = std::string(maps_dir) + "/mockup.flag.map";
     flag_val = std::string(boot_dir) + "/mockup.val";
     flag_info = std::string(boot_dir) + "/mockup.info";
-    copy_file(test_dir + "/package.map", package_map);
-    copy_file(test_dir + "/flag.map", flag_map);
-    copy_file(test_dir + "/flag.val", flag_val);
-    copy_file(test_dir + "/flag.info", flag_info);
+    copy_file(test_dir + "/package_v1.map", package_map);
+    copy_file(test_dir + "/flag_v1.map", flag_map);
+    copy_file(test_dir + "/flag_v1.val", flag_val);
+    copy_file(test_dir + "/flag_v1.info", flag_info);
   }
 
   void TearDown() override {
diff --git a/tools/aconfig/aconfig_storage_read_api/tests/storage_read_api_test.rs b/tools/aconfig/aconfig_storage_read_api/tests/storage_read_api_test.rs
index afc44d4d70..2a8edf3302 100644
--- a/tools/aconfig/aconfig_storage_read_api/tests/storage_read_api_test.rs
+++ b/tools/aconfig/aconfig_storage_read_api/tests/storage_read_api_test.rs
@@ -9,7 +9,7 @@ mod aconfig_storage_rust_test {
     use rand::Rng;
     use std::fs;
 
-    fn create_test_storage_files() -> String {
+    fn create_test_storage_files(version: u32) -> String {
         let mut rng = rand::thread_rng();
         let number: u32 = rng.gen();
         let storage_dir = String::from("/tmp/") + &number.to_string();
@@ -26,17 +26,17 @@ mod aconfig_storage_rust_test {
         let flag_map = storage_dir.clone() + "/maps/mockup.flag.map";
         let flag_val = storage_dir.clone() + "/boot/mockup.val";
         let flag_info = storage_dir.clone() + "/boot/mockup.info";
-        fs::copy("./package.map", package_map).unwrap();
-        fs::copy("./flag.map", flag_map).unwrap();
-        fs::copy("./flag.val", flag_val).unwrap();
-        fs::copy("./flag.info", flag_info).unwrap();
+        fs::copy(format!("./data/v{0}/package_v{0}.map", version), package_map).unwrap();
+        fs::copy(format!("./data/v{0}/flag_v{0}.map", version), flag_map).unwrap();
+        fs::copy(format!("./data/v{}/flag_v{0}.val", version), flag_val).unwrap();
+        fs::copy(format!("./data/v{}/flag_v{0}.info", version), flag_info).unwrap();
 
         storage_dir
     }
 
     #[test]
-    fn test_unavailable_stoarge() {
-        let storage_dir = create_test_storage_files();
+    fn test_unavailable_storage() {
+        let storage_dir = create_test_storage_files(1);
         // SAFETY:
         // The safety here is ensured as the test process will not write to temp storage file
         let err = unsafe {
@@ -53,7 +53,7 @@ mod aconfig_storage_rust_test {
 
     #[test]
     fn test_package_context_query() {
-        let storage_dir = create_test_storage_files();
+        let storage_dir = create_test_storage_files(1);
         // SAFETY:
         // The safety here is ensured as the test process will not write to temp storage file
         let package_mapped_file = unsafe {
@@ -64,27 +64,73 @@ mod aconfig_storage_rust_test {
             get_package_read_context(&package_mapped_file, "com.android.aconfig.storage.test_1")
                 .unwrap()
                 .unwrap();
-        let expected_package_context = PackageReadContext { package_id: 0, boolean_start_index: 0 };
+        let expected_package_context =
+            PackageReadContext { package_id: 0, boolean_start_index: 0, fingerprint: 0 };
         assert_eq!(package_context, expected_package_context);
 
         let package_context =
             get_package_read_context(&package_mapped_file, "com.android.aconfig.storage.test_2")
                 .unwrap()
                 .unwrap();
-        let expected_package_context = PackageReadContext { package_id: 1, boolean_start_index: 3 };
+        let expected_package_context =
+            PackageReadContext { package_id: 1, boolean_start_index: 3, fingerprint: 0 };
         assert_eq!(package_context, expected_package_context);
 
         let package_context =
             get_package_read_context(&package_mapped_file, "com.android.aconfig.storage.test_4")
                 .unwrap()
                 .unwrap();
-        let expected_package_context = PackageReadContext { package_id: 2, boolean_start_index: 6 };
+        let expected_package_context =
+            PackageReadContext { package_id: 2, boolean_start_index: 6, fingerprint: 0 };
+        assert_eq!(package_context, expected_package_context);
+    }
+
+    #[test]
+    fn test_package_context_query_with_fingerprint() {
+        let storage_dir = create_test_storage_files(2);
+        // SAFETY:
+        // The safety here is ensured as the test process will not write to temp storage file
+        let package_mapped_file = unsafe {
+            get_mapped_file(&storage_dir, "mockup", StorageFileType::PackageMap).unwrap()
+        };
+
+        let package_context =
+            get_package_read_context(&package_mapped_file, "com.android.aconfig.storage.test_1")
+                .unwrap()
+                .unwrap();
+        let expected_package_context = PackageReadContext {
+            package_id: 0,
+            boolean_start_index: 0,
+            fingerprint: 15248948510590158086u64,
+        };
+        assert_eq!(package_context, expected_package_context);
+
+        let package_context =
+            get_package_read_context(&package_mapped_file, "com.android.aconfig.storage.test_2")
+                .unwrap()
+                .unwrap();
+        let expected_package_context = PackageReadContext {
+            package_id: 1,
+            boolean_start_index: 3,
+            fingerprint: 4431940502274857964u64,
+        };
+        assert_eq!(package_context, expected_package_context);
+
+        let package_context =
+            get_package_read_context(&package_mapped_file, "com.android.aconfig.storage.test_4")
+                .unwrap()
+                .unwrap();
+        let expected_package_context = PackageReadContext {
+            package_id: 2,
+            boolean_start_index: 6,
+            fingerprint: 16233229917711622375u64,
+        };
         assert_eq!(package_context, expected_package_context);
     }
 
     #[test]
     fn test_none_exist_package_context_query() {
-        let storage_dir = create_test_storage_files();
+        let storage_dir = create_test_storage_files(1);
         // SAFETY:
         // The safety here is ensured as the test process will not write to temp storage file
         let package_mapped_file = unsafe {
@@ -99,7 +145,7 @@ mod aconfig_storage_rust_test {
 
     #[test]
     fn test_flag_context_query() {
-        let storage_dir = create_test_storage_files();
+        let storage_dir = create_test_storage_files(1);
         // SAFETY:
         // The safety here is ensured as the test process will not write to temp storage file
         let flag_mapped_file =
@@ -125,7 +171,7 @@ mod aconfig_storage_rust_test {
 
     #[test]
     fn test_none_exist_flag_context_query() {
-        let storage_dir = create_test_storage_files();
+        let storage_dir = create_test_storage_files(1);
         // SAFETY:
         // The safety here is ensured as the test process will not write to temp storage file
         let flag_mapped_file =
@@ -141,7 +187,7 @@ mod aconfig_storage_rust_test {
 
     #[test]
     fn test_boolean_flag_value_query() {
-        let storage_dir = create_test_storage_files();
+        let storage_dir = create_test_storage_files(1);
         // SAFETY:
         // The safety here is ensured as the test process will not write to temp storage file
         let flag_value_file =
@@ -155,7 +201,7 @@ mod aconfig_storage_rust_test {
 
     #[test]
     fn test_invalid_boolean_flag_value_query() {
-        let storage_dir = create_test_storage_files();
+        let storage_dir = create_test_storage_files(1);
         // SAFETY:
         // The safety here is ensured as the test process will not write to temp storage file
         let flag_value_file =
@@ -169,7 +215,7 @@ mod aconfig_storage_rust_test {
 
     #[test]
     fn test_flag_info_query() {
-        let storage_dir = create_test_storage_files();
+        let storage_dir = create_test_storage_files(1);
         // SAFETY:
         // The safety here is ensured as the test process will not write to temp storage file
         let flag_info_file =
@@ -186,7 +232,7 @@ mod aconfig_storage_rust_test {
 
     #[test]
     fn test_invalid_boolean_flag_info_query() {
-        let storage_dir = create_test_storage_files();
+        let storage_dir = create_test_storage_files(1);
         // SAFETY:
         // The safety here is ensured as the test process will not write to temp storage file
         let flag_info_file =
@@ -199,10 +245,18 @@ mod aconfig_storage_rust_test {
     }
 
     #[test]
-    fn test_storage_version_query() {
-        assert_eq!(get_storage_file_version("./package.map").unwrap(), 1);
-        assert_eq!(get_storage_file_version("./flag.map").unwrap(), 1);
-        assert_eq!(get_storage_file_version("./flag.val").unwrap(), 1);
-        assert_eq!(get_storage_file_version("./flag.info").unwrap(), 1);
+    fn test_storage_version_query_v1() {
+        assert_eq!(get_storage_file_version("./data/v1/package_v1.map").unwrap(), 1);
+        assert_eq!(get_storage_file_version("./data/v1/flag_v1.map").unwrap(), 1);
+        assert_eq!(get_storage_file_version("./data/v1/flag_v1.val").unwrap(), 1);
+        assert_eq!(get_storage_file_version("./data/v1/flag_v1.info").unwrap(), 1);
+    }
+
+    #[test]
+    fn test_storage_version_query_v2() {
+        assert_eq!(get_storage_file_version("./data/v2/package_v2.map").unwrap(), 2);
+        assert_eq!(get_storage_file_version("./data/v2/flag_v2.map").unwrap(), 2);
+        assert_eq!(get_storage_file_version("./data/v2/flag_v2.val").unwrap(), 2);
+        assert_eq!(get_storage_file_version("./data/v2/flag_v2.info").unwrap(), 2);
     }
 }
diff --git a/tools/aconfig/aconfig_storage_read_api/tests/unit/srcs/PlatformAconfigPackageInternalTest.java b/tools/aconfig/aconfig_storage_read_api/tests/unit/srcs/PlatformAconfigPackageInternalTest.java
new file mode 100644
index 0000000000..961f0ea7ff
--- /dev/null
+++ b/tools/aconfig/aconfig_storage_read_api/tests/unit/srcs/PlatformAconfigPackageInternalTest.java
@@ -0,0 +1,152 @@
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
+import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.assertThrows;
+import static org.junit.Assert.assertTrue;
+
+import android.aconfig.storage.PackageTable;
+import android.aconfig.storage.StorageFileProvider;
+import android.os.flagging.AconfigStorageReadException;
+import android.os.flagging.PlatformAconfigPackageInternal;
+
+import org.junit.Before;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
+@RunWith(JUnit4.class)
+public class PlatformAconfigPackageInternalTest {
+
+    public static final String TESTDATA_PATH =
+            "/data/local/tmp/aconfig_storage_read_unit/testdata/";
+
+    private StorageFileProvider pr;
+
+    @Before
+    public void setup() {
+        pr = new StorageFileProvider(TESTDATA_PATH, TESTDATA_PATH);
+    }
+
+    @Test
+    public void testLoad_container_package() throws Exception {
+        PackageTable packageTable = pr.getPackageTable("mockup");
+
+        PackageTable.Node node1 = packageTable.get("com.android.aconfig.storage.test_1");
+
+        long fingerprint = node1.getPackageFingerprint();
+        PlatformAconfigPackageInternal p =
+                PlatformAconfigPackageInternal.load(
+                        "mockup", "com.android.aconfig.storage.test_1", fingerprint, pr);
+    }
+
+    @Test
+    public void testLoad_container_package_error() throws Exception {
+        PackageTable packageTable = pr.getPackageTable("mockup");
+        PackageTable.Node node1 = packageTable.get("com.android.aconfig.storage.test_1");
+        long fingerprint = node1.getPackageFingerprint();
+        // cannot find package
+        AconfigStorageReadException e =
+                assertThrows(
+                        AconfigStorageReadException.class,
+                        () ->
+                                PlatformAconfigPackageInternal.load(
+                                        "mockup",
+                                        "com.android.aconfig.storage.test_10",
+                                        fingerprint,
+                                        pr));
+        assertEquals(AconfigStorageReadException.ERROR_PACKAGE_NOT_FOUND, e.getErrorCode());
+
+        // cannot find container
+        e =
+                assertThrows(
+                        AconfigStorageReadException.class,
+                        () ->
+                                PlatformAconfigPackageInternal.load(
+                                        null,
+                                        "com.android.aconfig.storage.test_1",
+                                        fingerprint,
+                                        pr));
+        assertEquals(AconfigStorageReadException.ERROR_CANNOT_READ_STORAGE_FILE, e.getErrorCode());
+
+        e =
+                assertThrows(
+                        AconfigStorageReadException.class,
+                        () ->
+                                PlatformAconfigPackageInternal.load(
+                                        "test",
+                                        "com.android.aconfig.storage.test_1",
+                                        fingerprint,
+                                        pr));
+        assertEquals(AconfigStorageReadException.ERROR_CANNOT_READ_STORAGE_FILE, e.getErrorCode());
+
+        // fingerprint doesn't match
+        e =
+                assertThrows(
+                        AconfigStorageReadException.class,
+                        () ->
+                                PlatformAconfigPackageInternal.load(
+                                        "mockup",
+                                        "com.android.aconfig.storage.test_1",
+                                        fingerprint + 1,
+                                        pr));
+        assertEquals(
+                // AconfigStorageException.ERROR_FILE_FINGERPRINT_MISMATCH,
+                5, e.getErrorCode());
+
+        // new storage doesn't exist
+        pr = new StorageFileProvider("fake/path/", "fake/path/");
+        e =
+                assertThrows(
+                        AconfigStorageReadException.class,
+                        () ->
+                                PlatformAconfigPackageInternal.load(
+                                        "mockup",
+                                        "com.android.aconfig.storage.test_1",
+                                        fingerprint,
+                                        pr));
+        assertEquals(AconfigStorageReadException.ERROR_CANNOT_READ_STORAGE_FILE, e.getErrorCode());
+
+        // file read issue
+        pr = new StorageFileProvider(TESTDATA_PATH, "fake/path/");
+        e =
+                assertThrows(
+                        AconfigStorageReadException.class,
+                        () ->
+                                PlatformAconfigPackageInternal.load(
+                                        "mockup",
+                                        "com.android.aconfig.storage.test_1",
+                                        fingerprint,
+                                        pr));
+        assertEquals(AconfigStorageReadException.ERROR_CANNOT_READ_STORAGE_FILE, e.getErrorCode());
+    }
+
+    @Test
+    public void testGetBooleanFlagValue_index() throws Exception {
+        PackageTable packageTable = pr.getPackageTable("mockup");
+        PackageTable.Node node1 = packageTable.get("com.android.aconfig.storage.test_1");
+        long fingerprint = node1.getPackageFingerprint();
+        PlatformAconfigPackageInternal p =
+                PlatformAconfigPackageInternal.load(
+                        "mockup", "com.android.aconfig.storage.test_1", fingerprint, pr);
+        assertFalse(p.getBooleanFlagValue(0));
+        assertTrue(p.getBooleanFlagValue(1));
+        assertTrue(p.getBooleanFlagValue(2));
+    }
+}
diff --git a/tools/aconfig/aconfig_storage_write_api/Android.bp b/tools/aconfig/aconfig_storage_write_api/Android.bp
index 0f1962c3ac..4c882b4b9a 100644
--- a/tools/aconfig/aconfig_storage_write_api/Android.bp
+++ b/tools/aconfig/aconfig_storage_write_api/Android.bp
@@ -16,6 +16,11 @@ rust_defaults {
         "libaconfig_storage_file",
         "libaconfig_storage_read_api",
     ],
+    min_sdk_version: "34",
+    apex_available: [
+        "//apex_available:anyapex",
+        "//apex_available:platform",
+    ],
 }
 
 rust_library {
diff --git a/tools/aconfig/aconfig_storage_write_api/aconfig_storage_write_api.cpp b/tools/aconfig/aconfig_storage_write_api/aconfig_storage_write_api.cpp
index 7b435746da..03a8fa284a 100644
--- a/tools/aconfig/aconfig_storage_write_api/aconfig_storage_write_api.cpp
+++ b/tools/aconfig/aconfig_storage_write_api/aconfig_storage_write_api.cpp
@@ -100,18 +100,4 @@ android::base::Result<void> set_flag_has_local_override(
   return {};
 }
 
-android::base::Result<void> create_flag_info(
-    std::string const& package_map,
-    std::string const& flag_map,
-    std::string const& flag_info_out) {
-  auto creation_cxx = create_flag_info_cxx(
-      rust::Str(package_map.c_str()),
-      rust::Str(flag_map.c_str()),
-      rust::Str(flag_info_out.c_str()));
-  if (creation_cxx.success) {
-    return {};
-  } else {
-    return android::base::Error() << creation_cxx.error_message;
-  }
-}
 } // namespace aconfig_storage
diff --git a/tools/aconfig/aconfig_storage_write_api/include/aconfig_storage/aconfig_storage_write_api.hpp b/tools/aconfig/aconfig_storage_write_api/include/aconfig_storage/aconfig_storage_write_api.hpp
index 0bba7ffcfc..50a51889b1 100644
--- a/tools/aconfig/aconfig_storage_write_api/include/aconfig_storage/aconfig_storage_write_api.hpp
+++ b/tools/aconfig/aconfig_storage_write_api/include/aconfig_storage/aconfig_storage_write_api.hpp
@@ -36,13 +36,4 @@ android::base::Result<void> set_flag_has_local_override(
     uint32_t offset,
     bool value);
 
-/// Create flag info file based on package and flag map
-/// \input package_map: package map file
-/// \input flag_map: flag map file
-/// \input flag_info_out: flag info file to be created
-android::base::Result<void> create_flag_info(
-    std::string const& package_map,
-    std::string const& flag_map,
-    std::string const& flag_info_out);
-
 } // namespace aconfig_storage
diff --git a/tools/aconfig/aconfig_storage_write_api/src/flag_info_update.rs b/tools/aconfig/aconfig_storage_write_api/src/flag_info_update.rs
index 7e6071340c..5721105d86 100644
--- a/tools/aconfig/aconfig_storage_write_api/src/flag_info_update.rs
+++ b/tools/aconfig/aconfig_storage_write_api/src/flag_info_update.rs
@@ -18,7 +18,7 @@
 
 use aconfig_storage_file::{
     read_u8_from_bytes, AconfigStorageError, FlagInfoBit, FlagInfoHeader, FlagValueType,
-    FILE_VERSION,
+    MAX_SUPPORTED_FILE_VERSION,
 };
 use anyhow::anyhow;
 
@@ -28,11 +28,11 @@ fn get_flag_info_offset(
     flag_index: u32,
 ) -> Result<usize, AconfigStorageError> {
     let interpreted_header = FlagInfoHeader::from_bytes(buf)?;
-    if interpreted_header.version > FILE_VERSION {
+    if interpreted_header.version > MAX_SUPPORTED_FILE_VERSION {
         return Err(AconfigStorageError::HigherStorageFileVersion(anyhow!(
             "Cannot write to storage file with a higher version of {} with lib version {}",
             interpreted_header.version,
-            FILE_VERSION
+            MAX_SUPPORTED_FILE_VERSION
         )));
     }
 
@@ -94,13 +94,13 @@ pub fn update_flag_has_local_override(
 #[cfg(test)]
 mod tests {
     use super::*;
-    use aconfig_storage_file::test_utils::create_test_flag_info_list;
+    use aconfig_storage_file::{test_utils::create_test_flag_info_list, DEFAULT_FILE_VERSION};
     use aconfig_storage_read_api::flag_info_query::find_flag_attribute;
 
     #[test]
     // this test point locks down has server override update
     fn test_update_flag_has_server_override() {
-        let flag_info_list = create_test_flag_info_list();
+        let flag_info_list = create_test_flag_info_list(DEFAULT_FILE_VERSION);
         let mut buf = flag_info_list.into_bytes();
         for i in 0..flag_info_list.header.num_flags {
             update_flag_has_server_override(&mut buf, FlagValueType::Boolean, i, true).unwrap();
@@ -115,7 +115,7 @@ mod tests {
     #[test]
     // this test point locks down has local override update
     fn test_update_flag_has_local_override() {
-        let flag_info_list = create_test_flag_info_list();
+        let flag_info_list = create_test_flag_info_list(DEFAULT_FILE_VERSION);
         let mut buf = flag_info_list.into_bytes();
         for i in 0..flag_info_list.header.num_flags {
             update_flag_has_local_override(&mut buf, FlagValueType::Boolean, i, true).unwrap();
diff --git a/tools/aconfig/aconfig_storage_write_api/src/flag_value_update.rs b/tools/aconfig/aconfig_storage_write_api/src/flag_value_update.rs
index dd15c996a6..9772db9ee8 100644
--- a/tools/aconfig/aconfig_storage_write_api/src/flag_value_update.rs
+++ b/tools/aconfig/aconfig_storage_write_api/src/flag_value_update.rs
@@ -16,7 +16,7 @@
 
 //! flag value update module defines the flag value file write to mapped bytes
 
-use aconfig_storage_file::{AconfigStorageError, FlagValueHeader, FILE_VERSION};
+use aconfig_storage_file::{AconfigStorageError, FlagValueHeader, MAX_SUPPORTED_FILE_VERSION};
 use anyhow::anyhow;
 
 /// Set flag value
@@ -26,11 +26,11 @@ pub fn update_boolean_flag_value(
     flag_value: bool,
 ) -> Result<usize, AconfigStorageError> {
     let interpreted_header = FlagValueHeader::from_bytes(buf)?;
-    if interpreted_header.version > FILE_VERSION {
+    if interpreted_header.version > MAX_SUPPORTED_FILE_VERSION {
         return Err(AconfigStorageError::HigherStorageFileVersion(anyhow!(
             "Cannot write to storage file with a higher version of {} with lib version {}",
             interpreted_header.version,
-            FILE_VERSION
+            MAX_SUPPORTED_FILE_VERSION
         )));
     }
 
@@ -49,12 +49,12 @@ pub fn update_boolean_flag_value(
 #[cfg(test)]
 mod tests {
     use super::*;
-    use aconfig_storage_file::test_utils::create_test_flag_value_list;
+    use aconfig_storage_file::{test_utils::create_test_flag_value_list, DEFAULT_FILE_VERSION};
 
     #[test]
     // this test point locks down flag value update
     fn test_boolean_flag_value_update() {
-        let flag_value_list = create_test_flag_value_list();
+        let flag_value_list = create_test_flag_value_list(DEFAULT_FILE_VERSION);
         let value_offset = flag_value_list.header.boolean_value_offset;
         let mut content = flag_value_list.into_bytes();
         let true_byte = u8::from(true).to_le_bytes()[0];
@@ -72,7 +72,7 @@ mod tests {
     #[test]
     // this test point locks down update beyond the end of boolean section
     fn test_boolean_out_of_range() {
-        let mut flag_value_list = create_test_flag_value_list().into_bytes();
+        let mut flag_value_list = create_test_flag_value_list(DEFAULT_FILE_VERSION).into_bytes();
         let error = update_boolean_flag_value(&mut flag_value_list[..], 8, true).unwrap_err();
         assert_eq!(
             format!("{:?}", error),
@@ -83,16 +83,16 @@ mod tests {
     #[test]
     // this test point locks down query error when file has a higher version
     fn test_higher_version_storage_file() {
-        let mut value_list = create_test_flag_value_list();
-        value_list.header.version = FILE_VERSION + 1;
+        let mut value_list = create_test_flag_value_list(DEFAULT_FILE_VERSION);
+        value_list.header.version = MAX_SUPPORTED_FILE_VERSION + 1;
         let mut flag_value = value_list.into_bytes();
         let error = update_boolean_flag_value(&mut flag_value[..], 4, true).unwrap_err();
         assert_eq!(
             format!("{:?}", error),
             format!(
                 "HigherStorageFileVersion(Cannot write to storage file with a higher version of {} with lib version {})",
-                FILE_VERSION + 1,
-                FILE_VERSION
+                MAX_SUPPORTED_FILE_VERSION + 1,
+                MAX_SUPPORTED_FILE_VERSION
             )
         );
     }
diff --git a/tools/aconfig/aconfig_storage_write_api/src/lib.rs b/tools/aconfig/aconfig_storage_write_api/src/lib.rs
index 0396a63d4e..09bb41f54f 100644
--- a/tools/aconfig/aconfig_storage_write_api/src/lib.rs
+++ b/tools/aconfig/aconfig_storage_write_api/src/lib.rs
@@ -24,15 +24,10 @@ pub mod mapped_file;
 #[cfg(test)]
 mod test_utils;
 
-use aconfig_storage_file::{
-    AconfigStorageError, FlagInfoHeader, FlagInfoList, FlagInfoNode, FlagTable, FlagValueType,
-    PackageTable, StorageFileType, StoredFlagType, FILE_VERSION,
-};
+use aconfig_storage_file::{AconfigStorageError, FlagValueType};
 
 use anyhow::anyhow;
 use memmap2::MmapMut;
-use std::fs::File;
-use std::io::{Read, Write};
 
 /// Get read write mapped storage files.
 ///
@@ -104,86 +99,6 @@ pub fn set_flag_has_local_override(
     })
 }
 
-/// Read in storage file as bytes
-fn read_file_to_bytes(file_path: &str) -> Result<Vec<u8>, AconfigStorageError> {
-    let mut file = File::open(file_path).map_err(|errmsg| {
-        AconfigStorageError::FileReadFail(anyhow!("Failed to open file {}: {}", file_path, errmsg))
-    })?;
-    let mut buffer = Vec::new();
-    file.read_to_end(&mut buffer).map_err(|errmsg| {
-        AconfigStorageError::FileReadFail(anyhow!(
-            "Failed to read bytes from file {}: {}",
-            file_path,
-            errmsg
-        ))
-    })?;
-    Ok(buffer)
-}
-
-/// Create flag info file given package map file and flag map file
-/// \input package_map: package map file
-/// \input flag_map: flag map file
-/// \output flag_info_out: created flag info file
-pub fn create_flag_info(
-    package_map: &str,
-    flag_map: &str,
-    flag_info_out: &str,
-) -> Result<(), AconfigStorageError> {
-    let package_table = PackageTable::from_bytes(&read_file_to_bytes(package_map)?)?;
-    let flag_table = FlagTable::from_bytes(&read_file_to_bytes(flag_map)?)?;
-
-    if package_table.header.container != flag_table.header.container {
-        return Err(AconfigStorageError::FileCreationFail(anyhow!(
-            "container for package map {} and flag map {} does not match",
-            package_table.header.container,
-            flag_table.header.container,
-        )));
-    }
-
-    let mut package_start_index = vec![0; package_table.header.num_packages as usize];
-    for node in package_table.nodes.iter() {
-        package_start_index[node.package_id as usize] = node.boolean_start_index;
-    }
-
-    let mut is_flag_rw = vec![false; flag_table.header.num_flags as usize];
-    for node in flag_table.nodes.iter() {
-        let flag_index = package_start_index[node.package_id as usize] + node.flag_index as u32;
-        is_flag_rw[flag_index as usize] = node.flag_type == StoredFlagType::ReadWriteBoolean;
-    }
-
-    let mut list = FlagInfoList {
-        header: FlagInfoHeader {
-            version: FILE_VERSION,
-            container: flag_table.header.container,
-            file_type: StorageFileType::FlagInfo as u8,
-            file_size: 0,
-            num_flags: flag_table.header.num_flags,
-            boolean_flag_offset: 0,
-        },
-        nodes: is_flag_rw.iter().map(|&rw| FlagInfoNode::create(rw)).collect(),
-    };
-
-    list.header.boolean_flag_offset = list.header.into_bytes().len() as u32;
-    list.header.file_size = list.into_bytes().len() as u32;
-
-    let mut file = File::create(flag_info_out).map_err(|errmsg| {
-        AconfigStorageError::FileCreationFail(anyhow!(
-            "fail to create file {}: {}",
-            flag_info_out,
-            errmsg
-        ))
-    })?;
-    file.write_all(&list.into_bytes()).map_err(|errmsg| {
-        AconfigStorageError::FileCreationFail(anyhow!(
-            "fail to write to file {}: {}",
-            flag_info_out,
-            errmsg
-        ))
-    })?;
-
-    Ok(())
-}
-
 // *************************************** //
 // CC INTERLOP
 // *************************************** //
@@ -212,12 +127,6 @@ mod ffi {
         pub error_message: String,
     }
 
-    // Flag info file creation return for cc interlop
-    pub struct FlagInfoCreationCXX {
-        pub success: bool,
-        pub error_message: String,
-    }
-
     // Rust export to c++
     extern "Rust" {
         pub fn update_boolean_flag_value_cxx(
@@ -239,12 +148,6 @@ mod ffi {
             offset: u32,
             value: bool,
         ) -> FlagHasLocalOverrideUpdateCXX;
-
-        pub fn create_flag_info_cxx(
-            package_map: &str,
-            flag_map: &str,
-            flag_info_out: &str,
-        ) -> FlagInfoCreationCXX;
     }
 }
 
@@ -329,34 +232,15 @@ pub(crate) fn update_flag_has_local_override_cxx(
     }
 }
 
-/// Create flag info file cc interlop
-pub(crate) fn create_flag_info_cxx(
-    package_map: &str,
-    flag_map: &str,
-    flag_info_out: &str,
-) -> ffi::FlagInfoCreationCXX {
-    match create_flag_info(package_map, flag_map, flag_info_out) {
-        Ok(()) => ffi::FlagInfoCreationCXX { success: true, error_message: String::from("") },
-        Err(errmsg) => {
-            ffi::FlagInfoCreationCXX { success: false, error_message: format!("{:?}", errmsg) }
-        }
-    }
-}
-
 #[cfg(test)]
 mod tests {
     use super::*;
     use crate::test_utils::copy_to_temp_file;
-    use aconfig_storage_file::test_utils::{
-        create_test_flag_info_list, create_test_flag_table, create_test_package_table,
-        write_bytes_to_temp_file,
-    };
     use aconfig_storage_file::FlagInfoBit;
     use aconfig_storage_read_api::flag_info_query::find_flag_attribute;
     use aconfig_storage_read_api::flag_value_query::find_boolean_flag_value;
     use std::fs::File;
     use std::io::Read;
-    use tempfile::NamedTempFile;
 
     fn get_boolean_flag_value_at_offset(file: &str, offset: u32) -> bool {
         let mut f = File::open(&file).unwrap();
@@ -439,31 +323,4 @@ mod tests {
             }
         }
     }
-
-    fn create_empty_temp_file() -> Result<NamedTempFile, AconfigStorageError> {
-        let file = NamedTempFile::new().map_err(|_| {
-            AconfigStorageError::FileCreationFail(anyhow!("Failed to create temp file"))
-        })?;
-        Ok(file)
-    }
-
-    #[test]
-    // this test point locks down the flag info creation
-    fn test_create_flag_info() {
-        let package_table =
-            write_bytes_to_temp_file(&create_test_package_table().into_bytes()).unwrap();
-        let flag_table = write_bytes_to_temp_file(&create_test_flag_table().into_bytes()).unwrap();
-        let flag_info = create_empty_temp_file().unwrap();
-
-        let package_table_path = package_table.path().display().to_string();
-        let flag_table_path = flag_table.path().display().to_string();
-        let flag_info_path = flag_info.path().display().to_string();
-
-        assert!(create_flag_info(&package_table_path, &flag_table_path, &flag_info_path).is_ok());
-
-        let flag_info =
-            FlagInfoList::from_bytes(&read_file_to_bytes(&flag_info_path).unwrap()).unwrap();
-        let expected_flag_info = create_test_flag_info_list();
-        assert_eq!(flag_info, expected_flag_info);
-    }
 }
diff --git a/tools/aconfig/aflags/Android.bp b/tools/aconfig/aflags/Android.bp
index 2040cc635b..a7aceeebad 100644
--- a/tools/aconfig/aflags/Android.bp
+++ b/tools/aconfig/aflags/Android.bp
@@ -12,7 +12,7 @@ rust_defaults {
         "libaconfig_device_paths",
         "libaconfig_flags",
         "libaconfig_protos",
-        "libaconfigd_protos",
+        "libaconfigd_protos_rust",
         "libaconfig_storage_read_api",
         "libaconfig_storage_file",
         "libanyhow",
@@ -20,6 +20,10 @@ rust_defaults {
         "libnix",
         "libprotobuf",
         "libregex",
+        // TODO: b/371021174 remove this fake dependency once we find a proper strategy to
+        // deal with test aconfig libs are not present in storage because they are never used
+        // by the actual build
+        "libaconfig_test_rust_library",
     ],
 }
 
diff --git a/tools/aconfig/aflags/Cargo.toml b/tools/aconfig/aflags/Cargo.toml
index 7efce6dc96..d31e232975 100644
--- a/tools/aconfig/aflags/Cargo.toml
+++ b/tools/aconfig/aflags/Cargo.toml
@@ -9,10 +9,10 @@ paste = "1.0.11"
 protobuf = "3.2.0"
 regex = "1.10.3"
 aconfig_protos = { path = "../aconfig_protos" }
-aconfigd_protos = { version = "0.1.0", path = "../../../../../system/server_configurable_flags/aconfigd"}
+aconfigd_protos = { version = "0.1.0", path = "../../../../../packages/modules/ConfigInfrastructure/aconfigd/proto"}
 nix = { version = "0.28.0", features = ["user"] }
 aconfig_storage_file = { version = "0.1.0", path = "../aconfig_storage_file" }
 aconfig_storage_read_api = { version = "0.1.0", path = "../aconfig_storage_read_api" }
 clap = {version = "4.5.2" }
 aconfig_device_paths = { version = "0.1.0", path = "../aconfig_device_paths" }
-aconfig_flags = { version = "0.1.0", path = "../aconfig_flags" }
\ No newline at end of file
+aconfig_flags = { version = "0.1.0", path = "../aconfig_flags" }
diff --git a/tools/aconfig/aflags/src/aconfig_storage_source.rs b/tools/aconfig/aflags/src/aconfig_storage_source.rs
index 68edf7d3ac..aef7d7e6ab 100644
--- a/tools/aconfig/aflags/src/aconfig_storage_source.rs
+++ b/tools/aconfig/aflags/src/aconfig_storage_source.rs
@@ -93,7 +93,8 @@ fn read_from_socket() -> Result<Vec<ProtoFlagQueryReturnMessage>> {
         special_fields: SpecialFields::new(),
     };
 
-    let mut socket = UnixStream::connect("/dev/socket/aconfigd")?;
+    let socket_name = "/dev/socket/aconfigd_system";
+    let mut socket = UnixStream::connect(socket_name)?;
 
     let message_buffer = messages.write_to_bytes()?;
     let mut message_length_buffer: [u8; 4] = [0; 4];
diff --git a/tools/aconfig/aflags/src/load_protos.rs b/tools/aconfig/aflags/src/load_protos.rs
index 90d8599145..c5ac8ff9dc 100644
--- a/tools/aconfig/aflags/src/load_protos.rs
+++ b/tools/aconfig/aflags/src/load_protos.rs
@@ -51,7 +51,10 @@ pub(crate) fn load() -> Result<Vec<Flag>> {
 
     let paths = aconfig_device_paths::parsed_flags_proto_paths()?;
     for path in paths {
-        let bytes = fs::read(path.clone())?;
+        let Ok(bytes) = fs::read(&path) else {
+            eprintln!("warning: failed to read {:?}", path);
+            continue;
+        };
         let parsed_flags: ProtoParsedFlags = protobuf::Message::parse_from_bytes(&bytes)?;
         for flag in parsed_flags.parsed_flag {
             // TODO(b/334954748): enforce one-container-per-flag invariant.
@@ -60,3 +63,10 @@ pub(crate) fn load() -> Result<Vec<Flag>> {
     }
     Ok(result)
 }
+
+pub(crate) fn list_containers() -> Result<Vec<String>> {
+    Ok(aconfig_device_paths::parsed_flags_proto_paths()?
+        .into_iter()
+        .map(|p| infer_container(&p))
+        .collect())
+}
diff --git a/tools/aconfig/aflags/src/main.rs b/tools/aconfig/aflags/src/main.rs
index 07b7243ab4..8173bc24da 100644
--- a/tools/aconfig/aflags/src/main.rs
+++ b/tools/aconfig/aflags/src/main.rs
@@ -253,6 +253,14 @@ fn list(source_type: FlagSourceType, container: Option<String>) -> Result<String
         FlagSourceType::DeviceConfig => DeviceConfigSource::list_flags()?,
         FlagSourceType::AconfigStorage => AconfigStorageSource::list_flags()?,
     };
+
+    if let Some(ref c) = container {
+        ensure!(
+            load_protos::list_containers()?.contains(c),
+            format!("container '{}' not found", &c)
+        );
+    }
+
     let flags = (Filter { container }).apply(&flags_unfiltered);
     let padding_info = PaddingInfo {
         longest_flag_col: flags.iter().map(|f| f.qualified_name().len()).max().unwrap_or(0),
@@ -298,7 +306,7 @@ fn main() -> Result<()> {
         Command::List { container } => {
             if aconfig_flags::auto_generated::enable_only_new_storage() {
                 list(FlagSourceType::AconfigStorage, container)
-                    .map_err(|err| anyhow!("storage may not be enabled: {err}"))
+                    .map_err(|err| anyhow!("could not list flags: {err}"))
                     .map(Some)
             } else {
                 list(FlagSourceType::DeviceConfig, container).map(Some)
diff --git a/tools/aconfig/fake_device_config/Android.bp b/tools/aconfig/fake_device_config/Android.bp
index 7704742601..1c5b7c5967 100644
--- a/tools/aconfig/fake_device_config/Android.bp
+++ b/tools/aconfig/fake_device_config/Android.bp
@@ -15,9 +15,7 @@
 java_library {
     name: "fake_device_config",
     srcs: [
-        "src/android/util/Log.java",
-        "src/android/provider/DeviceConfig.java",
-        "src/android/os/StrictMode.java",
+        "src/**/*.java",
     ],
     sdk_version: "none",
     system_modules: "core-all-system-modules",
@@ -34,3 +32,24 @@ java_library {
     host_supported: true,
     is_stubs_module: true,
 }
+
+java_library {
+    name: "aconfig_storage_stub",
+    srcs: [
+        "src/android/os/flagging/**/*.java",
+    ],
+    sdk_version: "core_current",
+    host_supported: true,
+    is_stubs_module: true,
+}
+
+java_library {
+    name: "aconfig_storage_stub_none",
+    srcs: [
+        "src/android/os/flagging/**/*.java",
+    ],
+    sdk_version: "none",
+    system_modules: "core-all-system-modules",
+    host_supported: true,
+    is_stubs_module: true,
+}
diff --git a/tools/aconfig/fake_device_config/src/android/os/Binder.java b/tools/aconfig/fake_device_config/src/android/os/Binder.java
new file mode 100644
index 0000000000..8a2313dfda
--- /dev/null
+++ b/tools/aconfig/fake_device_config/src/android/os/Binder.java
@@ -0,0 +1,26 @@
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
+package android.os;
+
+public class Binder {
+    public static final long clearCallingIdentity() {
+        throw new UnsupportedOperationException("Stub!");
+    }
+    public static final void restoreCallingIdentity(long token) {
+        throw new UnsupportedOperationException("Stub!");
+    }
+}
diff --git a/tools/aconfig/fake_device_config/src/android/os/Build.java b/tools/aconfig/fake_device_config/src/android/os/Build.java
new file mode 100644
index 0000000000..8ec72fb2dc
--- /dev/null
+++ b/tools/aconfig/fake_device_config/src/android/os/Build.java
@@ -0,0 +1,23 @@
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
+package android.os;
+
+public class Build {
+    public static class VERSION {
+        public static final int SDK_INT = 0;
+    }
+}
diff --git a/tools/aconfig/fake_device_config/src/android/os/flagging/AconfigPackage.java b/tools/aconfig/fake_device_config/src/android/os/flagging/AconfigPackage.java
new file mode 100644
index 0000000000..3cac5168d1
--- /dev/null
+++ b/tools/aconfig/fake_device_config/src/android/os/flagging/AconfigPackage.java
@@ -0,0 +1,30 @@
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
+/*
+ * This class allows generated aconfig code to compile independently of the framework.
+ */
+public class AconfigPackage {
+    public static AconfigPackage load(String packageName) {
+        throw new UnsupportedOperationException("Stub!");
+    }
+
+    public boolean getBooleanFlagValue(String flagName, boolean defaultValue) {
+        throw new UnsupportedOperationException("Stub!");
+    }
+}
diff --git a/tools/aconfig/fake_device_config/src/android/os/flagging/AconfigPackageInternal.java b/tools/aconfig/fake_device_config/src/android/os/flagging/AconfigPackageInternal.java
new file mode 100644
index 0000000000..d084048165
--- /dev/null
+++ b/tools/aconfig/fake_device_config/src/android/os/flagging/AconfigPackageInternal.java
@@ -0,0 +1,32 @@
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
+/*
+ * This class allows generated aconfig code to compile independently of the framework.
+ */
+public class AconfigPackageInternal {
+
+    public static AconfigPackageInternal load(
+            String container, String packageName, long packageFingerprint) {
+        throw new UnsupportedOperationException("Stub!");
+    }
+
+    public boolean getBooleanFlagValue(int index) {
+        throw new UnsupportedOperationException("Stub!");
+    }
+}
diff --git a/tools/aconfig/fake_device_config/src/android/os/flagging/AconfigStorageReadException.java b/tools/aconfig/fake_device_config/src/android/os/flagging/AconfigStorageReadException.java
new file mode 100644
index 0000000000..bfec98ccb1
--- /dev/null
+++ b/tools/aconfig/fake_device_config/src/android/os/flagging/AconfigStorageReadException.java
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
+package android.os.flagging;
+
+public class AconfigStorageReadException extends RuntimeException {
+
+    /** Generic error code indicating an unspecified Aconfig Storage error. */
+    public static final int ERROR_GENERIC = 0;
+
+    /** Error code indicating that the Aconfig Storage system is not found on the device. */
+    public static final int ERROR_STORAGE_SYSTEM_NOT_FOUND = 1;
+
+    /** Error code indicating that the requested configuration package is not found. */
+    public static final int ERROR_PACKAGE_NOT_FOUND = 2;
+
+    /** Error code indicating that the specified container is not found. */
+    public static final int ERROR_CONTAINER_NOT_FOUND = 3;
+
+    /** Error code indicating that there was an error reading the Aconfig Storage file. */
+    public static final int ERROR_CANNOT_READ_STORAGE_FILE = 4;
+
+    public static final int ERROR_FILE_FINGERPRINT_MISMATCH = 5;
+
+    public AconfigStorageReadException(int errorCode, String msg) {
+        super(msg);
+        throw new UnsupportedOperationException("Stub!");
+    }
+
+    public AconfigStorageReadException(int errorCode, String msg, Throwable cause) {
+        super(msg, cause);
+        throw new UnsupportedOperationException("Stub!");
+    }
+
+    public AconfigStorageReadException(int errorCode, Throwable cause) {
+        super(cause);
+        throw new UnsupportedOperationException("Stub!");
+    }
+
+    public int getErrorCode() {
+        throw new UnsupportedOperationException("Stub!");
+    }
+
+    @Override
+    public String getMessage() {
+        throw new UnsupportedOperationException("Stub!");
+    }
+}
diff --git a/tools/aconfig/fake_device_config/src/android/os/flagging/PlatformAconfigPackageInternal.java b/tools/aconfig/fake_device_config/src/android/os/flagging/PlatformAconfigPackageInternal.java
new file mode 100644
index 0000000000..283b251010
--- /dev/null
+++ b/tools/aconfig/fake_device_config/src/android/os/flagging/PlatformAconfigPackageInternal.java
@@ -0,0 +1,32 @@
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
+/*
+ * This class allows generated aconfig code to compile independently of the framework.
+ */
+public class PlatformAconfigPackageInternal {
+
+    public static PlatformAconfigPackageInternal load(
+            String container, String packageName, long packageFingerprint) {
+        throw new UnsupportedOperationException("Stub!");
+    }
+
+    public boolean getBooleanFlagValue(int index) {
+        throw new UnsupportedOperationException("Stub!");
+    }
+}
diff --git a/tools/auto_gen_test_config.py b/tools/auto_gen_test_config.py
index 8ee599a1ec..d54c4121e4 100755
--- a/tools/auto_gen_test_config.py
+++ b/tools/auto_gen_test_config.py
@@ -34,6 +34,7 @@ PLACEHOLDER_MODULE = '{MODULE}'
 PLACEHOLDER_PACKAGE = '{PACKAGE}'
 PLACEHOLDER_RUNNER = '{RUNNER}'
 PLACEHOLDER_TEST_TYPE = '{TEST_TYPE}'
+PLACEHOLDER_EXTRA_TEST_RUNNER_CONFIGS = '{EXTRA_TEST_RUNNER_CONFIGS}'
 
 
 def main(argv):
@@ -59,6 +60,7 @@ def main(argv):
       "instrumentation_test_config_template",
       help="Path to the instrumentation test config template.")
   parser.add_argument("--extra-configs", default="")
+  parser.add_argument("--extra-test-runner-configs", default="")
   args = parser.parse_args(argv)
 
   target_config = args.target_config
@@ -66,6 +68,7 @@ def main(argv):
   empty_config = args.empty_config
   instrumentation_test_config_template = args.instrumentation_test_config_template
   extra_configs = '\n'.join(args.extra_configs.split('\\n'))
+  extra_test_runner_configs = '\n'.join(args.extra_test_runner_configs.split('\\n'))
 
   module = os.path.splitext(os.path.basename(target_config))[0]
 
@@ -131,6 +134,7 @@ def main(argv):
     config = config.replace(PLACEHOLDER_PACKAGE, package)
     config = config.replace(PLACEHOLDER_TEST_TYPE, test_type)
     config = config.replace(PLACEHOLDER_EXTRA_CONFIGS, extra_configs)
+    config = config.replace(PLACEHOLDER_EXTRA_TEST_RUNNER_CONFIGS, extra_test_runner_configs)
     config = config.replace(PLACEHOLDER_RUNNER, runner)
     with open(target_config, 'w') as config_file:
       config_file.write(config)
diff --git a/tools/compliance/go.work b/tools/compliance/go.work
index a24d2ea541..506e619436 100644
--- a/tools/compliance/go.work
+++ b/tools/compliance/go.work
@@ -1,4 +1,4 @@
-go 1.22
+go 1.23
 
 use (
 	.
diff --git a/tools/edit_monitor/Android.bp b/tools/edit_monitor/Android.bp
index b939633817..b8ac5bff53 100644
--- a/tools/edit_monitor/Android.bp
+++ b/tools/edit_monitor/Android.bp
@@ -20,11 +20,28 @@ package {
     default_team: "trendy_team_adte",
 }
 
+python_library_host {
+    name: "edit_event_proto",
+    srcs: [
+        "proto/edit_event.proto",
+    ],
+    proto: {
+        canonical_path_from_root: false,
+    },
+}
+
 python_library_host {
     name: "edit_monitor_lib",
     pkg_path: "edit_monitor",
     srcs: [
         "daemon_manager.py",
+        "edit_monitor.py",
+        "utils.py",
+    ],
+    libs: [
+        "asuite_cc_client",
+        "edit_event_proto",
+        "watchdog",
     ],
 }
 
@@ -42,3 +59,60 @@ python_test_host {
         unit_test: true,
     },
 }
+
+python_test_host {
+    name: "edit_monitor_test",
+    main: "edit_monitor_test.py",
+    pkg_path: "edit_monitor",
+    srcs: [
+        "edit_monitor_test.py",
+    ],
+    libs: [
+        "edit_monitor_lib",
+    ],
+    test_options: {
+        unit_test: true,
+    },
+}
+
+python_test_host {
+    name: "edit_monitor_utils_test",
+    main: "utils_test.py",
+    pkg_path: "edit_monitor",
+    srcs: [
+        "utils_test.py",
+    ],
+    libs: [
+        "edit_monitor_lib",
+    ],
+    test_options: {
+        unit_test: true,
+    },
+}
+
+python_test_host {
+    name: "edit_monitor_integration_test",
+    main: "edit_monitor_integration_test.py",
+    pkg_path: "testdata",
+    srcs: [
+        "edit_monitor_integration_test.py",
+    ],
+    test_options: {
+        unit_test: true,
+    },
+    data: [
+        ":edit_monitor",
+    ],
+}
+
+python_binary_host {
+    name: "edit_monitor",
+    pkg_path: "edit_monitor",
+    srcs: [
+        "main.py",
+    ],
+    libs: [
+        "edit_monitor_lib",
+    ],
+    main: "main.py",
+}
diff --git a/tools/edit_monitor/daemon_manager.py b/tools/edit_monitor/daemon_manager.py
index 8ec25886dc..7d666fed55 100644
--- a/tools/edit_monitor/daemon_manager.py
+++ b/tools/edit_monitor/daemon_manager.py
@@ -13,18 +13,35 @@
 # limitations under the License.
 
 
+import errno
+import fcntl
+import getpass
 import hashlib
 import logging
 import multiprocessing
 import os
 import pathlib
+import platform
 import signal
 import subprocess
+import sys
 import tempfile
 import time
 
+from atest.metrics import clearcut_client
+from atest.proto import clientanalytics_pb2
+from edit_monitor import utils
+from proto import edit_event_pb2
 
-DEFAULT_PROCESS_TERMINATION_TIMEOUT_SECONDS = 1
+DEFAULT_PROCESS_TERMINATION_TIMEOUT_SECONDS = 5
+DEFAULT_MONITOR_INTERVAL_SECONDS = 5
+DEFAULT_MEMORY_USAGE_THRESHOLD = 0.02  # 2% of total memory
+DEFAULT_CPU_USAGE_THRESHOLD = 200
+DEFAULT_REBOOT_TIMEOUT_SECONDS = 60 * 60 * 24
+BLOCK_SIGN_FILE = "edit_monitor_block_sign"
+# Enum of the Clearcut log source defined under
+# /google3/wireless/android/play/playlog/proto/log_source_enum.proto
+LOG_SOURCE = 2524
 
 
 def default_daemon_target():
@@ -40,37 +57,209 @@ class DaemonManager:
       binary_path: str,
       daemon_target: callable = default_daemon_target,
       daemon_args: tuple = (),
+      cclient: clearcut_client.Clearcut | None = None,
   ):
     self.binary_path = binary_path
     self.daemon_target = daemon_target
     self.daemon_args = daemon_args
+    self.cclient = cclient or clearcut_client.Clearcut(LOG_SOURCE)
 
+    self.user_name = getpass.getuser()
+    self.host_name = platform.node()
+    self.source_root = os.environ.get("ANDROID_BUILD_TOP", "")
     self.pid = os.getpid()
     self.daemon_process = None
 
+    self.max_memory_usage = 0
+    self.max_cpu_usage = 0
+    self.total_memory_size = os.sysconf("SC_PAGE_SIZE") * os.sysconf(
+        "SC_PHYS_PAGES"
+    )
+
     pid_file_dir = pathlib.Path(tempfile.gettempdir()).joinpath("edit_monitor")
     pid_file_dir.mkdir(parents=True, exist_ok=True)
     self.pid_file_path = self._get_pid_file_path(pid_file_dir)
+    self.block_sign = pathlib.Path(tempfile.gettempdir()).joinpath(
+        BLOCK_SIGN_FILE
+    )
 
   def start(self):
     """Writes the pidfile and starts the daemon proces."""
-    try:
-      self._stop_any_existing_instance()
-      self._write_pid_to_pidfile()
-      self._start_daemon_process()
-    except Exception as e:
-      logging.exception("Failed to start daemon manager with error %s", e)
+    if not utils.is_feature_enabled(
+        "edit_monitor",
+        self.user_name,
+        "ENABLE_ANDROID_EDIT_MONITOR",
+        100,
+    ):
+      logging.warning("Edit monitor is disabled, exiting...")
+      return
+
+    if self.block_sign.exists():
+      logging.warning("Block sign found, exiting...")
+      return
+
+    if self.binary_path.startswith("/google/cog/"):
+      logging.warning("Edit monitor for cog is not supported, exiting...")
+      return
+
+    setup_lock_file = pathlib.Path(tempfile.gettempdir()).joinpath(
+        self.pid_file_path.name + ".setup"
+    )
+    logging.info("setup lock file: %s", setup_lock_file)
+    with open(setup_lock_file, "w") as f:
+      try:
+        # Acquire an exclusive lock
+        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
+        self._stop_any_existing_instance()
+        self._write_pid_to_pidfile()
+        self._start_daemon_process()
+      except Exception as e:
+        if (
+            isinstance(e, IOError) and e.errno == errno.EAGAIN
+        ):  # Failed to acquire the file lock.
+          logging.warning("Another edit monitor is starting, exitinng...")
+          return
+        else:
+          logging.exception("Failed to start daemon manager with error %s", e)
+          self._send_error_event_to_clearcut(
+              edit_event_pb2.EditEvent.FAILED_TO_START_EDIT_MONITOR
+          )
+          raise e
+      finally:
+        # Release the lock
+        fcntl.flock(f, fcntl.LOCK_UN)
+
+  def monitor_daemon(
+      self,
+      interval: int = DEFAULT_MONITOR_INTERVAL_SECONDS,
+      memory_threshold: float = DEFAULT_MEMORY_USAGE_THRESHOLD,
+      cpu_threshold: float = DEFAULT_CPU_USAGE_THRESHOLD,
+      reboot_timeout: int = DEFAULT_REBOOT_TIMEOUT_SECONDS,
+  ):
+    """Monits the daemon process status.
+
+    Periodically check the CPU/Memory usage of the daemon process as long as the
+    process is still running and kill the process if the resource usage is above
+    given thresholds.
+    """
+    if not self.daemon_process:
+      return
+
+    logging.info("start monitoring daemon process %d.", self.daemon_process.pid)
+    reboot_time = time.time() + reboot_timeout
+    while self.daemon_process.is_alive():
+      if time.time() > reboot_time:
+        self.reboot()
+      try:
+        memory_usage = self._get_process_memory_percent(self.daemon_process.pid)
+        self.max_memory_usage = max(self.max_memory_usage, memory_usage)
+
+        cpu_usage = self._get_process_cpu_percent(self.daemon_process.pid)
+        self.max_cpu_usage = max(self.max_cpu_usage, cpu_usage)
+
+        time.sleep(interval)
+      except Exception as e:
+        # Logging the error and continue.
+        logging.warning("Failed to monitor daemon process with error: %s", e)
+
+      if self.max_memory_usage >= memory_threshold:
+        self._send_error_event_to_clearcut(
+            edit_event_pb2.EditEvent.KILLED_DUE_TO_EXCEEDED_MEMORY_USAGE
+        )
+        logging.error(
+            "Daemon process is consuming too much memory, rebooting..."
+        )
+        self.reboot()
+
+      if self.max_cpu_usage >= cpu_threshold:
+        self._send_error_event_to_clearcut(
+            edit_event_pb2.EditEvent.KILLED_DUE_TO_EXCEEDED_CPU_USAGE
+        )
+        logging.error("Daemon process is consuming too much cpu, killing...")
+        self._terminate_process(self.daemon_process.pid)
+
+    logging.info(
+        "Daemon process %d terminated. Max memory usage: %f, Max cpu"
+        " usage: %f.",
+        self.daemon_process.pid,
+        self.max_memory_usage,
+        self.max_cpu_usage,
+    )
 
   def stop(self):
     """Stops the daemon process and removes the pidfile."""
 
-    logging.debug("in daemon manager cleanup.")
+    logging.info("in daemon manager cleanup.")
     try:
-      if self.daemon_process and self.daemon_process.is_alive():
-        self._terminate_process(self.daemon_process.pid)
-      self._remove_pidfile()
+      if self.daemon_process:
+        # The daemon process might already in termination process,
+        # wait some time before kill it explicitly.
+        self._wait_for_process_terminate(self.daemon_process.pid, 1)
+        if self.daemon_process.is_alive():
+          self._terminate_process(self.daemon_process.pid)
+      self._remove_pidfile(self.pid)
+      logging.info("Successfully stopped daemon manager.")
     except Exception as e:
       logging.exception("Failed to stop daemon manager with error %s", e)
+      self._send_error_event_to_clearcut(
+          edit_event_pb2.EditEvent.FAILED_TO_STOP_EDIT_MONITOR
+      )
+      sys.exit(1)
+    finally:
+      self.cclient.flush_events()
+
+  def reboot(self):
+    """Reboots the current process.
+
+    Stops the current daemon manager and reboots the entire process based on
+    the binary file. Exits directly If the binary file no longer exists.
+    """
+    logging.info("Rebooting process based on binary %s.", self.binary_path)
+
+    # Stop the current daemon manager first.
+    self.stop()
+
+    # If the binary no longer exists, exit directly.
+    if not os.path.exists(self.binary_path):
+      logging.info("binary %s no longer exists, exiting.", self.binary_path)
+      sys.exit(0)
+
+    try:
+      os.execv(self.binary_path, sys.argv)
+    except OSError as e:
+      logging.exception("Failed to reboot process with error: %s.", e)
+      self._send_error_event_to_clearcut(
+          edit_event_pb2.EditEvent.FAILED_TO_REBOOT_EDIT_MONITOR
+      )
+      sys.exit(1)  # Indicate an error occurred
+
+  def cleanup(self):
+    """Wipes out all edit monitor instances in the system.
+
+    Stops all the existing edit monitor instances and place a block sign
+    to prevent any edit monitor process to start. This method is only used
+    in emergency case when there's something goes wrong with the edit monitor
+    that requires immediate cleanup to prevent damanger to the system.
+    """
+    logging.debug("Start cleaning up all existing instances.")
+    self._send_error_event_to_clearcut(edit_event_pb2.EditEvent.FORCE_CLEANUP)
+
+    try:
+      # First places a block sign to prevent any edit monitor process to start.
+      self.block_sign.touch()
+    except (FileNotFoundError, PermissionError, OSError):
+      logging.exception("Failed to place the block sign")
+
+    # Finds and kills all the existing instances of edit monitor.
+    existing_instances_pids = self._find_all_instances_pids()
+    for pid in existing_instances_pids:
+      logging.info(
+          "Found existing edit monitor instance with pid %d, killing...", pid
+      )
+      try:
+        self._terminate_process(pid)
+      except Exception:
+        logging.exception("Failed to terminate process %d", pid)
 
   def _stop_any_existing_instance(self):
     if not self.pid_file_path.exists():
@@ -82,11 +271,15 @@ class DaemonManager:
     if ex_pid:
       logging.info("Found another instance with pid %d.", ex_pid)
       self._terminate_process(ex_pid)
-      self._remove_pidfile()
+      self._remove_pidfile(ex_pid)
 
-  def _read_pid_from_pidfile(self):
-    with open(self.pid_file_path, "r") as f:
-      return int(f.read().strip())
+  def _read_pid_from_pidfile(self) -> int | None:
+    try:
+      with open(self.pid_file_path, "r") as f:
+        return int(f.read().strip())
+    except FileNotFoundError as e:
+      logging.warning("pidfile %s does not exist.", self.pid_file_path)
+      return None
 
   def _write_pid_to_pidfile(self):
     """Creates a pidfile and writes the current pid to the file.
@@ -110,6 +303,7 @@ class DaemonManager:
     p = multiprocessing.Process(
         target=self.daemon_target, args=self.daemon_args
     )
+    p.daemon = True
     p.start()
 
     logging.info("Start subprocess with PID %d", p.pid)
@@ -161,7 +355,23 @@ class DaemonManager:
       )
       return True
 
-  def _remove_pidfile(self):
+  def _remove_pidfile(self, expected_pid: int):
+    recorded_pid = self._read_pid_from_pidfile()
+
+    if recorded_pid is None:
+      logging.info("pid file %s already removed.", self.pid_file_path)
+      return
+
+    if recorded_pid != expected_pid:
+      logging.warning(
+          "pid file contains pid from a different process, expected pid: %d,"
+          " actual pid: %d.",
+          expected_pid,
+          recorded_pid,
+      )
+      return
+
+    logging.debug("removing pidfile written by process %s", expected_pid)
     try:
       os.remove(self.pid_file_path)
     except FileNotFoundError:
@@ -180,3 +390,74 @@ class DaemonManager:
     logging.info("pid_file_path: %s", pid_file_path)
 
     return pid_file_path
+
+  def _get_process_memory_percent(self, pid: int) -> float:
+    with open(f"/proc/{pid}/stat", "r") as f:
+      stat_data = f.readline().split()
+      # RSS is the 24th field in /proc/[pid]/stat
+      rss_pages = int(stat_data[23])
+      process_memory = rss_pages * 4 * 1024  # Convert to bytes
+
+    return (
+        process_memory / self.total_memory_size
+        if self.total_memory_size
+        else 0.0
+    )
+
+  def _get_process_cpu_percent(self, pid: int, interval: int = 1) -> float:
+    total_start_time = self._get_total_cpu_time(pid)
+    with open("/proc/uptime", "r") as f:
+      uptime_start = float(f.readline().split()[0])
+
+    time.sleep(interval)
+
+    total_end_time = self._get_total_cpu_time(pid)
+    with open("/proc/uptime", "r") as f:
+      uptime_end = float(f.readline().split()[0])
+
+    return (
+        (total_end_time - total_start_time) / (uptime_end - uptime_start) * 100
+    )
+
+  def _get_total_cpu_time(self, pid: int) -> float:
+    with open(f"/proc/{str(pid)}/stat", "r") as f:
+      stats = f.readline().split()
+      # utime is the 14th field in /proc/[pid]/stat measured in clock ticks.
+      utime = int(stats[13])
+      # stime is the 15th field in /proc/[pid]/stat measured in clock ticks.
+      stime = int(stats[14])
+      return (utime + stime) / os.sysconf(os.sysconf_names["SC_CLK_TCK"])
+
+  def _find_all_instances_pids(self) -> list[int]:
+    pids = []
+
+    try:
+      output = subprocess.check_output(["ps", "-ef", "--no-headers"], text=True)
+      for line in output.splitlines():
+        parts = line.split()
+        process_path = parts[7]
+        if pathlib.Path(process_path).name == "edit_monitor":
+          pid = int(parts[1])
+          if pid != self.pid:  # exclude the current process
+            pids.append(pid)
+    except Exception:
+      logging.exception(
+          "Failed to get pids of existing edit monitors from ps command."
+      )
+
+    return pids
+
+  def _send_error_event_to_clearcut(self, error_type):
+    edit_monitor_error_event_proto = edit_event_pb2.EditEvent(
+        user_name=self.user_name,
+        host_name=self.host_name,
+        source_root=self.source_root,
+    )
+    edit_monitor_error_event_proto.edit_monitor_error_event.CopyFrom(
+        edit_event_pb2.EditEvent.EditMonitorErrorEvent(error_type=error_type)
+    )
+    log_event = clientanalytics_pb2.LogEvent(
+        event_time_ms=int(time.time() * 1000),
+        source_extension=edit_monitor_error_event_proto.SerializeToString(),
+    )
+    self.cclient.log(log_event)
diff --git a/tools/edit_monitor/daemon_manager_test.py b/tools/edit_monitor/daemon_manager_test.py
index 214b0388dc..be28965c9e 100644
--- a/tools/edit_monitor/daemon_manager_test.py
+++ b/tools/edit_monitor/daemon_manager_test.py
@@ -14,6 +14,7 @@
 
 """Unittests for DaemonManager."""
 
+import fcntl
 import logging
 import multiprocessing
 import os
@@ -26,6 +27,8 @@ import time
 import unittest
 from unittest import mock
 from edit_monitor import daemon_manager
+from proto import edit_event_pb2
+
 
 TEST_BINARY_FILE = '/path/to/test_binary'
 TEST_PID_FILE_PATH = (
@@ -43,6 +46,25 @@ def long_running_daemon():
     time.sleep(1)
 
 
+def memory_consume_daemon_target(size_mb):
+  try:
+    size_bytes = size_mb * 1024 * 1024
+    dummy_data = bytearray(size_bytes)
+    time.sleep(10)
+  except MemoryError:
+    print(f'Process failed to allocate {size_mb} MB of memory.')
+
+
+def cpu_consume_daemon_target(target_usage_percent):
+  while True:
+    start_time = time.time()
+    while time.time() - start_time < target_usage_percent / 100:
+      pass  # Busy loop to consume CPU
+
+    # Sleep to reduce CPU usage
+    time.sleep(1 - target_usage_percent / 100)
+
+
 class DaemonManagerTest(unittest.TestCase):
 
   @classmethod
@@ -60,6 +82,10 @@ class DaemonManagerTest(unittest.TestCase):
     # Sets the tempdir under the working dir so any temp files created during
     # tests will be cleaned.
     tempfile.tempdir = self.working_dir.name
+    self.patch = mock.patch.dict(
+        os.environ, {'ENABLE_ANDROID_EDIT_MONITOR': 'true'}
+    )
+    self.patch.start()
 
   def tearDown(self):
     # Cleans up any child processes left by the tests.
@@ -67,26 +93,18 @@ class DaemonManagerTest(unittest.TestCase):
     self.working_dir.cleanup()
     # Restores tempdir.
     tempfile.tempdir = self.original_tempdir
+    self.patch.stop()
     super().tearDown()
 
   def test_start_success_with_no_existing_instance(self):
     self.assert_run_simple_daemon_success()
 
   def test_start_success_with_existing_instance_running(self):
-    # Create a long running subprocess
-    p = multiprocessing.Process(target=long_running_daemon)
-    p.start()
-
-    # Create a pidfile with the subprocess pid
-    pid_file_path_dir = pathlib.Path(self.working_dir.name).joinpath(
-        'edit_monitor'
-    )
-    pid_file_path_dir.mkdir(parents=True, exist_ok=True)
-    with open(pid_file_path_dir.joinpath(TEST_PID_FILE_PATH), 'w') as f:
-      f.write(str(p.pid))
+    # Create a running daemon subprocess
+    p = self._create_fake_deamon_process()
 
     self.assert_run_simple_daemon_success()
-    p.terminate()
+    self.assert_no_subprocess_running()
 
   def test_start_success_with_existing_instance_already_dead(self):
     # Create a pidfile with pid that does not exist.
@@ -102,7 +120,7 @@ class DaemonManagerTest(unittest.TestCase):
   def test_start_success_with_existing_instance_from_different_binary(self):
     # First start an instance based on "some_binary_path"
     existing_dm = daemon_manager.DaemonManager(
-        "some_binary_path",
+        'some_binary_path',
         daemon_target=long_running_daemon,
     )
     existing_dm.start()
@@ -110,6 +128,56 @@ class DaemonManagerTest(unittest.TestCase):
     self.assert_run_simple_daemon_success()
     existing_dm.stop()
 
+  def test_start_return_directly_if_block_sign_exists(self):
+    # Creates the block sign.
+    pathlib.Path(self.working_dir.name).joinpath(
+        daemon_manager.BLOCK_SIGN_FILE
+    ).touch()
+
+    dm = daemon_manager.DaemonManager(TEST_BINARY_FILE)
+    dm.start()
+
+    # Verify no daemon process is started.
+    self.assertIsNone(dm.daemon_process)
+
+  @mock.patch.dict(
+      os.environ, {'ENABLE_ANDROID_EDIT_MONITOR': 'false'}, clear=True
+  )
+  def test_start_return_directly_if_disabled(self):
+    dm = daemon_manager.DaemonManager(TEST_BINARY_FILE)
+    dm.start()
+
+    # Verify no daemon process is started.
+    self.assertIsNone(dm.daemon_process)
+
+  def test_start_return_directly_if_in_cog_env(self):
+    dm = daemon_manager.DaemonManager(
+        '/google/cog/cloud/user/workspace/edit_monitor'
+    )
+    dm.start()
+
+    # Verify no daemon process is started.
+    self.assertIsNone(dm.daemon_process)
+
+  def test_start_failed_other_instance_is_starting(self):
+    f = open(
+        pathlib.Path(self.working_dir.name).joinpath(
+            TEST_PID_FILE_PATH + '.setup'
+        ),
+        'w',
+    )
+    # Acquire an exclusive lock
+    fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
+
+    dm = daemon_manager.DaemonManager(TEST_BINARY_FILE)
+    dm.start()
+
+    # Release the lock
+    fcntl.flock(f, fcntl.LOCK_UN)
+    f.close()
+    # Verify no daemon process is started.
+    self.assertIsNone(dm.daemon_process)
+
   @mock.patch('os.kill')
   def test_start_failed_to_kill_existing_instance(self, mock_kill):
     mock_kill.side_effect = OSError('Unknown OSError')
@@ -120,34 +188,107 @@ class DaemonManagerTest(unittest.TestCase):
     with open(pid_file_path_dir.joinpath(TEST_PID_FILE_PATH), 'w') as f:
       f.write('123456')
 
-    dm = daemon_manager.DaemonManager(TEST_BINARY_FILE)
-    dm.start()
-
-    # Verify no daemon process is started.
-    self.assertIsNone(dm.daemon_process)
+    fake_cclient = FakeClearcutClient()
+    with self.assertRaises(OSError):
+      dm = daemon_manager.DaemonManager(TEST_BINARY_FILE, cclient=fake_cclient)
+      dm.start()
+    self._assert_error_event_logged(
+        fake_cclient, edit_event_pb2.EditEvent.FAILED_TO_START_EDIT_MONITOR
+    )
 
   def test_start_failed_to_write_pidfile(self):
     pid_file_path_dir = pathlib.Path(self.working_dir.name).joinpath(
         'edit_monitor'
     )
     pid_file_path_dir.mkdir(parents=True, exist_ok=True)
+
     # Makes the directory read-only so write pidfile will fail.
     os.chmod(pid_file_path_dir, 0o555)
 
-    dm = daemon_manager.DaemonManager(TEST_BINARY_FILE)
+    fake_cclient = FakeClearcutClient()
+    with self.assertRaises(PermissionError):
+      dm = daemon_manager.DaemonManager(TEST_BINARY_FILE, cclient=fake_cclient)
+      dm.start()
+    self._assert_error_event_logged(
+        fake_cclient, edit_event_pb2.EditEvent.FAILED_TO_START_EDIT_MONITOR
+    )
+
+  def test_start_failed_to_start_daemon_process(self):
+    fake_cclient = FakeClearcutClient()
+    with self.assertRaises(TypeError):
+      dm = daemon_manager.DaemonManager(
+          TEST_BINARY_FILE,
+          daemon_target='wrong_target',
+          daemon_args=(1),
+          cclient=fake_cclient,
+      )
+      dm.start()
+    self._assert_error_event_logged(
+        fake_cclient, edit_event_pb2.EditEvent.FAILED_TO_START_EDIT_MONITOR
+    )
+
+  @mock.patch('os.execv')
+  def test_monitor_reboot_with_high_memory_usage(self, mock_execv):
+    fake_cclient = FakeClearcutClient()
+    binary_file = tempfile.NamedTemporaryFile(
+        dir=self.working_dir.name, delete=False
+    )
+
+    dm = daemon_manager.DaemonManager(
+        binary_file.name,
+        daemon_target=memory_consume_daemon_target,
+        daemon_args=(2,),
+        cclient=fake_cclient,
+    )
+    # set the fake total_memory_size
+    dm.total_memory_size = 100 * 1024 * 1024
     dm.start()
+    dm.monitor_daemon(interval=1)
 
-    # Verifies no daemon process is started.
-    self.assertIsNone(dm.daemon_process)
+    self.assertTrue(dm.max_memory_usage >= 0.02)
+    self.assert_no_subprocess_running()
+    self._assert_error_event_logged(
+        fake_cclient,
+        edit_event_pb2.EditEvent.KILLED_DUE_TO_EXCEEDED_MEMORY_USAGE,
+    )
+    mock_execv.assert_called_once()
 
-  def test_start_failed_to_start_daemon_process(self):
+  def test_monitor_daemon_subprocess_killed_high_cpu_usage(self):
+    fake_cclient = FakeClearcutClient()
     dm = daemon_manager.DaemonManager(
-        TEST_BINARY_FILE, daemon_target='wrong_target', daemon_args=(1)
+        TEST_BINARY_FILE,
+        daemon_target=cpu_consume_daemon_target,
+        daemon_args=(20,),
+        cclient=fake_cclient,
     )
     dm.start()
+    dm.monitor_daemon(interval=1, cpu_threshold=20)
 
-    # Verifies no daemon process is started.
-    self.assertIsNone(dm.daemon_process)
+    self.assertTrue(dm.max_cpu_usage >= 20)
+    self.assert_no_subprocess_running()
+    self._assert_error_event_logged(
+        fake_cclient,
+        edit_event_pb2.EditEvent.KILLED_DUE_TO_EXCEEDED_CPU_USAGE,
+    )
+
+  @mock.patch('subprocess.check_output')
+  def test_monitor_daemon_failed_does_not_matter(self, mock_output):
+    mock_output.side_effect = OSError('Unknown OSError')
+    self.assert_run_simple_daemon_success()
+
+  @mock.patch('os.execv')
+  def test_monitor_daemon_reboot_triggered(self, mock_execv):
+    binary_file = tempfile.NamedTemporaryFile(
+        dir=self.working_dir.name, delete=False
+    )
+
+    dm = daemon_manager.DaemonManager(
+        binary_file.name,
+        daemon_target=long_running_daemon,
+    )
+    dm.start()
+    dm.monitor_daemon(reboot_timeout=0.5)
+    mock_execv.assert_called_once()
 
   def test_stop_success(self):
     dm = daemon_manager.DaemonManager(
@@ -162,27 +303,114 @@ class DaemonManagerTest(unittest.TestCase):
   @mock.patch('os.kill')
   def test_stop_failed_to_kill_daemon_process(self, mock_kill):
     mock_kill.side_effect = OSError('Unknown OSError')
+    fake_cclient = FakeClearcutClient()
     dm = daemon_manager.DaemonManager(
-        TEST_BINARY_FILE, daemon_target=long_running_daemon
+        TEST_BINARY_FILE,
+        daemon_target=long_running_daemon,
+        cclient=fake_cclient,
     )
-    dm.start()
-    dm.stop()
 
-    self.assertTrue(dm.daemon_process.is_alive())
-    self.assertTrue(dm.pid_file_path.exists())
+    with self.assertRaises(SystemExit):
+      dm.start()
+      dm.stop()
+      self.assertTrue(dm.daemon_process.is_alive())
+      self.assertTrue(dm.pid_file_path.exists())
+    self._assert_error_event_logged(
+        fake_cclient, edit_event_pb2.EditEvent.FAILED_TO_STOP_EDIT_MONITOR
+    )
 
   @mock.patch('os.remove')
   def test_stop_failed_to_remove_pidfile(self, mock_remove):
     mock_remove.side_effect = OSError('Unknown OSError')
 
+    fake_cclient = FakeClearcutClient()
     dm = daemon_manager.DaemonManager(
-        TEST_BINARY_FILE, daemon_target=long_running_daemon
+        TEST_BINARY_FILE,
+        daemon_target=long_running_daemon,
+        cclient=fake_cclient,
+    )
+
+    with self.assertRaises(SystemExit):
+      dm.start()
+      dm.stop()
+      self.assert_no_subprocess_running()
+      self.assertTrue(dm.pid_file_path.exists())
+
+    self._assert_error_event_logged(
+        fake_cclient, edit_event_pb2.EditEvent.FAILED_TO_STOP_EDIT_MONITOR
+    )
+
+  @mock.patch('os.execv')
+  def test_reboot_success(self, mock_execv):
+    binary_file = tempfile.NamedTemporaryFile(
+        dir=self.working_dir.name, delete=False
+    )
+
+    dm = daemon_manager.DaemonManager(
+        binary_file.name, daemon_target=long_running_daemon
     )
     dm.start()
-    dm.stop()
+    dm.reboot()
 
+    # Verifies the old process is stopped
     self.assert_no_subprocess_running()
-    self.assertTrue(dm.pid_file_path.exists())
+    self.assertFalse(dm.pid_file_path.exists())
+
+    mock_execv.assert_called_once()
+
+  @mock.patch('os.execv')
+  def test_reboot_binary_no_longer_exists(self, mock_execv):
+    dm = daemon_manager.DaemonManager(
+        TEST_BINARY_FILE, daemon_target=long_running_daemon
+    )
+    dm.start()
+
+    with self.assertRaises(SystemExit):
+      dm.reboot()
+      mock_execv.assert_not_called()
+      self.assertEqual(cm.exception.code, 0)
+
+  @mock.patch('os.execv')
+  def test_reboot_failed(self, mock_execv):
+    mock_execv.side_effect = OSError('Unknown OSError')
+    fake_cclient = FakeClearcutClient()
+    binary_file = tempfile.NamedTemporaryFile(
+        dir=self.working_dir.name, delete=False
+    )
+
+    dm = daemon_manager.DaemonManager(
+        binary_file.name,
+        daemon_target=long_running_daemon,
+        cclient=fake_cclient,
+    )
+    dm.start()
+
+    with self.assertRaises(SystemExit):
+      dm.reboot()
+      self.assertEqual(cm.exception.code, 1)
+    self._assert_error_event_logged(
+        fake_cclient, edit_event_pb2.EditEvent.FAILED_TO_REBOOT_EDIT_MONITOR
+    )
+
+  @mock.patch('subprocess.check_output')
+  def test_cleanup_success(self, mock_check_output):
+    p = self._create_fake_deamon_process()
+    fake_cclient = FakeClearcutClient()
+    mock_check_output.return_value = f'user {p.pid} 1 1 1 1 1 edit_monitor arg'
+
+    dm = daemon_manager.DaemonManager(
+        TEST_BINARY_FILE,
+        daemon_target=long_running_daemon,
+        cclient=fake_cclient,
+    )
+    dm.cleanup()
+
+    self.assertFalse(p.is_alive())
+    self.assertTrue(
+        pathlib.Path(self.working_dir.name)
+        .joinpath(daemon_manager.BLOCK_SIGN_FILE)
+        .exists()
+    )
 
   def assert_run_simple_daemon_success(self):
     damone_output_file = tempfile.NamedTemporaryFile(
@@ -194,7 +422,7 @@ class DaemonManagerTest(unittest.TestCase):
         daemon_args=(damone_output_file.name,),
     )
     dm.start()
-    dm.daemon_process.join()
+    dm.monitor_daemon(interval=1)
 
     # Verifies the expected pid file is created.
     expected_pid_file_path = pathlib.Path(self.working_dir.name).joinpath(
@@ -214,7 +442,7 @@ class DaemonManagerTest(unittest.TestCase):
           self._is_process_alive(child_pid), f'process {child_pid} still alive'
       )
 
-  def _get_child_processes(self, parent_pid):
+  def _get_child_processes(self, parent_pid: int) -> list[int]:
     try:
       output = subprocess.check_output(
           ['ps', '-o', 'pid,ppid', '--no-headers'], text=True
@@ -229,7 +457,7 @@ class DaemonManagerTest(unittest.TestCase):
     except subprocess.CalledProcessError as e:
       self.fail(f'failed to get child process, error: {e}')
 
-  def _is_process_alive(self, pid):
+  def _is_process_alive(self, pid: int) -> bool:
     try:
       output = subprocess.check_output(
           ['ps', '-p', str(pid), '-o', 'state='], text=True
@@ -248,6 +476,49 @@ class DaemonManagerTest(unittest.TestCase):
         # process already terminated
         pass
 
+  def _create_fake_deamon_process(
+      self, name: str = TEST_PID_FILE_PATH
+  ) -> multiprocessing.Process:
+    # Create a long running subprocess
+    p = multiprocessing.Process(target=long_running_daemon)
+    p.start()
+
+    # Create the pidfile with the subprocess pid
+    pid_file_path_dir = pathlib.Path(self.working_dir.name).joinpath(
+        'edit_monitor'
+    )
+    pid_file_path_dir.mkdir(parents=True, exist_ok=True)
+    with open(pid_file_path_dir.joinpath(name), 'w') as f:
+      f.write(str(p.pid))
+    return p
+
+  def _assert_error_event_logged(self, fake_cclient, error_type):
+    error_events = fake_cclient.get_sent_events()
+    self.assertEquals(len(error_events), 1)
+    self.assertEquals(
+        edit_event_pb2.EditEvent.FromString(
+            error_events[0].source_extension
+        ).edit_monitor_error_event.error_type,
+        error_type,
+    )
+
+
+class FakeClearcutClient:
+
+  def __init__(self):
+    self.pending_log_events = []
+    self.sent_log_event = []
+
+  def log(self, log_event):
+    self.pending_log_events.append(log_event)
+
+  def flush_events(self):
+    self.sent_log_event.extend(self.pending_log_events)
+    self.pending_log_events.clear()
+
+  def get_sent_events(self):
+    return self.sent_log_event + self.pending_log_events
+
 
 if __name__ == '__main__':
   unittest.main()
diff --git a/tools/edit_monitor/edit_monitor.py b/tools/edit_monitor/edit_monitor.py
new file mode 100644
index 0000000000..ab528e870f
--- /dev/null
+++ b/tools/edit_monitor/edit_monitor.py
@@ -0,0 +1,220 @@
+# Copyright 2024, The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+
+import getpass
+import logging
+import multiprocessing.connection
+import os
+import pathlib
+import platform
+import threading
+import time
+
+from atest.metrics import clearcut_client
+from atest.proto import clientanalytics_pb2
+from proto import edit_event_pb2
+from watchdog.events import FileSystemEvent
+from watchdog.events import PatternMatchingEventHandler
+from watchdog.observers import Observer
+
+# Enum of the Clearcut log source defined under
+# /google3/wireless/android/play/playlog/proto/log_source_enum.proto
+LOG_SOURCE = 2524
+DEFAULT_FLUSH_INTERVAL_SECONDS = 5
+DEFAULT_SINGLE_EVENTS_SIZE_THRESHOLD = 100
+
+
+class ClearcutEventHandler(PatternMatchingEventHandler):
+
+  def __init__(
+      self,
+      path: str,
+      flush_interval_sec: int,
+      single_events_size_threshold: int,
+      is_dry_run: bool = False,
+      cclient: clearcut_client.Clearcut | None = None,
+  ):
+
+    super().__init__(patterns=["*"], ignore_directories=True)
+    self.root_monitoring_path = path
+    self.flush_interval_sec = flush_interval_sec
+    self.single_events_size_threshold = single_events_size_threshold
+    self.is_dry_run = is_dry_run
+    self.cclient = cclient or clearcut_client.Clearcut(LOG_SOURCE)
+
+    self.user_name = getpass.getuser()
+    self.host_name = platform.node()
+    self.source_root = os.environ.get("ANDROID_BUILD_TOP", "")
+
+    self.pending_events = []
+    self._scheduled_log_thread = None
+    self._pending_events_lock = threading.Lock()
+
+  def on_moved(self, event: FileSystemEvent):
+    self._log_edit_event(event, edit_event_pb2.EditEvent.MOVE)
+
+  def on_created(self, event: FileSystemEvent):
+    self._log_edit_event(event, edit_event_pb2.EditEvent.CREATE)
+
+  def on_deleted(self, event: FileSystemEvent):
+    self._log_edit_event(event, edit_event_pb2.EditEvent.DELETE)
+
+  def on_modified(self, event: FileSystemEvent):
+    self._log_edit_event(event, edit_event_pb2.EditEvent.MODIFY)
+
+  def flushall(self):
+    logging.info("flushing all pending events.")
+    if self._scheduled_log_thread:
+      logging.info("canceling log thread")
+      self._scheduled_log_thread.cancel()
+      self._scheduled_log_thread = None
+
+    self._log_clearcut_events()
+    self.cclient.flush_events()
+
+  def _log_edit_event(
+      self, event: FileSystemEvent, edit_type: edit_event_pb2.EditEvent.EditType
+  ):
+    try:
+      event_time = time.time()
+
+      if self._is_hidden_file(pathlib.Path(event.src_path)):
+        logging.debug("ignore hidden file: %s.", event.src_path)
+        return
+
+      if not self._is_under_git_project(pathlib.Path(event.src_path)):
+        logging.debug(
+            "ignore file %s which does not belong to a git project",
+            event.src_path,
+        )
+        return
+
+      logging.info("%s: %s", event.event_type, event.src_path)
+
+      event_proto = edit_event_pb2.EditEvent(
+          user_name=self.user_name,
+          host_name=self.host_name,
+          source_root=self.source_root,
+      )
+      event_proto.single_edit_event.CopyFrom(
+          edit_event_pb2.EditEvent.SingleEditEvent(
+              file_path=event.src_path, edit_type=edit_type
+          )
+      )
+      with self._pending_events_lock:
+        self.pending_events.append((event_proto, event_time))
+        if not self._scheduled_log_thread:
+          logging.debug(
+              "Scheduling thread to run in %d seconds", self.flush_interval_sec
+          )
+          self._scheduled_log_thread = threading.Timer(
+              self.flush_interval_sec, self._log_clearcut_events
+          )
+          self._scheduled_log_thread.start()
+
+    except Exception:
+      logging.exception("Failed to log edit event.")
+
+  def _is_hidden_file(self, file_path: pathlib.Path) -> bool:
+    return any(
+        part.startswith(".")
+        for part in file_path.relative_to(self.root_monitoring_path).parts
+    )
+
+  def _is_under_git_project(self, file_path: pathlib.Path) -> bool:
+    root_path = pathlib.Path(self.root_monitoring_path).resolve()
+    return any(
+        root_path.joinpath(dir).joinpath('.git').exists()
+        for dir in file_path.relative_to(root_path).parents
+    )
+
+  def _log_clearcut_events(self):
+    with self._pending_events_lock:
+      self._scheduled_log_thread = None
+      edit_events = self.pending_events
+      self.pending_events = []
+
+    pending_events_size = len(edit_events)
+    if pending_events_size > self.single_events_size_threshold:
+      logging.info(
+          "got %d events in %d seconds, sending aggregated events instead",
+          pending_events_size,
+          self.flush_interval_sec,
+      )
+      aggregated_event_time = edit_events[0][1]
+      aggregated_event_proto = edit_event_pb2.EditEvent(
+          user_name=self.user_name,
+          host_name=self.host_name,
+          source_root=self.source_root,
+      )
+      aggregated_event_proto.aggregated_edit_event.CopyFrom(
+          edit_event_pb2.EditEvent.AggregatedEditEvent(
+              num_edits=pending_events_size
+          )
+      )
+      edit_events = [(aggregated_event_proto, aggregated_event_time)]
+
+    if self.is_dry_run:
+      logging.info("Sent %d edit events in dry run.", len(edit_events))
+      return
+
+    for event_proto, event_time in edit_events:
+      log_event = clientanalytics_pb2.LogEvent(
+          event_time_ms=int(event_time * 1000),
+          source_extension=event_proto.SerializeToString(),
+      )
+      self.cclient.log(log_event)
+
+    logging.info("sent %d edit events", len(edit_events))
+
+
+def start(
+    path: str,
+    is_dry_run: bool = False,
+    flush_interval_sec: int = DEFAULT_FLUSH_INTERVAL_SECONDS,
+    single_events_size_threshold: int = DEFAULT_SINGLE_EVENTS_SIZE_THRESHOLD,
+    cclient: clearcut_client.Clearcut | None = None,
+    pipe_sender: multiprocessing.connection.Connection | None = None,
+):
+  """Method to start the edit monitor.
+
+  This is the entry point to start the edit monitor as a subprocess of
+  the daemon manager.
+
+  params:
+    path: The root path to monitor
+    cclient: The clearcut client to send the edit logs.
+    conn: the sender of the pipe to communicate with the deamon manager.
+  """
+  event_handler = ClearcutEventHandler(
+      path, flush_interval_sec, single_events_size_threshold, is_dry_run, cclient)
+  observer = Observer()
+
+  logging.info("Starting observer on path %s.", path)
+  observer.schedule(event_handler, path, recursive=True)
+  observer.start()
+  logging.info("Observer started.")
+  if pipe_sender:
+    pipe_sender.send("Observer started.")
+
+  try:
+    while True:
+      time.sleep(1)
+  finally:
+    event_handler.flushall()
+    observer.stop()
+    observer.join()
+    if pipe_sender:
+      pipe_sender.close()
diff --git a/tools/edit_monitor/edit_monitor_integration_test.py b/tools/edit_monitor/edit_monitor_integration_test.py
new file mode 100644
index 0000000000..f39b93667d
--- /dev/null
+++ b/tools/edit_monitor/edit_monitor_integration_test.py
@@ -0,0 +1,169 @@
+# Copyright 2024, The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+"""Integration tests for Edit Monitor."""
+
+import glob
+from importlib import resources
+import logging
+import os
+import pathlib
+import shutil
+import signal
+import subprocess
+import sys
+import tempfile
+import time
+import unittest
+from unittest import mock
+
+
+class EditMonitorIntegrationTest(unittest.TestCase):
+
+  @classmethod
+  def setUpClass(cls):
+    super().setUpClass()
+    # Configure to print logging to stdout.
+    logging.basicConfig(filename=None, level=logging.DEBUG)
+    console = logging.StreamHandler(sys.stdout)
+    logging.getLogger("").addHandler(console)
+
+  def setUp(self):
+    super().setUp()
+    self.working_dir = tempfile.TemporaryDirectory()
+    self.root_monitoring_path = pathlib.Path(self.working_dir.name).joinpath(
+        "files"
+    )
+    self.root_monitoring_path.mkdir()
+    self.edit_monitor_binary_path = self._import_executable("edit_monitor")
+    self.patch = mock.patch.dict(
+        os.environ, {"ENABLE_ANDROID_EDIT_MONITOR": "true"}
+    )
+    self.patch.start()
+
+  def tearDown(self):
+    self.patch.stop()
+    self.working_dir.cleanup()
+    super().tearDown()
+
+  def test_log_single_edit_event_success(self):
+    p = self._start_edit_monitor_process()
+
+    # Create the .git file under the monitoring dir.
+    self.root_monitoring_path.joinpath(".git").touch()
+
+    # Create and modify a file.
+    test_file = self.root_monitoring_path.joinpath("test.txt")
+    with open(test_file, "w") as f:
+      f.write("something")
+
+    # Move the file.
+    test_file_moved = self.root_monitoring_path.joinpath("new_test.txt")
+    test_file.rename(test_file_moved)
+
+    # Delete the file.
+    test_file_moved.unlink()
+
+    # Give some time for the edit monitor to receive the edit event.
+    time.sleep(1)
+    # Stop the edit monitor and flush all events.
+    os.kill(p.pid, signal.SIGINT)
+    p.communicate()
+
+    self.assertEqual(self._get_logged_events_num(), 4)
+
+  def test_start_multiple_edit_monitor_only_one_started(self):
+    p1 = self._start_edit_monitor_process(wait_for_observer_start=False)
+    p2 = self._start_edit_monitor_process(wait_for_observer_start=False)
+    p3 = self._start_edit_monitor_process(wait_for_observer_start=False)
+
+    live_processes = self._get_live_processes([p1, p2, p3])
+
+    # Cleanup all live processes.
+    for p in live_processes:
+      os.kill(p.pid, signal.SIGINT)
+      p.communicate()
+
+    self.assertEqual(len(live_processes), 1)
+
+  def _start_edit_monitor_process(self, wait_for_observer_start=True):
+    command = f"""
+    export TMPDIR="{self.working_dir.name}"
+    {self.edit_monitor_binary_path} --path={self.root_monitoring_path} --dry_run"""
+    p = subprocess.Popen(
+        command,
+        shell=True,
+        text=True,
+        start_new_session=True,
+        executable="/bin/bash",
+    )
+    if wait_for_observer_start:
+      self._wait_for_observer_start(time_out=5)
+
+    return p
+
+  def _wait_for_observer_start(self, time_out):
+    start_time = time.time()
+
+    while time.time() < start_time + time_out:
+      log_files = glob.glob(self.working_dir.name + "/edit_monitor_*/*.log")
+      if log_files:
+        with open(log_files[0], "r") as f:
+          for line in f:
+            logging.debug("initial log: %s", line)
+            if line.rstrip("\n").endswith("Observer started."):
+              return
+      else:
+        time.sleep(1)
+
+    self.fail(f"Observer not started in {time_out} seconds.")
+
+  def _get_logged_events_num(self):
+    log_files = glob.glob(self.working_dir.name + "/edit_monitor_*/*.log")
+    self.assertEqual(len(log_files), 1)
+
+    with open(log_files[0], "r") as f:
+      for line in f:
+        logging.debug("complete log: %s", line)
+        if line.rstrip("\n").endswith("in dry run."):
+          return int(line.split(":")[-1].split(" ")[2])
+
+    return 0
+
+  def _get_live_processes(self, processes):
+    live_processes = []
+    for p in processes:
+      try:
+        p.wait(timeout=5)
+      except subprocess.TimeoutExpired as e:
+        live_processes.append(p)
+        logging.info("process: %d still alive.", p.pid)
+      else:
+        logging.info("process: %d stopped.", p.pid)
+    return live_processes
+
+  def _import_executable(self, executable_name: str) -> pathlib.Path:
+    binary_dir = pathlib.Path(self.working_dir.name).joinpath("binary")
+    binary_dir.mkdir()
+    executable_path = binary_dir.joinpath(executable_name)
+    with resources.as_file(
+        resources.files("testdata").joinpath(executable_name)
+    ) as binary:
+      shutil.copy(binary, executable_path)
+    executable_path.chmod(0o755)
+    return executable_path
+
+
+if __name__ == "__main__":
+  unittest.main()
diff --git a/tools/edit_monitor/edit_monitor_test.py b/tools/edit_monitor/edit_monitor_test.py
new file mode 100644
index 0000000000..64a3871b22
--- /dev/null
+++ b/tools/edit_monitor/edit_monitor_test.py
@@ -0,0 +1,301 @@
+# Copyright 2024, The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+"""Unittests for Edit Monitor."""
+
+import logging
+import multiprocessing
+import os
+import pathlib
+import signal
+import sys
+import tempfile
+import time
+import unittest
+
+from atest.proto import clientanalytics_pb2
+from edit_monitor import edit_monitor
+from proto import edit_event_pb2
+
+
+class EditMonitorTest(unittest.TestCase):
+
+  @classmethod
+  def setUpClass(cls):
+    super().setUpClass()
+    # Configure to print logging to stdout.
+    logging.basicConfig(filename=None, level=logging.DEBUG)
+    console = logging.StreamHandler(sys.stdout)
+    logging.getLogger('').addHandler(console)
+
+  def setUp(self):
+    super().setUp()
+    self.working_dir = tempfile.TemporaryDirectory()
+    self.root_monitoring_path = pathlib.Path(self.working_dir.name).joinpath(
+        'files'
+    )
+    self.root_monitoring_path.mkdir()
+    self.log_event_dir = pathlib.Path(self.working_dir.name).joinpath('logs')
+    self.log_event_dir.mkdir()
+
+  def tearDown(self):
+    self.working_dir.cleanup()
+    super().tearDown()
+
+  def test_log_single_edit_event_success(self):
+    # Create the .git file under the monitoring dir.
+    self.root_monitoring_path.joinpath('.git').touch()
+    fake_cclient = FakeClearcutClient(
+        log_output_file=self.log_event_dir.joinpath('logs.output')
+    )
+    p = self._start_test_edit_monitor_process(fake_cclient)
+
+    # Create and modify a file.
+    test_file = self.root_monitoring_path.joinpath('test.txt')
+    with open(test_file, 'w') as f:
+      f.write('something')
+    # Move the file.
+    test_file_moved = self.root_monitoring_path.joinpath('new_test.txt')
+    test_file.rename(test_file_moved)
+    # Delete the file.
+    test_file_moved.unlink()
+    # Give some time for the edit monitor to receive the edit event.
+    time.sleep(1)
+    # Stop the edit monitor and flush all events.
+    os.kill(p.pid, signal.SIGINT)
+    p.join()
+
+    logged_events = self._get_logged_events()
+    self.assertEqual(len(logged_events), 4)
+    expected_create_event = edit_event_pb2.EditEvent.SingleEditEvent(
+        file_path=str(
+            self.root_monitoring_path.joinpath('test.txt').resolve()
+        ),
+        edit_type=edit_event_pb2.EditEvent.CREATE,
+    )
+    expected_modify_event = edit_event_pb2.EditEvent.SingleEditEvent(
+        file_path=str(
+            self.root_monitoring_path.joinpath('test.txt').resolve()
+        ),
+        edit_type=edit_event_pb2.EditEvent.MODIFY,
+    )
+    expected_move_event = edit_event_pb2.EditEvent.SingleEditEvent(
+        file_path=str(
+            self.root_monitoring_path.joinpath('test.txt').resolve()
+        ),
+        edit_type=edit_event_pb2.EditEvent.MOVE,
+    )
+    expected_delete_event = edit_event_pb2.EditEvent.SingleEditEvent(
+        file_path=str(
+            self.root_monitoring_path.joinpath('new_test.txt').resolve()
+        ),
+        edit_type=edit_event_pb2.EditEvent.DELETE,
+    )
+    self.assertEqual(
+        expected_create_event,
+        edit_event_pb2.EditEvent.FromString(
+            logged_events[0].source_extension
+        ).single_edit_event,
+    )
+    self.assertEqual(
+        expected_modify_event,
+        edit_event_pb2.EditEvent.FromString(
+            logged_events[1].source_extension
+        ).single_edit_event,
+    )
+    self.assertEqual(
+        expected_move_event,
+        edit_event_pb2.EditEvent.FromString(
+            logged_events[2].source_extension
+        ).single_edit_event,
+    )
+    self.assertEqual(
+        expected_delete_event,
+        edit_event_pb2.EditEvent.FromString(
+            logged_events[3].source_extension
+        ).single_edit_event,
+    )
+
+
+  def test_log_aggregated_edit_event_success(self):
+    # Create the .git file under the monitoring dir.
+    self.root_monitoring_path.joinpath('.git').touch()
+    fake_cclient = FakeClearcutClient(
+        log_output_file=self.log_event_dir.joinpath('logs.output')
+    )
+    p = self._start_test_edit_monitor_process(fake_cclient)
+
+    # Create 6 test files
+    for i in range(6):
+      test_file = self.root_monitoring_path.joinpath('test_' + str(i))
+      test_file.touch()
+
+    # Give some time for the edit monitor to receive the edit event.
+    time.sleep(1)
+    # Stop the edit monitor and flush all events.
+    os.kill(p.pid, signal.SIGINT)
+    p.join()
+
+    logged_events = self._get_logged_events()
+    self.assertEqual(len(logged_events), 1)
+
+    expected_aggregated_edit_event = (
+        edit_event_pb2.EditEvent.AggregatedEditEvent(
+            num_edits=6,
+        )
+    )
+
+    self.assertEqual(
+        expected_aggregated_edit_event,
+        edit_event_pb2.EditEvent.FromString(
+            logged_events[0].source_extension
+        ).aggregated_edit_event,
+    )
+
+  def test_do_not_log_edit_event_for_directory_change(self):
+    # Create the .git file under the monitoring dir.
+    self.root_monitoring_path.joinpath('.git').touch()
+    fake_cclient = FakeClearcutClient(
+        log_output_file=self.log_event_dir.joinpath('logs.output')
+    )
+    p = self._start_test_edit_monitor_process(fake_cclient)
+
+    # Create a sub directory
+    self.root_monitoring_path.joinpath('test_dir').mkdir()
+    # Give some time for the edit monitor to receive the edit event.
+    time.sleep(1)
+    # Stop the edit monitor and flush all events.
+    os.kill(p.pid, signal.SIGINT)
+    p.join()
+
+    logged_events = self._get_logged_events()
+    self.assertEqual(len(logged_events), 0)
+
+  def test_do_not_log_edit_event_for_hidden_file(self):
+    # Create the .git file under the monitoring dir.
+    self.root_monitoring_path.joinpath('.git').touch()
+    fake_cclient = FakeClearcutClient(
+        log_output_file=self.log_event_dir.joinpath('logs.output')
+    )
+    p = self._start_test_edit_monitor_process(fake_cclient)
+
+    # Create a hidden file.
+    self.root_monitoring_path.joinpath('.test.txt').touch()
+    # Create a hidden dir.
+    hidden_dir = self.root_monitoring_path.joinpath('.test')
+    hidden_dir.mkdir()
+    hidden_dir.joinpath('test.txt').touch()
+    # Give some time for the edit monitor to receive the edit event.
+    time.sleep(1)
+    # Stop the edit monitor and flush all events.
+    os.kill(p.pid, signal.SIGINT)
+    p.join()
+
+    logged_events = self._get_logged_events()
+    self.assertEqual(len(logged_events), 0)
+
+  def test_do_not_log_edit_event_for_non_git_project_file(self):
+    fake_cclient = FakeClearcutClient(
+        log_output_file=self.log_event_dir.joinpath('logs.output')
+    )
+    p = self._start_test_edit_monitor_process(fake_cclient)
+
+    # Create a file.
+    self.root_monitoring_path.joinpath('test.txt').touch()
+    # Create a file under a sub dir.
+    sub_dir = self.root_monitoring_path.joinpath('.test')
+    sub_dir.mkdir()
+    sub_dir.joinpath('test.txt').touch()
+    # Give some time for the edit monitor to receive the edit event.
+    time.sleep(1)
+    # Stop the edit monitor and flush all events.
+    os.kill(p.pid, signal.SIGINT)
+    p.join()
+
+    logged_events = self._get_logged_events()
+    self.assertEqual(len(logged_events), 0)
+
+  def test_log_edit_event_fail(self):
+    # Create the .git file under the monitoring dir.
+    self.root_monitoring_path.joinpath('.git').touch()
+    fake_cclient = FakeClearcutClient(
+        log_output_file=self.log_event_dir.joinpath('logs.output'),
+        raise_log_exception=True,
+    )
+    p = self._start_test_edit_monitor_process(fake_cclient)
+
+    # Create a file.
+    self.root_monitoring_path.joinpath('test.txt').touch()
+    # Give some time for the edit monitor to receive the edit event.
+    time.sleep(1)
+    # Stop the edit monitor and flush all events.
+    os.kill(p.pid, signal.SIGINT)
+    p.join()
+
+    logged_events = self._get_logged_events()
+    self.assertEqual(len(logged_events), 0)
+
+  def _start_test_edit_monitor_process(
+      self, cclient
+  ) -> multiprocessing.Process:
+    receiver, sender = multiprocessing.Pipe()
+    # Start edit monitor in a subprocess.
+    p = multiprocessing.Process(
+        target=edit_monitor.start,
+        args=(str(self.root_monitoring_path.resolve()), False, 0.5, 5, cclient, sender),
+    )
+    p.daemon = True
+    p.start()
+
+    # Wait until observer started.
+    received_data = receiver.recv()
+    self.assertEquals(received_data, 'Observer started.')
+
+    receiver.close()
+    return p
+
+  def _get_logged_events(self):
+    with open(self.log_event_dir.joinpath('logs.output'), 'rb') as f:
+      data = f.read()
+
+    return [
+        clientanalytics_pb2.LogEvent.FromString(record)
+        for record in data.split(b'\x00')
+        if record
+    ]
+
+
+class FakeClearcutClient:
+
+  def __init__(self, log_output_file, raise_log_exception=False):
+    self.pending_log_events = []
+    self.raise_log_exception = raise_log_exception
+    self.log_output_file = log_output_file
+
+  def log(self, log_event):
+    if self.raise_log_exception:
+      raise Exception('unknown exception')
+    self.pending_log_events.append(log_event)
+
+  def flush_events(self):
+    delimiter = b'\x00'  # Use a null byte as the delimiter
+    with open(self.log_output_file, 'wb') as f:
+      for log_event in self.pending_log_events:
+        f.write(log_event.SerializeToString() + delimiter)
+
+    self.pending_log_events.clear()
+
+
+if __name__ == '__main__':
+  unittest.main()
diff --git a/tools/edit_monitor/main.py b/tools/edit_monitor/main.py
new file mode 100644
index 0000000000..3c2d183aed
--- /dev/null
+++ b/tools/edit_monitor/main.py
@@ -0,0 +1,119 @@
+# Copyright 2024, The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+import argparse
+import logging
+import os
+import signal
+import sys
+import tempfile
+
+from edit_monitor import daemon_manager
+from edit_monitor import edit_monitor
+
+
+def create_arg_parser():
+  """Creates an instance of the default arg parser."""
+
+  parser = argparse.ArgumentParser(
+      description=(
+          'Monitors edits in Android source code and uploads the edit logs.'
+      ),
+      add_help=True,
+      formatter_class=argparse.RawDescriptionHelpFormatter,
+  )
+
+  parser.add_argument(
+      '--path',
+      type=str,
+      required=True,
+      help='Root path to monitor the edit events.',
+  )
+
+  parser.add_argument(
+      '--dry_run',
+      action='store_true',
+      help='Dry run the edit monitor. This starts the edit monitor process without actually send the edit logs to clearcut.',
+  )
+
+  parser.add_argument(
+      '--force_cleanup',
+      action='store_true',
+      help=(
+          'Instead of start a new edit monitor, force stop all existing edit'
+          ' monitors in the system. This option is only used in emergent cases'
+          ' when we want to prevent user damage by the edit monitor.'
+      ),
+  )
+
+  parser.add_argument(
+      '--verbose',
+      action='store_true',
+      help=(
+          'Log verbose info in the log file for debugging purpose.'
+      ),
+  )
+
+  return parser
+
+
+def configure_logging(verbose=False):
+  root_logging_dir = tempfile.mkdtemp(prefix='edit_monitor_')
+  _, log_path = tempfile.mkstemp(dir=root_logging_dir, suffix='.log')
+
+
+  log_fmt = '%(asctime)s.%(msecs)03d %(filename)s:%(lineno)s:%(levelname)s: %(message)s'
+  date_fmt = '%Y-%m-%d %H:%M:%S'
+  log_level = logging.DEBUG if verbose else logging.INFO
+
+  logging.basicConfig(
+      filename=log_path, level=log_level, format=log_fmt, datefmt=date_fmt
+  )
+  # Filter out logs from inotify_buff to prevent log pollution.
+  logging.getLogger('watchdog.observers.inotify_buffer').addFilter(
+      lambda record: record.filename != 'inotify_buffer.py')
+  print(f'logging to file {log_path}')
+
+
+def term_signal_handler(_signal_number, _frame):
+  logging.info('Process %d received SIGTERM, Terminating...', os.getpid())
+  sys.exit(0)
+
+
+def main(argv: list[str]):
+  args = create_arg_parser().parse_args(argv[1:])
+  configure_logging(args.verbose)
+  if args.dry_run:
+    logging.info('This is a dry run.')
+  dm = daemon_manager.DaemonManager(
+      binary_path=argv[0],
+      daemon_target=edit_monitor.start,
+      daemon_args=(args.path, args.dry_run),
+  )
+
+  try:
+    if args.force_cleanup:
+      dm.cleanup()
+    else:
+      dm.start()
+      dm.monitor_daemon()
+  except Exception:
+    logging.exception('Unexpected exception raised when run daemon.')
+  finally:
+    dm.stop()
+
+
+if __name__ == '__main__':
+  signal.signal(signal.SIGTERM, term_signal_handler)
+  main(sys.argv)
diff --git a/tools/edit_monitor/proto/edit_event.proto b/tools/edit_monitor/proto/edit_event.proto
new file mode 100644
index 0000000000..9acc2e754b
--- /dev/null
+++ b/tools/edit_monitor/proto/edit_event.proto
@@ -0,0 +1,57 @@
+syntax = "proto3";
+
+package tools.asuite.edit_monitor;
+
+message EditEvent {
+  enum EditType {
+    UNSUPPORTED_TYPE = 0;
+    CREATE = 1;
+    MODIFY = 2;
+    DELETE = 3;
+    MOVE = 4;
+  }
+
+  enum ErrorType {
+    UNKNOWN_ERROR = 0;
+    FAILED_TO_START_EDIT_MONITOR = 1;
+    FAILED_TO_STOP_EDIT_MONITOR = 2;
+    FAILED_TO_REBOOT_EDIT_MONITOR = 3;
+    KILLED_DUE_TO_EXCEEDED_MEMORY_USAGE = 4;
+    FORCE_CLEANUP = 5;
+    KILLED_DUE_TO_EXCEEDED_CPU_USAGE = 6;
+  }
+
+  // Event that logs a single edit
+  message SingleEditEvent {
+    // Full path of the file that edited.
+    string file_path = 1;
+    // Type of the edit.
+    EditType edit_type = 2;
+  }
+
+  // Event that logs aggregated info for a set of edits.
+  message AggregatedEditEvent {
+    int32 num_edits = 1;
+  }
+
+  // Event that logs errors happened in the edit monitor.
+  message EditMonitorErrorEvent {
+    ErrorType error_type = 1;
+  }
+
+  // ------------------------
+  // FIELDS FOR EditEvent
+  // ------------------------
+  // Internal user name.
+  string user_name = 1;
+  // The root of Android source.
+  string source_root = 2;
+  // Name of the host workstation.
+  string host_name = 3;
+
+  oneof event {
+    SingleEditEvent single_edit_event = 4;
+    AggregatedEditEvent aggregated_edit_event = 5;
+    EditMonitorErrorEvent edit_monitor_error_event = 6;
+  }
+}
diff --git a/tools/edit_monitor/utils.py b/tools/edit_monitor/utils.py
new file mode 100644
index 0000000000..b88949d300
--- /dev/null
+++ b/tools/edit_monitor/utils.py
@@ -0,0 +1,53 @@
+# Copyright 2024, The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+import hashlib
+import logging
+import os
+
+
+def is_feature_enabled(
+    feature_name: str,
+    user_name: str,
+    enable_flag: str = None,
+    rollout_percent: int = 100,
+) -> bool:
+  """Determine whether the given feature is enabled.
+
+  Whether a given feature is enabled or not depends on two flags: 1) the
+  enable_flag that explicitly enable/disable the feature and 2) the rollout_flag
+  that controls the rollout percentage.
+
+  Args:
+    feature_name: name of the feature.
+    user_name: system user name.
+    enable_flag: name of the env var that enables/disables the feature
+      explicitly.
+    rollout_flg: name of the env var that controls the rollout percentage, the
+      value stored in the env var should be an int between 0 and 100 string
+  """
+  if enable_flag:
+    if os.environ.get(enable_flag, "") == "false":
+      logging.info("feature: %s is disabled", feature_name)
+      return False
+
+    if os.environ.get(enable_flag, "") == "true":
+      logging.info("feature: %s is enabled", feature_name)
+      return True
+
+  hash_object = hashlib.sha256()
+  hash_object.update((user_name + feature_name).encode("utf-8"))
+  hash_number = int(hash_object.hexdigest(), 16) % 100
+
+  return hash_number < rollout_percent
diff --git a/tools/edit_monitor/utils_test.py b/tools/edit_monitor/utils_test.py
new file mode 100644
index 0000000000..1c30aa1acc
--- /dev/null
+++ b/tools/edit_monitor/utils_test.py
@@ -0,0 +1,71 @@
+# Copyright 2024, The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+"""Unittests for edit monitor utils."""
+import os
+import unittest
+from unittest import mock
+
+from edit_monitor import utils
+
+TEST_USER = 'test_user'
+TEST_FEATURE = 'test_feature'
+ENABLE_TEST_FEATURE_FLAG = 'ENABLE_TEST_FEATURE'
+ROLLOUT_TEST_FEATURE_FLAG = 'ROLLOUT_TEST_FEATURE'
+
+
+class EnableFeatureTest(unittest.TestCase):
+
+  def test_feature_enabled_without_flag(self):
+    self.assertTrue(utils.is_feature_enabled(TEST_FEATURE, TEST_USER))
+
+  @mock.patch.dict(os.environ, {ENABLE_TEST_FEATURE_FLAG: 'false'}, clear=True)
+  def test_feature_disabled_with_flag(self):
+    self.assertFalse(
+        utils.is_feature_enabled(
+            TEST_FEATURE, TEST_USER, ENABLE_TEST_FEATURE_FLAG
+        )
+    )
+
+  @mock.patch.dict(os.environ, {ENABLE_TEST_FEATURE_FLAG: 'true'}, clear=True)
+  def test_feature_enabled_with_flag(self):
+    self.assertTrue(
+        utils.is_feature_enabled(
+            TEST_FEATURE, TEST_USER, ENABLE_TEST_FEATURE_FLAG
+        )
+    )
+
+  def test_feature_enabled_with_rollout_percentage(self):
+    self.assertTrue(
+        utils.is_feature_enabled(
+            TEST_FEATURE,
+            TEST_USER,
+            ENABLE_TEST_FEATURE_FLAG,
+            90,
+        )
+    )
+
+  def test_feature_disabled_with_rollout_percentage(self):
+    self.assertFalse(
+        utils.is_feature_enabled(
+            TEST_FEATURE,
+            TEST_USER,
+            ENABLE_TEST_FEATURE_FLAG,
+            10,
+        )
+    )
+
+
+if __name__ == '__main__':
+  unittest.main()
diff --git a/tools/filelistdiff/Android.bp b/tools/filelistdiff/Android.bp
index ab766d6d93..3826e50ff3 100644
--- a/tools/filelistdiff/Android.bp
+++ b/tools/filelistdiff/Android.bp
@@ -24,4 +24,9 @@ python_binary_host {
 prebuilt_etc_host {
     name: "system_image_diff_allowlist",
     src: "allowlist",
-}
\ No newline at end of file
+}
+
+prebuilt_etc_host {
+    name: "system_image_diff_allowlist_next",
+    src: "allowlist_next",
+}
diff --git a/tools/filelistdiff/allowlist b/tools/filelistdiff/allowlist
index 120045e3b2..eb785872cf 100644
--- a/tools/filelistdiff/allowlist
+++ b/tools/filelistdiff/allowlist
@@ -1,51 +1,5 @@
-# Known diffs only in the KATI system image
-etc/NOTICE.xml.gz
-framework/oat/x86_64/apex@com.android.compos@javalib@service-compos.jar@classes.odex
-framework/oat/x86_64/apex@com.android.compos@javalib@service-compos.jar@classes.odex.fsv_meta
-framework/oat/x86_64/apex@com.android.compos@javalib@service-compos.jar@classes.vdex
-framework/oat/x86_64/apex@com.android.compos@javalib@service-compos.jar@classes.vdex.fsv_meta
-lib/aaudio-aidl-cpp.so
-lib/android.hardware.biometrics.fingerprint@2.1.so
-lib/android.hardware.radio.config@1.0.so
-lib/android.hardware.radio.deprecated@1.0.so
-lib/android.hardware.radio@1.0.so
-lib/android.hardware.radio@1.1.so
-lib/android.hardware.radio@1.2.so
-lib/android.hardware.radio@1.3.so
-lib/android.hardware.radio@1.4.so
-lib/android.hardware.secure_element@1.0.so
-lib/com.android.media.aaudio-aconfig-cc.so
-lib/heapprofd_client.so
-lib/heapprofd_client_api.so
-lib/libaaudio.so
-lib/libaaudio_internal.so
-lib/libalarm_jni.so
-lib/libamidi.so
-lib/libcups.so
-lib/libjni_deviceAsWebcam.so
-lib/libprintspooler_jni.so
-lib/libvendorsupport.so
-lib/libwfds.so
-lib/libyuv.so
-
-# b/351258461
-adb_keys
+# Known diffs that are installed in either system image with the configuration
+# b/353429422
 init.environ.rc
-
-# Known diffs only in the Soong system image
-lib/libhidcommand_jni.so
-lib/libuinputcommand_jni.so
-
-# Known diffs in internal source
-bin/uprobestats
-etc/aconfig/flag.map
-etc/aconfig/flag.val
-etc/aconfig/package.map
-etc/bpf/uprobestats/BitmapAllocation.o
-etc/bpf/uprobestats/GenericInstrumentation.o
-etc/bpf/uprobestats/ProcessManagement.o
-etc/init/UprobeStats.rc
-lib/libuprobestats_client.so
-lib64/libuprobestats_client.so
-priv-app/DeviceDiagnostics/DeviceDiagnostics.apk
-
+# b/338342381
+etc/NOTICE.xml.gz
diff --git a/tools/filelistdiff/allowlist_next b/tools/filelistdiff/allowlist_next
new file mode 100644
index 0000000000..8f91c9f3e4
--- /dev/null
+++ b/tools/filelistdiff/allowlist_next
@@ -0,0 +1,9 @@
+# Allowlist only for the next release configuration.
+# TODO(b/369678122): The list will be cleared when the trunk configurations are
+# available to the next.
+
+# KATI only installed files
+framework/oat/x86_64/apex@com.android.compos@javalib@service-compos.jar@classes.odex
+framework/oat/x86_64/apex@com.android.compos@javalib@service-compos.jar@classes.odex.fsv_meta
+framework/oat/x86_64/apex@com.android.compos@javalib@service-compos.jar@classes.vdex
+framework/oat/x86_64/apex@com.android.compos@javalib@service-compos.jar@classes.vdex.fsv_meta
diff --git a/tools/filelistdiff/file_list_diff.py b/tools/filelistdiff/file_list_diff.py
index cdc5b2ee41..a6408e87cc 100644
--- a/tools/filelistdiff/file_list_diff.py
+++ b/tools/filelistdiff/file_list_diff.py
@@ -19,38 +19,54 @@ COLOR_WARNING = '\033[93m'
 COLOR_ERROR = '\033[91m'
 COLOR_NORMAL = '\033[0m'
 
-def find_unique_items(kati_installed_files, soong_installed_files, allowlist, system_module_name):
+def find_unique_items(kati_installed_files, soong_installed_files, system_module_name, allowlists):
     with open(kati_installed_files, 'r') as kati_list_file, \
-            open(soong_installed_files, 'r') as soong_list_file, \
-            open(allowlist, 'r') as allowlist_file:
+            open(soong_installed_files, 'r') as soong_list_file:
         kati_files = set(kati_list_file.read().split())
         soong_files = set(soong_list_file.read().split())
-        allowed_files = set(filter(lambda x: len(x), map(lambda x: x.lstrip().split('#',1)[0].rstrip() , allowlist_file.read().split('\n'))))
+
+    allowed_files = set()
+    for allowlist in allowlists:
+        with open(allowlist, 'r') as allowlist_file:
+            allowed_files.update(set(filter(lambda x: len(x), map(lambda x: x.lstrip().split('#',1)[0].rstrip() , allowlist_file.read().split('\n')))))
 
     def is_unknown_diff(filepath):
-        return not filepath in allowed_files
+        return filepath not in allowed_files
+
+    def is_unnecessary_allowlist(filepath):
+        return filepath not in kati_files.symmetric_difference(soong_files)
 
     unique_in_kati = set(filter(is_unknown_diff, kati_files - soong_files))
     unique_in_soong = set(filter(is_unknown_diff, soong_files - kati_files))
+    unnecessary_allowlists = set(filter(is_unnecessary_allowlist, allowed_files))
 
     if unique_in_kati:
-        print(f'{COLOR_ERROR}Please add following modules into system image module {system_module_name}.{COLOR_NORMAL}')
-        print(f'{COLOR_WARNING}KATI only module(s):{COLOR_NORMAL}')
+        print('')
+        print(f'{COLOR_ERROR}Missing required modules in {system_module_name} module.{COLOR_NORMAL}')
+        print(f'To resolve this issue, please add the modules to the Android.bp file for the {system_module_name} to install the following KATI only installed files.')
+        print(f'You can find the correct Android.bp file using the command "gomod {system_module_name}".')
+        print(f'{COLOR_WARNING}KATI only installed file(s):{COLOR_NORMAL}')
         for item in sorted(unique_in_kati):
-            print(item)
+            print('  '+item)
 
     if unique_in_soong:
-        if unique_in_kati:
-            print('')
-
-        print(f'{COLOR_ERROR}Please add following modules into build/make/target/product/base_system.mk.{COLOR_NORMAL}')
-        print(f'{COLOR_WARNING}Soong only module(s):{COLOR_NORMAL}')
+        print('')
+        print(f'{COLOR_ERROR}Missing packages in base_system.mk.{COLOR_NORMAL}')
+        print('Please add packages into build/make/target/product/base_system.mk or build/make/tools/filelistdiff/allowlist to install or skip the following Soong only installed files.')
+        print(f'{COLOR_WARNING}Soong only installed file(s):{COLOR_NORMAL}')
         for item in sorted(unique_in_soong):
-            print(item)
+            print('  '+item)
+
+    if unnecessary_allowlists:
+        print('')
+        print(f'{COLOR_ERROR}Unnecessary files in allowlist.{COLOR_NORMAL}')
+        print('Please remove these entries from build/make/tools/filelistdiff/allowlist')
+        for item in sorted(unnecessary_allowlists):
+            print('  '+item)
+
 
-    if unique_in_kati or unique_in_soong:
+    if unique_in_kati or unique_in_soong or unnecessary_allowlists:
         print('')
-        print(f'{COLOR_ERROR}FAILED: System image from KATI and SOONG differs from installed file list.{COLOR_NORMAL}')
         sys.exit(1)
 
 
@@ -59,8 +75,8 @@ if __name__ == '__main__':
 
     parser.add_argument('kati_installed_file_list')
     parser.add_argument('soong_installed_file_list')
-    parser.add_argument('allowlist')
     parser.add_argument('system_module_name')
+    parser.add_argument('--allowlists', nargs='*', default=[])
     args = parser.parse_args()
 
-    find_unique_items(args.kati_installed_file_list, args.soong_installed_file_list, args.allowlist, args.system_module_name)
\ No newline at end of file
+    find_unique_items(args.kati_installed_file_list, args.soong_installed_file_list, args.system_module_name, args.allowlists)
\ No newline at end of file
diff --git a/tools/finalization/environment.sh b/tools/finalization/environment.sh
index cf3e61bd99..9a287c4666 100755
--- a/tools/finalization/environment.sh
+++ b/tools/finalization/environment.sh
@@ -34,3 +34,4 @@ export FINAL_CORRESPONDING_VERSION_LETTER='W'
 export FINAL_CORRESPONDING_PLATFORM_VERSION='16'
 export FINAL_NEXT_BOARD_API_LEVEL='202604'
 export FINAL_NEXT_CORRESPONDING_VERSION_LETTER='X'
+export FINAL_NEXT_CORRESPONDING_SDK_VERSION='37'
diff --git a/tools/finalization/finalize-vintf-resources.sh b/tools/finalization/finalize-vintf-resources.sh
index 6f1a6f646e..45efc104db 100755
--- a/tools/finalization/finalize-vintf-resources.sh
+++ b/tools/finalization/finalize-vintf-resources.sh
@@ -16,6 +16,13 @@ function finalize_vintf_resources() {
     export TARGET_RELEASE=fina_0
     export TARGET_PRODUCT=aosp_arm64
 
+    # build/soong
+    local vendor_api_level_map="case ${FINAL_NEXT_BOARD_API_LEVEL}:"
+    if ! grep -q "$vendor_api_level_map" "$top/build/soong/android/vendor_api_levels.go" ; then
+        sed -i -e "/case ${FINAL_BOARD_API_LEVEL}:/{N;a \\\t$vendor_api_level_map\n\t\tsdkVersion = ${FINAL_NEXT_CORRESPONDING_SDK_VERSION}
+        }" "$top/build/soong/android/vendor_api_levels.go"
+    fi
+
     # system/sepolicy
     "$top/system/sepolicy/tools/finalize-vintf-resources.sh" "$top" "$FINAL_BOARD_API_LEVEL"
 
diff --git a/tools/fs_config/Android.bp b/tools/fs_config/Android.bp
index 6aa528963d..a5b6fd0a4c 100644
--- a/tools/fs_config/Android.bp
+++ b/tools/fs_config/Android.bp
@@ -277,6 +277,7 @@ genrule_defaults {
     out: ["out"],
 }
 
+// system
 genrule {
     name: "fs_config_dirs_system_gen",
     defaults: ["fs_config_defaults"],
@@ -307,6 +308,7 @@ prebuilt_etc {
     src: ":fs_config_files_system_gen",
 }
 
+// system_ext
 genrule {
     name: "fs_config_dirs_system_ext_gen",
     defaults: ["fs_config_defaults"],
@@ -337,6 +339,7 @@ prebuilt_etc {
     system_ext_specific: true,
 }
 
+// product
 genrule {
     name: "fs_config_dirs_product_gen",
     defaults: ["fs_config_defaults"],
@@ -367,6 +370,7 @@ prebuilt_etc {
     product_specific: true,
 }
 
+// vendor
 genrule {
     name: "fs_config_dirs_vendor_gen",
     defaults: ["fs_config_defaults"],
@@ -397,6 +401,7 @@ prebuilt_etc {
     vendor: true,
 }
 
+// odm
 genrule {
     name: "fs_config_dirs_odm_gen",
     defaults: ["fs_config_defaults"],
@@ -427,4 +432,214 @@ prebuilt_etc {
     device_specific: true,
 }
 
-// TODO(jiyong): add fs_config for oem, system_dlkm, vendor_dlkm, odm_dlkm partitions
+// system_dlkm
+genrule {
+    name: "fs_config_dirs_system_dlkm_gen",
+    defaults: ["fs_config_defaults"],
+    cmd: fs_config_cmd_dirs +
+        "--partition system_dlkm " +
+        "$(locations :target_fs_config_gen)",
+}
+
+prebuilt_etc {
+    name: "fs_config_dirs_system_dlkm",
+    filename: "fs_config_dirs",
+    src: ":fs_config_dirs_system_dlkm_gen",
+    system_dlkm_specific: true,
+}
+
+genrule {
+    name: "fs_config_files_system_dlkm_gen",
+    defaults: ["fs_config_defaults"],
+    cmd: fs_config_cmd_files +
+        "--partition system_dlkm " +
+        "$(locations :target_fs_config_gen)",
+}
+
+prebuilt_etc {
+    name: "fs_config_files_system_dlkm",
+    filename: "fs_config_files",
+    src: ":fs_config_files_system_dlkm_gen",
+    system_dlkm_specific: true,
+}
+
+// vendor_dlkm
+genrule {
+    name: "fs_config_dirs_vendor_dlkm_gen",
+    defaults: ["fs_config_defaults"],
+    cmd: fs_config_cmd_dirs +
+        "--partition vendor_dlkm " +
+        "$(locations :target_fs_config_gen)",
+}
+
+prebuilt_etc {
+    name: "fs_config_dirs_vendor_dlkm",
+    filename: "fs_config_dirs",
+    src: ":fs_config_dirs_vendor_dlkm_gen",
+    vendor_dlkm_specific: true,
+}
+
+genrule {
+    name: "fs_config_files_vendor_dlkm_gen",
+    defaults: ["fs_config_defaults"],
+    cmd: fs_config_cmd_files +
+        "--partition vendor_dlkm " +
+        "$(locations :target_fs_config_gen)",
+}
+
+prebuilt_etc {
+    name: "fs_config_files_vendor_dlkm",
+    filename: "fs_config_files",
+    src: ":fs_config_files_vendor_dlkm_gen",
+    vendor_dlkm_specific: true,
+}
+
+// odm_dlkm
+genrule {
+    name: "fs_config_dirs_odm_dlkm_gen",
+    defaults: ["fs_config_defaults"],
+    cmd: fs_config_cmd_dirs +
+        "--partition odm_dlkm " +
+        "$(locations :target_fs_config_gen)",
+}
+
+prebuilt_etc {
+    name: "fs_config_dirs_odm_dlkm",
+    filename: "fs_config_dirs",
+    src: ":fs_config_dirs_odm_dlkm_gen",
+    odm_dlkm_specific: true,
+}
+
+genrule {
+    name: "fs_config_files_odm_dlkm_gen",
+    defaults: ["fs_config_defaults"],
+    cmd: fs_config_cmd_files +
+        "--partition odm_dlkm " +
+        "$(locations :target_fs_config_gen)",
+}
+
+prebuilt_etc {
+    name: "fs_config_files_odm_dlkm",
+    filename: "fs_config_files",
+    src: ":fs_config_files_odm_dlkm_gen",
+    odm_dlkm_specific: true,
+}
+
+// oem
+genrule {
+    name: "fs_config_dirs_oem_gen",
+    defaults: ["fs_config_defaults"],
+    cmd: fs_config_cmd_dirs +
+        "--partition oem " +
+        "$(locations :target_fs_config_gen)",
+}
+
+prebuilt_etc {
+    name: "fs_config_dirs_oem",
+    filename: "fs_config_dirs",
+    src: ":fs_config_dirs_oem_gen",
+    oem_specific: true,
+}
+
+genrule {
+    name: "fs_config_files_oem_gen",
+    defaults: ["fs_config_defaults"],
+    cmd: fs_config_cmd_files +
+        "--partition oem " +
+        "$(locations :target_fs_config_gen)",
+}
+
+prebuilt_etc {
+    name: "fs_config_files_oem",
+    filename: "fs_config_files",
+    src: ":fs_config_files_oem_gen",
+    oem_specific: true,
+}
+
+// Generate the <p>/etc/fs_config_dirs binary files for each partition.
+// Add fs_config_dirs to PRODUCT_PACKAGES in the device make file to enable.
+phony {
+    name: "fs_config_dirs",
+    required: [
+        "fs_config_dirs_system",
+        "fs_config_dirs_system_ext",
+        "fs_config_dirs_product",
+        "fs_config_dirs_nonsystem",
+    ],
+}
+
+// Generate the <p>/etc/fs_config_files binary files for each partition.
+// Add fs_config_files to PRODUCT_PACKAGES in the device make file to enable.
+phony {
+    name: "fs_config_files",
+    required: [
+        "fs_config_files_system",
+        "fs_config_files_system_ext",
+        "fs_config_files_product",
+        "fs_config_files_nonsystem",
+    ],
+}
+
+// Generate the <p>/etc/fs_config_dirs binary files for all enabled partitions
+// excluding /system, /system_ext and /product. Add fs_config_dirs_nonsystem to
+// PRODUCT_PACKAGES in the device make file to enable.
+phony {
+    name: "fs_config_dirs_nonsystem",
+    required: [] +
+        select(soong_config_variable("fs_config", "vendor"), {
+            true: ["fs_config_dirs_vendor"],
+            default: [],
+        }) +
+        select(soong_config_variable("fs_config", "oem"), {
+            true: ["fs_config_dirs_oem"],
+            default: [],
+        }) +
+        select(soong_config_variable("fs_config", "odm"), {
+            true: ["fs_config_dirs_odm"],
+            default: [],
+        }) +
+        select(soong_config_variable("fs_config", "vendor_dlkm"), {
+            true: ["fs_config_dirs_vendor_dlkm"],
+            default: [],
+        }) +
+        select(soong_config_variable("fs_config", "odm_dlkm"), {
+            true: ["fs_config_dirs_odm_dlkm"],
+            default: [],
+        }) +
+        select(soong_config_variable("fs_config", "system_dlkm"), {
+            true: ["fs_config_dirs_system_dlkm"],
+            default: [],
+        }),
+}
+
+// Generate the <p>/etc/fs_config_files binary files for all enabled partitions
+// excluding /system, /system_ext and /product. Add fs_config_files_nonsystem to
+// PRODUCT_PACKAGES in the device make file to enable.
+phony {
+    name: "fs_config_files_nonsystem",
+    required: [] +
+        select(soong_config_variable("fs_config", "vendor"), {
+            true: ["fs_config_files_vendor"],
+            default: [],
+        }) +
+        select(soong_config_variable("fs_config", "oem"), {
+            true: ["fs_config_files_oem"],
+            default: [],
+        }) +
+        select(soong_config_variable("fs_config", "odm"), {
+            true: ["fs_config_files_odm"],
+            default: [],
+        }) +
+        select(soong_config_variable("fs_config", "vendor_dlkm"), {
+            true: ["fs_config_files_vendor_dlkm"],
+            default: [],
+        }) +
+        select(soong_config_variable("fs_config", "odm_dlkm"), {
+            true: ["fs_config_files_odm_dlkm"],
+            default: [],
+        }) +
+        select(soong_config_variable("fs_config", "system_dlkm"), {
+            true: ["fs_config_files_system_dlkm"],
+            default: [],
+        }),
+}
diff --git a/tools/fs_config/Android.mk b/tools/fs_config/Android.mk
deleted file mode 100644
index e4c362630f..0000000000
--- a/tools/fs_config/Android.mk
+++ /dev/null
@@ -1,328 +0,0 @@
-# Copyright (C) 2008 The Android Open Source Project
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
-LOCAL_PATH := $(call my-dir)
-
-# One can override the default android_filesystem_config.h file by using TARGET_FS_CONFIG_GEN.
-#   Set TARGET_FS_CONFIG_GEN to contain a list of intermediate format files
-#   for generating the android_filesystem_config.h file.
-#
-# More information can be found in the README
-
-ifneq ($(wildcard $(TARGET_DEVICE_DIR)/android_filesystem_config.h),)
-$(error Using $(TARGET_DEVICE_DIR)/android_filesystem_config.h is deprecated, please use TARGET_FS_CONFIG_GEN instead)
-endif
-
-android_filesystem_config := system/core/libcutils/include/private/android_filesystem_config.h
-capability_header := bionic/libc/kernel/uapi/linux/capability.h
-
-# List of supported vendor, oem, odm, vendor_dlkm, odm_dlkm, and system_dlkm Partitions
-fs_config_generate_extra_partition_list := $(strip \
-  $(if $(BOARD_USES_VENDORIMAGE)$(BOARD_VENDORIMAGE_FILE_SYSTEM_TYPE),vendor) \
-  $(if $(BOARD_USES_OEMIMAGE)$(BOARD_OEMIMAGE_FILE_SYSTEM_TYPE),oem) \
-  $(if $(BOARD_USES_ODMIMAGE)$(BOARD_ODMIMAGE_FILE_SYSTEM_TYPE),odm) \
-  $(if $(BOARD_USES_VENDOR_DLKMIMAGE)$(BOARD_VENDOR_DLKMIMAGE_FILE_SYSTEM_TYPE),vendor_dlkm) \
-  $(if $(BOARD_USES_ODM_DLKMIMAGE)$(BOARD_ODM_DLKMIMAGE_FILE_SYSTEM_TYPE),odm_dlkm) \
-  $(if $(BOARD_USES_SYSTEM_DLKMIMAGE)$(BOARD_SYSTEM_DLKMIMAGE_FILE_SYSTEM_TYPE),system_dlkm) \
-)
-
-##################################
-# Generate the <p>/etc/fs_config_dirs binary files for each partition.
-# Add fs_config_dirs to PRODUCT_PACKAGES in the device make file to enable.
-include $(CLEAR_VARS)
-
-LOCAL_MODULE := fs_config_dirs
-LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
-LOCAL_LICENSE_CONDITIONS := notice
-LOCAL_NOTICE_FILE := build/soong/licenses/LICENSE
-LOCAL_REQUIRED_MODULES := \
-  fs_config_dirs_system \
-  fs_config_dirs_system_ext \
-  fs_config_dirs_product \
-  fs_config_dirs_nonsystem
-include $(BUILD_PHONY_PACKAGE)
-
-##################################
-# Generate the <p>/etc/fs_config_files binary files for each partition.
-# Add fs_config_files to PRODUCT_PACKAGES in the device make file to enable.
-include $(CLEAR_VARS)
-
-LOCAL_MODULE := fs_config_files
-LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
-LOCAL_LICENSE_CONDITIONS := notice
-LOCAL_NOTICE_FILE := build/soong/licenses/LICENSE
-LOCAL_REQUIRED_MODULES := \
-  fs_config_files_system \
-  fs_config_files_system_ext \
-  fs_config_files_product \
-  fs_config_files_nonsystem
-include $(BUILD_PHONY_PACKAGE)
-
-##################################
-# Generate the <p>/etc/fs_config_dirs binary files for all enabled partitions
-# excluding /system, /system_ext and /product. Add fs_config_dirs_nonsystem to
-# PRODUCT_PACKAGES in the device make file to enable.
-include $(CLEAR_VARS)
-
-LOCAL_MODULE := fs_config_dirs_nonsystem
-LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
-LOCAL_LICENSE_CONDITIONS := notice
-LOCAL_NOTICE_FILE := build/soong/licenses/LICENSE
-LOCAL_REQUIRED_MODULES := $(foreach t,$(fs_config_generate_extra_partition_list),fs_config_dirs_$(t))
-include $(BUILD_PHONY_PACKAGE)
-
-##################################
-# Generate the <p>/etc/fs_config_files binary files for all enabled partitions
-# excluding /system, /system_ext and /product. Add fs_config_files_nonsystem to
-# PRODUCT_PACKAGES in the device make file to enable.
-include $(CLEAR_VARS)
-
-LOCAL_MODULE := fs_config_files_nonsystem
-LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
-LOCAL_LICENSE_CONDITIONS := notice
-LOCAL_NOTICE_FILE := build/soong/licenses/LICENSE
-LOCAL_REQUIRED_MODULES := $(foreach t,$(fs_config_generate_extra_partition_list),fs_config_files_$(t))
-include $(BUILD_PHONY_PACKAGE)
-
-ifneq ($(filter oem,$(fs_config_generate_extra_partition_list)),)
-##################################
-# Generate the oem/etc/fs_config_dirs binary file for the target
-# Add fs_config_dirs or fs_config_dirs_nonsystem to PRODUCT_PACKAGES
-# in the device make file to enable
-include $(CLEAR_VARS)
-
-LOCAL_MODULE := fs_config_dirs_oem
-LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
-LOCAL_LICENSE_CONDITIONS := notice
-LOCAL_NOTICE_FILE := build/soong/licenses/LICENSE
-LOCAL_MODULE_CLASS := ETC
-LOCAL_INSTALLED_MODULE_STEM := fs_config_dirs
-LOCAL_MODULE_PATH := $(TARGET_OUT_OEM)/etc
-include $(BUILD_SYSTEM)/base_rules.mk
-$(LOCAL_BUILT_MODULE): PRIVATE_ANDROID_FS_HDR := $(android_filesystem_config)
-$(LOCAL_BUILT_MODULE): PRIVATE_ANDROID_CAP_HDR := $(capability_header)
-$(LOCAL_BUILT_MODULE): PRIVATE_TARGET_FS_CONFIG_GEN := $(TARGET_FS_CONFIG_GEN)
-$(LOCAL_BUILT_MODULE): $(LOCAL_PATH)/fs_config_generator.py $(TARGET_FS_CONFIG_GEN) $(android_filesystem_config) $(capability_header)
-	@mkdir -p $(dir $@)
-	$< fsconfig \
-	   --aid-header $(PRIVATE_ANDROID_FS_HDR) \
-	   --capability-header $(PRIVATE_ANDROID_CAP_HDR) \
-	   --partition oem \
-	   --dirs \
-	   --out_file $@ \
-	   $(or $(PRIVATE_TARGET_FS_CONFIG_GEN),/dev/null)
-
-##################################
-# Generate the oem/etc/fs_config_files binary file for the target
-# Add fs_config_files or fs_config_files_nonsystem to PRODUCT_PACKAGES
-# in the device make file to enable
-include $(CLEAR_VARS)
-
-LOCAL_MODULE := fs_config_files_oem
-LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
-LOCAL_LICENSE_CONDITIONS := notice
-LOCAL_NOTICE_FILE := build/soong/licenses/LICENSE
-LOCAL_MODULE_CLASS := ETC
-LOCAL_INSTALLED_MODULE_STEM := fs_config_files
-LOCAL_MODULE_PATH := $(TARGET_OUT_OEM)/etc
-include $(BUILD_SYSTEM)/base_rules.mk
-$(LOCAL_BUILT_MODULE): PRIVATE_ANDROID_FS_HDR := $(android_filesystem_config)
-$(LOCAL_BUILT_MODULE): PRIVATE_ANDROID_CAP_HDR := $(capability_header)
-$(LOCAL_BUILT_MODULE): PRIVATE_TARGET_FS_CONFIG_GEN := $(TARGET_FS_CONFIG_GEN)
-$(LOCAL_BUILT_MODULE): $(LOCAL_PATH)/fs_config_generator.py $(TARGET_FS_CONFIG_GEN) $(android_filesystem_config) $(capability_header)
-	@mkdir -p $(dir $@)
-	$< fsconfig \
-	   --aid-header $(PRIVATE_ANDROID_FS_HDR) \
-	   --capability-header $(PRIVATE_ANDROID_CAP_HDR) \
-	   --partition oem \
-	   --files \
-	   --out_file $@ \
-	   $(or $(PRIVATE_TARGET_FS_CONFIG_GEN),/dev/null)
-
-endif
-
-ifneq ($(filter vendor_dlkm,$(fs_config_generate_extra_partition_list)),)
-##################################
-# Generate the vendor_dlkm/etc/fs_config_dirs binary file for the target
-# Add fs_config_dirs or fs_config_dirs_nonsystem to PRODUCT_PACKAGES in
-# the device make file to enable
-include $(CLEAR_VARS)
-
-LOCAL_MODULE := fs_config_dirs_vendor_dlkm
-LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
-LOCAL_LICENSE_CONDITIONS := notice
-LOCAL_NOTICE_FILE := build/soong/licenses/LICENSE
-LOCAL_MODULE_CLASS := ETC
-LOCAL_INSTALLED_MODULE_STEM := fs_config_dirs
-LOCAL_MODULE_PATH := $(TARGET_OUT_VENDOR_DLKM)/etc
-include $(BUILD_SYSTEM)/base_rules.mk
-$(LOCAL_BUILT_MODULE): PRIVATE_ANDROID_FS_HDR := $(android_filesystem_config)
-$(LOCAL_BUILT_MODULE): PRIVATE_ANDROID_CAP_HDR := $(capability_header)
-$(LOCAL_BUILT_MODULE): PRIVATE_TARGET_FS_CONFIG_GEN := $(TARGET_FS_CONFIG_GEN)
-$(LOCAL_BUILT_MODULE): $(LOCAL_PATH)/fs_config_generator.py $(TARGET_FS_CONFIG_GEN) $(android_filesystem_config) $(capability_header)
-	@mkdir -p $(dir $@)
-	$< fsconfig \
-	   --aid-header $(PRIVATE_ANDROID_FS_HDR) \
-	   --capability-header $(PRIVATE_ANDROID_CAP_HDR) \
-	   --partition vendor_dlkm \
-	   --dirs \
-	   --out_file $@ \
-	   $(or $(PRIVATE_TARGET_FS_CONFIG_GEN),/dev/null)
-
-##################################
-# Generate the vendor_dlkm/etc/fs_config_files binary file for the target
-# Add fs_config_files or fs_config_files_nonsystem to PRODUCT_PACKAGES in
-# the device make file to enable
-include $(CLEAR_VARS)
-
-LOCAL_MODULE := fs_config_files_vendor_dlkm
-LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
-LOCAL_LICENSE_CONDITIONS := notice
-LOCAL_NOTICE_FILE := build/soong/licenses/LICENSE
-LOCAL_MODULE_CLASS := ETC
-LOCAL_INSTALLED_MODULE_STEM := fs_config_files
-LOCAL_MODULE_PATH := $(TARGET_OUT_VENDOR_DLKM)/etc
-include $(BUILD_SYSTEM)/base_rules.mk
-$(LOCAL_BUILT_MODULE): PRIVATE_ANDROID_FS_HDR := $(android_filesystem_config)
-$(LOCAL_BUILT_MODULE): PRIVATE_ANDROID_CAP_HDR := $(capability_header)
-$(LOCAL_BUILT_MODULE): PRIVATE_TARGET_FS_CONFIG_GEN := $(TARGET_FS_CONFIG_GEN)
-$(LOCAL_BUILT_MODULE): $(LOCAL_PATH)/fs_config_generator.py $(TARGET_FS_CONFIG_GEN) $(android_filesystem_config) $(capability_header)
-	@mkdir -p $(dir $@)
-	$< fsconfig \
-	   --aid-header $(PRIVATE_ANDROID_FS_HDR) \
-	   --capability-header $(PRIVATE_ANDROID_CAP_HDR) \
-	   --partition vendor_dlkm \
-	   --files \
-	   --out_file $@ \
-	   $(or $(PRIVATE_TARGET_FS_CONFIG_GEN),/dev/null)
-
-endif
-
-ifneq ($(filter odm_dlkm,$(fs_config_generate_extra_partition_list)),)
-##################################
-# Generate the odm_dlkm/etc/fs_config_dirs binary file for the target
-# Add fs_config_dirs or fs_config_dirs_nonsystem to PRODUCT_PACKAGES
-# in the device make file to enable
-include $(CLEAR_VARS)
-
-LOCAL_MODULE := fs_config_dirs_odm_dlkm
-LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
-LOCAL_LICENSE_CONDITIONS := notice
-LOCAL_NOTICE_FILE := build/soong/licenses/LICENSE
-LOCAL_MODULE_CLASS := ETC
-LOCAL_INSTALLED_MODULE_STEM := fs_config_dirs
-LOCAL_MODULE_PATH := $(TARGET_OUT_ODM_DLKM)/etc
-include $(BUILD_SYSTEM)/base_rules.mk
-$(LOCAL_BUILT_MODULE): PRIVATE_ANDROID_FS_HDR := $(android_filesystem_config)
-$(LOCAL_BUILT_MODULE): PRIVATE_ANDROID_CAP_HDR := $(capability_header)
-$(LOCAL_BUILT_MODULE): PRIVATE_TARGET_FS_CONFIG_GEN := $(TARGET_FS_CONFIG_GEN)
-$(LOCAL_BUILT_MODULE): $(LOCAL_PATH)/fs_config_generator.py $(TARGET_FS_CONFIG_GEN) $(android_filesystem_config) $(capability_header)
-	@mkdir -p $(dir $@)
-	$< fsconfig \
-	   --aid-header $(PRIVATE_ANDROID_FS_HDR) \
-	   --capability-header $(PRIVATE_ANDROID_CAP_HDR) \
-	   --partition odm_dlkm \
-	   --dirs \
-	   --out_file $@ \
-	   $(or $(PRIVATE_TARGET_FS_CONFIG_GEN),/dev/null)
-
-##################################
-# Generate the odm_dlkm/etc/fs_config_files binary file for the target
-# Add fs_config_files or fs_config_files_nonsystem to PRODUCT_PACKAGES
-# in the device make file to enable
-include $(CLEAR_VARS)
-
-LOCAL_MODULE := fs_config_files_odm_dlkm
-LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
-LOCAL_LICENSE_CONDITIONS := notice
-LOCAL_NOTICE_FILE := build/soong/licenses/LICENSE
-LOCAL_MODULE_CLASS := ETC
-LOCAL_INSTALLED_MODULE_STEM := fs_config_files
-LOCAL_MODULE_PATH := $(TARGET_OUT_ODM_DLKM)/etc
-include $(BUILD_SYSTEM)/base_rules.mk
-$(LOCAL_BUILT_MODULE): PRIVATE_ANDROID_FS_HDR := $(android_filesystem_config)
-$(LOCAL_BUILT_MODULE): PRIVATE_ANDROID_CAP_HDR := $(capability_header)
-$(LOCAL_BUILT_MODULE): PRIVATE_TARGET_FS_CONFIG_GEN := $(TARGET_FS_CONFIG_GEN)
-$(LOCAL_BUILT_MODULE): $(LOCAL_PATH)/fs_config_generator.py $(TARGET_FS_CONFIG_GEN) $(android_filesystem_config) $(capability_header)
-	@mkdir -p $(dir $@)
-	$< fsconfig \
-	   --aid-header $(PRIVATE_ANDROID_FS_HDR) \
-	   --capability-header $(PRIVATE_ANDROID_CAP_HDR) \
-	   --partition odm_dlkm \
-	   --files \
-	   --out_file $@ \
-	   $(or $(PRIVATE_TARGET_FS_CONFIG_GEN),/dev/null)
-
-endif
-
-ifneq ($(filter system_dlkm,$(fs_config_generate_extra_partition_list)),)
-##################################
-# Generate the system_dlkm/etc/fs_config_dirs binary file for the target
-# Add fs_config_dirs or fs_config_dirs_nonsystem to PRODUCT_PACKAGES
-# in the device make file to enable
-include $(CLEAR_VARS)
-
-LOCAL_MODULE := fs_config_dirs_system_dlkm
-LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
-LOCAL_LICENSE_CONDITIONS := notice
-LOCAL_NOTICE_FILE := build/soong/licenses/LICENSE
-LOCAL_MODULE_CLASS := ETC
-LOCAL_INSTALLED_MODULE_STEM := fs_config_dirs
-LOCAL_MODULE_PATH := $(TARGET_OUT_SYSTEM_DLKM)/etc
-include $(BUILD_SYSTEM)/base_rules.mk
-$(LOCAL_BUILT_MODULE): PRIVATE_ANDROID_FS_HDR := $(android_filesystem_config)
-$(LOCAL_BUILT_MODULE): PRIVATE_ANDROID_CAP_HDR := $(capability_header)
-$(LOCAL_BUILT_MODULE): PRIVATE_TARGET_FS_CONFIG_GEN := $(TARGET_FS_CONFIG_GEN)
-$(LOCAL_BUILT_MODULE): $(LOCAL_PATH)/fs_config_generator.py $(TARGET_FS_CONFIG_GEN) $(android_filesystem_config) $(capability_header)
-	@mkdir -p $(dir $@)
-	$< fsconfig \
-	   --aid-header $(PRIVATE_ANDROID_FS_HDR) \
-	   --capability-header $(PRIVATE_ANDROID_CAP_HDR) \
-	   --partition system_dlkm \
-	   --dirs \
-	   --out_file $@ \
-	   $(or $(PRIVATE_TARGET_FS_CONFIG_GEN),/dev/null)
-
-##################################
-# Generate the system_dlkm/etc/fs_config_files binary file for the target
-# Add fs_config_files or fs_config_files_nonsystem to PRODUCT_PACKAGES
-# in the device make file to enable
-include $(CLEAR_VARS)
-
-LOCAL_MODULE := fs_config_files_system_dlkm
-LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
-LOCAL_LICENSE_CONDITIONS := notice
-LOCAL_NOTICE_FILE := build/soong/licenses/LICENSE
-LOCAL_MODULE_CLASS := ETC
-LOCAL_INSTALLED_MODULE_STEM := fs_config_files
-LOCAL_MODULE_PATH := $(TARGET_OUT_SYSTEM_DLKM)/etc
-include $(BUILD_SYSTEM)/base_rules.mk
-$(LOCAL_BUILT_MODULE): PRIVATE_ANDROID_FS_HDR := $(android_filesystem_config)
-$(LOCAL_BUILT_MODULE): PRIVATE_ANDROID_CAP_HDR := $(capability_header)
-$(LOCAL_BUILT_MODULE): PRIVATE_TARGET_FS_CONFIG_GEN := $(TARGET_FS_CONFIG_GEN)
-$(LOCAL_BUILT_MODULE): $(LOCAL_PATH)/fs_config_generator.py $(TARGET_FS_CONFIG_GEN) $(android_filesystem_config) $(capability_header)
-	@mkdir -p $(dir $@)
-	$< fsconfig \
-	   --aid-header $(PRIVATE_ANDROID_FS_HDR) \
-	   --capability-header $(PRIVATE_ANDROID_CAP_HDR) \
-	   --partition system_dlkm \
-	   --files \
-	   --out_file $@ \
-	   $(or $(PRIVATE_TARGET_FS_CONFIG_GEN),/dev/null)
-
-endif
-
-android_filesystem_config :=
-capability_header :=
-fs_config_generate_extra_partition_list :=
diff --git a/tools/ide_query/ide_query.go b/tools/ide_query/ide_query.go
index 23c7abd2a0..c7cf5ed49a 100644
--- a/tools/ide_query/ide_query.go
+++ b/tools/ide_query/ide_query.go
@@ -293,11 +293,19 @@ func getCCInputs(ctx context.Context, env Env, filePaths []string) ([]*pb.Analys
 // If a file is covered by multiple modules, the first module is returned.
 func findJavaModules(paths []string, modules map[string]*javaModule) map[string]string {
 	ret := make(map[string]string)
-	for name, module := range modules {
+	// A file may be part of multiple modules. To make the result deterministic,
+	// check the modules in sorted order.
+	keys := make([]string, 0, len(modules))
+	for name := range modules {
+		keys = append(keys, name)
+	}
+	slices.Sort(keys)
+	for _, name := range keys {
 		if strings.HasSuffix(name, ".impl") {
 			continue
 		}
 
+		module := modules[name]
 		for i, p := range paths {
 			if slices.Contains(module.Srcs, p) {
 				ret[p] = name
@@ -341,6 +349,8 @@ func getJavaInputs(env Env, modulesByPath map[string]string, modules map[string]
 			Id:              moduleName,
 			Language:        pb.Language_LANGUAGE_JAVA,
 			SourceFilePaths: m.Srcs,
+			GeneratedFiles:  genFiles(env, m),
+			DependencyIds:   m.Deps,
 		}
 		unitsById[u.Id] = u
 
@@ -355,14 +365,11 @@ func getJavaInputs(env Env, modulesByPath map[string]string, modules map[string]
 				continue
 			}
 
-			var paths []string
-			paths = append(paths, mod.Srcs...)
-			paths = append(paths, mod.SrcJars...)
-			paths = append(paths, mod.Jars...)
 			unitsById[name] = &pb.BuildableUnit{
 				Id:              name,
 				SourceFilePaths: mod.Srcs,
-				GeneratedFiles:  genFiles(env, paths),
+				GeneratedFiles:  genFiles(env, mod),
+				DependencyIds:   mod.Deps,
 			}
 
 			for _, d := range mod.Deps {
@@ -379,8 +386,13 @@ func getJavaInputs(env Env, modulesByPath map[string]string, modules map[string]
 }
 
 // genFiles returns the generated files (paths that start with outDir/) for the
-// given paths. Generated files that do not exist are ignored.
-func genFiles(env Env, paths []string) []*pb.GeneratedFile {
+// given module. Generated files that do not exist are ignored.
+func genFiles(env Env, mod *javaModule) []*pb.GeneratedFile {
+	var paths []string
+	paths = append(paths, mod.Srcs...)
+	paths = append(paths, mod.SrcJars...)
+	paths = append(paths, mod.Jars...)
+
 	prefix := env.OutDir + "/"
 	var ret []*pb.GeneratedFile
 	for _, p := range paths {
diff --git a/tools/ide_query/ide_query.sh b/tools/ide_query/ide_query.sh
index 6f9b0c4b8b..8dfffc1cfa 100755
--- a/tools/ide_query/ide_query.sh
+++ b/tools/ide_query/ide_query.sh
@@ -19,7 +19,7 @@ source $(pwd)/../../shell_utils.sh
 require_top
 
 # Ensure cogsetup (out/ will be symlink outside the repo)
-. ${TOP}/build/make/cogsetup.sh
+setup_cog_env_if_needed
 
 case $(uname -s) in
     Linux)
diff --git a/tools/ide_query/prober_scripts/ide_query.out b/tools/ide_query/prober_scripts/ide_query.out
index cd7ce6d258..be48da1424 100644
--- a/tools/ide_query/prober_scripts/ide_query.out
+++ b/tools/ide_query/prober_scripts/ide_query.out
@@ -1,7 +1,9 @@
 
-out–a
-8build/make/tools/ide_query/prober_scripts/cpp/general.cc8prebuilts/clang/host/linux-x86/clang-r522817/bin/clang++-mthumb-Os-fomit-frame-pointer-mllvm-enable-shrink-wrap=false-O2-Wall-Wextra-Winit-self-Wpointer-arith-Wunguarded-availability-Werror=date-time-Werror=int-conversion-Werror=pragma-pack&-Werror=pragma-pack-suspicious-include-Werror=sizeof-array-div-Werror=string-plus-int'-Werror=unreachable-code-loop-increment"-Wno-error=deprecated-declarations-Wno-c99-designator-Wno-gnu-folding-constant"-Wno-inconsistent-missing-override-Wno-error=reorder-init-list-Wno-reorder-init-list-Wno-sign-compare-Wno-unused	-DANDROID-DNDEBUG-UDEBUG(-D__compiler_offsetof=__builtin_offsetof*-D__ANDROID_UNAVAILABLE_SYMBOLS_ARE_WEAK__	-faddrsig-fdebug-default-version=5-fcolor-diagnostics-ffp-contract=off-fno-exceptions-fno-strict-aliasing-fmessage-length=0#-fno-relaxed-template-template-args-gsimple-template-names-gz=zstd-no-canonical-prefixes-Wno-error=format"-fdebug-prefix-map=/proc/self/cwd=-ftrivial-auto-var-init=zero-g-ffunction-sections-fdata-sections-fno-short-enums-funwind-tables-fstack-protector-strong-Wa,--noexecstack-D_FORTIFY_SOURCE=2-Wstrict-aliasing=2-Werror=return-type-Werror=non-virtual-dtor-Werror=address-Werror=sequence-point-Werror=format-security-nostdlibinc-fdebug-info-for-profiling-msoft-float-march=armv7-a-mfloat-abi=softfp
--mfpu=neon/-Ibuild/make/tools/ide_query/prober_scripts/cpp³-Iout/soong/.intermediates/build/make/tools/ide_query/prober_scripts/cpp/ide_query_proberscript_cc/android_arm_armv7-a-neon/gen/proto/build/make/tools/ide_query/prober_scripts/cpp…-Iout/soong/.intermediates/build/make/tools/ide_query/prober_scripts/cpp/ide_query_proberscript_cc/android_arm_armv7-a-neon/gen/proto-D__LIBC_API__=10000-D__LIBM_API__=10000-D__LIBDL_API__=10000-Iexternal/protobuf/srcY-Iprebuilts/clang/host/linux-x86/clang-r522817/android_libc++/platform/arm/include/c++/v1=-Iprebuilts/clang/host/linux-x86/clang-r522817/include/c++/v1 -Ibionic/libc/async_safe/include-Isystem/logging/liblog/include'-Ibionic/libc/system_properties/include<-Isystem/core/property_service/libpropertyinfoparser/include-isystembionic/libc/include-isystembionic/libc/kernel/uapi/asm-arm-isystembionic/libc/kernel/uapi-isystembionic/libc/kernel/android/scsi-isystembionic/libc/kernel/android/uapi-targetarmv7a-linux-androideabi10000-DANDROID_STRICT-fPIE-Werror-Wno-unused-parameter-DGOOGLE_PROTOBUF_NO_RTTI-Wimplicit-fallthrough*-D_LIBCPP_ENABLE_THREAD_SAFETY_ANNOTATIONS-Wno-gnu-include-next-fvisibility-inlines-hidden-mllvm-enable-shrink-wrap=false-std=gnu++20	-fno-rtti-Isystem/core/include-Isystem/logging/liblog/include-Isystem/media/audio/include-Ihardware/libhardware/include%-Ihardware/libhardware_legacy/include-Ihardware/ril/include-Iframeworks/native/include"-Iframeworks/native/opengl/include-Iframeworks/av/include-Werror=bool-operation -Werror=format-insufficient-args%-Werror=implicit-int-float-conversion-Werror=int-in-bool-context-Werror=int-to-pointer-cast-Werror=pointer-to-int-cast-Werror=xor-used-as-pow-Wno-void-pointer-to-enum-cast-Wno-void-pointer-to-int-cast-Wno-pointer-to-int-cast-Werror=fortify-source-Wno-unused-variable-Wno-missing-field-initializers-Wno-packed-non-pod-Werror=address-of-temporary+-Werror=incompatible-function-pointer-types-Werror=null-dereference-Werror=return-type"-Wno-tautological-constant-compare$-Wno-tautological-type-limit-compare"-Wno-implicit-int-float-conversion!-Wno-tautological-overlap-compare-Wno-deprecated-copy-Wno-range-loop-construct"-Wno-zero-as-null-pointer-constant)-Wno-deprecated-anon-enum-enum-conversion$-Wno-deprecated-enum-enum-conversion-Wno-pessimizing-move-Wno-non-c-typedef-for-linkage-Wno-align-mismatch"-Wno-error=unused-but-set-variable#-Wno-error=unused-but-set-parameter-Wno-error=deprecated-builtins-Wno-error=deprecated2-Wno-error=single-bit-bitfield-constant-conversion$-Wno-error=enum-constexpr-conversion-Wno-error=invalid-offsetof&-Wno-deprecated-dynamic-exception-spec8build/make/tools/ide_query/prober_scripts/cpp/general.cc"Õ?
+out2x
+8build/make/tools/ide_query/prober_scripts/cpp/general.cc8build/make/tools/ide_query/prober_scripts/cpp/general.cc:—"
+8build/make/tools/ide_query/prober_scripts/cpp/general.cc8build/make/tools/ide_query/prober_scripts/cpp/general.cc"8prebuilts/clang/host/linux-x86/clang-r530567/bin/clang++"-nostdlibinc"-mthumb"-Os"-fomit-frame-pointer"-mllvm"-enable-shrink-wrap=false"-O2"-Wall"-Wextra"-Winit-self"-Wpointer-arith"-Wunguarded-availability"-Werror=date-time"-Werror=int-conversion"-Werror=pragma-pack"&-Werror=pragma-pack-suspicious-include"-Werror=sizeof-array-div"-Werror=string-plus-int"'-Werror=unreachable-code-loop-increment""-Wno-error=deprecated-declarations"-Wno-c23-extensions"-Wno-c99-designator"-Wno-gnu-folding-constant""-Wno-inconsistent-missing-override"-Wno-error=reorder-init-list"-Wno-reorder-init-list"-Wno-sign-compare"-Wno-unused"	-DANDROID"-DNDEBUG"-UDEBUG"(-D__compiler_offsetof=__builtin_offsetof"*-D__ANDROID_UNAVAILABLE_SYMBOLS_ARE_WEAK__"	-faddrsig"-fdebug-default-version=5"-fcolor-diagnostics"-ffp-contract=off"-fno-exceptions"-fno-strict-aliasing"-fmessage-length=0"-gsimple-template-names"-gz=zstd"-no-canonical-prefixes""-fdebug-prefix-map=/proc/self/cwd="-ftrivial-auto-var-init=zero"-g"-ffunction-sections"-fdata-sections"-fno-short-enums"-funwind-tables"-fstack-protector-strong"-Wa,--noexecstack"-D_FORTIFY_SOURCE=2"-Wstrict-aliasing=2"-Werror=return-type"-Werror=non-virtual-dtor"-Werror=address"-Werror=sequence-point"-Werror=format-security"-msoft-float"-march=armv7-a"-mfloat-abi=softfp"
+-mfpu=neon"/-Ibuild/make/tools/ide_query/prober_scripts/cpp"³-Iout/soong/.intermediates/build/make/tools/ide_query/prober_scripts/cpp/ide_query_proberscript_cc/android_arm_armv7-a-neon/gen/proto/build/make/tools/ide_query/prober_scripts/cpp"…-Iout/soong/.intermediates/build/make/tools/ide_query/prober_scripts/cpp/ide_query_proberscript_cc/android_arm_armv7-a-neon/gen/proto"-D__LIBC_API__=10000"-D__LIBM_API__=10000"-D__LIBDL_API__=10000"-Iexternal/protobuf/src"Y-Iprebuilts/clang/host/linux-x86/clang-r530567/android_libc++/platform/arm/include/c++/v1"=-Iprebuilts/clang/host/linux-x86/clang-r530567/include/c++/v1" -Ibionic/libc/async_safe/include"-Isystem/logging/liblog/include"'-Ibionic/libc/system_properties/include"<-Isystem/core/property_service/libpropertyinfoparser/include"-isystem"bionic/libc/include"-isystem"bionic/libc/kernel/uapi/asm-arm"-isystem"bionic/libc/kernel/uapi"-isystem"bionic/libc/kernel/android/scsi"-isystem"bionic/libc/kernel/android/uapi"-target"armv7a-linux-androideabi10000"-DANDROID_STRICT"-fPIE"-Werror"-Wno-unused-parameter"-DGOOGLE_PROTOBUF_NO_RTTI"-Wimplicit-fallthrough"*-D_LIBCPP_ENABLE_THREAD_SAFETY_ANNOTATIONS"-Wno-gnu-include-next"-fvisibility-inlines-hidden"-mllvm"-enable-shrink-wrap=false"-std=gnu++20"	-fno-rtti"-Isystem/core/include"-Isystem/logging/liblog/include"-Isystem/media/audio/include"-Ihardware/libhardware/include"%-Ihardware/libhardware_legacy/include"-Ihardware/ril/include"-Iframeworks/native/include""-Iframeworks/native/opengl/include"-Iframeworks/av/include"-Werror=bool-operation" -Werror=format-insufficient-args"%-Werror=implicit-int-float-conversion"-Werror=int-in-bool-context"-Werror=int-to-pointer-cast"-Werror=pointer-to-int-cast"-Werror=xor-used-as-pow"-Wno-void-pointer-to-enum-cast"-Wno-void-pointer-to-int-cast"-Wno-pointer-to-int-cast"-Werror=fortify-source"-Wno-unused-variable"-Wno-missing-field-initializers"-Wno-packed-non-pod"-Werror=address-of-temporary"+-Werror=incompatible-function-pointer-types"-Werror=null-dereference"-Werror=return-type""-Wno-tautological-constant-compare"$-Wno-tautological-type-limit-compare""-Wno-implicit-int-float-conversion"!-Wno-tautological-overlap-compare"-Wno-deprecated-copy"-Wno-range-loop-construct""-Wno-zero-as-null-pointer-constant")-Wno-deprecated-anon-enum-enum-conversion"$-Wno-deprecated-enum-enum-conversion"-Wno-error=pessimizing-move"-Wno-non-c-typedef-for-linkage"-Wno-align-mismatch""-Wno-error=unused-but-set-variable"#-Wno-error=unused-but-set-parameter"-Wno-error=deprecated-builtins"-Wno-error=deprecated"&-Wno-deprecated-dynamic-exception-spec"$-Wno-error=enum-constexpr-conversion"-Wno-error=invalid-offsetof")-Wno-error=thread-safety-reference-return"-Wno-vla-cxx-extension"8build/make/tools/ide_query/prober_scripts/cpp/general.cc2Egenfiles_for_build/make/tools/ide_query/prober_scripts/cpp/general.cc:Ÿ@
+Egenfiles_for_build/make/tools/ide_query/prober_scripts/cpp/general.cc*Õ?
 ¶soong/.intermediates/build/make/tools/ide_query/prober_scripts/cpp/ide_query_proberscript_cc/android_arm_armv7-a-neon/gen/proto/build/make/tools/ide_query/prober_scripts/cpp/foo.pb.h™>// Generated by the protocol buffer compiler.  DO NOT EDIT!
 // source: build/make/tools/ide_query/prober_scripts/cpp/foo.proto
 
diff --git a/tools/ide_query/prober_scripts/regen.sh b/tools/ide_query/prober_scripts/regen.sh
index 2edfe53ec3..04a02640d7 100755
--- a/tools/ide_query/prober_scripts/regen.sh
+++ b/tools/ide_query/prober_scripts/regen.sh
@@ -21,13 +21,8 @@
 # ide_query.sh. The prober doesn't check-out the full source code, so it
 # can't run ide_query.sh itself.
 
-cd $(dirname $BASH_SOURCE)
-source $(pwd)/../../../shell_utils.sh
-require_top
-
 files_to_build=(
   build/make/tools/ide_query/prober_scripts/cpp/general.cc
 )
 
-cd ${TOP}
 build/make/tools/ide_query/ide_query.sh --lunch_target=aosp_arm-trunk_staging-eng ${files_to_build[@]} > build/make/tools/ide_query/prober_scripts/ide_query.out
diff --git a/tools/metadata/Android.bp b/tools/metadata/Android.bp
deleted file mode 100644
index 77d106d705..0000000000
--- a/tools/metadata/Android.bp
+++ /dev/null
@@ -1,16 +0,0 @@
-package {
-    default_applicable_licenses: ["Android-Apache-2.0"],
-}
-
-blueprint_go_binary {
-    name: "metadata",
-    deps: [
-            "soong-testing-test_spec_proto",
-            "soong-testing-code_metadata_proto",
-            "soong-testing-code_metadata_internal_proto",
-            "golang-protobuf-proto",
-        ],
-    srcs: [
-        "generator.go",
-    ]
-}
\ No newline at end of file
diff --git a/tools/metadata/OWNERS b/tools/metadata/OWNERS
deleted file mode 100644
index 03bcdf1c40..0000000000
--- a/tools/metadata/OWNERS
+++ /dev/null
@@ -1,4 +0,0 @@
-dariofreni@google.com
-joeo@google.com
-ronish@google.com
-caditya@google.com
diff --git a/tools/metadata/generator.go b/tools/metadata/generator.go
deleted file mode 100644
index b7668be44f..0000000000
--- a/tools/metadata/generator.go
+++ /dev/null
@@ -1,328 +0,0 @@
-package main
-
-import (
-	"flag"
-	"fmt"
-	"io"
-	"log"
-	"os"
-	"sort"
-	"strings"
-	"sync"
-
-	"android/soong/testing/code_metadata_internal_proto"
-	"android/soong/testing/code_metadata_proto"
-	"android/soong/testing/test_spec_proto"
-	"google.golang.org/protobuf/proto"
-)
-
-type keyToLocksMap struct {
-	locks sync.Map
-}
-
-func (kl *keyToLocksMap) GetLockForKey(key string) *sync.Mutex {
-	mutex, _ := kl.locks.LoadOrStore(key, &sync.Mutex{})
-	return mutex.(*sync.Mutex)
-}
-
-// Define a struct to hold the combination of team ID and multi-ownership flag for validation
-type sourceFileAttributes struct {
-	TeamID         string
-	MultiOwnership bool
-	Path           string
-}
-
-func getSortedKeys(syncMap *sync.Map) []string {
-	var allKeys []string
-	syncMap.Range(
-		func(key, _ interface{}) bool {
-			allKeys = append(allKeys, key.(string))
-			return true
-		},
-	)
-
-	sort.Strings(allKeys)
-	return allKeys
-}
-
-// writeProtoToFile marshals a protobuf message and writes it to a file
-func writeProtoToFile(outputFile string, message proto.Message) {
-	data, err := proto.Marshal(message)
-	if err != nil {
-		log.Fatal(err)
-	}
-	file, err := os.Create(outputFile)
-	if err != nil {
-		log.Fatal(err)
-	}
-	defer file.Close()
-
-	_, err = file.Write(data)
-	if err != nil {
-		log.Fatal(err)
-	}
-}
-
-func readFileToString(filePath string) string {
-	file, err := os.Open(filePath)
-	if err != nil {
-		log.Fatal(err)
-	}
-	defer file.Close()
-
-	data, err := io.ReadAll(file)
-	if err != nil {
-		log.Fatal(err)
-	}
-	return string(data)
-}
-
-func writeEmptyOutputProto(outputFile string, metadataRule string) {
-	file, err := os.Create(outputFile)
-	if err != nil {
-		log.Fatal(err)
-	}
-	var message proto.Message
-	if metadataRule == "test_spec" {
-		message = &test_spec_proto.TestSpec{}
-	} else if metadataRule == "code_metadata" {
-		message = &code_metadata_proto.CodeMetadata{}
-	}
-	data, err := proto.Marshal(message)
-	if err != nil {
-		log.Fatal(err)
-	}
-	defer file.Close()
-
-	_, err = file.Write([]byte(data))
-	if err != nil {
-		log.Fatal(err)
-	}
-}
-
-func processTestSpecProtobuf(
-	filePath string, ownershipMetadataMap *sync.Map, keyLocks *keyToLocksMap,
-	errCh chan error, wg *sync.WaitGroup,
-) {
-	defer wg.Done()
-
-	fileContent := strings.TrimRight(readFileToString(filePath), "\n")
-	testData := test_spec_proto.TestSpec{}
-	err := proto.Unmarshal([]byte(fileContent), &testData)
-	if err != nil {
-		errCh <- err
-		return
-	}
-
-	ownershipMetadata := testData.GetOwnershipMetadataList()
-	for _, metadata := range ownershipMetadata {
-		key := metadata.GetTargetName()
-		lock := keyLocks.GetLockForKey(key)
-		lock.Lock()
-
-		value, loaded := ownershipMetadataMap.LoadOrStore(
-			key, []*test_spec_proto.TestSpec_OwnershipMetadata{metadata},
-		)
-		if loaded {
-			existingMetadata := value.([]*test_spec_proto.TestSpec_OwnershipMetadata)
-			isDuplicate := false
-			for _, existing := range existingMetadata {
-				if metadata.GetTrendyTeamId() != existing.GetTrendyTeamId() {
-					errCh <- fmt.Errorf(
-						"Conflicting trendy team IDs found for %s at:\n%s with teamId"+
-							": %s,\n%s with teamId: %s",
-						key,
-						metadata.GetPath(), metadata.GetTrendyTeamId(), existing.GetPath(),
-						existing.GetTrendyTeamId(),
-					)
-
-					lock.Unlock()
-					return
-				}
-				if metadata.GetTrendyTeamId() == existing.GetTrendyTeamId() && metadata.GetPath() == existing.GetPath() {
-					isDuplicate = true
-					break
-				}
-			}
-			if !isDuplicate {
-				existingMetadata = append(existingMetadata, metadata)
-				ownershipMetadataMap.Store(key, existingMetadata)
-			}
-		}
-
-		lock.Unlock()
-	}
-}
-
-// processCodeMetadataProtobuf processes CodeMetadata protobuf files
-func processCodeMetadataProtobuf(
-	filePath string, ownershipMetadataMap *sync.Map, sourceFileMetadataMap *sync.Map, keyLocks *keyToLocksMap,
-	errCh chan error, wg *sync.WaitGroup,
-) {
-	defer wg.Done()
-
-	fileContent := strings.TrimRight(readFileToString(filePath), "\n")
-	internalCodeData := code_metadata_internal_proto.CodeMetadataInternal{}
-	err := proto.Unmarshal([]byte(fileContent), &internalCodeData)
-	if err != nil {
-		errCh <- err
-		return
-	}
-
-	// Process each TargetOwnership entry
-	for _, internalMetadata := range internalCodeData.GetTargetOwnershipList() {
-		key := internalMetadata.GetTargetName()
-		lock := keyLocks.GetLockForKey(key)
-		lock.Lock()
-
-		for _, srcFile := range internalMetadata.GetSourceFiles() {
-			srcFileKey := srcFile
-			srcFileLock := keyLocks.GetLockForKey(srcFileKey)
-			srcFileLock.Lock()
-			attributes := sourceFileAttributes{
-				TeamID:         internalMetadata.GetTrendyTeamId(),
-				MultiOwnership: internalMetadata.GetMultiOwnership(),
-				Path:           internalMetadata.GetPath(),
-			}
-
-			existingAttributes, exists := sourceFileMetadataMap.Load(srcFileKey)
-			if exists {
-				existing := existingAttributes.(sourceFileAttributes)
-				if attributes.TeamID != existing.TeamID && (!attributes.MultiOwnership || !existing.MultiOwnership) {
-					errCh <- fmt.Errorf(
-						"Conflict found for source file %s covered at %s with team ID: %s. Existing team ID: %s and path: %s."+
-							" If multi-ownership is required, multiOwnership should be set to true in all test_spec modules using this target. "+
-							"Multiple-ownership in general is discouraged though as it make infrastructure around android relying on this information pick up a random value when it needs only one.",
-						srcFile, internalMetadata.GetPath(), attributes.TeamID, existing.TeamID, existing.Path,
-					)
-					srcFileLock.Unlock()
-					lock.Unlock()
-					return
-				}
-			} else {
-				// Store the metadata if no conflict
-				sourceFileMetadataMap.Store(srcFileKey, attributes)
-			}
-			srcFileLock.Unlock()
-		}
-
-		value, loaded := ownershipMetadataMap.LoadOrStore(
-			key, []*code_metadata_internal_proto.CodeMetadataInternal_TargetOwnership{internalMetadata},
-		)
-		if loaded {
-			existingMetadata := value.([]*code_metadata_internal_proto.CodeMetadataInternal_TargetOwnership)
-			isDuplicate := false
-			for _, existing := range existingMetadata {
-				if internalMetadata.GetTrendyTeamId() == existing.GetTrendyTeamId() && internalMetadata.GetPath() == existing.GetPath() {
-					isDuplicate = true
-					break
-				}
-			}
-			if !isDuplicate {
-				existingMetadata = append(existingMetadata, internalMetadata)
-				ownershipMetadataMap.Store(key, existingMetadata)
-			}
-		}
-
-		lock.Unlock()
-	}
-}
-
-func main() {
-	inputFile := flag.String("inputFile", "", "Input file path")
-	outputFile := flag.String("outputFile", "", "Output file path")
-	rule := flag.String(
-		"rule", "", "Metadata rule (Hint: test_spec or code_metadata)",
-	)
-	flag.Parse()
-
-	if *inputFile == "" || *outputFile == "" || *rule == "" {
-		fmt.Println("Usage: metadata -rule <rule> -inputFile <input file path> -outputFile <output file path>")
-		os.Exit(1)
-	}
-
-	inputFileData := strings.TrimRight(readFileToString(*inputFile), "\n")
-	filePaths := strings.Split(inputFileData, " ")
-	if len(filePaths) == 1 && filePaths[0] == "" {
-		writeEmptyOutputProto(*outputFile, *rule)
-		return
-	}
-	ownershipMetadataMap := &sync.Map{}
-	keyLocks := &keyToLocksMap{}
-	errCh := make(chan error, len(filePaths))
-	var wg sync.WaitGroup
-
-	switch *rule {
-	case "test_spec":
-		for _, filePath := range filePaths {
-			wg.Add(1)
-			go processTestSpecProtobuf(
-				filePath, ownershipMetadataMap, keyLocks, errCh, &wg,
-			)
-		}
-
-		wg.Wait()
-		close(errCh)
-
-		for err := range errCh {
-			log.Fatal(err)
-		}
-
-		allKeys := getSortedKeys(ownershipMetadataMap)
-		var allMetadata []*test_spec_proto.TestSpec_OwnershipMetadata
-
-		for _, key := range allKeys {
-			value, _ := ownershipMetadataMap.Load(key)
-			metadataList := value.([]*test_spec_proto.TestSpec_OwnershipMetadata)
-			allMetadata = append(allMetadata, metadataList...)
-		}
-
-		testSpec := &test_spec_proto.TestSpec{
-			OwnershipMetadataList: allMetadata,
-		}
-		writeProtoToFile(*outputFile, testSpec)
-		break
-	case "code_metadata":
-		sourceFileMetadataMap := &sync.Map{}
-		for _, filePath := range filePaths {
-			wg.Add(1)
-			go processCodeMetadataProtobuf(
-				filePath, ownershipMetadataMap, sourceFileMetadataMap, keyLocks, errCh, &wg,
-			)
-		}
-
-		wg.Wait()
-		close(errCh)
-
-		for err := range errCh {
-			log.Fatal(err)
-		}
-
-		sortedKeys := getSortedKeys(ownershipMetadataMap)
-		allMetadata := make([]*code_metadata_proto.CodeMetadata_TargetOwnership, 0)
-		for _, key := range sortedKeys {
-			value, _ := ownershipMetadataMap.Load(key)
-			metadata := value.([]*code_metadata_internal_proto.CodeMetadataInternal_TargetOwnership)
-			for _, m := range metadata {
-				targetName := m.GetTargetName()
-				path := m.GetPath()
-				trendyTeamId := m.GetTrendyTeamId()
-
-				allMetadata = append(allMetadata, &code_metadata_proto.CodeMetadata_TargetOwnership{
-					TargetName:   &targetName,
-					Path:         &path,
-					TrendyTeamId: &trendyTeamId,
-					SourceFiles:  m.GetSourceFiles(),
-				})
-			}
-		}
-
-		finalMetadata := &code_metadata_proto.CodeMetadata{
-			TargetOwnershipList: allMetadata,
-		}
-		writeProtoToFile(*outputFile, finalMetadata)
-		break
-	default:
-		log.Fatalf("No specific processing implemented for rule '%s'.\n", *rule)
-	}
-}
diff --git a/tools/metadata/go.mod b/tools/metadata/go.mod
deleted file mode 100644
index e9d04b16f6..0000000000
--- a/tools/metadata/go.mod
+++ /dev/null
@@ -1,7 +0,0 @@
-module android/soong/tools/metadata
-
-require google.golang.org/protobuf v0.0.0
-
-replace google.golang.org/protobuf v0.0.0 => ../../../external/golang-protobuf
-
-go 1.18
\ No newline at end of file
diff --git a/tools/metadata/go.work b/tools/metadata/go.work
deleted file mode 100644
index f2cdf8ec98..0000000000
--- a/tools/metadata/go.work
+++ /dev/null
@@ -1,11 +0,0 @@
-go 1.18
-
-use (
-	.
-	../../../../external/golang-protobuf
-	../../../soong/testing/test_spec_proto
-	../../../soong/testing/code_metadata_proto
-	../../../soong/testing/code_metadata_proto_internal
-)
-
-replace google.golang.org/protobuf v0.0.0 => ../../../../external/golang-protobuf
diff --git a/tools/metadata/testdata/emptyInputFile.txt b/tools/metadata/testdata/emptyInputFile.txt
deleted file mode 100644
index 8b13789179..0000000000
--- a/tools/metadata/testdata/emptyInputFile.txt
+++ /dev/null
@@ -1 +0,0 @@
-
diff --git a/tools/metadata/testdata/expectedCodeMetadataOutput.txt b/tools/metadata/testdata/expectedCodeMetadataOutput.txt
deleted file mode 100644
index 755cf40a30..0000000000
--- a/tools/metadata/testdata/expectedCodeMetadataOutput.txt
+++ /dev/null
@@ -1,7 +0,0 @@
-
- 
-bar
-Android.bp12346"b.java
- 
-foo
-Android.bp12345"a.java
\ No newline at end of file
diff --git a/tools/metadata/testdata/expectedOutputFile.txt b/tools/metadata/testdata/expectedOutputFile.txt
deleted file mode 100644
index b0d382f279..0000000000
--- a/tools/metadata/testdata/expectedOutputFile.txt
+++ /dev/null
@@ -1,22 +0,0 @@
-
-.
-java-test-module-name-one
-Android.bp12345
-.
-java-test-module-name-six
-Android.bp12346
-.
-java-test-module-name-six
-Aqwerty.bp12346
-.
-java-test-module-name-six
-Apoiuyt.bp12346
-.
-java-test-module-name-two
-Android.bp12345
-.
-java-test-module-name-two
-Asdfghj.bp12345
-.
-java-test-module-name-two
-Azxcvbn.bp12345
\ No newline at end of file
diff --git a/tools/metadata/testdata/file1.txt b/tools/metadata/testdata/file1.txt
deleted file mode 100644
index 81beed00ab..0000000000
--- a/tools/metadata/testdata/file1.txt
+++ /dev/null
@@ -1,13 +0,0 @@
-
-.
-java-test-module-name-one
-Android.bp12345
-.
-java-test-module-name-two
-Android.bp12345
-.
-java-test-module-name-two
-Asdfghj.bp12345
-.
-java-test-module-name-two
-Azxcvbn.bp12345
diff --git a/tools/metadata/testdata/file2.txt b/tools/metadata/testdata/file2.txt
deleted file mode 100644
index 32a753fef5..0000000000
--- a/tools/metadata/testdata/file2.txt
+++ /dev/null
@@ -1,25 +0,0 @@
-
-.
-java-test-module-name-one
-Android.bp12345
-.
-java-test-module-name-six
-Android.bp12346
-.
-java-test-module-name-one
-Android.bp12345
-.
-java-test-module-name-six
-Aqwerty.bp12346
-.
-java-test-module-name-six
-Apoiuyt.bp12346
-.
-java-test-module-name-six
-Apoiuyt.bp12346
-.
-java-test-module-name-six
-Apoiuyt.bp12346
-.
-java-test-module-name-six
-Apoiuyt.bp12346
diff --git a/tools/metadata/testdata/file3.txt b/tools/metadata/testdata/file3.txt
deleted file mode 100644
index 81beed00ab..0000000000
--- a/tools/metadata/testdata/file3.txt
+++ /dev/null
@@ -1,13 +0,0 @@
-
-.
-java-test-module-name-one
-Android.bp12345
-.
-java-test-module-name-two
-Android.bp12345
-.
-java-test-module-name-two
-Asdfghj.bp12345
-.
-java-test-module-name-two
-Azxcvbn.bp12345
diff --git a/tools/metadata/testdata/file4.txt b/tools/metadata/testdata/file4.txt
deleted file mode 100644
index 6a7590021d..0000000000
--- a/tools/metadata/testdata/file4.txt
+++ /dev/null
@@ -1,25 +0,0 @@
-
-.
-java-test-module-name-one
-Android.bp12345
-.
-java-test-module-name-six
-Android.bp12346
-.
-java-test-module-name-one
-Android.bp12346
-.
-java-test-module-name-six
-Aqwerty.bp12346
-.
-java-test-module-name-six
-Apoiuyt.bp12346
-.
-java-test-module-name-six
-Apoiuyt.bp12346
-.
-java-test-module-name-six
-Apoiuyt.bp12346
-.
-java-test-module-name-six
-Apoiuyt.bp12346
diff --git a/tools/metadata/testdata/file5.txt b/tools/metadata/testdata/file5.txt
deleted file mode 100644
index d8de06457d..0000000000
--- a/tools/metadata/testdata/file5.txt
+++ /dev/null
@@ -1,4 +0,0 @@
-
- 
-foo
-Android.bp12345"a.java
diff --git a/tools/metadata/testdata/file6.txt b/tools/metadata/testdata/file6.txt
deleted file mode 100644
index 9c7cdcd505..0000000000
--- a/tools/metadata/testdata/file6.txt
+++ /dev/null
@@ -1,4 +0,0 @@
-
- 
-bar
-Android.bp12346"b.java
diff --git a/tools/metadata/testdata/file7.txt b/tools/metadata/testdata/file7.txt
deleted file mode 100644
index d8de06457d..0000000000
--- a/tools/metadata/testdata/file7.txt
+++ /dev/null
@@ -1,4 +0,0 @@
-
- 
-foo
-Android.bp12345"a.java
diff --git a/tools/metadata/testdata/file8.txt b/tools/metadata/testdata/file8.txt
deleted file mode 100644
index a931690022..0000000000
--- a/tools/metadata/testdata/file8.txt
+++ /dev/null
@@ -1,4 +0,0 @@
-
- 
-foo
-Android.gp12346"a.java
diff --git a/tools/metadata/testdata/generatedCodeMetadataOutput.txt b/tools/metadata/testdata/generatedCodeMetadataOutput.txt
deleted file mode 100644
index 755cf40a30..0000000000
--- a/tools/metadata/testdata/generatedCodeMetadataOutput.txt
+++ /dev/null
@@ -1,7 +0,0 @@
-
- 
-bar
-Android.bp12346"b.java
- 
-foo
-Android.bp12345"a.java
\ No newline at end of file
diff --git a/tools/metadata/testdata/generatedCodeMetadataOutputFile.txt b/tools/metadata/testdata/generatedCodeMetadataOutputFile.txt
deleted file mode 100644
index 755cf40a30..0000000000
--- a/tools/metadata/testdata/generatedCodeMetadataOutputFile.txt
+++ /dev/null
@@ -1,7 +0,0 @@
-
- 
-bar
-Android.bp12346"b.java
- 
-foo
-Android.bp12345"a.java
\ No newline at end of file
diff --git a/tools/metadata/testdata/generatedEmptyOutputFile.txt b/tools/metadata/testdata/generatedEmptyOutputFile.txt
deleted file mode 100644
index e69de29bb2..0000000000
diff --git a/tools/metadata/testdata/generatedOutputFile.txt b/tools/metadata/testdata/generatedOutputFile.txt
deleted file mode 100644
index b0d382f279..0000000000
--- a/tools/metadata/testdata/generatedOutputFile.txt
+++ /dev/null
@@ -1,22 +0,0 @@
-
-.
-java-test-module-name-one
-Android.bp12345
-.
-java-test-module-name-six
-Android.bp12346
-.
-java-test-module-name-six
-Aqwerty.bp12346
-.
-java-test-module-name-six
-Apoiuyt.bp12346
-.
-java-test-module-name-two
-Android.bp12345
-.
-java-test-module-name-two
-Asdfghj.bp12345
-.
-java-test-module-name-two
-Azxcvbn.bp12345
\ No newline at end of file
diff --git a/tools/metadata/testdata/inputCodeMetadata.txt b/tools/metadata/testdata/inputCodeMetadata.txt
deleted file mode 100644
index 7a81b7d523..0000000000
--- a/tools/metadata/testdata/inputCodeMetadata.txt
+++ /dev/null
@@ -1 +0,0 @@
-file5.txt file6.txt
\ No newline at end of file
diff --git a/tools/metadata/testdata/inputCodeMetadataNegative.txt b/tools/metadata/testdata/inputCodeMetadataNegative.txt
deleted file mode 100644
index 26668e44a9..0000000000
--- a/tools/metadata/testdata/inputCodeMetadataNegative.txt
+++ /dev/null
@@ -1 +0,0 @@
-file7.txt file8.txt
\ No newline at end of file
diff --git a/tools/metadata/testdata/inputFiles.txt b/tools/metadata/testdata/inputFiles.txt
deleted file mode 100644
index e44bc94d32..0000000000
--- a/tools/metadata/testdata/inputFiles.txt
+++ /dev/null
@@ -1 +0,0 @@
-file1.txt file2.txt
\ No newline at end of file
diff --git a/tools/metadata/testdata/inputFilesNegativeCase.txt b/tools/metadata/testdata/inputFilesNegativeCase.txt
deleted file mode 100644
index a37aa3fd5d..0000000000
--- a/tools/metadata/testdata/inputFilesNegativeCase.txt
+++ /dev/null
@@ -1 +0,0 @@
-file3.txt file4.txt
\ No newline at end of file
diff --git a/tools/metadata/testdata/metadata_test.go b/tools/metadata/testdata/metadata_test.go
deleted file mode 100644
index 314add352f..0000000000
--- a/tools/metadata/testdata/metadata_test.go
+++ /dev/null
@@ -1,119 +0,0 @@
-package main
-
-import (
-	"fmt"
-	"io/ioutil"
-	"os/exec"
-	"strings"
-	"testing"
-)
-
-func TestMetadata(t *testing.T) {
-	cmd := exec.Command(
-		"metadata", "-rule", "test_spec", "-inputFile", "./inputFiles.txt", "-outputFile",
-		"./generatedOutputFile.txt",
-	)
-	stderr, err := cmd.CombinedOutput()
-	if err != nil {
-		t.Fatalf("Error running metadata command: %s. Error: %v", stderr, err)
-	}
-
-	// Read the contents of the expected output file
-	expectedOutput, err := ioutil.ReadFile("./expectedOutputFile.txt")
-	if err != nil {
-		t.Fatalf("Error reading expected output file: %s", err)
-	}
-
-	// Read the contents of the generated output file
-	generatedOutput, err := ioutil.ReadFile("./generatedOutputFile.txt")
-	if err != nil {
-		t.Fatalf("Error reading generated output file: %s", err)
-	}
-
-	fmt.Println()
-
-	// Compare the contents
-	if string(expectedOutput) != string(generatedOutput) {
-		t.Errorf("Generated file contents do not match the expected output")
-	}
-}
-
-func TestMetadataNegativeCase(t *testing.T) {
-	cmd := exec.Command(
-		"metadata", "-rule", "test_spec", "-inputFile", "./inputFilesNegativeCase.txt", "-outputFile",
-		"./generatedOutputFileNegativeCase.txt",
-	)
-	stderr, err := cmd.CombinedOutput()
-	if err == nil {
-		t.Fatalf(
-			"Expected an error, but the metadata command executed successfully. Output: %s",
-			stderr,
-		)
-	}
-
-	expectedError := "Conflicting trendy team IDs found for java-test-module" +
-		"-name-one at:\nAndroid.bp with teamId: 12346," +
-		"\nAndroid.bp with teamId: 12345"
-	if !strings.Contains(
-		strings.TrimSpace(string(stderr)), strings.TrimSpace(expectedError),
-	) {
-		t.Errorf(
-			"Unexpected error message. Expected to contain: %s, Got: %s",
-			expectedError, stderr,
-		)
-	}
-}
-
-func TestEmptyInputFile(t *testing.T) {
-	cmd := exec.Command(
-		"metadata", "-rule", "test_spec", "-inputFile", "./emptyInputFile.txt", "-outputFile",
-		"./generatedEmptyOutputFile.txt",
-	)
-	stderr, err := cmd.CombinedOutput()
-	if err != nil {
-		t.Fatalf("Error running metadata command: %s. Error: %v", stderr, err)
-	}
-
-	// Read the contents of the generated output file
-	generatedOutput, err := ioutil.ReadFile("./generatedEmptyOutputFile.txt")
-	if err != nil {
-		t.Fatalf("Error reading generated output file: %s", err)
-	}
-
-	fmt.Println()
-
-	// Compare the contents
-	if string(generatedOutput) != "\n" {
-		t.Errorf("Generated file contents do not match the expected output")
-	}
-}
-
-func TestCodeMetadata(t *testing.T) {
-	cmd := exec.Command(
-		"metadata", "-rule", "code_metadata", "-inputFile", "./inputCodeMetadata.txt", "-outputFile",
-		"./generatedCodeMetadataOutputFile.txt",
-	)
-	stderr, err := cmd.CombinedOutput()
-	if err != nil {
-		t.Fatalf("Error running metadata command: %s. Error: %v", stderr, err)
-	}
-
-	// Read the contents of the expected output file
-	expectedOutput, err := ioutil.ReadFile("./expectedCodeMetadataOutput.txt")
-	if err != nil {
-		t.Fatalf("Error reading expected output file: %s", err)
-	}
-
-	// Read the contents of the generated output file
-	generatedOutput, err := ioutil.ReadFile("./generatedCodeMetadataOutputFile.txt")
-	if err != nil {
-		t.Fatalf("Error reading generated output file: %s", err)
-	}
-
-	fmt.Println()
-
-	// Compare the contents
-	if string(expectedOutput) != string(generatedOutput) {
-		t.Errorf("Generated file contents do not match the expected output")
-	}
-}
diff --git a/tools/metadata/testdata/outputFile.txt b/tools/metadata/testdata/outputFile.txt
deleted file mode 100644
index b0d382f279..0000000000
--- a/tools/metadata/testdata/outputFile.txt
+++ /dev/null
@@ -1,22 +0,0 @@
-
-.
-java-test-module-name-one
-Android.bp12345
-.
-java-test-module-name-six
-Android.bp12346
-.
-java-test-module-name-six
-Aqwerty.bp12346
-.
-java-test-module-name-six
-Apoiuyt.bp12346
-.
-java-test-module-name-two
-Android.bp12345
-.
-java-test-module-name-two
-Asdfghj.bp12345
-.
-java-test-module-name-two
-Azxcvbn.bp12345
\ No newline at end of file
diff --git a/tools/releasetools/Android.bp b/tools/releasetools/Android.bp
index 8c710449f9..e371b2354c 100644
--- a/tools/releasetools/Android.bp
+++ b/tools/releasetools/Android.bp
@@ -637,6 +637,8 @@ python_defaults {
     ],
     data: [
         "testdata/**/*",
+    ],
+    device_common_data: [
         ":com.android.apex.compressed.v1",
         ":com.android.apex.vendor.foo.with_vintf",
     ],
diff --git a/tools/releasetools/add_img_to_target_files.py b/tools/releasetools/add_img_to_target_files.py
index c25ff2718c..30a6accf32 100644
--- a/tools/releasetools/add_img_to_target_files.py
+++ b/tools/releasetools/add_img_to_target_files.py
@@ -1100,7 +1100,7 @@ def AddImagesToTargetFiles(filename):
     vbmeta_partitions = common.AVB_PARTITIONS[:] + tuple(avb_custom_partitions)
 
     vbmeta_system = OPTIONS.info_dict.get("avb_vbmeta_system", "").strip()
-    if vbmeta_system:
+    if vbmeta_system and set(vbmeta_system.split()).intersection(partitions):
       banner("vbmeta_system")
       partitions["vbmeta_system"] = AddVBMeta(
           output_zip, partitions, "vbmeta_system", vbmeta_system.split())
@@ -1110,7 +1110,7 @@ def AddImagesToTargetFiles(filename):
       vbmeta_partitions.append("vbmeta_system")
 
     vbmeta_vendor = OPTIONS.info_dict.get("avb_vbmeta_vendor", "").strip()
-    if vbmeta_vendor:
+    if vbmeta_vendor and set(vbmeta_vendor.split()).intersection(partitions):
       banner("vbmeta_vendor")
       partitions["vbmeta_vendor"] = AddVBMeta(
           output_zip, partitions, "vbmeta_vendor", vbmeta_vendor.split())
@@ -1137,7 +1137,7 @@ def AddImagesToTargetFiles(filename):
             if item not in included_partitions]
         vbmeta_partitions.append(partition_name)
 
-    if OPTIONS.info_dict.get("avb_building_vbmeta_image") == "true":
+    if OPTIONS.info_dict.get("avb_building_vbmeta_image") == "true" and set(vbmeta_partitions).intersection(partitions):
       banner("vbmeta")
       AddVBMeta(output_zip, partitions, "vbmeta", vbmeta_partitions)
 
diff --git a/tools/releasetools/apex_utils.py b/tools/releasetools/apex_utils.py
index 54df955e9f..08f2b83388 100644
--- a/tools/releasetools/apex_utils.py
+++ b/tools/releasetools/apex_utils.py
@@ -79,15 +79,10 @@ class ApexApkSigner(object):
     Returns:
       The repacked apex file containing the signed apk files.
     """
-    if not os.path.exists(self.debugfs_path):
-      raise ApexSigningError(
-          "Couldn't find location of debugfs_static: " +
-          "Path {} does not exist. ".format(self.debugfs_path) +
-          "Make sure bin/debugfs_static can be found in -p <path>")
-    list_cmd = ['deapexer', '--debugfs_path', self.debugfs_path,
-                'list', self.apex_path]
-    entries_names = common.RunAndCheckOutput(list_cmd).split()
-    apk_entries = [name for name in entries_names if name.endswith('.apk')]
+    payload_dir = self.ExtractApexPayload(self.apex_path)
+    apk_entries = []
+    for base_dir, _, files in os.walk(payload_dir):
+      apk_entries.extend(os.path.join(base_dir, file) for file in files if file.endswith('.apk'))
 
     # No need to sign and repack, return the original apex path.
     if not apk_entries and self.sign_tool is None:
@@ -105,16 +100,16 @@ class ApexApkSigner(object):
         logger.warning('Apk path does not contain the intended directory name:'
                        ' %s', entry)
 
-    payload_dir, has_signed_content = self.ExtractApexPayloadAndSignContents(
-        apk_entries, apk_keys, payload_key, signing_args)
+    has_signed_content = self.SignContentsInPayload(
+        payload_dir, apk_entries, apk_keys, payload_key, signing_args)
     if not has_signed_content:
       logger.info('No contents has been signed in %s', self.apex_path)
       return self.apex_path
 
     return self.RepackApexPayload(payload_dir, payload_key, signing_args)
 
-  def ExtractApexPayloadAndSignContents(self, apk_entries, apk_keys, payload_key, signing_args):
-    """Extracts the payload image and signs the containing apk files."""
+  def ExtractApexPayload(self, apex_path):
+    """Extracts the contents of an APEX and returns the directory of the contents"""
     if not os.path.exists(self.debugfs_path):
       raise ApexSigningError(
           "Couldn't find location of debugfs_static: " +
@@ -129,9 +124,12 @@ class ApexApkSigner(object):
     extract_cmd = ['deapexer', '--debugfs_path', self.debugfs_path,
                    '--fsckerofs_path', self.fsckerofs_path,
                    'extract',
-                   self.apex_path, payload_dir]
+                   apex_path, payload_dir]
     common.RunAndCheckOutput(extract_cmd)
+    return payload_dir
 
+  def SignContentsInPayload(self, payload_dir, apk_entries, apk_keys, payload_key, signing_args):
+    """Signs the contents in payload."""
     has_signed_content = False
     for entry in apk_entries:
       apk_path = os.path.join(payload_dir, entry)
@@ -163,7 +161,7 @@ class ApexApkSigner(object):
       common.RunAndCheckOutput(cmd)
       has_signed_content = True
 
-    return payload_dir, has_signed_content
+    return has_signed_content
 
   def RepackApexPayload(self, payload_dir, payload_key, signing_args=None):
     """Rebuilds the apex file with the updated payload directory."""
diff --git a/tools/releasetools/ota_from_target_files.py b/tools/releasetools/ota_from_target_files.py
index 6446e1ff59..76d168cb8e 100755
--- a/tools/releasetools/ota_from_target_files.py
+++ b/tools/releasetools/ota_from_target_files.py
@@ -1039,6 +1039,9 @@ def GenerateAbOtaPackage(target_file, output_file, source_file=None):
 
   # Prepare custom images.
   if OPTIONS.custom_images:
+    if source_file is not None:
+      source_file = GetTargetFilesZipForCustomImagesUpdates(
+           source_file, OPTIONS.custom_images)
     target_file = GetTargetFilesZipForCustomImagesUpdates(
         target_file, OPTIONS.custom_images)
 
@@ -1121,17 +1124,18 @@ def GenerateAbOtaPackage(target_file, output_file, source_file=None):
   additional_args += ["--enable_lz4diff=" +
                       str(OPTIONS.enable_lz4diff).lower()]
 
+  env_override = {}
   if source_file and OPTIONS.enable_lz4diff:
-    input_tmp = common.UnzipTemp(source_file, ["META/liblz4.so"])
-    liblz4_path = os.path.join(input_tmp, "META", "liblz4.so")
+    liblz4_path = os.path.join(source_file, "META", "liblz4.so")
     assert os.path.exists(
         liblz4_path), "liblz4.so not found in META/ dir of target file {}".format(liblz4_path)
     logger.info("Enabling lz4diff %s", liblz4_path)
-    additional_args += ["--liblz4_path", liblz4_path]
     erofs_compression_param = OPTIONS.target_info_dict.get(
         "erofs_default_compressor")
     assert erofs_compression_param is not None, "'erofs_default_compressor' not found in META/misc_info.txt of target build. This is required to enable lz4diff."
     additional_args += ["--erofs_compression_param", erofs_compression_param]
+    env_override["LD_PRELOAD"] = liblz4_path + \
+        ":" + os.environ.get("LD_PRELOAD", "")
 
   if OPTIONS.disable_vabc:
     additional_args += ["--disable_vabc=true"]
@@ -1141,10 +1145,15 @@ def GenerateAbOtaPackage(target_file, output_file, source_file=None):
     additional_args += ["--compressor_types", OPTIONS.compressor_types]
   additional_args += ["--max_timestamp", max_timestamp]
 
+  env = dict(os.environ)
+  if env_override:
+    logger.info("Using environment variables %s", env_override)
+    env.update(env_override)
   payload.Generate(
       target_file,
       source_file,
-      additional_args + partition_timestamps_flags
+      additional_args + partition_timestamps_flags,
+      env=env
   )
 
   # Sign the payload.
diff --git a/tools/releasetools/ota_utils.py b/tools/releasetools/ota_utils.py
index 81b53dce36..852d62bb0f 100644
--- a/tools/releasetools/ota_utils.py
+++ b/tools/releasetools/ota_utils.py
@@ -845,16 +845,16 @@ class PayloadGenerator(object):
     self.is_partial_update = is_partial_update
     self.spl_downgrade = spl_downgrade
 
-  def _Run(self, cmd):  # pylint: disable=no-self-use
+  def _Run(self, cmd, **kwargs):  # pylint: disable=no-self-use
     # Don't pipe (buffer) the output if verbose is set. Let
     # brillo_update_payload write to stdout/stderr directly, so its progress can
     # be monitored.
     if OPTIONS.verbose:
-      common.RunAndCheckOutput(cmd, stdout=None, stderr=None)
+      common.RunAndCheckOutput(cmd, stdout=None, stderr=None, **kwargs)
     else:
-      common.RunAndCheckOutput(cmd)
+      common.RunAndCheckOutput(cmd, **kwargs)
 
-  def Generate(self, target_file, source_file=None, additional_args=None):
+  def Generate(self, target_file, source_file=None, additional_args=None, **kwargs):
     """Generates a payload from the given target-files zip(s).
 
     Args:
@@ -863,6 +863,7 @@ class PayloadGenerator(object):
           generating a full OTA.
       additional_args: A list of additional args that should be passed to
           delta_generator binary; or None.
+      kwargs: Any additional args to pass to subprocess.Popen
     """
     if additional_args is None:
       additional_args = []
@@ -918,7 +919,7 @@ class PayloadGenerator(object):
     if self.is_partial_update:
       cmd.extend(["--is_partial_update=true"])
     cmd.extend(additional_args)
-    self._Run(cmd)
+    self._Run(cmd, **kwargs)
 
     self.payload_file = payload_file
     self.payload_properties = None
diff --git a/tools/signapk/src/com/android/signapk/SignApk.java b/tools/signapk/src/com/android/signapk/SignApk.java
index 6b2341bc80..654e19675d 100644
--- a/tools/signapk/src/com/android/signapk/SignApk.java
+++ b/tools/signapk/src/com/android/signapk/SignApk.java
@@ -302,7 +302,6 @@ class SignApk {
             final KeyStore keyStore, final String keyName)
             throws CertificateException, KeyStoreException, NoSuchAlgorithmException,
                     UnrecoverableKeyException, UnrecoverableEntryException {
-        final Key key = keyStore.getKey(keyName, readPassword(keyName));
         final PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry) keyStore.getEntry(keyName, null);
         if (privateKeyEntry == null) {
         throw new Error(
```

