```diff
diff --git a/.github/dependabot.yml b/.github/dependabot.yml
index b76b8957..8519eb9a 100644
--- a/.github/dependabot.yml
+++ b/.github/dependabot.yml
@@ -3,8 +3,18 @@ updates:
   - package-ecosystem: "maven"
     directory: "/"
     schedule:
-      interval: "daily"
+      interval: "weekly"
+    groups:
+      dependencies:
+        applies-to: version-updates
+        patterns:
+          - "*"
   - package-ecosystem: "github-actions"
     directory: "/"
     schedule:
-      interval: "daily"
+      interval: "weekly"
+    groups:
+      github-actions:
+        applies-to: version-updates
+        patterns:
+          - "*"
diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml
index eb5ec20a..21b3781c 100644
--- a/.github/workflows/ci.yml
+++ b/.github/workflows/ci.yml
@@ -18,20 +18,20 @@ jobs:
     steps:
       # Cancel any previous runs for the same branch that are still running.
       - name: 'Cancel previous runs'
-        uses: styfle/cancel-workflow-action@b173b6ec0100793626c2d9e6b90435061f4fc3e5
+        uses: styfle/cancel-workflow-action@85880fa0301c86cca9da44039ee3bb12d3bedbfa
         with:
           access_token: ${{ github.token }}
       - name: 'Check out repository'
-        uses: actions/checkout@c85c95e3d7251135ab7dc9ce3241c5835cc595a9
+        uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332
       - name: 'Cache local Maven repository'
-        uses: actions/cache@88522ab9f39a2ea568f7027eddc7d8d8bc9d59c8
+        uses: actions/cache@0c45773b623bea8c8e75f6c82b208c3cf94ea4f9
         with:
           path: ~/.m2/repository
           key: maven-${{ hashFiles('**/pom.xml') }}
           restore-keys: |
             maven-
       - name: 'Set up JDK ${{ matrix.java }}'
-        uses: actions/setup-java@5ffc13f4174014e2d4d4572b3d74c3fa61aeb2c2
+        uses: actions/setup-java@99b8673ff64fbf99d8d325f52d9a5bdedb8483e9
         with:
           java-version: ${{ matrix.java }}
           distribution: 'zulu'
@@ -52,16 +52,16 @@ jobs:
     runs-on: ubuntu-latest
     steps:
       - name: 'Check out repository'
-        uses: actions/checkout@c85c95e3d7251135ab7dc9ce3241c5835cc595a9
+        uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332
       - name: 'Cache local Maven repository'
-        uses: actions/cache@88522ab9f39a2ea568f7027eddc7d8d8bc9d59c8
+        uses: actions/cache@0c45773b623bea8c8e75f6c82b208c3cf94ea4f9
         with:
           path: ~/.m2/repository
           key: maven-${{ hashFiles('**/pom.xml') }}
           restore-keys: |
             maven-
       - name: 'Set up JDK 11'
-        uses: actions/setup-java@5ffc13f4174014e2d4d4572b3d74c3fa61aeb2c2
+        uses: actions/setup-java@99b8673ff64fbf99d8d325f52d9a5bdedb8483e9
         with:
           java-version: 11
           distribution: 'zulu'
@@ -81,16 +81,16 @@ jobs:
     runs-on: ubuntu-latest
     steps:
       - name: 'Check out repository'
-        uses: actions/checkout@c85c95e3d7251135ab7dc9ce3241c5835cc595a9
+        uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332
       - name: 'Cache local Maven repository'
-        uses: actions/cache@88522ab9f39a2ea568f7027eddc7d8d8bc9d59c8
+        uses: actions/cache@0c45773b623bea8c8e75f6c82b208c3cf94ea4f9
         with:
           path: ~/.m2/repository
           key: maven-${{ hashFiles('**/pom.xml') }}
           restore-keys: |
             maven-
       - name: 'Set up JDK 11'
-        uses: actions/setup-java@5ffc13f4174014e2d4d4572b3d74c3fa61aeb2c2
+        uses: actions/setup-java@99b8673ff64fbf99d8d325f52d9a5bdedb8483e9
         with:
           java-version: 11
           distribution: 'zulu'
diff --git a/Android.bp b/Android.bp
index bccc4fc8..c6c5164c 100644
--- a/Android.bp
+++ b/Android.bp
@@ -35,6 +35,7 @@ java_library {
         "auto_value_annotations",
         "error_prone_annotations",
         "guava-android-annotation-stubs",
+        "jspecify",
         "junit",
     ],
     static_libs: [
@@ -69,6 +70,7 @@ java_library {
         "auto_value_annotations",
         "error_prone_annotations",
         "guava-android-annotation-stubs",
+        "jspecify",
         "truth",
     ],
     static_libs: [
@@ -86,6 +88,7 @@ java_library {
         "auto_value_annotations",
         "error_prone_annotations",
         "guava-android-annotation-stubs",
+        "jspecify",
         "truth",
     ],
     static_libs: [
@@ -103,6 +106,7 @@ java_library_host {
         "auto_value_memoized_extension_annotations",
         "error_prone_annotations",
         "guava-android-annotation-stubs",
+        "jspecify",
         "truth",
         "truth-liteproto-extension",
     ],
diff --git a/METADATA b/METADATA
index 4f40f8fa..0fd7a693 100644
--- a/METADATA
+++ b/METADATA
@@ -11,7 +11,7 @@ third_party {
     type: GIT
     value: "https://github.com/google/truth.git"
   }
-  version: "v1.1.5"
-  last_upgrade_date { year: 2023 month: 10 day: 7 }
+  version: "v1.4.4"
+  last_upgrade_date { year: 2024 month: 10 day: 25 }
   license_type: NOTICE
 }
diff --git a/core/pom.xml b/core/pom.xml
index 2afd00e5..747a8cfe 100644
--- a/core/pom.xml
+++ b/core/pom.xml
@@ -15,8 +15,8 @@
       <artifactId>guava</artifactId>
     </dependency>
     <dependency>
-      <groupId>org.checkerframework</groupId>
-      <artifactId>checker-qual</artifactId>
+      <groupId>org.jspecify</groupId>
+      <artifactId>jspecify</artifactId>
     </dependency>
     <dependency>
       <groupId>junit</groupId>
@@ -24,7 +24,7 @@
     </dependency>
     <!-- Required only to test the -gwt sub-artifact. -->
     <dependency>
-      <groupId>com.google.gwt</groupId>
+      <groupId>org.gwtproject</groupId>
       <artifactId>gwt-user</artifactId>
       <scope>test</scope>
     </dependency>
@@ -138,7 +138,7 @@
             <goals><goal>test</goal></goals>
             <configuration>
               <mode>htmlunit</mode>
-              <htmlunit>FF38</htmlunit>
+              <htmlunit>FF</htmlunit>
               <productionMode>true</productionMode>
               <!-- Fix OutOfMemoryError in Travis. -->
               <extraJvmArgs>-Xms3500m -Xmx3500m -Xss1024k</extraJvmArgs>
@@ -165,7 +165,7 @@
       <plugin>
         <groupId>org.codehaus.mojo</groupId>
         <artifactId>build-helper-maven-plugin</artifactId>
-        <version>3.4.0</version>
+        <version>3.6.0</version>
         <executions>
           <execution>
             <id>add-source</id>
@@ -227,7 +227,7 @@
       <plugin>
         <groupId>org.apache.maven.plugins</groupId>
         <artifactId>maven-project-info-reports-plugin</artifactId>
-        <version>3.4.5</version>
+        <version>3.6.1</version>
       </plugin>
     </plugins>
   </reporting>
diff --git a/core/src/main/java/com/google/common/truth/AbstractArraySubject.java b/core/src/main/java/com/google/common/truth/AbstractArraySubject.java
index 8eff47a1..a08863a9 100644
--- a/core/src/main/java/com/google/common/truth/AbstractArraySubject.java
+++ b/core/src/main/java/com/google/common/truth/AbstractArraySubject.java
@@ -20,7 +20,7 @@ import static com.google.common.base.Preconditions.checkNotNull;
 import static com.google.common.truth.Fact.simpleFact;
 
 import java.lang.reflect.Array;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * A common supertype for Array subjects, abstracting some common display and error infrastructure.
diff --git a/core/src/main/java/com/google/common/truth/ActualValueInference.java b/core/src/main/java/com/google/common/truth/ActualValueInference.java
index db49c1da..d90203c6 100644
--- a/core/src/main/java/com/google/common/truth/ActualValueInference.java
+++ b/core/src/main/java/com/google/common/truth/ActualValueInference.java
@@ -33,7 +33,7 @@ import java.io.IOException;
 import java.io.InputStream;
 import java.util.ArrayList;
 import java.util.Map.Entry;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 import org.objectweb.asm.ClassReader;
 import org.objectweb.asm.ClassVisitor;
 import org.objectweb.asm.Handle;
diff --git a/core/src/main/java/com/google/common/truth/AssertionErrorWithFacts.java b/core/src/main/java/com/google/common/truth/AssertionErrorWithFacts.java
index cc5d36d9..097e8ca3 100644
--- a/core/src/main/java/com/google/common/truth/AssertionErrorWithFacts.java
+++ b/core/src/main/java/com/google/common/truth/AssertionErrorWithFacts.java
@@ -19,7 +19,7 @@ import static com.google.common.base.Preconditions.checkNotNull;
 import static com.google.common.truth.Fact.makeMessage;
 
 import com.google.common.collect.ImmutableList;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * An {@link AssertionError} composed of structured {@link Fact} instances and other string
@@ -29,26 +29,10 @@ import org.checkerframework.checker.nullness.qual.Nullable;
 final class AssertionErrorWithFacts extends AssertionError implements ErrorWithFacts {
   private final ImmutableList<Fact> facts;
 
-  /** Separate cause field, in case initCause() fails. */
-  private final @Nullable Throwable cause;
-
   AssertionErrorWithFacts(
       ImmutableList<String> messages, ImmutableList<Fact> facts, @Nullable Throwable cause) {
-    super(makeMessage(messages, facts));
+    super(makeMessage(messages, facts), cause);
     this.facts = checkNotNull(facts);
-
-    this.cause = cause;
-    try {
-      initCause(cause);
-    } catch (IllegalStateException alreadyInitializedBecauseOfHarmonyBug) {
-      // See Truth.SimpleAssertionError.
-    }
-  }
-
-  @Override
-  @SuppressWarnings("UnsynchronizedOverridesSynchronized")
-  public @Nullable Throwable getCause() {
-    return cause;
   }
 
   @Override
diff --git a/core/src/main/java/com/google/common/truth/BigDecimalSubject.java b/core/src/main/java/com/google/common/truth/BigDecimalSubject.java
index dbba5917..c98fa1cf 100644
--- a/core/src/main/java/com/google/common/truth/BigDecimalSubject.java
+++ b/core/src/main/java/com/google/common/truth/BigDecimalSubject.java
@@ -20,7 +20,7 @@ import static com.google.common.truth.Fact.fact;
 import static com.google.common.truth.Fact.simpleFact;
 
 import java.math.BigDecimal;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * Propositions for {@link BigDecimal} typed subjects.
diff --git a/core/src/main/java/com/google/common/truth/BooleanSubject.java b/core/src/main/java/com/google/common/truth/BooleanSubject.java
index 4e7f3da0..ad0e17ba 100644
--- a/core/src/main/java/com/google/common/truth/BooleanSubject.java
+++ b/core/src/main/java/com/google/common/truth/BooleanSubject.java
@@ -17,7 +17,7 @@ package com.google.common.truth;
 
 import static com.google.common.truth.Fact.simpleFact;
 
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * Propositions for boolean subjects.
diff --git a/core/src/main/java/com/google/common/truth/ClassSubject.java b/core/src/main/java/com/google/common/truth/ClassSubject.java
index 1ef1b950..24f6283c 100644
--- a/core/src/main/java/com/google/common/truth/ClassSubject.java
+++ b/core/src/main/java/com/google/common/truth/ClassSubject.java
@@ -18,7 +18,7 @@ package com.google.common.truth;
 import static com.google.common.base.Preconditions.checkNotNull;
 
 import com.google.common.annotations.GwtIncompatible;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * Propositions for {@link Class} subjects.
diff --git a/core/src/main/java/com/google/common/truth/ComparableSubject.java b/core/src/main/java/com/google/common/truth/ComparableSubject.java
index 857f2149..0d766ec1 100644
--- a/core/src/main/java/com/google/common/truth/ComparableSubject.java
+++ b/core/src/main/java/com/google/common/truth/ComparableSubject.java
@@ -18,7 +18,7 @@ package com.google.common.truth;
 import static com.google.common.base.Preconditions.checkNotNull;
 
 import com.google.common.collect.Range;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * Propositions for {@link Comparable} typed subjects.
diff --git a/core/src/main/java/com/google/common/truth/ComparisonFailureWithFacts.java b/core/src/main/java/com/google/common/truth/ComparisonFailureWithFacts.java
index 47608db2..88d031c8 100644
--- a/core/src/main/java/com/google/common/truth/ComparisonFailureWithFacts.java
+++ b/core/src/main/java/com/google/common/truth/ComparisonFailureWithFacts.java
@@ -21,7 +21,7 @@ import static com.google.common.truth.Fact.makeMessage;
 
 import com.google.common.collect.ImmutableList;
 import com.google.common.truth.Platform.PlatformComparisonFailure;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * An {@link AssertionError} (usually a JUnit {@code ComparisonFailure}, but not under GWT) composed
diff --git a/core/src/main/java/com/google/common/truth/ComparisonFailures.java b/core/src/main/java/com/google/common/truth/ComparisonFailures.java
index 1e50f49c..af7ad300 100644
--- a/core/src/main/java/com/google/common/truth/ComparisonFailures.java
+++ b/core/src/main/java/com/google/common/truth/ComparisonFailures.java
@@ -26,7 +26,7 @@ import static java.lang.Math.max;
 
 import com.google.common.annotations.VisibleForTesting;
 import com.google.common.collect.ImmutableList;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * Contains part of the code responsible for creating a JUnit {@code ComparisonFailure} (if
diff --git a/core/src/main/java/com/google/common/truth/Correspondence.java b/core/src/main/java/com/google/common/truth/Correspondence.java
index 704a9e6c..5e5453b1 100644
--- a/core/src/main/java/com/google/common/truth/Correspondence.java
+++ b/core/src/main/java/com/google/common/truth/Correspondence.java
@@ -22,7 +22,7 @@ import static com.google.common.truth.DoubleSubject.checkTolerance;
 import static com.google.common.truth.Fact.fact;
 import static com.google.common.truth.Fact.simpleFact;
 import static com.google.common.truth.Platform.getStackTraceAsString;
-import static java.util.Arrays.asList;
+import static com.google.common.truth.SubjectUtils.asList;
 
 import com.google.common.base.Function;
 import com.google.common.base.Joiner;
@@ -31,7 +31,7 @@ import com.google.common.base.Strings;
 import com.google.common.collect.ImmutableList;
 import java.util.Arrays;
 import java.util.List;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * Determines whether an instance of type {@code A} corresponds in some way to an instance of type
@@ -323,13 +323,13 @@ public abstract class Correspondence<A extends @Nullable Object, E extends @Null
    * diff-formatting functionality to it. See e.g. {@link IterableSubject#formattingDiffsUsing}.
    */
   @SuppressWarnings("unchecked") // safe covariant cast
-  static <T> Correspondence<T, T> equality() {
+  static <T extends @Nullable Object> Correspondence<T, T> equality() {
     return (Equality<T>) Equality.INSTANCE;
   }
 
-  private static final class Equality<T> extends Correspondence<T, T> {
+  private static final class Equality<T extends @Nullable Object> extends Correspondence<T, T> {
 
-    private static final Equality<Object> INSTANCE = new Equality<>();
+    private static final Equality<@Nullable Object> INSTANCE = new Equality<>();
 
     @Override
     public boolean compare(T actual, T expected) {
diff --git a/core/src/main/java/com/google/common/truth/CustomSubjectBuilder.java b/core/src/main/java/com/google/common/truth/CustomSubjectBuilder.java
index 0b84ef88..9fee6f55 100644
--- a/core/src/main/java/com/google/common/truth/CustomSubjectBuilder.java
+++ b/core/src/main/java/com/google/common/truth/CustomSubjectBuilder.java
@@ -18,7 +18,6 @@ package com.google.common.truth;
 
 import static com.google.common.base.Preconditions.checkNotNull;
 
-
 /**
  * In a fluent assertion chain, exposes one or more "custom" {@code that} methods, which accept a
  * value under test and return a {@link Subject}.
diff --git a/core/src/main/java/com/google/common/truth/DoubleSubject.java b/core/src/main/java/com/google/common/truth/DoubleSubject.java
index 58cd50d6..f1a87351 100644
--- a/core/src/main/java/com/google/common/truth/DoubleSubject.java
+++ b/core/src/main/java/com/google/common/truth/DoubleSubject.java
@@ -26,7 +26,7 @@ import static com.google.common.truth.Platform.doubleToString;
 import static java.lang.Double.NaN;
 import static java.lang.Double.doubleToLongBits;
 
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * Propositions for {@link Double} subjects.
diff --git a/core/src/main/java/com/google/common/truth/Expect.java b/core/src/main/java/com/google/common/truth/Expect.java
index 4e7b77d7..8577c14f 100644
--- a/core/src/main/java/com/google/common/truth/Expect.java
+++ b/core/src/main/java/com/google/common/truth/Expect.java
@@ -30,7 +30,7 @@ import com.google.common.truth.Truth.SimpleAssertionError;
 import com.google.errorprone.annotations.concurrent.GuardedBy;
 import java.util.ArrayList;
 import java.util.List;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 import org.junit.internal.AssumptionViolatedException;
 import org.junit.rules.ErrorCollector;
 import org.junit.rules.TestRule;
@@ -73,7 +73,7 @@ import org.junit.runners.model.Statement;
  *       by a method like {@code executor.submit(...)}. It might also include checking for
  *       unexpected log messages
  *       or reading metrics that count failures.) If your tests already check for exceptions from a
- *       thread, then that will any cover exception from plain {@code assertThat}.
+ *       thread, then that will cover any exception from plain {@code assertThat}.
  * </ul>
  *
  * <p>To record failures for the purpose of testing that an assertion fails when it should, see
diff --git a/core/src/main/java/com/google/common/truth/ExpectFailure.java b/core/src/main/java/com/google/common/truth/ExpectFailure.java
index 5b036085..98b625cc 100644
--- a/core/src/main/java/com/google/common/truth/ExpectFailure.java
+++ b/core/src/main/java/com/google/common/truth/ExpectFailure.java
@@ -24,7 +24,7 @@ import static com.google.common.truth.TruthFailureSubject.truthFailures;
 import com.google.common.annotations.GwtIncompatible;
 import com.google.common.truth.Truth.SimpleAssertionError;
 import com.google.errorprone.annotations.CanIgnoreReturnValue;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 import org.junit.runner.Description;
 import org.junit.runners.model.Statement;
 
diff --git a/core/src/main/java/com/google/common/truth/Fact.java b/core/src/main/java/com/google/common/truth/Fact.java
index b2dadad2..28917790 100644
--- a/core/src/main/java/com/google/common/truth/Fact.java
+++ b/core/src/main/java/com/google/common/truth/Fact.java
@@ -22,7 +22,7 @@ import static java.lang.Math.max;
 
 import com.google.common.collect.ImmutableList;
 import java.io.Serializable;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * A string key-value pair in a failure message, such as "expected: abc" or "but was: xyz."
diff --git a/core/src/main/java/com/google/common/truth/FailureMetadata.java b/core/src/main/java/com/google/common/truth/FailureMetadata.java
index e6d86a74..6a9c90fd 100644
--- a/core/src/main/java/com/google/common/truth/FailureMetadata.java
+++ b/core/src/main/java/com/google/common/truth/FailureMetadata.java
@@ -29,7 +29,7 @@ import static com.google.common.truth.SubjectUtils.concat;
 
 import com.google.common.base.Function;
 import com.google.common.collect.ImmutableList;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * An opaque, immutable object containing state from the previous calls in the fluent assertion
diff --git a/core/src/main/java/com/google/common/truth/FloatSubject.java b/core/src/main/java/com/google/common/truth/FloatSubject.java
index 19dff124..c5d66118 100644
--- a/core/src/main/java/com/google/common/truth/FloatSubject.java
+++ b/core/src/main/java/com/google/common/truth/FloatSubject.java
@@ -26,7 +26,7 @@ import static com.google.common.truth.Platform.floatToString;
 import static java.lang.Float.NaN;
 import static java.lang.Float.floatToIntBits;
 
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * Propositions for {@link Float} subjects.
diff --git a/core/src/main/java/com/google/common/truth/GuavaOptionalSubject.java b/core/src/main/java/com/google/common/truth/GuavaOptionalSubject.java
index d65448d6..cd977690 100644
--- a/core/src/main/java/com/google/common/truth/GuavaOptionalSubject.java
+++ b/core/src/main/java/com/google/common/truth/GuavaOptionalSubject.java
@@ -19,21 +19,24 @@ import static com.google.common.truth.Fact.fact;
 import static com.google.common.truth.Fact.simpleFact;
 
 import com.google.common.base.Optional;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * Propositions for Guava {@link Optional} subjects.
  *
- * <p>If you are looking for a {@code java.util.Optional} subject, please read
- * <a href="https://truth.dev/faq#java8">faq#java8</a>
+ * <p>If you are looking for a {@code java.util.Optional} subject, see {@link OptionalSubject}.
  *
  * @author Christian Gruber
  */
 public final class GuavaOptionalSubject extends Subject {
+  @SuppressWarnings("NullableOptional") // Truth always accepts nulls, no matter the type
   private final @Nullable Optional<?> actual;
 
   GuavaOptionalSubject(
-      FailureMetadata metadata, @Nullable Optional<?> actual, @Nullable String typeDescription) {
+      FailureMetadata metadata,
+      @SuppressWarnings("NullableOptional") // Truth always accepts nulls, no matter the type
+          @Nullable Optional<?> actual,
+      @Nullable String typeDescription) {
     super(metadata, actual, typeDescription);
     this.actual = actual;
   }
diff --git a/extensions/java8/src/main/java/com/google/common/truth/PathSubject.java b/core/src/main/java/com/google/common/truth/IgnoreJRERequirement.java
similarity index 53%
rename from extensions/java8/src/main/java/com/google/common/truth/PathSubject.java
rename to core/src/main/java/com/google/common/truth/IgnoreJRERequirement.java
index 0be8532e..a2d48427 100644
--- a/extensions/java8/src/main/java/com/google/common/truth/PathSubject.java
+++ b/core/src/main/java/com/google/common/truth/IgnoreJRERequirement.java
@@ -1,5 +1,5 @@
 /*
- * Copyright (c) 2017 Google, Inc.
+ * Copyright (c) 2019 Google, Inc.
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -13,21 +13,17 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
+
 package com.google.common.truth;
 
-import com.google.common.annotations.GwtIncompatible;
-import com.google.j2objc.annotations.J2ObjCIncompatible;
-import java.nio.file.Path;
+import static java.lang.annotation.ElementType.CONSTRUCTOR;
+import static java.lang.annotation.ElementType.METHOD;
+import static java.lang.annotation.ElementType.TYPE;
 
-/** Assertions for {@link Path} instances. */
-@GwtIncompatible
-@J2ObjCIncompatible
-public final class PathSubject extends Subject {
-  private PathSubject(FailureMetadata failureMetadata, Path actual) {
-    super(failureMetadata, actual);
-  }
+import java.lang.annotation.Target;
 
-  public static Subject.Factory<PathSubject, Path> paths() {
-    return PathSubject::new;
-  }
-}
+/**
+ * Disables Animal Sniffer's checking of compatibility with older versions of Java/Android.
+ */
+@Target({METHOD, CONSTRUCTOR, TYPE})
+@interface IgnoreJRERequirement {}
diff --git a/extensions/java8/src/main/java/com/google/common/truth/IntStreamSubject.java b/core/src/main/java/com/google/common/truth/IntStreamSubject.java
similarity index 79%
rename from extensions/java8/src/main/java/com/google/common/truth/IntStreamSubject.java
rename to core/src/main/java/com/google/common/truth/IntStreamSubject.java
index 45699bce..3699e089 100644
--- a/extensions/java8/src/main/java/com/google/common/truth/IntStreamSubject.java
+++ b/core/src/main/java/com/google/common/truth/IntStreamSubject.java
@@ -15,6 +15,7 @@
  */
 package com.google.common.truth;
 
+import static com.google.common.base.Preconditions.checkNotNull;
 import static java.util.stream.Collectors.toCollection;
 
 import com.google.errorprone.annotations.CanIgnoreReturnValue;
@@ -23,7 +24,7 @@ import java.util.Comparator;
 import java.util.List;
 import java.util.stream.IntStream;
 import java.util.stream.Stream;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * Propositions for {@link IntStream} subjects.
@@ -39,13 +40,18 @@ import org.checkerframework.checker.nullness.qual.Nullable;
  * stream before asserting on it.
  *
  * @author Kurt Alfred Kluever
+ * @since 1.3.0 (previously part of {@code truth-java8-extension})
  */
-@SuppressWarnings("deprecation") // TODO(b/134064106): design an alternative to no-arg check()
+@SuppressWarnings({
+  "deprecation", // TODO(b/134064106): design an alternative to no-arg check()
+  "Java7ApiChecker", // used only from APIs with Java 8 in their signatures
+})
+@IgnoreJRERequirement
 public final class IntStreamSubject extends Subject {
 
-  private final List<?> actualList;
+  private final @Nullable List<?> actualList;
 
-  private IntStreamSubject(FailureMetadata failureMetadata, @Nullable IntStream stream) {
+  IntStreamSubject(FailureMetadata failureMetadata, @Nullable IntStream stream) {
     super(failureMetadata, stream);
     this.actualList =
         (stream == null) ? null : stream.boxed().collect(toCollection(ArrayList::new));
@@ -56,6 +62,17 @@ public final class IntStreamSubject extends Subject {
     return String.valueOf(actualList);
   }
 
+  /**
+   * Obsolete factory instance. This factory was previously necessary for assertions like {@code
+   * assertWithMessage(...).about(intStreams()).that(stream)....}. Now, you can perform assertions
+   * like that without the {@code about(...)} call.
+   *
+   * @deprecated Instead of {@code about(intStreams()).that(...)}, use just {@code that(...)}.
+   *     Similarly, instead of {@code assertAbout(intStreams()).that(...)}, use just {@code
+   *     assertThat(...)}.
+   */
+  @Deprecated
+  @SuppressWarnings("InlineMeSuggester") // We want users to remove the surrounding call entirely.
   public static Factory<IntStreamSubject, IntStream> intStreams() {
     return IntStreamSubject::new;
   }
@@ -102,7 +119,7 @@ public final class IntStreamSubject extends Subject {
   }
 
   /** Fails if the subject does not contain at least one of the given elements. */
-  public void containsAnyIn(Iterable<?> expected) {
+  public void containsAnyIn(@Nullable Iterable<?> expected) {
     check().that(actualList).containsAnyIn(expected);
   }
 
@@ -131,7 +148,7 @@ public final class IntStreamSubject extends Subject {
    * within the actual elements, but they are not required to be consecutive.
    */
   @CanIgnoreReturnValue
-  public Ordered containsAtLeastElementsIn(Iterable<?> expected) {
+  public Ordered containsAtLeastElementsIn(@Nullable Iterable<?> expected) {
     return check().that(actualList).containsAtLeastElementsIn(expected);
   }
 
@@ -145,7 +162,19 @@ public final class IntStreamSubject extends Subject {
    * on the object returned by this method.
    */
   @CanIgnoreReturnValue
-  public Ordered containsExactly(int... varargs) {
+  public Ordered containsExactly(int @Nullable ... varargs) {
+    /*
+     * We declare a parameter type that lets callers pass a nullable array, even though the
+     * assertion will fail if the array is ever actually null. This can be convenient if the
+     * expected value comes from a nullable source (e.g., a map lookup): Users would otherwise have
+     * to use {@code requireNonNull} or {@code !!} or similar, all to address a compile error
+     * warning about a runtime failure that might never happen—a runtime failure that Truth could
+     * produce a better exception message for, since it could make the message express that the
+     * caller is performing a containsExactly assertion.
+     *
+     * TODO(cpovirk): Actually produce such a better exception message.
+     */
+    checkNotNull(varargs);
     return check().that(actualList).containsExactlyElementsIn(box(varargs));
   }
 
@@ -159,7 +188,7 @@ public final class IntStreamSubject extends Subject {
    * on the object returned by this method.
    */
   @CanIgnoreReturnValue
-  public Ordered containsExactlyElementsIn(Iterable<?> expected) {
+  public Ordered containsExactlyElementsIn(@Nullable Iterable<?> expected) {
     return check().that(actualList).containsExactlyElementsIn(expected);
   }
 
@@ -176,7 +205,7 @@ public final class IntStreamSubject extends Subject {
    * Fails if the subject contains any of the given elements. (Duplicates are irrelevant to this
    * test, which fails if any of the actual elements equal any of the excluded.)
    */
-  public void containsNoneIn(Iterable<?> excluded) {
+  public void containsNoneIn(@Nullable Iterable<?> excluded) {
     check().that(actualList).containsNoneIn(excluded);
   }
 
diff --git a/core/src/main/java/com/google/common/truth/IntegerSubject.java b/core/src/main/java/com/google/common/truth/IntegerSubject.java
index bf144640..99fd82fd 100644
--- a/core/src/main/java/com/google/common/truth/IntegerSubject.java
+++ b/core/src/main/java/com/google/common/truth/IntegerSubject.java
@@ -15,7 +15,12 @@
  */
 package com.google.common.truth;
 
-import org.checkerframework.checker.nullness.qual.Nullable;
+import static com.google.common.base.Preconditions.checkArgument;
+import static com.google.common.base.Preconditions.checkNotNull;
+import static com.google.common.truth.Fact.fact;
+import static com.google.common.truth.MathUtil.equalWithinTolerance;
+
+import org.jspecify.annotations.Nullable;
 
 /**
  * Propositions for {@link Integer} subjects.
@@ -25,12 +30,110 @@ import org.checkerframework.checker.nullness.qual.Nullable;
  * @author Kurt Alfred Kluever
  */
 public class IntegerSubject extends ComparableSubject<Integer> {
+  private final @Nullable Integer actual;
+
   /**
    * Constructor for use by subclasses. If you want to create an instance of this class itself, call
    * {@link Subject#check(String, Object...) check(...)}{@code .that(actual)}.
    */
-  protected IntegerSubject(FailureMetadata metadata, @Nullable Integer integer) {
-    super(metadata, integer);
+  protected IntegerSubject(FailureMetadata metadata, @Nullable Integer actual) {
+    super(metadata, actual);
+    this.actual = actual;
+  }
+
+  /**
+   * A partially specified check about an approximate relationship to a {@code int} subject using a
+   * tolerance.
+   *
+   * @since 1.2
+   */
+  public abstract static class TolerantIntegerComparison {
+
+    // Prevent subclassing outside of this class
+    private TolerantIntegerComparison() {}
+
+    /**
+     * Fails if the subject was expected to be within the tolerance of the given value but was not
+     * <i>or</i> if it was expected <i>not</i> to be within the tolerance but was. The subject and
+     * tolerance are specified earlier in the fluent call chain.
+     */
+    public abstract void of(int expectedInteger);
+
+    /**
+     * @throws UnsupportedOperationException always
+     * @deprecated {@link Object#equals(Object)} is not supported on TolerantIntegerComparison. If
+     *     you meant to compare ints, use {@link #of(int)} instead.
+     */
+    @Deprecated
+    @Override
+    public boolean equals(@Nullable Object o) {
+      throw new UnsupportedOperationException(
+          "If you meant to compare ints, use .of(int) instead.");
+    }
+
+    /**
+     * @throws UnsupportedOperationException always
+     * @deprecated {@link Object#hashCode()} is not supported on TolerantIntegerComparison
+     */
+    @Deprecated
+    @Override
+    public int hashCode() {
+      throw new UnsupportedOperationException("Subject.hashCode() is not supported.");
+    }
+  }
+
+  /**
+   * Prepares for a check that the subject is a number within the given tolerance of an expected
+   * value that will be provided in the next call in the fluent chain.
+   *
+   * @param tolerance an inclusive upper bound on the difference between the subject and object
+   *     allowed by the check, which must be a non-negative value.
+   * @since 1.2
+   */
+  public TolerantIntegerComparison isWithin(int tolerance) {
+    return new TolerantIntegerComparison() {
+      @Override
+      public void of(int expected) {
+        Integer actual = IntegerSubject.this.actual;
+        checkNotNull(
+            actual, "actual value cannot be null. tolerance=%s expected=%s", tolerance, expected);
+        checkTolerance(tolerance);
+
+        if (!equalWithinTolerance(actual, expected, tolerance)) {
+          failWithoutActual(
+              fact("expected", Integer.toString(expected)),
+              butWas(),
+              fact("outside tolerance", Integer.toString(tolerance)));
+        }
+      }
+    };
+  }
+
+  /**
+   * Prepares for a check that the subject is a number not within the given tolerance of an expected
+   * value that will be provided in the next call in the fluent chain.
+   *
+   * @param tolerance an exclusive lower bound on the difference between the subject and object
+   *     allowed by the check, which must be a non-negative value.
+   * @since 1.2
+   */
+  public TolerantIntegerComparison isNotWithin(int tolerance) {
+    return new TolerantIntegerComparison() {
+      @Override
+      public void of(int expected) {
+        Integer actual = IntegerSubject.this.actual;
+        checkNotNull(
+            actual, "actual value cannot be null. tolerance=%s expected=%s", tolerance, expected);
+        checkTolerance(tolerance);
+
+        if (equalWithinTolerance(actual, expected, tolerance)) {
+          failWithoutActual(
+              fact("expected not to be", Integer.toString(expected)),
+              butWas(),
+              fact("within tolerance", Integer.toString(tolerance)));
+        }
+      }
+    };
   }
 
   /**
@@ -41,4 +144,9 @@ public class IntegerSubject extends ComparableSubject<Integer> {
   public final void isEquivalentAccordingToCompareTo(@Nullable Integer other) {
     super.isEquivalentAccordingToCompareTo(other);
   }
+
+  /** Ensures that the given tolerance is a non-negative value. */
+  private static void checkTolerance(int tolerance) {
+    checkArgument(tolerance >= 0, "tolerance (%s) cannot be negative", tolerance);
+  }
 }
diff --git a/core/src/main/java/com/google/common/truth/IterableSubject.java b/core/src/main/java/com/google/common/truth/IterableSubject.java
index bdafca93..b982014b 100644
--- a/core/src/main/java/com/google/common/truth/IterableSubject.java
+++ b/core/src/main/java/com/google/common/truth/IterableSubject.java
@@ -27,6 +27,7 @@ import static com.google.common.truth.IterableSubject.ElementFactGrouping.ALL_IN
 import static com.google.common.truth.IterableSubject.ElementFactGrouping.FACT_PER_ELEMENT;
 import static com.google.common.truth.SubjectUtils.accumulate;
 import static com.google.common.truth.SubjectUtils.annotateEmptyStrings;
+import static com.google.common.truth.SubjectUtils.asList;
 import static com.google.common.truth.SubjectUtils.countDuplicates;
 import static com.google.common.truth.SubjectUtils.countDuplicatesAndAddTypeInfo;
 import static com.google.common.truth.SubjectUtils.countDuplicatesAndMaybeAddTypeInfoReturnObject;
@@ -36,7 +37,6 @@ import static com.google.common.truth.SubjectUtils.iterableToCollection;
 import static com.google.common.truth.SubjectUtils.iterableToList;
 import static com.google.common.truth.SubjectUtils.objectToTypeName;
 import static com.google.common.truth.SubjectUtils.retainMatchingToString;
-import static java.util.Arrays.asList;
 
 import com.google.common.base.Function;
 import com.google.common.base.Objects;
@@ -67,7 +67,7 @@ import java.util.LinkedHashMap;
 import java.util.List;
 import java.util.Map;
 import java.util.Set;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * Propositions for {@link Iterable} subjects.
@@ -97,7 +97,15 @@ public class IterableSubject extends Subject {
    * {@link Subject#check(String, Object...) check(...)}{@code .that(actual)}.
    */
   protected IterableSubject(FailureMetadata metadata, @Nullable Iterable<?> iterable) {
-    super(metadata, iterable);
+    this(metadata, iterable, null);
+  }
+
+  /** Constructor for use by package-private callers. */
+  IterableSubject(
+      FailureMetadata metadata,
+      @Nullable Iterable<?> iterable,
+      @Nullable String typeDescriptionOverride) {
+    super(metadata, iterable, typeDescriptionOverride);
     this.actual = iterable;
   }
 
@@ -105,7 +113,8 @@ public class IterableSubject extends Subject {
   protected String actualCustomStringRepresentation() {
     if (actual != null) {
       // Check the value of iterable.toString() against the default Object.toString() implementation
-      // so we can avoid things like "com.google.common.graph.Traverser$GraphTraverser$1@5e316c74"
+      // so that we can avoid things like
+      // "com.google.common.graph.Traverser$GraphTraverser$1@5e316c74"
       String objectToString =
           actual.getClass().getName() + '@' + Integer.toHexString(System.identityHashCode(actual));
       if (actual.toString().equals(objectToString)) {
@@ -241,12 +250,12 @@ public class IterableSubject extends Subject {
    * fails.
    */
   @SuppressWarnings("AvoidObjectArrays")
-  public final void containsAnyIn(Object[] expected) {
+  public final void containsAnyIn(@Nullable Object[] expected) {
     containsAnyIn(asList(expected));
   }
 
   /**
-   * Checks that the actual iterable contains at least all of the expected elements or fails. If an
+   * Checks that the actual iterable contains at least all the expected elements or fails. If an
    * element appears more than once in the expected elements to this call then it must appear at
    * least that number of times in the actual elements.
    *
@@ -263,7 +272,7 @@ public class IterableSubject extends Subject {
   }
 
   /**
-   * Checks that the actual iterable contains at least all of the expected elements or fails. If an
+   * Checks that the actual iterable contains at least all the expected elements or fails. If an
    * element appears more than once in the expected elements then it must appear at least that
    * number of times in the actual elements.
    *
@@ -272,7 +281,7 @@ public class IterableSubject extends Subject {
    * within the actual elements, but they are not required to be consecutive.
    */
   @CanIgnoreReturnValue
-  public final Ordered containsAtLeastElementsIn(Iterable<?> expectedIterable) {
+  public final Ordered containsAtLeastElementsIn(@Nullable Iterable<?> expectedIterable) {
     List<?> actual = Lists.newLinkedList(checkNotNull(this.actual));
     Collection<?> expected = iterableToCollection(expectedIterable);
 
@@ -323,7 +332,7 @@ public class IterableSubject extends Subject {
   }
 
   /**
-   * Checks that the actual iterable contains at least all of the expected elements or fails. If an
+   * Checks that the actual iterable contains at least all the expected elements or fails. If an
    * element appears more than once in the expected elements then it must appear at least that
    * number of times in the actual elements.
    *
@@ -333,7 +342,7 @@ public class IterableSubject extends Subject {
    */
   @CanIgnoreReturnValue
   @SuppressWarnings("AvoidObjectArrays")
-  public final Ordered containsAtLeastElementsIn(Object[] expected) {
+  public final Ordered containsAtLeastElementsIn(@Nullable Object[] expected) {
     return containsAtLeastElementsIn(asList(expected));
   }
 
@@ -701,7 +710,7 @@ public class IterableSubject extends Subject {
   }
 
   /**
-   * Checks that a actual iterable contains none of the excluded objects or fails. (Duplicates are
+   * Checks that an actual iterable contains none of the excluded objects or fails. (Duplicates are
    * irrelevant to this test, which fails if any of the actual elements equal any of the excluded.)
    */
   public final void containsNoneOf(
@@ -716,8 +725,9 @@ public class IterableSubject extends Subject {
    * iterable or fails. (Duplicates are irrelevant to this test, which fails if any of the actual
    * elements equal any of the excluded.)
    */
-  public final void containsNoneIn(Iterable<?> excluded) {
+  public final void containsNoneIn(@Nullable Iterable<?> excluded) {
     Collection<?> actual = iterableToCollection(checkNotNull(this.actual));
+    checkNotNull(excluded); // TODO(cpovirk): Produce a better exception message.
     List<@Nullable Object> present = new ArrayList<>();
     for (Object item : Sets.newLinkedHashSet(excluded)) {
       if (actual.contains(item)) {
@@ -940,7 +950,7 @@ public class IterableSubject extends Subject {
    *
    * @since 1.1
    */
-  public <T> UsingCorrespondence<T, T> formattingDiffsUsing(
+  public <T extends @Nullable Object> UsingCorrespondence<T, T> formattingDiffsUsing(
       DiffFormatter<? super T, ? super T> formatter) {
     return comparingElementsUsing(Correspondence.<T>equality().formattingDiffsUsing(formatter));
   }
@@ -1033,7 +1043,7 @@ public class IterableSubject extends Subject {
      *
      * <p>On assertions where it makes sense to do so, the elements are paired as follows: they are
      * keyed by {@code keyFunction}, and if an unexpected element and a missing element have the
-     * same non-null key then the they are paired up. (Elements with null keys are not paired.) The
+     * same non-null key then they are paired up. (Elements with null keys are not paired.) The
      * failure message will show paired elements together, and a diff will be shown if the {@link
      * Correspondence#formatDiff} method returns non-null.
      *
@@ -1075,8 +1085,8 @@ public class IterableSubject extends Subject {
      * <p>On assertions where it makes sense to do so, the elements are paired as follows: the
      * unexpected elements are keyed by {@code actualKeyFunction}, the missing elements are keyed by
      * {@code expectedKeyFunction}, and if an unexpected element and a missing element have the same
-     * non-null key then the they are paired up. (Elements with null keys are not paired.) The
-     * failure message will show paired elements together, and a diff will be shown if the {@link
+     * non-null key then they are paired up. (Elements with null keys are not paired.) The failure
+     * message will show paired elements together, and a diff will be shown if the {@link
      * Correspondence#formatDiff} method returns non-null.
      *
      * <p>The expected elements given in the assertion should be uniquely keyed by {@code
@@ -1551,8 +1561,8 @@ public class IterableSubject extends Subject {
     }
 
     /**
-     * Checks that the subject contains elements that corresponds to all of the expected elements,
-     * i.e. that there is a 1:1 mapping between any subset of the actual elements and the expected
+     * Checks that the subject contains elements that correspond to all the expected elements, i.e.
+     * that there is a 1:1 mapping between any subset of the actual elements and the expected
      * elements where each pair of elements correspond.
      *
      * <p>To also test that the contents appear in the given order, make a call to {@code inOrder()}
@@ -1566,8 +1576,8 @@ public class IterableSubject extends Subject {
     }
 
     /**
-     * Checks that the subject contains elements that corresponds to all of the expected elements,
-     * i.e. that there is a 1:1 mapping between any subset of the actual elements and the expected
+     * Checks that the subject contains elements that correspond to all the expected elements, i.e.
+     * that there is a 1:1 mapping between any subset of the actual elements and the expected
      * elements where each pair of elements correspond.
      *
      * <p>To also test that the contents appear in the given order, make a call to {@code inOrder()}
@@ -1632,8 +1642,8 @@ public class IterableSubject extends Subject {
     }
 
     /**
-     * Checks that the subject contains elements that corresponds to all of the expected elements,
-     * i.e. that there is a 1:1 mapping between any subset of the actual elements and the expected
+     * Checks that the subject contains elements that correspond to all the expected elements, i.e.
+     * that there is a 1:1 mapping between any subset of the actual elements and the expected
      * elements where each pair of elements correspond.
      *
      * <p>To also test that the contents appear in the given order, make a call to {@code inOrder()}
diff --git a/core/src/main/java/com/google/common/truth/LazyMessage.java b/core/src/main/java/com/google/common/truth/LazyMessage.java
index 2e6861a7..ef6d6cd4 100644
--- a/core/src/main/java/com/google/common/truth/LazyMessage.java
+++ b/core/src/main/java/com/google/common/truth/LazyMessage.java
@@ -20,7 +20,7 @@ import static com.google.common.base.Strings.lenientFormat;
 
 import com.google.common.annotations.VisibleForTesting;
 import com.google.common.collect.ImmutableList;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 final class LazyMessage {
   private final String format;
diff --git a/extensions/java8/src/main/java/com/google/common/truth/LongStreamSubject.java b/core/src/main/java/com/google/common/truth/LongStreamSubject.java
similarity index 79%
rename from extensions/java8/src/main/java/com/google/common/truth/LongStreamSubject.java
rename to core/src/main/java/com/google/common/truth/LongStreamSubject.java
index 0a5c2255..2c8f3a04 100644
--- a/extensions/java8/src/main/java/com/google/common/truth/LongStreamSubject.java
+++ b/core/src/main/java/com/google/common/truth/LongStreamSubject.java
@@ -15,6 +15,7 @@
  */
 package com.google.common.truth;
 
+import static com.google.common.base.Preconditions.checkNotNull;
 import static java.util.stream.Collectors.toCollection;
 
 import com.google.errorprone.annotations.CanIgnoreReturnValue;
@@ -23,7 +24,7 @@ import java.util.Comparator;
 import java.util.List;
 import java.util.stream.LongStream;
 import java.util.stream.Stream;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * Propositions for {@link LongStream} subjects.
@@ -39,13 +40,18 @@ import org.checkerframework.checker.nullness.qual.Nullable;
  * stream before asserting on it.
  *
  * @author Kurt Alfred Kluever
+ * @since 1.3.0 (previously part of {@code truth-java8-extension})
  */
-@SuppressWarnings("deprecation") // TODO(b/134064106): design an alternative to no-arg check()
+@SuppressWarnings({
+  "deprecation", // TODO(b/134064106): design an alternative to no-arg check()
+  "Java7ApiChecker", // used only from APIs with Java 8 in their signatures
+})
+@IgnoreJRERequirement
 public final class LongStreamSubject extends Subject {
 
-  private final List<?> actualList;
+  private final @Nullable List<?> actualList;
 
-  private LongStreamSubject(FailureMetadata failureMetadata, @Nullable LongStream stream) {
+  LongStreamSubject(FailureMetadata failureMetadata, @Nullable LongStream stream) {
     super(failureMetadata, stream);
     this.actualList =
         (stream == null) ? null : stream.boxed().collect(toCollection(ArrayList::new));
@@ -56,6 +62,17 @@ public final class LongStreamSubject extends Subject {
     return String.valueOf(actualList);
   }
 
+  /**
+   * Obsolete factory instance. This factory was previously necessary for assertions like {@code
+   * assertWithMessage(...).about(longStreams()).that(stream)....}. Now, you can perform assertions
+   * like that without the {@code about(...)} call.
+   *
+   * @deprecated Instead of {@code about(longStreams()).that(...)}, use just {@code that(...)}.
+   *     Similarly, instead of {@code assertAbout(longStreams()).that(...)}, use just {@code
+   *     assertThat(...)}.
+   */
+  @Deprecated
+  @SuppressWarnings("InlineMeSuggester") // We want users to remove the surrounding call entirely.
   public static Factory<LongStreamSubject, LongStream> longStreams() {
     return LongStreamSubject::new;
   }
@@ -102,7 +119,7 @@ public final class LongStreamSubject extends Subject {
   }
 
   /** Fails if the subject does not contain at least one of the given elements. */
-  public void containsAnyIn(Iterable<?> expected) {
+  public void containsAnyIn(@Nullable Iterable<?> expected) {
     check().that(actualList).containsAnyIn(expected);
   }
 
@@ -131,7 +148,7 @@ public final class LongStreamSubject extends Subject {
    * within the actual elements, but they are not required to be consecutive.
    */
   @CanIgnoreReturnValue
-  public Ordered containsAtLeastElementsIn(Iterable<?> expected) {
+  public Ordered containsAtLeastElementsIn(@Nullable Iterable<?> expected) {
     return check().that(actualList).containsAtLeastElementsIn(expected);
   }
 
@@ -145,7 +162,19 @@ public final class LongStreamSubject extends Subject {
    * on the object returned by this method.
    */
   @CanIgnoreReturnValue
-  public Ordered containsExactly(long... varargs) {
+  public Ordered containsExactly(long @Nullable ... varargs) {
+    /*
+     * We declare a parameter type that lets callers pass a nullable array, even though the
+     * assertion will fail if the array is ever actually null. This can be convenient if the
+     * expected value comes from a nullable source (e.g., a map lookup): Users would otherwise have
+     * to use {@code requireNonNull} or {@code !!} or similar, all to address a compile error
+     * warning about a runtime failure that might never happen—a runtime failure that Truth could
+     * produce a better exception message for, since it could make the message express that the
+     * caller is performing a containsExactly assertion.
+     *
+     * TODO(cpovirk): Actually produce such a better exception message.
+     */
+    checkNotNull(varargs);
     return check().that(actualList).containsExactlyElementsIn(box(varargs));
   }
 
@@ -159,7 +188,7 @@ public final class LongStreamSubject extends Subject {
    * on the object returned by this method.
    */
   @CanIgnoreReturnValue
-  public Ordered containsExactlyElementsIn(Iterable<?> expected) {
+  public Ordered containsExactlyElementsIn(@Nullable Iterable<?> expected) {
     return check().that(actualList).containsExactlyElementsIn(expected);
   }
 
@@ -176,7 +205,7 @@ public final class LongStreamSubject extends Subject {
    * Fails if the subject contains any of the given elements. (Duplicates are irrelevant to this
    * test, which fails if any of the actual elements equal any of the excluded.)
    */
-  public void containsNoneIn(Iterable<?> excluded) {
+  public void containsNoneIn(@Nullable Iterable<?> excluded) {
     check().that(actualList).containsNoneIn(excluded);
   }
 
diff --git a/core/src/main/java/com/google/common/truth/LongSubject.java b/core/src/main/java/com/google/common/truth/LongSubject.java
index d56de24d..746d3cc6 100644
--- a/core/src/main/java/com/google/common/truth/LongSubject.java
+++ b/core/src/main/java/com/google/common/truth/LongSubject.java
@@ -15,7 +15,12 @@
  */
 package com.google.common.truth;
 
-import org.checkerframework.checker.nullness.qual.Nullable;
+import static com.google.common.base.Preconditions.checkArgument;
+import static com.google.common.base.Preconditions.checkNotNull;
+import static com.google.common.truth.Fact.fact;
+import static com.google.common.truth.MathUtil.equalWithinTolerance;
+
+import org.jspecify.annotations.Nullable;
 
 /**
  * Propositions for {@code long} subjects.
@@ -25,12 +30,111 @@ import org.checkerframework.checker.nullness.qual.Nullable;
  * @author Kurt Alfred Kluever
  */
 public class LongSubject extends ComparableSubject<Long> {
+
+  private final @Nullable Long actual;
+
   /**
    * Constructor for use by subclasses. If you want to create an instance of this class itself, call
    * {@link Subject#check(String, Object...) check(...)}{@code .that(actual)}.
    */
   protected LongSubject(FailureMetadata metadata, @Nullable Long actual) {
     super(metadata, actual);
+    this.actual = actual;
+  }
+
+  /**
+   * A partially specified check about an approximate relationship to a {@code long} subject using a
+   * tolerance.
+   *
+   * @since 1.2
+   */
+  public abstract static class TolerantLongComparison {
+
+    // Prevent subclassing outside of this class
+    private TolerantLongComparison() {}
+
+    /**
+     * Fails if the subject was expected to be within the tolerance of the given value but was not
+     * <i>or</i> if it was expected <i>not</i> to be within the tolerance but was. The subject and
+     * tolerance are specified earlier in the fluent call chain.
+     */
+    public abstract void of(long expectedLong);
+
+    /**
+     * @throws UnsupportedOperationException always
+     * @deprecated {@link Object#equals(Object)} is not supported on TolerantLongComparison. If you
+     *     meant to compare longs, use {@link #of(long)} instead.
+     */
+    @Deprecated
+    @Override
+    public boolean equals(@Nullable Object o) {
+      throw new UnsupportedOperationException(
+          "If you meant to compare longs, use .of(long) instead.");
+    }
+
+    /**
+     * @throws UnsupportedOperationException always
+     * @deprecated {@link Object#hashCode()} is not supported on TolerantLongComparison
+     */
+    @Deprecated
+    @Override
+    public int hashCode() {
+      throw new UnsupportedOperationException("Subject.hashCode() is not supported.");
+    }
+  }
+
+  /**
+   * Prepares for a check that the subject is a number within the given tolerance of an expected
+   * value that will be provided in the next call in the fluent chain.
+   *
+   * @param tolerance an inclusive upper bound on the difference between the subject and object
+   *     allowed by the check, which must be a non-negative value.
+   * @since 1.2
+   */
+  public TolerantLongComparison isWithin(long tolerance) {
+    return new TolerantLongComparison() {
+      @Override
+      public void of(long expected) {
+        Long actual = LongSubject.this.actual;
+        checkNotNull(
+            actual, "actual value cannot be null. tolerance=%s expected=%s", tolerance, expected);
+        checkTolerance(tolerance);
+
+        if (!equalWithinTolerance(actual, expected, tolerance)) {
+          failWithoutActual(
+              fact("expected", Long.toString(expected)),
+              butWas(),
+              fact("outside tolerance", Long.toString(tolerance)));
+        }
+      }
+    };
+  }
+
+  /**
+   * Prepares for a check that the subject is a number not within the given tolerance of an expected
+   * value that will be provided in the next call in the fluent chain.
+   *
+   * @param tolerance an exclusive lower bound on the difference between the subject and object
+   *     allowed by the check, which must be a non-negative value.
+   * @since 1.2
+   */
+  public TolerantLongComparison isNotWithin(long tolerance) {
+    return new TolerantLongComparison() {
+      @Override
+      public void of(long expected) {
+        Long actual = LongSubject.this.actual;
+        checkNotNull(
+            actual, "actual value cannot be null. tolerance=%s expected=%s", tolerance, expected);
+        checkTolerance(tolerance);
+
+        if (equalWithinTolerance(actual, expected, tolerance)) {
+          failWithoutActual(
+              fact("expected not to be", Long.toString(expected)),
+              butWas(),
+              fact("within tolerance", Long.toString(tolerance)));
+        }
+      }
+    };
   }
 
   /**
@@ -42,6 +146,11 @@ public class LongSubject extends ComparableSubject<Long> {
     super.isEquivalentAccordingToCompareTo(other);
   }
 
+  /** Ensures that the given tolerance is a non-negative value. */
+  private static void checkTolerance(long tolerance) {
+    checkArgument(tolerance >= 0, "tolerance (%s) cannot be negative", tolerance);
+  }
+
   /**
    * Checks that the subject is greater than {@code other}.
    *
diff --git a/core/src/main/java/com/google/common/truth/MapSubject.java b/core/src/main/java/com/google/common/truth/MapSubject.java
index a74f1752..2b0e496a 100644
--- a/core/src/main/java/com/google/common/truth/MapSubject.java
+++ b/core/src/main/java/com/google/common/truth/MapSubject.java
@@ -42,7 +42,7 @@ import java.util.LinkedHashSet;
 import java.util.List;
 import java.util.Map;
 import java.util.Set;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * Propositions for {@link Map} subjects.
@@ -526,7 +526,7 @@ public class MapSubject extends Subject {
    *
    * @since 1.1
    */
-  public final <V> UsingCorrespondence<V, V> formattingDiffsUsing(
+  public final <V extends @Nullable Object> UsingCorrespondence<V, V> formattingDiffsUsing(
       DiffFormatter<? super V, ? super V> formatter) {
     return comparingValuesUsing(Correspondence.<V>equality().formattingDiffsUsing(formatter));
   }
@@ -638,7 +638,11 @@ public class MapSubject extends Subject {
               ImmutableList.<Fact>builder()
                   .add(fact("expected not to contain", immutableEntry(excludedKey, excludedValue)))
                   .addAll(correspondence.describeForMapValues())
-                  .add(fact("but contained", immutableEntry(excludedKey, actualValue)))
+                  .add(
+                      fact(
+                          "but contained",
+                          Maps.<@Nullable Object, @Nullable A>immutableEntry(
+                              excludedKey, actualValue)))
                   .add(fact("full map", actualCustomStringRepresentationForPackageMembersToCall()))
                   .addAll(exceptions.describeAsAdditionalInfo())
                   .build());
diff --git a/core/src/main/java/com/google/common/truth/MathUtil.java b/core/src/main/java/com/google/common/truth/MathUtil.java
index 791ac4d7..2fb44da5 100644
--- a/core/src/main/java/com/google/common/truth/MathUtil.java
+++ b/core/src/main/java/com/google/common/truth/MathUtil.java
@@ -16,12 +16,46 @@
 
 package com.google.common.truth;
 
+import static java.lang.Math.subtractExact;
+
 import com.google.common.primitives.Doubles;
 
 /** Math utilities to be shared by numeric subjects. */
 final class MathUtil {
   private MathUtil() {}
 
+  /**
+   * Returns true iff {@code left} and {@code right} are values within {@code tolerance} of each
+   * other.
+   */
+  /* package */ static boolean equalWithinTolerance(long left, long right, long tolerance) {
+    try {
+      // subtractExact is always desugared.
+      @SuppressWarnings("Java7ApiChecker")
+      long absDiff = Math.abs(subtractExact(left, right));
+      return 0 <= absDiff && absDiff <= Math.abs(tolerance);
+    } catch (ArithmeticException e) {
+      // The numbers are so far apart their difference isn't even a long.
+      return false;
+    }
+  }
+
+  /**
+   * Returns true iff {@code left} and {@code right} are values within {@code tolerance} of each
+   * other.
+   */
+  /* package */ static boolean equalWithinTolerance(int left, int right, int tolerance) {
+    try {
+      // subtractExact is always desugared.
+      @SuppressWarnings("Java7ApiChecker")
+      int absDiff = Math.abs(subtractExact(left, right));
+      return 0 <= absDiff && absDiff <= Math.abs(tolerance);
+    } catch (ArithmeticException e) {
+      // The numbers are so far apart their difference isn't even a int.
+      return false;
+    }
+  }
+
   /**
    * Returns true iff {@code left} and {@code right} are finite values within {@code tolerance} of
    * each other. Note that both this method and {@link #notEqualWithinTolerance} returns false if
diff --git a/core/src/main/java/com/google/common/truth/MultimapSubject.java b/core/src/main/java/com/google/common/truth/MultimapSubject.java
index 4a02216f..96cef441 100644
--- a/core/src/main/java/com/google/common/truth/MultimapSubject.java
+++ b/core/src/main/java/com/google/common/truth/MultimapSubject.java
@@ -46,7 +46,7 @@ import java.util.LinkedHashSet;
 import java.util.List;
 import java.util.Map;
 import java.util.Set;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * Propositions for {@link Multimap} subjects.
diff --git a/core/src/main/java/com/google/common/truth/MultisetSubject.java b/core/src/main/java/com/google/common/truth/MultisetSubject.java
index 9e8a6315..264b30c8 100644
--- a/core/src/main/java/com/google/common/truth/MultisetSubject.java
+++ b/core/src/main/java/com/google/common/truth/MultisetSubject.java
@@ -19,7 +19,7 @@ import static com.google.common.base.Preconditions.checkArgument;
 import static com.google.common.base.Preconditions.checkNotNull;
 
 import com.google.common.collect.Multiset;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * Propositions for {@link Multiset} subjects.
@@ -31,7 +31,7 @@ public final class MultisetSubject extends IterableSubject {
   private final @Nullable Multiset<?> actual;
 
   MultisetSubject(FailureMetadata metadata, @Nullable Multiset<?> multiset) {
-    super(metadata, multiset);
+    super(metadata, multiset, /* typeDescriptionOverride= */ "multiset");
     this.actual = multiset;
   }
 
diff --git a/core/src/main/java/com/google/common/truth/ObjectArraySubject.java b/core/src/main/java/com/google/common/truth/ObjectArraySubject.java
index daa287d2..712fc30a 100644
--- a/core/src/main/java/com/google/common/truth/ObjectArraySubject.java
+++ b/core/src/main/java/com/google/common/truth/ObjectArraySubject.java
@@ -18,7 +18,7 @@ package com.google.common.truth;
 import static com.google.common.base.Preconditions.checkNotNull;
 
 import java.util.Arrays;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * A Subject for {@code Object[]} and more generically {@code T[]}.
@@ -26,10 +26,9 @@ import org.checkerframework.checker.nullness.qual.Nullable;
  * @author Christian Gruber
  */
 public final class ObjectArraySubject<T extends @Nullable Object> extends AbstractArraySubject {
-  private final @Nullable T @Nullable [] actual;
+  private final T @Nullable [] actual;
 
-  ObjectArraySubject(
-      FailureMetadata metadata, @Nullable T @Nullable [] o, @Nullable String typeDescription) {
+  ObjectArraySubject(FailureMetadata metadata, T @Nullable [] o, @Nullable String typeDescription) {
     super(metadata, o, typeDescription);
     this.actual = o;
   }
diff --git a/extensions/java8/src/main/java/com/google/common/truth/OptionalDoubleSubject.java b/core/src/main/java/com/google/common/truth/OptionalDoubleSubject.java
similarity index 75%
rename from extensions/java8/src/main/java/com/google/common/truth/OptionalDoubleSubject.java
rename to core/src/main/java/com/google/common/truth/OptionalDoubleSubject.java
index 4a9aa5f8..96403a4b 100644
--- a/extensions/java8/src/main/java/com/google/common/truth/OptionalDoubleSubject.java
+++ b/core/src/main/java/com/google/common/truth/OptionalDoubleSubject.java
@@ -19,16 +19,19 @@ import static com.google.common.truth.Fact.fact;
 import static com.google.common.truth.Fact.simpleFact;
 
 import java.util.OptionalDouble;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * Propositions for Java 8 {@link OptionalDouble} subjects.
  *
  * @author Ben Douglass
+ * @since 1.3.0 (previously part of {@code truth-java8-extension})
  */
+@SuppressWarnings("Java7ApiChecker") // used only from APIs with Java 8 in their signatures
+@IgnoreJRERequirement
 public final class OptionalDoubleSubject extends Subject {
 
-  private final OptionalDouble actual;
+  private final @Nullable OptionalDouble actual;
 
   OptionalDoubleSubject(
       FailureMetadata failureMetadata,
@@ -78,7 +81,18 @@ public final class OptionalDoubleSubject extends Subject {
     }
   }
 
-  public static Subject.Factory<OptionalDoubleSubject, OptionalDouble> optionalDoubles() {
+  /**
+   * Obsolete factory instance. This factory was previously necessary for assertions like {@code
+   * assertWithMessage(...).about(optionalDoubles()).that(optional)....}. Now, you can perform
+   * assertions like that without the {@code about(...)} call.
+   *
+   * @deprecated Instead of {@code about(optionalDoubles()).that(...)}, use just {@code that(...)}.
+   *     Similarly, instead of {@code assertAbout(optionalDoubles()).that(...)}, use just {@code
+   *     assertThat(...)}.
+   */
+  @Deprecated
+  @SuppressWarnings("InlineMeSuggester") // We want users to remove the surrounding call entirely.
+  public static Factory<OptionalDoubleSubject, OptionalDouble> optionalDoubles() {
     return (metadata, subject) -> new OptionalDoubleSubject(metadata, subject, "optionalDouble");
   }
 }
diff --git a/extensions/java8/src/main/java/com/google/common/truth/OptionalIntSubject.java b/core/src/main/java/com/google/common/truth/OptionalIntSubject.java
similarity index 72%
rename from extensions/java8/src/main/java/com/google/common/truth/OptionalIntSubject.java
rename to core/src/main/java/com/google/common/truth/OptionalIntSubject.java
index 957594f7..37921f8b 100644
--- a/extensions/java8/src/main/java/com/google/common/truth/OptionalIntSubject.java
+++ b/core/src/main/java/com/google/common/truth/OptionalIntSubject.java
@@ -19,15 +19,18 @@ import static com.google.common.truth.Fact.fact;
 import static com.google.common.truth.Fact.simpleFact;
 
 import java.util.OptionalInt;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * Propositions for Java 8 {@link OptionalInt} subjects.
  *
  * @author Ben Douglass
+ * @since 1.3.0 (previously part of {@code truth-java8-extension})
  */
+@SuppressWarnings("Java7ApiChecker") // used only from APIs with Java 8 in their signatures
+@IgnoreJRERequirement
 public final class OptionalIntSubject extends Subject {
-  private final OptionalInt actual;
+  private final @Nullable OptionalInt actual;
 
   OptionalIntSubject(
       FailureMetadata failureMetadata,
@@ -71,7 +74,18 @@ public final class OptionalIntSubject extends Subject {
     }
   }
 
-  public static Subject.Factory<OptionalIntSubject, OptionalInt> optionalInts() {
+  /**
+   * Obsolete factory instance. This factory was previously necessary for assertions like {@code
+   * assertWithMessage(...).about(optionalInts()).that(optional)....}. Now, you can perform
+   * assertions like that without the {@code about(...)} call.
+   *
+   * @deprecated Instead of {@code about(optionalInts()).that(...)}, use just {@code that(...)}.
+   *     Similarly, instead of {@code assertAbout(optionalInts()).that(...)}, use just {@code
+   *     assertThat(...)}.
+   */
+  @Deprecated
+  @SuppressWarnings("InlineMeSuggester") // We want users to remove the surrounding call entirely.
+  public static Factory<OptionalIntSubject, OptionalInt> optionalInts() {
     return (metadata, subject) -> new OptionalIntSubject(metadata, subject, "optionalInt");
   }
 }
diff --git a/extensions/java8/src/main/java/com/google/common/truth/OptionalLongSubject.java b/core/src/main/java/com/google/common/truth/OptionalLongSubject.java
similarity index 72%
rename from extensions/java8/src/main/java/com/google/common/truth/OptionalLongSubject.java
rename to core/src/main/java/com/google/common/truth/OptionalLongSubject.java
index 9b57b9a4..237706b6 100644
--- a/extensions/java8/src/main/java/com/google/common/truth/OptionalLongSubject.java
+++ b/core/src/main/java/com/google/common/truth/OptionalLongSubject.java
@@ -19,15 +19,18 @@ import static com.google.common.truth.Fact.fact;
 import static com.google.common.truth.Fact.simpleFact;
 
 import java.util.OptionalLong;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * Propositions for Java 8 {@link OptionalLong} subjects.
  *
  * @author Ben Douglass
+ * @since 1.3.0 (previously part of {@code truth-java8-extension})
  */
+@SuppressWarnings("Java7ApiChecker") // used only from APIs with Java 8 in their signatures
+@IgnoreJRERequirement
 public final class OptionalLongSubject extends Subject {
-  private final OptionalLong actual;
+  private final @Nullable OptionalLong actual;
 
   OptionalLongSubject(
       FailureMetadata failureMetadata,
@@ -71,7 +74,18 @@ public final class OptionalLongSubject extends Subject {
     }
   }
 
-  public static Subject.Factory<OptionalLongSubject, OptionalLong> optionalLongs() {
+  /**
+   * Obsolete factory instance. This factory was previously necessary for assertions like {@code
+   * assertWithMessage(...).about(optionalLongs()).that(optional)....}. Now, you can perform
+   * assertions like that without the {@code about(...)} call.
+   *
+   * @deprecated Instead of {@code about(optionalLongs()).that(...)}, use just {@code that(...)}.
+   *     Similarly, instead of {@code assertAbout(optionalLongs()).that(...)}, use just {@code
+   *     assertThat(...)}.
+   */
+  @Deprecated
+  @SuppressWarnings("InlineMeSuggester") // We want users to remove the surrounding call entirely.
+  public static Factory<OptionalLongSubject, OptionalLong> optionalLongs() {
     return (metadata, subject) -> new OptionalLongSubject(metadata, subject, "optionalLong");
   }
 }
diff --git a/extensions/java8/src/main/java/com/google/common/truth/OptionalSubject.java b/core/src/main/java/com/google/common/truth/OptionalSubject.java
similarity index 72%
rename from extensions/java8/src/main/java/com/google/common/truth/OptionalSubject.java
rename to core/src/main/java/com/google/common/truth/OptionalSubject.java
index 65ca4dae..24688804 100644
--- a/extensions/java8/src/main/java/com/google/common/truth/OptionalSubject.java
+++ b/core/src/main/java/com/google/common/truth/OptionalSubject.java
@@ -19,19 +19,24 @@ import static com.google.common.truth.Fact.fact;
 import static com.google.common.truth.Fact.simpleFact;
 
 import java.util.Optional;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * Propositions for Java 8 {@link Optional} subjects.
  *
  * @author Christian Gruber
+ * @since 1.3.0 (previously part of {@code truth-java8-extension})
  */
+@SuppressWarnings("Java7ApiChecker") // used only from APIs with Java 8 in their signatures
+@IgnoreJRERequirement
 public final class OptionalSubject extends Subject {
+  @SuppressWarnings("NullableOptional") // Truth always accepts nulls, no matter the type
   private final @Nullable Optional<?> actual;
 
   OptionalSubject(
       FailureMetadata failureMetadata,
-      @Nullable Optional<?> subject,
+      @SuppressWarnings("NullableOptional") // Truth always accepts nulls, no matter the type
+          @Nullable Optional<?> subject,
       @Nullable String typeDescription) {
     super(failureMetadata, subject, typeDescription);
     this.actual = subject;
@@ -81,7 +86,18 @@ public final class OptionalSubject extends Subject {
     }
   }
 
-  public static Subject.Factory<OptionalSubject, Optional<?>> optionals() {
+  /**
+   * Obsolete factory instance. This factory was previously necessary for assertions like {@code
+   * assertWithMessage(...).about(paths()).that(path)....}. Now, you can perform assertions like
+   * that without the {@code about(...)} call.
+   *
+   * @deprecated Instead of {@code about(optionals()).that(...)}, use just {@code that(...)}.
+   *     Similarly, instead of {@code assertAbout(optionals()).that(...)}, use just {@code
+   *     assertThat(...)}.
+   */
+  @Deprecated
+  @SuppressWarnings("InlineMeSuggester") // We want users to remove the surrounding call entirely.
+  public static Factory<OptionalSubject, Optional<?>> optionals() {
     return (metadata, subject) -> new OptionalSubject(metadata, subject, "optional");
   }
 }
diff --git a/core/src/main/java/com/google/common/truth/PathSubject.java b/core/src/main/java/com/google/common/truth/PathSubject.java
new file mode 100644
index 00000000..5957779d
--- /dev/null
+++ b/core/src/main/java/com/google/common/truth/PathSubject.java
@@ -0,0 +1,49 @@
+/*
+ * Copyright (c) 2017 Google, Inc.
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ * http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+package com.google.common.truth;
+
+import com.google.common.annotations.GwtIncompatible;
+import com.google.j2objc.annotations.J2ObjCIncompatible;
+import java.nio.file.Path;
+import org.jspecify.annotations.Nullable;
+
+/**
+ * Assertions for {@link Path} instances.
+ *
+ * @since 1.3.0 (previously part of {@code truth-java8-extension})
+ */
+@GwtIncompatible
+@J2ObjCIncompatible
+@J2ktIncompatible
+public final class PathSubject extends Subject {
+  PathSubject(FailureMetadata failureMetadata, @Nullable Path actual) {
+    super(failureMetadata, actual);
+  }
+
+  /**
+   * Obsolete factory instance. This factory was previously necessary for assertions like {@code
+   * assertWithMessage(...).about(intStreams()).that(stream)....}. Now, you can perform assertions
+   * like that without the {@code about(...)} call.
+   *
+   * @deprecated Instead of {@code about(paths()).that(...)}, use just {@code that(...)}. Similarly,
+   *     instead of {@code assertAbout(paths()).that(...)}, use just {@code assertThat(...)}.
+   */
+  @Deprecated
+  @SuppressWarnings("InlineMeSuggester") // We want users to remove the surrounding call entirely.
+  public static Factory<PathSubject, Path> paths() {
+    return PathSubject::new;
+  }
+}
diff --git a/core/src/main/java/com/google/common/truth/Platform.java b/core/src/main/java/com/google/common/truth/Platform.java
index bc4301a2..f3e9059f 100644
--- a/core/src/main/java/com/google/common/truth/Platform.java
+++ b/core/src/main/java/com/google/common/truth/Platform.java
@@ -32,7 +32,7 @@ import java.lang.reflect.InvocationTargetException;
 import java.lang.reflect.Method;
 import java.util.List;
 import java.util.regex.Pattern;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 import org.junit.ComparisonFailure;
 import org.junit.rules.TestRule;
 
@@ -56,7 +56,7 @@ final class Platform {
   }
 
   /**
-   * Returns an array containing all of the exceptions that were suppressed to deliver the given
+   * Returns an array containing all the exceptions that were suppressed to deliver the given
    * exception. If suppressed exceptions are not supported (pre-Java 1.7), an empty array will be
    * returned.
    */
@@ -85,8 +85,6 @@ final class Platform {
    * the value passed to {@code assertThat} or {@code that}, as distinct from any later actual
    * values produced by chaining calls like {@code hasMessageThat}.
    */
-  // Checker complains that first invoke argument is null.
-  @SuppressWarnings("argument.type.incompatible")
   static @Nullable String inferDescription() {
     if (isInferDescriptionDisabled()) {
       return null;
@@ -167,20 +165,12 @@ final class Platform {
   abstract static class PlatformComparisonFailure extends ComparisonFailure {
     private final String message;
 
-    /** Separate cause field, in case initCause() fails. */
-    private final @Nullable Throwable cause;
-
     PlatformComparisonFailure(
         String message, String expected, String actual, @Nullable Throwable cause) {
       super(message, expected, actual);
       this.message = message;
-      this.cause = cause;
 
-      try {
-        initCause(cause);
-      } catch (IllegalStateException alreadyInitializedBecauseOfHarmonyBug) {
-        // See Truth.SimpleAssertionError.
-      }
+      initCause(cause);
     }
 
     @Override
@@ -188,12 +178,6 @@ final class Platform {
       return message;
     }
 
-    @Override
-    @SuppressWarnings("UnsynchronizedOverridesSynchronized")
-    public final @Nullable Throwable getCause() {
-      return cause;
-    }
-
     // To avoid printing the class name before the message.
     // TODO(cpovirk): Write a test that fails without this. Ditto for SimpleAssertionError.
     @Override
@@ -364,4 +348,11 @@ final class Platform {
               throw newLinkageError(e);
             }
           });
+
+  static boolean classMetadataUnsupported() {
+    // https://github.com/google/truth/issues/198
+    // TODO(cpovirk): Consider whether to remove instanceof tests under GWT entirely.
+    // TODO(cpovirk): Run more Truth tests under GWT, and add tests for this.
+    return false;
+  }
 }
diff --git a/core/src/main/java/com/google/common/truth/PrimitiveBooleanArraySubject.java b/core/src/main/java/com/google/common/truth/PrimitiveBooleanArraySubject.java
index 33ff6d89..925ea571 100644
--- a/core/src/main/java/com/google/common/truth/PrimitiveBooleanArraySubject.java
+++ b/core/src/main/java/com/google/common/truth/PrimitiveBooleanArraySubject.java
@@ -18,7 +18,7 @@ package com.google.common.truth;
 import static com.google.common.base.Preconditions.checkNotNull;
 
 import com.google.common.primitives.Booleans;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * A Subject for {@code boolean[]}.
diff --git a/core/src/main/java/com/google/common/truth/PrimitiveByteArraySubject.java b/core/src/main/java/com/google/common/truth/PrimitiveByteArraySubject.java
index f8169ca4..1f649c6e 100644
--- a/core/src/main/java/com/google/common/truth/PrimitiveByteArraySubject.java
+++ b/core/src/main/java/com/google/common/truth/PrimitiveByteArraySubject.java
@@ -18,7 +18,7 @@ package com.google.common.truth;
 import static com.google.common.base.Preconditions.checkNotNull;
 
 import com.google.common.primitives.Bytes;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * A Subject for {@code byte[]}.
diff --git a/core/src/main/java/com/google/common/truth/PrimitiveCharArraySubject.java b/core/src/main/java/com/google/common/truth/PrimitiveCharArraySubject.java
index 79e6f12e..0ee8c057 100644
--- a/core/src/main/java/com/google/common/truth/PrimitiveCharArraySubject.java
+++ b/core/src/main/java/com/google/common/truth/PrimitiveCharArraySubject.java
@@ -18,7 +18,7 @@ package com.google.common.truth;
 import static com.google.common.base.Preconditions.checkNotNull;
 
 import com.google.common.primitives.Chars;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * A Subject for {@code char[]}.
diff --git a/core/src/main/java/com/google/common/truth/PrimitiveDoubleArraySubject.java b/core/src/main/java/com/google/common/truth/PrimitiveDoubleArraySubject.java
index 6fdb2750..ce22539f 100644
--- a/core/src/main/java/com/google/common/truth/PrimitiveDoubleArraySubject.java
+++ b/core/src/main/java/com/google/common/truth/PrimitiveDoubleArraySubject.java
@@ -23,7 +23,7 @@ import static com.google.common.truth.Correspondence.tolerance;
 import com.google.common.primitives.Doubles;
 import com.google.errorprone.annotations.CanIgnoreReturnValue;
 import java.util.Arrays;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * A Subject for {@code double[]}.
diff --git a/core/src/main/java/com/google/common/truth/PrimitiveFloatArraySubject.java b/core/src/main/java/com/google/common/truth/PrimitiveFloatArraySubject.java
index 339a4d5b..9ce5a289 100644
--- a/core/src/main/java/com/google/common/truth/PrimitiveFloatArraySubject.java
+++ b/core/src/main/java/com/google/common/truth/PrimitiveFloatArraySubject.java
@@ -23,7 +23,7 @@ import static com.google.common.truth.Correspondence.tolerance;
 import com.google.common.primitives.Floats;
 import com.google.errorprone.annotations.CanIgnoreReturnValue;
 import java.util.Arrays;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * A Subject for {@code float[]}.
diff --git a/core/src/main/java/com/google/common/truth/PrimitiveIntArraySubject.java b/core/src/main/java/com/google/common/truth/PrimitiveIntArraySubject.java
index b6c64634..b8ee605a 100644
--- a/core/src/main/java/com/google/common/truth/PrimitiveIntArraySubject.java
+++ b/core/src/main/java/com/google/common/truth/PrimitiveIntArraySubject.java
@@ -18,7 +18,7 @@ package com.google.common.truth;
 import static com.google.common.base.Preconditions.checkNotNull;
 
 import com.google.common.primitives.Ints;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * A Subject for {@code int[]}.
diff --git a/core/src/main/java/com/google/common/truth/PrimitiveLongArraySubject.java b/core/src/main/java/com/google/common/truth/PrimitiveLongArraySubject.java
index 07441086..8b34ddd4 100644
--- a/core/src/main/java/com/google/common/truth/PrimitiveLongArraySubject.java
+++ b/core/src/main/java/com/google/common/truth/PrimitiveLongArraySubject.java
@@ -18,7 +18,7 @@ package com.google.common.truth;
 import static com.google.common.base.Preconditions.checkNotNull;
 
 import com.google.common.primitives.Longs;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * A Subject for {@code long[]}.
diff --git a/core/src/main/java/com/google/common/truth/PrimitiveShortArraySubject.java b/core/src/main/java/com/google/common/truth/PrimitiveShortArraySubject.java
index dcefab47..147eeb10 100644
--- a/core/src/main/java/com/google/common/truth/PrimitiveShortArraySubject.java
+++ b/core/src/main/java/com/google/common/truth/PrimitiveShortArraySubject.java
@@ -18,7 +18,7 @@ package com.google.common.truth;
 import static com.google.common.base.Preconditions.checkNotNull;
 
 import com.google.common.primitives.Shorts;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * A Subject for {@code short[]}.
diff --git a/core/src/main/java/com/google/common/truth/SimpleSubjectBuilder.java b/core/src/main/java/com/google/common/truth/SimpleSubjectBuilder.java
index 80caa364..1bb1b2c5 100644
--- a/core/src/main/java/com/google/common/truth/SimpleSubjectBuilder.java
+++ b/core/src/main/java/com/google/common/truth/SimpleSubjectBuilder.java
@@ -17,7 +17,7 @@ package com.google.common.truth;
 
 import static com.google.common.base.Preconditions.checkNotNull;
 
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * In a fluent assertion chain, exposes the most common {@code that} method, which accepts a value
diff --git a/core/src/main/java/com/google/common/truth/StackTraceCleaner.java b/core/src/main/java/com/google/common/truth/StackTraceCleaner.java
index 5efc43a0..6284a016 100644
--- a/core/src/main/java/com/google/common/truth/StackTraceCleaner.java
+++ b/core/src/main/java/com/google/common/truth/StackTraceCleaner.java
@@ -27,7 +27,7 @@ import java.util.ArrayList;
 import java.util.List;
 import java.util.ListIterator;
 import java.util.Set;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /** Utility that cleans stack traces to remove noise from common frameworks. */
 @GwtIncompatible
diff --git a/core/src/main/java/com/google/common/truth/StandardSubjectBuilder.java b/core/src/main/java/com/google/common/truth/StandardSubjectBuilder.java
index f41fb486..288662af 100644
--- a/core/src/main/java/com/google/common/truth/StandardSubjectBuilder.java
+++ b/core/src/main/java/com/google/common/truth/StandardSubjectBuilder.java
@@ -18,14 +18,22 @@ package com.google.common.truth;
 import static com.google.common.base.Preconditions.checkNotNull;
 
 import com.google.common.annotations.GwtIncompatible;
-import com.google.common.base.Optional;
 import com.google.common.collect.ImmutableList;
 import com.google.common.collect.Multimap;
 import com.google.common.collect.Multiset;
 import com.google.common.collect.Table;
+import com.google.j2objc.annotations.J2ObjCIncompatible;
 import java.math.BigDecimal;
+import java.nio.file.Path;
 import java.util.Map;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import java.util.Optional;
+import java.util.OptionalDouble;
+import java.util.OptionalInt;
+import java.util.OptionalLong;
+import java.util.stream.IntStream;
+import java.util.stream.LongStream;
+import java.util.stream.Stream;
+import org.jspecify.annotations.Nullable;
 
 /**
  * In a fluent assertion chain, an object with which you can do any of the following:
@@ -113,7 +121,7 @@ public class StandardSubjectBuilder {
   }
 
   @SuppressWarnings("AvoidObjectArrays")
-  public final <T> ObjectArraySubject<T> that(@Nullable T @Nullable [] actual) {
+  public final <T extends @Nullable Object> ObjectArraySubject<T> that(T @Nullable [] actual) {
     return new ObjectArraySubject<>(metadata(), actual, "array");
   }
 
@@ -149,7 +157,7 @@ public class StandardSubjectBuilder {
     return new PrimitiveDoubleArraySubject(metadata(), actual, "array");
   }
 
-  public final GuavaOptionalSubject that(@Nullable Optional<?> actual) {
+  public final GuavaOptionalSubject that(com.google.common.base.@Nullable Optional<?> actual) {
     return new GuavaOptionalSubject(metadata(), actual, "optional");
   }
 
@@ -169,6 +177,89 @@ public class StandardSubjectBuilder {
     return new TableSubject(metadata(), actual);
   }
 
+  /**
+   * @since 1.3.0 (with access to {@link OptionalSubject} previously part of {@code
+   *     truth-java8-extension})
+   */
+  @SuppressWarnings({
+    "Java7ApiChecker", // no more dangerous that wherever the user got the Optional
+    "NullableOptional", // Truth always accepts nulls, no matter the type
+  })
+  public final OptionalSubject that(@Nullable Optional<?> actual) {
+    return new OptionalSubject(metadata(), actual, "optional");
+  }
+
+  /**
+   * @since 1.4.0 (with access to {@link OptionalIntSubject} previously part of {@code
+   *     truth-java8-extension})
+   */
+  @SuppressWarnings(
+      "Java7ApiChecker") // no more dangerous that wherever the user got the OptionalInt
+  public final OptionalIntSubject that(@Nullable OptionalInt actual) {
+    return new OptionalIntSubject(metadata(), actual, "optionalInt");
+  }
+
+  /**
+   * @since 1.4.0 (with access to {@link OptionalLongSubject} previously part of {@code
+   *     truth-java8-extension})
+   */
+  @SuppressWarnings(
+      "Java7ApiChecker") // no more dangerous that wherever the user got the OptionalLong
+  public final OptionalLongSubject that(@Nullable OptionalLong actual) {
+    return new OptionalLongSubject(metadata(), actual, "optionalLong");
+  }
+
+  /**
+   * @since 1.4.0 (with access to {@link OptionalDoubleSubject} previously part of {@code
+   *     truth-java8-extension})
+   */
+  @SuppressWarnings(
+      "Java7ApiChecker") // no more dangerous that wherever the user got the OptionalDouble
+  public final OptionalDoubleSubject that(@Nullable OptionalDouble actual) {
+    return new OptionalDoubleSubject(metadata(), actual, "optionalDouble");
+  }
+
+  /**
+   * @since 1.3.0 (with access to {@link StreamSubject} previously part of {@code
+   *     truth-java8-extension})
+   */
+  @SuppressWarnings("Java7ApiChecker") // no more dangerous that wherever the user got the Stream
+  public final StreamSubject that(@Nullable Stream<?> actual) {
+    return new StreamSubject(metadata(), actual);
+  }
+
+  /**
+   * @since 1.4.0 (with access to {@link IntStreamSubject} previously part of {@code
+   *     truth-java8-extension})
+   */
+  @SuppressWarnings("Java7ApiChecker") // no more dangerous that wherever the user got the IntStream
+  public final IntStreamSubject that(@Nullable IntStream actual) {
+    return new IntStreamSubject(metadata(), actual);
+  }
+
+  /**
+   * @since 1.4.0 (with access to {@link LongStreamSubject} previously part of {@code
+   *     truth-java8-extension})
+   */
+  @SuppressWarnings(
+      "Java7ApiChecker") // no more dangerous that wherever the user got the LongStream
+  public final LongStreamSubject that(@Nullable LongStream actual) {
+    return new LongStreamSubject(metadata(), actual);
+  }
+
+  // TODO(b/64757353): Add support for DoubleStream?
+
+  /**
+   * @since 1.4.0 (with access to {@link PathSubject} previously part of {@code
+   *     truth-java8-extension})
+   */
+  @GwtIncompatible
+  @J2ObjCIncompatible
+  @J2ktIncompatible
+  public final PathSubject that(@Nullable Path actual) {
+    return new PathSubject(metadata(), actual);
+  }
+
   /**
    * Returns a new instance that will output the given message before the main failure message. If
    * this method is called multiple times, the messages will appear in the order that they were
diff --git a/core/src/main/java/com/google/common/truth/StreamSubject.java b/core/src/main/java/com/google/common/truth/StreamSubject.java
new file mode 100644
index 00000000..0140d6dc
--- /dev/null
+++ b/core/src/main/java/com/google/common/truth/StreamSubject.java
@@ -0,0 +1,366 @@
+/*
+ * Copyright (c) 2016 Google, Inc.
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ * http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+package com.google.common.truth;
+
+import static com.google.common.base.Suppliers.memoize;
+import static com.google.common.truth.Fact.fact;
+import static java.util.stream.Collectors.toCollection;
+
+import com.google.common.base.Supplier;
+import com.google.errorprone.annotations.CanIgnoreReturnValue;
+import java.util.ArrayList;
+import java.util.Comparator;
+import java.util.List;
+import java.util.stream.Stream;
+import org.jspecify.annotations.Nullable;
+
+/**
+ * Propositions for {@link Stream} subjects.
+ *
+ * <p><b>Note:</b> When you perform an assertion based on the <i>contents</i> of the stream, or when
+ * <i>any</i> assertion <i>fails</i>, the wrapped stream will be drained immediately into a private
+ * collection to provide more readable failure messages. This consumes the stream. Take care if you
+ * intend to leave the stream un-consumed or if the stream is <i>very</i> large or infinite.
+ *
+ * <p>If you intend to make multiple assertions on the contents of the same stream, you should
+ * instead first collect the contents of the stream into a collection and then assert directly on
+ * that.
+ *
+ * <p>For very large or infinite streams you may want to first {@linkplain Stream#limit limit} the
+ * stream before asserting on it.
+ *
+ * @author Kurt Alfred Kluever
+ * @since 1.3.0 (previously part of {@code truth-java8-extension})
+ */
+@SuppressWarnings("Java7ApiChecker") // used only from APIs with Java 8 in their signatures
+@IgnoreJRERequirement
+public final class StreamSubject extends Subject {
+  // Storing the FailureMetadata instance is not usually advisable.
+  private final FailureMetadata metadata;
+  private final @Nullable Stream<?> actual;
+  private final Supplier<@Nullable List<?>> listSupplier;
+
+  StreamSubject(
+      FailureMetadata metadata,
+      @Nullable Stream<?> actual,
+      Supplier<@Nullable List<?>> listSupplier) {
+    super(metadata, actual);
+    this.metadata = metadata;
+    this.actual = actual;
+    this.listSupplier = listSupplier;
+  }
+
+  StreamSubject(FailureMetadata metadata, @Nullable Stream<?> actual) {
+    /*
+     * As discussed in the Javadoc, we're a *little* accommodating of streams that have already been
+     * collected (or are outright broken, like some mocks), and we avoid collecting the contents
+     * until we want them. So, if you want to perform an assertion like
+     * `assertThat(previousStream).isSameInstanceAs(firstStream)`, we'll let you do that, even if
+     * you've already collected the stream. This way, `assertThat(Stream)` works as well as
+     * `assertThat(Object)` for streams, following the usual rules of overloading. (This would also
+     * help if we someday make `assertThat(Object)` automatically delegate to `assertThat(Stream)`
+     * when passed a `Stream`.)
+     */
+    this(metadata, actual, memoize(listCollector(actual)));
+  }
+
+  @Override
+  protected String actualCustomStringRepresentation() {
+    List<?> asList;
+    try {
+      asList = listSupplier.get();
+    } catch (IllegalStateException e) {
+      return "Stream that has already been operated upon or closed: " + actual();
+    }
+    return String.valueOf(asList);
+  }
+
+  /**
+   * Obsolete factory instance. This factory was previously necessary for assertions like {@code
+   * assertWithMessage(...).about(streams()).that(stream)....}. Now, you can perform assertions like
+   * that without the {@code about(...)} call.
+   *
+   * @deprecated Instead of {@code about(streams()).that(...)}, use just {@code that(...)}.
+   *     Similarly, instead of {@code assertAbout(streams()).that(...)}, use just {@code
+   *     assertThat(...)}.
+   */
+  @Deprecated
+  @SuppressWarnings("InlineMeSuggester") // We want users to remove the surrounding call entirely.
+  public static Factory<StreamSubject, Stream<?>> streams() {
+    return StreamSubject::new;
+  }
+
+  /** Fails if the subject is not empty. */
+  public void isEmpty() {
+    checkThatContentsList().isEmpty();
+  }
+
+  /** Fails if the subject is empty. */
+  public void isNotEmpty() {
+    checkThatContentsList().isNotEmpty();
+  }
+
+  /**
+   * Fails if the subject does not have the given size.
+   *
+   * <p>If you'd like to check that your stream contains more than {@link Integer#MAX_VALUE}
+   * elements, use {@code assertThat(stream.count()).isEqualTo(...)}.
+   */
+  public void hasSize(int expectedSize) {
+    checkThatContentsList().hasSize(expectedSize);
+  }
+
+  /** Fails if the subject does not contain the given element. */
+  public void contains(@Nullable Object element) {
+    checkThatContentsList().contains(element);
+  }
+
+  /** Fails if the subject contains the given element. */
+  public void doesNotContain(@Nullable Object element) {
+    checkThatContentsList().doesNotContain(element);
+  }
+
+  /** Fails if the subject contains duplicate elements. */
+  public void containsNoDuplicates() {
+    checkThatContentsList().containsNoDuplicates();
+  }
+
+  /** Fails if the subject does not contain at least one of the given elements. */
+  public void containsAnyOf(
+      @Nullable Object first, @Nullable Object second, @Nullable Object @Nullable ... rest) {
+    checkThatContentsList().containsAnyOf(first, second, rest);
+  }
+
+  /** Fails if the subject does not contain at least one of the given elements. */
+  public void containsAnyIn(@Nullable Iterable<?> expected) {
+    checkThatContentsList().containsAnyIn(expected);
+  }
+
+  /**
+   * Fails if the subject does not contain all of the given elements. If an element appears more
+   * than once in the given elements, then it must appear at least that number of times in the
+   * actual elements.
+   *
+   * <p>To also test that the contents appear in the given order, make a call to {@code inOrder()}
+   * on the object returned by this method. The expected elements must appear in the given order
+   * within the actual elements, but they are not required to be consecutive.
+   */
+  @CanIgnoreReturnValue
+  public Ordered containsAtLeast(
+      @Nullable Object first, @Nullable Object second, @Nullable Object @Nullable ... rest) {
+    return checkThatContentsList().containsAtLeast(first, second, rest);
+  }
+
+  /**
+   * Fails if the subject does not contain all of the given elements. If an element appears more
+   * than once in the given elements, then it must appear at least that number of times in the
+   * actual elements.
+   *
+   * <p>To also test that the contents appear in the given order, make a call to {@code inOrder()}
+   * on the object returned by this method. The expected elements must appear in the given order
+   * within the actual elements, but they are not required to be consecutive.
+   */
+  @CanIgnoreReturnValue
+  public Ordered containsAtLeastElementsIn(@Nullable Iterable<?> expected) {
+    return checkThatContentsList().containsAtLeastElementsIn(expected);
+  }
+
+  // TODO(cpovirk): Add array overload of contains*ElementsIn methods? Also for int and long stream.
+
+  /**
+   * Fails if the subject does not contain exactly the given elements.
+   *
+   * <p>Multiplicity is respected. For example, an object duplicated exactly 3 times in the
+   * parameters asserts that the object must likewise be duplicated exactly 3 times in the subject.
+   *
+   * <p>To also test that the contents appear in the given order, make a call to {@code inOrder()}
+   * on the object returned by this method.
+   */
+  @CanIgnoreReturnValue
+  /*
+   * We need to call containsExactly, not containsExactlyElementsIn, to get the handling we want for
+   * containsExactly(null).
+   */
+  @SuppressWarnings("ContainsExactlyVariadic")
+  public Ordered containsExactly(@Nullable Object @Nullable ... varargs) {
+    return checkThatContentsList().containsExactly(varargs);
+  }
+
+  /**
+   * Fails if the subject does not contain exactly the given elements.
+   *
+   * <p>Multiplicity is respected. For example, an object duplicated exactly 3 times in the
+   * parameters asserts that the object must likewise be duplicated exactly 3 times in the subject.
+   *
+   * <p>To also test that the contents appear in the given order, make a call to {@code inOrder()}
+   * on the object returned by this method.
+   */
+  @CanIgnoreReturnValue
+  public Ordered containsExactlyElementsIn(@Nullable Iterable<?> expected) {
+    return checkThatContentsList().containsExactlyElementsIn(expected);
+  }
+
+  /**
+   * Fails if the subject contains any of the given elements. (Duplicates are irrelevant to this
+   * test, which fails if any of the actual elements equal any of the excluded.)
+   */
+  public void containsNoneOf(
+      @Nullable Object first, @Nullable Object second, @Nullable Object @Nullable ... rest) {
+    checkThatContentsList().containsNoneOf(first, second, rest);
+  }
+
+  /**
+   * Fails if the subject contains any of the given elements. (Duplicates are irrelevant to this
+   * test, which fails if any of the actual elements equal any of the excluded.)
+   */
+  public void containsNoneIn(@Nullable Iterable<?> excluded) {
+    checkThatContentsList().containsNoneIn(excluded);
+  }
+
+  /**
+   * Fails if the subject is not strictly ordered, according to the natural ordering of its
+   * elements. Strictly ordered means that each element in the stream is <i>strictly</i> greater
+   * than the element that preceded it.
+   *
+   * @throws ClassCastException if any pair of elements is not mutually Comparable
+   * @throws NullPointerException if any element is null
+   */
+  public void isInStrictOrder() {
+    checkThatContentsList().isInStrictOrder();
+  }
+
+  /**
+   * Fails if the subject is not strictly ordered, according to the given comparator. Strictly
+   * ordered means that each element in the stream is <i>strictly</i> greater than the element that
+   * preceded it.
+   *
+   * @throws ClassCastException if any pair of elements is not mutually Comparable
+   */
+  public void isInStrictOrder(Comparator<?> comparator) {
+    checkThatContentsList().isInStrictOrder(comparator);
+  }
+
+  /**
+   * Fails if the subject is not ordered, according to the natural ordering of its elements. Ordered
+   * means that each element in the stream is greater than or equal to the element that preceded it.
+   *
+   * @throws ClassCastException if any pair of elements is not mutually Comparable
+   * @throws NullPointerException if any element is null
+   */
+  public void isInOrder() {
+    checkThatContentsList().isInOrder();
+  }
+
+  /**
+   * Fails if the subject is not ordered, according to the given comparator. Ordered means that each
+   * element in the stream is greater than or equal to the element that preceded it.
+   *
+   * @throws ClassCastException if any pair of elements is not mutually Comparable
+   */
+  public void isInOrder(Comparator<?> comparator) {
+    checkThatContentsList().isInOrder(comparator);
+  }
+
+  /**
+   * @deprecated {@code streamA.isEqualTo(streamB)} always fails, except when passed the exact same
+   *     stream reference. If you really want to test object identity, you can eliminate this
+   *     deprecation warning by using {@link #isSameInstanceAs}. If you instead want to test the
+   *     contents of the stream, use {@link #containsExactly} or similar methods.
+   */
+  @Override
+  @Deprecated
+  public void isEqualTo(@Nullable Object expected) {
+    /*
+     * We add a warning about stream equality. Doing so is a bit of a pain. (There might be a better
+     * way.)
+     *
+     * Calling Subject constructors directly is not generally advisable. I'm not sure if the
+     * metadata munging we perform is advisable, either....
+     *
+     * We do need to create a StreamSubject (rather than a plain Subject) in order to get our
+     * desired string representation (unless we edit Subject itself to create and expose a
+     * Supplier<List> when given a Stream...). And we have to call a special constructor to avoid
+     * re-collecting the stream.
+     */
+    new StreamSubject(
+            metadata.withMessage(
+                "%s",
+                new Object[] {
+                  "Warning: Stream equality is based on object identity. To compare Stream"
+                      + " contents, use methods like containsExactly."
+                }),
+            actual,
+            listSupplier)
+        .superIsEqualTo(expected);
+  }
+
+  private void superIsEqualTo(@Nullable Object expected) {
+    super.isEqualTo(expected);
+  }
+
+  /**
+   * @deprecated {@code streamA.isNotEqualTo(streamB)} always passes, except when passed the exact
+   *     same stream reference. If you really want to test object identity, you can eliminate this
+   *     deprecation warning by using {@link #isNotSameInstanceAs}. If you instead want to test the
+   *     contents of the stream, collect both streams to lists and perform assertions like {@link
+   *     IterableSubject#isNotEqualTo} on them. In some cases, you may be able to use {@link
+   *     StreamSubject} assertions like {@link #doesNotContain}.
+   */
+  @Override
+  @Deprecated
+  public void isNotEqualTo(@Nullable Object unexpected) {
+    if (actual() == unexpected) {
+      /*
+       * We override the supermethod's message: That method would ask for both
+       * `String.valueOf(stream)` (for `unexpected`) and `actualCustomStringRepresentation()` (for
+       * `actual()`). The two strings are almost certain to differ, since `valueOf` is normally
+       * based on identity and `actualCustomStringRepresentation()` is based on contents. That can
+       * lead to a confusing error message.
+       *
+       * We could include isEqualTo's warning about Stream's identity-based equality here, too. But
+       * it doesn't seem necessary: The people we really want to warn are the people whose
+       * assertions *pass*. And we've already attempted to do that with deprecation.
+       */
+      failWithoutActual(
+          fact("expected not to be", actualCustomStringRepresentationForPackageMembersToCall()));
+      return;
+    }
+    /*
+     * But, if the objects aren't identical, we delegate to the supermethod (which checks equals())
+     * just in case someone has decided to override Stream.equals in a strange way. (I haven't
+     * checked whether this comes up in Google's codebase. I hope that it doesn't.)
+     */
+    super.isNotEqualTo(unexpected);
+  }
+
+  // TODO(user): Do we want to support comparingElementsUsing() on StreamSubject?
+
+  private IterableSubject checkThatContentsList() {
+    /*
+     * Calling Subject constructors directly is usually not advisable: It does not update the
+     * metadata, so the resultant failure message might say (for example) "value of: foo" when it
+     * should say "value of: foo.size()." However, in this specific case, that's exactly what we
+     * want: We're testing the contents of the stream, so we want a "value of" line for the stream,
+     * even though we happen to implement the contents check by delegating to IterableSubject.
+     */
+    return new IterableSubject(
+        metadata, listSupplier.get(), /* typeDescriptionOverride= */ "stream");
+  }
+
+  private static Supplier<@Nullable List<?>> listCollector(@Nullable Stream<?> actual) {
+    return () -> actual == null ? null : actual.collect(toCollection(ArrayList::new));
+  }
+}
diff --git a/core/src/main/java/com/google/common/truth/StringSubject.java b/core/src/main/java/com/google/common/truth/StringSubject.java
index dc5b12f7..8819c921 100644
--- a/core/src/main/java/com/google/common/truth/StringSubject.java
+++ b/core/src/main/java/com/google/common/truth/StringSubject.java
@@ -23,7 +23,7 @@ import static com.google.common.truth.Fact.simpleFact;
 import com.google.common.annotations.GwtIncompatible;
 import java.util.regex.Matcher;
 import java.util.regex.Pattern;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * Propositions for string subjects.
@@ -127,6 +127,11 @@ public class StringSubject extends ComparableSubject<String> {
             fact("expected to match", regex),
             fact("but was", actual),
             simpleFact("Looks like you want to use .isEqualTo() for an exact equality assertion."));
+      } else if (Platform.containsMatch(actual, regex)) {
+        failWithoutActual(
+            fact("expected to match", regex),
+            fact("but was", actual),
+            simpleFact("Did you mean to call containsMatch() instead of match()?"));
       } else {
         failWithActual("expected to match", regex);
       }
@@ -135,7 +140,6 @@ public class StringSubject extends ComparableSubject<String> {
 
   /** Fails if the string does not match the given regex. */
   @GwtIncompatible("java.util.regex.Pattern")
-  @J2ktIncompatible
   public void matches(@Nullable Pattern regex) {
     checkNotNull(regex);
     if (actual == null) {
@@ -148,6 +152,11 @@ public class StringSubject extends ComparableSubject<String> {
             simpleFact(
                 "If you want an exact equality assertion you can escape your regex with"
                     + " Pattern.quote()."));
+      } else if (regex.matcher(actual).find()) {
+        failWithoutActual(
+            fact("expected to match", regex),
+            fact("but was", actual),
+            simpleFact("Did you mean to call containsMatch() instead of match()?"));
       } else {
         failWithActual("expected to match", regex);
       }
@@ -166,7 +175,6 @@ public class StringSubject extends ComparableSubject<String> {
 
   /** Fails if the string matches the given regex. */
   @GwtIncompatible("java.util.regex.Pattern")
-  @J2ktIncompatible
   public void doesNotMatch(@Nullable Pattern regex) {
     checkNotNull(regex);
     if (actual == null) {
@@ -178,7 +186,6 @@ public class StringSubject extends ComparableSubject<String> {
 
   /** Fails if the string does not contain a match on the given regex. */
   @GwtIncompatible("java.util.regex.Pattern")
-  @J2ktIncompatible
   public void containsMatch(@Nullable Pattern regex) {
     checkNotNull(regex);
     if (actual == null) {
@@ -200,7 +207,6 @@ public class StringSubject extends ComparableSubject<String> {
 
   /** Fails if the string contains a match on the given regex. */
   @GwtIncompatible("java.util.regex.Pattern")
-  @J2ktIncompatible
   public void doesNotContainMatch(@Nullable Pattern regex) {
     checkNotNull(regex);
     if (actual == null) {
diff --git a/core/src/main/java/com/google/common/truth/Subject.java b/core/src/main/java/com/google/common/truth/Subject.java
index 94d9e169..08e14bb9 100644
--- a/core/src/main/java/com/google/common/truth/Subject.java
+++ b/core/src/main/java/com/google/common/truth/Subject.java
@@ -53,7 +53,7 @@ import java.lang.reflect.Array;
 import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.List;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * An object that lets you perform checks on the value under test. For example, {@code Subject}
@@ -299,7 +299,7 @@ public class Subject {
       return;
     }
     if (!isInstanceOfType(actual, clazz)) {
-      if (classMetadataUnsupported()) {
+      if (Platform.classMetadataUnsupported()) {
         throw new UnsupportedOperationException(
             actualCustomStringRepresentation()
                 + ", an instance of "
@@ -320,7 +320,7 @@ public class Subject {
     if (clazz == null) {
       throw new NullPointerException("clazz");
     }
-    if (classMetadataUnsupported()) {
+    if (Platform.classMetadataUnsupported()) {
       throw new UnsupportedOperationException(
           "isNotInstanceOf is not supported under -XdisableClassMetadata");
     }
@@ -1185,13 +1185,6 @@ public class Subject {
     return UPPER_CAMEL.to(LOWER_CAMEL, actualClass);
   }
 
-  private static boolean classMetadataUnsupported() {
-    // https://github.com/google/truth/issues/198
-    // TODO(cpovirk): Consider whether to remove instanceof tests under GWT entirely.
-    // TODO(cpovirk): Run more Truth tests under GWT, and add tests for this.
-    return String.class.getSuperclass() == null;
-  }
-
   private void doFail(ImmutableList<Fact> facts) {
     checkNotNull(metadata).fail(facts);
   }
diff --git a/core/src/main/java/com/google/common/truth/SubjectUtils.java b/core/src/main/java/com/google/common/truth/SubjectUtils.java
index ae55c066..84cf1f6e 100644
--- a/core/src/main/java/com/google/common/truth/SubjectUtils.java
+++ b/core/src/main/java/com/google/common/truth/SubjectUtils.java
@@ -15,6 +15,7 @@
  */
 package com.google.common.truth;
 
+import static com.google.common.base.Preconditions.checkNotNull;
 import static com.google.common.base.Strings.lenientFormat;
 import static com.google.common.collect.Iterables.isEmpty;
 import static com.google.common.collect.Iterables.transform;
@@ -36,7 +37,7 @@ import java.util.Arrays;
 import java.util.Collection;
 import java.util.List;
 import java.util.Map;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * Utility methods used in {@code Subject} implementors.
@@ -59,7 +60,7 @@ final class SubjectUtils {
     if (rest == null) {
       items.add((T) null);
     } else {
-      items.addAll(Arrays.asList(rest));
+      items.addAll(asList(rest));
     }
     return items;
   }
@@ -341,7 +342,10 @@ final class SubjectUtils {
     return itemsWithTypeInfo;
   }
 
-  static <T extends @Nullable Object> Collection<T> iterableToCollection(Iterable<T> iterable) {
+  static <T extends @Nullable Object> Collection<T> iterableToCollection(
+      @Nullable Iterable<T> iterable) {
+    // TODO(cpovirk): For null inputs, produce a better exception message (ideally in callers).
+    checkNotNull(iterable);
     if (iterable instanceof Collection) {
       // Should be safe to assume that any Iterable implementing Collection isn't a one-shot
       // iterable, right? I sure hope so.
@@ -401,4 +405,9 @@ final class SubjectUtils {
   static <E> ImmutableList<E> sandwich(E first, E[] array, E last) {
     return new ImmutableList.Builder<E>().add(first).add(array).add(last).build();
   }
+
+  @SuppressWarnings("nullness") // TODO: b/316358623 - Remove suppression after fixing checker
+  static <E extends @Nullable Object> List<E> asList(E... a) {
+    return Arrays.asList(a);
+  }
 }
diff --git a/core/src/main/java/com/google/common/truth/TableSubject.java b/core/src/main/java/com/google/common/truth/TableSubject.java
index 9ab8f5c3..61e2c2f0 100644
--- a/core/src/main/java/com/google/common/truth/TableSubject.java
+++ b/core/src/main/java/com/google/common/truth/TableSubject.java
@@ -23,7 +23,7 @@ import static com.google.common.truth.Fact.simpleFact;
 import com.google.common.collect.Table;
 import com.google.common.collect.Table.Cell;
 import com.google.common.collect.Tables;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * Propositions for {@link Table} subjects.
diff --git a/core/src/main/java/com/google/common/truth/ThrowableSubject.java b/core/src/main/java/com/google/common/truth/ThrowableSubject.java
index e85476d2..7a03a67a 100644
--- a/core/src/main/java/com/google/common/truth/ThrowableSubject.java
+++ b/core/src/main/java/com/google/common/truth/ThrowableSubject.java
@@ -17,11 +17,25 @@ package com.google.common.truth;
 
 import static com.google.common.base.Preconditions.checkNotNull;
 
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * Propositions for {@link Throwable} subjects.
  *
+ * <p>Truth does not provide its own support for calling a method and automatically catching an
+ * expected exception, only for asserting on the exception after it has been caught. To catch the
+ * exception, we suggest {@link org.junit.Assert#assertThrows(Class,
+ * org.junit.function.ThrowingRunnable) assertThrows} (JUnit), <a
+ * href="https://kotlinlang.org/api/latest/kotlin.test/kotlin.test/assert-fails-with.html">{@code
+ * assertFailsWith}</a> ({@code kotlin.test}), or similar functionality from your testing library of
+ * choice.
+ *
+ * <pre>
+ * InvocationTargetException expected =
+ *     assertThrows(InvocationTargetException.class, () -> method.invoke(null));
+ * assertThat(expected).hasCauseThat().isInstanceOf(IOException.class);
+ * </pre>
+ *
  * @author Kurt Alfred Kluever
  */
 public class ThrowableSubject extends Subject {
diff --git a/core/src/main/java/com/google/common/truth/Truth.java b/core/src/main/java/com/google/common/truth/Truth.java
index 1afbccaa..407f6df6 100644
--- a/core/src/main/java/com/google/common/truth/Truth.java
+++ b/core/src/main/java/com/google/common/truth/Truth.java
@@ -18,13 +18,21 @@ package com.google.common.truth;
 import static com.google.common.base.Preconditions.checkNotNull;
 
 import com.google.common.annotations.GwtIncompatible;
-import com.google.common.base.Optional;
 import com.google.common.collect.Multimap;
 import com.google.common.collect.Multiset;
 import com.google.common.collect.Table;
+import com.google.j2objc.annotations.J2ObjCIncompatible;
 import java.math.BigDecimal;
+import java.nio.file.Path;
 import java.util.Map;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import java.util.Optional;
+import java.util.OptionalDouble;
+import java.util.OptionalInt;
+import java.util.OptionalLong;
+import java.util.stream.IntStream;
+import java.util.stream.LongStream;
+import java.util.stream.Stream;
+import org.jspecify.annotations.Nullable;
 
 /**
  * The primary entry point for <a href="https://truth.dev">Truth</a>, a library for fluent test
@@ -160,6 +168,23 @@ public final class Truth {
     return assert_().that(actual);
   }
 
+  /**
+   * Begins an assertion about a {@link Throwable}.
+   *
+   * <p>Truth does not provide its own support for calling a method and automatically catching an
+   * expected exception, only for asserting on the exception after it has been caught. To catch the
+   * exception, we suggest {@link org.junit.Assert#assertThrows(Class,
+   * org.junit.function.ThrowingRunnable) assertThrows} (JUnit), <a
+   * href="https://kotlinlang.org/api/latest/kotlin.test/kotlin.test/assert-fails-with.html">{@code
+   * assertFailsWith}</a> ({@code kotlin.test}), or similar functionality from your testing library
+   * of choice.
+   *
+   * <pre>
+   * InvocationTargetException expected =
+   *     assertThrows(InvocationTargetException.class, () -> method.invoke(null));
+   * assertThat(expected).hasCauseThat().isInstanceOf(IOException.class);
+   * </pre>
+   */
   public static ThrowableSubject assertThat(@Nullable Throwable actual) {
     return assert_().that(actual);
   }
@@ -193,7 +218,8 @@ public final class Truth {
   }
 
   @SuppressWarnings("AvoidObjectArrays")
-  public static <T> ObjectArraySubject<T> assertThat(@Nullable T @Nullable [] actual) {
+  public static <T extends @Nullable Object> ObjectArraySubject<T> assertThat(
+      T @Nullable [] actual) {
     return assert_().that(actual);
   }
 
@@ -229,7 +255,8 @@ public final class Truth {
     return assert_().that(actual);
   }
 
-  public static GuavaOptionalSubject assertThat(@Nullable Optional<?> actual) {
+  public static GuavaOptionalSubject assertThat(
+      com.google.common.base.@Nullable Optional<?> actual) {
     return assert_().that(actual);
   }
 
@@ -250,39 +277,85 @@ public final class Truth {
   }
 
   /**
-   * An {@code AssertionError} that (a) always supports a cause, even under old versions of Android
-   * and (b) omits "java.lang.AssertionError:" from the beginning of its toString() representation.
+   * @since 1.3.0 (present in {@link Truth8} since before 1.0)
+   */
+  @SuppressWarnings({
+    "Java7ApiChecker", // no more dangerous than wherever the user got the Optional
+    "NullableOptional", // Truth always accepts nulls, no matter the type
+  })
+  public static OptionalSubject assertThat(@Nullable Optional<?> actual) {
+    return assert_().that(actual);
+  }
+
+  /**
+   * @since 1.3.0 (present in {@link Truth8} since before 1.0)
+   */
+  @SuppressWarnings("Java7ApiChecker") // no more dangerous than wherever the user got the Stream
+  public static OptionalIntSubject assertThat(@Nullable OptionalInt actual) {
+    return assert_().that(actual);
+  }
+
+  /**
+   * @since 1.4.0 (present in {@link Truth8} since before 1.0)
+   */
+  @SuppressWarnings("Java7ApiChecker") // no more dangerous than wherever the user got the Stream
+  public static OptionalLongSubject assertThat(@Nullable OptionalLong actual) {
+    return assert_().that(actual);
+  }
+
+  /**
+   * @since 1.4.0 (present in {@link Truth8} since before 1.0)
+   */
+  @SuppressWarnings("Java7ApiChecker") // no more dangerous than wherever the user got the Stream
+  public static OptionalDoubleSubject assertThat(@Nullable OptionalDouble actual) {
+    return assert_().that(actual);
+  }
+
+  /**
+   * @since 1.4.0 (present in {@link Truth8} since before 1.0)
+   */
+  @SuppressWarnings("Java7ApiChecker") // no more dangerous than wherever the user got the Stream
+  public static StreamSubject assertThat(@Nullable Stream<?> actual) {
+    return assert_().that(actual);
+  }
+
+  /**
+   * @since 1.4.0 (present in {@link Truth8} since before 1.0)
+   */
+  @SuppressWarnings("Java7ApiChecker") // no more dangerous than wherever the user got the Stream
+  public static IntStreamSubject assertThat(@Nullable IntStream actual) {
+    return assert_().that(actual);
+  }
+
+  /**
+   * @since 1.4.0 (present in {@link Truth8} since before 1.0)
+   */
+  @SuppressWarnings("Java7ApiChecker") // no more dangerous than wherever the user got the Stream
+  public static LongStreamSubject assertThat(@Nullable LongStream actual) {
+    return assert_().that(actual);
+  }
+
+  // TODO(b/64757353): Add support for DoubleStream?
+
+  /**
+   * @since 1.4.0 (present in {@link Truth8} since before 1.0)
+   */
+  @GwtIncompatible
+  @J2ObjCIncompatible
+  @J2ktIncompatible
+  public static PathSubject assertThat(@Nullable Path actual) {
+    return assert_().that(actual);
+  }
+
+  /**
+   * An {@code AssertionError} that omits "java.lang.AssertionError:" from the beginning of its
+   * toString() representation.
    */
   // TODO(cpovirk): Consider eliminating this, adding its functionality to AssertionErrorWithFacts?
   @SuppressWarnings("OverrideThrowableToString") // We intentionally replace the normal format.
   static final class SimpleAssertionError extends AssertionError {
-    /** Separate cause field, in case initCause() fails. */
-    private final @Nullable Throwable cause;
-
     private SimpleAssertionError(String message, @Nullable Throwable cause) {
-      super(checkNotNull(message));
-      this.cause = cause;
-
-      try {
-        initCause(cause);
-      } catch (IllegalStateException alreadyInitializedBecauseOfHarmonyBug) {
-        /*
-         * initCause() throws under old versions of Android:
-         * https://issuetracker.google.com/issues/36945167
-         *
-         * Yes, it's *nice* if initCause() works:
-         *
-         * - It ensures that, if someone tries to call initCause() later, the call will fail loudly
-         *   rather than be silently ignored.
-         *
-         * - It populates the usual `Throwable.cause` field, where users of debuggers and other
-         *   tools are likely to look first.
-         *
-         * But if it doesn't work, that's fine: Most consumers of the cause should be retrieving it
-         * through getCause(), which we've overridden to return *our* `cause` field, which we've
-         * populated with the correct value.
-         */
-      }
+      super(checkNotNull(message), cause);
     }
 
     static SimpleAssertionError create(String message, @Nullable Throwable cause) {
@@ -299,12 +372,6 @@ public final class Truth {
       return createWithNoStack(message, /* cause= */ null);
     }
 
-    @Override
-    @SuppressWarnings("UnsynchronizedOverridesSynchronized")
-    public @Nullable Throwable getCause() {
-      return cause;
-    }
-
     @Override
     public String toString() {
       return checkNotNull(getLocalizedMessage());
diff --git a/extensions/java8/src/main/java/com/google/common/truth/Truth8.java b/core/src/main/java/com/google/common/truth/Truth8.java
similarity index 53%
rename from extensions/java8/src/main/java/com/google/common/truth/Truth8.java
rename to core/src/main/java/com/google/common/truth/Truth8.java
index c156c54b..e28ad49e 100644
--- a/extensions/java8/src/main/java/com/google/common/truth/Truth8.java
+++ b/core/src/main/java/com/google/common/truth/Truth8.java
@@ -15,8 +15,6 @@
  */
 package com.google.common.truth;
 
-import static com.google.common.truth.Truth.assertAbout;
-
 import com.google.common.annotations.GwtIncompatible;
 import com.google.j2objc.annotations.J2ObjCIncompatible;
 import java.nio.file.Path;
@@ -27,60 +25,60 @@ import java.util.OptionalLong;
 import java.util.stream.IntStream;
 import java.util.stream.LongStream;
 import java.util.stream.Stream;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
- * The primary entry point for assertions about Java 8 types.
- *
- * <p>To use {@link Truth#assertWithMessage} with a Java 8 type, use {@code
- * assertWithMessage(...).about(}{@link OptionalSubject#optionals optionals()}{@code ).that(...)}
- * (or similarly for the other types).
+ * The obsolete entry point for assertions about Java 8 types.
  *
- * <p>Likewise, to use different failure strategies like {@link Expect}, use {@code
- * expect.about(}{@link OptionalSubject#optionals optionals()}{@code ).that(...)}.
- *
- * <p>For more information about combining different messages, failure strategies, and subjects, see
- * <a href="https://truth.dev/faq#full-chain">How do I specify a custom message/failure
- * behavior/{@code Subject} type?</a> in the Truth FAQ.
+ * @deprecated Instead of this class's methods, use the identical methods declared in the main
+ *     {@link Truth} class. In most cases, you can <a
+ *     href="https://github.com/google/truth/releases/tag/v1.4.0">migrate</a> your whole project
+ *     mechanically: {@code git grep -l Truth8 | xargs perl -pi -e 's/\bTruth8\b/Truth/g;'}
+ *     Migration is important <i>if</i> you static import {@code assertThat}: If you do not migrate,
+ *     such static imports will become ambiguous in Truth 1.4.2, breaking your build.
  */
+@Deprecated
+@SuppressWarnings({
+  // The methods here are no more dangerous that wherever the user got the (e.g.) Stream.
+  "Java7ApiChecker",
+  // Replacing "Truth.assertThat" with "assertThat" would produce an infinite loop.
+  "StaticImportPreferred",
+})
 public final class Truth8 {
   @SuppressWarnings("AssertAboutOptionals") // suggests infinite recursion
   public static OptionalSubject assertThat(@Nullable Optional<?> target) {
-    return assertAbout(OptionalSubject.optionals()).that(target);
+    return Truth.assertThat(target);
   }
 
   public static OptionalIntSubject assertThat(@Nullable OptionalInt target) {
-    return assertAbout(OptionalIntSubject.optionalInts()).that(target);
+    return Truth.assertThat(target);
   }
 
   public static OptionalLongSubject assertThat(@Nullable OptionalLong target) {
-    return assertAbout(OptionalLongSubject.optionalLongs()).that(target);
+    return Truth.assertThat(target);
   }
 
   public static OptionalDoubleSubject assertThat(@Nullable OptionalDouble target) {
-    return assertAbout(OptionalDoubleSubject.optionalDoubles()).that(target);
+    return Truth.assertThat(target);
   }
 
   public static StreamSubject assertThat(@Nullable Stream<?> target) {
-    return assertAbout(StreamSubject.streams()).that(target);
+    return Truth.assertThat(target);
   }
 
   public static IntStreamSubject assertThat(@Nullable IntStream target) {
-    return assertAbout(IntStreamSubject.intStreams()).that(target);
+    return Truth.assertThat(target);
   }
 
   public static LongStreamSubject assertThat(@Nullable LongStream target) {
-    return assertAbout(LongStreamSubject.longStreams()).that(target);
+    return Truth.assertThat(target);
   }
 
-  // TODO(b/64757353): Add support for DoubleStream?
-
-  // Not actually a Java 8 feature, but for now this is the best option since core Truth still has
-  // to support Java environments without java.nio.file such as Android and J2CL.
   @GwtIncompatible
   @J2ObjCIncompatible
+  @J2ktIncompatible
   public static PathSubject assertThat(@Nullable Path target) {
-    return assertAbout(PathSubject.paths()).that(target);
+    return Truth.assertThat(target);
   }
 
   private Truth8() {}
diff --git a/core/src/main/java/com/google/common/truth/TruthFailureSubject.java b/core/src/main/java/com/google/common/truth/TruthFailureSubject.java
index eb9f9387..6439cf7d 100644
--- a/core/src/main/java/com/google/common/truth/TruthFailureSubject.java
+++ b/core/src/main/java/com/google/common/truth/TruthFailureSubject.java
@@ -23,7 +23,7 @@ import static com.google.common.truth.Fact.fact;
 import static com.google.common.truth.Fact.simpleFact;
 
 import com.google.common.collect.ImmutableList;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * Subject for {@link AssertionError} objects thrown by Truth. {@code TruthFailureSubject} contains
diff --git a/core/src/main/java/com/google/common/truth/TruthJUnit.java b/core/src/main/java/com/google/common/truth/TruthJUnit.java
index ad82efb2..648d5123 100644
--- a/core/src/main/java/com/google/common/truth/TruthJUnit.java
+++ b/core/src/main/java/com/google/common/truth/TruthJUnit.java
@@ -15,7 +15,6 @@
  */
 package com.google.common.truth;
 
-import com.google.common.annotations.GwtIncompatible;
 import org.junit.AssumptionViolatedException;
 
 /**
@@ -40,8 +39,7 @@ import org.junit.AssumptionViolatedException;
  * @author David Saff
  * @author Christian Gruber (cgruber@israfil.net)
  */
-@GwtIncompatible("JUnit4")
-@J2ktIncompatible
+@com.google.common.annotations.GwtIncompatible("JUnit4")
 public final class TruthJUnit {
   @SuppressWarnings("ConstantCaseForConstants") // Despite the "Builder" name, it's not mutable.
   private static final StandardSubjectBuilder ASSUME =
diff --git a/core/src/main/java/com/google/common/truth/package-info.java b/core/src/main/java/com/google/common/truth/package-info.java
index 89839f73..99ee86a0 100644
--- a/core/src/main/java/com/google/common/truth/package-info.java
+++ b/core/src/main/java/com/google/common/truth/package-info.java
@@ -29,6 +29,8 @@
  * other docs.
  */
 @CheckReturnValue
+@NullMarked
 package com.google.common.truth;
 
 import com.google.errorprone.annotations.CheckReturnValue;
+import org.jspecify.annotations.NullMarked;
diff --git a/core/src/main/java/com/google/common/truth/super/com/google/common/truth/Platform.java b/core/src/main/java/com/google/common/truth/super/com/google/common/truth/Platform.java
index 4642f8ab..ff273b27 100644
--- a/core/src/main/java/com/google/common/truth/super/com/google/common/truth/Platform.java
+++ b/core/src/main/java/com/google/common/truth/super/com/google/common/truth/Platform.java
@@ -23,7 +23,8 @@ import com.google.common.collect.ImmutableList;
 import jsinterop.annotations.JsMethod;
 import jsinterop.annotations.JsProperty;
 import jsinterop.annotations.JsType;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.NullMarked;
+import org.jspecify.annotations.Nullable;
 
 
 /**
@@ -32,6 +33,7 @@ import org.checkerframework.checker.nullness.qual.Nullable;
  *
  * @author Christian Gruber (cgruber@google.com)
  */
+@NullMarked
 final class Platform {
   private Platform() {}
 
@@ -58,7 +60,7 @@ final class Platform {
   }
 
   /**
-   * Returns an array containing all of the exceptions that were suppressed to deliver the given
+   * Returns an array containing all the exceptions that were suppressed to deliver the given
    * exception. Delegates to the getSuppressed() method on Throwable that is available in Java 1.7+
    */
   static Throwable[] getSuppressed(Throwable throwable) {
@@ -268,5 +270,9 @@ final class Platform {
   static boolean kotlinRangeContains(Iterable<?> haystack, @Nullable Object needle) {
     throw new AssertionError(); // never called under GWT because isKotlinRange returns false
   }
+
+  static boolean classMetadataUnsupported() {
+    return String.class.getSuperclass() == null;
+  }
 }
 
diff --git a/core/src/test/java/com/google/common/truth/DoubleSubjectTest.java b/core/src/test/java/com/google/common/truth/DoubleSubjectTest.java
index e6535584..f65e2603 100644
--- a/core/src/test/java/com/google/common/truth/DoubleSubjectTest.java
+++ b/core/src/test/java/com/google/common/truth/DoubleSubjectTest.java
@@ -23,7 +23,7 @@ import static org.junit.Assert.fail;
 import com.google.common.annotations.GwtIncompatible;
 import com.google.common.truth.ExpectFailure.SimpleSubjectBuilderCallback;
 import com.google.errorprone.annotations.CanIgnoreReturnValue;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.junit.runners.JUnit4;
diff --git a/core/src/test/java/com/google/common/truth/ExpectFailureNonRuleTest.java b/core/src/test/java/com/google/common/truth/ExpectFailureNonRuleTest.java
index 460c35b3..060bc46c 100644
--- a/core/src/test/java/com/google/common/truth/ExpectFailureNonRuleTest.java
+++ b/core/src/test/java/com/google/common/truth/ExpectFailureNonRuleTest.java
@@ -125,6 +125,7 @@ public class ExpectFailureNonRuleTest {
     }
 
     @Test
+    @SuppressWarnings("TruthSelfEquals")
     public void testExpect_throwInSubject_shouldPropagate() {
       expectFailure.whenTesting().that(4).isEqualTo(4); // No failure being caught
       long unused = throwingMethod();
diff --git a/core/src/test/java/com/google/common/truth/ExpectFailureRuleTest.java b/core/src/test/java/com/google/common/truth/ExpectFailureRuleTest.java
index 5938ce25..01f67492 100644
--- a/core/src/test/java/com/google/common/truth/ExpectFailureRuleTest.java
+++ b/core/src/test/java/com/google/common/truth/ExpectFailureRuleTest.java
@@ -38,11 +38,13 @@ public class ExpectFailureRuleTest {
   }
 
   @Test
+  @SuppressWarnings("TruthSelfEquals")
   public void expectFail_passesIfUnused() {
     assertThat(4).isEqualTo(4);
   }
 
   @Test
+  @SuppressWarnings("TruthSelfEquals")
   public void expectFail_failsAfterTest() {
     expectFailure.whenTesting().that(4).isEqualTo(4);
     thrown.expectMessage("ExpectFailure.whenTesting() invoked, but no failure was caught.");
@@ -55,6 +57,7 @@ public class ExpectFailureRuleTest {
   }
 
   @Test
+  @SuppressWarnings("TruthSelfEquals")
   public void expectFail_throwAfterSubject_shouldPropagateOriginalException() {
     expectFailure.whenTesting().that(2).isEqualTo(2);
     thrown.expectMessage("Throwing deliberately");
diff --git a/core/src/test/java/com/google/common/truth/ExpectFailureTest.java b/core/src/test/java/com/google/common/truth/ExpectFailureTest.java
index 74dd80dd..06e1c4ef 100644
--- a/core/src/test/java/com/google/common/truth/ExpectFailureTest.java
+++ b/core/src/test/java/com/google/common/truth/ExpectFailureTest.java
@@ -54,11 +54,13 @@ public class ExpectFailureTest {
   }
 
   @Test
+  @SuppressWarnings("TruthSelfEquals")
   public void expectFail_passesIfUnused() {
     assertThat(4).isEqualTo(4);
   }
 
   @Test
+  @SuppressWarnings("TruthSelfEquals")
   public void expectFail_failsOnSuccess() {
     expectFailure.whenTesting().that(4).isEqualTo(4);
     try {
@@ -83,6 +85,7 @@ public class ExpectFailureTest {
   }
 
   @Test
+  @SuppressWarnings("TruthSelfEquals")
   public void expectFail_failsOnMultiplewhenTestings() {
     try {
       expectFailure.whenTesting().that(4).isEqualTo(4);
@@ -108,6 +111,7 @@ public class ExpectFailureTest {
   }
 
   @Test
+  @SuppressWarnings("TruthSelfEquals")
   public void expectFail_failsAfterTest() {
     try {
       expectFailure.whenTesting().that(4).isEqualTo(4);
@@ -121,6 +125,7 @@ public class ExpectFailureTest {
   }
 
   @Test
+  @SuppressWarnings("TruthSelfEquals")
   public void expectFail_whenTestingWithoutInContext_shouldFail() {
     ExpectFailure expectFailure = new ExpectFailure();
     try {
diff --git a/core/src/test/java/com/google/common/truth/ExpectFailureWithStackTraceTest.java b/core/src/test/java/com/google/common/truth/ExpectFailureWithStackTraceTest.java
index 8ac3e561..49676115 100644
--- a/core/src/test/java/com/google/common/truth/ExpectFailureWithStackTraceTest.java
+++ b/core/src/test/java/com/google/common/truth/ExpectFailureWithStackTraceTest.java
@@ -33,6 +33,7 @@ public class ExpectFailureWithStackTraceTest {
   @Rule public final FailingExpect failToExpect = new FailingExpect();
 
   @Test
+  @SuppressWarnings("TruthSelfEquals")
   public void expectTwoFailures() {
     failToExpect.delegate.that(4).isNotEqualTo(4);
     failToExpect.delegate.that("abc").contains("x");
diff --git a/core/src/test/java/com/google/common/truth/ExpectTest.java b/core/src/test/java/com/google/common/truth/ExpectTest.java
index f7371c45..958de6a1 100644
--- a/core/src/test/java/com/google/common/truth/ExpectTest.java
+++ b/core/src/test/java/com/google/common/truth/ExpectTest.java
@@ -79,6 +79,7 @@ public class ExpectTest {
       };
 
   @Test
+  @SuppressWarnings("TruthSelfEquals")
   public void expectTrue() {
     expect.that(4).isEqualTo(4);
   }
@@ -175,6 +176,7 @@ public class ExpectTest {
   }
 
   @Test
+  @SuppressWarnings("TruthSelfEquals")
   public void warnWhenExpectIsNotRule() {
     String message = "assertion made on Expect instance, but it's not enabled as a @Rule.";
     thrown.expectMessage(message);
diff --git a/core/src/test/java/com/google/common/truth/FloatSubjectTest.java b/core/src/test/java/com/google/common/truth/FloatSubjectTest.java
index b528ab09..b14da38f 100644
--- a/core/src/test/java/com/google/common/truth/FloatSubjectTest.java
+++ b/core/src/test/java/com/google/common/truth/FloatSubjectTest.java
@@ -23,7 +23,7 @@ import static org.junit.Assert.fail;
 import com.google.common.annotations.GwtIncompatible;
 import com.google.common.truth.ExpectFailure.SimpleSubjectBuilderCallback;
 import com.google.errorprone.annotations.CanIgnoreReturnValue;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.junit.runners.JUnit4;
diff --git a/core/src/test/java/com/google/common/truth/IntegerSubjectTest.java b/core/src/test/java/com/google/common/truth/IntegerSubjectTest.java
index bc6a5a02..a9f0fef9 100644
--- a/core/src/test/java/com/google/common/truth/IntegerSubjectTest.java
+++ b/core/src/test/java/com/google/common/truth/IntegerSubjectTest.java
@@ -15,9 +15,12 @@
  */
 package com.google.common.truth;
 
+import static com.google.common.truth.ExpectFailure.assertThat;
 import static com.google.common.truth.Truth.assertThat;
+import static org.junit.Assert.fail;
 
-import com.google.common.collect.ImmutableSet;
+import com.google.common.truth.ExpectFailure.SimpleSubjectBuilderCallback;
+import com.google.errorprone.annotations.CanIgnoreReturnValue;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.junit.runners.JUnit4;
@@ -33,6 +36,7 @@ import org.junit.runners.JUnit4;
 public class IntegerSubjectTest extends BaseSubjectTestCase {
 
   @Test
+  @SuppressWarnings("TruthSelfEquals")
   public void simpleEquality() {
     assertThat(4).isEqualTo(4);
   }
@@ -116,160 +120,124 @@ public class IntegerSubjectTest extends BaseSubjectTestCase {
     expectFailureWhenTestingThat(Integer.MAX_VALUE).isEqualTo(Long.MAX_VALUE);
   }
 
-  @SuppressWarnings("TruthSelfEquals")
-  @Test
-  public void testPrimitivesVsBoxedPrimitivesVsObject_int() {
-    int int42 = 42;
-    Integer integer42 = new Integer(42);
-    Object object42 = (Object) 42;
-
-    assertThat(int42).isEqualTo(int42);
-    assertThat(integer42).isEqualTo(int42);
-    assertThat(object42).isEqualTo(int42);
-
-    assertThat(int42).isEqualTo(integer42);
-    assertThat(integer42).isEqualTo(integer42);
-    assertThat(object42).isEqualTo(integer42);
-
-    assertThat(int42).isEqualTo(object42);
-    assertThat(integer42).isEqualTo(object42);
-    assertThat(object42).isEqualTo(object42);
-  }
-
-  @SuppressWarnings("TruthSelfEquals")
-  @Test
-  public void testPrimitivesVsBoxedPrimitivesVsObject_long() {
-    long longPrim42 = 42;
-    Long long42 = new Long(42);
-    Object object42 = (Object) 42L;
-
-    assertThat(longPrim42).isEqualTo(longPrim42);
-    assertThat(long42).isEqualTo(longPrim42);
-    assertThat(object42).isEqualTo(longPrim42);
-
-    assertThat(longPrim42).isEqualTo(long42);
-    assertThat(long42).isEqualTo(long42);
-    assertThat(object42).isEqualTo(long42);
-
-    assertThat(longPrim42).isEqualTo(object42);
-    assertThat(long42).isEqualTo(object42);
-    assertThat(object42).isEqualTo(object42);
-  }
-
-  @Test
-  public void testAllCombinations_pass() {
-    assertThat(42).isEqualTo(42L);
-    assertThat(42).isEqualTo(new Long(42L));
-    assertThat(new Integer(42)).isEqualTo(42L);
-    assertThat(new Integer(42)).isEqualTo(new Long(42L));
-    assertThat(42L).isEqualTo(42);
-    assertThat(42L).isEqualTo(new Integer(42));
-    assertThat(new Long(42L)).isEqualTo(42);
-    assertThat(new Long(42L)).isEqualTo(new Integer(42));
-
-    assertThat(42).isEqualTo(42);
-    assertThat(42).isEqualTo(new Integer(42));
-    assertThat(new Integer(42)).isEqualTo(42);
-    assertThat(new Integer(42)).isEqualTo(new Integer(42));
-    assertThat(42L).isEqualTo(42L);
-    assertThat(42L).isEqualTo(new Long(42L));
-    assertThat(new Long(42L)).isEqualTo(42L);
-    assertThat(new Long(42L)).isEqualTo(new Long(42L));
-  }
-
   @Test
-  public void testNumericTypeWithSameValue_shouldBeEqual_int_long() {
-    expectFailureWhenTestingThat(42).isNotEqualTo(42L);
-  }
-
-  @Test
-  public void testNumericTypeWithSameValue_shouldBeEqual_int_int() {
-    expectFailureWhenTestingThat(42).isNotEqualTo(42);
-  }
-
-  @Test
-  public void testNumericPrimitiveTypes_isNotEqual_shouldFail_intToChar() {
-    expectFailureWhenTestingThat(42).isNotEqualTo((char) 42);
-    // 42 in ASCII is '*'
-    assertFailureValue("expected not to be", "*");
-    assertFailureValue("but was; string representation of actual value", "42");
+  public void isWithinOf() {
+    assertThat(20000).isWithin(0).of(20000);
+    assertThat(20000).isWithin(1).of(20000);
+    assertThat(20000).isWithin(10000).of(20000);
+    assertThat(20000).isWithin(10000).of(30000);
+    assertThat(Integer.MIN_VALUE).isWithin(1).of(Integer.MIN_VALUE + 1);
+    assertThat(Integer.MAX_VALUE).isWithin(1).of(Integer.MAX_VALUE - 1);
+    assertThat(Integer.MAX_VALUE / 2).isWithin(Integer.MAX_VALUE).of(-Integer.MAX_VALUE / 2);
+    assertThat(-Integer.MAX_VALUE / 2).isWithin(Integer.MAX_VALUE).of(Integer.MAX_VALUE / 2);
+
+    assertThatIsWithinFails(20000, 9999, 30000);
+    assertThatIsWithinFails(20000, 10000, 30001);
+    assertThatIsWithinFails(Integer.MIN_VALUE, 0, Integer.MAX_VALUE);
+    assertThatIsWithinFails(Integer.MAX_VALUE, 0, Integer.MIN_VALUE);
+    assertThatIsWithinFails(Integer.MIN_VALUE, 1, Integer.MIN_VALUE + 2);
+    assertThatIsWithinFails(Integer.MAX_VALUE, 1, Integer.MAX_VALUE - 2);
+    // Don't fall for rollover
+    assertThatIsWithinFails(Integer.MIN_VALUE, 1, Integer.MAX_VALUE);
+    assertThatIsWithinFails(Integer.MAX_VALUE, 1, Integer.MIN_VALUE);
+  }
+
+  private static void assertThatIsWithinFails(int actual, int tolerance, int expected) {
+    ExpectFailure.SimpleSubjectBuilderCallback<IntegerSubject, Integer> callback =
+        new ExpectFailure.SimpleSubjectBuilderCallback<IntegerSubject, Integer>() {
+          @Override
+          public void invokeAssertion(SimpleSubjectBuilder<IntegerSubject, Integer> expect) {
+            expect.that(actual).isWithin(tolerance).of(expected);
+          }
+        };
+    AssertionError failure = expectFailure(callback);
+    assertThat(failure)
+        .factKeys()
+        .containsExactly("expected", "but was", "outside tolerance")
+        .inOrder();
+    assertThat(failure).factValue("expected").isEqualTo(Integer.toString(expected));
+    assertThat(failure).factValue("but was").isEqualTo(Integer.toString(actual));
+    assertThat(failure).factValue("outside tolerance").isEqualTo(Integer.toString(tolerance));
+  }
+
+  @Test
+  public void isNotWithinOf() {
+    assertThatIsNotWithinFails(20000, 0, 20000);
+    assertThatIsNotWithinFails(20000, 1, 20000);
+    assertThatIsNotWithinFails(20000, 10000, 20000);
+    assertThatIsNotWithinFails(20000, 10000, 30000);
+    assertThatIsNotWithinFails(Integer.MIN_VALUE, 1, Integer.MIN_VALUE + 1);
+    assertThatIsNotWithinFails(Integer.MAX_VALUE, 1, Integer.MAX_VALUE - 1);
+    assertThatIsNotWithinFails(Integer.MAX_VALUE / 2, Integer.MAX_VALUE, -Integer.MAX_VALUE / 2);
+    assertThatIsNotWithinFails(-Integer.MAX_VALUE / 2, Integer.MAX_VALUE, Integer.MAX_VALUE / 2);
+
+    assertThat(20000).isNotWithin(9999).of(30000);
+    assertThat(20000).isNotWithin(10000).of(30001);
+    assertThat(Integer.MIN_VALUE).isNotWithin(0).of(Integer.MAX_VALUE);
+    assertThat(Integer.MAX_VALUE).isNotWithin(0).of(Integer.MIN_VALUE);
+    assertThat(Integer.MIN_VALUE).isNotWithin(1).of(Integer.MIN_VALUE + 2);
+    assertThat(Integer.MAX_VALUE).isNotWithin(1).of(Integer.MAX_VALUE - 2);
+    // Don't fall for rollover
+    assertThat(Integer.MIN_VALUE).isNotWithin(1).of(Integer.MAX_VALUE);
+    assertThat(Integer.MAX_VALUE).isNotWithin(1).of(Integer.MIN_VALUE);
+  }
+
+  private static void assertThatIsNotWithinFails(int actual, int tolerance, int expected) {
+    ExpectFailure.SimpleSubjectBuilderCallback<IntegerSubject, Integer> callback =
+        new ExpectFailure.SimpleSubjectBuilderCallback<IntegerSubject, Integer>() {
+          @Override
+          public void invokeAssertion(SimpleSubjectBuilder<IntegerSubject, Integer> expect) {
+            expect.that(actual).isNotWithin(tolerance).of(expected);
+          }
+        };
+    AssertionError failure = expectFailure(callback);
+    assertThat(failure).factValue("expected not to be").isEqualTo(Integer.toString(expected));
+    assertThat(failure).factValue("within tolerance").isEqualTo(Integer.toString(tolerance));
+  }
+
+  @Test
+  public void isWithinNegativeTolerance() {
+    isWithinNegativeToleranceThrowsIAE(0, -10, 5);
+    isWithinNegativeToleranceThrowsIAE(0, -10, 20);
+    isNotWithinNegativeToleranceThrowsIAE(0, -10, 5);
+    isNotWithinNegativeToleranceThrowsIAE(0, -10, 20);
+  }
+
+  private static void isWithinNegativeToleranceThrowsIAE(int actual, int tolerance, int expected) {
+    try {
+      assertThat(actual).isWithin(tolerance).of(expected);
+      fail("Expected IllegalArgumentException to be thrown but wasn't");
+    } catch (IllegalArgumentException iae) {
+      assertThat(iae)
+          .hasMessageThat()
+          .isEqualTo("tolerance (" + tolerance + ") cannot be negative");
+    }
   }
 
-  @Test
-  public void testNumericPrimitiveTypes_isNotEqual_shouldFail_charToInt() {
-    // Uses Object overload rather than Integer.
-    expectFailure.whenTesting().that((char) 42).isNotEqualTo(42);
-    // 42 in ASCII is '*'
-    assertFailureValue("expected not to be", "42");
-    assertFailureValue("but was; string representation of actual value", "*");
+  private static void isNotWithinNegativeToleranceThrowsIAE(
+      int actual, int tolerance, int expected) {
+    try {
+      assertThat(actual).isNotWithin(tolerance).of(expected);
+      fail("Expected IllegalArgumentException to be thrown but wasn't");
+    } catch (IllegalArgumentException iae) {
+      assertThat(iae)
+          .hasMessageThat()
+          .isEqualTo("tolerance (" + tolerance + ") cannot be negative");
+    }
   }
 
-  private static final Subject.Factory<Subject, Object> DEFAULT_SUBJECT_FACTORY =
-      new Subject.Factory<Subject, Object>() {
+  private static final Subject.Factory<IntegerSubject, Integer> INTEGER_SUBJECT_FACTORY =
+      new Subject.Factory<IntegerSubject, Integer>() {
         @Override
-        public Subject createSubject(FailureMetadata metadata, Object that) {
-          return new Subject(metadata, that);
+        public IntegerSubject createSubject(FailureMetadata metadata, Integer that) {
+          return new IntegerSubject(metadata, that);
         }
       };
 
-  private static void expectFailure(
-      ExpectFailure.SimpleSubjectBuilderCallback<Subject, Object> callback) {
-    AssertionError unused = ExpectFailure.expectFailureAbout(DEFAULT_SUBJECT_FACTORY, callback);
-  }
-
-  @Test
-  public void testNumericPrimitiveTypes() {
-    byte byte42 = (byte) 42;
-    short short42 = (short) 42;
-    char char42 = (char) 42;
-    int int42 = 42;
-    long long42 = (long) 42;
-
-    ImmutableSet<Object> fortyTwos =
-        ImmutableSet.<Object>of(byte42, short42, char42, int42, long42);
-    for (Object actual : fortyTwos) {
-      for (Object expected : fortyTwos) {
-        assertThat(actual).isEqualTo(expected);
-      }
-    }
-
-    ImmutableSet<Object> fortyTwosNoChar = ImmutableSet.<Object>of(byte42, short42, int42, long42);
-    for (Object actual : fortyTwosNoChar) {
-      for (Object expected : fortyTwosNoChar) {
-        ExpectFailure.SimpleSubjectBuilderCallback<Subject, Object> actualFirst =
-            new ExpectFailure.SimpleSubjectBuilderCallback<Subject, Object>() {
-              @Override
-              public void invokeAssertion(SimpleSubjectBuilder<Subject, Object> expect) {
-                expect.that(actual).isNotEqualTo(expected);
-              }
-            };
-        ExpectFailure.SimpleSubjectBuilderCallback<Subject, Object> expectedFirst =
-            new ExpectFailure.SimpleSubjectBuilderCallback<Subject, Object>() {
-              @Override
-              public void invokeAssertion(SimpleSubjectBuilder<Subject, Object> expect) {
-                expect.that(expected).isNotEqualTo(actual);
-              }
-            };
-        expectFailure(actualFirst);
-        expectFailure(expectedFirst);
-      }
-    }
-
-    byte byte41 = (byte) 41;
-    short short41 = (short) 41;
-    char char41 = (char) 41;
-    int int41 = 41;
-    long long41 = (long) 41;
-
-    ImmutableSet<Object> fortyOnes =
-        ImmutableSet.<Object>of(byte41, short41, char41, int41, long41);
-
-    for (Object first : fortyTwos) {
-      for (Object second : fortyOnes) {
-        assertThat(first).isNotEqualTo(second);
-        assertThat(second).isNotEqualTo(first);
-      }
-    }
+  @CanIgnoreReturnValue
+  private static AssertionError expectFailure(
+      SimpleSubjectBuilderCallback<IntegerSubject, Integer> callback) {
+    return ExpectFailure.expectFailureAbout(INTEGER_SUBJECT_FACTORY, callback);
   }
 
   private IntegerSubject expectFailureWhenTestingThat(Integer actual) {
diff --git a/core/src/test/java/com/google/common/truth/IterableSubjectTest.java b/core/src/test/java/com/google/common/truth/IterableSubjectTest.java
index aaa20465..80eb4f9b 100644
--- a/core/src/test/java/com/google/common/truth/IterableSubjectTest.java
+++ b/core/src/test/java/com/google/common/truth/IterableSubjectTest.java
@@ -709,7 +709,7 @@ public class IterableSubjectTest extends BaseSubjectTestCase {
   }
 
   @Test
-  @SuppressWarnings("ContainsExactlyNone")
+  @SuppressWarnings({"ContainsExactlyNone", "TruthSelfEquals"})
   public void iterableContainsExactlyElementsInInOrderPassesWithEmptyExpectedAndActual() {
     assertThat(ImmutableList.of()).containsExactlyElementsIn(ImmutableList.of()).inOrder();
   }
diff --git a/core/src/test/java/com/google/common/truth/LongSubjectTest.java b/core/src/test/java/com/google/common/truth/LongSubjectTest.java
index b3a3f443..c2c2e15f 100644
--- a/core/src/test/java/com/google/common/truth/LongSubjectTest.java
+++ b/core/src/test/java/com/google/common/truth/LongSubjectTest.java
@@ -15,8 +15,12 @@
  */
 package com.google.common.truth;
 
+import static com.google.common.truth.ExpectFailure.assertThat;
 import static com.google.common.truth.Truth.assertThat;
+import static org.junit.Assert.fail;
 
+import com.google.common.truth.ExpectFailure.SimpleSubjectBuilderCallback;
+import com.google.errorprone.annotations.CanIgnoreReturnValue;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.junit.runners.JUnit4;
@@ -32,6 +36,7 @@ import org.junit.runners.JUnit4;
 public class LongSubjectTest extends BaseSubjectTestCase {
 
   @Test
+  @SuppressWarnings("TruthSelfEquals")
   public void simpleEquality() {
     assertThat(4L).isEqualTo(4L);
   }
@@ -129,6 +134,140 @@ public class LongSubjectTest extends BaseSubjectTestCase {
     assertThat(2L).isAtMost(3);
   }
 
+  @Test
+  public void isWithinOf() {
+    assertThat(20000L).isWithin(0L).of(20000L);
+    assertThat(20000L).isWithin(1L).of(20000L);
+    assertThat(20000L).isWithin(10000L).of(20000L);
+    assertThat(20000L).isWithin(10000L).of(30000L);
+    assertThat(Long.MIN_VALUE).isWithin(1L).of(Long.MIN_VALUE + 1);
+    assertThat(Long.MAX_VALUE).isWithin(1L).of(Long.MAX_VALUE - 1);
+    assertThat(Long.MAX_VALUE / 2).isWithin(Long.MAX_VALUE).of(-Long.MAX_VALUE / 2);
+    assertThat(-Long.MAX_VALUE / 2).isWithin(Long.MAX_VALUE).of(Long.MAX_VALUE / 2);
+
+    assertThatIsWithinFails(20000L, 9999L, 30000L);
+    assertThatIsWithinFails(20000L, 10000L, 30001L);
+    assertThatIsWithinFails(Long.MIN_VALUE, 0L, Long.MAX_VALUE);
+    assertThatIsWithinFails(Long.MAX_VALUE, 0L, Long.MIN_VALUE);
+    assertThatIsWithinFails(Long.MIN_VALUE, 1L, Long.MIN_VALUE + 2);
+    assertThatIsWithinFails(Long.MAX_VALUE, 1L, Long.MAX_VALUE - 2);
+    // Don't fall for rollover
+    assertThatIsWithinFails(Long.MIN_VALUE, 1L, Long.MAX_VALUE);
+    assertThatIsWithinFails(Long.MAX_VALUE, 1L, Long.MIN_VALUE);
+  }
+
+  private static void assertThatIsWithinFails(long actual, long tolerance, long expected) {
+    ExpectFailure.SimpleSubjectBuilderCallback<LongSubject, Long> callback =
+        new ExpectFailure.SimpleSubjectBuilderCallback<LongSubject, Long>() {
+          @Override
+          public void invokeAssertion(SimpleSubjectBuilder<LongSubject, Long> expect) {
+            expect.that(actual).isWithin(tolerance).of(expected);
+          }
+        };
+    AssertionError failure = expectFailure(callback);
+    assertThat(failure)
+        .factKeys()
+        .containsExactly("expected", "but was", "outside tolerance")
+        .inOrder();
+    assertThat(failure).factValue("expected").isEqualTo(Long.toString(expected));
+    assertThat(failure).factValue("but was").isEqualTo(Long.toString(actual));
+    assertThat(failure).factValue("outside tolerance").isEqualTo(Long.toString(tolerance));
+  }
+
+  @Test
+  public void isNotWithinOf() {
+    assertThatIsNotWithinFails(20000L, 0L, 20000L);
+    assertThatIsNotWithinFails(20000L, 1L, 20000L);
+    assertThatIsNotWithinFails(20000L, 10000L, 20000L);
+    assertThatIsNotWithinFails(20000L, 10000L, 30000L);
+    assertThatIsNotWithinFails(Long.MIN_VALUE, 1L, Long.MIN_VALUE + 1);
+    assertThatIsNotWithinFails(Long.MAX_VALUE, 1L, Long.MAX_VALUE - 1);
+    assertThatIsNotWithinFails(Long.MAX_VALUE / 2, Long.MAX_VALUE, -Long.MAX_VALUE / 2);
+    assertThatIsNotWithinFails(-Long.MAX_VALUE / 2, Long.MAX_VALUE, Long.MAX_VALUE / 2);
+
+    assertThat(20000L).isNotWithin(9999L).of(30000L);
+    assertThat(20000L).isNotWithin(10000L).of(30001L);
+    assertThat(Long.MIN_VALUE).isNotWithin(0L).of(Long.MAX_VALUE);
+    assertThat(Long.MAX_VALUE).isNotWithin(0L).of(Long.MIN_VALUE);
+    assertThat(Long.MIN_VALUE).isNotWithin(1L).of(Long.MIN_VALUE + 2);
+    assertThat(Long.MAX_VALUE).isNotWithin(1L).of(Long.MAX_VALUE - 2);
+    // Don't fall for rollover
+    assertThat(Long.MIN_VALUE).isNotWithin(1L).of(Long.MAX_VALUE);
+    assertThat(Long.MAX_VALUE).isNotWithin(1L).of(Long.MIN_VALUE);
+  }
+
+  private static void assertThatIsNotWithinFails(long actual, long tolerance, long expected) {
+    ExpectFailure.SimpleSubjectBuilderCallback<LongSubject, Long> callback =
+        new ExpectFailure.SimpleSubjectBuilderCallback<LongSubject, Long>() {
+          @Override
+          public void invokeAssertion(SimpleSubjectBuilder<LongSubject, Long> expect) {
+            expect.that(actual).isNotWithin(tolerance).of(expected);
+          }
+        };
+    AssertionError failure = expectFailure(callback);
+    assertThat(failure).factValue("expected not to be").isEqualTo(Long.toString(expected));
+    assertThat(failure).factValue("within tolerance").isEqualTo(Long.toString(tolerance));
+  }
+
+  @Test
+  public void isWithinIntegers() {
+    assertThat(20000L).isWithin(0).of(20000);
+    assertThat(20000L).isWithin(1).of(20000);
+    assertThat(20000L).isWithin(10000).of(20000);
+    assertThat(20000L).isWithin(10000).of(30000);
+
+    assertThat(20000L).isNotWithin(0).of(200000);
+    assertThat(20000L).isNotWithin(1).of(200000);
+    assertThat(20000L).isNotWithin(10000).of(200000);
+    assertThat(20000L).isNotWithin(10000).of(300000);
+  }
+
+  @Test
+  public void isWithinNegativeTolerance() {
+    isWithinNegativeToleranceThrowsIAE(0L, -10, 5);
+    isWithinNegativeToleranceThrowsIAE(0L, -10, 20);
+    isNotWithinNegativeToleranceThrowsIAE(0L, -10, 5);
+    isNotWithinNegativeToleranceThrowsIAE(0L, -10, 20);
+  }
+
+  private static void isWithinNegativeToleranceThrowsIAE(
+      long actual, long tolerance, long expected) {
+    try {
+      assertThat(actual).isWithin(tolerance).of(expected);
+      fail("Expected IllegalArgumentException to be thrown but wasn't");
+    } catch (IllegalArgumentException iae) {
+      assertThat(iae)
+          .hasMessageThat()
+          .isEqualTo("tolerance (" + tolerance + ") cannot be negative");
+    }
+  }
+
+  private static void isNotWithinNegativeToleranceThrowsIAE(
+      long actual, long tolerance, long expected) {
+    try {
+      assertThat(actual).isNotWithin(tolerance).of(expected);
+      fail("Expected IllegalArgumentException to be thrown but wasn't");
+    } catch (IllegalArgumentException iae) {
+      assertThat(iae)
+          .hasMessageThat()
+          .isEqualTo("tolerance (" + tolerance + ") cannot be negative");
+    }
+  }
+
+  private static final Subject.Factory<LongSubject, Long> LONG_SUBJECT_FACTORY =
+      new Subject.Factory<LongSubject, Long>() {
+        @Override
+        public LongSubject createSubject(FailureMetadata metadata, Long that) {
+          return new LongSubject(metadata, that);
+        }
+      };
+
+  @CanIgnoreReturnValue
+  private static AssertionError expectFailure(
+      SimpleSubjectBuilderCallback<LongSubject, Long> callback) {
+    return ExpectFailure.expectFailureAbout(LONG_SUBJECT_FACTORY, callback);
+  }
+
   private LongSubject expectFailureWhenTestingThat(Long actual) {
     return expectFailure.whenTesting().that(actual);
   }
diff --git a/core/src/test/java/com/google/common/truth/NumericComparisonTest.java b/core/src/test/java/com/google/common/truth/NumericComparisonTest.java
new file mode 100644
index 00000000..a2bc9b36
--- /dev/null
+++ b/core/src/test/java/com/google/common/truth/NumericComparisonTest.java
@@ -0,0 +1,195 @@
+/*
+ * Copyright (c) 2011 Google, Inc.
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ * http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+package com.google.common.truth;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import com.google.common.collect.ImmutableSet;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
+/**
+ * Tests for comparisons between various integral types.
+ *
+ * @author David Saff
+ * @author Christian Gruber
+ * @author Kurt Alfred Kluever
+ */
+@RunWith(JUnit4.class)
+public class NumericComparisonTest extends BaseSubjectTestCase {
+
+  @SuppressWarnings("TruthSelfEquals")
+  @Test
+  public void testPrimitivesVsBoxedPrimitivesVsObject_int() {
+    int int42 = 42;
+    Integer integer42 = 42;
+    Object object42 = (Object) 42;
+
+    assertThat(int42).isEqualTo(int42);
+    assertThat(integer42).isEqualTo(int42);
+    assertThat(object42).isEqualTo(int42);
+
+    assertThat(int42).isEqualTo(integer42);
+    assertThat(integer42).isEqualTo(integer42);
+    assertThat(object42).isEqualTo(integer42);
+
+    assertThat(int42).isEqualTo(object42);
+    assertThat(integer42).isEqualTo(object42);
+    assertThat(object42).isEqualTo(object42);
+  }
+
+  @SuppressWarnings("TruthSelfEquals")
+  @Test
+  public void testPrimitivesVsBoxedPrimitivesVsObject_long() {
+    long longPrim42 = 42;
+    Long long42 = (long) 42;
+    Object object42 = (Object) 42L;
+
+    assertThat(longPrim42).isEqualTo(longPrim42);
+    assertThat(long42).isEqualTo(longPrim42);
+    assertThat(object42).isEqualTo(longPrim42);
+
+    assertThat(longPrim42).isEqualTo(long42);
+    assertThat(long42).isEqualTo(long42);
+    assertThat(object42).isEqualTo(long42);
+
+    assertThat(longPrim42).isEqualTo(object42);
+    assertThat(long42).isEqualTo(object42);
+    assertThat(object42).isEqualTo(object42);
+  }
+
+  @Test
+  @SuppressWarnings("TruthSelfEquals")
+  public void testAllCombinations_pass() {
+    assertThat(42).isEqualTo(42L);
+    assertThat(42).isEqualTo(Long.valueOf(42L));
+    assertThat(Integer.valueOf(42)).isEqualTo(42L);
+    assertThat(Integer.valueOf(42)).isEqualTo(Long.valueOf(42L));
+    assertThat(42L).isEqualTo(42);
+    assertThat(42L).isEqualTo(Integer.valueOf(42));
+    assertThat(Long.valueOf(42L)).isEqualTo(42);
+    assertThat(Long.valueOf(42L)).isEqualTo(Integer.valueOf(42));
+
+    assertThat(42).isEqualTo(42);
+    assertThat(42).isEqualTo(Integer.valueOf(42));
+    assertThat(Integer.valueOf(42)).isEqualTo(42);
+    assertThat(Integer.valueOf(42)).isEqualTo(Integer.valueOf(42));
+    assertThat(42L).isEqualTo(42L);
+    assertThat(42L).isEqualTo(Long.valueOf(42L));
+    assertThat(Long.valueOf(42L)).isEqualTo(42L);
+    assertThat(Long.valueOf(42L)).isEqualTo(Long.valueOf(42L));
+  }
+
+  @Test
+  public void testNumericTypeWithSameValue_shouldBeEqual_int_long() {
+    expectFailureWhenTestingThat(42).isNotEqualTo(42L);
+  }
+
+  @Test
+  public void testNumericTypeWithSameValue_shouldBeEqual_int_int() {
+    expectFailureWhenTestingThat(42).isNotEqualTo(42);
+  }
+
+  @Test
+  public void testNumericPrimitiveTypes_isNotEqual_shouldFail_intToChar() {
+    expectFailureWhenTestingThat(42).isNotEqualTo((char) 42);
+    // 42 in ASCII is '*'
+    assertFailureValue("expected not to be", "*");
+    assertFailureValue("but was; string representation of actual value", "42");
+  }
+
+  @Test
+  public void testNumericPrimitiveTypes_isNotEqual_shouldFail_charToInt() {
+    // Uses Object overload rather than Integer.
+    expectFailure.whenTesting().that((char) 42).isNotEqualTo(42);
+    // 42 in ASCII is '*'
+    assertFailureValue("expected not to be", "42");
+    assertFailureValue("but was; string representation of actual value", "*");
+  }
+
+  private static final Subject.Factory<Subject, Object> DEFAULT_SUBJECT_FACTORY =
+      new Subject.Factory<Subject, Object>() {
+        @Override
+        public Subject createSubject(FailureMetadata metadata, Object that) {
+          return new Subject(metadata, that);
+        }
+      };
+
+  private static void expectFailure(
+      ExpectFailure.SimpleSubjectBuilderCallback<Subject, Object> callback) {
+    AssertionError unused = ExpectFailure.expectFailureAbout(DEFAULT_SUBJECT_FACTORY, callback);
+  }
+
+  @Test
+  public void testNumericPrimitiveTypes() {
+    byte byte42 = (byte) 42;
+    short short42 = (short) 42;
+    char char42 = (char) 42;
+    int int42 = 42;
+    long long42 = (long) 42;
+
+    ImmutableSet<Object> fortyTwos =
+        ImmutableSet.<Object>of(byte42, short42, char42, int42, long42);
+    for (Object actual : fortyTwos) {
+      for (Object expected : fortyTwos) {
+        assertThat(actual).isEqualTo(expected);
+      }
+    }
+
+    ImmutableSet<Object> fortyTwosNoChar = ImmutableSet.<Object>of(byte42, short42, int42, long42);
+    for (Object actual : fortyTwosNoChar) {
+      for (Object expected : fortyTwosNoChar) {
+        ExpectFailure.SimpleSubjectBuilderCallback<Subject, Object> actualFirst =
+            new ExpectFailure.SimpleSubjectBuilderCallback<Subject, Object>() {
+              @Override
+              public void invokeAssertion(SimpleSubjectBuilder<Subject, Object> expect) {
+                expect.that(actual).isNotEqualTo(expected);
+              }
+            };
+        ExpectFailure.SimpleSubjectBuilderCallback<Subject, Object> expectedFirst =
+            new ExpectFailure.SimpleSubjectBuilderCallback<Subject, Object>() {
+              @Override
+              public void invokeAssertion(SimpleSubjectBuilder<Subject, Object> expect) {
+                expect.that(expected).isNotEqualTo(actual);
+              }
+            };
+        expectFailure(actualFirst);
+        expectFailure(expectedFirst);
+      }
+    }
+
+    byte byte41 = (byte) 41;
+    short short41 = (short) 41;
+    char char41 = (char) 41;
+    int int41 = 41;
+    long long41 = (long) 41;
+
+    ImmutableSet<Object> fortyOnes =
+        ImmutableSet.<Object>of(byte41, short41, char41, int41, long41);
+
+    for (Object first : fortyTwos) {
+      for (Object second : fortyOnes) {
+        assertThat(first).isNotEqualTo(second);
+        assertThat(second).isNotEqualTo(first);
+      }
+    }
+  }
+
+  private IntegerSubject expectFailureWhenTestingThat(Integer actual) {
+    return expectFailure.whenTesting().that(actual);
+  }
+}
diff --git a/core/src/test/java/com/google/common/truth/StringSubjectTest.java b/core/src/test/java/com/google/common/truth/StringSubjectTest.java
index ec247402..feb85d60 100644
--- a/core/src/test/java/com/google/common/truth/StringSubjectTest.java
+++ b/core/src/test/java/com/google/common/truth/StringSubjectTest.java
@@ -128,6 +128,7 @@ public class StringSubjectTest extends BaseSubjectTestCase {
   }
 
   @Test
+  @SuppressWarnings("TruthSelfEquals")
   public void stringEquality() {
     assertThat("abc").isEqualTo("abc");
   }
@@ -215,6 +216,16 @@ public class StringSubjectTest extends BaseSubjectTestCase {
         .contains("Looks like you want to use .isEqualTo() for an exact equality assertion.");
   }
 
+  @Test
+  public void stringMatchesStringLiteralFailButContainsMatchSuccess() {
+    expectFailureWhenTestingThat("aba").matches("[b]");
+    assertFailureValue("expected to match", "[b]");
+    assertFailureValue("but was", "aba");
+    assertThat(expectFailure.getFailure())
+        .factKeys()
+        .contains("Did you mean to call containsMatch() instead of match()?");
+  }
+
   @Test
   @GwtIncompatible("Pattern")
   public void stringMatchesPattern() {
@@ -248,6 +259,17 @@ public class StringSubjectTest extends BaseSubjectTestCase {
                 + " Pattern.quote().");
   }
 
+  @Test
+  @GwtIncompatible("Pattern")
+  public void stringMatchesPatternLiteralFailButContainsMatchSuccess() {
+    expectFailureWhenTestingThat("aba").matches(Pattern.compile("[b]"));
+    assertFailureValue("expected to match", "[b]");
+    assertFailureValue("but was", "aba");
+    assertThat(expectFailure.getFailure())
+        .factKeys()
+        .contains("Did you mean to call containsMatch() instead of match()?");
+  }
+
   @Test
   public void stringDoesNotMatchString() {
     assertThat("abcaqadev").doesNotMatch(".*aaa.*");
diff --git a/core/src/test/java/com/google/common/truth/SubjectTest.java b/core/src/test/java/com/google/common/truth/SubjectTest.java
index 9544f52f..48b74b3d 100644
--- a/core/src/test/java/com/google/common/truth/SubjectTest.java
+++ b/core/src/test/java/com/google/common/truth/SubjectTest.java
@@ -42,7 +42,7 @@ import java.lang.reflect.Modifier;
 import java.math.BigDecimal;
 import java.util.Arrays;
 import java.util.Iterator;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.junit.runners.JUnit4;
diff --git a/core/src/test/java/com/google/common/truth/TestCorrespondences.java b/core/src/test/java/com/google/common/truth/TestCorrespondences.java
index d2488d5c..0c5c3af7 100644
--- a/core/src/test/java/com/google/common/truth/TestCorrespondences.java
+++ b/core/src/test/java/com/google/common/truth/TestCorrespondences.java
@@ -23,7 +23,7 @@ import com.google.common.base.Objects;
 import com.google.common.base.Splitter;
 import com.google.common.primitives.Ints;
 import java.util.List;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /** {@link Correspondence} implementations for testing purposes. */
 final class TestCorrespondences {
diff --git a/core/src/test/java/com/google/common/truth/extension/EmployeeSubject.java b/core/src/test/java/com/google/common/truth/extension/EmployeeSubject.java
index 224bf653..72c6a177 100644
--- a/core/src/test/java/com/google/common/truth/extension/EmployeeSubject.java
+++ b/core/src/test/java/com/google/common/truth/extension/EmployeeSubject.java
@@ -23,7 +23,7 @@ import com.google.common.truth.FailureMetadata;
 import com.google.common.truth.LongSubject;
 import com.google.common.truth.StringSubject;
 import com.google.common.truth.Subject;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * A <a href="https://github.com/google/truth">Truth</a> subject for {@link Employee}.
diff --git a/core/src/test/java/com/google/common/truth/gwt/Inventory.java b/core/src/test/java/com/google/common/truth/gwt/Inventory.java
index 63e2fbcc..61002ddc 100644
--- a/core/src/test/java/com/google/common/truth/gwt/Inventory.java
+++ b/core/src/test/java/com/google/common/truth/gwt/Inventory.java
@@ -23,13 +23,19 @@ import com.google.common.truth.DoubleSubject;
 import com.google.common.truth.FailureStrategy;
 import com.google.common.truth.FloatSubject;
 import com.google.common.truth.GuavaOptionalSubject;
+import com.google.common.truth.IntStreamSubject;
 import com.google.common.truth.IntegerSubject;
 import com.google.common.truth.IterableSubject;
+import com.google.common.truth.LongStreamSubject;
 import com.google.common.truth.LongSubject;
 import com.google.common.truth.MapSubject;
 import com.google.common.truth.MultimapSubject;
 import com.google.common.truth.MultisetSubject;
 import com.google.common.truth.ObjectArraySubject;
+import com.google.common.truth.OptionalDoubleSubject;
+import com.google.common.truth.OptionalIntSubject;
+import com.google.common.truth.OptionalLongSubject;
+import com.google.common.truth.OptionalSubject;
 import com.google.common.truth.Ordered;
 import com.google.common.truth.PrimitiveBooleanArraySubject;
 import com.google.common.truth.PrimitiveByteArraySubject;
@@ -39,12 +45,13 @@ import com.google.common.truth.PrimitiveFloatArraySubject;
 import com.google.common.truth.PrimitiveIntArraySubject;
 import com.google.common.truth.PrimitiveLongArraySubject;
 import com.google.common.truth.PrimitiveShortArraySubject;
+import com.google.common.truth.StreamSubject;
 import com.google.common.truth.StringSubject;
 import com.google.common.truth.Subject;
 import com.google.common.truth.TableSubject;
 import com.google.common.truth.ThrowableSubject;
 import com.google.common.truth.Truth;
-import com.google.common.truth.TruthJUnit;
+import com.google.common.truth.Truth8;
 
 /**
  * Static references to a variety of classes to force their loading during the {@link TruthGwtTest}.
@@ -59,12 +66,18 @@ public class Inventory {
   FloatSubject floatSubject;
   GuavaOptionalSubject guavaOptionalSubject;
   IntegerSubject integerSubject;
+  IntStreamSubject intStreamSubject;
   IterableSubject iterableSubject;
   LongSubject longSubject;
+  LongStreamSubject longStreamSubject;
   MapSubject mapSubject;
   MultimapSubject multimapSubject;
   MultisetSubject multisetSubject;
   ObjectArraySubject<?> objectArraySubject;
+  OptionalSubject optionalSubject;
+  OptionalDoubleSubject optionalDoubleSubject;
+  OptionalIntSubject optionalIntSubject;
+  OptionalLongSubject optionalLongSubject;
   Ordered ordered;
   PrimitiveBooleanArraySubject primitiveBooleanArraySubject;
   PrimitiveByteArraySubject primitiveByteArraySubject;
@@ -74,11 +87,12 @@ public class Inventory {
   PrimitiveIntArraySubject primitiveIntArraySubject;
   PrimitiveLongArraySubject primitiveLongArraySubject;
   PrimitiveShortArraySubject primitiveShortArraySubject;
+  StreamSubject streamSubject;
   StringSubject stringSubject;
   Subject.Factory<?, ?> subjectFactory;
   Subject subject;
   TableSubject tableSubject;
   ThrowableSubject throwableSubject;
   Truth truth;
-  TruthJUnit truthJUnit;
+  Truth8 truth8;
 }
diff --git a/core/src/test/java/com/google/common/truth/gwt/TruthGwtTest.java b/core/src/test/java/com/google/common/truth/gwt/TruthGwtTest.java
index 55d4aa91..aab6aa12 100644
--- a/core/src/test/java/com/google/common/truth/gwt/TruthGwtTest.java
+++ b/core/src/test/java/com/google/common/truth/gwt/TruthGwtTest.java
@@ -52,6 +52,7 @@ public class TruthGwtTest extends com.google.gwt.junit.client.GWTTestCase {
     }
   }
 
+  @SuppressWarnings("TruthSelfEquals")
   public void testInteger() {
     assertThat(457923).isEqualTo(457923);
     try {
diff --git a/core/src/test/java/com/google/common/truth/gwt/TruthTest.gwt.xml b/core/src/test/java/com/google/common/truth/gwt/TruthTest.gwt.xml
index ee9caccb..a0362fbd 100644
--- a/core/src/test/java/com/google/common/truth/gwt/TruthTest.gwt.xml
+++ b/core/src/test/java/com/google/common/truth/gwt/TruthTest.gwt.xml
@@ -3,6 +3,5 @@
   <inherits name="com.google.common.collect.Collect"/>
   <inherits name="com.google.common.primitives.Primitives"/>
   <inherits name="com.google.common.truth.Truth"/>
-  <!-- TODO(cpovirk): Test Truth8. -->
   <inherits name="com.google.gwt.junit.JUnit"/>
 </module>
diff --git a/extensions/java8/pom.xml b/extensions/java8/pom.xml
index 951dc43a..b6f38c54 100644
--- a/extensions/java8/pom.xml
+++ b/extensions/java8/pom.xml
@@ -10,19 +10,15 @@
     <version>HEAD-SNAPSHOT</version>
   </parent>
   <artifactId>truth-java8-extension</artifactId>
-  <name>Truth Extension for Java8</name>
+  <name>Obsolete Truth Extension for Java8</name>
   <description>
-    An extension for the Truth test assertion framework supporting Java8 types and structures
+    Obsolete, empty artifact that merely pulls in the main `truth` artifact: Assertions for Java 8 types are now part of that main artifact.
   </description>
   <dependencies>
     <dependency>
       <groupId>com.google.truth</groupId>
       <artifactId>truth</artifactId>
     </dependency>
-    <dependency>
-      <groupId>org.checkerframework</groupId>
-      <artifactId>checker-qual</artifactId>
-    </dependency>
   </dependencies>
   <build>
     <resources>
diff --git a/extensions/java8/src/main/java/com/google/common/truth/StreamSubject.java b/extensions/java8/src/main/java/com/google/common/truth/StreamSubject.java
deleted file mode 100644
index f3e90cd6..00000000
--- a/extensions/java8/src/main/java/com/google/common/truth/StreamSubject.java
+++ /dev/null
@@ -1,264 +0,0 @@
-/*
- * Copyright (c) 2016 Google, Inc.
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- * http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-package com.google.common.truth;
-
-import static java.util.stream.Collectors.toCollection;
-
-import com.google.errorprone.annotations.CanIgnoreReturnValue;
-import com.google.errorprone.annotations.DoNotCall;
-import java.util.ArrayList;
-import java.util.Comparator;
-import java.util.List;
-import java.util.stream.Stream;
-import org.checkerframework.checker.nullness.qual.Nullable;
-
-/**
- * Propositions for {@link Stream} subjects.
- *
- * <p><b>Note:</b> the wrapped stream will be drained immediately into a private collection to
- * provide more readable failure messages. You should not use this class if you intend to leave the
- * stream un-consumed or if the stream is <i>very</i> large or infinite.
- *
- * <p>If you intend to make multiple assertions on the same stream of data you should instead first
- * collect the contents of the stream into a collection, and then assert directly on that.
- *
- * <p>For very large or infinite streams you may want to first {@linkplain Stream#limit limit} the
- * stream before asserting on it.
- *
- * @author Kurt Alfred Kluever
- */
-@SuppressWarnings("deprecation") // TODO(b/134064106): design an alternative to no-arg check()
-public final class StreamSubject extends Subject {
-
-  private final List<?> actualList;
-
-  private StreamSubject(FailureMetadata failureMetadata, @Nullable Stream<?> stream) {
-    super(failureMetadata, stream);
-    this.actualList = (stream == null) ? null : stream.collect(toCollection(ArrayList::new));
-  }
-
-  @Override
-  protected String actualCustomStringRepresentation() {
-    return String.valueOf(actualList);
-  }
-
-  public static Subject.Factory<StreamSubject, Stream<?>> streams() {
-    return StreamSubject::new;
-  }
-
-  /** Fails if the subject is not empty. */
-  public void isEmpty() {
-    check().that(actualList).isEmpty();
-  }
-
-  /** Fails if the subject is empty. */
-  public void isNotEmpty() {
-    check().that(actualList).isNotEmpty();
-  }
-
-  /**
-   * Fails if the subject does not have the given size.
-   *
-   * <p>If you'd like to check that your stream contains more than {@link Integer#MAX_VALUE}
-   * elements, use {@code assertThat(stream.count()).isEqualTo(...)}.
-   */
-  public void hasSize(int expectedSize) {
-    check().that(actualList).hasSize(expectedSize);
-  }
-
-  /** Fails if the subject does not contain the given element. */
-  public void contains(@Nullable Object element) {
-    check().that(actualList).contains(element);
-  }
-
-  /** Fails if the subject contains the given element. */
-  public void doesNotContain(@Nullable Object element) {
-    check().that(actualList).doesNotContain(element);
-  }
-
-  /** Fails if the subject contains duplicate elements. */
-  public void containsNoDuplicates() {
-    check().that(actualList).containsNoDuplicates();
-  }
-
-  /** Fails if the subject does not contain at least one of the given elements. */
-  public void containsAnyOf(
-      @Nullable Object first, @Nullable Object second, @Nullable Object @Nullable ... rest) {
-    check().that(actualList).containsAnyOf(first, second, rest);
-  }
-
-  /** Fails if the subject does not contain at least one of the given elements. */
-  public void containsAnyIn(Iterable<?> expected) {
-    check().that(actualList).containsAnyIn(expected);
-  }
-
-  /**
-   * Fails if the subject does not contain all of the given elements. If an element appears more
-   * than once in the given elements, then it must appear at least that number of times in the
-   * actual elements.
-   *
-   * <p>To also test that the contents appear in the given order, make a call to {@code inOrder()}
-   * on the object returned by this method. The expected elements must appear in the given order
-   * within the actual elements, but they are not required to be consecutive.
-   */
-  @CanIgnoreReturnValue
-  public Ordered containsAtLeast(
-      @Nullable Object first, @Nullable Object second, @Nullable Object @Nullable ... rest) {
-    return check().that(actualList).containsAtLeast(first, second, rest);
-  }
-
-  /**
-   * Fails if the subject does not contain all of the given elements. If an element appears more
-   * than once in the given elements, then it must appear at least that number of times in the
-   * actual elements.
-   *
-   * <p>To also test that the contents appear in the given order, make a call to {@code inOrder()}
-   * on the object returned by this method. The expected elements must appear in the given order
-   * within the actual elements, but they are not required to be consecutive.
-   */
-  @CanIgnoreReturnValue
-  public Ordered containsAtLeastElementsIn(Iterable<?> expected) {
-    return check().that(actualList).containsAtLeastElementsIn(expected);
-  }
-
-  // TODO(cpovirk): Add array overload of contains*ElementsIn methods? Also for int and long stream.
-
-  /**
-   * Fails if the subject does not contain exactly the given elements.
-   *
-   * <p>Multiplicity is respected. For example, an object duplicated exactly 3 times in the
-   * parameters asserts that the object must likewise be duplicated exactly 3 times in the subject.
-   *
-   * <p>To also test that the contents appear in the given order, make a call to {@code inOrder()}
-   * on the object returned by this method.
-   */
-  @CanIgnoreReturnValue
-  /*
-   * We need to call containsExactly, not containsExactlyElementsIn, to get the handling we want for
-   * containsExactly(null).
-   */
-  @SuppressWarnings("ContainsExactlyVariadic")
-  public Ordered containsExactly(@Nullable Object @Nullable ... varargs) {
-    return check().that(actualList).containsExactly(varargs);
-  }
-
-  /**
-   * Fails if the subject does not contain exactly the given elements.
-   *
-   * <p>Multiplicity is respected. For example, an object duplicated exactly 3 times in the
-   * parameters asserts that the object must likewise be duplicated exactly 3 times in the subject.
-   *
-   * <p>To also test that the contents appear in the given order, make a call to {@code inOrder()}
-   * on the object returned by this method.
-   */
-  @CanIgnoreReturnValue
-  public Ordered containsExactlyElementsIn(Iterable<?> expected) {
-    return check().that(actualList).containsExactlyElementsIn(expected);
-  }
-
-  /**
-   * Fails if the subject contains any of the given elements. (Duplicates are irrelevant to this
-   * test, which fails if any of the actual elements equal any of the excluded.)
-   */
-  public void containsNoneOf(
-      @Nullable Object first, @Nullable Object second, @Nullable Object @Nullable ... rest) {
-    check().that(actualList).containsNoneOf(first, second, rest);
-  }
-
-  /**
-   * Fails if the subject contains any of the given elements. (Duplicates are irrelevant to this
-   * test, which fails if any of the actual elements equal any of the excluded.)
-   */
-  public void containsNoneIn(Iterable<?> excluded) {
-    check().that(actualList).containsNoneIn(excluded);
-  }
-
-  /**
-   * Fails if the subject is not strictly ordered, according to the natural ordering of its
-   * elements. Strictly ordered means that each element in the stream is <i>strictly</i> greater
-   * than the element that preceded it.
-   *
-   * @throws ClassCastException if any pair of elements is not mutually Comparable
-   * @throws NullPointerException if any element is null
-   */
-  public void isInStrictOrder() {
-    check().that(actualList).isInStrictOrder();
-  }
-
-  /**
-   * Fails if the subject is not strictly ordered, according to the given comparator. Strictly
-   * ordered means that each element in the stream is <i>strictly</i> greater than the element that
-   * preceded it.
-   *
-   * @throws ClassCastException if any pair of elements is not mutually Comparable
-   */
-  public void isInStrictOrder(Comparator<?> comparator) {
-    check().that(actualList).isInStrictOrder(comparator);
-  }
-
-  /**
-   * Fails if the subject is not ordered, according to the natural ordering of its elements. Ordered
-   * means that each element in the stream is greater than or equal to the element that preceded it.
-   *
-   * @throws ClassCastException if any pair of elements is not mutually Comparable
-   * @throws NullPointerException if any element is null
-   */
-  public void isInOrder() {
-    check().that(actualList).isInOrder();
-  }
-
-  /**
-   * Fails if the subject is not ordered, according to the given comparator. Ordered means that each
-   * element in the stream is greater than or equal to the element that preceded it.
-   *
-   * @throws ClassCastException if any pair of elements is not mutually Comparable
-   */
-  public void isInOrder(Comparator<?> comparator) {
-    check().that(actualList).isInOrder(comparator);
-  }
-
-  /**
-   * @deprecated {@code streamA.isEqualTo(streamB)} always fails, except when passed the exact same
-   *     stream reference
-   */
-  @Override
-  @DoNotCall(
-      "StreamSubject.isEqualTo() is not supported because Streams do not have well-defined"
-          + " equality semantics")
-  @Deprecated
-  public void isEqualTo(@Nullable Object expected) {
-    throw new UnsupportedOperationException(
-        "StreamSubject.isEqualTo() is not supported because Streams do not have well-defined"
-            + " equality semantics");
-  }
-
-  /**
-   * @deprecated {@code streamA.isNotEqualTo(streamB)} always passes, except when passed the exact
-   *     same stream reference
-   */
-  @Override
-  @DoNotCall(
-      "StreamSubject.isNotEqualTo() is not supported because Streams do not have well-defined"
-          + " equality semantics")
-  @Deprecated
-  public void isNotEqualTo(@Nullable Object unexpected) {
-    throw new UnsupportedOperationException(
-        "StreamSubject.isNotEqualTo() is not supported because Streams do not have well-defined"
-            + " equality semantics");
-  }
-
-  // TODO(user): Do we want to support comparingElementsUsing() on StreamSubject?
-}
diff --git a/extensions/java8/src/main/java/com/google/common/truth/Truth8.gwt.xml b/extensions/java8/src/main/java/com/google/common/truth/Truth8.gwt.xml
deleted file mode 100644
index f9aa5adf..00000000
--- a/extensions/java8/src/main/java/com/google/common/truth/Truth8.gwt.xml
+++ /dev/null
@@ -1,35 +0,0 @@
-<module>
-<source path="">
-  <!-- Hack to keep collect from hiding collect.testing supersource: -->
-  <exclude name="**/testing/**"/>
-</source>
-
-<!--
-    We used to set this only for packages that had manual supersource. That
-    worked everywhere that I know of except for one place: when running the GWT
-    util.concurrent tests under Guava.
-
-    The problem is that GWT responds poorly to two .gwt.xml files in the same
-    Java package; see https://goo.gl/pRV3Yn for details.
-
-    The summary is that it ignores one file in favor of the other.
-    util.concurrent, like nearly all our packages, has two .gwt.xml files: one
-    for prod and one for tests. However, unlike our other packages, as of this
-    writing it has test supersource but no prod supersource.
-
-    GWT happens to use the prod .gwt.xml, so it looks for no supersource for
-    tests, either. This causes it to fail to find AtomicLongMapTest.
-
-    Our workaround is to tell GWT that util.concurrent and all other packages
-    have prod supersource, even if they have none. GWT is happy to ignore us
-    when we specify a nonexistent path.
-
-    (I hope that this workaround does not cause its own problems in the future.)
--->
-<super-source path="super"/>
-
-<inherits name="com.google.common.annotations.Annotations" />
-<inherits name="com.google.common.truth.Truth" />
-<inherits name="com.google.gwt.core.Core" />
-<inherits name="com.google.gwt.user.User" />
-</module>
diff --git a/extensions/java8/src/test/java/com/google/common/truth/IntStreamSubjectTest.java b/extensions/java8/src/test/java/com/google/common/truth/IntStreamSubjectTest.java
index 9fc8ee41..84a0e102 100644
--- a/extensions/java8/src/test/java/com/google/common/truth/IntStreamSubjectTest.java
+++ b/extensions/java8/src/test/java/com/google/common/truth/IntStreamSubjectTest.java
@@ -18,7 +18,7 @@ package com.google.common.truth;
 import static com.google.common.truth.FailureAssertions.assertFailureKeys;
 import static com.google.common.truth.FailureAssertions.assertFailureValue;
 import static com.google.common.truth.IntStreamSubject.intStreams;
-import static com.google.common.truth.Truth8.assertThat;
+import static com.google.common.truth.Truth.assertThat;
 import static java.util.Arrays.asList;
 import static org.junit.Assert.fail;
 
@@ -37,6 +37,7 @@ import org.junit.runners.JUnit4;
 public final class IntStreamSubjectTest {
 
   @Test
+  @SuppressWarnings("TruthSelfEquals")
   public void testIsEqualTo() throws Exception {
     IntStream stream = IntStream.of(42);
     assertThat(stream).isEqualTo(stream);
@@ -66,6 +67,7 @@ public final class IntStreamSubjectTest {
   }
 
   @Test
+  @SuppressWarnings("TruthSelfEquals")
   public void testIsSameInstanceAs() throws Exception {
     IntStream stream = IntStream.of(1);
     assertThat(stream).isSameInstanceAs(stream);
diff --git a/extensions/java8/src/test/java/com/google/common/truth/LongStreamSubjectTest.java b/extensions/java8/src/test/java/com/google/common/truth/LongStreamSubjectTest.java
index 52c36ea0..41026046 100644
--- a/extensions/java8/src/test/java/com/google/common/truth/LongStreamSubjectTest.java
+++ b/extensions/java8/src/test/java/com/google/common/truth/LongStreamSubjectTest.java
@@ -18,7 +18,7 @@ package com.google.common.truth;
 import static com.google.common.truth.FailureAssertions.assertFailureKeys;
 import static com.google.common.truth.FailureAssertions.assertFailureValue;
 import static com.google.common.truth.LongStreamSubject.longStreams;
-import static com.google.common.truth.Truth8.assertThat;
+import static com.google.common.truth.Truth.assertThat;
 import static java.util.Arrays.asList;
 import static org.junit.Assert.fail;
 
@@ -37,6 +37,7 @@ import org.junit.runners.JUnit4;
 public final class LongStreamSubjectTest {
 
   @Test
+  @SuppressWarnings("TruthSelfEquals")
   public void testIsEqualTo() throws Exception {
     LongStream stream = LongStream.of(42);
     assertThat(stream).isEqualTo(stream);
@@ -66,6 +67,7 @@ public final class LongStreamSubjectTest {
   }
 
   @Test
+  @SuppressWarnings("TruthSelfEquals")
   public void testIsSameInstanceAs() throws Exception {
     LongStream stream = LongStream.of(1);
     assertThat(stream).isSameInstanceAs(stream);
diff --git a/extensions/java8/src/test/java/com/google/common/truth/OptionalDoubleSubjectTest.java b/extensions/java8/src/test/java/com/google/common/truth/OptionalDoubleSubjectTest.java
index 94490fa0..48154779 100644
--- a/extensions/java8/src/test/java/com/google/common/truth/OptionalDoubleSubjectTest.java
+++ b/extensions/java8/src/test/java/com/google/common/truth/OptionalDoubleSubjectTest.java
@@ -18,7 +18,6 @@ package com.google.common.truth;
 import static com.google.common.truth.ExpectFailure.assertThat;
 import static com.google.common.truth.OptionalDoubleSubject.optionalDoubles;
 import static com.google.common.truth.Truth.assertThat;
-import static com.google.common.truth.Truth8.assertThat;
 
 import java.util.OptionalDouble;
 import org.junit.Test;
diff --git a/extensions/java8/src/test/java/com/google/common/truth/OptionalIntSubjectTest.java b/extensions/java8/src/test/java/com/google/common/truth/OptionalIntSubjectTest.java
index 9c68a875..53b2c783 100644
--- a/extensions/java8/src/test/java/com/google/common/truth/OptionalIntSubjectTest.java
+++ b/extensions/java8/src/test/java/com/google/common/truth/OptionalIntSubjectTest.java
@@ -18,7 +18,6 @@ package com.google.common.truth;
 import static com.google.common.truth.ExpectFailure.assertThat;
 import static com.google.common.truth.OptionalIntSubject.optionalInts;
 import static com.google.common.truth.Truth.assertThat;
-import static com.google.common.truth.Truth8.assertThat;
 
 import java.util.OptionalInt;
 import org.junit.Test;
diff --git a/extensions/java8/src/test/java/com/google/common/truth/OptionalLongSubjectTest.java b/extensions/java8/src/test/java/com/google/common/truth/OptionalLongSubjectTest.java
index 211ed504..dc367889 100644
--- a/extensions/java8/src/test/java/com/google/common/truth/OptionalLongSubjectTest.java
+++ b/extensions/java8/src/test/java/com/google/common/truth/OptionalLongSubjectTest.java
@@ -18,7 +18,6 @@ package com.google.common.truth;
 import static com.google.common.truth.ExpectFailure.assertThat;
 import static com.google.common.truth.OptionalLongSubject.optionalLongs;
 import static com.google.common.truth.Truth.assertThat;
-import static com.google.common.truth.Truth8.assertThat;
 
 import java.util.OptionalLong;
 import org.junit.Test;
diff --git a/extensions/java8/src/test/java/com/google/common/truth/OptionalSubjectTest.java b/extensions/java8/src/test/java/com/google/common/truth/OptionalSubjectTest.java
index e1cdc566..757af0bd 100644
--- a/extensions/java8/src/test/java/com/google/common/truth/OptionalSubjectTest.java
+++ b/extensions/java8/src/test/java/com/google/common/truth/OptionalSubjectTest.java
@@ -18,7 +18,6 @@ package com.google.common.truth;
 import static com.google.common.truth.ExpectFailure.assertThat;
 import static com.google.common.truth.OptionalSubject.optionals;
 import static com.google.common.truth.Truth.assertThat;
-import static com.google.common.truth.Truth8.assertThat;
 import static org.junit.Assert.fail;
 
 import java.util.Optional;
diff --git a/extensions/java8/src/test/java/com/google/common/truth/PathSubjectTest.java b/extensions/java8/src/test/java/com/google/common/truth/PathSubjectTest.java
index 1e97f4d0..801dfd0c 100644
--- a/extensions/java8/src/test/java/com/google/common/truth/PathSubjectTest.java
+++ b/extensions/java8/src/test/java/com/google/common/truth/PathSubjectTest.java
@@ -15,7 +15,7 @@
  */
 package com.google.common.truth;
 
-import static com.google.common.truth.Truth8.assertThat;
+import static com.google.common.truth.Truth.assertThat;
 
 import java.nio.file.Paths;
 import org.junit.Test;
diff --git a/extensions/java8/src/test/java/com/google/common/truth/StreamSubjectTest.java b/extensions/java8/src/test/java/com/google/common/truth/StreamSubjectTest.java
index 3efc4866..cc1037d8 100644
--- a/extensions/java8/src/test/java/com/google/common/truth/StreamSubjectTest.java
+++ b/extensions/java8/src/test/java/com/google/common/truth/StreamSubjectTest.java
@@ -15,12 +15,12 @@
  */
 package com.google.common.truth;
 
+import static com.google.common.truth.ExpectFailure.assertThat;
 import static com.google.common.truth.FailureAssertions.assertFailureKeys;
 import static com.google.common.truth.FailureAssertions.assertFailureValue;
 import static com.google.common.truth.StreamSubject.streams;
-import static com.google.common.truth.Truth8.assertThat;
+import static com.google.common.truth.Truth.assertThat;
 import static java.util.Arrays.asList;
-import static org.junit.Assert.assertThrows;
 import static org.junit.Assert.fail;
 
 import java.util.stream.Stream;
@@ -33,22 +33,78 @@ import org.junit.runners.JUnit4;
  *
  * @author Kurt Alfred Kluever
  */
+// TODO: b/113905249 - Move this and other tests from extensions to core
 @RunWith(JUnit4.class)
 public final class StreamSubjectTest {
 
-  @SuppressWarnings({"DoNotCall", "deprecation"}) // test of a mistaken call
+  @SuppressWarnings({"deprecation", "TruthSelfEquals"}) // test of a possibly mistaken call
   @Test
-  public void testIsEqualTo() throws Exception {
+  public void testIsEqualToSameInstancePreviouslyConsumed() throws Exception {
     Stream<String> stream = Stream.of("hello");
-    assertThrows(UnsupportedOperationException.class, () -> assertThat(stream).isEqualTo(stream));
+    stream.forEach(e -> {}); // Consume it so that we can verify that isEqualTo still works
+    assertThat(stream).isEqualTo(stream);
   }
 
-  @SuppressWarnings({"DoNotCall", "deprecation"}) // test of a mistaken call
+  @SuppressWarnings({"deprecation", "TruthSelfEquals"}) // test of a possibly mistaken call
   @Test
-  public void testIsNotEqualTo() throws Exception {
+  public void testIsEqualToSameInstanceDoesNotConsume() throws Exception {
     Stream<String> stream = Stream.of("hello");
-    assertThrows(
-        UnsupportedOperationException.class, () -> assertThat(stream).isNotEqualTo(stream));
+    assertThat(stream).isEqualTo(stream);
+    assertThat(stream).containsExactly("hello");
+  }
+
+  @SuppressWarnings({
+    "deprecation", // test of a possibly mistaken call
+    "StreamToString", // not very useful but the best we can do
+  })
+  @Test
+  public void testIsEqualToFailurePreviouslyConsumed() throws Exception {
+    Stream<String> stream = Stream.of("hello");
+    stream.forEach(e -> {}); // Consume it so that we can verify that isEqualTo still works
+    AssertionError failure =
+        expectFailure(whenTesting -> whenTesting.that(stream).isEqualTo(Stream.of("hello")));
+    assertThat(failure)
+        .factValue("but was")
+        .isEqualTo("Stream that has already been operated upon or closed: " + stream);
+    assertThat(failure)
+        .hasMessageThat()
+        .contains("Warning: Stream equality is based on object identity.");
+  }
+
+  @SuppressWarnings("deprecation") // test of a possibly mistaken call
+  @Test
+  public void testIsEqualToFailureNotPreviouslyConsumed() throws Exception {
+    Stream<String> stream = Stream.of("hello");
+    AssertionError failure =
+        expectFailure(whenTesting -> whenTesting.that(stream).isEqualTo(Stream.of("hello")));
+    assertThat(failure).factValue("but was").isEqualTo("[hello]");
+    assertThat(failure)
+        .hasMessageThat()
+        .contains("Warning: Stream equality is based on object identity.");
+  }
+
+  @SuppressWarnings({
+    "deprecation", // test of a possibly mistaken call
+    "StreamToString", // not very useful but the best we can do
+  })
+  @Test
+  public void testIsNotEqualToSameInstance() throws Exception {
+    Stream<String> stream = Stream.of("hello");
+    stream.forEach(e -> {}); // Consume it so that we can verify that isNotEqualTo still works
+    AssertionError failure =
+        expectFailure(whenTesting -> whenTesting.that(stream).isNotEqualTo(stream));
+    assertThat(failure).factKeys().containsExactly("expected not to be");
+    assertThat(failure)
+        .factValue("expected not to be")
+        .isEqualTo("Stream that has already been operated upon or closed: " + stream);
+  }
+
+  @SuppressWarnings("deprecation") // test of a possibly mistaken call
+  @Test
+  public void testIsNotEqualToOtherInstance() throws Exception {
+    Stream<String> stream = Stream.of("hello");
+    stream.forEach(e -> {}); // Consume it so that we can verify that isNotEqualTo still works
+    assertThat(stream).isNotEqualTo(Stream.of("hello"));
   }
 
   @Test
@@ -68,6 +124,7 @@ public final class StreamSubjectTest {
   }
 
   @Test
+  @SuppressWarnings("TruthSelfEquals")
   public void testIsSameInstanceAs() throws Exception {
     Stream<String> stream = Stream.of("hello");
     assertThat(stream).isSameInstanceAs(stream);
@@ -102,8 +159,9 @@ public final class StreamSubjectTest {
 
   @Test
   public void testHasSize_fails() throws Exception {
-    AssertionError unused =
+    AssertionError failure =
         expectFailure(whenTesting -> whenTesting.that(Stream.of("hello")).hasSize(2));
+    assertThat(failure).factValue("value of").isEqualTo("stream.size()");
   }
 
   @Test
diff --git a/extensions/liteproto/pom.xml b/extensions/liteproto/pom.xml
index 7474ee5a..a70faa5d 100644
--- a/extensions/liteproto/pom.xml
+++ b/extensions/liteproto/pom.xml
@@ -25,8 +25,8 @@
       <artifactId>guava</artifactId>
     </dependency>
     <dependency>
-      <groupId>org.checkerframework</groupId>
-      <artifactId>checker-qual</artifactId>
+      <groupId>org.jspecify</groupId>
+      <artifactId>jspecify</artifactId>
     </dependency>
     <dependency>
       <groupId>com.google.auto.value</groupId>
diff --git a/extensions/liteproto/src/main/java/com/google/common/truth/extensions/proto/LiteProtoSubject.java b/extensions/liteproto/src/main/java/com/google/common/truth/extensions/proto/LiteProtoSubject.java
index 3a0774ee..0fcea474 100644
--- a/extensions/liteproto/src/main/java/com/google/common/truth/extensions/proto/LiteProtoSubject.java
+++ b/extensions/liteproto/src/main/java/com/google/common/truth/extensions/proto/LiteProtoSubject.java
@@ -27,7 +27,7 @@ import com.google.common.truth.Subject;
 import com.google.errorprone.annotations.CheckReturnValue;
 import com.google.protobuf.MessageLite;
 import java.util.regex.Pattern;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * Truth subjects for the Lite version of Protocol Buffers.
diff --git a/extensions/liteproto/src/main/java/com/google/common/truth/extensions/proto/LiteProtoTruth.java b/extensions/liteproto/src/main/java/com/google/common/truth/extensions/proto/LiteProtoTruth.java
index 94895d93..d3179b58 100644
--- a/extensions/liteproto/src/main/java/com/google/common/truth/extensions/proto/LiteProtoTruth.java
+++ b/extensions/liteproto/src/main/java/com/google/common/truth/extensions/proto/LiteProtoTruth.java
@@ -21,7 +21,7 @@ import static com.google.common.truth.Truth.assertAbout;
 import com.google.common.truth.Subject;
 import com.google.errorprone.annotations.CheckReturnValue;
 import com.google.protobuf.MessageLite;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * A set of static methods to begin a Truth assertion chain for the lite version of protocol
diff --git a/extensions/liteproto/src/test/java/com/google/common/truth/extensions/proto/LiteProtoSubjectTest.java b/extensions/liteproto/src/test/java/com/google/common/truth/extensions/proto/LiteProtoSubjectTest.java
index 372100e4..eba52260 100644
--- a/extensions/liteproto/src/test/java/com/google/common/truth/extensions/proto/LiteProtoSubjectTest.java
+++ b/extensions/liteproto/src/test/java/com/google/common/truth/extensions/proto/LiteProtoSubjectTest.java
@@ -30,7 +30,7 @@ import com.google.protobuf.MessageLite;
 import java.util.Arrays;
 import java.util.Collection;
 import java.util.regex.Pattern;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 import org.junit.Rule;
 import org.junit.Test;
 import org.junit.runner.RunWith;
diff --git a/extensions/proto/pom.xml b/extensions/proto/pom.xml
index 7c07acc5..d5285579 100644
--- a/extensions/proto/pom.xml
+++ b/extensions/proto/pom.xml
@@ -29,8 +29,8 @@
       <artifactId>guava</artifactId>
     </dependency>
     <dependency>
-      <groupId>org.checkerframework</groupId>
-      <artifactId>checker-qual</artifactId>
+      <groupId>org.jspecify</groupId>
+      <artifactId>jspecify</artifactId>
     </dependency>
     <dependency>
       <groupId>com.google.auto.value</groupId>
diff --git a/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/AnyUtils.java b/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/AnyUtils.java
index 34e1e3e7..454f50d1 100644
--- a/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/AnyUtils.java
+++ b/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/AnyUtils.java
@@ -69,8 +69,9 @@ class AnyUtils {
     return DEFAULT_EXTENSION_REGISTRY;
   }
 
-  /** Unpack an `Any` proto using the TypeRegistry and ExtensionRegistry on `config`. */
-  static Optional<Message> unpack(Message any, FluentEqualityConfig config) {
+  /** Unpack an `Any` proto using the given TypeRegistry and ExtensionRegistry. */
+  static Optional<Message> unpack(
+      Message any, TypeRegistry typeRegistry, ExtensionRegistry extensionRegistry) {
     Preconditions.checkArgument(
         any.getDescriptorForType().equals(Any.getDescriptor()),
         "Expected type google.protobuf.Any, but was: %s",
@@ -80,13 +81,12 @@ class AnyUtils {
     ByteString value = (ByteString) any.getField(valueFieldDescriptor());
 
     try {
-      Descriptor descriptor = config.useTypeRegistry().getDescriptorForTypeUrl(typeUrl);
+      Descriptor descriptor = typeRegistry.getDescriptorForTypeUrl(typeUrl);
       if (descriptor == null) {
         return Optional.absent();
       }
 
-      Message defaultMessage =
-          DynamicMessage.parseFrom(descriptor, value, config.useExtensionRegistry());
+      Message defaultMessage = DynamicMessage.parseFrom(descriptor, value, extensionRegistry);
       return Optional.of(defaultMessage);
     } catch (InvalidProtocolBufferException e) {
       return Optional.absent();
diff --git a/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/DiffResult.java b/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/DiffResult.java
index e6c0af64..990d350d 100644
--- a/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/DiffResult.java
+++ b/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/DiffResult.java
@@ -557,6 +557,9 @@ abstract class DiffResult extends RecursableDiffEntity.WithoutResultCode {
         case UNKNOWN_FIELD_DESCRIPTOR:
           printFieldValue(subScopeId.unknownFieldDescriptor(), o, sb);
           return;
+        case UNPACKED_ANY_VALUE_TYPE:
+          printFieldValue(AnyUtils.valueFieldDescriptor(), o, sb);
+          return;
       }
       throw new AssertionError(subScopeId.kind());
     }
diff --git a/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/FieldNumberTree.java b/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/FieldNumberTree.java
index d33e2fee..698b9d94 100644
--- a/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/FieldNumberTree.java
+++ b/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/FieldNumberTree.java
@@ -16,9 +16,12 @@
 
 package com.google.common.truth.extensions.proto;
 
+import com.google.common.base.Optional;
 import com.google.common.collect.Maps;
 import com.google.protobuf.Descriptors.FieldDescriptor;
+import com.google.protobuf.ExtensionRegistry;
 import com.google.protobuf.Message;
+import com.google.protobuf.TypeRegistry;
 import com.google.protobuf.UnknownFieldSet;
 import java.util.List;
 import java.util.Map;
@@ -62,7 +65,8 @@ final class FieldNumberTree {
     return children.containsKey(subScopeId);
   }
 
-  static FieldNumberTree fromMessage(Message message) {
+  static FieldNumberTree fromMessage(
+      Message message, TypeRegistry typeRegistry, ExtensionRegistry extensionRegistry) {
     FieldNumberTree tree = new FieldNumberTree();
 
     // Known fields.
@@ -72,15 +76,25 @@ final class FieldNumberTree {
       FieldNumberTree childTree = new FieldNumberTree();
       tree.children.put(subScopeId, childTree);
 
-      Object fieldValue = knownFieldValues.get(field);
-      if (field.getJavaType() == FieldDescriptor.JavaType.MESSAGE) {
-        if (field.isRepeated()) {
-          List<?> valueList = (List<?>) fieldValue;
-          for (Object value : valueList) {
-            childTree.merge(fromMessage((Message) value));
+      if (field.equals(AnyUtils.valueFieldDescriptor())) {
+        // Handle Any protos specially.
+        Optional<Message> unpackedAny = AnyUtils.unpack(message, typeRegistry, extensionRegistry);
+        if (unpackedAny.isPresent()) {
+          tree.children.put(
+              SubScopeId.ofUnpackedAnyValueType(unpackedAny.get().getDescriptorForType()),
+              fromMessage(unpackedAny.get(), typeRegistry, extensionRegistry));
+        }
+      } else {
+        Object fieldValue = knownFieldValues.get(field);
+        if (field.getJavaType() == FieldDescriptor.JavaType.MESSAGE) {
+          if (field.isRepeated()) {
+            List<?> valueList = (List<?>) fieldValue;
+            for (Object value : valueList) {
+              childTree.merge(fromMessage((Message) value, typeRegistry, extensionRegistry));
+            }
+          } else {
+            childTree.merge(fromMessage((Message) fieldValue, typeRegistry, extensionRegistry));
           }
-        } else {
-          childTree.merge(fromMessage((Message) fieldValue));
         }
       }
     }
@@ -91,11 +105,14 @@ final class FieldNumberTree {
     return tree;
   }
 
-  static FieldNumberTree fromMessages(Iterable<? extends Message> messages) {
+  static FieldNumberTree fromMessages(
+      Iterable<? extends Message> messages,
+      TypeRegistry typeRegistry,
+      ExtensionRegistry extensionRegistry) {
     FieldNumberTree tree = new FieldNumberTree();
     for (Message message : messages) {
       if (message != null) {
-        tree.merge(fromMessage(message));
+        tree.merge(fromMessage(message, typeRegistry, extensionRegistry));
       }
     }
     return tree;
diff --git a/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/FieldScopeImpl.java b/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/FieldScopeImpl.java
index 4acf9916..0eadd855 100644
--- a/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/FieldScopeImpl.java
+++ b/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/FieldScopeImpl.java
@@ -28,7 +28,9 @@ import com.google.common.base.Optional;
 import com.google.common.collect.Lists;
 import com.google.protobuf.Descriptors.Descriptor;
 import com.google.protobuf.Descriptors.FieldDescriptor;
+import com.google.protobuf.ExtensionRegistry;
 import com.google.protobuf.Message;
+import com.google.protobuf.TypeRegistry;
 import java.util.List;
 
 /**
@@ -62,13 +64,17 @@ abstract class FieldScopeImpl extends FieldScope {
   // Instantiation methods.
   //////////////////////////////////////////////////////////////////////////////////////////////////
 
-  static FieldScope createFromSetFields(Message message) {
+  static FieldScope createFromSetFields(
+      Message message, TypeRegistry typeRegistry, ExtensionRegistry extensionRegistry) {
     return create(
-        FieldScopeLogic.partialScope(message),
+        FieldScopeLogic.partialScope(message, typeRegistry, extensionRegistry),
         Functions.constant(String.format("FieldScopes.fromSetFields({%s})", message.toString())));
   }
 
-  static FieldScope createFromSetFields(Iterable<? extends Message> messages) {
+  static FieldScope createFromSetFields(
+      Iterable<? extends Message> messages,
+      TypeRegistry typeRegistry,
+      ExtensionRegistry extensionRegistry) {
     if (emptyOrAllNull(messages)) {
       return create(
           FieldScopeLogic.none(),
@@ -82,7 +88,8 @@ abstract class FieldScopeImpl extends FieldScope {
         getDescriptors(messages));
 
     return create(
-        FieldScopeLogic.partialScope(messages, optDescriptor.get()),
+        FieldScopeLogic.partialScope(
+            messages, optDescriptor.get(), typeRegistry, extensionRegistry),
         Functions.constant(String.format("FieldScopes.fromSetFields(%s)", formatList(messages))));
   }
 
diff --git a/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/FieldScopeLogic.java b/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/FieldScopeLogic.java
index 31fd0563..dfca1f80 100644
--- a/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/FieldScopeLogic.java
+++ b/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/FieldScopeLogic.java
@@ -28,7 +28,9 @@ import com.google.common.collect.ImmutableSet;
 import com.google.errorprone.annotations.ForOverride;
 import com.google.protobuf.Descriptors.Descriptor;
 import com.google.protobuf.Descriptors.FieldDescriptor;
+import com.google.protobuf.ExtensionRegistry;
 import com.google.protobuf.Message;
+import com.google.protobuf.TypeRegistry;
 import java.util.List;
 
 /**
@@ -267,14 +269,21 @@ abstract class FieldScopeLogic implements FieldScopeLogicContainer<FieldScopeLog
     }
   }
 
-  static FieldScopeLogic partialScope(Message message) {
+  static FieldScopeLogic partialScope(
+      Message message, TypeRegistry typeRegistry, ExtensionRegistry extensionRegistry) {
     return new RootPartialScopeLogic(
-        FieldNumberTree.fromMessage(message), message.toString(), message.getDescriptorForType());
+        FieldNumberTree.fromMessage(message, typeRegistry, extensionRegistry),
+        message.toString(),
+        message.getDescriptorForType());
   }
 
-  static FieldScopeLogic partialScope(Iterable<? extends Message> messages, Descriptor descriptor) {
+  static FieldScopeLogic partialScope(
+      Iterable<? extends Message> messages,
+      Descriptor descriptor,
+      TypeRegistry typeRegistry,
+      ExtensionRegistry extensionRegistry) {
     return new RootPartialScopeLogic(
-        FieldNumberTree.fromMessages(messages),
+        FieldNumberTree.fromMessages(messages, typeRegistry, extensionRegistry),
         Joiner.on(", ").useForNull("null").join(messages),
         descriptor);
   }
@@ -304,11 +313,18 @@ abstract class FieldScopeLogic implements FieldScopeLogicContainer<FieldScopeLog
 
     @Override
     final FieldScopeResult policyFor(Descriptor rootDescriptor, SubScopeId subScopeId) {
-      if (subScopeId.kind() == SubScopeId.Kind.UNKNOWN_FIELD_DESCRIPTOR) {
-        return FieldScopeResult.EXCLUDED_RECURSIVELY;
+      FieldDescriptor fieldDescriptor = null;
+      switch (subScopeId.kind()) {
+        case FIELD_DESCRIPTOR:
+          fieldDescriptor = subScopeId.fieldDescriptor();
+          break;
+        case UNPACKED_ANY_VALUE_TYPE:
+          fieldDescriptor = AnyUtils.valueFieldDescriptor();
+          break;
+        case UNKNOWN_FIELD_DESCRIPTOR:
+          return FieldScopeResult.EXCLUDED_RECURSIVELY;
       }
 
-      FieldDescriptor fieldDescriptor = subScopeId.fieldDescriptor();
       if (matchesFieldDescriptor(rootDescriptor, fieldDescriptor)) {
         return FieldScopeResult.of(/* included = */ true, isRecursive);
       }
diff --git a/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/FieldScopes.java b/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/FieldScopes.java
index 9b709e55..0ba6b440 100644
--- a/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/FieldScopes.java
+++ b/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/FieldScopes.java
@@ -19,7 +19,9 @@ import static com.google.common.collect.Lists.asList;
 import static com.google.common.truth.extensions.proto.FieldScopeUtil.asList;
 
 import com.google.protobuf.Descriptors.FieldDescriptor;
+import com.google.protobuf.ExtensionRegistry;
 import com.google.protobuf.Message;
+import com.google.protobuf.TypeRegistry;
 
 /** Factory class for {@link FieldScope} instances. */
 public final class FieldScopes {
@@ -66,7 +68,58 @@ public final class FieldScopes {
   // Alternatively II, add Scope.PARTIAL support to ProtoFluentEquals, but with a different name and
   // explicit documentation that it may cause issues with Proto 3.
   public static FieldScope fromSetFields(Message message) {
-    return FieldScopeImpl.createFromSetFields(message);
+    return fromSetFields(
+        message, AnyUtils.defaultTypeRegistry(), AnyUtils.defaultExtensionRegistry());
+  }
+
+  /**
+   * Returns a {@link FieldScope} which is constrained to precisely those specific field paths that
+   * are explicitly set in the message. Note that, for version 3 protobufs, such a {@link
+   * FieldScope} will omit fields in the provided message which are set to default values.
+   *
+   * <p>This can be used limit the scope of a comparison to a complex set of fields in a very brief
+   * statement. Often, {@code message} is the expected half of a comparison about to be performed.
+   *
+   * <p>Example usage:
+   *
+   * <pre>{@code
+   * Foo actual = Foo.newBuilder().setBar(3).setBaz(4).build();
+   * Foo expected = Foo.newBuilder().setBar(3).setBaz(5).build();
+   * // Fails, because actual.getBaz() != expected.getBaz().
+   * assertThat(actual).isEqualTo(expected);
+   *
+   * Foo scope = Foo.newBuilder().setBar(2).build();
+   * // Succeeds, because only the field 'bar' is compared.
+   * assertThat(actual).withPartialScope(FieldScopes.fromSetFields(scope)).isEqualTo(expected);
+   *
+   * }</pre>
+   *
+   * <p>The returned {@link FieldScope} does not respect repeated field indices nor map keys. For
+   * example, if the provided message sets different field values for different elements of a
+   * repeated field, like so:
+   *
+   * <pre>{@code
+   * sub_message: {
+   *   foo: "foo"
+   * }
+   * sub_message: {
+   *   bar: "bar"
+   * }
+   * }</pre>
+   *
+   * <p>The {@link FieldScope} will contain {@code sub_message.foo} and {@code sub_message.bar} for
+   * *all* repeated {@code sub_messages}, including those beyond index 1.
+   *
+   * <p>If there are {@code google.protobuf.Any} protos anywhere within these messages, they will be
+   * unpacked using the provided {@link TypeRegistry} and {@link ExtensionRegistry} to determine
+   * which fields within them should be compared.
+   *
+   * @see ProtoFluentAssertion#unpackingAnyUsing
+   * @since 1.2
+   */
+  public static FieldScope fromSetFields(
+      Message message, TypeRegistry typeRegistry, ExtensionRegistry extensionRegistry) {
+    return FieldScopeImpl.createFromSetFields(message, typeRegistry, extensionRegistry);
   }
 
   /**
@@ -89,7 +142,29 @@ public final class FieldScopes {
    * or the {@link FieldScope} for the merge of all the messages. These are equivalent.
    */
   public static FieldScope fromSetFields(Iterable<? extends Message> messages) {
-    return FieldScopeImpl.createFromSetFields(messages);
+    return fromSetFields(
+        messages, AnyUtils.defaultTypeRegistry(), AnyUtils.defaultExtensionRegistry());
+  }
+
+  /**
+   * Creates a {@link FieldScope} covering the fields set in every message in the provided list of
+   * messages, with the same semantics as in {@link #fromSetFields(Message)}.
+   *
+   * <p>This can be thought of as the union of the {@link FieldScope}s for each individual message,
+   * or the {@link FieldScope} for the merge of all the messages. These are equivalent.
+   *
+   * <p>If there are {@code google.protobuf.Any} protos anywhere within these messages, they will be
+   * unpacked using the provided {@link TypeRegistry} and {@link ExtensionRegistry} to determine
+   * which fields within them should be compared.
+   *
+   * @see ProtoFluentAssertion#unpackingAnyUsing
+   * @since 1.2
+   */
+  public static FieldScope fromSetFields(
+      Iterable<? extends Message> messages,
+      TypeRegistry typeRegistry,
+      ExtensionRegistry extensionRegistry) {
+    return FieldScopeImpl.createFromSetFields(messages, typeRegistry, extensionRegistry);
   }
 
   /**
diff --git a/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/FluentEqualityConfig.java b/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/FluentEqualityConfig.java
index 25efe721..b3c994a4 100644
--- a/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/FluentEqualityConfig.java
+++ b/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/FluentEqualityConfig.java
@@ -34,7 +34,7 @@ import com.google.protobuf.Descriptors.FieldDescriptor;
 import com.google.protobuf.ExtensionRegistry;
 import com.google.protobuf.Message;
 import com.google.protobuf.TypeRegistry;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * A specification for a {@link ProtoTruthMessageDifferencer} for comparing two individual
@@ -273,7 +273,11 @@ abstract class FluentEqualityConfig implements FieldScopeLogicContainer<FluentEq
     Builder builder = toBuilder().setHasExpectedMessages(true);
     if (compareExpectedFieldsOnly()) {
       builder.setCompareFieldsScope(
-          FieldScopeLogic.and(compareFieldsScope(), FieldScopes.fromSetFields(messages).logic()));
+          FieldScopeLogic.and(
+              compareFieldsScope(),
+              FieldScopeImpl.createFromSetFields(
+                      messages, useTypeRegistry(), useExtensionRegistry())
+                  .logic()));
     }
     return builder.build();
   }
diff --git a/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/IterableOfProtosSubject.java b/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/IterableOfProtosSubject.java
index b5f342bb..427fe4b9 100644
--- a/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/IterableOfProtosSubject.java
+++ b/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/IterableOfProtosSubject.java
@@ -34,7 +34,7 @@ import com.google.protobuf.TypeRegistry;
 import java.io.IOException;
 import java.util.Arrays;
 import java.util.Comparator;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * Truth subject for the iterables of protocol buffers.
diff --git a/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/IterableOfProtosUsingCorrespondence.java b/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/IterableOfProtosUsingCorrespondence.java
index 9c366f58..f7a15b35 100644
--- a/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/IterableOfProtosUsingCorrespondence.java
+++ b/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/IterableOfProtosUsingCorrespondence.java
@@ -19,7 +19,7 @@ import com.google.common.base.Function;
 import com.google.common.truth.Ordered;
 import com.google.errorprone.annotations.CanIgnoreReturnValue;
 import com.google.protobuf.Message;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * Comparison methods, which enforce the rules set in prior calls to {@link
diff --git a/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/MapWithProtoValuesFluentAssertion.java b/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/MapWithProtoValuesFluentAssertion.java
index f1aa7af1..f0ff0bed 100644
--- a/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/MapWithProtoValuesFluentAssertion.java
+++ b/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/MapWithProtoValuesFluentAssertion.java
@@ -22,7 +22,7 @@ import com.google.protobuf.ExtensionRegistry;
 import com.google.protobuf.Message;
 import com.google.protobuf.TypeRegistry;
 import java.util.Map;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * Fluent API to perform detailed, customizable comparison of maps containing protocol buffers as
diff --git a/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/MapWithProtoValuesSubject.java b/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/MapWithProtoValuesSubject.java
index 9248843e..662ddb0d 100644
--- a/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/MapWithProtoValuesSubject.java
+++ b/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/MapWithProtoValuesSubject.java
@@ -32,7 +32,7 @@ import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.List;
 import java.util.Map;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * Truth subject for maps with protocol buffers for values.
diff --git a/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/MultimapWithProtoValuesFluentAssertion.java b/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/MultimapWithProtoValuesFluentAssertion.java
index 838389b4..937bed8c 100644
--- a/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/MultimapWithProtoValuesFluentAssertion.java
+++ b/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/MultimapWithProtoValuesFluentAssertion.java
@@ -22,7 +22,7 @@ import com.google.protobuf.Descriptors.FieldDescriptor;
 import com.google.protobuf.ExtensionRegistry;
 import com.google.protobuf.Message;
 import com.google.protobuf.TypeRegistry;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * Fluent API to perform detailed, customizable comparison of {@link Multimap}s containing protocol
diff --git a/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/MultimapWithProtoValuesSubject.java b/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/MultimapWithProtoValuesSubject.java
index 8b37ee95..00bf5605 100644
--- a/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/MultimapWithProtoValuesSubject.java
+++ b/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/MultimapWithProtoValuesSubject.java
@@ -35,7 +35,7 @@ import com.google.protobuf.TypeRegistry;
 import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.List;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * Truth subject for {@link Multimap}s with protocol buffers for values.
diff --git a/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/ProtoFluentAssertion.java b/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/ProtoFluentAssertion.java
index 3047caba..6b5624f9 100644
--- a/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/ProtoFluentAssertion.java
+++ b/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/ProtoFluentAssertion.java
@@ -19,7 +19,7 @@ import com.google.protobuf.Descriptors.FieldDescriptor;
 import com.google.protobuf.ExtensionRegistry;
 import com.google.protobuf.Message;
 import com.google.protobuf.TypeRegistry;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * Fluent API to perform detailed, customizable comparison of Protocol buffers.
diff --git a/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/ProtoSubject.java b/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/ProtoSubject.java
index ba96333d..1388f900 100644
--- a/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/ProtoSubject.java
+++ b/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/ProtoSubject.java
@@ -29,7 +29,7 @@ import com.google.protobuf.ExtensionRegistry;
 import com.google.protobuf.Message;
 import com.google.protobuf.TypeRegistry;
 import java.util.Arrays;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * Truth subject for the full version of Protocol Buffers.
diff --git a/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/ProtoSubjectBuilder.java b/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/ProtoSubjectBuilder.java
index 0d813aa2..e7015c18 100644
--- a/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/ProtoSubjectBuilder.java
+++ b/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/ProtoSubjectBuilder.java
@@ -22,7 +22,7 @@ import com.google.common.truth.FailureMetadata;
 import com.google.protobuf.Message;
 import com.google.protobuf.MessageLite;
 import java.util.Map;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * {@link CustomSubjectBuilder} which aggregates all Proto-related {@link
diff --git a/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/ProtoTruth.java b/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/ProtoTruth.java
index fbdaa9e0..7daa0d1d 100644
--- a/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/ProtoTruth.java
+++ b/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/ProtoTruth.java
@@ -27,7 +27,7 @@ import com.google.common.truth.StandardSubjectBuilder;
 import com.google.protobuf.Message;
 import com.google.protobuf.MessageLite;
 import java.util.Map;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * A set of static methods to begin a Truth assertion chain for protocol buffers.
diff --git a/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/ProtoTruthMessageDifferencer.java b/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/ProtoTruthMessageDifferencer.java
index 5ccf6dc1..d5ec1a80 100644
--- a/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/ProtoTruthMessageDifferencer.java
+++ b/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/ProtoTruthMessageDifferencer.java
@@ -49,7 +49,7 @@ import java.util.LinkedHashSet;
 import java.util.List;
 import java.util.Map;
 import java.util.Set;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * Tool to differentiate two messages with the same {@link Descriptor}, subject to the rules set out
@@ -221,8 +221,10 @@ final class ProtoTruthMessageDifferencer {
     if (shouldCompareValue == FieldScopeResult.EXCLUDED_RECURSIVELY) {
       valueDiffResult = SingularField.ignored(name(AnyUtils.valueFieldDescriptor()));
     } else {
-      Optional<Message> unpackedActual = AnyUtils.unpack(actual, config);
-      Optional<Message> unpackedExpected = AnyUtils.unpack(expected, config);
+      Optional<Message> unpackedActual =
+          AnyUtils.unpack(actual, config.useTypeRegistry(), config.useExtensionRegistry());
+      Optional<Message> unpackedExpected =
+          AnyUtils.unpack(expected, config.useTypeRegistry(), config.useExtensionRegistry());
       if (unpackedActual.isPresent()
           && unpackedExpected.isPresent()
           && descriptorsMatch(unpackedActual.get(), unpackedExpected.get())) {
@@ -235,7 +237,10 @@ final class ProtoTruthMessageDifferencer {
                 shouldCompareValue == FieldScopeResult.EXCLUDED_NONRECURSIVELY,
                 AnyUtils.valueFieldDescriptor(),
                 name(AnyUtils.valueFieldDescriptor()),
-                config.subScope(rootDescriptor, AnyUtils.valueSubScopeId()));
+                config.subScope(
+                    rootDescriptor,
+                    SubScopeId.ofUnpackedAnyValueType(
+                        unpackedActual.get().getDescriptorForType())));
       } else {
         valueDiffResult =
             compareSingularValue(
@@ -959,7 +964,7 @@ final class ProtoTruthMessageDifferencer {
       FieldDescriptor fieldDescriptor, Object key, FieldDescriptor keyFieldDescriptor) {
     StringBuilder sb = new StringBuilder();
     try {
-      TextFormat.printFieldValue(keyFieldDescriptor, key, sb);
+      TextFormat.printer().printFieldValue(keyFieldDescriptor, key, sb);
     } catch (IOException impossible) {
       throw new AssertionError(impossible);
     }
diff --git a/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/SubScopeId.java b/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/SubScopeId.java
index 4860969e..925c1569 100644
--- a/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/SubScopeId.java
+++ b/extensions/proto/src/main/java/com/google/common/truth/extensions/proto/SubScopeId.java
@@ -17,13 +17,15 @@
 package com.google.common.truth.extensions.proto;
 
 import com.google.auto.value.AutoOneOf;
+import com.google.protobuf.Descriptors.Descriptor;
 import com.google.protobuf.Descriptors.FieldDescriptor;
 
 @AutoOneOf(SubScopeId.Kind.class)
 abstract class SubScopeId {
   enum Kind {
     FIELD_DESCRIPTOR,
-    UNKNOWN_FIELD_DESCRIPTOR;
+    UNKNOWN_FIELD_DESCRIPTOR,
+    UNPACKED_ANY_VALUE_TYPE;
   }
 
   abstract Kind kind();
@@ -32,6 +34,8 @@ abstract class SubScopeId {
 
   abstract UnknownFieldDescriptor unknownFieldDescriptor();
 
+  abstract Descriptor unpackedAnyValueType();
+
   /** Returns a short, human-readable version of this identifier. */
   final String shortName() {
     switch (kind()) {
@@ -41,6 +45,8 @@ abstract class SubScopeId {
             : fieldDescriptor().getName();
       case UNKNOWN_FIELD_DESCRIPTOR:
         return String.valueOf(unknownFieldDescriptor().fieldNumber());
+      case UNPACKED_ANY_VALUE_TYPE:
+        return AnyUtils.valueFieldDescriptor().getName();
     }
     throw new AssertionError(kind());
   }
@@ -52,4 +58,8 @@ abstract class SubScopeId {
   static SubScopeId of(UnknownFieldDescriptor unknownFieldDescriptor) {
     return AutoOneOf_SubScopeId.unknownFieldDescriptor(unknownFieldDescriptor);
   }
+
+  static SubScopeId ofUnpackedAnyValueType(Descriptor unpackedAnyValueType) {
+    return AutoOneOf_SubScopeId.unpackedAnyValueType(unpackedAnyValueType);
+  }
 }
diff --git a/extensions/proto/src/test/java/com/google/common/truth/extensions/proto/FieldScopesTest.java b/extensions/proto/src/test/java/com/google/common/truth/extensions/proto/FieldScopesTest.java
index fb0a07de..f99e7554 100644
--- a/extensions/proto/src/test/java/com/google/common/truth/extensions/proto/FieldScopesTest.java
+++ b/extensions/proto/src/test/java/com/google/common/truth/extensions/proto/FieldScopesTest.java
@@ -384,6 +384,96 @@ public class FieldScopesTest extends ProtoSubjectTestBase {
         .contains("modified: o_any_message.value.r_string[0]: \"foo\" -> \"bar\"");
   }
 
+  @Test
+  public void testAnyMessageComparingExpectedFieldsOnly() throws Exception {
+
+    String typeUrl =
+        isProto3()
+            ? "type.googleapis.com/com.google.common.truth.extensions.proto.SubTestMessage3"
+            : "type.googleapis.com/com.google.common.truth.extensions.proto.SubTestMessage2";
+
+    Message message = parse("o_any_message { [" + typeUrl + "]: { o_int: 2 } }");
+    Message eqMessage =
+        parse("o_any_message { [" + typeUrl + "]: { o_int: 2 r_string: \"foo\" } }");
+    Message diffMessage =
+        parse("o_any_message { [" + typeUrl + "]: { o_int: 3 r_string: \"bar\" } }");
+
+    expectThat(eqMessage)
+        .unpackingAnyUsing(getTypeRegistry(), getExtensionRegistry())
+        .comparingExpectedFieldsOnly()
+        .isEqualTo(message);
+    expectThat(diffMessage)
+        .unpackingAnyUsing(getTypeRegistry(), getExtensionRegistry())
+        .comparingExpectedFieldsOnly()
+        .isNotEqualTo(message);
+  }
+
+  @Test
+  public void testInvalidAnyMessageComparingExpectedFieldsOnly() throws Exception {
+
+    Message message = parse("o_any_message { type_url: 'invalid-type' value: 'abc123' }");
+    Message eqMessage = parse("o_any_message { type_url: 'invalid-type' value: 'abc123' }");
+    Message diffMessage = parse("o_any_message { type_url: 'invalid-type' value: 'def456' }");
+
+    expectThat(eqMessage)
+        .unpackingAnyUsing(getTypeRegistry(), getExtensionRegistry())
+        .comparingExpectedFieldsOnly()
+        .isEqualTo(message);
+    expectThat(diffMessage)
+        .unpackingAnyUsing(getTypeRegistry(), getExtensionRegistry())
+        .comparingExpectedFieldsOnly()
+        .isNotEqualTo(message);
+  }
+
+  @Test
+  public void testDifferentAnyMessagesComparingExpectedFieldsOnly() throws Exception {
+
+    // 'o_int' and 'o_float' have the same field numbers in both messages. However, to compare
+    // accurately, we incorporate the unpacked Descriptor type into the FieldNumberTree as well to
+    // disambiguate.
+    String typeUrl1 =
+        isProto3()
+            ? "type.googleapis.com/com.google.common.truth.extensions.proto.SubTestMessage3"
+            : "type.googleapis.com/com.google.common.truth.extensions.proto.SubTestMessage2";
+    String typeUrl2 =
+        isProto3()
+            ? "type.googleapis.com/com.google.common.truth.extensions.proto.SubSubTestMessage3"
+            : "type.googleapis.com/com.google.common.truth.extensions.proto.SubSubTestMessage2";
+
+    Message message =
+        parse(
+            "r_any_message { ["
+                + typeUrl1
+                + "]: { o_int: 2 } } r_any_message { ["
+                + typeUrl2
+                + "]: { o_float: 3.1 } }");
+    Message eqMessage =
+        parse(
+            "r_any_message { ["
+                + typeUrl1
+                + "]: { o_int: 2 o_float: 1.9 } } r_any_message { ["
+                + typeUrl2
+                + "]: { o_int: 5 o_float: 3.1 } }");
+    Message diffMessage =
+        parse(
+            "r_any_message { ["
+                + typeUrl1
+                + "]: { o_int: 5 o_float: 3.1 } } r_any_message { ["
+                + typeUrl2
+                + "]: { o_int: 2 o_float: 1.9 } }");
+
+    expectThat(eqMessage)
+        .unpackingAnyUsing(getTypeRegistry(), getExtensionRegistry())
+        .ignoringRepeatedFieldOrder()
+        .comparingExpectedFieldsOnly()
+        .isEqualTo(message);
+    expectThat(diffMessage)
+        .unpackingAnyUsing(getTypeRegistry(), getExtensionRegistry())
+        .ignoringRepeatedFieldOrder()
+        .comparingExpectedFieldsOnly()
+        .isNotEqualTo(message);
+  }
+
   @Test
   public void testIgnoringAllButOneFieldOfSubMessage() {
     // Consider all of TestMessage, but none of o_sub_test_message, except
diff --git a/extensions/proto/src/test/java/com/google/common/truth/extensions/proto/ProtoSubjectTestBase.java b/extensions/proto/src/test/java/com/google/common/truth/extensions/proto/ProtoSubjectTestBase.java
index cc7fd0a3..e686a4f4 100644
--- a/extensions/proto/src/test/java/com/google/common/truth/extensions/proto/ProtoSubjectTestBase.java
+++ b/extensions/proto/src/test/java/com/google/common/truth/extensions/proto/ProtoSubjectTestBase.java
@@ -45,7 +45,7 @@ import java.util.Collection;
 import java.util.Map;
 import java.util.Set;
 import java.util.regex.Pattern;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 import org.junit.Rule;
 
 /** Base class for testing {@link ProtoSubject} methods. */
diff --git a/extensions/re2j/src/main/java/com/google/common/truth/extensions/re2j/Re2jSubjects.java b/extensions/re2j/src/main/java/com/google/common/truth/extensions/re2j/Re2jSubjects.java
index 1dc387f5..ecaa6a61 100644
--- a/extensions/re2j/src/main/java/com/google/common/truth/extensions/re2j/Re2jSubjects.java
+++ b/extensions/re2j/src/main/java/com/google/common/truth/extensions/re2j/Re2jSubjects.java
@@ -21,7 +21,7 @@ import com.google.common.annotations.GwtIncompatible;
 import com.google.common.truth.FailureMetadata;
 import com.google.common.truth.Subject;
 import com.google.re2j.Pattern;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * Truth subjects for re2j regular expressions.
diff --git a/pom.xml b/pom.xml
index ac06274b..a7c35dce 100644
--- a/pom.xml
+++ b/pom.xml
@@ -14,13 +14,13 @@
     <project.reporting.outputEncoding>UTF-8</project.reporting.outputEncoding>
 
     <!-- Properties for multiple-artifact deps. -->
-    <auto-value.version>1.10.1</auto-value.version>
+    <auto-value.version>1.11.0</auto-value.version>
     <!--
       We have a separate property for each flavor of Guava (instead of a shared
       version without the -android and -jre suffixes) because that lets
       Dependabot update our Guava versions.
     -->
-    <guava.android.version>32.0.1-android</guava.android.version>
+    <guava.android.version>33.2.1-android</guava.android.version>
     <!--
       Also, we have this comment in between the 2 flavors of Guava. That's
       also to smooth the Dependabot update process: Dependabot generates a
@@ -28,9 +28,9 @@
       time, one gets submitted before the other, and
       the other ends up with a merge conflict. That requires reapprovals.
     -->
-    <guava.jre.version>32.0.0-jre</guava.jre.version>
-    <gwt.version>2.9.0</gwt.version>
-    <protobuf.version>3.23.2</protobuf.version>
+    <guava.jre.version>33.2.1-jre</guava.jre.version>
+    <gwt.version>2.10.0</gwt.version>
+    <protobuf.version>4.27.2</protobuf.version>
     <!-- Property for protobuf-lite protocArtifact, which isn't a "normal" Maven dep. -->
     <!-- TODO(cpovirk): Use protobuf.version instead. But that requires finding the new way to request the Lite runtime. -->
     <protobuf-lite.protoc.version>3.1.0</protobuf-lite.protoc.version>
@@ -71,9 +71,9 @@
         <version>${guava.android.version}</version>
       </dependency>
       <dependency>
-        <groupId>org.checkerframework</groupId>
-        <artifactId>checker-qual</artifactId>
-        <version>3.35.0</version>
+        <groupId>org.jspecify</groupId>
+        <artifactId>jspecify</artifactId>
+        <version>0.3.0</version>
       </dependency>
       <dependency>
         <groupId>junit</groupId>
@@ -81,7 +81,7 @@
         <version>4.13.2</version>
       </dependency>
       <dependency>
-        <groupId>com.google.gwt</groupId>
+        <groupId>org.gwtproject</groupId>
         <artifactId>gwt-user</artifactId>
         <version>${gwt.version}</version>
       </dependency>
@@ -103,7 +103,7 @@
       <dependency>
         <groupId>com.google.errorprone</groupId>
         <artifactId>error_prone_annotations</artifactId>
-        <version>2.19.1</version>
+        <version>2.28.0</version>
       </dependency>
       <dependency>
         <groupId>com.google.protobuf</groupId>
@@ -123,7 +123,7 @@
       <dependency>
         <groupId>org.ow2.asm</groupId>
         <artifactId>asm</artifactId>
-        <version>9.5</version>
+        <version>9.7</version>
       </dependency>
       <dependency>
         <groupId>com.google.jsinterop</groupId>
@@ -224,11 +224,11 @@
         <plugin>
           <groupId>org.apache.maven.plugins</groupId>
           <artifactId>maven-project-info-reports-plugin</artifactId>
-          <version>3.4.5</version>
+          <version>3.6.1</version>
         </plugin>
         <plugin>
           <artifactId>maven-javadoc-plugin</artifactId>
-          <version>3.5.0</version>
+          <version>3.7.0</version>
           <configuration>
             <additionalOptions>
               <additionalOption>-Xdoclint:-html ${conditionalJavadoc9PlusOptions}</additionalOption>
@@ -256,17 +256,19 @@
         </plugin>
         <plugin>
           <artifactId>maven-jar-plugin</artifactId>
-          <version>3.3.0</version> <!-- work around ubuntu bug -->
+          <version>3.4.2</version>
         </plugin>
         <plugin>
           <groupId>org.codehaus.mojo</groupId>
           <artifactId>animal-sniffer-maven-plugin</artifactId>
-          <version>1.23</version>
+          <version>1.24</version>
           <configuration>
+            <annotations>com.google.common.truth.IgnoreJRERequirement</annotations>
             <signature>
-              <groupId>org.codehaus.mojo.signature</groupId>
-              <artifactId>java16-sun</artifactId>
-              <version>1.10</version>
+              <groupId>com.toasttab.android</groupId>
+              <artifactId>gummy-bears-api-19</artifactId>
+              <version>0.6.1</version>
+              <!-- TODO(cpovirk): In principle, it would make sense to *also* test compatibility with JDK 1.8, since Truth also has JRE users. -->
             </signature>
           </configuration>
           <executions>
@@ -281,27 +283,28 @@
         </plugin>
         <plugin>
           <artifactId>maven-compiler-plugin</artifactId>
-          <version>3.11.0</version>
+          <version>3.13.0</version>
           <configuration>
             <source>1.8</source>
             <target>1.8</target>
+            <parameters>true</parameters>
           </configuration>
         </plugin>
         <plugin>
           <artifactId>maven-source-plugin</artifactId>
-          <version>3.3.0</version>
+          <version>3.3.1</version>
         </plugin>
         <plugin>
           <artifactId>maven-gpg-plugin</artifactId>
-          <version>3.1.0</version>
+          <version>3.2.4</version>
         </plugin>
         <plugin>
           <artifactId>maven-surefire-plugin</artifactId>
-          <version>3.1.2</version>
+          <version>3.3.0</version>
         </plugin>
         <plugin>
           <artifactId>maven-enforcer-plugin</artifactId>
-          <version>3.3.0</version>
+          <version>3.5.0</version>
           <executions>
             <execution>
               <id>enforce</id>
diff --git a/refactorings/src/main/java/com/google/common/truth/refactorings/CorrespondenceSubclassToFactoryCall.java b/refactorings/src/main/java/com/google/common/truth/refactorings/CorrespondenceSubclassToFactoryCall.java
index c10b24ea..7bd0076c 100644
--- a/refactorings/src/main/java/com/google/common/truth/refactorings/CorrespondenceSubclassToFactoryCall.java
+++ b/refactorings/src/main/java/com/google/common/truth/refactorings/CorrespondenceSubclassToFactoryCall.java
@@ -31,6 +31,7 @@ import static com.google.errorprone.BugPattern.SeverityLevel.SUGGESTION;
 import static com.google.errorprone.fixes.SuggestedFixes.compilesWithFix;
 import static com.google.errorprone.matchers.Description.NO_MATCH;
 import static com.google.errorprone.util.ASTHelpers.getDeclaredSymbol;
+import static com.google.errorprone.util.ASTHelpers.getEnclosedElements;
 import static com.google.errorprone.util.ASTHelpers.getSymbol;
 import static com.sun.source.tree.Tree.Kind.EXPRESSION_STATEMENT;
 import static com.sun.source.tree.Tree.Kind.IDENTIFIER;
@@ -82,7 +83,7 @@ import java.util.List;
 import java.util.Optional;
 import java.util.Set;
 import javax.lang.model.element.Modifier;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * Refactors some subclasses of {@code Correspondence} to instead call {@code Correspondence.from}.
@@ -644,7 +645,7 @@ public final class CorrespondenceSubclassToFactoryCall extends BugChecker
   private static boolean overrides(
       MethodSymbol potentialOverrider, String clazz, String method, VisitorState state) {
     Symbol overridable =
-        state.getTypeFromString(clazz).tsym.getEnclosedElements().stream()
+        getEnclosedElements(state.getTypeFromString(clazz).tsym).stream()
             .filter(s -> s.getKind() == METHOD)
             .filter(m -> m.getSimpleName().contentEquals(method))
             .collect(onlyElement());
diff --git a/refactorings/src/main/java/com/google/common/truth/refactorings/FailWithFacts.java b/refactorings/src/main/java/com/google/common/truth/refactorings/FailWithFacts.java
index 30cb5207..f2fa8506 100644
--- a/refactorings/src/main/java/com/google/common/truth/refactorings/FailWithFacts.java
+++ b/refactorings/src/main/java/com/google/common/truth/refactorings/FailWithFacts.java
@@ -40,7 +40,7 @@ import com.sun.source.tree.ExpressionTree;
 import com.sun.source.tree.MemberSelectTree;
 import com.sun.source.tree.MethodInvocationTree;
 import java.util.List;
-import org.checkerframework.checker.nullness.qual.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * Migrates Truth subjects from the old {@code fail(String, Object)} to the new {@code
```

