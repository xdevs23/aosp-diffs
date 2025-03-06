```diff
diff --git a/.github/workflows/build.yaml b/.github/workflows/build.yaml
index 3452265..2dc7926 100644
--- a/.github/workflows/build.yaml
+++ b/.github/workflows/build.yaml
@@ -39,10 +39,10 @@ jobs:
 
       - name: Deploy docs to website
         if: ${{ github.ref == 'refs/heads/main' }}
-        uses: JamesIves/github-pages-deploy-action@releases/v3
+        uses: JamesIves/github-pages-deploy-action@v4
         with:
-          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
-          BRANCH: site
-          FOLDER: junit4/target/site/apidocs
-          TARGET_FOLDER: docs/latest/
-          CLEAN: true
+          token: ${{ secrets.GITHUB_TOKEN }}
+          branch: site
+          folder: junit4/target/reports/apidocs
+          target-folder: docs/latest/
+          clean: true
diff --git a/.github/workflows/release.yaml b/.github/workflows/release.yaml
index 034eff7..f4b6972 100644
--- a/.github/workflows/release.yaml
+++ b/.github/workflows/release.yaml
@@ -34,10 +34,10 @@ jobs:
       - run: mvn javadoc:javadoc
 
       - name: Deploy docs to website
-        uses: JamesIves/github-pages-deploy-action@releases/v3
+        uses: JamesIves/github-pages-deploy-action@v4
         with:
-          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
-          BRANCH: site
-          FOLDER: junit4/target/site/apidocs
-          TARGET_FOLDER: docs/1.x/
-          CLEAN: true
+          token: ${{ secrets.GITHUB_TOKEN }}
+          branch: site
+          folder: junit4/target/reports/apidocs
+          target-folder: docs/1.x/
+          clean: true
diff --git a/Android.bp b/Android.bp
index 9dfa015..16ee275 100644
--- a/Android.bp
+++ b/Android.bp
@@ -11,11 +11,12 @@ package {
 java_library {
     name: "TestParameterInjector",
     srcs: [
-        "src/main/java/**/*.java",
+        "junit4/src/main/java/**/*.java",
     ],
     static_libs: [
         "guava",
         "auto_value_annotations",
+        "error_prone_annotations",
         "junit",
         "libprotobuf-java-lite",
         "snakeyaml",
@@ -29,7 +30,9 @@ java_library {
         "//cts/tests/app/WallpaperTest",
         "//cts/tests/autofillservice",
         "//cts/tests/tests/app",
+        "//cts/tests/tests/car",
         "//cts/tests/tests/content",
+        "//external/robolectric:__subpackages__",
         "//frameworks/base/core/tests/coretests",
         "//frameworks/base/libs/WindowManager/Shell/tests/unittest",
         "//frameworks/base/libs/WindowManager/Jetpack/tests/unittest",
@@ -46,11 +49,14 @@ java_library {
 
 java_test_host {
     name: "TestParameterInjectorTest",
-    srcs: ["src/test/java/**/*.java"],
+    srcs: ["junit4/src/test/java/**/*.java"],
     static_libs: [
         "TestParameterInjector",
         "truth",
     ],
+    javacflags: [
+        "-parameters",
+    ],
     test_options: {
         unit_test: true,
     },
diff --git a/CHANGELOG.md b/CHANGELOG.md
index 5b80fa1..0bb31e4 100644
--- a/CHANGELOG.md
+++ b/CHANGELOG.md
@@ -1,9 +1,37 @@
+## 1.18
+
+- Made some internal JUnit4 methods of `TestParameterInjector` public:
+
+  - `computeTestMethods()`
+  - `methodBlock()`
+  - `methodInvoker()`
+
+  These allow any client to combine `TestParameterInjector` with another JUnit4
+  runner by manually creating a `TestParameterInjector` instance and calling
+  these methods from the combined JUnit4 runner.
+
+## 1.17
+
+- Added support for parsing `java.time.Duration` from a string. Example:
+
+```
+@Test
+public void myTest(@TestParameter({"1d", "2h20min", "10.5ms"}) Duration duration){...}
+```
+
 ## 1.16
 
 - Deprecated [`TestParameter.TestParameterValuesProvider`](
   https://google.github.io/TestParameterInjector/docs/latest/com/google/testing/junit/testparameterinjector/TestParameter.TestParameterValuesProvider.html)
   in favor of its newer version [`TestParameterValuesProvider`](
   https://google.github.io/TestParameterInjector/docs/latest/com/google/testing/junit/testparameterinjector/TestParameterValuesProvider.html).
+- Added support for repeated annotations to [`TestParameterValuesProvider.Context`](
+  https://google.github.io/TestParameterInjector/docs/latest/com/google/testing/junit/testparameterinjector/TestParameterValuesProvider.Context.html)
+- Converting incorrectly YAML-parsed booleans back to their enum values when possible
+- Support enum aliases (defined as static fields on the enum), and in particular
+  Protocol Buffer enum aliases
+- When generating test names for enum values, the enum name is used instead of
+  its `toString()` method.
 
 ## 1.15
 
diff --git a/METADATA b/METADATA
index f2d2416..9163ce1 100644
--- a/METADATA
+++ b/METADATA
@@ -12,6 +12,6 @@ third_party {
     value: "https://github.com/google/TestParameterInjector"
   }
   version: "12066d29df68922d8c4a1a0c2c6128abc487340f"
-  last_upgrade_date { year: 2024 month: 4 day: 5 }
+  last_upgrade_date { year: 2024 month: 10 day: 16 }
   license_type: NOTICE
 }
diff --git a/OWNERS b/OWNERS
index 5c527de..14099dc 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,3 +1,2 @@
-licorne@google.com
 okamil@google.com
 wescande@google.com
diff --git a/README.md b/README.md
index d0178a6..60d19e5 100644
--- a/README.md
+++ b/README.md
@@ -54,7 +54,7 @@ And add the following dependency to your `.pom` file:
 <dependency>
   <groupId>com.google.testparameterinjector</groupId>
   <artifactId>test-parameter-injector</artifactId>
-  <version>1.15</version>
+  <version>1.18</version>
   <scope>test</scope>
 </dependency>
 ```
@@ -97,7 +97,7 @@ And add the following dependency to your `.pom` file:
 <dependency>
   <groupId>com.google.testparameterinjector</groupId>
   <artifactId>test-parameter-injector-junit5</artifactId>
-  <version>1.15</version>
+  <version>1.18</version>
   <scope>test</scope>
 </dependency>
 ```
@@ -182,6 +182,10 @@ The following examples show most of the supported types. See the `@TestParameter
 
 // Bytes
 @TestParameter({"!!binary 'ZGF0YQ=='", "some_string"}) byte[] bytes;
+
+// Durations (segments of number+unit as shown below)
+@TestParameter({"1d", "2h", "3min", "4s", "5ms", "6us", "7ns"}) java.time.Duration d;
+@TestParameter({"1h30min", "-2h10min20s", "1.5h", ".5s", "0"}) java.time.Duration d;
 ```
 
 For non-primitive types (e.g. String, enums, bytes), `"null"` is always parsed as the `null` reference.
@@ -379,12 +383,15 @@ Instead of providing a YAML mapping of parameters, you can implement your own
 `TestParametersValuesProvider` as follows:
 
 ```java
+import com.google.testing.junit.testparameterinjector.TestParametersValuesProvider;
+import com.google.testing.junit.testparameterinjector.TestParameters.TestParametersValues;
+
 @Test
 @TestParameters(valuesProvider = IsAdultValueProvider.class)
 public void personIsAdult(int age, boolean expectIsAdult) { ... }
 
-static final class IsAdultValueProvider implements TestParametersValuesProvider {
-  @Override public ImmutableList<TestParametersValues> provideValues() {
+static final class IsAdultValueProvider extends TestParametersValuesProvider {
+  @Override public ImmutableList<TestParametersValues> provideValues(Context context) {
     return ImmutableList.of(
       TestParametersValues.builder()
         .name("teenager")
diff --git a/junit4/src/main/java/com/google/testing/junit/testparameterinjector/GenericParameterContext.java b/junit4/src/main/java/com/google/testing/junit/testparameterinjector/GenericParameterContext.java
index 5586d7b..3321541 100644
--- a/junit4/src/main/java/com/google/testing/junit/testparameterinjector/GenericParameterContext.java
+++ b/junit4/src/main/java/com/google/testing/junit/testparameterinjector/GenericParameterContext.java
@@ -24,6 +24,7 @@ import com.google.common.collect.ImmutableList;
 import com.google.common.collect.Ordering;
 import java.lang.annotation.Annotation;
 import java.lang.annotation.Repeatable;
+import java.lang.reflect.Executable;
 import java.lang.reflect.Field;
 import java.lang.reflect.Method;
 import java.lang.reflect.Parameter;
@@ -79,6 +80,17 @@ final class GenericParameterContext {
         testClass);
   }
 
+  // Executable is not available on old Android SDKs, and isn't desugared. This method is only
+  // called via @TestParameters, wich only supports newer SDKs anyway.
+  @SuppressWarnings("AndroidJdkLibsChecker")
+  static GenericParameterContext create(Executable executable, Class<?> testClass) {
+    return new GenericParameterContext(
+        ImmutableList.copyOf(executable.getAnnotations()),
+        /* getAnnotationsFunction= */ annotationType ->
+            ImmutableList.copyOf(executable.getAnnotationsByType(annotationType)),
+        testClass);
+  }
+
   static GenericParameterContext createWithRepeatableAnnotationsFallback(
       Annotation[] annotationsOnParameter, Class<?> testClass) {
     return new GenericParameterContext(
diff --git a/junit4/src/main/java/com/google/testing/junit/testparameterinjector/ParameterValueParsing.java b/junit4/src/main/java/com/google/testing/junit/testparameterinjector/ParameterValueParsing.java
index e09c1d9..c03c369 100644
--- a/junit4/src/main/java/com/google/testing/junit/testparameterinjector/ParameterValueParsing.java
+++ b/junit4/src/main/java/com/google/testing/junit/testparameterinjector/ParameterValueParsing.java
@@ -14,27 +14,39 @@
 
 package com.google.testing.junit.testparameterinjector;
 
+import static com.google.common.base.MoreObjects.firstNonNull;
 import static com.google.common.base.Preconditions.checkArgument;
 import static com.google.common.base.Preconditions.checkNotNull;
 import static com.google.common.base.Preconditions.checkState;
+import static com.google.common.base.Verify.verify;
+import static com.google.common.collect.Iterables.getOnlyElement;
 
 import com.google.common.base.CharMatcher;
 import com.google.common.base.Function;
 import com.google.common.base.Optional;
+import com.google.common.collect.ImmutableMap;
+import com.google.common.collect.ImmutableSet;
 import com.google.common.collect.Lists;
 import com.google.common.primitives.Primitives;
 import com.google.common.primitives.UnsignedLong;
 import com.google.common.reflect.TypeToken;
 import com.google.errorprone.annotations.CanIgnoreReturnValue;
 import java.lang.reflect.Array;
+import java.lang.reflect.Field;
 import java.lang.reflect.ParameterizedType;
 import java.math.BigInteger;
 import java.nio.charset.Charset;
+import java.time.Duration;
 import java.util.Arrays;
+import java.util.HashSet;
 import java.util.LinkedHashMap;
 import java.util.List;
 import java.util.Map;
 import java.util.Map.Entry;
+import java.util.Objects;
+import java.util.Set;
+import java.util.regex.Matcher;
+import java.util.regex.Pattern;
 import javax.annotation.Nullable;
 import org.yaml.snakeyaml.LoaderOptions;
 import org.yaml.snakeyaml.Yaml;
@@ -45,7 +57,37 @@ final class ParameterValueParsing {
 
   @SuppressWarnings("unchecked")
   static <E extends Enum<E>> Enum<?> parseEnum(String str, Class<?> enumType) {
-    return Enum.valueOf((Class<E>) enumType, str);
+    try {
+      return Enum.valueOf((Class<E>) enumType, str);
+    } catch (IllegalArgumentException e) {
+      // The given name was not a valid enum value. However, the enum might have an alias to one of
+      // its values defined as static field. This happens for example (via code generation) in the
+      // case of Protocol Buffer aliases (see the allow_alias option).
+      Optional<Enum<?>> enumValue = maybeGetStaticConstant(enumType, str);
+      if (enumValue.isPresent()) {
+        return enumValue.get();
+      } else {
+        throw e;
+      }
+    }
+  }
+
+  @SuppressWarnings("unchecked")
+  private static Optional<Enum<?>> maybeGetStaticConstant(Class<?> enumType, String fieldName) {
+    verify(enumType.isEnum(), "Given type %s is not a enum.", enumType.getSimpleName());
+    try {
+      Field field = enumType.getField(fieldName);
+      Object valueCandidate = field.get(null);
+      checkArgument(
+          enumType.isInstance(valueCandidate),
+          "The field %s.%s exists, but is not of expected type %s.",
+          enumType.getSimpleName(),
+          fieldName,
+          enumType.getSimpleName());
+      return Optional.of((Enum<?>) valueCandidate);
+    } catch (SecurityException | ReflectiveOperationException e) {
+      return Optional.absent();
+    }
   }
 
   static boolean isValidYamlString(String yamlString) {
@@ -130,6 +172,11 @@ final class ParameterValueParsing {
 
     yamlValueTransformer
         .ifJavaType(Enum.class)
+        .supportParsedType(
+            Boolean.class,
+            bool ->
+                ParameterValueParsing.parseEnumIfUnambiguousYamlBoolean(
+                    bool, javaType.getRawType()))
         .supportParsedType(
             String.class, str -> ParameterValueParsing.parseEnum(str, javaType.getRawType()));
 
@@ -148,6 +195,12 @@ final class ParameterValueParsing {
           .supportParsedType(byte[].class, ByteStringReflection::copyFrom);
     }
 
+    yamlValueTransformer
+        .ifJavaType(Duration.class)
+        .supportParsedType(String.class, ParameterValueParsing::parseDuration)
+        // Support the special case where the YAML string is "0"
+        .supportParsedType(Integer.class, i -> parseDuration(String.valueOf(i)));
+
     // Added mainly for protocol buffer parsing
     yamlValueTransformer
         .ifJavaType(List.class)
@@ -166,6 +219,42 @@ final class ParameterValueParsing {
     return yamlValueTransformer.transformedJavaValue();
   }
 
+  private static Enum<?> parseEnumIfUnambiguousYamlBoolean(boolean yamlValue, Class<?> enumType) {
+    Set<String> negativeYamlStrings =
+        ImmutableSet.of("false", "False", "FALSE", "n", "N", "no", "No", "NO", "off", "Off", "OFF");
+    Set<String> positiveYamlStrings =
+        ImmutableSet.of("on", "On", "ON", "true", "True", "TRUE", "y", "Y", "yes", "Yes", "YES");
+
+    // This is the list of YAML strings that a user could have used to define this boolean. Since
+    // the user probably didn't intend a boolean but an enum (since we're expecting an enum), one of
+    // these strings may (unambiguously) match one of the enum values.
+    Set<String> yamlStringCandidates = yamlValue ? positiveYamlStrings : negativeYamlStrings;
+
+    Set<Enum<?>> matches = new HashSet<>();
+    for (Object enumValueObject : enumType.getEnumConstants()) {
+      Enum<?> enumValue = (Enum<?>) enumValueObject;
+      if (yamlStringCandidates.contains(enumValue.name())) {
+        matches.add(enumValue);
+      }
+    }
+
+    checkArgument(
+        !matches.isEmpty(),
+        "Cannot cast a boolean (%s) to an enum of type %s.",
+        yamlValue,
+        enumType.getSimpleName());
+    checkArgument(
+        matches.size() == 1,
+        "Cannot cast a boolean (%s) to an enum of type %s. It is likely that the YAML parser is"
+            + " 'wrongly' parsing one of these values as boolean: %s. You can solve this by putting"
+            + " quotes around the YAML value, forcing the YAML parser to parse a String, which can"
+            + " then be converted to the enum.",
+        yamlValue,
+        enumType.getSimpleName(),
+        matches);
+    return getOnlyElement(matches);
+  }
+
   private static Map<?, ?> parseYamlMapToJavaMap(Map<?, ?> map, TypeToken<?> javaType) {
     Map<Object, Object> returnedMap = new LinkedHashMap<>();
     for (Entry<?, ?> entry : map.entrySet()) {
@@ -294,10 +383,78 @@ final class ParameterValueParsing {
       return resultBuider.toString();
     } else if (ByteStringReflection.isInstanceOfByteString(value)) {
       return Arrays.toString(ByteStringReflection.byteStringToByteArray(value));
+    } else if (value instanceof Enum<?>) {
+      // Sometimes, enums have custom toString() methods. They are probably adding extra information
+      // (such as with protobuf enums on Android), but for a test name, the string should be as
+      // short as possible
+      return ((Enum<?>) value).name();
     } else {
       return String.valueOf(value);
     }
   }
 
+  // ********** Duration parsing ********** //
+
+  private static final ImmutableMap<String, Duration> ABBREVIATION_TO_DURATION =
+      new ImmutableMap.Builder<String, Duration>()
+          .put("d", Duration.ofDays(1))
+          .put("h", Duration.ofHours(1))
+          .put("m", Duration.ofMinutes(1))
+          .put("min", Duration.ofMinutes(1))
+          .put("s", Duration.ofSeconds(1))
+          .put("ms", Duration.ofMillis(1))
+          .put("us", Duration.ofNanos(1000))
+          .put("ns", Duration.ofNanos(1))
+          .buildOrThrow();
+  private static final Pattern UNIT_PATTERN =
+      Pattern.compile("(?x) ([0-9]+)? (\\.[0-9]*)? (d|h|min|ms?|s|us|ns)");
+  private static final CharMatcher ASCII_DIGIT = CharMatcher.inRange('0', '9');
+
+  private static Duration parseDuration(String value) {
+    checkArgument(value != null, "input value cannot be null");
+    checkArgument(!value.isEmpty(), "input value cannot be empty");
+    checkArgument(!value.equals("-"), "input value cannot be '-'");
+    checkArgument(!value.equals("+"), "input value cannot be '+'");
+
+    value = CharMatcher.whitespace().trimFrom(value);
+
+    if (Objects.equals(value, "0")) {
+      return Duration.ZERO;
+    }
+
+    Duration duration = Duration.ZERO;
+    boolean negative = value.startsWith("-");
+    boolean explicitlyPositive = value.startsWith("+");
+    int index = negative || explicitlyPositive ? 1 : 0;
+    Matcher matcher = UNIT_PATTERN.matcher(value);
+    while (matcher.find(index) && matcher.start() == index) {
+      // Prevent strings like ".s" or "d" by requiring at least one digit.
+      checkArgument(ASCII_DIGIT.matchesAnyOf(matcher.group(0)));
+      try {
+        String unit = matcher.group(3);
+
+        long whole = Long.parseLong(firstNonNull(matcher.group(1), "0"));
+        Duration singleUnit = ABBREVIATION_TO_DURATION.get(unit);
+        checkArgument(singleUnit != null, "invalid unit (%s)", unit);
+        // TODO(b/142748138): Consider using saturated duration math here
+        duration = duration.plus(singleUnit.multipliedBy(whole));
+
+        long nanosPerUnit = singleUnit.toNanos();
+        double frac = Double.parseDouble("0" + firstNonNull(matcher.group(2), ""));
+        duration = duration.plus(Duration.ofNanos((long) (nanosPerUnit * frac)));
+      } catch (ArithmeticException e) {
+        throw new IllegalArgumentException(e);
+      }
+      index = matcher.end();
+    }
+    if (index < value.length()) {
+      throw new IllegalArgumentException("Could not parse entire duration: " + value);
+    }
+    if (negative) {
+      duration = duration.negated();
+    }
+    return duration;
+  }
+
   private ParameterValueParsing() {}
 }
diff --git a/junit4/src/main/java/com/google/testing/junit/testparameterinjector/PluggableTestRunner.java b/junit4/src/main/java/com/google/testing/junit/testparameterinjector/PluggableTestRunner.java
index b2a0ad8..4a14752 100644
--- a/junit4/src/main/java/com/google/testing/junit/testparameterinjector/PluggableTestRunner.java
+++ b/junit4/src/main/java/com/google/testing/junit/testparameterinjector/PluggableTestRunner.java
@@ -16,7 +16,6 @@ package com.google.testing.junit.testparameterinjector;
 
 import com.google.common.base.Joiner;
 import com.google.common.base.Throwables;
-import com.google.common.collect.ComparisonChain;
 import com.google.common.collect.FluentIterable;
 import com.google.common.collect.ImmutableList;
 import com.google.common.collect.LinkedListMultimap;
@@ -66,9 +65,6 @@ abstract class PluggableTestRunner extends BlockJUnit4ClassRunner {
     super(klass);
   }
 
-  /** Returns the TestMethodProcessorList to use. This is meant to be overridden by subclasses. */
-  protected abstract TestMethodProcessorList createTestMethodProcessorList();
-
   /**
    * This method is run to perform optional additional operations on the test instance, right after
    * it was created.
@@ -77,20 +73,6 @@ abstract class PluggableTestRunner extends BlockJUnit4ClassRunner {
     // Do nothing by default
   }
 
-  /**
-   * If true, all test methods (across different TestMethodProcessors) will be sorted in a
-   * deterministic way.
-   *
-   * <p>Deterministic means that the order will not change, even when tests are added/removed or
-   * between releases.
-   *
-   * @deprecated Override {@link #sortTestMethods} with preferred sorting strategy.
-   */
-  @Deprecated
-  protected boolean shouldSortTestMethodsDeterministically() {
-    return false; // Don't sort methods by default
-  }
-
   /**
    * Sort test methods (across different TestMethodProcessors).
    *
@@ -98,16 +80,7 @@ abstract class PluggableTestRunner extends BlockJUnit4ClassRunner {
    * or between releases.
    */
   protected ImmutableList<FrameworkMethod> sortTestMethods(ImmutableList<FrameworkMethod> methods) {
-    if (!shouldSortTestMethodsDeterministically()) {
-      return methods;
-    }
-    return FluentIterable.from(methods)
-        .toSortedList(
-            (o1, o2) ->
-                ComparisonChain.start()
-                    .compare(o1.getName().hashCode(), o2.getName().hashCode())
-                    .compare(o1.getName(), o2.getName())
-                    .result());
+    return methods;
   }
 
   /**
@@ -128,7 +101,7 @@ abstract class PluggableTestRunner extends BlockJUnit4ClassRunner {
   }
 
   @Override
-  protected final ImmutableList<FrameworkMethod> computeTestMethods() {
+  public final ImmutableList<FrameworkMethod> computeTestMethods() {
     return sortTestMethods(
         FluentIterable.from(getSupportedTestAnnotations())
             .transformAndConcat(annotation -> getTestClass().getAnnotatedMethods(annotation))
@@ -195,7 +168,7 @@ abstract class PluggableTestRunner extends BlockJUnit4ClassRunner {
   // Note: This is a copy of the parent implementation, except that instead of calling
   // #createTest(), this method calls #createTestForMethod(method).
   @Override
-  protected final Statement methodBlock(final FrameworkMethod method) {
+  public final Statement methodBlock(final FrameworkMethod method) {
     Object testObject;
     try {
       testObject =
@@ -236,7 +209,7 @@ abstract class PluggableTestRunner extends BlockJUnit4ClassRunner {
   }
 
   @Override
-  protected final Statement methodInvoker(FrameworkMethod frameworkMethod, Object testObject) {
+  public final Statement methodInvoker(FrameworkMethod frameworkMethod, Object testObject) {
     TestInfo testInfo = ((OverriddenFrameworkMethod) frameworkMethod).getTestInfo();
 
     if (testInfo.getMethod().getParameterTypes().length == 0) {
@@ -416,7 +389,7 @@ abstract class PluggableTestRunner extends BlockJUnit4ClassRunner {
 
   private synchronized TestMethodProcessorList getTestMethodProcessors() {
     if (testMethodProcessors == null) {
-      testMethodProcessors = createTestMethodProcessorList();
+      testMethodProcessors = TestMethodProcessorList.createNewParameterizedProcessors();
     }
     return testMethodProcessors;
   }
diff --git a/junit4/src/main/java/com/google/testing/junit/testparameterinjector/TestParameterInjector.java b/junit4/src/main/java/com/google/testing/junit/testparameterinjector/TestParameterInjector.java
index 8b23e53..2f84665 100644
--- a/junit4/src/main/java/com/google/testing/junit/testparameterinjector/TestParameterInjector.java
+++ b/junit4/src/main/java/com/google/testing/junit/testparameterinjector/TestParameterInjector.java
@@ -25,9 +25,4 @@ public final class TestParameterInjector extends PluggableTestRunner {
   public TestParameterInjector(Class<?> testClass) throws InitializationError {
     super(testClass);
   }
-
-  @Override
-  protected TestMethodProcessorList createTestMethodProcessorList() {
-    return TestMethodProcessorList.createNewParameterizedProcessors();
-  }
 }
diff --git a/junit4/src/main/java/com/google/testing/junit/testparameterinjector/TestParameterValuesProvider.java b/junit4/src/main/java/com/google/testing/junit/testparameterinjector/TestParameterValuesProvider.java
index ccdb18b..d9ea27f 100644
--- a/junit4/src/main/java/com/google/testing/junit/testparameterinjector/TestParameterValuesProvider.java
+++ b/junit4/src/main/java/com/google/testing/junit/testparameterinjector/TestParameterValuesProvider.java
@@ -26,8 +26,8 @@ import javax.annotation.Nullable;
 /**
  * Abstract class for custom providers of @TestParameter values.
  *
- * <p>This is a replacement for {@link TestParameter.TestParameterValuesProvider}, which will soon
- * be deprecated. The difference with the former interface is that this class provides a {@code
+ * <p>This is a replacement for {@link TestParameter.TestParameterValuesProvider}, which is
+ * deprecated. The difference with the former interface is that this class provides a {@code
  * Context} instance when invoking {@link #provideValues}.
  */
 public abstract class TestParameterValuesProvider
@@ -90,7 +90,7 @@ public abstract class TestParameterValuesProvider
      *
      * @throws NoSuchElementException if this there is no annotation with the given type
      * @throws IllegalArgumentException if there are multiple annotations with the given type
-     * @throws IllegalArgumentException if the argument it TestParameter.class because it is already
+     * @throws IllegalArgumentException if the argument is TestParameter.class because it is already
      *     handled by the TestParameterInjector framework.
      */
     public <A extends Annotation> A getOtherAnnotation(Class<A> annotationType) {
@@ -102,7 +102,7 @@ public abstract class TestParameterValuesProvider
     }
 
     /**
-     * Returns the only annotation with the given type on the field or parameter that was annotated
+     * Returns all annotations with the given type on the field or parameter that was annotated
      * with @TestParameter.
      *
      * <p>For example, if the test code is as follows:
@@ -118,12 +118,12 @@ public abstract class TestParameterValuesProvider
      *   }
      * </pre>
      *
-     * then {@code context.getOtherAnnotations(CustomAnnotation.class)} will return the annotation
+     * then {@code context.getOtherAnnotations(CustomAnnotation.class)} will return the annotations
      * with 123 and 456.
      *
      * <p>Returns an empty list if this there is no annotation with the given type.
      *
-     * @throws IllegalArgumentException if the argument it TestParameter.class because it is already
+     * @throws IllegalArgumentException if the argument is TestParameter.class because it is already
      *     handled by the TestParameterInjector framework.
      */
     public <A extends Annotation> ImmutableList<A> getOtherAnnotations(Class<A> annotationType) {
diff --git a/junit4/src/main/java/com/google/testing/junit/testparameterinjector/TestParameters.java b/junit4/src/main/java/com/google/testing/junit/testparameterinjector/TestParameters.java
index 684e770..0e117ef 100644
--- a/junit4/src/main/java/com/google/testing/junit/testparameterinjector/TestParameters.java
+++ b/junit4/src/main/java/com/google/testing/junit/testparameterinjector/TestParameters.java
@@ -21,13 +21,10 @@ import static java.util.Collections.unmodifiableMap;
 
 import com.google.auto.value.AutoValue;
 import com.google.common.base.Optional;
-import com.google.common.collect.ImmutableList;
-import com.google.testing.junit.testparameterinjector.TestParameters.TestParametersValuesProvider;
 import java.lang.annotation.Repeatable;
 import java.lang.annotation.Retention;
 import java.lang.annotation.Target;
 import java.util.LinkedHashMap;
-import java.util.List;
 import java.util.Map;
 import javax.annotation.Nullable;
 
@@ -172,9 +169,24 @@ public @interface TestParameters {
   Class<? extends TestParametersValuesProvider> valuesProvider() default
       DefaultTestParametersValuesProvider.class;
 
-  /** Interface for custom providers of test parameter values. */
+  /**
+   * Interface for custom providers of test parameter values.
+   *
+   * @deprecated Use {@link
+   *     com.google.testing.junit.testparameterinjector.TestParametersValuesProvider} instead. The
+   *     replacement implements this same interface, but with an additional Context parameter.
+   */
+  @Deprecated
   interface TestParametersValuesProvider {
-    List<TestParametersValues> provideValues();
+    java.util.List<TestParametersValues> provideValues();
+  }
+
+  /** Default {@link TestParametersValuesProvider} implementation that does nothing. */
+  class DefaultTestParametersValuesProvider implements TestParametersValuesProvider {
+    @Override
+    public java.util.List<TestParametersValues> provideValues() {
+      return com.google.common.collect.ImmutableList.of();
+    }
   }
 
   /** A set of parameters for a single method invocation. */
@@ -257,14 +269,6 @@ public @interface TestParameters {
     }
   }
 
-  /** Default {@link TestParametersValuesProvider} implementation that does nothing. */
-  class DefaultTestParametersValuesProvider implements TestParametersValuesProvider {
-    @Override
-    public List<TestParametersValues> provideValues() {
-      return ImmutableList.of();
-    }
-  }
-
   /**
    * Holder annotation for multiple @TestParameters annotations. This should never be used directly.
    */
diff --git a/junit4/src/main/java/com/google/testing/junit/testparameterinjector/TestParametersMethodProcessor.java b/junit4/src/main/java/com/google/testing/junit/testparameterinjector/TestParametersMethodProcessor.java
index 7dffc29..ad1f12f 100644
--- a/junit4/src/main/java/com/google/testing/junit/testparameterinjector/TestParametersMethodProcessor.java
+++ b/junit4/src/main/java/com/google/testing/junit/testparameterinjector/TestParametersMethodProcessor.java
@@ -20,21 +20,20 @@ import static com.google.common.base.Verify.verify;
 import com.google.auto.value.AutoAnnotation;
 import com.google.common.base.Optional;
 import com.google.common.base.Throwables;
+import com.google.common.cache.Cache;
 import com.google.common.cache.CacheBuilder;
-import com.google.common.cache.CacheLoader;
-import com.google.common.cache.LoadingCache;
 import com.google.common.collect.FluentIterable;
 import com.google.common.collect.ImmutableList;
 import com.google.common.collect.ImmutableMap;
 import com.google.common.collect.Maps;
 import com.google.common.primitives.Primitives;
 import com.google.common.reflect.TypeToken;
-import com.google.common.util.concurrent.UncheckedExecutionException;
 import com.google.testing.junit.testparameterinjector.TestInfo.TestInfoParameter;
-import com.google.testing.junit.testparameterinjector.TestParameters.DefaultTestParametersValuesProvider;
 import com.google.testing.junit.testparameterinjector.TestParameters.RepeatedTestParameters;
 import com.google.testing.junit.testparameterinjector.TestParameters.TestParametersValues;
+import com.google.testing.junit.testparameterinjector.TestParametersValuesProvider.Context;
 import com.google.testing.junit.testparameterinjector.TestParameters.TestParametersValuesProvider;
+import com.google.testing.junit.testparameterinjector.TestParameters.DefaultTestParametersValuesProvider;
 import java.lang.annotation.Retention;
 import java.lang.annotation.RetentionPolicy;
 import java.lang.reflect.Constructor;
@@ -45,23 +44,22 @@ import java.lang.reflect.Parameter;
 import java.util.Arrays;
 import java.util.List;
 import java.util.Map;
+import java.util.concurrent.ExecutionException;
 
 /** {@code TestMethodProcessor} implementation for supporting {@link TestParameters}. */
 @SuppressWarnings("AndroidJdkLibsChecker") // Parameter is not available on old Android SDKs.
 final class TestParametersMethodProcessor implements TestMethodProcessor {
 
-  private final LoadingCache<Executable, ImmutableList<TestParametersValues>>
+  private final Cache<Executable, ImmutableList<TestParametersValues>>
       parameterValuesByConstructorOrMethodCache =
-          CacheBuilder.newBuilder()
-              .maximumSize(1000)
-              .build(CacheLoader.from(TestParametersMethodProcessor::toParameterValuesList));
+          CacheBuilder.newBuilder().maximumSize(1000).build();
 
   @Override
   public ExecutableValidationResult validateConstructor(Constructor<?> constructor) {
     if (hasRelevantAnnotation(constructor)) {
       try {
         // This method throws an exception if there is a validation error
-        getConstructorParameters(constructor);
+        ImmutableList<TestParametersValues> unused = getConstructorParameters(constructor);
       } catch (Throwable t) {
         return ExecutableValidationResult.validated(t);
       }
@@ -76,7 +74,7 @@ final class TestParametersMethodProcessor implements TestMethodProcessor {
     if (hasRelevantAnnotation(testMethod)) {
       try {
         // This method throws an exception if there is a validation error
-        getMethodParameters(testMethod);
+        ImmutableList<TestParametersValues> unused = getMethodParameters(testMethod, testClass);
       } catch (Throwable t) {
         return ExecutableValidationResult.validated(t);
       }
@@ -102,7 +100,8 @@ final class TestParametersMethodProcessor implements TestMethodProcessor {
     ImmutableList<Optional<TestParametersValues>> constructorParametersList =
         getConstructorParametersOrSingleAbsentElement(originalTest.getTestClass());
     ImmutableList<Optional<TestParametersValues>> methodParametersList =
-        getMethodParametersOrSingleAbsentElement(originalTest.getMethod());
+        getMethodParametersOrSingleAbsentElement(
+            originalTest.getMethod(), originalTest.getTestClass());
     for (int constructorParametersIndex = 0;
         constructorParametersIndex < constructorParametersList.size();
         ++constructorParametersIndex) {
@@ -157,9 +156,11 @@ final class TestParametersMethodProcessor implements TestMethodProcessor {
   }
 
   private ImmutableList<Optional<TestParametersValues>> getMethodParametersOrSingleAbsentElement(
-      Method method) {
+      Method method, Class<?> testClass) {
     return hasRelevantAnnotation(method)
-        ? FluentIterable.from(getMethodParameters(method)).transform(Optional::of).toList()
+        ? FluentIterable.from(getMethodParameters(method, testClass))
+            .transform(Optional::of)
+            .toList()
         : ImmutableList.of(Optional.absent());
   }
 
@@ -183,7 +184,8 @@ final class TestParametersMethodProcessor implements TestMethodProcessor {
   public Optional<List<Object>> maybeGetTestMethodParameters(TestInfo testInfo) {
     Method testMethod = testInfo.getMethod();
     if (hasRelevantAnnotation(testMethod)) {
-      ImmutableList<TestParametersValues> parameterValuesList = getMethodParameters(testMethod);
+      ImmutableList<TestParametersValues> parameterValuesList =
+          getMethodParameters(testMethod, testInfo.getTestClass());
       TestParametersValues parametersValues =
           parameterValuesList.get(
               testInfo.getAnnotation(TestIndexHolder.class).methodParametersIndex());
@@ -199,27 +201,31 @@ final class TestParametersMethodProcessor implements TestMethodProcessor {
 
   private ImmutableList<TestParametersValues> getConstructorParameters(Constructor<?> constructor) {
     try {
-      return parameterValuesByConstructorOrMethodCache.getUnchecked(constructor);
-    } catch (UncheckedExecutionException e) {
+      return parameterValuesByConstructorOrMethodCache.get(
+          constructor, () -> toParameterValuesList(constructor, constructor.getDeclaringClass()));
+    } catch (ExecutionException e) {
       // Rethrow IllegalStateException because they can be caused by user mistakes and the user
       // doesn't need to know that the caching layer is in between.
       Throwables.throwIfInstanceOf(e.getCause(), IllegalStateException.class);
-      throw e;
+      throw new RuntimeException(e);
     }
   }
 
-  private ImmutableList<TestParametersValues> getMethodParameters(Method method) {
+  private ImmutableList<TestParametersValues> getMethodParameters(
+      Method method, Class<?> testClass) {
     try {
-      return parameterValuesByConstructorOrMethodCache.getUnchecked(method);
-    } catch (UncheckedExecutionException e) {
+      return parameterValuesByConstructorOrMethodCache.get(
+          method, () -> toParameterValuesList(method, testClass));
+    } catch (ExecutionException e) {
       // Rethrow IllegalStateException because they can be caused by user mistakes and the user
       // doesn't need to know that the caching layer is in between.
       Throwables.throwIfInstanceOf(e.getCause(), IllegalStateException.class);
-      throw e;
+      throw new RuntimeException(e);
     }
   }
 
-  private static ImmutableList<TestParametersValues> toParameterValuesList(Executable executable) {
+  private static ImmutableList<TestParametersValues> toParameterValuesList(
+      Executable executable, Class<?> testClass) {
     checkParameterNamesArePresent(executable);
     ImmutableList<Parameter> parametersList = ImmutableList.copyOf(executable.getParameters());
 
@@ -258,7 +264,10 @@ final class TestParametersMethodProcessor implements TestMethodProcessor {
                 yamlMap -> toParameterValues(yamlMap, parametersList, annotation.customName()))
             .toList();
       } else {
-        return toParameterValuesList(annotation.valuesProvider(), parametersList);
+        return toParameterValuesList(
+            annotation.valuesProvider(),
+            parametersList,
+            GenericParameterContext.create(executable, testClass));
       }
     } else { // Not annotated with @TestParameters
       verify(
@@ -278,12 +287,22 @@ final class TestParametersMethodProcessor implements TestMethodProcessor {
   }
 
   private static ImmutableList<TestParametersValues> toParameterValuesList(
-      Class<? extends TestParametersValuesProvider> valuesProvider, List<Parameter> parameters) {
+      Class<? extends TestParametersValuesProvider> valuesProvider,
+      List<Parameter> parameters,
+      GenericParameterContext context) {
     try {
       Constructor<? extends TestParametersValuesProvider> constructor =
           valuesProvider.getDeclaredConstructor();
       constructor.setAccessible(true);
-      List<TestParametersValues> testParametersValues = constructor.newInstance().provideValues();
+      TestParametersValuesProvider provider = constructor.newInstance();
+      List<TestParametersValues> testParametersValues =
+          provider
+                  instanceof
+                  com.google.testing.junit.testparameterinjector.TestParametersValuesProvider
+              ? ((com.google.testing.junit.testparameterinjector.TestParametersValuesProvider)
+                      provider)
+                  .provideValues(new Context(context))
+              : provider.provideValues();
       for (TestParametersValues testParametersValue : testParametersValues) {
         validateThatValuesMatchParameters(testParametersValue, parameters);
       }
@@ -302,7 +321,7 @@ final class TestParametersMethodProcessor implements TestMethodProcessor {
                 "Could not find a no-arg constructor for %s.", valuesProvider.getSimpleName()),
             e);
       }
-    } catch (ReflectiveOperationException e) {
+    } catch (Exception e) {
       throw new IllegalStateException(e);
     }
   }
diff --git a/junit4/src/main/java/com/google/testing/junit/testparameterinjector/TestParametersValuesProvider.java b/junit4/src/main/java/com/google/testing/junit/testparameterinjector/TestParametersValuesProvider.java
new file mode 100644
index 0000000..2e365e8
--- /dev/null
+++ b/junit4/src/main/java/com/google/testing/junit/testparameterinjector/TestParametersValuesProvider.java
@@ -0,0 +1,149 @@
+/*
+ * Copyright 2024 Google Inc.
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
+ * in compliance with the License. You may obtain a copy of the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software distributed under the License
+ * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
+ * or implied. See the License for the specific language governing permissions and limitations under
+ * the License.
+ */
+
+package com.google.testing.junit.testparameterinjector;
+
+import static com.google.common.base.Preconditions.checkArgument;
+
+import com.google.common.annotations.VisibleForTesting;
+import com.google.common.collect.ImmutableList;
+import com.google.testing.junit.testparameterinjector.TestParameters.TestParametersValues;
+import java.lang.annotation.Annotation;
+import java.util.List;
+import java.util.NoSuchElementException;
+
+/**
+ * Abstract class for custom providers of @TestParameters values.
+ *
+ * <p>This is a replacement for {@link TestParameters.TestParametersValuesProvider}, which is
+ * deprecated. The difference with the former interface is that this class provides a {@code
+ * Context} instance when invoking {@link #provideValues}.
+ */
+public abstract class TestParametersValuesProvider
+    implements TestParameters.TestParametersValuesProvider {
+
+  protected abstract List<TestParametersValues> provideValues(Context context) throws Exception;
+
+  /**
+   * @deprecated This method should never be called as it will simply throw an {@link
+   *     UnsupportedOperationException}.
+   */
+  @Override
+  @Deprecated
+  public final List<TestParametersValues> provideValues() {
+    throw new UnsupportedOperationException(
+        "The TestParameterInjector framework should never call this method, and instead call"
+            + " #provideValues(Context)");
+  }
+
+  /**
+   * An immutable value class that contains extra information about the context of the parameter for
+   * which values are being provided.
+   */
+  public static final class Context {
+
+    private final GenericParameterContext delegate;
+
+    Context(GenericParameterContext delegate) {
+      this.delegate = delegate;
+    }
+
+    /**
+     * Returns the only annotation with the given type on the method or constructor that was
+     * annotated with @TestParameters.
+     *
+     * <p>For example, if the test code is as follows:
+     *
+     * <pre>
+     *   {@literal @}Test
+     *   {@literal @}TestParameters("{updateRequest: {country_code: BE}, expectedResultType: SUCCESS}")
+     *   {@literal @}TestParameters("{updateRequest: {country_code: XYZ}, expectedResultType: FAILURE}")
+     *   {@literal @}CustomAnnotation(123)
+     *   public void update(UpdateRequest updateRequest, ResultType expectedResultType) {
+     *     ...
+     *   }
+     * </pre>
+     *
+     * then {@code context.getOtherAnnotation(CustomAnnotation.class).value()} will equal 123.
+     *
+     * @throws NoSuchElementException if this there is no annotation with the given type
+     * @throws IllegalArgumentException if there are multiple annotations with the given type
+     * @throws IllegalArgumentException if the argument it TestParameters.class because it is
+     *     already handled by the TestParameterInjector framework.
+     */
+    public <A extends Annotation> A getOtherAnnotation(Class<A> annotationType) {
+      checkArgument(
+          !TestParameters.class.equals(annotationType),
+          "Getting the @TestParameters annotating the method or constructor is not allowed because"
+              + " it is already handled by the TestParameterInjector framework.");
+      return delegate.getAnnotation(annotationType);
+    }
+
+    /**
+     * Returns all annotations with the given type on the method or constructor that was annotated
+     * with @TestParameter.
+     *
+     * <pre>
+     *   {@literal @}Test
+     *   {@literal @}TestParameters("{updateRequest: {country_code: BE}, expectedResultType: SUCCESS}")
+     *   {@literal @}TestParameters("{updateRequest: {country_code: XYZ}, expectedResultType: FAILURE}")
+     *   {@literal @}CustomAnnotation(123)
+     *   {@literal @}CustomAnnotation(456)
+     *   public void update(UpdateRequest updateRequest, ResultType expectedResultType) {
+     *     ...
+     *   }
+     * </pre>
+     *
+     * then {@code context.getOtherAnnotations(CustomAnnotation.class)} will return the annotations
+     * with 123 and 456.
+     *
+     * <p>Returns an empty list if this there is no annotation with the given type.
+     *
+     * @throws IllegalArgumentException if the argument it TestParameters.class because it is
+     *     already handled by the TestParameterInjector framework.
+     */
+    public <A extends Annotation> ImmutableList<A> getOtherAnnotations(Class<A> annotationType) {
+      checkArgument(
+          !TestParameters.class.equals(annotationType),
+          "Getting the @TestParameters annotating the method or constructor is not allowed because"
+              + " it is already handled by the TestParameterInjector framework.");
+      return delegate.getAnnotations(annotationType);
+    }
+
+    /**
+     * The class that contains the test that is currently being run.
+     *
+     * <p>Having this can be useful when sharing providers between tests that have the same base
+     * class. In those cases, an abstract method can be called as follows:
+     *
+     * <pre>
+     *   ((MyBaseClass) context.testClass().newInstance()).myAbstractMethod()
+     * </pre>
+     */
+    public Class<?> testClass() {
+      return delegate.testClass();
+    }
+
+    /** A list of all annotations on the method or constructor. */
+    @VisibleForTesting
+    ImmutableList<Annotation> annotationsOnParameter() {
+      return delegate.annotationsOnParameter();
+    }
+
+    @Override
+    public String toString() {
+      return delegate.toString();
+    }
+  }
+}
diff --git a/junit4/src/test/java/com/google/testing/junit/testparameterinjector/ParameterValueParsingTest.java b/junit4/src/test/java/com/google/testing/junit/testparameterinjector/ParameterValueParsingTest.java
index a9336b7..a94c114 100644
--- a/junit4/src/test/java/com/google/testing/junit/testparameterinjector/ParameterValueParsingTest.java
+++ b/junit4/src/test/java/com/google/testing/junit/testparameterinjector/ParameterValueParsingTest.java
@@ -15,12 +15,16 @@
 package com.google.testing.junit.testparameterinjector;
 
 import static com.google.common.truth.Truth.assertThat;
+import static org.junit.Assert.assertThrows;
 
 import com.google.common.base.CharMatcher;
 import com.google.common.base.Optional;
+import com.google.common.collect.ImmutableList;
 import com.google.common.primitives.UnsignedLong;
 import com.google.protobuf.ByteString;
+import com.google.testing.junit.testparameterinjector.TestParameters.TestParametersValues;
 import java.math.BigInteger;
+import java.time.Duration;
 import javax.annotation.Nullable;
 import org.junit.Test;
 import org.junit.runner.RunWith;
@@ -127,6 +131,19 @@ public class ParameterValueParsingTest {
         /* yamlString= */ "AAA",
         /* javaClass= */ TestEnum.class,
         /* expectedResult= */ TestEnum.AAA),
+    BOOLEAN_TO_ENUM_FALSE(
+        /* yamlString= */ "NO", /* javaClass= */ TestEnum.class, /* expectedResult= */ TestEnum.NO),
+    BOOLEAN_TO_ENUM_TRUE(
+        /* yamlString= */ "TRUE",
+        /* javaClass= */ TestEnum.class,
+        /* expectedResult= */ TestEnum.TRUE),
+    // This works because the YAML parser in between makes it impossible to differentiate. This test
+    // case is not testing desired behavior, but rather double-checking that the YAML parsing step
+    // actually happens and we are testing this edge case.
+    BOOLEAN_TO_ENUM_TRUE_DIFFERENT_ALIAS(
+        /* yamlString= */ "ON",
+        /* javaClass= */ TestEnum.class,
+        /* expectedResult= */ TestEnum.TRUE),
 
     STRING_TO_BYTES(
         /* yamlString= */ "data",
@@ -169,6 +186,154 @@ public class ParameterValueParsingTest {
     assertThat(result).isEqualTo(parseYamlValueToJavaTypeCases.expectedResult);
   }
 
+  private static final class DurationSuccessTestCasesProvider extends TestParametersValuesProvider {
+    @Override
+    protected ImmutableList<TestParametersValues> provideValues(Context context) {
+      return ImmutableList.of(
+          // Simple
+          testCase("7d", Duration.ofDays(7)),
+          testCase("6h", Duration.ofHours(6)),
+          testCase("5m", Duration.ofMinutes(5)),
+          testCase("5min", Duration.ofMinutes(5)),
+          testCase("4s", Duration.ofSeconds(4)),
+          testCase("3.2s", Duration.ofMillis(3200)),
+          testCase("0.2s", Duration.ofMillis(200)),
+          testCase(".15s", Duration.ofMillis(150)),
+          testCase("5.0s", Duration.ofSeconds(5)),
+          testCase("1.0s", Duration.ofSeconds(1)),
+          testCase("1.00s", Duration.ofSeconds(1)),
+          testCase("1.004s", Duration.ofSeconds(1).plusMillis(4)),
+          testCase("1.0040s", Duration.ofSeconds(1).plusMillis(4)),
+          testCase("100.00100s", Duration.ofSeconds(100).plusMillis(1)),
+          testCase("0.3333333333333333333h", Duration.ofMinutes(20)),
+          testCase("1s3ms", Duration.ofSeconds(1).plusMillis(3)),
+          testCase("1s34ms", Duration.ofSeconds(1).plusMillis(34)),
+          testCase("1s345ms", Duration.ofSeconds(1).plusMillis(345)),
+          testCase("345ms", Duration.ofMillis(345)),
+          testCase(".9ms", Duration.ofNanos(900000)),
+          testCase("5.s", Duration.ofSeconds(5)),
+          testCase("+24h", Duration.ofHours(24)),
+          testCase("0d", Duration.ZERO),
+          testCase("-0d", Duration.ZERO),
+          testCase("-1d", Duration.ofDays(-1)),
+          testCase("1d", Duration.ofDays(1)),
+
+          // Zero
+          testCase("0", Duration.ZERO),
+          testCase("-0", Duration.ZERO),
+          testCase("+0", Duration.ZERO),
+
+          // Multiple fields
+          testCase("1h30m", Duration.ofMinutes(90)),
+          testCase("1h30min", Duration.ofMinutes(90)),
+          testCase("1d7m", Duration.ofDays(1).plusMinutes(7)),
+          testCase("1m3.5s", Duration.ofMinutes(1).plusMillis(3500)),
+          testCase("1m3s500ms", Duration.ofMinutes(1).plusMillis(3500)),
+          testCase("5d4h3m2.1s", Duration.ofDays(5).plusHours(4).plusMinutes(3).plusMillis(2100)),
+          testCase("3.5s250ms", Duration.ofMillis(3500 + 250)),
+          testCase("1m2m3m", Duration.ofMinutes(6)),
+          testCase("1m2h", Duration.ofHours(2).plusMinutes(1)),
+
+          // Negative duration
+          testCase("-.5h", Duration.ofMinutes(-30)),
+
+          // Overflow
+          testCase("106751d23h47m16s854ms775us807ns", Duration.ofNanos(Long.MAX_VALUE)),
+          testCase("106751991167d7h12m55s807ms", Duration.ofMillis(Long.MAX_VALUE)),
+          testCase("106751991167300d15h30m7s", Duration.ofSeconds(Long.MAX_VALUE)),
+          testCase("106945d", Duration.ofDays(293 * 365)),
+
+          // Underflow
+          testCase("-106751d23h47m16s854ms775us808ns", Duration.ofNanos(Long.MIN_VALUE)),
+          testCase("-106751991167d7h12m55s808ms", Duration.ofMillis(Long.MIN_VALUE)),
+          testCase("-106751991167300d15h30m7s", Duration.ofSeconds(Long.MIN_VALUE + 1)),
+          testCase("-106945d", Duration.ofDays(-293 * 365)),
+
+          // Very large values
+          testCase("9223372036854775807ns", Duration.ofNanos(Long.MAX_VALUE)),
+          testCase("9223372036854775806ns", Duration.ofNanos(Long.MAX_VALUE - 1)),
+          testCase("106751991167d7h12m55s807ms", Duration.ofMillis(Long.MAX_VALUE)),
+          testCase("900000000000d", Duration.ofDays(900000000000L)),
+          testCase("100000000000d100000000000d", Duration.ofDays(200000000000L)));
+    }
+
+    private static TestParametersValues testCase(String yamlString, Duration expectedResult) {
+      return TestParametersValues.builder()
+          .name(yamlString)
+          .addParameter("yamlString", yamlString)
+          .addParameter("expectedResult", expectedResult)
+          .build();
+    }
+  }
+
+  @Test
+  @TestParameters(valuesProvider = DurationSuccessTestCasesProvider.class)
+  public void parseYamlStringToJavaType_duration_success(String yamlString, Duration expectedResult)
+      throws Exception {
+    Object result = ParameterValueParsing.parseYamlStringToJavaType(yamlString, Duration.class);
+
+    assertThat(result).isEqualTo(expectedResult);
+  }
+
+  @Test
+  public void parseYamlStringToJavaType_duration_fails(
+      @TestParameter({
+            // Wrong format
+            "1m 3s", // spaces not allowed
+            "0x123abc",
+            "123x456",
+            ".s",
+            "d",
+            "5dh",
+            "1s500",
+            "unparseable",
+            "-",
+            "+",
+            "2",
+            "-2",
+            "+2",
+
+            // Uppercase
+            "1D",
+            "1H",
+            "1M",
+            "1S",
+            "1MS",
+            "1Ms",
+            "1mS",
+            "1NS",
+            "1Ns",
+            "1nS",
+
+            // Very large values
+            Long.MAX_VALUE + "d",
+            "10000000000000000000000000d"
+          })
+          String yamlString)
+      throws Exception {
+    assertThrows(
+        IllegalArgumentException.class,
+        () -> ParameterValueParsing.parseYamlStringToJavaType(yamlString, Duration.class));
+  }
+
+  @Test
+  public void parseYamlStringToJavaType_booleanToEnum_ambiguousValues_fails(
+      @TestParameter({"OFF", "YES", "false", "True"}) String yamlString) throws Exception {
+    IllegalArgumentException exception =
+        assertThrows(
+            IllegalArgumentException.class,
+            () ->
+                ParameterValueParsing.parseYamlStringToJavaType(
+                    yamlString, TestEnumWithAmbiguousValues.class));
+
+    assertThat(exception)
+        .hasCauseThat()
+        .hasMessageThat()
+        .contains(
+            "It is likely that the YAML parser is 'wrongly' parsing one of these values as"
+                + " boolean");
+  }
+
   enum FormatTestNameStringTestCases {
     NULL_REFERENCE(/* value= */ null, /* expectedResult= */ "param=null"),
     BOOLEAN(/* value= */ false, /* expectedResult= */ "param=false"),
@@ -201,6 +366,17 @@ public class ParameterValueParsingTest {
 
   private enum TestEnum {
     AAA,
-    BBB;
+    BBB,
+    NO,
+    TRUE;
+  }
+
+  private enum TestEnumWithAmbiguousValues {
+    AAA,
+    BBB,
+    NO,
+    OFF,
+    YES,
+    TRUE;
   }
 }
diff --git a/junit4/src/test/java/com/google/testing/junit/testparameterinjector/PluggableTestRunnerTest.java b/junit4/src/test/java/com/google/testing/junit/testparameterinjector/PluggableTestRunnerTest.java
index f7afd79..e1914e2 100644
--- a/junit4/src/test/java/com/google/testing/junit/testparameterinjector/PluggableTestRunnerTest.java
+++ b/junit4/src/test/java/com/google/testing/junit/testparameterinjector/PluggableTestRunnerTest.java
@@ -85,7 +85,6 @@ public class PluggableTestRunnerTest {
     }
   }
 
-  @RunWith(PluggableTestRunner.class)
   public static class TestAndMethodRuleTestClass {
 
     @Rule public TestAndMethodRule rule = new TestAndMethodRule();
@@ -99,17 +98,11 @@ public class PluggableTestRunnerTest {
   @Test
   public void ruleThatIsBothTestRuleAndMethodRuleIsInvokedOnceOnly() throws Exception {
     SharedTestUtilitiesJUnit4.runTestsAndAssertNoFailures(
-        new PluggableTestRunner(TestAndMethodRuleTestClass.class) {
-          @Override
-          protected TestMethodProcessorList createTestMethodProcessorList() {
-            return TestMethodProcessorList.empty();
-          }
-        });
+        new PluggableTestRunner(TestAndMethodRuleTestClass.class) {});
 
     assertThat(ruleInvocations).hasSize(1);
   }
 
-  @RunWith(PluggableTestRunner.class)
   public static class RuleOrderingTestClassWithExplicitOrder {
 
     @Rule(order = 3)
@@ -130,17 +123,11 @@ public class PluggableTestRunnerTest {
   @Test
   public void rulesAreSortedCorrectly_withExplicitOrder() throws Exception {
     SharedTestUtilitiesJUnit4.runTestsAndAssertNoFailures(
-        new PluggableTestRunner(RuleOrderingTestClassWithExplicitOrder.class) {
-          @Override
-          protected TestMethodProcessorList createTestMethodProcessorList() {
-            return TestMethodProcessorList.empty();
-          }
-        });
+        new PluggableTestRunner(RuleOrderingTestClassWithExplicitOrder.class) {});
 
     assertThat(ruleInvocations).containsExactly("B", "C", "A").inOrder();
   }
 
-  @RunWith(PluggableTestRunner.class)
   public static class CustomTestAnnotationTestClass {
     @SuppressWarnings("JUnit4TestNotRun")
     @CustomTest
@@ -159,10 +146,6 @@ public class PluggableTestRunnerTest {
     testMethodInvocationCount = 0;
     SharedTestUtilitiesJUnit4.runTestsAndAssertNoFailures(
         new PluggableTestRunner(CustomTestAnnotationTestClass.class) {
-          @Override
-          protected TestMethodProcessorList createTestMethodProcessorList() {
-            return TestMethodProcessorList.empty();
-          }
 
           @Override
           protected ImmutableList<Class<? extends Annotation>> getSupportedTestAnnotations() {
@@ -173,7 +156,6 @@ public class PluggableTestRunnerTest {
     assertThat(testMethodInvocationCount).isEqualTo(2);
   }
 
-  @RunWith(PluggableTestRunner.class)
   public static class SortedPluggableTestRunnerTestClass {
     @Test
     public void a() {
@@ -196,10 +178,6 @@ public class PluggableTestRunnerTest {
     testOrder.clear();
     SharedTestUtilitiesJUnit4.runTestsAndAssertNoFailures(
         new PluggableTestRunner(SortedPluggableTestRunnerTestClass.class) {
-          @Override
-          protected TestMethodProcessorList createTestMethodProcessorList() {
-            return TestMethodProcessorList.empty();
-          }
 
           @Override
           protected ImmutableList<FrameworkMethod> sortTestMethods(
diff --git a/junit4/src/test/java/com/google/testing/junit/testparameterinjector/TestParameterAnnotationMethodProcessorTest.java b/junit4/src/test/java/com/google/testing/junit/testparameterinjector/TestParameterAnnotationMethodProcessorTest.java
index 458b623..556f27c 100644
--- a/junit4/src/test/java/com/google/testing/junit/testparameterinjector/TestParameterAnnotationMethodProcessorTest.java
+++ b/junit4/src/test/java/com/google/testing/junit/testparameterinjector/TestParameterAnnotationMethodProcessorTest.java
@@ -27,12 +27,10 @@ import java.lang.annotation.Retention;
 import java.util.Arrays;
 import java.util.Collection;
 import java.util.List;
-import java.util.function.Function;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.junit.runners.Parameterized;
 import org.junit.runners.Parameterized.Parameters;
-import org.junit.runners.model.TestClass;
 
 /**
  * Test class to test the PluggableTestRunner test harness works with {@link
@@ -830,8 +828,7 @@ public class TestParameterAnnotationMethodProcessorTest {
     switch (result) {
       case SUCCESS_ALWAYS:
         SharedTestUtilitiesJUnit4.runTestsAndAssertNoFailures(
-            newTestRunnerWithParameterizedSupport(
-                testClass -> TestMethodProcessorList.createNewParameterizedProcessors()));
+            newTestRunner(/* supportLegacyFeatures= */ false));
         break;
 
       case SUCCESS_FOR_ALL_PLACEMENTS_ONLY:
@@ -839,8 +836,7 @@ public class TestParameterAnnotationMethodProcessorTest {
             Exception.class,
             () ->
                 SharedTestUtilitiesJUnit4.runTestsAndGetFailures(
-                    newTestRunnerWithParameterizedSupport(
-                        testClass -> TestMethodProcessorList.createNewParameterizedProcessors())));
+                    newTestRunner(/* supportLegacyFeatures= */ false)));
         break;
 
       case FAILURE:
@@ -848,19 +844,12 @@ public class TestParameterAnnotationMethodProcessorTest {
             Exception.class,
             () ->
                 SharedTestUtilitiesJUnit4.runTestsAndGetFailures(
-                    newTestRunnerWithParameterizedSupport(
-                        testClass -> TestMethodProcessorList.createNewParameterizedProcessors())));
+                    newTestRunner(/* supportLegacyFeatures= */ false)));
         break;
     }
   }
 
-  private PluggableTestRunner newTestRunnerWithParameterizedSupport(
-      Function<TestClass, TestMethodProcessorList> processorListGenerator) throws Exception {
-    return new PluggableTestRunner(testClass) {
-      @Override
-      protected TestMethodProcessorList createTestMethodProcessorList() {
-        return processorListGenerator.apply(getTestClass());
-      }
-    };
+  private PluggableTestRunner newTestRunner(boolean supportLegacyFeatures) throws Exception {
+    return new PluggableTestRunner(testClass) {};
   }
 }
diff --git a/junit4/src/test/java/com/google/testing/junit/testparameterinjector/TestParameterInjectorKotlinTest.kt b/junit4/src/test/java/com/google/testing/junit/testparameterinjector/TestParameterInjectorKotlinTest.kt
index 10ce60e..231b556 100644
--- a/junit4/src/test/java/com/google/testing/junit/testparameterinjector/TestParameterInjectorKotlinTest.kt
+++ b/junit4/src/test/java/com/google/testing/junit/testparameterinjector/TestParameterInjectorKotlinTest.kt
@@ -243,11 +243,7 @@ class TestParameterInjectorKotlinTest {
   @Test
   fun test_success() {
     SharedTestUtilitiesJUnit4.runTestsAndAssertNoFailures(
-      object : PluggableTestRunner(testClass) {
-        override fun createTestMethodProcessorList(): TestMethodProcessorList {
-          return TestMethodProcessorList.createNewParameterizedProcessors()
-        }
-      }
+      object : PluggableTestRunner(testClass) {}
     )
   }
 
@@ -267,7 +263,7 @@ class TestParameterInjectorKotlinTest {
   enum class Color {
     RED,
     BLUE,
-    GREEN
+    GREEN,
   }
 
   @JvmInline value class ColorValueClass(val onlyValue: Color)
diff --git a/junit4/src/test/java/com/google/testing/junit/testparameterinjector/TestParameterTest.java b/junit4/src/test/java/com/google/testing/junit/testparameterinjector/TestParameterTest.java
index 7c915ea..509005e 100644
--- a/junit4/src/test/java/com/google/testing/junit/testparameterinjector/TestParameterTest.java
+++ b/junit4/src/test/java/com/google/testing/junit/testparameterinjector/TestParameterTest.java
@@ -238,13 +238,7 @@ public class TestParameterTest {
 
   @Test
   public void test() throws Exception {
-    SharedTestUtilitiesJUnit4.runTestsAndAssertNoFailures(
-        new PluggableTestRunner(testClass) {
-          @Override
-          protected TestMethodProcessorList createTestMethodProcessorList() {
-            return TestMethodProcessorList.createNewParameterizedProcessors();
-          }
-        });
+    SharedTestUtilitiesJUnit4.runTestsAndAssertNoFailures(new PluggableTestRunner(testClass) {});
   }
 
   private static ImmutableList<Class<? extends Annotation>> annotationTypes(
diff --git a/junit4/src/test/java/com/google/testing/junit/testparameterinjector/TestParametersMethodProcessorTest.java b/junit4/src/test/java/com/google/testing/junit/testparameterinjector/TestParametersMethodProcessorTest.java
index 5628330..e8cedd0 100644
--- a/junit4/src/test/java/com/google/testing/junit/testparameterinjector/TestParametersMethodProcessorTest.java
+++ b/junit4/src/test/java/com/google/testing/junit/testparameterinjector/TestParametersMethodProcessorTest.java
@@ -15,17 +15,23 @@
 package com.google.testing.junit.testparameterinjector;
 
 import static com.google.common.collect.ImmutableList.toImmutableList;
+import static com.google.common.collect.Iterables.getOnlyElement;
+import static com.google.common.collect.Lists.newArrayList;
 import static com.google.common.truth.Truth.assertThat;
 import static com.google.common.truth.TruthJUnit.assume;
 import static java.lang.annotation.RetentionPolicy.RUNTIME;
 import static org.junit.Assert.assertThrows;
 
+import com.google.common.collect.FluentIterable;
 import com.google.common.collect.ImmutableList;
 import com.google.common.collect.ImmutableMap;
 import com.google.testing.junit.testparameterinjector.SharedTestUtilitiesJUnit4.SuccessfulTestCaseBase;
 import com.google.testing.junit.testparameterinjector.TestParameters.TestParametersValues;
-import com.google.testing.junit.testparameterinjector.TestParameters.TestParametersValuesProvider;
+import com.google.testing.junit.testparameterinjector.TestParametersValuesProvider.Context;
+import java.lang.annotation.Annotation;
+import java.lang.annotation.Repeatable;
 import java.lang.annotation.Retention;
+import java.time.Duration;
 import java.util.Arrays;
 import java.util.Collection;
 import java.util.List;
@@ -49,9 +55,9 @@ public class TestParametersMethodProcessorTest {
     THREE;
   }
 
-  private static final class TestEnumValuesProvider implements TestParametersValuesProvider {
+  private static final class TestEnumValuesProvider extends TestParametersValuesProvider {
     @Override
-    public List<TestParametersValues> provideValues() {
+    public List<TestParametersValues> provideValues(Context context) {
       return ImmutableList.of(
           TestParametersValues.builder().name("one").addParameter("testEnum", TestEnum.ONE).build(),
           TestParametersValues.builder().addParameter("testEnum", TestEnum.TWO).build(),
@@ -115,6 +121,14 @@ public class TestParametersMethodProcessorTest {
       storeTestParametersForThisTest(testEnum);
     }
 
+    @Test
+    @TestParameters("{testDuration: 0}")
+    @TestParameters("{testDuration: 1d}")
+    @TestParameters("{testDuration: -2h}")
+    public void test5_withDuration(Duration testDuration) {
+      storeTestParametersForThisTest(testDuration);
+    }
+
     @Override
     ImmutableMap<String, String> expectedTestNameToStringifiedParameters() {
       return ImmutableMap.<String, String>builder()
@@ -162,6 +176,9 @@ public class TestParametersMethodProcessorTest {
           .put("test4_withCustomName[custom1]", "ONE")
           .put("test4_withCustomName[{testEnum: TWO}]", "TWO")
           .put("test4_withCustomName[custom3]", "THREE")
+          .put("test5_withDuration[{testDuration: 0}]", "PT0S")
+          .put("test5_withDuration[{testDuration: 1d}]", "PT24H")
+          .put("test5_withDuration[{testDuration: -2h}]", "PT-2H")
           .build();
     }
   }
@@ -264,9 +281,9 @@ public class TestParametersMethodProcessorTest {
           .build();
     }
 
-    private static final class CustomProvider implements TestParametersValuesProvider {
+    private static final class CustomProvider extends TestParametersValuesProvider {
       @Override
-      public List<TestParametersValues> provideValues() {
+      public List<TestParametersValues> provideValues(Context context) {
         return ImmutableList.of(
             TestParametersValues.builder()
                 .addParameter("testInt", 5)
@@ -280,6 +297,109 @@ public class TestParametersMethodProcessorTest {
     }
   }
 
+  @RunAsTest
+  public static class ProviderWithContext extends SuccessfulTestCaseBase {
+
+    @CustomAnnotation('A')
+    @CustomRepeatableAnnotation('B')
+    @TestParameters(valuesProvider = InjectContextProvider.class)
+    public ProviderWithContext(Context context) {
+      assertThat(context.testClass()).isEqualTo(ProviderWithContext.class);
+
+      assertThat(annotationTypes(context.annotationsOnParameter()))
+          .containsExactly(
+              TestParameters.class, CustomAnnotation.class, CustomRepeatableAnnotation.class);
+
+      assertThat(context.getOtherAnnotation(CustomAnnotation.class).value()).isEqualTo('A');
+
+      assertThat(getOnlyElement(context.getOtherAnnotations(CustomAnnotation.class)).value())
+          .isEqualTo('A');
+      assertThat(
+              getOnlyElement(context.getOtherAnnotations(CustomRepeatableAnnotation.class)).value())
+          .isEqualTo('B');
+    }
+
+    @TestParameters(valuesProvider = InjectContextProvider.class)
+    @Test
+    public void testWithoutOtherAnnotations(Context context) {
+      assertThat(context.testClass()).isEqualTo(ProviderWithContext.class);
+
+      assertThat(annotationTypes(context.annotationsOnParameter()))
+          .containsExactly(TestParameters.class, Test.class);
+
+      assertThat(context.getOtherAnnotations(CustomAnnotation.class)).isEmpty();
+      assertThat(context.getOtherAnnotations(CustomRepeatableAnnotation.class)).isEmpty();
+
+      storeTestParametersForThisTest(context);
+    }
+
+    @TestParameters(valuesProvider = InjectContextProvider.class)
+    @CustomAnnotation('C')
+    @CustomRepeatableAnnotation('D')
+    @CustomRepeatableAnnotation('E')
+    @Test
+    public void testWithOtherAnnotations(Context context) {
+      assertThat(context.testClass()).isEqualTo(ProviderWithContext.class);
+
+      assertThat(annotationTypes(context.annotationsOnParameter()))
+          .containsExactly(
+              TestParameters.class,
+              Test.class,
+              CustomAnnotation.class,
+              CustomRepeatableAnnotation.CustomRepeatableAnnotationHolder.class);
+
+      assertThat(context.getOtherAnnotation(CustomAnnotation.class).value()).isEqualTo('C');
+
+      assertThat(getOnlyElement(context.getOtherAnnotations(CustomAnnotation.class)).value())
+          .isEqualTo('C');
+      assertThat(
+              FluentIterable.from(context.getOtherAnnotations(CustomRepeatableAnnotation.class))
+                  .transform(a -> a.value())
+                  .toList())
+          .containsExactly('D', 'E');
+
+      storeTestParametersForThisTest(context);
+    }
+
+    @Override
+    ImmutableMap<String, String> expectedTestNameToStringifiedParameters() {
+      return ImmutableMap.<String, String>builder()
+          .put(
+              "testWithoutOtherAnnotations[1.{context(annotationsOnParameter=[@TestParameters,@CustomAnnotation,@CustomRepe...,1.{context(annotationsOnParameter=[@TestParameters,@Test],testClass=ProviderWith...]",
+              "context(annotationsOnParameter=[@TestParameters,@Test],testClass=ProviderWithContext)")
+          .put(
+              "testWithOtherAnnotations[1.{context(annotationsOnParameter=[@TestParameters,@CustomAnnotation,@CustomRepeat...,1.{context(annotationsOnParameter=[@TestParameters,@CustomAnnotation,@CustomRepeat...]",
+              "context(annotationsOnParameter=[@TestParameters,@CustomAnnotation,@CustomRepeatableAnnotationHolder,@Test],testClass=ProviderWithContext)")
+          .build();
+    }
+
+    private static final class InjectContextProvider extends TestParametersValuesProvider {
+      @Override
+      protected List<TestParametersValues> provideValues(Context context) {
+        return newArrayList(
+            TestParametersValues.builder().addParameter("context", context).build());
+      }
+    }
+
+    @Retention(RUNTIME)
+    @interface CustomAnnotation {
+      char value();
+    }
+
+    @Retention(RUNTIME)
+    @Repeatable(CustomRepeatableAnnotation.CustomRepeatableAnnotationHolder.class)
+    @interface CustomRepeatableAnnotation {
+      char value();
+
+      @Retention(RUNTIME)
+      @interface CustomRepeatableAnnotationHolder {
+        CustomRepeatableAnnotation[] value();
+
+        String test() default "TEST";
+      }
+    }
+  }
+
   public abstract static class BaseClassWithMethodAnnotation extends SuccessfulTestCaseBase {
 
     @Test
@@ -544,11 +664,11 @@ public class TestParametersMethodProcessorTest {
   }
 
   private PluggableTestRunner newTestRunner() throws Exception {
-    return new PluggableTestRunner(testClass) {
-      @Override
-      protected TestMethodProcessorList createTestMethodProcessorList() {
-        return TestMethodProcessorList.createNewParameterizedProcessors();
-      }
-    };
+    return new PluggableTestRunner(testClass) {};
+  }
+
+  private static ImmutableList<Class<? extends Annotation>> annotationTypes(
+      Iterable<Annotation> annotations) {
+    return FluentIterable.from(annotations).transform(Annotation::annotationType).toList();
   }
 }
diff --git a/junit5/src/main/java/com/google/testing/junit/testparameterinjector/junit5/GenericParameterContext.java b/junit5/src/main/java/com/google/testing/junit/testparameterinjector/junit5/GenericParameterContext.java
index 02e5367..861f3b0 100644
--- a/junit5/src/main/java/com/google/testing/junit/testparameterinjector/junit5/GenericParameterContext.java
+++ b/junit5/src/main/java/com/google/testing/junit/testparameterinjector/junit5/GenericParameterContext.java
@@ -24,6 +24,7 @@ import com.google.common.collect.ImmutableList;
 import com.google.common.collect.Ordering;
 import java.lang.annotation.Annotation;
 import java.lang.annotation.Repeatable;
+import java.lang.reflect.Executable;
 import java.lang.reflect.Field;
 import java.lang.reflect.Method;
 import java.lang.reflect.Parameter;
@@ -79,6 +80,17 @@ final class GenericParameterContext {
         testClass);
   }
 
+  // Executable is not available on old Android SDKs, and isn't desugared. This method is only
+  // called via @TestParameters, wich only supports newer SDKs anyway.
+  @SuppressWarnings("AndroidJdkLibsChecker")
+  static GenericParameterContext create(Executable executable, Class<?> testClass) {
+    return new GenericParameterContext(
+        ImmutableList.copyOf(executable.getAnnotations()),
+        /* getAnnotationsFunction= */ annotationType ->
+            ImmutableList.copyOf(executable.getAnnotationsByType(annotationType)),
+        testClass);
+  }
+
   static GenericParameterContext createWithRepeatableAnnotationsFallback(
       Annotation[] annotationsOnParameter, Class<?> testClass) {
     return new GenericParameterContext(
diff --git a/junit5/src/main/java/com/google/testing/junit/testparameterinjector/junit5/ParameterValueParsing.java b/junit5/src/main/java/com/google/testing/junit/testparameterinjector/junit5/ParameterValueParsing.java
index 130c186..7631e59 100644
--- a/junit5/src/main/java/com/google/testing/junit/testparameterinjector/junit5/ParameterValueParsing.java
+++ b/junit5/src/main/java/com/google/testing/junit/testparameterinjector/junit5/ParameterValueParsing.java
@@ -14,27 +14,39 @@
 
 package com.google.testing.junit.testparameterinjector.junit5;
 
+import static com.google.common.base.MoreObjects.firstNonNull;
 import static com.google.common.base.Preconditions.checkArgument;
 import static com.google.common.base.Preconditions.checkNotNull;
 import static com.google.common.base.Preconditions.checkState;
+import static com.google.common.base.Verify.verify;
+import static com.google.common.collect.Iterables.getOnlyElement;
 
 import com.google.common.base.CharMatcher;
 import com.google.common.base.Function;
 import com.google.common.base.Optional;
+import com.google.common.collect.ImmutableMap;
+import com.google.common.collect.ImmutableSet;
 import com.google.common.collect.Lists;
 import com.google.common.primitives.Primitives;
 import com.google.common.primitives.UnsignedLong;
 import com.google.common.reflect.TypeToken;
 import com.google.errorprone.annotations.CanIgnoreReturnValue;
 import java.lang.reflect.Array;
+import java.lang.reflect.Field;
 import java.lang.reflect.ParameterizedType;
 import java.math.BigInteger;
 import java.nio.charset.Charset;
+import java.time.Duration;
 import java.util.Arrays;
+import java.util.HashSet;
 import java.util.LinkedHashMap;
 import java.util.List;
 import java.util.Map;
 import java.util.Map.Entry;
+import java.util.Objects;
+import java.util.Set;
+import java.util.regex.Matcher;
+import java.util.regex.Pattern;
 import javax.annotation.Nullable;
 import org.yaml.snakeyaml.LoaderOptions;
 import org.yaml.snakeyaml.Yaml;
@@ -45,7 +57,37 @@ final class ParameterValueParsing {
 
   @SuppressWarnings("unchecked")
   static <E extends Enum<E>> Enum<?> parseEnum(String str, Class<?> enumType) {
-    return Enum.valueOf((Class<E>) enumType, str);
+    try {
+      return Enum.valueOf((Class<E>) enumType, str);
+    } catch (IllegalArgumentException e) {
+      // The given name was not a valid enum value. However, the enum might have an alias to one of
+      // its values defined as static field. This happens for example (via code generation) in the
+      // case of Protocol Buffer aliases (see the allow_alias option).
+      Optional<Enum<?>> enumValue = maybeGetStaticConstant(enumType, str);
+      if (enumValue.isPresent()) {
+        return enumValue.get();
+      } else {
+        throw e;
+      }
+    }
+  }
+
+  @SuppressWarnings("unchecked")
+  private static Optional<Enum<?>> maybeGetStaticConstant(Class<?> enumType, String fieldName) {
+    verify(enumType.isEnum(), "Given type %s is not a enum.", enumType.getSimpleName());
+    try {
+      Field field = enumType.getField(fieldName);
+      Object valueCandidate = field.get(null);
+      checkArgument(
+          enumType.isInstance(valueCandidate),
+          "The field %s.%s exists, but is not of expected type %s.",
+          enumType.getSimpleName(),
+          fieldName,
+          enumType.getSimpleName());
+      return Optional.of((Enum<?>) valueCandidate);
+    } catch (SecurityException | ReflectiveOperationException e) {
+      return Optional.absent();
+    }
   }
 
   static boolean isValidYamlString(String yamlString) {
@@ -130,6 +172,11 @@ final class ParameterValueParsing {
 
     yamlValueTransformer
         .ifJavaType(Enum.class)
+        .supportParsedType(
+            Boolean.class,
+            bool ->
+                ParameterValueParsing.parseEnumIfUnambiguousYamlBoolean(
+                    bool, javaType.getRawType()))
         .supportParsedType(
             String.class, str -> ParameterValueParsing.parseEnum(str, javaType.getRawType()));
 
@@ -148,6 +195,12 @@ final class ParameterValueParsing {
           .supportParsedType(byte[].class, ByteStringReflection::copyFrom);
     }
 
+    yamlValueTransformer
+        .ifJavaType(Duration.class)
+        .supportParsedType(String.class, ParameterValueParsing::parseDuration)
+        // Support the special case where the YAML string is "0"
+        .supportParsedType(Integer.class, i -> parseDuration(String.valueOf(i)));
+
     // Added mainly for protocol buffer parsing
     yamlValueTransformer
         .ifJavaType(List.class)
@@ -166,6 +219,42 @@ final class ParameterValueParsing {
     return yamlValueTransformer.transformedJavaValue();
   }
 
+  private static Enum<?> parseEnumIfUnambiguousYamlBoolean(boolean yamlValue, Class<?> enumType) {
+    Set<String> negativeYamlStrings =
+        ImmutableSet.of("false", "False", "FALSE", "n", "N", "no", "No", "NO", "off", "Off", "OFF");
+    Set<String> positiveYamlStrings =
+        ImmutableSet.of("on", "On", "ON", "true", "True", "TRUE", "y", "Y", "yes", "Yes", "YES");
+
+    // This is the list of YAML strings that a user could have used to define this boolean. Since
+    // the user probably didn't intend a boolean but an enum (since we're expecting an enum), one of
+    // these strings may (unambiguously) match one of the enum values.
+    Set<String> yamlStringCandidates = yamlValue ? positiveYamlStrings : negativeYamlStrings;
+
+    Set<Enum<?>> matches = new HashSet<>();
+    for (Object enumValueObject : enumType.getEnumConstants()) {
+      Enum<?> enumValue = (Enum<?>) enumValueObject;
+      if (yamlStringCandidates.contains(enumValue.name())) {
+        matches.add(enumValue);
+      }
+    }
+
+    checkArgument(
+        !matches.isEmpty(),
+        "Cannot cast a boolean (%s) to an enum of type %s.",
+        yamlValue,
+        enumType.getSimpleName());
+    checkArgument(
+        matches.size() == 1,
+        "Cannot cast a boolean (%s) to an enum of type %s. It is likely that the YAML parser is"
+            + " 'wrongly' parsing one of these values as boolean: %s. You can solve this by putting"
+            + " quotes around the YAML value, forcing the YAML parser to parse a String, which can"
+            + " then be converted to the enum.",
+        yamlValue,
+        enumType.getSimpleName(),
+        matches);
+    return getOnlyElement(matches);
+  }
+
   private static Map<?, ?> parseYamlMapToJavaMap(Map<?, ?> map, TypeToken<?> javaType) {
     Map<Object, Object> returnedMap = new LinkedHashMap<>();
     for (Entry<?, ?> entry : map.entrySet()) {
@@ -294,10 +383,78 @@ final class ParameterValueParsing {
       return resultBuider.toString();
     } else if (ByteStringReflection.isInstanceOfByteString(value)) {
       return Arrays.toString(ByteStringReflection.byteStringToByteArray(value));
+    } else if (value instanceof Enum<?>) {
+      // Sometimes, enums have custom toString() methods. They are probably adding extra information
+      // (such as with protobuf enums on Android), but for a test name, the string should be as
+      // short as possible
+      return ((Enum<?>) value).name();
     } else {
       return String.valueOf(value);
     }
   }
 
+  // ********** Duration parsing ********** //
+
+  private static final ImmutableMap<String, Duration> ABBREVIATION_TO_DURATION =
+      new ImmutableMap.Builder<String, Duration>()
+          .put("d", Duration.ofDays(1))
+          .put("h", Duration.ofHours(1))
+          .put("m", Duration.ofMinutes(1))
+          .put("min", Duration.ofMinutes(1))
+          .put("s", Duration.ofSeconds(1))
+          .put("ms", Duration.ofMillis(1))
+          .put("us", Duration.ofNanos(1000))
+          .put("ns", Duration.ofNanos(1))
+          .buildOrThrow();
+  private static final Pattern UNIT_PATTERN =
+      Pattern.compile("(?x) ([0-9]+)? (\\.[0-9]*)? (d|h|min|ms?|s|us|ns)");
+  private static final CharMatcher ASCII_DIGIT = CharMatcher.inRange('0', '9');
+
+  private static Duration parseDuration(String value) {
+    checkArgument(value != null, "input value cannot be null");
+    checkArgument(!value.isEmpty(), "input value cannot be empty");
+    checkArgument(!value.equals("-"), "input value cannot be '-'");
+    checkArgument(!value.equals("+"), "input value cannot be '+'");
+
+    value = CharMatcher.whitespace().trimFrom(value);
+
+    if (Objects.equals(value, "0")) {
+      return Duration.ZERO;
+    }
+
+    Duration duration = Duration.ZERO;
+    boolean negative = value.startsWith("-");
+    boolean explicitlyPositive = value.startsWith("+");
+    int index = negative || explicitlyPositive ? 1 : 0;
+    Matcher matcher = UNIT_PATTERN.matcher(value);
+    while (matcher.find(index) && matcher.start() == index) {
+      // Prevent strings like ".s" or "d" by requiring at least one digit.
+      checkArgument(ASCII_DIGIT.matchesAnyOf(matcher.group(0)));
+      try {
+        String unit = matcher.group(3);
+
+        long whole = Long.parseLong(firstNonNull(matcher.group(1), "0"));
+        Duration singleUnit = ABBREVIATION_TO_DURATION.get(unit);
+        checkArgument(singleUnit != null, "invalid unit (%s)", unit);
+        // TODO(b/142748138): Consider using saturated duration math here
+        duration = duration.plus(singleUnit.multipliedBy(whole));
+
+        long nanosPerUnit = singleUnit.toNanos();
+        double frac = Double.parseDouble("0" + firstNonNull(matcher.group(2), ""));
+        duration = duration.plus(Duration.ofNanos((long) (nanosPerUnit * frac)));
+      } catch (ArithmeticException e) {
+        throw new IllegalArgumentException(e);
+      }
+      index = matcher.end();
+    }
+    if (index < value.length()) {
+      throw new IllegalArgumentException("Could not parse entire duration: " + value);
+    }
+    if (negative) {
+      duration = duration.negated();
+    }
+    return duration;
+  }
+
   private ParameterValueParsing() {}
 }
diff --git a/junit5/src/main/java/com/google/testing/junit/testparameterinjector/junit5/TestParameterValuesProvider.java b/junit5/src/main/java/com/google/testing/junit/testparameterinjector/junit5/TestParameterValuesProvider.java
index 29f945f..05c1212 100644
--- a/junit5/src/main/java/com/google/testing/junit/testparameterinjector/junit5/TestParameterValuesProvider.java
+++ b/junit5/src/main/java/com/google/testing/junit/testparameterinjector/junit5/TestParameterValuesProvider.java
@@ -26,8 +26,8 @@ import javax.annotation.Nullable;
 /**
  * Abstract class for custom providers of @TestParameter values.
  *
- * <p>This is a replacement for {@link TestParameter.TestParameterValuesProvider}, which will soon
- * be deprecated. The difference with the former interface is that this class provides a {@code
+ * <p>This is a replacement for {@link TestParameter.TestParameterValuesProvider}, which is
+ * deprecated. The difference with the former interface is that this class provides a {@code
  * Context} instance when invoking {@link #provideValues}.
  */
 public abstract class TestParameterValuesProvider
@@ -90,7 +90,7 @@ public abstract class TestParameterValuesProvider
      *
      * @throws NoSuchElementException if this there is no annotation with the given type
      * @throws IllegalArgumentException if there are multiple annotations with the given type
-     * @throws IllegalArgumentException if the argument it TestParameter.class because it is already
+     * @throws IllegalArgumentException if the argument is TestParameter.class because it is already
      *     handled by the TestParameterInjector framework.
      */
     public <A extends Annotation> A getOtherAnnotation(Class<A> annotationType) {
@@ -102,7 +102,7 @@ public abstract class TestParameterValuesProvider
     }
 
     /**
-     * Returns the only annotation with the given type on the field or parameter that was annotated
+     * Returns all annotations with the given type on the field or parameter that was annotated
      * with @TestParameter.
      *
      * <p>For example, if the test code is as follows:
@@ -118,12 +118,12 @@ public abstract class TestParameterValuesProvider
      *   }
      * </pre>
      *
-     * then {@code context.getOtherAnnotations(CustomAnnotation.class)} will return the annotation
+     * then {@code context.getOtherAnnotations(CustomAnnotation.class)} will return the annotations
      * with 123 and 456.
      *
      * <p>Returns an empty list if this there is no annotation with the given type.
      *
-     * @throws IllegalArgumentException if the argument it TestParameter.class because it is already
+     * @throws IllegalArgumentException if the argument is TestParameter.class because it is already
      *     handled by the TestParameterInjector framework.
      */
     public <A extends Annotation> ImmutableList<A> getOtherAnnotations(Class<A> annotationType) {
diff --git a/junit5/src/main/java/com/google/testing/junit/testparameterinjector/junit5/TestParameters.java b/junit5/src/main/java/com/google/testing/junit/testparameterinjector/junit5/TestParameters.java
index 07d0fff..65a47d8 100644
--- a/junit5/src/main/java/com/google/testing/junit/testparameterinjector/junit5/TestParameters.java
+++ b/junit5/src/main/java/com/google/testing/junit/testparameterinjector/junit5/TestParameters.java
@@ -21,13 +21,10 @@ import static java.util.Collections.unmodifiableMap;
 
 import com.google.auto.value.AutoValue;
 import com.google.common.base.Optional;
-import com.google.common.collect.ImmutableList;
-import com.google.testing.junit.testparameterinjector.junit5.TestParameters.TestParametersValuesProvider;
 import java.lang.annotation.Repeatable;
 import java.lang.annotation.Retention;
 import java.lang.annotation.Target;
 import java.util.LinkedHashMap;
-import java.util.List;
 import java.util.Map;
 import javax.annotation.Nullable;
 
@@ -172,9 +169,24 @@ public @interface TestParameters {
   Class<? extends TestParametersValuesProvider> valuesProvider() default
       DefaultTestParametersValuesProvider.class;
 
-  /** Interface for custom providers of test parameter values. */
+  /**
+   * Interface for custom providers of test parameter values.
+   *
+   * @deprecated Use {@link
+   *     com.google.testing.junit.testparameterinjector.junit5.TestParametersValuesProvider} instead. The
+   *     replacement implements this same interface, but with an additional Context parameter.
+   */
+  @Deprecated
   interface TestParametersValuesProvider {
-    List<TestParametersValues> provideValues();
+    java.util.List<TestParametersValues> provideValues();
+  }
+
+  /** Default {@link TestParametersValuesProvider} implementation that does nothing. */
+  class DefaultTestParametersValuesProvider implements TestParametersValuesProvider {
+    @Override
+    public java.util.List<TestParametersValues> provideValues() {
+      return com.google.common.collect.ImmutableList.of();
+    }
   }
 
   /** A set of parameters for a single method invocation. */
@@ -257,14 +269,6 @@ public @interface TestParameters {
     }
   }
 
-  /** Default {@link TestParametersValuesProvider} implementation that does nothing. */
-  class DefaultTestParametersValuesProvider implements TestParametersValuesProvider {
-    @Override
-    public List<TestParametersValues> provideValues() {
-      return ImmutableList.of();
-    }
-  }
-
   /**
    * Holder annotation for multiple @TestParameters annotations. This should never be used directly.
    */
diff --git a/junit5/src/main/java/com/google/testing/junit/testparameterinjector/junit5/TestParametersMethodProcessor.java b/junit5/src/main/java/com/google/testing/junit/testparameterinjector/junit5/TestParametersMethodProcessor.java
index 26a1e65..63e07d4 100644
--- a/junit5/src/main/java/com/google/testing/junit/testparameterinjector/junit5/TestParametersMethodProcessor.java
+++ b/junit5/src/main/java/com/google/testing/junit/testparameterinjector/junit5/TestParametersMethodProcessor.java
@@ -20,21 +20,20 @@ import static com.google.common.base.Verify.verify;
 import com.google.auto.value.AutoAnnotation;
 import com.google.common.base.Optional;
 import com.google.common.base.Throwables;
+import com.google.common.cache.Cache;
 import com.google.common.cache.CacheBuilder;
-import com.google.common.cache.CacheLoader;
-import com.google.common.cache.LoadingCache;
 import com.google.common.collect.FluentIterable;
 import com.google.common.collect.ImmutableList;
 import com.google.common.collect.ImmutableMap;
 import com.google.common.collect.Maps;
 import com.google.common.primitives.Primitives;
 import com.google.common.reflect.TypeToken;
-import com.google.common.util.concurrent.UncheckedExecutionException;
 import com.google.testing.junit.testparameterinjector.junit5.TestInfo.TestInfoParameter;
-import com.google.testing.junit.testparameterinjector.junit5.TestParameters.DefaultTestParametersValuesProvider;
 import com.google.testing.junit.testparameterinjector.junit5.TestParameters.RepeatedTestParameters;
 import com.google.testing.junit.testparameterinjector.junit5.TestParameters.TestParametersValues;
+import com.google.testing.junit.testparameterinjector.junit5.TestParametersValuesProvider.Context;
 import com.google.testing.junit.testparameterinjector.junit5.TestParameters.TestParametersValuesProvider;
+import com.google.testing.junit.testparameterinjector.junit5.TestParameters.DefaultTestParametersValuesProvider;
 import java.lang.annotation.Retention;
 import java.lang.annotation.RetentionPolicy;
 import java.lang.reflect.Constructor;
@@ -45,23 +44,22 @@ import java.lang.reflect.Parameter;
 import java.util.Arrays;
 import java.util.List;
 import java.util.Map;
+import java.util.concurrent.ExecutionException;
 
 /** {@code TestMethodProcessor} implementation for supporting {@link TestParameters}. */
 @SuppressWarnings("AndroidJdkLibsChecker") // Parameter is not available on old Android SDKs.
 final class TestParametersMethodProcessor implements TestMethodProcessor {
 
-  private final LoadingCache<Executable, ImmutableList<TestParametersValues>>
+  private final Cache<Executable, ImmutableList<TestParametersValues>>
       parameterValuesByConstructorOrMethodCache =
-          CacheBuilder.newBuilder()
-              .maximumSize(1000)
-              .build(CacheLoader.from(TestParametersMethodProcessor::toParameterValuesList));
+          CacheBuilder.newBuilder().maximumSize(1000).build();
 
   @Override
   public ExecutableValidationResult validateConstructor(Constructor<?> constructor) {
     if (hasRelevantAnnotation(constructor)) {
       try {
         // This method throws an exception if there is a validation error
-        getConstructorParameters(constructor);
+        ImmutableList<TestParametersValues> unused = getConstructorParameters(constructor);
       } catch (Throwable t) {
         return ExecutableValidationResult.validated(t);
       }
@@ -76,7 +74,7 @@ final class TestParametersMethodProcessor implements TestMethodProcessor {
     if (hasRelevantAnnotation(testMethod)) {
       try {
         // This method throws an exception if there is a validation error
-        getMethodParameters(testMethod);
+        ImmutableList<TestParametersValues> unused = getMethodParameters(testMethod, testClass);
       } catch (Throwable t) {
         return ExecutableValidationResult.validated(t);
       }
@@ -102,7 +100,8 @@ final class TestParametersMethodProcessor implements TestMethodProcessor {
     ImmutableList<Optional<TestParametersValues>> constructorParametersList =
         getConstructorParametersOrSingleAbsentElement(originalTest.getTestClass());
     ImmutableList<Optional<TestParametersValues>> methodParametersList =
-        getMethodParametersOrSingleAbsentElement(originalTest.getMethod());
+        getMethodParametersOrSingleAbsentElement(
+            originalTest.getMethod(), originalTest.getTestClass());
     for (int constructorParametersIndex = 0;
         constructorParametersIndex < constructorParametersList.size();
         ++constructorParametersIndex) {
@@ -157,9 +156,11 @@ final class TestParametersMethodProcessor implements TestMethodProcessor {
   }
 
   private ImmutableList<Optional<TestParametersValues>> getMethodParametersOrSingleAbsentElement(
-      Method method) {
+      Method method, Class<?> testClass) {
     return hasRelevantAnnotation(method)
-        ? FluentIterable.from(getMethodParameters(method)).transform(Optional::of).toList()
+        ? FluentIterable.from(getMethodParameters(method, testClass))
+            .transform(Optional::of)
+            .toList()
         : ImmutableList.of(Optional.absent());
   }
 
@@ -183,7 +184,8 @@ final class TestParametersMethodProcessor implements TestMethodProcessor {
   public Optional<List<Object>> maybeGetTestMethodParameters(TestInfo testInfo) {
     Method testMethod = testInfo.getMethod();
     if (hasRelevantAnnotation(testMethod)) {
-      ImmutableList<TestParametersValues> parameterValuesList = getMethodParameters(testMethod);
+      ImmutableList<TestParametersValues> parameterValuesList =
+          getMethodParameters(testMethod, testInfo.getTestClass());
       TestParametersValues parametersValues =
           parameterValuesList.get(
               testInfo.getAnnotation(TestIndexHolder.class).methodParametersIndex());
@@ -199,27 +201,31 @@ final class TestParametersMethodProcessor implements TestMethodProcessor {
 
   private ImmutableList<TestParametersValues> getConstructorParameters(Constructor<?> constructor) {
     try {
-      return parameterValuesByConstructorOrMethodCache.getUnchecked(constructor);
-    } catch (UncheckedExecutionException e) {
+      return parameterValuesByConstructorOrMethodCache.get(
+          constructor, () -> toParameterValuesList(constructor, constructor.getDeclaringClass()));
+    } catch (ExecutionException e) {
       // Rethrow IllegalStateException because they can be caused by user mistakes and the user
       // doesn't need to know that the caching layer is in between.
       Throwables.throwIfInstanceOf(e.getCause(), IllegalStateException.class);
-      throw e;
+      throw new RuntimeException(e);
     }
   }
 
-  private ImmutableList<TestParametersValues> getMethodParameters(Method method) {
+  private ImmutableList<TestParametersValues> getMethodParameters(
+      Method method, Class<?> testClass) {
     try {
-      return parameterValuesByConstructorOrMethodCache.getUnchecked(method);
-    } catch (UncheckedExecutionException e) {
+      return parameterValuesByConstructorOrMethodCache.get(
+          method, () -> toParameterValuesList(method, testClass));
+    } catch (ExecutionException e) {
       // Rethrow IllegalStateException because they can be caused by user mistakes and the user
       // doesn't need to know that the caching layer is in between.
       Throwables.throwIfInstanceOf(e.getCause(), IllegalStateException.class);
-      throw e;
+      throw new RuntimeException(e);
     }
   }
 
-  private static ImmutableList<TestParametersValues> toParameterValuesList(Executable executable) {
+  private static ImmutableList<TestParametersValues> toParameterValuesList(
+      Executable executable, Class<?> testClass) {
     checkParameterNamesArePresent(executable);
     ImmutableList<Parameter> parametersList = ImmutableList.copyOf(executable.getParameters());
 
@@ -258,7 +264,10 @@ final class TestParametersMethodProcessor implements TestMethodProcessor {
                 yamlMap -> toParameterValues(yamlMap, parametersList, annotation.customName()))
             .toList();
       } else {
-        return toParameterValuesList(annotation.valuesProvider(), parametersList);
+        return toParameterValuesList(
+            annotation.valuesProvider(),
+            parametersList,
+            GenericParameterContext.create(executable, testClass));
       }
     } else { // Not annotated with @TestParameters
       verify(
@@ -278,12 +287,22 @@ final class TestParametersMethodProcessor implements TestMethodProcessor {
   }
 
   private static ImmutableList<TestParametersValues> toParameterValuesList(
-      Class<? extends TestParametersValuesProvider> valuesProvider, List<Parameter> parameters) {
+      Class<? extends TestParametersValuesProvider> valuesProvider,
+      List<Parameter> parameters,
+      GenericParameterContext context) {
     try {
       Constructor<? extends TestParametersValuesProvider> constructor =
           valuesProvider.getDeclaredConstructor();
       constructor.setAccessible(true);
-      List<TestParametersValues> testParametersValues = constructor.newInstance().provideValues();
+      TestParametersValuesProvider provider = constructor.newInstance();
+      List<TestParametersValues> testParametersValues =
+          provider
+                  instanceof
+                  com.google.testing.junit.testparameterinjector.junit5.TestParametersValuesProvider
+              ? ((com.google.testing.junit.testparameterinjector.junit5.TestParametersValuesProvider)
+                      provider)
+                  .provideValues(new Context(context))
+              : provider.provideValues();
       for (TestParametersValues testParametersValue : testParametersValues) {
         validateThatValuesMatchParameters(testParametersValue, parameters);
       }
@@ -302,7 +321,7 @@ final class TestParametersMethodProcessor implements TestMethodProcessor {
                 "Could not find a no-arg constructor for %s.", valuesProvider.getSimpleName()),
             e);
       }
-    } catch (ReflectiveOperationException e) {
+    } catch (Exception e) {
       throw new IllegalStateException(e);
     }
   }
diff --git a/junit5/src/main/java/com/google/testing/junit/testparameterinjector/junit5/TestParametersValuesProvider.java b/junit5/src/main/java/com/google/testing/junit/testparameterinjector/junit5/TestParametersValuesProvider.java
new file mode 100644
index 0000000..7d47c37
--- /dev/null
+++ b/junit5/src/main/java/com/google/testing/junit/testparameterinjector/junit5/TestParametersValuesProvider.java
@@ -0,0 +1,149 @@
+/*
+ * Copyright 2024 Google Inc.
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
+ * in compliance with the License. You may obtain a copy of the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software distributed under the License
+ * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
+ * or implied. See the License for the specific language governing permissions and limitations under
+ * the License.
+ */
+
+package com.google.testing.junit.testparameterinjector.junit5;
+
+import static com.google.common.base.Preconditions.checkArgument;
+
+import com.google.common.annotations.VisibleForTesting;
+import com.google.common.collect.ImmutableList;
+import com.google.testing.junit.testparameterinjector.junit5.TestParameters.TestParametersValues;
+import java.lang.annotation.Annotation;
+import java.util.List;
+import java.util.NoSuchElementException;
+
+/**
+ * Abstract class for custom providers of @TestParameters values.
+ *
+ * <p>This is a replacement for {@link TestParameters.TestParametersValuesProvider}, which is
+ * deprecated. The difference with the former interface is that this class provides a {@code
+ * Context} instance when invoking {@link #provideValues}.
+ */
+public abstract class TestParametersValuesProvider
+    implements TestParameters.TestParametersValuesProvider {
+
+  protected abstract List<TestParametersValues> provideValues(Context context) throws Exception;
+
+  /**
+   * @deprecated This method should never be called as it will simply throw an {@link
+   *     UnsupportedOperationException}.
+   */
+  @Override
+  @Deprecated
+  public final List<TestParametersValues> provideValues() {
+    throw new UnsupportedOperationException(
+        "The TestParameterInjector framework should never call this method, and instead call"
+            + " #provideValues(Context)");
+  }
+
+  /**
+   * An immutable value class that contains extra information about the context of the parameter for
+   * which values are being provided.
+   */
+  public static final class Context {
+
+    private final GenericParameterContext delegate;
+
+    Context(GenericParameterContext delegate) {
+      this.delegate = delegate;
+    }
+
+    /**
+     * Returns the only annotation with the given type on the method or constructor that was
+     * annotated with @TestParameters.
+     *
+     * <p>For example, if the test code is as follows:
+     *
+     * <pre>
+     *   {@literal @}Test
+     *   {@literal @}TestParameters("{updateRequest: {country_code: BE}, expectedResultType: SUCCESS}")
+     *   {@literal @}TestParameters("{updateRequest: {country_code: XYZ}, expectedResultType: FAILURE}")
+     *   {@literal @}CustomAnnotation(123)
+     *   public void update(UpdateRequest updateRequest, ResultType expectedResultType) {
+     *     ...
+     *   }
+     * </pre>
+     *
+     * then {@code context.getOtherAnnotation(CustomAnnotation.class).value()} will equal 123.
+     *
+     * @throws NoSuchElementException if this there is no annotation with the given type
+     * @throws IllegalArgumentException if there are multiple annotations with the given type
+     * @throws IllegalArgumentException if the argument it TestParameters.class because it is
+     *     already handled by the TestParameterInjector framework.
+     */
+    public <A extends Annotation> A getOtherAnnotation(Class<A> annotationType) {
+      checkArgument(
+          !TestParameters.class.equals(annotationType),
+          "Getting the @TestParameters annotating the method or constructor is not allowed because"
+              + " it is already handled by the TestParameterInjector framework.");
+      return delegate.getAnnotation(annotationType);
+    }
+
+    /**
+     * Returns all annotations with the given type on the method or constructor that was annotated
+     * with @TestParameter.
+     *
+     * <pre>
+     *   {@literal @}Test
+     *   {@literal @}TestParameters("{updateRequest: {country_code: BE}, expectedResultType: SUCCESS}")
+     *   {@literal @}TestParameters("{updateRequest: {country_code: XYZ}, expectedResultType: FAILURE}")
+     *   {@literal @}CustomAnnotation(123)
+     *   {@literal @}CustomAnnotation(456)
+     *   public void update(UpdateRequest updateRequest, ResultType expectedResultType) {
+     *     ...
+     *   }
+     * </pre>
+     *
+     * then {@code context.getOtherAnnotations(CustomAnnotation.class)} will return the annotations
+     * with 123 and 456.
+     *
+     * <p>Returns an empty list if this there is no annotation with the given type.
+     *
+     * @throws IllegalArgumentException if the argument it TestParameters.class because it is
+     *     already handled by the TestParameterInjector framework.
+     */
+    public <A extends Annotation> ImmutableList<A> getOtherAnnotations(Class<A> annotationType) {
+      checkArgument(
+          !TestParameters.class.equals(annotationType),
+          "Getting the @TestParameters annotating the method or constructor is not allowed because"
+              + " it is already handled by the TestParameterInjector framework.");
+      return delegate.getAnnotations(annotationType);
+    }
+
+    /**
+     * The class that contains the test that is currently being run.
+     *
+     * <p>Having this can be useful when sharing providers between tests that have the same base
+     * class. In those cases, an abstract method can be called as follows:
+     *
+     * <pre>
+     *   ((MyBaseClass) context.testClass().newInstance()).myAbstractMethod()
+     * </pre>
+     */
+    public Class<?> testClass() {
+      return delegate.testClass();
+    }
+
+    /** A list of all annotations on the method or constructor. */
+    @VisibleForTesting
+    ImmutableList<Annotation> annotationsOnParameter() {
+      return delegate.annotationsOnParameter();
+    }
+
+    @Override
+    public String toString() {
+      return delegate.toString();
+    }
+  }
+}
diff --git a/junit5/src/test/java/com/google/testing/junit/testparameterinjector/junit5/TestParameterInjectorJUnit5Test.java b/junit5/src/test/java/com/google/testing/junit/testparameterinjector/junit5/TestParameterInjectorJUnit5Test.java
index 0ebf54b..88188b2 100644
--- a/junit5/src/test/java/com/google/testing/junit/testparameterinjector/junit5/TestParameterInjectorJUnit5Test.java
+++ b/junit5/src/test/java/com/google/testing/junit/testparameterinjector/junit5/TestParameterInjectorJUnit5Test.java
@@ -28,11 +28,11 @@ import com.google.common.base.Throwables;
 import com.google.common.collect.ImmutableList;
 import com.google.common.collect.ImmutableMap;
 import com.google.testing.junit.testparameterinjector.junit5.TestParameter;
-import com.google.testing.junit.testparameterinjector.junit5.TestParameter.TestParameterValuesProvider;
 import com.google.testing.junit.testparameterinjector.junit5.TestParameterInjectorTest;
+import com.google.testing.junit.testparameterinjector.junit5.TestParameterValuesProvider;
 import com.google.testing.junit.testparameterinjector.junit5.TestParameters;
 import com.google.testing.junit.testparameterinjector.junit5.TestParameters.TestParametersValues;
-import com.google.testing.junit.testparameterinjector.junit5.TestParameters.TestParametersValuesProvider;
+import com.google.testing.junit.testparameterinjector.junit5.TestParametersValuesProvider;
 import java.lang.annotation.Retention;
 import java.util.ArrayList;
 import java.util.LinkedHashMap;
@@ -310,16 +310,16 @@ class TestParameterInjectorJUnit5Test {
           .build();
     }
 
-    private static final class TestStringProvider implements TestParameterValuesProvider {
+    private static final class TestStringProvider extends TestParameterValuesProvider {
       @Override
-      public List<?> provideValues() {
+      public List<?> provideValues(Context context) {
         return newArrayList("A", "B", null, value("harry").withName("wizard"));
       }
     }
 
-    private static final class CharMatcherProvider implements TestParameterValuesProvider {
+    private static final class CharMatcherProvider extends TestParameterValuesProvider {
       @Override
-      public List<CharMatcher> provideValues() {
+      public List<CharMatcher> provideValues(Context context) {
         return newArrayList(CharMatcher.any(), CharMatcher.ascii(), CharMatcher.whitespace());
       }
     }
@@ -487,9 +487,9 @@ class TestParameterInjectorJUnit5Test {
     void test(@TestParameter(valuesProvider = NonStaticProvider.class) int i) {}
 
     @SuppressWarnings("ClassCanBeStatic")
-    class NonStaticProvider implements TestParameterValuesProvider {
+    class NonStaticProvider extends TestParameterValuesProvider {
       @Override
-      public List<?> provideValues() {
+      public List<?> provideValues(Context context) {
         return ImmutableList.of();
       }
     }
@@ -596,9 +596,9 @@ class TestParameterInjectorJUnit5Test {
     THREE;
   }
 
-  private static final class TestEnumValuesProvider implements TestParametersValuesProvider {
+  private static final class TestEnumValuesProvider extends TestParametersValuesProvider {
     @Override
-    public List<TestParametersValues> provideValues() {
+    public List<TestParametersValues> provideValues(Context context) {
       return ImmutableList.of(
           TestParametersValues.builder().name("one").addParameter("testEnum", TestEnum.ONE).build(),
           TestParametersValues.builder().name("two").addParameter("testEnum", TestEnum.TWO).build(),
```

