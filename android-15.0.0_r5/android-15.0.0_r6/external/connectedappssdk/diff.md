```diff
diff --git a/annotations/src/main/java/com/google/android/enterprise/connectedapps/annotations/CrossProfile.java b/annotations/src/main/java/com/google/android/enterprise/connectedapps/annotations/CrossProfile.java
index f6a00ba..34880ad 100644
--- a/annotations/src/main/java/com/google/android/enterprise/connectedapps/annotations/CrossProfile.java
+++ b/annotations/src/main/java/com/google/android/enterprise/connectedapps/annotations/CrossProfile.java
@@ -64,4 +64,11 @@ public @interface CrossProfile {
    * <p>This argument can only be passed when annotating types, not methods.
    */
   boolean isStatic() default false;
+
+  /**
+   * A list of additional used types
+   *
+   * <p>This argument can only be passed when annotating types, not methods.
+   */
+  Class<?>[] additionalUsedTypes() default {};
 }
diff --git a/annotations/src/main/java/com/google/android/enterprise/connectedapps/annotations/CrossUser.java b/annotations/src/main/java/com/google/android/enterprise/connectedapps/annotations/CrossUser.java
index ff2c311..47746af 100644
--- a/annotations/src/main/java/com/google/android/enterprise/connectedapps/annotations/CrossUser.java
+++ b/annotations/src/main/java/com/google/android/enterprise/connectedapps/annotations/CrossUser.java
@@ -64,4 +64,11 @@ public @interface CrossUser {
    * <p>This argument can only be passed when annotating types, not methods.
    */
   boolean isStatic() default false;
+
+  /**
+   * A list of additional used types
+   *
+   * <p>This argument can only be passed when annotating types, not methods.
+   */
+  Class<?>[] additionalUsedTypes() default {};
 }
diff --git a/annotations/src/main/java/com/google/android/enterprise/connectedapps/annotations/CustomProfileConnector.java b/annotations/src/main/java/com/google/android/enterprise/connectedapps/annotations/CustomProfileConnector.java
index 7265e72..6dcdcc7 100644
--- a/annotations/src/main/java/com/google/android/enterprise/connectedapps/annotations/CustomProfileConnector.java
+++ b/annotations/src/main/java/com/google/android/enterprise/connectedapps/annotations/CustomProfileConnector.java
@@ -79,4 +79,11 @@ public @interface CustomProfileConnector {
    */
   UncaughtExceptionsPolicy uncaughtExceptionsPolicy() default
       UncaughtExceptionsPolicy.NOTIFY_RETHROW;
+
+  /**
+   * A list of additional used types
+   *
+   * <p>This argument can only be passed when annotating types, not methods.
+   */
+  Class<?>[] additionalUsedTypes() default {};
 }
diff --git a/annotations/src/main/java/com/google/android/enterprise/connectedapps/annotations/CustomUserConnector.java b/annotations/src/main/java/com/google/android/enterprise/connectedapps/annotations/CustomUserConnector.java
index 0d01df6..09de5ba 100644
--- a/annotations/src/main/java/com/google/android/enterprise/connectedapps/annotations/CustomUserConnector.java
+++ b/annotations/src/main/java/com/google/android/enterprise/connectedapps/annotations/CustomUserConnector.java
@@ -51,4 +51,11 @@ public @interface CustomUserConnector {
    * <p>By default, this will require that a user be running, unlocked, and not in quiet mode.
    */
   AvailabilityRestrictions availabilityRestrictions() default AvailabilityRestrictions.DEFAULT;
+
+  /**
+   * A list of additional used types
+   *
+   * <p>This argument can only be passed when annotating types, not methods.
+   */
+  Class<?>[] additionalUsedTypes() default {};
 }
diff --git a/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/AlwaysThrowsGenerator.java b/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/AlwaysThrowsGenerator.java
index 6ad7219..3e5a1a9 100644
--- a/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/AlwaysThrowsGenerator.java
+++ b/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/AlwaysThrowsGenerator.java
@@ -70,6 +70,9 @@ final class AlwaysThrowsGenerator {
     ClassName singleSenderCanThrowInterface =
         InterfaceGenerator.getSingleSenderCanThrowInterfaceClassName(
             generatorContext, crossProfileType);
+    ClassName singleSenderCanThrowCacheableInterface =
+        InterfaceGenerator.getSingleSenderCanThrowCacheableInterfaceClassName(
+            generatorContext, crossProfileType);
 
     TypeSpec.Builder classBuilder =
         TypeSpec.classBuilder(className)
@@ -103,6 +106,18 @@ final class AlwaysThrowsGenerator {
             .addStatement("return new $T(this)", ifAvailableClass)
             .build());
 
+    if (crossProfileType.hasCacheableMethod()) {
+      classBuilder.addSuperinterface(singleSenderCanThrowCacheableInterface);
+
+      classBuilder.addMethod(
+          MethodSpec.methodBuilder("useCache")
+              .addAnnotation(Override.class)
+              .addModifiers(Modifier.PUBLIC)
+              .returns(singleSenderCanThrowCacheableInterface)
+              .addStatement("return new $T(this.errorMessage)", className)
+              .build());
+    }
+
     for (CrossProfileMethodInfo method : crossProfileType.crossProfileMethods()) {
       if (method.isBlocking(generatorContext, crossProfileType)) {
         generateBlockingMethodOnAlwaysThrowsClass(classBuilder, method, crossProfileType);
diff --git a/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/BundlerGenerator.java b/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/BundlerGenerator.java
index c472003..e499bb6 100644
--- a/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/BundlerGenerator.java
+++ b/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/BundlerGenerator.java
@@ -38,6 +38,7 @@ import java.util.List;
 import javax.lang.model.element.Modifier;
 import javax.lang.model.type.PrimitiveType;
 import javax.lang.model.type.TypeMirror;
+import javax.annotation.processing.Generated;
 
 /**
  * Generate the {@code *_Bundler} class for a single {@link CrossProfileConfiguration} annotated
@@ -80,6 +81,10 @@ final class BundlerGenerator {
                 BUNDLER_CLASSNAME,
                 crossProfileType.className())
             .addModifiers(Modifier.PUBLIC, Modifier.FINAL)
+            .addAnnotation(
+                AnnotationSpec.builder(Generated.class)
+                    .addMember("value", "$S", this.getClass().getCanonicalName())
+                    .build())
             .addSuperinterface(BUNDLER_CLASSNAME);
 
     classBuilder.addMethod(MethodSpec.constructorBuilder().addModifiers(Modifier.PUBLIC).build());
@@ -129,7 +134,7 @@ final class BundlerGenerator {
             // ReflectedParcelable isn't a problem because it's the same APK on both sides
             .addAnnotation(
                 AnnotationSpec.builder(SuppressWarnings.class)
-                    .addMember("value", "{\"unchecked\", \"ReflectedParcelable\"}")
+                    .addMember("value", "\"unchecked\"")
                     .build())
             .addParameter(PARCEL_CLASSNAME, "parcel")
             .addParameter(Object.class, "value")
@@ -284,7 +289,7 @@ final class BundlerGenerator {
             // This is for passing rawtypes into the Parcelable*.of() methods
             .addAnnotation(
                 AnnotationSpec.builder(SuppressWarnings.class)
-                    .addMember("value", "{\"unchecked\", \"ReflectedParcelable\"}")
+                    .addMember("value", "\"unchecked\"")
                     .build())
             .addAnnotation(Override.class)
             .addModifiers(Modifier.PUBLIC)
diff --git a/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/CurrentProfileGenerator.java b/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/CurrentProfileGenerator.java
index d16bdf8..a892243 100644
--- a/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/CurrentProfileGenerator.java
+++ b/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/CurrentProfileGenerator.java
@@ -72,6 +72,9 @@ final class CurrentProfileGenerator {
     ClassName singleSenderCanThrowInterface =
         InterfaceGenerator.getSingleSenderCanThrowInterfaceClassName(
             generatorContext, crossProfileType);
+    ClassName singleSenderCanThrowCacheableInterface =
+        InterfaceGenerator.getSingleSenderCanThrowCacheableInterfaceClassName(
+            generatorContext, crossProfileType);
 
     TypeSpec.Builder classBuilder =
         TypeSpec.classBuilder(className)
@@ -110,6 +113,19 @@ final class CurrentProfileGenerator {
             .addStatement("return new $T(this)", ifAvailableClass)
             .build());
 
+    if (crossProfileType.hasCacheableMethod()) {
+      classBuilder.addMethod(
+          MethodSpec.methodBuilder("useCache")
+              .addAnnotation(Override.class)
+              .addModifiers(Modifier.PUBLIC)
+              .returns(singleSenderCanThrowCacheableInterface)
+              .addStatement(
+                  "throw new $T($S)",
+                  IllegalStateException.class,
+                  "Results of calls to the current profile can't be cached")
+              .build());
+    }
+
     generatorUtilities.writeClassToFile(className.packageName(), classBuilder);
   }
 
diff --git a/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/EarlyValidator.java b/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/EarlyValidator.java
index 8c84a70..7801c33 100644
--- a/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/EarlyValidator.java
+++ b/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/EarlyValidator.java
@@ -53,6 +53,7 @@ import com.google.android.enterprise.connectedapps.processor.containers.Validato
 import com.squareup.javapoet.ClassName;
 import com.squareup.javapoet.ParameterizedTypeName;
 import com.squareup.javapoet.TypeName;
+import com.google.common.collect.ImmutableList;
 import java.io.Serializable;
 import java.util.Arrays;
 import java.util.Collection;
@@ -102,6 +103,9 @@ public final class EarlyValidator {
       "@CROSS_PROFILE_ANNOTATION types must not be in the default package";
   private static final String NON_PUBLIC_CROSS_PROFILE_TYPE_ERROR =
       "@CROSS_PROFILE_ANNOTATION types must be public";
+  private static final String ADDITIONAL_TYPE_INVALID_TYPE_ERROR =
+      "The additional type %s cannot be used by used as a parameter for, or returned by methods"
+          + " annotated @CROSS_PROFILE_ANNOTATION";
   private static final String NOT_A_PROVIDER_CLASS_ERROR =
       "All classes specified in 'providers' must be provider classes";
   private static final String CONNECTOR_MUST_BE_INTERFACE = "Connectors must be interfaces";
@@ -517,7 +521,33 @@ public final class EarlyValidator {
             validatorContext.newProviderClasses());
 
     for (ValidatorCrossProfileTypeInfo crossProfileType : crossProfileTypes) {
-      isValid = validateCrossProfileType(crossProfileType) && isValid;
+      isValid =
+          validateCrossProfileType(crossProfileType)
+              && validateAdditionalUsedTypes(crossProfileType)
+              && isValid;
+    }
+
+    return isValid;
+  }
+
+  private boolean validateAdditionalUsedTypes(ValidatorCrossProfileTypeInfo crossProfileType) {
+    boolean isValid = true;
+    ImmutableList<TypeElement> additionalUsedTypes =
+        crossProfileType.additionalUsedTypes().asList();
+
+    for (TypeElement supportedType : additionalUsedTypes) {
+      if (!crossProfileType
+              .supportedTypes()
+              .isValidReturnType(supportedType.asType(), /* check generics */ false)
+          && !crossProfileType
+              .supportedTypes()
+              .isValidParameterType(supportedType.asType(), /* check generics */ false)) {
+
+        showError(
+            String.format(ADDITIONAL_TYPE_INVALID_TYPE_ERROR, supportedType.getSimpleName()),
+            supportedType);
+        isValid = false;
+      }
     }
 
     return isValid;
diff --git a/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/FakeOtherCacheableGenerator.java b/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/FakeOtherCacheableGenerator.java
new file mode 100644
index 0000000..c51b2dc
--- /dev/null
+++ b/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/FakeOtherCacheableGenerator.java
@@ -0,0 +1,139 @@
+/*
+ * Copyright 2021 Google LLC
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *   https://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+package com.google.android.enterprise.connectedapps.processor;
+
+import static com.google.android.enterprise.connectedapps.processor.ClassNameUtilities.append;
+import static com.google.android.enterprise.connectedapps.processor.ClassNameUtilities.transformClassName;
+import static com.google.android.enterprise.connectedapps.processor.CommonClassNames.FAKE_PROFILE_CONNECTOR_CLASSNAME;
+import static com.google.android.enterprise.connectedapps.processor.CommonClassNames.UNAVAILABLE_PROFILE_EXCEPTION_CLASSNAME;
+import static com.google.android.enterprise.connectedapps.processor.containers.CrossProfileMethodInfo.AutomaticallyResolvedParameterFilterBehaviour.REMOVE_AUTOMATICALLY_RESOLVED_PARAMETERS;
+import static com.google.common.base.Preconditions.checkNotNull;
+
+import com.google.android.enterprise.connectedapps.processor.containers.CrossProfileMethodInfo;
+import com.google.android.enterprise.connectedapps.processor.containers.CrossProfileTypeInfo;
+import com.google.android.enterprise.connectedapps.processor.containers.GeneratorContext;
+import com.squareup.javapoet.ClassName;
+import com.squareup.javapoet.FieldSpec;
+import com.squareup.javapoet.MethodSpec;
+import com.squareup.javapoet.TypeSpec;
+import javax.lang.model.element.Modifier;
+
+/**
+ * Generate the {@code Profile_*_FakeOtherCacheable} class for a single cross-profile type.
+ *
+ * <p>This must only be used once. It should be used after {@link EarlyValidator} has been used to
+ * validate that the annotated code is correct.
+ */
+final class FakeOtherCacheableGenerator {
+
+  private boolean generated = false;
+  private final GeneratorContext generatorContext;
+  private final GeneratorUtilities generatorUtilities;
+  private final CrossProfileTypeInfo crossProfileType;
+
+  FakeOtherCacheableGenerator(
+      GeneratorContext generatorContext, CrossProfileTypeInfo crossProfileType) {
+    this.generatorContext = checkNotNull(generatorContext);
+    this.generatorUtilities = new GeneratorUtilities(generatorContext);
+    this.crossProfileType = checkNotNull(crossProfileType);
+  }
+
+  void generate() {
+    if (generated) {
+      throw new IllegalStateException(
+          "FakeOtherCacheableGenerator#generate can only be called once");
+    }
+    generated = true;
+
+    generateFakeOtherCacheable();
+  }
+
+  private void generateFakeOtherCacheable() {
+    ClassName className = getFakeOtherCacheableClassName(generatorContext, crossProfileType);
+
+    ClassName singleSenderCanThrowInterface =
+        InterfaceGenerator.getSingleSenderCanThrowInterfaceClassName(
+            generatorContext, crossProfileType);
+    ClassName singleSenderCanThrowCacheableInterface =
+        InterfaceGenerator.getSingleSenderCanThrowCacheableInterfaceClassName(
+            generatorContext, crossProfileType);
+
+    TypeSpec.Builder classBuilder =
+        TypeSpec.classBuilder(className)
+            .addJavadoc(
+                "Fake implementation of {@link $T} for use during tests.\n\n"
+                    + "<p>This acts based on the state of the passed in {@link $T} and acts as if"
+                    + " making a call on the other profile.\n",
+                singleSenderCanThrowCacheableInterface,
+                FAKE_PROFILE_CONNECTOR_CLASSNAME)
+            .addModifiers(Modifier.PUBLIC, Modifier.FINAL)
+            .addSuperinterface(singleSenderCanThrowCacheableInterface);
+
+    classBuilder.addField(
+        FieldSpec.builder(singleSenderCanThrowInterface, "singleSenderCanThrow")
+            .addModifiers(Modifier.PRIVATE, Modifier.FINAL)
+            .build());
+
+    classBuilder.addMethod(
+        MethodSpec.constructorBuilder()
+            .addModifiers(Modifier.PUBLIC)
+            .addParameter(singleSenderCanThrowInterface, "singleSenderCanThrow")
+            .addStatement("this.singleSenderCanThrow = singleSenderCanThrow")
+            .build());
+
+    for (CrossProfileMethodInfo method : crossProfileType.crossProfileMethods()) {
+      if (!method.isCacheable()) {
+        continue;
+      }
+
+      if (method.isBlocking(generatorContext, crossProfileType)) {
+        generateBlockingMethodOnFakeOtherCacheable(classBuilder, method, crossProfileType);
+      } else {
+        throw new IllegalStateException("Unknown method type: " + method);
+      }
+    }
+
+    generatorUtilities.writeClassToFile(className.packageName(), classBuilder);
+  }
+
+  private void generateBlockingMethodOnFakeOtherCacheable(
+      TypeSpec.Builder classBuilder,
+      CrossProfileMethodInfo method,
+      CrossProfileTypeInfo crossProfileType) {
+
+    MethodSpec.Builder methodBuilder =
+        MethodSpec.methodBuilder(method.simpleName())
+            .addAnnotation(Override.class)
+            .addModifiers(Modifier.PUBLIC)
+            .addExceptions(method.thrownExceptions())
+            .addException(UNAVAILABLE_PROFILE_EXCEPTION_CLASSNAME)
+            .returns(method.returnTypeTypeName())
+            .addParameters(
+                GeneratorUtilities.extractParametersFromMethod(
+                    crossProfileType.supportedTypes(),
+                    method.methodElement(),
+                    REMOVE_AUTOMATICALLY_RESOLVED_PARAMETERS));
+
+    methodBuilder.addStatement("return singleSenderCanThrow.$L()", method.simpleName());
+
+    classBuilder.addMethod(methodBuilder.build());
+  }
+
+  static ClassName getFakeOtherCacheableClassName(
+      GeneratorContext generatorContext, CrossProfileTypeInfo crossProfileType) {
+    return transformClassName(crossProfileType.generatedClassName(), append("_FakeOtherCacheable"));
+  }
+}
diff --git a/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/FakeOtherGenerator.java b/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/FakeOtherGenerator.java
index 9726689..527fbca 100644
--- a/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/FakeOtherGenerator.java
+++ b/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/FakeOtherGenerator.java
@@ -101,6 +101,23 @@ final class FakeOtherGenerator {
             .addStatement("return new $T(this)", ifAvailableClass)
             .build());
 
+    ClassName singleSenderCanThrowCacheableInterface =
+        InterfaceGenerator.getSingleSenderCanThrowCacheableInterfaceClassName(
+            generatorContext, crossProfileType);
+    ClassName fakeOtherCacheableClass =
+        FakeOtherCacheableGenerator.getFakeOtherCacheableClassName(
+            generatorContext, crossProfileType);
+
+    if (crossProfileType.hasCacheableMethod()) {
+      classBuilder.addMethod(
+          MethodSpec.methodBuilder("useCache")
+              .addAnnotation(Override.class)
+              .addModifiers(Modifier.PUBLIC)
+              .returns(singleSenderCanThrowCacheableInterface)
+              .addStatement("return new $T(this)", fakeOtherCacheableClass)
+              .build());
+    }
+
     for (CrossProfileMethodInfo method : crossProfileType.crossProfileMethods()) {
       if (method.isBlocking(generatorContext, crossProfileType)) {
         generateBlockingMethodOnFakeOther(classBuilder, method, crossProfileType);
diff --git a/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/InterfaceGenerator.java b/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/InterfaceGenerator.java
index a8d94c1..2ee66ef 100644
--- a/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/InterfaceGenerator.java
+++ b/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/InterfaceGenerator.java
@@ -69,6 +69,9 @@ final class InterfaceGenerator {
     generateSingleSenderInterface();
     generateSingleSenderCanThrowInterface();
     generateMultipleSenderInterface();
+    if (crossProfileType.hasCacheableMethod()) {
+      generateSingleSenderCanThrowCacheableInterface();
+    }
   }
 
   private void generateSingleSenderInterface() {
@@ -126,6 +129,53 @@ final class InterfaceGenerator {
     interfaceBuilder.addMethod(methodBuilder.build());
   }
 
+  private void generateSingleSenderCanThrowCacheableInterface() {
+    ClassName interfaceName =
+        getSingleSenderCanThrowCacheableInterfaceClassName(generatorContext, crossProfileType);
+
+    TypeSpec.Builder interfaceBuilder =
+        TypeSpec.interfaceBuilder(interfaceName)
+            .addModifiers(Modifier.PUBLIC)
+            .addJavadoc(
+                "Interface used for caching the results and interacting with the cached results of"
+                    + " cross-profile calls.\n",
+                crossProfileType.className());
+
+    for (CrossProfileMethodInfo method : crossProfileType.crossProfileMethods()) {
+      if (method.isCacheable()) {
+        generateMethodOnSingleSenderCanThrowCacheableInterface(
+            interfaceBuilder, method, crossProfileType);
+      }
+    }
+
+    generatorUtilities.writeClassToFile(interfaceName.packageName(), interfaceBuilder);
+  }
+
+  private void generateMethodOnSingleSenderCanThrowCacheableInterface(
+      TypeSpec.Builder interfaceBuilder,
+      CrossProfileMethodInfo method,
+      CrossProfileTypeInfo crossProfileType) {
+
+    CodeBlock methodReference = generateMethodReference(crossProfileType, method);
+
+    MethodSpec.Builder methodBuilder =
+        MethodSpec.methodBuilder(method.simpleName())
+            .addModifiers(Modifier.PUBLIC, Modifier.ABSTRACT)
+            .addExceptions(method.thrownExceptions())
+            .addException(UNAVAILABLE_PROFILE_EXCEPTION_CLASSNAME)
+            .returns(method.returnTypeTypeName())
+            .addJavadoc(
+                "Attempts to fetch the cached result of calling {@link $L} on the given profile.\n"
+                    + "If a result is not already in the cache, this will make a call to {@link $L}"
+                    + " on the given profile.\n\n",
+                methodReference,
+                methodReference);
+
+    methodBuilder.addJavadoc("@see $L\n", methodReference);
+
+    interfaceBuilder.addMethod(methodBuilder.build());
+  }
+
   private void generateSingleSenderCanThrowInterface() {
     ClassName interfaceName =
         getSingleSenderCanThrowInterfaceClassName(generatorContext, crossProfileType);
@@ -152,6 +202,20 @@ final class InterfaceGenerator {
                 IfAvailableGenerator.getIfAvailableClassName(generatorContext, crossProfileType))
             .build());
 
+    if (crossProfileType.hasCacheableMethod()) {
+      interfaceBuilder.addMethod(
+          MethodSpec.methodBuilder("useCache")
+              .addJavadoc("Check the cache before making a cross-profile call.\n\n")
+              .addJavadoc(
+                  "<p> Throws a {@link $T} if used on a call to the current profile.\n\n",
+                  IllegalStateException.class)
+              .addModifiers(Modifier.PUBLIC, Modifier.ABSTRACT)
+              .returns(
+                  getSingleSenderCanThrowCacheableInterfaceClassName(
+                      generatorContext, crossProfileType))
+              .build());
+    }
+
     generatorUtilities.writeClassToFile(interfaceName.packageName(), interfaceBuilder);
   }
 
@@ -406,8 +470,7 @@ final class InterfaceGenerator {
             PROFILE_RUNTIME_EXCEPTION_CLASSNAME)
         .addJavadoc(
             "<p>Only the first result passed in for each profile will be passed into the "
-                + "callback.\n\n"
-        )
+                + "callback.\n\n")
         .addJavadoc("@see $L\n", methodReference);
 
     interfaceBuilder.addMethod(methodBuilder.build());
@@ -445,6 +508,12 @@ final class InterfaceGenerator {
     return transformClassName(crossProfileType.generatedClassName(), append("_SingleSender"));
   }
 
+  static ClassName getSingleSenderCanThrowCacheableInterfaceClassName(
+      GeneratorContext generatorContext, CrossProfileTypeInfo crossProfileType) {
+    return transformClassName(
+        crossProfileType.generatedClassName(), append("_SingleSenderCanThrowCacheable"));
+  }
+
   static ClassName getSingleSenderCanThrowInterfaceClassName(
       GeneratorContext generatorContext, CrossProfileTypeInfo crossProfileType) {
     return transformClassName(
diff --git a/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/OtherProfileCacheableGenerator.java b/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/OtherProfileCacheableGenerator.java
new file mode 100644
index 0000000..c6080d7
--- /dev/null
+++ b/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/OtherProfileCacheableGenerator.java
@@ -0,0 +1,171 @@
+/*
+ * Copyright 2021 Google LLC
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *   https://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+package com.google.android.enterprise.connectedapps.processor;
+
+import static com.google.android.enterprise.connectedapps.processor.ClassNameUtilities.append;
+import static com.google.android.enterprise.connectedapps.processor.ClassNameUtilities.transformClassName;
+import static com.google.android.enterprise.connectedapps.processor.CommonClassNames.UNAVAILABLE_PROFILE_EXCEPTION_CLASSNAME;
+import static com.google.common.base.Preconditions.checkNotNull;
+
+import com.google.android.enterprise.connectedapps.processor.containers.CrossProfileCallbackParameterInfo;
+import com.google.android.enterprise.connectedapps.processor.containers.CrossProfileMethodInfo;
+import com.google.android.enterprise.connectedapps.processor.containers.CrossProfileTypeInfo;
+import com.google.android.enterprise.connectedapps.processor.containers.GeneratorContext;
+import com.squareup.javapoet.ClassName;
+import com.squareup.javapoet.FieldSpec;
+import com.squareup.javapoet.MethodSpec;
+import com.squareup.javapoet.TypeSpec;
+import javax.lang.model.element.Modifier;
+
+/**
+ * Generate the {@code Profile_*_OtherProfileCacheable} class for a single cross-profile type.
+ *
+ * <p>This must only be used once. It should be used after {@link EarlyValidator} has been used to
+ * validate that the annotated code is correct.
+ */
+final class OtherProfileCacheableGenerator {
+
+  private boolean generated = false;
+  private final GeneratorContext generatorContext;
+  private final GeneratorUtilities generatorUtilities;
+  private final CrossProfileTypeInfo crossProfileType;
+
+  OtherProfileCacheableGenerator(
+      GeneratorContext generatorContext, CrossProfileTypeInfo crossProfileType) {
+    this.generatorContext = checkNotNull(generatorContext);
+    this.generatorUtilities = new GeneratorUtilities(generatorContext);
+    this.crossProfileType = checkNotNull(crossProfileType);
+  }
+
+  void generate() {
+    if (generated) {
+      throw new IllegalStateException(
+          "OtherProfileCacheableGenerator#generate can only be called once");
+    }
+    generated = true;
+
+    generateOtherProfileCacheableClass();
+  }
+
+  private void generateOtherProfileCacheableClass() {
+    ClassName className = getOtherProfileCacheableClassName(generatorContext, crossProfileType);
+
+    ClassName singleSenderCanThrowInterface =
+        InterfaceGenerator.getSingleSenderCanThrowInterfaceClassName(
+            generatorContext, crossProfileType);
+    ClassName singleSenderCanThrowCacheableInterface =
+        InterfaceGenerator.getSingleSenderCanThrowCacheableInterfaceClassName(
+            generatorContext, crossProfileType);
+
+    TypeSpec.Builder classBuilder =
+        TypeSpec.classBuilder(className)
+            .addJavadoc(
+                "Implementation of {@link $T} used when interacting with the cache.\n",
+                singleSenderCanThrowCacheableInterface)
+            .addModifiers(Modifier.PUBLIC, Modifier.FINAL)
+            .addSuperinterface(singleSenderCanThrowCacheableInterface);
+
+    classBuilder.addField(
+        FieldSpec.builder(singleSenderCanThrowInterface, "singleSenderCanThrow")
+            .addModifiers(Modifier.PRIVATE, Modifier.FINAL)
+            .build());
+
+    classBuilder.addMethod(
+        MethodSpec.constructorBuilder()
+            .addModifiers(Modifier.PUBLIC)
+            .addParameter(singleSenderCanThrowInterface, "singleSenderCanThrow")
+            .addStatement("this.singleSenderCanThrow = singleSenderCanThrow")
+            .build());
+
+    for (CrossProfileMethodInfo method : crossProfileType.crossProfileMethods()) {
+      if (!method.isCacheable()) {
+        continue;
+      }
+
+      if (method.isBlocking(generatorContext, crossProfileType)) {
+        generateBlockingMethodOnOtherProfileCacheableClass(classBuilder, method);
+      } else if (method.isCrossProfileCallback(generatorContext)) {
+        generateCrossProfileCallbackMethodOnOtherProfileCacheableClass(classBuilder, method);
+      } else if (method.isFuture(crossProfileType)) {
+        generateFutureMethodOnOtherProfileCacheableClass(classBuilder, method);
+      } else {
+        throw new IllegalStateException("Unknown method type: " + method);
+      }
+    }
+
+    generatorUtilities.writeClassToFile(className.packageName(), classBuilder);
+  }
+
+  private void generateBlockingMethodOnOtherProfileCacheableClass(
+      TypeSpec.Builder classBuilder, CrossProfileMethodInfo method) {
+
+    MethodSpec.Builder methodBuilder =
+        MethodSpec.methodBuilder(method.simpleName())
+            .addAnnotation(Override.class)
+            .addModifiers(Modifier.PUBLIC)
+            .addExceptions(method.thrownExceptions())
+            .addException(UNAVAILABLE_PROFILE_EXCEPTION_CLASSNAME)
+            .returns(method.returnTypeTypeName());
+
+    // TODO: Check the cache
+    methodBuilder.addStatement("return singleSenderCanThrow.$L()", method.simpleName());
+
+    classBuilder.addMethod(methodBuilder.build());
+  }
+
+  // TODO: Add to the javadocs for future and callback methods to reflect what will be cached.
+  private void generateFutureMethodOnOtherProfileCacheableClass(
+      TypeSpec.Builder classBuilder, CrossProfileMethodInfo method) {
+
+    MethodSpec.Builder methodBuilder =
+        MethodSpec.methodBuilder(method.simpleName())
+            .addAnnotation(Override.class)
+            .addModifiers(Modifier.PUBLIC)
+            .addExceptions(method.thrownExceptions())
+            .addException(UNAVAILABLE_PROFILE_EXCEPTION_CLASSNAME)
+            .returns(method.returnTypeTypeName());
+
+    // TODO: Check the cache
+    methodBuilder.addStatement("return singleSenderCanThrow.$L()", method.simpleName());
+
+    classBuilder.addMethod(methodBuilder.build());
+  }
+
+  private void generateCrossProfileCallbackMethodOnOtherProfileCacheableClass(
+      TypeSpec.Builder classBuilder, CrossProfileMethodInfo method) {
+    CrossProfileCallbackParameterInfo callback =
+        method.getCrossProfileCallbackParam(generatorContext).get();
+
+    MethodSpec.Builder methodBuilder =
+        MethodSpec.methodBuilder(method.simpleName())
+            .addAnnotation(Override.class)
+            .addModifiers(Modifier.PUBLIC)
+            .addExceptions(method.thrownExceptions())
+            .addException(UNAVAILABLE_PROFILE_EXCEPTION_CLASSNAME)
+            .returns(method.returnTypeTypeName());
+
+    // TODO: Check the cache
+    methodBuilder.addStatement("return singleSenderCanThrow.$L()", method.simpleName());
+
+    classBuilder.addMethod(methodBuilder.build());
+  }
+
+  static ClassName getOtherProfileCacheableClassName(
+      GeneratorContext generatorContext, CrossProfileTypeInfo crossProfileType) {
+    return transformClassName(
+        crossProfileType.generatedClassName(), append("_OtherProfileCacheable"));
+  }
+}
diff --git a/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/OtherProfileGenerator.java b/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/OtherProfileGenerator.java
index 0188ea7..f4353a7 100644
--- a/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/OtherProfileGenerator.java
+++ b/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/OtherProfileGenerator.java
@@ -110,6 +110,23 @@ final class OtherProfileGenerator {
             .addStatement("return new $T(this)", ifAvailableClass)
             .build());
 
+    ClassName singleSenderCanThrowCacheableInterface =
+        InterfaceGenerator.getSingleSenderCanThrowCacheableInterfaceClassName(
+            generatorContext, crossProfileType);
+    ClassName otherProfileCacheableClass =
+        OtherProfileCacheableGenerator.getOtherProfileCacheableClassName(
+            generatorContext, crossProfileType);
+
+    if (crossProfileType.hasCacheableMethod()) {
+      classBuilder.addMethod(
+          MethodSpec.methodBuilder("useCache")
+              .addAnnotation(Override.class)
+              .addModifiers(Modifier.PUBLIC)
+              .returns(singleSenderCanThrowCacheableInterface)
+              .addStatement("return new $T(this)", otherProfileCacheableClass)
+              .build());
+    }
+
     for (CrossProfileMethodInfo method : crossProfileType.crossProfileMethods()) {
       if (method.isBlocking(generatorContext, crossProfileType)) {
         generateBlockingMethodOnOtherProfileClass(classBuilder, method, crossProfileType);
diff --git a/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/SharedTypeCodeGenerator.java b/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/SharedTypeCodeGenerator.java
index ca6c105..6608cf0 100644
--- a/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/SharedTypeCodeGenerator.java
+++ b/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/SharedTypeCodeGenerator.java
@@ -25,11 +25,13 @@ class SharedTypeCodeGenerator {
   private boolean generated = false;
   private final InterfaceGenerator interfaceGenerator;
   private final CurrentProfileGenerator currentProfileGenerator;
+  private final OtherProfileCacheableGenerator otherProfileCacheableGenerator;
   private final OtherProfileGenerator otherProfileGenerator;
   private final IfAvailableGenerator ifAvailableGenerator;
   private final AlwaysThrowsGenerator alwaysThrowsGenerator;
   private final InternalCrossProfileClassGenerator internalCrossProfileClassGenerator;
   private final BundlerGenerator bundlerGenerator;
+  private final CrossProfileTypeInfo crossProfileType;
 
   public SharedTypeCodeGenerator(
       GeneratorContext generatorContext,
@@ -37,8 +39,11 @@ class SharedTypeCodeGenerator {
       CrossProfileTypeInfo crossProfileType) {
     checkNotNull(generatorContext);
     checkNotNull(crossProfileType);
+    this.crossProfileType = crossProfileType;
     this.interfaceGenerator = new InterfaceGenerator(generatorContext, crossProfileType);
     this.currentProfileGenerator = new CurrentProfileGenerator(generatorContext, crossProfileType);
+    this.otherProfileCacheableGenerator =
+        new OtherProfileCacheableGenerator(generatorContext, crossProfileType);
     this.otherProfileGenerator = new OtherProfileGenerator(generatorContext, crossProfileType);
     this.ifAvailableGenerator = new IfAvailableGenerator(generatorContext, crossProfileType);
     this.alwaysThrowsGenerator = new AlwaysThrowsGenerator(generatorContext, crossProfileType);
@@ -60,5 +65,8 @@ class SharedTypeCodeGenerator {
     alwaysThrowsGenerator.generate();
     internalCrossProfileClassGenerator.generate();
     bundlerGenerator.generate();
+    if (crossProfileType.hasCacheableMethod()) {
+      otherProfileCacheableGenerator.generate();
+    }
   }
 }
diff --git a/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/SupportedTypes.java b/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/SupportedTypes.java
index 51eae3d..1b3a4ed 100644
--- a/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/SupportedTypes.java
+++ b/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/SupportedTypes.java
@@ -29,7 +29,7 @@ import com.google.common.collect.ImmutableMap;
 import com.squareup.javapoet.ClassName;
 import com.squareup.javapoet.CodeBlock;
 import java.util.Collection;
-import java.util.HashMap;
+import java.util.LinkedHashMap;
 import java.util.Map;
 import java.util.Objects;
 import java.util.Optional;
@@ -114,10 +114,22 @@ public final class SupportedTypes {
   }
 
   boolean isValidReturnType(TypeMirror type) {
-    return isValidReturnType(type, TypeCheckContext.create());
+    // default behaviour is to check generics
+    return isValidReturnType(type, TypeCheckContext.create(), /* checkGenerics= */ true);
   }
 
-  private boolean isValidReturnType(TypeMirror type, TypeCheckContext context) {
+  boolean isValidReturnType(TypeMirror type, TypeCheckContext context) {
+    // default behaviour is to check generics
+    return isValidReturnType(type, context, /* checkGenerics= */ true);
+  }
+
+  boolean isValidReturnType(TypeMirror type, boolean checkGenerics) {
+    return isValidReturnType(type, TypeCheckContext.create(), checkGenerics);
+  }
+
+  private boolean isValidReturnType(
+      TypeMirror type, TypeCheckContext context, boolean checkGenerics) {
+
     if (TypeUtils.isArray(type)) {
       TypeMirror wrappedType = TypeUtils.extractTypeFromArray(type);
       if (TypeUtils.isGeneric(wrappedType)) {
@@ -127,10 +139,10 @@ public final class SupportedTypes {
         // We don't support non-primitive multidimensional arrays
         return TypeUtils.isPrimitiveArray(wrappedType);
       }
-      return isValidReturnType(wrappedType, context);
+      return isValidReturnType(wrappedType, context, checkGenerics);
     }
 
-    return TypeUtils.isGeneric(type)
+    return (TypeUtils.isGeneric(type) && checkGenerics)
         ? isValidGenericReturnType(type, context)
         : isValidReturnType(get(type), context);
   }
@@ -185,10 +197,20 @@ public final class SupportedTypes {
   }
 
   boolean isValidParameterType(TypeMirror type) {
-    return isValidParameterType(type, TypeCheckContext.create());
+    // default behaviour is to check generics
+    return isValidParameterType(type, TypeCheckContext.create(), /* checkGenerics= */ true);
   }
-
+  
   boolean isValidParameterType(TypeMirror type, TypeCheckContext context) {
+    // default behaviour is to check generics
+    return isValidParameterType(type, context, /* checkGenerics= */ true);
+  }
+
+  boolean isValidParameterType(TypeMirror type, boolean checkGenerics) {
+    return isValidParameterType(type, TypeCheckContext.create(), checkGenerics);
+  }
+
+  boolean isValidParameterType(TypeMirror type, TypeCheckContext context, boolean checkGenerics) {
     if (TypeUtils.isArray(type)) {
       TypeMirror wrappedType = TypeUtils.extractTypeFromArray(type);
       if (TypeUtils.isGeneric(wrappedType)) {
@@ -198,7 +220,8 @@ public final class SupportedTypes {
         // We don't support non-primitive multidimensional arrays
         return TypeUtils.isPrimitiveArray(wrappedType);
       }
-      return isValidParameterType(wrappedType, context.toBuilder().setWrapped(true).build());
+      return isValidParameterType(
+          wrappedType, context.toBuilder().setWrapped(true).build(), checkGenerics);
     }
 
     Type supportedType = get(TypeUtils.removeTypeArguments(type));
@@ -214,7 +237,7 @@ public final class SupportedTypes {
       }
     }
 
-    return TypeUtils.isGeneric(type)
+    return (TypeUtils.isGeneric(type) && checkGenerics)
         ? isValidGenericParameterType(type, context)
         : isValidParameterType(get(type));
   }
@@ -307,7 +330,7 @@ public final class SupportedTypes {
       Collection<ParcelableWrapper> parcelableWrappers,
       Collection<FutureWrapper> futureWrappers,
       Collection<ExecutableElement> methods) {
-    Map<String, Type> usableTypes = new HashMap<>();
+    Map<String, Type> usableTypes = new LinkedHashMap<>();
 
     addDefaultTypes(context, usableTypes);
     addParcelableWrapperTypes(usableTypes, parcelableWrappers);
@@ -492,7 +515,7 @@ public final class SupportedTypes {
             .setTypeMirror(elements.getTypeElement("java.lang.CharSequence").asType())
             .setAcceptableReturnType(true)
             .setAcceptableParameterType(true)
-            .setPutIntoBundleCode("$L.putString($L, String.valueOf($L))")
+            .setPutIntoBundleCode("$1L.putString($2L, $3L == null ? null : String.valueOf($3L))")
             .setGetFromBundleCode("$L.getString($L)")
             .setWriteToParcelCode("$L.writeString(String.valueOf($L))")
             .setReadFromParcelCode("$L.readString()")
@@ -839,15 +862,24 @@ public final class SupportedTypes {
       this.usableTypes = usableTypes;
     }
 
-    /** Filtering to only include used types. */
-    public Builder filterUsed(Context context, Collection<CrossProfileMethodInfo> methods) {
+    /** Filtering to only include used types and additional used types */
+    public Builder filterUsed(
+        Context context,
+        Collection<CrossProfileMethodInfo> methods,
+        Collection<TypeElement> additionalUsedTypes) {
 
-      Map<String, Type> usedTypes = new HashMap<>();
+      Map<String, Type> usedTypes = new LinkedHashMap<>();
 
       for (CrossProfileMethodInfo method : methods) {
         copySupportedTypesForMethod(context, usedTypes, method);
       }
 
+      for (TypeElement type : additionalUsedTypes) {
+        // We do not want to recurse generics in additional types because generics will not be a
+        // supported type.
+        copySupportedType(context, usedTypes, type.asType(), /* recurseGenerics= */ false);
+      }
+
       this.usableTypes = usedTypes;
 
       return this;
@@ -861,8 +893,14 @@ public final class SupportedTypes {
       }
     }
 
+    // default behaviour is to recurse generics
     private void copySupportedType(Context context, Map<String, Type> usedTypes, TypeMirror type) {
-      if (TypeUtils.isGeneric(type)) {
+      copySupportedType(context, usedTypes, type, true);
+    }
+
+    private void copySupportedType(
+        Context context, Map<String, Type> usedTypes, TypeMirror type, boolean recurseGenerics) {
+      if (TypeUtils.isGeneric(type) && recurseGenerics) {
         copySupportedGenericType(context, usedTypes, type);
         return;
       }
@@ -915,9 +953,9 @@ public final class SupportedTypes {
       copySupportedType(usedTypes, supportedType);
     }
 
-    /** Add additianal parcelable wrappers. */
+    /** Add additional parcelable wrappers. */
     public Builder addParcelableWrappers(Collection<ParcelableWrapper> parcelableWrappers) {
-      Map<String, Type> newUsableTypes = new HashMap<>(usableTypes);
+      Map<String, Type> newUsableTypes = new LinkedHashMap<>(usableTypes);
 
       addParcelableWrapperTypes(newUsableTypes, parcelableWrappers);
 
@@ -926,9 +964,9 @@ public final class SupportedTypes {
       return this;
     }
 
-    /** Add additianal future wrappers. */
+    /** Add additional future wrappers. */
     public Builder addFutureWrappers(Collection<FutureWrapper> futureWrappers) {
-      Map<String, Type> newUsableTypes = new HashMap<>(usableTypes);
+      Map<String, Type> newUsableTypes = new LinkedHashMap<>(usableTypes);
 
       addFutureWrapperTypes(newUsableTypes, futureWrappers);
 
@@ -938,7 +976,7 @@ public final class SupportedTypes {
     }
 
     public Builder replaceWrapperPrefix(ClassName prefix) {
-      Map<String, Type> newUsableTypes = new HashMap<>();
+      Map<String, Type> newUsableTypes = new LinkedHashMap<>();
 
       for (Type usableType : usableTypes.values()) {
         if (usableType.getParcelableWrapper().isPresent()) {
diff --git a/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/TestCodeGenerator.java b/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/TestCodeGenerator.java
index e4f229a..623d856 100644
--- a/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/TestCodeGenerator.java
+++ b/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/TestCodeGenerator.java
@@ -71,6 +71,9 @@ final class TestCodeGenerator {
 
     for (CrossProfileTypeInfo type : allFakedTypes) {
       new FakeOtherGenerator(generatorContext, type).generate();
+      if (type.hasCacheableMethod()) {
+        new FakeOtherCacheableGenerator(generatorContext, type).generate();
+      }
     }
 
     for (CrossProfileTypeInfo type : crossProfileFakedTypes) {
diff --git a/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/annotationdiscovery/CrossProfileAnnotationInfoExtractor.java b/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/annotationdiscovery/CrossProfileAnnotationInfoExtractor.java
index 7403ddb..cfb1422 100644
--- a/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/annotationdiscovery/CrossProfileAnnotationInfoExtractor.java
+++ b/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/annotationdiscovery/CrossProfileAnnotationInfoExtractor.java
@@ -37,6 +37,7 @@ final class CrossProfileAnnotationInfoExtractor
   }
 
   @Override
+  @SuppressWarnings("CheckReturnValue") // extract classes from annotation is incorrectly flagged
   protected CrossProfileAnnotationInfo annotationInfoFromAnnotation(
       CrossProfileAnnotation annotation, Types types) {
     CrossProfileAnnotationInfo.Builder builder =
@@ -51,6 +52,9 @@ final class CrossProfileAnnotationInfoExtractor
                 ImmutableSet.copyOf(
                     GeneratorUtilities.extractClassesFromAnnotation(
                         types, annotation::futureWrappers)))
+            .setAdditionalUsedTypes(ImmutableSet.copyOf(
+                    GeneratorUtilities.extractClassesFromAnnotation(
+                        types, annotation::additionalUsedTypes)))
             .setIsStatic(annotation.isStatic());
 
     return builder.build();
@@ -64,6 +68,7 @@ final class CrossProfileAnnotationInfoExtractor
                 "com.google.android.enterprise.connectedapps.annotations.CrossProfile"))
         .setParcelableWrapperClasses(ImmutableSet.of())
         .setFutureWrapperClasses(ImmutableSet.of())
+        .setAdditionalUsedTypes(ImmutableSet.of())
         .setIsStatic(false)
         .build();
   }
diff --git a/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/annotationdiscovery/interfaces/CrossProfileAnnotation.java b/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/annotationdiscovery/interfaces/CrossProfileAnnotation.java
index 0d3226e..1df33d0 100644
--- a/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/annotationdiscovery/interfaces/CrossProfileAnnotation.java
+++ b/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/annotationdiscovery/interfaces/CrossProfileAnnotation.java
@@ -23,5 +23,7 @@ public interface CrossProfileAnnotation {
 
   Class<?>[] futureWrappers();
 
+  Class<?>[] additionalUsedTypes();
+
   boolean isStatic();
 }
diff --git a/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/containers/CrossProfileAnnotationInfo.java b/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/containers/CrossProfileAnnotationInfo.java
index c75cfc2..0215813 100644
--- a/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/containers/CrossProfileAnnotationInfo.java
+++ b/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/containers/CrossProfileAnnotationInfo.java
@@ -33,6 +33,8 @@ public abstract class CrossProfileAnnotationInfo {
 
   public abstract ImmutableCollection<TypeElement> futureWrapperClasses();
 
+  public abstract ImmutableCollection<TypeElement> additionalUsedTypes();
+
   public abstract boolean isStatic();
 
   public boolean connectorIsDefault() {
@@ -52,6 +54,8 @@ public abstract class CrossProfileAnnotationInfo {
 
     public abstract Builder setFutureWrapperClasses(ImmutableCollection<TypeElement> value);
 
+    public abstract Builder setAdditionalUsedTypes(ImmutableCollection<TypeElement> value);
+
     public abstract Builder setIsStatic(boolean value);
 
     public abstract CrossProfileAnnotationInfo build();
diff --git a/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/containers/CrossProfileMethodInfo.java b/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/containers/CrossProfileMethodInfo.java
index 6a90652..7980912 100644
--- a/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/containers/CrossProfileMethodInfo.java
+++ b/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/containers/CrossProfileMethodInfo.java
@@ -17,7 +17,7 @@ package com.google.android.enterprise.connectedapps.processor.containers;
 
 import static com.google.android.enterprise.connectedapps.processor.annotationdiscovery.AnnotationFinder.hasCrossProfileCallbackAnnotation;
 import static java.util.stream.Collectors.joining;
-import static java.util.stream.Collectors.toSet;
+import static java.util.stream.Collectors.toCollection;
 
 import com.google.android.enterprise.connectedapps.annotations.Cacheable;
 import com.google.android.enterprise.connectedapps.annotations.CrossProfile;
@@ -28,6 +28,7 @@ import com.google.auto.value.AutoValue;
 import com.squareup.javapoet.ClassName;
 import com.squareup.javapoet.TypeName;
 import java.util.Collection;
+import java.util.LinkedHashSet;
 import java.util.Optional;
 import java.util.function.Function;
 import javax.lang.model.element.Element;
@@ -65,13 +66,13 @@ public abstract class CrossProfileMethodInfo {
   public Collection<TypeName> thrownExceptions() {
     return methodElement().getThrownTypes().stream()
         .map(ClassName::get)
-        .collect(toSet());
+        .collect(toCollection(LinkedHashSet::new));
   }
 
   public Collection<TypeMirror> automaticallyResolvedParameterTypes(SupportedTypes supportedTypes) {
     return parameterTypes().stream()
         .filter(supportedTypes::isAutomaticallyResolved)
-        .collect(toSet());
+        .collect(toCollection(LinkedHashSet::new));
   }
 
   /**
@@ -141,7 +142,9 @@ public abstract class CrossProfileMethodInfo {
 
   /** An unordered collection of the types used in the parameters of this method. */
   public Collection<TypeMirror> parameterTypes() {
-    return methodElement().getParameters().stream().map(Element::asType).collect(toSet());
+    return methodElement().getParameters().stream()
+        .map(Element::asType)
+        .collect(toCollection(LinkedHashSet::new));
   }
 
   /**
diff --git a/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/containers/CrossProfileTypeInfo.java b/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/containers/CrossProfileTypeInfo.java
index 869eb15..75bf651 100644
--- a/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/containers/CrossProfileTypeInfo.java
+++ b/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/containers/CrossProfileTypeInfo.java
@@ -17,6 +17,7 @@ package com.google.android.enterprise.connectedapps.processor.containers;
 
 import static java.util.stream.Collectors.toCollection;
 
+import com.google.android.enterprise.connectedapps.annotations.Cacheable;
 import com.google.android.enterprise.connectedapps.annotations.CrossProfile;
 import com.google.android.enterprise.connectedapps.processor.ProcessorConfiguration;
 import com.google.android.enterprise.connectedapps.processor.SupportedTypes;
@@ -64,6 +65,16 @@ public abstract class CrossProfileTypeInfo {
     return crossProfileMethods().stream().allMatch(CrossProfileMethodInfo::isStatic);
   }
 
+  /**
+   * Checks if there are any cacheable methods on this cross-profile type.
+   *
+   * <p>Where cacheable methods are methods annotated with {@link Cacheable} indicating that the
+   * result of a cross-profile call of that method should be cached.
+   */
+  public boolean hasCacheableMethod() {
+    return crossProfileMethods().stream().anyMatch(CrossProfileMethodInfo::isCacheable);
+  }
+
   /**
    * Get a numeric identifier for the cross-profile type.
    *
@@ -76,6 +87,7 @@ public abstract class CrossProfileTypeInfo {
         .asLong();
   }
 
+  @SuppressWarnings("CheckReturnValue") // extract classes from annotation is incorrectly flagged
   public static CrossProfileTypeInfo create(
       ValidatorContext context, ValidatorCrossProfileTypeInfo crossProfileType) {
     TypeElement crossProfileTypeElement = crossProfileType.crossProfileTypeElement();
@@ -92,7 +104,8 @@ public abstract class CrossProfileTypeInfo {
 
     SupportedTypes.Builder supportedTypesBuilder = crossProfileType.supportedTypes().asBuilder();
 
-    supportedTypesBuilder.filterUsed(context, crossProfileMethods);
+    supportedTypesBuilder.filterUsed(
+        context, crossProfileMethods, crossProfileType.additionalUsedTypes());
 
     if (ProcessorConfiguration.GENERATE_TYPE_SPECIFIC_WRAPPERS) {
       supportedTypesBuilder.replaceWrapperPrefix(
diff --git a/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/containers/ParcelableWrapper.java b/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/containers/ParcelableWrapper.java
index 87f699f..b54ef53 100644
--- a/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/containers/ParcelableWrapper.java
+++ b/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/containers/ParcelableWrapper.java
@@ -202,6 +202,72 @@ public abstract class ParcelableWrapper {
         "com.google.common.collect.ImmutableMap",
         ClassName.get(PARCELABLE_WRAPPER_PACKAGE, "ParcelableImmutableMap"));
 
+    tryAddWrapper(
+        elements,
+        wrappers,
+        "com.google.common.collect.ImmutableMultimap",
+        ClassName.get(PARCELABLE_WRAPPER_PACKAGE, "ParcelableImmutableMultimap"));
+
+    tryAddWrapper(
+        elements,
+        wrappers,
+        "com.google.common.collect.ImmutableSetMultimap",
+        ClassName.get(PARCELABLE_WRAPPER_PACKAGE, "ParcelableImmutableSetMultimap"));
+
+    tryAddWrapper(
+        elements,
+        wrappers,
+        "com.google.common.collect.ImmutableListMultimap",
+        ClassName.get(PARCELABLE_WRAPPER_PACKAGE, "ParcelableImmutableListMultimap"));
+
+    tryAddWrapper(
+        elements,
+        wrappers,
+        "com.google.common.collect.ImmutableSortedMap",
+        ClassName.get(PARCELABLE_WRAPPER_PACKAGE, "ParcelableImmutableSortedMap"));
+
+    tryAddWrapper(
+        elements,
+        wrappers,
+        "com.google.common.collect.ImmutableList",
+        ClassName.get(PARCELABLE_WRAPPER_PACKAGE, "ParcelableImmutableList"));
+
+    tryAddWrapper(
+        elements,
+        wrappers,
+        "com.google.common.collect.ImmutableSet",
+        ClassName.get(PARCELABLE_WRAPPER_PACKAGE, "ParcelableImmutableSet"));
+
+    tryAddWrapper(
+        elements,
+        wrappers,
+        "com.google.common.collect.ImmutableMultiset",
+        ClassName.get(PARCELABLE_WRAPPER_PACKAGE, "ParcelableImmutableMultiset"));
+
+    tryAddWrapper(
+        elements,
+        wrappers,
+        "com.google.common.collect.ImmutableSortedSet",
+        ClassName.get(PARCELABLE_WRAPPER_PACKAGE, "ParcelableImmutableSortedSet"));
+
+    tryAddWrapper(
+        elements,
+        wrappers,
+        "com.google.common.collect.ImmutableSortedMultiset",
+        ClassName.get(PARCELABLE_WRAPPER_PACKAGE, "ParcelableImmutableSortedMultiset"));
+
+    tryAddWrapper(
+        elements,
+        wrappers,
+        "com.google.common.collect.ImmutableBiMap",
+        ClassName.get(PARCELABLE_WRAPPER_PACKAGE, "ParcelableImmutableBiMap"));
+
+    tryAddWrapper(
+        elements,
+        wrappers,
+        "com.google.common.collect.ImmutableCollection",
+        ClassName.get(PARCELABLE_WRAPPER_PACKAGE, "ParcelableImmutableCollection"));
+
     tryAddWrapper(
         elements,
         wrappers,
diff --git a/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/containers/ProfileConnectorInfo.java b/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/containers/ProfileConnectorInfo.java
index 6f4f71d..8646faf 100644
--- a/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/containers/ProfileConnectorInfo.java
+++ b/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/containers/ProfileConnectorInfo.java
@@ -48,6 +48,8 @@ public abstract class ProfileConnectorInfo {
 
     abstract ImmutableCollection<TypeElement> importsClasses();
 
+    abstract ImmutableCollection<TypeElement> additionalUsedTypes();
+
     abstract AvailabilityRestrictions availabilityRestrictions();
 
     abstract UncaughtExceptionsPolicy uncaughtExceptionsPolicy();
@@ -71,6 +73,8 @@ public abstract class ProfileConnectorInfo {
 
   public abstract ImmutableCollection<TypeElement> importsClasses();
 
+  public abstract ImmutableCollection<TypeElement> additionalUsedTypes();
+
   public abstract AvailabilityRestrictions availabilityRestrictions();
 
   public abstract UncaughtExceptionsPolicy uncaughtExceptionsPolicy();
@@ -84,12 +88,15 @@ public abstract class ProfileConnectorInfo {
 
     Set<TypeElement> parcelableWrappers = new HashSet<>(annotationInfo.parcelableWrapperClasses());
     Set<TypeElement> futureWrappers = new HashSet<>(annotationInfo.futureWrapperClasses());
+    Set<TypeElement> additionalUsedTypes =
+        new HashSet<>(annotationInfo.additionalUsedTypes());
 
     for (TypeElement importConnectorClass : annotationInfo.importsClasses()) {
       ProfileConnectorInfo importConnector =
           ProfileConnectorInfo.create(context, importConnectorClass, globalSupportedTypes);
       parcelableWrappers.addAll(importConnector.parcelableWrapperClasses());
       futureWrappers.addAll(importConnector.futureWrapperClasses());
+      additionalUsedTypes.addAll(importConnector.additionalUsedTypes());
     }
 
     return new AutoValue_ProfileConnectorInfo(
@@ -105,10 +112,12 @@ public abstract class ProfileConnectorInfo {
         ImmutableSet.copyOf(parcelableWrappers),
         ImmutableSet.copyOf(futureWrappers),
         annotationInfo.importsClasses(),
+        ImmutableSet.copyOf(additionalUsedTypes),
         annotationInfo.availabilityRestrictions(),
         annotationInfo.uncaughtExceptionsPolicy());
   }
 
+  @SuppressWarnings("CheckReturnValue") // extract classes from annotation is incorrectly flagged
   private static CustomProfileConnectorAnnotationInfo extractFromCustomProfileConnectorAnnotation(
       Context context, Elements elements, TypeElement connectorElement) {
     CustomProfileConnector customProfileConnector =
@@ -121,6 +130,7 @@ public abstract class ProfileConnectorInfo {
           ImmutableSet.of(),
           ImmutableSet.of(),
           ImmutableSet.of(),
+          ImmutableSet.of(),
           AvailabilityRestrictions.DEFAULT,
           UncaughtExceptionsPolicy.NOTIFY_RETHROW);
     }
@@ -134,6 +144,9 @@ public abstract class ProfileConnectorInfo {
     Collection<TypeElement> imports =
         GeneratorUtilities.extractClassesFromAnnotation(
             context.types(), customProfileConnector::imports);
+    Collection<TypeElement> additionalUsedTypes =
+        GeneratorUtilities.extractClassesFromAnnotation(
+            context.types(), customProfileConnector::additionalUsedTypes);
 
     String serviceClassName = customProfileConnector.serviceClassName();
 
@@ -145,6 +158,7 @@ public abstract class ProfileConnectorInfo {
         ImmutableSet.copyOf(parcelableWrappers),
         ImmutableSet.copyOf(futureWrappers),
         ImmutableSet.copyOf(imports),
+        ImmutableSet.copyOf(additionalUsedTypes),
         customProfileConnector.availabilityRestrictions(),
         customProfileConnector.uncaughtExceptionsPolicy());
   }
diff --git a/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/containers/UserConnectorInfo.java b/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/containers/UserConnectorInfo.java
index 82395f9..0c60164 100644
--- a/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/containers/UserConnectorInfo.java
+++ b/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/containers/UserConnectorInfo.java
@@ -43,6 +43,8 @@ public abstract class UserConnectorInfo {
 
     abstract ImmutableCollection<TypeElement> importsClasses();
 
+    abstract ImmutableCollection<TypeElement> additionalUsedTypes();
+
     abstract AvailabilityRestrictions availabilityRestrictions();
   }
 
@@ -62,6 +64,8 @@ public abstract class UserConnectorInfo {
 
   public abstract ImmutableCollection<TypeElement> importsClasses();
 
+  public abstract ImmutableCollection<TypeElement> additionalUsedTypes();
+
   public abstract AvailabilityRestrictions availabilityRestrictions();
 
   public static UserConnectorInfo create(
@@ -71,12 +75,15 @@ public abstract class UserConnectorInfo {
 
     Set<TypeElement> parcelableWrappers = new HashSet<>(annotationInfo.parcelableWrapperClasses());
     Set<TypeElement> futureWrappers = new HashSet<>(annotationInfo.futureWrapperClasses());
+    Set<TypeElement> additionalUsedTypes =
+        new HashSet<>(annotationInfo.additionalUsedTypes());
 
     for (TypeElement importConnectorClass : annotationInfo.importsClasses()) {
       UserConnectorInfo importConnector =
           UserConnectorInfo.create(context, importConnectorClass, globalSupportedTypes);
       parcelableWrappers.addAll(importConnector.parcelableWrapperClasses());
       futureWrappers.addAll(importConnector.futureWrapperClasses());
+      additionalUsedTypes.addAll(importConnector.additionalUsedTypes());
     }
 
     return new AutoValue_UserConnectorInfo(
@@ -91,9 +98,11 @@ public abstract class UserConnectorInfo {
         ImmutableSet.copyOf(parcelableWrappers),
         ImmutableSet.copyOf(futureWrappers),
         annotationInfo.importsClasses(),
+        annotationInfo.additionalUsedTypes(),
         annotationInfo.availabilityRestrictions());
   }
 
+  @SuppressWarnings("CheckReturnValue") // extract classes from annotation is incorrectly flagged
   private static CustomUserConnectorAnnotationInfo extractFromCustomUserConnectorAnnotation(
       Context context, TypeElement connectorElement) {
     CustomUserConnector customUserConnector =
@@ -105,6 +114,7 @@ public abstract class UserConnectorInfo {
           ImmutableSet.of(),
           ImmutableSet.of(),
           ImmutableSet.of(),
+          ImmutableSet.of(),
           AvailabilityRestrictions.DEFAULT);
     }
 
@@ -117,6 +127,9 @@ public abstract class UserConnectorInfo {
     Collection<TypeElement> imports =
         GeneratorUtilities.extractClassesFromAnnotation(
             context.types(), customUserConnector::imports);
+    Collection<TypeElement> additionalUsedTypes =
+        GeneratorUtilities.extractClassesFromAnnotation(
+            context.types(), customUserConnector::additionalUsedTypes);
 
     String serviceClassName = customUserConnector.serviceClassName();
 
@@ -127,6 +140,7 @@ public abstract class UserConnectorInfo {
         ImmutableSet.copyOf(parcelableWrappers),
         ImmutableSet.copyOf(futureWrappers),
         ImmutableSet.copyOf(imports),
+        ImmutableSet.copyOf(additionalUsedTypes),
         customUserConnector.availabilityRestrictions());
   }
 
diff --git a/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/containers/ValidatorCrossProfileTypeInfo.java b/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/containers/ValidatorCrossProfileTypeInfo.java
index bc828ae..bd79353 100644
--- a/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/containers/ValidatorCrossProfileTypeInfo.java
+++ b/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/containers/ValidatorCrossProfileTypeInfo.java
@@ -46,6 +46,8 @@ public abstract class ValidatorCrossProfileTypeInfo {
 
   public abstract ImmutableCollection<TypeElement> futureWrapperClasses();
 
+  public abstract ImmutableCollection<TypeElement> additionalUsedTypes();
+
   public abstract boolean isStatic();
 
   public static ValidatorCrossProfileTypeInfo create(
@@ -82,6 +84,7 @@ public abstract class ValidatorCrossProfileTypeInfo {
         supportedTypes,
         annotationInfo.parcelableWrapperClasses(),
         annotationInfo.futureWrapperClasses(),
+        annotationInfo.additionalUsedTypes(),
         annotationInfo.isStatic());
   }
 
diff --git a/processor/src/main/resources/parcelablewrappers/ParcelableArray.java b/processor/src/main/resources/parcelablewrappers/ParcelableArray.java
index c1cf335..e2353e1 100644
--- a/processor/src/main/resources/parcelablewrappers/ParcelableArray.java
+++ b/processor/src/main/resources/parcelablewrappers/ParcelableArray.java
@@ -21,7 +21,7 @@ import com.google.android.enterprise.connectedapps.internal.Bundler;
 import com.google.android.enterprise.connectedapps.internal.BundlerType;
 
 /** Wrapper for reading & writing arrays from and to {@link Parcel} instances. */
-public class ParcelableArray<E> implements Parcelable {
+public final class ParcelableArray<E> implements Parcelable {
 
   private static final int NULL_SIZE = -1;
 
diff --git a/processor/src/main/resources/parcelablewrappers/ParcelableBitmap.java b/processor/src/main/resources/parcelablewrappers/ParcelableBitmap.java
index ba27af8..8836465 100644
--- a/processor/src/main/resources/parcelablewrappers/ParcelableBitmap.java
+++ b/processor/src/main/resources/parcelablewrappers/ParcelableBitmap.java
@@ -24,7 +24,7 @@ import com.google.android.enterprise.connectedapps.internal.BundlerType;
 /** Wrapper for reading & writing {@link Bitmap} instances from and to {@link Parcel} instances. */
 // Though Bitmap is itself Parcelable, in some circumstances the Parcelling process can fail (see
 // b/159895007).
-public class ParcelableBitmap implements Parcelable {
+public final class ParcelableBitmap implements Parcelable {
   private final Bitmap bitmap;
 
   /** Create a wrapper for a given bitmap. */
diff --git a/processor/src/main/resources/parcelablewrappers/ParcelableCollection.java b/processor/src/main/resources/parcelablewrappers/ParcelableCollection.java
index 66db136..7f97442 100644
--- a/processor/src/main/resources/parcelablewrappers/ParcelableCollection.java
+++ b/processor/src/main/resources/parcelablewrappers/ParcelableCollection.java
@@ -25,7 +25,7 @@ import java.util.Collection;
 /**
  * Wrapper for reading & writing {@link Collection} instances from and to {@link Parcel} instances.
  */
-public class ParcelableCollection<E> implements Parcelable {
+public final class ParcelableCollection<E> implements Parcelable {
 
   private static final int NULL_SIZE = -1;
 
diff --git a/processor/src/main/resources/parcelablewrappers/ParcelableDrawable.java b/processor/src/main/resources/parcelablewrappers/ParcelableDrawable.java
index b9852aa..5e2c5c1 100644
--- a/processor/src/main/resources/parcelablewrappers/ParcelableDrawable.java
+++ b/processor/src/main/resources/parcelablewrappers/ParcelableDrawable.java
@@ -30,7 +30,7 @@ import com.google.android.enterprise.connectedapps.internal.BundlerType;
  *
  * <p>Note that all {@link Drawable} instances are converted to {@link Bitmap} when parcelling.
  */
-public class ParcelableDrawable implements Parcelable {
+public final class ParcelableDrawable implements Parcelable {
 
   private static final int NULL = -1;
   private static final int NOT_NULL = 1;
diff --git a/processor/src/main/resources/parcelablewrappers/ParcelableGuavaOptional.java b/processor/src/main/resources/parcelablewrappers/ParcelableGuavaOptional.java
index e2a14b9..2877b84 100644
--- a/processor/src/main/resources/parcelablewrappers/ParcelableGuavaOptional.java
+++ b/processor/src/main/resources/parcelablewrappers/ParcelableGuavaOptional.java
@@ -24,7 +24,7 @@ import com.google.common.base.Optional;
 /**
  * Wrapper for reading & writing {@link Optional} instances from and to {@link Parcel} instances.
  */
-public class ParcelableGuavaOptional<E> implements Parcelable {
+public final class ParcelableGuavaOptional<E> implements Parcelable {
 
   private static final int NULL = -1;
   private static final int ABSENT = 0;
diff --git a/processor/src/main/resources/parcelablewrappers/ParcelableImmutableBiMap.java b/processor/src/main/resources/parcelablewrappers/ParcelableImmutableBiMap.java
new file mode 100644
index 0000000..5172774
--- /dev/null
+++ b/processor/src/main/resources/parcelablewrappers/ParcelableImmutableBiMap.java
@@ -0,0 +1,129 @@
+/*
+ * Copyright 2021 Google LLC
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *   https://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+package com.google.android.enterprise.connectedapps.parcelablewrappers;
+
+import android.os.Parcel;
+import android.os.Parcelable;
+import com.google.android.enterprise.connectedapps.internal.Bundler;
+import com.google.android.enterprise.connectedapps.internal.BundlerType;
+import com.google.common.collect.ImmutableBiMap;
+
+/**
+ * Wrapper for reading & writing {@link ImmutableBiMap} instances from and to {@link Parcel}
+ * instances.
+ */
+public final class ParcelableImmutableBiMap<E, F> implements Parcelable {
+
+  private static final int NULL_SIZE = -1;
+  private static final int KEY_TYPE_INDEX = 0;
+  private static final int VALUE_TYPE_INDEX = 1;
+
+  private final Bundler bundler;
+  private final BundlerType type;
+  private final ImmutableBiMap<E, F> biMap;
+
+  /**
+   * Create a wrapper for a given immutable biMap.
+   *
+   * <p>The passed in {@link Bundler} must be capable of bundling {@code E} and {@code F}.
+   */
+  public static <E, F> ParcelableImmutableBiMap<E, F> of(
+      Bundler bundler, BundlerType type, ImmutableBiMap<E, F> biMap) {
+    return new ParcelableImmutableBiMap<>(bundler, type, biMap);
+  }
+
+  public ImmutableBiMap<E, F> get() {
+    return biMap;
+  }
+
+  private ParcelableImmutableBiMap(Bundler bundler, BundlerType type, ImmutableBiMap<E, F> biMap) {
+    if (bundler == null || type == null) {
+      throw new NullPointerException();
+    }
+    this.bundler = bundler;
+    this.type = type;
+    this.biMap = biMap;
+  }
+
+  private ParcelableImmutableBiMap(Parcel in) {
+    bundler = in.readParcelable(Bundler.class.getClassLoader());
+    int size = in.readInt();
+
+    if (size == NULL_SIZE) {
+      type = null;
+      biMap = null;
+      return;
+    }
+
+    ImmutableBiMap.Builder<E, F> biMapBuilder = ImmutableBiMap.builder();
+
+    type = (BundlerType) in.readParcelable(Bundler.class.getClassLoader());
+    if (size > 0) {
+      BundlerType keyType = type.typeArguments().get(KEY_TYPE_INDEX);
+      BundlerType valueType = type.typeArguments().get(VALUE_TYPE_INDEX);
+      for (int i = 0; i < size; i++) {
+        @SuppressWarnings("unchecked")
+        E key = (E) bundler.readFromParcel(in, keyType);
+        @SuppressWarnings("unchecked")
+        F value = (F) bundler.readFromParcel(in, valueType);
+        biMapBuilder.put(key, value);
+      }
+    }
+
+    biMap = biMapBuilder.build();
+  }
+
+  @Override
+  public void writeToParcel(Parcel dest, int flags) {
+    dest.writeParcelable(bundler, flags);
+
+    if (biMap == null) {
+      dest.writeInt(NULL_SIZE);
+      return;
+    }
+
+    dest.writeInt(biMap.size());
+    dest.writeParcelable(type, flags);
+    if (!biMap.isEmpty()) {
+      BundlerType keyType = type.typeArguments().get(0);
+      BundlerType valueType = type.typeArguments().get(1);
+
+      for (ImmutableBiMap.Entry<E, F> entry : biMap.entrySet()) {
+        bundler.writeToParcel(dest, entry.getKey(), keyType, flags);
+        bundler.writeToParcel(dest, entry.getValue(), valueType, flags);
+      }
+    }
+  }
+
+  @Override
+  public int describeContents() {
+    return 0;
+  }
+
+  @SuppressWarnings("rawtypes")
+  public static final Creator<ParcelableImmutableBiMap> CREATOR =
+      new Creator<ParcelableImmutableBiMap>() {
+        @Override
+        public ParcelableImmutableBiMap createFromParcel(Parcel in) {
+          return new ParcelableImmutableBiMap(in);
+        }
+
+        @Override
+        public ParcelableImmutableBiMap[] newArray(int size) {
+          return new ParcelableImmutableBiMap[size];
+        }
+      };
+}
diff --git a/processor/src/main/resources/parcelablewrappers/ParcelableImmutableCollection.java b/processor/src/main/resources/parcelablewrappers/ParcelableImmutableCollection.java
new file mode 100644
index 0000000..51b15f2
--- /dev/null
+++ b/processor/src/main/resources/parcelablewrappers/ParcelableImmutableCollection.java
@@ -0,0 +1,124 @@
+/*
+ * Copyright 2021 Google LLC
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *   https://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+package com.google.android.enterprise.connectedapps.parcelablewrappers;
+
+import android.os.Parcel;
+import android.os.Parcelable;
+import com.google.android.enterprise.connectedapps.internal.Bundler;
+import com.google.android.enterprise.connectedapps.internal.BundlerType;
+import com.google.common.collect.ImmutableCollection;
+import com.google.common.collect.ImmutableList;
+
+/**
+ * Wrapper for reading & writing {@link ImmutableCollection} instances from and to {@link Parcel}
+ * instances.
+ */
+public final class ParcelableImmutableCollection<E> implements Parcelable {
+
+  private static final int NULL_SIZE = -1;
+
+  private final Bundler bundler;
+  private final BundlerType type;
+  private final ImmutableCollection<E> collection;
+
+  /**
+   * Create a wrapper for a given immutable collection.
+   *
+   * <p>The passed in {@link Bundler} must be capable of bundling {@code E}
+   */
+  public static <E> ParcelableImmutableCollection<E> of(
+      Bundler bundler, BundlerType type, ImmutableCollection<E> collection) {
+    return new ParcelableImmutableCollection<>(bundler, type, collection);
+  }
+
+  public ImmutableCollection<E> get() {
+    return collection;
+  }
+
+  private ParcelableImmutableCollection(
+      Bundler bundler, BundlerType type, ImmutableCollection<E> collection) {
+    if (bundler == null || type == null) {
+      throw new NullPointerException();
+    }
+    this.bundler = bundler;
+    this.type = type;
+    this.collection = collection;
+  }
+
+  private ParcelableImmutableCollection(Parcel in) {
+    bundler = in.readParcelable(Bundler.class.getClassLoader());
+    int size = in.readInt();
+
+    if (size == NULL_SIZE) {
+      type = null;
+      collection = null;
+      return;
+    }
+
+    ImmutableCollection.Builder<E> collectionBuilder = ImmutableList.builder();
+
+    type = (BundlerType) in.readParcelable(Bundler.class.getClassLoader());
+    if (size > 0) {
+      BundlerType elementType = type.typeArguments().get(0);
+      for (int i = 0; i < size; i++) {
+        @SuppressWarnings("unchecked")
+        E element = (E) bundler.readFromParcel(in, elementType);
+        collectionBuilder.add(element);
+      }
+    }
+
+    collection = collectionBuilder.build();
+  }
+
+  @Override
+  public void writeToParcel(Parcel dest, int flags) {
+    dest.writeParcelable(bundler, flags);
+
+    if (collection == null) {
+      dest.writeInt(NULL_SIZE);
+      return;
+    }
+
+    dest.writeInt(collection.size());
+    dest.writeParcelable(type, flags);
+    if (!collection.isEmpty()) {
+      BundlerType valueType = type.typeArguments().get(0);
+
+      for (E value : collection) {
+        bundler.writeToParcel(dest, value, valueType, flags);
+      }
+    }
+  }
+
+  @Override
+  public int describeContents() {
+    return 0;
+  }
+
+  @SuppressWarnings("rawtypes")
+  public static final Creator<ParcelableImmutableCollection> CREATOR =
+      new Creator<ParcelableImmutableCollection>() {
+        @Override
+        public ParcelableImmutableCollection createFromParcel(Parcel in) {
+          return new ParcelableImmutableCollection(in);
+        }
+
+        @Override
+        public ParcelableImmutableCollection[] newArray(int size) {
+          return new ParcelableImmutableCollection[size];
+        }
+      };
+}
diff --git a/processor/src/main/resources/parcelablewrappers/ParcelableImmutableList.java b/processor/src/main/resources/parcelablewrappers/ParcelableImmutableList.java
new file mode 100644
index 0000000..8f7ec8b
--- /dev/null
+++ b/processor/src/main/resources/parcelablewrappers/ParcelableImmutableList.java
@@ -0,0 +1,122 @@
+/*
+ * Copyright 2021 Google LLC
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *   https://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+package com.google.android.enterprise.connectedapps.parcelablewrappers;
+
+import android.os.Parcel;
+import android.os.Parcelable;
+import com.google.android.enterprise.connectedapps.internal.Bundler;
+import com.google.android.enterprise.connectedapps.internal.BundlerType;
+import com.google.common.collect.ImmutableList;
+
+/**
+ * Wrapper for reading & writing {@link ImmutableList} instances from and to {@link Parcel}
+ * instances.
+ */
+public final class ParcelableImmutableList<E> implements Parcelable {
+
+  private static final int NULL_SIZE = -1;
+
+  private final Bundler bundler;
+  private final BundlerType type;
+  private final ImmutableList<E> list;
+
+  /**
+   * Create a wrapper for a given immutable list.
+   *
+   * <p>The passed in {@link Bundler} must be capable of bundling {@code E}
+   */
+  public static <E> ParcelableImmutableList<E> of(
+      Bundler bundler, BundlerType type, ImmutableList<E> list) {
+    return new ParcelableImmutableList<>(bundler, type, list);
+  }
+
+  public ImmutableList<E> get() {
+    return list;
+  }
+
+  private ParcelableImmutableList(Bundler bundler, BundlerType type, ImmutableList<E> list) {
+    if (bundler == null || type == null) {
+      throw new NullPointerException();
+    }
+    this.bundler = bundler;
+    this.type = type;
+    this.list = list;
+  }
+
+  private ParcelableImmutableList(Parcel in) {
+    bundler = in.readParcelable(Bundler.class.getClassLoader());
+    int size = in.readInt();
+
+    if (size == NULL_SIZE) {
+      type = null;
+      list = null;
+      return;
+    }
+
+    ImmutableList.Builder<E> listBuilder = ImmutableList.builder();
+
+    type = (BundlerType) in.readParcelable(Bundler.class.getClassLoader());
+    if (size > 0) {
+      BundlerType elementType = type.typeArguments().get(0);
+      for (int i = 0; i < size; i++) {
+        @SuppressWarnings("unchecked")
+        E element = (E) bundler.readFromParcel(in, elementType);
+        listBuilder.add(element);
+      }
+    }
+
+    list = listBuilder.build();
+  }
+
+  @Override
+  public void writeToParcel(Parcel dest, int flags) {
+    dest.writeParcelable(bundler, flags);
+
+    if (list == null) {
+      dest.writeInt(NULL_SIZE);
+      return;
+    }
+
+    dest.writeInt(list.size());
+    dest.writeParcelable(type, flags);
+    if (!list.isEmpty()) {
+      BundlerType valueType = type.typeArguments().get(0);
+
+      for (E value : list) {
+        bundler.writeToParcel(dest, value, valueType, flags);
+      }
+    }
+  }
+
+  @Override
+  public int describeContents() {
+    return 0;
+  }
+
+  @SuppressWarnings("rawtypes")
+  public static final Creator<ParcelableImmutableList> CREATOR =
+      new Creator<ParcelableImmutableList>() {
+        @Override
+        public ParcelableImmutableList createFromParcel(Parcel in) {
+          return new ParcelableImmutableList(in);
+        }
+
+        @Override
+        public ParcelableImmutableList[] newArray(int size) {
+          return new ParcelableImmutableList[size];
+        }
+      };
+}
diff --git a/processor/src/main/resources/parcelablewrappers/ParcelableImmutableListMultimap.java b/processor/src/main/resources/parcelablewrappers/ParcelableImmutableListMultimap.java
new file mode 100644
index 0000000..102c433
--- /dev/null
+++ b/processor/src/main/resources/parcelablewrappers/ParcelableImmutableListMultimap.java
@@ -0,0 +1,131 @@
+/*
+ * Copyright 2021 Google LLC
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *   https://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+package com.google.android.enterprise.connectedapps.parcelablewrappers;
+
+import android.os.Parcel;
+import android.os.Parcelable;
+import com.google.android.enterprise.connectedapps.internal.Bundler;
+import com.google.android.enterprise.connectedapps.internal.BundlerType;
+import com.google.common.collect.ImmutableListMultimap;
+import java.util.Map;
+
+/**
+ * Wrapper for reading & writing {@link ImmutableListMultimap} instances from and to {@link Parcel}
+ * instances.
+ */
+public final class ParcelableImmutableListMultimap<E, F> implements Parcelable {
+
+  private static final int NULL_SIZE = -1;
+  private static final int KEY_TYPE_INDEX = 0;
+  private static final int VALUE_TYPE_INDEX = 1;
+
+  private final Bundler bundler;
+  private final BundlerType type;
+  private final ImmutableListMultimap<E, F> listMultimap;
+
+  /**
+   * Create a wrapper for a given immutable listMultimap.
+   *
+   * <p>The passed in {@link Bundler} must be capable of bundling {@code E} and {@code F}.
+   */
+  public static <E, F> ParcelableImmutableListMultimap<E, F> of(
+      Bundler bundler, BundlerType type, ImmutableListMultimap<E, F> listMultimap) {
+    return new ParcelableImmutableListMultimap<>(bundler, type, listMultimap);
+  }
+
+  public ImmutableListMultimap<E, F> get() {
+    return listMultimap;
+  }
+
+  private ParcelableImmutableListMultimap(
+      Bundler bundler, BundlerType type, ImmutableListMultimap<E, F> listMultimap) {
+    if (bundler == null || type == null) {
+      throw new NullPointerException();
+    }
+    this.bundler = bundler;
+    this.type = type;
+    this.listMultimap = listMultimap;
+  }
+
+  private ParcelableImmutableListMultimap(Parcel in) {
+    bundler = in.readParcelable(Bundler.class.getClassLoader());
+    int size = in.readInt();
+
+    if (size == NULL_SIZE) {
+      type = null;
+      listMultimap = null;
+      return;
+    }
+
+    ImmutableListMultimap.Builder<E, F> listMultimapBuilder = ImmutableListMultimap.builder();
+
+    type = (BundlerType) in.readParcelable(Bundler.class.getClassLoader());
+    if (size > 0) {
+      BundlerType keyType = type.typeArguments().get(KEY_TYPE_INDEX);
+      BundlerType valueType = type.typeArguments().get(VALUE_TYPE_INDEX);
+      for (int i = 0; i < size; i++) {
+        @SuppressWarnings("unchecked")
+        E key = (E) bundler.readFromParcel(in, keyType);
+        @SuppressWarnings("unchecked")
+        F value = (F) bundler.readFromParcel(in, valueType);
+        listMultimapBuilder.put(key, value);
+      }
+    }
+
+    listMultimap = listMultimapBuilder.build();
+  }
+
+  @Override
+  public void writeToParcel(Parcel dest, int flags) {
+    dest.writeParcelable(bundler, flags);
+
+    if (listMultimap == null) {
+      dest.writeInt(NULL_SIZE);
+      return;
+    }
+
+    dest.writeInt(listMultimap.size());
+    dest.writeParcelable(type, flags);
+    if (!listMultimap.isEmpty()) {
+      BundlerType keyType = type.typeArguments().get(0);
+      BundlerType valueType = type.typeArguments().get(1);
+
+      for (Map.Entry<E, F> entry : listMultimap.entries()) {
+        bundler.writeToParcel(dest, entry.getKey(), keyType, flags);
+        bundler.writeToParcel(dest, entry.getValue(), valueType, flags);
+      }
+    }
+  }
+
+  @Override
+  public int describeContents() {
+    return 0;
+  }
+
+  @SuppressWarnings("rawtypes")
+  public static final Creator<ParcelableImmutableListMultimap> CREATOR =
+      new Creator<ParcelableImmutableListMultimap>() {
+        @Override
+        public ParcelableImmutableListMultimap createFromParcel(Parcel in) {
+          return new ParcelableImmutableListMultimap(in);
+        }
+
+        @Override
+        public ParcelableImmutableListMultimap[] newArray(int size) {
+          return new ParcelableImmutableListMultimap[size];
+        }
+      };
+}
diff --git a/processor/src/main/resources/parcelablewrappers/ParcelableImmutableMap.java b/processor/src/main/resources/parcelablewrappers/ParcelableImmutableMap.java
index 78b7790..d04dc9d 100644
--- a/processor/src/main/resources/parcelablewrappers/ParcelableImmutableMap.java
+++ b/processor/src/main/resources/parcelablewrappers/ParcelableImmutableMap.java
@@ -25,7 +25,7 @@ import com.google.common.collect.ImmutableMap;
  * Wrapper for reading & writing {@link ImmutableMap} instances from and to {@link Parcel}
  * instances.
  */
-public class ParcelableImmutableMap<E, F> implements Parcelable {
+public final class ParcelableImmutableMap<E, F> implements Parcelable {
 
   private static final int NULL_SIZE = -1;
   private static final int KEY_TYPE_INDEX = 0;
diff --git a/processor/src/main/resources/parcelablewrappers/ParcelableImmutableMultimap.java b/processor/src/main/resources/parcelablewrappers/ParcelableImmutableMultimap.java
new file mode 100644
index 0000000..8231a3a
--- /dev/null
+++ b/processor/src/main/resources/parcelablewrappers/ParcelableImmutableMultimap.java
@@ -0,0 +1,131 @@
+/*
+ * Copyright 2021 Google LLC
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *   https://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+package com.google.android.enterprise.connectedapps.parcelablewrappers;
+
+import android.os.Parcel;
+import android.os.Parcelable;
+import com.google.android.enterprise.connectedapps.internal.Bundler;
+import com.google.android.enterprise.connectedapps.internal.BundlerType;
+import com.google.common.collect.ImmutableMultimap;
+import java.util.Map;
+
+/**
+ * Wrapper for reading & writing {@link ImmutableMultimap} instances from and to {@link Parcel}
+ * instances.
+ */
+public final class ParcelableImmutableMultimap<E, F> implements Parcelable {
+
+  private static final int NULL_SIZE = -1;
+  private static final int KEY_TYPE_INDEX = 0;
+  private static final int VALUE_TYPE_INDEX = 1;
+
+  private final Bundler bundler;
+  private final BundlerType type;
+  private final ImmutableMultimap<E, F> multimap;
+
+  /**
+   * Create a wrapper for a given immutable multimap.
+   *
+   * <p>The passed in {@link Bundler} must be capable of bundling {@code E} and {@code F}.
+   */
+  public static <E, F> ParcelableImmutableMultimap<E, F> of(
+      Bundler bundler, BundlerType type, ImmutableMultimap<E, F> multimap) {
+    return new ParcelableImmutableMultimap<>(bundler, type, multimap);
+  }
+
+  public ImmutableMultimap<E, F> get() {
+    return multimap;
+  }
+
+  private ParcelableImmutableMultimap(
+      Bundler bundler, BundlerType type, ImmutableMultimap<E, F> multimap) {
+    if (bundler == null || type == null) {
+      throw new NullPointerException();
+    }
+    this.bundler = bundler;
+    this.type = type;
+    this.multimap = multimap;
+  }
+
+  private ParcelableImmutableMultimap(Parcel in) {
+    bundler = in.readParcelable(Bundler.class.getClassLoader());
+    int size = in.readInt();
+
+    if (size == NULL_SIZE) {
+      type = null;
+      multimap = null;
+      return;
+    }
+
+    ImmutableMultimap.Builder<E, F> multimapBuilder = ImmutableMultimap.builder();
+
+    type = (BundlerType) in.readParcelable(Bundler.class.getClassLoader());
+    if (size > 0) {
+      BundlerType keyType = type.typeArguments().get(KEY_TYPE_INDEX);
+      BundlerType valueType = type.typeArguments().get(VALUE_TYPE_INDEX);
+      for (int i = 0; i < size; i++) {
+        @SuppressWarnings("unchecked")
+        E key = (E) bundler.readFromParcel(in, keyType);
+        @SuppressWarnings("unchecked")
+        F value = (F) bundler.readFromParcel(in, valueType);
+        multimapBuilder.put(key, value);
+      }
+    }
+
+    multimap = multimapBuilder.build();
+  }
+
+  @Override
+  public void writeToParcel(Parcel dest, int flags) {
+    dest.writeParcelable(bundler, flags);
+
+    if (multimap == null) {
+      dest.writeInt(NULL_SIZE);
+      return;
+    }
+
+    dest.writeInt(multimap.size());
+    dest.writeParcelable(type, flags);
+    if (!multimap.isEmpty()) {
+      BundlerType keyType = type.typeArguments().get(0);
+      BundlerType valueType = type.typeArguments().get(1);
+
+      for (Map.Entry<E, F> entry : multimap.entries()) {
+        bundler.writeToParcel(dest, entry.getKey(), keyType, flags);
+        bundler.writeToParcel(dest, entry.getValue(), valueType, flags);
+      }
+    }
+  }
+
+  @Override
+  public int describeContents() {
+    return 0;
+  }
+
+  @SuppressWarnings("rawtypes")
+  public static final Creator<ParcelableImmutableMultimap> CREATOR =
+      new Creator<ParcelableImmutableMultimap>() {
+        @Override
+        public ParcelableImmutableMultimap createFromParcel(Parcel in) {
+          return new ParcelableImmutableMultimap(in);
+        }
+
+        @Override
+        public ParcelableImmutableMultimap[] newArray(int size) {
+          return new ParcelableImmutableMultimap[size];
+        }
+      };
+}
diff --git a/processor/src/main/resources/parcelablewrappers/ParcelableImmutableMultiset.java b/processor/src/main/resources/parcelablewrappers/ParcelableImmutableMultiset.java
new file mode 100644
index 0000000..0e321d2
--- /dev/null
+++ b/processor/src/main/resources/parcelablewrappers/ParcelableImmutableMultiset.java
@@ -0,0 +1,123 @@
+/*
+ * Copyright 2021 Google LLC
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *   https://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+package com.google.android.enterprise.connectedapps.parcelablewrappers;
+
+import android.os.Parcel;
+import android.os.Parcelable;
+import com.google.android.enterprise.connectedapps.internal.Bundler;
+import com.google.android.enterprise.connectedapps.internal.BundlerType;
+import com.google.common.collect.ImmutableMultiset;
+
+/**
+ * Wrapper for reading & writing {@link ImmutableMultiset} instances from and to {@link Parcel}
+ * instances.
+ */
+public final class ParcelableImmutableMultiset<E> implements Parcelable {
+
+  private static final int NULL_SIZE = -1;
+
+  private final Bundler bundler;
+  private final BundlerType type;
+  private final ImmutableMultiset<E> multiset;
+
+  /**
+   * Create a wrapper for a given immutable multiset.
+   *
+   * <p>The passed in {@link Bundler} must be capable of bundling {@code E}
+   */
+  public static <E> ParcelableImmutableMultiset<E> of(
+      Bundler bundler, BundlerType type, ImmutableMultiset<E> multiset) {
+    return new ParcelableImmutableMultiset<>(bundler, type, multiset);
+  }
+
+  public ImmutableMultiset<E> get() {
+    return multiset;
+  }
+
+  private ParcelableImmutableMultiset(
+      Bundler bundler, BundlerType type, ImmutableMultiset<E> multiset) {
+    if (bundler == null || type == null) {
+      throw new NullPointerException();
+    }
+    this.bundler = bundler;
+    this.type = type;
+    this.multiset = multiset;
+  }
+
+  private ParcelableImmutableMultiset(Parcel in) {
+    bundler = in.readParcelable(Bundler.class.getClassLoader());
+    int size = in.readInt();
+
+    if (size == NULL_SIZE) {
+      type = null;
+      multiset = null;
+      return;
+    }
+
+    ImmutableMultiset.Builder<E> multisetBuilder = ImmutableMultiset.builder();
+
+    type = (BundlerType) in.readParcelable(Bundler.class.getClassLoader());
+    if (size > 0) {
+      BundlerType elementType = type.typeArguments().get(0);
+      for (int i = 0; i < size; i++) {
+        @SuppressWarnings("unchecked")
+        E element = (E) bundler.readFromParcel(in, elementType);
+        multisetBuilder.add(element);
+      }
+    }
+
+    multiset = multisetBuilder.build();
+  }
+
+  @Override
+  public void writeToParcel(Parcel dest, int flags) {
+    dest.writeParcelable(bundler, flags);
+
+    if (multiset == null) {
+      dest.writeInt(NULL_SIZE);
+      return;
+    }
+
+    dest.writeInt(multiset.size());
+    dest.writeParcelable(type, flags);
+    if (!multiset.isEmpty()) {
+      BundlerType valueType = type.typeArguments().get(0);
+
+      for (E value : multiset) {
+        bundler.writeToParcel(dest, value, valueType, flags);
+      }
+    }
+  }
+
+  @Override
+  public int describeContents() {
+    return 0;
+  }
+
+  @SuppressWarnings("rawtypes")
+  public static final Creator<ParcelableImmutableMultiset> CREATOR =
+      new Creator<ParcelableImmutableMultiset>() {
+        @Override
+        public ParcelableImmutableMultiset createFromParcel(Parcel in) {
+          return new ParcelableImmutableMultiset(in);
+        }
+
+        @Override
+        public ParcelableImmutableMultiset[] newArray(int size) {
+          return new ParcelableImmutableMultiset[size];
+        }
+      };
+}
diff --git a/processor/src/main/resources/parcelablewrappers/ParcelableImmutableSet.java b/processor/src/main/resources/parcelablewrappers/ParcelableImmutableSet.java
new file mode 100644
index 0000000..0899b82
--- /dev/null
+++ b/processor/src/main/resources/parcelablewrappers/ParcelableImmutableSet.java
@@ -0,0 +1,122 @@
+/*
+ * Copyright 2021 Google LLC
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *   https://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+package com.google.android.enterprise.connectedapps.parcelablewrappers;
+
+import android.os.Parcel;
+import android.os.Parcelable;
+import com.google.android.enterprise.connectedapps.internal.Bundler;
+import com.google.android.enterprise.connectedapps.internal.BundlerType;
+import com.google.common.collect.ImmutableSet;
+
+/**
+ * Wrapper for reading & writing {@link ImmutableSet} instances from and to {@link Parcel}
+ * instances.
+ */
+public final class ParcelableImmutableSet<E> implements Parcelable {
+
+  private static final int NULL_SIZE = -1;
+
+  private final Bundler bundler;
+  private final BundlerType type;
+  private final ImmutableSet<E> set;
+
+  /**
+   * Create a wrapper for a given immutable set.
+   *
+   * <p>The passed in {@link Bundler} must be capable of bundling {@code E}
+   */
+  public static <E> ParcelableImmutableSet<E> of(
+      Bundler bundler, BundlerType type, ImmutableSet<E> set) {
+    return new ParcelableImmutableSet<>(bundler, type, set);
+  }
+
+  public ImmutableSet<E> get() {
+    return set;
+  }
+
+  private ParcelableImmutableSet(Bundler bundler, BundlerType type, ImmutableSet<E> set) {
+    if (bundler == null || type == null) {
+      throw new NullPointerException();
+    }
+    this.bundler = bundler;
+    this.type = type;
+    this.set = set;
+  }
+
+  private ParcelableImmutableSet(Parcel in) {
+    bundler = in.readParcelable(Bundler.class.getClassLoader());
+    int size = in.readInt();
+
+    if (size == NULL_SIZE) {
+      type = null;
+      set = null;
+      return;
+    }
+
+    ImmutableSet.Builder<E> setBuilder = ImmutableSet.builder();
+
+    type = (BundlerType) in.readParcelable(Bundler.class.getClassLoader());
+    if (size > 0) {
+      BundlerType elementType = type.typeArguments().get(0);
+      for (int i = 0; i < size; i++) {
+        @SuppressWarnings("unchecked")
+        E element = (E) bundler.readFromParcel(in, elementType);
+        setBuilder.add(element);
+      }
+    }
+
+    set = setBuilder.build();
+  }
+
+  @Override
+  public void writeToParcel(Parcel dest, int flags) {
+    dest.writeParcelable(bundler, flags);
+
+    if (set == null) {
+      dest.writeInt(NULL_SIZE);
+      return;
+    }
+
+    dest.writeInt(set.size());
+    dest.writeParcelable(type, flags);
+    if (!set.isEmpty()) {
+      BundlerType valueType = type.typeArguments().get(0);
+
+      for (E value : set) {
+        bundler.writeToParcel(dest, value, valueType, flags);
+      }
+    }
+  }
+
+  @Override
+  public int describeContents() {
+    return 0;
+  }
+
+  @SuppressWarnings("rawtypes")
+  public static final Creator<ParcelableImmutableSet> CREATOR =
+      new Creator<ParcelableImmutableSet>() {
+        @Override
+        public ParcelableImmutableSet createFromParcel(Parcel in) {
+          return new ParcelableImmutableSet(in);
+        }
+
+        @Override
+        public ParcelableImmutableSet[] newArray(int size) {
+          return new ParcelableImmutableSet[size];
+        }
+      };
+}
diff --git a/processor/src/main/resources/parcelablewrappers/ParcelableImmutableSetMultimap.java b/processor/src/main/resources/parcelablewrappers/ParcelableImmutableSetMultimap.java
new file mode 100644
index 0000000..00ac0d2
--- /dev/null
+++ b/processor/src/main/resources/parcelablewrappers/ParcelableImmutableSetMultimap.java
@@ -0,0 +1,131 @@
+/*
+ * Copyright 2021 Google LLC
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *   https://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+package com.google.android.enterprise.connectedapps.parcelablewrappers;
+
+import android.os.Parcel;
+import android.os.Parcelable;
+import com.google.android.enterprise.connectedapps.internal.Bundler;
+import com.google.android.enterprise.connectedapps.internal.BundlerType;
+import com.google.common.collect.ImmutableSetMultimap;
+import java.util.Map;
+
+/**
+ * Wrapper for reading & writing {@link ImmutableSetMultimap} instances from and to {@link Parcel}
+ * instances.
+ */
+public final class ParcelableImmutableSetMultimap<E, F> implements Parcelable {
+
+  private static final int NULL_SIZE = -1;
+  private static final int KEY_TYPE_INDEX = 0;
+  private static final int VALUE_TYPE_INDEX = 1;
+
+  private final Bundler bundler;
+  private final BundlerType type;
+  private final ImmutableSetMultimap<E, F> setMultimap;
+
+  /**
+   * Create a wrapper for a given immutable setMultimap.
+   *
+   * <p>The passed in {@link Bundler} must be capable of bundling {@code E} and {@code F}.
+   */
+  public static <E, F> ParcelableImmutableSetMultimap<E, F> of(
+      Bundler bundler, BundlerType type, ImmutableSetMultimap<E, F> setMultimap) {
+    return new ParcelableImmutableSetMultimap<>(bundler, type, setMultimap);
+  }
+
+  public ImmutableSetMultimap<E, F> get() {
+    return setMultimap;
+  }
+
+  private ParcelableImmutableSetMultimap(
+      Bundler bundler, BundlerType type, ImmutableSetMultimap<E, F> setMultimap) {
+    if (bundler == null || type == null) {
+      throw new NullPointerException();
+    }
+    this.bundler = bundler;
+    this.type = type;
+    this.setMultimap = setMultimap;
+  }
+
+  private ParcelableImmutableSetMultimap(Parcel in) {
+    bundler = in.readParcelable(Bundler.class.getClassLoader());
+    int size = in.readInt();
+
+    if (size == NULL_SIZE) {
+      type = null;
+      setMultimap = null;
+      return;
+    }
+
+    ImmutableSetMultimap.Builder<E, F> setMultimapBuilder = ImmutableSetMultimap.builder();
+
+    type = (BundlerType) in.readParcelable(Bundler.class.getClassLoader());
+    if (size > 0) {
+      BundlerType keyType = type.typeArguments().get(KEY_TYPE_INDEX);
+      BundlerType valueType = type.typeArguments().get(VALUE_TYPE_INDEX);
+      for (int i = 0; i < size; i++) {
+        @SuppressWarnings("unchecked")
+        E key = (E) bundler.readFromParcel(in, keyType);
+        @SuppressWarnings("unchecked")
+        F value = (F) bundler.readFromParcel(in, valueType);
+        setMultimapBuilder.put(key, value);
+      }
+    }
+
+    setMultimap = setMultimapBuilder.build();
+  }
+
+  @Override
+  public void writeToParcel(Parcel dest, int flags) {
+    dest.writeParcelable(bundler, flags);
+
+    if (setMultimap == null) {
+      dest.writeInt(NULL_SIZE);
+      return;
+    }
+
+    dest.writeInt(setMultimap.size());
+    dest.writeParcelable(type, flags);
+    if (!setMultimap.isEmpty()) {
+      BundlerType keyType = type.typeArguments().get(0);
+      BundlerType valueType = type.typeArguments().get(1);
+
+      for (Map.Entry<E, F> entry : setMultimap.entries()) {
+        bundler.writeToParcel(dest, entry.getKey(), keyType, flags);
+        bundler.writeToParcel(dest, entry.getValue(), valueType, flags);
+      }
+    }
+  }
+
+  @Override
+  public int describeContents() {
+    return 0;
+  }
+
+  @SuppressWarnings("rawtypes")
+  public static final Creator<ParcelableImmutableSetMultimap> CREATOR =
+      new Creator<ParcelableImmutableSetMultimap>() {
+        @Override
+        public ParcelableImmutableSetMultimap createFromParcel(Parcel in) {
+          return new ParcelableImmutableSetMultimap(in);
+        }
+
+        @Override
+        public ParcelableImmutableSetMultimap[] newArray(int size) {
+          return new ParcelableImmutableSetMultimap[size];
+        }
+      };
+}
diff --git a/processor/src/main/resources/parcelablewrappers/ParcelableImmutableSortedMap.java b/processor/src/main/resources/parcelablewrappers/ParcelableImmutableSortedMap.java
new file mode 100644
index 0000000..f0552bd
--- /dev/null
+++ b/processor/src/main/resources/parcelablewrappers/ParcelableImmutableSortedMap.java
@@ -0,0 +1,128 @@
+/*
+ * Copyright 2021 Google LLC
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *   https://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+package com.google.android.enterprise.connectedapps.parcelablewrappers;
+
+import android.os.Parcel;
+import android.os.Parcelable;
+import com.google.android.enterprise.connectedapps.internal.Bundler;
+import com.google.android.enterprise.connectedapps.internal.BundlerType;
+import com.google.common.collect.ImmutableSortedMap;
+
+/**
+ * Wrapper for reading & writing {@link ImmutableSortedMap} instances from and to {@link Parcel}
+ * instances.
+ */
+public final class ParcelableImmutableSortedMap<E extends Comparable, F> implements Parcelable {
+
+  private static final int NULL_SIZE = -1;
+
+  private final Bundler bundler;
+  private final BundlerType type;
+  private final ImmutableSortedMap<E, F> sortedMap;
+
+  /**
+   * Create a wrapper for a given immutable sorted map.
+   *
+   * <p>The passed in {@link Bundler} must be capable of bundling {@code E}
+   */
+  public static <E extends Comparable, F> ParcelableImmutableSortedMap<E, F> of(
+      Bundler bundler, BundlerType type, ImmutableSortedMap<E, F> sortedMap) {
+    return new ParcelableImmutableSortedMap<E, F>(bundler, type, sortedMap);
+  }
+
+  public ImmutableSortedMap<E, F> get() {
+    return sortedMap;
+  }
+
+  private ParcelableImmutableSortedMap(
+      Bundler bundler, BundlerType type, ImmutableSortedMap<E, F> sortedMap) {
+    if (bundler == null || type == null) {
+      throw new NullPointerException();
+    }
+    this.bundler = bundler;
+    this.type = type;
+    this.sortedMap = sortedMap;
+  }
+
+  private ParcelableImmutableSortedMap(Parcel in) {
+    bundler = in.readParcelable(Bundler.class.getClassLoader());
+    int size = in.readInt();
+
+    if (size == NULL_SIZE) {
+      type = null;
+      sortedMap = null;
+      return;
+    }
+
+    ImmutableSortedMap.Builder<E, F> sortedMapBuilder = ImmutableSortedMap.naturalOrder();
+
+    type = (BundlerType) in.readParcelable(Bundler.class.getClassLoader());
+    if (size > 0) {
+      BundlerType elementType = type.typeArguments().get(0);
+      BundlerType valueType = type.typeArguments().get(1);
+      for (int i = 0; i < size; i++) {
+        @SuppressWarnings("unchecked")
+        E key = (E) bundler.readFromParcel(in, elementType);
+        @SuppressWarnings("unchecked")
+        F value = (F) bundler.readFromParcel(in, valueType);
+        sortedMapBuilder.put(key, value);
+      }
+    }
+
+    sortedMap = sortedMapBuilder.build();
+  }
+
+  @Override
+  public void writeToParcel(Parcel dest, int flags) {
+    dest.writeParcelable(bundler, flags);
+
+    if (sortedMap == null) {
+      dest.writeInt(NULL_SIZE);
+      return;
+    }
+
+    dest.writeInt(sortedMap.size());
+    dest.writeParcelable(type, flags);
+    if (!sortedMap.isEmpty()) {
+      BundlerType valueType = type.typeArguments().get(0);
+      BundlerType keyType = type.typeArguments().get(1);
+
+      for (ImmutableSortedMap.Entry<E, F> entry : sortedMap.entrySet()) {
+        bundler.writeToParcel(dest, entry.getKey(), keyType, flags);
+        bundler.writeToParcel(dest, entry.getValue(), valueType, flags);
+      }
+    }
+  }
+
+  @Override
+  public int describeContents() {
+    return 0;
+  }
+
+  @SuppressWarnings("rawtypes")
+  public static final Creator<ParcelableImmutableSortedMap> CREATOR =
+      new Creator<ParcelableImmutableSortedMap>() {
+        @Override
+        public ParcelableImmutableSortedMap createFromParcel(Parcel in) {
+          return new ParcelableImmutableSortedMap(in);
+        }
+
+        @Override
+        public ParcelableImmutableSortedMap[] newArray(int size) {
+          return new ParcelableImmutableSortedMap[size];
+        }
+      };
+}
diff --git a/processor/src/main/resources/parcelablewrappers/ParcelableImmutableSortedMultiset.java b/processor/src/main/resources/parcelablewrappers/ParcelableImmutableSortedMultiset.java
new file mode 100644
index 0000000..c5c4a12
--- /dev/null
+++ b/processor/src/main/resources/parcelablewrappers/ParcelableImmutableSortedMultiset.java
@@ -0,0 +1,124 @@
+/*
+ * Copyright 2021 Google LLC
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *   https://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+package com.google.android.enterprise.connectedapps.parcelablewrappers;
+
+import android.os.Parcel;
+import android.os.Parcelable;
+import com.google.android.enterprise.connectedapps.internal.Bundler;
+import com.google.android.enterprise.connectedapps.internal.BundlerType;
+import com.google.common.collect.ImmutableSortedMultiset;
+
+/**
+ * Wrapper for reading & writing {@link ImmutableSortedMultiset} instances from and to {@link
+ * Parcel} instances.
+ */
+public final class ParcelableImmutableSortedMultiset<E extends Comparable> implements Parcelable {
+
+  private static final int NULL_SIZE = -1;
+
+  private final Bundler bundler;
+  private final BundlerType type;
+  private final ImmutableSortedMultiset<E> sortedMultiset;
+
+  /**
+   * Create a wrapper for a given immutable sorted set.
+   *
+   * <p>The passed in {@link Bundler} must be capable of bundling {@code E}
+   */
+  public static <E extends Comparable> ParcelableImmutableSortedMultiset<E> of(
+      Bundler bundler, BundlerType type, ImmutableSortedMultiset<E> sortedMultiset) {
+    return new ParcelableImmutableSortedMultiset<E>(bundler, type, sortedMultiset);
+  }
+
+  public ImmutableSortedMultiset<E> get() {
+    return sortedMultiset;
+  }
+
+  private ParcelableImmutableSortedMultiset(
+      Bundler bundler, BundlerType type, ImmutableSortedMultiset<E> sortedMultiset) {
+    if (bundler == null || type == null) {
+      throw new NullPointerException();
+    }
+    this.bundler = bundler;
+    this.type = type;
+    this.sortedMultiset = sortedMultiset;
+  }
+
+  private ParcelableImmutableSortedMultiset(Parcel in) {
+    bundler = in.readParcelable(Bundler.class.getClassLoader());
+    int size = in.readInt();
+
+    if (size == NULL_SIZE) {
+      type = null;
+      sortedMultiset = null;
+      return;
+    }
+
+    ImmutableSortedMultiset.Builder<E> sortedMultisetBuilder =
+        ImmutableSortedMultiset.naturalOrder();
+
+    type = (BundlerType) in.readParcelable(Bundler.class.getClassLoader());
+    if (size > 0) {
+      BundlerType elementType = type.typeArguments().get(0);
+      for (int i = 0; i < size; i++) {
+        @SuppressWarnings("unchecked")
+        E element = (E) bundler.readFromParcel(in, elementType);
+        sortedMultisetBuilder.add(element);
+      }
+    }
+
+    sortedMultiset = sortedMultisetBuilder.build();
+  }
+
+  @Override
+  public void writeToParcel(Parcel dest, int flags) {
+    dest.writeParcelable(bundler, flags);
+
+    if (sortedMultiset == null) {
+      dest.writeInt(NULL_SIZE);
+      return;
+    }
+
+    dest.writeInt(sortedMultiset.size());
+    dest.writeParcelable(type, flags);
+    if (!sortedMultiset.isEmpty()) {
+      BundlerType valueType = type.typeArguments().get(0);
+
+      for (E value : sortedMultiset) {
+        bundler.writeToParcel(dest, value, valueType, flags);
+      }
+    }
+  }
+
+  @Override
+  public int describeContents() {
+    return 0;
+  }
+
+  @SuppressWarnings("rawtypes")
+  public static final Creator<ParcelableImmutableSortedMultiset> CREATOR =
+      new Creator<ParcelableImmutableSortedMultiset>() {
+        @Override
+        public ParcelableImmutableSortedMultiset createFromParcel(Parcel in) {
+          return new ParcelableImmutableSortedMultiset(in);
+        }
+
+        @Override
+        public ParcelableImmutableSortedMultiset[] newArray(int size) {
+          return new ParcelableImmutableSortedMultiset[size];
+        }
+      };
+}
diff --git a/processor/src/main/resources/parcelablewrappers/ParcelableImmutableSortedSet.java b/processor/src/main/resources/parcelablewrappers/ParcelableImmutableSortedSet.java
new file mode 100644
index 0000000..7f738ac
--- /dev/null
+++ b/processor/src/main/resources/parcelablewrappers/ParcelableImmutableSortedSet.java
@@ -0,0 +1,123 @@
+/*
+ * Copyright 2021 Google LLC
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *   https://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+package com.google.android.enterprise.connectedapps.parcelablewrappers;
+
+import android.os.Parcel;
+import android.os.Parcelable;
+import com.google.android.enterprise.connectedapps.internal.Bundler;
+import com.google.android.enterprise.connectedapps.internal.BundlerType;
+import com.google.common.collect.ImmutableSortedSet;
+
+/**
+ * Wrapper for reading & writing {@link ImmutableSortedSet} instances from and to {@link Parcel}
+ * instances.
+ */
+public final class ParcelableImmutableSortedSet<E extends Comparable> implements Parcelable {
+
+  private static final int NULL_SIZE = -1;
+
+  private final Bundler bundler;
+  private final BundlerType type;
+  private final ImmutableSortedSet<E> sortedSet;
+
+  /**
+   * Create a wrapper for a given immutable sorted set.
+   *
+   * <p>The passed in {@link Bundler} must be capable of bundling {@code E}
+   */
+  public static <E extends Comparable> ParcelableImmutableSortedSet<E> of(
+      Bundler bundler, BundlerType type, ImmutableSortedSet<E> sortedSet) {
+    return new ParcelableImmutableSortedSet<E>(bundler, type, sortedSet);
+  }
+
+  public ImmutableSortedSet<E> get() {
+    return sortedSet;
+  }
+
+  private ParcelableImmutableSortedSet(
+      Bundler bundler, BundlerType type, ImmutableSortedSet<E> sortedSet) {
+    if (bundler == null || type == null) {
+      throw new NullPointerException();
+    }
+    this.bundler = bundler;
+    this.type = type;
+    this.sortedSet = sortedSet;
+  }
+
+  private ParcelableImmutableSortedSet(Parcel in) {
+    bundler = in.readParcelable(Bundler.class.getClassLoader());
+    int size = in.readInt();
+
+    if (size == NULL_SIZE) {
+      type = null;
+      sortedSet = null;
+      return;
+    }
+
+    ImmutableSortedSet.Builder<E> sortedSetBuilder = ImmutableSortedSet.naturalOrder();
+
+    type = (BundlerType) in.readParcelable(Bundler.class.getClassLoader());
+    if (size > 0) {
+      BundlerType elementType = type.typeArguments().get(0);
+      for (int i = 0; i < size; i++) {
+        @SuppressWarnings("unchecked")
+        E element = (E) bundler.readFromParcel(in, elementType);
+        sortedSetBuilder.add(element);
+      }
+    }
+
+    sortedSet = sortedSetBuilder.build();
+  }
+
+  @Override
+  public void writeToParcel(Parcel dest, int flags) {
+    dest.writeParcelable(bundler, flags);
+
+    if (sortedSet == null) {
+      dest.writeInt(NULL_SIZE);
+      return;
+    }
+
+    dest.writeInt(sortedSet.size());
+    dest.writeParcelable(type, flags);
+    if (!sortedSet.isEmpty()) {
+      BundlerType valueType = type.typeArguments().get(0);
+
+      for (E value : sortedSet) {
+        bundler.writeToParcel(dest, value, valueType, flags);
+      }
+    }
+  }
+
+  @Override
+  public int describeContents() {
+    return 0;
+  }
+
+  @SuppressWarnings("rawtypes")
+  public static final Creator<ParcelableImmutableSortedSet> CREATOR =
+      new Creator<ParcelableImmutableSortedSet>() {
+        @Override
+        public ParcelableImmutableSortedSet createFromParcel(Parcel in) {
+          return new ParcelableImmutableSortedSet(in);
+        }
+
+        @Override
+        public ParcelableImmutableSortedSet[] newArray(int size) {
+          return new ParcelableImmutableSortedSet[size];
+        }
+      };
+}
diff --git a/processor/src/main/resources/parcelablewrappers/ParcelableList.java b/processor/src/main/resources/parcelablewrappers/ParcelableList.java
index b1ff12e..f79dc23 100644
--- a/processor/src/main/resources/parcelablewrappers/ParcelableList.java
+++ b/processor/src/main/resources/parcelablewrappers/ParcelableList.java
@@ -23,8 +23,7 @@ import java.util.ArrayList;
 import java.util.List;
 
 /** Wrapper for reading & writing {@link List} instances from and to {@link Parcel} instances. */
-
-public class ParcelableList<E> implements Parcelable {
+public final class ParcelableList<E> implements Parcelable {
 
   private static final int NULL_SIZE = -1;
 
diff --git a/processor/src/main/resources/parcelablewrappers/ParcelableMap.java b/processor/src/main/resources/parcelablewrappers/ParcelableMap.java
index e90c22b..a28e3ba 100644
--- a/processor/src/main/resources/parcelablewrappers/ParcelableMap.java
+++ b/processor/src/main/resources/parcelablewrappers/ParcelableMap.java
@@ -23,7 +23,7 @@ import java.util.HashMap;
 import java.util.Map;
 
 /** Wrapper for reading & writing {@link Map} instances from and to {@link Parcel} instances. */
-public class ParcelableMap<E, F> implements Parcelable {
+public final class ParcelableMap<E, F> implements Parcelable {
 
   private static final int NULL_SIZE = -1;
 
diff --git a/processor/src/main/resources/parcelablewrappers/ParcelableOptional.java b/processor/src/main/resources/parcelablewrappers/ParcelableOptional.java
index aa81dc9..b41bc28 100644
--- a/processor/src/main/resources/parcelablewrappers/ParcelableOptional.java
+++ b/processor/src/main/resources/parcelablewrappers/ParcelableOptional.java
@@ -24,7 +24,7 @@ import java.util.Optional;
 /**
  * Wrapper for reading & writing {@link Optional} instances from and to {@link Parcel} instances.
  */
-public class ParcelableOptional<E> implements Parcelable {
+public final class ParcelableOptional<E> implements Parcelable {
 
   private static final int NULL = -1;
   private static final int ABSENT = 0;
diff --git a/processor/src/main/resources/parcelablewrappers/ParcelablePair.java b/processor/src/main/resources/parcelablewrappers/ParcelablePair.java
index 41dea47..a200ff7 100644
--- a/processor/src/main/resources/parcelablewrappers/ParcelablePair.java
+++ b/processor/src/main/resources/parcelablewrappers/ParcelablePair.java
@@ -22,7 +22,7 @@ import com.google.android.enterprise.connectedapps.internal.Bundler;
 import com.google.android.enterprise.connectedapps.internal.BundlerType;
 
 /** Wrapper for reading & writing {@link Pair} instances from and to {@link Parcel} instances. */
-public class ParcelablePair<F, S> implements Parcelable {
+public final class ParcelablePair<F, S> implements Parcelable {
 
   private static final int NULL = -1;
   private static final int NOT_NULL = 1;
diff --git a/processor/src/main/resources/parcelablewrappers/ParcelableSet.java b/processor/src/main/resources/parcelablewrappers/ParcelableSet.java
index b032f21..28342c2 100644
--- a/processor/src/main/resources/parcelablewrappers/ParcelableSet.java
+++ b/processor/src/main/resources/parcelablewrappers/ParcelableSet.java
@@ -23,7 +23,7 @@ import java.util.HashSet;
 import java.util.Set;
 
 /** Wrapper for reading & writing {@link Set} instances from and to {@link Parcel} instances. */
-public class ParcelableSet<E> implements Parcelable {
+public final class ParcelableSet<E> implements Parcelable {
 
   private static final int NULL_SIZE = -1;
 
diff --git a/sdk/src/main/java/com/google/android/enterprise/connectedapps/AbstractProfileBinder.java b/sdk/src/main/java/com/google/android/enterprise/connectedapps/AbstractProfileBinder.java
index 15b4ae0..5a8c726 100644
--- a/sdk/src/main/java/com/google/android/enterprise/connectedapps/AbstractProfileBinder.java
+++ b/sdk/src/main/java/com/google/android/enterprise/connectedapps/AbstractProfileBinder.java
@@ -48,6 +48,7 @@ public abstract class AbstractProfileBinder implements ConnectionBinder {
   private static final String INTERACT_ACROSS_USERS = "android.permission.INTERACT_ACROSS_USERS";
   private static final String INTERACT_ACROSS_USERS_FULL =
       "android.permission.INTERACT_ACROSS_USERS_FULL";
+  private static final String TAG = "AbstractProfileBinder";
 
   protected abstract Intent createIntent(Context context, ComponentName bindToService);
 
@@ -67,6 +68,10 @@ public abstract class AbstractProfileBinder implements ConnectionBinder {
     }
 
     Intent bindIntent = createIntent(context, bindToService);
+    if (bindIntent == null) {
+      Log.e(TAG, "Unable to create bind Intent");
+      return false;
+    }
 
     boolean hasBound =
         ReflectionUtilities.bindServiceAsUser(context, bindIntent, connection, otherUserHandle);
@@ -132,7 +137,7 @@ public abstract class AbstractProfileBinder implements ConnectionBinder {
         }
       }
     } catch (NameNotFoundException e) {
-      Log.e("AbstractProfileBinder", "Could not find package.", e);
+      Log.e(TAG, "Could not find package.", e);
       requestsInteractAcrossProfiles = false;
       requestsInteractAcrossUsers = false;
       requestsInteractAcrossUsersFull = false;
diff --git a/sdk/src/main/java/com/google/android/enterprise/connectedapps/Cache.java b/sdk/src/main/java/com/google/android/enterprise/connectedapps/Cache.java
new file mode 100644
index 0000000..bf600c7
--- /dev/null
+++ b/sdk/src/main/java/com/google/android/enterprise/connectedapps/Cache.java
@@ -0,0 +1,25 @@
+package com.google.android.enterprise.connectedapps;
+
+import java.io.Serializable;
+import org.checkerframework.checker.nullness.qual.Nullable;
+
+/** A cache of arbitrary {@link Serializable} values. */
+public interface Cache {
+  /**
+   * Returns a Serializable value associated with a {@code key} from the cache or null if no such
+   * value exists.
+   */
+  @Nullable Serializable getSerializable(String key);
+
+  /** Adds a serializable {@code value} to the cache at {@code key}. */
+  void putSerializable(String key, Serializable value);
+
+  /** Deletes an entry in the cache at {@code key}. */
+  void remove(String key);
+
+  /** Deletes all entries in the cache. */
+  void clearAll();
+
+  /** Returns {@code true} if there is an entry in the cache at {@code key}. */
+  boolean contains(String key);
+}
diff --git a/sdk/src/main/java/com/google/android/enterprise/connectedapps/CrossProfileCache.java b/sdk/src/main/java/com/google/android/enterprise/connectedapps/CrossProfileCache.java
new file mode 100644
index 0000000..9015b76
--- /dev/null
+++ b/sdk/src/main/java/com/google/android/enterprise/connectedapps/CrossProfileCache.java
@@ -0,0 +1,76 @@
+package com.google.android.enterprise.connectedapps;
+
+import android.util.LruCache;
+import com.google.errorprone.annotations.CheckReturnValue;
+import java.io.Serializable;
+
+/** In-memory implementation of {@link Cache}. */
+@CheckReturnValue // see go/why-crv
+final class CrossProfileCache implements Cache {
+
+  private static CrossProfileCache instance;
+
+  private static final int DEFAULT_NUMBER_OF_ENTRIES = 10;
+
+  private int maxNumberOfEntries = DEFAULT_NUMBER_OF_ENTRIES;
+  private int numberOfEntries = 0;
+  private final LruCache<String, Serializable> memCache = new LruCache<>(maxNumberOfEntries);
+
+  private CrossProfileCache() {}
+
+  /**
+   * Returns the current instance of the cache or create a new one if one does not already exists.
+   */
+  public static synchronized CrossProfileCache getInstance() {
+    if (instance == null) {
+      instance = new CrossProfileCache();
+    }
+    return instance;
+  }
+
+  @Override
+  public Serializable getSerializable(String key) {
+    return memCache.get(key);
+  }
+
+  @Override
+  public void putSerializable(String key, Serializable value) {
+    memCache.put(key, value);
+    if (numberOfEntries < maxNumberOfEntries) {
+      numberOfEntries++;
+    }
+  }
+
+  @Override
+  public void remove(String key) {
+    if (memCache.remove(key) != null) {
+      numberOfEntries--;
+    }
+  }
+
+  @Override
+  public void clearAll() {
+    memCache.evictAll();
+    numberOfEntries = 0;
+  }
+
+  @Override
+  public boolean contains(String key) {
+    return this.getSerializable(key) != null;
+  }
+
+  /** Returns the current number of entries in the cache. */
+  int numberOfEntries() {
+    return numberOfEntries;
+  }
+
+  int maxNumberOfEntries() {
+    return maxNumberOfEntries;
+  }
+
+  /** Changes the maximum number of entries in the cache. */
+  public void resize(int maxNumberOfEntries) {
+    instance.maxNumberOfEntries = maxNumberOfEntries;
+    memCache.resize(maxNumberOfEntries);
+  }
+}
diff --git a/sdk/src/main/java/com/google/android/enterprise/connectedapps/CrossProfileSDKUtilities.java b/sdk/src/main/java/com/google/android/enterprise/connectedapps/CrossProfileSDKUtilities.java
index 40cf326..16bcebf 100644
--- a/sdk/src/main/java/com/google/android/enterprise/connectedapps/CrossProfileSDKUtilities.java
+++ b/sdk/src/main/java/com/google/android/enterprise/connectedapps/CrossProfileSDKUtilities.java
@@ -17,6 +17,7 @@ package com.google.android.enterprise.connectedapps;
 
 import android.app.admin.DevicePolicyManager;
 import android.content.Context;
+import android.content.pm.CrossProfileApps;
 import android.content.pm.PackageInfo;
 import android.content.pm.PackageManager;
 import android.os.Build.VERSION;
@@ -27,6 +28,7 @@ import com.google.android.enterprise.connectedapps.annotations.AvailabilityRestr
 import java.util.ArrayList;
 import java.util.Collections;
 import java.util.List;
+
 import org.checkerframework.checker.nullness.qual.Nullable;
 
 /** Utility methods for acting on profiles. These methods should only be used by the SDK. */
@@ -74,9 +76,26 @@ class CrossProfileSDKUtilities {
   }
 
   static boolean isRunningOnPersonalProfile(Context context) {
+    if (VERSION.SDK_INT >= VERSION_CODES.TIRAMISU) {
+      UserManager userManager = context.getSystemService(UserManager.class);
+      return !userManager.isProfile();
+    }
     return !isRunningOnWorkProfile(context);
   }
 
+  /**
+   * Check if a user is either the personal user or the managed work profile.
+   *
+   * <p>If the user is not a profile, it is assumed to be the personal user.
+   */
+  static boolean isPersonalOrWorkProfile(CrossProfileApps crossProfileApps, UserHandle userHandle) {
+    if (VERSION.SDK_INT >= VERSION_CODES.VANILLA_ICE_CREAM) {
+      return crossProfileApps.isManagedProfile(userHandle)
+          || !crossProfileApps.isProfile(userHandle);
+    }
+    throw new UnsupportedOperationException("isPersonalOrWorkProfile is not supported on this SDK");
+  }
+
   /**
    * Deterministically select the user to bind to.
    *
@@ -85,6 +104,14 @@ class CrossProfileSDKUtilities {
    */
   @Nullable
   static UserHandle selectUserHandleToBind(Context context, List<UserHandle> userHandles) {
+    if (VERSION.SDK_INT >= VERSION_CODES.VANILLA_ICE_CREAM) {
+      CrossProfileApps crossProfileApps = context.getSystemService(CrossProfileApps.class);
+      userHandles =
+          userHandles.stream()
+              .filter(userHandle -> isPersonalOrWorkProfile(crossProfileApps, userHandle))
+                  .toList();
+    }
+
     if (userHandles.isEmpty()) {
       return null;
     }
diff --git a/sdk/src/main/java/com/google/android/enterprise/connectedapps/CrossProfileSender.java b/sdk/src/main/java/com/google/android/enterprise/connectedapps/CrossProfileSender.java
index 91aaadc..33ee4bb 100644
--- a/sdk/src/main/java/com/google/android/enterprise/connectedapps/CrossProfileSender.java
+++ b/sdk/src/main/java/com/google/android/enterprise/connectedapps/CrossProfileSender.java
@@ -49,13 +49,11 @@ import com.google.android.enterprise.connectedapps.internal.CrossProfileBundleCa
 import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.Collections;
-import java.util.HashSet;
 import java.util.List;
 import java.util.Map;
 import java.util.Objects;
 import java.util.Set;
 import java.util.WeakHashMap;
-import java.util.Iterator;
 import java.util.concurrent.ConcurrentHashMap;
 import java.util.concurrent.ConcurrentLinkedDeque;
 import java.util.concurrent.CountDownLatch;
@@ -285,18 +283,19 @@ public final class CrossProfileSender {
   // This is synchronized which isn't massively performant but it only gets accessed once straight
   // after creating a Sender, and once each time availability changes
   private static final Set<CrossProfileSender> senders =
-     synchronizedSet(newSetFromMap(new WeakHashMap<>()));
+      synchronizedSet(newSetFromMap(new WeakHashMap<>()));
 
-  private static final BroadcastReceiver profileAvailabilityReceiver = new BroadcastReceiver() {
-    @Override
-    public void onReceive(Context context, Intent intent) {
-      synchronized (senders) {
-        for (CrossProfileSender sender : senders) {
-          sender.scheduledExecutorService.execute(sender::checkAvailability);
+  private static final BroadcastReceiver profileAvailabilityReceiver =
+      new BroadcastReceiver() {
+        @Override
+        public void onReceive(Context context, Intent intent) {
+          synchronized (senders) {
+            for (CrossProfileSender sender : senders) {
+              sender.scheduledExecutorService.execute(sender::checkAvailability);
+            }
+          }
         }
-      }
-    }
-  };
+      };
 
   private final AtomicReference<ScheduledFuture<Void>> automaticDisconnectionFuture =
       new AtomicReference<>();
@@ -419,7 +418,11 @@ public final class CrossProfileSender {
     Log.i(LOG_TAG, "Blocking for bind");
     try {
       if (manuallyBindLatch != null) {
-        manuallyBindLatch.await();
+        try {
+          manuallyBindLatch.await(30, SECONDS);
+        } catch (NullPointerException e) {
+          // Ignore - avoiding race condition
+        }
       }
     } catch (InterruptedException e) {
       Log.e(LOG_TAG, "Interrupted waiting for manually bind", e);
diff --git a/sdk/src/main/java/com/google/android/enterprise/connectedapps/internal/BundleCallSender.java b/sdk/src/main/java/com/google/android/enterprise/connectedapps/internal/BundleCallSender.java
index e7fa9fd..ae0ce77 100644
--- a/sdk/src/main/java/com/google/android/enterprise/connectedapps/internal/BundleCallSender.java
+++ b/sdk/src/main/java/com/google/android/enterprise/connectedapps/internal/BundleCallSender.java
@@ -108,7 +108,14 @@ abstract class BundleCallSender {
       throws RemoteException {
     while (true) {
       try {
-        return call(callId, blockId, bytes);
+        byte[] returnBytes = call(callId, blockId, bytes);
+        if (returnBytes == null || returnBytes.length == 0) {
+          Log.w(
+              LOG_TAG,
+              String.format(
+                  "Call returned null or empty bytes from %s", super.getClass().getName()));
+        }
+        return returnBytes;
       } catch (TransactionTooLargeException e) {
         if (retries-- <= 0) {
           throw e;
@@ -209,7 +216,11 @@ abstract class BundleCallSender {
 
     byte[] returnBytes = makeParcelCall(callIdentifier, bytes);
 
+    if (returnBytes == null) {
+      throw new IllegalStateException("Return bytes are null");
+    }
     if (returnBytes.length == 0) {
+      Log.w(LOG_TAG, "Return bytes are empty");
       return null;
     }
 
diff --git a/sdk/src/main/java/com/google/android/enterprise/connectedapps/internal/ExceptionThrower.java b/sdk/src/main/java/com/google/android/enterprise/connectedapps/internal/ExceptionThrower.java
index 64338c6..e71259e 100644
--- a/sdk/src/main/java/com/google/android/enterprise/connectedapps/internal/ExceptionThrower.java
+++ b/sdk/src/main/java/com/google/android/enterprise/connectedapps/internal/ExceptionThrower.java
@@ -23,6 +23,8 @@ public final class ExceptionThrower {
 
   private ExceptionThrower() {}
 
+  private static final int DELAY_MILLIS = 5000;
+
   private static class ThrowingRunnable implements Runnable {
     RuntimeException runtimeException;
     Error error;
@@ -45,12 +47,13 @@ public final class ExceptionThrower {
   /** Throw the given {@link RuntimeException} after a delay on the main looper. */
   public static void delayThrow(RuntimeException runtimeException) {
     // We add a small delay to ensure that the return can be completed before crashing
-    new Handler(Looper.getMainLooper()).postDelayed(new ThrowingRunnable(runtimeException), 1000);
+    new Handler(Looper.getMainLooper())
+        .postDelayed(new ThrowingRunnable(runtimeException), DELAY_MILLIS);
   }
 
   /** Throw the given {@link Error} after a delay on the main looper. */
   public static void delayThrow(Error error) {
     // We add a small delay to ensure that the return can be completed before crashing
-    new Handler(Looper.getMainLooper()).postDelayed(new ThrowingRunnable(error), 1000);
+    new Handler(Looper.getMainLooper()).postDelayed(new ThrowingRunnable(error), DELAY_MILLIS);
   }
 }
diff --git a/tests/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/AlwaysThrowsTest.java b/tests/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/AlwaysThrowsTest.java
index b7ff2dd..ca04050 100644
--- a/tests/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/AlwaysThrowsTest.java
+++ b/tests/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/AlwaysThrowsTest.java
@@ -25,6 +25,8 @@ import com.google.android.enterprise.connectedapps.processor.annotationdiscovery
 import com.google.android.enterprise.connectedapps.processor.annotationdiscovery.AnnotationPrinter;
 import com.google.android.enterprise.connectedapps.processor.annotationdiscovery.AnnotationStrings;
 import com.google.testing.compile.Compilation;
+import com.google.testing.compile.JavaFileObjects;
+import javax.tools.JavaFileObject;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.junit.runners.Parameterized;
@@ -85,4 +87,56 @@ public class AlwaysThrowsTest {
         .contentsAsUtf8String()
         .contains("public NotesType_AlwaysThrows(String errorMessage)");
   }
+
+  @Test
+  public void compile_hasCacheableMethods_generatesUseCacheMethod() {
+    JavaFileObject notesType =
+        JavaFileObjects.forSourceLines(
+            NOTES_PACKAGE + ".NotesType",
+            "package " + NOTES_PACKAGE + ";",
+            "import com.google.android.enterprise.connectedapps.annotations.Cacheable;",
+            "import " + annotationPrinter.crossProfileQualifiedName() + ";",
+            "public final class NotesType {",
+            annotationPrinter.crossProfileAsAnnotation(),
+            "  @Cacheable",
+            "  public int countNotes() {",
+            "    return 1;",
+            "  }",
+            "}");
+
+    Compilation compilation =
+        javac()
+            .withProcessors(new Processor())
+            .compile(notesType, annotatedNotesProvider(annotationPrinter));
+
+    assertThat(compilation)
+        .generatedSourceFile(NOTES_PACKAGE + ".NotesType_AlwaysThrows")
+        .contentsAsUtf8String()
+        .contains("public NotesType_SingleSenderCanThrowCacheable useCache()");
+  }
+
+  @Test
+  public void compile_noCacheableMethods_doesNotGenerateUseCacheMethod() {
+    JavaFileObject notesType =
+        JavaFileObjects.forSourceLines(
+            NOTES_PACKAGE + ".NotesType",
+            "package " + NOTES_PACKAGE + ";",
+            "import " + annotationPrinter.crossProfileQualifiedName() + ";",
+            "public final class NotesType {",
+            annotationPrinter.crossProfileAsAnnotation(),
+            "  public int countNotes() {",
+            "    return 1;",
+            "  }",
+            "}");
+
+    Compilation compilation =
+        javac()
+            .withProcessors(new Processor())
+            .compile(notesType, annotatedNotesProvider(annotationPrinter));
+
+    assertThat(compilation)
+        .generatedSourceFile(NOTES_PACKAGE + ".NotesType_AlwaysThrows")
+        .contentsAsUtf8String()
+        .doesNotContain("public NotesType_SingleSenderCanThrowCacheable useCache()");
+  }
 }
diff --git a/tests/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/BundlerTest.java b/tests/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/BundlerTest.java
index 88d3d96..4037266 100644
--- a/tests/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/BundlerTest.java
+++ b/tests/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/BundlerTest.java
@@ -15,9 +15,15 @@
  */
 package com.google.android.enterprise.connectedapps.processor;
 
-import static com.google.android.enterprise.connectedapps.processor.TestUtilities.NOTES_PACKAGE;
 import static com.google.android.enterprise.connectedapps.processor.TestUtilities.annotatedNotesCrossProfileType;
 import static com.google.android.enterprise.connectedapps.processor.TestUtilities.annotatedNotesProvider;
+import static com.google.android.enterprise.connectedapps.processor.TestUtilities.CUSTOM_WRAPPER;
+import static com.google.android.enterprise.connectedapps.processor.TestUtilities.NOTES_PACKAGE;
+import static com.google.android.enterprise.connectedapps.processor.TestUtilities.PARCELABLE_CUSTOM_WRAPPER;
+import static com.google.android.enterprise.connectedapps.processor.TestUtilities.UNSUPPORTED_TYPE;
+import static com.google.android.enterprise.connectedapps.processor.TestUtilities.UNSUPPORTED_TYPE_NAME;
+import static com.google.android.enterprise.connectedapps.processor.TestUtilities.CUSTOM_PROFILE_CONNECTOR_QUALIFIED_NAME;
+import static com.google.android.enterprise.connectedapps.processor.TestUtilities.PROFILE_CONNECTOR_QUALIFIED_NAME;
 import static com.google.testing.compile.CompilationSubject.assertThat;
 import static com.google.testing.compile.Compiler.javac;
 
@@ -25,6 +31,8 @@ import com.google.android.enterprise.connectedapps.processor.annotationdiscovery
 import com.google.android.enterprise.connectedapps.processor.annotationdiscovery.AnnotationPrinter;
 import com.google.android.enterprise.connectedapps.processor.annotationdiscovery.AnnotationStrings;
 import com.google.testing.compile.Compilation;
+import com.google.testing.compile.JavaFileObjects;
+import javax.tools.JavaFileObject;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.junit.runners.Parameterized;
@@ -33,6 +41,10 @@ import org.junit.runners.Parameterized.Parameters;
 @RunWith(Parameterized.class)
 public class BundlerTest {
 
+  private static final String ADDITIONAL_TYPE_INVALID_TYPE_ERROR =
+      "The additional type %s cannot be used by used as a parameter for, or returned by methods"
+          + " annotated @CrossProfile";
+
   private final AnnotationPrinter annotationPrinter;
 
   public BundlerTest(AnnotationPrinter annotationPrinter) {
@@ -70,4 +82,121 @@ public class BundlerTest {
         .contentsAsUtf8String()
         .contains("NotesType_Bundler implements Bundler");
   }
+
+  @Test
+  public void additionalUsedType_isIncludedInBundler() {
+    JavaFileObject crossProfileTypeWithAdditionalUsedType =
+        JavaFileObjects.forSourceLines(
+            NOTES_PACKAGE + ".NotesType",
+            "package " + NOTES_PACKAGE + ";",
+            "import " + annotationPrinter.crossProfileQualifiedName() + ";",
+            annotationPrinter.crossProfileAsAnnotation("additionalUsedTypes=String.class"),
+            "public final class NotesType {",
+            "  void emptyMethod() {",
+            "  };",
+            "}");
+
+    Compilation compilation =
+        javac()
+            .withProcessors(new Processor())
+            .compile(
+                annotatedNotesProvider(annotationPrinter), crossProfileTypeWithAdditionalUsedType);
+
+    assertThat(compilation)
+        .generatedSourceFile(NOTES_PACKAGE + ".NotesType_Bundler")
+        .contentsAsUtf8String()
+        .contains("java.lang.String");
+  }
+
+  @Test
+  public void crossProfileTypeWithAdditionalUsedType_unsupportedType_failsCompile() {
+    JavaFileObject crossProfileTypeWithAdditionalUsedType =
+        JavaFileObjects.forSourceLines(
+            NOTES_PACKAGE + ".NotesType",
+            "package " + NOTES_PACKAGE + ";",
+            "import " + annotationPrinter.crossProfileQualifiedName() + ";",
+            annotationPrinter.crossProfileAsAnnotation(
+                "additionalUsedTypes=" + UNSUPPORTED_TYPE_NAME + ".class"),
+            "public final class NotesType {",
+            "  void emptyMethod() {",
+            "  }",
+            "}");
+
+    Compilation compilation =
+        javac()
+            .withProcessors(new Processor())
+            .compile(
+                UNSUPPORTED_TYPE,
+                annotatedNotesProvider(annotationPrinter),
+                crossProfileTypeWithAdditionalUsedType);
+
+    assertThat(compilation)
+        .hadErrorContaining(
+            String.format(ADDITIONAL_TYPE_INVALID_TYPE_ERROR, UNSUPPORTED_TYPE_NAME));
+  }
+
+  @Test
+  public void crossProfileTypeWithAdditionalUsedType_typedWithCustomWrapper_isIncludedInBundler() {
+    JavaFileObject crossProfileTypeWithAdditionalUsedType =
+        JavaFileObjects.forSourceLines(
+            NOTES_PACKAGE + ".NotesType",
+            "package " + NOTES_PACKAGE + ";",
+            "import " + annotationPrinter.crossProfileQualifiedName() + ";",
+            annotationPrinter.crossProfileAsAnnotation(
+                "parcelableWrappers=ParcelableCustomWrapper.class,"
+                    + " additionalUsedTypes=CustomWrapper.class"),
+            "public final class NotesType {",
+            annotationPrinter.crossProfileAsAnnotation(),
+            "  void emptyMethod() {",
+            "  }",
+            "}");
+
+    Compilation compilation =
+        javac()
+            .withProcessors(new Processor())
+            .compile(
+                annotatedNotesProvider(annotationPrinter),
+                crossProfileTypeWithAdditionalUsedType,
+                CUSTOM_WRAPPER,
+                PARCELABLE_CUSTOM_WRAPPER);
+
+    assertThat(compilation)
+        .generatedSourceFile(NOTES_PACKAGE + ".NotesType_Bundler")
+        .contentsAsUtf8String()
+        .contains("notes.CustomWrapper");
+  }
+
+  @Test
+  public void customProfileConnectorWithAdditionalUsedType_isIncludedInBundler() {
+    final JavaFileObject notesConnector =
+        JavaFileObjects.forSourceLines(
+            NOTES_PACKAGE + ".NotesConnector",
+            "package " + NOTES_PACKAGE + ";",
+            "import " + CUSTOM_PROFILE_CONNECTOR_QUALIFIED_NAME + ";",
+            "import " + PROFILE_CONNECTOR_QUALIFIED_NAME + ";",
+            "@CustomProfileConnector(additionalUsedTypes=String.class)",
+            "public interface NotesConnector extends ProfileConnector {",
+            "}");
+
+    final JavaFileObject notesType =
+        JavaFileObjects.forSourceLines(
+            NOTES_PACKAGE + ".NotesType",
+            "package " + NOTES_PACKAGE + ";",
+            "import " + annotationPrinter.crossProfileQualifiedName() + ";",
+            annotationPrinter.crossProfileAsAnnotation("connector=NotesConnector.class"),
+            "public final class NotesType {",
+            "  void emptyMethod() {",
+            "  };",
+            "}");
+
+    Compilation compilation =
+        javac()
+            .withProcessors(new Processor())
+            .compile(annotatedNotesProvider(annotationPrinter), notesConnector, notesType);
+
+    assertThat(compilation)
+        .generatedSourceFile(NOTES_PACKAGE + ".NotesType_Bundler")
+        .contentsAsUtf8String()
+        .contains("java.lang.String");
+  }
 }
diff --git a/tests/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/CacheableTest.java b/tests/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/CacheableTest.java
index f0c1bef..563ae16 100644
--- a/tests/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/CacheableTest.java
+++ b/tests/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/CacheableTest.java
@@ -25,7 +25,7 @@ public class CacheableTest {
   private static final String CACHEABLE_METHOD_RETURNS_VOID_ERROR =
       "Methods annotated with @Cacheable must return a non-void type";
   private static final String CACHEABLE_ANNOTATION_ON_NON_METHOD_ERROR =
-      "annotation type not applicable to this kind of declaration";
+      "annotation interface not applicable to this kind of declaration";
   private static final String CACHEABLE_METHOD_RETURNS_NON_SERIALIZABLE_ERROR =
       "Methods annotated with @Cacheable must return a type which implements Serializable, return"
           + " a future with a Serializable result or return void with a simple callback parameter.";
diff --git a/tests/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/CrossProfileSupportedParameterTypeTest.java b/tests/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/CrossProfileSupportedParameterTypeTest.java
index 325165f..40ef08e 100644
--- a/tests/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/CrossProfileSupportedParameterTypeTest.java
+++ b/tests/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/CrossProfileSupportedParameterTypeTest.java
@@ -103,7 +103,18 @@ public class CrossProfileSupportedParameterTypeTest {
       "com.google.protos.connectedappssdk.TestProtoOuterClass.TestProto[]",
       "java.util.List<com.google.protos.connectedappssdk.TestProtoOuterClass.TestProto>",
       "InstallationListener",
+      "com.google.common.collect.ImmutableCollection<String>",
       "com.google.common.collect.ImmutableMap<String, String>",
+      "com.google.common.collect.ImmutableMultimap<String, String>",
+      "com.google.common.collect.ImmutableSortedMap<String, String>",
+      "com.google.common.collect.ImmutableListMultimap<String, String>",
+      "com.google.common.collect.ImmutableSetMultimap<String, String>",
+      "com.google.common.collect.ImmutableList<String>",
+      "com.google.common.collect.ImmutableSet<String>",
+      "com.google.common.collect.ImmutableMultiset<String>",
+      "com.google.common.collect.ImmutableSortedSet<String>",
+      "com.google.common.collect.ImmutableSortedMultiset<String>",
+      "com.google.common.collect.ImmutableBiMap<String, String>",
       "android.util.Pair<String, Integer>",
       "android.graphics.Bitmap",
       "android.content.Context",
diff --git a/tests/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/CrossProfileSupportedReturnTypeTest.java b/tests/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/CrossProfileSupportedReturnTypeTest.java
index 7c5cebb..1d94916 100644
--- a/tests/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/CrossProfileSupportedReturnTypeTest.java
+++ b/tests/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/CrossProfileSupportedReturnTypeTest.java
@@ -114,8 +114,26 @@ public class CrossProfileSupportedReturnTypeTest {
               "com.google.common.util.concurrent.ListenableFuture<com.google.protos.connectedappssdk.TestProtoOuterClass.TestProto>"),
           TypeWithReturnValue.referenceType(
               "com.google.common.util.concurrent.ListenableFuture<java.util.List<String>>"),
+          TypeWithReturnValue.referenceType(
+              "com.google.common.collect.ImmutableCollection<String>"),
           TypeWithReturnValue.referenceType(
               "com.google.common.collect.ImmutableMap<String, String>"),
+          TypeWithReturnValue.referenceType(
+              "com.google.common.collect.ImmutableSortedMap<String, String>"),
+          TypeWithReturnValue.referenceType(
+              "com.google.common.collect.ImmutableMultimap<String, String>"),
+          TypeWithReturnValue.referenceType(
+              "com.google.common.collect.ImmutableSetMultimap<String, String>"),
+          TypeWithReturnValue.referenceType(
+              "com.google.common.collect.ImmutableListMultimap<String, String>"),
+          TypeWithReturnValue.referenceType("com.google.common.collect.ImmutableList<String>"),
+          TypeWithReturnValue.referenceType("com.google.common.collect.ImmutableSet<String>"),
+          TypeWithReturnValue.referenceType("com.google.common.collect.ImmutableSortedSet<String>"),
+          TypeWithReturnValue.referenceType("com.google.common.collect.ImmutableMultiset<String>"),
+          TypeWithReturnValue.referenceType(
+              "com.google.common.collect.ImmutableSortedMultiset<String>"),
+          TypeWithReturnValue.referenceType(
+              "com.google.common.collect.ImmutableBiMap<String, String>"),
           TypeWithReturnValue.referenceType("android.util.Pair<String, Integer>"),
           TypeWithReturnValue.referenceType("com.google.common.base.Optional<ParcelableObject>"),
           TypeWithReturnValue.referenceType("android.graphics.Bitmap"),
diff --git a/tests/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/InterfaceTest.java b/tests/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/InterfaceTest.java
index 485bb9f..aed1a2f 100644
--- a/tests/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/InterfaceTest.java
+++ b/tests/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/InterfaceTest.java
@@ -142,6 +142,162 @@ public class InterfaceTest {
         .doesNotContain("anotherMethod");
   }
 
+  @Test
+  public void compile_generatesSingleSenderCanThrowCacheableInterface() {
+    JavaFileObject notesType =
+        JavaFileObjects.forSourceLines(
+            NOTES_PACKAGE + ".NotesType",
+            "package " + NOTES_PACKAGE + ";",
+            "import com.google.android.enterprise.connectedapps.annotations.Cacheable;",
+            "import " + annotationPrinter.crossProfileQualifiedName() + ";",
+            "public final class NotesType {",
+            annotationPrinter.crossProfileAsAnnotation(),
+            "  @Cacheable",
+            "  public int countNotes() {",
+            "    return 1;",
+            "  }",
+            "}");
+
+    Compilation compilation =
+        javac()
+            .withProcessors(new Processor())
+            .compile(notesType, annotatedNotesProvider(annotationPrinter));
+
+    assertThat(compilation)
+        .generatedSourceFile(NOTES_PACKAGE + ".NotesType_SingleSenderCanThrowCacheable");
+  }
+
+  @Test
+  public void compile_generatesSingleSenderCanThrowCacheableInterfaceWithCorrectJavadoc() {
+    JavaFileObject notesType =
+        JavaFileObjects.forSourceLines(
+            NOTES_PACKAGE + ".NotesType",
+            "package " + NOTES_PACKAGE + ";",
+            "import com.google.android.enterprise.connectedapps.annotations.Cacheable;",
+            "import " + annotationPrinter.crossProfileQualifiedName() + ";",
+            "public final class NotesType {",
+            annotationPrinter.crossProfileAsAnnotation(),
+            "  @Cacheable",
+            "  public int countNotes() {",
+            "    return 1;",
+            "  }",
+            "}");
+
+    Compilation compilation =
+        javac()
+            .withProcessors(new Processor())
+            .compile(notesType, annotatedNotesProvider(annotationPrinter));
+
+    assertThat(compilation)
+        .generatedSourceFile(NOTES_PACKAGE + ".NotesType_SingleSenderCanThrowCacheable")
+        .contentsAsUtf8String()
+        .contains(
+            "Interface used for caching the results and interacting with the cached results"
+                + " of cross-profile calls.");
+  }
+
+  @Test
+  public void
+      compile_multipleAnnotatedMethods_singleSenderCanThrowCacheableInterfaceHasAllMethods() {
+    JavaFileObject notesType =
+        JavaFileObjects.forSourceLines(
+            NOTES_PACKAGE + ".NotesType",
+            "package " + NOTES_PACKAGE + ";",
+            "import com.google.android.enterprise.connectedapps.annotations.Cacheable;",
+            "import " + annotationPrinter.crossProfileQualifiedName() + ";",
+            "public final class NotesType {",
+            annotationPrinter.crossProfileAsAnnotation(),
+            "  @Cacheable",
+            "  public int countNotes() {",
+            "     return 1;",
+            "  }",
+            annotationPrinter.crossProfileAsAnnotation(),
+            "  @Cacheable",
+            "  public int anotherMethod() {",
+            "    return 0;",
+            "  }",
+            "}");
+
+    Compilation compilation =
+        javac()
+            .withProcessors(new Processor())
+            .compile(notesType, annotatedNotesProvider(annotationPrinter));
+
+    assertThat(compilation)
+        .generatedSourceFile(NOTES_PACKAGE + ".NotesType_SingleSenderCanThrowCacheable")
+        .contentsAsUtf8String()
+        .contains("int countNotes()");
+
+    assertThat(compilation)
+        .generatedSourceFile(NOTES_PACKAGE + ".NotesType_SingleSenderCanThrowCacheable")
+        .contentsAsUtf8String()
+        .contains("int anotherMethod()");
+  }
+
+  @Test
+  public void compile_singleSenderCanThrowCacheableInterfaceHasMethodWithCorrectJavadoc() {
+    JavaFileObject notesType =
+        JavaFileObjects.forSourceLines(
+            NOTES_PACKAGE + ".NotesType",
+            "package " + NOTES_PACKAGE + ";",
+            "import com.google.android.enterprise.connectedapps.annotations.Cacheable;",
+            "import " + annotationPrinter.crossProfileQualifiedName() + ";",
+            "public final class NotesType {",
+            annotationPrinter.crossProfileAsAnnotation(),
+            "  @Cacheable",
+            "  public int countNotes() {",
+            "     return 1;",
+            "  }",
+            "}");
+
+    Compilation compilation =
+        javac()
+            .withProcessors(new Processor())
+            .compile(notesType, annotatedNotesProvider(annotationPrinter));
+
+    assertThat(compilation)
+        .generatedSourceFile(NOTES_PACKAGE + ".NotesType_SingleSenderCanThrowCacheable")
+        .contentsAsUtf8String()
+        .contains(
+            "* Attempts to fetch the cached result of calling {@link NotesType#countNotes()} on the"
+                + " given profile.\n"
+                + "   * If a result is not already in the cache, this will make a call to {@link"
+                + " NotesType#countNotes()} on the given profile.\n"
+                + "   *\n"
+                + "   * @see NotesType#countNotes()\n");
+  }
+
+  @Test
+  public void
+      compile_multipleMethods_singleSenderCanThrowCacheableInterfaceDoesNotHaveUnannotatedMethods() {
+    JavaFileObject notesType =
+        JavaFileObjects.forSourceLines(
+            NOTES_PACKAGE + ".NotesType",
+            "package " + NOTES_PACKAGE + ";",
+            "import com.google.android.enterprise.connectedapps.annotations.Cacheable;",
+            "import " + annotationPrinter.crossProfileQualifiedName() + ";",
+            "public final class NotesType {",
+            annotationPrinter.crossProfileAsAnnotation(),
+            "  @Cacheable",
+            "  public int countNotes() {",
+            "    return 1;",
+            "  }",
+            "  public int anotherMethod(String s) {",
+            "    return 0;",
+            "  }",
+            "}");
+
+    Compilation compilation =
+        javac()
+            .withProcessors(new Processor())
+            .compile(notesType, annotatedNotesProvider(annotationPrinter));
+
+    assertThat(compilation)
+        .generatedSourceFile(NOTES_PACKAGE + ".NotesType_SingleSenderCanThrowCacheable")
+        .contentsAsUtf8String()
+        .doesNotContain("anotherMethod");
+  }
+
   @Test
   public void compile_generatesSingleSenderCanThrowInterface() {
     Compilation compilation =
diff --git a/tests/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/OtherProfileCacheableTest.java b/tests/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/OtherProfileCacheableTest.java
new file mode 100644
index 0000000..ff88d09
--- /dev/null
+++ b/tests/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/OtherProfileCacheableTest.java
@@ -0,0 +1,118 @@
+/*
+ * Copyright 2021 Google LLC
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *   https://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+package com.google.android.enterprise.connectedapps.processor;
+
+import static com.google.android.enterprise.connectedapps.processor.TestUtilities.NOTES_PACKAGE;
+import static com.google.android.enterprise.connectedapps.processor.TestUtilities.annotatedNotesCrossProfileType;
+import static com.google.android.enterprise.connectedapps.processor.TestUtilities.annotatedNotesProvider;
+import static com.google.common.truth.Truth.assertThat;
+import static com.google.testing.compile.CompilationSubject.assertThat;
+import static com.google.testing.compile.Compiler.javac;
+
+import com.google.android.enterprise.connectedapps.processor.annotationdiscovery.AnnotationFinder;
+import com.google.android.enterprise.connectedapps.processor.annotationdiscovery.AnnotationPrinter;
+import com.google.android.enterprise.connectedapps.processor.annotationdiscovery.AnnotationStrings;
+import com.google.testing.compile.Compilation;
+import com.google.testing.compile.JavaFileObjects;
+import java.util.Optional;
+import javax.tools.JavaFileObject;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.Parameterized;
+import org.junit.runners.Parameterized.Parameters;
+
+@RunWith(Parameterized.class)
+public final class OtherProfileCacheableTest {
+
+  private final AnnotationPrinter annotationPrinter;
+
+  public OtherProfileCacheableTest(AnnotationPrinter annotationPrinter) {
+    this.annotationPrinter = annotationPrinter;
+  }
+
+  @Parameters(name = "{0}")
+  public static Iterable<AnnotationStrings> getAnnotationPrinters() {
+    return AnnotationFinder.annotationStrings();
+  }
+
+  @Test
+  public void compile_generatesOtherProfileCacheableClass() {
+    JavaFileObject notesType =
+        JavaFileObjects.forSourceLines(
+            NOTES_PACKAGE + ".NotesType",
+            "package " + NOTES_PACKAGE + ";",
+            "import com.google.android.enterprise.connectedapps.annotations.Cacheable;",
+            "import " + annotationPrinter.crossProfileQualifiedName() + ";",
+            "public final class NotesType {",
+            annotationPrinter.crossProfileAsAnnotation(),
+            "  @Cacheable",
+            "  public int countNotes() {",
+            "    return 1;",
+            "  }",
+            "}");
+
+    Compilation compilation =
+        javac()
+            .withProcessors(new Processor())
+            .compile(notesType, annotatedNotesProvider(annotationPrinter));
+
+    assertThat(compilation).generatedSourceFile(NOTES_PACKAGE + ".NotesType_OtherProfileCacheable");
+  }
+
+  @Test
+  public void compile_otherProfileClassCacheableImplementsSingleSenderCanThrowCacheable() {
+    JavaFileObject notesType =
+        JavaFileObjects.forSourceLines(
+            NOTES_PACKAGE + ".NotesType",
+            "package " + NOTES_PACKAGE + ";",
+            "import com.google.android.enterprise.connectedapps.annotations.Cacheable;",
+            "import " + annotationPrinter.crossProfileQualifiedName() + ";",
+            "public final class NotesType {",
+            annotationPrinter.crossProfileAsAnnotation(),
+            "  @Cacheable",
+            "  public int countNotes() {",
+            "    return 1;",
+            "  }",
+            "}");
+
+    Compilation compilation =
+        javac()
+            .withProcessors(new Processor())
+            .compile(notesType, annotatedNotesProvider(annotationPrinter));
+
+    assertThat(compilation)
+        .generatedSourceFile(NOTES_PACKAGE + ".NotesType_OtherProfileCacheable")
+        .contentsAsUtf8String()
+        .contains(
+            "class NotesType_OtherProfileCacheable implements "
+                + "NotesType_SingleSenderCanThrowCacheable");
+  }
+
+  @Test
+  public void compile_noCacheableMethods_doesNotGenerateOtherProfileCacheableClass() {
+    Compilation compilation =
+        javac()
+            .withProcessors(new Processor())
+            .compile(
+                annotatedNotesProvider(annotationPrinter),
+                annotatedNotesCrossProfileType(annotationPrinter));
+
+    Optional<JavaFileObject> otherProfileCacheableClass =
+        compilation.generatedSourceFile(NOTES_PACKAGE + ".NotesType_OtherProfileCacheable");
+
+    assertThat(otherProfileCacheableClass).isEmpty();
+  }
+}
diff --git a/tests/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/OtherProfileTest.java b/tests/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/OtherProfileTest.java
index e7eae98..27d8586 100644
--- a/tests/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/OtherProfileTest.java
+++ b/tests/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/OtherProfileTest.java
@@ -25,6 +25,8 @@ import com.google.android.enterprise.connectedapps.processor.annotationdiscovery
 import com.google.android.enterprise.connectedapps.processor.annotationdiscovery.AnnotationPrinter;
 import com.google.android.enterprise.connectedapps.processor.annotationdiscovery.AnnotationStrings;
 import com.google.testing.compile.Compilation;
+import com.google.testing.compile.JavaFileObjects;
+import javax.tools.JavaFileObject;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.junit.runners.Parameterized;
@@ -85,4 +87,56 @@ public class OtherProfileTest {
         .contentsAsUtf8String()
         .contains("public NotesType_OtherProfile(ProfileConnector connector)");
   }
+
+  @Test
+  public void compile_hasCacheableMethods_generatesUseCacheMethod() {
+    JavaFileObject notesType =
+        JavaFileObjects.forSourceLines(
+            NOTES_PACKAGE + ".NotesType",
+            "package " + NOTES_PACKAGE + ";",
+            "import com.google.android.enterprise.connectedapps.annotations.Cacheable;",
+            "import " + annotationPrinter.crossProfileQualifiedName() + ";",
+            "public final class NotesType {",
+            annotationPrinter.crossProfileAsAnnotation(),
+            "  @Cacheable",
+            "  public int countNotes() {",
+            "    return 1;",
+            "  }",
+            "}");
+
+    Compilation compilation =
+        javac()
+            .withProcessors(new Processor())
+            .compile(notesType, annotatedNotesProvider(annotationPrinter));
+
+    assertThat(compilation)
+        .generatedSourceFile(NOTES_PACKAGE + ".NotesType_OtherProfile")
+        .contentsAsUtf8String()
+        .contains("public NotesType_SingleSenderCanThrowCacheable useCache()");
+  }
+
+  @Test
+  public void compile_noCacheableMethods_doesNotGenerateUseCacheMethod() {
+    JavaFileObject notesType =
+        JavaFileObjects.forSourceLines(
+            NOTES_PACKAGE + ".NotesType",
+            "package " + NOTES_PACKAGE + ";",
+            "import " + annotationPrinter.crossProfileQualifiedName() + ";",
+            "public final class NotesType {",
+            annotationPrinter.crossProfileAsAnnotation(),
+            "  public int countNotes() {",
+            "    return 1;",
+            "  }",
+            "}");
+
+    Compilation compilation =
+        javac()
+            .withProcessors(new Processor())
+            .compile(notesType, annotatedNotesProvider(annotationPrinter));
+
+    assertThat(compilation)
+        .generatedSourceFile(NOTES_PACKAGE + ".NotesType_OtherProfile")
+        .contentsAsUtf8String()
+        .doesNotContain("public NotesType_SingleSenderCanThrowCacheable useCache()");
+  }
 }
diff --git a/tests/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/ProcessorCurrentProfileTest.java b/tests/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/ProcessorCurrentProfileTest.java
index 6daab70..a39e143 100644
--- a/tests/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/ProcessorCurrentProfileTest.java
+++ b/tests/processor/src/main/java/com/google/android/enterprise/connectedapps/processor/ProcessorCurrentProfileTest.java
@@ -25,6 +25,8 @@ import com.google.android.enterprise.connectedapps.processor.annotationdiscovery
 import com.google.android.enterprise.connectedapps.processor.annotationdiscovery.AnnotationPrinter;
 import com.google.android.enterprise.connectedapps.processor.annotationdiscovery.AnnotationStrings;
 import com.google.testing.compile.Compilation;
+import com.google.testing.compile.JavaFileObjects;
+import javax.tools.JavaFileObject;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.junit.runners.Parameterized;
@@ -85,4 +87,56 @@ public class ProcessorCurrentProfileTest {
         .contentsAsUtf8String()
         .contains("public NotesType_CurrentProfile(Context context, NotesType crossProfileType)");
   }
+
+  @Test
+  public void compile_hasCacheableMethods_generatesUseCacheMethod() {
+    JavaFileObject notesType =
+        JavaFileObjects.forSourceLines(
+            NOTES_PACKAGE + ".NotesType",
+            "package " + NOTES_PACKAGE + ";",
+            "import com.google.android.enterprise.connectedapps.annotations.Cacheable;",
+            "import " + annotationPrinter.crossProfileQualifiedName() + ";",
+            "public final class NotesType {",
+            annotationPrinter.crossProfileAsAnnotation(),
+            "  @Cacheable",
+            "  public int countNotes() {",
+            "    return 1;",
+            "  }",
+            "}");
+
+    Compilation compilation =
+        javac()
+            .withProcessors(new Processor())
+            .compile(notesType, annotatedNotesProvider(annotationPrinter));
+
+    assertThat(compilation)
+        .generatedSourceFile(NOTES_PACKAGE + ".NotesType_CurrentProfile")
+        .contentsAsUtf8String()
+        .contains("public NotesType_SingleSenderCanThrowCacheable useCache()");
+  }
+
+  @Test
+  public void compile_noCacheableMethods_doesNotGenerateUseCacheMethod() {
+    JavaFileObject notesType =
+        JavaFileObjects.forSourceLines(
+            NOTES_PACKAGE + ".NotesType",
+            "package " + NOTES_PACKAGE + ";",
+            "import " + annotationPrinter.crossProfileQualifiedName() + ";",
+            "public final class NotesType {",
+            annotationPrinter.crossProfileAsAnnotation(),
+            "  public int countNotes() {",
+            "    return 1;",
+            "  }",
+            "}");
+
+    Compilation compilation =
+        javac()
+            .withProcessors(new Processor())
+            .compile(notesType, annotatedNotesProvider(annotationPrinter));
+
+    assertThat(compilation)
+        .generatedSourceFile(NOTES_PACKAGE + ".NotesType_CurrentProfile")
+        .contentsAsUtf8String()
+        .doesNotContain("public NotesType_SingleSenderCanThrowCacheable useCache()");
+  }
 }
diff --git a/tests/robotests/src/test/java/com/google/android/enterprise/connectedapps/CrossProfileCacheTest.java b/tests/robotests/src/test/java/com/google/android/enterprise/connectedapps/CrossProfileCacheTest.java
new file mode 100644
index 0000000..7d3151f
--- /dev/null
+++ b/tests/robotests/src/test/java/com/google/android/enterprise/connectedapps/CrossProfileCacheTest.java
@@ -0,0 +1,104 @@
+package com.google.android.enterprise.connectedapps;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import java.io.Serializable;
+import org.junit.Before;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.robolectric.RobolectricTestRunner;
+
+@RunWith(RobolectricTestRunner.class)
+public final class CrossProfileCacheTest {
+
+  private static final String KEY1 = "key1";
+  private static final String KEY2 = "key2";
+  private static final Serializable value1 = 123;
+  private static final Serializable value2 = false;
+
+  CrossProfileCache cache = CrossProfileCache.getInstance();
+
+  @Before
+  public void setUp() {
+    cache.clearAll();
+  }
+
+  @Test
+  public void getSerializable_valueInMemCache_valueReturned() {
+    cache.putSerializable(KEY1, value1);
+
+    Serializable result = cache.getSerializable(KEY1);
+
+    assertThat(result).isEqualTo(value1);
+  }
+
+  @Test
+  public void getSerializable_valueNotInMemCache_nullReturned() {
+    Serializable result = cache.getSerializable(KEY1);
+
+    assertThat(result).isNull();
+  }
+
+  @Test
+  public void putSerializable_valueAddedToMemCache() {
+    cache.putSerializable(KEY1, value1);
+
+    boolean inMemCache = cache.contains(KEY1);
+
+    assertThat(inMemCache).isTrue();
+  }
+
+  @Test
+  public void putSerializable_keyAlreadyUsed_newValueReplacedOldValue() {
+    cache.putSerializable(KEY1, value1);
+    cache.putSerializable(KEY1, value2);
+
+    Serializable result = cache.getSerializable(KEY1);
+
+    assertThat(result).isEqualTo(value2);
+  }
+
+  @Test
+  public void putSerializable_cacheFull_newEntryAdded_oneEntryRemoved() {
+    for (int i = 0; i < cache.maxNumberOfEntries(); i++) {
+      cache.putSerializable(KEY1 + i, value1);
+    }
+
+    cache.putSerializable(KEY2, value2);
+
+    assertThat(cache.numberOfEntries()).isEqualTo(cache.maxNumberOfEntries());
+    assertThat(cache.contains(KEY2)).isTrue();
+    // The least recently used entry should be evicted.
+    assertThat(cache.contains(KEY1 + 0)).isFalse();
+  }
+
+  @Test
+  public void remove_valueInMemCache_valueRemovedFromMemCache() {
+    cache.putSerializable(KEY1, value1);
+
+    cache.remove(KEY1);
+
+    assertThat(cache.contains(KEY1)).isFalse();
+  }
+
+  @Test
+  public void remove_valueNotInMemCache_nothingRemovedFromMemCache() {
+    cache.putSerializable(KEY1, value1);
+
+    cache.remove(KEY2);
+
+    assertThat(cache.numberOfEntries()).isEqualTo(1);
+  }
+
+  @Test
+  public void clearAll_allValuesRemovedFromMemCache() {
+    cache.putSerializable(KEY1, value1);
+    cache.putSerializable(KEY1, value2);
+
+    cache.clearAll();
+
+    assertThat(cache.contains(KEY1)).isFalse();
+    assertThat(cache.contains(KEY2)).isFalse();
+    assertThat(cache.numberOfEntries()).isEqualTo(0);
+  }
+}
diff --git a/tests/robotests/src/test/java/com/google/android/enterprise/connectedapps/CrossProfileSenderTest.java b/tests/robotests/src/test/java/com/google/android/enterprise/connectedapps/CrossProfileSenderTest.java
index 0bea467..887e0a0 100644
--- a/tests/robotests/src/test/java/com/google/android/enterprise/connectedapps/CrossProfileSenderTest.java
+++ b/tests/robotests/src/test/java/com/google/android/enterprise/connectedapps/CrossProfileSenderTest.java
@@ -27,6 +27,8 @@ import static org.robolectric.annotation.LooperMode.Mode.LEGACY;
 import android.app.Application;
 import android.app.admin.DevicePolicyManager;
 import android.content.ComponentName;
+import android.content.Context;
+import android.content.Intent;
 import android.os.Build.VERSION_CODES;
 import android.os.Bundle;
 import android.os.UserHandle;
@@ -158,7 +160,7 @@ public class CrossProfileSenderTest {
                 AvailabilityRestrictions.DEFAULT));
   }
 
-    @Test
+  @Test
   public void construct_nullTimeoutExecutor_throwsNullPointerException() {
     assertThrows(
         NullPointerException.class,
@@ -188,6 +190,58 @@ public class CrossProfileSenderTest {
                 /* availabilityRestrictions= */ null));
   }
 
+  @Test
+  public void nullBinderIntent_throwsException() {
+    ConnectionBinder nullIntentBinder =
+        new AbstractProfileBinder() {
+          @Override
+          protected Intent createIntent(Context context, ComponentName componentName) {
+            return null;
+          }
+        };
+
+    CrossProfileSender sender =
+        new CrossProfileSender(
+            context,
+            TEST_SERVICE_CLASS_NAME,
+            nullIntentBinder,
+            connectionListener,
+            availabilityListener,
+            scheduledExecutorService,
+            AvailabilityRestrictions.DEFAULT);
+
+    int crossProfileTypeIdentifier = 1;
+    int methodIdentifier = 0;
+    Bundle params = new Bundle(Bundler.class.getClassLoader());
+
+    assertThrows(
+        UnavailableProfileException.class,
+        () -> sender.call(crossProfileTypeIdentifier, methodIdentifier, params));
+  }
+
+  @Test
+  public void connectionBinderException() {
+    ConnectionBinder throwsIntentBinder =
+        new AbstractProfileBinder() {
+          @Override
+          protected Intent createIntent(Context context, ComponentName componentName) {
+            throw new NullPointerException("ConnectionBinder throws NPE");
+          }
+        };
+
+    CrossProfileSender sender =
+        new CrossProfileSender(
+            context,
+            TEST_SERVICE_CLASS_NAME,
+            throwsIntentBinder,
+            connectionListener,
+            availabilityListener,
+            scheduledExecutorService,
+            AvailabilityRestrictions.DEFAULT);
+
+    assertThrows(NullPointerException.class, () -> sender.addConnectionHolder(this));
+  }
+
   // Other manuallyBind tests are covered in Instrumented ConnectTest because Robolectric doesn't
   // handle the multiple threads very well
   @Test
@@ -459,7 +513,7 @@ public class CrossProfileSenderTest {
 
   @Test
   public void createMultipleSenders_workProfileBecomesAvailable_callsAvailabilityListenerForEachSender() {
-    CrossProfileSender sender2 =
+    CrossProfileSender unusedSender2 =
         new CrossProfileSender(
             context,
             TEST_SERVICE_CLASS_NAME,
@@ -508,6 +562,32 @@ public class CrossProfileSenderTest {
         testUtilities::simulateDisconnectingServiceConnection);
   }
 
+  // Regression test for b/292471207
+  @Test
+  public void concurrentAvailabilityBroadcastAndCreateCrossProfileSender_doesntCrash()
+      throws Exception {
+    tryForceRaceCondition(
+        1000,
+        () -> {
+          // This will cause CrossProfileSender to iterate through its list of senders.
+          testUtilities.turnOffWorkProfile();
+          testUtilities.turnOnWorkProfile();
+        },
+        () -> {
+          // We don't care about the return value here, just that creating a cross profile
+          // sender modifies its global set of senders.
+          var unused =
+              new CrossProfileSender(
+                  context,
+                  TEST_SERVICE_CLASS_NAME,
+                  new DpcProfileBinder(new ComponentName("A", "B")),
+                  connectionListener,
+                  availabilityListener,
+                  scheduledExecutorService,
+                  AvailabilityRestrictions.DEFAULT);
+        });
+  }
+
   private void initWithDpcBinding() {
     shadowOf(devicePolicyManager)
         .setBindDeviceAdminTargetUsers(ImmutableList.of(getWorkUserHandle()));
diff --git a/tests/robotests/src/test/java/com/google/android/enterprise/connectedapps/RobolectricTestUtilities.java b/tests/robotests/src/test/java/com/google/android/enterprise/connectedapps/RobolectricTestUtilities.java
index cd7c0d3..d99bc81 100644
--- a/tests/robotests/src/test/java/com/google/android/enterprise/connectedapps/RobolectricTestUtilities.java
+++ b/tests/robotests/src/test/java/com/google/android/enterprise/connectedapps/RobolectricTestUtilities.java
@@ -60,6 +60,8 @@ public class RobolectricTestUtilities {
 
   /* Matches UserHandle#PER_USER_RANGE */
   private static final int PER_USER_RANGE = 100000;
+  /* Matches UserInfo#FLAG_PROFILE */
+  private static final int FLAG_PROFILE = 0x00001000;
 
   private final UserHandle personalProfileUserHandle =
       getUserHandleForUserId(PERSONAL_PROFILE_USER_ID);
@@ -136,10 +138,11 @@ public class RobolectricTestUtilities {
   }
 
   public void createWorkUser() {
-    shadowOf(userManager).addUser(WORK_PROFILE_USER_ID, "Work Profile", /* flags= */ 0);
+    shadowOf(userManager).addUser(WORK_PROFILE_USER_ID, "Work Profile", /* flags= */ FLAG_PROFILE);
     shadowOf(userManager)
-        .addProfile(PERSONAL_PROFILE_USER_ID, WORK_PROFILE_USER_ID, "Work Profile", 0);
-    shadowOf(userManager).addProfile(WORK_PROFILE_USER_ID, WORK_PROFILE_USER_ID, "Work Profile", 0);
+        .addProfile(PERSONAL_PROFILE_USER_ID, WORK_PROFILE_USER_ID, "Work Profile", FLAG_PROFILE);
+    shadowOf(userManager)
+        .addProfile(WORK_PROFILE_USER_ID, WORK_PROFILE_USER_ID, "Work Profile", FLAG_PROFILE);
     shadowOf(userManager)
         .addProfile(WORK_PROFILE_USER_ID, PERSONAL_PROFILE_USER_ID, "Personal Profile", 0);
   }
diff --git a/tests/robotests/src/test/java/com/google/android/enterprise/connectedapps/robotests/TypesTest.java b/tests/robotests/src/test/java/com/google/android/enterprise/connectedapps/robotests/TypesTest.java
index 717a6e9..6b549e9 100644
--- a/tests/robotests/src/test/java/com/google/android/enterprise/connectedapps/robotests/TypesTest.java
+++ b/tests/robotests/src/test/java/com/google/android/enterprise/connectedapps/robotests/TypesTest.java
@@ -17,6 +17,7 @@ package com.google.android.enterprise.connectedapps.robotests;
 
 import static com.google.android.enterprise.connectedapps.SharedTestUtilities.INTERACT_ACROSS_USERS;
 import static com.google.common.truth.Truth.assertThat;
+import static org.robolectric.annotation.GraphicsMode.Mode.LEGACY;
 
 import android.app.Application;
 import android.app.Service;
@@ -49,16 +50,24 @@ import com.google.android.enterprise.connectedapps.testapp.types.ProfileTestCros
 import com.google.android.enterprise.connectedapps.testapp.types.TestCrossProfileType;
 import com.google.android.enterprise.connectedapps.testapp.types.TestCrossProfileType_SingleSenderCanThrow;
 import com.google.common.base.Optional;
+import com.google.common.collect.ImmutableBiMap;
+import com.google.common.collect.ImmutableCollection;
 import com.google.common.collect.ImmutableList;
+import com.google.common.collect.ImmutableListMultimap;
 import com.google.common.collect.ImmutableMap;
+import com.google.common.collect.ImmutableMultimap;
+import com.google.common.collect.ImmutableMultiset;
 import com.google.common.collect.ImmutableSet;
+import com.google.common.collect.ImmutableSetMultimap;
+import com.google.common.collect.ImmutableSortedMap;
+import com.google.common.collect.ImmutableSortedMultiset;
+import com.google.common.collect.ImmutableSortedSet;
 import com.google.common.util.concurrent.ListenableFuture;
 import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.Collection;
 import java.util.Collections;
 import java.util.List;
-import java.util.Set;
 import java.util.concurrent.ExecutionException;
 import org.junit.Before;
 import org.junit.Test;
@@ -66,45 +75,47 @@ import org.junit.runner.RunWith;
 import org.robolectric.ParameterizedRobolectricTestRunner;
 import org.robolectric.Robolectric;
 import org.robolectric.annotation.Config;
+import org.robolectric.annotation.GraphicsMode;
 import org.robolectric.annotation.LooperMode;
 
 @LooperMode(LooperMode.Mode.LEGACY)
+@GraphicsMode(LEGACY)
 @RunWith(ParameterizedRobolectricTestRunner.class)
 @Config(minSdk = VERSION_CODES.O)
 public class TypesTest {
 
   private static final String STRING = "string";
   private static final byte BYTE = 1;
-  private static final byte[] BYTE_ARRAY = new byte[]{BYTE};
+  private static final byte[] BYTE_ARRAY = new byte[] {BYTE};
   private static final byte[][][] MULTIDIMENSIONAL_BYTE_ARRAY = new byte[][][] {{BYTE_ARRAY}};
   private static final Byte BYTE_BOXED = 1;
   private static final short SHORT = 1;
-  private static final short[] SHORT_ARRAY = new short[]{SHORT};
+  private static final short[] SHORT_ARRAY = new short[] {SHORT};
   private static final short[][][] MULTIDIMENSIONAL_SHORT_ARRAY = new short[][][] {{SHORT_ARRAY}};
   private static final Short SHORT_BOXED = 1;
   private static final int INT = 1;
-  private static final int[] INT_ARRAY = new int[]{INT};
+  private static final int[] INT_ARRAY = new int[] {INT};
   private static final int[][][] MULTIDIMENSIONAL_INT_ARRAY = new int[][][] {{INT_ARRAY}};
   private static final Integer INTEGER = 1;
   private static final long LONG = 1;
-  private static final long[] LONG_ARRAY = new long[]{LONG};
+  private static final long[] LONG_ARRAY = new long[] {LONG};
   private static final long[][][] MULTIDIMENSIONAL_LONG_ARRAY = new long[][][] {{LONG_ARRAY}};
   private static final Long LONG_BOXED = 1L;
   private static final float FLOAT = 1;
-  private static final float[] FLOAT_ARRAY = new float[]{FLOAT};
+  private static final float[] FLOAT_ARRAY = new float[] {FLOAT};
   private static final float[][][] MULTIDIMENSIONAL_FLOAT_ARRAY = new float[][][] {{FLOAT_ARRAY}};
   private static final Float FLOAT_BOXED = 1f;
   private static final double DOUBLE = 1;
-  private static final double[] DOUBLE_ARRAY = new double[]{DOUBLE};
+  private static final double[] DOUBLE_ARRAY = new double[] {DOUBLE};
   private static final double[][][] MULTIDIMENSIONAL_DOUBLE_ARRAY =
       new double[][][] {{DOUBLE_ARRAY}};
   private static final Double DOUBLE_BOXED = 1d;
   private static final char CHAR = 1;
-  private static final char[] CHAR_ARRAY = new char[]{CHAR};
+  private static final char[] CHAR_ARRAY = new char[] {CHAR};
   private static final char[][][] MULTIDIMENSIONAL_CHAR_ARRAY = new char[][][] {{CHAR_ARRAY}};
   private static final Character CHARACTER = 1;
   private static final boolean BOOLEAN = true;
-  private static final boolean[] BOOLEAN_ARRAY = new boolean[]{BOOLEAN};
+  private static final boolean[] BOOLEAN_ARRAY = new boolean[] {BOOLEAN};
   private static final boolean[][][] MULTIDIMENSIONAL_BOOLEAN_ARRAY =
       new boolean[][][] {{BOOLEAN_ARRAY}};
   private static final Boolean BOOLEAN_BOXED = true;
@@ -116,8 +127,27 @@ public class TypesTest {
   private static final List<SerializableObject> listOfSerializable = ImmutableList.of(SERIALIZABLE);
   private static final ImmutableMap<String, String> IMMUTABLE_MAP_STRING_TO_STRING =
       ImmutableMap.of(STRING, STRING);
-  private static final Set<String> setOfString = ImmutableSet.of(STRING);
-  private static final Collection<String> collectionOfString = ImmutableList.of(STRING);
+  private static final ImmutableSortedMap<String, String> IMMUTABLE_SORTED_MAP_STRING_TO_STRING =
+      ImmutableSortedMap.of(STRING, STRING);
+  private static final ImmutableMultimap<String, String> IMMUTABLE_MULTIMAP_STRING_TO_STRING =
+      ImmutableMultimap.of(STRING, STRING);
+  private static final ImmutableSetMultimap<String, String>
+      IMMUTABLE_SET_MULTIMAP_STRING_TO_STRING = ImmutableSetMultimap.of(STRING, STRING);
+  private static final ImmutableListMultimap<String, String>
+      IMMUTABLE_LIST_MULTIMAP_STRING_TO_STRING = ImmutableListMultimap.of(STRING, STRING);
+  private static final ImmutableList<String> IMMUTABLE_LIST_STRING = ImmutableList.of(STRING);
+  private static final ImmutableSet<String> IMMUTABLE_SET_STRING = ImmutableSet.of(STRING);
+  private static final ImmutableSortedSet<String> IMMUTABLE_SORTED_SET_STRING =
+      ImmutableSortedSet.of(STRING);
+  private static final ImmutableMultiset<String> IMMUTABLE_MULTISET_STRING =
+      ImmutableMultiset.of(STRING);
+  private static final ImmutableSortedMultiset<String> IMMUTABLE_SORTED_MULTISET_STRING =
+      ImmutableSortedMultiset.of(STRING);
+  private static final ImmutableBiMap<String, String> IMMUTABLE_BIMAP_STRING_TO_STRING =
+      ImmutableBiMap.of(STRING, STRING);
+  private static final Collection<String> COLLECTION_OF_STRING = ImmutableList.of(STRING);
+  private static final ImmutableCollection<String> IMMUTABLE_COLLECTION_OF_STRING =
+      ImmutableList.of(STRING);
   // private static final TestProto PROTO = TestProto.newBuilder().setText(STRING).build();
   // private static final List<TestProto> listOfProto = ImmutableList.of(PROTO);
   private static final String[] arrayOfString = new String[] {STRING};
@@ -147,7 +177,6 @@ public class TypesTest {
       new ParcelableContainingBinder();
   private final Drawable drawable = new BitmapDrawable(context.getResources(), bitmap);
 
-
   private final TestScheduledExecutorService scheduledExecutorService =
       new TestScheduledExecutorService();
   private final TestProfileConnector testProfileConnector =
@@ -402,10 +431,99 @@ public class TypesTest {
         .isEqualTo(IMMUTABLE_MAP_STRING_TO_STRING);
   }
 
+  @Test
+  public void immutableSortedMapReturnTypeAndArgument_bothWork()
+      throws UnavailableProfileException {
+    assertThat(
+            senderProvider
+                .provide(context, testProfileConnector)
+                .identityImmutableSortedMapMethod(IMMUTABLE_SORTED_MAP_STRING_TO_STRING))
+        .isEqualTo(IMMUTABLE_SORTED_MAP_STRING_TO_STRING);
+  }
+
+  @Test
+  public void immutableMultimapReturnTypeAndArgument_bothWork() throws UnavailableProfileException {
+    assertThat(
+            senderProvider
+                .provide(context, testProfileConnector)
+                .identityImmutableMultimapMethod(IMMUTABLE_MULTIMAP_STRING_TO_STRING))
+        .containsExactlyEntriesIn(IMMUTABLE_MULTIMAP_STRING_TO_STRING);
+  }
+
+  @Test
+  public void immutableSetMultimapReturnTypeAndArgument_bothWork()
+      throws UnavailableProfileException {
+    assertThat(
+            senderProvider
+                .provide(context, testProfileConnector)
+                .identityImmutableSetMultimapMethod(IMMUTABLE_SET_MULTIMAP_STRING_TO_STRING))
+        .isEqualTo(IMMUTABLE_SET_MULTIMAP_STRING_TO_STRING);
+  }
+
+  @Test
+  public void immutableListMultimapReturnTypeAndArgument_bothWork()
+      throws UnavailableProfileException {
+    assertThat(
+            senderProvider
+                .provide(context, testProfileConnector)
+                .identityImmutableListMultimapMethod(IMMUTABLE_LIST_MULTIMAP_STRING_TO_STRING))
+        .isEqualTo(IMMUTABLE_LIST_MULTIMAP_STRING_TO_STRING);
+  }
+
+  @Test
+  public void immutableListReturnTypeAndArgument_bothWork() throws UnavailableProfileException {
+    assertThat(
+            senderProvider
+                .provide(context, testProfileConnector)
+                .identityImmutableListMethod(IMMUTABLE_LIST_STRING))
+        .isEqualTo(IMMUTABLE_LIST_STRING);
+  }
+
+  @Test
+  public void immutableSetReturnTypeAndArgument_bothWork() throws UnavailableProfileException {
+    assertThat(
+            senderProvider
+                .provide(context, testProfileConnector)
+                .identityImmutableSetMethod(IMMUTABLE_SET_STRING))
+        .isEqualTo(IMMUTABLE_SET_STRING);
+  }
+
+  @Test
+  public void immutableMultisetReturnTypeAndArgument_bothWork() throws UnavailableProfileException {
+    assertThat(
+            senderProvider
+                .provide(context, testProfileConnector)
+                .identityImmutableMultisetMethod(IMMUTABLE_MULTISET_STRING))
+        .isEqualTo(IMMUTABLE_MULTISET_STRING);
+  }
+
+  @Test
+  public void immutableSortedMultisetReturnTypeAndArgument_bothWork()
+      throws UnavailableProfileException {
+    assertThat(
+            senderProvider
+                .provide(context, testProfileConnector)
+                .identityImmutableSortedMultisetMethod(IMMUTABLE_SORTED_MULTISET_STRING))
+        .isEqualTo(IMMUTABLE_SORTED_MULTISET_STRING);
+  }
+
+  @Test
+  public void immutableSortedSetReturnTypeAndArgument_bothWork()
+      throws UnavailableProfileException {
+    assertThat(
+            senderProvider
+                .provide(context, testProfileConnector)
+                .identityImmutableSortedSetMethod(IMMUTABLE_SORTED_SET_STRING))
+        .isEqualTo(IMMUTABLE_SORTED_SET_STRING);
+  }
+
   @Test
   public void setReturnTypeAndArgument_bothWork() throws UnavailableProfileException {
-    assertThat(senderProvider.provide(context, testProfileConnector).identitySetMethod(setOfString))
-        .isEqualTo(setOfString);
+    assertThat(
+            senderProvider
+                .provide(context, testProfileConnector)
+                .identitySetMethod(IMMUTABLE_SET_STRING))
+        .isEqualTo(IMMUTABLE_SET_STRING);
   }
 
   @Test
@@ -413,8 +531,27 @@ public class TypesTest {
     assertThat(
             senderProvider
                 .provide(context, testProfileConnector)
-                .identityCollectionMethod(collectionOfString))
-        .containsExactlyElementsIn(collectionOfString);
+                .identityCollectionMethod(COLLECTION_OF_STRING))
+        .containsExactlyElementsIn(COLLECTION_OF_STRING);
+  }
+
+  @Test
+  public void immutableCollectionReturnTypeAndArgument_bothWork()
+      throws UnavailableProfileException {
+    assertThat(
+            senderProvider
+                .provide(context, testProfileConnector)
+                .identityCollectionMethod(IMMUTABLE_COLLECTION_OF_STRING))
+        .containsExactlyElementsIn(IMMUTABLE_COLLECTION_OF_STRING);
+  }
+
+  @Test
+  public void immutableBiMapReturnTypeAndArgument_bothWork() throws UnavailableProfileException {
+    assertThat(
+            senderProvider
+                .provide(context, testProfileConnector)
+                .identityImmutableBiMapMethod(IMMUTABLE_BIMAP_STRING_TO_STRING))
+        .isEqualTo(IMMUTABLE_BIMAP_STRING_TO_STRING);
   }
 
   @Test
@@ -677,8 +814,11 @@ public class TypesTest {
 
   @Test
   public void parcelableArgumentAndReturnType_bothWork() throws UnavailableProfileException {
-    assertThat(senderProvider.provide(context, testProfileConnector)
-        .identityParcelableMethod((Parcelable) PARCELABLE)).isEqualTo(PARCELABLE);
+    assertThat(
+            senderProvider
+                .provide(context, testProfileConnector)
+                .identityParcelableMethod((Parcelable) PARCELABLE))
+        .isEqualTo(PARCELABLE);
   }
 
   @Test
@@ -716,14 +856,27 @@ public class TypesTest {
 
   @Test
   public void charSequenceReturnTypeAndArgument_bothWork() throws UnavailableProfileException {
-    assertThat(senderProvider.provide(context, testProfileConnector)
-                   .identityCharSequenceMethod(CHAR_SEQUENCE).toString())
+    assertThat(
+            senderProvider
+                .provide(context, testProfileConnector)
+                .identityCharSequenceMethod(CHAR_SEQUENCE)
+                .toString())
         .isEqualTo(CHAR_SEQUENCE.toString());
   }
 
+  @Test
+  public void nullCharSequenceReturnTypeAndArgument_bothWork() throws UnavailableProfileException {
+    assertThat(
+            senderProvider.provide(context, testProfileConnector).identityCharSequenceMethod(null))
+        .isEqualTo(null);
+  }
+
   @Test
   public void floatArrayReturnTypeAndArgument_bothWork() throws UnavailableProfileException {
-    assertThat(senderProvider.provide(context, testProfileConnector).identityFloatArrayMethod(FLOAT_ARRAY))
+    assertThat(
+            senderProvider
+                .provide(context, testProfileConnector)
+                .identityFloatArrayMethod(FLOAT_ARRAY))
         .isEqualTo(FLOAT_ARRAY);
   }
 
@@ -758,7 +911,10 @@ public class TypesTest {
 
   @Test
   public void shortArrayReturnTypeAndArgument_bothWork() throws UnavailableProfileException {
-    assertThat(senderProvider.provide(context, testProfileConnector).identityShortArrayMethod(SHORT_ARRAY))
+    assertThat(
+            senderProvider
+                .provide(context, testProfileConnector)
+                .identityShortArrayMethod(SHORT_ARRAY))
         .isEqualTo(SHORT_ARRAY);
   }
 
@@ -774,7 +930,8 @@ public class TypesTest {
 
   @Test
   public void intArrayReturnTypeAndArgument_bothWork() throws UnavailableProfileException {
-    assertThat(senderProvider.provide(context, testProfileConnector).identityIntArrayMethod(INT_ARRAY))
+    assertThat(
+            senderProvider.provide(context, testProfileConnector).identityIntArrayMethod(INT_ARRAY))
         .isEqualTo(INT_ARRAY);
   }
 
@@ -790,7 +947,10 @@ public class TypesTest {
 
   @Test
   public void longArrayReturnTypeAndArgument_bothWork() throws UnavailableProfileException {
-    assertThat(senderProvider.provide(context, testProfileConnector).identityLongArrayMethod(LONG_ARRAY))
+    assertThat(
+            senderProvider
+                .provide(context, testProfileConnector)
+                .identityLongArrayMethod(LONG_ARRAY))
         .isEqualTo(LONG_ARRAY);
   }
 
@@ -806,7 +966,10 @@ public class TypesTest {
 
   @Test
   public void doubleArrayReturnTypeAndArgument_bothWork() throws UnavailableProfileException {
-    assertThat(senderProvider.provide(context, testProfileConnector).identityDoubleArrayMethod(DOUBLE_ARRAY))
+    assertThat(
+            senderProvider
+                .provide(context, testProfileConnector)
+                .identityDoubleArrayMethod(DOUBLE_ARRAY))
         .isEqualTo(DOUBLE_ARRAY);
   }
 
@@ -822,7 +985,10 @@ public class TypesTest {
 
   @Test
   public void charArrayReturnTypeAndArgument_bothWork() throws UnavailableProfileException {
-    assertThat(senderProvider.provide(context, testProfileConnector).identityCharArrayMethod(CHAR_ARRAY))
+    assertThat(
+            senderProvider
+                .provide(context, testProfileConnector)
+                .identityCharArrayMethod(CHAR_ARRAY))
         .isEqualTo(CHAR_ARRAY);
   }
 
@@ -838,7 +1004,10 @@ public class TypesTest {
 
   @Test
   public void booleanArrayReturnTypeAndArgument_bothWork() throws UnavailableProfileException {
-    assertThat(senderProvider.provide(context, testProfileConnector).identityBooleanArrayMethod(BOOLEAN_ARRAY))
+    assertThat(
+            senderProvider
+                .provide(context, testProfileConnector)
+                .identityBooleanArrayMethod(BOOLEAN_ARRAY))
         .isEqualTo(BOOLEAN_ARRAY);
   }
 
@@ -863,8 +1032,9 @@ public class TypesTest {
   }
 
   private static int[] getDrawablePixels(Drawable drawable) {
-    Bitmap bitmap = Bitmap.createBitmap(
-        drawable.getIntrinsicWidth(), drawable.getIntrinsicHeight(), Bitmap.Config.ARGB_8888);
+    Bitmap bitmap =
+        Bitmap.createBitmap(
+            drawable.getIntrinsicWidth(), drawable.getIntrinsicHeight(), Bitmap.Config.ARGB_8888);
     drawable.draw(new Canvas(bitmap));
 
     int[] pixels = new int[bitmap.getHeight() * bitmap.getWidth()];
@@ -872,4 +1042,3 @@ public class TypesTest {
     return pixels;
   }
 }
-
diff --git a/tests/robotests/src/test/java/com/google/android/enterprise/connectedapps/robotests/UseCacheTest.java b/tests/robotests/src/test/java/com/google/android/enterprise/connectedapps/robotests/UseCacheTest.java
new file mode 100644
index 0000000..5e3e61d
--- /dev/null
+++ b/tests/robotests/src/test/java/com/google/android/enterprise/connectedapps/robotests/UseCacheTest.java
@@ -0,0 +1,68 @@
+package com.google.android.enterprise.connectedapps.robotests;
+
+import static com.google.android.enterprise.connectedapps.SharedTestUtilities.INTERACT_ACROSS_USERS;
+import static com.google.common.truth.Truth.assertThat;
+
+import android.app.Application;
+import android.app.Service;
+import android.os.Build.VERSION_CODES;
+import android.os.IBinder;
+import androidx.test.core.app.ApplicationProvider;
+import com.google.android.enterprise.connectedapps.RobolectricTestUtilities;
+import com.google.android.enterprise.connectedapps.TestScheduledExecutorService;
+import com.google.android.enterprise.connectedapps.exceptions.UnavailableProfileException;
+import com.google.android.enterprise.connectedapps.testapp.configuration.TestApplication;
+import com.google.android.enterprise.connectedapps.testapp.connector.TestProfileConnector;
+import com.google.android.enterprise.connectedapps.testapp.types.ProfileTestCrossProfileType;
+import com.google.android.enterprise.connectedapps.testapp.types.TestCrossProfileType;
+import org.junit.Before;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.robolectric.Robolectric;
+import org.robolectric.RobolectricTestRunner;
+import org.robolectric.annotation.Config;
+
+@RunWith(RobolectricTestRunner.class)
+@Config(minSdk = VERSION_CODES.O)
+public final class UseCacheTest {
+
+  private final Application context = ApplicationProvider.getApplicationContext();
+  private final TestScheduledExecutorService scheduledExecutorService =
+      new TestScheduledExecutorService();
+  private final TestProfileConnector testProfileConnector =
+      TestProfileConnector.create(context, scheduledExecutorService);
+  private final RobolectricTestUtilities testUtilities =
+      new RobolectricTestUtilities(testProfileConnector, scheduledExecutorService);
+  private final ProfileTestCrossProfileType profileTestCrossProfileType =
+      ProfileTestCrossProfileType.create(testProfileConnector);
+
+  @Before
+  public void setUp() {
+    Service profileAwareService = Robolectric.setupService(TestApplication.getService());
+    testUtilities.initTests();
+    IBinder binder = profileAwareService.onBind(/* intent= */ null);
+    testUtilities.setBinding(binder, RobolectricTestUtilities.TEST_CONNECTOR_CLASS_NAME);
+    testUtilities.createWorkUser();
+    testUtilities.turnOnWorkProfile();
+    testUtilities.setRunningOnPersonalProfile();
+    testUtilities.setRequestsPermissions(INTERACT_ACROSS_USERS);
+    testUtilities.grantPermissions(INTERACT_ACROSS_USERS);
+    testUtilities.addDefaultConnectionHolderAndWait();
+  }
+
+  @Test
+  public void useCache_cacheMiss_resultRetrievedFromOtherProfile()
+      throws UnavailableProfileException, InterruptedException {
+    // As there is nothing in the cache yet, calling useCache will result in a cache miss and
+    // should make a cross profile call to get the result.
+    // TODO(eliselliott) Clear the cache before calling this once the cache is implemented.
+    int result = profileTestCrossProfileType.other().useCache().getCacheableData();
+
+    assertThat(TestCrossProfileType.cacheableMethodCalls).isEqualTo(1);
+  }
+
+  @Test
+  public void useCache_cacheHit_resultRetrievedFromCache() {
+    // Cache not yet implemented.
+  }
+}
diff --git a/tests/shared/src/main/java/com/google/android/enterprise/connectedapps/testapp/types/TestCrossProfileType.java b/tests/shared/src/main/java/com/google/android/enterprise/connectedapps/testapp/types/TestCrossProfileType.java
index 1466ffd..cc6da85 100644
--- a/tests/shared/src/main/java/com/google/android/enterprise/connectedapps/testapp/types/TestCrossProfileType.java
+++ b/tests/shared/src/main/java/com/google/android/enterprise/connectedapps/testapp/types/TestCrossProfileType.java
@@ -25,6 +25,7 @@ import android.os.Handler;
 import android.os.Looper;
 import android.os.Parcelable;
 import android.util.Pair;
+import com.google.android.enterprise.connectedapps.annotations.Cacheable;
 import com.google.android.enterprise.connectedapps.annotations.CrossProfile;
 import com.google.android.enterprise.connectedapps.testapp.CustomError;
 import com.google.android.enterprise.connectedapps.testapp.CustomRuntimeException;
@@ -46,7 +47,18 @@ import com.google.android.enterprise.connectedapps.testapp.connector.TestProfile
 import com.google.android.enterprise.connectedapps.testapp.wrappers.ParcelableCustomWrapper2;
 import com.google.android.enterprise.connectedapps.testapp.wrappers.ParcelableStringWrapper;
 import com.google.common.base.Optional;
+import com.google.common.collect.ImmutableBiMap;
+import com.google.common.collect.ImmutableCollection;
+import com.google.common.collect.ImmutableList;
+import com.google.common.collect.ImmutableListMultimap;
 import com.google.common.collect.ImmutableMap;
+import com.google.common.collect.ImmutableMultimap;
+import com.google.common.collect.ImmutableMultiset;
+import com.google.common.collect.ImmutableSet;
+import com.google.common.collect.ImmutableSetMultimap;
+import com.google.common.collect.ImmutableSortedMap;
+import com.google.common.collect.ImmutableSortedMultiset;
+import com.google.common.collect.ImmutableSortedSet;
 import com.google.common.util.concurrent.Futures;
 import com.google.common.util.concurrent.ListenableFuture;
 import com.google.common.util.concurrent.SettableFuture;
@@ -184,7 +196,6 @@ public class TestCrossProfileType {
             TimeUnit.SECONDS.toMillis(secondsDelay));
   }
 
-
   @CrossProfile
   public void asyncVoidMethod(TestVoidCallbackListener callback) {
     voidMethod();
@@ -411,6 +422,56 @@ public class TestCrossProfileType {
     return m;
   }
 
+  @CrossProfile
+  public ImmutableSortedMap<String, String> identityImmutableSortedMapMethod(
+      ImmutableSortedMap<String, String> m) {
+    return m;
+  }
+
+  @CrossProfile
+  public ImmutableMultimap<String, String> identityImmutableMultimapMethod(
+      ImmutableMultimap<String, String> m) {
+    return m;
+  }
+
+  @CrossProfile
+  public ImmutableSetMultimap<String, String> identityImmutableSetMultimapMethod(
+      ImmutableSetMultimap<String, String> m) {
+    return m;
+  }
+
+  @CrossProfile
+  public ImmutableListMultimap<String, String> identityImmutableListMultimapMethod(
+      ImmutableListMultimap<String, String> m) {
+    return m;
+  }
+
+  @CrossProfile
+  public ImmutableList<String> identityImmutableListMethod(ImmutableList<String> l) {
+    return l;
+  }
+
+  @CrossProfile
+  public ImmutableSet<String> identityImmutableSetMethod(ImmutableSet<String> s) {
+    return s;
+  }
+
+  @CrossProfile
+  public ImmutableSortedSet<String> identityImmutableSortedSetMethod(ImmutableSortedSet<String> s) {
+    return s;
+  }
+
+  @CrossProfile
+  public ImmutableMultiset<String> identityImmutableMultisetMethod(ImmutableMultiset<String> s) {
+    return s;
+  }
+
+  @CrossProfile
+  public ImmutableSortedMultiset<String> identityImmutableSortedMultisetMethod(
+      ImmutableSortedMultiset<String> s) {
+    return s;
+  }
+
   // @CrossProfile
   // public TestProto identityProtoMethod(TestProto p) {
   //   return p;
@@ -426,6 +487,17 @@ public class TestCrossProfileType {
     return c;
   }
 
+  @CrossProfile
+  public ImmutableCollection<String> identitySortedCollectionMethod(ImmutableCollection<String> c) {
+    return c;
+  }
+
+  @CrossProfile
+  public ImmutableBiMap<String, String> identityImmutableBiMapMethod(
+      ImmutableBiMap<String, String> m) {
+    return m;
+  }
+
   @CrossProfile
   public List<ParcelableObject> identityParcelableWrapperOfParcelableMethod(
       List<ParcelableObject> l) {
@@ -596,8 +668,7 @@ public class TestCrossProfileType {
   }
 
   @CrossProfile
-  public String identityStringMethodThrowsIOException(String s)
-      throws IOException {
+  public String identityStringMethodThrowsIOException(String s) throws IOException {
     throw new IOException("Requested to throw");
   }
 
@@ -703,4 +774,13 @@ public class TestCrossProfileType {
   public Drawable identityDrawableMethod(Drawable d) {
     return d;
   }
+
+  public static int cacheableMethodCalls = 0;
+
+  @CrossProfile
+  @Cacheable
+  public int getCacheableData() {
+    cacheableMethodCalls++;
+    return 123;
+  }
 }
```

