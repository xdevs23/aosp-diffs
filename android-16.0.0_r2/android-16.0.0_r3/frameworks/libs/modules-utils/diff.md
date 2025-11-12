```diff
diff --git a/TEST_MAPPING b/TEST_MAPPING
index 41c2c80..f088c30 100644
--- a/TEST_MAPPING
+++ b/TEST_MAPPING
@@ -17,6 +17,9 @@
     {
       "name": "ModulesUtilsTests"
     },
+    {
+      "name": "ComposHostTestCases"
+    },
     {
       // b/255344517: The binary XML tests currently lives in frameworks/base.
       "name": "FrameworksCoreTests",
@@ -51,12 +54,5 @@
       // Unit tests for service-wifi.jar
       "name": "FrameworksWifiTests"
     }
-  ],
-  // Run these on real devices in postsubmit while they're
-  // flakey on Cuttlefish. TODO(b/264496291): Fix this.
-  "avf-postsubmit": [
-    {
-        "name": "ComposHostTestCases"
-    }
   ]
 }
diff --git a/java/Android.bp b/java/Android.bp
index b1445d1..03562ea 100644
--- a/java/Android.bp
+++ b/java/Android.bp
@@ -21,8 +21,8 @@ filegroup {
     name: "framework-annotations",
     srcs: [
         ":framework-metalava-annotations",
+        ":ravenwood-annotations",
         "com/android/internal/annotations/*.java",
-        "android/ravenwood/annotation/*.java",
     ],
 
     // This list is intentionally restricted, with few exceptions.
@@ -46,6 +46,16 @@ filegroup {
     ],
 }
 
+filegroup {
+    name: "ravenwood-annotations",
+    srcs: [
+        "android/ravenwood/annotation/*.java",
+    ],
+    visibility: [
+        "//visibility:public",
+    ],
+}
+
 java_library {
     name: "framework-annotations-lib",
     srcs: [":framework-annotations"],
@@ -93,6 +103,16 @@ java_library {
     patch_module: "java.base",
 }
 
+java_library {
+    name: "ravenwood-annotations-lib",
+    srcs: [":ravenwood-annotations"],
+    sdk_version: "core_current",
+    host_supported: true,
+    visibility: [
+        "//visibility:public",
+    ],
+}
+
 filegroup {
     name: "framework-api-annotations",
     srcs: [
diff --git a/java/android/annotation/DeprecatedForSdk.java b/java/android/annotation/DeprecatedForSdk.java
deleted file mode 100644
index bbd0a2c..0000000
--- a/java/android/annotation/DeprecatedForSdk.java
+++ /dev/null
@@ -1,54 +0,0 @@
-/*
- * Copyright (C) 2022 The Android Open Source Project
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
-package android.annotation;
-
-import static java.lang.annotation.ElementType.CONSTRUCTOR;
-import static java.lang.annotation.ElementType.FIELD;
-import static java.lang.annotation.ElementType.LOCAL_VARIABLE;
-import static java.lang.annotation.ElementType.METHOD;
-import static java.lang.annotation.ElementType.PACKAGE;
-import static java.lang.annotation.ElementType.PARAMETER;
-import static java.lang.annotation.ElementType.TYPE;
-import static java.lang.annotation.RetentionPolicy.SOURCE;
-
-import java.lang.annotation.Retention;
-import java.lang.annotation.Target;
-
-/**
- * The annotated element is considered deprecated in the public SDK. This will be turned into a
- * plain &#64;Deprecated annotation in the SDK.
- *
- * <p>The value parameter should be the message to include in the documentation as a &#64;deprecated
- * comment.
- *
- * @hide
- */
-@Retention(SOURCE)
-@Target(value = {CONSTRUCTOR, FIELD, LOCAL_VARIABLE, METHOD, PACKAGE, PARAMETER, TYPE})
-public @interface DeprecatedForSdk {
-    /**
-     * The message to include in the documentation, which will be merged in as a &#64;deprecated
-     * tag.
-     */
-    String value();
-
-    /**
-     * If specified, one or more annotation classes corresponding to particular API surfaces where
-     * the API will <b>not</b> be marked as deprecated, such as {@link SystemApi} or {@link
-     * TestApi}.
-     */
-    Class<?>[] allowIn() default {};
-}
diff --git a/java/android/annotation/OWNERS b/java/android/annotation/OWNERS
index 853c090..1fae66b 100644
--- a/java/android/annotation/OWNERS
+++ b/java/android/annotation/OWNERS
@@ -1,2 +1,4 @@
 tnorbye@google.com
 aurimas@google.com
+
+per-file *User* = file:platform/frameworks/base:/MULTIUSER_OWNERS
diff --git a/java/android/annotation/RestrictedForEnvironment.java b/java/android/annotation/RestrictedForEnvironment.java
index d471f5e..7c73b8c 100644
--- a/java/android/annotation/RestrictedForEnvironment.java
+++ b/java/android/annotation/RestrictedForEnvironment.java
@@ -46,26 +46,32 @@ import java.lang.annotation.Target;
 public @interface RestrictedForEnvironment {
 
     /** List of environments where the entity is restricted. */
-    Environment[] environments();
+    @Environment String[] environments();
 
     /**
      * SDK version since when the restriction started.
      *
+     * <p>
      * Possible values are defined in {@link android.os.Build.VERSION_CODES}.
+     * </p>
      */
     int from();
 
-    enum Environment {
-        /**
-         * See {@link android.app.sdksandbox.SdkSandboxManager}
-         */
-        SDK_SANDBOX {
-            @Override
-            public String toString() {
-                return "SDK Runtime";
-            }
-        }
-    }
+    /**
+     * See {@link android.app.sdksandbox.SdkSandboxManager}
+     */
+    String ENVIRONMENT_SDK_RUNTIME = "SDK Runtime";
+
+    /**
+     * All possible environments supported by this annotation.
+     *
+     * @hide
+     */
+    @StringDef(prefix = "ENVIRONMENT_", value = {
+            ENVIRONMENT_SDK_RUNTIME
+    })
+    @Retention(RetentionPolicy.SOURCE)
+    @interface Environment {}
 
     /**
      * Container for {@link RestrictedForEnvironment} that allows it to be applied repeatedly to
diff --git a/java/android/annotation/SpecialUsers.java b/java/android/annotation/SpecialUsers.java
index 7e47717..527e7e8 100644
--- a/java/android/annotation/SpecialUsers.java
+++ b/java/android/annotation/SpecialUsers.java
@@ -76,7 +76,7 @@ public @interface SpecialUsers {
      */
     @Retention(SOURCE)
     @Target({TYPE, TYPE_USE, FIELD, METHOD, PARAMETER, LOCAL_VARIABLE, ANNOTATION_TYPE})
-    @CanBeUsers(specialUsersAllowed = {SpecialUser.USER_ALL})
+    @CanBeUsers({SpecialUser.USER_ALL})
     public @interface CanBeALL {
     }
 
@@ -87,10 +87,24 @@ public @interface SpecialUsers {
      */
     @Retention(SOURCE)
     @Target({TYPE, TYPE_USE, FIELD, METHOD, PARAMETER, LOCAL_VARIABLE, ANNOTATION_TYPE})
-    @CanBeUsers(specialUsersAllowed = {SpecialUser.USER_CURRENT})
+    @CanBeUsers({SpecialUser.USER_CURRENT})
     public @interface CanBeCURRENT {
     }
 
+    /**
+     * Indication that a {@link android.os.UserHandle} or {@link UserIdInt} can be
+     * {@link android.os.UserHandle#CURRENT_OR_SELF} and
+     * {@link android.os.UserHandle#USER_CURRENT_OR_SELF}, respectively.
+     *
+     * TODO(b/373455030): Annotate places that accept this. Lack of this annotation doesn't
+     *                    currently mean anything since we haven't added it much.
+     */
+    @Retention(SOURCE)
+    @Target({TYPE, TYPE_USE, FIELD, METHOD, PARAMETER, LOCAL_VARIABLE, ANNOTATION_TYPE})
+    @CanBeUsers({SpecialUser.USER_CURRENT_OR_SELF})
+    public @interface CanBeCURRENT_OR_SELF {
+    }
+
     /**
      * Indication that a {@link android.os.UserHandle} or {@link UserIdInt} can be
      * {@link android.os.UserHandle#NULL} and {@link android.os.UserHandle#USER_NULL}, respectively.
@@ -98,7 +112,7 @@ public @interface SpecialUsers {
      */
     @Retention(SOURCE)
     @Target({TYPE, TYPE_USE, FIELD, METHOD, PARAMETER, LOCAL_VARIABLE, ANNOTATION_TYPE})
-    @CanBeUsers(specialUsersAllowed = {SpecialUser.USER_NULL})
+    @CanBeUsers({SpecialUser.USER_NULL})
     public @interface CanBeNULL {
     }
 
@@ -108,7 +122,7 @@ public @interface SpecialUsers {
      */
     @Retention(SOURCE)
     @Target({TYPE, TYPE_USE, FIELD, METHOD, PARAMETER, LOCAL_VARIABLE, ANNOTATION_TYPE})
-    @CanBeUsers(specialUsersAllowed = {SpecialUser.DISALLOW_EVERY})
+    @CanBeUsers({SpecialUser.DISALLOW_EVERY})
     public @interface CannotBeSpecialUser {
     }
 
@@ -121,6 +135,6 @@ public @interface SpecialUsers {
     @Target({TYPE, TYPE_USE, FIELD, METHOD, PARAMETER, LOCAL_VARIABLE, ANNOTATION_TYPE})
     public @interface CanBeUsers {
         /** Specify which types of {@link SpecialUser}s are allowed. For use in advanced cases.  */
-        SpecialUser[] specialUsersAllowed() default {SpecialUser.UNSPECIFIED};
+        SpecialUser[] value() default {SpecialUser.UNSPECIFIED};
     }
 }
diff --git a/java/android/ravenwood/annotation/RavenwoodClassLoadHook.java b/java/android/ravenwood/annotation/RavenwoodClassLoadHook.java
index c47aa94..4be38c9 100644
--- a/java/android/ravenwood/annotation/RavenwoodClassLoadHook.java
+++ b/java/android/ravenwood/annotation/RavenwoodClassLoadHook.java
@@ -44,4 +44,7 @@ public @interface RavenwoodClassLoadHook {
      */
     public static String LIBANDROID_LOADING_HOOK
             = "com.android.platform.test.ravenwood.runtimehelper.ClassLoadHook.onClassLoaded";
+
+    /** Optional, human-readable comment */
+    String comment() default "";
 }
diff --git a/java/android/ravenwood/annotation/RavenwoodIgnore.java b/java/android/ravenwood/annotation/RavenwoodIgnore.java
index 775cfab..8c5ed2a 100644
--- a/java/android/ravenwood/annotation/RavenwoodIgnore.java
+++ b/java/android/ravenwood/annotation/RavenwoodIgnore.java
@@ -48,4 +48,7 @@ public @interface RavenwoodIgnore {
      * Tracking bug number, if any.
      */
     long bug() default 0;
+
+    /** Optional, human-readable comment */
+    String comment() default "";
 }
diff --git a/java/android/ravenwood/annotation/RavenwoodKeep.java b/java/android/ravenwood/annotation/RavenwoodKeep.java
index 52c3b70..4caea9e 100644
--- a/java/android/ravenwood/annotation/RavenwoodKeep.java
+++ b/java/android/ravenwood/annotation/RavenwoodKeep.java
@@ -35,4 +35,6 @@ import java.lang.annotation.Target;
 @Target({FIELD, METHOD, CONSTRUCTOR})
 @Retention(RetentionPolicy.CLASS)
 public @interface RavenwoodKeep {
+    /** Optional, human-readable comment */
+    String comment() default "";
 }
diff --git a/java/android/ravenwood/annotation/RavenwoodKeepPartialClass.java b/java/android/ravenwood/annotation/RavenwoodKeepPartialClass.java
index 61bb613..ffe6ba0 100644
--- a/java/android/ravenwood/annotation/RavenwoodKeepPartialClass.java
+++ b/java/android/ravenwood/annotation/RavenwoodKeepPartialClass.java
@@ -35,4 +35,6 @@ import java.lang.annotation.Target;
 @Target(ElementType.TYPE)
 @Retention(RetentionPolicy.CLASS)
 public @interface RavenwoodKeepPartialClass {
+    /** Optional, human-readable comment */
+    String comment() default "";
 }
diff --git a/java/android/ravenwood/annotation/RavenwoodKeepStaticInitializer.java b/java/android/ravenwood/annotation/RavenwoodKeepStaticInitializer.java
index abd1074..793f7dd 100644
--- a/java/android/ravenwood/annotation/RavenwoodKeepStaticInitializer.java
+++ b/java/android/ravenwood/annotation/RavenwoodKeepStaticInitializer.java
@@ -34,4 +34,6 @@ import java.lang.annotation.Target;
 @Target(TYPE)
 @Retention(RetentionPolicy.CLASS)
 public @interface RavenwoodKeepStaticInitializer {
+    /** Optional, human-readable comment */
+    String comment() default "";
 }
diff --git a/java/android/ravenwood/annotation/RavenwoodKeepWholeClass.java b/java/android/ravenwood/annotation/RavenwoodKeepWholeClass.java
index 7310b4b..3a27e54 100644
--- a/java/android/ravenwood/annotation/RavenwoodKeepWholeClass.java
+++ b/java/android/ravenwood/annotation/RavenwoodKeepWholeClass.java
@@ -37,4 +37,6 @@ import java.lang.annotation.Target;
 @Target({TYPE, FIELD, METHOD, CONSTRUCTOR})
 @Retention(RetentionPolicy.CLASS)
 public @interface RavenwoodKeepWholeClass {
+    /** Optional, human-readable comment */
+    String comment() default "";
 }
diff --git a/java/android/ravenwood/annotation/RavenwoodPartiallyAllowlisted.java b/java/android/ravenwood/annotation/RavenwoodPartiallyAllowlisted.java
index 166db7b..939790d 100644
--- a/java/android/ravenwood/annotation/RavenwoodPartiallyAllowlisted.java
+++ b/java/android/ravenwood/annotation/RavenwoodPartiallyAllowlisted.java
@@ -35,4 +35,6 @@ import java.lang.annotation.Target;
 @Target({TYPE})
 @Retention(RetentionPolicy.CLASS)
 public @interface RavenwoodPartiallyAllowlisted {
+    /** Optional, human-readable comment */
+    String comment() default "";
 }
diff --git a/java/android/ravenwood/annotation/RavenwoodRedirect.java b/java/android/ravenwood/annotation/RavenwoodRedirect.java
index aae4c3c..f82a25c 100644
--- a/java/android/ravenwood/annotation/RavenwoodRedirect.java
+++ b/java/android/ravenwood/annotation/RavenwoodRedirect.java
@@ -67,4 +67,6 @@ import java.lang.annotation.Target;
 @Target({METHOD})
 @Retention(RetentionPolicy.CLASS)
 public @interface RavenwoodRedirect {
+    /** Optional, human-readable comment */
+    String comment() default "";
 }
diff --git a/java/android/ravenwood/annotation/RavenwoodRedirectionClass.java b/java/android/ravenwood/annotation/RavenwoodRedirectionClass.java
index bb8bddb..553f2dc 100644
--- a/java/android/ravenwood/annotation/RavenwoodRedirectionClass.java
+++ b/java/android/ravenwood/annotation/RavenwoodRedirectionClass.java
@@ -36,4 +36,7 @@ import java.lang.annotation.Target;
 @Retention(RetentionPolicy.CLASS)
 public @interface RavenwoodRedirectionClass {
     String value();
+
+    /** Optional, human-readable comment */
+    String comment() default "";
 }
diff --git a/java/android/ravenwood/annotation/RavenwoodRemove.java b/java/android/ravenwood/annotation/RavenwoodRemove.java
index db41a2a..7b7ffeb 100644
--- a/java/android/ravenwood/annotation/RavenwoodRemove.java
+++ b/java/android/ravenwood/annotation/RavenwoodRemove.java
@@ -54,4 +54,7 @@ public @interface RavenwoodRemove {
      * Tracking bug number, if any.
      */
     long bug() default 0;
+
+    /** Optional, human-readable comment */
+    String comment() default "";
 }
diff --git a/java/android/ravenwood/annotation/RavenwoodReplace.java b/java/android/ravenwood/annotation/RavenwoodReplace.java
index 197f65f..3487966 100644
--- a/java/android/ravenwood/annotation/RavenwoodReplace.java
+++ b/java/android/ravenwood/annotation/RavenwoodReplace.java
@@ -66,4 +66,7 @@ public @interface RavenwoodReplace {
      * Tracking bug number, if any.
      */
     long bug() default 0;
+
+    /** Optional, human-readable comment */
+    String comment() default "";
 }
diff --git a/java/android/ravenwood/annotation/RavenwoodSupported.java b/java/android/ravenwood/annotation/RavenwoodSupported.java
new file mode 100644
index 0000000..37d86c3
--- /dev/null
+++ b/java/android/ravenwood/annotation/RavenwoodSupported.java
@@ -0,0 +1,80 @@
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
+package android.ravenwood.annotation;
+
+import static java.lang.annotation.ElementType.METHOD;
+import static java.lang.annotation.ElementType.TYPE;
+
+import java.lang.annotation.Retention;
+import java.lang.annotation.RetentionPolicy;
+import java.lang.annotation.Target;
+
+/**
+ * Denotes that the annotated method is supported on Ravenwood with a subclass in the ravenwood
+ * runtime.
+ *
+ * For example, most of the {@link android.content.Context} class is supported via
+ * the {@code RavenwoodContext} class in the ravenwood runtime.
+ *
+ * Note, this annotation is purely for documentation and for the dashboard.
+ *
+ * The annotations are validated by
+ * {@code com.android.ravenwoodtest.coretest.RavenwoodSupportedAnnotationTest}.
+ *
+ * TODO: Make it work class-wide too.
+ *
+ * @hide
+ */
+@Target({METHOD})
+@Retention(RetentionPolicy.CLASS)
+public @interface RavenwoodSupported {
+    enum SupportType {
+        OTHER,
+        /**
+         * The API is supported by a subclass in ravenwood-runtime.
+         * {@link #subclass} should contain the name of the class.
+         */
+        SUBCLASS,
+    }
+
+    /** How the API is supported. */
+    SupportType type();
+
+    /** If it's implemented by a subclass, then its name. */
+    String subclass() default "";
+
+    /** Optional, human-readable comment */
+    String comment() default "";
+
+    /**
+     * Tracking bug number, if any.
+     */
+    long bug() default 0;
+
+    /**
+     * A marker annotation for a class that provides implementation for {@link RavenwoodSupported}
+     * methods. It's just for documentation and doesn't do anything at runtime.
+     */
+    @Target({TYPE})
+    @Retention(RetentionPolicy.RUNTIME)
+    @interface RavenwoodProvidingImplementation {
+        /** Target class that has methods that are implemented by this class. */
+        Class<?> target();
+
+        /** Optional, human-readable comment */
+        String comment() default "";
+    }
+}
diff --git a/java/android/ravenwood/annotation/RavenwoodThrow.java b/java/android/ravenwood/annotation/RavenwoodThrow.java
index 4cc9d1c..68cda18 100644
--- a/java/android/ravenwood/annotation/RavenwoodThrow.java
+++ b/java/android/ravenwood/annotation/RavenwoodThrow.java
@@ -30,7 +30,7 @@ import java.lang.annotation.Target;
  * will throw a runtime exception with a message indicating that the method is unsupported
  * on Ravenwood.
  *
- * TODO: Create "whole-class-throw"?
+ * TODO: Make it work class-wide too.
  *
  * @hide
  */
@@ -51,4 +51,7 @@ public @interface RavenwoodThrow {
      * Tracking bug number, if any.
      */
     long bug() default 0;
+
+    /** Optional, human-readable comment */
+    String comment() default "";
 }
diff --git a/java/com/android/internal/annotations/CachedProperty.java b/java/com/android/internal/annotations/CachedProperty.java
index b2eb51b..52a26b1 100644
--- a/java/com/android/internal/annotations/CachedProperty.java
+++ b/java/com/android/internal/annotations/CachedProperty.java
@@ -69,4 +69,10 @@ public @interface CachedProperty {
    * Specify modifiers for generating cached property. By default it will be static property.
    */
   CacheModifier[] mods() default { CacheModifier.STATIC };
+
+  /**
+   * Specifies whether null values should be cached or not. By default, it is false.
+   * @return true if null values should be cached; false otherwise
+   */
+  boolean cacheNulls() default false;
 }
diff --git a/java/com/android/internal/annotations/CachedPropertyDefaults.java b/java/com/android/internal/annotations/CachedPropertyDefaults.java
index 435c82b..897ebb3 100644
--- a/java/com/android/internal/annotations/CachedPropertyDefaults.java
+++ b/java/com/android/internal/annotations/CachedPropertyDefaults.java
@@ -46,4 +46,10 @@ public @interface CachedPropertyDefaults {
    * The default number of entries in the {@link android.os.IpcDataCache}.
    */
   int max() default 32;
+
+  /**
+   * The name of the cache of the {@link android.os.IpcDataCache}. By default, the cache name is
+   * <ClassName> + Cache
+   */
+  String name() default "";
 }
diff --git a/java/com/android/internal/util/Preconditions.java b/java/com/android/internal/util/Preconditions.java
index 894f61c..f689bc5 100644
--- a/java/com/android/internal/util/Preconditions.java
+++ b/java/com/android/internal/util/Preconditions.java
@@ -24,6 +24,8 @@ import android.os.Build;
 import android.text.TextUtils;
 
 import com.google.errorprone.annotations.CompileTimeConstant;
+import com.google.errorprone.annotations.FormatMethod;
+import com.google.errorprone.annotations.FormatString;
 
 import java.util.Arrays;
 import java.util.Collection;
@@ -74,9 +76,10 @@ public class Preconditions {
      * @param messageArgs arguments for {@code messageTemplate}
      * @throws IllegalArgumentException if {@code expression} is false
      */
+    @FormatMethod
     public static void checkArgument(
             final boolean expression,
-            final @CompileTimeConstant @NonNull String messageTemplate,
+            final @FormatString @CompileTimeConstant String messageTemplate,
             final Object... messageArgs) {
         if (!expression) {
             throw new IllegalArgumentException(String.format(messageTemplate, messageArgs));
@@ -126,9 +129,10 @@ public class Preconditions {
      * @return the string reference that was validated
      * @throws IllegalArgumentException if {@code string} is empty
      */
+    @FormatMethod
     public static @NonNull <T extends CharSequence> T checkStringNotEmpty(
             final T string,
-            final @NonNull @CompileTimeConstant String messageTemplate,
+            final @FormatString @CompileTimeConstant String messageTemplate,
             final Object... messageArgs) {
         if (TextUtils.isEmpty(string)) {
             throw new IllegalArgumentException(String.format(messageTemplate, messageArgs));
@@ -185,9 +189,10 @@ public class Preconditions {
      * @param messageArgs arguments for {@code messageTemplate}
      * @throws NullPointerException if {@code reference} is null
      */
+    @FormatMethod
     public static @NonNull <T> T checkNotNull(
             final T reference,
-            final @NonNull @CompileTimeConstant String messageTemplate,
+            final @FormatString @CompileTimeConstant String messageTemplate,
             final Object... messageArgs) {
         if (reference == null) {
             throw new NullPointerException(String.format(messageTemplate, messageArgs));
@@ -233,9 +238,10 @@ public class Preconditions {
      * @param messageArgs arguments for {@code messageTemplate}
      * @throws IllegalStateException if {@code expression} is false
      */
+    @FormatMethod
     public static void checkState(
             final boolean expression,
-            final @NonNull @CompileTimeConstant String messageTemplate,
+            final @FormatString @CompileTimeConstant String messageTemplate,
             final Object... messageArgs) {
         if (!expression) {
             throw new IllegalStateException(String.format(messageTemplate, messageArgs));
@@ -279,9 +285,10 @@ public class Preconditions {
      * @param messageArgs arguments for {@code messageTemplate}
      * @throws SecurityException if {@code expression} is false
      */
+    @FormatMethod
     public static void checkCallAuthorization(
             final boolean expression,
-            final @NonNull @CompileTimeConstant String messageTemplate,
+            final @FormatString @CompileTimeConstant String messageTemplate,
             final Object... messageArgs) {
         if (!expression) {
             throw new SecurityException(String.format(messageTemplate, messageArgs));
diff --git a/java/com/android/modules/expresslog/Android.bp b/java/com/android/modules/expresslog/Android.bp
index fec346c..2cccf9f 100644
--- a/java/com/android/modules/expresslog/Android.bp
+++ b/java/com/android/modules/expresslog/Android.bp
@@ -26,6 +26,7 @@ java_library {
         ":statslog-expresslog-java-gen",
     ],
     libs: [
+        "androidx.annotation_annotation",
         "framework-statsd.stubs.module_lib",
     ],
     static_libs: [
diff --git a/java/com/android/modules/expresslog/OWNERS b/java/com/android/modules/expresslog/OWNERS
index d3a5812..f21ae84 100644
--- a/java/com/android/modules/expresslog/OWNERS
+++ b/java/com/android/modules/expresslog/OWNERS
@@ -6,5 +6,4 @@ muhammadq@google.com
 rslawik@google.com
 sharaienko@google.com
 singhtejinder@google.com
-tsaichristine@google.com
 yaochen@google.com
diff --git a/java/com/android/modules/utils/ravenwood/Android.bp b/java/com/android/modules/utils/ravenwood/Android.bp
new file mode 100644
index 0000000..023f118
--- /dev/null
+++ b/java/com/android/modules/utils/ravenwood/Android.bp
@@ -0,0 +1,12 @@
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+java_library {
+    name: "modules-utils-ravenwood",
+    srcs: ["*.java"],
+    libs: [
+        "ravenwood-annotations-lib",
+    ],
+    defaults: ["modules-utils-defaults"],
+}
diff --git a/java/com/android/modules/utils/ravenwood/RavenwoodHelper.java b/java/com/android/modules/utils/ravenwood/RavenwoodHelper.java
new file mode 100644
index 0000000..91b2508
--- /dev/null
+++ b/java/com/android/modules/utils/ravenwood/RavenwoodHelper.java
@@ -0,0 +1,85 @@
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
+package com.android.modules.utils.ravenwood;
+
+import java.util.Objects;
+
+/**
+ * Class containing constants used by Ravenwood, and accessors to them.
+ */
+@android.ravenwood.annotation.RavenwoodKeepWholeClass
+public class RavenwoodHelper {
+    private RavenwoodHelper() {
+    }
+
+    private static void throwIfCalledOnDevice() {
+        if (!isRunningOnRavenwood()) {
+            throw new UnsupportedOperationException("This method can only be used on Ravenwood");
+        }
+    }
+
+    /**
+     * USE IT SPARINGLY! Returns true if it's running on Ravenwood, hostside test environment.
+     *
+     * <p>Using this allows code to behave differently on a real device and on Ravenwood, but
+     * generally speaking, that's a bad idea because we want the test target code to behave
+     * differently.
+     *
+     * <p>This should be only used when different behavior is absolutely needed.
+     *
+     * <p>If someone needs it without having access to the SDK, the following hack would work too.
+     * <code>System.getProperty("android.ravenwood.version") != null</code>
+     */
+    public static boolean isRunningOnRavenwood() {
+        return System.getProperty(RavenwoodInternal.RAVENWOOD_VERSION_JAVA_SYSPROP) != null;
+    }
+
+    /**
+     * @return the directory path containing the ravenwood runtime.
+     *
+     * @throws UnsupportedOperationException if called on a non-ravenwood environment
+     */
+    public static String getRavenwoodRuntimePath() {
+        throwIfCalledOnDevice();
+        return Objects.requireNonNull(
+                System.getProperty(RavenwoodInternal.RAVENWOOD_RUNTIME_PATH_JAVA_SYSPROP),
+                        "Ravenwood runtime path not set. (called outside of Ravenwood?)");
+    }
+
+    /**
+     * @return the directory path containing the aconfig storage files.
+     *
+     * @throws UnsupportedOperationException if called on a non-ravenwood environment
+     */
+    public static String getRavenwoodAconfigStoragePath() {
+        throwIfCalledOnDevice();
+        return getRavenwoodRuntimePath() + "/aconfig";
+    }
+
+    /**
+     * DO NOT use this class directly from outside the Ravenwood core classes.
+     */
+    public static class RavenwoodInternal {
+        private RavenwoodInternal() {
+        }
+
+        public static final String RAVENWOOD_VERSION_JAVA_SYSPROP = "android.ravenwood.version";
+
+        public static final String RAVENWOOD_RUNTIME_PATH_JAVA_SYSPROP =
+                "android.ravenwood.runtime_path";
+
+    }
+}
diff --git a/javatests/android/annotation/RestrictedForEnvironmentTests.java b/javatests/android/annotation/RestrictedForEnvironmentTests.java
index 9ab45f8..10746d7 100644
--- a/javatests/android/annotation/RestrictedForEnvironmentTests.java
+++ b/javatests/android/annotation/RestrictedForEnvironmentTests.java
@@ -16,9 +16,9 @@
 
 package android.annotation;
 
-import static com.google.common.truth.Truth.assertThat;
+import static android.annotation.RestrictedForEnvironment.ENVIRONMENT_SDK_RUNTIME;
 
-import android.annotation.RestrictedForEnvironment.Environment;
+import static com.google.common.truth.Truth.assertThat;
 
 import org.junit.Test;
 import org.junit.runner.RunWith;
@@ -51,44 +51,33 @@ public class RestrictedForEnvironmentTests {
         RestrictedForEnvironment annotation = clz.getClass().getAnnotation(
                 RestrictedForEnvironment.class);
 
-        Environment[] e = annotation.environments();
-        assertThat(e).asList().containsExactly(Environment.SDK_SANDBOX);
+        String[] e = annotation.environments();
+        assertThat(e).asList().containsExactly(ENVIRONMENT_SDK_RUNTIME);
         int from = annotation.from();
         assertThat(from).isEqualTo(33);
     }
 
-    @Test
-    public void testAnnotationParameters_environmentToString() throws Exception {
-        ClassWithAnnotation clz = new ClassWithAnnotation();
-        RestrictedForEnvironment annotation = clz.getClass().getAnnotation(
-                RestrictedForEnvironment.class);
-
-        Environment e = annotation.environments()[0];
-        assertThat(e).isEqualTo(Environment.SDK_SANDBOX);
-        assertThat(e.toString()).isEqualTo("SDK Runtime");
-    }
-
     @Test
     public void testAnnotationParameters_environment_multipleEnvironments() throws Exception {
         ClassWithMultipleEnvironment clz = new ClassWithMultipleEnvironment();
         RestrictedForEnvironment annotation = clz.getClass().getAnnotation(
                 RestrictedForEnvironment.class);
 
-        Environment[] e = annotation.environments();
-        assertThat(e).asList().containsExactly(Environment.SDK_SANDBOX, Environment.SDK_SANDBOX);
+        String[] e = annotation.environments();
+        assertThat(e).asList().containsExactly(ENVIRONMENT_SDK_RUNTIME, ENVIRONMENT_SDK_RUNTIME);
     }
 
-    @RestrictedForEnvironment(environments=Environment.SDK_SANDBOX, from=33)
+    @RestrictedForEnvironment(environments=ENVIRONMENT_SDK_RUNTIME, from=33)
     private static class ClassWithAnnotation {
     }
 
-    @RestrictedForEnvironment(environments=Environment.SDK_SANDBOX, from=0)
-    @RestrictedForEnvironment(environments=Environment.SDK_SANDBOX, from=0)
+    @RestrictedForEnvironment(environments=ENVIRONMENT_SDK_RUNTIME, from=0)
+    @RestrictedForEnvironment(environments=ENVIRONMENT_SDK_RUNTIME, from=0)
     private static class ClassWithRepeatedAnnotation {
     }
 
     @RestrictedForEnvironment(
-        environments={Environment.SDK_SANDBOX, Environment.SDK_SANDBOX},
+        environments={ENVIRONMENT_SDK_RUNTIME, ENVIRONMENT_SDK_RUNTIME},
         from=0)
     private static class ClassWithMultipleEnvironment {
     }
```

