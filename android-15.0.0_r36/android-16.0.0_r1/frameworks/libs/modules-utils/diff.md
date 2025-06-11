```diff
diff --git a/build/include/android-modules-utils/sdk_level.h b/build/include/android-modules-utils/sdk_level.h
index f35c09e..a4a8113 100644
--- a/build/include/android-modules-utils/sdk_level.h
+++ b/build/include/android-modules-utils/sdk_level.h
@@ -63,6 +63,9 @@ inline bool IsAtLeastV() {
           detail::IsAtLeastPreReleaseCodename("VanillaIceCream"));
 }
 
+// Checks if the device is running on release version of Android B or newer.
+inline bool IsAtLeastB() { return android_get_device_api_level() >= 36; }
+
 } // namespace sdklevel
 } // namespace modules
 } // namespace android
diff --git a/java/android/annotation/DurationNanosLong.java b/java/android/annotation/DurationNanosLong.java
new file mode 100644
index 0000000..f35a1c2
--- /dev/null
+++ b/java/android/annotation/DurationNanosLong.java
@@ -0,0 +1,36 @@
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
+package android.annotation;
+
+import static java.lang.annotation.ElementType.FIELD;
+import static java.lang.annotation.ElementType.METHOD;
+import static java.lang.annotation.ElementType.PARAMETER;
+import static java.lang.annotation.RetentionPolicy.SOURCE;
+
+import java.lang.annotation.Retention;
+import java.lang.annotation.Target;
+
+/**
+ * @memberDoc Value is a non-negative duration in nanoseconds.
+ * @paramDoc Value is a non-negative duration in nanoseconds.
+ * @returnDoc Value is a non-negative duration in nanoseconds.
+ * @hide
+ */
+@Retention(SOURCE)
+@Target({METHOD, PARAMETER, FIELD})
+public @interface DurationNanosLong {
+}
diff --git a/java/android/annotation/RequiresFeature.java b/java/android/annotation/RequiresFeature.java
index 9236700..397e460 100644
--- a/java/android/annotation/RequiresFeature.java
+++ b/java/android/annotation/RequiresFeature.java
@@ -34,9 +34,27 @@ import java.lang.annotation.Target;
 @Target({TYPE,FIELD,METHOD,CONSTRUCTOR})
 public @interface RequiresFeature {
     /**
-     * The name of the device feature that is required.
+     * The name of the device feature that is required, if precisely one feature
+     * is required. If more than one feature is required, specify either
+     * {@link #allOf()} or {@link #anyOf()} instead.
+     * <p>
+     * If specified, {@link #anyOf()} and {@link #allOf()} must both be null.
+     */
+    String value() default "";
+
+    /**
+     * Specifies a list of feature names that are all required.
+     * <p>
+     * If specified, {@link #anyOf()} and {@link #value()} must both be null.
+     */
+    String[] allOf() default {};
+
+    /**
+     * Specifies a list of permission names where at least one is required
+     * <p>
+     * If specified, {@link #allOf()} and {@link #value()} must both be null.
      */
-    String value();
+    String[] anyOf() default {};
 
     /**
      * Defines the name of the method that should be called to check whether the feature is
diff --git a/java/android/annotation/SpecialUsers.java b/java/android/annotation/SpecialUsers.java
new file mode 100644
index 0000000..7e47717
--- /dev/null
+++ b/java/android/annotation/SpecialUsers.java
@@ -0,0 +1,126 @@
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
+package android.annotation;
+
+import static java.lang.annotation.ElementType.ANNOTATION_TYPE;
+import static java.lang.annotation.ElementType.FIELD;
+import static java.lang.annotation.ElementType.METHOD;
+import static java.lang.annotation.ElementType.LOCAL_VARIABLE;
+import static java.lang.annotation.ElementType.PARAMETER;
+import static java.lang.annotation.ElementType.TYPE;
+import static java.lang.annotation.ElementType.TYPE_USE;
+import static java.lang.annotation.RetentionPolicy.SOURCE;
+
+import java.lang.annotation.Retention;
+import java.lang.annotation.Target;
+
+/**
+ * Contains annotations to indicate whether special {@link android.os.UserHandle} values
+ * are permitted for a given {@link android.os.UserHandle} or {@link UserIdInt}.
+ *
+ * <p>User IDs are typically specified by either a UserHandle or a userId int, which ultimately are
+ * whole numbers (0 or larger). There also exist special userId values that correspond to
+ * special cases ("all users", "the current user", etc.), which are internally handled using
+ * negative integers. Some method parameters, return values, and variables accept such special
+ * values, but others do not. This annotation indicates whether they are supported, and which.
+ *
+ * <p>Example usage:
+ * <li><code>
+ *     public @CanBeALL @CanBeCURRENT UserHandle myMethod(@CanBeALL @UserIdInt int userId) {}
+ * </code>
+ *
+ * @see android.os.UserHandle#ALL
+ * @see android.os.UserHandle#CURRENT
+ * @see UserHandleAware#specialUsersAllowed() Specification usage for @UserHandleAware
+ *
+ * @hide
+ */
+@Retention(SOURCE)
+public @interface SpecialUsers {
+    /**
+     * Special UserHandle and userId ints corresponding to
+     * <li>{@link android.os.UserHandle#ALL} and {@link android.os.UserHandle#USER_ALL}</li>
+     * <li>{@link android.os.UserHandle#CURRENT} and {@link android.os.UserHandle#USER_CURRENT}</li>
+     * as well as more advanced options (and their negations, catchalls, etc.).
+     */
+    static enum SpecialUser {
+        // Values direct from UserHandle (common)
+        USER_ALL, USER_CURRENT,
+        // Values direct from UserHandle (less common)
+        USER_CURRENT_OR_SELF, USER_NULL,
+        // Negation of the UserHandle values
+        DISALLOW_USER_ALL, DISALLOW_USER_CURRENT, DISALLOW_USER_CURRENT_OR_SELF, DISALLOW_USER_NULL,
+        // Catchall values (caution: needs to remain valid even if more specials are ever added!)
+        ALLOW_EVERY, DISALLOW_EVERY,
+        // Indication that the answer is as-yet unknown
+        UNSPECIFIED;
+    }
+
+    /**
+     * Indication that a {@link android.os.UserHandle} or {@link UserIdInt} can be
+     * {@link android.os.UserHandle#ALL} and {@link android.os.UserHandle#USER_ALL}, respectively.
+     */
+    @Retention(SOURCE)
+    @Target({TYPE, TYPE_USE, FIELD, METHOD, PARAMETER, LOCAL_VARIABLE, ANNOTATION_TYPE})
+    @CanBeUsers(specialUsersAllowed = {SpecialUser.USER_ALL})
+    public @interface CanBeALL {
+    }
+
+    /**
+     * Indication that a {@link android.os.UserHandle} or {@link UserIdInt} can be
+     * {@link android.os.UserHandle#CURRENT} and {@link android.os.UserHandle#USER_CURRENT},
+     * respectively.
+     */
+    @Retention(SOURCE)
+    @Target({TYPE, TYPE_USE, FIELD, METHOD, PARAMETER, LOCAL_VARIABLE, ANNOTATION_TYPE})
+    @CanBeUsers(specialUsersAllowed = {SpecialUser.USER_CURRENT})
+    public @interface CanBeCURRENT {
+    }
+
+    /**
+     * Indication that a {@link android.os.UserHandle} or {@link UserIdInt} can be
+     * {@link android.os.UserHandle#NULL} and {@link android.os.UserHandle#USER_NULL}, respectively.
+     * (This is unrelated to the Java concept of <code>null</code>.)
+     */
+    @Retention(SOURCE)
+    @Target({TYPE, TYPE_USE, FIELD, METHOD, PARAMETER, LOCAL_VARIABLE, ANNOTATION_TYPE})
+    @CanBeUsers(specialUsersAllowed = {SpecialUser.USER_NULL})
+    public @interface CanBeNULL {
+    }
+
+    /**
+     * Indication that a {@link android.os.UserHandle} or {@link UserIdInt} cannot take on any
+     * special values.
+     */
+    @Retention(SOURCE)
+    @Target({TYPE, TYPE_USE, FIELD, METHOD, PARAMETER, LOCAL_VARIABLE, ANNOTATION_TYPE})
+    @CanBeUsers(specialUsersAllowed = {SpecialUser.DISALLOW_EVERY})
+    public @interface CannotBeSpecialUser {
+    }
+
+    /**
+     * Indication that a {@link android.os.UserHandle} or {@link UserIdInt} can take on
+     * {@link SpecialUser special values} as specified.
+     * <p> For use when simple {@link CanBeALL} and {@link CanBeCURRENT} do not suffice.
+     */
+    @Retention(SOURCE)
+    @Target({TYPE, TYPE_USE, FIELD, METHOD, PARAMETER, LOCAL_VARIABLE, ANNOTATION_TYPE})
+    public @interface CanBeUsers {
+        /** Specify which types of {@link SpecialUser}s are allowed. For use in advanced cases.  */
+        SpecialUser[] specialUsersAllowed() default {SpecialUser.UNSPECIFIED};
+    }
+}
diff --git a/java/android/annotation/UserHandleAware.java b/java/android/annotation/UserHandleAware.java
index 2c3badc..02e3e12 100644
--- a/java/android/annotation/UserHandleAware.java
+++ b/java/android/annotation/UserHandleAware.java
@@ -15,6 +15,8 @@
  */
 package android.annotation;
 
+import static android.annotation.SpecialUsers.SpecialUser.DISALLOW_EVERY;
+
 import static java.lang.annotation.ElementType.CONSTRUCTOR;
 import static java.lang.annotation.ElementType.METHOD;
 import static java.lang.annotation.ElementType.PACKAGE;
@@ -52,7 +54,7 @@ public @interface UserHandleAware {
      * if it was not always so.
      *
      * Prior to this level, the method is not considered {@literal @}UserHandleAware and therefore
-     * uses the {@link android.os#myUserHandle() calling user},
+     * uses the {@link android.os.Process#myUserHandle() calling user},
      * not the {@link android.content.Context#getUser context user}.
      *
      * Note that when an API marked with this parameter is run on a device whose OS predates the
@@ -93,4 +95,22 @@ public @interface UserHandleAware {
      * @see android.annotation.RequiresPermission#anyOf()
      */
     String[] requiresAnyOfPermissionsIfNotCallerProfileGroup() default {};
+
+    /**
+     * Indicates whether special {@link android.os.UserHandle UserHandle} values are supported by
+     * this method or class.
+     *
+     * <p>When creating a Context using (e.g. via
+     * {@link android.content.Context#createContextAsUser}), a special UserHandle (such as
+     * {@link android.os.UserHandle#CURRENT}) can be used.
+     * However, most UserHandleAware methods do not support Contexts built upon such special
+     * users. This annotation indicates whether they are supported, and which. Note that it is
+     * likely rare that any special users are supported.
+     *
+     * <p>Typical values could include one or more of
+     * <li>{@link SpecialUsers.SpecialUser#USER_ALL}
+     * <li>{@link SpecialUsers.SpecialUser#USER_CURRENT}
+     * <li>{@link SpecialUsers.SpecialUser#DISALLOW_EVERY}
+     */
+    SpecialUsers.SpecialUser[] specialUsersAllowed() default {DISALLOW_EVERY};
 }
diff --git a/java/android/annotation/UserIdInt.java b/java/android/annotation/UserIdInt.java
index 7b9ce25..f3e7de4 100644
--- a/java/android/annotation/UserIdInt.java
+++ b/java/android/annotation/UserIdInt.java
@@ -17,6 +17,7 @@
 package android.annotation;
 
 import static java.lang.annotation.ElementType.FIELD;
+import static java.lang.annotation.ElementType.LOCAL_VARIABLE;
 import static java.lang.annotation.ElementType.METHOD;
 import static java.lang.annotation.ElementType.PARAMETER;
 import static java.lang.annotation.RetentionPolicy.SOURCE;
@@ -31,6 +32,6 @@ import java.lang.annotation.Target;
  * @hide
  */
 @Retention(SOURCE)
-@Target({METHOD, PARAMETER, FIELD})
+@Target({METHOD, PARAMETER, FIELD, LOCAL_VARIABLE})
 public @interface UserIdInt {
 }
diff --git a/java/android/ravenwood/annotation/OWNERS b/java/android/ravenwood/annotation/OWNERS
new file mode 100644
index 0000000..93d9c7f
--- /dev/null
+++ b/java/android/ravenwood/annotation/OWNERS
@@ -0,0 +1 @@
+include platform/frameworks/base:/ravenwood/OWNERS
\ No newline at end of file
diff --git a/java/android/ravenwood/annotation/RavenwoodClassLoadHook.java b/java/android/ravenwood/annotation/RavenwoodClassLoadHook.java
index 7a3142b..c47aa94 100644
--- a/java/android/ravenwood/annotation/RavenwoodClassLoadHook.java
+++ b/java/android/ravenwood/annotation/RavenwoodClassLoadHook.java
@@ -22,8 +22,7 @@ import java.lang.annotation.RetentionPolicy;
 import java.lang.annotation.Target;
 
 /**
- * THIS ANNOTATION IS EXPERIMENTAL. REACH OUT TO g/ravenwood BEFORE USING IT, OR YOU HAVE ANY
- * QUESTIONS ABOUT IT.
+ * Set a "class load hook" for the annotated class.
  *
  * Add this with a fully-specified method name (e.g. {@code "com.package.Class.methodName"})
  * of a callback to get a callback at the class load time.
diff --git a/java/android/ravenwood/annotation/RavenwoodIgnore.java b/java/android/ravenwood/annotation/RavenwoodIgnore.java
new file mode 100644
index 0000000..775cfab
--- /dev/null
+++ b/java/android/ravenwood/annotation/RavenwoodIgnore.java
@@ -0,0 +1,51 @@
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
+
+import java.lang.annotation.Retention;
+import java.lang.annotation.RetentionPolicy;
+import java.lang.annotation.Target;
+
+/**
+ * Denotes that the annotated method is unsupported on Ravenwood, and calling it will be a no-op.
+ * <p>
+ * Implementation included in the annotated method will be removed on Ravenwood, making it
+ * effectively a no-op. If the method returns a value, the value that is returned will be the
+ * "default" value for the type, meaning 0 for primitives types, and null for reference types.
+ *
+ * @hide
+ */
+@Target({METHOD})
+@Retention(RetentionPolicy.CLASS)
+public @interface RavenwoodIgnore {
+    /**
+     * One or more classes that aren't yet supported by Ravenwood, which is why this method is
+     * being ignored.
+     */
+    Class<?>[] blockedBy() default {};
+
+    /**
+     * General free-form description of why this method is being ignored.
+     */
+    String reason() default "";
+
+    /**
+     * Tracking bug number, if any.
+     */
+    long bug() default 0;
+}
diff --git a/java/android/ravenwood/annotation/RavenwoodKeep.java b/java/android/ravenwood/annotation/RavenwoodKeep.java
index f02f06c..52c3b70 100644
--- a/java/android/ravenwood/annotation/RavenwoodKeep.java
+++ b/java/android/ravenwood/annotation/RavenwoodKeep.java
@@ -24,10 +24,11 @@ import java.lang.annotation.RetentionPolicy;
 import java.lang.annotation.Target;
 
 /**
- * THIS ANNOTATION IS EXPERIMENTAL. REACH OUT TO g/ravenwood BEFORE USING IT, OR YOU HAVE ANY
- * QUESTIONS ABOUT IT.
- *
- * TODO: Javadoc
+ * Denotes that the annotated method is supported on Ravenwood, and the implementation
+ * is kept as-is.
+ * <p>
+ * Implementation included in the annotated method will not be processed and
+ * will be kept as-is on Ravenwood, just like it does on a real device.
  *
  * @hide
  */
diff --git a/java/android/ravenwood/annotation/RavenwoodKeepPartialClass.java b/java/android/ravenwood/annotation/RavenwoodKeepPartialClass.java
index 7847274..61bb613 100644
--- a/java/android/ravenwood/annotation/RavenwoodKeepPartialClass.java
+++ b/java/android/ravenwood/annotation/RavenwoodKeepPartialClass.java
@@ -21,10 +21,14 @@ import java.lang.annotation.RetentionPolicy;
 import java.lang.annotation.Target;
 
 /**
- * THIS ANNOTATION IS EXPERIMENTAL. REACH OUT TO g/ravenwood BEFORE USING IT, OR YOU HAVE ANY
- * QUESTIONS ABOUT IT.
+ * Denotes that the annotated class is partially supported on Ravenwood.
+ * <p>
+ * Methods in this class are not supported on Ravenwood by default.
+ * Each method must explicitly opt-in to be supported on Ravenwood by annotating it with either
+ * {@link RavenwoodKeep}, {@link RavenwoodReplace}, or {@link RavenwoodRedirect}.
  *
- * TODO: Javadoc
+ * @see RavenwoodKeepWholeClass
+ * @see RavenwoodKeepStaticInitializer
  *
  * @hide
  */
diff --git a/java/android/ravenwood/annotation/RavenwoodKeepStaticInitializer.java b/java/android/ravenwood/annotation/RavenwoodKeepStaticInitializer.java
index eeebee9..abd1074 100644
--- a/java/android/ravenwood/annotation/RavenwoodKeepStaticInitializer.java
+++ b/java/android/ravenwood/annotation/RavenwoodKeepStaticInitializer.java
@@ -22,8 +22,12 @@ import java.lang.annotation.RetentionPolicy;
 import java.lang.annotation.Target;
 
 /**
- * THIS ANNOTATION IS EXPERIMENTAL. REACH OUT TO g/ravenwood BEFORE USING IT, OR YOU HAVE ANY
- * QUESTIONS ABOUT IT.
+ * Denotes that the static initializer of the annotated class should be kept on Ravenwood.
+ * <p>
+ * When a class is annotated with {@link RavenwoodKeepPartialClass}, its static initializer
+ * is not kept by default.
+ * This annotation can be used to opt-in the static initializer of such a class.
+ * Note: without the static initializer, static fields of the class will not be initialized!
  *
  * @hide
  */
diff --git a/java/android/ravenwood/annotation/RavenwoodKeepWholeClass.java b/java/android/ravenwood/annotation/RavenwoodKeepWholeClass.java
index d2c77c1..7310b4b 100644
--- a/java/android/ravenwood/annotation/RavenwoodKeepWholeClass.java
+++ b/java/android/ravenwood/annotation/RavenwoodKeepWholeClass.java
@@ -25,11 +25,12 @@ import java.lang.annotation.RetentionPolicy;
 import java.lang.annotation.Target;
 
 /**
- * THIS ANNOTATION IS EXPERIMENTAL. REACH OUT TO g/ravenwood BEFORE USING IT, OR YOU HAVE ANY
- * QUESTIONS ABOUT IT.
- *
- * TODO: Javadoc
- * TODO: Create "whole-class-throw"?
+ * Denotes that the annotated class is fully supported on Ravenwood.
+ * <p>
+ * All methods in this class are treated as if they were all annotated with {@link RavenwoodKeep}.
+ * For methods that need to be replaced or redirected, explicitly annotate them with
+ * {@link RavenwoodReplace} or {@link RavenwoodRedirect} respectively.
+ * To opt-out a method from Ravenwood, annotate it explicitly with {@link RavenwoodThrow}.
  *
  * @hide
  */
diff --git a/java/android/ravenwood/annotation/RavenwoodPartiallyAllowlisted.java b/java/android/ravenwood/annotation/RavenwoodPartiallyAllowlisted.java
new file mode 100644
index 0000000..166db7b
--- /dev/null
+++ b/java/android/ravenwood/annotation/RavenwoodPartiallyAllowlisted.java
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
+package android.ravenwood.annotation;
+
+import static java.lang.annotation.ElementType.TYPE;
+
+import java.lang.annotation.Retention;
+import java.lang.annotation.RetentionPolicy;
+import java.lang.annotation.Target;
+
+/**
+ * Denotes that the annotated class is not officially supported on Ravenwood, however certain
+ * methods of the class are allowed to be used.
+ * <p>
+ * Opting-in additional methods of the class to be used on Ravenwood requires explicit approval
+ * from the Ravenwood team.
+ *
+ * TODO: Add a link to the Ravenwood team's page once it's available.
+ *
+ * @hide
+ */
+@Target({TYPE})
+@Retention(RetentionPolicy.CLASS)
+public @interface RavenwoodPartiallyAllowlisted {
+}
diff --git a/java/android/ravenwood/annotation/RavenwoodRedirect.java b/java/android/ravenwood/annotation/RavenwoodRedirect.java
index b582ccf..aae4c3c 100644
--- a/java/android/ravenwood/annotation/RavenwoodRedirect.java
+++ b/java/android/ravenwood/annotation/RavenwoodRedirect.java
@@ -22,10 +22,45 @@ import java.lang.annotation.RetentionPolicy;
 import java.lang.annotation.Target;
 
 /**
- * THIS ANNOTATION IS EXPERIMENTAL. REACH OUT TO g/ravenwood BEFORE USING IT, OR YOU HAVE ANY
- * QUESTIONS ABOUT IT.
+ * Redirects the annotated method to the corresponding method in the class specified by
+ * {@link RavenwoodRedirectionClass}.
+ * <p>
+ * This annotation has to be used in conjunction with {@link RavenwoodRedirectionClass}.
+ * Each method annotated with {@link RavenwoodRedirect} will be redirected to the corresponding
+ * method in the class specified by the value of this annotation.
+ * <p>
+ * All redirection methods in the redirection class must be static.
+ * If the annotated method is static, the redirection method shall have the same signature.
+ * If the annotated method is non-static, the redirection method shall have an additional
+ * first parameter that is a reference to the {@code this} object.
  *
- * TODO: Javadoc
+ * Example:
+ * <pre>
+ *     @RavenwoodRedirectionClass("Foo_ravenwood")
+ *     public class Foo {
+ *         @RavenwoodRedirect
+ *         public void bar(int i, int j, int k) {
+ *             // ...
+ *         }
+ *
+ *         @RavenwoodRedirect
+ *         public static void baz(int i, int j, int k) {
+ *             // ...
+ *         }
+ *     }
+ *
+ *     public class Foo_ravenwod {
+ *         public static void bar(Foo foo, int i, int j, int k) {
+ *             // The "this" object of the original method is the "foo" parameter here.
+ *         }
+ *
+ *         public static void baz(int i, int j, int k) {
+ *             // ...
+ *         }
+ *     }
+ * </pre>
+ *
+ * @see RavenwoodRedirectionClass
  *
  * @hide
  */
diff --git a/java/android/ravenwood/annotation/RavenwoodRedirectionClass.java b/java/android/ravenwood/annotation/RavenwoodRedirectionClass.java
index bee9222..bb8bddb 100644
--- a/java/android/ravenwood/annotation/RavenwoodRedirectionClass.java
+++ b/java/android/ravenwood/annotation/RavenwoodRedirectionClass.java
@@ -22,10 +22,13 @@ import java.lang.annotation.RetentionPolicy;
 import java.lang.annotation.Target;
 
 /**
- * THIS ANNOTATION IS EXPERIMENTAL. REACH OUT TO g/ravenwood BEFORE USING IT, OR YOU HAVE ANY
- * QUESTIONS ABOUT IT.
+ * Set a "redirection class" for the annotated class.
+ * <p>
+ * This annotation has to be used in conjunction with {@link RavenwoodRedirect}.
+ * Each method annotated with {@link RavenwoodRedirect} will be redirected to the corresponding
+ * method in the class specified by the value of this annotation.
  *
- * TODO: Javadoc
+ * @see RavenwoodRedirect
  *
  * @hide
  */
diff --git a/java/android/ravenwood/annotation/RavenwoodRemove.java b/java/android/ravenwood/annotation/RavenwoodRemove.java
index b69c637..db41a2a 100644
--- a/java/android/ravenwood/annotation/RavenwoodRemove.java
+++ b/java/android/ravenwood/annotation/RavenwoodRemove.java
@@ -25,10 +25,14 @@ import java.lang.annotation.RetentionPolicy;
 import java.lang.annotation.Target;
 
 /**
- * THIS ANNOTATION IS EXPERIMENTAL. REACH OUT TO g/ravenwood BEFORE USING IT, OR YOU HAVE ANY
- * QUESTIONS ABOUT IT.
+ * Denotes that the annotated target is unsupported on Ravenwood, and it will be completely removed.
+ * <p>
+ * The target element will actually be removed, so it can't be accessed or even mocked, which
+ * is not something normally needed.
+ * Consider using {@link RavenwoodThrow} or {@link RavenwoodIgnore} instead.
  *
- * TODO: Javadoc
+ * @see RavenwoodThrow
+ * @see RavenwoodIgnore
  *
  * @hide
  */
@@ -36,12 +40,13 @@ import java.lang.annotation.Target;
 @Retention(RetentionPolicy.CLASS)
 public @interface RavenwoodRemove {
     /**
-     * One or more classes that aren't yet supported by Ravenwood, which is why this method throws.
+     * One or more classes that aren't yet supported by Ravenwood, which is why this target
+     * is removed.
      */
     Class<?>[] blockedBy() default {};
 
     /**
-     * General free-form description of why this method throws.
+     * General free-form description of why this target is removed.
      */
     String reason() default "";
 
diff --git a/java/android/ravenwood/annotation/RavenwoodReplace.java b/java/android/ravenwood/annotation/RavenwoodReplace.java
index 57cdfd2..197f65f 100644
--- a/java/android/ravenwood/annotation/RavenwoodReplace.java
+++ b/java/android/ravenwood/annotation/RavenwoodReplace.java
@@ -22,10 +22,29 @@ import java.lang.annotation.RetentionPolicy;
 import java.lang.annotation.Target;
 
 /**
- * THIS ANNOTATION IS EXPERIMENTAL. REACH OUT TO g/ravenwood BEFORE USING IT, OR YOU HAVE ANY
- * QUESTIONS ABOUT IT.
+ * Denotes that the annotated method is supported on Ravenwood, however the implementation
+ * will be replaced with the method suffixed with "$ravenwood".
+ * <p>
+ * Example:
+ * <pre>
+ *     @RavenwoodKeepPartialClass
+ *     public class Foo {
+ *         @RavenwoodReplace
+ *         public void doComplex() {
+ *             // This method implementation runs as-is on devices, but the
+ *             // implementation is replaced/substituted by the
+ *             // doComplex$ravenwood() method implementation under Ravenwood
+ *         }
  *
- * TODO: Javadoc
+ *         private void doComplex$ravenwood() {
+ *             // This method implementation only runs under Ravenwood.
+ *             // The visibility of this replacement method does not need to match
+ *             // the original method, so it's recommended to always use
+ *             // private methods so that these methods won't be accidentally used
+ *             // by unexpected users.
+ *         }
+ *     }
+ * </pre>
  *
  * @hide
  */
diff --git a/java/android/ravenwood/annotation/RavenwoodThrow.java b/java/android/ravenwood/annotation/RavenwoodThrow.java
index 19e6af1..4cc9d1c 100644
--- a/java/android/ravenwood/annotation/RavenwoodThrow.java
+++ b/java/android/ravenwood/annotation/RavenwoodThrow.java
@@ -23,10 +23,13 @@ import java.lang.annotation.RetentionPolicy;
 import java.lang.annotation.Target;
 
 /**
- * THIS ANNOTATION IS EXPERIMENTAL. REACH OUT TO g/ravenwood BEFORE USING IT, OR YOU HAVE ANY
- * QUESTIONS ABOUT IT.
+ * Denotes that the annotated method is unsupported on Ravenwood, and calling it will throw
+ * a runtime exception.
+ * <p>
+ * Implementation included in the annotated method will be removed on Ravenwood, and calling it
+ * will throw a runtime exception with a message indicating that the method is unsupported
+ * on Ravenwood.
  *
- * TODO: Javadoc
  * TODO: Create "whole-class-throw"?
  *
  * @hide
diff --git a/java/com/android/internal/annotations/CacheModifier.java b/java/com/android/internal/annotations/CacheModifier.java
index 3908271..fd3fb8f 100644
--- a/java/com/android/internal/annotations/CacheModifier.java
+++ b/java/com/android/internal/annotations/CacheModifier.java
@@ -20,7 +20,7 @@ public enum CacheModifier {
     /**
      * This modifier is used to indicate that the annotated method should be cached in as a static
      * field. When STATIC is not present in
-     * {@link com.android.internal.annotations.CachedProperty#modsFlagOnOrNone} then generated cache
+     * {@link com.android.internal.annotations.CachedProperty#mods} then generated cache
      * field will not be static.
      */
     STATIC,
diff --git a/java/com/android/internal/annotations/CachedProperty.java b/java/com/android/internal/annotations/CachedProperty.java
index 9a1b161..b2eb51b 100644
--- a/java/com/android/internal/annotations/CachedProperty.java
+++ b/java/com/android/internal/annotations/CachedProperty.java
@@ -67,9 +67,6 @@ public @interface CachedProperty {
 
   /**
    * Specify modifiers for generating cached property. By default it will be static property.
-   * This modifiers will apply when flag is on or does not exist.
-   * TODO: Add support for flag modifiers. b/361731022
    */
-  CacheModifier[] modsFlagOnOrNone() default { CacheModifier.STATIC };
+  CacheModifier[] mods() default { CacheModifier.STATIC };
 }
-
diff --git a/java/com/android/modules/utils/build/SdkLevel.java b/java/com/android/modules/utils/build/SdkLevel.java
index 4b811b1..3b1d2bb 100644
--- a/java/com/android/modules/utils/build/SdkLevel.java
+++ b/java/com/android/modules/utils/build/SdkLevel.java
@@ -71,6 +71,12 @@ public final class SdkLevel {
                 (SDK_INT == 34 && isAtLeastPreReleaseCodename("VanillaIceCream"));
     }
 
+    /** Checks if the device is running on a release version of Android Baklava or newer */
+    @ChecksSdkIntAtLeast(api = 36 /* BUILD_VERSION_CODES.Baklava */)
+    public static boolean isAtLeastB() {
+        return SDK_INT >= 36;
+    }
+
     private static boolean isAtLeastPreReleaseCodename(@NonNull String codename) {
         // Special case "REL", which means the build is not a pre-release build.
         if ("REL".equals(CODENAME)) {
diff --git a/java/com/android/modules/utils/testing/AbstractExtendedMockitoRule.java b/java/com/android/modules/utils/testing/AbstractExtendedMockitoRule.java
index 2242ca0..f391f36 100644
--- a/java/com/android/modules/utils/testing/AbstractExtendedMockitoRule.java
+++ b/java/com/android/modules/utils/testing/AbstractExtendedMockitoRule.java
@@ -146,9 +146,9 @@ public abstract class AbstractExtendedMockitoRule<R extends AbstractExtendedMock
         return new Statement() {
             @Override
             public void evaluate() throws Throwable {
-                createMockitoSession(base, description);
                 Throwable error = null;
                 try {
+                    createMockitoSession(base, description);
                     // TODO(b/296937563): need to add unit tests that make sure the session is
                     // always closed
                     base.evaluate();
diff --git a/javatests/com/android/modules/utils/testing/ExtendedMockitoRuleTest.java b/javatests/com/android/modules/utils/testing/ExtendedMockitoRuleTest.java
index 26d0cc3..e91c28f 100644
--- a/javatests/com/android/modules/utils/testing/ExtendedMockitoRuleTest.java
+++ b/javatests/com/android/modules/utils/testing/ExtendedMockitoRuleTest.java
@@ -40,6 +40,7 @@ import org.junit.runner.RunWith;
 import org.junit.runners.model.Statement;
 import org.mockito.InOrder;
 import org.mockito.Mock;
+import org.mockito.Mockito;
 import org.mockito.MockitoFramework;
 import org.mockito.MockitoSession;
 import org.mockito.exceptions.misusing.UnnecessaryStubbingException;
@@ -600,6 +601,19 @@ public final class ExtendedMockitoRuleTest {
         assertWithMessage("mockito framework cleared").that(mockitoFramework.called).isTrue();
     }
 
+    @Test
+    public void testMockitoSessionFinished_whenStaticMockFixturesSetupFailed() throws Throwable {
+        RuntimeException exception = new RuntimeException("D'OH!");
+        doThrow(exception).when(mStaticMockFixture1).setUpMockBehaviors();
+
+        assertThrows(Exception.class,
+                () -> mBuilder.addStaticMockFixtures(mSupplier1)
+                        .build().apply(mStatement, mDescription).evaluate());
+
+        // Assert that the previous session was closed.
+        Mockito.mockitoSession().startMocking().finishMocking();
+    }
+
     @Test
     public void testGetClearInlineMethodsAtTheEnd() throws Throwable {
         assertWithMessage("getClearInlineMethodsAtTheEnd() by default")
@@ -834,4 +848,4 @@ public final class ExtendedMockitoRuleTest {
     @MockStatic(AnotherStaticClassMockedBySubClass.class)
     private static final class SubClass extends SuperClass{
     }
-}
\ No newline at end of file
+}
```

