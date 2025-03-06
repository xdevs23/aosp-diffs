```diff
diff --git a/java/Android.bp b/java/Android.bp
index ea03aea..b1445d1 100644
--- a/java/Android.bp
+++ b/java/Android.bp
@@ -22,20 +22,15 @@ filegroup {
     srcs: [
         ":framework-metalava-annotations",
         "com/android/internal/annotations/*.java",
+        "android/ravenwood/annotation/*.java",
     ],
 
-    // TODO: Prune this list
+    // This list is intentionally restricted, with few exceptions.
+    // Prefer using framework-annotations-lib wherever possible.
     visibility: [
         "//frameworks/base",
-        "//frameworks/base/services/net",
+        "//frameworks/base/tools/processors/property_cache",
         "//frameworks/base/tools/processors/intdef_mappings",
-        "//frameworks/libs/net/common",
-        "//packages/apps/CellBroadcastReceiver",
-        "//packages/apps/CellBroadcastReceiver/legacy",
-        "//packages/modules/CellBroadcastService",
-        "//packages/modules/NetworkStack/common/netlinkclient",
-        "//packages/modules/NetworkStack/common/networkstackclient",
-        "//packages/services/Iwlan",
     ],
 }
 
@@ -132,6 +127,18 @@ filegroup {
     ],
 }
 
+filegroup {
+    name: "module-utils-future-aidls",
+    srcs: [
+        "com/android/modules/utils/AndroidFuture.aidl",
+        "com/android/modules/utils/IAndroidFuture.aidl",
+    ],
+    visibility: [
+        "//packages/modules/NeuralNetworks/framework",
+        "//frameworks/libs/modules-utils/java/com/android/modules/utils",
+    ],
+}
+
 // This file group is deprecated; new users should use modules-utils-preconditions
 filegroup {
     name: "modules-utils-preconditions-srcs",
diff --git a/java/android/ravenwood/annotation/RavenwoodClassLoadHook.java b/java/android/ravenwood/annotation/RavenwoodClassLoadHook.java
new file mode 100644
index 0000000..7a3142b
--- /dev/null
+++ b/java/android/ravenwood/annotation/RavenwoodClassLoadHook.java
@@ -0,0 +1,48 @@
+/*
+ * Copyright (C) 2023 The Android Open Source Project
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
+ * THIS ANNOTATION IS EXPERIMENTAL. REACH OUT TO g/ravenwood BEFORE USING IT, OR YOU HAVE ANY
+ * QUESTIONS ABOUT IT.
+ *
+ * Add this with a fully-specified method name (e.g. {@code "com.package.Class.methodName"})
+ * of a callback to get a callback at the class load time.
+ *
+ * The method must be {@code public static} with a single argument that takes {@link Class}.
+ *
+ * Typically, this is used with {@link #LIBANDROID_LOADING_HOOK}, which will load the necessary
+ * native libraries.
+ *
+ * @hide
+ */
+@Target({TYPE})
+@Retention(RetentionPolicy.CLASS)
+public @interface RavenwoodClassLoadHook {
+    String value();
+
+    /**
+     * Class load hook that loads <code>libandroid_runtime</code>.
+     */
+    public static String LIBANDROID_LOADING_HOOK
+            = "com.android.platform.test.ravenwood.runtimehelper.ClassLoadHook.onClassLoaded";
+}
diff --git a/java/android/ravenwood/annotation/RavenwoodKeep.java b/java/android/ravenwood/annotation/RavenwoodKeep.java
new file mode 100644
index 0000000..f02f06c
--- /dev/null
+++ b/java/android/ravenwood/annotation/RavenwoodKeep.java
@@ -0,0 +1,37 @@
+/*
+ * Copyright (C) 2023 The Android Open Source Project
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
+import static java.lang.annotation.ElementType.CONSTRUCTOR;
+import static java.lang.annotation.ElementType.FIELD;
+import static java.lang.annotation.ElementType.METHOD;
+
+import java.lang.annotation.Retention;
+import java.lang.annotation.RetentionPolicy;
+import java.lang.annotation.Target;
+
+/**
+ * THIS ANNOTATION IS EXPERIMENTAL. REACH OUT TO g/ravenwood BEFORE USING IT, OR YOU HAVE ANY
+ * QUESTIONS ABOUT IT.
+ *
+ * TODO: Javadoc
+ *
+ * @hide
+ */
+@Target({FIELD, METHOD, CONSTRUCTOR})
+@Retention(RetentionPolicy.CLASS)
+public @interface RavenwoodKeep {
+}
diff --git a/java/android/ravenwood/annotation/RavenwoodKeepPartialClass.java b/java/android/ravenwood/annotation/RavenwoodKeepPartialClass.java
new file mode 100644
index 0000000..7847274
--- /dev/null
+++ b/java/android/ravenwood/annotation/RavenwoodKeepPartialClass.java
@@ -0,0 +1,34 @@
+/*
+ * Copyright (C) 2023 The Android Open Source Project
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
+import java.lang.annotation.ElementType;
+import java.lang.annotation.Retention;
+import java.lang.annotation.RetentionPolicy;
+import java.lang.annotation.Target;
+
+/**
+ * THIS ANNOTATION IS EXPERIMENTAL. REACH OUT TO g/ravenwood BEFORE USING IT, OR YOU HAVE ANY
+ * QUESTIONS ABOUT IT.
+ *
+ * TODO: Javadoc
+ *
+ * @hide
+ */
+@Target(ElementType.TYPE)
+@Retention(RetentionPolicy.CLASS)
+public @interface RavenwoodKeepPartialClass {
+}
diff --git a/java/android/ravenwood/annotation/RavenwoodKeepStaticInitializer.java b/java/android/ravenwood/annotation/RavenwoodKeepStaticInitializer.java
new file mode 100644
index 0000000..eeebee9
--- /dev/null
+++ b/java/android/ravenwood/annotation/RavenwoodKeepStaticInitializer.java
@@ -0,0 +1,33 @@
+/*
+ * Copyright (C) 2023 The Android Open Source Project
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
+ * THIS ANNOTATION IS EXPERIMENTAL. REACH OUT TO g/ravenwood BEFORE USING IT, OR YOU HAVE ANY
+ * QUESTIONS ABOUT IT.
+ *
+ * @hide
+ */
+@Target(TYPE)
+@Retention(RetentionPolicy.CLASS)
+public @interface RavenwoodKeepStaticInitializer {
+}
diff --git a/java/android/ravenwood/annotation/RavenwoodKeepWholeClass.java b/java/android/ravenwood/annotation/RavenwoodKeepWholeClass.java
new file mode 100644
index 0000000..d2c77c1
--- /dev/null
+++ b/java/android/ravenwood/annotation/RavenwoodKeepWholeClass.java
@@ -0,0 +1,39 @@
+/*
+ * Copyright (C) 2023 The Android Open Source Project
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
+import static java.lang.annotation.ElementType.CONSTRUCTOR;
+import static java.lang.annotation.ElementType.FIELD;
+import static java.lang.annotation.ElementType.METHOD;
+import static java.lang.annotation.ElementType.TYPE;
+
+import java.lang.annotation.Retention;
+import java.lang.annotation.RetentionPolicy;
+import java.lang.annotation.Target;
+
+/**
+ * THIS ANNOTATION IS EXPERIMENTAL. REACH OUT TO g/ravenwood BEFORE USING IT, OR YOU HAVE ANY
+ * QUESTIONS ABOUT IT.
+ *
+ * TODO: Javadoc
+ * TODO: Create "whole-class-throw"?
+ *
+ * @hide
+ */
+@Target({TYPE, FIELD, METHOD, CONSTRUCTOR})
+@Retention(RetentionPolicy.CLASS)
+public @interface RavenwoodKeepWholeClass {
+}
diff --git a/java/android/ravenwood/annotation/RavenwoodRedirect.java b/java/android/ravenwood/annotation/RavenwoodRedirect.java
new file mode 100644
index 0000000..b582ccf
--- /dev/null
+++ b/java/android/ravenwood/annotation/RavenwoodRedirect.java
@@ -0,0 +1,35 @@
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
+package android.ravenwood.annotation;
+
+import static java.lang.annotation.ElementType.METHOD;
+
+import java.lang.annotation.Retention;
+import java.lang.annotation.RetentionPolicy;
+import java.lang.annotation.Target;
+
+/**
+ * THIS ANNOTATION IS EXPERIMENTAL. REACH OUT TO g/ravenwood BEFORE USING IT, OR YOU HAVE ANY
+ * QUESTIONS ABOUT IT.
+ *
+ * TODO: Javadoc
+ *
+ * @hide
+ */
+@Target({METHOD})
+@Retention(RetentionPolicy.CLASS)
+public @interface RavenwoodRedirect {
+}
diff --git a/java/android/ravenwood/annotation/RavenwoodRedirectionClass.java b/java/android/ravenwood/annotation/RavenwoodRedirectionClass.java
new file mode 100644
index 0000000..bee9222
--- /dev/null
+++ b/java/android/ravenwood/annotation/RavenwoodRedirectionClass.java
@@ -0,0 +1,36 @@
+/*
+ * Copyright (C) 2023 The Android Open Source Project
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
+ * THIS ANNOTATION IS EXPERIMENTAL. REACH OUT TO g/ravenwood BEFORE USING IT, OR YOU HAVE ANY
+ * QUESTIONS ABOUT IT.
+ *
+ * TODO: Javadoc
+ *
+ * @hide
+ */
+@Target({TYPE})
+@Retention(RetentionPolicy.CLASS)
+public @interface RavenwoodRedirectionClass {
+    String value();
+}
diff --git a/java/android/ravenwood/annotation/RavenwoodRemove.java b/java/android/ravenwood/annotation/RavenwoodRemove.java
new file mode 100644
index 0000000..b69c637
--- /dev/null
+++ b/java/android/ravenwood/annotation/RavenwoodRemove.java
@@ -0,0 +1,52 @@
+/*
+ * Copyright (C) 2023 The Android Open Source Project
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
+import static java.lang.annotation.ElementType.CONSTRUCTOR;
+import static java.lang.annotation.ElementType.FIELD;
+import static java.lang.annotation.ElementType.METHOD;
+import static java.lang.annotation.ElementType.TYPE;
+
+import java.lang.annotation.Retention;
+import java.lang.annotation.RetentionPolicy;
+import java.lang.annotation.Target;
+
+/**
+ * THIS ANNOTATION IS EXPERIMENTAL. REACH OUT TO g/ravenwood BEFORE USING IT, OR YOU HAVE ANY
+ * QUESTIONS ABOUT IT.
+ *
+ * TODO: Javadoc
+ *
+ * @hide
+ */
+@Target({TYPE, FIELD, METHOD, CONSTRUCTOR})
+@Retention(RetentionPolicy.CLASS)
+public @interface RavenwoodRemove {
+    /**
+     * One or more classes that aren't yet supported by Ravenwood, which is why this method throws.
+     */
+    Class<?>[] blockedBy() default {};
+
+    /**
+     * General free-form description of why this method throws.
+     */
+    String reason() default "";
+
+    /**
+     * Tracking bug number, if any.
+     */
+    long bug() default 0;
+}
diff --git a/java/android/ravenwood/annotation/RavenwoodReplace.java b/java/android/ravenwood/annotation/RavenwoodReplace.java
new file mode 100644
index 0000000..57cdfd2
--- /dev/null
+++ b/java/android/ravenwood/annotation/RavenwoodReplace.java
@@ -0,0 +1,50 @@
+/*
+ * Copyright (C) 2023 The Android Open Source Project
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
+ * THIS ANNOTATION IS EXPERIMENTAL. REACH OUT TO g/ravenwood BEFORE USING IT, OR YOU HAVE ANY
+ * QUESTIONS ABOUT IT.
+ *
+ * TODO: Javadoc
+ *
+ * @hide
+ */
+@Target({METHOD})
+@Retention(RetentionPolicy.CLASS)
+public @interface RavenwoodReplace {
+    /**
+     * One or more classes that aren't yet supported by Ravenwood, which is why this method is
+     * being replaced.
+     */
+    Class<?>[] blockedBy() default {};
+
+    /**
+     * General free-form description of why this method is being replaced.
+     */
+    String reason() default "";
+
+    /**
+     * Tracking bug number, if any.
+     */
+    long bug() default 0;
+}
diff --git a/java/android/ravenwood/annotation/RavenwoodThrow.java b/java/android/ravenwood/annotation/RavenwoodThrow.java
new file mode 100644
index 0000000..19e6af1
--- /dev/null
+++ b/java/android/ravenwood/annotation/RavenwoodThrow.java
@@ -0,0 +1,51 @@
+/*
+ * Copyright (C) 2023 The Android Open Source Project
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
+import static java.lang.annotation.ElementType.CONSTRUCTOR;
+import static java.lang.annotation.ElementType.METHOD;
+
+import java.lang.annotation.Retention;
+import java.lang.annotation.RetentionPolicy;
+import java.lang.annotation.Target;
+
+/**
+ * THIS ANNOTATION IS EXPERIMENTAL. REACH OUT TO g/ravenwood BEFORE USING IT, OR YOU HAVE ANY
+ * QUESTIONS ABOUT IT.
+ *
+ * TODO: Javadoc
+ * TODO: Create "whole-class-throw"?
+ *
+ * @hide
+ */
+@Target({METHOD, CONSTRUCTOR})
+@Retention(RetentionPolicy.CLASS)
+public @interface RavenwoodThrow {
+    /**
+     * One or more classes that aren't yet supported by Ravenwood, which is why this method throws.
+     */
+    Class<?>[] blockedBy() default {};
+
+    /**
+     * General free-form description of why this method throws.
+     */
+    String reason() default "";
+
+    /**
+     * Tracking bug number, if any.
+     */
+    long bug() default 0;
+}
diff --git a/java/com/android/internal/annotations/CacheModifier.java b/java/com/android/internal/annotations/CacheModifier.java
new file mode 100644
index 0000000..3908271
--- /dev/null
+++ b/java/com/android/internal/annotations/CacheModifier.java
@@ -0,0 +1,27 @@
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
+package com.android.internal.annotations;
+
+public enum CacheModifier {
+    /**
+     * This modifier is used to indicate that the annotated method should be cached in as a static
+     * field. When STATIC is not present in
+     * {@link com.android.internal.annotations.CachedProperty#modsFlagOnOrNone} then generated cache
+     * field will not be static.
+     */
+    STATIC,
+}
diff --git a/java/com/android/internal/annotations/CachedProperty.java b/java/com/android/internal/annotations/CachedProperty.java
new file mode 100644
index 0000000..9a1b161
--- /dev/null
+++ b/java/com/android/internal/annotations/CachedProperty.java
@@ -0,0 +1,75 @@
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
+package com.android.internal.annotations;
+
+import java.lang.annotation.ElementType;
+import java.lang.annotation.Retention;
+import java.lang.annotation.RetentionPolicy;
+import java.lang.annotation.Target;
+
+/**
+ * The annotation that generates boilerplate code required by {@link android.os.IpcDataCache}
+ * Instead of implementing IpcDataCache and adding the same code into multiple places within the
+ * same class, annotating method with CachedProperty generate the property and making sure it is
+ * thread safe if property is defined as static.
+ *
+ * To use this annotation on method, owning class needs to be annotated with
+ * {@link com.android.internal.annotations.CachedPropertyDefaults}
+ *
+ * <p>Need static IpcDataCache use @CachedProperty() or @CachedProperty(modifiers =
+ * {Modifier.STATIC}) in front of a method which calls a binder.
+ *
+ * <p>Need NON-static IpcDataCache use @CachedProperty(modifiers = {}) in front of a method which
+ * calls a binder.
+ *
+ * <p>Need to change the max capacity of cache or give custom API name use @CachedProperty(
+ * modifiers = {}, max = 1, apiName = "my_unique_key") in front of a method which calls a binder.
+ */
+@Retention(RetentionPolicy.SOURCE)
+@Target({ElementType.METHOD})
+public @interface CachedProperty {
+  /**
+   * The module under which the cache is registered {@link android.os.IpcDataCache.Config#module}.
+   * There are some well-known modules (such as {@link android.os.IpcDataCache.MODULE_SYSTEM}
+   * but any string is permitted. New modules needs to be registered.
+   * When the module is empty, then the module will be the same value as defined in
+   * CachedPropertyDefaults.
+   */
+  String module() default "";
+
+  /**
+   * The name of the {@link android.os.IpcDataCache.Config#api}
+   * When the api is empty, the api name will be the same value as defined in
+   * class level annotation {@link com.android.internal.annotations.CachedPropertyDefaults}.
+   */
+  String api() default "";
+
+  /**
+   * The maximum number of entries in the cache {@link android.os.IpcDataCache.Config#maxEntries}
+   * When the value is -1, the value will be the same value as defined in
+   * class level annotation {@link com.android.internal.annotations.CachedPropertyDefaults}.
+   */
+  int max() default -1;
+
+  /**
+   * Specify modifiers for generating cached property. By default it will be static property.
+   * This modifiers will apply when flag is on or does not exist.
+   * TODO: Add support for flag modifiers. b/361731022
+   */
+  CacheModifier[] modsFlagOnOrNone() default { CacheModifier.STATIC };
+}
+
diff --git a/java/com/android/internal/annotations/CachedPropertyDefaults.java b/java/com/android/internal/annotations/CachedPropertyDefaults.java
new file mode 100644
index 0000000..435c82b
--- /dev/null
+++ b/java/com/android/internal/annotations/CachedPropertyDefaults.java
@@ -0,0 +1,49 @@
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
+package com.android.internal.annotations;
+
+import java.lang.annotation.ElementType;
+import java.lang.annotation.Retention;
+import java.lang.annotation.RetentionPolicy;
+import java.lang.annotation.Target;
+
+/**
+ * The annotation that generates default values for {@link CachedProperty} within class.
+ * This annotation is rquired on class level when intending to use {@link CachedProperty}
+ * annotation within that class.
+ *
+ * <p>To use, annotate the class with {@code @CachedPropertyDefaults}. By default it has a maximum
+ * capacity of 4 and stores in the "system_server" module
+ * {@link android.os.IpcDataCache.MODULE_SYSTEM}. Both parameters can be overwritten and will be
+ * used as default for each property inside of annotated class, eg:
+ * {@code @CachedPropertyDefaults(module = "my_custom_module", max=32)}
+ *
+ */
+@Retention(RetentionPolicy.SOURCE)
+@Target(ElementType.TYPE)
+public @interface CachedPropertyDefaults {
+  /**
+   * The module name under which the {@link android.os.IpcDataCache} will be registered, by default it is
+   * "system_server".
+   */
+  String module() default "system_server";
+
+  /**
+   * The default number of entries in the {@link android.os.IpcDataCache}.
+   */
+  int max() default 32;
+}
diff --git a/java/com/android/internal/annotations/WeaklyReferencedCallback.java b/java/com/android/internal/annotations/WeaklyReferencedCallback.java
new file mode 100644
index 0000000..1f4f8c0
--- /dev/null
+++ b/java/com/android/internal/annotations/WeaklyReferencedCallback.java
@@ -0,0 +1,35 @@
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
+package com.android.internal.annotations;
+
+import static java.lang.annotation.ElementType.TYPE;
+
+import java.lang.annotation.Retention;
+import java.lang.annotation.RetentionPolicy;
+import java.lang.annotation.Target;
+
+/**
+ * Descriptive annotation for clearly tagging callback types that are weakly
+ * referenced during registration.
+ *
+ * <p>This is useful in providing hints to tools about certain fields that
+ * should be kept to preserve a strong reference when used downstream as a weak
+ * reference.
+ */
+@Retention(RetentionPolicy.CLASS)
+@Target({TYPE})
+public @interface WeaklyReferencedCallback {}
\ No newline at end of file
diff --git a/java/com/android/internal/util/StateMachine.java b/java/com/android/internal/util/StateMachine.java
index b2410a2..aed11ba 100644
--- a/java/com/android/internal/util/StateMachine.java
+++ b/java/com/android/internal/util/StateMachine.java
@@ -810,14 +810,15 @@ public class StateMachine {
                 if (mDbg) mSm.log("handleMessage: E msg.what=" + msg.what);
 
                 // Save the current message
-                mMsg = msg;
-
+                /* Copy the "msg" to "mMsg" as "msg" will be recycled */
+                mMsg = obtainMessage();
+                mMsg.copyFrom(msg);
                 // State that processed the message
                 State msgProcessedState = null;
-                if (mIsConstructionCompleted || (mMsg.what == SM_QUIT_CMD)) {
+                if (mIsConstructionCompleted || (msg.what == SM_QUIT_CMD)) {
                     // Normal path
                     msgProcessedState = processMsg(msg);
-                } else if (mMsg.what == SM_INIT_CMD && mMsg.obj == mSmHandlerObj) {
+                } else if (msg.what == SM_INIT_CMD && msg.obj == mSmHandlerObj) {
                     // Initial one time path.
                     mIsConstructionCompleted = true;
                     invokeEnterMethods(0);
@@ -853,17 +854,17 @@ public class StateMachine {
              * and we won't log special messages SM_INIT_CMD or SM_QUIT_CMD which
              * always set msg.obj to the handler.
              */
-            boolean recordLogMsg = mSm.recordLogRec(mMsg) && (msg.obj != mSmHandlerObj);
+            boolean recordLogMsg = mSm.recordLogRec(msg) && (msg.obj != mSmHandlerObj);
 
             if (mLogRecords.logOnlyTransitions()) {
                 // Record only if there is a transition
                 if (mDestState != null) {
-                    mLogRecords.add(mSm, mMsg, mSm.getLogRecString(mMsg), msgProcessedState,
+                    mLogRecords.add(mSm, msg, mSm.getLogRecString(msg), msgProcessedState,
                             orgState, mDestState);
                 }
             } else if (recordLogMsg) {
                 // Record message
-                mLogRecords.add(mSm, mMsg, mSm.getLogRecString(mMsg), msgProcessedState, orgState,
+                mLogRecords.add(mSm, msg, mSm.getLogRecString(msg), msgProcessedState, orgState,
                         mDestState);
             }
 
diff --git a/java/com/android/modules/expresslog/Counter.java b/java/com/android/modules/expresslog/Counter.java
index bcacb8b..fbe5e65 100644
--- a/java/com/android/modules/expresslog/Counter.java
+++ b/java/com/android/modules/expresslog/Counter.java
@@ -49,7 +49,9 @@ public final class Counter {
     public static void logIncrement(@NonNull String metricId, long amount) {
         final long metricIdHash =
                 MetricIds.getMetricIdHash(metricId, MetricIds.METRIC_TYPE_COUNTER);
-        StatsExpressLog.write(StatsExpressLog.EXPRESS_EVENT_REPORTED, metricIdHash, amount);
+        if (metricIdHash != MetricIds.INVALID_METRIC_ID) {
+          StatsExpressLog.write(StatsExpressLog.EXPRESS_EVENT_REPORTED, metricIdHash, amount);
+        }
     }
 
     /**
@@ -61,7 +63,9 @@ public final class Counter {
     public static void logIncrementWithUid(@NonNull String metricId, int uid, long amount) {
         final long metricIdHash =
                 MetricIds.getMetricIdHash(metricId, MetricIds.METRIC_TYPE_COUNTER_WITH_UID);
-        StatsExpressLog.write(
-            StatsExpressLog.EXPRESS_UID_EVENT_REPORTED, metricIdHash, amount, uid);
+        if (metricIdHash != MetricIds.INVALID_METRIC_ID) {
+          StatsExpressLog.write(
+              StatsExpressLog.EXPRESS_UID_EVENT_REPORTED, metricIdHash, amount, uid);
+        }
     }
 }
diff --git a/java/com/android/modules/expresslog/Histogram.java b/java/com/android/modules/expresslog/Histogram.java
index 4f61c85..cab72b7 100644
--- a/java/com/android/modules/expresslog/Histogram.java
+++ b/java/com/android/modules/expresslog/Histogram.java
@@ -46,9 +46,11 @@ public final class Histogram {
      */
     public void logSample(float sample) {
         final long hash = MetricIds.getMetricIdHash(mMetricId, MetricIds.METRIC_TYPE_HISTOGRAM);
-        final int binIndex = mBinOptions.getBinForSample(sample);
-        StatsExpressLog.write(
-                StatsExpressLog.EXPRESS_HISTOGRAM_SAMPLE_REPORTED, hash, /*count*/ 1, binIndex);
+        if (hash != MetricIds.INVALID_METRIC_ID) {
+          final int binIndex = mBinOptions.getBinForSample(sample);
+          StatsExpressLog.write(
+              StatsExpressLog.EXPRESS_HISTOGRAM_SAMPLE_REPORTED, hash, /*count*/ 1, binIndex);
+        }
     }
 
     /**
@@ -60,13 +62,12 @@ public final class Histogram {
     public void logSampleWithUid(int uid, float sample) {
         final long hash =
                 MetricIds.getMetricIdHash(mMetricId, MetricIds.METRIC_TYPE_HISTOGRAM_WITH_UID);
-        final int binIndex = mBinOptions.getBinForSample(sample);
-        StatsExpressLog.write(
-                StatsExpressLog.EXPRESS_UID_HISTOGRAM_SAMPLE_REPORTED,
-                hash, /*count*/
-                1,
-                binIndex,
-                uid);
+        if (hash != MetricIds.INVALID_METRIC_ID) {
+          final int binIndex = mBinOptions.getBinForSample(sample);
+          StatsExpressLog.write(StatsExpressLog.EXPRESS_UID_HISTOGRAM_SAMPLE_REPORTED,
+              hash, /*count*/
+              1, binIndex, uid);
+        }
     }
 
     /** Used by Histogram to map data sample to corresponding bin */
diff --git a/java/com/android/modules/utils/Android.bp b/java/com/android/modules/utils/Android.bp
index cb4aca1..02fc4e9 100644
--- a/java/com/android/modules/utils/Android.bp
+++ b/java/com/android/modules/utils/Android.bp
@@ -109,3 +109,18 @@ java_library {
     defaults: ["modules-utils-defaults"],
     srcs: ["BasicShellCommandHandler.java"],
 }
+
+java_library {
+    name: "modules-utils-infra",
+    defaults: ["modules-utils-defaults"],
+    srcs: [
+        "AndroidFuture.java",
+        "ServiceConnector.java",
+        ":module-utils-future-aidls",
+    ],
+    static_libs: [
+        "modules-utils-handlerexecutor",
+        "modules-utils-preconditions",
+    ],
+    min_sdk_version: "33",
+}
diff --git a/java/com/android/modules/utils/AndroidFuture.aidl b/java/com/android/modules/utils/AndroidFuture.aidl
new file mode 100644
index 0000000..9a16cfa
--- /dev/null
+++ b/java/com/android/modules/utils/AndroidFuture.aidl
@@ -0,0 +1,20 @@
+/*
+** Copyright 2019, The Android Open Source Project
+**
+** Licensed under the Apache License, Version 2.0 (the "License");
+** you may not use this file except in compliance with the License.
+** You may obtain a copy of the License at
+**
+**     http://www.apache.org/licenses/LICENSE-2.0
+**
+** Unless required by applicable law or agreed to in writing, software
+** distributed under the License is distributed on an "AS IS" BASIS,
+** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+** See the License for the specific language governing permissions and
+** limitations under the License.
+*/
+
+package com.android.modules.utils;
+
+/** @hide */
+@JavaOnlyStableParcelable  parcelable AndroidFuture<T>;
\ No newline at end of file
diff --git a/java/com/android/modules/utils/AndroidFuture.java b/java/com/android/modules/utils/AndroidFuture.java
new file mode 100644
index 0000000..887f4a8
--- /dev/null
+++ b/java/com/android/modules/utils/AndroidFuture.java
@@ -0,0 +1,650 @@
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
+package com.android.modules.utils;
+
+import android.annotation.CallSuper;
+import android.annotation.NonNull;
+import android.annotation.Nullable;
+import android.os.Handler;
+import android.os.Looper;
+import android.os.Parcel;
+import android.os.Parcelable;
+import android.os.RemoteException;
+import android.util.Log;
+
+import com.android.internal.annotations.GuardedBy;
+import com.android.internal.util.Preconditions;
+
+import java.lang.reflect.Constructor;
+import java.util.concurrent.CancellationException;
+import java.util.concurrent.CompletableFuture;
+import java.util.concurrent.CompletionStage;
+import java.util.concurrent.ExecutionException;
+import java.util.concurrent.Executor;
+import java.util.concurrent.TimeUnit;
+import java.util.concurrent.TimeoutException;
+import java.util.function.BiConsumer;
+import java.util.function.BiFunction;
+import java.util.function.Function;
+import java.util.function.Supplier;
+
+/**
+ * A customized {@link CompletableFuture} with focus on reducing the number of allocations involved
+ * in a typical future usage scenario for Android.
+ *
+ * <p>
+ * In particular this involves allocations optimizations in:
+ * <ul>
+ *     <li>{@link #thenCompose(Function)}</li>
+ *     <li>{@link #thenApply(Function)}</li>
+ *     <li>{@link #thenCombine(CompletionStage, BiFunction)}</li>
+ *     <li>{@link #orTimeout(long, TimeUnit)}</li>
+ *     <li>{@link #whenComplete(BiConsumer)}</li>
+ * </ul>
+ * As well as their *Async versions.
+ *
+ * <p>
+ * You can pass {@link AndroidFuture} across an IPC.
+ * When doing so, completing the future on the other side will propagate the completion back,
+ * effectively acting as an error-aware remote callback.
+ *
+ * <p>
+ * {@link AndroidFuture} is {@link Parcelable} iff its wrapped type {@code T} is
+ * effectively parcelable, i.e. is supported by {@link Parcel#readValue}/{@link Parcel#writeValue}.
+ *
+ * @param <T> see {@link CompletableFuture}
+ * @hide
+ */
+public class AndroidFuture<T> extends CompletableFuture<T> implements Parcelable {
+
+    private static final boolean DEBUG = false;
+    private static final String LOG_TAG = AndroidFuture.class.getSimpleName();
+    private static final Executor DIRECT_EXECUTOR = Runnable::run;
+    private static final StackTraceElement[] EMPTY_STACK_TRACE = new StackTraceElement[0];
+    private static @Nullable Handler sMainHandler;
+
+    private final @NonNull Object mLock = new Object();
+    @GuardedBy("mLock")
+    private @Nullable BiConsumer<? super T, ? super Throwable> mListener;
+    @GuardedBy("mLock")
+    private @Nullable Executor mListenerExecutor = DIRECT_EXECUTOR;
+    private @NonNull Handler mTimeoutHandler = getMainHandler();
+    private final @Nullable IAndroidFuture mRemoteOrigin;
+
+    public AndroidFuture() {
+        super();
+        mRemoteOrigin = null;
+    }
+
+    AndroidFuture(Parcel in) {
+        super();
+        if (in.readBoolean()) {
+            // Done
+            if (in.readBoolean()) {
+                // Failed
+                completeExceptionally(readThrowable(in));
+            } else {
+                // Success
+                complete((T) in.readValue(null));
+            }
+            mRemoteOrigin = null;
+        } else {
+            // Not done
+            mRemoteOrigin = IAndroidFuture.Stub.asInterface(in.readStrongBinder());
+        }
+    }
+
+    @NonNull
+    private static Handler getMainHandler() {
+        // This isn't thread-safe but we are okay with it.
+        if (sMainHandler == null) {
+            sMainHandler = new Handler(Looper.getMainLooper());
+        }
+        return sMainHandler;
+    }
+
+    /**
+     * Create a completed future with the given value.
+     *
+     * @param value the value for the completed future
+     * @param <U> the type of the value
+     * @return the completed future
+     */
+    @NonNull
+    public static <U> AndroidFuture<U> completedFuture(U value) {
+        AndroidFuture<U> future = new AndroidFuture<>();
+        future.complete(value);
+        return future;
+    }
+
+    @Override
+    public boolean complete(@Nullable T value) {
+        boolean changed = super.complete(value);
+        if (changed) {
+            onCompleted(value, null);
+        }
+        return changed;
+    }
+
+    @Override
+    public boolean completeExceptionally(@NonNull Throwable ex) {
+        boolean changed = super.completeExceptionally(ex);
+        if (changed) {
+            onCompleted(null, ex);
+        }
+        return changed;
+    }
+
+    @Override
+    public boolean cancel(boolean mayInterruptIfRunning) {
+        boolean changed = super.cancel(mayInterruptIfRunning);
+        if (changed) {
+            try {
+                get();
+                throw new IllegalStateException("Expected CancellationException");
+            } catch (CancellationException ex) {
+                onCompleted(null, ex);
+            } catch (Throwable e) {
+                throw new IllegalStateException("Expected CancellationException", e);
+            }
+        }
+        return changed;
+    }
+
+    @CallSuper
+    protected void onCompleted(@Nullable T res, @Nullable Throwable err) {
+        cancelTimeout();
+
+        if (DEBUG) {
+            Log.i(LOG_TAG, this + " completed with result " + (err == null ? res : err),
+                    new RuntimeException());
+        }
+
+        BiConsumer<? super T, ? super Throwable> listener;
+        synchronized (mLock) {
+            listener = mListener;
+            mListener = null;
+        }
+
+        if (listener != null) {
+            callListenerAsync(listener, res, err);
+        }
+
+        if (mRemoteOrigin != null) {
+            try {
+                mRemoteOrigin.complete(this /* resultContainer */);
+            } catch (RemoteException e) {
+                Log.e(LOG_TAG, "Failed to propagate completion", e);
+            }
+        }
+    }
+
+    @Override
+    public AndroidFuture<T> whenComplete(@NonNull BiConsumer<? super T, ? super Throwable> action) {
+        return whenCompleteAsync(action, DIRECT_EXECUTOR);
+    }
+
+    @Override
+    public AndroidFuture<T> whenCompleteAsync(
+            @NonNull BiConsumer<? super T, ? super Throwable> action,
+            @NonNull Executor executor) {
+        Preconditions.checkNotNull(action);
+        Preconditions.checkNotNull(executor);
+        synchronized (mLock) {
+            if (!isDone()) {
+                BiConsumer<? super T, ? super Throwable> oldListener = mListener;
+
+                if (oldListener != null && executor != mListenerExecutor) {
+                    // 2 listeners with different executors
+                    // Too complex - give up on saving allocations and delegate to superclass
+                    super.whenCompleteAsync(action, executor);
+                    return this;
+                }
+
+                mListenerExecutor = executor;
+                mListener = oldListener == null
+                        ? action
+                        : (res, err) -> {
+                            callListener(oldListener, res, err);
+                            callListener(action, res, err);
+                        };
+                return this;
+            }
+        }
+
+        // isDone() == true at this point
+        T res = null;
+        Throwable err = null;
+        try {
+            res = get();
+        } catch (ExecutionException e) {
+            err = e.getCause();
+        } catch (Throwable e) {
+            err = e;
+        }
+        callListenerAsync(action, res, err);
+        return this;
+    }
+
+    private void callListenerAsync(BiConsumer<? super T, ? super Throwable> listener,
+            @Nullable T res, @Nullable Throwable err) {
+      synchronized (mLock) {
+        if (mListenerExecutor == DIRECT_EXECUTOR) {
+            callListener(listener, res, err);
+        } else {
+            mListenerExecutor.execute(() -> callListener(listener, res, err));
+        }
+      }
+    }
+
+    /**
+     * Calls the provided listener, handling any exceptions that may arise.
+     */
+    // package-private to avoid synthetic method when called from lambda
+    static <TT> void callListener(
+            @NonNull BiConsumer<? super TT, ? super Throwable> listener,
+            @Nullable TT res, @Nullable Throwable err) {
+        try {
+            try {
+                listener.accept(res, err);
+            } catch (Throwable t) {
+                if (err == null) {
+                    // listener happy-case threw, but exception case might not throw, so report the
+                    // same exception thrown by listener's happy-path to it again
+                    listener.accept(null, t);
+                } else {
+                    // listener exception-case threw
+                    // give up on listener but preserve the original exception when throwing up
+                    t.addSuppressed(err);
+                    throw t;
+                }
+            }
+        } catch (Throwable t2) {
+            // give up on listener and log the result & exception to logcat
+            Log.e(LOG_TAG, "Failed to call whenComplete listener. res = " + res, t2);
+        }
+    }
+
+    /** @inheritDoc */
+    //@Override //TODO uncomment once java 9 APIs are exposed to frameworks
+    public AndroidFuture<T> orTimeout(long timeout, @NonNull TimeUnit unit) {
+        mTimeoutHandler.postDelayed(this::triggerTimeout, this, unit.toMillis(timeout));
+        return this;
+    }
+
+    void triggerTimeout() {
+        cancelTimeout();
+        if (!isDone()) {
+            completeExceptionally(new TimeoutException());
+        }
+    }
+
+    /**
+     * Cancel all timeouts previously set with {@link #orTimeout}, if any.
+     *
+     * @return {@code this} for chaining
+     */
+    public AndroidFuture<T> cancelTimeout() {
+        mTimeoutHandler.removeCallbacksAndMessages(this);
+        return this;
+    }
+
+    /**
+     * Specifies the handler on which timeout is to be triggered
+     */
+    public AndroidFuture<T> setTimeoutHandler(@NonNull Handler h) {
+        cancelTimeout();
+        mTimeoutHandler = Preconditions.checkNotNull(h);
+        return this;
+    }
+
+    @Override
+    public <U> AndroidFuture<U> thenCompose(
+            @NonNull Function<? super T, ? extends CompletionStage<U>> fn) {
+        return thenComposeAsync(fn, DIRECT_EXECUTOR);
+    }
+
+    @Override
+    public <U> AndroidFuture<U> thenComposeAsync(
+            @NonNull Function<? super T, ? extends CompletionStage<U>> fn,
+            @NonNull Executor executor) {
+        return new ThenComposeAsync<>(this, fn, executor);
+    }
+
+    private static class ThenComposeAsync<T, U> extends AndroidFuture<U>
+            implements BiConsumer<Object, Throwable>, Runnable {
+        private volatile T mSourceResult = null;
+        private final Executor mExecutor;
+        private volatile Function<? super T, ? extends CompletionStage<U>> mFn;
+
+        ThenComposeAsync(@NonNull AndroidFuture<T> source,
+                @NonNull Function<? super T, ? extends CompletionStage<U>> fn,
+                @NonNull Executor executor) {
+            mFn = Preconditions.checkNotNull(fn);
+            mExecutor = Preconditions.checkNotNull(executor);
+
+            // subscribe to first job completion
+            source.whenComplete(this);
+        }
+
+        @Override
+        public void accept(Object res, Throwable err) {
+            if (err != null) {
+                // first or second job failed
+                completeExceptionally(err);
+            } else if (mFn != null) {
+                // first job completed
+                mSourceResult = (T) res;
+                // subscribe to second job completion asynchronously
+                mExecutor.execute(this);
+            } else {
+                // second job completed
+                complete((U) res);
+            }
+        }
+
+        @Override
+        public void run() {
+            CompletionStage<U> secondJob;
+            try {
+                secondJob = Preconditions.checkNotNull(mFn.apply(mSourceResult));
+            } catch (Throwable t) {
+                completeExceptionally(t);
+                return;
+            } finally {
+                // Marks first job complete
+                mFn = null;
+            }
+            // subscribe to second job completion
+            secondJob.whenComplete(this);
+        }
+    }
+
+    @Override
+    public <U> AndroidFuture<U> thenApply(@NonNull Function<? super T, ? extends U> fn) {
+        return thenApplyAsync(fn, DIRECT_EXECUTOR);
+    }
+
+    @Override
+    public <U> AndroidFuture<U> thenApplyAsync(@NonNull Function<? super T, ? extends U> fn,
+            @NonNull Executor executor) {
+        return new ThenApplyAsync<>(this, fn, executor);
+    }
+
+    private static class ThenApplyAsync<T, U> extends AndroidFuture<U>
+            implements BiConsumer<T, Throwable>, Runnable {
+        private volatile T mSourceResult = null;
+        private final Executor mExecutor;
+        private final Function<? super T, ? extends U> mFn;
+
+        ThenApplyAsync(@NonNull AndroidFuture<T> source,
+                @NonNull Function<? super T, ? extends U> fn,
+                @NonNull Executor executor) {
+            mExecutor = Preconditions.checkNotNull(executor);
+            mFn = Preconditions.checkNotNull(fn);
+
+            // subscribe to job completion
+            source.whenComplete(this);
+        }
+
+        @Override
+        public void accept(T res, Throwable err) {
+            if (err != null) {
+                completeExceptionally(err);
+            } else {
+                mSourceResult = res;
+                mExecutor.execute(this);
+            }
+        }
+
+        @Override
+        public void run() {
+            try {
+                complete(mFn.apply(mSourceResult));
+            } catch (Throwable t) {
+                completeExceptionally(t);
+            }
+        }
+    }
+
+    @Override
+    public <U, V> AndroidFuture<V> thenCombine(
+            @NonNull CompletionStage<? extends U> other,
+            @NonNull BiFunction<? super T, ? super U, ? extends V> combineResults) {
+        return new ThenCombine<T, U, V>(this, other, combineResults);
+    }
+
+    /** @see CompletionStage#thenCombine */
+    public AndroidFuture<T> thenCombine(@NonNull CompletionStage<Void> other) {
+        return thenCombine(other, (res, aVoid) -> res);
+    }
+
+    private static class ThenCombine<T, U, V> extends AndroidFuture<V>
+            implements BiConsumer<Object, Throwable> {
+        private volatile @Nullable T mResultT = null;
+        private volatile @NonNull CompletionStage<? extends U> mSourceU;
+        private final @NonNull BiFunction<? super T, ? super U, ? extends V> mCombineResults;
+
+        ThenCombine(CompletableFuture<T> sourceT,
+                CompletionStage<? extends U> sourceU,
+                BiFunction<? super T, ? super U, ? extends V> combineResults) {
+            mSourceU = Preconditions.checkNotNull(sourceU);
+            mCombineResults = Preconditions.checkNotNull(combineResults);
+
+            sourceT.whenComplete(this);
+        }
+
+        @Override
+        public void accept(Object res, Throwable err) {
+            if (err != null) {
+                completeExceptionally(err);
+                return;
+            }
+
+            if (mSourceU != null) {
+                // T done
+                mResultT = (T) res;
+
+                // Subscribe to the second job completion.
+                mSourceU.whenComplete((r, e) -> {
+                    // Mark the first job completion by setting mSourceU to null, so that next time
+                    // the execution flow goes to the else case below.
+                    mSourceU = null;
+                    accept(r, e);
+                });
+            } else {
+                // U done
+                try {
+                    complete(mCombineResults.apply(mResultT, (U) res));
+                } catch (Throwable t) {
+                    completeExceptionally(t);
+                }
+            }
+        }
+    }
+
+    /**
+     * Similar to {@link CompletableFuture#supplyAsync} but
+     * runs the given action directly.
+     *
+     * The resulting future is immediately completed.
+     */
+    public static <T> AndroidFuture<T> supply(Supplier<T> supplier) {
+        return supplyAsync(supplier, DIRECT_EXECUTOR);
+    }
+
+    /**
+     * @see CompletableFuture#supplyAsync(Supplier, Executor)
+     */
+    public static <T> AndroidFuture<T> supplyAsync(Supplier<T> supplier, Executor executor) {
+        return new SupplyAsync<>(supplier, executor);
+    }
+
+    private static class SupplyAsync<T> extends AndroidFuture<T> implements Runnable {
+        private final @NonNull Supplier<T> mSupplier;
+
+        SupplyAsync(Supplier<T> supplier, Executor executor) {
+            mSupplier = supplier;
+            executor.execute(this);
+        }
+
+        @Override
+        public void run() {
+            try {
+                complete(mSupplier.get());
+            } catch (Throwable t) {
+                completeExceptionally(t);
+            }
+        }
+    }
+
+    @Override
+    public void writeToParcel(Parcel dest, int flags) {
+        boolean done = isDone();
+        dest.writeBoolean(done);
+        if (done) {
+            T result;
+            try {
+                result = get();
+            } catch (Throwable t) {
+                dest.writeBoolean(true);
+                writeThrowable(dest, unwrapExecutionException(t));
+                return;
+            }
+            dest.writeBoolean(false);
+            dest.writeValue(result);
+        } else {
+            dest.writeStrongBinder(new IAndroidFuture.Stub() {
+                @Override
+                public void complete(AndroidFuture resultContainer) {
+                    boolean changed;
+                    try {
+                        changed = AndroidFuture.this.complete((T) resultContainer.get());
+                    } catch (Throwable t) {
+                        changed = completeExceptionally(unwrapExecutionException(t));
+                    }
+                    if (!changed) {
+                        Log.w(LOG_TAG, "Remote result " + resultContainer
+                                + " ignored, as local future is already completed: "
+                                + AndroidFuture.this);
+                    }
+                }
+            }.asBinder());
+        }
+    }
+
+    /**
+     * Exceptions coming out of {@link #get} are wrapped in {@link ExecutionException}
+     */
+    Throwable unwrapExecutionException(Throwable t) {
+        return t instanceof ExecutionException
+                ? t.getCause()
+                : t;
+    }
+
+    /**
+     * Alternative to {@link Parcel#writeException} that stores the stack trace, in a
+     * way consistent with the binder IPC exception propagation behavior.
+     */
+    private static void writeThrowable(@NonNull Parcel parcel, @Nullable Throwable throwable) {
+        boolean hasThrowable = throwable != null;
+        parcel.writeBoolean(hasThrowable);
+        if (!hasThrowable) {
+            return;
+        }
+
+        boolean isFrameworkParcelable = throwable instanceof Parcelable
+                && throwable.getClass().getClassLoader() == Parcelable.class.getClassLoader();
+        parcel.writeBoolean(isFrameworkParcelable);
+        if (isFrameworkParcelable) {
+            parcel.writeParcelable((Parcelable) throwable,
+                    Parcelable.PARCELABLE_WRITE_RETURN_VALUE);
+            return;
+        }
+
+        parcel.writeString(throwable.getClass().getName());
+        parcel.writeString(throwable.getMessage());
+        StackTraceElement[] stackTrace = throwable.getStackTrace();
+        StringBuilder stackTraceBuilder = new StringBuilder();
+        int truncatedStackTraceLength = Math.min(stackTrace != null ? stackTrace.length : 0, 5);
+        for (int i = 0; i < truncatedStackTraceLength; i++) {
+            if (i > 0) {
+                stackTraceBuilder.append('\n');
+            }
+            stackTraceBuilder.append("\tat ").append(stackTrace[i]);
+        }
+        parcel.writeString(stackTraceBuilder.toString());
+        writeThrowable(parcel, throwable.getCause());
+    }
+
+    /**
+     * @see #writeThrowable
+     */
+    @SuppressWarnings("UnsafeParcelApi")
+    private static @Nullable Throwable readThrowable(@NonNull Parcel parcel) {
+        final boolean hasThrowable = parcel.readBoolean();
+        if (!hasThrowable) {
+            return null;
+        }
+
+        boolean isFrameworkParcelable = parcel.readBoolean();
+        if (isFrameworkParcelable) {
+            return parcel.readParcelable(Parcelable.class.getClassLoader());
+        }
+
+        String className = parcel.readString();
+        String message = parcel.readString();
+        String stackTrace = parcel.readString();
+        String messageWithStackTrace = message + '\n' + stackTrace;
+        Throwable throwable;
+        try {
+            Class<?> clazz = Class.forName(className, true, Parcelable.class.getClassLoader());
+            if (Throwable.class.isAssignableFrom(clazz)) {
+                Constructor<?> constructor = clazz.getConstructor(String.class);
+                throwable = (Throwable) constructor.newInstance(messageWithStackTrace);
+            } else {
+                android.util.EventLog.writeEvent(0x534e4554, "186530450", -1, "");
+                throwable = new RuntimeException(className + ": " + messageWithStackTrace);
+            }
+        } catch (Throwable t) {
+            throwable = new RuntimeException(className + ": " + messageWithStackTrace);
+            throwable.addSuppressed(t);
+        }
+        throwable.setStackTrace(EMPTY_STACK_TRACE);
+        Throwable cause = readThrowable(parcel);
+        if (cause != null) {
+            throwable.initCause(cause);
+        }
+        return throwable;
+    }
+
+    @Override
+    public int describeContents() {
+        return 0;
+    }
+
+    public static final @NonNull Parcelable.Creator<AndroidFuture> CREATOR =
+            new Parcelable.Creator<AndroidFuture>() {
+                public AndroidFuture createFromParcel(Parcel parcel) {
+                    return new AndroidFuture(parcel);
+                }
+
+                public AndroidFuture[] newArray(int size) {
+                    return new AndroidFuture[size];
+                }
+            };
+}
diff --git a/java/com/android/modules/utils/IAndroidFuture.aidl b/java/com/android/modules/utils/IAndroidFuture.aidl
new file mode 100644
index 0000000..bbf7daa
--- /dev/null
+++ b/java/com/android/modules/utils/IAndroidFuture.aidl
@@ -0,0 +1,24 @@
+/*
+** Copyright 2019, The Android Open Source Project
+**
+** Licensed under the Apache License, Version 2.0 (the "License");
+** you may not use this file except in compliance with the License.
+** You may obtain a copy of the License at
+**
+**     http://www.apache.org/licenses/LICENSE-2.0
+**
+** Unless required by applicable law or agreed to in writing, software
+** distributed under the License is distributed on an "AS IS" BASIS,
+** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+** See the License for the specific language governing permissions and
+** limitations under the License.
+*/
+
+package com.android.modules.utils;
+
+import com.android.modules.utils.AndroidFuture;
+
+/** @hide */
+oneway interface IAndroidFuture {
+    void complete(in AndroidFuture resultContainer);
+}
\ No newline at end of file
diff --git a/java/com/android/modules/utils/ServiceConnector.java b/java/com/android/modules/utils/ServiceConnector.java
new file mode 100644
index 0000000..f50aab3
--- /dev/null
+++ b/java/com/android/modules/utils/ServiceConnector.java
@@ -0,0 +1,852 @@
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
+package com.android.modules.utils;
+
+import android.annotation.CheckResult;
+import android.annotation.NonNull;
+import android.annotation.Nullable;
+import android.annotation.UserIdInt;
+import android.content.ComponentName;
+import android.content.Context;
+import android.content.Intent;
+import android.content.ServiceConnection;
+import android.os.Handler;
+import android.os.IBinder;
+import android.os.IInterface;
+import android.os.Looper;
+import android.os.RemoteException;
+import android.os.UserHandle;
+import android.util.Log;
+import android.util.Slog;
+
+import java.io.PrintWriter;
+import java.util.ArrayDeque;
+import java.util.ArrayList;
+import java.util.Arrays;
+import java.util.List;
+import java.util.Objects;
+import java.util.Queue;
+import java.util.concurrent.CompletableFuture;
+import java.util.concurrent.CompletionStage;
+import java.util.concurrent.Executor;
+import java.util.concurrent.TimeUnit;
+import java.util.function.BiConsumer;
+import java.util.function.Function;
+
+/**
+ * Takes care of managing a {@link ServiceConnection} and auto-disconnecting from the service upon
+ * a certain timeout.
+ *
+ * <p>
+ * The requests are always processed in the order they are scheduled.
+ *
+ * <p>
+ * Use {@link ServiceConnector.Impl} to construct an instance.
+ *
+ * @param <I> the type of the {@link IInterface ipc interface} for the remote service
+ * @hide
+ */
+public interface ServiceConnector<I extends IInterface> {
+
+    /**
+     * Schedules to run a given job when service is connected, without providing any means to track
+     * the job's completion.
+     *
+     * <p>
+     * This is slightly more efficient than {@link #post(VoidJob)} as it doesn't require an extra
+     * allocation of a {@link AndroidFuture} for progress tracking.
+     *
+     * @return whether a job was successfully scheduled
+     */
+    boolean run(@NonNull VoidJob<I> job);
+
+    /**
+     * Schedules to run a given job when service is connected.
+     *
+     * <p>
+     * You can choose to wait for the job synchronously using {@link AndroidFuture#get} or
+     * attach a listener to it using one of the options such as
+     * {@link AndroidFuture#whenComplete}
+     * You can also {@link AndroidFuture#cancel cancel} the pending job.
+     *
+     * @return a {@link AndroidFuture} tracking the job's completion
+     *
+     * @see #postForResult(Job) for a variant of this that also propagates an arbitrary result
+     *                          back to the caller
+     * @see CompletableFuture for more options on what you can do with a result of an asynchronous
+     *                        operation, including more advanced operations such as
+     *                        {@link CompletableFuture#thenApply transforming} its result,
+     *                        {@link CompletableFuture#thenCombine joining}
+     *                        results of multiple async operation into one,
+     *                        {@link CompletableFuture#thenCompose composing} results of
+     *                        multiple async operations that depend on one another, and more.
+     */
+    @CheckResult(suggest = "#fireAndForget")
+    AndroidFuture<Void> post(@NonNull VoidJob<I> job);
+
+    /**
+     * Variant of {@link #post(VoidJob)} that also propagates an arbitrary result back to the
+     * caller asynchronously.
+     *
+     * @param <R> the type of the result this job produces
+     *
+     * @see #post(VoidJob)
+     */
+    @CheckResult(suggest = "#fireAndForget")
+    <R> AndroidFuture<R> postForResult(@NonNull Job<I, R> job);
+
+    /**
+     * Schedules a job that is itself asynchronous, that is job returns a result in the form of a
+     * {@link CompletableFuture}
+     *
+     * <p>
+     * This takes care of "flattening" the nested futures that would have resulted from 2
+     * asynchronous operations performed in sequence.
+     *
+     * <p>
+     * Like with other options, {@link AndroidFuture#cancel cancelling} the resulting future
+     * will remove the job from the queue, preventing it from running if it hasn't yet started.
+     *
+     * @see #postForResult
+     * @see #post
+     */
+    <R> AndroidFuture<R> postAsync(@NonNull Job<I, CompletableFuture<R>> job);
+
+    /**
+     * Requests to connect to the service without posting any meaningful job to run.
+     *
+     * <p>
+     * This returns a {@link AndroidFuture} tracking the progress of binding to the service,
+     * which can be used to schedule calls to the service once it's connected.
+     *
+     * <p>
+     * Avoid caching the resulting future as the instance may change due to service disconnecting
+     * and reconnecting.
+     */
+    AndroidFuture<I> connect();
+
+    /**
+     * Request to unbind from the service as soon as possible.
+     *
+     * <p>
+     * If there are any pending jobs remaining they will be
+     * {@link AndroidFuture#cancel cancelled}.
+     */
+    void unbind();
+
+    /**
+     * Registers a {@link ServiceLifecycleCallbacks callbacks} to be invoked when the lifecycle
+     * of the managed service changes.
+     *
+     * @param callbacks The callbacks that will be run, or {@code null} to clear the existing
+     *                 callbacks.
+     */
+    void setServiceLifecycleCallbacks(@Nullable ServiceLifecycleCallbacks<I> callbacks);
+
+    /**
+     * A request to be run when the service is
+     * {@link ServiceConnection#onServiceConnected connected}.
+     *
+     * @param <II> type of the {@link IInterface ipc interface} to be used
+     * @param <R> type of the return value
+     *
+     * @see VoidJob for a variant that doesn't produce any return value
+     */
+    @FunctionalInterface
+    interface Job<II, R> {
+
+        /**
+         * Perform the remote call using the provided {@link IInterface ipc interface instance}.
+         *
+         * Avoid caching the provided {@code service} instance as it may become invalid when service
+         * disconnects.
+         *
+         * @return the result of this operation to be propagated to the original caller.
+         *         If you do not need to provide a result you can implement {@link VoidJob} instead
+         */
+        R run(@NonNull II service) throws Exception;
+
+    }
+
+    /**
+     * Variant of {@link Job} that doesn't return a result
+     *
+     * @param <II> see {@link Job}
+     */
+    @FunctionalInterface
+    interface VoidJob<II> extends Job<II, Void> {
+
+        /** @see Job#run */
+        void runNoResult(II service) throws Exception;
+
+        @Override
+        default Void run(II service) throws Exception {
+            runNoResult(service);
+            return null;
+        }
+    }
+
+    /**
+     * Collection of callbacks invoked when the lifecycle of the service changes.
+     *
+     * @param <II> the type of the {@link IInterface ipc interface} for the remote service
+     * @see ServiceConnector#setServiceLifecycleCallbacks(ServiceLifecycleCallbacks)
+     */
+    interface ServiceLifecycleCallbacks<II extends IInterface> {
+        /**
+         * Called when the service has just connected and before any queued jobs are run.
+         */
+        default void onConnected(@NonNull II service) {}
+
+        /**
+         * Called just before the service is disconnected and unbound.
+         */
+        default void onDisconnected(@NonNull II service) {}
+
+        /**
+         * Called when the service Binder has died.
+         *
+         * In cases where {@link #onBinderDied()} is invoked the service becomes unbound without
+         * a callback to {@link #onDisconnected(IInterface)}.
+         */
+        default void onBinderDied() {}
+    }
+
+
+    /**
+     * Implementation of {@link ServiceConnector}
+     *
+     * <p>
+     * For allocation-efficiency reasons this implements a bunch of interfaces that are not meant to
+     * be a public API of {@link ServiceConnector}.
+     * For this reason prefer to use {@link ServiceConnector} instead of
+     * {@link ServiceConnector.Impl} as the field type when storing an instance.
+     *
+     * <p>
+     * In some rare cases you may want to extend this class, overriding certain methods for further
+     * flexibility.
+     * If you do, it would typically be one of the {@code protected} methods on this class.
+     *
+     * @param <I> see {@link ServiceConnector}
+     */
+    class Impl<I extends IInterface> extends ArrayDeque<Job<I, ?>>
+            implements ServiceConnector<I>, ServiceConnection, IBinder.DeathRecipient, Runnable {
+
+        static final boolean DEBUG = false;
+        static final String LOG_TAG = "ServiceConnector.Impl";
+
+        private static final long DEFAULT_DISCONNECT_TIMEOUT_MS = 15_000;
+        private static final long DEFAULT_REQUEST_TIMEOUT_MS = 30_000;
+
+        private final @NonNull Queue<Job<I, ?>> mQueue = this;
+        private final @NonNull List<CompletionAwareJob<I, ?>> mUnfinishedJobs = new ArrayList<>();
+
+        private final @NonNull Handler mMainHandler = new Handler(Looper.getMainLooper());
+        private final @NonNull ServiceConnection mServiceConnection = this;
+        private final @NonNull Runnable mTimeoutDisconnect = this;
+
+        // This context contains the user information.
+        protected final @NonNull Context mContext;
+        private final @NonNull Intent mIntent;
+        private final int mBindingFlags;
+        private final @Nullable Function<IBinder, I> mBinderAsInterface;
+        private final @NonNull Handler mHandler;
+        protected final @NonNull Executor mExecutor;
+
+        @Nullable
+        private volatile ServiceLifecycleCallbacks<I> mServiceLifecycleCallbacks = null;
+        private volatile I mService = null;
+        private boolean mBinding = false;
+        private boolean mUnbinding = false;
+
+        private CompletionAwareJob<I, I> mServiceConnectionFutureCache = null;
+
+        /**
+         * Creates an instance of {@link ServiceConnector}
+         *
+         * See {@code protected} methods for optional parameters you can override.
+         *
+         * @param context to be used for {@link Context#bindServiceAsUser binding} and
+         *                {@link Context#unbindService unbinding}
+         * @param intent to be used for {@link Context#bindServiceAsUser binding}
+         * @param bindingFlags to be used for {@link Context#bindServiceAsUser binding}
+         * @param userId to be used for {@link Context#bindServiceAsUser binding}
+         * @param binderAsInterface to be used for converting an {@link IBinder} provided in
+         *                          {@link ServiceConnection#onServiceConnected} into a specific
+         *                          {@link IInterface}.
+         *                          Typically this is {@code IMyInterface.Stub::asInterface}
+         */
+        public Impl(@NonNull Context context, @NonNull Intent intent, int bindingFlags,
+                @UserIdInt int userId, @Nullable Function<IBinder, I> binderAsInterface) {
+            mContext = context.createContextAsUser(UserHandle.of(userId), 0);
+            mIntent = intent;
+            mBindingFlags = bindingFlags;
+            mBinderAsInterface = binderAsInterface;
+
+            mHandler = getJobHandler();
+            mExecutor = new HandlerExecutor(mHandler);
+        }
+
+        /**
+         * {@link Handler} on which {@link Job}s will be called
+         */
+        protected Handler getJobHandler() {
+            return mMainHandler;
+        }
+
+        /**
+         * Gets the amount of time spent without any calls before the service is automatically
+         * {@link Context#unbindService unbound}
+         *
+         * @return amount of time in ms, or non-positive (<=0) value to disable automatic unbinding
+         */
+        protected long getAutoDisconnectTimeoutMs() {
+            return DEFAULT_DISCONNECT_TIMEOUT_MS;
+        }
+
+        /**
+         * Gets the amount of time to wait for a request to complete, before finishing it with a
+         * {@link java.util.concurrent.TimeoutException}
+         *
+         * <p>
+         * This includes time spent connecting to the service, if any.
+         *
+         * @return amount of time in ms
+         */
+        protected long getRequestTimeoutMs() {
+            return DEFAULT_REQUEST_TIMEOUT_MS;
+        }
+
+        /**
+         * {@link Context#bindServiceAsUser Binds} to the service.
+         *
+         * <p>
+         * If overridden, implementation must use at least the provided {@link ServiceConnection}
+         */
+        protected boolean bindService(@NonNull ServiceConnection serviceConnection) {
+            if (DEBUG) {
+                logTrace();
+            }
+            return mContext.bindService(mIntent, Context.BIND_AUTO_CREATE | mBindingFlags,
+                    mExecutor, serviceConnection);
+        }
+
+        /**
+         * Gets the binder interface.
+         * Typically {@code IMyInterface.Stub.asInterface(service)}.
+         *
+         * <p>
+         * Can be overridden instead of provided as a constructor parameter to save a singleton
+         * allocation
+         */
+        protected I binderAsInterface(@NonNull IBinder service) {
+            return mBinderAsInterface.apply(service);
+        }
+
+        /**
+         * Called when service was {@link Context#unbindService unbound}
+         *
+         * <p>
+         * Can be overridden to perform some cleanup on service disconnect
+         */
+        protected void onServiceUnbound() {
+            if (DEBUG) {
+                logTrace();
+            }
+        }
+
+        private void dispatchOnServiceConnectionStatusChanged(
+                @NonNull I service, boolean isConnected) {
+            ServiceLifecycleCallbacks<I> serviceLifecycleCallbacks = mServiceLifecycleCallbacks;
+            if (serviceLifecycleCallbacks != null) {
+                if (isConnected) {
+                    serviceLifecycleCallbacks.onConnected(service);
+                } else {
+                    serviceLifecycleCallbacks.onDisconnected(service);
+                }
+            }
+            onServiceConnectionStatusChanged(service, isConnected);
+        }
+
+        /**
+         * Called when the service just connected or is about to disconnect
+         */
+        protected void onServiceConnectionStatusChanged(@NonNull I service, boolean isConnected) {}
+
+        @Override
+        public boolean run(@NonNull VoidJob<I> job) {
+            if (DEBUG) {
+                Log.d(LOG_TAG, "Wrapping fireAndForget job to take advantage of its mDebugName");
+                return !post(job).isCompletedExceptionally();
+            }
+            return enqueue(job);
+        }
+
+        @Override
+        public AndroidFuture<Void> post(@NonNull VoidJob<I> job) {
+            return postForResult((Job) job);
+        }
+
+        @Override
+        public <R> CompletionAwareJob<I, R> postForResult(@NonNull Job<I, R> job) {
+            CompletionAwareJob<I, R> task = new CompletionAwareJob<>();
+            task.mDelegate = Objects.requireNonNull(job);
+            enqueue(task);
+            return task;
+        }
+
+        @Override
+        public <R> AndroidFuture<R> postAsync(@NonNull Job<I, CompletableFuture<R>> job) {
+            CompletionAwareJob<I, R> task = new CompletionAwareJob<>();
+            task.mDelegate = Objects.requireNonNull((Job) job);
+            task.mAsync = true;
+            enqueue(task);
+            return task;
+        }
+
+        @Override
+        public synchronized AndroidFuture<I> connect() {
+            if (mServiceConnectionFutureCache == null) {
+                mServiceConnectionFutureCache = new CompletionAwareJob<>();
+                mServiceConnectionFutureCache.mDelegate = s -> s;
+                I service = mService;
+                if (service != null) {
+                    mServiceConnectionFutureCache.complete(service);
+                } else {
+                    enqueue(mServiceConnectionFutureCache);
+                }
+            }
+            return mServiceConnectionFutureCache;
+        }
+
+        private void enqueue(@NonNull CompletionAwareJob<I, ?> task) {
+            if (!enqueue((Job<I, ?>) task)) {
+                task.completeExceptionally(new IllegalStateException(
+                        "Failed to post a job to handler. Likely "
+                                + mHandler.getLooper() + " is exiting"));
+            }
+        }
+
+        private boolean enqueue(@NonNull Job<I, ?> job) {
+            cancelTimeout();
+            return mHandler.post(() -> enqueueJobThread(job));
+        }
+
+        void enqueueJobThread(@NonNull Job<I, ?> job) {
+            if (DEBUG) {
+                Log.i(LOG_TAG, "post(" + job + ", this = " + this + ")");
+            }
+            cancelTimeout();
+            if (mUnbinding) {
+                completeExceptionally(job,
+                        new IllegalStateException("Service is unbinding. Ignoring " + job));
+            } else if (!mQueue.offer(job)) {
+                completeExceptionally(job,
+                        new IllegalStateException("Failed to add to queue: " + job));
+            } else if (isBound()) {
+                processQueue();
+            } else if (!mBinding) {
+                if (bindService(mServiceConnection)) {
+                    mBinding = true;
+                } else {
+                    completeExceptionally(job,
+                            new IllegalStateException("Failed to bind to service " + mIntent));
+                }
+            }
+        }
+
+        private void cancelTimeout() {
+            if (DEBUG) {
+                logTrace();
+            }
+            mMainHandler.removeCallbacks(mTimeoutDisconnect);
+        }
+
+        void completeExceptionally(@NonNull Job<?, ?> job, @NonNull Throwable ex) {
+            CompletionAwareJob task = castOrNull(job, CompletionAwareJob.class);
+            boolean taskChanged = false;
+            if (task != null) {
+                taskChanged = task.completeExceptionally(ex);
+            }
+            if (task == null || (DEBUG && taskChanged)) {
+                Log.e(LOG_TAG, "Job failed: " + job, ex);
+            }
+        }
+
+        static @Nullable <BASE, T extends BASE> T castOrNull(
+                @Nullable BASE instance, @NonNull Class<T> cls) {
+            return cls.isInstance(instance) ? (T) instance : null;
+        }
+
+        private void processQueue() {
+            if (DEBUG) {
+                logTrace();
+            }
+
+            Job<I, ?> job;
+            while ((job = mQueue.poll()) != null) {
+                CompletionAwareJob task = castOrNull(job, CompletionAwareJob.class);
+                try {
+                    I service = mService;
+                    if (service == null) {
+                        return;
+                    }
+                    Object result = job.run(service);
+                    if (DEBUG) {
+                        Log.i(LOG_TAG, "complete(" + job + ", result = " + result + ")");
+                    }
+                    if (task != null) {
+                        if (task.mAsync) {
+                            mUnfinishedJobs.add(task);
+                            ((CompletionStage) result).whenComplete(task);
+                        } else {
+                            task.complete(result);
+                        }
+                    }
+                } catch (Throwable e) {
+                    completeExceptionally(job, e);
+                }
+            }
+
+            maybeScheduleUnbindTimeout();
+        }
+
+        private void maybeScheduleUnbindTimeout() {
+            if (mUnfinishedJobs.isEmpty() && mQueue.isEmpty()) {
+                scheduleUnbindTimeout();
+            }
+        }
+
+        private void scheduleUnbindTimeout() {
+            if (DEBUG) {
+                logTrace();
+            }
+            long timeout = getAutoDisconnectTimeoutMs();
+            if (timeout > 0) {
+                mMainHandler.postDelayed(mTimeoutDisconnect, timeout);
+            } else if (DEBUG) {
+                Log.i(LOG_TAG, "Not scheduling unbind for permanently bound " + this);
+            }
+        }
+
+        private boolean isBound() {
+            return mService != null;
+        }
+
+        @Override
+        public void unbind() {
+            if (DEBUG) {
+                logTrace();
+            }
+            mUnbinding = true;
+            mHandler.post(this::unbindJobThread);
+        }
+
+        @Override
+        public void setServiceLifecycleCallbacks(@Nullable ServiceLifecycleCallbacks<I> callbacks) {
+            mServiceLifecycleCallbacks = callbacks;
+        }
+
+        void unbindJobThread() {
+            cancelTimeout();
+            I service = mService;
+            // TODO(b/224695239): This is actually checking wasConnected. Rename and/or fix
+            // implementation based on what this should actually be checking. At least the first
+            // check for calling unbind is the correct behavior, though.
+            boolean wasBound = service != null;
+            if (wasBound || mBinding) {
+                try {
+                    mContext.unbindService(mServiceConnection);
+                } catch (IllegalArgumentException e) {  // TODO(b/224697137): Fix the race condition
+                    // that requires catching this (crashes if
+                    // service isn't currently bound).
+                    Slog.e(LOG_TAG, "Failed to unbind: " + e);
+                }
+            }
+            if (wasBound) {
+                dispatchOnServiceConnectionStatusChanged(service, false);
+                service.asBinder().unlinkToDeath(this, 0);
+                mService = null;
+            }
+            mBinding = false;
+            mUnbinding = false;
+            synchronized (this) {
+                if (mServiceConnectionFutureCache != null) {
+                    mServiceConnectionFutureCache.cancel(true);
+                    mServiceConnectionFutureCache = null;
+                }
+            }
+
+            cancelPendingJobs();
+
+            if (wasBound) {
+                onServiceUnbound();
+            }
+        }
+
+        protected void cancelPendingJobs() {
+            Job<I, ?> job;
+            while ((job = mQueue.poll()) != null) {
+                if (DEBUG) {
+                    Log.i(LOG_TAG, "cancel(" + job + ")");
+                }
+                CompletionAwareJob task = castOrNull(job, CompletionAwareJob.class);
+                if (task != null) {
+                    task.cancel(/* mayInterruptWhileRunning= */ false);
+                }
+            }
+        }
+
+        @Override
+        public void onServiceConnected(@NonNull ComponentName name, @NonNull IBinder binder) {
+            if (mUnbinding) {
+                Log.i(LOG_TAG, "Ignoring onServiceConnected due to ongoing unbinding: " + this);
+                return;
+            }
+            if (DEBUG) {
+                logTrace();
+            }
+            I service = binderAsInterface(binder);
+            mService = service;
+            mBinding = false;
+            try {
+                binder.linkToDeath(ServiceConnector.Impl.this, 0);
+            } catch (RemoteException e) {
+                Log.e(LOG_TAG, "onServiceConnected " + name + ": ", e);
+            }
+            dispatchOnServiceConnectionStatusChanged(service, true);
+            processQueue();
+        }
+
+        @Override
+        public void onServiceDisconnected(@NonNull ComponentName name) {
+            if (DEBUG) {
+                logTrace();
+            }
+            mBinding = true;
+            I service = mService;
+            if (service != null) {
+                dispatchOnServiceConnectionStatusChanged(service, false);
+                mService = null;
+            }
+        }
+
+        @Override
+        public void onBindingDied(@NonNull ComponentName name) {
+            if (DEBUG) {
+                logTrace();
+            }
+            binderDied();
+        }
+
+        @Override
+        public void binderDied() {
+            if (DEBUG) {
+                logTrace();
+            }
+            mService = null;
+            unbind();
+            dispatchOnBinderDied();
+        }
+
+        private void dispatchOnBinderDied() {
+            ServiceLifecycleCallbacks<I> serviceLifecycleCallbacks = mServiceLifecycleCallbacks;
+            if (serviceLifecycleCallbacks != null) {
+                serviceLifecycleCallbacks.onBinderDied();
+            }
+        }
+
+        @Override
+        public void run() {
+            onTimeout();
+        }
+
+        private void onTimeout() {
+            if (DEBUG) {
+                logTrace();
+            }
+            unbind();
+        }
+
+        @Override
+        public String toString() {
+            StringBuilder sb = new StringBuilder("ServiceConnector@")
+                    .append(System.identityHashCode(this) % 1000).append("(")
+                    .append(mIntent).append(", user: ").append(mContext.getUser().getIdentifier())
+                    .append(")[").append(stateToString());
+            if (!mQueue.isEmpty()) {
+                sb.append(", ").append(mQueue.size()).append(" pending job(s)");
+                if (DEBUG) {
+                    sb.append(": ").append(super.toString());
+                }
+            }
+            if (!mUnfinishedJobs.isEmpty()) {
+                sb.append(", ").append(mUnfinishedJobs.size()).append(" unfinished async job(s)");
+            }
+            return sb.append("]").toString();
+        }
+
+        public void dump(@NonNull String prefix, @NonNull PrintWriter pw) {
+            String tab = "  ";
+            pw.append(prefix).append("ServiceConnector:").println();
+            pw.append(prefix).append(tab).append(String.valueOf(mIntent)).println();
+            pw.append(prefix).append(tab).append("userId: ")
+                    .append(String.valueOf(mContext.getUser().getIdentifier())).println();
+            pw.append(prefix).append(tab)
+                    .append("State: ").append(stateToString()).println();
+            pw.append(prefix).append(tab)
+                    .append("Pending jobs: ").append(String.valueOf(mQueue.size())).println();
+            if (DEBUG) {
+                for (Job<I, ?> pendingJob : mQueue) {
+                    pw.append(prefix).append(tab).append(tab)
+                            .append(String.valueOf(pendingJob)).println();
+                }
+            }
+            pw.append(prefix).append(tab)
+                    .append("Unfinished async jobs: ")
+                    .append(String.valueOf(mUnfinishedJobs.size())).println();
+        }
+
+        private String stateToString() {
+            if (mBinding) {
+                return "Binding...";
+            } else if (mUnbinding) {
+                return "Unbinding...";
+            } else if (isBound()) {
+                return "Bound";
+            } else {
+                return "Unbound";
+            }
+        }
+
+        private void logTrace() {
+            Log.i(LOG_TAG, "See stacktrace", new Throwable());
+        }
+
+        /**
+         * {@link Job} + {@link AndroidFuture}
+         */
+        class CompletionAwareJob<II, R> extends AndroidFuture<R>
+                implements Job<II, R>, BiConsumer<R, Throwable> {
+            Job<II, R> mDelegate;
+            boolean mAsync = false;
+            private String mDebugName;
+            {
+                // The timeout handler must be set before any calls to set timeouts on the
+                // AndroidFuture, to ensure they are posted on the proper thread.
+                setTimeoutHandler(getJobHandler());
+
+                long requestTimeout = getRequestTimeoutMs();
+                if (requestTimeout > 0) {
+                    orTimeout(requestTimeout, TimeUnit.MILLISECONDS);
+                }
+
+                if (DEBUG) {
+                    mDebugName = Arrays.stream(Thread.currentThread().getStackTrace())
+                            .skip(2)
+                            .filter(st ->
+                                    !st.getClassName().contains(ServiceConnector.class.getName()))
+                            .findFirst()
+                            .get()
+                            .getMethodName();
+                }
+            }
+
+            @Override
+            public R run(@NonNull II service) throws Exception {
+                return mDelegate.run(service);
+            }
+
+            @Override
+            public boolean cancel(boolean mayInterruptIfRunning) {
+                if (mayInterruptIfRunning) {
+                    Log.w(LOG_TAG, "mayInterruptIfRunning not supported - ignoring");
+                }
+                boolean wasRemoved = mQueue.remove(this);
+                return super.cancel(mayInterruptIfRunning) || wasRemoved;
+            }
+
+            @Override
+            public String toString() {
+                if (DEBUG) {
+                    return mDebugName;
+                }
+                return mDelegate + " wrapped into " + super.toString();
+            }
+
+            @Override
+            public void accept(@Nullable R res, @Nullable Throwable err) {
+                if (err != null) {
+                    completeExceptionally(err);
+                } else {
+                    complete(res);
+                }
+            }
+
+            @Override
+            protected void onCompleted(R res, Throwable err) {
+                super.onCompleted(res, err);
+                if (mUnfinishedJobs.remove(this)) {
+                    maybeScheduleUnbindTimeout();
+                }
+            }
+        }
+    }
+
+    /**
+     * A {@link ServiceConnector} that doesn't connect to anything.
+     *
+     * @param <T> the type of the {@link IInterface ipc interface} for the remote service
+     */
+    class NoOp<T extends IInterface> extends AndroidFuture<Object> implements ServiceConnector<T> {
+        {
+            completeExceptionally(new IllegalStateException("ServiceConnector is a no-op"));
+        }
+
+        @Override
+        public boolean run(@NonNull VoidJob<T> job) {
+            return false;
+        }
+
+        @Override
+        public AndroidFuture<Void> post(@NonNull VoidJob<T> job) {
+            return (AndroidFuture) this;
+        }
+
+        @Override
+        public <R> AndroidFuture<R> postForResult(@NonNull Job<T, R> job) {
+            return (AndroidFuture) this;
+        }
+
+        @Override
+        public <R> AndroidFuture<R> postAsync(@NonNull Job<T, CompletableFuture<R>> job) {
+            return (AndroidFuture) this;
+        }
+
+        @Override
+        public AndroidFuture<T> connect() {
+            return (AndroidFuture) this;
+        }
+
+        @Override
+        public void unbind() {}
+
+        @Override
+        public void setServiceLifecycleCallbacks(@Nullable ServiceLifecycleCallbacks<T> callbacks) {
+            // Do nothing.
+        }
+    }
+}
diff --git a/javatests/com/android/internal/annotations/Android.bp b/javatests/com/android/internal/annotations/Android.bp
index bf85703..26d2bd1 100644
--- a/javatests/com/android/internal/annotations/Android.bp
+++ b/javatests/com/android/internal/annotations/Android.bp
@@ -29,10 +29,13 @@ android_test {
     static_libs: [
         "androidx.test.rules",
         "androidx.test.runner",
-        "framework-annotations-lib",
+        "truth",
     ],
 
-    libs: ["android.test.runner.stubs.system"],
+    libs: [
+        "android.test.runner.stubs.system",
+        "framework-annotations-lib",
+    ],
 
     // Note: We explicitly optimize this test target to validate post-optimized
     // code paths and their interop with annotations.
@@ -43,5 +46,10 @@ android_test {
         proguard_flags_files: ["proguard.flags"],
     },
 
+    // Explicitly request release mode, overriding the implicit debug mode used
+    // in eng builds that would disable bytecode optimizations. This ensures
+    // consistent test behavior across test suite build configurations.
+    dxflags: ["--release"],
+
     test_suites: ["general-tests"],
 }
diff --git a/javatests/com/android/internal/annotations/ClassWithWeaklyReferencedCallback.java b/javatests/com/android/internal/annotations/ClassWithWeaklyReferencedCallback.java
new file mode 100644
index 0000000..9e8b546
--- /dev/null
+++ b/javatests/com/android/internal/annotations/ClassWithWeaklyReferencedCallback.java
@@ -0,0 +1,50 @@
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
+package com.android.internal.annotations;
+
+import android.util.Log;
+
+import java.lang.ref.WeakReference;
+import java.util.List;
+
+public class ClassWithWeaklyReferencedCallback {
+
+    // This field should be kept despite being write-once, as the type has
+    // the necessary annotation.
+    private final AnnotatedCallback mKeptCallback = new AnnotatedCallback();
+
+    // This field should be stripped as it's write-once and doesn't have the necessary annotation.
+    private final UnannotatedCallback mStrippedCallback = new UnannotatedCallback();
+
+    public ClassWithWeaklyReferencedCallback(List<WeakReference<Object>> weakRefs) {
+        weakRefs.add(new WeakReference<>(mKeptCallback));
+        weakRefs.add(new WeakReference<>(mStrippedCallback));
+    }
+
+    @WeaklyReferencedCallback
+    public static class AnnotatedCallback {
+        public void onCallback() {
+            Log.i("AnnotatedCallback", "onCallback");
+        }
+    }
+
+    public static class UnannotatedCallback {
+        public void onCallback() {
+            Log.i("UnannotatedCallback", "onCallBack");
+        }
+    }
+}
diff --git a/javatests/com/android/internal/annotations/ClassWithWeaklyReferencedField.java b/javatests/com/android/internal/annotations/ClassWithWeaklyReferencedField.java
index fe85e17..65edf9c 100644
--- a/javatests/com/android/internal/annotations/ClassWithWeaklyReferencedField.java
+++ b/javatests/com/android/internal/annotations/ClassWithWeaklyReferencedField.java
@@ -21,11 +21,13 @@ import java.util.List;
 
 public class ClassWithWeaklyReferencedField {
 
-    // Without this annotation, `mKeptField` could be optimized away after
-    // tree shaking.
-    @KeepForWeakReference private final Object mKeptField = new Integer(1);
+    // Without this annotation, `mKeptField` could be optimized away after tree shaking.
+    @KeepForWeakReference
+    private final Integer mKeptField = 7;
+    private final Integer mStrippedField = 77;
 
     public ClassWithWeaklyReferencedField(List<WeakReference<Object>> weakRefs) {
         weakRefs.add(new WeakReference<>(mKeptField));
+        weakRefs.add(new WeakReference<>(mStrippedField));
     }
 }
diff --git a/javatests/com/android/internal/annotations/KeepForWeakReferenceTest.java b/javatests/com/android/internal/annotations/KeepForWeakReferenceTest.java
index e7f9988..0aeda78 100644
--- a/javatests/com/android/internal/annotations/KeepForWeakReferenceTest.java
+++ b/javatests/com/android/internal/annotations/KeepForWeakReferenceTest.java
@@ -16,9 +16,10 @@
 
 package com.android.internal.annotations;
 
-import androidx.test.filters.SmallTest;
+import static com.google.common.truth.Truth.assertThat;
+import static org.junit.Assert.assertThrows;
 
-import junit.framework.TestCase;
+import androidx.test.filters.SmallTest;
 
 import org.junit.Test;
 import org.junit.runner.RunWith;
@@ -30,8 +31,7 @@ import java.util.List;
 
 @RunWith(JUnit4.class)
 @SmallTest
-@Keep
-public class KeepForWeakReferenceTest extends TestCase {
+public class KeepForWeakReferenceTest {
     @Test
     public void testAnnotatedMemberKept() throws Exception {
         // Note: This code is simply to exercise the class behavior to ensure
@@ -44,7 +44,12 @@ public class KeepForWeakReferenceTest extends TestCase {
         // call itself (with the string constant) as an implicit Keep signal.
         String[] keptFields = {"mKeptField"};
         for (String field : keptFields) {
-            assertTrue(instance.getClass().getDeclaredField(field) != null);
+            assertThat(instance.getClass().getDeclaredField(field)).isNotNull();
+        }
+        String[] strippedFields = {"mStrippedField"};
+        for (String field : strippedFields) {
+            assertThrows(
+                    NoSuchFieldException.class, () -> instance.getClass().getDeclaredField(field));
         }
     }
 }
diff --git a/javatests/com/android/internal/annotations/WeaklyReferencedCallbackTest.java b/javatests/com/android/internal/annotations/WeaklyReferencedCallbackTest.java
new file mode 100644
index 0000000..f695119
--- /dev/null
+++ b/javatests/com/android/internal/annotations/WeaklyReferencedCallbackTest.java
@@ -0,0 +1,56 @@
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
+package com.android.internal.annotations;
+
+import static com.google.common.truth.Truth.assertThat;
+import static org.junit.Assert.assertThrows;
+
+import androidx.test.filters.SmallTest;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
+import java.lang.ref.WeakReference;
+import java.util.ArrayList;
+import java.util.List;
+
+@RunWith(JUnit4.class)
+@SmallTest
+public class WeaklyReferencedCallbackTest {
+    @Test
+    public void testAnnotatedCallbackMemberKept() throws Exception {
+        // Note: This code is simply to exercise the class behavior to ensure
+        // that it's kept during compilation.
+        List<WeakReference<Object>> weakRefs = new ArrayList<>();
+        ClassWithWeaklyReferencedCallback instance =
+                new ClassWithWeaklyReferencedCallback(weakRefs);
+
+        // Ensure fields of annotated callback types are kept.
+        // Note: We use an intermediate string field variable to avoid R8 using the reflection
+        // call itself (with the string constant) as an implicit Keep signal.
+        String[] keptFields = {"mKeptCallback"};
+        for (String field : keptFields) {
+            assertThat(instance.getClass().getDeclaredField(field)).isNotNull();
+        }
+        String[] strippedFields = {"mStrippedCallback"};
+        for (String field : strippedFields) {
+            assertThrows(
+                    NoSuchFieldException.class, () -> instance.getClass().getDeclaredField(field));
+        }
+    }
+}
diff --git a/javatests/com/android/internal/annotations/proguard.flags b/javatests/com/android/internal/annotations/proguard.flags
index df6850d..759221f 100644
--- a/javatests/com/android/internal/annotations/proguard.flags
+++ b/javatests/com/android/internal/annotations/proguard.flags
@@ -1,2 +1,4 @@
--keep class * extends junit.framework.Test { *; }
--keep class * extends junit.framework.TestCase { *; }
\ No newline at end of file
+-keep class org.junit.runners.JUnit4 { *; }
+-keep @org.junit.runner.RunWith class * {
+    public *;
+}
```

