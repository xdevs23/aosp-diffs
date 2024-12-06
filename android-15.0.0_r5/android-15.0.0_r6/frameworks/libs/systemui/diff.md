```diff
diff --git a/PREUPLOAD.cfg b/PREUPLOAD.cfg
index 00cf70d..40a81e7 100644
--- a/PREUPLOAD.cfg
+++ b/PREUPLOAD.cfg
@@ -12,4 +12,4 @@ checkstyle_hook = ${REPO_ROOT}/prebuilts/checkstyle/checkstyle.py --sha ${PREUPL
 ktlint_hook = ${REPO_ROOT}/prebuilts/ktlint/ktlint.py --no-verify-format -f ${PREUPLOAD_FILES}
 
 [Tool Paths]
-ktfmt = ${REPO_ROOT}/prebuilts/build-tools/common/framework/ktfmt.jar
+ktfmt = ${REPO_ROOT}/external/ktfmt/ktfmt.sh
diff --git a/aconfig/systemui.aconfig b/aconfig/systemui.aconfig
index 287d96e..54f5f2e 100644
--- a/aconfig/systemui.aconfig
+++ b/aconfig/systemui.aconfig
@@ -15,6 +15,13 @@ flag {
     bug: "273205603"
 }
 
+flag {
+    name: "return_animation_framework_long_lived"
+    namespace: "systemui"
+    description: "Turn on long-lived Return registrations in the Animation library"
+    bug: "273205603"
+}
+
 flag {
     name: "shade_allow_back_gesture"
     namespace: "systemui"
@@ -41,3 +48,24 @@ flag {
         purpose: PURPOSE_BUGFIX
     }
 }
+
+flag {
+  name: "new_touchpad_gestures_tutorial"
+  namespace: "systemui"
+  description: "Enables new interactive tutorial for learning touchpad gestures"
+  bug: "309928033"
+}
+
+flag {
+    name: "three_button_corner_swipe"
+    namespace: "systemui"
+    description: "Allow the Assistant corner swipe gesture while in 3 button mode"
+    bug: "361651619"
+}
+
+flag {
+    name: "new_customization_picker_ui"
+    namespace: "systemui"
+    description: "Enables the BC25 design of the customization picker UI."
+    bug: "339081035"
+}
diff --git a/animationlib/Android.bp b/animationlib/Android.bp
index ffafd9b..06a7034 100644
--- a/animationlib/Android.bp
+++ b/animationlib/Android.bp
@@ -40,7 +40,7 @@ android_library {
 android_library {
     name: "animationlib-tests-base",
     libs: [
-        "android.test.base",
+        "android.test.base.stubs.system",
         "androidx.test.core",
     ],
     static_libs: [
diff --git a/compilelib/Android.bp b/compilelib/Android.bp
index 27a0192..29dfc7a 100644
--- a/compilelib/Android.bp
+++ b/compilelib/Android.bp
@@ -44,4 +44,7 @@ java_library {
             exclude_srcs: [":compilelib-ReleaseJavaFiles"],
         },
     },
+    sdk_version: "31",
+    min_sdk_version: "19",
+    java_version: "17",
 }
diff --git a/contextualeducationlib/Android.bp b/contextualeducationlib/Android.bp
new file mode 100644
index 0000000..25ebbf8
--- /dev/null
+++ b/contextualeducationlib/Android.bp
@@ -0,0 +1,29 @@
+// Copyright 2024 The Android Open Source Project
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
+    default_team: "trendy_team_large_screen_experiences_sysui",
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+android_library {
+    name: "contextualeducationlib",
+    manifest: "AndroidManifest.xml",
+    sdk_version: "system_current",
+    min_sdk_version: "26",
+    srcs: [
+        "src/**/*.kt",
+    ],
+    kotlincflags: ["-Xjvm-default=all"],
+}
diff --git a/contextualeducationlib/AndroidManifest.xml b/contextualeducationlib/AndroidManifest.xml
new file mode 100644
index 0000000..b4e7a2c
--- /dev/null
+++ b/contextualeducationlib/AndroidManifest.xml
@@ -0,0 +1,20 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+     Copyright 2024 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+-->
+
+<manifest xmlns:android="http://schemas.android.com/apk/res/android"
+    package="com.android.systemui.contextualeducation">
+</manifest>
diff --git a/contextualeducationlib/build.gradle b/contextualeducationlib/build.gradle
new file mode 100644
index 0000000..909304d
--- /dev/null
+++ b/contextualeducationlib/build.gradle
@@ -0,0 +1,30 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+plugins {
+    id 'com.android.library'
+    id 'org.jetbrains.kotlin.android'
+}
+android {
+    namespace = "com.android.systemui.contextualeducation"
+
+    sourceSets {
+        main {
+            java.srcDirs = ['src']
+            manifest.srcFile 'AndroidManifest.xml'
+        }
+    }
+}
\ No newline at end of file
diff --git a/contextualeducationlib/src/com/android/systemui/contextualeducation/GestureType.kt b/contextualeducationlib/src/com/android/systemui/contextualeducation/GestureType.kt
new file mode 100644
index 0000000..0e19cf5
--- /dev/null
+++ b/contextualeducationlib/src/com/android/systemui/contextualeducation/GestureType.kt
@@ -0,0 +1,24 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+package com.android.systemui.contextualeducation
+
+enum class GestureType {
+    BACK,
+    HOME,
+    OVERVIEW,
+    ALL_APPS
+}
diff --git a/iconloaderlib/Android.bp b/iconloaderlib/Android.bp
index 083091d..6fdf2eb 100644
--- a/iconloaderlib/Android.bp
+++ b/iconloaderlib/Android.bp
@@ -22,12 +22,14 @@ android_library {
     min_sdk_version: "26",
     static_libs: [
         "androidx.core_core",
+        "com_android_launcher3_flags_lib",
     ],
     resource_dirs: [
         "res",
     ],
     srcs: [
         "src/**/*.java",
+        "src/**/*.kt",
     ],
 }
 
@@ -37,13 +39,16 @@ android_library {
     min_sdk_version: "26",
     static_libs: [
         "androidx.core_core",
+        "com_android_launcher3_flags_lib",
     ],
     resource_dirs: [
         "res",
     ],
     srcs: [
         "src/**/*.java",
+        "src/**/*.kt",
         "src_full_lib/**/*.java",
+        "src_full_lib/**/*.kt",
     ],
     apex_available: [
         "//apex_available:platform",
diff --git a/iconloaderlib/build.gradle b/iconloaderlib/build.gradle
deleted file mode 100644
index 344ac20..0000000
--- a/iconloaderlib/build.gradle
+++ /dev/null
@@ -1,25 +0,0 @@
-plugins {
-    id 'com.android.library'
-}
-
-android {
-    namespace = "com.android.launcher3.icons"
-    sourceSets {
-        main {
-            java.srcDirs = ['src', 'src_full_lib']
-            manifest.srcFile 'AndroidManifest.xml'
-            res.srcDirs = ['res']
-        }
-    }
-    lint {
-        abortOnError false
-    }
-
-    tasks.withType(JavaCompile) {
-        options.compilerArgs << "-Xlint:unchecked" << "-Xlint:deprecation"
-    }
-}
-
-dependencies {
-    implementation "androidx.core:core"
-}
diff --git a/iconloaderlib/build.gradle.kts b/iconloaderlib/build.gradle.kts
new file mode 100644
index 0000000..2678433
--- /dev/null
+++ b/iconloaderlib/build.gradle.kts
@@ -0,0 +1,20 @@
+plugins {
+    id(libs.plugins.android.library.get().pluginId)
+    id(libs.plugins.kotlin.android.get().pluginId)
+}
+
+android {
+    namespace = "com.android.launcher3.icons"
+    sourceSets {
+        named("main") {
+            java.setSrcDirs(listOf("src", "src_full_lib"))
+            manifest.srcFile("AndroidManifest.xml")
+            res.setSrcDirs(listOf("res"))
+        }
+    }
+}
+
+dependencies {
+    implementation("androidx.core:core")
+    api(project(":NexusLauncher.Flags"))
+}
diff --git a/iconloaderlib/res/values-night-v31/colors.xml b/iconloaderlib/res/values-night-v31/colors.xml
index e5ebda6..e7d89b4 100644
--- a/iconloaderlib/res/values-night-v31/colors.xml
+++ b/iconloaderlib/res/values-night-v31/colors.xml
@@ -17,8 +17,6 @@
 */
 -->
 <resources>
-    <color name="themed_icon_color">@android:color/system_accent1_200</color>
-    <color name="themed_icon_background_color">@android:color/system_accent2_800</color>
     <color name="themed_badge_icon_color">@android:color/system_accent2_800</color>
     <color name="themed_badge_icon_background_color">@android:color/system_accent1_200</color>
 </resources>
diff --git a/iconloaderlib/res/values-night/colors.xml b/iconloaderlib/res/values-night/colors.xml
index 9de7074..f23f1c0 100644
--- a/iconloaderlib/res/values-night/colors.xml
+++ b/iconloaderlib/res/values-night/colors.xml
@@ -16,9 +16,9 @@
 ** limitations under the License.
 */
 -->
-<resources>
-    <color name="themed_icon_color">#A8C7FA</color>
-    <color name="themed_icon_background_color">#003355</color>
+<resources xmlns:androidprv="http://schemas.android.com/apk/prv/res/android">
+    <color name="themed_icon_color">@androidprv:color/system_on_theme_app_dark</color>
+    <color name="themed_icon_background_color">@androidprv:color/system_theme_app_dark</color>
     <color name="themed_badge_icon_color">#003355</color>
     <color name="themed_badge_icon_background_color">#A8C7FA</color>
 </resources>
diff --git a/iconloaderlib/res/values-v31/colors.xml b/iconloaderlib/res/values-v31/colors.xml
index 1405ad0..28614a2 100644
--- a/iconloaderlib/res/values-v31/colors.xml
+++ b/iconloaderlib/res/values-v31/colors.xml
@@ -17,8 +17,6 @@
 */
 -->
 <resources>
-    <color name="themed_icon_color">@android:color/system_accent1_700</color>
-    <color name="themed_icon_background_color">@android:color/system_accent1_100</color>
     <color name="themed_badge_icon_color">@android:color/system_accent1_700</color>
     <color name="themed_badge_icon_background_color">@android:color/system_accent1_100</color>
 </resources>
diff --git a/iconloaderlib/res/values/colors.xml b/iconloaderlib/res/values/colors.xml
index 56ae0b6..ee8bce2 100644
--- a/iconloaderlib/res/values/colors.xml
+++ b/iconloaderlib/res/values/colors.xml
@@ -16,9 +16,9 @@
 ** limitations under the License.
 */
 -->
-<resources>
-    <color name="themed_icon_color">#0842A0</color>
-    <color name="themed_icon_background_color">#D3E3FD</color>
+<resources xmlns:androidprv="http://schemas.android.com/apk/prv/res/android">
+    <color name="themed_icon_color">@androidprv:color/system_on_theme_app_light</color>
+    <color name="themed_icon_background_color">@androidprv:color/system_theme_app_light</color>
     <color name="themed_badge_icon_color">#0842A0</color>
     <color name="themed_badge_icon_background_color">#D3E3FD</color>
 
diff --git a/iconloaderlib/src/com/android/launcher3/icons/BaseIconFactory.java b/iconloaderlib/src/com/android/launcher3/icons/BaseIconFactory.java
index bef02d6..e3b907e 100644
--- a/iconloaderlib/src/com/android/launcher3/icons/BaseIconFactory.java
+++ b/iconloaderlib/src/com/android/launcher3/icons/BaseIconFactory.java
@@ -85,7 +85,7 @@ public class BaseIconFactory implements AutoCloseable {
     @NonNull
     private final ColorExtractor mColorExtractor;
 
-    protected final int mFillResIconDpi;
+    protected final int mFullResIconDpi;
     protected final int mIconBitmapSize;
 
     protected boolean mMonoIconEnabled;
@@ -106,11 +106,11 @@ public class BaseIconFactory implements AutoCloseable {
 
     private static int PLACEHOLDER_BACKGROUND_COLOR = Color.rgb(245, 245, 245);
 
-    protected BaseIconFactory(Context context, int fillResIconDpi, int iconBitmapSize,
+    protected BaseIconFactory(Context context, int fullResIconDpi, int iconBitmapSize,
             boolean shapeDetection) {
         mContext = context.getApplicationContext();
         mShapeDetection = shapeDetection;
-        mFillResIconDpi = fillResIconDpi;
+        mFullResIconDpi = fullResIconDpi;
         mIconBitmapSize = iconBitmapSize;
 
         mPm = mContext.getPackageManager();
@@ -121,8 +121,8 @@ public class BaseIconFactory implements AutoCloseable {
         clear();
     }
 
-    public BaseIconFactory(Context context, int fillResIconDpi, int iconBitmapSize) {
-        this(context, fillResIconDpi, iconBitmapSize, false);
+    public BaseIconFactory(Context context, int fullResIconDpi, int iconBitmapSize) {
+        this(context, fullResIconDpi, iconBitmapSize, false);
     }
 
     protected void clear() {
@@ -145,6 +145,10 @@ public class BaseIconFactory implements AutoCloseable {
         return mNormalizer;
     }
 
+    public int getFullResIconDpi() {
+        return mFullResIconDpi;
+    }
+
     @SuppressWarnings("deprecation")
     public BitmapInfo createIconBitmap(Intent.ShortcutIconResource iconRes) {
         try {
@@ -152,7 +156,7 @@ public class BaseIconFactory implements AutoCloseable {
             if (resources != null) {
                 final int id = resources.getIdentifier(iconRes.resourceName, null, null);
                 // do not stamp old legacy shortcuts as the app may have already forgotten about it
-                return createBadgedIconBitmap(resources.getDrawableForDensity(id, mFillResIconDpi));
+                return createBadgedIconBitmap(resources.getDrawableForDensity(id, mFullResIconDpi));
             }
         } catch (Exception e) {
             // Icon not found.
@@ -186,13 +190,12 @@ public class BaseIconFactory implements AutoCloseable {
      * Creates an icon from the bitmap cropped to the current device icon shape
      */
     @NonNull
-    public BitmapInfo createShapedIconBitmap(Bitmap icon, IconOptions options) {
-        Drawable d = new FixedSizeBitmapDrawable(icon);
+    public AdaptiveIconDrawable createShapedAdaptiveIcon(Bitmap iconBitmap) {
+        Drawable drawable = new FixedSizeBitmapDrawable(iconBitmap);
         float inset = getExtraInsetFraction();
         inset = inset / (1 + 2 * inset);
-        d = new AdaptiveIconDrawable(new ColorDrawable(Color.BLACK),
-                new InsetDrawable(d, inset, inset, inset, inset));
-        return createBadgedIconBitmap(d, options);
+        return new AdaptiveIconDrawable(new ColorDrawable(Color.BLACK),
+                new InsetDrawable(drawable, inset, inset, inset, inset));
     }
 
     @NonNull
@@ -205,14 +208,23 @@ public class BaseIconFactory implements AutoCloseable {
      * The bitmap is visually normalized with other icons and has enough spacing to add shadow.
      *
      * @param icon source of the icon
-     * @return a bitmap suitable for disaplaying as an icon at various system UIs.
+     * @return a bitmap suitable for displaying as an icon at various system UIs.
      */
     @TargetApi(Build.VERSION_CODES.TIRAMISU)
     @NonNull
     public BitmapInfo createBadgedIconBitmap(@NonNull Drawable icon,
             @Nullable IconOptions options) {
         float[] scale = new float[1];
-        AdaptiveIconDrawable adaptiveIcon = normalizeAndWrapToAdaptiveIcon(icon, null, scale);
+        Drawable tempIcon = icon;
+        if (options != null
+                && options.mIsArchived
+                && icon instanceof BitmapDrawable bitmapDrawable) {
+            // b/358123888
+            // Pre-archived apps can have BitmapDrawables without insets.
+            // Need to convert to Adaptive Icon with insets to avoid cropping.
+            tempIcon = createShapedAdaptiveIcon(bitmapDrawable.getBitmap());
+        }
+        AdaptiveIconDrawable adaptiveIcon = normalizeAndWrapToAdaptiveIcon(tempIcon, null, scale);
         Bitmap bitmap = createIconBitmap(adaptiveIcon, scale[0],
                 options == null ? MODE_WITH_SHADOW : options.mGenerationMode);
 
@@ -366,7 +378,7 @@ public class BaseIconFactory implements AutoCloseable {
     }
 
     @NonNull
-    protected Bitmap createIconBitmap(@Nullable final Drawable icon, final float scale) {
+    public Bitmap createIconBitmap(@Nullable final Drawable icon, final float scale) {
         return createIconBitmap(icon, scale, MODE_DEFAULT);
     }
 
@@ -477,7 +489,7 @@ public class BaseIconFactory implements AutoCloseable {
 
     @NonNull
     public BitmapInfo makeDefaultIcon() {
-        return createBadgedIconBitmap(getFullResDefaultActivityIcon(mFillResIconDpi));
+        return createBadgedIconBitmap(getFullResDefaultActivityIcon(mFullResIconDpi));
     }
 
     @NonNull
@@ -497,6 +509,8 @@ public class BaseIconFactory implements AutoCloseable {
 
         boolean mIsInstantApp;
 
+        boolean mIsArchived;
+
         @BitmapGenerationMode
         int mGenerationMode = MODE_WITH_SHADOW;
 
@@ -537,6 +551,14 @@ public class BaseIconFactory implements AutoCloseable {
             return this;
         }
 
+        /**
+         * If the icon represents an archived app
+         */
+        public IconOptions setIsArchived(boolean isArchived) {
+            mIsArchived = isArchived;
+            return this;
+        }
+
         /**
          * Disables auto color extraction and overrides the color to the provided value
          */
diff --git a/iconloaderlib/src/com/android/launcher3/icons/RoundDrawableWrapper.java b/iconloaderlib/src/com/android/launcher3/icons/RoundDrawableWrapper.java
index e569c1e..0bd8866 100644
--- a/iconloaderlib/src/com/android/launcher3/icons/RoundDrawableWrapper.java
+++ b/iconloaderlib/src/com/android/launcher3/icons/RoundDrawableWrapper.java
@@ -31,18 +31,27 @@ public class RoundDrawableWrapper extends DrawableWrapper {
     private final RectF mTempRect = new RectF();
     private final Path mClipPath = new Path();
     private final float mRoundedCornersRadius;
+    private float mScaledCornerRadius;
 
     public RoundDrawableWrapper(Drawable dr, float radius) {
         super(dr);
         mRoundedCornersRadius = radius;
+        mScaledCornerRadius = mRoundedCornersRadius;
+    }
+
+    /**
+     * Sets the scaling to be applied to the corner radius when it draws next time.
+     */
+    public void setCornerRadiusScale(float scale) {
+        mScaledCornerRadius = Math.round(mRoundedCornersRadius * scale);
     }
 
     @Override
     protected void onBoundsChange(Rect bounds) {
         mTempRect.set(getBounds());
         mClipPath.reset();
-        mClipPath.addRoundRect(mTempRect, mRoundedCornersRadius,
-                mRoundedCornersRadius, Path.Direction.CCW);
+        mClipPath.addRoundRect(mTempRect, mScaledCornerRadius, mScaledCornerRadius,
+                Path.Direction.CCW);
         super.onBoundsChange(bounds);
     }
 
diff --git a/iconloaderlib/src/com/android/launcher3/icons/cache/BaseIconCache.java b/iconloaderlib/src/com/android/launcher3/icons/cache/BaseIconCache.java
index 5963f0c..287480f 100644
--- a/iconloaderlib/src/com/android/launcher3/icons/cache/BaseIconCache.java
+++ b/iconloaderlib/src/com/android/launcher3/icons/cache/BaseIconCache.java
@@ -36,6 +36,7 @@ import android.content.res.Resources;
 import android.database.Cursor;
 import android.database.sqlite.SQLiteDatabase;
 import android.database.sqlite.SQLiteException;
+import android.database.sqlite.SQLiteReadOnlyDatabaseException;
 import android.graphics.Bitmap;
 import android.graphics.Bitmap.Config;
 import android.graphics.BitmapFactory;
@@ -56,9 +57,11 @@ import androidx.annotation.Nullable;
 import androidx.annotation.VisibleForTesting;
 import androidx.annotation.WorkerThread;
 
+import com.android.launcher3.Flags;
 import com.android.launcher3.icons.BaseIconFactory;
 import com.android.launcher3.icons.BaseIconFactory.IconOptions;
 import com.android.launcher3.icons.BitmapInfo;
+import com.android.launcher3.icons.IconProvider;
 import com.android.launcher3.util.ComponentKey;
 import com.android.launcher3.util.FlagOp;
 import com.android.launcher3.util.SQLiteCacheHelper;
@@ -101,6 +104,9 @@ public abstract class BaseIconCache {
     @NonNull
     protected final PackageManager mPackageManager;
 
+    @NonNull
+    protected final IconProvider mIconProvider;
+
     @NonNull
     private final Map<ComponentKey, CacheEntry> mCache;
 
@@ -137,8 +143,16 @@ public abstract class BaseIconCache {
     public BaseIconCache(@NonNull final Context context, @Nullable final String dbFileName,
             @NonNull final Looper bgLooper, final int iconDpi, final int iconPixelSize,
             final boolean inMemoryCache) {
+        this(context, dbFileName, bgLooper, iconDpi, iconPixelSize, inMemoryCache,
+                new IconProvider(context));
+    }
+
+    public BaseIconCache(@NonNull final Context context, @Nullable final String dbFileName,
+            @NonNull final Looper bgLooper, final int iconDpi, final int iconPixelSize,
+            final boolean inMemoryCache, @NonNull IconProvider iconProvider) {
         mContext = context;
         mDbFileName = dbFileName;
+        mIconProvider = iconProvider;
         mPackageManager = context.getPackageManager();
         mBgLooper = bgLooper;
         mWorkerHandler = new Handler(mBgLooper);
@@ -187,13 +201,24 @@ public abstract class BaseIconCache {
     }
 
     private synchronized void updateIconParamsBg(final int iconDpi, final int iconPixelSize) {
-        mIconDpi = iconDpi;
-        mDefaultIcon = null;
-        mUserFlagOpMap.clear();
-        mIconDb.clear();
-        mIconDb.close();
-        mIconDb = new IconDB(mContext, mDbFileName, iconPixelSize);
-        mCache.clear();
+        try {
+            mIconDpi = iconDpi;
+            mDefaultIcon = null;
+            mUserFlagOpMap.clear();
+            mIconDb.clear();
+            mIconDb.close();
+            mIconDb = new IconDB(mContext, mDbFileName, iconPixelSize);
+            mCache.clear();
+        } catch (SQLiteReadOnlyDatabaseException e) {
+            // This is known to happen during repeated backup and restores, if the Launcher is in
+            // restricted mode. When the launcher is loading and the backup restore is being cleared
+            // there can be a conflict where one DB is trying to delete the DB file, and the other
+            // is attempting to write to it. The effect is that launcher crashes, then the backup /
+            // restore process fails, then the user's home screen icons fail to restore. Adding this
+            // try / catch will stop the crash, and LoaderTask will sanitize any residual icon data,
+            // leading to a completed backup / restore and a better experience for our customers.
+            Log.e(TAG, "failed to clear the launcher's icon db or cache.", e);
+        }
     }
 
     @Nullable
@@ -290,7 +315,11 @@ public abstract class BaseIconCache {
 
     @NonNull
     protected String getIconSystemState(@Nullable final String packageName) {
-        return mSystemState;
+        return mIconProvider.getSystemStateForPackage(mSystemState, packageName);
+    }
+
+    public IconProvider getIconProvider() {
+        return mIconProvider;
     }
 
     public CharSequence getUserBadgedLabel(CharSequence label, UserHandle user) {
@@ -334,12 +363,14 @@ public abstract class BaseIconCache {
         }
         if (entry == null) {
             entry = new CacheEntry();
-            entry.bitmap = cachingLogic.loadIcon(mContext, object);
+            entry.bitmap = cachingLogic.loadIcon(mContext, this, object);
         }
         // Icon can't be loaded from cachingLogic, which implies alternative icon was loaded
         // (e.g. fallback icon, default icon). So we drop here since there's no point in caching
         // an empty entry.
-        if (entry.bitmap.isNullOrLowRes()) return;
+        if (entry.bitmap.isNullOrLowRes() || isDefaultIcon(entry.bitmap, user)) {
+            return;
+        }
 
         CharSequence entryTitle = cachingLogic.getLabel(object);
         if (TextUtils.isEmpty(entryTitle)) {
@@ -353,8 +384,8 @@ public abstract class BaseIconCache {
         entry.contentDescription = getUserBadgedLabel(entry.title, user);
         if (cachingLogic.addToMemCache()) mCache.put(key, entry);
 
-        ContentValues values = newContentValues(entry.bitmap, entry.title.toString(),
-                componentName.getPackageName(), cachingLogic.getKeywords(object, mLocaleList));
+        ContentValues values = newContentValues(
+                entry.bitmap, entry.title.toString(), componentName.getPackageName());
         addIconToDB(values, componentName, info, userSerial,
                 cachingLogic.getLastUpdatedTime(object, info));
     }
@@ -477,7 +508,7 @@ public abstract class BaseIconCache {
             final boolean usePackageTitle, @NonNull final ComponentName componentName,
             @NonNull final UserHandle user) {
         if (object != null) {
-            entry.bitmap = cachingLogic.loadIcon(mContext, object);
+            entry.bitmap = cachingLogic.loadIcon(mContext, this, object);
         } else {
             if (usePackageIcon) {
                 CacheEntry packageEntry = getEntryForPackageLocked(
@@ -541,7 +572,10 @@ public abstract class BaseIconCache {
         }
         if (icon != null) {
             BaseIconFactory li = getIconFactory();
-            entry.bitmap = li.createShapedIconBitmap(icon, new IconOptions().setUser(user));
+            entry.bitmap = li.createBadgedIconBitmap(
+                    li.createShapedAdaptiveIcon(icon),
+                    new IconOptions().setUser(user)
+            );
             li.close();
         }
         if (!TextUtils.isEmpty(title) && entry.bitmap.icon != null) {
@@ -613,7 +647,7 @@ public abstract class BaseIconCache {
                     // Add the icon in the DB here, since these do not get written during
                     // package updates.
                     ContentValues values = newContentValues(
-                            iconInfo, entry.title.toString(), packageName, null);
+                            iconInfo, entry.title.toString(), packageName);
                     addIconToDB(values, cacheKey.componentName, info, getSerialNumberForUser(user),
                             info.lastUpdateTime);
 
@@ -719,7 +753,9 @@ public abstract class BaseIconCache {
      * Cache class to store the actual entries on disk
      */
     public static final class IconDB extends SQLiteCacheHelper {
-        private static final int RELEASE_VERSION = 34;
+        // Ensures archived app icons are invalidated after flag is flipped.
+        // TODO: Remove conditional with FLAG_USE_NEW_ICON_FOR_ARCHIVED_APPS
+        private static final int RELEASE_VERSION = Flags.useNewIconForArchivedApps() ? 35 : 34;
 
         public static final String TABLE_NAME = "icons";
         public static final String COLUMN_ROWID = "rowid";
@@ -733,7 +769,6 @@ public abstract class BaseIconCache {
         public static final String COLUMN_FLAGS = "flags";
         public static final String COLUMN_LABEL = "label";
         public static final String COLUMN_SYSTEM_STATE = "system_state";
-        public static final String COLUMN_KEYWORDS = "keywords";
 
         public static final String[] COLUMNS_LOW_RES = new String[]{
                 COLUMN_COMPONENT,
@@ -772,7 +807,6 @@ public abstract class BaseIconCache {
                     + COLUMN_FLAGS + " INTEGER NOT NULL DEFAULT 0, "
                     + COLUMN_LABEL + " TEXT, "
                     + COLUMN_SYSTEM_STATE + " TEXT, "
-                    + COLUMN_KEYWORDS + " TEXT, "
                     + "PRIMARY KEY (" + COLUMN_COMPONENT + ", " + COLUMN_USER + ") "
                     + ");");
         }
@@ -780,8 +814,7 @@ public abstract class BaseIconCache {
 
     @NonNull
     private ContentValues newContentValues(@NonNull final BitmapInfo bitmapInfo,
-            @NonNull final String label, @NonNull final String packageName,
-            @Nullable final String keywords) {
+            @NonNull final String label, @NonNull final String packageName) {
         ContentValues values = new ContentValues();
         if (bitmapInfo.canPersist()) {
             values.put(IconDB.COLUMN_ICON, flattenBitmap(bitmapInfo.icon));
@@ -806,7 +839,6 @@ public abstract class BaseIconCache {
 
         values.put(IconDB.COLUMN_LABEL, label);
         values.put(IconDB.COLUMN_SYSTEM_STATE, getIconSystemState(packageName));
-        values.put(IconDB.COLUMN_KEYWORDS, keywords);
         return values;
     }
 
diff --git a/iconloaderlib/src/com/android/launcher3/icons/cache/CachedObject.java b/iconloaderlib/src/com/android/launcher3/icons/cache/CachedObject.java
new file mode 100644
index 0000000..7fc49bb
--- /dev/null
+++ b/iconloaderlib/src/com/android/launcher3/icons/cache/CachedObject.java
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
+package com.android.launcher3.icons.cache;
+
+import android.content.ComponentName;
+import android.content.pm.PackageManager;
+import android.graphics.drawable.Drawable;
+import android.os.UserHandle;
+
+import androidx.annotation.NonNull;
+import androidx.annotation.Nullable;
+
+/**
+ * A simple interface to represent an object which can be added to icon cache
+ *
+ * @param <T> Any subclass of the icon cache with which this object is associated
+ */
+public interface CachedObject<T extends BaseIconCache> {
+
+    /**
+     * Returns the component name for the underlying object
+     */
+    @NonNull ComponentName getComponent();
+
+    /**
+     * Returns the user for the underlying object
+     */
+    @NonNull UserHandle getUser();
+
+    /**
+     * Loads the user visible label for the provided object
+     */
+    @Nullable CharSequence getLabel(PackageManager pm);
+
+    /**
+     * Loads the user visible icon for the provided object
+     */
+    @Nullable
+    default Drawable getFullResIcon(@NonNull T cache) {
+        return null;
+    }
+}
diff --git a/iconloaderlib/src/com/android/launcher3/icons/cache/CachedObjectCachingLogic.kt b/iconloaderlib/src/com/android/launcher3/icons/cache/CachedObjectCachingLogic.kt
new file mode 100644
index 0000000..ac284b1
--- /dev/null
+++ b/iconloaderlib/src/com/android/launcher3/icons/cache/CachedObjectCachingLogic.kt
@@ -0,0 +1,55 @@
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
+package com.android.launcher3.icons.cache
+
+import android.content.ComponentName
+import android.content.Context
+import android.os.UserHandle
+import com.android.launcher3.icons.BaseIconFactory.IconOptions
+import com.android.launcher3.icons.BitmapInfo
+
+/** Caching logic for ComponentWithLabelAndIcon */
+class CachedObjectCachingLogic<T : BaseIconCache>
+@JvmOverloads
+constructor(
+    context: Context,
+    private val loadIcons: Boolean = true,
+    private val addToMemCache: Boolean = true,
+) : CachingLogic<CachedObject<T>> {
+
+    private val pm = context.packageManager
+
+    override fun getComponent(info: CachedObject<T>): ComponentName = info.component
+
+    override fun getUser(info: CachedObject<T>): UserHandle = info.user
+
+    override fun getLabel(info: CachedObject<T>): CharSequence? = info.getLabel(pm)
+
+    override fun loadIcon(
+        context: Context,
+        cache: BaseIconCache,
+        info: CachedObject<T>,
+    ): BitmapInfo {
+        if (!loadIcons) return BitmapInfo.LOW_RES_INFO
+        val d = info.getFullResIcon(cache as T) ?: return BitmapInfo.LOW_RES_INFO
+        cache.iconFactory.use { li ->
+            return li.createBadgedIconBitmap(d, IconOptions().setUser(info.user))
+        }
+    }
+
+    override fun addToMemCache() = addToMemCache
+}
diff --git a/iconloaderlib/src/com/android/launcher3/icons/cache/CachingLogic.java b/iconloaderlib/src/com/android/launcher3/icons/cache/CachingLogic.java
index 8034d6e..ef5c7b2 100644
--- a/iconloaderlib/src/com/android/launcher3/icons/cache/CachingLogic.java
+++ b/iconloaderlib/src/com/android/launcher3/icons/cache/CachingLogic.java
@@ -18,7 +18,6 @@ package com.android.launcher3.icons.cache;
 import android.content.ComponentName;
 import android.content.Context;
 import android.content.pm.PackageInfo;
-import android.os.LocaleList;
 import android.os.UserHandle;
 
 import androidx.annotation.NonNull;
@@ -34,7 +33,10 @@ public interface CachingLogic<T> {
     @NonNull
     UserHandle getUser(@NonNull final T object);
 
-    @NonNull
+    /**
+     * Loads the user visible label for the object
+     */
+    @Nullable
     CharSequence getLabel(@NonNull final T object);
 
     @NonNull
@@ -44,15 +46,7 @@ public interface CachingLogic<T> {
     }
 
     @NonNull
-    BitmapInfo loadIcon(@NonNull final Context context, @NonNull final T object);
-
-    /**
-     * Provides a option list of keywords to associate with this object
-     */
-    @Nullable
-    default String getKeywords(@NonNull final T object, @NonNull final LocaleList localeList) {
-        return null;
-    }
+    BitmapInfo loadIcon(@NonNull Context context, @NonNull BaseIconCache cache, @NonNull T object);
 
     /**
      * Returns the timestamp the entry was last updated in cache.
diff --git a/iconloaderlib/src/com/android/launcher3/icons/cache/IconCacheUpdateHandler.java b/iconloaderlib/src/com/android/launcher3/icons/cache/IconCacheUpdateHandler.java
index bf029ad..953551d 100644
--- a/iconloaderlib/src/com/android/launcher3/icons/cache/IconCacheUpdateHandler.java
+++ b/iconloaderlib/src/com/android/launcher3/icons/cache/IconCacheUpdateHandler.java
@@ -28,6 +28,8 @@ import android.util.ArrayMap;
 import android.util.Log;
 import android.util.SparseBooleanArray;
 
+import androidx.annotation.VisibleForTesting;
+
 import com.android.launcher3.icons.cache.BaseIconCache.IconDB;
 
 import java.util.ArrayDeque;
@@ -67,6 +69,15 @@ public class IconCacheUpdateHandler {
     private final SparseBooleanArray mItemsToDelete = new SparseBooleanArray();
     private boolean mFilterMode = MODE_SET_INVALID_ITEMS;
 
+    /**
+     * Constructor for testing.
+     */
+    @VisibleForTesting
+    public IconCacheUpdateHandler(HashMap<String, PackageInfo> pkgInfoMap, BaseIconCache cache) {
+        mIconCache = cache;
+        mPkgInfoMap = pkgInfoMap;
+    }
+
     IconCacheUpdateHandler(BaseIconCache cache) {
         mIconCache = cache;
 
@@ -152,53 +163,9 @@ public class IconCacheUpdateHandler {
                 IconDB.COLUMN_USER + " = ? ",
                 new String[]{Long.toString(userSerial)})) {
 
-            final int indexComponent = c.getColumnIndex(IconDB.COLUMN_COMPONENT);
-            final int indexLastUpdate = c.getColumnIndex(IconDB.COLUMN_LAST_UPDATED);
-            final int indexVersion = c.getColumnIndex(IconDB.COLUMN_VERSION);
-            final int rowIndex = c.getColumnIndex(IconDB.COLUMN_ROWID);
-            final int systemStateIndex = c.getColumnIndex(IconDB.COLUMN_SYSTEM_STATE);
-
             while (c.moveToNext()) {
-                String cn = c.getString(indexComponent);
-                ComponentName component = ComponentName.unflattenFromString(cn);
-                PackageInfo info = mPkgInfoMap.get(component.getPackageName());
-
-                int rowId = c.getInt(rowIndex);
-                if (info == null) {
-                    if (!ignorePackages.contains(component.getPackageName())) {
-
-                        if (mFilterMode == MODE_SET_INVALID_ITEMS) {
-                            mIconCache.remove(component, user);
-                            mItemsToDelete.put(rowId, true);
-                        }
-                    }
-                    continue;
-                }
-                if ((info.applicationInfo.flags & ApplicationInfo.FLAG_IS_DATA_ONLY) != 0) {
-                    // Application is not present
-                    continue;
-                }
-
-                long updateTime = c.getLong(indexLastUpdate);
-                int version = c.getInt(indexVersion);
-                T app = componentMap.remove(component);
-                if (version == info.versionCode
-                        && updateTime == cachingLogic.getLastUpdatedTime(app, info)
-                        && TextUtils.equals(c.getString(systemStateIndex),
-                        mIconCache.getIconSystemState(info.packageName))) {
-
-                    if (mFilterMode == MODE_CLEAR_VALID_ITEMS) {
-                        mItemsToDelete.put(rowId, false);
-                    }
-                    continue;
-                }
-
-                if (app == null) {
-                    if (mFilterMode == MODE_SET_INVALID_ITEMS) {
-                        mIconCache.remove(component, user);
-                        mItemsToDelete.put(rowId, true);
-                    }
-                } else {
+                var app = updateOrDeleteIcon(c, componentMap, ignorePackages, user, cachingLogic);
+                if (app != null) {
                     appsToUpdate.add(app);
                 }
             }
@@ -217,6 +184,71 @@ public class IconCacheUpdateHandler {
         }
     }
 
+    /**
+     * This method retrieves the component and either adds it to the list of apps to update or
+     * adds it to a list of apps to delete from cache later. Returns the individual app if it
+     * should be updated, or null if nothing should be updated.
+     */
+    @VisibleForTesting
+    public <T> T updateOrDeleteIcon(Cursor c, HashMap<ComponentName, T> componentMap,
+            Set<String> ignorePackages, UserHandle user, CachingLogic<T> cachingLogic) {
+
+        final int indexComponent = c.getColumnIndex(IconDB.COLUMN_COMPONENT);
+        final int indexLastUpdate = c.getColumnIndex(IconDB.COLUMN_LAST_UPDATED);
+        final int indexVersion = c.getColumnIndex(IconDB.COLUMN_VERSION);
+        final int rowIndex = c.getColumnIndex(IconDB.COLUMN_ROWID);
+        final int systemStateIndex = c.getColumnIndex(IconDB.COLUMN_SYSTEM_STATE);
+
+        int rowId = c.getInt(rowIndex);
+        String cn = c.getString(indexComponent);
+        ComponentName component = ComponentName.unflattenFromString(cn);
+        if (component == null) {
+            // b/357725795
+            Log.e(TAG, "Invalid component name while updating icon cache: " + cn);
+            mItemsToDelete.put(rowId, true);
+            return null;
+        }
+
+        PackageInfo info = mPkgInfoMap.get(component.getPackageName());
+
+        if (info == null) {
+            if (!ignorePackages.contains(component.getPackageName())) {
+
+                if (mFilterMode == MODE_SET_INVALID_ITEMS) {
+                    mIconCache.remove(component, user);
+                    mItemsToDelete.put(rowId, true);
+                }
+            }
+            return null;
+        }
+        if ((info.applicationInfo.flags & ApplicationInfo.FLAG_IS_DATA_ONLY) != 0) {
+            // Application is not present
+            return null;
+        }
+
+        long updateTime = c.getLong(indexLastUpdate);
+        int version = c.getInt(indexVersion);
+        T app = componentMap.remove(component);
+        if (version == info.versionCode
+                && updateTime == cachingLogic.getLastUpdatedTime(app, info)
+                && TextUtils.equals(c.getString(systemStateIndex),
+                mIconCache.getIconSystemState(info.packageName))) {
+
+            if (mFilterMode == MODE_CLEAR_VALID_ITEMS) {
+                mItemsToDelete.put(rowId, false);
+            }
+            return null;
+        }
+
+        if (app == null) {
+            if (mFilterMode == MODE_SET_INVALID_ITEMS) {
+                mIconCache.remove(component, user);
+                mItemsToDelete.put(rowId, true);
+            }
+        }
+        return app;
+    }
+
     /**
      * Commits all updates as part of the update handler to disk. Not more calls should be made
      * to this class after this.
diff --git a/iconloaderlib/src/com/android/launcher3/icons/cache/LauncherActivityCachingLogic.kt b/iconloaderlib/src/com/android/launcher3/icons/cache/LauncherActivityCachingLogic.kt
new file mode 100644
index 0000000..99af08b
--- /dev/null
+++ b/iconloaderlib/src/com/android/launcher3/icons/cache/LauncherActivityCachingLogic.kt
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
+
+package com.android.launcher3.icons.cache
+
+import android.content.ComponentName
+import android.content.Context
+import android.content.pm.LauncherActivityInfo
+import android.os.Build.VERSION
+import android.os.UserHandle
+import android.util.Log
+import com.android.launcher3.Flags.useNewIconForArchivedApps
+import com.android.launcher3.icons.BaseIconFactory.IconOptions
+import com.android.launcher3.icons.BitmapInfo
+
+object LauncherActivityCachingLogic : CachingLogic<LauncherActivityInfo> {
+    const val TAG = "LauncherActivityCachingLogic"
+
+    override fun getComponent(info: LauncherActivityInfo): ComponentName = info.componentName
+
+    override fun getUser(info: LauncherActivityInfo): UserHandle = info.user
+
+    override fun getLabel(info: LauncherActivityInfo): CharSequence? = info.label
+
+    override fun getDescription(info: LauncherActivityInfo, fallback: CharSequence) = fallback
+
+    override fun loadIcon(
+        context: Context,
+        cache: BaseIconCache,
+        info: LauncherActivityInfo,
+    ): BitmapInfo {
+        cache.iconFactory.use { li ->
+            val iconOptions: IconOptions = IconOptions().setUser(info.user)
+            iconOptions.setIsArchived(
+                useNewIconForArchivedApps() && VERSION.SDK_INT >= 35 && info.activityInfo.isArchived
+            )
+            val iconDrawable = cache.iconProvider.getIcon(info, li.fullResIconDpi)
+            if (
+                VERSION.SDK_INT >= 30 &&
+                    context.packageManager.isDefaultApplicationIcon(iconDrawable)
+            ) {
+                Log.w(
+                    TAG,
+                    "loadIcon: Default app icon returned from PackageManager." +
+                        " component=${info.componentName}, user=${info.user}",
+                    Exception(),
+                )
+                // Make sure this default icon always matches BaseIconCache#getDefaultIcon
+                return cache.getDefaultIcon(info.user)
+            }
+            return li.createBadgedIconBitmap(iconDrawable, iconOptions)
+        }
+    }
+}
diff --git a/iconloaderlib/src/com/android/launcher3/util/ComponentKey.java b/iconloaderlib/src/com/android/launcher3/util/ComponentKey.java
index 7145103..b79eae0 100644
--- a/iconloaderlib/src/com/android/launcher3/util/ComponentKey.java
+++ b/iconloaderlib/src/com/android/launcher3/util/ComponentKey.java
@@ -48,8 +48,8 @@ public class ComponentKey {
 
     @Override
     public boolean equals(Object o) {
-        ComponentKey other = (ComponentKey) o;
-        return other.componentName.equals(componentName) && other.user.equals(user);
+        return (o instanceof ComponentKey other)
+                && other.componentName.equals(componentName) && other.user.equals(user);
     }
 
     /**
diff --git a/monet/TEST_MAPPING b/monet/TEST_MAPPING
new file mode 100644
index 0000000..edd5f5f
--- /dev/null
+++ b/monet/TEST_MAPPING
@@ -0,0 +1,12 @@
+{
+  "presubmit": [
+    {
+      "name": "CtsGraphicsTestCases",
+      "options": [
+        {
+          "exclude-annotation": "androidx.test.filters.FlakyTest"
+        }
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/monet/src/com/android/systemui/monet/ColorScheme.java b/monet/src/com/android/systemui/monet/ColorScheme.java
index d290fff..61e3d38 100644
--- a/monet/src/com/android/systemui/monet/ColorScheme.java
+++ b/monet/src/com/android/systemui/monet/ColorScheme.java
@@ -328,7 +328,13 @@ public class ColorScheme {
     }
 
     private static double hueDiff(double a, double b) {
-        return 180f - (Math.abs(a - b) - 180f);
+        double diff = Math.abs(a - b);
+        if (diff > 180f) {
+            // 0 and 360 are the same hue. If hue difference is greater than 180, subtract from 360
+            // to account for the circularity.
+            diff = 360f - diff;
+        }
+        return diff;
     }
 
     private static String stringForColor(int color) {
diff --git a/monet/src/com/android/systemui/monet/CustomDynamicColors.java b/monet/src/com/android/systemui/monet/CustomDynamicColors.java
index 2e36229..9546ce0 100644
--- a/monet/src/com/android/systemui/monet/CustomDynamicColors.java
+++ b/monet/src/com/android/systemui/monet/CustomDynamicColors.java
@@ -47,7 +47,7 @@ class CustomDynamicColors {
         return new DynamicColor(
                 /* name= */ "clock_hour",
                 /* palette= */ (s) -> s.secondaryPalette,
-                /* tone= */ (s) -> s.isDark ? 30.0 : 60.0,
+                /* tone= */ (s) -> s.isDark ? 60.0 : 30.0,
                 /* isBackground= */ false,
                 /* background= */ (s) -> widgetBackground(),
                 /* secondBackground= */ null,
@@ -61,7 +61,7 @@ class CustomDynamicColors {
         return new DynamicColor(
                 /* name= */ "clock_minute",
                 /* palette= */ (s) -> s.primaryPalette,
-                /* tone= */ (s) -> s.isDark ? 40.0 : 90.0,
+                /* tone= */ (s) -> s.isDark ? 90.0 : 40.0,
                 /* isBackground= */ false,
                 /* background= */ (s) -> widgetBackground(),
                 /* secondBackground= */ null,
@@ -73,7 +73,7 @@ class CustomDynamicColors {
         return new DynamicColor(
                 /* name= */ "clock_second",
                 /* palette= */ (s) -> s.tertiaryPalette,
-                /* tone= */ (s) -> s.isDark ? 40.0 : 90.0,
+                /* tone= */ (s) -> s.isDark ? 90.0 : 40.0,
                 /* isBackground= */ false,
                 /* background= */ (s) -> widgetBackground(),
                 /* secondBackground= */ null,
@@ -83,9 +83,9 @@ class CustomDynamicColors {
 
     public DynamicColor weatherTemp() {
         return new DynamicColor(
-                /* name= */ "clock_second",
+                /* name= */ "weather_temp",
                 /* palette= */ (s) -> s.primaryPalette,
-                /* tone= */ (s) -> s.isDark ? 55.0 : 80.0,
+                /* tone= */ (s) -> s.isDark ? 80.0 : 55.0,
                 /* isBackground= */ false,
                 /* background= */ (s) -> widgetBackground(),
                 /* secondBackground= */ null,
@@ -99,7 +99,7 @@ class CustomDynamicColors {
         return new DynamicColor(
                 /* name= */ "theme_app",
                 /* palette= */ (s) -> s.primaryPalette,
-                /* tone= */ (s) -> s.isDark ? 90.0 : 30.0, // Adjusted values
+                /* tone= */ (s) -> s.isDark ? 30.0 : 90.0, // Adjusted values
                 /* isBackground= */ true,
                 /* background= */ null,
                 /* secondBackground= */ null,
@@ -111,7 +111,7 @@ class CustomDynamicColors {
         return new DynamicColor(
                 /* name= */ "on_theme_app",
                 /* palette= */ (s) -> s.primaryPalette,
-                /* tone= */ (s) -> s.isDark ? 40.0 : 80.0, // Adjusted values
+                /* tone= */ (s) -> s.isDark ? 80.0 : 40.0, // Adjusted values
                 /* isBackground= */ false,
                 /* background= */ (s) -> themeApp(),
                 /* secondBackground= */ null,
@@ -135,7 +135,7 @@ class CustomDynamicColors {
         return new DynamicColor(
                 /* name= */ "theme_notif",
                 /* palette= */ (s) -> s.tertiaryPalette,
-                /* tone= */ (s) -> s.isDark ? 80.0 : 90.0,
+                /* tone= */ (s) -> s.isDark ? 90.0 : 80.0,
                 /* isBackground= */ false,
                 /* background= */ (s) -> themeAppRing(),
                 /* secondBackground= */ null,
@@ -151,7 +151,7 @@ class CustomDynamicColors {
         return new DynamicColor(
                 /* name= */ "brand_a",
                 /* palette= */ (s) -> s.primaryPalette,
-                /* tone= */ (s) -> s.isDark ? 40.0 : 80.0,
+                /* tone= */ (s) -> s.isDark ? 80.0 : 40.0,
                 /* isBackground= */ true,
                 /* background= */ (s) -> mMdc.surfaceContainerLow(),
                 /* secondBackground= */ null,
@@ -164,7 +164,7 @@ class CustomDynamicColors {
         return new DynamicColor(
                 /* name= */ "brand_b",
                 /* palette= */ (s) -> s.secondaryPalette,
-                /* tone= */ (s) -> s.isDark ? 70.0 : 98.0,
+                /* tone= */ (s) -> s.isDark ? 98.0 : 70.0,
                 /* isBackground= */ true,
                 /* background= */ (s) -> mMdc.surfaceContainerLow(),
                 /* secondBackground= */ null,
@@ -177,7 +177,7 @@ class CustomDynamicColors {
         return new DynamicColor(
                 /* name= */ "brand_c",
                 /* palette= */ (s) -> s.primaryPalette,
-                /* tone= */ (s) -> s.isDark ? 50.0 : 60.0,
+                /* tone= */ (s) -> s.isDark ? 60.0 : 50.0,
                 /* isBackground= */ false,
                 /* background= */ (s) -> mMdc.surfaceContainerLow(),
                 /* secondBackground= */ null,
@@ -190,7 +190,7 @@ class CustomDynamicColors {
         return new DynamicColor(
                 /* name= */ "brand_d",
                 /* palette= */ (s) -> s.tertiaryPalette,
-                /* tone= */ (s) -> s.isDark ? 59.0 : 90.0,
+                /* tone= */ (s) -> s.isDark ? 90.0 : 59.0,
                 /* isBackground= */ false,
                 /* background= */ (s) -> mMdc.surfaceContainerLow(),
                 /* secondBackground= */ null,
@@ -312,7 +312,7 @@ class CustomDynamicColors {
         return new DynamicColor(
                 /* name= */ "overview_background",
                 /* palette= */ (s) -> s.neutralVariantPalette,
-                /* tone= */ (s) -> s.isDark ? 80.0 : 35.0,
+                /* tone= */ (s) -> s.isDark ? 35.0 : 80.0,
                 /* isBackground= */ true,
                 /* background= */ null,
                 /* secondBackground= */ null,
diff --git a/monet/src/com/android/systemui/monet/DynamicColors.java b/monet/src/com/android/systemui/monet/DynamicColors.java
index 118a034..7653e77 100644
--- a/monet/src/com/android/systemui/monet/DynamicColors.java
+++ b/monet/src/com/android/systemui/monet/DynamicColors.java
@@ -130,7 +130,7 @@ public class DynamicColors {
         list.add(Pair.create("theme_app", customMdc.themeApp()));
         list.add(Pair.create("on_theme_app", customMdc.onThemeApp()));
         list.add(Pair.create("theme_app_ring", customMdc.themeAppRing()));
-        list.add(Pair.create("on_theme_app_ring", customMdc.themeNotif()));
+        list.add(Pair.create("theme_notif", customMdc.themeNotif()));
         list.add(Pair.create("brand_a", customMdc.brandA()));
         list.add(Pair.create("brand_b", customMdc.brandB()));
         list.add(Pair.create("brand_c", customMdc.brandC()));
diff --git a/monet/tests/Android.bp b/monet/tests/Android.bp
index 0304ab6..b62fd4b 100644
--- a/monet/tests/Android.bp
+++ b/monet/tests/Android.bp
@@ -35,8 +35,8 @@ android_test {
         "**/*.kt",
     ],
     libs: [
-        "android.test.runner",
-        "android.test.base",
+        "android.test.runner.stubs.system",
+        "android.test.base.stubs.system",
     ],
     test_suites: ["device-tests"],
 }
diff --git a/motiontoollib/Android.bp b/motiontoollib/Android.bp
index c7d9463..7d8be54 100644
--- a/motiontoollib/Android.bp
+++ b/motiontoollib/Android.bp
@@ -73,8 +73,8 @@ android_test {
         "**/*.kt",
     ],
     libs: [
-        "android.test.runner",
-        "android.test.base",
+        "android.test.runner.stubs.system",
+        "android.test.base.stubs.system",
     ],
     test_suites: ["device-tests"],
 }
diff --git a/motiontoollib/build.gradle b/motiontoollib/build.gradle
index 0e3c6a1..62dfa3b 100644
--- a/motiontoollib/build.gradle
+++ b/motiontoollib/build.gradle
@@ -1,11 +1,8 @@
 plugins {
     id 'com.android.library'
     id 'org.jetbrains.kotlin.android'
-    id 'com.google.protobuf'
 }
 
-final String PROTOS_DIR = "${ANDROID_TOP}/frameworks/libs/systemui/motiontoollib/src/com/android/app/motiontool/proto"
-
 android {
     namespace = "com.android.app.motiontool"
     testNamespace = "com.android.app.motiontool.tests"
@@ -17,7 +14,6 @@ android {
         main {
             java.srcDirs = ['src']
             manifest.srcFile 'AndroidManifest.xml'
-            proto.srcDirs = ["${PROTOS_DIR}"]
         }
         androidTest {
             java.srcDirs = ["tests"]
@@ -32,32 +28,11 @@ android {
 
 dependencies {
     implementation "androidx.core:core:1.9.0"
-    implementation "com.google.protobuf:protobuf-lite:${protobuf_lite_version}"
+    implementation(project(":frameworks:libs:systemui:motiontoollib:motion_tool_proto"))
+    implementation(project(":frameworks:libs:systemui:viewcapturelib:view_capture_proto"))
+
     api project(":ViewCaptureLib")
     androidTestImplementation project(':SharedTestLib')
     androidTestImplementation 'androidx.test.ext:junit:1.1.3'
     androidTestImplementation "androidx.test:rules:1.4.0"
-}
-
-protobuf {
-    // Configure the protoc executable
-    protoc {
-        artifact = "com.google.protobuf:protoc:${protobuf_version}${PROTO_ARCH_SUFFIX}"
-    }
-    plugins {
-        javalite {
-            // The codegen for lite comes as a separate artifact
-            artifact = "com.google.protobuf:protoc-gen-javalite:${protobuf_lite_version}${PROTO_ARCH_SUFFIX}"
-        }
-    }
-    generateProtoTasks {
-        all().each { task ->
-            task.builtins {
-                remove java
-            }
-            task.plugins {
-                javalite { }
-            }
-        }
-    }
-}
+}
\ No newline at end of file
diff --git a/msdllib/Android.bp b/msdllib/Android.bp
new file mode 100644
index 0000000..920ed17
--- /dev/null
+++ b/msdllib/Android.bp
@@ -0,0 +1,73 @@
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
+    default_team: "trendy_team_motion",
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+android_library {
+    name: "msdl",
+    manifest: "AndroidManifest.xml",
+    sdk_version: "system_current",
+    min_sdk_version: "33",
+    static_libs: [
+        "kotlinx_coroutines_android",
+        "androidx.annotation_annotation",
+    ],
+    srcs: [
+        "src/**/*.java",
+        "src/**/*.kt",
+    ],
+    kotlincflags: ["-Xjvm-default=all"],
+}
+
+android_library {
+    name: "msdl-tests-base",
+    libs: [
+        "android.test.base.stubs.system",
+        "androidx.test.core",
+    ],
+    static_libs: [
+        "msdl",
+        "androidx.test.ext.junit",
+        "androidx.test.rules",
+        "testables",
+        "truth",
+        "kotlinx_coroutines_test",
+        "kotlin-test",
+    ],
+}
+
+android_app {
+    name: "TestMSDLApp",
+    platform_apis: true,
+    static_libs: [
+        "msdl-tests-base",
+    ],
+}
+
+android_test {
+    name: "msdl_tests",
+    manifest: "tests/AndroidManifest.xml",
+
+    static_libs: [
+        "msdl-tests-base",
+    ],
+    srcs: [
+        "tests/src/**/*.kt",
+    ],
+    kotlincflags: ["-Xjvm-default=all"],
+    test_suites: ["general-tests"],
+}
diff --git a/msdllib/AndroidManifest.xml b/msdllib/AndroidManifest.xml
new file mode 100644
index 0000000..937187d
--- /dev/null
+++ b/msdllib/AndroidManifest.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+     Copyright (C) 2024 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+-->
+
+<manifest xmlns:android="http://schemas.android.com/apk/res/android"
+  package="com.google.android.msdl">
+  <uses-permission android:name="android.permission.VIBRATE" />
+</manifest>
diff --git a/msdllib/TEST_MAPPING b/msdllib/TEST_MAPPING
new file mode 100644
index 0000000..de14781
--- /dev/null
+++ b/msdllib/TEST_MAPPING
@@ -0,0 +1,7 @@
+{
+  "postsubmit": [
+    {
+      "name": "msdl_tests"
+    }
+  ]
+}
diff --git a/msdllib/src/com/google/android/msdl/data/model/HapticComposition.kt b/msdllib/src/com/google/android/msdl/data/model/HapticComposition.kt
new file mode 100644
index 0000000..30f8e13
--- /dev/null
+++ b/msdllib/src/com/google/android/msdl/data/model/HapticComposition.kt
@@ -0,0 +1,42 @@
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
+package com.google.android.msdl.data.model
+
+import android.os.VibrationEffect
+
+/**
+ * A haptic composition as a list of [HapticCompositionPrimitive] and a [android.os.VibrationEffect]
+ * to use as a fallback.
+ */
+data class HapticComposition(
+    val primitives: List<HapticCompositionPrimitive>,
+    val fallbackEffect: VibrationEffect,
+)
+
+/**
+ * An abstraction of a haptic primitive in a composition that includes:
+ *
+ * @param[primitiveId] The id of the primitive.
+ * @param[scale] The scale of the primitive.
+ * @param[delayMillis] The delay of the primitive relative to the end of a previous primitive. Given
+ *   in milliseconds.
+ */
+data class HapticCompositionPrimitive(
+    val primitiveId: Int,
+    var scale: Float = 1f,
+    var delayMillis: Int = 0,
+)
diff --git a/msdllib/src/com/google/android/msdl/data/model/HapticToken.kt b/msdllib/src/com/google/android/msdl/data/model/HapticToken.kt
new file mode 100644
index 0000000..98be02d
--- /dev/null
+++ b/msdllib/src/com/google/android/msdl/data/model/HapticToken.kt
@@ -0,0 +1,39 @@
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
+package com.google.android.msdl.data.model
+
+/** Haptic tokens from the Multi-sensory Design Language (MSDL) */
+enum class HapticToken {
+    NEGATIVE_CONFIRMATION_HIGH_EMPHASIS,
+    NEGATIVE_CONFIRMATION_MEDIUM_EMPHASIS,
+    POSITIVE_CONFIRMATION_HIGH_EMPHASIS,
+    POSITIVE_CONFIRMATION_MEDIUM_EMPHASIS,
+    POSITIVE_CONFIRMATION_LOW_EMPHASIS,
+    NEUTRAL_CONFIRMATION_HIGH_EMPHASIS,
+    NEUTRAL_CONFIRMATION_MEDIUM_EMPHASIS,
+    LONG_PRESS,
+    SWIPE_THRESHOLD_INDICATOR,
+    TAP_HIGH_EMPHASIS,
+    TAP_MEDIUM_EMPHASIS,
+    DRAG_THRESHOLD_INDICATOR,
+    DRAG_INDICATOR,
+    TAP_LOW_EMPHASIS,
+    KEYPRESS_STANDARD,
+    KEYPRESS_SPACEBAR,
+    KEYPRESS_RETURN,
+    KEYPRESS_DELETE,
+}
diff --git a/msdllib/src/com/google/android/msdl/data/model/MSDLToken.kt b/msdllib/src/com/google/android/msdl/data/model/MSDLToken.kt
new file mode 100644
index 0000000..99e6d00
--- /dev/null
+++ b/msdllib/src/com/google/android/msdl/data/model/MSDLToken.kt
@@ -0,0 +1,169 @@
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
+package com.google.android.msdl.data.model
+
+/** System-level tokens defined in the Multi-sensory Design Language (MSDL) */
+enum class MSDLToken(
+    val hapticToken: HapticToken,
+    val soundToken: SoundToken,
+    val minimumFeedbackLevel: FeedbackLevel,
+) {
+    /* Inform the user with emphasis that their current action FAILED to complete */
+    FAILURE_HIGH_EMPHASIS(
+        HapticToken.NEGATIVE_CONFIRMATION_HIGH_EMPHASIS,
+        SoundToken.FAILURE_HIGH_EMPHASIS,
+        FeedbackLevel.MINIMAL,
+    ),
+    /* Inform the user that their current action FAILED to complete */
+    FAILURE(
+        HapticToken.NEGATIVE_CONFIRMATION_MEDIUM_EMPHASIS,
+        SoundToken.FAILURE,
+        FeedbackLevel.MINIMAL,
+    ),
+    /* Inform the user their current action was completed SUCCESSFULLY */
+    SUCCESS(
+        HapticToken.POSITIVE_CONFIRMATION_HIGH_EMPHASIS,
+        SoundToken.SUCCESS,
+        FeedbackLevel.MINIMAL,
+    ),
+    /* Inform the user that an ongoing activity has started */
+    START(
+        HapticToken.NEUTRAL_CONFIRMATION_HIGH_EMPHASIS,
+        SoundToken.START,
+        FeedbackLevel.DEFAULT,
+    ),
+    /* Inform the user that an ongoing activity has paused */
+    PAUSE(
+        HapticToken.NEUTRAL_CONFIRMATION_MEDIUM_EMPHASIS,
+        SoundToken.PAUSE,
+        FeedbackLevel.DEFAULT,
+    ),
+    /* Inform the user that their previously started activity has stopped SUCCESSFULLY */
+    STOP(
+        HapticToken.POSITIVE_CONFIRMATION_MEDIUM_EMPHASIS,
+        SoundToken.STOP,
+        FeedbackLevel.DEFAULT,
+    ),
+    /* Inform the user that their previously started activity has cancelled SUCCESSFULLY */
+    CANCEL(
+        HapticToken.POSITIVE_CONFIRMATION_MEDIUM_EMPHASIS,
+        SoundToken.CANCEL,
+        FeedbackLevel.DEFAULT,
+    ),
+    /* Inform the user that the state of an interactive component has been switched to on SUCCESSFULLY */
+    SWITCH_ON(
+        HapticToken.POSITIVE_CONFIRMATION_MEDIUM_EMPHASIS,
+        SoundToken.SWITCH_ON,
+        FeedbackLevel.DEFAULT,
+    ),
+    /* Inform the user that the state of an interactive component has been switched to off SUCCESSFULLY */
+    SWITCH_OFF(
+        HapticToken.POSITIVE_CONFIRMATION_MEDIUM_EMPHASIS,
+        SoundToken.SWITCH_OFF,
+        FeedbackLevel.DEFAULT,
+    ),
+    /* Inform the user the state of their device changed to unlocked SUCCESSFULLY */
+    UNLOCK(
+        HapticToken.POSITIVE_CONFIRMATION_LOW_EMPHASIS,
+        SoundToken.UNLOCK,
+        FeedbackLevel.DEFAULT,
+    ),
+    /* Inform the user the state of their device changed to locked SUCCESSFULLY */
+    LOCK(
+        HapticToken.POSITIVE_CONFIRMATION_LOW_EMPHASIS,
+        SoundToken.LOCK,
+        FeedbackLevel.DEFAULT,
+    ),
+    /* Inform the user that their long-press gesture has resulted in the revealing of more contextual information */
+    LONG_PRESS(
+        HapticToken.LONG_PRESS,
+        SoundToken.LONG_PRESS,
+        FeedbackLevel.MINIMAL,
+    ),
+    /* Inform the user that their swipe gesture has reached a threshold that confirms navigation or the reveal of additional information. */
+    SWIPE_THRESHOLD_INDICATOR(
+        HapticToken.SWIPE_THRESHOLD_INDICATOR,
+        SoundToken.SWIPE_THRESHOLD_INDICATOR,
+        FeedbackLevel.MINIMAL,
+    ),
+    /* Played when the user taps on a high-emphasis UI element */
+    TAP_HIGH_EMPHASIS(
+        HapticToken.TAP_HIGH_EMPHASIS,
+        SoundToken.TAP_HIGH_EMPHASIS,
+        FeedbackLevel.EXPRESSIVE,
+    ),
+    /* Inform the user that their tap has resulted in a selection */
+    TAP_MEDIUM_EMPHASIS(
+        HapticToken.TAP_MEDIUM_EMPHASIS,
+        SoundToken.TAP_MEDIUM_EMPHASIS,
+        FeedbackLevel.DEFAULT,
+    ),
+    /* Played when a users drag gesture reaches the maximum or minimum value */
+    DRAG_THRESHOLD_INDICATOR_LIMIT(
+        HapticToken.DRAG_THRESHOLD_INDICATOR,
+        SoundToken.DRAG_THRESHOLD_INDICATOR_LIMIT,
+        FeedbackLevel.DEFAULT,
+    ),
+    /* Inform the user that their drag gesture has resulted in an incremental value change.
+     * For usage in haptic sliders, this token can be played along with
+     * [InteractionProperties.DynamicVibrationScale] properties to control haptic scaling as a
+     * function of position and velocity.
+     */
+    DRAG_INDICATOR(
+        HapticToken.DRAG_INDICATOR,
+        SoundToken.DRAG_INDICATOR,
+        FeedbackLevel.DEFAULT,
+    ),
+    /* Played when a user taps on any UI element that can be interacted with but is not otherwise defined */
+    TAP_LOW_EMPHASIS(
+        HapticToken.TAP_LOW_EMPHASIS,
+        SoundToken.TAP_LOW_EMPHASIS,
+        FeedbackLevel.EXPRESSIVE,
+    ),
+    /* Played when the user touches a key on the keyboard that is otherwise undefined */
+    KEYPRESS_STANDARD(
+        HapticToken.KEYPRESS_STANDARD,
+        SoundToken.KEYPRESS_STANDARD,
+        FeedbackLevel.DEFAULT,
+    ),
+    /* Played when the user touches the space key */
+    KEYPRESS_SPACEBAR(
+        HapticToken.KEYPRESS_SPACEBAR,
+        SoundToken.KEYPRESS_SPACEBAR,
+        FeedbackLevel.DEFAULT,
+    ),
+    /* Played when the user touches the return key */
+    KEYPRESS_RETURN(
+        HapticToken.KEYPRESS_RETURN,
+        SoundToken.KEYPRESS_RETURN,
+        FeedbackLevel.DEFAULT,
+    ),
+    /* Played when the user touches the delete key */
+    KEYPRESS_DELETE(
+        HapticToken.KEYPRESS_DELETE,
+        SoundToken.KEYPRESS_DELETE,
+        FeedbackLevel.DEFAULT,
+    ),
+}
+
+/** Level of feedback that contains a token */
+enum class FeedbackLevel {
+    NO_FEEDBACK,
+    MINIMAL,
+    DEFAULT,
+    EXPRESSIVE,
+}
diff --git a/msdllib/src/com/google/android/msdl/data/model/SoundToken.kt b/msdllib/src/com/google/android/msdl/data/model/SoundToken.kt
new file mode 100644
index 0000000..bc1ebf0
--- /dev/null
+++ b/msdllib/src/com/google/android/msdl/data/model/SoundToken.kt
@@ -0,0 +1,43 @@
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
+package com.google.android.msdl.data.model
+
+/** Sound tokens from the Multi-sensory Design Language (MSDL) */
+enum class SoundToken {
+    FAILURE_HIGH_EMPHASIS,
+    FAILURE,
+    SUCCESS,
+    START,
+    PAUSE,
+    STOP,
+    CANCEL,
+    SWITCH_ON,
+    SWITCH_OFF,
+    UNLOCK,
+    LOCK,
+    LONG_PRESS,
+    SWIPE_THRESHOLD_INDICATOR,
+    TAP_HIGH_EMPHASIS,
+    TAP_MEDIUM_EMPHASIS,
+    DRAG_THRESHOLD_INDICATOR_LIMIT,
+    DRAG_INDICATOR,
+    TAP_LOW_EMPHASIS,
+    KEYPRESS_STANDARD,
+    KEYPRESS_SPACEBAR,
+    KEYPRESS_RETURN,
+    KEYPRESS_DELETE,
+}
diff --git a/msdllib/src/com/google/android/msdl/data/repository/MSDLRepository.kt b/msdllib/src/com/google/android/msdl/data/repository/MSDLRepository.kt
new file mode 100644
index 0000000..b891661
--- /dev/null
+++ b/msdllib/src/com/google/android/msdl/data/repository/MSDLRepository.kt
@@ -0,0 +1,70 @@
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
+package com.google.android.msdl.data.repository
+
+import androidx.annotation.VisibleForTesting
+import com.google.android.msdl.data.model.HapticToken
+import com.google.android.msdl.data.model.SoundToken
+
+/**
+ * A repository of data for [HapticToken] and [SoundToken].
+ *
+ * The principle behind this repository is to hold the data for all tokens as a cache in memory.
+ * This is only suitable if the number of tokens and the data stored is manageable. The purpose of
+ * this design choice is to provide fast and easy access to the data when required to be played by
+ * UI interactions.
+ */
+sealed interface MSDLRepository {
+
+    /**
+     * Get the [MSDLHapticData] that corresponds to the given haptic reference token. This function
+     * needs to be fast since it will be called repeatedly to deliver feedback. If necessary, a
+     * caching strategy should be applied.
+     *
+     * @param[hapticToken] The [HapticToken] that points to the data.
+     * @return the data that corresponds to the token at the time this function is called.
+     */
+    fun getHapticData(hapticToken: HapticToken): MSDLHapticData?
+
+    /**
+     * Get the [MSDLSoundData] that corresponds to the given sound reference token. This function
+     * needs to be fast since it will be called repeatedly to deliver feedback. If necessary, a
+     * caching strategy should be applied.
+     *
+     * @param[soundToken] The [SoundToken] that points to the data.
+     * @return the data that corresponds to the token at the time this function is called.
+     */
+    fun getAudioData(soundToken: SoundToken): MSDLSoundData?
+
+    companion object {
+
+        @VisibleForTesting fun createRepository(): MSDLRepository = MSDLRepositoryImpl()
+    }
+}
+
+/** Representation of data contained in a [MSDLRepository] */
+fun interface MSDLHapticData {
+
+    /** Retrieve the haptic data */
+    fun get(): Any?
+}
+
+/** Representation of data contained in a [MSDLRepository] */
+fun interface MSDLSoundData {
+
+    /** Retrieve the sound data */
+    fun get(): Any?
+}
diff --git a/msdllib/src/com/google/android/msdl/data/repository/MSDLRepositoryImpl.kt b/msdllib/src/com/google/android/msdl/data/repository/MSDLRepositoryImpl.kt
new file mode 100644
index 0000000..5074a99
--- /dev/null
+++ b/msdllib/src/com/google/android/msdl/data/repository/MSDLRepositoryImpl.kt
@@ -0,0 +1,343 @@
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
+package com.google.android.msdl.data.repository
+
+import android.os.VibrationEffect
+import com.google.android.msdl.data.model.HapticComposition
+import com.google.android.msdl.data.model.HapticCompositionPrimitive
+import com.google.android.msdl.data.model.HapticToken
+import com.google.android.msdl.data.model.SoundToken
+
+/** A [MSDLRepository] that holds haptic compositions as haptic data. */
+internal class MSDLRepositoryImpl : MSDLRepository {
+
+    override fun getAudioData(soundToken: SoundToken): MSDLSoundData? {
+        // TODO(b/345248875) Implement a caching strategy in accordance to the audio file strategy
+        return null
+    }
+
+    override fun getHapticData(hapticToken: HapticToken): MSDLHapticData? = HAPTIC_DATA[hapticToken]
+
+    companion object {
+        // Timings and amplitudes that recreate a composition of three SPIN primitives as a waveform
+        private val SPIN_TIMINGS = longArrayOf(20, 20, 3, 43, 20, 20, 3)
+        private val SPIN_AMPLITUDES = intArrayOf(40, 80, 40, 0, 40, 80, 40)
+        private const val SPIN_DELAY = 56L
+        private const val SPIN_BREAK = 10
+        private val SPIN_WAVEFORM_TIMINGS =
+            SPIN_TIMINGS + SPIN_DELAY + SPIN_TIMINGS + SPIN_DELAY + SPIN_TIMINGS
+        private val SPIN_WAVEFORM_AMPLITUDES =
+            SPIN_AMPLITUDES + SPIN_BREAK + SPIN_AMPLITUDES + SPIN_BREAK + SPIN_AMPLITUDES
+
+        private val HAPTIC_DATA: Map<HapticToken, MSDLHapticData> =
+            mapOf(
+                HapticToken.NEGATIVE_CONFIRMATION_HIGH_EMPHASIS to
+                    MSDLHapticData {
+                        HapticComposition(
+                            listOf(
+                                HapticCompositionPrimitive(
+                                    VibrationEffect.Composition.PRIMITIVE_SPIN,
+                                    scale = 1f,
+                                    delayMillis = 0,
+                                ),
+                                HapticCompositionPrimitive(
+                                    VibrationEffect.Composition.PRIMITIVE_SPIN,
+                                    scale = 1f,
+                                    delayMillis = SPIN_DELAY.toInt(),
+                                ),
+                                HapticCompositionPrimitive(
+                                    VibrationEffect.Composition.PRIMITIVE_SPIN,
+                                    scale = 1f,
+                                    delayMillis = SPIN_DELAY.toInt(),
+                                ),
+                            ),
+                            VibrationEffect.createWaveform(
+                                SPIN_WAVEFORM_TIMINGS,
+                                SPIN_WAVEFORM_AMPLITUDES,
+                                -1,
+                            ),
+                        )
+                    },
+                HapticToken.NEGATIVE_CONFIRMATION_MEDIUM_EMPHASIS to
+                    MSDLHapticData {
+                        HapticComposition(
+                            listOf(
+                                HapticCompositionPrimitive(
+                                    VibrationEffect.Composition.PRIMITIVE_CLICK,
+                                    scale = 1f,
+                                    delayMillis = 0,
+                                ),
+                                HapticCompositionPrimitive(
+                                    VibrationEffect.Composition.PRIMITIVE_CLICK,
+                                    scale = 1f,
+                                    delayMillis = 114,
+                                ),
+                                HapticCompositionPrimitive(
+                                    VibrationEffect.Composition.PRIMITIVE_CLICK,
+                                    scale = 1f,
+                                    delayMillis = 114,
+                                ),
+                            ),
+                            VibrationEffect.createWaveform(
+                                longArrayOf(10, 10, 10, 114, 10, 10, 10, 114, 10, 10, 10),
+                                intArrayOf(10, 255, 20, 0, 10, 255, 20, 0, 10, 255, 20),
+                                -1,
+                            ),
+                        )
+                    },
+                HapticToken.POSITIVE_CONFIRMATION_HIGH_EMPHASIS to
+                    MSDLHapticData {
+                        HapticComposition(
+                            listOf(
+                                HapticCompositionPrimitive(
+                                    VibrationEffect.Composition.PRIMITIVE_CLICK,
+                                    scale = 1f,
+                                    delayMillis = 0,
+                                ),
+                                HapticCompositionPrimitive(
+                                    VibrationEffect.Composition.PRIMITIVE_CLICK,
+                                    scale = 1f,
+                                    delayMillis = 114,
+                                ),
+                            ),
+                            VibrationEffect.createWaveform(
+                                longArrayOf(10, 10, 10, 114, 10, 10, 10),
+                                intArrayOf(10, 255, 20, 0, 10, 255, 20),
+                                -1,
+                            ),
+                        )
+                    },
+                HapticToken.POSITIVE_CONFIRMATION_MEDIUM_EMPHASIS to
+                    MSDLHapticData {
+                        HapticComposition(
+                            listOf(
+                                HapticCompositionPrimitive(
+                                    VibrationEffect.Composition.PRIMITIVE_CLICK,
+                                    scale = 1f,
+                                    delayMillis = 0,
+                                ),
+                                HapticCompositionPrimitive(
+                                    VibrationEffect.Composition.PRIMITIVE_CLICK,
+                                    scale = 1f,
+                                    delayMillis = 52,
+                                ),
+                            ),
+                            VibrationEffect.createWaveform(
+                                longArrayOf(10, 10, 10, 52, 10, 10, 10),
+                                intArrayOf(10, 255, 20, 0, 10, 255, 20),
+                                -1,
+                            ),
+                        )
+                    },
+                HapticToken.POSITIVE_CONFIRMATION_LOW_EMPHASIS to
+                    MSDLHapticData {
+                        HapticComposition(
+                            listOf(
+                                HapticCompositionPrimitive(
+                                    VibrationEffect.Composition.PRIMITIVE_TICK,
+                                    scale = 1f,
+                                    delayMillis = 0,
+                                ),
+                                HapticCompositionPrimitive(
+                                    VibrationEffect.Composition.PRIMITIVE_CLICK,
+                                    scale = 1f,
+                                    delayMillis = 52,
+                                ),
+                            ),
+                            VibrationEffect.createWaveform(
+                                longArrayOf(5, 52, 10, 10, 10),
+                                intArrayOf(100, 0, 10, 255, 20),
+                                -1,
+                            ),
+                        )
+                    },
+                HapticToken.NEUTRAL_CONFIRMATION_HIGH_EMPHASIS to
+                    MSDLHapticData {
+                        HapticComposition(
+                            listOf(
+                                HapticCompositionPrimitive(
+                                    VibrationEffect.Composition.PRIMITIVE_THUD,
+                                    scale = 1f,
+                                    delayMillis = 0,
+                                )
+                            ),
+                            VibrationEffect.createWaveform(
+                                longArrayOf(50, 100, 100, 50),
+                                intArrayOf(5, 50, 20, 10),
+                                -1,
+                            ),
+                        )
+                    },
+                HapticToken.NEUTRAL_CONFIRMATION_MEDIUM_EMPHASIS to
+                    MSDLHapticData {
+                        HapticComposition(
+                            listOf(
+                                HapticCompositionPrimitive(
+                                    VibrationEffect.Composition.PRIMITIVE_CLICK,
+                                    scale = 1f,
+                                    delayMillis = 0,
+                                )
+                            ),
+                            VibrationEffect.createPredefined(VibrationEffect.EFFECT_CLICK),
+                        )
+                    },
+                HapticToken.LONG_PRESS to
+                    MSDLHapticData {
+                        HapticComposition(
+                            listOf(
+                                HapticCompositionPrimitive(
+                                    VibrationEffect.Composition.PRIMITIVE_CLICK,
+                                    scale = 1f,
+                                    delayMillis = 0,
+                                )
+                            ),
+                            VibrationEffect.createPredefined(VibrationEffect.EFFECT_CLICK),
+                        )
+                    },
+                HapticToken.SWIPE_THRESHOLD_INDICATOR to
+                    MSDLHapticData {
+                        HapticComposition(
+                            listOf(
+                                HapticCompositionPrimitive(
+                                    VibrationEffect.Composition.PRIMITIVE_CLICK,
+                                    scale = 0.7f,
+                                    delayMillis = 0,
+                                )
+                            ),
+                            VibrationEffect.createPredefined(VibrationEffect.EFFECT_CLICK),
+                        )
+                    },
+                HapticToken.TAP_HIGH_EMPHASIS to
+                    MSDLHapticData {
+                        HapticComposition(
+                            listOf(
+                                HapticCompositionPrimitive(
+                                    VibrationEffect.Composition.PRIMITIVE_CLICK,
+                                    scale = 0.7f,
+                                    delayMillis = 0,
+                                )
+                            ),
+                            VibrationEffect.createPredefined(VibrationEffect.EFFECT_CLICK),
+                        )
+                    },
+                HapticToken.TAP_MEDIUM_EMPHASIS to
+                    MSDLHapticData {
+                        HapticComposition(
+                            listOf(
+                                HapticCompositionPrimitive(
+                                    VibrationEffect.Composition.PRIMITIVE_CLICK,
+                                    scale = 0.5f,
+                                    delayMillis = 0,
+                                )
+                            ),
+                            VibrationEffect.createPredefined(VibrationEffect.EFFECT_CLICK),
+                        )
+                    },
+                HapticToken.DRAG_THRESHOLD_INDICATOR to
+                    MSDLHapticData {
+                        HapticComposition(
+                            listOf(
+                                HapticCompositionPrimitive(
+                                    VibrationEffect.Composition.PRIMITIVE_TICK,
+                                    scale = 1f,
+                                    delayMillis = 0,
+                                )
+                            ),
+                            VibrationEffect.createPredefined(VibrationEffect.EFFECT_TICK),
+                        )
+                    },
+                HapticToken.DRAG_INDICATOR to
+                    MSDLHapticData {
+                        HapticComposition(
+                            listOf(
+                                HapticCompositionPrimitive(
+                                    VibrationEffect.Composition.PRIMITIVE_TICK,
+                                    scale = 0.5f,
+                                    delayMillis = 0,
+                                )
+                            ),
+                            VibrationEffect.createPredefined(VibrationEffect.EFFECT_TICK),
+                        )
+                    },
+                HapticToken.TAP_LOW_EMPHASIS to
+                    MSDLHapticData {
+                        HapticComposition(
+                            listOf(
+                                HapticCompositionPrimitive(
+                                    VibrationEffect.Composition.PRIMITIVE_CLICK,
+                                    scale = 0.3f,
+                                    delayMillis = 0,
+                                )
+                            ),
+                            VibrationEffect.createPredefined(VibrationEffect.EFFECT_CLICK),
+                        )
+                    },
+                HapticToken.KEYPRESS_STANDARD to
+                    MSDLHapticData {
+                        HapticComposition(
+                            listOf(
+                                HapticCompositionPrimitive(
+                                    VibrationEffect.Composition.PRIMITIVE_TICK,
+                                    scale = 0.7f,
+                                    delayMillis = 0,
+                                )
+                            ),
+                            VibrationEffect.createPredefined(VibrationEffect.EFFECT_TICK),
+                        )
+                    },
+                HapticToken.KEYPRESS_SPACEBAR to
+                    MSDLHapticData {
+                        HapticComposition(
+                            listOf(
+                                HapticCompositionPrimitive(
+                                    VibrationEffect.Composition.PRIMITIVE_CLICK,
+                                    scale = 0.7f,
+                                    delayMillis = 0,
+                                )
+                            ),
+                            VibrationEffect.createPredefined(VibrationEffect.EFFECT_CLICK),
+                        )
+                    },
+                HapticToken.KEYPRESS_RETURN to
+                    MSDLHapticData {
+                        HapticComposition(
+                            listOf(
+                                HapticCompositionPrimitive(
+                                    VibrationEffect.Composition.PRIMITIVE_CLICK,
+                                    scale = 0.7f,
+                                    delayMillis = 0,
+                                )
+                            ),
+                            VibrationEffect.createPredefined(VibrationEffect.EFFECT_CLICK),
+                        )
+                    },
+                HapticToken.KEYPRESS_DELETE to
+                    MSDLHapticData {
+                        HapticComposition(
+                            listOf(
+                                HapticCompositionPrimitive(
+                                    VibrationEffect.Composition.PRIMITIVE_CLICK,
+                                    scale = 1f,
+                                    delayMillis = 0,
+                                )
+                            ),
+                            VibrationEffect.createPredefined(VibrationEffect.EFFECT_CLICK),
+                        )
+                    },
+            )
+    }
+}
diff --git a/msdllib/src/com/google/android/msdl/domain/InteractionProperties.kt b/msdllib/src/com/google/android/msdl/domain/InteractionProperties.kt
new file mode 100644
index 0000000..5dfeaa4
--- /dev/null
+++ b/msdllib/src/com/google/android/msdl/domain/InteractionProperties.kt
@@ -0,0 +1,53 @@
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
+package com.google.android.msdl.domain
+
+import android.os.VibrationAttributes
+import androidx.annotation.FloatRange
+
+/**
+ * Properties associated to an interaction that is currently occurring.
+ *
+ * The properties define parameters required to play the data associated with a
+ * [com.google.android.msdl.data.model.MSDLToken]. These can be dynamic, in the sense that they can
+ * be created as an interaction progresses throughout time.
+ *
+ * Each set of properties needs to define [VibrationAttributes] for a haptic effect to play with. If
+ * no properties are provided when playing a token, the effect will play with a default set of
+ * attributes with [VibrationAttributes.USAGE_TOUCH] usage.
+ */
+interface InteractionProperties {
+
+    /** [android.os.VibrationAttributes] for haptics in the interaction */
+    val vibrationAttributes: VibrationAttributes
+
+    /**
+     * Properties for a vibration that changes scale dynamically.
+     *
+     * The scale must be calculated at the time of calling the
+     * [com.google.android.msdl.domain.MSDLPlayer] API to play feedback. Use these properties for
+     * effects where vibration scales depend on temporal variables, such as position and velocity
+     * for slider haptics.
+     *
+     * @param[scale] The scale of the vibration at the time of calling. Must be between 0 and 1.
+     * @param[vibrationUsageId] Id used to create [android.os.VibrationAttributes]
+     */
+    data class DynamicVibrationScale(
+        @FloatRange(from = 0.0, to = 1.0) val scale: Float,
+        override val vibrationAttributes: VibrationAttributes,
+    ) : InteractionProperties
+}
diff --git a/msdllib/src/com/google/android/msdl/domain/MSDLPlayer.kt b/msdllib/src/com/google/android/msdl/domain/MSDLPlayer.kt
new file mode 100644
index 0000000..d976fb7
--- /dev/null
+++ b/msdllib/src/com/google/android/msdl/domain/MSDLPlayer.kt
@@ -0,0 +1,118 @@
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
+package com.google.android.msdl.domain
+
+import android.os.Vibrator
+import com.google.android.msdl.data.model.FeedbackLevel
+import com.google.android.msdl.data.model.HapticComposition
+import com.google.android.msdl.data.model.MSDLToken
+import com.google.android.msdl.data.repository.MSDLRepository
+import com.google.android.msdl.data.repository.MSDLRepositoryImpl
+import com.google.android.msdl.domain.MSDLPlayerImpl.Companion.REQUIRED_PRIMITIVES
+import com.google.android.msdl.logging.MSDLEvent
+import java.util.concurrent.Executor
+import java.util.concurrent.Executors
+
+/**
+ * Player of MSDL feedback.
+ *
+ * This player is central API to deliver audio and haptic feedback bundled and referenced by
+ * instances of [MSDLToken].
+ */
+interface MSDLPlayer {
+
+    // Current feedback level set in the system
+    fun getSystemFeedbackLevel(): FeedbackLevel
+
+    /**
+     * Play a [MSDLToken].
+     *
+     * @param[token] The [MSDLToken] to play. This will be used to fetch its corresponding haptic
+     *   and sound data.
+     * @param[properties] [InteractionProperties] associated with the token requested to play. These
+     *   properties can modify how a token plays (e.g.,
+     *   [InteractionProperties.DynamicVibrationScale] for slider haptics in the
+     *   [MSDLToken.DRAG_INDICATOR] token) and can be supplied if custom
+     *   [android.os.VibrationAttributes] are required for haptic playback. If no properties are
+     *   supplied, haptic feedback will play using USAGE_TOUCH [android.os.VibrationAttributes].
+     */
+    fun playToken(token: MSDLToken, properties: InteractionProperties? = null)
+
+    /**
+     * Get the history of recent [MSDLEvent]s. The list can be useful to include in loggers and
+     * system dumps for debugging purposes.
+     */
+    fun getHistory(): List<MSDLEvent>
+
+    companion object {
+
+        // TODO(b/355230334): remove once we have a system setting for the level
+        var SYSTEM_FEEDBACK_LEVEL = FeedbackLevel.DEFAULT
+
+        /**
+         * Create a new [MSDLPlayer].
+         *
+         * @param[vibrator] The [Vibrator] this player will use for haptic playback.
+         * @param[executor] An [Executor] to schedule haptic playback.
+         * @param[useHapticFeedbackForToken] A map that determines if a haptic fallback effect
+         *   should be used to play haptics for a given [MSDLToken]. If null, the map will be
+         *   created using the support information from the given vibrator.
+         */
+        fun createPlayer(
+            vibrator: Vibrator,
+            executor: Executor = Executors.newSingleThreadExecutor(),
+            useHapticFeedbackForToken: Map<MSDLToken, Boolean>? = null,
+        ): MSDLPlayer {
+
+            // Create repository
+            val repository = MSDLRepositoryImpl()
+
+            // Determine the support for haptic primitives to know if fallbacks will be used.
+            // This can be provided by the client. If omitted, it will be determined from the
+            // supported primitives of the given vibrator.
+            val shouldUseFallbackForToken =
+                useHapticFeedbackForToken ?: createHapticFallbackDecisionMap(vibrator, repository)
+
+            return MSDLPlayerImpl(repository, vibrator, executor, shouldUseFallbackForToken)
+        }
+
+        private fun createHapticFallbackDecisionMap(
+            vibrator: Vibrator,
+            repository: MSDLRepository,
+        ): Map<MSDLToken, Boolean> {
+            val supportedPrimitives =
+                REQUIRED_PRIMITIVES.associateWith { vibrator.arePrimitivesSupported(it).first() }
+            return MSDLToken.entries.associateWith { token ->
+                // For each token, determine if the haptic data from the repository
+                // should use the fallback effect.
+                val hapticComposition =
+                    repository.getHapticData(token.hapticToken)?.get() as? HapticComposition
+                hapticComposition?.shouldPlayFallback(supportedPrimitives) ?: false
+            }
+        }
+    }
+}
+
+fun HapticComposition.shouldPlayFallback(supportedPrimitives: Map<Int, Boolean>): Boolean {
+    primitives.forEach { primitive ->
+        val isSupported = supportedPrimitives[primitive.primitiveId]
+        if (isSupported == null || isSupported == false) {
+            return true
+        }
+    }
+    return false
+}
diff --git a/msdllib/src/com/google/android/msdl/domain/MSDLPlayerImpl.kt b/msdllib/src/com/google/android/msdl/domain/MSDLPlayerImpl.kt
new file mode 100644
index 0000000..b103083
--- /dev/null
+++ b/msdllib/src/com/google/android/msdl/domain/MSDLPlayerImpl.kt
@@ -0,0 +1,133 @@
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
+package com.google.android.msdl.domain
+
+import android.os.VibrationAttributes
+import android.os.VibrationEffect
+import android.os.Vibrator
+import com.google.android.msdl.data.model.FeedbackLevel
+import com.google.android.msdl.data.model.HapticComposition
+import com.google.android.msdl.data.model.MSDLToken
+import com.google.android.msdl.data.repository.MSDLRepository
+import com.google.android.msdl.logging.MSDLEvent
+import com.google.android.msdl.logging.MSDLHistoryLogger
+import com.google.android.msdl.logging.MSDLHistoryLoggerImpl
+import java.util.concurrent.Executor
+
+/**
+ * Implementation of the MSDLPlayer.
+ *
+ * At the core, the player is in charge of delivering haptic and audio feedback closely in time.
+ *
+ * @param[repository] Repository to retrieve audio and haptic data.
+ * @param[executor] An [Executor] used to schedule haptic playback.
+ * @param[vibrator] Instance of the default [Vibrator] on the device.
+ * @param[useHapticFallbackForToken] A map that determines if the haptic fallback effect should be
+ *   used for a given token.
+ */
+internal class MSDLPlayerImpl(
+    private val repository: MSDLRepository,
+    private val vibrator: Vibrator,
+    private val executor: Executor,
+    private val useHapticFallbackForToken: Map<MSDLToken, Boolean?>,
+) : MSDLPlayer {
+
+    /** A logger to keep a history of playback events */
+    private val historyLogger = MSDLHistoryLoggerImpl(MSDLHistoryLogger.HISTORY_SIZE)
+
+    // TODO(b/355230334): This should be retrieved from the system Settings
+    override fun getSystemFeedbackLevel(): FeedbackLevel = MSDLPlayer.SYSTEM_FEEDBACK_LEVEL
+
+    override fun playToken(token: MSDLToken, properties: InteractionProperties?) {
+        // Don't play the data for the token if the current feedback level is below the minimal
+        // level of the token
+        if (getSystemFeedbackLevel() < token.minimumFeedbackLevel) return
+
+        // Play the data for the token with the given properties
+        playData(token, properties)
+    }
+
+    private fun playData(token: MSDLToken, properties: InteractionProperties?) {
+        // Gather the data from the repositories
+        val hapticData = repository.getHapticData(token.hapticToken)
+        val soundData = repository.getAudioData(token.soundToken)
+
+        // Nothing to play
+        if (hapticData == null && soundData == null) return
+
+        if (soundData == null) {
+            // Play haptics only
+            // 1. Create the effect
+            val composition: HapticComposition? = hapticData?.get() as? HapticComposition
+            val effect =
+                if (useHapticFallbackForToken[token] == true) {
+                    composition?.fallbackEffect
+                } else {
+                    when (properties) {
+                        is InteractionProperties.DynamicVibrationScale -> {
+                            composition?.composeIntoVibrationEffect(
+                                scaleOverride = properties.scale
+                            )
+                        }
+                        else -> composition?.composeIntoVibrationEffect() // compose as-is
+                    }
+                }
+
+            // 2. Deliver the haptics with attributes
+            if (effect == null || !vibrator.hasVibrator()) return
+            val attributes =
+                if (properties?.vibrationAttributes != null) {
+                    properties.vibrationAttributes
+                } else {
+                    VibrationAttributes.Builder().setUsage(VibrationAttributes.USAGE_TOUCH).build()
+                }
+            executor.execute { vibrator.vibrate(effect, attributes) }
+
+            // 3. Log the event
+            historyLogger.addEvent(MSDLEvent(token, properties))
+        } else {
+            // TODO(b/345248875): Play audio and haptics
+        }
+    }
+
+    override fun getHistory(): List<MSDLEvent> = historyLogger.getHistory()
+
+    companion object {
+        val REQUIRED_PRIMITIVES =
+            listOf(
+                VibrationEffect.Composition.PRIMITIVE_SPIN,
+                VibrationEffect.Composition.PRIMITIVE_THUD,
+                VibrationEffect.Composition.PRIMITIVE_TICK,
+                VibrationEffect.Composition.PRIMITIVE_CLICK,
+            )
+    }
+}
+
+fun HapticComposition.composeIntoVibrationEffect(
+    scaleOverride: Float? = null,
+    delayOverride: Int? = null,
+): VibrationEffect? {
+    val effectComposition = VibrationEffect.startComposition()
+    primitives.forEach { primitive ->
+        effectComposition.addPrimitive(
+            primitive.primitiveId,
+            scaleOverride ?: primitive.scale,
+            delayOverride ?: primitive.delayMillis,
+        )
+    }
+    return effectComposition.compose()
+}
diff --git a/msdllib/src/com/google/android/msdl/logging/MSDLEvent.kt b/msdllib/src/com/google/android/msdl/logging/MSDLEvent.kt
new file mode 100644
index 0000000..a81b6a7
--- /dev/null
+++ b/msdllib/src/com/google/android/msdl/logging/MSDLEvent.kt
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
+package com.google.android.msdl.logging
+
+import com.google.android.msdl.data.model.MSDLToken
+import com.google.android.msdl.domain.InteractionProperties
+
+/**
+ * A summary that represents a MSDL event. The event summarizes the delivery of playback from a
+ * [MSDLToken] along with optional [InteractionProperties].
+ *
+ * @param[tokenName] The name of the [MSDLToken] played.
+ * @param[properties] The text representation of [InteractionProperties] used to play the token.
+ * @param[timeStamp] A formatted time stamp for when the event occurred. The format for this time
+ *   stamp is [MSDLHistoryLogger.DATE_FORMAT]
+ */
+data class MSDLEvent(val tokenName: String, val properties: String?, val timeStamp: String) {
+    constructor(
+        token: MSDLToken,
+        properties: InteractionProperties?,
+    ) : this(
+        token.name,
+        properties?.toString(),
+        MSDLHistoryLogger.DATE_FORMAT.format(System.currentTimeMillis()),
+    )
+}
diff --git a/msdllib/src/com/google/android/msdl/logging/MSDLHistoryLogger.kt b/msdllib/src/com/google/android/msdl/logging/MSDLHistoryLogger.kt
new file mode 100644
index 0000000..6e255af
--- /dev/null
+++ b/msdllib/src/com/google/android/msdl/logging/MSDLHistoryLogger.kt
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
+package com.google.android.msdl.logging
+
+import java.text.SimpleDateFormat
+import java.util.Locale
+
+/** A logging component to keep track of recent [MSDLEvent]s */
+interface MSDLHistoryLogger {
+
+    /**
+     * Add an event to the history.
+     *
+     * @param[event] The event to log.
+     */
+    fun addEvent(event: MSDLEvent)
+
+    /** Get the history of latest events. */
+    fun getHistory(): List<MSDLEvent>
+
+    companion object {
+
+        const val HISTORY_SIZE = 20
+        val DATE_FORMAT = SimpleDateFormat("MM-dd HH:mm:ss.SSS", Locale.US)
+    }
+}
diff --git a/msdllib/src/com/google/android/msdl/logging/MSDLHistoryLoggerImpl.kt b/msdllib/src/com/google/android/msdl/logging/MSDLHistoryLoggerImpl.kt
new file mode 100644
index 0000000..bc8a810
--- /dev/null
+++ b/msdllib/src/com/google/android/msdl/logging/MSDLHistoryLoggerImpl.kt
@@ -0,0 +1,39 @@
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
+package com.google.android.msdl.logging
+
+import androidx.annotation.VisibleForTesting
+import androidx.annotation.VisibleForTesting.Companion.PACKAGE_PRIVATE
+import java.util.ArrayDeque
+import java.util.Deque
+
+@VisibleForTesting(otherwise = PACKAGE_PRIVATE)
+class MSDLHistoryLoggerImpl(private val maxHistorySize: Int) : MSDLHistoryLogger {
+
+    // Use an [ArrayDequeue] with a fixed size as the history structure
+    private val history: Deque<MSDLEvent> = ArrayDeque(maxHistorySize)
+
+    override fun addEvent(event: MSDLEvent) {
+        // Keep the history as a FIFO structure
+        if (history.size == maxHistorySize) {
+            history.removeFirst()
+        }
+        history.addLast(event)
+    }
+
+    override fun getHistory(): List<MSDLEvent> = history.toList()
+}
diff --git a/msdllib/tests/AndroidManifest.xml b/msdllib/tests/AndroidManifest.xml
new file mode 100644
index 0000000..0283081
--- /dev/null
+++ b/msdllib/tests/AndroidManifest.xml
@@ -0,0 +1,26 @@
+<?xml version="1.0" encoding="utf-8"?><!--
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
+    package="com.google.android.msdl.tests">
+
+    <instrumentation
+        android:name="android.testing.TestableInstrumentation"
+        android:label="Tests for the public MSDL Lib"
+        android:targetPackage="com.google.android.msdl.tests"/>
+
+</manifest>
+
diff --git a/msdllib/tests/src/com/google/android/msdl/data/repository/MSDLRepositoryImplTest.kt b/msdllib/tests/src/com/google/android/msdl/data/repository/MSDLRepositoryImplTest.kt
new file mode 100644
index 0000000..576e749
--- /dev/null
+++ b/msdllib/tests/src/com/google/android/msdl/data/repository/MSDLRepositoryImplTest.kt
@@ -0,0 +1,41 @@
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
+package com.google.android.msdl.data.repository
+
+import com.google.android.msdl.data.model.HapticComposition
+import com.google.android.msdl.data.model.HapticToken
+import com.google.common.truth.Truth.assertThat
+import org.junit.Test
+import org.junit.runner.RunWith
+import org.junit.runners.JUnit4
+
+@RunWith(JUnit4::class)
+class MSDLRepositoryImplTest {
+
+    private val repository = MSDLRepository.createRepository()
+
+    @Test
+    fun getHapticData_forAllHapticTokens_returnsCompositions() {
+        var validCompositions = 0
+        HapticToken.entries.forEach { token ->
+            if (repository.getHapticData(token)?.get() is HapticComposition) {
+                validCompositions++
+            }
+        }
+        assertThat(validCompositions).isEqualTo(HapticToken.entries.size)
+    }
+}
diff --git a/msdllib/tests/src/com/google/android/msdl/domain/FakeVibrator.kt b/msdllib/tests/src/com/google/android/msdl/domain/FakeVibrator.kt
new file mode 100644
index 0000000..e15a6ee
--- /dev/null
+++ b/msdllib/tests/src/com/google/android/msdl/domain/FakeVibrator.kt
@@ -0,0 +1,76 @@
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
+package com.google.android.msdl.domain
+
+import android.os.VibrationAttributes
+import android.os.VibrationEffect
+import android.os.Vibrator
+
+class FakeVibrator : Vibrator() {
+    var hasAmplitudeControl = true
+    var hasVibrator = true
+    var latestVibration: VibrationEffect? = null
+        private set
+
+    val supportedPrimitives =
+        mutableMapOf(
+            VibrationEffect.Composition.PRIMITIVE_CLICK to true,
+            VibrationEffect.Composition.PRIMITIVE_SPIN to true,
+            VibrationEffect.Composition.PRIMITIVE_THUD to true,
+            VibrationEffect.Composition.PRIMITIVE_TICK to true,
+            VibrationEffect.Composition.PRIMITIVE_LOW_TICK to true,
+            VibrationEffect.Composition.PRIMITIVE_QUICK_FALL to true,
+            VibrationEffect.Composition.PRIMITIVE_QUICK_RISE to true,
+            VibrationEffect.Composition.PRIMITIVE_SLOW_RISE to true,
+        )
+
+    var latestAttributes: VibrationAttributes? = null
+        private set
+
+    fun setSupportForAllPrimitives(supported: Boolean) =
+        supportedPrimitives.replaceAll { _, _ -> supported }
+
+    override fun cancel() {}
+
+    override fun cancel(usageFilter: Int) {}
+
+    override fun hasAmplitudeControl(): Boolean = this.hasAmplitudeControl
+
+    override fun hasVibrator(): Boolean = this.hasVibrator
+
+    override fun arePrimitivesSupported(vararg primitiveIds: Int): BooleanArray =
+        primitiveIds.map { id -> supportedPrimitives[id] ?: false }.toBooleanArray()
+
+    override fun vibrate(
+        uid: Int,
+        opPkg: String,
+        vibe: VibrationEffect,
+        reason: String,
+        attributes: VibrationAttributes,
+    ) {
+        latestVibration = vibe
+        latestAttributes = attributes
+    }
+
+    override fun vibrate(
+        vibe: VibrationEffect,
+        attributes: VibrationAttributes,
+    ) {
+        latestVibration = vibe
+        latestAttributes = attributes
+    }
+}
diff --git a/msdllib/tests/src/com/google/android/msdl/domain/MSDLPlayerImplTest.kt b/msdllib/tests/src/com/google/android/msdl/domain/MSDLPlayerImplTest.kt
new file mode 100644
index 0000000..1b929ab
--- /dev/null
+++ b/msdllib/tests/src/com/google/android/msdl/domain/MSDLPlayerImplTest.kt
@@ -0,0 +1,154 @@
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
+package com.google.android.msdl.domain
+
+import android.os.VibrationAttributes
+import android.os.VibrationEffect
+import com.google.android.msdl.data.model.FeedbackLevel
+import com.google.android.msdl.data.model.HapticComposition
+import com.google.android.msdl.data.model.MSDLToken
+import com.google.android.msdl.data.repository.MSDLRepository
+import com.google.common.truth.Truth.assertThat
+import java.util.concurrent.Executor
+import org.junit.Before
+import org.junit.Test
+import org.junit.runner.RunWith
+import org.junit.runners.Parameterized
+
+@RunWith(Parameterized::class)
+class MSDLPlayerImplTest {
+
+    @Parameterized.Parameter lateinit var token: MSDLToken
+
+    private val repository = MSDLRepository.createRepository()
+    private val vibrator = FakeVibrator()
+    private val executor = Executor { it.run() }
+    private val useHapticFallbackForToken = MSDLToken.entries.associateWith { false }.toMutableMap()
+
+    private var msdlPlayer = MSDLPlayer.createPlayer(vibrator, executor, useHapticFallbackForToken)
+
+    @Before
+    fun setup() {
+        MSDLPlayer.SYSTEM_FEEDBACK_LEVEL = FeedbackLevel.EXPRESSIVE
+        vibrator.setSupportForAllPrimitives(true)
+    }
+
+    @Test
+    fun playToken_withExpressiveSetting_deliversAllFeedback() {
+        // GIVEN that the feedback level is expressive (all tokens play)
+        MSDLPlayer.SYSTEM_FEEDBACK_LEVEL = FeedbackLevel.EXPRESSIVE
+        val composition = repository.getHapticData(token.hapticToken)?.get() as? HapticComposition
+        val effect = composition?.composeIntoVibrationEffect()
+
+        // WHEN the token plays
+        msdlPlayer.playToken(token)
+
+        // THEN the vibration is delivered
+        assertThat(vibrator.latestVibration).isEqualTo(effect)
+    }
+
+    @Test
+    fun playToken_withoutFeedbackSetting_doesNotDeliverAnyFeedback() {
+        // GIVEN that the feedback level specifies no feedback
+        MSDLPlayer.SYSTEM_FEEDBACK_LEVEL = FeedbackLevel.NO_FEEDBACK
+
+        // WHEN the token plays
+        msdlPlayer.playToken(token)
+
+        // THEN no vibration is delivered
+        assertThat(vibrator.latestVibration).isNull()
+    }
+
+    @Test
+    fun playHapticComposition_withNullProperties_playsExpectedVibrationEffect() {
+        // GIVEN the vibration effect of a composition
+        val composition = repository.getHapticData(token.hapticToken)?.get() as? HapticComposition
+        val effect = composition?.composeIntoVibrationEffect()
+
+        // WHEN the composition is played for a token without interaction properties
+        msdlPlayer.playToken(token)
+
+        // THEN the vibration delivers the same vibration effect with USAGE_TOUCH vibration
+        // attributes and the correct token reason.
+        val touchAttributes =
+            VibrationAttributes.Builder().setUsage(VibrationAttributes.USAGE_TOUCH).build()
+        assertVibrationEffectDelivered(effect, touchAttributes)
+    }
+
+    @Test
+    fun playHapticComposition_withoutSupportedPrimitives_playsFallbackEffects() {
+        // GIVEN that no primitives are supported
+        useHapticFallbackForToken.replaceAll { _, _ -> true }
+
+        // GIVEN the fallback effect of a composition
+        val composition = repository.getHapticData(token.hapticToken)?.get() as? HapticComposition
+        val effect = composition?.fallbackEffect
+
+        // WHEN the composition is played for a token without interaction properties
+        msdlPlayer.playToken(token)
+
+        // THEN the vibration delivers the same fallback effect with USAGE_TOUCH vibration
+        val touchAttributes =
+            VibrationAttributes.Builder().setUsage(VibrationAttributes.USAGE_TOUCH).build()
+        assertVibrationEffectDelivered(effect, touchAttributes)
+    }
+
+    @Test
+    fun playHapticComposition_withDynamicVibrationScaleProperties_playsExpectedVibrationEffect() {
+        // GIVEN  DynamicVibrationScaleProperties and a vibration effect built with this scale
+        val scaleOverride = 0.4f
+        val composition = repository.getHapticData(token.hapticToken)?.get() as? HapticComposition
+        val effect = composition?.composeIntoVibrationEffect(scaleOverride)
+        val attributes =
+            VibrationAttributes.Builder().setUsage(VibrationAttributes.USAGE_ALARM).build()
+        val properties = InteractionProperties.DynamicVibrationScale(scaleOverride, attributes)
+
+        // WHEN the composition is played for the token with the properties
+        msdlPlayer.playToken(token, properties)
+
+        // THEN the vibration effect delivered is the same vibration effect with the properties
+        assertVibrationEffectDelivered(effect, attributes)
+    }
+
+    @Test
+    fun playHapticComposition_withoutHardwareVibrator_doesNotPlayVibrationEffect() {
+        // GIVEN the vibration effect of a composition when there is no hardware vibrator
+        vibrator.hasVibrator = false
+
+        // WHEN the composition is played for a token
+        msdlPlayer.playToken(token)
+
+        // THEN the vibration does not deliver any effect
+        assertThat(vibrator.latestVibration).isNull()
+    }
+
+    private fun assertVibrationEffectDelivered(
+        effect: VibrationEffect?,
+        attributes: VibrationAttributes,
+    ) {
+        assertThat(vibrator.latestVibration).isEqualTo(effect)
+        if (effect != null) {
+            assertThat(vibrator.latestAttributes).isEqualTo(attributes)
+        } else {
+            assertThat(vibrator.latestAttributes).isNull()
+        }
+    }
+
+    companion object {
+        @JvmStatic @Parameterized.Parameters fun tokens() = MSDLToken.entries
+    }
+}
diff --git a/msdllib/tests/src/com/google/android/msdl/logging/MSDLHistoryLoggerImplTest.kt b/msdllib/tests/src/com/google/android/msdl/logging/MSDLHistoryLoggerImplTest.kt
new file mode 100644
index 0000000..f2da3df
--- /dev/null
+++ b/msdllib/tests/src/com/google/android/msdl/logging/MSDLHistoryLoggerImplTest.kt
@@ -0,0 +1,108 @@
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
+package com.google.android.msdl.logging
+
+import android.os.VibrationAttributes
+import com.google.android.msdl.data.model.MSDLToken
+import com.google.android.msdl.domain.InteractionProperties
+import com.google.common.truth.Truth.assertThat
+import kotlin.random.Random
+import org.junit.Test
+import org.junit.runner.RunWith
+import org.junit.runners.JUnit4
+
+@RunWith(JUnit4::class)
+class MSDLHistoryLoggerImplTest {
+
+    private val properties =
+        object : InteractionProperties {
+            override val vibrationAttributes: VibrationAttributes =
+                VibrationAttributes.createForUsage(VibrationAttributes.USAGE_HARDWARE_FEEDBACK)
+        }
+    private val random = Random(0)
+
+    private val logger = MSDLHistoryLoggerImpl(MSDLHistoryLogger.HISTORY_SIZE)
+
+    @Test
+    fun addEvent_eventIsAddedToHistory() {
+        val token = getRandomToken()
+        val event = MSDLEvent(token, properties)
+        logger.addEvent(event)
+
+        assertThat(logger.getHistory().containsEvent(event)).isTrue()
+    }
+
+    @Test
+    fun addEvent_beyondLimit_keepsHistorySize() {
+        val tokens = getRandomTokens(MSDLHistoryLogger.HISTORY_SIZE + 10)
+        tokens.forEach { logger.addEvent(MSDLEvent(it, properties)) }
+
+        assertThat(logger.getHistory().size).isEqualTo(MSDLHistoryLogger.HISTORY_SIZE)
+    }
+
+    @Test
+    fun addEvent_beyondLimit_keepsLatestEvents() {
+        val localHistory = arrayListOf<MSDLEvent>()
+        val tokens = getRandomTokens(MSDLHistoryLogger.HISTORY_SIZE + 10)
+        var event: MSDLEvent
+        tokens.forEach {
+            event = MSDLEvent(it, properties)
+            logger.addEvent(event)
+            localHistory.add(event)
+        }
+
+        val latestLocalHistory = localHistory.takeLast(MSDLHistoryLogger.HISTORY_SIZE)
+        val loggerHistory = logger.getHistory()
+        assertThat(latestLocalHistory.isEqualTo(loggerHistory)).isTrue()
+    }
+
+    private fun getRandomToken(): MSDLToken =
+        MSDLToken.entries[random.nextInt(0, MSDLToken.entries.size)]
+
+    private fun getRandomTokens(n: Int): List<MSDLToken> = List(n) { getRandomToken() }
+
+    /**
+     * Check if the list is equal to another by making sure it has the same elements in the same
+     * order. Events are compared by their token name and interaction properties.
+     *
+     * @param[other] The other list to compare to.
+     */
+    private fun List<MSDLEvent>.isEqualTo(other: List<MSDLEvent>): Boolean {
+        assert(other.size == this.size) { "Both lists must be of the same size" }
+        this.forEachIndexed { i, event ->
+            if (event.tokenName != other[i].tokenName || event.properties != other[i].properties) {
+                return false
+            }
+        }
+        return true
+    }
+
+    /**
+     * Check if the list contains an event. Events are compared by their token name and interaction
+     * properties.
+     *
+     * @param[other] The event to find.
+     */
+    private fun List<MSDLEvent>.containsEvent(other: MSDLEvent): Boolean {
+        this.forEach { event ->
+            if (event.tokenName == other.tokenName && event.properties == other.properties) {
+                return true
+            }
+        }
+        return false
+    }
+}
diff --git a/toruslib/Android.bp b/toruslib/Android.bp
index e42f205..01dab66 100644
--- a/toruslib/Android.bp
+++ b/toruslib/Android.bp
@@ -47,7 +47,5 @@ android_library {
     optimize: {
         enabled: true,
     },
-    min_sdk_version: "31",
-    sdk_version: "system_current",
+    platform_apis: true,
 }
-
diff --git a/toruslib/torus-core/src/main/java/com/google/android/torus/core/wallpaper/LiveWallpaper.kt b/toruslib/torus-core/src/main/java/com/google/android/torus/core/wallpaper/LiveWallpaper.kt
index 4eb0603..4ebc8f4 100644
--- a/toruslib/torus-core/src/main/java/com/google/android/torus/core/wallpaper/LiveWallpaper.kt
+++ b/toruslib/torus-core/src/main/java/com/google/android/torus/core/wallpaper/LiveWallpaper.kt
@@ -409,7 +409,7 @@ abstract class LiveWallpaper : WallpaperService() {
         /**
          * This is overriding a hidden API [WallpaperService.shouldZoomOutWallpaper].
          */
-        fun shouldZoomOutWallpaper(): Boolean {
+        override fun shouldZoomOutWallpaper(): Boolean {
             if (wallpaperEngine is LiveWallpaperEventListener) {
                 return (wallpaperEngine as LiveWallpaperEventListener).shouldZoomOutWallpaper()
             }
diff --git a/tracinglib/Android.bp b/tracinglib/Android.bp
new file mode 100644
index 0000000..07f90cc
--- /dev/null
+++ b/tracinglib/Android.bp
@@ -0,0 +1,19 @@
+//
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
+//
+
+package {
+    default_team: "trendy_team_performance",
+}
diff --git a/tracinglib/README.md b/tracinglib/README.md
new file mode 100644
index 0000000..61f938e
--- /dev/null
+++ b/tracinglib/README.md
@@ -0,0 +1,112 @@
+# Coroutine Tracing
+
+This library contains utilities for tracing coroutines. Coroutines cannot normally be traced using
+the `android.os.Trace` APIs because it will often lead to malformed trace sections. This is because
+each `Trace.beginSection` must have a matching `Trace.endSection` on the same thread before the
+scope is finished, so if they are used around a suspend point, the trace section will remain open
+while other unrelated work executes. It could even remain open indefinitely if the coroutine is
+canceled.
+
+To address this, we introduce a function `traceCoroutine("name") {}` that can be used for tracing
+sections of coroutine code. When invoked, a trace section with the given name will start
+immediately, and its name will also be written to an object in the current `CoroutineContext` used
+for coroutine-local storage. When the coroutine suspends, all trace sections will end immediately.
+When resumed, the coroutine will read the names of the previous sections from coroutine-local
+storage, and it will begin the sections again.
+
+For example, the following coroutine code will be traced as follows:
+
+```
+traceCoroutine("Slice A") {
+  println("Start")
+  delay(10)
+  println("End")
+}
+```
+
+```
+Thread #1 |  [==== Slice ====]          [==== Slice ====]
+               ^ "Start" printed          ^ "End" printed
+```
+
+If multiple threads are used, it would be as follows:
+
+```
+traceCoroutine("Slice") {
+  println("Start")
+  delay(10)
+  withContext(backgroundThread) {
+    println("End")
+  }
+}
+```
+
+```
+Thread #1 |  [==== Slice ====]
+          |    ^ "Start" printed
+----------+---------------------------------------------------------
+Thread #2 |                              [==== Slice ====]
+                                           ^ "End" printed
+```
+
+This library also provides wrappers for some of the coroutine functions provided in the
+`kotlinx.coroutines.*` package.  For example, instead of:
+`launch { traceCoroutine("my-launch") { /* block */ } }`, you can instead write:
+`launch("my-launch") { /* block */ }`.
+
+It also provides a wrapper for tracing Flow emissions. For example,
+
+```
+val coldFlow = flow {
+  emit(1)
+  emit(2)
+  emit(3)
+}.withTraceName("my-flow")
+
+coldFlow.collect {
+  println(it)
+  delay(10)
+}
+```
+
+Would be traced as follows:
+
+```
+Thread #1 |  [=== my-flow:collect ===]    [=== my-flow:collect ===]    [=== my-flow:collect ===]
+          |    [== my-flow:emit ==]         [== my-flow:emit ==]         [== my-flow:emit ==]
+```
+
+# Building and Running
+
+## Host Tests
+
+Host tests are implemented in `tracinglib-host-test`. To run the host tests:
+
+```
+atest tracinglib-host-test
+```
+
+## Feature Flag
+
+Coroutine tracing is flagged off by default. To enable coroutine tracing on a device, flip the flag
+and restart the user-space system:
+
+```
+adb shell device_config override systemui com.android.systemui.coroutine_tracing true
+adb shell am restart
+```
+
+## Demo App
+
+Build and install the app using Soong and adevice:
+
+```
+adevice track CoroutineTracingDemoApp
+m CoroutineTracingDemoApp
+adevice update
+```
+
+Then, open the app and tap an experiment to run it. The experiments run in the background. To see
+the effects of what coroutine tracing is doing, you will need to capture a Perfetto trace. The
+[`coroutine_tracing` flag](#feature-flag) will need to be enabled for coroutine trace sections to
+work.
diff --git a/tracinglib/benchmark/Android.bp b/tracinglib/benchmark/Android.bp
new file mode 100644
index 0000000..965b622
--- /dev/null
+++ b/tracinglib/benchmark/Android.bp
@@ -0,0 +1,48 @@
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
+    default_team: "trendy_team_performance",
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+android_test {
+    name: "tracinglib-benchmark",
+
+    srcs: ["src/**/*.kt"],
+
+    static_libs: [
+        "androidx.annotation_annotation",
+        "androidx.benchmark_benchmark-common",
+        "androidx.benchmark_benchmark-junit4",
+        "androidx.test.core",
+        "androidx.test.ext.junit",
+        "androidx.test.rules",
+        "androidx.test.runner",
+        "apct-perftests-utils",
+        "collector-device-lib",
+        "flag-junit",
+        "kotlinx_coroutines_android",
+        "platform-test-rules",
+        "tracinglib-platform",
+    ],
+
+    data: [":perfetto_artifacts"],
+
+    sdk_version: "current",
+    certificate: "platform",
+    use_resource_processor: true,
+
+    test_suites: ["device-tests"],
+}
diff --git a/tracinglib/benchmark/AndroidManifest.xml b/tracinglib/benchmark/AndroidManifest.xml
new file mode 100644
index 0000000..4460e31
--- /dev/null
+++ b/tracinglib/benchmark/AndroidManifest.xml
@@ -0,0 +1,26 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!-- Copyright (C) 2024 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+-->
+
+<manifest xmlns:android="http://schemas.android.com/apk/res/android"
+    package="com.android.app.tracing.benchmark" >
+
+    <application/>
+
+    <instrumentation android:name="androidx.benchmark.junit4.AndroidBenchmarkRunner"
+                     android:targetPackage="com.android.app.tracing.benchmark"
+                     android:label="Benchmark tests for tracinglib"/>
+
+</manifest>
diff --git a/tracinglib/benchmark/AndroidTest.xml b/tracinglib/benchmark/AndroidTest.xml
new file mode 100644
index 0000000..e68e883
--- /dev/null
+++ b/tracinglib/benchmark/AndroidTest.xml
@@ -0,0 +1,61 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!-- Copyright (C) 2024 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+-->
+<configuration description="Runs tracinglib-benchmark metric instrumentation.">
+    <target_preparer class="com.android.tradefed.targetprep.RootTargetPreparer"/>
+    <!-- Needed for pushing the trace config file -->
+    <target_preparer class="com.android.tradefed.targetprep.PushFilePreparer">
+        <option name="push-file" key="trace_config_detailed.textproto" value="/data/misc/perfetto-traces/trace_config.textproto" />
+    </target_preparer>
+
+    <target_preparer class="com.android.tradefed.targetprep.TestFilePushSetup" />
+    <target_preparer class="com.android.tradefed.targetprep.RunCommandTargetPreparer" />
+
+    <target_preparer class="com.android.tradefed.targetprep.suite.SuiteApkInstaller">
+        <option name="cleanup-apks" value="true" />
+        <option name="test-file-name" value="tracinglib-benchmark.apk" />
+    </target_preparer>
+
+    <target_preparer class="com.android.tradefed.targetprep.RunCommandTargetPreparer">
+        <option name="run-command" value="input keyevent KEYCODE_WAKEUP" />
+    </target_preparer>
+
+    <!-- Needed for pulling the collected trace config on to the host -->
+    <metrics_collector class="com.android.tradefed.device.metric.FilePullerLogCollector">
+        <option name="pull-pattern-keys" value="perfetto_file_path" />
+    </metrics_collector>
+
+    <!-- Needed for storing the perfetto trace files in the sdcard/test_results -->
+    <option name="isolated-storage" value="false" />
+
+    <test class="com.android.tradefed.testtype.AndroidJUnitTest" >
+        <option name="package" value="com.android.app.tracing.benchmark" />
+        <!-- <option name="runner" value="androidx.test.runner.AndroidJUnitRunner" /> -->
+
+        <option name="device-listeners" value="android.device.collectors.ProcLoadListener,android.device.collectors.PerfettoListener" />
+        <!-- ProcLoadListener related arguments -->
+        <!-- Wait for device last minute threshold to reach 3 with 2 minute timeout before starting the test run -->
+        <option name="instrumentation-arg" key="procload-collector:per_run" value="true" />
+        <option name="instrumentation-arg" key="proc-loadavg-threshold" value="3" />
+        <option name="instrumentation-arg" key="proc-loadavg-timeout" value="120000" />
+        <option name="instrumentation-arg" key="proc-loadavg-interval" value="10000" />
+
+        <!-- PerfettoListener related arguments -->
+        <option name="instrumentation-arg" key="perfetto_config_text_proto" value="true" />
+        <option name="instrumentation-arg" key="perfetto_config_file" value="trace_config.textproto" />
+
+        <option name="instrumentation-arg" key="newRunListenerMode" value="true" />
+    </test>
+</configuration>
diff --git a/tracinglib/benchmark/src/TraceContextMicroBenchmark.kt b/tracinglib/benchmark/src/TraceContextMicroBenchmark.kt
new file mode 100644
index 0000000..5f25bf6
--- /dev/null
+++ b/tracinglib/benchmark/src/TraceContextMicroBenchmark.kt
@@ -0,0 +1,142 @@
+/*
+ * Copyright (C) 2016 The Android Open Source Project
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
+package com.android.app.tracing.benchmark
+
+import android.os.Trace
+import android.perftests.utils.BenchmarkState
+import android.perftests.utils.PerfStatusReporter
+import android.platform.test.annotations.EnableFlags
+import android.platform.test.flag.junit.SetFlagsRule
+import android.platform.test.rule.EnsureDeviceSettingsRule
+import androidx.test.ext.junit.runners.AndroidJUnit4
+import androidx.test.filters.SmallTest
+import com.android.app.tracing.coroutines.createCoroutineTracingContext
+import com.android.app.tracing.coroutines.nameCoroutine
+import com.android.app.tracing.coroutines.traceCoroutine
+import com.android.systemui.Flags
+import kotlinx.coroutines.delay
+import kotlinx.coroutines.launch
+import kotlinx.coroutines.runBlocking
+import kotlinx.coroutines.withContext
+import kotlinx.coroutines.yield
+import org.junit.After
+import org.junit.Assert
+import org.junit.Before
+import org.junit.ClassRule
+import org.junit.Rule
+import org.junit.Test
+import org.junit.runner.RunWith
+
+private val TAG: String = TraceContextMicroBenchmark::class.java.simpleName
+
+@RunWith(AndroidJUnit4::class)
+@EnableFlags(Flags.FLAG_COROUTINE_TRACING)
+class TraceContextMicroBenchmark {
+
+    @get:Rule val perfStatusReporter = PerfStatusReporter()
+
+    @get:Rule val setFlagsRule = SetFlagsRule()
+
+    companion object {
+        @JvmField @ClassRule(order = 1) var ensureDeviceSettingsRule = EnsureDeviceSettingsRule()
+    }
+
+    @Before
+    fun before() {
+        Assert.assertTrue(Trace.isEnabled())
+    }
+
+    @After
+    fun after() {
+        Assert.assertTrue(Trace.isEnabled())
+    }
+
+    private suspend fun ensureSuspend(state: BenchmarkState) {
+        state.pauseTiming()
+        delay(1)
+        state.resumeTiming()
+    }
+
+    @SmallTest
+    @Test
+    fun testSingleTraceSection() {
+        val state = perfStatusReporter.benchmarkState
+        runBlocking(createCoroutineTracingContext("root")) {
+            while (state.keepRunning()) {
+                traceCoroutine("hello-world") { ensureSuspend(state) }
+            }
+        }
+    }
+
+    @SmallTest
+    @Test
+    fun testNestedContext() {
+        val state = perfStatusReporter.benchmarkState
+
+        val context1 = createCoroutineTracingContext("scope1")
+        val context2 = nameCoroutine("scope2")
+        runBlocking {
+            while (state.keepRunning()) {
+                withContext(context1) {
+                    traceCoroutine("hello") {
+                        traceCoroutine("world") {
+                            withContext(context2) {
+                                traceCoroutine("hallo") {
+                                    traceCoroutine("welt") { ensureSuspend(state) }
+                                    ensureSuspend(state)
+                                }
+                            }
+                            ensureSuspend(state)
+                        }
+                        ensureSuspend(state)
+                    }
+                }
+            }
+        }
+    }
+
+    @SmallTest
+    @Test
+    fun testInterleavedLaunch() {
+        val state = perfStatusReporter.benchmarkState
+
+        runBlocking(createCoroutineTracingContext("root")) {
+            val job1 =
+                launch(nameCoroutine("scope1")) {
+                    while (true) {
+                        traceCoroutine("hello") {
+                            traceCoroutine("world") { yield() }
+                            yield()
+                        }
+                    }
+                }
+            val job2 =
+                launch(nameCoroutine("scope2")) {
+                    while (true) {
+                        traceCoroutine("hallo") {
+                            traceCoroutine("welt") { yield() }
+                            yield()
+                        }
+                    }
+                }
+            while (state.keepRunning()) {
+                repeat(10_000) { traceCoroutine("main-loop") { yield() } }
+            }
+            job1.cancel()
+            job2.cancel()
+        }
+    }
+}
diff --git a/tracinglib/core/Android.bp b/tracinglib/core/Android.bp
index f43afeb..da4f1fd 100644
--- a/tracinglib/core/Android.bp
+++ b/tracinglib/core/Android.bp
@@ -18,52 +18,18 @@ package {
 
 java_library {
     name: "tracinglib-platform",
-    defaults: ["tracinglib-defaults"],
     static_libs: [
         "kotlinx_coroutines_android",
         "com_android_systemui_flags_lib",
     ],
-    srcs: ["android/src-platform-api/**/*.kt"],
-}
-
-java_library {
-    name: "tracinglib-androidx",
-    defaults: ["tracinglib-defaults"],
-    static_libs: [
-        "kotlinx_coroutines_android",
-        "com_android_systemui_flags_lib",
-        "androidx.tracing_tracing",
-    ],
-    srcs: ["android/src-public-api/**/*.kt"],
-    sdk_version: "31",
-    min_sdk_version: "19",
-    java_version: "17",
-}
-
-java_test_host {
-    name: "tracinglib-host-test",
-    defaults: ["tracinglib-defaults"],
-    srcs: [
-        "host/src-fake/**/*.kt",
-        "host/test/**/*.kt",
-    ],
-    static_libs: [
-        "kotlinx_coroutines",
-        "kotlinx_coroutines_test",
-    ],
     libs: [
-        "junit",
+        "androidx.annotation_annotation",
     ],
-}
-
-java_defaults {
-    name: "tracinglib-defaults",
-    common_srcs: ["common/src/**/*.kt"],
     kotlincflags: [
         "-Xjvm-default=all",
-        "-Xmulti-platform",
         "-opt-in=kotlin.ExperimentalStdlibApi",
         "-opt-in=kotlinx.coroutines.DelicateCoroutinesApi",
         "-opt-in=kotlinx.coroutines.ExperimentalCoroutinesApi",
     ],
+    srcs: ["src/**/*.kt"],
 }
diff --git a/tracinglib/core/android/src-platform-api/TraceProxy.platform.kt b/tracinglib/core/android/src-platform-api/TraceProxy.platform.kt
deleted file mode 100644
index f4a30d3..0000000
--- a/tracinglib/core/android/src-platform-api/TraceProxy.platform.kt
+++ /dev/null
@@ -1,63 +0,0 @@
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
-package com.android.app.tracing
-
-import android.os.Trace
-
-@PublishedApi
-internal actual fun isEnabled(): Boolean {
-    return Trace.isEnabled()
-}
-
-internal actual fun traceCounter(counterName: String, counterValue: Int) {
-    Trace.traceCounter(Trace.TRACE_TAG_APP, counterName, counterValue)
-}
-
-internal actual fun traceBegin(methodName: String) {
-    Trace.traceBegin(Trace.TRACE_TAG_APP, methodName)
-}
-
-internal actual fun traceEnd() {
-    Trace.traceEnd(Trace.TRACE_TAG_APP)
-}
-
-internal actual fun asyncTraceBegin(methodName: String, cookie: Int) {
-    Trace.asyncTraceBegin(Trace.TRACE_TAG_APP, methodName, cookie)
-}
-
-internal actual fun asyncTraceEnd(methodName: String, cookie: Int) {
-    Trace.asyncTraceEnd(Trace.TRACE_TAG_APP, methodName, cookie)
-}
-
-@PublishedApi
-internal actual fun asyncTraceForTrackBegin(trackName: String, methodName: String, cookie: Int) {
-    Trace.asyncTraceForTrackBegin(Trace.TRACE_TAG_APP, trackName, methodName, cookie)
-}
-
-@PublishedApi
-internal actual fun asyncTraceForTrackEnd(trackName: String, methodName: String, cookie: Int) {
-    Trace.asyncTraceForTrackEnd(Trace.TRACE_TAG_APP, trackName, cookie)
-}
-
-internal actual fun instant(eventName: String) {
-    Trace.instant(Trace.TRACE_TAG_APP, eventName)
-}
-
-@PublishedApi
-internal actual fun instantForTrack(trackName: String, eventName: String) {
-    Trace.instantForTrack(Trace.TRACE_TAG_APP, trackName, eventName)
-}
diff --git a/tracinglib/core/android/src-public-api/src/TraceProxy.jetpack.kt b/tracinglib/core/android/src-public-api/src/TraceProxy.jetpack.kt
deleted file mode 100644
index 27c1b93..0000000
--- a/tracinglib/core/android/src-public-api/src/TraceProxy.jetpack.kt
+++ /dev/null
@@ -1,77 +0,0 @@
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
-package com.android.app.tracing
-
-import androidx.tracing.Trace
-import java.util.concurrent.ThreadLocalRandom
-
-@PublishedApi
-internal actual fun isEnabled(): Boolean {
-    return Trace.isEnabled()
-}
-
-internal actual fun traceCounter(counterName: String, counterValue: Int) {
-    Trace.setCounter(counterName, counterValue)
-}
-
-internal actual fun traceBegin(methodName: String) {
-    Trace.beginSection(methodName)
-}
-
-internal actual fun traceEnd() {
-    Trace.endSection()
-}
-
-internal actual fun asyncTraceBegin(methodName: String, cookie: Int) {
-    Trace.beginAsyncSection(methodName, cookie)
-}
-
-internal actual fun asyncTraceEnd(methodName: String, cookie: Int) {
-    Trace.endAsyncSection(methodName, cookie)
-}
-
-private fun namedSlice(trackName: String, methodName: String) = "$trackName:$methodName"
-
-@PublishedApi
-internal actual fun asyncTraceForTrackBegin(trackName: String, methodName: String, cookie: Int) {
-    if (isEnabled()) {
-        asyncTraceBegin(namedSlice(trackName, methodName), cookie)
-    }
-}
-
-@PublishedApi
-internal actual fun asyncTraceForTrackEnd(trackName: String, methodName: String, cookie: Int) {
-    if (isEnabled()) {
-        asyncTraceEnd(namedSlice(trackName, methodName), cookie)
-    }
-}
-
-internal actual fun instant(eventName: String) {
-    if (isEnabled()) {
-        traceBegin("instant:$eventName")
-        traceEnd()
-    }
-}
-
-internal actual fun instantForTrack(trackName: String, eventName: String) {
-    if (Trace.isEnabled()) {
-        val cookie = ThreadLocalRandom.current().nextInt()
-        val name = "instant:${namedSlice(trackName,eventName)}"
-        asyncTraceBegin(name, cookie)
-        asyncTraceEnd(name, cookie)
-    }
-}
diff --git a/tracinglib/core/common/src/FlowTracing.kt b/tracinglib/core/common/src/FlowTracing.kt
deleted file mode 100644
index 5791779..0000000
--- a/tracinglib/core/common/src/FlowTracing.kt
+++ /dev/null
@@ -1,44 +0,0 @@
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
-package com.android.app.tracing
-
-import kotlinx.coroutines.flow.Flow
-import kotlinx.coroutines.flow.onEach
-
-/** Utilities to trace Flows */
-object FlowTracing {
-
-    /** Logs each flow element to a trace. */
-    inline fun <T> Flow<T>.traceEach(
-        flowName: String,
-        logcat: Boolean = false,
-        traceEmissionCount: Boolean = false,
-        crossinline valueToString: (T) -> String = { it.toString() }
-    ): Flow<T> {
-        val stateLogger = TraceStateLogger(flowName, logcat = logcat)
-        val baseFlow = if (traceEmissionCount) traceEmissionCount(flowName) else this
-        return baseFlow.onEach { stateLogger.log(valueToString(it)) }
-    }
-
-    fun <T> Flow<T>.traceEmissionCount(flowName: String): Flow<T> {
-        val trackName = "$flowName#emissionCount"
-        var count = 0
-        return onEach {
-            count += 1
-            traceCounter(trackName, count)
-        }
-    }
-}
diff --git a/tracinglib/core/common/src/TraceProxy.kt b/tracinglib/core/common/src/TraceProxy.kt
deleted file mode 100644
index fcff079..0000000
--- a/tracinglib/core/common/src/TraceProxy.kt
+++ /dev/null
@@ -1,62 +0,0 @@
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
-package com.android.app.tracing
-
-internal expect fun isEnabled(): Boolean
-
-internal expect fun traceCounter(counterName: String, counterValue: Int)
-
-internal expect fun traceBegin(methodName: String)
-
-internal expect fun traceEnd()
-
-internal expect fun asyncTraceBegin(methodName: String, cookie: Int)
-
-internal expect fun asyncTraceEnd(methodName: String, cookie: Int)
-
-internal expect fun asyncTraceForTrackBegin(trackName: String, methodName: String, cookie: Int)
-
-internal expect fun asyncTraceForTrackEnd(trackName: String, methodName: String, cookie: Int)
-
-/**
- * Writes a trace message indicating that an instant event occurred on the current thread. Unlike
- * slices, instant events have no duration and do not need to be matched with another call. Perfetto
- * will display instant events using an arrow pointing to the timestamp they occurred:
- * ```
- * Thread #1 | [==============]               [======]
- *           |     [====]                        ^
- *           |        ^
- * ```
- *
- * @param eventName The name of the event to appear in the trace.
- */
-internal expect fun instant(eventName: String)
-
-/**
- * Writes a trace message indicating that an instant event occurred on the given track. Unlike
- * slices, instant events have no duration and do not need to be matched with another call. Perfetto
- * will display instant events using an arrow pointing to the timestamp they occurred:
- * ```
- * Async  | [==============]               [======]
- *  Track |     [====]                        ^
- *   Name |        ^
- * ```
- *
- * @param trackName The track where the event should appear in the trace.
- * @param eventName The name of the event to appear in the trace.
- */
-internal expect fun instantForTrack(trackName: String, eventName: String)
diff --git a/tracinglib/core/common/src/coroutines/TraceContextElement.kt b/tracinglib/core/common/src/coroutines/TraceContextElement.kt
deleted file mode 100644
index cf8946d..0000000
--- a/tracinglib/core/common/src/coroutines/TraceContextElement.kt
+++ /dev/null
@@ -1,157 +0,0 @@
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
-package com.android.app.tracing.coroutines
-
-import com.android.systemui.Flags.coroutineTracing
-import kotlin.coroutines.CoroutineContext
-import kotlin.coroutines.EmptyCoroutineContext
-import kotlinx.coroutines.CopyableThreadContextElement
-
-private const val DEBUG = false
-
-/** Log a message with a tag indicating the current thread ID */
-private inline fun debug(message: () -> String) {
-    if (DEBUG) println("Thread #${Thread.currentThread().id}: ${message()}")
-}
-
-/** Use a final subclass to avoid virtual calls (b/316642146). */
-@PublishedApi internal class TraceDataThreadLocal : ThreadLocal<TraceData?>()
-
-/**
- * Thread-local storage for giving each thread a unique [TraceData]. It can only be used when paired
- * with a [TraceContextElement].
- *
- * [traceThreadLocal] will be `null` if either 1) we aren't in a coroutine, or 2) the current
- * coroutine context does not have [TraceContextElement]. In both cases, writing to this
- * thread-local would be undefined behavior if it were not null, which is why we use null as the
- * default value rather than an empty TraceData.
- *
- * @see traceCoroutine
- */
-@PublishedApi internal val traceThreadLocal = TraceDataThreadLocal()
-
-/**
- * Returns a new [CoroutineContext] used for tracing. Used to hide internal implementation details.
- */
-fun createCoroutineTracingContext(): CoroutineContext {
-    return if (coroutineTracing()) TraceContextElement(TraceData()) else EmptyCoroutineContext
-}
-
-/**
- * Used for safely persisting [TraceData] state when coroutines are suspended and resumed.
- *
- * This is internal machinery for [traceCoroutine]. It cannot be made `internal` or `private`
- * because [traceCoroutine] is a Public-API inline function.
- *
- * @see traceCoroutine
- */
-internal class TraceContextElement(internal val traceData: TraceData? = TraceData()) :
-    CopyableThreadContextElement<TraceData?> {
-
-    internal companion object Key : CoroutineContext.Key<TraceContextElement>
-
-    override val key: CoroutineContext.Key<*>
-        get() = Key
-
-    init {
-        debug { "$this #init" }
-    }
-
-    /**
-     * This function is invoked before the coroutine is resumed on the current thread. When a
-     * multi-threaded dispatcher is used, calls to `updateThreadContext` may happen in parallel to
-     * the prior `restoreThreadContext` in the same context. However, calls to `updateThreadContext`
-     * will not run in parallel on the same context.
-     *
-     * ```
-     * Thread #1 | [updateThreadContext]....^              [restoreThreadContext]
-     * --------------------------------------------------------------------------------------------
-     * Thread #2 |                           [updateThreadContext]...........^[restoreThreadContext]
-     * ```
-     *
-     * (`...` indicate coroutine body is running; whitespace indicates the thread is not scheduled;
-     * `^` is a suspension point)
-     */
-    override fun updateThreadContext(context: CoroutineContext): TraceData? {
-        val oldState = traceThreadLocal.get()
-        debug { "$this #updateThreadContext oldState=$oldState" }
-        if (oldState !== traceData) {
-            traceThreadLocal.set(traceData)
-            // Calls to `updateThreadContext` will not happen in parallel on the same context, and
-            // they cannot happen before the prior suspension point. Additionally,
-            // `restoreThreadContext` does not modify `traceData`, so it is safe to iterate over the
-            // collection here:
-            traceData?.beginAllOnThread()
-        }
-        return oldState
-    }
-
-    /**
-     * This function is invoked after the coroutine has suspended on the current thread. When a
-     * multi-threaded dispatcher is used, calls to `restoreThreadContext` may happen in parallel to
-     * the subsequent `updateThreadContext` and `restoreThreadContext` operations. The coroutine
-     * body itself will not run in parallel, but `TraceData` could be modified by a coroutine body
-     * after the suspension point in parallel to `restoreThreadContext` associated with the
-     * coroutine body _prior_ to the suspension point.
-     *
-     * ```
-     * Thread #1 | [updateThreadContext].x..^              [restoreThreadContext]
-     * --------------------------------------------------------------------------------------------
-     * Thread #2 |                           [updateThreadContext]..x..x.....^[restoreThreadContext]
-     * ```
-     *
-     * OR
-     *
-     * ```
-     * Thread #1 |                                 [restoreThreadContext]
-     * --------------------------------------------------------------------------------------------
-     * Thread #2 |     [updateThreadContext]...x....x..^[restoreThreadContext]
-     * ```
-     *
-     * (`...` indicate coroutine body is running; whitespace indicates the thread is not scheduled;
-     * `^` is a suspension point; `x` are calls to modify the thread-local trace data)
-     *
-     * ```
-     */
-    override fun restoreThreadContext(context: CoroutineContext, oldState: TraceData?) {
-        debug { "$this#restoreThreadContext restoring=$oldState" }
-        // We not use the `TraceData` object here because it may have been modified on another
-        // thread after the last suspension point. This is why we use a [TraceStateHolder]:
-        // so we can end the correct number of trace sections, restoring the thread to its state
-        // prior to the last call to [updateThreadContext].
-        if (oldState !== traceThreadLocal.get()) {
-            traceData?.endAllOnThread()
-            traceThreadLocal.set(oldState)
-        }
-    }
-
-    override fun copyForChild(): CopyableThreadContextElement<TraceData?> {
-        debug { "$this #copyForChild" }
-        return TraceContextElement(traceData?.clone())
-    }
-
-    override fun mergeForChild(overwritingElement: CoroutineContext.Element): CoroutineContext {
-        debug { "$this #mergeForChild" }
-        // For our use-case, we always give precedence to the parent trace context, and the
-        // child context (overwritingElement) is ignored
-        return TraceContextElement(traceData?.clone())
-    }
-
-    override fun toString(): String {
-        return "TraceContextElement@${hashCode().toHexString()}[$traceData]"
-    }
-}
diff --git a/tracinglib/core/host/test/CoroutineTracingTest.kt b/tracinglib/core/host/test/CoroutineTracingTest.kt
deleted file mode 100644
index 9866366..0000000
--- a/tracinglib/core/host/test/CoroutineTracingTest.kt
+++ /dev/null
@@ -1,602 +0,0 @@
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
-package com.android.app.tracing.coroutines
-
-import com.android.app.tracing.FakeTraceState.getOpenTraceSectionsOnCurrentThread
-import com.android.systemui.Flags
-import java.util.concurrent.CyclicBarrier
-import java.util.concurrent.Executors
-import java.util.concurrent.TimeUnit
-import java.util.concurrent.atomic.AtomicInteger
-import kotlin.coroutines.CoroutineContext
-import kotlin.coroutines.EmptyCoroutineContext
-import kotlinx.coroutines.CoroutineScope
-import kotlinx.coroutines.CoroutineStart
-import kotlinx.coroutines.channels.Channel
-import kotlinx.coroutines.delay
-import kotlinx.coroutines.launch
-import kotlinx.coroutines.newSingleThreadContext
-import kotlinx.coroutines.test.TestScope
-import kotlinx.coroutines.test.UnconfinedTestDispatcher
-import kotlinx.coroutines.test.runTest
-import kotlinx.coroutines.withContext
-import org.junit.After
-import org.junit.Assert.assertArrayEquals
-import org.junit.Assert.assertEquals
-import org.junit.Assert.assertNotNull
-import org.junit.Assert.assertNotSame
-import org.junit.Assert.assertNull
-import org.junit.Assert.assertSame
-import org.junit.Assert.assertTrue
-import org.junit.Before
-import org.junit.Test
-import org.junit.runner.RunWith
-import org.junit.runners.BlockJUnit4ClassRunner
-
-@RunWith(BlockJUnit4ClassRunner::class)
-class CoroutineTracingTest {
-    @Before
-    fun setup() {
-        TraceData.strictModeForTesting = true
-    }
-
-    @After
-    fun checkFinished() {
-        val lastEvent = eventCounter.get()
-        assertTrue(
-            "Expected `finish(${lastEvent + 1})` to be called, but the test finished",
-            lastEvent == FINAL_EVENT || lastEvent == 0,
-        )
-    }
-
-    @Test
-    fun simpleTraceSection() = runTestWithTraceContext {
-        expect(1)
-        traceCoroutine("hello") { expect(2, "hello") }
-        finish(3)
-    }
-
-    @Test
-    fun simpleNestedTraceSection() = runTestWithTraceContext {
-        expect(1)
-        traceCoroutine("hello") {
-            expect(2, "hello")
-            traceCoroutine("world") { expect(3, "hello", "world") }
-            expect(4, "hello")
-        }
-        finish(5)
-    }
-
-    @Test
-    fun simpleLaunch() = runTestWithTraceContext {
-        expect(1)
-        traceCoroutine("hello") {
-            expect(2, "hello")
-            launch { finish(4, "hello") }
-        }
-        expect(3)
-    }
-
-    @Test
-    fun launchWithSuspendingLambda() = runTestWithTraceContext {
-        val fetchData: suspend () -> String = {
-            expect(3, "span-for-launch")
-            delay(1L)
-            traceCoroutine("span-for-fetchData") {
-                expect(4, "span-for-launch", "span-for-fetchData")
-            }
-            "stuff"
-        }
-        expect(1)
-        launch("span-for-launch") {
-            assertEquals("stuff", fetchData())
-            finish(5, "span-for-launch")
-        }
-        expect(2)
-    }
-
-    @Test
-    fun nestedUpdateAndRestoreOnSingleThread_unconfinedDispatcher() = runTestWithTraceContext {
-        traceCoroutine("parent-span") {
-            expect(1, "parent-span")
-            launch(UnconfinedTestDispatcher(scheduler = testScheduler)) {
-                // While this may appear unusual, it is actually expected behavior:
-                //   1) The parent has an open trace section called "parent-span".
-                //   2) The child launches, it inherits from its parent, and it is resumed
-                //      immediately due to its use of the unconfined dispatcher.
-                //   3) The child emits all the trace sections known to its scope. The parent
-                //      does not have an opportunity to restore its context yet.
-                traceCoroutine("child-span") {
-                    // [parent's active trace]
-                    //           \  [trace section inherited from parent]
-                    //            \                 |    [new trace section in child scope]
-                    //             \                |             /
-                    expect(2, "parent-span", "parent-span", "child-span")
-                    delay(1) // <-- delay will give parent a chance to restore its context
-                    // After a delay, the parent resumes, finishing its trace section, so we are
-                    // left with only those in the child's scope
-                    finish(4, "parent-span", "child-span")
-                }
-            }
-        }
-        expect(3)
-    }
-
-    /** @see nestedUpdateAndRestoreOnSingleThread_unconfinedDispatcher */
-    @Test
-    fun nestedUpdateAndRestoreOnSingleThread_undispatchedLaunch() = runTestWithTraceContext {
-        traceCoroutine("parent-span") {
-            launch(start = CoroutineStart.UNDISPATCHED) {
-                traceCoroutine("child-span") {
-                    expect(1, "parent-span", "parent-span", "child-span")
-                    delay(1) // <-- delay will give parent a chance to restore its context
-                    finish(3, "parent-span", "child-span")
-                }
-            }
-        }
-        expect(2)
-    }
-
-    @Test
-    fun launchOnSeparateThread_defaultDispatcher() = runTestWithTraceContext {
-        val channel = Channel<Int>()
-        val bgThread = newSingleThreadContext("thread-#1")
-        expect()
-        traceCoroutine("hello") {
-            expect(1, "hello")
-            launch(bgThread) {
-                expect(2, "hello")
-                traceCoroutine("world") {
-                    expect("hello", "world")
-                    channel.send(1)
-                    expect(3, "hello", "world")
-                }
-            }
-            expect("hello")
-        }
-        expect()
-        assertEquals(1, channel.receive())
-        finish(4)
-    }
-
-    @Test
-    fun testTraceStorage() = runTestWithTraceContext {
-        val channel = Channel<Int>()
-        val fetchData: suspend () -> String = {
-            traceCoroutine("span-for-fetchData") {
-                channel.receive()
-                expect("span-for-launch", "span-for-fetchData")
-            }
-            "stuff"
-        }
-        val threadContexts =
-            listOf(
-                newSingleThreadContext("thread-#1"),
-                newSingleThreadContext("thread-#2"),
-                newSingleThreadContext("thread-#3"),
-                newSingleThreadContext("thread-#4"),
-            )
-
-        val finishedLaunches = Channel<Int>()
-
-        // Start 1000 coroutines waiting on [channel]
-        val job = launch {
-            repeat(1000) {
-                launch("span-for-launch", threadContexts[it % threadContexts.size]) {
-                    assertNotNull(traceThreadLocal.get())
-                    assertEquals("stuff", fetchData())
-                    expect("span-for-launch")
-                    assertNotNull(traceThreadLocal.get())
-                    expect("span-for-launch")
-                    finishedLaunches.send(it)
-                }
-                expect()
-            }
-        }
-        // Resume half the coroutines that are waiting on this channel
-        repeat(500) { channel.send(1) }
-        var receivedClosures = 0
-        repeat(500) {
-            finishedLaunches.receive()
-            receivedClosures++
-        }
-        // ...and cancel the rest
-        job.cancel()
-    }
-
-    private fun CoroutineScope.testTraceSectionsMultiThreaded(
-        thread1Context: CoroutineContext,
-        thread2Context: CoroutineContext
-    ) {
-        val fetchData1: suspend () -> String = {
-            expect("span-for-launch-1")
-            delay(1L)
-            traceCoroutine("span-for-fetchData-1") {
-                expect("span-for-launch-1", "span-for-fetchData-1")
-            }
-            expect("span-for-launch-1")
-            "stuff-1"
-        }
-
-        val fetchData2: suspend () -> String = {
-            expect(
-                "span-for-launch-1",
-                "span-for-launch-2",
-            )
-            delay(1L)
-            traceCoroutine("span-for-fetchData-2") {
-                expect("span-for-launch-1", "span-for-launch-2", "span-for-fetchData-2")
-            }
-            expect(
-                "span-for-launch-1",
-                "span-for-launch-2",
-            )
-            "stuff-2"
-        }
-
-        val thread1 = newSingleThreadContext("thread-#1") + thread1Context
-        val thread2 = newSingleThreadContext("thread-#2") + thread2Context
-
-        launch("span-for-launch-1", thread1) {
-            assertEquals("stuff-1", fetchData1())
-            expect("span-for-launch-1")
-            launch("span-for-launch-2", thread2) {
-                assertEquals("stuff-2", fetchData2())
-                expect("span-for-launch-1", "span-for-launch-2")
-            }
-            expect("span-for-launch-1")
-        }
-        expect()
-
-        // Launching without the trace extension won't result in traces
-        launch(thread1) { expect() }
-        launch(thread2) { expect() }
-    }
-
-    @Test
-    fun nestedTraceSectionsMultiThreaded1() = runTestWithTraceContext {
-        // Thread-#1 and Thread-#2 inherit TraceContextElement from the test's CoroutineContext.
-        testTraceSectionsMultiThreaded(
-            thread1Context = EmptyCoroutineContext,
-            thread2Context = EmptyCoroutineContext
-        )
-    }
-
-    @Test
-    fun nestedTraceSectionsMultiThreaded2() = runTest {
-        // Thread-#2 inherits the TraceContextElement from Thread-#1. The test's CoroutineContext
-        // does not need a TraceContextElement because it does not do any tracing.
-        testTraceSectionsMultiThreaded(
-            thread1Context = TraceContextElement(TraceData()),
-            thread2Context = EmptyCoroutineContext
-        )
-    }
-
-    @Test
-    fun nestedTraceSectionsMultiThreaded3() = runTest {
-        // Thread-#2 overrides the TraceContextElement from Thread-#1, but the merging context
-        // should be fine; it is essentially a no-op. The test's CoroutineContext does not need the
-        // trace context because it does not do any tracing.
-        testTraceSectionsMultiThreaded(
-            thread1Context = TraceContextElement(TraceData()),
-            thread2Context = TraceContextElement(TraceData())
-        )
-    }
-
-    @Test
-    fun nestedTraceSectionsMultiThreaded4() = runTestWithTraceContext {
-        // TraceContextElement is merged on each context switch, which should have no effect on the
-        // trace results.
-        testTraceSectionsMultiThreaded(
-            thread1Context = TraceContextElement(TraceData()),
-            thread2Context = TraceContextElement(TraceData())
-        )
-    }
-
-    @Test
-    fun missingTraceContextObjects() = runTest {
-        val channel = Channel<Int>()
-        // Thread-#1 is missing a TraceContextElement, so some of the trace sections get dropped.
-        // The resulting trace sections will be different than the 4 tests above.
-        val fetchData1: suspend () -> String = {
-            expect()
-            channel.receive()
-            traceCoroutine("span-for-fetchData-1") { expect() }
-            expect()
-            "stuff-1"
-        }
-
-        val fetchData2: suspend () -> String = {
-            expect(
-                "span-for-launch-2",
-            )
-            channel.receive()
-            traceCoroutine("span-for-fetchData-2") {
-                expect("span-for-launch-2", "span-for-fetchData-2")
-            }
-            expect(
-                "span-for-launch-2",
-            )
-            "stuff-2"
-        }
-
-        val thread1 = newSingleThreadContext("thread-#1")
-        val thread2 = newSingleThreadContext("thread-#2") + TraceContextElement(TraceData())
-
-        launch("span-for-launch-1", thread1) {
-            assertEquals("stuff-1", fetchData1())
-            expect()
-            launch("span-for-launch-2", thread2) {
-                assertEquals("stuff-2", fetchData2())
-                expect("span-for-launch-2")
-            }
-            expect()
-        }
-        expect()
-
-        channel.send(1)
-        channel.send(2)
-
-        // Launching without the trace extension won't result in traces
-        launch(thread1) { expect() }
-        launch(thread2) { expect() }
-    }
-
-    /**
-     * Tests interleaving:
-     * ```
-     * Thread #1 | [updateThreadContext]....^              [restoreThreadContext]
-     * --------------------------------------------------------------------------------------------
-     * Thread #2 |                           [updateThreadContext]...........^[restoreThreadContext]
-     * ```
-     *
-     * This test checks for issues with concurrent modification of the trace state. For example, the
-     * test should fail if [TraceData.endAllOnThread] uses the size of the slices array as follows
-     * instead of using the ThreadLocal count:
-     * ```
-     * class TraceData {
-     *   ...
-     *   fun endAllOnThread() {
-     *     repeat(slices.size) {
-     *       // THIS WOULD BE AN ERROR. If the thread is slow, the TraceData object could have been
-     *       // modified by another thread
-     *       endSlice()
-     *     }
-     *   ...
-     *   }
-     * }
-     * ```
-     */
-    @Test
-    fun coroutineMachinery() {
-        assertNull(traceThreadLocal.get())
-        val traceContext = TraceContextElement()
-        assertNull(traceThreadLocal.get())
-
-        val thread1ResumptionPoint = CyclicBarrier(2)
-        val thread1SuspensionPoint = CyclicBarrier(2)
-
-        val thread1 = Executors.newSingleThreadExecutor()
-        val thread2 = Executors.newSingleThreadExecutor()
-        val slicesForThread1 = listOf("a", "c", "e", "g")
-        val slicesForThread2 = listOf("b", "d", "f", "h")
-        var failureOnThread1: Error? = null
-        var failureOnThread2: Error? = null
-
-        val expectedTraceForThread1 = arrayOf("1:a", "2:b", "1:c", "2:d", "1:e", "2:f", "1:g")
-        thread1.execute {
-            try {
-                slicesForThread1.forEachIndexed { index, sliceName ->
-                    assertNull(traceThreadLocal.get())
-                    val oldTrace = traceContext.updateThreadContext(EmptyCoroutineContext)
-                    // await() AFTER updateThreadContext, thus thread #1 always resumes the
-                    // coroutine before thread #2
-                    assertSame(traceThreadLocal.get(), traceContext.traceData)
-
-                    // coroutine body start {
-                    traceThreadLocal.get()?.beginSpan("1:$sliceName")
-
-                    // At the end, verify the interleaved trace sections look correct:
-                    if (index == slicesForThread1.size - 1) {
-                        expect(*expectedTraceForThread1)
-                    }
-
-                    // simulate a slow thread, wait to call restoreThreadContext until after thread
-                    // A
-                    // has resumed
-                    thread1SuspensionPoint.await(3, TimeUnit.SECONDS)
-                    Thread.sleep(500)
-                    // } coroutine body end
-
-                    traceContext.restoreThreadContext(EmptyCoroutineContext, oldTrace)
-                    thread1ResumptionPoint.await(3, TimeUnit.SECONDS)
-                    assertNull(traceThreadLocal.get())
-                }
-            } catch (e: Error) {
-                failureOnThread1 = e
-            }
-        }
-
-        val expectedTraceForThread2 =
-            arrayOf("1:a", "2:b", "1:c", "2:d", "1:e", "2:f", "1:g", "2:h")
-        thread2.execute {
-            try {
-                slicesForThread2.forEachIndexed { i, n ->
-                    assertNull(traceThreadLocal.get())
-                    thread1SuspensionPoint.await(3, TimeUnit.SECONDS)
-
-                    val oldTrace: TraceData? =
-                        traceContext.updateThreadContext(EmptyCoroutineContext)
-
-                    // coroutine body start {
-                    traceThreadLocal.get()?.beginSpan("2:$n")
-
-                    // At the end, verify the interleaved trace sections look correct:
-                    if (i == slicesForThread2.size - 1) {
-                        expect(*expectedTraceForThread2)
-                    }
-                    // } coroutine body end
-
-                    traceContext.restoreThreadContext(EmptyCoroutineContext, oldTrace)
-                    thread1ResumptionPoint.await(3, TimeUnit.SECONDS)
-                    assertNull(traceThreadLocal.get())
-                }
-            } catch (e: Error) {
-                failureOnThread2 = e
-            }
-        }
-
-        thread1.shutdown()
-        thread1.awaitTermination(5, TimeUnit.SECONDS)
-        thread2.shutdown()
-        thread2.awaitTermination(5, TimeUnit.SECONDS)
-
-        assertNull("Failure executing coroutine on thread-#1.", failureOnThread1)
-        assertNull("Failure executing coroutine on thread-#2.", failureOnThread2)
-    }
-
-    @Test
-    fun scopeReentry_withContextFastPath() = runTestWithTraceContext {
-        val channel = Channel<Int>()
-        val bgThread = newSingleThreadContext("bg-thread #1")
-        val job =
-            launch("#1", bgThread) {
-                expect("#1")
-                var i = 0
-                while (true) {
-                    expect("#1")
-                    channel.send(i++)
-                    expect("#1")
-                    // when withContext is passed the same scope, it takes a fast path, dispatching
-                    // immediately. This means that in subsequent loops, if we do not handle reentry
-                    // correctly in TraceContextElement, the trace may become deeply nested:
-                    // "#1", "#1", "#1", ... "#2"
-                    withContext(bgThread) {
-                        expect("#1")
-                        traceCoroutine("#2") {
-                            expect("#1", "#2")
-                            channel.send(i++)
-                            expect("#1", "#2")
-                        }
-                        expect("#1")
-                    }
-                }
-            }
-        repeat(1000) {
-            expect()
-            traceCoroutine("receive") {
-                expect("receive")
-                val receivedVal = channel.receive()
-                assertEquals(it, receivedVal)
-                expect("receive")
-            }
-            expect()
-        }
-        job.cancel()
-    }
-
-    @Test
-    fun traceContextIsCopied() = runTest {
-        expect()
-        val traceContext = TraceContextElement()
-        expect()
-        withContext(traceContext) {
-            // Not the same object because it should be copied into the current context
-            assertNotSame(traceThreadLocal.get(), traceContext.traceData)
-            assertNotSame(traceThreadLocal.get()?.slices, traceContext.traceData?.slices)
-            expect()
-            traceCoroutine("hello") {
-                assertNotSame(traceThreadLocal.get(), traceContext.traceData)
-                assertNotSame(traceThreadLocal.get()?.slices, traceContext.traceData?.slices)
-                assertArrayEquals(arrayOf("hello"), traceThreadLocal.get()?.slices?.toArray())
-            }
-            assertNotSame(traceThreadLocal.get(), traceContext.traceData)
-            assertNotSame(traceThreadLocal.get()?.slices, traceContext.traceData?.slices)
-            expect()
-        }
-        expect()
-    }
-
-    @Test
-    fun tracingDisabled() = runTest {
-        Flags.disableCoroutineTracing()
-        assertNull(traceThreadLocal.get())
-        withContext(createCoroutineTracingContext()) {
-            assertNull(traceThreadLocal.get())
-            traceCoroutine("hello") { // should not crash
-                assertNull(traceThreadLocal.get())
-            }
-        }
-    }
-
-    private fun expect(vararg expectedOpenTraceSections: String) {
-        expect(null, *expectedOpenTraceSections)
-    }
-
-    /**
-     * Checks the currently active trace sections on the current thread, and optionally checks the
-     * order of operations if [expectedEvent] is not null.
-     */
-    private fun expect(expectedEvent: Int? = null, vararg expectedOpenTraceSections: String) {
-        if (expectedEvent != null) {
-            val previousEvent = eventCounter.getAndAdd(1)
-            val currentEvent = previousEvent + 1
-            check(expectedEvent == currentEvent) {
-                if (previousEvent == FINAL_EVENT) {
-                    "Expected event=$expectedEvent, but finish() was already called"
-                } else {
-                    "Expected event=$expectedEvent," +
-                        " but the event counter is currently at $currentEvent"
-                }
-            }
-        }
-
-        // Inspect trace output to the fake used for recording android.os.Trace API calls:
-        assertArrayEquals(expectedOpenTraceSections, getOpenTraceSectionsOnCurrentThread())
-    }
-
-    /** Same as [expect], except that no more [expect] statements can be called after it. */
-    private fun finish(expectedEvent: Int, vararg expectedOpenTraceSections: String) {
-        val previousEvent = eventCounter.getAndSet(FINAL_EVENT)
-        val currentEvent = previousEvent + 1
-        check(expectedEvent == currentEvent) {
-            if (previousEvent == FINAL_EVENT) {
-                "finish() was called more than once"
-            } else {
-                "Finished with event=$expectedEvent," +
-                    " but the event counter is currently $currentEvent"
-            }
-        }
-
-        // Inspect trace output to the fake used for recording android.os.Trace API calls:
-        assertArrayEquals(expectedOpenTraceSections, getOpenTraceSectionsOnCurrentThread())
-    }
-
-    private val eventCounter = AtomicInteger(0)
-
-    companion object {
-        const val FINAL_EVENT = Int.MIN_VALUE
-    }
-}
-
-/**
- * Helper util for calling [runTest] with a [TraceContextElement]. This is useful for formatting
- * purposes. Passing an arg to `runTest {}` directly, as in `fun testStuff() =
- * runTestWithTraceContext {}` would require more indentations according to our style guide.
- */
-private fun runTestWithTraceContext(testBody: suspend TestScope.() -> Unit) =
-    runTest(context = TraceContextElement(TraceData()), testBody = testBody)
diff --git a/tracinglib/core/src/FlowTracing.kt b/tracinglib/core/src/FlowTracing.kt
new file mode 100644
index 0000000..ce2b645
--- /dev/null
+++ b/tracinglib/core/src/FlowTracing.kt
@@ -0,0 +1,134 @@
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
+@file:OptIn(ExperimentalTypeInference::class)
+
+package com.android.app.tracing
+
+import android.os.Trace
+import com.android.app.tracing.TraceUtils.traceAsync
+import java.util.concurrent.atomic.AtomicInteger
+import kotlin.experimental.ExperimentalTypeInference
+import kotlinx.coroutines.channels.ProducerScope
+import kotlinx.coroutines.channels.awaitClose
+import kotlinx.coroutines.flow.Flow
+import kotlinx.coroutines.flow.callbackFlow
+import kotlinx.coroutines.flow.conflate
+import kotlinx.coroutines.flow.onEach
+
+/** Utilities to trace Flows */
+object FlowTracing {
+
+    private const val TAG = "FlowTracing"
+    private const val DEFAULT_ASYNC_TRACK_NAME = TAG
+    private val counter = AtomicInteger(0)
+
+    /** Logs each flow element to a trace. */
+    inline fun <T> Flow<T>.traceEach(
+        flowName: String,
+        logcat: Boolean = false,
+        traceEmissionCount: Boolean = false,
+        crossinline valueToString: (T) -> String = { it.toString() },
+    ): Flow<T> {
+        val stateLogger = TraceStateLogger(flowName, logcat = logcat)
+        val baseFlow = if (traceEmissionCount) traceEmissionCount(flowName) else this
+        return baseFlow.onEach { stateLogger.log(valueToString(it)) }
+    }
+
+    /** Records value of a given numeric flow as a counter track in traces. */
+    fun <T : Number> Flow<T>.traceAsCounter(
+        counterName: String,
+        traceEmissionCount: Boolean = false,
+        valueToInt: (T) -> Int = { it.toInt() },
+    ): Flow<T> {
+        val baseFlow = if (traceEmissionCount) traceEmissionCount(counterName) else this
+        return baseFlow.onEach {
+            if (Trace.isEnabled()) {
+                Trace.traceCounter(Trace.TRACE_TAG_APP, counterName, valueToInt(it))
+            }
+        }
+    }
+
+    /** Adds a counter track to monitor emissions from a specific flow.] */
+    fun <T> Flow<T>.traceEmissionCount(flowName: String, uniqueSuffix: Boolean = false): Flow<T> {
+        val trackName by lazy {
+            "$flowName#emissionCount" + if (uniqueSuffix) "\$${counter.addAndGet(1)}" else ""
+        }
+        var count = 0
+        return onEach {
+            count += 1
+            Trace.traceCounter(Trace.TRACE_TAG_APP, trackName, count)
+        }
+    }
+
+    /**
+     * Adds a counter track to monitor emissions from a specific flow.
+     *
+     * [flowName] is lazy: it would be computed only if tracing is enabled and only the first time.
+     */
+    fun <T> Flow<T>.traceEmissionCount(
+        flowName: () -> String,
+        uniqueSuffix: Boolean = false,
+    ): Flow<T> {
+        val trackName by lazy {
+            "${flowName()}#emissionCount" + if (uniqueSuffix) "\$${counter.addAndGet(1)}" else ""
+        }
+        var count = 0
+        return onEach {
+            count += 1
+            if (Trace.isEnabled()) {
+                Trace.traceCounter(Trace.TRACE_TAG_APP, trackName, count)
+            }
+        }
+    }
+
+    /**
+     * Makes [awaitClose] output Perfetto traces.
+     *
+     * There will be 2 traces:
+     * - One in the thread this is being executed on
+     * - One in a track having [DEFAULT_ASYNC_TRACK_NAME] name.
+     *
+     * This allows to easily have visibility into what's happening in awaitClose.
+     */
+    suspend fun ProducerScope<*>.tracedAwaitClose(name: String, block: () -> Unit = {}) {
+        awaitClose {
+            val traceName = { "$name#TracedAwaitClose" }
+            traceAsync(DEFAULT_ASYNC_TRACK_NAME, traceName) { traceSection(traceName) { block() } }
+        }
+    }
+
+    /**
+     * Traced version of [callbackFlow].
+     *
+     * Adds tracing in 2 ways:
+     * - An async slice will appear in the [DEFAULT_ASYNC_TRACK_NAME] named track.
+     * - A counter will be increased at every emission
+     *
+     * Should be used with [tracedAwaitClose] (when needed).
+     */
+    fun <T> tracedConflatedCallbackFlow(
+        name: String,
+        @BuilderInference block: suspend ProducerScope<T>.() -> Unit,
+    ): Flow<T> {
+        return callbackFlow {
+                traceAsync(DEFAULT_ASYNC_TRACK_NAME, { "$name#CallbackFlowBlock" }) {
+                    block(this@callbackFlow)
+                }
+            }
+            .conflate()
+            .traceEmissionCount(name, uniqueSuffix = true)
+    }
+}
diff --git a/tracinglib/core/common/src/ListenersTracing.kt b/tracinglib/core/src/ListenersTracing.kt
similarity index 100%
rename from tracinglib/core/common/src/ListenersTracing.kt
rename to tracinglib/core/src/ListenersTracing.kt
diff --git a/tracinglib/core/common/src/TraceStateLogger.kt b/tracinglib/core/src/TraceStateLogger.kt
similarity index 82%
rename from tracinglib/core/common/src/TraceStateLogger.kt
rename to tracinglib/core/src/TraceStateLogger.kt
index a440d06..697b143 100644
--- a/tracinglib/core/common/src/TraceStateLogger.kt
+++ b/tracinglib/core/src/TraceStateLogger.kt
@@ -16,6 +16,7 @@
 
 package com.android.app.tracing
 
+import android.os.Trace
 import android.util.Log
 
 /**
@@ -34,7 +35,9 @@ import android.util.Log
  * This creates a new slice in a perfetto trace only if the state is different than the previous
  * one.
  */
-class TraceStateLogger(
+class TraceStateLogger
+@JvmOverloads
+constructor(
     private val trackName: String,
     private val logOnlyIfDifferent: Boolean = true,
     private val instantEvent: Boolean = true,
@@ -46,11 +49,13 @@ class TraceStateLogger(
     /** If needed, logs the value to a track with name [trackName]. */
     fun log(newValue: String) {
         if (instantEvent) {
-            instantForTrack(trackName, newValue)
+            Trace.instantForTrack(Trace.TRACE_TAG_APP, trackName, newValue)
         }
         if (logOnlyIfDifferent && previousValue == newValue) return
-        previousValue?.let { asyncTraceForTrackEnd(trackName, it, 0) }
-        asyncTraceForTrackBegin(trackName, newValue, 0)
+        if (previousValue != null) {
+            Trace.asyncTraceForTrackEnd(Trace.TRACE_TAG_APP, trackName, 0)
+        }
+        Trace.asyncTraceForTrackBegin(Trace.TRACE_TAG_APP, trackName, newValue, 0)
         if (logcat) {
             Log.d(trackName, "newValue: $newValue")
         }
diff --git a/tracinglib/core/android/src-platform-api/TraceUtils.platform.kt b/tracinglib/core/src/TraceUtils.android.kt
similarity index 88%
rename from tracinglib/core/android/src-platform-api/TraceUtils.platform.kt
rename to tracinglib/core/src/TraceUtils.android.kt
index 2d33b5b..633038d 100644
--- a/tracinglib/core/android/src-platform-api/TraceUtils.platform.kt
+++ b/tracinglib/core/src/TraceUtils.android.kt
@@ -16,6 +16,7 @@
 
 package com.android.app.tracing
 
+import android.os.Trace
 import android.os.TraceNameSupplier
 
 inline fun namedRunnable(tag: String, crossinline block: () -> Unit): Runnable {
@@ -27,7 +28,7 @@ inline fun namedRunnable(tag: String, crossinline block: () -> Unit): Runnable {
 }
 
 inline fun instantForTrack(trackName: String, eventName: () -> String) {
-    if (isEnabled()) {
-        instantForTrack(trackName, eventName())
+    if (Trace.isEnabled()) {
+        Trace.instantForTrack(Trace.TRACE_TAG_APP, trackName, eventName())
     }
 }
diff --git a/tracinglib/core/common/src/TraceUtils.kt b/tracinglib/core/src/TraceUtils.kt
similarity index 83%
rename from tracinglib/core/common/src/TraceUtils.kt
rename to tracinglib/core/src/TraceUtils.kt
index 0fd6f73..8ae5482 100644
--- a/tracinglib/core/common/src/TraceUtils.kt
+++ b/tracinglib/core/src/TraceUtils.kt
@@ -16,6 +16,7 @@
 
 package com.android.app.tracing
 
+import android.os.Trace
 import com.android.app.tracing.coroutines.traceCoroutine
 import java.util.concurrent.ThreadLocalRandom
 
@@ -64,7 +65,7 @@ import java.util.concurrent.ThreadLocalRandom
  * @see traceCoroutine
  */
 fun beginSlice(sliceName: String) {
-    traceBegin(sliceName)
+    Trace.traceBegin(Trace.TRACE_TAG_APP, sliceName)
 }
 
 /**
@@ -76,7 +77,7 @@ fun beginSlice(sliceName: String) {
  * @see traceCoroutine
  */
 fun endSlice() {
-    traceEnd()
+    Trace.traceEnd(Trace.TRACE_TAG_APP)
 }
 
 /**
@@ -84,7 +85,7 @@ fun endSlice() {
  * after the passed block.
  */
 inline fun <T> traceSection(tag: String, block: () -> T): T {
-    val tracingEnabled = isEnabled()
+    val tracingEnabled = Trace.isEnabled()
     if (tracingEnabled) beginSlice(tag)
     return try {
         // Note that as this is inline, the block section would be duplicated if it is called
@@ -100,7 +101,7 @@ inline fun <T> traceSection(tag: String, block: () -> T): T {
  * strings when not needed.
  */
 inline fun <T> traceSection(tag: () -> String, block: () -> T): T {
-    val tracingEnabled = isEnabled()
+    val tracingEnabled = Trace.isEnabled()
     if (tracingEnabled) beginSlice(tag())
     return try {
         block()
@@ -131,7 +132,7 @@ object TraceUtils {
     @JvmStatic
     inline fun traceRunnable(
         crossinline tag: () -> String,
-        crossinline block: () -> Unit
+        crossinline block: () -> Unit,
     ): Runnable {
         return Runnable { traceSection(tag) { block() } }
     }
@@ -146,6 +147,32 @@ object TraceUtils {
     inline fun <T> traceAsync(method: String, block: () -> T): T =
         traceAsync(DEFAULT_TRACK_NAME, method, block)
 
+    /** Creates an async slice in the default track. */
+    @JvmStatic
+    inline fun <T> traceAsync(tag: () -> String, block: () -> T): T {
+        val tracingEnabled = Trace.isEnabled()
+        return if (tracingEnabled) {
+            traceAsync(DEFAULT_TRACK_NAME, tag(), block)
+        } else {
+            block()
+        }
+    }
+
+    /**
+     * Creates an async slice in the default track.
+     *
+     * The [tag] is computed only if tracing is enabled. See [traceAsync].
+     */
+    @JvmStatic
+    inline fun <T> traceAsync(trackName: String, tag: () -> String, block: () -> T): T {
+        val tracingEnabled = Trace.isEnabled()
+        return if (tracingEnabled) {
+            traceAsync(trackName, tag(), block)
+        } else {
+            block()
+        }
+    }
+
     /**
      * Creates an async slice in a track with [trackName] while [block] runs.
      *
@@ -156,11 +183,11 @@ object TraceUtils {
     @JvmStatic
     inline fun <T> traceAsync(trackName: String, method: String, block: () -> T): T {
         val cookie = ThreadLocalRandom.current().nextInt()
-        asyncTraceForTrackBegin(trackName, method, cookie)
+        Trace.asyncTraceForTrackBegin(Trace.TRACE_TAG_APP, trackName, method, cookie)
         try {
             return block()
         } finally {
-            asyncTraceForTrackEnd(trackName, method, cookie)
+            Trace.asyncTraceForTrackEnd(Trace.TRACE_TAG_APP, trackName, cookie)
         }
     }
 }
diff --git a/tracinglib/core/common/src/coroutines/CoroutineTracing.kt b/tracinglib/core/src/coroutines/CoroutineTracing.kt
similarity index 68%
rename from tracinglib/core/common/src/coroutines/CoroutineTracing.kt
rename to tracinglib/core/src/coroutines/CoroutineTracing.kt
index 5b11dcc..1d55535 100644
--- a/tracinglib/core/common/src/coroutines/CoroutineTracing.kt
+++ b/tracinglib/core/src/coroutines/CoroutineTracing.kt
@@ -16,26 +16,36 @@
 
 package com.android.app.tracing.coroutines
 
-import com.android.app.tracing.asyncTraceForTrackBegin
-import com.android.app.tracing.asyncTraceForTrackEnd
-import com.android.app.tracing.isEnabled
-import java.util.concurrent.ThreadLocalRandom
+import com.android.systemui.Flags
 import kotlin.contracts.ExperimentalContracts
 import kotlin.contracts.InvocationKind
 import kotlin.contracts.contract
 import kotlin.coroutines.CoroutineContext
 import kotlin.coroutines.EmptyCoroutineContext
 import kotlinx.coroutines.CoroutineScope
+import kotlinx.coroutines.CoroutineStart
 import kotlinx.coroutines.Deferred
 import kotlinx.coroutines.Job
 import kotlinx.coroutines.async
+import kotlinx.coroutines.coroutineScope
 import kotlinx.coroutines.launch
 import kotlinx.coroutines.runBlocking
 import kotlinx.coroutines.withContext
 
-@PublishedApi internal const val TAG = "CoroutineTracing"
+const val DEFAULT_TRACK_NAME = "Coroutines"
 
-@PublishedApi internal const val DEFAULT_TRACK_NAME = "Coroutines"
+@OptIn(ExperimentalContracts::class)
+suspend inline fun <R> coroutineScope(
+    traceName: String,
+    crossinline block: suspend CoroutineScope.() -> R,
+): R {
+    contract { callsInPlace(block, InvocationKind.EXACTLY_ONCE) }
+    return traceCoroutine(traceName) {
+        return@traceCoroutine coroutineScope wrappedCoroutineScope@{
+            return@wrappedCoroutineScope block()
+        }
+    }
+}
 
 /**
  * Convenience function for calling [CoroutineScope.launch] with [traceCoroutine] to enable tracing.
@@ -45,21 +55,21 @@ import kotlinx.coroutines.withContext
 inline fun CoroutineScope.launch(
     crossinline spanName: () -> String,
     context: CoroutineContext = EmptyCoroutineContext,
-    // TODO(b/306457056): DO NOT pass CoroutineStart; doing so will regress .odex size
-    crossinline block: suspend CoroutineScope.() -> Unit
-): Job = launch(context) { traceCoroutine(spanName) { block() } }
+    start: CoroutineStart = CoroutineStart.DEFAULT,
+    noinline block: suspend CoroutineScope.() -> Unit,
+): Job = launch(nameCoroutine(spanName) + context, start, block)
 
 /**
  * Convenience function for calling [CoroutineScope.launch] with [traceCoroutine] to enable tracing.
  *
  * @see traceCoroutine
  */
-inline fun CoroutineScope.launch(
+fun CoroutineScope.launch(
     spanName: String,
     context: CoroutineContext = EmptyCoroutineContext,
-    // TODO(b/306457056): DO NOT pass CoroutineStart; doing so will regress .odex size
-    crossinline block: suspend CoroutineScope.() -> Unit
-): Job = launch(context) { traceCoroutine(spanName) { block() } }
+    start: CoroutineStart = CoroutineStart.DEFAULT,
+    block: suspend CoroutineScope.() -> Unit,
+): Job = launch(nameCoroutine(spanName) + context, start, block)
 
 /**
  * Convenience function for calling [CoroutineScope.async] with [traceCoroutine] enable tracing
@@ -67,23 +77,23 @@ inline fun CoroutineScope.launch(
  * @see traceCoroutine
  */
 inline fun <T> CoroutineScope.async(
-    crossinline spanName: () -> String,
+    spanName: () -> String,
     context: CoroutineContext = EmptyCoroutineContext,
-    // TODO(b/306457056): DO NOT pass CoroutineStart; doing so will regress .odex size
-    crossinline block: suspend CoroutineScope.() -> T
-): Deferred<T> = async(context) { traceCoroutine(spanName) { block() } }
+    start: CoroutineStart = CoroutineStart.DEFAULT,
+    noinline block: suspend CoroutineScope.() -> T,
+): Deferred<T> = async(nameCoroutine(spanName) + context, start, block)
 
 /**
  * Convenience function for calling [CoroutineScope.async] with [traceCoroutine] enable tracing.
  *
  * @see traceCoroutine
  */
-inline fun <T> CoroutineScope.async(
+fun <T> CoroutineScope.async(
     spanName: String,
     context: CoroutineContext = EmptyCoroutineContext,
-    // TODO(b/306457056): DO NOT pass CoroutineStart; doing so will regress .odex size
-    crossinline block: suspend CoroutineScope.() -> T
-): Deferred<T> = async(context) { traceCoroutine(spanName) { block() } }
+    start: CoroutineStart = CoroutineStart.DEFAULT,
+    block: suspend CoroutineScope.() -> T,
+): Deferred<T> = async(nameCoroutine(spanName) + context, start, block)
 
 /**
  * Convenience function for calling [runBlocking] with [traceCoroutine] to enable tracing.
@@ -91,32 +101,32 @@ inline fun <T> CoroutineScope.async(
  * @see traceCoroutine
  */
 inline fun <T> runBlocking(
-    crossinline spanName: () -> String,
+    spanName: () -> String,
     context: CoroutineContext,
-    crossinline block: suspend () -> T
-): T = runBlocking(context) { traceCoroutine(spanName) { block() } }
+    noinline block: suspend CoroutineScope.() -> T,
+): T = runBlocking(nameCoroutine(spanName) + context, block)
 
 /**
  * Convenience function for calling [runBlocking] with [traceCoroutine] to enable tracing.
  *
  * @see traceCoroutine
  */
-inline fun <T> runBlocking(
+fun <T> runBlocking(
     spanName: String,
     context: CoroutineContext,
-    crossinline block: suspend CoroutineScope.() -> T
-): T = runBlocking(context) { traceCoroutine(spanName) { block() } }
+    block: suspend CoroutineScope.() -> T,
+): T = runBlocking(nameCoroutine(spanName) + context, block)
 
 /**
  * Convenience function for calling [withContext] with [traceCoroutine] to enable tracing.
  *
  * @see traceCoroutine
  */
-suspend inline fun <T> withContext(
+suspend fun <T> withContext(
     spanName: String,
     context: CoroutineContext,
-    crossinline block: suspend CoroutineScope.() -> T
-): T = withContext(context) { traceCoroutine(spanName) { block() } }
+    block: suspend CoroutineScope.() -> T,
+): T = withContext(nameCoroutine(spanName) + context, block)
 
 /**
  * Convenience function for calling [withContext] with [traceCoroutine] to enable tracing.
@@ -124,10 +134,10 @@ suspend inline fun <T> withContext(
  * @see traceCoroutine
  */
 suspend inline fun <T> withContext(
-    crossinline spanName: () -> String,
+    spanName: () -> String,
     context: CoroutineContext,
-    crossinline block: suspend CoroutineScope.() -> T
-): T = withContext(context) { traceCoroutine(spanName) { block() } }
+    noinline block: suspend CoroutineScope.() -> T,
+): T = withContext(nameCoroutine(spanName) + context, block)
 
 /**
  * Traces a section of work of a `suspend` [block]. The trace sections will appear on the thread
@@ -176,21 +186,11 @@ inline fun <T> traceCoroutine(spanName: () -> String, block: () -> T): T {
     // For coroutine tracing to work, trace spans must be added and removed even when
     // tracing is not active (i.e. when TRACE_TAG_APP is disabled). Otherwise, when the
     // coroutine resumes when tracing is active, we won't know its name.
-    val traceData = traceThreadLocal.get()
-    val asyncTracingEnabled = isEnabled()
-    val spanString = if (traceData != null || asyncTracingEnabled) spanName() else "<none>"
-
-    traceData?.beginSpan(spanString)
-
-    // Also trace to the "Coroutines" async track. This makes it easy to see the duration of
-    // coroutine spans. When the coroutine_tracing flag is enabled, those same names will
-    // appear in small slices on each thread as the coroutines are suspended and resumed.
-    val cookie = if (asyncTracingEnabled) ThreadLocalRandom.current().nextInt() else 0
-    if (asyncTracingEnabled) asyncTraceForTrackBegin(DEFAULT_TRACK_NAME, spanString, cookie)
+    val traceData = if (Flags.coroutineTracing()) traceThreadLocal.get() else null
+    traceData?.beginSpan(spanName())
     try {
         return block()
     } finally {
-        if (asyncTracingEnabled) asyncTraceForTrackEnd(DEFAULT_TRACK_NAME, spanString, cookie)
         traceData?.endSpan()
     }
 }
diff --git a/tracinglib/core/src/coroutines/TraceContextElement.kt b/tracinglib/core/src/coroutines/TraceContextElement.kt
new file mode 100644
index 0000000..240bef1
--- /dev/null
+++ b/tracinglib/core/src/coroutines/TraceContextElement.kt
@@ -0,0 +1,254 @@
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
+
+package com.android.app.tracing.coroutines
+
+import android.annotation.SuppressLint
+import android.os.Trace
+import android.util.Log
+import androidx.annotation.VisibleForTesting
+import com.android.systemui.Flags
+import java.util.concurrent.atomic.AtomicInteger
+import kotlin.coroutines.AbstractCoroutineContextKey
+import kotlin.coroutines.CoroutineContext
+import kotlin.coroutines.EmptyCoroutineContext
+import kotlin.coroutines.getPolymorphicElement
+import kotlin.coroutines.minusPolymorphicKey
+import kotlinx.coroutines.CopyableThreadContextElement
+import kotlinx.coroutines.DelicateCoroutinesApi
+import kotlinx.coroutines.ExperimentalCoroutinesApi
+
+/** Use a final subclass to avoid virtual calls (b/316642146). */
+class TraceDataThreadLocal : ThreadLocal<TraceData?>()
+
+/**
+ * Thread-local storage for giving each thread a unique [TraceData]. It can only be used when paired
+ * with a [TraceContextElement].
+ *
+ * [traceThreadLocal] will be `null` if either 1) we aren't in a coroutine, or 2) the current
+ * coroutine context does not have [TraceContextElement]. In both cases, writing to this
+ * thread-local would be undefined behavior if it were not null, which is why we use null as the
+ * default value rather than an empty TraceData.
+ *
+ * @see traceCoroutine
+ */
+val traceThreadLocal = TraceDataThreadLocal()
+
+/**
+ * Returns a new [CoroutineContext] used for tracing. Used to hide internal implementation details.
+ */
+fun createCoroutineTracingContext(name: String = "UnnamedScope"): CoroutineContext =
+    if (Flags.coroutineTracing()) TraceContextElement(name) else EmptyCoroutineContext
+
+fun nameCoroutine(name: String): CoroutineContext =
+    if (Flags.coroutineTracing()) CoroutineTraceName(name) else EmptyCoroutineContext
+
+inline fun nameCoroutine(name: () -> String): CoroutineContext =
+    if (Flags.coroutineTracing()) CoroutineTraceName(name()) else EmptyCoroutineContext
+
+open class BaseTraceElement : CoroutineContext.Element {
+    companion object Key : CoroutineContext.Key<BaseTraceElement>
+
+    override val key: CoroutineContext.Key<*>
+        get() = Key
+
+    // It is important to use getPolymorphicKey and minusPolymorphicKey
+    @OptIn(ExperimentalStdlibApi::class)
+    override fun <E : CoroutineContext.Element> get(key: CoroutineContext.Key<E>): E? =
+        getPolymorphicElement(key)
+
+    @OptIn(ExperimentalStdlibApi::class)
+    override fun minusKey(key: CoroutineContext.Key<*>): CoroutineContext = minusPolymorphicKey(key)
+
+    @Suppress("DeprecatedCallableAddReplaceWith")
+    @Deprecated(
+        message =
+            "Operator `+` on two BaseTraceElement objects is meaningless. " +
+                "If used, the context element to the right of `+` would simply replace the " +
+                "element to the left. To properly use `BaseTraceElement`, `CoroutineTraceName` " +
+                "should be used when creating a top-level `CoroutineScope`, " +
+                "and `TraceContextElement` should be passed to the child context " +
+                "that is under construction.",
+        level = DeprecationLevel.ERROR,
+    )
+    operator fun plus(other: BaseTraceElement): BaseTraceElement = other
+}
+
+class CoroutineTraceName(val name: String) : BaseTraceElement() {
+    @OptIn(ExperimentalStdlibApi::class)
+    companion object Key :
+        AbstractCoroutineContextKey<BaseTraceElement, CoroutineTraceName>(
+            BaseTraceElement,
+            { it as? CoroutineTraceName },
+        )
+}
+
+const val ROOT_SCOPE = 0
+
+/**
+ * Used for safely persisting [TraceData] state when coroutines are suspended and resumed.
+ *
+ * This is internal machinery for [traceCoroutine]. It cannot be made `internal` or `private`
+ * because [traceCoroutine] is a Public-API inline function.
+ *
+ * @see traceCoroutine
+ */
+@OptIn(DelicateCoroutinesApi::class, ExperimentalCoroutinesApi::class)
+@VisibleForTesting(otherwise = VisibleForTesting.PACKAGE_PRIVATE)
+class TraceContextElement
+private constructor(
+    coroutineTraceName: String,
+    inheritedTracePrefix: String,
+    @get:VisibleForTesting(otherwise = VisibleForTesting.PACKAGE_PRIVATE)
+    val contextTraceData: TraceData?,
+    private val coroutineDepth: Int, // depth relative to first TraceContextElement
+    parentId: Int,
+) : CopyableThreadContextElement<TraceData?>, BaseTraceElement() {
+
+    @OptIn(ExperimentalStdlibApi::class)
+    companion object Key :
+        AbstractCoroutineContextKey<BaseTraceElement, TraceContextElement>(
+            BaseTraceElement,
+            { it as? TraceContextElement },
+        )
+
+    /**
+     * Minor perf optimization: no need to create TraceData() for root scopes since all launches
+     * require creation of child via [copyForChild] or [mergeForChild].
+     */
+    constructor(scopeName: String) : this(scopeName, "", null, 0, ROOT_SCOPE)
+
+    private var childCoroutineCount = AtomicInteger(0)
+    private val currentId = hashCode()
+
+    private val fullCoroutineTraceName = "$inheritedTracePrefix$coroutineTraceName"
+    private val continuationTraceMessage =
+        "$fullCoroutineTraceName;$coroutineTraceName;d=$coroutineDepth;c=$currentId;p=$parentId"
+
+    init {
+        debug { "#init" }
+    }
+
+    /**
+     * This function is invoked before the coroutine is resumed on the current thread. When a
+     * multi-threaded dispatcher is used, calls to `updateThreadContext` may happen in parallel to
+     * the prior `restoreThreadContext` in the same context. However, calls to `updateThreadContext`
+     * will not run in parallel on the same context.
+     *
+     * ```
+     * Thread #1 | [updateThreadContext]....^              [restoreThreadContext]
+     * --------------------------------------------------------------------------------------------
+     * Thread #2 |                           [updateThreadContext]...........^[restoreThreadContext]
+     * ```
+     *
+     * (`...` indicate coroutine body is running; whitespace indicates the thread is not scheduled;
+     * `^` is a suspension point)
+     */
+    @SuppressLint("UnclosedTrace")
+    override fun updateThreadContext(context: CoroutineContext): TraceData? {
+        val oldState = traceThreadLocal.get()
+        debug { "#updateThreadContext oldState=$oldState" }
+        if (oldState !== contextTraceData) {
+            Trace.traceBegin(Trace.TRACE_TAG_APP, continuationTraceMessage)
+            traceThreadLocal.set(contextTraceData)
+            // Calls to `updateThreadContext` will not happen in parallel on the same context, and
+            // they cannot happen before the prior suspension point. Additionally,
+            // `restoreThreadContext` does not modify `traceData`, so it is safe to iterate over the
+            // collection here:
+            contextTraceData?.beginAllOnThread()
+        }
+        return oldState
+    }
+
+    /**
+     * This function is invoked after the coroutine has suspended on the current thread. When a
+     * multi-threaded dispatcher is used, calls to `restoreThreadContext` may happen in parallel to
+     * the subsequent `updateThreadContext` and `restoreThreadContext` operations. The coroutine
+     * body itself will not run in parallel, but `TraceData` could be modified by a coroutine body
+     * after the suspension point in parallel to `restoreThreadContext` associated with the
+     * coroutine body _prior_ to the suspension point.
+     *
+     * ```
+     * Thread #1 | [updateThreadContext].x..^              [restoreThreadContext]
+     * --------------------------------------------------------------------------------------------
+     * Thread #2 |                           [updateThreadContext]..x..x.....^[restoreThreadContext]
+     * ```
+     *
+     * OR
+     *
+     * ```
+     * Thread #1 |                                 [restoreThreadContext]
+     * --------------------------------------------------------------------------------------------
+     * Thread #2 |     [updateThreadContext]...x....x..^[restoreThreadContext]
+     * ```
+     *
+     * (`...` indicate coroutine body is running; whitespace indicates the thread is not scheduled;
+     * `^` is a suspension point; `x` are calls to modify the thread-local trace data)
+     *
+     * ```
+     */
+    override fun restoreThreadContext(context: CoroutineContext, oldState: TraceData?) {
+        debug { "#restoreThreadContext restoring=$oldState" }
+        // We not use the `TraceData` object here because it may have been modified on another
+        // thread after the last suspension point. This is why we use a [TraceStateHolder]:
+        // so we can end the correct number of trace sections, restoring the thread to its state
+        // prior to the last call to [updateThreadContext].
+        if (oldState !== traceThreadLocal.get()) {
+            contextTraceData?.endAllOnThread()
+            traceThreadLocal.set(oldState)
+            Trace.traceEnd(Trace.TRACE_TAG_APP) // end: currentScopeTraceMessage
+        }
+    }
+
+    override fun copyForChild(): CopyableThreadContextElement<TraceData?> {
+        debug { "#copyForChild" }
+        return createChildContext()
+    }
+
+    override fun mergeForChild(overwritingElement: CoroutineContext.Element): CoroutineContext {
+        debug { "#mergeForChild" }
+        val otherTraceContext = overwritingElement[TraceContextElement]
+        if (DEBUG && otherTraceContext != null) {
+            Log.e(
+                TAG,
+                UNEXPECTED_TRACE_DATA_ERROR_MESSAGE +
+                    "Current CoroutineContext.Element=$fullCoroutineTraceName, other CoroutineContext.Element=${otherTraceContext.fullCoroutineTraceName}",
+            )
+        }
+        return createChildContext(overwritingElement[CoroutineTraceName]?.name ?: "")
+    }
+
+    private fun createChildContext(coroutineTraceName: String = ""): TraceContextElement {
+        val childCount = childCoroutineCount.incrementAndGet()
+        return TraceContextElement(
+            coroutineTraceName,
+            "$fullCoroutineTraceName:$childCount^",
+            TraceData(),
+            coroutineDepth + 1,
+            currentId,
+        )
+    }
+
+    private inline fun debug(message: () -> String) {
+        if (DEBUG) Log.d(TAG, "@$currentId ${message()} $contextTraceData")
+    }
+}
+
+private const val UNEXPECTED_TRACE_DATA_ERROR_MESSAGE =
+    "Overwriting context element with non-empty trace data. There should only be one " +
+        "TraceContextElement per coroutine, and it should be installed in the root scope. "
+private const val TAG = "TraceContextElement"
+internal const val DEBUG = false
diff --git a/tracinglib/core/common/src/coroutines/TraceData.kt b/tracinglib/core/src/coroutines/TraceData.kt
similarity index 70%
rename from tracinglib/core/common/src/coroutines/TraceData.kt
rename to tracinglib/core/src/coroutines/TraceData.kt
index be03d9d..8dabea4 100644
--- a/tracinglib/core/common/src/coroutines/TraceData.kt
+++ b/tracinglib/core/src/coroutines/TraceData.kt
@@ -16,6 +16,7 @@
 
 package com.android.app.tracing.coroutines
 
+import androidx.annotation.VisibleForTesting
 import com.android.app.tracing.beginSlice
 import com.android.app.tracing.endSlice
 import java.util.ArrayDeque
@@ -28,8 +29,7 @@ import java.util.ArrayDeque
  */
 typealias TraceSection = String
 
-@PublishedApi
-internal class TraceCountThreadLocal : ThreadLocal<Int>() {
+class TraceCountThreadLocal : ThreadLocal<Int>() {
     override fun initialValue(): Int {
         return 0
     }
@@ -41,10 +41,10 @@ internal class TraceCountThreadLocal : ThreadLocal<Int>() {
  *
  * @see traceCoroutine
  */
-@PublishedApi
-internal class TraceData(
-    internal val slices: ArrayDeque<TraceSection> = ArrayDeque(),
-) : Cloneable {
+@VisibleForTesting(otherwise = VisibleForTesting.PACKAGE_PRIVATE)
+class TraceData {
+
+    var slices: ArrayDeque<TraceSection>? = null
 
     /**
      * ThreadLocal counter for how many open trace sections there are. This is needed because it is
@@ -57,18 +57,18 @@ internal class TraceData(
     private val openSliceCount = TraceCountThreadLocal()
 
     /** Adds current trace slices back to the current thread. Called when coroutine is resumed. */
-    internal fun beginAllOnThread() {
+    fun beginAllOnThread() {
         strictModeCheck()
-        slices.descendingIterator().forEach { beginSlice(it) }
-        openSliceCount.set(slices.size)
+        slices?.descendingIterator()?.forEach { beginSlice(it) }
+        openSliceCount.set(slices?.size ?: 0)
     }
 
     /**
      * Removes all current trace slices from the current thread. Called when coroutine is suspended.
      */
-    internal fun endAllOnThread() {
+    fun endAllOnThread() {
         strictModeCheck()
-        repeat(openSliceCount.get()) { endSlice() }
+        repeat(openSliceCount.get() ?: 0) { endSlice() }
         openSliceCount.set(0)
     }
 
@@ -78,11 +78,13 @@ internal class TraceData(
      * coroutines, or to child coroutines that have already started. The unique ID is used to verify
      * that the [endSpan] is corresponds to a [beginSpan].
      */
-    @PublishedApi
-    internal fun beginSpan(name: String) {
+    fun beginSpan(name: String) {
         strictModeCheck()
-        slices.push(name)
-        openSliceCount.set(slices.size)
+        if (slices == null) {
+            slices = ArrayDeque()
+        }
+        slices!!.push(name)
+        openSliceCount.set(slices!!.size)
         beginSlice(name)
     }
 
@@ -91,51 +93,42 @@ internal class TraceData(
      * trace slice will immediately be removed from the current thread. This information will not
      * propagate to parent coroutines, or to child coroutines that have already started.
      */
-    @PublishedApi
-    internal fun endSpan() {
+    fun endSpan() {
         strictModeCheck()
         // Should never happen, but we should be defensive rather than crash the whole application
-        if (slices.size > 0) {
-            slices.pop()
-            openSliceCount.set(slices.size)
+        if (slices != null && slices!!.size > 0) {
+            slices!!.pop()
+            openSliceCount.set(slices!!.size)
             endSlice()
-        } else if (strictModeForTesting) {
+        } else if (STRICT_MODE_FOR_TESTING) {
             throw IllegalStateException(INVALID_SPAN_END_CALL_ERROR_MESSAGE)
         }
     }
 
-    /**
-     * Used by [TraceContextElement] when launching a child coroutine so that the child coroutine's
-     * state is isolated from the parent.
-     */
-    public override fun clone(): TraceData {
-        return TraceData(slices.clone())
-    }
-
-    override fun toString(): String {
-        return "TraceData@${hashCode().toHexString()}-size=${slices.size}"
-    }
+    override fun toString(): String =
+        if (DEBUG) "{${slices?.joinToString(separator = "\", \"", prefix = "\"", postfix = "\"")}}"
+        else super.toString()
 
     private fun strictModeCheck() {
-        if (strictModeForTesting && traceThreadLocal.get() !== this) {
+        if (STRICT_MODE_FOR_TESTING && traceThreadLocal.get() !== this) {
             throw ConcurrentModificationException(STRICT_MODE_ERROR_MESSAGE)
         }
     }
-
-    companion object {
-        /**
-         * Whether to add additional checks to the coroutine machinery, throwing a
-         * `ConcurrentModificationException` if TraceData is modified from the wrong thread. This
-         * should only be set for testing.
-         */
-        internal var strictModeForTesting: Boolean = false
-    }
 }
 
+/**
+ * Whether to add additional checks to the coroutine machinery, throwing a
+ * `ConcurrentModificationException` if TraceData is modified from the wrong thread. This should
+ * only be set for testing.
+ */
+var STRICT_MODE_FOR_TESTING: Boolean = false
+
 private const val INVALID_SPAN_END_CALL_ERROR_MESSAGE =
-    "TraceData#endSpan called when there were no active trace sections."
+    "TraceData#endSpan called when there were no active trace sections in its scope."
 
 private const val STRICT_MODE_ERROR_MESSAGE =
     "TraceData should only be accessed using " +
         "the ThreadLocal: CURRENT_TRACE.get(). Accessing TraceData by other means, such as " +
         "through the TraceContextElement's property may lead to concurrent modification."
+
+@OptIn(ExperimentalStdlibApi::class) val hexFormatForId = HexFormat { number.prefix = "0x" }
diff --git a/tracinglib/core/src/coroutines/flow/FlowExt.kt b/tracinglib/core/src/coroutines/flow/FlowExt.kt
new file mode 100644
index 0000000..ec693c3
--- /dev/null
+++ b/tracinglib/core/src/coroutines/flow/FlowExt.kt
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
+package com.android.app.tracing.coroutines.flow
+
+import android.os.Trace
+import com.android.app.tracing.coroutines.CoroutineTraceName
+import com.android.app.tracing.coroutines.traceCoroutine
+import kotlin.coroutines.CoroutineContext
+import kotlin.experimental.ExperimentalTypeInference
+import kotlinx.coroutines.CoroutineDispatcher
+import kotlinx.coroutines.CoroutineName
+import kotlinx.coroutines.flow.Flow
+import kotlinx.coroutines.flow.FlowCollector
+import kotlinx.coroutines.flow.collectLatest as kx_collectLatest
+import kotlinx.coroutines.flow.filter as kx_filter
+import kotlinx.coroutines.flow.filterIsInstance as kx_filterIsInstance
+import kotlinx.coroutines.flow.flowOn as kx_flowOn
+import kotlinx.coroutines.flow.map as kx_map
+
+fun <T> Flow<T>.withTraceName(name: String?): Flow<T> {
+    return object : Flow<T> {
+        override suspend fun collect(collector: FlowCollector<T>) {
+            this@withTraceName.collect(name ?: walkStackForClassName(), collector)
+        }
+    }
+}
+
+/**
+ * NOTE: We cannot use a default value for the String name because [Flow.collect] is a member
+ * function. When an extension function has the same receiver type, name, and applicable arguments
+ * as a class member function, the member takes precedence.
+ */
+@OptIn(ExperimentalTypeInference::class)
+suspend inline fun <T> Flow<T>.collect(
+    name: String, /* cannot have a default parameter or else Flow#collect() override this call */
+    @BuilderInference block: FlowCollector<T>,
+) {
+    val (collectSlice, emitSlice) = getFlowSliceNames(name)
+    traceCoroutine(collectSlice) {
+        collect { value -> traceCoroutine(emitSlice) { block.emit(value) } }
+    }
+}
+
+@OptIn(ExperimentalTypeInference::class)
+suspend inline fun <T> Flow<T>.collectTraced(@BuilderInference block: FlowCollector<T>) {
+    collect(walkStackForClassName(), block)
+}
+
+suspend fun <T> Flow<T>.collectLatest(name: String? = null, action: suspend (T) -> Unit) {
+    val (collectSlice, emitSlice) = getFlowSliceNames(name)
+    traceCoroutine(collectSlice) {
+        kx_collectLatest { value -> traceCoroutine(emitSlice) { action(value) } }
+    }
+}
+
+@OptIn(ExperimentalStdlibApi::class)
+fun <T> Flow<T>.flowOn(context: CoroutineContext): Flow<T> {
+    val contextName =
+        context[CoroutineTraceName]?.name
+            ?: context[CoroutineName]?.name
+            ?: context[CoroutineDispatcher]?.javaClass?.simpleName
+            ?: context.javaClass.simpleName
+    return kx_flowOn(context).withTraceName("flowOn($contextName)")
+}
+
+inline fun <T> Flow<T>.filter(
+    name: String? = null,
+    crossinline predicate: suspend (T) -> Boolean,
+): Flow<T> {
+    val flowName = name ?: walkStackForClassName()
+    return withTraceName(flowName).kx_filter {
+        return@kx_filter traceCoroutine("$flowName:predicate") { predicate(it) }
+    }
+}
+
+inline fun <reified R> Flow<*>.filterIsInstance(): Flow<R> {
+    return kx_filterIsInstance<R>().withTraceName("${walkStackForClassName()}#filterIsInstance")
+}
+
+inline fun <T, R> Flow<T>.map(
+    name: String? = null,
+    crossinline transform: suspend (T) -> R,
+): Flow<R> {
+    val flowName = name ?: walkStackForClassName()
+    return withTraceName(flowName).kx_map {
+        return@kx_map traceCoroutine("$flowName:transform") { transform(it) }
+    }
+}
+
+fun getFlowSliceNames(name: String?): Pair<String, String> {
+    val flowName = name ?: walkStackForClassName()
+    return Pair("$flowName:collect", "$flowName:emit")
+}
+
+object FlowExt {
+    val currentFileName: String =
+        StackWalker.getInstance().walk { stream -> stream.limit(1).findFirst() }.get().fileName
+}
+
+private fun isFrameInteresting(frame: StackWalker.StackFrame): Boolean {
+    return frame.fileName != FlowExt.currentFileName
+}
+
+/** Get a name for the trace section include the name of the call site. */
+fun walkStackForClassName(): String {
+    Trace.traceBegin(Trace.TRACE_TAG_APP, "FlowExt#walkStackForClassName")
+    try {
+        val interestingFrame =
+            StackWalker.getInstance().walk { stream ->
+                stream.filter(::isFrameInteresting).limit(5).findFirst()
+            }
+        return if (interestingFrame.isPresent) {
+            val frame = interestingFrame.get()
+            return frame.className
+        } else {
+            "<unknown>"
+        }
+    } finally {
+        Trace.traceEnd(Trace.TRACE_TAG_APP)
+    }
+}
diff --git a/tracinglib/demo/README.md b/tracinglib/demo/README.md
deleted file mode 100644
index fa8e551..0000000
--- a/tracinglib/demo/README.md
+++ /dev/null
@@ -1,5 +0,0 @@
-# Building and Running
-
-Build and install the app using Soong and adevice. Then, tap an experiment to run it. The
-experiments run in the background, so to see what it is doing you will neeed to capture a perfetto
-trace.
diff --git a/tracinglib/demo/src/com/android/app/tracing/demo/ApplicationComponent.kt b/tracinglib/demo/src/com/android/app/tracing/demo/ApplicationComponent.kt
index 5318859..008df55 100644
--- a/tracinglib/demo/src/com/android/app/tracing/demo/ApplicationComponent.kt
+++ b/tracinglib/demo/src/com/android/app/tracing/demo/ApplicationComponent.kt
@@ -15,7 +15,11 @@
  */
 package com.android.app.tracing.demo
 
-import com.android.app.tracing.coroutines.createCoroutineTracingContext
+import android.os.Handler
+import android.os.HandlerThread
+import android.os.Looper
+import android.os.Trace
+import com.android.app.tracing.coroutines.nameCoroutine
 import com.android.app.tracing.demo.experiments.CollectFlow
 import com.android.app.tracing.demo.experiments.CombineDeferred
 import com.android.app.tracing.demo.experiments.Experiment
@@ -35,10 +39,10 @@ import javax.inject.Qualifier
 import javax.inject.Singleton
 import kotlin.annotation.AnnotationRetention.RUNTIME
 import kotlin.coroutines.CoroutineContext
-import kotlinx.coroutines.DelicateCoroutinesApi
+import kotlin.coroutines.EmptyCoroutineContext
+import kotlinx.coroutines.CoroutineDispatcher
 import kotlinx.coroutines.Dispatchers
-import kotlinx.coroutines.ExperimentalCoroutinesApi
-import kotlinx.coroutines.newSingleThreadContext
+import kotlinx.coroutines.android.asCoroutineDispatcher
 
 @Qualifier @MustBeDocumented @Retention(RUNTIME) annotation class Main
 
@@ -52,7 +56,16 @@ import kotlinx.coroutines.newSingleThreadContext
 
 @Qualifier @MustBeDocumented @Retention(RUNTIME) annotation class FixedThread2
 
-@Qualifier @MustBeDocumented @Retention(RUNTIME) annotation class Tracer
+@Qualifier @MustBeDocumented @Retention(RUNTIME) annotation class ExperimentLauncherThread
+
+const val NAME_DISPATCHERS = false
+
+private fun nameDispatcher(name: String) =
+    if (NAME_DISPATCHERS) {
+        nameCoroutine(name)
+    } else {
+        EmptyCoroutineContext
+    }
 
 @Module
 class ConcurrencyModule {
@@ -60,51 +73,48 @@ class ConcurrencyModule {
     @Provides
     @Singleton
     @Default
-    fun provideDefaultCoroutineContext(@Tracer tracerContext: CoroutineContext): CoroutineContext {
-        return Dispatchers.Default + tracerContext
+    fun provideDefaultCoroutineContext(): CoroutineContext {
+        return Dispatchers.Default + nameDispatcher("Dispatchers.Default")
     }
 
     @Provides
     @Singleton
     @IO
-    fun provideIOCoroutineContext(@Tracer tracerContext: CoroutineContext): CoroutineContext {
-        return Dispatchers.IO + tracerContext
+    fun provideIOCoroutineContext(): CoroutineContext {
+        return Dispatchers.IO + nameDispatcher("Dispatchers.IO")
     }
 
     @Provides
     @Singleton
     @Unconfined
-    fun provideUnconfinedCoroutineContext(
-        @Tracer tracerContext: CoroutineContext
-    ): CoroutineContext {
-        return Dispatchers.Unconfined + tracerContext
+    fun provideUnconfinedCoroutineContext(): CoroutineContext {
+        return Dispatchers.Unconfined + nameDispatcher("Dispatchers.Unconfined")
     }
 
-    @OptIn(ExperimentalCoroutinesApi::class, DelicateCoroutinesApi::class)
     @Provides
     @Singleton
     @FixedThread1
-    fun provideFixedThread1CoroutineContext(
-        @Tracer tracerContext: CoroutineContext
-    ): CoroutineContext {
-        return newSingleThreadContext("FixedThread #1") + tracerContext
+    fun provideFixedThread1CoroutineContext(): CoroutineContext {
+        val looper = startThreadWithLooper("FixedThread #1")
+        return Handler(looper).asCoroutineDispatcher("FixedCoroutineDispatcher #1") +
+            nameDispatcher("FixedCoroutineDispatcher #1")
     }
 
-    @OptIn(ExperimentalCoroutinesApi::class, DelicateCoroutinesApi::class)
     @Provides
     @Singleton
     @FixedThread2
-    fun provideFixedThread2CoroutineContext(
-        @Tracer tracerContext: CoroutineContext
-    ): CoroutineContext {
-        return newSingleThreadContext("FixedThread #2") + tracerContext
+    fun provideFixedThread2CoroutineContext(): CoroutineContext {
+        val looper = startThreadWithLooper("FixedThread #2")
+        return Handler(looper).asCoroutineDispatcher("FixedCoroutineDispatcher #2") +
+            nameDispatcher("FixedCoroutineDispatcher #2")
     }
 
     @Provides
-    @Tracer
     @Singleton
-    fun provideTracerCoroutineContext(): CoroutineContext {
-        return createCoroutineTracingContext()
+    @ExperimentLauncherThread
+    fun provideExperimentDispatcher(): CoroutineDispatcher {
+        val looper = startThreadWithLooper("Experiment Launcher Thread")
+        return Handler(looper).asCoroutineDispatcher("Experiment Launcher CoroutineDispatcher")
     }
 }
 
@@ -151,4 +161,14 @@ interface ExperimentModule {
 interface ApplicationComponent {
     /** Returns [Experiment]s that should be used with the application. */
     @Singleton fun getAllExperiments(): Map<Class<*>, Provider<Experiment>>
+
+    @Singleton @ExperimentLauncherThread fun getExperimentDispatcher(): CoroutineDispatcher
+}
+
+private fun startThreadWithLooper(name: String): Looper {
+    val thread = HandlerThread(name)
+    thread.start()
+    val looper = thread.looper
+    looper.setTraceTag(Trace.TRACE_TAG_APP)
+    return looper
 }
diff --git a/tracinglib/demo/src/com/android/app/tracing/demo/MainActivity.kt b/tracinglib/demo/src/com/android/app/tracing/demo/MainActivity.kt
index 6d27db6..031c458 100644
--- a/tracinglib/demo/src/com/android/app/tracing/demo/MainActivity.kt
+++ b/tracinglib/demo/src/com/android/app/tracing/demo/MainActivity.kt
@@ -24,32 +24,43 @@ import android.widget.LinearLayout
 import android.widget.ScrollView
 import android.widget.TextView
 import com.android.app.tracing.TraceUtils.trace
+import com.android.app.tracing.coroutines.createCoroutineTracingContext
+import com.android.app.tracing.coroutines.nameCoroutine
 import com.android.app.tracing.demo.experiments.Experiment
 import kotlinx.coroutines.CancellationException
 import kotlinx.coroutines.CoroutineScope
-import kotlinx.coroutines.DelicateCoroutinesApi
-import kotlinx.coroutines.ExperimentalCoroutinesApi
 import kotlinx.coroutines.Job
 import kotlinx.coroutines.cancel
 import kotlinx.coroutines.launch
-import kotlinx.coroutines.newSingleThreadContext
 
 private const val TRACK_NAME = "Active experiments"
 
 class MainActivity : Activity() {
 
-    @OptIn(ExperimentalCoroutinesApi::class, DelicateCoroutinesApi::class)
-    val threadContext = newSingleThreadContext("Experiment launcher")
-
     private val allExperiments = lazy {
         (applicationContext as MainApplication).appComponent.getAllExperiments()
     }
 
+    private val experimentLaunchContext = lazy {
+        (applicationContext as MainApplication).appComponent.getExperimentDispatcher()
+    }
+
+    private val scopeForExperiment = mutableMapOf<String, CoroutineScope>()
+
     private var logContainer: ScrollView? = null
     private var loggerView: TextView? = null
 
+    private fun getScopeForExperiment(name: String): CoroutineScope {
+        var scope = scopeForExperiment[name]
+        if (scope == null) {
+            scope =
+                CoroutineScope(experimentLaunchContext.value + createCoroutineTracingContext(name))
+            scopeForExperiment[name] = scope
+        }
+        return scope
+    }
+
     private fun <T : Experiment> createButtonForExperiment(demo: T): Button {
-        val buttonCoroutineScope = CoroutineScope(threadContext)
         var launchCounter = 0
         var job: Job? = null
         val className = demo::class.simpleName ?: "<unknown class>"
@@ -58,20 +69,25 @@ class MainActivity : Activity() {
                 context.getString(
                     R.string.run_experiment_button_text,
                     className,
-                    demo.getDescription()
+                    demo.getDescription(),
                 )
             setOnClickListener {
                 val experimentName = "$className #${launchCounter++}"
                 trace("$className#onClick") {
                     job?.let { trace("cancel") { it.cancel("Cancelled due to click") } }
-                    trace("launch") { job = buttonCoroutineScope.launch { demo.run() } }
+                    trace("launch") {
+                        job =
+                            getScopeForExperiment(className).launch(nameCoroutine("run")) {
+                                demo.run()
+                            }
+                    }
                     trace("toast") { appendLine("$experimentName started") }
                     job?.let {
                         Trace.asyncTraceForTrackBegin(
                             Trace.TRACE_TAG_APP,
                             TRACK_NAME,
-                            "Running $experimentName",
-                            it.hashCode()
+                            experimentName,
+                            it.hashCode(),
                         )
                     }
                 }
diff --git a/tracinglib/demo/src/com/android/app/tracing/demo/experiments/CollectFlow.kt b/tracinglib/demo/src/com/android/app/tracing/demo/experiments/CollectFlow.kt
index 025beed..0efc639 100644
--- a/tracinglib/demo/src/com/android/app/tracing/demo/experiments/CollectFlow.kt
+++ b/tracinglib/demo/src/com/android/app/tracing/demo/experiments/CollectFlow.kt
@@ -15,41 +15,71 @@
  */
 package com.android.app.tracing.demo.experiments
 
+import com.android.app.tracing.coroutines.flow.withTraceName
 import com.android.app.tracing.coroutines.launch
 import com.android.app.tracing.coroutines.traceCoroutine
 import com.android.app.tracing.demo.FixedThread1
+import com.android.app.tracing.demo.FixedThread2
 import javax.inject.Inject
 import javax.inject.Singleton
 import kotlin.coroutines.CoroutineContext
 import kotlinx.coroutines.coroutineScope
 import kotlinx.coroutines.delay
+import kotlinx.coroutines.flow.filter
 import kotlinx.coroutines.flow.flow
 import kotlinx.coroutines.flow.flowOn
+import kotlinx.coroutines.flow.map
+
+/** Util for introducing artificial delays to make the trace more readable for demo purposes. */
+private fun blockCurrentThread(millis: Long) {
+    Thread.sleep(millis)
+}
 
 @Singleton
 class CollectFlow
 @Inject
 constructor(
     @FixedThread1 private var fixedThreadContext1: CoroutineContext,
-    @FixedThread1 private var fixedThreadContext2: CoroutineContext,
+    @FixedThread2 private var fixedThreadContext2: CoroutineContext,
 ) : Experiment {
 
-    override fun getDescription(): String = "Collect flow and delay after getting result"
+    override fun getDescription(): String = "Collect a cold flow with intermediate operators"
 
-    private val countTo100 =
-        flow {
-                for (n in 0..100) {
-                    traceCoroutine("$tag: flow producer - delay(20)") { delay(20) }
-                    traceCoroutine("$tag: flow producer - emit($n)") { emit(n) }
+    override suspend fun run(): Unit = coroutineScope {
+        val numFlow =
+            flow {
+                    for (n in 0..4) {
+                        traceCoroutine("delay-and-emit for $n") {
+                            blockCurrentThread(5)
+                            delay(1)
+                            blockCurrentThread(6)
+                            emit(n)
+                            blockCurrentThread(7)
+                            delay(1)
+                            blockCurrentThread(8)
+                        }
+                    }
                 }
-            }
-            .flowOn(fixedThreadContext2)
+                .withTraceName("flowOf numbers")
+                .filter {
+                    blockCurrentThread(9)
+                    it % 2 == 0
+                }
+                .withTraceName("filter for even")
+                .map {
+                    blockCurrentThread(10)
+                    it * 3
+                }
+                .withTraceName("map 3x")
+                .flowOn(fixedThreadContext2)
+                .withTraceName("flowOn thread #2")
 
-    override suspend fun run(): Unit = coroutineScope {
-        launch("$tag: launch and collect", fixedThreadContext1) {
-            traceCoroutine("$tag: flow consumer - collect") {
-                countTo100.collect { value ->
-                    traceCoroutine("$tag: flow consumer - got $value") { delay(1) }
+        launch("launch on thread #1", fixedThreadContext1) {
+            numFlow.collect {
+                traceCoroutine("got: $it") {
+                    blockCurrentThread(11)
+                    delay(1)
+                    blockCurrentThread(12)
                 }
             }
         }
diff --git a/tracinglib/demo/src/com/android/app/tracing/demo/experiments/CombineDeferred.kt b/tracinglib/demo/src/com/android/app/tracing/demo/experiments/CombineDeferred.kt
index 7b806e3..30cc769 100644
--- a/tracinglib/demo/src/com/android/app/tracing/demo/experiments/CombineDeferred.kt
+++ b/tracinglib/demo/src/com/android/app/tracing/demo/experiments/CombineDeferred.kt
@@ -15,13 +15,17 @@
  */
 package com.android.app.tracing.demo.experiments
 
-import com.android.app.tracing.coroutines.async
-import com.android.app.tracing.demo.Default
+import com.android.app.tracing.coroutines.nameCoroutine
+import com.android.app.tracing.coroutines.traceCoroutine
 import com.android.app.tracing.demo.FixedThread1
 import com.android.app.tracing.demo.FixedThread2
+import com.android.app.tracing.demo.Unconfined
+import com.android.app.tracing.traceSection
 import javax.inject.Inject
 import javax.inject.Singleton
 import kotlin.coroutines.CoroutineContext
+import kotlinx.coroutines.CoroutineStart.LAZY
+import kotlinx.coroutines.async
 import kotlinx.coroutines.coroutineScope
 import kotlinx.coroutines.launch
 
@@ -31,20 +35,64 @@ class CombineDeferred
 constructor(
     @FixedThread1 private var fixedThreadContext1: CoroutineContext,
     @FixedThread2 private var fixedThreadContext2: CoroutineContext,
-    @Default private var defaultContext: CoroutineContext,
+    @Unconfined private var unconfinedContext: CoroutineContext,
 ) : Experiment {
-    override fun getDescription(): String = "async{} then await()"
+    override fun getDescription(): String = "async{} then start()"
 
-    override suspend fun run(): Unit = coroutineScope {
-        val results =
-            listOf(
-                async("$tag: async#1 - getNumber()", fixedThreadContext1) { getNumber() },
-                async("$tag: async#2 - getNumber()", fixedThreadContext2) { getNumber() },
-                async("$tag: async#3 - getNumber()", defaultContext) { getNumber() },
-                async("$tag: async#4 - getNumber()") { getNumber(0, 50) },
-                async("$tag: async#5 - getNumber()") { getNumber(50, 0) },
-                async("$tag: async#5 - getNumber()") { getNumber(50, 50) },
-            )
-        launch(fixedThreadContext1) { results.forEach { it.await() } }
+    override suspend fun run() {
+        traceCoroutine("start1") { incSlowly(50, 50) }
+        traceCoroutine("start2") { incSlowly(50, 50) }
+        traceCoroutine("start3") { incSlowly(50, 50) }
+        traceCoroutine("start4") { incSlowly(50, 50) }
+        traceCoroutine("coroutineScope") {
+            coroutineScope {
+                // deferred10 -> deferred20 -> deferred30
+                val deferred30 =
+                    async(start = LAZY, context = fixedThreadContext2) {
+                        traceCoroutine("async#30") { incSlowly(25, 25) }
+                    }
+                val deferred20 =
+                    async(start = LAZY, context = unconfinedContext) {
+                        traceCoroutine("async#20") { incSlowly(5, 45) }
+                        traceSection("start30") { deferred30.start() }
+                    }
+                val deferred10 =
+                    async(start = LAZY, context = fixedThreadContext1) {
+                        traceCoroutine("async#10") { incSlowly(10, 20) }
+                        traceSection("start20") { deferred20.start() }
+                    }
+
+                // deferredA -> deferredB -> deferredC
+                val deferredC =
+                    async(start = LAZY, context = fixedThreadContext1) {
+                        traceCoroutine("async#C") { incSlowly(35, 15) }
+                    }
+                val deferredB =
+                    async(start = LAZY, context = unconfinedContext) {
+                        traceCoroutine("async#B") { incSlowly(15, 35) }
+                        traceSection("startC") { deferredC.start() }
+                    }
+                val deferredA =
+                    async(start = LAZY, context = fixedThreadContext2) {
+                        traceCoroutine("async#A") { incSlowly(20, 30) }
+                        traceSection("startB") { deferredB.start() }
+                    }
+
+                // no dispatcher specified, so will inherit dispatcher from whoever called
+                // run(),
+                // meaning the ExperimentLauncherThread
+                val deferredE =
+                    async(nameCoroutine("overridden-scope-name-for-deferredE")) {
+                        traceCoroutine("async#E") { incSlowly(30, 20) }
+                    }
+
+                launch(fixedThreadContext1) {
+                    traceSection("start10") { deferred10.start() }
+                    traceSection("startA") { deferredA.start() }
+                    traceSection("startE") { deferredE.start() }
+                }
+            }
+        }
+        traceCoroutine("end") { incSlowly(50, 50) }
     }
 }
diff --git a/tracinglib/demo/src/com/android/app/tracing/demo/experiments/NestedLaunchesWithParentSpan.kt b/tracinglib/demo/src/com/android/app/tracing/demo/experiments/NestedLaunchesWithParentSpan.kt
index 5c0632f..5849149 100644
--- a/tracinglib/demo/src/com/android/app/tracing/demo/experiments/NestedLaunchesWithParentSpan.kt
+++ b/tracinglib/demo/src/com/android/app/tracing/demo/experiments/NestedLaunchesWithParentSpan.kt
@@ -30,7 +30,7 @@ class NestedLaunchesWithParentSpan
 @Inject
 constructor(
     @FixedThread1 private var fixedThreadContext1: CoroutineContext,
-    @FixedThread2 private var fixedThreadContext2: CoroutineContext
+    @FixedThread2 private var fixedThreadContext2: CoroutineContext,
 ) : Experiment {
     override fun getDescription(): String =
         "Nested launches in which only the parent uses a trace name"
@@ -40,7 +40,7 @@ constructor(
             delay(10)
             launch(fixedThreadContext2) {
                 delay(10)
-                launch(fixedThreadContext1) { getNumber() }
+                launch(fixedThreadContext1) { incSlowly() }
             }
         }
     }
diff --git a/tracinglib/demo/src/com/android/app/tracing/demo/experiments/NestedLaunchesWithoutName.kt b/tracinglib/demo/src/com/android/app/tracing/demo/experiments/NestedLaunchesWithoutName.kt
index 0fa7333..913026b 100644
--- a/tracinglib/demo/src/com/android/app/tracing/demo/experiments/NestedLaunchesWithoutName.kt
+++ b/tracinglib/demo/src/com/android/app/tracing/demo/experiments/NestedLaunchesWithoutName.kt
@@ -29,7 +29,7 @@ class NestedLaunchesWithoutName
 @Inject
 constructor(
     @FixedThread1 private var fixedThreadContext1: CoroutineContext,
-    @FixedThread2 private var fixedThreadContext2: CoroutineContext
+    @FixedThread2 private var fixedThreadContext2: CoroutineContext,
 ) : Experiment {
     override fun getDescription(): String =
         "Nested launches in which only the leaf uses a trace name"
@@ -39,7 +39,7 @@ constructor(
             delay(10)
             launch(fixedThreadContext2) {
                 delay(10)
-                launch(fixedThreadContext1) { getNumber() }
+                launch(fixedThreadContext1) { incSlowly() }
             }
         }
     }
diff --git a/tracinglib/demo/src/com/android/app/tracing/demo/experiments/Util.kt b/tracinglib/demo/src/com/android/app/tracing/demo/experiments/Util.kt
index 4ef4f0e..f9638a8 100644
--- a/tracinglib/demo/src/com/android/app/tracing/demo/experiments/Util.kt
+++ b/tracinglib/demo/src/com/android/app/tracing/demo/experiments/Util.kt
@@ -15,30 +15,45 @@
  */
 package com.android.app.tracing.demo.experiments
 
-import com.android.app.tracing.coroutines.traceCoroutine
+import android.os.Trace
+import java.util.concurrent.Executors.newFixedThreadPool
 import java.util.concurrent.atomic.AtomicInteger
 import kotlin.coroutines.resume
-import kotlin.coroutines.suspendCoroutine
+import kotlinx.coroutines.suspendCancellableCoroutine
 
 private val counter = AtomicInteger()
 
 internal suspend fun doWork() {
-    getNumber(0, 50)
-    getNumber(50, 0)
-    getNumber(50, 50)
+    incSlowly(0, 50)
+    incSlowly(50, 0)
+    incSlowly(50, 50)
 }
 
+// BAD - wastefully use a thread pool for resuming continuations in a contrived manner
+val threadPoolForSleep = newFixedThreadPool(4)
+
 /**
  * A simple suspending function that returns a unique sequential number, ordered by when it was
  * originally called. It can optionally be used to simulate slow functions by sleeping before or
  * after the suspension point
  */
-suspend fun getNumber(delayBeforeSuspension: Long = 0, delayAfterSuspension: Long = 0): Int {
+@Suppress("BlockingMethodInNonBlockingContext")
+suspend fun incSlowly(delayBeforeSuspension: Long = 0, delayBeforeResume: Long = 0): Int {
     val num = counter.incrementAndGet()
-    traceCoroutine("getNumber#$num") {
-        Thread.sleep(delayBeforeSuspension) // BAD
-        return suspendCoroutine { continuation ->
-            Thread.sleep(delayAfterSuspension) // BAD
+    Trace.traceBegin(Trace.TRACE_TAG_APP, "inc#$num:sleep-before-suspend:$delayBeforeSuspension")
+    try {
+        Thread.sleep(delayBeforeSuspension) // BAD - sleep for demo purposes only
+    } finally {
+        Trace.traceEnd(Trace.TRACE_TAG_APP)
+    }
+    return suspendCancellableCoroutine { continuation ->
+        threadPoolForSleep.submit {
+            Trace.traceBegin(Trace.TRACE_TAG_APP, "inc#$num:sleep-before-resume:$delayBeforeResume")
+            try {
+                Thread.sleep(delayBeforeResume) // BAD - sleep for demo purposes only
+            } finally {
+                Trace.traceEnd(Trace.TRACE_TAG_APP)
+            }
             continuation.resume(num)
         }
     }
diff --git a/tracinglib/robolectric/Android.bp b/tracinglib/robolectric/Android.bp
new file mode 100644
index 0000000..f2d3640
--- /dev/null
+++ b/tracinglib/robolectric/Android.bp
@@ -0,0 +1,42 @@
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
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+android_app {
+    name: "tracinglib-test-app",
+    manifest: "app-manifest.xml",
+    platform_apis: true,
+}
+
+android_robolectric_test {
+    enabled: true,
+    name: "tracinglib-robo-test",
+    srcs: ["src/**/*.kt"],
+    java_resource_dirs: ["config"],
+    static_libs: [
+        "tracinglib-platform",
+        "flag-junit",
+    ],
+    libs: [
+        "androidx.test.core",
+        "androidx.test.runner",
+        "androidx.test.ext.junit",
+    ],
+    instrumentation_for: "tracinglib-test-app",
+    upstream: true,
+    strict_mode: false,
+}
diff --git a/tracinglib/robolectric/app-manifest.xml b/tracinglib/robolectric/app-manifest.xml
new file mode 100644
index 0000000..4094248
--- /dev/null
+++ b/tracinglib/robolectric/app-manifest.xml
@@ -0,0 +1,19 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!-- Copyright (C) 2024 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+-->
+
+<manifest xmlns:android="http://schemas.android.com/apk/res/android"
+          package="com.android.app.tracing.testapp">
+</manifest>
diff --git a/tracinglib/robolectric/config/robolectric.properties b/tracinglib/robolectric/config/robolectric.properties
new file mode 100644
index 0000000..d164b7c
--- /dev/null
+++ b/tracinglib/robolectric/config/robolectric.properties
@@ -0,0 +1,16 @@
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
+sdk=NEWEST_SDK
+looperMode=INSTRUMENTATION_TEST
\ No newline at end of file
diff --git a/tracinglib/robolectric/src/CoroutineTracingFlagsTest.kt b/tracinglib/robolectric/src/CoroutineTracingFlagsTest.kt
new file mode 100644
index 0000000..64726e1
--- /dev/null
+++ b/tracinglib/robolectric/src/CoroutineTracingFlagsTest.kt
@@ -0,0 +1,85 @@
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
+package com.android.app.tracing.coroutines
+
+import android.platform.test.annotations.DisableFlags
+import android.platform.test.annotations.EnableFlags
+import com.android.app.tracing.coroutines.util.FakeTraceState
+import com.android.systemui.Flags.FLAG_COROUTINE_TRACING
+import kotlinx.coroutines.withContext
+import org.junit.Assert.assertEquals
+import org.junit.Assert.assertFalse
+import org.junit.Assert.assertNotNull
+import org.junit.Assert.assertNull
+import org.junit.Assert.assertTrue
+import org.junit.Assert.fail
+import org.junit.Test
+
+class CoroutineTracingFlagsTest : TestBase() {
+
+    @DisableFlags(FLAG_COROUTINE_TRACING)
+    @Test
+    fun tracingDisabledWhenFlagIsOff() = runTest {
+        assertFalse(com.android.systemui.Flags.coroutineTracing())
+        assertNull(traceThreadLocal.get())
+        withContext(createCoroutineTracingContext()) {
+            assertNull(traceThreadLocal.get())
+            traceCoroutine("hello") { // should not crash
+                assertNull(traceThreadLocal.get())
+            }
+
+            // Change Trace.isEnabled() to false so that the lazy-String is not called for async
+            // tracing, which would be expected even when coroutine tracing is disabled.
+            FakeTraceState.isTracingEnabled = false
+
+            // Verify that the lazy-String is not called when tracing is disabled and feature flag
+            // is off
+            traceCoroutine({
+                fail("Lazy string should not be called when FLAG_COROUTINE_TRACING is disabled")
+                "error"
+            }) {
+                assertNull(traceThreadLocal.get())
+            }
+        }
+    }
+
+    @EnableFlags(FLAG_COROUTINE_TRACING)
+    @Test
+    fun lazyStringIsAlwaysCalledOnDebugBuilds() = runTest {
+        FakeTraceState.isTracingEnabled = false
+        assertNull(traceThreadLocal.get())
+        withContext(createCoroutineTracingContext()) {
+            assertNotNull(traceThreadLocal.get())
+
+            // It is expected that the lazy-String is called even when tracing is disabled because
+            // otherwise the coroutine resumption points would be missing names.
+            var lazyStringCalled = false
+            traceCoroutine({
+                lazyStringCalled = true
+                "hello"
+            }) {
+                assertTrue(
+                    "Lazy string should be been called when FLAG_COROUTINE_TRACING is enabled, " +
+                        "even when Trace.isEnabled()=false",
+                    lazyStringCalled,
+                )
+                val traceData = traceThreadLocal.get() as TraceData
+                assertEquals(traceData.slices?.size, 1)
+            }
+        }
+    }
+}
diff --git a/tracinglib/robolectric/src/CoroutineTracingTest.kt b/tracinglib/robolectric/src/CoroutineTracingTest.kt
new file mode 100644
index 0000000..483e51f
--- /dev/null
+++ b/tracinglib/robolectric/src/CoroutineTracingTest.kt
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
+package com.android.app.tracing.coroutines
+
+import android.platform.test.annotations.EnableFlags
+import com.android.systemui.Flags.FLAG_COROUTINE_TRACING
+import kotlinx.coroutines.delay
+import kotlinx.coroutines.launch
+import org.junit.Assert.assertEquals
+import org.junit.Test
+
+@EnableFlags(FLAG_COROUTINE_TRACING)
+class CoroutineTracingTest : TracingTestBase() {
+
+    @Test
+    fun simpleTraceSection() = runTestTraced {
+        expectD(1, "main:1^")
+        traceCoroutine("hello") { expectD(2, "main:1^", "hello") }
+        finish(3, "main:1^")
+    }
+
+    @Test
+    fun simpleNestedTraceSection() = runTestTraced {
+        expectD(1, "main:1^")
+        traceCoroutine("hello") {
+            expectD(2, "main:1^", "hello")
+            traceCoroutine("world") { expectD(3, "main:1^", "hello", "world") }
+            expectD(4, "main:1^", "hello")
+        }
+        finish(5, "main:1^")
+    }
+
+    @Test
+    fun simpleLaunch() = runTestTraced {
+        expectD(1, "main:1^")
+        traceCoroutine("hello") {
+            expectD(2, "main:1^", "hello")
+            launch {
+                // "hello" is not passed to child scope
+                finish(4, "main:1^:1^")
+            }
+        }
+        expect(3, "main:1^")
+    }
+
+    @Test
+    fun launchWithSuspendingLambda() = runTestTraced {
+        val fetchData: suspend () -> String = {
+            expect(3, "main:1^:1^span-for-launch")
+            delay(1L)
+            traceCoroutine("span-for-fetchData") {
+                expect(4, "main:1^:1^span-for-launch", "span-for-fetchData")
+            }
+            "stuff"
+        }
+        expect(1, "main:1^")
+        launch("span-for-launch") {
+            assertEquals("stuff", fetchData())
+            finish(5, "main:1^:1^span-for-launch")
+        }
+        expect(2, "main:1^")
+    }
+
+    @Test
+    fun launchInCoroutineScope() = runTestTraced {
+        launch("launch#0") {
+            expect("main:1^:1^launch#0")
+            delay(1)
+            expect("main:1^:1^launch#0")
+        }
+        coroutineScope("span-for-coroutineScope-1") {
+            launch("launch#1") {
+                expect("main:1^:2^launch#1")
+                delay(1)
+                expect("main:1^:2^launch#1")
+            }
+            launch("launch#2") {
+                expect("main:1^:3^launch#2")
+                delay(1)
+                expect("main:1^:3^launch#2")
+            }
+            coroutineScope("span-for-coroutineScope-2") {
+                launch("launch#3") {
+                    expect("main:1^:4^launch#3")
+                    delay(1)
+                    expect("main:1^:4^launch#3")
+                }
+                launch("launch#4") {
+                    expect("main:1^:5^launch#4")
+                    delay(1)
+                    expect("main:1^:5^launch#4")
+                }
+            }
+        }
+        launch("launch#5") {
+            expect("main:1^:6^launch#5")
+            delay(1)
+            expect("main:1^:6^launch#5")
+        }
+    }
+
+    @Test
+    fun namedScopeMerging() = runTestTraced {
+        // to avoid race conditions in the test leading to flakes, avoid calling expectD() or
+        // delaying before launching (e.g. only call expectD() in leaf blocks)
+        expect("main:1^")
+        launch("A") {
+            expect("main:1^:1^A")
+            traceCoroutine("span") { expectD("main:1^:1^A", "span") }
+            launch("B") { expectD("main:1^:1^A:1^B") }
+            launch("C") {
+                expect("main:1^:1^A:2^C")
+                launch { expectD("main:1^:1^A:2^C:1^") }
+                launch("D") { expectD("main:1^:1^A:2^C:2^D") }
+                launch("E") {
+                    expect("main:1^:1^A:2^C:3^E")
+                    launch("F") { expectD("main:1^:1^A:2^C:3^E:1^F") }
+                    expect("main:1^:1^A:2^C:3^E")
+                }
+            }
+            launch("G") { expectD("main:1^:1^A:3^G") }
+        }
+        launch { launch { launch { expectD("main:1^:2^:1^:1^") } } }
+        delay(2)
+        launch("H") { launch { launch { expectD("main:1^:3^H:1^:1^") } } }
+        delay(2)
+        launch {
+            launch {
+                launch {
+                    launch { launch { launch("I") { expectD("main:1^:4^:1^:1^:1^:1^:1^I") } } }
+                }
+            }
+        }
+        delay(2)
+        launch("J") { launch("K") { launch { launch { expectD("main:1^:5^J:1^K:1^:1^") } } } }
+        delay(2)
+        launch("L") { launch("M") { launch { launch { expectD("main:1^:6^L:1^M:1^:1^") } } } }
+        delay(2)
+        launch("N") { launch("O") { launch { launch("D") { expectD("main:1^:7^N:1^O:1^:1^D") } } } }
+        delay(2)
+        launch("P") { launch("Q") { launch { launch("R") { expectD("main:1^:8^P:1^Q:1^:1^R") } } } }
+        delay(2)
+        launch("S") { launch("T") { launch { expectD("main:1^:9^S:1^T:1^") } } }
+        delay(2)
+        launch("U") { launch("V") { launch { expectD("main:1^:10^U:1^V:1^") } } }
+        delay(2)
+        expectD("main:1^")
+    }
+
+    @Test
+    fun launchIntoSelf() = runTestTraced {
+        expectD("main:1^")
+        val reusedNameContext = nameCoroutine("my-coroutine")
+        launch(reusedNameContext) {
+            expectD("main:1^:1^my-coroutine")
+            launch(reusedNameContext) { expectD("main:1^:1^my-coroutine:1^my-coroutine") }
+            expectD("main:1^:1^my-coroutine")
+            launch(reusedNameContext) { expectD("main:1^:1^my-coroutine:2^my-coroutine") }
+            expectD("main:1^:1^my-coroutine")
+        }
+        launch(reusedNameContext) { expectD("main:1^:2^my-coroutine") }
+        expectD("main:1^")
+    }
+}
diff --git a/tracinglib/robolectric/src/FlowTracingTest.kt b/tracinglib/robolectric/src/FlowTracingTest.kt
new file mode 100644
index 0000000..4cb57c5
--- /dev/null
+++ b/tracinglib/robolectric/src/FlowTracingTest.kt
@@ -0,0 +1,147 @@
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
+package com.android.app.tracing.coroutines
+
+import android.platform.test.annotations.EnableFlags
+import com.android.app.tracing.coroutines.flow.collect
+import com.android.app.tracing.coroutines.flow.collectTraced
+import com.android.app.tracing.coroutines.flow.filter
+import com.android.app.tracing.coroutines.flow.flowOn
+import com.android.app.tracing.coroutines.flow.map
+import com.android.app.tracing.coroutines.flow.withTraceName
+import com.android.app.tracing.coroutines.util.ExampleClass
+import com.android.systemui.Flags.FLAG_COROUTINE_TRACING
+import kotlinx.coroutines.DelicateCoroutinesApi
+import kotlinx.coroutines.ExperimentalCoroutinesApi
+import kotlinx.coroutines.delay
+import kotlinx.coroutines.flow.MutableStateFlow
+import kotlinx.coroutines.flow.flowOf
+import kotlinx.coroutines.launch
+import kotlinx.coroutines.newFixedThreadPoolContext
+import kotlinx.coroutines.newSingleThreadContext
+import kotlinx.coroutines.withContext
+import org.junit.Assert.assertEquals
+import org.junit.Test
+
+@OptIn(DelicateCoroutinesApi::class, ExperimentalCoroutinesApi::class)
+@EnableFlags(FLAG_COROUTINE_TRACING)
+class FlowTracingTest : TracingTestBase() {
+
+    @Test
+    fun stateFlowCollection() = runTestTraced {
+        val state = MutableStateFlow(1)
+        val bgThreadPool = newFixedThreadPoolContext(2, "bg-pool")
+
+        // Inefficient fine-grained thread confinement
+        val counterThread = newSingleThreadContext("counter-thread")
+        var counter = 0
+        val incrementCounter: suspend () -> Unit = {
+            withContext("increment", counterThread) {
+                expectEndsWith("increment")
+                counter++
+            }
+        }
+
+        val helper = ExampleClass(this@FlowTracingTest, incrementCounter)
+        val collectJob =
+            launch("launch-for-collect", bgThreadPool) {
+                expect("main:1^:1^launch-for-collect")
+                launch {
+                    state.collect("state-flow") {
+                        expect(
+                            "main:1^:1^launch-for-collect:1^",
+                            "state-flow:collect",
+                            "state-flow:emit",
+                        )
+                        incrementCounter()
+                    }
+                }
+                launch {
+                    state.collectTraced {
+                        expect(
+                            "main:1^:1^launch-for-collect:2^",
+                            "com.android.app.tracing.coroutines.FlowTracingTest\$stateFlowCollection$1\$collectJob$1$2:collect",
+                            "com.android.app.tracing.coroutines.FlowTracingTest\$stateFlowCollection$1\$collectJob$1$2:emit",
+                        )
+                        incrementCounter()
+                    }
+                }
+                launch { state.collectTraced(helper::classMethod) }
+            }
+        val emitJob =
+            launch(newSingleThreadContext("emitter-thread")) {
+                for (n in 2..5) {
+                    delay(100)
+                    state.value = n
+                }
+            }
+        emitJob.join()
+        delay(10)
+        collectJob.cancel()
+        withContext(counterThread) { assertEquals(15, counter) }
+    }
+
+    @Test
+    fun flowOnWithTraceName() = runTestTraced {
+        val state =
+            flowOf(1, 2, 3, 4)
+                .withTraceName("my-flow")
+                .flowOn(newSingleThreadContext("flow-thread") + nameCoroutine("the-name"))
+        val bgThreadPool = newFixedThreadPoolContext(2, "bg-pool")
+        val collectJob =
+            launch("launch-for-collect", bgThreadPool) {
+                expect("main:1^:1^launch-for-collect")
+                launch {
+                    state.collect("state-flow") {
+                        expect(
+                            "main:1^:1^launch-for-collect:1^",
+                            "state-flow:collect",
+                            "flowOn(the-name):collect",
+                            "flowOn(the-name):emit",
+                            "state-flow:emit",
+                        )
+                    }
+                }
+            }
+        collectJob.join()
+    }
+
+    @Test
+    fun mapAndFilter() = runTestTraced {
+        val state =
+            flowOf(1, 2, 3, 4)
+                .withTraceName("my-flow")
+                .map("multiply-by-3") { it * 2 }
+                .filter("mod-2") { it % 2 == 0 }
+        launch("launch-for-collect") {
+                state.collect("my-collect-call") {
+                    expect(
+                        "main:1^:1^launch-for-collect",
+                        "my-collect-call:collect",
+                        "mod-2:collect",
+                        "multiply-by-3:collect",
+                        "my-flow:collect",
+                        "my-flow:emit",
+                        "multiply-by-3:emit",
+                        "mod-2:emit",
+                        "my-collect-call:emit",
+                    )
+                }
+            }
+            .join()
+    }
+}
diff --git a/tracinglib/robolectric/src/MultiThreadedCoroutineTracingTest.kt b/tracinglib/robolectric/src/MultiThreadedCoroutineTracingTest.kt
new file mode 100644
index 0000000..c7d432b
--- /dev/null
+++ b/tracinglib/robolectric/src/MultiThreadedCoroutineTracingTest.kt
@@ -0,0 +1,425 @@
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
+package com.android.app.tracing.coroutines
+
+import android.os.HandlerThread
+import android.platform.test.annotations.EnableFlags
+import com.android.systemui.Flags.FLAG_COROUTINE_TRACING
+import java.util.concurrent.CyclicBarrier
+import java.util.concurrent.Executors
+import java.util.concurrent.TimeUnit
+import kotlin.coroutines.EmptyCoroutineContext
+import kotlinx.coroutines.CoroutineStart
+import kotlinx.coroutines.DelicateCoroutinesApi
+import kotlinx.coroutines.Dispatchers
+import kotlinx.coroutines.ExperimentalCoroutinesApi
+import kotlinx.coroutines.android.asCoroutineDispatcher
+import kotlinx.coroutines.channels.Channel
+import kotlinx.coroutines.delay
+import kotlinx.coroutines.launch
+import kotlinx.coroutines.newSingleThreadContext
+import kotlinx.coroutines.withContext
+import org.junit.Assert.assertArrayEquals
+import org.junit.Assert.assertEquals
+import org.junit.Assert.assertNotEquals
+import org.junit.Assert.assertNotNull
+import org.junit.Assert.assertNotSame
+import org.junit.Assert.assertNull
+import org.junit.Assert.assertSame
+import org.junit.Ignore
+import org.junit.Test
+
+@OptIn(ExperimentalCoroutinesApi::class, DelicateCoroutinesApi::class)
+@EnableFlags(FLAG_COROUTINE_TRACING)
+class MultiThreadedCoroutineTracingTest : TracingTestBase() {
+    @Test
+    fun nestedUpdateAndRestoreOnSingleThread_unconfinedDispatcher() = runTestTraced {
+        traceCoroutine("parent-span") {
+            expect(1, "main:1^", "parent-span")
+            launch(Dispatchers.Unconfined) {
+                // This may appear unusual, but it is expected behavior:
+                //   1) The parent has an open trace section called "parent-span".
+                //   2) The child launches, derives a new scope name from its parent, and resumes
+                //      immediately due to its use of the unconfined dispatcher.
+                //   3) The child emits all the trace sections known to its scope. The parent
+                //      does not have an opportunity to restore its context yet.
+                //   4) After the suspension point, the parent restores its context, and the
+                //      child
+                //
+                // [parent's active trace sections]
+                //               /           \      [new trace section for child scope]
+                //              /             \                \
+                expect(2, "main:1^", "parent-span", "main:1^:1^")
+                traceCoroutine("child-span") {
+                    expect(3, "main:1^", "parent-span", "main:1^:1^", "child-span")
+                    delay(1) // <-- delay will give parent a chance to restore its context
+                    // After a delay, the parent resumes, finishing its trace section, so we are
+                    // left with only those in the child's scope
+                    finish(5, "main:1^:1^", "child-span")
+                }
+            }
+        }
+        expect(4, "main:1^") // <-- because of the delay above, this is not the last event
+    }
+
+    /** @see nestedUpdateAndRestoreOnSingleThread_unconfinedDispatcher */
+    @Test
+    fun nestedUpdateAndRestoreOnSingleThread_undispatchedLaunch() = runTestTraced {
+        traceCoroutine("parent-span") {
+            launch(start = CoroutineStart.UNDISPATCHED) {
+                traceCoroutine("child-span") {
+                    expect(1, "main:1^", "parent-span", "main:1^:1^", "child-span")
+                    delay(1) // <-- delay will give parent a chance to restore its context
+                    finish(3, "main:1^:1^", "child-span")
+                }
+            }
+        }
+        expect(2, "main:1^")
+    }
+
+    @Test
+    fun launchOnSeparateThread_defaultDispatcher() = runTestTraced {
+        val channel = Channel<Int>()
+        val thread1 = newSingleThreadContext("thread-#1")
+        expect("main:1^")
+        traceCoroutine("hello") {
+            expect(1, "main:1^", "hello")
+            launch(thread1) {
+                expect(2, "main:1^:1^")
+                traceCoroutine("world") {
+                    expect("main:1^:1^", "world")
+                    channel.send(1)
+                    expect(3, "main:1^:1^", "world")
+                }
+            }
+            expect("main:1^", "hello")
+        }
+        expect("main:1^")
+        assertEquals(1, channel.receive())
+        finish(4, "main:1^")
+    }
+
+    @Test
+    fun testTraceStorage() = runTestTraced {
+        val thread1 = newSingleThreadContext("thread-#1")
+        val thread2 = newSingleThreadContext("thread-#2")
+        val thread3 = newSingleThreadContext("thread-#3")
+        val thread4 = newSingleThreadContext("thread-#4")
+        val channel = Channel<Int>()
+        val threadContexts = listOf(thread1, thread2, thread3, thread4)
+        val finishedLaunches = Channel<Int>()
+        // Start 1000 coroutines waiting on [channel]
+        val job = launch {
+            repeat(1000) {
+                launch("span-for-launch", threadContexts[it % threadContexts.size]) {
+                    assertNotNull(traceThreadLocal.get())
+                    traceCoroutine("span-for-fetchData") {
+                        channel.receive()
+                        expectEndsWith("span-for-fetchData")
+                    }
+                    assertNotNull(traceThreadLocal.get())
+                    finishedLaunches.send(it)
+                }
+                expect("main:1^:1^")
+            }
+        }
+        // Resume half the coroutines that are waiting on this channel
+        repeat(500) { channel.send(1) }
+        var receivedClosures = 0
+        repeat(500) {
+            finishedLaunches.receive()
+            receivedClosures++
+        }
+        // ...and cancel the rest
+        job.cancel()
+    }
+
+    @Test
+    fun nestedTraceSectionsMultiThreaded() = runTestTraced {
+        val context1 = newSingleThreadContext("thread-#1") + nameCoroutine("coroutineA")
+        val context2 = newSingleThreadContext("thread-#2") + nameCoroutine("coroutineB")
+        val context3 = context1 + nameCoroutine("coroutineC")
+
+        launch("launch#1", context1) {
+            expect("main:1^:1^coroutineA")
+            delay(1L)
+            traceCoroutine("span-1") { expect("main:1^:1^coroutineA", "span-1") }
+            expect("main:1^:1^coroutineA")
+            expect("main:1^:1^coroutineA")
+            launch("launch#2", context2) {
+                expect("main:1^:1^coroutineA:1^coroutineB")
+                delay(1L)
+                traceCoroutine("span-2") { expect("main:1^:1^coroutineA:1^coroutineB", "span-2") }
+                expect("main:1^:1^coroutineA:1^coroutineB")
+                expect("main:1^:1^coroutineA:1^coroutineB")
+                launch("launch#3", context3) {
+                    // "launch#3" is dropped because context has a TraceContextElement.
+                    // The CoroutineScope (i.e. `this` in `this.launch {}`) should have a
+                    // TraceContextElement, but using TraceContextElement in the passed context is
+                    // incorrect.
+                    expect("main:1^:1^coroutineA:1^coroutineB:1^coroutineC")
+                    launch("launch#4", context1) {
+                        expect("main:1^:1^coroutineA:1^coroutineB:1^coroutineC:1^coroutineA")
+                    }
+                }
+            }
+            expect("main:1^:1^coroutineA")
+        }
+        expect("main:1^")
+
+        // Launching without the trace extension won't result in traces
+        launch(context1) { expect("main:1^:2^coroutineA") }
+        launch(context2) { expect("main:1^:3^coroutineB") }
+    }
+
+    @Test
+    fun missingTraceContextObjects() = runTest {
+        val channel = Channel<Int>()
+        val context1 = newSingleThreadContext("thread-#1")
+        val context2 = newSingleThreadContext("thread-#2") + mainTraceContext
+
+        launch("launch#1", context1) {
+            expect()
+            channel.receive()
+            traceCoroutine("span-1") { expect() }
+            expect()
+            launch("launch#2", context2) {
+                // "launch#2" is not traced because TraceContextElement was installed too
+                // late; it is not part of the scope that was launched (i.e., the `this` in
+                // `this.launch {}`)
+                expect("main:1^")
+                channel.receive()
+                traceCoroutine("span-2") { expect("main:1^", "span-2") }
+                expect("main:1^")
+                launch {
+                    // ...it won't appear in the child scope either because in launch("string"), it
+                    // adds: `CoroutineTraceName` + `TraceContextElement`. This demonstrates why
+                    // it is important to only use `TraceContextElement` in the root scope. In this
+                    // case, the `TraceContextElement`  overwrites the name, so the name is dropped.
+                    // Tracing still works with a default, empty name, however.
+                    expect("main:1^:1^")
+                }
+            }
+            expect()
+        }
+        expect()
+
+        channel.send(1)
+        channel.send(2)
+
+        launch(context1) { expect() }
+        launch(context2) { expect("main:2^") }
+    }
+
+    /**
+     * Tests interleaving:
+     * ```
+     * Thread #1 | [updateThreadContext]....^              [restoreThreadContext]
+     * --------------------------------------------------------------------------------------------
+     * Thread #2 |                           [updateThreadContext]...........^[restoreThreadContext]
+     * ```
+     *
+     * This test checks for issues with concurrent modification of the trace state. For example, the
+     * test should fail if [TraceData.endAllOnThread] uses the size of the slices array as follows
+     * instead of using the ThreadLocal count:
+     * ```
+     * class TraceData {
+     *   ...
+     *   fun endAllOnThread() {
+     *     repeat(slices.size) {
+     *       // THIS WOULD BE AN ERROR. If the thread is slow, the TraceData object could have been
+     *       // modified by another thread
+     *       endSlice()
+     *     }
+     *   ...
+     *   }
+     * }
+     * ```
+     */
+    @Test
+    fun coroutineMachinery() {
+        assertNull(traceThreadLocal.get())
+
+        val thread1ResumptionPoint = CyclicBarrier(2)
+        val thread1SuspensionPoint = CyclicBarrier(2)
+
+        val thread1 = Executors.newSingleThreadExecutor()
+        val thread2 = Executors.newSingleThreadExecutor()
+        val slicesForThread1 = listOf("a", "c", "e", "g")
+        val slicesForThread2 = listOf("b", "d", "f", "h")
+        var failureOnThread1: Error? = null
+        var failureOnThread2: Error? = null
+
+        val expectedTraceForThread1 = arrayOf("1:a", "2:b", "1:c", "2:d", "1:e", "2:f", "1:g")
+
+        val traceContext = mainTraceContext as TraceContextElement
+        thread1.execute {
+            try {
+                slicesForThread1.forEachIndexed { index, sliceName ->
+                    assertNull(traceThreadLocal.get())
+                    val oldTrace = traceContext.updateThreadContext(EmptyCoroutineContext)
+                    // await() AFTER updateThreadContext, thus thread #1 always resumes the
+                    // coroutine before thread #2
+                    assertSame(traceThreadLocal.get(), traceContext.contextTraceData)
+
+                    // coroutine body start {
+                    (traceThreadLocal.get() as TraceData).beginSpan("1:$sliceName")
+
+                    // At the end, verify the interleaved trace sections look correct:
+                    if (index == slicesForThread1.size - 1) {
+                        expect(*expectedTraceForThread1)
+                    }
+
+                    // simulate a slow thread, wait to call restoreThreadContext until after thread
+                    // A
+                    // has resumed
+                    thread1SuspensionPoint.await(3, TimeUnit.SECONDS)
+                    Thread.sleep(500)
+                    // } coroutine body end
+
+                    traceContext.restoreThreadContext(EmptyCoroutineContext, oldTrace)
+                    thread1ResumptionPoint.await(3, TimeUnit.SECONDS)
+                    assertNull(traceThreadLocal.get())
+                }
+            } catch (e: Error) {
+                failureOnThread1 = e
+            }
+        }
+
+        val expectedTraceForThread2 =
+            arrayOf("1:a", "2:b", "1:c", "2:d", "1:e", "2:f", "1:g", "2:h")
+        thread2.execute {
+            try {
+                slicesForThread2.forEachIndexed { i, n ->
+                    assertNull(traceThreadLocal.get())
+                    thread1SuspensionPoint.await(3, TimeUnit.SECONDS)
+
+                    val oldTrace = traceContext.updateThreadContext(EmptyCoroutineContext)
+
+                    // coroutine body start {
+                    (traceThreadLocal.get() as TraceData).beginSpan("2:$n")
+
+                    // At the end, verify the interleaved trace sections look correct:
+                    if (i == slicesForThread2.size - 1) {
+                        expect(*expectedTraceForThread2)
+                    }
+                    // } coroutine body end
+
+                    traceContext.restoreThreadContext(EmptyCoroutineContext, oldTrace)
+                    thread1ResumptionPoint.await(3, TimeUnit.SECONDS)
+                    assertNull(traceThreadLocal.get())
+                }
+            } catch (e: Error) {
+                failureOnThread2 = e
+            }
+        }
+
+        thread1.shutdown()
+        thread1.awaitTermination(5, TimeUnit.SECONDS)
+        thread2.shutdown()
+        thread2.awaitTermination(5, TimeUnit.SECONDS)
+
+        assertNull("Failure executing coroutine on thread-#1.", failureOnThread1)
+        assertNull("Failure executing coroutine on thread-#2.", failureOnThread2)
+    }
+
+    @Test
+    fun scopeReentry_withContextFastPath() = runTestTraced {
+        val thread1 = newSingleThreadContext("thread-#1")
+        val channel = Channel<Int>()
+        val job =
+            launch("#1", thread1) {
+                expect("main:1^:1^#1")
+                var i = 0
+                while (true) {
+                    expect("main:1^:1^#1")
+                    channel.send(i++)
+                    expect("main:1^:1^#1")
+                    // when withContext is passed the same scope, it takes a fast path, dispatching
+                    // immediately. This means that in subsequent loops, if we do not handle reentry
+                    // correctly in TraceContextElement, the trace may become deeply nested:
+                    // "#1", "#1", "#1", ... "#2"
+                    withContext(thread1) {
+                        expect("main:1^:1^#1")
+                        traceCoroutine("#2") {
+                            expect("main:1^:1^#1", "#2")
+                            channel.send(i++)
+                            expect("main:1^:1^#1", "#2")
+                        }
+                        expect("main:1^:1^#1")
+                    }
+                }
+            }
+        repeat(1000) {
+            expect("main:1^")
+            traceCoroutine("receive") {
+                expect("main:1^", "receive")
+                val receivedVal = channel.receive()
+                assertEquals(it, receivedVal)
+                expect("main:1^", "receive")
+            }
+            expect("main:1^")
+        }
+        job.cancel()
+    }
+
+    @Test
+    fun traceContextIsCopied() = runTest {
+        expect()
+        val traceContext = mainTraceContext as TraceContextElement
+        withContext(traceContext) {
+            // Not the same object because it should be copied into the current context
+            assertNotSame(traceThreadLocal.get(), traceContext.contextTraceData)
+            // slices is lazily created, so it should be null:
+            assertNull((traceThreadLocal.get() as TraceData).slices)
+            assertNull(traceContext.contextTraceData?.slices)
+            expect("main:1^")
+            traceCoroutine("hello") {
+                assertNotSame(traceThreadLocal.get(), traceContext.contextTraceData)
+                assertArrayEquals(
+                    arrayOf("hello"),
+                    (traceThreadLocal.get() as TraceData).slices?.toArray(),
+                )
+                assertNull(traceContext.contextTraceData?.slices)
+            }
+            assertNotSame(traceThreadLocal.get(), traceContext.contextTraceData)
+            // Because slices is lazily created, it will no longer be null after it was used to
+            // trace "hello", but this time it will be empty
+            assertArrayEquals(arrayOf(), (traceThreadLocal.get() as TraceData).slices?.toArray())
+            assertNull(traceContext.contextTraceData?.slices)
+            expect("main:1^")
+        }
+        expect()
+    }
+
+    @Ignore("Fails with java.net.SocketTimeoutException: Read timed out")
+    @Test
+    fun testHandlerDispatcher() = runTest {
+        val handlerThread = HandlerThread("test-handler-thread")
+        handlerThread.start()
+        val dispatcher = handlerThread.threadHandler.asCoroutineDispatcher()
+        val previousThread = Thread.currentThread().id
+        launch(dispatcher) {
+            val currentThreadBeforeDelay = Thread.currentThread().id
+            delay(1)
+            assertEquals(currentThreadBeforeDelay, Thread.currentThread().id)
+            assertNotEquals(previousThread, currentThreadBeforeDelay)
+            delay(1)
+            assertEquals(currentThreadBeforeDelay, Thread.currentThread().id)
+        }
+    }
+}
diff --git a/tracinglib/robolectric/src/TestBase.kt b/tracinglib/robolectric/src/TestBase.kt
new file mode 100644
index 0000000..0eab0d1
--- /dev/null
+++ b/tracinglib/robolectric/src/TestBase.kt
@@ -0,0 +1,235 @@
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
+package com.android.app.tracing.coroutines
+
+import android.platform.test.flag.junit.SetFlagsRule
+import android.util.Log
+import androidx.test.ext.junit.runners.AndroidJUnit4
+import com.android.app.tracing.coroutines.util.FakeTraceState
+import com.android.app.tracing.coroutines.util.FakeTraceState.getOpenTraceSectionsOnCurrentThread
+import com.android.app.tracing.coroutines.util.ShadowTrace
+import java.util.concurrent.atomic.AtomicInteger
+import kotlin.coroutines.CoroutineContext
+import kotlin.coroutines.EmptyCoroutineContext
+import kotlinx.coroutines.CoroutineScope
+import kotlinx.coroutines.delay
+import kotlinx.coroutines.runBlocking
+import org.junit.After
+import org.junit.Before
+import org.junit.ClassRule
+import org.junit.Rule
+import org.junit.runner.RunWith
+import org.robolectric.annotation.Config
+
+@RunWith(AndroidJUnit4::class)
+@Config(shadows = [ShadowTrace::class])
+open class TestBase {
+
+    companion object {
+        @JvmField
+        @ClassRule
+        val setFlagsClassRule: SetFlagsRule.ClassRule = SetFlagsRule.ClassRule()
+    }
+
+    @JvmField @Rule val setFlagsRule = SetFlagsRule()
+
+    private var skipAfterCheck = false
+
+    @Before
+    fun setup() {
+        STRICT_MODE_FOR_TESTING = true
+        FakeTraceState.isTracingEnabled = true
+        eventCounter.set(0)
+        skipAfterCheck = false
+    }
+
+    @After
+    fun tearDown() {
+        if (skipAfterCheck) return
+        val lastEvent = eventCounter.get()
+        check(lastEvent == FINAL_EVENT || lastEvent == 0) {
+            "Expected `finish(${lastEvent + 1})` to be called, but the test finished"
+        }
+    }
+
+    protected fun runTest(
+        context: CoroutineContext = EmptyCoroutineContext,
+        block: suspend CoroutineScope.() -> Unit,
+    ) {
+        runBlocking(context, block)
+    }
+
+    /**
+     * Same as [expect], but also call [delay] for 1ms, calling [expect] before and after the
+     * suspension point.
+     */
+    protected suspend fun expectD(vararg expectedOpenTraceSections: String) {
+        expectD(null, *expectedOpenTraceSections)
+    }
+
+    /**
+     * Same as [expect], but also call [delay] for 1ms, calling [expect] before and after the
+     * suspension point.
+     */
+    protected suspend fun expectD(
+        expectedEvent: Int? = null,
+        vararg expectedOpenTraceSections: String,
+    ) {
+        expect(expectedEvent, *expectedOpenTraceSections)
+        delay(1)
+        expect(*expectedOpenTraceSections)
+    }
+
+    internal fun expect(vararg expectedOpenTraceSections: String) {
+        expect(null, *expectedOpenTraceSections)
+    }
+
+    protected fun expectEndsWith(vararg expectedOpenTraceSections: String) {
+        try {
+            // Inspect trace output to the fake used for recording android.os.Trace API calls:
+            val actualSections = getOpenTraceSectionsOnCurrentThread()
+            check(expectedOpenTraceSections.size <= actualSections.size)
+            val lastSections =
+                actualSections.takeLast(expectedOpenTraceSections.size).toTypedArray()
+            assertTraceSectionsEquals(expectedOpenTraceSections, lastSections)
+        } catch (e: IllegalStateException) {
+            skipAfterCheck = true
+        }
+    }
+
+    /**
+     * Checks the currently active trace sections on the current thread, and optionally checks the
+     * order of operations if [expectedEvent] is not null.
+     */
+    protected fun expect(expectedEvent: Int? = null, vararg expectedOpenTraceSections: String) {
+        try {
+            expectInternal(expectedEvent, *expectedOpenTraceSections)
+        } catch (e: IllegalStateException) {
+            skipAfterCheck = true
+            throw e
+        }
+    }
+
+    private fun expectInternal(
+        expectedEvent: Int? = null,
+        vararg expectedOpenTraceSections: String,
+    ) {
+        if (expectedEvent != null) {
+            val previousEvent = eventCounter.getAndAdd(1)
+            val currentEvent = previousEvent + 1
+            check(expectedEvent == currentEvent) {
+                if (previousEvent == FINAL_EVENT) {
+                    "Expected event=$expectedEvent, but finish() was already called"
+                } else {
+                    "Expected event=$expectedEvent," +
+                        " but the event counter is currently at $currentEvent"
+                }
+            }
+        }
+
+        // Inspect trace output to the fake used for recording android.os.Trace API calls:
+        assertTraceSectionsEquals(expectedOpenTraceSections, getOpenTraceSectionsOnCurrentThread())
+    }
+
+    private fun assertTraceSectionsEquals(
+        expectedOpenTraceSections: Array<out String>,
+        actualOpenSections: Array<String>,
+    ) {
+        val expectedSize = expectedOpenTraceSections.size
+        val actualSize = actualOpenSections.size
+        check(expectedSize == actualSize) {
+            createFailureMessage(
+                expectedOpenTraceSections,
+                actualOpenSections,
+                "Size mismatch, expected size $expectedSize but was size $actualSize",
+            )
+        }
+        expectedOpenTraceSections.forEachIndexed { n, expectedTrace ->
+            val actualTrace = actualOpenSections[n]
+            val expected = expectedTrace.substringBefore(";")
+            val actual = actualTrace.substringBefore(";")
+            check(expected == actual) {
+                createFailureMessage(
+                    expectedOpenTraceSections,
+                    actualOpenSections,
+                    "Differed at index #$n, expected \"$expected\" but was \"$actual\"",
+                )
+            }
+        }
+    }
+
+    private fun createFailureMessage(
+        expectedOpenTraceSections: Array<out String>,
+        actualOpenSections: Array<String>,
+        extraMessage: String,
+    ): String =
+        """
+                Incorrect trace sections found on current thread:
+                  Expected : {${expectedOpenTraceSections.prettyPrintList()}}
+                  Actual   : {${actualOpenSections.prettyPrintList()}}
+                  $extraMessage
+                """
+            .trimIndent()
+
+    /** Same as [expect], except that no more [expect] statements can be called after it. */
+    protected fun finish(expectedEvent: Int, vararg expectedOpenTraceSections: String) {
+        try {
+            finishInternal(expectedEvent, *expectedOpenTraceSections)
+        } catch (e: IllegalStateException) {
+            skipAfterCheck = true
+            throw e
+        }
+    }
+
+    private fun finishInternal(expectedEvent: Int, vararg expectedOpenTraceSections: String) {
+        val previousEvent = eventCounter.getAndSet(FINAL_EVENT)
+        val currentEvent = previousEvent + 1
+        check(expectedEvent == currentEvent) {
+            if (previousEvent == FINAL_EVENT) {
+                "finish() was called more than once"
+            } else {
+                "Finished with event=$expectedEvent," +
+                    " but the event counter is currently $currentEvent"
+            }
+        }
+
+        // Inspect trace output to the fake used for recording android.os.Trace API calls:
+        assertTraceSectionsEquals(expectedOpenTraceSections, getOpenTraceSectionsOnCurrentThread())
+    }
+
+    private val eventCounter = AtomicInteger(0)
+}
+
+private const val FINAL_EVENT = Int.MIN_VALUE
+
+private fun Array<out String>.prettyPrintList(): String {
+    return toList().joinToString(separator = "\", \"", prefix = "\"", postfix = "\"") {
+        it.substringBefore(";")
+    }
+}
+
+private fun check(value: Boolean, lazyMessage: () -> String) {
+    if (DEBUG_TEST) {
+        if (!value) {
+            Log.e("TestBase", lazyMessage(), Throwable())
+        }
+    } else {
+        kotlin.check(value, lazyMessage)
+    }
+}
+
+private const val DEBUG_TEST = false
diff --git a/tracinglib/robolectric/src/TracingTestBase.kt b/tracinglib/robolectric/src/TracingTestBase.kt
new file mode 100644
index 0000000..9ace6b4
--- /dev/null
+++ b/tracinglib/robolectric/src/TracingTestBase.kt
@@ -0,0 +1,38 @@
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
+package com.android.app.tracing.coroutines
+
+import android.platform.test.annotations.EnableFlags
+import com.android.systemui.Flags.FLAG_COROUTINE_TRACING
+import kotlin.coroutines.CoroutineContext
+import kotlinx.coroutines.CoroutineScope
+import org.junit.Before
+
+@EnableFlags(FLAG_COROUTINE_TRACING)
+open class TracingTestBase : TestBase() {
+
+    protected lateinit var mainTraceContext: CoroutineContext
+
+    @Before
+    fun setupContexts() {
+        mainTraceContext = createCoroutineTracingContext("main")
+    }
+
+    protected fun runTestTraced(block: suspend CoroutineScope.() -> Unit) {
+        runTest(mainTraceContext, block)
+    }
+}
diff --git a/tracinglib/robolectric/src/util/ExampleClass.kt b/tracinglib/robolectric/src/util/ExampleClass.kt
new file mode 100644
index 0000000..e0f9a25
--- /dev/null
+++ b/tracinglib/robolectric/src/util/ExampleClass.kt
@@ -0,0 +1,34 @@
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
+package com.android.app.tracing.coroutines.util
+
+import com.android.app.tracing.coroutines.TestBase
+
+class ExampleClass(
+    private val testBase: TestBase,
+    private val incrementCounter: suspend () -> Unit,
+) {
+    suspend fun classMethod(value: Int) {
+        value.inc() // <-- suppress warning that parameter 'value' is unused
+        testBase.expect(
+            "main:1^:1^launch-for-collect:3^",
+            "com.android.app.tracing.coroutines.FlowTracingTest\$stateFlowCollection$1\$collectJob$1$3:collect",
+            "com.android.app.tracing.coroutines.FlowTracingTest\$stateFlowCollection$1\$collectJob$1$3:emit",
+        )
+        incrementCounter()
+    }
+}
diff --git a/tracinglib/core/host/src-fake/TraceProxy.fake.kt b/tracinglib/robolectric/src/util/FakeTraceState.kt
similarity index 52%
rename from tracinglib/core/host/src-fake/TraceProxy.fake.kt
rename to tracinglib/robolectric/src/util/FakeTraceState.kt
index 1bb9591..476ee8d 100644
--- a/tracinglib/core/host/src-fake/TraceProxy.fake.kt
+++ b/tracinglib/robolectric/src/util/FakeTraceState.kt
@@ -14,34 +14,18 @@
  * limitations under the License.
  */
 
-package com.android.app.tracing
+package com.android.app.tracing.coroutines.util
 
 import org.junit.Assert.assertFalse
 
-const val DEBUG = false
-
-/** Log a message with a tag indicating the current thread ID */
-private fun debug(message: String) {
-    if (DEBUG) println("Thread #${Thread.currentThread().id}: $message")
-}
-
-@PublishedApi
-internal actual fun isEnabled(): Boolean {
-    return true
-}
-
-val traceCounters = mutableMapOf<String, Int>()
-
-internal actual fun traceCounter(counterName: String, counterValue: Int) {
-    traceCounters[counterName] = counterValue
-}
-
 object FakeTraceState {
 
+    var isTracingEnabled: Boolean = true
+
     private val allThreadStates = hashMapOf<Long, MutableList<String>>()
 
     fun begin(sectionName: String) {
-        val threadId = Thread.currentThread().id
+        val threadId = currentThreadId()
         synchronized(allThreadStates) {
             if (allThreadStates.containsKey(threadId)) {
                 allThreadStates[threadId]!!.add(sectionName)
@@ -52,12 +36,12 @@ object FakeTraceState {
     }
 
     fun end() {
-        val threadId = Thread.currentThread().id
+        val threadId = currentThreadId()
         synchronized(allThreadStates) {
             assertFalse(
                 "Attempting to close trace section on thread=$threadId, " +
                     "but there are no open sections",
-                allThreadStates[threadId].isNullOrEmpty()
+                allThreadStates[threadId].isNullOrEmpty(),
             )
             // TODO: Replace with .removeLast() once available
             allThreadStates[threadId]!!.removeAt(allThreadStates[threadId]!!.lastIndex)
@@ -65,7 +49,7 @@ object FakeTraceState {
     }
 
     fun getOpenTraceSectionsOnCurrentThread(): Array<String> {
-        val threadId = Thread.currentThread().id
+        val threadId = currentThreadId()
         synchronized(allThreadStates) {
             return allThreadStates[threadId]?.toTypedArray() ?: emptyArray()
         }
@@ -85,41 +69,3 @@ object FakeTraceState {
         return sb.toString()
     }
 }
-
-internal actual fun traceBegin(methodName: String) {
-    debug("traceBegin: name=$methodName")
-    FakeTraceState.begin(methodName)
-}
-
-internal actual fun traceEnd() {
-    debug("traceEnd")
-    FakeTraceState.end()
-}
-
-internal actual fun asyncTraceBegin(methodName: String, cookie: Int) {
-    debug("asyncTraceBegin: name=$methodName cookie=${cookie.toHexString()}")
-}
-
-internal actual fun asyncTraceEnd(methodName: String, cookie: Int) {
-    debug("asyncTraceEnd: name=$methodName cookie=${cookie.toHexString()}")
-}
-
-@PublishedApi
-internal actual fun asyncTraceForTrackBegin(trackName: String, methodName: String, cookie: Int) {
-    debug(
-        "asyncTraceForTrackBegin: track=$trackName name=$methodName cookie=${cookie.toHexString()}"
-    )
-}
-
-@PublishedApi
-internal actual fun asyncTraceForTrackEnd(trackName: String, methodName: String, cookie: Int) {
-    debug("asyncTraceForTrackEnd: track=$trackName name=$methodName cookie=${cookie.toHexString()}")
-}
-
-internal actual fun instant(eventName: String) {
-    debug("instant: name=$eventName")
-}
-
-internal actual fun instantForTrack(trackName: String, eventName: String) {
-    debug("instantForTrack: track=$trackName name=$eventName")
-}
diff --git a/tracinglib/robolectric/src/util/ShadowTrace.kt b/tracinglib/robolectric/src/util/ShadowTrace.kt
new file mode 100644
index 0000000..11f8ecd
--- /dev/null
+++ b/tracinglib/robolectric/src/util/ShadowTrace.kt
@@ -0,0 +1,92 @@
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
+package com.android.app.tracing.coroutines.util
+
+import android.os.Trace
+import org.robolectric.annotation.Implementation
+import org.robolectric.annotation.Implements
+
+@OptIn(ExperimentalStdlibApi::class)
+@Suppress("unused_parameter")
+@Implements(Trace::class)
+object ShadowTrace {
+
+    @Implementation
+    @JvmStatic
+    fun isEnabled(): Boolean {
+        return FakeTraceState.isTracingEnabled
+    }
+
+    @Implementation
+    @JvmStatic
+    fun traceBegin(traceTag: Long, methodName: String) {
+        debugLog("traceBegin: name=$methodName")
+        FakeTraceState.begin(methodName)
+    }
+
+    @Implementation
+    @JvmStatic
+    fun traceEnd(traceTag: Long) {
+        debugLog("traceEnd")
+        FakeTraceState.end()
+    }
+
+    @Implementation
+    @JvmStatic
+    fun asyncTraceBegin(traceTag: Long, methodName: String, cookie: Int) {
+        debugLog("asyncTraceBegin: name=$methodName cookie=${cookie.toHexString()}")
+    }
+
+    @Implementation
+    @JvmStatic
+    fun asyncTraceEnd(traceTag: Long, methodName: String, cookie: Int) {
+        debugLog("asyncTraceEnd: name=$methodName cookie=${cookie.toHexString()}")
+    }
+
+    @Implementation
+    @JvmStatic
+    fun asyncTraceForTrackBegin(
+        traceTag: Long,
+        trackName: String,
+        methodName: String,
+        cookie: Int,
+    ) {
+        debugLog(
+            "asyncTraceForTrackBegin: track=$trackName name=$methodName cookie=${cookie.toHexString()}"
+        )
+    }
+
+    @Implementation
+    @JvmStatic
+    fun asyncTraceForTrackEnd(traceTag: Long, trackName: String, methodName: String, cookie: Int) {
+        debugLog(
+            "asyncTraceForTrackEnd: track=$trackName name=$methodName cookie=${cookie.toHexString()}"
+        )
+    }
+
+    @Implementation
+    @JvmStatic
+    fun instant(traceTag: Long, eventName: String) {
+        debugLog("instant: name=$eventName")
+    }
+
+    @Implementation
+    @JvmStatic
+    fun instantForTrack(traceTag: Long, trackName: String, eventName: String) {
+        debugLog("instantForTrack: track=$trackName name=$eventName")
+    }
+}
diff --git a/tracinglib/core/host/src-fake/Log.fake.kt b/tracinglib/robolectric/src/util/Util.kt
similarity index 64%
rename from tracinglib/core/host/src-fake/Log.fake.kt
rename to tracinglib/robolectric/src/util/Util.kt
index d758d4c..7e405d1 100644
--- a/tracinglib/core/host/src-fake/Log.fake.kt
+++ b/tracinglib/robolectric/src/util/Util.kt
@@ -14,21 +14,13 @@
  * limitations under the License.
  */
 
-package android.util
+package com.android.app.tracing.coroutines.util
 
-@Suppress("UNUSED_PARAMETER")
-object Log {
-    const val VERBOSE: Int = 2
+const val DEBUG = false
 
-    fun v(tag: String, msg: String) {}
-
-    fun d(tag: String, msg: String) {}
-
-    fun i(tag: String, msg: String) {}
-
-    fun w(tag: String, msg: String) {}
-
-    fun e(tag: String, msg: String) {}
-
-    fun isLoggable(tag: String, level: Int) = true
+/** Log a message with a tag indicating the current thread ID */
+internal fun debugLog(message: String) {
+    if (DEBUG) println("Thread #${currentThreadId()}: $message")
 }
+
+internal fun currentThreadId(): Long = Thread.currentThread().id
diff --git a/viewcapturelib/Android.bp b/viewcapturelib/Android.bp
index cc08ff1..fa772e6 100644
--- a/viewcapturelib/Android.bp
+++ b/viewcapturelib/Android.bp
@@ -39,7 +39,6 @@ android_library {
     static_libs: [
         "androidx.core_core",
         "view_capture_proto",
-        "perfetto_trace_javastream_protos_jarjar",
     ],
 
     srcs: [
@@ -60,6 +59,7 @@ android_test {
         "androidx.test.ext.junit",
         "androidx.test.rules",
         "testables",
+        "mockito-kotlin2",
         "mockito-target-extended-minus-junit4",
     ],
     srcs: [
@@ -67,9 +67,12 @@ android_test {
         "**/*.kt",
     ],
     libs: [
-        "android.test.runner",
-        "android.test.base",
-        "android.test.mock",
+        "android.test.runner.stubs.system",
+        "android.test.base.stubs.system",
+        "android.test.mock.stubs.system",
+    ],
+    jni_libs: [
+        "libdexmakerjvmtiagent",
     ],
     test_suites: ["device-tests"],
 }
diff --git a/viewcapturelib/build.gradle b/viewcapturelib/build.gradle
index f054d00..6e22edc 100644
--- a/viewcapturelib/build.gradle
+++ b/viewcapturelib/build.gradle
@@ -1,11 +1,8 @@
 plugins {
     id 'com.android.library'
     id 'org.jetbrains.kotlin.android'
-    id 'com.google.protobuf'
 }
 
-final String PROTOS_DIR = "${ANDROID_TOP}/frameworks/libs/systemui/viewcapturelib/src/com/android/app/viewcapture/proto"
-
 android {
     namespace = "com.android.app.viewcapture"
     testNamespace = "com.android.app.viewcapture.test"
@@ -17,7 +14,6 @@ android {
         main {
             java.srcDirs = ['src']
             manifest.srcFile 'AndroidManifest.xml'
-            proto.srcDirs = ["${PROTOS_DIR}"]
         }
         androidTest {
             java.srcDirs = ["tests"]
@@ -32,31 +28,8 @@ android {
 
 dependencies {
     implementation "androidx.core:core:1.9.0"
-    implementation "com.google.protobuf:protobuf-lite:${protobuf_lite_version}"
+    implementation project(":frameworks:libs:systemui:viewcapturelib:view_capture_proto")
     androidTestImplementation project(':SharedTestLib')
     androidTestImplementation 'androidx.test.ext:junit:1.1.3'
     androidTestImplementation "androidx.test:rules:1.4.0"
 }
-
-protobuf {
-    // Configure the protoc executable
-    protoc {
-        artifact = "com.google.protobuf:protoc:${protobuf_version}${PROTO_ARCH_SUFFIX}"
-    }
-    plugins {
-        javalite {
-            // The codegen for lite comes as a separate artifact
-            artifact = "com.google.protobuf:protoc-gen-javalite:${protobuf_lite_version}${PROTO_ARCH_SUFFIX}"
-        }
-    }
-    generateProtoTasks {
-        all().each { task ->
-            task.builtins {
-                remove java
-            }
-            task.plugins {
-                javalite { }
-            }
-        }
-    }
-}
\ No newline at end of file
diff --git a/viewcapturelib/src/com/android/app/viewcapture/SettingsAwareViewCapture.kt b/viewcapturelib/src/com/android/app/viewcapture/SettingsAwareViewCapture.kt
index 0e36671..2f2f3f8 100644
--- a/viewcapturelib/src/com/android/app/viewcapture/SettingsAwareViewCapture.kt
+++ b/viewcapturelib/src/com/android/app/viewcapture/SettingsAwareViewCapture.kt
@@ -51,14 +51,16 @@ internal constructor(private val context: Context, executor: Executor) :
 
     init {
         enableOrDisableWindowListeners()
-        context.contentResolver.registerContentObserver(
-                Settings.Global.getUriFor(VIEW_CAPTURE_ENABLED),
-                false,
-                object : ContentObserver(Handler()) {
-                    override fun onChange(selfChange: Boolean) {
-                        enableOrDisableWindowListeners()
-                    }
-                })
+        mBgExecutor.execute {
+            context.contentResolver.registerContentObserver(
+                    Settings.Global.getUriFor(VIEW_CAPTURE_ENABLED),
+                    false,
+                    object : ContentObserver(Handler()) {
+                        override fun onChange(selfChange: Boolean) {
+                            enableOrDisableWindowListeners()
+                        }
+                    })
+        }
     }
 
     @AnyThread
diff --git a/viewcapturelib/src/com/android/app/viewcapture/ViewCapture.java b/viewcapturelib/src/com/android/app/viewcapture/ViewCapture.java
index 3e2cc53..761b863 100644
--- a/viewcapturelib/src/com/android/app/viewcapture/ViewCapture.java
+++ b/viewcapturelib/src/com/android/app/viewcapture/ViewCapture.java
@@ -89,7 +89,7 @@ public abstract class ViewCapture {
     protected final Executor mBgExecutor;
 
     // Pool used for capturing view tree on the UI thread.
-    private ViewRef mPool = new ViewRef();
+    private ViewPropertyRef mPool = new ViewPropertyRef();
     private boolean mIsEnabled = true;
 
     protected ViewCapture(int memorySize, int initPoolSize, Executor bgExecutor) {
@@ -105,22 +105,22 @@ public abstract class ViewCapture {
     }
 
     @UiThread
-    private void addToPool(ViewRef start, ViewRef end) {
+    private void addToPool(ViewPropertyRef start, ViewPropertyRef end) {
         end.next = mPool;
         mPool = start;
     }
 
     @WorkerThread
     private void initPool(int initPoolSize) {
-        ViewRef start = new ViewRef();
-        ViewRef current = start;
+        ViewPropertyRef start = new ViewPropertyRef();
+        ViewPropertyRef current = start;
 
         for (int i = 0; i < initPoolSize; i++) {
-            current.next = new ViewRef();
+            current.next = new ViewPropertyRef();
             current = current.next;
         }
 
-        ViewRef finalCurrent = current;
+        ViewPropertyRef finalCurrent = current;
         MAIN_EXECUTOR.execute(() -> addToPool(start, finalCurrent));
     }
 
@@ -241,11 +241,11 @@ public abstract class ViewCapture {
      * background thread, and prepared for being dumped into a bugreport.
      * <p>
      * Since some of the work needs to be done on the main thread after every draw, this piece of
-     * code needs to be hyper optimized. That is why we are recycling ViewRef and ViewPropertyRef
-     * objects and storing the list of nodes as a flat LinkedList, rather than as a tree. This data
+     * code needs to be hyper optimized. That is why we are recycling ViewPropertyRef objects
+     * and storing the list of nodes as a flat LinkedList, rather than as a tree. This data
      * structure allows recycling to happen in O(1) time via pointer assignment. Without this
-     * optimization, a lot of time is wasted creating ViewRef objects, or finding ViewRef objects to
-     * recycle.
+     * optimization, a lot of time is wasted creating ViewPropertyRef objects, or finding
+     * ViewPropertyRef objects to recycle.
      * <p>
      * Another optimization is to only traverse view nodes on the main thread that have potentially
      * changed since the last frame was drawn. This can be determined via a combination of private
@@ -265,7 +265,7 @@ public abstract class ViewCapture {
      * TODO: b/262585897: Another memory optimization could be to store all integer, float, and
      * boolean information via single integer values via the Chinese remainder theorem, or a similar
      * algorithm, which enables multiple numerical values to be stored inside 1 number. Doing this
-     * would allow each ViewProperty / ViewRef to slim down its memory footprint significantly.
+     * would allow each ViewPropertyRef to slim down its memory footprint significantly.
      * <p>
      * One important thing to remember is that bugs related to recycling will usually only appear
      * after at least 2000 frames have been rendered. If that code is changed, the tester can
@@ -283,7 +283,7 @@ public abstract class ViewCapture {
         public View mRoot;
         public final String name;
 
-        private final ViewRef mViewRef = new ViewRef();
+        private final ViewPropertyRef mViewPropertyRef = new ViewPropertyRef();
 
         private int mFrameIndexBg = -1;
         private boolean mIsFirstFrame = true;
@@ -291,7 +291,8 @@ public abstract class ViewCapture {
         private ViewPropertyRef[] mNodesBg = new ViewPropertyRef[mMemorySize];
 
         private boolean mIsActive = true;
-        private final Consumer<ViewRef> mCaptureCallback = this::captureViewPropertiesBg;
+        private final Consumer<ViewPropertyRef> mCaptureCallback =
+                this::copyCleanViewsFromLastFrameBg;
 
         WindowListener(View view, String name) {
             mRoot = view;
@@ -307,8 +308,8 @@ public abstract class ViewCapture {
         @Override
         public void onDraw() {
             Trace.beginSection("vc#onDraw");
-            captureViewTree(mRoot, mViewRef);
-            ViewRef captured = mViewRef.next;
+            captureViewTree(mRoot, mViewPropertyRef);
+            ViewPropertyRef captured = mViewPropertyRef.next;
             if (captured != null) {
                 captured.callback = mCaptureCallback;
                 captured.elapsedRealtimeNanos = SystemClock.elapsedRealtimeNanos();
@@ -319,14 +320,15 @@ public abstract class ViewCapture {
         }
 
         /**
-         * Captures the View property on the background thread, and transfer all the ViewRef objects
-         * back to the pool
+         * Copy clean views from the last frame on the background thread. Clean views are
+         * the remaining part of the view hierarchy that was not already copied by the UI thread.
+         * Then transfer the received ViewPropertyRef objects back to the UI thread's pool.
          */
         @WorkerThread
-        private void captureViewPropertiesBg(ViewRef viewRefStart) {
-            Trace.beginSection("vc#captureViewPropertiesBg");
+        private void copyCleanViewsFromLastFrameBg(ViewPropertyRef start) {
+            Trace.beginSection("vc#copyCleanViewsFromLastFrameBg");
 
-            long elapsedRealtimeNanos = viewRefStart.elapsedRealtimeNanos;
+            long elapsedRealtimeNanos = start.elapsedRealtimeNanos;
             mFrameIndexBg++;
             if (mFrameIndexBg >= mMemorySize) {
                 mFrameIndexBg = 0;
@@ -338,8 +340,11 @@ public abstract class ViewCapture {
             ViewPropertyRef resultStart = null;
             ViewPropertyRef resultEnd = null;
 
-            ViewRef viewRefEnd = viewRefStart;
-            while (viewRefEnd != null) {
+            ViewPropertyRef end = start;
+
+            while (end != null) {
+                end.completeTransferFromViewBg();
+
                 ViewPropertyRef propertyRef = recycle;
                 if (propertyRef == null) {
                     propertyRef = new ViewPropertyRef();
@@ -349,11 +354,15 @@ public abstract class ViewCapture {
                 }
 
                 ViewPropertyRef copy = null;
-                if (viewRefEnd.childCount < 0) {
-                    copy = findInLastFrame(viewRefEnd.view.hashCode());
-                    viewRefEnd.childCount = (copy != null) ? copy.childCount : 0;
+                if (end.childCount < 0) {
+                    copy = findInLastFrame(end.hashCode);
+                    if (copy != null) {
+                        copy.transferTo(end);
+                    } else {
+                        end.childCount = 0;
+                    }
                 }
-                viewRefEnd.transferTo(propertyRef);
+                end.transferTo(propertyRef);
 
                 if (resultStart == null) {
                     resultStart = propertyRef;
@@ -384,14 +393,14 @@ public abstract class ViewCapture {
                     }
                 }
 
-                if (viewRefEnd.next == null) {
+                if (end.next == null) {
                     // The compiler will complain about using a non-final variable from
-                    // an outer class in a lambda if we pass in viewRefEnd directly.
-                    final ViewRef finalViewRefEnd = viewRefEnd;
-                    MAIN_EXECUTOR.execute(() -> addToPool(viewRefStart, finalViewRefEnd));
+                    // an outer class in a lambda if we pass in 'end' directly.
+                    final ViewPropertyRef finalEnd = end;
+                    MAIN_EXECUTOR.execute(() -> addToPool(start, finalEnd));
                     break;
                 }
-                viewRefEnd = viewRefEnd.next;
+                end = end.next;
             }
             mNodesBg[mFrameIndexBg] = resultStart;
 
@@ -461,16 +470,15 @@ public abstract class ViewCapture {
             return builder.build();
         }
 
-        private ViewRef captureViewTree(View view, ViewRef start) {
-            ViewRef ref;
+        private ViewPropertyRef captureViewTree(View view, ViewPropertyRef start) {
+            ViewPropertyRef ref;
             if (mPool != null) {
                 ref = mPool;
                 mPool = mPool.next;
                 ref.next = null;
             } else {
-                ref = new ViewRef();
+                ref = new ViewPropertyRef();
             }
-            ref.view = view;
             start.next = ref;
             if (view instanceof ViewGroup) {
                 ViewGroup parent = (ViewGroup) view;
@@ -479,17 +487,20 @@ public abstract class ViewCapture {
                 if ((view.mPrivateFlags & (PFLAG_INVALIDATED | PFLAG_DIRTY_MASK)) == 0
                         && !mIsFirstFrame) {
                     // A negative child count is the signal to copy this view from the last frame.
-                    ref.childCount = -parent.getChildCount();
+                    ref.childCount = -1;
+                    ref.view = view;
                     return ref;
                 }
-                ViewRef result = ref;
+                ViewPropertyRef result = ref;
                 int childCount = ref.childCount = parent.getChildCount();
+                ref.transferFrom(view);
                 for (int i = 0; i < childCount; i++) {
                     result = captureViewTree(parent.getChildAt(i), result);
                 }
                 return result;
             } else {
                 ref.childCount = 0;
+                ref.transferFrom(view);
                 return ref;
             }
         }
@@ -518,11 +529,12 @@ public abstract class ViewCapture {
         }
     }
 
-    protected static class ViewPropertyRef {
+    protected static class ViewPropertyRef implements Runnable {
+        public View view;
+
         // We store reference in memory to avoid generating and storing too many strings
         public Class clazz;
         public int hashCode;
-        public int childCount = 0;
 
         public int id;
         public int left, top, right, bottom;
@@ -536,9 +548,45 @@ public abstract class ViewCapture {
         public int visibility;
         public boolean willNotDraw;
         public boolean clipChildren;
+        public int childCount = 0;
 
         public ViewPropertyRef next;
 
+        public Consumer<ViewPropertyRef> callback = null;
+        public long elapsedRealtimeNanos = 0;
+
+
+        public void transferFrom(View in) {
+            view = in;
+
+            left = in.getLeft();
+            top = in.getTop();
+            right = in.getRight();
+            bottom = in.getBottom();
+            scrollX = in.getScrollX();
+            scrollY = in.getScrollY();
+
+            translateX = in.getTranslationX();
+            translateY = in.getTranslationY();
+            scaleX = in.getScaleX();
+            scaleY = in.getScaleY();
+            alpha = in.getAlpha();
+            elevation = in.getElevation();
+
+            visibility = in.getVisibility();
+            willNotDraw = in.willNotDraw();
+        }
+
+        /**
+         * Transfer in backgroup thread view properties that remain unchanged between frames.
+         */
+        public void completeTransferFromViewBg() {
+            clazz = view.getClass();
+            hashCode = view.hashCode();
+            id = view.getId();
+            view = null;
+        }
+
         public void transferTo(ViewPropertyRef out) {
             out.clazz = this.clazz;
             out.hashCode = this.hashCode;
@@ -600,48 +648,10 @@ public abstract class ViewCapture {
             }
             return result;
         }
-    }
-
-
-    private static class ViewRef implements Runnable {
-        public View view;
-        public int childCount = 0;
-        @Nullable
-        public ViewRef next;
-
-        public Consumer<ViewRef> callback = null;
-        public long elapsedRealtimeNanos = 0;
-
-        public void transferTo(ViewPropertyRef out) {
-            out.childCount = this.childCount;
-
-            View view = this.view;
-            this.view = null;
-
-            out.clazz = view.getClass();
-            out.hashCode = view.hashCode();
-            out.id = view.getId();
-            out.left = view.getLeft();
-            out.top = view.getTop();
-            out.right = view.getRight();
-            out.bottom = view.getBottom();
-            out.scrollX = view.getScrollX();
-            out.scrollY = view.getScrollY();
-
-            out.translateX = view.getTranslationX();
-            out.translateY = view.getTranslationY();
-            out.scaleX = view.getScaleX();
-            out.scaleY = view.getScaleY();
-            out.alpha = view.getAlpha();
-            out.elevation = view.getElevation();
-
-            out.visibility = view.getVisibility();
-            out.willNotDraw = view.willNotDraw();
-        }
 
         @Override
         public void run() {
-            Consumer<ViewRef> oldCallback = callback;
+            Consumer<ViewPropertyRef> oldCallback = callback;
             callback = null;
             if (oldCallback != null) {
                 oldCallback.accept(this);
diff --git a/viewcapturelib/src/com/android/app/viewcapture/ViewCaptureAwareWindowManager.kt b/viewcapturelib/src/com/android/app/viewcapture/ViewCaptureAwareWindowManager.kt
new file mode 100644
index 0000000..172975b
--- /dev/null
+++ b/viewcapturelib/src/com/android/app/viewcapture/ViewCaptureAwareWindowManager.kt
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
+package com.android.app.viewcapture
+
+import android.media.permission.SafeCloseable
+import android.util.Log
+import android.view.View
+import android.view.ViewGroup
+import android.view.WindowManager
+
+/** Tag for debug logging. */
+private const val TAG = "ViewCaptureWindowManager"
+
+/**
+ * Wrapper class for [WindowManager]. Adds [ViewCapture] to associated window when it is added to
+ * view hierarchy.
+ */
+class ViewCaptureAwareWindowManager(
+    private val windowManager: WindowManager,
+    private val lazyViewCapture: Lazy<ViewCapture>,
+    private val isViewCaptureEnabled: Boolean,
+) : WindowManager by windowManager {
+
+    private var viewCaptureCloseableMap: MutableMap<View, SafeCloseable> = mutableMapOf()
+
+    override fun addView(view: View, params: ViewGroup.LayoutParams?) {
+        windowManager.addView(view, params)
+        if (isViewCaptureEnabled) {
+            val viewCaptureCloseable: SafeCloseable =
+                lazyViewCapture.value.startCapture(view, getViewName(view))
+            viewCaptureCloseableMap[view] = viewCaptureCloseable
+        }
+    }
+
+    override fun removeView(view: View?) {
+        removeViewFromCloseableMap(view)
+        windowManager.removeView(view)
+    }
+
+    override fun removeViewImmediate(view: View?) {
+        removeViewFromCloseableMap(view)
+        windowManager.removeViewImmediate(view)
+    }
+
+    private fun getViewName(view: View) = "." + view.javaClass.name
+
+    private fun removeViewFromCloseableMap(view: View?) {
+        if (isViewCaptureEnabled) {
+            if (viewCaptureCloseableMap.containsKey(view)) {
+                viewCaptureCloseableMap[view]?.close()
+                viewCaptureCloseableMap.remove(view)
+            } else {
+                Log.wtf(TAG, "removeView called with view not present in closeable map!")
+            }
+        }
+    }
+
+    interface Factory {
+        fun create(windowManager: WindowManager): ViewCaptureAwareWindowManager
+    }
+}
diff --git a/viewcapturelib/src/com/android/app/viewcapture/ViewCaptureFactory.kt b/viewcapturelib/src/com/android/app/viewcapture/ViewCaptureFactory.kt
index 8ef0c4d..c2b2a3f 100644
--- a/viewcapturelib/src/com/android/app/viewcapture/ViewCaptureFactory.kt
+++ b/viewcapturelib/src/com/android/app/viewcapture/ViewCaptureFactory.kt
@@ -21,6 +21,7 @@ import android.os.Looper
 import android.os.Process
 import android.tracing.Flags
 import android.util.Log
+import android.view.WindowManager
 
 /**
  * Factory to create polymorphic instances of ViewCapture according to build configurations and
@@ -68,5 +69,20 @@ class ViewCaptureFactory {
                 }
             }.also { instance = it }
         }
+
+        /** Returns an instance of [ViewCaptureAwareWindowManager]. */
+        @JvmStatic
+        fun getViewCaptureAwareWindowManagerInstance(
+            context: Context,
+            isViewCaptureTracingEnabled: Boolean
+        ): ViewCaptureAwareWindowManager {
+            val windowManager = context.getSystemService(Context.WINDOW_SERVICE) as WindowManager
+            val lazyViewCapture = lazy { getInstance(context) }
+            return ViewCaptureAwareWindowManager(
+                windowManager,
+                lazyViewCapture,
+                isViewCaptureTracingEnabled
+            )
+        }
     }
 }
diff --git a/viewcapturelib/tests/com/android/app/viewcapture/ViewCaptureAwareWindowManagerTest.kt b/viewcapturelib/tests/com/android/app/viewcapture/ViewCaptureAwareWindowManagerTest.kt
new file mode 100644
index 0000000..174639b
--- /dev/null
+++ b/viewcapturelib/tests/com/android/app/viewcapture/ViewCaptureAwareWindowManagerTest.kt
@@ -0,0 +1,85 @@
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
+package com.android.app.viewcapture
+
+import android.content.Context
+import android.testing.AndroidTestingRunner
+import android.view.View
+import android.view.WindowManager
+import androidx.test.core.app.ApplicationProvider
+import androidx.test.filters.SmallTest
+import org.junit.Before
+import org.junit.Test
+import org.junit.runner.RunWith
+import org.mockito.ArgumentMatchers.any
+import org.mockito.ArgumentMatchers.anyString
+import org.mockito.Mockito.doAnswer
+import org.mockito.Mockito.spy
+import org.mockito.Mockito.times
+import org.mockito.Mockito.verify
+import org.mockito.Mockito.`when`
+import org.mockito.invocation.InvocationOnMock
+import org.mockito.kotlin.doReturn
+import org.mockito.kotlin.mock
+
+@RunWith(AndroidTestingRunner::class)
+@SmallTest
+class ViewCaptureAwareWindowManagerTest {
+    private val context: Context = ApplicationProvider.getApplicationContext()
+    private val mockRootView = mock<View>()
+    private val windowManager = mock<WindowManager>()
+    private val viewCaptureSpy = spy(ViewCaptureFactory.getInstance(context))
+    private val lazyViewCapture = mock<Lazy<ViewCapture>> { on { value } doReturn viewCaptureSpy }
+    private var mViewCaptureAwareWindowManager: ViewCaptureAwareWindowManager? = null
+
+    @Before
+    fun setUp() {
+        doAnswer { invocation: InvocationOnMock ->
+                val view = invocation.getArgument<View>(0)
+                val lp = invocation.getArgument<WindowManager.LayoutParams>(1)
+                view.layoutParams = lp
+                null
+            }
+            .`when`(windowManager)
+            .addView(any(View::class.java), any(WindowManager.LayoutParams::class.java))
+        `when`(mockRootView.context).thenReturn(context)
+    }
+
+    @Test
+    fun testAddView_viewCaptureEnabled_verifyStartCaptureCall() {
+        mViewCaptureAwareWindowManager =
+            ViewCaptureAwareWindowManager(
+                windowManager,
+                lazyViewCapture,
+                isViewCaptureEnabled = true
+            )
+        mViewCaptureAwareWindowManager?.addView(mockRootView, mockRootView.layoutParams)
+        verify(viewCaptureSpy).startCapture(any(), anyString())
+    }
+
+    @Test
+    fun testAddView_viewCaptureNotEnabled_verifyStartCaptureCall() {
+        mViewCaptureAwareWindowManager =
+            ViewCaptureAwareWindowManager(
+                windowManager,
+                lazyViewCapture,
+                isViewCaptureEnabled = false
+            )
+        mViewCaptureAwareWindowManager?.addView(mockRootView, mockRootView.layoutParams)
+        verify(viewCaptureSpy, times(0)).startCapture(any(), anyString())
+    }
+}
diff --git a/weathereffects/Android.bp b/weathereffects/Android.bp
index a62bf53..25b13c8 100644
--- a/weathereffects/Android.bp
+++ b/weathereffects/Android.bp
@@ -46,8 +46,7 @@ android_app {
     name: "WeatherEffectsDebug",
     manifest: "debug/AndroidManifest.xml",
     owner: "google",
-    sdk_version: "system_current",
-    min_sdk_version: "34",
+    platform_apis: true,
     srcs: [
         "src/**/*.java",
         "src/**/*.kt",
@@ -89,6 +88,7 @@ android_test {
     manifest: "AndroidManifest.xml",
     test_suites: ["general-tests"],
     sdk_version: "current",
+    owner: "google",
     srcs: [
         "tests/src/**/*.java",
         "tests/src/**/*.kt",
diff --git a/weathereffects/debug/AndroidManifest.xml b/weathereffects/debug/AndroidManifest.xml
index 53180d3..424d38b 100644
--- a/weathereffects/debug/AndroidManifest.xml
+++ b/weathereffects/debug/AndroidManifest.xml
@@ -21,6 +21,7 @@
     <uses-feature
         android:name="android.software.live_wallpaper"
         android:required="true" />
+    <uses-permission android:name="android.permission.SUBSCRIBE_TO_KEYGUARD_LOCKED_STATE" />
 
     <queries>
         <package android:name="com.google.android.apps.wallpaper" />
diff --git a/weathereffects/debug/res/layout/debug_activity.xml b/weathereffects/debug/res/layout/debug_activity.xml
index a05fd5e..13b6349 100644
--- a/weathereffects/debug/res/layout/debug_activity.xml
+++ b/weathereffects/debug/res/layout/debug_activity.xml
@@ -70,6 +70,16 @@
             android:text="@string/button_snow"
             android:layout_width="wrap_content"
             android:layout_height="wrap_content"
+            app:layout_constraintBottom_toTopOf="@id/sunny"
+            app:layout_constraintEnd_toEndOf="parent"
+            android:layout_marginBottom="10dp"
+            android:layout_marginEnd="20dp" />
+
+        <Button
+            android:id="@+id/sunny"
+            android:text="@string/button_sunny"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
             app:layout_constraintBottom_toTopOf="@id/clear"
             app:layout_constraintEnd_toEndOf="parent"
             android:layout_marginBottom="10dp"
@@ -100,10 +110,20 @@
             android:text="@string/set_wallpaper"
             android:layout_width="wrap_content"
             android:layout_height="wrap_content"
-            app:layout_constraintBottom_toBottomOf="parent"
+            app:layout_constraintBottom_toBottomOf="@id/seekBar"
             app:layout_constraintEnd_toEndOf="parent"
             android:layout_marginBottom="30dp"
             android:layout_marginEnd="20dp" />
+
+        <SeekBar
+            android:id="@+id/seekBar"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:max="100"
+            android:progress="80"
+            android:layout_marginBottom="50dp"
+            app:layout_constraintBottom_toBottomOf="parent"
+            app:layout_constraintEnd_toEndOf="parent"/>
     </androidx.constraintlayout.widget.ConstraintLayout>
 
 </FrameLayout>
diff --git a/weathereffects/debug/res/values/strings.xml b/weathereffects/debug/res/values/strings.xml
index b5bb889..31ba2b0 100644
--- a/weathereffects/debug/res/values/strings.xml
+++ b/weathereffects/debug/res/values/strings.xml
@@ -22,6 +22,7 @@
     <string name="button_rain" translatable="false">Rain</string>
     <string name="button_fog" translatable="false">Fog</string>
     <string name="button_snow" translatable="false">Snow</string>
+    <string name="button_sunny" translatable="false">Sun</string>
     <string name="button_clear" translatable="false">Clear Weather</string>
     <string name="change_asset" translatable="false">Change Asset</string>
 </resources>
diff --git a/weathereffects/debug/src/com/google/android/wallpaper/weathereffects/WallpaperEffectsDebugActivity.kt b/weathereffects/debug/src/com/google/android/wallpaper/weathereffects/WallpaperEffectsDebugActivity.kt
index d1efd03..2f8687a 100644
--- a/weathereffects/debug/src/com/google/android/wallpaper/weathereffects/WallpaperEffectsDebugActivity.kt
+++ b/weathereffects/debug/src/com/google/android/wallpaper/weathereffects/WallpaperEffectsDebugActivity.kt
@@ -29,6 +29,7 @@ import android.view.SurfaceView
 import android.view.View
 import android.widget.Button
 import android.widget.FrameLayout
+import android.widget.SeekBar
 import android.widget.TextView
 import androidx.constraintlayout.widget.ConstraintLayout
 import com.google.android.torus.core.activity.TorusViewerActivity
@@ -36,14 +37,15 @@ import com.google.android.torus.core.engine.TorusEngine
 import com.google.android.torus.utils.extensions.setImmersiveFullScreen
 import com.google.android.wallpaper.weathereffects.dagger.BackgroundScope
 import com.google.android.wallpaper.weathereffects.dagger.MainScope
+import com.google.android.wallpaper.weathereffects.data.repository.WallpaperFileUtils
+import com.google.android.wallpaper.weathereffects.domain.WeatherEffectsInteractor
 import com.google.android.wallpaper.weathereffects.provider.WallpaperInfoContract
 import com.google.android.wallpaper.weathereffects.shared.model.WallpaperFileModel
-import com.google.android.wallpaper.weathereffects.domain.WeatherEffectsInteractor
-import java.io.File
-import javax.inject.Inject
 import kotlinx.coroutines.CoroutineScope
 import kotlinx.coroutines.delay
 import kotlinx.coroutines.launch
+import java.io.File
+import javax.inject.Inject
 
 class WallpaperEffectsDebugActivity : TorusViewerActivity() {
 
@@ -66,22 +68,31 @@ class WallpaperEffectsDebugActivity : TorusViewerActivity() {
     private val fgCachedAssetPaths: ArrayList<String> = arrayListOf()
     private val bgCachedAssetPaths: ArrayList<String> = arrayListOf()
 
+    /** It will be initialized on [onCreate]. */
+    private var intensity: Float = 0.8f
+
     override fun getWallpaperEngine(context: Context, surfaceView: SurfaceView): TorusEngine {
         this.surfaceView = surfaceView
-        val engine = WeatherEngine(surfaceView.holder, context)
+        val engine = WeatherEngine(
+            surfaceView.holder,
+            mainScope,
+            interactor,
+            context,
+            isDebugActivity = true
+        )
         this.engine = engine
         return engine
     }
 
     @SuppressLint("ClickableViewAccessibility")
     override fun onCreate(savedInstanceState: Bundle?) {
-        super.onCreate(savedInstanceState)
         WallpaperEffectsDebugApplication.graph.inject(this)
+        super.onCreate(savedInstanceState)
 
         setContentView(R.layout.debug_activity)
         setImmersiveFullScreen()
 
-         writeAssetsToCache()
+        writeAssetsToCache()
 
         rootView = requireViewById(R.id.main_layout)
         rootView.requireViewById<FrameLayout>(R.id.wallpaper_layout).addView(surfaceView)
@@ -101,6 +112,11 @@ class WallpaperEffectsDebugActivity : TorusViewerActivity() {
             updateWallpaper()
             setDebugText(context.getString(R.string.generating))
         }
+        rootView.requireViewById<Button>(R.id.sunny).setOnClickListener {
+            weatherEffect = WallpaperInfoContract.WeatherEffect.SUN
+            updateWallpaper()
+            setDebugText(context.getString(R.string.generating))
+        }
         rootView.requireViewById<Button>(R.id.clear).setOnClickListener {
             weatherEffect = null
 
@@ -139,8 +155,28 @@ class WallpaperEffectsDebugActivity : TorusViewerActivity() {
                 view.onTouchEvent(event)
             }
 
-        engine?.initialize(mainScope, interactor)
         setDebugText()
+        val seekBar = rootView.requireViewById<SeekBar>(R.id.seekBar)
+        seekBar.setOnSeekBarChangeListener(object : SeekBar.OnSeekBarChangeListener {
+            override fun onProgressChanged(seekBar: SeekBar?, progress: Int, fromUser: Boolean) {
+                // Convert progress to a value between 0 and 1
+                val value = progress.toFloat() / 100f
+                engine?.setTargetIntensity(value)
+                intensity = value
+            }
+
+            override fun onStartTrackingTouch(seekBar: SeekBar?) {
+                hideButtons()
+            }
+
+            override fun onStopTrackingTouch(seekBar: SeekBar?) {
+                showButtons()
+            }
+        })
+        intensity = seekBar.progress.toFloat() / 100f
+
+        // This avoids that the initial state after installing is showing a black screen.
+        if (!WallpaperFileUtils.hasBitmapsInLocalStorage(applicationContext)) updateWallpaper()
     }
 
     private fun writeAssetsToCache() {
@@ -191,8 +227,11 @@ class WallpaperEffectsDebugActivity : TorusViewerActivity() {
                     weatherEffect,
                 )
             )
-            setDebugText("Wallpaper updated successfully.\n* Weather: " +
-                    "$weatherEffect\n* Foreground: $fgPath\n* Background: $bgPath")
+            engine?.setTargetIntensity(intensity)
+            setDebugText(
+                "Wallpaper updated successfully.\n* Weather: " +
+                        "$weatherEffect\n* Foreground: $fgPath\n* Background: $bgPath"
+            )
         }
     }
 
diff --git a/weathereffects/graphics/assets/shaders/fog_effect.agsl b/weathereffects/graphics/assets/shaders/fog_effect.agsl
index 5f00db9..51ae25b 100644
--- a/weathereffects/graphics/assets/shaders/fog_effect.agsl
+++ b/weathereffects/graphics/assets/shaders/fog_effect.agsl
@@ -34,7 +34,7 @@ uniform half intensity;
 #include "shaders/utils.agsl"
 #include "shaders/simplex2d.agsl"
 
-const vec3 fogColor = vec3(1.);
+const vec3 fogColor = vec3(0.20);
 
 vec4 main(float2 fragCoord) {
     float2 uv = fragCoord / screenSize;
@@ -54,11 +54,11 @@ vec4 main(float2 fragCoord) {
 
     // Load foreground and blend it with constant solid fog color.
     vec4 fgd = foreground.eval(fragCoord * uvScaleFgd + uvOffsetFgd);
-    fgd.rgb = mix(fgd.rgb, fogColor, 0.32 * intensity * fgd.a);
+    fgd.rgb = mix(fgd.rgb, fogColor, 0.15 * intensity * fgd.a);
 
     // Load background and blend it with constant solid fog color.
     vec4 bgd = background.eval(fragCoord * uvScaleBgd + uvOffsetBgd);
-    bgd.rgb = mix(bgd.rgb, fogColor, 0.15 * intensity * bgd.a);
+    bgd.rgb = mix(bgd.rgb, fogColor, 0.32 * intensity * bgd.a);
 
     /* Add first layer: background. */
     // set background color as the starting layer.
@@ -66,7 +66,7 @@ vec4 main(float2 fragCoord) {
 
     /* Prepare fog layers. */
     // Dither to be applied to background noise.
-    float bgdDither = triangleNoise((fragCoord + 0.0002 * timeBackground) * pixelDensity) * 0.1;
+    float bgdDither = triangleNoise((fragCoord + 0.0002 * timeBackground) * pixelDensity) * 0.075;
 
     // The furthest fog layer in the background.
     vec4 bgdFogFar = fog.eval(
@@ -74,7 +74,7 @@ vec4 main(float2 fragCoord) {
         // Moves UV based on time.
         vec2(timeBackground * 1.5) +
         // Adds sampling dithering.
-        vec2(bgdDither * 7));
+        vec2(bgdDither * 14));
 
     // The furthest fog layer in the background.
     vec4 bgdFogClose = fog.eval(
@@ -82,43 +82,60 @@ vec4 main(float2 fragCoord) {
         // Moves UV based on time.
         vec2(timeBackground * 5.5) +
         // Adds sampling dithering.
-        vec2(bgdDither * 22));
+        vec2(bgdDither * 40));
 
-    float fgdDither = triangleNoise((fragCoord + 0.003 * timeForeground) * pixelDensity) * 0.07;
+    float fgdDither = triangleNoise((fragCoord + 0.003 * timeForeground) * pixelDensity) * 0.09;
     vec4 fgdFogFar = clouds.eval(
         0.5 * cloudsSize * uv +
         // Moves UV based on time.
-        vec2(timeForeground * 10.) +
+        vec2(timeForeground * 15.) +
         // Adds distosions based on noise.
-        vec2(bgdFogFar.b * 70., bgdFogFar.g * 10) +
+        vec2(bgdFogFar.b * 20., bgdFogFar.g * 2) +
         // Adds sampling dithering.
-        vec2(fgdDither * 10));
+        vec2(fgdDither * 12));
     vec4 fgdFogClose = clouds.eval(
         0.5 * cloudsSize * uv +
         // moves UV based on time.
-        vec2(timeForeground * 72.) +
+        vec2(timeForeground * 32.) +
         // Adds distosions based on noise.
-        vec2(bgdFogFar.g * 50., bgdFogFar.b * 80) +
+        vec2(bgdFogFar.g * 2., bgdFogFar.b * 10) +
         // Adds sampling dithering.
-        vec2(fgdDither * 8));
+        vec2(fgdDither * 22));
+
+    // Undo aspect ratio adjustment.
+    uv.y *= screenAspectRatio;
 
     /* Add second layer: background fog (far or 1, and close or 2). */
     // background, layer 1.
-    float bgdFogLayer1 =
-        map(bgdFogFar.r, 0.2, 1., fgdFogFar.g, 0.8) *
-        bgdFogFar.r *
-        (1. - 0.7 * bgdDither);
-    // Blend with background.
-    color.rgb = normalBlendWithWhiteSrc(color.rgb, bgdFogLayer1 * intensity);
-
-    // background, layer 2.
-    float fbmSimplexWorley = bgdFogClose.g * 0.625 + bgdFogClose.b * 0.3755;
-    float bgdFogLayer2 =
-        0.85 *
-        smoothstep(0.88 * fbmSimplexWorley, 1., bgdFogClose.r) *
-        (1.- 0.4 * bgdDither);
-    // Blend with background.
-    color.rgb = normalBlendWithWhiteSrc(color.rgb, bgdFogLayer2 * intensity);
+    float fogHeightVariation;
+    if (uv.y < 0.38) {
+        fogHeightVariation = 0.03 * cos(uv.x * 2.5 + timeBackground.x * 0.07);
+        float bgFogFarCombined = map(bgdFogFar.r, 0.74, 0.9, fgdFogFar.g, 0.95) * bgdFogFar.r;
+        float bgdFogLayer1 =
+            bgFogFarCombined *
+            smoothstep(-0.1, 0.05, uv.y + fogHeightVariation) *
+            (1. - smoothstep(0.15, 0.35, uv.y + fogHeightVariation));
+        bgdFogLayer1 *= 0.45 * (1. - bgdDither);
+        bgdFogLayer1 = clamp(bgdFogLayer1, 0., 1.);
+        // Blend with background.
+        color.rgb = screenBlend(color.rgb, bgdFogLayer1 * intensity);
+    //    color.rgb = vec3(bgdFogLayer1 * intensity);
+    }
+
+    if (uv.y > 0.23 && uv.y < 0.87) {
+        // background, layer 2.
+        float fbmSimplexWorley = bgdFogClose.g * 0.625 + bgdFogClose.b * 0.3755;
+        float bgFogloseCombined = smoothstep(0.88 * fbmSimplexWorley, 1., bgdFogClose.r);
+        fogHeightVariation = 0.02 * sin(uv.x * 2.5 + timeBackground.x * 0.09);
+        float bgdFogLayer2 =
+            bgFogloseCombined *
+            smoothstep(0.25, 0.55, uv.y + fogHeightVariation) *
+            (1. - smoothstep(0.7, 0.85, uv.y + fogHeightVariation));
+        bgdFogLayer2 *= 0.6 * (1.- bgdDither);
+        bgdFogLayer2 = clamp(bgdFogLayer2, 0., 1.);
+        // Blend with background.
+        color.rgb = screenBlend(color.rgb, bgdFogLayer2 * intensity);
+    }
 
     /* Add third layer: foreground. */
     // Add the foreground. Any effect from here will be in front of the subject.
@@ -126,16 +143,30 @@ vec4 main(float2 fragCoord) {
 
     /* Add fourth layer: foreground fog (far or 1, and close or 2). */
     // foreground fog, layer 1.
-    float fgdFogLayer1 =
-        fgdFogFar.r *
-        0.5 * (1. - fgdDither);
-    color.rgb = normalBlendWithWhiteSrc(color.rgb, fgdFogLayer1 * intensity);
-
-    // Foreground fog, layer 2.
-    float fgdFogLayer2 =
-            fgdFogClose.g *
-            0.4 * (1. - fgdDither);
-    color.rgb = normalBlendWithWhiteSrc(color.rgb, fgdFogLayer2 * intensity);
-
+    if (uv.y > 0.32) {
+        fogHeightVariation = 0.1 * cos(uv.x * 2.5 + timeForeground.x * 0.085);
+        float fgdFogLayer1 =
+                mix(
+                    fgdFogFar.r,
+                    1.,
+                    0.5 * intensity * smoothstep(0.72, 0.92, uv.y + fogHeightVariation)) *
+                smoothstep(0.42, 0.82, uv.y + fogHeightVariation);
+        fgdFogLayer1 *= 0.65 * (1. - fgdDither);
+        fgdFogLayer1 = clamp(fgdFogLayer1, 0., 1.);
+        color.rgb = screenBlend(color.rgb, fgdFogLayer1 * intensity);
+    }
+    if (uv.y > 0.25) {
+        // Foreground fog, layer 2.
+        fogHeightVariation = 0.05 * sin(uv.x * 2. + timeForeground.y * 0.5);
+        float fgdFogLayer2 =
+                mix(
+                    fgdFogClose.g,
+                    1.,
+                    0.65 * intensity * smoothstep(0.85, 0.98, uv.y + fogHeightVariation)) *
+                smoothstep(0.30, 0.90, uv.y + uv.x * 0.09);
+        fgdFogLayer2 *= 0.8 * (1. - fgdDither);
+        fgdFogLayer2 = clamp(fgdFogLayer2, 0., 1.);
+        color.rgb = screenBlend(color.rgb, fgdFogLayer2 * intensity);
+    }
     return color;
 }
\ No newline at end of file
diff --git a/weathereffects/graphics/assets/shaders/glass_rain.agsl b/weathereffects/graphics/assets/shaders/glass_rain.agsl
index 60e102a..001239b 100644
--- a/weathereffects/graphics/assets/shaders/glass_rain.agsl
+++ b/weathereffects/graphics/assets/shaders/glass_rain.agsl
@@ -54,7 +54,7 @@ GlassRain generateGlassRain(
     // Number of rows and columns (each one is a cell, a drop).
     float cellAspectRatio = rainGridSize.x / rainGridSize.y;
     // Aspect ratio impacts visible cells.
-    rainGridSize.y /= screenAspectRatio;
+    uv.y /= screenAspectRatio;
     // scale the UV to allocate number of rows and columns.
     vec2 gridUv = uv * rainGridSize;
     // Invert y (otherwise it goes from 0=top to 1=bottom).
@@ -149,10 +149,7 @@ GlassRain generateGlassRain(
 /**
  * Generate rain drops that stay in place on the glass surface.
  */
-vec3 generateStaticGlassRain(vec2 uv, half screenAspectRatio, half time, half intensity) {
-    vec2 gridSize = vec2(15., 15.);
-    // Aspect ratio impacts visible cells.
-    gridSize.y /= screenAspectRatio;
+vec3 generateStaticGlassRain(vec2 uv, half time, half intensity, vec2 gridSize) {
     // scale the UV to allocate number of rows and columns.
     vec2 gridUv = uv * gridSize;
     // Invert y (otherwise it goes from 0=top to 1=bottom).
diff --git a/tracinglib/core/host/src-fake/Flags.fake.kt b/weathereffects/graphics/assets/shaders/lens_flare.agsl
similarity index 69%
rename from tracinglib/core/host/src-fake/Flags.fake.kt
rename to weathereffects/graphics/assets/shaders/lens_flare.agsl
index 9ada4b3..016f6bf 100644
--- a/tracinglib/core/host/src-fake/Flags.fake.kt
+++ b/weathereffects/graphics/assets/shaders/lens_flare.agsl
@@ -14,14 +14,4 @@
  * limitations under the License.
  */
 
-package com.android.systemui
-
-private var isCoroutineTracingFlagEnabledForTests = true
-
-object Flags {
-    fun coroutineTracing() = isCoroutineTracingFlagEnabledForTests
-
-    fun disableCoroutineTracing() {
-        isCoroutineTracingFlagEnabledForTests = false
-    }
-}
+// TODO(b/347299395): to add flare
diff --git a/weathereffects/graphics/assets/shaders/rain_glass_layer.agsl b/weathereffects/graphics/assets/shaders/rain_glass_layer.agsl
index bf4732f..8fdf1fc 100644
--- a/weathereffects/graphics/assets/shaders/rain_glass_layer.agsl
+++ b/weathereffects/graphics/assets/shaders/rain_glass_layer.agsl
@@ -17,6 +17,7 @@
 uniform shader texture;
 uniform float time;
 uniform float screenAspectRatio;
+uniform float gridScale;
 uniform float2 screenSize;
 uniform half intensity;
 
@@ -26,18 +27,16 @@ uniform half intensity;
 #include "shaders/rain_constants.agsl"
 
 vec4 main(float2 fragCoord) {
-    // 0. Add a bit of noise so that the droplets are not perfect circles.
-    fragCoord += vec2(valueNoise(fragCoord) * 0.015 - 0.0025);
-
-    float2 uv = fragCoord / screenSize;
+    // 0. Calculate UV and add a bit of noise so that the droplets are not perfect circles.
+    float2 uv = vec2(valueNoise(fragCoord) * 0.015 - 0.0025) + fragCoord / screenSize;
 
     // 1. Generate small glass rain.
     GlassRain smallDrippingRain = generateGlassRain(
          uv,
          screenAspectRatio,
-         time,
-         /* Grid size = */ vec2(4.0, 2.0),
-         intensity);
+         time * 0.7,
+         /* Grid size = */ vec2(5.0, 1.6) * gridScale,
+         intensity * 0.6);
     float dropMask = smallDrippingRain.dropMask;
     float droppletsMask = smallDrippingRain.droppletsMask;
     float trailMask = smallDrippingRain.trailMask;
@@ -48,9 +47,9 @@ vec4 main(float2 fragCoord) {
     GlassRain medDrippingRain = generateGlassRain(
           uv,
           screenAspectRatio,
-          time * 1.267,
-          /* Grid size = */ vec2(3.5, 1.5),
-          intensity);
+          time * 0.80,
+          /* Grid size = */ vec2(6., 0.945) * gridScale,
+          intensity * 0.6);
 
     // 3. Combine those two glass rains.
     dropMask = max(medDrippingRain.dropMask, dropMask);
@@ -62,7 +61,10 @@ vec4 main(float2 fragCoord) {
         medDrippingRain.dropplets * medDrippingRain.droppletsMask, medDrippingRain.droppletsMask);
 
     // 4. Add static rain droplets on the glass surface. (They stay in place and dissapate.)
-    vec3 staticRain = generateStaticGlassRain(uv, screenAspectRatio, time, intensity);
+    vec2 gridSize = vec2(12., 12.) * gridScale;
+    // Aspect ratio impacts visible cells.
+    gridSize.y /= screenAspectRatio;
+    vec3 staticRain = generateStaticGlassRain(uv, time, intensity, gridSize);
     dropMask = max(dropMask, staticRain.z);
     dropUvMasked = mix(dropUvMasked, staticRain.xy * staticRain.z, staticRain.z);
 
diff --git a/weathereffects/graphics/assets/shaders/rain_shower.agsl b/weathereffects/graphics/assets/shaders/rain_shower.agsl
index eed39f8..c3afeba 100644
--- a/weathereffects/graphics/assets/shaders/rain_shower.agsl
+++ b/weathereffects/graphics/assets/shaders/rain_shower.agsl
@@ -44,7 +44,7 @@ Rain generateRain(
     // Number of rows and columns (each one is a cell, a drop).
     float cellAspectRatio = rainGridSize.x / rainGridSize.y;
     // Aspect ratio impacts visible cells.
-    rainGridSize.y /= screenAspectRatio;
+    uv.y /= screenAspectRatio;
     // scale the UV to allocate number of rows and columns.
     vec2 gridUv = uv * rainGridSize;
     // Invert y (otherwise it goes from 0=top to 1=bottom).
@@ -63,20 +63,27 @@ Rain generateRain(
     vec2 cellUv = fract(gridUv) - 0.5;
 
     float intensity = idGenerator(floor(vec2(cellId * 8.16, 27.2)));
-    if (intensity < 1. - rainIntensity) {
+    if (rainIntensity < intensity) {
         return Rain(0.0, cellUv);
     }
 
+    /* Cell-id-based variations. */
+    // This factor is used to make the particle visibile right after it is visible
+    // (based on cellIntensity). 0 = snow flake invisible, 1 = snow flake visible.
+    float visivilityFactor = smoothstep(
+        intensity,
+        min(intensity + 0.18, 1.0),
+        rainIntensity);
+
     /* Cell-id-based variations. */
     // Adjust time based on columnId.
     time += columnId * 7.1203;
     // Adjusts scale of each drop (higher is smaller).
     float scaleVariation = 1.0 - 0.3 * cellId;
-    float opacityVariation = (1. - 0.9 * cellId);
 
     /* Cell drop. */
     // Define the start based on the cell id.
-    float horizontalStart = 0.8 * (cellId - 0.5);
+    float horizontalStart = 0.8 * (intensity - 0.5);
 
     // Calculate drop.
     vec2 dropPos = cellUv;
@@ -90,7 +97,7 @@ Rain generateRain(
         .80 + 3. * cellId,
         // Adjust the shape.
         1. - length(vec2(dropPos.x, (dropPos.y - dropPos.x * dropPos.x)))
-    );
+    ) * visivilityFactor;
 
     return Rain(dropMask, cellUv);
 }
diff --git a/weathereffects/graphics/assets/shaders/rain_shower_layer.agsl b/weathereffects/graphics/assets/shaders/rain_shower_layer.agsl
index 9991ba8..403c734 100644
--- a/weathereffects/graphics/assets/shaders/rain_shower_layer.agsl
+++ b/weathereffects/graphics/assets/shaders/rain_shower_layer.agsl
@@ -23,6 +23,7 @@ uniform float2 uvOffsetBgd;
 uniform float2 uvScaleBgd;
 uniform float time;
 uniform float screenAspectRatio;
+uniform float gridScale;
 uniform float2 screenSize;
 uniform half intensity;
 
@@ -40,7 +41,7 @@ const float rainVisibility = 0.4;
  */
 vec3 drawSplashes(vec2 uv, vec2 fragCoord, vec3 color) {
     /** 1. Make a grid */
-    vec2 gridSize = vec2(15., 15.);
+    vec2 gridSize = vec2(15., 15.) * gridScale;
     // Aspect ratio impacts visible cells.
     gridSize.y /= screenAspectRatio;
     // Scale the UV to allocate number of rows and columns.
@@ -76,7 +77,7 @@ vec3 drawSplashes(vec2 uv, vec2 fragCoord, vec3 color) {
 
     float splash = drawSplash(cellUv, cellTime) * smoothstep(0., 0.45, intensity);
 
-    return normalBlendWithWhiteSrc(color, splash);
+    return screenBlend(color, splash);
 }
 
 vec4 main(float2 fragCoord) {
@@ -91,24 +92,24 @@ vec4 main(float2 fragCoord) {
 
     // Add rotation for the rain (as a default sin(time * 0.05) can be used).
     float variation = wiggle(time - uv.y * 1.1, 0.10);
-    uv = rotateAroundPoint(uv, vec2(0.5, -1.42), variation * PI / 9.);
+    vec2 uvRot = rotateAroundPoint(uv, vec2(0.5, -1.42), variation * PI / 9.);
 
     // 1. Generate a layer of rain behind the subject.
     Rain rain = generateRain(
-          uv,
+          uvRot,
           screenAspectRatio,
           time * 18.,
-          /* Grid size = */ vec2(20.0, 2.0),
+          /* Grid size = */ vec2(20.0, 2.0) * gridScale,
           intensity);
 
     color.rgb = mix(color.rgb, highlightColor, rainVisibility * rain.dropMask);
 
     // 2. Generate mid layer of rain behind the subject.
     rain = generateRain(
-          uv,
+          uvRot,
           screenAspectRatio,
           time * 21.4,
-          /* Grid size = */ vec2(30.0, 4.0),
+          /* Grid size = */ vec2(30.0, 4.0) * gridScale,
           intensity);
 
     // 3. Blend those layers.
@@ -122,10 +123,10 @@ vec4 main(float2 fragCoord) {
 
     // 6. Generate a layer of rain in front of the subject (bigger and faster).
     rain = generateRain(
-          uv,
+          uvRot,
           screenAspectRatio,
           time * 27.,
-          /* Grid size = */ vec2(8.0, 3.0),
+          /* Grid size = */ vec2(8.0, 3.0) * gridScale,
           intensity);
 
     // Closer rain drops are less visible.
diff --git a/weathereffects/graphics/assets/shaders/rain_splash.agsl b/weathereffects/graphics/assets/shaders/rain_splash.agsl
index 3fdb6cc..31fdb48 100644
--- a/weathereffects/graphics/assets/shaders/rain_splash.agsl
+++ b/weathereffects/graphics/assets/shaders/rain_splash.agsl
@@ -21,8 +21,9 @@
  */
 float drawSplash(vec2 cellUv, float cellTime) {
     /** 0. Adjust UV and time. */
-    cellUv = cellUv * 0.5;
-    cellUv += 0.1;
+    cellUv *= 0.5;
+    // Moves drop a little bit down on the its grid cell.
+    cellUv.y += 0.15;
     float t = 0.408 + cellTime * 4.;
 
     /** 1. Start of drawing a splash */
diff --git a/weathereffects/graphics/assets/shaders/snow.agsl b/weathereffects/graphics/assets/shaders/snow.agsl
index f3997af..79da6c8 100644
--- a/weathereffects/graphics/assets/shaders/snow.agsl
+++ b/weathereffects/graphics/assets/shaders/snow.agsl
@@ -26,8 +26,8 @@ const mat2 rot45 = mat2(
 
 uniform half intensity;
 
-const float farthestSnowLayerWiggleSpeed = 5.8;
-const float closestSnowLayerWiggleSpeed = 2.6;
+const float farthestSnowLayerWiggleSpeed = 2.18;
+const float closestSnowLayerWiggleSpeed = 0.9;
 
 /**
  * Generates snow flakes.
@@ -58,7 +58,7 @@ Snow generateSnow(
 
     /* Grid. */
     // Increase the last number to make each layer more separate from the previous one.
-    float depth = 0.65 + layerIndex * 0.41;
+    float depth = 0.65 + layerIndex * 0.37;
     float speedAdj = 1. + layerIndex * 0.15;
     float layerR = idGenerator(layerIndex);
     snowGridSize *= depth;
@@ -66,7 +66,7 @@ Snow generateSnow(
     // Number of rows and columns (each one is a cell, a drop).
     float cellAspectRatio = snowGridSize.x / snowGridSize.y;
     // Aspect ratio impacts visible cells.
-    snowGridSize.y /= screenAspectRatio;
+    uv.y /= screenAspectRatio;
     // Skew uv.x so it goes to left or right
     uv.x += uv.y * (0.8 * layerR - 0.4);
     // scale the UV to allocate number of rows and columns.
@@ -79,7 +79,7 @@ Snow generateSnow(
     // Generate column id, to offset columns vertically (so snow flakes are not aligned).
     float columnId = idGenerator(floor(gridUv.x));
     // Have time affect the position of each column as well.
-    gridUv.y += columnId * 2.6 + time * 0.09 * (1 - columnId);
+    gridUv.y += columnId * 2.6 + time * 0.19 * (1 - columnId);
 
     /* Cell. */
     // Get the cell ID based on the grid position. Value from 0 to 1.
@@ -145,9 +145,12 @@ Snow generateSnow(
     float snowFlakePosUncorrected = (cellUv.x - horizontalWiggle);
 
     // Calculate snow flake.
-    vec2 snowFlakeShape = vec2(1., 1.2);
-    vec2 snowFlakePos = vec2(snowFlakePosUncorrected / cellAspectRatio, cellUv.y);
-    snowFlakePos -= vec2(0., uv.y - 0.5) * cellId;
+    vec2 snowFlakeShape = vec2(0.28, 0.26);
+    vec2 snowFlakePos = vec2(snowFlakePosUncorrected, cellUv.y * cellAspectRatio);
+    snowFlakePos -= vec2(
+            0.,
+            (uv.y - 0.5 / screenAspectRatio)  - cellUv.y / snowGridSize.y
+        ) * screenAspectRatio;
     snowFlakePos *= snowFlakeShape * decreaseFactor;
     vec2 snowFlakeShapeVariation = vec2(0.055) * // max variation
         vec2((cellId * 2. - 1.), // random A based on cell ID
diff --git a/weathereffects/graphics/assets/shaders/snow_effect.agsl b/weathereffects/graphics/assets/shaders/snow_effect.agsl
index a6b231a..d88de3c 100644
--- a/weathereffects/graphics/assets/shaders/snow_effect.agsl
+++ b/weathereffects/graphics/assets/shaders/snow_effect.agsl
@@ -22,6 +22,7 @@ uniform float2 uvOffsetFgd;
 uniform float2 uvScaleFgd;
 uniform float2 uvOffsetBgd;
 uniform float2 uvScaleBgd;
+uniform float2 gridSize;
 uniform float time;
 uniform float screenAspectRatio;
 uniform float2 screenSize;
@@ -71,8 +72,7 @@ vec4 main(float2 fragCoord) {
             uv,
             screenAspectRatio,
             time,
-            // TODO: adjust grid size based on aspect ratio.
-            /* Grid size = */ vec2(7., 1.5),
+            gridSize,
             /* layer number = */ i,
             closestSnowLayerIndex,
             farthestSnowLayerIndex);
@@ -111,8 +111,7 @@ vec4 main(float2 fragCoord) {
             uv,
             screenAspectRatio,
             time,
-            // TODO: adjust grid size based on aspect ratio
-            /* Grid size = */ vec2(7., 1.5),
+            gridSize,
             /* layer number = */ i,
             closestSnowLayerIndex,
             farthestSnowLayerIndex);
diff --git a/weathereffects/graphics/assets/shaders/sun_effect.agsl b/weathereffects/graphics/assets/shaders/sun_effect.agsl
new file mode 100644
index 0000000..6eb7505
--- /dev/null
+++ b/weathereffects/graphics/assets/shaders/sun_effect.agsl
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
+uniform shader foreground;
+uniform shader background;
+uniform float2 uvOffsetFgd;
+uniform float2 uvScaleFgd;
+uniform float2 uvOffsetBgd;
+uniform float2 uvScaleBgd;
+uniform float screenAspectRatio;
+uniform float2 screenSize;
+uniform float time;
+uniform float intensity;
+
+#include "shaders/constants.agsl"
+#include "shaders/utils.agsl"
+#include "shaders/simplex2d.agsl"
+
+#include "shaders/lens_flare.agsl"
+
+vec4 main(float2 fragCoord) {
+    float2 uv = fragCoord / screenSize;
+    uv.y /= screenAspectRatio;
+
+    vec4 colorForeground = foreground.eval(fragCoord * uvScaleFgd + uvOffsetFgd);
+    vec4 color = background.eval(fragCoord * uvScaleBgd + uvOffsetBgd);
+
+    // TODO(b/347299395): to add flare and sun effect background
+
+    // add foreground
+    color.rgb = normalBlend(color.rgb, colorForeground.rgb, colorForeground.a);
+
+    // TODO(b/347299395): to add flare and sun effect foreground
+
+    return color;
+}
diff --git a/weathereffects/graphics/assets/shaders/utils.agsl b/weathereffects/graphics/assets/shaders/utils.agsl
index 1749a91..05f40bb 100644
--- a/weathereffects/graphics/assets/shaders/utils.agsl
+++ b/weathereffects/graphics/assets/shaders/utils.agsl
@@ -90,7 +90,7 @@ vec3 normalBlend(vec3 b, vec3 f, float o) {
     return b * (1. - o) + f;
 }
 
-vec3 normalBlendWithWhiteSrc(vec3 b, float o) {
+vec3 screenBlend(vec3 b, float o) {
     return b * (1. - o) + o;
 }
 
diff --git a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/FrameBuffer.kt b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/FrameBuffer.kt
index dc0ea6c..11b6440 100644
--- a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/FrameBuffer.kt
+++ b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/FrameBuffer.kt
@@ -87,8 +87,10 @@ class FrameBuffer(width: Int, height: Int, format: Int = HardwareBuffer.RGBA_888
             if (result.status == HardwareBufferRenderer.RenderResult.SUCCESS) {
                 result.fence.await(Duration.ofMillis(RESULT_FENCE_TIME_OUT))
                 if (!buffer.isClosed) {
-                    Bitmap.wrapHardwareBuffer(buffer, colorSpace)?.let {
-                        callbackExecutor.execute { onImageReady.invoke(it) }
+                    if (!buffer.isClosed) {
+                        Bitmap.wrapHardwareBuffer(buffer, colorSpace)?.let {
+                            callbackExecutor.execute { onImageReady.invoke(it) }
+                        }
                     }
                 }
             }
diff --git a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/WeatherEffect.kt b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/WeatherEffect.kt
index 0517fa3..0761d3c 100644
--- a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/WeatherEffect.kt
+++ b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/WeatherEffect.kt
@@ -16,6 +16,7 @@
 
 package com.google.android.wallpaper.weathereffects.graphics
 
+import android.graphics.Bitmap
 import android.graphics.Canvas
 import android.util.SizeF
 import androidx.annotation.FloatRange
@@ -59,4 +60,16 @@ interface WeatherEffect {
      * @param intensity [0, 1] the intensity of the weather effect.
      */
     fun setIntensity(@FloatRange(from = 0.0, to = 1.0) intensity: Float)
+
+    /**
+     * Reuse current shader but change background, foreground
+     *
+     * @param foreground A bitmap containing the foreground of the image
+     * @param background A bitmap containing the background of the image
+     */
+    fun setBitmaps(foreground: Bitmap, background: Bitmap)
+
+    companion object {
+        val DEFAULT_INTENSITY = 1f
+    }
 }
diff --git a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/fog/FogEffect.kt b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/fog/FogEffect.kt
index 5a189c5..73d870c 100644
--- a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/fog/FogEffect.kt
+++ b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/fog/FogEffect.kt
@@ -16,22 +16,28 @@
 
 package com.google.android.wallpaper.weathereffects.graphics.fog
 
+import android.graphics.Bitmap
 import android.graphics.BitmapShader
 import android.graphics.Canvas
 import android.graphics.Paint
 import android.graphics.Shader
 import android.util.SizeF
 import com.google.android.wallpaper.weathereffects.graphics.WeatherEffect
+import com.google.android.wallpaper.weathereffects.graphics.WeatherEffect.Companion.DEFAULT_INTENSITY
 import com.google.android.wallpaper.weathereffects.graphics.utils.GraphicsUtils
 import com.google.android.wallpaper.weathereffects.graphics.utils.ImageCrop
+import com.google.android.wallpaper.weathereffects.graphics.utils.TimeUtils
 import kotlin.math.sin
 import kotlin.random.Random
 
 /** Defines and generates the fog weather effect animation. */
 class FogEffect(
     private val fogConfig: FogEffectConfig,
+    private var foreground: Bitmap,
+    private var background: Bitmap,
+    private var intensity: Float = DEFAULT_INTENSITY,
     /** The initial size of the surface where the effect will be shown. */
-    surfaceSize: SizeF
+    private var surfaceSize: SizeF
 ) : WeatherEffect {
 
     private val fogPaint = Paint().also { it.shader = fogConfig.colorGradingShader }
@@ -41,15 +47,20 @@ class FogEffect(
         updateTextureUniforms()
         adjustCropping(surfaceSize)
         prepareColorGrading()
-        setIntensity(fogConfig.intensity)
+        updateFogGridSize(surfaceSize)
+        setIntensity(intensity)
     }
 
-    override fun resize(newSurfaceSize: SizeF) = adjustCropping(newSurfaceSize)
+    override fun resize(newSurfaceSize: SizeF) {
+        adjustCropping(newSurfaceSize)
+        updateFogGridSize(newSurfaceSize)
+        surfaceSize = newSurfaceSize
+    }
 
     override fun update(deltaMillis: Long, frameTimeNanos: Long) {
-        val deltaTime = deltaMillis * MILLIS_TO_SECONDS
+        val deltaTime = TimeUtils.millisToSeconds(deltaMillis)
 
-        val time = frameTimeNanos.toFloat() * NANOS_TO_SECONDS
+        val time = TimeUtils.nanosToSeconds(frameTimeNanos)
         // Variation range [0.4, 1]. We don't want the variation to be 0.
         val variation = sin(0.06f * time + sin(0.18f * time)) * 0.3f + 0.7f
         elapsedTime += variation * deltaTime
@@ -59,7 +70,7 @@ class FogEffect(
         val variationFgd0 = 0.256f * sin(scaledElapsedTime)
         val variationFgd1 = 0.156f * sin(scaledElapsedTime) * sin(scaledElapsedTime)
         val timeFgd0 = 0.4f * elapsedTime * 5f + variationFgd0
-        val timeFgd1 = 0.03f * elapsedTime * 5f + variationFgd1
+        val timeFgd1 = 0.1f * elapsedTime * 5f + variationFgd1
 
         val variationBgd0 = 0.156f * sin((scaledElapsedTime + Math.PI.toFloat() / 2.0f))
         val variationBgd1 =
@@ -92,13 +103,27 @@ class FogEffect(
         )
     }
 
+    override fun setBitmaps(foreground: Bitmap, background: Bitmap) {
+        this.foreground = foreground
+        this.background = background
+        fogConfig.shader.setInputBuffer(
+            "background",
+            BitmapShader(background, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR)
+        )
+        fogConfig.shader.setInputBuffer(
+            "foreground",
+            BitmapShader(foreground, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR)
+        )
+        adjustCropping(surfaceSize)
+    }
+
     private fun adjustCropping(surfaceSize: SizeF) {
         val imageCropFgd =
             ImageCrop.centerCoverCrop(
                 surfaceSize.width,
                 surfaceSize.height,
-                fogConfig.foreground.width.toFloat(),
-                fogConfig.foreground.height.toFloat()
+                foreground.width.toFloat(),
+                foreground.height.toFloat()
             )
         fogConfig.shader.setFloatUniform(
             "uvOffsetFgd",
@@ -114,8 +139,8 @@ class FogEffect(
             ImageCrop.centerCoverCrop(
                 surfaceSize.width,
                 surfaceSize.height,
-                fogConfig.background.width.toFloat(),
-                fogConfig.background.height.toFloat()
+                background.width.toFloat(),
+                background.height.toFloat()
             )
         fogConfig.shader.setFloatUniform(
             "uvOffsetBgd",
@@ -137,12 +162,12 @@ class FogEffect(
     private fun updateTextureUniforms() {
         fogConfig.shader.setInputBuffer(
             "foreground",
-            BitmapShader(fogConfig.foreground, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR)
+            BitmapShader(foreground, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR)
         )
 
         fogConfig.shader.setInputBuffer(
             "background",
-            BitmapShader(fogConfig.background, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR)
+            BitmapShader(background, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR)
         )
 
         fogConfig.shader.setInputBuffer(
@@ -150,23 +175,11 @@ class FogEffect(
             BitmapShader(fogConfig.cloudsTexture, Shader.TileMode.REPEAT, Shader.TileMode.REPEAT)
         )
 
-        fogConfig.shader.setFloatUniform(
-            "cloudsSize",
-            fogConfig.cloudsTexture.width.toFloat(),
-            fogConfig.cloudsTexture.height.toFloat()
-        )
-
         fogConfig.shader.setInputBuffer(
             "fog",
             BitmapShader(fogConfig.fogTexture, Shader.TileMode.REPEAT, Shader.TileMode.REPEAT)
         )
 
-        fogConfig.shader.setFloatUniform(
-            "fogSize",
-            fogConfig.fogTexture.width.toFloat(),
-            fogConfig.fogTexture.height.toFloat()
-        )
-
         fogConfig.shader.setFloatUniform("pixelDensity", fogConfig.pixelDensity)
     }
 
@@ -181,9 +194,19 @@ class FogEffect(
         fogConfig.colorGradingShader.setFloatUniform("intensity", fogConfig.colorGradingIntensity)
     }
 
-    private companion object {
+    private fun updateFogGridSize(surfaceSize: SizeF) {
+        val widthScreenScale =
+            GraphicsUtils.computeDefaultGridSize(surfaceSize, fogConfig.pixelDensity)
+        fogConfig.shader.setFloatUniform(
+            "cloudsSize",
+            widthScreenScale * fogConfig.cloudsTexture.width.toFloat(),
+            widthScreenScale * fogConfig.cloudsTexture.height.toFloat()
+        )
 
-        private const val MILLIS_TO_SECONDS = 1 / 1000f
-        private const val NANOS_TO_SECONDS = 1 / 1_000_000_000f
+        fogConfig.shader.setFloatUniform(
+            "fogSize",
+            widthScreenScale * fogConfig.fogTexture.width.toFloat(),
+            widthScreenScale * fogConfig.fogTexture.height.toFloat()
+        )
     }
 }
diff --git a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/fog/FogEffectConfig.kt b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/fog/FogEffectConfig.kt
index 35f3073..4ac9b06 100644
--- a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/fog/FogEffectConfig.kt
+++ b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/fog/FogEffectConfig.kt
@@ -40,14 +40,8 @@ data class FogEffectConfig(
      * tileable, and at least 16-bit per channel for render quality.
      */
     val fogTexture: Bitmap,
-    /** A bitmap containing the foreground of the image. */
-    val foreground: Bitmap,
-    /** A bitmap containing the background of the image. */
-    val background: Bitmap,
     /** Pixel density of the display. Used for dithering. */
     val pixelDensity: Float,
-    /** The amount of the fog. This contributes to the color grading as well. */
-    @FloatRange(from = 0.0, to = 1.0) val intensity: Float,
     /** The intensity of the color grading. 0: no color grading, 1: color grading in full effect. */
     @FloatRange(from = 0.0, to = 1.0) val colorGradingIntensity: Float,
 ) {
@@ -55,30 +49,22 @@ data class FogEffectConfig(
      * Constructor for [FogEffectConfig].
      *
      * @param assets the application [AssetManager].
-     * @param foreground a bitmap containing the foreground of the image.
-     * @param background a bitmap containing the background of the image.
      * @param pixelDensity pixel density of the display.
-     * @param intensity initial intensity that affects the amount of fog and color grading. Expected
-     *   range is [0, 1]. You can always change the intensity dynamically. Defaults to 1.
      */
     constructor(
         assets: AssetManager,
-        foreground: Bitmap,
-        background: Bitmap,
         pixelDensity: Float,
-        intensity: Float = DEFAULT_INTENSITY,
     ) : this(
         shader = GraphicsUtils.loadShader(assets, SHADER_PATH),
         colorGradingShader = GraphicsUtils.loadShader(assets, COLOR_GRADING_SHADER_PATH),
         lut = GraphicsUtils.loadTexture(assets, LOOKUP_TABLE_TEXTURE_PATH),
-        cloudsTexture = GraphicsUtils.loadTexture(assets, CLOUDS_TEXTURE_PATH)
+        cloudsTexture =
+            GraphicsUtils.loadTexture(assets, CLOUDS_TEXTURE_PATH)
                 ?: throw RuntimeException("Clouds texture is missing."),
-        fogTexture = GraphicsUtils.loadTexture(assets, FOG_TEXTURE_PATH)
+        fogTexture =
+            GraphicsUtils.loadTexture(assets, FOG_TEXTURE_PATH)
                 ?: throw RuntimeException("Fog texture is missing."),
-        foreground,
-        background,
         pixelDensity,
-        intensity,
         COLOR_GRADING_INTENSITY
     )
 
@@ -88,7 +74,6 @@ data class FogEffectConfig(
         private const val LOOKUP_TABLE_TEXTURE_PATH = "textures/lut_rain_and_fog.png"
         private const val CLOUDS_TEXTURE_PATH = "textures/clouds.png"
         private const val FOG_TEXTURE_PATH = "textures/fog.png"
-        private const val DEFAULT_INTENSITY = 1f
         private const val COLOR_GRADING_INTENSITY = 0.7f
     }
 }
diff --git a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/none/NoEffect.kt b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/none/NoEffect.kt
index 592b627..d1aedcd 100644
--- a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/none/NoEffect.kt
+++ b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/none/NoEffect.kt
@@ -23,7 +23,7 @@ import com.google.android.wallpaper.weathereffects.graphics.WeatherEffect
 import com.google.android.wallpaper.weathereffects.graphics.utils.MatrixUtils
 
 /** Simply draws foreground and background images with no weather effect. */
-class NoEffect(val foreground: Bitmap, val background: Bitmap, private var surfaceSize: SizeF) :
+class NoEffect(var foreground: Bitmap, var background: Bitmap, private var surfaceSize: SizeF) :
     WeatherEffect {
     override fun resize(newSurfaceSize: SizeF) {
         surfaceSize = newSurfaceSize
@@ -40,7 +40,6 @@ class NoEffect(val foreground: Bitmap, val background: Bitmap, private var surfa
             ),
             null
         )
-
         canvas.drawBitmap(
             foreground,
             MatrixUtils.centerCropMatrix(
@@ -56,4 +55,9 @@ class NoEffect(val foreground: Bitmap, val background: Bitmap, private var surfa
     override fun release() {}
 
     override fun setIntensity(intensity: Float) {}
+
+    override fun setBitmaps(foreground: Bitmap, background: Bitmap) {
+        this.foreground = foreground
+        this.background = background
+    }
 }
diff --git a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/rain/RainEffect.kt b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/rain/RainEffect.kt
index fe1776a..c554b5e 100644
--- a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/rain/RainEffect.kt
+++ b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/rain/RainEffect.kt
@@ -16,6 +16,7 @@
 
 package com.google.android.wallpaper.weathereffects.graphics.rain
 
+import android.graphics.Bitmap
 import android.graphics.BitmapShader
 import android.graphics.Canvas
 import android.graphics.Color
@@ -25,9 +26,11 @@ import android.graphics.Shader
 import android.util.SizeF
 import com.google.android.wallpaper.weathereffects.graphics.FrameBuffer
 import com.google.android.wallpaper.weathereffects.graphics.WeatherEffect
+import com.google.android.wallpaper.weathereffects.graphics.WeatherEffect.Companion.DEFAULT_INTENSITY
 import com.google.android.wallpaper.weathereffects.graphics.utils.GraphicsUtils
 import com.google.android.wallpaper.weathereffects.graphics.utils.ImageCrop
 import com.google.android.wallpaper.weathereffects.graphics.utils.SolidColorShader
+import com.google.android.wallpaper.weathereffects.graphics.utils.TimeUtils
 import java.util.concurrent.Executor
 import kotlin.random.Random
 
@@ -35,16 +38,20 @@ import kotlin.random.Random
 class RainEffect(
     /** The config of the rain effect. */
     private val rainConfig: RainEffectConfig,
+    private var foreground: Bitmap,
+    private var background: Bitmap,
+    private var intensity: Float = DEFAULT_INTENSITY,
     /** The initial size of the surface where the effect will be shown. */
-    surfaceSize: SizeF,
+    private var surfaceSize: SizeF,
     private val mainExecutor: Executor
 ) : WeatherEffect {
 
     private val rainPaint = Paint().also { it.shader = rainConfig.colorGradingShader }
+
     // Set blur effect to reduce the outline noise. No need to set blur effect every time we
     // re-generate the outline buffer.
-    private val outlineBuffer =
-        FrameBuffer(rainConfig.background.width, rainConfig.background.height).apply {
+    private var outlineBuffer =
+        FrameBuffer(background.width, background.height).apply {
             setRenderEffect(RenderEffect.createBlurEffect(2f, 2f, Shader.TileMode.CLAMP))
         }
     private val outlineBufferPaint = Paint().also { it.shader = rainConfig.outlineShader }
@@ -55,16 +62,21 @@ class RainEffect(
         updateTextureUniforms()
         adjustCropping(surfaceSize)
         prepareColorGrading()
-        setIntensity(rainConfig.intensity)
+        updateRainGridSize(surfaceSize)
+        setIntensity(intensity)
     }
 
-    override fun resize(newSurfaceSize: SizeF) = adjustCropping(newSurfaceSize)
+    override fun resize(newSurfaceSize: SizeF) {
+        adjustCropping(newSurfaceSize)
+        updateRainGridSize(newSurfaceSize)
+        surfaceSize = newSurfaceSize
+    }
 
     override fun update(deltaMillis: Long, frameTimeNanos: Long) {
-        elapsedTime += deltaMillis * MILLIS_TO_SECONDS
+        elapsedTime += TimeUtils.millisToSeconds(deltaMillis)
 
         rainConfig.rainShowerShader.setFloatUniform("time", elapsedTime)
-        rainConfig.glassRainShader.setFloatUniform("time", elapsedTime * 0.7f)
+        rainConfig.glassRainShader.setFloatUniform("time", elapsedTime)
 
         rainConfig.glassRainShader.setInputShader("texture", rainConfig.rainShowerShader)
         rainConfig.colorGradingShader.setInputShader("texture", rainConfig.glassRainShader)
@@ -85,7 +97,7 @@ class RainEffect(
 
     override fun setIntensity(intensity: Float) {
         rainConfig.rainShowerShader.setFloatUniform("intensity", intensity)
-        rainConfig.glassRainShader.setFloatUniform("intensity", intensity * 0.6f)
+        rainConfig.glassRainShader.setFloatUniform("intensity", intensity)
         rainConfig.colorGradingShader.setFloatUniform(
             "intensity",
             rainConfig.colorGradingIntensity * intensity
@@ -97,13 +109,27 @@ class RainEffect(
         createOutlineBuffer()
     }
 
+    override fun setBitmaps(foreground: Bitmap, background: Bitmap) {
+        this.foreground = foreground
+        this.background = background
+        outlineBuffer =
+            FrameBuffer(background.width, background.height).apply {
+                setRenderEffect(RenderEffect.createBlurEffect(2f, 2f, Shader.TileMode.CLAMP))
+            }
+        adjustCropping(surfaceSize)
+        updateTextureUniforms()
+
+        // Need to recreate the outline buffer as the outlineBuffer has changed due to background
+        createOutlineBuffer()
+    }
+
     private fun adjustCropping(surfaceSize: SizeF) {
         val imageCropFgd =
             ImageCrop.centerCoverCrop(
                 surfaceSize.width,
                 surfaceSize.height,
-                rainConfig.foreground.width.toFloat(),
-                rainConfig.foreground.height.toFloat()
+                foreground.width.toFloat(),
+                foreground.height.toFloat()
             )
         rainConfig.rainShowerShader.setFloatUniform(
             "uvOffsetFgd",
@@ -120,8 +146,8 @@ class RainEffect(
             ImageCrop.centerCoverCrop(
                 surfaceSize.width,
                 surfaceSize.height,
-                rainConfig.background.width.toFloat(),
-                rainConfig.background.height.toFloat()
+                background.width.toFloat(),
+                background.height.toFloat()
             )
         rainConfig.rainShowerShader.setFloatUniform(
             "uvOffsetBgd",
@@ -152,13 +178,13 @@ class RainEffect(
 
     private fun updateTextureUniforms() {
         val foregroundBuffer =
-            BitmapShader(rainConfig.foreground, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR)
+            BitmapShader(foreground, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR)
         rainConfig.rainShowerShader.setInputBuffer("foreground", foregroundBuffer)
         rainConfig.outlineShader.setInputBuffer("texture", foregroundBuffer)
 
         rainConfig.rainShowerShader.setInputBuffer(
             "background",
-            BitmapShader(rainConfig.background, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR)
+            BitmapShader(background, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR)
         )
     }
 
@@ -190,7 +216,10 @@ class RainEffect(
         }
     }
 
-    private companion object {
-        private const val MILLIS_TO_SECONDS = 1 / 1000f
+    private fun updateRainGridSize(surfaceSize: SizeF) {
+        val widthScreenScale =
+            GraphicsUtils.computeDefaultGridSize(surfaceSize, rainConfig.pixelDensity)
+        rainConfig.rainShowerShader.setFloatUniform("gridScale", widthScreenScale)
+        rainConfig.glassRainShader.setFloatUniform("gridScale", widthScreenScale)
     }
 }
diff --git a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/rain/RainEffectConfig.kt b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/rain/RainEffectConfig.kt
index 11782c4..1567db3 100644
--- a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/rain/RainEffectConfig.kt
+++ b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/rain/RainEffectConfig.kt
@@ -34,38 +34,27 @@ data class RainEffectConfig(
     val outlineShader: RuntimeShader,
     /** The main lut (color grading) for the effect. */
     val lut: Bitmap?,
-    /** A bitmap containing the foreground of the image. */
-    val foreground: Bitmap,
-    /** A bitmap containing the background of the image. */
-    val background: Bitmap,
-    /** The amount of the rain. This contributes to the color grading as well. */
-    @FloatRange(from = 0.0, to = 1.0) val intensity: Float,
+    /** Pixel density of the display. Used for dithering. */
+    val pixelDensity: Float,
     /** The intensity of the color grading. 0: no color grading, 1: color grading in full effect. */
     @FloatRange(from = 0.0, to = 1.0) val colorGradingIntensity: Float,
 ) {
     /**
      * Constructor for [RainEffectConfig].
      *
-     * @param assets asset manager.
-     * @param foreground a bitmap containing the foreground of the image.
-     * @param background a bitmap containing the background of the image.
-     * @param intensity initial intensity that affects the amount of rain and color grading.
-     *   Expected range is [0, 1]. You can always change the intensity dynamically. Defaults to 1.
+     * @param assets asset manager,
+     * @param pixelDensity pixel density of the display.
      */
     constructor(
         assets: AssetManager,
-        foreground: Bitmap,
-        background: Bitmap,
-        intensity: Float = DEFAULT_INTENSITY,
+        pixelDensity: Float,
     ) : this(
         rainShowerShader = GraphicsUtils.loadShader(assets, RAIN_SHOWER_LAYER_SHADER_PATH),
         glassRainShader = GraphicsUtils.loadShader(assets, GLASS_RAIN_LAYER_SHADER_PATH),
         colorGradingShader = GraphicsUtils.loadShader(assets, COLOR_GRADING_SHADER_PATH),
         outlineShader = GraphicsUtils.loadShader(assets, OUTLINE_SHADER_PATH),
         lut = GraphicsUtils.loadTexture(assets, LOOKUP_TABLE_TEXTURE_PATH),
-        foreground,
-        background,
-        intensity,
+        pixelDensity,
         COLOR_GRADING_INTENSITY
     )
 
@@ -75,7 +64,6 @@ data class RainEffectConfig(
         private const val COLOR_GRADING_SHADER_PATH = "shaders/color_grading_lut.agsl"
         private const val OUTLINE_SHADER_PATH = "shaders/outline.agsl"
         private const val LOOKUP_TABLE_TEXTURE_PATH = "textures/lut_rain_and_fog.png"
-        private const val DEFAULT_INTENSITY = 1f
         private const val COLOR_GRADING_INTENSITY = 0.7f
     }
 }
diff --git a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/snow/SnowEffect.kt b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/snow/SnowEffect.kt
index 315f632..cec6cc2 100644
--- a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/snow/SnowEffect.kt
+++ b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/snow/SnowEffect.kt
@@ -16,6 +16,7 @@
 
 package com.google.android.wallpaper.weathereffects.graphics.snow
 
+import android.graphics.Bitmap
 import android.graphics.BitmapShader
 import android.graphics.Canvas
 import android.graphics.Paint
@@ -24,9 +25,11 @@ import android.graphics.Shader
 import android.util.SizeF
 import com.google.android.wallpaper.weathereffects.graphics.FrameBuffer
 import com.google.android.wallpaper.weathereffects.graphics.WeatherEffect
+import com.google.android.wallpaper.weathereffects.graphics.WeatherEffect.Companion.DEFAULT_INTENSITY
 import com.google.android.wallpaper.weathereffects.graphics.utils.GraphicsUtils
 import com.google.android.wallpaper.weathereffects.graphics.utils.ImageCrop
 import com.google.android.wallpaper.weathereffects.graphics.utils.MathUtils
+import com.google.android.wallpaper.weathereffects.graphics.utils.TimeUtils
 import java.util.concurrent.Executor
 import kotlin.random.Random
 
@@ -34,8 +37,11 @@ import kotlin.random.Random
 class SnowEffect(
     /** The config of the snow effect. */
     private val snowConfig: SnowEffectConfig,
+    private var foreground: Bitmap,
+    private var background: Bitmap,
+    private var intensity: Float = DEFAULT_INTENSITY,
     /** The initial size of the surface where the effect will be shown. */
-    surfaceSize: SizeF,
+    private var surfaceSize: SizeF,
     /** App main executor. */
     private val mainExecutor: Executor
 ) : WeatherEffect {
@@ -44,7 +50,7 @@ class SnowEffect(
     private val snowPaint = Paint().also { it.shader = snowConfig.colorGradingShader }
     private var elapsedTime: Float = 0f
 
-    private val frameBuffer = FrameBuffer(snowConfig.background.width, snowConfig.background.height)
+    private var frameBuffer = FrameBuffer(background.width, background.height)
     private val frameBufferPaint = Paint().also { it.shader = snowConfig.accumulatedSnowShader }
 
     init {
@@ -52,16 +58,21 @@ class SnowEffect(
         updateTextureUniforms()
         adjustCropping(surfaceSize)
         prepareColorGrading()
-        setIntensity(snowConfig.intensity)
+        updateSnowGridSize(surfaceSize)
+        setIntensity(intensity)
 
         // Generate accumulated snow at the end after we updated all the uniforms.
         generateAccumulatedSnow()
     }
 
-    override fun resize(newSurfaceSize: SizeF) = adjustCropping(newSurfaceSize)
+    override fun resize(newSurfaceSize: SizeF) {
+        adjustCropping(newSurfaceSize)
+        updateSnowGridSize(newSurfaceSize)
+        surfaceSize = newSurfaceSize
+    }
 
     override fun update(deltaMillis: Long, frameTimeNanos: Long) {
-        elapsedTime += snowSpeed * deltaMillis * MILLIS_TO_SECONDS
+        elapsedTime += snowSpeed * TimeUtils.millisToSeconds(deltaMillis)
 
         snowConfig.shader.setFloatUniform("time", elapsedTime)
         snowConfig.colorGradingShader.setInputShader("texture", snowConfig.shader)
@@ -100,13 +111,31 @@ class SnowEffect(
         generateAccumulatedSnow()
     }
 
+    override fun setBitmaps(foreground: Bitmap, background: Bitmap) {
+        this.foreground = foreground
+        this.background = background
+        frameBuffer = FrameBuffer(background.width, background.height)
+        snowConfig.shader.setInputBuffer(
+            "background",
+            BitmapShader(background, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR)
+        )
+        snowConfig.shader.setInputBuffer(
+            "foreground",
+            BitmapShader(foreground, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR)
+        )
+        adjustCropping(surfaceSize)
+        // generateAccumulatedSnow needs foreground for accumulatedSnowShader, and needs frameBuffer
+        // which is also changed with background
+        generateAccumulatedSnow()
+    }
+
     private fun adjustCropping(surfaceSize: SizeF) {
         val imageCropFgd =
             ImageCrop.centerCoverCrop(
                 surfaceSize.width,
                 surfaceSize.height,
-                snowConfig.foreground.width.toFloat(),
-                snowConfig.foreground.height.toFloat()
+                foreground.width.toFloat(),
+                foreground.height.toFloat()
             )
         snowConfig.shader.setFloatUniform(
             "uvOffsetFgd",
@@ -122,8 +151,8 @@ class SnowEffect(
             ImageCrop.centerCoverCrop(
                 surfaceSize.width,
                 surfaceSize.height,
-                snowConfig.background.width.toFloat(),
-                snowConfig.background.height.toFloat()
+                background.width.toFloat(),
+                background.height.toFloat()
             )
         snowConfig.shader.setFloatUniform(
             "uvOffsetBgd",
@@ -145,12 +174,12 @@ class SnowEffect(
     private fun updateTextureUniforms() {
         snowConfig.shader.setInputBuffer(
             "foreground",
-            BitmapShader(snowConfig.foreground, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR)
+            BitmapShader(foreground, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR)
         )
 
         snowConfig.shader.setInputBuffer(
             "background",
-            BitmapShader(snowConfig.background, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR)
+            BitmapShader(background, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR)
         )
 
         snowConfig.shader.setInputBuffer(
@@ -177,7 +206,7 @@ class SnowEffect(
         )
         snowConfig.accumulatedSnowShader.setInputBuffer(
             "foreground",
-            BitmapShader(snowConfig.foreground, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR)
+            BitmapShader(foreground, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR)
         )
         renderingCanvas.drawPaint(frameBufferPaint)
         frameBuffer.endDrawing()
@@ -193,7 +222,8 @@ class SnowEffect(
         )
     }
 
-    private companion object {
-        private const val MILLIS_TO_SECONDS = 1 / 1000f
+    private fun updateSnowGridSize(surfaceSize: SizeF) {
+        val gridSize = GraphicsUtils.computeDefaultGridSize(surfaceSize, snowConfig.pixelDensity)
+        snowConfig.shader.setFloatUniform("gridSize", 7 * gridSize, 2f * gridSize)
     }
 }
diff --git a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/snow/SnowEffectConfig.kt b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/snow/SnowEffectConfig.kt
index 06e79c8..76b4892 100644
--- a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/snow/SnowEffectConfig.kt
+++ b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/snow/SnowEffectConfig.kt
@@ -16,7 +16,7 @@
 
 package com.google.android.wallpaper.weathereffects.graphics.snow
 
-import android.content.Context
+import android.content.res.AssetManager
 import android.graphics.Bitmap
 import android.graphics.RuntimeShader
 import androidx.annotation.FloatRange
@@ -37,12 +37,8 @@ data class SnowEffectConfig(
     val noiseTexture: Bitmap,
     /** The main lut (color grading) for the effect. */
     val lut: Bitmap?,
-    /** A bitmap containing the foreground of the image. */
-    val foreground: Bitmap,
-    /** A bitmap containing the background of the image. */
-    val background: Bitmap,
-    /** The amount of the snow flakes. This contributes to the color grading as well. */
-    @FloatRange(from = 0.0, to = 1.0) val intensity: Float,
+    /** Pixel density of the display. Used for dithering. */
+    val pixelDensity: Float,
     /** The intensity of the color grading. 0: no color grading, 1: color grading in full effect. */
     @FloatRange(from = 0.0, to = 1.0) val colorGradingIntensity: Float,
     /** Max thickness for the accumulated snow. */
@@ -51,28 +47,22 @@ data class SnowEffectConfig(
     /**
      * Constructor for [SnowEffectConfig].
      *
-     * @param context the application context.
-     * @param foreground a bitmap containing the foreground of the image.
-     * @param background a bitmap containing the background of the image.
-     * @param intensity initial intensity that affects the amount of snow flakes and color grading.
-     *   Expected range is [0, 1]. You can always change the intensity dynamically. Defaults to 1.
+     * @param assets asset manager,
+     * @param pixelDensity pixel density of the display. Expected range is [0, 1]. You can always
+     *   change the intensity dynamically. Defaults to 1.
      */
     constructor(
-        context: Context,
-        foreground: Bitmap,
-        background: Bitmap,
-        intensity: Float = DEFAULT_INTENSITY,
+        assets: AssetManager,
+        pixelDensity: Float,
     ) : this(
-        shader = GraphicsUtils.loadShader(context.assets, SHADER_PATH),
-        accumulatedSnowShader =
-            GraphicsUtils.loadShader(context.assets, ACCUMULATED_SNOW_SHADER_PATH),
-        colorGradingShader = GraphicsUtils.loadShader(context.assets, COLOR_GRADING_SHADER_PATH),
-        noiseTexture = GraphicsUtils.loadTexture(context.assets, NOISE_TEXTURE_PATH)
+        shader = GraphicsUtils.loadShader(assets, SHADER_PATH),
+        accumulatedSnowShader = GraphicsUtils.loadShader(assets, ACCUMULATED_SNOW_SHADER_PATH),
+        colorGradingShader = GraphicsUtils.loadShader(assets, COLOR_GRADING_SHADER_PATH),
+        noiseTexture =
+            GraphicsUtils.loadTexture(assets, NOISE_TEXTURE_PATH)
                 ?: throw RuntimeException("Noise texture is missing."),
-        lut = GraphicsUtils.loadTexture(context.assets, LOOKUP_TABLE_TEXTURE_PATH),
-        foreground,
-        background,
-        intensity,
+        lut = GraphicsUtils.loadTexture(assets, LOOKUP_TABLE_TEXTURE_PATH),
+        pixelDensity,
         COLOR_GRADING_INTENSITY,
         MAX_SNOW_THICKNESS
     )
@@ -83,7 +73,6 @@ data class SnowEffectConfig(
         private const val COLOR_GRADING_SHADER_PATH = "shaders/color_grading_lut.agsl"
         private const val NOISE_TEXTURE_PATH = "textures/clouds.png"
         private const val LOOKUP_TABLE_TEXTURE_PATH = "textures/lut_rain_and_fog.png"
-        private const val DEFAULT_INTENSITY = 1f
         private const val COLOR_GRADING_INTENSITY = 0.7f
         private const val MAX_SNOW_THICKNESS = 10f
     }
diff --git a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/sun/SunEffect.kt b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/sun/SunEffect.kt
new file mode 100644
index 0000000..29ffe5d
--- /dev/null
+++ b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/sun/SunEffect.kt
@@ -0,0 +1,161 @@
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
+package com.google.android.wallpaper.weathereffects.graphics.sun
+
+import android.graphics.Bitmap
+import android.graphics.BitmapShader
+import android.graphics.Canvas
+import android.graphics.Paint
+import android.graphics.Shader
+import android.util.SizeF
+import com.google.android.wallpaper.weathereffects.graphics.WeatherEffect
+import com.google.android.wallpaper.weathereffects.graphics.utils.GraphicsUtils
+import com.google.android.wallpaper.weathereffects.graphics.utils.ImageCrop
+import java.util.concurrent.TimeUnit
+import kotlin.random.Random
+
+/** Defines and generates the sunny weather animation. */
+class SunEffect(
+    /** The config of the sunny effect. */
+    private val sunConfig: SunEffectConfig,
+    private var foreground: Bitmap,
+    private var background: Bitmap,
+    private var intensity: Float = WeatherEffect.DEFAULT_INTENSITY,
+    /** The initial size of the surface where the effect will be shown. */
+    var surfaceSize: SizeF
+) : WeatherEffect {
+
+    private val sunnyPaint = Paint().also { it.shader = sunConfig.colorGradingShader }
+    private var elapsedTime: Float = 0f
+
+    init {
+        updateTextureUniforms()
+        adjustCropping(surfaceSize)
+        prepareColorGrading()
+        setIntensity(intensity)
+    }
+
+    override fun resize(newSurfaceSize: SizeF) {
+        adjustCropping(newSurfaceSize)
+        surfaceSize = newSurfaceSize
+    }
+
+    override fun update(deltaMillis: Long, frameTimeNanos: Long) {
+        elapsedTime += TimeUnit.MILLISECONDS.toSeconds(deltaMillis)
+        sunConfig.shader.setFloatUniform("time", elapsedTime)
+        sunConfig.colorGradingShader.setInputShader("texture", sunConfig.shader)
+    }
+
+    override fun draw(canvas: Canvas) {
+        canvas.drawPaint(sunnyPaint)
+    }
+
+    override fun reset() {
+        elapsedTime = Random.nextFloat() * 90f
+    }
+
+    override fun release() {
+        sunConfig.lut?.recycle()
+    }
+
+    override fun setIntensity(intensity: Float) {
+        sunConfig.shader.setFloatUniform("intensity", intensity)
+        sunConfig.colorGradingShader.setFloatUniform(
+            "intensity",
+            sunConfig.colorGradingIntensity * intensity
+        )
+    }
+
+    override fun setBitmaps(foreground: Bitmap, background: Bitmap) {
+        this.foreground = foreground
+        this.background = background
+        sunConfig.shader.setInputBuffer(
+            "background",
+            BitmapShader(background, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR)
+        )
+        sunConfig.shader.setInputBuffer(
+            "foreground",
+            BitmapShader(foreground, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR)
+        )
+        adjustCropping(surfaceSize)
+    }
+
+    private fun adjustCropping(surfaceSize: SizeF) {
+        val imageCropFgd =
+            ImageCrop.centerCoverCrop(
+                surfaceSize.width,
+                surfaceSize.height,
+                foreground.width.toFloat(),
+                foreground.height.toFloat()
+            )
+        sunConfig.shader.setFloatUniform(
+            "uvOffsetFgd",
+            imageCropFgd.leftOffset,
+            imageCropFgd.topOffset
+        )
+        sunConfig.shader.setFloatUniform(
+            "uvScaleFgd",
+            imageCropFgd.horizontalScale,
+            imageCropFgd.verticalScale
+        )
+        val imageCropBgd =
+            ImageCrop.centerCoverCrop(
+                surfaceSize.width,
+                surfaceSize.height,
+                background.width.toFloat(),
+                background.height.toFloat()
+            )
+        sunConfig.shader.setFloatUniform(
+            "uvOffsetBgd",
+            imageCropBgd.leftOffset,
+            imageCropBgd.topOffset
+        )
+        sunConfig.shader.setFloatUniform(
+            "uvScaleBgd",
+            imageCropBgd.horizontalScale,
+            imageCropBgd.verticalScale
+        )
+        sunConfig.shader.setFloatUniform("screenSize", surfaceSize.width, surfaceSize.height)
+        sunConfig.shader.setFloatUniform(
+            "screenAspectRatio",
+            GraphicsUtils.getAspectRatio(surfaceSize)
+        )
+    }
+
+    private fun updateTextureUniforms() {
+        sunConfig.shader.setInputBuffer(
+            "foreground",
+            BitmapShader(foreground, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR)
+        )
+
+        sunConfig.shader.setInputBuffer(
+            "background",
+            BitmapShader(background, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR)
+        )
+    }
+
+    private fun prepareColorGrading() {
+        sunConfig.colorGradingShader.setInputShader("texture", sunConfig.shader)
+        sunConfig.lut?.let {
+            sunConfig.colorGradingShader.setInputShader(
+                "lut",
+                BitmapShader(it, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR)
+            )
+        }
+        sunConfig.colorGradingShader.setFloatUniform("intensity", sunConfig.colorGradingIntensity)
+    }
+}
diff --git a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/sun/SunEffectConfig.kt b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/sun/SunEffectConfig.kt
new file mode 100644
index 0000000..05f6b80
--- /dev/null
+++ b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/sun/SunEffectConfig.kt
@@ -0,0 +1,62 @@
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
+package com.google.android.wallpaper.weathereffects.graphics.sun
+
+import android.content.res.AssetManager
+import android.graphics.Bitmap
+import android.graphics.RuntimeShader
+import androidx.annotation.FloatRange
+import com.google.android.wallpaper.weathereffects.graphics.fog.FogEffectConfig
+import com.google.android.wallpaper.weathereffects.graphics.utils.GraphicsUtils
+
+/** Configuration for a snow effect. */
+data class SunEffectConfig(
+    /** The main shader of the effect. */
+    val shader: RuntimeShader,
+    /** The color grading shader. */
+    val colorGradingShader: RuntimeShader,
+    /** The main lut (color grading) for the effect. */
+    val lut: Bitmap?,
+    /** Pixel density of the display. Used for dithering. */
+    val pixelDensity: Float,
+    /** The intensity of the color grading. 0: no color grading, 1: color grading in full effect. */
+    @FloatRange(from = 0.0, to = 1.0) val colorGradingIntensity: Float,
+) {
+    /**
+     * Constructor for [FogEffectConfig].
+     *
+     * @param assets the application [AssetManager].
+     * @param pixelDensity pixel density of the display.
+     */
+    constructor(
+        assets: AssetManager,
+        pixelDensity: Float,
+    ) : this(
+        shader = GraphicsUtils.loadShader(assets, SHADER_PATH),
+        colorGradingShader = GraphicsUtils.loadShader(assets, COLOR_GRADING_SHADER_PATH),
+        lut = GraphicsUtils.loadTexture(assets, LOOKUP_TABLE_TEXTURE_PATH),
+        pixelDensity,
+        COLOR_GRADING_INTENSITY
+    )
+
+    companion object {
+        private const val SHADER_PATH = "shaders/sun_effect.agsl"
+        private const val COLOR_GRADING_SHADER_PATH = "shaders/color_grading_lut.agsl"
+        private const val LOOKUP_TABLE_TEXTURE_PATH = "textures/lut_rain_and_fog.png"
+        private const val COLOR_GRADING_INTENSITY = 0.7f
+    }
+}
diff --git a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/utils/GraphicsUtils.kt b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/utils/GraphicsUtils.kt
index c206b9d..ab0db98 100644
--- a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/utils/GraphicsUtils.kt
+++ b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/utils/GraphicsUtils.kt
@@ -31,6 +31,8 @@ import androidx.annotation.FloatRange
 
 /** Contains functions for rendering. */
 object GraphicsUtils {
+    /* Default width dp is calculated as default_display_width / default_display_density. */
+    private const val DEFAULT_WIDTH_DP = 1080 / 2.625f
 
     /**
      * Loads a shader from an asset file.
@@ -89,6 +91,7 @@ object GraphicsUtils {
         allocationOut.copyTo(blurredImage)
         return blurredImage
     }
+
     /**
      * @return the [Float] representing the aspect ratio of width / height, -1 if either width or
      *   height is equal to or less than 0.
@@ -102,6 +105,26 @@ object GraphicsUtils {
         } else width / height
     }
 
+    /**
+     * Compute the weather effect default grid size. This takes into consideration the different
+     * display densities and aspect ratio so the effect looks good on displays with different sizes.
+     * @param surfaceSize the size of the surface where the wallpaper is being rendered.
+     * @param density the current display density.
+     * @return a [Float] representing the default size.
+     */
+    fun computeDefaultGridSize(surfaceSize: SizeF, density: Float): Float {
+        val displayWidthDp = surfaceSize.width / density
+        val adjustedScale = when {
+            // "COMPACT"
+            displayWidthDp < 600 -> 1f
+            // "MEDIUM"
+            displayWidthDp >= 600 && displayWidthDp < 840 -> 0.9f
+            // "EXPANDED"
+            else -> 0.8f
+        }
+        return adjustedScale * displayWidthDp / DEFAULT_WIDTH_DP
+    }
+
     private fun resolveShaderIncludes(assetManager: AssetManager, string: String): String {
         val match = Regex("[ \\t]*#include +\"([\\w\\d./]+)\"")
         return string.replace(match) { m ->
diff --git a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/utils/TimeUtils.kt b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/utils/TimeUtils.kt
new file mode 100644
index 0000000..7a3b1ac
--- /dev/null
+++ b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/utils/TimeUtils.kt
@@ -0,0 +1,28 @@
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
+package com.google.android.wallpaper.weathereffects.graphics.utils
+
+/** Contains functions related to time. */
+object TimeUtils {
+    private const val MILLIS_TO_SECONDS = 1 / 1_000f
+    private const val NANOS_TO_SECONDS = 1 / 1_000_000_000f
+
+    /** Converts milliseconds to decimal seconds. */
+    fun millisToSeconds(millis: Long): Float = millis * MILLIS_TO_SECONDS
+
+    /** Converts nanoseconds to decimal seconds. */
+    fun nanosToSeconds(nanos: Long): Float = nanos * NANOS_TO_SECONDS
+}
diff --git a/weathereffects/res/xml/weather_wallpaper.xml b/weathereffects/res/xml/weather_wallpaper.xml
index 3550669..fcf8257 100644
--- a/weathereffects/res/xml/weather_wallpaper.xml
+++ b/weathereffects/res/xml/weather_wallpaper.xml
@@ -18,4 +18,5 @@
     android:author="@string/google_author"
     android:description="@string/wallpaper_description"
     android:showMetadataInPreview="true"
+    android:thumbnail="@drawable/ic_launcher_foreground"
     android:supportsAmbientMode="false"/>
diff --git a/weathereffects/src/com/google/android/wallpaper/weathereffects/WeatherEngine.kt b/weathereffects/src/com/google/android/wallpaper/weathereffects/WeatherEngine.kt
index 547e2aa..ce6ccf7 100644
--- a/weathereffects/src/com/google/android/wallpaper/weathereffects/WeatherEngine.kt
+++ b/weathereffects/src/com/google/android/wallpaper/weathereffects/WeatherEngine.kt
@@ -16,14 +16,20 @@
 
 package com.google.android.wallpaper.weathereffects
 
+import android.animation.ValueAnimator
+import android.app.WallpaperColors
 import android.content.Context
 import android.graphics.Bitmap
+import android.os.Bundle
+import android.os.SystemClock
 import android.util.Log
 import android.util.Size
 import android.util.SizeF
 import android.view.SurfaceHolder
+import androidx.annotation.FloatRange
 import com.google.android.torus.canvas.engine.CanvasWallpaperEngine
-import com.google.android.wallpaper.weathereffects.shared.model.WallpaperImageModel
+import com.google.android.torus.core.wallpaper.listener.LiveWallpaperEventListener
+import com.google.android.torus.core.wallpaper.listener.LiveWallpaperKeyguardEventListener
 import com.google.android.wallpaper.weathereffects.domain.WeatherEffectsInteractor
 import com.google.android.wallpaper.weathereffects.graphics.WeatherEffect
 import com.google.android.wallpaper.weathereffects.graphics.fog.FogEffect
@@ -33,18 +39,34 @@ import com.google.android.wallpaper.weathereffects.graphics.rain.RainEffect
 import com.google.android.wallpaper.weathereffects.graphics.rain.RainEffectConfig
 import com.google.android.wallpaper.weathereffects.graphics.snow.SnowEffect
 import com.google.android.wallpaper.weathereffects.graphics.snow.SnowEffectConfig
+import com.google.android.wallpaper.weathereffects.graphics.sun.SunEffect
+import com.google.android.wallpaper.weathereffects.graphics.sun.SunEffectConfig
 import com.google.android.wallpaper.weathereffects.provider.WallpaperInfoContract
+import com.google.android.wallpaper.weathereffects.sensor.UserPresenceController
+import com.google.android.wallpaper.weathereffects.shared.model.WallpaperImageModel
+import kotlin.math.max
+import kotlin.math.roundToInt
 import kotlinx.coroutines.CoroutineScope
 import kotlinx.coroutines.Job
 import kotlinx.coroutines.launch
 
 class WeatherEngine(
     defaultHolder: SurfaceHolder,
+    private val applicationScope: CoroutineScope,
+    private val interactor: WeatherEffectsInteractor,
     private val context: Context,
-    hardwareAccelerated: Boolean = true
-) : CanvasWallpaperEngine(defaultHolder, hardwareAccelerated) {
+    private val isDebugActivity: Boolean = false,
+    hardwareAccelerated: Boolean = true,
+) :
+    CanvasWallpaperEngine(defaultHolder, hardwareAccelerated),
+    LiveWallpaperKeyguardEventListener,
+    LiveWallpaperEventListener {
+
+    private var lockStartTime: Long = 0
+    private var unlockAnimator: ValueAnimator? = null
 
-    private val currentAssets: WallpaperImageModel? = null
+    private var backgroundColor: WallpaperColors? = null
+    private var currentAssets: WallpaperImageModel? = null
     private var activeEffect: WeatherEffect? = null
         private set(value) {
             field = value
@@ -56,11 +78,33 @@ class WeatherEngine(
         }
 
     private var collectWallpaperImageJob: Job? = null
-    private lateinit var interactor: WeatherEffectsInteractor
-    private lateinit var applicationScope: CoroutineScope
+    private var effectTargetIntensity: Float = 1f
+    private var effectIntensity: Float = 0f
+
+    private var userPresenceController =
+        UserPresenceController(context) { newUserPresence, oldUserPresence ->
+            onUserPresenceChange(newUserPresence, oldUserPresence)
+        }
+
+    init {
+        /* Load assets. */
+        if (interactor.wallpaperImageModel.value == null) {
+            applicationScope.launch { interactor.loadWallpaper() }
+        }
+    }
 
     override fun onCreate(isFirstActiveInstance: Boolean) {
         Log.d(TAG, "Engine created.")
+        /*
+         * Initialize `effectIntensity` to `effectTargetIntensity` so we show the weather effect
+         * on preview and when `isDebugActivity` is true.
+         *
+         * isPreview() is only reliable after `onCreate`. Thus update the initial value of
+         * `effectIntensity` in case it is not 0.
+         */
+        if (shouldSkipIntensityOutAnimation()) {
+            updateCurrentIntensity(effectTargetIntensity)
+        }
     }
 
     override fun onResize(size: Size) {
@@ -70,83 +114,144 @@ class WeatherEngine(
         }
     }
 
-    fun initialize(
-        applicationScope: CoroutineScope,
-        interactor: WeatherEffectsInteractor,
-    ) {
-        this.interactor = interactor
-        this.applicationScope = applicationScope
-
-        if (interactor.wallpaperImageModel.value == null) {
+    override fun onResume() {
+        collectWallpaperImageJob =
             applicationScope.launch {
-                interactor.loadWallpaper()
+                interactor.wallpaperImageModel.collect { asset ->
+                    if (asset == null || asset == currentAssets) return@collect
+                    currentAssets = asset
+                    createWeatherEffect(asset.foreground, asset.background, asset.weatherEffect)
+                    updateWallpaperColors(asset.background)
+                }
             }
+        if (activeEffect != null) {
+            if (shouldTriggerUpdate()) startUpdateLoop()
         }
+        userPresenceController.start(context.mainExecutor)
     }
 
-    override fun onResume() {
-        if (shouldTriggerUpdate()) {
-            startUpdateLoop()
-        }
-        collectWallpaperImageJob = applicationScope.launch {
-            interactor.wallpaperImageModel.collect { asset ->
-                if (asset == null || asset == currentAssets) return@collect
+    override fun onUpdate(deltaMillis: Long, frameTimeNanos: Long) {
+        activeEffect?.update(deltaMillis, frameTimeNanos)
 
-                createWeatherEffect(asset.foreground, asset.background, asset.weatherEffect)
-            }
-        }
+        renderWithFpsLimit(frameTimeNanos) { canvas -> activeEffect?.draw(canvas) }
     }
 
     override fun onPause() {
         stopUpdateLoop()
-        activeEffect?.reset()
         collectWallpaperImageJob?.cancel()
+        activeEffect?.reset()
+        userPresenceController.stop()
     }
 
-
     override fun onDestroy(isLastActiveInstance: Boolean) {
         activeEffect?.release()
         activeEffect = null
     }
 
-    override fun onUpdate(deltaMillis: Long, frameTimeNanos: Long) {
-        super.onUpdate(deltaMillis, frameTimeNanos)
-        activeEffect?.update(deltaMillis, frameTimeNanos)
+    override fun onKeyguardGoingAway() {
+        userPresenceController.onKeyguardGoingAway()
+    }
 
-        renderWithFpsLimit(frameTimeNanos) { canvas -> activeEffect?.draw(canvas) }
+    override fun onOffsetChanged(xOffset: Float, xOffsetStep: Float) {
+        // No-op.
+    }
+
+    override fun onZoomChanged(zoomLevel: Float) {
+        // No-op.
+    }
+
+    override fun onWallpaperReapplied() {
+        // No-op.
+    }
+
+    override fun shouldZoomOutWallpaper(): Boolean = true
+
+    override fun computeWallpaperColors(): WallpaperColors? = backgroundColor
+
+    override fun onWake(extras: Bundle) {
+        userPresenceController.setWakeState(true)
+    }
+
+    override fun onSleep(extras: Bundle) {
+        userPresenceController.setWakeState(false)
+    }
+
+    fun setTargetIntensity(@FloatRange(from = 0.0, to = 1.0) intensity: Float) {
+        effectTargetIntensity = intensity
+
+        /* If we don't want to animate, update the target intensity as it happens. */
+        if (shouldSkipIntensityOutAnimation()) {
+            updateCurrentIntensity(effectTargetIntensity)
+        }
     }
 
     private fun createWeatherEffect(
         foreground: Bitmap,
         background: Bitmap,
-        weatherEffect: WallpaperInfoContract.WeatherEffect? = null
+        weatherEffect: WallpaperInfoContract.WeatherEffect? = null,
     ) {
         activeEffect?.release()
         activeEffect = null
 
         when (weatherEffect) {
             WallpaperInfoContract.WeatherEffect.RAIN -> {
-                val rainConfig = RainEffectConfig(context.assets, foreground, background)
-                activeEffect = RainEffect(rainConfig, screenSize.toSizeF(), context.mainExecutor)
+                val rainConfig =
+                    RainEffectConfig(context.assets, context.resources.displayMetrics.density)
+                activeEffect =
+                    RainEffect(
+                        rainConfig,
+                        foreground,
+                        background,
+                        effectIntensity,
+                        screenSize.toSizeF(),
+                        context.mainExecutor,
+                    )
             }
-
             WallpaperInfoContract.WeatherEffect.FOG -> {
-                val fogConfig = FogEffectConfig(
-                    context.assets, foreground, background, context.resources.displayMetrics.density
-                )
-                activeEffect = FogEffect(fogConfig, screenSize.toSizeF())
-            }
+                val fogConfig =
+                    FogEffectConfig(context.assets, context.resources.displayMetrics.density)
 
+                activeEffect =
+                    FogEffect(
+                        fogConfig,
+                        foreground,
+                        background,
+                        effectIntensity,
+                        screenSize.toSizeF()
+                    )
+            }
             WallpaperInfoContract.WeatherEffect.SNOW -> {
-                val snowConfig = SnowEffectConfig(context, foreground, background)
-                activeEffect = SnowEffect(snowConfig, screenSize.toSizeF(), context.mainExecutor)
+                val snowConfig =
+                    SnowEffectConfig(context.assets, context.resources.displayMetrics.density)
+                activeEffect =
+                    SnowEffect(
+                        snowConfig,
+                        foreground,
+                        background,
+                        effectIntensity,
+                        screenSize.toSizeF(),
+                        context.mainExecutor,
+                    )
+            }
+            WallpaperInfoContract.WeatherEffect.SUN -> {
+                val snowConfig =
+                    SunEffectConfig(context.assets, context.resources.displayMetrics.density)
+                activeEffect =
+                    SunEffect(
+                        snowConfig,
+                        foreground,
+                        background,
+                        effectIntensity,
+                        screenSize.toSizeF()
+                    )
             }
-
             else -> {
                 activeEffect = NoEffect(foreground, background, screenSize.toSizeF())
             }
         }
 
+        updateCurrentIntensity()
+
         render { canvas -> activeEffect?.draw(canvas) }
     }
 
@@ -156,8 +261,136 @@ class WeatherEngine(
 
     private fun Size.toSizeF(): SizeF = SizeF(width.toFloat(), height.toFloat())
 
-    private companion object {
+    private fun onUserPresenceChange(
+        newUserPresence: UserPresenceController.UserPresence,
+        oldUserPresence: UserPresenceController.UserPresence,
+    ) {
+        playIntensityFadeOutAnimation(getAnimationType(newUserPresence, oldUserPresence))
+    }
+
+    private fun updateCurrentIntensity(intensity: Float = effectIntensity) {
+        if (effectIntensity != intensity) {
+            effectIntensity = intensity
+        }
+        activeEffect?.setIntensity(effectIntensity)
+    }
+
+    private fun playIntensityFadeOutAnimation(animationType: AnimationType) {
+        when (animationType) {
+            AnimationType.WAKE -> {
+                unlockAnimator?.cancel()
+                updateCurrentIntensity(effectTargetIntensity)
+                lockStartTime = SystemClock.elapsedRealtime()
+                animateWeatherIntensityOut(AUTO_FADE_DELAY_FROM_AWAY_MILLIS)
+            }
+            AnimationType.UNLOCK -> {
+                // If already running, don't stop it.
+                if (unlockAnimator?.isRunning == true) {
+                    return
+                }
+
+                /*
+                 * When waking up the device (from AWAY), we normally wait for a delay
+                 * (AUTO_FADE_DELAY_FROM_AWAY_MILLIS) before playing the fade out animation.
+                 * However, there is a situation where this might be interrupted:
+                 *     AWAY -> LOCKED -> LOCKED -> ACTIVE.
+                 * If this happens, we might have already waited for sometime (between
+                 * AUTO_FADE_DELAY_MILLIS and AUTO_FADE_DELAY_FROM_AWAY_MILLIS). We compare how long
+                 * we've waited with AUTO_FADE_DELAY_MILLIS, and if we've waited longer than
+                 * AUTO_FADE_DELAY_MILLIS, we play the animation immediately. Otherwise, we wait
+                 * the rest of the AUTO_FADE_DELAY_MILLIS delay.
+                 */
+                var delayTime = AUTO_FADE_DELAY_MILLIS
+                if (unlockAnimator?.isStarted == true) {
+                    val deltaTime = (SystemClock.elapsedRealtime() - lockStartTime)
+                    delayTime = max(delayTime - deltaTime, 0)
+                    lockStartTime = 0
+                }
+                unlockAnimator?.cancel()
+                updateCurrentIntensity()
+                animateWeatherIntensityOut(delayTime, AUTO_FADE_SHORT_DURATION_MILLIS)
+            }
+            AnimationType.NONE -> {
+                // No-op.
+            }
+        }
+    }
+
+    private fun shouldSkipIntensityOutAnimation(): Boolean = isPreview() || isDebugActivity
 
+    private fun animateWeatherIntensityOut(
+        delayMillis: Long,
+        durationMillis: Long = AUTO_FADE_DURATION_MILLIS,
+    ) {
+        unlockAnimator =
+            ValueAnimator.ofFloat(effectIntensity, 0f).apply {
+                duration = durationMillis
+                startDelay = delayMillis
+                addUpdateListener { updatedAnimation ->
+                    effectIntensity = updatedAnimation.animatedValue as Float
+                    updateCurrentIntensity()
+                }
+                start()
+            }
+    }
+
+    private fun getAnimationType(
+        newPresence: UserPresenceController.UserPresence,
+        oldPresence: UserPresenceController.UserPresence,
+    ): AnimationType {
+        if (shouldSkipIntensityOutAnimation()) {
+            return AnimationType.NONE
+        }
+        when (oldPresence) {
+            UserPresenceController.UserPresence.AWAY -> {
+                if (
+                    newPresence == UserPresenceController.UserPresence.LOCKED ||
+                        newPresence == UserPresenceController.UserPresence.ACTIVE
+                ) {
+                    return AnimationType.WAKE
+                }
+            }
+            UserPresenceController.UserPresence.LOCKED -> {
+                if (newPresence == UserPresenceController.UserPresence.ACTIVE) {
+                    return AnimationType.UNLOCK
+                }
+            }
+            else -> {
+                // No-op.
+            }
+        }
+
+        return AnimationType.NONE
+    }
+
+    private fun updateWallpaperColors(background: Bitmap) {
+        backgroundColor =
+            WallpaperColors.fromBitmap(
+                Bitmap.createScaledBitmap(
+                    background,
+                    256,
+                    (background.width / background.height.toFloat() * 256).roundToInt(),
+                    /* filter = */ true
+                )
+            )
+    }
+
+    /**
+     * Types of animations. Currently we animate when we wake the device (from screen off to lock
+     * screen or home screen) or when whe unlock device (from lock screen to home screen).
+     */
+    private enum class AnimationType {
+        UNLOCK,
+        WAKE,
+        NONE
+    }
+
+    private companion object {
         private val TAG = WeatherEngine::class.java.simpleName
+
+        private const val AUTO_FADE_DURATION_MILLIS: Long = 3000
+        private const val AUTO_FADE_SHORT_DURATION_MILLIS: Long = 3000
+        private const val AUTO_FADE_DELAY_MILLIS: Long = 1000
+        private const val AUTO_FADE_DELAY_FROM_AWAY_MILLIS: Long = 2000
     }
 }
diff --git a/weathereffects/src/com/google/android/wallpaper/weathereffects/WeatherWallpaperService.kt b/weathereffects/src/com/google/android/wallpaper/weathereffects/WeatherWallpaperService.kt
index 199a4c1..3ab9f3f 100644
--- a/weathereffects/src/com/google/android/wallpaper/weathereffects/WeatherWallpaperService.kt
+++ b/weathereffects/src/com/google/android/wallpaper/weathereffects/WeatherWallpaperService.kt
@@ -36,8 +36,6 @@ class WeatherWallpaperService @Inject constructor(): LiveWallpaper() {
     }
 
     override fun getWallpaperEngine(context: Context, surfaceHolder: SurfaceHolder): TorusEngine {
-        val engine = WeatherEngine(surfaceHolder, context)
-        engine.initialize(applicationScope, interactor)
-        return engine
+        return WeatherEngine(surfaceHolder, applicationScope, interactor, context)
     }
 }
diff --git a/weathereffects/src/com/google/android/wallpaper/weathereffects/data/repository/WallpaperFileUtils.kt b/weathereffects/src/com/google/android/wallpaper/weathereffects/data/repository/WallpaperFileUtils.kt
index 39bacb0..b4808d9 100644
--- a/weathereffects/src/com/google/android/wallpaper/weathereffects/data/repository/WallpaperFileUtils.kt
+++ b/weathereffects/src/com/google/android/wallpaper/weathereffects/data/repository/WallpaperFileUtils.kt
@@ -20,6 +20,7 @@ import android.content.Context
 import android.graphics.Bitmap
 import android.graphics.BitmapFactory
 import android.util.Log
+import com.google.android.wallpaper.weathereffects.provider.WallpaperInfoContract
 import kotlinx.coroutines.CoroutineDispatcher
 import kotlinx.coroutines.Dispatchers
 import kotlinx.coroutines.withContext
@@ -35,7 +36,7 @@ object WallpaperFileUtils {
      * @param dispatcher the dispatcher to run within.
      * @return `true` when exported successfully
      */
-    suspend fun export(
+    suspend fun exportBitmap(
         context: Context,
         fileName: String,
         bitmap: Bitmap,
@@ -122,6 +123,59 @@ object WallpaperFileUtils {
         }
     }
 
+    /**
+     * Exports the last known weather, and saves it into a shared preferences file. This is
+     * needed so when we reboot the device, we have information about the last weather and we can
+     * show it (also so we don't have to wait for the weather API to fetch the current weather).
+     *
+     * @param weatherEffect the last known weather effect.
+     * @param context the [Context] of the caller.
+     */
+    fun exportLastKnownWeather(
+        weatherEffect: WallpaperInfoContract.WeatherEffect,
+        context: Context
+    ) {
+        asProtectedContext(context).getSharedPreferences(PREF_FILENAME, Context.MODE_PRIVATE)
+            .edit()
+            .putString(LAST_KNOWN_WEATHER_KEY, weatherEffect.value)
+            .apply()
+    }
+
+    /**
+     * Imports the last known weather from shared preferences.
+     *
+     * @param context the [Context] of the caller
+     *
+     * @return the last known weather effect, or null if not found
+     */
+    fun importLastKnownWeather(context: Context): WallpaperInfoContract.WeatherEffect? {
+        return WallpaperInfoContract.WeatherEffect.fromStringValue(
+            asProtectedContext(context).getSharedPreferences(
+                PREF_FILENAME,
+                Context.MODE_PRIVATE
+            ).getString(LAST_KNOWN_WEATHER_KEY, null)
+        )
+    }
+
+    /**
+     * Checks if we have Foreground and Background Bitmap in local storage.
+     *
+     * @param context the [Context] of the caller
+     *
+     * @return whether both Bitmaps exists
+     */
+    fun hasBitmapsInLocalStorage(context: Context): Boolean {
+        val protectedContext = if (context.isDeviceProtectedStorage) {
+            context
+        } else {
+            context.createDeviceProtectedStorageContext()
+        }
+        val fileBgd = protectedContext.getFileStreamPath(BG_FILE_NAME)
+        val fileFgd = protectedContext.getFileStreamPath(FG_FILE_NAME)
+
+        return fileBgd.exists() && fileFgd.exists()
+    }
+
     private fun asProtectedContext(context: Context): Context {
         return if (context.isDeviceProtectedStorage) {
             context
@@ -133,4 +187,6 @@ object WallpaperFileUtils {
     private const val TAG = "WallpaperFileUtils"
     const val FG_FILE_NAME = "fg_image"
     const val BG_FILE_NAME = "bg_image"
+    private const val PREF_FILENAME = "weather_preferences"
+    private const val LAST_KNOWN_WEATHER_KEY = "last_known_weather"
 }
diff --git a/weathereffects/src/com/google/android/wallpaper/weathereffects/data/repository/WeatherEffectsRepository.kt b/weathereffects/src/com/google/android/wallpaper/weathereffects/data/repository/WeatherEffectsRepository.kt
index 8b2fc6f..02ea8a5 100644
--- a/weathereffects/src/com/google/android/wallpaper/weathereffects/data/repository/WeatherEffectsRepository.kt
+++ b/weathereffects/src/com/google/android/wallpaper/weathereffects/data/repository/WeatherEffectsRepository.kt
@@ -31,7 +31,7 @@ class WeatherEffectsRepository @Inject constructor(
     private val context: Context,
 ) {
     private val _wallpaperImage = MutableStateFlow<WallpaperImageModel?>(null)
-    val wallpaperImage: StateFlow<WallpaperImageModel?>  = _wallpaperImage.asStateFlow()
+    val wallpaperImage: StateFlow<WallpaperImageModel?> = _wallpaperImage.asStateFlow()
 
     /**
      * Generates or updates a wallpaper from the provided [wallpaperFileModel].
@@ -61,10 +61,32 @@ class WeatherEffectsRepository @Inject constructor(
 
             val foreground = fgBitmap!!
             val background = bgBitmap!!
+
+            var success = true
+            // TODO: Only persist assets when the wallpaper is applied.
+            success = success and WallpaperFileUtils.exportBitmap(
+                context,
+                WallpaperFileUtils.FG_FILE_NAME,
+                foreground,
+            )
+            success = success and WallpaperFileUtils.exportBitmap(
+                context,
+                WallpaperFileUtils.BG_FILE_NAME,
+                background,
+            )
+            if (!success) {
+                Log.e(TAG, "Failed to export assets during wallpaper generation")
+                return
+            }
+
+            // We always respect the new weather.
+            val weather = wallpaperFileModel.weatherEffect
+            if (weather != null) WallpaperFileUtils.exportLastKnownWeather(weather, context)
+
             _wallpaperImage.value = WallpaperImageModel(
                 foreground,
                 background,
-                wallpaperFileModel.weatherEffect,
+                weather
             )
         } catch (e: RuntimeException) {
             Log.e(TAG, "Unable to load wallpaper: ", e)
@@ -89,15 +111,19 @@ class WeatherEffectsRepository @Inject constructor(
                 Log.w(TAG, "Cannot load wallpaper from local storage.")
                 return
             }
+
+            val weatherEffect = WallpaperFileUtils.importLastKnownWeather(context)
+
             _wallpaperImage.value = WallpaperImageModel(
                 fgBitmap,
                 bgBitmap,
-                // TODO: Add new API to change weather type dynamically
+                weatherEffect,
             )
         } catch (e: RuntimeException) {
             Log.e(TAG, "Unable to load wallpaper: ", e)
         } catch (e: OutOfMemoryError) {
             Log.e(TAG, "Unable to load wallpaper: ", e)
+            null
         }
     }
 
@@ -107,14 +133,14 @@ class WeatherEffectsRepository @Inject constructor(
 
         var success = true
         success = success and (foreground?.let {
-            WallpaperFileUtils.export(
+            WallpaperFileUtils.exportBitmap(
                 context,
                 WallpaperFileUtils.FG_FILE_NAME,
                 it,
             )
         } == true)
         success = success and (background?.let {
-            WallpaperFileUtils.export(
+            WallpaperFileUtils.exportBitmap(
                 context,
                 WallpaperFileUtils.BG_FILE_NAME,
                 it,
diff --git a/weathereffects/src/com/google/android/wallpaper/weathereffects/provider/WallpaperInfoContract.kt b/weathereffects/src/com/google/android/wallpaper/weathereffects/provider/WallpaperInfoContract.kt
index d3a3174..095b2e0 100644
--- a/weathereffects/src/com/google/android/wallpaper/weathereffects/provider/WallpaperInfoContract.kt
+++ b/weathereffects/src/com/google/android/wallpaper/weathereffects/provider/WallpaperInfoContract.kt
@@ -45,7 +45,8 @@ object WallpaperInfoContract {
     enum class WeatherEffect(val value: String) {
         RAIN("rain"),
         FOG("fog"),
-        SNOW("snow");
+        SNOW("snow"),
+        SUN("SUN");
 
         companion object {
 
@@ -66,6 +67,7 @@ object WallpaperInfoContract {
                     RAIN.value -> RAIN
                     FOG.value -> FOG
                     SNOW.value -> SNOW
+                    SUN.value -> SUN
                     else -> null
                 }
             }
diff --git a/weathereffects/src/com/google/android/wallpaper/weathereffects/sensor/UserPresenceController.kt b/weathereffects/src/com/google/android/wallpaper/weathereffects/sensor/UserPresenceController.kt
new file mode 100644
index 0000000..b787afc
--- /dev/null
+++ b/weathereffects/src/com/google/android/wallpaper/weathereffects/sensor/UserPresenceController.kt
@@ -0,0 +1,109 @@
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
+package com.google.android.wallpaper.weathereffects.sensor
+
+import android.app.KeyguardManager
+import android.content.Context
+import java.util.concurrent.Executor
+
+/** Controls user presence based on Keyguard and Live Wallpaper wake/sleep events. */
+class UserPresenceController(
+    context: Context,
+    private var onUserPresenceChanged:
+        (newPresence: UserPresence, oldPresence: UserPresence) -> Unit
+) {
+
+    /** The current user presence. It is [UserPresence.UNDEFINED] when it hasn't been set yet. */
+    private var userPresence: UserPresence = UserPresence.UNDEFINED
+        set(value) {
+            val oldValue = field
+            field = value
+            if (field != oldValue) onUserPresenceChanged(field, oldValue)
+        }
+
+    private val keyguardManager =
+        context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager?
+    private var keyguardListener: (Boolean) -> Unit = { locked: Boolean ->
+        updateUserPresence(isDeviceLocked = locked)
+    }
+
+    private var deviceLocked: Boolean = keyguardManager?.isKeyguardLocked ?: false
+    private var deviceAwake: Boolean = true
+
+    /** Start listening to the different sensors. */
+    fun start(executor: Executor) {
+        updateUserPresence(isDeviceLocked = keyguardManager?.isKeyguardLocked ?: false)
+        /*
+         * From KeyguardManager.java `keyguardListener` is saved into a map and thus won't add
+         * multiple of the same listener.
+         */
+        keyguardManager?.addKeyguardLockedStateListener(executor, keyguardListener)
+    }
+
+    /** Stop listening to the different sensors. */
+    fun stop() {
+        keyguardManager?.removeKeyguardLockedStateListener(keyguardListener)
+    }
+
+    /**
+     * Set the device wake state.
+     *
+     * @param isAwake if the device is awake. That means that the screen is not turned off or that
+     * the device is not in Ambient on Display mode.
+     */
+    fun setWakeState(isAwake: Boolean) {
+        updateUserPresence(isDeviceAwake = isAwake)
+    }
+
+    /**
+     * Call when the keyguard is going away. This will happen before lock state is false (but it
+     * happens at the same time that unlock animation starts).
+     */
+    fun onKeyguardGoingAway() = updateUserPresence(isDeviceLocked = false)
+
+    private fun updateUserPresence(
+        isDeviceAwake: Boolean = deviceAwake,
+        isDeviceLocked: Boolean = deviceLocked
+    ) {
+        this.deviceAwake = isDeviceAwake
+        this.deviceLocked = isDeviceLocked
+
+        userPresence = when {
+            !deviceAwake -> UserPresence.AWAY
+            deviceLocked -> UserPresence.LOCKED
+            else -> UserPresence.ACTIVE // == awake && !locked.
+        }
+    }
+
+    /** Define the different user presence available. */
+    enum class UserPresence {
+
+        /**
+         * We don't know the status of the User presence (usually at the beginning of the session).
+         */
+        UNDEFINED,
+
+        /** User is in AoD or with the screen off. */
+        AWAY,
+
+        /** User is in lock screen. */
+        LOCKED,
+
+        /** User is in the home screen or in an app. */
+        ACTIVE
+    }
+}
```

