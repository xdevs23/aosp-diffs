```diff
diff --git a/.gitignore b/.gitignore
new file mode 100644
index 0000000..ed36c6a
--- /dev/null
+++ b/.gitignore
@@ -0,0 +1 @@
+/weathereffects/graphics/build/
diff --git a/aconfig/systemui.aconfig b/aconfig/systemui.aconfig
index 54f5f2e..9a9259c 100644
--- a/aconfig/systemui.aconfig
+++ b/aconfig/systemui.aconfig
@@ -66,6 +66,30 @@ flag {
 flag {
     name: "new_customization_picker_ui"
     namespace: "systemui"
-    description: "Enables the BC25 design of the customization picker UI."
+    description: "Enables the new design of the customization picker UI."
     bug: "339081035"
 }
+
+flag {
+    name: "ambient_aod"
+    namespace: "systemui"
+    description: "Enables ambient wallpaper and AOD enhancements"
+    bug: "372655702"
+}
+
+flag {
+    name: "enable_launcher_icon_shapes"
+    namespace: "systemui"
+    description: "Enables launcher icon shapes customization"
+    bug: "348708061"
+}
+
+flag {
+    name: "smartspace_sports_card_background"
+    namespace: "systemui"
+    description: "Enables Smartspace sports card background protection and related ui updates"
+    bug: "380285747"
+    metadata {
+         purpose: PURPOSE_BUGFIX
+    }
+}
diff --git a/animationlib/res/values/ids.xml b/animationlib/res/values/ids.xml
new file mode 100644
index 0000000..2f5ee3a
--- /dev/null
+++ b/animationlib/res/values/ids.xml
@@ -0,0 +1,19 @@
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
+<resources>
+    <!-- Animations -->
+    <item type="id" name="ongoing_animation"/>
+</resources>
diff --git a/animationlib/src/com/android/app/animation/Animations.kt b/animationlib/src/com/android/app/animation/Animations.kt
new file mode 100644
index 0000000..2b787fe
--- /dev/null
+++ b/animationlib/src/com/android/app/animation/Animations.kt
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
+package com.android.app.animation
+
+import android.animation.Animator
+import android.view.View
+
+/** A static class for general animation-related utilities. */
+class Animations {
+    companion object {
+        /** Stores a [view]'s ongoing [animation] so it can be cancelled if needed. */
+        @JvmStatic
+        fun setOngoingAnimation(view: View, animation: Animator?) {
+            cancelOngoingAnimation(view)
+            view.setTag(R.id.ongoing_animation, animation)
+        }
+
+        /**
+         * Cancels the ongoing animation affecting a [view], if any was previously stored using
+         * [setOngoingAnimation].
+         */
+        @JvmStatic
+        fun cancelOngoingAnimation(view: View) {
+            (view.getTag(R.id.ongoing_animation) as? Animator)?.cancel()
+            view.setTag(R.id.ongoing_animation, null)
+        }
+    }
+}
diff --git a/animationlib/tests/robolectric/config/robolectric.properties b/animationlib/tests/robolectric/config/robolectric.properties
index 527eab6..fab7251 100644
--- a/animationlib/tests/robolectric/config/robolectric.properties
+++ b/animationlib/tests/robolectric/config/robolectric.properties
@@ -1,2 +1 @@
 sdk=NEWEST_SDK
-shadows=com.android.app.animation.robolectric.ShadowAnimationUtils2
diff --git a/animationlib/tests/robolectric/src/com/android/app/animation/robolectric/ShadowAnimationUtils2.kt b/animationlib/tests/robolectric/src/com/android/app/animation/robolectric/ShadowAnimationUtils2.kt
deleted file mode 100644
index c3e74ee..0000000
--- a/animationlib/tests/robolectric/src/com/android/app/animation/robolectric/ShadowAnimationUtils2.kt
+++ /dev/null
@@ -1,12 +0,0 @@
-package com.android.app.animation.robolectric
-
-import android.view.animation.AnimationUtils
-import org.robolectric.annotation.Implements
-import org.robolectric.shadows.ShadowAnimationUtils
-
-/**
- * This shadow overwrites [ShadowAnimationUtils] and ensures that the real implementation of
- * [AnimationUtils] is used in tests.
- */
-@Implements(AnimationUtils::class)
-class ShadowAnimationUtils2
diff --git a/animationlib/tests/src/com/android/app/animation/AnimationsTest.kt b/animationlib/tests/src/com/android/app/animation/AnimationsTest.kt
new file mode 100644
index 0000000..decc503
--- /dev/null
+++ b/animationlib/tests/src/com/android/app/animation/AnimationsTest.kt
@@ -0,0 +1,77 @@
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
+package com.android.app.animation
+
+import android.animation.ValueAnimator
+import android.content.Context
+import android.view.View
+import androidx.test.ext.junit.runners.AndroidJUnit4
+import androidx.test.filters.SmallTest
+import androidx.test.platform.app.InstrumentationRegistry
+import org.junit.Assert.assertEquals
+import org.junit.Assert.assertNull
+import org.junit.Assert.assertTrue
+import org.junit.Test
+import org.junit.runner.RunWith
+
+@SmallTest
+@RunWith(AndroidJUnit4::class)
+class AnimationsTest {
+    companion object {
+        const val TEST_DURATION = 1000L
+    }
+
+    private val context: Context = InstrumentationRegistry.getInstrumentation().context
+
+    @Test
+    fun ongoingAnimationsAreStoredAndCancelledCorrectly() {
+        val view = View(context)
+
+        val oldAnimation = FakeAnimator()
+        Animations.setOngoingAnimation(view, oldAnimation)
+        oldAnimation.start()
+        assertEquals(oldAnimation, view.getTag(R.id.ongoing_animation))
+        assertTrue(oldAnimation.started)
+
+        val newAnimation = FakeAnimator()
+        Animations.setOngoingAnimation(view, newAnimation)
+        newAnimation.start()
+        assertEquals(newAnimation, view.getTag(R.id.ongoing_animation))
+        assertTrue(oldAnimation.cancelled)
+        assertTrue(newAnimation.started)
+
+        Animations.cancelOngoingAnimation(view)
+        assertNull(view.getTag(R.id.ongoing_animation))
+        assertTrue(newAnimation.cancelled)
+    }
+}
+
+/** Test animator for tracking start and cancel signals. */
+private class FakeAnimator : ValueAnimator() {
+    var started = false
+    var cancelled = false
+
+    override fun start() {
+        started = true
+        cancelled = false
+    }
+
+    override fun cancel() {
+        started = false
+        cancelled = true
+    }
+}
diff --git a/iconloaderlib/Android.bp b/iconloaderlib/Android.bp
index 6fdf2eb..104f956 100644
--- a/iconloaderlib/Android.bp
+++ b/iconloaderlib/Android.bp
@@ -19,7 +19,7 @@ package {
 android_library {
     name: "iconloader_base",
     sdk_version: "current",
-    min_sdk_version: "26",
+    min_sdk_version: "31",
     static_libs: [
         "androidx.core_core",
         "com_android_launcher3_flags_lib",
@@ -36,7 +36,7 @@ android_library {
 android_library {
     name: "iconloader",
     sdk_version: "system_current",
-    min_sdk_version: "26",
+    min_sdk_version: "31",
     static_libs: [
         "androidx.core_core",
         "com_android_launcher3_flags_lib",
diff --git a/iconloaderlib/src/com/android/launcher3/icons/BaseIconFactory.java b/iconloaderlib/src/com/android/launcher3/icons/BaseIconFactory.java
index e3b907e..f3f9d1e 100644
--- a/iconloaderlib/src/com/android/launcher3/icons/BaseIconFactory.java
+++ b/iconloaderlib/src/com/android/launcher3/icons/BaseIconFactory.java
@@ -43,7 +43,6 @@ import com.android.launcher3.util.FlagOp;
 import com.android.launcher3.util.UserIconInfo;
 
 import java.lang.annotation.Retention;
-import java.util.Objects;
 
 /**
  * This class will be moved to androidx library. There shouldn't be any dependency outside
@@ -88,7 +87,7 @@ public class BaseIconFactory implements AutoCloseable {
     protected final int mFullResIconDpi;
     protected final int mIconBitmapSize;
 
-    protected boolean mMonoIconEnabled;
+    protected IconThemeController mThemeController;
 
     @Nullable
     private IconNormalizer mNormalizer;
@@ -145,10 +144,19 @@ public class BaseIconFactory implements AutoCloseable {
         return mNormalizer;
     }
 
+    @Nullable
+    public IconThemeController getThemeController() {
+        return mThemeController;
+    }
+
     public int getFullResIconDpi() {
         return mFullResIconDpi;
     }
 
+    public int getIconBitmapSize() {
+        return mIconBitmapSize;
+    }
+
     @SuppressWarnings("deprecation")
     public BitmapInfo createIconBitmap(Intent.ShortcutIconResource iconRes) {
         try {
@@ -234,30 +242,13 @@ public class BaseIconFactory implements AutoCloseable {
 
         if (adaptiveIcon instanceof BitmapInfo.Extender extender) {
             info = extender.getExtendedInfo(bitmap, color, this, scale[0]);
-        } else if (IconProvider.ATLEAST_T && mMonoIconEnabled) {
-            Drawable mono = getMonochromeDrawable(adaptiveIcon);
-            if (mono != null) {
-                info.setMonoIcon(createIconBitmap(mono, scale[0], MODE_ALPHA), this);
-            }
+        } else if (IconProvider.ATLEAST_T && mThemeController != null && adaptiveIcon != null) {
+            info.setThemedBitmap(mThemeController.createThemedBitmap(adaptiveIcon, info, this));
         }
         info = info.withFlags(getBitmapFlagOp(options));
         return info;
     }
 
-    /**
-     * Returns a monochromatic version of the given drawable or null, if it is not supported
-     *
-     * @param base the original icon
-     */
-    @TargetApi(Build.VERSION_CODES.TIRAMISU)
-    protected Drawable getMonochromeDrawable(AdaptiveIconDrawable base) {
-        Drawable mono = base.getMonochrome();
-        if (mono != null) {
-            return new ClippedMonoDrawable(mono);
-        }
-        return null;
-    }
-
     @NonNull
     public FlagOp getBitmapFlagOp(@Nullable IconOptions options) {
         FlagOp op = FlagOp.NO_OP;
@@ -383,7 +374,7 @@ public class BaseIconFactory implements AutoCloseable {
     }
 
     @NonNull
-    protected Bitmap createIconBitmap(@Nullable final Drawable icon, final float scale,
+    public Bitmap createIconBitmap(@Nullable final Drawable icon, final float scale,
             @BitmapGenerationMode int bitmapGenerationMode) {
         final int size = mIconBitmapSize;
         final Bitmap bitmap;
@@ -488,14 +479,8 @@ public class BaseIconFactory implements AutoCloseable {
     }
 
     @NonNull
-    public BitmapInfo makeDefaultIcon() {
-        return createBadgedIconBitmap(getFullResDefaultActivityIcon(mFullResIconDpi));
-    }
-
-    @NonNull
-    public static Drawable getFullResDefaultActivityIcon(final int iconDpi) {
-        return Objects.requireNonNull(Resources.getSystem().getDrawableForDensity(
-                android.R.drawable.sym_def_app_icon, iconDpi));
+    public BitmapInfo makeDefaultIcon(IconProvider iconProvider) {
+        return createBadgedIconBitmap(iconProvider.getFullResDefaultActivityIcon(mFullResIconDpi));
     }
 
     /**
@@ -613,26 +598,6 @@ public class BaseIconFactory implements AutoCloseable {
         }
     }
 
-    protected static class ClippedMonoDrawable extends InsetDrawable {
-
-        @NonNull
-        private final AdaptiveIconDrawable mCrop;
-
-        public ClippedMonoDrawable(@Nullable final Drawable base) {
-            super(base, -getExtraInsetFraction());
-            mCrop = new AdaptiveIconDrawable(new ColorDrawable(Color.BLACK), null);
-        }
-
-        @Override
-        public void draw(Canvas canvas) {
-            mCrop.setBounds(getBounds());
-            int saveCount = canvas.save();
-            canvas.clipPath(mCrop.getIconMask());
-            super.draw(canvas);
-            canvas.restoreToCount(saveCount);
-        }
-    }
-
     private static class CenterTextDrawable extends ColorDrawable {
 
         @NonNull
diff --git a/iconloaderlib/src/com/android/launcher3/icons/BitmapInfo.java b/iconloaderlib/src/com/android/launcher3/icons/BitmapInfo.java
index 2767e12..480061a 100644
--- a/iconloaderlib/src/com/android/launcher3/icons/BitmapInfo.java
+++ b/iconloaderlib/src/com/android/launcher3/icons/BitmapInfo.java
@@ -60,8 +60,7 @@ public class BitmapInfo {
     public final int color;
 
     @Nullable
-    protected Bitmap mMono;
-    protected Bitmap mWhiteShadowLayer;
+    private ThemedBitmap mThemedBitmap;
 
     public @BitmapInfoFlags int flags;
     private BitmapInfo badgeInfo;
@@ -90,8 +89,7 @@ public class BitmapInfo {
     }
 
     protected BitmapInfo copyInternalsTo(BitmapInfo target) {
-        target.mMono = mMono;
-        target.mWhiteShadowLayer = mWhiteShadowLayer;
+        target.mThemedBitmap = mThemedBitmap;
         target.flags = flags;
         target.badgeInfo = badgeInfo;
         return target;
@@ -102,9 +100,13 @@ public class BitmapInfo {
         return copyInternalsTo(new BitmapInfo(icon, color));
     }
 
-    public void setMonoIcon(Bitmap mono, BaseIconFactory iconFactory) {
-        mMono = mono;
-        mWhiteShadowLayer = iconFactory.getWhiteShadowLayer();
+    public void setThemedBitmap(@Nullable ThemedBitmap themedBitmap) {
+        mThemedBitmap = themedBitmap;
+    }
+
+    @Nullable
+    public ThemedBitmap getThemedBitmap() {
+        return mThemedBitmap;
     }
 
     /**
@@ -125,10 +127,6 @@ public class BitmapInfo {
         return !isNullOrLowRes();
     }
 
-    public Bitmap getMono() {
-        return mMono;
-    }
-
     /**
      * Creates a drawable for the provided BitmapInfo
      */
@@ -143,8 +141,8 @@ public class BitmapInfo {
         FastBitmapDrawable drawable;
         if (isLowRes()) {
             drawable = new PlaceHolderIconDrawable(this, context);
-        } else  if ((creationFlags & FLAG_THEMED) != 0 && mMono != null) {
-            drawable = ThemedIconDrawable.newDrawable(this, context);
+        } else  if ((creationFlags & FLAG_THEMED) != 0 && mThemedBitmap != null) {
+            drawable = mThemedBitmap.newDrawable(this, context);
         } else {
             drawable = new FastBitmapDrawable(this);
         }
diff --git a/iconloaderlib/src/com/android/launcher3/icons/ClockDrawableWrapper.java b/iconloaderlib/src/com/android/launcher3/icons/ClockDrawableWrapper.java
index b625f3a..664294e 100644
--- a/iconloaderlib/src/com/android/launcher3/icons/ClockDrawableWrapper.java
+++ b/iconloaderlib/src/com/android/launcher3/icons/ClockDrawableWrapper.java
@@ -22,7 +22,6 @@ import android.content.Context;
 import android.content.pm.ApplicationInfo;
 import android.content.pm.PackageManager;
 import android.content.res.Resources;
-import android.content.res.TypedArray;
 import android.graphics.Bitmap;
 import android.graphics.BlendMode;
 import android.graphics.BlendModeColorFilter;
@@ -39,11 +38,8 @@ import android.os.Build;
 import android.os.Bundle;
 import android.os.SystemClock;
 import android.util.Log;
-import android.util.TypedValue;
 
-import androidx.annotation.Nullable;
-
-import com.android.launcher3.icons.IconProvider.ThemeData;
+import com.android.launcher3.icons.mono.ThemedIconDrawable;
 
 import java.util.Calendar;
 import java.util.concurrent.TimeUnit;
@@ -53,7 +49,6 @@ import java.util.function.IntFunction;
  * Wrapper over {@link AdaptiveIconDrawable} to intercept icon flattening logic for dynamic
  * clock icons
  */
-@TargetApi(Build.VERSION_CODES.O)
 public class ClockDrawableWrapper extends AdaptiveIconDrawable implements BitmapInfo.Extender {
 
     public static boolean sRunningInTest = false;
@@ -94,34 +89,6 @@ public class ClockDrawableWrapper extends AdaptiveIconDrawable implements Bitmap
         super(base.getBackground(), base.getForeground());
     }
 
-    private void applyThemeData(ThemeData themeData) {
-        if (!IconProvider.ATLEAST_T || mThemeInfo != null) {
-            return;
-        }
-        try {
-            TypedArray ta = themeData.mResources.obtainTypedArray(themeData.mResID);
-            int count = ta.length();
-            Bundle extras = new Bundle();
-            for (int i = 0; i < count; i += 2) {
-                TypedValue v = ta.peekValue(i + 1);
-                extras.putInt(ta.getString(i), v.type >= TypedValue.TYPE_FIRST_INT
-                        && v.type <= TypedValue.TYPE_LAST_INT
-                        ? v.data : v.resourceId);
-            }
-            ta.recycle();
-            ClockDrawableWrapper drawable = ClockDrawableWrapper.forExtras(extras, resId -> {
-                Drawable bg = new ColorDrawable(Color.WHITE);
-                Drawable fg = themeData.mResources.getDrawable(resId).mutate();
-                return new AdaptiveIconDrawable(bg, fg);
-            });
-            if (drawable != null) {
-                mThemeInfo = drawable.mAnimationInfo;
-            }
-        } catch (Exception e) {
-            Log.e(TAG, "Error loading themed clock", e);
-        }
-    }
-
     @Override
     public Drawable getMonochrome() {
         if (mThemeInfo == null) {
@@ -140,26 +107,19 @@ public class ClockDrawableWrapper extends AdaptiveIconDrawable implements Bitmap
      * Loads and returns the wrapper from the provided package, or returns null
      * if it is unable to load.
      */
-    public static ClockDrawableWrapper forPackage(Context context, String pkg, int iconDpi,
-            @Nullable ThemeData themeData) {
+    public static ClockDrawableWrapper forPackage(Context context, String pkg, int iconDpi) {
         try {
             PackageManager pm = context.getPackageManager();
             ApplicationInfo appInfo =  pm.getApplicationInfo(pkg,
                     PackageManager.MATCH_UNINSTALLED_PACKAGES | PackageManager.GET_META_DATA);
             Resources res = pm.getResourcesForApplication(appInfo);
-            ClockDrawableWrapper wrapper = forExtras(appInfo.metaData,
-                    resId -> res.getDrawableForDensity(resId, iconDpi));
-            if (wrapper != null && themeData != null) {
-                wrapper.applyThemeData(themeData);
-            }
-            return wrapper;
+            return forExtras(appInfo.metaData, resId -> res.getDrawableForDensity(resId, iconDpi));
         } catch (Exception e) {
             Log.d(TAG, "Unable to load clock drawable info", e);
         }
         return null;
     }
 
-    @TargetApi(Build.VERSION_CODES.TIRAMISU)
     private static ClockDrawableWrapper forExtras(
             Bundle metadata, IntFunction<Drawable> drawableProvider) {
         if (metadata == null) {
@@ -220,7 +180,7 @@ public class ClockDrawableWrapper extends AdaptiveIconDrawable implements Bitmap
                 BaseIconFactory.MODE_HARDWARE_WITH_SHADOW);
 
         // Only pass theme info if mono-icon is enabled
-        AnimationInfo themeInfo = iconFactory.mMonoIconEnabled ? mThemeInfo : null;
+        AnimationInfo themeInfo = iconFactory.getThemeController() != null ? mThemeInfo : null;
         Bitmap themeBG = themeInfo == null ? null : iconFactory.getWhiteShadowLayer();
         return new ClockBitmapInfo(bitmap, color, normalizationScale,
                 mAnimationInfo, flattenBG, themeInfo, themeBG);
diff --git a/iconloaderlib/src/com/android/launcher3/icons/FastBitmapDrawable.java b/iconloaderlib/src/com/android/launcher3/icons/FastBitmapDrawable.java
index e6668d1..50ca8d6 100644
--- a/iconloaderlib/src/com/android/launcher3/icons/FastBitmapDrawable.java
+++ b/iconloaderlib/src/com/android/launcher3/icons/FastBitmapDrawable.java
@@ -73,7 +73,7 @@ public class FastBitmapDrawable extends Drawable implements Drawable.Callback {
     @VisibleForTesting protected boolean mIsPressed;
     @VisibleForTesting protected boolean mIsHovered;
     protected boolean mIsDisabled;
-    float mDisabledAlpha = 1f;
+    protected float mDisabledAlpha = 1f;
 
     @DrawableCreationFlags int mCreationFlags = 0;
 
@@ -414,7 +414,7 @@ public class FastBitmapDrawable extends Drawable implements Drawable.Callback {
         sFlagHoverEnabled = isFlagHoverEnabled;
     }
 
-    protected static class FastBitmapConstantState extends ConstantState {
+    public static class FastBitmapConstantState extends ConstantState {
         protected final Bitmap mBitmap;
         protected final int mIconColor;
 
diff --git a/iconloaderlib/src/com/android/launcher3/icons/IconProvider.java b/iconloaderlib/src/com/android/launcher3/icons/IconProvider.java
index e8ce3b1..594db35 100644
--- a/iconloaderlib/src/com/android/launcher3/icons/IconProvider.java
+++ b/iconloaderlib/src/com/android/launcher3/icons/IconProvider.java
@@ -28,8 +28,9 @@ import android.content.ComponentName;
 import android.content.Context;
 import android.content.Intent;
 import android.content.IntentFilter;
-import android.content.pm.ActivityInfo;
-import android.content.pm.LauncherActivityInfo;
+import android.content.pm.ApplicationInfo;
+import android.content.pm.ComponentInfo;
+import android.content.pm.PackageItemInfo;
 import android.content.pm.PackageManager;
 import android.content.pm.PackageManager.NameNotFoundException;
 import android.content.res.Resources;
@@ -47,13 +48,14 @@ import android.os.UserManager;
 import android.text.TextUtils;
 import android.util.Log;
 
+import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
 import androidx.core.os.BuildCompat;
 
 import com.android.launcher3.util.SafeCloseable;
 
 import java.util.Calendar;
-import java.util.function.Supplier;
+import java.util.Objects;
 
 /**
  * Class to handle icon loading from different packages
@@ -76,6 +78,9 @@ public class IconProvider {
     private final ComponentName mCalendar;
     private final ComponentName mClock;
 
+    @NonNull
+    private String mSystemState = "";
+
     public IconProvider(Context context) {
         mContext = context;
         mCalendar = parseComponentOrNull(context, R.string.calendar_component_name);
@@ -83,53 +88,73 @@ public class IconProvider {
     }
 
     /**
-     * Adds any modification to the provided systemState for dynamic icons. This system state
-     * is used by caches to check for icon invalidation.
+     * Returns a string representing the current state of the app icon. It can be used as a
+     * identifier to invalidate any resources loaded from the app.
+     * It also incorporated ay system state, that can affect the loaded resource
+     *
+     * @see #updateSystemState()
      */
-    public String getSystemStateForPackage(String systemState, String packageName) {
-        if (mCalendar != null && mCalendar.getPackageName().equals(packageName)) {
-            return systemState + SYSTEM_STATE_SEPARATOR + getDay();
+    public String getStateForApp(@Nullable ApplicationInfo appInfo) {
+        if (appInfo == null) {
+            return mSystemState;
+        }
+
+        if (mCalendar != null && mCalendar.getPackageName().equals(appInfo.packageName)) {
+            return mSystemState + SYSTEM_STATE_SEPARATOR + getDay() + SYSTEM_STATE_SEPARATOR
+                    + getApplicationInfoHash(appInfo);
         } else {
-            return systemState;
+            return mSystemState + SYSTEM_STATE_SEPARATOR + getApplicationInfoHash(appInfo);
         }
     }
 
     /**
-     * Loads the icon for the provided LauncherActivityInfo
+     * Returns a hash to uniquely identify a particular version of appInfo
      */
-    public Drawable getIcon(LauncherActivityInfo info, int iconDpi) {
-        return getIconWithOverrides(info.getApplicationInfo().packageName, iconDpi,
-                () -> info.getIcon(iconDpi));
+    protected String getApplicationInfoHash(@NonNull ApplicationInfo appInfo) {
+        // The hashString in source dir changes with every install
+        return appInfo.sourceDir;
     }
 
     /**
      * Loads the icon for the provided activity info
      */
-    public Drawable getIcon(ActivityInfo info) {
+    public Drawable getIcon(ComponentInfo info) {
         return getIcon(info, mContext.getResources().getConfiguration().densityDpi);
     }
 
     /**
-     * Loads the icon for the provided activity info
+     * Loads the icon for the provided component info
      */
-    public Drawable getIcon(ActivityInfo info, int iconDpi) {
-        return getIconWithOverrides(info.applicationInfo.packageName, iconDpi,
-                () -> loadActivityInfoIcon(info, iconDpi));
+    public Drawable getIcon(ComponentInfo info, int iconDpi) {
+        return getIcon(info, info.applicationInfo, iconDpi);
     }
 
-    @TargetApi(Build.VERSION_CODES.TIRAMISU)
-    private Drawable getIconWithOverrides(String packageName, int iconDpi,
-            Supplier<Drawable> fallback) {
+    /**
+     * Loads the icon for the provided application info
+     */
+    public Drawable getIcon(ApplicationInfo info) {
+        return getIcon(info, mContext.getResources().getConfiguration().densityDpi);
+    }
+
+    /**
+     * Loads the icon for the provided application info
+     */
+    public Drawable getIcon(ApplicationInfo info, int iconDpi) {
+        return getIcon(info, info, iconDpi);
+    }
+
+    private Drawable getIcon(PackageItemInfo info, ApplicationInfo appInfo, int iconDpi) {
+        String packageName = info.packageName;
         ThemeData td = getThemeDataForPackage(packageName);
 
         Drawable icon = null;
         if (mCalendar != null && mCalendar.getPackageName().equals(packageName)) {
             icon = loadCalendarDrawable(iconDpi, td);
         } else if (mClock != null && mClock.getPackageName().equals(packageName)) {
-            icon = ClockDrawableWrapper.forPackage(mContext, mClock.getPackageName(), iconDpi, td);
+            icon = ClockDrawableWrapper.forPackage(mContext, mClock.getPackageName(), iconDpi);
         }
         if (icon == null) {
-            icon = fallback.get();
+            icon = loadPackageIcon(info, appInfo, iconDpi);
             if (ATLEAST_T && icon instanceof AdaptiveIconDrawable && td != null) {
                 AdaptiveIconDrawable aid = (AdaptiveIconDrawable) icon;
                 if  (aid.getMonochrome() == null) {
@@ -145,22 +170,31 @@ public class IconProvider {
         return null;
     }
 
-    private Drawable loadActivityInfoIcon(ActivityInfo ai, int density) {
-        final int iconRes = ai.getIconResource();
+    private Drawable loadPackageIcon(PackageItemInfo info, ApplicationInfo appInfo, int density) {
         Drawable icon = null;
-        // Get the preferred density icon from the app's resources
-        if (density != 0 && iconRes != 0) {
+        if (BuildCompat.isAtLeastV() && info.isArchived) {
+            // Icons for archived apps com from system service, let the default impl handle that
+            icon = info.loadIcon(mContext.getPackageManager());
+        }
+        if (icon == null && density != 0 && (info.icon != 0 || appInfo.icon != 0)) {
             try {
                 final Resources resources = mContext.getPackageManager()
-                        .getResourcesForApplication(ai.applicationInfo);
-                icon = resources.getDrawableForDensity(iconRes, density);
+                        .getResourcesForApplication(appInfo);
+                // Try to load the package item icon first
+                if (info.icon != 0) {
+                    try {
+                        icon = resources.getDrawableForDensity(info.icon, density);
+                    } catch (Resources.NotFoundException exc) { }
+                }
+                if (icon == null && appInfo.icon != 0) {
+                    // Load the fallback app icon
+                    try {
+                        icon = resources.getDrawableForDensity(appInfo.icon, density);
+                    } catch (Resources.NotFoundException exc) { }
+                }
             } catch (NameNotFoundException | Resources.NotFoundException exc) { }
         }
-        // Get the default density icon
-        if (icon == null) {
-            icon = ai.loadIcon(mContext.getPackageManager());
-        }
-        return icon;
+        return icon != null ? icon : getFullResDefaultActivityIcon(density);
     }
 
     @TargetApi(Build.VERSION_CODES.TIRAMISU)
@@ -201,6 +235,15 @@ public class IconProvider {
         return null;
     }
 
+    /**
+     * Returns the default activity icon
+     */
+    @NonNull
+    public Drawable getFullResDefaultActivityIcon(final int iconDpi) {
+        return Objects.requireNonNull(Resources.getSystem().getDrawableForDensity(
+                android.R.drawable.sym_def_app_icon, iconDpi));
+    }
+
     /**
      * @param metadata metadata of the default activity of Calendar
      * @param resources from the Calendar package
@@ -225,6 +268,16 @@ public class IconProvider {
         }
     }
 
+    /**
+     * Refreshes the system state definition used to check the validity of an app icon. It
+     * incorporates all the properties that can affect the app icon like the list of enabled locale
+     * and system-version.
+     */
+    public void updateSystemState() {
+        mSystemState = mContext.getResources().getConfiguration().getLocales().toLanguageTags()
+                + "," + Build.VERSION.SDK_INT;
+    }
+
     /**
      * @return Today's day of the month, zero-indexed.
      */
diff --git a/iconloaderlib/src/com/android/launcher3/icons/MonochromeIconFactory.java b/iconloaderlib/src/com/android/launcher3/icons/MonochromeIconFactory.java
new file mode 100644
index 0000000..dc4ded8
--- /dev/null
+++ b/iconloaderlib/src/com/android/launcher3/icons/MonochromeIconFactory.java
@@ -0,0 +1,172 @@
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
+package com.android.launcher3.icons;
+
+import static android.graphics.Paint.FILTER_BITMAP_FLAG;
+
+import android.annotation.TargetApi;
+import android.graphics.Bitmap;
+import android.graphics.Bitmap.Config;
+import android.graphics.BlendMode;
+import android.graphics.Canvas;
+import android.graphics.Color;
+import android.graphics.ColorFilter;
+import android.graphics.ColorMatrix;
+import android.graphics.ColorMatrixColorFilter;
+import android.graphics.Paint;
+import android.graphics.PixelFormat;
+import android.graphics.Rect;
+import android.graphics.drawable.AdaptiveIconDrawable;
+import android.graphics.drawable.Drawable;
+import android.os.Build;
+
+import androidx.annotation.WorkerThread;
+
+import com.android.launcher3.icons.mono.MonoIconThemeController.ClippedMonoDrawable;
+
+import java.nio.ByteBuffer;
+
+/**
+ * Utility class to generate monochrome icons version for a given drawable.
+ */
+@TargetApi(Build.VERSION_CODES.TIRAMISU)
+public class MonochromeIconFactory extends Drawable {
+
+    private final Bitmap mFlatBitmap;
+    private final Canvas mFlatCanvas;
+    private final Paint mCopyPaint;
+
+    private final Bitmap mAlphaBitmap;
+    private final Canvas mAlphaCanvas;
+    private final byte[] mPixels;
+
+    private final int mBitmapSize;
+    private final int mEdgePixelLength;
+
+    private final Paint mDrawPaint;
+    private final Rect mSrcRect;
+
+    public MonochromeIconFactory(int iconBitmapSize) {
+        float extraFactor = AdaptiveIconDrawable.getExtraInsetFraction();
+        float viewPortScale = 1 / (1 + 2 * extraFactor);
+        mBitmapSize = Math.round(iconBitmapSize * 2 * viewPortScale);
+        mPixels = new byte[mBitmapSize * mBitmapSize];
+        mEdgePixelLength = mBitmapSize * (mBitmapSize - iconBitmapSize) / 2;
+
+        mFlatBitmap = Bitmap.createBitmap(mBitmapSize, mBitmapSize, Config.ARGB_8888);
+        mFlatCanvas = new Canvas(mFlatBitmap);
+
+        mAlphaBitmap = Bitmap.createBitmap(mBitmapSize, mBitmapSize, Config.ALPHA_8);
+        mAlphaCanvas = new Canvas(mAlphaBitmap);
+
+        mDrawPaint = new Paint(FILTER_BITMAP_FLAG);
+        mDrawPaint.setColor(Color.WHITE);
+        mSrcRect = new Rect(0, 0, mBitmapSize, mBitmapSize);
+
+        mCopyPaint = new Paint(FILTER_BITMAP_FLAG);
+        mCopyPaint.setBlendMode(BlendMode.SRC);
+
+        // Crate a color matrix which converts the icon to grayscale and then uses the average
+        // of RGB components as the alpha component.
+        ColorMatrix satMatrix = new ColorMatrix();
+        satMatrix.setSaturation(0);
+        float[] vals = satMatrix.getArray();
+        vals[15] = vals[16] = vals[17] = .3333f;
+        vals[18] = vals[19] = 0;
+        mCopyPaint.setColorFilter(new ColorMatrixColorFilter(vals));
+    }
+
+    private void drawDrawable(Drawable drawable) {
+        if (drawable != null) {
+            drawable.setBounds(0, 0, mBitmapSize, mBitmapSize);
+            drawable.draw(mFlatCanvas);
+        }
+    }
+
+    /**
+     * Creates a monochrome version of the provided drawable
+     */
+    @WorkerThread
+    public Drawable wrap(AdaptiveIconDrawable icon) {
+        mFlatCanvas.drawColor(Color.BLACK);
+        drawDrawable(icon.getBackground());
+        drawDrawable(icon.getForeground());
+        generateMono();
+        return new ClippedMonoDrawable(this);
+    }
+
+    @WorkerThread
+    private void generateMono() {
+        mAlphaCanvas.drawBitmap(mFlatBitmap, 0, 0, mCopyPaint);
+
+        // Scale the end points:
+        ByteBuffer buffer = ByteBuffer.wrap(mPixels);
+        buffer.rewind();
+        mAlphaBitmap.copyPixelsToBuffer(buffer);
+
+        int min = 0xFF;
+        int max = 0;
+        for (byte b : mPixels) {
+            min = Math.min(min, b & 0xFF);
+            max = Math.max(max, b & 0xFF);
+        }
+
+        if (min < max) {
+            // rescale pixels to increase contrast
+            float range = max - min;
+
+            // In order to check if the colors should be flipped, we just take the average color
+            // of top and bottom edge which should correspond to be background color. If the edge
+            // colors have more opacity, we flip the colors;
+            int sum = 0;
+            for (int i = 0; i < mEdgePixelLength; i++) {
+                sum += (mPixels[i] & 0xFF);
+                sum += (mPixels[mPixels.length - 1 - i] & 0xFF);
+            }
+            float edgeAverage = sum / (mEdgePixelLength * 2f);
+            float edgeMapped = (edgeAverage - min) / range;
+            boolean flipColor = edgeMapped > .5f;
+
+            for (int i = 0; i < mPixels.length; i++) {
+                int p = mPixels[i] & 0xFF;
+                int p2 = Math.round((p - min) * 0xFF / range);
+                mPixels[i] = flipColor ? (byte) (255 - p2) : (byte) (p2);
+            }
+            buffer.rewind();
+            mAlphaBitmap.copyPixelsFromBuffer(buffer);
+        }
+    }
+
+    @Override
+    public void draw(Canvas canvas) {
+        canvas.drawBitmap(mAlphaBitmap, mSrcRect, getBounds(), mDrawPaint);
+    }
+
+    @Override
+    public int getOpacity() {
+        return PixelFormat.TRANSLUCENT;
+    }
+
+    @Override
+    public void setAlpha(int i) {
+        mDrawPaint.setAlpha(i);
+    }
+
+    @Override
+    public void setColorFilter(ColorFilter colorFilter) {
+        mDrawPaint.setColorFilter(colorFilter);
+    }
+}
diff --git a/iconloaderlib/src/com/android/launcher3/icons/ThemedBitmap.kt b/iconloaderlib/src/com/android/launcher3/icons/ThemedBitmap.kt
new file mode 100644
index 0000000..27b4619
--- /dev/null
+++ b/iconloaderlib/src/com/android/launcher3/icons/ThemedBitmap.kt
@@ -0,0 +1,46 @@
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
+package com.android.launcher3.icons
+
+import android.content.Context
+import android.graphics.drawable.AdaptiveIconDrawable
+
+/** Represents a themed version of a BitmapInfo */
+interface ThemedBitmap {
+
+    /** Creates a new Drawable */
+    fun newDrawable(info: BitmapInfo, context: Context): FastBitmapDrawable
+
+    fun serialize(): ByteArray
+}
+
+interface IconThemeController {
+
+    fun createThemedBitmap(
+        icon: AdaptiveIconDrawable,
+        info: BitmapInfo,
+        factory: BaseIconFactory,
+    ): ThemedBitmap?
+
+    fun decode(data: ByteArray, info: BitmapInfo, factory: BaseIconFactory): ThemedBitmap?
+
+    fun createThemedAdaptiveIcon(
+        context: Context,
+        originalIcon: AdaptiveIconDrawable,
+        info: BitmapInfo?,
+    ): AdaptiveIconDrawable?
+}
diff --git a/iconloaderlib/src/com/android/launcher3/icons/ThemedIconDrawable.java b/iconloaderlib/src/com/android/launcher3/icons/ThemedIconDrawable.java
deleted file mode 100644
index 46073ea..0000000
--- a/iconloaderlib/src/com/android/launcher3/icons/ThemedIconDrawable.java
+++ /dev/null
@@ -1,130 +0,0 @@
-/*
- * Copyright (C) 2021 The Android Open Source Project
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
-package com.android.launcher3.icons;
-
-import android.content.Context;
-import android.content.res.Resources;
-import android.graphics.Bitmap;
-import android.graphics.BlendMode;
-import android.graphics.BlendModeColorFilter;
-import android.graphics.Canvas;
-import android.graphics.ColorFilter;
-import android.graphics.Paint;
-import android.graphics.Rect;
-
-/**
- * Class to handle monochrome themed app icons
- */
-@SuppressWarnings("NewApi")
-public class ThemedIconDrawable extends FastBitmapDrawable {
-
-    public static final String TAG = "ThemedIconDrawable";
-
-    final BitmapInfo bitmapInfo;
-    final int colorFg, colorBg;
-
-    // The foreground/monochrome icon for the app
-    private final Bitmap mMonoIcon;
-    private final Paint mMonoPaint = new Paint(Paint.ANTI_ALIAS_FLAG | Paint.FILTER_BITMAP_FLAG);
-
-    private final Bitmap mBgBitmap;
-    private final Paint mBgPaint = new Paint(Paint.ANTI_ALIAS_FLAG | Paint.FILTER_BITMAP_FLAG);
-
-    private final ColorFilter mBgFilter, mMonoFilter;
-
-    protected ThemedIconDrawable(ThemedConstantState constantState) {
-        super(constantState.mBitmap, constantState.colorFg);
-        bitmapInfo = constantState.bitmapInfo;
-        colorBg = constantState.colorBg;
-        colorFg = constantState.colorFg;
-
-        mMonoIcon = bitmapInfo.mMono;
-        mMonoFilter = new BlendModeColorFilter(colorFg, BlendMode.SRC_IN);
-        mMonoPaint.setColorFilter(mMonoFilter);
-
-        mBgBitmap = bitmapInfo.mWhiteShadowLayer;
-        mBgFilter = new BlendModeColorFilter(colorBg, BlendMode.SRC_IN);
-        mBgPaint.setColorFilter(mBgFilter);
-    }
-
-    @Override
-    protected void drawInternal(Canvas canvas, Rect bounds) {
-        canvas.drawBitmap(mBgBitmap, null, bounds, mBgPaint);
-        canvas.drawBitmap(mMonoIcon, null, bounds, mMonoPaint);
-    }
-
-    @Override
-    protected void updateFilter() {
-        super.updateFilter();
-        int alpha = mIsDisabled ? (int) (mDisabledAlpha * FULLY_OPAQUE) : FULLY_OPAQUE;
-        mBgPaint.setAlpha(alpha);
-        mBgPaint.setColorFilter(mIsDisabled ? new BlendModeColorFilter(
-                getDisabledColor(colorBg), BlendMode.SRC_IN) : mBgFilter);
-
-        mMonoPaint.setAlpha(alpha);
-        mMonoPaint.setColorFilter(mIsDisabled ? new BlendModeColorFilter(
-                getDisabledColor(colorFg), BlendMode.SRC_IN) : mMonoFilter);
-    }
-
-    @Override
-    public boolean isThemed() {
-        return true;
-    }
-
-    @Override
-    public FastBitmapConstantState newConstantState() {
-        return new ThemedConstantState(bitmapInfo, colorBg, colorFg);
-    }
-
-    static class ThemedConstantState extends FastBitmapConstantState {
-
-        final BitmapInfo bitmapInfo;
-        final int colorFg, colorBg;
-
-        public ThemedConstantState(BitmapInfo bitmapInfo, int colorBg, int colorFg) {
-            super(bitmapInfo.icon, bitmapInfo.color);
-            this.bitmapInfo = bitmapInfo;
-            this.colorBg = colorBg;
-            this.colorFg = colorFg;
-        }
-
-        @Override
-        public FastBitmapDrawable createDrawable() {
-            return new ThemedIconDrawable(this);
-        }
-    }
-
-    public static FastBitmapDrawable newDrawable(BitmapInfo info, Context context) {
-        int[] colors = getColors(context);
-        return new ThemedConstantState(info, colors[0], colors[1]).newDrawable();
-    }
-
-    /**
-     * Get an int array representing background and foreground colors for themed icons
-     */
-    public static int[] getColors(Context context) {
-        Resources res = context.getResources();
-        int[] colors = new int[2];
-        colors[0] = res.getColor(R.color.themed_icon_background_color);
-        colors[1] = res.getColor(R.color.themed_icon_color);
-        return colors;
-    }
-
-    @Override
-    public int getIconColor() {
-        return colorFg;
-    }
-}
diff --git a/iconloaderlib/src/com/android/launcher3/icons/cache/BaseIconCache.java b/iconloaderlib/src/com/android/launcher3/icons/cache/BaseIconCache.java
index 287480f..959f14d 100644
--- a/iconloaderlib/src/com/android/launcher3/icons/cache/BaseIconCache.java
+++ b/iconloaderlib/src/com/android/launcher3/icons/cache/BaseIconCache.java
@@ -15,9 +15,10 @@
  */
 package com.android.launcher3.icons.cache;
 
+import static android.content.pm.PackageManager.MATCH_UNINSTALLED_PACKAGES;
 import static android.graphics.BitmapFactory.decodeByteArray;
 
-import static com.android.launcher3.icons.BaseIconFactory.getFullResDefaultActivityIcon;
+import static com.android.launcher3.Flags.forceMonochromeAppIcons;
 import static com.android.launcher3.icons.BitmapInfo.LOW_RES_ICON;
 import static com.android.launcher3.icons.GraphicsUtils.flattenBitmap;
 import static com.android.launcher3.icons.GraphicsUtils.setColorAlphaBound;
@@ -29,10 +30,9 @@ import android.content.ContentValues;
 import android.content.Context;
 import android.content.pm.ActivityInfo;
 import android.content.pm.ApplicationInfo;
-import android.content.pm.PackageInfo;
+import android.content.pm.LauncherApps;
 import android.content.pm.PackageManager;
 import android.content.pm.PackageManager.NameNotFoundException;
-import android.content.res.Resources;
 import android.database.Cursor;
 import android.database.sqlite.SQLiteDatabase;
 import android.database.sqlite.SQLiteException;
@@ -41,32 +41,32 @@ import android.graphics.Bitmap;
 import android.graphics.Bitmap.Config;
 import android.graphics.BitmapFactory;
 import android.graphics.drawable.Drawable;
-import android.os.Build;
 import android.os.Handler;
-import android.os.LocaleList;
 import android.os.Looper;
-import android.os.Process;
 import android.os.Trace;
 import android.os.UserHandle;
 import android.text.TextUtils;
 import android.util.Log;
 import android.util.SparseArray;
 
+import androidx.annotation.IntDef;
 import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
 import androidx.annotation.VisibleForTesting;
 import androidx.annotation.WorkerThread;
 
-import com.android.launcher3.Flags;
 import com.android.launcher3.icons.BaseIconFactory;
 import com.android.launcher3.icons.BaseIconFactory.IconOptions;
 import com.android.launcher3.icons.BitmapInfo;
 import com.android.launcher3.icons.IconProvider;
+import com.android.launcher3.icons.IconThemeController;
+import com.android.launcher3.icons.ThemedBitmap;
 import com.android.launcher3.util.ComponentKey;
 import com.android.launcher3.util.FlagOp;
 import com.android.launcher3.util.SQLiteCacheHelper;
 
-import java.nio.ByteBuffer;
+import java.lang.annotation.Retention;
+import java.lang.annotation.RetentionPolicy;
 import java.util.AbstractMap;
 import java.util.Arrays;
 import java.util.Collections;
@@ -88,6 +88,37 @@ public abstract class BaseIconCache {
     // Empty class name is used for storing package default entry.
     public static final String EMPTY_CLASS_NAME = ".";
 
+    @Retention(RetentionPolicy.SOURCE)
+    @IntDef(value = {
+            LookupFlag.DEFAULT,
+            LookupFlag.USE_LOW_RES,
+            LookupFlag.USE_PACKAGE_ICON,
+            LookupFlag.SKIP_ADD_TO_MEM_CACHE
+    }, flag = true)
+    /** Various options to control cache lookup */
+    public @interface LookupFlag {
+        /**
+         * Default behavior of cache lookup is to load high-res icon with no fallback
+         */
+        int DEFAULT = 0;
+
+        /**
+         * When specified, the cache tries to load the low res version of the entry unless a
+         * high-res is already in memory
+         */
+        int USE_LOW_RES = 1 << 0;
+        /**
+         * When specified, the cache tries to lookup the package entry for the item, if the object
+         * entry fails
+         */
+        int USE_PACKAGE_ICON = 1 << 1;
+        /**
+         * When specified, the entry will not be added to the memory cache if it was not already
+         * added by a previous lookup
+         */
+        int SKIP_ADD_TO_MEM_CACHE = 1 << 2;
+    }
+
     public static class CacheEntry {
 
         @NonNull
@@ -110,20 +141,16 @@ public abstract class BaseIconCache {
     @NonNull
     private final Map<ComponentKey, CacheEntry> mCache;
 
+    public final Object iconUpdateToken = new Object();
+
     @NonNull
-    protected final Handler mWorkerHandler;
+    public final Handler workerHandler;
 
     protected int mIconDpi;
 
     @NonNull
     protected IconDB mIconDb;
 
-    @NonNull
-    protected LocaleList mLocaleList = LocaleList.getEmptyLocaleList();
-
-    @NonNull
-    protected String mSystemState = "";
-
     @Nullable
     private BitmapInfo mDefaultIcon;
 
@@ -138,8 +165,6 @@ public abstract class BaseIconCache {
     @NonNull
     private final Looper mBgLooper;
 
-    private volatile boolean mIconUpdateInProgress = false;
-
     public BaseIconCache(@NonNull final Context context, @Nullable final String dbFileName,
             @NonNull final Looper bgLooper, final int iconDpi, final int iconPixelSize,
             final boolean inMemoryCache) {
@@ -155,13 +180,13 @@ public abstract class BaseIconCache {
         mIconProvider = iconProvider;
         mPackageManager = context.getPackageManager();
         mBgLooper = bgLooper;
-        mWorkerHandler = new Handler(mBgLooper);
+        workerHandler = new Handler(mBgLooper);
 
         if (inMemoryCache) {
             mCache = new HashMap<>(INITIAL_ICON_CACHE_CAPACITY);
         } else {
             // Use a dummy cache
-            mCache = new AbstractMap<ComponentKey, CacheEntry>() {
+            mCache = new AbstractMap<>() {
                 @Override
                 public Set<Entry<ComponentKey, CacheEntry>> entrySet() {
                     return Collections.emptySet();
@@ -197,7 +222,7 @@ public abstract class BaseIconCache {
     public abstract BaseIconFactory getIconFactory();
 
     public void updateIconParams(final int iconDpi, final int iconPixelSize) {
-        mWorkerHandler.post(() -> updateIconParamsBg(iconDpi, iconPixelSize));
+        workerHandler.post(() -> updateIconParamsBg(iconDpi, iconPixelSize));
     }
 
     private synchronized void updateIconParamsBg(final int iconDpi, final int iconPixelSize) {
@@ -221,42 +246,9 @@ public abstract class BaseIconCache {
         }
     }
 
-    @Nullable
-    private Drawable getFullResIcon(@Nullable final Resources resources, final int iconId) {
-        if (resources != null && iconId != 0) {
-            try {
-                return resources.getDrawableForDensity(iconId, mIconDpi);
-            } catch (Resources.NotFoundException e) {
-            }
-        }
-        return getFullResDefaultActivityIcon(mIconDpi);
-    }
-
-    @Nullable
-    public Drawable getFullResIcon(@NonNull final String packageName, final int iconId) {
-        try {
-            return getFullResIcon(mPackageManager.getResourcesForApplication(packageName), iconId);
-        } catch (PackageManager.NameNotFoundException e) {
-        }
-        return getFullResDefaultActivityIcon(mIconDpi);
-    }
-
     @Nullable
     public Drawable getFullResIcon(@NonNull final ActivityInfo info) {
-        try {
-            return getFullResIcon(mPackageManager.getResourcesForApplication(info.applicationInfo),
-                    info.getIconResource());
-        } catch (PackageManager.NameNotFoundException e) {
-        }
-        return getFullResDefaultActivityIcon(mIconDpi);
-    }
-
-    public void setIconUpdateInProgress(boolean updating) {
-        mIconUpdateInProgress = updating;
-    }
-
-    public boolean isIconUpdateInProgress() {
-        return mIconUpdateInProgress;
+        return mIconProvider.getIcon(info, mIconDpi);
     }
 
     /**
@@ -299,7 +291,11 @@ public abstract class BaseIconCache {
     @NonNull
     public IconCacheUpdateHandler getUpdateHandler() {
         updateSystemState();
-        return new IconCacheUpdateHandler(this);
+
+        // Remove all active icon update tasks.
+        workerHandler.removeCallbacksAndMessages(iconUpdateToken);
+
+        return new IconCacheUpdateHandler(this, mIconDb, workerHandler);
     }
 
     /**
@@ -308,16 +304,10 @@ public abstract class BaseIconCache {
      * and system-version.
      */
     private void updateSystemState() {
-        mLocaleList = mContext.getResources().getConfiguration().getLocales();
-        mSystemState = mLocaleList.toLanguageTags() + "," + Build.VERSION.SDK_INT;
+        mIconProvider.updateSystemState();
         mUserFormatString.clear();
     }
 
-    @NonNull
-    protected String getIconSystemState(@Nullable final String packageName) {
-        return mIconProvider.getSystemStateForPackage(mSystemState, packageName);
-    }
-
     public IconProvider getIconProvider() {
         return mIconProvider;
     }
@@ -339,76 +329,49 @@ public abstract class BaseIconCache {
     }
 
     /**
-     * Adds an entry into the DB and the in-memory cache.
-     *
-     * @param replaceExisting if true, it will recreate the bitmap even if it already exists in
-     *                        the memory. This is useful then the previous bitmap was created using
-     *                        old data.
+     * Adds/updates an entry into the DB and the in-memory cache. The update is skipped if the
+     * entry fails to load
      */
-    @VisibleForTesting
-    public synchronized <T> void addIconToDBAndMemCache(@NonNull final T object,
-            @NonNull final CachingLogic<T> cachingLogic, @NonNull final PackageInfo info,
-            final long userSerial, final boolean replaceExisting) {
+    protected synchronized <T> void addIconToDBAndMemCache(@NonNull final T object,
+            @NonNull final CachingLogic<T> cachingLogic, final long userSerial) {
         UserHandle user = cachingLogic.getUser(object);
         ComponentName componentName = cachingLogic.getComponent(object);
-
         final ComponentKey key = new ComponentKey(componentName, user);
-        CacheEntry entry = null;
-        if (!replaceExisting) {
-            entry = mCache.get(key);
-            // We can't reuse the entry if the high-res icon is not present.
-            if (entry == null || entry.bitmap.isNullOrLowRes()) {
-                entry = null;
-            }
-        }
-        if (entry == null) {
-            entry = new CacheEntry();
-            entry.bitmap = cachingLogic.loadIcon(mContext, this, object);
-        }
+
+        BitmapInfo bitmapInfo = cachingLogic.loadIcon(mContext, this, object);
+
         // Icon can't be loaded from cachingLogic, which implies alternative icon was loaded
         // (e.g. fallback icon, default icon). So we drop here since there's no point in caching
         // an empty entry.
-        if (entry.bitmap.isNullOrLowRes() || isDefaultIcon(entry.bitmap, user)) {
+        if (bitmapInfo.isNullOrLowRes() || isDefaultIcon(bitmapInfo, user)) {
             return;
         }
 
         CharSequence entryTitle = cachingLogic.getLabel(object);
         if (TextUtils.isEmpty(entryTitle)) {
-            if (entryTitle == null) {
-                Log.wtf(TAG, "No label returned from caching logic instance: " + cachingLogic);
-            }
             entryTitle = componentName.getPackageName();
         }
-        entry.title = entryTitle;
-
-        entry.contentDescription = getUserBadgedLabel(entry.title, user);
-        if (cachingLogic.addToMemCache()) mCache.put(key, entry);
 
-        ContentValues values = newContentValues(
-                entry.bitmap, entry.title.toString(), componentName.getPackageName());
-        addIconToDB(values, componentName, info, userSerial,
-                cachingLogic.getLastUpdatedTime(object, info));
-    }
+        // Only add an entry in memory, if there was already something previously
+        if (mCache.get(key) != null) {
+            CacheEntry entry = new CacheEntry();
+            entry.bitmap = bitmapInfo;
+            entry.title = entryTitle;
+            entry.contentDescription = getUserBadgedLabel(entryTitle, user);
+            mCache.put(key, entry);
+        }
 
-    /**
-     * Updates {@param values} to contain versioning information and adds it to the DB.
-     *
-     * @param values {@link ContentValues} containing icon & title
-     */
-    private void addIconToDB(@NonNull final ContentValues values, @NonNull final ComponentName key,
-            @NonNull final PackageInfo info, final long userSerial, final long lastUpdateTime) {
-        values.put(IconDB.COLUMN_COMPONENT, key.flattenToString());
-        values.put(IconDB.COLUMN_USER, userSerial);
-        values.put(IconDB.COLUMN_LAST_UPDATED, lastUpdateTime);
-        values.put(IconDB.COLUMN_VERSION, info.versionCode);
-        mIconDb.insertOrReplace(values);
+        String freshnessId = cachingLogic.getFreshnessIdentifier(object, mIconProvider);
+        if (freshnessId != null) {
+            addOrUpdateCacheDbEntry(bitmapInfo, entryTitle, componentName, userSerial, freshnessId);
+        }
     }
 
     @NonNull
     public synchronized BitmapInfo getDefaultIcon(@NonNull final UserHandle user) {
         if (mDefaultIcon == null) {
             try (BaseIconFactory li = getIconFactory()) {
-                mDefaultIcon = li.makeDefaultIcon();
+                mDefaultIcon = li.makeDefaultIcon(mIconProvider);
             }
         }
         return mDefaultIcon.withFlags(getUserFlagOpLocked(user));
@@ -441,29 +404,30 @@ public abstract class BaseIconCache {
     protected <T> CacheEntry cacheLocked(
             @NonNull final ComponentName componentName, @NonNull final UserHandle user,
             @NonNull final Supplier<T> infoProvider, @NonNull final CachingLogic<T> cachingLogic,
-            final boolean usePackageIcon, final boolean useLowResIcon) {
+            @LookupFlag int lookupFlags) {
         return cacheLocked(
                 componentName,
                 user,
                 infoProvider,
                 cachingLogic,
-                null,
-                usePackageIcon,
-                useLowResIcon);
+                lookupFlags,
+                null);
     }
 
     @NonNull
     protected <T> CacheEntry cacheLocked(
             @NonNull final ComponentName componentName, @NonNull final UserHandle user,
             @NonNull final Supplier<T> infoProvider, @NonNull final CachingLogic<T> cachingLogic,
-            @Nullable final Cursor cursor, final boolean usePackageIcon,
-            final boolean useLowResIcon) {
+            @LookupFlag int lookupFlags, @Nullable final Cursor cursor) {
         assertWorkerThread();
         ComponentKey cacheKey = new ComponentKey(componentName, user);
         CacheEntry entry = mCache.get(cacheKey);
+        final boolean useLowResIcon = (lookupFlags & LookupFlag.USE_LOW_RES) != 0;
         if (entry == null || (entry.bitmap.isLowRes() && !useLowResIcon)) {
+            boolean addToMemCache = entry != null
+                    || (lookupFlags & LookupFlag.SKIP_ADD_TO_MEM_CACHE) == 0;
             entry = new CacheEntry();
-            if (cachingLogic.addToMemCache()) {
+            if (addToMemCache) {
                 mCache.put(cacheKey, entry);
             }
 
@@ -481,7 +445,7 @@ public abstract class BaseIconCache {
                         object,
                         entry,
                         cachingLogic,
-                        usePackageIcon,
+                        (lookupFlags & LookupFlag.USE_PACKAGE_ICON) != 0,
                         /* usePackageTitle= */ true,
                         componentName,
                         user);
@@ -542,8 +506,7 @@ public abstract class BaseIconCache {
         if (TextUtils.isEmpty(entry.title)) {
             entry.title = cachingLogic.getComponent(object).getPackageName();
         }
-        entry.contentDescription = getUserBadgedLabel(
-                cachingLogic.getDescription(object, entry.title), user);
+        entry.contentDescription = getUserBadgedLabel(entry.title, user);
     }
 
     public synchronized void clearMemoryCache() {
@@ -584,12 +547,27 @@ public abstract class BaseIconCache {
     }
 
     @NonNull
-    private static ComponentKey getPackageKey(@NonNull final String packageName,
+    public static ComponentKey getPackageKey(@NonNull final String packageName,
             @NonNull final UserHandle user) {
         ComponentName cn = new ComponentName(packageName, packageName + EMPTY_CLASS_NAME);
         return new ComponentKey(cn, user);
     }
 
+    /**
+     * Returns the package entry if it has already been cached in memory, null otherwise
+     */
+    @Nullable
+    protected CacheEntry getInMemoryPackageEntryLocked(@NonNull final String packageName,
+            @NonNull final UserHandle user) {
+        return getInMemoryEntryLocked(getPackageKey(packageName, user));
+    }
+
+    @VisibleForTesting
+    public CacheEntry getInMemoryEntryLocked(ComponentKey key) {
+        assertWorkerThread();
+        return mCache.get(key);
+    }
+
     /**
      * Gets an entry for the package, which can be used as a fallback entry for various components.
      * This method is not thread safe, it must be called from a synchronized method.
@@ -610,28 +588,23 @@ public abstract class BaseIconCache {
             // Check the DB first.
             if (!getEntryFromDBLocked(cacheKey, entry, useLowResIcon)) {
                 try {
-                    long flags = Process.myUserHandle().equals(user) ? 0 :
-                            PackageManager.GET_UNINSTALLED_PACKAGES;
-                    flags |= PackageManager.MATCH_ARCHIVED_PACKAGES;
-                    PackageInfo info = mPackageManager.getPackageInfo(packageName,
-                            PackageManager.PackageInfoFlags.of(flags));
-                    ApplicationInfo appInfo = info.applicationInfo;
+                    ApplicationInfo appInfo = mContext.getSystemService(LauncherApps.class)
+                            .getApplicationInfo(packageName, MATCH_UNINSTALLED_PACKAGES, user);
                     if (appInfo == null) {
-                        NameNotFoundException e = new NameNotFoundException(
-                                "ApplicationInfo is null");
+                        NameNotFoundException e =
+                                new NameNotFoundException("ApplicationInfo is null");
                         logdPersistently(TAG,
-                                String.format("ApplicationInfo is null for %s", packageName),
-                                e);
+                                String.format("ApplicationInfo is null for %s", packageName), e);
                         throw e;
                     }
 
                     BaseIconFactory li = getIconFactory();
                     // Load the full res icon for the application, but if useLowResIcon is set, then
                     // only keep the low resolution icon instead of the larger full-sized icon
-                    Drawable appIcon = appInfo.loadIcon(mPackageManager);
+                    Drawable appIcon = mIconProvider.getIcon(appInfo);
                     if (mPackageManager.isDefaultApplicationIcon(appIcon)) {
                         logdPersistently(TAG,
-                                String.format("Default icon returned for %s", packageName),
+                                String.format("Default icon returned for %s", appInfo.packageName),
                                 null);
                     }
                     BitmapInfo iconInfo = li.createBadgedIconBitmap(appIcon,
@@ -646,11 +619,12 @@ public abstract class BaseIconCache {
 
                     // Add the icon in the DB here, since these do not get written during
                     // package updates.
-                    ContentValues values = newContentValues(
-                            iconInfo, entry.title.toString(), packageName);
-                    addIconToDB(values, cacheKey.componentName, info, getSerialNumberForUser(user),
-                            info.lastUpdateTime);
-
+                    String freshnessId = mIconProvider.getStateForApp(appInfo);
+                    if (freshnessId != null) {
+                        addOrUpdateCacheDbEntry(
+                                iconInfo, entry.title, cacheKey.componentName,
+                                getSerialNumberForUser(user), freshnessId);
+                    }
                 } catch (NameNotFoundException e) {
                     if (DEBUG) Log.d(TAG, "Application not installed " + packageName);
                     entryUpdated = false;
@@ -719,20 +693,13 @@ public abstract class BaseIconCache {
                 return false;
             }
 
-            // Decode mono bitmap
-            data = c.getBlob(IconDB.INDEX_MONO_ICON);
-            Bitmap icon = entry.bitmap.icon;
-            if (data != null && data.length == icon.getHeight() * icon.getWidth()) {
-                Bitmap monoBitmap = Bitmap.createBitmap(
-                        icon.getWidth(), icon.getHeight(), Config.ALPHA_8);
-                monoBitmap.copyPixelsFromBuffer(ByteBuffer.wrap(data));
-                Bitmap hwMonoBitmap = monoBitmap.copy(Config.HARDWARE, false /*isMutable*/);
-                if (hwMonoBitmap != null) {
-                    monoBitmap.recycle();
-                    monoBitmap = hwMonoBitmap;
-                }
-                try (BaseIconFactory factory = getIconFactory()) {
-                    entry.bitmap.setMonoIcon(monoBitmap, factory);
+            // Decode theme bitmap
+            try (BaseIconFactory factory = getIconFactory()) {
+                IconThemeController themeController = factory.getThemeController();
+                data = c.getBlob(IconDB.INDEX_MONO_ICON);
+                if (themeController != null && data != null) {
+                    entry.bitmap.setThemedBitmap(
+                            themeController.decode(data, entry.bitmap, factory));
                 }
             }
         }
@@ -755,20 +722,18 @@ public abstract class BaseIconCache {
     public static final class IconDB extends SQLiteCacheHelper {
         // Ensures archived app icons are invalidated after flag is flipped.
         // TODO: Remove conditional with FLAG_USE_NEW_ICON_FOR_ARCHIVED_APPS
-        private static final int RELEASE_VERSION = Flags.useNewIconForArchivedApps() ? 35 : 34;
+        private static final int RELEASE_VERSION = forceMonochromeAppIcons() ? 3 : 2;
 
         public static final String TABLE_NAME = "icons";
         public static final String COLUMN_ROWID = "rowid";
         public static final String COLUMN_COMPONENT = "componentName";
         public static final String COLUMN_USER = "profileId";
-        public static final String COLUMN_LAST_UPDATED = "lastUpdated";
-        public static final String COLUMN_VERSION = "version";
+        public static final String COLUMN_FRESHNESS_ID = "freshnessId";
         public static final String COLUMN_ICON = "icon";
         public static final String COLUMN_ICON_COLOR = "icon_color";
         public static final String COLUMN_MONO_ICON = "mono_icon";
         public static final String COLUMN_FLAGS = "flags";
         public static final String COLUMN_LABEL = "label";
-        public static final String COLUMN_SYSTEM_STATE = "system_state";
 
         public static final String[] COLUMNS_LOW_RES = new String[]{
                 COLUMN_COMPONENT,
@@ -799,47 +764,43 @@ public abstract class BaseIconCache {
             db.execSQL("CREATE TABLE IF NOT EXISTS " + TABLE_NAME + " ("
                     + COLUMN_COMPONENT + " TEXT NOT NULL, "
                     + COLUMN_USER + " INTEGER NOT NULL, "
-                    + COLUMN_LAST_UPDATED + " INTEGER NOT NULL DEFAULT 0, "
-                    + COLUMN_VERSION + " INTEGER NOT NULL DEFAULT 0, "
+                    + COLUMN_FRESHNESS_ID + " TEXT, "
                     + COLUMN_ICON + " BLOB, "
                     + COLUMN_MONO_ICON + " BLOB, "
                     + COLUMN_ICON_COLOR + " INTEGER NOT NULL DEFAULT 0, "
                     + COLUMN_FLAGS + " INTEGER NOT NULL DEFAULT 0, "
                     + COLUMN_LABEL + " TEXT, "
-                    + COLUMN_SYSTEM_STATE + " TEXT, "
                     + "PRIMARY KEY (" + COLUMN_COMPONENT + ", " + COLUMN_USER + ") "
                     + ");");
         }
     }
 
     @NonNull
-    private ContentValues newContentValues(@NonNull final BitmapInfo bitmapInfo,
-            @NonNull final String label, @NonNull final String packageName) {
+    private void addOrUpdateCacheDbEntry(
+            @NonNull final BitmapInfo bitmapInfo,
+            @NonNull final CharSequence label,
+            @NonNull final ComponentName key,
+            final long userSerial,
+            @NonNull final String freshnessId) {
         ContentValues values = new ContentValues();
         if (bitmapInfo.canPersist()) {
             values.put(IconDB.COLUMN_ICON, flattenBitmap(bitmapInfo.icon));
 
-            // Persist mono bitmap as alpha channel
-            Bitmap mono = bitmapInfo.getMono();
-            if (mono != null && mono.getHeight() == bitmapInfo.icon.getHeight()
-                    && mono.getWidth() == bitmapInfo.icon.getWidth()
-                    && mono.getConfig() == Config.ALPHA_8) {
-                byte[] pixels = new byte[mono.getWidth() * mono.getHeight()];
-                mono.copyPixelsToBuffer(ByteBuffer.wrap(pixels));
-                values.put(IconDB.COLUMN_MONO_ICON, pixels);
-            } else {
-                values.put(IconDB.COLUMN_MONO_ICON, (byte[]) null);
-            }
+            ThemedBitmap themedBitmap = bitmapInfo.getThemedBitmap();
+            values.put(IconDB.COLUMN_MONO_ICON,
+                    themedBitmap != null ? themedBitmap.serialize() : null);
         } else {
             values.put(IconDB.COLUMN_ICON, (byte[]) null);
             values.put(IconDB.COLUMN_MONO_ICON, (byte[]) null);
         }
         values.put(IconDB.COLUMN_ICON_COLOR, bitmapInfo.color);
         values.put(IconDB.COLUMN_FLAGS, bitmapInfo.flags);
+        values.put(IconDB.COLUMN_LABEL, label.toString());
 
-        values.put(IconDB.COLUMN_LABEL, label);
-        values.put(IconDB.COLUMN_SYSTEM_STATE, getIconSystemState(packageName));
-        return values;
+        values.put(IconDB.COLUMN_COMPONENT, key.flattenToString());
+        values.put(IconDB.COLUMN_USER, userSerial);
+        values.put(IconDB.COLUMN_FRESHNESS_ID, freshnessId);
+        mIconDb.insertOrReplace(values);
     }
 
     private void assertWorkerThread() {
diff --git a/iconloaderlib/src/com/android/launcher3/icons/cache/CachedObject.java b/iconloaderlib/src/com/android/launcher3/icons/cache/CachedObject.java
index 7fc49bb..a4419a3 100644
--- a/iconloaderlib/src/com/android/launcher3/icons/cache/CachedObject.java
+++ b/iconloaderlib/src/com/android/launcher3/icons/cache/CachedObject.java
@@ -17,19 +17,19 @@
 package com.android.launcher3.icons.cache;
 
 import android.content.ComponentName;
-import android.content.pm.PackageManager;
+import android.content.pm.ApplicationInfo;
 import android.graphics.drawable.Drawable;
 import android.os.UserHandle;
 
 import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
 
+import com.android.launcher3.icons.IconProvider;
+
 /**
  * A simple interface to represent an object which can be added to icon cache
- *
- * @param <T> Any subclass of the icon cache with which this object is associated
  */
-public interface CachedObject<T extends BaseIconCache> {
+public interface CachedObject {
 
     /**
      * Returns the component name for the underlying object
@@ -44,13 +44,28 @@ public interface CachedObject<T extends BaseIconCache> {
     /**
      * Loads the user visible label for the provided object
      */
-    @Nullable CharSequence getLabel(PackageManager pm);
+    @Nullable CharSequence getLabel();
 
     /**
      * Loads the user visible icon for the provided object
      */
     @Nullable
-    default Drawable getFullResIcon(@NonNull T cache) {
+    default Drawable getFullResIcon(@NonNull BaseIconCache cache) {
         return null;
     }
+
+    /**
+     * @see CachingLogic#getApplicationInfo
+     */
+    @Nullable
+    ApplicationInfo getApplicationInfo();
+
+    /**
+     * Returns a persistable string that can be used to indicate indicate the correctness of the
+     * cache for the provided item
+     */
+    @Nullable
+    default String getFreshnessIdentifier(@NonNull IconProvider iconProvider) {
+        return iconProvider.getStateForApp(getApplicationInfo());
+    }
 }
diff --git a/iconloaderlib/src/com/android/launcher3/icons/cache/CachedObjectCachingLogic.kt b/iconloaderlib/src/com/android/launcher3/icons/cache/CachedObjectCachingLogic.kt
index ac284b1..0266939 100644
--- a/iconloaderlib/src/com/android/launcher3/icons/cache/CachedObjectCachingLogic.kt
+++ b/iconloaderlib/src/com/android/launcher3/icons/cache/CachedObjectCachingLogic.kt
@@ -21,35 +21,26 @@ import android.content.Context
 import android.os.UserHandle
 import com.android.launcher3.icons.BaseIconFactory.IconOptions
 import com.android.launcher3.icons.BitmapInfo
+import com.android.launcher3.icons.IconProvider
 
 /** Caching logic for ComponentWithLabelAndIcon */
-class CachedObjectCachingLogic<T : BaseIconCache>
-@JvmOverloads
-constructor(
-    context: Context,
-    private val loadIcons: Boolean = true,
-    private val addToMemCache: Boolean = true,
-) : CachingLogic<CachedObject<T>> {
+object CachedObjectCachingLogic : CachingLogic<CachedObject> {
 
-    private val pm = context.packageManager
+    override fun getComponent(info: CachedObject): ComponentName = info.component
 
-    override fun getComponent(info: CachedObject<T>): ComponentName = info.component
+    override fun getUser(info: CachedObject): UserHandle = info.user
 
-    override fun getUser(info: CachedObject<T>): UserHandle = info.user
+    override fun getLabel(info: CachedObject): CharSequence? = info.label
 
-    override fun getLabel(info: CachedObject<T>): CharSequence? = info.getLabel(pm)
-
-    override fun loadIcon(
-        context: Context,
-        cache: BaseIconCache,
-        info: CachedObject<T>,
-    ): BitmapInfo {
-        if (!loadIcons) return BitmapInfo.LOW_RES_INFO
-        val d = info.getFullResIcon(cache as T) ?: return BitmapInfo.LOW_RES_INFO
+    override fun loadIcon(context: Context, cache: BaseIconCache, info: CachedObject): BitmapInfo {
+        val d = info.getFullResIcon(cache) ?: return BitmapInfo.LOW_RES_INFO
         cache.iconFactory.use { li ->
             return li.createBadgedIconBitmap(d, IconOptions().setUser(info.user))
         }
     }
 
-    override fun addToMemCache() = addToMemCache
+    override fun getApplicationInfo(info: CachedObject) = info.applicationInfo
+
+    override fun getFreshnessIdentifier(item: CachedObject, provider: IconProvider): String? =
+        item.getFreshnessIdentifier(provider)
 }
diff --git a/iconloaderlib/src/com/android/launcher3/icons/cache/CachingLogic.java b/iconloaderlib/src/com/android/launcher3/icons/cache/CachingLogic.java
index ef5c7b2..6dce880 100644
--- a/iconloaderlib/src/com/android/launcher3/icons/cache/CachingLogic.java
+++ b/iconloaderlib/src/com/android/launcher3/icons/cache/CachingLogic.java
@@ -17,13 +17,14 @@ package com.android.launcher3.icons.cache;
 
 import android.content.ComponentName;
 import android.content.Context;
-import android.content.pm.PackageInfo;
+import android.content.pm.ApplicationInfo;
 import android.os.UserHandle;
 
 import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
 
 import com.android.launcher3.icons.BitmapInfo;
+import com.android.launcher3.icons.IconProvider;
 
 public interface CachingLogic<T> {
 
@@ -39,26 +40,21 @@ public interface CachingLogic<T> {
     @Nullable
     CharSequence getLabel(@NonNull final T object);
 
-    @NonNull
-    default CharSequence getDescription(@NonNull final T object,
-            @NonNull final CharSequence fallback) {
-        return fallback;
-    }
+    /**
+     * Returns the application info associated with the object. This is used to maintain the
+     * "freshness" of the disk cache. If null, the item will not be persisted to the disk
+     */
+    @Nullable
+    ApplicationInfo getApplicationInfo(@NonNull T object);
 
     @NonNull
     BitmapInfo loadIcon(@NonNull Context context, @NonNull BaseIconCache cache, @NonNull T object);
 
     /**
-     * Returns the timestamp the entry was last updated in cache.
+     * Returns a persistable string that can be used to indicate indicate the correctness of the
+     * cache for the provided item
      */
-    default long getLastUpdatedTime(@Nullable final T object, @NonNull final PackageInfo info) {
-        return info.lastUpdateTime;
-    }
+    @Nullable
+    String getFreshnessIdentifier(@NonNull T item, @NonNull IconProvider iconProvider);
 
-    /**
-     * Returns true the object should be added to mem cache; otherwise returns false.
-     */
-    default boolean addToMemCache() {
-        return true;
-    }
 }
diff --git a/iconloaderlib/src/com/android/launcher3/icons/cache/IconCacheUpdateHandler.java b/iconloaderlib/src/com/android/launcher3/icons/cache/IconCacheUpdateHandler.java
deleted file mode 100644
index 953551d..0000000
--- a/iconloaderlib/src/com/android/launcher3/icons/cache/IconCacheUpdateHandler.java
+++ /dev/null
@@ -1,354 +0,0 @@
-/*
- * Copyright (C) 2018 The Android Open Source Project
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
-package com.android.launcher3.icons.cache;
-
-import android.content.ComponentName;
-import android.content.pm.ApplicationInfo;
-import android.content.pm.PackageInfo;
-import android.content.pm.PackageManager;
-import android.database.Cursor;
-import android.database.sqlite.SQLiteException;
-import android.os.SystemClock;
-import android.os.UserHandle;
-import android.text.TextUtils;
-import android.util.ArrayMap;
-import android.util.Log;
-import android.util.SparseBooleanArray;
-
-import androidx.annotation.VisibleForTesting;
-
-import com.android.launcher3.icons.cache.BaseIconCache.IconDB;
-
-import java.util.ArrayDeque;
-import java.util.Collections;
-import java.util.HashMap;
-import java.util.HashSet;
-import java.util.List;
-import java.util.Map.Entry;
-import java.util.Set;
-
-/**
- * Utility class to handle updating the Icon cache
- */
-public class IconCacheUpdateHandler {
-
-    private static final String TAG = "IconCacheUpdateHandler";
-
-    /**
-     * In this mode, all invalid icons are marked as to-be-deleted in {@link #mItemsToDelete}.
-     * This mode is used for the first run.
-     */
-    private static final boolean MODE_SET_INVALID_ITEMS = true;
-
-    /**
-     * In this mode, any valid icon is removed from {@link #mItemsToDelete}. This is used for all
-     * subsequent runs, which essentially acts as set-union of all valid items.
-     */
-    private static final boolean MODE_CLEAR_VALID_ITEMS = false;
-
-    static final Object ICON_UPDATE_TOKEN = new Object();
-
-    private final HashMap<String, PackageInfo> mPkgInfoMap;
-    private final BaseIconCache mIconCache;
-
-    private final ArrayMap<UserHandle, Set<String>> mPackagesToIgnore = new ArrayMap<>();
-
-    private final SparseBooleanArray mItemsToDelete = new SparseBooleanArray();
-    private boolean mFilterMode = MODE_SET_INVALID_ITEMS;
-
-    /**
-     * Constructor for testing.
-     */
-    @VisibleForTesting
-    public IconCacheUpdateHandler(HashMap<String, PackageInfo> pkgInfoMap, BaseIconCache cache) {
-        mIconCache = cache;
-        mPkgInfoMap = pkgInfoMap;
-    }
-
-    IconCacheUpdateHandler(BaseIconCache cache) {
-        mIconCache = cache;
-
-        mPkgInfoMap = new HashMap<>();
-
-        // Remove all active icon update tasks.
-        mIconCache.mWorkerHandler.removeCallbacksAndMessages(ICON_UPDATE_TOKEN);
-
-        createPackageInfoMap();
-    }
-
-    /**
-     * Sets a package to ignore for processing
-     */
-    public void addPackagesToIgnore(UserHandle userHandle, String packageName) {
-        Set<String> packages = mPackagesToIgnore.get(userHandle);
-        if (packages == null) {
-            packages = new HashSet<>();
-            mPackagesToIgnore.put(userHandle, packages);
-        }
-        packages.add(packageName);
-    }
-
-    private void createPackageInfoMap() {
-        PackageManager pm = mIconCache.mPackageManager;
-        for (PackageInfo info :
-                pm.getInstalledPackages(PackageManager.MATCH_UNINSTALLED_PACKAGES)) {
-            mPkgInfoMap.put(info.packageName, info);
-        }
-    }
-
-    /**
-     * Updates the persistent DB, such that only entries corresponding to {@param apps} remain in
-     * the DB and are updated.
-     *
-     * @return The set of packages for which icons have updated.
-     */
-    public <T> void updateIcons(List<T> apps, CachingLogic<T> cachingLogic,
-            OnUpdateCallback onUpdateCallback) {
-        // Filter the list per user
-        HashMap<UserHandle, HashMap<ComponentName, T>> userComponentMap = new HashMap<>();
-        int count = apps.size();
-        for (int i = 0; i < count; i++) {
-            T app = apps.get(i);
-            UserHandle userHandle = cachingLogic.getUser(app);
-            HashMap<ComponentName, T> componentMap = userComponentMap.get(userHandle);
-            if (componentMap == null) {
-                componentMap = new HashMap<>();
-                userComponentMap.put(userHandle, componentMap);
-            }
-            componentMap.put(cachingLogic.getComponent(app), app);
-        }
-
-        for (Entry<UserHandle, HashMap<ComponentName, T>> entry : userComponentMap.entrySet()) {
-            updateIconsPerUser(entry.getKey(), entry.getValue(), cachingLogic, onUpdateCallback);
-        }
-
-        // From now on, clear every valid item from the global valid map.
-        mFilterMode = MODE_CLEAR_VALID_ITEMS;
-    }
-
-    /**
-     * Updates the persistent DB, such that only entries corresponding to {@param apps} remain in
-     * the DB and are updated.
-     *
-     * @return The set of packages for which icons have updated.
-     */
-    @SuppressWarnings("unchecked")
-    private <T> void updateIconsPerUser(UserHandle user, HashMap<ComponentName, T> componentMap,
-            CachingLogic<T> cachingLogic, OnUpdateCallback onUpdateCallback) {
-        Set<String> ignorePackages = mPackagesToIgnore.get(user);
-        if (ignorePackages == null) {
-            ignorePackages = Collections.emptySet();
-        }
-        long userSerial = mIconCache.getSerialNumberForUser(user);
-
-        ArrayDeque<T> appsToUpdate = new ArrayDeque<>();
-
-        try (Cursor c = mIconCache.mIconDb.query(
-                new String[]{IconDB.COLUMN_ROWID, IconDB.COLUMN_COMPONENT,
-                        IconDB.COLUMN_LAST_UPDATED, IconDB.COLUMN_VERSION,
-                        IconDB.COLUMN_SYSTEM_STATE},
-                IconDB.COLUMN_USER + " = ? ",
-                new String[]{Long.toString(userSerial)})) {
-
-            while (c.moveToNext()) {
-                var app = updateOrDeleteIcon(c, componentMap, ignorePackages, user, cachingLogic);
-                if (app != null) {
-                    appsToUpdate.add(app);
-                }
-            }
-        } catch (SQLiteException e) {
-            Log.d(TAG, "Error reading icon cache", e);
-            // Continue updating whatever we have read so far
-        }
-
-        // Insert remaining apps.
-        if (!componentMap.isEmpty() || !appsToUpdate.isEmpty()) {
-            ArrayDeque<T> appsToAdd = new ArrayDeque<>();
-            appsToAdd.addAll(componentMap.values());
-            mIconCache.setIconUpdateInProgress(true);
-            new SerializedIconUpdateTask(userSerial, user, appsToAdd, appsToUpdate, cachingLogic,
-                    onUpdateCallback).scheduleNext();
-        }
-    }
-
-    /**
-     * This method retrieves the component and either adds it to the list of apps to update or
-     * adds it to a list of apps to delete from cache later. Returns the individual app if it
-     * should be updated, or null if nothing should be updated.
-     */
-    @VisibleForTesting
-    public <T> T updateOrDeleteIcon(Cursor c, HashMap<ComponentName, T> componentMap,
-            Set<String> ignorePackages, UserHandle user, CachingLogic<T> cachingLogic) {
-
-        final int indexComponent = c.getColumnIndex(IconDB.COLUMN_COMPONENT);
-        final int indexLastUpdate = c.getColumnIndex(IconDB.COLUMN_LAST_UPDATED);
-        final int indexVersion = c.getColumnIndex(IconDB.COLUMN_VERSION);
-        final int rowIndex = c.getColumnIndex(IconDB.COLUMN_ROWID);
-        final int systemStateIndex = c.getColumnIndex(IconDB.COLUMN_SYSTEM_STATE);
-
-        int rowId = c.getInt(rowIndex);
-        String cn = c.getString(indexComponent);
-        ComponentName component = ComponentName.unflattenFromString(cn);
-        if (component == null) {
-            // b/357725795
-            Log.e(TAG, "Invalid component name while updating icon cache: " + cn);
-            mItemsToDelete.put(rowId, true);
-            return null;
-        }
-
-        PackageInfo info = mPkgInfoMap.get(component.getPackageName());
-
-        if (info == null) {
-            if (!ignorePackages.contains(component.getPackageName())) {
-
-                if (mFilterMode == MODE_SET_INVALID_ITEMS) {
-                    mIconCache.remove(component, user);
-                    mItemsToDelete.put(rowId, true);
-                }
-            }
-            return null;
-        }
-        if ((info.applicationInfo.flags & ApplicationInfo.FLAG_IS_DATA_ONLY) != 0) {
-            // Application is not present
-            return null;
-        }
-
-        long updateTime = c.getLong(indexLastUpdate);
-        int version = c.getInt(indexVersion);
-        T app = componentMap.remove(component);
-        if (version == info.versionCode
-                && updateTime == cachingLogic.getLastUpdatedTime(app, info)
-                && TextUtils.equals(c.getString(systemStateIndex),
-                mIconCache.getIconSystemState(info.packageName))) {
-
-            if (mFilterMode == MODE_CLEAR_VALID_ITEMS) {
-                mItemsToDelete.put(rowId, false);
-            }
-            return null;
-        }
-
-        if (app == null) {
-            if (mFilterMode == MODE_SET_INVALID_ITEMS) {
-                mIconCache.remove(component, user);
-                mItemsToDelete.put(rowId, true);
-            }
-        }
-        return app;
-    }
-
-    /**
-     * Commits all updates as part of the update handler to disk. Not more calls should be made
-     * to this class after this.
-     */
-    public void finish() {
-        // Commit all deletes
-        int deleteCount = 0;
-        StringBuilder queryBuilder = new StringBuilder()
-                .append(IconDB.COLUMN_ROWID)
-                .append(" IN (");
-
-        int count = mItemsToDelete.size();
-        for (int i = 0; i < count; i++) {
-            if (mItemsToDelete.valueAt(i)) {
-                if (deleteCount > 0) {
-                    queryBuilder.append(", ");
-                }
-                queryBuilder.append(mItemsToDelete.keyAt(i));
-                deleteCount++;
-            }
-        }
-        queryBuilder.append(')');
-
-        if (deleteCount > 0) {
-            mIconCache.mIconDb.delete(queryBuilder.toString(), null);
-        }
-    }
-
-    /**
-     * A runnable that updates invalid icons and adds missing icons in the DB for the provided
-     * LauncherActivityInfo list. Items are updated/added one at a time, so that the
-     * worker thread doesn't get blocked.
-     */
-    private class SerializedIconUpdateTask<T> implements Runnable {
-        private final long mUserSerial;
-        private final UserHandle mUserHandle;
-        private final ArrayDeque<T> mAppsToAdd;
-        private final ArrayDeque<T> mAppsToUpdate;
-        private final CachingLogic<T> mCachingLogic;
-        private final HashSet<String> mUpdatedPackages = new HashSet<>();
-        private final OnUpdateCallback mOnUpdateCallback;
-
-        SerializedIconUpdateTask(long userSerial, UserHandle userHandle,
-                ArrayDeque<T> appsToAdd, ArrayDeque<T> appsToUpdate, CachingLogic<T> cachingLogic,
-                OnUpdateCallback onUpdateCallback) {
-            mUserHandle = userHandle;
-            mUserSerial = userSerial;
-            mAppsToAdd = appsToAdd;
-            mAppsToUpdate = appsToUpdate;
-            mCachingLogic = cachingLogic;
-            mOnUpdateCallback = onUpdateCallback;
-        }
-
-        @Override
-        public void run() {
-            if (!mAppsToUpdate.isEmpty()) {
-                T app = mAppsToUpdate.removeLast();
-                String pkg = mCachingLogic.getComponent(app).getPackageName();
-                PackageInfo info = mPkgInfoMap.get(pkg);
-
-                mIconCache.addIconToDBAndMemCache(
-                        app, mCachingLogic, info, mUserSerial, true /*replace existing*/);
-                mUpdatedPackages.add(pkg);
-
-                if (mAppsToUpdate.isEmpty() && !mUpdatedPackages.isEmpty()) {
-                    // No more app to update. Notify callback.
-                    mOnUpdateCallback.onPackageIconsUpdated(mUpdatedPackages, mUserHandle);
-                }
-
-                // Let it run one more time.
-                scheduleNext();
-            } else if (!mAppsToAdd.isEmpty()) {
-                T app = mAppsToAdd.removeLast();
-                PackageInfo info = mPkgInfoMap.get(
-                        mCachingLogic.getComponent(app).getPackageName());
-                // We do not check the mPkgInfoMap when generating the mAppsToAdd. Although every
-                // app should have package info, this is not guaranteed by the api
-                if (info != null) {
-                    mIconCache.addIconToDBAndMemCache(app, mCachingLogic, info,
-                            mUserSerial, false /*replace existing*/);
-                }
-
-                if (!mAppsToAdd.isEmpty()) {
-                    scheduleNext();
-                } else if (!mIconCache.mWorkerHandler.hasMessages(0, ICON_UPDATE_TOKEN)) {
-                    // This checks if there is a second icon update process happening
-                    // before notifying BaseIconCache that the updates are over
-                    mIconCache.setIconUpdateInProgress(false);
-                }
-            }
-        }
-
-        public void scheduleNext() {
-            mIconCache.mWorkerHandler.postAtTime(this, ICON_UPDATE_TOKEN,
-                    SystemClock.uptimeMillis() + 1);
-        }
-    }
-
-    public interface OnUpdateCallback {
-
-        void onPackageIconsUpdated(HashSet<String> updatedPackages, UserHandle user);
-    }
-}
diff --git a/iconloaderlib/src/com/android/launcher3/icons/cache/IconCacheUpdateHandler.kt b/iconloaderlib/src/com/android/launcher3/icons/cache/IconCacheUpdateHandler.kt
new file mode 100644
index 0000000..9db9a09
--- /dev/null
+++ b/iconloaderlib/src/com/android/launcher3/icons/cache/IconCacheUpdateHandler.kt
@@ -0,0 +1,301 @@
+/*
+ * Copyright (C) 2018 The Android Open Source Project
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
+package com.android.launcher3.icons.cache
+
+import android.content.ComponentName
+import android.content.pm.ApplicationInfo
+import android.database.sqlite.SQLiteException
+import android.os.Handler
+import android.os.SystemClock
+import android.os.UserHandle
+import android.util.ArrayMap
+import android.util.Log
+import com.android.launcher3.icons.cache.BaseIconCache.IconDB
+import com.android.launcher3.util.ComponentKey
+import com.android.launcher3.util.SQLiteCacheHelper
+import java.util.ArrayDeque
+
+/** Utility class to handle updating the Icon cache */
+class IconCacheUpdateHandler(
+    private val iconCache: BaseIconCache,
+    private val cacheDb: SQLiteCacheHelper,
+    private val workerHandler: Handler,
+) {
+
+    private val packagesToIgnore = ArrayMap<UserHandle, MutableSet<String>>()
+    // Map of packageKey to ApplicationInfo, dynamically created based on all incoming data
+    private val packageAppInfoMap = HashMap<ComponentKey, ApplicationInfo?>()
+
+    private val itemsToDelete = HashSet<UpdateRow>()
+
+    // During the first pass, we load all the items from DB and add all invalid items to
+    // mItemsToDelete. In follow up passes, we  go through the items in mItemsToDelete, and if the
+    // item is valid, removes it from the list, or leave it there.
+    private var firstPass = true
+
+    /** Sets a package to ignore for processing */
+    fun addPackagesToIgnore(userHandle: UserHandle, packageName: String) {
+        packagesToIgnore.getOrPut(userHandle) { HashSet() }.add(packageName)
+    }
+
+    /**
+     * Updates the persistent DB, such that only entries corresponding to {@param apps} remain in
+     * the DB and are updated.
+     *
+     * @return The set of packages for which icons have updated.
+     */
+    fun <T : Any> updateIcons(
+        apps: List<T>,
+        cachingLogic: CachingLogic<T>,
+        onUpdateCallback: OnUpdateCallback,
+    ) {
+        // Filter the list per user
+        val userComponentMap = HashMap<UserHandle, HashMap<ComponentName, T>>()
+        for (app in apps) {
+            val userHandle = cachingLogic.getUser(app)
+            val cn = cachingLogic.getComponent(app)
+            userComponentMap.getOrPut(userHandle) { HashMap() }[cn] = app
+
+            // Populate application info map
+            val packageKey = BaseIconCache.getPackageKey(cn.packageName, userHandle)
+            packageAppInfoMap.getOrPut(packageKey) { cachingLogic.getApplicationInfo(app) }
+        }
+
+        if (firstPass) {
+            userComponentMap.forEach { (user, componentMap) ->
+                updateIconsPerUserForFirstPass(user, componentMap, cachingLogic, onUpdateCallback)
+            }
+        } else {
+            userComponentMap.forEach { (user, componentMap) ->
+                updateIconsPerUserForSecondPass(user, componentMap, cachingLogic, onUpdateCallback)
+            }
+        }
+
+        // From now on, clear every valid item from the global valid map.
+        firstPass = false
+    }
+
+    /**
+     * During the first pass, all the items from the cache are verified one-by-one and any entry
+     * with no corresponding entry in {@code componentMap} is added to {@code itemsToDelete}
+     *
+     * Also starts a SerializedIconUpdateTask for all updated entries
+     */
+    private fun <T : Any> updateIconsPerUserForFirstPass(
+        user: UserHandle,
+        componentMap: MutableMap<ComponentName, T>,
+        cachingLogic: CachingLogic<T>,
+        onUpdateCallback: OnUpdateCallback,
+    ) {
+        val appsToUpdate = ArrayDeque<T>()
+
+        val userSerial = iconCache.getSerialNumberForUser(user)
+        try {
+            cacheDb
+                .query(
+                    arrayOf(
+                        IconDB.COLUMN_ROWID,
+                        IconDB.COLUMN_COMPONENT,
+                        IconDB.COLUMN_FRESHNESS_ID,
+                    ),
+                    "${IconDB.COLUMN_USER} = ? ",
+                    arrayOf(userSerial.toString()),
+                )
+                .use { c ->
+                    var ignorePackages = packagesToIgnore[user] ?: emptySet()
+
+                    val indexComponent = c.getColumnIndex(IconDB.COLUMN_COMPONENT)
+                    val indexFreshnessId = c.getColumnIndex(IconDB.COLUMN_FRESHNESS_ID)
+                    val rowIndex = c.getColumnIndex(IconDB.COLUMN_ROWID)
+
+                    while (c.moveToNext()) {
+                        val rowId = c.getInt(rowIndex)
+                        val cn = c.getString(indexComponent)
+                        val freshnessId = c.getString(indexFreshnessId) ?: ""
+
+                        val component = ComponentName.unflattenFromString(cn)
+                        if (component == null) {
+                            // b/357725795
+                            Log.e(TAG, "Invalid component name while updating icon cache: $cn")
+                            itemsToDelete.add(
+                                UpdateRow(rowId, ComponentName("", ""), user, freshnessId)
+                            )
+                            continue
+                        }
+
+                        val app = componentMap.remove(component)
+                        if (app == null) {
+                            if (!ignorePackages.contains(component.packageName)) {
+                                iconCache.remove(component, user)
+                                itemsToDelete.add(UpdateRow(rowId, component, user, freshnessId))
+                            }
+                            continue
+                        }
+
+                        if (
+                            freshnessId ==
+                                cachingLogic.getFreshnessIdentifier(app, iconCache.iconProvider)
+                        ) {
+                            // Item is up-to-date
+                            continue
+                        }
+                        appsToUpdate.add(app)
+                    }
+                }
+        } catch (e: SQLiteException) {
+            Log.d(TAG, "Error reading icon cache", e)
+            // Continue updating whatever we have read so far
+        }
+
+        // Insert remaining apps.
+        if (componentMap.isNotEmpty() || appsToUpdate.isNotEmpty()) {
+            val appsToAdd = ArrayDeque(componentMap.values)
+            SerializedIconUpdateTask(
+                    userSerial,
+                    user,
+                    appsToAdd,
+                    appsToUpdate,
+                    cachingLogic,
+                    onUpdateCallback,
+                )
+                .scheduleNext()
+        }
+    }
+
+    /**
+     * During the second pass, we go through the items in {@code itemsToDelete}, and remove any item
+     * with corresponding entry in {@code componentMap}.
+     */
+    private fun <T : Any> updateIconsPerUserForSecondPass(
+        user: UserHandle,
+        componentMap: MutableMap<ComponentName, T>,
+        cachingLogic: CachingLogic<T>,
+        onUpdateCallback: OnUpdateCallback,
+    ) {
+        val userSerial = iconCache.getSerialNumberForUser(user)
+        val appsToUpdate = ArrayDeque<T>()
+
+        val itr = itemsToDelete.iterator()
+        while (itr.hasNext()) {
+            val row = itr.next()
+            if (user != row.user) continue
+            val app = componentMap.remove(row.componentName) ?: continue
+
+            itr.remove()
+            if (
+                row.freshnessId != cachingLogic.getFreshnessIdentifier(app, iconCache.iconProvider)
+            ) {
+                appsToUpdate.add(app)
+            }
+        }
+
+        // Insert remaining apps.
+        if (componentMap.isNotEmpty() || appsToUpdate.isNotEmpty()) {
+            val appsToAdd = ArrayDeque<T>()
+            appsToAdd.addAll(componentMap.values)
+            SerializedIconUpdateTask(
+                    userSerial,
+                    user,
+                    appsToAdd,
+                    appsToUpdate,
+                    cachingLogic,
+                    onUpdateCallback,
+                )
+                .scheduleNext()
+        }
+    }
+
+    /**
+     * Commits all updates as part of the update handler to disk. Not more calls should be made to
+     * this class after this.
+     */
+    fun finish() {
+        // Ignore any application info entries which are already correct
+        itemsToDelete.removeIf { row ->
+            val info = packageAppInfoMap[ComponentKey(row.componentName, row.user)]
+            info != null && row.freshnessId == iconCache.iconProvider.getStateForApp(info)
+        }
+
+        // Commit all deletes
+        if (itemsToDelete.isNotEmpty()) {
+            val r = itemsToDelete.joinToString { it.rowId.toString() }
+            cacheDb.delete("${IconDB.COLUMN_ROWID} IN ($r)", null)
+            Log.d(TAG, "Deleting obsolete entries, count=" + itemsToDelete.size)
+        }
+    }
+
+    data class UpdateRow(
+        val rowId: Int,
+        val componentName: ComponentName,
+        val user: UserHandle,
+        val freshnessId: String,
+    )
+
+    /**
+     * A runnable that updates invalid icons and adds missing icons in the DB for the provided
+     * LauncherActivityInfo list. Items are updated/added one at a time, so that the worker thread
+     * doesn't get blocked.
+     */
+    private inner class SerializedIconUpdateTask<T : Any>(
+        private val userSerial: Long,
+        private val userHandle: UserHandle,
+        private val appsToAdd: ArrayDeque<T>,
+        private val appsToUpdate: ArrayDeque<T>,
+        private val cachingLogic: CachingLogic<T>,
+        private val onUpdateCallback: OnUpdateCallback,
+    ) : Runnable {
+        private val updatedPackages = HashSet<String>()
+
+        override fun run() {
+            if (appsToUpdate.isNotEmpty()) {
+                val app = appsToUpdate.removeLast()
+                val pkg = cachingLogic.getComponent(app).packageName
+
+                iconCache.addIconToDBAndMemCache(app, cachingLogic, userSerial)
+                updatedPackages.add(pkg)
+
+                if (appsToUpdate.isEmpty() && updatedPackages.isNotEmpty()) {
+                    // No more app to update. Notify callback.
+                    onUpdateCallback.onPackageIconsUpdated(updatedPackages, userHandle)
+                }
+
+                // Let it run one more time.
+                scheduleNext()
+            } else if (appsToAdd.isNotEmpty()) {
+                iconCache.addIconToDBAndMemCache(appsToAdd.removeLast(), cachingLogic, userSerial)
+
+                // Let it run one more time.
+                scheduleNext()
+            }
+        }
+
+        fun scheduleNext() {
+            workerHandler.postAtTime(
+                this,
+                iconCache.iconUpdateToken,
+                SystemClock.uptimeMillis() + 1,
+            )
+        }
+    }
+
+    fun interface OnUpdateCallback {
+        fun onPackageIconsUpdated(updatedPackages: HashSet<String>, user: UserHandle)
+    }
+
+    companion object {
+        private const val TAG = "IconCacheUpdateHandler"
+    }
+}
diff --git a/iconloaderlib/src/com/android/launcher3/icons/cache/LauncherActivityCachingLogic.kt b/iconloaderlib/src/com/android/launcher3/icons/cache/LauncherActivityCachingLogic.kt
index 99af08b..85902d2 100644
--- a/iconloaderlib/src/com/android/launcher3/icons/cache/LauncherActivityCachingLogic.kt
+++ b/iconloaderlib/src/com/android/launcher3/icons/cache/LauncherActivityCachingLogic.kt
@@ -25,6 +25,7 @@ import android.util.Log
 import com.android.launcher3.Flags.useNewIconForArchivedApps
 import com.android.launcher3.icons.BaseIconFactory.IconOptions
 import com.android.launcher3.icons.BitmapInfo
+import com.android.launcher3.icons.IconProvider
 
 object LauncherActivityCachingLogic : CachingLogic<LauncherActivityInfo> {
     const val TAG = "LauncherActivityCachingLogic"
@@ -35,7 +36,7 @@ object LauncherActivityCachingLogic : CachingLogic<LauncherActivityInfo> {
 
     override fun getLabel(info: LauncherActivityInfo): CharSequence? = info.label
 
-    override fun getDescription(info: LauncherActivityInfo, fallback: CharSequence) = fallback
+    override fun getApplicationInfo(info: LauncherActivityInfo) = info.applicationInfo
 
     override fun loadIcon(
         context: Context,
@@ -47,11 +48,8 @@ object LauncherActivityCachingLogic : CachingLogic<LauncherActivityInfo> {
             iconOptions.setIsArchived(
                 useNewIconForArchivedApps() && VERSION.SDK_INT >= 35 && info.activityInfo.isArchived
             )
-            val iconDrawable = cache.iconProvider.getIcon(info, li.fullResIconDpi)
-            if (
-                VERSION.SDK_INT >= 30 &&
-                    context.packageManager.isDefaultApplicationIcon(iconDrawable)
-            ) {
+            val iconDrawable = cache.iconProvider.getIcon(info.activityInfo, li.fullResIconDpi)
+            if (context.packageManager.isDefaultApplicationIcon(iconDrawable)) {
                 Log.w(
                     TAG,
                     "loadIcon: Default app icon returned from PackageManager." +
@@ -64,4 +62,9 @@ object LauncherActivityCachingLogic : CachingLogic<LauncherActivityInfo> {
             return li.createBadgedIconBitmap(iconDrawable, iconOptions)
         }
     }
+
+    override fun getFreshnessIdentifier(
+        item: LauncherActivityInfo,
+        provider: IconProvider,
+    ): String? = provider.getStateForApp(getApplicationInfo(item))
 }
diff --git a/iconloaderlib/src/com/android/launcher3/icons/mono/MonoIconThemeController.kt b/iconloaderlib/src/com/android/launcher3/icons/mono/MonoIconThemeController.kt
new file mode 100644
index 0000000..cdaf05f
--- /dev/null
+++ b/iconloaderlib/src/com/android/launcher3/icons/mono/MonoIconThemeController.kt
@@ -0,0 +1,145 @@
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
+package com.android.launcher3.icons.mono
+
+import android.annotation.TargetApi
+import android.content.Context
+import android.graphics.Bitmap
+import android.graphics.Bitmap.Config.ALPHA_8
+import android.graphics.Bitmap.Config.HARDWARE
+import android.graphics.BlendMode.SRC_IN
+import android.graphics.BlendModeColorFilter
+import android.graphics.Canvas
+import android.graphics.Color
+import android.graphics.drawable.AdaptiveIconDrawable
+import android.graphics.drawable.BitmapDrawable
+import android.graphics.drawable.ColorDrawable
+import android.graphics.drawable.Drawable
+import android.graphics.drawable.InsetDrawable
+import android.os.Build
+import com.android.launcher3.Flags
+import com.android.launcher3.icons.BaseIconFactory
+import com.android.launcher3.icons.BitmapInfo
+import com.android.launcher3.icons.IconThemeController
+import com.android.launcher3.icons.MonochromeIconFactory
+import com.android.launcher3.icons.ThemedBitmap
+import com.android.launcher3.icons.mono.ThemedIconDrawable.Companion.getColors
+import java.nio.ByteBuffer
+
+@TargetApi(Build.VERSION_CODES.TIRAMISU)
+class MonoIconThemeController : IconThemeController {
+
+    override fun createThemedBitmap(
+        icon: AdaptiveIconDrawable,
+        info: BitmapInfo,
+        factory: BaseIconFactory,
+    ): ThemedBitmap? {
+        val mono = getMonochromeDrawable(icon, info)
+        if (mono != null) {
+            val scale =
+                factory.normalizer.getScale(
+                    AdaptiveIconDrawable(ColorDrawable(Color.BLACK), null),
+                    null,
+                    null,
+                    null,
+                )
+            return MonoThemedBitmap(
+                factory.createIconBitmap(mono, scale, BaseIconFactory.MODE_ALPHA),
+                factory.whiteShadowLayer,
+            )
+        }
+        return null
+    }
+
+    /**
+     * Returns a monochromatic version of the given drawable or null, if it is not supported
+     *
+     * @param base the original icon
+     */
+    private fun getMonochromeDrawable(base: AdaptiveIconDrawable, info: BitmapInfo): Drawable? {
+        val mono = base.monochrome
+        if (mono != null) {
+            return ClippedMonoDrawable(mono)
+        }
+        if (Flags.forceMonochromeAppIcons()) {
+            return MonochromeIconFactory(info.icon.width).wrap(base)
+        }
+        return null
+    }
+
+    override fun decode(
+        data: ByteArray,
+        info: BitmapInfo,
+        factory: BaseIconFactory,
+    ): ThemedBitmap? {
+        val icon = info.icon
+        if (data.size != icon.height * icon.width) return null
+
+        var monoBitmap = Bitmap.createBitmap(icon.width, icon.height, ALPHA_8)
+        monoBitmap.copyPixelsFromBuffer(ByteBuffer.wrap(data))
+
+        val hwMonoBitmap = monoBitmap.copy(HARDWARE, false /*isMutable*/)
+        if (hwMonoBitmap != null) {
+            monoBitmap.recycle()
+            monoBitmap = hwMonoBitmap
+        }
+        return MonoThemedBitmap(monoBitmap, factory.whiteShadowLayer)
+    }
+
+    override fun createThemedAdaptiveIcon(
+        context: Context,
+        originalIcon: AdaptiveIconDrawable,
+        info: BitmapInfo?,
+    ): AdaptiveIconDrawable? {
+        val colors = getColors(context)
+        originalIcon.mutate()
+        var monoDrawable = originalIcon.monochrome?.apply { setTint(colors[1]) }
+
+        if (monoDrawable == null) {
+            info?.themedBitmap?.let { themedBitmap ->
+                if (themedBitmap is MonoThemedBitmap) {
+                    // Inject a previously generated monochrome icon
+                    // Use BitmapDrawable instead of FastBitmapDrawable so that the colorState is
+                    // preserved in constantState
+                    // Inset the drawable according to the AdaptiveIconDrawable layers
+                    monoDrawable =
+                        InsetDrawable(
+                            BitmapDrawable(themedBitmap.mono).apply {
+                                colorFilter = BlendModeColorFilter(colors[1], SRC_IN)
+                            },
+                            AdaptiveIconDrawable.getExtraInsetFraction() / 2,
+                        )
+                }
+            }
+        }
+
+        return monoDrawable?.let { AdaptiveIconDrawable(ColorDrawable(colors[0]), it) }
+    }
+
+    class ClippedMonoDrawable(base: Drawable?) :
+        InsetDrawable(base, -AdaptiveIconDrawable.getExtraInsetFraction()) {
+        private val mCrop = AdaptiveIconDrawable(ColorDrawable(Color.BLACK), null)
+
+        override fun draw(canvas: Canvas) {
+            mCrop.bounds = bounds
+            val saveCount = canvas.save()
+            canvas.clipPath(mCrop.iconMask)
+            super.draw(canvas)
+            canvas.restoreToCount(saveCount)
+        }
+    }
+}
diff --git a/iconloaderlib/src/com/android/launcher3/icons/mono/MonoThemedBitmap.kt b/iconloaderlib/src/com/android/launcher3/icons/mono/MonoThemedBitmap.kt
new file mode 100644
index 0000000..dc6030e
--- /dev/null
+++ b/iconloaderlib/src/com/android/launcher3/icons/mono/MonoThemedBitmap.kt
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
+package com.android.launcher3.icons.mono
+
+import android.content.Context
+import android.graphics.Bitmap
+import com.android.launcher3.icons.BitmapInfo
+import com.android.launcher3.icons.FastBitmapDrawable
+import com.android.launcher3.icons.ThemedBitmap
+import com.android.launcher3.icons.mono.ThemedIconDrawable.ThemedConstantState
+import java.nio.ByteBuffer
+
+class MonoThemedBitmap(val mono: Bitmap, private val whiteShadowLayer: Bitmap) : ThemedBitmap {
+
+    override fun newDrawable(info: BitmapInfo, context: Context): FastBitmapDrawable {
+        val colors = ThemedIconDrawable.getColors(context)
+        return ThemedConstantState(info, mono, whiteShadowLayer, colors[0], colors[1]).newDrawable()
+    }
+
+    override fun serialize() =
+        ByteArray(mono.width * mono.height).apply { mono.copyPixelsToBuffer(ByteBuffer.wrap(this)) }
+}
diff --git a/iconloaderlib/src/com/android/launcher3/icons/mono/ThemedIconDrawable.kt b/iconloaderlib/src/com/android/launcher3/icons/mono/ThemedIconDrawable.kt
new file mode 100644
index 0000000..59fb245
--- /dev/null
+++ b/iconloaderlib/src/com/android/launcher3/icons/mono/ThemedIconDrawable.kt
@@ -0,0 +1,99 @@
+/*
+ * Copyright (C) 2021 The Android Open Source Project
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
+package com.android.launcher3.icons.mono
+
+import android.content.Context
+import android.graphics.Bitmap
+import android.graphics.BlendMode.SRC_IN
+import android.graphics.BlendModeColorFilter
+import android.graphics.Canvas
+import android.graphics.Paint
+import android.graphics.Rect
+import com.android.launcher3.icons.BitmapInfo
+import com.android.launcher3.icons.FastBitmapDrawable
+import com.android.launcher3.icons.R
+
+/** Class to handle monochrome themed app icons */
+class ThemedIconDrawable(constantState: ThemedConstantState) :
+    FastBitmapDrawable(constantState.getBitmap(), constantState.colorFg) {
+    val bitmapInfo = constantState.bitmapInfo
+    private val colorFg = constantState.colorFg
+    private val colorBg = constantState.colorBg
+
+    // The foreground/monochrome icon for the app
+    private val monoIcon = constantState.mono
+    private val monoFilter = BlendModeColorFilter(colorFg, SRC_IN)
+    private val monoPaint =
+        Paint(Paint.ANTI_ALIAS_FLAG or Paint.FILTER_BITMAP_FLAG).apply { colorFilter = monoFilter }
+
+    private val bgBitmap = constantState.whiteShadowLayer
+    private val bgFilter = BlendModeColorFilter(colorBg, SRC_IN)
+    private val mBgPaint =
+        Paint(Paint.ANTI_ALIAS_FLAG or Paint.FILTER_BITMAP_FLAG).apply { colorFilter = bgFilter }
+
+    override fun drawInternal(canvas: Canvas, bounds: Rect) {
+        canvas.drawBitmap(bgBitmap, null, bounds, mBgPaint)
+        canvas.drawBitmap(monoIcon, null, bounds, monoPaint)
+    }
+
+    override fun updateFilter() {
+        super.updateFilter()
+        val alpha = if (mIsDisabled) (mDisabledAlpha * FULLY_OPAQUE).toInt() else FULLY_OPAQUE
+        mBgPaint.alpha = alpha
+        mBgPaint.setColorFilter(
+            if (mIsDisabled) BlendModeColorFilter(getDisabledColor(colorBg), SRC_IN) else bgFilter
+        )
+
+        monoPaint.alpha = alpha
+        monoPaint.setColorFilter(
+            if (mIsDisabled) BlendModeColorFilter(getDisabledColor(colorFg), SRC_IN) else monoFilter
+        )
+    }
+
+    override fun isThemed() = true
+
+    override fun newConstantState() =
+        ThemedConstantState(bitmapInfo, monoIcon, bgBitmap, colorBg, colorFg)
+
+    override fun getIconColor() = colorFg
+
+    class ThemedConstantState(
+        val bitmapInfo: BitmapInfo,
+        val mono: Bitmap,
+        val whiteShadowLayer: Bitmap,
+        val colorBg: Int,
+        val colorFg: Int,
+    ) : FastBitmapConstantState(bitmapInfo.icon, bitmapInfo.color) {
+
+        public override fun createDrawable() = ThemedIconDrawable(this)
+
+        fun getBitmap(): Bitmap = mBitmap
+    }
+
+    companion object {
+        const val TAG: String = "ThemedIconDrawable"
+
+        /** Get an int array representing background and foreground colors for themed icons */
+        @JvmStatic
+        fun getColors(context: Context): IntArray {
+            val res = context.resources
+            return intArrayOf(
+                res.getColor(R.color.themed_icon_background_color),
+                res.getColor(R.color.themed_icon_color),
+            )
+        }
+    }
+}
diff --git a/mechanics/Android.bp b/mechanics/Android.bp
new file mode 100644
index 0000000..ae00b5f
--- /dev/null
+++ b/mechanics/Android.bp
@@ -0,0 +1,40 @@
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
+filegroup {
+    name: "mechanics-srcs",
+    srcs: [
+        "src/**/*.kt",
+    ],
+}
+
+android_library {
+    name: "mechanics",
+    manifest: "AndroidManifest.xml",
+    sdk_version: "system_current",
+    min_sdk_version: "current",
+    static_libs: [
+        "androidx.compose.runtime_runtime",
+        "androidx.compose.ui_ui-util",
+    ],
+    srcs: [
+        ":mechanics-srcs",
+    ],
+    kotlincflags: ["-Xjvm-default=all"],
+}
diff --git a/mechanics/AndroidManifest.xml b/mechanics/AndroidManifest.xml
new file mode 100644
index 0000000..29874f3
--- /dev/null
+++ b/mechanics/AndroidManifest.xml
@@ -0,0 +1,19 @@
+<?xml version="1.0" encoding="utf-8"?><!--
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
+    package="com.android.mechanics">
+</manifest>
diff --git a/mechanics/TEST_MAPPING b/mechanics/TEST_MAPPING
new file mode 100644
index 0000000..4e50571
--- /dev/null
+++ b/mechanics/TEST_MAPPING
@@ -0,0 +1,15 @@
+{
+  "presubmit": [
+    {
+      "name": "mechanics_tests",
+      "options": [
+        {
+          "exclude-annotation": "org.junit.Ignore"
+        },
+        {
+          "exclude-annotation": "androidx.test.filters.FlakyTest"
+        }
+      ]
+    }
+  ]
+}
diff --git a/mechanics/src/com/android/mechanics/GestureContext.kt b/mechanics/src/com/android/mechanics/GestureContext.kt
new file mode 100644
index 0000000..00665f8
--- /dev/null
+++ b/mechanics/src/com/android/mechanics/GestureContext.kt
@@ -0,0 +1,171 @@
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
+package com.android.mechanics
+
+import androidx.compose.runtime.Stable
+import androidx.compose.runtime.getValue
+import androidx.compose.runtime.mutableFloatStateOf
+import androidx.compose.runtime.mutableStateOf
+import androidx.compose.runtime.setValue
+import com.android.mechanics.spec.InputDirection
+import kotlin.math.max
+import kotlin.math.min
+
+/**
+ * Gesture-specific context to augment [MotionValue.currentInput].
+ *
+ * This context helps to capture the user's intent, and should be provided to [MotionValue]s that
+ * respond to a user gesture.
+ */
+@Stable
+interface GestureContext {
+
+    /**
+     * The intrinsic direction of the [MotionValue.currentInput].
+     *
+     * This property determines which of the [DirectionalMotionSpec] from the [MotionSpec] is used,
+     * and also prevents flip-flopping of the output value on tiny input-changes around a
+     * breakpoint.
+     *
+     * If the [MotionValue.currentInput] is driven - directly or indirectly - by a user gesture,
+     * this property should only change direction after the gesture travelled a significant distance
+     * in the opposite direction.
+     *
+     * @see DistanceGestureContext for a default implementation.
+     */
+    val direction: InputDirection
+
+    /**
+     * The gesture distance of the current gesture, in pixels.
+     *
+     * Used solely for the [GestureDistance] [Guarantee]. Can be hard-coded to a static value if
+     * this type of [Guarantee] is not used.
+     */
+    val distance: Float
+}
+
+/** [GestureContext] implementation for manually set values. */
+class ProvidedGestureContext(direction: InputDirection, distance: Float) : GestureContext {
+    override var direction by mutableStateOf(direction)
+    override var distance by mutableFloatStateOf(distance)
+}
+
+/**
+ * [GestureContext] driven by a gesture distance.
+ *
+ * The direction is determined from the gesture input, where going further than
+ * [directionChangeSlop] in the opposite direction toggles the direction.
+ *
+ * @param initialDistance The initial [distance] of the [GestureContext]
+ * @param initialDirection The initial [direction] of the [GestureContext]
+ * @param directionChangeSlop the amount [distance] must be moved in the opposite direction for the
+ *   [direction] to flip.
+ */
+class DistanceGestureContext(
+    initialDistance: Float,
+    initialDirection: InputDirection,
+    directionChangeSlop: Float,
+) : GestureContext {
+    init {
+        require(directionChangeSlop > 0) {
+            "directionChangeSlop must be greater than 0, was $directionChangeSlop"
+        }
+    }
+
+    override var direction by mutableStateOf(initialDirection)
+        private set
+
+    private var furthestDistance by mutableFloatStateOf(initialDistance)
+    private var _distance by mutableFloatStateOf(initialDistance)
+
+    override var distance: Float
+        get() = _distance
+        /**
+         * Updates the [distance].
+         *
+         * This flips the [direction], if the [value] is further than [directionChangeSlop] away
+         * from the furthest recorded value regarding to the current [direction].
+         */
+        set(value) {
+            _distance = value
+            this.direction =
+                when (direction) {
+                    InputDirection.Max -> {
+                        if (furthestDistance - value > directionChangeSlop) {
+                            furthestDistance = value
+                            InputDirection.Min
+                        } else {
+                            furthestDistance = max(value, furthestDistance)
+                            InputDirection.Max
+                        }
+                    }
+
+                    InputDirection.Min -> {
+                        if (value - furthestDistance > directionChangeSlop) {
+                            furthestDistance = value
+                            InputDirection.Max
+                        } else {
+                            furthestDistance = min(value, furthestDistance)
+                            InputDirection.Min
+                        }
+                    }
+                }
+        }
+
+    private var _directionChangeSlop by mutableFloatStateOf(directionChangeSlop)
+
+    var directionChangeSlop: Float
+        get() = _directionChangeSlop
+
+        /**
+         * This flips the [direction], if the current [direction] is further than the new
+         * directionChangeSlop [value] away from the furthest recorded value regarding to the
+         * current [direction].
+         */
+        set(value) {
+            require(value > 0) { "directionChangeSlop must be greater than 0, was $value" }
+
+            _directionChangeSlop = value
+
+            when (direction) {
+                InputDirection.Max -> {
+                    if (furthestDistance - distance > directionChangeSlop) {
+                        furthestDistance = distance
+                        direction = InputDirection.Min
+                    }
+                }
+                InputDirection.Min -> {
+                    if (distance - furthestDistance > directionChangeSlop) {
+                        furthestDistance = value
+                        direction = InputDirection.Max
+                    }
+                }
+            }
+        }
+
+    /**
+     * Sets [distance] and [direction] to the specified values.
+     *
+     * This also resets memoized [furthestDistance], which is used to determine the direction
+     * change.
+     */
+    fun reset(distance: Float, direction: InputDirection) {
+        this.distance = distance
+        this.direction = direction
+        this.furthestDistance = distance
+    }
+}
diff --git a/mechanics/src/com/android/mechanics/spec/Breakpoint.kt b/mechanics/src/com/android/mechanics/spec/Breakpoint.kt
new file mode 100644
index 0000000..1ff5ad9
--- /dev/null
+++ b/mechanics/src/com/android/mechanics/spec/Breakpoint.kt
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
+
+package com.android.mechanics.spec
+
+import com.android.mechanics.spring.SpringParameters
+
+/**
+ * Key to identify a breakpoint in a [DirectionalMotionSpec].
+ *
+ * @param debugLabel name of the breakpoint, for tooling and debugging.
+ * @param identity is used to check the equality of two key instances.
+ */
+class BreakpointKey(val debugLabel: String? = null, val identity: Any = Object()) {
+    override fun equals(other: Any?): Boolean {
+        if (this === other) return true
+        if (javaClass != other?.javaClass) return false
+
+        other as BreakpointKey
+
+        return identity == other.identity
+    }
+
+    override fun hashCode(): Int {
+        return identity.hashCode()
+    }
+
+    override fun toString(): String {
+        return if (debugLabel != null) "BreakpointKey(label=$debugLabel)" else "BreakpointKey()"
+    }
+}
+
+/**
+ * Specification of a breakpoint, in the context of a [DirectionalMotionSpec].
+ *
+ * The [spring] and [guarantee] define the physics animation for the discontinuity at this
+ * breakpoint.They are applied in the direction of the containing [DirectionalMotionSpec].
+ *
+ * This [Breakpoint]'s animation definition is valid while the input is within the next segment. If
+ * the animation is still in progress when the input value reaches the next breakpoint, the
+ * remaining animation will be blended with the animation starting at the next breakpoint.
+ *
+ * @param key Identity of the [Breakpoint], unique within a [DirectionalMotionSpec].
+ * @param position The position of the [Breakpoint], in the domain of the `MotionValue`'s input.
+ * @param spring Parameters of the spring used to animate the breakpoints discontinuity.
+ * @param guarantee Optional constraints to accelerate the completion of the spring motion, based on
+ *   `MotionValue`'s input or other non-time signals.
+ */
+data class Breakpoint(
+    val key: BreakpointKey,
+    val position: Float,
+    val spring: SpringParameters,
+    val guarantee: Guarantee,
+) : Comparable<Breakpoint> {
+    companion object {
+        /** First breakpoint of each spec. */
+        val minLimit =
+            Breakpoint(
+                BreakpointKey("built-in::min"),
+                Float.NEGATIVE_INFINITY,
+                SpringParameters.Snap,
+                Guarantee.None,
+            )
+
+        /** Last breakpoint of each spec. */
+        val maxLimit =
+            Breakpoint(
+                BreakpointKey("built-in::max"),
+                Float.POSITIVE_INFINITY,
+                SpringParameters.Snap,
+                Guarantee.None,
+            )
+    }
+
+    override fun compareTo(other: Breakpoint): Int {
+        return position.compareTo(other.position)
+    }
+}
diff --git a/mechanics/src/com/android/mechanics/spec/FluentSpecBuilder.kt b/mechanics/src/com/android/mechanics/spec/FluentSpecBuilder.kt
new file mode 100644
index 0000000..297c949
--- /dev/null
+++ b/mechanics/src/com/android/mechanics/spec/FluentSpecBuilder.kt
@@ -0,0 +1,369 @@
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
+package com.android.mechanics.spec
+
+import com.android.mechanics.spring.SpringParameters
+
+/**
+ * Fluent builder for [DirectionalMotionSpec].
+ *
+ * This builder ensures correctness at compile-time, and simplifies the expression of the
+ * input-to-output mapping.
+ *
+ * The [MotionSpec] is defined by specify interleaved [Mapping]s and [Breakpoint]s. [Breakpoint]s
+ * must be specified in ascending order.
+ *
+ * NOTE: The returned fluent interfaces must only be used for chaining calls to build exactly one
+ * [DirectionalMotionSpec], otherwise resulting behavior is undefined, since the builder is
+ * internally mutated.
+ *
+ * @param defaultSpring spring to use for all breakpoints by default.
+ * @param initialMapping the [Mapping] from [Breakpoint.minLimit] to the next [Breakpoint].
+ * @see reverseBuilder to specify [Breakpoint]s in descending order.
+ */
+fun DirectionalMotionSpec.Companion.builder(
+    defaultSpring: SpringParameters,
+    initialMapping: Mapping = Mapping.Identity,
+): FluentSpecEndSegmentWithNextBreakpoint<DirectionalMotionSpec> {
+    return FluentSpecBuilder(defaultSpring, InputDirection.Max) { it }
+        .apply { mappings.add(initialMapping) }
+}
+
+/**
+ * Fluent builder for [DirectionalMotionSpec], specifying breakpoints and mappings in reverse order.
+ *
+ * Variant of [DirectionalMotionSpec.Companion.builder], where [Breakpoint]s must be specified in
+ * *descending* order. The resulting [DirectionalMotionSpec] will contain the breakpoints in
+ * ascending order.
+ *
+ * @param defaultSpring spring to use for all breakpoints by default.
+ * @param initialMapping the [Mapping] from [Breakpoint.maxLimit] to the next [Breakpoint].
+ * @see DirectionalMotionSpec.Companion.builder for more documentation.
+ */
+fun DirectionalMotionSpec.Companion.reverseBuilder(
+    defaultSpring: SpringParameters,
+    initialMapping: Mapping = Mapping.Identity,
+): FluentSpecEndSegmentWithNextBreakpoint<DirectionalMotionSpec> {
+    return FluentSpecBuilder(defaultSpring, InputDirection.Min) { it }
+        .apply { mappings.add(initialMapping) }
+}
+
+/**
+ * Fluent builder for a [MotionSpec], which uses the same spec in both directions.
+ *
+ * @param defaultSpring spring to use for all breakpoints by default.
+ * @param initialMapping [Mapping] for the first segment
+ * @param resetSpring the [MotionSpec.resetSpring].
+ */
+fun MotionSpec.Companion.builder(
+    defaultSpring: SpringParameters,
+    initialMapping: Mapping = Mapping.Identity,
+    resetSpring: SpringParameters = defaultSpring,
+): FluentSpecEndSegmentWithNextBreakpoint<MotionSpec> {
+    return FluentSpecBuilder(defaultSpring, InputDirection.Max) {
+            MotionSpec(it, resetSpring = resetSpring)
+        }
+        .apply { mappings.add(initialMapping) }
+}
+
+/** Fluent-interface to end the current segment, by placing the next [Breakpoint]. */
+interface FluentSpecEndSegmentWithNextBreakpoint<R> {
+    /**
+     * Adds a new [Breakpoint] at the specified position.
+     *
+     * @param atPosition The position of the breakpoint, in the input domain of the [MotionValue].
+     * @param key identifies the breakpoint in the [DirectionalMotionSpec]. Must be specified to
+     *   reference the breakpoint or segment.
+     */
+    fun toBreakpoint(
+        atPosition: Float,
+        key: BreakpointKey = BreakpointKey(),
+    ): FluentSpecDefineBreakpointAndStartNextSegment<R>
+
+    /** Completes the spec by placing the last, implicit [Breakpoint]. */
+    fun complete(): R
+}
+
+/** Fluent-interface to define the [Breakpoint]'s properties and start to start the next segment. */
+interface FluentSpecDefineBreakpointAndStartNextSegment<R> {
+    /**
+     * Default spring parameters for breakpoint, as specified at creation time of the builder.
+     *
+     * Used as the default `spring` parameters.
+     */
+    val defaultSpring: SpringParameters
+
+    /**
+     * Starts the next segment, using the specified mapping.
+     *
+     * @param mapping the mapping to use for the next segment.
+     * @param spring the spring to animate this breakpoints discontinuity.
+     * @param guarantee a guarantee by when the animation must be complete
+     */
+    fun continueWith(
+        mapping: Mapping,
+        spring: SpringParameters = defaultSpring,
+        guarantee: Guarantee = Guarantee.None,
+    ): FluentSpecEndSegmentWithNextBreakpoint<R>
+
+    /**
+     * Starts the next linear-mapped segment, by specifying the output [value] this breakpoint.
+     *
+     * @param value the output value the new mapping will produce at this breakpoints position.
+     * @param spring the spring to animate this breakpoints discontinuity.
+     * @param guarantee a guarantee by when the animation must be complete
+     */
+    fun jumpTo(
+        value: Float,
+        spring: SpringParameters = defaultSpring,
+        guarantee: Guarantee = Guarantee.None,
+    ): FluentSpecDefineLinearSegmentMapping<R>
+
+    /**
+     * Starts the next linear-mapped segment, by offsetting the output by [delta] from the incoming
+     * mapping.
+     *
+     * @param delta the delta in output from the previous mapping's output.
+     * @param spring the spring to animate this breakpoints discontinuity.
+     * @param guarantee a guarantee by when the animation must be complete
+     */
+    fun jumpBy(
+        delta: Float,
+        spring: SpringParameters = defaultSpring,
+        guarantee: Guarantee = Guarantee.None,
+    ): FluentSpecDefineLinearSegmentMapping<R>
+
+    /**
+     * Completes the spec by using [mapping] between the this and the implicit sentinel breakpoint
+     * at infinity.
+     *
+     * @param mapping the mapping to use for the final segment.
+     * @param spring the spring to animate this breakpoints discontinuity.
+     * @param guarantee a guarantee by when the animation must be complete
+     */
+    fun completeWith(
+        mapping: Mapping,
+        spring: SpringParameters = defaultSpring,
+        guarantee: Guarantee = Guarantee.None,
+    ): R
+}
+
+/** Fluent-interface to define a linear mapping between two breakpoints. */
+interface FluentSpecDefineLinearSegmentMapping<R> {
+    /**
+     * The linear-mapping will produce the specified [target] output at the next breakpoint
+     * position.
+     *
+     * @param target the output value the new mapping will produce at the next breakpoint position.
+     */
+    fun continueWithTargetValue(target: Float): FluentSpecEndSegmentWithNextBreakpoint<R>
+
+    /**
+     * Defines the slope for the linear mapping, as a fraction of the input value.
+     *
+     * @param fraction the multiplier applied to the input value..
+     */
+    fun continueWithFractionalInput(fraction: Float): FluentSpecEndSegmentWithNextBreakpoint<R>
+
+    /**
+     * The linear-mapping will produce a constant value, as defined at the source breakpoint of this
+     * segment.
+     */
+    fun continueWithConstantValue(): FluentSpecEndSegmentWithNextBreakpoint<R>
+}
+
+/** Implements the fluent spec builder logic. */
+private class FluentSpecBuilder<R>(
+    override val defaultSpring: SpringParameters,
+    buildDirection: InputDirection = InputDirection.Max,
+    private val toResult: (DirectionalMotionSpec) -> R,
+) :
+    FluentSpecDefineLinearSegmentMapping<R>,
+    FluentSpecDefineBreakpointAndStartNextSegment<R>,
+    FluentSpecEndSegmentWithNextBreakpoint<R> {
+    private val buildForward = buildDirection == InputDirection.Max
+
+    val breakpoints = mutableListOf<Breakpoint>()
+    val mappings = mutableListOf<Mapping>()
+
+    var sourceValue: Float = Float.NaN
+    var targetValue: Float = Float.NaN
+    var fractionalMapping: Float = Float.NaN
+    var breakpointPosition: Float = Float.NaN
+    var breakpointKey: BreakpointKey? = null
+
+    init {
+        val initialBreakpoint = if (buildForward) Breakpoint.minLimit else Breakpoint.maxLimit
+        breakpoints.add(initialBreakpoint)
+    }
+
+    //  FluentSpecDefineLinearSegmentMapping
+
+    override fun continueWithTargetValue(target: Float): FluentSpecEndSegmentWithNextBreakpoint<R> {
+        check(sourceValue.isFinite())
+
+        // memoize for FluentSpecEndSegmentWithNextBreakpoint
+        targetValue = target
+
+        return this
+    }
+
+    override fun continueWithFractionalInput(
+        fraction: Float
+    ): FluentSpecEndSegmentWithNextBreakpoint<R> {
+        check(sourceValue.isFinite())
+
+        // memoize for FluentSpecEndSegmentWithNextBreakpoint
+        fractionalMapping = fraction
+
+        return this
+    }
+
+    override fun continueWithConstantValue(): FluentSpecEndSegmentWithNextBreakpoint<R> {
+        check(sourceValue.isFinite())
+
+        mappings.add(Mapping.Fixed(sourceValue))
+
+        sourceValue = Float.NaN
+        return this
+    }
+
+    // FluentSpecDefineBreakpointAndStartNextSegment implementation
+
+    override fun jumpTo(
+        value: Float,
+        spring: SpringParameters,
+        guarantee: Guarantee,
+    ): FluentSpecDefineLinearSegmentMapping<R> {
+        check(sourceValue.isNaN())
+
+        doAddBreakpoint(spring, guarantee)
+        sourceValue = value
+
+        return this
+    }
+
+    override fun jumpBy(
+        delta: Float,
+        spring: SpringParameters,
+        guarantee: Guarantee,
+    ): FluentSpecDefineLinearSegmentMapping<R> {
+        check(sourceValue.isNaN())
+
+        val breakpoint = doAddBreakpoint(spring, guarantee)
+        sourceValue = mappings.last().map(breakpoint.position) + delta
+
+        return this
+    }
+
+    override fun continueWith(
+        mapping: Mapping,
+        spring: SpringParameters,
+        guarantee: Guarantee,
+    ): FluentSpecEndSegmentWithNextBreakpoint<R> {
+        check(sourceValue.isNaN())
+
+        doAddBreakpoint(spring, guarantee)
+        mappings.add(mapping)
+
+        return this
+    }
+
+    override fun completeWith(mapping: Mapping, spring: SpringParameters, guarantee: Guarantee): R {
+        check(sourceValue.isNaN())
+
+        doAddBreakpoint(spring, guarantee)
+        mappings.add(mapping)
+
+        return complete()
+    }
+
+    // FluentSpecEndSegmentWithNextBreakpoint implementation
+
+    override fun toBreakpoint(
+        atPosition: Float,
+        key: BreakpointKey,
+    ): FluentSpecDefineBreakpointAndStartNextSegment<R> {
+        check(breakpointPosition.isNaN())
+        check(breakpointKey == null)
+
+        if (!targetValue.isNaN() || !fractionalMapping.isNaN()) {
+            check(!sourceValue.isNaN())
+
+            val sourcePosition = breakpoints.last().position
+
+            if (fractionalMapping.isNaN()) {
+                val delta = targetValue - sourceValue
+                fractionalMapping = delta / (atPosition - sourcePosition)
+            } else {
+                val delta = (atPosition - sourcePosition) * fractionalMapping
+                targetValue = sourceValue + delta
+            }
+
+            val offset =
+                if (buildForward) sourceValue - (sourcePosition * fractionalMapping)
+                else targetValue - (atPosition * fractionalMapping)
+
+            mappings.add(Mapping.Linear(fractionalMapping, offset))
+            targetValue = Float.NaN
+            sourceValue = Float.NaN
+            fractionalMapping = Float.NaN
+        }
+
+        breakpointPosition = atPosition
+        breakpointKey = key
+
+        return this
+    }
+
+    override fun complete(): R {
+        check(targetValue.isNaN()) { "cant specify target value for last segment" }
+
+        if (!fractionalMapping.isNaN()) {
+            check(!sourceValue.isNaN())
+
+            val sourcePosition = breakpoints.last().position
+
+            mappings.add(
+                Mapping.Linear(
+                    fractionalMapping,
+                    sourceValue - (sourcePosition * fractionalMapping),
+                )
+            )
+        }
+
+        if (buildForward) {
+            breakpoints.add(Breakpoint.maxLimit)
+        } else {
+            breakpoints.add(Breakpoint.minLimit)
+            breakpoints.reverse()
+            mappings.reverse()
+        }
+
+        return toResult(DirectionalMotionSpec(breakpoints.toList(), mappings.toList()))
+    }
+
+    private fun doAddBreakpoint(springSpec: SpringParameters, guarantee: Guarantee): Breakpoint {
+        check(breakpointPosition.isFinite())
+        return Breakpoint(checkNotNull(breakpointKey), breakpointPosition, springSpec, guarantee)
+            .also {
+                breakpoints.add(it)
+                breakpointPosition = Float.NaN
+                breakpointKey = null
+            }
+    }
+}
diff --git a/mechanics/src/com/android/mechanics/spec/Guarantee.kt b/mechanics/src/com/android/mechanics/spec/Guarantee.kt
new file mode 100644
index 0000000..33185ea
--- /dev/null
+++ b/mechanics/src/com/android/mechanics/spec/Guarantee.kt
@@ -0,0 +1,45 @@
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
+package com.android.mechanics.spec
+
+/**
+ * Describes the condition by which a discontinuity at a breakpoint must have finished animating.
+ *
+ * With a guarantee in effect, the spring parameters will be continuously adjusted, ensuring the
+ * guarantee's target will be met.
+ */
+sealed class Guarantee {
+    /**
+     * No guarantee is provided.
+     *
+     * The spring animation will proceed at its natural pace, regardless of the input or gesture's
+     * progress.
+     */
+    data object None : Guarantee()
+
+    /**
+     * Guarantees that the animation will be complete before the input value is [delta] away from
+     * the [Breakpoint] position.
+     */
+    data class InputDelta(val delta: Float) : Guarantee()
+
+    /**
+     * Guarantees to complete the animation before the gesture is [distance] away from the gesture
+     * position captured when the breakpoint was crossed.
+     */
+    data class GestureDistance(val distance: Float) : Guarantee()
+}
diff --git a/mechanics/src/com/android/mechanics/spec/InputDirection.kt b/mechanics/src/com/android/mechanics/spec/InputDirection.kt
new file mode 100644
index 0000000..58fa590
--- /dev/null
+++ b/mechanics/src/com/android/mechanics/spec/InputDirection.kt
@@ -0,0 +1,31 @@
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
+package com.android.mechanics.spec
+
+/**
+ * The intrinsic direction of the input value.
+ *
+ * It reflects the user's intent, that is its meant to be derived from a gesture. If the input is
+ * driven by an animation, the direction is expected to not change.
+ *
+ * The directions are labelled [Min] and [Max] to reflect descending and ascending input values
+ * respectively, but it does not imply an spatial direction.
+ */
+enum class InputDirection(val sign: Int) {
+    Min(sign = -1),
+    Max(sign = +1),
+}
diff --git a/mechanics/src/com/android/mechanics/spec/MotionSpec.kt b/mechanics/src/com/android/mechanics/spec/MotionSpec.kt
new file mode 100644
index 0000000..4bd4240
--- /dev/null
+++ b/mechanics/src/com/android/mechanics/spec/MotionSpec.kt
@@ -0,0 +1,204 @@
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
+package com.android.mechanics.spec
+
+import com.android.mechanics.spring.SpringParameters
+
+/**
+ * Handler to allow for custom segment-change logic.
+ *
+ * This handler is called whenever the new input (position or direction) does not match
+ * [currentSegment] anymore (see [SegmentData.isValidForInput]).
+ *
+ * This is intended to implement custom effects on direction-change.
+ *
+ * Implementations can return:
+ * 1. [currentSegment] to delay/suppress segment change.
+ * 2. `null` to use the default segment lookup based on [newPosition] and [newDirection]
+ * 3. manually looking up segments on this [MotionSpec]
+ * 4. create a [SegmentData] that is not in the spec.
+ */
+typealias OnChangeSegmentHandler =
+    MotionSpec.(
+        currentSegment: SegmentData, newPosition: Float, newDirection: InputDirection,
+    ) -> SegmentData?
+
+/**
+ * Specification for the mapping of input values to output values.
+ *
+ * The spec consists of two independent directional spec's, while only one the one matching
+ * `MotionInput`'s `direction` is used at any given time.
+ *
+ * @param maxDirection spec used when the MotionInput's direction is [InputDirection.Max]
+ * @param minDirection spec used when the MotionInput's direction is [InputDirection.Min]
+ * @param resetSpring spring parameters to animate a difference in output, if the difference is
+ *   caused by setting this new spec.
+ * @param segmentHandlers allow for custom segment-change logic, when the `MotionValue` runtime
+ *   would leave the [SegmentKey].
+ */
+data class MotionSpec(
+    val maxDirection: DirectionalMotionSpec,
+    val minDirection: DirectionalMotionSpec = maxDirection,
+    val resetSpring: SpringParameters = DefaultResetSpring,
+    val segmentHandlers: Map<SegmentKey, OnChangeSegmentHandler> = emptyMap(),
+) {
+
+    /** The [DirectionalMotionSpec] for the specified [direction]. */
+    operator fun get(direction: InputDirection): DirectionalMotionSpec {
+        return when (direction) {
+            InputDirection.Min -> minDirection
+            InputDirection.Max -> maxDirection
+        }
+    }
+
+    /** Whether this spec contains a segment with the specified [segmentKey]. */
+    fun containsSegment(segmentKey: SegmentKey): Boolean {
+        return get(segmentKey.direction).findSegmentIndex(segmentKey) != -1
+    }
+
+    /**
+     * The [SegmentData] for an input with the specified [position] and [direction].
+     *
+     * The returned [SegmentData] will be cached while [SegmentData.isValidForInput] returns `true`.
+     */
+    fun segmentAtInput(position: Float, direction: InputDirection): SegmentData {
+        require(position.isFinite())
+
+        return with(get(direction)) {
+            var idx = findBreakpointIndex(position)
+            if (direction == InputDirection.Min && breakpoints[idx].position == position) {
+                // The segment starts at `position`. Since the breakpoints are sorted ascending, no
+                // matter the spec's direction, need to return the previous segment in the min
+                // direction.
+                idx--
+            }
+
+            SegmentData(
+                this@MotionSpec,
+                breakpoints[idx],
+                breakpoints[idx + 1],
+                direction,
+                mappings[idx],
+            )
+        }
+    }
+
+    /**
+     * Looks up the new [SegmentData] once the [currentSegment] is not valid for an input with
+     * [newPosition] and [newDirection].
+     *
+     * This will delegate to the [segmentHandlers], if registered for the [currentSegment]'s key.
+     */
+    internal fun onChangeSegment(
+        currentSegment: SegmentData,
+        newPosition: Float,
+        newDirection: InputDirection,
+    ): SegmentData {
+        val segmentChangeHandler = segmentHandlers[currentSegment.key]
+        return segmentChangeHandler?.invoke(this, currentSegment, newPosition, newDirection)
+            ?: segmentAtInput(newPosition, newDirection)
+    }
+
+    companion object {
+        /**
+         * Default spring parameters for the reset spring. Matches the Fast Spatial spring of the
+         * standard motion scheme.
+         */
+        private val DefaultResetSpring = SpringParameters(stiffness = 1400f, dampingRatio = 1f)
+
+        /* Empty motion spec, the output is the same as the input. */
+        val Empty = MotionSpec(DirectionalMotionSpec.Empty)
+    }
+}
+
+/**
+ * Defines the [breakpoints], as well as the [mappings] in-between adjacent [Breakpoint] pairs.
+ *
+ * This [DirectionalMotionSpec] is applied in the direction defined by the containing [MotionSpec]:
+ * especially the direction in which the `breakpoint` [Guarantee] are applied depend on how this is
+ * used; this type does not have an inherit direction.
+ *
+ * All [breakpoints] are sorted in ascending order by their `position`, with the first and last
+ * breakpoints are guaranteed to be sentinel values for negative and positive infinity respectively.
+ *
+ * @param breakpoints All breakpoints in the spec, must contain [Breakpoint.minLimit] as the first
+ *   element, and [Breakpoint.maxLimit] as the last element.
+ * @param mappings All mappings in between the breakpoints, thus must always contain
+ *   `breakpoints.size - 1` elements.
+ */
+data class DirectionalMotionSpec(val breakpoints: List<Breakpoint>, val mappings: List<Mapping>) {
+    init {
+        require(breakpoints.size >= 2)
+        require(breakpoints.first() == Breakpoint.minLimit)
+        require(breakpoints.last() == Breakpoint.maxLimit)
+        require(breakpoints.zipWithNext { a, b -> a <= b }.all { it }) {
+            "Breakpoints are not sorted ascending ${breakpoints.map { "${it.key}@${it.position}" }}"
+        }
+        require(mappings.size == breakpoints.size - 1)
+    }
+
+    /**
+     * Returns the index of the closest breakpoint where `Breakpoint.position <= position`.
+     *
+     * Guaranteed to be a valid index into [breakpoints], and guaranteed to be neither the first nor
+     * the last element.
+     *
+     * @param position the position in the input domain.
+     * @return Index into [breakpoints], guaranteed to be in range `1..breakpoints.size - 2`
+     */
+    fun findBreakpointIndex(position: Float): Int {
+        require(position.isFinite())
+        val breakpointPosition = breakpoints.binarySearchBy(position) { it.position }
+
+        val result =
+            when {
+                // position is between two anchors, return the min one.
+                breakpointPosition < 0 -> -breakpointPosition - 2
+                else -> breakpointPosition
+            }
+
+        check(result >= 0)
+        check(result < breakpoints.size - 1)
+
+        return result
+    }
+
+    /**
+     * The index of the breakpoint with the specified [breakpointKey], or `-1` if no such breakpoint
+     * exists.
+     */
+    fun findBreakpointIndex(breakpointKey: BreakpointKey): Int {
+        return breakpoints.indexOfFirst { it.key == breakpointKey }
+    }
+
+    /** Index into [mappings] for the specified [segmentKey], or `-1` if no such segment exists. */
+    fun findSegmentIndex(segmentKey: SegmentKey): Int {
+        val result = breakpoints.indexOfFirst { it.key == segmentKey.minBreakpoint }
+        if (result < 0 || breakpoints[result + 1].key != segmentKey.maxBreakpoint) return -1
+
+        return result
+    }
+
+    companion object {
+        /* Empty spec, the full input domain is mapped to output using [Mapping.identity]. */
+        val Empty =
+            DirectionalMotionSpec(
+                listOf(Breakpoint.minLimit, Breakpoint.maxLimit),
+                listOf(Mapping.Identity),
+            )
+    }
+}
diff --git a/mechanics/src/com/android/mechanics/spec/Segment.kt b/mechanics/src/com/android/mechanics/spec/Segment.kt
new file mode 100644
index 0000000..14b1f40
--- /dev/null
+++ b/mechanics/src/com/android/mechanics/spec/Segment.kt
@@ -0,0 +1,115 @@
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
+package com.android.mechanics.spec
+
+/**
+ * Identifies a segment in a [MotionSpec].
+ *
+ * A segment only exists between two adjacent [Breakpoint]s; it cannot span multiple breakpoints.
+ * The [direction] indicates to the relevant [DirectionalMotionSpec] of the [MotionSpec].
+ *
+ * The position of the [minBreakpoint] must be less or equal to the position of the [maxBreakpoint].
+ */
+data class SegmentKey(
+    val minBreakpoint: BreakpointKey,
+    val maxBreakpoint: BreakpointKey,
+    val direction: InputDirection,
+)
+
+/**
+ * Captures denormalized segment data from a [MotionSpec].
+ *
+ * Instances are created by the [MotionSpec] and used by the [MotionValue] runtime to compute the
+ * output value. By default, the [SegmentData] is cached while [isValidForInput] returns true.
+ *
+ * The [SegmentData] has an intrinsic direction, thus the segment has an entry and exit side, at the
+ * respective breakpoint.
+ */
+data class SegmentData(
+    val spec: MotionSpec,
+    val minBreakpoint: Breakpoint,
+    val maxBreakpoint: Breakpoint,
+    val direction: InputDirection,
+    val mapping: Mapping,
+) {
+    val key = SegmentKey(minBreakpoint.key, maxBreakpoint.key, direction)
+
+    /**
+     * Whether the given [inputPosition] and [inputDirection] should be handled by this segment.
+     *
+     * The input is considered invalid only if the direction changes or the input is *at or outside*
+     * the segment on the exit-side. The input remains intentionally valid outside the segment on
+     * the entry-side, to avoid flip-flopping.
+     */
+    fun isValidForInput(inputPosition: Float, inputDirection: InputDirection): Boolean {
+        if (inputDirection != direction) return false
+
+        return when (inputDirection) {
+            InputDirection.Max -> inputPosition < maxBreakpoint.position
+            InputDirection.Min -> inputPosition > minBreakpoint.position
+        }
+    }
+
+    /**
+     * The breakpoint at the side of the segment's start.
+     *
+     * The [entryBreakpoint]'s [Guarantee] is the relevant guarantee for this segment.
+     */
+    val entryBreakpoint: Breakpoint
+        get() =
+            when (direction) {
+                InputDirection.Max -> minBreakpoint
+                InputDirection.Min -> maxBreakpoint
+            }
+}
+
+/**
+ * Maps the `input` of a [MotionValue] to the desired output value.
+ *
+ * The mapping implementation can be arbitrary, but must not produce discontinuities.
+ */
+fun interface Mapping {
+    /** Computes the [MotionValue]'s target output, given the input. */
+    fun map(input: Float): Float
+
+    /** `f(x) = x` */
+    object Identity : Mapping {
+        override fun map(input: Float): Float {
+            return input
+        }
+    }
+
+    /** `f(x) = value` */
+    data class Fixed(val value: Float) : Mapping {
+        override fun map(input: Float): Float {
+            return value
+        }
+    }
+
+    /** `f(x) = factor*x + offset` */
+    data class Linear(val factor: Float, val offset: Float = 0f) : Mapping {
+        override fun map(input: Float): Float {
+            return input * factor + offset
+        }
+    }
+
+    companion object {
+        val Zero = Fixed(0f)
+        val One = Fixed(1f)
+        val Two = Fixed(2f)
+    }
+}
diff --git a/mechanics/src/com/android/mechanics/spring/SpringParameters.kt b/mechanics/src/com/android/mechanics/spring/SpringParameters.kt
new file mode 100644
index 0000000..98b64e8
--- /dev/null
+++ b/mechanics/src/com/android/mechanics/spring/SpringParameters.kt
@@ -0,0 +1,78 @@
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
+package com.android.mechanics.spring
+
+import androidx.compose.ui.util.lerp
+import androidx.compose.ui.util.packFloats
+import androidx.compose.ui.util.unpackFloat1
+import androidx.compose.ui.util.unpackFloat2
+import kotlin.math.pow
+
+/**
+ * Describes the parameters of a spring.
+ *
+ * Note: This is conceptually compatible with the Compose [SpringSpec]. In contrast to the compose
+ * implementation, these [SpringParameters] are intended to be continuously updated.
+ *
+ * @see SpringParameters function to create this value.
+ */
+@JvmInline
+value class SpringParameters(private val packedValue: Long) {
+    val stiffness: Float
+        get() = unpackFloat1(packedValue)
+
+    val dampingRatio: Float
+        get() = unpackFloat2(packedValue)
+
+    /** Whether the spring is expected to immediately end movement. */
+    val isSnapSpring: Boolean
+        get() = stiffness >= snapStiffness && dampingRatio == snapDamping
+
+    override fun toString(): String {
+        return "MechanicsSpringSpec(stiffness=$stiffness, dampingRatio=$dampingRatio)"
+    }
+
+    companion object {
+        private val snapStiffness = 100_000f
+        private val snapDamping = 1f
+
+        /** A spring so stiff it completes the motion almost immediately. */
+        val Snap = SpringParameters(snapStiffness, snapDamping)
+    }
+}
+
+/** Creates a [SpringParameters] with the given [stiffness] and [dampingRatio]. */
+fun SpringParameters(stiffness: Float, dampingRatio: Float): SpringParameters {
+    require(stiffness > 0) { "Spring stiffness constant must be positive." }
+    require(dampingRatio >= 0) { "Spring damping constant must be positive." }
+    return SpringParameters(packFloats(stiffness, dampingRatio))
+}
+
+/**
+ * Return interpolated [SpringParameters], based on the [fraction] between [start] and [stop].
+ *
+ * The [SpringParameters.dampingRatio] is interpolated linearly, the [SpringParameters.stiffness] is
+ * interpolated logarithmically.
+ *
+ * The [fraction] is clamped to a `0..1` range.
+ */
+fun lerp(start: SpringParameters, stop: SpringParameters, fraction: Float): SpringParameters {
+    val f = fraction.coerceIn(0f, 1f)
+    val stiffness = start.stiffness.pow(1 - f) * stop.stiffness.pow(f)
+    val dampingRatio = lerp(start.dampingRatio, stop.dampingRatio, f)
+    return SpringParameters(packFloats(stiffness, dampingRatio))
+}
diff --git a/mechanics/src/com/android/mechanics/spring/SpringState.kt b/mechanics/src/com/android/mechanics/spring/SpringState.kt
new file mode 100644
index 0000000..57de280
--- /dev/null
+++ b/mechanics/src/com/android/mechanics/spring/SpringState.kt
@@ -0,0 +1,129 @@
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
+package com.android.mechanics.spring
+
+import androidx.compose.ui.util.packFloats
+import androidx.compose.ui.util.unpackFloat1
+import androidx.compose.ui.util.unpackFloat2
+import kotlin.math.cos
+import kotlin.math.exp
+import kotlin.math.sin
+import kotlin.math.sqrt
+
+/**
+ * Describes the motion state of a spring.
+ *
+ * @see calculateUpdatedState to simulate the springs movement
+ * @see SpringState function to create this value.
+ */
+@JvmInline
+value class SpringState(private val packedValue: Long) {
+    val displacement: Float
+        get() = unpackFloat1(packedValue)
+
+    val velocity: Float
+        get() = unpackFloat2(packedValue)
+
+    /**
+     * Whether the state is considered stable.
+     *
+     * The amplitude of the remaining movement, for a spring with [parameters] is less than
+     * [stableThreshold]
+     */
+    fun isStable(parameters: SpringParameters, stableThreshold: Float): Boolean {
+        if (this == AtRest) return true
+        val currentEnergy = parameters.stiffness * displacement * displacement + velocity * velocity
+        val maxStableEnergy = parameters.stiffness * stableThreshold * stableThreshold
+        return currentEnergy <= maxStableEnergy
+    }
+
+    override fun toString(): String {
+        return "MechanicsSpringState(displacement=$displacement, velocity=$velocity)"
+    }
+
+    companion object {
+        /** Spring at rest. */
+        val AtRest = SpringState(displacement = 0f, velocity = 0f)
+    }
+}
+
+/** Creates a [SpringState] given [displacement] and [velocity] */
+fun SpringState(displacement: Float, velocity: Float = 0f) =
+    SpringState(packFloats(displacement, velocity))
+
+/**
+ * Computes the updated [SpringState], after letting the spring with the specified [parameters]
+ * settle for [elapsedNanos].
+ *
+ * This implementation is based on Compose's [SpringSimulation].
+ */
+fun SpringState.calculateUpdatedState(
+    elapsedNanos: Long,
+    parameters: SpringParameters,
+): SpringState {
+    if (parameters.isSnapSpring || this == SpringState.AtRest) {
+        return SpringState.AtRest
+    }
+
+    val stiffness = parameters.stiffness.toDouble()
+    val naturalFreq = sqrt(stiffness)
+
+    val dampingRatio = parameters.dampingRatio
+    val displacement = displacement
+    val velocity = velocity
+    val deltaT = elapsedNanos / 1_000_000_000.0 // unit: seconds
+    val dampingRatioSquared = dampingRatio * dampingRatio.toDouble()
+    val r = -dampingRatio * naturalFreq
+
+    val currentDisplacement: Double
+    val currentVelocity: Double
+
+    if (dampingRatio > 1) {
+        // Over damping
+        val s = naturalFreq * sqrt(dampingRatioSquared - 1)
+        val gammaPlus = r + s
+        val gammaMinus = r - s
+
+        val coeffB = (gammaMinus * displacement - velocity) / (gammaMinus - gammaPlus)
+        val coeffA = displacement - coeffB
+        currentDisplacement = (coeffA * exp(gammaMinus * deltaT) + coeffB * exp(gammaPlus * deltaT))
+        currentVelocity =
+            (coeffA * gammaMinus * exp(gammaMinus * deltaT) +
+                coeffB * gammaPlus * exp(gammaPlus * deltaT))
+    } else if (dampingRatio == 1.0f) {
+        // Critically damped
+        val coeffA = displacement
+        val coeffB = velocity + naturalFreq * displacement
+        val nFdT = -naturalFreq * deltaT
+        currentDisplacement = (coeffA + coeffB * deltaT) * exp(nFdT)
+        currentVelocity =
+            (((coeffA + coeffB * deltaT) * exp(nFdT) * (-naturalFreq)) + coeffB * exp(nFdT))
+    } else {
+        // Underdamped
+        val dampedFreq = naturalFreq * sqrt(1 - dampingRatioSquared)
+        val cosCoeff = displacement
+        val sinCoeff = ((1 / dampedFreq) * (((-r * displacement) + velocity)))
+        val dFdT = dampedFreq * deltaT
+        currentDisplacement = (exp(r * deltaT) * ((cosCoeff * cos(dFdT) + sinCoeff * sin(dFdT))))
+        currentVelocity =
+            (currentDisplacement * r +
+                (exp(r * deltaT) *
+                    ((-dampedFreq * cosCoeff * sin(dFdT) + dampedFreq * sinCoeff * cos(dFdT)))))
+    }
+
+    return SpringState(currentDisplacement.toFloat(), currentVelocity.toFloat())
+}
diff --git a/mechanics/tests/Android.bp b/mechanics/tests/Android.bp
new file mode 100644
index 0000000..f892ef1
--- /dev/null
+++ b/mechanics/tests/Android.bp
@@ -0,0 +1,49 @@
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
+android_test {
+    name: "mechanics_tests",
+    manifest: "AndroidManifest.xml",
+    test_suites: ["device-tests"],
+
+    srcs: [
+        "src/**/*.kt",
+
+        // TODO(b/240432457): Depend on mechanics directly
+        ":mechanics-srcs",
+    ],
+
+    static_libs: [
+        // ":mechanics" dependencies
+        "androidx.compose.runtime_runtime",
+        "androidx.compose.ui_ui-util",
+
+        // ":mechanics_tests" dependencies
+        "androidx.compose.animation_animation-core",
+        "platform-test-annotations",
+        "PlatformMotionTesting",
+        "androidx.compose.ui_ui-test-junit4",
+        "androidx.test.runner",
+        "androidx.test.ext.junit",
+        "kotlin-test",
+        "truth",
+    ],
+    asset_dirs: ["goldens"],
+    kotlincflags: ["-Xjvm-default=all"],
+}
diff --git a/mechanics/tests/AndroidManifest.xml b/mechanics/tests/AndroidManifest.xml
new file mode 100644
index 0000000..edbbcbf
--- /dev/null
+++ b/mechanics/tests/AndroidManifest.xml
@@ -0,0 +1,28 @@
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
+    package="com.android.mechanics.tests">
+
+    <application>
+        <uses-library android:name="android.test.runner" />
+    </application>
+
+    <instrumentation
+        android:name="androidx.test.runner.AndroidJUnitRunner"
+        android:label="Tests for Motion Mechanics"
+        android:targetPackage="com.android.mechanics.tests" />
+</manifest>
diff --git a/mechanics/tests/goldens/criticallyDamped_matchesGolden.json b/mechanics/tests/goldens/criticallyDamped_matchesGolden.json
new file mode 100644
index 0000000..5dbf8b0
--- /dev/null
+++ b/mechanics/tests/goldens/criticallyDamped_matchesGolden.json
@@ -0,0 +1,814 @@
+{
+  "frame_ids": [
+    0,
+    10,
+    20,
+    30,
+    40,
+    50,
+    60,
+    70,
+    80,
+    90,
+    100,
+    110,
+    120,
+    130,
+    140,
+    150,
+    160,
+    170,
+    180,
+    190,
+    200,
+    210,
+    220,
+    230,
+    240,
+    250,
+    260,
+    270,
+    280,
+    290,
+    300,
+    310,
+    320,
+    330,
+    340,
+    350,
+    360,
+    370,
+    380,
+    390,
+    400,
+    410,
+    420,
+    430,
+    440,
+    450,
+    460,
+    470,
+    480,
+    490,
+    500,
+    510,
+    520,
+    530,
+    540,
+    550,
+    560,
+    570,
+    580,
+    590,
+    600,
+    610,
+    620,
+    630,
+    640,
+    650,
+    660,
+    670,
+    680,
+    690,
+    700,
+    710,
+    720,
+    730,
+    740,
+    750,
+    760,
+    770,
+    780,
+    790,
+    800,
+    810,
+    820,
+    830,
+    840,
+    850,
+    860,
+    870,
+    880,
+    890,
+    900,
+    910,
+    920,
+    930,
+    940,
+    950,
+    960,
+    970
+  ],
+  "features": [
+    {
+      "name": "displacement",
+      "type": "float",
+      "data_points": [
+        10,
+        9.953212,
+        9.824769,
+        9.630637,
+        9.38448,
+        9.0979595,
+        8.780986,
+        8.44195,
+        8.087921,
+        7.7248235,
+        7.357589,
+        6.9902925,
+        6.6262727,
+        6.2682314,
+        5.9183273,
+        5.578254,
+        5.2493095,
+        4.932455,
+        4.628369,
+        4.33749,
+        4.0600586,
+        3.7961493,
+        3.545701,
+        3.3085418,
+        3.0844104,
+        2.8729749,
+        2.6738486,
+        2.4866037,
+        2.3107822,
+        2.1459055,
+        1.9914826,
+        1.8470172,
+        1.7120124,
+        1.585976,
+        1.4684237,
+        1.3588821,
+        1.256891,
+        1.1620055,
+        1.0737969,
+        0.9918535,
+        0.91578174,
+        0.84520626,
+        0.77976984,
+        0.7191335,
+        0.6629762,
+        0.61099464,
+        0.5629026,
+        0.51843065,
+        0.4773252,
+        0.43934828,
+        0.4042767,
+        0.37190142,
+        0.3420269,
+        0.31447032,
+        0.2890611,
+        0.26564008,
+        0.24405895,
+        0.22417964,
+        0.20587368,
+        0.18902166,
+        0.17351262,
+        0.15924358,
+        0.14611898,
+        0.13405024,
+        0.122955225,
+        0.11275793,
+        0.10338796,
+        0.09478021,
+        0.086874455,
+        0.07961504,
+        0.07295055,
+        0.06683349,
+        0.061220028,
+        0.05606971,
+        0.051345225,
+        0.047012165,
+        0.04303882,
+        0.039395962,
+        0.036056675,
+        0.032996174,
+        0.030191636,
+        0.02762206,
+        0.025268128,
+        0.023112064,
+        0.021137528,
+        0.019329496,
+        0.017674157,
+        0.016158825,
+        0.014771842,
+        0.013502505,
+        0.0123409815,
+        0.011278247,
+        0.01030602,
+        0.009416698,
+        0.008603305,
+        0.007859444,
+        0.007179248,
+        0.006557336
+      ]
+    },
+    {
+      "name": "velocity",
+      "type": "float",
+      "data_points": [
+        0,
+        -9.048374,
+        -16.374615,
+        -22.224546,
+        -26.812801,
+        -30.326532,
+        -32.928696,
+        -34.760967,
+        -35.946312,
+        -36.591267,
+        -36.78794,
+        -36.615818,
+        -36.143303,
+        -35.42913,
+        -34.523575,
+        -33.469524,
+        -32.303444,
+        -31.0562,
+        -29.753801,
+        -28.41804,
+        -27.067059,
+        -25.71585,
+        -24.376696,
+        -23.059534,
+        -21.772308,
+        -20.52125,
+        -19.31113,
+        -18.145489,
+        -17.026817,
+        -15.956734,
+        -14.93612,
+        -13.965252,
+        -13.043904,
+        -12.171444,
+        -11.34691,
+        -10.569083,
+        -9.836539,
+        -9.147704,
+        -8.500893,
+        -7.894345,
+        -7.326255,
+        -6.794796,
+        -6.2981415,
+        -5.83448,
+        -5.402029,
+        -4.9990478,
+        -4.6238437,
+        -4.2747793,
+        -3.9502778,
+        -3.648825,
+        -3.3689728,
+        -3.10934,
+        -2.8686128,
+        -2.645544,
+        -2.438953,
+        -2.2477236,
+        -2.070803,
+        -1.9071996,
+        -1.7559812,
+        -1.616272,
+        -1.4872509,
+        -1.3681489,
+        -1.2582467,
+        -1.1568717,
+        -1.0633963,
+        -0.9772352,
+        -0.89784265,
+        -0.8247107,
+        -0.7573669,
+        -0.69537175,
+        -0.6383172,
+        -0.5858244,
+        -0.5375417,
+        -0.49314323,
+        -0.45232698,
+        -0.41481322,
+        -0.38034305,
+        -0.3486769,
+        -0.31959325,
+        -0.29288736,
+        -0.26837006,
+        -0.24586667,
+        -0.2252159,
+        -0.20626894,
+        -0.18888852,
+        -0.17294809,
+        -0.15833096,
+        -0.14492963,
+        -0.13264509,
+        -0.121386126,
+        -0.11106881,
+        -0.101615876,
+        -0.092956245,
+        -0.085024536,
+        -0.07776062,
+        -0.07110924,
+        -0.06501959,
+        -0.059444997
+      ]
+    },
+    {
+      "name": "stable",
+      "type": "boolean",
+      "data_points": [
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        true,
+        true
+      ]
+    },
+    {
+      "name": "parameters",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 1
+        }
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/goldens/overDamped_matchesGolden.json b/mechanics/tests/goldens/overDamped_matchesGolden.json
new file mode 100644
index 0000000..2fcf21a
--- /dev/null
+++ b/mechanics/tests/goldens/overDamped_matchesGolden.json
@@ -0,0 +1,2142 @@
+{
+  "frame_ids": [
+    0,
+    10,
+    20,
+    30,
+    40,
+    50,
+    60,
+    70,
+    80,
+    90,
+    100,
+    110,
+    120,
+    130,
+    140,
+    150,
+    160,
+    170,
+    180,
+    190,
+    200,
+    210,
+    220,
+    230,
+    240,
+    250,
+    260,
+    270,
+    280,
+    290,
+    300,
+    310,
+    320,
+    330,
+    340,
+    350,
+    360,
+    370,
+    380,
+    390,
+    400,
+    410,
+    420,
+    430,
+    440,
+    450,
+    460,
+    470,
+    480,
+    490,
+    500,
+    510,
+    520,
+    530,
+    540,
+    550,
+    560,
+    570,
+    580,
+    590,
+    600,
+    610,
+    620,
+    630,
+    640,
+    650,
+    660,
+    670,
+    680,
+    690,
+    700,
+    710,
+    720,
+    730,
+    740,
+    750,
+    760,
+    770,
+    780,
+    790,
+    800,
+    810,
+    820,
+    830,
+    840,
+    850,
+    860,
+    870,
+    880,
+    890,
+    900,
+    910,
+    920,
+    930,
+    940,
+    950,
+    960,
+    970,
+    980,
+    990,
+    1000,
+    1010,
+    1020,
+    1030,
+    1040,
+    1050,
+    1060,
+    1070,
+    1080,
+    1090,
+    1100,
+    1110,
+    1120,
+    1130,
+    1140,
+    1150,
+    1160,
+    1170,
+    1180,
+    1190,
+    1200,
+    1210,
+    1220,
+    1230,
+    1240,
+    1250,
+    1260,
+    1270,
+    1280,
+    1290,
+    1300,
+    1310,
+    1320,
+    1330,
+    1340,
+    1350,
+    1360,
+    1370,
+    1380,
+    1390,
+    1400,
+    1410,
+    1420,
+    1430,
+    1440,
+    1450,
+    1460,
+    1470,
+    1480,
+    1490,
+    1500,
+    1510,
+    1520,
+    1530,
+    1540,
+    1550,
+    1560,
+    1570,
+    1580,
+    1590,
+    1600,
+    1610,
+    1620,
+    1630,
+    1640,
+    1650,
+    1660,
+    1670,
+    1680,
+    1690,
+    1700,
+    1710,
+    1720,
+    1730,
+    1740,
+    1750,
+    1760,
+    1770,
+    1780,
+    1790,
+    1800,
+    1810,
+    1820,
+    1830,
+    1840,
+    1850,
+    1860,
+    1870,
+    1880,
+    1890,
+    1900,
+    1910,
+    1920,
+    1930,
+    1940,
+    1950,
+    1960,
+    1970,
+    1980,
+    1990,
+    2000,
+    2010,
+    2020,
+    2030,
+    2040,
+    2050,
+    2060,
+    2070,
+    2080,
+    2090,
+    2100,
+    2110,
+    2120,
+    2130,
+    2140,
+    2150,
+    2160,
+    2170,
+    2180,
+    2190,
+    2200,
+    2210,
+    2220,
+    2230,
+    2240,
+    2250,
+    2260,
+    2270,
+    2280,
+    2290,
+    2300,
+    2310,
+    2320,
+    2330,
+    2340,
+    2350,
+    2360,
+    2370,
+    2380,
+    2390,
+    2400,
+    2410,
+    2420,
+    2430,
+    2440,
+    2450,
+    2460,
+    2470,
+    2480,
+    2490,
+    2500,
+    2510,
+    2520,
+    2530,
+    2540,
+    2550,
+    2560,
+    2570,
+    2580,
+    2590,
+    2600,
+    2610,
+    2620,
+    2630
+  ],
+  "features": [
+    {
+      "name": "displacement",
+      "type": "float",
+      "data_points": [
+        10,
+        9.956085,
+        9.844659,
+        9.688895,
+        9.504694,
+        9.302948,
+        9.091103,
+        8.874231,
+        8.655778,
+        8.438063,
+        8.222635,
+        8.010515,
+        7.802359,
+        7.598574,
+        7.399398,
+        7.204951,
+        7.015275,
+        6.83036,
+        6.6501584,
+        6.474601,
+        6.3036017,
+        6.1370664,
+        5.9748945,
+        5.8169837,
+        5.663229,
+        5.5135264,
+        5.367773,
+        5.2258673,
+        5.0877094,
+        4.9532013,
+        4.8222475,
+        4.6947546,
+        4.5706315,
+        4.4497895,
+        4.332142,
+        4.2176046,
+        4.1060953,
+        3.997534,
+        3.891843,
+        3.7889464,
+        3.68877,
+        3.5912423,
+        3.496293,
+        3.4038541,
+        3.3138592,
+        3.2262437,
+        3.1409447,
+        3.057901,
+        2.9770527,
+        2.8983421,
+        2.8217125,
+        2.747109,
+        2.6744778,
+        2.603767,
+        2.5349257,
+        2.4679046,
+        2.4026554,
+        2.3391314,
+        2.2772868,
+        2.2170773,
+        2.1584597,
+        2.1013918,
+        2.0458329,
+        1.9917428,
+        1.939083,
+        1.8878154,
+        1.8379031,
+        1.7893106,
+        1.7420027,
+        1.6959457,
+        1.6511065,
+        1.6074526,
+        1.564953,
+        1.523577,
+        1.483295,
+        1.444078,
+        1.4058979,
+        1.3687272,
+        1.3325393,
+        1.2973082,
+        1.2630085,
+        1.2296157,
+        1.1971058,
+        1.1654553,
+        1.1346418,
+        1.1046429,
+        1.0754371,
+        1.0470035,
+        1.0193217,
+        0.99237174,
+        0.9661343,
+        0.94059056,
+        0.9157222,
+        0.8915113,
+        0.86794055,
+        0.84499294,
+        0.82265204,
+        0.80090183,
+        0.7797267,
+        0.7591114,
+        0.73904115,
+        0.71950155,
+        0.70047855,
+        0.6819585,
+        0.6639281,
+        0.6463744,
+        0.62928486,
+        0.6126471,
+        0.59644926,
+        0.58067966,
+        0.565327,
+        0.55038023,
+        0.53582865,
+        0.5216618,
+        0.50786954,
+        0.49444193,
+        0.48136932,
+        0.46864232,
+        0.45625183,
+        0.44418892,
+        0.43244496,
+        0.4210115,
+        0.40988034,
+        0.39904347,
+        0.38849312,
+        0.3782217,
+        0.36822185,
+        0.35848638,
+        0.34900832,
+        0.33978084,
+        0.33079734,
+        0.32205135,
+        0.31353658,
+        0.30524695,
+        0.29717648,
+        0.2893194,
+        0.28167003,
+        0.27422294,
+        0.26697272,
+        0.2599142,
+        0.25304228,
+        0.24635206,
+        0.23983873,
+        0.2334976,
+        0.22732413,
+        0.22131388,
+        0.21546254,
+        0.2097659,
+        0.20421988,
+        0.19882049,
+        0.19356385,
+        0.1884462,
+        0.18346384,
+        0.17861322,
+        0.17389084,
+        0.16929333,
+        0.16481736,
+        0.16045974,
+        0.15621732,
+        0.15208708,
+        0.14806603,
+        0.1441513,
+        0.14034006,
+        0.1366296,
+        0.13301723,
+        0.12950037,
+        0.1260765,
+        0.12274315,
+        0.11949793,
+        0.116338514,
+        0.11326262,
+        0.11026806,
+        0.10735267,
+        0.10451435,
+        0.10175108,
+        0.09906087,
+        0.09644179,
+        0.093891956,
+        0.091409534,
+        0.088992745,
+        0.08663985,
+        0.08434917,
+        0.082119055,
+        0.0799479,
+        0.077834144,
+        0.07577628,
+        0.07377282,
+        0.07182233,
+        0.06992341,
+        0.068074696,
+        0.06627486,
+        0.06452261,
+        0.06281669,
+        0.06115587,
+        0.059538964,
+        0.057964806,
+        0.056432266,
+        0.054940246,
+        0.053487673,
+        0.052073505,
+        0.050696727,
+        0.04935635,
+        0.04805141,
+        0.046780974,
+        0.045544125,
+        0.044339977,
+        0.043167666,
+        0.042026352,
+        0.040915214,
+        0.039833453,
+        0.03878029,
+        0.037754975,
+        0.036756765,
+        0.03578495,
+        0.034838825,
+        0.033917718,
+        0.033020962,
+        0.032147918,
+        0.031297956,
+        0.030470464,
+        0.029664852,
+        0.028880538,
+        0.028116962,
+        0.027373575,
+        0.026649842,
+        0.025945244,
+        0.025259275,
+        0.024591442,
+        0.023941265,
+        0.023308279,
+        0.022692028,
+        0.02209207,
+        0.021507975,
+        0.020939322,
+        0.020385705,
+        0.019846724,
+        0.019321995,
+        0.018811138,
+        0.018313788,
+        0.017829588,
+        0.01735819,
+        0.016899254,
+        0.016452452,
+        0.016017463,
+        0.015593976,
+        0.015181685,
+        0.014780294,
+        0.014389516,
+        0.01400907,
+        0.013638682,
+        0.013278087,
+        0.012927026,
+        0.012585246,
+        0.012252503,
+        0.011928557,
+        0.011613177,
+        0.011306135,
+        0.011007211,
+        0.010716191,
+        0.010432864,
+        0.010157028,
+        0.009888485,
+        0.009627042,
+        0.009372512
+      ]
+    },
+    {
+      "name": "velocity",
+      "type": "float",
+      "data_points": [
+        0,
+        -8.228306,
+        -13.676142,
+        -17.215311,
+        -19.445917,
+        -20.780996,
+        -21.504791,
+        -21.812872,
+        -21.839752,
+        -21.677917,
+        -21.390915,
+        -21.022373,
+        -20.602211,
+        -20.150906,
+        -19.68244,
+        -19.206331,
+        -18.72902,
+        -18.254831,
+        -17.786642,
+        -17.32633,
+        -16.875088,
+        -16.433643,
+        -16.0024,
+        -15.581547,
+        -15.171124,
+        -14.771073,
+        -14.3812685,
+        -14.001543,
+        -13.6317005,
+        -13.271528,
+        -12.920805,
+        -12.579304,
+        -12.246796,
+        -11.923055,
+        -11.607857,
+        -11.300981,
+        -11.00221,
+        -10.711333,
+        -10.4281435,
+        -10.152438,
+        -9.884021,
+        -9.622699,
+        -9.368285,
+        -9.120597,
+        -8.879457,
+        -8.644693,
+        -8.416136,
+        -8.193621,
+        -7.976989,
+        -7.766084,
+        -7.5607557,
+        -7.360856,
+        -7.1662416,
+        -6.9767723,
+        -6.7923126,
+        -6.61273,
+        -6.4378953,
+        -6.267683,
+        -6.101971,
+        -5.9406404,
+        -5.783575,
+        -5.6306624,
+        -5.4817924,
+        -5.3368587,
+        -5.195757,
+        -5.058386,
+        -4.924647,
+        -4.7944436,
+        -4.6676826,
+        -4.544273,
+        -4.424126,
+        -4.307156,
+        -4.193279,
+        -4.0824122,
+        -3.9744768,
+        -3.8693953,
+        -3.7670918,
+        -3.667493,
+        -3.570528,
+        -3.4761264,
+        -3.3842208,
+        -3.294745,
+        -3.207635,
+        -3.122828,
+        -3.0402632,
+        -2.9598813,
+        -2.8816247,
+        -2.805437,
+        -2.7312639,
+        -2.6590517,
+        -2.5887487,
+        -2.5203047,
+        -2.45367,
+        -2.3887973,
+        -2.3256397,
+        -2.2641518,
+        -2.2042897,
+        -2.1460102,
+        -2.0892715,
+        -2.034033,
+        -1.980255,
+        -1.9278988,
+        -1.8769268,
+        -1.8273025,
+        -1.7789901,
+        -1.7319552,
+        -1.6861638,
+        -1.6415831,
+        -1.598181,
+        -1.5559264,
+        -1.5147891,
+        -1.4747394,
+        -1.4357486,
+        -1.3977886,
+        -1.3608323,
+        -1.3248532,
+        -1.2898252,
+        -1.2557234,
+        -1.2225231,
+        -1.1902007,
+        -1.1587328,
+        -1.1280969,
+        -1.098271,
+        -1.0692337,
+        -1.0409641,
+        -1.0134419,
+        -0.9866474,
+        -0.96056134,
+        -0.9351649,
+        -0.91044,
+        -0.8863688,
+        -0.862934,
+        -0.84011877,
+        -0.81790674,
+        -0.796282,
+        -0.775229,
+        -0.7547326,
+        -0.7347781,
+        -0.7153512,
+        -0.69643795,
+        -0.67802477,
+        -0.6600984,
+        -0.64264596,
+        -0.62565494,
+        -0.60911316,
+        -0.59300876,
+        -0.5773301,
+        -0.562066,
+        -0.5472055,
+        -0.53273785,
+        -0.51865274,
+        -0.50494003,
+        -0.49158987,
+        -0.47859266,
+        -0.4659391,
+        -0.45362008,
+        -0.44162676,
+        -0.42995054,
+        -0.41858304,
+        -0.40751606,
+        -0.39674172,
+        -0.38625222,
+        -0.37604007,
+        -0.3660979,
+        -0.35641858,
+        -0.34699517,
+        -0.33782095,
+        -0.32888928,
+        -0.32019374,
+        -0.3117281,
+        -0.3034863,
+        -0.29546237,
+        -0.28765061,
+        -0.2800454,
+        -0.27264124,
+        -0.26543283,
+        -0.258415,
+        -0.25158274,
+        -0.24493112,
+        -0.23845536,
+        -0.23215081,
+        -0.22601293,
+        -0.22003734,
+        -0.21421975,
+        -0.20855597,
+        -0.20304193,
+        -0.19767368,
+        -0.19244736,
+        -0.18735923,
+        -0.1824056,
+        -0.17758296,
+        -0.17288782,
+        -0.16831681,
+        -0.16386665,
+        -0.15953417,
+        -0.15531623,
+        -0.1512098,
+        -0.14721195,
+        -0.1433198,
+        -0.13953055,
+        -0.13584149,
+        -0.13224995,
+        -0.12875338,
+        -0.12534925,
+        -0.12203512,
+        -0.11880862,
+        -0.115667425,
+        -0.112609275,
+        -0.109631985,
+        -0.10673341,
+        -0.103911474,
+        -0.10116415,
+        -0.098489456,
+        -0.09588548,
+        -0.09335035,
+        -0.09088225,
+        -0.0884794,
+        -0.08614008,
+        -0.08386262,
+        -0.08164536,
+        -0.07948673,
+        -0.07738517,
+        -0.075339176,
+        -0.07334727,
+        -0.07140803,
+        -0.06952007,
+        -0.06768202,
+        -0.06589257,
+        -0.06415043,
+        -0.062454347,
+        -0.060803108,
+        -0.059195526,
+        -0.05763045,
+        -0.05610675,
+        -0.054623336,
+        -0.05317914,
+        -0.05177313,
+        -0.050404295,
+        -0.04907165,
+        -0.047774237,
+        -0.04651113,
+        -0.045281414,
+        -0.044084214,
+        -0.042918667,
+        -0.041783933,
+        -0.0406792,
+        -0.03960368,
+        -0.038556594,
+        -0.03753719,
+        -0.03654474,
+        -0.03557853,
+        -0.034637865,
+        -0.03372207,
+        -0.032830484,
+        -0.031962473,
+        -0.031117413,
+        -0.030294696,
+        -0.02949373,
+        -0.028713943,
+        -0.027954772,
+        -0.027215673,
+        -0.026496114,
+        -0.02579558,
+        -0.02511357
+      ]
+    },
+    {
+      "name": "stable",
+      "type": "boolean",
+      "data_points": [
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        true,
+        true
+      ]
+    },
+    {
+      "name": "parameters",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 2
+        }
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/goldens/snapSpring_updatesImmediately_matchesGolden.json b/mechanics/tests/goldens/snapSpring_updatesImmediately_matchesGolden.json
new file mode 100644
index 0000000..a772271
--- /dev/null
+++ b/mechanics/tests/goldens/snapSpring_updatesImmediately_matchesGolden.json
@@ -0,0 +1,54 @@
+{
+  "frame_ids": [
+    0,
+    10,
+    20
+  ],
+  "features": [
+    {
+      "name": "displacement",
+      "type": "float",
+      "data_points": [
+        10,
+        0,
+        0
+      ]
+    },
+    {
+      "name": "velocity",
+      "type": "float",
+      "data_points": [
+        -10,
+        0,
+        0
+      ]
+    },
+    {
+      "name": "stable",
+      "type": "boolean",
+      "data_points": [
+        false,
+        true,
+        true
+      ]
+    },
+    {
+      "name": "parameters",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        },
+        {
+          "stiffness": 100000,
+          "dampingRatio": 1
+        }
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/goldens/stiffeningSpring_matchesGolden.json b/mechanics/tests/goldens/stiffeningSpring_matchesGolden.json
new file mode 100644
index 0000000..78ef84e
--- /dev/null
+++ b/mechanics/tests/goldens/stiffeningSpring_matchesGolden.json
@@ -0,0 +1,182 @@
+{
+  "frame_ids": [
+    0,
+    10,
+    20,
+    30,
+    40,
+    50,
+    60,
+    70,
+    80,
+    90,
+    100,
+    110,
+    120,
+    130,
+    140,
+    150,
+    160,
+    170,
+    180
+  ],
+  "features": [
+    {
+      "name": "displacement",
+      "type": "float",
+      "data_points": [
+        10,
+        9.854129,
+        9.603651,
+        9.21957,
+        8.671186,
+        7.931126,
+        6.9840484,
+        5.839193,
+        4.544642,
+        3.1971405,
+        1.936856,
+        0.9162949,
+        0.24406782,
+        -0.070853025,
+        -0.12870777,
+        -0.07792437,
+        -0.02628906,
+        -0.004520869,
+        -0.00013658773
+      ]
+    },
+    {
+      "name": "velocity",
+      "type": "float",
+      "data_points": [
+        -10,
+        -19.059385,
+        -30.821104,
+        -45.60961,
+        -63.405827,
+        -83.52585,
+        -104.22404,
+        -122.36138,
+        -133.45284,
+        -132.56017,
+        -116.37609,
+        -86.074936,
+        -49.053444,
+        -16.799938,
+        1.6967986,
+        6.1317945,
+        3.6371715,
+        1.0193218,
+        0.10724213
+      ]
+    },
+    {
+      "name": "stable",
+      "type": "boolean",
+      "data_points": [
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        true,
+        true
+      ]
+    },
+    {
+      "name": "parameters",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 141.25374,
+          "dampingRatio": 0.335
+        },
+        {
+          "stiffness": 199.52621,
+          "dampingRatio": 0.37
+        },
+        {
+          "stiffness": 281.83835,
+          "dampingRatio": 0.40500003
+        },
+        {
+          "stiffness": 398.10718,
+          "dampingRatio": 0.44
+        },
+        {
+          "stiffness": 562.3414,
+          "dampingRatio": 0.47500002
+        },
+        {
+          "stiffness": 794.3283,
+          "dampingRatio": 0.51
+        },
+        {
+          "stiffness": 1122.0183,
+          "dampingRatio": 0.545
+        },
+        {
+          "stiffness": 1584.8934,
+          "dampingRatio": 0.58000004
+        },
+        {
+          "stiffness": 2238.7207,
+          "dampingRatio": 0.615
+        },
+        {
+          "stiffness": 3162.2776,
+          "dampingRatio": 0.65
+        },
+        {
+          "stiffness": 4466.8364,
+          "dampingRatio": 0.685
+        },
+        {
+          "stiffness": 6309.574,
+          "dampingRatio": 0.72
+        },
+        {
+          "stiffness": 8912.508,
+          "dampingRatio": 0.755
+        },
+        {
+          "stiffness": 12589.254,
+          "dampingRatio": 0.78999996
+        },
+        {
+          "stiffness": 17782.793,
+          "dampingRatio": 0.825
+        },
+        {
+          "stiffness": 25118.865,
+          "dampingRatio": 0.86
+        },
+        {
+          "stiffness": 35481.344,
+          "dampingRatio": 0.89500004
+        },
+        {
+          "stiffness": 50118.715,
+          "dampingRatio": 0.93
+        }
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/goldens/underDamped_matchesGolden.json b/mechanics/tests/goldens/underDamped_matchesGolden.json
new file mode 100644
index 0000000..32413ec
--- /dev/null
+++ b/mechanics/tests/goldens/underDamped_matchesGolden.json
@@ -0,0 +1,1870 @@
+{
+  "frame_ids": [
+    0,
+    10,
+    20,
+    30,
+    40,
+    50,
+    60,
+    70,
+    80,
+    90,
+    100,
+    110,
+    120,
+    130,
+    140,
+    150,
+    160,
+    170,
+    180,
+    190,
+    200,
+    210,
+    220,
+    230,
+    240,
+    250,
+    260,
+    270,
+    280,
+    290,
+    300,
+    310,
+    320,
+    330,
+    340,
+    350,
+    360,
+    370,
+    380,
+    390,
+    400,
+    410,
+    420,
+    430,
+    440,
+    450,
+    460,
+    470,
+    480,
+    490,
+    500,
+    510,
+    520,
+    530,
+    540,
+    550,
+    560,
+    570,
+    580,
+    590,
+    600,
+    610,
+    620,
+    630,
+    640,
+    650,
+    660,
+    670,
+    680,
+    690,
+    700,
+    710,
+    720,
+    730,
+    740,
+    750,
+    760,
+    770,
+    780,
+    790,
+    800,
+    810,
+    820,
+    830,
+    840,
+    850,
+    860,
+    870,
+    880,
+    890,
+    900,
+    910,
+    920,
+    930,
+    940,
+    950,
+    960,
+    970,
+    980,
+    990,
+    1000,
+    1010,
+    1020,
+    1030,
+    1040,
+    1050,
+    1060,
+    1070,
+    1080,
+    1090,
+    1100,
+    1110,
+    1120,
+    1130,
+    1140,
+    1150,
+    1160,
+    1170,
+    1180,
+    1190,
+    1200,
+    1210,
+    1220,
+    1230,
+    1240,
+    1250,
+    1260,
+    1270,
+    1280,
+    1290,
+    1300,
+    1310,
+    1320,
+    1330,
+    1340,
+    1350,
+    1360,
+    1370,
+    1380,
+    1390,
+    1400,
+    1410,
+    1420,
+    1430,
+    1440,
+    1450,
+    1460,
+    1470,
+    1480,
+    1490,
+    1500,
+    1510,
+    1520,
+    1530,
+    1540,
+    1550,
+    1560,
+    1570,
+    1580,
+    1590,
+    1600,
+    1610,
+    1620,
+    1630,
+    1640,
+    1650,
+    1660,
+    1670,
+    1680,
+    1690,
+    1700,
+    1710,
+    1720,
+    1730,
+    1740,
+    1750,
+    1760,
+    1770,
+    1780,
+    1790,
+    1800,
+    1810,
+    1820,
+    1830,
+    1840,
+    1850,
+    1860,
+    1870,
+    1880,
+    1890,
+    1900,
+    1910,
+    1920,
+    1930,
+    1940,
+    1950,
+    1960,
+    1970,
+    1980,
+    1990,
+    2000,
+    2010,
+    2020,
+    2030,
+    2040,
+    2050,
+    2060,
+    2070,
+    2080,
+    2090,
+    2100,
+    2110,
+    2120,
+    2130,
+    2140,
+    2150,
+    2160,
+    2170,
+    2180,
+    2190,
+    2200,
+    2210,
+    2220,
+    2230,
+    2240,
+    2250,
+    2260,
+    2270,
+    2280,
+    2290
+  ],
+  "features": [
+    {
+      "name": "displacement",
+      "type": "float",
+      "data_points": [
+        10,
+        9.951026,
+        9.8084,
+        9.57896,
+        9.269987,
+        8.889109,
+        8.444205,
+        7.9433208,
+        7.3945727,
+        6.80607,
+        6.185835,
+        5.5417304,
+        4.881393,
+        4.2121716,
+        3.5410736,
+        2.8747165,
+        2.2192867,
+        1.5805038,
+        0.9635933,
+        0.3732641,
+        -0.18630688,
+        -0.7114842,
+        -1.1991777,
+        -1.6468408,
+        -2.0524633,
+        -2.4145596,
+        -2.7321532,
+        -3.0047555,
+        -3.2323432,
+        -3.4153304,
+        -3.5545402,
+        -3.6511714,
+        -3.706767,
+        -3.7231774,
+        -3.7025254,
+        -3.6471696,
+        -3.5596678,
+        -3.4427407,
+        -3.2992358,
+        -3.1320927,
+        -2.9443088,
+        -2.738907,
+        -2.5189056,
+        -2.2872882,
+        -2.0469773,
+        -1.8008097,
+        -1.5515139,
+        -1.3016896,
+        -1.0537905,
+        -0.81010836,
+        -0.57276094,
+        -0.34368098,
+        -0.12460864,
+        0.08291435,
+        0.27754804,
+        0.45815554,
+        0.6238022,
+        0.7737528,
+        0.90746725,
+        1.0245943,
+        1.1249641,
+        1.2085791,
+        1.2756041,
+        1.3263553,
+        1.3612883,
+        1.3809854,
+        1.3861428,
+        1.3775574,
+        1.3561126,
+        1.3227652,
+        1.2785319,
+        1.2244756,
+        1.1616926,
+        1.0912999,
+        1.0144233,
+        0.9321859,
+        0.84569746,
+        0.7560443,
+        0.6642802,
+        0.57141787,
+        0.47842193,
+        0.386202,
+        0.29560724,
+        0.20742154,
+        0.12235984,
+        0.04106513,
+        -0.03589359,
+        -0.108022496,
+        -0.17490335,
+        -0.23619318,
+        -0.2916232,
+        -0.34099713,
+        -0.3841888,
+        -0.4211394,
+        -0.45185402,
+        -0.47639796,
+        -0.49489257,
+        -0.5075107,
+        -0.5144723,
+        -0.51603925,
+        -0.5125105,
+        -0.50421697,
+        -0.49151662,
+        -0.47478923,
+        -0.45443153,
+        -0.43085238,
+        -0.40446806,
+        -0.37569776,
+        -0.34495947,
+        -0.31266588,
+        -0.27922073,
+        -0.24501546,
+        -0.21042602,
+        -0.17581023,
+        -0.14150535,
+        -0.10782593,
+        -0.07506216,
+        -0.043478478,
+        -0.013312436,
+        0.015225975,
+        0.041954778,
+        0.06672015,
+        0.08939626,
+        0.109884866,
+        0.12811466,
+        0.14404039,
+        0.15764181,
+        0.16892236,
+        0.17790781,
+        0.18464467,
+        0.18919855,
+        0.19165242,
+        0.19210477,
+        0.19066778,
+        0.18746541,
+        0.18263154,
+        0.17630802,
+        0.16864295,
+        0.1597888,
+        0.14990067,
+        0.13913468,
+        0.12764633,
+        0.11558912,
+        0.10311311,
+        0.09036367,
+        0.07748037,
+        0.064595945,
+        0.05183541,
+        0.0393153,
+        0.02714303,
+        0.01541639,
+        0.0042231516,
+        -0.0063591995,
+        -0.016263612,
+        -0.025433514,
+        -0.033822753,
+        -0.041395433,
+        -0.04812567,
+        -0.053997252,
+        -0.059003245,
+        -0.06314551,
+        -0.066434175,
+        -0.068887055,
+        -0.070529036,
+        -0.07139142,
+        -0.07151124,
+        -0.07093058,
+        -0.06969586,
+        -0.067857146,
+        -0.06546744,
+        -0.06258201,
+        -0.059257705,
+        -0.055552322,
+        -0.051523987,
+        -0.047230575,
+        -0.042729158,
+        -0.038075503,
+        -0.033323605,
+        -0.028525269,
+        -0.023729734,
+        -0.018983342,
+        -0.014329261,
+        -0.00980725,
+        -0.005453472,
+        -0.0013003512,
+        0.0026235213,
+        0.0062934426,
+        0.009688612,
+        0.012792103,
+        0.015590806,
+        0.018075326,
+        0.02023987,
+        0.022082077,
+        0.023602854,
+        0.024806172,
+        0.025698848,
+        0.026290316,
+        0.026592381,
+        0.026618967,
+        0.026385859,
+        0.025910439,
+        0.025211431,
+        0.024308635,
+        0.023222672,
+        0.02197474,
+        0.020586377,
+        0.019079221,
+        0.01747481,
+        0.015794363,
+        0.014058607,
+        0.012287595,
+        0.010500557,
+        0.008715754,
+        0.0069503672,
+        0.005220385,
+        0.0035405224,
+        0.0019241521,
+        0.00038325193,
+        -0.0010716299,
+        -0.0024313936,
+        -0.0036883915,
+        -0.004836418,
+        -0.0058706864,
+        -0.0067877905,
+        -0.0075856596,
+        -0.0082635,
+        -0.008821729,
+        -0.009261897,
+        -0.009586611,
+        -0.009799446
+      ]
+    },
+    {
+      "name": "velocity",
+      "type": "float",
+      "data_points": [
+        0,
+        -9.689744,
+        -18.721231,
+        -27.04521,
+        -34.622158,
+        -41.4221,
+        -47.42434,
+        -52.617123,
+        -56.99723,
+        -60.56951,
+        -63.346367,
+        -65.34719,
+        -66.59777,
+        -67.12967,
+        -66.979576,
+        -66.18867,
+        -64.80193,
+        -62.86752,
+        -60.436077,
+        -57.560135,
+        -54.293465,
+        -50.690502,
+        -46.80577,
+        -42.693356,
+        -38.406395,
+        -33.99663,
+        -29.513977,
+        -25.006151,
+        -20.518335,
+        -16.092886,
+        -11.769089,
+        -7.582956,
+        -3.567066,
+        0.24954945,
+        3.8414824,
+        7.186983,
+        10.26796,
+        13.069937,
+        15.581989,
+        17.79664,
+        19.70973,
+        21.32027,
+        22.630259,
+        23.644495,
+        24.370367,
+        24.817629,
+        24.998167,
+        24.925762,
+        24.615849,
+        24.085262,
+        23.352001,
+        22.434978,
+        21.353788,
+        20.128475,
+        18.779318,
+        17.32661,
+        15.790471,
+        14.190657,
+        12.54639,
+        10.8762045,
+        9.197807,
+        7.527954,
+        5.882341,
+        4.2755146,
+        2.7207994,
+        1.230238,
+        -0.1854506,
+        -1.5168974,
+        -2.7560964,
+        -3.8964016,
+        -4.932514,
+        -5.8604536,
+        -6.6775203,
+        -7.3822474,
+        -7.974343,
+        -8.454623,
+        -8.824943,
+        -9.088114,
+        -9.247824,
+        -9.30855,
+        -9.275467,
+        -9.154358,
+        -8.951525,
+        -8.673694,
+        -8.327926,
+        -7.921531,
+        -7.461982,
+        -6.956829,
+        -6.413628,
+        -5.8398623,
+        -5.2428765,
+        -4.629812,
+        -4.0075502,
+        -3.3826616,
+        -2.7613592,
+        -2.1494596,
+        -1.5523491,
+        -0.97495717,
+        -0.42173502,
+        0.10335989,
+        0.59687334,
+        1.0558584,
+        1.4778748,
+        1.8609827,
+        2.2037325,
+        2.5051508,
+        2.7647214,
+        2.982364,
+        3.1584096,
+        3.2935734,
+        3.3889253,
+        3.4458592,
+        3.4660602,
+        3.4514713,
+        3.4042604,
+        3.3267848,
+        3.2215586,
+        3.091218,
+        2.93849,
+        2.766159,
+        2.5770383,
+        2.3739393,
+        2.1596458,
+        1.936888,
+        1.708319,
+        1.4764937,
+        1.2438502,
+        1.0126922,
+        0.78517485,
+        0.56329256,
+        0.34886897,
+        0.14354916,
+        -0.051205866,
+        -0.23412266,
+        -0.40411672,
+        -0.56029207,
+        -0.70193887,
+        -0.8285295,
+        -0.93971306,
+        -1.0353087,
+        -1.1152971,
+        -1.1798112,
+        -1.2291268,
+        -1.2636507,
+        -1.2839093,
+        -1.290537,
+        -1.2842634,
+        -1.2659005,
+        -1.2363305,
+        -1.1964928,
+        -1.1473718,
+        -1.0899843,
+        -1.0253683,
+        -0.9545714,
+        -0.8786402,
+        -0.7986099,
+        -0.71549547,
+        -0.63028246,
+        -0.5439195,
+        -0.4573111,
+        -0.37131146,
+        -0.28671914,
+        -0.20427254,
+        -0.12464625,
+        -0.048448235,
+        0.023782196,
+        0.09157562,
+        0.15453298,
+        0.21232536,
+        0.26469308,
+        0.3114442,
+        0.3524524,
+        0.38765445,
+        0.41704708,
+        0.44068357,
+        0.4586699,
+        0.4711607,
+        0.47835487,
+        0.48049107,
+        0.47784314,
+        0.47071537,
+        0.4594378,
+        0.44436142,
+        0.42585367,
+        0.4042939,
+        0.38006887,
+        0.35356876,
+        0.32518306,
+        0.29529685,
+        0.26428732,
+        0.23252065,
+        0.20034899,
+        0.1681079,
+        0.1361141,
+        0.10466347,
+        0.07402937,
+        0.04446134,
+        0.016184038,
+        -0.0106034735,
+        -0.03572817,
+        -0.059043236,
+        -0.080427945,
+        -0.09978733,
+        -0.117051594,
+        -0.13217531,
+        -0.14513649,
+        -0.15593536,
+        -0.16459312,
+        -0.17115049,
+        -0.1756662,
+        -0.17821535,
+        -0.17888775,
+        -0.17778617,
+        -0.17502461,
+        -0.17072651,
+        -0.16502303,
+        -0.15805133,
+        -0.14995287,
+        -0.14087182,
+        -0.13095346,
+        -0.12034274,
+        -0.10918287,
+        -0.097614065,
+        -0.085772336,
+        -0.073788404,
+        -0.06178678,
+        -0.049884874,
+        -0.03819231,
+        -0.026810283,
+        -0.015831092
+      ]
+    },
+    {
+      "name": "stable",
+      "type": "boolean",
+      "data_points": [
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        true,
+        true
+      ]
+    },
+    {
+      "name": "parameters",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        }
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/goldens/zeroDisplacement_initialVelocity_matchesGolden.json b/mechanics/tests/goldens/zeroDisplacement_initialVelocity_matchesGolden.json
new file mode 100644
index 0000000..062143b
--- /dev/null
+++ b/mechanics/tests/goldens/zeroDisplacement_initialVelocity_matchesGolden.json
@@ -0,0 +1,1318 @@
+{
+  "frame_ids": [
+    0,
+    10,
+    20,
+    30,
+    40,
+    50,
+    60,
+    70,
+    80,
+    90,
+    100,
+    110,
+    120,
+    130,
+    140,
+    150,
+    160,
+    170,
+    180,
+    190,
+    200,
+    210,
+    220,
+    230,
+    240,
+    250,
+    260,
+    270,
+    280,
+    290,
+    300,
+    310,
+    320,
+    330,
+    340,
+    350,
+    360,
+    370,
+    380,
+    390,
+    400,
+    410,
+    420,
+    430,
+    440,
+    450,
+    460,
+    470,
+    480,
+    490,
+    500,
+    510,
+    520,
+    530,
+    540,
+    550,
+    560,
+    570,
+    580,
+    590,
+    600,
+    610,
+    620,
+    630,
+    640,
+    650,
+    660,
+    670,
+    680,
+    690,
+    700,
+    710,
+    720,
+    730,
+    740,
+    750,
+    760,
+    770,
+    780,
+    790,
+    800,
+    810,
+    820,
+    830,
+    840,
+    850,
+    860,
+    870,
+    880,
+    890,
+    900,
+    910,
+    920,
+    930,
+    940,
+    950,
+    960,
+    970,
+    980,
+    990,
+    1000,
+    1010,
+    1020,
+    1030,
+    1040,
+    1050,
+    1060,
+    1070,
+    1080,
+    1090,
+    1100,
+    1110,
+    1120,
+    1130,
+    1140,
+    1150,
+    1160,
+    1170,
+    1180,
+    1190,
+    1200,
+    1210,
+    1220,
+    1230,
+    1240,
+    1250,
+    1260,
+    1270,
+    1280,
+    1290,
+    1300,
+    1310,
+    1320,
+    1330,
+    1340,
+    1350,
+    1360,
+    1370,
+    1380,
+    1390,
+    1400,
+    1410,
+    1420,
+    1430,
+    1440,
+    1450,
+    1460,
+    1470,
+    1480,
+    1490,
+    1500,
+    1510,
+    1520,
+    1530,
+    1540,
+    1550,
+    1560,
+    1570,
+    1580,
+    1590,
+    1600
+  ],
+  "features": [
+    {
+      "name": "displacement",
+      "type": "float",
+      "data_points": [
+        0,
+        0.09689744,
+        0.18721232,
+        0.2704521,
+        0.3462216,
+        0.41422102,
+        0.4742434,
+        0.52617127,
+        0.56997234,
+        0.6056951,
+        0.6334637,
+        0.6534719,
+        0.66597766,
+        0.6712966,
+        0.6697957,
+        0.66188663,
+        0.6480193,
+        0.62867516,
+        0.60436076,
+        0.57560134,
+        0.54293466,
+        0.506905,
+        0.46805772,
+        0.42693356,
+        0.38406396,
+        0.3399663,
+        0.29513976,
+        0.2500615,
+        0.20518336,
+        0.16092888,
+        0.117690906,
+        0.07582957,
+        0.035670675,
+        -0.0024954774,
+        -0.038414806,
+        -0.07186981,
+        -0.10267957,
+        -0.13069934,
+        -0.15581986,
+        -0.17796637,
+        -0.19709727,
+        -0.21320267,
+        -0.22630256,
+        -0.23644494,
+        -0.24370365,
+        -0.24817626,
+        -0.24998164,
+        -0.2492576,
+        -0.24615847,
+        -0.24085261,
+        -0.23352,
+        -0.22434977,
+        -0.21353786,
+        -0.20128474,
+        -0.18779317,
+        -0.1732661,
+        -0.15790471,
+        -0.14190657,
+        -0.1254639,
+        -0.108762056,
+        -0.09197809,
+        -0.075279556,
+        -0.058823425,
+        -0.042755164,
+        -0.027208013,
+        -0.012302401,
+        0.0018544839,
+        0.015168951,
+        0.027560938,
+        0.038963992,
+        0.049325116,
+        0.05860451,
+        0.06677517,
+        0.073822446,
+        0.0797434,
+        0.08454621,
+        0.08824941,
+        0.09088112,
+        0.09247822,
+        0.09308548,
+        0.09275465,
+        0.09154356,
+        0.08951523,
+        0.08673692,
+        0.083279245,
+        0.0792153,
+        0.07461981,
+        0.069568284,
+        0.064136274,
+        0.05839862,
+        0.05242876,
+        0.046298113,
+        0.040075496,
+        0.033826612,
+        0.02761359,
+        0.021494593,
+        0.015523489,
+        0.009749569,
+        0.0042173467,
+        -0.0010336027,
+        -0.0059687374,
+        -0.010558588,
+        -0.014778752,
+        -0.01860983,
+        -0.022037327,
+        -0.02505151,
+        -0.027647214,
+        -0.029823638,
+        -0.031584095,
+        -0.03293573,
+        -0.03388925,
+        -0.03445859,
+        -0.034660596,
+        -0.03451471,
+        -0.0340426,
+        -0.033267844,
+        -0.03221558,
+        -0.030912176,
+        -0.029384894,
+        -0.027661586,
+        -0.025770377,
+        -0.023739388,
+        -0.021596454,
+        -0.019368876,
+        -0.017083187,
+        -0.014764935,
+        -0.0124385,
+        -0.01012692,
+        -0.007851747,
+        -0.0056329244,
+        -0.003488689,
+        -0.0014354915,
+        0.00051205826,
+        0.0023412257,
+        0.004041166,
+        0.005602919,
+        0.007019386,
+        0.008285292,
+        0.009397129,
+        0.010353085,
+        0.011152968,
+        0.01179811,
+        0.012291266,
+        0.012636503,
+        0.012839089,
+        0.012905367,
+        0.01284263,
+        0.012659001,
+        0.012363302,
+        0.011964925,
+        0.011473714,
+        0.01089984,
+        0.01025368,
+        0.009545711,
+        0.008786398,
+        0.007986096,
+        0.0071549513,
+        0.0063028214,
+        0.005439192,
+        0.0045731086,
+        0.0037131126
+      ]
+    },
+    {
+      "name": "velocity",
+      "type": "float",
+      "data_points": [
+        10,
+        9.369641,
+        8.685126,
+        7.956248,
+        7.1926575,
+        6.4037824,
+        5.598745,
+        4.7862935,
+        3.9747388,
+        3.171899,
+        2.3850527,
+        1.6208987,
+        0.8855264,
+        0.18439122,
+        -0.47770125,
+        -1.0966038,
+        -1.6688296,
+        -2.1915476,
+        -2.6625717,
+        -3.0803442,
+        -3.443915,
+        -3.7529144,
+        -4.007524,
+        -4.208442,
+        -4.356847,
+        -4.454357,
+        -4.5029917,
+        -4.5051246,
+        -4.4634433,
+        -4.3809037,
+        -4.2606854,
+        -4.1061487,
+        -3.920791,
+        -3.7082043,
+        -3.4720364,
+        -3.2159505,
+        -2.9435902,
+        -2.6585445,
+        -2.3643165,
+        -2.0642943,
+        -1.7617248,
+        -1.4596908,
+        -1.16109,
+        -0.8686183,
+        -0.5847551,
+        -0.311752,
+        -0.051623996,
+        0.19385597,
+        0.4231603,
+        0.63500726,
+        0.828359,
+        1.0024176,
+        1.1566185,
+        1.2906227,
+        1.4043069,
+        1.497752,
+        1.5712303,
+        1.625192,
+        1.6602504,
+        1.6771663,
+        1.6768323,
+        1.6602561,
+        1.6285444,
+        1.5828861,
+        1.5245361,
+        1.4547995,
+        1.3750156,
+        1.2865434,
+        1.1907467,
+        1.088981,
+        0.982581,
+        0.8728484,
+        0.76104134,
+        0.648365,
+        0.5359627,
+        0.42490852,
+        0.31620094,
+        0.21075752,
+        0.10941076,
+        0.012904932,
+        -0.078105986,
+        -0.16305938,
+        -0.24148415,
+        -0.31299993,
+        -0.37731555,
+        -0.43422657,
+        -0.48361233,
+        -0.5254321,
+        -0.55972093,
+        -0.58658487,
+        -0.60619575,
+        -0.6187858,
+        -0.6246418,
+        -0.6240991,
+        -0.6175356,
+        -0.6053656,
+        -0.58803356,
+        -0.5660082,
+        -0.53977644,
+        -0.5098377,
+        -0.47669807,
+        -0.44086543,
+        -0.40284407,
+        -0.3631302,
+        -0.32220754,
+        -0.2805433,
+        -0.23858473,
+        -0.19675589,
+        -0.15545486,
+        -0.11505145,
+        -0.0758852,
+        -0.038263895,
+        -0.0024624073,
+        0.03127804,
+        0.06275027,
+        0.09178116,
+        0.11823134,
+        0.1419946,
+        0.16299695,
+        0.1811955,
+        0.19657704,
+        0.20915647,
+        0.21897496,
+        0.22609809,
+        0.23061374,
+        0.23262997,
+        0.23227277,
+        0.22968385,
+        0.22501825,
+        0.21844217,
+        0.21013063,
+        0.20026532,
+        0.18903238,
+        0.17662038,
+        0.16321836,
+        0.14901397,
+        0.13419166,
+        0.11893117,
+        0.103406,
+        0.08778213,
+        0.07221683,
+        0.056857638,
+        0.0418415,
+        0.027294062,
+        0.013329109,
+        4.8148875e-05,
+        -0.0124598555,
+        -0.024118617,
+        -0.034864526,
+        -0.04464653,
+        -0.053425904,
+        -0.06117589,
+        -0.06788128,
+        -0.07353788,
+        -0.078151904,
+        -0.08173932,
+        -0.084325135,
+        -0.08594259,
+        -0.08663239,
+        -0.08644188,
+        -0.08542417
+      ]
+    },
+    {
+      "name": "stable",
+      "type": "boolean",
+      "data_points": [
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        false,
+        true,
+        true
+      ]
+    },
+    {
+      "name": "parameters",
+      "type": "springParameters",
+      "data_points": [
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        },
+        {
+          "stiffness": 100,
+          "dampingRatio": 0.3
+        }
+      ]
+    }
+  ]
+}
\ No newline at end of file
diff --git a/mechanics/tests/src/com/android/mechanics/DistanceGestureContextTest.kt b/mechanics/tests/src/com/android/mechanics/DistanceGestureContextTest.kt
new file mode 100644
index 0000000..4784f9e
--- /dev/null
+++ b/mechanics/tests/src/com/android/mechanics/DistanceGestureContextTest.kt
@@ -0,0 +1,151 @@
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
+package com.android.mechanics
+
+import androidx.test.ext.junit.runners.AndroidJUnit4
+import com.android.mechanics.spec.InputDirection
+import com.google.common.truth.Truth.assertThat
+import kotlin.math.nextDown
+import kotlin.math.nextUp
+import org.junit.Test
+import org.junit.runner.RunWith
+
+@RunWith(AndroidJUnit4::class)
+class DistanceGestureContextTest {
+
+    @Test
+    fun setDistance_maxDirection_increasingInput_keepsDirection() {
+        val underTest =
+            DistanceGestureContext(
+                initialDistance = 0f,
+                initialDirection = InputDirection.Max,
+                directionChangeSlop = 5f,
+            )
+
+        for (value in 0..6) {
+            underTest.distance = value.toFloat()
+            assertThat(underTest.direction).isEqualTo(InputDirection.Max)
+        }
+    }
+
+    @Test
+    fun setDistance_minDirection_decreasingInput_keepsDirection() {
+        val underTest =
+            DistanceGestureContext(
+                initialDistance = 0f,
+                initialDirection = InputDirection.Min,
+                directionChangeSlop = 5f,
+            )
+
+        for (value in 0 downTo -6) {
+            underTest.distance = value.toFloat()
+            assertThat(underTest.direction).isEqualTo(InputDirection.Min)
+        }
+    }
+
+    @Test
+    fun setDistance_maxDirection_decreasingInput_keepsDirection_belowDirectionChangeSlop() {
+        val underTest =
+            DistanceGestureContext(
+                initialDistance = 0f,
+                initialDirection = InputDirection.Max,
+                directionChangeSlop = 5f,
+            )
+
+        underTest.distance = -5f
+        assertThat(underTest.direction).isEqualTo(InputDirection.Max)
+    }
+
+    @Test
+    fun setDistance_maxDirection_decreasingInput_switchesDirection_aboveDirectionChangeSlop() {
+        val underTest =
+            DistanceGestureContext(
+                initialDistance = 0f,
+                initialDirection = InputDirection.Max,
+                directionChangeSlop = 5f,
+            )
+
+        underTest.distance = (-5f).nextDown()
+        assertThat(underTest.direction).isEqualTo(InputDirection.Min)
+    }
+
+    @Test
+    fun setDistance_minDirection_increasingInput_keepsDirection_belowDirectionChangeSlop() {
+        val underTest =
+            DistanceGestureContext(
+                initialDistance = 0f,
+                initialDirection = InputDirection.Min,
+                directionChangeSlop = 5f,
+            )
+
+        underTest.distance = 5f
+        assertThat(underTest.direction).isEqualTo(InputDirection.Min)
+    }
+
+    @Test
+    fun setDistance_minDirection_decreasingInput_switchesDirection_aboveDirectionChangeSlop() {
+        val underTest =
+            DistanceGestureContext(
+                initialDistance = 0f,
+                initialDirection = InputDirection.Min,
+                directionChangeSlop = 5f,
+            )
+
+        underTest.distance = 5f.nextUp()
+        assertThat(underTest.direction).isEqualTo(InputDirection.Max)
+    }
+
+    @Test
+    fun reset_resetsFurthestValue() {
+        val underTest =
+            DistanceGestureContext(
+                initialDistance = 10f,
+                initialDirection = InputDirection.Max,
+                directionChangeSlop = 1f,
+            )
+
+        underTest.reset(5f, direction = InputDirection.Max)
+        assertThat(underTest.direction).isEqualTo(InputDirection.Max)
+        assertThat(underTest.distance).isEqualTo(5f)
+
+        underTest.distance -= 1f
+        assertThat(underTest.direction).isEqualTo(InputDirection.Max)
+        assertThat(underTest.distance).isEqualTo(4f)
+
+        underTest.distance = underTest.distance.nextDown()
+        assertThat(underTest.direction).isEqualTo(InputDirection.Min)
+        assertThat(underTest.distance).isWithin(0.0001f).of(4f)
+    }
+
+    @Test
+    fun setDirectionChangeSlop_smallerThanCurrentDelta_switchesDirection() {
+        val underTest =
+            DistanceGestureContext(
+                initialDistance = 10f,
+                initialDirection = InputDirection.Max,
+                directionChangeSlop = 5f,
+            )
+
+        underTest.distance -= 2f
+        assertThat(underTest.direction).isEqualTo(InputDirection.Max)
+        assertThat(underTest.distance).isEqualTo(8f)
+
+        underTest.directionChangeSlop = 1f
+        assertThat(underTest.direction).isEqualTo(InputDirection.Min)
+        assertThat(underTest.distance).isEqualTo(8f)
+    }
+}
diff --git a/mechanics/tests/src/com/android/mechanics/spec/DirectionalMotionSpecTest.kt b/mechanics/tests/src/com/android/mechanics/spec/DirectionalMotionSpecTest.kt
new file mode 100644
index 0000000..d73f39b
--- /dev/null
+++ b/mechanics/tests/src/com/android/mechanics/spec/DirectionalMotionSpecTest.kt
@@ -0,0 +1,177 @@
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
+package com.android.mechanics.spec
+
+import androidx.test.ext.junit.runners.AndroidJUnit4
+import com.android.mechanics.spring.SpringParameters
+import com.google.common.truth.Truth.assertThat
+import kotlin.math.nextDown
+import kotlin.math.nextUp
+import kotlin.test.assertFailsWith
+import org.junit.Test
+import org.junit.runner.RunWith
+
+@RunWith(AndroidJUnit4::class)
+class DirectionalMotionSpecTest {
+
+    @Test
+    fun noBreakpoints_throws() {
+        assertFailsWith<IllegalArgumentException> {
+            DirectionalMotionSpec(emptyList(), emptyList())
+        }
+    }
+
+    @Test
+    fun wrongSentinelBreakpoints_throws() {
+        val breakpoint1 = Breakpoint(B1, position = 10f, Spring, Guarantee.None)
+        val breakpoint2 = Breakpoint(B2, position = 20f, Spring, Guarantee.None)
+
+        assertFailsWith<IllegalArgumentException> {
+            DirectionalMotionSpec(listOf(breakpoint1, breakpoint2), listOf(Mapping.Identity))
+        }
+    }
+
+    @Test
+    fun tooFewMappings_throws() {
+        assertFailsWith<IllegalArgumentException> {
+            DirectionalMotionSpec(listOf(Breakpoint.minLimit, Breakpoint.maxLimit), emptyList())
+        }
+    }
+
+    @Test
+    fun tooManyMappings_throws() {
+        assertFailsWith<IllegalArgumentException> {
+            DirectionalMotionSpec(
+                listOf(Breakpoint.minLimit, Breakpoint.maxLimit),
+                listOf(Mapping.One, Mapping.Two),
+            )
+        }
+    }
+
+    @Test
+    fun breakpointsOutOfOrder_throws() {
+        val breakpoint1 = Breakpoint(B1, position = 10f, Spring, Guarantee.None)
+        val breakpoint2 = Breakpoint(B2, position = 20f, Spring, Guarantee.None)
+        assertFailsWith<IllegalArgumentException> {
+            DirectionalMotionSpec(
+                listOf(Breakpoint.minLimit, breakpoint2, breakpoint1, Breakpoint.maxLimit),
+                listOf(Mapping.Zero, Mapping.One, Mapping.Two),
+            )
+        }
+    }
+
+    @Test
+    fun findBreakpointIndex_returnsMinForEmptySpec() {
+        val underTest = DirectionalMotionSpec.builder(Spring).complete()
+
+        assertThat(underTest.findBreakpointIndex(0f)).isEqualTo(0)
+        assertThat(underTest.findBreakpointIndex(Float.MAX_VALUE)).isEqualTo(0)
+        assertThat(underTest.findBreakpointIndex(-Float.MAX_VALUE)).isEqualTo(0)
+    }
+
+    @Test
+    fun findBreakpointIndex_throwsForNonFiniteInput() {
+        val underTest = DirectionalMotionSpec.builder(Spring).complete()
+
+        assertFailsWith<IllegalArgumentException> { underTest.findBreakpointIndex(Float.NaN) }
+        assertFailsWith<IllegalArgumentException> {
+            underTest.findBreakpointIndex(Float.NEGATIVE_INFINITY)
+        }
+        assertFailsWith<IllegalArgumentException> {
+            underTest.findBreakpointIndex(Float.POSITIVE_INFINITY)
+        }
+    }
+
+    @Test
+    fun findBreakpointIndex_atBreakpoint_returnsIndex() {
+        val underTest =
+            DirectionalMotionSpec.builder(Spring).toBreakpoint(10f).completeWith(Mapping.Identity)
+
+        assertThat(underTest.findBreakpointIndex(10f)).isEqualTo(1)
+    }
+
+    @Test
+    fun findBreakpointIndex_afterBreakpoint_returnsPreviousIndex() {
+        val underTest =
+            DirectionalMotionSpec.builder(Spring).toBreakpoint(10f).completeWith(Mapping.Identity)
+
+        assertThat(underTest.findBreakpointIndex(10f.nextUp())).isEqualTo(1)
+    }
+
+    @Test
+    fun findBreakpointIndex_beforeBreakpoint_returnsIndex() {
+        val underTest =
+            DirectionalMotionSpec.builder(Spring).toBreakpoint(10f).completeWith(Mapping.Identity)
+
+        assertThat(underTest.findBreakpointIndex(10f.nextDown())).isEqualTo(0)
+    }
+
+    @Test
+    fun findBreakpointIndexByKey_returnsIndex() {
+        val underTest =
+            DirectionalMotionSpec.builder(Spring)
+                .toBreakpoint(10f, key = B1)
+                .completeWith(Mapping.Identity)
+
+        assertThat(underTest.findBreakpointIndex(B1)).isEqualTo(1)
+    }
+
+    @Test
+    fun findBreakpointIndexByKey_unknown_returnsMinusOne() {
+        val underTest =
+            DirectionalMotionSpec.builder(Spring)
+                .toBreakpoint(10f, key = B1)
+                .completeWith(Mapping.Identity)
+
+        assertThat(underTest.findBreakpointIndex(B2)).isEqualTo(-1)
+    }
+
+    @Test
+    fun findSegmentIndex_returnsIndexForSegment_ignoringDirection() {
+        val underTest =
+            DirectionalMotionSpec.builder(Spring)
+                .toBreakpoint(10f, key = B1)
+                .continueWith(Mapping.One)
+                .toBreakpoint(20f, key = B2)
+                .completeWith(Mapping.Identity)
+
+        assertThat(underTest.findSegmentIndex(SegmentKey(B1, B2, InputDirection.Max))).isEqualTo(1)
+        assertThat(underTest.findSegmentIndex(SegmentKey(B1, B2, InputDirection.Min))).isEqualTo(1)
+    }
+
+    @Test
+    fun findSegmentIndex_forInvalidKeys_returnsMinusOne() {
+        val underTest =
+            DirectionalMotionSpec.builder(Spring)
+                .toBreakpoint(10f, key = B1)
+                .continueWith(Mapping.One)
+                .toBreakpoint(20f, key = B2)
+                .continueWith(Mapping.One)
+                .toBreakpoint(30f, key = B3)
+                .completeWith(Mapping.Identity)
+
+        assertThat(underTest.findSegmentIndex(SegmentKey(B2, B1, InputDirection.Max))).isEqualTo(-1)
+        assertThat(underTest.findSegmentIndex(SegmentKey(B1, B3, InputDirection.Max))).isEqualTo(-1)
+    }
+
+    companion object {
+        val B1 = BreakpointKey("one")
+        val B2 = BreakpointKey("two")
+        val B3 = BreakpointKey("three")
+        val Spring = SpringParameters(stiffness = 100f, dampingRatio = 1f)
+    }
+}
diff --git a/mechanics/tests/src/com/android/mechanics/spec/FluentSpecBuilderTest.kt b/mechanics/tests/src/com/android/mechanics/spec/FluentSpecBuilderTest.kt
new file mode 100644
index 0000000..e950bc7
--- /dev/null
+++ b/mechanics/tests/src/com/android/mechanics/spec/FluentSpecBuilderTest.kt
@@ -0,0 +1,253 @@
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
+package com.android.mechanics.spec
+
+import androidx.test.ext.junit.runners.AndroidJUnit4
+import com.android.mechanics.spring.SpringParameters
+import com.android.mechanics.testing.DirectionalMotionSpecSubject.Companion.assertThat
+import org.junit.Test
+import org.junit.runner.RunWith
+
+@RunWith(AndroidJUnit4::class)
+class FluentSpecBuilderTest {
+
+    @Test
+    fun directionalSpec_buildEmptySpec() {
+        val result = DirectionalMotionSpec.builder(Spring).complete()
+
+        assertThat(result).breakpoints().isEmpty()
+        assertThat(result).mappings().containsExactly(Mapping.Identity)
+    }
+
+    @Test
+    fun directionalSpec_buildEmptySpec_inReverse() {
+        val result = DirectionalMotionSpec.reverseBuilder(Spring).complete()
+
+        assertThat(result).breakpoints().isEmpty()
+        assertThat(result).mappings().containsExactly(Mapping.Identity)
+    }
+
+    @Test
+    fun motionSpec_sameSpecInBothDirections() {
+        val result =
+            MotionSpec.builder(Spring, Mapping.Zero)
+                .toBreakpoint(0f, B1)
+                .continueWith(Mapping.One)
+                .toBreakpoint(10f, B2)
+                .completeWith(Mapping.Two)
+
+        assertThat(result.maxDirection).isSameInstanceAs(result.minDirection)
+
+        assertThat(result.minDirection).breakpoints().keys().containsExactly(B1, B2).inOrder()
+        assertThat(result.minDirection)
+            .mappings()
+            .containsExactly(Mapping.Zero, Mapping.One, Mapping.Two)
+            .inOrder()
+    }
+
+    @Test
+    fun directionalSpec_addBreakpointsAndMappings() {
+        val result =
+            DirectionalMotionSpec.builder(Spring, Mapping.Zero)
+                .toBreakpoint(0f, B1)
+                .continueWith(Mapping.One)
+                .toBreakpoint(10f, B2)
+                .completeWith(Mapping.Two)
+
+        assertThat(result).breakpoints().keys().containsExactly(B1, B2).inOrder()
+        assertThat(result).breakpoints().withKey(B1).isAt(0f)
+        assertThat(result).breakpoints().withKey(B2).isAt(10f)
+        assertThat(result)
+            .mappings()
+            .containsExactly(Mapping.Zero, Mapping.One, Mapping.Two)
+            .inOrder()
+    }
+
+    @Test
+    fun directionalSpec_addBreakpointsAndMappings_inReverse() {
+        val result =
+            DirectionalMotionSpec.reverseBuilder(Spring, Mapping.Two)
+                .toBreakpoint(10f, B2)
+                .continueWith(Mapping.One)
+                .toBreakpoint(0f, B1)
+                .completeWith(Mapping.Zero)
+
+        assertThat(result).breakpoints().keys().containsExactly(B1, B2).inOrder()
+        assertThat(result).breakpoints().withKey(B1).isAt(0f)
+        assertThat(result).breakpoints().withKey(B2).isAt(10f)
+        assertThat(result)
+            .mappings()
+            .containsExactly(Mapping.Zero, Mapping.One, Mapping.Two)
+            .inOrder()
+    }
+
+    @Test
+    fun directionalSpec_mappingBuilder_setsDefaultSpring() {
+        val result =
+            DirectionalMotionSpec.builder(Spring)
+                .toBreakpoint(10f)
+                .jumpTo(20f)
+                .continueWithConstantValue()
+                .complete()
+
+        assertThat(result).breakpoints().atPosition(10f).spring().isEqualTo(Spring)
+    }
+
+    @Test
+    fun directionalSpec_mappingBuilder_canOverrideDefaultSpring() {
+        val otherSpring = SpringParameters(stiffness = 10f, dampingRatio = 0.1f)
+        val result =
+            DirectionalMotionSpec.builder(Spring)
+                .toBreakpoint(10f)
+                .jumpTo(20f, spring = otherSpring)
+                .continueWithConstantValue()
+                .complete()
+
+        assertThat(result).breakpoints().atPosition(10f).spring().isEqualTo(otherSpring)
+    }
+
+    @Test
+    fun directionalSpec_mappingBuilder_defaultsToNoGuarantee() {
+        val result =
+            DirectionalMotionSpec.builder(Spring)
+                .toBreakpoint(10f)
+                .jumpTo(20f)
+                .continueWithConstantValue()
+                .complete()
+
+        assertThat(result).breakpoints().atPosition(10f).guarantee().isEqualTo(Guarantee.None)
+    }
+
+    @Test
+    fun directionalSpec_mappingBuilder_canSetGuarantee() {
+        val guarantee = Guarantee.InputDelta(10f)
+        val result =
+            DirectionalMotionSpec.builder(Spring)
+                .toBreakpoint(10f)
+                .jumpTo(20f, guarantee = guarantee)
+                .continueWithConstantValue()
+                .complete()
+
+        assertThat(result).breakpoints().atPosition(10f).guarantee().isEqualTo(guarantee)
+    }
+
+    @Test
+    fun directionalSpec_mappingBuilder_jumpTo_setsAbsoluteValue() {
+        val result =
+            DirectionalMotionSpec.builder(Spring, Mapping.Fixed(99f))
+                .toBreakpoint(10f)
+                .jumpTo(20f)
+                .continueWithConstantValue()
+                .complete()
+
+        assertThat(result).breakpoints().positions().containsExactly(10f)
+        assertThat(result).mappings().atOrAfter(10f).isConstantValue(20f)
+    }
+
+    @Test
+    fun directionalSpec_mappingBuilder_jumpBy_setsRelativeValue() {
+        val result =
+            DirectionalMotionSpec.builder(Spring, Mapping.Linear(factor = 0.5f))
+                .toBreakpoint(10f)
+                .jumpBy(30f)
+                .continueWithConstantValue()
+                .complete()
+
+        assertThat(result).breakpoints().positions().containsExactly(10f)
+        assertThat(result).mappings().atOrAfter(10f).isConstantValue(35f)
+    }
+
+    @Test
+    fun directionalSpec_mappingBuilder_continueWithConstantValue_usesSourceValue() {
+        val result =
+            DirectionalMotionSpec.builder(Spring, Mapping.Linear(factor = 0.5f))
+                .toBreakpoint(5f)
+                .jumpBy(0f)
+                .continueWithConstantValue()
+                .complete()
+
+        assertThat(result).mappings().atOrAfter(5f).isConstantValue(2.5f)
+    }
+
+    @Test
+    fun directionalSpec_mappingBuilder_continueWithFractionalInput_matchesLinearMapping() {
+        val result =
+            DirectionalMotionSpec.builder(Spring)
+                .toBreakpoint(5f)
+                .jumpTo(1f)
+                .continueWithFractionalInput(fraction = .1f)
+                .complete()
+
+        assertThat(result)
+            .mappings()
+            .atOrAfter(5f)
+            .matchesLinearMapping(in1 = 5f, out1 = 1f, in2 = 15f, out2 = 2f)
+    }
+
+    @Test
+    fun directionalSpec_mappingBuilder_reverse_continueWithFractionalInput_matchesLinearMapping() {
+        val result =
+            DirectionalMotionSpec.reverseBuilder(Spring)
+                .toBreakpoint(15f)
+                .jumpTo(2f)
+                .continueWithFractionalInput(fraction = .1f)
+                .complete()
+
+        assertThat(result)
+            .mappings()
+            .atOrAfter(5f)
+            .matchesLinearMapping(in1 = 5f, out1 = 1f, in2 = 15f, out2 = 2f)
+    }
+
+    @Test
+    fun directionalSpec_mappingBuilder_continueWithTargetValue_matchesLinearMapping() {
+        val result =
+            DirectionalMotionSpec.builder(Spring)
+                .toBreakpoint(5f)
+                .jumpTo(1f)
+                .continueWithTargetValue(target = 20f)
+                .toBreakpoint(30f)
+                .completeWith(Mapping.Identity)
+
+        assertThat(result)
+            .mappings()
+            .atOrAfter(5f)
+            .matchesLinearMapping(in1 = 5f, out1 = 1f, in2 = 30f, out2 = 20f)
+    }
+
+    @Test
+    fun directionalSpec_mappingBuilder_reverse_continueWithTargetValue_matchesLinearMapping() {
+        val result =
+            DirectionalMotionSpec.reverseBuilder(Spring)
+                .toBreakpoint(30f)
+                .jumpTo(20f)
+                .continueWithTargetValue(target = 1f)
+                .toBreakpoint(5f)
+                .completeWith(Mapping.Identity)
+
+        assertThat(result)
+            .mappings()
+            .atOrAfter(5f)
+            .matchesLinearMapping(in1 = 5f, out1 = 1f, in2 = 30f, out2 = 20f)
+    }
+
+    companion object {
+        val Spring = SpringParameters(stiffness = 100f, dampingRatio = 1f)
+        val B1 = BreakpointKey("One")
+        val B2 = BreakpointKey("Two")
+    }
+}
diff --git a/mechanics/tests/src/com/android/mechanics/spec/MotionSpecTest.kt b/mechanics/tests/src/com/android/mechanics/spec/MotionSpecTest.kt
new file mode 100644
index 0000000..3254695
--- /dev/null
+++ b/mechanics/tests/src/com/android/mechanics/spec/MotionSpecTest.kt
@@ -0,0 +1,251 @@
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
+package com.android.mechanics.spec
+
+import androidx.test.ext.junit.runners.AndroidJUnit4
+import com.android.mechanics.spring.SpringParameters
+import com.android.mechanics.testing.BreakpointSubject.Companion.assertThat
+import com.google.common.truth.Truth.assertThat
+import org.junit.Test
+import org.junit.runner.RunWith
+
+@RunWith(AndroidJUnit4::class)
+class MotionSpecTest {
+
+    @Test
+    fun containsSegment_unknownSegment_returnsFalse() {
+        val underTest = MotionSpec.builder(Spring).complete()
+        assertThat(underTest.containsSegment(SegmentKey(B1, B2, InputDirection.Max))).isFalse()
+    }
+
+    @Test
+    fun containsSegment_symmetricSpec_knownSegment_returnsTrue() {
+        val underTest =
+            MotionSpec.builder(Spring)
+                .toBreakpoint(10f, key = B1)
+                .continueWith(Mapping.One)
+                .toBreakpoint(20f, key = B2)
+                .completeWith(Mapping.Identity)
+
+        assertThat(underTest.containsSegment(SegmentKey(B1, B2, InputDirection.Max))).isTrue()
+        assertThat(underTest.containsSegment(SegmentKey(B1, B2, InputDirection.Min))).isTrue()
+    }
+
+    @Test
+    fun containsSegment_asymmetricSpec_knownMaxDirectionSegment_trueOnlyInMaxDirection() {
+        val forward =
+            DirectionalMotionSpec.builder(Spring)
+                .toBreakpoint(10f, key = B1)
+                .continueWith(Mapping.One)
+                .toBreakpoint(20f, key = B2)
+                .completeWith(Mapping.Identity)
+        val reverse = DirectionalMotionSpec.builder(Spring).complete()
+
+        val underTest = MotionSpec(forward, reverse)
+
+        assertThat(underTest.containsSegment(SegmentKey(B1, B2, InputDirection.Max))).isTrue()
+        assertThat(underTest.containsSegment(SegmentKey(B1, B2, InputDirection.Min))).isFalse()
+    }
+
+    @Test
+    fun containsSegment_asymmetricSpec_knownMinDirectionSegment_trueOnlyInMinDirection() {
+        val forward = DirectionalMotionSpec.builder(Spring).complete()
+        val reverse =
+            DirectionalMotionSpec.builder(Spring)
+                .toBreakpoint(10f, key = B1)
+                .continueWith(Mapping.One)
+                .toBreakpoint(20f, key = B2)
+                .completeWith(Mapping.Identity)
+
+        val underTest = MotionSpec(forward, reverse)
+
+        assertThat(underTest.containsSegment(SegmentKey(B1, B2, InputDirection.Max))).isFalse()
+        assertThat(underTest.containsSegment(SegmentKey(B1, B2, InputDirection.Min))).isTrue()
+    }
+
+    @Test
+    fun segmentAtInput_emptySpec_maxDirection_segmentDataIsCorrect() {
+        val underTest = MotionSpec.builder(Spring).complete()
+
+        val segmentAtInput = underTest.segmentAtInput(0f, InputDirection.Max)
+
+        assertThat(segmentAtInput.spec).isSameInstanceAs(underTest)
+        assertThat(segmentAtInput.minBreakpoint).isSameInstanceAs(Breakpoint.minLimit)
+        assertThat(segmentAtInput.maxBreakpoint).isSameInstanceAs(Breakpoint.maxLimit)
+        assertThat(segmentAtInput.direction).isEqualTo(InputDirection.Max)
+        assertThat(segmentAtInput.mapping).isEqualTo(Mapping.Identity)
+    }
+
+    @Test
+    fun segmentAtInput_emptySpec_minDirection_segmentDataIsCorrect() {
+        val underTest = MotionSpec.builder(Spring).complete()
+
+        val segmentAtInput = underTest.segmentAtInput(0f, InputDirection.Min)
+
+        assertThat(segmentAtInput.spec).isSameInstanceAs(underTest)
+        assertThat(segmentAtInput.minBreakpoint).isSameInstanceAs(Breakpoint.minLimit)
+        assertThat(segmentAtInput.maxBreakpoint).isSameInstanceAs(Breakpoint.maxLimit)
+        assertThat(segmentAtInput.direction).isEqualTo(InputDirection.Min)
+        assertThat(segmentAtInput.mapping).isEqualTo(Mapping.Identity)
+    }
+
+    @Test
+    fun segmentAtInput_atBreakpointPosition() {
+        val underTest =
+            MotionSpec.builder(Spring)
+                .toBreakpoint(10f, key = B1)
+                .continueWith(Mapping.One)
+                .toBreakpoint(20f, key = B2)
+                .completeWith(Mapping.Identity)
+
+        val segmentAtInput = underTest.segmentAtInput(10f, InputDirection.Max)
+
+        assertThat(segmentAtInput.key).isEqualTo(SegmentKey(B1, B2, InputDirection.Max))
+        assertThat(segmentAtInput.minBreakpoint).isAt(10f)
+        assertThat(segmentAtInput.maxBreakpoint).isAt(20f)
+        assertThat(segmentAtInput.mapping).isEqualTo(Mapping.One)
+    }
+
+    @Test
+    fun segmentAtInput_reverse_atBreakpointPosition() {
+        val underTest =
+            MotionSpec.builder(Spring)
+                .toBreakpoint(10f, key = B1)
+                .continueWith(Mapping.One)
+                .toBreakpoint(20f, key = B2)
+                .completeWith(Mapping.Identity)
+
+        val segmentAtInput = underTest.segmentAtInput(20f, InputDirection.Min)
+
+        assertThat(segmentAtInput.key).isEqualTo(SegmentKey(B1, B2, InputDirection.Min))
+        assertThat(segmentAtInput.minBreakpoint).isAt(10f)
+        assertThat(segmentAtInput.maxBreakpoint).isAt(20f)
+        assertThat(segmentAtInput.mapping).isEqualTo(Mapping.One)
+    }
+
+    @Test
+    fun containsSegment_asymmetricSpec_readsFromIndicatedDirection() {
+        val forward =
+            DirectionalMotionSpec.builder(Spring)
+                .toBreakpoint(10f, key = B1)
+                .continueWith(Mapping.One)
+                .toBreakpoint(20f, key = B2)
+                .completeWith(Mapping.Identity)
+        val reverse =
+            DirectionalMotionSpec.builder(Spring)
+                .toBreakpoint(5f, key = B1)
+                .continueWith(Mapping.Two)
+                .toBreakpoint(25f, key = B2)
+                .completeWith(Mapping.Identity)
+
+        val underTest = MotionSpec(forward, reverse)
+
+        val segmentAtInputMax = underTest.segmentAtInput(15f, InputDirection.Max)
+        assertThat(segmentAtInputMax.key).isEqualTo(SegmentKey(B1, B2, InputDirection.Max))
+        assertThat(segmentAtInputMax.minBreakpoint).isAt(10f)
+        assertThat(segmentAtInputMax.maxBreakpoint).isAt(20f)
+        assertThat(segmentAtInputMax.mapping).isEqualTo(Mapping.One)
+
+        val segmentAtInputMin = underTest.segmentAtInput(15f, InputDirection.Min)
+        assertThat(segmentAtInputMin.key).isEqualTo(SegmentKey(B1, B2, InputDirection.Min))
+        assertThat(segmentAtInputMin.minBreakpoint).isAt(5f)
+        assertThat(segmentAtInputMin.maxBreakpoint).isAt(25f)
+        assertThat(segmentAtInputMin.mapping).isEqualTo(Mapping.Two)
+    }
+
+    @Test
+    fun onSegmentChanged_noHandler_returnsEqualSegmentForSameInput() {
+        val underTest =
+            MotionSpec.builder(Spring)
+                .toBreakpoint(10f, key = B1)
+                .continueWith(Mapping.One)
+                .toBreakpoint(20f, key = B2)
+                .completeWith(Mapping.Identity)
+
+        val segmentAtInput = underTest.segmentAtInput(15f, InputDirection.Max)
+        val onChangedResult = underTest.onChangeSegment(segmentAtInput, 15f, InputDirection.Max)
+        assertThat(segmentAtInput).isEqualTo(onChangedResult)
+    }
+
+    @Test
+    fun onSegmentChanged_noHandler_returnsNewSegmentForNewInput() {
+        val underTest =
+            MotionSpec.builder(Spring)
+                .toBreakpoint(10f, key = B1)
+                .continueWith(Mapping.One)
+                .toBreakpoint(20f, key = B2)
+                .completeWith(Mapping.Identity)
+
+        val segmentAtInput = underTest.segmentAtInput(15f, InputDirection.Max)
+        val onChangedResult = underTest.onChangeSegment(segmentAtInput, 15f, InputDirection.Min)
+        assertThat(segmentAtInput).isNotEqualTo(onChangedResult)
+
+        assertThat(onChangedResult.key).isEqualTo(SegmentKey(B1, B2, InputDirection.Min))
+    }
+
+    @Test
+    fun onSegmentChanged_withHandlerReturningNull_returnsSegmentAtInput() {
+        val underTest =
+            MotionSpec.builder(Spring)
+                .toBreakpoint(10f, key = B1)
+                .continueWith(Mapping.One)
+                .toBreakpoint(20f, key = B2)
+                .completeWith(Mapping.Identity)
+                .copy(
+                    segmentHandlers =
+                        mapOf(SegmentKey(B1, B2, InputDirection.Max) to { _, _, _ -> null })
+                )
+
+        val segmentAtInput = underTest.segmentAtInput(15f, InputDirection.Max)
+        val onChangedResult = underTest.onChangeSegment(segmentAtInput, 15f, InputDirection.Min)
+
+        assertThat(segmentAtInput).isNotEqualTo(onChangedResult)
+        assertThat(onChangedResult.key).isEqualTo(SegmentKey(B1, B2, InputDirection.Min))
+    }
+
+    @Test
+    fun onSegmentChanged_withHandlerReturningSegment_returnsHandlerResult() {
+        val underTest =
+            MotionSpec.builder(Spring)
+                .toBreakpoint(10f, key = B1)
+                .continueWith(Mapping.One)
+                .toBreakpoint(20f, key = B2)
+                .completeWith(Mapping.Identity)
+                .copy(
+                    segmentHandlers =
+                        mapOf(
+                            SegmentKey(B1, B2, InputDirection.Max) to
+                                { _, _, _ ->
+                                    segmentAtInput(0f, InputDirection.Min)
+                                }
+                        )
+                )
+
+        val segmentAtInput = underTest.segmentAtInput(15f, InputDirection.Max)
+        val onChangedResult = underTest.onChangeSegment(segmentAtInput, 15f, InputDirection.Min)
+
+        assertThat(segmentAtInput).isNotEqualTo(onChangedResult)
+        assertThat(onChangedResult.key)
+            .isEqualTo(SegmentKey(Breakpoint.minLimit.key, B1, InputDirection.Min))
+    }
+
+    companion object {
+        val B1 = BreakpointKey("one")
+        val B2 = BreakpointKey("two")
+        val Spring = SpringParameters(stiffness = 100f, dampingRatio = 1f)
+    }
+}
diff --git a/mechanics/tests/src/com/android/mechanics/spec/SegmentTest.kt b/mechanics/tests/src/com/android/mechanics/spec/SegmentTest.kt
new file mode 100644
index 0000000..f66991c
--- /dev/null
+++ b/mechanics/tests/src/com/android/mechanics/spec/SegmentTest.kt
@@ -0,0 +1,106 @@
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
+package com.android.mechanics.spec
+
+import androidx.test.ext.junit.runners.AndroidJUnit4
+import com.android.mechanics.spring.SpringParameters
+import com.google.common.truth.Truth.assertThat
+import com.google.common.truth.Truth.assertWithMessage
+import org.junit.Test
+import org.junit.runner.RunWith
+
+@RunWith(AndroidJUnit4::class)
+class SegmentTest {
+
+    private val fakeSpec = MotionSpec.Empty
+
+    @Test
+    fun segmentData_isValidForInput_betweenBreakpointsSameDirection_isTrue() {
+        val breakpoint1 = Breakpoint(B1, position = 10f, Spring, Guarantee.None)
+        val breakpoint2 = Breakpoint(B2, position = 20f, Spring, Guarantee.None)
+        val underTest =
+            SegmentData(fakeSpec, breakpoint1, breakpoint2, InputDirection.Max, Mapping.Identity)
+
+        assertThat(underTest.isValidForInput(15f, InputDirection.Max)).isTrue()
+    }
+
+    @Test
+    fun segmentData_isValidForInput_betweenBreakpointsOppositeDirection_isFalse() {
+        val breakpoint1 = Breakpoint(B1, position = 10f, Spring, Guarantee.None)
+        val breakpoint2 = Breakpoint(B2, position = 20f, Spring, Guarantee.None)
+        val underTest =
+            SegmentData(fakeSpec, breakpoint1, breakpoint2, InputDirection.Max, Mapping.Identity)
+
+        assertThat(underTest.isValidForInput(15f, InputDirection.Min)).isFalse()
+    }
+
+    @Test
+    fun segmentData_isValidForInput_inMaxDirection_sampledAtVariousPositions_matchesExpectation() {
+        val breakpoint1 = Breakpoint(B1, position = 10f, Spring, Guarantee.None)
+        val breakpoint2 = Breakpoint(B2, position = 20f, Spring, Guarantee.None)
+        val underTest =
+            SegmentData(fakeSpec, breakpoint1, breakpoint2, InputDirection.Max, Mapping.Identity)
+
+        for ((samplePosition, expectedResult) in
+            listOf(5f to true, 10f to true, 15f to true, 20f to false, 25f to false)) {
+            assertWithMessage("at $samplePosition")
+                .that(underTest.isValidForInput(samplePosition, InputDirection.Max))
+                .isEqualTo(expectedResult)
+        }
+    }
+
+    @Test
+    fun segmentData_isValidForInput_inMinDirection_sampledAtVariousPositions_matchesExpectation() {
+        val breakpoint1 = Breakpoint(B1, position = 10f, Spring, Guarantee.None)
+        val breakpoint2 = Breakpoint(B2, position = 20f, Spring, Guarantee.None)
+        val underTest =
+            SegmentData(fakeSpec, breakpoint1, breakpoint2, InputDirection.Min, Mapping.Identity)
+
+        for ((samplePosition, expectedResult) in
+            listOf(5f to false, 10f to false, 15f to true, 20f to true, 25f to true)) {
+            assertWithMessage("at $samplePosition")
+                .that(underTest.isValidForInput(samplePosition, InputDirection.Min))
+                .isEqualTo(expectedResult)
+        }
+    }
+
+    @Test
+    fun segmentData_entryBreakpoint_maxDirection_returnsMinBreakpoint() {
+        val breakpoint1 = Breakpoint(B1, position = 10f, Spring, Guarantee.None)
+        val breakpoint2 = Breakpoint(B2, position = 20f, Spring, Guarantee.None)
+        val underTest =
+            SegmentData(fakeSpec, breakpoint1, breakpoint2, InputDirection.Max, Mapping.Identity)
+
+        assertThat(underTest.entryBreakpoint).isSameInstanceAs(breakpoint1)
+    }
+
+    @Test
+    fun segmentData_entryBreakpoint_minDirection_returnsMaxBreakpoint() {
+        val breakpoint1 = Breakpoint(B1, position = 10f, Spring, Guarantee.None)
+        val breakpoint2 = Breakpoint(B2, position = 20f, Spring, Guarantee.None)
+        val underTest =
+            SegmentData(fakeSpec, breakpoint1, breakpoint2, InputDirection.Min, Mapping.Identity)
+
+        assertThat(underTest.entryBreakpoint).isSameInstanceAs(breakpoint2)
+    }
+
+    companion object {
+        val B1 = BreakpointKey("one")
+        val B2 = BreakpointKey("two")
+        val Spring = SpringParameters(stiffness = 100f, dampingRatio = 1f)
+    }
+}
diff --git a/mechanics/tests/src/com/android/mechanics/spring/ComposeAndMechanicsSpringCompatibilityTest.kt b/mechanics/tests/src/com/android/mechanics/spring/ComposeAndMechanicsSpringCompatibilityTest.kt
new file mode 100644
index 0000000..d06012d
--- /dev/null
+++ b/mechanics/tests/src/com/android/mechanics/spring/ComposeAndMechanicsSpringCompatibilityTest.kt
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
+package com.android.mechanics.spring
+
+import androidx.compose.animation.core.Animatable
+import androidx.compose.animation.core.SpringSpec
+import androidx.compose.ui.test.ExperimentalTestApi
+import androidx.compose.ui.test.TestMonotonicFrameClock
+import androidx.test.ext.junit.runners.AndroidJUnit4
+import com.google.common.truth.Truth.assertThat
+import kotlin.math.abs
+import kotlin.math.max
+import kotlin.math.min
+import kotlinx.coroutines.ExperimentalCoroutinesApi
+import kotlinx.coroutines.test.TestScope
+import kotlinx.coroutines.test.runTest
+import kotlinx.coroutines.withContext
+import org.junit.Test
+import org.junit.runner.RunWith
+
+@OptIn(ExperimentalTestApi::class, ExperimentalCoroutinesApi::class)
+@RunWith(AndroidJUnit4::class)
+class ComposeAndMechanicsSpringCompatibilityTest {
+
+    @Test
+    fun criticallyDamped_matchesComposeSpring() = runTestWithFrameClock {
+        assertMechanicsMatchesComposeSpringMovement(
+            SpringParameters(stiffness = 100f, dampingRatio = 1f)
+        )
+    }
+
+    @Test
+    fun underDamped_matchesComposeSpring() = runTestWithFrameClock {
+        assertMechanicsMatchesComposeSpringMovement(
+            SpringParameters(stiffness = 1000f, dampingRatio = .5f)
+        )
+    }
+
+    @Test
+    fun overDamped_matchesComposeSpring() = runTestWithFrameClock {
+        assertMechanicsMatchesComposeSpringMovement(
+            SpringParameters(stiffness = 2000f, dampingRatio = 1.5f)
+        )
+    }
+
+    @Test
+    fun withInitialVelocity_matchesComposeSpring() = runTestWithFrameClock {
+        assertMechanicsMatchesComposeSpringMovement(
+            SpringParameters(stiffness = 2000f, dampingRatio = .85f),
+            startDisplacement = 0f,
+            initialVelocity = 10f,
+        )
+    }
+
+    private suspend fun assertMechanicsMatchesComposeSpringMovement(
+        parameters: SpringParameters,
+        startDisplacement: Float = 10f,
+        initialVelocity: Float = 0f,
+    ) {
+        val byCompose = computeComposeSpringValues(startDisplacement, initialVelocity, parameters)
+
+        val byMechanics =
+            computeMechanicsSpringValues(startDisplacement, initialVelocity, parameters)
+
+        assertSpringValuesMatch(byMechanics, byCompose)
+    }
+
+    private suspend fun computeComposeSpringValues(
+        displacement: Float,
+        initialVelocity: Float,
+        parameters: SpringParameters,
+    ) = buildList {
+        Animatable(displacement, DisplacementThreshold).animateTo(
+            0f,
+            parameters.asSpringSpec(),
+            initialVelocity,
+        ) {
+            add(SpringState(value, velocity))
+        }
+    }
+
+    private fun computeMechanicsSpringValues(
+        displacement: Float,
+        initialVelocity: Float,
+        parameters: SpringParameters,
+    ) = buildList {
+        var state = SpringState(displacement, initialVelocity)
+        while (!state.isStable(parameters, DisplacementThreshold)) {
+            add(state)
+            state = state.calculateUpdatedState(FrameDelayNanos, parameters)
+        }
+    }
+
+    private fun assertSpringValuesMatch(
+        byMechanics: List<SpringState>,
+        byCompose: List<SpringState>,
+    ) {
+        // Last element by compose is zero displacement, zero velocity
+        assertThat(byCompose.last()).isEqualTo(SpringState.AtRest)
+
+        // Mechanics computes when the spring is stable differently. Allow some variance.
+        assertThat(abs(byMechanics.size - byCompose.size)).isAtMost(2)
+
+        // All frames until either one is considered stable must produce the same displacement
+        // and velocity
+        val maxFramesToExactlyCompare = min(byMechanics.size, byCompose.size - 1)
+        val tolerance = 0.0001f
+        for (i in 0 until maxFramesToExactlyCompare) {
+            val mechanics = byMechanics[i]
+            val compose = byCompose[i]
+            assertThat(mechanics.displacement).isWithin(tolerance).of(compose.displacement)
+            assertThat(mechanics.velocity).isWithin(tolerance).of(compose.velocity)
+        }
+
+        // Afterwards, the displacement must be within displacementThreshold.
+        for (i in maxFramesToExactlyCompare until max(byMechanics.size, byCompose.size)) {
+            val mechanics = byMechanics.elementAtOrNull(i) ?: SpringState.AtRest
+            val compose = byCompose.elementAtOrNull(i) ?: SpringState.AtRest
+            assertThat(mechanics.displacement)
+                .isWithin(DisplacementThreshold)
+                .of(compose.displacement)
+        }
+    }
+
+    private fun SpringParameters.asSpringSpec(): SpringSpec<Float> {
+        return SpringSpec(dampingRatio, stiffness)
+    }
+
+    private fun runTestWithFrameClock(testBody: suspend () -> Unit) = runTest {
+        val testScope: TestScope = this
+        withContext(TestMonotonicFrameClock(testScope, FrameDelayNanos)) { testBody() }
+    }
+
+    companion object {
+        private val FrameDelayNanos: Long = 16_000_000L
+        private val DisplacementThreshold: Float = 0.01f
+    }
+}
diff --git a/mechanics/tests/src/com/android/mechanics/spring/SpringParameterTest.kt b/mechanics/tests/src/com/android/mechanics/spring/SpringParameterTest.kt
new file mode 100644
index 0000000..c8f6c38
--- /dev/null
+++ b/mechanics/tests/src/com/android/mechanics/spring/SpringParameterTest.kt
@@ -0,0 +1,58 @@
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
+package com.android.mechanics.spring
+
+import androidx.test.ext.junit.runners.AndroidJUnit4
+import com.google.common.truth.Truth.assertThat
+import org.junit.Test
+import org.junit.runner.RunWith
+
+@RunWith(AndroidJUnit4::class)
+class SpringParameterTest {
+
+    @Test
+    fun lerp_interpolatesDampingLinearly() {
+        val start = SpringParameters(stiffness = 100f, dampingRatio = 1.5f)
+        val stop = SpringParameters(stiffness = 100f, dampingRatio = 0.5f)
+
+        assertThat(lerp(start, stop, 0f).dampingRatio).isEqualTo(1.5f)
+        assertThat(lerp(start, stop, .25f).dampingRatio).isEqualTo(1.25f)
+        assertThat(lerp(start, stop, .5f).dampingRatio).isEqualTo(1f)
+        assertThat(lerp(start, stop, 1f).dampingRatio).isEqualTo(.5f)
+    }
+
+    @Test
+    fun lerp_interpolatesStiffnessLogarithmically() {
+        val start = SpringParameters(stiffness = 100f, dampingRatio = 1f)
+        val stop = SpringParameters(stiffness = 500_000f, dampingRatio = 1f)
+
+        assertThat(lerp(start, stop, 0f).stiffness).isEqualTo(100f)
+        assertThat(lerp(start, stop, .25f).stiffness).isWithin(1f).of(840f)
+        assertThat(lerp(start, stop, .5f).stiffness).isWithin(1f).of(7_071f)
+        assertThat(lerp(start, stop, .75f).stiffness).isWithin(1f).of(59_460f)
+        assertThat(lerp(start, stop, 1f).stiffness).isEqualTo(500_000f)
+    }
+
+    @Test
+    fun lerp_limitsFraction() {
+        val start = SpringParameters(stiffness = 100f, dampingRatio = 0.5f)
+        val stop = SpringParameters(stiffness = 1000f, dampingRatio = 1.5f)
+
+        assertThat(lerp(start, stop, -1f)).isEqualTo(start)
+        assertThat(lerp(start, stop, +2f)).isEqualTo(stop)
+    }
+}
diff --git a/mechanics/tests/src/com/android/mechanics/spring/SpringStateTest.kt b/mechanics/tests/src/com/android/mechanics/spring/SpringStateTest.kt
new file mode 100644
index 0000000..3bae23c
--- /dev/null
+++ b/mechanics/tests/src/com/android/mechanics/spring/SpringStateTest.kt
@@ -0,0 +1,144 @@
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
+package com.android.mechanics.spring
+
+import android.platform.test.annotations.MotionTest
+import androidx.test.ext.junit.runners.AndroidJUnit4
+import com.android.mechanics.testing.asDataPoint
+import org.junit.Rule
+import org.junit.Test
+import org.junit.runner.RunWith
+import platform.test.motion.MotionTestRule
+import platform.test.motion.RecordedMotion.Companion.create
+import platform.test.motion.golden.DataPoint
+import platform.test.motion.golden.Feature
+import platform.test.motion.golden.FrameId
+import platform.test.motion.golden.TimeSeries
+import platform.test.motion.golden.TimestampFrameId
+import platform.test.motion.golden.asDataPoint
+import platform.test.motion.testing.createGoldenPathManager
+
+@RunWith(AndroidJUnit4::class)
+@MotionTest
+class SpringStateTest {
+    private val goldenPathManager =
+        createGoldenPathManager("frameworks/libs/systemui/mechanics/tests/goldens")
+
+    @get:Rule val motion = MotionTestRule(Unit, goldenPathManager)
+
+    @Test
+    fun criticallyDamped_matchesGolden() {
+        val parameters = SpringParameters(stiffness = 100f, dampingRatio = 1f)
+        val initialState = SpringState(displacement = 10f)
+
+        assertSpringMotionMatchesGolden(initialState) { parameters }
+    }
+
+    @Test
+    fun overDamped_matchesGolden() {
+        val parameters = SpringParameters(stiffness = 100f, dampingRatio = 2f)
+        val initialState = SpringState(displacement = 10f)
+
+        assertSpringMotionMatchesGolden(initialState) { parameters }
+    }
+
+    @Test
+    fun underDamped_matchesGolden() {
+        val parameters = SpringParameters(stiffness = 100f, dampingRatio = .3f)
+        val initialState = SpringState(displacement = 10f)
+
+        assertSpringMotionMatchesGolden(initialState) { parameters }
+    }
+
+    @Test
+    fun zeroDisplacement_initialVelocity_matchesGolden() {
+        val parameters = SpringParameters(stiffness = 100f, dampingRatio = .3f)
+        val initialState = SpringState(displacement = 0f, velocity = 10f)
+
+        assertSpringMotionMatchesGolden(initialState) { parameters }
+    }
+
+    @Test
+    fun snapSpring_updatesImmediately_matchesGolden() {
+        val initialState = SpringState(displacement = 10f, velocity = -10f)
+
+        assertSpringMotionMatchesGolden(initialState) { SpringParameters.Snap }
+    }
+
+    @Test
+    fun stiffeningSpring_matchesGolden() {
+        val parameters = SpringParameters(stiffness = 100f, dampingRatio = .3f)
+        val initialState = SpringState(displacement = 10f, velocity = -10f)
+
+        assertSpringMotionMatchesGolden(initialState) {
+            lerp(parameters, SpringParameters.Snap, it / 200f)
+        }
+    }
+
+    private fun assertSpringMotionMatchesGolden(
+        initialState: SpringState,
+        stableThreshold: Float = 0.01f,
+        sampleFrequencyHz: Float = 100f,
+        springParameters: (timeMillis: Long) -> SpringParameters,
+    ) {
+        val sampleDurationMillis = (1_000f / sampleFrequencyHz).toLong()
+
+        val frameIds = mutableListOf<FrameId>()
+
+        val displacement = mutableListOf<DataPoint<Float>>()
+        val velocity = mutableListOf<DataPoint<Float>>()
+        val isStable = mutableListOf<DataPoint<Boolean>>()
+        val params = mutableListOf<DataPoint<SpringParameters>>()
+
+        var iterationTimeMillis = 0L
+        var keepRecording = 2
+
+        var springState = initialState
+        while (keepRecording > 0 && frameIds.size < 1000) {
+            frameIds.add(TimestampFrameId(iterationTimeMillis))
+
+            val parameters = springParameters(iterationTimeMillis)
+            val currentlyStable = springState.isStable(parameters, stableThreshold)
+            if (currentlyStable) {
+                keepRecording--
+            }
+
+            displacement.add(springState.displacement.asDataPoint())
+            velocity.add(springState.velocity.asDataPoint())
+            isStable.add(currentlyStable.asDataPoint())
+            params.add(parameters.asDataPoint())
+
+            val elapsedNanos = sampleDurationMillis * 1_000_000
+            springState = springState.calculateUpdatedState(elapsedNanos, parameters)
+            iterationTimeMillis += sampleDurationMillis
+        }
+
+        val timeSeries =
+            TimeSeries(
+                frameIds.toList(),
+                listOf(
+                    Feature("displacement", displacement),
+                    Feature("velocity", velocity),
+                    Feature("stable", isStable),
+                    Feature("parameters", params),
+                ),
+            )
+
+        val recordedMotion = motion.create(timeSeries, screenshots = null)
+        motion.assertThat(recordedMotion).timeSeriesMatchesGolden()
+    }
+}
diff --git a/mechanics/tests/src/com/android/mechanics/testing/DataPointTypes.kt b/mechanics/tests/src/com/android/mechanics/testing/DataPointTypes.kt
new file mode 100644
index 0000000..21c2f09
--- /dev/null
+++ b/mechanics/tests/src/com/android/mechanics/testing/DataPointTypes.kt
@@ -0,0 +1,46 @@
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
+package com.android.mechanics.testing
+
+import com.android.mechanics.spring.SpringParameters
+import com.android.mechanics.testing.DataPointTypes.springParameters
+import org.json.JSONObject
+import platform.test.motion.golden.DataPointType
+import platform.test.motion.golden.UnknownTypeException
+
+fun SpringParameters.asDataPoint() = springParameters.makeDataPoint(this)
+
+object DataPointTypes {
+    val springParameters: DataPointType<SpringParameters> =
+        DataPointType(
+            "springParameters",
+            jsonToValue = {
+                with(it as? JSONObject ?: throw UnknownTypeException()) {
+                    SpringParameters(
+                        getDouble("stiffness").toFloat(),
+                        getDouble("dampingRatio").toFloat(),
+                    )
+                }
+            },
+            valueToJson = {
+                JSONObject().apply {
+                    put("stiffness", it.stiffness)
+                    put("dampingRatio", it.dampingRatio)
+                }
+            },
+        )
+}
diff --git a/mechanics/tests/src/com/android/mechanics/testing/MotionSpecSubject.kt b/mechanics/tests/src/com/android/mechanics/testing/MotionSpecSubject.kt
new file mode 100644
index 0000000..1a83e06
--- /dev/null
+++ b/mechanics/tests/src/com/android/mechanics/testing/MotionSpecSubject.kt
@@ -0,0 +1,203 @@
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
+package com.android.mechanics.testing
+
+import com.android.mechanics.spec.Breakpoint
+import com.android.mechanics.spec.BreakpointKey
+import com.android.mechanics.spec.DirectionalMotionSpec
+import com.android.mechanics.spec.Mapping
+import com.android.mechanics.testing.BreakpointSubject.Companion.BreakpointKeys
+import com.android.mechanics.testing.BreakpointSubject.Companion.BreakpointPositions
+import com.google.common.truth.Correspondence
+import com.google.common.truth.FailureMetadata
+import com.google.common.truth.FloatSubject
+import com.google.common.truth.IterableSubject
+import com.google.common.truth.Subject
+import com.google.common.truth.Subject.Factory
+import com.google.common.truth.Truth
+
+/** Subject to verify the definition of a [DirectionalMotionSpec]. */
+class DirectionalMotionSpecSubject
+internal constructor(failureMetadata: FailureMetadata, private val actual: DirectionalMotionSpec?) :
+    Subject(failureMetadata, actual) {
+
+    /** Assert on breakpoints, excluding the implicit start and end breakpoints. */
+    fun breakpoints(): BreakpointsSubject {
+        isNotNull()
+
+        return check("breakpoints").about(BreakpointsSubject.SubjectFactory).that(actual)
+    }
+
+    /** Assert on the mappings. */
+    fun mappings(): MappingsSubject {
+        isNotNull()
+
+        return check("mappings").about(MappingsSubject.SubjectFactory).that(actual)
+    }
+
+    companion object {
+
+        /** Returns a factory to be used with [Truth.assertAbout]. */
+        fun directionalMotionSpec(): Factory<DirectionalMotionSpecSubject, DirectionalMotionSpec> {
+            return Factory { failureMetadata: FailureMetadata, subject: DirectionalMotionSpec? ->
+                DirectionalMotionSpecSubject(failureMetadata, subject)
+            }
+        }
+
+        /** Shortcut for `Truth.assertAbout(directionalMotionSpec()).that(spec)`. */
+        fun assertThat(spec: DirectionalMotionSpec): DirectionalMotionSpecSubject =
+            Truth.assertAbout(directionalMotionSpec()).that(spec)
+    }
+}
+
+/** Subject to assert on the list of breakpoints of a [DirectionalMotionSpec]. */
+class BreakpointsSubject(
+    failureMetadata: FailureMetadata,
+    private val actual: DirectionalMotionSpec?,
+) : IterableSubject(failureMetadata, actual?.breakpoints?.let { it.slice(1 until it.size - 1) }) {
+
+    fun keys() = comparingElementsUsing(BreakpointKeys)
+
+    fun positions() = comparingElementsUsing(BreakpointPositions)
+
+    fun atPosition(position: Float): BreakpointSubject {
+        return check("breakpoint @ $position")
+            .about(BreakpointSubject.SubjectFactory)
+            .that(actual?.breakpoints?.find { it.position == position })
+    }
+
+    fun withKey(key: BreakpointKey): BreakpointSubject {
+        return check("breakpoint with $key]")
+            .about(BreakpointSubject.SubjectFactory)
+            .that(actual?.breakpoints?.find { it.key == key })
+    }
+
+    companion object {
+
+        /** Returns a factory to be used with [Truth.assertAbout]. */
+        val SubjectFactory =
+            Factory<BreakpointsSubject, DirectionalMotionSpec> { failureMetadata, subject ->
+                BreakpointsSubject(failureMetadata, subject)
+            }
+    }
+}
+
+/** Subject to assert on a [Breakpoint] definition. */
+class BreakpointSubject
+internal constructor(failureMetadata: FailureMetadata, private val actual: Breakpoint?) :
+    Subject(failureMetadata, actual) {
+
+    fun exists() {
+        isNotNull()
+    }
+
+    fun key(): Subject {
+        return check("key").that(actual?.key)
+    }
+
+    fun position(): FloatSubject {
+        return check("position").that(actual?.position)
+    }
+
+    fun guarantee(): Subject {
+        return check("guarantee").that(actual?.guarantee)
+    }
+
+    fun spring(): Subject {
+        return check("spring").that(actual?.spring)
+    }
+
+    fun isAt(position: Float) = position().isEqualTo(position)
+
+    fun hasKey(key: BreakpointKey) = key().isEqualTo(key)
+
+    companion object {
+        val BreakpointKeys =
+            Correspondence.transforming<Breakpoint, BreakpointKey>({ it?.key }, "key")
+        val BreakpointPositions =
+            Correspondence.transforming<Breakpoint, Float>({ it?.position }, "position")
+
+        /** Returns a factory to be used with [Truth.assertAbout]. */
+        val SubjectFactory =
+            Factory<BreakpointSubject, Breakpoint> { failureMetadata, subject ->
+                BreakpointSubject(failureMetadata, subject)
+            }
+
+        /** Shortcut for `Truth.assertAbout(subjectFactory).that(breakpoint)`. */
+        fun assertThat(breakpoint: Breakpoint): BreakpointSubject =
+            Truth.assertAbout(SubjectFactory).that(breakpoint)
+    }
+}
+
+/** Subject to assert on the list of mappings of a [DirectionalMotionSpec]. */
+class MappingsSubject(
+    failureMetadata: FailureMetadata,
+    private val actual: DirectionalMotionSpec?,
+) : IterableSubject(failureMetadata, actual?.mappings) {
+
+    /** Assert on the mapping at or after the specified position. */
+    fun atOrAfter(position: Float): MappingSubject {
+        return check("mapping @ $position")
+            .about(MappingSubject.SubjectFactory)
+            .that(actual?.run { mappings[findBreakpointIndex(position)] })
+    }
+
+    companion object {
+        /** Returns a factory to be used with [Truth.assertAbout]. */
+        val SubjectFactory =
+            Factory<MappingsSubject, DirectionalMotionSpec> { failureMetadata, subject ->
+                MappingsSubject(failureMetadata, subject)
+            }
+    }
+}
+
+/** Subject to assert on a [Mapping] function. */
+class MappingSubject
+internal constructor(failureMetadata: FailureMetadata, private val actual: Mapping?) :
+    Subject(failureMetadata, actual) {
+
+    fun matchesLinearMapping(in1: Float, out1: Float, in2: Float, out2: Float) {
+        isNotNull()
+
+        check("input @ $in1").that(actual?.map(in1)).isEqualTo(out1)
+        check("input @ $in2").that(actual?.map(in2)).isEqualTo(out2)
+    }
+
+    fun isConstantValue(value: Float) {
+        when (actual) {
+            is Mapping.Fixed -> check("fixed value").that(actual.value).isEqualTo(value)
+            is Mapping.Linear -> {
+                check("linear factor").that(actual.factor).isZero()
+                check("linear offset").that(actual.offset).isEqualTo(value)
+            }
+
+            else -> failWithActual("Unexpected mapping type", actual)
+        }
+    }
+
+    companion object {
+        /** Returns a factory to be used with [Truth.assertAbout]. */
+        val SubjectFactory =
+            Factory<MappingSubject, Mapping> { failureMetadata, subject ->
+                MappingSubject(failureMetadata, subject)
+            }
+
+        /** Shortcut for `Truth.assertAbout(subjectFactory).that(mapping)`. */
+        fun assertThat(mapping: Mapping): MappingSubject =
+            Truth.assertAbout(SubjectFactory).that(mapping)
+    }
+}
diff --git a/monet/src/com/android/systemui/monet/ColorScheme.java b/monet/src/com/android/systemui/monet/ColorScheme.java
index 61e3d38..7216026 100644
--- a/monet/src/com/android/systemui/monet/ColorScheme.java
+++ b/monet/src/com/android/systemui/monet/ColorScheme.java
@@ -16,6 +16,7 @@
 
 package com.android.systemui.monet;
 
+
 import android.annotation.ColorInt;
 import android.app.WallpaperColors;
 import android.graphics.Color;
@@ -52,17 +53,20 @@ public class ColorScheme {
     @ColorInt
     private final int mSeed;
     private final boolean mIsDark;
-    private final Style mStyle;
+    @Style.Type
+    private final  int mStyle;
     private final DynamicScheme mMaterialScheme;
     private final TonalPalette mAccent1;
     private final TonalPalette mAccent2;
     private final TonalPalette mAccent3;
     private final TonalPalette mNeutral1;
     private final TonalPalette mNeutral2;
+    private final TonalPalette mError;
     private final Hct mProposedSeedHct;
 
 
-    public ColorScheme(@ColorInt int seed, boolean isDark, Style style, double contrastLevel) {
+    public ColorScheme(@ColorInt int seed, boolean isDark, @Style.Type int style,
+            double contrastLevel) {
         this.mSeed = seed;
         this.mIsDark = isDark;
         this.mStyle = style;
@@ -77,17 +81,17 @@ public class ColorScheme {
                                 : seed));
 
         mMaterialScheme = switch (style) {
-            case SPRITZ -> new SchemeNeutral(seedHct, isDark, contrastLevel);
-            case TONAL_SPOT -> new SchemeTonalSpot(seedHct, isDark, contrastLevel);
-            case VIBRANT -> new SchemeVibrant(seedHct, isDark, contrastLevel);
-            case EXPRESSIVE -> new SchemeExpressive(seedHct, isDark, contrastLevel);
-            case RAINBOW -> new SchemeRainbow(seedHct, isDark, contrastLevel);
-            case FRUIT_SALAD -> new SchemeFruitSalad(seedHct, isDark, contrastLevel);
-            case CONTENT -> new SchemeContent(seedHct, isDark, contrastLevel);
-            case MONOCHROMATIC -> new SchemeMonochrome(seedHct, isDark, contrastLevel);
+            case Style.SPRITZ -> new SchemeNeutral(seedHct, isDark, contrastLevel);
+            case Style.TONAL_SPOT -> new SchemeTonalSpot(seedHct, isDark, contrastLevel);
+            case Style.VIBRANT -> new SchemeVibrant(seedHct, isDark, contrastLevel);
+            case Style.EXPRESSIVE -> new SchemeExpressive(seedHct, isDark, contrastLevel);
+            case Style.RAINBOW -> new SchemeRainbow(seedHct, isDark, contrastLevel);
+            case Style.FRUIT_SALAD -> new SchemeFruitSalad(seedHct, isDark, contrastLevel);
+            case Style.CONTENT -> new SchemeContent(seedHct, isDark, contrastLevel);
+            case Style.MONOCHROMATIC -> new SchemeMonochrome(seedHct, isDark, contrastLevel);
             // SystemUI Schemes
-            case CLOCK -> new SchemeClock(seedHct, isDark, contrastLevel);
-            case CLOCK_VIBRANT -> new SchemeClockVibrant(seedHct, isDark, contrastLevel);
+            case Style.CLOCK -> new SchemeClock(seedHct, isDark, contrastLevel);
+            case Style.CLOCK_VIBRANT -> new SchemeClockVibrant(seedHct, isDark, contrastLevel);
             default -> throw new IllegalArgumentException("Unknown style: " + style);
         };
 
@@ -96,17 +100,18 @@ public class ColorScheme {
         mAccent3 = new TonalPalette(mMaterialScheme.tertiaryPalette);
         mNeutral1 = new TonalPalette(mMaterialScheme.neutralPalette);
         mNeutral2 = new TonalPalette(mMaterialScheme.neutralVariantPalette);
+        mError = new TonalPalette(mMaterialScheme.errorPalette);
     }
 
     public ColorScheme(@ColorInt int seed, boolean darkTheme) {
         this(seed, darkTheme, Style.TONAL_SPOT);
     }
 
-    public ColorScheme(@ColorInt int seed, boolean darkTheme, Style style) {
+    public ColorScheme(@ColorInt int seed, boolean darkTheme, @Style.Type int style) {
         this(seed, darkTheme, style, 0.0);
     }
 
-    public ColorScheme(WallpaperColors wallpaperColors, boolean darkTheme, Style style) {
+    public ColorScheme(WallpaperColors wallpaperColors, boolean darkTheme, @Style.Type int style) {
         this(getSeedColor(wallpaperColors, style != Style.CONTENT), darkTheme, style);
     }
 
@@ -134,7 +139,8 @@ public class ColorScheme {
         return mSeed;
     }
 
-    public Style getStyle() {
+    @Style.Type
+    public int getStyle() {
         return mStyle;
     }
 
@@ -162,6 +168,10 @@ public class ColorScheme {
         return mNeutral2;
     }
 
+    public TonalPalette getError() {
+        return mError;
+    }
+
     @Override
     public String toString() {
         return "ColorScheme {\n"
@@ -253,14 +263,14 @@ public class ColorScheme {
         // in the image.
         Map<Integer, Hct> filteredIntToHct = filter
                 ? intToHct
-                    .entrySet()
-                    .stream()
-                    .filter(entry -> {
-                        Hct hct = entry.getValue();
-                        double proportion = intToHueProportion.get(entry.getKey());
-                        return hct.getChroma() >= MIN_CHROMA && proportion > 0.01;
-                    })
-                    .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue))
+                .entrySet()
+                .stream()
+                .filter(entry -> {
+                    Hct hct = entry.getValue();
+                    double proportion = intToHueProportion.get(entry.getKey());
+                    return hct.getChroma() >= MIN_CHROMA && proportion > 0.01;
+                })
+                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue))
                 : intToHct;
         // Sort the colors by score, from high to low.
         List<Map.Entry<Integer, Double>> intToScore = filteredIntToHct.entrySet().stream()
@@ -310,7 +320,7 @@ public class ColorScheme {
      * Filters and ranks colors from WallpaperColors. Defaults Filter to TRUE
      *
      * @param newWallpaperColors Colors extracted from an image via quantization.
-     *                        themes.
+     *                           themes.
      * @return List of ARGB ints, ordered from highest scoring to lowest.
      */
     public static List<Integer> getSeedColors(WallpaperColors newWallpaperColors) {
@@ -350,9 +360,9 @@ public class ColorScheme {
     private static String humanReadable(String paletteName, List<Integer> colors) {
         return paletteName + "\n"
                 + colors
-                    .stream()
-                    .map(ColorScheme::stringForColor)
-                    .collect(Collectors.joining("\n"));
+                .stream()
+                .map(ColorScheme::stringForColor)
+                .collect(Collectors.joining("\n"));
     }
 
     private static double score(Hct hct, double proportion) {
diff --git a/monet/src/com/android/systemui/monet/CustomDynamicColors.java b/monet/src/com/android/systemui/monet/CustomDynamicColors.java
index 9546ce0..77d0f28 100644
--- a/monet/src/com/android/systemui/monet/CustomDynamicColors.java
+++ b/monet/src/com/android/systemui/monet/CustomDynamicColors.java
@@ -22,11 +22,39 @@ import com.google.ux.material.libmonet.dynamiccolor.MaterialDynamicColors;
 import com.google.ux.material.libmonet.dynamiccolor.ToneDeltaPair;
 import com.google.ux.material.libmonet.dynamiccolor.TonePolarity;
 
+import java.util.function.Supplier;
+
 class CustomDynamicColors {
     private final MaterialDynamicColors mMdc;
+    public final Supplier<DynamicColor>[] allColors;
 
     CustomDynamicColors(boolean isExtendedFidelity) {
         this.mMdc = new MaterialDynamicColors(isExtendedFidelity);
+
+        allColors = new Supplier[]{
+                this::widgetBackground,
+                this::clockHour,
+                this::clockMinute,
+                this::clockSecond,
+                this::weatherTemp,
+                this::themeApp,
+                this::onThemeApp,
+                this::themeAppRing,
+                this::themeNotif,
+                this::brandA,
+                this::brandB,
+                this::brandC,
+                this::brandD,
+                this::underSurface,
+                this::shadeActive,
+                this::onShadeActive,
+                this::onShadeActiveVariant,
+                this::shadeInactive,
+                this::onShadeInactive,
+                this::onShadeInactiveVariant,
+                this::shadeDisabled,
+                this::overviewBackground
+        };
     }
 
     // CLOCK COLORS
diff --git a/monet/src/com/android/systemui/monet/DynamicColors.java b/monet/src/com/android/systemui/monet/DynamicColors.java
index 7653e77..b76d3a6 100644
--- a/monet/src/com/android/systemui/monet/DynamicColors.java
+++ b/monet/src/com/android/systemui/monet/DynamicColors.java
@@ -22,7 +22,9 @@ import com.google.ux.material.libmonet.dynamiccolor.DynamicColor;
 import com.google.ux.material.libmonet.dynamiccolor.MaterialDynamicColors;
 
 import java.util.ArrayList;
+import java.util.Comparator;
 import java.util.List;
+import java.util.function.Supplier;
 
 public class DynamicColors {
 
@@ -35,55 +37,60 @@ public class DynamicColors {
     public static List<Pair<String, DynamicColor>> getAllDynamicColorsMapped(
             boolean isExtendedFidelity) {
         MaterialDynamicColors mdc = new MaterialDynamicColors(isExtendedFidelity);
-        List<Pair<String, DynamicColor>> list = new ArrayList<>();
-        list.add(Pair.create("primary_container", mdc.primaryContainer()));
-        list.add(Pair.create("on_primary_container", mdc.onPrimaryContainer()));
-        list.add(Pair.create("primary", mdc.primary()));
-        list.add(Pair.create("on_primary", mdc.onPrimary()));
-        list.add(Pair.create("secondary_container", mdc.secondaryContainer()));
-        list.add(Pair.create("on_secondary_container", mdc.onSecondaryContainer()));
-        list.add(Pair.create("secondary", mdc.secondary()));
-        list.add(Pair.create("on_secondary", mdc.onSecondary()));
-        list.add(Pair.create("tertiary_container", mdc.tertiaryContainer()));
-        list.add(Pair.create("on_tertiary_container", mdc.onTertiaryContainer()));
-        list.add(Pair.create("tertiary", mdc.tertiary()));
-        list.add(Pair.create("on_tertiary", mdc.onTertiary()));
-        list.add(Pair.create("background", mdc.background()));
-        list.add(Pair.create("on_background", mdc.onBackground()));
-        list.add(Pair.create("surface", mdc.surface()));
-        list.add(Pair.create("on_surface", mdc.onSurface()));
-        list.add(Pair.create("surface_container_low", mdc.surfaceContainerLow()));
-        list.add(Pair.create("surface_container_lowest", mdc.surfaceContainerLowest()));
-        list.add(Pair.create("surface_container", mdc.surfaceContainer()));
-        list.add(Pair.create("surface_container_high", mdc.surfaceContainerHigh()));
-        list.add(Pair.create("surface_container_highest", mdc.surfaceContainerHighest()));
-        list.add(Pair.create("surface_bright", mdc.surfaceBright()));
-        list.add(Pair.create("surface_dim", mdc.surfaceDim()));
-        list.add(Pair.create("surface_variant", mdc.surfaceVariant()));
-        list.add(Pair.create("on_surface_variant", mdc.onSurfaceVariant()));
-        list.add(Pair.create("outline", mdc.outline()));
-        list.add(Pair.create("outline_variant", mdc.outlineVariant()));
-        list.add(Pair.create("error", mdc.error()));
-        list.add(Pair.create("on_error", mdc.onError()));
-        list.add(Pair.create("error_container", mdc.errorContainer()));
-        list.add(Pair.create("on_error_container", mdc.onErrorContainer()));
-        list.add(Pair.create("control_activated", mdc.controlActivated()));
-        list.add(Pair.create("control_normal", mdc.controlNormal()));
-        list.add(Pair.create("control_highlight", mdc.controlHighlight()));
-        list.add(Pair.create("text_primary_inverse", mdc.textPrimaryInverse()));
-        list.add(Pair.create("text_secondary_and_tertiary_inverse",
-                mdc.textSecondaryAndTertiaryInverse()));
-        list.add(Pair.create("text_primary_inverse_disable_only",
-                mdc.textPrimaryInverseDisableOnly()));
-        list.add(Pair.create("text_secondary_and_tertiary_inverse_disabled",
-                mdc.textSecondaryAndTertiaryInverseDisabled()));
-        list.add(Pair.create("text_hint_inverse", mdc.textHintInverse()));
-        list.add(Pair.create("palette_key_color_primary", mdc.primaryPaletteKeyColor()));
-        list.add(Pair.create("palette_key_color_secondary", mdc.secondaryPaletteKeyColor()));
-        list.add(Pair.create("palette_key_color_tertiary", mdc.tertiaryPaletteKeyColor()));
-        list.add(Pair.create("palette_key_color_neutral", mdc.neutralPaletteKeyColor()));
-        list.add(Pair.create("palette_key_color_neutral_variant",
-                mdc.neutralVariantPaletteKeyColor()));
+        final Supplier<DynamicColor>[] allColors = new Supplier[]{
+                mdc::primaryPaletteKeyColor,
+                mdc::secondaryPaletteKeyColor,
+                mdc::tertiaryPaletteKeyColor,
+                mdc::neutralPaletteKeyColor,
+                mdc::neutralVariantPaletteKeyColor,
+                mdc::background,
+                mdc::onBackground,
+                mdc::surface,
+                mdc::surfaceDim,
+                mdc::surfaceBright,
+                mdc::surfaceContainerLowest,
+                mdc::surfaceContainerLow,
+                mdc::surfaceContainer,
+                mdc::surfaceContainerHigh,
+                mdc::surfaceContainerHighest,
+                mdc::onSurface,
+                mdc::surfaceVariant,
+                mdc::onSurfaceVariant,
+                mdc::inverseSurface,
+                mdc::inverseOnSurface,
+                mdc::outline,
+                mdc::outlineVariant,
+                mdc::shadow,
+                mdc::scrim,
+                mdc::surfaceTint,
+                mdc::primary,
+                mdc::onPrimary,
+                mdc::primaryContainer,
+                mdc::onPrimaryContainer,
+                mdc::inversePrimary,
+                mdc::secondary,
+                mdc::onSecondary,
+                mdc::secondaryContainer,
+                mdc::onSecondaryContainer,
+                mdc::tertiary,
+                mdc::onTertiary,
+                mdc::tertiaryContainer,
+                mdc::onTertiaryContainer,
+                mdc::error,
+                mdc::onError,
+                mdc::errorContainer,
+                mdc::onErrorContainer,
+                mdc::controlActivated,
+                mdc::controlNormal,
+                mdc::controlHighlight,
+                mdc::textPrimaryInverse,
+                mdc::textSecondaryAndTertiaryInverse,
+                mdc::textPrimaryInverseDisableOnly,
+                mdc::textSecondaryAndTertiaryInverseDisabled,
+                mdc::textHintInverse
+        };
+
+        List<Pair<String, DynamicColor>> list = generateSysUINames(allColors);
         return list;
     }
 
@@ -96,19 +103,23 @@ public class DynamicColors {
     public static List<Pair<String, DynamicColor>> getFixedColorsMapped(
             boolean isExtendedFidelity) {
         MaterialDynamicColors mdc = new MaterialDynamicColors(isExtendedFidelity);
-        List<Pair<String, DynamicColor>> list = new ArrayList<>();
-        list.add(Pair.create("primary_fixed", mdc.primaryFixed()));
-        list.add(Pair.create("primary_fixed_dim", mdc.primaryFixedDim()));
-        list.add(Pair.create("on_primary_fixed", mdc.onPrimaryFixed()));
-        list.add(Pair.create("on_primary_fixed_variant", mdc.onPrimaryFixedVariant()));
-        list.add(Pair.create("secondary_fixed", mdc.secondaryFixed()));
-        list.add(Pair.create("secondary_fixed_dim", mdc.secondaryFixedDim()));
-        list.add(Pair.create("on_secondary_fixed", mdc.onSecondaryFixed()));
-        list.add(Pair.create("on_secondary_fixed_variant", mdc.onSecondaryFixedVariant()));
-        list.add(Pair.create("tertiary_fixed", mdc.tertiaryFixed()));
-        list.add(Pair.create("tertiary_fixed_dim", mdc.tertiaryFixedDim()));
-        list.add(Pair.create("on_tertiary_fixed", mdc.onTertiaryFixed()));
-        list.add(Pair.create("on_tertiary_fixed_variant", mdc.onTertiaryFixedVariant()));
+
+        final Supplier<DynamicColor>[] allColors = new Supplier[]{
+                mdc::primaryFixed,
+                mdc::primaryFixedDim,
+                mdc::onPrimaryFixed,
+                mdc::onPrimaryFixedVariant,
+                mdc::secondaryFixed,
+                mdc::secondaryFixedDim,
+                mdc::onSecondaryFixed,
+                mdc::onSecondaryFixedVariant,
+                mdc::tertiaryFixed,
+                mdc::tertiaryFixedDim,
+                mdc::onTertiaryFixed,
+                mdc::onTertiaryFixedVariant
+        };
+
+        List<Pair<String, DynamicColor>> list = generateSysUINames(allColors);
         return list;
     }
 
@@ -122,29 +133,30 @@ public class DynamicColors {
     public static List<Pair<String, DynamicColor>> getCustomColorsMapped(
             boolean isExtendedFidelity) {
         CustomDynamicColors customMdc = new CustomDynamicColors(isExtendedFidelity);
-        List<Pair<String, DynamicColor>> list = new ArrayList<>();
-        list.add(Pair.create("widget_background", customMdc.widgetBackground()));
-        list.add(Pair.create("clock_hour", customMdc.clockHour()));
-        list.add(Pair.create("clock_minute", customMdc.clockMinute()));
-        list.add(Pair.create("clock_second", customMdc.weatherTemp()));
-        list.add(Pair.create("theme_app", customMdc.themeApp()));
-        list.add(Pair.create("on_theme_app", customMdc.onThemeApp()));
-        list.add(Pair.create("theme_app_ring", customMdc.themeAppRing()));
-        list.add(Pair.create("theme_notif", customMdc.themeNotif()));
-        list.add(Pair.create("brand_a", customMdc.brandA()));
-        list.add(Pair.create("brand_b", customMdc.brandB()));
-        list.add(Pair.create("brand_c", customMdc.brandC()));
-        list.add(Pair.create("brand_d", customMdc.brandD()));
-        list.add(Pair.create("under_surface", customMdc.underSurface()));
-        list.add(Pair.create("shade_active", customMdc.shadeActive()));
-        list.add(Pair.create("on_shade_active", customMdc.onShadeActive()));
-        list.add(Pair.create("on_shade_active_variant", customMdc.onShadeActiveVariant()));
-        list.add(Pair.create("shade_inactive", customMdc.shadeInactive()));
-        list.add(Pair.create("on_shade_inactive", customMdc.onShadeInactive()));
-        list.add(Pair.create("on_shade_inactive_variant", customMdc.onShadeInactiveVariant()));
-        list.add(Pair.create("shade_disabled", customMdc.shadeDisabled()));
-        list.add(Pair.create("overview_background", customMdc.overviewBackground()));
+        List<Pair<String, DynamicColor>> list = generateSysUINames(customMdc.allColors);
         return list;
     }
 
+    private static List<Pair<String, DynamicColor>> generateSysUINames(
+            Supplier<DynamicColor>[] allColors) {
+        List<Pair<String, DynamicColor>> list = new ArrayList<>();
+
+        for (Supplier<DynamicColor> supplier : allColors) {
+            DynamicColor dynamicColor = supplier.get();
+            String name = dynamicColor.name;
+
+            // Fix tokens containing `palette_key_color` for SysUI requirements:
+            // In SysUI palette_key_color should come first in the token name;
+            String paletteMark = "palette_key_color";
+            if (name.contains("_" + paletteMark)) {
+                name = paletteMark + "_" + name.replace("_" + paletteMark, "");
+            }
+
+            list.add(new Pair(name, dynamicColor));
+        }
+
+        list.sort(Comparator.comparing(pair -> pair.first));
+        return list;
+    }
 }
+
diff --git a/monet/src/com/android/systemui/monet/Style.java b/monet/src/com/android/systemui/monet/Style.java
index 6efbbb0..ec50b55 100644
--- a/monet/src/com/android/systemui/monet/Style.java
+++ b/monet/src/com/android/systemui/monet/Style.java
@@ -15,15 +15,169 @@
  */
 
 package com.android.systemui.monet;
-public enum Style {
-    SPRITZ,
-    TONAL_SPOT,
-    VIBRANT,
-    EXPRESSIVE,
-    RAINBOW,
-    FRUIT_SALAD,
-    CONTENT,
-    MONOCHROMATIC,
-    CLOCK,
-    CLOCK_VIBRANT
-}
+
+import android.annotation.IntDef;
+import android.annotation.NonNull;
+import android.annotation.Nullable;
+
+import java.lang.annotation.Retention;
+import java.lang.annotation.RetentionPolicy;
+
+/**
+ * A class defining the different styles available for theming.
+ * This class replaces the previous enum implementation for improved performance and compatibility.
+ */
+public final class Style {
+
+    private Style() {
+    }
+
+    /**
+     * @hide
+     */
+    @IntDef({
+            SPRITZ,
+            TONAL_SPOT,
+            VIBRANT,
+            EXPRESSIVE,
+            RAINBOW,
+            FRUIT_SALAD,
+            CONTENT,
+            MONOCHROMATIC,
+            CLOCK,
+            CLOCK_VIBRANT
+    })
+    @Retention(RetentionPolicy.SOURCE)
+    public @interface Type {
+    }
+
+    /**
+     * Represents the SPRITZ style.
+     */
+    public static final int SPRITZ = 0;
+    /**
+     * Represents the TONAL_SPOT style.
+     */
+    public static final int TONAL_SPOT = 1;
+    /**
+     * Represents the VIBRANT style.
+     */
+    public static final int VIBRANT = 2;
+    /**
+     * Represents the EXPRESSIVE style.
+     */
+    public static final int EXPRESSIVE = 3;
+    /**
+     * Represents the RAINBOW style.
+     */
+    public static final int RAINBOW = 4;
+    /**
+     * Represents the FRUIT_SALAD style.
+     */
+    public static final int FRUIT_SALAD = 5;
+    /**
+     * Represents the CONTENT style.
+     */
+    public static final int CONTENT = 6;
+    /**
+     * Represents the MONOCHROMATIC style.
+     */
+    public static final int MONOCHROMATIC = 7;
+    /**
+     * Represents the CLOCK style.
+     */
+    public static final int CLOCK = 8;
+    /**
+     * Represents the CLOCK_VIBRANT style.
+     */
+    public static final int CLOCK_VIBRANT = 9;
+
+
+    /**
+     * Returns the string representation of the given style.
+     *
+     * @param style The style value.
+     * @return The string representation of the style.
+     * @throws IllegalArgumentException if the style value is invalid.
+     */
+    @NonNull
+    public static String toString(@Nullable @Type Integer style) {
+        // Throw an exception if style is null
+        if (style == null) {
+            throw new IllegalArgumentException("Invalid style value: null");
+        }
+
+        return switch (style) {
+            case SPRITZ -> "SPRITZ";
+            case TONAL_SPOT -> "TONAL_SPOT";
+            case VIBRANT -> "VIBRANT";
+            case EXPRESSIVE -> "EXPRESSIVE";
+            case RAINBOW -> "RAINBOW";
+            case FRUIT_SALAD -> "FRUIT_SALAD";
+            case CONTENT -> "CONTENT";
+            case MONOCHROMATIC -> "MONOCHROMATIC";
+            case CLOCK -> "CLOCK";
+            case CLOCK_VIBRANT -> "CLOCK_VIBRANT";
+            default -> throw new IllegalArgumentException("Invalid style value: " + style);
+        };
+    }
+
+    /**
+     * Returns the style value corresponding to the given style name.
+     *
+     * @param styleName The name of the style.
+     * @return The style value.
+     * @throws IllegalArgumentException if the style name is invalid.
+     */
+    public static @Type int valueOf(@Nullable @NonNull String styleName) {
+        if (styleName == null) {
+            throw new IllegalArgumentException("Invalid style value: null");
+        }
+
+        return switch (styleName) {
+            case "SPRITZ" -> SPRITZ;
+            case "TONAL_SPOT" -> TONAL_SPOT;
+            case "VIBRANT" -> VIBRANT;
+            case "EXPRESSIVE" -> EXPRESSIVE;
+            case "RAINBOW" -> RAINBOW;
+            case "FRUIT_SALAD" -> FRUIT_SALAD;
+            case "CONTENT" -> CONTENT;
+            case "MONOCHROMATIC" -> MONOCHROMATIC;
+            case "CLOCK" -> CLOCK;
+            case "CLOCK_VIBRANT" -> CLOCK_VIBRANT;
+            default -> throw new IllegalArgumentException("Invalid style name: " + styleName);
+        };
+    }
+
+    /**
+     * Returns the name of the given style. This method is equivalent to {@link #toString(int)}.
+     *
+     * @param style The style value.
+     * @return The name of the style.
+     */
+    @NonNull
+    public static String name(@Type int style) {
+        return toString(style);
+    }
+
+    /**
+     * Returns an array containing all the style values.
+     *
+     * @return An array of all style values.
+     */
+    public static int[] values() {
+        return new int[]{
+                SPRITZ,
+                TONAL_SPOT,
+                VIBRANT,
+                EXPRESSIVE,
+                RAINBOW,
+                FRUIT_SALAD,
+                CONTENT,
+                MONOCHROMATIC,
+                CLOCK,
+                CLOCK_VIBRANT
+        };
+    }
+
+}
\ No newline at end of file
diff --git a/monet/tests/com/android/systemui/monet/ColorSchemeTest.kt b/monet/tests/com/android/systemui/monet/ColorSchemeTest.kt
index 7cb2ed4..edbe729 100644
--- a/monet/tests/com/android/systemui/monet/ColorSchemeTest.kt
+++ b/monet/tests/com/android/systemui/monet/ColorSchemeTest.kt
@@ -38,6 +38,10 @@ import org.w3c.dom.Document
 import org.w3c.dom.Element
 import org.w3c.dom.Node
 
+private const val CONTRAST = 0.0
+
+private const val IS_FIDELITY_ENABLED = false
+
 private const val fileHeader =
     """
   ~ Copyright (C) 2022 The Android Open Source Project
@@ -97,7 +101,7 @@ class ColorSchemeTest {
             theme.setAttribute("color", sourceColorHex)
             themes.appendChild(theme)
 
-            for (styleValue in Style.entries) {
+            for (styleValue in Style.values()) {
                 if (
                     styleValue == Style.CLOCK ||
                         styleValue == Style.CLOCK_VIBRANT ||
@@ -106,7 +110,7 @@ class ColorSchemeTest {
                     continue
                 }
 
-                val style = document.createElement(styleValue.name.lowercase())
+                val style = document.createElement(Style.name(styleValue).lowercase())
                 val colorScheme = ColorScheme(sourceColor.toInt(), false, styleValue)
 
                 style.appendChild(
@@ -116,7 +120,8 @@ class ColorSchemeTest {
                                 colorScheme.accent2,
                                 colorScheme.accent3,
                                 colorScheme.neutral1,
-                                colorScheme.neutral2
+                                colorScheme.neutral2,
+                                colorScheme.error,
                             )
                             .flatMap { a -> listOf(*a.allShades.toTypedArray()) }
                             .joinToString(",", transform = Int::toRGBHex)
@@ -128,7 +133,7 @@ class ColorSchemeTest {
             hue += 60
         }
 
-        saveFile(document, "current_themes.xml")
+        saveFile(document, "themes.xml")
     }
 
     @Test
@@ -145,11 +150,14 @@ class ColorSchemeTest {
                 Triple("accent2", "Secondary", colorScheme.accent2),
                 Triple("accent3", "Tertiary", colorScheme.accent3),
                 Triple("neutral1", "Neutral", colorScheme.neutral1),
-                Triple("neutral2", "Secondary Neutral", colorScheme.neutral2)
+                Triple("neutral2", "Secondary Neutral", colorScheme.neutral2),
+                Triple("error", "Error", colorScheme.error),
             )
             .forEach {
                 val (paletteName, readable, palette) = it
-                palette.allShadesMapped.entries.forEachIndexed { index, (shade, colorValue) ->
+                palette.allShadesMapped.toSortedMap().entries.forEachIndexed {
+                    index,
+                    (shade, colorValue) ->
                     val comment =
                         when (index) {
                             0 -> commentWhite(readable)
@@ -165,22 +173,145 @@ class ColorSchemeTest {
         // dynamic colors
         arrayOf(false, true).forEach { isDark ->
             val suffix = if (isDark) "_dark" else "_light"
-            val dynamicScheme = SchemeTonalSpot(Hct.fromInt(GOOGLE_BLUE), isDark, 0.5)
-            DynamicColors.getAllDynamicColorsMapped(false).forEach {
+            val dynamicScheme = SchemeTonalSpot(Hct.fromInt(GOOGLE_BLUE), isDark, CONTRAST)
+            DynamicColors.getAllDynamicColorsMapped(IS_FIDELITY_ENABLED).forEach {
                 resources.createColorEntry(
                     "system_${it.first}$suffix",
-                    it.second.getArgb(dynamicScheme)
+                    it.second.getArgb(dynamicScheme),
                 )
             }
         }
 
         // fixed colors
-        val dynamicScheme = SchemeTonalSpot(Hct.fromInt(GOOGLE_BLUE), false, 0.5)
-        DynamicColors.getFixedColorsMapped(false).forEach {
+        val dynamicScheme = SchemeTonalSpot(Hct.fromInt(GOOGLE_BLUE), false, CONTRAST)
+        DynamicColors.getFixedColorsMapped(IS_FIDELITY_ENABLED).forEach {
             resources.createColorEntry("system_${it.first}", it.second.getArgb(dynamicScheme))
         }
 
-        saveFile(document, "role_values.xml")
+        // custom colors
+        arrayOf(false, true).forEach { isDark ->
+            val suffix = if (isDark) "_dark" else "_light"
+            val dynamicScheme = SchemeTonalSpot(Hct.fromInt(GOOGLE_BLUE), isDark, CONTRAST)
+            DynamicColors.getCustomColorsMapped(IS_FIDELITY_ENABLED).forEach {
+                resources.createColorEntry(
+                    "system_${it.first}$suffix",
+                    it.second.getArgb(dynamicScheme),
+                )
+            }
+        }
+
+        saveFile(document, "colors.xml")
+    }
+
+    @Test
+    fun generateSymbols() {
+        val document = buildDoc<Any>()
+
+        val resources = document.createElement("resources")
+        document.appendWithBreak(resources)
+
+        (DynamicColors.getAllDynamicColorsMapped(IS_FIDELITY_ENABLED) +
+                DynamicColors.getFixedColorsMapped(IS_FIDELITY_ENABLED))
+            .forEach {
+                val newName = ("material_color_" + it.first).snakeToLowerCamelCase()
+
+                resources.createEntry(
+                    "java-symbol",
+                    arrayOf(Pair("name", newName), Pair("type", "color")),
+                    null,
+                )
+            }
+
+        DynamicColors.getCustomColorsMapped(IS_FIDELITY_ENABLED).forEach {
+            val newName = ("custom_color_" + it.first).snakeToLowerCamelCase()
+
+            resources.createEntry(
+                "java-symbol",
+                arrayOf(Pair("name", newName), Pair("type", "color")),
+                null,
+            )
+        }
+
+        arrayOf("_light", "_dark").forEach { suffix ->
+            DynamicColors.getCustomColorsMapped(IS_FIDELITY_ENABLED).forEach {
+                val newName = "system_" + it.first + suffix
+
+                resources.createEntry(
+                    "java-symbol",
+                    arrayOf(Pair("name", newName), Pair("type", "color")),
+                    null,
+                )
+            }
+        }
+
+        saveFile(document, "symbols.xml")
+    }
+
+    @Test
+    fun generateDynamicColors() {
+        arrayOf(false, true).forEach { isDark ->
+            val document = buildDoc<Any>()
+
+            val resources = document.createElement("resources")
+            document.appendWithBreak(resources)
+
+            (DynamicColors.getAllDynamicColorsMapped(IS_FIDELITY_ENABLED) +
+                    DynamicColors.getFixedColorsMapped(IS_FIDELITY_ENABLED))
+                .forEach {
+                    val newName = ("material_color_" + it.first).snakeToLowerCamelCase()
+
+                    val suffix = if (isDark) "_dark" else "_light"
+                    val colorValue =
+                        "@color/system_" + it.first + if (it.first.contains("fixed")) "" else suffix
+
+                    resources.createColorEntry(newName, colorValue)
+                }
+
+            val suffix = if (isDark) "_dark" else "_light"
+
+            DynamicColors.getCustomColorsMapped(IS_FIDELITY_ENABLED).forEach {
+                val newName = ("custom_color_" + it.first).snakeToLowerCamelCase()
+                resources.createColorEntry(newName, "@color/system_" + it.first + suffix)
+            }
+
+            saveFile(document, "colors_dynamic_$suffix.xml")
+        }
+    }
+
+    @Test
+    fun generatePublic() {
+        val document = buildDoc<Any>()
+
+        val resources = document.createElement("resources")
+
+        val group = document.createElement("staging-public-group")
+        resources.appendChild(group)
+
+        document.appendWithBreak(resources)
+
+        val context = InstrumentationRegistry.getInstrumentation().targetContext
+        val res = context.resources
+
+        val rClass = com.android.internal.R.color::class.java
+        val existingFields = rClass.declaredFields.map { it.name }.toSet()
+
+        arrayOf("_light", "_dark").forEach { suffix ->
+            DynamicColors.getAllDynamicColorsMapped(IS_FIDELITY_ENABLED).forEach {
+                val name = "system_" + it.first + suffix
+                if (!existingFields.contains(name)) {
+                    group.createEntry("public", arrayOf(Pair("name", name)), null)
+                }
+            }
+        }
+
+        DynamicColors.getFixedColorsMapped(IS_FIDELITY_ENABLED).forEach {
+            val name = "system_${it.first}"
+            if (!existingFields.contains(name)) {
+                group.createEntry("public", arrayOf(Pair("name", name)), null)
+            }
+        }
+
+        saveFile(document, "public.xml")
     }
 
     // Helper Functions
@@ -225,17 +356,33 @@ class ColorSchemeTest {
 }
 
 private fun Element.createColorEntry(name: String, value: Int, comment: String? = null) {
+    this.createColorEntry(name, "#" + value.toRGBHex(), comment)
+}
+
+private fun Element.createColorEntry(name: String, value: String, comment: String? = null) {
+    this.createEntry("color", arrayOf(Pair("name", name)), value, comment)
+}
+
+private fun Element.createEntry(
+    tagName: String,
+    attrs: Array<Pair<String, String>>,
+    value: String?,
+    comment: String? = null,
+) {
     val doc = this.ownerDocument
 
     if (comment != null) {
         this.appendChild(doc.createComment(comment))
     }
 
-    val color = doc.createElement("color")
-    this.appendChild(color)
+    val child = doc.createElement(tagName)
+    this.appendChild(child)
 
-    color.setAttribute("name", name)
-    color.appendChild(doc.createTextNode("#" + value.toRGBHex()))
+    attrs.forEach { child.setAttribute(it.first, it.second) }
+
+    if (value !== null) {
+        child.appendChild(doc.createTextNode(value))
+    }
 }
 
 private fun Node.appendWithBreak(child: Node, lineBreaks: Int = 1): Node {
@@ -248,3 +395,8 @@ private fun Node.appendWithBreak(child: Node, lineBreaks: Int = 1): Node {
 private fun Int.toRGBHex(): String {
     return "%06X".format(0xFFFFFF and this)
 }
+
+private fun String.snakeToLowerCamelCase(): String {
+    val pattern = "_[a-z]".toRegex()
+    return replace(pattern) { it.value.last().uppercase() }
+}
diff --git a/msdllib/Android.bp b/msdllib/Android.bp
index 920ed17..6fe3628 100644
--- a/msdllib/Android.bp
+++ b/msdllib/Android.bp
@@ -21,7 +21,7 @@ android_library {
     name: "msdl",
     manifest: "AndroidManifest.xml",
     sdk_version: "system_current",
-    min_sdk_version: "33",
+    min_sdk_version: "31",
     static_libs: [
         "kotlinx_coroutines_android",
         "androidx.annotation_annotation",
diff --git a/msdllib/src/com/google/android/msdl/data/model/HapticToken.kt b/msdllib/src/com/google/android/msdl/data/model/HapticToken.kt
index 98be02d..8f65738 100644
--- a/msdllib/src/com/google/android/msdl/data/model/HapticToken.kt
+++ b/msdllib/src/com/google/android/msdl/data/model/HapticToken.kt
@@ -30,7 +30,8 @@ enum class HapticToken {
     TAP_HIGH_EMPHASIS,
     TAP_MEDIUM_EMPHASIS,
     DRAG_THRESHOLD_INDICATOR,
-    DRAG_INDICATOR,
+    DRAG_INDICATOR_CONTINUOUS,
+    DRAG_INDICATOR_DISCRETE,
     TAP_LOW_EMPHASIS,
     KEYPRESS_STANDARD,
     KEYPRESS_SPACEBAR,
diff --git a/msdllib/src/com/google/android/msdl/data/model/MSDLToken.kt b/msdllib/src/com/google/android/msdl/data/model/MSDLToken.kt
index 99e6d00..8779526 100644
--- a/msdllib/src/com/google/android/msdl/data/model/MSDLToken.kt
+++ b/msdllib/src/com/google/android/msdl/data/model/MSDLToken.kt
@@ -41,11 +41,7 @@ enum class MSDLToken(
         FeedbackLevel.MINIMAL,
     ),
     /* Inform the user that an ongoing activity has started */
-    START(
-        HapticToken.NEUTRAL_CONFIRMATION_HIGH_EMPHASIS,
-        SoundToken.START,
-        FeedbackLevel.DEFAULT,
-    ),
+    START(HapticToken.NEUTRAL_CONFIRMATION_HIGH_EMPHASIS, SoundToken.START, FeedbackLevel.DEFAULT),
     /* Inform the user that an ongoing activity has paused */
     PAUSE(
         HapticToken.NEUTRAL_CONFIRMATION_MEDIUM_EMPHASIS,
@@ -53,11 +49,7 @@ enum class MSDLToken(
         FeedbackLevel.DEFAULT,
     ),
     /* Inform the user that their previously started activity has stopped SUCCESSFULLY */
-    STOP(
-        HapticToken.POSITIVE_CONFIRMATION_MEDIUM_EMPHASIS,
-        SoundToken.STOP,
-        FeedbackLevel.DEFAULT,
-    ),
+    STOP(HapticToken.POSITIVE_CONFIRMATION_MEDIUM_EMPHASIS, SoundToken.STOP, FeedbackLevel.DEFAULT),
     /* Inform the user that their previously started activity has cancelled SUCCESSFULLY */
     CANCEL(
         HapticToken.POSITIVE_CONFIRMATION_MEDIUM_EMPHASIS,
@@ -83,17 +75,9 @@ enum class MSDLToken(
         FeedbackLevel.DEFAULT,
     ),
     /* Inform the user the state of their device changed to locked SUCCESSFULLY */
-    LOCK(
-        HapticToken.POSITIVE_CONFIRMATION_LOW_EMPHASIS,
-        SoundToken.LOCK,
-        FeedbackLevel.DEFAULT,
-    ),
+    LOCK(HapticToken.POSITIVE_CONFIRMATION_LOW_EMPHASIS, SoundToken.LOCK, FeedbackLevel.DEFAULT),
     /* Inform the user that their long-press gesture has resulted in the revealing of more contextual information */
-    LONG_PRESS(
-        HapticToken.LONG_PRESS,
-        SoundToken.LONG_PRESS,
-        FeedbackLevel.MINIMAL,
-    ),
+    LONG_PRESS(HapticToken.LONG_PRESS, SoundToken.LONG_PRESS, FeedbackLevel.MINIMAL),
     /* Inform the user that their swipe gesture has reached a threshold that confirms navigation or the reveal of additional information. */
     SWIPE_THRESHOLD_INDICATOR(
         HapticToken.SWIPE_THRESHOLD_INDICATOR,
@@ -119,12 +103,22 @@ enum class MSDLToken(
         FeedbackLevel.DEFAULT,
     ),
     /* Inform the user that their drag gesture has resulted in an incremental value change.
-     * For usage in haptic sliders, this token can be played along with
+     * For usage in haptic sliders that change continuously, this token can be played along with
      * [InteractionProperties.DynamicVibrationScale] properties to control haptic scaling as a
      * function of position and velocity.
      */
-    DRAG_INDICATOR(
-        HapticToken.DRAG_INDICATOR,
+    DRAG_INDICATOR_CONTINUOUS(
+        HapticToken.DRAG_INDICATOR_CONTINUOUS,
+        SoundToken.NO_SOUND,
+        FeedbackLevel.DEFAULT,
+    ),
+    /* Inform the user that their drag gesture has resulted in a stepped value change.
+     * For usage in haptic sliders that change in discrete steps, this token can be played with
+     * [InteractionProperties.DynamicVibrationScale] properties to control haptic scaling as a
+     * function of position and velocity.
+     */
+    DRAG_INDICATOR_DISCRETE(
+        HapticToken.DRAG_INDICATOR_DISCRETE,
         SoundToken.DRAG_INDICATOR,
         FeedbackLevel.DEFAULT,
     ),
@@ -147,17 +141,9 @@ enum class MSDLToken(
         FeedbackLevel.DEFAULT,
     ),
     /* Played when the user touches the return key */
-    KEYPRESS_RETURN(
-        HapticToken.KEYPRESS_RETURN,
-        SoundToken.KEYPRESS_RETURN,
-        FeedbackLevel.DEFAULT,
-    ),
+    KEYPRESS_RETURN(HapticToken.KEYPRESS_RETURN, SoundToken.KEYPRESS_RETURN, FeedbackLevel.DEFAULT),
     /* Played when the user touches the delete key */
-    KEYPRESS_DELETE(
-        HapticToken.KEYPRESS_DELETE,
-        SoundToken.KEYPRESS_DELETE,
-        FeedbackLevel.DEFAULT,
-    ),
+    KEYPRESS_DELETE(HapticToken.KEYPRESS_DELETE, SoundToken.KEYPRESS_DELETE, FeedbackLevel.DEFAULT),
 }
 
 /** Level of feedback that contains a token */
diff --git a/msdllib/src/com/google/android/msdl/data/model/SoundToken.kt b/msdllib/src/com/google/android/msdl/data/model/SoundToken.kt
index bc1ebf0..1d3047d 100644
--- a/msdllib/src/com/google/android/msdl/data/model/SoundToken.kt
+++ b/msdllib/src/com/google/android/msdl/data/model/SoundToken.kt
@@ -40,4 +40,5 @@ enum class SoundToken {
     KEYPRESS_SPACEBAR,
     KEYPRESS_RETURN,
     KEYPRESS_DELETE,
+    NO_SOUND,
 }
diff --git a/msdllib/src/com/google/android/msdl/data/repository/MSDLRepositoryImpl.kt b/msdllib/src/com/google/android/msdl/data/repository/MSDLRepositoryImpl.kt
index 5074a99..7555907 100644
--- a/msdllib/src/com/google/android/msdl/data/repository/MSDLRepositoryImpl.kt
+++ b/msdllib/src/com/google/android/msdl/data/repository/MSDLRepositoryImpl.kt
@@ -252,7 +252,7 @@ internal class MSDLRepositoryImpl : MSDLRepository {
                         HapticComposition(
                             listOf(
                                 HapticCompositionPrimitive(
-                                    VibrationEffect.Composition.PRIMITIVE_TICK,
+                                    VibrationEffect.Composition.PRIMITIVE_CLICK,
                                     scale = 1f,
                                     delayMillis = 0,
                                 )
@@ -260,7 +260,24 @@ internal class MSDLRepositoryImpl : MSDLRepository {
                             VibrationEffect.createPredefined(VibrationEffect.EFFECT_TICK),
                         )
                     },
-                HapticToken.DRAG_INDICATOR to
+                HapticToken.DRAG_INDICATOR_CONTINUOUS to
+                    MSDLHapticData {
+                        HapticComposition(
+                            List(size = 5) {
+                                HapticCompositionPrimitive(
+                                    VibrationEffect.Composition.PRIMITIVE_LOW_TICK,
+                                    scale = 0.3f,
+                                    delayMillis = 0,
+                                )
+                            },
+                            VibrationEffect.createWaveform(
+                                longArrayOf(10, 20, 20, 10),
+                                intArrayOf(10, 30, 50, 10),
+                                -1,
+                            ),
+                        )
+                    },
+                HapticToken.DRAG_INDICATOR_DISCRETE to
                     MSDLHapticData {
                         HapticComposition(
                             listOf(
diff --git a/msdllib/src/com/google/android/msdl/domain/EmptyMSDLPlayer.kt b/msdllib/src/com/google/android/msdl/domain/EmptyMSDLPlayer.kt
new file mode 100644
index 0000000..3de8289
--- /dev/null
+++ b/msdllib/src/com/google/android/msdl/domain/EmptyMSDLPlayer.kt
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
+package com.google.android.msdl.domain
+
+import com.google.android.msdl.data.model.FeedbackLevel
+import com.google.android.msdl.data.model.MSDLToken
+import com.google.android.msdl.logging.MSDLEvent
+
+/** An empty [MSDLPlayer] that was created without a [android.os.Vibrator] */
+internal class EmptyMSDLPlayer : MSDLPlayer {
+    override fun getSystemFeedbackLevel(): FeedbackLevel = FeedbackLevel.NO_FEEDBACK
+
+    override fun playToken(token: MSDLToken, properties: InteractionProperties?) {}
+
+    override fun getHistory(): List<MSDLEvent> = listOf()
+
+    override fun toString(): String = "Empty MSDL player without a vibrator."
+}
diff --git a/msdllib/src/com/google/android/msdl/domain/MSDLPlayer.kt b/msdllib/src/com/google/android/msdl/domain/MSDLPlayer.kt
index d976fb7..c040184 100644
--- a/msdllib/src/com/google/android/msdl/domain/MSDLPlayer.kt
+++ b/msdllib/src/com/google/android/msdl/domain/MSDLPlayer.kt
@@ -17,6 +17,7 @@
 package com.google.android.msdl.domain
 
 import android.os.Vibrator
+import android.util.Log
 import com.google.android.msdl.data.model.FeedbackLevel
 import com.google.android.msdl.data.model.HapticComposition
 import com.google.android.msdl.data.model.MSDLToken
@@ -73,10 +74,18 @@ interface MSDLPlayer {
          *   created using the support information from the given vibrator.
          */
         fun createPlayer(
-            vibrator: Vibrator,
+            vibrator: Vibrator?,
             executor: Executor = Executors.newSingleThreadExecutor(),
             useHapticFeedbackForToken: Map<MSDLToken, Boolean>? = null,
         ): MSDLPlayer {
+            // Return an empty player if no vibrator is available
+            if (vibrator == null) {
+                Log.w(
+                    "MSDLPlayer",
+                    "A null vibrator was used to create a MSDLPlayer. An empty player was created",
+                )
+                return EmptyMSDLPlayer()
+            }
 
             // Create repository
             val repository = MSDLRepositoryImpl()
diff --git a/msdllib/src/com/google/android/msdl/domain/MSDLPlayerImpl.kt b/msdllib/src/com/google/android/msdl/domain/MSDLPlayerImpl.kt
index b103083..606f634 100644
--- a/msdllib/src/com/google/android/msdl/domain/MSDLPlayerImpl.kt
+++ b/msdllib/src/com/google/android/msdl/domain/MSDLPlayerImpl.kt
@@ -16,6 +16,7 @@
 
 package com.google.android.msdl.domain
 
+import android.os.Build
 import android.os.VibrationAttributes
 import android.os.VibrationEffect
 import android.os.Vibrator
@@ -87,15 +88,21 @@ internal class MSDLPlayerImpl(
                     }
                 }
 
-            // 2. Deliver the haptics with attributes
+            // 2. Deliver the haptics with or without attributes
             if (effect == null || !vibrator.hasVibrator()) return
-            val attributes =
-                if (properties?.vibrationAttributes != null) {
-                    properties.vibrationAttributes
-                } else {
-                    VibrationAttributes.Builder().setUsage(VibrationAttributes.USAGE_TOUCH).build()
-                }
-            executor.execute { vibrator.vibrate(effect, attributes) }
+            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
+                val attributes =
+                    if (properties?.vibrationAttributes != null) {
+                        properties.vibrationAttributes
+                    } else {
+                        VibrationAttributes.Builder()
+                            .setUsage(VibrationAttributes.USAGE_TOUCH)
+                            .build()
+                    }
+                executor.execute { vibrator.vibrate(effect, attributes) }
+            } else {
+                executor.execute { vibrator.vibrate(effect) }
+            }
 
             // 3. Log the event
             historyLogger.addEvent(MSDLEvent(token, properties))
@@ -106,6 +113,14 @@ internal class MSDLPlayerImpl(
 
     override fun getHistory(): List<MSDLEvent> = historyLogger.getHistory()
 
+    override fun toString(): String =
+        """
+            Default MSDL player implementation.
+            Vibrator: $vibrator
+            Repository: $repository
+        """
+            .trimIndent()
+
     companion object {
         val REQUIRED_PRIMITIVES =
             listOf(
@@ -113,6 +128,7 @@ internal class MSDLPlayerImpl(
                 VibrationEffect.Composition.PRIMITIVE_THUD,
                 VibrationEffect.Composition.PRIMITIVE_TICK,
                 VibrationEffect.Composition.PRIMITIVE_CLICK,
+                VibrationEffect.Composition.PRIMITIVE_LOW_TICK,
             )
     }
 }
diff --git a/msdllib/src/com/google/android/msdl/logging/MSDLEvent.kt b/msdllib/src/com/google/android/msdl/logging/MSDLEvent.kt
index a81b6a7..c4c1d2a 100644
--- a/msdllib/src/com/google/android/msdl/logging/MSDLEvent.kt
+++ b/msdllib/src/com/google/android/msdl/logging/MSDLEvent.kt
@@ -37,4 +37,6 @@ data class MSDLEvent(val tokenName: String, val properties: String?, val timeSta
         properties?.toString(),
         MSDLHistoryLogger.DATE_FORMAT.format(System.currentTimeMillis()),
     )
+
+    override fun toString(): String = "$timeStamp | token: $tokenName | properties: $properties"
 }
diff --git a/toruslib/torus-core/src/main/java/com/google/android/torus/core/wallpaper/LiveWallpaper.kt b/toruslib/torus-core/src/main/java/com/google/android/torus/core/wallpaper/LiveWallpaper.kt
index 4ebc8f4..533a95e 100644
--- a/toruslib/torus-core/src/main/java/com/google/android/torus/core/wallpaper/LiveWallpaper.kt
+++ b/toruslib/torus-core/src/main/java/com/google/android/torus/core/wallpaper/LiveWallpaper.kt
@@ -36,11 +36,11 @@ import com.google.android.torus.core.wallpaper.listener.LiveWallpaperKeyguardEve
 import java.lang.ref.WeakReference
 
 /**
- * Implements [WallpaperService] using Filament to render the wallpaper.
- * An instance of this class should only implement [getWallpaperEngine]
+ * Implements [WallpaperService] using Filament to render the wallpaper. An instance of this class
+ * should only implement [getWallpaperEngine]
  *
- * Note: [LiveWallpaper] subclasses must include the following attribute/s
- * in the AndroidManifest.xml:
+ * Note: [LiveWallpaper] subclasses must include the following attribute/s in the
+ * AndroidManifest.xml:
  * - android:configChanges="uiMode"
  */
 abstract class LiveWallpaper : WallpaperService() {
@@ -50,6 +50,7 @@ abstract class LiveWallpaper : WallpaperService() {
         const val COMMAND_KEYGUARD_GOING_AWAY = "android.wallpaper.keyguardgoingaway"
         const val COMMAND_GOING_TO_SLEEP = "android.wallpaper.goingtosleep"
         const val COMMAND_PREVIEW_INFO = "android.wallpaper.previewinfo"
+        const val COMMAND_LOCKSCREEN_LAYOUT_CHANGED = "android.wallpaper.lockscreen_layout_changed"
         const val WALLPAPER_FLAG_NOT_FOUND = -1
     }
 
@@ -77,40 +78,41 @@ abstract class LiveWallpaper : WallpaperService() {
          * through WallpaperService.Engine.onCommand events that should be more accurate.
          */
         if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.R) {
-            wakeStateReceiver = object : BroadcastReceiver() {
-                override fun onReceive(context: Context, intent: Intent) {
-                    val positionExtras = Bundle()
-                    when (intent.action) {
-                        Intent.ACTION_SCREEN_ON -> {
-                            positionExtras.putInt(
-                                LiveWallpaperEventListener.WAKE_ACTION_LOCATION_X,
-                                -1
-                            )
-                            positionExtras.putInt(
-                                LiveWallpaperEventListener.WAKE_ACTION_LOCATION_Y,
-                                -1
-                            )
-                            wakeStateChangeListeners.forEach {
-                                it.get()?.onWake(positionExtras)
+            wakeStateReceiver =
+                object : BroadcastReceiver() {
+                    override fun onReceive(context: Context, intent: Intent) {
+                        val positionExtras = Bundle()
+                        when (intent.action) {
+                            Intent.ACTION_SCREEN_ON -> {
+                                positionExtras.putInt(
+                                    LiveWallpaperEventListener.WAKE_ACTION_LOCATION_X,
+                                    -1,
+                                )
+                                positionExtras.putInt(
+                                    LiveWallpaperEventListener.WAKE_ACTION_LOCATION_Y,
+                                    -1,
+                                )
+                                wakeStateChangeListeners.forEach {
+                                    it.get()?.onWake(positionExtras)
+                                }
                             }
-                        }
 
-                        Intent.ACTION_SCREEN_OFF -> {
-                            positionExtras.putInt(
-                                LiveWallpaperEventListener.SLEEP_ACTION_LOCATION_X,
-                                -1
-                            )
-                            positionExtras.putInt(
-                                LiveWallpaperEventListener.SLEEP_ACTION_LOCATION_Y,
-                                -1
-                            )
-                            wakeStateChangeListeners.forEach {
-                                it.get()?.onSleep(positionExtras)
+                            Intent.ACTION_SCREEN_OFF -> {
+                                positionExtras.putInt(
+                                    LiveWallpaperEventListener.SLEEP_ACTION_LOCATION_X,
+                                    -1,
+                                )
+                                positionExtras.putInt(
+                                    LiveWallpaperEventListener.SLEEP_ACTION_LOCATION_Y,
+                                    -1,
+                                )
+                                wakeStateChangeListeners.forEach {
+                                    it.get()?.onSleep(positionExtras)
+                                }
                             }
                         }
                     }
                 }
-            }
             registerReceiver(wakeStateReceiver, wakeStateChangeIntentFilter)
         }
     }
@@ -121,22 +123,21 @@ abstract class LiveWallpaper : WallpaperService() {
     }
 
     /**
-     * Must be implemented to return a new instance of [TorusEngine].
-     * If you want it to subscribe to wallpaper interactions (offset, preview, zoom...) the engine
-     * should also implement [LiveWallpaperEventListener]. If you want it to subscribe to touch
-     * events, it should implement [TorusTouchListener].
+     * Must be implemented to return a new instance of [TorusEngine]. If you want it to subscribe to
+     * wallpaper interactions (offset, preview, zoom...) the engine should also implement
+     * [LiveWallpaperEventListener]. If you want it to subscribe to touch events, it should
+     * implement [TorusTouchListener].
      *
      * Note: You might have multiple Engines running at the same time (when the wallpaper is set as
-     * the active wallpaper and the user is in the wallpaper picker viewing a preview of it
-     * as well). You can track the lifecycle when *any* Engine is active using the
+     * the active wallpaper and the user is in the wallpaper picker viewing a preview of it as
+     * well). You can track the lifecycle when *any* Engine is active using the
      * is{First/Last}ActiveInstance parameters of the create/destroy methods.
-     *
      */
     abstract fun getWallpaperEngine(context: Context, surfaceHolder: SurfaceHolder): TorusEngine
 
     /**
-     * returns a new instance of [LiveWallpaperEngineWrapper].
-     * Caution: This function should not be override when extending [LiveWallpaper] class.
+     * returns a new instance of [LiveWallpaperEngineWrapper]. Caution: This function should not be
+     * override when extending [LiveWallpaper] class.
      */
     override fun onCreateEngine(): Engine {
         val wrapper = LiveWallpaperEngineWrapper()
@@ -197,8 +198,16 @@ abstract class LiveWallpaper : WallpaperService() {
         }
 
         /**
-         * Triggers the [WallpaperService] to recompute the Wallpaper Colors.
+         * Returns the information if the wallpaper is visible.
          */
+        fun isVisible(): Boolean {
+            this.wallpaperServiceEngine?.let {
+                return it.isVisible
+            }
+            return false
+        }
+
+        /** Triggers the [WallpaperService] to recompute the Wallpaper Colors. */
         fun notifyWallpaperColorsChanged() {
             this.wallpaperServiceEngine?.notifyColorsChanged()
         }
@@ -227,11 +236,11 @@ abstract class LiveWallpaper : WallpaperService() {
 
     /**
      * Implementation of [WallpaperService.Engine] that works as a wrapper. If we used a
-     * [WallpaperService.Engine] instance as the framework engine, we would find the problem
-     * that the engine will be created for preview, then destroyed and recreated again when the
-     * wallpaper is set. This behavior may cause to load assets multiple time for every time the
-     * Rendering engine is created. Also, wrapping our [TorusEngine] inside
-     * [WallpaperService.Engine] allow us to reuse [TorusEngine] in other places, like Activities.
+     * [WallpaperService.Engine] instance as the framework engine, we would find the problem that
+     * the engine will be created for preview, then destroyed and recreated again when the wallpaper
+     * is set. This behavior may cause to load assets multiple time for every time the Rendering
+     * engine is created. Also, wrapping our [TorusEngine] inside [WallpaperService.Engine] allow us
+     * to reuse [TorusEngine] in other places, like Activities.
      */
     private inner class LiveWallpaperEngineWrapper : WallpaperService.Engine() {
         private lateinit var wallpaperEngine: TorusEngine
@@ -245,11 +254,12 @@ abstract class LiveWallpaper : WallpaperService() {
              * For Android 10 (SDK 29).
              * This is needed for Foldables and multiple display devices.
              */
-            val context = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
-                displayContext ?: this@LiveWallpaper
-            } else {
-                this@LiveWallpaper
-            }
+            val context =
+                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
+                    displayContext ?: this@LiveWallpaper
+                } else {
+                    this@LiveWallpaper
+                }
 
             wallpaperEngine = getWallpaperEngine(context, surfaceHolder)
             numEngines++
@@ -298,7 +308,7 @@ abstract class LiveWallpaper : WallpaperService() {
             holder: SurfaceHolder?,
             format: Int,
             width: Int,
-            height: Int
+            height: Int,
         ) {
             super.onSurfaceChanged(holder, format, width, height)
             wallpaperEngine.resize(width, height)
@@ -310,7 +320,7 @@ abstract class LiveWallpaper : WallpaperService() {
             xOffsetStep: Float,
             yOffsetStep: Float,
             xPixelOffset: Int,
-            yPixelOffset: Int
+            yPixelOffset: Int,
         ) {
             super.onOffsetsChanged(
                 xOffset,
@@ -318,7 +328,7 @@ abstract class LiveWallpaper : WallpaperService() {
                 xOffsetStep,
                 yOffsetStep,
                 xPixelOffset,
-                yPixelOffset
+                yPixelOffset,
             )
 
             if (wallpaperEngine is LiveWallpaperEventListener) {
@@ -328,7 +338,7 @@ abstract class LiveWallpaper : WallpaperService() {
                         1.0f
                     } else {
                         xOffsetStep
-                    }
+                    },
                 )
             }
         }
@@ -368,7 +378,7 @@ abstract class LiveWallpaper : WallpaperService() {
             y: Int,
             z: Int,
             extras: Bundle?,
-            resultRequested: Boolean
+            resultRequested: Boolean,
         ): Bundle? {
             when (action) {
                 COMMAND_REAPPLY -> onWallpaperReapplied()
@@ -386,6 +396,11 @@ abstract class LiveWallpaper : WallpaperService() {
                 }
                 COMMAND_KEYGUARD_GOING_AWAY -> onKeyguardGoingAway()
                 COMMAND_PREVIEW_INFO -> onPreviewInfoReceived(extras)
+                COMMAND_LOCKSCREEN_LAYOUT_CHANGED -> {
+                    if (extras != null) {
+                        onLockscreenLayoutChanged(extras)
+                    }
+                }
             }
 
             if (resultRequested) return extras
@@ -406,9 +421,7 @@ abstract class LiveWallpaper : WallpaperService() {
             wallpaperEngine.onWallpaperFlagsChanged(which)
         }
 
-        /**
-         * This is overriding a hidden API [WallpaperService.shouldZoomOutWallpaper].
-         */
+        /** This is overriding a hidden API [WallpaperService.shouldZoomOutWallpaper]. */
         override fun shouldZoomOutWallpaper(): Boolean {
             if (wallpaperEngine is LiveWallpaperEventListener) {
                 return (wallpaperEngine as LiveWallpaperEventListener).shouldZoomOutWallpaper()
@@ -445,5 +458,11 @@ abstract class LiveWallpaper : WallpaperService() {
                 (wallpaperEngine as LiveWallpaperEventListener).onPreviewInfoReceived(extras)
             }
         }
+
+        fun onLockscreenLayoutChanged(extras: Bundle) {
+            if (wallpaperEngine is LiveWallpaperEventListener) {
+                (wallpaperEngine as LiveWallpaperEventListener).onLockscreenLayoutChanged(extras)
+            }
+        }
     }
 }
diff --git a/toruslib/torus-core/src/main/java/com/google/android/torus/core/wallpaper/listener/LiveWallpaperEventListener.kt b/toruslib/torus-core/src/main/java/com/google/android/torus/core/wallpaper/listener/LiveWallpaperEventListener.kt
index 6803bd0..6b05517 100644
--- a/toruslib/torus-core/src/main/java/com/google/android/torus/core/wallpaper/listener/LiveWallpaperEventListener.kt
+++ b/toruslib/torus-core/src/main/java/com/google/android/torus/core/wallpaper/listener/LiveWallpaperEventListener.kt
@@ -36,8 +36,8 @@ interface LiveWallpaperEventListener {
      * the home of the launcher). This only tracts the horizontal scroll.
      *
      * @param xOffset The current offset of the scroll. The value is normalize between [0,1].
-     * @param xOffsetStep How is stepped the scroll. If you invert [xOffsetStep] you get the
-     * number of pages in the scrolling area.
+     * @param xOffsetStep How is stepped the scroll. If you invert [xOffsetStep] you get the number
+     *   of pages in the scrolling area.
      */
     fun onOffsetChanged(xOffset: Float, xOffsetStep: Float)
 
@@ -45,27 +45,28 @@ interface LiveWallpaperEventListener {
      * Called when the zoom level of the wallpaper is changing.
      *
      * @param zoomLevel A value between 0 and 1 that tells how much the wallpaper should be zoomed
-     * out: if 0, the wallpaper should be in normal state; if 1 the wallpaper should be zoomed out.
+     *   out: if 0, the wallpaper should be in normal state; if 1 the wallpaper should be zoomed
+     *   out.
      */
     fun onZoomChanged(zoomLevel: Float)
 
     /**
-     * Call when the wallpaper was set, and then is reapplied. This means that the wallpaper was
-     * set and is being set again. This is useful to know if the wallpaper settings have to be
-     * reapplied again (i.e. if the user enters the wallpaper picker and picks the same wallpaper,
-     * changes the settings and sets the wallpaper again).
+     * Call when the wallpaper was set, and then is reapplied. This means that the wallpaper was set
+     * and is being set again. This is useful to know if the wallpaper settings have to be reapplied
+     * again (i.e. if the user enters the wallpaper picker and picks the same wallpaper, changes the
+     * settings and sets the wallpaper again).
      */
     fun onWallpaperReapplied()
 
     /**
      * Called when the Wallpaper colors need to be computed you can create a [WallpaperColors]
-     * instance using the [WallpaperColors.fromBitmap] function and passing a bitmap that
-     * represents the wallpaper (i.e. the gallery thumbnail) or use the [WallpaperColors]
-     * constructor and pass the primary, secondary and tertiary colors. This method is specially
-     * important since the UI will change their colors based on what is returned here.
+     * instance using the [WallpaperColors.fromBitmap] function and passing a bitmap that represents
+     * the wallpaper (i.e. the gallery thumbnail) or use the [WallpaperColors] constructor and pass
+     * the primary, secondary and tertiary colors. This method is specially important since the UI
+     * will change their colors based on what is returned here.
      *
-     * @return The colors that represent the wallpaper; null if you want the System to take
-     * care of the colors.
+     * @return The colors that represent the wallpaper; null if you want the System to take care of
+     *   the colors.
      */
     fun computeWallpaperColors(): WallpaperColors?
 
@@ -73,8 +74,8 @@ interface LiveWallpaperEventListener {
      * Called when the wallpaper receives the preview information (asynchronous call).
      *
      * @param extras the bundle of the preview information. The key "which_preview" can be used to
-     * retrieve a string value (ex. main_preview_home) that specifies which preview the engine
-     * is referring to.
+     *   retrieve a string value (ex. main_preview_home) that specifies which preview the engine is
+     *   referring to.
      */
     fun onPreviewInfoReceived(extras: Bundle?) {}
 
@@ -83,9 +84,9 @@ interface LiveWallpaperEventListener {
      *
      * @param extras contains the location of the action that caused the wake event:
      * - [LiveWallpaperEventListener.WAKE_ACTION_LOCATION_X]: the X screen location (in Pixels). if
-     * the value is not included or is -1, the X screen location is unknown.
+     *   the value is not included or is -1, the X screen location is unknown.
      * - [LiveWallpaperEventListener.WAKE_ACTION_LOCATION_Y]: the Y screen location (in Pixels). if
-     * the value is not included or is -1, the Y screen location is unknown.
+     *   the value is not included or is -1, the Y screen location is unknown.
      */
     fun onWake(extras: Bundle)
 
@@ -94,9 +95,9 @@ interface LiveWallpaperEventListener {
      *
      * @param extras contains the location of the action that caused the sleep event:
      * - [LiveWallpaperEventListener.SLEEP_ACTION_LOCATION_X]: the X screen location (in Pixels). if
-     * the value is not included or is -1, the X screen location is unknown.
+     *   the value is not included or is -1, the X screen location is unknown.
      * - [LiveWallpaperEventListener.SLEEP_ACTION_LOCATION_Y]: the Y screen location (in Pixels). if
-     * the value is not included or is -1, the Y screen location is unknown.
+     *   the value is not included or is -1, the Y screen location is unknown.
      */
     fun onSleep(extras: Bundle)
 
@@ -107,4 +108,21 @@ interface LiveWallpaperEventListener {
      * See [WallpaperService.shouldZoomOutWallpaper].
      */
     fun shouldZoomOutWallpaper() = false
+
+    /**
+     * React to COMMAND_LOCKSCREEN_LAYOUT_CHANGED from SystemUI. Current usage is to show the
+     * remaining space in lockscreen to bound the position for wallpaper shape effects. We also pass
+     * the bottom of smartspace as a reference.
+     *
+     * @param extras contains the necessary value from lockscreen layout currently for magic
+     *   portrait, it contains
+     * - "screenLeft": the left of the screen
+     * - "screenRight": the left of the screen
+     * - "smartspaceBottom": the bottom of the smartspace date and weather part, not bc smartspace
+     * - "shortCutTop": the top of the shortcut in locksreen
+     * - "notificationBottom": the bottom of notifications in lockscreen With smartspaceBottom,
+     *   screenLeft, screenRight, shortCutTop, we can get the remaining space bounds in lockscreen
+     *   without notifications. And with notificationBottom, we have bounds with notifications
+     */
+    fun onLockscreenLayoutChanged(extras: Bundle) {}
 }
diff --git a/tracinglib/README.md b/tracinglib/README.md
index 61f938e..924df41 100644
--- a/tracinglib/README.md
+++ b/tracinglib/README.md
@@ -1,14 +1,13 @@
 # Coroutine Tracing
 
-This library contains utilities for tracing coroutines. Coroutines cannot normally be traced using
-the `android.os.Trace` APIs because it will often lead to malformed trace sections. This is because
-each `Trace.beginSection` must have a matching `Trace.endSection` on the same thread before the
-scope is finished, so if they are used around a suspend point, the trace section will remain open
-while other unrelated work executes. It could even remain open indefinitely if the coroutine is
-canceled.
-
-To address this, we introduce a function `traceCoroutine("name") {}` that can be used for tracing
-sections of coroutine code. When invoked, a trace section with the given name will start
+This library contains utilities for tracing coroutines. Coroutines cannot be traced using the
+`android.os.Trace` APIs because suspension points will lead to malformed trace sections. This is
+because each `Trace.beginSection` must have a matching `Trace.endSection`; if a coroutine suspends
+before `Trace.endSection` is called, the trace section will remain open while other unrelated work
+executes.
+
+To address this, we introduce a function `traceCoroutine("name") { ... }` that can be used for
+tracing sections of coroutine code. When invoked, a trace section with the given name will start
 immediately, and its name will also be written to an object in the current `CoroutineContext` used
 for coroutine-local storage. When the coroutine suspends, all trace sections will end immediately.
 When resumed, the coroutine will read the names of the previous sections from coroutine-local
@@ -61,19 +60,19 @@ val coldFlow = flow {
   emit(1)
   emit(2)
   emit(3)
-}.withTraceName("my-flow")
+}
 
-coldFlow.collect {
+coldFlow.collect("F") {
   println(it)
-  delay(10)
+  yield()
 }
 ```
 
 Would be traced as follows:
 
 ```
-Thread #1 |  [=== my-flow:collect ===]    [=== my-flow:collect ===]    [=== my-flow:collect ===]
-          |    [== my-flow:emit ==]         [== my-flow:emit ==]         [== my-flow:emit ==]
+Thread #1 |  [====== collect:F ======]    [==== collect:F =====]    [====== collect:F ======]
+          |    [== collect:F:emit ==]     [== collect:F:emit ==]    [== collect:F:emit ==]
 ```
 
 # Building and Running
diff --git a/tracinglib/benchmark/Android.bp b/tracinglib/benchmark/Android.bp
index 965b622..aef471f 100644
--- a/tracinglib/benchmark/Android.bp
+++ b/tracinglib/benchmark/Android.bp
@@ -18,9 +18,12 @@ package {
 }
 
 android_test {
-    name: "tracinglib-benchmark",
+    name: "CoroutineTracingPerfTests",
 
-    srcs: ["src/**/*.kt"],
+    srcs: [
+        "src/**/*.kt",
+        ":tracinglib-core-srcs",
+    ],
 
     static_libs: [
         "androidx.annotation_annotation",
@@ -35,12 +38,12 @@ android_test {
         "flag-junit",
         "kotlinx_coroutines_android",
         "platform-test-rules",
-        "tracinglib-platform",
+        "com_android_systemui_flags_lib",
     ],
 
     data: [":perfetto_artifacts"],
 
-    sdk_version: "current",
+    platform_apis: true,
     certificate: "platform",
     use_resource_processor: true,
 
diff --git a/tracinglib/benchmark/AndroidTest.xml b/tracinglib/benchmark/AndroidTest.xml
index e68e883..0a8ebb2 100644
--- a/tracinglib/benchmark/AndroidTest.xml
+++ b/tracinglib/benchmark/AndroidTest.xml
@@ -13,7 +13,7 @@
      See the License for the specific language governing permissions and
      limitations under the License.
 -->
-<configuration description="Runs tracinglib-benchmark metric instrumentation.">
+<configuration description="Runs CoroutineTracingPerfTests metric instrumentation.">
     <target_preparer class="com.android.tradefed.targetprep.RootTargetPreparer"/>
     <!-- Needed for pushing the trace config file -->
     <target_preparer class="com.android.tradefed.targetprep.PushFilePreparer">
@@ -25,7 +25,7 @@
 
     <target_preparer class="com.android.tradefed.targetprep.suite.SuiteApkInstaller">
         <option name="cleanup-apks" value="true" />
-        <option name="test-file-name" value="tracinglib-benchmark.apk" />
+        <option name="test-file-name" value="CoroutineTracingPerfTests.apk" />
     </target_preparer>
 
     <target_preparer class="com.android.tradefed.targetprep.RunCommandTargetPreparer">
diff --git a/tracinglib/core/Android.bp b/tracinglib/core/Android.bp
index da4f1fd..339e8fc 100644
--- a/tracinglib/core/Android.bp
+++ b/tracinglib/core/Android.bp
@@ -16,20 +16,25 @@ package {
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
+// TODO(b/240432457): Replace with library once `-Xfriend-paths` is supported by Soong
+filegroup {
+    name: "tracinglib-core-srcs",
+    srcs: ["src/**/*.kt"],
+    visibility: ["//frameworks/libs/systemui/tracinglib:__subpackages__"],
+}
+
 java_library {
     name: "tracinglib-platform",
     static_libs: [
         "kotlinx_coroutines_android",
         "com_android_systemui_flags_lib",
     ],
-    libs: [
-        "androidx.annotation_annotation",
-    ],
     kotlincflags: [
         "-Xjvm-default=all",
         "-opt-in=kotlin.ExperimentalStdlibApi",
         "-opt-in=kotlinx.coroutines.DelicateCoroutinesApi",
         "-opt-in=kotlinx.coroutines.ExperimentalCoroutinesApi",
+        "-Xexplicit-api=strict",
     ],
-    srcs: ["src/**/*.kt"],
+    srcs: [":tracinglib-core-srcs"],
 }
diff --git a/tracinglib/core/src/FlowTracing.kt b/tracinglib/core/src/FlowTracing.kt
index ce2b645..5916382 100644
--- a/tracinglib/core/src/FlowTracing.kt
+++ b/tracinglib/core/src/FlowTracing.kt
@@ -29,14 +29,14 @@ import kotlinx.coroutines.flow.conflate
 import kotlinx.coroutines.flow.onEach
 
 /** Utilities to trace Flows */
-object FlowTracing {
+public object FlowTracing {
 
     private const val TAG = "FlowTracing"
     private const val DEFAULT_ASYNC_TRACK_NAME = TAG
     private val counter = AtomicInteger(0)
 
     /** Logs each flow element to a trace. */
-    inline fun <T> Flow<T>.traceEach(
+    public inline fun <T> Flow<T>.traceEach(
         flowName: String,
         logcat: Boolean = false,
         traceEmissionCount: Boolean = false,
@@ -48,7 +48,7 @@ object FlowTracing {
     }
 
     /** Records value of a given numeric flow as a counter track in traces. */
-    fun <T : Number> Flow<T>.traceAsCounter(
+    public fun <T : Number> Flow<T>.traceAsCounter(
         counterName: String,
         traceEmissionCount: Boolean = false,
         valueToInt: (T) -> Int = { it.toInt() },
@@ -62,7 +62,10 @@ object FlowTracing {
     }
 
     /** Adds a counter track to monitor emissions from a specific flow.] */
-    fun <T> Flow<T>.traceEmissionCount(flowName: String, uniqueSuffix: Boolean = false): Flow<T> {
+    public fun <T> Flow<T>.traceEmissionCount(
+        flowName: String,
+        uniqueSuffix: Boolean = false,
+    ): Flow<T> {
         val trackName by lazy {
             "$flowName#emissionCount" + if (uniqueSuffix) "\$${counter.addAndGet(1)}" else ""
         }
@@ -78,7 +81,7 @@ object FlowTracing {
      *
      * [flowName] is lazy: it would be computed only if tracing is enabled and only the first time.
      */
-    fun <T> Flow<T>.traceEmissionCount(
+    public fun <T> Flow<T>.traceEmissionCount(
         flowName: () -> String,
         uniqueSuffix: Boolean = false,
     ): Flow<T> {
@@ -103,7 +106,7 @@ object FlowTracing {
      *
      * This allows to easily have visibility into what's happening in awaitClose.
      */
-    suspend fun ProducerScope<*>.tracedAwaitClose(name: String, block: () -> Unit = {}) {
+    public suspend fun ProducerScope<*>.tracedAwaitClose(name: String, block: () -> Unit = {}) {
         awaitClose {
             val traceName = { "$name#TracedAwaitClose" }
             traceAsync(DEFAULT_ASYNC_TRACK_NAME, traceName) { traceSection(traceName) { block() } }
@@ -119,7 +122,7 @@ object FlowTracing {
      *
      * Should be used with [tracedAwaitClose] (when needed).
      */
-    fun <T> tracedConflatedCallbackFlow(
+    public fun <T> tracedConflatedCallbackFlow(
         name: String,
         @BuilderInference block: suspend ProducerScope<T>.() -> Unit,
     ): Flow<T> {
diff --git a/tracinglib/core/src/ListenersTracing.kt b/tracinglib/core/src/ListenersTracing.kt
index d73ca07..25a1b6e 100644
--- a/tracinglib/core/src/ListenersTracing.kt
+++ b/tracinglib/core/src/ListenersTracing.kt
@@ -17,7 +17,7 @@
 package com.android.app.tracing
 
 /** Utilities to trace automatically computations happening for each element of a list. */
-object ListenersTracing {
+public object ListenersTracing {
 
     /**
      * Like [forEach], but outputs a trace for each element.
@@ -33,7 +33,7 @@ object ListenersTracing {
      * listeners.forEachTraced(TAG) { it.dispatch(state) }
      * ```
      */
-    inline fun <T : Any> List<T>.forEachTraced(tag: String = "", f: (T) -> Unit) {
+    public inline fun <T : Any> List<T>.forEachTraced(tag: String = "", f: (T) -> Unit) {
         forEach { traceSection({ "$tag#${it::javaClass.get().name}" }) { f(it) } }
     }
 }
diff --git a/tracinglib/core/src/TraceStateLogger.kt b/tracinglib/core/src/TraceStateLogger.kt
index 697b143..3394293 100644
--- a/tracinglib/core/src/TraceStateLogger.kt
+++ b/tracinglib/core/src/TraceStateLogger.kt
@@ -35,7 +35,7 @@ import android.util.Log
  * This creates a new slice in a perfetto trace only if the state is different than the previous
  * one.
  */
-class TraceStateLogger
+public class TraceStateLogger
 @JvmOverloads
 constructor(
     private val trackName: String,
@@ -47,7 +47,7 @@ constructor(
     private var previousValue: String? = null
 
     /** If needed, logs the value to a track with name [trackName]. */
-    fun log(newValue: String) {
+    public fun log(newValue: String) {
         if (instantEvent) {
             Trace.instantForTrack(Trace.TRACE_TAG_APP, trackName, newValue)
         }
diff --git a/tracinglib/core/src/TraceUtils.android.kt b/tracinglib/core/src/TraceUtils.android.kt
index 633038d..0c9838f 100644
--- a/tracinglib/core/src/TraceUtils.android.kt
+++ b/tracinglib/core/src/TraceUtils.android.kt
@@ -19,7 +19,7 @@ package com.android.app.tracing
 import android.os.Trace
 import android.os.TraceNameSupplier
 
-inline fun namedRunnable(tag: String, crossinline block: () -> Unit): Runnable {
+public inline fun namedRunnable(tag: String, crossinline block: () -> Unit): Runnable {
     return object : Runnable, TraceNameSupplier {
         override fun getTraceName(): String = tag
 
@@ -27,7 +27,7 @@ inline fun namedRunnable(tag: String, crossinline block: () -> Unit): Runnable {
     }
 }
 
-inline fun instantForTrack(trackName: String, eventName: () -> String) {
+public inline fun instantForTrack(trackName: String, eventName: () -> String) {
     if (Trace.isEnabled()) {
         Trace.instantForTrack(Trace.TRACE_TAG_APP, trackName, eventName())
     }
diff --git a/tracinglib/core/src/TraceUtils.kt b/tracinglib/core/src/TraceUtils.kt
index 8ae5482..ede2610 100644
--- a/tracinglib/core/src/TraceUtils.kt
+++ b/tracinglib/core/src/TraceUtils.kt
@@ -16,6 +16,7 @@
 
 package com.android.app.tracing
 
+import android.annotation.SuppressLint
 import android.os.Trace
 import com.android.app.tracing.coroutines.traceCoroutine
 import java.util.concurrent.ThreadLocalRandom
@@ -64,7 +65,9 @@ import java.util.concurrent.ThreadLocalRandom
  * @see endSlice
  * @see traceCoroutine
  */
-fun beginSlice(sliceName: String) {
+@SuppressLint("UnclosedTrace")
+@PublishedApi
+internal fun beginSlice(sliceName: String) {
     Trace.traceBegin(Trace.TRACE_TAG_APP, sliceName)
 }
 
@@ -76,7 +79,8 @@ fun beginSlice(sliceName: String) {
  * @see beginSlice
  * @see traceCoroutine
  */
-fun endSlice() {
+@PublishedApi
+internal fun endSlice() {
     Trace.traceEnd(Trace.TRACE_TAG_APP)
 }
 
@@ -84,7 +88,7 @@ fun endSlice() {
  * Run a block within a [Trace] section. Calls [Trace.beginSection] before and [Trace.endSection]
  * after the passed block.
  */
-inline fun <T> traceSection(tag: String, block: () -> T): T {
+public inline fun <T> traceSection(tag: String, block: () -> T): T {
     val tracingEnabled = Trace.isEnabled()
     if (tracingEnabled) beginSlice(tag)
     return try {
@@ -100,7 +104,7 @@ inline fun <T> traceSection(tag: String, block: () -> T): T {
  * Same as [traceSection], but the tag is provided as a lambda to help avoiding creating expensive
  * strings when not needed.
  */
-inline fun <T> traceSection(tag: () -> String, block: () -> T): T {
+public inline fun <T> traceSection(tag: () -> String, block: () -> T): T {
     val tracingEnabled = Trace.isEnabled()
     if (tracingEnabled) beginSlice(tag())
     return try {
@@ -110,27 +114,27 @@ inline fun <T> traceSection(tag: () -> String, block: () -> T): T {
     }
 }
 
-object TraceUtils {
-    const val TAG = "TraceUtils"
-    const val DEFAULT_TRACK_NAME = "AsyncTraces"
+public object TraceUtils {
+    public const val TAG: String = "TraceUtils"
+    public const val DEFAULT_TRACK_NAME: String = "AsyncTraces"
 
     @JvmStatic
-    inline fun <T> trace(tag: () -> String, block: () -> T): T {
+    public inline fun <T> trace(tag: () -> String, block: () -> T): T {
         return traceSection(tag) { block() }
     }
 
     @JvmStatic
-    inline fun <T> trace(tag: String, crossinline block: () -> T): T {
+    public inline fun <T> trace(tag: String, crossinline block: () -> T): T {
         return traceSection(tag) { block() }
     }
 
     @JvmStatic
-    inline fun traceRunnable(tag: String, crossinline block: () -> Unit): Runnable {
+    public inline fun traceRunnable(tag: String, crossinline block: () -> Unit): Runnable {
         return Runnable { traceSection(tag) { block() } }
     }
 
     @JvmStatic
-    inline fun traceRunnable(
+    public inline fun traceRunnable(
         crossinline tag: () -> String,
         crossinline block: () -> Unit,
     ): Runnable {
@@ -144,12 +148,12 @@ object TraceUtils {
      * under a single track.
      */
     @JvmStatic
-    inline fun <T> traceAsync(method: String, block: () -> T): T =
+    public inline fun <T> traceAsync(method: String, block: () -> T): T =
         traceAsync(DEFAULT_TRACK_NAME, method, block)
 
     /** Creates an async slice in the default track. */
     @JvmStatic
-    inline fun <T> traceAsync(tag: () -> String, block: () -> T): T {
+    public inline fun <T> traceAsync(tag: () -> String, block: () -> T): T {
         val tracingEnabled = Trace.isEnabled()
         return if (tracingEnabled) {
             traceAsync(DEFAULT_TRACK_NAME, tag(), block)
@@ -164,7 +168,7 @@ object TraceUtils {
      * The [tag] is computed only if tracing is enabled. See [traceAsync].
      */
     @JvmStatic
-    inline fun <T> traceAsync(trackName: String, tag: () -> String, block: () -> T): T {
+    public inline fun <T> traceAsync(trackName: String, tag: () -> String, block: () -> T): T {
         val tracingEnabled = Trace.isEnabled()
         return if (tracingEnabled) {
             traceAsync(trackName, tag(), block)
@@ -181,7 +185,7 @@ object TraceUtils {
      * process.
      */
     @JvmStatic
-    inline fun <T> traceAsync(trackName: String, method: String, block: () -> T): T {
+    public inline fun <T> traceAsync(trackName: String, method: String, block: () -> T): T {
         val cookie = ThreadLocalRandom.current().nextInt()
         Trace.asyncTraceForTrackBegin(Trace.TRACE_TAG_APP, trackName, method, cookie)
         try {
diff --git a/tracinglib/core/src/coroutines/CoroutineTracing.kt b/tracinglib/core/src/coroutines/CoroutineTracing.kt
index 1d55535..d86d13d 100644
--- a/tracinglib/core/src/coroutines/CoroutineTracing.kt
+++ b/tracinglib/core/src/coroutines/CoroutineTracing.kt
@@ -32,17 +32,15 @@ import kotlinx.coroutines.launch
 import kotlinx.coroutines.runBlocking
 import kotlinx.coroutines.withContext
 
-const val DEFAULT_TRACK_NAME = "Coroutines"
-
 @OptIn(ExperimentalContracts::class)
-suspend inline fun <R> coroutineScope(
+public suspend inline fun <R> coroutineScopeTraced(
     traceName: String,
     crossinline block: suspend CoroutineScope.() -> R,
 ): R {
     contract { callsInPlace(block, InvocationKind.EXACTLY_ONCE) }
-    return traceCoroutine(traceName) {
-        return@traceCoroutine coroutineScope wrappedCoroutineScope@{
-            return@wrappedCoroutineScope block()
+    return coroutineScope {
+        traceCoroutine(traceName) {
+            return@coroutineScope block()
         }
     }
 }
@@ -52,31 +50,33 @@ suspend inline fun <R> coroutineScope(
  *
  * @see traceCoroutine
  */
-inline fun CoroutineScope.launch(
+public inline fun CoroutineScope.launchTraced(
     crossinline spanName: () -> String,
     context: CoroutineContext = EmptyCoroutineContext,
     start: CoroutineStart = CoroutineStart.DEFAULT,
     noinline block: suspend CoroutineScope.() -> Unit,
-): Job = launch(nameCoroutine(spanName) + context, start, block)
+): Job {
+    return launch(nameCoroutine(spanName) + context, start, block)
+}
 
 /**
  * Convenience function for calling [CoroutineScope.launch] with [traceCoroutine] to enable tracing.
  *
  * @see traceCoroutine
  */
-fun CoroutineScope.launch(
-    spanName: String,
+public fun CoroutineScope.launchTraced(
+    spanName: String? = null,
     context: CoroutineContext = EmptyCoroutineContext,
     start: CoroutineStart = CoroutineStart.DEFAULT,
     block: suspend CoroutineScope.() -> Unit,
-): Job = launch(nameCoroutine(spanName) + context, start, block)
+): Job = launchTraced({ spanName ?: block::class.simpleName ?: "launch" }, context, start, block)
 
 /**
  * Convenience function for calling [CoroutineScope.async] with [traceCoroutine] enable tracing
  *
  * @see traceCoroutine
  */
-inline fun <T> CoroutineScope.async(
+public inline fun <T> CoroutineScope.asyncTraced(
     spanName: () -> String,
     context: CoroutineContext = EmptyCoroutineContext,
     start: CoroutineStart = CoroutineStart.DEFAULT,
@@ -88,19 +88,20 @@ inline fun <T> CoroutineScope.async(
  *
  * @see traceCoroutine
  */
-fun <T> CoroutineScope.async(
-    spanName: String,
+public fun <T> CoroutineScope.asyncTraced(
+    spanName: String? = null,
     context: CoroutineContext = EmptyCoroutineContext,
     start: CoroutineStart = CoroutineStart.DEFAULT,
     block: suspend CoroutineScope.() -> T,
-): Deferred<T> = async(nameCoroutine(spanName) + context, start, block)
+): Deferred<T> =
+    asyncTraced({ spanName ?: block::class.simpleName ?: "async" }, context, start, block)
 
 /**
  * Convenience function for calling [runBlocking] with [traceCoroutine] to enable tracing.
  *
  * @see traceCoroutine
  */
-inline fun <T> runBlocking(
+public inline fun <T> runBlockingTraced(
     spanName: () -> String,
     context: CoroutineContext,
     noinline block: suspend CoroutineScope.() -> T,
@@ -111,29 +112,29 @@ inline fun <T> runBlocking(
  *
  * @see traceCoroutine
  */
-fun <T> runBlocking(
-    spanName: String,
+public fun <T> runBlockingTraced(
+    spanName: String? = null,
     context: CoroutineContext,
     block: suspend CoroutineScope.() -> T,
-): T = runBlocking(nameCoroutine(spanName) + context, block)
+): T = runBlockingTraced({ spanName ?: block::class.simpleName ?: "runBlocking" }, context, block)
 
 /**
  * Convenience function for calling [withContext] with [traceCoroutine] to enable tracing.
  *
  * @see traceCoroutine
  */
-suspend fun <T> withContext(
-    spanName: String,
+public suspend fun <T> withContextTraced(
+    spanName: String? = null,
     context: CoroutineContext,
     block: suspend CoroutineScope.() -> T,
-): T = withContext(nameCoroutine(spanName) + context, block)
+): T = withContextTraced({ spanName ?: block::class.simpleName ?: "withContext" }, context, block)
 
 /**
  * Convenience function for calling [withContext] with [traceCoroutine] to enable tracing.
  *
  * @see traceCoroutine
  */
-suspend inline fun <T> withContext(
+public suspend inline fun <T> withContextTraced(
     spanName: () -> String,
     context: CoroutineContext,
     noinline block: suspend CoroutineScope.() -> T,
@@ -143,41 +144,34 @@ suspend inline fun <T> withContext(
  * Traces a section of work of a `suspend` [block]. The trace sections will appear on the thread
  * that is currently executing the [block] of work. If the [block] is suspended, all trace sections
  * added using this API will end until the [block] is resumed, which could happen either on this
- * thread or on another thread. If a child coroutine is started, it will inherit the trace sections
- * of its parent. The child will continue to print these trace sections whether or not the parent
- * coroutine is still running them.
+ * thread or on another thread. If a child coroutine is started, it will *NOT* inherit the trace
+ * sections of its parent; however, it will include metadata in the trace section pointing to the
+ * parent.
  *
  * The current [CoroutineContext] must have a [TraceContextElement] for this API to work. Otherwise,
  * the trace sections will be dropped.
  *
- * For example, in the following trace, Thread #1 ran some work, suspended, then continued working
- * on Thread #2. Meanwhile, Thread #2 created a new child coroutine which inherited its trace
- * sections. Then, the original coroutine resumed on Thread #1 before ending. Meanwhile Thread #3 is
- * still printing trace sections from its parent because they were copied when it was created. There
- * is no way for the parent to communicate to the child that it marked these slices as completed.
- * While this might seem counterintuitive, it allows us to pinpoint the origin of the child
- * coroutine's work.
+ * For example, in the following trace, Thread #1 starts a coroutine, suspends, and continues the
+ * coroutine on Thread #2. Next, Thread #2 start a child coroutine in an unconfined manner. Then,
+ * still on Thread #2, the original coroutine suspends, the child resumes, and the child suspends.
+ * Then, the original coroutine resumes on Thread#1.
  *
  * ```
- * Thread #1 | [==== Slice A ====]                        [==== Slice A ====]
- *           |       [==== B ====]                        [=== B ===]
- * --------------------------------------------------------------------------------------
- * Thread #2 |                    [====== Slice A ======]
- *           |                    [========= B =========]
- *           |                        [===== C ======]
- * --------------------------------------------------------------------------------------
- * Thread #3 |                            [== Slice A ==]                [== Slice A ==]
- *           |                            [===== B =====]                [===== B =====]
- *           |                            [===== C =====]                [===== C =====]
- *           |                                                               [=== D ===]
+ * -----------------------------------------------------------------------------------------------|
+ * Thread #1 | [== Slice A ==]                                            [==== Slice A ====]
+ *           |       [== B ==]                                            [=== B ===]
+ * -----------------------------------------------------------------------------------------------|
+ * Thread #2 |                     [==== Slice A ====]    [=== C ====]
+ *           |                     [======= B =======]
+ *           |                         [=== C ====]
+ * -----------------------------------------------------------------------------------------------|
  * ```
  *
- * @param name The name of the code section to appear in the trace
- * @see endSlice
+ * @param spanName The name of the code section to appear in the trace
  * @see traceCoroutine
  */
 @OptIn(ExperimentalContracts::class)
-inline fun <T> traceCoroutine(spanName: () -> String, block: () -> T): T {
+public inline fun <T> traceCoroutine(spanName: () -> String, block: () -> T): T {
     contract {
         callsInPlace(spanName, InvocationKind.AT_MOST_ONCE)
         callsInPlace(block, InvocationKind.EXACTLY_ONCE)
@@ -196,5 +190,5 @@ inline fun <T> traceCoroutine(spanName: () -> String, block: () -> T): T {
 }
 
 /** @see traceCoroutine */
-inline fun <T> traceCoroutine(spanName: String, block: () -> T): T =
+public inline fun <T> traceCoroutine(spanName: String, block: () -> T): T =
     traceCoroutine({ spanName }, block)
diff --git a/tracinglib/core/src/coroutines/TraceContextElement.kt b/tracinglib/core/src/coroutines/TraceContextElement.kt
index 240bef1..3e87e18 100644
--- a/tracinglib/core/src/coroutines/TraceContextElement.kt
+++ b/tracinglib/core/src/coroutines/TraceContextElement.kt
@@ -17,129 +17,241 @@
 package com.android.app.tracing.coroutines
 
 import android.annotation.SuppressLint
+import android.os.SystemProperties
 import android.os.Trace
 import android.util.Log
-import androidx.annotation.VisibleForTesting
 import com.android.systemui.Flags
+import java.lang.StackWalker.StackFrame
+import java.util.concurrent.ThreadLocalRandom
 import java.util.concurrent.atomic.AtomicInteger
-import kotlin.coroutines.AbstractCoroutineContextKey
+import java.util.stream.Stream
+import kotlin.contracts.ExperimentalContracts
+import kotlin.contracts.InvocationKind
+import kotlin.contracts.contract
 import kotlin.coroutines.CoroutineContext
 import kotlin.coroutines.EmptyCoroutineContext
-import kotlin.coroutines.getPolymorphicElement
-import kotlin.coroutines.minusPolymorphicKey
 import kotlinx.coroutines.CopyableThreadContextElement
+import kotlinx.coroutines.CoroutineScope
 import kotlinx.coroutines.DelicateCoroutinesApi
 import kotlinx.coroutines.ExperimentalCoroutinesApi
 
 /** Use a final subclass to avoid virtual calls (b/316642146). */
-class TraceDataThreadLocal : ThreadLocal<TraceData?>()
+@PublishedApi internal class TraceDataThreadLocal : ThreadLocal<TraceData?>()
 
 /**
- * Thread-local storage for giving each thread a unique [TraceData]. It can only be used when paired
- * with a [TraceContextElement].
+ * Thread-local storage for tracking open trace sections in the current coroutine context; it should
+ * only be used when paired with a [TraceContextElement].
  *
- * [traceThreadLocal] will be `null` if either 1) we aren't in a coroutine, or 2) the current
- * coroutine context does not have [TraceContextElement]. In both cases, writing to this
- * thread-local would be undefined behavior if it were not null, which is why we use null as the
- * default value rather than an empty TraceData.
+ * [traceThreadLocal] will be `null` if the code being executed is either 1) not part of coroutine,
+ * or 2) part of a coroutine that does not have a [TraceContextElement] in its context. In both
+ * cases, writing to this thread-local will result in undefined behavior. However, it is safe to
+ * check if [traceThreadLocal] is `null` to determine if coroutine tracing is enabled.
  *
  * @see traceCoroutine
  */
-val traceThreadLocal = TraceDataThreadLocal()
+@PublishedApi internal val traceThreadLocal: TraceDataThreadLocal = TraceDataThreadLocal()
+
+private val alwaysEnableStackWalker: Boolean by lazy {
+    SystemProperties.getBoolean("debug.coroutine_tracing.walk_stack_override", false)
+}
 
 /**
- * Returns a new [CoroutineContext] used for tracing. Used to hide internal implementation details.
+ * Returns a new [TraceContextElement] (or [EmptyCoroutineContext] if `coroutine_tracing` feature is
+ * flagged off). This context should only be installed on root coroutines (e.g. when constructing a
+ * `CoroutineScope`). The context will be copied automatically to child scopes and thus should not
+ * be passed to children explicitly.
+ *
+ * [TraceContextElement] should be installed on the root, and [CoroutineTraceName] on the children.
+ *
+ * For example, the following snippet will add trace sections to indicate that `C` is a child of
+ * `B`, and `B` was started by `A`. Perfetto will post-process this information to show that: `A ->
+ * B -> C`
+ *
+ * ```
+ * val scope = CoroutineScope(createCoroutineTracingContext("A")
+ * scope.launch(nameCoroutine("B")) {
+ *     // ...
+ *     launch(nameCoroutine("C")) {
+ *         // ...
+ *     }
+ *     // ...
+ * }
+ * ```
+ *
+ * **NOTE:** The sysprop `debug.coroutine_tracing.walk_stack_override` can be used to override the
+ * `walkStackForDefaultNames` parameter, forcing it to always be `true`. If the sysprop is `false`
+ * (or does not exist), the value of `walkStackForDefaultNames` is used, whether `true` or `false`.
+ *
+ * @param name the name of the coroutine scope. Since this should only be installed on top-level
+ *   coroutines, this should be the name of the root [CoroutineScope].
+ * @param walkStackForDefaultNames whether to walk the stack and use the class name of the current
+ *   suspending function if child does not have a name that was manually specified. Walking the
+ *   stack is very expensive so this should not be used in production.
+ * @param includeParentNames whether to concatenate parent names and sibling counts with the name of
+ *   the child. This should only be used for testing because it can result in extremely long trace
+ *   names.
+ * @param strictMode whether to add additional checks to coroutine tracing machinery. These checks
+ *   are expensive and should only be used for testing.
+ * @param shouldIgnoreClassName lambda that takes binary class name (as returned from
+ *   [StackFrame.getClassName] and returns true if it should be ignored (e.g. search for relevant
+ *   class name should continue) or false otherwise
  */
-fun createCoroutineTracingContext(name: String = "UnnamedScope"): CoroutineContext =
-    if (Flags.coroutineTracing()) TraceContextElement(name) else EmptyCoroutineContext
+public fun createCoroutineTracingContext(
+    name: String = "UnnamedScope",
+    walkStackForDefaultNames: Boolean = false,
+    includeParentNames: Boolean = false,
+    strictMode: Boolean = false,
+    shouldIgnoreClassName: (String) -> Boolean = { false },
+): CoroutineContext {
+    return if (Flags.coroutineTracing()) {
+        TraceContextElement(
+            name = name,
+            // Minor perf optimization: no need to create TraceData() for root scopes since all
+            // launches require creation of child via [copyForChild] or [mergeForChild].
+            contextTraceData = null,
+            inheritedTracePrefix = "",
+            coroutineDepth = 0,
+            parentId = -1,
+            TraceConfig(
+                walkStackForDefaultNames = walkStackForDefaultNames || alwaysEnableStackWalker,
+                includeParentNames = includeParentNames,
+                strictMode = strictMode,
+                shouldIgnoreClassName = shouldIgnoreClassName,
+            ),
+        )
+    } else {
+        EmptyCoroutineContext
+    }
+}
 
-fun nameCoroutine(name: String): CoroutineContext =
-    if (Flags.coroutineTracing()) CoroutineTraceName(name) else EmptyCoroutineContext
+/**
+ * Returns a new [CoroutineTraceName] (or [EmptyCoroutineContext] if `coroutine_tracing` feature is
+ * flagged off). When the current [CoroutineScope] has a [TraceContextElement] installed,
+ * [CoroutineTraceName] can be used to name the child scope under construction.
+ *
+ * [TraceContextElement] should be installed on the root, and [CoroutineTraceName] on the children.
+ */
+public fun nameCoroutine(name: String): CoroutineContext = nameCoroutine { name }
 
-inline fun nameCoroutine(name: () -> String): CoroutineContext =
-    if (Flags.coroutineTracing()) CoroutineTraceName(name()) else EmptyCoroutineContext
+/**
+ * Returns a new [CoroutineTraceName] (or [EmptyCoroutineContext] if `coroutine_tracing` feature is
+ * flagged off). When the current [CoroutineScope] has a [TraceContextElement] installed,
+ * [CoroutineTraceName] can be used to name the child scope under construction.
+ *
+ * [TraceContextElement] should be installed on the root, and [CoroutineTraceName] on the children.
+ *
+ * @param name lazy string to only be called if feature is enabled
+ */
+@OptIn(ExperimentalContracts::class)
+public inline fun nameCoroutine(name: () -> String): CoroutineContext {
+    contract { callsInPlace(name, InvocationKind.AT_MOST_ONCE) }
+    return if (Flags.coroutineTracing()) CoroutineTraceName(name()) else EmptyCoroutineContext
+}
 
-open class BaseTraceElement : CoroutineContext.Element {
-    companion object Key : CoroutineContext.Key<BaseTraceElement>
+/**
+ * Common base class of [TraceContextElement] and [CoroutineTraceName]. For internal use only.
+ *
+ * [TraceContextElement] should be installed on the root, and [CoroutineTraceName] on the children.
+ *
+ * @property name the name of the current coroutine
+ */
+/**
+ * A coroutine context element that can be used for naming the child coroutine under construction.
+ *
+ * @property name the name to be used for the child under construction
+ * @see nameCoroutine
+ */
+@PublishedApi
+internal open class CoroutineTraceName(internal val name: String) : CoroutineContext.Element {
+    internal companion object Key : CoroutineContext.Key<CoroutineTraceName>
 
-    override val key: CoroutineContext.Key<*>
+    public override val key: CoroutineContext.Key<*>
         get() = Key
 
-    // It is important to use getPolymorphicKey and minusPolymorphicKey
-    @OptIn(ExperimentalStdlibApi::class)
-    override fun <E : CoroutineContext.Element> get(key: CoroutineContext.Key<E>): E? =
-        getPolymorphicElement(key)
-
-    @OptIn(ExperimentalStdlibApi::class)
-    override fun minusKey(key: CoroutineContext.Key<*>): CoroutineContext = minusPolymorphicKey(key)
+    protected val currentId: Int = ThreadLocalRandom.current().nextInt(1, Int.MAX_VALUE)
 
-    @Suppress("DeprecatedCallableAddReplaceWith")
     @Deprecated(
         message =
-            "Operator `+` on two BaseTraceElement objects is meaningless. " +
-                "If used, the context element to the right of `+` would simply replace the " +
-                "element to the left. To properly use `BaseTraceElement`, `CoroutineTraceName` " +
-                "should be used when creating a top-level `CoroutineScope`, " +
-                "and `TraceContextElement` should be passed to the child context " +
-                "that is under construction.",
+            """
+         Operator `+` on two BaseTraceElement objects is meaningless. If used, the context element
+         to the right of `+` would simply replace the element to the left. To properly use
+         `BaseTraceElement`, `TraceContextElement` should be used when creating a top-level
+         `CoroutineScope` and `CoroutineTraceName` should be passed to the child context that is
+         under construction.
+        """,
         level = DeprecationLevel.ERROR,
     )
-    operator fun plus(other: BaseTraceElement): BaseTraceElement = other
-}
+    public operator fun plus(other: CoroutineTraceName): CoroutineTraceName {
+        debug { "#plus(${other.currentId})" }
+        return other
+    }
 
-class CoroutineTraceName(val name: String) : BaseTraceElement() {
-    @OptIn(ExperimentalStdlibApi::class)
-    companion object Key :
-        AbstractCoroutineContextKey<BaseTraceElement, CoroutineTraceName>(
-            BaseTraceElement,
-            { it as? CoroutineTraceName },
-        )
+    @OptIn(ExperimentalContracts::class)
+    protected inline fun debug(message: () -> String) {
+        contract { callsInPlace(message, InvocationKind.AT_MOST_ONCE) }
+        if (DEBUG) Log.d(TAG, "${this::class.java.simpleName}@$currentId${message()}")
+    }
 }
 
-const val ROOT_SCOPE = 0
+internal data class TraceConfig(
+    val walkStackForDefaultNames: Boolean,
+    val includeParentNames: Boolean,
+    val strictMode: Boolean,
+    val shouldIgnoreClassName: (String) -> Boolean,
+)
 
 /**
- * Used for safely persisting [TraceData] state when coroutines are suspended and resumed.
+ * Used for tracking parent-child relationship of coroutines and persisting [TraceData] when
+ * coroutines are suspended and resumed.
  *
- * This is internal machinery for [traceCoroutine]. It cannot be made `internal` or `private`
- * because [traceCoroutine] is a Public-API inline function.
+ * This is internal machinery for [traceCoroutine] and should not be used directly.
  *
+ * @param name the name of the current coroutine. Since this should only be installed on top-level
+ *   coroutines, this should be the name of the root [CoroutineScope].
+ * @property contextTraceData [TraceData] to be saved to thread-local storage.
+ * @param inheritedTracePrefix prefix containing metadata for parent scopes. Each child is separated
+ *   by a `:` and prefixed by a counter indicating the ordinal of this child relative to its
+ *   siblings. Thus, the prefix such as `root-name:3^child-name` would indicate this is the 3rd
+ *   child (of any name) to be started on `root-scope`. If the child has no name, an empty string
+ *   would be used instead: `root-scope:3^`
+ * @property coroutineDepth how deep the coroutine is relative to the top-level [CoroutineScope]
+ *   containing the original [TraceContextElement] from which this [TraceContextElement] was copied.
+ * @param parentId the ID of the parent coroutine, as defined in [BaseTraceElement]
+ * @param walkStackForDefaultNames whether to walk the stack and use the class name of the current
+ *   suspending function if child does not have a name that was manually specified. Walking the
+ *   stack is very expensive so this should not be used in production.
+ * @param includeParentNames whether to concatenate parent names and sibling counts with the name of
+ *   the child. This should only be used for testing because it can result in extremely long trace
+ *   names.
+ * @param strictMode whether to add additional checks to coroutine machinery. These checks are
+ *   expensive and should only be used for testing.
+ * @param shouldIgnoreClassName lambda that takes binary class name (as returned from
+ *   [StackFrame.getClassName] and returns true if it should be ignored (e.g. search for relevant
+ *   class name should continue) or false otherwise
+ * @see createCoroutineTracingContext
+ * @see nameCoroutine
  * @see traceCoroutine
  */
 @OptIn(DelicateCoroutinesApi::class, ExperimentalCoroutinesApi::class)
-@VisibleForTesting(otherwise = VisibleForTesting.PACKAGE_PRIVATE)
-class TraceContextElement
-private constructor(
-    coroutineTraceName: String,
+internal class TraceContextElement(
+    name: String,
+    internal val contextTraceData: TraceData?,
     inheritedTracePrefix: String,
-    @get:VisibleForTesting(otherwise = VisibleForTesting.PACKAGE_PRIVATE)
-    val contextTraceData: TraceData?,
-    private val coroutineDepth: Int, // depth relative to first TraceContextElement
+    private val coroutineDepth: Int,
     parentId: Int,
-) : CopyableThreadContextElement<TraceData?>, BaseTraceElement() {
-
-    @OptIn(ExperimentalStdlibApi::class)
-    companion object Key :
-        AbstractCoroutineContextKey<BaseTraceElement, TraceContextElement>(
-            BaseTraceElement,
-            { it as? TraceContextElement },
-        )
-
-    /**
-     * Minor perf optimization: no need to create TraceData() for root scopes since all launches
-     * require creation of child via [copyForChild] or [mergeForChild].
-     */
-    constructor(scopeName: String) : this(scopeName, "", null, 0, ROOT_SCOPE)
+    private val config: TraceConfig,
+) : CopyableThreadContextElement<TraceData?>, CoroutineTraceName(name) {
 
     private var childCoroutineCount = AtomicInteger(0)
-    private val currentId = hashCode()
 
-    private val fullCoroutineTraceName = "$inheritedTracePrefix$coroutineTraceName"
+    private val fullCoroutineTraceName =
+        if (config.includeParentNames) "$inheritedTracePrefix$name" else ""
     private val continuationTraceMessage =
-        "$fullCoroutineTraceName;$coroutineTraceName;d=$coroutineDepth;c=$currentId;p=$parentId"
+        "$fullCoroutineTraceName;$name;d=$coroutineDepth;c=$currentId;p=$parentId"
 
     init {
-        debug { "#init" }
+        debug { "#init: name=$name" }
+        Trace.instant(Trace.TRACE_TAG_APP, continuationTraceMessage)
     }
 
     /**
@@ -158,7 +270,7 @@ private constructor(
      * `^` is a suspension point)
      */
     @SuppressLint("UnclosedTrace")
-    override fun updateThreadContext(context: CoroutineContext): TraceData? {
+    public override fun updateThreadContext(context: CoroutineContext): TraceData? {
         val oldState = traceThreadLocal.get()
         debug { "#updateThreadContext oldState=$oldState" }
         if (oldState !== contextTraceData) {
@@ -200,7 +312,7 @@ private constructor(
      *
      * ```
      */
-    override fun restoreThreadContext(context: CoroutineContext, oldState: TraceData?) {
+    public override fun restoreThreadContext(context: CoroutineContext, oldState: TraceData?) {
         debug { "#restoreThreadContext restoring=$oldState" }
         // We not use the `TraceData` object here because it may have been modified on another
         // thread after the last suspension point. This is why we use a [TraceStateHolder]:
@@ -213,42 +325,82 @@ private constructor(
         }
     }
 
-    override fun copyForChild(): CopyableThreadContextElement<TraceData?> {
+    public override fun copyForChild(): CopyableThreadContextElement<TraceData?> {
         debug { "#copyForChild" }
         return createChildContext()
     }
 
-    override fun mergeForChild(overwritingElement: CoroutineContext.Element): CoroutineContext {
+    public override fun mergeForChild(
+        overwritingElement: CoroutineContext.Element
+    ): CoroutineContext {
         debug { "#mergeForChild" }
-        val otherTraceContext = overwritingElement[TraceContextElement]
-        if (DEBUG && otherTraceContext != null) {
-            Log.e(
-                TAG,
-                UNEXPECTED_TRACE_DATA_ERROR_MESSAGE +
-                    "Current CoroutineContext.Element=$fullCoroutineTraceName, other CoroutineContext.Element=${otherTraceContext.fullCoroutineTraceName}",
-            )
+        if (DEBUG) {
+            (overwritingElement as? TraceContextElement)?.let {
+                Log.e(
+                    TAG,
+                    "${this::class.java.simpleName}@$currentId#mergeForChild(@${it.currentId}): " +
+                        "current name=\"$name\", overwritingElement name=\"${it.name}\". " +
+                        UNEXPECTED_TRACE_DATA_ERROR_MESSAGE,
+                )
+            }
         }
-        return createChildContext(overwritingElement[CoroutineTraceName]?.name ?: "")
+        val nameForChild = (overwritingElement as CoroutineTraceName).name
+        return createChildContext(nameForChild)
     }
 
-    private fun createChildContext(coroutineTraceName: String = ""): TraceContextElement {
+    private fun createChildContext(
+        name: String =
+            if (config.walkStackForDefaultNames) walkStackForClassName(config.shouldIgnoreClassName)
+            else ""
+    ): TraceContextElement {
+        debug { "#createChildContext: \"$name\" has new child with name \"${name}\"" }
         val childCount = childCoroutineCount.incrementAndGet()
         return TraceContextElement(
-            coroutineTraceName,
-            "$fullCoroutineTraceName:$childCount^",
-            TraceData(),
-            coroutineDepth + 1,
-            currentId,
+            name = name,
+            contextTraceData = TraceData(config.strictMode),
+            inheritedTracePrefix =
+                if (config.includeParentNames) "$fullCoroutineTraceName:$childCount^" else "",
+            coroutineDepth = coroutineDepth + 1,
+            parentId = currentId,
+            config = config,
         )
     }
+}
 
-    private inline fun debug(message: () -> String) {
-        if (DEBUG) Log.d(TAG, "@$currentId ${message()} $contextTraceData")
+/**
+ * Get a name for the trace section include the name of the call site.
+ *
+ * @param additionalDropPredicate additional checks for whether class should be ignored
+ */
+private fun walkStackForClassName(
+    additionalDropPredicate: (String) -> Boolean = { false }
+): String {
+    Trace.traceBegin(Trace.TRACE_TAG_APP, "walkStackForClassName")
+    try {
+        var frame = ""
+        StackWalker.getInstance().walk { s: Stream<StackFrame> ->
+            s.dropWhile { f: StackFrame ->
+                    val className = f.className
+                    className.startsWith("kotlin") ||
+                        className.startsWith("com.android.app.tracing.") ||
+                        additionalDropPredicate(className)
+                }
+                .findFirst()
+                .ifPresent { frame = it.className.substringAfterLast(".") + "." + it.methodName }
+        }
+        return frame
+    } catch (e: Exception) {
+        if (DEBUG) Log.e(TAG, "Error walking stack to infer a trace name", e)
+        return ""
+    } finally {
+        Trace.traceEnd(Trace.TRACE_TAG_APP)
     }
 }
 
 private const val UNEXPECTED_TRACE_DATA_ERROR_MESSAGE =
     "Overwriting context element with non-empty trace data. There should only be one " +
         "TraceContextElement per coroutine, and it should be installed in the root scope. "
-private const val TAG = "TraceContextElement"
-internal const val DEBUG = false
+
+@PublishedApi internal const val TAG: String = "CoroutineTracing"
+
+@PublishedApi internal const val DEBUG: Boolean = false
diff --git a/tracinglib/core/src/coroutines/TraceData.kt b/tracinglib/core/src/coroutines/TraceData.kt
index 8dabea4..49cea0d 100644
--- a/tracinglib/core/src/coroutines/TraceData.kt
+++ b/tracinglib/core/src/coroutines/TraceData.kt
@@ -16,7 +16,6 @@
 
 package com.android.app.tracing.coroutines
 
-import androidx.annotation.VisibleForTesting
 import com.android.app.tracing.beginSlice
 import com.android.app.tracing.endSlice
 import java.util.ArrayDeque
@@ -27,9 +26,9 @@ import java.util.ArrayDeque
  *
  * @see traceCoroutine
  */
-typealias TraceSection = String
+private typealias TraceSection = String
 
-class TraceCountThreadLocal : ThreadLocal<Int>() {
+private class TraceCountThreadLocal : ThreadLocal<Int>() {
     override fun initialValue(): Int {
         return 0
     }
@@ -39,12 +38,15 @@ class TraceCountThreadLocal : ThreadLocal<Int>() {
  * Used for storing trace sections so that they can be added and removed from the currently running
  * thread when the coroutine is suspended and resumed.
  *
+ * @property strictMode Whether to add additional checks to the coroutine machinery, throwing a
+ *   `ConcurrentModificationException` if TraceData is modified from the wrong thread. This should
+ *   only be set for testing.
  * @see traceCoroutine
  */
-@VisibleForTesting(otherwise = VisibleForTesting.PACKAGE_PRIVATE)
-class TraceData {
+@PublishedApi
+internal class TraceData(private val strictMode: Boolean) {
 
-    var slices: ArrayDeque<TraceSection>? = null
+    internal var slices: ArrayDeque<TraceSection>? = null
 
     /**
      * ThreadLocal counter for how many open trace sections there are. This is needed because it is
@@ -57,7 +59,7 @@ class TraceData {
     private val openSliceCount = TraceCountThreadLocal()
 
     /** Adds current trace slices back to the current thread. Called when coroutine is resumed. */
-    fun beginAllOnThread() {
+    internal fun beginAllOnThread() {
         strictModeCheck()
         slices?.descendingIterator()?.forEach { beginSlice(it) }
         openSliceCount.set(slices?.size ?: 0)
@@ -66,7 +68,7 @@ class TraceData {
     /**
      * Removes all current trace slices from the current thread. Called when coroutine is suspended.
      */
-    fun endAllOnThread() {
+    internal fun endAllOnThread() {
         strictModeCheck()
         repeat(openSliceCount.get() ?: 0) { endSlice() }
         openSliceCount.set(0)
@@ -78,7 +80,8 @@ class TraceData {
      * coroutines, or to child coroutines that have already started. The unique ID is used to verify
      * that the [endSpan] is corresponds to a [beginSpan].
      */
-    fun beginSpan(name: String) {
+    @PublishedApi
+    internal fun beginSpan(name: String) {
         strictModeCheck()
         if (slices == null) {
             slices = ArrayDeque()
@@ -93,36 +96,30 @@ class TraceData {
      * trace slice will immediately be removed from the current thread. This information will not
      * propagate to parent coroutines, or to child coroutines that have already started.
      */
-    fun endSpan() {
+    @PublishedApi
+    internal fun endSpan() {
         strictModeCheck()
         // Should never happen, but we should be defensive rather than crash the whole application
         if (slices != null && slices!!.size > 0) {
             slices!!.pop()
             openSliceCount.set(slices!!.size)
             endSlice()
-        } else if (STRICT_MODE_FOR_TESTING) {
+        } else if (strictMode) {
             throw IllegalStateException(INVALID_SPAN_END_CALL_ERROR_MESSAGE)
         }
     }
 
-    override fun toString(): String =
+    public override fun toString(): String =
         if (DEBUG) "{${slices?.joinToString(separator = "\", \"", prefix = "\"", postfix = "\"")}}"
         else super.toString()
 
     private fun strictModeCheck() {
-        if (STRICT_MODE_FOR_TESTING && traceThreadLocal.get() !== this) {
+        if (strictMode && traceThreadLocal.get() !== this) {
             throw ConcurrentModificationException(STRICT_MODE_ERROR_MESSAGE)
         }
     }
 }
 
-/**
- * Whether to add additional checks to the coroutine machinery, throwing a
- * `ConcurrentModificationException` if TraceData is modified from the wrong thread. This should
- * only be set for testing.
- */
-var STRICT_MODE_FOR_TESTING: Boolean = false
-
 private const val INVALID_SPAN_END_CALL_ERROR_MESSAGE =
     "TraceData#endSpan called when there were no active trace sections in its scope."
 
@@ -130,5 +127,3 @@ private const val STRICT_MODE_ERROR_MESSAGE =
     "TraceData should only be accessed using " +
         "the ThreadLocal: CURRENT_TRACE.get(). Accessing TraceData by other means, such as " +
         "through the TraceContextElement's property may lead to concurrent modification."
-
-@OptIn(ExperimentalStdlibApi::class) val hexFormatForId = HexFormat { number.prefix = "0x" }
diff --git a/tracinglib/core/src/coroutines/flow/FlowExt.kt b/tracinglib/core/src/coroutines/flow/FlowExt.kt
index ec693c3..0a41e37 100644
--- a/tracinglib/core/src/coroutines/flow/FlowExt.kt
+++ b/tracinglib/core/src/coroutines/flow/FlowExt.kt
@@ -16,120 +16,182 @@
 
 package com.android.app.tracing.coroutines.flow
 
-import android.os.Trace
-import com.android.app.tracing.coroutines.CoroutineTraceName
+import com.android.app.tracing.coroutines.nameCoroutine
 import com.android.app.tracing.coroutines.traceCoroutine
-import kotlin.coroutines.CoroutineContext
+import com.android.systemui.Flags
 import kotlin.experimental.ExperimentalTypeInference
-import kotlinx.coroutines.CoroutineDispatcher
-import kotlinx.coroutines.CoroutineName
 import kotlinx.coroutines.flow.Flow
 import kotlinx.coroutines.flow.FlowCollector
-import kotlinx.coroutines.flow.collectLatest as kx_collectLatest
-import kotlinx.coroutines.flow.filter as kx_filter
-import kotlinx.coroutines.flow.filterIsInstance as kx_filterIsInstance
-import kotlinx.coroutines.flow.flowOn as kx_flowOn
-import kotlinx.coroutines.flow.map as kx_map
+import kotlinx.coroutines.flow.SharedFlow
+import kotlinx.coroutines.flow.collect
+import kotlinx.coroutines.flow.collectLatest
+import kotlinx.coroutines.flow.filter
+import kotlinx.coroutines.flow.flow as safeFlow
+import kotlinx.coroutines.flow.flowOn
+import kotlinx.coroutines.flow.map
+import kotlinx.coroutines.flow.transform
 
-fun <T> Flow<T>.withTraceName(name: String?): Flow<T> {
+/** @see kotlinx.coroutines.flow.internal.unsafeFlow */
+@PublishedApi
+internal inline fun <T> unsafeFlow(
+    crossinline block: suspend FlowCollector<T>.() -> Unit
+): Flow<T> {
     return object : Flow<T> {
         override suspend fun collect(collector: FlowCollector<T>) {
-            this@withTraceName.collect(name ?: walkStackForClassName(), collector)
+            collector.block()
         }
     }
 }
 
+/** @see kotlinx.coroutines.flow.unsafeTransform */
+@PublishedApi
+internal inline fun <T, R> Flow<T>.unsafeTransform(
+    crossinline transform: suspend FlowCollector<R>.(value: T) -> Unit
+): Flow<R> = unsafeFlow { collect { value -> transform(value) } }
+
 /**
- * NOTE: We cannot use a default value for the String name because [Flow.collect] is a member
- * function. When an extension function has the same receiver type, name, and applicable arguments
- * as a class member function, the member takes precedence.
+ * Helper for naming the coroutine a flow is collected in. This only has an effect if the flow
+ * changes contexts (e.g. `flowOn()` is used to change the dispatcher), meaning a new coroutine is
+ * created during collection.
+ *
+ * For example, the following would `emit(1)` from a trace section named "a" and collect in section
+ * named "b".
+ *
+ * ```
+ *   launch(nameCoroutine("b") {
+ *     val flow {
+ *       emit(1)
+ *     }
+ *     .flowName("a")
+ *     .flowOn(Dispatchers.Default)
+ *     .collect {
+ *     }
+ *   }
+ * ```
  */
-@OptIn(ExperimentalTypeInference::class)
-suspend inline fun <T> Flow<T>.collect(
-    name: String, /* cannot have a default parameter or else Flow#collect() override this call */
-    @BuilderInference block: FlowCollector<T>,
-) {
-    val (collectSlice, emitSlice) = getFlowSliceNames(name)
-    traceCoroutine(collectSlice) {
-        collect { value -> traceCoroutine(emitSlice) { block.emit(value) } }
-    }
-}
+public fun <T> Flow<T>.flowName(name: String): Flow<T> = flowOn(nameCoroutine(name))
 
-@OptIn(ExperimentalTypeInference::class)
-suspend inline fun <T> Flow<T>.collectTraced(@BuilderInference block: FlowCollector<T>) {
-    collect(walkStackForClassName(), block)
-}
+/**
+ * Applying [flowName][Flow.flowName] to [SharedFlow] has no effect. See the [SharedFlow]
+ * documentation on Operator Fusion.
+ *
+ * @see SharedFlow.flowOn
+ */
+@Deprecated(
+    level = DeprecationLevel.ERROR,
+    message =
+        "Applying 'flowName' to SharedFlow has no effect. See the SharedFlow documentation on Operator Fusion.",
+    replaceWith = ReplaceWith("this"),
+)
+@Suppress("UnusedReceiverParameter")
+public fun <T> SharedFlow<T>.flowName(@Suppress("UNUSED_PARAMETER") name: String): Flow<T> =
+    throw UnsupportedOperationException("Not implemented, should not be called")
 
-suspend fun <T> Flow<T>.collectLatest(name: String? = null, action: suspend (T) -> Unit) {
-    val (collectSlice, emitSlice) = getFlowSliceNames(name)
-    traceCoroutine(collectSlice) {
-        kx_collectLatest { value -> traceCoroutine(emitSlice) { action(value) } }
+/**
+ * NOTE: [Flow.collect] is a member function and takes precedence if this function is imported as
+ * `collect` and the default parameter is used. (In Kotlin, when an extension function has the same
+ * receiver type, name, and applicable arguments as a class member function, the member takes
+ * precedence).
+ *
+ * For example,
+ * ```
+ * import com.android.app.tracing.coroutines.flow.collectTraced as collect
+ * ...
+ * flowOf(1).collect { ... } // this will call `Flow.collect`
+ * flowOf(1).collect(null) { ... } // this will call `collectTraced`
+ * ```
+ */
+public suspend fun <T> Flow<T>.collectTraced(name: String, collector: FlowCollector<T>) {
+    if (Flags.coroutineTracing()) {
+        val collectName = "collect:$name"
+        val emitName = "$collectName:emit"
+        traceCoroutine(collectName) { collect { traceCoroutine(emitName) { collector.emit(it) } } }
+    } else {
+        collect(collector)
     }
 }
 
-@OptIn(ExperimentalStdlibApi::class)
-fun <T> Flow<T>.flowOn(context: CoroutineContext): Flow<T> {
-    val contextName =
-        context[CoroutineTraceName]?.name
-            ?: context[CoroutineName]?.name
-            ?: context[CoroutineDispatcher]?.javaClass?.simpleName
-            ?: context.javaClass.simpleName
-    return kx_flowOn(context).withTraceName("flowOn($contextName)")
-}
-
-inline fun <T> Flow<T>.filter(
-    name: String? = null,
-    crossinline predicate: suspend (T) -> Boolean,
-): Flow<T> {
-    val flowName = name ?: walkStackForClassName()
-    return withTraceName(flowName).kx_filter {
-        return@kx_filter traceCoroutine("$flowName:predicate") { predicate(it) }
+/** @see Flow.collectTraced */
+public suspend fun <T> Flow<T>.collectTraced(collector: FlowCollector<T>) {
+    if (Flags.coroutineTracing()) {
+        collectTraced(
+            name = collector::class.java.name.substringAfterLast("."),
+            collector = collector,
+        )
+    } else {
+        collect(collector)
     }
 }
 
-inline fun <reified R> Flow<*>.filterIsInstance(): Flow<R> {
-    return kx_filterIsInstance<R>().withTraceName("${walkStackForClassName()}#filterIsInstance")
-}
-
-inline fun <T, R> Flow<T>.map(
-    name: String? = null,
-    crossinline transform: suspend (T) -> R,
-): Flow<R> {
-    val flowName = name ?: walkStackForClassName()
-    return withTraceName(flowName).kx_map {
-        return@kx_map traceCoroutine("$flowName:transform") { transform(it) }
+internal suspend fun <T> Flow<T>.collectLatestTraced(
+    name: String,
+    action: suspend (value: T) -> Unit,
+) {
+    if (Flags.coroutineTracing()) {
+        val collectName = "collectLatest:$name"
+        val actionName = "$collectName:action"
+        return traceCoroutine(collectName) {
+            collectLatest { traceCoroutine(actionName) { action(it) } }
+        }
+    } else {
+        collectLatest(action)
     }
 }
 
-fun getFlowSliceNames(name: String?): Pair<String, String> {
-    val flowName = name ?: walkStackForClassName()
-    return Pair("$flowName:collect", "$flowName:emit")
+public suspend fun <T> Flow<T>.collectLatestTraced(action: suspend (value: T) -> Unit) {
+    if (Flags.coroutineTracing()) {
+        collectLatestTraced(action::class.java.name.substringAfterLast("."), action)
+    } else {
+        collectLatest(action)
+    }
 }
 
-object FlowExt {
-    val currentFileName: String =
-        StackWalker.getInstance().walk { stream -> stream.limit(1).findFirst() }.get().fileName
-}
+/** @see kotlinx.coroutines.flow.transform */
+@OptIn(ExperimentalTypeInference::class)
+public inline fun <T, R> Flow<T>.transformTraced(
+    name: String,
+    @BuilderInference crossinline transform: suspend FlowCollector<R>.(value: T) -> Unit,
+): Flow<R> =
+    if (Flags.coroutineTracing()) {
+        val emitName = "$name:emit"
+        safeFlow { collect { value -> traceCoroutine(emitName) { transform(value) } } }
+    } else {
+        transform(transform)
+    }
 
-private fun isFrameInteresting(frame: StackWalker.StackFrame): Boolean {
-    return frame.fileName != FlowExt.currentFileName
+public inline fun <T> Flow<T>.filterTraced(
+    name: String,
+    crossinline predicate: suspend (T) -> Boolean,
+): Flow<T> {
+    if (Flags.coroutineTracing()) {
+        val predicateName = "filter:$name:predicate"
+        val emitName = "filter:$name:emit"
+        return unsafeTransform { value ->
+            if (traceCoroutine(predicateName) { predicate(value) }) {
+                traceCoroutine(emitName) {
+                    return@unsafeTransform emit(value)
+                }
+            }
+        }
+    } else {
+        return filter(predicate)
+    }
 }
 
-/** Get a name for the trace section include the name of the call site. */
-fun walkStackForClassName(): String {
-    Trace.traceBegin(Trace.TRACE_TAG_APP, "FlowExt#walkStackForClassName")
-    try {
-        val interestingFrame =
-            StackWalker.getInstance().walk { stream ->
-                stream.filter(::isFrameInteresting).limit(5).findFirst()
+public inline fun <T, R> Flow<T>.mapTraced(
+    name: String,
+    crossinline transform: suspend (value: T) -> R,
+): Flow<R> {
+    if (Flags.coroutineTracing()) {
+        val transformName = "map:$name:transform"
+        val emitName = "map:$name:emit"
+        return unsafeTransform { value ->
+            val transformedValue = traceCoroutine(transformName) { transform(value) }
+            traceCoroutine(emitName) {
+                return@unsafeTransform emit(transformedValue)
             }
-        return if (interestingFrame.isPresent) {
-            val frame = interestingFrame.get()
-            return frame.className
-        } else {
-            "<unknown>"
         }
-    } finally {
-        Trace.traceEnd(Trace.TRACE_TAG_APP)
+    } else {
+        return map(transform)
     }
 }
diff --git a/tracinglib/demo/app-manifest.xml b/tracinglib/demo/app-manifest.xml
index 17c9d45..6db5580 100644
--- a/tracinglib/demo/app-manifest.xml
+++ b/tracinglib/demo/app-manifest.xml
@@ -14,7 +14,7 @@
      limitations under the License.
 -->
 <manifest xmlns:android="http://schemas.android.com/apk/res/android"
-        package="com.android.app.tracing.demo">
+        package="com.example.tracing.demo">
     <application
         android:name=".MainApplication"
         android:label="@string/app_name">
diff --git a/tracinglib/demo/res/layout/activity_main.xml b/tracinglib/demo/res/layout/activity_main.xml
index 79cde7d..432d958 100644
--- a/tracinglib/demo/res/layout/activity_main.xml
+++ b/tracinglib/demo/res/layout/activity_main.xml
@@ -18,6 +18,7 @@
     android:layout_width="match_parent"
     android:layout_height="match_parent"
     android:orientation="vertical"
+    android:layout_marginTop="40dp"
     tools:context=".MainActivity">
 
     <TextView
@@ -28,7 +29,7 @@
         android:textAppearance="@style/Title"/>
 
     <LinearLayout
-        android:id="@+id/button_container"
+        android:id="@+id/experiment_list"
         android:layout_width="wrap_content"
         android:layout_height="wrap_content"
         android:orientation="vertical" />
diff --git a/tracinglib/demo/res/layout/experiment_buttons.xml b/tracinglib/demo/res/layout/experiment_buttons.xml
new file mode 100644
index 0000000..26da571
--- /dev/null
+++ b/tracinglib/demo/res/layout/experiment_buttons.xml
@@ -0,0 +1,48 @@
+<?xml version="1.0" encoding="utf-8"?><!--
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
+<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:tools="http://schemas.android.com/tools"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    android:orientation="vertical">
+
+    <TextView android:id="@+id/description"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content" />
+
+    <LinearLayout
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        android:orientation="horizontal">
+
+        <Button
+            android:id="@+id/start_button"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:text="Start" />
+
+        <Button
+            android:id="@+id/cancel_button"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:text="Stop" />
+
+        <TextView android:id="@+id/current_state"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content" />
+
+    </LinearLayout>
+</LinearLayout>
\ No newline at end of file
diff --git a/tracinglib/demo/src/ApplicationComponent.kt b/tracinglib/demo/src/ApplicationComponent.kt
new file mode 100644
index 0000000..5a47064
--- /dev/null
+++ b/tracinglib/demo/src/ApplicationComponent.kt
@@ -0,0 +1,153 @@
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
+package com.example.tracing.demo
+
+import com.example.tracing.demo.experiments.CancellableSharedFlow
+import com.example.tracing.demo.experiments.CollectFlow
+import com.example.tracing.demo.experiments.CombineDeferred
+import com.example.tracing.demo.experiments.Experiment
+import com.example.tracing.demo.experiments.LaunchNested
+import com.example.tracing.demo.experiments.LaunchSequentially
+import com.example.tracing.demo.experiments.LeakySharedFlow
+import com.example.tracing.demo.experiments.SharedFlowUsage
+import com.example.tracing.demo.experiments.startThreadWithLooper
+import dagger.Binds
+import dagger.Component
+import dagger.Module
+import dagger.Provides
+import dagger.multibindings.ClassKey
+import dagger.multibindings.IntoMap
+import javax.inject.Provider
+import javax.inject.Qualifier
+import javax.inject.Singleton
+import kotlin.annotation.AnnotationRetention.RUNTIME
+import kotlinx.coroutines.CoroutineDispatcher
+import kotlinx.coroutines.Dispatchers
+import kotlinx.coroutines.android.asCoroutineDispatcher
+
+@Qualifier @MustBeDocumented @Retention(RUNTIME) annotation class Main
+
+@Qualifier @MustBeDocumented @Retention(RUNTIME) annotation class Default
+
+@Qualifier @MustBeDocumented @Retention(RUNTIME) annotation class IO
+
+@Qualifier @MustBeDocumented @Retention(RUNTIME) annotation class Unconfined
+
+@Qualifier @MustBeDocumented @Retention(RUNTIME) annotation class FixedThreadA
+
+@Qualifier @MustBeDocumented @Retention(RUNTIME) annotation class FixedThreadB
+
+@Qualifier @MustBeDocumented @Retention(RUNTIME) annotation class FixedThreadC
+
+@Qualifier @MustBeDocumented @Retention(RUNTIME) annotation class FixedThreadD
+
+@Module
+class ConcurrencyModule {
+
+    @Provides
+    @Singleton
+    @Default
+    fun provideDefaultDispatcher(): CoroutineDispatcher {
+        return Dispatchers.Default
+    }
+
+    @Provides
+    @Singleton
+    @IO
+    fun provideIODispatcher(): CoroutineDispatcher {
+        return Dispatchers.IO
+    }
+
+    @Provides
+    @Singleton
+    @Unconfined
+    fun provideUnconfinedDispatcher(): CoroutineDispatcher {
+        return Dispatchers.Unconfined
+    }
+
+    @Provides
+    @Singleton
+    @FixedThreadA
+    fun provideDispatcherA(): CoroutineDispatcher {
+        return startThreadWithLooper("Thread:A").threadHandler.asCoroutineDispatcher()
+    }
+
+    @Provides
+    @Singleton
+    @FixedThreadB
+    fun provideDispatcherB(): CoroutineDispatcher {
+        return startThreadWithLooper("Thread:B").threadHandler.asCoroutineDispatcher()
+    }
+
+    @Provides
+    @Singleton
+    @FixedThreadC
+    fun provideDispatcherC(): CoroutineDispatcher {
+        return startThreadWithLooper("Thread:C").threadHandler.asCoroutineDispatcher()
+    }
+
+    @Provides
+    @Singleton
+    @FixedThreadD
+    fun provideDispatcherD(): CoroutineDispatcher {
+        return startThreadWithLooper("Thread:D").threadHandler.asCoroutineDispatcher()
+    }
+}
+
+@Module
+interface ExperimentModule {
+    @Binds
+    @IntoMap
+    @ClassKey(CollectFlow::class)
+    fun bindCollectFlow(service: CollectFlow): Experiment
+
+    @Binds
+    @IntoMap
+    @ClassKey(SharedFlowUsage::class)
+    fun bindSharedFlowUsage(service: SharedFlowUsage): Experiment
+
+    @Binds
+    @IntoMap
+    @ClassKey(LeakySharedFlow::class)
+    fun bindLeakySharedFlow(service: LeakySharedFlow): Experiment
+
+    @Binds
+    @IntoMap
+    @ClassKey(CancellableSharedFlow::class)
+    fun bindCancellableSharedFlow(service: CancellableSharedFlow): Experiment
+
+    @Binds
+    @IntoMap
+    @ClassKey(CombineDeferred::class)
+    fun bindCombineDeferred(service: CombineDeferred): Experiment
+
+    @Binds
+    @IntoMap
+    @ClassKey(LaunchNested::class)
+    fun bindLaunchNested(service: LaunchNested): Experiment
+
+    @Binds
+    @IntoMap
+    @ClassKey(LaunchSequentially::class)
+    fun bindLaunchSequentially(service: LaunchSequentially): Experiment
+}
+
+@Singleton
+@Component(modules = [ConcurrencyModule::class, ExperimentModule::class])
+interface ApplicationComponent {
+    /** Returns [Experiment]s that should be used with the application. */
+    @Singleton fun getAllExperiments(): Map<Class<*>, Provider<Experiment>>
+}
diff --git a/tracinglib/demo/src/MainActivity.kt b/tracinglib/demo/src/MainActivity.kt
new file mode 100644
index 0000000..19c9f72
--- /dev/null
+++ b/tracinglib/demo/src/MainActivity.kt
@@ -0,0 +1,121 @@
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
+package com.example.tracing.demo
+
+import android.app.Activity
+import android.os.Bundle
+import android.os.Trace
+import android.view.LayoutInflater
+import android.view.View
+import android.view.ViewGroup
+import android.widget.Button
+import android.widget.LinearLayout
+import android.widget.ScrollView
+import android.widget.TextView
+import com.android.app.tracing.coroutines.createCoroutineTracingContext
+import com.example.tracing.demo.experiments.Experiment
+import com.example.tracing.demo.experiments.TRACK_NAME
+import kotlin.coroutines.cancellation.CancellationException
+import kotlin.random.Random
+import kotlinx.coroutines.CoroutineScope
+import kotlinx.coroutines.Dispatchers
+import kotlinx.coroutines.Job
+import kotlinx.coroutines.launch
+
+class MainActivity : Activity() {
+
+    private val allExperiments by lazy {
+        (applicationContext as MainApplication).appComponent.getAllExperiments()
+    }
+
+    val mainScope: CoroutineScope =
+        CoroutineScope(
+            Dispatchers.Main +
+                createCoroutineTracingContext("test-scope", walkStackForDefaultNames = true)
+        )
+
+    private var logContainer: ScrollView? = null
+    private var loggerView: TextView? = null
+
+    private fun <T : Experiment> connectButtonsForExperiment(demo: T, view: ViewGroup) {
+        val className = demo::class.simpleName
+        view.findViewById<TextView>(R.id.description).text =
+            baseContext.getString(R.string.run_experiment_button_text, className, demo.description)
+        val currentState = view.findViewById<TextView>(R.id.current_state)
+
+        val launchedJobs = mutableListOf<Job>()
+
+        view.findViewById<Button>(R.id.start_button).setOnClickListener {
+            val cookie = Random.nextInt()
+            Trace.asyncTraceForTrackBegin(
+                Trace.TRACE_TAG_APP,
+                TRACK_NAME,
+                "Running: $className",
+                cookie,
+            )
+
+            val job = mainScope.launch { demo.start() }
+            job.invokeOnCompletion { cause ->
+                Trace.asyncTraceForTrackEnd(Trace.TRACE_TAG_APP, TRACK_NAME, cookie)
+                val message =
+                    when (cause) {
+                        null -> "completed normally"
+                        is CancellationException -> "cancelled normally"
+                        else -> "failed"
+                    }
+                mainExecutor.execute {
+                    currentState.text = message
+                    appendLine("$className $message")
+                }
+            }
+
+            launchedJobs.add(job)
+
+            currentState.text = "started"
+            appendLine("$className started")
+        }
+
+        view.findViewById<Button>(R.id.cancel_button).setOnClickListener {
+            var activeJobs = 0
+            launchedJobs.forEach {
+                if (it.isActive) activeJobs++
+                it.cancel()
+            }
+            appendLine(if (activeJobs == 0) "Nothing to cancel." else "Cancelled $activeJobs jobs.")
+            launchedJobs.clear()
+        }
+    }
+
+    override fun onCreate(savedInstanceState: Bundle?) {
+        super.onCreate(savedInstanceState)
+        setContentView(R.layout.activity_main)
+        logContainer = requireViewById(R.id.log_container)
+        loggerView = requireViewById(R.id.logger_view)
+        val experimentList = requireViewById<LinearLayout>(R.id.experiment_list)
+        val inflater = LayoutInflater.from(baseContext)
+        allExperiments.forEach {
+            val experimentButtons =
+                inflater.inflate(R.layout.experiment_buttons, experimentList, false) as ViewGroup
+            connectButtonsForExperiment(it.value.get(), experimentButtons)
+            experimentList.addView(experimentButtons)
+        }
+    }
+
+    private fun appendLine(message: String) {
+        loggerView?.append("$message\n")
+        logContainer?.fullScroll(View.FOCUS_DOWN)
+    }
+}
diff --git a/tracinglib/demo/src/com/android/app/tracing/demo/MainApplication.kt b/tracinglib/demo/src/MainApplication.kt
similarity index 95%
rename from tracinglib/demo/src/com/android/app/tracing/demo/MainApplication.kt
rename to tracinglib/demo/src/MainApplication.kt
index c77afbd..0d98bbe 100644
--- a/tracinglib/demo/src/com/android/app/tracing/demo/MainApplication.kt
+++ b/tracinglib/demo/src/MainApplication.kt
@@ -13,7 +13,7 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.android.app.tracing.demo
+package com.example.tracing.demo
 
 import android.app.Application
 
diff --git a/tracinglib/demo/src/com/android/app/tracing/demo/ApplicationComponent.kt b/tracinglib/demo/src/com/android/app/tracing/demo/ApplicationComponent.kt
deleted file mode 100644
index 008df55..0000000
--- a/tracinglib/demo/src/com/android/app/tracing/demo/ApplicationComponent.kt
+++ /dev/null
@@ -1,174 +0,0 @@
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
-package com.android.app.tracing.demo
-
-import android.os.Handler
-import android.os.HandlerThread
-import android.os.Looper
-import android.os.Trace
-import com.android.app.tracing.coroutines.nameCoroutine
-import com.android.app.tracing.demo.experiments.CollectFlow
-import com.android.app.tracing.demo.experiments.CombineDeferred
-import com.android.app.tracing.demo.experiments.Experiment
-import com.android.app.tracing.demo.experiments.LaunchNested
-import com.android.app.tracing.demo.experiments.LaunchSequentially
-import com.android.app.tracing.demo.experiments.NestedLaunchesWithParentSpan
-import com.android.app.tracing.demo.experiments.NestedLaunchesWithoutName
-import com.android.app.tracing.demo.experiments.UnconfinedThreadSwitch
-import dagger.Binds
-import dagger.Component
-import dagger.Module
-import dagger.Provides
-import dagger.multibindings.ClassKey
-import dagger.multibindings.IntoMap
-import javax.inject.Provider
-import javax.inject.Qualifier
-import javax.inject.Singleton
-import kotlin.annotation.AnnotationRetention.RUNTIME
-import kotlin.coroutines.CoroutineContext
-import kotlin.coroutines.EmptyCoroutineContext
-import kotlinx.coroutines.CoroutineDispatcher
-import kotlinx.coroutines.Dispatchers
-import kotlinx.coroutines.android.asCoroutineDispatcher
-
-@Qualifier @MustBeDocumented @Retention(RUNTIME) annotation class Main
-
-@Qualifier @MustBeDocumented @Retention(RUNTIME) annotation class Default
-
-@Qualifier @MustBeDocumented @Retention(RUNTIME) annotation class IO
-
-@Qualifier @MustBeDocumented @Retention(RUNTIME) annotation class Unconfined
-
-@Qualifier @MustBeDocumented @Retention(RUNTIME) annotation class FixedThread1
-
-@Qualifier @MustBeDocumented @Retention(RUNTIME) annotation class FixedThread2
-
-@Qualifier @MustBeDocumented @Retention(RUNTIME) annotation class ExperimentLauncherThread
-
-const val NAME_DISPATCHERS = false
-
-private fun nameDispatcher(name: String) =
-    if (NAME_DISPATCHERS) {
-        nameCoroutine(name)
-    } else {
-        EmptyCoroutineContext
-    }
-
-@Module
-class ConcurrencyModule {
-
-    @Provides
-    @Singleton
-    @Default
-    fun provideDefaultCoroutineContext(): CoroutineContext {
-        return Dispatchers.Default + nameDispatcher("Dispatchers.Default")
-    }
-
-    @Provides
-    @Singleton
-    @IO
-    fun provideIOCoroutineContext(): CoroutineContext {
-        return Dispatchers.IO + nameDispatcher("Dispatchers.IO")
-    }
-
-    @Provides
-    @Singleton
-    @Unconfined
-    fun provideUnconfinedCoroutineContext(): CoroutineContext {
-        return Dispatchers.Unconfined + nameDispatcher("Dispatchers.Unconfined")
-    }
-
-    @Provides
-    @Singleton
-    @FixedThread1
-    fun provideFixedThread1CoroutineContext(): CoroutineContext {
-        val looper = startThreadWithLooper("FixedThread #1")
-        return Handler(looper).asCoroutineDispatcher("FixedCoroutineDispatcher #1") +
-            nameDispatcher("FixedCoroutineDispatcher #1")
-    }
-
-    @Provides
-    @Singleton
-    @FixedThread2
-    fun provideFixedThread2CoroutineContext(): CoroutineContext {
-        val looper = startThreadWithLooper("FixedThread #2")
-        return Handler(looper).asCoroutineDispatcher("FixedCoroutineDispatcher #2") +
-            nameDispatcher("FixedCoroutineDispatcher #2")
-    }
-
-    @Provides
-    @Singleton
-    @ExperimentLauncherThread
-    fun provideExperimentDispatcher(): CoroutineDispatcher {
-        val looper = startThreadWithLooper("Experiment Launcher Thread")
-        return Handler(looper).asCoroutineDispatcher("Experiment Launcher CoroutineDispatcher")
-    }
-}
-
-@Module
-interface ExperimentModule {
-    @Binds
-    @IntoMap
-    @ClassKey(CollectFlow::class)
-    fun bindCollectFlow(service: CollectFlow): Experiment
-
-    @Binds
-    @IntoMap
-    @ClassKey(CombineDeferred::class)
-    fun bindCombineDeferred(service: CombineDeferred): Experiment
-
-    @Binds
-    @IntoMap
-    @ClassKey(LaunchNested::class)
-    fun bindLaunchNested(service: LaunchNested): Experiment
-
-    @Binds
-    @IntoMap
-    @ClassKey(LaunchSequentially::class)
-    fun bindLaunchSequentially(service: LaunchSequentially): Experiment
-
-    @Binds
-    @IntoMap
-    @ClassKey(NestedLaunchesWithParentSpan::class)
-    fun bindNestedLaunchesWithNames(service: NestedLaunchesWithParentSpan): Experiment
-
-    @Binds
-    @IntoMap
-    @ClassKey(NestedLaunchesWithoutName::class)
-    fun bindNestedLaunchesWithoutNames(service: NestedLaunchesWithoutName): Experiment
-
-    @Binds
-    @IntoMap
-    @ClassKey(UnconfinedThreadSwitch::class)
-    fun bindUnconfinedThreadSwitch(service: UnconfinedThreadSwitch): Experiment
-}
-
-@Singleton
-@Component(modules = [ConcurrencyModule::class, ExperimentModule::class])
-interface ApplicationComponent {
-    /** Returns [Experiment]s that should be used with the application. */
-    @Singleton fun getAllExperiments(): Map<Class<*>, Provider<Experiment>>
-
-    @Singleton @ExperimentLauncherThread fun getExperimentDispatcher(): CoroutineDispatcher
-}
-
-private fun startThreadWithLooper(name: String): Looper {
-    val thread = HandlerThread(name)
-    thread.start()
-    val looper = thread.looper
-    looper.setTraceTag(Trace.TRACE_TAG_APP)
-    return looper
-}
diff --git a/tracinglib/demo/src/com/android/app/tracing/demo/MainActivity.kt b/tracinglib/demo/src/com/android/app/tracing/demo/MainActivity.kt
deleted file mode 100644
index 031c458..0000000
--- a/tracinglib/demo/src/com/android/app/tracing/demo/MainActivity.kt
+++ /dev/null
@@ -1,127 +0,0 @@
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
-package com.android.app.tracing.demo
-
-import android.app.Activity
-import android.os.Bundle
-import android.os.Trace
-import android.view.View
-import android.widget.Button
-import android.widget.LinearLayout
-import android.widget.ScrollView
-import android.widget.TextView
-import com.android.app.tracing.TraceUtils.trace
-import com.android.app.tracing.coroutines.createCoroutineTracingContext
-import com.android.app.tracing.coroutines.nameCoroutine
-import com.android.app.tracing.demo.experiments.Experiment
-import kotlinx.coroutines.CancellationException
-import kotlinx.coroutines.CoroutineScope
-import kotlinx.coroutines.Job
-import kotlinx.coroutines.cancel
-import kotlinx.coroutines.launch
-
-private const val TRACK_NAME = "Active experiments"
-
-class MainActivity : Activity() {
-
-    private val allExperiments = lazy {
-        (applicationContext as MainApplication).appComponent.getAllExperiments()
-    }
-
-    private val experimentLaunchContext = lazy {
-        (applicationContext as MainApplication).appComponent.getExperimentDispatcher()
-    }
-
-    private val scopeForExperiment = mutableMapOf<String, CoroutineScope>()
-
-    private var logContainer: ScrollView? = null
-    private var loggerView: TextView? = null
-
-    private fun getScopeForExperiment(name: String): CoroutineScope {
-        var scope = scopeForExperiment[name]
-        if (scope == null) {
-            scope =
-                CoroutineScope(experimentLaunchContext.value + createCoroutineTracingContext(name))
-            scopeForExperiment[name] = scope
-        }
-        return scope
-    }
-
-    private fun <T : Experiment> createButtonForExperiment(demo: T): Button {
-        var launchCounter = 0
-        var job: Job? = null
-        val className = demo::class.simpleName ?: "<unknown class>"
-        return Button(baseContext).apply {
-            text =
-                context.getString(
-                    R.string.run_experiment_button_text,
-                    className,
-                    demo.getDescription(),
-                )
-            setOnClickListener {
-                val experimentName = "$className #${launchCounter++}"
-                trace("$className#onClick") {
-                    job?.let { trace("cancel") { it.cancel("Cancelled due to click") } }
-                    trace("launch") {
-                        job =
-                            getScopeForExperiment(className).launch(nameCoroutine("run")) {
-                                demo.run()
-                            }
-                    }
-                    trace("toast") { appendLine("$experimentName started") }
-                    job?.let {
-                        Trace.asyncTraceForTrackBegin(
-                            Trace.TRACE_TAG_APP,
-                            TRACK_NAME,
-                            experimentName,
-                            it.hashCode(),
-                        )
-                    }
-                }
-                job?.let {
-                    it.invokeOnCompletion { cause ->
-                        Trace.asyncTraceForTrackEnd(Trace.TRACE_TAG_APP, TRACK_NAME, it.hashCode())
-                        mainExecutor.execute {
-                            val message =
-                                when (cause) {
-                                    null -> "$experimentName completed normally"
-                                    is CancellationException -> "$experimentName cancelled normally"
-                                    else -> "$experimentName failed"
-                                }
-                            appendLine(message)
-                        }
-                    }
-                }
-            }
-        }
-    }
-
-    override fun onCreate(savedInstanceState: Bundle?) {
-        super.onCreate(savedInstanceState)
-        setContentView(R.layout.activity_main)
-        logContainer = requireViewById(R.id.log_container)
-        loggerView = requireViewById(R.id.logger_view)
-        val buttonContainer = requireViewById<LinearLayout>(R.id.button_container)
-        allExperiments.value.forEach {
-            buttonContainer.addView(createButtonForExperiment(it.value.get()))
-        }
-    }
-
-    private fun appendLine(message: String) {
-        loggerView?.append("$message\n")
-        logContainer?.fullScroll(View.FOCUS_DOWN)
-    }
-}
diff --git a/tracinglib/demo/src/com/android/app/tracing/demo/experiments/CollectFlow.kt b/tracinglib/demo/src/com/android/app/tracing/demo/experiments/CollectFlow.kt
deleted file mode 100644
index 0efc639..0000000
--- a/tracinglib/demo/src/com/android/app/tracing/demo/experiments/CollectFlow.kt
+++ /dev/null
@@ -1,87 +0,0 @@
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
-package com.android.app.tracing.demo.experiments
-
-import com.android.app.tracing.coroutines.flow.withTraceName
-import com.android.app.tracing.coroutines.launch
-import com.android.app.tracing.coroutines.traceCoroutine
-import com.android.app.tracing.demo.FixedThread1
-import com.android.app.tracing.demo.FixedThread2
-import javax.inject.Inject
-import javax.inject.Singleton
-import kotlin.coroutines.CoroutineContext
-import kotlinx.coroutines.coroutineScope
-import kotlinx.coroutines.delay
-import kotlinx.coroutines.flow.filter
-import kotlinx.coroutines.flow.flow
-import kotlinx.coroutines.flow.flowOn
-import kotlinx.coroutines.flow.map
-
-/** Util for introducing artificial delays to make the trace more readable for demo purposes. */
-private fun blockCurrentThread(millis: Long) {
-    Thread.sleep(millis)
-}
-
-@Singleton
-class CollectFlow
-@Inject
-constructor(
-    @FixedThread1 private var fixedThreadContext1: CoroutineContext,
-    @FixedThread2 private var fixedThreadContext2: CoroutineContext,
-) : Experiment {
-
-    override fun getDescription(): String = "Collect a cold flow with intermediate operators"
-
-    override suspend fun run(): Unit = coroutineScope {
-        val numFlow =
-            flow {
-                    for (n in 0..4) {
-                        traceCoroutine("delay-and-emit for $n") {
-                            blockCurrentThread(5)
-                            delay(1)
-                            blockCurrentThread(6)
-                            emit(n)
-                            blockCurrentThread(7)
-                            delay(1)
-                            blockCurrentThread(8)
-                        }
-                    }
-                }
-                .withTraceName("flowOf numbers")
-                .filter {
-                    blockCurrentThread(9)
-                    it % 2 == 0
-                }
-                .withTraceName("filter for even")
-                .map {
-                    blockCurrentThread(10)
-                    it * 3
-                }
-                .withTraceName("map 3x")
-                .flowOn(fixedThreadContext2)
-                .withTraceName("flowOn thread #2")
-
-        launch("launch on thread #1", fixedThreadContext1) {
-            numFlow.collect {
-                traceCoroutine("got: $it") {
-                    blockCurrentThread(11)
-                    delay(1)
-                    blockCurrentThread(12)
-                }
-            }
-        }
-    }
-}
diff --git a/tracinglib/demo/src/com/android/app/tracing/demo/experiments/CombineDeferred.kt b/tracinglib/demo/src/com/android/app/tracing/demo/experiments/CombineDeferred.kt
deleted file mode 100644
index 30cc769..0000000
--- a/tracinglib/demo/src/com/android/app/tracing/demo/experiments/CombineDeferred.kt
+++ /dev/null
@@ -1,98 +0,0 @@
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
-package com.android.app.tracing.demo.experiments
-
-import com.android.app.tracing.coroutines.nameCoroutine
-import com.android.app.tracing.coroutines.traceCoroutine
-import com.android.app.tracing.demo.FixedThread1
-import com.android.app.tracing.demo.FixedThread2
-import com.android.app.tracing.demo.Unconfined
-import com.android.app.tracing.traceSection
-import javax.inject.Inject
-import javax.inject.Singleton
-import kotlin.coroutines.CoroutineContext
-import kotlinx.coroutines.CoroutineStart.LAZY
-import kotlinx.coroutines.async
-import kotlinx.coroutines.coroutineScope
-import kotlinx.coroutines.launch
-
-@Singleton
-class CombineDeferred
-@Inject
-constructor(
-    @FixedThread1 private var fixedThreadContext1: CoroutineContext,
-    @FixedThread2 private var fixedThreadContext2: CoroutineContext,
-    @Unconfined private var unconfinedContext: CoroutineContext,
-) : Experiment {
-    override fun getDescription(): String = "async{} then start()"
-
-    override suspend fun run() {
-        traceCoroutine("start1") { incSlowly(50, 50) }
-        traceCoroutine("start2") { incSlowly(50, 50) }
-        traceCoroutine("start3") { incSlowly(50, 50) }
-        traceCoroutine("start4") { incSlowly(50, 50) }
-        traceCoroutine("coroutineScope") {
-            coroutineScope {
-                // deferred10 -> deferred20 -> deferred30
-                val deferred30 =
-                    async(start = LAZY, context = fixedThreadContext2) {
-                        traceCoroutine("async#30") { incSlowly(25, 25) }
-                    }
-                val deferred20 =
-                    async(start = LAZY, context = unconfinedContext) {
-                        traceCoroutine("async#20") { incSlowly(5, 45) }
-                        traceSection("start30") { deferred30.start() }
-                    }
-                val deferred10 =
-                    async(start = LAZY, context = fixedThreadContext1) {
-                        traceCoroutine("async#10") { incSlowly(10, 20) }
-                        traceSection("start20") { deferred20.start() }
-                    }
-
-                // deferredA -> deferredB -> deferredC
-                val deferredC =
-                    async(start = LAZY, context = fixedThreadContext1) {
-                        traceCoroutine("async#C") { incSlowly(35, 15) }
-                    }
-                val deferredB =
-                    async(start = LAZY, context = unconfinedContext) {
-                        traceCoroutine("async#B") { incSlowly(15, 35) }
-                        traceSection("startC") { deferredC.start() }
-                    }
-                val deferredA =
-                    async(start = LAZY, context = fixedThreadContext2) {
-                        traceCoroutine("async#A") { incSlowly(20, 30) }
-                        traceSection("startB") { deferredB.start() }
-                    }
-
-                // no dispatcher specified, so will inherit dispatcher from whoever called
-                // run(),
-                // meaning the ExperimentLauncherThread
-                val deferredE =
-                    async(nameCoroutine("overridden-scope-name-for-deferredE")) {
-                        traceCoroutine("async#E") { incSlowly(30, 20) }
-                    }
-
-                launch(fixedThreadContext1) {
-                    traceSection("start10") { deferred10.start() }
-                    traceSection("startA") { deferredA.start() }
-                    traceSection("startE") { deferredE.start() }
-                }
-            }
-        }
-        traceCoroutine("end") { incSlowly(50, 50) }
-    }
-}
diff --git a/tracinglib/demo/src/com/android/app/tracing/demo/experiments/LaunchNested.kt b/tracinglib/demo/src/com/android/app/tracing/demo/experiments/LaunchNested.kt
deleted file mode 100644
index 100cb87..0000000
--- a/tracinglib/demo/src/com/android/app/tracing/demo/experiments/LaunchNested.kt
+++ /dev/null
@@ -1,51 +0,0 @@
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
-package com.android.app.tracing.demo.experiments
-
-import com.android.app.tracing.coroutines.launch
-import com.android.app.tracing.demo.Default
-import com.android.app.tracing.demo.FixedThread1
-import com.android.app.tracing.demo.FixedThread2
-import com.android.app.tracing.demo.IO
-import javax.inject.Inject
-import javax.inject.Singleton
-import kotlin.coroutines.CoroutineContext
-import kotlinx.coroutines.coroutineScope
-
-@Singleton
-class LaunchNested
-@Inject
-constructor(
-    @FixedThread1 private var fixedThreadContext1: CoroutineContext,
-    @FixedThread2 private var fixedThreadContext2: CoroutineContext,
-    @Default private var defaultContext: CoroutineContext,
-    @IO private var ioContext: CoroutineContext,
-) : Experiment {
-    override fun getDescription(): String = "launch{launch{launch{launch{}}}}"
-
-    override suspend fun run(): Unit = coroutineScope {
-        launch("launch(fixedThreadContext1)", fixedThreadContext1) {
-            doWork()
-            launch("launch(fixedThreadContext2)", fixedThreadContext2) {
-                doWork()
-                launch("launch(Dispatchers.IO)", ioContext) {
-                    doWork()
-                    launch("launch(Dispatchers.Default)", defaultContext) { doWork() }
-                }
-            }
-        }
-    }
-}
diff --git a/tracinglib/demo/src/com/android/app/tracing/demo/experiments/LaunchSequentially.kt b/tracinglib/demo/src/com/android/app/tracing/demo/experiments/LaunchSequentially.kt
deleted file mode 100644
index 0f44599..0000000
--- a/tracinglib/demo/src/com/android/app/tracing/demo/experiments/LaunchSequentially.kt
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
-package com.android.app.tracing.demo.experiments
-
-import com.android.app.tracing.coroutines.launch
-import com.android.app.tracing.demo.Default
-import com.android.app.tracing.demo.FixedThread1
-import com.android.app.tracing.demo.FixedThread2
-import com.android.app.tracing.demo.IO
-import javax.inject.Inject
-import javax.inject.Singleton
-import kotlin.coroutines.CoroutineContext
-import kotlinx.coroutines.coroutineScope
-
-@Singleton
-class LaunchSequentially
-@Inject
-constructor(
-    @FixedThread1 private var fixedThreadContext1: CoroutineContext,
-    @FixedThread2 private var fixedThreadContext2: CoroutineContext,
-    @Default private var defaultContext: CoroutineContext,
-    @IO private var ioContext: CoroutineContext,
-) : Experiment {
-    override fun getDescription(): String = "launch{};launch{};launch{};launch{}"
-
-    override suspend fun run(): Unit = coroutineScope {
-        launch("$tag: launch on fixed thread #1", fixedThreadContext1) { doWork() }
-        launch("$tag: launch on fixed thread #2", fixedThreadContext2) { doWork() }
-        launch("$tag: launch on Default", defaultContext) { doWork() }
-        launch("$tag: launch on IO", ioContext) { doWork() }
-    }
-}
diff --git a/tracinglib/demo/src/com/android/app/tracing/demo/experiments/NestedLaunchesWithParentSpan.kt b/tracinglib/demo/src/com/android/app/tracing/demo/experiments/NestedLaunchesWithParentSpan.kt
deleted file mode 100644
index 5849149..0000000
--- a/tracinglib/demo/src/com/android/app/tracing/demo/experiments/NestedLaunchesWithParentSpan.kt
+++ /dev/null
@@ -1,47 +0,0 @@
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
-package com.android.app.tracing.demo.experiments
-
-import com.android.app.tracing.coroutines.launch
-import com.android.app.tracing.demo.FixedThread1
-import com.android.app.tracing.demo.FixedThread2
-import javax.inject.Inject
-import javax.inject.Singleton
-import kotlin.coroutines.CoroutineContext
-import kotlinx.coroutines.coroutineScope
-import kotlinx.coroutines.delay
-import kotlinx.coroutines.launch
-
-@Singleton
-class NestedLaunchesWithParentSpan
-@Inject
-constructor(
-    @FixedThread1 private var fixedThreadContext1: CoroutineContext,
-    @FixedThread2 private var fixedThreadContext2: CoroutineContext,
-) : Experiment {
-    override fun getDescription(): String =
-        "Nested launches in which only the parent uses a trace name"
-
-    override suspend fun run(): Unit = coroutineScope {
-        launch("launch", fixedThreadContext1) {
-            delay(10)
-            launch(fixedThreadContext2) {
-                delay(10)
-                launch(fixedThreadContext1) { incSlowly() }
-            }
-        }
-    }
-}
diff --git a/tracinglib/demo/src/com/android/app/tracing/demo/experiments/NestedLaunchesWithoutName.kt b/tracinglib/demo/src/com/android/app/tracing/demo/experiments/NestedLaunchesWithoutName.kt
deleted file mode 100644
index 913026b..0000000
--- a/tracinglib/demo/src/com/android/app/tracing/demo/experiments/NestedLaunchesWithoutName.kt
+++ /dev/null
@@ -1,46 +0,0 @@
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
-package com.android.app.tracing.demo.experiments
-
-import com.android.app.tracing.demo.FixedThread1
-import com.android.app.tracing.demo.FixedThread2
-import javax.inject.Inject
-import javax.inject.Singleton
-import kotlin.coroutines.CoroutineContext
-import kotlinx.coroutines.coroutineScope
-import kotlinx.coroutines.delay
-import kotlinx.coroutines.launch
-
-@Singleton
-class NestedLaunchesWithoutName
-@Inject
-constructor(
-    @FixedThread1 private var fixedThreadContext1: CoroutineContext,
-    @FixedThread2 private var fixedThreadContext2: CoroutineContext,
-) : Experiment {
-    override fun getDescription(): String =
-        "Nested launches in which only the leaf uses a trace name"
-
-    override suspend fun run(): Unit = coroutineScope {
-        launch(fixedThreadContext1) {
-            delay(10)
-            launch(fixedThreadContext2) {
-                delay(10)
-                launch(fixedThreadContext1) { incSlowly() }
-            }
-        }
-    }
-}
diff --git a/tracinglib/demo/src/com/android/app/tracing/demo/experiments/UnconfinedThreadSwitch.kt b/tracinglib/demo/src/com/android/app/tracing/demo/experiments/UnconfinedThreadSwitch.kt
deleted file mode 100644
index e814459..0000000
--- a/tracinglib/demo/src/com/android/app/tracing/demo/experiments/UnconfinedThreadSwitch.kt
+++ /dev/null
@@ -1,40 +0,0 @@
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
-package com.android.app.tracing.demo.experiments
-
-import com.android.app.tracing.coroutines.launch
-import com.android.app.tracing.demo.IO
-import com.android.app.tracing.demo.Unconfined
-import javax.inject.Inject
-import javax.inject.Singleton
-import kotlin.coroutines.CoroutineContext
-import kotlinx.coroutines.coroutineScope
-
-@Singleton
-class UnconfinedThreadSwitch
-@Inject
-constructor(
-    @IO private var ioContext: CoroutineContext,
-    @Unconfined private var unconfinedContext: CoroutineContext,
-) : Experiment {
-    override fun getDescription(): String = "launch with Dispatchers.Unconfined"
-
-    override suspend fun run(): Unit = coroutineScope {
-        launch("launch(Dispatchers.Unconfined)", unconfinedContext) { doWork() }
-        launch("launch(EmptyCoroutineContext)") { doWork() }
-        launch("launch(Dispatchers.IO)", ioContext) { doWork() }
-    }
-}
diff --git a/tracinglib/demo/src/com/android/app/tracing/demo/experiments/Util.kt b/tracinglib/demo/src/com/android/app/tracing/demo/experiments/Util.kt
deleted file mode 100644
index f9638a8..0000000
--- a/tracinglib/demo/src/com/android/app/tracing/demo/experiments/Util.kt
+++ /dev/null
@@ -1,60 +0,0 @@
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
-package com.android.app.tracing.demo.experiments
-
-import android.os.Trace
-import java.util.concurrent.Executors.newFixedThreadPool
-import java.util.concurrent.atomic.AtomicInteger
-import kotlin.coroutines.resume
-import kotlinx.coroutines.suspendCancellableCoroutine
-
-private val counter = AtomicInteger()
-
-internal suspend fun doWork() {
-    incSlowly(0, 50)
-    incSlowly(50, 0)
-    incSlowly(50, 50)
-}
-
-// BAD - wastefully use a thread pool for resuming continuations in a contrived manner
-val threadPoolForSleep = newFixedThreadPool(4)
-
-/**
- * A simple suspending function that returns a unique sequential number, ordered by when it was
- * originally called. It can optionally be used to simulate slow functions by sleeping before or
- * after the suspension point
- */
-@Suppress("BlockingMethodInNonBlockingContext")
-suspend fun incSlowly(delayBeforeSuspension: Long = 0, delayBeforeResume: Long = 0): Int {
-    val num = counter.incrementAndGet()
-    Trace.traceBegin(Trace.TRACE_TAG_APP, "inc#$num:sleep-before-suspend:$delayBeforeSuspension")
-    try {
-        Thread.sleep(delayBeforeSuspension) // BAD - sleep for demo purposes only
-    } finally {
-        Trace.traceEnd(Trace.TRACE_TAG_APP)
-    }
-    return suspendCancellableCoroutine { continuation ->
-        threadPoolForSleep.submit {
-            Trace.traceBegin(Trace.TRACE_TAG_APP, "inc#$num:sleep-before-resume:$delayBeforeResume")
-            try {
-                Thread.sleep(delayBeforeResume) // BAD - sleep for demo purposes only
-            } finally {
-                Trace.traceEnd(Trace.TRACE_TAG_APP)
-            }
-            continuation.resume(num)
-        }
-    }
-}
diff --git a/tracinglib/demo/src/experiments/CancellableSharedFlow.kt b/tracinglib/demo/src/experiments/CancellableSharedFlow.kt
new file mode 100644
index 0000000..8e7d633
--- /dev/null
+++ b/tracinglib/demo/src/experiments/CancellableSharedFlow.kt
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
+package com.example.tracing.demo.experiments
+
+import com.example.tracing.demo.FixedThreadB
+import javax.inject.Inject
+import javax.inject.Singleton
+import kotlinx.coroutines.CoroutineDispatcher
+import kotlinx.coroutines.coroutineScope
+import kotlinx.coroutines.flow.SharingStarted
+import kotlinx.coroutines.flow.flowOn
+import kotlinx.coroutines.flow.shareIn
+
+@Singleton
+class CancellableSharedFlow
+@Inject
+constructor(@FixedThreadB private var dispatcherB: CoroutineDispatcher) : Experiment {
+
+    override val description: String = "Create shared flows that can be cancelled by the parent"
+
+    override suspend fun start() {
+        // GOOD - launched into child scope, parent can cancel this
+        coroutineScope {
+            coldCounterFlow("good")
+                .flowOn(dispatcherB)
+                .shareIn(this, SharingStarted.Eagerly, replay = 10)
+        }
+    }
+}
diff --git a/tracinglib/demo/src/experiments/CollectFlow.kt b/tracinglib/demo/src/experiments/CollectFlow.kt
new file mode 100644
index 0000000..d06acf2
--- /dev/null
+++ b/tracinglib/demo/src/experiments/CollectFlow.kt
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
+package com.example.tracing.demo.experiments
+
+import android.os.Trace
+import com.android.app.tracing.coroutines.flow.collectTraced
+import com.android.app.tracing.coroutines.flow.filterTraced as filter
+import com.android.app.tracing.coroutines.flow.flowName
+import com.android.app.tracing.coroutines.flow.mapTraced as map
+import com.android.app.tracing.coroutines.launchTraced as launch
+import com.example.tracing.demo.FixedThreadA
+import com.example.tracing.demo.FixedThreadB
+import com.example.tracing.demo.FixedThreadC
+import javax.inject.Inject
+import javax.inject.Singleton
+import kotlinx.coroutines.CoroutineDispatcher
+import kotlinx.coroutines.coroutineScope
+import kotlinx.coroutines.flow.flowOn
+
+@Singleton
+class CollectFlow
+@Inject
+constructor(
+    @FixedThreadA private var dispatcherA: CoroutineDispatcher,
+    @FixedThreadB private var dispatcherB: CoroutineDispatcher,
+    @FixedThreadC private val dispatcherC: CoroutineDispatcher,
+) : Experiment {
+    override val description: String = "Collect a cold flow with intermediate operators"
+
+    private val coldFlow =
+        coldCounterFlow("count", 4)
+            .flowName("original-cold-flow-scope")
+            .flowOn(dispatcherA)
+            .filter("evens") {
+                forceSuspend("B", 20)
+                it % 2 == 0
+            }
+            .flowOn(dispatcherB)
+            .flowName("even-filter-scope")
+            .map("3x") {
+                forceSuspend("C", 15)
+                it * 3
+            }
+            .flowOn(dispatcherC)
+
+    override suspend fun start(): Unit = coroutineScope {
+        launch(context = dispatcherA) {
+            coldFlow.collectTraced {
+                Trace.instant(Trace.TRACE_TAG_APP, "got: $it")
+                forceSuspend("A2", 60)
+            }
+        }
+    }
+}
diff --git a/tracinglib/demo/src/experiments/CombineDeferred.kt b/tracinglib/demo/src/experiments/CombineDeferred.kt
new file mode 100644
index 0000000..7ef09ce
--- /dev/null
+++ b/tracinglib/demo/src/experiments/CombineDeferred.kt
@@ -0,0 +1,90 @@
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
+package com.example.tracing.demo.experiments
+
+import com.android.app.tracing.coroutines.nameCoroutine
+import com.android.app.tracing.coroutines.traceCoroutine
+import com.android.app.tracing.traceSection
+import com.example.tracing.demo.FixedThreadA
+import com.example.tracing.demo.FixedThreadB
+import com.example.tracing.demo.FixedThreadC
+import com.example.tracing.demo.Unconfined
+import javax.inject.Inject
+import javax.inject.Singleton
+import kotlinx.coroutines.CoroutineDispatcher
+import kotlinx.coroutines.CoroutineStart.LAZY
+import kotlinx.coroutines.async
+import kotlinx.coroutines.coroutineScope
+import kotlinx.coroutines.launch
+
+@Singleton
+class CombineDeferred
+@Inject
+constructor(
+    @FixedThreadA private var dispatcherA: CoroutineDispatcher,
+    @FixedThreadB private var dispatcherB: CoroutineDispatcher,
+    @FixedThreadC private val dispatcherC: CoroutineDispatcher,
+    @Unconfined private var unconfinedContext: CoroutineDispatcher,
+) : Experiment {
+    override val description: String = "async{} then start()"
+
+    override suspend fun start(): Unit = coroutineScope {
+        // deferred10 -> deferred20 -> deferred30
+        val deferred30 =
+            async(start = LAZY, context = dispatcherB) {
+                traceCoroutine("async#30") { forceSuspend("deferred30", 250) }
+            }
+        val deferred20 =
+            async(start = LAZY, context = unconfinedContext) {
+                traceCoroutine("async#20") { forceSuspend("deferred20", 250) }
+                traceSection("start30") { deferred30.start() }
+            }
+        val deferred10 =
+            async(start = LAZY, context = dispatcherC) {
+                traceCoroutine("async#10") { forceSuspend("deferred10", 250) }
+                traceSection("start20") { deferred20.start() }
+            }
+
+        // deferredA -> deferredB -> deferredC
+        val deferredC =
+            async(start = LAZY, context = dispatcherB) {
+                traceCoroutine("async#C") { forceSuspend("deferredC", 250) }
+            }
+        val deferredB =
+            async(start = LAZY, context = unconfinedContext) {
+                traceCoroutine("async#B") { forceSuspend("deferredB", 250) }
+                traceSection("startC") { deferredC.start() }
+            }
+        val deferredA =
+            async(start = LAZY, context = dispatcherC) {
+                traceCoroutine("async#A") { forceSuspend("deferredA", 250) }
+                traceSection("startB") { deferredB.start() }
+            }
+
+        // no dispatcher specified, so will inherit dispatcher from whoever called
+        // run(), meaning the main thread
+        val deferredE =
+            async(nameCoroutine("overridden-scope-name-for-deferredE")) {
+                traceCoroutine("async#E") { forceSuspend("deferredE", 250) }
+            }
+
+        launch(dispatcherA) {
+            traceSection("start10") { deferred10.start() }
+            traceSection("startA") { deferredA.start() }
+            traceSection("startE") { deferredE.start() }
+        }
+    }
+}
diff --git a/tracinglib/demo/src/com/android/app/tracing/demo/experiments/Experiment.kt b/tracinglib/demo/src/experiments/Experiment.kt
similarity index 87%
rename from tracinglib/demo/src/com/android/app/tracing/demo/experiments/Experiment.kt
rename to tracinglib/demo/src/experiments/Experiment.kt
index 5dca2b6..9851825 100644
--- a/tracinglib/demo/src/com/android/app/tracing/demo/experiments/Experiment.kt
+++ b/tracinglib/demo/src/experiments/Experiment.kt
@@ -13,15 +13,14 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.android.app.tracing.demo.experiments
+package com.example.tracing.demo.experiments
 
 interface Experiment {
-
     /** The track name for async traces */
     val tag: String
         get() = "Experiment:${this::class.simpleName}"
 
-    fun getDescription(): String
+    val description: String
 
-    suspend fun run()
+    suspend fun start()
 }
diff --git a/tracinglib/demo/src/experiments/LaunchNested.kt b/tracinglib/demo/src/experiments/LaunchNested.kt
new file mode 100644
index 0000000..ad1ebf7
--- /dev/null
+++ b/tracinglib/demo/src/experiments/LaunchNested.kt
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
+package com.example.tracing.demo.experiments
+
+import com.android.app.tracing.coroutines.launchTraced as launch
+import com.example.tracing.demo.Default
+import com.example.tracing.demo.FixedThreadA
+import com.example.tracing.demo.FixedThreadB
+import com.example.tracing.demo.FixedThreadC
+import com.example.tracing.demo.IO
+import javax.inject.Inject
+import javax.inject.Singleton
+import kotlinx.coroutines.CoroutineDispatcher
+import kotlinx.coroutines.coroutineScope
+
+@Singleton
+class LaunchNested
+@Inject
+constructor(
+    @FixedThreadA private var dispatcherA: CoroutineDispatcher,
+    @FixedThreadB private var dispatcherB: CoroutineDispatcher,
+    @FixedThreadC private val dispatcherC: CoroutineDispatcher,
+    @Default private var defaultContext: CoroutineDispatcher,
+    @IO private var ioContext: CoroutineDispatcher,
+) : Experiment {
+    override val description: String = "launch{launch{launch{launch{}}}}"
+
+    override suspend fun start(): Unit = coroutineScope {
+        launch("launch(threadA)", dispatcherA) {
+            forceSuspend("A", 250)
+            launch("launch(threadB)", dispatcherB) {
+                forceSuspend("B", 250)
+                launch("launch(threadC)", dispatcherC) {
+                    forceSuspend("C", 250)
+                    launch("launch(Dispatchers.Default)", defaultContext) {
+                        forceSuspend("D", 250)
+                        launch("launch(Dispatchers.IO)", ioContext) { forceSuspend("E", 250) }
+                    }
+                }
+            }
+        }
+    }
+}
diff --git a/tracinglib/demo/src/experiments/LaunchSequentially.kt b/tracinglib/demo/src/experiments/LaunchSequentially.kt
new file mode 100644
index 0000000..028b7da
--- /dev/null
+++ b/tracinglib/demo/src/experiments/LaunchSequentially.kt
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
+package com.example.tracing.demo.experiments
+
+import com.android.app.tracing.coroutines.launchTraced as launch
+import com.example.tracing.demo.Default
+import com.example.tracing.demo.FixedThreadA
+import com.example.tracing.demo.FixedThreadB
+import com.example.tracing.demo.FixedThreadC
+import com.example.tracing.demo.IO
+import com.example.tracing.demo.Unconfined
+import javax.inject.Inject
+import javax.inject.Singleton
+import kotlinx.coroutines.CoroutineDispatcher
+import kotlinx.coroutines.coroutineScope
+
+@Singleton
+class LaunchSequentially
+@Inject
+constructor(
+    @FixedThreadA private var dispatcherA: CoroutineDispatcher,
+    @FixedThreadB private var dispatcherB: CoroutineDispatcher,
+    @FixedThreadC private val dispatcherC: CoroutineDispatcher,
+    @Default private var defaultContext: CoroutineDispatcher,
+    @IO private var ioContext: CoroutineDispatcher,
+    @Unconfined private var unconfinedContext: CoroutineDispatcher,
+) : Experiment {
+    override val description: String = "launch{};launch{};launch{};launch{}"
+
+    override suspend fun start(): Unit = coroutineScope {
+        launch("launch(threadA)", dispatcherA) { forceSuspend("A", 250) }
+        launch("launch(threadB)", dispatcherB) { forceSuspend("B", 250) }
+        launch("launch(threadC)", dispatcherC) { forceSuspend("C", 250) }
+        launch("launch(Dispatchers.Default)", defaultContext) { forceSuspend("D", 250) }
+        launch("launch(EmptyCoroutineContext)") { forceSuspend("E", 250) }
+        launch("launch(Dispatchers.IO)", ioContext) { forceSuspend("F", 250) }
+        launch("launch(Dispatchers.Unconfined)", unconfinedContext) { forceSuspend("G", 250) }
+    }
+}
diff --git a/tracinglib/demo/src/experiments/LeakySharedFlow.kt b/tracinglib/demo/src/experiments/LeakySharedFlow.kt
new file mode 100644
index 0000000..3ece62d
--- /dev/null
+++ b/tracinglib/demo/src/experiments/LeakySharedFlow.kt
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
+package com.example.tracing.demo.experiments
+
+import com.android.app.tracing.coroutines.createCoroutineTracingContext
+import com.example.tracing.demo.FixedThreadA
+import javax.inject.Inject
+import javax.inject.Singleton
+import kotlinx.coroutines.CoroutineDispatcher
+import kotlinx.coroutines.CoroutineScope
+import kotlinx.coroutines.coroutineScope
+import kotlinx.coroutines.flow.SharingStarted
+import kotlinx.coroutines.flow.shareIn
+
+@Singleton
+class LeakySharedFlow
+@Inject
+constructor(@FixedThreadA private var dispatcherA: CoroutineDispatcher) : Experiment {
+
+    override val description: String = "Create a shared flow that cannot be cancelled by the caller"
+
+    private val leakedScope =
+        CoroutineScope(dispatcherA + createCoroutineTracingContext("flow-scope"))
+
+    override suspend fun start() {
+        // BAD - does not follow structured concurrency. This creates a new job each time it is
+        // called. There is no way to cancel the shared flow because the parent does not know about
+        // it
+        coldCounterFlow("leaky1").shareIn(leakedScope, SharingStarted.Eagerly, replay = 10)
+
+        // BAD - this also leaks
+        coroutineScope {
+            coldCounterFlow("leaky2").shareIn(leakedScope, SharingStarted.Eagerly, replay = 10)
+        }
+    }
+}
diff --git a/tracinglib/demo/src/experiments/SharedFlowUsage.kt b/tracinglib/demo/src/experiments/SharedFlowUsage.kt
new file mode 100644
index 0000000..60929a5
--- /dev/null
+++ b/tracinglib/demo/src/experiments/SharedFlowUsage.kt
@@ -0,0 +1,101 @@
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
+package com.example.tracing.demo.experiments
+
+import com.android.app.tracing.coroutines.flow.collectTraced as collect
+import com.android.app.tracing.coroutines.flow.collectTraced
+import com.android.app.tracing.coroutines.flow.filterTraced as filter
+import com.android.app.tracing.coroutines.flow.flowName
+import com.android.app.tracing.coroutines.flow.mapTraced as map
+import com.android.app.tracing.coroutines.launchTraced as launch
+import com.android.app.tracing.coroutines.nameCoroutine
+import com.android.app.tracing.coroutines.traceCoroutine
+import com.example.tracing.demo.FixedThreadA
+import com.example.tracing.demo.FixedThreadB
+import com.example.tracing.demo.FixedThreadC
+import com.example.tracing.demo.FixedThreadD
+import javax.inject.Inject
+import javax.inject.Singleton
+import kotlinx.coroutines.CoroutineDispatcher
+import kotlinx.coroutines.coroutineScope
+import kotlinx.coroutines.flow.SharingStarted
+import kotlinx.coroutines.flow.flowOn
+import kotlinx.coroutines.flow.stateIn
+
+@Singleton
+class SharedFlowUsage
+@Inject
+constructor(
+    @FixedThreadA private var dispatcherA: CoroutineDispatcher,
+    @FixedThreadB private var dispatcherB: CoroutineDispatcher,
+    @FixedThreadC private var dispatcherC: CoroutineDispatcher,
+    @FixedThreadD private var dispatcherD: CoroutineDispatcher,
+) : Experiment {
+
+    override val description: String = "Create a shared flow and collect from it"
+
+    private val coldFlow =
+        coldCounterFlow("shared", 10)
+            // this trace name is NOT used because the dispatcher did NOT change
+            .flowName("UNUSED_NAME")
+            .map("pow2") {
+                val rv = it * it
+                forceSuspend("map($it) -> $rv", 50)
+                rv
+            }
+            // this trace name is used here because the dispatcher changed
+            .flowOn(dispatcherC + nameCoroutine("NEW_COLD_FLOW_NAME"))
+            .filter("mod4") {
+                val rv = it % 4 == 0
+                forceSuspend("filter($it) -> $rv", 50)
+                rv
+            }
+            // this trace name is used, because the scope it is collected in has a
+            // CoroutineTracingContext
+            .flowName("COLD_FLOW")
+
+    override suspend fun start() {
+        coroutineScope {
+            val stateFlow = coldFlow.stateIn(this, SharingStarted.Eagerly, 10)
+            launch("launchAAAA", dispatcherA) {
+                stateFlow.collect("collectAAAA") {
+                    traceCoroutine("AAAA collected: $it") { forceSuspend("AAAA", 15) }
+                }
+            }
+            launch("launchBBBB", dispatcherB) {
+                // Don't pass a string. Instead, rely on default behavior to walk the stack for the
+                // name. This results in trace sections like:
+                // `collect:SharedFlowUsage$start$1$2:emit`
+                // NOTE: `Flow.collect` is a member function and takes precedence, so we need
+                // to invoke `collectTraced` using its original name instead of its `collect` alias
+                stateFlow.collectTraced {
+                    traceCoroutine("BBBB collected: $it") { forceSuspend("BBBB", 30) }
+                }
+            }
+            launch("launchCCCC", dispatcherC) {
+                stateFlow.collect("collectCCCC") {
+                    traceCoroutine("CCCC collected: $it") { forceSuspend("CCCC", 60) }
+                }
+            }
+            launch("launchDDDD", dispatcherD) {
+                // Uses Flow.collect member function instead of collectTraced:
+                stateFlow.collect {
+                    traceCoroutine("DDDD collected: $it") { forceSuspend("DDDD", 90) }
+                }
+            }
+        }
+    }
+}
diff --git a/tracinglib/demo/src/experiments/Util.kt b/tracinglib/demo/src/experiments/Util.kt
new file mode 100644
index 0000000..2cb61ec
--- /dev/null
+++ b/tracinglib/demo/src/experiments/Util.kt
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
+package com.example.tracing.demo.experiments
+
+import android.os.HandlerThread
+import android.os.Trace
+import com.android.app.tracing.coroutines.traceCoroutine
+import kotlin.coroutines.resume
+import kotlin.random.Random
+import kotlinx.coroutines.delay
+import kotlinx.coroutines.flow.flow
+import kotlinx.coroutines.suspendCancellableCoroutine
+
+fun coldCounterFlow(name: String, maxCount: Int = Int.MAX_VALUE) = flow {
+    for (n in 0..maxCount) {
+        emit(n)
+        forceSuspend("coldCounterFlow:$name:$n", 25)
+    }
+}
+
+private val delayHandler by lazy { startThreadWithLooper("Thread:forceSuspend").threadHandler }
+
+/** Like [delay], but naively implemented so that it always suspends. */
+suspend fun forceSuspend(traceName: String, timeMillis: Long) {
+    val traceMessage = "forceSuspend:$traceName"
+    return traceCoroutine(traceMessage) {
+        val cookie = Random.nextInt()
+        suspendCancellableCoroutine { continuation ->
+            Trace.asyncTraceForTrackBegin(Trace.TRACE_TAG_APP, TRACK_NAME, traceMessage, cookie)
+            Trace.instant(Trace.TRACE_TAG_APP, "will resume in ${timeMillis}ms")
+            continuation.invokeOnCancellation { cause ->
+                Trace.instant(
+                    Trace.TRACE_TAG_APP,
+                    "forceSuspend:$traceName, cancelled due to ${cause?.javaClass}",
+                )
+                Trace.asyncTraceForTrackEnd(Trace.TRACE_TAG_APP, TRACK_NAME, cookie)
+            }
+            delayHandler.postDelayed(
+                {
+                    Trace.asyncTraceForTrackEnd(Trace.TRACE_TAG_APP, TRACK_NAME, cookie)
+                    Trace.traceBegin(Trace.TRACE_TAG_APP, "resume")
+                    try {
+                        continuation.resume(Unit)
+                    } finally {
+                        Trace.traceEnd(Trace.TRACE_TAG_APP)
+                    }
+                },
+                timeMillis,
+            )
+        }
+    }
+}
+
+fun startThreadWithLooper(name: String): HandlerThread {
+    val thread = HandlerThread(name)
+    thread.start()
+    val looper = thread.looper
+    looper.setTraceTag(Trace.TRACE_TAG_APP)
+    return thread
+}
+
+const val TRACK_NAME = "Async events"
diff --git a/tracinglib/robolectric/Android.bp b/tracinglib/robolectric/Android.bp
index f2d3640..74625a7 100644
--- a/tracinglib/robolectric/Android.bp
+++ b/tracinglib/robolectric/Android.bp
@@ -25,11 +25,15 @@ android_app {
 android_robolectric_test {
     enabled: true,
     name: "tracinglib-robo-test",
-    srcs: ["src/**/*.kt"],
+    srcs: [
+        "src/**/*.kt",
+        ":tracinglib-core-srcs",
+    ],
     java_resource_dirs: ["config"],
     static_libs: [
-        "tracinglib-platform",
+        "kotlinx_coroutines_android",
         "flag-junit",
+        "com_android_systemui_flags_lib",
     ],
     libs: [
         "androidx.test.core",
diff --git a/tracinglib/robolectric/src/CallbackFlowTracingTest.kt b/tracinglib/robolectric/src/CallbackFlowTracingTest.kt
new file mode 100644
index 0000000..dfc7f42
--- /dev/null
+++ b/tracinglib/robolectric/src/CallbackFlowTracingTest.kt
@@ -0,0 +1,184 @@
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
+package com.android.test.tracing.coroutines
+
+import android.platform.test.annotations.EnableFlags
+import com.android.app.tracing.coroutines.createCoroutineTracingContext
+import com.android.app.tracing.coroutines.flow.collectTraced
+import com.android.app.tracing.coroutines.flow.flowName
+import com.android.app.tracing.coroutines.launchTraced
+import com.android.systemui.Flags.FLAG_COROUTINE_TRACING
+import java.util.concurrent.Executor
+import kotlin.coroutines.CoroutineContext
+import kotlinx.coroutines.CoroutineDispatcher
+import kotlinx.coroutines.CoroutineScope
+import kotlinx.coroutines.DelicateCoroutinesApi
+import kotlinx.coroutines.ExperimentalCoroutinesApi
+import kotlinx.coroutines.asExecutor
+import kotlinx.coroutines.cancel
+import kotlinx.coroutines.channels.awaitClose
+import kotlinx.coroutines.delay
+import kotlinx.coroutines.flow.Flow
+import kotlinx.coroutines.flow.MutableStateFlow
+import kotlinx.coroutines.flow.SharingStarted
+import kotlinx.coroutines.flow.StateFlow
+import kotlinx.coroutines.flow.callbackFlow
+import kotlinx.coroutines.flow.combine
+import kotlinx.coroutines.flow.distinctUntilChanged
+import kotlinx.coroutines.flow.map
+import kotlinx.coroutines.flow.onEach
+import kotlinx.coroutines.flow.onStart
+import kotlinx.coroutines.flow.stateIn
+import kotlinx.coroutines.newSingleThreadContext
+import org.junit.Test
+
+data class ExampleInfo(val a: Int, val b: Boolean, val c: String)
+
+interface ExampleStateTracker {
+    val info: ExampleInfo
+
+    fun addCallback(callback: Callback, executor: Executor)
+
+    fun removeCallback(callback: Callback)
+
+    interface Callback {
+        fun onInfoChanged(newInfo: ExampleInfo)
+    }
+}
+
+interface ExampleRepository {
+    val currentInfo: Flow<ExampleInfo>
+    val otherState: StateFlow<Boolean>
+    val combinedState: StateFlow<Boolean> // true when otherState == true and current.b == true
+}
+
+class ExampleStateTrackerImpl : ExampleStateTracker {
+    private var _info = ExampleInfo(0, false, "Initial")
+    override val info: ExampleInfo
+        get() = _info
+
+    val callbacks = mutableListOf<Pair<ExampleStateTracker.Callback, Executor>>()
+
+    override fun addCallback(callback: ExampleStateTracker.Callback, executor: Executor) {
+        callbacks.add(Pair(callback, executor))
+    }
+
+    override fun removeCallback(callback: ExampleStateTracker.Callback) {
+        callbacks.removeIf { it.first == callback }
+    }
+
+    fun forceUpdate(a: Int, b: Boolean, c: String) {
+        _info = ExampleInfo(a, b, c)
+        callbacks.forEach { it.second.execute { it.first.onInfoChanged(_info) } }
+    }
+}
+
+private class ExampleRepositoryImpl(
+    private val testBase: TestBase,
+    private val bgScope: CoroutineScope,
+    private val tracker: ExampleStateTrackerImpl,
+) : ExampleRepository {
+    @OptIn(ExperimentalStdlibApi::class)
+    override val currentInfo: StateFlow<ExampleInfo> =
+        callbackFlow {
+                channel.trySend(tracker.info)
+                val callback =
+                    object : ExampleStateTracker.Callback {
+                        override fun onInfoChanged(newInfo: ExampleInfo) {
+                            channel.trySend(newInfo)
+                        }
+                    }
+                tracker.addCallback(
+                    callback,
+                    bgScope.coroutineContext[CoroutineDispatcher]!!.asExecutor(),
+                )
+                awaitClose { tracker.removeCallback(callback) }
+            }
+            .onEach { testBase.expect("bg:1^currentInfo") }
+            .flowName("currentInfo")
+            .stateIn(bgScope, SharingStarted.Eagerly, initialValue = tracker.info)
+
+    override val otherState = MutableStateFlow(false)
+
+    /** flow that emits true only when currentInfo.b == true and otherState == true */
+    override val combinedState: StateFlow<Boolean>
+        get() =
+            combine(currentInfo, otherState, ::Pair)
+                .map { it.first.b && it.second }
+                .distinctUntilChanged()
+                .onEach { testBase.expect("bg:2^combinedState:1^:2^") }
+                .onStart { emit(false) }
+                .flowName("combinedState")
+                .stateIn(
+                    scope = bgScope,
+                    started = SharingStarted.WhileSubscribed(),
+                    initialValue = false,
+                )
+}
+
+@OptIn(DelicateCoroutinesApi::class, ExperimentalCoroutinesApi::class)
+@EnableFlags(FLAG_COROUTINE_TRACING)
+class CallbackFlowTracingTest : TestBase() {
+
+    override val extraCoroutineContext: CoroutineContext
+        get() = createCoroutineTracingContext("main", includeParentNames = true, strictMode = true)
+
+    @Test
+    fun callbackFlow1() {
+        val exampleTracker = ExampleStateTrackerImpl()
+        val bgScope =
+            CoroutineScope(
+                createCoroutineTracingContext("bg", includeParentNames = true, strictMode = true) +
+                    newSingleThreadContext("bg-thread")
+            )
+        val repository = ExampleRepositoryImpl(this, bgScope, exampleTracker)
+
+        expect(1)
+        runTest {
+            launchTraced("collectCombined") {
+                repository.combinedState.collectTraced("combined-states") {
+                    expect(
+                        listOf(2, 4, 5, 6),
+                        "main:1^:1^collectCombined",
+                        "collect:combined-states",
+                        "collect:combined-states:emit",
+                    )
+                }
+            }
+            delay(10)
+            expect(3, "main:1^")
+            delay(10)
+            exampleTracker.forceUpdate(1, false, "A") // <-- no change
+            delay(10)
+            repository.otherState.value = true // <-- no change
+            delay(10)
+            exampleTracker.forceUpdate(2, true, "B") // <-- should update `combinedState`
+            delay(10)
+            repository.otherState.value = false // <-- should update `combinedState`
+            delay(10)
+            exampleTracker.forceUpdate(3, false, "C") // <-- no change
+            delay(10)
+            exampleTracker.forceUpdate(4, true, "D") // <-- no change
+            delay(10)
+            repository.otherState.value = true // <-- should update `combinedState`
+            delay(10)
+            finish(7, "main:1^")
+            cancel("Cancelled normally for test")
+        }
+        bgScope.cancel("Cancelled normally for test")
+    }
+}
diff --git a/tracinglib/robolectric/src/CoroutineTracingFlagsTest.kt b/tracinglib/robolectric/src/CoroutineTracingFlagsTest.kt
index 64726e1..159a85a 100644
--- a/tracinglib/robolectric/src/CoroutineTracingFlagsTest.kt
+++ b/tracinglib/robolectric/src/CoroutineTracingFlagsTest.kt
@@ -14,12 +14,16 @@
  * limitations under the License.
  */
 
-package com.android.app.tracing.coroutines
+package com.android.test.tracing.coroutines
 
 import android.platform.test.annotations.DisableFlags
 import android.platform.test.annotations.EnableFlags
-import com.android.app.tracing.coroutines.util.FakeTraceState
+import com.android.app.tracing.coroutines.TraceData
+import com.android.app.tracing.coroutines.createCoroutineTracingContext
+import com.android.app.tracing.coroutines.traceCoroutine
+import com.android.app.tracing.coroutines.traceThreadLocal
 import com.android.systemui.Flags.FLAG_COROUTINE_TRACING
+import com.android.test.tracing.coroutines.util.FakeTraceState
 import kotlinx.coroutines.withContext
 import org.junit.Assert.assertEquals
 import org.junit.Assert.assertFalse
@@ -36,7 +40,7 @@ class CoroutineTracingFlagsTest : TestBase() {
     fun tracingDisabledWhenFlagIsOff() = runTest {
         assertFalse(com.android.systemui.Flags.coroutineTracing())
         assertNull(traceThreadLocal.get())
-        withContext(createCoroutineTracingContext()) {
+        withContext(createCoroutineTracingContext(strictMode = true)) {
             assertNull(traceThreadLocal.get())
             traceCoroutine("hello") { // should not crash
                 assertNull(traceThreadLocal.get())
diff --git a/tracinglib/robolectric/src/CoroutineTracingMachineryTest.kt b/tracinglib/robolectric/src/CoroutineTracingMachineryTest.kt
new file mode 100644
index 0000000..a82c7de
--- /dev/null
+++ b/tracinglib/robolectric/src/CoroutineTracingMachineryTest.kt
@@ -0,0 +1,233 @@
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
+package com.android.test.tracing.coroutines
+
+import android.platform.test.annotations.EnableFlags
+import com.android.app.tracing.coroutines.TraceContextElement
+import com.android.app.tracing.coroutines.TraceData
+import com.android.app.tracing.coroutines.createCoroutineTracingContext
+import com.android.app.tracing.coroutines.launchTraced
+import com.android.app.tracing.coroutines.traceCoroutine
+import com.android.app.tracing.coroutines.traceThreadLocal
+import com.android.systemui.Flags.FLAG_COROUTINE_TRACING
+import java.util.concurrent.CyclicBarrier
+import java.util.concurrent.Executors
+import java.util.concurrent.TimeUnit
+import kotlin.coroutines.EmptyCoroutineContext
+import kotlinx.coroutines.DelicateCoroutinesApi
+import kotlinx.coroutines.ExperimentalCoroutinesApi
+import kotlinx.coroutines.channels.Channel
+import kotlinx.coroutines.launch
+import kotlinx.coroutines.newSingleThreadContext
+import kotlinx.coroutines.withContext
+import org.junit.Assert.assertArrayEquals
+import org.junit.Assert.assertNotSame
+import org.junit.Assert.assertNull
+import org.junit.Assert.assertSame
+import org.junit.Test
+
+@OptIn(ExperimentalCoroutinesApi::class, DelicateCoroutinesApi::class)
+@EnableFlags(FLAG_COROUTINE_TRACING)
+class CoroutineTracingMachineryTest : TestBase() {
+
+    @Test
+    fun missingTraceContextObjects() = runTest {
+        val channel = Channel<Int>()
+        val context1 = newSingleThreadContext("thread-#1")
+        val context2 =
+            newSingleThreadContext("thread-#2") +
+                createCoroutineTracingContext("main", includeParentNames = true, strictMode = true)
+
+        launchTraced("launch#1", context1) {
+            expect()
+            channel.receive()
+            traceCoroutine("span-1") { expect() }
+            expect()
+            launchTraced("launch#2", context2) {
+                // "launch#2" is not traced because TraceContextElement was installed too
+                // late; it is not part of the scope that was launched (i.e., the `this` in
+                // `this.launch {}`)
+                expect("main:1^")
+                channel.receive()
+                traceCoroutine("span-2") { expect("main:1^", "span-2") }
+                expect("main:1^")
+                launch {
+                    // ...it won't appear in the child scope either because in
+                    // launchTraced("string"), it
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
+        val traceContext =
+            createCoroutineTracingContext("main", includeParentNames = true, strictMode = true)
+                as TraceContextElement
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
+    fun traceContextIsCopied() = runTest {
+        expect()
+        val traceContext =
+            createCoroutineTracingContext("main", includeParentNames = true, strictMode = true)
+                as TraceContextElement
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
+}
diff --git a/tracinglib/robolectric/src/CoroutineTracingTest.kt b/tracinglib/robolectric/src/CoroutineTracingTest.kt
index 483e51f..8cc3e2e 100644
--- a/tracinglib/robolectric/src/CoroutineTracingTest.kt
+++ b/tracinglib/robolectric/src/CoroutineTracingTest.kt
@@ -14,27 +14,36 @@
  * limitations under the License.
  */
 
-package com.android.app.tracing.coroutines
+package com.android.test.tracing.coroutines
 
 import android.platform.test.annotations.EnableFlags
+import com.android.app.tracing.coroutines.coroutineScopeTraced
+import com.android.app.tracing.coroutines.createCoroutineTracingContext
+import com.android.app.tracing.coroutines.launchTraced
+import com.android.app.tracing.coroutines.nameCoroutine
+import com.android.app.tracing.coroutines.traceCoroutine
 import com.android.systemui.Flags.FLAG_COROUTINE_TRACING
+import kotlin.coroutines.CoroutineContext
 import kotlinx.coroutines.delay
 import kotlinx.coroutines.launch
 import org.junit.Assert.assertEquals
 import org.junit.Test
 
 @EnableFlags(FLAG_COROUTINE_TRACING)
-class CoroutineTracingTest : TracingTestBase() {
+class CoroutineTracingTest : TestBase() {
+
+    override val extraCoroutineContext: CoroutineContext
+        get() = createCoroutineTracingContext("main", includeParentNames = true, strictMode = true)
 
     @Test
-    fun simpleTraceSection() = runTestTraced {
+    fun simpleTraceSection() = runTest {
         expectD(1, "main:1^")
         traceCoroutine("hello") { expectD(2, "main:1^", "hello") }
         finish(3, "main:1^")
     }
 
     @Test
-    fun simpleNestedTraceSection() = runTestTraced {
+    fun simpleNestedTraceSection() = runTest {
         expectD(1, "main:1^")
         traceCoroutine("hello") {
             expectD(2, "main:1^", "hello")
@@ -45,7 +54,7 @@ class CoroutineTracingTest : TracingTestBase() {
     }
 
     @Test
-    fun simpleLaunch() = runTestTraced {
+    fun simpleLaunch() = runTest {
         expectD(1, "main:1^")
         traceCoroutine("hello") {
             expectD(2, "main:1^", "hello")
@@ -58,7 +67,7 @@ class CoroutineTracingTest : TracingTestBase() {
     }
 
     @Test
-    fun launchWithSuspendingLambda() = runTestTraced {
+    fun launchWithSuspendingLambda() = runTest {
         val fetchData: suspend () -> String = {
             expect(3, "main:1^:1^span-for-launch")
             delay(1L)
@@ -68,7 +77,7 @@ class CoroutineTracingTest : TracingTestBase() {
             "stuff"
         }
         expect(1, "main:1^")
-        launch("span-for-launch") {
+        launchTraced("span-for-launch") {
             assertEquals("stuff", fetchData())
             finish(5, "main:1^:1^span-for-launch")
         }
@@ -76,37 +85,37 @@ class CoroutineTracingTest : TracingTestBase() {
     }
 
     @Test
-    fun launchInCoroutineScope() = runTestTraced {
-        launch("launch#0") {
+    fun launchInCoroutineScope() = runTest {
+        launchTraced("launch#0") {
             expect("main:1^:1^launch#0")
             delay(1)
             expect("main:1^:1^launch#0")
         }
-        coroutineScope("span-for-coroutineScope-1") {
-            launch("launch#1") {
+        coroutineScopeTraced("span-for-coroutineScope-1") {
+            launchTraced("launch#1") {
                 expect("main:1^:2^launch#1")
                 delay(1)
                 expect("main:1^:2^launch#1")
             }
-            launch("launch#2") {
+            launchTraced("launch#2") {
                 expect("main:1^:3^launch#2")
                 delay(1)
                 expect("main:1^:3^launch#2")
             }
-            coroutineScope("span-for-coroutineScope-2") {
-                launch("launch#3") {
+            coroutineScopeTraced("span-for-coroutineScope-2") {
+                launchTraced("launch#3") {
                     expect("main:1^:4^launch#3")
                     delay(1)
                     expect("main:1^:4^launch#3")
                 }
-                launch("launch#4") {
+                launchTraced("launch#4") {
                     expect("main:1^:5^launch#4")
                     delay(1)
                     expect("main:1^:5^launch#4")
                 }
             }
         }
-        launch("launch#5") {
+        launchTraced("launch#5") {
             expect("main:1^:6^launch#5")
             delay(1)
             expect("main:1^:6^launch#5")
@@ -114,55 +123,65 @@ class CoroutineTracingTest : TracingTestBase() {
     }
 
     @Test
-    fun namedScopeMerging() = runTestTraced {
+    fun namedScopeMerging() = runTest {
         // to avoid race conditions in the test leading to flakes, avoid calling expectD() or
         // delaying before launching (e.g. only call expectD() in leaf blocks)
         expect("main:1^")
-        launch("A") {
+        launchTraced("A") {
             expect("main:1^:1^A")
             traceCoroutine("span") { expectD("main:1^:1^A", "span") }
-            launch("B") { expectD("main:1^:1^A:1^B") }
-            launch("C") {
+            launchTraced("B") { expectD("main:1^:1^A:1^B") }
+            launchTraced("C") {
                 expect("main:1^:1^A:2^C")
                 launch { expectD("main:1^:1^A:2^C:1^") }
-                launch("D") { expectD("main:1^:1^A:2^C:2^D") }
-                launch("E") {
+                launchTraced("D") { expectD("main:1^:1^A:2^C:2^D") }
+                launchTraced("E") {
                     expect("main:1^:1^A:2^C:3^E")
-                    launch("F") { expectD("main:1^:1^A:2^C:3^E:1^F") }
+                    launchTraced("F") { expectD("main:1^:1^A:2^C:3^E:1^F") }
                     expect("main:1^:1^A:2^C:3^E")
                 }
             }
-            launch("G") { expectD("main:1^:1^A:3^G") }
+            launchTraced("G") { expectD("main:1^:1^A:3^G") }
         }
         launch { launch { launch { expectD("main:1^:2^:1^:1^") } } }
         delay(2)
-        launch("H") { launch { launch { expectD("main:1^:3^H:1^:1^") } } }
+        launchTraced("H") { launch { launch { expectD("main:1^:3^H:1^:1^") } } }
         delay(2)
         launch {
             launch {
                 launch {
-                    launch { launch { launch("I") { expectD("main:1^:4^:1^:1^:1^:1^:1^I") } } }
+                    launch {
+                        launch { launchTraced("I") { expectD("main:1^:4^:1^:1^:1^:1^:1^I") } }
+                    }
                 }
             }
         }
         delay(2)
-        launch("J") { launch("K") { launch { launch { expectD("main:1^:5^J:1^K:1^:1^") } } } }
+        launchTraced("J") {
+            launchTraced("K") { launch { launch { expectD("main:1^:5^J:1^K:1^:1^") } } }
+        }
         delay(2)
-        launch("L") { launch("M") { launch { launch { expectD("main:1^:6^L:1^M:1^:1^") } } } }
+        launchTraced("L") {
+            launchTraced("M") { launch { launch { expectD("main:1^:6^L:1^M:1^:1^") } } }
+        }
         delay(2)
-        launch("N") { launch("O") { launch { launch("D") { expectD("main:1^:7^N:1^O:1^:1^D") } } } }
+        launchTraced("N") {
+            launchTraced("O") { launch { launchTraced("D") { expectD("main:1^:7^N:1^O:1^:1^D") } } }
+        }
         delay(2)
-        launch("P") { launch("Q") { launch { launch("R") { expectD("main:1^:8^P:1^Q:1^:1^R") } } } }
+        launchTraced("P") {
+            launchTraced("Q") { launch { launchTraced("R") { expectD("main:1^:8^P:1^Q:1^:1^R") } } }
+        }
         delay(2)
-        launch("S") { launch("T") { launch { expectD("main:1^:9^S:1^T:1^") } } }
+        launchTraced("S") { launchTraced("T") { launch { expectD("main:1^:9^S:1^T:1^") } } }
         delay(2)
-        launch("U") { launch("V") { launch { expectD("main:1^:10^U:1^V:1^") } } }
+        launchTraced("U") { launchTraced("V") { launch { expectD("main:1^:10^U:1^V:1^") } } }
         delay(2)
         expectD("main:1^")
     }
 
     @Test
-    fun launchIntoSelf() = runTestTraced {
+    fun launchIntoSelf() = runTest {
         expectD("main:1^")
         val reusedNameContext = nameCoroutine("my-coroutine")
         launch(reusedNameContext) {
diff --git a/tracinglib/robolectric/src/DefaultNamingTest.kt b/tracinglib/robolectric/src/DefaultNamingTest.kt
new file mode 100644
index 0000000..d940377
--- /dev/null
+++ b/tracinglib/robolectric/src/DefaultNamingTest.kt
@@ -0,0 +1,393 @@
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
+package com.android.test.tracing.coroutines
+
+import android.platform.test.annotations.EnableFlags
+import com.android.app.tracing.coroutines.createCoroutineTracingContext
+import com.android.app.tracing.coroutines.flow.collectLatestTraced
+import com.android.app.tracing.coroutines.flow.collectTraced
+import com.android.app.tracing.coroutines.flow.filterTraced
+import com.android.app.tracing.coroutines.flow.flowName
+import com.android.app.tracing.coroutines.flow.mapTraced
+import com.android.app.tracing.coroutines.flow.transformTraced
+import com.android.app.tracing.coroutines.launchTraced
+import com.android.systemui.Flags.FLAG_COROUTINE_TRACING
+import kotlin.coroutines.CoroutineContext
+import kotlinx.coroutines.DelicateCoroutinesApi
+import kotlinx.coroutines.ExperimentalCoroutinesApi
+import kotlinx.coroutines.cancel
+import kotlinx.coroutines.delay
+import kotlinx.coroutines.flow.Flow
+import kotlinx.coroutines.flow.FlowCollector
+import kotlinx.coroutines.flow.SharingStarted
+import kotlinx.coroutines.flow.flow
+import kotlinx.coroutines.flow.shareIn
+import kotlinx.coroutines.newSingleThreadContext
+import kotlinx.coroutines.withContext
+import org.junit.Assert.assertEquals
+import org.junit.Test
+
+/** Tests behavior of default names, whether that's via stack walking or reflection */
+@EnableFlags(FLAG_COROUTINE_TRACING)
+class DefaultNamingTest : TestBase() {
+
+    override val extraCoroutineContext: CoroutineContext
+        get() = createCoroutineTracingContext("main", includeParentNames = true, strictMode = true)
+
+    fun namedCollectFun() {}
+
+    @Test
+    fun collectTraced1() = runTest {
+        expect(1, "main:1^")
+        flow {
+                expect(2, "main:1^", "collect:DefaultNamingTest\$collectTraced1$1$4")
+                emit(21) // 21 * 2 = 42
+                expect(6, "main:1^", "collect:DefaultNamingTest\$collectTraced1$1$4")
+            }
+            .mapTraced("2x") {
+                expect(
+                    3,
+                    "main:1^",
+                    "collect:DefaultNamingTest\$collectTraced1$1$4",
+                    "map:2x:transform",
+                )
+                it * 2 // 42
+            }
+            .flowName("UNUSED_NAME") // unused because scope is unchanged
+            .filterTraced("mod2") {
+                expect(
+                    4,
+                    "main:1^",
+                    "collect:DefaultNamingTest\$collectTraced1$1$4",
+                    "map:2x:emit",
+                    "filter:mod2:predicate",
+                )
+                it % 2 == 0 // true
+            }
+            .collectTraced {
+                assertEquals(42, it) // 21 * 2 = 42
+                expect(
+                    5,
+                    "main:1^",
+                    "collect:DefaultNamingTest\$collectTraced1$1$4",
+                    "map:2x:emit",
+                    "filter:mod2:emit",
+                    "collect:DefaultNamingTest\$collectTraced1$1$4:emit",
+                )
+            }
+        finish(7, "main:1^")
+    }
+
+    @Test
+    fun collectTraced2() = runTest {
+        expect(1, "main:1^") // top-level scope
+
+        flow {
+                expect(2, "main:1^:1^") // child scope used by `collectLatest {}`
+                emit(1) // should not get used by collectLatest {}
+                expect(6, "main:1^:1^")
+                emit(21) // 21 * 2 = 42
+                expect(10, "main:1^:1^")
+            }
+            .filterTraced("mod2") {
+                expect(listOf(3, 7), "main:1^:1^", "filter:mod2:predicate")
+                it % 2 == 1 // true
+            }
+            .mapTraced("2x") {
+                expect(listOf(4, 8), "main:1^:1^", "filter:mod2:emit", "map:2x:transform")
+                it * 2 // 42
+            }
+            // this name won't be used because it's not passed the scope used by mapLatest{}, which
+            // is an internal implementation detail in kotlinx
+            .flowName("UNUSED_NAME")
+            .collectLatestTraced {
+                expectEvent(listOf(5, 9))
+                delay(10)
+                assertEquals(42, it) // 21 * 2 = 42
+                expect(
+                    11,
+                    "main:1^:1^:2^",
+                    "collectLatest:DefaultNamingTest\$collectTraced2$1$4:action",
+                )
+            }
+        finish(12, "main:1^")
+    }
+
+    @Test
+    fun collectTraced3() = runTest {
+        expect(1, "main:1^") // top-level scope
+
+        val sharedFlow =
+            flow {
+                    expect(2, "main:1^:1^")
+                    delay(1)
+                    emit(22)
+                    expect(3, "main:1^:1^")
+                    delay(1)
+                    emit(32)
+                    expect(4, "main:1^:1^")
+                    delay(1)
+                    emit(42)
+                    expect(5, "main:1^:1^")
+                } // there is no API for passing a custom context to the new shared flow, so weg
+                // can't pass our custom child name using `nameCoroutine()`
+                .shareIn(this, SharingStarted.Eagerly, 4)
+
+        launchTraced("AAAA") {
+            sharedFlow.collectLatestTraced {
+                delay(10)
+                expect(
+                    6,
+                    "main:1^:2^AAAA:1^:3^",
+                    "collectLatest:DefaultNamingTest\$collectTraced3$1$1$1:action",
+                )
+            }
+        }
+        launchTraced("BBBB") {
+            sharedFlow.collectLatestTraced {
+                delay(40)
+                assertEquals(42, it)
+                expect(
+                    7,
+                    "main:1^:3^BBBB:1^:3^",
+                    "collectLatest:DefaultNamingTest\$collectTraced3$1$2$1:action",
+                )
+            }
+        }
+
+        delay(50)
+        finish(8, "main:1^")
+        cancel()
+    }
+
+    @Test
+    fun collectTraced4() = runTest {
+        expect(1, "main:1^")
+        flow {
+                expect(2, "main:1^", "collect:DefaultNamingTest\$collectTraced4$1$2")
+                emit(42)
+                expect(4, "main:1^", "collect:DefaultNamingTest\$collectTraced4$1$2")
+            }
+            .collectTraced {
+                assertEquals(42, it)
+                expect(
+                    3,
+                    "main:1^",
+                    "collect:DefaultNamingTest\$collectTraced4$1$2",
+                    "collect:DefaultNamingTest\$collectTraced4$1$2:emit",
+                )
+            }
+        finish(5, "main:1^")
+    }
+
+    @Test
+    fun collectTraced5_localFun() {
+        fun localFun(value: Int) {
+            assertEquals(42, value)
+            expect(
+                3,
+                "main:1^",
+                "collect:DefaultNamingTest\$collectTraced5_localFun$1$2",
+                "collect:DefaultNamingTest\$collectTraced5_localFun$1$2:emit",
+            )
+        }
+        return runTest {
+            expect(1, "main:1^")
+            flow {
+                    expect(2, "main:1^", "collect:DefaultNamingTest\$collectTraced5_localFun$1$2")
+                    emit(42)
+                    expect(4, "main:1^", "collect:DefaultNamingTest\$collectTraced5_localFun$1$2")
+                }
+                .collectTraced(::localFun)
+            finish(5, "main:1^")
+        }
+    }
+
+    fun memberFun(value: Int) {
+        assertEquals(42, value)
+        expect(
+            3,
+            "main:1^",
+            "collect:DefaultNamingTest\$collectTraced6_memberFun$1$2",
+            "collect:DefaultNamingTest\$collectTraced6_memberFun$1$2:emit",
+        )
+    }
+
+    @Test
+    fun collectTraced6_memberFun() = runTest {
+        expect(1, "main:1^")
+        flow {
+                expect(2, "main:1^", "collect:DefaultNamingTest\$collectTraced6_memberFun$1$2")
+                emit(42)
+                expect(4, "main:1^", "collect:DefaultNamingTest\$collectTraced6_memberFun$1$2")
+            }
+            .collectTraced(::memberFun)
+        finish(5, "main:1^")
+    }
+
+    @Test
+    fun collectTraced7_topLevelFun() = runTest {
+        expect(1, "main:1^")
+        flow {
+                expect(2, "main:1^", "collect:DefaultNamingTest\$collectTraced7_topLevelFun$1$2")
+                emit(42)
+                expect(3, "main:1^", "collect:DefaultNamingTest\$collectTraced7_topLevelFun$1$2")
+            }
+            .collectTraced(::topLevelFun)
+        finish(4, "main:1^")
+    }
+
+    @Test
+    fun collectTraced8_localFlowObject() = runTest {
+        expect(1, "main:1^")
+        val flowObj =
+            object : Flow<Int> {
+                override suspend fun collect(collector: FlowCollector<Int>) {
+                    expect(
+                        2,
+                        "main:1^",
+                        "collect:DefaultNamingTest\$collectTraced8_localFlowObject$1$1",
+                    )
+                    collector.emit(42)
+                    expect(
+                        4,
+                        "main:1^",
+                        "collect:DefaultNamingTest\$collectTraced8_localFlowObject$1$1",
+                    )
+                }
+            }
+        flowObj.collectTraced {
+            assertEquals(42, it)
+            expect(
+                3,
+                "main:1^",
+                "collect:DefaultNamingTest\$collectTraced8_localFlowObject$1$1",
+                "collect:DefaultNamingTest\$collectTraced8_localFlowObject$1$1:emit",
+            )
+        }
+        finish(5, "main:1^")
+    }
+
+    @Test
+    fun collectTraced9_flowObjectWithClassName() = runTest {
+        expect(1, "main:1^")
+        FlowWithName(this@DefaultNamingTest).collectTraced {
+            assertEquals(42, it)
+            expect(
+                3,
+                "main:1^",
+                "collect:DefaultNamingTest\$collectTraced9_flowObjectWithClassName$1$1",
+                "collect:DefaultNamingTest\$collectTraced9_flowObjectWithClassName$1$1:emit",
+            )
+        }
+        finish(5, "main:1^")
+    }
+
+    @Test
+    fun collectTraced10_flowCollectorObjectWithClassName() = runTest {
+        expect(1, "main:1^")
+        flow {
+                expect(2, "main:1^", "collect:FlowCollectorWithName")
+                emit(42)
+                expect(4, "main:1^", "collect:FlowCollectorWithName")
+            }
+            .collectTraced(FlowCollectorWithName(this@DefaultNamingTest))
+        finish(5, "main:1^")
+    }
+
+    @Test
+    fun collectTraced11_transform() = runTest {
+        expect(1, "main:1^")
+        flow {
+                expect(2, "main:1^", "collect:COLLECT")
+                emit(42)
+                expect(7, "main:1^", "collect:COLLECT")
+            }
+            .transformTraced("TRANSFORM") {
+                expect(3, "main:1^", "collect:COLLECT", "TRANSFORM:emit")
+                emit(it)
+                emit(it * 2)
+                emit(it * 4)
+            }
+            .collectTraced("COLLECT") {
+                expect(
+                    listOf(4, 5, 6),
+                    "main:1^",
+                    "collect:COLLECT",
+                    "TRANSFORM:emit",
+                    "collect:COLLECT:emit",
+                )
+            }
+        finish(8, "main:1^")
+    }
+
+    @OptIn(ExperimentalCoroutinesApi::class, DelicateCoroutinesApi::class)
+    @Test
+    fun collectTraced12_badTransform() =
+        runTest(
+            expectedException = { e ->
+                return@runTest e is java.lang.IllegalStateException &&
+                    (e.message?.startsWith("Flow invariant is violated") ?: false)
+            }
+        ) {
+            val thread1 = newSingleThreadContext("thread-#1")
+            expect(1, "main:1^")
+            flow {
+                    expect(2, "main:1^", "collect:COLLECT")
+                    emit(42)
+                    expect(4, "main:1^", "collect:COLLECT")
+                }
+                .transformTraced("TRANSFORM") {
+                    // SHOULD THROW AN EXCEPTION:
+                    withContext(thread1) { emit(it * 2) }
+                }
+                .collectTraced("COLLECT") {}
+            finish(5, "main:1^")
+        }
+}
+
+fun topLevelFun(value: Int) {
+    assertEquals(42, value)
+}
+
+class FlowWithName(private val test: TestBase) : Flow<Int> {
+    override suspend fun collect(collector: FlowCollector<Int>) {
+        test.expect(
+            2,
+            "main:1^",
+            "collect:DefaultNamingTest\$collectTraced9_flowObjectWithClassName$1$1",
+        )
+        collector.emit(42)
+        test.expect(
+            4,
+            "main:1^",
+            "collect:DefaultNamingTest\$collectTraced9_flowObjectWithClassName$1$1",
+        )
+    }
+}
+
+class FlowCollectorWithName(private val test: TestBase) : FlowCollector<Int> {
+    override suspend fun emit(value: Int) {
+        assertEquals(42, value)
+        test.expect(
+            3,
+            "main:1^",
+            "collect:FlowCollectorWithName",
+            "collect:FlowCollectorWithName:emit",
+        )
+    }
+}
diff --git a/tracinglib/robolectric/src/FlowTracingTest.kt b/tracinglib/robolectric/src/FlowTracingTest.kt
index 4cb57c5..74a2aa6 100644
--- a/tracinglib/robolectric/src/FlowTracingTest.kt
+++ b/tracinglib/robolectric/src/FlowTracingTest.kt
@@ -14,134 +14,278 @@
  * limitations under the License.
  */
 
-package com.android.app.tracing.coroutines
+package com.android.test.tracing.coroutines
 
 import android.platform.test.annotations.EnableFlags
-import com.android.app.tracing.coroutines.flow.collect
+import com.android.app.tracing.coroutines.createCoroutineTracingContext
 import com.android.app.tracing.coroutines.flow.collectTraced
-import com.android.app.tracing.coroutines.flow.filter
-import com.android.app.tracing.coroutines.flow.flowOn
-import com.android.app.tracing.coroutines.flow.map
-import com.android.app.tracing.coroutines.flow.withTraceName
-import com.android.app.tracing.coroutines.util.ExampleClass
+import com.android.app.tracing.coroutines.flow.filterTraced
+import com.android.app.tracing.coroutines.flow.flowName
+import com.android.app.tracing.coroutines.flow.mapTraced
+import com.android.app.tracing.coroutines.launchTraced
 import com.android.systemui.Flags.FLAG_COROUTINE_TRACING
+import kotlin.coroutines.CoroutineContext
+import kotlinx.coroutines.CompletableDeferred
 import kotlinx.coroutines.DelicateCoroutinesApi
 import kotlinx.coroutines.ExperimentalCoroutinesApi
+import kotlinx.coroutines.cancel
 import kotlinx.coroutines.delay
-import kotlinx.coroutines.flow.MutableStateFlow
+import kotlinx.coroutines.flow.filter
+import kotlinx.coroutines.flow.flow
 import kotlinx.coroutines.flow.flowOf
-import kotlinx.coroutines.launch
-import kotlinx.coroutines.newFixedThreadPoolContext
+import kotlinx.coroutines.flow.flowOn
+import kotlinx.coroutines.flow.map
+import kotlinx.coroutines.flow.stateIn
+import kotlinx.coroutines.flow.transform
 import kotlinx.coroutines.newSingleThreadContext
-import kotlinx.coroutines.withContext
 import org.junit.Assert.assertEquals
 import org.junit.Test
 
 @OptIn(DelicateCoroutinesApi::class, ExperimentalCoroutinesApi::class)
 @EnableFlags(FLAG_COROUTINE_TRACING)
-class FlowTracingTest : TracingTestBase() {
+class FlowTracingTest : TestBase() {
+
+    override val extraCoroutineContext: CoroutineContext
+        get() = createCoroutineTracingContext("main", includeParentNames = true, strictMode = true)
 
     @Test
-    fun stateFlowCollection() = runTestTraced {
-        val state = MutableStateFlow(1)
-        val bgThreadPool = newFixedThreadPoolContext(2, "bg-pool")
-
-        // Inefficient fine-grained thread confinement
-        val counterThread = newSingleThreadContext("counter-thread")
-        var counter = 0
-        val incrementCounter: suspend () -> Unit = {
-            withContext("increment", counterThread) {
-                expectEndsWith("increment")
-                counter++
+    fun collectFlow1() {
+        val coldFlow = flow {
+            expect(1, "main:1^")
+            delay(1)
+            expect(2, "main:1^")
+            emit(42)
+            expect(4, "main:1^")
+            delay(1)
+            expect(5, "main:1^")
+        }
+        runTest {
+            coldFlow.collect {
+                assertEquals(42, it)
+                expect(3, "main:1^")
             }
+            delay(1)
+            finish(6, "main:1^")
         }
+    }
 
-        val helper = ExampleClass(this@FlowTracingTest, incrementCounter)
-        val collectJob =
-            launch("launch-for-collect", bgThreadPool) {
-                expect("main:1^:1^launch-for-collect")
-                launch {
-                    state.collect("state-flow") {
-                        expect(
-                            "main:1^:1^launch-for-collect:1^",
-                            "state-flow:collect",
-                            "state-flow:emit",
-                        )
-                        incrementCounter()
-                    }
+    @Test
+    fun collectFlow2() {
+        val coldFlow =
+            flow {
+                    expect(1, "main:1^")
+                    delay(1)
+                    expect(2)
+                    emit(1)
+                    expect(5, "main:1^")
+                    delay(1)
+                    finish(6)
                 }
-                launch {
-                    state.collectTraced {
-                        expect(
-                            "main:1^:1^launch-for-collect:2^",
-                            "com.android.app.tracing.coroutines.FlowTracingTest\$stateFlowCollection$1\$collectJob$1$2:collect",
-                            "com.android.app.tracing.coroutines.FlowTracingTest\$stateFlowCollection$1\$collectJob$1$2:emit",
-                        )
-                        incrementCounter()
-                    }
+                .flowName("new-name")
+        runTest {
+            coldFlow.collect {
+                expect(3, "main:1^")
+                delay(1)
+                expect(4, "main:1^")
+            }
+        }
+    }
+
+    @Test
+    fun collectFlow3() {
+        val thread1 = newSingleThreadContext("thread-#1")
+        val coldFlow =
+            flow {
+                    expect("main:1^:1^new-name")
+                    delay(1)
+                    expect("main:1^:1^new-name")
+                    emit(42)
+                    expect("main:1^:1^new-name")
+                    delay(1)
+                    expect("main:1^:1^new-name")
                 }
-                launch { state.collectTraced(helper::classMethod) }
+                .flowName("new-name")
+                .flowOn(thread1)
+        runTest {
+            coldFlow.collect {
+                assertEquals(42, it)
+                expect("main:1^")
+                delay(1)
+                expect("main:1^")
             }
-        val emitJob =
-            launch(newSingleThreadContext("emitter-thread")) {
-                for (n in 2..5) {
-                    delay(100)
-                    state.value = n
+        }
+    }
+
+    @Test
+    fun collectFlow4() {
+        val thread1 = newSingleThreadContext("thread-#1")
+        val coldFlow =
+            flow {
+                    expect("main:1^:1^new-name")
+                    delay(1)
+                    expect("main:1^:1^new-name")
+                    emit(42)
+                    expect("main:1^:1^new-name")
+                    delay(1)
+                    expect("main:1^:1^new-name")
                 }
+                .flowOn(thread1)
+                .flowName("new-name")
+        runTest {
+            coldFlow.collect {
+                assertEquals(42, it)
+                expect("main:1^")
+                delay(1)
+                expect("main:1^")
             }
-        emitJob.join()
-        delay(10)
-        collectJob.cancel()
-        withContext(counterThread) { assertEquals(15, counter) }
+        }
     }
 
     @Test
-    fun flowOnWithTraceName() = runTestTraced {
-        val state =
-            flowOf(1, 2, 3, 4)
-                .withTraceName("my-flow")
-                .flowOn(newSingleThreadContext("flow-thread") + nameCoroutine("the-name"))
-        val bgThreadPool = newFixedThreadPoolContext(2, "bg-pool")
-        val collectJob =
-            launch("launch-for-collect", bgThreadPool) {
-                expect("main:1^:1^launch-for-collect")
-                launch {
-                    state.collect("state-flow") {
-                        expect(
-                            "main:1^:1^launch-for-collect:1^",
-                            "state-flow:collect",
-                            "flowOn(the-name):collect",
-                            "flowOn(the-name):emit",
-                            "state-flow:emit",
-                        )
-                    }
+    fun collectFlow5() {
+        val thread1 = newSingleThreadContext("thread-#1")
+        val coldFlow =
+            flow {
+                    expect("main:1^:1^new-name")
+                    delay(1)
+                    expect("main:1^:1^new-name")
+                    emit(42)
+                    expect("main:1^:1^new-name")
+                    delay(1)
+                    expect("main:1^:1^new-name")
                 }
+                .flowName("new-name")
+                .flowOn(thread1)
+                .flowName("UNUSED_NAME")
+
+        runTest {
+            coldFlow.collect {
+                assertEquals(42, it)
+                expect("main:1^")
             }
-        collectJob.join()
+            delay(1)
+            expect("main:1^")
+        }
     }
 
     @Test
-    fun mapAndFilter() = runTestTraced {
+    fun collectFlow6() {
+        val barrier1 = CompletableDeferred<Unit>()
+        val barrier2 = CompletableDeferred<Unit>()
+        val thread1 = newSingleThreadContext("thread-#1")
+        val thread2 = newSingleThreadContext("thread-#2")
+        val thread3 = newSingleThreadContext("thread-#3")
+        val coldFlow =
+            flow {
+                    expect(2, "main:1^:1^name-for-filter:1^name-for-map:1^name-for-emit")
+                    delay(1)
+                    expect(3, "main:1^:1^name-for-filter:1^name-for-map:1^name-for-emit")
+                    emit(42)
+                    barrier1.await()
+                    expect(9, "main:1^:1^name-for-filter:1^name-for-map:1^name-for-emit")
+                    delay(1)
+                    expect(10, "main:1^:1^name-for-filter:1^name-for-map:1^name-for-emit")
+                    barrier2.complete(Unit)
+                }
+                .flowName("name-for-emit")
+                .flowOn(thread3)
+                .map {
+                    expect(4, "main:1^:1^name-for-filter:1^name-for-map")
+                    delay(1)
+                    expect(5, "main:1^:1^name-for-filter:1^name-for-map")
+                    it
+                }
+                .flowName("name-for-map")
+                .flowOn(thread2)
+                .filter {
+                    expect(6, "main:1^:1^name-for-filter")
+                    delay(1)
+                    expect(7, "main:1^:1^name-for-filter")
+                    true
+                }
+                .flowName("name-for-filter")
+                .flowOn(thread1)
+
+        runTest {
+            expect(1, "main:1^")
+            coldFlow.collect {
+                assertEquals(42, it)
+                expect(8, "main:1^")
+                barrier1.complete(Unit)
+            }
+            barrier2.await()
+            finish(11, "main:1^")
+        }
+    }
+
+    @Test
+    fun collectFlow7_withIntermediateOperatorNames() = runTest {
+        expect(1, "main:1^")
+        flow {
+                expect(2, "main:1^", "collect:do-the-assert")
+                emit(21) // 42 / 2 = 21
+                expect(6, "main:1^", "collect:do-the-assert")
+            }
+            .flowName("UNUSED_NAME") // unused because scope is unchanged and operators are fused
+            .mapTraced("multiply-by-3") {
+                expect(3, "main:1^", "collect:do-the-assert", "map:multiply-by-3:transform")
+                it * 2
+            }
+            .filterTraced("mod-2") {
+                expect(
+                    4,
+                    "main:1^",
+                    "collect:do-the-assert",
+                    "map:multiply-by-3:emit",
+                    "filter:mod-2:predicate",
+                )
+                it % 2 == 0
+            }
+            .collectTraced("do-the-assert") {
+                assertEquals(42, it)
+                expect(
+                    5,
+                    "main:1^",
+                    "collect:do-the-assert",
+                    "map:multiply-by-3:emit",
+                    "filter:mod-2:emit",
+                    "collect:do-the-assert:emit",
+                )
+            }
+        finish(7, "main:1^")
+    }
+
+    @Test
+    fun collectFlow8_separateJobs() = runTest {
+        val flowThread = newSingleThreadContext("flow-thread")
+        expect(1, "main:1^")
         val state =
             flowOf(1, 2, 3, 4)
-                .withTraceName("my-flow")
-                .map("multiply-by-3") { it * 2 }
-                .filter("mod-2") { it % 2 == 0 }
-        launch("launch-for-collect") {
-                state.collect("my-collect-call") {
-                    expect(
-                        "main:1^:1^launch-for-collect",
-                        "my-collect-call:collect",
-                        "mod-2:collect",
-                        "multiply-by-3:collect",
-                        "my-flow:collect",
-                        "my-flow:emit",
-                        "multiply-by-3:emit",
-                        "mod-2:emit",
-                        "my-collect-call:emit",
-                    )
+                .transform {
+                    expect("main:1^:1^:1^FLOW_NAME")
+                    emit(it)
+                }
+                .flowName("unused-name")
+                .transform {
+                    expect("main:1^:1^:1^FLOW_NAME")
+                    emit(it)
                 }
+                .flowName("FLOW_NAME")
+                .flowOn(flowThread)
+                .transform {
+                    expect("main:1^:1^")
+                    emit(it)
+                }
+                .stateIn(this)
+
+        launchTraced("LAUNCH_CALL") {
+            state.collectTraced("state-flow") {
+                expect(2, "main:1^:2^LAUNCH_CALL", "collect:state-flow", "collect:state-flow:emit")
             }
-            .join()
+        }
+
+        delay(50)
+        finish(3, "main:1^")
+        cancel()
     }
 }
diff --git a/tracinglib/robolectric/src/MultiThreadedCoroutineTracingTest.kt b/tracinglib/robolectric/src/MultiThreadedCoroutineTracingTest.kt
index c7d432b..8c30a53 100644
--- a/tracinglib/robolectric/src/MultiThreadedCoroutineTracingTest.kt
+++ b/tracinglib/robolectric/src/MultiThreadedCoroutineTracingTest.kt
@@ -14,40 +14,86 @@
  * limitations under the License.
  */
 
-package com.android.app.tracing.coroutines
+package com.android.test.tracing.coroutines
 
-import android.os.HandlerThread
 import android.platform.test.annotations.EnableFlags
+import com.android.app.tracing.coroutines.createCoroutineTracingContext
+import com.android.app.tracing.coroutines.launchTraced
+import com.android.app.tracing.coroutines.nameCoroutine
+import com.android.app.tracing.coroutines.traceCoroutine
+import com.android.app.tracing.coroutines.traceThreadLocal
+import com.android.app.tracing.coroutines.withContextTraced
 import com.android.systemui.Flags.FLAG_COROUTINE_TRACING
-import java.util.concurrent.CyclicBarrier
-import java.util.concurrent.Executors
-import java.util.concurrent.TimeUnit
-import kotlin.coroutines.EmptyCoroutineContext
+import kotlin.coroutines.CoroutineContext
+import kotlinx.coroutines.CompletableDeferred
 import kotlinx.coroutines.CoroutineStart
 import kotlinx.coroutines.DelicateCoroutinesApi
 import kotlinx.coroutines.Dispatchers
 import kotlinx.coroutines.ExperimentalCoroutinesApi
-import kotlinx.coroutines.android.asCoroutineDispatcher
 import kotlinx.coroutines.channels.Channel
 import kotlinx.coroutines.delay
 import kotlinx.coroutines.launch
 import kotlinx.coroutines.newSingleThreadContext
 import kotlinx.coroutines.withContext
-import org.junit.Assert.assertArrayEquals
 import org.junit.Assert.assertEquals
-import org.junit.Assert.assertNotEquals
 import org.junit.Assert.assertNotNull
-import org.junit.Assert.assertNotSame
-import org.junit.Assert.assertNull
-import org.junit.Assert.assertSame
-import org.junit.Ignore
 import org.junit.Test
 
 @OptIn(ExperimentalCoroutinesApi::class, DelicateCoroutinesApi::class)
 @EnableFlags(FLAG_COROUTINE_TRACING)
-class MultiThreadedCoroutineTracingTest : TracingTestBase() {
+class MultiThreadedCoroutineTracingTest : TestBase() {
+
+    override val extraCoroutineContext: CoroutineContext
+        get() = createCoroutineTracingContext("main", includeParentNames = true, strictMode = true)
+
+    @Test
+    fun unconfinedLaunch() = runTest {
+        val barrier1 = CompletableDeferred<Unit>()
+        val barrier2 = CompletableDeferred<Unit>()
+        val barrier3 = CompletableDeferred<Unit>()
+        val thread1 = newSingleThreadContext("thread-#1")
+        val thread2 = newSingleThreadContext("thread-#1")
+        // Do NOT assert order. Doing so will make this test flaky due to its use of
+        // Dispatchers.Unconfined
+        expect("main:1^")
+        launchTraced("unconfined-launch", Dispatchers.Unconfined) {
+                launchTraced("thread1-launch", thread1) {
+                    traceCoroutine("thread1-inner") {
+                        barrier1.await()
+                        expect("main:1^:1^unconfined-launch:1^thread1-launch", "thread1-inner")
+                        barrier2.complete(Unit)
+                    }
+                }
+                launchTraced("default-launch", Dispatchers.Unconfined) {
+                    traceCoroutine("default-inner") {
+                        barrier2.await()
+                        expect(
+                            "main:1^",
+                            "main:1^:1^unconfined-launch:2^default-launch",
+                            "default-inner",
+                        )
+                        barrier3.complete(Unit)
+                    }
+                }
+                launchTraced("thread2-launch", thread2) {
+                    traceCoroutine("thread2-inner") {
+                        barrier3.await()
+                        expect("main:1^:1^unconfined-launch:3^thread2-launch", "thread2-inner")
+                        barrier2.complete(Unit)
+                    }
+                }
+                withContextTraced("unconfined-withContext", Dispatchers.Unconfined) {
+                    expect("main:1^", "main:1^:1^unconfined-launch")
+                    barrier1.complete(Unit)
+                    expect("main:1^", "main:1^:1^unconfined-launch")
+                }
+            }
+            .join()
+        expect("main:1^")
+    }
+
     @Test
-    fun nestedUpdateAndRestoreOnSingleThread_unconfinedDispatcher() = runTestTraced {
+    fun nestedUpdateAndRestoreOnSingleThread_unconfinedDispatcher() = runTest {
         traceCoroutine("parent-span") {
             expect(1, "main:1^", "parent-span")
             launch(Dispatchers.Unconfined) {
@@ -66,7 +112,7 @@ class MultiThreadedCoroutineTracingTest : TracingTestBase() {
                 expect(2, "main:1^", "parent-span", "main:1^:1^")
                 traceCoroutine("child-span") {
                     expect(3, "main:1^", "parent-span", "main:1^:1^", "child-span")
-                    delay(1) // <-- delay will give parent a chance to restore its context
+                    delay(10) // <-- delay will give parent a chance to restore its context
                     // After a delay, the parent resumes, finishing its trace section, so we are
                     // left with only those in the child's scope
                     finish(5, "main:1^:1^", "child-span")
@@ -78,7 +124,7 @@ class MultiThreadedCoroutineTracingTest : TracingTestBase() {
 
     /** @see nestedUpdateAndRestoreOnSingleThread_unconfinedDispatcher */
     @Test
-    fun nestedUpdateAndRestoreOnSingleThread_undispatchedLaunch() = runTestTraced {
+    fun nestedUpdateAndRestoreOnSingleThread_undispatchedLaunch() = runTest {
         traceCoroutine("parent-span") {
             launch(start = CoroutineStart.UNDISPATCHED) {
                 traceCoroutine("child-span") {
@@ -92,7 +138,7 @@ class MultiThreadedCoroutineTracingTest : TracingTestBase() {
     }
 
     @Test
-    fun launchOnSeparateThread_defaultDispatcher() = runTestTraced {
+    fun launchOnSeparateThread_defaultDispatcher() = runTest {
         val channel = Channel<Int>()
         val thread1 = newSingleThreadContext("thread-#1")
         expect("main:1^")
@@ -114,7 +160,7 @@ class MultiThreadedCoroutineTracingTest : TracingTestBase() {
     }
 
     @Test
-    fun testTraceStorage() = runTestTraced {
+    fun testTraceStorage() = runTest {
         val thread1 = newSingleThreadContext("thread-#1")
         val thread2 = newSingleThreadContext("thread-#2")
         val thread3 = newSingleThreadContext("thread-#3")
@@ -125,7 +171,7 @@ class MultiThreadedCoroutineTracingTest : TracingTestBase() {
         // Start 1000 coroutines waiting on [channel]
         val job = launch {
             repeat(1000) {
-                launch("span-for-launch", threadContexts[it % threadContexts.size]) {
+                launchTraced("span-for-launch", threadContexts[it % threadContexts.size]) {
                     assertNotNull(traceThreadLocal.get())
                     traceCoroutine("span-for-fetchData") {
                         channel.receive()
@@ -149,30 +195,30 @@ class MultiThreadedCoroutineTracingTest : TracingTestBase() {
     }
 
     @Test
-    fun nestedTraceSectionsMultiThreaded() = runTestTraced {
+    fun nestedTraceSectionsMultiThreaded() = runTest {
         val context1 = newSingleThreadContext("thread-#1") + nameCoroutine("coroutineA")
         val context2 = newSingleThreadContext("thread-#2") + nameCoroutine("coroutineB")
         val context3 = context1 + nameCoroutine("coroutineC")
 
-        launch("launch#1", context1) {
+        launchTraced("launch#1", context1) {
             expect("main:1^:1^coroutineA")
             delay(1L)
             traceCoroutine("span-1") { expect("main:1^:1^coroutineA", "span-1") }
             expect("main:1^:1^coroutineA")
             expect("main:1^:1^coroutineA")
-            launch("launch#2", context2) {
+            launchTraced("launch#2", context2) {
                 expect("main:1^:1^coroutineA:1^coroutineB")
                 delay(1L)
                 traceCoroutine("span-2") { expect("main:1^:1^coroutineA:1^coroutineB", "span-2") }
                 expect("main:1^:1^coroutineA:1^coroutineB")
                 expect("main:1^:1^coroutineA:1^coroutineB")
-                launch("launch#3", context3) {
+                launchTraced("launch#3", context3) {
                     // "launch#3" is dropped because context has a TraceContextElement.
                     // The CoroutineScope (i.e. `this` in `this.launch {}`) should have a
                     // TraceContextElement, but using TraceContextElement in the passed context is
                     // incorrect.
                     expect("main:1^:1^coroutineA:1^coroutineB:1^coroutineC")
-                    launch("launch#4", context1) {
+                    launchTraced("launch#4", context1) {
                         expect("main:1^:1^coroutineA:1^coroutineB:1^coroutineC:1^coroutineA")
                     }
                 }
@@ -187,162 +233,11 @@ class MultiThreadedCoroutineTracingTest : TracingTestBase() {
     }
 
     @Test
-    fun missingTraceContextObjects() = runTest {
-        val channel = Channel<Int>()
-        val context1 = newSingleThreadContext("thread-#1")
-        val context2 = newSingleThreadContext("thread-#2") + mainTraceContext
-
-        launch("launch#1", context1) {
-            expect()
-            channel.receive()
-            traceCoroutine("span-1") { expect() }
-            expect()
-            launch("launch#2", context2) {
-                // "launch#2" is not traced because TraceContextElement was installed too
-                // late; it is not part of the scope that was launched (i.e., the `this` in
-                // `this.launch {}`)
-                expect("main:1^")
-                channel.receive()
-                traceCoroutine("span-2") { expect("main:1^", "span-2") }
-                expect("main:1^")
-                launch {
-                    // ...it won't appear in the child scope either because in launch("string"), it
-                    // adds: `CoroutineTraceName` + `TraceContextElement`. This demonstrates why
-                    // it is important to only use `TraceContextElement` in the root scope. In this
-                    // case, the `TraceContextElement`  overwrites the name, so the name is dropped.
-                    // Tracing still works with a default, empty name, however.
-                    expect("main:1^:1^")
-                }
-            }
-            expect()
-        }
-        expect()
-
-        channel.send(1)
-        channel.send(2)
-
-        launch(context1) { expect() }
-        launch(context2) { expect("main:2^") }
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
-
-        val traceContext = mainTraceContext as TraceContextElement
-        thread1.execute {
-            try {
-                slicesForThread1.forEachIndexed { index, sliceName ->
-                    assertNull(traceThreadLocal.get())
-                    val oldTrace = traceContext.updateThreadContext(EmptyCoroutineContext)
-                    // await() AFTER updateThreadContext, thus thread #1 always resumes the
-                    // coroutine before thread #2
-                    assertSame(traceThreadLocal.get(), traceContext.contextTraceData)
-
-                    // coroutine body start {
-                    (traceThreadLocal.get() as TraceData).beginSpan("1:$sliceName")
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
-                    val oldTrace = traceContext.updateThreadContext(EmptyCoroutineContext)
-
-                    // coroutine body start {
-                    (traceThreadLocal.get() as TraceData).beginSpan("2:$n")
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
-    fun scopeReentry_withContextFastPath() = runTestTraced {
+    fun scopeReentry_withContextFastPath() = runTest {
         val thread1 = newSingleThreadContext("thread-#1")
         val channel = Channel<Int>()
         val job =
-            launch("#1", thread1) {
+            launchTraced("#1", thread1) {
                 expect("main:1^:1^#1")
                 var i = 0
                 while (true) {
@@ -376,50 +271,4 @@ class MultiThreadedCoroutineTracingTest : TracingTestBase() {
         }
         job.cancel()
     }
-
-    @Test
-    fun traceContextIsCopied() = runTest {
-        expect()
-        val traceContext = mainTraceContext as TraceContextElement
-        withContext(traceContext) {
-            // Not the same object because it should be copied into the current context
-            assertNotSame(traceThreadLocal.get(), traceContext.contextTraceData)
-            // slices is lazily created, so it should be null:
-            assertNull((traceThreadLocal.get() as TraceData).slices)
-            assertNull(traceContext.contextTraceData?.slices)
-            expect("main:1^")
-            traceCoroutine("hello") {
-                assertNotSame(traceThreadLocal.get(), traceContext.contextTraceData)
-                assertArrayEquals(
-                    arrayOf("hello"),
-                    (traceThreadLocal.get() as TraceData).slices?.toArray(),
-                )
-                assertNull(traceContext.contextTraceData?.slices)
-            }
-            assertNotSame(traceThreadLocal.get(), traceContext.contextTraceData)
-            // Because slices is lazily created, it will no longer be null after it was used to
-            // trace "hello", but this time it will be empty
-            assertArrayEquals(arrayOf(), (traceThreadLocal.get() as TraceData).slices?.toArray())
-            assertNull(traceContext.contextTraceData?.slices)
-            expect("main:1^")
-        }
-        expect()
-    }
-
-    @Ignore("Fails with java.net.SocketTimeoutException: Read timed out")
-    @Test
-    fun testHandlerDispatcher() = runTest {
-        val handlerThread = HandlerThread("test-handler-thread")
-        handlerThread.start()
-        val dispatcher = handlerThread.threadHandler.asCoroutineDispatcher()
-        val previousThread = Thread.currentThread().id
-        launch(dispatcher) {
-            val currentThreadBeforeDelay = Thread.currentThread().id
-            delay(1)
-            assertEquals(currentThreadBeforeDelay, Thread.currentThread().id)
-            assertNotEquals(previousThread, currentThreadBeforeDelay)
-            delay(1)
-            assertEquals(currentThreadBeforeDelay, Thread.currentThread().id)
-        }
-    }
 }
diff --git a/tracinglib/robolectric/src/TestBase.kt b/tracinglib/robolectric/src/TestBase.kt
index 0eab0d1..e3be00d 100644
--- a/tracinglib/robolectric/src/TestBase.kt
+++ b/tracinglib/robolectric/src/TestBase.kt
@@ -14,26 +14,40 @@
  * limitations under the License.
  */
 
-package com.android.app.tracing.coroutines
+package com.android.test.tracing.coroutines
 
+import android.os.Looper
 import android.platform.test.flag.junit.SetFlagsRule
-import android.util.Log
 import androidx.test.ext.junit.runners.AndroidJUnit4
-import com.android.app.tracing.coroutines.util.FakeTraceState
-import com.android.app.tracing.coroutines.util.FakeTraceState.getOpenTraceSectionsOnCurrentThread
-import com.android.app.tracing.coroutines.util.ShadowTrace
+import com.android.app.tracing.coroutines.CoroutineTraceName
+import com.android.test.tracing.coroutines.util.FakeTraceState
+import com.android.test.tracing.coroutines.util.FakeTraceState.getOpenTraceSectionsOnCurrentThread
+import com.android.test.tracing.coroutines.util.ShadowTrace
+import java.io.PrintWriter
+import java.io.StringWriter
+import java.util.concurrent.TimeUnit.MILLISECONDS
 import java.util.concurrent.atomic.AtomicInteger
 import kotlin.coroutines.CoroutineContext
 import kotlin.coroutines.EmptyCoroutineContext
+import kotlinx.coroutines.CancellationException
+import kotlinx.coroutines.CoroutineExceptionHandler
 import kotlinx.coroutines.CoroutineScope
+import kotlinx.coroutines.Dispatchers
+import kotlinx.coroutines.Job
 import kotlinx.coroutines.delay
-import kotlinx.coroutines.runBlocking
+import kotlinx.coroutines.launch
 import org.junit.After
+import org.junit.Assert.assertEquals
+import org.junit.Assert.assertTrue
 import org.junit.Before
 import org.junit.ClassRule
 import org.junit.Rule
 import org.junit.runner.RunWith
+import org.robolectric.Shadows.shadowOf
 import org.robolectric.annotation.Config
+import org.robolectric.shadows.ShadowLooper
+
+class InvalidTraceStateException(message: String) : Exception(message)
 
 @RunWith(AndroidJUnit4::class)
 @Config(shadows = [ShadowTrace::class])
@@ -47,30 +61,85 @@ open class TestBase {
 
     @JvmField @Rule val setFlagsRule = SetFlagsRule()
 
-    private var skipAfterCheck = false
+    private val eventCounter = AtomicInteger(0)
+    private val finalEvent = AtomicInteger(INVALID_EVENT)
+    private var expectedExceptions = false
+    private lateinit var allExceptions: MutableList<Throwable>
+    private lateinit var shadowLooper: ShadowLooper
+    private lateinit var mainTraceScope: CoroutineScope
+
+    open val extraCoroutineContext: CoroutineContext
+        get() = EmptyCoroutineContext
 
     @Before
     fun setup() {
-        STRICT_MODE_FOR_TESTING = true
         FakeTraceState.isTracingEnabled = true
         eventCounter.set(0)
-        skipAfterCheck = false
+        allExceptions = mutableListOf()
+        shadowLooper = shadowOf(Looper.getMainLooper())
+        mainTraceScope = CoroutineScope(Dispatchers.Main + extraCoroutineContext)
     }
 
     @After
     fun tearDown() {
-        if (skipAfterCheck) return
+        val sw = StringWriter()
+        val pw = PrintWriter(sw)
+        allExceptions.forEach { it.printStackTrace(pw) }
+        assertTrue("Test failed due to incorrect trace sections\n$sw", allExceptions.isEmpty())
+
         val lastEvent = eventCounter.get()
-        check(lastEvent == FINAL_EVENT || lastEvent == 0) {
-            "Expected `finish(${lastEvent + 1})` to be called, but the test finished"
-        }
+        assertTrue(
+            "`finish()` was never called. Last seen event was #$lastEvent",
+            lastEvent == FINAL_EVENT || lastEvent == 0 || expectedExceptions,
+        )
     }
 
     protected fun runTest(
-        context: CoroutineContext = EmptyCoroutineContext,
+        expectedException: ((Throwable) -> Boolean)? = null,
         block: suspend CoroutineScope.() -> Unit,
     ) {
-        runBlocking(context, block)
+        var foundExpectedException = false
+        if (expectedException != null) expectedExceptions = true
+        mainTraceScope.launch(
+            block = block,
+            context =
+                CoroutineExceptionHandler { _, e ->
+                    if (e is CancellationException) return@CoroutineExceptionHandler // ignore
+                    if (expectedException != null && expectedException(e)) {
+                        foundExpectedException = true
+                        return@CoroutineExceptionHandler // ignore
+                    }
+                    allExceptions.add(e)
+                },
+        )
+
+        for (n in 0..1000) {
+            shadowLooper.idleFor(1, MILLISECONDS)
+        }
+
+        val names = mutableListOf<String?>()
+        var numChildren = 0
+        mainTraceScope.coroutineContext[Job]?.children?.forEach { it ->
+            names.add(it[CoroutineTraceName]?.name)
+            numChildren++
+        }
+
+        val allNames =
+            names.joinToString(prefix = "{ ", separator = ", ", postfix = " }") {
+                it?.let { "\"$it\" " } ?: "unnamed"
+            }
+        assertEquals(
+            "The main test scope still has $numChildren running jobs: $allNames.",
+            0,
+            numChildren,
+        )
+        if (expectedExceptions) {
+            assertTrue("Expected exceptions, but none were thrown", foundExpectedException)
+        }
+    }
+
+    private fun logInvalidTraceState(message: String) {
+        allExceptions.add(InvalidTraceStateException(message))
     }
 
     /**
@@ -78,158 +147,181 @@ open class TestBase {
      * suspension point.
      */
     protected suspend fun expectD(vararg expectedOpenTraceSections: String) {
-        expectD(null, *expectedOpenTraceSections)
+        expect(*expectedOpenTraceSections)
+        delay(1)
+        expect(*expectedOpenTraceSections)
     }
 
     /**
      * Same as [expect], but also call [delay] for 1ms, calling [expect] before and after the
      * suspension point.
      */
-    protected suspend fun expectD(
-        expectedEvent: Int? = null,
-        vararg expectedOpenTraceSections: String,
-    ) {
+    protected suspend fun expectD(expectedEvent: Int, vararg expectedOpenTraceSections: String) {
         expect(expectedEvent, *expectedOpenTraceSections)
         delay(1)
         expect(*expectedOpenTraceSections)
     }
 
-    internal fun expect(vararg expectedOpenTraceSections: String) {
-        expect(null, *expectedOpenTraceSections)
-    }
-
     protected fun expectEndsWith(vararg expectedOpenTraceSections: String) {
-        try {
-            // Inspect trace output to the fake used for recording android.os.Trace API calls:
-            val actualSections = getOpenTraceSectionsOnCurrentThread()
-            check(expectedOpenTraceSections.size <= actualSections.size)
+        // Inspect trace output to the fake used for recording android.os.Trace API calls:
+        val actualSections = getOpenTraceSectionsOnCurrentThread()
+        if (expectedOpenTraceSections.size <= actualSections.size) {
             val lastSections =
                 actualSections.takeLast(expectedOpenTraceSections.size).toTypedArray()
-            assertTraceSectionsEquals(expectedOpenTraceSections, lastSections)
-        } catch (e: IllegalStateException) {
-            skipAfterCheck = true
-        }
-    }
-
-    /**
-     * Checks the currently active trace sections on the current thread, and optionally checks the
-     * order of operations if [expectedEvent] is not null.
-     */
-    protected fun expect(expectedEvent: Int? = null, vararg expectedOpenTraceSections: String) {
-        try {
-            expectInternal(expectedEvent, *expectedOpenTraceSections)
-        } catch (e: IllegalStateException) {
-            skipAfterCheck = true
-            throw e
+            assertTraceSectionsEquals(expectedOpenTraceSections, null, lastSections, null)
+        } else {
+            logInvalidTraceState(
+                "Invalid length: expected size (${expectedOpenTraceSections.size}) <= actual size (${actualSections.size})"
+            )
         }
     }
 
-    private fun expectInternal(
-        expectedEvent: Int? = null,
-        vararg expectedOpenTraceSections: String,
-    ) {
-        if (expectedEvent != null) {
-            val previousEvent = eventCounter.getAndAdd(1)
-            val currentEvent = previousEvent + 1
-            check(expectedEvent == currentEvent) {
+    protected fun expectEvent(expectedEvent: Collection<Int>): Int {
+        val previousEvent = eventCounter.getAndAdd(1)
+        val currentEvent = previousEvent + 1
+        if (!expectedEvent.contains(currentEvent)) {
+            logInvalidTraceState(
                 if (previousEvent == FINAL_EVENT) {
-                    "Expected event=$expectedEvent, but finish() was already called"
+                    "Expected event ${expectedEvent.prettyPrintList()}, but finish() was already called"
                 } else {
-                    "Expected event=$expectedEvent," +
-                        " but the event counter is currently at $currentEvent"
+                    "Expected event ${expectedEvent.prettyPrintList()}," +
+                        " but the event counter is currently at #$currentEvent"
                 }
-            }
+            )
         }
+        return currentEvent
+    }
 
-        // Inspect trace output to the fake used for recording android.os.Trace API calls:
-        assertTraceSectionsEquals(expectedOpenTraceSections, getOpenTraceSectionsOnCurrentThread())
+    internal fun expect(vararg expectedOpenTraceSections: String) {
+        expect(null, *expectedOpenTraceSections)
+    }
+
+    internal fun expect(expectedEvent: Int, vararg expectedOpenTraceSections: String) {
+        expect(listOf(expectedEvent), *expectedOpenTraceSections)
+    }
+
+    /**
+     * Checks the currently active trace sections on the current thread, and optionally checks the
+     * order of operations if [expectedEvent] is not null.
+     */
+    internal fun expect(possibleEventPos: List<Int>?, vararg expectedOpenTraceSections: String) {
+        var currentEvent: Int? = null
+        if (possibleEventPos != null) {
+            currentEvent = expectEvent(possibleEventPos)
+        }
+        val actualOpenSections = getOpenTraceSectionsOnCurrentThread()
+        assertTraceSectionsEquals(
+            expectedOpenTraceSections,
+            possibleEventPos,
+            actualOpenSections,
+            currentEvent,
+        )
     }
 
     private fun assertTraceSectionsEquals(
         expectedOpenTraceSections: Array<out String>,
+        expectedEvent: List<Int>?,
         actualOpenSections: Array<String>,
+        actualEvent: Int?,
     ) {
         val expectedSize = expectedOpenTraceSections.size
         val actualSize = actualOpenSections.size
-        check(expectedSize == actualSize) {
-            createFailureMessage(
-                expectedOpenTraceSections,
-                actualOpenSections,
-                "Size mismatch, expected size $expectedSize but was size $actualSize",
-            )
-        }
-        expectedOpenTraceSections.forEachIndexed { n, expectedTrace ->
-            val actualTrace = actualOpenSections[n]
-            val expected = expectedTrace.substringBefore(";")
-            val actual = actualTrace.substringBefore(";")
-            check(expected == actual) {
+        if (expectedSize != actualSize) {
+            logInvalidTraceState(
                 createFailureMessage(
                     expectedOpenTraceSections,
+                    expectedEvent,
                     actualOpenSections,
-                    "Differed at index #$n, expected \"$expected\" but was \"$actual\"",
+                    actualEvent,
+                    "Size mismatch, expected size $expectedSize but was size $actualSize",
                 )
+            )
+        } else {
+            expectedOpenTraceSections.forEachIndexed { n, expectedTrace ->
+                val actualTrace = actualOpenSections[n]
+                val expected = expectedTrace.substringBefore(";")
+                val actual = actualTrace.substringBefore(";")
+                if (expected != actual) {
+                    logInvalidTraceState(
+                        createFailureMessage(
+                            expectedOpenTraceSections,
+                            expectedEvent,
+                            actualOpenSections,
+                            actualEvent,
+                            "Differed at index #$n, expected \"$expected\" but was \"$actual\"",
+                        )
+                    )
+                    return@forEachIndexed
+                }
             }
         }
     }
 
     private fun createFailureMessage(
         expectedOpenTraceSections: Array<out String>,
+        expectedEventNumber: List<Int>?,
         actualOpenSections: Array<String>,
+        actualEventNumber: Int?,
         extraMessage: String,
-    ): String =
-        """
-                Incorrect trace sections found on current thread:
+    ): String {
+        val locationMarker =
+            if (expectedEventNumber == null || actualEventNumber == null) ""
+            else if (expectedEventNumber.contains(actualEventNumber))
+                " at event #$actualEventNumber"
+            else
+                ", expected event ${expectedEventNumber.prettyPrintList()}, actual event #$actualEventNumber"
+        return """
+                Incorrect trace$locationMarker. $extraMessage
                   Expected : {${expectedOpenTraceSections.prettyPrintList()}}
                   Actual   : {${actualOpenSections.prettyPrintList()}}
-                  $extraMessage
                 """
             .trimIndent()
+    }
 
     /** Same as [expect], except that no more [expect] statements can be called after it. */
     protected fun finish(expectedEvent: Int, vararg expectedOpenTraceSections: String) {
-        try {
-            finishInternal(expectedEvent, *expectedOpenTraceSections)
-        } catch (e: IllegalStateException) {
-            skipAfterCheck = true
-            throw e
-        }
-    }
-
-    private fun finishInternal(expectedEvent: Int, vararg expectedOpenTraceSections: String) {
+        finalEvent.compareAndSet(INVALID_EVENT, expectedEvent)
         val previousEvent = eventCounter.getAndSet(FINAL_EVENT)
         val currentEvent = previousEvent + 1
-        check(expectedEvent == currentEvent) {
-            if (previousEvent == FINAL_EVENT) {
-                "finish() was called more than once"
-            } else {
-                "Finished with event=$expectedEvent," +
-                    " but the event counter is currently $currentEvent"
-            }
+        if (expectedEvent != currentEvent) {
+            logInvalidTraceState(
+                "Expected to finish with event #$expectedEvent, but " +
+                    if (previousEvent == FINAL_EVENT)
+                        "finish() was already called with event #${finalEvent.get()}"
+                    else "the event counter is currently at #$currentEvent"
+            )
         }
-
-        // Inspect trace output to the fake used for recording android.os.Trace API calls:
-        assertTraceSectionsEquals(expectedOpenTraceSections, getOpenTraceSectionsOnCurrentThread())
+        assertTraceSectionsEquals(
+            expectedOpenTraceSections,
+            listOf(expectedEvent),
+            getOpenTraceSectionsOnCurrentThread(),
+            currentEvent,
+        )
     }
-
-    private val eventCounter = AtomicInteger(0)
 }
 
+private const val INVALID_EVENT = -1
+
 private const val FINAL_EVENT = Int.MIN_VALUE
 
-private fun Array<out String>.prettyPrintList(): String {
-    return toList().joinToString(separator = "\", \"", prefix = "\"", postfix = "\"") {
-        it.substringBefore(";")
+private fun Collection<Int>.prettyPrintList(): String {
+    return if (isEmpty()) ""
+    else if (size == 1) "#${iterator().next()}"
+    else {
+        "{${
+            toList().joinToString(
+                separator = ", #",
+                prefix = "#",
+                postfix = "",
+            ) { it.toString() }
+        }}"
     }
 }
 
-private fun check(value: Boolean, lazyMessage: () -> String) {
-    if (DEBUG_TEST) {
-        if (!value) {
-            Log.e("TestBase", lazyMessage(), Throwable())
+private fun Array<out String>.prettyPrintList(): String {
+    return if (isEmpty()) ""
+    else
+        toList().joinToString(separator = "\", \"", prefix = "\"", postfix = "\"") {
+            it.substringBefore(";")
         }
-    } else {
-        kotlin.check(value, lazyMessage)
-    }
 }
-
-private const val DEBUG_TEST = false
diff --git a/tracinglib/robolectric/src/TracingTestBase.kt b/tracinglib/robolectric/src/TracingTestBase.kt
deleted file mode 100644
index 9ace6b4..0000000
--- a/tracinglib/robolectric/src/TracingTestBase.kt
+++ /dev/null
@@ -1,38 +0,0 @@
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
-import android.platform.test.annotations.EnableFlags
-import com.android.systemui.Flags.FLAG_COROUTINE_TRACING
-import kotlin.coroutines.CoroutineContext
-import kotlinx.coroutines.CoroutineScope
-import org.junit.Before
-
-@EnableFlags(FLAG_COROUTINE_TRACING)
-open class TracingTestBase : TestBase() {
-
-    protected lateinit var mainTraceContext: CoroutineContext
-
-    @Before
-    fun setupContexts() {
-        mainTraceContext = createCoroutineTracingContext("main")
-    }
-
-    protected fun runTestTraced(block: suspend CoroutineScope.() -> Unit) {
-        runTest(mainTraceContext, block)
-    }
-}
diff --git a/tracinglib/robolectric/src/util/ExampleClass.kt b/tracinglib/robolectric/src/util/ExampleClass.kt
deleted file mode 100644
index e0f9a25..0000000
--- a/tracinglib/robolectric/src/util/ExampleClass.kt
+++ /dev/null
@@ -1,34 +0,0 @@
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
-package com.android.app.tracing.coroutines.util
-
-import com.android.app.tracing.coroutines.TestBase
-
-class ExampleClass(
-    private val testBase: TestBase,
-    private val incrementCounter: suspend () -> Unit,
-) {
-    suspend fun classMethod(value: Int) {
-        value.inc() // <-- suppress warning that parameter 'value' is unused
-        testBase.expect(
-            "main:1^:1^launch-for-collect:3^",
-            "com.android.app.tracing.coroutines.FlowTracingTest\$stateFlowCollection$1\$collectJob$1$3:collect",
-            "com.android.app.tracing.coroutines.FlowTracingTest\$stateFlowCollection$1\$collectJob$1$3:emit",
-        )
-        incrementCounter()
-    }
-}
diff --git a/tracinglib/robolectric/src/util/FakeTraceState.kt b/tracinglib/robolectric/src/util/FakeTraceState.kt
index 476ee8d..4a0eb8c 100644
--- a/tracinglib/robolectric/src/util/FakeTraceState.kt
+++ b/tracinglib/robolectric/src/util/FakeTraceState.kt
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-package com.android.app.tracing.coroutines.util
+package com.android.test.tracing.coroutines.util
 
 import org.junit.Assert.assertFalse
 
@@ -43,8 +43,7 @@ object FakeTraceState {
                     "but there are no open sections",
                 allThreadStates[threadId].isNullOrEmpty(),
             )
-            // TODO: Replace with .removeLast() once available
-            allThreadStates[threadId]!!.removeAt(allThreadStates[threadId]!!.lastIndex)
+            allThreadStates[threadId]!!.removeLast()
         }
     }
 
diff --git a/tracinglib/robolectric/src/util/ShadowTrace.kt b/tracinglib/robolectric/src/util/ShadowTrace.kt
index 11f8ecd..683f7ab 100644
--- a/tracinglib/robolectric/src/util/ShadowTrace.kt
+++ b/tracinglib/robolectric/src/util/ShadowTrace.kt
@@ -14,9 +14,10 @@
  * limitations under the License.
  */
 
-package com.android.app.tracing.coroutines.util
+package com.android.test.tracing.coroutines.util
 
 import android.os.Trace
+import android.util.Log
 import org.robolectric.annotation.Implementation
 import org.robolectric.annotation.Implements
 
@@ -34,27 +35,27 @@ object ShadowTrace {
     @Implementation
     @JvmStatic
     fun traceBegin(traceTag: Long, methodName: String) {
-        debugLog("traceBegin: name=$methodName")
+        debug { "traceBegin: name=$methodName" }
         FakeTraceState.begin(methodName)
     }
 
     @Implementation
     @JvmStatic
     fun traceEnd(traceTag: Long) {
-        debugLog("traceEnd")
+        debug { "traceEnd" }
         FakeTraceState.end()
     }
 
     @Implementation
     @JvmStatic
     fun asyncTraceBegin(traceTag: Long, methodName: String, cookie: Int) {
-        debugLog("asyncTraceBegin: name=$methodName cookie=${cookie.toHexString()}")
+        debug { "asyncTraceBegin: name=$methodName cookie=${cookie.toHexString()}" }
     }
 
     @Implementation
     @JvmStatic
     fun asyncTraceEnd(traceTag: Long, methodName: String, cookie: Int) {
-        debugLog("asyncTraceEnd: name=$methodName cookie=${cookie.toHexString()}")
+        debug { "asyncTraceEnd: name=$methodName cookie=${cookie.toHexString()}" }
     }
 
     @Implementation
@@ -65,28 +66,35 @@ object ShadowTrace {
         methodName: String,
         cookie: Int,
     ) {
-        debugLog(
+        debug {
             "asyncTraceForTrackBegin: track=$trackName name=$methodName cookie=${cookie.toHexString()}"
-        )
+        }
     }
 
     @Implementation
     @JvmStatic
     fun asyncTraceForTrackEnd(traceTag: Long, trackName: String, methodName: String, cookie: Int) {
-        debugLog(
+        debug {
             "asyncTraceForTrackEnd: track=$trackName name=$methodName cookie=${cookie.toHexString()}"
-        )
+        }
     }
 
     @Implementation
     @JvmStatic
     fun instant(traceTag: Long, eventName: String) {
-        debugLog("instant: name=$eventName")
+        debug { "instant: name=$eventName" }
     }
 
     @Implementation
     @JvmStatic
     fun instantForTrack(traceTag: Long, trackName: String, eventName: String) {
-        debugLog("instantForTrack: track=$trackName name=$eventName")
+        debug { "instantForTrack: track=$trackName name=$eventName" }
     }
 }
+
+private const val DEBUG = false
+
+/** Log a message with a tag indicating the current thread ID */
+private fun debug(message: () -> String) {
+    if (DEBUG) Log.d("ShadowTrace", "Thread #${currentThreadId()}: $message")
+}
diff --git a/tracinglib/robolectric/src/util/Util.kt b/tracinglib/robolectric/src/util/Util.kt
index 7e405d1..15349d2 100644
--- a/tracinglib/robolectric/src/util/Util.kt
+++ b/tracinglib/robolectric/src/util/Util.kt
@@ -14,13 +14,6 @@
  * limitations under the License.
  */
 
-package com.android.app.tracing.coroutines.util
-
-const val DEBUG = false
-
-/** Log a message with a tag indicating the current thread ID */
-internal fun debugLog(message: String) {
-    if (DEBUG) println("Thread #${currentThreadId()}: $message")
-}
+package com.android.test.tracing.coroutines.util
 
 internal fun currentThreadId(): Long = Thread.currentThread().id
diff --git a/viewcapturelib/AndroidManifest.xml b/viewcapturelib/AndroidManifest.xml
index 1da8129..d86f1c5 100644
--- a/viewcapturelib/AndroidManifest.xml
+++ b/viewcapturelib/AndroidManifest.xml
@@ -15,9 +15,4 @@
      limitations under the License.
 -->
 
-<manifest xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:tools="http://schemas.android.com/tools"
-    package="com.android.app.viewcapture">
-    <uses-permission android:name="android.permission.WRITE_SECURE_SETTINGS"
-        tools:ignore="ProtectedPermissions" />
-</manifest>
+<manifest package="com.android.app.viewcapture"/>
\ No newline at end of file
diff --git a/viewcapturelib/OWNERS b/viewcapturelib/OWNERS
index 30bdc84..2f30b7c 100644
--- a/viewcapturelib/OWNERS
+++ b/viewcapturelib/OWNERS
@@ -1,2 +1,3 @@
 sunnygoyal@google.com
 andonian@google.com
+include platform/development:/tools/winscope/OWNERS
diff --git a/viewcapturelib/src/com/android/app/viewcapture/ViewCapture.java b/viewcapturelib/src/com/android/app/viewcapture/ViewCapture.java
index 761b863..33f6a95 100644
--- a/viewcapturelib/src/com/android/app/viewcapture/ViewCapture.java
+++ b/viewcapturelib/src/com/android/app/viewcapture/ViewCapture.java
@@ -311,8 +311,12 @@ public abstract class ViewCapture {
             captureViewTree(mRoot, mViewPropertyRef);
             ViewPropertyRef captured = mViewPropertyRef.next;
             if (captured != null) {
-                captured.callback = mCaptureCallback;
                 captured.elapsedRealtimeNanos = SystemClock.elapsedRealtimeNanos();
+
+                // Main thread writes volatile field:
+                // guarantee that variable changes prior the field write are visible to bg thread
+                captured.volatileCallback = mCaptureCallback;
+
                 mBgExecutor.execute(captured);
             }
             mIsFirstFrame = false;
@@ -552,9 +556,11 @@ public abstract class ViewCapture {
 
         public ViewPropertyRef next;
 
-        public Consumer<ViewPropertyRef> callback = null;
         public long elapsedRealtimeNanos = 0;
 
+        // Volatile field to establish happens-before relationship between main and bg threads
+        // (see JSR-133: Java Memory Model and Thread Specification)
+        public volatile Consumer<ViewPropertyRef> volatileCallback = null;
 
         public void transferFrom(View in) {
             view = in;
@@ -651,8 +657,10 @@ public abstract class ViewCapture {
 
         @Override
         public void run() {
-            Consumer<ViewPropertyRef> oldCallback = callback;
-            callback = null;
+            // Bg thread reads volatile field:
+            // guarantee that variable changes in main thread prior the field write are visible
+            Consumer<ViewPropertyRef> oldCallback = volatileCallback;
+            volatileCallback = null;
             if (oldCallback != null) {
                 oldCallback.accept(this);
             }
diff --git a/viewcapturelib/src/com/android/app/viewcapture/ViewCaptureAwareWindowManager.kt b/viewcapturelib/src/com/android/app/viewcapture/ViewCaptureAwareWindowManager.kt
index 172975b..59e35da 100644
--- a/viewcapturelib/src/com/android/app/viewcapture/ViewCaptureAwareWindowManager.kt
+++ b/viewcapturelib/src/com/android/app/viewcapture/ViewCaptureAwareWindowManager.kt
@@ -17,7 +17,6 @@
 package com.android.app.viewcapture
 
 import android.media.permission.SafeCloseable
-import android.util.Log
 import android.view.View
 import android.view.ViewGroup
 import android.view.WindowManager
@@ -63,8 +62,6 @@ class ViewCaptureAwareWindowManager(
             if (viewCaptureCloseableMap.containsKey(view)) {
                 viewCaptureCloseableMap[view]?.close()
                 viewCaptureCloseableMap.remove(view)
-            } else {
-                Log.wtf(TAG, "removeView called with view not present in closeable map!")
             }
         }
     }
diff --git a/viewcapturelib/src/com/android/app/viewcapture/ViewCaptureFactory.kt b/viewcapturelib/src/com/android/app/viewcapture/ViewCaptureFactory.kt
index c2b2a3f..2e6a783 100644
--- a/viewcapturelib/src/com/android/app/viewcapture/ViewCaptureFactory.kt
+++ b/viewcapturelib/src/com/android/app/viewcapture/ViewCaptureFactory.kt
@@ -17,7 +17,6 @@
 package com.android.app.viewcapture
 
 import android.content.Context
-import android.os.Looper
 import android.os.Process
 import android.tracing.Flags
 import android.util.Log
@@ -27,62 +26,61 @@ import android.view.WindowManager
  * Factory to create polymorphic instances of ViewCapture according to build configurations and
  * flags.
  */
-class ViewCaptureFactory {
-    companion object {
-        private val TAG = ViewCaptureFactory::class.java.simpleName
-        private var instance: ViewCapture? = null
+object ViewCaptureFactory {
+    private val TAG = ViewCaptureFactory::class.java.simpleName
+    private val instance: ViewCapture by lazy { createInstance() }
+    private lateinit var appContext: Context
 
-        @JvmStatic
-        fun getInstance(context: Context): ViewCapture {
-            if (Looper.myLooper() != Looper.getMainLooper()) {
-                return ViewCapture.MAIN_EXECUTOR.submit { getInstance(context) }.get()
+    private fun createInstance(): ViewCapture {
+        return when {
+            !android.os.Build.IS_DEBUGGABLE -> {
+                Log.i(TAG, "instantiating ${NoOpViewCapture::class.java.simpleName}")
+                NoOpViewCapture()
             }
-
-            if (instance != null) {
-                return instance!!
+            !Flags.perfettoViewCaptureTracing() -> {
+                Log.i(TAG, "instantiating ${SettingsAwareViewCapture::class.java.simpleName}")
+                SettingsAwareViewCapture(
+                    appContext,
+                    ViewCapture.createAndStartNewLooperExecutor(
+                        "SAViewCapture",
+                        Process.THREAD_PRIORITY_FOREGROUND,
+                    ),
+                )
+            }
+            else -> {
+                Log.i(TAG, "instantiating ${PerfettoViewCapture::class.java.simpleName}")
+                PerfettoViewCapture(
+                    appContext,
+                    ViewCapture.createAndStartNewLooperExecutor(
+                        "PerfettoViewCapture",
+                        Process.THREAD_PRIORITY_FOREGROUND,
+                    ),
+                )
             }
-
-            return when {
-                !android.os.Build.IS_DEBUGGABLE -> {
-                    Log.i(TAG, "instantiating ${NoOpViewCapture::class.java.simpleName}")
-                    NoOpViewCapture()
-                }
-                !Flags.perfettoViewCaptureTracing() -> {
-                    Log.i(TAG, "instantiating ${SettingsAwareViewCapture::class.java.simpleName}")
-                    SettingsAwareViewCapture(
-                        context.applicationContext,
-                        ViewCapture.createAndStartNewLooperExecutor(
-                            "SAViewCapture",
-                            Process.THREAD_PRIORITY_FOREGROUND
-                        )
-                    )
-                }
-                else -> {
-                    Log.i(TAG, "instantiating ${PerfettoViewCapture::class.java.simpleName}")
-                    PerfettoViewCapture(
-                        context.applicationContext,
-                        ViewCapture.createAndStartNewLooperExecutor(
-                            "PerfettoViewCapture",
-                            Process.THREAD_PRIORITY_FOREGROUND
-                        )
-                    )
-                }
-            }.also { instance = it }
         }
+    }
 
-        /** Returns an instance of [ViewCaptureAwareWindowManager]. */
-        @JvmStatic
-        fun getViewCaptureAwareWindowManagerInstance(
-            context: Context,
-            isViewCaptureTracingEnabled: Boolean
-        ): ViewCaptureAwareWindowManager {
-            val windowManager = context.getSystemService(Context.WINDOW_SERVICE) as WindowManager
-            val lazyViewCapture = lazy { getInstance(context) }
-            return ViewCaptureAwareWindowManager(
-                windowManager,
-                lazyViewCapture,
-                isViewCaptureTracingEnabled
-            )
+    /** Returns an instance of [ViewCapture]. */
+    @JvmStatic
+    fun getInstance(context: Context): ViewCapture {
+        if (!this::appContext.isInitialized) {
+            synchronized(this) { appContext = context.applicationContext }
         }
+        return instance
+    }
+
+    /** Returns an instance of [ViewCaptureAwareWindowManager]. */
+    @JvmStatic
+    fun getViewCaptureAwareWindowManagerInstance(
+        context: Context,
+        isViewCaptureTracingEnabled: Boolean,
+    ): ViewCaptureAwareWindowManager {
+        val windowManager = context.getSystemService(Context.WINDOW_SERVICE) as WindowManager
+        val lazyViewCapture = lazy { getInstance(context) }
+        return ViewCaptureAwareWindowManager(
+            windowManager,
+            lazyViewCapture,
+            isViewCaptureTracingEnabled,
+        )
     }
 }
diff --git a/viewcapturelib/tests/AndroidManifest.xml b/viewcapturelib/tests/AndroidManifest.xml
index 8d31c0e..f32f93c 100644
--- a/viewcapturelib/tests/AndroidManifest.xml
+++ b/viewcapturelib/tests/AndroidManifest.xml
@@ -15,7 +15,12 @@
   -->
 
 <manifest xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:tools="http://schemas.android.com/tools"
     package="com.android.app.viewcapture.test">
+
+    <uses-permission android:name="android.permission.WRITE_SECURE_SETTINGS"
+        tools:ignore="ProtectedPermissions" />
+
     <application
         android:debuggable="true"
         android:theme="@android:style/Theme.NoTitleBar">
diff --git a/weathereffects/graphics/assets/shaders/fog_effect.agsl b/weathereffects/graphics/assets/shaders/fog_effect.agsl
index 51ae25b..0527c7c 100644
--- a/weathereffects/graphics/assets/shaders/fog_effect.agsl
+++ b/weathereffects/graphics/assets/shaders/fog_effect.agsl
@@ -20,26 +20,22 @@ uniform shader fog;
 uniform shader clouds;
 uniform half2 fogSize;
 uniform half2 cloudsSize;
-uniform float2 uvOffsetFgd;
-uniform float2 uvScaleFgd;
-uniform float2 uvOffsetBgd;
-uniform float2 uvScaleBgd;
 uniform half4 time;
 uniform half screenAspectRatio;
 uniform half2 screenSize;
 uniform half pixelDensity;
 uniform half intensity;
+uniform mat3 transformMatrixBitmap;
+uniform mat3 transformMatrixWeather;
 
 #include "shaders/constants.agsl"
 #include "shaders/utils.agsl"
 #include "shaders/simplex2d.agsl"
 
-const vec3 fogColor = vec3(0.20);
+const vec3 fogScrimColor = vec3(0.20);
+const vec3 fogColor = vec3(1.0);
 
 vec4 main(float2 fragCoord) {
-    float2 uv = fragCoord / screenSize;
-    uv.y /= screenAspectRatio;
-
     vec2 timeForeground = vec2(time.x, time.y);
     vec2 timeBackground = vec2(time.z, time.w);
 
@@ -51,15 +47,22 @@ vec4 main(float2 fragCoord) {
      * - Foreground
      * - fgdFogFar (layer 1) / fgdFogClose (layer 2)
      */
+    float2 adjustedCoord = transformPoint(transformMatrixBitmap, fragCoord);
+    float2 uv = transformPoint(transformMatrixWeather, fragCoord) / screenSize;
+    uv.y /= screenAspectRatio;
 
-    // Load foreground and blend it with constant solid fog color.
-    vec4 fgd = foreground.eval(fragCoord * uvScaleFgd + uvOffsetFgd);
-    fgd.rgb = mix(fgd.rgb, fogColor, 0.15 * intensity * fgd.a);
+    // Load background and foreground.
+    vec4 fgd = foreground.eval(adjustedCoord);
+    vec4 bgd = background.eval(adjustedCoord);
 
-    // Load background and blend it with constant solid fog color.
-    vec4 bgd = background.eval(fragCoord * uvScaleBgd + uvOffsetBgd);
-    bgd.rgb = mix(bgd.rgb, fogColor, 0.32 * intensity * bgd.a);
+    // Adjusts contrast and brightness.
+    float noise = 0.025 * triangleNoise(fragCoord.xy + vec2(12.31, 1024.1241));
+    bgd.rgb = imageRangeConversion(bgd.rgb, 0.8, 0.02, noise, intensity);
+    fgd.rgb = imageRangeConversion(fgd.rgb, 0.8, 0.02, noise, intensity);
 
+    // Blend them with constant solid fog color.
+    bgd.rgb = mix(bgd.rgb, fogScrimColor, 0.14 * intensity * bgd.a);
+    fgd.rgb = mix(fgd.rgb, fogScrimColor, 0.12 * intensity * fgd.a);
     /* Add first layer: background. */
     // set background color as the starting layer.
     vec4 color = bgd;
@@ -115,11 +118,12 @@ vec4 main(float2 fragCoord) {
             bgFogFarCombined *
             smoothstep(-0.1, 0.05, uv.y + fogHeightVariation) *
             (1. - smoothstep(0.15, 0.35, uv.y + fogHeightVariation));
-        bgdFogLayer1 *= 0.45 * (1. - bgdDither);
+        bgdFogLayer1 *= 1.1;
+        bgdFogLayer1 += 0.55 * bgdDither;
         bgdFogLayer1 = clamp(bgdFogLayer1, 0., 1.);
         // Blend with background.
-        color.rgb = screenBlend(color.rgb, bgdFogLayer1 * intensity);
-    //    color.rgb = vec3(bgdFogLayer1 * intensity);
+        color.rgb =
+            normalBlendNotPremultiplied(color.rgb, fogColor * 0.8, bgdFogLayer1 * intensity);
     }
 
     if (uv.y > 0.23 && uv.y < 0.87) {
@@ -131,10 +135,12 @@ vec4 main(float2 fragCoord) {
             bgFogloseCombined *
             smoothstep(0.25, 0.55, uv.y + fogHeightVariation) *
             (1. - smoothstep(0.7, 0.85, uv.y + fogHeightVariation));
-        bgdFogLayer2 *= 0.6 * (1.- bgdDither);
+        bgdFogLayer2 *= 1.2;
+        bgdFogLayer2 += 0.6 * bgdDither;
         bgdFogLayer2 = clamp(bgdFogLayer2, 0., 1.);
         // Blend with background.
-        color.rgb = screenBlend(color.rgb, bgdFogLayer2 * intensity);
+        color.rgb =
+            normalBlendNotPremultiplied(color.rgb, fogColor * 0.85, bgdFogLayer2 * intensity);
     }
 
     /* Add third layer: foreground. */
@@ -151,9 +157,11 @@ vec4 main(float2 fragCoord) {
                     1.,
                     0.5 * intensity * smoothstep(0.72, 0.92, uv.y + fogHeightVariation)) *
                 smoothstep(0.42, 0.82, uv.y + fogHeightVariation);
-        fgdFogLayer1 *= 0.65 * (1. - fgdDither);
+        fgdFogLayer1 *= 1.3;
+        fgdFogLayer1 += 0.6 * fgdDither;
         fgdFogLayer1 = clamp(fgdFogLayer1, 0., 1.);
-        color.rgb = screenBlend(color.rgb, fgdFogLayer1 * intensity);
+        color.rgb =
+            normalBlendNotPremultiplied(color.rgb, fogColor * 0.9, fgdFogLayer1 * intensity);
     }
     if (uv.y > 0.25) {
         // Foreground fog, layer 2.
@@ -162,11 +170,12 @@ vec4 main(float2 fragCoord) {
                 mix(
                     fgdFogClose.g,
                     1.,
-                    0.65 * intensity * smoothstep(0.85, 0.98, uv.y + fogHeightVariation)) *
+                    0.65 * intensity * smoothstep(0.85, 1.3, uv.y + fogHeightVariation)) *
                 smoothstep(0.30, 0.90, uv.y + uv.x * 0.09);
-        fgdFogLayer2 *= 0.8 * (1. - fgdDither);
+        fgdFogLayer2 *= 1.4;
+        fgdFogLayer2 += 0.6 * fgdDither;
         fgdFogLayer2 = clamp(fgdFogLayer2, 0., 1.);
-        color.rgb = screenBlend(color.rgb, fgdFogLayer2 * intensity);
+        color.rgb = normalBlendNotPremultiplied(color.rgb, fogColor, fgdFogLayer2 * intensity);
     }
     return color;
 }
\ No newline at end of file
diff --git a/weathereffects/graphics/assets/shaders/lens_flare.agsl b/weathereffects/graphics/assets/shaders/lens_flare.agsl
index 016f6bf..d32f8fe 100644
--- a/weathereffects/graphics/assets/shaders/lens_flare.agsl
+++ b/weathereffects/graphics/assets/shaders/lens_flare.agsl
@@ -13,5 +13,43 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
+vec3 addFlareCircle(
+    vec2 uv, vec2 sunPos, float distScale, float size, float chroAb, float definition) {
+    float dR = distance(uv, distScale * (1. - chroAb) * sunPos) / (size * (1. - chroAb));
+    float dG = distance(uv, distScale * 1. * sunPos) / (size);
+    float dB = distance(uv, distScale * (1 + chroAb) * sunPos) / (size * (1. + chroAb));
+    float wR = 1.0 - smoothstep(definition, 0.75, dR);
+    float wG = 1.0 - smoothstep(definition, 0.75, dG);
+    float wB = 1.0 - smoothstep(definition, 0.75, dB);
+    return vec3(wR, wG, wB);
+}
 
-// TODO(b/347299395): to add flare
+vec3 addFlareRing(vec2 uv, vec2 sunPos, float distScale, float size, float chroAb, float stroke) {
+    float dR = distance(uv, distScale * (1. - chroAb) * sunPos) / (size * (1. - chroAb));
+    float dG = distance(uv, distScale * 1. * sunPos) / (size);
+    float dB = distance(uv, distScale * (1 + chroAb) * sunPos) / (size * (1. + chroAb));
+    float wR = smoothstep(0.75 - stroke, 0.75, dR) - smoothstep(0.75, 0.75 + stroke, dR);
+    float wG = smoothstep(0.75 - stroke, 0.75, dG) - smoothstep(0.75, 0.75 + stroke, dG);
+    float wB = smoothstep(0.75 - stroke, 0.75, dB) - smoothstep(0.75, 0.75 + stroke, dB);
+    return vec3(wR, wG, wB);
+}
+
+vec3 addFlareCircle(vec2 uv, vec2 sunPos, float distScale, float size, float chroAb) {
+    return addFlareCircle(uv, sunPos, distScale, size, chroAb, 0.25);
+}
+
+vec3 addFlareDistorted(vec2 uv, vec2 sunPos, float distScale, float size, float chroAb) {
+    vec2 uvd = uv*(length(uv));
+    return addFlareCircle(uvd, sunPos, distScale, size, chroAb, 0.35);
+}
+
+vec3 addFlare(vec3 color, vec2 uv, vec2 sunPos, float intensity, float time) {
+    vec3 ret = vec3(0.0);
+    ret += vec3(0.7) * addFlareCircle(uv, sunPos, -0.1, 0.1, 0.04);
+    ret += vec3(0.64) * addFlareCircle(uv, sunPos, 0.05, 0.035, 0.04);
+    ret += vec3(0.5) * addFlareCircle(uv, sunPos, -0.22, 0.18, 0.04);
+    ret += vec3(0.34) * addFlareRing(uv, sunPos, -0.35, 0.4, 0.02, 0.16);
+    ret += vec3(0.52) * addFlareDistorted(uv, sunPos, -0.4, 0.3, 0.08);
+    ret += vec3(0.57) * addFlareDistorted(uv, sunPos, 0.4, 0.15, 0.06);
+    return mix(color.rgb, vec3(1., 0.95, 0.88), intensity * ret);
+}
diff --git a/weathereffects/graphics/assets/shaders/rain_constants.agsl b/weathereffects/graphics/assets/shaders/rain_constants.agsl
index ecef00e..79e73b7 100644
--- a/weathereffects/graphics/assets/shaders/rain_constants.agsl
+++ b/weathereffects/graphics/assets/shaders/rain_constants.agsl
@@ -16,9 +16,9 @@
 
  /* Color and intensity constants. */
  // The color of the highlight of each drop.
- const vec3 highlightColor = vec3(1.); // white
+ const vec3 highlightColor = vec3(0.9, 1., 1.); // white
  // The color of the contact ambient occlusion shadow.
- const vec3 contactShadowColor = vec3(0.); // black
+ const vec3 contactShadowColor = vec3(0.2); // black
  // The tint color of the drop.
  const vec3 dropTint = vec3(1.); // white
 
diff --git a/weathereffects/graphics/assets/shaders/rain_shower_layer.agsl b/weathereffects/graphics/assets/shaders/rain_shower_layer.agsl
index 403c734..f039c76 100644
--- a/weathereffects/graphics/assets/shaders/rain_shower_layer.agsl
+++ b/weathereffects/graphics/assets/shaders/rain_shower_layer.agsl
@@ -17,15 +17,13 @@
 uniform shader foreground;
 uniform shader background;
 uniform shader outlineBuffer;
-uniform float2 uvOffsetFgd;
-uniform float2 uvScaleFgd;
-uniform float2 uvOffsetBgd;
-uniform float2 uvScaleBgd;
 uniform float time;
 uniform float screenAspectRatio;
 uniform float gridScale;
 uniform float2 screenSize;
 uniform half intensity;
+uniform mat3 transformMatrixBitmap;
+uniform mat3 transformMatrixWeather;
 
 #include "shaders/constants.agsl"
 #include "shaders/utils.agsl"
@@ -57,9 +55,9 @@ vec3 drawSplashes(vec2 uv, vec2 fragCoord, vec3 color) {
     vec2 pixUv = cellUv;
     pixUv.x *= -1;
     vec2 pixDistance = screenSize * pixUv / gridSize;
-    float2 uvTextureFgd = (fragCoord + pixDistance) * uvScaleFgd + uvOffsetFgd;
+    float2 uvTexture =  transformPoint(transformMatrixBitmap, fragCoord + pixDistance);
 
-    float outline = step(0.1, outlineBuffer.eval(uvTextureFgd).r);
+    float outline = step(0.1, outlineBuffer.eval(uvTexture).r);
     if (outline < 0.1) {
         // Simply return the given color when it's not considered as an outline.
         return color;
@@ -81,14 +79,18 @@ vec3 drawSplashes(vec2 uv, vec2 fragCoord, vec3 color) {
 }
 
 vec4 main(float2 fragCoord) {
-    float2 uv = fragCoord / screenSize;
-
-    // Adjusts the UVs to have the expected rect of the image.
-    float2 uvTextureFgd = fragCoord * uvScaleFgd + uvOffsetFgd;
-    float2 uvTextureBgd = fragCoord * uvScaleBgd + uvOffsetBgd;
-
-    vec4 colorForeground = foreground.eval(uvTextureFgd);
-    vec4 color = background.eval(uvTextureBgd);
+    // Apply transform matrix to fragCoord
+    float2 uvTexture = transformPoint(transformMatrixBitmap, fragCoord);
+    // Calculate uv for snow based on transformed coordinates
+    float2 uv = transformPoint(transformMatrixWeather, fragCoord) / screenSize;
+
+    vec4 colorForeground = foreground.eval(uvTexture);
+    vec4 color = background.eval(uvTexture);
+
+    // Adjusts contrast and brightness.
+    float noise = 0.025 * triangleNoise(fragCoord.xy + vec2(12.31, 1024.1241));
+    color.rgb = imageRangeConversion(color.rgb, 0.84, 0.02, noise, intensity);
+    colorForeground.rgb = imageRangeConversion(colorForeground.rgb, 0.84, 0.02, noise, intensity);
 
     // Add rotation for the rain (as a default sin(time * 0.05) can be used).
     float variation = wiggle(time - uv.y * 1.1, 0.10);
diff --git a/weathereffects/graphics/assets/shaders/snow_accumulation.agsl b/weathereffects/graphics/assets/shaders/snow_accumulation.agsl
index a3a4959..0b23a03 100644
--- a/weathereffects/graphics/assets/shaders/snow_accumulation.agsl
+++ b/weathereffects/graphics/assets/shaders/snow_accumulation.agsl
@@ -15,8 +15,9 @@
  */
 
 uniform shader foreground;
-uniform half imageWidth;
 uniform half snowThickness;
+uniform half scale;
+uniform half screenWidth;
 
 #include "shaders/simplex2d.agsl"
 #include "shaders/utils.agsl"
@@ -27,7 +28,7 @@ float random(vec2 uv) {
 
 vec4 main(float2 fragCoord) {
     // fragCoord should be already the adjusted UVs to have the expected rect of the image.
-    vec2 uv = fragCoord / imageWidth;
+    vec2 uv = fragCoord * scale / screenWidth;
     float variation = 0.3 + simplex2d(11. * uv);
     float distance = variation * snowThickness;
 
diff --git a/weathereffects/graphics/assets/shaders/snow_effect.agsl b/weathereffects/graphics/assets/shaders/snow_effect.agsl
index d88de3c..7d7e8e9 100644
--- a/weathereffects/graphics/assets/shaders/snow_effect.agsl
+++ b/weathereffects/graphics/assets/shaders/snow_effect.agsl
@@ -18,14 +18,12 @@ uniform shader foreground;
 uniform shader background;
 uniform shader accumulatedSnow;
 uniform shader noise;
-uniform float2 uvOffsetFgd;
-uniform float2 uvScaleFgd;
-uniform float2 uvOffsetBgd;
-uniform float2 uvScaleBgd;
 uniform float2 gridSize;
 uniform float time;
 uniform float screenAspectRatio;
 uniform float2 screenSize;
+uniform mat3 transformMatrixBitmap;
+uniform mat3 transformMatrixWeather;
 
 #include "shaders/constants.agsl"
 #include "shaders/utils.agsl"
@@ -42,9 +40,6 @@ const float midSnowLayerIndex = 3;
 const float closestSnowLayerIndex = 0;
 
 vec4 main(float2 fragCoord) {
-    float2 uv = fragCoord / screenSize;
-    float2 uvAdjusted = vec2(uv.x, uv.y / screenAspectRatio);
-
     /**
      * The effect is consisted of 2 image textures (foreground and background) + 10 layers of
      * snow + 1 layer of snow accumulation. Below describes the rendering order (back to front):
@@ -55,10 +50,22 @@ vec4 main(float2 fragCoord) {
      * 5. Foreground snow layers (from mid layer to closest layer)
      */
 
-    // Adjusts the UVs to have the expected rect of the image.
-    float2 adjustedUvForeground = fragCoord * uvScaleFgd + uvOffsetFgd;
-    vec4 colorForeground = foreground.eval(adjustedUvForeground);
-    vec4 colorBackground = background.eval(fragCoord * uvScaleBgd + uvOffsetBgd);
+    // Apply transform matrix to fragCoord
+    float2 adjustedUv = transformPoint(transformMatrixBitmap, fragCoord);
+
+    // Calculate uv for snow based on transformed coordinates
+    float2 uv = transformPoint(transformMatrixWeather, fragCoord) / screenSize;
+    float2 uvAdjusted = vec2(uv.x, uv.y / screenAspectRatio);
+
+    vec4 colorForeground = foreground.eval(adjustedUv);
+    vec4 colorBackground = background.eval(adjustedUv);
+
+     // Adjusts contrast and brightness.
+    float noiseT = triangleNoise(fragCoord.xy + vec2(12.31, 1024.1241));
+    colorBackground.rgb =
+        imageRangeConversion(colorBackground.rgb, 0.88, 0.02, noiseT * 0.025, intensity);
+    colorForeground.rgb =
+        imageRangeConversion(colorForeground.rgb, 0.88, 0.02, noiseT * 0.025, intensity);
 
     // 1. Draw background.
     vec4 color = colorBackground;
@@ -91,7 +98,7 @@ vec4 main(float2 fragCoord) {
     float dither = abs(triangleNoise(fragCoord * 0.01));
 
     // Get the accumulated snow buffer. r contains its mask, g contains some random noise.
-    vec2 accSnow = accumulatedSnow.eval(adjustedUvForeground).rg;
+    vec2 accSnow = accumulatedSnow.eval(adjustedUv).rg;
     // Sharpen the mask of the accumulated snow, but not in excess.
     float accSnowMask = smoothstep(0.1, 0.9, /* mask= */ accSnow.r);
     // Makes the edges of the snow layer accumulation rougher.
diff --git a/weathereffects/graphics/assets/shaders/sun_effect.agsl b/weathereffects/graphics/assets/shaders/sun_effect.agsl
index 6eb7505..601b3d3 100644
--- a/weathereffects/graphics/assets/shaders/sun_effect.agsl
+++ b/weathereffects/graphics/assets/shaders/sun_effect.agsl
@@ -16,34 +16,128 @@
 
 uniform shader foreground;
 uniform shader background;
-uniform float2 uvOffsetFgd;
-uniform float2 uvScaleFgd;
-uniform float2 uvOffsetBgd;
-uniform float2 uvScaleBgd;
 uniform float screenAspectRatio;
 uniform float2 screenSize;
 uniform float time;
 uniform float intensity;
+uniform mat3 transformMatrixBitmap;
+uniform mat3 transformMatrixWeather;
+
 
 #include "shaders/constants.agsl"
 #include "shaders/utils.agsl"
-#include "shaders/simplex2d.agsl"
+#include "shaders/simplex3d.agsl"
 
 #include "shaders/lens_flare.agsl"
 
-vec4 main(float2 fragCoord) {
-    float2 uv = fragCoord / screenSize;
-    uv.y /= screenAspectRatio;
+const vec2 sunCenter = vec2(0.57, -0.8);
+const vec3 godRaysColor = vec3(1., 0.857, 0.71428);
+
+float calculateRay(float angle, float time) {
+    /*
+     * God rays oscilations. It works like a fourier series, using the the uv position angle
+     * and time and phase to adjust how it looks.
+     */
+    float rays = 17.5 + 8.0 * sin(3. * angle + time);
+    rays += 4.0 * sin(12. * angle - 0.3 * time);
+    rays += 4.0 * sin(25. * angle + 0.9252 * time);
+    rays += -1.8 * cos(38. * angle - 0.114 * time);
+    rays += 0.45 * cos(60.124 * angle + 0.251 * time);
+    return rays;
+}
+
+float godRays(vec2 uv, vec2 center, float phase, float frequency, float time, float intensity) {
+    // Adjust position to center.
+    uv -= center;
+    // For each position, get the angle.
+    float angle = atan(uv.y, uv.x);
+    // The glow around the position of the sun.
+    float sunGlow = 1.0 / (1. + 20.0 * length(uv));
+    float rays = calculateRay(angle * frequency, phase + time);
+    return intensity * sunGlow * (rays * 0.4 + 2 + 2 * length(uv));
+}
+
+vec3 addGodRays(
+    vec3 background,
+    vec2 fragCoord,
+    vec2 uv,
+    vec2 sunPos,
+    float phase,
+    float frequency,
+    float timeSpeed) {
+    float rays =
+        godRays(
+            uv,
+            sunPos,
+            phase,
+            frequency,
+            timeSpeed * time,
+            intensity);
+    // Dithering.
+    rays -= triangleNoise(fragCoord.xy) * 0.025;
+    rays = clamp(rays, 0., 1.);
+    vec3 raysColor = mix(godRaysColor, min(godRaysColor + 0.5, vec3(1)), smoothstep(0.15, 0.6, rays));
+    return normalBlendNotPremultiplied(background.rgb, raysColor, smoothstep(0.1, 1., rays));
+}
 
-    vec4 colorForeground = foreground.eval(fragCoord * uvScaleFgd + uvOffsetFgd);
-    vec4 color = background.eval(fragCoord * uvScaleBgd + uvOffsetBgd);
+float checkBrightnessGodRaysAtCenter(
+    vec2 center,
+    float phase,
+    float frequency,
+    float timeSpeed) {
+    // For each position, get the angle.
+    float angle = atan(-center.y, -center.x);
+    float rays = calculateRay(angle * frequency, phase + timeSpeed * time);
+    // Normalize [0, 1] the brightness.
+    return smoothstep(-0.75, 35.25, rays);
 
-    // TODO(b/347299395): to add flare and sun effect background
+}
+
+vec4 main(float2 fragCoord) {
+    // Apply transform matrix to fragCoord
+    float2 adjustedUv = transformPoint(transformMatrixBitmap, fragCoord);
+
+    float2 uv = transformPoint(transformMatrixWeather, fragCoord) / screenSize;
+    uv -= vec2(0.5, 0.5);
+    uv.y /= screenAspectRatio;
+    vec2 sunVariation = vec2(0.1 * sin(time * 0.3), 0.14 * cos(time * 0.5));
+    sunVariation += 0.1 * (0.5 * sin(time * 0.456) + 0.5) * sunCenter / vec2(1., screenAspectRatio);
+    vec2 sunPos = sunVariation + sunCenter / vec2(1., screenAspectRatio);
+    //TODO(b/375214506): fix the uv position of the sun
 
+    vec4 colorForeground = foreground.eval(adjustedUv);
+    vec4 color = background.eval(adjustedUv);
     // add foreground
     color.rgb = normalBlend(color.rgb, colorForeground.rgb, colorForeground.a);
 
-    // TODO(b/347299395): to add flare and sun effect foreground
+    // Calculate brightness from sunrays.
+    float brightnessSunray = checkBrightnessGodRaysAtCenter(sunPos, 10.0, 1.1, 0.9);
+    brightnessSunray *= brightnessSunray;
+
+    // Adjusts contrast and brightness.
+    float noise = 0.025 * triangleNoise(fragCoord.xy + vec2(12.31, 1024.1241));
+    color.rgb = imageRangeConversion(color.rgb, 0.88, 0.02, noise, intensity);
+
+    // Adjust color grading for shadows and highlights.
+    float lum = relativeLuminance(color.rgb);
+    vec3 highlightColor = vec3(0.41, 0.69, 0.856);
+    float highlightThres = 0.66;
+    float highlightBlend = 0.30 +  + brightnessSunray * 0.1;
+    vec3 shadowColor = vec3(0.756, 0.69, 0.31);
+    float shadowThres = 0.33;
+    float shadowBlend = 0.2 + brightnessSunray * 0.1;
+
+    float highlightsMask = smoothstep(highlightThres, 1., lum);
+    float shadowsMask = 1. - smoothstep(0., shadowThres, lum);
+
+    color.rgb = normalBlendNotPremultiplied(
+        color.rgb, shadowColor, intensity * shadowBlend * shadowsMask);
+    color.rgb = normalBlendNotPremultiplied(
+        color.rgb, highlightColor, intensity * highlightBlend * highlightsMask);
 
+    // Add god rays.
+    color.rgb = addGodRays(color.rgb, fragCoord.xy, uv, sunPos, 10.0, 1.1, 0.9);
+    // Add flare.
+    color.rgb = addFlare(color.rgb, uv, sunPos, (0.4 + 0.8 * brightnessSunray) * intensity, time);
     return color;
 }
diff --git a/weathereffects/graphics/assets/shaders/utils.agsl b/weathereffects/graphics/assets/shaders/utils.agsl
index 05f40bb..04e20e4 100644
--- a/weathereffects/graphics/assets/shaders/utils.agsl
+++ b/weathereffects/graphics/assets/shaders/utils.agsl
@@ -90,8 +90,16 @@ vec3 normalBlend(vec3 b, vec3 f, float o) {
     return b * (1. - o) + f;
 }
 
-vec3 screenBlend(vec3 b, float o) {
-    return b * (1. - o) + o;
+float screenBlend(float bgd, float fgd) {
+    return mix(bgd, 1., fgd);
+}
+
+vec3 screenBlend(vec3 bgd, float fgd) {
+    return mix(bgd, vec3(1.), fgd);
+}
+
+vec3 screenBlend(vec3 bgd, vec3 fgd) {
+    return mix(bgd, vec3(1.), fgd);
 }
 
 /*
@@ -108,6 +116,18 @@ vec3 normalBlendNotPremultiplied(vec3 b, vec3 f, float o) {
     return mix(b, f, o);
 }
 
+float relativeLuminance(vec3 color) {
+    return dot(vec3(0.2126, 0.7152, 0.0722), color);
+}
+
+/* Adjusts the image color range and black level. */
+vec3 imageRangeConversion(
+    vec3 color, float rangeCompression, float blackLevel, float noise, float intensity) {
+    color *= mix(1., rangeCompression + noise, intensity);
+    color += blackLevel * intensity;
+    return color;
+}
+
 /** Math Utils */
 // function created on Grapher (equation decided by testing in Grapher).
 float wiggle(float time, float wiggleSpeed) {
@@ -121,3 +141,12 @@ float map(float value, float inMin, float inMax, float outMin, float outMax) {
     return p * (outMax - outMin) + outMin;
 }
 
+// Adjusts the UVs to have the expected rect of the image.
+float2 transformPoint(mat3 transformMatrix, float2 point) {
+    // Convert the point to homogeneous coordinates (x, y, 1)
+    vec3 homogeneousPoint = vec3(point, 1.0);
+    // Multiply the matrix by the point
+    vec3 transformedPoint = transformMatrix * homogeneousPoint;
+    // Convert back to Cartesian coordinates (x, y)
+    return transformedPoint.xy / transformedPoint.z;
+}
diff --git a/weathereffects/graphics/assets/textures/cloud_lut.png b/weathereffects/graphics/assets/textures/cloud_lut.png
new file mode 100644
index 0000000..65b3f09
Binary files /dev/null and b/weathereffects/graphics/assets/textures/cloud_lut.png differ
diff --git a/weathereffects/graphics/assets/textures/fog_lut.png b/weathereffects/graphics/assets/textures/fog_lut.png
new file mode 100644
index 0000000..54aab35
Binary files /dev/null and b/weathereffects/graphics/assets/textures/fog_lut.png differ
diff --git a/weathereffects/graphics/assets/textures/lut_rain_and_fog.png b/weathereffects/graphics/assets/textures/lut_rain_and_fog.png
deleted file mode 100644
index 7e8af9c..0000000
Binary files a/weathereffects/graphics/assets/textures/lut_rain_and_fog.png and /dev/null differ
diff --git a/weathereffects/graphics/assets/textures/rain_lut.png b/weathereffects/graphics/assets/textures/rain_lut.png
new file mode 100644
index 0000000..c0b1508
Binary files /dev/null and b/weathereffects/graphics/assets/textures/rain_lut.png differ
diff --git a/weathereffects/graphics/assets/textures/snow_lut.png b/weathereffects/graphics/assets/textures/snow_lut.png
new file mode 100644
index 0000000..d96de45
Binary files /dev/null and b/weathereffects/graphics/assets/textures/snow_lut.png differ
diff --git a/weathereffects/graphics/assets/textures/sun_lut.png b/weathereffects/graphics/assets/textures/sun_lut.png
new file mode 100644
index 0000000..81e635c
Binary files /dev/null and b/weathereffects/graphics/assets/textures/sun_lut.png differ
diff --git a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/WeatherEffect.kt b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/WeatherEffect.kt
index 0761d3c..6140c60 100644
--- a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/WeatherEffect.kt
+++ b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/WeatherEffect.kt
@@ -18,6 +18,7 @@ package com.google.android.wallpaper.weathereffects.graphics
 
 import android.graphics.Bitmap
 import android.graphics.Canvas
+import android.graphics.Matrix
 import android.util.SizeF
 import androidx.annotation.FloatRange
 
@@ -64,10 +65,18 @@ interface WeatherEffect {
     /**
      * Reuse current shader but change background, foreground
      *
-     * @param foreground A bitmap containing the foreground of the image
+     * @param foreground A bitmap containing the foreground of the image, will be null when
+     *   segmentation hasn't finished.
      * @param background A bitmap containing the background of the image
      */
-    fun setBitmaps(foreground: Bitmap, background: Bitmap)
+    fun setBitmaps(foreground: Bitmap?, background: Bitmap)
+
+    /**
+     * Apply matrix to transform coordinates in shaders. In Editor and preview, it's a center crop
+     * matrix to center the bitmap in surface size; in applied wallpaper, the matrix is the parallax
+     * matrix due to the pagination in homescreen
+     */
+    fun setMatrix(matrix: Matrix) {}
 
     companion object {
         val DEFAULT_INTENSITY = 1f
diff --git a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/WeatherEffectBase.kt b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/WeatherEffectBase.kt
new file mode 100644
index 0000000..ee815a1
--- /dev/null
+++ b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/WeatherEffectBase.kt
@@ -0,0 +1,136 @@
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
+package com.google.android.wallpaper.weathereffects.graphics
+
+import android.graphics.Bitmap
+import android.graphics.BitmapShader
+import android.graphics.Canvas
+import android.graphics.Matrix
+import android.graphics.RuntimeShader
+import android.graphics.Shader
+import android.util.SizeF
+import com.google.android.wallpaper.weathereffects.graphics.utils.GraphicsUtils
+import com.google.android.wallpaper.weathereffects.graphics.utils.MatrixUtils.calculateTransformDifference
+import com.google.android.wallpaper.weathereffects.graphics.utils.MatrixUtils.centerCropMatrix
+import com.google.android.wallpaper.weathereffects.graphics.utils.MatrixUtils.invertAndTransposeMatrix
+import kotlin.random.Random
+
+/** Give default implementation of some functions in WeatherEffect */
+abstract class WeatherEffectBase(
+    protected var foreground: Bitmap,
+    protected var background: Bitmap,
+    /** The initial size of the surface where the effect will be shown. */
+    private var surfaceSize: SizeF,
+) : WeatherEffect {
+    private var centerCropMatrix: Matrix =
+        centerCropMatrix(
+            surfaceSize,
+            SizeF(background.width.toFloat(), background.height.toFloat()),
+        )
+    protected var parallaxMatrix = Matrix(centerCropMatrix)
+    // Currently, we use same transform for both foreground and background
+    protected open val transformMatrixBitmap: FloatArray = FloatArray(9)
+    // Apply to weather components not rely on image textures
+    // Should be identity matrix in editor, and only change when parallax applied in homescreen
+    private val transformMatrixWeather: FloatArray = FloatArray(9)
+    protected var elapsedTime: Float = 0f
+
+    abstract val shader: RuntimeShader
+    abstract val colorGradingShader: RuntimeShader
+    abstract val lut: Bitmap?
+    abstract val colorGradingIntensity: Float
+
+    override fun setMatrix(matrix: Matrix) {
+        this.parallaxMatrix.set(matrix)
+        adjustCropping(surfaceSize)
+    }
+
+    open fun adjustCropping(newSurfaceSize: SizeF) {
+        invertAndTransposeMatrix(parallaxMatrix, transformMatrixBitmap)
+        calculateTransformDifference(centerCropMatrix, parallaxMatrix, transformMatrixWeather)
+        shader.setFloatUniform("transformMatrixBitmap", transformMatrixBitmap)
+        shader.setFloatUniform("transformMatrixWeather", transformMatrixWeather)
+        shader.setFloatUniform("screenSize", newSurfaceSize.width, newSurfaceSize.height)
+        shader.setFloatUniform("screenAspectRatio", GraphicsUtils.getAspectRatio(newSurfaceSize))
+    }
+
+    open fun updateGridSize(newSurfaceSize: SizeF) {}
+
+    override fun resize(newSurfaceSize: SizeF) {
+        surfaceSize = newSurfaceSize
+        adjustCropping(newSurfaceSize)
+        updateGridSize(newSurfaceSize)
+    }
+
+    abstract override fun update(deltaMillis: Long, frameTimeNanos: Long)
+
+    abstract override fun draw(canvas: Canvas)
+
+    override fun reset() {
+        elapsedTime = Random.nextFloat() * 90f
+    }
+
+    override fun release() {
+        lut?.recycle()
+    }
+
+    override fun setIntensity(intensity: Float) {
+        shader.setFloatUniform("intensity", intensity)
+        colorGradingShader.setFloatUniform("intensity", colorGradingIntensity * intensity)
+    }
+
+    override fun setBitmaps(foreground: Bitmap?, background: Bitmap) {
+        if (this.foreground == foreground && this.background == background) {
+            return
+        }
+        // Only when background changes, we can infer the bitmap set changes
+        if (this.background != background) {
+            this.background.recycle()
+            this.foreground.recycle()
+        }
+        this.foreground = foreground ?: background
+        this.background = background
+
+        centerCropMatrix =
+            centerCropMatrix(
+                surfaceSize,
+                SizeF(background.width.toFloat(), background.height.toFloat()),
+            )
+        parallaxMatrix.set(centerCropMatrix)
+        shader.setInputBuffer(
+            "background",
+            BitmapShader(this.background, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR),
+        )
+        shader.setInputBuffer(
+            "foreground",
+            BitmapShader(this.foreground, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR),
+        )
+        adjustCropping(surfaceSize)
+    }
+
+    open fun updateTextureUniforms() {
+        shader.setInputBuffer(
+            "foreground",
+            BitmapShader(foreground, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR),
+        )
+
+        shader.setInputBuffer(
+            "background",
+            BitmapShader(background, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR),
+        )
+    }
+}
diff --git a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/fog/FogEffect.kt b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/fog/FogEffect.kt
index 73d870c..47f2a24 100644
--- a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/fog/FogEffect.kt
+++ b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/fog/FogEffect.kt
@@ -20,43 +20,35 @@ import android.graphics.Bitmap
 import android.graphics.BitmapShader
 import android.graphics.Canvas
 import android.graphics.Paint
+import android.graphics.RuntimeShader
 import android.graphics.Shader
 import android.util.SizeF
-import com.google.android.wallpaper.weathereffects.graphics.WeatherEffect
 import com.google.android.wallpaper.weathereffects.graphics.WeatherEffect.Companion.DEFAULT_INTENSITY
+import com.google.android.wallpaper.weathereffects.graphics.WeatherEffectBase
 import com.google.android.wallpaper.weathereffects.graphics.utils.GraphicsUtils
-import com.google.android.wallpaper.weathereffects.graphics.utils.ImageCrop
 import com.google.android.wallpaper.weathereffects.graphics.utils.TimeUtils
 import kotlin.math.sin
-import kotlin.random.Random
 
 /** Defines and generates the fog weather effect animation. */
 class FogEffect(
     private val fogConfig: FogEffectConfig,
-    private var foreground: Bitmap,
-    private var background: Bitmap,
-    private var intensity: Float = DEFAULT_INTENSITY,
+    foreground: Bitmap,
+    background: Bitmap,
+    intensity: Float = DEFAULT_INTENSITY,
     /** The initial size of the surface where the effect will be shown. */
-    private var surfaceSize: SizeF
-) : WeatherEffect {
+    surfaceSize: SizeF,
+) : WeatherEffectBase(foreground, background, surfaceSize) {
 
     private val fogPaint = Paint().also { it.shader = fogConfig.colorGradingShader }
-    private var elapsedTime: Float = 0f
 
     init {
         updateTextureUniforms()
         adjustCropping(surfaceSize)
         prepareColorGrading()
-        updateFogGridSize(surfaceSize)
+        updateGridSize(surfaceSize)
         setIntensity(intensity)
     }
 
-    override fun resize(newSurfaceSize: SizeF) {
-        adjustCropping(newSurfaceSize)
-        updateFogGridSize(newSurfaceSize)
-        surfaceSize = newSurfaceSize
-    }
-
     override fun update(deltaMillis: Long, frameTimeNanos: Long) {
         val deltaTime = TimeUtils.millisToSeconds(deltaMillis)
 
@@ -87,97 +79,16 @@ class FogEffect(
         canvas.drawPaint(fogPaint)
     }
 
-    override fun reset() {
-        elapsedTime = Random.nextFloat() * 90f
-    }
-
-    override fun release() {
-        fogConfig.lut?.recycle()
-    }
-
-    override fun setIntensity(intensity: Float) {
-        fogConfig.shader.setFloatUniform("intensity", intensity)
-        fogConfig.colorGradingShader.setFloatUniform(
-            "intensity",
-            fogConfig.colorGradingIntensity * intensity
-        )
-    }
-
-    override fun setBitmaps(foreground: Bitmap, background: Bitmap) {
-        this.foreground = foreground
-        this.background = background
-        fogConfig.shader.setInputBuffer(
-            "background",
-            BitmapShader(background, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR)
-        )
-        fogConfig.shader.setInputBuffer(
-            "foreground",
-            BitmapShader(foreground, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR)
-        )
-        adjustCropping(surfaceSize)
-    }
-
-    private fun adjustCropping(surfaceSize: SizeF) {
-        val imageCropFgd =
-            ImageCrop.centerCoverCrop(
-                surfaceSize.width,
-                surfaceSize.height,
-                foreground.width.toFloat(),
-                foreground.height.toFloat()
-            )
-        fogConfig.shader.setFloatUniform(
-            "uvOffsetFgd",
-            imageCropFgd.leftOffset,
-            imageCropFgd.topOffset
-        )
-        fogConfig.shader.setFloatUniform(
-            "uvScaleFgd",
-            imageCropFgd.horizontalScale,
-            imageCropFgd.verticalScale
-        )
-        val imageCropBgd =
-            ImageCrop.centerCoverCrop(
-                surfaceSize.width,
-                surfaceSize.height,
-                background.width.toFloat(),
-                background.height.toFloat()
-            )
-        fogConfig.shader.setFloatUniform(
-            "uvOffsetBgd",
-            imageCropBgd.leftOffset,
-            imageCropBgd.topOffset
-        )
-        fogConfig.shader.setFloatUniform(
-            "uvScaleBgd",
-            imageCropBgd.horizontalScale,
-            imageCropBgd.verticalScale
-        )
-        fogConfig.shader.setFloatUniform("screenSize", surfaceSize.width, surfaceSize.height)
-        fogConfig.shader.setFloatUniform(
-            "screenAspectRatio",
-            GraphicsUtils.getAspectRatio(surfaceSize)
-        )
-    }
-
-    private fun updateTextureUniforms() {
-        fogConfig.shader.setInputBuffer(
-            "foreground",
-            BitmapShader(foreground, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR)
-        )
-
-        fogConfig.shader.setInputBuffer(
-            "background",
-            BitmapShader(background, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR)
-        )
-
+    override fun updateTextureUniforms() {
+        super.updateTextureUniforms()
         fogConfig.shader.setInputBuffer(
             "clouds",
-            BitmapShader(fogConfig.cloudsTexture, Shader.TileMode.REPEAT, Shader.TileMode.REPEAT)
+            BitmapShader(fogConfig.cloudsTexture, Shader.TileMode.REPEAT, Shader.TileMode.REPEAT),
         )
 
         fogConfig.shader.setInputBuffer(
             "fog",
-            BitmapShader(fogConfig.fogTexture, Shader.TileMode.REPEAT, Shader.TileMode.REPEAT)
+            BitmapShader(fogConfig.fogTexture, Shader.TileMode.REPEAT, Shader.TileMode.REPEAT),
         )
 
         fogConfig.shader.setFloatUniform("pixelDensity", fogConfig.pixelDensity)
@@ -188,25 +99,37 @@ class FogEffect(
         fogConfig.lut?.let {
             fogConfig.colorGradingShader.setInputShader(
                 "lut",
-                BitmapShader(it, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR)
+                BitmapShader(it, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR),
             )
         }
         fogConfig.colorGradingShader.setFloatUniform("intensity", fogConfig.colorGradingIntensity)
     }
 
-    private fun updateFogGridSize(surfaceSize: SizeF) {
+    override val shader: RuntimeShader
+        get() = fogConfig.shader
+
+    override val colorGradingShader: RuntimeShader
+        get() = fogConfig.colorGradingShader
+
+    override val lut: Bitmap?
+        get() = fogConfig.lut
+
+    override val colorGradingIntensity: Float
+        get() = fogConfig.colorGradingIntensity
+
+    override fun updateGridSize(newSurfaceSize: SizeF) {
         val widthScreenScale =
-            GraphicsUtils.computeDefaultGridSize(surfaceSize, fogConfig.pixelDensity)
+            GraphicsUtils.computeDefaultGridSize(newSurfaceSize, fogConfig.pixelDensity)
         fogConfig.shader.setFloatUniform(
             "cloudsSize",
             widthScreenScale * fogConfig.cloudsTexture.width.toFloat(),
-            widthScreenScale * fogConfig.cloudsTexture.height.toFloat()
+            widthScreenScale * fogConfig.cloudsTexture.height.toFloat(),
         )
 
         fogConfig.shader.setFloatUniform(
             "fogSize",
             widthScreenScale * fogConfig.fogTexture.width.toFloat(),
-            widthScreenScale * fogConfig.fogTexture.height.toFloat()
+            widthScreenScale * fogConfig.fogTexture.height.toFloat(),
         )
     }
 }
diff --git a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/fog/FogEffectConfig.kt b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/fog/FogEffectConfig.kt
index 4ac9b06..51e0cfd 100644
--- a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/fog/FogEffectConfig.kt
+++ b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/fog/FogEffectConfig.kt
@@ -71,9 +71,9 @@ data class FogEffectConfig(
     private companion object {
         private const val SHADER_PATH = "shaders/fog_effect.agsl"
         private const val COLOR_GRADING_SHADER_PATH = "shaders/color_grading_lut.agsl"
-        private const val LOOKUP_TABLE_TEXTURE_PATH = "textures/lut_rain_and_fog.png"
+        private const val LOOKUP_TABLE_TEXTURE_PATH = "textures/fog_lut.png"
         private const val CLOUDS_TEXTURE_PATH = "textures/clouds.png"
         private const val FOG_TEXTURE_PATH = "textures/fog.png"
-        private const val COLOR_GRADING_INTENSITY = 0.7f
+        private const val COLOR_GRADING_INTENSITY = 0.3f
     }
 }
diff --git a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/none/NoEffect.kt b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/none/NoEffect.kt
index d1aedcd..d4ac8f5 100644
--- a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/none/NoEffect.kt
+++ b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/none/NoEffect.kt
@@ -23,8 +23,11 @@ import com.google.android.wallpaper.weathereffects.graphics.WeatherEffect
 import com.google.android.wallpaper.weathereffects.graphics.utils.MatrixUtils
 
 /** Simply draws foreground and background images with no weather effect. */
-class NoEffect(var foreground: Bitmap, var background: Bitmap, private var surfaceSize: SizeF) :
-    WeatherEffect {
+class NoEffect(
+    private var foreground: Bitmap,
+    private var background: Bitmap,
+    private var surfaceSize: SizeF,
+) : WeatherEffect {
     override fun resize(newSurfaceSize: SizeF) {
         surfaceSize = newSurfaceSize
     }
@@ -36,17 +39,17 @@ class NoEffect(var foreground: Bitmap, var background: Bitmap, private var surfa
             background,
             MatrixUtils.centerCropMatrix(
                 surfaceSize,
-                SizeF(background.width.toFloat(), background.height.toFloat())
+                SizeF(background.width.toFloat(), background.height.toFloat()),
             ),
-            null
+            null,
         )
         canvas.drawBitmap(
             foreground,
             MatrixUtils.centerCropMatrix(
                 surfaceSize,
-                SizeF(foreground.width.toFloat(), foreground.height.toFloat())
+                SizeF(foreground.width.toFloat(), foreground.height.toFloat()),
             ),
-            null
+            null,
         )
     }
 
@@ -56,8 +59,13 @@ class NoEffect(var foreground: Bitmap, var background: Bitmap, private var surfa
 
     override fun setIntensity(intensity: Float) {}
 
-    override fun setBitmaps(foreground: Bitmap, background: Bitmap) {
-        this.foreground = foreground
+    override fun setBitmaps(foreground: Bitmap?, background: Bitmap) {
+        // Only when background changes, we can infer the bitmap set changes
+        if (this.background != background) {
+            this.background.recycle()
+            this.foreground.recycle()
+        }
         this.background = background
+        this.foreground = foreground ?: background
     }
 }
diff --git a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/rain/RainEffect.kt b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/rain/RainEffect.kt
index c554b5e..1805731 100644
--- a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/rain/RainEffect.kt
+++ b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/rain/RainEffect.kt
@@ -22,29 +22,28 @@ import android.graphics.Canvas
 import android.graphics.Color
 import android.graphics.Paint
 import android.graphics.RenderEffect
+import android.graphics.RuntimeShader
 import android.graphics.Shader
 import android.util.SizeF
 import com.google.android.wallpaper.weathereffects.graphics.FrameBuffer
-import com.google.android.wallpaper.weathereffects.graphics.WeatherEffect
 import com.google.android.wallpaper.weathereffects.graphics.WeatherEffect.Companion.DEFAULT_INTENSITY
+import com.google.android.wallpaper.weathereffects.graphics.WeatherEffectBase
 import com.google.android.wallpaper.weathereffects.graphics.utils.GraphicsUtils
-import com.google.android.wallpaper.weathereffects.graphics.utils.ImageCrop
 import com.google.android.wallpaper.weathereffects.graphics.utils.SolidColorShader
 import com.google.android.wallpaper.weathereffects.graphics.utils.TimeUtils
 import java.util.concurrent.Executor
-import kotlin.random.Random
 
 /** Defines and generates the rain weather effect animation. */
 class RainEffect(
     /** The config of the rain effect. */
     private val rainConfig: RainEffectConfig,
-    private var foreground: Bitmap,
-    private var background: Bitmap,
-    private var intensity: Float = DEFAULT_INTENSITY,
+    foreground: Bitmap,
+    background: Bitmap,
+    intensity: Float = DEFAULT_INTENSITY,
     /** The initial size of the surface where the effect will be shown. */
-    private var surfaceSize: SizeF,
-    private val mainExecutor: Executor
-) : WeatherEffect {
+    surfaceSize: SizeF,
+    private val mainExecutor: Executor,
+) : WeatherEffectBase(foreground, background, surfaceSize) {
 
     private val rainPaint = Paint().also { it.shader = rainConfig.colorGradingShader }
 
@@ -56,22 +55,14 @@ class RainEffect(
         }
     private val outlineBufferPaint = Paint().also { it.shader = rainConfig.outlineShader }
 
-    private var elapsedTime: Float = 0f
-
     init {
         updateTextureUniforms()
         adjustCropping(surfaceSize)
         prepareColorGrading()
-        updateRainGridSize(surfaceSize)
+        updateGridSize(surfaceSize)
         setIntensity(intensity)
     }
 
-    override fun resize(newSurfaceSize: SizeF) {
-        adjustCropping(newSurfaceSize)
-        updateRainGridSize(newSurfaceSize)
-        surfaceSize = newSurfaceSize
-    }
-
     override fun update(deltaMillis: Long, frameTimeNanos: Long) {
         elapsedTime += TimeUtils.millisToSeconds(deltaMillis)
 
@@ -86,22 +77,14 @@ class RainEffect(
         canvas.drawPaint(rainPaint)
     }
 
-    override fun reset() {
-        elapsedTime = Random.nextFloat() * 90f
-    }
-
     override fun release() {
-        rainConfig.lut?.recycle()
+        super.release()
         outlineBuffer.close()
     }
 
     override fun setIntensity(intensity: Float) {
-        rainConfig.rainShowerShader.setFloatUniform("intensity", intensity)
+        super.setIntensity(intensity)
         rainConfig.glassRainShader.setFloatUniform("intensity", intensity)
-        rainConfig.colorGradingShader.setFloatUniform(
-            "intensity",
-            rainConfig.colorGradingIntensity * intensity
-        )
         val thickness = 1f + intensity * 10f
         rainConfig.outlineShader.setFloatUniform("thickness", thickness)
 
@@ -109,82 +92,51 @@ class RainEffect(
         createOutlineBuffer()
     }
 
-    override fun setBitmaps(foreground: Bitmap, background: Bitmap) {
-        this.foreground = foreground
-        this.background = background
+    override fun setBitmaps(foreground: Bitmap?, background: Bitmap) {
+        super.setBitmaps(foreground, background)
         outlineBuffer =
             FrameBuffer(background.width, background.height).apply {
                 setRenderEffect(RenderEffect.createBlurEffect(2f, 2f, Shader.TileMode.CLAMP))
             }
-        adjustCropping(surfaceSize)
         updateTextureUniforms()
 
         // Need to recreate the outline buffer as the outlineBuffer has changed due to background
         createOutlineBuffer()
     }
 
-    private fun adjustCropping(surfaceSize: SizeF) {
-        val imageCropFgd =
-            ImageCrop.centerCoverCrop(
-                surfaceSize.width,
-                surfaceSize.height,
-                foreground.width.toFloat(),
-                foreground.height.toFloat()
-            )
-        rainConfig.rainShowerShader.setFloatUniform(
-            "uvOffsetFgd",
-            imageCropFgd.leftOffset,
-            imageCropFgd.topOffset
-        )
-        rainConfig.rainShowerShader.setFloatUniform(
-            "uvScaleFgd",
-            imageCropFgd.horizontalScale,
-            imageCropFgd.verticalScale
-        )
+    override val shader: RuntimeShader
+        get() = rainConfig.rainShowerShader
 
-        val imageCropBgd =
-            ImageCrop.centerCoverCrop(
-                surfaceSize.width,
-                surfaceSize.height,
-                background.width.toFloat(),
-                background.height.toFloat()
-            )
-        rainConfig.rainShowerShader.setFloatUniform(
-            "uvOffsetBgd",
-            imageCropBgd.leftOffset,
-            imageCropBgd.topOffset
-        )
-        rainConfig.rainShowerShader.setFloatUniform(
-            "uvScaleBgd",
-            imageCropBgd.horizontalScale,
-            imageCropBgd.verticalScale
-        )
+    override val colorGradingShader: RuntimeShader
+        get() = rainConfig.colorGradingShader
 
-        rainConfig.rainShowerShader.setFloatUniform(
-            "screenSize",
-            surfaceSize.width,
-            surfaceSize.height
-        )
+    override val lut: Bitmap?
+        get() = rainConfig.lut
+
+    override val colorGradingIntensity: Float
+        get() = rainConfig.colorGradingIntensity
+
+    override fun adjustCropping(newSurfaceSize: SizeF) {
+        super.adjustCropping(newSurfaceSize)
         rainConfig.glassRainShader.setFloatUniform(
             "screenSize",
-            surfaceSize.width,
-            surfaceSize.height
+            newSurfaceSize.width,
+            newSurfaceSize.height,
         )
 
-        val screenAspectRatio = GraphicsUtils.getAspectRatio(surfaceSize)
-        rainConfig.rainShowerShader.setFloatUniform("screenAspectRatio", screenAspectRatio)
+        val screenAspectRatio = GraphicsUtils.getAspectRatio(newSurfaceSize)
         rainConfig.glassRainShader.setFloatUniform("screenAspectRatio", screenAspectRatio)
     }
 
-    private fun updateTextureUniforms() {
+    override fun updateTextureUniforms() {
         val foregroundBuffer =
-            BitmapShader(foreground, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR)
+            BitmapShader(super.foreground, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR)
         rainConfig.rainShowerShader.setInputBuffer("foreground", foregroundBuffer)
         rainConfig.outlineShader.setInputBuffer("texture", foregroundBuffer)
 
         rainConfig.rainShowerShader.setInputBuffer(
             "background",
-            BitmapShader(background, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR)
+            BitmapShader(super.background, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR),
         )
     }
 
@@ -197,10 +149,10 @@ class RainEffect(
             { buffer ->
                 rainConfig.rainShowerShader.setInputBuffer(
                     "outlineBuffer",
-                    BitmapShader(buffer, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR)
+                    BitmapShader(buffer, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR),
                 )
             },
-            mainExecutor
+            mainExecutor,
         )
     }
 
@@ -211,14 +163,14 @@ class RainEffect(
         rainConfig.lut?.let {
             rainConfig.colorGradingShader.setInputShader(
                 "lut",
-                BitmapShader(it, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR)
+                BitmapShader(it, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR),
             )
         }
     }
 
-    private fun updateRainGridSize(surfaceSize: SizeF) {
+    override fun updateGridSize(newSurfaceSize: SizeF) {
         val widthScreenScale =
-            GraphicsUtils.computeDefaultGridSize(surfaceSize, rainConfig.pixelDensity)
+            GraphicsUtils.computeDefaultGridSize(newSurfaceSize, rainConfig.pixelDensity)
         rainConfig.rainShowerShader.setFloatUniform("gridScale", widthScreenScale)
         rainConfig.glassRainShader.setFloatUniform("gridScale", widthScreenScale)
     }
diff --git a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/rain/RainEffectConfig.kt b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/rain/RainEffectConfig.kt
index 1567db3..7fefd72 100644
--- a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/rain/RainEffectConfig.kt
+++ b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/rain/RainEffectConfig.kt
@@ -63,7 +63,7 @@ data class RainEffectConfig(
         private const val GLASS_RAIN_LAYER_SHADER_PATH = "shaders/rain_glass_layer.agsl"
         private const val COLOR_GRADING_SHADER_PATH = "shaders/color_grading_lut.agsl"
         private const val OUTLINE_SHADER_PATH = "shaders/outline.agsl"
-        private const val LOOKUP_TABLE_TEXTURE_PATH = "textures/lut_rain_and_fog.png"
-        private const val COLOR_GRADING_INTENSITY = 0.7f
+        private const val LOOKUP_TABLE_TEXTURE_PATH = "textures/rain_lut.png"
+        private const val COLOR_GRADING_INTENSITY = 0.3f
     }
 }
diff --git a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/snow/SnowEffect.kt b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/snow/SnowEffect.kt
index cec6cc2..33a0732 100644
--- a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/snow/SnowEffect.kt
+++ b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/snow/SnowEffect.kt
@@ -19,58 +19,56 @@ package com.google.android.wallpaper.weathereffects.graphics.snow
 import android.graphics.Bitmap
 import android.graphics.BitmapShader
 import android.graphics.Canvas
+import android.graphics.Matrix
 import android.graphics.Paint
 import android.graphics.RenderEffect
+import android.graphics.RuntimeShader
 import android.graphics.Shader
 import android.util.SizeF
 import com.google.android.wallpaper.weathereffects.graphics.FrameBuffer
-import com.google.android.wallpaper.weathereffects.graphics.WeatherEffect
 import com.google.android.wallpaper.weathereffects.graphics.WeatherEffect.Companion.DEFAULT_INTENSITY
+import com.google.android.wallpaper.weathereffects.graphics.WeatherEffectBase
 import com.google.android.wallpaper.weathereffects.graphics.utils.GraphicsUtils
-import com.google.android.wallpaper.weathereffects.graphics.utils.ImageCrop
 import com.google.android.wallpaper.weathereffects.graphics.utils.MathUtils
+import com.google.android.wallpaper.weathereffects.graphics.utils.MatrixUtils.getScale
 import com.google.android.wallpaper.weathereffects.graphics.utils.TimeUtils
 import java.util.concurrent.Executor
-import kotlin.random.Random
 
 /** Defines and generates the rain weather effect animation. */
 class SnowEffect(
     /** The config of the snow effect. */
     private val snowConfig: SnowEffectConfig,
-    private var foreground: Bitmap,
-    private var background: Bitmap,
+    foreground: Bitmap,
+    background: Bitmap,
     private var intensity: Float = DEFAULT_INTENSITY,
     /** The initial size of the surface where the effect will be shown. */
     private var surfaceSize: SizeF,
     /** App main executor. */
-    private val mainExecutor: Executor
-) : WeatherEffect {
+    private val mainExecutor: Executor,
+) : WeatherEffectBase(foreground, background, surfaceSize) {
 
     private var snowSpeed: Float = 0.8f
     private val snowPaint = Paint().also { it.shader = snowConfig.colorGradingShader }
-    private var elapsedTime: Float = 0f
 
     private var frameBuffer = FrameBuffer(background.width, background.height)
     private val frameBufferPaint = Paint().also { it.shader = snowConfig.accumulatedSnowShader }
 
+    private var scale = getScale(parallaxMatrix)
+
     init {
-        frameBuffer.setRenderEffect(RenderEffect.createBlurEffect(4f, 4f, Shader.TileMode.CLAMP))
+        frameBuffer.setRenderEffect(
+            RenderEffect.createBlurEffect(4f / scale, 4f / scale, Shader.TileMode.CLAMP)
+        )
         updateTextureUniforms()
         adjustCropping(surfaceSize)
         prepareColorGrading()
-        updateSnowGridSize(surfaceSize)
+        updateGridSize(surfaceSize)
         setIntensity(intensity)
 
         // Generate accumulated snow at the end after we updated all the uniforms.
         generateAccumulatedSnow()
     }
 
-    override fun resize(newSurfaceSize: SizeF) {
-        adjustCropping(newSurfaceSize)
-        updateSnowGridSize(newSurfaceSize)
-        surfaceSize = newSurfaceSize
-    }
-
     override fun update(deltaMillis: Long, frameTimeNanos: Long) {
         elapsedTime += snowSpeed * TimeUtils.millisToSeconds(deltaMillis)
 
@@ -82,109 +80,59 @@ class SnowEffect(
         canvas.drawPaint(snowPaint)
     }
 
-    override fun reset() {
-        elapsedTime = Random.nextFloat() * 90f
-    }
-
     override fun release() {
-        snowConfig.lut?.recycle()
+        super.release()
         frameBuffer.close()
     }
 
     override fun setIntensity(intensity: Float) {
+        super.setIntensity(intensity)
         /**
          * Increase effect speed as weather intensity decreases. This compensates for the floaty
          * appearance when there are fewer particles at the original speed.
          */
         snowSpeed = MathUtils.map(intensity, 0f, 1f, 2.5f, 1.7f)
-
-        snowConfig.shader.setFloatUniform("intensity", intensity)
-        snowConfig.colorGradingShader.setFloatUniform(
-            "intensity",
-            snowConfig.colorGradingIntensity * intensity
-        )
-        snowConfig.accumulatedSnowShader.setFloatUniform(
-            "snowThickness",
-            snowConfig.maxAccumulatedSnowThickness * intensity
-        )
+        this.intensity = intensity
         // Regenerate accumulated snow since the uniform changed.
         generateAccumulatedSnow()
     }
 
-    override fun setBitmaps(foreground: Bitmap, background: Bitmap) {
-        this.foreground = foreground
-        this.background = background
-        frameBuffer = FrameBuffer(background.width, background.height)
-        snowConfig.shader.setInputBuffer(
-            "background",
-            BitmapShader(background, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR)
-        )
-        snowConfig.shader.setInputBuffer(
-            "foreground",
-            BitmapShader(foreground, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR)
-        )
-        adjustCropping(surfaceSize)
-        // generateAccumulatedSnow needs foreground for accumulatedSnowShader, and needs frameBuffer
+    override fun setBitmaps(foreground: Bitmap?, background: Bitmap) {
+        super.setBitmaps(foreground, background)
+        scale = getScale(parallaxMatrix)
+        frameBuffer =
+            FrameBuffer(background.width, background.height).apply {
+                setRenderEffect(
+                    RenderEffect.createBlurEffect(4f / scale, 4f / scale, Shader.TileMode.CLAMP)
+                )
+            }
+        // GenerateAccumulatedSnow needs foreground for accumulatedSnowShader, and needs frameBuffer
         // which is also changed with background
         generateAccumulatedSnow()
     }
 
-    private fun adjustCropping(surfaceSize: SizeF) {
-        val imageCropFgd =
-            ImageCrop.centerCoverCrop(
-                surfaceSize.width,
-                surfaceSize.height,
-                foreground.width.toFloat(),
-                foreground.height.toFloat()
-            )
-        snowConfig.shader.setFloatUniform(
-            "uvOffsetFgd",
-            imageCropFgd.leftOffset,
-            imageCropFgd.topOffset
-        )
-        snowConfig.shader.setFloatUniform(
-            "uvScaleFgd",
-            imageCropFgd.horizontalScale,
-            imageCropFgd.verticalScale
-        )
-        val imageCropBgd =
-            ImageCrop.centerCoverCrop(
-                surfaceSize.width,
-                surfaceSize.height,
-                background.width.toFloat(),
-                background.height.toFloat()
-            )
-        snowConfig.shader.setFloatUniform(
-            "uvOffsetBgd",
-            imageCropBgd.leftOffset,
-            imageCropBgd.topOffset
-        )
-        snowConfig.shader.setFloatUniform(
-            "uvScaleBgd",
-            imageCropBgd.horizontalScale,
-            imageCropBgd.verticalScale
-        )
-        snowConfig.shader.setFloatUniform("screenSize", surfaceSize.width, surfaceSize.height)
-        snowConfig.shader.setFloatUniform(
-            "screenAspectRatio",
-            GraphicsUtils.getAspectRatio(surfaceSize)
-        )
-    }
+    override val shader: RuntimeShader
+        get() = snowConfig.shader
 
-    private fun updateTextureUniforms() {
-        snowConfig.shader.setInputBuffer(
-            "foreground",
-            BitmapShader(foreground, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR)
-        )
+    override val colorGradingShader: RuntimeShader
+        get() = snowConfig.colorGradingShader
 
-        snowConfig.shader.setInputBuffer(
-            "background",
-            BitmapShader(background, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR)
-        )
+    override val lut: Bitmap?
+        get() = snowConfig.lut
+
+    override val colorGradingIntensity: Float
+        get() = snowConfig.colorGradingIntensity
 
+    override fun setMatrix(matrix: Matrix) {
+        super.setMatrix(matrix)
+        generateAccumulatedSnow()
+    }
+
+    override fun updateTextureUniforms() {
+        super.updateTextureUniforms()
         snowConfig.shader.setInputBuffer(
             "noise",
-            BitmapShader(snowConfig.noiseTexture, Shader.TileMode.REPEAT, Shader.TileMode.REPEAT)
+            BitmapShader(snowConfig.noiseTexture, Shader.TileMode.REPEAT, Shader.TileMode.REPEAT),
         )
     }
 
@@ -193,20 +141,22 @@ class SnowEffect(
         snowConfig.lut?.let {
             snowConfig.colorGradingShader.setInputShader(
                 "lut",
-                BitmapShader(it, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR)
+                BitmapShader(it, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR),
             )
         }
     }
 
     private fun generateAccumulatedSnow() {
         val renderingCanvas = frameBuffer.beginDrawing()
+        snowConfig.accumulatedSnowShader.setFloatUniform("scale", scale)
         snowConfig.accumulatedSnowShader.setFloatUniform(
-            "imageWidth",
-            renderingCanvas.width.toFloat()
+            "snowThickness",
+            snowConfig.maxAccumulatedSnowThickness * intensity / scale,
         )
+        snowConfig.accumulatedSnowShader.setFloatUniform("screenWidth", surfaceSize.width)
         snowConfig.accumulatedSnowShader.setInputBuffer(
             "foreground",
-            BitmapShader(foreground, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR)
+            BitmapShader(foreground, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR),
         )
         renderingCanvas.drawPaint(frameBufferPaint)
         frameBuffer.endDrawing()
@@ -215,15 +165,15 @@ class SnowEffect(
             { image ->
                 snowConfig.shader.setInputBuffer(
                     "accumulatedSnow",
-                    BitmapShader(image, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR)
+                    BitmapShader(image, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR),
                 )
             },
-            mainExecutor
+            mainExecutor,
         )
     }
 
-    private fun updateSnowGridSize(surfaceSize: SizeF) {
-        val gridSize = GraphicsUtils.computeDefaultGridSize(surfaceSize, snowConfig.pixelDensity)
+    override fun updateGridSize(newSurfaceSize: SizeF) {
+        val gridSize = GraphicsUtils.computeDefaultGridSize(newSurfaceSize, snowConfig.pixelDensity)
         snowConfig.shader.setFloatUniform("gridSize", 7 * gridSize, 2f * gridSize)
     }
 }
diff --git a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/snow/SnowEffectConfig.kt b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/snow/SnowEffectConfig.kt
index 76b4892..dedb17c 100644
--- a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/snow/SnowEffectConfig.kt
+++ b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/snow/SnowEffectConfig.kt
@@ -72,8 +72,8 @@ data class SnowEffectConfig(
         private const val ACCUMULATED_SNOW_SHADER_PATH = "shaders/snow_accumulation.agsl"
         private const val COLOR_GRADING_SHADER_PATH = "shaders/color_grading_lut.agsl"
         private const val NOISE_TEXTURE_PATH = "textures/clouds.png"
-        private const val LOOKUP_TABLE_TEXTURE_PATH = "textures/lut_rain_and_fog.png"
-        private const val COLOR_GRADING_INTENSITY = 0.7f
+        private const val LOOKUP_TABLE_TEXTURE_PATH = "textures/snow_lut.png"
+        private const val COLOR_GRADING_INTENSITY = 0.25f
         private const val MAX_SNOW_THICKNESS = 10f
     }
 }
diff --git a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/sun/SunEffect.kt b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/sun/SunEffect.kt
index 29ffe5d..aa1ea71 100644
--- a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/sun/SunEffect.kt
+++ b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/sun/SunEffect.kt
@@ -20,27 +20,25 @@ import android.graphics.Bitmap
 import android.graphics.BitmapShader
 import android.graphics.Canvas
 import android.graphics.Paint
+import android.graphics.RuntimeShader
 import android.graphics.Shader
 import android.util.SizeF
 import com.google.android.wallpaper.weathereffects.graphics.WeatherEffect
-import com.google.android.wallpaper.weathereffects.graphics.utils.GraphicsUtils
-import com.google.android.wallpaper.weathereffects.graphics.utils.ImageCrop
-import java.util.concurrent.TimeUnit
-import kotlin.random.Random
+import com.google.android.wallpaper.weathereffects.graphics.WeatherEffectBase
+import com.google.android.wallpaper.weathereffects.graphics.utils.TimeUtils
 
 /** Defines and generates the sunny weather animation. */
 class SunEffect(
     /** The config of the sunny effect. */
     private val sunConfig: SunEffectConfig,
-    private var foreground: Bitmap,
-    private var background: Bitmap,
-    private var intensity: Float = WeatherEffect.DEFAULT_INTENSITY,
+    foreground: Bitmap,
+    background: Bitmap,
+    intensity: Float = WeatherEffect.DEFAULT_INTENSITY,
     /** The initial size of the surface where the effect will be shown. */
-    var surfaceSize: SizeF
-) : WeatherEffect {
+    surfaceSize: SizeF,
+) : WeatherEffectBase(foreground = foreground, background = background, surfaceSize = surfaceSize) {
 
     private val sunnyPaint = Paint().also { it.shader = sunConfig.colorGradingShader }
-    private var elapsedTime: Float = 0f
 
     init {
         updateTextureUniforms()
@@ -49,13 +47,20 @@ class SunEffect(
         setIntensity(intensity)
     }
 
-    override fun resize(newSurfaceSize: SizeF) {
-        adjustCropping(newSurfaceSize)
-        surfaceSize = newSurfaceSize
-    }
+    override val shader: RuntimeShader
+        get() = sunConfig.shader
+
+    override val colorGradingShader: RuntimeShader
+        get() = sunConfig.colorGradingShader
+
+    override val lut: Bitmap?
+        get() = sunConfig.lut
+
+    override val colorGradingIntensity: Float
+        get() = sunConfig.colorGradingIntensity
 
     override fun update(deltaMillis: Long, frameTimeNanos: Long) {
-        elapsedTime += TimeUnit.MILLISECONDS.toSeconds(deltaMillis)
+        elapsedTime += TimeUtils.millisToSeconds(deltaMillis)
         sunConfig.shader.setFloatUniform("time", elapsedTime)
         sunConfig.colorGradingShader.setInputShader("texture", sunConfig.shader)
     }
@@ -64,96 +69,12 @@ class SunEffect(
         canvas.drawPaint(sunnyPaint)
     }
 
-    override fun reset() {
-        elapsedTime = Random.nextFloat() * 90f
-    }
-
-    override fun release() {
-        sunConfig.lut?.recycle()
-    }
-
-    override fun setIntensity(intensity: Float) {
-        sunConfig.shader.setFloatUniform("intensity", intensity)
-        sunConfig.colorGradingShader.setFloatUniform(
-            "intensity",
-            sunConfig.colorGradingIntensity * intensity
-        )
-    }
-
-    override fun setBitmaps(foreground: Bitmap, background: Bitmap) {
-        this.foreground = foreground
-        this.background = background
-        sunConfig.shader.setInputBuffer(
-            "background",
-            BitmapShader(background, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR)
-        )
-        sunConfig.shader.setInputBuffer(
-            "foreground",
-            BitmapShader(foreground, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR)
-        )
-        adjustCropping(surfaceSize)
-    }
-
-    private fun adjustCropping(surfaceSize: SizeF) {
-        val imageCropFgd =
-            ImageCrop.centerCoverCrop(
-                surfaceSize.width,
-                surfaceSize.height,
-                foreground.width.toFloat(),
-                foreground.height.toFloat()
-            )
-        sunConfig.shader.setFloatUniform(
-            "uvOffsetFgd",
-            imageCropFgd.leftOffset,
-            imageCropFgd.topOffset
-        )
-        sunConfig.shader.setFloatUniform(
-            "uvScaleFgd",
-            imageCropFgd.horizontalScale,
-            imageCropFgd.verticalScale
-        )
-        val imageCropBgd =
-            ImageCrop.centerCoverCrop(
-                surfaceSize.width,
-                surfaceSize.height,
-                background.width.toFloat(),
-                background.height.toFloat()
-            )
-        sunConfig.shader.setFloatUniform(
-            "uvOffsetBgd",
-            imageCropBgd.leftOffset,
-            imageCropBgd.topOffset
-        )
-        sunConfig.shader.setFloatUniform(
-            "uvScaleBgd",
-            imageCropBgd.horizontalScale,
-            imageCropBgd.verticalScale
-        )
-        sunConfig.shader.setFloatUniform("screenSize", surfaceSize.width, surfaceSize.height)
-        sunConfig.shader.setFloatUniform(
-            "screenAspectRatio",
-            GraphicsUtils.getAspectRatio(surfaceSize)
-        )
-    }
-
-    private fun updateTextureUniforms() {
-        sunConfig.shader.setInputBuffer(
-            "foreground",
-            BitmapShader(foreground, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR)
-        )
-
-        sunConfig.shader.setInputBuffer(
-            "background",
-            BitmapShader(background, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR)
-        )
-    }
-
     private fun prepareColorGrading() {
         sunConfig.colorGradingShader.setInputShader("texture", sunConfig.shader)
         sunConfig.lut?.let {
             sunConfig.colorGradingShader.setInputShader(
                 "lut",
-                BitmapShader(it, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR)
+                BitmapShader(it, Shader.TileMode.MIRROR, Shader.TileMode.MIRROR),
             )
         }
         sunConfig.colorGradingShader.setFloatUniform("intensity", sunConfig.colorGradingIntensity)
diff --git a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/sun/SunEffectConfig.kt b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/sun/SunEffectConfig.kt
index 05f6b80..fa87cc2 100644
--- a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/sun/SunEffectConfig.kt
+++ b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/sun/SunEffectConfig.kt
@@ -56,7 +56,7 @@ data class SunEffectConfig(
     companion object {
         private const val SHADER_PATH = "shaders/sun_effect.agsl"
         private const val COLOR_GRADING_SHADER_PATH = "shaders/color_grading_lut.agsl"
-        private const val LOOKUP_TABLE_TEXTURE_PATH = "textures/lut_rain_and_fog.png"
-        private const val COLOR_GRADING_INTENSITY = 0.7f
+        private const val LOOKUP_TABLE_TEXTURE_PATH = "textures/sun_lut.png"
+        private const val COLOR_GRADING_INTENSITY = 0.18f
     }
 }
diff --git a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/utils/GraphicsUtils.kt b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/utils/GraphicsUtils.kt
index ab0db98..dca32cd 100644
--- a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/utils/GraphicsUtils.kt
+++ b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/utils/GraphicsUtils.kt
@@ -59,7 +59,7 @@ object GraphicsUtils {
             BitmapFactory.decodeStream(
                 it,
                 Rect(),
-                BitmapFactory.Options().apply { inPreferredConfig = Bitmap.Config.HARDWARE }
+                BitmapFactory.Options().apply { inPreferredConfig = Bitmap.Config.HARDWARE },
             )
         }
     }
@@ -77,7 +77,7 @@ object GraphicsUtils {
         context: Context,
         sourceBitmap: Bitmap,
         @FloatRange(from = 0.0, to = 25.0) blurRadius: Float,
-        config: Bitmap.Config = Bitmap.Config.ARGB_8888
+        config: Bitmap.Config = Bitmap.Config.ARGB_8888,
     ): Bitmap {
         // TODO: This might not be the ideal option, find a better one.
         val blurredImage = Bitmap.createBitmap(sourceBitmap.copy(config, true))
@@ -108,20 +108,22 @@ object GraphicsUtils {
     /**
      * Compute the weather effect default grid size. This takes into consideration the different
      * display densities and aspect ratio so the effect looks good on displays with different sizes.
+     *
      * @param surfaceSize the size of the surface where the wallpaper is being rendered.
      * @param density the current display density.
      * @return a [Float] representing the default size.
      */
     fun computeDefaultGridSize(surfaceSize: SizeF, density: Float): Float {
         val displayWidthDp = surfaceSize.width / density
-        val adjustedScale = when {
-            // "COMPACT"
-            displayWidthDp < 600 -> 1f
-            // "MEDIUM"
-            displayWidthDp >= 600 && displayWidthDp < 840 -> 0.9f
-            // "EXPANDED"
-            else -> 0.8f
-        }
+        val adjustedScale =
+            when {
+                // "COMPACT"
+                displayWidthDp < 600 -> 1f
+                // "MEDIUM"
+                displayWidthDp >= 600 && displayWidthDp < 840 -> 0.9f
+                // "EXPANDED"
+                else -> 0.8f
+            }
         return adjustedScale * displayWidthDp / DEFAULT_WIDTH_DP
     }
 
diff --git a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/utils/ImageCrop.kt b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/utils/ImageCrop.kt
index 0414a72..27988f9 100644
--- a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/utils/ImageCrop.kt
+++ b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/utils/ImageCrop.kt
@@ -52,7 +52,7 @@ class ImageCrop(
             surfaceWidth: Float,
             surfaceHeight: Float,
             imageWidth: Float,
-            imageHeight: Float
+            imageHeight: Float,
         ): ImageCrop {
             val uvScaleHeight: Float = imageHeight / surfaceHeight
             val uvScaleWidth: Float = imageWidth / surfaceWidth
diff --git a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/utils/MatrixUtils.kt b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/utils/MatrixUtils.kt
index a7c862c..7d2afa6 100644
--- a/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/utils/MatrixUtils.kt
+++ b/weathereffects/graphics/src/main/java/com/google/android/wallpaper/weathereffects/graphics/utils/MatrixUtils.kt
@@ -21,6 +21,12 @@ import android.util.SizeF
 
 /** Helper functions for matrix operations. */
 object MatrixUtils {
+    // Member variables in this object should be only used as intermediate buffer
+    // Should not be used as any return value
+    private val inverseMatrix: Matrix = Matrix()
+    private val concatMatrix: Matrix = Matrix()
+    private val matrixValues = FloatArray(9)
+
     /** Returns a [Matrix] that crops the image and centers to the screen. */
     fun centerCropMatrix(surfaceSize: SizeF, imageSize: SizeF): Matrix {
         val widthScale = surfaceSize.width / imageSize.width
@@ -36,4 +42,48 @@ object MatrixUtils {
             postTranslate(surfaceSize.width / 2f, surfaceSize.height / 2f)
         }
     }
+
+    // To apply parallax matrix to fragCoord, we need to invert and transpose the matrix
+    fun invertAndTransposeMatrix(matrix: Matrix, outArray: FloatArray): FloatArray {
+        matrix.invert(inverseMatrix)
+        inverseMatrix.getValues(matrixValues)
+        return transposeMatrixArray(matrixValues, outArray)
+    }
+
+    fun getScale(matrix: Matrix): Float {
+        matrix.getValues(matrixValues)
+        return matrixValues[0]
+    }
+
+    /**
+     * Calculates the transformation matrix that, when applied to `originMatrix`, results in
+     * `targetMatrix`. Current use case: Calculating parallax effect for the homescreen compared
+     * with page 0.
+     *
+     * @param originMatrix The original transformation matrix.
+     * @param targetMatrix The target transformation matrix.
+     * @param outArray A pre-allocated FloatArray to store the result.
+     * @return The transformation difference matrix as a FloatArray.
+     */
+    fun calculateTransformDifference(
+        originMatrix: Matrix,
+        targetMatrix: Matrix,
+        outArray: FloatArray,
+    ): FloatArray {
+        targetMatrix.invert(inverseMatrix)
+        concatMatrix.set(originMatrix)
+        concatMatrix.postConcat(inverseMatrix)
+        concatMatrix.getValues(matrixValues)
+        return transposeMatrixArray(matrixValues, outArray)
+    }
+
+    // Transpose 3x3 matrix values as a FloatArray[9], write results to outArray
+    private fun transposeMatrixArray(inMatrixArray: FloatArray, outArray: FloatArray): FloatArray {
+        for (i in 0 until 3) {
+            for (j in 0 until 3) {
+                outArray[j * 3 + i] = inMatrixArray[i * 3 + j]
+            }
+        }
+        return outArray
+    }
 }
diff --git a/weathereffects/src/com/google/android/wallpaper/weathereffects/WeatherEngine.kt b/weathereffects/src/com/google/android/wallpaper/weathereffects/WeatherEngine.kt
index ce6ccf7..137a2fc 100644
--- a/weathereffects/src/com/google/android/wallpaper/weathereffects/WeatherEngine.kt
+++ b/weathereffects/src/com/google/android/wallpaper/weathereffects/WeatherEngine.kt
@@ -217,7 +217,7 @@ class WeatherEngine(
                         foreground,
                         background,
                         effectIntensity,
-                        screenSize.toSizeF()
+                        screenSize.toSizeF(),
                     )
             }
             WallpaperInfoContract.WeatherEffect.SNOW -> {
@@ -242,7 +242,7 @@ class WeatherEngine(
                         foreground,
                         background,
                         effectIntensity,
-                        screenSize.toSizeF()
+                        screenSize.toSizeF(),
                     )
             }
             else -> {
@@ -370,7 +370,7 @@ class WeatherEngine(
                     background,
                     256,
                     (background.width / background.height.toFloat() * 256).roundToInt(),
-                    /* filter = */ true
+                    /* filter = */ true,
                 )
             )
     }
@@ -382,7 +382,7 @@ class WeatherEngine(
     private enum class AnimationType {
         UNLOCK,
         WAKE,
-        NONE
+        NONE,
     }
 
     private companion object {
```

