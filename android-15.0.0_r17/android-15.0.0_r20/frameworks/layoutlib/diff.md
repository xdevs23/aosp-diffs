```diff
diff --git a/.idea/libraries/mockito.xml b/.idea/libraries/mockito.xml
index 516f451cf0..243c2d4644 100644
--- a/.idea/libraries/mockito.xml
+++ b/.idea/libraries/mockito.xml
@@ -1,7 +1,7 @@
 <component name="libraryTable">
   <library name="mockito">
     <CLASSES>
-      <root url="jar://$PROJECT_DIR$/../../out/soong/.intermediates/external/mockito/mockito/linux_glibc_common/combined/mockito.jar!/" />
+      <root url="jar://$PROJECT_DIR$/../../out/soong/.intermediates/external/mockito/mockito/linux_glibc_common/javac/mockito.jar!/" />
     </CLASSES>
     <JAVADOC />
     <SOURCES>
diff --git a/.idea/misc.xml b/.idea/misc.xml
index e4f8290c2e..21b83b6acc 100644
--- a/.idea/misc.xml
+++ b/.idea/misc.xml
@@ -53,7 +53,7 @@
       </value>
     </option>
   </component>
-  <component name="ProjectRootManager" version="2" languageLevel="JDK_17" default="true" project-jdk-name="jbr-17" project-jdk-type="JavaSDK">
+  <component name="ProjectRootManager" version="2" languageLevel="JDK_21" default="true" project-jdk-name="jbr-21" project-jdk-type="JavaSDK">
     <output url="file://$PROJECT_DIR$/out" />
   </component>
 </project>
\ No newline at end of file
diff --git a/.idea/runConfigurations/Create.xml b/.idea/runConfigurations/Create.xml
index af69537b09..150458d918 100644
--- a/.idea/runConfigurations/Create.xml
+++ b/.idea/runConfigurations/Create.xml
@@ -4,7 +4,7 @@
     <option name="ALTERNATIVE_JRE_PATH_ENABLED" value="true" />
     <option name="MAIN_CLASS_NAME" value="com.android.tools.layoutlib.create.Main" />
     <module name="create" />
-    <option name="PROGRAM_PARAMETERS" value="--create-stub out/soong/.temp/temp_layoutlib.jar out/soong/.intermediates/prebuilts/misc/common/atf/atf-prebuilt-jars-557133692/linux_glibc_common/combined/atf-prebuilt-jars-557133692.jar out/soong/.intermediates/external/icu/android_icu4j/core-icu4j-for-host/android_common/withres/core-icu4j-for-host.jar out/soong/.intermediates/libcore/core-libart/android_common/combined/core-libart.jar out/soong/.intermediates/frameworks/base/framework-all/android_common/combined/framework-all.jar out/soong/.intermediates/frameworks/base/ext/android_common/withres/ext.jar out/soong/.intermediates/external/icu/icu4j/icu4j-icudata-jarjar/linux_glibc_common/jarjar/icu4j-icudata-jarjar.jar out/soong/.intermediates/external/icu/icu4j/icu4j-icutzdata-jarjar/linux_glibc_common/jarjar/icu4j-icutzdata-jarjar.jar out/soong/.intermediates/frameworks/libs/systemui/monet/monet/android_common/combined/monet.jar" />
+    <option name="PROGRAM_PARAMETERS" value="--create-stub out/soong/.temp/temp_layoutlib.jar out/soong/.intermediates/prebuilts/misc/common/atf/atf-prebuilt-jars-557133692/linux_glibc_common/local-combined/atf-prebuilt-jars-557133692.jar out/soong/.intermediates/external/icu/icu4j/icu4j-icudata-jarjar/linux_glibc_common/jarjar/icu4j-icudata-jarjar.jar out/soong/.intermediates/external/icu/icu4j/icu4j-icutzdata-jarjar/linux_glibc_common/jarjar/icu4j-icutzdata-jarjar.jar out/soong/.intermediates/external/icu/android_icu4j/core-icu4j-for-host/android_common/withres/core-icu4j-for-host.jar out/soong/.intermediates/libcore/core-libart-for-host/android_common/combined/core-libart-for-host.jar out/soong/.intermediates/frameworks/base/framework-all/android_common/combined/framework-all.jar out/soong/.intermediates/frameworks/base/ext/android_common/withres/ext.jar out/soong/.intermediates/frameworks/libs/systemui/iconloaderlib/iconloader_base/android_common/withres/iconloader_base.jar out/soong/.intermediates/frameworks/libs/systemui/monet/monet/android_common/combined/monet.jar" />
     <option name="VM_PARAMETERS" value="-ea" />
     <option name="WORKING_DIRECTORY" value="$PROJECT_DIR$/../.." />
     <RunnerSettings RunnerId="Debug">
diff --git a/Android.bp b/Android.bp
index 3320e227fe..5e5fd7aa64 100644
--- a/Android.bp
+++ b/Android.bp
@@ -30,13 +30,16 @@ java_genrule_host {
     tools: ["layoutlib_create"],
     out: ["temp_layoutlib.jar"],
     srcs: [
-        ":atf-prebuilt-557133692{.jar}",
+        ":atf-prebuilt-557133692{.jar}", // HOST
+        ":icu4j-icudata-jarjar{.jar}", // HOST
+        ":icu4j-icutzdata-jarjar{.jar}", // HOST
+    ],
+    device_common_srcs: [
         ":core-icu4j-for-host{.jar}",
         ":core-libart-for-host{.jar}",
         ":framework-all{.jar}",
         ":ext{.jar}",
-        ":icu4j-icudata-jarjar{.jar}", // HOST
-        ":icu4j-icutzdata-jarjar{.jar}", // HOST
+        ":iconloader_base{.jar}",
         ":monet{.jar}",
     ],
     cmd: "rm -f $(out) && $(location layoutlib_create) --create-stub $(out) $(in)",
@@ -50,6 +53,7 @@ java_device_for_host {
         "core-libart-for-host",
         "ext",
         "framework-all",
+        "iconloader_base",
         "icu4j-icudata-jarjar",
         "icu4j-icutzdata-jarjar",
         "monet",
@@ -66,6 +70,8 @@ cc_library_host_shared {
         "-Wno-unused-parameter",
     ],
     header_libs: [
+        "libbase_headers",
+        "libhostgraphics_headers",
         "libnativebase_headers",
         "libnativedisplay_headers",
         "libnativewindow_headers",
@@ -74,25 +80,27 @@ cc_library_host_shared {
         "libandroid_runtime",
     ],
     static_libs: [
-        "libbase",
-        "libbinder",
-        "libcutils",
-        "libharfbuzz_ng",
         "libhostgraphics",
-        "libhwui",
-        "libicui18n",
-        "libicuuc",
-        "libicuuc_stubdata",
-        "libimage_io",
         "libinput",
-        "liblog",
-        "libjpegdecoder",
-        "libjpegencoder",
-        "libminikin",
-        "libnativehelper_jvm",
-        "libui-types",
-        "libultrahdr",
-        "libutils",
     ],
     stl: "libc++_static",
+    target: {
+        linux: {
+            version_script: "jni/linux/layoutlib_jni_export.txt",
+        },
+        darwin: {
+            ldflags: ["-Wl,-exported_symbols_list,frameworks/layoutlib/jni/darwin/layoutlib_jni_export.exp"],
+            dist: {
+                targets: ["layoutlib_jni"],
+                dir: "layoutlib_native/darwin",
+            },
+        },
+        linux_glibc_x86_64: {
+            dist: {
+                targets: ["layoutlib"],
+                dir: "layoutlib_native/linux",
+                tag: "stripped_all",
+            },
+        },
+    },
 }
diff --git a/bridge/bridge_client/src/com/android/layoutlib/bridge/intensive/BridgeClient.java b/bridge/bridge_client/src/com/android/layoutlib/bridge/intensive/BridgeClient.java
index b0689da390..8801cd4465 100644
--- a/bridge/bridge_client/src/com/android/layoutlib/bridge/intensive/BridgeClient.java
+++ b/bridge/bridge_client/src/com/android/layoutlib/bridge/intensive/BridgeClient.java
@@ -91,12 +91,14 @@ public abstract class BridgeClient {
     private static final String NATIVE_LIB_PATH_PROPERTY = "native.lib.path";
     private static final String FONT_DIR_PROPERTY = "font.dir";
     private static final String ICU_DATA_PATH_PROPERTY = "icu.data.path";
+    private static final String HYPHEN_DATA_DIR_PROPERTY = "hyphen.data.dir";
     private static final String KEYBOARD_DIR_PROPERTY = "keyboard.dir";
     private static final String PLATFORM_DIR_PROPERTY = "platform.dir";
 
     private static final String NATIVE_LIB_DIR_PATH;
     private static final String FONT_DIR;
     private static final String ICU_DATA_PATH;
+    private static final String HYPHEN_DATA_DIR;
     private static final String KEYBOARD_DIR;
     private static final String EMPTY_FRAME =
             "<?xml version=\"1.0\" encoding=\"utf-8\"?> <FrameLayout "
@@ -122,6 +124,7 @@ public abstract class BridgeClient {
         NATIVE_LIB_DIR_PATH = getNativeLibDirPath();
         FONT_DIR = getFontDir();
         ICU_DATA_PATH = getIcuDataPath();
+        HYPHEN_DATA_DIR = getHyphenDataDir();
         KEYBOARD_DIR = getKeyboardDir();
     }
 
@@ -195,6 +198,15 @@ public abstract class BridgeClient {
         return icuDataPath;
     }
 
+    private static String getHyphenDataDir() {
+        String hyphenDataDir = System.getProperty(HYPHEN_DATA_DIR_PROPERTY);
+        if (hyphenDataDir == null) {
+            hyphenDataDir = PLATFORM_DIR +
+                    "/../../../../../../common/obj/PACKAGING/hyphen_intermediates";
+        }
+        return hyphenDataDir;
+    }
+
     private static String getKeyboardDir() {
         String keyboardDir = System.getProperty(KEYBOARD_DIR_PROPERTY);
         if (keyboardDir == null) {
@@ -373,7 +385,8 @@ public abstract class BridgeClient {
         String[] keyboardPaths = new String[0];
         sBridge = new Bridge();
         sBridge.init(ConfigGenerator.loadProperties(buildProp), fontLocation, NATIVE_LIB_DIR_PATH,
-                ICU_DATA_PATH, keyboardPaths, ConfigGenerator.getEnumMap(attrs), getLayoutLog());
+                ICU_DATA_PATH, HYPHEN_DATA_DIR, keyboardPaths, ConfigGenerator.getEnumMap(attrs),
+                getLayoutLog());
         Bridge.getLock().lock();
         try {
             Bridge.setLog(getLayoutLog());
diff --git a/bridge/jarjar-rules.txt b/bridge/jarjar-rules.txt
index b30190708f..f4206d7fe9 100644
--- a/bridge/jarjar-rules.txt
+++ b/bridge/jarjar-rules.txt
@@ -1,3 +1,5 @@
+rule androidx.** com.android.layoutlib.androidx.@1
 rule com.google.protobuf.** com.android.layoutlib.protobuf.@1
 rule org.hamcrest.** com.android.layoutlib.hamcrest.@1
+rule org.jetbrains.** com.android.layoutlib.jetbrains.@1
 rule org.jsoup.** com.android.layoutlib.jsoup.@1
diff --git a/bridge/src/android/graphics/drawable/AdaptiveIconDrawable_Delegate.java b/bridge/src/android/graphics/drawable/AdaptiveIconDrawable_Delegate.java
index faf35321cb..5ddf69391f 100644
--- a/bridge/src/android/graphics/drawable/AdaptiveIconDrawable_Delegate.java
+++ b/bridge/src/android/graphics/drawable/AdaptiveIconDrawable_Delegate.java
@@ -17,6 +17,7 @@
 package android.graphics.drawable;
 
 import com.android.internal.R;
+import com.android.launcher3.icons.MonochromeIconFactory_Accessor;
 import com.android.layoutlib.bridge.android.BridgeContext;
 import com.android.layoutlib.bridge.impl.RenderAction;
 import com.android.tools.layoutlib.annotations.LayoutlibDelegate;
@@ -42,11 +43,22 @@ public class AdaptiveIconDrawable_Delegate {
 
     @LayoutlibDelegate
     public static void draw(AdaptiveIconDrawable thisDrawable, Canvas canvas) {
-        Resources res = Resources.getSystem();
         BridgeContext context = RenderAction.getCurrentContext();
-        if (context.useThemedIcon() && thisDrawable.getMonochrome() != null) {
+        if (context.useThemedIcon()) {
+            Drawable mono = thisDrawable.getMonochrome();
+            if (mono == null && !context.forceMonochromeIcon()) {
+                thisDrawable.draw_Original(canvas);
+                return;
+            }
+            int[] colors = getColors();
+            if (mono != null) {
+                mono.mutate();
+                mono.setTint(colors[1]);
+            } else {
+                mono = MonochromeIconFactory_Accessor.getMonochromeIcon(thisDrawable, colors[1]);
+            }
             AdaptiveIconDrawable themedIcon =
-                    createThemedVersionFromMonochrome(thisDrawable.getMonochrome(), res);
+                    new AdaptiveIconDrawable(new ColorDrawable(colors[0]), mono);
             themedIcon.onBoundsChange(thisDrawable.getBounds());
             themedIcon.draw_Original(canvas);
         } else {
@@ -54,26 +66,16 @@ public class AdaptiveIconDrawable_Delegate {
         }
     }
 
-    /**
-     * This builds the themed version of {@link AdaptiveIconDrawable}, copying what the
-     * framework does in {@link com.android.launcher3.Utilities#getFullDrawable}
-     */
-    private static AdaptiveIconDrawable createThemedVersionFromMonochrome(Drawable mono,
-            Resources resources) {
-        mono = mono.mutate();
-        int[] colors = getColors(resources);
-        mono.setTint(colors[1]);
-        return new AdaptiveIconDrawable(new ColorDrawable(colors[0]), mono);
-    }
-
-    private static int[] getColors(Resources resources) {
+    // Adapted from com.android.launcher3.icons.ThemedIconDrawable
+    private static int[] getColors() {
+        Resources resources = Resources.getSystem();
         int[] colors = new int[2];
         if (resources.getConfiguration().isNightModeActive()) {
-            colors[0] = resources.getColor(android.R.color.system_neutral1_800, null);
-            colors[1] = resources.getColor(android.R.color.system_accent1_100, null);
+            colors[0] = resources.getColor(android.R.color.system_accent2_800, null);
+            colors[1] = resources.getColor(android.R.color.system_accent1_200, null);
         } else {
             colors[0] = resources.getColor(android.R.color.system_accent1_100, null);
-            colors[1] = resources.getColor(android.R.color.system_neutral2_700, null);
+            colors[1] = resources.getColor(android.R.color.system_accent1_700, null);
         }
         return colors;
     }
diff --git a/bridge/src/android/hardware/display/DisplayManagerGlobal.java b/bridge/src/android/hardware/display/DisplayManagerGlobal.java
index e30009083f..a91c3b1916 100644
--- a/bridge/src/android/hardware/display/DisplayManagerGlobal.java
+++ b/bridge/src/android/hardware/display/DisplayManagerGlobal.java
@@ -36,12 +36,18 @@ import android.view.DisplayInfo;
 import android.view.Surface;
 
 import java.util.List;
+import java.util.concurrent.Executor;
 
 public final class DisplayManagerGlobal {
     public static final int EVENT_DISPLAY_ADDED = 1;
     public static final int EVENT_DISPLAY_CHANGED = 2;
     public static final int EVENT_DISPLAY_REMOVED = 3;
     public static final int EVENT_DISPLAY_BRIGHTNESS_CHANGED = 4;
+    public static final int EVENT_DISPLAY_HDR_SDR_RATIO_CHANGED = 5;
+    public static final int EVENT_DISPLAY_CONNECTED = 6;
+    public static final int EVENT_DISPLAY_DISCONNECTED = 7;
+    public static final int EVENT_DISPLAY_REFRESH_RATE_CHANGED = 8;
+    public static final int EVENT_DISPLAY_STATE_CHANGED = 9;
 
     private static DisplayManagerGlobal sInstance;
 
@@ -82,7 +88,10 @@ public final class DisplayManagerGlobal {
     }
 
     public void registerDisplayListener(@NonNull DisplayListener listener,
-            @Nullable Handler handler, long eventsMask) {}
+            @Nullable Handler handler, long internalEventFlagsMask, String packageName) {}
+
+    public void registerDisplayListener(@NonNull DisplayListener listener,
+            @NonNull Executor executor, long internalEventFlagsMask, String packageName) {}
 
     public void unregisterDisplayListener(DisplayListener listener) {}
 
diff --git a/bridge/src/android/view/AttachInfo_Accessor.java b/bridge/src/android/view/AttachInfo_Accessor.java
index 645e6a1182..8042f32817 100644
--- a/bridge/src/android/view/AttachInfo_Accessor.java
+++ b/bridge/src/android/view/AttachInfo_Accessor.java
@@ -67,6 +67,7 @@ public class AttachInfo_Accessor {
                     ((Layout)view).getInsetsFrameProviders());
         }
         view.dispatchAttachedToWindow(info, 0);
+        root.mTmpFrames.displayFrame.set(wm.getCurrentWindowMetrics().getBounds());
         return renderer;
     }
 
diff --git a/bridge/src/android/view/inputmethod/InputMethodManager_Delegate.java b/bridge/src/android/view/inputmethod/InputMethodManager_Delegate.java
index e97813f17d..4bdb63292f 100644
--- a/bridge/src/android/view/inputmethod/InputMethodManager_Delegate.java
+++ b/bridge/src/android/view/inputmethod/InputMethodManager_Delegate.java
@@ -77,7 +77,8 @@ public class InputMethodManager_Delegate {
 
     @LayoutlibDelegate
     /*package*/ static boolean hideSoftInputFromWindow(InputMethodManager thisManager,
-            IBinder windowToken, int flags, ResultReceiver resultReceiver, int reason) {
+            IBinder windowToken, int flags, ResultReceiver resultReceiver, int reason,
+            ImeTracker.Token statsToken) {
         return false;
     }
 }
diff --git a/bridge/src/com/android/launcher3/icons/MonochromeIconFactory_Accessor.java b/bridge/src/com/android/launcher3/icons/MonochromeIconFactory_Accessor.java
new file mode 100644
index 0000000000..8e6311409f
--- /dev/null
+++ b/bridge/src/com/android/launcher3/icons/MonochromeIconFactory_Accessor.java
@@ -0,0 +1,37 @@
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
+package com.android.launcher3.icons;
+
+import android.graphics.BlendMode;
+import android.graphics.BlendModeColorFilter;
+import android.graphics.drawable.AdaptiveIconDrawable;
+import android.graphics.drawable.Drawable;
+import android.graphics.drawable.InsetDrawable;
+
+import static android.graphics.drawable.AdaptiveIconDrawable.getExtraInsetFraction;
+
+public class MonochromeIconFactory_Accessor {
+        // Adapted from com.android.launcher3.icons.ThemedIconDrawable
+        public static Drawable getMonochromeIcon(AdaptiveIconDrawable adaptiveIcon,
+            int foregroundColor) {
+        MonochromeIconFactory monoFactory = new MonochromeIconFactory(adaptiveIcon.getBounds().width());
+        monoFactory.setColorFilter(new BlendModeColorFilter(foregroundColor, BlendMode.SRC_IN));
+        Drawable mono = monoFactory.wrap(adaptiveIcon);
+        float inset = getExtraInsetFraction() / (1 + 2 * getExtraInsetFraction());
+        return new InsetDrawable(mono, inset);
+    }
+}
diff --git a/bridge/src/com/android/layoutlib/bridge/Bridge.java b/bridge/src/com/android/layoutlib/bridge/Bridge.java
index 90d8a28348..d4af5dc837 100644
--- a/bridge/src/com/android/layoutlib/bridge/Bridge.java
+++ b/bridge/src/com/android/layoutlib/bridge/Bridge.java
@@ -52,6 +52,7 @@ import android.icu.util.ULocale;
 import android.os.Looper;
 import android.os.Looper_Accessor;
 import android.os.SystemProperties;
+import android.text.Hyphenator;
 import android.util.Pair;
 import android.util.SparseArray;
 import android.view.Gravity;
@@ -170,25 +171,27 @@ public final class Bridge extends com.android.ide.common.rendering.api.Bridge {
     private static ILayoutLog sCurrentLog = sDefaultLog;
 
     private static String sIcuDataPath;
+    private static String sHyphenDataDir;
     private static String[] sKeyboardPaths;
 
     private static final String[] LINUX_NATIVE_LIBRARIES = {"layoutlib_jni.so"};
     private static final String[] MAC_NATIVE_LIBRARIES = {"layoutlib_jni.dylib"};
     private static final String[] WINDOWS_NATIVE_LIBRARIES =
-            {"libicuuc_stubdata.dll", "libicuuc-host.dll", "libandroid_runtime.dll",
-                    "layoutlib_jni.dll"};
+            {"libandroid_runtime.dll", "layoutlib_jni.dll"};
 
     @Override
     public boolean init(Map<String, String> platformProperties,
             File fontLocation,
             String nativeLibPath,
             String icuDataPath,
+            String hyphenDataDir,
             String[] keyboardPaths,
             Map<String, Map<String, Integer>> enumValueMap,
             ILayoutLog log) {
         sPlatformProperties = platformProperties;
         sEnumValueMap = enumValueMap;
         sIcuDataPath = icuDataPath;
+        sHyphenDataDir = hyphenDataDir;
         sKeyboardPaths = keyboardPaths;
         sCurrentLog = log;
 
@@ -258,6 +261,7 @@ public final class Bridge extends com.android.ide.common.rendering.api.Bridge {
             // Load system fonts now that Typeface has been initialized
             Typeface.loadPreinstalledSystemFontMap();
             ParserFactory.setParserFactory(null);
+            Hyphenator.init();
         } catch (Throwable t) {
             if (log != null) {
                 log.error(ILayoutLog.TAG_BROKEN, "Layoutlib Bridge initialization failed", t,
@@ -336,6 +340,7 @@ public final class Bridge extends com.android.ide.common.rendering.api.Bridge {
             SystemProperties.set(property.getKey(), property.getValue());
         }
         SystemProperties.set("ro.icu.data.path", Bridge.getIcuDataPath());
+        SystemProperties.set("ro.hyphen.data.dir", sHyphenDataDir);
         SystemProperties.set("ro.keyboard.paths", String.join(",", sKeyboardPaths));
     }
 
@@ -798,8 +803,9 @@ public final class Bridge extends com.android.ide.common.rendering.api.Bridge {
                     NativeConfig.CORE_CLASS_NATIVES));
             System.setProperty("graphics_native_classes", String.join(",",
                     NativeConfig.GRAPHICS_CLASS_NATIVES));
-            System.setProperty("use_bridge_for_logging", "true");
-            System.setProperty("register_properties_during_load", "true");
+            // This is needed on Windows to avoid creating HostRuntime when loading
+            // libandroid_runtime.dll.
+            System.setProperty("use_base_native_hostruntime", "false");
             for (String library : getNativeLibraries()) {
                 String path = new File(nativeLibDir, library).getAbsolutePath();
                 System.load(path);
diff --git a/bridge/src/com/android/layoutlib/bridge/android/BridgeContext.java b/bridge/src/com/android/layoutlib/bridge/android/BridgeContext.java
index f85fae8c8e..68206251b8 100644
--- a/bridge/src/com/android/layoutlib/bridge/android/BridgeContext.java
+++ b/bridge/src/com/android/layoutlib/bridge/android/BridgeContext.java
@@ -206,6 +206,7 @@ public class BridgeContext extends Context {
     private PackageManager mPackageManager;
     private Boolean mIsThemeAppCompat;
     private boolean mUseThemedIcon;
+    private boolean mForceMonochromeIcon;
     private Context mApplicationContext;
     private AccessibilityManager mAccessibilityManager;
     private final ResourceNamespace mAppCompatNamespace;
@@ -730,6 +731,9 @@ public class BridgeContext extends Context {
             case TEXT_CLASSIFICATION_SERVICE:
             case CONTENT_CAPTURE_MANAGER_SERVICE:
             case ALARM_SERVICE:
+            case CAPTIONING_SERVICE:
+            case TELEPHONY_SERVICE:
+            case WIFI_SERVICE:
                 return null;
             default:
                 // Only throw exception if the required service is unsupported but recognized as
@@ -2315,6 +2319,14 @@ public class BridgeContext extends Context {
         mUseThemedIcon = useThemedIcon;
     }
 
+    public boolean forceMonochromeIcon() {
+        return mForceMonochromeIcon;
+    }
+
+    public void setForceMonochromeIcon(boolean forceMonochromeIcon) {
+        mForceMonochromeIcon = forceMonochromeIcon;
+    }
+
     public void applyWallpaper(String wallpaperPath) {
         mRenderResources.setWallpaper(wallpaperPath, mConfig.isNightModeActive());
     }
diff --git a/bridge/src/com/android/layoutlib/bridge/android/BridgePowerManager.java b/bridge/src/com/android/layoutlib/bridge/android/BridgePowerManager.java
index c376429186..ed96282932 100644
--- a/bridge/src/com/android/layoutlib/bridge/android/BridgePowerManager.java
+++ b/bridge/src/com/android/layoutlib/bridge/android/BridgePowerManager.java
@@ -180,7 +180,7 @@ public class BridgePowerManager implements IPowerManager {
     }
 
     @Override
-    public float getBrightnessConstraint(int constraint) {
+    public float getBrightnessConstraint(int displayId, int constraint) {
         return PowerManager.BRIGHTNESS_MAX;
     }
 
@@ -245,6 +245,13 @@ public class BridgePowerManager implements IPowerManager {
         return true;
     }
 
+    @Override
+    public boolean isWakeLockLevelSupportedWithDisplayId(int level, int displayId)
+            throws RemoteException {
+        // pass for now.
+        return true;
+    }
+
     @Override
     public void userActivity(int displayId, long time, int event, int flags)
             throws RemoteException {
@@ -257,6 +264,12 @@ public class BridgePowerManager implements IPowerManager {
         // pass for now.
     }
 
+    @Override
+    public void wakeUpWithDisplayId(long time, @WakeReason int reason,
+        String details , String opPackageName, int displayId) throws RemoteException {
+        // pass for now.
+    }
+
     @Override
     public void boostScreenBrightness(long time) throws RemoteException {
         // pass for now.
diff --git a/bridge/src/com/android/layoutlib/bridge/android/BridgeThermalService.java b/bridge/src/com/android/layoutlib/bridge/android/BridgeThermalService.java
index 53b9228d1b..cbc4f7b4a0 100644
--- a/bridge/src/com/android/layoutlib/bridge/android/BridgeThermalService.java
+++ b/bridge/src/com/android/layoutlib/bridge/android/BridgeThermalService.java
@@ -19,6 +19,7 @@ package com.android.layoutlib.bridge.android;
 import android.os.CoolingDevice;
 import android.os.IBinder;
 import android.os.IThermalEventListener;
+import android.os.IThermalHeadroomListener;
 import android.os.IThermalStatusListener;
 import android.os.IThermalService;
 import android.os.Temperature;
@@ -92,4 +93,14 @@ public class BridgeThermalService implements IThermalService {
     public float[] getThermalHeadroomThresholds() {
         return new float[]{};
     }
+
+    @Override
+    public boolean registerThermalHeadroomListener(IThermalHeadroomListener listener) {
+        return false;
+    }
+
+    @Override
+    public boolean unregisterThermalHeadroomListener(IThermalHeadroomListener listener) {
+        return false;
+    }
 }
diff --git a/bridge/src/com/android/layoutlib/bridge/android/RenderParamsFlags.java b/bridge/src/com/android/layoutlib/bridge/android/RenderParamsFlags.java
index 73d8728b67..733ea2c753 100644
--- a/bridge/src/com/android/layoutlib/bridge/android/RenderParamsFlags.java
+++ b/bridge/src/com/android/layoutlib/bridge/android/RenderParamsFlags.java
@@ -82,6 +82,13 @@ public final class RenderParamsFlags {
     public static final Key<Boolean> FLAG_KEY_USE_THEMED_ICON =
             new Key<>("useThemedIcon", Boolean.class);
 
+    /**
+     * To tell Layoutlib to automatically create a monochrome version of adaptive icons
+     * if one is not explicitly provided.
+     */
+    public static final Key<Boolean> FLAG_KEY_FORCE_MONOCHROME_ICON =
+            new Key<>("forceMonochromeIcon", Boolean.class);
+
     /**
      * To tell Layoutlib to use the gesture navigation, instead of a button navigation bar.
      */
diff --git a/bridge/src/com/android/layoutlib/bridge/bars/StatusBar.java b/bridge/src/com/android/layoutlib/bridge/bars/StatusBar.java
index 0b3caebe57..66f4bbcf83 100644
--- a/bridge/src/com/android/layoutlib/bridge/bars/StatusBar.java
+++ b/bridge/src/com/android/layoutlib/bridge/bars/StatusBar.java
@@ -103,8 +103,15 @@ public class StatusBar extends CustomBar {
             return;
         }
 
-        int foregroundColor =
-                isEdgeToEdge ? DARK_ICON_COLOR : getForegroundColor(simulatedPlatformVersion);
+        int foregroundColor;
+        if (isEdgeToEdge) {
+            boolean isLightTheme =
+                    ResourceHelper.getBooleanThemeFrameworkAttrValue(context.getRenderResources(),
+                            "isLightTheme", false);
+            foregroundColor = isLightTheme ? DARK_ICON_COLOR : LIGHT_ICON_COLOR;
+        } else {
+            foregroundColor = getForegroundColor(simulatedPlatformVersion);
+        }
         // Cannot access the inside items through id because no R.id values have been
         // created for them.
         // We do know the order though.
diff --git a/bridge/src/com/android/layoutlib/bridge/impl/RenderAction.java b/bridge/src/com/android/layoutlib/bridge/impl/RenderAction.java
index 9bc6dbf603..1a3279f417 100644
--- a/bridge/src/com/android/layoutlib/bridge/impl/RenderAction.java
+++ b/bridge/src/com/android/layoutlib/bridge/impl/RenderAction.java
@@ -289,6 +289,8 @@ public abstract class RenderAction<T extends RenderParams> {
         mContext.applyWallpaper(mParams.getFlag(RenderParamsFlags.FLAG_KEY_WALLPAPER_PATH));
         mContext.setUseThemedIcon(
                 Boolean.TRUE.equals(mParams.getFlag(RenderParamsFlags.FLAG_KEY_USE_THEMED_ICON)));
+        mContext.setForceMonochromeIcon(Boolean.TRUE.equals(
+                mParams.getFlag(RenderParamsFlags.FLAG_KEY_FORCE_MONOCHROME_ICON)));
 
         // Set-up WindowManager
         // FIXME: find those out, and possibly add them to the render params
@@ -508,6 +510,8 @@ public abstract class RenderAction<T extends RenderParams> {
                 animationHandler.mAnimationCallbacks.clear();
                 animationHandler.mCommitCallbacks.clear();
             }
+            // Clear the ThreadLocal to avoid memory leaks
+            sCurrentContext.getAnimationHandlerThreadLocal().remove();
         }
 
         sCurrentContext = null;
diff --git a/bridge/src/com/android/layoutlib/bridge/impl/RenderSessionImpl.java b/bridge/src/com/android/layoutlib/bridge/impl/RenderSessionImpl.java
index 71657abfd6..94920ec8c4 100644
--- a/bridge/src/com/android/layoutlib/bridge/impl/RenderSessionImpl.java
+++ b/bridge/src/com/android/layoutlib/bridge/impl/RenderSessionImpl.java
@@ -1221,6 +1221,7 @@ public class RenderSessionImpl extends RenderAction<SessionParams> {
             mValidatorHierarchy = null;
             mViewRoot = null;
             mContentRoot = null;
+            mBlockParser = null;
         } catch (Throwable t) {
             getContext().error("Error while disposing a RenderSession", t);
         }
diff --git a/bridge/src/com/android/layoutlib/bridge/util/InsetUtil.java b/bridge/src/com/android/layoutlib/bridge/util/InsetUtil.java
index 19d582defb..6d5abec4c4 100644
--- a/bridge/src/com/android/layoutlib/bridge/util/InsetUtil.java
+++ b/bridge/src/com/android/layoutlib/bridge/util/InsetUtil.java
@@ -39,10 +39,8 @@ import android.view.WindowManager;
 import java.util.List;
 
 import static android.app.WindowConfiguration.ROTATION_UNDEFINED;
-import static android.inputmethodservice.InputMethodService.ENABLE_HIDE_IME_CAPTION_BAR;
 import static android.view.InsetsSource.FLAG_SUPPRESS_SCRIM;
 import static android.view.WindowManager.LayoutParams.LAYOUT_IN_DISPLAY_CUTOUT_MODE_ALWAYS;
-import static android.view.WindowManager.LayoutParams.TYPE_INPUT_METHOD;
 
 public class InsetUtil {
     public static Rect getCurrentBounds(Context context) {
@@ -176,10 +174,6 @@ public class InsetUtil {
             Context userContext) {
         final InsetsFrameProvider navBarProvider =
                 new InsetsFrameProvider(navBar, 0, WindowInsets.Type.navigationBars());
-        if (!ENABLE_HIDE_IME_CAPTION_BAR) {
-            navBarProvider.setInsetsSizeOverrides(new InsetsFrameProvider.InsetsSizeOverride[]{
-                    new InsetsFrameProvider.InsetsSizeOverride(TYPE_INPUT_METHOD, null)});
-        }
         if (insetsHeight != -1) {
             navBarProvider.setInsetsSize(Insets.of(0, 0, 0, insetsHeight));
         }
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/a11y_test1.png b/bridge/tests/res/testApp/MyApplication/golden-mac/a11y_test1.png
deleted file mode 100644
index 067a19363e..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/a11y_test1.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/activity.png b/bridge/tests/res/testApp/MyApplication/golden-mac/activity.png
deleted file mode 100644
index 0dbe45fa86..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/activity.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/adaptive_icon.png b/bridge/tests/res/testApp/MyApplication/golden-mac/adaptive_icon.png
deleted file mode 100644
index efcd49e750..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/adaptive_icon.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/adaptive_icon_circle.png b/bridge/tests/res/testApp/MyApplication/golden-mac/adaptive_icon_circle.png
deleted file mode 100644
index f85ef1b7fe..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/adaptive_icon_circle.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/adaptive_icon_rounded_corners.png b/bridge/tests/res/testApp/MyApplication/golden-mac/adaptive_icon_rounded_corners.png
deleted file mode 100644
index 3bb70551c2..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/adaptive_icon_rounded_corners.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/adaptive_icon_squircle.png b/bridge/tests/res/testApp/MyApplication/golden-mac/adaptive_icon_squircle.png
deleted file mode 100644
index f3b3a08d5d..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/adaptive_icon_squircle.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/allwidgets.png b/bridge/tests/res/testApp/MyApplication/golden-mac/allwidgets.png
deleted file mode 100644
index d99df26898..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/allwidgets.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/allwidgets_tab.png b/bridge/tests/res/testApp/MyApplication/golden-mac/allwidgets_tab.png
deleted file mode 100644
index 5ddd9d2e85..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/allwidgets_tab.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/animated_vector.png b/bridge/tests/res/testApp/MyApplication/golden-mac/animated_vector.png
deleted file mode 100644
index b4bed24937..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/animated_vector.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/animated_vector_1.png b/bridge/tests/res/testApp/MyApplication/golden-mac/animated_vector_1.png
deleted file mode 100644
index 37863c7e05..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/animated_vector_1.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/array_check.png b/bridge/tests/res/testApp/MyApplication/golden-mac/array_check.png
deleted file mode 100644
index db6e934548..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/array_check.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/asset.png b/bridge/tests/res/testApp/MyApplication/golden-mac/asset.png
deleted file mode 100644
index 9e587206eb..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/asset.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/auto-scale-image.png b/bridge/tests/res/testApp/MyApplication/golden-mac/auto-scale-image.png
deleted file mode 100644
index 7644183a59..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/auto-scale-image.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/button_resize.png b/bridge/tests/res/testApp/MyApplication/golden-mac/button_resize.png
deleted file mode 100644
index dc81204ad6..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/button_resize.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/button_resize2.png b/bridge/tests/res/testApp/MyApplication/golden-mac/button_resize2.png
deleted file mode 100644
index 9b7957628a..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/button_resize2.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/canvas.png b/bridge/tests/res/testApp/MyApplication/golden-mac/canvas.png
deleted file mode 100644
index ec503a4f1a..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/canvas.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/color_interpolation.png b/bridge/tests/res/testApp/MyApplication/golden-mac/color_interpolation.png
deleted file mode 100644
index c816e57273..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/color_interpolation.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/context_theme_wrapper.png b/bridge/tests/res/testApp/MyApplication/golden-mac/context_theme_wrapper.png
deleted file mode 100644
index 63578fafa9..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/context_theme_wrapper.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/dialog.png b/bridge/tests/res/testApp/MyApplication/golden-mac/dialog.png
deleted file mode 100644
index 2f029e5a52..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/dialog.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/expand_horz_layout.png b/bridge/tests/res/testApp/MyApplication/golden-mac/expand_horz_layout.png
deleted file mode 100644
index f179977a92..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/expand_horz_layout.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/expand_vert_layout.png b/bridge/tests/res/testApp/MyApplication/golden-mac/expand_vert_layout.png
deleted file mode 100644
index 269b7ac4ea..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/expand_vert_layout.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/font_test.png b/bridge/tests/res/testApp/MyApplication/golden-mac/font_test.png
deleted file mode 100644
index e036c162ad..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/font_test.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/four_corners.png b/bridge/tests/res/testApp/MyApplication/golden-mac/four_corners.png
deleted file mode 100644
index fc68ac18d1..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/four_corners.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/four_corners_translucent.png b/bridge/tests/res/testApp/MyApplication/golden-mac/four_corners_translucent.png
deleted file mode 100644
index 2aae93b01a..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/four_corners_translucent.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/four_corners_translucent_land.png b/bridge/tests/res/testApp/MyApplication/golden-mac/four_corners_translucent_land.png
deleted file mode 100644
index dae944a2ff..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/four_corners_translucent_land.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/gradient_alpha_drawable.png b/bridge/tests/res/testApp/MyApplication/golden-mac/gradient_alpha_drawable.png
deleted file mode 100644
index 8892bcf6e1..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/gradient_alpha_drawable.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/gradient_colors.png b/bridge/tests/res/testApp/MyApplication/golden-mac/gradient_colors.png
deleted file mode 100644
index d5b7c101a2..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/gradient_colors.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/justified_inter_word.png b/bridge/tests/res/testApp/MyApplication/golden-mac/justified_inter_word.png
deleted file mode 100644
index 48078217cb..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/justified_inter_word.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/justified_none.png b/bridge/tests/res/testApp/MyApplication/golden-mac/justified_none.png
deleted file mode 100644
index e083346b66..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/justified_none.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/large_shadows_test.png b/bridge/tests/res/testApp/MyApplication/golden-mac/large_shadows_test.png
deleted file mode 100644
index a79ad55557..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/large_shadows_test.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/many_line_breaks.png b/bridge/tests/res/testApp/MyApplication/golden-mac/many_line_breaks.png
deleted file mode 100644
index ea5750c79c..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/many_line_breaks.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/ninepatch_background.png b/bridge/tests/res/testApp/MyApplication/golden-mac/ninepatch_background.png
deleted file mode 100644
index 014df65928..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/ninepatch_background.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/ninepatch_drawable.png b/bridge/tests/res/testApp/MyApplication/golden-mac/ninepatch_drawable.png
deleted file mode 100644
index 211594dfe3..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/ninepatch_drawable.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/non-styled_resources.png b/bridge/tests/res/testApp/MyApplication/golden-mac/non-styled_resources.png
deleted file mode 100644
index 6490b263cf..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/non-styled_resources.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/normal_layout.png b/bridge/tests/res/testApp/MyApplication/golden-mac/normal_layout.png
deleted file mode 100644
index f60ecb0b74..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/normal_layout.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/ondraw_crash.png b/bridge/tests/res/testApp/MyApplication/golden-mac/ondraw_crash.png
deleted file mode 100644
index 8633a259d8..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/ondraw_crash.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/onmeasure_crash.png b/bridge/tests/res/testApp/MyApplication/golden-mac/onmeasure_crash.png
deleted file mode 100644
index 5559a89456..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/onmeasure_crash.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/render_effect.png b/bridge/tests/res/testApp/MyApplication/golden-mac/render_effect.png
deleted file mode 100644
index 7a909981e9..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/render_effect.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/rtl_ltr.png b/bridge/tests/res/testApp/MyApplication/golden-mac/rtl_ltr.png
deleted file mode 100644
index 6a451a2a65..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/rtl_ltr.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/scrolled.png b/bridge/tests/res/testApp/MyApplication/golden-mac/scrolled.png
deleted file mode 100644
index 97bf039562..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/scrolled.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/shadow_scrollview_test.png b/bridge/tests/res/testApp/MyApplication/golden-mac/shadow_scrollview_test.png
deleted file mode 100644
index b1a3b26739..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/shadow_scrollview_test.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/shadow_sizes_test.png b/bridge/tests/res/testApp/MyApplication/golden-mac/shadow_sizes_test.png
deleted file mode 100644
index 3bc9b4c27b..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/shadow_sizes_test.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/shadows_test.png b/bridge/tests/res/testApp/MyApplication/golden-mac/shadows_test.png
deleted file mode 100644
index c8dea1bf57..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/shadows_test.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/shadows_test_rounded_edge.png b/bridge/tests/res/testApp/MyApplication/golden-mac/shadows_test_rounded_edge.png
deleted file mode 100644
index 8bac13b854..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/shadows_test_rounded_edge.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/shrunk_layout.png b/bridge/tests/res/testApp/MyApplication/golden-mac/shrunk_layout.png
deleted file mode 100644
index e2eb120ef7..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/shrunk_layout.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/simple_activity-old-theme.png b/bridge/tests/res/testApp/MyApplication/golden-mac/simple_activity-old-theme.png
deleted file mode 100644
index d782cd198c..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/simple_activity-old-theme.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/simple_activity.png b/bridge/tests/res/testApp/MyApplication/golden-mac/simple_activity.png
deleted file mode 100644
index efb7ac3ae3..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/simple_activity.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/simple_activity_noactionbar.png b/bridge/tests/res/testApp/MyApplication/golden-mac/simple_activity_noactionbar.png
deleted file mode 100644
index 36350a04ad..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/simple_activity_noactionbar.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/textclock.png b/bridge/tests/res/testApp/MyApplication/golden-mac/textclock.png
deleted file mode 100644
index 108380c4d3..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/textclock.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/translate_test.png b/bridge/tests/res/testApp/MyApplication/golden-mac/translate_test.png
deleted file mode 100644
index 032089f012..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/translate_test.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/transparent_drawable.png b/bridge/tests/res/testApp/MyApplication/golden-mac/transparent_drawable.png
deleted file mode 100644
index 68ccf2f91d..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/transparent_drawable.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/typed_arrays.png b/bridge/tests/res/testApp/MyApplication/golden-mac/typed_arrays.png
deleted file mode 100644
index e3f4df7c20..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/typed_arrays.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/vector_drawable.png b/bridge/tests/res/testApp/MyApplication/golden-mac/vector_drawable.png
deleted file mode 100644
index ecc4497a3c..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/vector_drawable.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/vector_drawable_91383.png b/bridge/tests/res/testApp/MyApplication/golden-mac/vector_drawable_91383.png
deleted file mode 100644
index 1d4ac397f0..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/vector_drawable_91383.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/vector_drawable_gradient.png b/bridge/tests/res/testApp/MyApplication/golden-mac/vector_drawable_gradient.png
deleted file mode 100644
index 0268d9c33f..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/vector_drawable_gradient.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/vector_drawable_radial_gradient.png b/bridge/tests/res/testApp/MyApplication/golden-mac/vector_drawable_radial_gradient.png
deleted file mode 100644
index a27a48eb21..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/vector_drawable_radial_gradient.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/vector_drawable_with_tint_in_image_view.png b/bridge/tests/res/testApp/MyApplication/golden-mac/vector_drawable_with_tint_in_image_view.png
deleted file mode 100644
index 48f0f0542a..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/vector_drawable_with_tint_in_image_view.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/vector_drawable_with_tint_itself.png b/bridge/tests/res/testApp/MyApplication/golden-mac/vector_drawable_with_tint_itself.png
deleted file mode 100644
index 92855d13db..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/vector_drawable_with_tint_itself.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/view_boundaries.png b/bridge/tests/res/testApp/MyApplication/golden-mac/view_boundaries.png
deleted file mode 100644
index da770e1f94..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/view_boundaries.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/view_stub.png b/bridge/tests/res/testApp/MyApplication/golden-mac/view_stub.png
deleted file mode 100644
index b66ff2d524..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/view_stub.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden-mac/window_background.png b/bridge/tests/res/testApp/MyApplication/golden-mac/window_background.png
deleted file mode 100644
index 1d25725e4e..0000000000
Binary files a/bridge/tests/res/testApp/MyApplication/golden-mac/window_background.png and /dev/null differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/adaptive_icon_dynamic_green.png b/bridge/tests/res/testApp/MyApplication/golden/adaptive_icon_dynamic_green.png
index 1348f00de2..70722989ce 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/adaptive_icon_dynamic_green.png and b/bridge/tests/res/testApp/MyApplication/golden/adaptive_icon_dynamic_green.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/adaptive_icon_dynamic_orange.png b/bridge/tests/res/testApp/MyApplication/golden/adaptive_icon_dynamic_orange.png
index 8bee0a8544..bb83bcada8 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/adaptive_icon_dynamic_orange.png and b/bridge/tests/res/testApp/MyApplication/golden/adaptive_icon_dynamic_orange.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/adaptive_no_monochrome_green.png b/bridge/tests/res/testApp/MyApplication/golden/adaptive_no_monochrome_green.png
new file mode 100644
index 0000000000..65e3870f71
Binary files /dev/null and b/bridge/tests/res/testApp/MyApplication/golden/adaptive_no_monochrome_green.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/adaptive_no_monochrome_orange.png b/bridge/tests/res/testApp/MyApplication/golden/adaptive_no_monochrome_orange.png
new file mode 100644
index 0000000000..a6d586e1bc
Binary files /dev/null and b/bridge/tests/res/testApp/MyApplication/golden/adaptive_no_monochrome_orange.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/dark_gesture_nav.png b/bridge/tests/res/testApp/MyApplication/golden/dark_gesture_nav.png
index 02e5c26bfa..c893927fd4 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/dark_gesture_nav.png and b/bridge/tests/res/testApp/MyApplication/golden/dark_gesture_nav.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/hyphenation.png b/bridge/tests/res/testApp/MyApplication/golden/hyphenation.png
new file mode 100644
index 0000000000..75df6d83a4
Binary files /dev/null and b/bridge/tests/res/testApp/MyApplication/golden/hyphenation.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/land_gesture_nav.png b/bridge/tests/res/testApp/MyApplication/golden/land_gesture_nav.png
index 71d38e0219..0450e0b1e8 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/land_gesture_nav.png and b/bridge/tests/res/testApp/MyApplication/golden/land_gesture_nav.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/simple_activity-old-theme.png b/bridge/tests/res/testApp/MyApplication/golden/simple_activity-old-theme.png
index afa2082eff..fe1fdc5696 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/simple_activity-old-theme.png and b/bridge/tests/res/testApp/MyApplication/golden/simple_activity-old-theme.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/src/main/res/drawable/adaptive_no_monochrome.xml b/bridge/tests/res/testApp/MyApplication/src/main/res/drawable/adaptive_no_monochrome.xml
new file mode 100644
index 0000000000..cc9c449563
--- /dev/null
+++ b/bridge/tests/res/testApp/MyApplication/src/main/res/drawable/adaptive_no_monochrome.xml
@@ -0,0 +1,6 @@
+<?xml version="1.0" encoding="utf-8"?>
+
+<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">
+    <background android:drawable="@color/red" />
+    <foreground android:drawable="@drawable/headset" />
+</adaptive-icon>
\ No newline at end of file
diff --git a/bridge/tests/run_tests.sh b/bridge/tests/run_tests.sh
index 376e948f17..12b8ff6367 100755
--- a/bridge/tests/run_tests.sh
+++ b/bridge/tests/run_tests.sh
@@ -22,6 +22,7 @@ HOST_LIBRARIES="${BASE_DIR}/out/host/linux-x86"
 SDK="${BASE_DIR}/out/host/linux-x86/sdk/sdk*/android-sdk*"
 SDK_REPO="${BASE_DIR}/out/host/linux-x86/sdk-repo"
 FONT_DIR="${BASE_DIR}/out/host/common/obj/PACKAGING/fonts_intermediates"
+HYPHEN_DATA_DIR="${BASE_DIR}/out/host/common/obj/PACKAGING/hyphen_intermediates"
 KEYBOARD_DIR="${BASE_DIR}/out/host/common/obj/PACKAGING/keyboards_intermediates"
 ICU_DATA_PATH="${BASE_DIR}/out/host/linux-x86/com.android.i18n/etc/icu/icudt75l.dat"
 TMP_DIR=${OUT_DIR}"/layoutlib_tmp"
@@ -62,6 +63,7 @@ ${STUDIO_JDK}/bin/java -ea $DEBUGGER \
     -Dnative.lib.path=${NATIVE_LIBRARIES} \
     -Dfont.dir=${FONT_DIR} \
     -Dicu.data.path=${ICU_DATA_PATH} \
+    -Dhyphen.data.dir=${HYPHEN_DATA_DIR} \
     -Dkeyboard.dir=${KEYBOARD_DIR} \
     -Dplatform.dir=${PLATFORM} \
     -Dtest_failure.dir=${OUT_DIR}/${FAILURE_DIR} \
diff --git a/bridge/tests/run_tests_mac.sh b/bridge/tests/run_tests_mac.sh
deleted file mode 100755
index 0649f254f4..0000000000
--- a/bridge/tests/run_tests_mac.sh
+++ /dev/null
@@ -1,82 +0,0 @@
-#!/bin/bash
-
-# There is no macOS build of the SDK anymore
-# Do not run layoutlib tests
-exit 0
-
-readonly OUT_DIR="$1"
-readonly DIST_DIR="$2"
-readonly BUILD_NUMBER="$3"
-
-readonly SCRIPT_DIR="$(dirname "$0")"
-
-readonly FAILURE_DIR=layoutlib-test-failures
-readonly FAILURE_ZIP=layoutlib-test-failures.zip
-
-STUDIO_JDK=${SCRIPT_DIR}"/../../../../prebuilts/jdk/jdk11/darwin-x86"
-MISC_COMMON=${SCRIPT_DIR}"/../../../../prebuilts/misc/common"
-OUT_INTERMEDIATES=${SCRIPT_DIR}"/../../../../out/soong/.intermediates"
-NATIVE_LIBRARIES=${SCRIPT_DIR}"/../../../../out/host/darwin-x86/lib64/"
-SDK=${SCRIPT_DIR}"/../../../../out/host/darwin-x86/sdk/sdk*/android-sdk*"
-SDK_REPO=${SCRIPT_DIR}"/../../../../out/soong/host/linux-x86/sdk-repo"
-FONT_DIR=${SCRIPT_DIR}"/../../../../out/host/common/obj/PACKAGING/fonts_intermediates"
-ICU_DATA_PATH=${SCRIPT_DIR}"/../../../../out/host/darwin-x86/com.android.i18n/etc/icu/icudt69l.dat"
-TMP_DIR=$(mktemp -d -t tmp)
-PLATFORM=${TMP_DIR}/"android"
-
-# Copy resources to a temp directory
-cp -r ${SDK}/platforms/android* ${PLATFORM}
-
-# Unzip build-tools to access aapt2
-mkdir ${TMP_DIR}/build-tools
-unzip -q ${SDK_REPO}/sdk-repo-linux-build-tools.zip -d ${TMP_DIR}/build-tools
-
-# Compile 9-patch files
-mkdir ${TMP_DIR}/compiled
-mkdir ${TMP_DIR}/manifest
-echo \
-'<?xml version="1.0" encoding="utf-8"?>
-<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.google.android.layoutlib" />' \
-> ${TMP_DIR}/manifest/AndroidManifest.xml
-for f in ${SDK}/platforms/android*/data/res/*
-do
-    find $f -name "*.9.png" -print0 | xargs -0 ${TMP_DIR}/build-tools/android-*/aapt2 compile -o ${TMP_DIR}/compiled/
-    find ${TMP_DIR}/compiled -name "*.flat" -print0 | xargs -0 ${TMP_DIR}/build-tools/android-*/aapt2 link -o ${TMP_DIR}/compiled.apk --manifest ${TMP_DIR}/manifest/AndroidManifest.xml -R
-    if [[ -f "${TMP_DIR}/compiled.apk" ]]; then
-        unzip -qo ${TMP_DIR}/compiled.apk -d ${TMP_DIR}
-        rm -r ${TMP_DIR}/compiled/*
-        rm ${TMP_DIR}/compiled.apk
-    fi
-done
-for f in ${TMP_DIR}/res/*; do mv "$f" "${f/-v4/}";done
-cp -RL ${TMP_DIR}/res ${PLATFORM}/data
-
-# Run layoutlib tests
-${STUDIO_JDK}/bin/java -ea \
-    -Dnative.lib.path=${NATIVE_LIBRARIES} \
-    -Dfont.dir=${FONT_DIR} \
-    -Dicu.data.path=${ICU_DATA_PATH} \
-    -Dplatform.dir=${PLATFORM} \
-    -Dtest_res.dir=${SCRIPT_DIR}/res \
-    -Dtest_failure.dir=${OUT_DIR}/${FAILURE_DIR} \
-    -cp ${MISC_COMMON}/tools-common/tools-common-prebuilt.jar:${MISC_COMMON}/ninepatch/ninepatch-prebuilt.jar:${MISC_COMMON}/sdk-common/sdk-common.jar:${MISC_COMMON}/kxml2/kxml2-2.3.0.jar:${MISC_COMMON}/layoutlib_api/layoutlib_api-prebuilt.jar:${OUT_INTERMEDIATES}/prebuilts/tools/common/m2/trove-prebuilt/darwin_common/combined/trove-prebuilt.jar:${OUT_INTERMEDIATES}/external/junit/junit/darwin_common/javac/junit.jar:${OUT_INTERMEDIATES}/external/guava/guava-jre/darwin_common/javac/guava-jre.jar:${OUT_INTERMEDIATES}/external/hamcrest/hamcrest-core/hamcrest/darwin_common/javac/hamcrest.jar:${OUT_INTERMEDIATES}/external/mockito/mockito/darwin_common/combined/mockito.jar:${OUT_INTERMEDIATES}/external/objenesis/objenesis/darwin_common/javac/objenesis.jar:${OUT_INTERMEDIATES}/frameworks/layoutlib/bridge/layoutlib/darwin_common/withres/layoutlib.jar:${OUT_INTERMEDIATES}/frameworks/layoutlib/temp_layoutlib/darwin_common/gen/temp_layoutlib.jar:${OUT_INTERMEDIATES}/frameworks/layoutlib/bridge/tests/layoutlib-tests/darwin_common/withres/layoutlib-tests.jar \
-    org.junit.runner.JUnitCore \
-    com.android.layoutlib.bridge.intensive.Main
-
-test_exit_code=$?
-
-# Create zip of all failure screenshots
-if [[ -d "${OUT_DIR}/${FAILURE_DIR}" ]]; then
-    zip -q -j -r ${OUT_DIR}/${FAILURE_ZIP} ${OUT_DIR}/${FAILURE_DIR}
-fi
-
-# Move failure zip to dist directory if specified
-if [[ -d "${DIST_DIR}" ]] && [[ -e "${OUT_DIR}/${FAILURE_ZIP}" ]]; then
-    mv ${OUT_DIR}/${FAILURE_ZIP} ${DIST_DIR}
-fi
-
-# Clean
-rm -rf ${TMP_DIR}
-rm -rf ${OUT_DIR}/${FAILURE_DIR}
-
-exit ${test_exit_code}
diff --git a/bridge/tests/src/com/android/layoutlib/bridge/intensive/RenderTests.java b/bridge/tests/src/com/android/layoutlib/bridge/intensive/RenderTests.java
index 23fe8434ab..7cc00e5e87 100644
--- a/bridge/tests/src/com/android/layoutlib/bridge/intensive/RenderTests.java
+++ b/bridge/tests/src/com/android/layoutlib/bridge/intensive/RenderTests.java
@@ -2065,6 +2065,98 @@ public class RenderTests extends RenderTestBase {
         renderAndVerify(params, "adaptive_icon_circle.png");
     }
 
+    @Test
+    public void testThemedAdaptiveIconNoMonochrome() throws ClassNotFoundException {
+        // Create the layout pull parser.
+        String layout = """
+                <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+                              android:padding="16dp"
+                              android:orientation="horizontal"
+                              android:layout_width="fill_parent"
+                              android:layout_height="fill_parent">
+                    <ImageView
+                             android:layout_height="wrap_content"
+                             android:layout_width="wrap_content"
+                             android:src="@drawable/adaptive_no_monochrome" />
+                </LinearLayout>
+                """;
+        // Create LayoutLibCallback.
+        LayoutLibTestCallback layoutLibCallback =
+                new LayoutLibTestCallback(getLogger(), mDefaultClassLoader);
+        layoutLibCallback.initResources();
+        SessionParams params = getSessionParamsBuilder()
+                .setParser(LayoutPullParser.createFromString(layout))
+                .setCallback(layoutLibCallback)
+                .setTheme("Theme.Material.NoActionBar.Fullscreen", false)
+                .setRenderingMode(RenderingMode.V_SCROLL)
+                .build();
+        params.setFlag(RenderParamsFlags.FLAG_KEY_ADAPTIVE_ICON_MASK_PATH,
+                "M50 0C77.6 0 100 22.4 100 50C100 77.6 77.6 100 50 100C22.4 100 0 77.6 0 50C0 " +
+                        "22.4 22.4 0 50 0Z");
+        params.setFlag(RenderParamsFlags.FLAG_KEY_FORCE_MONOCHROME_ICON, true);
+        renderAndVerify(params, "adaptive_icon_circle.png");
+
+        params = getSessionParamsBuilder()
+                .setParser(LayoutPullParser.createFromString(layout))
+                .setCallback(layoutLibCallback)
+                .setTheme("Theme.Material.NoActionBar.Fullscreen", false)
+                .setRenderingMode(RenderingMode.V_SCROLL)
+                .build();
+        params.setFlag(RenderParamsFlags.FLAG_KEY_ADAPTIVE_ICON_MASK_PATH,
+                "M50 0C77.6 0 100 22.4 100 50C100 77.6 77.6 100 50 100C22.4 100 0 77.6 0 50C0 " +
+                        "22.4 22.4 0 50 0Z");
+        params.setFlag(RenderParamsFlags.FLAG_KEY_WALLPAPER_PATH,
+                "/com/android/layoutlib/testdata/wallpaper1.webp");
+        params.setFlag(RenderParamsFlags.FLAG_KEY_USE_THEMED_ICON, true);
+        params.setFlag(RenderParamsFlags.FLAG_KEY_FORCE_MONOCHROME_ICON, true);
+        renderAndVerify(params, "adaptive_no_monochrome_orange.png");
+
+        params = getSessionParamsBuilder()
+                .setParser(LayoutPullParser.createFromString(layout))
+                .setCallback(layoutLibCallback)
+                .setTheme("Theme.Material.NoActionBar.Fullscreen", false)
+                .setRenderingMode(RenderingMode.V_SCROLL)
+                .build();
+        params.setFlag(RenderParamsFlags.FLAG_KEY_ADAPTIVE_ICON_MASK_PATH,
+                "M50 0C77.6 0 100 22.4 100 50C100 77.6 77.6 100 50 100C22.4 100 0 77.6 0 50C0 " +
+                        "22.4 22.4 0 50 0Z");
+        params.setFlag(RenderParamsFlags.FLAG_KEY_WALLPAPER_PATH,
+                "/com/android/layoutlib/testdata/wallpaper2.webp");
+        params.setFlag(RenderParamsFlags.FLAG_KEY_USE_THEMED_ICON, true);
+        params.setFlag(RenderParamsFlags.FLAG_KEY_FORCE_MONOCHROME_ICON, true);
+        renderAndVerify(params, "adaptive_no_monochrome_green.png");
+
+        params = getSessionParamsBuilder()
+                .setParser(LayoutPullParser.createFromString(layout))
+                .setCallback(layoutLibCallback)
+                .setTheme("Theme.Material.NoActionBar.Fullscreen", false)
+                .setRenderingMode(RenderingMode.V_SCROLL)
+                .build();
+        params.setFlag(RenderParamsFlags.FLAG_KEY_ADAPTIVE_ICON_MASK_PATH,
+                "M50 0C77.6 0 100 22.4 100 50C100 77.6 77.6 100 50 100C22.4 100 0 77.6 0 50C0 " +
+                        "22.4 22.4 0 50 0Z");
+        params.setFlag(RenderParamsFlags.FLAG_KEY_WALLPAPER_PATH,
+                "/com/android/layoutlib/testdata/wallpaper2.webp");
+        params.setFlag(RenderParamsFlags.FLAG_KEY_USE_THEMED_ICON, false);
+        params.setFlag(RenderParamsFlags.FLAG_KEY_FORCE_MONOCHROME_ICON, true);
+        renderAndVerify(params, "adaptive_icon_circle.png");
+
+        params = getSessionParamsBuilder()
+                .setParser(LayoutPullParser.createFromString(layout))
+                .setCallback(layoutLibCallback)
+                .setTheme("Theme.Material.NoActionBar.Fullscreen", false)
+                .setRenderingMode(RenderingMode.V_SCROLL)
+                .build();
+        params.setFlag(RenderParamsFlags.FLAG_KEY_ADAPTIVE_ICON_MASK_PATH,
+                "M50 0C77.6 0 100 22.4 100 50C100 77.6 77.6 100 50 100C22.4 100 0 77.6 0 50C0 " +
+                        "22.4 22.4 0 50 0Z");
+        params.setFlag(RenderParamsFlags.FLAG_KEY_WALLPAPER_PATH,
+                "/com/android/layoutlib/testdata/wallpaper2.webp");
+        params.setFlag(RenderParamsFlags.FLAG_KEY_USE_THEMED_ICON, true);
+        params.setFlag(RenderParamsFlags.FLAG_KEY_FORCE_MONOCHROME_ICON, false);
+        renderAndVerify(params, "adaptive_icon_circle.png");
+    }
+
     @Test
     public void testHtmlText() throws ClassNotFoundException {
         final String layout = """
@@ -2313,4 +2405,36 @@ public class RenderTests extends RenderTestBase {
 
         renderAndVerify(params, "hole_cutout_landscape.png", TimeUnit.SECONDS.toNanos(2));
     }
+
+    @Test
+    public void testHyphenation() throws ClassNotFoundException {
+        final String layout = """
+                <FrameLayout xmlns:android="http://schemas.android.com/apk/res/android"
+                              android:layout_width="match_parent"
+                              android:layout_height="match_parent">
+
+                    <TextView
+                            android:layout_width="wrap_content"
+                            android:layout_height="wrap_content"
+                            android:hyphenationFrequency="full"
+                            android:breakStrategy="balanced"
+                            android:text="A material metaphor is the unifying theory of a rationalized space hyperextended hyperextended hyperextended and a system of motion."
+                            android:textSize="20sp" />
+                </FrameLayout>""";
+        LayoutPullParser parser = LayoutPullParser.createFromString(layout);
+        // Create LayoutLibCallback.
+        LayoutLibTestCallback layoutLibCallback =
+                new LayoutLibTestCallback(getLogger(), mDefaultClassLoader);
+        layoutLibCallback.initResources();
+
+        SessionParams params = getSessionParamsBuilder()
+                .setParser(parser)
+                .setCallback(layoutLibCallback)
+                .setTheme("Theme.Material.Light.NoActionBar.Fullscreen", false)
+                .setRenderingMode(RenderingMode.V_SCROLL)
+                .disableDecoration()
+                .build();
+
+        renderAndVerify(params, "hyphenation.png", TimeUnit.SECONDS.toNanos(2));
+    }
 }
diff --git a/common/src/com/android/tools/layoutlib/create/NativeConfig.java b/common/src/com/android/tools/layoutlib/create/NativeConfig.java
index 099adbaaf1..9b3d34c9ae 100644
--- a/common/src/com/android/tools/layoutlib/create/NativeConfig.java
+++ b/common/src/com/android/tools/layoutlib/create/NativeConfig.java
@@ -164,8 +164,8 @@ public class NativeConfig {
             "android.content.res.StringBlock",
             "android.content.res.XmlBlock",
             "android.os.SystemProperties",
-            "android.os.Trace",
             "android.text.AndroidCharacter",
+            "android.text.Hyphenator",
             "android.util.EventLog",
             "android.util.Log",
             "android.view.MotionEvent",
diff --git a/create/create.iml b/create/create.iml
index 5c7d27ade6..8a0ec1c6a5 100644
--- a/create/create.iml
+++ b/create/create.iml
@@ -64,7 +64,7 @@
     <orderEntry type="module-library" scope="RUNTIME">
       <library>
         <CLASSES>
-          <root url="jar://$MODULE_DIR$/../../../out/soong/.intermediates/prebuilts/misc/common/atf/atf-prebuilt-jars-557133692/linux_glibc_common/combined/atf-prebuilt-jars-557133692.jar!/" />
+          <root url="jar://$MODULE_DIR$/../../../out/soong/.intermediates/prebuilts/misc/common/atf/atf-prebuilt-jars-557133692/linux_glibc_common/local-combined/atf-prebuilt-jars-557133692.jar!/" />
         </CLASSES>
         <JAVADOC />
         <SOURCES />
@@ -80,5 +80,32 @@
         <SOURCES />
       </library>
     </orderEntry>
+    <orderEntry type="module-library" scope="RUNTIME">
+      <library>
+        <CLASSES>
+          <root url="jar://$MODULE_DIR$/../../../out/soong/.intermediates/external/icu/icu4j/icu4j-icudata-jarjar/linux_glibc_common/jarjar/icu4j-icudata-jarjar.jar!/" />
+        </CLASSES>
+        <JAVADOC />
+        <SOURCES />
+      </library>
+    </orderEntry>
+    <orderEntry type="module-library" scope="RUNTIME">
+      <library>
+        <CLASSES>
+          <root url="jar://$MODULE_DIR$/../../../out/soong/.intermediates/external/icu/icu4j/icu4j-icutzdata-jarjar/linux_glibc_common/jarjar/icu4j-icutzdata-jarjar.jar!/" />
+        </CLASSES>
+        <JAVADOC />
+        <SOURCES />
+      </library>
+    </orderEntry>
+    <orderEntry type="module-library">
+      <library>
+        <CLASSES>
+          <root url="jar://$MODULE_DIR$/../../../out/soong/.intermediates/frameworks/libs/systemui/iconloaderlib/iconloader_base/android_common/withres/iconloader_base.jar!/" />
+        </CLASSES>
+        <JAVADOC />
+        <SOURCES />
+      </library>
+    </orderEntry>
   </component>
 </module>
diff --git a/create/src/com/android/tools/layoutlib/create/AsmAnalyzer.java b/create/src/com/android/tools/layoutlib/create/AsmAnalyzer.java
index 258fec70c2..403cc68276 100644
--- a/create/src/com/android/tools/layoutlib/create/AsmAnalyzer.java
+++ b/create/src/com/android/tools/layoutlib/create/AsmAnalyzer.java
@@ -96,6 +96,8 @@ public class AsmAnalyzer {
     private final List<String> mOsSourceJar;
     /** Keep all classes that derive from these one (these included). */
     private final String[] mDeriveFrom;
+    /** Glob patterns of classes to not consider when deriving classes from {@link #mDeriveFrom}. */
+    private final String[] mExcludeFromDerivedGlobs;
     /** Glob patterns of classes to keep, e.g. "com.foo.*" */
     private final String[] mIncludeGlobs;
     /** Glob patterns of classes to exclude.*/
@@ -112,16 +114,21 @@ public class AsmAnalyzer {
      * @param log The log output.
      * @param osJarPath The input source JARs to parse.
      * @param deriveFrom Keep all classes that derive from these one (these included).
+     * @param excludeFromDerivedGlobs Glob patterns of classes to not consider when deriving
+     *        classes.
      * @param includeGlobs Glob patterns of classes to keep, e.g. "com.foo.*"
-*        ("*" does not matches dots whilst "**" does, "." and "$" are interpreted as-is)
+     *        ("*" does not matches dots whilst "**" does, "." and "$" are interpreted as-is)
      * @param includeFileGlobs Glob patterns of files which are kept as is. This is only for files
      * @param methodReplacers names of method calls that need to be rewritten
      */
-    public AsmAnalyzer(Log log, List<String> osJarPath, String[] deriveFrom, String[] includeGlobs,
-            String[] excludedGlobs, String[] includeFileGlobs, MethodReplacer[] methodReplacers) {
+    public AsmAnalyzer(Log log, List<String> osJarPath, String[] deriveFrom,
+            String[] excludeFromDerivedGlobs, String[] includeGlobs, String[] excludedGlobs,
+            String[] includeFileGlobs, MethodReplacer[] methodReplacers) {
         mLog = log;
         mOsSourceJar = osJarPath != null ? osJarPath : new ArrayList<>();
         mDeriveFrom = deriveFrom != null ? deriveFrom : new String[0];
+        mExcludeFromDerivedGlobs = excludeFromDerivedGlobs != null ? excludeFromDerivedGlobs :
+                new String[0];
         mIncludeGlobs = includeGlobs != null ? includeGlobs : new String[0];
         mExcludedGlobs = excludedGlobs != null ? excludedGlobs : new String[0];
         mIncludeFileGlobs = includeFileGlobs != null ? includeFileGlobs : new String[0];
@@ -149,7 +156,8 @@ public class AsmAnalyzer {
 
 
         Map<String, ClassReader> found = new HashMap<>();
-        findIncludes(mLog, includePatterns, mDeriveFrom, zipClasses, entry -> {
+        findIncludes(mLog, includePatterns, mDeriveFrom, mExcludeFromDerivedGlobs, zipClasses,
+                entry -> {
             if (!matchesAny(entry.getKey(), excludePatterns)) {
                 found.put(entry.getKey(), entry.getValue());
             }
@@ -273,7 +281,8 @@ public class AsmAnalyzer {
      * This updates the in_out_found map.
      */
     private static void findIncludes(@NotNull Log log, @NotNull Pattern[] includePatterns,
-            @NotNull String[] deriveFrom, @NotNull Map<String, ClassReader> zipClasses,
+            @NotNull String[] deriveFrom, @NotNull String[] excludeFromDerivedGlobs,
+            @NotNull Map<String, ClassReader> zipClasses,
             @NotNull Consumer<Entry<String, ClassReader>> newInclude) throws FileNotFoundException {
         TreeMap<String, ClassReader> found = new TreeMap<>();
 
@@ -284,7 +293,7 @@ public class AsmAnalyzer {
                 .forEach(entry -> found.put(entry.getKey(), entry.getValue()));
 
         for (String entry : deriveFrom) {
-            findClassesDerivingFrom(entry, zipClasses, found);
+            findClassesDerivingFrom(entry, zipClasses, excludeFromDerivedGlobs, found);
         }
 
         found.entrySet().forEach(newInclude);
@@ -332,12 +341,16 @@ public class AsmAnalyzer {
      * Inserts the super class and all the class objects found in the map.
      */
     static void findClassesDerivingFrom(String super_name, Map<String, ClassReader> zipClasses,
-            Map<String, ClassReader> inOutFound) throws FileNotFoundException {
+            String[] excludeFromDerivedGlobs, Map<String, ClassReader> inOutFound)
+            throws FileNotFoundException {
         findClass(super_name, zipClasses, inOutFound);
 
+        Pattern[] excludeFromDerivedPatterns = Arrays.stream(excludeFromDerivedGlobs).parallel()
+                .map(AsmAnalyzer::getPatternFromGlob)
+                .toArray(Pattern[]::new);
         for (Entry<String, ClassReader> entry : zipClasses.entrySet()) {
             String className = entry.getKey();
-            if (super_name.equals(className)) {
+            if (super_name.equals(className) || matchesAny(className, excludeFromDerivedPatterns)) {
                 continue;
             }
             ClassReader classReader = entry.getValue();
diff --git a/create/src/com/android/tools/layoutlib/create/CreateInfo.java b/create/src/com/android/tools/layoutlib/create/CreateInfo.java
index fcb4ac8371..75c53c000e 100644
--- a/create/src/com/android/tools/layoutlib/create/CreateInfo.java
+++ b/create/src/com/android/tools/layoutlib/create/CreateInfo.java
@@ -243,6 +243,7 @@ public final class CreateInfo implements ICreateInfo {
         "android.graphics.RegionIterator",
         "android.graphics.RenderEffect",
         "android.graphics.RenderNode",
+        "android.graphics.RuntimeColorFilter",
         "android.graphics.RuntimeShader",
         "android.graphics.Shader",
         "android.graphics.SumPathEffect",
@@ -268,8 +269,8 @@ public final class CreateInfo implements ICreateInfo {
         "android.graphics.text.MeasuredText$Builder",
         "android.graphics.text.TextRunShaper",
         "android.os.SystemProperties",
-        "android.os.Trace",
         "android.text.AndroidCharacter",
+        "android.text.Hyphenator",
         "android.util.EventLog",
         "android.util.Log",
         "android.util.PathParser",
diff --git a/create/src/com/android/tools/layoutlib/create/Main.java b/create/src/com/android/tools/layoutlib/create/Main.java
index 5f67ff44d3..66f8279d44 100644
--- a/create/src/com/android/tools/layoutlib/create/Main.java
+++ b/create/src/com/android/tools/layoutlib/create/Main.java
@@ -104,6 +104,9 @@ public class Main {
                         "android.app.Fragment",
                         "android.view.View",
                     },
+                    new String[] {                          // exclude from derived
+                        "androidx.**",
+                    },
                     new String[] {                          // include classes
                         "android.*", // for android.R
                         "android.annotation.NonNull",       // annotations
@@ -117,6 +120,7 @@ public class Main {
                         "android.graphics.*",
                         "android.graphics.drawable.**",
                         "android.icu.**",                   // needed by LayoutLib
+                        "android.media.MediaCryptoException",    // needed by ExoPlayer
                         "android.os.*",  // for android.os.Handler
                         "android.os.ext.*", // for android.os.ext.SdkExtensions, needed by Compose
                         "android.pim.*", // for datepicker
@@ -133,6 +137,7 @@ public class Main {
                         "com.android.internal.util.*",
                         "com.android.internal.view.menu.ActionMenu",
                         "com.android.internal.widget.*",
+                        "com.android.launcher3.icons.MonochromeIconFactory",
                         "com.android.systemui.monet.**",     // needed for dynamic theming
                         "com.google.android.apps.common.testing.accessibility.**",
                         "com.google.android.libraries.accessibility.**",
diff --git a/create/tests/src/com/android/tools/layoutlib/create/AsmAnalyzerTest.java b/create/tests/src/com/android/tools/layoutlib/create/AsmAnalyzerTest.java
index d0943d5cad..9c899fa009 100644
--- a/create/tests/src/com/android/tools/layoutlib/create/AsmAnalyzerTest.java
+++ b/create/tests/src/com/android/tools/layoutlib/create/AsmAnalyzerTest.java
@@ -55,7 +55,7 @@ public class AsmAnalyzerTest {
 
     private static AsmAnalyzer getDefaultAnalyzer() {
         MockLog log = new MockLog();
-        return new AsmAnalyzer(log, MOCK_ANDROID_JAR, null ,
+        return new AsmAnalyzer(log, MOCK_ANDROID_JAR, null , null,
                 null /* includeGlobs */, DEFAULT_EXCLUDES, DEFAULT_INCLUDE_FILES,
                 new MethodReplacer[] {});
     }
@@ -122,7 +122,7 @@ public class AsmAnalyzerTest {
 
     @Test
     public void testInclude() throws IOException {
-        AsmAnalyzer analyzer = new AsmAnalyzer(new MockLog(), MOCK_ANDROID_JAR, null,
+        AsmAnalyzer analyzer = new AsmAnalyzer(new MockLog(), MOCK_ANDROID_JAR, null, null,
                 new String[] {
                     "mock_android.util.EmptyArray", // Single class select
                     "mock_android.fake.**", // Multi package select
@@ -161,13 +161,12 @@ public class AsmAnalyzerTest {
         getDefaultAnalyzer().parseZip(MOCK_ANDROID_JAR, zipClasses, filesFound);
         TreeMap<String, ClassReader> found = new TreeMap<>();
 
-        AsmAnalyzer.findClassesDerivingFrom("mock_android.view.View", zipClasses, found);
+        AsmAnalyzer.findClassesDerivingFrom("mock_android.view.View", zipClasses,
+                new String[] { "mock_android.widget.*" }, found);
 
         assertArrayEquals(new String[] {
                 "mock_android.view.View",
                 "mock_android.view.ViewGroup",
-                "mock_android.widget.LinearLayout",
-                "mock_android.widget.TableLayout",
             },
             found.keySet().toArray());
 
diff --git a/create/tests/src/com/android/tools/layoutlib/create/AsmGeneratorTest.java b/create/tests/src/com/android/tools/layoutlib/create/AsmGeneratorTest.java
index 334bcd2aa1..8b13a98ef0 100644
--- a/create/tests/src/com/android/tools/layoutlib/create/AsmGeneratorTest.java
+++ b/create/tests/src/com/android/tools/layoutlib/create/AsmGeneratorTest.java
@@ -107,6 +107,7 @@ public class AsmGeneratorTest {
 
         AsmAnalyzer aa = new AsmAnalyzer(mLog, mOsJarPath,
                 null,                 // derived from
+                null,                 // exclude from derived
                 new String[] {        // include classes
                     "**"
                 },
@@ -150,6 +151,7 @@ public class AsmGeneratorTest {
 
         AsmAnalyzer aa = new AsmAnalyzer(mLog, mOsJarPath,
                 null,                 // derived from
+                null,                 // exclude from derived
                 new String[] {        // include classes
                     "**"
                 },
@@ -198,6 +200,7 @@ public class AsmGeneratorTest {
 
         AsmAnalyzer aa = new AsmAnalyzer(mLog, mOsJarPath,
                 null,                 // derived from
+                null,                 // exclude from derived
                 new String[] {        // include classes
                         "**"
                 },
@@ -234,6 +237,7 @@ public class AsmGeneratorTest {
         AsmGenerator agen = new AsmGenerator(mLog, ci);
         AsmAnalyzer aa = new AsmAnalyzer(mLog, mOsJarPath,
                 null,                 // derived from
+                null,                 // exclude from derived
                 new String[] {        // include classes
                         "**"
                 },
@@ -279,6 +283,7 @@ public class AsmGeneratorTest {
         AsmGenerator agen = new AsmGenerator(mLog, ci);
         AsmAnalyzer aa = new AsmAnalyzer(mLog, mOsJarPath,
                 null,                 // derived from
+                null,                 // exclude from derived
                 new String[] {        // include classes
                         "**"
                 },
@@ -350,6 +355,7 @@ public class AsmGeneratorTest {
         AsmGenerator agen = new AsmGenerator(mLog, ci);
         AsmAnalyzer aa = new AsmAnalyzer(mLog, mOsJarPath,
                 null,                 // derived from
+                null,                 // exclude from derived
                 new String[] {        // include classes
                         "**"
                 },
diff --git a/create/tests/src/com/android/tools/layoutlib/create/PromoteClassClassAdapterTest.java b/create/tests/src/com/android/tools/layoutlib/create/PromoteClassClassAdapterTest.java
index 3655ec23b7..abc650a5c8 100644
--- a/create/tests/src/com/android/tools/layoutlib/create/PromoteClassClassAdapterTest.java
+++ b/create/tests/src/com/android/tools/layoutlib/create/PromoteClassClassAdapterTest.java
@@ -155,7 +155,7 @@ public class PromoteClassClassAdapterTest {
         PromoteClassClassAdapter adapter = new PromoteClassClassAdapter(log, Set.of(
                 PackageProtectedClass.class.getName()));
         reader.accept(adapter, 0);
-        assertTrue(log.mLog.contains("[visit] - version=61, access=[public], " +
+        assertTrue(log.mLog.contains("[visit] - version=65, access=[public], " +
                 "name=com/android/tools/layoutlib/create/PackageProtectedClass, signature=null, " +
                 "superName=java/lang/Object, interfaces=[]"));
 
diff --git a/jni/LayoutlibLoader.cpp b/jni/LayoutlibLoader.cpp
index 4a5f925535..8993ef0c1b 100644
--- a/jni/LayoutlibLoader.cpp
+++ b/jni/LayoutlibLoader.cpp
@@ -75,7 +75,7 @@ static void init_keyboard(const vector<string>& keyboardPaths) {
     int keyboardId = 1;
 
     for (const string& path : keyboardPaths) {
-        base::Result<std::shared_ptr<KeyCharacterMap>> charMap =
+        base::Result<std::unique_ptr<KeyCharacterMap>> charMap =
                 KeyCharacterMap::load(path, KeyCharacterMap::Format::BASE);
 
         InputDeviceInfo info = InputDeviceInfo();
@@ -83,7 +83,7 @@ static void init_keyboard(const vector<string>& keyboardPaths) {
                         "keyboard " + std::to_string(keyboardId), true, false,
                         ui::LogicalDisplayId::DEFAULT);
         info.setKeyboardType(AINPUT_KEYBOARD_TYPE_ALPHABETIC);
-        info.setKeyCharacterMap(*charMap);
+        info.setKeyCharacterMap(std::move(*charMap));
 
         jobject inputDeviceObj = android_view_InputDevice_create(env, info);
         if (inputDeviceObj) {
diff --git a/jni/android_view_LayoutlibRenderer.cpp b/jni/android_view_LayoutlibRenderer.cpp
index ed701493fb..50ddb26107 100644
--- a/jni/android_view_LayoutlibRenderer.cpp
+++ b/jni/android_view_LayoutlibRenderer.cpp
@@ -87,6 +87,7 @@ static jobject android_view_LayoutlibRenderer_createBuffer(JNIEnv* env, jobject
     auto* bufferItem = new BufferItem();
     bufferConsumer->acquireBuffer(bufferItem, 0);
     sp<GraphicBuffer> buffer = bufferItem->mGraphicBuffer;
+    delete bufferItem;
 
     int bytesPerPixel = 4;
     uint32_t dataSize = buffer->getStride() * buffer->getHeight() * bytesPerPixel;
diff --git a/jni/darwin/layoutlib_jni_export.exp b/jni/darwin/layoutlib_jni_export.exp
new file mode 100644
index 0000000000..49998295b7
--- /dev/null
+++ b/jni/darwin/layoutlib_jni_export.exp
@@ -0,0 +1,19 @@
+#
+# Copyright (C) 2024 The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      http://www.apache.org/licenses/LICENSE-2.0
+#
+#  Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+#
+
+# symbols needed for JNI operations
+_JNI_OnLoad
+_JNI_OnUnload
diff --git a/jni/linux/layoutlib_jni_export.txt b/jni/linux/layoutlib_jni_export.txt
new file mode 100644
index 0000000000..3d21e4aefe
--- /dev/null
+++ b/jni/linux/layoutlib_jni_export.txt
@@ -0,0 +1,24 @@
+#
+# Copyright (C) 2024 The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      http://www.apache.org/licenses/LICENSE-2.0
+#
+#  Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+#
+
+{
+  global:
+    # symbols needed for JNI operations
+    JNI_OnLoad;
+    JNI_OnUnload;
+  local:
+    *;
+};
\ No newline at end of file
```

