```diff
diff --git a/bridge/src/android/content/res/Resources_Delegate.java b/bridge/src/android/content/res/Resources_Delegate.java
index e45c81bfb0..0d41393f98 100644
--- a/bridge/src/android/content/res/Resources_Delegate.java
+++ b/bridge/src/android/content/res/Resources_Delegate.java
@@ -89,8 +89,6 @@ public class Resources_Delegate {
                 "Resources_Delegate.initSystem called twice before disposeSystem was called";
         Resources resources = new Resources(Resources_Delegate.class.getClassLoader());
         resources.setImpl(new ResourcesImpl(assets, metrics, config, new DisplayAdjustments()));
-        resources.getConfiguration().windowConfiguration.setMaxBounds(0, 0, metrics.widthPixels,
-                metrics.heightPixels);
         sContexts.put(resources, Objects.requireNonNull(context));
         sLayoutlibCallbacks.put(resources, Objects.requireNonNull(layoutlibCallback));
         return Resources.mSystem = resources;
diff --git a/bridge/src/android/hardware/display/DisplayManagerGlobal.java b/bridge/src/android/hardware/display/DisplayManagerGlobal.java
index 5816b11bd4..fef89ed691 100644
--- a/bridge/src/android/hardware/display/DisplayManagerGlobal.java
+++ b/bridge/src/android/hardware/display/DisplayManagerGlobal.java
@@ -54,7 +54,8 @@ public final class DisplayManagerGlobal {
     private static DisplayManagerGlobal sInstance;
 
     @VisibleForTesting
-    public DisplayManagerGlobal(IDisplayManager dm) {}
+    public DisplayManagerGlobal(IDisplayManager dm) {
+    }
 
     public static DisplayManagerGlobal getInstance() {
         synchronized (DisplayManagerGlobal.class) {
@@ -94,37 +95,50 @@ public final class DisplayManagerGlobal {
             boolean isEventFilterExplicit) {}
 
     public void registerDisplayListener(@NonNull DisplayListener listener,
-            @Nullable Handler handler, long internalEventFlagsMask, String packageName) {}
+            @Nullable Handler handler, long internalEventFlagsMask, String packageName) {
+    }
 
     public void registerDisplayListener(@NonNull DisplayListener listener,
             @NonNull Executor executor, long internalEventFlagsMask, String packageName,
-            boolean isEventFilterExplicit) {}
+            boolean isEventFilterExplicit) {
+    }
 
-    public void unregisterDisplayListener(DisplayListener listener) {}
+    public void unregisterDisplayListener(DisplayListener listener) {
+    }
 
-    public void startWifiDisplayScan() {}
+    public void startWifiDisplayScan() {
+    }
 
-    public void stopWifiDisplayScan() {}
+    public void stopWifiDisplayScan() {
+    }
 
-    public void connectWifiDisplay(String deviceAddress) {}
+    public void connectWifiDisplay(String deviceAddress) {
+    }
 
-    public void pauseWifiDisplay() {}
+    public void pauseWifiDisplay() {
+    }
 
-    public void resumeWifiDisplay() {}
+    public void resumeWifiDisplay() {
+    }
 
-    public void disconnectWifiDisplay() {}
+    public void disconnectWifiDisplay() {
+    }
 
-    public void renameWifiDisplay(String deviceAddress, String alias) {}
+    public void renameWifiDisplay(String deviceAddress, String alias) {
+    }
 
-    public void forgetWifiDisplay(String deviceAddress) {}
+    public void forgetWifiDisplay(String deviceAddress) {
+    }
 
     public WifiDisplayStatus getWifiDisplayStatus() {
         return null;
     }
 
-    public void setUserDisabledHdrTypes(int[] userDisabledHdrTypes) {}
+    public void setUserDisabledHdrTypes(int[] userDisabledHdrTypes) {
+    }
 
-    public void setAreUserDisabledHdrTypesAllowed(boolean areUserDisabledHdrTypesAllowed) {}
+    public void setAreUserDisabledHdrTypesAllowed(boolean areUserDisabledHdrTypesAllowed) {
+    }
 
     public boolean areUserDisabledHdrTypesAllowed() {
         return false;
@@ -134,7 +148,8 @@ public final class DisplayManagerGlobal {
         return null;
     }
 
-    public void requestColorMode(int displayId, int colorMode) {}
+    public void requestColorMode(int displayId, int colorMode) {
+    }
 
     public VirtualDisplay createVirtualDisplay(@NonNull Context context, MediaProjection projection,
             @NonNull VirtualDisplayConfig virtualDisplayConfig, VirtualDisplay.Callback callback,
@@ -142,14 +157,18 @@ public final class DisplayManagerGlobal {
         return null;
     }
 
-    public void setVirtualDisplaySurface(IVirtualDisplayCallback token, Surface surface) {}
+    public void setVirtualDisplaySurface(IVirtualDisplayCallback token, Surface surface) {
+    }
 
-    public void resizeVirtualDisplay(IVirtualDisplayCallback token,
-            int width, int height, int densityDpi) {}
+    public void resizeVirtualDisplay(IVirtualDisplayCallback token, int width, int height,
+            int densityDpi) {
+    }
 
-    public void releaseVirtualDisplay(IVirtualDisplayCallback token) {}
+    public void releaseVirtualDisplay(IVirtualDisplayCallback token) {
+    }
 
-    void setVirtualDisplayState(IVirtualDisplayCallback token, boolean isOn) {}
+    void setVirtualDisplayState(IVirtualDisplayCallback token, boolean isOn) {
+    }
 
     public Point getStableDisplaySize() {
         return null;
@@ -167,10 +186,13 @@ public final class DisplayManagerGlobal {
         return null;
     }
 
-    public OverlayProperties getOverlaySupport() { return null; }
+    public OverlayProperties getOverlaySupport() {
+        return null;
+    }
 
     public void setBrightnessConfigurationForUser(BrightnessConfiguration c, int userId,
-            String packageName) {}
+            String packageName) {
+    }
 
     public BrightnessConfiguration getBrightnessConfigurationForUser(int userId) {
         return null;
@@ -184,15 +206,18 @@ public final class DisplayManagerGlobal {
         return false;
     }
 
-    public void setTemporaryBrightness(int displayId, float brightness) {}
+    public void setTemporaryBrightness(int displayId, float brightness) {
+    }
 
-    public void setBrightness(int displayId, float brightness) {}
+    public void setBrightness(int displayId, float brightness) {
+    }
 
     public float getBrightness(int displayId) {
         return 0.0f;
     }
 
-    public void setTemporaryAutoBrightnessAdjustment(float adjustment) {}
+    public void setTemporaryAutoBrightnessAdjustment(float adjustment) {
+    }
 
     public Pair<float[], float[]> getMinimumBrightnessCurve() {
         return null;
@@ -202,22 +227,29 @@ public final class DisplayManagerGlobal {
         return null;
     }
 
-    public void setShouldAlwaysRespectAppRequestedMode(boolean enabled) {}
+    public void setShouldAlwaysRespectAppRequestedMode(boolean enabled) {
+    }
 
     public boolean shouldAlwaysRespectAppRequestedMode() {
         return false;
     }
 
-    public void setRefreshRateSwitchingType(int newValue) {}
+    public void setRefreshRateSwitchingType(int newValue) {
+    }
 
     public int getRefreshRateSwitchingType() {
         return 0;
     }
 
-    public static final String CACHE_KEY_DISPLAY_INFO_PROPERTY =
-            "cache_key.display_info";
+    public static final String CACHE_KEY_DISPLAY_INFO_PROPERTY = "cache_key.display_info";
 
-    public static void invalidateLocalDisplayInfoCaches() {}
+    public static void invalidateLocalDisplayInfoCaches() {
+    }
+
+    public void disableLocalDisplayInfoCaches() {
+    }
 
-    public void disableLocalDisplayInfoCaches() {}
+    public static long mapFiltersToInternalEventFlag(long val1, long val2) {
+        return val1;
+    }
 }
diff --git a/bridge/src/android/media/AudioManager.java b/bridge/src/android/media/AudioManager.java
index a64547cf3c..bcea6bd116 100644
--- a/bridge/src/android/media/AudioManager.java
+++ b/bridge/src/android/media/AudioManager.java
@@ -27,6 +27,7 @@ import android.os.Handler;
 import android.view.KeyEvent;
 
 import java.io.IOException;
+import java.util.Collections;
 import java.util.List;
 import java.util.Map;
 import java.util.concurrent.Executor;
@@ -551,6 +552,10 @@ public class AudioManager {
 
     public void removeOnCommunicationDeviceChangedListener(AudioManager.OnCommunicationDeviceChangedListener listener) { }
 
+    public List<AudioDeviceInfo> getAudioDevicesForAttributes(AudioAttributes attributes) {
+        return Collections.emptyList();
+    }
+
     public interface OnCommunicationDeviceChangedListener {
         void onCommunicationDeviceChanged(AudioDeviceInfo var1);
     }
diff --git a/bridge/src/android/os/Trace_Delegate.java b/bridge/src/android/os/Trace_Delegate.java
new file mode 100644
index 0000000000..479cfefc53
--- /dev/null
+++ b/bridge/src/android/os/Trace_Delegate.java
@@ -0,0 +1,91 @@
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
+package android.os;
+
+import com.android.tools.layoutlib.annotations.LayoutlibDelegate;
+
+import android.annotation.NonNull;
+
+
+public class Trace_Delegate {
+    @LayoutlibDelegate
+    public static boolean isTagEnabled(long traceTag) {
+        return true;
+    }
+
+    @LayoutlibDelegate
+    public static void traceCounter(long traceTag, @NonNull String counterName, int counterValue) {
+    }
+
+    @LayoutlibDelegate
+    public static void setAppTracingAllowed(boolean allowed) {
+    }
+
+    @LayoutlibDelegate
+    public static void setTracingEnabled(boolean enabled, int debugFlags) {
+    }
+
+    @LayoutlibDelegate
+    public static void traceBegin(long traceTag, @NonNull String methodName) {
+    }
+
+    @LayoutlibDelegate
+    public static void traceEnd(long traceTag) {
+    }
+
+    @LayoutlibDelegate
+    public static void asyncTraceBegin(long traceTag, @NonNull String methodName, int cookie) {
+    }
+
+    @LayoutlibDelegate
+    public static void asyncTraceEnd(long traceTag, @NonNull String methodName, int cookie) {
+    }
+
+
+    @LayoutlibDelegate
+    public static void asyncTraceForTrackBegin(long traceTag, @NonNull String trackName,
+            @NonNull String methodName, int cookie) {
+    }
+
+    @LayoutlibDelegate
+    public static void asyncTraceForTrackBegin(String trackName, @NonNull String methodName,
+            int cookie) {
+    }
+
+    @LayoutlibDelegate
+    public static void asyncTraceForTrackEnd(long traceTag, @NonNull String trackName, int cookie) {
+    }
+
+    @LayoutlibDelegate
+    public static void asyncTraceForTrackEnd(@NonNull String trackName, int cookie) {
+    }
+
+    @LayoutlibDelegate
+    public static void instant(long traceTag, String methodName) {
+
+    }
+
+    @LayoutlibDelegate
+    public static void instantForTrack(long traceTag, String trackName, String methodName) {
+    }
+
+    @LayoutlibDelegate
+    public static boolean isEnabled() {
+        return true;
+    }
+}
+
diff --git a/bridge/src/android/provider/Settings_Global_Delegate.java b/bridge/src/android/provider/Settings_Global_Delegate.java
new file mode 100644
index 0000000000..9b3369c217
--- /dev/null
+++ b/bridge/src/android/provider/Settings_Global_Delegate.java
@@ -0,0 +1,59 @@
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
+package android.provider;
+
+import com.android.layoutlib.bridge.android.BridgeContentResolver;
+import com.android.tools.layoutlib.annotations.LayoutlibDelegate;
+
+import android.annotation.NonNull;
+import android.annotation.Nullable;
+import android.annotation.UserIdInt;
+import android.content.ContentResolver;
+
+import java.util.Map;
+
+public class Settings_Global_Delegate {
+    @LayoutlibDelegate
+    public static String getStringForUser(ContentResolver cr, String name, int userHandle) {
+        Map<String, String> settingsUserMap = getSettingsMap(cr);
+        return settingsUserMap.get(name);
+    }
+
+    @LayoutlibDelegate
+    public static boolean putStringForUser(ContentResolver resolver, String name, String value,
+            int userHandle) {
+        Map<String, String> settingsUserMap = getSettingsMap(resolver);
+        settingsUserMap.put(name, value);
+        return true;
+
+    }
+
+    @LayoutlibDelegate
+    public static boolean putStringForUser(@NonNull ContentResolver resolver, @NonNull String name,
+            @Nullable String value, @Nullable String tag, boolean makeDefault,
+            @UserIdInt int userHandle, boolean overrideableByRestore) {
+        Map<String, String> settingsUserMap = getSettingsMap(resolver);
+        settingsUserMap.put(name, value);
+        return true;
+    }
+
+    static Map<String, String> getSettingsMap(ContentResolver cr) {
+        BridgeContentResolver bridgeContentResolver = (BridgeContentResolver) cr;
+        return bridgeContentResolver.settingsUserMap;
+    }
+}
+
diff --git a/bridge/src/android/provider/Settings_Secure_Delegate.java b/bridge/src/android/provider/Settings_Secure_Delegate.java
new file mode 100644
index 0000000000..153a7b134f
--- /dev/null
+++ b/bridge/src/android/provider/Settings_Secure_Delegate.java
@@ -0,0 +1,59 @@
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
+package android.provider;
+
+import com.android.layoutlib.bridge.android.BridgeContentResolver;
+import com.android.tools.layoutlib.annotations.LayoutlibDelegate;
+
+import android.annotation.NonNull;
+import android.annotation.Nullable;
+import android.annotation.UserIdInt;
+import android.content.ContentResolver;
+
+import java.util.Map;
+
+public class Settings_Secure_Delegate {
+    @LayoutlibDelegate
+    public static String getStringForUser(ContentResolver cr, String name, int userHandle) {
+        Map<String, String> settingsUserMap = getSettingsMap(cr);
+        return settingsUserMap.get(name);
+    }
+
+    @LayoutlibDelegate
+    public static boolean putStringForUser(ContentResolver resolver, String name, String value,
+            int userHandle) {
+        Map<String, String> settingsUserMap = getSettingsMap(resolver);
+        settingsUserMap.put(name, value);
+        return true;
+
+    }
+
+    @LayoutlibDelegate
+    public static boolean putStringForUser(@NonNull ContentResolver resolver, @NonNull String name,
+            @Nullable String value, @Nullable String tag, boolean makeDefault,
+            @UserIdInt int userHandle, boolean overrideableByRestore) {
+        Map<String, String> settingsUserMap = getSettingsMap(resolver);
+        settingsUserMap.put(name, value);
+        return true;
+    }
+
+    static Map<String, String> getSettingsMap(ContentResolver cr) {
+        BridgeContentResolver bridgeContentResolver = (BridgeContentResolver) cr;
+        return bridgeContentResolver.settingsUserMap;
+    }
+
+}
diff --git a/bridge/src/android/provider/Settings_System_Delegate.java b/bridge/src/android/provider/Settings_System_Delegate.java
new file mode 100644
index 0000000000..ce92849cdf
--- /dev/null
+++ b/bridge/src/android/provider/Settings_System_Delegate.java
@@ -0,0 +1,64 @@
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
+package android.provider;
+
+import com.android.layoutlib.bridge.android.BridgeContentResolver;
+import com.android.tools.layoutlib.annotations.LayoutlibDelegate;
+
+import android.content.ContentResolver;
+
+import java.util.Map;
+
+public class Settings_System_Delegate {
+    @LayoutlibDelegate
+    public static String getStringForUser(ContentResolver cr, String name, int userHandle) {
+        Map<String, String> settingsUserMap = getSettingsMap(cr);
+        return settingsUserMap.get(name);
+    }
+
+    @LayoutlibDelegate
+    public static boolean putStringForUser(ContentResolver resolver, String name, String value,
+            int userHandle) {
+        Map<String, String> settingsUserMap = getSettingsMap(resolver);
+        settingsUserMap.put(name, value);
+        return true;
+
+
+    }
+
+    @LayoutlibDelegate
+    public static boolean putStringForUser(ContentResolver resolver, String name, String value,
+            int userHandle, boolean overrideableByRestore) {
+        Map<String, String> settingsUserMap = getSettingsMap(resolver);
+        settingsUserMap.put(name, value);
+        return true;
+
+    }
+
+    @LayoutlibDelegate
+    public static boolean putStringForUser(ContentResolver resolver, String name, String value,
+            String tag, boolean makeDefault, int userHandle, boolean overrideableByRestore) {
+        Map<String, String> settingsUserMap = getSettingsMap(resolver);
+        settingsUserMap.put(name, value);
+        return true;
+    }
+
+    static Map<String, String> getSettingsMap(ContentResolver cr) {
+        BridgeContentResolver bridgeContentResolver = (BridgeContentResolver) cr;
+        return bridgeContentResolver.settingsUserMap;
+    }
+}
diff --git a/bridge/src/android/view/ViewRootImpl_Delegate.java b/bridge/src/android/view/ViewRootImpl_Delegate.java
index d9e18dde83..d128dd127e 100644
--- a/bridge/src/android/view/ViewRootImpl_Delegate.java
+++ b/bridge/src/android/view/ViewRootImpl_Delegate.java
@@ -29,7 +29,7 @@ public class ViewRootImpl_Delegate {
 
     @LayoutlibDelegate
     /*package*/ static boolean performHapticFeedback(ViewRootImpl thisViewRoot, int effectId,
-            int flags, int privFlags) {
+            int usage, int flags, int privFlags) {
         return false;
     }
 }
diff --git a/bridge/src/android/view/WindowManagerImpl.java b/bridge/src/android/view/WindowManagerImpl.java
index ffca71f294..61b1da4073 100644
--- a/bridge/src/android/view/WindowManagerImpl.java
+++ b/bridge/src/android/view/WindowManagerImpl.java
@@ -20,6 +20,7 @@ import static android.view.ViewGroup.LayoutParams.WRAP_CONTENT;
 import static com.android.layoutlib.bridge.util.InsetUtil.getCurrentBounds;
 
 import android.content.Context;
+import android.content.res.Configuration;
 import android.graphics.Color;
 import android.graphics.Point;
 import android.graphics.Rect;
@@ -70,6 +71,11 @@ public class WindowManagerImpl implements WindowManager {
         };
         mDisplayInfo.logicalDensityDpi = mMetrics.densityDpi;
         mDisplayInfo.displayCutout = DisplayCutout.NO_CUTOUT;
+        if (context.getConfiguration().orientation == Configuration.ORIENTATION_LANDSCAPE) {
+            mDisplayInfo.rotation = Surface.ROTATION_90;
+        } else {
+            mDisplayInfo.rotation = Surface.ROTATION_0;
+        }
     }
 
     public WindowManagerImpl createLocalWindowManager(Window parentWindow) {
@@ -335,15 +341,24 @@ public class WindowManagerImpl implements WindowManager {
         }
     }
 
+    @SuppressWarnings("SuspiciousNameCombination")
     public void setupDisplayCutout() {
+        int displayWidth;
+        int displayHeight;
+        if (mDisplayInfo.rotation == Surface.ROTATION_90) {
+            displayWidth = mMetrics.heightPixels;
+            displayHeight = mMetrics.widthPixels;
+        } else {
+            displayWidth = mMetrics.widthPixels;
+            displayHeight = mMetrics.heightPixels;
+        }
+        // Get cutout for default orientation
         DisplayCutout displayCutout =
                 DisplayCutout.fromResourcesRectApproximation(mContext.getResources(), null,
-                        mMetrics.widthPixels, mMetrics.heightPixels, mMetrics.widthPixels,
-                        mMetrics.heightPixels);
+                        displayWidth, displayHeight, displayWidth, displayHeight);
         if (displayCutout != null) {
-            mDisplayInfo.displayCutout = displayCutout.getRotated(mDisplayInfo.logicalWidth,
-                    mDisplayInfo.logicalHeight, mDisplayInfo.rotation,
-                    getDefaultDisplay().getRotation());
+            mDisplayInfo.displayCutout = displayCutout.getRotated(displayWidth, displayHeight,
+                    Surface.ROTATION_0, mDisplayInfo.rotation);
         }
     }
 }
diff --git a/bridge/src/android/view/flags/Flags_Delegate.java b/bridge/src/com/android/internal/hidden_from_bootclasspath/android/view/flags/Flags_Delegate.java
similarity index 91%
rename from bridge/src/android/view/flags/Flags_Delegate.java
rename to bridge/src/com/android/internal/hidden_from_bootclasspath/android/view/flags/Flags_Delegate.java
index 2e2ed053a3..9bba76b4c6 100644
--- a/bridge/src/android/view/flags/Flags_Delegate.java
+++ b/bridge/src/com/android/internal/hidden_from_bootclasspath/android/view/flags/Flags_Delegate.java
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-package android.view.flags;
+package com.android.internal.hidden_from_bootclasspath.android.view.flags;
 
 import com.android.tools.layoutlib.annotations.LayoutlibDelegate;
 
diff --git a/bridge/src/android/tracing/Flags_Delegate.java b/bridge/src/com/android/internal/protolog/ProtoLog_Delegate.java
similarity index 83%
rename from bridge/src/android/tracing/Flags_Delegate.java
rename to bridge/src/com/android/internal/protolog/ProtoLog_Delegate.java
index 805328f44a..f5c5e744fb 100644
--- a/bridge/src/android/tracing/Flags_Delegate.java
+++ b/bridge/src/com/android/internal/protolog/ProtoLog_Delegate.java
@@ -14,13 +14,13 @@
  * limitations under the License.
  */
 
-package android.tracing;
+package com.android.internal.protolog;
 
 import com.android.tools.layoutlib.annotations.LayoutlibDelegate;
 
-public class Flags_Delegate {
+public class ProtoLog_Delegate {
     @LayoutlibDelegate
-    public static boolean perfettoProtologTracing() {
-        return false;
+    /*package*/ static boolean logOnlyToLogcat() {
+        return true;
     }
 }
diff --git a/bridge/src/com/android/launcher3/icons/MonochromeIconFactory_Accessor.java b/bridge/src/com/android/launcher3/icons/MonochromeIconFactory_Accessor.java
index 8427a780e4..754ff99ee5 100644
--- a/bridge/src/com/android/launcher3/icons/MonochromeIconFactory_Accessor.java
+++ b/bridge/src/com/android/launcher3/icons/MonochromeIconFactory_Accessor.java
@@ -30,7 +30,7 @@ public class MonochromeIconFactory_Accessor {
             int foregroundColor) {
         MonochromeIconFactory monoFactory = new MonochromeIconFactory(adaptiveIcon.getBounds().width());
         monoFactory.setColorFilter(new BlendModeColorFilter(foregroundColor, BlendMode.SRC_IN));
-        Drawable mono = monoFactory.wrap(adaptiveIcon, adaptiveIcon.getIconMask(), 1f);
+        Drawable mono = monoFactory.wrap(adaptiveIcon, adaptiveIcon.getIconMask());
         float inset = getExtraInsetFraction() / (1 + 2 * getExtraInsetFraction());
         return new InsetDrawable(mono, inset);
     }
diff --git a/bridge/src/com/android/layoutlib/bridge/android/BridgeContentResolver.java b/bridge/src/com/android/layoutlib/bridge/android/BridgeContentResolver.java
index 80a50a7901..a575bef2f8 100644
--- a/bridge/src/com/android/layoutlib/bridge/android/BridgeContentResolver.java
+++ b/bridge/src/com/android/layoutlib/bridge/android/BridgeContentResolver.java
@@ -23,6 +23,9 @@ import android.database.ContentObserver;
 import android.net.Uri;
 import android.os.Bundle;
 
+import java.util.HashMap;
+import java.util.Map;
+
 /**
  * A mock content resolver for the LayoutLib Bridge.
  * <p/>
@@ -31,6 +34,7 @@ import android.os.Bundle;
  * {@link BridgeContext#getContentResolver()}.
  */
 public class BridgeContentResolver extends ContentResolver {
+    public Map<String,String> settingsUserMap = new HashMap<>();
 
     private BridgeContentProvider mProvider = null;
 
diff --git a/bridge/src/com/android/layoutlib/bridge/android/BridgeContext.java b/bridge/src/com/android/layoutlib/bridge/android/BridgeContext.java
index 68206251b8..1d9f812fb4 100644
--- a/bridge/src/com/android/layoutlib/bridge/android/BridgeContext.java
+++ b/bridge/src/com/android/layoutlib/bridge/android/BridgeContext.java
@@ -121,6 +121,7 @@ import java.util.ArrayList;
 import java.util.HashMap;
 import java.util.IdentityHashMap;
 import java.util.List;
+import java.util.Locale;
 import java.util.Map;
 import java.util.concurrent.Executor;
 
@@ -134,8 +135,8 @@ public class BridgeContext extends Context {
 
     private static final Map<String, ResourceValue> FRAMEWORK_PATCHED_VALUES = new HashMap<>(2);
     private static final Map<String, ResourceValue> FRAMEWORK_REPLACE_VALUES = new HashMap<>(3);
-    private static final int MAX_PARSER_STACK_SIZE = Integer.getInteger(
-            "layoutlib.max.parser.stack.size", 1000);
+    private static final int MAX_PARSER_STACK_SIZE =
+            Integer.getInteger("layoutlib.max.parser.stack.size", 1000);
 
     static {
         FRAMEWORK_PATCHED_VALUES.put("animateFirstView",
@@ -187,6 +188,9 @@ public class BridgeContext extends Context {
     private final HashMap<View, Integer> mScrollYPos = new HashMap<>();
     private final HashMap<View, Integer> mScrollXPos = new HashMap<>();
 
+    private static final String CREATE_CONFIG_NOT_SUPPORTED = String.format(Locale.ENGLISH,
+            "We do not currently support #createConfigurationContext.");
+
     private Resources.Theme mTheme;
 
     private final Map<Object, Map<ResourceReference, ResourceValue>> mDefaultPropMaps =
@@ -247,12 +251,9 @@ public class BridgeContext extends Context {
      * @param targetSdkVersion the targetSdkVersion of the application.
      */
     public BridgeContext(Object projectKey, @NonNull DisplayMetrics metrics,
-            @NonNull RenderResources renderResources,
-            @NonNull AssetRepository assets,
-            @NonNull LayoutlibCallback layoutlibCallback,
-            @NonNull Configuration config,
-            int targetSdkVersion,
-            boolean hasRtlSupport) {
+            @NonNull RenderResources renderResources, @NonNull AssetRepository assets,
+            @NonNull LayoutlibCallback layoutlibCallback, @NonNull Configuration config,
+            int targetSdkVersion, boolean hasRtlSupport) {
         mProjectKey = projectKey;
         mMetrics = metrics;
         mLayoutlibCallback = layoutlibCallback;
@@ -307,11 +308,7 @@ public class BridgeContext extends Context {
 
         mAssets.setAssetRepository(assetRepository);
 
-        mSystemResources = Resources_Delegate.initSystem(
-                this,
-                assetManager,
-                mMetrics,
-                mConfig,
+        mSystemResources = Resources_Delegate.initSystem(this, assetManager, mMetrics, mConfig,
                 mLayoutlibCallback);
         mTheme = mSystemResources.newTheme();
     }
@@ -378,6 +375,7 @@ public class BridgeContext extends Context {
 
     /**
      * Adds a parser to the stack.
+     *
      * @param parser the parser to add.
      */
     public void pushParser(BridgeXmlBlockParser parser) {
@@ -403,6 +401,7 @@ public class BridgeContext extends Context {
 
     /**
      * Returns the current parser at the top the of the stack.
+     *
      * @return a parser or null.
      */
     private BridgeXmlBlockParser getCurrentParser() {
@@ -411,6 +410,7 @@ public class BridgeContext extends Context {
 
     /**
      * Returns the previous parser.
+     *
      * @return a parser or null if there isn't any previous parser
      */
     public BridgeXmlBlockParser getPreviousParser() {
@@ -464,20 +464,16 @@ public class BridgeContext extends Context {
                     default:
                         outValue.type = TypedValue.TYPE_INT_COLOR_ARGB8;
                 }
-            }
-            else if (stringValue.charAt(0) == '@') {
+            } else if (stringValue.charAt(0) == '@') {
                 outValue.type = TypedValue.TYPE_REFERENCE;
-            }
-            else if ("true".equals(stringValue) || "false".equals(stringValue)) {
+            } else if ("true".equals(stringValue) || "false".equals(stringValue)) {
                 outValue.type = TypedValue.TYPE_INT_BOOLEAN;
                 outValue.data = "true".equals(stringValue) ? 1 : 0;
-            }
-            else {
+            } else {
                 try {
                     outValue.data = Integer.parseInt(stringValue);
                     outValue.type = TypedValue.TYPE_INT_DEC;
-                }
-                catch (NumberFormatException e) {
+                } catch (NumberFormatException e) {
                     if (!ResourceHelper.parseFloatAttribute(null, stringValue, outValue, false)) {
                         outValue.type = TypedValue.TYPE_STRING;
                         outValue.string = stringValue;
@@ -533,8 +529,7 @@ public class BridgeContext extends Context {
                         new BridgeXmlBlockParser(parser, this, layout.getNamespace());
                 try {
                     pushParser(blockParser);
-                    return Pair.create(
-                            mBridgeInflater.inflate(blockParser, parent, attachToRoot),
+                    return Pair.create(mBridgeInflater.inflate(blockParser, parent, attachToRoot),
                             Boolean.TRUE);
                 } finally {
                     popParser();
@@ -558,8 +553,8 @@ public class BridgeContext extends Context {
                             new BridgeXmlBlockParser(parser, this, layout.getNamespace());
                     try {
                         pushParser(blockParser);
-                        return Pair.create(mBridgeInflater.inflate(blockParser, parent,
-                                attachToRoot),
+                        return Pair.create(
+                                mBridgeInflater.inflate(blockParser, parent, attachToRoot),
                                 Boolean.FALSE);
                     } finally {
                         popParser();
@@ -569,8 +564,8 @@ public class BridgeContext extends Context {
                             String.format("File %s is missing!", path), null, null);
                 }
             } catch (XmlPullParserException e) {
-                Bridge.getLog().error(ILayoutLog.TAG_BROKEN,
-                        "Failed to parse file " + path, e, null, null /*data*/);
+                Bridge.getLog().error(ILayoutLog.TAG_BROKEN, "Failed to parse file " + path, e,
+                        null, null /*data*/);
                 // we'll return null below.
             } finally {
                 mBridgeInflater.setResourceReference(null);
@@ -740,8 +735,8 @@ public class BridgeContext extends Context {
                 // an existing system service.
                 assert SystemServiceRegistry.getSystemServiceClassName(service) == null :
                         "Unsupported Service: " + service;
-                Bridge.getLog().warning(ILayoutLog.TAG_UNSUPPORTED, "Service " + service +
-                        " was not found or is unsupported", null, null);
+                Bridge.getLog().warning(ILayoutLog.TAG_UNSUPPORTED,
+                        "Service " + service + " was not found or is unsupported", null, null);
         }
 
         return null;
@@ -773,8 +768,8 @@ public class BridgeContext extends Context {
             }
 
             if (style == null) {
-                Bridge.getLog().warning(ILayoutLog.TAG_INFO,
-                        "Failed to find style with " + resId, null, null);
+                Bridge.getLog().warning(ILayoutLog.TAG_INFO, "Failed to find style with " + resId,
+                        null, null);
             }
         }
 
@@ -825,7 +820,7 @@ public class BridgeContext extends Context {
         // Hint: for XmlPullParser, attach source //DEVICE_SRC/dalvik/libcore/xml/src/java
         if (set instanceof BridgeXmlBlockParser) {
             BridgeXmlBlockParser parser;
-            parser = (BridgeXmlBlockParser)set;
+            parser = (BridgeXmlBlockParser) set;
 
             key = parser.getViewCookie();
             if (key != null) {
@@ -833,7 +828,8 @@ public class BridgeContext extends Context {
             }
 
             currentFileNamespace = parser.getFileResourceNamespace();
-            resolver = new XmlPullParserResolver(parser, mLayoutlibCallback.getImplicitNamespaces());
+            resolver =
+                    new XmlPullParserResolver(parser, mLayoutlibCallback.getImplicitNamespaces());
         } else if (set instanceof BridgeLayoutParamsMapAttributes) {
             // This is for temp layout params generated dynamically in MockView. The set contains
             // hardcoded values and we don't need to worry about resolving them.
@@ -841,8 +837,8 @@ public class BridgeContext extends Context {
             resolver = Resolver.EMPTY_RESOLVER;
         } else if (set != null) {
             // really this should not be happening since its instantiated in Bridge
-            Bridge.getLog().error(ILayoutLog.TAG_BROKEN,
-                    "Parser is not a BridgeXmlBlockParser!", null, null);
+            Bridge.getLog().error(ILayoutLog.TAG_BROKEN, "Parser is not a BridgeXmlBlockParser!",
+                    null, null);
             return null;
         } else {
             // `set` is null, so there will be no values to resolve.
@@ -852,8 +848,7 @@ public class BridgeContext extends Context {
 
         List<AttributeHolder> attributeList = searchAttrs(attrs);
 
-        BridgeTypedArray ta =
-                Resources_Delegate.newTypeArray(mSystemResources, attrs.length);
+        BridgeTypedArray ta = Resources_Delegate.newTypeArray(mSystemResources, attrs.length);
 
         // Look for a custom style.
         StyleResourceValue customStyleValues = null;
@@ -921,25 +916,19 @@ public class BridgeContext extends Context {
 
                             defStyleValues = item;
                         } else {
-                            Bridge.getLog().error(null,
-                                    String.format(
-                                            "Style with id 0x%x (resolved to '%s') does not exist.",
-                                            defStyleRes, value.getName()),
-                                    null, null);
+                            Bridge.getLog().error(null, String.format(
+                                    "Style with id 0x%x (resolved to '%s') does not exist.",
+                                    defStyleRes, value.getName()), null, null);
                         }
                     } else {
                         Bridge.getLog().error(null,
-                                String.format(
-                                        "Resource id 0x%x is not of type STYLE (instead %s)",
-                                        defStyleRes, value.getResourceType().name()),
-                                null, null);
+                                String.format("Resource id 0x%x is not of type STYLE (instead %s)",
+                                        defStyleRes, value.getResourceType().name()), null, null);
                     }
                 } else {
                     Bridge.getLog().error(null,
-                            String.format(
-                                    "Failed to find style with id 0x%x in current theme",
-                                    defStyleRes),
-                            null, null);
+                            String.format("Failed to find style with id 0x%x in current theme",
+                                    defStyleRes), null, null);
                 }
             }
         }
@@ -1030,7 +1019,8 @@ public class BridgeContext extends Context {
                         // Only log a warning if the referenced value isn't one of the RTL
                         // attributes, or the app targets old API.
                         if (defaultValue == null &&
-                                (getApplicationInfo().targetSdkVersion < JELLY_BEAN_MR1 || !attrName.equals(RTL_ATTRS.get(val)))) {
+                                (getApplicationInfo().targetSdkVersion < JELLY_BEAN_MR1 ||
+                                        !attrName.equals(RTL_ATTRS.get(val)))) {
                             if (reference != null) {
                                 val = reference.getResourceUrl().toString();
                             }
@@ -1041,14 +1031,15 @@ public class BridgeContext extends Context {
                     }
                 }
 
-                ta.bridgeSetValue(index, attrName, attributeHolder.getNamespace(), attributeHolder.getResourceId(),
-                        defaultValue);
+                ta.bridgeSetValue(index, attrName, attributeHolder.getNamespace(),
+                        attributeHolder.getResourceId(), defaultValue);
             } else {
                 // There is a value in the XML, but we need to resolve it in case it's
                 // referencing another resource or a theme value.
-                ta.bridgeSetValue(index, attrName, attributeHolder.getNamespace(), attributeHolder.getResourceId(),
-                        mRenderResources.resolveResValue(
-                                new UnresolvedResourceValue(value, currentFileNamespace, resolver)));
+                ta.bridgeSetValue(index, attrName, attributeHolder.getNamespace(),
+                        attributeHolder.getResourceId(), mRenderResources.resolveResValue(
+                                new UnresolvedResourceValue(value, currentFileNamespace,
+                                        resolver)));
             }
         }
 
@@ -1080,10 +1071,17 @@ public class BridgeContext extends Context {
     }
 
     @Override
-    public void registerComponentCallbacks(ComponentCallbacks callback) {}
+    public void registerComponentCallbacks(ComponentCallbacks callback) {
+    }
+
+    @Override
+    public void unregisterComponentCallbacks(ComponentCallbacks callback) {
+    }
 
     @Override
-    public void unregisterComponentCallbacks(ComponentCallbacks callback) {}
+    public int getDeviceId() {
+        return DEVICE_ID_DEFAULT;
+    }
 
     // ------------- private new methods
 
@@ -1098,8 +1096,7 @@ public class BridgeContext extends Context {
             @Nullable StyleResourceValue style, int[] attrs) throws Resources.NotFoundException {
         List<AttributeHolder> attributes = searchAttrs(attrs);
 
-        BridgeTypedArray ta =
-                Resources_Delegate.newTypeArray(mSystemResources, attrs.length);
+        BridgeTypedArray ta = Resources_Delegate.newTypeArray(mSystemResources, attrs.length);
 
         Map<ResourceReference, ResourceValue> defaultPropMap = new HashMap<>();
         // for each attribute, get its name so that we can search it in the style
@@ -1119,10 +1116,8 @@ public class BridgeContext extends Context {
                     defaultPropMap.put(attrHolder.asReference(), resValue);
                     // resolve it to make sure there are no references left.
                     resValue = mRenderResources.resolveResValue(resValue);
-                    ta.bridgeSetValue(
-                            i, attrHolder.getName(), attrHolder.getNamespace(),
-                            attrHolder.getResourceId(),
-                            resValue);
+                    ta.bridgeSetValue(i, attrHolder.getName(), attrHolder.getNamespace(),
+                            attrHolder.getResourceId(), resValue);
                 }
             }
         }
@@ -1138,6 +1133,7 @@ public class BridgeContext extends Context {
      * <p/>
      *
      * @param attributeIds An attribute array reference given to obtainStyledAttributes.
+     *
      * @return List of attribute information.
      */
     @NotNull
@@ -1318,7 +1314,7 @@ public class BridgeContext extends Context {
 
                 @Override
                 public void shellCommand(FileDescriptor in, FileDescriptor out, FileDescriptor err,
-                  String[] args, ShellCallback shellCallback, ResultReceiver resultReceiver) {
+                        String[] args, ShellCallback shellCallback, ResultReceiver resultReceiver) {
                 }
             };
         }
@@ -1339,8 +1335,8 @@ public class BridgeContext extends Context {
     }
 
     @Override
-    public boolean bindIsolatedService(Intent arg0,
-            int arg1, String arg2, Executor arg3, ServiceConnection arg4) {
+    public boolean bindIsolatedService(Intent arg0, int arg1, String arg2, Executor arg3,
+            ServiceConnection arg4) {
         return false;
     }
 
@@ -1399,8 +1395,8 @@ public class BridgeContext extends Context {
     }
 
     @Override
-    public int checkUriPermission(Uri arg0, String arg1, String arg2, int arg3,
-            int arg4, int arg5) {
+    public int checkUriPermission(Uri arg0, String arg1, String arg2, int arg3, int arg4,
+            int arg5) {
         // pass
         return 0;
     }
@@ -1425,8 +1421,9 @@ public class BridgeContext extends Context {
 
     @Override
     public Context createConfigurationContext(Configuration overrideConfiguration) {
-        // pass
-        return null;
+        Bridge.getLog().fidelityWarning(ILayoutLog.TAG_UNSUPPORTED, CREATE_CONFIG_NOT_SUPPORTED, null,
+                null, null);
+        return this;
     }
 
     @Override
@@ -1478,8 +1475,7 @@ public class BridgeContext extends Context {
     }
 
     @Override
-    public void enforceCallingOrSelfUriPermission(Uri arg0, int arg1,
-            String arg2) {
+    public void enforceCallingOrSelfUriPermission(Uri arg0, int arg1, String arg2) {
         // pass
 
     }
@@ -1503,15 +1499,14 @@ public class BridgeContext extends Context {
     }
 
     @Override
-    public void enforceUriPermission(Uri arg0, int arg1, int arg2, int arg3,
-            String arg4) {
+    public void enforceUriPermission(Uri arg0, int arg1, int arg2, int arg3, String arg4) {
         // pass
 
     }
 
     @Override
-    public void enforceUriPermission(Uri arg0, String arg1, String arg2,
-            int arg3, int arg4, int arg5, String arg6) {
+    public void enforceUriPermission(Uri arg0, String arg1, String arg2, int arg3, int arg4,
+            int arg5, String arg6) {
         // pass
 
     }
@@ -1710,8 +1705,8 @@ public class BridgeContext extends Context {
     }
 
     @Override
-    public SQLiteDatabase openOrCreateDatabase(String arg0, int arg1,
-            CursorFactory arg2, DatabaseErrorHandler arg3) {
+    public SQLiteDatabase openOrCreateDatabase(String arg0, int arg1, CursorFactory arg2,
+            DatabaseErrorHandler arg3) {
         // pass
         return null;
     }
@@ -1735,15 +1730,15 @@ public class BridgeContext extends Context {
     }
 
     @Override
-    public Intent registerReceiver(BroadcastReceiver arg0, IntentFilter arg1,
-            String arg2, Handler arg3) {
+    public Intent registerReceiver(BroadcastReceiver arg0, IntentFilter arg1, String arg2,
+            Handler arg3) {
         // pass
         return null;
     }
 
     @Override
-    public Intent registerReceiver(BroadcastReceiver arg0, IntentFilter arg1,
-            String arg2, Handler arg3, int arg4) {
+    public Intent registerReceiver(BroadcastReceiver arg0, IntentFilter arg1, String arg2,
+            Handler arg3, int arg4) {
         // pass
         return null;
     }
@@ -1823,17 +1818,15 @@ public class BridgeContext extends Context {
     }
 
     @Override
-    public void sendOrderedBroadcast(Intent arg0, String arg1,
-            BroadcastReceiver arg2, Handler arg3, int arg4, String arg5,
-            Bundle arg6) {
+    public void sendOrderedBroadcast(Intent arg0, String arg1, BroadcastReceiver arg2, Handler arg3,
+            int arg4, String arg5, Bundle arg6) {
         // pass
 
     }
 
     @Override
-    public void sendOrderedBroadcast(Intent arg0, String arg1,
-            Bundle arg7, BroadcastReceiver arg2, Handler arg3, int arg4, String arg5,
-            Bundle arg6) {
+    public void sendOrderedBroadcast(Intent arg0, String arg1, Bundle arg7, BroadcastReceiver arg2,
+            Handler arg3, int arg4, String arg5, Bundle arg6) {
         // pass
 
     }
@@ -1851,19 +1844,18 @@ public class BridgeContext extends Context {
     }
 
     @Override
-    public void sendBroadcastAsUser(Intent intent, UserHandle user,
-            String receiverPermission) {
+    public void sendBroadcastAsUser(Intent intent, UserHandle user, String receiverPermission) {
         // pass
     }
 
     @Override
-    public void sendBroadcastAsUser(Intent intent, UserHandle user,
-            String receiverPermission, Bundle options) {
+    public void sendBroadcastAsUser(Intent intent, UserHandle user, String receiverPermission,
+            Bundle options) {
         // pass
     }
 
-    public void sendBroadcastAsUser(Intent intent, UserHandle user,
-            String receiverPermission, int appOp) {
+    public void sendBroadcastAsUser(Intent intent, UserHandle user, String receiverPermission,
+            int appOp) {
         // pass
     }
 
@@ -1877,16 +1869,14 @@ public class BridgeContext extends Context {
     @Override
     public void sendOrderedBroadcastAsUser(Intent intent, UserHandle user,
             String receiverPermission, int appOp, BroadcastReceiver resultReceiver,
-            Handler scheduler,
-            int initialCode, String initialData, Bundle initialExtras) {
+            Handler scheduler, int initialCode, String initialData, Bundle initialExtras) {
         // pass
     }
 
     @Override
     public void sendOrderedBroadcastAsUser(Intent intent, UserHandle user,
             String receiverPermission, int appOp, Bundle options, BroadcastReceiver resultReceiver,
-            Handler scheduler,
-            int initialCode, String initialData, Bundle initialExtras) {
+            Handler scheduler, int initialCode, String initialData, Bundle initialExtras) {
         // pass
     }
 
@@ -1904,9 +1894,8 @@ public class BridgeContext extends Context {
     }
 
     @Override
-    public void sendStickyOrderedBroadcast(Intent intent,
-            BroadcastReceiver resultReceiver, Handler scheduler, int initialCode, String initialData,
-           Bundle initialExtras) {
+    public void sendStickyOrderedBroadcast(Intent intent, BroadcastReceiver resultReceiver,
+            Handler scheduler, int initialCode, String initialData, Bundle initialExtras) {
         // pass
     }
 
@@ -1921,10 +1910,9 @@ public class BridgeContext extends Context {
     }
 
     @Override
-    public void sendStickyOrderedBroadcastAsUser(Intent intent,
-            UserHandle user, BroadcastReceiver resultReceiver,
-            Handler scheduler, int initialCode, String initialData,
-            Bundle initialExtras) {
+    public void sendStickyOrderedBroadcastAsUser(Intent intent, UserHandle user,
+            BroadcastReceiver resultReceiver, Handler scheduler, int initialCode,
+            String initialData, Bundle initialExtras) {
         // pass
     }
 
@@ -1962,22 +1950,20 @@ public class BridgeContext extends Context {
     }
 
     @Override
-    public void startIntentSender(IntentSender intent,
-            Intent fillInIntent, int flagsMask, int flagsValues, int extraFlags)
-            throws IntentSender.SendIntentException {
+    public void startIntentSender(IntentSender intent, Intent fillInIntent, int flagsMask,
+            int flagsValues, int extraFlags) throws IntentSender.SendIntentException {
         // pass
     }
 
     @Override
-    public void startIntentSender(IntentSender intent,
-            Intent fillInIntent, int flagsMask, int flagsValues, int extraFlags,
-            Bundle options) throws IntentSender.SendIntentException {
+    public void startIntentSender(IntentSender intent, Intent fillInIntent, int flagsMask,
+            int flagsValues, int extraFlags, Bundle options)
+            throws IntentSender.SendIntentException {
         // pass
     }
 
     @Override
-    public boolean startInstrumentation(ComponentName arg0, String arg1,
-            Bundle arg2) {
+    public boolean startInstrumentation(ComponentName arg0, String arg1, Bundle arg2) {
         // pass
         return false;
     }
@@ -2019,8 +2005,7 @@ public class BridgeContext extends Context {
     }
 
     @Override
-    public void updateServiceGroup(@NonNull ServiceConnection conn, int group,
-            int importance) {
+    public void updateServiceGroup(@NonNull ServiceConnection conn, int group, int importance) {
         // pass
     }
 
@@ -2227,7 +2212,8 @@ public class BridgeContext extends Context {
 
     private static class AttributeHolder {
         private final int resourceId;
-        @NonNull private final ResourceReference reference;
+        @NonNull
+        private final ResourceReference reference;
 
         private AttributeHolder(int resourceId, @NonNull ResourceReference reference) {
             this.resourceId = resourceId;
@@ -2262,7 +2248,7 @@ public class BridgeContext extends Context {
      * creation of the TypedArray</li>
      * <li>{@code Integer}: the default style used at the time of creation</li>
      * </ol>
-     *
+     * <p>
      * The class is created by using nested maps resolving one dependency at a time.
      * <p/>
      * The final value of the nested maps is a pair of the typed array and a map of properties
@@ -2270,10 +2256,9 @@ public class BridgeContext extends Context {
      */
     private static class TypedArrayCache {
 
-        private final Map<int[],
-                Map<List<StyleResourceValue>,
-                        Map<Integer, Pair<BridgeTypedArray,
-                                Map<ResourceReference, ResourceValue>>>>> mCache;
+        private final Map<int[], Map<List<StyleResourceValue>, Map<Integer, Pair<BridgeTypedArray
+                , Map<ResourceReference, ResourceValue>>>>>
+                mCache;
 
         private TypedArrayCache() {
             mCache = new IdentityHashMap<>();
@@ -2281,12 +2266,12 @@ public class BridgeContext extends Context {
 
         private Pair<BridgeTypedArray, Map<ResourceReference, ResourceValue>> get(int[] attrs,
                 List<StyleResourceValue> themes, int resId) {
-            Map<List<StyleResourceValue>, Map<Integer, Pair<BridgeTypedArray, Map<ResourceReference,
-                    ResourceValue>>>>
+            Map<List<StyleResourceValue>, Map<Integer, Pair<BridgeTypedArray,
+                    Map<ResourceReference, ResourceValue>>>>
                     cacheFromThemes = mCache.get(attrs);
             if (cacheFromThemes != null) {
-                Map<Integer, Pair<BridgeTypedArray, Map<ResourceReference, ResourceValue>>> cacheFromResId =
-                        cacheFromThemes.get(themes);
+                Map<Integer, Pair<BridgeTypedArray, Map<ResourceReference, ResourceValue>>>
+                        cacheFromResId = cacheFromThemes.get(themes);
                 if (cacheFromResId != null) {
                     return cacheFromResId.get(resId);
                 }
@@ -2296,11 +2281,11 @@ public class BridgeContext extends Context {
 
         private void put(int[] attrs, List<StyleResourceValue> themes, int resId,
                 Pair<BridgeTypedArray, Map<ResourceReference, ResourceValue>> value) {
-            Map<List<StyleResourceValue>, Map<Integer, Pair<BridgeTypedArray, Map<ResourceReference,
-                    ResourceValue>>>>
+            Map<List<StyleResourceValue>, Map<Integer, Pair<BridgeTypedArray,
+                    Map<ResourceReference, ResourceValue>>>>
                     cacheFromThemes = mCache.computeIfAbsent(attrs, k -> new HashMap<>());
-            Map<Integer, Pair<BridgeTypedArray, Map<ResourceReference, ResourceValue>>> cacheFromResId =
-                    cacheFromThemes.computeIfAbsent(themes, k -> new HashMap<>());
+            Map<Integer, Pair<BridgeTypedArray, Map<ResourceReference, ResourceValue>>>
+                    cacheFromResId = cacheFromThemes.computeIfAbsent(themes, k -> new HashMap<>());
             cacheFromResId.put(resId, value);
         }
 
@@ -2328,7 +2313,7 @@ public class BridgeContext extends Context {
     }
 
     public void applyWallpaper(String wallpaperPath) {
-        mRenderResources.setWallpaper(wallpaperPath, mConfig.isNightModeActive());
+        mRenderResources.setWallpaper(wallpaperPath);
     }
 
     @NotNull
diff --git a/bridge/src/com/android/layoutlib/bridge/android/BridgePowerManager.java b/bridge/src/com/android/layoutlib/bridge/android/BridgePowerManager.java
index ccd8b947f3..661a6a2d33 100644
--- a/bridge/src/com/android/layoutlib/bridge/android/BridgePowerManager.java
+++ b/bridge/src/com/android/layoutlib/bridge/android/BridgePowerManager.java
@@ -393,6 +393,11 @@ public class BridgePowerManager implements IPowerManager {
         // pass for now
     }
 
+    @Override
+    public void suppressAmbientDisplayBehavior(String token, int suppressionFlags) {
+        // pass for now
+    }
+
     @Override
     public boolean isAmbientDisplaySuppressedForToken(String token) {
         return false;
diff --git a/bridge/src/com/android/layoutlib/bridge/android/DynamicRenderResources.java b/bridge/src/com/android/layoutlib/bridge/android/DynamicRenderResources.java
index e356b6570b..3593e90f4a 100644
--- a/bridge/src/com/android/layoutlib/bridge/android/DynamicRenderResources.java
+++ b/bridge/src/com/android/layoutlib/bridge/android/DynamicRenderResources.java
@@ -22,18 +22,15 @@ import com.android.ide.common.rendering.api.ResourceReference;
 import com.android.ide.common.rendering.api.ResourceValue;
 import com.android.ide.common.rendering.api.ResourceValueImpl;
 import com.android.ide.common.rendering.api.StyleResourceValue;
-import com.android.internal.graphics.ColorUtils;
 import com.android.resources.ResourceType;
 import com.android.systemui.monet.ColorScheme;
 import com.android.systemui.monet.DynamicColors;
 import com.android.systemui.monet.Style;
-import com.android.systemui.monet.TonalPalette;
 import com.android.tools.layoutlib.annotations.VisibleForTesting;
 
 import android.app.WallpaperColors;
 import android.graphics.Bitmap;
 import android.graphics.BitmapFactory;
-import android.graphics.Color;
 import android.util.Pair;
 
 import java.io.IOException;
@@ -143,12 +140,12 @@ public class DynamicRenderResources extends RenderResources {
         return baseValue;
     }
 
-    public void setWallpaper(String wallpaperPath, boolean isNightMode) {
+    public void setWallpaper(String wallpaperPath) {
         if (wallpaperPath == null) {
             mDynamicColorMap = null;
             return;
         }
-        mDynamicColorMap = createDynamicColorMap(wallpaperPath, isNightMode);
+        mDynamicColorMap = createDynamicColorMap(wallpaperPath);
     }
 
     /**
@@ -156,12 +153,11 @@ public class DynamicRenderResources extends RenderResources {
      * It uses the main wallpaper color and the {@link Style#TONAL_SPOT} style.
      *
      * @param wallpaperPath path of the wallpaper resource to use
-     * @param isNightMode whether to use night mode or not
      *
      * @return map of system color names to their dynamic values
      */
     @VisibleForTesting
-    static Map<String, Integer> createDynamicColorMap(String wallpaperPath, boolean isNightMode) {
+    static Map<String, Integer> createDynamicColorMap(String wallpaperPath) {
         try (InputStream stream = DynamicRenderResources.class.getResourceAsStream(wallpaperPath)) {
             Bitmap wallpaper = BitmapFactory.decodeStream(stream);
             if (wallpaper == null) {
@@ -171,23 +167,23 @@ public class DynamicRenderResources extends RenderResources {
             int seed = ColorScheme.getSeedColor(wallpaperColors);
             ColorScheme lightScheme = new ColorScheme(seed, false);
             ColorScheme darkScheme = new ColorScheme(seed, true);
-            ColorScheme currentScheme = isNightMode ? darkScheme : lightScheme;
             Map<String, Integer> dynamicColorMap = new HashMap<>();
-            extractPalette("accent1", dynamicColorMap, currentScheme.getAccent1());
-            extractPalette("accent2", dynamicColorMap, currentScheme.getAccent2());
-            extractPalette("accent3", dynamicColorMap, currentScheme.getAccent3());
-            extractPalette("neutral1", dynamicColorMap, currentScheme.getNeutral1());
-            extractPalette("neutral2", dynamicColorMap, currentScheme.getNeutral2());
 
-            //Themed Colors
+            // Accent Colors
             extractDynamicColors(dynamicColorMap, lightScheme, darkScheme,
-                    DynamicColors.getAllDynamicColorsMapped(false), false);
+                    DynamicColors.getAllAccentPalette(), false);
+            // Neutral Colors
+            extractDynamicColors(dynamicColorMap, lightScheme, darkScheme,
+                    DynamicColors.getAllNeutralPalette(), false);
+            // Themed Colors
+            extractDynamicColors(dynamicColorMap, lightScheme, darkScheme,
+                    DynamicColors.getAllDynamicColorsMapped(), false);
             // Fixed Colors
             extractDynamicColors(dynamicColorMap, lightScheme, darkScheme,
-                    DynamicColors.getFixedColorsMapped(false), true);
-            //Custom Colors
+                    DynamicColors.getFixedColorsMapped(), true);
+            // Custom Colors
             extractDynamicColors(dynamicColorMap, lightScheme, darkScheme,
-                    DynamicColors.getCustomColorsMapped(false), false);
+                    DynamicColors.getCustomColorsMapped(), false);
             return dynamicColorMap;
         } catch (IllegalArgumentException | IOException ignore) {
             return null;
@@ -198,17 +194,6 @@ public class DynamicRenderResources extends RenderResources {
      * Builds the dynamic theme from the {@link ColorScheme} copying what is done
      * in {@link ThemeOverlayController#getOverlay}
      */
-    private static void extractPalette(String name,
-            Map<String, Integer> colorMap, TonalPalette tonalPalette) {
-        String resourcePrefix = "system_" + name;
-        tonalPalette.allShadesMapped.forEach((key, value) -> {
-            String resourceName = resourcePrefix + "_" + key;
-            int colorValue = ColorUtils.setAlphaComponent(value, 0xFF);
-            colorMap.put(resourceName, colorValue);
-        });
-        colorMap.put(resourcePrefix + "_0", Color.WHITE);
-    }
-
     private static void extractDynamicColors(Map<String, Integer> colorMap, ColorScheme lightScheme,
             ColorScheme darkScheme, List<Pair<String, DynamicColor>> colors, Boolean isFixed) {
         colors.forEach(p -> {
diff --git a/bridge/src/com/android/layoutlib/bridge/bars/StatusBar.java b/bridge/src/com/android/layoutlib/bridge/bars/StatusBar.java
index 66f4bbcf83..9abfd0ef27 100644
--- a/bridge/src/com/android/layoutlib/bridge/bars/StatusBar.java
+++ b/bridge/src/com/android/layoutlib/bridge/bars/StatusBar.java
@@ -24,6 +24,7 @@ import com.android.layoutlib.bridge.android.BridgeContext;
 import com.android.layoutlib.bridge.impl.ResourceHelper;
 import com.android.resources.Density;
 
+import android.app.WindowConfiguration;
 import android.content.Context;
 import android.graphics.Color;
 import android.graphics.Insets;
@@ -48,7 +49,6 @@ import java.util.stream.Stream;
 
 import static android.graphics.Color.WHITE;
 import static android.os._Original_Build.VERSION_CODES.M;
-import static android.view.Surface.ROTATION_0;
 import static android.view.WindowInsets.Type.mandatorySystemGestures;
 import static android.view.WindowInsets.Type.statusBars;
 import static android.view.WindowInsets.Type.tappableElement;
@@ -189,8 +189,8 @@ public class StatusBar extends CustomBar {
             insets = Insets.NONE;
             waterfallInsets = Insets.NONE;
         } else {
-            DisplayCutout rotated =
-                    cutout.getRotated(info.logicalWidth, info.logicalHeight, ROTATION_0, targetRot);
+            DisplayCutout rotated = cutout.getRotated(info.logicalWidth, info.logicalHeight,
+                    info.rotation, targetRot);
             insets = Insets.of(rotated.getSafeInsets());
             waterfallInsets = rotated.getWaterfallInsets();
         }
@@ -262,9 +262,9 @@ public class StatusBar extends CustomBar {
     }
 
     private Insets getStatusBarContentInsets() {
-        Rect screenBounds =
-                getContext().getResources().getConfiguration().windowConfiguration.getMaxBounds();
-        int width = screenBounds.width();
+        WindowConfiguration windowConfiguration =
+                getContext().getResources().getConfiguration().windowConfiguration;
+        Rect screenBounds = windowConfiguration.getMaxBounds();
         List<Rect> cutoutRects = Stream.of(mDisplayCutout.getBoundingRectLeft(),
                 mDisplayCutout.getBoundingRectRight(),
                 mDisplayCutout.getBoundingRectTop()).filter(rect -> !rect.isEmpty()).toList();
@@ -274,9 +274,16 @@ public class StatusBar extends CustomBar {
 
         int leftMargin = 0;
         int rightMargin = 0;
+        int width = screenBounds.width();
         Rect sbRect = new Rect(0, 0, width, mStatusBarHeight);
         for (Rect cutoutRect : cutoutRects) {
-            if (!sbRect.intersects(0, cutoutRect.top, width, cutoutRect.bottom)) {
+            Rect shortEdge;
+            if (windowConfiguration.getRotation() == Surface.ROTATION_90) {
+                shortEdge = new Rect(cutoutRect.left, 0, cutoutRect.right, screenBounds.height());
+            } else {
+                shortEdge = new Rect(0, cutoutRect.top, width, cutoutRect.bottom);
+            }
+            if (!sbRect.intersect(shortEdge)) {
                 continue;
             }
             if (cutoutRect.left == 0) {
diff --git a/bridge/src/com/android/layoutlib/bridge/impl/RenderAction.java b/bridge/src/com/android/layoutlib/bridge/impl/RenderAction.java
index e4b73b8801..ad03988a1e 100644
--- a/bridge/src/com/android/layoutlib/bridge/impl/RenderAction.java
+++ b/bridge/src/com/android/layoutlib/bridge/impl/RenderAction.java
@@ -41,6 +41,7 @@ import android.graphics.Rect;
 import android.graphics.drawable.AdaptiveIconDrawable_Delegate;
 import android.os.HandlerThread_Delegate;
 import android.os.SystemProperties;
+import android.provider.Settings;
 import android.util.DisplayMetrics;
 import android.view.IWindowManager;
 import android.view.IWindowManagerImpl;
@@ -100,6 +101,8 @@ public abstract class RenderAction<T extends RenderParams> {
 
     private final T mParams;
 
+    protected boolean mConfigurationUpdated;
+
     private BridgeContext mContext;
 
     private static final Object sContextLock = new Object();
@@ -153,13 +156,10 @@ public abstract class RenderAction<T extends RenderParams> {
 
         metrics.scaledDensity = metrics.noncompatScaledDensity = metrics.density;
 
-        if (hardwareConfig.getOrientation() == ScreenOrientation.PORTRAIT) {
-            metrics.widthPixels = metrics.noncompatWidthPixels = hardwareConfig.getScreenWidth();
-            metrics.heightPixels = metrics.noncompatHeightPixels = hardwareConfig.getScreenHeight();
-        } else {
-            metrics.widthPixels = metrics.noncompatWidthPixels = hardwareConfig.getScreenHeight();
-            metrics.heightPixels = metrics.noncompatHeightPixels = hardwareConfig.getScreenWidth();
-        }
+        // Display metrics width and height are for the current orientation
+        metrics.widthPixels = metrics.noncompatWidthPixels = hardwareConfig.getScreenWidth();
+        metrics.heightPixels = metrics.noncompatHeightPixels = hardwareConfig.getScreenHeight();
+
         metrics.xdpi = metrics.noncompatXdpi = hardwareConfig.getXdpi();
         metrics.ydpi = metrics.noncompatYdpi = hardwareConfig.getYdpi();
 
@@ -173,6 +173,10 @@ public abstract class RenderAction<T extends RenderParams> {
         mContext = new BridgeContext(mParams.getProjectKey(), metrics, resources,
                 mParams.getAssets(), mParams.getLayoutlibCallback(), getConfiguration(mParams),
                 mParams.getTargetSdkVersion(), mParams.isRtlSupported());
+        Settings.Global.putFloat(
+                mContext.getContentResolver(),
+                Settings.Global.ANIMATOR_DURATION_SCALE,
+                mParams.getAnimatorDurationScale());
 
         synchronized (sContextLock) {
             sContexts.add(mContext);
@@ -184,6 +188,8 @@ public abstract class RenderAction<T extends RenderParams> {
 
     public void updateHardwareConfiguration(HardwareConfig hardwareConfig) {
         mParams.setHardwareConfig(hardwareConfig);
+        mContext.getConfiguration().setTo(getConfiguration(mParams));
+        mConfigurationUpdated = true;
     }
 
     /**
@@ -431,15 +437,18 @@ public abstract class RenderAction<T extends RenderParams> {
             switch (orientation) {
             case PORTRAIT:
                 config.orientation = Configuration.ORIENTATION_PORTRAIT;
+                config.windowConfiguration.setRotation(ROTATION_0);
                 config.windowConfiguration.setDisplayRotation(ROTATION_0);
                 break;
             case LANDSCAPE:
                 config.orientation = Configuration.ORIENTATION_LANDSCAPE;
+                config.windowConfiguration.setRotation(ROTATION_90);
                 config.windowConfiguration.setDisplayRotation(ROTATION_90);
                 break;
             case SQUARE:
                 //noinspection deprecation
                 config.orientation = Configuration.ORIENTATION_SQUARE;
+                config.windowConfiguration.setRotation(ROTATION_0);
                 config.windowConfiguration.setDisplayRotation(ROTATION_0);
                 break;
             }
diff --git a/bridge/src/com/android/layoutlib/bridge/impl/RenderDrawable.java b/bridge/src/com/android/layoutlib/bridge/impl/RenderDrawable.java
index 371ccbf8d6..b06419b4ca 100644
--- a/bridge/src/com/android/layoutlib/bridge/impl/RenderDrawable.java
+++ b/bridge/src/com/android/layoutlib/bridge/impl/RenderDrawable.java
@@ -40,6 +40,7 @@ import java.awt.image.DataBufferInt;
 import java.util.ArrayList;
 import java.util.Collections;
 import java.util.List;
+import java.util.Objects;
 
 /**
  * Action to render a given {@link Drawable} provided through {@link DrawableParams#getDrawable()}.
@@ -82,7 +83,7 @@ public class RenderDrawable extends RenderAction<DrawableParams> {
         }
 
         Boolean allStates = params.getFlag(RenderParamsFlags.FLAG_KEY_RENDER_ALL_DRAWABLE_STATES);
-        if (allStates == Boolean.TRUE) {
+        if (Objects.equals(allStates, Boolean.TRUE)) {
             List<BufferedImage> result;
 
             if (d instanceof StateListDrawable stateList) {
diff --git a/bridge/src/com/android/layoutlib/bridge/impl/RenderSessionImpl.java b/bridge/src/com/android/layoutlib/bridge/impl/RenderSessionImpl.java
index 1cb50ec565..ab2164e680 100644
--- a/bridge/src/com/android/layoutlib/bridge/impl/RenderSessionImpl.java
+++ b/bridge/src/com/android/layoutlib/bridge/impl/RenderSessionImpl.java
@@ -213,6 +213,7 @@ public class RenderSessionImpl extends RenderAction<SessionParams> {
         if (mMeasuredScreenWidth == -1) {
             mMeasuredScreenWidth = hardwareConfig.getScreenWidth();
             mMeasuredScreenHeight = hardwareConfig.getScreenHeight();
+            mContentRoot.forceLayout();
         }
 
         RenderingMode renderingMode = params.getRenderingMode();
@@ -482,6 +483,11 @@ public class RenderSessionImpl extends RenderAction<SessionParams> {
                 return ERROR_NOT_INFLATED.createResult();
             }
 
+            if (mConfigurationUpdated) {
+                mViewRoot.dispatchConfigurationChanged(getContext().getConfiguration());
+                mConfigurationUpdated = false;
+            }
+
             measureLayout(params);
 
             float scaleX = 1.0f;
diff --git a/bridge/src/com/android/layoutlib/bridge/util/InsetUtil.java b/bridge/src/com/android/layoutlib/bridge/util/InsetUtil.java
index 6d5abec4c4..186bd02f7c 100644
--- a/bridge/src/com/android/layoutlib/bridge/util/InsetUtil.java
+++ b/bridge/src/com/android/layoutlib/bridge/util/InsetUtil.java
@@ -75,8 +75,8 @@ public class InsetUtil {
             if (provider.getMinimalInsetsSizeInDisplayCutoutSafe() != null) {
                 tmpRect.set(sourceFrame);
             }
-            source.updateSideHint(currentBounds);
             calculateInsetsFrame(sourceFrame, insets);
+            source.updateSideHint(currentBounds);
 
             if (provider.getMinimalInsetsSizeInDisplayCutoutSafe() != null) {
                 // The insets is at least with the given size within the display cutout safe area.
@@ -161,7 +161,7 @@ public class InsetUtil {
                         WindowManager.LayoutParams.FLAG_SPLIT_TOUCH |
                         WindowManager.LayoutParams.FLAG_SLIPPERY, PixelFormat.TRANSLUCENT);
         lp.gravity = gravity;
-        lp.providedInsets = getInsetsFrameProvider(navBar, insetsHeight, context);
+        lp.providedInsets = getInsetsFrameProvider(navBar, insetsHeight, width, context);
 
         lp.privateFlags |= WindowManager.LayoutParams.PRIVATE_FLAG_COLOR_SPACE_AGNOSTIC |
                 WindowManager.LayoutParams.PRIVATE_FLAG_LAYOUT_SIZE_EXTENDED_BY_CUTOUT;
@@ -171,11 +171,13 @@ public class InsetUtil {
 
     // Copied/adapted from packages/SystemUI/src/com/android/systemui/navigationbar/NavigationBar.java
     private static InsetsFrameProvider[] getInsetsFrameProvider(View navBar, int insetsHeight,
-            Context userContext) {
+            int insetWidth, Context userContext) {
         final InsetsFrameProvider navBarProvider =
                 new InsetsFrameProvider(navBar, 0, WindowInsets.Type.navigationBars());
         if (insetsHeight != -1) {
             navBarProvider.setInsetsSize(Insets.of(0, 0, 0, insetsHeight));
+        } else if (insetWidth != -1) {
+            navBarProvider.setInsetsSize(Insets.of(0, 0, insetWidth, 0));
         }
         final boolean needsScrim = userContext.getResources().getBoolean(
                 com.android.internal.R.bool.config_navBarNeedsScrim);
diff --git a/bridge/src/libcore/io/BlockGuardOs_Delegate.java b/bridge/src/libcore/io/BlockGuardOs_Delegate.java
new file mode 100644
index 0000000000..69b4f11895
--- /dev/null
+++ b/bridge/src/libcore/io/BlockGuardOs_Delegate.java
@@ -0,0 +1,34 @@
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
+package libcore.io;
+
+import com.android.tools.layoutlib.annotations.LayoutlibDelegate;
+
+import android.system.ErrnoException;
+
+import java.io.FileDescriptor;
+
+
+public class BlockGuardOs_Delegate {
+    @LayoutlibDelegate
+    public static void close(BlockGuardOs blockGuardOs, FileDescriptor fd) {
+        try {
+            blockGuardOs.delegate().close(fd);
+        } catch (ErrnoException e) {
+        }
+    }
+}
diff --git a/bridge/tests/res/testApp/MyApplication/golden/activity.png b/bridge/tests/res/testApp/MyApplication/golden/activity.png
index c0d57856ed..b2222cfa9c 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/activity.png and b/bridge/tests/res/testApp/MyApplication/golden/activity.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/allwidgets.png b/bridge/tests/res/testApp/MyApplication/golden/allwidgets.png
index d22ba99053..d7bc2b61cf 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/allwidgets.png and b/bridge/tests/res/testApp/MyApplication/golden/allwidgets.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/allwidgets_resized.png b/bridge/tests/res/testApp/MyApplication/golden/allwidgets_resized.png
index 617b05ce37..28cc3da9a2 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/allwidgets_resized.png and b/bridge/tests/res/testApp/MyApplication/golden/allwidgets_resized.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/allwidgets_tab.png b/bridge/tests/res/testApp/MyApplication/golden/allwidgets_tab.png
index 4a1ec67a11..df2086384c 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/allwidgets_tab.png and b/bridge/tests/res/testApp/MyApplication/golden/allwidgets_tab.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/array_check.png b/bridge/tests/res/testApp/MyApplication/golden/array_check.png
index db6e934548..895ccee074 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/array_check.png and b/bridge/tests/res/testApp/MyApplication/golden/array_check.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/button_resize.png b/bridge/tests/res/testApp/MyApplication/golden/button_resize.png
index 5c3df0d1b7..4633f80538 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/button_resize.png and b/bridge/tests/res/testApp/MyApplication/golden/button_resize.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/button_resize2.png b/bridge/tests/res/testApp/MyApplication/golden/button_resize2.png
index c806502d58..20fb5ba1df 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/button_resize2.png and b/bridge/tests/res/testApp/MyApplication/golden/button_resize2.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/dark_gesture_nav.png b/bridge/tests/res/testApp/MyApplication/golden/dark_gesture_nav.png
index c893927fd4..4b9fc9df06 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/dark_gesture_nav.png and b/bridge/tests/res/testApp/MyApplication/golden/dark_gesture_nav.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/dark_status_bar.png b/bridge/tests/res/testApp/MyApplication/golden/dark_status_bar.png
index 871188c397..a446234c01 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/dark_status_bar.png and b/bridge/tests/res/testApp/MyApplication/golden/dark_status_bar.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/dialog.png b/bridge/tests/res/testApp/MyApplication/golden/dialog.png
index 2f029e5a52..4e45a792ad 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/dialog.png and b/bridge/tests/res/testApp/MyApplication/golden/dialog.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/font_test.png b/bridge/tests/res/testApp/MyApplication/golden/font_test.png
index e036c162ad..f2fe595444 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/font_test.png and b/bridge/tests/res/testApp/MyApplication/golden/font_test.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/four_corners.png b/bridge/tests/res/testApp/MyApplication/golden/four_corners.png
index dc41617323..ece66f3d8a 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/four_corners.png and b/bridge/tests/res/testApp/MyApplication/golden/four_corners.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/four_corners_translucent.png b/bridge/tests/res/testApp/MyApplication/golden/four_corners_translucent.png
index dc41617323..ece66f3d8a 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/four_corners_translucent.png and b/bridge/tests/res/testApp/MyApplication/golden/four_corners_translucent.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/four_corners_translucent_land.png b/bridge/tests/res/testApp/MyApplication/golden/four_corners_translucent_land.png
index 783d52f874..d9937e4720 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/four_corners_translucent_land.png and b/bridge/tests/res/testApp/MyApplication/golden/four_corners_translucent_land.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/hole_cutout.png b/bridge/tests/res/testApp/MyApplication/golden/hole_cutout.png
index 9ca7777be0..83c700d8ed 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/hole_cutout.png and b/bridge/tests/res/testApp/MyApplication/golden/hole_cutout.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/hole_cutout_landscape.png b/bridge/tests/res/testApp/MyApplication/golden/hole_cutout_landscape.png
index fd0eba67d9..66fd34be94 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/hole_cutout_landscape.png and b/bridge/tests/res/testApp/MyApplication/golden/hole_cutout_landscape.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/hyphenation.png b/bridge/tests/res/testApp/MyApplication/golden/hyphenation.png
index 75df6d83a4..fb5ec388c4 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/hyphenation.png and b/bridge/tests/res/testApp/MyApplication/golden/hyphenation.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/justified_inter_word.png b/bridge/tests/res/testApp/MyApplication/golden/justified_inter_word.png
index 48078217cb..ed4325b17b 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/justified_inter_word.png and b/bridge/tests/res/testApp/MyApplication/golden/justified_inter_word.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/justified_none.png b/bridge/tests/res/testApp/MyApplication/golden/justified_none.png
index e083346b66..c9ae4f2346 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/justified_none.png and b/bridge/tests/res/testApp/MyApplication/golden/justified_none.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/land_gesture_nav.png b/bridge/tests/res/testApp/MyApplication/golden/land_gesture_nav.png
index 0450e0b1e8..7990daa84b 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/land_gesture_nav.png and b/bridge/tests/res/testApp/MyApplication/golden/land_gesture_nav.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/light_gesture_nav.png b/bridge/tests/res/testApp/MyApplication/golden/light_gesture_nav.png
index db0b4ea0e6..5c929eab2c 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/light_gesture_nav.png and b/bridge/tests/res/testApp/MyApplication/golden/light_gesture_nav.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/light_status_bar.png b/bridge/tests/res/testApp/MyApplication/golden/light_status_bar.png
index 871188c397..a446234c01 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/light_status_bar.png and b/bridge/tests/res/testApp/MyApplication/golden/light_status_bar.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/many_line_breaks.png b/bridge/tests/res/testApp/MyApplication/golden/many_line_breaks.png
index ea5750c79c..6826591fac 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/many_line_breaks.png and b/bridge/tests/res/testApp/MyApplication/golden/many_line_breaks.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/rtl_ltr.png b/bridge/tests/res/testApp/MyApplication/golden/rtl_ltr.png
index fab98dc2d4..d2f7ffb681 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/rtl_ltr.png and b/bridge/tests/res/testApp/MyApplication/golden/rtl_ltr.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/typed_arrays.png b/bridge/tests/res/testApp/MyApplication/golden/typed_arrays.png
index e3f4df7c20..32a027d1d0 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/typed_arrays.png and b/bridge/tests/res/testApp/MyApplication/golden/typed_arrays.png differ
diff --git a/bridge/tests/res/testApp/MyApplication/golden/view_stub.png b/bridge/tests/res/testApp/MyApplication/golden/view_stub.png
index b66ff2d524..4e932fa385 100644
Binary files a/bridge/tests/res/testApp/MyApplication/golden/view_stub.png and b/bridge/tests/res/testApp/MyApplication/golden/view_stub.png differ
diff --git a/bridge/tests/src/android/provider/Settings_Global_DelegateTest.java b/bridge/tests/src/android/provider/Settings_Global_DelegateTest.java
new file mode 100644
index 0000000000..d0207d9ac4
--- /dev/null
+++ b/bridge/tests/src/android/provider/Settings_Global_DelegateTest.java
@@ -0,0 +1,101 @@
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
+package android.provider;
+
+import com.android.ide.common.rendering.api.SessionParams;
+import com.android.layoutlib.bridge.Bridge;
+import com.android.layoutlib.bridge.android.BridgeContentResolver;
+import com.android.layoutlib.bridge.android.BridgeContext;
+import com.android.layoutlib.bridge.android.RenderTestBase;
+import com.android.layoutlib.bridge.impl.RenderAction;
+import com.android.layoutlib.bridge.intensive.LayoutLibTestCallback;
+import com.android.layoutlib.bridge.intensive.setup.LayoutPullParser;
+
+import org.junit.BeforeClass;
+import org.junit.Test;
+
+import android.content.ContentResolver;
+import android.content.res.Configuration;
+import android.provider.Settings.SettingNotFoundException;
+import android.util.DisplayMetrics;
+
+import static org.junit.Assert.assertEquals;
+
+public class Settings_Global_DelegateTest extends RenderTestBase {
+    private String name = "Setting Name";
+    private String value = "value";
+    private int intValue = 5;
+
+    @BeforeClass
+    public static void setUp() {
+        Bridge.prepareThread();
+    }
+
+    @Test
+    public void fullCircleString() {
+        // Setup
+        // Create the layout pull parser for our resources (empty.xml can not be part of the test
+        // app as it won't compile).
+        LayoutPullParser parser = LayoutPullParser.createFromPath("/empty.xml");
+        // Create LayoutLibCallback.
+        LayoutLibTestCallback layoutLibCallback =
+                new LayoutLibTestCallback(getLogger(), mDefaultClassLoader);
+        SessionParams params = getSessionParamsBuilder()
+                .setParser(parser)
+                .setCallback(layoutLibCallback)
+                .setTheme("Theme.Material", false)
+                .build();
+        DisplayMetrics metrics = new DisplayMetrics();
+        Configuration configuration = RenderAction.getConfiguration(params);
+        BridgeContext context = new BridgeContext(params.getProjectKey(), metrics, params.getResources(),
+                params.getAssets(), params.getLayoutlibCallback(), configuration,
+                params.getTargetSdkVersion(), params.isRtlSupported());
+        context.initResources(params.getAssets());
+        ContentResolver cr = new BridgeContentResolver(context);
+
+        //String round trip
+        Settings_Secure_Delegate.putStringForUser(cr, name, value, "", false, 0, false);
+        String retrievedValue = Settings_Secure_Delegate.getStringForUser(cr, name, 5);
+        assertEquals(retrievedValue, value);
+
+        // int round trip
+        Settings.Global.putInt(cr, name, intValue);
+        try {
+            assertEquals(intValue, Settings.Secure.getInt(cr, name));
+        } catch (SettingNotFoundException e) {
+            throw new RuntimeException(e);
+        }
+
+        // long round trip
+        Settings.Global.putLong(cr, name, intValue);
+        try {
+            assertEquals(intValue, Settings.Secure.getLong(cr, name));
+        } catch (SettingNotFoundException e) {
+            throw new RuntimeException(e);
+        }
+
+        // float round trip
+        Settings.Global.putFloat(cr, name, (float) intValue);
+        try {
+            assertEquals((float) intValue, Settings.Global.getFloat(cr, name),0);
+        } catch (SettingNotFoundException e) {
+            throw new RuntimeException(e);
+        } finally {
+            context.disposeResources();
+        }
+
+    }
+}
\ No newline at end of file
diff --git a/bridge/tests/src/android/provider/Settings_Secure_DelegateTest.java b/bridge/tests/src/android/provider/Settings_Secure_DelegateTest.java
new file mode 100644
index 0000000000..65bafa2580
--- /dev/null
+++ b/bridge/tests/src/android/provider/Settings_Secure_DelegateTest.java
@@ -0,0 +1,101 @@
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
+package android.provider;
+
+import com.android.ide.common.rendering.api.SessionParams;
+import com.android.layoutlib.bridge.Bridge;
+import com.android.layoutlib.bridge.android.BridgeContentResolver;
+import com.android.layoutlib.bridge.android.BridgeContext;
+import com.android.layoutlib.bridge.android.RenderTestBase;
+import com.android.layoutlib.bridge.impl.RenderAction;
+import com.android.layoutlib.bridge.intensive.LayoutLibTestCallback;
+import com.android.layoutlib.bridge.intensive.setup.LayoutPullParser;
+
+import org.junit.BeforeClass;
+import org.junit.Test;
+
+import android.content.ContentResolver;
+import android.content.res.Configuration;
+import android.provider.Settings.SettingNotFoundException;
+import android.util.DisplayMetrics;
+
+import static org.junit.Assert.assertEquals;
+
+public class Settings_Secure_DelegateTest extends RenderTestBase {
+    private String name = "Setting Name";
+    private String value = "value";
+    private int intValue = 5;
+
+    @BeforeClass
+    public static void setUp() {
+        Bridge.prepareThread();
+    }
+
+    @Test
+    public void fullCircleString() {
+        // Setup
+        // Create the layout pull parser for our resources (empty.xml can not be part of the test
+        // app as it won't compile).
+        LayoutPullParser parser = LayoutPullParser.createFromPath("/empty.xml");
+        // Create LayoutLibCallback.
+        LayoutLibTestCallback layoutLibCallback =
+                new LayoutLibTestCallback(getLogger(), mDefaultClassLoader);
+        SessionParams params =
+                getSessionParamsBuilder().setParser(parser).setCallback(layoutLibCallback).setTheme(
+                        "Theme.Material", false).build();
+        DisplayMetrics metrics = new DisplayMetrics();
+        Configuration configuration = RenderAction.getConfiguration(params);
+        BridgeContext context =
+                new BridgeContext(params.getProjectKey(), metrics, params.getResources(),
+                        params.getAssets(), params.getLayoutlibCallback(), configuration,
+                        params.getTargetSdkVersion(), params.isRtlSupported());
+        context.initResources(params.getAssets());
+        ContentResolver cr = new BridgeContentResolver(context);
+
+        //String round trip
+        Settings_Secure_Delegate.putStringForUser(cr, name, value, "", false, 0, false);
+        String retrievedValue = Settings_Secure_Delegate.getStringForUser(cr, name, 5);
+        assertEquals(retrievedValue, value);
+
+        // int round trip
+        Settings.Global.putInt(cr, name, intValue);
+        try {
+            assertEquals(intValue, Settings.Secure.getInt(cr, name));
+        } catch (SettingNotFoundException e) {
+            throw new RuntimeException(e);
+        }
+
+        // long round trip
+        Settings.Global.putLong(cr, name, intValue);
+        try {
+            assertEquals(intValue, Settings.Secure.getLong(cr, name));
+        } catch (SettingNotFoundException e) {
+            throw new RuntimeException(e);
+        }
+
+        // float round trip
+        Settings.Global.putFloat(cr, name, (float) intValue);
+        try {
+            assertEquals((float) intValue, Settings.Secure.getFloat(cr, name), 0);
+        } catch (SettingNotFoundException e) {
+            throw new RuntimeException(e);
+        } finally {
+            context.disposeResources();
+        }
+
+    }
+}
\ No newline at end of file
diff --git a/bridge/tests/src/android/provider/Settings_System_DelegateTest.java b/bridge/tests/src/android/provider/Settings_System_DelegateTest.java
new file mode 100644
index 0000000000..74961db2bd
--- /dev/null
+++ b/bridge/tests/src/android/provider/Settings_System_DelegateTest.java
@@ -0,0 +1,103 @@
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
+
+package android.provider;
+
+import com.android.ide.common.rendering.api.SessionParams;
+import com.android.layoutlib.bridge.Bridge;
+import com.android.layoutlib.bridge.android.BridgeContentResolver;
+import com.android.layoutlib.bridge.android.BridgeContext;
+import com.android.layoutlib.bridge.android.RenderTestBase;
+import com.android.layoutlib.bridge.impl.RenderAction;
+import com.android.layoutlib.bridge.intensive.LayoutLibTestCallback;
+import com.android.layoutlib.bridge.intensive.setup.LayoutPullParser;
+
+import org.junit.BeforeClass;
+import org.junit.Test;
+
+import android.content.ContentResolver;
+import android.content.res.Configuration;
+import android.provider.Settings.SettingNotFoundException;
+import android.util.DisplayMetrics;
+
+import static org.junit.Assert.assertEquals;
+
+public class Settings_System_DelegateTest extends RenderTestBase {
+    private String name = "Setting Name";
+    private String value = "value";
+    private int intValue = 5;
+
+    @BeforeClass
+    public static void setUp() {
+        Bridge.prepareThread();
+    }
+
+    @Test
+    public void fullCircleString() {
+        // Setup
+        // Create the layout pull parser for our resources (empty.xml can not be part of the test
+        // app as it won't compile).
+        LayoutPullParser parser = LayoutPullParser.createFromPath("/empty.xml");
+        // Create LayoutLibCallback.
+        LayoutLibTestCallback layoutLibCallback =
+                new LayoutLibTestCallback(getLogger(), mDefaultClassLoader);
+        SessionParams params =
+                getSessionParamsBuilder().setParser(parser).setCallback(layoutLibCallback).setTheme(
+                        "Theme.Material", false).build();
+        DisplayMetrics metrics = new DisplayMetrics();
+        Configuration configuration = RenderAction.getConfiguration(params);
+        BridgeContext context =
+                new BridgeContext(params.getProjectKey(), metrics, params.getResources(),
+                        params.getAssets(), params.getLayoutlibCallback(), configuration,
+                        params.getTargetSdkVersion(), params.isRtlSupported());
+        context.initResources(params.getAssets());
+        ContentResolver cr = new BridgeContentResolver(context);
+
+        //String round trip
+        Settings_System_Delegate.putStringForUser(cr, name, value, "", false, 0, false);
+        String retrievedValue = Settings_System_Delegate.getStringForUser(cr, name, 5);
+        assertEquals(retrievedValue, value);
+
+        // int round trip
+        Settings.Global.putInt(cr, name, intValue);
+        try {
+            assertEquals(intValue, Settings.System.getInt(cr, name));
+        } catch (SettingNotFoundException e) {
+            throw new RuntimeException(e);
+        }
+
+        // long round trip
+        Settings.Global.putLong(cr, name, intValue);
+        try {
+            assertEquals(intValue, Settings.System.getLong(cr, name));
+        } catch (SettingNotFoundException e) {
+            throw new RuntimeException(e);
+        }
+
+        // float round trip
+        Settings.Global.putFloat(cr, name, (float) intValue);
+        try {
+            assertEquals((float) intValue, Settings.System.getFloat(cr, name), 0);
+        } catch (SettingNotFoundException e) {
+            throw new RuntimeException(e);
+        } finally {
+            context.disposeResources();
+        }
+
+    }
+}
+
diff --git a/bridge/tests/src/com/android/layoutlib/bridge/android/BridgeContextTest.java b/bridge/tests/src/com/android/layoutlib/bridge/android/BridgeContextTest.java
index 215da97471..0bafda06ce 100644
--- a/bridge/tests/src/com/android/layoutlib/bridge/android/BridgeContextTest.java
+++ b/bridge/tests/src/com/android/layoutlib/bridge/android/BridgeContextTest.java
@@ -179,17 +179,15 @@ public class BridgeContextTest extends RenderTestBase {
                 params.getTargetSdkVersion(), params.isRtlSupported());
         context.initResources(params.getAssets());
         try {
-            assertEquals(-13684682, context.getResources().getColor(android.R.color.system_neutral1_800, null));
+            assertEquals(-13684683, context.getResources().getColor(android.R.color.system_neutral1_800, null));
 
             ((DynamicRenderResources) context.getRenderResources()).setWallpaper(
-                    "/com/android/layoutlib/testdata/wallpaper1.webp",
-                    configuration.isNightModeActive());
-            assertEquals(-13029845, context.getResources().getColor(android.R.color.system_neutral1_800, null));
+                    "/com/android/layoutlib/testdata/wallpaper1.webp");
+            assertEquals(-13160916, context.getResources().getColor(android.R.color.system_neutral1_800, null));
 
             ((DynamicRenderResources) context.getRenderResources()).setWallpaper(
-                    "/com/android/layoutlib/testdata/wallpaper2.webp",
-                    configuration.isNightModeActive());
-            assertEquals(-13946321, context.getResources().getColor(android.R.color.system_neutral1_800, null));
+                    "/com/android/layoutlib/testdata/wallpaper2.webp");
+            assertEquals(-13815505, context.getResources().getColor(android.R.color.system_neutral1_800, null));
         } finally {
             context.disposeResources();
         }
diff --git a/bridge/tests/src/com/android/layoutlib/bridge/android/DynamicRenderResourcesTest.java b/bridge/tests/src/com/android/layoutlib/bridge/android/DynamicRenderResourcesTest.java
index 509c38f493..5616dd95e5 100644
--- a/bridge/tests/src/com/android/layoutlib/bridge/android/DynamicRenderResourcesTest.java
+++ b/bridge/tests/src/com/android/layoutlib/bridge/android/DynamicRenderResourcesTest.java
@@ -35,31 +35,31 @@ public class DynamicRenderResourcesTest extends RenderTestBase {
     @Test
     public void createDynamicTheme() {
         Map<String, Integer> dynamicColorMap = DynamicRenderResources.createDynamicColorMap(
-                "/com/android/layoutlib/testdata/wallpaper1.webp", false);
+                "/com/android/layoutlib/testdata/wallpaper1.webp");
         assertNotNull(dynamicColorMap);
-        assertEquals(-1, (int)dynamicColorMap.get("system_accent1_0"));
-        assertEquals(-4632, (int)dynamicColorMap.get("system_accent1_50"));
-        assertEquals(-1403268, (int)dynamicColorMap.get("system_accent1_300"));
-        assertEquals(-11198451, (int)dynamicColorMap.get("system_accent1_800"));
-        assertEquals(-1, (int)dynamicColorMap.get("system_accent2_0"));
-        assertEquals(-4632, (int)dynamicColorMap.get("system_accent2_50"));
-        assertEquals(-3497321, (int)dynamicColorMap.get("system_accent2_300"));
-        assertEquals(-12309982, (int)dynamicColorMap.get("system_accent2_800"));
-        assertEquals(-1, (int)dynamicColorMap.get("system_accent3_0"));
-        assertEquals(-3900, (int)dynamicColorMap.get("system_accent3_50"));
-        assertEquals(-4478092, (int)dynamicColorMap.get("system_accent3_300"));
-        assertEquals(-12963835, (int)dynamicColorMap.get("system_accent3_800"));
-        assertEquals(-1, (int)dynamicColorMap.get("system_neutral1_0"));
-        assertEquals(-4632, (int)dynamicColorMap.get("system_neutral1_50"));
-        assertEquals(-4675421, (int)dynamicColorMap.get("system_neutral1_300"));
-        assertEquals(-13029845, (int)dynamicColorMap.get("system_neutral1_800"));
-        assertEquals(-1, (int)dynamicColorMap.get("system_neutral2_0"));
-        assertEquals(-4632, (int)dynamicColorMap.get("system_neutral2_50"));
-        assertEquals(-4413535, (int)dynamicColorMap.get("system_neutral2_300"));
-        assertEquals(-12899031, (int)dynamicColorMap.get("system_neutral2_800"));
+        assertEquals(-1, (int)dynamicColorMap.get("system_accent1_0_light"));
+        assertEquals(-4632, (int)dynamicColorMap.get("system_accent1_50_light"));
+        assertEquals(-1795711, (int)dynamicColorMap.get("system_accent1_300_light"));
+        assertEquals(-11394543, (int)dynamicColorMap.get("system_accent1_800_light"));
+        assertEquals(-1, (int)dynamicColorMap.get("system_accent2_0_light"));
+        assertEquals(-4632, (int)dynamicColorMap.get("system_accent2_50_light"));
+        assertEquals(-3497321, (int)dynamicColorMap.get("system_accent2_300_light"));
+        assertEquals(-12309982, (int)dynamicColorMap.get("system_accent2_800_light"));
+        assertEquals(-1, (int)dynamicColorMap.get("system_accent3_0_light"));
+        assertEquals(-4138, (int)dynamicColorMap.get("system_accent3_50_light"));
+        assertEquals(-3692695, (int)dynamicColorMap.get("system_accent3_300_light"));
+        assertEquals(-12571392, (int)dynamicColorMap.get("system_accent3_800_light"));
+        assertEquals(-1, (int)dynamicColorMap.get("system_neutral1_0_light"));
+        assertEquals(-135703, (int)dynamicColorMap.get("system_neutral1_50_light"));
+        assertEquals(-4806492, (int)dynamicColorMap.get("system_neutral1_300_light"));
+        assertEquals(-13160916, (int)dynamicColorMap.get("system_neutral1_800_light"));
+        assertEquals(-1, (int)dynamicColorMap.get("system_neutral2_0_light"));
+        assertEquals(-4632, (int)dynamicColorMap.get("system_neutral2_50_light"));
+        assertEquals(-4413536, (int)dynamicColorMap.get("system_neutral2_300_light"));
+        assertEquals(-12833495, (int)dynamicColorMap.get("system_neutral2_800_light"));
 
-        assertEquals(-8956083, (int)dynamicColorMap.get("system_secondary_light"));
+        assertEquals(-8890290, (int)dynamicColorMap.get("system_secondary_light"));
         assertEquals(-1589839, (int)dynamicColorMap.get("system_secondary_dark"));
-        assertEquals(-12973312, (int)dynamicColorMap.get("system_on_primary_fixed"));
+        assertEquals(-12117750, (int)dynamicColorMap.get("system_on_primary_fixed"));
     }
 }
diff --git a/bridge/tests/src/com/android/layoutlib/bridge/intensive/Main.java b/bridge/tests/src/com/android/layoutlib/bridge/intensive/Main.java
index 062a27413e..bd27034059 100644
--- a/bridge/tests/src/com/android/layoutlib/bridge/intensive/Main.java
+++ b/bridge/tests/src/com/android/layoutlib/bridge/intensive/Main.java
@@ -37,20 +37,22 @@ import org.junit.runners.Suite.SuiteClasses;
 
 import android.content.res.BridgeTypedArrayTest;
 import android.content.res.Resources_DelegateTest;
+import android.provider.Settings_Secure_DelegateTest;
+import android.provider.Settings_Global_DelegateTest;
+import android.provider.Settings_System_DelegateTest;
 import android.util.BridgeXmlPullAttributesTest;
 
 /**
  * Suite used by the layoutlib build system
  */
 @RunWith(Suite.class)
-@SuiteClasses({
-        RenderTests.class, LayoutParserWrapperTest.class,
-        BridgeXmlBlockParserTest.class, BridgeXmlPullAttributesTest.class,
-        TestDelegates.class, BridgeRenderSessionTest.class, ResourceHelperTest.class,
-        BridgeContextTest.class, Resources_DelegateTest.class, ShadowsRenderTests.class,
-        LayoutValidatorTests.class, AccessibilityValidatorTests.class, BridgeTypedArrayTest.class,
-        ValidatorResultTests.class, BitmapTest.class, DynamicRenderResourcesTest.class,
-        AccessibilityTest.class, ChoreographerCallbacksTest.class, HandlerMessageQueueTest.class
-})
+@SuiteClasses({RenderTests.class, LayoutParserWrapperTest.class, Settings_Secure_DelegateTest.class,
+        Settings_System_DelegateTest.class, Settings_Global_DelegateTest.class,
+        BridgeXmlBlockParserTest.class, BridgeXmlPullAttributesTest.class, TestDelegates.class,
+        BridgeRenderSessionTest.class, ResourceHelperTest.class, BridgeContextTest.class,
+        Resources_DelegateTest.class, ShadowsRenderTests.class, LayoutValidatorTests.class,
+        AccessibilityValidatorTests.class, BridgeTypedArrayTest.class, ValidatorResultTests.class,
+        BitmapTest.class, DynamicRenderResourcesTest.class, AccessibilityTest.class,
+        ChoreographerCallbacksTest.class, HandlerMessageQueueTest.class})
 public class Main {
 }
diff --git a/common/src/com/android/tools/layoutlib/create/NativeConfig.java b/common/src/com/android/tools/layoutlib/create/NativeConfig.java
index aaf27253a7..d56344997d 100644
--- a/common/src/com/android/tools/layoutlib/create/NativeConfig.java
+++ b/common/src/com/android/tools/layoutlib/create/NativeConfig.java
@@ -91,6 +91,20 @@ public class NativeConfig {
             "android.graphics.fonts.SystemFonts#mmap",
             "android.os.Binder#getNativeBBinderHolder",
             "android.os.Binder#getNativeFinalizer",
+            "android.os.Trace#isTagEnabled",
+            "android.os.Trace#traceCounter",
+            "android.os.Trace#executeCallbacks",
+            "android.os.Trace#setAppTracingAllowed",
+            "android.os.Trace#setTracingEnabled",
+            "android.os.Trace#traceBegin",
+            "android.os.Trace#traceEnd",
+            "android.os.Trace#asyncTraceBegin",
+            "android.os.Trace#asyncTraceEnd",
+            "android.os.Trace#asyncTraceForTrackBegin",
+            "android.os.Trace#asyncTraceForTrackEnd",
+            "android.os.Trace#instant",
+            "android.os.Trace#instantForTrack",
+            "android.os.Trace#isEnabled",
             "android.os.Handler#sendMessageAtFrontOfQueue",
             "android.os.Handler#sendMessageAtTime",
             "android.os.HandlerThread#run",
@@ -113,8 +127,13 @@ public class NativeConfig {
             "android.provider.DeviceConfig#getProperty",
             "android.provider.DeviceConfig#getString",
             "android.provider.Settings$Config#getContentResolver",
+            "android.provider.Settings$Secure#getStringForUser",
+            "android.provider.Settings$Secure#putStringForUser",
+            "android.provider.Settings$Global#getStringForUser",
+            "android.provider.Settings$Global#putStringForUser",
+            "android.provider.Settings$System#getStringForUser",
+            "android.provider.Settings$System#putStringForUser",
             "android.text.format.DateFormat#is24HourFormat",
-            "android.tracing.Flags#perfettoProtologTracing",
             "android.util.Pools$SimplePool#acquire",
             "android.util.Pools$SimplePool#release",
             "android.util.Xml#newPullParser",
@@ -145,13 +164,16 @@ public class NativeConfig {
             "android.view.WindowManagerGlobal#getWindowManagerService",
             "android.view.accessibility.AccessibilityManager#getInstance",
             "android.view.accessibility.AccessibilityManager#getWindowTransformationSpec",
-            "android.view.flags.Flags#sensitiveContentAppProtection",
             "android.view.inputmethod.InputMethodManager#hideSoftInputFromWindow",
             "android.view.inputmethod.InputMethodManager#isInEditMode",
             "android.view.inputmethod.InputMethodManager#showSoftInput",
             "android.widget.AbsListView#setupDeviceConfigProperties",
             "android.widget.Magnifier#show",
             "android.widget.RemoteViews#getApplicationInfo",
+            // Android framework build jarjars Flag classes,
+            // adding com.android.internal.hidden_from_bootclasspath to the package
+            "com.android.internal.hidden_from_bootclasspath.android.view.flags.Flags#sensitiveContentAppProtection",
+            "com.android.internal.protolog.ProtoLog#logOnlyToLogcat",
             "com.android.internal.util.XmlUtils#convertValueToInt",
             "com.android.internal.view.menu.MenuBuilder#createNewMenuItem",
             "dalvik.system.VMRuntime#getNotifyNativeInterval",
@@ -160,6 +182,7 @@ public class NativeConfig {
             "libcore.io.MemoryMappedFile#bigEndianIterator",
             "libcore.io.MemoryMappedFile#close",
             "libcore.io.MemoryMappedFile#mmapRO",
+            "libcore.io.BlockGuardOs#close",
             "libcore.util.NativeAllocationRegistry#createMalloced",
     };
 
```

