```diff
diff --git a/proto/car_rotary_controller.proto b/proto/car_rotary_controller.proto
index f8f6554..681b918 100644
--- a/proto/car_rotary_controller.proto
+++ b/proto/car_rotary_controller.proto
@@ -31,28 +31,26 @@ message RotaryService {
   optional int32 ignore_view_clicked_ms = 7;
   optional string ignore_view_clicked_node = 8;
   optional int64 last_view_clicked_time = 9;
-  optional string rotary_input_method = 10;
-  optional string default_touch_input_method = 11;
-  optional string touch_input_method = 12;
-  optional FocusRealDirection hun_nudge_direction = 13;
-  optional FocusRealDirection hun_escape_nudge_direction = 14;
-  repeated int32 off_screen_nudge_global_actions = 15;
-  repeated int32 off_screen_nudge_key_codes = 16;
-  repeated string off_screen_nudge_intents = 17;
-  optional int32 after_scroll_timeout_ms = 18;
-  optional AfterScrollAction after_scroll_action = 19;
-  optional int64 after_scroll_action_until = 20;
-  optional bool in_rotary_mode = 21;
-  optional bool in_direct_manipulation_mode = 22;
-  optional int64 last_rotate_event_time = 23;
-  optional int64 long_press_ms = 24;
-  optional bool long_press_triggered = 25;
-  optional ComponentName foreground_activity = 26;
-  optional int64 after_focus_timeout_ms = 27;
-  optional string pending_focused_node = 28;
-  optional int64 pending_focused_expiration_time = 29;
-  optional Navigator navigator = 30;
-  optional WindowCache window_cache = 31;
+  optional FocusRealDirection hun_nudge_direction = 10;
+  optional FocusRealDirection hun_escape_nudge_direction = 11;
+  repeated int32 off_screen_nudge_global_actions = 12;
+  repeated int32 off_screen_nudge_key_codes = 13;
+  repeated string off_screen_nudge_intents = 14;
+  optional int32 after_scroll_timeout_ms = 15;
+  optional AfterScrollAction after_scroll_action = 16;
+  optional int64 after_scroll_action_until = 17;
+  optional bool in_rotary_mode = 18;
+  optional bool in_direct_manipulation_mode = 19;
+  optional int64 last_rotate_event_time = 20;
+  optional int64 long_press_ms = 21;
+  optional bool long_press_triggered = 22;
+  optional ComponentName foreground_activity = 23;
+  optional int64 after_focus_timeout_ms = 24;
+  optional string pending_focused_node = 25;
+  optional int64 pending_focused_expiration_time = 26;
+  optional Navigator navigator = 27;
+  optional WindowCache window_cache = 28;
+  optional ImeSwitcher ime_switcher = 29;
 }
 
 message Navigator {
@@ -63,6 +61,12 @@ message Navigator {
   optional SurfaceViewHelper surface_view_helper = 5;
 }
 
+message ImeSwitcher {
+  optional string rotary_input_method = 1;
+  optional string default_touch_input_method = 2;
+  optional string touch_input_method = 3;
+}
+
 message SurfaceViewHelper {
   optional string host_app = 1;
   repeated string clientApps = 2;
diff --git a/res/values/overlayable.xml b/res/values/overlayable.xml
index 1280b21..cb21601 100644
--- a/res/values/overlayable.xml
+++ b/res/values/overlayable.xml
@@ -29,8 +29,6 @@ REGENERATE USING packages/apps/Car/tests/tools/rro/generate-overlayable.py
       <item type="integer" name="long_press_ms"/>
       <item type="integer" name="rotation_acceleration_2x_ms"/>
       <item type="integer" name="rotation_acceleration_3x_ms"/>
-      <item type="string" name="default_touch_input_method"/>
-      <item type="string" name="rotary_input_method"/>
     </policy>
   </overlayable>
 </resources>
diff --git a/res/values/strings.xml b/res/values/strings.xml
index c8411ef..d409af8 100644
--- a/res/values/strings.xml
+++ b/res/values/strings.xml
@@ -15,15 +15,6 @@
   ~ limitations under the License.
   -->
 <resources>
-    <!-- Component name of default touch IME. This resource should be overlaid if a device uses an
-         IME other than CarLatinIME. This resource should not be empty. -->
-    <string name="default_touch_input_method" translatable="false">com.android.inputmethod.latin/.CarLatinIME</string>
-    <!-- Component name of rotary IME. Empty if none. The value must be different from
-         default_touch_input_method.
-         If the value is not empty, this IME will be only used in rotary mode; otherwise, touch IME
-         will be used in both touch mode and rotary mode.  -->
-    <string name="rotary_input_method" translatable="false"></string>
-
     <!-- Intents to launch an activity when the user nudges up, down, left, or right off the edge of
          the screen. No activity is launched if the relevant element of this array is empty. -->
     <string-array name="off_screen_nudge_intents" translatable="false">
diff --git a/res/xml/accessibility_service_config.xml b/res/xml/accessibility_service_config.xml
index 9be3774..de70a97 100644
--- a/res/xml/accessibility_service_config.xml
+++ b/res/xml/accessibility_service_config.xml
@@ -18,4 +18,5 @@
     android:accessibilityEventTypes="typeViewFocused|typeViewClicked|typeViewAccessibilityFocused|typeViewAccessibilityFocusCleared|typeViewScrolled|typeWindowStateChanged|typeWindowsChanged"
     android:accessibilityFlags="flagDefault|flagRetrieveInteractiveWindows"
     android:canRequestFilterKeyEvents="true"
-    android:canRetrieveWindowContent="true"/>
+    android:canRetrieveWindowContent="true"
+    android:isAccessibilityTool="true"/>
diff --git a/src/com/android/car/rotary/ImeSwitcher.java b/src/com/android/car/rotary/ImeSwitcher.java
new file mode 100644
index 0000000..ec9f3b7
--- /dev/null
+++ b/src/com/android/car/rotary/ImeSwitcher.java
@@ -0,0 +1,295 @@
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
+package com.android.car.rotary;
+
+import static android.provider.Settings.Secure.DEFAULT_INPUT_METHOD;
+
+import android.content.ContentResolver;
+import android.content.Context;
+import android.content.SharedPreferences;
+import android.content.res.Resources;
+import android.database.ContentObserver;
+import android.os.Handler;
+import android.os.Looper;
+import android.os.UserManager;
+import android.provider.Settings;
+import android.text.TextUtils;
+import android.view.inputmethod.InputMethodInfo;
+import android.view.inputmethod.InputMethodManager;
+import android.view.inputmethod.InputMethodSubtype;
+
+import androidx.annotation.NonNull;
+import androidx.annotation.Nullable;
+
+import com.android.internal.util.dump.DualDumpOutputStream;
+
+import java.util.List;
+import java.util.Locale;
+
+/**
+ * This helper class manages Input Method Editor (IME) switching between rotary and touch modes.
+ * It activates the dedicated rotary IME in rotary mode and the touch IME in touch mode. This class
+ * is only used if a touch IME and a dedicated rotary IME exist.
+ */
+class ImeSwitcher {
+    private static final String SHARED_PREFS = "com.android.car.rotary.ImeSwitcher";
+    private static final String TOUCH_INPUT_METHOD_PREFIX = "TOUCH_INPUT_METHOD_";
+    private static final String INPUT_METHOD_SUBTYPE_MODE_KEYBOARD = "keyboard";
+    private static final String INPUT_METHOD_SUBTYPE_MODE_ROTARY = "rotary";
+
+    @NonNull
+    private final SharedPreferences mPrefs;
+    @NonNull
+    private final InputMethodManager mInputMethodManager;
+    @NonNull
+    private final UserManager mUserManager;
+    @NonNull
+    private final ContentResolver mContentResolver;
+
+    /** Component name of rotary IME. */
+    @NonNull
+    private final String mRotaryInputMethod;
+
+    /** Component name of default IME used in touch mode. */
+    @NonNull
+    private final String mDefaultTouchInputMethod;
+
+    /** Component name of current IME used in touch mode. */
+    @NonNull
+    private String mTouchInputMethod;
+
+    /** Observer to update {@link #mTouchInputMethod} when the user switches IMEs. */
+    @Nullable
+    private ContentObserver mInputMethodObserver;
+
+    private ImeSwitcher(@NonNull Context context,
+            @NonNull InputMethodManager imm,
+            @NonNull ContentResolver contentResolver,
+            @NonNull String rotaryInputMethod,
+            @NonNull String defaultTouchInputMethod) {
+        mContentResolver = contentResolver;
+        mInputMethodManager = imm;
+        mRotaryInputMethod = rotaryInputMethod;
+        mDefaultTouchInputMethod = defaultTouchInputMethod;
+
+        mPrefs = context.createDeviceProtectedStorageContext().getSharedPreferences(
+                SHARED_PREFS, Context.MODE_PRIVATE);
+
+        mUserManager = context.getSystemService(UserManager.class);
+
+        mTouchInputMethod = mPrefs.getString(TOUCH_INPUT_METHOD_PREFIX
+                + mUserManager.getUserName(), mDefaultTouchInputMethod);
+        if (mTouchInputMethod.isEmpty()
+                || !Utils.isInstalledIme(mTouchInputMethod, mInputMethodManager)) {
+            // Workaround for b/323013736.
+            L.e("mTouchInputMethod is empty or not installed!");
+            mTouchInputMethod = mDefaultTouchInputMethod;
+        }
+
+        // Switch from the rotary IME to the touch IME in case RotaryService failed to reset IME
+        // before it was killed (e.g., run `adb reboot` when it is in rotary mode).
+        switchIme(/* inRotaryMode= */ false);
+    }
+
+    /**
+     * Returns an instance of this class as needed.
+     * <p>We only need to switch IME when there is a dedicated rotary IME and a touch IME.
+     * Besides, we need a non-null ContentResolver to set the current IME.
+     */
+    @Nullable
+    static ImeSwitcher getOptionalInstance(@NonNull Context context,
+            @Nullable ContentResolver contentResolver) {
+        if (contentResolver == null) {
+            return null;
+        }
+        InputMethodManager imm = context.getSystemService(InputMethodManager.class);
+        String rotaryInputMethod = getRotaryInputMethod(imm);
+        L.d("rotaryInputMethod: " + rotaryInputMethod);
+        if (TextUtils.isEmpty(rotaryInputMethod)) {
+            return null;
+        }
+        String defaultTouchInputMethod = getDefaultTouchInputMethod(imm);
+        L.d("defaultTouchInputMethod: " + defaultTouchInputMethod);
+        if (TextUtils.isEmpty(defaultTouchInputMethod)) {
+            return null;
+        }
+        return new ImeSwitcher(context, imm, contentResolver, rotaryInputMethod,
+                defaultTouchInputMethod);
+    }
+
+    /**
+     * Registers an observer to updates {@link #mTouchInputMethod} whenever the user switches IMEs.
+     */
+    void registerInputMethodObserver() {
+        if (mInputMethodObserver != null) {
+            throw new IllegalStateException("Input method observer already registered");
+        }
+        mInputMethodObserver = new ContentObserver(new Handler(Looper.myLooper())) {
+            @Override
+            public void onChange(boolean selfChange) {
+                // Either the user switched input methods or we did. In the former case, update
+                // mTouchInputMethod and save it so we can switch back after switching to the rotary
+                // input method.
+                String inputMethod = getCurrentIme();
+                L.d("Current IME changed to " + inputMethod);
+                if (!TextUtils.isEmpty(inputMethod) && !inputMethod.equals(mRotaryInputMethod)) {
+                    mTouchInputMethod = inputMethod;
+                    String userName = mUserManager.getUserName();
+                    L.d("Save mTouchInputMethod(" + mTouchInputMethod + ") for user "
+                            + userName);
+                    mPrefs.edit()
+                            .putString(TOUCH_INPUT_METHOD_PREFIX + userName, mTouchInputMethod)
+                            .apply();
+                }
+            }
+        };
+        mContentResolver.registerContentObserver(
+                Settings.Secure.getUriFor(DEFAULT_INPUT_METHOD),
+                /* notifyForDescendants= */ false,
+                mInputMethodObserver);
+    }
+
+    /** Unregisters the observer registered by {@link #registerInputMethodObserver}. */
+    void unregisterInputMethodObserver() {
+        if (mInputMethodObserver == null) {
+            return;
+        }
+        mContentResolver.unregisterContentObserver(mInputMethodObserver);
+        mInputMethodObserver = null;
+    }
+
+    /** Switches to the rotary IME or the touch IME if needed. */
+    void switchIme(boolean inRotaryMode) {
+        String oldIme = getCurrentIme();
+        if ((inRotaryMode && mRotaryInputMethod.equals(oldIme))
+                || (!inRotaryMode && mTouchInputMethod.equals(oldIme))) {
+            return;
+        }
+        String newIme = inRotaryMode ? mRotaryInputMethod : mTouchInputMethod;
+        setCurrentIme(oldIme, newIme);
+    }
+
+    void dump(@NonNull DualDumpOutputStream dumpOutputStream, @NonNull String fieldName,
+            long fieldId) {
+        long fieldToken = dumpOutputStream.start(fieldName, fieldId);
+        dumpOutputStream.write("rotaryInputMethod", RotaryProtos.ImeSwitcher.ROTARY_INPUT_METHOD,
+                mRotaryInputMethod);
+        dumpOutputStream.write("defaultTouchInputMethod",
+                RotaryProtos.ImeSwitcher.DEFAULT_TOUCH_INPUT_METHOD, mDefaultTouchInputMethod);
+        dumpOutputStream.write("touchInputMethod", RotaryProtos.ImeSwitcher.TOUCH_INPUT_METHOD,
+                mTouchInputMethod);
+        dumpOutputStream.end(fieldToken);
+    }
+
+    @NonNull
+    private String getCurrentIme() {
+        return Settings.Secure.getString(mContentResolver, DEFAULT_INPUT_METHOD);
+    }
+
+    private void setCurrentIme(String oldIme, String newIme) {
+        validateImeConfiguration(newIme);
+        boolean result =
+                Settings.Secure.putString(mContentResolver, DEFAULT_INPUT_METHOD, newIme);
+        L.successOrFailure("Switching IME from " + oldIme + " to " + newIme, result);
+    }
+
+    /**
+     * Ensure that the IME configuration passed as argument is also available in
+     * {@link InputMethodManager}.
+     *
+     * @throws IllegalStateException if the ime configuration passed as argument is not available
+     *                               in {@link InputMethodManager}
+     */
+    private void validateImeConfiguration(String imeConfiguration) {
+        if (!Utils.isInstalledIme(imeConfiguration, mInputMethodManager)) {
+            throw new IllegalStateException(String.format("%s is not installed (run "
+                            + "`adb shell ime list -a -s` to list all installed input methods)",
+                    imeConfiguration));
+        }
+    }
+
+    /**
+     * Similar to IMMS's default IME selection, this method selects an enabled IMEs as follows:
+     * First, it seeks a system non-auxiliary IME with system language subtype and "keyboard"
+     * layout. If unavailable, it defaults to the first system non-auxiliary IME.
+     * If that also isn't found, it selects the very first IME in the enabled list, if there is any.
+     */
+    @Nullable
+    private static String getDefaultTouchInputMethod(InputMethodManager imm) {
+        List<InputMethodInfo> enabledImes = imm.getEnabledInputMethodList();
+        if (enabledImes.isEmpty()) {
+            L.e("No IME enabled! Run `adb shell ime list -s` to list installed input methods ");
+            return null;
+        }
+        // We'd prefer to fall back on a system IME, since that is safer.
+        int i = enabledImes.size();
+        int firstFoundSystemIme = -1;
+        Locale systemLocale = Resources.getSystem().getConfiguration().getLocales().get(0);
+        while (i > 0) {
+            i--;
+            InputMethodInfo imi = enabledImes.get(i);
+            if (imi.isAuxiliaryIme()) {
+                continue;
+            }
+            if (imi.isSystem()
+                    && containsSubtypeOf(imi, systemLocale, INPUT_METHOD_SUBTYPE_MODE_KEYBOARD)) {
+                L.v("Found default touch IME:" + imi);
+                return imi.getComponent().flattenToShortString();
+            }
+            if (firstFoundSystemIme < 0 && imi.isSystem()) {
+                firstFoundSystemIme = i;
+            }
+        }
+        L.v(String.format("Default to %s IME",
+                firstFoundSystemIme >= 0 ? "system non-auxiliary" : " first enabled"));
+        InputMethodInfo imi = enabledImes.get(Math.max(firstFoundSystemIme, 0));
+        return imi.getComponent().flattenToShortString();
+    }
+
+    @Nullable
+    private static String getRotaryInputMethod(InputMethodManager imm) {
+        // getInputMethodList() is used rather than getEnabledInputMethodList() because the Rotary
+        // IME could be installed on the system but not actively enabled.
+        List<InputMethodInfo> installedImes = imm.getInputMethodList();
+        for (InputMethodInfo imi : installedImes) {
+            List<InputMethodSubtype> subtypes = imm.getEnabledInputMethodSubtypeList(imi,
+                    /* allowsImplicitlyEnabledSubtypes= */ true);
+            for (InputMethodSubtype subtype : subtypes) {
+                if (INPUT_METHOD_SUBTYPE_MODE_ROTARY.equals(subtype.getMode())) {
+                    return imi.getComponent().flattenToShortString();
+                }
+            }
+        }
+        return null;
+    }
+
+    private static boolean containsSubtypeOf(@NonNull InputMethodInfo imi, @NonNull Locale locale,
+            @NonNull String mode) {
+        for (int i = 0; i < imi.getSubtypeCount(); ++i) {
+            final InputMethodSubtype subtype = imi.getSubtypeAt(i);
+            if (!subtype.getMode().equals(mode)) {
+                continue;
+            }
+            // Ignore country and check language only.
+            String language = locale.getLanguage();
+            if (subtype.getLocaleObject().getLanguage().equals(language)) {
+                return true;
+            }
+        }
+        return false;
+    }
+}
diff --git a/src/com/android/car/rotary/Navigator.java b/src/com/android/car/rotary/Navigator.java
index 20ab450..fd42699 100644
--- a/src/com/android/car/rotary/Navigator.java
+++ b/src/com/android/car/rotary/Navigator.java
@@ -142,7 +142,7 @@ class Navigator {
     }
 
     /**
-     * Returns the target focusable for a rotate. The caller is responsible for recycling the node
+     * Returns the target focusable for a rotation. The caller is responsible for recycling the node
      * in the result.
      *
      * <p>Limits navigation to focusable views within a scrollable container's viewport, if any.
@@ -168,18 +168,67 @@ class Navigator {
         AccessibilityNodeInfo candidate = copyNode(sourceNode);
         AccessibilityNodeInfo target = null;
         while (advancedCount < rotationCount) {
+
+            // When the WebView is focused and not scrollable, it means it has been scrolled to
+            // its edge (b/416347411). In that case, controller rotation should move focus to the
+            // next/previous focusable View.
+            boolean focusShouldLeaveWebView = false;
+            if (Utils.isWebView(sourceNode)) {
+                AccessibilityNodeInfo.AccessibilityAction scrollAction =
+                        direction == View.FOCUS_FORWARD
+                                ? ACTION_SCROLL_FORWARD
+                                : ACTION_SCROLL_BACKWARD;
+                if (!sourceNode.getActionList().contains(scrollAction)) {
+                    focusShouldLeaveWebView = true;
+                    L.d("Focus should leave WebView and move to an adjacent View");
+                }
+            }
+
             AccessibilityNodeInfo nextCandidate = null;
             // Virtual View hierarchies like WebViews and ComposeViews do not support focusSearch().
             AccessibilityNodeInfo virtualViewAncestor = findVirtualViewAncestor(candidate);
-            if (virtualViewAncestor != null) {
+            if (virtualViewAncestor != null && !focusShouldLeaveWebView) {
+                // Current focus is a virtual node.
                 nextCandidate =
                     findNextFocusableInVirtualRoot(virtualViewAncestor, candidate, direction);
-            }
-            if (nextCandidate == null) {
-                // If we aren't in a virtual node hierarchy, or there aren't any more focusable
-                // nodes within the virtual node hierarchy, use focusSearch().
+                if (nextCandidate == null || Utils.isVirtualView(nextCandidate)) {
+                    // nextCandidate == null happens when handling clockwise rotation from the last
+                    // virtual node, while Utils.isVirtualView(nextCandidate) happens when handling
+                    // counter-clock wise rotation from the first virtual node.
+                    // In either case, we need to move focus out of the virtual view hierarchy.
+                    if (Utils.isComposeView(virtualViewAncestor)
+                            && !virtualViewAncestor.isFocusable()) {
+                        // If the ComposeView is not focusable, ComposeView#focusSearch() will not
+                        // return the next focusable View as expected. Luckily, its only
+                        // child AndroidComposeView#focusSearch() will return the next focusable
+                        // View, so let's call focusSearch() on AndroidComposeView.
+                        nextCandidate = virtualViewAncestor.getChild(0);
+                        L.v("virtualViewAncestor is a non-focusable ComposeView");
+                    } else {
+                        // Otherwise, call focusSearch() on virtualViewAncestor.
+                        nextCandidate =  virtualViewAncestor;
+                        L.v("virtualViewAncestor is not a ComposeView or it's focusable");
+                    }
+                    do {
+                        nextCandidate = nextCandidate.focusSearch(direction);
+                    } while (nextCandidate != null && isInVirtualNodeHierarchy(nextCandidate));
+                    L.v("Moving focus out of virtual view hierarchy");
+                } else {
+                    L.v("Moving focus between virtual nodes");
+                }
+            } else {
+                // Current focus is a View.
                 nextCandidate = candidate.focusSearch(direction);
+                if (nextCandidate != null && isInVirtualNodeHierarchy(nextCandidate)) {
+                    virtualViewAncestor = findVirtualViewAncestor(nextCandidate);
+                    nextCandidate = findNextFocusableInVirtualRoot(
+                            virtualViewAncestor, virtualViewAncestor, direction);
+                    L.v("Moving focus into virtual view hierarchy");
+                } else {
+                    L.v("Moving focus between views");
+                }
             }
+
             AccessibilityNodeInfo candidateFocusArea =
                     nextCandidate == null ? null : getAncestorFocusArea(nextCandidate);
 
@@ -953,7 +1002,8 @@ class Navigator {
                         return false;
                     }
                     // The node represents a focusable view in a focus area, so check the geometry.
-                    return FocusFinder.isCandidate(sourceBounds, nodeBounds, direction);
+                    Rect candidateBounds = Utils.getBoundsInScreen(candidateNode);
+                    return FocusFinder.isCandidate(sourceBounds, candidateBounds, direction);
                 });
         if (candidate == null) {
             return false;
@@ -1017,6 +1067,16 @@ class Navigator {
         return mTreeTraverser.findNodeOrAncestor(node, Utils::isWebView);
     }
 
+    /**
+     * Returns a copy of {@code node} or the ancestor that represents a {@code ComposeView}.
+     * Returns null if {@code node} isn't a {@code ComposeView} and isn't a descendant of a {@code
+     * ComposeView}.
+     */
+    @Nullable
+    private AccessibilityNodeInfo findComposeViewAncestor(@NonNull AccessibilityNodeInfo node) {
+        return mTreeTraverser.findNodeOrAncestor(node, Utils::isComposeView);
+    }
+
     /**
      * Returns a copy of {@code node} or the nearest ancestor that represents a {@code ComposeView}
      * or a {@code WebView}. Returns null if {@code node} isn't a {@code ComposeView} or a
@@ -1026,8 +1086,7 @@ class Navigator {
      */
     @Nullable
     private AccessibilityNodeInfo findVirtualViewAncestor(@NonNull AccessibilityNodeInfo node) {
-        return mTreeTraverser.findNodeOrAncestor(node, /* targetPredicate= */ (nodeInfo) ->
-            Utils.isComposeView(nodeInfo) || Utils.isWebView(nodeInfo));
+        return mTreeTraverser.findNodeOrAncestor(node, Utils::isVirtualView);
     }
 
     /** Returns whether {@code node} is a {@code WebView} or is a descendant of one. */
@@ -1040,6 +1099,16 @@ class Navigator {
         return true;
     }
 
+    /** Returns whether the {@code node} represents a Jetpack Composable. */
+    boolean isComposable(@NonNull AccessibilityNodeInfo node) {
+        AccessibilityNodeInfo composeView = findComposeViewAncestor(node);
+        if (composeView == null) {
+            return false;
+        }
+        composeView.recycle();
+        return true;
+    }
+
     /**
      * Returns whether {@code node} is a {@code ComposeView}, is a {@code WebView}, or is a
      * descendant of either.
diff --git a/src/com/android/car/rotary/RotaryService.java b/src/com/android/car/rotary/RotaryService.java
index 76b610e..41adcd8 100644
--- a/src/com/android/car/rotary/RotaryService.java
+++ b/src/com/android/car/rotary/RotaryService.java
@@ -17,7 +17,6 @@ package com.android.car.rotary;
 
 import static android.accessibilityservice.AccessibilityServiceInfo.FLAG_REQUEST_FILTER_KEY_EVENTS;
 import static android.car.settings.CarSettings.Secure.KEY_ROTARY_KEY_EVENT_FILTER;
-import static android.provider.Settings.Secure.DEFAULT_INPUT_METHOD;
 import static android.view.Display.DEFAULT_DISPLAY;
 import static android.view.KeyEvent.ACTION_DOWN;
 import static android.view.KeyEvent.ACTION_UP;
@@ -43,6 +42,7 @@ import static android.view.accessibility.AccessibilityNodeInfo.ACTION_LONG_CLICK
 import static android.view.accessibility.AccessibilityNodeInfo.ACTION_SELECT;
 import static android.view.accessibility.AccessibilityNodeInfo.AccessibilityAction.ACTION_SCROLL_BACKWARD;
 import static android.view.accessibility.AccessibilityNodeInfo.AccessibilityAction.ACTION_SCROLL_FORWARD;
+import static android.view.accessibility.AccessibilityNodeInfo.FOCUS_INPUT;
 import static android.view.accessibility.AccessibilityWindowInfo.TYPE_APPLICATION;
 import static android.view.accessibility.AccessibilityWindowInfo.TYPE_INPUT_METHOD;
 
@@ -67,7 +67,6 @@ import android.content.ContentResolver;
 import android.content.Context;
 import android.content.Intent;
 import android.content.IntentFilter;
-import android.content.SharedPreferences;
 import android.content.pm.ActivityInfo;
 import android.content.pm.ApplicationInfo;
 import android.content.pm.PackageManager;
@@ -84,7 +83,6 @@ import android.os.Handler;
 import android.os.Looper;
 import android.os.Message;
 import android.os.SystemClock;
-import android.os.UserManager;
 import android.provider.Settings;
 import android.text.TextUtils;
 import android.util.IndentingPrintWriter;
@@ -100,7 +98,6 @@ import android.view.WindowManager;
 import android.view.accessibility.AccessibilityEvent;
 import android.view.accessibility.AccessibilityNodeInfo;
 import android.view.accessibility.AccessibilityWindowInfo;
-import android.view.inputmethod.InputMethodManager;
 import android.widget.FrameLayout;
 
 import androidx.annotation.NonNull;
@@ -124,7 +121,6 @@ import java.util.Collections;
 import java.util.HashMap;
 import java.util.List;
 import java.util.Map;
-import java.util.Objects;
 import java.util.concurrent.ExecutorService;
 import java.util.concurrent.Executors;
 import java.util.stream.Collectors;
@@ -178,9 +174,6 @@ public class RotaryService extends AccessibilityService implements
      */
     private static final int MSG_LONG_PRESS = 1;
 
-    private static final String SHARED_PREFS = "com.android.car.rotary.RotaryService";
-    private static final String TOUCH_INPUT_METHOD_PREFIX = "TOUCH_INPUT_METHOD_";
-
     /**
      * Key for activity metadata indicating that a nudge in the given direction ("up", "down",
      * "left", or "right") that would otherwise do nothing should trigger a global action, e.g.
@@ -252,6 +245,9 @@ public class RotaryService extends AccessibilityService implements
     @NonNull
     private Navigator mNavigator;
 
+    @Nullable
+    private ImeSwitcher mImeSwitcher;
+
     /** Input types to capture. */
     private final int[] mInputTypes = new int[]{
             // Capture controller rotation.
@@ -329,24 +325,9 @@ public class RotaryService extends AccessibilityService implements
      */
     private long mLastViewClickedTime;
 
-    /** Component name of rotary IME. Empty if none. */
-    @Nullable private String mRotaryInputMethod;
-
-    /** Component name of default IME used in touch mode. */
-    @Nullable private String mDefaultTouchInputMethod;
-
-    /** Component name of current IME used in touch mode. */
-    @Nullable private String mTouchInputMethod;
-
-    /** Observer to update {@link #mTouchInputMethod} when the user switches IMEs. */
-    private ContentObserver mInputMethodObserver;
-
     /** Observer to update service info when the developer toggles key event filtering. */
     private ContentObserver mKeyEventFilterObserver;
 
-    private SharedPreferences mPrefs;
-    private UserManager mUserManager;
-
     /**
      * The direction of the HUN. If there is no focused node, or the focused node is outside the
      * HUN, nudging to this direction will focus on a node inside the HUN.
@@ -564,8 +545,6 @@ public class RotaryService extends AccessibilityService implements
 
     @Nullable private ContentResolver mContentResolver;
 
-    @Nullable private InputMethodManager mInputMethodManager;
-
     private final ExecutorService mExecutor = Executors.newSingleThreadExecutor();
 
     private final BroadcastReceiver mAppInstallUninstallReceiver = new BroadcastReceiver() {
@@ -620,39 +599,8 @@ public class RotaryService extends AccessibilityService implements
 
         mNavigator = new Navigator(displayWidth, displayHeight, hunLeft, hunRight, showHunOnBottom);
         mNavigator.initHostApp(getPackageManager());
-
-        mPrefs = createDeviceProtectedStorageContext().getSharedPreferences(SHARED_PREFS,
-                Context.MODE_PRIVATE);
-        mUserManager = getSystemService(UserManager.class);
-
         mInputManager = getSystemService(InputManager.class);
-        mInputMethodManager = getSystemService(InputMethodManager.class);
-        if (mInputMethodManager == null) {
-            throw new IllegalStateException("Failed to get InputMethodManager");
-        }
-
-        mRotaryInputMethod = res.getString(R.string.rotary_input_method);
-        mDefaultTouchInputMethod = res.getString(R.string.default_touch_input_method);
-        L.d("mRotaryInputMethod:" + mRotaryInputMethod + ", mDefaultTouchInputMethod:"
-                + mDefaultTouchInputMethod);
-        validateImeConfiguration(mDefaultTouchInputMethod);
-        mTouchInputMethod = mPrefs.getString(TOUCH_INPUT_METHOD_PREFIX
-                + mUserManager.getUserName(), mDefaultTouchInputMethod);
-        // TODO(b/346437360): use a better way to initialize mTouchInputMethod.
-        if (mTouchInputMethod.isEmpty()
-                || !Utils.isInstalledIme(mTouchInputMethod, mInputMethodManager)) {
-            // Workaround for b/323013736.
-            L.e("mTouchInputMethod is empty or not installed!");
-            mTouchInputMethod = mDefaultTouchInputMethod;
-        }
-
-        if (mRotaryInputMethod != null && mRotaryInputMethod.equals(getCurrentIme())) {
-            // Switch from the rotary IME to the touch IME in case Android defaults to the rotary
-            // IME.
-            // TODO(b/169423887): Figure out how to configure the default IME through Android
-            // without needing to do this.
-            setCurrentIme(mTouchInputMethod);
-        }
+        mImeSwitcher = ImeSwitcher.getOptionalInstance(this, mContentResolver);
 
         mAfterFocusTimeoutMs = res.getInteger(R.integer.after_focus_timeout_ms);
 
@@ -687,21 +635,6 @@ public class RotaryService extends AccessibilityService implements
         registerReceiver(mAppInstallUninstallReceiver, filter);
     }
 
-    /**
-     * Ensure that the IME configuration passed as argument is also available in
-     * {@link InputMethodManager}.
-     *
-     * @throws IllegalStateException if the ime configuration passed as argument is not available
-     *                               in {@link InputMethodManager}
-     */
-    private void validateImeConfiguration(String imeConfiguration) {
-        if (!Utils.isInstalledIme(imeConfiguration, mInputMethodManager)) {
-            throw new IllegalStateException(String.format("%s is not installed (run "
-                            + "`dumpsys input_method` to list all available input methods)",
-                    imeConfiguration));
-        }
-    }
-
     /**
      * {@inheritDoc}
      * <p>
@@ -754,7 +687,9 @@ public class RotaryService extends AccessibilityService implements
         addTouchOverlay();
 
         // Register an observer to update mTouchInputMethod whenever the user switches IMEs.
-        registerInputMethodObserver();
+        if (mImeSwitcher != null) {
+            mImeSwitcher.registerInputMethodObserver();
+        }
 
         // Register an observer to update the service info when the developer changes the filter
         // setting.
@@ -771,8 +706,9 @@ public class RotaryService extends AccessibilityService implements
         L.v("onDestroy");
         mExecutor.shutdown();
         unregisterReceiver(mAppInstallUninstallReceiver);
-
-        unregisterInputMethodObserver();
+        if (mImeSwitcher != null) {
+            mImeSwitcher.unregisterInputMethodObserver();
+        }
         unregisterFilterObserver();
         removeTouchOverlay();
         if (mCarInputManager != null) {
@@ -782,9 +718,12 @@ public class RotaryService extends AccessibilityService implements
             mCar.disconnect();
         }
 
-        // Reset to touch IME if the current IME is rotary IME.
         mInRotaryMode = false;
-        updateIme();
+        // Reset to touch IME if the current IME is rotary IME.
+        // Note: onDestroy() might not be called, so this is just the best effort.
+        if (mImeSwitcher != null) {
+            mImeSwitcher.switchIme(mInRotaryMode);
+        }
 
         super.onDestroy();
     }
@@ -971,7 +910,9 @@ public class RotaryService extends AccessibilityService implements
 
         // Set mFocusedNode to null when user uses touch.
         if (mFocusedNode != null) {
-            setFocusedNode(null);
+            // Don't call setFocusedNode(), otherwise it will move focus to the FocusParkingView
+            // unnecessarily.
+            setFocusedNodeInternal(null);
         }
     }
 
@@ -1002,52 +943,6 @@ public class RotaryService extends AccessibilityService implements
         setServiceInfo(serviceInfo);
     }
 
-    /**
-     * Registers an observer to updates {@link #mTouchInputMethod} whenever the user switches IMEs.
-     */
-    private void registerInputMethodObserver() {
-        if (mInputMethodObserver != null) {
-            throw new IllegalStateException("Input method observer already registered");
-        }
-        mInputMethodObserver = new ContentObserver(new Handler(Looper.myLooper())) {
-            @Override
-            public void onChange(boolean selfChange) {
-                // Either the user switched input methods or we did. In the former case, update
-                // mTouchInputMethod and save it so we can switch back after switching to the rotary
-                // input method.
-                String inputMethod = getCurrentIme();
-                L.d("Current IME changed to " + inputMethod);
-                if (!TextUtils.isEmpty(inputMethod) && !inputMethod.equals(mRotaryInputMethod)) {
-                    mTouchInputMethod = inputMethod;
-                    String userName = mUserManager.getUserName();
-                    L.d("Save mTouchInputMethod(" + mTouchInputMethod + ") for user "
-                            + userName);
-                    mPrefs.edit()
-                            .putString(TOUCH_INPUT_METHOD_PREFIX + userName, mTouchInputMethod)
-                            .apply();
-                }
-            }
-        };
-        if (mContentResolver == null) {
-            return;
-        }
-        mContentResolver.registerContentObserver(
-                Settings.Secure.getUriFor(DEFAULT_INPUT_METHOD),
-                /* notifyForDescendants= */ false,
-                mInputMethodObserver);
-    }
-
-    /** Unregisters the observer registered by {@link #registerInputMethodObserver}. */
-    private void unregisterInputMethodObserver() {
-        if (mInputMethodObserver != null) {
-            if (mContentResolver == null) {
-                return;
-            }
-            mContentResolver.unregisterContentObserver(mInputMethodObserver);
-            mInputMethodObserver = null;
-        }
-    }
-
     /**
      * Registers an observer to update our accessibility service info whenever the developer changes
      * the key event filter setting.
@@ -1728,7 +1623,7 @@ public class RotaryService extends AccessibilityService implements
         // targetFocusArea is an explicit FocusArea (i.e., an instance of the FocusArea class), so
         // perform ACTION_FOCUS on it. The FocusArea will handle this by focusing one of its
         // descendants.
-        if (Utils.isFocusArea(targetFocusArea)) {
+        if (Utils.isFocusArea(targetFocusArea) && !mNavigator.isComposable(targetFocusArea)) {
             arguments.clear();
             arguments.putInt(NUDGE_DIRECTION, direction);
             boolean success = performFocusAction(targetFocusArea, arguments);
@@ -1739,21 +1634,26 @@ public class RotaryService extends AccessibilityService implements
 
         // targetFocusArea is an implicit focus area, which means there is no explicit focus areas
         // or the implicit focus area is better than any other explicit focus areas. In this case,
-        // focus on the first orphan view.
+        // focus on the first focusable node.
         // Don't call restoreDefaultFocusInRoot(targetFocusArea), because it usually focuses on the
         // first focusable view in the view tree, which might be wrapped inside an explicit focus
         // area.
-        AccessibilityNodeInfo firstOrphan = mNavigator.findFirstOrphan(targetFocusArea);
-        if (firstOrphan == null) {
+        AccessibilityNodeInfo nodeToFocus = Utils.isFocusArea(targetFocusArea)
+                // targetFocusArea represents a Composable with AccessibilityClassName being
+                // "com.android.car.ui.FocusArea".
+                ? mNavigator.findFirstFocusableDescendant(targetFocusArea)
+                // targetFocusArea is an implicit focus area, or there is an orphan view.
+                : mNavigator.findFirstOrphan(targetFocusArea);
+        if (nodeToFocus == null) {
             // This shouldn't happen because a focus area without focusable descendants can't be
             // the target focus area.
             L.e("No focusable node in " + targetFocusArea);
             return;
         }
-        boolean success = performFocusAction(firstOrphan);
-        firstOrphan.recycle();
-        L.successOrFailure("Nudging to the nearest implicit focus area " + targetFocusArea,
-                success);
+        boolean success = performFocusAction(nodeToFocus);
+        nodeToFocus.recycle();
+        L.successOrFailure("Nudging to the Compose FocusArea or the nearest implicit focus area "
+                        + targetFocusArea, success);
         targetFocusArea.recycle();
     }
 
@@ -2344,6 +2244,19 @@ public class RotaryService extends AccessibilityService implements
             // it properly when the user uses the controller next time.
             if (mNavigator.isInVirtualNodeHierarchy(mFocusedNode)) {
                 L.v("mFocusedNode is in a WebView or ComposeView: " + mFocusedNode);
+                if (Utils.isComposeView(mFocusedNode.getParent())) {
+                    // Workaround for b/418077193:
+                    // Normally, when focus transitions from a classic View to a Composable, focus
+                    // events occur for both the AndroidComposeView (the Compose host) and then the
+                    // specific Composable that gained focus.
+                    // However, the event for the Composable itself can be intermittently missing.
+                    // This leads to an incorrect mFocusedNode.
+                    // To mitigate this, we proactively search for and update to the truly focused
+                    // Composable when mFocusedNode is AndroidComposeView.
+                    mFocusedNode = mFocusedNode.findFocus(FOCUS_INPUT);
+                    L.i("Adjust mFocusedNode to the really focused Composable: " + mFocusedNode);
+                }
+
                 return false;
             }
         }
@@ -2553,9 +2466,7 @@ public class RotaryService extends AccessibilityService implements
         }
         // Don't call performFocusAction(fpv) because it might cause infinite loop (b/322137915).
         boolean result = fpv.performAction(ACTION_FOCUS);
-        if (!result) {
-            L.w("Failed to perform ACTION_FOCUS on " + fpv);
-        }
+        L.successOrFailure("Perform ACTION_FOCUS on FocusParkingView:" + fpv, result);
         fpv.recycle();
         return result;
     }
@@ -2730,7 +2641,9 @@ public class RotaryService extends AccessibilityService implements
         if (!mInRotaryMode) {
             setEditNode(null);
         }
-        updateIme();
+        if (mImeSwitcher != null) {
+            mImeSwitcher.switchIme(inRotaryMode);
+        }
 
         // If we're controlling direct manipulation mode (i.e., the focused node supports rotate
         // directly), exit the mode when the user touches the screen.
@@ -2750,51 +2663,7 @@ public class RotaryService extends AccessibilityService implements
         }
     }
 
-    /** Switches to the rotary IME or the touch IME if needed. */
-    private void updateIme() {
-        String newIme;
-        if (mInRotaryMode) {
-            // We're entering Rotary mode, therefore we're setting the rotary IME as the
-            // default IME.
-            newIme = mRotaryInputMethod;
-        } else {
-            String oldIme = getCurrentIme();
-            if (Objects.equals(oldIme, mRotaryInputMethod)) {
-                // Since the previous IME was rotary IME and we're leaving rotary mode, then we
-                // switch back to the Android Auto default IME.
-                newIme = mTouchInputMethod;
-            } else {
-                // Since we're not entering rotary mode and the current keyboard is not the rotary
-                // IME, then there is no need to switch IMEs.
-                return;
-            }
-        }
 
-        if (!Utils.isInstalledIme(newIme, mInputMethodManager)) {
-            L.w("Rotary IME doesn't exist: " + newIme);
-            return;
-        }
-        setCurrentIme(newIme);
-    }
-
-    @Nullable
-    private String getCurrentIme() {
-        if (mContentResolver == null) {
-            return null;
-        }
-        return Settings.Secure.getString(mContentResolver, DEFAULT_INPUT_METHOD);
-    }
-
-    private void setCurrentIme(String newIme) {
-        if (mContentResolver == null) {
-            return;
-        }
-        String oldIme = getCurrentIme();
-        validateImeConfiguration(newIme);
-        boolean result =
-                Settings.Secure.putString(mContentResolver, DEFAULT_INPUT_METHOD, newIme);
-        L.successOrFailure("Switching IME from " + oldIme + " to " + newIme, result);
-    }
 
     /**
      * Performs {@link AccessibilityNodeInfo#ACTION_FOCUS} on a copy of the given {@code
@@ -2980,12 +2849,6 @@ public class RotaryService extends AccessibilityService implements
                 mFocusArea);
         DumpUtils.writeObject(dumpOutputStream, "lastTouchedNode",
                 RotaryProtos.RotaryService.LAST_TOUCHED_NODE, mLastTouchedNode);
-        dumpOutputStream.write("rotaryInputMethod", RotaryProtos.RotaryService.ROTARY_INPUT_METHOD,
-                mRotaryInputMethod);
-        dumpOutputStream.write("defaultTouchInputMethod",
-                RotaryProtos.RotaryService.DEFAULT_TOUCH_INPUT_METHOD, mDefaultTouchInputMethod);
-        dumpOutputStream.write("touchInputMethod", RotaryProtos.RotaryService.TOUCH_INPUT_METHOD,
-                mTouchInputMethod);
         DumpUtils.writeFocusDirection(dumpOutputStream, dumpAsProto, "hunNudgeDirection",
                 RotaryProtos.RotaryService.HUN_NUDGE_DIRECTION, mHunNudgeDirection);
         DumpUtils.writeFocusDirection(dumpOutputStream, dumpAsProto, "hunEscapeNudgeDirection",
@@ -3026,6 +2889,10 @@ public class RotaryService extends AccessibilityService implements
                 RotaryProtos.RotaryService.NAVIGATOR);
         mWindowCache.dump(dumpOutputStream, dumpAsProto, "windowCache",
                 RotaryProtos.RotaryService.WINDOW_CACHE);
+        if (mImeSwitcher != null) {
+            mImeSwitcher.dump(dumpOutputStream, "imeSwitcher",
+                    RotaryProtos.RotaryService.IME_SWITCHER);
+        }
         dumpOutputStream.flush();
     }
 }
diff --git a/src/com/android/car/rotary/Utils.java b/src/com/android/car/rotary/Utils.java
index c0af618..addac5e 100644
--- a/src/com/android/car/rotary/Utils.java
+++ b/src/com/android/car/rotary/Utils.java
@@ -292,6 +292,13 @@ final class Utils {
         return className != null && COMPOSE_VIEW_CLASS_NAME.contentEquals(className);
     }
 
+    /**
+     * Returns whether the given {@code node} represents a {@code ComposeView} or {@link WebView}.
+     */
+    static boolean isVirtualView(@NonNull AccessibilityNodeInfo node) {
+        return isWebView(node) || isComposeView(node);
+    }
+
     /** Returns whether the given {@code node} represents a {@link SurfaceView}. */
     static boolean isSurfaceView(@NonNull AccessibilityNodeInfo node) {
         CharSequence className = node.getClassName();
@@ -301,7 +308,7 @@ final class Utils {
     /**
      * Returns whether the given node represents a rotary container, as indicated by its content
      * description. This includes containers that can be scrolled using the rotary controller as
-     * well as other containers."
+     * well as other containers.
      */
     static boolean isRotaryContainer(@NonNull AccessibilityNodeInfo node) {
         CharSequence contentDescription = node.getContentDescription();
diff --git a/tests/unit/Android.bp b/tests/unit/Android.bp
index eef91fb..908fa88 100644
--- a/tests/unit/Android.bp
+++ b/tests/unit/Android.bp
@@ -8,7 +8,10 @@ android_test {
 
     certificate: "platform",
 
-    srcs: ["src/**/*.java"],
+    srcs: [
+        "src/**/*.kt",
+        "src/**/*.java",
+    ],
 
     libs: [
         "android.car-system-stubs",
@@ -19,6 +22,10 @@ android_test {
 
     static_libs: [
         "CarRotaryControllerForUnitTesting",
+        "androidx.activity_activity-compose",
+        "androidx.compose.foundation_foundation",
+        "androidx.compose.material3_material3",
+        "androidx.compose.runtime_runtime",
         "androidx.test.core",
         "androidx.test.rules",
         "androidx.test.ext.junit",
diff --git a/tests/unit/AndroidManifest.xml b/tests/unit/AndroidManifest.xml
index 5e3a292..8254d27 100644
--- a/tests/unit/AndroidManifest.xml
+++ b/tests/unit/AndroidManifest.xml
@@ -29,8 +29,11 @@
     <application android:debuggable="true"
                  android:theme="@style/Theme.App">
         <uses-library android:name="android.test.runner" />
+        <activity android:name="com.android.car.rotary.ComposeActivity" />
+        <activity android:name="com.android.car.rotary.ViewComposeActivity" />
         <activity android:name="com.android.car.rotary.NavigatorTestActivity" />
         <activity android:name="com.android.car.rotary.TreeTraverserTestActivity" />
+        <activity android:name="com.android.car.rotary.WebViewTestActivity" />
     </application>
 
     <instrumentation android:name="androidx.test.runner.AndroidJUnitRunner"
diff --git a/tests/unit/res/layout/navigator_view_and_compose_activity.xml b/tests/unit/res/layout/navigator_view_and_compose_activity.xml
new file mode 100644
index 0000000..01e7a0c
--- /dev/null
+++ b/tests/unit/res/layout/navigator_view_and_compose_activity.xml
@@ -0,0 +1,49 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+<FrameLayout xmlns:android="http://schemas.android.com/apk/res/android"
+             android:layout_width="match_parent"
+             android:layout_height="match_parent">
+
+    <com.android.car.ui.FocusParkingView
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"/>
+
+    <com.android.car.ui.FocusArea
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:layout_marginTop="200dp"
+        android:orientation="vertical">
+
+        <Button
+            android:id="@+id/button1"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:text="button1" />
+        <androidx.compose.ui.platform.ComposeView
+            android:id="@+id/compose_view"
+            android:layout_width="wrap_content"
+            android:layout_height="200dp"
+            android:focusable="true"/>
+        <Button
+            android:id="@+id/button2"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:text="button2"/>
+    </com.android.car.ui.FocusArea>
+
+</FrameLayout>
diff --git a/tests/unit/res/layout/navigator_webview_activity.xml b/tests/unit/res/layout/navigator_webview_activity.xml
new file mode 100644
index 0000000..6f3843d
--- /dev/null
+++ b/tests/unit/res/layout/navigator_webview_activity.xml
@@ -0,0 +1,50 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+<LinearLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    android:orientation="vertical">
+
+    <com.android.car.ui.FocusArea
+        android:layout_width="match_parent"
+        android:layout_height="match_parent"
+        android:layout_marginTop="100dp"
+        android:layout_marginBottom="100dp"
+        android:orientation="vertical">
+
+        <Button
+            android:id="@+id/top_button"
+            android:layout_width="match_parent"
+            android:layout_height="50dp"
+            android:text="Top Button"/>
+
+        <com.android.car.ui.RotaryScrollWebView
+            android:id="@+id/web_view"
+            android:layout_width="match_parent"
+            android:layout_height="300dp"/>
+
+        <Button
+            android:id="@+id/bottom_button"
+            android:layout_width="match_parent"
+            android:layout_height="50dp"
+            android:text="Bottom Button"/>
+
+    </com.android.car.ui.FocusArea>
+
+</LinearLayout>
diff --git a/tests/unit/res/raw/web_view_html.xml b/tests/unit/res/raw/web_view_html.xml
new file mode 100644
index 0000000..aa64367
--- /dev/null
+++ b/tests/unit/res/raw/web_view_html.xml
@@ -0,0 +1,31 @@
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
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
+<html>
+    <head>
+        <title>Sample Web Page</title>
+    </head>
+
+    <body>
+
+        <h1>1. Lists</h1>
+        <ol>
+            <li><b>First</b></li>
+            <li><i>Second</i></li>
+        </ol>
+
+    </body>
+</html>
diff --git a/tests/unit/res/values/themes.xml b/tests/unit/res/values/themes.xml
index 71a3352..0666e97 100644
--- a/tests/unit/res/values/themes.xml
+++ b/tests/unit/res/values/themes.xml
@@ -15,7 +15,7 @@
   ~ limitations under the License
   -->
 <resources>
-    <style name="Theme.App" parent="android:Theme.DeviceDefault">
+    <style name="Theme.App" parent="android:Theme.DeviceDefault.NoActionBar">
         <item name="carUiActivity">true</item>
     </style>
 </resources>
\ No newline at end of file
diff --git a/tests/unit/src/com/android/car/rotary/ComposeActivity.kt b/tests/unit/src/com/android/car/rotary/ComposeActivity.kt
new file mode 100644
index 0000000..2465d6f
--- /dev/null
+++ b/tests/unit/src/com/android/car/rotary/ComposeActivity.kt
@@ -0,0 +1,78 @@
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
+package com.android.car.rotary
+
+import android.os.Bundle
+import androidx.activity.ComponentActivity
+import androidx.activity.compose.setContent
+import androidx.compose.foundation.layout.Box
+import androidx.compose.foundation.layout.Row
+import androidx.compose.foundation.layout.fillMaxSize
+import androidx.compose.foundation.layout.padding
+import androidx.compose.material3.Button
+import androidx.compose.material3.ButtonDefaults
+import androidx.compose.material3.MaterialTheme
+import androidx.compose.material3.Surface
+import androidx.compose.material3.Text
+import androidx.compose.runtime.Composable
+import androidx.compose.ui.Modifier
+import androidx.compose.ui.graphics.Color
+import androidx.compose.ui.semantics.accessibilityClassName
+import androidx.compose.ui.semantics.contentDescription
+import androidx.compose.ui.semantics.semantics
+import androidx.compose.ui.unit.dp
+import com.android.car.ui.FocusArea
+
+const val LEFT_FOCUS_AREA_CONTENT_DESCRIPTION = "left_focus_area"
+const val RIGHT_FOCUS_AREA_CONTENT_DESCRIPTION = "right_focus_area"
+
+class ComposeActivity : ComponentActivity() {
+    override fun onCreate(savedInstanceState: Bundle?) {
+        super.onCreate(savedInstanceState)
+        setContent {
+            MaterialTheme {
+                Surface(
+                    modifier = Modifier.fillMaxSize(),
+                    color = MaterialTheme.colorScheme.background
+                ) {
+                    Row {
+                        FocusArea(LEFT_FOCUS_AREA_CONTENT_DESCRIPTION)
+                        FocusArea(RIGHT_FOCUS_AREA_CONTENT_DESCRIPTION)
+                    }
+                }
+            }
+        }
+    }
+}
+
+@Composable
+fun FocusArea(name: String) {
+    Box (
+        Modifier
+        .semantics {
+            accessibilityClassName = FocusArea::class.qualifiedName!!
+            contentDescription = name
+        }
+        .padding(horizontal = 10.dp, vertical = 200.dp)
+    ){
+        Button(
+            onClick = {},
+            colors = ButtonDefaults.buttonColors(containerColor = Color.Gray)
+        ) {
+            Text(name)
+        }
+    }
+}
diff --git a/tests/unit/src/com/android/car/rotary/NavigatorTest.java b/tests/unit/src/com/android/car/rotary/NavigatorTest.java
index 03fed32..30ac06c 100644
--- a/tests/unit/src/com/android/car/rotary/NavigatorTest.java
+++ b/tests/unit/src/com/android/car/rotary/NavigatorTest.java
@@ -19,6 +19,10 @@ import static android.view.accessibility.AccessibilityWindowInfo.TYPE_APPLICATIO
 import static android.view.accessibility.AccessibilityWindowInfo.TYPE_INPUT_METHOD;
 import static android.view.accessibility.AccessibilityWindowInfo.TYPE_SYSTEM;
 
+import static com.android.car.rotary.ComposeActivityKt.LEFT_FOCUS_AREA_CONTENT_DESCRIPTION;
+import static com.android.car.rotary.ComposeActivityKt.RIGHT_FOCUS_AREA_CONTENT_DESCRIPTION;
+import static com.android.car.rotary.ViewComposeActivityKt.BUTTONA_CONTENT_DESCRIPTION;
+import static com.android.car.rotary.ViewComposeActivityKt.BUTTONB_CONTENT_DESCRIPTION;
 import static com.android.car.ui.utils.RotaryConstants.ROTARY_VERTICALLY_SCROLLABLE;
 
 import static com.google.common.truth.Truth.assertThat;
@@ -53,19 +57,22 @@ import org.junit.runner.RunWith;
 import java.util.ArrayList;
 import java.util.Collections;
 import java.util.List;
+import java.util.concurrent.CountDownLatch;
+import java.util.concurrent.TimeUnit;
 
 @RunWith(AndroidJUnit4.class)
 public class NavigatorTest {
 
+    private static final long WAIT_TIME_MS = 3000;
     private static final String HOST_APP_PACKAGE_NAME = "host.app.package.name";
     private static final String CLIENT_APP_PACKAGE_NAME = "client.app.package.name";
+    private static final int INVALID_RESOURCE_ID = -1;
 
-    private static UiAutomation sUiAutomoation;
+    private static UiAutomation sUiAutomation;
     private static int sOriginalFlags;
 
     private final List<AccessibilityNodeInfo> mNodes = new ArrayList<>();
-
-    private ActivityTestRule<NavigatorTestActivity> mActivityRule;
+    private ActivityTestRule<? extends Activity> mActivityRule;
     private Intent mIntent;
     private Rect mDisplayBounds;
     private Rect mHunWindowBounds;
@@ -75,28 +82,25 @@ public class NavigatorTest {
 
     @BeforeClass
     public static void oneTimeSetup() {
-        sUiAutomoation = InstrumentationRegistry.getInstrumentation().getUiAutomation(
+        sUiAutomation = InstrumentationRegistry.getInstrumentation().getUiAutomation(
                 UiAutomation.FLAG_DONT_SUPPRESS_ACCESSIBILITY_SERVICES);
 
         // FLAG_RETRIEVE_INTERACTIVE_WINDOWS is necessary to reliably access the root window.
-        AccessibilityServiceInfo serviceInfo = sUiAutomoation.getServiceInfo();
+        AccessibilityServiceInfo serviceInfo = sUiAutomation.getServiceInfo();
         sOriginalFlags = serviceInfo.flags;
         serviceInfo.flags |= AccessibilityServiceInfo.FLAG_RETRIEVE_INTERACTIVE_WINDOWS;
-        sUiAutomoation.setServiceInfo(serviceInfo);
+        sUiAutomation.setServiceInfo(serviceInfo);
     }
 
     @AfterClass
     public static void oneTimeTearDown() {
-        AccessibilityServiceInfo serviceInfo = sUiAutomoation.getServiceInfo();
+        AccessibilityServiceInfo serviceInfo = sUiAutomation.getServiceInfo();
         serviceInfo.flags = sOriginalFlags;
-        sUiAutomoation.setServiceInfo(serviceInfo);
+        sUiAutomation.setServiceInfo(serviceInfo);
     }
 
     @Before
     public void setUp() {
-        mActivityRule = new ActivityTestRule<>(NavigatorTestActivity.class);
-        mIntent = new Intent();
-        mIntent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TASK | Intent.FLAG_ACTIVITY_NEW_TASK);
         mDisplayBounds = new Rect(0, 0, 1080, 920);
         mHunWindowBounds = new Rect(50, 10, 950, 200);
         // The values of displayWidth and displayHeight affects testFindNudgeTargetFocusArea5
@@ -111,7 +115,9 @@ public class NavigatorTest {
 
     @After
     public void tearDown() {
-        mActivityRule.finishActivity();
+        if (mActivityRule != null) {
+            mActivityRule.finishActivity();
+        }
         Utils.recycleNode(mWindowRoot);
         Utils.recycleNodes(mNodes);
     }
@@ -368,7 +374,7 @@ public class NavigatorTest {
 
         InstrumentationRegistry.getInstrumentation().waitForIdleSync();
 
-        AccessibilityNodeInfo windowRoot = sUiAutomoation.getRootInActiveWindow();
+        AccessibilityNodeInfo windowRoot = sUiAutomation.getRootInActiveWindow();
         AccessibilityNodeInfo button1 = createNode("button1");
         AccessibilityNodeInfo scrollable = createNode("scrollable");
 
@@ -597,6 +603,203 @@ public class NavigatorTest {
         Utils.recycleNode(target.node);
     }
 
+    /**
+     * Tests {@link Navigator#findRotateTarget} in the following node tree:
+     * <pre>
+     *                  FocusArea
+     *               /    |     \
+     *            /       |       \
+     *     button1   ComposeView   button2
+     *               (focusable)
+     *                   / \
+     *                 /    \
+     *           buttonA   buttonB
+     * </pre>
+     */
+    @Test
+    public void testFindRotateTarget_ViewAndCompose1() throws InterruptedException {
+        initActivity(ViewComposeActivity.class, INVALID_RESOURCE_ID);
+        Activity activity = mActivityRule.getActivity();
+        View composeView = activity.findViewById(R.id.compose_view);
+        assertThat(composeView.isFocusable()).isTrue();
+
+        AccessibilityNodeInfo button1 = createNode("button1");
+        AccessibilityNodeInfo button2 = createNode("button2");
+
+        TreeTraverser treeTraverser = new TreeTraverser();
+        AccessibilityNodeInfo buttonA = treeTraverser.depthFirstSearch(mWindowRoot,
+                node -> BUTTONA_CONTENT_DESCRIPTION.equals(node.getContentDescription()));
+        if (!buttonA.isFocusable()) {
+            // The button node with content description is not focusable while its parent is
+            // focusable.
+            buttonA = buttonA.getParent();
+        }
+        AccessibilityNodeInfo buttonB = treeTraverser.depthFirstSearch(mWindowRoot,
+                node -> BUTTONB_CONTENT_DESCRIPTION.equals(node.getContentDescription()));
+        if (!buttonB.isFocusable()) {
+            buttonB = buttonB.getParent();
+        }
+
+        // Rotate once, the focus should move from button1 to buttonA.
+        FindRotateTargetResult target = mNavigator.findRotateTarget(button1, View.FOCUS_FORWARD, 1);
+        assertThat(target.node).isEqualTo(buttonA);
+        assertThat(target.advancedCount).isEqualTo(1);
+
+        // Rotate twice, the focus should move from button1 to buttonB.
+        target = mNavigator.findRotateTarget(button1, View.FOCUS_FORWARD, 2);
+        assertThat(target.node).isEqualTo(buttonB);
+        assertThat(target.advancedCount).isEqualTo(2);
+
+        // Rotate three times, the focus should move from button1 to button2.
+        target = mNavigator.findRotateTarget(button1, View.FOCUS_FORWARD, 3);
+        assertThat(target.node).isEqualTo(button2);
+        assertThat(target.advancedCount).isEqualTo(3);
+
+        // Rotate forward four times, the focus should move from button1 to button2 (it has reached
+        // to the boundary).
+        target = mNavigator.findRotateTarget(button1, View.FOCUS_FORWARD, 4);
+        assertThat(target.node).isEqualTo(button2);
+        assertThat(target.advancedCount).isEqualTo(3);
+
+        // Rotate back 1, 2, 3, 4 times.
+        target = mNavigator.findRotateTarget(button2, View.FOCUS_BACKWARD, 1);
+        assertThat(target.node).isEqualTo(buttonB);
+        assertThat(target.advancedCount).isEqualTo(1);
+
+        target = mNavigator.findRotateTarget(button2, View.FOCUS_BACKWARD, 2);
+        assertThat(target.node).isEqualTo(buttonA);
+        assertThat(target.advancedCount).isEqualTo(2);
+
+        target = mNavigator.findRotateTarget(button2, View.FOCUS_BACKWARD, 3);
+        assertThat(target.node).isEqualTo(button1);
+        assertThat(target.advancedCount).isEqualTo(3);
+
+        target = mNavigator.findRotateTarget(button2, View.FOCUS_BACKWARD, 4);
+        assertThat(target.node).isEqualTo(button1);
+        assertThat(target.advancedCount).isEqualTo(3);
+    }
+
+    /**
+     * Tests {@link Navigator#findRotateTarget} in the following node tree:
+     * <pre>
+     *                  FocusArea
+     *               /    |     \
+     *            /       |       \
+     *     button1   ComposeView   button2
+     *             (not focusable)
+     *                   / \
+     *                 /    \
+     *           buttonA   buttonB
+     * </pre>
+     */
+    @Test
+    public void testFindRotateTarget_ViewAndCompose2() throws InterruptedException {
+        initActivity(ViewComposeActivity.class, INVALID_RESOURCE_ID);
+
+        // Set ComposeView non-focusable.
+        Activity activity = mActivityRule.getActivity();
+        View composeView = activity.findViewById(R.id.compose_view);
+        CountDownLatch latch = new CountDownLatch(1);
+        composeView.post(() -> {
+            composeView.setFocusable(false);
+            composeView.post(() -> latch.countDown());
+        });
+        latch.await(WAIT_TIME_MS, TimeUnit.MILLISECONDS);
+        assertThat(composeView.isFocusable()).isFalse();
+
+        AccessibilityNodeInfo button1 = createNode("button1");
+        AccessibilityNodeInfo button2 = createNode("button2");
+
+        TreeTraverser treeTraverser = new TreeTraverser();
+        AccessibilityNodeInfo buttonA = treeTraverser.depthFirstSearch(mWindowRoot,
+                node -> BUTTONA_CONTENT_DESCRIPTION.equals(node.getContentDescription()));
+        if (!buttonA.isFocusable()) {
+            // The button node with content description is not focusable while its parent is
+            // focusable.
+            buttonA = buttonA.getParent();
+        }
+        AccessibilityNodeInfo buttonB = treeTraverser.depthFirstSearch(mWindowRoot,
+                node -> BUTTONB_CONTENT_DESCRIPTION.equals(node.getContentDescription()));
+        if (!buttonB.isFocusable()) {
+            buttonB = buttonB.getParent();
+        }
+
+        // Rotate once, the focus should move from button1 to buttonA.
+        FindRotateTargetResult target = mNavigator.findRotateTarget(button1, View.FOCUS_FORWARD, 1);
+        assertThat(target.node).isEqualTo(buttonA);
+        assertThat(target.advancedCount).isEqualTo(1);
+
+        // Rotate twice, the focus should move from button1 to buttonB.
+        target = mNavigator.findRotateTarget(button1, View.FOCUS_FORWARD, 2);
+        assertThat(target.node).isEqualTo(buttonB);
+        assertThat(target.advancedCount).isEqualTo(2);
+
+        // Rotate three times, the focus should move from button1 to button2.
+        target = mNavigator.findRotateTarget(button1, View.FOCUS_FORWARD, 3);
+        assertThat(target.node).isEqualTo(button2);
+        assertThat(target.advancedCount).isEqualTo(3);
+
+        // Rotate forward four times, the focus should move from button1 to button2 (it has reached
+        // to the boundary).
+        target = mNavigator.findRotateTarget(button1, View.FOCUS_FORWARD, 4);
+        assertThat(target.node).isEqualTo(button2);
+        assertThat(target.advancedCount).isEqualTo(3);
+
+        // Rotate back 1, 2, 3, 4 times.
+        target = mNavigator.findRotateTarget(button2, View.FOCUS_BACKWARD, 1);
+        assertThat(target.node).isEqualTo(buttonB);
+        assertThat(target.advancedCount).isEqualTo(1);
+
+        target = mNavigator.findRotateTarget(button2, View.FOCUS_BACKWARD, 2);
+        assertThat(target.node).isEqualTo(buttonA);
+        assertThat(target.advancedCount).isEqualTo(2);
+
+        target = mNavigator.findRotateTarget(button2, View.FOCUS_BACKWARD, 3);
+        assertThat(target.node).isEqualTo(button1);
+        assertThat(target.advancedCount).isEqualTo(3);
+
+        target = mNavigator.findRotateTarget(button2, View.FOCUS_BACKWARD, 4);
+        assertThat(target.node).isEqualTo(button1);
+        assertThat(target.advancedCount).isEqualTo(3);
+    }
+
+    /**
+     * Tests {@link Navigator#findRotateTarget} in the following node tree:
+     * <pre>
+     *                  FocusArea
+     *               /      |        \
+     *            /         |          \
+     *    button1        WebView          button2
+     *          (focused, not scrollable)
+     *                    |
+     *                    |
+     *                  links
+     * </pre>
+     */
+    @Test
+    public void testFindRotateTarget_WebView() throws InterruptedException {
+        initActivity(WebViewTestActivity.class, INVALID_RESOURCE_ID);
+
+        Activity activity = mActivityRule.getActivity();
+        View webView = activity.findViewById(R.id.web_view);
+        CountDownLatch latch = new CountDownLatch(1);
+        webView.post(() -> {
+            webView.requestFocus();
+            webView.post(() -> latch.countDown());
+        });
+        latch.await(WAIT_TIME_MS, TimeUnit.MILLISECONDS);
+        assertThat(webView.isFocused()).isTrue();
+
+        AccessibilityNodeInfo webViewNode = createNode("web_view");
+        assertThat(webViewNode).isNotNull();
+        AccessibilityNodeInfo bottomButton = createNode("bottom_button");
+
+        FindRotateTargetResult target =
+                mNavigator.findRotateTarget(webViewNode, View.FOCUS_FORWARD, 1);
+        assertThat(target.node).isEqualTo(bottomButton);
+        assertThat(target.advancedCount).isEqualTo(1);
+    }
+
     /**
      * Tests {@link Navigator#findScrollableContainer} in the following node tree:
      * <pre>
@@ -1062,6 +1265,7 @@ public class NavigatorTest {
         Rect imeWindowBounds = new Rect(0,528, 1080, 600);
         AccessibilityNodeInfo imeRoot = mNodeBuilder
                 .setBoundsInScreen(imeWindowBounds)
+                .setFocusable(false)
                 .build();
         AccessibilityWindowInfo imeWindow = new WindowBuilder()
                 .setRoot(imeRoot)
@@ -1352,6 +1556,64 @@ public class NavigatorTest {
         assertThat(targetFocusArea).isEqualTo(root);
     }
 
+    /**
+     * Tests {@link Navigator#findNudgeTargetFocusArea} in the following layout:
+     *
+     * <pre>
+     *
+     *    ===============focus area1=================
+     *    =  ............                           =
+     *    =  . view1    .                           =
+     *    =  ............                           =
+     *    =   ===============focus area2=========   =
+     *    =   =  ..........                     =   =
+     *    =   =  . view2  .                     =   =
+     *    =   =  ..........                     =   =
+     *    =   ===================================   =
+     *    =                                         =
+     *    ===========================================
+     *</pre>
+     *
+     */
+    @Test
+    public void testFindNudgeTargetFocusArea7() {
+        Rect windowBounds = new Rect(0, 0, 1080, 600);
+        AccessibilityNodeInfo windowRoot = mNodeBuilder
+                .setBoundsInScreen(windowBounds)
+                .build();
+        AccessibilityWindowInfo window = new WindowBuilder()
+                .setRoot(windowRoot)
+                .setBoundsInScreen(windowBounds)
+                .build();
+        AccessibilityNodeInfo focusArea1 = mNodeBuilder
+                .setBoundsInScreen(windowBounds)
+                .setFocusArea()
+                .setParent(windowRoot)
+                .build();
+        AccessibilityNodeInfo view1 = mNodeBuilder
+                .setParent(focusArea1)
+                .setBoundsInScreen(new Rect(0, 0, 10, 10))
+                .build();
+        AccessibilityNodeInfo focusArea2 = mNodeBuilder
+                .setBoundsInScreen(new Rect(0, 100, 1080, 200))
+                .setFocusArea()
+                .setParent(windowRoot)
+                .build();
+        AccessibilityNodeInfo view2 = mNodeBuilder
+                .setParent(focusArea2)
+                .setBoundsInScreen(new Rect(0, 100, 10, 110))
+                .setWindow(window)
+                .build();
+
+        List<AccessibilityWindowInfo> windows = new ArrayList<>();
+        windows.add(window);
+
+        // Nudge up from view2 in Dialog focusArea2, the focus should move to focusArea1.
+        AccessibilityNodeInfo targetFocusArea =
+                mNavigator.findNudgeTargetFocusArea(windows, view2, focusArea2, View.FOCUS_UP);
+        assertThat(targetFocusArea).isEqualTo(focusArea1);
+    }
+
     /**
      * Tests {@link Navigator#findFirstOrphan} in the following layout:
      *
@@ -1924,14 +2186,76 @@ public class NavigatorTest {
     }
 
     /**
-     * Starts the test activity with the given layout and initializes the root
+     * Tests {@link Navigator#findNudgeTargetFocusArea} between Composable focus areas in the
+     * following layout:
+     * <pre>
+     *    ---------------------------------ComposeView-----------------------------------
+     *    -  =======Composable(FocusArea)======    ========Composable(FocusArea)======  -
+     *    -  =                                =    =                                 =  -
+     *    -  =  ...............               =    =  ...............                =  -
+     *    -  =  .             .               =    =  .             .                =  -
+     *    -  =  . Composable1 .               =    =  . Composable2 .                =  -
+     *    -  =  .             .               =    =  .             .                =  -
+     *    -  =  ...............               =    =  ...............                =  -
+     *    -  =                                =    =                                 =  -
+     *    -  ==================================    ===================================  -
+     *    -------------------------------------------------------------------------------
+     * </pre>
+     */
+    @Test
+    public void testFindNudgeTargetFocusArea_Composables() {
+        initActivity(ComposeActivity.class, INVALID_RESOURCE_ID);
+        // The only way to create a AccessibilityWindowInfo in the test is via mock.
+        AccessibilityWindowInfo mockWindow = new WindowBuilder()
+                .setRoot(mWindowRoot)
+                .setBoundsInScreen(mWindowRoot.getBoundsInScreen())
+                .build();
+        List<AccessibilityWindowInfo> windows = new ArrayList<>();
+        windows.add(mockWindow);
+        TreeTraverser treeTraverser = new TreeTraverser();
+        AccessibilityNodeInfo leftFocusArea = treeTraverser.depthFirstSearch(mWindowRoot,
+                node -> LEFT_FOCUS_AREA_CONTENT_DESCRIPTION.equals(node.getContentDescription()));
+        assertThat(leftFocusArea).isNotNull();
+        AccessibilityNodeInfo leftButton = mNavigator.findFirstFocusableDescendant(leftFocusArea);
+        assertThat(leftButton).isNotNull();
+        AccessibilityNodeInfo rightFocusArea = treeTraverser.depthFirstSearch(mWindowRoot,
+                node -> RIGHT_FOCUS_AREA_CONTENT_DESCRIPTION.equals(node.getContentDescription()));
+        assertThat(leftButton).isNotNull();
+        // Only an AccessibilityService with the permission to retrieve the active window content
+        // can create an AccessibilityWindowInfo. So the AccessibilityWindowInfo and the associated
+        // AccessibilityNodeInfos have to be mocked.
+        AccessibilityNodeInfo mockLeftButton = mNodeBuilder
+                .setWindow(mockWindow)
+                .setBoundsInScreen(leftButton.getBoundsInScreen())
+                .setParent(leftFocusArea)
+                .build();
+        // Nudge right.
+        AccessibilityNodeInfo target = mNavigator.findNudgeTargetFocusArea(
+                windows, mockLeftButton, leftFocusArea, View.FOCUS_RIGHT);
+        assertThat(target).isEqualTo(rightFocusArea);
+    }
+
+    /**
+     * Starts the NavigatorTestActivity with the given layout and initializes the root
      * {@link AccessibilityNodeInfo}.
      */
     private void initActivity(@LayoutRes int layoutResId) {
-        mIntent.putExtra(NavigatorTestActivity.KEY_LAYOUT_ID, layoutResId);
-        mActivityRule.launchActivity(mIntent);
+        initActivity(NavigatorTestActivity.class, layoutResId);
+    }
 
-        mWindowRoot = sUiAutomoation.getRootInActiveWindow();
+    /**
+     * Starts the given Activity with the given layout and initializes the root
+     * {@link AccessibilityNodeInfo}.
+     */
+    private void initActivity(Class<? extends Activity> activityClass, @LayoutRes int layoutResId) {
+        mActivityRule = new ActivityTestRule<>(activityClass);
+        mIntent = new Intent();
+        mIntent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TASK | Intent.FLAG_ACTIVITY_NEW_TASK);
+        if (layoutResId != INVALID_RESOURCE_ID) {
+            mIntent.putExtra(NavigatorTestActivity.KEY_LAYOUT_ID, layoutResId);
+        }
+        mActivityRule.launchActivity(mIntent);
+        PollingCheck.waitFor(() -> (mWindowRoot = sUiAutomation.getRootInActiveWindow()) != null);
     }
 
     /**
diff --git a/tests/unit/src/com/android/car/rotary/PollingCheck.java b/tests/unit/src/com/android/car/rotary/PollingCheck.java
new file mode 100644
index 0000000..6ebcfd0
--- /dev/null
+++ b/tests/unit/src/com/android/car/rotary/PollingCheck.java
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
+package com.android.car.rotary;
+
+import org.junit.Assert;
+
+/**
+ * Utility used for testing that allows to poll for a certain condition to happen within a timeout.
+ *
+ * Code copied from com.android.compatibility.common.util.PollingCheck
+ */
+abstract class PollingCheck {
+
+    private static final long DEFAULT_TIMEOUT = 3000;
+    private static final long TIME_SLICE = 50;
+    private final long mTimeout;
+
+    /**
+     * The condition that the PollingCheck should use to proceed successfully.
+     */
+    interface PollingCheckCondition {
+
+        /**
+         * @return Whether the polling condition has been met.
+         */
+        boolean canProceed();
+    }
+
+    PollingCheck(long timeout) {
+        mTimeout = timeout;
+    }
+
+    protected abstract boolean check();
+
+    /**
+     * Start running the polling check.
+     */
+    void run() {
+        if (check()) {
+            return;
+        }
+
+        long timeout = mTimeout;
+        while (timeout > 0) {
+            try {
+                Thread.sleep(TIME_SLICE);
+            } catch (InterruptedException e) {
+                Assert.fail("unexpected InterruptedException");
+            }
+
+            if (check()) {
+                return;
+            }
+
+            timeout -= TIME_SLICE;
+        }
+
+        Assert.fail("unexpected timeout");
+    }
+
+    /**
+     * Instantiate and start polling for a given condition with a default 3000ms timeout.
+     *
+     * @param condition The condition to check for success.
+     */
+    static void waitFor(final PollingCheckCondition condition) {
+        new PollingCheck(DEFAULT_TIMEOUT) {
+            @Override
+            protected boolean check() {
+                return condition.canProceed();
+            }
+        }.run();
+    }
+
+    /**
+     * Instantiate and start polling for a given condition.
+     *
+     * @param timeout Time out in ms
+     * @param condition The condition to check for success.
+     */
+    static void waitFor(long timeout, final PollingCheckCondition condition) {
+        new PollingCheck(timeout) {
+            @Override
+            protected boolean check() {
+                return condition.canProceed();
+            }
+        }.run();
+    }
+}
diff --git a/tests/unit/src/com/android/car/rotary/RotaryServiceTest.java b/tests/unit/src/com/android/car/rotary/RotaryServiceTest.java
index 358e4c5..5ff2103 100644
--- a/tests/unit/src/com/android/car/rotary/RotaryServiceTest.java
+++ b/tests/unit/src/com/android/car/rotary/RotaryServiceTest.java
@@ -24,6 +24,10 @@ import static android.view.accessibility.AccessibilityEvent.TYPE_VIEW_FOCUSED;
 import static android.view.accessibility.AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED;
 import static android.view.accessibility.AccessibilityWindowInfo.TYPE_APPLICATION;
 
+import static com.android.car.rotary.ComposeActivityKt.LEFT_FOCUS_AREA_CONTENT_DESCRIPTION;
+import static com.android.car.rotary.ComposeActivityKt.RIGHT_FOCUS_AREA_CONTENT_DESCRIPTION;
+import static com.android.car.rotary.ViewComposeActivityKt.BUTTONA_CONTENT_DESCRIPTION;
+import static com.android.car.rotary.ViewComposeActivityKt.BUTTONB_CONTENT_DESCRIPTION;
 import static com.android.car.ui.utils.DirectManipulationHelper.DIRECT_MANIPULATION;
 import static com.android.car.ui.utils.RotaryConstants.ACTION_RESTORE_DEFAULT_FOCUS;
 
@@ -74,14 +78,19 @@ import org.mockito.Spy;
 import java.util.ArrayList;
 import java.util.Collections;
 import java.util.List;
+import java.util.concurrent.CountDownLatch;
+import java.util.concurrent.TimeUnit;
 
 @RunWith(AndroidJUnit4.class)
 public class RotaryServiceTest {
 
+    private static final long WAIT_TIME_MS = 3000;
+
     private final static String HOST_APP_PACKAGE_NAME = "host.app.package.name";
     private final static String CLIENT_APP_PACKAGE_NAME = "client.app.package.name";
     private static final int ROTATION_ACCELERATION_2X_MS = 50;
     private static final int ROTATION_ACCELERATION_3X_MS = 25;
+    private static final int INVALID_RESOURCE_ID = -1;
 
     private static UiAutomation sUiAutomation;
     private static int sOriginalFlags;
@@ -89,7 +98,7 @@ public class RotaryServiceTest {
     private final List<AccessibilityNodeInfo> mNodes = new ArrayList<>();
 
     private AccessibilityNodeInfo mWindowRoot;
-    private ActivityTestRule<NavigatorTestActivity> mActivityRule;
+    private ActivityTestRule<? extends Activity> mActivityRule;
     private Intent mIntent;
     private NodeBuilder mNodeBuilder;
 
@@ -115,15 +124,10 @@ public class RotaryServiceTest {
         AccessibilityServiceInfo serviceInfo = sUiAutomation.getServiceInfo();
         serviceInfo.flags = sOriginalFlags;
         sUiAutomation.setServiceInfo(serviceInfo);
-
     }
 
     @Before
     public void setUp() {
-        mActivityRule = new ActivityTestRule<>(NavigatorTestActivity.class);
-        mIntent = new Intent();
-        mIntent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TASK | Intent.FLAG_ACTIVITY_NEW_TASK);
-
         MockitoAnnotations.initMocks(this);
         mRotaryService.setNavigator(mNavigator);
         mRotaryService.setNodeCopier(MockNodeCopierProvider.get());
@@ -135,7 +139,9 @@ public class RotaryServiceTest {
 
     @After
     public void tearDown() {
-        mActivityRule.finishActivity();
+        if (mActivityRule != null) {
+            mActivityRule.finishActivity();
+        }
         Utils.recycleNode(mWindowRoot);
         Utils.recycleNodes(mNodes);
     }
@@ -610,6 +616,218 @@ public class RotaryServiceTest {
         assertThat(mRotaryService.getFocusedNode()).isEqualTo(button5Node);
     }
 
+    /**
+     * Tests {@link RotaryService#onRotaryEvents} in the following node tree:
+     * <pre>
+     *                  FocusArea
+     *               /    |     \
+     *            /       |       \
+     *     button1   ComposeView   button2
+     *               (focusable)
+     *                   / \
+     *                 /    \
+     *           buttonA   buttonB
+     * </pre>
+     */
+    @Test
+    public void testOnRotaryEvents_ViewAndCompose1() {
+        initActivity(ViewComposeActivity.class, INVALID_RESOURCE_ID);
+        Activity activity = mActivityRule.getActivity();
+        View composeView = activity.findViewById(R.id.compose_view);
+        assertThat(composeView.isFocusable()).isTrue();
+
+        AccessibilityWindowInfo window = new WindowBuilder()
+                .setRoot(mWindowRoot)
+                .setBoundsInScreen(mWindowRoot.getBoundsInScreen())
+                .build();
+        List<AccessibilityWindowInfo> windows = Collections.singletonList(window);
+        when(mRotaryService.getWindows()).thenReturn(windows);
+
+        AccessibilityNodeInfo button1 = createNode("button1");
+        assertThat(button1.isFocused()).isTrue();
+        mRotaryService.setFocusedNode(button1);
+        assertThat(mRotaryService.getFocusedNode()).isEqualTo(button1);
+
+        AccessibilityNodeInfo button2 = createNode("button2");
+        TreeTraverser treeTraverser = new TreeTraverser();
+        AccessibilityNodeInfo buttonA = treeTraverser.depthFirstSearch(mWindowRoot,
+                node -> BUTTONA_CONTENT_DESCRIPTION.equals(node.getContentDescription()));
+        if (!buttonA.isFocusable()) {
+            // The button node with content description is not focusable while its parent is
+            // focusable.
+            buttonA = buttonA.getParent();
+        }
+        AccessibilityNodeInfo buttonB = treeTraverser.depthFirstSearch(mWindowRoot,
+                node -> BUTTONB_CONTENT_DESCRIPTION.equals(node.getContentDescription()));
+        if (!buttonB.isFocusable()) {
+            buttonB = buttonB.getParent();
+        }
+
+        // Rotate clockwise 4 times (button1 -> buttonA -> ButtonB -> Button2 -> Button2).
+        int inputType = CarInputManager.INPUT_TYPE_ROTARY_NAVIGATION;
+        int eventTime = ROTATION_ACCELERATION_2X_MS + 1;
+        int validDisplayId = CarOccupantZoneManager.DISPLAY_TYPE_MAIN;
+        mRotaryService.onRotaryEvents(validDisplayId,
+                Collections.singletonList(
+                        new RotaryEvent(inputType, true, new long[]{eventTime})));
+        assertThat(mRotaryService.getFocusedNode()).isEqualTo(buttonA);
+
+        eventTime += ROTATION_ACCELERATION_2X_MS + 1;
+        mRotaryService.onRotaryEvents(validDisplayId,
+                Collections.singletonList(
+                        new RotaryEvent(inputType, true, new long[]{eventTime})));
+        assertThat(mRotaryService.getFocusedNode()).isEqualTo(buttonB);
+
+        eventTime += ROTATION_ACCELERATION_2X_MS + 1;
+        mRotaryService.onRotaryEvents(validDisplayId,
+                Collections.singletonList(
+                        new RotaryEvent(inputType, true, new long[]{eventTime})));
+        assertThat(mRotaryService.getFocusedNode()).isEqualTo(button2);
+
+        eventTime += ROTATION_ACCELERATION_2X_MS + 1;
+        mRotaryService.onRotaryEvents(validDisplayId,
+                Collections.singletonList(
+                        new RotaryEvent(inputType, true, new long[]{eventTime})));
+        // It has reached to the boundary.
+        assertThat(mRotaryService.getFocusedNode()).isEqualTo(button2);
+
+        // Rotate counter-clockwise 4 times (button2 -> buttonB -> ButtonA -> Button1 -> Button1).
+        eventTime += ROTATION_ACCELERATION_2X_MS + 1;
+        mRotaryService.onRotaryEvents(validDisplayId,
+                Collections.singletonList(
+                        new RotaryEvent(inputType, false, new long[]{eventTime})));
+        assertThat(mRotaryService.getFocusedNode()).isEqualTo(buttonB);
+
+        eventTime += ROTATION_ACCELERATION_2X_MS + 1;
+        mRotaryService.onRotaryEvents(validDisplayId,
+                Collections.singletonList(
+                        new RotaryEvent(inputType, false, new long[]{eventTime})));
+        assertThat(mRotaryService.getFocusedNode()).isEqualTo(buttonA);
+
+        eventTime += ROTATION_ACCELERATION_2X_MS + 1;
+        mRotaryService.onRotaryEvents(validDisplayId,
+                Collections.singletonList(
+                        new RotaryEvent(inputType, false, new long[]{eventTime})));
+        assertThat(mRotaryService.getFocusedNode()).isEqualTo(button1);
+
+        eventTime += ROTATION_ACCELERATION_2X_MS + 1;
+        mRotaryService.onRotaryEvents(validDisplayId,
+                Collections.singletonList(
+                        new RotaryEvent(inputType, false, new long[]{eventTime})));
+        // It has reached to the boundary.
+        assertThat(mRotaryService.getFocusedNode()).isEqualTo(button1);
+    }
+
+    /**
+     * Tests {@link RotaryService#onRotaryEvents} in the following node tree:
+     * <pre>
+     *                  FocusArea
+     *               /    |     \
+     *            /       |       \
+     *     button1   ComposeView   button2
+     *             (not focusable)
+     *                   / \
+     *                 /    \
+     *           buttonA   buttonB
+     * </pre>
+     */
+    @Test
+    public void testOnRotaryEvents_ViewAndCompose2() throws InterruptedException {
+        initActivity(ViewComposeActivity.class, INVALID_RESOURCE_ID);
+
+        // Set ComposeView non-focusable.
+        Activity activity = mActivityRule.getActivity();
+        View composeView = activity.findViewById(R.id.compose_view);
+        CountDownLatch latch = new CountDownLatch(1);
+        composeView.post(() -> {
+            composeView.setFocusable(false);
+            composeView.post(() -> latch.countDown());
+        });
+        latch.await(WAIT_TIME_MS, TimeUnit.MILLISECONDS);
+        assertThat(composeView.isFocusable()).isFalse();
+
+        AccessibilityWindowInfo window = new WindowBuilder()
+                .setRoot(mWindowRoot)
+                .setBoundsInScreen(mWindowRoot.getBoundsInScreen())
+                .build();
+        List<AccessibilityWindowInfo> windows = Collections.singletonList(window);
+        when(mRotaryService.getWindows()).thenReturn(windows);
+
+        AccessibilityNodeInfo button1 = createNode("button1");
+        assertThat(button1.isFocused()).isTrue();
+        mRotaryService.setFocusedNode(button1);
+        assertThat(mRotaryService.getFocusedNode()).isEqualTo(button1);
+
+        AccessibilityNodeInfo button2 = createNode("button2");
+        TreeTraverser treeTraverser = new TreeTraverser();
+        AccessibilityNodeInfo buttonA = treeTraverser.depthFirstSearch(mWindowRoot,
+                node -> BUTTONA_CONTENT_DESCRIPTION.equals(node.getContentDescription()));
+        if (!buttonA.isFocusable()) {
+            // The button node with content description is not focusable while its parent is
+            // focusable.
+            buttonA = buttonA.getParent();
+        }
+        AccessibilityNodeInfo buttonB = treeTraverser.depthFirstSearch(mWindowRoot,
+                node -> BUTTONB_CONTENT_DESCRIPTION.equals(node.getContentDescription()));
+        if (!buttonB.isFocusable()) {
+            buttonB = buttonB.getParent();
+        }
+
+        // Rotate clockwise 4 times (button1 -> buttonA -> ButtonB -> Button2 -> Button2).
+        int inputType = CarInputManager.INPUT_TYPE_ROTARY_NAVIGATION;
+        int eventTime = ROTATION_ACCELERATION_2X_MS + 1;
+        int validDisplayId = CarOccupantZoneManager.DISPLAY_TYPE_MAIN;
+        mRotaryService.onRotaryEvents(validDisplayId,
+                Collections.singletonList(
+                        new RotaryEvent(inputType, true, new long[]{eventTime})));
+        assertThat(mRotaryService.getFocusedNode()).isEqualTo(buttonA);
+
+        eventTime += ROTATION_ACCELERATION_2X_MS + 1;
+        mRotaryService.onRotaryEvents(validDisplayId,
+                Collections.singletonList(
+                        new RotaryEvent(inputType, true, new long[]{eventTime})));
+        assertThat(mRotaryService.getFocusedNode()).isEqualTo(buttonB);
+
+        eventTime += ROTATION_ACCELERATION_2X_MS + 1;
+        mRotaryService.onRotaryEvents(validDisplayId,
+                Collections.singletonList(
+                        new RotaryEvent(inputType, true, new long[]{eventTime})));
+        assertThat(mRotaryService.getFocusedNode()).isEqualTo(button2);
+
+        eventTime += ROTATION_ACCELERATION_2X_MS + 1;
+        mRotaryService.onRotaryEvents(validDisplayId,
+                Collections.singletonList(
+                        new RotaryEvent(inputType, true, new long[]{eventTime})));
+        // It has reached to the boundary.
+        assertThat(mRotaryService.getFocusedNode()).isEqualTo(button2);
+
+        // Rotate counter-clockwise 4 times (button2 -> buttonB -> ButtonA -> Button1 -> Button1).
+        eventTime += ROTATION_ACCELERATION_2X_MS + 1;
+        mRotaryService.onRotaryEvents(validDisplayId,
+                Collections.singletonList(
+                        new RotaryEvent(inputType, false, new long[]{eventTime})));
+        assertThat(mRotaryService.getFocusedNode()).isEqualTo(buttonB);
+
+        eventTime += ROTATION_ACCELERATION_2X_MS + 1;
+        mRotaryService.onRotaryEvents(validDisplayId,
+                Collections.singletonList(
+                        new RotaryEvent(inputType, false, new long[]{eventTime})));
+        assertThat(mRotaryService.getFocusedNode()).isEqualTo(buttonA);
+
+        eventTime += ROTATION_ACCELERATION_2X_MS + 1;
+        mRotaryService.onRotaryEvents(validDisplayId,
+                Collections.singletonList(
+                        new RotaryEvent(inputType, false, new long[]{eventTime})));
+        assertThat(mRotaryService.getFocusedNode()).isEqualTo(button1);
+
+        eventTime += ROTATION_ACCELERATION_2X_MS + 1;
+        mRotaryService.onRotaryEvents(validDisplayId,
+                Collections.singletonList(
+                        new RotaryEvent(inputType, false, new long[]{eventTime})));
+        // It has reached to the boundary.
+        assertThat(mRotaryService.getFocusedNode()).isEqualTo(button1);
+    }
+
     /**
      * Tests {@link RotaryService#nudgeTo(List, int)} in the following view tree:
      * <pre>
@@ -947,6 +1165,55 @@ public class RotaryServiceTest {
         assertThat(mRotaryService.getFocusedNode()).isEqualTo(appButton1Node);
     }
 
+    /**
+     * Tests {@link RotaryService#nudgeTo(List, int)} in the following layout:
+     * <pre>
+     *    ---------------------------------ComposeView-----------------------------------
+     *    -  =======Composable(FocusArea)======    ========Composable(FocusArea)======  -
+     *    -  =                                =    =                                 =  -
+     *    -  =  ...............               =    =  ...............                =  -
+     *    -  =  .             .               =    =  .             .                =  -
+     *    -  =  . Composable1 .               =    =  . Composable2 .                =  -
+     *    -  =  .             .               =    =  .             .                =  -
+     *    -  =  ...............               =    =  ...............                =  -
+     *    -  =                                =    =                                 =  -
+     *    -  ==================================    ===================================  -
+     *    -------------------------------------------------------------------------------
+     * </pre>
+     */
+    @Test
+    public void testNudgeTo_nudgeToComposables() {
+        initActivity(ComposeActivity.class, INVALID_RESOURCE_ID);
+
+        AccessibilityWindowInfo window = mWindowRoot.getWindow();
+        List<AccessibilityWindowInfo> windows = new ArrayList<>();
+        windows.add(window);
+        when(mRotaryService.getWindows()).thenReturn(windows);
+
+        TreeTraverser treeTraverser = new TreeTraverser();
+        AccessibilityNodeInfo leftFocusArea = treeTraverser.depthFirstSearch(mWindowRoot,
+                node -> LEFT_FOCUS_AREA_CONTENT_DESCRIPTION.equals(node.getContentDescription()));
+        AccessibilityNodeInfo leftButton = leftFocusArea.getChild(0);
+        assertThat(leftButton).isNotNull();
+        AccessibilityNodeInfo rightFocusArea = treeTraverser.depthFirstSearch(mWindowRoot,
+                node -> RIGHT_FOCUS_AREA_CONTENT_DESCRIPTION.equals(node.getContentDescription()));
+        AccessibilityNodeInfo rightButton = rightFocusArea.getChild(0);
+        assertThat(rightButton).isNotNull();
+        assertThat(leftButton).isNotEqualTo(rightButton);
+
+        mRotaryService.setFocusedNode(leftButton);
+
+        // Nudge to the right.
+        mRotaryService.nudgeTo(windows, View.FOCUS_RIGHT);
+        assertThat(mRotaryService.getFocusedNode()).isEqualTo(rightButton);
+
+        // Nudge back to the left.
+        mRotaryService.nudgeTo(windows, View.FOCUS_LEFT);
+        assertThat(mRotaryService.getFocusedNode()).isEqualTo(leftButton);
+
+        window.recycle();
+    }
+
     /**
      * Tests {@link RotaryService#onKeyEvents} in the following view tree:
      * <pre>
@@ -2296,13 +2563,26 @@ public class RotaryServiceTest {
     }
 
     /**
-     * Starts the test activity with the given layout and initializes the root
+     * Starts the NavigatorTestActivity with the given layout and initializes the root
      * {@link AccessibilityNodeInfo}.
      */
     private void initActivity(@LayoutRes int layoutResId) {
-        mIntent.putExtra(NavigatorTestActivity.KEY_LAYOUT_ID, layoutResId);
+        initActivity(NavigatorTestActivity.class, layoutResId);
+    }
+
+    /**
+     * Starts the given Activity with the given layout and initializes the root
+     * {@link AccessibilityNodeInfo}.
+     */
+    private void initActivity(Class<? extends Activity> activityClass, @LayoutRes int layoutResId) {
+        mActivityRule = new ActivityTestRule<>(activityClass);
+        mIntent = new Intent();
+        mIntent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TASK | Intent.FLAG_ACTIVITY_NEW_TASK);
+        if (layoutResId != INVALID_RESOURCE_ID) {
+            mIntent.putExtra(NavigatorTestActivity.KEY_LAYOUT_ID, layoutResId);
+        }
         mActivityRule.launchActivity(mIntent);
-        mWindowRoot = sUiAutomation.getRootInActiveWindow();
+        PollingCheck.waitFor(() -> (mWindowRoot = sUiAutomation.getRootInActiveWindow()) != null);
     }
 
     /**
diff --git a/tests/unit/src/com/android/car/rotary/ViewComposeActivity.kt b/tests/unit/src/com/android/car/rotary/ViewComposeActivity.kt
new file mode 100644
index 0000000..8fd593b
--- /dev/null
+++ b/tests/unit/src/com/android/car/rotary/ViewComposeActivity.kt
@@ -0,0 +1,66 @@
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
+package com.android.car.rotary
+
+import android.os.Bundle
+import androidx.activity.ComponentActivity
+import androidx.activity.compose.setContent
+import androidx.compose.foundation.layout.Row
+import androidx.compose.foundation.layout.fillMaxWidth
+import androidx.compose.material3.Button
+import androidx.compose.material3.MaterialTheme
+import androidx.compose.material3.Surface
+import androidx.compose.material3.Text
+import androidx.compose.ui.Modifier
+import androidx.compose.ui.platform.ComposeView
+import androidx.compose.ui.semantics.contentDescription
+import androidx.compose.ui.semantics.semantics
+import androidx.core.view.WindowCompat
+
+const val BUTTONA_CONTENT_DESCRIPTION = "ButtonA"
+const val BUTTONB_CONTENT_DESCRIPTION = "ButtonB"
+
+class ViewComposeActivity : ComponentActivity() {
+    override fun onCreate(savedInstanceState: Bundle?) {
+        super.onCreate(savedInstanceState)
+        WindowCompat.setDecorFitsSystemWindows(this.window, true)
+        setContentView(R.layout.navigator_view_and_compose_activity)
+        val composeView: ComposeView = findViewById<ComposeView>(R.id.compose_view)
+        composeView.setContent {
+            MaterialTheme {
+                Surface(
+                        modifier = Modifier.fillMaxWidth(),
+                        color = MaterialTheme.colorScheme.surfaceVariant
+                ) {
+                    Row {
+                        Button(
+                                onClick = {},
+                                modifier = Modifier.semantics() {
+                                    contentDescription = BUTTONA_CONTENT_DESCRIPTION
+                                }
+                        ) { Text(BUTTONA_CONTENT_DESCRIPTION) }
+                        Button(
+                                onClick = {},
+                                modifier = Modifier.semantics() {
+                                    contentDescription = BUTTONB_CONTENT_DESCRIPTION
+                                }
+                        ) { Text(BUTTONB_CONTENT_DESCRIPTION) }
+                    }
+                }
+            }
+        }
+    }
+}
diff --git a/tests/unit/src/com/android/car/rotary/WebViewTestActivity.java b/tests/unit/src/com/android/car/rotary/WebViewTestActivity.java
new file mode 100644
index 0000000..9abfd5b
--- /dev/null
+++ b/tests/unit/src/com/android/car/rotary/WebViewTestActivity.java
@@ -0,0 +1,54 @@
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
+package com.android.car.rotary;
+
+import android.app.Activity;
+import android.content.res.Resources;
+import android.os.Bundle;
+import android.util.Base64;
+import android.util.Log;
+import android.webkit.WebView;
+
+import androidx.annotation.Nullable;
+
+import java.io.IOException;
+import java.io.InputStream;
+
+/** An activity used for testing {@link com.android.car.rotary.Navigator}. */
+public class WebViewTestActivity extends Activity {
+
+    @Override
+    protected void onCreate(@Nullable Bundle savedInstanceState) {
+        super.onCreate(savedInstanceState);
+
+        setContentView(R.layout.navigator_webview_activity);
+
+        WebView webView = findViewById(R.id.web_view);
+        Resources res = getResources();
+        InputStream inputStream = res.openRawResource(R.raw.web_view_html);
+        byte[] byteArray = new byte[0];
+        try {
+            byteArray = new byte[inputStream.available()];
+            inputStream.read(byteArray);
+        } catch (IOException e) {
+            Log.w("WebViewFragment", "Can't read HTML");
+        }
+        String webViewHtml = new String(byteArray);
+        String encodedHtml = Base64.encodeToString(webViewHtml.getBytes(), Base64.NO_PADDING);
+        webView.loadData(encodedHtml, "text/html", "base64");
+    }
+}
```

