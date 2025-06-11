```diff
diff --git a/Android.bp b/Android.bp
index a67ea3a..2c11929 100644
--- a/Android.bp
+++ b/Android.bp
@@ -26,6 +26,9 @@ android_library {
     resource_dirs: [
         "res",
     ],
+    javacflags: [
+        "-Adagger.useBindingGraphFix=ENABLED",
+    ],
     static_libs: [
         "SystemUI-core",
         "SystemUIPluginLib",
@@ -55,6 +58,10 @@ android_app {
     certificate: "platform",
     privileged: true,
 
+    javacflags: [
+        "-Adagger.useBindingGraphFix=ENABLED",
+    ],
+
     kotlincflags: ["-Xjvm-default=all"],
 
     dxflags: ["--multi-dex"],
diff --git a/src/com/android/systemui/go/SystemUIGoComponent.java b/src/com/android/systemui/go/SystemUIGoComponent.java
index 1b67cd6..a386578 100644
--- a/src/com/android/systemui/go/SystemUIGoComponent.java
+++ b/src/com/android/systemui/go/SystemUIGoComponent.java
@@ -26,6 +26,7 @@ import com.android.systemui.dagger.SystemUIModule;
 import com.android.systemui.keyguard.dagger.KeyguardModule;
 import com.android.systemui.keyguard.CustomizationProvider;
 import com.android.systemui.recents.RecentsModule;
+import com.android.systemui.rotationlock.DeviceStateAutoRotateModule;
 import com.android.systemui.scene.SceneContainerFrameworkModule;
 import com.android.systemui.statusbar.dagger.CentralSurfacesModule;
 import com.android.systemui.statusbar.NotificationInsetsModule;
@@ -43,6 +44,7 @@ import dagger.Subcomponent;
         DefaultActivityBinder.class,
         DefaultBroadcastReceiverBinder.class,
         DefaultServiceBinder.class,
+        DeviceStateAutoRotateModule.class,
         SystemUIGoCoreStartableModule.class,
         KeyguardModule.class,
         RecentsModule.class,
diff --git a/src/com/android/systemui/go/SystemUIGoModule.java b/src/com/android/systemui/go/SystemUIGoModule.java
index b7c5012..de231d8 100644
--- a/src/com/android/systemui/go/SystemUIGoModule.java
+++ b/src/com/android/systemui/go/SystemUIGoModule.java
@@ -30,6 +30,7 @@ import com.android.systemui.accessibility.data.repository.AccessibilityRepositor
 import com.android.systemui.battery.BatterySaverModule;
 import com.android.systemui.biometrics.dagger.BiometricsModule;
 import com.android.systemui.clipboardoverlay.dagger.ClipboardOverlayOverrideModule;
+import com.android.systemui.communal.posturing.dagger.NoopPosturingModule;
 import com.android.systemui.dagger.GlobalRootComponent;
 import com.android.systemui.dagger.ReferenceSystemUIModule;
 import com.android.systemui.dagger.SysUISingleton;
@@ -56,6 +57,7 @@ import com.android.systemui.rotationlock.RotationLockModule;
 import com.android.systemui.screenshot.ReferenceScreenshotModule;
 import com.android.systemui.settings.MultiUserUtilsModule;
 import com.android.systemui.settings.UserTracker;
+import com.android.systemui.settings.brightness.dagger.BrightnessSliderModule;
 import com.android.systemui.shade.NotificationShadeWindowControllerImpl;
 import com.android.systemui.shade.ShadeModule;
 import com.android.systemui.statusbar.CommandQueue;
@@ -97,6 +99,7 @@ import javax.inject.Named;
         AospPolicyModule.class,
         BatterySaverModule.class,
         BiometricsModule.class,
+        BrightnessSliderModule.class,
         ClipboardOverlayOverrideModule.class,
         CollapsedStatusBarFragmentStartableModule.class,
         ConnectingDisplayViewModel.StartableModule.class,
@@ -110,6 +113,7 @@ import javax.inject.Named;
         MultiUserUtilsModule.class,
         NavigationBarControllerModule.class,
         NearbyMediaDevicesManager.StartableModule.class,
+        NoopPosturingModule.class,
         PowerModule.class,
         QSModule.class,
         RecentsModule.class,
```

