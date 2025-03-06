```diff
diff --git a/Android.bp b/Android.bp
index 0fbcfd7..a67ea3a 100644
--- a/Android.bp
+++ b/Android.bp
@@ -40,6 +40,7 @@ android_app {
     defaults: [
         "platform_app_defaults",
         "SystemUI_optimized_defaults",
+        "wmshell_defaults",
     ],
     static_libs: [
         "SystemUIGo-core"
diff --git a/src/com/android/systemui/go/SystemUIGoCoreStartableModule.java b/src/com/android/systemui/go/SystemUIGoCoreStartableModule.java
index 7262e3c..8358bd9 100644
--- a/src/com/android/systemui/go/SystemUIGoCoreStartableModule.java
+++ b/src/com/android/systemui/go/SystemUIGoCoreStartableModule.java
@@ -32,8 +32,7 @@ import com.android.systemui.log.SessionTracker;
 import com.android.systemui.media.RingtonePlayer;
 import com.android.systemui.shortcut.ShortcutKeyDispatcher;
 import com.android.systemui.statusbar.notification.InstantAppNotifier;
-import com.android.systemui.statusbar.phone.ScrimController;
-import com.android.systemui.statusbar.phone.StatusBarHeadsUpChangeListener;
+import com.android.systemui.statusbar.notification.headsup.StatusBarHeadsUpChangeListener;
 import com.android.systemui.theme.ThemeOverlayController;
 import com.android.systemui.usb.StorageNotification;
 import com.android.systemui.util.NotificationChannels;
@@ -160,12 +159,6 @@ abstract class SystemUIGoCoreStartableModule {
     @ClassKey(KeyguardViewConfigurator.class)
     abstract CoreStartable bindKeyguardViewConfigurator(KeyguardViewConfigurator impl);
 
-    /** Inject into ScrimController. */
-    @Binds
-    @IntoMap
-    @ClassKey(ScrimController.class)
-    abstract CoreStartable bindScrimController(ScrimController scrimController);
-
     @Binds
     @IntoMap
     @ClassKey(StatusBarHeadsUpChangeListener.class)
diff --git a/src/com/android/systemui/go/SystemUIGoModule.java b/src/com/android/systemui/go/SystemUIGoModule.java
index aa6a500..b7c5012 100644
--- a/src/com/android/systemui/go/SystemUIGoModule.java
+++ b/src/com/android/systemui/go/SystemUIGoModule.java
@@ -29,6 +29,7 @@ import com.android.systemui.accessibility.SystemActionsModule;
 import com.android.systemui.accessibility.data.repository.AccessibilityRepositoryModule;
 import com.android.systemui.battery.BatterySaverModule;
 import com.android.systemui.biometrics.dagger.BiometricsModule;
+import com.android.systemui.clipboardoverlay.dagger.ClipboardOverlayOverrideModule;
 import com.android.systemui.dagger.GlobalRootComponent;
 import com.android.systemui.dagger.ReferenceSystemUIModule;
 import com.android.systemui.dagger.SysUISingleton;
@@ -36,6 +37,7 @@ import com.android.systemui.display.ui.viewmodel.ConnectingDisplayViewModel;
 import com.android.systemui.dock.DockManager;
 import com.android.systemui.dock.DockManagerImpl;
 import com.android.systemui.doze.DozeHost;
+import com.android.systemui.emergency.EmergencyGestureModule;
 import com.android.systemui.keyguard.ui.view.layout.blueprints.KeyguardBlueprintModule;
 import com.android.systemui.keyguard.ui.view.layout.sections.KeyguardSectionsModule;
 import com.android.systemui.media.dagger.MediaModule;
@@ -61,9 +63,11 @@ import com.android.systemui.statusbar.NotificationLockscreenUserManager;
 import com.android.systemui.statusbar.NotificationLockscreenUserManagerImpl;
 import com.android.systemui.statusbar.NotificationShadeWindowController;
 import com.android.systemui.statusbar.dagger.StartCentralSurfacesModule;
+import com.android.systemui.statusbar.notification.dagger.ReferenceNotificationsModule;
+import com.android.systemui.statusbar.notification.headsup.HeadsUpModule;
 import com.android.systemui.statusbar.phone.DozeServiceHost;
-import com.android.systemui.statusbar.phone.HeadsUpModule;
 import com.android.systemui.statusbar.phone.StatusBarKeyguardViewManager;
+import com.android.systemui.statusbar.phone.dagger.StatusBarPhoneModule;
 import com.android.systemui.statusbar.phone.fragment.CollapsedStatusBarFragmentStartableModule;
 import com.android.systemui.statusbar.policy.AospPolicyModule;
 import com.android.systemui.statusbar.policy.DeviceProvisionedController;
@@ -93,8 +97,10 @@ import javax.inject.Named;
         AospPolicyModule.class,
         BatterySaverModule.class,
         BiometricsModule.class,
+        ClipboardOverlayOverrideModule.class,
         CollapsedStatusBarFragmentStartableModule.class,
         ConnectingDisplayViewModel.StartableModule.class,
+        EmergencyGestureModule.class,
         GestureModule.class,
         HeadsUpModule.class,
         KeyguardBlueprintModule.class,
@@ -107,10 +113,12 @@ import javax.inject.Named;
         PowerModule.class,
         QSModule.class,
         RecentsModule.class,
+        ReferenceNotificationsModule.class,
         ReferenceScreenshotModule.class,
         RotationLockModule.class,
         ScreenDecorationsModule.class,
         ShadeModule.class,
+        StatusBarPhoneModule.class,
         StartCentralSurfacesModule.class,
         SystemActionsModule.class,
         SysUIUnfoldStartableModule.class,
```

