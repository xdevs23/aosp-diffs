```diff
diff --git a/Android.bp b/Android.bp
index 2c11929..0ee4c9b 100644
--- a/Android.bp
+++ b/Android.bp
@@ -16,6 +16,7 @@
 
 package {
     default_applicable_licenses: ["Android-Apache-2.0"],
+    default_team: "trendy_team_android_go",
 }
 
 android_library {
@@ -46,7 +47,7 @@ android_app {
         "wmshell_defaults",
     ],
     static_libs: [
-        "SystemUIGo-core"
+        "SystemUIGo-core",
     ],
     overrides: [
         "SystemUI",
diff --git a/res/values/config.xml b/res/values/config.xml
index 4e5e4e2..9aa3110 100644
--- a/res/values/config.xml
+++ b/res/values/config.xml
@@ -23,6 +23,11 @@
         internet,bt,airplane,flashlight
     </string>
 
+    <!-- The default tiles to display in QuickSettings with the new UI -->
+    <string name="quick_settings_tiles_new_default" translatable="false">
+        @string/quick_settings_tiles_default
+    </string>
+
     <!-- The minimum number of tiles to display in QuickSettings -->
     <integer name="quick_settings_min_num_tiles">3</integer>
 
diff --git a/src/com/android/systemui/go/SystemUIGoModule.java b/src/com/android/systemui/go/SystemUIGoModule.java
index de231d8..bb2605b 100644
--- a/src/com/android/systemui/go/SystemUIGoModule.java
+++ b/src/com/android/systemui/go/SystemUIGoModule.java
@@ -34,6 +34,9 @@ import com.android.systemui.communal.posturing.dagger.NoopPosturingModule;
 import com.android.systemui.dagger.GlobalRootComponent;
 import com.android.systemui.dagger.ReferenceSystemUIModule;
 import com.android.systemui.dagger.SysUISingleton;
+import com.android.systemui.display.dagger.SystemUIDisplaySubcomponent;
+import com.android.systemui.display.dagger.SystemUIPhoneDisplaySubcomponent;
+import com.android.systemui.display.data.repository.DisplayPhoneModule;
 import com.android.systemui.display.ui.viewmodel.ConnectingDisplayViewModel;
 import com.android.systemui.dock.DockManager;
 import com.android.systemui.dock.DockManagerImpl;
@@ -44,10 +47,14 @@ import com.android.systemui.keyguard.ui.view.layout.sections.KeyguardSectionsMod
 import com.android.systemui.media.dagger.MediaModule;
 import com.android.systemui.media.muteawait.MediaMuteAwaitConnectionCli;
 import com.android.systemui.media.nearby.NearbyMediaDevicesManager;
+import com.android.systemui.Flags;
+import com.android.systemui.minmode.MinModeManager;
+import com.android.systemui.minmode.MinModeManagerImpl;
 import com.android.systemui.navigationbar.NavigationBarControllerModule;
 import com.android.systemui.navigationbar.gestural.GestureModule;
 import com.android.systemui.plugins.qs.QSFactory;
 import com.android.systemui.power.dagger.PowerModule;
+import com.android.systemui.qs.QSFragmentStartableModule;
 import com.android.systemui.qs.dagger.QSModule;
 import com.android.systemui.qs.tileimpl.QSFactoryImpl;
 import com.android.systemui.recents.Recents;
@@ -87,7 +94,9 @@ import dagger.Binds;
 import dagger.Module;
 import dagger.Provides;
 
+import java.util.Optional;
 import javax.inject.Named;
+import javax.inject.Provider;
 
 /**
  * A dagger module for overriding the default implementations of injected System UI components on
@@ -103,6 +112,7 @@ import javax.inject.Named;
         ClipboardOverlayOverrideModule.class,
         CollapsedStatusBarFragmentStartableModule.class,
         ConnectingDisplayViewModel.StartableModule.class,
+        DisplayPhoneModule.class,
         EmergencyGestureModule.class,
         GestureModule.class,
         HeadsUpModule.class,
@@ -115,6 +125,7 @@ import javax.inject.Named;
         NearbyMediaDevicesManager.StartableModule.class,
         NoopPosturingModule.class,
         PowerModule.class,
+        QSFragmentStartableModule.class,
         QSModule.class,
         RecentsModule.class,
         ReferenceNotificationsModule.class,
@@ -129,9 +140,15 @@ import javax.inject.Named;
         ToastModule.class,
         WallpaperModule.class,
         VolumeModule.class,
+}, subcomponents = {
+        SystemUIPhoneDisplaySubcomponent.class
 })
 public abstract class SystemUIGoModule {
 
+    @Binds
+    abstract SystemUIDisplaySubcomponent.Factory systemUIDisplaySubcomponentFactory(
+            SystemUIPhoneDisplaySubcomponent.Factory factory);
+
     @Binds
     abstract GlobalRootComponent bindGlobalRootComponent(
             SystemUIGoGlobalRootComponent globalRootComponent);
@@ -205,4 +222,15 @@ public abstract class SystemUIGoModule {
 
     @Binds
     abstract DozeHost provideDozeHost(DozeServiceHost dozeServiceHost);
+
+    @Provides
+    @SysUISingleton
+    static Optional<MinModeManager> provideMinModeManager(
+            Provider<MinModeManagerImpl> minModeManagerProvider) {
+        if (Flags.enableMinmode()) {
+            return Optional.of(minModeManagerProvider.get());
+        } else {
+            return Optional.empty();
+        }
+    }
 }
```

