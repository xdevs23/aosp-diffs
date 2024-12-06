```diff
diff --git a/OWNERS b/OWNERS
index 2cb7cb2..8f13331 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,2 +1,3 @@
 zzhen@google.com
 rajekumar@google.com
+kevhan@google.com
diff --git a/src/com/android/systemui/go/SystemUIGoModule.java b/src/com/android/systemui/go/SystemUIGoModule.java
index 188f71e..aa6a500 100644
--- a/src/com/android/systemui/go/SystemUIGoModule.java
+++ b/src/com/android/systemui/go/SystemUIGoModule.java
@@ -24,7 +24,9 @@ import android.hardware.SensorPrivacyManager;
 
 import com.android.keyguard.KeyguardViewController;
 import com.android.systemui.ScreenDecorationsModule;
+import com.android.systemui.accessibility.AccessibilityModule;
 import com.android.systemui.accessibility.SystemActionsModule;
+import com.android.systemui.accessibility.data.repository.AccessibilityRepositoryModule;
 import com.android.systemui.battery.BatterySaverModule;
 import com.android.systemui.biometrics.dagger.BiometricsModule;
 import com.android.systemui.dagger.GlobalRootComponent;
@@ -51,6 +53,7 @@ import com.android.systemui.recents.RecentsModule;
 import com.android.systemui.rotationlock.RotationLockModule;
 import com.android.systemui.screenshot.ReferenceScreenshotModule;
 import com.android.systemui.settings.MultiUserUtilsModule;
+import com.android.systemui.settings.UserTracker;
 import com.android.systemui.shade.NotificationShadeWindowControllerImpl;
 import com.android.systemui.shade.ShadeModule;
 import com.android.systemui.statusbar.CommandQueue;
@@ -85,6 +88,8 @@ import javax.inject.Named;
  * Android Go. This is forked from {@link ReferenceSystemUIModule}
  */
 @Module(includes = {
+        AccessibilityModule.class,
+        AccessibilityRepositoryModule.class,
         AospPolicyModule.class,
         BatterySaverModule.class,
         BiometricsModule.class,
@@ -142,9 +147,9 @@ public abstract class SystemUIGoModule {
     @Provides
     @SysUISingleton
     static IndividualSensorPrivacyController provideIndividualSensorPrivacyController(
-            SensorPrivacyManager sensorPrivacyManager) {
+            SensorPrivacyManager sensorPrivacyManager, UserTracker userTracker) {
         IndividualSensorPrivacyController ispC = new IndividualSensorPrivacyControllerImpl(
-                sensorPrivacyManager);
+                sensorPrivacyManager, userTracker);
         ispC.init();
         return ispC;
     }
```

