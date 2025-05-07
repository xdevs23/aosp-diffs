```diff
diff --git a/src/com/android/settings/Utils.java b/src/com/android/settings/Utils.java
index a9144ead6b7..61c9df47015 100644
--- a/src/com/android/settings/Utils.java
+++ b/src/com/android/settings/Utils.java
@@ -131,6 +131,7 @@ import com.android.settings.password.ConfirmDeviceCredentialActivity;
 import com.android.settingslib.widget.ActionBarShadowController;
 import com.android.settingslib.widget.AdaptiveIcon;
 
+import java.util.Arrays;
 import java.util.Iterator;
 import java.util.List;
 import java.util.Locale;
@@ -1600,4 +1601,19 @@ public final class Utils extends com.android.settingslib.Utils {
         pm.setComponentEnabledSetting(componentName,
                 PackageManager.COMPONENT_ENABLED_STATE_DISABLED, PackageManager.DONT_KILL_APP);
     }
+
+    /**
+     * Returns {@code true} if the supplied package is a protected package. Otherwise, returns
+     * {@code false}.
+     *
+     * @param context the context
+     * @param packageName the package name
+     */
+    public static boolean isProtectedPackage(
+            @NonNull Context context, @NonNull String packageName) {
+        final List<String> protectedPackageNames = Arrays.asList(context.getResources()
+                .getStringArray(com.android.internal.R.array
+                        .config_biometric_protected_package_names));
+        return protectedPackageNames != null && protectedPackageNames.contains(packageName);
+    }
 }
diff --git a/src/com/android/settings/applications/appinfo/AppButtonsPreferenceController.java b/src/com/android/settings/applications/appinfo/AppButtonsPreferenceController.java
index 1d80099f5c3..70bf78e879d 100644
--- a/src/com/android/settings/applications/appinfo/AppButtonsPreferenceController.java
+++ b/src/com/android/settings/applications/appinfo/AppButtonsPreferenceController.java
@@ -53,6 +53,7 @@ import com.android.settings.R;
 import com.android.settings.SettingsActivity;
 import com.android.settings.Utils;
 import com.android.settings.applications.ApplicationFeatureProvider;
+import com.android.settings.applications.appinfo.AppInfoDashboardFragment;
 import com.android.settings.applications.specialaccess.deviceadmin.DeviceAdminAdd;
 import com.android.settings.core.BasePreferenceController;
 import com.android.settings.core.InstrumentedPreferenceFragment;
@@ -240,13 +241,21 @@ public class AppButtonsPreferenceController extends BasePreferenceController imp
             } else if ((mAppEntry.info.flags & ApplicationInfo.FLAG_SYSTEM) != 0) {
                 if (mAppEntry.info.enabled && !isDisabledUntilUsed()) {
                     showDialogInner(ButtonActionDialogFragment.DialogType.DISABLE);
+                } else if (mAppEntry.info.enabled) {
+                    requireAuthAndExecute(() -> {
+                        mMetricsFeatureProvider.action(
+                                mActivity,
+                                SettingsEnums.ACTION_SETTINGS_DISABLE_APP,
+                                getPackageNameForMetric());
+                        AsyncTask.execute(new DisableChangerRunnable(mPm,
+                                mAppEntry.info.packageName,
+                                PackageManager.COMPONENT_ENABLED_STATE_DEFAULT));
+                    });
                 } else {
                     mMetricsFeatureProvider.action(
                             mActivity,
-                            mAppEntry.info.enabled
-                                    ? SettingsEnums.ACTION_SETTINGS_DISABLE_APP
-                                    : SettingsEnums.ACTION_SETTINGS_ENABLE_APP,
-                                    getPackageNameForMetric());
+                            SettingsEnums.ACTION_SETTINGS_ENABLE_APP,
+                            getPackageNameForMetric());
                     AsyncTask.execute(new DisableChangerRunnable(mPm, mAppEntry.info.packageName,
                             PackageManager.COMPONENT_ENABLED_STATE_DEFAULT));
                 }
@@ -289,17 +298,34 @@ public class AppButtonsPreferenceController extends BasePreferenceController imp
         }
     }
 
+    /**
+     * Runs the given action with restricted lock authentication if it is a protected package.
+     *
+     * @param action The action to run.
+     */
+    private void requireAuthAndExecute(Runnable action) {
+        if (Utils.isProtectedPackage(mContext, mAppEntry.info.packageName)) {
+            AppInfoDashboardFragment.showLockScreen(mContext, () -> action.run());
+        } else {
+            action.run();
+        }
+    }
+
     public void handleDialogClick(int id) {
         switch (id) {
             case ButtonActionDialogFragment.DialogType.DISABLE:
-                mMetricsFeatureProvider.action(mActivity,
-                        SettingsEnums.ACTION_SETTINGS_DISABLE_APP,
-                        getPackageNameForMetric());
-                AsyncTask.execute(new DisableChangerRunnable(mPm, mAppEntry.info.packageName,
-                        PackageManager.COMPONENT_ENABLED_STATE_DISABLED_USER));
+                requireAuthAndExecute(() -> {
+                    mMetricsFeatureProvider.action(mActivity,
+                            SettingsEnums.ACTION_SETTINGS_DISABLE_APP,
+                            getPackageNameForMetric());
+                    AsyncTask.execute(new DisableChangerRunnable(mPm, mAppEntry.info.packageName,
+                            PackageManager.COMPONENT_ENABLED_STATE_DISABLED_USER));
+                });
                 break;
             case ButtonActionDialogFragment.DialogType.FORCE_STOP:
-                forceStopPackage(mAppEntry.info.packageName);
+                requireAuthAndExecute(() -> {
+                    forceStopPackage(mAppEntry.info.packageName);
+                });
                 break;
         }
     }
@@ -535,14 +561,16 @@ public class AppButtonsPreferenceController extends BasePreferenceController imp
 
     @VisibleForTesting
     void uninstallPkg(String packageName, boolean allUsers) {
-        stopListeningToPackageRemove();
-        // Create new intent to launch Uninstaller activity
-        Uri packageUri = Uri.parse("package:" + packageName);
-        Intent uninstallIntent = new Intent(Intent.ACTION_UNINSTALL_PACKAGE, packageUri);
-        uninstallIntent.putExtra(Intent.EXTRA_UNINSTALL_ALL_USERS, allUsers);
-
-        mMetricsFeatureProvider.action(mActivity, SettingsEnums.ACTION_SETTINGS_UNINSTALL_APP);
-        mFragment.startActivityForResult(uninstallIntent, mRequestUninstall);
+        requireAuthAndExecute(() -> {
+            stopListeningToPackageRemove();
+            // Create new intent to launch Uninstaller activity
+            Uri packageUri = Uri.parse("package:" + packageName);
+            Intent uninstallIntent = new Intent(Intent.ACTION_UNINSTALL_PACKAGE, packageUri);
+            uninstallIntent.putExtra(Intent.EXTRA_UNINSTALL_ALL_USERS, allUsers);
+
+            mMetricsFeatureProvider.action(mActivity, SettingsEnums.ACTION_SETTINGS_UNINSTALL_APP);
+            mFragment.startActivityForResult(uninstallIntent, mRequestUninstall);
+        });
     }
 
     @VisibleForTesting
diff --git a/src/com/android/settings/notification/NotificationAccessConfirmationActivity.java b/src/com/android/settings/notification/NotificationAccessConfirmationActivity.java
index 8448a8e752a..541c1051913 100644
--- a/src/com/android/settings/notification/NotificationAccessConfirmationActivity.java
+++ b/src/com/android/settings/notification/NotificationAccessConfirmationActivity.java
@@ -123,7 +123,7 @@ public class NotificationAccessConfirmationActivity extends Activity
                 NLSIntent, /* flags */ 0, mUserId);
         boolean hasNLSIntentFilter = false;
         for (ResolveInfo service : matchedServiceList) {
-            if (service.serviceInfo.packageName.equals(mComponentName.getPackageName())) {
+            if (service.serviceInfo.getComponentName().equals(mComponentName)) {
                 if (!requiredPermission.equals(service.serviceInfo.permission)) {
                     Slog.e(LOG_TAG, "Service " + mComponentName + " lacks permission "
                             + requiredPermission);
@@ -157,7 +157,7 @@ public class NotificationAccessConfirmationActivity extends Activity
                 .installContent(p);
         // Consistent with the permission dialog
         // Used instead of p.mCancelable as that is only honored for AlertDialog
-        getWindow().setCloseOnTouchOutside(false); 
+        getWindow().setCloseOnTouchOutside(false);
     }
 
     private void onAllow() {
diff --git a/src/com/android/settings/security/ContentProtectionTogglePreferenceController.java b/src/com/android/settings/security/ContentProtectionTogglePreferenceController.java
index 9203d61f047..69ac6b100be 100644
--- a/src/com/android/settings/security/ContentProtectionTogglePreferenceController.java
+++ b/src/com/android/settings/security/ContentProtectionTogglePreferenceController.java
@@ -21,6 +21,7 @@ import android.app.admin.DevicePolicyManager;
 import android.content.ContentResolver;
 import android.content.Context;
 import android.os.UserHandle;
+import android.os.UserManager;
 import android.provider.Settings;
 import android.widget.CompoundButton;
 import android.widget.CompoundButton.OnCheckedChangeListener;
@@ -126,6 +127,14 @@ public class ContentProtectionTogglePreferenceController extends TogglePreferenc
                 && mContentProtectionPolicy
                         != DevicePolicyManager.CONTENT_PROTECTION_NOT_CONTROLLED_BY_POLICY) {
             mSwitchBar.setDisabledByAdmin(mEnforcedAdmin);
+            return;
+        }
+
+        UserManager userManager = mContext.getSystemService(UserManager.class);
+        if (userManager != null
+                && userManager.isGuestUser()
+                && mSwitchBar != null) {
+            mSwitchBar.setEnabled(false);
         }
     }
 
diff --git a/src/com/android/settings/spa/SpaAppBridgeActivity.kt b/src/com/android/settings/spa/SpaAppBridgeActivity.kt
index a68d2204c3b..67a5be951fd 100644
--- a/src/com/android/settings/spa/SpaAppBridgeActivity.kt
+++ b/src/com/android/settings/spa/SpaAppBridgeActivity.kt
@@ -38,7 +38,7 @@ class SpaAppBridgeActivity : Activity() {
 
     companion object {
         fun getDestinationForApp(destinationPrefix: String, intent: Intent): String? {
-            val packageName = intent.data?.schemeSpecificPart ?: return null
+            val packageName = intent.data?.schemeSpecificPart?.takeIf { Regex("^([a-zA-Z]\\w*\\.)*[a-zA-Z]\\w*$").matches(it) } ?: return null
             return "$destinationPrefix/$packageName/${UserHandle.myUserId()}"
         }
     }
diff --git a/src/com/android/settings/spa/app/appinfo/PackageInfoPresenter.kt b/src/com/android/settings/spa/app/appinfo/PackageInfoPresenter.kt
index 8dbcb14e83b..36fe93e2f27 100644
--- a/src/com/android/settings/spa/app/appinfo/PackageInfoPresenter.kt
+++ b/src/com/android/settings/spa/app/appinfo/PackageInfoPresenter.kt
@@ -29,6 +29,8 @@ import android.os.UserHandle
 import android.util.Log
 import androidx.annotation.VisibleForTesting
 import androidx.compose.runtime.Composable
+import com.android.settings.Utils
+import com.android.settings.applications.appinfo.AppInfoDashboardFragment
 import com.android.settings.flags.FeatureFlags
 import com.android.settings.flags.FeatureFlagsImpl
 import com.android.settings.overlay.FeatureFactory.Companion.featureFactory
@@ -116,6 +118,16 @@ class PackageInfoPresenter(
 
     private fun isForThisApp(intent: Intent) = packageName == intent.data?.schemeSpecificPart
 
+    private fun requireAuthAndExecute(action: () -> Unit) {
+        if (Utils.isProtectedPackage(context, packageName)) {
+            AppInfoDashboardFragment.showLockScreen(context) {
+                action()
+            }
+        } else {
+            action()
+        }
+    }
+
     /** Enables this package. */
     fun enable() {
         logAction(SettingsEnums.ACTION_SETTINGS_ENABLE_APP)
@@ -129,17 +141,21 @@ class PackageInfoPresenter(
     /** Disables this package. */
     fun disable() {
         logAction(SettingsEnums.ACTION_SETTINGS_DISABLE_APP)
-        coroutineScope.launch(Dispatchers.IO) {
-            userPackageManager.setApplicationEnabledSetting(
-                packageName, PackageManager.COMPONENT_ENABLED_STATE_DISABLED_USER, 0
-            )
+        requireAuthAndExecute {
+            coroutineScope.launch(Dispatchers.IO) {
+                userPackageManager.setApplicationEnabledSetting(
+                    packageName, PackageManager.COMPONENT_ENABLED_STATE_DISABLED_USER, 0
+                )
+            }
         }
     }
 
     /** Starts the uninstallation activity. */
     fun startUninstallActivity(forAllUsers: Boolean = false) {
         logAction(SettingsEnums.ACTION_SETTINGS_UNINSTALL_APP)
-        context.startUninstallActivity(packageName, userHandle, forAllUsers)
+        requireAuthAndExecute {
+            context.startUninstallActivity(packageName, userHandle, forAllUsers)
+        }
     }
 
     /** Clears this instant app. */
@@ -153,17 +169,19 @@ class PackageInfoPresenter(
     /** Force stops this package. */
     fun forceStop() {
         logAction(SettingsEnums.ACTION_APP_FORCE_STOP)
-        coroutineScope.launch(Dispatchers.Default) {
-            Log.d(TAG, "Stopping package $packageName")
-            if (android.app.Flags.appRestrictionsApi()) {
-                val uid = userPackageManager.getPackageUid(packageName, 0)
-                context.activityManager.noteAppRestrictionEnabled(
-                    packageName, uid,
-                    ActivityManager.RESTRICTION_LEVEL_FORCE_STOPPED, true,
-                    ActivityManager.RESTRICTION_REASON_USER, "settings",
-                    ActivityManager.RESTRICTION_SOURCE_USER, 0)
+        requireAuthAndExecute {
+            coroutineScope.launch(Dispatchers.Default) {
+                Log.d(TAG, "Stopping package $packageName")
+                if (android.app.Flags.appRestrictionsApi()) {
+                    val uid = userPackageManager.getPackageUid(packageName, 0)
+                    context.activityManager.noteAppRestrictionEnabled(
+                        packageName, uid,
+                        ActivityManager.RESTRICTION_LEVEL_FORCE_STOPPED, true,
+                        ActivityManager.RESTRICTION_REASON_USER, "settings",
+                        ActivityManager.RESTRICTION_SOURCE_USER, 0)
+                }
+                context.activityManager.forceStopPackageAsUser(packageName, userId)
             }
-            context.activityManager.forceStopPackageAsUser(packageName, userId)
         }
     }
 
diff --git a/tests/robotests/src/com/android/settings/applications/appinfo/AppButtonsPreferenceControllerTest.java b/tests/robotests/src/com/android/settings/applications/appinfo/AppButtonsPreferenceControllerTest.java
index 6fc01fc52ed..6c29036cb7b 100644
--- a/tests/robotests/src/com/android/settings/applications/appinfo/AppButtonsPreferenceControllerTest.java
+++ b/tests/robotests/src/com/android/settings/applications/appinfo/AppButtonsPreferenceControllerTest.java
@@ -60,6 +60,7 @@ import com.android.settings.R;
 import com.android.settings.SettingsActivity;
 import com.android.settings.core.InstrumentedPreferenceFragment;
 import com.android.settings.testutils.FakeFeatureFactory;
+import com.android.settings.testutils.shadow.ShadowUtils;
 import com.android.settingslib.applications.AppUtils;
 import com.android.settingslib.applications.ApplicationsState;
 import com.android.settingslib.applications.instantapps.InstantAppDataProvider;
@@ -85,6 +86,7 @@ import org.robolectric.util.ReflectionHelpers;
 
 import java.util.Set;
 
+@Config(shadows = {ShadowUtils.class})
 @RunWith(RobolectricTestRunner.class)
 public class AppButtonsPreferenceControllerTest {
 
@@ -168,6 +170,7 @@ public class AppButtonsPreferenceControllerTest {
     @After
     public void tearDown() {
         ShadowAppUtils.reset();
+        ShadowUtils.reset();
     }
 
     @Test
diff --git a/tests/robotests/src/com/android/settings/security/ContentProtectionTogglePreferenceControllerTest.java b/tests/robotests/src/com/android/settings/security/ContentProtectionTogglePreferenceControllerTest.java
index 075ac6c1ba1..6514a4e4043 100644
--- a/tests/robotests/src/com/android/settings/security/ContentProtectionTogglePreferenceControllerTest.java
+++ b/tests/robotests/src/com/android/settings/security/ContentProtectionTogglePreferenceControllerTest.java
@@ -24,8 +24,11 @@ import static com.google.common.truth.Truth.assertThat;
 
 import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.Mockito.never;
+import static org.mockito.Mockito.spy;
+import static org.mockito.Mockito.times;
 import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.when;
+import static org.robolectric.Shadows.shadowOf;
 
 import android.app.admin.DevicePolicyManager;
 import android.content.Context;
@@ -38,6 +41,7 @@ import androidx.preference.PreferenceScreen;
 import androidx.test.core.app.ApplicationProvider;
 
 import com.android.settings.testutils.shadow.ShadowUtils;
+import com.android.settings.testutils.shadow.ShadowUserManager;
 import com.android.settings.widget.SettingsMainSwitchPreference;
 import com.android.settingslib.RestrictedLockUtils;
 
@@ -53,7 +57,8 @@ import org.robolectric.RobolectricTestRunner;
 import org.robolectric.annotation.Config;
 
 @RunWith(RobolectricTestRunner.class)
-@Config(shadows = {ShadowUtils.class})
+@Config(shadows = {ShadowUtils.class,
+                   ShadowUserManager.class})
 public class ContentProtectionTogglePreferenceControllerTest {
 
     @Rule public final MockitoRule mMockitoRule = MockitoJUnit.rule();
@@ -62,7 +67,7 @@ public class ContentProtectionTogglePreferenceControllerTest {
 
     private final Context mContext = ApplicationProvider.getApplicationContext();
 
-    @Mock private PreferenceScreen mMockPreferenceScreen;
+   @Mock private PreferenceScreen mMockPreferenceScreen;
 
     @Mock private SettingsMainSwitchPreference mMockSwitchPreference;
 
@@ -74,9 +79,13 @@ public class ContentProtectionTogglePreferenceControllerTest {
     private TestContentProtectionTogglePreferenceController mController;
 
     private int mSettingBackupValue;
+    private ShadowUserManager mShadowUserManager;
+
 
     @Before
     public void setUp() {
+        mShadowUserManager = ShadowUserManager.getShadow();
+        mShadowUserManager.setGuestUser(false);
         mController = new TestContentProtectionTogglePreferenceController();
         SettingsMainSwitchPreference switchPreference = new SettingsMainSwitchPreference(mContext);
         when(mMockPreferenceScreen.findPreference(mController.getPreferenceKey()))
@@ -225,6 +234,7 @@ public class ContentProtectionTogglePreferenceControllerTest {
 
         assertThat(mController.mCounterGetEnforcedAdmin).isEqualTo(1);
         verify(mMockSwitchPreference, never()).setDisabledByAdmin(any());
+        verify(mMockSwitchPreference, never()).setEnabled(false);
     }
 
     @Test
@@ -237,6 +247,7 @@ public class ContentProtectionTogglePreferenceControllerTest {
 
         assertThat(mController.mCounterGetEnforcedAdmin).isEqualTo(1);
         verify(mMockSwitchPreference).setDisabledByAdmin(mEnforcedAdmin);
+        verify(mMockSwitchPreference, never()).setEnabled(false);
     }
 
     @Test
@@ -249,6 +260,7 @@ public class ContentProtectionTogglePreferenceControllerTest {
 
         assertThat(mController.mCounterGetEnforcedAdmin).isEqualTo(1);
         verify(mMockSwitchPreference, never()).setDisabledByAdmin(any());
+        verify(mMockSwitchPreference, never()).setEnabled(false);
     }
 
     @Test
@@ -261,6 +273,30 @@ public class ContentProtectionTogglePreferenceControllerTest {
 
         assertThat(mController.mCounterGetEnforcedAdmin).isEqualTo(1);
         verify(mMockSwitchPreference, never()).setDisabledByAdmin(any());
+        verify(mMockSwitchPreference, never()).setEnabled(false);
+    }
+
+    @Test
+    public void updateState_flagEnabled_noEnforcedAdmin_guestUser_switchBarDisabled() {
+        mShadowUserManager.setGuestUser(true);
+        mSetFlagsRule.enableFlags(FLAG_MANAGE_DEVICE_POLICY_ENABLED);
+        mContentProtectionPolicy = DevicePolicyManager.CONTENT_PROTECTION_ENABLED;
+        setupForUpdateState();
+
+        mController.updateState(mMockSwitchPreference);
+
+        verify(mMockSwitchPreference).setEnabled(false);
+    }
+
+    @Test
+    public void updateState_flagEnabled_noEnforcedAdmin_nonGuestUser_switchBarEnabled() {
+        mSetFlagsRule.enableFlags(FLAG_MANAGE_DEVICE_POLICY_ENABLED);
+        mContentProtectionPolicy = DevicePolicyManager.CONTENT_PROTECTION_ENABLED;
+        setupForUpdateState();
+
+        mController.updateState(mMockSwitchPreference);
+
+        verify(mMockSwitchPreference, never()).setEnabled(false);
     }
 
     @Test
@@ -273,6 +309,7 @@ public class ContentProtectionTogglePreferenceControllerTest {
 
         assertThat(mController.mCounterGetEnforcedAdmin).isEqualTo(1);
         verify(mMockSwitchPreference, never()).setDisabledByAdmin(any());
+        verify(mMockSwitchPreference, never()).setEnabled(false);
     }
 
     @Test
@@ -286,6 +323,7 @@ public class ContentProtectionTogglePreferenceControllerTest {
 
         assertThat(mController.mCounterGetEnforcedAdmin).isEqualTo(1);
         verify(mMockSwitchPreference).setDisabledByAdmin(mEnforcedAdmin);
+        verify(mMockSwitchPreference, never()).setEnabled(false);
     }
 
     @Test
@@ -299,6 +337,7 @@ public class ContentProtectionTogglePreferenceControllerTest {
 
         assertThat(mController.mCounterGetEnforcedAdmin).isEqualTo(1);
         verify(mMockSwitchPreference).setDisabledByAdmin(mEnforcedAdmin);
+        verify(mMockSwitchPreference, never()).setEnabled(false);
     }
 
     @Test
@@ -312,6 +351,7 @@ public class ContentProtectionTogglePreferenceControllerTest {
 
         assertThat(mController.mCounterGetEnforcedAdmin).isEqualTo(1);
         verify(mMockSwitchPreference, never()).setDisabledByAdmin(any());
+        verify(mMockSwitchPreference, never()).setEnabled(false);
     }
 
     @Test
diff --git a/tests/robotests/testutils/com/android/settings/testutils/shadow/ShadowUtils.java b/tests/robotests/testutils/com/android/settings/testutils/shadow/ShadowUtils.java
index ed03bcc8413..7d115f81aca 100644
--- a/tests/robotests/testutils/com/android/settings/testutils/shadow/ShadowUtils.java
+++ b/tests/robotests/testutils/com/android/settings/testutils/shadow/ShadowUtils.java
@@ -51,6 +51,7 @@ public class ShadowUtils {
     private static boolean sIsBatteryPresent;
     private static boolean sIsMultipleBiometricsSupported;
     private static boolean sIsPrivateProfile;
+    private static boolean sIsProtectedPackage;
 
     @Implementation
     protected static int enforceSameOwner(Context context, int userId) {
@@ -84,6 +85,7 @@ public class ShadowUtils {
         sIsBatteryPresent = true;
         sIsMultipleBiometricsSupported = false;
         sIsPrivateProfile = false;
+        sIsProtectedPackage = false;
     }
 
     public static void setIsDemoUser(boolean isDemoUser) {
@@ -199,4 +201,13 @@ public class ShadowUtils {
     public static void setIsPrivateProfile(boolean isPrivateProfile) {
         sIsPrivateProfile = isPrivateProfile;
     }
+
+    @Implementation
+    protected static boolean isProtectedPackage(Context context, String packageName) {
+        return sIsProtectedPackage;
+    }
+
+    public static void setIsProtectedPackage(boolean isProtectedPackage) {
+        sIsProtectedPackage = isProtectedPackage;
+    }
 }
diff --git a/tests/spa_unit/src/com/android/settings/spa/SpaAppBridgeActivityTest.kt b/tests/spa_unit/src/com/android/settings/spa/SpaAppBridgeActivityTest.kt
index be2b5e0bb35..134cdb487c2 100644
--- a/tests/spa_unit/src/com/android/settings/spa/SpaAppBridgeActivityTest.kt
+++ b/tests/spa_unit/src/com/android/settings/spa/SpaAppBridgeActivityTest.kt
@@ -37,6 +37,16 @@ class SpaAppBridgeActivityTest {
 
         assertThat(destination).isEqualTo("$DESTINATION/$PACKAGE_NAME/${UserHandle.myUserId()}")
     }
+    @Test
+    fun getDestinationForApp_hasMalformedPackageName() {
+        val intent = Intent().apply {
+            data = Uri.parse("package:package.name/10#")
+        }
+
+        val destination = getDestinationForApp(DESTINATION, intent)
+
+        assertThat(destination).isNull()
+    }
 
     @Test
     fun getDestinationForApp_noPackageName() {
diff --git a/tests/spa_unit/src/com/android/settings/spa/app/appinfo/PackageInfoPresenterTest.kt b/tests/spa_unit/src/com/android/settings/spa/app/appinfo/PackageInfoPresenterTest.kt
index 5dd66e8fff5..f35359fe66c 100644
--- a/tests/spa_unit/src/com/android/settings/spa/app/appinfo/PackageInfoPresenterTest.kt
+++ b/tests/spa_unit/src/com/android/settings/spa/app/appinfo/PackageInfoPresenterTest.kt
@@ -17,6 +17,7 @@
 package com.android.settings.spa.app.appinfo
 
 import android.app.ActivityManager
+import android.app.KeyguardManager
 import android.app.settings.SettingsEnums
 import android.content.Context
 import android.content.Intent
@@ -25,6 +26,8 @@ import android.content.pm.PackageManager
 import android.net.Uri
 import androidx.test.core.app.ApplicationProvider
 import androidx.test.ext.junit.runners.AndroidJUnit4
+import com.android.dx.mockito.inline.extended.ExtendedMockito
+import com.android.settings.Utils
 import com.android.settings.testutils.FakeFeatureFactory
 import com.android.settings.testutils.mockAsUser
 import com.android.settingslib.spaprivileged.framework.common.activityManager
@@ -33,8 +36,11 @@ import com.google.common.truth.Truth.assertThat
 import kotlinx.coroutines.delay
 import kotlinx.coroutines.runBlocking
 import kotlinx.coroutines.test.TestScope
+import org.junit.After
+import org.junit.Before
 import org.junit.Test
 import org.junit.runner.RunWith
+import org.mockito.MockitoSession
 import org.mockito.kotlin.any
 import org.mockito.kotlin.argumentCaptor
 import org.mockito.kotlin.doNothing
@@ -43,6 +49,7 @@ import org.mockito.kotlin.mock
 import org.mockito.kotlin.spy
 import org.mockito.kotlin.verify
 import org.mockito.kotlin.whenever
+import org.mockito.quality.Strictness
 
 @RunWith(AndroidJUnit4::class)
 class PackageInfoPresenterTest {
@@ -51,9 +58,14 @@ class PackageInfoPresenterTest {
 
     private val mockActivityManager = mock<ActivityManager>()
 
+    private val mockKeyguardManager = mock<KeyguardManager>()
+
+    private lateinit var mockSession: MockitoSession
+
     private val context: Context = spy(ApplicationProvider.getApplicationContext()) {
         on { packageManager } doReturn mockPackageManager
         on { activityManager } doReturn mockActivityManager
+        on { getSystemService(Context.KEYGUARD_SERVICE) } doReturn mockKeyguardManager
         doNothing().whenever(mock).startActivityAsUser(any(), any())
         mock.mockAsUser()
     }
@@ -66,6 +78,24 @@ class PackageInfoPresenterTest {
     private val packageInfoPresenter =
         PackageInfoPresenter(context, PACKAGE_NAME, USER_ID, TestScope(), packageManagers)
 
+    private var isUserAuthenticated: Boolean = false
+
+    @Before
+    fun setUp() {
+        mockSession = ExtendedMockito.mockitoSession()
+            .initMocks(this)
+            .mockStatic(Utils::class.java)
+            .strictness(Strictness.LENIENT)
+            .startMocking()
+        whenever(Utils.isProtectedPackage(context, PACKAGE_NAME)).thenReturn(false)
+    }
+
+    @After
+    fun tearDown() {
+        mockSession.finishMocking()
+        isUserAuthenticated = false
+    }
+
     @Test
     fun isInterestedAppChange_packageChanged_isInterested() {
         val intent = Intent(Intent.ACTION_PACKAGE_CHANGED).apply {
@@ -129,25 +159,37 @@ class PackageInfoPresenterTest {
         packageInfoPresenter.disable()
         delay(100)
 
-        verifyAction(SettingsEnums.ACTION_SETTINGS_DISABLE_APP)
-        verify(mockPackageManager).setApplicationEnabledSetting(
-            PACKAGE_NAME, PackageManager.COMPONENT_ENABLED_STATE_DISABLED_USER, 0
-        )
+        verifyDisablePackage()
+    }
+
+    @Test
+    fun disable_protectedPackage() = runBlocking {
+        mockProtectedPackage()
+        setAuthPassesAutomatically()
+
+        packageInfoPresenter.disable()
+        delay(100)
+
+        verifyUserAuthenticated()
+        verifyDisablePackage()
     }
 
     @Test
     fun startUninstallActivity() = runBlocking {
         packageInfoPresenter.startUninstallActivity()
 
-        verifyAction(SettingsEnums.ACTION_SETTINGS_UNINSTALL_APP)
-        val intent = argumentCaptor<Intent> {
-            verify(context).startActivityAsUser(capture(), any())
-        }.firstValue
-        with(intent) {
-            assertThat(action).isEqualTo(Intent.ACTION_UNINSTALL_PACKAGE)
-            assertThat(data?.schemeSpecificPart).isEqualTo(PACKAGE_NAME)
-            assertThat(getBooleanExtra(Intent.EXTRA_UNINSTALL_ALL_USERS, true)).isEqualTo(false)
-        }
+        verifyUninstallPackage()
+    }
+
+    @Test
+    fun startUninstallActivity_protectedPackage() = runBlocking {
+        mockProtectedPackage()
+        setAuthPassesAutomatically()
+
+        packageInfoPresenter.startUninstallActivity()
+
+        verifyUserAuthenticated()
+        verifyUninstallPackage()
     }
 
     @Test
@@ -164,8 +206,19 @@ class PackageInfoPresenterTest {
         packageInfoPresenter.forceStop()
         delay(100)
 
-        verifyAction(SettingsEnums.ACTION_APP_FORCE_STOP)
-        verify(mockActivityManager).forceStopPackageAsUser(PACKAGE_NAME, USER_ID)
+        verifyForceStop()
+    }
+
+    @Test
+    fun forceStop_protectedPackage() = runBlocking {
+        mockProtectedPackage()
+        setAuthPassesAutomatically()
+
+        packageInfoPresenter.forceStop()
+        delay(100)
+
+        verifyUserAuthenticated()
+        verifyForceStop()
     }
 
     @Test
@@ -179,6 +232,48 @@ class PackageInfoPresenterTest {
         verify(metricsFeatureProvider).action(context, category, PACKAGE_NAME)
     }
 
+    private fun verifyDisablePackage() {
+        verifyAction(SettingsEnums.ACTION_SETTINGS_DISABLE_APP)
+        verify(mockPackageManager).setApplicationEnabledSetting(
+            PACKAGE_NAME, PackageManager.COMPONENT_ENABLED_STATE_DISABLED_USER, 0
+        )
+    }
+
+    private fun verifyUninstallPackage() {
+        verifyAction(SettingsEnums.ACTION_SETTINGS_UNINSTALL_APP)
+
+        val intent = argumentCaptor<Intent> {
+            verify(context).startActivityAsUser(capture(), any())
+        }.firstValue
+        with(intent) {
+            assertThat(action).isEqualTo(Intent.ACTION_UNINSTALL_PACKAGE)
+            assertThat(data?.schemeSpecificPart).isEqualTo(PACKAGE_NAME)
+            assertThat(getBooleanExtra(Intent.EXTRA_UNINSTALL_ALL_USERS, true)).isEqualTo(false)
+        }
+    }
+
+    private fun verifyForceStop() {
+        verifyAction(SettingsEnums.ACTION_APP_FORCE_STOP)
+        verify(mockActivityManager).forceStopPackageAsUser(PACKAGE_NAME, USER_ID)
+    }
+
+    private fun setAuthPassesAutomatically() {
+        whenever(mockKeyguardManager.isKeyguardSecure).thenReturn(mockUserAuthentication())
+    }
+
+    private fun mockUserAuthentication() : Boolean {
+        isUserAuthenticated = true
+        return false
+    }
+
+    private fun mockProtectedPackage() {
+        whenever(Utils.isProtectedPackage(context, PACKAGE_NAME)).thenReturn(true)
+    }
+
+    private fun verifyUserAuthenticated() {
+        assertThat(isUserAuthenticated).isTrue()
+    }
+
     private companion object {
         const val PACKAGE_NAME = "package.name"
         const val USER_ID = 0
```

