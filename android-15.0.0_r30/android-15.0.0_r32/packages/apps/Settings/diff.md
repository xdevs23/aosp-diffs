```diff
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
```

