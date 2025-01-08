```diff
diff --git a/packages/SettingsLib/src/com/android/settingslib/applications/ServiceListing.java b/packages/SettingsLib/src/com/android/settingslib/applications/ServiceListing.java
index c8bcabff1094..261c722e517c 100644
--- a/packages/SettingsLib/src/com/android/settingslib/applications/ServiceListing.java
+++ b/packages/SettingsLib/src/com/android/settingslib/applications/ServiceListing.java
@@ -138,23 +138,37 @@ public class ServiceListing {
         }
 
         final PackageManager pmWrapper = mContext.getPackageManager();
+        // Add requesting apps, with full validation
         List<ResolveInfo> installedServices = pmWrapper.queryIntentServicesAsUser(
                 new Intent(mIntentAction), flags, user);
         for (ResolveInfo resolveInfo : installedServices) {
             ServiceInfo info = resolveInfo.serviceInfo;
 
-            if (!mPermission.equals(info.permission)) {
-                Slog.w(mTag, "Skipping " + mNoun + " service "
-                        + info.packageName + "/" + info.name
-                        + ": it does not require the permission "
-                        + mPermission);
-                continue;
+            if (!mEnabledServices.contains(info.getComponentName())) {
+                if (!mPermission.equals(info.permission)) {
+                    Slog.w(mTag, "Skipping " + mNoun + " service "
+                            + info.packageName + "/" + info.name
+                            + ": it does not require the permission "
+                            + mPermission);
+                    continue;
+                }
+                if (mValidator != null && !mValidator.test(info)) {
+                    continue;
+                }
+                mServices.add(info);
             }
-            if (mValidator != null && !mValidator.test(info)) {
-                continue;
+        }
+
+        // Add all apps with access, in case prior approval was granted without full validation
+        for (ComponentName cn : mEnabledServices) {
+            List<ResolveInfo> enabledServices = pmWrapper.queryIntentServicesAsUser(
+                    new Intent().setComponent(cn), flags, user);
+            for (ResolveInfo resolveInfo : enabledServices) {
+                ServiceInfo info = resolveInfo.serviceInfo;
+                mServices.add(info);
             }
-            mServices.add(info);
         }
+
         for (Callback callback : mCallbacks) {
             callback.onServicesReloaded(mServices);
         }
diff --git a/packages/SettingsLib/tests/robotests/src/com/android/settingslib/applications/ServiceListingTest.java b/packages/SettingsLib/tests/robotests/src/com/android/settingslib/applications/ServiceListingTest.java
index 7ff0988c494d..feef559dfe26 100644
--- a/packages/SettingsLib/tests/robotests/src/com/android/settingslib/applications/ServiceListingTest.java
+++ b/packages/SettingsLib/tests/robotests/src/com/android/settingslib/applications/ServiceListingTest.java
@@ -21,6 +21,7 @@ import static com.google.common.truth.Truth.assertThat;
 import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.ArgumentMatchers.anyList;
+import static org.mockito.ArgumentMatchers.argThat;
 import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.spy;
 import static org.mockito.Mockito.times;
@@ -29,6 +30,7 @@ import static org.mockito.Mockito.when;
 
 import android.content.ComponentName;
 import android.content.Context;
+import android.content.Intent;
 import android.content.pm.PackageManager;
 import android.content.pm.ResolveInfo;
 import android.content.pm.ServiceInfo;
@@ -42,6 +44,7 @@ import org.junit.Before;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.mockito.ArgumentCaptor;
+import org.mockito.ArgumentMatcher;
 import org.robolectric.RobolectricTestRunner;
 import org.robolectric.RuntimeEnvironment;
 
@@ -72,19 +75,26 @@ public class ServiceListingTest {
                 .build();
     }
 
+    private ArgumentMatcher<Intent> filterEquals(Intent intent) {
+        return (test) -> {
+            return intent.filterEquals(test);
+        };
+    }
+
     @Test
     public void testValidator() {
         ServiceInfo s1 = new ServiceInfo();
         s1.permission = "testPermission";
         s1.packageName = "pkg";
+        s1.name = "Service1";
         ServiceInfo s2 = new ServiceInfo();
         s2.permission = "testPermission";
         s2.packageName = "pkg2";
+        s2.name = "service2";
         ResolveInfo r1 = new ResolveInfo();
         r1.serviceInfo = s1;
         ResolveInfo r2 = new ResolveInfo();
         r2.serviceInfo = s2;
-
         when(mPm.queryIntentServicesAsUser(any(), anyInt(), anyInt())).thenReturn(
                 ImmutableList.of(r1, r2));
 
@@ -118,9 +128,11 @@ public class ServiceListingTest {
         ServiceInfo s1 = new ServiceInfo();
         s1.permission = "testPermission";
         s1.packageName = "pkg";
+        s1.name = "Service1";
         ServiceInfo s2 = new ServiceInfo();
         s2.permission = "testPermission";
         s2.packageName = "pkg2";
+        s2.name = "service2";
         ResolveInfo r1 = new ResolveInfo();
         r1.serviceInfo = s1;
         ResolveInfo r2 = new ResolveInfo();
@@ -193,4 +205,56 @@ public class ServiceListingTest {
         assertThat(Settings.Secure.getString(RuntimeEnvironment.application.getContentResolver(),
                 TEST_SETTING)).contains(testComponent2.flattenToString());
     }
+
+    @Test
+    public void testHasPermissionWithoutMeetingCurrentRegs() {
+        ServiceInfo s1 = new ServiceInfo();
+        s1.permission = "testPermission";
+        s1.packageName = "pkg";
+        s1.name = "Service1";
+        ServiceInfo s2 = new ServiceInfo();
+        s2.permission = "testPermission";
+        s2.packageName = "pkg2";
+        s2.name = "service2";
+        ResolveInfo r1 = new ResolveInfo();
+        r1.serviceInfo = s1;
+        ResolveInfo r2 = new ResolveInfo();
+        r2.serviceInfo = s2;
+
+        ComponentName approvedComponent = new ComponentName(s2.packageName, s2.name);
+
+        Settings.Secure.putString(
+                mContext.getContentResolver(), TEST_SETTING, approvedComponent.flattenToString());
+
+        when(mPm.queryIntentServicesAsUser(argThat(
+                filterEquals(new Intent(TEST_INTENT))), anyInt(), anyInt()))
+                .thenReturn(ImmutableList.of(r1));
+        when(mPm.queryIntentServicesAsUser(argThat(
+                filterEquals(new Intent().setComponent(approvedComponent))),
+                anyInt(), anyInt()))
+                .thenReturn(ImmutableList.of(r2));
+
+        mServiceListing = new ServiceListing.Builder(mContext)
+                .setTag("testTag")
+                .setSetting(TEST_SETTING)
+                .setNoun("testNoun")
+                .setIntentAction(TEST_INTENT)
+                .setValidator(info -> {
+                    if (info.packageName.equals("pkg")) {
+                        return true;
+                    }
+                    return false;
+                })
+                .setPermission("testPermission")
+                .build();
+        ServiceListing.Callback callback = mock(ServiceListing.Callback.class);
+        mServiceListing.addCallback(callback);
+        mServiceListing.reload();
+
+        verify(mPm, times(2)).queryIntentServicesAsUser(any(), anyInt(), anyInt());
+        ArgumentCaptor<List<ServiceInfo>> captor = ArgumentCaptor.forClass(List.class);
+        verify(callback, times(1)).onServicesReloaded(captor.capture());
+
+        assertThat(captor.getValue()).containsExactlyElementsIn(ImmutableList.of(s2, s1));
+    }
 }
diff --git a/packages/SystemUI/multivalentTests/src/com/android/systemui/deviceentry/domain/interactor/OccludingAppDeviceEntryInteractorTest.kt b/packages/SystemUI/multivalentTests/src/com/android/systemui/deviceentry/domain/interactor/OccludingAppDeviceEntryInteractorTest.kt
index 77337d36a6b1..a981e2083312 100644
--- a/packages/SystemUI/multivalentTests/src/com/android/systemui/deviceentry/domain/interactor/OccludingAppDeviceEntryInteractorTest.kt
+++ b/packages/SystemUI/multivalentTests/src/com/android/systemui/deviceentry/domain/interactor/OccludingAppDeviceEntryInteractorTest.kt
@@ -18,6 +18,7 @@ package com.android.systemui.deviceentry.domain.interactor
 
 import android.content.Intent
 import android.content.mockedContext
+import android.content.res.Resources
 import android.hardware.fingerprint.FingerprintManager
 import androidx.test.ext.junit.runners.AndroidJUnit4
 import androidx.test.filters.SmallTest
@@ -41,13 +42,16 @@ import com.android.systemui.kosmos.testScope
 import com.android.systemui.plugins.ActivityStarter.OnDismissAction
 import com.android.systemui.plugins.activityStarter
 import com.android.systemui.power.data.repository.fakePowerRepository
+import com.android.systemui.res.R
 import com.android.systemui.testKosmos
 import com.android.systemui.util.mockito.any
+import com.android.systemui.util.mockito.whenever
 import com.google.common.truth.Truth.assertThat
 import kotlinx.coroutines.ExperimentalCoroutinesApi
 import kotlinx.coroutines.flow.flowOf
 import kotlinx.coroutines.test.runCurrent
 import kotlinx.coroutines.test.runTest
+import org.junit.Before
 import org.junit.Test
 import org.junit.runner.RunWith
 import org.mockito.ArgumentCaptor
@@ -55,6 +59,7 @@ import org.mockito.ArgumentMatchers.eq
 import org.mockito.ArgumentMatchers.isNull
 import org.mockito.Mockito.never
 import org.mockito.Mockito.verify
+import org.mockito.kotlin.mock
 
 @OptIn(ExperimentalCoroutinesApi::class)
 @SmallTest
@@ -63,8 +68,8 @@ class OccludingAppDeviceEntryInteractorTest : SysuiTestCase() {
 
     private val kosmos = testKosmos()
     private val testScope = kosmos.testScope
-    private val underTest = kosmos.occludingAppDeviceEntryInteractor
-
+    private lateinit var underTest: OccludingAppDeviceEntryInteractor
+    private lateinit var mockedResources: Resources
     private val fingerprintAuthRepository = kosmos.deviceEntryFingerprintAuthRepository
     private val keyguardRepository = kosmos.fakeKeyguardRepository
     private val bouncerRepository = kosmos.keyguardBouncerRepository
@@ -74,9 +79,18 @@ class OccludingAppDeviceEntryInteractorTest : SysuiTestCase() {
     private val mockedContext = kosmos.mockedContext
     private val mockedActivityStarter = kosmos.activityStarter
 
+    @Before
+    fun setup() {
+        mockedResources = mock<Resources>()
+        whenever(mockedContext.resources).thenReturn(mockedResources)
+        whenever(mockedResources.getBoolean(R.bool.config_goToHomeFromOccludedApps))
+            .thenReturn(true)
+    }
+
     @Test
     fun fingerprintSuccess_goToHomeScreen() =
         testScope.runTest {
+            underTest = kosmos.occludingAppDeviceEntryInteractor
             givenOnOccludingApp(true)
             fingerprintAuthRepository.setAuthenticationStatus(
                 SuccessFingerprintAuthenticationStatus(0, true)
@@ -85,9 +99,24 @@ class OccludingAppDeviceEntryInteractorTest : SysuiTestCase() {
             verifyGoToHomeScreen()
         }
 
+    @Test
+    fun fingerprintSuccess_configOff_doesNotGoToHomeScreen() =
+        testScope.runTest {
+            whenever(mockedResources.getBoolean(R.bool.config_goToHomeFromOccludedApps))
+                .thenReturn(false)
+            underTest = kosmos.occludingAppDeviceEntryInteractor
+            givenOnOccludingApp(true)
+            fingerprintAuthRepository.setAuthenticationStatus(
+                SuccessFingerprintAuthenticationStatus(0, true)
+            )
+            runCurrent()
+            verifyNeverGoToHomeScreen()
+        }
+
     @Test
     fun fingerprintSuccess_notInteractive_doesNotGoToHomeScreen() =
         testScope.runTest {
+            underTest = kosmos.occludingAppDeviceEntryInteractor
             givenOnOccludingApp(true)
             powerRepository.setInteractive(false)
             fingerprintAuthRepository.setAuthenticationStatus(
@@ -100,6 +129,7 @@ class OccludingAppDeviceEntryInteractorTest : SysuiTestCase() {
     @Test
     fun fingerprintSuccess_dreaming_doesNotGoToHomeScreen() =
         testScope.runTest {
+            underTest = kosmos.occludingAppDeviceEntryInteractor
             givenOnOccludingApp(true)
             keyguardRepository.setDreaming(true)
             fingerprintAuthRepository.setAuthenticationStatus(
@@ -112,6 +142,7 @@ class OccludingAppDeviceEntryInteractorTest : SysuiTestCase() {
     @Test
     fun fingerprintSuccess_notOnOccludingApp_doesNotGoToHomeScreen() =
         testScope.runTest {
+            underTest = kosmos.occludingAppDeviceEntryInteractor
             givenOnOccludingApp(false)
             fingerprintAuthRepository.setAuthenticationStatus(
                 SuccessFingerprintAuthenticationStatus(0, true)
@@ -123,11 +154,12 @@ class OccludingAppDeviceEntryInteractorTest : SysuiTestCase() {
     @Test
     fun lockout_goToHomeScreenOnDismissAction() =
         testScope.runTest {
+            underTest = kosmos.occludingAppDeviceEntryInteractor
             givenOnOccludingApp(true)
             fingerprintAuthRepository.setAuthenticationStatus(
                 ErrorFingerprintAuthenticationStatus(
                     FingerprintManager.FINGERPRINT_ERROR_LOCKOUT,
-                    "lockoutTest"
+                    "lockoutTest",
                 )
             )
             runCurrent()
@@ -137,11 +169,12 @@ class OccludingAppDeviceEntryInteractorTest : SysuiTestCase() {
     @Test
     fun lockout_notOnOccludingApp_neverGoToHomeScreen() =
         testScope.runTest {
+            underTest = kosmos.occludingAppDeviceEntryInteractor
             givenOnOccludingApp(false)
             fingerprintAuthRepository.setAuthenticationStatus(
                 ErrorFingerprintAuthenticationStatus(
                     FingerprintManager.FINGERPRINT_ERROR_LOCKOUT,
-                    "lockoutTest"
+                    "lockoutTest",
                 )
             )
             runCurrent()
@@ -151,11 +184,12 @@ class OccludingAppDeviceEntryInteractorTest : SysuiTestCase() {
     @Test
     fun lockout_onOccludingApp_onCommunal_neverGoToHomeScreen() =
         testScope.runTest {
+            underTest = kosmos.occludingAppDeviceEntryInteractor
             givenOnOccludingApp(isOnOccludingApp = true, isOnCommunal = true)
             fingerprintAuthRepository.setAuthenticationStatus(
                 ErrorFingerprintAuthenticationStatus(
                     FingerprintManager.FINGERPRINT_ERROR_LOCKOUT,
-                    "lockoutTest"
+                    "lockoutTest",
                 )
             )
             runCurrent()
@@ -165,6 +199,7 @@ class OccludingAppDeviceEntryInteractorTest : SysuiTestCase() {
     @Test
     fun message_fpFailOnOccludingApp_thenNotOnOccludingApp() =
         testScope.runTest {
+            underTest = kosmos.occludingAppDeviceEntryInteractor
             val message by collectLastValue(underTest.message)
 
             givenOnOccludingApp(true)
@@ -186,6 +221,7 @@ class OccludingAppDeviceEntryInteractorTest : SysuiTestCase() {
     @Test
     fun message_fpErrorHelpFailOnOccludingApp() =
         testScope.runTest {
+            underTest = kosmos.occludingAppDeviceEntryInteractor
             val message by collectLastValue(underTest.message)
 
             givenOnOccludingApp(true)
@@ -218,6 +254,7 @@ class OccludingAppDeviceEntryInteractorTest : SysuiTestCase() {
     @Test
     fun message_fpError_lockoutFilteredOut() =
         testScope.runTest {
+            underTest = kosmos.occludingAppDeviceEntryInteractor
             val message by collectLastValue(underTest.message)
 
             givenOnOccludingApp(true)
@@ -246,6 +283,7 @@ class OccludingAppDeviceEntryInteractorTest : SysuiTestCase() {
     @Test
     fun noMessage_fpErrorsWhileDozing() =
         testScope.runTest {
+            underTest = kosmos.occludingAppDeviceEntryInteractor
             val message by collectLastValue(underTest.message)
 
             givenOnOccludingApp(true)
@@ -254,7 +292,7 @@ class OccludingAppDeviceEntryInteractorTest : SysuiTestCase() {
             kosmos.fakeKeyguardTransitionRepository.sendTransitionSteps(
                 from = KeyguardState.OCCLUDED,
                 to = KeyguardState.DOZING,
-                testScope
+                testScope,
             )
             runCurrent()
 
@@ -283,7 +321,7 @@ class OccludingAppDeviceEntryInteractorTest : SysuiTestCase() {
 
     private suspend fun givenOnOccludingApp(
         isOnOccludingApp: Boolean,
-        isOnCommunal: Boolean = false
+        isOnCommunal: Boolean = false,
     ) {
         powerRepository.setInteractive(true)
         keyguardRepository.setIsDozing(false)
@@ -305,13 +343,13 @@ class OccludingAppDeviceEntryInteractorTest : SysuiTestCase() {
             kosmos.fakeKeyguardTransitionRepository.sendTransitionSteps(
                 from = KeyguardState.LOCKSCREEN,
                 to = KeyguardState.OCCLUDED,
-                testScope
+                testScope,
             )
         } else {
             kosmos.fakeKeyguardTransitionRepository.sendTransitionSteps(
                 from = KeyguardState.OCCLUDED,
                 to = KeyguardState.LOCKSCREEN,
-                testScope
+                testScope,
             )
         }
     }
diff --git a/packages/SystemUI/res/values/config.xml b/packages/SystemUI/res/values/config.xml
index 38ef0e9d5df4..78b2aef5b3b7 100644
--- a/packages/SystemUI/res/values/config.xml
+++ b/packages/SystemUI/res/values/config.xml
@@ -324,6 +324,9 @@
     <!-- Whether to show the full screen user switcher. -->
     <bool name="config_enableFullscreenUserSwitcher">false</bool>
 
+    <!-- Whether to go to the launcher when unlocking via an occluding app -->
+    <bool name="config_goToHomeFromOccludedApps">false</bool>
+
     <!-- Determines whether the shell features all run on another thread. -->
     <bool name="config_enableShellMainThread">true</bool>
 
diff --git a/packages/SystemUI/src/com/android/systemui/deviceentry/domain/interactor/OccludingAppDeviceEntryInteractor.kt b/packages/SystemUI/src/com/android/systemui/deviceentry/domain/interactor/OccludingAppDeviceEntryInteractor.kt
index f90f02aad892..9f4b1ccca9db 100644
--- a/packages/SystemUI/src/com/android/systemui/deviceentry/domain/interactor/OccludingAppDeviceEntryInteractor.kt
+++ b/packages/SystemUI/src/com/android/systemui/deviceentry/domain/interactor/OccludingAppDeviceEntryInteractor.kt
@@ -34,6 +34,7 @@ import com.android.systemui.keyguard.shared.model.KeyguardState
 import com.android.systemui.keyguard.shared.model.SuccessFingerprintAuthenticationStatus
 import com.android.systemui.plugins.ActivityStarter
 import com.android.systemui.power.domain.interactor.PowerInteractor
+import com.android.systemui.res.R
 import com.android.systemui.util.kotlin.combine
 import com.android.systemui.util.kotlin.sample
 import javax.inject.Inject
@@ -123,19 +124,28 @@ constructor(
             .ifKeyguardOccludedByApp(/* elseFlow */ flowOf(null))
 
     init {
-        scope.launch {
-            // On fingerprint success when the screen is on and not dreaming, go to the home screen
-            fingerprintUnlockSuccessEvents
-                .sample(
-                    combine(powerInteractor.isInteractive, keyguardInteractor.isDreaming, ::Pair)
-                )
-                .collect { (interactive, dreaming) ->
-                    if (interactive && !dreaming) {
-                        goToHomeScreen()
+        // This seems undesirable in most cases, except when a video is playing and can PiP when
+        // unlocked. It was originally added for tablets, so allow it there
+        if (context.resources.getBoolean(R.bool.config_goToHomeFromOccludedApps)) {
+            scope.launch {
+                // On fingerprint success when the screen is on and not dreaming, go to the home
+                // screen
+                fingerprintUnlockSuccessEvents
+                    .sample(
+                        combine(
+                            powerInteractor.isInteractive,
+                            keyguardInteractor.isDreaming,
+                            ::Pair,
+                        )
+                    )
+                    .collect { (interactive, dreaming) ->
+                        if (interactive && !dreaming) {
+                            goToHomeScreen()
+                        }
+                        // don't go to the home screen if the authentication is from
+                        // AOD/dozing/off/dreaming
                     }
-                    // don't go to the home screen if the authentication is from
-                    // AOD/dozing/off/dreaming
-                }
+            }
         }
 
         scope.launch {
diff --git a/services/companion/java/com/android/server/companion/CompanionDeviceManagerService.java b/services/companion/java/com/android/server/companion/CompanionDeviceManagerService.java
index 42f69e9ae02f..c73e457c565d 100644
--- a/services/companion/java/com/android/server/companion/CompanionDeviceManagerService.java
+++ b/services/companion/java/com/android/server/companion/CompanionDeviceManagerService.java
@@ -628,16 +628,25 @@ public class CompanionDeviceManagerService extends SystemService {
 
         @Override
         public void enablePermissionsSync(int associationId) {
+            if (getCallingUid() != SYSTEM_UID) {
+                throw new SecurityException("Caller must be system UID");
+            }
             mSystemDataTransferProcessor.enablePermissionsSync(associationId);
         }
 
         @Override
         public void disablePermissionsSync(int associationId) {
+            if (getCallingUid() != SYSTEM_UID) {
+                throw new SecurityException("Caller must be system UID");
+            }
             mSystemDataTransferProcessor.disablePermissionsSync(associationId);
         }
 
         @Override
         public PermissionSyncRequest getPermissionSyncRequest(int associationId) {
+            if (getCallingUid() != SYSTEM_UID) {
+                throw new SecurityException("Caller must be system UID");
+            }
             return mSystemDataTransferProcessor.getPermissionSyncRequest(associationId);
         }
 
diff --git a/services/core/java/com/android/server/accounts/AccountManagerService.java b/services/core/java/com/android/server/accounts/AccountManagerService.java
index 3499a3a5edde..0ca3b56486e3 100644
--- a/services/core/java/com/android/server/accounts/AccountManagerService.java
+++ b/services/core/java/com/android/server/accounts/AccountManagerService.java
@@ -5062,6 +5062,8 @@ public class AccountManagerService
                     Log.e(TAG, String.format(tmpl, activityName, pkgName, mAccountType));
                     return false;
                 }
+                intent.setComponent(targetActivityInfo.getComponentName());
+                bundle.putParcelable(AccountManager.KEY_INTENT, intent);
                 return true;
             } finally {
                 Binder.restoreCallingIdentity(bid);
@@ -5083,14 +5085,15 @@ public class AccountManagerService
             Bundle simulateBundle = p.readBundle();
             p.recycle();
             Intent intent = bundle.getParcelable(AccountManager.KEY_INTENT, Intent.class);
-            if (intent != null && intent.getClass() != Intent.class) {
-                return false;
-            }
             Intent simulateIntent = simulateBundle.getParcelable(AccountManager.KEY_INTENT,
                     Intent.class);
             if (intent == null) {
                 return (simulateIntent == null);
             }
+            if (intent.getClass() != Intent.class || simulateIntent.getClass() != Intent.class) {
+                return false;
+            }
+
             if (!intent.filterEquals(simulateIntent)) {
                 return false;
             }
diff --git a/services/core/java/com/android/server/audio/AudioDeviceBroker.java b/services/core/java/com/android/server/audio/AudioDeviceBroker.java
index 0fd22c583192..cdfb7402e1be 100644
--- a/services/core/java/com/android/server/audio/AudioDeviceBroker.java
+++ b/services/core/java/com/android/server/audio/AudioDeviceBroker.java
@@ -679,6 +679,8 @@ public class AudioDeviceBroker {
                 elapsed = System.currentTimeMillis() - start;
                 if (elapsed >= SET_COMMUNICATION_DEVICE_TIMEOUT_MS) {
                     Log.e(TAG, "Timeout waiting for communication device update.");
+                    // reset counter to avoid sticky out of sync condition
+                    mCommunicationDeviceUpdateCount = 0;
                     break;
                 }
             }
@@ -1321,9 +1323,9 @@ public class AudioDeviceBroker {
         sendLMsgNoDelay(MSG_II_SET_LE_AUDIO_OUT_VOLUME, SENDMSG_REPLACE, info);
     }
 
-    /*package*/ void postSetModeOwner(int mode, int pid, int uid) {
-        sendLMsgNoDelay(MSG_I_SET_MODE_OWNER, SENDMSG_REPLACE,
-                new AudioModeInfo(mode, pid, uid));
+    /*package*/ void postSetModeOwner(int mode, int pid, int uid, boolean signal) {
+        sendLMsgNoDelay(signal ? MSG_L_SET_MODE_OWNER_SIGNAL : MSG_L_SET_MODE_OWNER,
+                SENDMSG_REPLACE, new AudioModeInfo(mode, pid, uid));
     }
 
     /*package*/ void postBluetoothDeviceConfigChange(@NonNull BtDeviceInfo info) {
@@ -2025,7 +2027,8 @@ public class AudioDeviceBroker {
                         mBtHelper.setAvrcpAbsoluteVolumeIndex(msg.arg1);
                     }
                     break;
-                case MSG_I_SET_MODE_OWNER:
+                case MSG_L_SET_MODE_OWNER:
+                case MSG_L_SET_MODE_OWNER_SIGNAL:
                     synchronized (mSetModeLock) {
                         synchronized (mDeviceStateLock) {
                             int btScoRequesterUid = bluetoothScoRequestOwnerUid();
@@ -2036,6 +2039,9 @@ public class AudioDeviceBroker {
                             }
                         }
                     }
+                    if (msg.what == MSG_L_SET_MODE_OWNER_SIGNAL) {
+                        mAudioService.decrementAudioModeResetCount();
+                    }
                     break;
 
                 case MSG_L_SET_COMMUNICATION_DEVICE_FOR_CLIENT:
@@ -2224,7 +2230,8 @@ public class AudioDeviceBroker {
     private static final int MSG_REPORT_NEW_ROUTES = 13;
     private static final int MSG_II_SET_HEARING_AID_VOLUME = 14;
     private static final int MSG_I_SET_AVRCP_ABSOLUTE_VOLUME = 15;
-    private static final int MSG_I_SET_MODE_OWNER = 16;
+    private static final int MSG_L_SET_MODE_OWNER = 16;
+    private static final int MSG_L_SET_MODE_OWNER_SIGNAL = 17;
 
     private static final int MSG_I_BT_SERVICE_DISCONNECTED_PROFILE = 22;
     private static final int MSG_IL_BT_SERVICE_CONNECTED_PROFILE = 23;
diff --git a/services/core/java/com/android/server/audio/AudioService.java b/services/core/java/com/android/server/audio/AudioService.java
index e1909d91a77d..8abe12175f89 100644
--- a/services/core/java/com/android/server/audio/AudioService.java
+++ b/services/core/java/com/android/server/audio/AudioService.java
@@ -455,7 +455,7 @@ public class AudioService extends IAudioService.Stub
     private static final int MSG_UPDATE_AUDIO_MODE = 36;
     private static final int MSG_RECORDING_CONFIG_CHANGE = 37;
     private static final int MSG_BT_DEV_CHANGED = 38;
-
+    private static final int MSG_UPDATE_AUDIO_MODE_SIGNAL = 39;
     private static final int MSG_DISPATCH_AUDIO_MODE = 40;
     private static final int MSG_ROUTING_UPDATED = 41;
     private static final int MSG_INIT_HEADTRACKING_SENSORS = 42;
@@ -1918,7 +1918,7 @@ public class AudioService extends IAudioService.Stub
         // Restore call state
         synchronized (mDeviceBroker.mSetModeLock) {
             onUpdateAudioMode(AudioSystem.MODE_CURRENT, android.os.Process.myPid(),
-                    mContext.getPackageName(), true /*force*/);
+                    mContext.getPackageName(), true /*force*/, false /*signal*/);
         }
         final int forSys;
         synchronized (mSettingsLock) {
@@ -4746,14 +4746,42 @@ public class AudioService extends IAudioService.Stub
                 }
             }
             if (updateAudioMode) {
-                sendMsg(mAudioHandler,
-                        MSG_UPDATE_AUDIO_MODE,
-                        existingMsgPolicy,
-                        AudioSystem.MODE_CURRENT,
-                        android.os.Process.myPid(),
-                        mContext.getPackageName(),
-                        delay);
+                postUpdateAudioMode(existingMsgPolicy, AudioSystem.MODE_CURRENT,
+                        android.os.Process.myPid(), mContext.getPackageName(),
+                        false /*signal*/, delay);
+            }
+        }
+    }
+
+    static class UpdateAudioModeInfo {
+        UpdateAudioModeInfo(int mode, int pid, String packageName) {
+            mMode = mode;
+            mPid = pid;
+            mPackageName = packageName;
+        }
+        private final int mMode;
+        private final int mPid;
+        private final String mPackageName;
+
+        int getMode() {
+            return mMode;
+        }
+        int getPid() {
+            return mPid;
+        }
+        String getPackageName() {
+            return mPackageName;
+        }
+    }
+
+    void postUpdateAudioMode(int msgPolicy, int mode, int pid, String packageName,
+            boolean signal, int delay) {
+        synchronized (mAudioModeResetLock) {
+            if (signal) {
+                mAudioModeResetCount++;
             }
+            sendMsg(mAudioHandler, signal ? MSG_UPDATE_AUDIO_MODE_SIGNAL : MSG_UPDATE_AUDIO_MODE,
+                    msgPolicy, 0, 0, new UpdateAudioModeInfo(mode, pid, packageName), delay);
         }
     }
 
@@ -6155,13 +6183,9 @@ public class AudioService extends IAudioService.Stub
                 } else {
                     SetModeDeathHandler h = mSetModeDeathHandlers.get(index);
                     mSetModeDeathHandlers.remove(index);
-                    sendMsg(mAudioHandler,
-                            MSG_UPDATE_AUDIO_MODE,
-                            SENDMSG_QUEUE,
-                            AudioSystem.MODE_CURRENT,
-                            android.os.Process.myPid(),
-                            mContext.getPackageName(),
-                            0);
+                    postUpdateAudioMode(SENDMSG_QUEUE, AudioSystem.MODE_CURRENT,
+                            android.os.Process.myPid(), mContext.getPackageName(),
+                            false /*signal*/, 0);
                 }
             }
         }
@@ -6407,19 +6431,14 @@ public class AudioService extends IAudioService.Stub
                 }
             }
 
-            sendMsg(mAudioHandler,
-                    MSG_UPDATE_AUDIO_MODE,
-                    SENDMSG_REPLACE,
-                    mode,
-                    pid,
-                    callingPackage,
-                    0);
+            postUpdateAudioMode(SENDMSG_REPLACE, mode, pid, callingPackage,
+                    hasModifyPhoneStatePermission && mode == AudioSystem.MODE_NORMAL, 0);
         }
     }
 
     @GuardedBy("mDeviceBroker.mSetModeLock")
     void onUpdateAudioMode(int requestedMode, int requesterPid, String requesterPackage,
-                           boolean force) {
+                           boolean force, boolean signal) {
         if (requestedMode == AudioSystem.MODE_CURRENT) {
             requestedMode = getMode();
         }
@@ -6434,7 +6453,7 @@ public class AudioService extends IAudioService.Stub
         }
         if (DEBUG_MODE) {
             Log.v(TAG, "onUpdateAudioMode() new mode: " + mode + ", current mode: "
-                    + mMode.get() + " requested mode: " + requestedMode);
+                    + mMode.get() + " requested mode: " + requestedMode + " signal: " + signal);
         }
         if (mode != mMode.get() || force) {
             int status = AudioSystem.SUCCESS;
@@ -6480,8 +6499,11 @@ public class AudioService extends IAudioService.Stub
 
                 // when entering RINGTONE, IN_CALL or IN_COMMUNICATION mode, clear all SCO
                 // connections not started by the application changing the mode when pid changes
-                mDeviceBroker.postSetModeOwner(mode, pid, uid);
+                mDeviceBroker.postSetModeOwner(mode, pid, uid, signal);
             } else {
+                // reset here to avoid sticky out of sync condition (would have been reset
+                // by AudioDeviceBroker processing MSG_L_SET_MODE_OWNER_SIGNAL message)
+                resetAudioModeResetCount();
                 Log.w(TAG, "onUpdateAudioMode: failed to set audio mode to: " + mode);
             }
         }
@@ -10162,7 +10184,7 @@ public class AudioService extends IAudioService.Stub
                         h.setRecordingActive(isRecordingActiveForUid(h.getUid()));
                         if (wasActive != h.isActive()) {
                             onUpdateAudioMode(AudioSystem.MODE_CURRENT, android.os.Process.myPid(),
-                                    mContext.getPackageName(), false /*force*/);
+                                    mContext.getPackageName(), false /*force*/, false /*signal*/);
                         }
                     }
                     break;
@@ -10191,8 +10213,11 @@ public class AudioService extends IAudioService.Stub
                     break;
 
                 case MSG_UPDATE_AUDIO_MODE:
+                case MSG_UPDATE_AUDIO_MODE_SIGNAL:
                     synchronized (mDeviceBroker.mSetModeLock) {
-                        onUpdateAudioMode(msg.arg1, msg.arg2, (String) msg.obj, false /*force*/);
+                        UpdateAudioModeInfo info = (UpdateAudioModeInfo) msg.obj;
+                        onUpdateAudioMode(info.getMode(), info.getPid(), info.getPackageName(),
+                                false /*force*/, msg.what == MSG_UPDATE_AUDIO_MODE_SIGNAL);
                     }
                     break;
 
@@ -10895,9 +10920,68 @@ public class AudioService extends IAudioService.Stub
             return AudioManager.AUDIOFOCUS_REQUEST_FAILED;
         }
         mmi.record();
+        //delay abandon focus requests from Telecom if an audio mode reset from Telecom
+        // is still being processed
+        final boolean abandonFromTelecom = (mContext.checkCallingOrSelfPermission(
+                    MODIFY_PHONE_STATE) == PackageManager.PERMISSION_GRANTED)
+                && ((aa != null && aa.getUsage() == AudioAttributes.USAGE_VOICE_COMMUNICATION)
+                        || AudioSystem.IN_VOICE_COMM_FOCUS_ID.equals(clientId));
+        if (abandonFromTelecom) {
+            synchronized (mAudioModeResetLock) {
+                final long start = java.lang.System.currentTimeMillis();
+                long elapsed = 0;
+                while (mAudioModeResetCount > 0) {
+                    if (DEBUG_MODE) {
+                        Log.i(TAG, "Abandon focus from Telecom, waiting for mode change");
+                    }
+                    try {
+                        mAudioModeResetLock.wait(
+                                AUDIO_MODE_RESET_TIMEOUT_MS - elapsed);
+                    } catch (InterruptedException e) {
+                        Log.w(TAG, "Interrupted while waiting for audio mode reset");
+                    }
+                    elapsed = java.lang.System.currentTimeMillis() - start;
+                    if (elapsed >= AUDIO_MODE_RESET_TIMEOUT_MS) {
+                        Log.e(TAG, "Timeout waiting for audio mode reset");
+                        // reset count to avoid sticky out of sync state.
+                        resetAudioModeResetCount();
+                        break;
+                    }
+                }
+                if (DEBUG_MODE && elapsed != 0) {
+                    Log.i(TAG, "Abandon focus from Telecom done waiting");
+                }
+            }
+        }
         return mMediaFocusControl.abandonAudioFocus(fd, clientId, aa, callingPackageName);
     }
 
+    /** synchronization between setMode(NORMAL) and abandonAudioFocus() from Telecom */
+    private static final long AUDIO_MODE_RESET_TIMEOUT_MS = 3000;
+
+    private final Object mAudioModeResetLock = new Object();
+
+    @GuardedBy("mAudioModeResetLock")
+    private int mAudioModeResetCount = 0;
+
+    void decrementAudioModeResetCount() {
+        synchronized (mAudioModeResetLock) {
+            if (mAudioModeResetCount > 0) {
+                mAudioModeResetCount--;
+            } else {
+                Log.w(TAG, "mAudioModeResetCount already 0");
+            }
+            mAudioModeResetLock.notify();
+        }
+    }
+
+    private void resetAudioModeResetCount() {
+        synchronized (mAudioModeResetLock) {
+            mAudioModeResetCount = 0;
+            mAudioModeResetLock.notify();
+        }
+    }
+
     /** see {@link AudioManager#abandonAudioFocusForTest(AudioFocusRequest, String)} */
     public int abandonAudioFocusForTest(IAudioFocusDispatcher fd, String clientId,
             AudioAttributes aa, String callingPackageName) {
diff --git a/services/core/java/com/android/server/media/projection/MediaProjectionManagerService.java b/services/core/java/com/android/server/media/projection/MediaProjectionManagerService.java
index e7e519ede768..e0913ccbc7f7 100644
--- a/services/core/java/com/android/server/media/projection/MediaProjectionManagerService.java
+++ b/services/core/java/com/android/server/media/projection/MediaProjectionManagerService.java
@@ -28,6 +28,7 @@ import static android.media.projection.ReviewGrantedConsentResult.RECORD_CANCEL;
 import static android.media.projection.ReviewGrantedConsentResult.RECORD_CONTENT_DISPLAY;
 import static android.media.projection.ReviewGrantedConsentResult.RECORD_CONTENT_TASK;
 import static android.media.projection.ReviewGrantedConsentResult.UNKNOWN;
+import static android.provider.Settings.Global.DISABLE_SCREEN_SHARE_PROTECTIONS_FOR_APPS_AND_NOTIFICATIONS;
 import static android.view.Display.DEFAULT_DISPLAY;
 import static android.view.Display.INVALID_DISPLAY;
 
@@ -73,6 +74,7 @@ import android.os.PermissionEnforcer;
 import android.os.RemoteException;
 import android.os.SystemClock;
 import android.os.UserHandle;
+import android.provider.Settings;
 import android.util.ArrayMap;
 import android.util.Slog;
 import android.view.ContentRecordingSession;
@@ -195,6 +197,15 @@ public final class MediaProjectionManagerService extends SystemService
             if (mProjectionGrant == null || mProjectionGrant.packageName == null) {
                 return false;
             }
+            boolean disableScreenShareProtections = Settings.Global.getInt(
+                    getContext().getContentResolver(),
+                    DISABLE_SCREEN_SHARE_PROTECTIONS_FOR_APPS_AND_NOTIFICATIONS, 0) != 0;
+            if (disableScreenShareProtections) {
+                Slog.v(TAG,
+                        "Allowing keyguard capture as screenshare protections are disabled.");
+                return true;
+            }
+
             if (mPackageManager.checkPermission(RECORD_SENSITIVE_CONTENT,
                     mProjectionGrant.packageName)
                     == PackageManager.PERMISSION_GRANTED) {
@@ -226,7 +237,8 @@ public final class MediaProjectionManagerService extends SystemService
     void onKeyguardLockedStateChanged(boolean isKeyguardLocked) {
         if (!isKeyguardLocked) return;
         synchronized (mLock) {
-            if (mProjectionGrant != null && !canCaptureKeyguard()) {
+            if (mProjectionGrant != null && !canCaptureKeyguard()
+                    && mProjectionGrant.mVirtualDisplayId != INVALID_DISPLAY) {
                 Slog.d(TAG, "Content Recording: Stopped MediaProjection"
                         + " due to keyguard lock");
                 mProjectionGrant.stop();
diff --git a/services/core/java/com/android/server/wm/ActivityStartController.java b/services/core/java/com/android/server/wm/ActivityStartController.java
index 35ec5adf54b0..0580d4a5a4a3 100644
--- a/services/core/java/com/android/server/wm/ActivityStartController.java
+++ b/services/core/java/com/android/server/wm/ActivityStartController.java
@@ -43,7 +43,6 @@ import android.content.pm.ApplicationInfo;
 import android.content.pm.PackageManager;
 import android.content.pm.ResolveInfo;
 import android.os.Binder;
-import android.os.Bundle;
 import android.os.IBinder;
 import android.os.Trace;
 import android.os.UserHandle;
@@ -550,14 +549,14 @@ public class ActivityStartController {
      * Starts an activity in the TaskFragment.
      * @param taskFragment TaskFragment {@link TaskFragment} to start the activity in.
      * @param activityIntent intent to start the activity.
-     * @param activityOptions ActivityOptions to start the activity with.
+     * @param activityOptions SafeActivityOptions to start the activity with.
      * @param resultTo the caller activity
      * @param callingUid the caller uid
      * @param callingPid the caller pid
      * @return the start result.
      */
     int startActivityInTaskFragment(@NonNull TaskFragment taskFragment,
-            @NonNull Intent activityIntent, @Nullable Bundle activityOptions,
+            @NonNull Intent activityIntent, @Nullable SafeActivityOptions activityOptions,
             @Nullable IBinder resultTo, int callingUid, int callingPid,
             @Nullable IBinder errorCallbackToken) {
         final ActivityRecord caller =
diff --git a/services/core/java/com/android/server/wm/WindowOrganizerController.java b/services/core/java/com/android/server/wm/WindowOrganizerController.java
index 476443aa2050..b7ecde06d3d2 100644
--- a/services/core/java/com/android/server/wm/WindowOrganizerController.java
+++ b/services/core/java/com/android/server/wm/WindowOrganizerController.java
@@ -1501,8 +1501,10 @@ class WindowOrganizerController extends IWindowOrganizerController.Stub
                 final IBinder callerActivityToken = operation.getActivityToken();
                 final Intent activityIntent = operation.getActivityIntent();
                 final Bundle activityOptions = operation.getBundle();
+                final SafeActivityOptions safeOptions =
+                        SafeActivityOptions.fromBundle(activityOptions, caller.mPid, caller.mUid);
                 final int result = waitAsyncStart(() -> mService.getActivityStartController()
-                        .startActivityInTaskFragment(taskFragment, activityIntent, activityOptions,
+                        .startActivityInTaskFragment(taskFragment, activityIntent, safeOptions,
                                 callerActivityToken, caller.mUid, caller.mPid,
                                 errorCallbackToken));
                 if (!isStartResultSuccessful(result)) {
diff --git a/services/tests/servicestests/src/com/android/server/media/projection/MediaProjectionManagerServiceTest.java b/services/tests/servicestests/src/com/android/server/media/projection/MediaProjectionManagerServiceTest.java
index 425bb158f997..a89350c3e300 100644
--- a/services/tests/servicestests/src/com/android/server/media/projection/MediaProjectionManagerServiceTest.java
+++ b/services/tests/servicestests/src/com/android/server/media/projection/MediaProjectionManagerServiceTest.java
@@ -25,6 +25,7 @@ import static android.media.projection.ReviewGrantedConsentResult.RECORD_CANCEL;
 import static android.media.projection.ReviewGrantedConsentResult.RECORD_CONTENT_DISPLAY;
 import static android.media.projection.ReviewGrantedConsentResult.RECORD_CONTENT_TASK;
 import static android.media.projection.ReviewGrantedConsentResult.UNKNOWN;
+import static android.provider.Settings.Global.DISABLE_SCREEN_SHARE_PROTECTIONS_FOR_APPS_AND_NOTIFICATIONS;
 import static android.view.ContentRecordingSession.TARGET_UID_FULL_SCREEN;
 import static android.view.ContentRecordingSession.TARGET_UID_UNKNOWN;
 import static android.view.ContentRecordingSession.createDisplaySession;
@@ -80,6 +81,7 @@ import android.os.test.TestLooper;
 import android.platform.test.annotations.EnableFlags;
 import android.platform.test.annotations.Presubmit;
 import android.platform.test.flag.junit.SetFlagsRule;
+import android.provider.Settings;
 import android.testing.TestableContext;
 import android.view.ContentRecordingSession;
 import android.view.ContentRecordingSession.RecordContent;
@@ -372,6 +374,50 @@ public class MediaProjectionManagerServiceTest {
         });
     }
 
+    @EnableFlags(android.companion.virtualdevice.flags
+            .Flags.FLAG_MEDIA_PROJECTION_KEYGUARD_RESTRICTIONS)
+    @Test
+    public void testCreateProjection_keyguardLocked_screenshareProtectionsDisabled()
+            throws NameNotFoundException {
+        MediaProjectionManagerService.MediaProjection projection = startProjectionPreconditions();
+        int value = Settings.Global.getInt(mContext.getContentResolver(),
+                DISABLE_SCREEN_SHARE_PROTECTIONS_FOR_APPS_AND_NOTIFICATIONS, 0);
+        try {
+            Settings.Global.putInt(mContext.getContentResolver(),
+                    DISABLE_SCREEN_SHARE_PROTECTIONS_FOR_APPS_AND_NOTIFICATIONS, 1);
+            doReturn(true).when(mKeyguardManager).isKeyguardLocked();
+
+            doReturn(PackageManager.PERMISSION_DENIED).when(mPackageManager).checkPermission(
+                    RECORD_SENSITIVE_CONTENT, projection.packageName);
+
+            projection.start(mIMediaProjectionCallback);
+            projection.notifyVirtualDisplayCreated(10);
+
+            // The projection was started because it was allowed to capture the keyguard.
+            assertThat(mService.getActiveProjectionInfo()).isNotNull();
+        } finally {
+            Settings.Global.putInt(mContext.getContentResolver(),
+                    DISABLE_SCREEN_SHARE_PROTECTIONS_FOR_APPS_AND_NOTIFICATIONS, value);
+        }
+    }
+
+    @EnableFlags(android.companion.virtualdevice.flags
+            .Flags.FLAG_MEDIA_PROJECTION_KEYGUARD_RESTRICTIONS)
+    @Test
+    public void testCreateProjection_keyguardLocked_noDisplayCreated()
+            throws NameNotFoundException {
+        MediaProjectionManagerService.MediaProjection projection = startProjectionPreconditions();
+        doReturn(true).when(mKeyguardManager).isKeyguardLocked();
+
+        doReturn(PackageManager.PERMISSION_DENIED).when(mPackageManager).checkPermission(
+                RECORD_SENSITIVE_CONTENT, projection.packageName);
+
+        projection.start(mIMediaProjectionCallback);
+
+        // The projection was started because it was allowed to capture the keyguard.
+        assertThat(mService.getActiveProjectionInfo()).isNotNull();
+    }
+
     @Test
     public void testCreateProjection_attemptReuse_noPriorProjectionGrant()
             throws NameNotFoundException {
@@ -485,6 +531,7 @@ public class MediaProjectionManagerServiceTest {
         MediaProjectionManagerService.MediaProjection projection =
                 startProjectionPreconditions(service);
         projection.start(mIMediaProjectionCallback);
+        projection.notifyVirtualDisplayCreated(10);
 
         assertThat(service.getActiveProjectionInfo()).isNotNull();
 
@@ -507,6 +554,7 @@ public class MediaProjectionManagerServiceTest {
         MediaProjectionManagerService.MediaProjection projection =
                 startProjectionPreconditions(service);
         projection.start(mIMediaProjectionCallback);
+        projection.notifyVirtualDisplayCreated(10);
 
         assertThat(service.getActiveProjectionInfo()).isNotNull();
 
```

