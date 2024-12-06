```diff
diff --git a/Android.bp b/Android.bp
index 223e9288..682c74e8 100644
--- a/Android.bp
+++ b/Android.bp
@@ -15,6 +15,7 @@
 //
 package {
     default_applicable_licenses: ["Android-Apache-2.0"],
+    default_team: "trendy_team_system_experience",
 }
 
 android_library {
@@ -87,89 +88,6 @@ android_library {
 
 }
 
-android_library {
-    name: "CarSystemUI-tests",
-    manifest: "tests/AndroidManifest.xml",
-    resource_dirs: [
-        "tests/res",
-        "res-keyguard",
-        "res",
-    ],
-    srcs: [
-        "tests/src/**/*.java",
-        "src/**/*.java",
-        "src/**/*.kt",
-        "src/**/I*.aidl",
-    ],
-    static_libs: [
-        "SystemUI-tests",
-        "CarNotificationLib",
-        "SystemUIPluginLib",
-        "SystemUISharedLib",
-        "SettingsLib",
-        "android.car.test.utils",
-        "androidx.legacy_legacy-support-v4",
-        "androidx.recyclerview_recyclerview",
-        "androidx.preference_preference",
-        "androidx.appcompat_appcompat",
-        "androidx.mediarouter_mediarouter",
-        "androidx.palette_palette",
-        "androidx.legacy_legacy-preference-v14",
-        "androidx.leanback_leanback",
-        "androidx.slice_slice-core",
-        "androidx.slice_slice-view",
-        "androidx.slice_slice-builders",
-        "androidx.arch.core_core-runtime",
-        "androidx.lifecycle_lifecycle-common-java8",
-        "androidx.lifecycle_lifecycle-extensions",
-        "car-admin-ui-lib",
-        "car-helper-lib",
-        "car-telephony-common-no-overlayable",
-        "car-ui-lib-no-overlayable",
-        "car-qc-lib",
-        "car-resource-common",
-        "com_android_systemui_car_flags_lib",
-        "SystemUI-tags",
-        "SystemUI-proto",
-        "metrics-helper-lib",
-        "androidx.test.rules",
-        "hamcrest-library",
-        "mockito-target-extended-minus-junit4",
-        "flag-junit",
-        "testables",
-        "truth",
-        "testng",
-        "dagger2",
-        "//external/kotlinc:kotlin-annotations",
-        "CarDockLib",
-        "car-data-subscription-lib",
-
-    ],
-    libs: [
-        "android.test.runner",
-        "android.test.base",
-        "android.car",
-    ],
-
-    aaptflags: [
-        "--extra-packages",
-        "com.android.systemui",
-    ],
-
-    plugins: ["dagger2-compiler"],
-
-    lint: {
-        test: true,
-    },
-
-    // TODO(b/218518451) re-enable errorprone.
-    errorprone: {
-        enabled: false,
-    },
-    // TODO(b/319708040): re-enable use_resource_processor
-    use_resource_processor: false,
-}
-
 android_app {
     name: "CarSystemUI",
 
@@ -218,6 +136,9 @@ android_app {
         "privapp_whitelist_com.android.systemui",
         "allowed_privapp_com.android.carsystemui",
     ],
+
+    // TODO(b/319708040): re-enable use_resource_processor
+    use_resource_processor: false,
 }
 
 // Resource lib
@@ -241,3 +162,179 @@ android_library {
         disabled_checks: ["MissingClass"],
     },
 }
+
+android_library {
+    name: "CarSystemUI-tests-base",
+    manifest: "tests/AndroidManifest-base.xml",
+    resource_dirs: [
+        "tests/res",
+    ],
+    static_libs: [
+        "CarSystemUI-res",
+        "SystemUI-tests-base",
+        "CarNotificationLib",
+        "android.car.test.utils",
+        "car-admin-ui-lib",
+        "car-helper-lib",
+        "car-telephony-common-no-overlayable",
+        "car-ui-lib-no-overlayable",
+        "car-qc-lib",
+        "car-resource-common",
+        "com_android_systemui_car_flags_lib",
+        "CarDockLib",
+        "car-data-subscription-lib",
+        "testng",
+        "//external/kotlinc:kotlin-annotations",
+    ],
+}
+
+android_library {
+    name: "CarSystemUI-tests",
+    manifest: "tests/AndroidManifest-base.xml",
+    additional_manifests: ["tests/AndroidManifest.xml"],
+    srcs: [
+        "tests/src/**/*.java",
+        "tests/src/**/*.kt",
+        ":CarSystemUI-tests-multivalent",
+        "src/**/*.java",
+        "src/**/*.kt",
+        "src/**/I*.aidl",
+    ],
+    static_libs: [
+        "SystemUI-tests",
+        "CarSystemUI-tests-base",
+    ],
+    libs: [
+        "android.test.runner.stubs.system",
+        "android.test.base.stubs.system",
+        "android.car",
+    ],
+
+    aaptflags: [
+        "--extra-packages",
+        "com.android.systemui",
+    ],
+
+    plugins: ["dagger2-compiler"],
+
+    lint: {
+        test: true,
+    },
+
+    // TODO(b/218518451) re-enable errorprone.
+    errorprone: {
+        enabled: false,
+    },
+    // TODO(b/319708040): re-enable use_resource_processor
+    use_resource_processor: false,
+}
+
+android_app {
+    name: "CarSystemUIRobo-stub",
+    defaults: [
+        "platform_app_defaults",
+        "SystemUI_optimized_defaults",
+    ],
+    manifest: "tests/AndroidManifest-base.xml",
+
+    srcs: [
+        "src/**/*.java",
+        "src/**/*.kt",
+        "src/**/I*.aidl",
+    ],
+    static_libs: [
+        "//frameworks/libs/systemui:compilelib",
+        "CarSystemUI-tests-base",
+        "androidx.compose.runtime_runtime",
+        "CarSystemUI-core",
+    ],
+    libs: [
+        "keepanno-annotations",
+        "android.car",
+    ],
+    aaptflags: [
+        "--extra-packages",
+        "com.android.systemui",
+    ],
+    dont_merge_manifests: true,
+    platform_apis: true,
+    system_ext_specific: true,
+    certificate: "platform",
+    privileged: true,
+    kotlincflags: ["-Xjvm-default=all"],
+    optimize: {
+        shrink_resources: false,
+        optimized_shrink_resources: false,
+        proguard_flags_files: ["proguard.flags"],
+    },
+
+    plugins: ["dagger2-compiler"],
+
+    // TODO(b/319708040): re-enable use_resource_processor
+    use_resource_processor: false,
+}
+
+android_robolectric_test {
+    name: "CarSystemUIRoboTests",
+    srcs: [
+        ":SystemUI-robotest-utils",
+        ":SystemUI-tests-utils",
+        ":CarSystemUI-tests-multivalent",
+    ],
+    static_libs: [
+        "RoboTestLibraries",
+    ],
+    libs: [
+        "android.car",
+        "android.test.runner.stubs.system",
+        "android.test.base.stubs.system",
+        "android.test.mock.stubs.system",
+        "truth",
+    ],
+
+    upstream: true,
+
+    instrumentation_for: "CarSystemUIRobo-stub",
+    java_resource_dirs: ["tests/robolectric/config"],
+    plugins: [
+        "dagger2-compiler",
+    ],
+    strict_mode: false,
+}
+
+android_ravenwood_test {
+    name: "CarSystemUIRavenTests",
+    srcs: [
+        ":SystemUI-tests-utils",
+        ":CarSystemUI-tests-multivalent",
+        ":CarSystemUIRobo-stub{.aapt.srcjar}",
+    ],
+    static_libs: [
+        "CarSystemUI-core",
+        "CarSystemUI-res",
+        "CarSystemUI-tests-base",
+        "androidx.test.uiautomator_uiautomator",
+        "androidx.core_core-animation-testing",
+        "androidx.test.ext.junit",
+        "kosmos",
+        "mockito-kotlin-nodeps",
+    ],
+    libs: [
+        "android.car",
+        "android.test.runner.stubs.system",
+        "android.test.base.stubs.system",
+        "android.test.mock.stubs.system",
+    ],
+    auto_gen_config: true,
+    plugins: [
+        "dagger2-compiler",
+    ],
+}
+
+filegroup {
+    name: "CarSystemUI-tests-multivalent",
+    srcs: [
+        "multivalentTests/src/**/*.kt",
+        "multivalentTests/src/**/*.java",
+    ],
+}
diff --git a/AndroidManifest.xml b/AndroidManifest.xml
index 5b6ae870..066277c3 100644
--- a/AndroidManifest.xml
+++ b/AndroidManifest.xml
@@ -40,6 +40,8 @@
     <uses-permission android:name="android.permission.INTERACT_ACROSS_USERS"/>
     <!-- This permission is required to check the foreground user id. -->
     <uses-permission android:name="android.permission.INTERACT_ACROSS_USERS_FULL" />
+    <!-- System permission to use internal system windows -->
+    <uses-permission android:name="android.permission.INTERNAL_SYSTEM_WINDOW"/>
     <!-- This permission is required to get the tasks from CarActivityService. -->
     <uses-permission android:name="android.permission.MANAGE_ACTIVITY_TASKS" />
     <!-- These permissions are required to implement icons based on role holders. -->
@@ -79,7 +81,7 @@
             android:configChanges="screenSize|smallestScreenSize|screenLayout|orientation"
             android:exported="false"
             android:showForAllUsers="true"
-            android:theme="@android:style/Theme.NoTitleBar">
+            android:theme="@style/Theme.NoTitleBar.NoSplash">
             <intent-filter>
                 <action android:name="android.intent.action.MAIN"/>
             </intent-filter>
diff --git a/aconfig/carsystemui.aconfig b/aconfig/carsystemui.aconfig
index e468b3de..08d9ef4a 100644
--- a/aconfig/carsystemui.aconfig
+++ b/aconfig/carsystemui.aconfig
@@ -27,4 +27,32 @@ flag {
     namespace: "car_sys_exp"
     description: "Flag that sets a keyguard showing timeout to ensure keyguard is shown on user switch"
     bug: "335455314"
-}
\ No newline at end of file
+}
+
+flag {
+    name: "move_task_to_distant_display"
+    namespace: "car_sys_exp"
+    description: "Flag that enables task to move between distant display experience"
+    bug: "341963483"
+}
+
+flag {
+    name: "daview_based_windowing"
+    namespace: "car_framework"
+    description: "Flag controlling the use of DaView and DaViewTransitions to implement windowing structure"
+    bug: "348502619"
+}
+
+flag {
+    name: "show_qc_sound_panel"
+    namespace: "car_sys_exp"
+    description: "Flag that shows the quick controls panel for sound."
+    bug: "344677470"
+}
+
+flag {
+    name: "display_compatibility_v2"
+    namespace: "car_sys_exp"
+    description: "This flag controls v2 development to enable display compatibility feature."
+    bug: "364382110"
+}
diff --git a/multivalentTests/src/com/android/systemui/car/systembar/UserNameImageViewControllerTest.java b/multivalentTests/src/com/android/systemui/car/systembar/UserNameImageViewControllerTest.java
new file mode 100644
index 00000000..cb2aed8b
--- /dev/null
+++ b/multivalentTests/src/com/android/systemui/car/systembar/UserNameImageViewControllerTest.java
@@ -0,0 +1,151 @@
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
+package com.android.systemui.car.systembar;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.Mockito.verify;
+import static org.mockito.Mockito.when;
+
+import android.content.pm.UserInfo;
+import android.graphics.drawable.Drawable;
+import android.os.UserManager;
+import android.testing.TestableLooper;
+
+import androidx.test.ext.junit.runners.AndroidJUnit4;
+import androidx.test.filters.SmallTest;
+
+import com.android.systemui.SysuiTestCase;
+import com.android.systemui.car.CarSystemUiTest;
+import com.android.systemui.car.systembar.element.CarSystemBarElementStateController;
+import com.android.systemui.car.systembar.element.CarSystemBarElementStatusBarDisableController;
+import com.android.systemui.car.systembar.element.layout.CarSystemBarImageView;
+import com.android.systemui.car.users.CarProfileIconUpdater;
+import com.android.systemui.car.userswitcher.UserIconProvider;
+import com.android.systemui.settings.UserTracker;
+
+import org.junit.Before;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.mockito.ArgumentCaptor;
+import org.mockito.Mock;
+import org.mockito.MockitoAnnotations;
+
+import java.util.concurrent.Executor;
+
+@CarSystemUiTest
+@RunWith(AndroidJUnit4.class)
+@TestableLooper.RunWithLooper
+@SmallTest
+public class UserNameImageViewControllerTest extends SysuiTestCase {
+    private final UserInfo mUserInfo1 =
+            new UserInfo(/* id= */ 0, /* name= */ "User 1", /* flags= */ 0);
+    private final UserInfo mUserInfo2 =
+            new UserInfo(/* id= */ 1, /* name= */ "User 2", /* flags= */ 0);
+
+    @Mock
+    CarSystemBarElementStatusBarDisableController mDisableController;
+    @Mock
+    CarSystemBarElementStateController mStateController;
+    @Mock
+    private Executor mExecutor;
+    @Mock
+    private UserTracker mUserTracker;
+    @Mock
+    private UserManager mUserManager;
+    @Mock
+    private CarProfileIconUpdater mIconUpdater;
+    @Mock
+    private UserIconProvider mUserIconProvider;
+    @Mock
+    private Drawable mTestDrawable1;
+    @Mock
+    private Drawable mTestDrawable2;
+
+    private CarSystemBarImageView mView;
+    private UserNameImageViewController mController;
+
+    @Before
+    public void setUp() {
+        MockitoAnnotations.initMocks(this);
+
+        when(mUserManager.getUserInfo(mUserInfo1.id)).thenReturn(mUserInfo1);
+        when(mUserManager.getUserInfo(mUserInfo2.id)).thenReturn(mUserInfo2);
+        when(mUserTracker.getUserId()).thenReturn(mUserInfo1.id);
+        when(mUserIconProvider.getRoundedUserIcon(any(), any())).thenReturn(mTestDrawable1);
+
+        mView = new CarSystemBarImageView(mContext);
+        mController = new UserNameImageViewController(mView, mDisableController,
+                mStateController, mContext, mExecutor, mUserTracker, mUserManager, mIconUpdater,
+                mUserIconProvider);
+    }
+
+    @Test
+    public void onViewAttached_registersListeners() {
+        mController.onViewAttached();
+
+        verify(mUserTracker).addCallback(any(), any());
+        verify(mIconUpdater).addCallback(any());
+    }
+
+    @Test
+    public void onViewAttached_updatesUser() {
+        mController.onViewAttached();
+
+        assertThat(mView.getDrawable()).isEqualTo(mTestDrawable1);
+    }
+
+    @Test
+    public void onViewDetached_unregistersListeners() {
+        mController.onViewAttached();
+        mController.onViewDetached();
+
+        verify(mUserTracker).removeCallback(any());
+        verify(mIconUpdater).removeCallback(any());
+    }
+
+    @Test
+    public void onUserSwitched_updatesUser() {
+        ArgumentCaptor<UserTracker.Callback> captor = ArgumentCaptor.forClass(
+                UserTracker.Callback.class);
+        mController.onViewAttached();
+        verify(mUserTracker).addCallback(captor.capture(), any());
+        assertThat(captor.getValue()).isNotNull();
+
+        when(mUserTracker.getUserId()).thenReturn(mUserInfo2.id);
+        when(mUserIconProvider.getRoundedUserIcon(any(), any())).thenReturn(mTestDrawable2);
+        captor.getValue().onUserChanged(mUserInfo2.id, mContext);
+
+        assertThat(mView.getDrawable()).isEqualTo(mTestDrawable2);
+    }
+
+    @Test
+    public void onUserIconChanged_updatesUser() {
+        ArgumentCaptor<CarProfileIconUpdater.Callback> captor = ArgumentCaptor.forClass(
+                CarProfileIconUpdater.Callback.class);
+        mController.onViewAttached();
+        verify(mIconUpdater).addCallback(captor.capture());
+        assertThat(captor.getValue()).isNotNull();
+
+        when(mUserTracker.getUserId()).thenReturn(mUserInfo2.id);
+        when(mUserIconProvider.getRoundedUserIcon(any(), any())).thenReturn(mTestDrawable2);
+        captor.getValue().onUserIconUpdated(mUserInfo2.id);
+
+        assertThat(mView.getDrawable()).isEqualTo(mTestDrawable2);
+    }
+}
diff --git a/multivalentTests/src/com/android/systemui/car/systembar/UserNameTextViewControllerTest.java b/multivalentTests/src/com/android/systemui/car/systembar/UserNameTextViewControllerTest.java
new file mode 100644
index 00000000..ea803b97
--- /dev/null
+++ b/multivalentTests/src/com/android/systemui/car/systembar/UserNameTextViewControllerTest.java
@@ -0,0 +1,142 @@
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
+package com.android.systemui.car.systembar;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.Mockito.verify;
+import static org.mockito.Mockito.when;
+
+import android.content.BroadcastReceiver;
+import android.content.Intent;
+import android.content.pm.UserInfo;
+import android.os.UserManager;
+import android.testing.TestableLooper;
+
+import androidx.test.ext.junit.runners.AndroidJUnit4;
+import androidx.test.filters.SmallTest;
+
+import com.android.systemui.SysuiTestCase;
+import com.android.systemui.broadcast.BroadcastDispatcher;
+import com.android.systemui.car.CarSystemUiTest;
+import com.android.systemui.car.systembar.element.CarSystemBarElementStateController;
+import com.android.systemui.car.systembar.element.CarSystemBarElementStatusBarDisableController;
+import com.android.systemui.car.systembar.element.layout.CarSystemBarTextView;
+import com.android.systemui.settings.UserTracker;
+
+import org.junit.Before;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.mockito.ArgumentCaptor;
+import org.mockito.Mock;
+import org.mockito.MockitoAnnotations;
+
+import java.util.concurrent.Executor;
+
+@CarSystemUiTest
+@RunWith(AndroidJUnit4.class)
+@TestableLooper.RunWithLooper
+@SmallTest
+public class UserNameTextViewControllerTest extends SysuiTestCase {
+    private static final String USER_1_NAME = "User 1";
+    private static final String USER_2_NAME = "User 2";
+    private final UserInfo mUserInfo1 =
+            new UserInfo(/* id= */ 0, USER_1_NAME, /* flags= */ 0);
+    private final UserInfo mUserInfo2 =
+            new UserInfo(/* id= */ 1, USER_2_NAME, /* flags= */ 0);
+
+    @Mock
+    CarSystemBarElementStatusBarDisableController mDisableController;
+    @Mock
+    CarSystemBarElementStateController mStateController;
+    @Mock
+    private Executor mExecutor;
+    @Mock
+    private UserTracker mUserTracker;
+    @Mock
+    private UserManager mUserManager;
+    @Mock
+    private BroadcastDispatcher mBroadcastDispatcher;
+
+    private CarSystemBarTextView mView;
+    private UserNameTextViewController mController;
+
+    @Before
+    public void setUp() {
+        MockitoAnnotations.initMocks(this);
+
+        when(mUserManager.getUserInfo(mUserInfo1.id)).thenReturn(mUserInfo1);
+        when(mUserManager.getUserInfo(mUserInfo2.id)).thenReturn(mUserInfo2);
+        when(mUserTracker.getUserId()).thenReturn(mUserInfo1.id);
+
+        mView = new CarSystemBarTextView(mContext);
+        mController = new UserNameTextViewController(mView, mDisableController,
+                mStateController, mExecutor, mUserTracker, mUserManager, mBroadcastDispatcher);
+    }
+
+    @Test
+    public void onViewAttached_registersListeners() {
+        mController.onViewAttached();
+
+        verify(mUserTracker).addCallback(any(), any());
+        verify(mBroadcastDispatcher).registerReceiver(any(), any(), any(), any());
+    }
+
+    @Test
+    public void onViewAttached_updatesUser() {
+        mController.onViewAttached();
+
+        assertThat(mView.getText().toString()).isEqualTo(USER_1_NAME);
+    }
+
+    @Test
+    public void onViewDetached_unregistersListeners() {
+        mController.onViewAttached();
+        mController.onViewDetached();
+
+        verify(mUserTracker).removeCallback(any());
+        verify(mBroadcastDispatcher).unregisterReceiver(any());
+    }
+
+    @Test
+    public void onUserSwitched_updatesUser() {
+        ArgumentCaptor<UserTracker.Callback> captor = ArgumentCaptor.forClass(
+                UserTracker.Callback.class);
+        mController.onViewAttached();
+        verify(mUserTracker).addCallback(captor.capture(), any());
+        assertThat(captor.getValue()).isNotNull();
+
+        captor.getValue().onUserChanged(mUserInfo2.id, mContext);
+
+        assertThat(mView.getText().toString()).isEqualTo(USER_2_NAME);
+    }
+
+    @Test
+    public void onUserNameChanged_updatesUser() {
+        ArgumentCaptor<BroadcastReceiver> captor = ArgumentCaptor.forClass(BroadcastReceiver.class);
+        mController.onViewAttached();
+        verify(mBroadcastDispatcher).registerReceiver(captor.capture(), any(), any(), any());
+        assertThat(captor.getValue()).isNotNull();
+
+        when(mUserTracker.getUserId()).thenReturn(mUserInfo2.id);
+        captor.getValue().onReceive(getContext(),
+                new Intent(Intent.ACTION_USER_INFO_CHANGED));
+
+        assertThat(mView.getText().toString()).isEqualTo(USER_2_NAME);
+    }
+}
diff --git a/multivalentTests/src/com/android/systemui/car/users/CarProfileIconUpdaterTest.java b/multivalentTests/src/com/android/systemui/car/users/CarProfileIconUpdaterTest.java
new file mode 100644
index 00000000..cbf86a4c
--- /dev/null
+++ b/multivalentTests/src/com/android/systemui/car/users/CarProfileIconUpdaterTest.java
@@ -0,0 +1,150 @@
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
+package com.android.systemui.car.users;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.anyInt;
+import static org.mockito.Mockito.clearInvocations;
+import static org.mockito.Mockito.never;
+import static org.mockito.Mockito.verify;
+import static org.mockito.Mockito.when;
+
+import android.content.BroadcastReceiver;
+import android.content.Intent;
+import android.content.pm.UserInfo;
+import android.os.UserHandle;
+import android.os.UserManager;
+import android.testing.TestableLooper;
+
+import androidx.test.ext.junit.runners.AndroidJUnit4;
+import androidx.test.filters.SmallTest;
+
+import com.android.systemui.SysuiTestCase;
+import com.android.systemui.broadcast.BroadcastDispatcher;
+import com.android.systemui.car.CarSystemUiTest;
+import com.android.systemui.car.userswitcher.UserIconProvider;
+import com.android.systemui.settings.UserTracker;
+
+import org.junit.Before;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.mockito.ArgumentCaptor;
+import org.mockito.InOrder;
+import org.mockito.Mock;
+import org.mockito.Mockito;
+import org.mockito.MockitoAnnotations;
+
+import java.util.concurrent.Executor;
+
+@CarSystemUiTest
+@RunWith(AndroidJUnit4.class)
+@TestableLooper.RunWithLooper
+@SmallTest
+public class CarProfileIconUpdaterTest extends SysuiTestCase {
+    private final UserInfo mUserInfo1 =
+            new UserInfo(/* id= */ 0, /* name= */ "User 1", /* flags= */ 0);
+    private final UserInfo mUserInfo2 =
+            new UserInfo(/* id= */ 1, /* name= */ "User 2", /* flags= */ 0);
+
+    @Mock
+    private Executor mExecutor;
+    @Mock
+    private UserTracker mUserTracker;
+    @Mock
+    private UserManager mUserManager;
+    @Mock
+    private BroadcastDispatcher mBroadcastDispatcher;
+    @Mock
+    private UserIconProvider mUserIconProvider;
+    @Mock
+    private CarProfileIconUpdater.Callback mTestCallback;
+
+    private CarProfileIconUpdater mIconUpdater;
+
+    @Before
+    public void setUp() {
+        MockitoAnnotations.initMocks(this);
+
+        when(mUserManager.getUserInfo(mUserInfo1.id)).thenReturn(mUserInfo1);
+        when(mUserManager.getUserInfo(mUserInfo2.id)).thenReturn(mUserInfo2);
+        when(mUserTracker.getUserId()).thenReturn(mUserInfo1.id);
+        when(mUserTracker.getUserHandle()).thenReturn(UserHandle.of(mUserInfo1.id));
+
+        mIconUpdater = new CarProfileIconUpdater(mContext, mExecutor, mUserTracker, mUserManager,
+                mBroadcastDispatcher, mUserIconProvider);
+        mIconUpdater.addCallback(mTestCallback);
+    }
+
+    @Test
+    public void onStart_registersListeners() {
+        mIconUpdater.start();
+
+        verify(mUserTracker).addCallback(any(), any());
+        verify(mBroadcastDispatcher).registerReceiver(any(), any(), any(), any());
+    }
+
+    @Test
+    public void onUserInfoUpdate_userNameChanged_iconUpdated() {
+        ArgumentCaptor<BroadcastReceiver> captor = ArgumentCaptor.forClass(BroadcastReceiver.class);
+        mIconUpdater.start();
+        verify(mBroadcastDispatcher).registerReceiver(captor.capture(), any(), any(), any());
+        assertThat(captor.getValue()).isNotNull();
+
+        when(mUserTracker.getUserId()).thenReturn(mUserInfo2.id);
+        when(mUserTracker.getUserHandle()).thenReturn(UserHandle.of(mUserInfo2.id));
+        captor.getValue().onReceive(getContext(),
+                new Intent(Intent.ACTION_USER_INFO_CHANGED));
+
+        verify(mUserIconProvider).setRoundedUserIcon(any(), any());
+        verify(mTestCallback).onUserIconUpdated(anyInt());
+    }
+
+    @Test
+    public void onUserInfoUpdate_userNameNotChanged_iconNotUpdated() {
+        ArgumentCaptor<BroadcastReceiver> captor = ArgumentCaptor.forClass(BroadcastReceiver.class);
+        mIconUpdater.start();
+        verify(mBroadcastDispatcher).registerReceiver(captor.capture(), any(), any(), any());
+        assertThat(captor.getValue()).isNotNull();
+
+        captor.getValue().onReceive(getContext(),
+                new Intent(Intent.ACTION_USER_INFO_CHANGED));
+
+        verify(mUserIconProvider, never()).setRoundedUserIcon(any(), any());
+        verify(mTestCallback, never()).onUserIconUpdated(anyInt());
+    }
+
+    @Test
+    public void onUserSwitched_refreshInfoListener() {
+        ArgumentCaptor<UserTracker.Callback> captor = ArgumentCaptor.forClass(
+                UserTracker.Callback.class);
+        mIconUpdater.start();
+        verify(mUserTracker).addCallback(captor.capture(), any());
+        verify(mBroadcastDispatcher).registerReceiver(any(), any(), any(), any());
+        assertThat(captor.getValue()).isNotNull();
+
+        clearInvocations(mBroadcastDispatcher);
+        when(mUserTracker.getUserId()).thenReturn(mUserInfo2.id);
+        when(mUserTracker.getUserHandle()).thenReturn(UserHandle.of(mUserInfo2.id));
+        captor.getValue().onUserChanged(mUserInfo2.id, mContext);
+
+        InOrder inOrder = Mockito.inOrder(mBroadcastDispatcher);
+        inOrder.verify(mBroadcastDispatcher).unregisterReceiver(any());
+        inOrder.verify(mBroadcastDispatcher).registerReceiver(any(), any(), any(), any());
+    }
+}
diff --git a/tests/src/com/android/systemui/wm/BarControlPolicyTest.java b/multivalentTests/src/com/android/systemui/wm/BarControlPolicyTest.java
similarity index 97%
rename from tests/src/com/android/systemui/wm/BarControlPolicyTest.java
rename to multivalentTests/src/com/android/systemui/wm/BarControlPolicyTest.java
index da7cb8e4..cd025abf 100644
--- a/tests/src/com/android/systemui/wm/BarControlPolicyTest.java
+++ b/multivalentTests/src/com/android/systemui/wm/BarControlPolicyTest.java
@@ -23,19 +23,21 @@ import static com.google.common.truth.Truth.assertThat;
 
 import android.car.settings.CarSettings;
 import android.provider.Settings;
-import android.testing.AndroidTestingRunner;
 import android.testing.TestableLooper;
 
+import androidx.test.ext.junit.runners.AndroidJUnit4;
 import androidx.test.filters.SmallTest;
 
 import com.android.systemui.SysuiTestCase;
+import com.android.systemui.car.CarSystemUiTest;
 
 import org.junit.After;
 import org.junit.Before;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 
-@RunWith(AndroidTestingRunner.class)
+@CarSystemUiTest
+@RunWith(AndroidJUnit4.class)
 @TestableLooper.RunWithLooper
 @SmallTest
 public class BarControlPolicyTest extends SysuiTestCase {
diff --git a/tests/src/com/android/systemui/wm/DisplaySystemBarsControllerTest.java b/multivalentTests/src/com/android/systemui/wm/DisplaySystemBarsControllerTest.java
similarity index 94%
rename from tests/src/com/android/systemui/wm/DisplaySystemBarsControllerTest.java
rename to multivalentTests/src/com/android/systemui/wm/DisplaySystemBarsControllerTest.java
index 3677742d..1c5648ed 100644
--- a/tests/src/com/android/systemui/wm/DisplaySystemBarsControllerTest.java
+++ b/multivalentTests/src/com/android/systemui/wm/DisplaySystemBarsControllerTest.java
@@ -24,13 +24,14 @@ import static org.mockito.Mockito.when;
 import android.car.settings.CarSettings;
 import android.os.Handler;
 import android.provider.Settings;
-import android.testing.AndroidTestingRunner;
 import android.testing.TestableLooper;
 import android.view.IWindowManager;
 
+import androidx.test.ext.junit.runners.AndroidJUnit4;
 import androidx.test.filters.SmallTest;
 
 import com.android.systemui.SysuiTestCase;
+import com.android.systemui.car.CarSystemUiTest;
 import com.android.wm.shell.common.DisplayController;
 import com.android.wm.shell.common.DisplayInsetsController;
 import com.android.wm.shell.common.DisplayLayout;
@@ -41,7 +42,8 @@ import org.junit.runner.RunWith;
 import org.mockito.Mock;
 import org.mockito.MockitoAnnotations;
 
-@RunWith(AndroidTestingRunner.class)
+@CarSystemUiTest
+@RunWith(AndroidJUnit4.class)
 @TestableLooper.RunWithLooper
 @SmallTest
 public class DisplaySystemBarsControllerTest extends SysuiTestCase {
diff --git a/res-keyguard/layout/keyguard_password_view.xml b/res-keyguard/layout/keyguard_password_view.xml
index 7e5d011d..716648e8 100644
--- a/res-keyguard/layout/keyguard_password_view.xml
+++ b/res-keyguard/layout/keyguard_password_view.xml
@@ -47,7 +47,8 @@
             android:id="@+id/passwordEntry"
             android:layout_width="@dimen/password_field_width"
             android:layout_height="wrap_content"
-            android:gravity="center_horizontal"
+            android:gravity="center"
+            android:layout_gravity="center"
             android:singleLine="true"
             android:textStyle="normal"
             android:inputType="textPassword"
@@ -59,7 +60,7 @@
          />
 
         <TextView
-            android:layout_width="match_parent"
+            android:layout_width="wrap_content"
             android:layout_height="wrap_content"
             android:layout_margin="@*android:dimen/car_padding_2"
             android:gravity="center"
diff --git a/res/drawable/car_ic_control_center.xml b/res/drawable/car_ic_control_center.xml
index fb4bb740..1d884774 100644
--- a/res/drawable/car_ic_control_center.xml
+++ b/res/drawable/car_ic_control_center.xml
@@ -14,17 +14,17 @@
   ~ See the License for the specific language governing permissions and
   ~ limitations under the License.
   -->
+
 <vector xmlns:android="http://schemas.android.com/apk/res/android"
-        android:viewportWidth="41"
-        android:viewportHeight="33"
-        android:width="41dp"
-        android:height="33dp">
+    android:width="37dp"
+    android:height="36dp"
+    android:viewportWidth="37"
+    android:viewportHeight="36">
     <path
-        android:pathData="M9.11196 7.52276L9.11196 32.8337C9.11196 32.8337 10.9251 32.8337 13.1617 32.8337L40.4976 32.8337C40.4976 32.8337 40.4976 31.0206 40.4976 28.784L40.4976 11.5725C40.4976 9.3359 40.4976 7.52276 40.4976 7.52276L9.11196 7.52276Z"
-        android:fillType="evenOdd"
-        android:fillColor="@color/car_nav_icon_fill_color" />
+        android:pathData="M25.05,30.717L3.711,30.717C3.199,30.717 2.783,30.301 2.783,29.789L2.783,14.017C2.783,13.504 3.199,13.089 3.711,13.089L25.05,13.089C25.562,13.089 25.978,13.504 25.978,14.017L25.978,29.789C25.978,30.301 25.562,30.717 25.05,30.717ZM3.711,33.5C1.662,33.5 0,31.838 0,29.789L0,14.017C-0,11.967 1.662,10.306 3.711,10.306L25.05,10.306C27.1,10.306 28.761,11.967 28.761,14.017V29.789C28.761,31.838 27.1,33.5 25.05,33.5L3.711,33.5Z"
+        android:fillColor="@color/car_nav_icon_fill_color"
+        android:fillType="evenOdd"/>
     <path
-        android:pathData="M6.1423 4.76394L31.5695 4.76394V3.09985L31.5198 0L0.0252967 0.000335693C-0.00000108965 0.000335693 0 1.86323 0 4.09985L0 21.4988C0 23.7354 0 25.5486 0.0235426 25.5486H6.1423L6.1423 22.5112C6.1423 22.5112 6.1423 22.058 6.1423 21.4988L6.1423 4.76394Z"
-        android:fillType="evenOdd"
-        android:fillColor="@color/car_nav_icon_fill_color" />
-</vector>
\ No newline at end of file
+        android:pathData="M7.312,7.697L7.312,6.712C7.312,4.662 8.974,3.001 11.024,3.001L32.362,3.001C34.412,3.001 36.074,4.662 36.074,6.712V22.484C36.074,24.534 34.412,26.195 32.362,26.195H31.316V23.412H32.362C32.875,23.412 33.29,22.997 33.29,22.484L33.29,6.712C33.29,6.2 32.875,5.784 32.362,5.784L11.024,5.784C10.511,5.784 10.096,6.2 10.096,6.712V7.697H7.312Z"
+        android:fillColor="@color/car_nav_icon_fill_color"/>
+</vector>
diff --git a/res/drawable/car_ic_debug.xml b/res/drawable/car_ic_debug.xml
new file mode 100644
index 00000000..6ff5103c
--- /dev/null
+++ b/res/drawable/car_ic_debug.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2024 The Android Open Source Project
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
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+        android:width="24dp"
+        android:height="24dp"
+        android:viewportWidth="24"
+        android:viewportHeight="24"
+        android:tint="?android:attr/colorControlNormal">
+    <path
+        android:pathData="m4.3301,20.7553c-0.9663,-0.9663 -0.9968,-1.0933 -0.9968,-4.1483 0,-3.2625 -0.1683,-3.7057 -1.5,-3.9507C0.6808,12.4444 0.8254,11.2374 2.0688,10.6903l1.0978,-0.483 0.1667,-3.2801c0.1577,-3.1043 0.218,-3.3242 1.1232,-4.1016 1.1668,-1.0022 2.7101,-0.9771 2.7101,0.0439 0,0.3936 -0.3717,0.8403 -0.9167,1.1015 -0.8964,0.4296 -0.9167,0.5037 -0.9167,3.347 0,2.0922 -0.1455,3.1154 -0.5189,3.6485 -0.4696,0.6705 -0.4696,0.8112 0,1.4817 0.3796,0.542 0.5189,1.5755 0.5189,3.8507v3.1098l1.0181,0.3549c0.7672,0.2674 0.9931,0.5301 0.9167,1.066 -0.1664,1.1666 -1.7368,1.127 -2.9379,-0.0742zM16.8889,21.485c-0.5444,-0.5444 -0.1586,-1.4014 0.7778,-1.7278l1,-0.3486v-3.1098c0,-2.2752 0.1393,-3.3087 0.5189,-3.8507 0.4696,-0.6705 0.4696,-0.8112 0,-1.4817 -0.3734,-0.5331 -0.5189,-1.5563 -0.5189,-3.6485 0,-2.8432 -0.0203,-2.9174 -0.9167,-3.347 -0.5449,-0.2612 -0.9167,-0.7079 -0.9167,-1.1015 0,-1.0211 1.5433,-1.0461 2.7101,-0.0439 0.9052,0.7775 0.9655,0.9974 1.1232,4.1016l0.1667,3.2801 1.0978,0.483c1.2434,0.5471 1.388,1.7541 0.2355,1.9661 -1.3317,0.2449 -1.5,0.6881 -1.5,3.9507 0,3.0388 -0.0349,3.1863 -0.9744,4.1259 -0.9044,0.9044 -2.2817,1.2739 -2.8034,0.7521z"
+        android:strokeWidth="0.33333334"
+        android:fillColor="#000000"/>
+</vector>
diff --git a/res/drawable/car_ic_media_volume_down.xml b/res/drawable/car_ic_media_volume_down.xml
index 629415f2..b264ddcb 100644
--- a/res/drawable/car_ic_media_volume_down.xml
+++ b/res/drawable/car_ic_media_volume_down.xml
@@ -14,8 +14,8 @@
   ~ limitations under the License.
   -->
 <vector xmlns:android="http://schemas.android.com/apk/res/android"
-        android:width="@dimen/car_quick_controls_icon_drawable_width"
-        android:height="@dimen/car_quick_controls_icon_drawable_height"
+        android:width="@dimen/system_bar_icon_drawing_size"
+        android:height="@dimen/system_bar_icon_drawing_size"
         android:viewportWidth="36"
         android:viewportHeight="36">
     <path
diff --git a/res/drawable/car_ic_media_volume_off.xml b/res/drawable/car_ic_media_volume_off.xml
index a4243e8f..cc8fe1e6 100644
--- a/res/drawable/car_ic_media_volume_off.xml
+++ b/res/drawable/car_ic_media_volume_off.xml
@@ -14,8 +14,8 @@
   ~ limitations under the License.
   -->
 <vector xmlns:android="http://schemas.android.com/apk/res/android"
-        android:width="@dimen/car_quick_controls_icon_drawable_width"
-        android:height="@dimen/car_quick_controls_icon_drawable_height"
+        android:width="@dimen/system_bar_icon_drawing_size"
+        android:height="@dimen/system_bar_icon_drawing_size"
         android:viewportWidth="36"
         android:viewportHeight="36">
     <path
diff --git a/res/drawable/car_ic_media_volume_up.xml b/res/drawable/car_ic_media_volume_up.xml
index 58dad969..40810541 100644
--- a/res/drawable/car_ic_media_volume_up.xml
+++ b/res/drawable/car_ic_media_volume_up.xml
@@ -14,8 +14,8 @@
   ~ limitations under the License.
   -->
 <vector xmlns:android="http://schemas.android.com/apk/res/android"
-        android:width="@dimen/car_quick_controls_icon_drawable_width"
-        android:height="@dimen/car_quick_controls_icon_drawable_height"
+        android:width="@dimen/system_bar_icon_drawing_size"
+        android:height="@dimen/system_bar_icon_drawing_size"
         android:viewportWidth="36"
         android:viewportHeight="36">
     <path
diff --git a/res/layout/activity_blocking.xml b/res/layout/activity_blocking.xml
index 5d9d9041..fff08358 100644
--- a/res/layout/activity_blocking.xml
+++ b/res/layout/activity_blocking.xml
@@ -29,6 +29,7 @@
         android:layout_width="match_parent"
         android:layout_height="match_parent"
         android:background="@color/activity_blocking_activity_background"
+        android:visibility="gone"
         android:gravity="center"
         android:orientation="vertical">
 
diff --git a/res/layout/car_bottom_system_bar.xml b/res/layout/car_bottom_system_bar.xml
index b65d6eb3..c260f95b 100644
--- a/res/layout/car_bottom_system_bar.xml
+++ b/res/layout/car_bottom_system_bar.xml
@@ -116,7 +116,7 @@
                 style="@style/SystemBarButton"
                 systemui:highlightWhenSelected="true"
                 systemui:icon="@drawable/car_ic_notification"
-                systemui:longIntent="intent:#Intent;action=com.android.car.bugreport.action.START_AUDIO_FIRST;component=com.android.car.bugreport/.BugReportActivity;end"/>
+                systemui:longIntent="intent:#Intent;action=com.android.car.bugreport.action.START_BUG_REPORT;end"/>
 
             <com.android.systemui.car.systembar.AssistantButton
                 android:id="@+id/assistant"
@@ -173,4 +173,4 @@
             systemui:icon="@drawable/car_ic_home"
             systemui:intent="intent:#Intent;action=android.intent.action.MAIN;category=android.intent.category.HOME;launchFlags=0x14000000;end"/>
     </LinearLayout>
-</com.android.systemui.car.systembar.CarSystemBarView>
\ No newline at end of file
+</com.android.systemui.car.systembar.CarSystemBarView>
diff --git a/res/layout/car_bottom_system_bar_dock.xml b/res/layout/car_bottom_system_bar_dock.xml
index 7d455209..5bc42a8f 100644
--- a/res/layout/car_bottom_system_bar_dock.xml
+++ b/res/layout/car_bottom_system_bar_dock.xml
@@ -88,12 +88,15 @@
                 android:layout_height="wrap_content" />
         </com.android.systemui.car.systembar.element.layout.CarSystemBarFrameLayout>
 
-        <com.android.systemui.car.systembar.AssistantButton
-            android:id="@+id/assistant"
-            android:contentDescription="@string/system_bar_assistant_label"
-            style="@style/SystemBarButtonWithDock"
+        <com.android.systemui.car.systembar.CarSystemBarButton
+            android:id="@+id/control_center_nav"
+            android:contentDescription="@string/system_bar_control_center_label"
+            style="@style/SystemBarButton"
+            android:visibility="gone"
             systemui:highlightWhenSelected="true"
-            systemui:icon="@drawable/ic_mic_light"/>
+            systemui:icon="@drawable/car_ic_control_center"
+            systemui:intent="intent:#Intent;action=android.intent.action.MAIN;package=com.android.car.multidisplay.controlcenter;component=com.android.car.multidisplay.controlcenter/.ControlCenterActivity;B.BOTTOM_BAR_LAUNCH=true;end"
+            systemui:componentNames="com.android.car.multidisplay.controlcenter/.ControlCenterActivity"/>
 
         <Space
             android:layout_width="0dp"
@@ -112,11 +115,12 @@
             android:layout_height="match_parent"
             android:layout_weight="1"/>
 
-        <com.android.systemui.car.systembar.VolumeButton
-            android:id="@+id/volume"
-            android:contentDescription="@string/system_bar_home_label"
+        <com.android.systemui.car.systembar.AssistantButton
+            android:id="@+id/assistant"
+            android:contentDescription="@string/system_bar_assistant_label"
             style="@style/SystemBarButtonWithDock"
-            systemui:icon="@drawable/car_ic_volume" />
+            systemui:highlightWhenSelected="true"
+            systemui:icon="@drawable/ic_mic_light"/>
 
     </LinearLayout>
 
diff --git a/res/layout/car_left_system_bar.xml b/res/layout/car_left_system_bar.xml
index cbcdaf6f..703587bf 100644
--- a/res/layout/car_left_system_bar.xml
+++ b/res/layout/car_left_system_bar.xml
@@ -24,7 +24,7 @@
     android:orientation="vertical"
     app:default_layout="@layout/car_left_system_bar_default"
     app:displaycompat_layout="@layout/displaycompat_toolbar"
-    app:displaycompat_side="left"
+    app:displaycompat_side="1"
     android:background="@drawable/nav_bar_background">
 
 </com.android.systemui.car.displaycompat.CarDisplayCompatSystemBarView>
diff --git a/res/layout/car_system_bar_button.xml b/res/layout/car_system_bar_button.xml
index d7210008..bf0de2a1 100644
--- a/res/layout/car_system_bar_button.xml
+++ b/res/layout/car_system_bar_button.xml
@@ -25,7 +25,8 @@
         android:layout_height="match_parent"
         android:layout_weight="1"
         android:animateLayoutChanges="true"
-        android:orientation="vertical">
+        android:orientation="vertical"
+        android:visibility="gone">
 
         <com.android.systemui.statusbar.AlphaOptimizedImageView
             android:id="@+id/car_nav_button_icon_image"
@@ -38,6 +39,7 @@
             android:tintMode="src_in"
             android:tint="@color/car_nav_icon_fill_color_selected"
             android:clickable="false"
+            android:visibility="gone"
         />
 
         <com.android.systemui.statusbar.AlphaOptimizedImageView
@@ -62,6 +64,7 @@
             android:background="@android:color/transparent"
             android:scaleType="fitCenter"
             android:clickable="false"
+            android:visibility="gone"
         />
 
     </FrameLayout>
diff --git a/res/layout/car_top_system_bar.xml b/res/layout/car_top_system_bar.xml
index b15aeb30..86287d3f 100644
--- a/res/layout/car_top_system_bar.xml
+++ b/res/layout/car_top_system_bar.xml
@@ -75,51 +75,10 @@
             android:contentDescription="@string/system_bar_mic_privacy_chip"
         />
 
-        <FrameLayout
-            android:id="@+id/user_name_container"
+        <include layout="@layout/user_name_container"
             android:layout_width="wrap_content"
             android:layout_height="match_parent"
-            android:layout_alignParentEnd="true"
-            android:layout_centerVertical="true">
-            <com.android.systemui.car.systembar.CarSystemBarButton
-                android:id="@+id/user_name"
-                android:layout_width="wrap_content"
-                android:layout_height="@dimen/car_system_bar_user_name_button_height"
-                android:layout_marginEnd="@dimen/car_padding_2"
-                android:background="@drawable/status_icon_background"
-                android:layout_gravity="center_vertical"
-                systemui:longIntent="@string/user_profile_long_press_intent">
-                <LinearLayout
-                    android:layout_width="match_parent"
-                    android:layout_height="match_parent"
-                    android:orientation="horizontal"
-                    android:layout_marginStart="@dimen/car_padding_2"
-                    android:layout_marginEnd="@dimen/car_padding_2"
-                    android:gravity="center_vertical"
-                >
-                    <ImageView
-                        android:id="@+id/user_avatar"
-                        android:layout_width="wrap_content"
-                        android:layout_height="match_parent"
-                        android:src="@drawable/car_ic_users_icon"
-                        android:tint="@color/system_bar_icon_color_with_selection"
-                        android:layout_marginEnd="@dimen/system_bar_user_icon_padding"
-                        android:contentDescription="@string/system_bar_user_avatar"
-                    />
-                    <TextView
-                        android:id="@+id/user_name_text"
-                        android:layout_width="wrap_content"
-                        android:layout_height="match_parent"
-                        android:gravity="center_vertical"
-                        android:textAppearance="@style/TextAppearance.SystemBar.Username"
-                        android:singleLine="true"
-                        android:maxWidth="@dimen/car_system_bar_user_name_max_width"
-                        android:layout_marginEnd="@dimen/system_bar_user_icon_padding"
-                        android:contentDescription="@string/system_bar_user_name_text"
-                    />
-                </LinearLayout>
-            </com.android.systemui.car.systembar.CarSystemBarButton>
-        </FrameLayout>
+            android:layout_alignParentEnd="true" />
     </RelativeLayout>
 
 </com.android.systemui.car.systembar.CarSystemBarView>
diff --git a/res/layout/car_top_system_bar_dock.xml b/res/layout/car_top_system_bar_dock.xml
index 2b49ce23..b7afa4af 100644
--- a/res/layout/car_top_system_bar_dock.xml
+++ b/res/layout/car_top_system_bar_dock.xml
@@ -65,24 +65,13 @@
         <com.android.systemui.car.systembar.CarSystemBarButton
             android:id="@+id/notifications"
             android:contentDescription="@string/system_bar_notifications_label"
-            android:layout_width="@dimen/car_quick_controls_entry_points_button_width"
+            android:layout_width="wrap_content"
             android:layout_height="match_parent"
             style="@style/TopBarButton"
             android:layout_toLeftOf="@id/camera_privacy_chip"
-            systemui:longIntent="intent:#Intent;action=com.android.car.bugreport.action.START_AUDIO_FIRST;component=com.android.car.bugreport/.BugReportActivity;end">
-            <LinearLayout
-                android:layout_width="match_parent"
-                android:layout_height="match_parent"
-                android:orientation="horizontal"
-                android:gravity="center">
-                <ImageView
-                    android:id="@+id/notification_icon"
-                    android:layout_width="wrap_content"
-                    android:layout_height="match_parent"
-                    android:src="@drawable/car_ic_notification_dock"
-                    android:tint="@color/system_bar_icon_color_with_selection" />
-            </LinearLayout>
-        </com.android.systemui.car.systembar.CarSystemBarButton>
+            systemui:highlightWhenSelected="true"
+            systemui:icon="@drawable/car_ic_notification_dock"
+            systemui:longIntent="intent:#Intent;action=com.android.car.bugreport.action.START_BUG_REPORT;end"/>
 
         <include layout="@layout/camera_privacy_chip"
             android:layout_width="wrap_content"
@@ -97,45 +86,9 @@
             android:layout_toLeftOf="@id/user_name_container"
             android:contentDescription="@string/system_bar_mic_privacy_chip" />
 
-        <FrameLayout
-            android:id="@+id/user_name_container"
+        <include layout="@layout/user_name_container"
             android:layout_width="wrap_content"
             android:layout_height="match_parent"
-            android:layout_alignParentEnd="true"
-            android:layout_centerVertical="true">
-            <com.android.systemui.car.systembar.CarSystemBarButton
-                android:id="@+id/user_name"
-                android:layout_width="wrap_content"
-                android:layout_height="match_parent"
-                style="@style/TopBarButton"
-                android:gravity="center">
-                <LinearLayout
-                    android:layout_width="match_parent"
-                    android:layout_height="match_parent"
-                    android:orientation="horizontal"
-                    android:layout_marginStart="@dimen/car_padding_2"
-                    android:layout_marginEnd="@dimen/car_padding_2"
-                    android:gravity="center_vertical">
-                    <ImageView
-                        android:id="@+id/user_avatar"
-                        android:layout_width="wrap_content"
-                        android:layout_height="match_parent"
-                        android:src="@drawable/car_ic_users_icon"
-                        android:tint="@color/system_bar_icon_color_with_selection"
-                        android:layout_marginEnd="@dimen/system_bar_user_icon_padding"
-                        android:contentDescription="@string/system_bar_user_avatar" />
-                    <TextView
-                        android:id="@+id/user_name_text"
-                        android:layout_width="wrap_content"
-                        android:layout_height="match_parent"
-                        android:gravity="center_vertical"
-                        android:textAppearance="@style/TextAppearance.SystemBar.Username"
-                        android:singleLine="true"
-                        android:maxWidth="@dimen/car_system_bar_user_name_max_width"
-                        android:layout_marginEnd="@dimen/system_bar_user_icon_padding"
-                        android:contentDescription="@string/system_bar_user_name_text" />
-                </LinearLayout>
-            </com.android.systemui.car.systembar.CarSystemBarButton>
-        </FrameLayout>
+            android:layout_alignParentEnd="true" />
     </RelativeLayout>
 </com.android.systemui.car.systembar.CarSystemBarView>
diff --git a/res/layout/car_top_system_bar_unprovisioned.xml b/res/layout/car_top_system_bar_unprovisioned.xml
index 4e1464db..728ca151 100644
--- a/res/layout/car_top_system_bar_unprovisioned.xml
+++ b/res/layout/car_top_system_bar_unprovisioned.xml
@@ -64,49 +64,10 @@
                  android:layout_centerVertical="true"
                  android:layout_toLeftOf="@id/user_name_container" />
 
-        <FrameLayout
-            android:id="@+id/user_name_container"
+        <include layout="@layout/user_name_container"
             android:layout_width="wrap_content"
             android:layout_height="match_parent"
-            android:layout_alignParentEnd="true"
-            android:layout_centerVertical="true"
-            android:layout_marginTop="@dimen/car_padding_2"
-        >
-            <com.android.systemui.car.systembar.CarSystemBarButton
-                android:id="@+id/user_name"
-                android:layout_width="wrap_content"
-                android:layout_height="match_parent"
-                android:layout_marginEnd="@dimen/car_padding_2"
-                android:background="@drawable/system_bar_background_pill"
-                android:gravity="center_vertical">
-                <LinearLayout
-                    android:layout_width="match_parent"
-                    android:layout_height="match_parent"
-                    android:orientation="horizontal"
-                    android:layout_marginStart="@dimen/car_padding_2"
-                    android:layout_marginEnd="@dimen/car_padding_2"
-                    android:gravity="center_vertical"
-                >
-                    <ImageView
-                        android:id="@+id/user_avatar"
-                        android:layout_width="wrap_content"
-                        android:layout_height="match_parent"
-                        android:src="@drawable/car_ic_users_icon"
-                        android:layout_marginEnd="@dimen/system_bar_user_icon_padding"
-                    />
-                    <TextView
-                        android:id="@+id/user_name_text"
-                        android:layout_width="wrap_content"
-                        android:layout_height="match_parent"
-                        android:gravity="center_vertical"
-                        android:textAppearance="@style/TextAppearance.SystemBar.Username"
-                        android:singleLine="true"
-                        android:maxWidth="@dimen/car_system_bar_user_name_max_width"
-                        android:layout_marginEnd="@dimen/system_bar_user_icon_padding"
-                    />
-                </LinearLayout>
-            </com.android.systemui.car.systembar.CarSystemBarButton>
-        </FrameLayout>
+            android:layout_alignParentEnd="true" />
 
     </RelativeLayout>
 </com.android.systemui.car.systembar.CarSystemBarView>
diff --git a/res/layout/car_volume_item.xml b/res/layout/car_volume_item.xml
index 1e670786..21f31bcf 100644
--- a/res/layout/car_volume_item.xml
+++ b/res/layout/car_volume_item.xml
@@ -43,14 +43,11 @@
         android:min="0"
         android:paddingBottom="@dimen/car_volume_item_seekbar_padding_vertical"
         android:layout_centerVertical="true"
-        android:paddingEnd="0dp"
-        android:paddingStart="0dp"
         android:paddingTop="@dimen/car_volume_item_seekbar_padding_vertical"
         android:splitTrack="false"
         android:layout_toStartOf="@id/supplemental_icon_divider"
         android:layout_marginStart="@dimen/car_volume_item_seekbar_margin_start"
-        android:layout_marginEnd="@dimen/car_volume_item_seekbar_margin_end"
-        android:thumbOffset="0dp"/>
+        android:layout_marginEnd="@dimen/car_volume_item_seekbar_margin_end"/>
 
     <!-- Supplemental action. -->
     <View
diff --git a/res/layout/data_subscription_popup_window.xml b/res/layout/data_subscription_popup_window.xml
index 0ede487e..7915d780 100644
--- a/res/layout/data_subscription_popup_window.xml
+++ b/res/layout/data_subscription_popup_window.xml
@@ -58,8 +58,8 @@
             android:layout_width="@dimen/data_subscription_pop_up_button_width"
             android:layout_height="@dimen/data_subscription_pop_up_button_height"
             android:layout_marginRight="@dimen/data_subscription_pop_up_horizontal_padding"
-            android:text="@string/data_subscription_button_text"/>
-
+            android:text="@string/data_subscription_button_text"
+            style="@android:style/Widget.DeviceDefault.Button.Colored"/>
     </LinearLayout>
 
 </com.android.car.ui.shortcutspopup.CarUiArrowContainerView>
diff --git a/res/layout/qc_debug_panel.xml b/res/layout/qc_debug_panel.xml
new file mode 100644
index 00000000..21e4e7c8
--- /dev/null
+++ b/res/layout/qc_debug_panel.xml
@@ -0,0 +1,66 @@
+<!--
+  ~ Copyright (C) 2024 The Android Open Source Project
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
+<FrameLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:app="http://schemas.android.com/apk/res-auto"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    android:layoutDirection="locale"
+    android:background="@color/status_icon_panel_bg_color">
+    <com.android.car.ui.FocusParkingView
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"/>
+    <com.android.car.ui.FocusArea
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        android:gravity="center"
+        android:orientation="vertical">
+        <androidx.constraintlayout.widget.ConstraintLayout
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content">
+            <ScrollView
+                android:id="@+id/debug_panel_scroll_view"
+                android:layout_width="match_parent"
+                android:layout_height="0dp"
+                android:layout_marginBottom="@dimen/car_quick_controls_footer_button_margin_top"
+                app:layout_constraintHeight_default="wrap"
+                app:layout_constraintTop_toTopOf="parent"
+                app:layout_constraintStart_toStartOf="parent"
+                app:layout_constraintEnd_toEndOf="parent"
+                app:layout_constraintBottom_toTopOf="@+id/qc_debug_footer_button">
+                <LinearLayout
+                    android:layout_width="match_parent"
+                    android:layout_height="wrap_content"
+                    android:orientation="vertical">
+                    <com.android.systemui.car.qc.SystemUIQCView
+                        android:layout_width="match_parent"
+                        android:layout_height="wrap_content"
+                        android:gravity="center"
+                        app:remoteQCProvider="content://com.android.car.settings.qc/debug_layout_bounds_toggle"/>
+                </LinearLayout>
+            </ScrollView>
+            <com.android.systemui.car.qc.QCFooterButton
+                android:id="@+id/qc_debug_footer_button"
+                app:layout_constraintTop_toBottomOf="@id/debug_panel_scroll_view"
+                app:layout_constraintBottom_toBottomOf="parent"
+                app:layout_constraintStart_toStartOf="parent"
+                app:layout_constraintEnd_toEndOf="parent"
+                style="@style/QCFooterButtonStyle"
+                android:text="@string/qc_footer_debug_settings"
+                app:intent="intent:#Intent;action=android.settings.APPLICATION_DEVELOPMENT_SETTINGS;launchFlags=0x14000000;end"/>
+        </androidx.constraintlayout.widget.ConstraintLayout>
+    </com.android.car.ui.FocusArea>
+</FrameLayout>
diff --git a/res/layout/qc_display_panel.xml b/res/layout/qc_display_panel.xml
index 2bf62fb3..6ce8938c 100644
--- a/res/layout/qc_display_panel.xml
+++ b/res/layout/qc_display_panel.xml
@@ -48,7 +48,7 @@
                         android:layout_width="match_parent"
                         android:layout_height="wrap_content"
                         android:gravity="center"
-                        app:remoteQCProvider="content://com.android.car.settings.qc/brightness_slider"/>
+                        app:remoteQCProvider="content://com.android.car.settings.qc/brightness_slider_with_icon"/>
                     <com.android.systemui.car.qc.SystemUIQCView
                         android:layout_width="match_parent"
                         android:layout_height="wrap_content"
diff --git a/res/layout/qc_status_icons_horizontal.xml b/res/layout/qc_status_icons_horizontal.xml
index afda8036..f3c9c69c 100644
--- a/res/layout/qc_status_icons_horizontal.xml
+++ b/res/layout/qc_status_icons_horizontal.xml
@@ -52,12 +52,12 @@
         systemui:disabledWhileUnprovisioned="true"
         systemui:systemBarDisable2Flags="quickSettings">
         <FrameLayout
-            android:layout_width="@dimen/car_quick_controls_icon_drawable_width"
-            android:layout_height="@dimen/car_quick_controls_icon_drawable_height">
+            android:layout_width="match_parent"
+            android:layout_height="match_parent">
             <com.android.systemui.car.statusicon.StatusIconView
                 android:id="@+id/connectivity_status_icon"
-                android:layout_width="match_parent"
-                android:layout_height="match_parent"
+                android:layout_width="@dimen/car_quick_controls_icon_drawable_width"
+                android:layout_height="@dimen/car_quick_controls_icon_drawable_height"
                 android:layout_gravity="center"
                 android:tint="@color/car_status_icon_color"
                 android:duplicateParentState="true"
@@ -85,13 +85,57 @@
         systemui:panelLayoutRes="@layout/qc_display_panel"
         systemui:disabledWhileUnprovisioned="true"
         systemui:systemBarDisable2Flags="quickSettings">
-        <com.android.systemui.car.statusicon.StatusIconView
+        <!-- Simplify by using ImageView instead of StatusIconView since this icon is not dynamic. -->
+        <ImageView
             android:id="@+id/display_status_icon"
             android:layout_width="@dimen/car_quick_controls_icon_drawable_width"
             android:layout_height="@dimen/car_quick_controls_icon_drawable_height"
             android:layout_gravity="center"
             android:tint="@color/car_status_icon_color"
             android:duplicateParentState="true"
-            systemui:controller="com.android.systemui.car.statusicon.ui.DisplayStatusIconController"/>
+            android:src="@drawable/car_ic_brightness"
+            android:contentDescription="@string/status_icon_display_status"/>
+    </com.android.systemui.car.systembar.CarSystemBarPanelButtonView>
+    <com.android.systemui.car.systembar.CarSystemBarPanelButtonView
+        android:id="@+id/volume_panel"
+        android:layout_width="@dimen/car_quick_controls_entry_points_button_width"
+        android:layout_height="match_parent"
+        android:orientation="horizontal"
+        android:gravity="center"
+        android:layout_alignParentStart="true"
+        style="@style/TopBarButton"
+        systemui:panelLayoutRes="@layout/qc_volume_panel"
+        systemui:disabledWhileUnprovisioned="true"
+        systemui:systemBarDisable2Flags="quickSettings">
+        <com.android.systemui.car.statusicon.StatusIconView
+            android:id="@+id/volume_status_icon"
+            android:layout_width="@dimen/car_quick_controls_icon_drawable_width"
+            android:layout_height="@dimen/car_quick_controls_icon_drawable_height"
+            android:layout_gravity="center"
+            android:tint="@color/car_status_icon_color"
+            android:duplicateParentState="true"
+            systemui:controller="com.android.systemui.car.statusicon.ui.MediaVolumeStatusIconController"/>
+    </com.android.systemui.car.systembar.CarSystemBarPanelButtonView>
+    <com.android.systemui.car.systembar.CarSystemBarPanelButtonView
+        android:id="@+id/debug_panel"
+        android:layout_width="@dimen/car_quick_controls_entry_points_button_width"
+        android:layout_height="match_parent"
+        android:orientation="horizontal"
+        android:gravity="center"
+        android:layout_alignParentStart="true"
+        style="@style/TopBarButton"
+        systemui:controller="com.android.systemui.car.systembar.DebugPanelButtonViewController"
+        systemui:panelLayoutRes="@layout/qc_debug_panel"
+        systemui:disabledWhileUnprovisioned="true"
+        systemui:systemBarDisable2Flags="quickSettings">
+        <ImageView
+            android:id="@+id/debug_status_icon"
+            android:layout_width="@dimen/car_quick_controls_icon_drawable_width"
+            android:layout_height="@dimen/car_quick_controls_icon_drawable_height"
+            android:layout_gravity="center"
+            android:tint="@color/car_status_icon_color"
+            android:duplicateParentState="true"
+            android:src="@drawable/car_ic_debug"
+            android:contentDescription="@string/status_icon_debug_status"/>
     </com.android.systemui.car.systembar.CarSystemBarPanelButtonView>
 </LinearLayout>
diff --git a/res/layout/qc_status_icons_vertical.xml b/res/layout/qc_status_icons_vertical.xml
index b4e3f12a..441c79da 100644
--- a/res/layout/qc_status_icons_vertical.xml
+++ b/res/layout/qc_status_icons_vertical.xml
@@ -52,12 +52,12 @@
         systemui:disabledWhileUnprovisioned="true"
         systemui:systemBarDisable2Flags="quickSettings">
         <FrameLayout
-            android:layout_width="@dimen/car_quick_controls_icon_drawable_width"
-            android:layout_height="@dimen/car_quick_controls_icon_drawable_height">
+            android:layout_width="match_parent"
+            android:layout_height="match_parent">
             <com.android.systemui.car.statusicon.StatusIconView
                 android:id="@+id/connectivity_status_icon"
-                android:layout_width="match_parent"
-                android:layout_height="match_parent"
+                android:layout_width="@dimen/car_quick_controls_icon_drawable_width"
+                android:layout_height="@dimen/car_quick_controls_icon_drawable_height"
                 android:layout_gravity="center"
                 android:tint="@color/car_status_icon_color"
                 android:duplicateParentState="true"
@@ -85,13 +85,56 @@
         systemui:panelLayoutRes="@layout/qc_display_panel"
         systemui:disabledWhileUnprovisioned="true"
         systemui:systemBarDisable2Flags="quickSettings">
-        <com.android.systemui.car.statusicon.StatusIconView
+        <ImageView
             android:id="@+id/display_status_icon"
             android:layout_width="@dimen/car_quick_controls_icon_drawable_width"
             android:layout_height="@dimen/car_quick_controls_icon_drawable_height"
             android:layout_gravity="center"
             android:tint="@color/car_status_icon_color"
             android:duplicateParentState="true"
-            systemui:controller="com.android.systemui.car.statusicon.ui.DisplayStatusIconController"/>
+            android:src="@drawable/car_ic_brightness"
+            android:contentDescription="@string/status_icon_display_status"/>
+    </com.android.systemui.car.systembar.CarSystemBarPanelButtonView>
+    <com.android.systemui.car.systembar.CarSystemBarPanelButtonView
+        android:id="@+id/volume_panel"
+        android:layout_height="@dimen/car_quick_controls_entry_points_button_width"
+        android:layout_width="match_parent"
+        android:orientation="vertical"
+        android:gravity="center"
+        android:layout_alignParentStart="true"
+        style="@style/TopBarButton"
+        systemui:panelLayoutRes="@layout/qc_volume_panel"
+        systemui:disabledWhileUnprovisioned="true"
+        systemui:systemBarDisable2Flags="quickSettings">
+        <com.android.systemui.car.statusicon.StatusIconView
+            android:id="@+id/volume_status_icon"
+            android:layout_width="@dimen/car_quick_controls_icon_drawable_width"
+            android:layout_height="@dimen/car_quick_controls_icon_drawable_height"
+            android:layout_gravity="center"
+            android:tint="@color/car_status_icon_color"
+            android:duplicateParentState="true"
+            systemui:controller="com.android.systemui.car.statusicon.ui.MediaVolumeStatusIconController"/>
+    </com.android.systemui.car.systembar.CarSystemBarPanelButtonView>
+    <com.android.systemui.car.systembar.CarSystemBarPanelButtonView
+        android:id="@+id/debug_panel"
+        android:layout_height="@dimen/car_quick_controls_entry_points_button_width"
+        android:layout_width="match_parent"
+        android:orientation="vertical"
+        android:gravity="center"
+        android:layout_alignParentStart="true"
+        style="@style/TopBarButton"
+        systemui:controller="com.android.systemui.car.systembar.DebugPanelButtonViewController"
+        systemui:panelLayoutRes="@layout/qc_debug_panel"
+        systemui:disabledWhileUnprovisioned="true"
+        systemui:systemBarDisable2Flags="quickSettings">
+        <ImageView
+            android:id="@+id/debug_status_icon"
+            android:layout_width="@dimen/car_quick_controls_icon_drawable_width"
+            android:layout_height="@dimen/car_quick_controls_icon_drawable_height"
+            android:layout_gravity="center"
+            android:tint="@color/car_status_icon_color"
+            android:duplicateParentState="true"
+            android:src="@drawable/car_ic_debug"
+            android:contentDescription="@string/status_icon_debug_status"/>
     </com.android.systemui.car.systembar.CarSystemBarPanelButtonView>
 </LinearLayout>
diff --git a/res/layout/qc_volume_panel.xml b/res/layout/qc_volume_panel.xml
new file mode 100644
index 00000000..7f944259
--- /dev/null
+++ b/res/layout/qc_volume_panel.xml
@@ -0,0 +1,81 @@
+<!--
+  ~ Copyright (C) 2024 The Android Open Source Project
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
+<FrameLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:app="http://schemas.android.com/apk/res-auto"
+    android:layout_width="match_parent"
+    android:layout_height="wrap_content"
+    android:layoutDirection="locale"
+    android:background="@color/status_icon_panel_bg_color">
+    <com.android.car.ui.FocusParkingView
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"/>
+    <com.android.car.ui.FocusArea
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        android:gravity="center"
+        android:orientation="vertical">
+        <androidx.constraintlayout.widget.ConstraintLayout
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content">
+            <ScrollView
+                android:id="@+id/sound_panel_scroll_view"
+                android:layout_width="match_parent"
+                android:layout_height="0dp"
+                android:layout_marginBottom="@dimen/car_quick_controls_footer_button_margin_top"
+                app:layout_constraintHeight_default="wrap"
+                app:layout_constraintTop_toTopOf="parent"
+                app:layout_constraintStart_toStartOf="parent"
+                app:layout_constraintEnd_toEndOf="parent"
+                app:layout_constraintBottom_toTopOf="@+id/qc_sound_footer_button">
+                <LinearLayout
+                    android:layout_width="match_parent"
+                    android:layout_height="wrap_content"
+                    android:orientation="vertical">
+                    <com.android.systemui.car.qc.SystemUIQCView
+                        android:layout_width="match_parent"
+                        android:layout_height="wrap_content"
+                        android:gravity="center"
+                        app:remoteQCProvider="content://com.android.car.settings.qc/media_audio_selector"/>
+                    <com.android.systemui.car.qc.SystemUIQCView
+                        android:layout_width="match_parent"
+                        android:layout_height="wrap_content"
+                        android:gravity="center"
+                        app:remoteQCProvider="content://com.android.car.settings.qc/media_volume_slider"/>
+                    <com.android.systemui.car.qc.SystemUIQCView
+                        android:layout_width="match_parent"
+                        android:layout_height="wrap_content"
+                        android:gravity="center"
+                        app:remoteQCProvider="content://com.android.car.settings.qc/call_volume_slider"/>
+                    <com.android.systemui.car.qc.SystemUIQCView
+                        android:layout_width="match_parent"
+                        android:layout_height="wrap_content"
+                        android:gravity="center"
+                        app:remoteQCProvider="content://com.android.car.settings.qc/navigation_volume_slider"/>
+                </LinearLayout>
+            </ScrollView>
+            <com.android.systemui.car.qc.QCFooterButton
+                android:id="@+id/qc_sound_footer_button"
+                app:layout_constraintTop_toBottomOf="@id/sound_panel_scroll_view"
+                app:layout_constraintBottom_toBottomOf="parent"
+                app:layout_constraintStart_toStartOf="parent"
+                app:layout_constraintEnd_toEndOf="parent"
+                style="@style/QCFooterButtonStyle"
+                android:text="@string/qc_footer_network_sound_settings"
+                app:intent="intent:#Intent;component=com.android.car.settings/.common.CarSettingActivities$SoundSettingsActivity;launchFlags=0x14008000;end"/>
+        </androidx.constraintlayout.widget.ConstraintLayout>
+    </com.android.car.ui.FocusArea>
+</FrameLayout>
diff --git a/res/layout/user_name_container.xml b/res/layout/user_name_container.xml
new file mode 100644
index 00000000..4a8d4d82
--- /dev/null
+++ b/res/layout/user_name_container.xml
@@ -0,0 +1,67 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2024 The Android Open Source Project
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
+  ~ limitations under the License
+  -->
+
+<FrameLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:systemui="http://schemas.android.com/apk/res-auto"
+    android:id="@+id/user_name_container"
+    android:layout_width="wrap_content"
+    android:layout_height="match_parent"
+    android:layout_centerVertical="true">
+    <com.android.systemui.car.systembar.CarSystemBarPanelButtonView
+        android:id="@+id/user_name"
+        android:layout_width="wrap_content"
+        android:layout_height="@dimen/car_system_bar_user_name_button_height"
+        android:layout_marginEnd="@dimen/car_padding_2"
+        style="@style/TopBarButton"
+        android:layout_gravity="center_vertical"
+        systemui:controller="com.android.systemui.car.systembar.UserNamePanelButtonViewController"
+        systemui:panelLayoutRes="@layout/qc_profile_switcher"
+        systemui:panelWidthRes="@dimen/car_profile_quick_controls_panel_width"
+        systemui:gravity="top|end"
+        systemui:disabledWhileUnprovisioned="true"
+        systemui:disabledWhileDriving="@bool/config_profile_panel_disabled_while_driving"
+        systemui:systemBarDisable2Flags="quickSettings">
+        <LinearLayout
+            android:layout_width="match_parent"
+            android:layout_height="match_parent"
+            android:orientation="horizontal"
+            android:layout_marginStart="@dimen/car_padding_2"
+            android:layout_marginEnd="@dimen/car_padding_2"
+            android:gravity="center_vertical">
+            <ImageView
+                android:id="@+id/user_avatar"
+                android:layout_width="wrap_content"
+                android:layout_height="match_parent"
+                android:src="@drawable/car_ic_users_icon"
+                android:tint="@color/system_bar_icon_color_with_selection"
+                android:layout_marginEnd="@dimen/system_bar_user_icon_padding"
+                android:contentDescription="@string/system_bar_user_avatar" />
+            <com.android.systemui.car.systembar.element.layout.CarSystemBarTextView
+                android:id="@+id/user_name_text"
+                android:layout_width="wrap_content"
+                android:layout_height="match_parent"
+                android:gravity="center_vertical"
+                android:textAppearance="@style/TextAppearance.SystemBar.Username"
+                android:singleLine="true"
+                android:maxWidth="@dimen/car_system_bar_user_name_max_width"
+                android:layout_marginEnd="@dimen/system_bar_user_icon_padding"
+                android:contentDescription="@string/system_bar_user_name_text"
+                systemui:controller="com.android.systemui.car.systembar.UserNameTextViewController"/>
+        </LinearLayout>
+    </com.android.systemui.car.systembar.CarSystemBarPanelButtonView>
+</FrameLayout>
diff --git a/res/layout/user_picker.xml b/res/layout/user_picker.xml
index 46467a48..73fbf0a6 100644
--- a/res/layout/user_picker.xml
+++ b/res/layout/user_picker.xml
@@ -14,7 +14,7 @@
      See the License for the specific language governing permissions and
      limitations under the License.
 -->
-<FrameLayout
+<com.android.systemui.car.userpicker.UserPickerFrameLayout
     xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:app="http://schemas.android.com/apk/res-auto"
     xmlns:systemui="http://schemas.android.com/apk/res-auto"
@@ -139,4 +139,4 @@
                 systemui:amPmStyle="gone"/>
         </androidx.constraintlayout.widget.ConstraintLayout>
     </com.android.car.ui.ConstraintFocusArea>
-</FrameLayout>
+</com.android.systemui.car.userpicker.UserPickerFrameLayout>
diff --git a/res/values-af/strings.xml b/res/values-af/strings.xml
index 028ac237..3a449fd0 100644
--- a/res/values-af/strings.xml
+++ b/res/values-af/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{Net een profiel kan geskep word.}other{Jy kan tot # profiele byvoeg.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"Laai tans"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"Laai tans gebruiker (van <xliff:g id="FROM_USER">%1$d</xliff:g> na <xliff:g id="TO_USER">%2$d</xliff:g>)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"Huidige profiel"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g> is af."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"Gebruik <xliff:g id="SENSOR">%1$s</xliff:g>"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"Vir programme wat toestemming het"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"Seininstellings: wi-fi aan"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"Seininstellings: warmkol aan"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"Vertooninstellings"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"Ontfoutinstellings"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"Klankinstellings"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"Rymodus"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"Jy kan nie hierdie kenmerk gebruik terwyl jy bestuur nie"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"Maak program toe"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Vertooninstellings"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Klankinstellings"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Profiel- en rekeninginstellings"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Ontwikkelaaropsies"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"Patroon steun nie rotasie nie; gebruik raak"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"Jou skerm is gesluit"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"Jou skerm is gesluit"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"Kan nie besoekerprofiel begin nie. Probeer later weer."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"Meld tans af …"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> word tans afgemeld. Probeer later weer."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Gebruiker is nie tans beskikbaar nie"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Kan nie veilige gebruiker op passasierskerm begin nie"</string>
     <string name="seat_driver" msgid="4502591979520445677">"bestuurder"</string>
     <string name="seat_front" msgid="836133281052793377">"voor"</string>
     <string name="seat_rear" msgid="403133444964528577">"agter"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"Volskerm"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Sien pakkette"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Jou internetpakket het verval"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"Hierdie app benodig ’n internetverbinding"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s het ’n internetverbinding nodig"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Hierdie app"</string>
 </resources>
diff --git a/res/values-am/strings.xml b/res/values-am/strings.xml
index 692421b1..e8a472ff 100644
--- a/res/values-am/strings.xml
+++ b/res/values-am/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{አንድ መገለጫ ብቻ ነው ሊፈጠር የሚችለው።}one{እስከ # መገለጫዎች ድረስ ማከል ይችላሉ።}other{እስከ # መገለጫዎች ድረስ ማከል ይችላሉ።}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"በመጫን ላይ"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"ተጠቃሚን (ከ<xliff:g id="FROM_USER">%1$d</xliff:g> ወደ <xliff:g id="TO_USER">%2$d</xliff:g>) በመጫን ላይ"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"የአሁን መገለጫ"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g> ጠፍቷል።"</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"<xliff:g id="SENSOR">%1$s</xliff:g>ን ይጠቀሙ"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"ፈቃድ ላላቸው መተግበሪያዎች"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"የሲግናል ቅንብሮች፦ Wi-Fi በርቷል"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"የሲግናል ቅንብሮች፦ መገናኛ ነጥብ በርቷል"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"የማሳያ ቅንብሮች"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"የስህተት አርም ቅንብሮች"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"የድምፅ ቅንብሮች"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"የማሽከርከር ሁነታ"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"እየነዱ ሳለ ይህን ባህሪ መጠቀም አይችሉም"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"መተግበሪያን ዝጋ"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"የማሳያ ቅንብሮች"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"የድምፅ ቅንብሮች"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"የመገለጫዎች እና የመለያዎች ቅንብሮች"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"የገንቢ አማራጮች"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"ሥርዓተ ጥለት መሽከርከርን አይደግፍም፤ እባክዎ ንካን ይጠቀሙ"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"ማያ ገጽዎ አሁን ተቆልፏል"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"ማያ ገጽዎ ተቆልፏል"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"የእንግዳ መገለጫን መጀመር አልተቻለም። ቆይተው እንደገና ይሞክሩ።"</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"ዘግቶ በመውጣት ላይ…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> ዘግተው እንዲውጡ እየተደረገ ነው። ቆይተው እንደገና ይሞክሩ።"</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"ተጠቃሚ በአሁኑ ጊዜ አይገኙም"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"በመንገደኛ ማሳያ ላይ ደህንነታቸው የተጠበቀ ተጠቃሚን ማስጀመር አልተቻለም"</string>
     <string name="seat_driver" msgid="4502591979520445677">"ነጂ"</string>
     <string name="seat_front" msgid="836133281052793377">"የፊት"</string>
     <string name="seat_rear" msgid="403133444964528577">"የኋላ"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"ሙሉ ገፅ ዕይታ"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"ዕቅዶችን አሳይ"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"የበይነመረብ ዕቅድዎ ጊዜው አልፎበታል"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"ይህ መተግበሪያ የበይነመረብ ግንኙነት ያስፈልገዋል"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s የበይነመረብ ግንኙነት ያስፈልገዋል"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"ይህ መተግበሪያ"</string>
 </resources>
diff --git a/res/values-ar/strings.xml b/res/values-ar/strings.xml
index 8b238ac7..a6a02587 100644
--- a/res/values-ar/strings.xml
+++ b/res/values-ar/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{يمكنك إنشاء ملف شخصي واحد فقط.}zero{يمكنك إضافة # ملف شخصي كحد أقصى.}two{يمكنك إضافة ملفين شخصيين كحد أقصى.}few{يمكنك إضافة # ملفات شخصية كحد أقصى.}many{يمكنك إضافة # ملفًا شخصيًا كحد أقصى.}other{يمكنك إضافة # ملف شخصي كحد أقصى.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"جارٍ التحميل"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"جارٍ تحميل الملف الشخصي الجديد للمستخدم (من <xliff:g id="FROM_USER">%1$d</xliff:g> إلى <xliff:g id="TO_USER">%2$d</xliff:g>)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"الملف الشخصي الحالي"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"تم إيقاف ميزة <xliff:g id="SENSOR">%1$s</xliff:g>."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"استخدام <xliff:g id="SENSOR">%1$s</xliff:g>"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"للتطبيقات التي حصلت على الإذن"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"إعدادات الإشارة: تفعيل Wifi"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"إعدادات الإشارة: تفعيل نقطة الاتصال"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"إعدادات الشاشة"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"إعدادات تصحيح الأخطاء"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"إعدادات الصوت"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"وضع القيادة"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"لا يمكنك استخدام هذه الميزة أثناء القيادة."</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"إغلاق التطبيق"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"إعدادات الشاشة"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"إعدادات الصوت"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"إعدادات الملفات الشخصية والحسابات"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"خيارات المطوّرين"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"لا يدعم النقش الإدخال عبر وحدة تحكّم دورانية، يُرجى استخدام وحدة تحكّم باللمس."</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"تم قفل شاشتك."</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"تم قفل شاشتك."</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"يتعذّر بدء استخدام الملف الشخصي للضيف. يُرجى إعادة المحاولة لاحقًا."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"جارٍ تسجيل الخروج…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"يتم الآن تسجيل خروج \"<xliff:g id="USER_NAME">%s</xliff:g>\". يُرجى إعادة المحاولة لاحقًا."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"المستخدم غير متاح حاليًا"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"يتعذّر بدء تشغيل مستخدم آمن على شاشة الراكب"</string>
     <string name="seat_driver" msgid="4502591979520445677">"السائق"</string>
     <string name="seat_front" msgid="836133281052793377">"المقعد الأمامي"</string>
     <string name="seat_rear" msgid="403133444964528577">"المقعد الخلفي"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"ملء الشاشة"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"الاطّلاع على الخطط"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"انتهت صلاحية خطط الإنترنت الخاصة بك"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"يحتاج هذا التطبيق إلى اتصال بالإنترنت"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"يحتاج %s إلى الاتصال بالإنترنت"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"هذا التطبيق"</string>
 </resources>
diff --git a/res/values-as/strings.xml b/res/values-as/strings.xml
index 9afbd001..3c1b13d8 100644
--- a/res/values-as/strings.xml
+++ b/res/values-as/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{কেৱল এটা প্ৰ’ফাইল সৃষ্টি কৰিব পাৰি।}one{আপুনি # টা পর্যন্ত প্ৰ’ফাইল যোগ দিব পাৰে।}other{আপুনি # টা পর্যন্ত প্ৰ’ফাইল যোগ দিব পাৰে।}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"ল’ড হৈ আছে"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"ব্যৱহাৰকাৰী ল’ড হৈ আছে (<xliff:g id="FROM_USER">%1$d</xliff:g>ৰ পৰা to <xliff:g id="TO_USER">%2$d</xliff:g>লৈ)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"বৰ্তমানৰ প্ৰ’ফাইল"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g> অফ কৰা আছে।"</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"<xliff:g id="SENSOR">%1$s</xliff:g> ব্যৱহাৰ কৰক"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"অনুমতি থকা এপৰ বাবে"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"ছিগনেলৰ ছেটিং: ৱাই-ফাই অন আছে"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"ছিগনেলৰ ছেটিং: হ’টস্প’ট অন আছে"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"ডিছপ্লে’ৰ ছেটিং"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"ডিবাগৰ ছেটিং"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"ধ্বনিৰ ছেটিং"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"ড্ৰাইভ ম’ড"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"আপুনি গাড়ী চলাই থকাৰ সময়ত এই সুবিধাটো ব্যৱহাৰ কৰিব নোৱাৰে"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"এপ্‌টো বন্ধ কৰক"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"ডিছপ্লে’ ছেটিং"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"ধ্বনিৰ ছেটিং"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"প্ৰ’ফাইল আৰু একাউণ্ট ছেটিং"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"বিকাশকৰ্তাৰ বিকল্পসমূহ"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"আৰ্হিটোৱে ৰ’টেৰী সমৰ্থন কৰে; স্পৰ্শ কৰাটো ব্যৱহাৰ কৰক"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"আপোনাৰ স্ক্ৰীন লক কৰা আছে"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"আপোনাৰ স্ক্ৰীন লক কৰা হৈছে"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"অতিথিৰ প্ৰ’ফাইল আৰম্ভ কৰিব নোৱাৰি। পাছত পুনৰ চেষ্টা কৰক।"</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"ছাইন আউট কৰি থকা হৈছে…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g>ক ছাইন আউট কৰাই থকা হৈছে। পাছত পুনৰ চেষ্টা কৰক।"</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"ব্যৱহাৰকাৰী বৰ্তমান উপলব্ধ নহয়"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"যাত্ৰীৰ ডিছপ্লে’ত ব্যৱহাৰকাৰী সুৰক্ষিত কৰক আৰম্ভ কৰিব পৰা নগ’ল"</string>
     <string name="seat_driver" msgid="4502591979520445677">"চালকৰ আসন"</string>
     <string name="seat_front" msgid="836133281052793377">"সন্মুখৰ আসন"</string>
     <string name="seat_rear" msgid="403133444964528577">"পিছফালৰ আসন"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"পূৰ্ণ স্ক্ৰীন"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"আঁচনি চাওক"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"আপোনাৰ ইণ্টাৰনেটৰ আঁচনিৰ ম্যাদ উকলিছে"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"এই এপ্‌টোক ইণ্টাৰনেট সংযোগৰ আৱশ্যক"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%sক ইণ্টাৰনেট সংযোগৰ আৱশ্যক"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"এইটো এপ্‌"</string>
 </resources>
diff --git a/res/values-az/strings.xml b/res/values-az/strings.xml
index 84806d48..799dc65a 100644
--- a/res/values-az/strings.xml
+++ b/res/values-az/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{Yalnız bir profil yaradıla bilər.}other{Maksimum # profil əlavə edə bilərsiniz.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"Yüklənir"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"İstifadəçi yüklənir (<xliff:g id="FROM_USER">%1$d</xliff:g>-<xliff:g id="TO_USER">%2$d</xliff:g>)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"Cari profil"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g> deaktivdir."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"<xliff:g id="SENSOR">%1$s</xliff:g> istifadə edin"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"İcazəsi olan tətbiqlər üçün"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"Siqnal Ayarları: Wifi Aktivdir"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"Siqnal Ayarları: Hotspot Aktivdir"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"Displey Ayarları"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"Debaq Ayarları"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"Səs Ayarları"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"Sürmə Rejimi"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"Avtomobil sürərkən bu funksiyanı istifadə edə bilməzsiniz"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"Tətbiqi qapadın"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Displey ayarları"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Səs ayarları"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Profillər və hesab ayarları"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Developer seçimləri"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"Model fırlanmanı dəstəkləmir; toxunuşdan istifadə edin"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"Ekran kilidlənib"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"Ekran kilidlənib"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"Qonaq profili yaratmaq olmur. Sonra cəhd edin."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"Çıxış edilir…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> çıxır. Sonra cəhd edin."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"İstifadəçi hazırda əlçatan deyil"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Sərnişin ekranında təhlükəsiz istifadəçi seçimini işə salmaq olmur"</string>
     <string name="seat_driver" msgid="4502591979520445677">"sürücü"</string>
     <string name="seat_front" msgid="836133281052793377">"ön"</string>
     <string name="seat_rear" msgid="403133444964528577">"arxa"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"Tam ekran"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Planlara baxın"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"İnternet planının vaxtı keçib"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"Bu tətbiq internet bağlantısı tələb edir"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s internet bağlantısı tələb edir"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Bu tətbiq"</string>
 </resources>
diff --git a/res/values-b+sr+Latn/strings.xml b/res/values-b+sr+Latn/strings.xml
index cb3770a2..70d90d77 100644
--- a/res/values-b+sr+Latn/strings.xml
+++ b/res/values-b+sr+Latn/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{Možete da napravite samo jedan profil.}one{Možete da dodate najviše # profil.}few{Možete da dodate najviše # profila.}other{Možete da dodate najviše # profila.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"Učitava se"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"Profil korisnika se učitava (iz<xliff:g id="FROM_USER">%1$d</xliff:g> u <xliff:g id="TO_USER">%2$d</xliff:g>)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"Aktuelni profil"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"Senzor <xliff:g id="SENSOR">%1$s</xliff:g> je isključen."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"Koristi: <xliff:g id="SENSOR">%1$s</xliff:g>"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"Za aplikacije koje imaju dozvolu"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"Podešavanja signala: WiFi je isključen"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"Podešavanja signala: hotspot je uključen"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"Podešavanja ekrana"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"Podešavanja otklanjanja grešaka"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"Podešavanja zvuka"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"Režim vožnje"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"Ne možete da koristite ovu funkciju dok vozite"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"Zatvori aplikaciju"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Podešavanja ekrana"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Podešavanja zvuka"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Podešavanja profila i naloga"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Opcije za programera"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"Šablon ne dopušta kružne pokrete; koristite dodir"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"Ekran je zaključan"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"Ekran je zaključan"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"Ne možete da pokrenete profil gosta. Probajte ponovo kasnije."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"Odjavljujete se…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> se odjavljuje. Probajte ponovo kasnije."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Korisnik trenutno nije dostupan"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Nije moguće pokrenuti bezbednog korisnika na ekranu putnika"</string>
     <string name="seat_driver" msgid="4502591979520445677">"vozač"</string>
     <string name="seat_front" msgid="836133281052793377">"prednje"</string>
     <string name="seat_rear" msgid="403133444964528577">"zadnje"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"Ceo ekran"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Prikaži pakete"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Internet paket je istekao"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"Za ovu aplikaciju je potrebna internet veza"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s zahteva internet vezu"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Ova aplikacija"</string>
 </resources>
diff --git a/res/values-be/strings.xml b/res/values-be/strings.xml
index 81071e36..c463f82f 100644
--- a/res/values-be/strings.xml
+++ b/res/values-be/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{Можна стварыць толькі адзін профіль.}one{Можна дадаць максімум # профіль.}few{Можна дадаць максімум # профілі.}many{Можна дадаць максімум # профіляў.}other{Можна дадаць максімум # профілю.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"Ідзе загрузка"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"Ідзе загрузка профілю карыстальніка (ад <xliff:g id="FROM_USER">%1$d</xliff:g> да <xliff:g id="TO_USER">%2$d</xliff:g>)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"Бягучы профіль"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g>: выключана."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"Выкарыстоўваць гэта: <xliff:g id="SENSOR">%1$s</xliff:g>"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"Для праграм, якія маюць дазвол"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"Налады сігналу: Wi-Fi уключаны"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"Налады сігналу: хот-спот уключаны"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"Налады экрана"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"Налады адладкі"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"Налады гуку"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"Рэжым кіравання"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"Вам нельга выкарыстоўваць гэту функцыю, калі вы ведзяце аўтамабіль"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"Закрыць праграму"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Налады экрана"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Налады гуку"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Налады ўліковых запісаў і профіляў"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Параметры распрацоўшчыка"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"Паваротны рэгулятар не падтрымліваецца, выкарыстайце сэнсарны ўвод"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"Экран заблакіраваны"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"Экран заблакіраваны"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"Не ўдаецца стварыць гасцявы профіль. Паўтарыце спробу пазней."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"Ажыццяўляецца выхад…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> выходзіць з уліковага запісу. Паўтарыце спробу пазней."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Карыстальнік недаступны"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Не ўдалося ўключыць абаронены профіль карыстальніка на дысплэі пасажыра"</string>
     <string name="seat_driver" msgid="4502591979520445677">"на месцы вадзіцеля"</string>
     <string name="seat_front" msgid="836133281052793377">"на пярэднім сядзенні"</string>
     <string name="seat_rear" msgid="403133444964528577">"на заднім сядзенні"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"Поўнаэкранны рэжым"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Паглядзець тарыфныя планы"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Тэрмін дзеяння вашага інтэрнэт-плана скончыўся"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"Гэтай праграме патрабуецца падключэнне да інтэрнэту"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s патрабуе падключэння да інтэрнэту"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Гэта праграма"</string>
 </resources>
diff --git a/res/values-bg/strings.xml b/res/values-bg/strings.xml
index 646bc125..5f6a47e1 100644
--- a/res/values-bg/strings.xml
+++ b/res/values-bg/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{Може да бъде създаден само един потребителски профил.}other{Можете да добавите до # потребителски профила.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"Зарежда се"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"Потребителят се зарежда (от <xliff:g id="FROM_USER">%1$d</xliff:g> до <xliff:g id="TO_USER">%2$d</xliff:g>)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"Текущ потр. профил"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g> е изкл."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"Използване на <xliff:g id="SENSOR">%1$s</xliff:g>"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"За приложения, които имат разрешение"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"Настройки за сигнала: Wi-Fi е вкл."</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"Настройки за сигнала: Точката за достъп е вкл."</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"Настройки за дисплея"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"Настройки за отстраняване на грешки"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"Настройки за звука"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"Режим за шофиране"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"Не можете да използвате тази функция по време на шофиране"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"Затваряне на прилож."</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Настройки за дисплея"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Настройки за звука"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Настройки за потр. профили и профилите"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Опции за програмисти"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"Фигурата не поддържа ротация. Моля, докоснете"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"Екранът ви е заключен"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"Екранът ви е заключен"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"Потребителският профил на гост не може да се стартира. Опитайте отново по-късно."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"Излизате от профила си…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> излиза от профила си. Опитайте отново по-късно."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Понастоящем потребителят не е налице"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"На екрана на пътника не може да се стартира надежден потребител"</string>
     <string name="seat_driver" msgid="4502591979520445677">"шофьорска"</string>
     <string name="seat_front" msgid="836133281052793377">"предна"</string>
     <string name="seat_rear" msgid="403133444964528577">"задна"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"Цял екран"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Вижте плановете"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Планът ви за интернет е изтекъл"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"За това приложение е необходима връзка с интернет"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s се нуждае от връзка с интернет"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Това приложение"</string>
 </resources>
diff --git a/res/values-bn/strings.xml b/res/values-bn/strings.xml
index 94a1c7a2..27955b9c 100644
--- a/res/values-bn/strings.xml
+++ b/res/values-bn/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{শুধুমাত্র একটি প্রোফাইল তৈরি করা যাবে।}one{আপনি সর্বাধিক #টি প্রোফাইল যোগ করতে পারবেন।}other{আপনি সর্বাধিক #টি প্রোফাইল যোগ করতে পারবেন।}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"লোড হচ্ছে"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"ব্যবহারকারীর প্রোফাইল লোড করা হচ্ছে (<xliff:g id="FROM_USER">%1$d</xliff:g> থেকে <xliff:g id="TO_USER">%2$d</xliff:g>-এ)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"বর্তমান প্রোফাইল"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g> বন্ধ আছে।"</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"<xliff:g id="SENSOR">%1$s</xliff:g> ব্যবহার করুন"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"যেসব অ্যাপের অনুমতি আছে"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"সিগন্যাল সেটিংস: ওয়াই-ফাই চালু আছে"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"সিগন্যাল সেটিংস: হটস্পট চালু আছে"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"ডিসপ্লে সেটিংস"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"ডিবাগ সেটিংস"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"সাউন্ড সেটিংস"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"ড্রাইভিং মোড"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"ড্রাইভ করার সময় আপনি এই ফিচারটি ব্যবহার করতে পারবেন না"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"অ্যাপ বন্ধ করুন"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"ডিসপ্লে সেটিংস"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"সাউন্ড সেটিংস"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"প্রোফাইল ও অ্যাকাউন্ট সেটিংস"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"ডেভেলপার বিকল্প"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"প্যাটার্নে রোটারি ব্যবহার করা যাবে না; টাচ ফিচার ব্যবহার করুন"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"আপনার স্ক্রিন লক করা আছে"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"আপনার স্ক্রিন লক করা হয়েছে"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"অতিথি প্রোফাইল চালু করা যাচ্ছে না। পরে আবার চেষ্টা করুন।"</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"সাইন-আউট করা হচ্ছে…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> সাইন-আউট করছেন। পরে আবার চেষ্টা করুন।"</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"বর্তমান ব্যবহারকারীর উপলভ্য নেই"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"যাত্রীর ডিসপ্লেতে ব্যবহারকারীর সুরক্ষিত প্রোফাইল চালু করা যায়নি"</string>
     <string name="seat_driver" msgid="4502591979520445677">"ড্রাইভার"</string>
     <string name="seat_front" msgid="836133281052793377">"সামনের দিক"</string>
     <string name="seat_rear" msgid="403133444964528577">"পিছন দিক"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"ফুল-স্ক্রিন"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"প্ল্যান দেখুন"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"আপনার ইন্টারনেট প্ল্যানের মেয়াদ শেষ হয়ে গেছে"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"এই অ্যাপ ব্যবহার করার জন্য ইন্টারনেট কানেকশন থাকতে হবে।"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s-এর ক্ষেত্রে ইন্টারনেট কানেকশন প্রয়োজন"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"এই অ্যাপ"</string>
 </resources>
diff --git a/res/values-bs/strings.xml b/res/values-bs/strings.xml
index 3f170e55..e1b6bd13 100644
--- a/res/values-bs/strings.xml
+++ b/res/values-bs/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{Možete kreirati samo jedan profil.}one{Možete dodati najviše # profil.}few{Možete dodati najviše # profila.}other{Možete dodati najviše # profila.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"Učitavanje"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"Učitavanje korisnika (od korisnika <xliff:g id="FROM_USER">%1$d</xliff:g> do korisnika <xliff:g id="TO_USER">%2$d</xliff:g>)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"Trenutni profil"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"Senzor <xliff:g id="SENSOR">%1$s</xliff:g> isključen."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"Koristite senzor <xliff:g id="SENSOR">%1$s</xliff:g>"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"Za aplikacije koje imaju odobrenje"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"Postavke signala: Wifi je uključen"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"Postavke signala: pristupna tačka je uključena"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"Postavke ekrana"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"Postavke otklanjanja grešaka"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"Postavke zvuka"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"Način rada za vožnju"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"Ne možete koristiti ovu funkciju tokom vožnje"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"Zatvori aplikaciju"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Postavke ekrana"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Postavke zvuka"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Postavke profila i računa"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Opcije za programere"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"Uzorak ne podržava brojčanik. Koristite dodir"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"Ekran je sada zaključan"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"Ekran je zaključan"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"Nije moguće pokrenuti Profil gosta. Pokušajte ponovo kasnije."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"Odjavljivanje…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> se odjavljuje. Pokušajte ponovo kasnije."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Korisnik trenutno nije dostupan"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Nije moguće pokrenuti sigurni profil korisnika na ekranu putnika"</string>
     <string name="seat_driver" msgid="4502591979520445677">"vozačevom"</string>
     <string name="seat_front" msgid="836133281052793377">"prednjem"</string>
     <string name="seat_rear" msgid="403133444964528577">"stražnjem"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"Prikaži preko cijelog ekrana"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Pogledajte pakete"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Internetski paket je istekao"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"Za aplikaciju je potrebna internetska veza"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s treba internetsku vezu"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Ova aplikacija"</string>
 </resources>
diff --git a/res/values-ca/strings.xml b/res/values-ca/strings.xml
index 52066ac6..22f21268 100644
--- a/res/values-ca/strings.xml
+++ b/res/values-ca/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{Només es pot crear 1 perfil.}other{Pots afegir fins a # perfils.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"S\'està carregant"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"S\'està carregant l\'usuari (de <xliff:g id="FROM_USER">%1$d</xliff:g> a <xliff:g id="TO_USER">%2$d</xliff:g>)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"Perfil actual"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g>: s\'ha desactivat."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"Utilitza <xliff:g id="SENSOR">%1$s</xliff:g>"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"Per a les aplicacions que tinguin permís"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"Configuració del senyal: Wi‑Fi activada"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"Configuració del senyal: punt d\'accés Wi‑Fi activat"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"Configuració de la pantalla"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"Configuració de depuració"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"Configuració del so"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"Mode de conducció"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"No pots fer servir aquesta funció mentre condueixes"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"Tanca l\'aplicació"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Configuració de la pantalla"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Configuració del so"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Configuració dels perfils i els comptes"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Opcions per a desenvolupadors"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"Patró de rotació no admès; utilitza un tàctil"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"La pantalla està bloquejada"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"La pantalla s\'ha bloquejat"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"No es pot iniciar un perfil de convidat. Torna-ho a provar més tard."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"S\'està tancant la sessió…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"S\'està tancant la sessió de: <xliff:g id="USER_NAME">%s</xliff:g>. Torna-ho a provar més tard."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Actualment l\'usuari no està disponible"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"No es pot iniciar el mode d\'usuari segur a la pantalla del passatger"</string>
     <string name="seat_driver" msgid="4502591979520445677">"del conductor"</string>
     <string name="seat_front" msgid="836133281052793377">"davanter"</string>
     <string name="seat_rear" msgid="403133444964528577">"posterior"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"Pantalla completa"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Mostra els plans"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"El teu pla d\'Internet ha caducat"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"Aquesta aplicació necessita connexió a Internet"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s necessita connexió a Internet"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Aquesta aplicació"</string>
 </resources>
diff --git a/res/values-cs/strings.xml b/res/values-cs/strings.xml
index f86c613a..9a116e1f 100644
--- a/res/values-cs/strings.xml
+++ b/res/values-cs/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{Můžete vytvořit jen jeden profil.}few{Můžete přidat až # profily.}many{Můžete přidat až # profilu.}other{Můžete přidat až # profilů.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"Načítání"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"Načítání uživatele (předchozí: <xliff:g id="FROM_USER">%1$d</xliff:g>, následující: <xliff:g id="TO_USER">%2$d</xliff:g>)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"Aktuální profil"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g> – vypnuto."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"Použít <xliff:g id="SENSOR">%1$s</xliff:g>"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"Aplikace s oprávněním"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"Nastavení signálu: je zapnutá Wi-Fi"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"Nastavení signálu: je zapnutý hotspot"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"Nastavení displeje"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"Nastavení ladění"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"Nastavení zvuku"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"Režim jízdy autem"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"Tuto funkci nelze používat při řízení"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"Zavřít aplikaci"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Nastavení displeje"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Nastavení zvuku"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Nastavení profilů a účtů"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Pro vývojáře"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"Nelze použít otáčivý vstup, použijte dotykový"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"Obrazkova je zamknuta"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"Obrazovka byla uzamknuta"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"Profil hosta se nepodařilo spustit. Zkuste to později."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"Odhlašování…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"Uživatel <xliff:g id="USER_NAME">%s</xliff:g> je odhlašován. Zkuste to později."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Uživatel teď není k dispozici"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Na displeji pasažéra se nepodařilo spustit bezpečného uživatele"</string>
     <string name="seat_driver" msgid="4502591979520445677">"řidiče"</string>
     <string name="seat_front" msgid="836133281052793377">"vpředu"</string>
     <string name="seat_rear" msgid="403133444964528577">"vzadu"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"Celá obrazovka"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Zobrazit tarify"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Vašemu internetovému tarifu vypršela platnost"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"Tahle aplikace vyžaduje připojení k internetu"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s potřebuje připojení k internetu"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Tato aplikace"</string>
 </resources>
diff --git a/res/values-da/strings.xml b/res/values-da/strings.xml
index ef299a77..db6503f8 100644
--- a/res/values-da/strings.xml
+++ b/res/values-da/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{Der kan kun oprettes én profil.}one{Du kan kun tilføje # profil.}other{Du kan kun tilføje # profiler.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"Indlæser"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"Indlæser bruger (fra <xliff:g id="FROM_USER">%1$d</xliff:g> til <xliff:g id="TO_USER">%2$d</xliff:g>)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"Aktuel profil"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g> er deaktiveret."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"Brug <xliff:g id="SENSOR">%1$s</xliff:g>"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"For apps, der har tilladelse"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"Signalindstillinger: Wi-Fi er aktiveret"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"Signalindstillinger: Hotspot er aktiveret"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"Skærmindstillinger"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"Indstillinger for fejlretning"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"Lydindstillinger"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"Køretilstand"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"Du kan ikke bruge denne funktion, mens du kører"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"Luk app"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Skærmindstillinger"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Lydindstillinger"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Indstillinger for profiler og konti"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Indstillinger for udviklere"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"Mønster understøtter ikke drejeinput – brug berøring"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"Din skærm er låst"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"Skærmen er blevet låst"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"Gæsteprofil kan ikke oprettes. Prøv igen senere."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"Logger ud…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> logges ud. Prøv igen senere."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Brugeren er ikke tilgængelig i øjeblikket"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Den sikre bruger kan ikke tilgå passagerskærmen"</string>
     <string name="seat_driver" msgid="4502591979520445677">"chauffør"</string>
     <string name="seat_front" msgid="836133281052793377">"forside"</string>
     <string name="seat_rear" msgid="403133444964528577">"bagside"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"Fuld skærm"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Se abonnementer"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Dit internetabonnement er udløbet"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"Denne app skal have forbindelse til internettet"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s kræver en internetforbindelse"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Denne app"</string>
 </resources>
diff --git a/res/values-de/strings.xml b/res/values-de/strings.xml
index 5b74d472..82d63f9a 100644
--- a/res/values-de/strings.xml
+++ b/res/values-de/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{Du kannst maximal ein Profil erstellen.}other{Du kannst maximal # Profile hinzufügen.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"Wird geladen"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"Nutzer wird geladen (von <xliff:g id="FROM_USER">%1$d</xliff:g> bis <xliff:g id="TO_USER">%2$d</xliff:g>)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"Aktuelles Profil"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g> ist deaktiviert."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"<xliff:g id="SENSOR">%1$s</xliff:g> verwenden"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"Für Apps mit Berechtigung"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"Signaleinstellungen: WLAN an"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"Signaleinstellungen: Hotspot aktiviert"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"Displayeinstellungen"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"Einstellungen für die Fehlerbehebung"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"Toneinstellungen"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"Fahrmodus"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"Du kannst diese Funktion nicht während der Fahrt nutzen"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"App schließen"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Displayeinstellungen"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Toneinstellungen"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Profil- &amp; Kontoeinstellungen"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Entwickleroptionen"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"Dreheingabe nicht möglich, Touch nutzen"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"Dein Bildschirm ist gesperrt"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"Dein Display wurde gesperrt"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"Es konnte kein Gastprofil gestartet werden. Bitte versuche es später noch einmal."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"Abmeldung erfolgt…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> wird abgemeldet. Bitte versuche es später noch einmal."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Nutzer derzeit nicht verfügbar"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"„Geschützter Nutzer“ kann auf dem Display des Beifahrers nicht gestartet werden"</string>
     <string name="seat_driver" msgid="4502591979520445677">"Fahrer"</string>
     <string name="seat_front" msgid="836133281052793377">"vorne"</string>
     <string name="seat_rear" msgid="403133444964528577">"hinten"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"Vollbild"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Tarife ansehen"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Dein Internettarif ist abgelaufen"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"Für diese App ist eine Internetverbindung erforderlich"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s benötigt eine Internetverbindung"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Diese App"</string>
 </resources>
diff --git a/res/values-el/strings.xml b/res/values-el/strings.xml
index 4bdaa7b8..ef3dd86f 100644
--- a/res/values-el/strings.xml
+++ b/res/values-el/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{Είναι δυνατή η δημιουργία μόνο ενός προφίλ.}other{Μπορείτε να προσθέσετε έως # προφίλ.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"Φόρτωση"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"Φόρτωση χρήστη (από <xliff:g id="FROM_USER">%1$d</xliff:g> έως <xliff:g id="TO_USER">%2$d</xliff:g>)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"Τρέχον προφίλ"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"Το <xliff:g id="SENSOR">%1$s</xliff:g> είναι ανενεργό."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"Χρήση <xliff:g id="SENSOR">%1$s</xliff:g>"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"Για εφαρμογές που έχουν άδεια"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"Ρυθμίσεις σήματος: Wi-Fi ενεργό"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"Ρυθμίσεις σήματος: Σημείο πρόσβασης Wi-Fi ενεργό"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"Ρυθμίσεις οθόνης"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"Ρυθμίσεις εντοπισμού σφαλμάτων"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"Ρυθμίσεις ήχου"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"Λειτουργία οδήγησης"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"Δεν μπορείτε να χρησιμοποιείτε αυτήν τη λειτουργία κατά την οδήγηση."</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"Κλείσιμο εφαρμογής"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Ρυθμίσεις προβολής"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Ρυθμίσεις ήχου"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Ρυθμίσεις λογαριασμών και προφίλ"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Επιλογές για προγραμματιστές"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"Το μοτίβο δεν υποστ. περιστρ. Χρησ. αφή"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"Η οθόνη σας είναι κλειδωμένη"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"Η οθόνη σας κλειδώθηκε"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"Δεν ήταν δυνατή η εκκίνηση του προφίλ επισκέπτη. Δοκιμάστε ξανά αργότερα."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"Πραγματοποιείται έξοδος…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"Γίνεται αποσύνδεση του χρήστη <xliff:g id="USER_NAME">%s</xliff:g>. Δοκιμάστε ξανά αργότερα."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Ο χρήστης δεν είναι διαθέσιμος προσωρινά"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Δεν είναι δυνατή η εκκίνηση του ασφαλούς χρήστη στην οθόνη επιβατών"</string>
     <string name="seat_driver" msgid="4502591979520445677">"οδηγός"</string>
     <string name="seat_front" msgid="836133281052793377">"μπροστά"</string>
     <string name="seat_rear" msgid="403133444964528577">"πίσω"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"Πλήρης οθόνη"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Δείτε τα προγράμματα"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Το πρόγραμμα δεδομένων σας στο διαδίκτυο έληξε"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"Αυτή η εφαρμογή χρειάζεται σύνδεση στο διαδίκτυο"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s χρειάζεται σύνδεση στο διαδίκτυο"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Αυτή η εφαρμογή"</string>
 </resources>
diff --git a/res/values-en-rAU/strings.xml b/res/values-en-rAU/strings.xml
index 212f2b37..a13496e6 100644
--- a/res/values-en-rAU/strings.xml
+++ b/res/values-en-rAU/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{Only one profile can be created.}other{You can add up to # profiles.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"Loading"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"Loading user (from <xliff:g id="FROM_USER">%1$d</xliff:g> to <xliff:g id="TO_USER">%2$d</xliff:g>)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"Current profile"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g> is off."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"Use <xliff:g id="SENSOR">%1$s</xliff:g>"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"For apps that have permission"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"Signal settings: Wi-Fi on"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"Signal settings: hotspot on"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"Display settings"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"Debug settings"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"Sound settings"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"Drive Mode"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"You can’t use this feature while driving"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"Close app"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Display settings"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Sound settings"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Profiles &amp; accounts settings"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Developer options"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"Pattern does not support rotary; please use touch"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"Your screen is locked"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"Your screen has been locked"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"Can’t start guest profile. Try again later."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"Signing out…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> is being signed out. Try again later."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"User currently unavailable"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Unable to start secure user on passenger display"</string>
     <string name="seat_driver" msgid="4502591979520445677">"driver"</string>
     <string name="seat_front" msgid="836133281052793377">"front"</string>
     <string name="seat_rear" msgid="403133444964528577">"rear"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"Full Screen"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"See plans"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Your Internet plan has expired"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"This app needs an Internet connection"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s needs an Internet connection"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"This app"</string>
 </resources>
diff --git a/res/values-en-rCA/strings.xml b/res/values-en-rCA/strings.xml
index 6221615b..2edb4c53 100644
--- a/res/values-en-rCA/strings.xml
+++ b/res/values-en-rCA/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{Only one profile can be created.}other{You can add up to # profiles.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"Loading"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"Loading user (from <xliff:g id="FROM_USER">%1$d</xliff:g> to <xliff:g id="TO_USER">%2$d</xliff:g>)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"Current profile"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g> is off."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"Use <xliff:g id="SENSOR">%1$s</xliff:g>"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"For apps that have permission"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"Signal Settings: Wifi On"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"Signal Settings: Hotspot On"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"Display Settings"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"Debug Settings"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"Sound Settings"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"Drive Mode"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"You can’t use this feature while driving"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"Close app"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Display settings"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Sound settings"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Profiles &amp; accounts settings"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Developer options"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"Pattern does not support rotary; please use touch"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"Your screen is locked"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"Your screen has been locked"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"Can’t start Guest profile. Try again later."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"Signing out…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> is being signed out. Try again later."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"User currently unavailable"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Unable to start secure user on passenger display"</string>
     <string name="seat_driver" msgid="4502591979520445677">"driver"</string>
     <string name="seat_front" msgid="836133281052793377">"front"</string>
     <string name="seat_rear" msgid="403133444964528577">"rear"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"Full Screen"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"See plans"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Your internet plan expired"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"This app needs an internet connection"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s needs an internet connection"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"This app"</string>
 </resources>
diff --git a/res/values-en-rGB/strings.xml b/res/values-en-rGB/strings.xml
index 212f2b37..a13496e6 100644
--- a/res/values-en-rGB/strings.xml
+++ b/res/values-en-rGB/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{Only one profile can be created.}other{You can add up to # profiles.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"Loading"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"Loading user (from <xliff:g id="FROM_USER">%1$d</xliff:g> to <xliff:g id="TO_USER">%2$d</xliff:g>)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"Current profile"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g> is off."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"Use <xliff:g id="SENSOR">%1$s</xliff:g>"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"For apps that have permission"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"Signal settings: Wi-Fi on"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"Signal settings: hotspot on"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"Display settings"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"Debug settings"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"Sound settings"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"Drive Mode"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"You can’t use this feature while driving"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"Close app"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Display settings"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Sound settings"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Profiles &amp; accounts settings"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Developer options"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"Pattern does not support rotary; please use touch"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"Your screen is locked"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"Your screen has been locked"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"Can’t start guest profile. Try again later."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"Signing out…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> is being signed out. Try again later."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"User currently unavailable"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Unable to start secure user on passenger display"</string>
     <string name="seat_driver" msgid="4502591979520445677">"driver"</string>
     <string name="seat_front" msgid="836133281052793377">"front"</string>
     <string name="seat_rear" msgid="403133444964528577">"rear"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"Full Screen"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"See plans"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Your Internet plan has expired"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"This app needs an Internet connection"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s needs an Internet connection"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"This app"</string>
 </resources>
diff --git a/res/values-en-rIN/strings.xml b/res/values-en-rIN/strings.xml
index 212f2b37..a13496e6 100644
--- a/res/values-en-rIN/strings.xml
+++ b/res/values-en-rIN/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{Only one profile can be created.}other{You can add up to # profiles.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"Loading"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"Loading user (from <xliff:g id="FROM_USER">%1$d</xliff:g> to <xliff:g id="TO_USER">%2$d</xliff:g>)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"Current profile"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g> is off."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"Use <xliff:g id="SENSOR">%1$s</xliff:g>"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"For apps that have permission"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"Signal settings: Wi-Fi on"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"Signal settings: hotspot on"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"Display settings"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"Debug settings"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"Sound settings"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"Drive Mode"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"You can’t use this feature while driving"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"Close app"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Display settings"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Sound settings"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Profiles &amp; accounts settings"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Developer options"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"Pattern does not support rotary; please use touch"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"Your screen is locked"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"Your screen has been locked"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"Can’t start guest profile. Try again later."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"Signing out…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> is being signed out. Try again later."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"User currently unavailable"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Unable to start secure user on passenger display"</string>
     <string name="seat_driver" msgid="4502591979520445677">"driver"</string>
     <string name="seat_front" msgid="836133281052793377">"front"</string>
     <string name="seat_rear" msgid="403133444964528577">"rear"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"Full Screen"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"See plans"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Your Internet plan has expired"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"This app needs an Internet connection"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s needs an Internet connection"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"This app"</string>
 </resources>
diff --git a/res/values-en-rXC/strings.xml b/res/values-en-rXC/strings.xml
index 00f82336..0d8540fa 100644
--- a/res/values-en-rXC/strings.xml
+++ b/res/values-en-rXC/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‎‏‏‎‏‎‏‎‏‎‎‏‎‏‏‎‎‏‎‏‏‎‏‎‎‎‎‎‎‏‎‎‎‎‎‎‏‎‏‎‏‏‎‏‎‏‎‏‎‎‏‎‎‎‏‏‏‎‏‏‏‏‎‎Only one profile can be created.‎‏‎‎‏‎}other{‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‎‏‏‎‏‎‏‎‏‎‎‏‎‏‏‎‎‏‎‏‏‎‏‎‎‎‎‎‎‏‎‎‎‎‎‎‏‎‏‎‏‏‎‏‎‏‎‏‎‎‏‎‎‎‏‏‏‎‏‏‏‏‎‎You can add up to # profiles.‎‏‎‎‏‎}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‏‏‏‏‏‏‏‏‏‏‏‏‏‏‎‏‏‏‏‎‎‏‎‏‏‏‏‎‏‎‎‎‏‏‏‎‏‏‎‎‎‏‎‏‏‎‏‏‏‏‏‎‎‏‏‏‏‎‎‏‎‎‏‏‏‎‎‎‎‎‏‏‎‎‎‏‎Loading‎‏‎‎‏‎"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‎‎‏‎‏‎‎‎‏‏‏‏‎‏‎‎‏‏‏‎‏‏‎‎‎‎‎‎‏‎‎‎‏‏‎‎‎‏‏‎‏‎‏‎‏‏‏‎‏‎‎‏‏‎‏‏‎‏‎‏‏‎‎Loading user (from ‎‏‎‎‏‏‎<xliff:g id="FROM_USER">%1$d</xliff:g>‎‏‎‎‏‏‏‎ to ‎‏‎‎‏‏‎<xliff:g id="TO_USER">%2$d</xliff:g>‎‏‎‎‏‏‏‎)‎‏‎‎‏‎"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‎‎‎‏‏‎‎‏‏‏‎‎‎‎‎‏‎‏‏‏‎‎‏‏‎‏‎‏‏‏‏‏‏‏‎‏‎‏‏‏‏‎‏‎‏‏‎‎‎‎‎‎‏‎‎‎‏‏‎‏‏‎Current profile‎‏‎‎‏‎"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‎‏‎‎‏‎‏‎‏‎‎‏‏‎‎‏‎‏‎‏‏‏‏‏‏‏‏‎‎‎‏‏‎‏‎‏‎‎‎‎‏‏‎‎‎‎‎‎‏‏‎‎‎‏‏‏‎‏‎‎‎‎‏‎‎‏‏‎<xliff:g id="SENSOR">%1$s</xliff:g>‎‏‎‎‏‏‏‎ is off.‎‏‎‎‏‎"</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‎‏‎‏‎‏‎‏‏‎‎‏‎‎‎‎‏‎‏‎‏‎‎‎‏‏‎‏‏‎‏‎‎‏‎‎‎‏‎‏‏‎‏‏‎‏‎‏‎‏‏‎‎‏‏‏‏‎‏‎‏‎Use ‎‏‎‎‏‏‎<xliff:g id="SENSOR">%1$s</xliff:g>‎‏‎‎‏‏‏‎‎‏‎‎‏‎"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‎‎‏‏‏‎‎‏‏‏‏‎‏‏‎‎‎‏‏‏‏‏‎‏‏‎‎‏‏‏‏‏‏‎‏‏‎‎‏‏‏‎‏‏‎‎‏‎‏‎‏‎‏‏‏‏‏‏‏‏‏‎‎For apps that have permission‎‏‎‎‏‎"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‎‏‏‎‎‎‏‎‏‏‏‎‎‏‏‏‏‎‎‏‎‎‎‏‎‏‎‎‏‏‎‎‏‎‏‎‎‏‎‏‏‏‎‏‏‏‏‏‎‎‏‎‎‎‎‏‎‎‏‏‎‏‎‎Signal Settings: Wifi On‎‏‎‎‏‎"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‎‎‏‏‏‎‎‎‏‏‎‎‏‎‏‎‎‏‎‎‎‎‏‎‏‎‏‎‎‎‏‏‏‎‎‏‎‏‏‏‎‏‏‏‏‎‏‎‏‏‎‎‏‏‏‏‏‎‎‎‎‎‎Signal Settings: Hotspot On‎‏‎‎‏‎"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‎‏‎‏‎‎‏‎‎‏‏‎‏‏‏‏‎‏‎‎‎‏‎‎‏‎‎‏‎‏‏‎‎‏‏‎‏‎‏‏‎‏‏‎‎‏‏‏‏‏‎‎‎‎‎‎‎‏‎‏‎‎‎‎Display Settings‎‏‎‎‏‎"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‎‏‎‎‎‏‎‏‎‏‏‏‏‏‏‏‏‎‎‏‏‎‎‎‎‏‏‏‏‎‏‏‎‎‏‎‏‎‎‏‎‎‏‏‏‎‏‎‏‏‎‏‏‎‎‏‏‏‏‎‏‎‎‎Debug Settings‎‏‎‎‏‎"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‎‎‎‏‎‎‎‏‎‏‎‎‏‎‏‎‎‎‏‎‏‎‎‎‏‎‎‏‎‎‎‎‏‎‏‏‎‏‎‎‏‏‎‎‎‎‏‎‏‏‎‎‏‏‏‏‎‏‎‏‏‎‎Sound Settings‎‏‎‎‏‎"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‎‏‏‎‏‏‎‏‎‏‎‏‎‎‎‏‏‎‎‏‏‎‎‎‎‏‏‏‎‏‏‏‏‎‏‎‏‎‏‎‎‎‏‏‏‏‏‏‎‏‏‎‏‏‏‎‏‎‏‎‏‎‎‎Drive Mode‎‏‎‎‏‎"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‎‎‏‎‏‎‎‏‎‎‏‎‏‎‎‎‏‏‏‏‎‎‎‎‏‎‏‏‏‎‏‏‏‏‏‎‏‎‎‏‎‎‏‏‎‏‏‎‎‎‎‎‏‎‎‎‎‏‎‎‏‎‎You can’t use this feature while driving‎‏‎‎‏‎"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‏‏‏‏‏‏‏‏‏‏‏‏‏‏‎‎‏‏‏‎‎‎‏‏‏‎‏‎‏‏‎‏‏‎‏‎‎‎‎‎‏‎‎‎‎‏‎‎‎‎‎‏‎‏‎‏‏‏‏‎‎‎‏‎‎‏‏‎‏‏‏‎‎‎‎Close app‎‏‎‎‏‎"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‎‏‎‏‎‎‎‏‏‏‏‎‎‏‎‎‏‏‎‏‎‏‏‏‏‎‎‏‏‏‎‎‏‏‎‎‏‏‎‏‎‏‎‎‎‏‎‎‎‏‏‎‏‎‏‎‏‎‎‏‎‎‎‎Display settings‎‏‎‎‏‎"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‎‎‎‏‏‏‎‎‎‎‎‎‏‏‎‏‎‎‎‏‏‎‎‏‏‎‏‏‎‎‏‏‎‏‎‏‏‏‎‏‏‏‏‏‎‏‏‏‎‏‎‎‏‎‏‎‏‏‏‎‎‏‎Sound settings‎‏‎‎‏‎"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‎‏‏‏‏‎‏‏‏‎‏‏‎‎‎‎‏‏‎‎‎‎‏‏‎‏‏‎‎‎‏‏‏‏‎‏‏‏‎‏‎‏‎‎‏‎‎‎‎‏‏‎‏‎‎‏‎‎‏‏‎‎‎‎Profiles &amp; accounts settings‎‏‎‎‏‎"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‎‏‎‏‎‎‏‏‏‎‎‏‏‏‏‎‏‏‏‏‏‏‎‎‎‏‏‎‏‏‎‎‎‎‎‎‎‏‎‏‎‎‎‎‏‎‎‏‎‏‏‎‏‎‎‎‏‎‏‎‏‎Developer options‎‏‎‎‏‎"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‎‏‏‏‏‏‏‏‏‏‎‏‎‏‏‎‎‎‎‏‎‏‏‏‎‏‏‎‎‎‏‎‏‎‏‏‏‎‎‏‏‏‎‎‏‎‏‎‎‏‎‏‎‏‎‎‎‏‏‎‏‎‎‎Pattern does not support rotary; please use touch‎‏‎‎‏‎"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‎‏‏‎‏‏‏‎‎‏‏‎‎‎‏‎‏‎‎‏‎‎‏‎‏‏‎‏‏‎‎‎‎‏‏‎‏‎‎‎‏‏‏‏‎‎‏‎‏‎‎‎‎‎‏‏‎‏‏‏‏‎‏‎Your screen is locked‎‏‎‎‏‎"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‎‏‎‎‎‎‏‏‏‎‎‎‏‏‏‎‏‏‏‏‏‏‏‏‎‏‏‎‎‎‏‎‎‏‏‏‎‏‏‎‏‏‏‏‎‎‏‏‎‎‎‏‎‎‏‎‏‎‏‎‏‏‎‎Your screen has been locked‎‏‎‎‏‎"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‎‎‎‏‏‏‎‎‎‏‎‏‏‎‎‏‏‎‎‎‏‎‎‎‏‏‏‎‎‏‏‎‎‏‎‎‎‎‎‏‎‎‏‏‎‎‎‎‎‏‎‎‏‎‎‏‏‏‎‏‎Can’t start Guest profile. Try again later.‎‏‎‎‏‎"</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‎‎‎‏‎‎‏‎‏‎‎‏‎‏‎‏‎‏‏‏‏‏‎‏‏‎‎‎‎‎‏‏‎‏‎‏‏‏‏‏‏‎‎‎‏‏‏‏‏‎‏‎‎‎‏‎‎‏‏‏‎‎‎Signing out…‎‏‎‎‏‎"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‎‎‎‏‎‎‏‏‏‎‎‏‎‎‏‎‏‏‎‎‎‏‎‏‎‏‎‎‏‎‏‎‏‎‎‎‏‎‎‏‎‎‎‏‎‏‎‏‏‎‎‏‎‏‎‎‏‏‎‏‏‎‎‎‏‎‎‏‏‎<xliff:g id="USER_NAME">%s</xliff:g>‎‏‎‎‏‏‏‎ is being signed out. Try again later.‎‏‎‎‏‎"</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‎‏‎‎‏‏‏‎‏‎‏‏‎‏‎‎‏‎‏‎‎‎‎‏‎‎‎‏‎‏‎‏‏‏‎‏‎‎‏‏‎‏‏‏‏‏‏‏‎‎‎‎‎‏‎‎‏‎‏‎‏‎‎User currently unavailable‎‏‎‎‏‎"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‎‏‏‏‏‎‎‎‏‏‏‏‏‏‎‎‎‏‎‏‏‏‏‎‎‏‎‏‎‎‎‏‏‏‏‏‏‎‎‏‏‎‏‏‎‏‎‏‎‏‎‎‏‎‏‎‏‏‎‎‎‎‏‎Unable to start secure user on passenger display‎‏‎‎‏‎"</string>
     <string name="seat_driver" msgid="4502591979520445677">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‎‏‏‏‏‏‎‎‏‏‏‏‏‎‎‎‏‏‎‏‎‏‏‏‎‎‎‏‏‎‎‏‎‏‏‎‎‏‏‏‏‎‏‎‏‏‎‏‏‎‎‏‏‎‎‏‏‏‎‏‏‎‏‎driver‎‏‎‎‏‎"</string>
     <string name="seat_front" msgid="836133281052793377">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‎‎‏‎‏‏‏‎‎‏‏‎‏‎‏‎‎‎‏‎‏‎‏‏‎‎‏‎‏‎‎‎‎‎‎‎‏‎‎‎‎‎‏‎‎‎‏‎‎‏‏‎‏‎‎‎‏‎‎‎‎‏‎front‎‏‎‎‏‎"</string>
     <string name="seat_rear" msgid="403133444964528577">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‏‏‏‏‏‏‏‏‏‏‏‏‏‏‎‏‏‏‎‏‏‎‎‏‏‎‎‎‎‎‏‏‎‏‏‏‏‎‏‏‏‎‏‏‎‏‏‏‏‎‎‎‎‎‏‏‎‎‎‎‏‎‏‏‎‎‎‏‏‏‎‎‎‎‎‏‎rear‎‏‎‎‏‎"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‎‏‎‏‎‎‎‏‎‎‏‏‎‏‎‎‎‏‏‎‏‎‏‏‎‎‎‎‏‏‎‎‏‏‎‎‎‎‏‎‏‎‎‎‎‏‎‏‏‎‎‏‏‎‎‏‎‎‏‎‎‎Full Screen‎‏‎‎‏‎"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‎‏‏‎‏‏‏‎‎‎‏‎‎‏‏‎‏‎‎‏‎‎‎‏‎‏‏‎‎‎‎‎‏‎‏‎‏‏‏‎‎‎‎‏‎‏‎‏‎‎‏‏‏‎‎‎‏‎‏‏‎‏‎See plans‎‏‎‎‏‎"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‎‏‎‏‎‏‏‎‏‏‏‎‎‎‎‎‏‏‎‎‎‏‎‏‏‏‏‏‎‏‎‎‏‏‏‎‏‏‎‎‎‎‎‎‏‎‎‏‎‏‏‏‏‏‎‏‎‏‎‎‏‎‏‎Your internet plan expired‎‏‎‎‏‎"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‎‎‎‎‎‎‎‎‎‏‎‎‎‎‏‏‎‏‎‏‎‎‎‏‏‏‎‏‎‏‏‏‎‏‏‎‏‎‎‎‏‏‎‎‎‏‎‏‏‎‏‏‎‎‎‎‎‏‏‏‎This app needs an internet connection‎‏‎‎‏‎"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‎‎‏‎‎‎‏‏‏‎‎‎‏‏‏‏‏‎‏‏‏‏‎‎‎‏‏‏‎‏‏‎‏‎‏‎‎‎‎‎‎‏‎‎‏‏‏‏‏‏‏‏‏‎‏‏‏‎‏‎‏‎‎%s needs an internet connection‎‏‎‎‏‎"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‏‎‎‏‏‏‎‎‏‎‎‏‎‏‏‏‏‎‎‏‎‎‎‏‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‎‏‏‏‏‎‏‎‎‎‎‎‎‎‎‏‎‏‏‏‏‎‎This app‎‏‎‎‏‎"</string>
 </resources>
diff --git a/res/values-es-rUS/strings.xml b/res/values-es-rUS/strings.xml
index 16a79c0c..3cdb7798 100644
--- a/res/values-es-rUS/strings.xml
+++ b/res/values-es-rUS/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{Solo se puede crear un perfil.}other{Puedes agregar hasta # perfiles.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"Cargando"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"Cargando usuario (de <xliff:g id="FROM_USER">%1$d</xliff:g> a <xliff:g id="TO_USER">%2$d</xliff:g>)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"Perfil actual"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"Se desactivó <xliff:g id="SENSOR">%1$s</xliff:g>."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"Usar <xliff:g id="SENSOR">%1$s</xliff:g>"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"Para apps que tienen permiso"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"Configuración de señal: Wi-Fi activado"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"Configuración de señal: Hotspot activado"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"Configuración de pantalla"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"Configuración de depuración"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"Configuración de sonido"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"Modo en automóvil"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"No puedes usar esta función mientras conduces"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"Cerrar app"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Configuración de pantalla"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Configuración de sonido"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Configuración de perfiles y cuentas"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Opciones para desarrolladores"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"No se admite patrón rotativo; usa táctil"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"Tu pantalla está bloqueada"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"Se bloqueó la pantalla"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"No se puede iniciar el perfil de invitado. Vuelve a intentarlo más tarde."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"Saliendo…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> está saliendo. Vuelve a intentarlo más tarde."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"El usuario no está disponible en este momento"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"No se puede iniciar la protección del usuario en la pantalla de pasajero"</string>
     <string name="seat_driver" msgid="4502591979520445677">"conductor"</string>
     <string name="seat_front" msgid="836133281052793377">"parte frontal"</string>
     <string name="seat_rear" msgid="403133444964528577">"parte posterior"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"Pantalla completa"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Ver planes"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Tu plan de Internet venció"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"Esta app requiere una conexión a Internet"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s requiere conexión a Internet"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Esta app"</string>
 </resources>
diff --git a/res/values-es/strings.xml b/res/values-es/strings.xml
index 36ddc89b..87b3bc5b 100644
--- a/res/values-es/strings.xml
+++ b/res/values-es/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{Solo se puede crear un perfil.}other{Puedes crear # perfiles como máximo.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"Cargando"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"Cargando usuario (de <xliff:g id="FROM_USER">%1$d</xliff:g> a <xliff:g id="TO_USER">%2$d</xliff:g>)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"Perfil actual"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g> se ha desactivado."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"Usar <xliff:g id="SENSOR">%1$s</xliff:g>"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"Para aplicaciones que tienen permiso"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"Ajustes de señal: Wi-Fi activado"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"Ajustes de señal: Compartir Internet activado"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"Ajustes de pantalla"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"Ajustes de depuración"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"Ajustes de sonido"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"Modo de conducción"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"No puedes usar esta función mientras conduces"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"Cerrar aplicación"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Ajustes de pantalla"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Ajustes de sonido"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Ajustes de perfiles y de cuentas"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Opciones para desarrolladores"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"No puede usarse patrón de rotación; usa uno táctil"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"Tu pantalla está bloqueada"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"Se ha bloqueado tu pantalla"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"No se puede iniciar el perfil de invitado. Inténtalo de nuevo más tarde."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"Cerrando sesión…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> está cerrando sesión. Inténtalo de nuevo más tarde."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Usuario no disponible actualmente"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"No se puede iniciar el modo de usuario seguro en la pantalla del pasajero"</string>
     <string name="seat_driver" msgid="4502591979520445677">"del conductor"</string>
     <string name="seat_front" msgid="836133281052793377">"delantero"</string>
     <string name="seat_rear" msgid="403133444964528577">"trasero"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"Pantalla completa"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Ver planes"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Tu plan de Internet ha caducado"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"Esta aplicación necesita conexión a Internet"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s necesita conexión a Internet"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Esta aplicación"</string>
 </resources>
diff --git a/res/values-et/strings.xml b/res/values-et/strings.xml
index 147d9784..05407504 100644
--- a/res/values-et/strings.xml
+++ b/res/values-et/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{Luua saab ainult ühe profiili.}other{Võite lisada kuni # profiili.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"Laadimine"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"Kasutaja laadimine (<xliff:g id="FROM_USER">%1$d</xliff:g> &gt; <xliff:g id="TO_USER">%2$d</xliff:g>)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"Praegune profiil"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g> on välja lülitatud."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"Kasuta järgmist: <xliff:g id="SENSOR">%1$s</xliff:g>"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"Rakendustele, millel on luba"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"Signaali seaded: WiFi on sisse lülitatud"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"Signaali seaded: kuumkoht on sisse lülitatud"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"Kuvaseaded"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"Silumisseaded"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"Heliseaded"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"Sõidurežiim"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"Te ei saa seda funktsiooni sõidu ajal kasutada"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"Sule rakendus"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Kuvaseaded"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Heliseaded"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Profiili- ja kontoseaded"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Arendaja valikud"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"Muster ei toeta pöördvalijat, kasutage puudutust."</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"Teie ekraan on lukus"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"Teie ekraanikuva on lukustatud"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"Külalise profiili ei saa käivitada. Proovige hiljem uuesti."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"Väljalogimine …"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"Kasutaja <xliff:g id="USER_NAME">%s</xliff:g> väljalogimine on pooleli. Proovige hiljem uuesti."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Kasutaja pole praegu saadaval"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Kõrvalistuja ekraanil ei saa turvalist kasutajaprofiili avada"</string>
     <string name="seat_driver" msgid="4502591979520445677">"juht"</string>
     <string name="seat_front" msgid="836133281052793377">"eesmine"</string>
     <string name="seat_rear" msgid="403133444964528577">"tagumine"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"Täisekraan"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Kuva paketid"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Teie internetipakett on aegunud"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"See rakendus vajab internetiühendust"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s vajab internetiühendust"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"See rakendus"</string>
 </resources>
diff --git a/res/values-eu/strings.xml b/res/values-eu/strings.xml
index 8d1d304e..c953468e 100644
--- a/res/values-eu/strings.xml
+++ b/res/values-eu/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{Profil bakarra sor daiteke.}other{Gehienez # profil gehi daitezke.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"Kargatzen"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"Erabiltzailea kargatzen (<xliff:g id="FROM_USER">%1$d</xliff:g> izatetik<xliff:g id="TO_USER">%2$d</xliff:g> izatera igaroko da)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"Oraingo profila"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g> desaktibatuta dago."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"Erabili <xliff:g id="SENSOR">%1$s</xliff:g>"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"Baimena duten aplikazioekin"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"Seinalearen ezarpenak: wifia aktibatuta"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"Seinalearen ezarpenak: wifi-gunea aktibatuta"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"Bistaratze-ezarpenak"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"Arazketa-ezarpenak"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"Soinuaren ezarpenak"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"Gidatze modua"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"Ezin duzu erabili eginbidea gidatu bitartean"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"Itxi aplikazioa"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Bistaratze-ezarpenak"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Soinuaren ezarpenak"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Profilen eta kontuen ezarpenak"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Garatzaileentzako aukerak"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"Ezin da erabili biratze bidezko idazketa; erabili ukipen-keinuak"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"Pantaila blokeatuta dago"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"Blokeatu da pantaila"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"Ezin da abiarazi gonbidatu-profila. Saiatu berriro geroago."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"Saioa amaitzen…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> erabiltzailearen saioa amaitzen. Saiatu berriro geroago."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Erabiltzailea ez dago erabilgarri une honetan"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Ezin izan da abiarazi erabiltzaile segurua bidaiariaren pantailan"</string>
     <string name="seat_driver" msgid="4502591979520445677">"gidaria"</string>
     <string name="seat_front" msgid="836133281052793377">"aurrekoa"</string>
     <string name="seat_rear" msgid="403133444964528577">"atzekoa"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"Pantaila osoa"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Ikusi kidetzak"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Interneteko kidetza iraungi da"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"Aplikazio honek Interneteko konexioa behar du"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"Beharrezkoa da %s Internetera konektatzea"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"aplikazio hau"</string>
 </resources>
diff --git a/res/values-fa/strings.xml b/res/values-fa/strings.xml
index ff296b08..5f532703 100644
--- a/res/values-fa/strings.xml
+++ b/res/values-fa/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{فقط یک نمایه می‌توانید بسازید.}one{می‌توانید تا # نمایه اضافه کنید.}other{می‌توانید تا # نمایه اضافه کنید.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"درحال بارگیری"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"بارگیری کاربر (از <xliff:g id="FROM_USER">%1$d</xliff:g> تا <xliff:g id="TO_USER">%2$d</xliff:g>)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"نمایه کنونی"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g> خاموش است."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"استفاده از <xliff:g id="SENSOR">%1$s</xliff:g>"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"برای برنامه‌هایی که اجازه دارند"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"تنظیمات سیگنال: Wi-Fi روشن است"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"تنظیمات سیگنال: نقطه اتصال روشن است"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"تنظیمات نمایشگر"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"تنظیمات اشکال‌زدایی"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"تنظیمات صدا"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"حالت رانندگی"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"هنگام رانندگی نمی‌توانید از این ویژگی استفاده کنید"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"بستن برنامه"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"تنظیمات نمایش"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"تنظیمات صدا"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"تنظیمات حساب و نمایه"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"گزینه‌های توسعه‌دهندگان"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"الگو حالت چرخشی ندارد، لمسی است"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"صفحه شما قفل است"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"صفحه‌نمایش قفل شده است"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"«نمایه مهمان» شروع نشد. بعداً دوباره امتحان کنید."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"درحال خروج از سیستم…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> درحال خروج از سیستم است. بعداً دوباره امتحان کنید."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"کاربر فعلاً دردسترس نیست"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"کاربر ایمن در نمایشگر مسافر راه‌اندازی نشد"</string>
     <string name="seat_driver" msgid="4502591979520445677">"راننده"</string>
     <string name="seat_front" msgid="836133281052793377">"جلو"</string>
     <string name="seat_rear" msgid="403133444964528577">"عقب"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"تمام صفحه"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"دیدن طرح‌ها"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"طرح اینترنت شما منقضی شده است"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"این برنامه به اتصال اینترنت نیاز دارد"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"‫%s به اتصال اینترنت نیاز دارد"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"این برنامه"</string>
 </resources>
diff --git a/res/values-fi/strings.xml b/res/values-fi/strings.xml
index 28a1b68b..fc02f91c 100644
--- a/res/values-fi/strings.xml
+++ b/res/values-fi/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{Voit luoda vain yhden profiilin.}other{Voit lisätä enintään # profiilia.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"Ladataan"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"Ladataan käyttäjäprofiilia (<xliff:g id="FROM_USER">%1$d</xliff:g>–<xliff:g id="TO_USER">%2$d</xliff:g>)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"Nykyinen profiili"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g> ei ole päällä."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"Valitse <xliff:g id="SENSOR">%1$s</xliff:g>"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"Sovelluksissa, joilla on lupa"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"Signaaliasetukset: Wi-Fi päällä"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"Signaaliasetukset: Hotspot päällä"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"Näyttöasetukset"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"Virheenkorjausasetukset"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"Ääniasetukset"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"Ajotila"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"Et voi käyttää ominaisuutta ajon aikana"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"Sulje sovellus"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Näyttöasetukset"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Ääniasetukset"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Profiili- ja tiliasetukset"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Kehittäjäasetukset"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"Kuvio ei tue kiertoa –käytä kosketusta"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"Näyttösi on lukittu"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"Näyttö on lukittu"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"Vierasprofiilia ei voi käynnistää. Yritä myöhemmin uudelleen."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"Kirjaudutaan ulos…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> kirjataan ulos. Yritä myöhemmin uudelleen."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Käyttäjä ei juuri nyt saatavilla"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Suojattua käyttäjää ei voi valita matkustajan näytöltä"</string>
     <string name="seat_driver" msgid="4502591979520445677">"kuljettajan paikalla"</string>
     <string name="seat_front" msgid="836133281052793377">"edessä"</string>
     <string name="seat_rear" msgid="403133444964528577">"takana"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"Koko näyttö"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Katso liittymät"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Internetliittymä on vanhentunut"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"Tämä sovellus tarvitsee internetyhteyden"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s tarvitsee internetyhteyden"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Tämä sovellus"</string>
 </resources>
diff --git a/res/values-fr-rCA/strings.xml b/res/values-fr-rCA/strings.xml
index 9288c53a..58ec57bb 100644
--- a/res/values-fr-rCA/strings.xml
+++ b/res/values-fr-rCA/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{Un seul profil peut être créé.}one{Vous pouvez ajouter jusqu\'à # profil.}other{Vous pouvez ajouter jusqu\'à # profils.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"Chargement en cours…"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"Chargement de l\'utilisateur (de <xliff:g id="FROM_USER">%1$d</xliff:g> vers <xliff:g id="TO_USER">%2$d</xliff:g>) en cours…"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"Profil actuel"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"Le capteur <xliff:g id="SENSOR">%1$s</xliff:g> est désactivé."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"Utiliser <xliff:g id="SENSOR">%1$s</xliff:g>"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"Pour les applications qui ont l\'autorisation"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"Paramètres du signal : Wi-Fi activé"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"Paramètres du signal : point d\'accès activé"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"Paramètres d\'affichage"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"Paramètres de débogage"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"Paramètres sonores"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"Mode Voiture"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"Vous ne pouvez pas utiliser cette fonctionnalité en conduisant"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"Fermer l\'application"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Paramètres d\'affichage"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Paramètres sonores"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Paramètres des profils et des comptes"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Options pour les développeurs"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"Schéma prend pas en charge la rotation, utilisez le toucher"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"Votre écran est verrouillé"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"Votre écran a été verrouillé"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"Impossible de lancer le profil d\'invité. Réessayez plus tard."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"Déconnexion en cours…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"Déconnexion de <xliff:g id="USER_NAME">%s</xliff:g> en cours… Réessayez plus tard."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Utilisateur actuellement inaccessible"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Impossible de lancer l\'utilisateur sécurisé sur l\'écran du passager"</string>
     <string name="seat_driver" msgid="4502591979520445677">"conducteur"</string>
     <string name="seat_front" msgid="836133281052793377">"avant"</string>
     <string name="seat_rear" msgid="403133444964528577">"arrière"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"Plein écran"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Voir les forfaits"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Votre forfait Internet a expiré"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"Cette appli nécessite une connexion Internet"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s nécessite une connexion Internet"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Cette appli"</string>
 </resources>
diff --git a/res/values-fr/strings.xml b/res/values-fr/strings.xml
index d4718c29..6e8efbf3 100644
--- a/res/values-fr/strings.xml
+++ b/res/values-fr/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{Vous ne pouvez créer qu\'un seul profil.}one{Vous ne pouvez ajouter que # profil.}other{Vous pouvez ajouter jusqu\'à # profils.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"Chargement…"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"Chargement de l\'utilisateur (de <xliff:g id="FROM_USER">%1$d</xliff:g> à <xliff:g id="TO_USER">%2$d</xliff:g>)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"Profil actuel"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g> est désactivé."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"Utiliser <xliff:g id="SENSOR">%1$s</xliff:g>"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"Pour les applis qui ont l\'autorisation"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"Paramètres du signal : Wi-Fi activé"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"Paramètres du signal : point d\'accès activé"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"Paramètres d\'affichage"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"Paramètres de débogage"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"Paramètres audio"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"Mode Voiture"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"Vous ne pouvez pas utiliser cette fonctionnalité en conduisant"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"Fermer l\'application"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Paramètres d\'affichage"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Paramètres audio"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Paramètres des profils et comptes"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Options pour les développeurs"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"Schéma incompat. avec dispositif rotatif, appuyez"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"Votre écran est verrouillé"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"Votre écran a été verrouillé"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"Impossible de lancer le profil invité. Réessayez plus tard."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"Déconnexion…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> est en cours de déconnexion. Réessayez plus tard."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Utilisateur actuellement indisponible"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Impossible de démarrer \"Utilisateur sécurisé\" sur l\'écran passager"</string>
     <string name="seat_driver" msgid="4502591979520445677">"conducteur"</string>
     <string name="seat_front" msgid="836133281052793377">"avant"</string>
     <string name="seat_rear" msgid="403133444964528577">"arrière"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"Plein écran"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Afficher les forfaits"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Votre forfait Internet a expiré"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"Cette application a besoin d\'une connexion Internet"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s nécessite une connexion Internet."</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Cette appli"</string>
 </resources>
diff --git a/res/values-gl/strings.xml b/res/values-gl/strings.xml
index e0f81cbb..ab670f77 100644
--- a/res/values-gl/strings.xml
+++ b/res/values-gl/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{Só se pode crear 1 perfil.}other{Podes engadir ata # perfís.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"Cargando"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"Cargando usuario (do <xliff:g id="FROM_USER">%1$d</xliff:g> ao <xliff:g id="TO_USER">%2$d</xliff:g>)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"Perfil actual"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g>: desactivouse."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"Usar <xliff:g id="SENSOR">%1$s</xliff:g>"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"Para as aplicacións que teñan permiso"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"Configuración de sinal: wifi activada"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"Configuración de sinal: zona wifi activada"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"Configuración de pantalla"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"Configuración de depuración"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"Configuración do son"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"Modo de condución"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"Non podes utilizar esta función mentres conduces"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"Pechar aplicación"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Configuración de pantalla"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Configuración de son"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Configuración de perfís e contas"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Opcións de programación"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"Manexo xiratorio incompatible; usa padrón táctil"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"A túa pantalla está bloqueada"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"Bloqueouse a túa pantalla"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"Non se puido iniciar o perfil de convidado. Volve tentalo máis tarde."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"Pechando sesión…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"Estase pechando a sesión de <xliff:g id="USER_NAME">%s</xliff:g>. Volve tentalo máis tarde."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Usuario non dispoñible actualmente"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Non é posible iniciar o modo de usuario seguro na pantalla do pasaxeiro"</string>
     <string name="seat_driver" msgid="4502591979520445677">"asento de conducir"</string>
     <string name="seat_front" msgid="836133281052793377">"diante"</string>
     <string name="seat_rear" msgid="403133444964528577">"detrás"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"Pantalla completa"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Ver plans"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"O teu plan de Internet caducou"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"Para usar esta aplicación, cómpre ter conexión a Internet"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s necesita conexión a Internet"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Esta aplicación"</string>
 </resources>
diff --git a/res/values-gu/strings.xml b/res/values-gu/strings.xml
index 0d2fc828..fccbc2f4 100644
--- a/res/values-gu/strings.xml
+++ b/res/values-gu/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{માત્ર એક પ્રોફાઇલ બનાવી શકાય છે.}one{તમે વધુમાં વધુ # પ્રોફાઇલ ઉમેરી શકો છો.}other{તમે વધુમાં વધુ # પ્રોફાઇલ ઉમેરી શકો છો.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"લોડ કરી રહ્યાં છીએ"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"વપરાશકર્તાને લોડ કરી રહ્યાં છીએ (<xliff:g id="FROM_USER">%1$d</xliff:g>માંથી <xliff:g id="TO_USER">%2$d</xliff:g>માં)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"વર્તમાન પ્રોફાઇલ"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g> બંધ છે."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"<xliff:g id="SENSOR">%1$s</xliff:g>નો ઉપયોગ કરો"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"પરવાનગી ધરાવતી ઍપ માટે"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"સિગ્નલના સેટિંગ: વાઇ-ફાઇ ચાલુ છે"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"સિગ્નલના સેટિંગ: હૉટસ્પૉટ બંધ છે"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"ડિસ્પ્લેના સેટિંગ"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"ડિબગ સેટિંગ"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"સાઉન્ડ સેટિંગ"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"ડ્રાઇવિંગ મોડ"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"ડ્રાઇવ કરતી વખતે તમે આ સુવિધાનો ઉપયોગ કરી શકતા નથી"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"ઍપ બંધ કરો"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"ડિસ્પ્લે સેટિંગ"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"સાઉન્ડ સેટિંગ"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"પ્રોફાઇલ અને એકાઉન્ટ સેટિંગ"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"ડેવલપરના વિકલ્પો"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"પૅટર્ન રોટરીને સપોર્ટ કરતી નથી; ટચ વાપરો"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"તમારી સ્ક્રીન લૉક કરેલી છે"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"તમારી સ્ક્રીન લૉક કરવામાં આવી છે"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"અતિથિની પ્રોફાઇલ શરૂ કરી શકતાં નથી. થોડા સમય પછી ફરી પ્રયાસ કરો."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"સાઇન ઇન કરી રહ્યાં છીએ…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> સાઇન આઉટ થઈ રહ્યાં છે. થોડા સમય પછી ફરી પ્રયાસ કરો."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"વપરાશકર્તા હાલમાં ઉપલબ્ધ નથી"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"મુસાફરના ડિસ્પ્લે પર સુરક્ષિત વપરાશકર્તા માટે શરૂઆત કરી શકતા નથી"</string>
     <string name="seat_driver" msgid="4502591979520445677">"ડ્રાઇવર"</string>
     <string name="seat_front" msgid="836133281052793377">"આગળ"</string>
     <string name="seat_rear" msgid="403133444964528577">"પાછળ"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"પૂર્ણ સ્ક્રીન"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"પ્લાન જુઓ"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"તમારો ઇન્ટરનેટ પ્લાન સમાપ્ત થઈ ગયો છે"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"આ ઍપને કોઈ ઇન્ટરનેટ કનેક્શન હોવું જરૂરી છે"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s માટે ઇન્ટરનેટ કનેક્શન જરૂરી છે"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"આ ઍપ"</string>
 </resources>
diff --git a/res/values-hi/strings.xml b/res/values-hi/strings.xml
index 9cdc4be1..07c7edf6 100644
--- a/res/values-hi/strings.xml
+++ b/res/values-hi/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{सिर्फ़ एक प्रोफ़ाइल बनाई जा सकती है.}one{ज़्यादा से ज़्यादा # प्रोफ़ाइल जोड़ी जा सकती है.}other{ज़्यादा से ज़्यादा # प्रोफ़ाइलें जोड़ी जा सकती हैं.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"लोड हो रही है"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"उपयोगकर्ता को लोड किया जा रहा है (<xliff:g id="FROM_USER">%1$d</xliff:g> से <xliff:g id="TO_USER">%2$d</xliff:g> पर)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"मौजूदा प्रोफ़ाइल"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g> बंद है."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"<xliff:g id="SENSOR">%1$s</xliff:g> का इस्तेमाल करें"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"उन ऐप्लिकेशन के लिए जिन्हें अनुमति है"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"सिग्नल सेटिंग: वाई-फ़ाई चालू है"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"सिग्नल सेटिंग: हॉटस्पॉट चालू है"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"डिसप्ले सेटिंग"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"डीबग सेटिंग"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"आवाज़ की सेटिंग"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"ड्राइव मोड"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"आप गाड़ी चलाते समय इस सुविधा का इस्तेमाल नहीं कर सकते"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"ऐप्लिकेशन बंद करें"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"डिसप्ले की सेटिंग"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"आवाज़ की सेटिंग"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"प्रोफ़ाइल और खाता सेटिंग"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"डेवलपर के लिए सेटिंग और टूल"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"पैटर्न, रोटरी के साथ काम नहीं करता, टच इस्तेमाल करें"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"डिवाइस की स्क्रीन लॉक है"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"डिवाइस की स्क्रीन को लॉक किया गया"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"मेहमान प्रोफ़ाइल नहीं बनाई जा सकी. कुछ देर बाद कोशिश करें."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"साइन आउट किया जा रहा है…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> को साइन आउट किया जा रहा है. कुछ देर बाद कोशिश करें."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"फ़िलहाल, उपयोगकर्ता की प्रोफ़ाइल उपलब्ध नहीं है"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"पैसेंजर की डिसप्ले पर, उपयोगकर्ता की सुरक्षित प्रोफ़ाइल को चालू नहीं किया जा सका"</string>
     <string name="seat_driver" msgid="4502591979520445677">"ड्राइवर वाली सीट"</string>
     <string name="seat_front" msgid="836133281052793377">"सामने वाली सीट"</string>
     <string name="seat_rear" msgid="403133444964528577">"पीछे वाली सीट"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"फ़ुल स्क्रीन"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"प्लान देखें"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"आपका इंटरनेट प्लान खत्म हो गया है"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"इस ऐप्लिकेशन को इंटरनेट कनेक्शन की ज़रूरत हैं"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s के लिए इंटरनेट कनेक्शन होना ज़रूरी है"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"यह ऐप्लिकेशन"</string>
 </resources>
diff --git a/res/values-hr/strings.xml b/res/values-hr/strings.xml
index bcf7f4aa..9de25bce 100644
--- a/res/values-hr/strings.xml
+++ b/res/values-hr/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{Može se izraditi samo jedan profil.}one{Možete dodati najviše # profil.}few{Možete dodati najviše # profila.}other{Možete dodati najviše # profila.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"Učitavanje"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"Učitavanje korisnika (od <xliff:g id="FROM_USER">%1$d</xliff:g> do <xliff:g id="TO_USER">%2$d</xliff:g>)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"Trenutačni profil"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g>: isključeno."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"Koristi sljedeće: <xliff:g id="SENSOR">%1$s</xliff:g>"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"Za aplikacije koje imaju dopuštenje"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"Postavke signala: Wi-Fi je uključen"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"Postavke signala: žarišna točka je uključena"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"Postavke zaslona"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"Postavke otklanjanja pogrešaka"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"Postavke zvuka"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"Način za vožnju"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"Tu značajku ne možete upotrebljavati tijekom vožnje"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"Zatvori aplikaciju"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Postavke zaslona"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Postavke zvuka"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Postavke profila i računa"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Opcije za razvojne programere"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"Uzorak se ne unosi rotacijski; dodirnite"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"Zaslon je zaključan"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"Zaslon je zaključan"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"Pokretanje profila gosta nije uspjelo. Pokušajte ponovo kasnije."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"Odjava…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> se odjavljuje. Pokušajte ponovo kasnije."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Korisnik trenutačno nije dostupan"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Nije moguće pokrenuti profil sigurnog korisnika na zaslonu putnika"</string>
     <string name="seat_driver" msgid="4502591979520445677">"vozač"</string>
     <string name="seat_front" msgid="836133281052793377">"prednja"</string>
     <string name="seat_rear" msgid="403133444964528577">"stražnja"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"Cijeli zaslon"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Prikaži pakete"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Vaš je internetski paket istekao"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"Ova aplikacija zahtjeva internetsku vezu"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s zahtijeva internetsku vezu"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Ova aplikacija"</string>
 </resources>
diff --git a/res/values-hu/strings.xml b/res/values-hu/strings.xml
index 06f35cd0..2da2ec07 100644
--- a/res/values-hu/strings.xml
+++ b/res/values-hu/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{Legfeljebb egy profilt hozhat létre.}other{Legfeljebb # profilt hozhat létre.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"Betöltés"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"Felhasználó betöltése (<xliff:g id="FROM_USER">%1$d</xliff:g> → <xliff:g id="TO_USER">%2$d</xliff:g>)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"Aktuális profil"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g> kikapcsolva."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"<xliff:g id="SENSOR">%1$s</xliff:g> használata"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"Engedéllyel rendelkező alkalmazások számára"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"Jelbeállítások: Wi-Fi bekapcsolva"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"Jelbeállítások: hotspot bekapcsolva"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"Megjelenítési beállítások"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"Hibaelhárítási beállítások"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"Hangbeállítások"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"Vezetési mód"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"Vezetés közben nem használhatja ezt a funkciót"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"Alkalmazás bezárása"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Megjelenítési beállítások"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Hangbeállítások"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Profil- és fiókbeállítások"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Fejlesztői beállítások"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"Nem támogatott a forgó bevitel; használjon érintést"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"Képernyő lezárva"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"Képernyője zárolva van"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"Nem lehet vendégprofilt indítani. Próbálja újra később."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"Kijelentkezés…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> kijelentkeztetése folyamatban van. Próbálja újra később."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"A felhasználó jelenleg nem áll rendelkezésre"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Nem sikerült elindítani a biztonságos felhasználói munkamenetet az utaskijelzőn"</string>
     <string name="seat_driver" msgid="4502591979520445677">"sofőr"</string>
     <string name="seat_front" msgid="836133281052793377">"elöl"</string>
     <string name="seat_rear" msgid="403133444964528577">"hátul"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"Teljes képernyő"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Csomagok megtekintése"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Lejárt az internetcsomagja"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"Az alkalmazásnak internetkapcsolatra van szüksége"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"A(z) %s internetkapcsolatot igényel"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Ez az alkalmazás"</string>
 </resources>
diff --git a/res/values-hy/strings.xml b/res/values-hy/strings.xml
index 11f999d1..06d53e67 100644
--- a/res/values-hy/strings.xml
+++ b/res/values-hy/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{Դուք կարող եք միայն մեկ պրոֆիլ ստեղծել:}one{Դուք կարող եք առավելագույնը # պրոֆիլ ավելացնել։}other{Դուք կարող եք առավելագույնը # պրոֆիլ ավելացնել։}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"Բեռնում"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"Օգտատերը բեռնվում է (<xliff:g id="FROM_USER">%1$d</xliff:g> – <xliff:g id="TO_USER">%2$d</xliff:g>)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"Ընթացիկ պրոֆիլը"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g>ն անջատված է։"</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"Օգտագործել <xliff:g id="SENSOR">%1$s</xliff:g>ը"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"Թույլտվություն ունեցող հավելվածների համար"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"Ազդանշանի կարգավորումներ․ Wi-Fi-ը միացված է"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"Ազդանշանի կարգավորումներ․ թեժ կետը միացված է"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"Էկրանի կարգավորումներ"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"Վրիպազերծման կարգավորումներ"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"Ձայնի կարգավորումներ"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"«Մեքենայով» ռեժիմ"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"Դուք չեք կարող օգտագործել այս գործառույթը մեքենա վարելիս"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"Փակել հավելվածը"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Ցուցադրել կարգավորումները"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Ձայնի կարգավորումներ"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Պրոֆիլների և հաշիվների կարգավորումներ"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Մշակողի ընտրանքներ"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"Նախշը չի աջակցում պտտաշարժում. օգտագործեք հպում"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"Ձեր էկրանը կողպված է"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"Ձեր էկրանը կողպվել է"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"Չհաջողվեց օգտագործել հյուրի պրոֆիլը։ Փորձեք ավելի ուշ։"</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"Ելք…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> օգտատերը դուրս է գրվում հաշվից։ Փորձեք ավելի ուշ։"</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Օգտատերն այս պահին անհասանելի է"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Հնարավոր չէ օգտատիրոջ անվտանգ պրոֆիլ ակտիվացնել ուղևորի էկրանին"</string>
     <string name="seat_driver" msgid="4502591979520445677">"վարորդի"</string>
     <string name="seat_front" msgid="836133281052793377">"առջևում նստած ուղևորի"</string>
     <string name="seat_rear" msgid="403133444964528577">"հետևում նստած ուղևորի"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"Լիաէկրան"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Դիտել պլանները"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Ձեր ինտերնետ սակագնային պլանի ժամկետը սպառվել է"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"Այս հավելվածի աշխատանքի համար ինտերնետ կապ է հարկավոր"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s հավելվածի աշխատանքի համար ինտերնետ կապ է հարկավոր"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Այս"</string>
 </resources>
diff --git a/res/values-in/strings.xml b/res/values-in/strings.xml
index 533c4bc1..a3f6fbe7 100644
--- a/res/values-in/strings.xml
+++ b/res/values-in/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{Hanya satu profil yang dapat dibuat.}other{Anda dapat menambahkan hingga # profil.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"Memuat"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"Memuat pengguna (dari <xliff:g id="FROM_USER">%1$d</xliff:g> menjadi <xliff:g id="TO_USER">%2$d</xliff:g>)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"Profil saat ini"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g> nonaktif."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"Gunakan <xliff:g id="SENSOR">%1$s</xliff:g>"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"Untuk aplikasi yang memiliki izin"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"Setelan Sinyal: Wi-Fi Aktif"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"Setelan Sinyal: Hotspot Aktif"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"Setelan Layar"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"Setelan Debug"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"Setelan Suara"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"Mode Mengemudi"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"Anda tidak dapat menggunakan fitur ini saat mengemudi"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"Tutup aplikasi"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Setelan layar"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Setelan suara"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Setelan akun &amp; profil"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Opsi developer"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"Pola tidak mendukung rotasi; gunakan sentuhan"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"Layar Anda terkunci"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"Layar Anda telah dikunci"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"Tidak dapat memulai profil Tamu. Coba lagi nanti."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"Logout…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> saat ini logout. Coba lagi nanti."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Pengguna tidak tersedia untuk saat ini"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Tidak dapat memulai pengguna aman di tampilan penumpang"</string>
     <string name="seat_driver" msgid="4502591979520445677">"pengemudi"</string>
     <string name="seat_front" msgid="836133281052793377">"depan"</string>
     <string name="seat_rear" msgid="403133444964528577">"belakang"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"Layar Penuh"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Lihat paket"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Masa berlaku paket internet Anda telah berakhir"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"Aplikasi ini memerlukan koneksi internet"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s memerlukan koneksi internet"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Aplikasi ini"</string>
 </resources>
diff --git a/res/values-is/strings.xml b/res/values-is/strings.xml
index 61a78b7b..5220e8da 100644
--- a/res/values-is/strings.xml
+++ b/res/values-is/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{Aðeins er hægt að búa til einn prófíl.}one{Þú getur bætt við allt að # prófíl.}other{Þú getur bætt við allt að # prófílum.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"Hleður"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"Hleður notanda (frá <xliff:g id="FROM_USER">%1$d</xliff:g> til <xliff:g id="TO_USER">%2$d</xliff:g>)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"Núverandi prófíll"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"Slökkt er á <xliff:g id="SENSOR">%1$s</xliff:g>."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"Nota <xliff:g id="SENSOR">%1$s</xliff:g>"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"Fyrir forrit með heimild"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"Stillingar merkis: Kveikt á Wi-Fi"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"Stillingar merkis: Kveikt á heitum reit"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"Skjástillingar"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"Stillingar villuleitar"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"Hljóðstillingar"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"Akstursstilling"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"Þú getur ekki notað þennan eiginleika við akstur"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"Loka forriti"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Skjástillingar"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Hljóðstillingar"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Prófíl- og reikningsstillingar"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Forritunarkostir"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"Mynstur styður ekki snúning, notaðu snertingu"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"Skjárinn er læstur"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"Skjánum hjá þér var læst"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"Ekki er hægt að opna gestaprófíl. Reyndu aftur síðar."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"Skráir út…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"Verið er að skrá „<xliff:g id="USER_NAME">%s</xliff:g>“ út. Reyndu aftur síðar."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Notandi ekki tiltækur sem stendur"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Ekki tókst að ræsa öruggan notanda á skjá farþega"</string>
     <string name="seat_driver" msgid="4502591979520445677">"ökumannssæti"</string>
     <string name="seat_front" msgid="836133281052793377">"framsæti"</string>
     <string name="seat_rear" msgid="403133444964528577">"í aftursæti"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"Allur skjárinn"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Sjá áskriftir"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Netáskriftin þín rann út"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"Þetta forrit þarfnast nettengingar"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s þarf nettengingu"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Þetta forrit"</string>
 </resources>
diff --git a/res/values-it/strings.xml b/res/values-it/strings.xml
index 4cfde59a..8cdb67cf 100644
--- a/res/values-it/strings.xml
+++ b/res/values-it/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{È possibile creare un solo profilo.}other{Puoi aggiungere massimo # profili.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"Caricamento"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"Caricamento dell\'utente (da <xliff:g id="FROM_USER">%1$d</xliff:g> a <xliff:g id="TO_USER">%2$d</xliff:g>)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"Profilo corrente"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g> spento."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"Usa <xliff:g id="SENSOR">%1$s</xliff:g>"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"Per le app provviste di autorizzazione"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"Impostazioni segnale: Wi-Fi ON"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"Impostazioni segnale: hotspot ON"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"Impostazioni display"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"Impostazioni di debug"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"Impostazioni audio"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"Modalità di guida"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"Non è possibile usare questa funzionalità durante la guida"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"Chiudi app"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Impostazioni Display"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Impostazioni audio"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Impostazioni del profilo e dell\'account"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Opzioni sviluppatore"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"Sequ. non supporta input rotatorio: usa tocco"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"Il tuo schermo è bloccato"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"Lo schermo è stato bloccato"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"Impossibile avviare profilo ospite. Riprova più tardi."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"Uscita…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> è in uscita. Riprova più tardi."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Utente al momento non disponibile"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Impossibile avviare la protezione utente sul display del passeggero"</string>
     <string name="seat_driver" msgid="4502591979520445677">"conducente"</string>
     <string name="seat_front" msgid="836133281052793377">"anteriore"</string>
     <string name="seat_rear" msgid="403133444964528577">"posteriore"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"Schermo intero"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Vedi i piani"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Il tuo piano internet è scaduto"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"Questa app necessita di una connessione a internet"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s richiede una connessione a internet"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Quest\'app"</string>
 </resources>
diff --git a/res/values-iw/strings.xml b/res/values-iw/strings.xml
index 4c579b4b..96024a6d 100644
--- a/res/values-iw/strings.xml
+++ b/res/values-iw/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{ניתן ליצור רק פרופיל אחד.}one{ניתן להוסיף עד # פרופילים.}two{ניתן להוסיף עד # פרופילים.}other{ניתן להוסיף עד # פרופילים.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"בטעינה"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"המשתמש בטעינה (מהמשתמש <xliff:g id="FROM_USER">%1$d</xliff:g> אל <xliff:g id="TO_USER">%2$d</xliff:g>)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"הפרופיל הנוכחי"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"ה<xliff:g id="SENSOR">%1$s</xliff:g> במצב כבוי."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"שימוש ב<xliff:g id="SENSOR">%1$s</xliff:g>"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"לאפליקציות שקיבלו הרשאה"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"הגדרות האות: Wi-Fi פועל"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"הגדרות האות: נקודת אינטרנט פועלת"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"הגדרות התצוגה"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"ההגדרות של ניפוי הבאגים"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"הגדרות צליל"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"מצב נהיגה"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"אי אפשר להשתמש בתכונה הזו במהלך הנהיגה"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"סגירת האפליקציה"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"הגדרות תצוגה"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"הגדרות צליל"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"הגדרות פרופילים וחשבונות"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"אפשרויות למפתחים"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"אין תמיכה בקו ביטול נעילה סיבובי. יש להשתמש במגע"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"המסך שלך נעול"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"המסך ננעל"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"לא ניתן להפעיל פרופיל אורח. צריך לנסות שוב מאוחר יותר."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"בתהליך יציאה…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"מתבצעת יציאה מהמערכת של <xliff:g id="USER_NAME">%s</xliff:g>. צריך לנסות שוב מאוחר יותר."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"המשתמש לא זמין כרגע"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"אי אפשר להציג פרופיל של משתמש מאובטח במסך של הנוסע"</string>
     <string name="seat_driver" msgid="4502591979520445677">"נהג/ת"</string>
     <string name="seat_front" msgid="836133281052793377">"חלק קדמי"</string>
     <string name="seat_rear" msgid="403133444964528577">"חלק אחורי"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"מסך מלא"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"להצגת חבילות הגלישה"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"חבילת הגלישה שלך כבר לא תקפה"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"כדי להשתמש באפליקציה הזו צריך חיבור לאינטרנט"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"ל-%s נדרש חיבור לאינטרנט"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"האפליקציה הזו"</string>
 </resources>
diff --git a/res/values-ja/strings.xml b/res/values-ja/strings.xml
index b7b42871..a01bc0c4 100644
--- a/res/values-ja/strings.xml
+++ b/res/values-ja/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{作成できるプロファイルは 1 件のみです。}other{追加できるプロファイルは # 件までです。}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"読み込んでいます"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"ユーザーを読み込んでいます（<xliff:g id="FROM_USER">%1$d</xliff:g>～<xliff:g id="TO_USER">%2$d</xliff:g>）"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"現在のプロファイル"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g>は OFF です。"</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"<xliff:g id="SENSOR">%1$s</xliff:g>の使用"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"権限が付与されているアプリ"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"電波状況の設定: Wi-Fi ON"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"電波状況の設定: アクセス ポイント ON"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"ディスプレイの設定"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"デバッグ設定"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"音声の設定"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"運転モード"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"運転中はこの機能を利用できません"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"アプリを閉じる"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"ディスプレイの設定"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"音声の設定"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"プロフィールとアカウントの設定"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"開発者向けオプション"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"パターンは回転に非対応 - タップしてください"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"画面をロックしました"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"画面はロックされています"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"ゲスト プロファイルを開始できません。しばらくしてからもう一度お試しください。"</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"ログアウトしています…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> さんはログアウト中です。しばらくしてからもう一度お試しください。"</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"現在、このユーザーは利用できません"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"助手席のディスプレイでセキュア ユーザーを開始できません"</string>
     <string name="seat_driver" msgid="4502591979520445677">"ドライバー"</string>
     <string name="seat_front" msgid="836133281052793377">"前"</string>
     <string name="seat_rear" msgid="403133444964528577">"後"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"全画面表示"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"プランを見る"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"ご利用のインターネット プランの期限が切れています"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"このアプリを使用するにはインターネット接続が必要です"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s を使用するには、インターネット接続が必要です"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"このアプリ"</string>
 </resources>
diff --git a/res/values-ka/strings.xml b/res/values-ka/strings.xml
index ed566fe2..2b9cc421 100644
--- a/res/values-ka/strings.xml
+++ b/res/values-ka/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{შესაძლებელია მხოლოდ ერთი პროფილის შექმნა.}other{შეგიძლიათ დაამატოთ #-მდე პროფილი.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"იტვირთება"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"იტვირთება მომხმარებელი (<xliff:g id="FROM_USER">%1$d</xliff:g>-დან <xliff:g id="TO_USER">%2$d</xliff:g>-მდე)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"მიმდინარე პროფილი"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g> გამორთულია."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"<xliff:g id="SENSOR">%1$s</xliff:g>-ის გამოყენება"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"ნებადართული აპებისთვის"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"სიგნალის პარამეტრები: Wifi ჩართულია"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"სიგნალის პარამეტრები: უსადენო ქსელი ჩართულია"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"ჩვენების პარამეტრები"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"გამართვის პარამეტრები"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"ხმის პარამეტრები"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"საავტომობილო რეჟიმი"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"მანქანის მართვისას ამ ფუნქციას ვერ გამოიყენებთ"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"აპის დახურვა"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"ეკრანის პარამეტრები"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"ხმის პარამეტრები"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"პროფილებისა და ანგარიშების პარამეტრები"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"დეველოპერთა პარამეტრები"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"ნიმუშს არ აქვს როტაციულის მხარდაჭერა; ისარგებლეთ შეხებით"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"თქვენი ეკრანი ჩაკეტილია"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"თქვენი ეკრანი ჩაიკეტა"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"სტუმრის პროფილის დაწყება შეუძლებელია. სცადეთ მოგვიანებით."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"გასვლა…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> მიმდინარეობს გასვლა. სცადეთ მოგვიანებით."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"მომხმარებელი ამჟამად მიუწვდომელია"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"მგზავრის ეკრანზე უსაფრთხო მომხმარებლის გაშვება ვერ მოხერხდა"</string>
     <string name="seat_driver" msgid="4502591979520445677">"მძღოლი"</string>
     <string name="seat_front" msgid="836133281052793377">"წინა"</string>
     <string name="seat_rear" msgid="403133444964528577">"უკანა"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"სრულ ეკრანზე"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"გეგმების ნახვა"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"თქვენს ინტერნეტის გეგმას ვადა გაუვიდა"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"ამ აპს სჭირდება ინტერნეტ-კავშირი"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s საჭიროებს ინტერნეტ-კავშირს"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"ეს აპი"</string>
 </resources>
diff --git a/res/values-kk/strings.xml b/res/values-kk/strings.xml
index ca00b527..3225c40e 100644
--- a/res/values-kk/strings.xml
+++ b/res/values-kk/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{Тек бір профиль жасауға болады.}other{Ең көбі # профиль қосуға болады.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"Жүктелуде"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"Пайдаланушы профилі жүктелуде (<xliff:g id="FROM_USER">%1$d</xliff:g> – <xliff:g id="TO_USER">%2$d</xliff:g>)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"Қазіргі профиль"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g> өшірулі."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"<xliff:g id="SENSOR">%1$s</xliff:g> пайдалану"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"Рұқсаты бар қолданбалар үшін"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"Сигнал параметрлері: Wi‑Fi қосулы"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"Сигнал параметрлері: хотспот қосулы"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"Дисплей параметрлері"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"Түзету параметрлері"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"Дыбыс параметрлері"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"Автокөлік режимі"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"Бұл функцияны көлік жүргізген кезде пайдалана алмайсыз."</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"Қолданбаны жабу"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Дисплей параметрлері"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Дыбыс параметрлері"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Профиль мен аккаунт параметрлері"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Әзірлеуші опциялары"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"Өрнекті айналма түймемен емес, түрту арқылы салу керек."</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"Экран құлыптаулы"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"Экраныңыз құлыпталды"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"Қонақ профилін іске қосу мүмкін емес. Кейінірек қайталап көріңіз."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"Аккаунттан шығып жатырсыз…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> аккаунттан шығып жатыр. Кейінірек қайталап көріңіз."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Пайдаланушы қазіргі уақытта қолжетімді емес."</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Жолаушы дисплейінде қауіпсіз пайдаланушыны іске қосу мүмкін емес."</string>
     <string name="seat_driver" msgid="4502591979520445677">"жүргізуші"</string>
     <string name="seat_front" msgid="836133281052793377">"алдыңғы"</string>
     <string name="seat_rear" msgid="403133444964528577">"артқы"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"Толық экран"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Жоспарларды көру"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Интернет тарифтік жоспарыңыздың мерзімі аяқталды."</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"Бұл қолданбаға интернет байланысы қажет."</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s үшін интернет байланысы қажет."</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Осы қолданба"</string>
 </resources>
diff --git a/res/values-km/strings.xml b/res/values-km/strings.xml
index 24f89969..9e3b9cae 100644
--- a/res/values-km/strings.xml
+++ b/res/values-km/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{អាចបង្កើតកម្រងព័ត៌មានបានតែ​មួយ​ប៉ុណ្ណោះ។}other{អ្នកអាច​បញ្ចូល​កម្រងព័ត៌មាន​បានរហូតដល់ #។}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"កំពុងផ្ទុក"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"កំពុងផ្ទុក​អ្នកប្រើប្រាស់ (ពី <xliff:g id="FROM_USER">%1$d</xliff:g> ដល់ <xliff:g id="TO_USER">%2$d</xliff:g>)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"កម្រងព័ត៌មានបច្ចុប្បន្ន"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g> ត្រូវបានបិទ។"</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"ប្រើ <xliff:g id="SENSOR">%1$s</xliff:g>"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"សម្រាប់កម្មវិធី​ដែលមាន​ការអនុញ្ញាត"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"ការកំណត់រលកសញ្ញា៖ បានបើក Wi-Fi"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"ការកំណត់រលកសញ្ញា៖ បានបើកហតស្ប៉ត"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"ការកំណត់​ផ្ទាំងអេក្រង់"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"ការកំណត់ការជួសជុល"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"ការកំណត់​សំឡេង"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"មុខងារបើកបរ"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"អ្នកមិនអាចប្រើ​មុខងារនេះ​បានទេ ខណៈពេលកំពុង​បើកបរ"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"បិទកម្មវិធី"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"ការកំណត់​ផ្ទាំងអេក្រង់"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"ការកំណត់សំឡេង"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"ការកំណត់​គណនី និង​កម្រងព័ត៌មាន"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"ជម្រើសសម្រាប់អ្នកអភិវឌ្ឍន៍"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"មិនអាចបង្វិលលំនាំបានទេ សូមប្រើការចុច"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"អេក្រង់របស់អ្នក​ត្រូវបានចាក់សោ"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"អេក្រង់របស់អ្នកត្រូវបានចាក់សោ"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"មិនអាចចាប់ផ្ដើមកម្រងព័ត៌មានភ្ញៀវបានទេ។ សូមព្យាយាមម្តងទៀតនៅពេលក្រោយ។"</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"កំពុង​ចេញពីគណនី…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> កំពុងចេញពីគណនី។ សូមព្យាយាមម្តងទៀតនៅពេលក្រោយ។"</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"បច្ចុប្បន្ន មិនអាចជ្រើសរើសអ្នកប្រើប្រាស់នេះបានទេ"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"មិនអាចចាប់ផ្ដើមអ្នកប្រើប្រាស់ដែលមានការរក្សាសុវត្ថិភាពនៅលើផ្ទាំងអេក្រង់អ្នកដំណើរបានទេ"</string>
     <string name="seat_driver" msgid="4502591979520445677">"អ្នកបើកបរ"</string>
     <string name="seat_front" msgid="836133281052793377">"មុខ"</string>
     <string name="seat_rear" msgid="403133444964528577">"ក្រោយ"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"អេក្រង់ពេញ"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"មើល​គម្រោង"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"គម្រោងអ៊ីនធឺណិតរបស់អ្នកផុតកំណត់ហើយ"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"កម្មវិធីនេះត្រូវការការតភ្ជាប់អ៊ីនធឺណិត"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s ត្រូវការការតភ្ជាប់អ៊ីនធឺណិត"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"កម្មវិធីនេះ"</string>
 </resources>
diff --git a/res/values-kn/strings.xml b/res/values-kn/strings.xml
index 9fc7db2f..2df6c99b 100644
--- a/res/values-kn/strings.xml
+++ b/res/values-kn/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{ಒಂದು ಪ್ರೊಫೈಲ್ ಅನ್ನು ಮಾತ್ರ ರಚಿಸಬಹುದು.}one{ನೀವು ಗರಿಷ್ಠ # ಪ್ರೊಫೈಲ್‌ಗಳನ್ನು ಸೇರಿಸಬಹುದು.}other{ನೀವು ಗರಿಷ್ಠ # ಪ್ರೊಫೈಲ್‌ಗಳನ್ನು ಸೇರಿಸಬಹುದು.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"ಲೋಡ್ ಆಗುತ್ತಿದೆ"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"ಬಳಕೆದಾರರನ್ನು ಲೋಡ್ ಮಾಡಲಾಗುತ್ತಿದೆ (<xliff:g id="FROM_USER">%1$d</xliff:g> ನಿಂದ <xliff:g id="TO_USER">%2$d</xliff:g> ವರೆಗೆ)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"ಪ್ರಸ್ತುತ ಪ್ರೊಫೈಲ್"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g> ಆಫ್ ಆಗಿದೆ."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"<xliff:g id="SENSOR">%1$s</xliff:g> ಅನ್ನು ಬಳಸಿ"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"ಅನುಮತಿಯನ್ನು ಹೊಂದಿರುವ ಆ್ಯಪ್‌ಗಳಿಗಾಗಿ"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"ಸಿಗ್ನಲ್ ಸೆಟ್ಟಿಂಗ್‌ಗಳು: ವೈ-ಫೈ ಆನ್ ಆಗಿದೆ"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"ಸಿಗ್ನಲ್ ಸೆಟ್ಟಿಂಗ್‌ಗಳು: ಹಾಟ್‌ಸ್ಪಾಟ್ ಆನ್ ಆಗಿದೆ"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"ಡಿಸ್‌ಪ್ಲೇ ಸೆಟ್ಟಿಂಗ್‌ಗಳು"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"ಸೆಟ್ಟಿಂಗ್‌ಗಳನ್ನು ಡೀಬಗ್ ಮಾಡಿ"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"ಧ್ವನಿ ಸೆಟ್ಟಿಂಗ್‌ಗಳು"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"ಡ್ರೈವ್ ಮೋಡ್"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"ಡ್ರೈವ್ ಮಾಡುವಾಗ ನೀವು ಈ ಫೀಚರ್ ಅನ್ನು ಬಳಸಲಾಗುವುದಿಲ್ಲ"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"ಆ್ಯಪ್ ಅನ್ನು ಮುಚ್ಚಿರಿ"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"ಡಿಸ್‌ಪ್ಲೇ ಸೆಟ್ಟಿಂಗ್‌ಗಳು"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"ಸೌಂಡ್ ಸೆಟ್ಟಿಂಗ್‌ಗಳು"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"ಪ್ರೊಫೈಲ್‌ಗಳು ಮತ್ತು ಖಾತೆಗಳ ಸೆಟ್ಟಿಂಗ್‌ಗಳು"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"ಡೆವಲಪರ್ ಆಯ್ಕೆಗಳು"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"ಪ್ಯಾಟರ್ನ್ ರೋಟರಿಯನ್ನು ಬೆಂಬಲಿಸುವುದಿಲ್ಲ, ಸ್ಪರ್ಶಿಸಿ"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"ನಿಮ್ಮ ಸ್ಕ್ರೀನ್ ಲಾಕ್ ಆಗಿದೆ"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"ನಿಮ್ಮ ಸ್ಕ್ರೀನ್ ಅನ್ನು ಲಾಕ್ ಮಾಡಲಾಗಿದೆ"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"ಅತಿಥಿ ಪ್ರೊಫೈಲ್ ಪ್ರಾರಂಭಿಸಲು ಸಾಧ್ಯವಿಲ್ಲ ನಂತರ ಪುನಃ ಪ್ರಯತ್ನಿಸಿ."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"ಸೈನ್ ಔಟ್ ಆಗುತ್ತಿದೆ…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> ಅವರ ಸೈನ್ ಔಟ್ ಆಗುತ್ತಿದ್ದಾರೆ. ನಂತರ ಪುನಃ ಪ್ರಯತ್ನಿಸಿ."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"ಬಳಕೆದಾರರು ಪ್ರಸ್ತುತ ಲಭ್ಯವಿಲ್ಲ"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"ಪ್ರಯಾಣಿಕರ ಡಿಸ್‌ಪ್ಲೇನಲ್ಲಿ ಸುರಕ್ಷಿತ ಬಳಕೆದಾರರನ್ನು ಪ್ರಾರಂಭಿಸಲು ಸಾಧ್ಯವಿಲ್ಲ"</string>
     <string name="seat_driver" msgid="4502591979520445677">"ಡ್ರೈವರ್"</string>
     <string name="seat_front" msgid="836133281052793377">"ಮುಂದೆ"</string>
     <string name="seat_rear" msgid="403133444964528577">"ಹಿಂಭಾಗ"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"ಪೂರ್ಣ ಸ್ಕ್ರೀನ್"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"ಪ್ಲಾನ್‌ಗಳನ್ನು ನೋಡಿ"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"ನಿಮ್ಮ ಇಂಟರ್ನೆಟ್ ಪ್ಲಾನ್ ಅವಧಿ ಮುಗಿದಿದೆ"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"ಈ ಆ್ಯಪ್‌ಗೆ ಇಂಟರ್‌ನೆಟ್ ಕನೆಕ್ಷನ್‌ನ ಅಗತ್ಯವಿದೆ"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s ಗೆಇಂಟರ್‌ನೆಟ್ ಕನೆಕ್ಷನ್‌ನ ಅಗತ್ಯವಿದೆ"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"ಈ ಆ್ಯಪ್"</string>
 </resources>
diff --git a/res/values-ko/strings.xml b/res/values-ko/strings.xml
index 09c5f2a2..a336088a 100644
--- a/res/values-ko/strings.xml
+++ b/res/values-ko/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{프로필은 1개만 만들 수 있습니다.}other{프로필은 #개까지 만들 수 있습니다.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"로드 중"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"사용자 로드 중(<xliff:g id="FROM_USER">%1$d</xliff:g>님에서 <xliff:g id="TO_USER">%2$d</xliff:g>님으로)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"현재 프로필"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g>이(가) 꺼져 있습니다."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"<xliff:g id="SENSOR">%1$s</xliff:g> 사용"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"권한 있는 앱용"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"신호 설정: Wi-Fi 켜짐"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"신호 설정: 핫스팟 켜짐"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"디스플레이 설정"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"디버그 설정"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"사운드 설정"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"주행 모드"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"운전 중에는 이 기능을 사용하실 수 없습니다."</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"앱 닫기"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"디스플레이 설정"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"소리 설정"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"프로필 및 계정 설정"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"개발자 옵션"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"로터리 패턴은 지원되지 않습니다. 터치를 사용하세요."</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"화면이 잠겨 있음"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"화면 잠김"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"게스트 프로필을 시작할 수 없습니다. 나중에 다시 시도해 주세요."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"로그아웃 중…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g>님이 로그아웃 중입니다. 나중에 다시 시도해 주세요."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"사용자를 현재 선택할 수 없음"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"승객 디스플레이에서 보안 사용자를 선택할 수 없음"</string>
     <string name="seat_driver" msgid="4502591979520445677">"드라이버"</string>
     <string name="seat_front" msgid="836133281052793377">"전면"</string>
     <string name="seat_rear" msgid="403133444964528577">"후면"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"전체 화면"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"요금제 보기"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"인터넷 요금제가 만료되었습니다."</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"이 앱을 사용하려면 인터넷 연결이 필요합니다."</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s에 인터넷 연결이 필요합니다."</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"이 앱"</string>
 </resources>
diff --git a/res/values-ky/strings.xml b/res/values-ky/strings.xml
index 6527f46b..0fd4d833 100644
--- a/res/values-ky/strings.xml
+++ b/res/values-ky/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{Бир профилди гана түзүүгө болот.}other{# профилге чейин кошууга болот.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"Жүктөлүүдө"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"Колдонуучу тууралуу маалымат жүктөлүүдө (<xliff:g id="FROM_USER">%1$d</xliff:g> – <xliff:g id="TO_USER">%2$d</xliff:g>)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"Учурдагы профиль"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g> өчүк."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"<xliff:g id="SENSOR">%1$s</xliff:g> колдонуу"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"Уруксаты бар колдонмолор үчүн"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"Сигналдын параметрлери: Wifi күйүк"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"Сигналдын параметрлери: Хоспот күйүк"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"Көрүнүш параметрлери"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"Мүчүлүштүктөрдү оңдоо параметрлери"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"Үн параметрлери"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"Айдоо режими"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"Бул функцияны унаа айдап баратканда колдоно албайсыз"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"Колдонмону жабуу"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Көрүнүш параметрлери"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Добуштун параметрлери"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Профилдердин жана аккаунттардын параметрлери"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Иштеп чыгуучунун параметрлери"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"Графикалык ачкычта буруу колдоого алынбайт; тийүүнү колдонуңуз"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"Экраныңыз кулпуланды"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"Экраныңыз кулпуланды"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"Конок профили иштебей жатат. Кийинчерээк кайталап көрүңүз."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"Чыгып жатасыз…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> чыгып жатат. Кийинчерээк кайталап көрүңүз."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Учурда колдонуучу жеткиликсиз"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Жүргүнчүлөрдүн дисплейинде корголгон колдонуучуну ишке киргизүү мүмкүн эмес"</string>
     <string name="seat_driver" msgid="4502591979520445677">"айдоочу"</string>
     <string name="seat_front" msgid="836133281052793377">"маңдайкы"</string>
     <string name="seat_rear" msgid="403133444964528577">"арткы"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"Толук экран"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Тарифтик пландарды көрүү"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Интернет үчүн тарифтик планыңыздын мөөнөтү бүттү"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"Бул колдонмону иштетүү үчүн Интернет байланышы керек"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s үчүн Интернет байланышы керек"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Ушул колдонмо"</string>
 </resources>
diff --git a/res/values-lo/strings.xml b/res/values-lo/strings.xml
index 3143f11f..3f26a22b 100644
--- a/res/values-lo/strings.xml
+++ b/res/values-lo/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{ສາມາດສ້າງໄດ້ພຽງໂປຣໄຟລ໌ດຽວເທົ່ານັ້ນ.}other{ທ່ານ​ສາ​ມາດ​ເພີ່ມ​ໄດ້​ເຖິງ # ໂປຣໄຟລ໌.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"ກຳລັງໂຫຼດ"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"ກຳລັງໂຫຼດຜູ້ໃຊ້ (ຈາກ <xliff:g id="FROM_USER">%1$d</xliff:g> ໄປຍັງ <xliff:g id="TO_USER">%2$d</xliff:g>)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"ໂປຣໄຟລ໌ປັດຈຸບັນ"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g> ປິດຢູ່."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"ໃຊ້ <xliff:g id="SENSOR">%1$s</xliff:g>"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"ສຳລັບແອັບທີ່ມີການອະນຸຍາດ"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"ການຕັ້ງຄ່າສັນຍານ: Wi-Fi ເປີດຢູ່"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"ການຕັ້ງຄ່າສັນຍານ: ຮັອດສະປອດເປີດຢູ່"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"ການຕັ້ງຄ່າສະແດງຜົນ"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"ການຕັ້ງຄ່າດີບັກ"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"ການຕັ້ງຄ່າສຽງ"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"ໂໝດຂັບຂີ່"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"ທ່ານບໍ່ສາມາດໃຊ້ຄຸນສົມບັດນີ້ໃນຂະນະທີ່ຂັບລົດໄດ້"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"ປິດແອັບ"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"ການຕັ້ງຄ່າສະແດງຜົນ"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"ການຕັ້ງຄ່າສຽງ"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"ການຕັ້ງຄ່າໂປຣໄຟລ໌ ແລະ ບັນຊີ"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"ຕົວເລືອກນັກພັດທະນາ"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"ຮູບແບບບໍ່ຮອງຮັບປຸ່ມໝຸນ, ກະລຸນາໃຊ້ໜ້າຈໍສຳຜັດ"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"ໜ້າຈໍຂອງທ່ານລັອກຢູ່"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"ໜ້າຈໍຂອງທ່ານຖືກລັອກ"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"ບໍ່ສາມາດເລີ່ມໂປຣໄຟລ໌ແຂກໄດ້. ກະລຸນາລອງໃໝ່ໃນພາຍຫຼັງ."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"ກຳລັງອອກຈາກລະບົບ…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> ກຳລັງຖືກໃຫ້ອອກຈາກລະບົບ. ກະລຸນາລອງໃໝ່ໃນພາຍຫຼັງ."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"ຜູ້ໃຊ້ບໍ່ພ້ອມນຳໃຊ້ໃນຕອນນີ້"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"ບໍ່ສາມາດເປີດນຳໃຊ້ຜູ້ໃຊ້ທີ່ປອດໄພຢູ່ຈໍສະແດງຜົນສຳລັບຜູ້ໂດຍສານໄດ້"</string>
     <string name="seat_driver" msgid="4502591979520445677">"ຄົນຂັບລົດ"</string>
     <string name="seat_front" msgid="836133281052793377">"ໜ້າ"</string>
     <string name="seat_rear" msgid="403133444964528577">"ທາງຫຼັງ"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"ເຕັມຈໍ"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"ເບິ່ງແພັກເກດ"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"ແພັກເກດອິນເຕີເນັດຂອງທ່ານໝົດອາຍຸແລ້ວ"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"ແອັບນີ້ຕ້ອງໃຊ້ການເຊື່ອມຕໍ່ອິນເຕີເນັດ"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s ຕ້ອງການການເຊື່ອມຕໍ່ອິນເຕີເນັດ"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"ແອັບນີ້"</string>
 </resources>
diff --git a/res/values-lt/strings.xml b/res/values-lt/strings.xml
index ed9eca8d..24abbbb0 100644
--- a/res/values-lt/strings.xml
+++ b/res/values-lt/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{Galima sukurti tik vieną profilį.}one{Galite pridėti iki # profilio.}few{Galite pridėti iki # profilių.}many{Galite pridėti iki # profilio.}other{Galite pridėti iki # profilių.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"Įkeliama"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"Įkeliamas naudotojo profilis (<xliff:g id="FROM_USER">%1$d</xliff:g> – <xliff:g id="TO_USER">%2$d</xliff:g>)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"Dabartinis profilis"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g> – išjungta."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"Naudoti: <xliff:g id="SENSOR">%1$s</xliff:g>"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"Programoms, turinčioms leidimą"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"Signalų nustatymai: „Wi-Fi“ įjungtas"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"Signalų nustatymai: viešosios interneto prieigos taškas įjungtas"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"Vaizdo nustatymai"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"Derinti nustatymus"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"Garso nustatymai"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"Vairavimo režimas"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"Negalite naudoti šios funkcijos vairuodami"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"Uždaryti programą"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Vaizdo nustatymai"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Garso nustatymai"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Profilių ir paskyrų nustatymai"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Kūrėjo parinktys"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"Atr. pieš. negalima nubr. sukam. įvest. vald."</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"Jūsų ekranas užrakintas"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"Jūsų ekranas užrakintas"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"Nepavyko paleisti svečio profilio. Vėliau bandykite dar kartą."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"Atsijungiama…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> atsijungė. Vėliau bandykite dar kartą."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Naudotojas šiuo metu nepasiekiamas"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Nepavyko pasiekti saugaus naudotojo keleivio ekrane"</string>
     <string name="seat_driver" msgid="4502591979520445677">"vairuotojas"</string>
     <string name="seat_front" msgid="836133281052793377">"priekis"</string>
     <string name="seat_rear" msgid="403133444964528577">"galas"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"Visas ekranas"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Peržiūrėti planus"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Jūsų interneto planas nebegalioja"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"Šiai programai reikalingas interneto ryšys"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s reikalingas interneto ryšys"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Šiai programai"</string>
 </resources>
diff --git a/res/values-lv/strings.xml b/res/values-lv/strings.xml
index 5a09203d..68bb24c0 100644
--- a/res/values-lv/strings.xml
+++ b/res/values-lv/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{Var izveidot tikai vienu profilu.}zero{Varat pievienot ne vairāk kā # profilus.}one{Varat pievienot ne vairāk kā # profilu.}other{Varat pievienot ne vairāk kā # profilus.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"Notiek ielāde…"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"Notiek lietotāja profila ielāde (<xliff:g id="FROM_USER">%1$d</xliff:g>–<xliff:g id="TO_USER">%2$d</xliff:g>)…"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"Pašreizējais profils"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g> ir izslēgtā stāvoklī."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"Izmantot šādu sensoru: <xliff:g id="SENSOR">%1$s</xliff:g>"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"Lietotnēm, kurām ir atļauja"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"Signāla iestatījums: ieslēgts Wi-Fi"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"Signāla iestatījums: ieslēgts tīklājs"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"Displeja iestatījumi"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"Atkļūdošanas iestatījumi"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"Skaņas iestatījumi"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"Braukšanas režīms"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"Jūs nevarat izmantot šo funkciju braukšanas laikā."</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"Aizvērt lietotni"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Displeja iestatījumi"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Skaņas iestatījumi"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Profilu un kontu iestatījumi"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Izstrādātāju opcijas"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"Tiek atbalstīta skārienievade, bet ne rotācija."</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"Jūsu ekrāns ir bloķēts"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"Jūsu ekrāns ir bloķēts"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"Nevar izveidot viesa profilu. Vēlāk mēģiniet vēlreiz."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"Notiek izrakstīšanās…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"Notiek lietotāja <xliff:g id="USER_NAME">%s</xliff:g> izrakstīšana. Vēlāk mēģiniet vēlreiz."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Lietotājs pašlaik nav pieejams"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Neizdodas izvēlēties drošu lietotāju pasažiera displejā."</string>
     <string name="seat_driver" msgid="4502591979520445677">"vadītāja sēdeklī"</string>
     <string name="seat_front" msgid="836133281052793377">"priekšējā sēdeklī"</string>
     <string name="seat_rear" msgid="403133444964528577">"aizmugurējā sēdeklī"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"Pilnekrāna režīms"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Skatīt plānus"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Beidzies jūsu interneta plāna derīguma termiņš"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"Šai lietotnei ir nepieciešams interneta savienojums"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s pieprasa interneta savienojumu"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Šī lietotne"</string>
 </resources>
diff --git a/res/values-mk/strings.xml b/res/values-mk/strings.xml
index da626c69..d66d45b6 100644
--- a/res/values-mk/strings.xml
+++ b/res/values-mk/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{Може да се создаде само еден профил.}one{Може да додадете најмногу # профил.}other{Може да додадете најмногу # профили.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"Се вчитува"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"Се вчитува корисникот (од <xliff:g id="FROM_USER">%1$d</xliff:g> до <xliff:g id="TO_USER">%2$d</xliff:g>)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"Тековен профил"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g> е исклучен."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"Користи <xliff:g id="SENSOR">%1$s</xliff:g>"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"за апликациите што имаат дозвола"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"Поставки за сигнал: Wi-Fi е вклучено"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"Поставки за сигнал: вклучена пристапна точка"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"Поставки за екран"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"Поставки за отстранување грешки"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"Поставки за звук"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"Режим на возење"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"Не може да ја користите функцијава додека возите"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"Затвори апликација"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Поставки за екран"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Поставки за звук"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Поставки за профили и сметки"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Програмерски опции"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"Шемата не поддржува вртење; користете допир"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"Вашиот екран е заклучен"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"Вашиот екран е заклучен"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"Не може да се започне гостински профил. Обидете се повторно подоцна."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"Се одјавува…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> се одјавува. Обидете се повторно подоцна."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Корисникот е недостапен во моментов"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Не може да се вклучи безбеден корисник на екранот на патниците"</string>
     <string name="seat_driver" msgid="4502591979520445677">"возачкото"</string>
     <string name="seat_front" msgid="836133281052793377">"предното"</string>
     <string name="seat_rear" msgid="403133444964528577">"задното"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"Цел екран"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Погледнете ги пакетите"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Вашиот интернет-пакет е истечен"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"Апликацијава има потреба од интернет-врска"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s бара интернет-врска"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Оваа апликација"</string>
 </resources>
diff --git a/res/values-ml/strings.xml b/res/values-ml/strings.xml
index 2c2ad528..86defd06 100644
--- a/res/values-ml/strings.xml
+++ b/res/values-ml/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{ഒരു പ്രൊഫൈൽ മാത്രമേ സൃഷ്‌ടിക്കാനാകൂ.}other{നിങ്ങൾക്ക് # പ്രൊഫൈലുകൾ വരെ ചേർക്കാനാകും.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"ലോഡ് ചെയ്യുന്നു"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"ഉപയോക്തൃ പ്രൊഫൈൽ ലോഡ് ചെയ്യുന്നു (<xliff:g id="FROM_USER">%1$d</xliff:g> എന്നതിൽ നിന്ന് <xliff:g id="TO_USER">%2$d</xliff:g> എന്നതിലേക്ക്)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"നിലവിലെ പ്രൊഫൈൽ"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g> ഓഫാണ്."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"<xliff:g id="SENSOR">%1$s</xliff:g> ഉപയോഗിക്കുക"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"അനുമതിയുള്ള ആപ്പുകൾക്ക്"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"സിഗ്നൽ ക്രമീകരണം: വൈഫൈ ഓണാണ്"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"സിഗ്നൽ ക്രമീകരണം: ഹോട്ട്സ്പോട്ട് ഓണാണ്"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"ഡിസ്‌പ്ലേ ക്രമീകരണം"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"ഡീബഗ് ക്രമീകരണം"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"ശബ്‌ദ ക്രമീകരണം"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"ഡ്രെെവ് മോഡ്"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"ഡ്രെെവ് ചെയ്യുമ്പോൾ നിങ്ങൾ ഈ ഫീച്ചർ ഉപയോഗിക്കരുത്"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"ആപ്പ് അടയ്‌ക്കുക"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"ഡിസ്‌പ്ലേ ക്രമീകരണം"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"ശബ്‌ദ ക്രമീകരണം"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"പ്രൊഫൈലുകളും അക്കൗണ്ടുകളും ക്രമീകരണം"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"ഡെവലപ്പർ ഓപ്ഷനുകൾ"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"റോട്ടറിക്ക് പാറ്റേണിന്റെ പിന്തുണയില്ല, ടച്ച് ഉപയോഗിക്കൂ"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"നിങ്ങളുടെ സ്ക്രീൻ ലോക്ക് ചെയ്തിരിക്കുന്നു"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"നിങ്ങളുടെ സ്ക്രീൻ ലോക്ക് ചെയ്തിരിക്കുന്നു"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"അതിഥി പ്രൊഫൈൽ ആരംഭിക്കാനാകില്ല. പിന്നീട് വീണ്ടും ശ്രമിക്കുക."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"സൈൻ ഔട്ട് ചെയ്യുന്നു…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> സൈൻ ഔട്ട് ചെയ്‌തു. പിന്നീട് വീണ്ടും ശ്രമിക്കുക."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"ഉപയോക്താവ് നിലവിൽ ലഭ്യമല്ല"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"പാസഞ്ചർ ഡിസ്‌പ്ലേയിൽ സുരക്ഷിത ഉപയോക്താവിനെ തിരഞ്ഞെടുക്കാനാകുന്നില്ല"</string>
     <string name="seat_driver" msgid="4502591979520445677">"ഡ്രൈവർ"</string>
     <string name="seat_front" msgid="836133281052793377">"മുൻവശം"</string>
     <string name="seat_rear" msgid="403133444964528577">"പിൻഭാഗം"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"പൂർണ്ണ സ്ക്രീൻ"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"പ്ലാനുകൾ കാണുക"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"നിങ്ങളുടെ ഇന്റർനെറ്റ് പ്ലാൻ കാലഹരണപ്പെട്ടു"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"ഈ ആപ്പിന് ഇന്റർനെറ്റ് കണക്ഷൻ ആവശ്യമാണ്"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s എന്നതിന് ഇന്റർനെറ്റ് കണക്ഷൻ ആവശ്യമാണ്"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"ഈ ആപ്പ്"</string>
 </resources>
diff --git a/res/values-mn/strings.xml b/res/values-mn/strings.xml
index 760cc491..c7b37123 100644
--- a/res/values-mn/strings.xml
+++ b/res/values-mn/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{Зөвхөн нэг профайл үүсгэх боломжтой.}other{Та # хүртэлх профайл нэмэх боломжтой.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"Ачаалж байна"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"Хэрэглэгчийг ачаалж байна (<xliff:g id="FROM_USER">%1$d</xliff:g>-с <xliff:g id="TO_USER">%2$d</xliff:g> хүртэл)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"Одоогийн профайл"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g> унтраалттай байна."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"<xliff:g id="SENSOR">%1$s</xliff:g>-г ашиглах"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"Зөвшөөрөлтэй аппуудад"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"Дохионы тохиргоо: Wifi асаалттай"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"Дохионы тохиргоо: Сүлжээний цэг асаалттай"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"Дэлгэцийн тохиргоо"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"Дебаг хийх тохиргоо"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"Дууны тохиргоо"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"Автомашин жолоодох горим"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"Та жолоо барьж байхдаа энэ онцлогийг ашиглах боломжгүй"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"Аппыг хаах"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Дэлгэцийн тохиргоо"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Дууны тохиргоо"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Профайл болон бүртгэлийн тохиргоо"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Хөгжүүлэгчийн тохиргоо"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"Хээ нь эргүүлэхийг дэмждэггүй. Хүрэлт ашиглана уу"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"Таны дэлгэцийг түгжсэн"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"Таны дэлгэцийг түгжсэн байна"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"Зочны профайлыг эхлүүлэх боломжгүй. Дараа дахин оролдоно уу."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"Гарч байна…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g>-г гаргаж байна. Дараа дахин оролдоно уу."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Хэрэглэгч одоогоор боломжгүй"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Зорчигчийн дэлгэц дээр аюулгүй хэрэглэгчийг эхлүүлэх боломжгүй"</string>
     <string name="seat_driver" msgid="4502591979520445677">"жолооч"</string>
     <string name="seat_front" msgid="836133281052793377">"урд тал"</string>
     <string name="seat_rear" msgid="403133444964528577">"ар тал"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"Бүтэн дэлгэц"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Багцыг харах"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Таны интернэт багцын хугацаа дууссан"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"Энэ аппад интернэт холболт шаардлагатай"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s-д интернэт холболт шаардлагатай"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Энэ апп"</string>
 </resources>
diff --git a/res/values-mr/strings.xml b/res/values-mr/strings.xml
index bdc1dc38..863d0ea2 100644
--- a/res/values-mr/strings.xml
+++ b/res/values-mr/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{फक्त एक प्रोफाइल तयार केली जाऊ शकते.}other{तुम्ही कमाल # प्रोफाइल जोडू शकता.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"लोड करत आहे"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"वापरकर्ता लोड करत आहे (<xliff:g id="FROM_USER">%1$d</xliff:g> पासून <xliff:g id="TO_USER">%2$d</xliff:g> पर्यंत)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"सद्य प्रोफाइल"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g> बंद आहे."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"<xliff:g id="SENSOR">%1$s</xliff:g> वापरा"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"परवानगी असलेल्या ॲप्ससाठी"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"सिग्नल सेटिंग्ज: Wifi सुरू आहे"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"सिग्नल सेटिंग्ज: हॉटस्पॉट सुरू आहे"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"डिस्प्ले सेटिंग्ज"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"सेटिंग्ज डीबग करा"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"आवाजाची सेटिंग्ज"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"ड्राइव्ह मोड"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"तुम्ही गाडी चालवत असताना हे वैशिष्ट्य वापरू शकत नाही"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"अ‍ॅप बंद करा"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"डिस्प्लेची सेटिंग्ज"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"आवाजाची सेटिंग्ज"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"प्रोफाइल आणि खात्यांची सेटिंग्ज"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"डेव्हलपर पर्याय"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"रोटरीला पॅटर्नचा सपोर्ट नाही; कृपया टच वापरा"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"तुमची स्क्रीन लॉक केली आहे"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"तुमची स्क्रीन लॉक केली आहे"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"अतिथी प्रोफाइल सुरू करू शकत नाही. नंतर पुन्हा प्रयत्न करा."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"साइन आउट करत आहे…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> यांना साइन आउट केले जात आहे. नंतर पुन्हा प्रयत्न करा."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"सध्या वापरकर्ता उपलब्ध नाही"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"प्रवासी डिस्प्लेवर सुरक्षित वापरकर्ता सुरू करता आला नाही"</string>
     <string name="seat_driver" msgid="4502591979520445677">"ड्रायव्हर"</string>
     <string name="seat_front" msgid="836133281052793377">"समोरचा"</string>
     <string name="seat_rear" msgid="403133444964528577">"मागचा डबा"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"फुल स्क्रीन"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"प्लॅन पहा"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"तुमचा इंटरनेट प्लॅन एक्स्पायर झाला आहे"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"या अ‍ॅपसाठी इंटरनेट कनेक्शन आवश्यक आहे"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s ला इंटरनेट कनेक्शन आवश्यक आहे"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"हे अ‍ॅप"</string>
 </resources>
diff --git a/res/values-ms/strings.xml b/res/values-ms/strings.xml
index 290794ed..cf2bf135 100644
--- a/res/values-ms/strings.xml
+++ b/res/values-ms/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{Hanya satu profil boleh dibuat.}other{Anda boleh menambahkan sehingga # profil.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"Memuatkan"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"Memuatkan pengguna (daripada <xliff:g id="FROM_USER">%1$d</xliff:g> hingga <xliff:g id="TO_USER">%2$d</xliff:g>)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"Profil semasa"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g> dimatikan."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"Gunakan <xliff:g id="SENSOR">%1$s</xliff:g>"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"Untuk apl yang mempunyai kebenaran"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"Tetapan Isyarat: Wi-Fi Dihidupkan"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"Tetapan Isyarat: Tempat Liputan Dihidupkan"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"Tetapan Paparan"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"Tetapan Nyahpepijat"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"Tetapan Bunyi"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"Mod Memandu"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"Anda tidak boleh menggunakan ciri ini semasa memandu"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"Tutup apl"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Tetapan paparan"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Tetapan bunyi"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Tetapan profil &amp; akaun"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Pilihan pembangun"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"Corak tak sokong putaran; guna sentuhan"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"Skrin anda dikunci"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"Skrin anda telah dikunci"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"Tidak dapat memulakan profil Tetamu. Cuba lagi nanti."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"Melog keluar…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> sedang dilog keluar. Cuba lagi nanti."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Pengguna tidak tersedia pada masa ini"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Tidak dapat memulakan pengguna pada paparan penumpang secara selamat"</string>
     <string name="seat_driver" msgid="4502591979520445677">"pemandu"</string>
     <string name="seat_front" msgid="836133281052793377">"hadapan"</string>
     <string name="seat_rear" msgid="403133444964528577">"belakang"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"Skrin Penuh"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Lihat pelan"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Pelan Internet anda telah tamat tempoh"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"Apl ini memerlukan sambungan Internet"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s memerlukan sambungan Internet"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Apl ini"</string>
 </resources>
diff --git a/res/values-my/strings.xml b/res/values-my/strings.xml
index d68ffdae..f3605501 100644
--- a/res/values-my/strings.xml
+++ b/res/values-my/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{ပရိုဖိုင်တစ်ခုသာ ပြုလုပ်နိုင်သည်။}other{ပရိုဖိုင် # ခုအထိ ထည့်နိုင်သည်။}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"ဖွင့်နေသည်"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"အသုံးပြုသူကို ဖွင့်နေသည် (<xliff:g id="FROM_USER">%1$d</xliff:g> မှ <xliff:g id="TO_USER">%2$d</xliff:g> သို့)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"လက်ရှိပရိုဖိုင်"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g> ပိတ်ထားသည်။"</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"<xliff:g id="SENSOR">%1$s</xliff:g> သုံးရန်"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"ခွင့်ပြုချက်ရှိသော အက်ပ်များအတွက်"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"ချိတ်ဆက်မှု ဆက်တင်များ- Wifi ဖွင့်ထားသည်"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"ချိတ်ဆက်မှု ဆက်တင်များ- ဟော့စပေါ့ ဖွင့်ထားသည်"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"ဖန်သားပြင်ပြသမှု ဆက်တင်များ"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"အမှားရှာပြင်သည့် ဆက်တင်များ"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"အသံဆက်တင်များ"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"မောင်းနှင်မုဒ်"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"ကားမောင်းနေစဉ် ဤဝန်ဆောင်မှုကို သုံး၍မရပါ"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"အက်ပ်ကိုပိတ်ရန်"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"ဖန်သားပြင်ပြသမှု ဆက်တင်များ"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"အသံဆက်တင်များ"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"ပရိုဖိုင်နှင့် အကောင့် ဆက်တင်များ"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"ဆော့ဖ်ဝဲရေးသူအတွက် ရွေးစရာများ"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"ပုံစံကလှည့်ပတ်မှုကို မထောက်ပံ့၍ ထိတွေ့မှုကိုသုံးပါ"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"သင့်ဖန်သားပြင် ပိတ်ထားသည်"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"စခရင် လော့ခ်ချထားသည်"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"‘ဧည့်သည်ပရိုဖိုင်’ စတင်၍မရပါ။ နောက်မှ ထပ်စမ်းကြည့်ပါ။"</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"ထွက်နေသည်…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> ထွက်နေသည်။ နောက်မှ ထပ်စမ်းကြည့်ပါ။"</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"အသုံးပြုသူကို လောလောဆယ် မရနိုင်ပါ"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"ခရီးသည် ဖန်သားပြင်တွင် လုံခြုံသော အသုံးပြုသူကို စတင်၍မရပါ"</string>
     <string name="seat_driver" msgid="4502591979520445677">"ယာဉ်မောင်းသူ"</string>
     <string name="seat_front" msgid="836133281052793377">"အရှေ့"</string>
     <string name="seat_rear" msgid="403133444964528577">"နောက်ဘက်"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"ဖန်သားပြင်အပြည့်"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"အစီအစဉ်များ ကြည့်ရန်"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"သင့်အင်တာနက်အစီအစဉ် သက်တမ်းကုန်သွားပါပြီ"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"ဤအက်ပ်သည် အင်တာနက်ချိတ်ဆက်မှု လိုအပ်သည်"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s သည် အင်တာနက်ချိတ်ဆက်မှု လိုအပ်သည်"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"ဤအက်ပ်"</string>
 </resources>
diff --git a/res/values-nb/strings.xml b/res/values-nb/strings.xml
index 7d5c513d..df1eb4dd 100644
--- a/res/values-nb/strings.xml
+++ b/res/values-nb/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{Du kan bare opprette én profil.}other{Du kan legge til opptil # profiler.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"Laster inn"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"Laster inn brukeren (fra <xliff:g id="FROM_USER">%1$d</xliff:g> til <xliff:g id="TO_USER">%2$d</xliff:g>)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"Nåværende profil"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g> er av."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"Bruk <xliff:g id="SENSOR">%1$s</xliff:g>"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"For apper som har tillatelse"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"Signalinnstillinger: wifi på"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"Signalinnstillinger: wifi-sone på"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"Skjerminnstillinger"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"Innstillinger for feilsøking"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"Lydinnstillinger"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"Kjøremodus"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"Du kan ikke bruke denne funksjonen når du kjører"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"Lukk appen"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Skjerminnstillinger"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Lydinnstillinger"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Profil- og kontoinnstillinger"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Utvikleralternativer"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"Mønsteret støtter ikke rotasjon. Bruk berøring."</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"Skjermen er låst"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"Skjermen er låst"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"Kan ikke åpne gjesteprofilen. Prøv på nytt senere."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"Logger av …"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> logges av. Prøv på nytt senere."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Brukeren er ikke tilgjengelig"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Kan ikke starte sikker bruker i passasjervisningen"</string>
     <string name="seat_driver" msgid="4502591979520445677">"for sjåføren"</string>
     <string name="seat_front" msgid="836133281052793377">"foran"</string>
     <string name="seat_rear" msgid="403133444964528577">"bak"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"Fullskjerm"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Se abonnementer"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Internettabonnementet ditt er utløpt"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"Denne appen krever internettilkobling"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s trenger internettilkobling"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Denne appen"</string>
 </resources>
diff --git a/res/values-ne/strings.xml b/res/values-ne/strings.xml
index 8f97f2ff..06029088 100644
--- a/res/values-ne/strings.xml
+++ b/res/values-ne/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{तपाईं एउटा मात्र प्रोफाइल बनाउन सक्नुहुन्छ।}other{तपाईं बढीमा # वटा प्रोफाइल थप्न सक्नुहुन्छ।}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"लोड गरिँदै"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"प्रयोगकर्तासम्बन्धी जानकारी लोड गरिँदै (<xliff:g id="FROM_USER">%1$d</xliff:g> बाट <xliff:g id="TO_USER">%2$d</xliff:g> मा)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"हालको प्रोफाइल"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g> अफ छ।"</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"<xliff:g id="SENSOR">%1$s</xliff:g> प्रयोग गर्नुहोस्"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"अनुमति प्राप्त एपहरूका हकमा"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"सिग्नलसम्बन्धी सेटिङ: Wifi अन छ"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"सिग्नलसम्बन्धी सेटिङ: हटस्पट अन छ"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"डिस्प्लेसम्बन्धी सेटिङ"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"डिबग सेटिङ"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"साउन्डसम्बन्धी सेटिङ"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"ड्राइभ मोड"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"तपाईं सवारी साधन चलाइरहेका बेला यो सुविधा प्रयोग गर्न सक्नुहुन्न"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"एप बन्द गर्नुहोस्"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"डिस्प्लेसम्बन्धी सेटिङ"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"ध्वनिसम्बन्धी सेटिङ"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"प्रोफाइल तथा खातासम्बन्धी सेटिङ"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"विकासकर्ता मोड"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"रोटरी प्रयोग गरी प्याटर्न कोर्न मिल्दैन, स्क्रिनमा छोएर कोर्नुहोस्"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"तपाईंको स्क्रिन लक गरिएको छ"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"तपाईंको स्क्रिन लक गरिएको छ"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"अतिथि प्रोफाइल सुरु गर्न सकिएन। पछि फेरि प्रयास गर्नुहोस्।"</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"साइन आउट गरिँदै छ…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> को प्रोफाइल साइन आउट गरिँदै छ। पछि फेरि प्रयास गर्नुहोस्।"</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"यी प्रयोगकर्ता हाल उपलब्ध हुनुहुन्न"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"यात्रुको जानकारी देखाइने डिस्प्लेमा \"सुरक्षित प्रयोगकर्ता\" सुरु गर्न सकिएन"</string>
     <string name="seat_driver" msgid="4502591979520445677">"चालकको सिट"</string>
     <string name="seat_front" msgid="836133281052793377">"अगाडिको सिट"</string>
     <string name="seat_rear" msgid="403133444964528577">"पछाडिको सिट"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"फुल स्क्रिन"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"योजनाहरू हेर्नुहोस्"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"तपाईंको इन्टरनेट योजनाको म्याद सकिएको छ"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"यो एप चलाउन इन्टरनेट कनेक्सन चाहिन्छ"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s चलाउन इन्टरनेट कनेक्सन चाहिन्छ"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"यो एप"</string>
 </resources>
diff --git a/res/values-nl/strings.xml b/res/values-nl/strings.xml
index b6b69af2..fa1ba5c1 100644
--- a/res/values-nl/strings.xml
+++ b/res/values-nl/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{Je kunt maar één profiel maken.}other{Je kunt maximaal # profielen toevoegen.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"Laden"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"Gebruiker laden (van <xliff:g id="FROM_USER">%1$d</xliff:g> naar <xliff:g id="TO_USER">%2$d</xliff:g>)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"Huidig profiel"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g> staat uit."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"<xliff:g id="SENSOR">%1$s</xliff:g> gebruiken"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"Voor apps die toestemming hebben"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"Signaalinstellingen: wifi aan"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"Signaalinstellingen: hotspot aan"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"Scherminstellingen"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"Instellingen voor foutopsporing"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"Geluidsinstellingen"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"Rijstand"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"Je kunt deze functie niet gebruiken tijdens het rijden"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"App sluiten"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Scherminstellingen"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Geluidsinstellingen"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Profiel- en accountinstellingen"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Ontwikkelaarsopties"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"Patroon ondersteunt geen draaien, gebruik tikken"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"Je scherm is vergrendeld"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"Je scherm is vergrendeld"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"Kan gastprofiel niet starten. Probeer het later opnieuw."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"Uitloggen…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> wordt uitgelogd. Probeer het later opnieuw."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Gebruiker op dit moment niet beschikbaar"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Kan beveiligde gebruiker niet starten op scherm van passagier"</string>
     <string name="seat_driver" msgid="4502591979520445677">"bestuurder"</string>
     <string name="seat_front" msgid="836133281052793377">"voor"</string>
     <string name="seat_rear" msgid="403133444964528577">"achter"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"Volledig scherm"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Abonnementen bekijken"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Je internetabonnement is verlopen"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"Deze app heeft een internetverbinding nodig"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s heeft een internetverbinding nodig"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Deze app"</string>
 </resources>
diff --git a/res/values-or/strings.xml b/res/values-or/strings.xml
index 41ef1672..8e6c56a6 100644
--- a/res/values-or/strings.xml
+++ b/res/values-or/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{କେବଳ ଗୋଟିଏ ପ୍ରୋଫାଇଲ ତିଆରି କରାଯାଇପାରିବ।}other{ଆପଣ #ଟି ପର୍ଯ୍ୟନ୍ତ ପ୍ରୋଫାଇଲ ଯୋଗ କରିପାରିବେ।}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"ଲୋଡ୍ କରାଯାଉଛି"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"ୟୁଜର ଲୋଡ କରାଯାଉଛି (<xliff:g id="FROM_USER">%1$d</xliff:g>ଙ୍କ ଠାରୁ <xliff:g id="TO_USER">%2$d</xliff:g> ପର୍ଯ୍ୟନ୍ତ)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"ବର୍ତ୍ତମାନର ପ୍ରୋଫାଇଲ"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g> ବନ୍ଦ ଅଛି।"</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"<xliff:g id="SENSOR">%1$s</xliff:g> ବ୍ୟବହାର କରନ୍ତୁ"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"ଅନୁମତି ଥିବା ଆପ୍ସ ପାଇଁ"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"ସିଗନାଲ ସେଟିଂସ: ୱାଇଫାଇ ଚାଲୁ ଅଛି"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"ସିଗନାଲ ସେଟିଂସ: ହଟସ୍ପଟ ଚାଲୁ ଅଛି"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"ଡିସପ୍ଲେ ସେଟିଂସ"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"ଡିବଗ ସେଟିଂସ"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"ସାଉଣ୍ଡ ସେଟିଂସ"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"ଡ୍ରାଇଭ ମୋଡ"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"ଆପଣ ଡ୍ରାଇଭ୍‍ କରିବା ସମୟରେ ଏହି ଫିଚର୍‍ ବ୍ୟବହାର କରିପାରିବେ ନାହିଁ"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"ଆପ୍‍ ବନ୍ଦ କରନ୍ତୁ"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"ଡିସପ୍ଲେ ସେଟିଂସ"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"ସାଉଣ୍ଡ ସେଟିଂସ"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"ପ୍ରୋଫାଇଲ ଏବଂ ଆକାଉଣ୍ଟ ସେଟିଂସ"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"ଡେଭେଲପର ବିକଳ୍ପ"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"ରୋଟାରୀକୁ ପାଟର୍ନ ସମର୍ଥନ କରେ ନାହିଁ, ସ୍ପର୍ଶ ବ୍ୟବହାର କର"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"ଆପଣଙ୍କ ସ୍କ୍ରିନକୁ ଲକ କରାଯାଇଛି"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"ଆପଣଙ୍କ ସ୍କ୍ରିନକୁ ଲକ କରାଯାଇଛି"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"ଅତିଥି ପ୍ରୋଫାଇଲ ଆରମ୍ଭ କରାଯାଇପାରିବ ନାହିଁ। ପରେ ପୁଣି ଚେଷ୍ଟା କରନ୍ତୁ।"</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"ସାଇନ ଆଉଟ କରାଯାଉଛି…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g>ଙ୍କୁ ସାଇନ ଆଉଟ କରାଯାଉଛି। ପରେ ପୁଣି ଚେଷ୍ଟା କରନ୍ତୁ।"</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"ୟୁଜର ବର୍ତ୍ତମାନ ଅନୁପଲବ୍ଧ"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"ପାସେଞ୍ଜର ଡିସପ୍ଲେରେ ସୁରକ୍ଷିତ ୟୁଜର ଆରମ୍ଭ କରିବାକୁ ଅସମର୍ଥ"</string>
     <string name="seat_driver" msgid="4502591979520445677">"ଡ୍ରାଇଭର"</string>
     <string name="seat_front" msgid="836133281052793377">"ସାମ୍ନା"</string>
     <string name="seat_rear" msgid="403133444964528577">"ପଛ"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"ପୂର୍ଣ୍ଣ ସ୍କ୍ରିନ"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"ପ୍ଲାନଗୁଡ଼ିକ ଦେଖନ୍ତୁ"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"ଆପଣଙ୍କର ଇଣ୍ଟର୍ନେଟ ପ୍ଲାନର ମିଆଦ ଶେଷ ହୋଇଯାଇଛି"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"ଏହି ଆପ ଏକ ଇଣ୍ଟର୍ନେଟ କନେକ୍ସନ ଆବଶ୍ୟକ କରେ"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s ଏକ ଇଣ୍ଟର୍ନେଟ କନେକ୍ସନ ଆବଶ୍ୟକ କରେ"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"ଏହି ଆପ"</string>
 </resources>
diff --git a/res/values-pa/strings.xml b/res/values-pa/strings.xml
index 2f116976..32280eb3 100644
--- a/res/values-pa/strings.xml
+++ b/res/values-pa/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{ਸਿਰਫ਼ ਇੱਕ ਪ੍ਰੋਫਾਈਲ ਬਣਾਇਆ ਜਾ ਸਕਦਾ ਹੈ।}one{ਤੁਸੀਂ # ਤੱਕ ਪ੍ਰੋਫਾਈਲ ਸ਼ਾਮਲ ਕਰ ਸਕਦੇ ਹੋ।}other{ਤੁਸੀਂ # ਤੱਕ ਪ੍ਰੋਫਾਈਲ ਸ਼ਾਮਲ ਕਰ ਸਕਦੇ ਹੋ।}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"ਲੋਡ ਕੀਤਾ ਜਾ ਰਿਹਾ ਹੈ"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"ਵਰਤੋਂਕਾਰ ਨੂੰ ਲੋਡ ਕੀਤਾ ਜਾ ਰਿਹਾ ਹੈ (<xliff:g id="FROM_USER">%1$d</xliff:g> ਤੋਂ <xliff:g id="TO_USER">%2$d</xliff:g> ਤੱਕ)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"ਮੌਜੂਦਾ ਪ੍ਰੋਫਾਈਲ"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g> ਬੰਦ ਹੈ।"</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"<xliff:g id="SENSOR">%1$s</xliff:g> ਵਰਤੋ"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"ਇਜਾਜ਼ਤ ਵਾਲੀਆਂ ਐਪਾਂ ਲਈ"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"ਸਿਗਨਲ ਸੈਟਿੰਗਾਂ: ਵਾਈ-ਫਾਈ ਚਾਲੂ ਹੈ"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"ਸਿਗਨਲ ਸੈਟਿੰਗਾਂ: ਹੌਟਸਪੌਟ ਚਾਲੂ ਹੈ"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"ਡਿਸਪਲੇ ਸੈਟਿੰਗਾਂ"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"ਡੀਬੱਗ ਸੈਟਿੰਗਾਂ"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"ਧੁਨੀ ਸੈਟਿੰਗਾਂ"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"ਡਰਾਈਵ ਮੋਡ"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"ਤੁਸੀਂ ਇਹ ਵਿਸ਼ੇਸ਼ਤਾ ਗੱਡੀ ਚਲਾਉਂਦੇ ਸਮੇਂ ਨਹੀਂ ਵਰਤ ਸਕਦੇ"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"ਐਪ ਬੰਦ ਕਰੋ"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"ਡਿਸਪਲੇ ਸੈਟਿੰਗਾਂ"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"ਧੁਨੀ ਸੈਟਿੰਗਾਂ"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"ਪ੍ਰੋਫਾਈਲ ਅਤੇ ਖਾਤਾ ਸੈਟਿੰਗਾਂ"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"ਵਿਕਾਸਕਾਰ ਵਿਕਲਪ"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"ਪੈਟਰਨ ਰੋਟਰੀ ਦਾ ਸਮਰਥਨ ਨਹੀਂ ਕਰਦਾ, ਕਿਰਪਾ ਕਰਕੇ ਸਪਰਸ਼ ਵਰਤੋ"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"ਤੁਹਾਡੀ ਸਕ੍ਰੀਨ ਲਾਕ ਹੈ"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"ਤੁਹਾਡੀ ਸਕ੍ਰੀਨ ਨੂੰ ਲਾਕ ਕਰ ਦਿੱਤਾ ਗਿਆ ਹੈ"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"ਮਹਿਮਾਨ ਪ੍ਰੋਫਾਈਲ ਬਣਾਇਆ ਨਹੀਂ ਜਾ ਸਕਦਾ। ਬਾਅਦ ਵਿੱਚ ਦੁਬਾਰਾ ਕੋਸ਼ਿਸ਼ ਕਰੋ।"</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"ਸਾਈਨ-ਆਊਟ ਕੀਤਾ ਜਾ ਰਿਹਾ ਹੈ…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> ਨੂੰ ਸਾਈਨ-ਆਊਟ ਕੀਤਾ ਜਾ ਰਿਹਾ ਹੈ। ਬਾਅਦ ਵਿੱਚ ਦੁਬਾਰਾ ਕੋਸ਼ਿਸ਼ ਕਰੋ।"</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"ਫ਼ਿਲਹਾਲ ਵਰਤੋਂਕਾਰ ਉਪਲਬਧ ਨਹੀਂ"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"ਯਾਤਰੀ ਡਿਸਪਲੇ \'ਤੇ ਸੁਰੱਖਿਅਤ ਵਰਤੋਂਕਾਰ ਨੂੰ ਸ਼ੁਰੂ ਨਹੀਂ ਕੀਤਾ ਜਾ ਸਕਿਆ"</string>
     <string name="seat_driver" msgid="4502591979520445677">"ਡਰਾਈਵਰ"</string>
     <string name="seat_front" msgid="836133281052793377">"ਅਗਲਾ"</string>
     <string name="seat_rear" msgid="403133444964528577">"ਪਿਛਲਾ"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"ਪੂਰੀ ਸਕ੍ਰੀਨ"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"ਪਲਾਨ ਦੇਖੋ"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"ਤੁਹਾਡੇ ਇੰਟਰਨੈੱਟ ਪਲਾਨ ਦੀ ਮਿਆਦ ਸਮਾਪਤ ਹੋ ਗਈ ਹੈ"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"ਇਸ ਐਪ ਲਈ ਇੰਟਰਨੈੱਟ ਕਨੈਕਸ਼ਨ ਦੀ ਲੋੜ ਹੈ"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s ਲਈ ਇੰਟਰਨੈੱਟ ਕਨੈਕਸ਼ਨ ਦੀ ਲੋੜ ਹੈ"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"ਇਹ ਐਪ"</string>
 </resources>
diff --git a/res/values-pl/strings.xml b/res/values-pl/strings.xml
index 0b450c77..7a374d66 100644
--- a/res/values-pl/strings.xml
+++ b/res/values-pl/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{Możesz utworzyć tylko 1 profil.}few{Możesz dodać maksymalnie # profile.}many{Możesz dodać maksymalnie # profili.}other{Możesz dodać maksymalnie # profilu.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"Ładuję"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"Ładuję użytkownika (od <xliff:g id="FROM_USER">%1$d</xliff:g> do <xliff:g id="TO_USER">%2$d</xliff:g>)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"Bieżący profil"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"Moduł <xliff:g id="SENSOR">%1$s</xliff:g> został wyłączony."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"Używaj modułu: <xliff:g id="SENSOR">%1$s</xliff:g>"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"Dotyczy aplikacji z uprawnieniami"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"Ustawienia sygnału: Wi-Fi włączone"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"Ustawienia sygnału: hotspot włączony"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"Ustawienia wyświetlacza"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"Ustawienia debugowania"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"Ustawienia dźwięku"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"Tryb samochodowy"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"Podczas jazdy nie można korzystać z tej funkcji"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"Zamknij aplikację"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Ustawienia wyświetlacza"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Ustawienia dźwięku"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Ustawienia profili i kont"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Opcje programisty"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"Wzór nie obsługuje pokrętła, użyj dotyku"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"Ekran jest zablokowany"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"Twój ekran został zablokowany"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"Nie udało się uruchomić profilu gościa. Spróbuj później."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"Wylogowuję…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> wylogowuje się. Spróbuj później."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Profil użytkownika jest w tej chwili niedostępny"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Nie udało się uruchomić bezpiecznego profilu użytkownika na ekranie pasażera"</string>
     <string name="seat_driver" msgid="4502591979520445677">"kierowcy"</string>
     <string name="seat_front" msgid="836133281052793377">"przednim"</string>
     <string name="seat_rear" msgid="403133444964528577">"tylnym"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"Pełny ekran"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Zobacz abonamenty"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Twój abonament internetowy stracił ważność"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"Ta aplikacja potrzebuje połączenia z internetem"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s wymaga połączenia z internetem"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Ta aplikacja"</string>
 </resources>
diff --git a/res/values-pt-rPT/strings.xml b/res/values-pt-rPT/strings.xml
index 321d6d93..b32c64bd 100644
--- a/res/values-pt-rPT/strings.xml
+++ b/res/values-pt-rPT/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{Apenas pode criar um perfil.}other{Pode adicionar até # perfis.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"A carregar…"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"A carregar o utilizador (de <xliff:g id="FROM_USER">%1$d</xliff:g> para <xliff:g id="TO_USER">%2$d</xliff:g>)…"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"Perfil atual"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g> desativado(a)."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"Usar <xliff:g id="SENSOR">%1$s</xliff:g>"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"Para as apps que têm autorização"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"Definições do sinal: Wi-Fi ativado"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"Definições do sinal: zona Wi-Fi ativada"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"Definições do ecrã"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"Definições de depuração"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"Definições de som"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"Modo de condução"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"Não pode usar esta funcionalidade enquanto conduz"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"Fechar app"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Definições do ecrã"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Definições de som"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Definições de perfis e contas"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Opções de programador"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"O padrão não sup. control. rotativo; use o toque"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"O ecrã está bloqueado"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"O ecrã foi bloqueado"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"Não é possível iniciar o perfil de convidado. Tente mais tarde."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"A terminar sessão…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"A sessão de <xliff:g id="USER_NAME">%s</xliff:g> está a ser terminada. Tente mais tarde."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Utilizador atualmente indisponível"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Não é possível iniciar o utilizador seguro no ecrã do passageiro"</string>
     <string name="seat_driver" msgid="4502591979520445677">"condutor"</string>
     <string name="seat_front" msgid="836133281052793377">"frente"</string>
     <string name="seat_rear" msgid="403133444964528577">"traseira"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"Ecrã inteiro"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Ver planos"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"O seu plano de Internet expirou"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"Esta app precisa de ligação à Internet"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s precisa de uma ligação à Internet"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Esta app"</string>
 </resources>
diff --git a/res/values-pt/strings.xml b/res/values-pt/strings.xml
index b23e69e0..007c82fa 100644
--- a/res/values-pt/strings.xml
+++ b/res/values-pt/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{Só um perfil pode ser criado.}one{É possível adicionar até # perfil.}other{É possível adicionar até # perfis.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"Carregando"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"Carregando usuário (de <xliff:g id="FROM_USER">%1$d</xliff:g> para <xliff:g id="TO_USER">%2$d</xliff:g>)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"Perfil atual"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"Desativado: <xliff:g id="SENSOR">%1$s</xliff:g>"</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"Usar <xliff:g id="SENSOR">%1$s</xliff:g>"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"Para apps com permissão"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"Configurações de sinal: Wi-Fi ativado"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"Configurações de sinal: ponto de acesso ativado"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"Configurações de tela"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"Configurações de depuração"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"Configurações de som"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"Modo carro"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"Não é possível usar esse recurso enquanto você dirige"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"Fechar app"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Configurações da tela"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Configurações de som"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Configurações de perfis e contas"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Opções do desenvolvedor"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"Sem seletor giratório, use o toque"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"Sua tela está bloqueada"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"Sua tela foi bloqueada"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"Não foi possível iniciar um perfil de visitante. Tente novamente mais tarde."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"Saindo…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> está saindo. Tente novamente mais tarde."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Usuário indisponível no momento"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Não é possível acessar perfis de usuário protegidos na tela do passageiro"</string>
     <string name="seat_driver" msgid="4502591979520445677">"do motorista"</string>
     <string name="seat_front" msgid="836133281052793377">"dianteiro"</string>
     <string name="seat_rear" msgid="403133444964528577">"traseiro"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"Tela cheia"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Ver planos"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Seu plano de Internet expirou"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"Este app precisa de conexão com a Internet"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s precisa de conexão com a Internet"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Este app"</string>
 </resources>
diff --git a/res/values-ro/strings.xml b/res/values-ro/strings.xml
index 22e3b499..520a03c5 100644
--- a/res/values-ro/strings.xml
+++ b/res/values-ro/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{Poți crea un singur profil.}few{Poți să adaugi până la # profiluri.}other{Poți să adaugi până la # de profiluri.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"Se încarcă"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"Se încarcă utilizatorul (de la <xliff:g id="FROM_USER">%1$d</xliff:g> la <xliff:g id="TO_USER">%2$d</xliff:g>)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"Profilul actual"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g> este dezactivat."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"Folosește <xliff:g id="SENSOR">%1$s</xliff:g>"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"Pentru aplicațiile care au permisiunea"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"Setări pentru semnal: Wi-Fi activat"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"Setări pentru semnal: hotspot activat"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"Setări de afișare"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"Setări pentru remedierea erorilor"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"Setări de sunet"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"Modul cu mașina"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"Nu poți folosi această funcție în timp ce conduci"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"Închide aplicația"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Setări de afișare"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Setări de sunet"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Setări pentru profiluri și conturi"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Opțiuni pentru dezvoltatori"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"Modelul nu acceptă accesul prin rotire. Folosește atingerea."</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"Ecranul este blocat"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"S-a blocat ecranul"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"Nu se poate porni Profilul de invitat. Încearcă din nou mai târziu."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"Se deconectează…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> se deconectează. Încearcă din nou mai târziu."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Utilizator indisponibil momentan"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Nu se poate porni utilizatorul securizat pe ecranul pentru pasageri"</string>
     <string name="seat_driver" msgid="4502591979520445677">"locul șoferului"</string>
     <string name="seat_front" msgid="836133281052793377">"locul din față"</string>
     <string name="seat_rear" msgid="403133444964528577">"locul din spate"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"Ecran complet"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Vezi planurile"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Planul tău de internet a expirat"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"Aplicația necesită o conexiune la internet"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s necesită o conexiune la internet"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Această aplicație"</string>
 </resources>
diff --git a/res/values-ru/strings.xml b/res/values-ru/strings.xml
index 73dcd9d5..775bab49 100644
--- a/res/values-ru/strings.xml
+++ b/res/values-ru/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{Можно создать только один профиль.}one{Можно добавить до # профиля.}few{Можно добавить до # профилей.}many{Можно добавить до # профилей.}other{Можно добавить до # профиля.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"Загрузка…"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"Загрузка профиля пользователя (с <xliff:g id="FROM_USER">%1$d</xliff:g> по <xliff:g id="TO_USER">%2$d</xliff:g>)…"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"Текущий профиль"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g>: отключено."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"Использовать <xliff:g id="SENSOR">%1$s</xliff:g>"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"Для приложений, у которых есть разрешение"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"Настройки связи: сеть Wi-Fi включена"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"Настройки связи: точка доступа включена"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"Настройки экрана"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"Параметры отладки"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"Настройки звука"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"Режим вождения"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"Эту функцию нельзя использовать во время вождения."</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"Закрыть приложение"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Настройки экрана"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Настройки звука"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Настройки профилей и аккаунтов"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Для разработчиков"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"Граф. ключ невозможно ввести вращением."</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"Экран заблокирован"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"Экран заблокирован"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"Не удалось использовать гостевой профиль. Повторите попытку позже."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"Выход…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"Сейчас выходит пользователь <xliff:g id="USER_NAME">%s</xliff:g>. Повторите попытку позже."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Пользователь сейчас недоступен"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Не удается выбрать защищенного пользователя на экране пассажира."</string>
     <string name="seat_driver" msgid="4502591979520445677">"на водительском сиденье"</string>
     <string name="seat_front" msgid="836133281052793377">"на переднем сиденье"</string>
     <string name="seat_rear" msgid="403133444964528577">"на заднем сиденье"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"Полноэкранный режим"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Посмотреть тарифы"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Ваш тарифный план на интернет больше не действует"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"Для работы приложению требуется подключение к интернету."</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s требует подключения к интернету."</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Это приложение"</string>
 </resources>
diff --git a/res/values-si/strings.xml b/res/values-si/strings.xml
index 14a7d268..153bae16 100644
--- a/res/values-si/strings.xml
+++ b/res/values-si/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{එක් පැතිකඩක් පමණක් තැනිය හැකිය.}one{ඔබට පැතිකඩවල් #ක් දක්වා එක් කළ හැකිය.}other{ඔබට පැතිකඩවල් #ක් දක්වා එක් කළ හැකිය.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"පූරණය වෙමින්"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"පරිශීලකයා පූරණය වෙමින් (<xliff:g id="FROM_USER">%1$d</xliff:g> සිට <xliff:g id="TO_USER">%2$d</xliff:g> වෙත)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"වත්මන් පැතිකඩ"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g> ක්‍රියාවිරහිතයි."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"<xliff:g id="SENSOR">%1$s</xliff:g> භාවිත කරන්න"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"අවසර ඇති යෙදුම් සඳහා"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"සංඥා සැකසීම්: Wifi ක්‍රියාත්මකයි"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"සංඥා සැකසීම්: හොට්ස්පොට් ක්‍රියාත්මකයි"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"උපාංග සැකසීම්"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"නිදොසීම් සැකසීම්"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"ශබ්ද සැකසීම්"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"ධාවන ආකාරය"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"රිය පදවන අතරතුර ඔබට මෙම විශේෂාංගය භාවිත කළ නොහැකිය"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"යෙදුම වසන්න"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"සංදර්ශක සැකසීම්"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"ශබ්ද සැකසීම්"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"පැතිකඩවල් &amp; ගිණුම් සැකසීම්"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"සංවර්ධක විකල්ප"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"රටාව භ්‍රමණ සහාය නොදක්වයි; කරුණාකර ස්පර්ශය භාවිත කරන්න"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"ඔබේ තිරය අගුළු දමා ඇත"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"ඔබේ තිරය අගුළු දමා ඇත"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"අමුත්තාගේ පැතිකඩ ආරම්භ කළ නොහැක. පසුව නැවත උත්සාහ කරන්න."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"වරනය වෙමින්…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> වරනය වෙමින් පවතී. පසුව නැවත උත්සාහ කරන්න."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"පරිශීලක දැනට නොමැත"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"මගී සංදර්ශකය මත සුරක්ෂිත පරිශීලකයා ආරම්භ කළ නොහැකි වේ"</string>
     <string name="seat_driver" msgid="4502591979520445677">"රියදුරු"</string>
     <string name="seat_front" msgid="836133281052793377">"ඉදිරිපස"</string>
     <string name="seat_rear" msgid="403133444964528577">"පසුපස"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"පූර්ණ තිරය"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"සැලසුම් බලන්න"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"ඔබේ අන්තර්ජාල සැලසුම කල් ඉකුත් විය"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"මෙම යෙදුමට අන්තර්ජාල සම්බන්ධතාවයක් අවශ්‍යයි"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s හට අන්තර්ජාල සම්බන්ධතාවයක් අවශ්‍යයි"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"මෙම යෙදුම"</string>
 </resources>
diff --git a/res/values-sk/strings.xml b/res/values-sk/strings.xml
index 6b346c92..5da4c824 100644
--- a/res/values-sk/strings.xml
+++ b/res/values-sk/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{Môžete vytvoriť iba jeden profil.}few{Môžete pridať až # profily.}many{You can add up to # profiles.}other{Môžete pridať až # profilov.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"Načítava sa"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"Načítava sa používateľ (predchádzajúci: <xliff:g id="FROM_USER">%1$d</xliff:g>, nasledujúci: <xliff:g id="TO_USER">%2$d</xliff:g>)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"Aktuálny profil"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"Zariadenie <xliff:g id="SENSOR">%1$s</xliff:g> je vypnuté."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"Použiť zariadenie <xliff:g id="SENSOR">%1$s</xliff:g>"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"V prípade aplikácií, ktoré majú povolenie"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"Nastavenia signálu: pripojenie Wi‑Fi je zapnuté"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"Nastavenia signálu: hotspot je zapnutý"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"Nastavenia zobrazenia"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"Nastavenia ladenia"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"Nastavenia zvuku"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"Režim v aute"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"Túto funkciu nie je možné používať za jazdy"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"Zavrieť aplikáciu"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Nastavenia obrazovky"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Nastavenia zvuku"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Nastavenia profilov a účtov"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Pre vývojárov"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"Vzor nepodporuje otočné ovládanie, zadajte ho klepnutím"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"Obrazovka je uzamknutá"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"Obrazovka bola uzamknutá"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"Profil pre hostí sa nedá spustiť. Skúste to znova neskôr."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"Odhlasuje sa…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> sa odhlasuje. Skúste to znova neskôr."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Používateľ momentálne nie je k dispozícii"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Na obrazovke pasažiera sa nepodarilo spustiť bezpečného používateľa"</string>
     <string name="seat_driver" msgid="4502591979520445677">"vodič"</string>
     <string name="seat_front" msgid="836133281052793377">"predná časť"</string>
     <string name="seat_rear" msgid="403133444964528577">"zadná časť"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"Celá obrazovka"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Zobraziť tarify"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Vaša internetová tarifa vypršala"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"Táto aplikácia vyžaduje internetové pripojenie"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"Aplikácia %s vyžaduje internetové pripojenie"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Táto aplikácia"</string>
 </resources>
diff --git a/res/values-sl/strings.xml b/res/values-sl/strings.xml
index fba1466d..8d8ff6d8 100644
--- a/res/values-sl/strings.xml
+++ b/res/values-sl/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{Ustvariti je mogoče samo en profil.}one{Dodati je mogoče do # profil.}two{Dodati je mogoče do # profila.}few{Dodati je mogoče do # profile.}other{Dodati je mogoče do # profilov.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"Nalaganje"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"Nalaganje uporabnika (od uporabnika <xliff:g id="FROM_USER">%1$d</xliff:g> do uporabnika <xliff:g id="TO_USER">%2$d</xliff:g>)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"Trenutni profil"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"To je izklopljeno: <xliff:g id="SENSOR">%1$s</xliff:g>."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"Uporaba tega: <xliff:g id="SENSOR">%1$s</xliff:g>."</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"Za aplikacije z dovoljenjem."</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"Nastavitve signala: Omrežje Wi-Fi je vklopljeno"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"Nastavitve signala: Dostopna točka je vklopljena"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"Nastavitve zaslona"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"Nastavitve odpravljanja napak"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"Nastavitve zvoka"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"Način vožnje"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"Te funkcije med vožnjo ne morete uporabljati"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"Zapri aplikacijo"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Nastavitve zaslona"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Nastavitve zvoka"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Nastavitve profilov in računov"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Možnosti za razvijalce"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"Vzorec ne podpira sukanja; uporabite dotik"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"Zaslon je zdaj zaklenjen"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"Vaš zaslon je zaklenjen"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"Profila gosta ni mogoče začeti. Poskusite znova pozneje."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"Odjava …"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"Poteka odjava uporabnika <xliff:g id="USER_NAME">%s</xliff:g>. Poskusite znova pozneje."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Uporabnik trenutno ni na voljo"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Prikaza varnega uporabnika na zaslonu sopotnika ni mogoče začeti"</string>
     <string name="seat_driver" msgid="4502591979520445677">"voznikov sedež"</string>
     <string name="seat_front" msgid="836133281052793377">"sprednji sedež"</string>
     <string name="seat_rear" msgid="403133444964528577">"zadnji sedež"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"Celozaslonski način"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Oglejte si pakete"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Vaš internetni paket je potekel"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"Ta aplikacija potrebuje internetno povezavo"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s potrebuje internetno povezavo"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Ta aplikacija"</string>
 </resources>
diff --git a/res/values-sq/strings.xml b/res/values-sq/strings.xml
index 9c7de7cc..48491464 100644
--- a/res/values-sq/strings.xml
+++ b/res/values-sq/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{Mund të krijohet vetëm një profil.}other{Mund të shtosh deri në # profile.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"Po ngarkohet"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"Përdoruesi po ngarkohet (nga <xliff:g id="FROM_USER">%1$d</xliff:g> te <xliff:g id="TO_USER">%2$d</xliff:g>)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"Profili aktual"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g> është çaktivizuar."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"Përdor <xliff:g id="SENSOR">%1$s</xliff:g>"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"Për aplikacionet që kanë leje"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"Cilësimet e sinjaleve: Wifi aktiv"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"Cilësimet e sinjaleve: Zona e qasjes për internet aktive"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"Cilësimet e ekranit"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"Cilësimet e korrigjimit"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"Cilësimet e zërit"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"Modaliteti \"me makinë\""</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"Nuk mund ta përdorësh këtë veçori gjatë drejtimit të makinës"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"Mbyll aplikacionin"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Shfaq cilësimet"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Cilësimet e zërit"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Cilësimet e profileve dhe të llogarive"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Opsionet e zhvilluesit"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"Motivi me rrotullim nuk mbështetet; përdor prekjen"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"Ekrani yt është i kyçur"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"Ekrani yt është kyçur"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"Profili i vizitorit nuk mund të fillohet. Provo përsëri më vonë."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"Po del…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> po del. Provo përsëri më vonë."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Përdoruesi nuk disponohet aktualisht"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Përdoruesi i sigurt nuk mund të niset në ekranin e pasagjerit"</string>
     <string name="seat_driver" msgid="4502591979520445677">"drejtuesi"</string>
     <string name="seat_front" msgid="836133281052793377">"ana e përparme"</string>
     <string name="seat_rear" msgid="403133444964528577">"ana e pasme"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"Ekran i plotë"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Shiko planet"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Plani yt i internetit ka skaduar"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"Ky aplikacion ka nevojë për lidhje interneti"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s ka nevojë për një lidhje interneti"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Ky aplikacion"</string>
 </resources>
diff --git a/res/values-sr/strings.xml b/res/values-sr/strings.xml
index c3dbf3ea..0527bd3c 100644
--- a/res/values-sr/strings.xml
+++ b/res/values-sr/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{Можете да направите само један профил.}one{Можете да додате највише # профил.}few{Можете да додате највише # профила.}other{Можете да додате највише # профила.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"Учитава се"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"Профил корисника се учитава (из<xliff:g id="FROM_USER">%1$d</xliff:g> у <xliff:g id="TO_USER">%2$d</xliff:g>)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"Актуелни профил"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"Сензор <xliff:g id="SENSOR">%1$s</xliff:g> је искључен."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"Користи: <xliff:g id="SENSOR">%1$s</xliff:g>"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"За апликације које имају дозволу"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"Подешавања сигнала: WiFi је искључен"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"Подешавања сигнала: хотспот је укључен"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"Подешавања екрана"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"Подешавања отклањања грешака"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"Подешавања звука"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"Режим вожње"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"Не можете да користите ову функцију док возите"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"Затвори апликацију"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Подешавања екрана"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Подешавања звука"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Подешавања профила и налога"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Опције за програмера"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"Шаблон не допушта кружне покрете; користите додир"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"Екран је закључан"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"Екран је закључан"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"Не можете да покренете профил госта. Пробајте поново касније."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"Одјављујете се…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> се одјављује. Пробајте поново касније."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Корисник тренутно није доступан"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Није могуће покренути безбедног корисника на екрану путника"</string>
     <string name="seat_driver" msgid="4502591979520445677">"возач"</string>
     <string name="seat_front" msgid="836133281052793377">"предње"</string>
     <string name="seat_rear" msgid="403133444964528577">"задње"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"Цео екран"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Прикажи пакете"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Интернет пакет је истекао"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"За ову апликацију је потребна интернет веза"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s захтева интернет везу"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Ова апликација"</string>
 </resources>
diff --git a/res/values-sv/strings.xml b/res/values-sv/strings.xml
index e6861076..13aeff04 100644
--- a/res/values-sv/strings.xml
+++ b/res/values-sv/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{Det går bara att skapa en profil.}other{Du kan lägga till högst # profiler.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"Läser in"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"Läser in användare (från <xliff:g id="FROM_USER">%1$d</xliff:g> till <xliff:g id="TO_USER">%2$d</xliff:g>)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"Aktuell profil"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g> är avstängd."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"Använd <xliff:g id="SENSOR">%1$s</xliff:g>"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"För appar som har behörighet"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"Signalinställningar: Wifi på"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"Signalinställningar: Surfzon på"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"Skärminställningar"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"Felsökningsinställningar"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"Ljudinställningar"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"Körläge"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"Du kan inte använda funktionen medan du kör"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"Stäng appen"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Skärminställningar"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Ljudinställningar"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Profil- och kontoinställningar"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Utvecklaralternativ"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"Mönstret stödjer inte rotation – använd tryck"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"Skärmen är låst"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"Skärmen har låsts"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"Det gick inte att starta gästprofilen. Försök igen senare."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"Loggar ut …"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> loggas ut. Försök igen senare."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Användaren är inte tillgänglig just nu"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Det går inte att starta den säkra användaren på passagerarskärmen"</string>
     <string name="seat_driver" msgid="4502591979520445677">"förarsätet"</string>
     <string name="seat_front" msgid="836133281052793377">"framsätet"</string>
     <string name="seat_rear" msgid="403133444964528577">"baksätet"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"Helskärm"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Se abonnemang"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Ditt internetabonnemang har löpt ut"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"En internetanslutning krävs för appen"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s behöver en internetanslutning"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Den här appen"</string>
 </resources>
diff --git a/res/values-sw/strings.xml b/res/values-sw/strings.xml
index 8461ec00..1dc8b93e 100644
--- a/res/values-sw/strings.xml
+++ b/res/values-sw/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{Unaweza kuweka wasifu mmoja pekee.}other{Unaweza kuweka hadi wasifu #.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"Inapakia"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"Inapakia wasifu wa mtumiaji (kutoka <xliff:g id="FROM_USER">%1$d</xliff:g> kuwa <xliff:g id="TO_USER">%2$d</xliff:g>)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"Wasifu wa sasa"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g> imezimwa"</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"Tumia <xliff:g id="SENSOR">%1$s</xliff:g>"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"Kwenye programu zilizo na ruhusa"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"Mipangilio ya Mtandao: Wifi Imewashwa"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"Mipangilio ya Mtandao: Mtandao pepe Umewashwa"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"Mipangilio ya Skrini"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"Mipangilio ya Utatuzi"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"Mipangilio ya Sauti"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"Hali ya Kuendesha Gari"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"Huwezi kutumia kipengele hiki wakati unaendesha gari"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"Funga programu"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Mipangilio ya kuonyesha"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Mipangilio ya sauti"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Mipangilio ya akaunti na wasifu"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Chaguo za wasanidi programu"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"Mchoro hautumii zana ya kuzungusha; tafadhali tumia zana ya kugusa"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"Skrini yako imefungwa"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"Skrini yako imefungwa"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"Huwezi kuanzisha Wasifu wa mgeni. Jaribu tena baadaye."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"Inaondoka katika akaunti…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> anaondolewa katika akaunti. Jaribu tena baadaye."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Mtumiaji hapatikani kwa sasa"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Imeshindwa kuanzisha hali ya mtumiaji salama kwenye skrini ya abiria"</string>
     <string name="seat_driver" msgid="4502591979520445677">"dereva"</string>
     <string name="seat_front" msgid="836133281052793377">"mbele"</string>
     <string name="seat_rear" msgid="403133444964528577">"nyuma"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"Skrini Nzima"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Angalia mipango"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Muda wa mpango wako wa intaneti umeisha"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"Programu hii inahitaji muunganisho wa intaneti"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s inahitaji muunganisho wa intaneti"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Programu hii"</string>
 </resources>
diff --git a/res/values-ta/strings.xml b/res/values-ta/strings.xml
index ec45c163..a5e4e23a 100644
--- a/res/values-ta/strings.xml
+++ b/res/values-ta/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{ஒரு சுயவிவரத்தை மட்டுமே உருவாக்க முடியும்.}other{# சுயவிவரங்கள் வரை சேர்க்க முடியும்.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"ஏற்றுகிறது"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"பயனர் தகவலை ஏற்றுகிறது (<xliff:g id="FROM_USER">%1$d</xliff:g>லிருந்து <xliff:g id="TO_USER">%2$d</xliff:g> வரை)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"தற்போதைய சுயவிவரம்"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g> முடக்கப்பட்டுள்ளது."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"<xliff:g id="SENSOR">%1$s</xliff:g> ஐ உபயோகித்தல்"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"அனுமதியுள்ள ஆப்ஸுக்கு"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"சிக்னல் அமைப்புகள்: Wi-Fi ஆன் செய்யப்பட்டுள்ளது"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"சிக்னல் அமைப்புகள்: ஹாட்ஸ்பாட் ஆன் செய்யப்பட்டுள்ளது"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"காட்சி அமைப்புகள்"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"பிழைதிருத்த அமைப்புகள்"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"ஒலி அமைப்புகள்"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"வாகனம் ஓட்டும் பயன்முறை"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"வாகனம் ஓட்டும்போது இந்த அம்சத்தைப் பயன்படுத்த முடியாது"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"ஆப்ஸை மூடு"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"காட்சி அமைப்புகள்"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"ஒலி அமைப்புகள்"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"சுயவிவரங்கள் &amp; கணக்கு அமைப்புகள்"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"டெவெலப்பர் விருப்பங்கள்"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"தொடுதல் முறையைப் பயன்படுத்தவும்"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"உங்கள் திரை லாக் செய்யப்பட்டுள்ளது"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"உங்கள் திரை லாக் செய்யப்பட்டது"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"விருந்தினர் சுயவிவரத்தைத் தொடங்க முடியவில்லை. பிறகு மீண்டும் முயலவும்."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"வெளியேறுகிறது…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> வெளியேறுகிறார். பிறகு மீண்டும் முயலவும்."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"தற்சமயம் பயனர் இல்லை"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"பயணியின் திரையில் பயனரைப் பாதுகாத்தலைத் தொடங்க முடியவில்லை"</string>
     <string name="seat_driver" msgid="4502591979520445677">"ஓட்டுநர்"</string>
     <string name="seat_front" msgid="836133281052793377">"முன்புறம்"</string>
     <string name="seat_rear" msgid="403133444964528577">"பின்புறம்"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"முழுத்திரை"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"திட்டங்களைக் காட்டு"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"உங்கள் இணையத் திட்டம் காலாவதியாகிவிட்டது"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"இந்த ஆப்ஸுக்கு இணைய இணைப்பு தேவை"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%sக்கு இணைய இணைப்பு தேவை"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"இந்த ஆப்ஸ்"</string>
 </resources>
diff --git a/res/values-te/strings.xml b/res/values-te/strings.xml
index 45a7cc50..22508185 100644
--- a/res/values-te/strings.xml
+++ b/res/values-te/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{ఒక ప్రొఫైల్‌ను మాత్రమే క్రియేట్ చేయగలరు.}other{మీరు గరిష్ఠంగా # ప్రొఫైల్స్‌ను జోడించవచ్చు.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"లోడ్ అవుతోంది"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"యూజర్‌ను లోడ్ చేస్తోంది (<xliff:g id="FROM_USER">%1$d</xliff:g> నుండి <xliff:g id="TO_USER">%2$d</xliff:g> వరకు)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"ప్రస్తుత ప్రొఫైల్"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g> ఆఫ్‌లో ఉంది."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"<xliff:g id="SENSOR">%1$s</xliff:g>ను ఉపయోగించండి"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"అనుమతి ఉన్న యాప్‌ల కోసం"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"సిగ్నల్ సెట్టింగ్‌లు: Wi-Fi ఆన్‌లో ఉంది"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"సిగ్నల్ సెట్టింగ్‌లు: హాట్‌స్పాట్ ఆన్‌లో ఉంది"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"డిస్‌ప్లే సెట్టింగ్‌లు"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"డీబగ్ సెట్టింగ్‌లు"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"సౌండ్ సెట్టింగ్‌లు"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"డ్రైవ్ మోడ్"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"డ్రైవింగ్‌లో ఉండగా మీరు ఈ ఫీచర్‌ను ఉపయోగించలేరు"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"యాప్‌ను మూసివేయండి"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"ప్రదర్శన సెట్టింగ్‌లు"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"సౌండ్ సెట్టింగ్‌లు"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"ప్రొఫైళ్లు &amp; ఖాతాల సెట్టింగ్‌లు"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"డెవలపర్ ఆప్షన్‌లు"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"ఆకృతి రోటరీకి సపోర్ట్ చేయదు; \'తాకండి\'"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"మీ స్క్రీన్ లాక్ అయ్యింది"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"మీ స్క్రీన్ లాక్ చేయబడింది"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"గెస్ట్ ప్రొఫైల్‌ను ప్రారంభించడం సాధ్యం కాదు. తర్వాత మళ్లీ ట్రై చేయండి."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"సైన్ అవుట్ అవుతోంది…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> సైన్ అవుట్ చేయబడుతున్నారు. తర్వాత మళ్లీ ట్రై చేయండి."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"యూజర్ ప్రస్తుతం అందుబాటులో లేరు"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"ప్యాసింజర్ డిస్‌ప్లేలో సురక్షిత యూజర్‌ను ప్రారంభించడం సాధ్యం కాలేదు"</string>
     <string name="seat_driver" msgid="4502591979520445677">"డ్రైవర్"</string>
     <string name="seat_front" msgid="836133281052793377">"ముందువైపు"</string>
     <string name="seat_rear" msgid="403133444964528577">"వెనుక భాగం"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"ఫుల్ స్క్రీన్"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"ప్లాన్‌లను చూడండి"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"మీ ఇంటర్నెట్ ప్లాన్‌ గడువు ముగిసింది"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"ఈ యాప్‌కు ఇంటర్నెట్ కనెక్షన్ అవసరమవుతుంది"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s‌కు ఇంటర్నెట్ కనెక్షన్ అవసరం"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"ఈ యాప్"</string>
 </resources>
diff --git a/res/values-th/strings.xml b/res/values-th/strings.xml
index 4034576e..7aa21101 100644
--- a/res/values-th/strings.xml
+++ b/res/values-th/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{สร้างได้เพียงโปรไฟล์เดียวเท่านั้น}other{คุณเพิ่มโปรไฟล์ได้สูงสุด # โปรไฟล์}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"กำลังโหลด"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"กำลังโหลดผู้ใช้ (จาก <xliff:g id="FROM_USER">%1$d</xliff:g> ถึง <xliff:g id="TO_USER">%2$d</xliff:g>)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"โปรไฟล์ปัจจุบัน"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g>ปิดอยู่"</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"ใช้<xliff:g id="SENSOR">%1$s</xliff:g>"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"สำหรับแอปที่มีสิทธิ์"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"การตั้งค่าสัญญาณ: Wi-Fi เปิดอยู่"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"การตั้งค่าสัญญาณ: ฮอตสปอตเปิดอยู่"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"การตั้งค่าการแสดงผล"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"การตั้งค่าการแก้ไขข้อบกพร่อง"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"การตั้งค่าเสียง"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"โหมดขับรถ"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"คุณใช้ฟีเจอร์นี้ขณะขับรถไม่ได้"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"ปิดแอป"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"การตั้งค่าการแสดงผล"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"การตั้งค่าเสียง"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"การตั้งค่าโปรไฟล์และบัญชี"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"ตัวเลือกสำหรับนักพัฒนาแอป"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"รูปแบบไม่รองรับปุ่มหมุน โปรดใช้หน้าจอสัมผัส"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"หน้าจอล็อกอยู่"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"หน้าจอล็อกอยู่"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"เริ่มโปรไฟล์ผู้ใช้ชั่วคราวไม่ได้ ลองอีกครั้งในภายหลัง"</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"กำลังออกจากระบบ…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> กำลังออกจากระบบ ลองอีกครั้งในภายหลัง"</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"ผู้ใช้ไม่พร้อมใช้งานในขณะนี้"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"เปิดใช้งานผู้ใช้ที่ปลอดภัยบนจอแสดงผลสำหรับผู้โดยสารไม่ได้"</string>
     <string name="seat_driver" msgid="4502591979520445677">"คนขับ"</string>
     <string name="seat_front" msgid="836133281052793377">"ด้านหน้า"</string>
     <string name="seat_rear" msgid="403133444964528577">"ด้านหลัง"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"เต็มหน้าจอ"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"ดูแพ็กเกจ"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"แพ็กเกจอินเทอร์เน็ตของคุณหมดอายุแล้ว"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"แอปนี้ต้องใช้การเชื่อมต่ออินเทอร์เน็ต"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s ต้องมีการเชื่อมต่ออินเทอร์เน็ต"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"แอปนี้"</string>
 </resources>
diff --git a/res/values-tl/strings.xml b/res/values-tl/strings.xml
index aa7bc8c8..3c74e0da 100644
--- a/res/values-tl/strings.xml
+++ b/res/values-tl/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{Isang profile lang ang puwedeng gawin.}one{Puwede kang magdagdag ng hanggang # profile.}other{Puwede kang magdagdag ng hanggang # na profile.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"Naglo-load"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"Nilo-load ang user (mula kay <xliff:g id="FROM_USER">%1$d</xliff:g> papunta kay <xliff:g id="TO_USER">%2$d</xliff:g>)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"Kasalukuyang profile"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"Naka-off ang <xliff:g id="SENSOR">%1$s</xliff:g>."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"Gamitin ang <xliff:g id="SENSOR">%1$s</xliff:g>"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"Para sa mga app na may pahintulot"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"Mga Setting ng Signal: Naka-on ang Wi-Fi"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"Mga Setting ng Signal: Naka-on ang Hotspot"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"Mga Setting ng Display"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"Mga Setting ng Pag-debug"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"Mga Setting ng Tunog"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"Drive Mode"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"Hindi mo puwedeng gamitin ang feature na ito habang nagmamaneho"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"Isara ang app"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Mga setting ng display"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Mga setting ng tunog"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Mga setting ng mga profile at account"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Mga opsyon ng developer"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"Hindi sinusuportahan ng pattern ang rotary; pumindot"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"Naka-lock ang iyong screen"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"Na-lock ang iyong screen"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"Hindi masimulan ang profile ng Bisita. Subukan ulit sa ibang pagkakataon."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"Nagsa-sign out…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"Sina-sign out si <xliff:g id="USER_NAME">%s</xliff:g>. Subukan ulit sa ibang pagkakataon."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Kasalukuyang hindi available ang user"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Hindi masimulan ang secure na user sa screen ng pasahero"</string>
     <string name="seat_driver" msgid="4502591979520445677">"driver"</string>
     <string name="seat_front" msgid="836133281052793377">"harap"</string>
     <string name="seat_rear" msgid="403133444964528577">"likod"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"Full Screen"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Tingnan ang mga plan"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Nag-expire na ang internet plan mo"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"Kailangan ng app na ito ang koneksyon sa internet"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"Kailangan ng %s ng koneksyon sa internet"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"App na ito"</string>
 </resources>
diff --git a/res/values-tr/strings.xml b/res/values-tr/strings.xml
index cfbb2ab6..81011d08 100644
--- a/res/values-tr/strings.xml
+++ b/res/values-tr/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{Yalnızca tek bir profil oluşturulabilir.}other{En çok # profil ekleyebilirsiniz.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"Yükleniyor"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"Kullanıcı yükleniyor (<xliff:g id="FROM_USER">%1$d</xliff:g> kullanıcısından <xliff:g id="TO_USER">%2$d</xliff:g> kullanıcısına)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"Geçerli profil"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g> kapalı."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"<xliff:g id="SENSOR">%1$s</xliff:g> kullanılır"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"İzne sahip uygulamalar için"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"Sinyal Ayarları: WiFi Açık"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"Sinyal Ayarları: Hotspot Açık"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"Ekran Ayarları"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"Hata Ayıklama Ayarları"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"Ses Ayarları"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"Sürüş Modu"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"Sürüş sırasında bu özelliği kullanamazsınız"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"Uygulamayı kapat"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Ekran ayarları"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Ses ayarları"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Profil ve hesap ayarları"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Geliştirici seçenekleri"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"Desende çevirme desteklenmiyor. Dokunmayı kullanın"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"EKranınız kilitlendi"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"Ekranınız kilitlendi"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"Misafir profili başlatılamıyor. Daha sonra tekrar deneyin."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"Çıkış yapılıyor…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> oturumu kapatılıyor. Daha sonra tekrar deneyin."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Kullanıcı şu anda kullanılamıyor"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Yolcu ekranında güvenli kullanıcı başlatılamadı"</string>
     <string name="seat_driver" msgid="4502591979520445677">"sürücü"</string>
     <string name="seat_front" msgid="836133281052793377">"ön"</string>
     <string name="seat_rear" msgid="403133444964528577">"arka"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"Tam Ekran"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Planları göster"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"İnternet planınızın süresi doldu"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"Bu uygulama için internet bağlantısı gerekiyor"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s için internet bağlantısı gerekiyor"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Bu uygulama"</string>
 </resources>
diff --git a/res/values-uk/strings.xml b/res/values-uk/strings.xml
index c4bfd7e5..7163c960 100644
--- a/res/values-uk/strings.xml
+++ b/res/values-uk/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{Можна створити лише один профіль.}one{Можна додати не більше ніж # профіль.}few{Можна додати не більше ніж # профілі.}many{Можна додати не більше ніж # профілів.}other{Можна додати не більше ніж # профілю.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"Завантаження"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"Завантаження профілю користувача (від <xliff:g id="FROM_USER">%1$d</xliff:g> до <xliff:g id="TO_USER">%2$d</xliff:g>)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"Поточний профіль"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g>: вимкнено."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"Використовувати функцію \"<xliff:g id="SENSOR">%1$s</xliff:g>\""</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"Для додатків, яким надано дозвіл"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"Налаштування сигналу: Wi-Fi увімкнено"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"Налаштування сигналу: точку доступу ввімкнено"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"Налаштування дисплея"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"Параметри налагодження"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"Налаштування звуку"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"Режим автомобіля"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"Ця функція недоступна під час руху"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"Закрити додаток"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Налаштування дисплея"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Налаштування звуку"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Налаштування профілів і облікових записів"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Параметри розробника"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"Ключ вводиться лише на сенсорній панелі"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"Екран заблоковано"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"Екран заблоковано"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"Не вдається запустити профіль гостя. Спробуйте пізніше."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"Вихід…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"Користувач <xliff:g id="USER_NAME">%s</xliff:g> виходить з облікового запису. Спробуйте пізніше."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Профіль користувача зараз недоступний"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Неможливо запустити захищений профіль користувача на дисплеї пасажира"</string>
     <string name="seat_driver" msgid="4502591979520445677">"водій"</string>
     <string name="seat_front" msgid="836133281052793377">"спереду"</string>
     <string name="seat_rear" msgid="403133444964528577">"ззаду"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"На весь екран"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Переглянути плани"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Строк дії вашого тарифного плану Інтернету закінчився"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"Цьому додатку потрібне інтернет-з’єднання"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s потребує інтернет-з’єднання"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Цей додаток"</string>
 </resources>
diff --git a/res/values-ur/strings.xml b/res/values-ur/strings.xml
index 0cfcc862..567784ee 100644
--- a/res/values-ur/strings.xml
+++ b/res/values-ur/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{صرف ایک پروفائل تخلیق کی جا سکتی ہے۔}other{آپ # تک پروفائلز شامل کر سکتے ہیں۔}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"لوڈ ہو رہی ہے"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"صارف کی نئی پروفائل لوڈ ہو رہی ہے (<xliff:g id="FROM_USER">%1$d</xliff:g> سے <xliff:g id="TO_USER">%2$d</xliff:g> کو)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"موجودہ پروفائل"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g> آف ہے۔"</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"<xliff:g id="SENSOR">%1$s</xliff:g> استعمال کریں"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"ان ایپس کے لیے جن کو اجازت ہے"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"سگنل کی ترتیبات: Wifi آن ہے"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"سگنل کی ترتیبات: ہاٹ اسپاٹ آن ہے"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"ڈسپلے کی ترتیبات"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"ڈیبگ کریں کی ترتیبات"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"صوتی ترتیبات"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"ڈرائیو وضع"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"ڈرائیونگ کے دوران آپ یہ خصوصیت استعمال نہیں کر سکتے"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"ایپ بند کریں"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"ڈسپلے کی ترتیبات"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"آواز کی ترتیبات"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"پروفائلز اور اکاؤنٹس کی ترتیبات"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"ڈیولپر کے اختیارات"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"پیٹرن روٹری کو سپورٹ نہیں کرتا ہے؛ براہ کرم ٹچ کریں استعمال کریں"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"آپ کی اسکرین مقفل ہے"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"آپ کی اسکرین مقفل ہو گئی ہے"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"مہمان پروفائل شروع نہیں کر سکتے۔ بعد میں دوبارہ کوشش کریں۔"</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"سائن آؤٹ ہو رہا ہے…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> سائن آؤٹ ہو رہا ہے۔ بعد میں دوبارہ کوشش کریں۔"</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"صارف فی الحال دستیاب نہیں ہے"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"مسافر ڈسپلے پر صارف کی محفوظ پروفائل شروع کرنے سے قاصر ہے"</string>
     <string name="seat_driver" msgid="4502591979520445677">"ڈرائیور"</string>
     <string name="seat_front" msgid="836133281052793377">"فرنٹ"</string>
     <string name="seat_rear" msgid="403133444964528577">"پیچھے"</string>
@@ -120,7 +126,7 @@
     <string name="keyguard_enter_your_pin" msgid="141736439348916894"></string>
     <string name="keyguard_enter_your_pattern" msgid="4004401928097798697"></string>
     <string name="keyguard_enter_your_password" msgid="1345546935461513721"></string>
-    <string name="car_keyguard_enter_your_pin" msgid="6306637610891409860">"اپنا PIN درج کریں"</string>
+    <string name="car_keyguard_enter_your_pin" msgid="6306637610891409860">"‫اپنا PIN درج کریں"</string>
     <string name="car_keyguard_enter_your_pattern" msgid="7314854851472119334">"اپنا پیٹرن درج کریں"</string>
     <string name="car_keyguard_enter_your_password" msgid="2084173625085820354">"اپنا پاس ورڈ درج کریں"</string>
     <string name="backspace_key" msgid="5570862528655375412">"Backspace کلید"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"فُل اسکرین"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"پلانز دیکھیں"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"آپ کے انٹرنیٹ پلان کی میعاد ختم ہو گئی"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"اس ایپ کو انٹرنیٹ کنکشن درکار ہے"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"‫%s کو انٹرنیٹ کنکشن درکار ہے"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"یہ ایپ"</string>
 </resources>
diff --git a/res/values-uz/strings.xml b/res/values-uz/strings.xml
index 78aa4a43..e45aee9c 100644
--- a/res/values-uz/strings.xml
+++ b/res/values-uz/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{Faqat bitta profil yaratish mumkin.}other{Maksimal # ta profil kiritish mumkin.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"Yuklanmoqda"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"Foydalanuvchi profili yuklanmoqda (<xliff:g id="FROM_USER">%1$d</xliff:g> – <xliff:g id="TO_USER">%2$d</xliff:g>)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"Joriy profil"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g> yoniq emas."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"<xliff:g id="SENSOR">%1$s</xliff:g> ishlatish"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"Ruxsati bor ilovalar uchun"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"Signal sozlamalari: Wi-Fi yoniq"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"Signal sozlamalari: hotspot yoniq"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"Ekran sozlamalari"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"Debag sozlamalari"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"Tovush sozlamalari"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"Avtomobilda"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"Avtomobilda harakatlanayotganda bu funksiyadan foydalanish imkonsiz"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"Ilovani yopish"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Ekran sozlamalari"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Tovush sozlamalari"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Profillar va hisoblar sozlamalari"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Dasturchi sozlamalari"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"Grafik kalit burilmaydi, telefonni buring"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"Ekraningiz qulflandi"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"Ekraningiz qulflandi"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"Mehmon profili boshlanmadi. Keyinroq qayta urining."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"Hisobdan chiqilmoqda…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> hisobidan chiqadi. Keyinroq qayta urining."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Foydalanuvchi ishlamaydi"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Yoʻlovchi ekranida xavfsiz foydalanuvchini ishga tushirish imkonsiz"</string>
     <string name="seat_driver" msgid="4502591979520445677">"haydovchi"</string>
     <string name="seat_front" msgid="836133281052793377">"old"</string>
     <string name="seat_rear" msgid="403133444964528577">"orqa"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"Butun ekran"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Tarif rejalari"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Internet tarif rejangiz muddati tugagan"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"Bu ilovaga internet aloqasi kerak"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s ilovasiga internet aloqasi kerak"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Bu ilova"</string>
 </resources>
diff --git a/res/values-vi/strings.xml b/res/values-vi/strings.xml
index e62617bc..2d5004a6 100644
--- a/res/values-vi/strings.xml
+++ b/res/values-vi/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{Chỉ có thể tạo một hồ sơ.}other{Bạn có thể thêm tối đa # hồ sơ.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"Đang tải"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"Đang tải hồ sơ người dùng (từ <xliff:g id="FROM_USER">%1$d</xliff:g> sang <xliff:g id="TO_USER">%2$d</xliff:g>)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"Hồ sơ hiện tại"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g> đang tắt."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"Sử dụng <xliff:g id="SENSOR">%1$s</xliff:g>"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"Cho những ứng dụng có quyền"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"Cài đặt tín hiệu: Wi-Fi đang bật"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"Cài đặt tín hiệu: Điểm phát sóng đang bật"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"Cài đặt màn hình"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"Cài đặt gỡ lỗi"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"Cài đặt âm thanh"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"Chế độ lái xe"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"Bạn không thể dùng tính năng này khi đang lái xe"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"Tắt ứng dụng"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Cài đặt màn hình"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Cài đặt âm thanh"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Cài đặt tài khoản và hồ sơ"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Tuỳ chọn cho nhà phát triển"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"Không hỗ trợ xoay trong hình mở khoá; hãy chạm"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"Màn hình của bạn đã được khoá"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"Màn hình của bạn đã được khoá"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"Không bắt đầu được Hồ sơ khách. Hãy thử lại sau."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"Đang đăng xuất..."</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g> đang đăng xuất. Hãy thử lại sau."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Hiện không có người dùng này"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Không thể khởi động chế độ người dùng bảo mật trên màn hình của hành khách"</string>
     <string name="seat_driver" msgid="4502591979520445677">"tài xế"</string>
     <string name="seat_front" msgid="836133281052793377">"trước"</string>
     <string name="seat_rear" msgid="403133444964528577">"sau"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"Toàn màn hình"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Xem các gói"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Gói Internet của bạn đã hết hạn"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"Ứng dụng này cần có kết nối Internet"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s cần có kết nối Internet"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Ứng dụng này"</string>
 </resources>
diff --git a/res/values-zh-rCN/strings.xml b/res/values-zh-rCN/strings.xml
index b73bc690..61d8f8af 100644
--- a/res/values-zh-rCN/strings.xml
+++ b/res/values-zh-rCN/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{只能创建 1 份个人资料。}other{您最多可以添加 # 份个人资料。}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"正在加载"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"正在加载用户（从 <xliff:g id="FROM_USER">%1$d</xliff:g> 到 <xliff:g id="TO_USER">%2$d</xliff:g>）"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"当前个人资料"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g>已关闭。"</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"使用<xliff:g id="SENSOR">%1$s</xliff:g>"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"对于已拥有权限的应用"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"信号设置：已开启 WLAN"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"信号设置：已开启热点"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"显示设置"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"调试设置"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"声音设置"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"驾车模式"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"您不能在驾车时使用此功能"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"关闭应用"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"显示设置"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"声音设置"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"个人资料和账号设置"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"开发者选项"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"图案不支持旋转输入；请使用触控输入"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"您的屏幕已锁定"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"已锁定您的屏幕"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"无法添加访客资料。请稍后重试。"</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"正在退出账号…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"<xliff:g id="USER_NAME">%s</xliff:g>正在退出账号。请稍后重试。"</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"目前无法启动用户"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"无法在乘客显示屏上启动安全用户"</string>
     <string name="seat_driver" msgid="4502591979520445677">"驾驶员"</string>
     <string name="seat_front" msgid="836133281052793377">"前排"</string>
     <string name="seat_rear" msgid="403133444964528577">"后排"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"全屏"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"查看套餐"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"您的互联网套餐已过期"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"此应用需要互联网连接"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s需要连接到互联网"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"此应用"</string>
 </resources>
diff --git a/res/values-zh-rHK/strings.xml b/res/values-zh-rHK/strings.xml
index e095033f..53e86bcb 100644
--- a/res/values-zh-rHK/strings.xml
+++ b/res/values-zh-rHK/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{只可建立一個設定檔。}other{你可建立最多 # 個設定檔。}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"正在載入"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"正在載入使用者 (由 <xliff:g id="FROM_USER">%1$d</xliff:g> 至 <xliff:g id="TO_USER">%2$d</xliff:g>)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"目前的設定檔"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"閂咗<xliff:g id="SENSOR">%1$s</xliff:g>。"</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"使用<xliff:g id="SENSOR">%1$s</xliff:g>"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"擁有權限的應用程式"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"訊號設定：已開啟 Wi-Fi"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"訊號設定：已開啟熱點"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"顯示設定"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"偵錯設定"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"音效設定"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"駕駛模式"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"你無法在駕駛時使用此功能"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"關閉應用程式"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"顯示設定"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"音效設定"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"設定檔和帳戶設定"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"開發人員選項"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"圖案不支援旋轉輸入；請使用輕觸輸入"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"螢幕現已鎖定"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"您的螢幕已鎖定"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"無法啟動訪客設定檔。請稍後再試。"</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"正在登出…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"正在將 <xliff:g id="USER_NAME">%s</xliff:g> 登出。請稍後再試。"</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"目前無法連接使用者"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"無法開始在乘客顯示屏中鎖定使用者"</string>
     <string name="seat_driver" msgid="4502591979520445677">"司機座位"</string>
     <string name="seat_front" msgid="836133281052793377">"前排座位"</string>
     <string name="seat_rear" msgid="403133444964528577">"車尾座位"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"全螢幕"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"查看計劃"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"你的互聯網計劃已到期"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"此應用程式需要互聯網連線"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"%s 需要互聯網連線"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"此應用程式"</string>
 </resources>
diff --git a/res/values-zh-rTW/strings.xml b/res/values-zh-rTW/strings.xml
index 4466cdb8..f758c1d8 100644
--- a/res/values-zh-rTW/strings.xml
+++ b/res/values-zh-rTW/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{只能建立 1 個設定檔。}other{最多可以新增 # 個設定檔。}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"載入中"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"正在載入使用者 (從 <xliff:g id="FROM_USER">%1$d</xliff:g> 到 <xliff:g id="TO_USER">%2$d</xliff:g>)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"目前的設定檔"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"<xliff:g id="SENSOR">%1$s</xliff:g>已關閉。"</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"使用<xliff:g id="SENSOR">%1$s</xliff:g>"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"擁有權限的應用程式"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"訊號設定：Wi-Fi 已開啟"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"訊號設定：無線基地台已開啟"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"螢幕設定"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"偵錯設定"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"音效設定"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"行車模式"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"開車時無法使用這項功能"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"關閉應用程式"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"螢幕設定"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"音效設定"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"設定檔和帳戶設定"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"開發人員選項"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"無法旋轉輸入解鎖圖案，請用觸控的方式解鎖"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"螢幕已鎖定"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"螢幕已鎖定"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"無法建立訪客設定檔，請稍後再試。"</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"登出中…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"正在將<xliff:g id="USER_NAME">%s</xliff:g>登出，請稍後再試。"</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"目前無法啟動使用者"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"無法在乘客螢幕上啟動安全使用者"</string>
     <string name="seat_driver" msgid="4502591979520445677">"駕駛座"</string>
     <string name="seat_front" msgid="836133281052793377">"前方座位"</string>
     <string name="seat_rear" msgid="403133444964528577">"後方座位"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"全螢幕"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"查看方案"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"你的網際網路方案已過期"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"必須連上網路，這個應用程式才能運作"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"「%s」需連上網路"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"這個應用程式"</string>
 </resources>
diff --git a/res/values-zu/strings.xml b/res/values-zu/strings.xml
index e98b104e..1ec83f28 100644
--- a/res/values-zu/strings.xml
+++ b/res/values-zu/strings.xml
@@ -33,6 +33,7 @@
     <string name="profile_limit_reached_message" msgid="1534369584753840606">"{count,plural, =1{Yiphrofayela eyodwa kuphela engenziwa.}one{Ungangeza kufika kumaphrofayela angu-#.}other{Ungangeza kufika kumaphrofayela angu-#.}}"</string>
     <string name="car_loading_profile" msgid="458961191993686065">"Iyalayisha"</string>
     <string name="car_loading_profile_developer_message" msgid="737810794567935702">"Ilayisha umsebenzisi (kusuka ku-<xliff:g id="FROM_USER">%1$d</xliff:g> kuya ku-<xliff:g id="TO_USER">%2$d</xliff:g>)"</string>
+    <string name="current_profile_subtitle" msgid="7149515449757434139">"Iphrofayela yamanje"</string>
     <string name="privacy_chip_off_content" msgid="8406415098507955316">"I-<xliff:g id="SENSOR">%1$s</xliff:g> ivaliwe."</string>
     <string name="privacy_chip_use_sensor" msgid="7688230720803089653">"Sebenzisa i-<xliff:g id="SENSOR">%1$s</xliff:g>"</string>
     <string name="privacy_chip_use_sensor_subtext" msgid="5655148288310815742">"Okwama-app anemvume"</string>
@@ -76,6 +77,8 @@
     <string name="status_icon_signal_wifi" msgid="1257569337648058522">"Amasethingi Esignali: I-Wifi Ivuliwe"</string>
     <string name="status_icon_signal_hotspot" msgid="1023039120452006880">"Amasethingi Esignali: I-Hotspot Ivuliwe"</string>
     <string name="status_icon_display_status" msgid="2970020923181359144">"Amasethingi Esibonisi"</string>
+    <string name="status_icon_debug_status" msgid="2503944482699701492">"Amasethingi Okususa Iphutha"</string>
+    <string name="status_icon_sound_status" msgid="4923149230650995670">"Amasethingi Omsindo"</string>
     <string name="status_icon_drive_mode" msgid="3938622431486261076">"Imodi Yokushayela"</string>
     <string name="activity_blocked_text" msgid="5353157279548801554">"Awukwazi ukusebenzisa lesi sakhi ngenkathi ushayela"</string>
     <string name="exit_button_close_application" msgid="112227710467017144">"Vala i-app"</string>
@@ -90,6 +93,7 @@
     <string name="qc_footer_display_settings" msgid="2950539240110437704">"Bonisa amasethingi"</string>
     <string name="qc_footer_network_sound_settings" msgid="5117011034908775097">"Amasethingi omsindo"</string>
     <string name="qc_footer_profiles_accounts_settings" msgid="4456419248123950232">"Amasethingi wamaphrofayela ne-akhawunti"</string>
+    <string name="qc_footer_debug_settings" msgid="7670720389183515925">"Okukhethwa kukho konjiniyela"</string>
     <string name="lockpattern_does_not_support_rotary" msgid="4605787900312103476">"Iphethini ayisekeli i-rotary; sicela usebenzise ukuthinta"</string>
     <string name="display_input_lock_text" msgid="1671197665816822205">"Isikrini sakho sikhiyiwe"</string>
     <string name="display_input_lock_started_text" msgid="2434054522800802134">"Isikrini sakho sikhiyiwe"</string>
@@ -111,6 +115,8 @@
     <string name="guest_creation_failed_message" msgid="8198126434029601949">"Ayikwazi ukuqalisa iphrofayela yesivakashi. Zama futhi ngemuva kwesikhathi."</string>
     <string name="stopping_user_text" msgid="4946464635279894684">"Iphuma ngemvume…"</string>
     <string name="wait_for_until_stopped_message" msgid="4964287657737020726">"U-<xliff:g id="USER_NAME">%s</xliff:g> ukhishiwe. Zama futhi ngemuva kwesikhathi."</string>
+    <string name="unavailable_secure_user_text" msgid="6029519754897637674">"Umsebenzisi akatholakali okwamanje"</string>
+    <string name="unavailable_secure_user_message" msgid="4358973342428603745">"Ayikwazi ukuqala umsebenzisi ovikelekile esibonisini somgibeli"</string>
     <string name="seat_driver" msgid="4502591979520445677">"umshayeli"</string>
     <string name="seat_front" msgid="836133281052793377">"phambili"</string>
     <string name="seat_rear" msgid="403133444964528577">"ingemuva"</string>
@@ -130,5 +136,6 @@
     <string name="fullscreen" msgid="7648956467442135844">"Isikrini Esigcwele"</string>
     <string name="data_subscription_button_text" msgid="6595983827855035949">"Bona izinhlelo"</string>
     <string name="data_subscription_proactive_msg_prompt" msgid="3130110568883863205">"Uhlelo lwakho lwe-inthanethi luphelelwe isikhathi"</string>
-    <string name="data_subscription_reactive_msg_prompt" msgid="8071634832814004999">"Le app idinga ukuxhumeka kwe-inthanethi"</string>
+    <string name="data_subscription_reactive_msg_prompt" msgid="5252304501097103082">"I-%s idinga ukuxhumeka kwe-inthanethi"</string>
+    <string name="data_subscription_reactive_generic_app_label" msgid="5641823691346968670">"Le app"</string>
 </resources>
diff --git a/res/values/colors.xml b/res/values/colors.xml
index 49765c2f..e2d91a04 100644
--- a/res/values/colors.xml
+++ b/res/values/colors.xml
@@ -30,7 +30,7 @@
     <!-- colors for status bar -->
     <color name="system_bar_background_pill_color">@color/car_surface_3</color>
     <color name="privacy_chip_indicator_color">@color/car_green_tint</color>
-    <color name="privacy_chip_dark_icon_color">@color/car_on_surface</color>
+    <color name="privacy_chip_dark_icon_color">@color/car_surface</color>
     <color name="privacy_chip_light_icon_color">@color/car_nav_icon_fill_color_selected</color>
     <color name="privacy_chip_indicator_outside_stroke_color">@android:color/black</color>
     <color name="system_bar_icon_color">@android:color/white</color>
@@ -145,7 +145,7 @@
     <color name="car_qc_unseen_indicator_color">@color/car_yellow_color</color>
 
     <!-- Color for data subscription popup.-->
-    <color name="qc_pop_up_color">@color/car_blue_color</color>
-    <color name="qc_pop_up_text_color">@android:color/black</color>
+    <color name="qc_pop_up_color">@color/car_surface_2</color>
+    <color name="qc_pop_up_text_color">@color/car_on_surface</color>
 
 </resources>
diff --git a/res/values/config.xml b/res/values/config.xml
index 0296d494..09c0983e 100644
--- a/res/values/config.xml
+++ b/res/values/config.xml
@@ -171,6 +171,10 @@
     -->
     <integer name="hvac_panel_settle_close_percentage">50</integer>
 
+    <!-- Amount of time (in ms) to wait before auto closing the HVAC panel.
+         Set to 0 to disable auto close. -->
+    <integer name="config_hvacAutoDismissDurationMs">0</integer>
+
     <!-- Determines whether the shell features all run on another thread. -->
     <bool name="config_enableShellMainThread">true</bool>
 
@@ -219,13 +223,14 @@
     <!-- 0 disabled -->
     <!-- 1 left -->
     <!-- 2 right -->
-    <integer name="config_showDisplayCompatToolbarOnSystemBar">0</integer>
+    <integer name="config_showDisplayCompatToolbarOnSystemBar">1</integer>
 
     <!-- Determines how to show navigation bar and status bar on app's immersive request, only
         works if config_remoteInsetsControllerControlsSystemBars is set to true-->
     <!-- 0 non_immersive show all system bars on immersive request. -->
     <!-- 1 immersive, hide both bars -->
     <!-- 2 immersive_with_nav, show nav bar and hide status bar -->
+    <!-- 3 immersive based on bar control policy  -->
     <integer name="config_systemBarPersistency">1</integer>
 
     <!-- Determines the orientation of the status icon. -->
@@ -255,5 +260,6 @@
     -->
     <string-array translatable="false" name="config_dataSubscriptionBlockedPackagesList">
         <item>com.android.car.settings</item>
+        <item>com.android.car.carlauncher</item>
     </string-array>
 </resources>
diff --git a/res/values/dimens.xml b/res/values/dimens.xml
index a056f9c7..8e06e8a0 100644
--- a/res/values/dimens.xml
+++ b/res/values/dimens.xml
@@ -470,15 +470,17 @@
 
     <dimen name="dock_container_margin">10dp</dimen>
 
-    <dimen name="data_subscription_pop_up_radius">16dp</dimen>
+    <dimen name="data_subscription_pop_up_radius">24dp</dimen>
     <dimen name="data_subscription_pop_up_arrow_height">19dp</dimen>
     <dimen name="data_subscription_pop_up_arrow_width">38dp</dimen>
     <dimen name="data_subscription_pop_up_arrow_radius">5dp</dimen>
-    <dimen name="data_subscription_pop_up_arrow_offset">30dp</dimen>
+    <dimen name="data_subscription_pop_up_arrow_offset">84dp</dimen>
     <dimen name="data_subscription_pop_up_vertical_padding">46dp</dimen>
     <dimen name="data_subscription_pop_up_horizontal_padding">@*android:dimen/car_padding_3</dimen>
     <dimen name="data_subscription_pop_up_button_width">224dp</dimen>
     <dimen name="data_subscription_pop_up_button_height">68dp</dimen>
     <dimen name="car_quick_controls_panel_margin">8dp</dimen>
     <dimen name="data_subscription_pop_up_horizontal_margin">15dp</dimen>
+    <dimen name="data_subscription_pop_up_horizontal_offset">92dp</dimen>
+    <dimen name="data_subscription_pop_up_vertical_offset">6dp</dimen>
 </resources>
diff --git a/res/values/ids.xml b/res/values/ids.xml
index 0c4c8d7f..886b5664 100644
--- a/res/values/ids.xml
+++ b/res/values/ids.xml
@@ -24,6 +24,7 @@
     <item type="id" name="qc_display_status_icon"/>
     <item type="id" name="qc_bluetooth_status_icon"/>
     <item type="id" name="qc_signal_status_icon"/>
+    <item type="id" name="qc_sound_status_icon"/>
     <item type="id" name="qc_location_status_icon"/>
     <item type="id" name="qc_phone_call_status_icon"/>
     <item type="id" name="qc_drive_mode_status_icon"/>
@@ -37,4 +38,8 @@
     <item type="id" name="car_bottom_bar_window"/>
     <item type="id" name="car_left_bar_window"/>
     <item type="id" name="car_right_bar_window"/>
+
+    <!-- Id values for custom HVAC animations -->
+    <item type="anim" name="hvac_open_anim"/>
+    <item type="anim" name="hvac_close_anim"/>
 </resources>
diff --git a/res/values/strings.xml b/res/values/strings.xml
index 1eb07f83..2dfa2254 100644
--- a/res/values/strings.xml
+++ b/res/values/strings.xml
@@ -59,6 +59,8 @@
     <string name="car_loading_profile">Loading</string>
     <!-- Message to inform user that the new user profile is loading with additional information on the previous and the next user. [CHAR LIMIT=100] -->
     <string name="car_loading_profile_developer_message">Loading user (from <xliff:g id="from_user" example="10">%1$d</xliff:g> to <xliff:g id="to_user" example="12">%2$d</xliff:g>)</string>
+    <!-- Subtitle for current profile in profile switch panel [CHAR LIMIT=20]-->
+    <string name="current_profile_subtitle">Current profile</string>
 
     <!-- Accessibility content description for microphone/camera off state of privacy chip. [CHAR LIMIT=40]-->
     <string name="privacy_chip_off_content"><xliff:g id="sensor" example="Microphone">%1$s</xliff:g> is off.</string>
@@ -144,6 +146,9 @@
     <string name="status_icon_signal_hotspot">Signal Settings: Hotspot On</string>
     <!-- Status icon for display settings in status bar-->
     <string name="status_icon_display_status">Display Settings</string>
+    <!-- Status icon for debug settings in status bar-->
+    <string name="status_icon_debug_status">Debug Settings</string>
+    <string name="status_icon_sound_status">Sound Settings</string>
     <!-- Status icon for drive mode settings in status bar -->
     <string name="status_icon_drive_mode">Drive Mode</string>
 
@@ -174,6 +179,8 @@
     <string name="qc_footer_network_sound_settings">Sound settings</string>
     <!-- Quick Controls: Message to be displayed as the footer button to launch profiles and accounts settings [CHAR LIMIT=45] -->
     <string name="qc_footer_profiles_accounts_settings">Profiles &amp; accounts settings</string>
+    <!-- Quick Controls: Message to be displayed as the footer button to launch developer options settings [CHAR LIMIT=45] -->
+    <string name="qc_footer_debug_settings">Developer options</string>
 
     <!-- Message shown when the lock pattern is focused. [CHAR LIMIT=40] -->
     <string name="lockpattern_does_not_support_rotary">Pattern does not support rotary; please use touch</string>
@@ -220,6 +227,10 @@
     <string name="stopping_user_text">Signing out…</string>
     <!-- User Picker: snack bar message when clicking stopping user -->
     <string name="wait_for_until_stopped_message"><xliff:g id="user_name" example="Peter">%s</xliff:g> is being signed out. Try again later.</string>
+    <!-- User Picker: text when user is unavailable because they're secure -->
+    <string name="unavailable_secure_user_text">User currently unavailable</string>
+    <!-- User Picker: snack bar message when clicking unavailable secure user -->
+    <string name="unavailable_secure_user_message">Unable to start secure user on passenger display</string>
 
     <!-- User Picker: seat string -->
     <string name="seat_driver">driver</string>
@@ -277,6 +288,7 @@
     <string name="data_subscription_button_text">See plans</string>
     <!-- Data subscription proactive message prompt-->
     <string name="data_subscription_proactive_msg_prompt">Your internet plan expired</string>
-    <string name="data_subscription_reactive_msg_prompt">This app needs an internet connection</string>
+    <string name="data_subscription_reactive_msg_prompt">%s needs an internet connection</string>
+    <string name="data_subscription_reactive_generic_app_label">This app</string>
 
 </resources>
diff --git a/res/values/themes.xml b/res/values/themes.xml
index f95dc156..3538cc06 100644
--- a/res/values/themes.xml
+++ b/res/values/themes.xml
@@ -30,4 +30,10 @@
         <item name="snackbarButtonStyle">@style/Widget.MaterialComponents.Button.TextButton.Snackbar</item>
         <item name="snackbarTextViewStyle">@style/UserPickerSnackBarText</item>
     </style>
+
+    <!-- Used by the ActivityBlockingActivity to hide the splash screen icon -->
+    <style name="Theme.NoTitleBar.NoSplash" parent="@android:style/Theme.NoTitleBar">
+        <item name="android:windowSplashScreenAnimatedIcon">@android:color/transparent</item>
+        <item name="android:windowSplashScreenAnimationDuration">0</item>
+    </style>
 </resources>
diff --git a/samples/SystemBarPersistencyBarPolicy/Android.bp b/samples/SystemBarPersistencyBarPolicy/Android.bp
new file mode 100644
index 00000000..5eea5645
--- /dev/null
+++ b/samples/SystemBarPersistencyBarPolicy/Android.bp
@@ -0,0 +1,26 @@
+//
+// Copyright (C) 2023 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+//
+
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+// Sets the CarSystemUI systemBar persistcy to bar policy.
+runtime_resource_overlay {
+    name: "CarSystemUISystemBarPersistcyBarPolicy",
+    resource_dirs: ["res"],
+    manifest: "AndroidManifest.xml",
+}
diff --git a/samples/SystemBarPersistencyBarPolicy/AndroidManifest.xml b/samples/SystemBarPersistencyBarPolicy/AndroidManifest.xml
new file mode 100644
index 00000000..62ab002a
--- /dev/null
+++ b/samples/SystemBarPersistencyBarPolicy/AndroidManifest.xml
@@ -0,0 +1,24 @@
+<!--
+  ~ Copyright (C) 2023 The Android Open Source Project
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
+<manifest xmlns:android="http://schemas.android.com/apk/res/android"
+          package="com.android.car.systemui.systembar.persistency.barpolicy">
+    <overlay
+        android:targetPackage="com.android.systemui"
+        android:isStatic="false"
+        android:resourcesMap="@xml/car_sysui_overlays"
+    />
+</manifest>
\ No newline at end of file
diff --git a/samples/SystemBarPersistencyBarPolicy/res/values/config.xml b/samples/SystemBarPersistencyBarPolicy/res/values/config.xml
new file mode 100644
index 00000000..1e08c47d
--- /dev/null
+++ b/samples/SystemBarPersistencyBarPolicy/res/values/config.xml
@@ -0,0 +1,26 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2023 The Android Open Source Project
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
+<resources>
+    <!-- Determines if how to show navigation bar and status bar on app's immersive request, only
+        works if config_remoteInsetsControllerControlsSystemBars is set to true-->
+    <!-- 0 non_immersive show all system bars on immersive request. -->
+    <!-- 1 immersive, hide both bars -->
+    <!-- 2 immersive_with_nav, show nav bar and hide status bar -->
+    <!-- 3 immersive based on bar control policy  -->
+    <integer name="config_systemBarPersistency">3</integer>
+</resources>
\ No newline at end of file
diff --git a/samples/SystemBarPersistencyBarPolicy/res/xml/car_sysui_overlays.xml b/samples/SystemBarPersistencyBarPolicy/res/xml/car_sysui_overlays.xml
new file mode 100644
index 00000000..30d15d21
--- /dev/null
+++ b/samples/SystemBarPersistencyBarPolicy/res/xml/car_sysui_overlays.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2023 The Android Open Source Project
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
+<overlay>
+    <item
+        target="integer/config_systemBarPersistency"
+        value="@integer/config_systemBarPersistency" />
+</overlay>
\ No newline at end of file
diff --git a/samples/systemui_sample_rros.mk b/samples/systemui_sample_rros.mk
index 95d4005b..50dd0d2e 100644
--- a/samples/systemui_sample_rros.mk
+++ b/samples/systemui_sample_rros.mk
@@ -16,6 +16,7 @@
 
 PRODUCT_PACKAGES += \
     CarSystemUIControllsSystemBarInsetsRRO \
+    CarSystemUISystemBarPersistcyBarPolicy \
     CarSystemUISystemBarPersistcyImmersive \
     CarSystemUISystemBarPersistcyImmersiveWithNav \
     CarSystemUISystemBarPersistcyNonImmersive \
diff --git a/src/com/android/systemui/CarSysUIComponent.java b/src/com/android/systemui/CarSysUIComponent.java
index cb78def9..731159cb 100644
--- a/src/com/android/systemui/CarSysUIComponent.java
+++ b/src/com/android/systemui/CarSysUIComponent.java
@@ -21,7 +21,6 @@ import com.android.systemui.dagger.SysUIComponent;
 import com.android.systemui.dagger.SysUISingleton;
 import com.android.systemui.dagger.SystemUIModule;
 import com.android.systemui.scene.ShadelessSceneContainerFrameworkModule;
-import com.android.systemui.wm.MDSystemBarsController;
 import com.android.wm.shell.RootTaskDisplayAreaOrganizer;
 
 import dagger.BindsInstance;
@@ -51,9 +50,6 @@ public interface CarSysUIComponent extends SysUIComponent {
         @BindsInstance
         Builder setRootTaskDisplayAreaOrganizer(Optional<RootTaskDisplayAreaOrganizer> r);
 
-        @BindsInstance
-        Builder setMDSystemBarsController(Optional<MDSystemBarsController> m);
-
         CarSysUIComponent build();
     }
 }
diff --git a/src/com/android/systemui/CarSystemUIInitializer.java b/src/com/android/systemui/CarSystemUIInitializer.java
index ef03e25e..98f80f43 100644
--- a/src/com/android/systemui/CarSystemUIInitializer.java
+++ b/src/com/android/systemui/CarSystemUIInitializer.java
@@ -48,8 +48,7 @@ public class CarSystemUIInitializer extends SystemUIInitializer {
         boolean isSystemUser = UserHandle.myUserId() == UserHandle.USER_SYSTEM;
         return ((CarSysUIComponent.Builder) sysUIBuilder).setRootTaskDisplayAreaOrganizer(
                         isSystemUser ? Optional.of(carWm.getRootTaskDisplayAreaOrganizer())
-                                : Optional.empty())
-                .setMDSystemBarsController(carWm.getMDSystemBarController());
+                                : Optional.empty());
     }
 
     private void initWmComponents(CarWMComponent carWm) {
diff --git a/src/com/android/systemui/CarSystemUIModule.java b/src/com/android/systemui/CarSystemUIModule.java
index 5784d7e2..87739912 100644
--- a/src/com/android/systemui/CarSystemUIModule.java
+++ b/src/com/android/systemui/CarSystemUIModule.java
@@ -25,11 +25,14 @@ import android.window.DisplayAreaOrganizer;
 
 import com.android.keyguard.KeyguardViewController;
 import com.android.keyguard.dagger.KeyguardDisplayModule;
+import com.android.systemui.accessibility.AccessibilityModule;
+import com.android.systemui.accessibility.data.repository.AccessibilityRepositoryModule;
 import com.android.systemui.biometrics.dagger.BiometricsModule;
 import com.android.systemui.car.CarDeviceProvisionedController;
 import com.android.systemui.car.CarDeviceProvisionedControllerImpl;
 import com.android.systemui.car.decor.CarPrivacyChipDecorProviderFactory;
 import com.android.systemui.car.decor.CarPrivacyChipViewController;
+import com.android.systemui.car.displayconfig.ExternalDisplayController;
 import com.android.systemui.car.drivemode.DriveModeModule;
 import com.android.systemui.car.keyguard.CarKeyguardViewController;
 import com.android.systemui.car.notification.NotificationShadeWindowControllerImpl;
@@ -41,7 +44,6 @@ import com.android.systemui.dagger.GlobalRootComponent;
 import com.android.systemui.dagger.SysUISingleton;
 import com.android.systemui.dagger.qualifiers.Main;
 import com.android.systemui.decor.PrivacyDotDecorProviderFactory;
-import com.android.systemui.display.ui.viewmodel.ConnectingDisplayViewModel;
 import com.android.systemui.dock.DockManager;
 import com.android.systemui.dock.DockManagerImpl;
 import com.android.systemui.doze.DozeHost;
@@ -57,6 +59,7 @@ import com.android.systemui.recents.Recents;
 import com.android.systemui.recents.RecentsImplementation;
 import com.android.systemui.recents.RecentsModule;
 import com.android.systemui.screenshot.ReferenceScreenshotModule;
+import com.android.systemui.settings.UserTracker;
 import com.android.systemui.shade.ShadeEmptyImplModule;
 import com.android.systemui.statusbar.CommandQueue;
 import com.android.systemui.statusbar.NotificationLockscreenUserManager;
@@ -83,12 +86,14 @@ import javax.inject.Named;
 
 @Module(
         includes = {
+                AccessibilityModule.class,
+                AccessibilityRepositoryModule.class,
                 ActivityWindowModule.class,
                 AospPolicyModule.class,
                 BiometricsModule.class,
                 CarMultiUserUtilsModule.class,
                 CarVolumeModule.class,
-                ConnectingDisplayViewModel.StartableModule.class,
+                ExternalDisplayController.StartableModule.class,
                 DriveModeModule.class,
                 GestureModule.class,
                 HeadsUpEmptyImplModule.class,
@@ -151,9 +156,9 @@ abstract class CarSystemUIModule {
     @Provides
     @SysUISingleton
     static IndividualSensorPrivacyController provideIndividualSensorPrivacyController(
-            SensorPrivacyManager sensorPrivacyManager) {
+            SensorPrivacyManager sensorPrivacyManager, UserTracker userTracker) {
         IndividualSensorPrivacyController spC = new IndividualSensorPrivacyControllerImpl(
-                sensorPrivacyManager);
+                sensorPrivacyManager, userTracker);
         spC.init();
         return spC;
     }
diff --git a/src/com/android/systemui/car/displaycompat/CarDisplayCompatSystemBarView.java b/src/com/android/systemui/car/displaycompat/CarDisplayCompatSystemBarView.java
index 479aa14d..b77a9417 100644
--- a/src/com/android/systemui/car/displaycompat/CarDisplayCompatSystemBarView.java
+++ b/src/com/android/systemui/car/displaycompat/CarDisplayCompatSystemBarView.java
@@ -28,7 +28,8 @@ import com.android.systemui.car.systembar.CarSystemBarView;
  */
 public class CarDisplayCompatSystemBarView extends CarSystemBarView {
 
-    public static final String DISPLAYCOMPAT_SYSTEM_FEATURE = "android.car.displaycompatibility";
+    public static final String DISPLAYCOMPAT_SYSTEM_FEATURE =
+            "android.software.car.display_compatibility";
 
     public CarDisplayCompatSystemBarView(Context context, AttributeSet attrs) {
         super(context, attrs);
diff --git a/src/com/android/systemui/car/displayconfig/ExternalDisplayController.kt b/src/com/android/systemui/car/displayconfig/ExternalDisplayController.kt
new file mode 100644
index 00000000..c36b9b17
--- /dev/null
+++ b/src/com/android/systemui/car/displayconfig/ExternalDisplayController.kt
@@ -0,0 +1,73 @@
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
+package com.android.systemui.car.displayconfig
+
+import android.os.Build
+import android.util.Log
+import com.android.systemui.CoreStartable
+import com.android.systemui.dagger.SysUISingleton
+import com.android.systemui.dagger.qualifiers.Application
+import com.android.systemui.dagger.qualifiers.Background
+import com.android.systemui.display.data.repository.DisplayRepository
+import com.android.systemui.process.ProcessWrapper
+import dagger.Binds
+import dagger.Module
+import dagger.multibindings.ClassKey
+import dagger.multibindings.IntoMap
+import javax.inject.Inject
+import kotlinx.coroutines.CoroutineDispatcher
+import kotlinx.coroutines.CoroutineScope
+import kotlinx.coroutines.launch
+
+@SysUISingleton
+class ExternalDisplayController @Inject constructor(
+    private val displayRepository: DisplayRepository,
+    private val processWrapper: ProcessWrapper,
+    @Application private val scope: CoroutineScope,
+    @Background private val bgDispatcher: CoroutineDispatcher,
+) : CoreStartable {
+
+    override fun start() {
+        if (!processWrapper.isSystemUser) {
+            if (DEBUG) {
+                Log.d(TAG, "no-op for non-system users")
+            }
+            return
+        }
+        scope.launch(bgDispatcher) {
+            displayRepository.pendingDisplay.collect {
+                if (DEBUG) {
+                    Log.d(TAG, "Enabling pending display")
+                }
+                it?.enable()
+            }
+        }
+    }
+
+    companion object {
+        private val TAG: String = ExternalDisplayController::class.java.simpleName
+        private val DEBUG: Boolean = Build.IS_ENG || Build.IS_USERDEBUG
+    }
+
+    @Module
+    interface StartableModule {
+        @Binds
+        @IntoMap
+        @ClassKey(ExternalDisplayController::class)
+        fun bindsExternalDisplayController(impl: ExternalDisplayController): CoreStartable
+    }
+}
diff --git a/src/com/android/systemui/car/hvac/HvacController.java b/src/com/android/systemui/car/hvac/HvacController.java
index 8ca95c79..c091dbdd 100644
--- a/src/com/android/systemui/car/hvac/HvacController.java
+++ b/src/com/android/systemui/car/hvac/HvacController.java
@@ -178,6 +178,9 @@ public class HvacController implements HvacPropertySetter,
     }
 
     private int[] getSupportedAreaIds(int propertyId) {
+        if (mCarPropertyManager == null) {
+            return new int[] {};
+        }
         CarPropertyConfig config = mCarPropertyManager.getCarPropertyConfig(propertyId);
         if (config == null) {
             // This property isn't supported/exposed by the CarPropertyManager. So an empty array is
@@ -366,6 +369,10 @@ public class HvacController implements HvacPropertySetter,
      * Unregisters all {@link HvacView}s in the {@code rootView} and its descendents.
      */
     public void unregisterViews(View rootView) {
+        if (!mIsConnectedToCar) {
+            mViewsToInit.remove(rootView);
+            return;
+        }
         if (rootView instanceof HvacView) {
             HvacView hvacView = (HvacView) rootView;
             @HvacProperty Integer propId = hvacView.getHvacPropertyToView();
diff --git a/src/com/android/systemui/car/hvac/HvacPanelController.java b/src/com/android/systemui/car/hvac/HvacPanelController.java
new file mode 100644
index 00000000..ba4a1624
--- /dev/null
+++ b/src/com/android/systemui/car/hvac/HvacPanelController.java
@@ -0,0 +1,25 @@
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
+package com.android.systemui.car.hvac;
+
+/** Interface for controlling the HVAC panel. */
+public interface HvacPanelController {
+    /** Toggles the visibility of the HVAC shade. */
+    void togglePanel();
+
+    /** Returns {@code true} if the panel is open. */
+    boolean isHvacPanelOpen();
+}
diff --git a/src/com/android/systemui/car/hvac/HvacPanelOverlayViewController.java b/src/com/android/systemui/car/hvac/HvacPanelOverlayViewController.java
index ed2df3af..d335d6f9 100644
--- a/src/com/android/systemui/car/hvac/HvacPanelOverlayViewController.java
+++ b/src/com/android/systemui/car/hvac/HvacPanelOverlayViewController.java
@@ -16,11 +16,16 @@
 
 package com.android.systemui.car.hvac;
 
-import android.app.UiModeManager;
+import android.animation.Animator;
+import android.animation.AnimatorInflater;
+import android.animation.ValueAnimator;
 import android.content.Context;
 import android.content.res.Configuration;
 import android.content.res.Resources;
 import android.graphics.Rect;
+import android.os.Build;
+import android.os.Handler;
+import android.util.Log;
 import android.view.KeyEvent;
 import android.view.LayoutInflater;
 import android.view.MotionEvent;
@@ -28,6 +33,8 @@ import android.view.View;
 import android.view.ViewGroup;
 import android.view.WindowInsets;
 
+import androidx.annotation.Nullable;
+
 import com.android.systemui.R;
 import com.android.systemui.car.CarDeviceProvisionedController;
 import com.android.systemui.car.window.OverlayPanelViewController;
@@ -42,36 +49,49 @@ import javax.inject.Inject;
 @SysUISingleton
 public class HvacPanelOverlayViewController extends OverlayPanelViewController implements
         ConfigurationController.ConfigurationListener {
+    private static final boolean DEBUG = Build.IS_ENG || Build.IS_USERDEBUG;
+    private static final String TAG = HvacPanelOverlayViewController.class.getName();
 
     private final Context mContext;
     private final Resources mResources;
+    private final Handler mHandler;
     private final HvacController mHvacController;
-    private final UiModeManager mUiModeManager;
     private final float mFullyOpenDimAmount;
+    private final int mAutoDismissDurationMs;
 
     private boolean mIsUiModeNight;
     private float mCurrentDimAmount = 0f;
+    @Nullable
+    private Animator mOpenAnimator;
+    @Nullable
+    private Animator mCloseAnimator;
 
     private HvacPanelView mHvacPanelView;
 
+    private final Runnable mAutoDismiss = () -> {
+        if (isPanelExpanded()) {
+            toggle();
+        }
+    };
+
     @Inject
     public HvacPanelOverlayViewController(Context context,
             @Main Resources resources,
+            @Main Handler handler,
             HvacController hvacController,
             OverlayViewGlobalStateController overlayViewGlobalStateController,
             FlingAnimationUtils.Builder flingAnimationUtilsBuilder,
             CarDeviceProvisionedController carDeviceProvisionedController,
-            ConfigurationController configurationController,
-            UiModeManager uiModeManager) {
+            ConfigurationController configurationController) {
         super(context, resources, R.id.hvac_panel_stub, overlayViewGlobalStateController,
                 flingAnimationUtilsBuilder, carDeviceProvisionedController);
         mContext = context;
         mResources = resources;
+        mHandler = handler;
         mHvacController = hvacController;
-        mUiModeManager = uiModeManager;
         configurationController.addCallback(this);
-        mFullyOpenDimAmount = mContext.getResources().getFloat(
-                R.fraction.hvac_overlay_window_dim_amount);
+        mFullyOpenDimAmount = mResources.getFloat(R.fraction.hvac_overlay_window_dim_amount);
+        mAutoDismissDurationMs = mResources.getInteger(R.integer.config_hvacAutoDismissDurationMs);
     }
 
     @Override
@@ -80,7 +100,7 @@ public class HvacPanelOverlayViewController extends OverlayPanelViewController i
 
         View closeButton = getLayout().findViewById(R.id.hvac_panel_close_button);
         if (closeButton != null) {
-            closeButton.setOnClickListener(v -> toggle());
+            closeButton.setOnClickListener(v -> dismissHvacPanel());
         }
 
         mHvacPanelView = getLayout().findViewById(R.id.hvac_panel);
@@ -92,10 +112,16 @@ public class HvacPanelOverlayViewController extends OverlayPanelViewController i
             }
 
             if (event.getAction() == KeyEvent.ACTION_UP && isPanelExpanded()) {
-                toggle();
+                dismissHvacPanel();
             }
             return true;
         });
+
+        mHvacPanelView.setMotionEventHandler((event -> {
+            setAutoDismissTimeout();
+        }));
+
+        loadCustomAnimators();
     }
 
     @Override
@@ -149,13 +175,13 @@ public class HvacPanelOverlayViewController extends OverlayPanelViewController i
     }
 
     @Override
-    protected void onAnimateCollapsePanel() {
-        // no-op.
+    protected void onAnimateExpandPanel() {
+        setAutoDismissTimeout();
     }
 
     @Override
-    protected void onAnimateExpandPanel() {
-        // no-op.
+    protected void onAnimateCollapsePanel() {
+        removeAutoDismissTimeout();
     }
 
     @Override
@@ -182,7 +208,7 @@ public class HvacPanelOverlayViewController extends OverlayPanelViewController i
         mHvacPanelView.getBoundsInWindow(outBounds, /* clipToParent= */ true);
         if (isPanelExpanded() && (event.getAction() == MotionEvent.ACTION_UP)
                 && isTouchOutside(outBounds, event.getX(), event.getY())) {
-            toggle();
+            dismissHvacPanel();
         }
     }
 
@@ -201,6 +227,57 @@ public class HvacPanelOverlayViewController extends OverlayPanelViewController i
         return x < bounds.left || x > bounds.right || y < bounds.top || y > bounds.bottom;
     }
 
+    private void dismissHvacPanel() {
+        removeAutoDismissTimeout();
+        mHandler.post(mAutoDismiss);
+    }
+
+    private void setAutoDismissTimeout() {
+        if (mAutoDismissDurationMs > 0) {
+            mHandler.removeCallbacks(mAutoDismiss);
+            mHandler.postDelayed(mAutoDismiss, mAutoDismissDurationMs);
+        }
+    }
+
+    private void removeAutoDismissTimeout() {
+        if (mAutoDismissDurationMs > 0) {
+            mHandler.removeCallbacks(mAutoDismiss);
+        }
+    }
+
+    private void loadCustomAnimators() {
+        try {
+            mOpenAnimator = AnimatorInflater.loadAnimator(mContext, R.anim.hvac_open_anim);
+            mOpenAnimator.setTarget(getLayout());
+        } catch (Resources.NotFoundException e) {
+            if (DEBUG) {
+                Log.d(TAG, "Custom open animator not found - using default");
+            }
+        }
+
+        try {
+            mCloseAnimator = AnimatorInflater.loadAnimator(mContext, R.anim.hvac_close_anim);
+            mCloseAnimator.setTarget(getLayout());
+        } catch (Resources.NotFoundException e) {
+            if (DEBUG) {
+                Log.d(TAG, "Custom close animator not found - using default");
+            }
+        }
+    }
+
+    @Override
+    protected Animator getCustomAnimator(float from, float to, float velocity, boolean isClosing) {
+        Animator animator = isClosing ? mCloseAnimator : mOpenAnimator;
+        if (animator != null) {
+            animator.removeAllListeners();
+            if (animator instanceof ValueAnimator) {
+                ((ValueAnimator) animator).setFloatValues(from, to);
+            }
+        }
+
+        return animator;
+    }
+
     @Override
     public void onConfigChanged(Configuration newConfig) {
         boolean isConfigNightMode = newConfig.isNightModeActive();
@@ -208,7 +285,6 @@ public class HvacPanelOverlayViewController extends OverlayPanelViewController i
         // Only refresh UI on Night mode changes
         if (isConfigNightMode != mIsUiModeNight) {
             mIsUiModeNight = isConfigNightMode;
-            mUiModeManager.setNightModeActivated(mIsUiModeNight);
 
             if (getLayout() == null) return;
             mHvacPanelView = getLayout().findViewById(R.id.hvac_panel);
diff --git a/src/com/android/systemui/car/hvac/HvacPanelOverlayViewMediator.java b/src/com/android/systemui/car/hvac/HvacPanelOverlayViewMediator.java
index 6c7e55c8..348d11d3 100644
--- a/src/com/android/systemui/car/hvac/HvacPanelOverlayViewMediator.java
+++ b/src/com/android/systemui/car/hvac/HvacPanelOverlayViewMediator.java
@@ -16,6 +16,10 @@
 
 package com.android.systemui.car.hvac;
 
+import static com.android.systemui.car.systembar.CarSystemBarController.BOTTOM;
+import static com.android.systemui.car.systembar.CarSystemBarController.LEFT;
+import static com.android.systemui.car.systembar.CarSystemBarController.RIGHT;
+import static com.android.systemui.car.systembar.CarSystemBarController.TOP;
 import static com.android.systemui.car.window.OverlayPanelViewController.OVERLAY_FROM_BOTTOM_BAR;
 
 import android.content.BroadcastReceiver;
@@ -85,17 +89,17 @@ public class HvacPanelOverlayViewMediator implements OverlayViewMediator {
 
     @Override
     public void registerListeners() {
-        mCarSystemBarController.registerTopBarTouchListener(
+        mCarSystemBarController.registerBarTouchListener(TOP,
                 mHvacPanelOverlayViewController.getDragCloseTouchListener());
-        mCarSystemBarController.registerBottomBarTouchListener(
+        mCarSystemBarController.registerBarTouchListener(BOTTOM,
                 mHvacPanelOverlayViewController.getDragCloseTouchListener());
-        mCarSystemBarController.registerLeftBarTouchListener(
+        mCarSystemBarController.registerBarTouchListener(LEFT,
                 mHvacPanelOverlayViewController.getDragCloseTouchListener());
-        mCarSystemBarController.registerRightBarTouchListener(
+        mCarSystemBarController.registerBarTouchListener(RIGHT,
                 mHvacPanelOverlayViewController.getDragCloseTouchListener());
 
         mCarSystemBarController.registerHvacPanelController(
-                new CarSystemBarController.HvacPanelController() {
+                new HvacPanelController() {
                     @Override
                     public void togglePanel() {
                         mHvacPanelOverlayViewController.toggle();
diff --git a/src/com/android/systemui/car/keyguard/CarKeyguardDisplayManager.java b/src/com/android/systemui/car/keyguard/CarKeyguardDisplayManager.java
new file mode 100644
index 00000000..f54c79f6
--- /dev/null
+++ b/src/com/android/systemui/car/keyguard/CarKeyguardDisplayManager.java
@@ -0,0 +1,55 @@
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
+package com.android.systemui.car.keyguard;
+
+import android.content.Context;
+
+import com.android.keyguard.ConnectedDisplayKeyguardPresentation;
+import com.android.keyguard.KeyguardDisplayManager;
+import com.android.systemui.dagger.SysUISingleton;
+import com.android.systemui.navigationbar.NavigationBarController;
+import com.android.systemui.settings.DisplayTracker;
+import com.android.systemui.statusbar.policy.KeyguardStateController;
+
+import dagger.Lazy;
+
+import java.util.concurrent.Executor;
+
+/**
+ * Implementation of the {@link KeyguardDisplayManager} that provides different display tracker
+ * implementations depending on the system.
+ *
+ * For the driver SystemUI instance on a MUMD system, the default DisplayTrackerImpl is provided
+ * in place of the MUMD display tracker so that when the driver is locked, the
+ * KeyguardDisplayManager can be aware of all displays on the system, not just the driver displays.
+ * In all other cases, the default display tracker provided by dagger will be used.
+ */
+@SysUISingleton
+public class CarKeyguardDisplayManager extends KeyguardDisplayManager {
+    public CarKeyguardDisplayManager(Context context,
+            Lazy<NavigationBarController> navigationBarControllerLazy,
+            DisplayTracker displayTracker,
+            Executor mainExecutor, Executor uiBgExecutor,
+            KeyguardDisplayManager.DeviceStateHelper deviceStateHelper,
+            KeyguardStateController keyguardStateController,
+            ConnectedDisplayKeyguardPresentation.Factory
+                    connectedDisplayKeyguardPresentationFactory) {
+        super(context, navigationBarControllerLazy, displayTracker, mainExecutor, uiBgExecutor,
+                deviceStateHelper, keyguardStateController,
+                connectedDisplayKeyguardPresentationFactory);
+    }
+}
diff --git a/src/com/android/systemui/car/keyguard/CarKeyguardModule.java b/src/com/android/systemui/car/keyguard/CarKeyguardModule.java
index 7794c96f..ec597b82 100644
--- a/src/com/android/systemui/car/keyguard/CarKeyguardModule.java
+++ b/src/com/android/systemui/car/keyguard/CarKeyguardModule.java
@@ -23,7 +23,9 @@ import android.os.PowerManager;
 
 import com.android.internal.jank.InteractionJankMonitor;
 import com.android.internal.logging.UiEventLogger;
+import com.android.internal.statusbar.IStatusBarService;
 import com.android.internal.widget.LockPatternUtils;
+import com.android.keyguard.ConnectedDisplayKeyguardPresentation;
 import com.android.keyguard.KeyguardDisplayManager;
 import com.android.keyguard.KeyguardUpdateMonitor;
 import com.android.keyguard.KeyguardViewController;
@@ -36,6 +38,7 @@ import com.android.keyguard.mediator.ScreenOnCoordinator;
 import com.android.systemui.CoreStartable;
 import com.android.systemui.animation.ActivityTransitionAnimator;
 import com.android.systemui.broadcast.BroadcastDispatcher;
+import com.android.systemui.car.users.CarSystemUIUserUtil;
 import com.android.systemui.classifier.FalsingCollector;
 import com.android.systemui.classifier.FalsingModule;
 import com.android.systemui.communal.ui.viewmodel.CommunalTransitionViewModel;
@@ -56,7 +59,11 @@ import com.android.systemui.keyguard.dagger.KeyguardFaceAuthNotSupportedModule;
 import com.android.systemui.keyguard.data.repository.KeyguardRepositoryModule;
 import com.android.systemui.keyguard.domain.interactor.KeyguardInteractor;
 import com.android.systemui.log.SessionTracker;
+import com.android.systemui.navigationbar.NavigationBarController;
 import com.android.systemui.navigationbar.NavigationModeController;
+import com.android.systemui.process.ProcessWrapper;
+import com.android.systemui.settings.DisplayTracker;
+import com.android.systemui.settings.DisplayTrackerImpl;
 import com.android.systemui.settings.UserTracker;
 import com.android.systemui.shade.ShadeController;
 import com.android.systemui.statusbar.NotificationShadeDepthController;
@@ -83,10 +90,10 @@ import dagger.Provides;
 import dagger.multibindings.ClassKey;
 import dagger.multibindings.IntoMap;
 
-import java.util.concurrent.Executor;
-
 import kotlinx.coroutines.CoroutineDispatcher;
 
+import java.util.concurrent.Executor;
+
 /**
  * Dagger Module providing keyguard.
  */
@@ -125,7 +132,7 @@ public interface CarKeyguardModule {
             @UiBackground Executor uiBgExecutor,
             DeviceConfigProxy deviceConfig,
             NavigationModeController navigationModeController,
-            KeyguardDisplayManager keyguardDisplayManager,
+            CarKeyguardDisplayManager keyguardDisplayManager,
             DozeParameters dozeParameters,
             SysuiStatusBarStateController statusBarStateController,
             KeyguardStateController keyguardStateController,
@@ -143,10 +150,12 @@ public interface CarKeyguardModule {
             Lazy<ActivityTransitionAnimator> activityTransitionAnimator,
             Lazy<ScrimController> scrimControllerLazy,
             IActivityTaskManager activityTaskManagerService,
+            IStatusBarService statusBarService,
             FeatureFlags featureFlags,
             SecureSettings secureSettings,
             SystemSettings systemSettings,
             SystemClock systemClock,
+            ProcessWrapper processWrapper,
             @Main CoroutineDispatcher mainDispatcher,
             Lazy<DreamViewModel> dreamViewModel,
             Lazy<CommunalTransitionViewModel> communalTransitionViewModel,
@@ -191,10 +200,12 @@ public interface CarKeyguardModule {
                 activityTransitionAnimator,
                 scrimControllerLazy,
                 activityTaskManagerService,
+                statusBarService,
                 featureFlags,
                 secureSettings,
                 systemSettings,
                 systemClock,
+                processWrapper,
                 mainDispatcher,
                 dreamViewModel,
                 communalTransitionViewModel,
@@ -211,6 +222,27 @@ public interface CarKeyguardModule {
         return viewMediator.getViewMediatorCallback();
     }
 
+    /** Provide car keyguard display manager instance. */
+    @Provides
+    @SysUISingleton
+    static CarKeyguardDisplayManager provideCarKeyguardDisplayManager(Context context,
+            Lazy<NavigationBarController> navigationBarControllerLazy,
+            DisplayTracker defaultDisplayTracker,
+            Lazy<DisplayTrackerImpl> displayTrackerImpl,
+            @Main Executor mainExecutor,
+            @UiBackground Executor uiBgExecutor,
+            KeyguardDisplayManager.DeviceStateHelper deviceStateHelper,
+            KeyguardStateController keyguardStateController,
+            ConnectedDisplayKeyguardPresentation.Factory
+                    connectedDisplayKeyguardPresentationFactory) {
+        DisplayTracker finalDisplayTracker =
+                CarSystemUIUserUtil.isDriverMUMDSystemUI() ? displayTrackerImpl.get()
+                        : defaultDisplayTracker;
+        return new CarKeyguardDisplayManager(context, navigationBarControllerLazy,
+                finalDisplayTracker, mainExecutor, uiBgExecutor, deviceStateHelper,
+                keyguardStateController, connectedDisplayKeyguardPresentationFactory);
+    }
+
     /** Binds {@link KeyguardUpdateMonitor} as a {@link CoreStartable}. */
     @Binds
     @IntoMap
diff --git a/src/com/android/systemui/car/keyguard/CarKeyguardViewController.java b/src/com/android/systemui/car/keyguard/CarKeyguardViewController.java
index ef2e61fd..e17fbe27 100644
--- a/src/com/android/systemui/car/keyguard/CarKeyguardViewController.java
+++ b/src/com/android/systemui/car/keyguard/CarKeyguardViewController.java
@@ -16,7 +16,6 @@
 
 package com.android.systemui.car.keyguard;
 
-
 import android.animation.Animator;
 import android.animation.AnimatorListenerAdapter;
 import android.content.Context;
@@ -49,7 +48,6 @@ import com.android.systemui.bouncer.domain.interactor.PrimaryBouncerInteractor;
 import com.android.systemui.bouncer.ui.BouncerView;
 import com.android.systemui.bouncer.ui.binder.KeyguardBouncerViewBinder;
 import com.android.systemui.bouncer.ui.viewmodel.KeyguardBouncerViewModel;
-import com.android.systemui.car.systembar.CarSystemBarController;
 import com.android.systemui.car.window.OverlayViewController;
 import com.android.systemui.car.window.OverlayViewGlobalStateController;
 import com.android.systemui.car.window.SystemUIOverlayWindowController;
@@ -70,6 +68,8 @@ import com.android.systemui.util.concurrency.DelayableExecutor;
 
 import dagger.Lazy;
 
+import java.util.Optional;
+
 import javax.inject.Inject;
 
 /**
@@ -93,7 +93,6 @@ public class CarKeyguardViewController extends OverlayViewController implements
     private final KeyguardUpdateMonitor mKeyguardUpdateMonitor;
     private final Lazy<BiometricUnlockController> mBiometricUnlockControllerLazy;
     private final ViewMediatorCallback mViewMediatorCallback;
-    private final CarSystemBarController mCarSystemBarController;
     private final PrimaryBouncerInteractor mPrimaryBouncerInteractor;
     private final KeyguardSecurityModel mKeyguardSecurityModel;
     private final KeyguardBouncerViewModel mKeyguardBouncerViewModel;
@@ -144,6 +143,7 @@ public class CarKeyguardViewController extends OverlayViewController implements
     private int mToastShowDurationMillisecond;
     private ViewGroup mKeyguardContainer;
     private PrimaryBouncerToGoneTransitionViewModel mPrimaryBouncerToGoneTransitionViewModel;
+    private final Optional<KeyguardSystemBarPresenter> mKeyguardSystemBarPresenter;
 
     @Inject
     public CarKeyguardViewController(
@@ -158,7 +158,6 @@ public class CarKeyguardViewController extends OverlayViewController implements
             KeyguardUpdateMonitor keyguardUpdateMonitor,
             Lazy<BiometricUnlockController> biometricUnlockControllerLazy,
             ViewMediatorCallback viewMediatorCallback,
-            CarSystemBarController carSystemBarController,
             PrimaryBouncerCallbackInteractor primaryBouncerCallbackInteractor,
             PrimaryBouncerInteractor primaryBouncerInteractor,
             KeyguardSecurityModel keyguardSecurityModel,
@@ -169,7 +168,8 @@ public class CarKeyguardViewController extends OverlayViewController implements
             KeyguardMessageAreaController.Factory messageAreaControllerFactory,
             BouncerLogger bouncerLogger,
             BouncerMessageInteractor bouncerMessageInteractor,
-            SelectedUserInteractor selectedUserInteractor) {
+            SelectedUserInteractor selectedUserInteractor,
+            Optional<KeyguardSystemBarPresenter> keyguardSystemBarPresenter) {
         super(R.id.keyguard_stub, overlayViewGlobalStateController);
 
         mContext = context;
@@ -182,7 +182,6 @@ public class CarKeyguardViewController extends OverlayViewController implements
         mKeyguardUpdateMonitor = keyguardUpdateMonitor;
         mBiometricUnlockControllerLazy = biometricUnlockControllerLazy;
         mViewMediatorCallback = viewMediatorCallback;
-        mCarSystemBarController = carSystemBarController;
         mPrimaryBouncerInteractor = primaryBouncerInteractor;
         mKeyguardSecurityModel = keyguardSecurityModel;
         mKeyguardBouncerViewModel = keyguardBouncerViewModel;
@@ -197,6 +196,7 @@ public class CarKeyguardViewController extends OverlayViewController implements
         mBouncerLogger = bouncerLogger;
         mBouncerMessageInteractor = bouncerMessageInteractor;
         primaryBouncerCallbackInteractor.addBouncerExpansionCallback(mExpansionCallback);
+        mKeyguardSystemBarPresenter = keyguardSystemBarPresenter;
     }
 
     @Override
@@ -244,7 +244,9 @@ public class CarKeyguardViewController extends OverlayViewController implements
         mShowing = true;
         mKeyguardStateController.notifyKeyguardState(mShowing,
                 mKeyguardStateController.isOccluded());
-        mCarSystemBarController.showAllKeyguardButtons(/* isSetUp= */ true);
+        if (mKeyguardSystemBarPresenter.isPresent()) {
+            mKeyguardSystemBarPresenter.get().showAllKeyguardButtons();
+        }
         start();
         reset(/* hideBouncerWhenShowing= */ false);
         notifyKeyguardUpdateMonitor();
@@ -260,7 +262,9 @@ public class CarKeyguardViewController extends OverlayViewController implements
         mKeyguardStateController.notifyKeyguardState(mShowing,
                 mKeyguardStateController.isOccluded());
         mPrimaryBouncerInteractor.hide();
-        mCarSystemBarController.showAllNavigationButtons(/* isSetUp= */ true);
+        if (mKeyguardSystemBarPresenter.isPresent()) {
+            mKeyguardSystemBarPresenter.get().showAllNavigationButtons();
+        }
         stop();
         mKeyguardStateController.notifyKeyguardDoneFading();
         mMainExecutor.execute(mViewMediatorCallback::keyguardGone);
@@ -306,13 +310,15 @@ public class CarKeyguardViewController extends OverlayViewController implements
         mKeyguardStateController.notifyKeyguardState(
                 mKeyguardStateController.isShowing(), occluded);
         getOverlayViewGlobalStateController().setOccluded(occluded);
-        if (occluded && !mKeyguardStateController.isUnlocked()) {
-            mCarSystemBarController.showAllOcclusionButtons(/* isSetup= */ true);
-        } else {
-            if (mShowing && isSecure()) {
-                mCarSystemBarController.showAllKeyguardButtons(/* isSetup= */ true);
+        if (mKeyguardSystemBarPresenter.isPresent()) {
+            if (occluded && !mKeyguardStateController.isUnlocked()) {
+                mKeyguardSystemBarPresenter.get().showAllOcclusionButtons();
             } else {
-                mCarSystemBarController.showAllNavigationButtons(/* isSetUp= */ true);
+                if (mShowing && isSecure()) {
+                    mKeyguardSystemBarPresenter.get().showAllKeyguardButtons();
+                } else {
+                    mKeyguardSystemBarPresenter.get().showAllNavigationButtons();
+                }
             }
         }
     }
diff --git a/src/com/android/systemui/car/keyguard/CarKeyguardViewMediator.java b/src/com/android/systemui/car/keyguard/CarKeyguardViewMediator.java
index 69857e25..10279e03 100644
--- a/src/com/android/systemui/car/keyguard/CarKeyguardViewMediator.java
+++ b/src/com/android/systemui/car/keyguard/CarKeyguardViewMediator.java
@@ -28,6 +28,7 @@ import android.view.RemoteAnimationTarget;
 
 import com.android.internal.jank.InteractionJankMonitor;
 import com.android.internal.logging.UiEventLogger;
+import com.android.internal.statusbar.IStatusBarService;
 import com.android.internal.widget.LockPatternUtils;
 import com.android.keyguard.KeyguardDisplayManager;
 import com.android.keyguard.KeyguardUpdateMonitor;
@@ -52,6 +53,7 @@ import com.android.systemui.keyguard.WindowManagerOcclusionManager;
 import com.android.systemui.keyguard.domain.interactor.KeyguardInteractor;
 import com.android.systemui.log.SessionTracker;
 import com.android.systemui.navigationbar.NavigationModeController;
+import com.android.systemui.process.ProcessWrapper;
 import com.android.systemui.settings.UserTracker;
 import com.android.systemui.shade.ShadeController;
 import com.android.systemui.statusbar.NotificationShadeDepthController;
@@ -84,6 +86,8 @@ import kotlinx.coroutines.CoroutineDispatcher;
 public class CarKeyguardViewMediator extends KeyguardViewMediator {
     private static final String TAG = "CarKeyguardViewMediator";
     private final Context mContext;
+    private final TrustManager mTrustManager;
+    private final UserTracker mUserTracker;
     private final Object mOcclusionLock = new Object();
     private final IRemoteAnimationRunner mOccludeAnimationRunner =
             new CarOcclusionAnimationRunner(/* occlude= */ true);
@@ -127,10 +131,12 @@ public class CarKeyguardViewMediator extends KeyguardViewMediator {
             Lazy<ActivityTransitionAnimator> activityTransitionAnimator,
             Lazy<ScrimController> scrimControllerLazy,
             IActivityTaskManager activityTaskManagerService,
+            IStatusBarService statusBarService,
             FeatureFlags featureFlags,
             SecureSettings secureSettings,
             SystemSettings systemSettings,
             SystemClock systemClock,
+            ProcessWrapper processWrapper,
             @Main CoroutineDispatcher mainDispatcher,
             Lazy<DreamViewModel> dreamViewModel,
             Lazy<CommunalTransitionViewModel> communalTransitionViewModel,
@@ -155,7 +161,8 @@ public class CarKeyguardViewMediator extends KeyguardViewMediator {
                 activityTransitionAnimator,
                 scrimControllerLazy,
                 activityTaskManagerService,
-                featureFlags, secureSettings, systemSettings, systemClock,
+                statusBarService,
+                featureFlags, secureSettings, systemSettings, systemClock, processWrapper,
                 mainDispatcher,
                 dreamViewModel,
                 communalTransitionViewModel,
@@ -165,6 +172,8 @@ public class CarKeyguardViewMediator extends KeyguardViewMediator {
                 keyguardInteractor,
                 wmOcclusionManager);
         mContext = context;
+        mTrustManager = trustManager;
+        mUserTracker = userTracker;
     }
 
     @Override
@@ -172,6 +181,11 @@ public class CarKeyguardViewMediator extends KeyguardViewMediator {
         if (CarSystemUIUserUtil.isSecondaryMUMDSystemUI()) {
             // Currently keyguard is not functional for the secondary users in a MUMD configuration
             // TODO_MD: make keyguard functional for secondary users
+
+            // Until keyguard for secondary users is supported, the secondary user's lock status
+            // must be manually updated instead of relying on keyguard hooks.
+            mTrustManager.reportEnabledTrustAgentsChanged(mUserTracker.getUserId());
+
             return;
         }
         super.start();
diff --git a/src/com/android/systemui/car/keyguard/KeyguardSystemBarPresenter.java b/src/com/android/systemui/car/keyguard/KeyguardSystemBarPresenter.java
new file mode 100644
index 00000000..ff292242
--- /dev/null
+++ b/src/com/android/systemui/car/keyguard/KeyguardSystemBarPresenter.java
@@ -0,0 +1,36 @@
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
+package com.android.systemui.car.keyguard;
+
+/**
+ * An interface to handle the UI needed for keygaurd on systembars.
+ */
+public interface KeyguardSystemBarPresenter {
+    /**
+     * Shows all navigation buttons.
+     */
+    void showAllNavigationButtons();
+
+    /**
+     * Shows all keyguard buttons.
+     */
+    void showAllKeyguardButtons();
+
+    /**
+     * Shows all occulusion buttons.
+     */
+    void showAllOcclusionButtons();
+}
diff --git a/src/com/android/systemui/car/ndo/BlockerViewModel.java b/src/com/android/systemui/car/ndo/BlockerViewModel.java
index dc5b637e..ebcb24f1 100644
--- a/src/com/android/systemui/car/ndo/BlockerViewModel.java
+++ b/src/com/android/systemui/car/ndo/BlockerViewModel.java
@@ -48,14 +48,15 @@ public class BlockerViewModel extends ViewModel implements PropertyChangeListene
     @VisibleForTesting
     InCallLiveData mInCallLiveData;
     private final InCallServiceManager mServiceManager;
-    @VisibleForTesting
-    MediaSessionHelper mMediaSessionHelper;
+    private final MediaSessionHelper mMediaSessionHelper;
     private final MediatorLiveData<BlockingType> mBlockingTypeLiveData = new MediatorLiveData<>();
 
     @Inject
-    public BlockerViewModel(Context context, InCallServiceManager serviceManager) {
+    public BlockerViewModel(Context context, InCallServiceManager serviceManager,
+            MediaSessionHelper mediaSessionHelper) {
         mContext = context;
         mServiceManager = serviceManager;
+        mMediaSessionHelper = mediaSessionHelper;
     }
 
     /** Initialize data sources **/
@@ -69,7 +70,7 @@ public class BlockerViewModel extends ViewModel implements PropertyChangeListene
             onInCallServiceConnected();
         }
 
-        mMediaSessionHelper = new MediaSessionHelper(mContext, userHandle);
+        mMediaSessionHelper.init(userHandle);
 
         // Set initial liveData value
         onUpdate();
diff --git a/src/com/android/systemui/car/ndo/MediaSessionHelper.java b/src/com/android/systemui/car/ndo/MediaSessionHelper.java
index 69278d06..bbee5045 100644
--- a/src/com/android/systemui/car/ndo/MediaSessionHelper.java
+++ b/src/com/android/systemui/car/ndo/MediaSessionHelper.java
@@ -16,11 +16,16 @@
 
 package com.android.systemui.car.ndo;
 
+import android.app.INotificationManager;
+import android.app.Notification;
 import android.content.Context;
 import android.media.session.MediaController;
 import android.media.session.MediaSessionManager;
 import android.media.session.PlaybackState;
+import android.os.RemoteException;
 import android.os.UserHandle;
+import android.service.notification.StatusBarNotification;
+import android.util.Log;
 
 import androidx.annotation.Nullable;
 import androidx.annotation.VisibleForTesting;
@@ -28,32 +33,40 @@ import androidx.lifecycle.LiveData;
 import androidx.lifecycle.MutableLiveData;
 
 import java.util.ArrayList;
+import java.util.Collections;
 import java.util.List;
 import java.util.concurrent.Executor;
 
+import javax.inject.Inject;
+
 /**
  * Class that handles listening to and returning active media sessions.
  */
 public class MediaSessionHelper extends MediaController.Callback {
-
+    private static final String TAG = "MediaSessionHelper";
     private final MutableLiveData<List<MediaController>> mLiveData = new MutableLiveData<>();
     private final MediaSessionManager mMediaSessionManager;
-    private final UserHandle mUserHandle;
+    private UserHandle mUserHandle;
     @VisibleForTesting
     final List<MediaController> mMediaControllersList = new ArrayList<>();
     private final Executor mExecutor;
+    private final Context mContext;
+    private final INotificationManager mINotificationManager;
 
     private final MediaSessionManager.OnActiveSessionsChangedListener mChangedListener =
             this::onMediaSessionChange;
 
-    public MediaSessionHelper(Context context, UserHandle userHandle) {
+    @Inject
+    public MediaSessionHelper(Context context, INotificationManager iNotificationManager) {
         mMediaSessionManager = context.getSystemService(MediaSessionManager.class);
-        mUserHandle = userHandle;
         mExecutor = context.getMainExecutor();
-        init();
+        mContext = context;
+        mINotificationManager = iNotificationManager;
     }
 
-    private void init() {
+    /** Performs initialization */
+    public void init(UserHandle userHandle) {
+        mUserHandle = userHandle;
         // Set initial data
         onMediaSessionChange(mMediaSessionManager
                 .getActiveSessionsForUser(/* notificationListener= */ null, mUserHandle));
@@ -88,9 +101,11 @@ public class MediaSessionHelper extends MediaController.Callback {
         }
 
         List<MediaController> activeMediaControllers = new ArrayList<>();
+        List<String> mediaNotificationPackages = getActiveMediaNotificationPackages();
 
         for (MediaController mediaController : mediaControllers) {
-            if (isPausedOrActive(mediaController.getPlaybackState())) {
+            if (isPausedOrActive(mediaController.getPlaybackState())
+                    && mediaNotificationPackages.contains(mediaController.getPackageName())) {
                 activeMediaControllers.add(mediaController);
             } else {
                 // Since playback state changes don't trigger an active media session change, we
@@ -126,4 +141,28 @@ public class MediaSessionHelper extends MediaController.Callback {
         }
         mMediaControllersList.clear();
     }
+
+    // We only want to detect media sessions with an associated media notification
+    private List<String> getActiveMediaNotificationPackages() {
+        try {
+            List<StatusBarNotification> activeNotifications = List.of(
+                    mINotificationManager.getActiveNotificationsWithAttribution(
+                            mContext.getPackageName(), /* callingAttributionTag= */ null
+                    ));
+
+            List<String> packageNames = new ArrayList<>();
+            for (StatusBarNotification statusBarNotification : activeNotifications) {
+                Notification notification = statusBarNotification.getNotification();
+                if (notification.extras != null
+                        && notification.isMediaNotification()) {
+                    packageNames.add(statusBarNotification.getPackageName());
+                }
+            }
+
+            return packageNames;
+        } catch (RemoteException e) {
+            Log.e(TAG, "Exception trying to get active notifications " + e);
+            return Collections.emptyList();
+        }
+    }
 }
diff --git a/src/com/android/systemui/car/ndo/NdoViewModelFactory.java b/src/com/android/systemui/car/ndo/NdoViewModelFactory.java
index c29f0721..6014df95 100644
--- a/src/com/android/systemui/car/ndo/NdoViewModelFactory.java
+++ b/src/com/android/systemui/car/ndo/NdoViewModelFactory.java
@@ -34,11 +34,14 @@ public class NdoViewModelFactory implements ViewModelProvider.Factory {
 
     private final Context mContext;
     private final InCallServiceManager mServiceManager;
+    private final MediaSessionHelper mMediaSessionHelper;
 
     @Inject
-    public NdoViewModelFactory(Context context, InCallServiceManager serviceManager) {
+    public NdoViewModelFactory(Context context, InCallServiceManager serviceManager,
+            MediaSessionHelper mediaSessionHelper) {
         mContext = context;
         mServiceManager = serviceManager;
+        mMediaSessionHelper = mediaSessionHelper;
     }
 
     /**
@@ -49,7 +52,7 @@ public class NdoViewModelFactory implements ViewModelProvider.Factory {
     @SuppressWarnings("unchecked")
     public <T extends ViewModel> T create(@NonNull Class<T> modelClass) {
         if (modelClass.isAssignableFrom(BlockerViewModel.class)) {
-            return (T) new BlockerViewModel(mContext, mServiceManager);
+            return (T) new BlockerViewModel(mContext, mServiceManager, mMediaSessionHelper);
         }
         throw new IllegalArgumentException("Unknown ViewModel class");
     }
diff --git a/src/com/android/systemui/car/notification/BottomNotificationPanelViewMediator.java b/src/com/android/systemui/car/notification/BottomNotificationPanelViewMediator.java
index f52e18d4..c581de72 100644
--- a/src/com/android/systemui/car/notification/BottomNotificationPanelViewMediator.java
+++ b/src/com/android/systemui/car/notification/BottomNotificationPanelViewMediator.java
@@ -16,7 +16,8 @@
 
 package com.android.systemui.car.notification;
 
-import android.app.UiModeManager;
+import static com.android.systemui.car.systembar.CarSystemBarController.BOTTOM;
+
 import android.content.Context;
 
 import com.android.systemui.broadcast.BroadcastDispatcher;
@@ -45,8 +46,7 @@ public class BottomNotificationPanelViewMediator extends NotificationPanelViewMe
             BroadcastDispatcher broadcastDispatcher,
             UserTracker userTracker,
             CarDeviceProvisionedController carDeviceProvisionedController,
-            ConfigurationController configurationController,
-            UiModeManager uiModeManager
+            ConfigurationController configurationController
     ) {
         super(context,
                 carSystemBarController,
@@ -55,15 +55,14 @@ public class BottomNotificationPanelViewMediator extends NotificationPanelViewMe
                 broadcastDispatcher,
                 userTracker,
                 carDeviceProvisionedController,
-                configurationController,
-                uiModeManager);
+                configurationController);
         notificationPanelViewController.setOverlayDirection(
                 OverlayPanelViewController.OVERLAY_FROM_BOTTOM_BAR);
     }
 
     @Override
     protected void registerBottomBarTouchListener() {
-        getCarSystemBarController().registerBottomBarTouchListener(
+        getCarSystemBarController().registerBarTouchListener(BOTTOM,
                 getNotificationPanelViewController().getDragOpenTouchListener());
     }
 }
diff --git a/src/com/android/systemui/car/notification/CarHeadsUpNotificationSystemContainer.java b/src/com/android/systemui/car/notification/CarHeadsUpNotificationSystemContainer.java
index 98b1fc4a..e39ea987 100644
--- a/src/com/android/systemui/car/notification/CarHeadsUpNotificationSystemContainer.java
+++ b/src/com/android/systemui/car/notification/CarHeadsUpNotificationSystemContainer.java
@@ -62,6 +62,9 @@ public class CarHeadsUpNotificationSystemContainer extends CarHeadsUpNotificatio
                         | WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN,
                 PixelFormat.TRANSLUCENT);
 
+        // Needed for passing through touches through HUN's scrim to application content underneath
+        lp.privateFlags = WindowManager.LayoutParams.PRIVATE_FLAG_TRUSTED_OVERLAY;
+
         lp.gravity = getShowHunOnBottom() ? Gravity.BOTTOM : Gravity.TOP;
         lp.setTitle(WINDOW_TITLE);
 
diff --git a/src/com/android/systemui/car/notification/NotificationPanelViewController.java b/src/com/android/systemui/car/notification/NotificationPanelViewController.java
index 58832fa3..ac68b2b8 100644
--- a/src/com/android/systemui/car/notification/NotificationPanelViewController.java
+++ b/src/com/android/systemui/car/notification/NotificationPanelViewController.java
@@ -24,7 +24,6 @@ import android.content.res.Resources;
 import android.graphics.Rect;
 import android.graphics.drawable.Drawable;
 import android.inputmethodservice.InputMethodService;
-import android.os.IBinder;
 import android.os.RemoteException;
 import android.util.Log;
 import android.view.GestureDetector;
@@ -50,6 +49,7 @@ import com.android.systemui.R;
 import com.android.systemui.car.CarDeviceProvisionedController;
 import com.android.systemui.car.CarServiceProvider;
 import com.android.systemui.car.CarServiceProvider.CarServiceOnConnectedListener;
+import com.android.systemui.car.users.CarSystemUIUserUtil;
 import com.android.systemui.car.window.OverlayPanelViewController;
 import com.android.systemui.car.window.OverlayViewController;
 import com.android.systemui.car.window.OverlayViewGlobalStateController;
@@ -231,7 +231,7 @@ public class NotificationPanelViewController extends OverlayPanelViewController
     }
 
     @Override
-    public void setImeWindowStatus(int displayId, IBinder token, int vis, int backDisposition,
+    public void setImeWindowStatus(int displayId, int vis, int backDisposition,
             boolean showImeSwitcher) {
         if (mContext.getDisplayId() != displayId) {
             return;
@@ -525,6 +525,12 @@ public class NotificationPanelViewController extends OverlayPanelViewController
     @Override
     protected void onPanelVisible(boolean visible) {
         super.onPanelVisible(visible);
+        if (CarSystemUIUserUtil.isSecondaryMUMDSystemUI()) {
+            // TODO: b/341604160 - Supports visible background users properly.
+            Log.d(TAG, "Status bar manager is disabled for visible background users");
+            return;
+        }
+
         mUiBgExecutor.execute(() -> {
             try {
                 if (visible) {
@@ -565,6 +571,12 @@ public class NotificationPanelViewController extends OverlayPanelViewController
      * Clear Buzz/Beep/Blink.
      */
     private void clearNotificationEffects() {
+        if (CarSystemUIUserUtil.isSecondaryMUMDSystemUI()) {
+            // TODO: b/341604160 - Supports visible background users properly.
+            Log.d(TAG, "Status bar manager is disabled for visible background users");
+            return;
+        }
+
         try {
             mBarService.clearNotificationEffects();
         } catch (RemoteException e) {
diff --git a/src/com/android/systemui/car/notification/NotificationPanelViewMediator.java b/src/com/android/systemui/car/notification/NotificationPanelViewMediator.java
index b5fab268..ff579d65 100644
--- a/src/com/android/systemui/car/notification/NotificationPanelViewMediator.java
+++ b/src/com/android/systemui/car/notification/NotificationPanelViewMediator.java
@@ -16,7 +16,11 @@
 
 package com.android.systemui.car.notification;
 
-import android.app.UiModeManager;
+import static com.android.systemui.car.systembar.CarSystemBarController.BOTTOM;
+import static com.android.systemui.car.systembar.CarSystemBarController.LEFT;
+import static com.android.systemui.car.systembar.CarSystemBarController.RIGHT;
+import static com.android.systemui.car.systembar.CarSystemBarController.TOP;
+
 import android.car.hardware.power.CarPowerManager;
 import android.content.BroadcastReceiver;
 import android.content.Context;
@@ -57,7 +61,6 @@ public class NotificationPanelViewMediator implements OverlayViewMediator,
     private final UserTracker mUserTracker;
     private final CarDeviceProvisionedController mCarDeviceProvisionedController;
     private final ConfigurationController mConfigurationController;
-    private final UiModeManager mUiModeManager;
 
     private final BroadcastReceiver mBroadcastReceiver = new BroadcastReceiver() {
         @Override
@@ -98,8 +101,7 @@ public class NotificationPanelViewMediator implements OverlayViewMediator,
             BroadcastDispatcher broadcastDispatcher,
             UserTracker userTracker,
             CarDeviceProvisionedController carDeviceProvisionedController,
-            ConfigurationController configurationController,
-            UiModeManager uiModeManager
+            ConfigurationController configurationController
     ) {
         mContext = context;
         mCarSystemBarController = carSystemBarController;
@@ -109,7 +111,6 @@ public class NotificationPanelViewMediator implements OverlayViewMediator,
         mUserTracker = userTracker;
         mCarDeviceProvisionedController = carDeviceProvisionedController;
         mConfigurationController = configurationController;
-        mUiModeManager = uiModeManager;
     }
 
     @Override
@@ -121,7 +122,7 @@ public class NotificationPanelViewMediator implements OverlayViewMediator,
         registerRightBarTouchListener();
 
         mCarSystemBarController.registerNotificationController(
-                new CarSystemBarController.NotificationsShadeController() {
+                new NotificationsShadeController() {
                     @Override
                     public void togglePanel() {
                         mNotificationPanelViewController.toggle();
@@ -166,7 +167,6 @@ public class NotificationPanelViewMediator implements OverlayViewMediator,
         // Only refresh UI on Night mode changes
         if (isConfigNightMode != mIsUiModeNight) {
             mIsUiModeNight = isConfigNightMode;
-            mUiModeManager.setNightModeActivated(mIsUiModeNight);
             mNotificationPanelViewController.reinflate();
             registerListeners();
         }
@@ -194,22 +194,22 @@ public class NotificationPanelViewMediator implements OverlayViewMediator,
     }
 
     protected void registerTopBarTouchListener() {
-        mCarSystemBarController.registerTopBarTouchListener(
+        mCarSystemBarController.registerBarTouchListener(TOP,
                 mNotificationPanelViewController.getDragCloseTouchListener());
     }
 
     protected void registerBottomBarTouchListener() {
-        mCarSystemBarController.registerBottomBarTouchListener(
+        mCarSystemBarController.registerBarTouchListener(BOTTOM,
                 mNotificationPanelViewController.getDragCloseTouchListener());
     }
 
     protected void registerLeftBarTouchListener() {
-        mCarSystemBarController.registerLeftBarTouchListener(
+        mCarSystemBarController.registerBarTouchListener(LEFT,
                 mNotificationPanelViewController.getDragCloseTouchListener());
     }
 
     protected void registerRightBarTouchListener() {
-        mCarSystemBarController.registerRightBarTouchListener(
+        mCarSystemBarController.registerBarTouchListener(RIGHT,
                 mNotificationPanelViewController.getDragCloseTouchListener());
     }
 
diff --git a/src/com/android/systemui/car/notification/NotificationVisibilityLogger.java b/src/com/android/systemui/car/notification/NotificationVisibilityLogger.java
index 3846af86..d5ad1f33 100644
--- a/src/com/android/systemui/car/notification/NotificationVisibilityLogger.java
+++ b/src/com/android/systemui/car/notification/NotificationVisibilityLogger.java
@@ -24,6 +24,7 @@ import com.android.car.notification.AlertEntry;
 import com.android.car.notification.NotificationDataManager;
 import com.android.internal.statusbar.IStatusBarService;
 import com.android.internal.statusbar.NotificationVisibility;
+import com.android.systemui.car.users.CarSystemUIUserUtil;
 import com.android.systemui.dagger.SysUISingleton;
 import com.android.systemui.dagger.qualifiers.UiBackground;
 
@@ -117,6 +118,12 @@ public class NotificationVisibilityLogger {
             return;
         }
 
+        if (CarSystemUIUserUtil.isSecondaryMUMDSystemUI()) {
+            // TODO: b/341604160 - Supports visible background users properly.
+            Log.d(TAG, "Status bar manager is disabled for visible background users");
+            return;
+        }
+
         try {
             mBarService.onNotificationVisibilityChanged(
                     cloneVisibilitiesAsArr(newlyVisible), cloneVisibilitiesAsArr(noLongerVisible));
diff --git a/src/com/android/systemui/car/notification/NotificationsShadeController.java b/src/com/android/systemui/car/notification/NotificationsShadeController.java
new file mode 100644
index 00000000..8ed74887
--- /dev/null
+++ b/src/com/android/systemui/car/notification/NotificationsShadeController.java
@@ -0,0 +1,25 @@
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
+package com.android.systemui.car.notification;
+
+/** Interface for controlling the notifications shade. */
+public interface NotificationsShadeController {
+    /** Toggles the visibility of the notifications shade. */
+    void togglePanel();
+
+    /** Returns {@code true} if the panel is open. */
+    boolean isNotificationPanelOpen();
+}
diff --git a/src/com/android/systemui/car/notification/TopNotificationPanelViewMediator.java b/src/com/android/systemui/car/notification/TopNotificationPanelViewMediator.java
index 0284968e..291426bf 100644
--- a/src/com/android/systemui/car/notification/TopNotificationPanelViewMediator.java
+++ b/src/com/android/systemui/car/notification/TopNotificationPanelViewMediator.java
@@ -16,7 +16,8 @@
 
 package com.android.systemui.car.notification;
 
-import android.app.UiModeManager;
+import static com.android.systemui.car.systembar.CarSystemBarController.TOP;
+
 import android.content.Context;
 
 import com.android.systemui.broadcast.BroadcastDispatcher;
@@ -45,8 +46,7 @@ public class TopNotificationPanelViewMediator extends NotificationPanelViewMedia
             BroadcastDispatcher broadcastDispatcher,
             UserTracker userTracker,
             CarDeviceProvisionedController carDeviceProvisionedController,
-            ConfigurationController configurationController,
-            UiModeManager uiModeManager
+            ConfigurationController configurationController
     ) {
         super(context,
                 carSystemBarController,
@@ -55,15 +55,14 @@ public class TopNotificationPanelViewMediator extends NotificationPanelViewMedia
                 broadcastDispatcher,
                 userTracker,
                 carDeviceProvisionedController,
-                configurationController,
-                uiModeManager);
+                configurationController);
         notificationPanelViewController.setOverlayDirection(
                 OverlayPanelViewController.OVERLAY_FROM_TOP_BAR);
     }
 
     @Override
     protected void registerTopBarTouchListener() {
-        getCarSystemBarController().registerTopBarTouchListener(
+        getCarSystemBarController().registerBarTouchListener(TOP,
                 getNotificationPanelViewController().getDragOpenTouchListener());
     }
 }
diff --git a/src/com/android/systemui/car/qc/DataSubscriptionController.java b/src/com/android/systemui/car/qc/DataSubscriptionController.java
index f82cfb46..d0dae30c 100644
--- a/src/com/android/systemui/car/qc/DataSubscriptionController.java
+++ b/src/com/android/systemui/car/qc/DataSubscriptionController.java
@@ -18,6 +18,7 @@ package com.android.systemui.car.qc;
 
 import static android.Manifest.permission.ACCESS_NETWORK_STATE;
 import static android.Manifest.permission.INTERNET;
+import static android.widget.PopupWindow.INPUT_METHOD_NOT_NEEDED;
 
 import android.annotation.Nullable;
 import android.annotation.SuppressLint;
@@ -132,6 +133,7 @@ public class DataSubscriptionController implements DataSubscription.DataSubscrip
 
                 ApplicationInfo appInfo = mContext.getPackageManager().getApplicationInfoAsUser(
                         mTopPackage, 0, mUserTracker.getUserId());
+                mTopLabel = appInfo.loadLabel(mContext.getPackageManager());
                 int uid = appInfo.uid;
                 mConnectivityManager.registerDefaultNetworkCallbackForUid(uid, mNetworkCallback,
                         mMainHandler);
@@ -199,6 +201,7 @@ public class DataSubscriptionController implements DataSubscription.DataSubscrip
     private boolean mShouldDisplayReactiveMsg;
     private String mTopActivity;
     private String mTopPackage;
+    private CharSequence mTopLabel;
     private NetworkCapabilities mNetworkCapabilities;
     private boolean mIsUxRestrictionsListenerRegistered;
 
@@ -227,6 +230,7 @@ public class DataSubscriptionController implements DataSubscription.DataSubscrip
         mPopupWindow = new PopupWindow(mPopupView, width, height, focusable);
         mPopupWindow.setTouchModal(false);
         mPopupWindow.setOutsideTouchable(true);
+        mPopupWindow.setInputMethodMode(INPUT_METHOD_NOT_NEEDED);
         mPopupView.setOnTouchListener(new View.OnTouchListener() {
             @Override
             public boolean onTouch(View v, MotionEvent event) {
@@ -316,14 +320,14 @@ public class DataSubscriptionController implements DataSubscription.DataSubscrip
                         if (mIsProactiveMsg) {
                             popUpPrompt.setText(R.string.data_subscription_proactive_msg_prompt);
                         } else {
-                            popUpPrompt.setText(R.string.data_subscription_reactive_msg_prompt);
+                            popUpPrompt.setText(getReactiveMsg());
                         }
                     }
                     int xOffsetInPx = mContext.getResources().getDimensionPixelSize(
-                            R.dimen.car_quick_controls_entry_points_button_width);
+                            R.dimen.data_subscription_pop_up_horizontal_offset);
                     int yOffsetInPx = mContext.getResources().getDimensionPixelSize(
-                            R.dimen.car_quick_controls_panel_margin);
-                    mPopupWindow.showAsDropDown(mAnchorView, -xOffsetInPx / 2, yOffsetInPx);
+                            R.dimen.data_subscription_pop_up_vertical_offset);
+                    mPopupWindow.showAsDropDown(mAnchorView, -xOffsetInPx, yOffsetInPx);
                     mAnchorView.getHandler().postDelayed(new Runnable() {
 
                         public void run() {
@@ -370,6 +374,15 @@ public class DataSubscriptionController implements DataSubscription.DataSubscrip
                 NetworkCapabilities.NET_CAPABILITY_NOT_SUSPENDED);
     }
 
+    private CharSequence getReactiveMsg() {
+        return mContext.getString(
+                R.string.data_subscription_reactive_msg_prompt, mTopLabel.isEmpty()
+                ? mContext.getResources().getString(
+                        R.string.data_subscription_reactive_generic_app_label) :
+                        mTopLabel);
+
+    }
+
     @Override
     public void onChange(int value) {
         updateShouldDisplayProactiveMsg();
diff --git a/src/com/android/systemui/car/qc/ProfileSwitcher.java b/src/com/android/systemui/car/qc/ProfileSwitcher.java
index b23eed6b..c1920424 100644
--- a/src/com/android/systemui/car/qc/ProfileSwitcher.java
+++ b/src/com/android/systemui/car/qc/ProfileSwitcher.java
@@ -220,9 +220,11 @@ public class ProfileSwitcher extends BaseLocalQCProvider {
             }
             switchUser(userInfo.id);
         };
+        boolean isCurrentProfile = userInfo.id == mUserTracker.getUserId();
 
         return createProfileRow(userInfo.name,
-                mUserIconProvider.getDrawableWithBadge(mContext, userInfo), actionHandler);
+                mUserIconProvider.getDrawableWithBadge(mContext, userInfo), actionHandler,
+                isCurrentProfile);
     }
 
     protected QCRow createGuestProfileRow() {
@@ -235,10 +237,12 @@ public class ProfileSwitcher extends BaseLocalQCProvider {
                 switchUser(guest.id);
             }
         };
+        boolean isCurrentProfile = mUserTracker.getUserInfo() != null
+                && mUserTracker.getUserInfo().isGuest();
 
         return createProfileRow(mContext.getString(com.android.internal.R.string.guest_name),
                 mUserIconProvider.getRoundedGuestDefaultIcon(mContext),
-                actionHandler);
+                actionHandler, isCurrentProfile);
     }
 
     private QCRow createAddProfileRow() {
@@ -269,12 +273,20 @@ public class ProfileSwitcher extends BaseLocalQCProvider {
 
     private QCRow createProfileRow(String title, Drawable iconDrawable,
             QCItem.ActionHandler actionHandler) {
+        return createProfileRow(title, iconDrawable, actionHandler, /* isCurrentProfile= */ false);
+    }
+
+    private QCRow createProfileRow(String title, Drawable iconDrawable,
+            QCItem.ActionHandler actionHandler, boolean isCurrentProfile) {
         Icon icon = Icon.createWithBitmap(drawableToBitmap(iconDrawable));
-        QCRow row = new QCRow.Builder()
+        QCRow.Builder rowBuilder = new QCRow.Builder()
                 .setIcon(icon)
                 .setIconTintable(false)
-                .setTitle(title)
-                .build();
+                .setTitle(title);
+        if (isCurrentProfile) {
+            rowBuilder.setSubtitle(mContext.getString(R.string.current_profile_subtitle));
+        }
+        QCRow row = rowBuilder.build();
         row.setActionHandler(actionHandler);
         return row;
     }
diff --git a/src/com/android/systemui/car/qc/QCUserPickerButtonController.java b/src/com/android/systemui/car/qc/QCUserPickerButtonController.java
index 769d5c3c..c7c18753 100644
--- a/src/com/android/systemui/car/qc/QCUserPickerButtonController.java
+++ b/src/com/android/systemui/car/qc/QCUserPickerButtonController.java
@@ -19,20 +19,11 @@ package com.android.systemui.car.qc;
 import android.car.app.CarActivityManager;
 import android.content.Context;
 import android.content.Intent;
-import android.graphics.drawable.Drawable;
-import android.os.UserManager;
-import android.widget.ImageView;
 
-import androidx.annotation.VisibleForTesting;
-
-import com.android.systemui.R;
-import com.android.systemui.broadcast.BroadcastDispatcher;
 import com.android.systemui.car.CarServiceProvider;
-import com.android.systemui.car.statusbar.UserNameViewController;
 import com.android.systemui.car.systembar.element.CarSystemBarElementController;
 import com.android.systemui.car.systembar.element.CarSystemBarElementStateController;
 import com.android.systemui.car.systembar.element.CarSystemBarElementStatusBarDisableController;
-import com.android.systemui.car.userswitcher.UserIconProvider;
 import com.android.systemui.settings.UserTracker;
 
 import dagger.assisted.Assisted;
@@ -43,16 +34,11 @@ import dagger.assisted.AssistedInject;
  * One of {@link QCFooterView} for quick control panels, which shows user information
  * and opens the user picker.
  */
-
 public class QCUserPickerButtonController extends QCFooterViewController {
     private final Context mContext;
     private final UserTracker mUserTracker;
     private final CarServiceProvider mCarServiceProvider;
-    private final BroadcastDispatcher mBroadcastDispatcher;
-    private final UserManager mUserManager;
     private CarActivityManager mCarActivityManager;
-    @VisibleForTesting
-    UserNameViewController mUserNameViewController;
 
     private final CarServiceProvider.CarServiceOnConnectedListener mCarServiceLifecycleListener =
             car -> {
@@ -63,14 +49,11 @@ public class QCUserPickerButtonController extends QCFooterViewController {
     protected QCUserPickerButtonController(@Assisted QCFooterView view,
             CarSystemBarElementStatusBarDisableController disableController,
             CarSystemBarElementStateController stateController, Context context,
-            UserTracker userTracker, CarServiceProvider carServiceProvider,
-            BroadcastDispatcher broadcastDispatcher) {
+            UserTracker userTracker, CarServiceProvider carServiceProvider) {
         super(view, disableController, stateController, context, userTracker);
         mContext = context;
         mUserTracker = userTracker;
         mCarServiceProvider = carServiceProvider;
-        mBroadcastDispatcher = broadcastDispatcher;
-        mUserManager = mContext.getSystemService(UserManager.class);
     }
 
     @AssistedFactory
@@ -81,24 +64,12 @@ public class QCUserPickerButtonController extends QCFooterViewController {
     protected void onInit() {
         super.onInit();
         mView.setOnClickListener(v -> openUserPicker());
-
-        ImageView userIconView = mView.findViewById(R.id.user_icon);
-        if (userIconView != null) {
-            // Set user icon as the first letter of the username.
-            UserIconProvider userIconProvider = new UserIconProvider();
-            Drawable circleIcon = userIconProvider.getRoundedUserIcon(
-                    mUserTracker.getUserInfo(), mContext);
-            userIconView.setImageDrawable(circleIcon);
-        }
     }
 
     @Override
     protected void onViewAttached() {
         super.onViewAttached();
         mCarServiceProvider.addListener(mCarServiceLifecycleListener);
-        mUserNameViewController = new UserNameViewController(
-                mContext, mUserTracker, mUserManager, mBroadcastDispatcher);
-        mUserNameViewController.addUserNameView(mView);
 
     }
 
@@ -106,10 +77,6 @@ public class QCUserPickerButtonController extends QCFooterViewController {
     protected void onViewDetached() {
         super.onViewDetached();
         mCarServiceProvider.removeListener(mCarServiceLifecycleListener);
-        if (mUserNameViewController != null) {
-            mUserNameViewController.removeUserNameView(mView);
-            mUserNameViewController = null;
-        }
     }
 
     private void openUserPicker() {
diff --git a/src/com/android/systemui/car/statusbar/DozeServiceHost.java b/src/com/android/systemui/car/statusbar/DozeServiceHost.java
index d477fe51..bb94d520 100644
--- a/src/com/android/systemui/car/statusbar/DozeServiceHost.java
+++ b/src/com/android/systemui/car/statusbar/DozeServiceHost.java
@@ -104,6 +104,11 @@ public class DozeServiceHost implements DozeHost {
         // No op.
     }
 
+    @Override
+    public void setDozeScreenBrightnessFloat(float value) {
+        // No op.
+    }
+
     @Override
     public void prepareForGentleSleep(Runnable onDisplayOffCallback) {
         // No op.
diff --git a/src/com/android/systemui/car/statusbar/UserNameViewController.java b/src/com/android/systemui/car/statusbar/UserNameViewController.java
deleted file mode 100644
index fb510490..00000000
--- a/src/com/android/systemui/car/statusbar/UserNameViewController.java
+++ /dev/null
@@ -1,186 +0,0 @@
-/*
- * Copyright (C) 2020 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-package com.android.systemui.car.statusbar;
-
-import android.content.BroadcastReceiver;
-import android.content.Context;
-import android.content.Intent;
-import android.content.IntentFilter;
-import android.content.pm.UserInfo;
-import android.graphics.drawable.Drawable;
-import android.os.UserHandle;
-import android.os.UserManager;
-import android.view.View;
-import android.widget.ImageView;
-import android.widget.TextView;
-
-import androidx.annotation.MainThread;
-import androidx.annotation.VisibleForTesting;
-
-import com.android.systemui.R;
-import com.android.systemui.broadcast.BroadcastDispatcher;
-import com.android.systemui.car.userswitcher.UserIconProvider;
-import com.android.systemui.dagger.SysUISingleton;
-import com.android.systemui.settings.UserTracker;
-
-import java.util.ArrayList;
-
-import javax.inject.Inject;
-
-/**
- * Controls TextView and ImageView for the current logged in user.
- * User icon image consists of the first letter of user name.
- * Therefore, the user name and icon have to be changed at the same time.
- */
-@SysUISingleton
-public class UserNameViewController {
-    private static final String TAG = "UserNameViewController";
-
-    private Context mContext;
-    private UserTracker mUserTracker;
-    private UserManager mUserManager;
-    private BroadcastDispatcher mBroadcastDispatcher;
-    private String mLastUserName;
-
-    @VisibleForTesting
-    UserIconProvider mUserIconProvider;
-
-    @VisibleForTesting
-    ArrayList<TextView> mUserNameViews = new ArrayList<TextView>();
-    @VisibleForTesting
-    ArrayList<ImageView> mUserIconViews = new ArrayList<ImageView>();
-
-    private final BroadcastReceiver mUserUpdateReceiver = new BroadcastReceiver() {
-        @Override
-        public void onReceive(Context context, Intent intent) {
-            updateUser(mUserTracker.getUserId());
-        }
-    };
-
-    private boolean mUserLifecycleListenerRegistered = false;
-
-    private final UserTracker.Callback mUserChangedCallback =
-            new UserTracker.Callback() {
-                @Override
-                public void onUserChanged(int newUser, Context userContext) {
-                    updateUser(newUser);
-                }
-            };
-
-    @Inject
-    public UserNameViewController(Context context, UserTracker userTracker,
-            UserManager userManager, BroadcastDispatcher broadcastDispatcher) {
-        mContext = context;
-        mUserTracker = userTracker;
-        mUserManager = userManager;
-        mBroadcastDispatcher = broadcastDispatcher;
-        mUserIconProvider = new UserIconProvider();
-    }
-
-    /**
-     * Find the {@link ImageView} or {@link TextView} for the user from a view
-     * and if found set them with the current user name and icon.
-     */
-     @MainThread
-    public void addUserNameView(View v) {
-        TextView userNameView = v.findViewById(R.id.user_name_text);
-        if (userNameView != null) {
-            ImageView userIconView = v.findViewById(R.id.user_icon);
-
-            if (mUserNameViews.size() == 0
-                    || (userIconView != null && mUserIconViews.size() == 0)) {
-                registerForUserChangeEvents();
-            }
-
-            if (!mUserNameViews.contains(userNameView)) {
-                mUserNameViews.add(userNameView);
-            }
-
-            if (userIconView != null && !mUserIconViews.contains(userIconView)) {
-                mUserIconViews.add(userIconView);
-            }
-
-            updateUser(mUserTracker.getUserId());
-        }
-    }
-
-    /**
-     * Find the {@link ImageView} or {@link TextView} for the user from a view and if found remove
-     * them from the user views list.
-     */
-    public void removeUserNameView(View v) {
-        TextView userNameView = v.findViewById(R.id.user_name_text);
-        if (userNameView != null && mUserNameViews.contains(userNameView)) {
-            mUserNameViews.remove(userNameView);
-        }
-
-        ImageView userIconView = v.findViewById(R.id.user_icon);
-        if (userIconView != null && mUserIconViews.contains(userIconView)) {
-            mUserIconViews.remove(userIconView);
-        }
-    }
-
-    /**
-     * Clean up the controller and unregister receiver.
-     */
-    public void removeAll() {
-        mUserNameViews.clear();
-        mUserIconViews.clear();
-        if (mUserLifecycleListenerRegistered) {
-            mBroadcastDispatcher.unregisterReceiver(mUserUpdateReceiver);
-            mUserTracker.removeCallback(mUserChangedCallback);
-            mUserLifecycleListenerRegistered = false;
-        }
-    }
-
-    private void registerForUserChangeEvents() {
-        // Register for user switching
-        if (!mUserLifecycleListenerRegistered) {
-            mUserTracker.addCallback(mUserChangedCallback, mContext.getMainExecutor());
-            mUserLifecycleListenerRegistered = true;
-        }
-        // Also register for user info changing
-        IntentFilter filter = new IntentFilter();
-        filter.addAction(Intent.ACTION_USER_INFO_CHANGED);
-        mBroadcastDispatcher.registerReceiver(mUserUpdateReceiver, filter, /* executor= */ null,
-                UserHandle.ALL);
-    }
-
-    private void updateUser(int userId) {
-        UserInfo currentUserInfo = mUserManager.getUserInfo(userId);
-
-        // Update user name
-        for (int i = 0; i < mUserNameViews.size(); i++) {
-            mUserNameViews.get(i).setText(currentUserInfo.name);
-        }
-
-        // Update user icon with the first letter of the user name
-        if (mLastUserName == null || !mLastUserName.equals(currentUserInfo.name)) {
-            mLastUserName = currentUserInfo.name;
-            mUserIconProvider.setRoundedUserIcon(currentUserInfo, mContext);
-        }
-
-        for (int i = 0; i < mUserIconViews.size(); i++) {
-            updateUserIcon(mUserIconViews.get(i), currentUserInfo);
-        }
-    }
-
-    private void updateUserIcon(ImageView userIconView, UserInfo currentUserInfo) {
-        Drawable circleIcon = mUserIconProvider.getRoundedUserIcon(currentUserInfo, mContext);
-        userIconView.setImageDrawable(circleIcon);
-    }
-}
diff --git a/src/com/android/systemui/car/statusicon/StatusIconPanelViewController.java b/src/com/android/systemui/car/statusicon/StatusIconPanelViewController.java
index e828a4b0..543bb4e7 100644
--- a/src/com/android/systemui/car/statusicon/StatusIconPanelViewController.java
+++ b/src/com/android/systemui/car/statusicon/StatusIconPanelViewController.java
@@ -18,11 +18,11 @@ package com.android.systemui.car.statusicon;
 
 import static android.view.WindowManager.LayoutParams.TYPE_SYSTEM_DIALOG;
 import static android.widget.ListPopupWindow.WRAP_CONTENT;
+import static android.widget.PopupWindow.INPUT_METHOD_NOT_NEEDED;
 
 import android.annotation.DimenRes;
 import android.annotation.LayoutRes;
 import android.app.PendingIntent;
-import android.car.app.CarActivityManager;
 import android.car.drivingstate.CarUxRestrictions;
 import android.content.BroadcastReceiver;
 import android.content.Context;
@@ -50,11 +50,9 @@ import com.android.car.ui.utils.CarUxRestrictionsUtil;
 import com.android.systemui.R;
 import com.android.systemui.broadcast.BroadcastDispatcher;
 import com.android.systemui.car.CarDeviceProvisionedController;
-import com.android.systemui.car.CarServiceProvider;
 import com.android.systemui.car.qc.SystemUIQCViewController;
 import com.android.systemui.car.systembar.element.CarSystemBarElementController;
 import com.android.systemui.car.systembar.element.CarSystemBarElementInitializer;
-import com.android.systemui.car.users.CarSystemUIUserUtil;
 import com.android.systemui.settings.UserTracker;
 import com.android.systemui.statusbar.policy.ConfigurationController;
 import com.android.systemui.util.ViewController;
@@ -70,7 +68,6 @@ import javax.inject.Inject;
 public class StatusIconPanelViewController extends ViewController<View> {
     private final Context mContext;
     private final UserTracker mUserTracker;
-    private final CarServiceProvider mCarServiceProvider;
     private final BroadcastDispatcher mBroadcastDispatcher;
     private final ConfigurationController mConfigurationController;
     private final CarDeviceProvisionedController mCarDeviceProvisionedController;
@@ -91,7 +88,6 @@ public class StatusIconPanelViewController extends ViewController<View> {
     private PopupWindow mPanel;
     private ViewGroup mPanelContent;
     private CarUxRestrictionsUtil mCarUxRestrictionsUtil;
-    private CarActivityManager mCarActivityManager;
     private float mDimValue = -1.0f;
     private View.OnClickListener mOnClickListener;
 
@@ -127,11 +123,6 @@ public class StatusIconPanelViewController extends ViewController<View> {
                 }
             };
 
-    private final CarServiceProvider.CarServiceOnConnectedListener mCarServiceOnConnectedListener =
-            car -> {
-                mCarActivityManager = car.getCarManager(CarActivityManager.class);
-            };
-
     private final BroadcastReceiver mBroadcastReceiver = new BroadcastReceiver() {
         @Override
         public void onReceive(Context context, Intent intent) {
@@ -183,7 +174,6 @@ public class StatusIconPanelViewController extends ViewController<View> {
 
     private StatusIconPanelViewController(Context context,
             UserTracker userTracker,
-            CarServiceProvider carServiceProvider,
             BroadcastDispatcher broadcastDispatcher,
             ConfigurationController configurationController,
             CarDeviceProvisionedController deviceProvisionedController,
@@ -194,7 +184,6 @@ public class StatusIconPanelViewController extends ViewController<View> {
         super(anchorView);
         mContext = context;
         mUserTracker = userTracker;
-        mCarServiceProvider = carServiceProvider;
         mBroadcastDispatcher = broadcastDispatcher;
         mConfigurationController = configurationController;
         mCarDeviceProvisionedController = deviceProvisionedController;
@@ -238,28 +227,20 @@ public class StatusIconPanelViewController extends ViewController<View> {
 
             registerFocusListener(true);
 
-            if (CarSystemUIUserUtil.isMUMDSystemUI()
-                    && mPanelLayoutRes == R.layout.qc_profile_switcher) {
-                // TODO(b/269490856): consider removal of UserPicker carve-outs
-                if (mCarActivityManager != null) {
-                    mCarActivityManager.startUserPickerOnDisplay(mContext.getDisplayId());
-                }
+            if (mShowAsDropDown) {
+                // TODO(b/202563671): remove yOffsetPixel when the PopupWindow API is updated.
+                mPanel.showAsDropDown(mView, mXOffsetPixel, mYOffsetPixel, mPanelGravity);
             } else {
-                if (mShowAsDropDown) {
-                    // TODO(b/202563671): remove yOffsetPixel when the PopupWindow API is updated.
-                    mPanel.showAsDropDown(mView, mXOffsetPixel, mYOffsetPixel, mPanelGravity);
-                } else {
-                    int verticalGravity = mPanelGravity & Gravity.VERTICAL_GRAVITY_MASK;
-                    int animationStyle = verticalGravity == Gravity.BOTTOM
-                            ? com.android.internal.R.style.Animation_DropDownUp
-                            : com.android.internal.R.style.Animation_DropDownDown;
-                    mPanel.setAnimationStyle(animationStyle);
-                    mPanel.showAtLocation(mView, mPanelGravity, mXOffsetPixel, mYOffsetPixel);
-                }
-                mView.setSelected(true);
-                setAnimatedStatusIconHighlightedStatus(true);
-                dimBehind(mPanel);
+                int verticalGravity = mPanelGravity & Gravity.VERTICAL_GRAVITY_MASK;
+                int animationStyle = verticalGravity == Gravity.BOTTOM
+                        ? com.android.internal.R.style.Animation_DropDownUp
+                        : com.android.internal.R.style.Animation_DropDownDown;
+                mPanel.setAnimationStyle(animationStyle);
+                mPanel.showAtLocation(mView, mPanelGravity, mXOffsetPixel, mYOffsetPixel);
             }
+            mView.setSelected(true);
+            setAnimatedStatusIconHighlightedStatus(true);
+            dimBehind(mPanel);
         };
 
         mView.setOnClickListener(mOnClickListener);
@@ -280,7 +261,6 @@ public class StatusIconPanelViewController extends ViewController<View> {
             mCarUxRestrictionsUtil = CarUxRestrictionsUtil.getInstance(mContext);
             mCarUxRestrictionsUtil.register(mUxRestrictionsChangedListener);
         }
-        mCarServiceProvider.addListener(mCarServiceOnConnectedListener);
     }
 
     @Override
@@ -289,7 +269,6 @@ public class StatusIconPanelViewController extends ViewController<View> {
         if (mCarUxRestrictionsUtil != null) {
             mCarUxRestrictionsUtil.unregister(mUxRestrictionsChangedListener);
         }
-        mCarServiceProvider.removeListener(mCarServiceOnConnectedListener);
         mConfigurationController.removeCallback(mConfigurationListener);
         mUserTracker.removeCallback(mUserTrackerCallback);
         mBroadcastDispatcher.unregisterReceiver(mBroadcastReceiver);
@@ -362,6 +341,7 @@ public class StatusIconPanelViewController extends ViewController<View> {
         mPanel.setBackgroundDrawable(panelBackgroundDrawable);
         mPanel.setWindowLayoutType(TYPE_SYSTEM_DIALOG);
         mPanel.setFocusable(true);
+        mPanel.setInputMethodMode(INPUT_METHOD_NOT_NEEDED);
         mPanel.setOutsideTouchable(false);
         mPanel.setOnDismissListener(() -> {
             setAnimatedStatusIconHighlightedStatus(false);
@@ -487,7 +467,6 @@ public class StatusIconPanelViewController extends ViewController<View> {
     public static class Builder {
         private final Context mContext;
         private final UserTracker mUserTracker;
-        private final CarServiceProvider mCarServiceProvider;
         private final BroadcastDispatcher mBroadcastDispatcher;
         private final ConfigurationController mConfigurationController;
         private final CarDeviceProvisionedController mCarDeviceProvisionedController;
@@ -504,14 +483,12 @@ public class StatusIconPanelViewController extends ViewController<View> {
         public Builder(
                 Context context,
                 UserTracker userTracker,
-                CarServiceProvider carServiceProvider,
                 BroadcastDispatcher broadcastDispatcher,
                 ConfigurationController configurationController,
                 CarDeviceProvisionedController deviceProvisionedController,
                 CarSystemBarElementInitializer elementInitializer) {
             mContext = context;
             mUserTracker = userTracker;
-            mCarServiceProvider = carServiceProvider;
             mBroadcastDispatcher = broadcastDispatcher;
             mConfigurationController = configurationController;
             mCarDeviceProvisionedController = deviceProvisionedController;
@@ -573,8 +550,8 @@ public class StatusIconPanelViewController extends ViewController<View> {
          */
         public StatusIconPanelViewController build(View anchorView, @LayoutRes int layoutRes,
                 @DimenRes int widthRes) {
-            return new StatusIconPanelViewController(mContext, mUserTracker, mCarServiceProvider,
-                    mBroadcastDispatcher, mConfigurationController, mCarDeviceProvisionedController,
+            return new StatusIconPanelViewController(mContext, mUserTracker, mBroadcastDispatcher,
+                    mConfigurationController, mCarDeviceProvisionedController,
                     mCarSystemBarElementInitializer, anchorView, layoutRes, widthRes, mXOffset,
                     mYOffset, mGravity, mIsDisabledWhileDriving, mIsDisabledWhileUnprovisioned,
                     mShowAsDropDown);
diff --git a/src/com/android/systemui/car/statusicon/ui/DisplayStatusIconController.java b/src/com/android/systemui/car/statusicon/ui/DisplayStatusIconController.java
deleted file mode 100644
index 84d5f35d..00000000
--- a/src/com/android/systemui/car/statusicon/ui/DisplayStatusIconController.java
+++ /dev/null
@@ -1,67 +0,0 @@
-/*
- * Copyright (C) 2021 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-package com.android.systemui.car.statusicon.ui;
-
-import android.content.Context;
-import android.content.res.Resources;
-import android.graphics.drawable.Drawable;
-
-import com.android.systemui.R;
-import com.android.systemui.car.statusicon.StatusIconView;
-import com.android.systemui.car.statusicon.StatusIconViewController;
-import com.android.systemui.car.systembar.element.CarSystemBarElementStateController;
-import com.android.systemui.car.systembar.element.CarSystemBarElementStatusBarDisableController;
-import com.android.systemui.dagger.qualifiers.Main;
-
-import dagger.assisted.Assisted;
-import dagger.assisted.AssistedFactory;
-import dagger.assisted.AssistedInject;
-
-/**
- * A controller for Display status icon.
- */
-public class DisplayStatusIconController extends StatusIconViewController {
-
-    private final Drawable mDisplayBrightnessDrawable;
-    private final String mDisplayBrightnessContentDescription;
-
-    @AssistedInject
-    DisplayStatusIconController(
-            @Assisted StatusIconView view,
-            CarSystemBarElementStatusBarDisableController disableController,
-            CarSystemBarElementStateController stateController,
-            Context context, @Main Resources resources) {
-        super(view, disableController, stateController);
-        mDisplayBrightnessDrawable = resources.getDrawable(R.drawable.car_ic_brightness,
-                context.getTheme());
-        mDisplayBrightnessContentDescription = resources.getString(
-                R.string.status_icon_display_status);
-        updateStatus();
-    }
-
-    @AssistedFactory
-    public interface Factory extends
-            StatusIconViewController.Factory<DisplayStatusIconController> {
-    }
-
-    @Override
-    protected void updateStatus() {
-        setIconDrawableToDisplay(mDisplayBrightnessDrawable);
-        setIconContentDescription(mDisplayBrightnessContentDescription);
-        onStatusUpdated();
-    }
-}
diff --git a/src/com/android/systemui/car/statusicon/ui/MediaVolumeStatusIconController.java b/src/com/android/systemui/car/statusicon/ui/MediaVolumeStatusIconController.java
index 6263ca14..5b8e40d3 100644
--- a/src/com/android/systemui/car/statusicon/ui/MediaVolumeStatusIconController.java
+++ b/src/com/android/systemui/car/statusicon/ui/MediaVolumeStatusIconController.java
@@ -16,6 +16,7 @@
 
 package com.android.systemui.car.statusicon.ui;
 
+import static android.car.media.CarAudioManager.INVALID_AUDIO_ZONE;
 import static android.car.media.CarAudioManager.PRIMARY_AUDIO_ZONE;
 import static android.media.AudioAttributes.USAGE_MEDIA;
 
@@ -77,8 +78,14 @@ public class MediaVolumeStatusIconController extends StatusIconViewController {
                     if (carOccupantZoneManager != null) {
                         occupantZoneInfo = carOccupantZoneManager.getMyOccupantZone();
                     }
-                    mZoneId =
-                            occupantZoneInfo != null ? occupantZoneInfo.zoneId : PRIMARY_AUDIO_ZONE;
+                    mZoneId = PRIMARY_AUDIO_ZONE;
+                    if (occupantZoneInfo != null) {
+                        int occupantAudioId = carOccupantZoneManager
+                                .getAudioZoneIdForOccupant(occupantZoneInfo);
+                        if (occupantAudioId != INVALID_AUDIO_ZONE) {
+                            mZoneId = occupantAudioId;
+                        }
+                    }
 
                     mCarAudioManager = (CarAudioManager) car.getCarManager(Car.AUDIO_SERVICE);
 
diff --git a/src/com/android/systemui/car/statusicon/ui/QuickControlsEntryPointsModule.java b/src/com/android/systemui/car/statusicon/ui/QuickControlsEntryPointsModule.java
index 26b24033..f99a8906 100644
--- a/src/com/android/systemui/car/statusicon/ui/QuickControlsEntryPointsModule.java
+++ b/src/com/android/systemui/car/statusicon/ui/QuickControlsEntryPointsModule.java
@@ -44,13 +44,6 @@ public abstract class QuickControlsEntryPointsModule {
     public abstract CarSystemBarElementController.Factory bindSignalStatusIconController(
             SignalStatusIconController.Factory signalStatusIconController);
 
-    /** Injects DisplayStatusIconController. */
-    @Binds
-    @IntoMap
-    @ClassKey(DisplayStatusIconController.class)
-    public abstract CarSystemBarElementController.Factory bindDisplayStatusIconController(
-            DisplayStatusIconController.Factory displayStatusIconController);
-
     /** Injects LocationStatusIconController. */
     @Binds
     @IntoMap
diff --git a/src/com/android/systemui/car/systembar/ButtonSelectionStateListener.java b/src/com/android/systemui/car/systembar/ButtonSelectionStateListener.java
index 38522fac..e23a8b54 100644
--- a/src/com/android/systemui/car/systembar/ButtonSelectionStateListener.java
+++ b/src/com/android/systemui/car/systembar/ButtonSelectionStateListener.java
@@ -27,7 +27,7 @@ import com.android.systemui.shared.system.TaskStackChangeListener;
  * task stack and notifies the navigation bar.
  */
 @SysUISingleton
-class ButtonSelectionStateListener implements TaskStackChangeListener {
+public class ButtonSelectionStateListener implements TaskStackChangeListener {
     private static final String TAG = ButtonSelectionStateListener.class.getSimpleName();
 
     /* Visible so that subclasses can make calls to this controller. */
diff --git a/src/com/android/systemui/car/systembar/CarSystemBar.java b/src/com/android/systemui/car/systembar/CarSystemBar.java
index 232369f5..8ceeffe5 100644
--- a/src/com/android/systemui/car/systembar/CarSystemBar.java
+++ b/src/com/android/systemui/car/systembar/CarSystemBar.java
@@ -16,851 +16,23 @@
 
 package com.android.systemui.car.systembar;
 
-import static android.content.Intent.ACTION_OVERLAY_CHANGED;
-import static android.view.WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS;
-
-import static com.android.systemui.car.Flags.configAwareSystemui;
-import static com.android.systemui.car.systembar.SystemBarConfigs.BOTTOM;
-import static com.android.systemui.car.systembar.SystemBarConfigs.LEFT;
-import static com.android.systemui.car.systembar.SystemBarConfigs.RIGHT;
-import static com.android.systemui.car.systembar.SystemBarConfigs.TOP;
-import static com.android.systemui.statusbar.phone.BarTransitions.MODE_SEMI_TRANSPARENT;
-import static com.android.systemui.statusbar.phone.BarTransitions.MODE_TRANSPARENT;
-
-import android.annotation.Nullable;
-import android.app.ActivityManager.RunningTaskInfo;
-import android.app.StatusBarManager.Disable2Flags;
-import android.app.StatusBarManager.DisableFlags;
-import android.app.UiModeManager;
-import android.content.BroadcastReceiver;
-import android.content.Context;
-import android.content.Intent;
-import android.content.IntentFilter;
-import android.content.res.Configuration;
-import android.graphics.Rect;
-import android.inputmethodservice.InputMethodService;
-import android.os.IBinder;
-import android.os.PatternMatcher;
-import android.os.RemoteException;
-import android.os.UserHandle;
-import android.util.Log;
-import android.view.View;
-import android.view.ViewGroup;
-import android.view.WindowInsets;
-import android.view.WindowInsets.Type.InsetsType;
-import android.view.WindowInsetsController;
-import android.view.WindowManager;
-
-import androidx.annotation.VisibleForTesting;
-
-import com.android.internal.statusbar.IStatusBarService;
-import com.android.internal.statusbar.LetterboxDetails;
-import com.android.internal.statusbar.RegisterStatusBarResult;
-import com.android.internal.view.AppearanceRegion;
 import com.android.systemui.CoreStartable;
-import com.android.systemui.R;
-import com.android.systemui.car.CarDeviceProvisionedController;
-import com.android.systemui.car.CarDeviceProvisionedListener;
-import com.android.systemui.car.displaycompat.ToolbarController;
-import com.android.systemui.car.hvac.HvacController;
-import com.android.systemui.car.users.CarSystemUIUserUtil;
 import com.android.systemui.dagger.SysUISingleton;
-import com.android.systemui.dagger.qualifiers.Main;
-import com.android.systemui.dagger.qualifiers.UiBackground;
-import com.android.systemui.plugins.DarkIconDispatcher;
-import com.android.systemui.settings.DisplayTracker;
-import com.android.systemui.shared.system.TaskStackChangeListener;
-import com.android.systemui.shared.system.TaskStackChangeListeners;
-import com.android.systemui.statusbar.AutoHideUiElement;
-import com.android.systemui.statusbar.CommandQueue;
-import com.android.systemui.statusbar.phone.AutoHideController;
-import com.android.systemui.statusbar.phone.BarTransitions;
-import com.android.systemui.statusbar.phone.LightBarController;
-import com.android.systemui.statusbar.phone.PhoneStatusBarPolicy;
-import com.android.systemui.statusbar.phone.StatusBarSignalPolicy;
-import com.android.systemui.statusbar.phone.SysuiDarkIconDispatcher;
-import com.android.systemui.statusbar.policy.ConfigurationController;
-import com.android.systemui.statusbar.policy.KeyguardStateController;
-import com.android.systemui.util.concurrency.DelayableExecutor;
-import com.android.systemui.wm.MDSystemBarsController;
-
-import dagger.Lazy;
-
-import java.io.PrintWriter;
-import java.util.ArrayList;
-import java.util.Locale;
-import java.util.Optional;
-import java.util.concurrent.Executor;
 
 import javax.inject.Inject;
 
-/** Navigation bars customized for the automotive use case. */
+/** Corestartable class that is responsible for initializing the system bar controller. */
 @SysUISingleton
-public class CarSystemBar implements CoreStartable, CommandQueue.Callbacks,
-        ConfigurationController.ConfigurationListener,
-        MDSystemBarsController.Listener {
-    private static final String TAG = CarSystemBar.class.getSimpleName();
-    private static final String OVERLAY_FILTER_DATA_SCHEME = "package";
-
-    protected static final boolean DEBUG = Log.isLoggable(TAG, Log.DEBUG);
-
-    private final Context mContext;
+public class CarSystemBar implements CoreStartable {
     private final CarSystemBarController mCarSystemBarController;
-    private final SysuiDarkIconDispatcher mStatusBarIconController;
-    private final WindowManager mWindowManager;
-    private final CarDeviceProvisionedController mCarDeviceProvisionedController;
-    private final CommandQueue mCommandQueue;
-    private final AutoHideController mAutoHideController;
-    private final ButtonSelectionStateListener mButtonSelectionStateListener;
-    private final DelayableExecutor mExecutor;
-    private final Executor mUiBgExecutor;
-    private final IStatusBarService mBarService;
-    private final DisplayTracker mDisplayTracker;
-    private final Lazy<KeyguardStateController> mKeyguardStateControllerLazy;
-    private final Lazy<PhoneStatusBarPolicy> mIconPolicyLazy;
-    private final HvacController mHvacController;
-    private final ConfigurationController mConfigurationController;
-    private final CarSystemBarRestartTracker mCarSystemBarRestartTracker;
-    private final int mDisplayId;
-    private final SystemBarConfigs mSystemBarConfigs;
-    @Nullable
-    private final ToolbarController mDisplayCompatToolbarController;
-    private UiModeManager mUiModeManager;
-    private StatusBarSignalPolicy mSignalPolicy;
-
-    // If the nav bar should be hidden when the soft keyboard is visible.
-    private boolean mHideTopBarForKeyboard;
-    private boolean mHideLeftBarForKeyboard;
-    private boolean mHideRightBarForKeyboard;
-    private boolean mHideBottomBarForKeyboard;
-    // Nav bar views.
-    private ViewGroup mTopSystemBarWindow;
-    private ViewGroup mBottomSystemBarWindow;
-    private ViewGroup mLeftSystemBarWindow;
-    private ViewGroup mRightSystemBarWindow;
-    private CarSystemBarView mTopSystemBarView;
-    private CarSystemBarView mBottomSystemBarView;
-    private CarSystemBarView mLeftSystemBarView;
-    private CarSystemBarView mRightSystemBarView;
-    private boolean mTopSystemBarAttached;
-    private boolean mBottomSystemBarAttached;
-    private boolean mLeftSystemBarAttached;
-    private boolean mRightSystemBarAttached;
-
-    // To be attached to the navigation bars such that they can close the notification panel if
-    // it's open.
-    private boolean mDeviceIsSetUpForUser = true;
-    private boolean mIsUserSetupInProgress = false;
-
-    private AppearanceRegion[] mAppearanceRegions = new AppearanceRegion[0];
-    @BarTransitions.TransitionMode
-    private int mStatusBarMode;
-    @BarTransitions.TransitionMode
-    private int mSystemBarMode;
-    private boolean mStatusBarTransientShown;
-    private boolean mNavBarTransientShown;
-
-    private boolean mIsUiModeNight = false;
-    private MDSystemBarsController mMDSystemBarsController;
-
-    private Locale mCurrentLocale;
 
     @Inject
-    public CarSystemBar(Context context,
-            CarSystemBarController carSystemBarController,
-            // TODO(b/156052638): Should not need to inject LightBarController
-            LightBarController lightBarController,
-            DarkIconDispatcher darkIconDispatcher,
-            WindowManager windowManager,
-            CarDeviceProvisionedController deviceProvisionedController,
-            CommandQueue commandQueue,
-            AutoHideController autoHideController,
-            ButtonSelectionStateListener buttonSelectionStateListener,
-            @Main DelayableExecutor mainExecutor,
-            @UiBackground Executor uiBgExecutor,
-            IStatusBarService barService,
-            Lazy<KeyguardStateController> keyguardStateControllerLazy,
-            Lazy<PhoneStatusBarPolicy> iconPolicyLazy,
-            HvacController hvacController,
-            StatusBarSignalPolicy signalPolicy,
-            SystemBarConfigs systemBarConfigs,
-            ConfigurationController configurationController,
-            CarSystemBarRestartTracker restartTracker,
-            DisplayTracker displayTracker,
-            Optional<MDSystemBarsController> mdSystemBarsController,
-            @Nullable ToolbarController toolbarController
-    ) {
-        mContext = context;
+    public CarSystemBar(CarSystemBarController carSystemBarController) {
         mCarSystemBarController = carSystemBarController;
-        mStatusBarIconController = (SysuiDarkIconDispatcher) darkIconDispatcher;
-        mWindowManager = windowManager;
-        mCarDeviceProvisionedController = deviceProvisionedController;
-        mCommandQueue = commandQueue;
-        mAutoHideController = autoHideController;
-        mButtonSelectionStateListener = buttonSelectionStateListener;
-        mExecutor = mainExecutor;
-        mUiBgExecutor = uiBgExecutor;
-        mBarService = barService;
-        mKeyguardStateControllerLazy = keyguardStateControllerLazy;
-        mIconPolicyLazy = iconPolicyLazy;
-        mHvacController = hvacController;
-        mSystemBarConfigs = systemBarConfigs;
-        mSignalPolicy = signalPolicy;
-        mDisplayId = context.getDisplayId();
-        mUiModeManager = mContext.getSystemService(UiModeManager.class);
-        mDisplayTracker = displayTracker;
-        mIsUiModeNight = mContext.getResources().getConfiguration().isNightModeActive();
-        mMDSystemBarsController = mdSystemBarsController.orElse(null);
-        mCurrentLocale = mContext.getResources().getConfiguration().getLocales().get(0);
-        mConfigurationController = configurationController;
-        mCarSystemBarRestartTracker = restartTracker;
-        mDisplayCompatToolbarController = toolbarController;
-    }
-
-    private void registerOverlayChangeBroadcastReceiver() {
-        if (!configAwareSystemui()) {
-            if (DEBUG) {
-                Log.d(TAG, "Ignore overlay change for car systemui");
-            }
-            return;
-        }
-        IntentFilter overlayFilter = new IntentFilter(ACTION_OVERLAY_CHANGED);
-        overlayFilter.addDataScheme(OVERLAY_FILTER_DATA_SCHEME);
-        overlayFilter.addDataSchemeSpecificPart(mContext.getPackageName(),
-                PatternMatcher.PATTERN_LITERAL);
-        BroadcastReceiver receiver = new BroadcastReceiver() {
-            @Override
-            public void onReceive(Context context, Intent intent) {
-                if (mTopSystemBarAttached || mBottomSystemBarAttached || mLeftSystemBarAttached
-                        || mRightSystemBarAttached) {
-                    restartSystemBars();
-                }
-            }
-        };
-        mContext.registerReceiverAsUser(receiver, UserHandle.ALL,
-                overlayFilter, /* broadcastPermission= */null, /* handler= */ null);
     }
 
     @Override
     public void start() {
-        // Set initial state.
-        mHideTopBarForKeyboard = mSystemBarConfigs.getHideForKeyboardBySide(TOP);
-        mHideBottomBarForKeyboard = mSystemBarConfigs.getHideForKeyboardBySide(BOTTOM);
-        mHideLeftBarForKeyboard = mSystemBarConfigs.getHideForKeyboardBySide(LEFT);
-        mHideRightBarForKeyboard = mSystemBarConfigs.getHideForKeyboardBySide(RIGHT);
-
-        // Connect into the status bar manager service
-        mCommandQueue.addCallback(this);
-
-        RegisterStatusBarResult result = null;
-        //Register only for Primary User.
-        if (!CarSystemUIUserUtil.isSecondaryMUMDSystemUI()) {
-            try {
-                result = mBarService.registerStatusBar(mCommandQueue);
-            } catch (RemoteException ex) {
-                ex.rethrowFromSystemServer();
-            }
-        } else if (mMDSystemBarsController != null) {
-            mMDSystemBarsController.addListener(this);
-        }
-
-        if (result != null) {
-            onSystemBarAttributesChanged(mDisplayId, result.mAppearance, result.mAppearanceRegions,
-                    result.mNavbarColorManagedByIme, result.mBehavior,
-                    result.mRequestedVisibleTypes,
-                    result.mPackageName, result.mLetterboxDetails);
-
-            // StatusBarManagerService has a back up of IME token and it's restored here.
-            setImeWindowStatus(mDisplayId, result.mImeToken, result.mImeWindowVis,
-                    result.mImeBackDisposition, result.mShowImeSwitcher);
-
-            // Set up the initial icon state
-            int numIcons = result.mIcons.size();
-            for (int i = 0; i < numIcons; i++) {
-                mCommandQueue.setIcon(result.mIcons.keyAt(i), result.mIcons.valueAt(i));
-            }
-        }
-
-        mAutoHideController.setStatusBar(new AutoHideUiElement() {
-            @Override
-            public void synchronizeState() {
-                // No op.
-            }
-
-            @Override
-            public boolean isVisible() {
-                return mStatusBarTransientShown;
-            }
-
-            @Override
-            public void hide() {
-                clearTransient();
-            }
-        });
-
-        mAutoHideController.setNavigationBar(new AutoHideUiElement() {
-            @Override
-            public void synchronizeState() {
-                // No op.
-            }
-
-            @Override
-            public boolean isVisible() {
-                return mNavBarTransientShown;
-            }
-
-            @Override
-            public void hide() {
-                clearTransient();
-            }
-        });
-
-        mDeviceIsSetUpForUser = mCarDeviceProvisionedController.isCurrentUserSetup();
-        mIsUserSetupInProgress = mCarDeviceProvisionedController.isCurrentUserSetupInProgress();
-        mCarDeviceProvisionedController.addCallback(
-                new CarDeviceProvisionedListener() {
-                    @Override
-                    public void onUserSetupInProgressChanged() {
-                        mExecutor.execute(() -> resetSystemBarContentIfNecessary());
-                    }
-
-                    @Override
-                    public void onUserSetupChanged() {
-                        mExecutor.execute(() -> resetSystemBarContentIfNecessary());
-                    }
-
-                    @Override
-                    public void onUserSwitched() {
-                        mExecutor.execute(() -> resetSystemBarContentIfNecessary());
-                    }
-                });
-
-        mConfigurationController.addCallback(/* listener= */ this);
-        registerOverlayChangeBroadcastReceiver();
-
-        createSystemBar(result);
-
-        TaskStackChangeListeners.getInstance().registerTaskStackListener(
-                mButtonSelectionStateListener);
-        TaskStackChangeListeners.getInstance().registerTaskStackListener(
-                new TaskStackChangeListener() {
-                    @Override
-                    public void onLockTaskModeChanged(int mode) {
-                        mCarSystemBarController.refreshSystemBar();
-                    }
-
-                    @Override
-                    public void onTaskMovedToFront(RunningTaskInfo taskInfo) {
-                        if (mDisplayCompatToolbarController != null) {
-                            mDisplayCompatToolbarController.update(taskInfo);
-                        }
-                    }
-                });
-
-        // Lastly, call to the icon policy to install/update all the icons.
-        // Must be called on the main thread due to the use of observeForever() in
-        // mIconPolicy.init().
-        mExecutor.execute(() -> {
-            mIconPolicyLazy.get().init();
-        });
-    }
-
-    private void resetSystemBarContentIfNecessary() {
-        boolean currentUserSetup = mCarDeviceProvisionedController.isCurrentUserSetup();
-        boolean currentUserSetupInProgress = mCarDeviceProvisionedController
-                .isCurrentUserSetupInProgress();
-        if (mIsUserSetupInProgress != currentUserSetupInProgress
-                || mDeviceIsSetUpForUser != currentUserSetup) {
-            mDeviceIsSetUpForUser = currentUserSetup;
-            mIsUserSetupInProgress = currentUserSetupInProgress;
-            resetSystemBarContent(/* isProvisionedStateChange= */ true);
-        }
-    }
-
-    /**
-     * Remove all content from navbars and rebuild them. Used to allow for different nav bars
-     * before and after the device is provisioned. . Also for change of density and font size.
-     */
-    private void resetSystemBarContent(boolean isProvisionedStateChange) {
-        mCarSystemBarRestartTracker.notifyPendingRestart(/* recreateWindows= */ false,
-                isProvisionedStateChange);
-
-        if (!isProvisionedStateChange) {
-            mCarSystemBarController.resetViewCache();
-        }
-        // remove and reattach all components such that we don't keep a reference to unused ui
-        // elements
-        mCarSystemBarController.removeAll();
-        clearSystemBarWindow(/* removeUnusedWindow= */ false);
-
-        buildNavBarContent();
-        // If the UI was rebuilt (day/night change or user change) while the keyguard was up we need
-        // to correctly respect that state.
-        if (mKeyguardStateControllerLazy.get().isShowing()) {
-            mCarSystemBarController.showAllKeyguardButtons(isDeviceSetupForUser());
-        } else {
-            mCarSystemBarController.showAllNavigationButtons(isDeviceSetupForUser());
-        }
-
-        // Upon restarting the Navigation Bar, CarFacetButtonController should immediately apply the
-        // selection state that reflects the current task stack.
-        mButtonSelectionStateListener.onTaskStackChanged();
-
-        mCarSystemBarRestartTracker.notifyRestartComplete(/* recreateWindows= */ false,
-                isProvisionedStateChange);
-    }
-
-    private boolean isDeviceSetupForUser() {
-        return mDeviceIsSetUpForUser && !mIsUserSetupInProgress;
-    }
-
-    private void createSystemBar(RegisterStatusBarResult result) {
-        buildNavBarWindows();
-        buildNavBarContent();
-        attachNavBarWindows();
-
-        // Try setting up the initial state of the nav bar if applicable.
-        if (result != null) {
-            setImeWindowStatus(mDisplayTracker.getDefaultDisplayId(), result.mImeToken,
-                    result.mImeWindowVis, result.mImeBackDisposition,
-                    result.mShowImeSwitcher);
-        }
-    }
-
-    private void buildNavBarWindows() {
-        mTopSystemBarWindow = mCarSystemBarController.getTopWindow();
-        mBottomSystemBarWindow = mCarSystemBarController.getBottomWindow();
-        mLeftSystemBarWindow = mCarSystemBarController.getLeftWindow();
-        mRightSystemBarWindow = mCarSystemBarController.getRightWindow();
-
-        if (mDisplayCompatToolbarController != null) {
-            if (mSystemBarConfigs
-                    .isLeftDisplayCompatToolbarEnabled()) {
-                mDisplayCompatToolbarController.init(mLeftSystemBarWindow);
-            } else if (mSystemBarConfigs
-                    .isRightDisplayCompatToolbarEnabled()) {
-                mDisplayCompatToolbarController.init(mRightSystemBarWindow);
-            }
-        }
-    }
-
-    private void buildNavBarContent() {
-        mTopSystemBarView = mCarSystemBarController.getTopBar(isDeviceSetupForUser());
-        if (mTopSystemBarView != null) {
-            mSystemBarConfigs.insetSystemBar(TOP, mTopSystemBarView);
-            mHvacController.registerHvacViews(mTopSystemBarView);
-            mTopSystemBarWindow.addView(mTopSystemBarView);
-        }
-
-        mBottomSystemBarView = mCarSystemBarController.getBottomBar(isDeviceSetupForUser());
-        if (mBottomSystemBarView != null) {
-            mSystemBarConfigs.insetSystemBar(BOTTOM, mBottomSystemBarView);
-            mHvacController.registerHvacViews(mBottomSystemBarView);
-            mBottomSystemBarWindow.addView(mBottomSystemBarView);
-        }
-
-        mLeftSystemBarView = mCarSystemBarController.getLeftBar(isDeviceSetupForUser());
-        if (mLeftSystemBarView != null) {
-            mSystemBarConfigs.insetSystemBar(LEFT, mLeftSystemBarView);
-            mHvacController.registerHvacViews(mLeftSystemBarView);
-            mLeftSystemBarWindow.addView(mLeftSystemBarView);
-        }
-
-        mRightSystemBarView = mCarSystemBarController.getRightBar(isDeviceSetupForUser());
-        if (mRightSystemBarView != null) {
-            mSystemBarConfigs.insetSystemBar(RIGHT, mRightSystemBarView);
-            mHvacController.registerHvacViews(mRightSystemBarView);
-            mRightSystemBarWindow.addView(mRightSystemBarView);
-        }
-    }
-
-    private void attachNavBarWindows() {
-        mSystemBarConfigs.getSystemBarSidesByZOrder().forEach(this::attachNavBarBySide);
-    }
-
-    @VisibleForTesting
-    ViewGroup getSystemBarWindowBySide(int side) {
-        switch (side) {
-            case TOP:
-                return mTopSystemBarWindow;
-            case BOTTOM:
-                return mBottomSystemBarWindow;
-            case LEFT:
-                return mLeftSystemBarWindow;
-            case RIGHT:
-                return mRightSystemBarWindow;
-            default:
-                return null;
-        }
-    }
-
-    private void attachNavBarBySide(int side) {
-        switch (side) {
-            case TOP:
-                if (DEBUG) {
-                    Log.d(TAG, "mTopSystemBarWindow = " + mTopSystemBarWindow
-                            + ", mTopSystemBarAttached=" + mTopSystemBarAttached
-                            + ", enabled=" + mSystemBarConfigs.getEnabledStatusBySide(TOP));
-                }
-                if (mTopSystemBarWindow != null && !mTopSystemBarAttached
-                        && mSystemBarConfigs.getEnabledStatusBySide(TOP)) {
-                    mWindowManager.addView(mTopSystemBarWindow,
-                            mSystemBarConfigs.getLayoutParamsBySide(TOP));
-                    mTopSystemBarAttached = true;
-                }
-                break;
-            case BOTTOM:
-                if (DEBUG) {
-                    Log.d(TAG, "mBottomSystemBarWindow = " + mBottomSystemBarWindow
-                            + ", mBottomSystemBarAttached=" + mBottomSystemBarAttached
-                            + ", enabled=" + mSystemBarConfigs.getEnabledStatusBySide(BOTTOM));
-                }
-                if (mBottomSystemBarWindow != null && !mBottomSystemBarAttached
-                        && mSystemBarConfigs.getEnabledStatusBySide(BOTTOM)) {
-                    mWindowManager.addView(mBottomSystemBarWindow,
-                            mSystemBarConfigs.getLayoutParamsBySide(BOTTOM));
-                    mBottomSystemBarAttached = true;
-                }
-                break;
-            case LEFT:
-                if (DEBUG) {
-                    Log.d(TAG, "mLeftSystemBarWindow = " + mLeftSystemBarWindow
-                            + ", mLeftSystemBarAttached=" + mLeftSystemBarAttached
-                            + ", enabled=" + mSystemBarConfigs.getEnabledStatusBySide(LEFT));
-                }
-                if (mLeftSystemBarWindow != null && !mLeftSystemBarAttached
-                        && mSystemBarConfigs.getEnabledStatusBySide(LEFT)) {
-                    mWindowManager.addView(mLeftSystemBarWindow,
-                            mSystemBarConfigs.getLayoutParamsBySide(LEFT));
-                    mLeftSystemBarAttached = true;
-                }
-                break;
-            case RIGHT:
-                if (DEBUG) {
-                    Log.d(TAG, "mRightSystemBarWindow = " + mRightSystemBarWindow
-                            + ", mRightSystemBarAttached=" + mRightSystemBarAttached
-                            + ", "
-                            + "enabled=" + mSystemBarConfigs.getEnabledStatusBySide(RIGHT));
-                }
-                if (mRightSystemBarWindow != null && !mRightSystemBarAttached
-                        && mSystemBarConfigs.getEnabledStatusBySide(RIGHT)) {
-                    mWindowManager.addView(mRightSystemBarWindow,
-                            mSystemBarConfigs.getLayoutParamsBySide(RIGHT));
-                    mRightSystemBarAttached = true;
-                }
-                break;
-            default:
-                return;
-        }
-    }
-
-    /**
-     * We register for soft keyboard visibility events such that we can hide the navigation bar
-     * giving more screen space to the IME. Note: this is optional and controlled by
-     * {@code com.android.internal.R.bool.config_hideNavBarForKeyboard}.
-     */
-    @Override
-    public void setImeWindowStatus(int displayId, IBinder token, int vis, int backDisposition,
-            boolean showImeSwitcher) {
-        if (mContext.getDisplayId() != displayId) {
-            return;
-        }
-
-        boolean isKeyboardVisible = (vis & InputMethodService.IME_VISIBLE) != 0;
-
-        updateKeyboardVisibility(isKeyboardVisible);
-    }
-
-    private void updateKeyboardVisibility(boolean isKeyboardVisible) {
-        if (mHideTopBarForKeyboard) {
-            mCarSystemBarController.setTopWindowVisibility(
-                    isKeyboardVisible ? View.GONE : View.VISIBLE);
-        }
-
-        if (mHideBottomBarForKeyboard) {
-            mCarSystemBarController.setBottomWindowVisibility(
-                    isKeyboardVisible ? View.GONE : View.VISIBLE);
-        }
-
-        if (mHideLeftBarForKeyboard) {
-            mCarSystemBarController.setLeftWindowVisibility(
-                    isKeyboardVisible ? View.GONE : View.VISIBLE);
-        }
-        if (mHideRightBarForKeyboard) {
-            mCarSystemBarController.setRightWindowVisibility(
-                    isKeyboardVisible ? View.GONE : View.VISIBLE);
-        }
-    }
-
-    @Override
-    public void onSystemBarAttributesChanged(
-            int displayId,
-            @WindowInsetsController.Appearance int appearance,
-            AppearanceRegion[] appearanceRegions,
-            boolean navbarColorManagedByIme,
-            @WindowInsetsController.Behavior int behavior,
-            @InsetsType int requestedVisibleTypes,
-            String packageName,
-            LetterboxDetails[] letterboxDetails) {
-        if (displayId != mDisplayId) {
-            return;
-        }
-        boolean barModeChanged = updateStatusBarMode(
-                mStatusBarTransientShown ? MODE_SEMI_TRANSPARENT : MODE_TRANSPARENT);
-        int numStacks = appearanceRegions.length;
-        boolean stackAppearancesChanged = mAppearanceRegions.length != numStacks;
-        for (int i = 0; i < numStacks && !stackAppearancesChanged; i++) {
-            stackAppearancesChanged |= !appearanceRegions[i].equals(mAppearanceRegions[i]);
-        }
-        if (stackAppearancesChanged || barModeChanged) {
-            mAppearanceRegions = appearanceRegions;
-            updateStatusBarAppearance();
-        }
-        mCarSystemBarController.refreshSystemBar();
-    }
-
-    @Override
-    public void disable(int displayId, @DisableFlags int state1, @Disable2Flags int state2,
-            boolean animate) {
-        if (displayId != mDisplayId) {
-            return;
-        }
-        mCarSystemBarController.setSystemBarStates(state1, state2);
-    }
-
-    private void updateStatusBarAppearance() {
-        int numStacks = mAppearanceRegions.length;
-        final ArrayList<Rect> lightBarBounds = new ArrayList<>();
-
-        for (int i = 0; i < numStacks; i++) {
-            final AppearanceRegion ar = mAppearanceRegions[i];
-            if (isLight(ar.getAppearance())) {
-                lightBarBounds.add(ar.getBounds());
-            }
-        }
-
-        // If all stacks are light, all icons become dark.
-        if (lightBarBounds.size() == numStacks) {
-            mStatusBarIconController.setIconsDarkArea(null);
-            mStatusBarIconController.getTransitionsController().setIconsDark(
-                    /* dark= */ true, /* animate= */ false);
-        } else if (lightBarBounds.isEmpty()) {
-            // If no one is light, all icons become white.
-            mStatusBarIconController.getTransitionsController().setIconsDark(
-                    /* dark= */ false, /* animate= */ false);
-        } else {
-            // Not the same for every stack, update icons in area only.
-            mStatusBarIconController.setIconsDarkArea(lightBarBounds);
-            mStatusBarIconController.getTransitionsController().setIconsDark(
-                    /* dark= */ true, /* animate= */ false);
-        }
-    }
-
-    private static boolean isLight(int appearance) {
-        return (appearance & APPEARANCE_LIGHT_STATUS_BARS) != 0;
-    }
-
-    @Override
-    public void showTransient(int displayId, int types, boolean isGestureOnSystemBar) {
-        if (displayId != mDisplayId) {
-            return;
-        }
-        if ((types & WindowInsets.Type.statusBars()) != 0) {
-            if (!mStatusBarTransientShown) {
-                mStatusBarTransientShown = true;
-                handleTransientChanged();
-            }
-        }
-        if ((types & WindowInsets.Type.navigationBars()) != 0) {
-            if (!mNavBarTransientShown) {
-                mNavBarTransientShown = true;
-                handleTransientChanged();
-            }
-        }
-    }
-
-    @Override
-    public void abortTransient(int displayId, int types) {
-        if (displayId != mDisplayId) {
-            return;
-        }
-        if ((types & (WindowInsets.Type.statusBars() | WindowInsets.Type.navigationBars())) == 0) {
-            return;
-        }
-        clearTransient();
-    }
-
-    private void clearTransient() {
-        if (mStatusBarTransientShown) {
-            mStatusBarTransientShown = false;
-            handleTransientChanged();
-        }
-        if (mNavBarTransientShown) {
-            mNavBarTransientShown = false;
-            handleTransientChanged();
-        }
-    }
-
-    @VisibleForTesting
-    boolean isStatusBarTransientShown() {
-        return mStatusBarTransientShown;
-    }
-
-    @VisibleForTesting
-    boolean isNavBarTransientShown() {
-        return mNavBarTransientShown;
-    }
-
-    @VisibleForTesting
-    void setSignalPolicy(StatusBarSignalPolicy signalPolicy) {
-        mSignalPolicy = signalPolicy;
-    }
-
-    @Override
-    public void dump(PrintWriter pw, String[] args) {
-        pw.print("  mTaskStackListener=");
-        pw.println(mButtonSelectionStateListener);
-        pw.print("  mBottomSystemBarView=");
-        pw.println(mBottomSystemBarView);
-    }
-
-    private void handleTransientChanged() {
-        updateStatusBarMode(mStatusBarTransientShown ? MODE_SEMI_TRANSPARENT : MODE_TRANSPARENT);
-        updateNavBarMode(mNavBarTransientShown ? MODE_SEMI_TRANSPARENT : MODE_TRANSPARENT);
-    }
-
-    // Returns true if the status bar mode has changed.
-    private boolean updateStatusBarMode(int barMode) {
-        if (mStatusBarMode != barMode) {
-            mStatusBarMode = barMode;
-            mAutoHideController.touchAutoHide();
-            return true;
-        }
-        return false;
-    }
-
-    // Returns true if the nav bar mode has changed.
-    private boolean updateNavBarMode(int barMode) {
-        if (mSystemBarMode != barMode) {
-            mSystemBarMode = barMode;
-            mAutoHideController.touchAutoHide();
-            return true;
-        }
-        return false;
-    }
-
-    @Override
-    public void onConfigChanged(Configuration newConfig) {
-        Locale oldLocale = mCurrentLocale;
-        mCurrentLocale = newConfig.getLocales().get(0);
-
-        boolean isConfigNightMode = newConfig.isNightModeActive();
-        if (isConfigNightMode == mIsUiModeNight
-                && (mCurrentLocale != null && mCurrentLocale.equals(oldLocale)
-                || mCurrentLocale == oldLocale)) {
-            return;
-        }
-
-        // Refresh UI on Night mode or system language changes.
-        if (isConfigNightMode != mIsUiModeNight) {
-            mIsUiModeNight = isConfigNightMode;
-            mUiModeManager.setNightModeActivated(mIsUiModeNight);
-        }
-
-        // cache the current state
-        // The focused view will be destroyed during re-layout, causing the framework to adjust
-        // the focus unexpectedly. To avoid that, move focus to a view that won't be
-        // destroyed during re-layout and has no focus highlight (the FocusParkingView), then
-        // move focus back to the previously focused view after re-layout.
-        mCarSystemBarController.cacheAndHideFocus();
-        View profilePickerView = null;
-        boolean isProfilePickerOpen = false;
-        if (mTopSystemBarView != null) {
-            profilePickerView = mTopSystemBarView.findViewById(R.id.user_name);
-        }
-        if (profilePickerView != null) isProfilePickerOpen = profilePickerView.isSelected();
-        if (isProfilePickerOpen) {
-            profilePickerView.callOnClick();
-        }
-
-        resetSystemBarContent(/* isProvisionedStateChange= */ false);
-
-        // retrieve the previous state
-        if (isProfilePickerOpen) {
-            if (mTopSystemBarView != null) {
-                profilePickerView = mTopSystemBarView.findViewById(R.id.user_name);
-            }
-            if (profilePickerView != null) profilePickerView.callOnClick();
-        }
-
-        mCarSystemBarController.restoreFocus();
-    }
-
-    @VisibleForTesting
-    void restartSystemBars() {
-        mCarSystemBarRestartTracker.notifyPendingRestart(/* recreateWindows= */ true,
-                /* provisionedStateChanged= */ false);
-
-        mCarSystemBarController.removeAll();
-        mCarSystemBarController.resetSystemBarConfigs();
-        clearSystemBarWindow(/* removeUnusedWindow= */ true);
-        buildNavBarWindows();
-        buildNavBarContent();
-        attachNavBarWindows();
-
-        mCarSystemBarRestartTracker.notifyRestartComplete(/* recreateWindows= */ true,
-                /* provisionedStateChanged= */ false);
-    }
-
-    private void clearSystemBarWindow(boolean removeUnusedWindow) {
-        if (mTopSystemBarWindow != null) {
-            mTopSystemBarWindow.removeAllViews();
-            mHvacController.unregisterViews(mTopSystemBarView);
-            if (removeUnusedWindow) {
-                mWindowManager.removeViewImmediate(mTopSystemBarWindow);
-                mTopSystemBarAttached = false;
-            }
-            mTopSystemBarView = null;
-        }
-
-        if (mBottomSystemBarWindow != null) {
-            mBottomSystemBarWindow.removeAllViews();
-            mHvacController.unregisterViews(mBottomSystemBarView);
-            if (removeUnusedWindow) {
-                mWindowManager.removeViewImmediate(mBottomSystemBarWindow);
-                mBottomSystemBarAttached = false;
-            }
-            mBottomSystemBarView = null;
-        }
-
-        if (mLeftSystemBarWindow != null) {
-            mLeftSystemBarWindow.removeAllViews();
-            mHvacController.unregisterViews(mLeftSystemBarView);
-            if (removeUnusedWindow) {
-                mWindowManager.removeViewImmediate(mLeftSystemBarWindow);
-                mLeftSystemBarAttached = false;
-            }
-            mLeftSystemBarView = null;
-        }
-
-        if (mRightSystemBarWindow != null) {
-            mRightSystemBarWindow.removeAllViews();
-            mHvacController.unregisterViews(mRightSystemBarView);
-            if (removeUnusedWindow) {
-                mWindowManager.removeViewImmediate(mRightSystemBarWindow);
-                mRightSystemBarAttached = false;
-            }
-            mRightSystemBarView = null;
-        }
-    }
-
-    @VisibleForTesting
-    void setUiModeManager(UiModeManager uiModeManager) {
-        mUiModeManager = uiModeManager;
-    }
-
-    @Override
-    public void onKeyboardVisibilityChanged(boolean show) {
-        updateKeyboardVisibility(show);
+        mCarSystemBarController.init();
     }
 }
diff --git a/src/com/android/systemui/car/systembar/CarSystemBarButton.java b/src/com/android/systemui/car/systembar/CarSystemBarButton.java
index 0c1f9da1..9e69d54f 100644
--- a/src/com/android/systemui/car/systembar/CarSystemBarButton.java
+++ b/src/com/android/systemui/car/systembar/CarSystemBarButton.java
@@ -27,6 +27,7 @@ import android.app.ActivityTaskManager;
 import android.app.role.RoleManager;
 import android.content.Context;
 import android.content.Intent;
+import android.content.res.Resources;
 import android.content.res.TypedArray;
 import android.graphics.drawable.Drawable;
 import android.os.Build;
@@ -35,6 +36,7 @@ import android.util.AttributeSet;
 import android.util.Log;
 import android.view.Display;
 import android.view.View;
+import android.view.ViewGroup;
 import android.widget.ImageView;
 import android.widget.LinearLayout;
 
@@ -70,6 +72,7 @@ public class CarSystemBarButton extends LinearLayout implements
     private final ActivityManager mActivityManager;
     @Nullable
     private UserTracker mUserTracker;
+    private ViewGroup mIconContainer;
     private AlphaOptimizedImageView mIcon;
     private AlphaOptimizedImageView mMoreIcon;
     private ImageView mUnseenIcon;
@@ -418,27 +421,39 @@ public class CarSystemBarButton extends LinearLayout implements
                 mShowMoreWhenSelected);
 
         mIconResourceId = typedArray.getResourceId(
-                R.styleable.CarSystemBarButton_icon, 0);
+                R.styleable.CarSystemBarButton_icon, Resources.ID_NULL);
         mSelectedIconResourceId = typedArray.getResourceId(
                 R.styleable.CarSystemBarButton_selectedIcon, mIconResourceId);
         mIsDefaultAppIconForRoleEnabled = typedArray.getBoolean(
                 R.styleable.CarSystemBarButton_useDefaultAppIconForRole, false);
         mToggleSelectedState = typedArray.getBoolean(
                 R.styleable.CarSystemBarButton_toggleSelected, false);
+        mIconContainer = findViewById(R.id.car_nav_button_icon);
         mIcon = findViewById(R.id.car_nav_button_icon_image);
-        refreshIconAlpha(mIcon);
         mMoreIcon = findViewById(R.id.car_nav_button_more_icon);
         mUnseenIcon = findViewById(R.id.car_nav_button_unseen_icon);
+        refreshIconAlpha(mIcon);
         updateImage(mIcon);
     }
 
+    private void updateIconContainerVisibility() {
+        boolean visible = mIcon.getVisibility() == VISIBLE
+                || mUnseenIcon.getVisibility() == VISIBLE
+                || mMoreIcon.getVisibility() == VISIBLE;
+        mIconContainer.setVisibility(visible ? VISIBLE : GONE);
+    }
+
     protected void updateImage(AlphaOptimizedImageView icon) {
         if (mIsDefaultAppIconForRoleEnabled && mAppIcon != null) {
             icon.setImageDrawable(mAppIcon);
+            icon.setVisibility(VISIBLE);
         } else {
-            icon.setImageResource(mSelected ? mSelectedIconResourceId : mIconResourceId);
+            int resId = mSelected ? mSelectedIconResourceId : mIconResourceId;
+            icon.setImageResource(resId);
+            icon.setVisibility(resId != Resources.ID_NULL ? VISIBLE : GONE);
         }
         mUnseenIcon.setVisibility(mHasUnseen ? VISIBLE : GONE);
+        updateIconContainerVisibility();
     }
 
     protected void refreshIconAlpha(AlphaOptimizedImageView icon) {
diff --git a/src/com/android/systemui/car/systembar/CarSystemBarController.java b/src/com/android/systemui/car/systembar/CarSystemBarController.java
index ee220798..031682e0 100644
--- a/src/com/android/systemui/car/systembar/CarSystemBarController.java
+++ b/src/com/android/systemui/car/systembar/CarSystemBarController.java
@@ -16,722 +16,133 @@
 
 package com.android.systemui.car.systembar;
 
-import static com.android.systemui.car.systembar.SystemBarConfigs.BOTTOM;
-import static com.android.systemui.car.systembar.SystemBarConfigs.LEFT;
-import static com.android.systemui.car.systembar.SystemBarConfigs.RIGHT;
-import static com.android.systemui.car.systembar.SystemBarConfigs.TOP;
-
-import android.annotation.LayoutRes;
-import android.app.ActivityManager;
-import android.app.StatusBarManager;
-import android.content.Context;
-import android.os.Build;
-import android.util.ArraySet;
-import android.util.Log;
-import android.view.Gravity;
+import android.annotation.IntDef;
+import android.app.StatusBarManager.Disable2Flags;
+import android.app.StatusBarManager.DisableFlags;
 import android.view.View;
 import android.view.ViewGroup;
-import android.widget.Toast;
-
-import androidx.annotation.IdRes;
-import androidx.annotation.Nullable;
+import android.view.WindowInsets.Type.InsetsType;
+import android.view.WindowInsetsController;
 
-import com.android.car.ui.FocusParkingView;
-import com.android.car.ui.utils.ViewUtils;
-import com.android.internal.annotations.VisibleForTesting;
-import com.android.systemui.R;
+import com.android.internal.statusbar.LetterboxDetails;
+import com.android.internal.view.AppearanceRegion;
+import com.android.systemui.car.hvac.HvacPanelController;
 import com.android.systemui.car.hvac.HvacPanelOverlayViewController;
 import com.android.systemui.car.notification.NotificationPanelViewController;
-import com.android.systemui.car.statusbar.UserNameViewController;
-import com.android.systemui.car.statusicon.StatusIconPanelViewController;
-import com.android.systemui.car.users.CarSystemUIUserUtil;
-import com.android.systemui.dagger.SysUISingleton;
-import com.android.systemui.settings.UserTracker;
-
-import dagger.Lazy;
-
-import java.util.ArrayList;
-import java.util.List;
-import java.util.Set;
-
-import javax.inject.Provider;
-
-/** A single class which controls the navigation bar views. */
-@SysUISingleton
-public class CarSystemBarController {
-    private static final boolean DEBUG = Build.IS_ENG || Build.IS_USERDEBUG;
-
-    private static final String TAG = CarSystemBarController.class.getSimpleName();
-
-    private final Context mContext;
-    private final UserTracker mUserTracker;
-    private final CarSystemBarViewFactory mCarSystemBarViewFactory;
-    private final ButtonSelectionStateController mButtonSelectionStateController;
-    private final ButtonRoleHolderController mButtonRoleHolderController;
-    private final Provider<StatusIconPanelViewController.Builder> mPanelControllerBuilderProvider;
-    private final Lazy<UserNameViewController> mUserNameViewControllerLazy;
-    private final Lazy<MicPrivacyChipViewController> mMicPrivacyChipViewControllerLazy;
-    private final Lazy<CameraPrivacyChipViewController> mCameraPrivacyChipViewControllerLazy;
-
-    private final SystemBarConfigs mSystemBarConfigs;
-    private boolean mShowTop;
-    private boolean mShowBottom;
-    private boolean mShowLeft;
-    private boolean mShowRight;
-    private final int mPrivacyChipXOffset;
+import com.android.systemui.car.notification.NotificationsShadeController;
+import com.android.systemui.statusbar.policy.ConfigurationController;
 
-    @IdRes
-    private int mTopFocusedViewId;
-    @IdRes
-    private int mBottomFocusedViewId;
-    @IdRes
-    private int mLeftFocusedViewId;
-    @IdRes
-    private int mRightFocusedViewId;
+import java.lang.annotation.ElementType;
+import java.lang.annotation.Retention;
+import java.lang.annotation.RetentionPolicy;
+import java.lang.annotation.Target;
 
-    private final Set<View.OnTouchListener> mTopBarTouchListeners = new ArraySet<>();
-    private final Set<View.OnTouchListener> mBottomBarTouchListeners = new ArraySet<>();
-    private final Set<View.OnTouchListener> mLeftBarTouchListeners = new ArraySet<>();
-    private final Set<View.OnTouchListener> mRightBarTouchListeners = new ArraySet<>();
-
-    private NotificationsShadeController mNotificationsShadeController;
-    private HvacPanelController mHvacPanelController;
-    private StatusIconPanelViewController mMicPanelController;
-    private StatusIconPanelViewController mCameraPanelController;
-    private StatusIconPanelViewController mProfilePanelController;
-    private HvacPanelOverlayViewController mHvacPanelOverlayViewController;
-    private NotificationPanelViewController mNotificationPanelViewController;
-
-    private CarSystemBarView mTopView;
-    private CarSystemBarView mBottomView;
-    private CarSystemBarView mLeftView;
-    private CarSystemBarView mRightView;
-
-    // Saved StatusBarManager.DisableFlags
-    private int mStatusBarState;
-    // Saved StatusBarManager.Disable2Flags
-    private int mStatusBarState2;
-    private int mLockTaskMode;
-
-    public CarSystemBarController(Context context,
-            UserTracker userTracker,
-            CarSystemBarViewFactory carSystemBarViewFactory,
-            ButtonSelectionStateController buttonSelectionStateController,
-            Lazy<UserNameViewController> userNameViewControllerLazy,
-            Lazy<MicPrivacyChipViewController> micPrivacyChipViewControllerLazy,
-            Lazy<CameraPrivacyChipViewController> cameraPrivacyChipViewControllerLazy,
-            ButtonRoleHolderController buttonRoleHolderController,
-            SystemBarConfigs systemBarConfigs,
-            Provider<StatusIconPanelViewController.Builder> panelControllerBuilderProvider) {
-        mContext = context;
-        mUserTracker = userTracker;
-        mCarSystemBarViewFactory = carSystemBarViewFactory;
-        mButtonSelectionStateController = buttonSelectionStateController;
-        mUserNameViewControllerLazy = userNameViewControllerLazy;
-        mMicPrivacyChipViewControllerLazy = micPrivacyChipViewControllerLazy;
-        mCameraPrivacyChipViewControllerLazy = cameraPrivacyChipViewControllerLazy;
-        mButtonRoleHolderController = buttonRoleHolderController;
-        mPanelControllerBuilderProvider = panelControllerBuilderProvider;
-        mSystemBarConfigs = systemBarConfigs;
+/**
+ * An interface for controlling system bars.
+ */
+public interface CarSystemBarController extends ConfigurationController.ConfigurationListener {
 
-        // Read configuration.
-        readConfigs();
-        mPrivacyChipXOffset = -context.getResources()
-                .getDimensionPixelOffset(R.dimen.privacy_chip_horizontal_padding);
-    }
+    int LEFT = 0;
+    int TOP = 1;
+    int RIGHT = 2;
+    int BOTTOM = 3;
 
-    private void readConfigs() {
-        mShowTop = mSystemBarConfigs.getEnabledStatusBySide(TOP);
-        mShowBottom = mSystemBarConfigs.getEnabledStatusBySide(BOTTOM);
-        mShowLeft = mSystemBarConfigs.getEnabledStatusBySide(LEFT);
-        mShowRight = mSystemBarConfigs.getEnabledStatusBySide(RIGHT);
+    @IntDef(value = {LEFT, TOP, RIGHT, BOTTOM})
+    @Target({ElementType.TYPE_PARAMETER, ElementType.TYPE_USE})
+    @Retention(RetentionPolicy.SOURCE)
+    @interface SystemBarSide {
     }
 
     /**
-     * Hides all system bars.
+     * initializes the system bars.
      */
-    public void hideBars() {
-        setTopWindowVisibility(View.GONE);
-        setBottomWindowVisibility(View.GONE);
-        setLeftWindowVisibility(View.GONE);
-        setRightWindowVisibility(View.GONE);
-    }
+    void init();
 
     /**
-     * Shows all system bars.
+     * See {@code CommandQueue.Callback#setImeWindowStatus}
      */
-    public void showBars() {
-        setTopWindowVisibility(View.VISIBLE);
-        setBottomWindowVisibility(View.VISIBLE);
-        setLeftWindowVisibility(View.VISIBLE);
-        setRightWindowVisibility(View.VISIBLE);
-    }
-
-    /** Clean up */
-    public void removeAll() {
-        mButtonSelectionStateController.removeAll();
-        mButtonRoleHolderController.removeAll();
-        mUserNameViewControllerLazy.get().removeAll();
-        mMicPrivacyChipViewControllerLazy.get().removeAll();
-        mCameraPrivacyChipViewControllerLazy.get().removeAll();
-
-        mMicPanelController = null;
-        mCameraPanelController = null;
-        mProfilePanelController = null;
-    }
-
-    /** Gets the top window if configured to do so. */
-    @Nullable
-    public ViewGroup getTopWindow() {
-        return mShowTop ? mCarSystemBarViewFactory.getTopWindow() : null;
-    }
-
-    /** Gets the bottom window if configured to do so. */
-    @Nullable
-    public ViewGroup getBottomWindow() {
-        return mShowBottom ? mCarSystemBarViewFactory.getBottomWindow() : null;
-    }
-
-    /** Gets the left window if configured to do so. */
-    @Nullable
-    public ViewGroup getLeftWindow() {
-        return mShowLeft ? mCarSystemBarViewFactory.getLeftWindow() : null;
-    }
-
-    /** Gets the right window if configured to do so. */
-    @Nullable
-    public ViewGroup getRightWindow() {
-        return mShowRight ? mCarSystemBarViewFactory.getRightWindow() : null;
-    }
-
-    /** Toggles the top nav bar visibility. */
-    public boolean setTopWindowVisibility(@View.Visibility int visibility) {
-        return setWindowVisibility(getTopWindow(), visibility);
-    }
-
-    /** Toggles the bottom nav bar visibility. */
-    public boolean setBottomWindowVisibility(@View.Visibility int visibility) {
-        return setWindowVisibility(getBottomWindow(), visibility);
-    }
-
-    /** Toggles the left nav bar visibility. */
-    public boolean setLeftWindowVisibility(@View.Visibility int visibility) {
-        return setWindowVisibility(getLeftWindow(), visibility);
-    }
-
-    /** Toggles the right nav bar visibility. */
-    public boolean setRightWindowVisibility(@View.Visibility int visibility) {
-        return setWindowVisibility(getRightWindow(), visibility);
-    }
-
-    private boolean setWindowVisibility(ViewGroup window, @View.Visibility int visibility) {
-        if (window == null) {
-            return false;
-        }
-
-        if (window.getVisibility() == visibility) {
-            return false;
-        }
-
-        window.setVisibility(visibility);
-        return true;
-    }
+    void setImeWindowStatus(int displayId, int vis, int backDisposition,
+                boolean showImeSwitcher);
 
     /**
-     * Sets the system bar states - {@code StatusBarManager.DisableFlags},
-     * {@code StatusBarManager.Disable2Flags}, lock task mode. When there is a change in state,
-     * and refreshes the system bars.
-     *
-     * @param state {@code StatusBarManager.DisableFlags}
-     * @param state2 {@code StatusBarManager.Disable2Flags}
+     * See {@code CommandQueue.Callback#onSystemBarAttributesChanged}
      */
-    public void setSystemBarStates(int state, int state2) {
-        int diff = (state ^ mStatusBarState) | (state2 ^ mStatusBarState2);
-        int lockTaskMode = getLockTaskModeState();
-        if (diff == 0 && mLockTaskMode == lockTaskMode) {
-            if (DEBUG) {
-                Log.d(TAG, "setSystemBarStates(): status bar states unchanged: state: "
-                        + state + " state2: " +  state2 + " lockTaskMode: " + mLockTaskMode);
-            }
-            return;
-        }
-        mStatusBarState = state;
-        mStatusBarState2 = state2;
-        mLockTaskMode = lockTaskMode;
-        refreshSystemBar();
-    }
-
-    @VisibleForTesting
-    protected int getStatusBarState() {
-        return mStatusBarState;
-    }
-
-    @VisibleForTesting
-    protected int getStatusBarState2() {
-        return mStatusBarState2;
-    }
-
-    @VisibleForTesting
-    protected int getLockTaskMode() {
-        return mLockTaskMode;
-    }
+    void onSystemBarAttributesChanged(
+                int displayId,
+                @WindowInsetsController.Appearance int appearance,
+                AppearanceRegion[] appearanceRegions,
+                boolean navbarColorManagedByIme,
+                @WindowInsetsController.Behavior int behavior,
+                @InsetsType int requestedVisibleTypes,
+                String packageName,
+                LetterboxDetails[] letterboxDetails);
 
     /**
-     * Refreshes system bar views and sets the visibility of certain components based on
-     * {@link StatusBarManager} flags and lock task mode.
-     * <ul>
-     * <li>Home button will be disabled when {@code StatusBarManager.DISABLE_HOME} is set.
-     * <li>Phone call button will be disable in lock task mode.
-     * <li>App grid button will be disable when {@code StatusBarManager.DISABLE_HOME} is set.
-     * <li>Notification button will be disable when
-     * {@code StatusBarManager.DISABLE_NOTIFICATION_ICONS} is set.
-     * <li>Quick settings and user switcher will be hidden when in lock task mode or when
-     * {@code StatusBarManager.DISABLE2_QUICK_SETTINGS} is set.
-     * </ul>
+     * See {@code CommandQueue.Callback#showTransient}
      */
-    public void refreshSystemBar() {
-        boolean homeDisabled = ((mStatusBarState & StatusBarManager.DISABLE_HOME) > 0);
-        boolean notificationDisabled =
-                ((mStatusBarState & StatusBarManager.DISABLE_NOTIFICATION_ICONS) > 0);
-        boolean locked = (mLockTaskMode == ActivityManager.LOCK_TASK_MODE_LOCKED);
-        boolean qcDisabled =
-                ((mStatusBarState2 & StatusBarManager.DISABLE2_QUICK_SETTINGS) > 0) || locked;
-        boolean systemIconsDisabled =
-                ((mStatusBarState2 & StatusBarManager.DISABLE2_SYSTEM_ICONS) > 0) || locked;
-
-        setDisabledSystemBarButton(R.id.home, homeDisabled, "home");
-        setDisabledSystemBarButton(R.id.passenger_home, homeDisabled, "passenger_home");
-        setDisabledSystemBarButton(R.id.phone_nav, locked, "phone_nav");
-        setDisabledSystemBarButton(R.id.grid_nav, homeDisabled, "grid_nav");
-        setDisabledSystemBarButton(R.id.notifications, notificationDisabled, "notifications");
-
-        setDisabledSystemBarContainer(R.id.user_name_container, qcDisabled,
-                "user_name_container");
-
-        if (DEBUG) {
-            Log.d(TAG, "refreshSystemBar: locked?: " + locked
-                    + " homeDisabled: " + homeDisabled
-                    + " notificationDisabled: " + notificationDisabled
-                    + " qcDisabled: " + qcDisabled
-                    + " systemIconsDisabled: " + systemIconsDisabled);
-        }
-    }
-
-    private int getLockTaskModeState() {
-        return mContext.getSystemService(ActivityManager.class).getLockTaskModeState();
-    }
-
-    private void setDisabledSystemBarButton(int viewId, boolean disabled,
-                @Nullable String buttonName) {
-        for (CarSystemBarView barView : getAllAvailableSystemBarViews()) {
-            barView.setDisabledSystemBarButton(viewId, disabled,
-                    () -> showAdminSupportDetailsDialog(), buttonName);
-        }
-    }
-
-    private void setDisabledSystemBarContainer(int viewId, boolean disabled,
-                @Nullable String viewName) {
-        for (CarSystemBarView barView : getAllAvailableSystemBarViews()) {
-            barView.setVisibilityByViewId(viewId, viewName,
-                    disabled ? View.INVISIBLE : View.VISIBLE);
-        }
-    }
-
-    private void showAdminSupportDetailsDialog() {
-        // TODO(b/205891123): launch AdminSupportDetailsDialog after moving
-        // AdminSupportDetailsDialog out of CarSettings since CarSettings is not and should not
-        // be allowlisted for lock task mode.
-        Toast.makeText(mContext, "This action is unavailable for your profile",
-                Toast.LENGTH_LONG).show();
-    }
-
-    /** Gets the top navigation bar with the appropriate listeners set. */
-    @Nullable
-    public CarSystemBarView getTopBar(boolean isSetUp) {
-        if (!mShowTop) {
-            return null;
-        }
-
-        mTopView = mCarSystemBarViewFactory.getTopBar(isSetUp);
-        setupBar(mTopView, mTopBarTouchListeners, mNotificationsShadeController,
-                mHvacPanelController, mHvacPanelOverlayViewController,
-                mNotificationPanelViewController);
-
-        if (isSetUp) {
-            // We do not want the privacy chips or the profile picker to be clickable in
-            // unprovisioned mode.
-            mMicPanelController = setupSensorQcPanel(mMicPanelController, R.id.mic_privacy_chip,
-                    R.layout.qc_mic_panel);
-            mCameraPanelController = setupSensorQcPanel(mCameraPanelController,
-                    R.id.camera_privacy_chip, R.layout.qc_camera_panel);
-            setupProfilePanel();
-        }
-
-        return mTopView;
-    }
-
-    /** Gets the bottom navigation bar with the appropriate listeners set. */
-    @Nullable
-    public CarSystemBarView getBottomBar(boolean isSetUp) {
-        if (!mShowBottom) {
-            return null;
-        }
-
-        mBottomView = mCarSystemBarViewFactory.getBottomBar(isSetUp);
-        setupBar(mBottomView, mBottomBarTouchListeners, mNotificationsShadeController,
-                mHvacPanelController, mHvacPanelOverlayViewController,
-                mNotificationPanelViewController);
-
-        return mBottomView;
-    }
-
-    /** Gets the left navigation bar with the appropriate listeners set. */
-    @Nullable
-    public CarSystemBarView getLeftBar(boolean isSetUp) {
-        if (!mShowLeft) {
-            return null;
-        }
-
-        mLeftView = mCarSystemBarViewFactory.getLeftBar(isSetUp);
-        setupBar(mLeftView, mLeftBarTouchListeners, mNotificationsShadeController,
-                mHvacPanelController, mHvacPanelOverlayViewController,
-                mNotificationPanelViewController);
-        return mLeftView;
-    }
-
-    /** Gets the right navigation bar with the appropriate listeners set. */
-    @Nullable
-    public CarSystemBarView getRightBar(boolean isSetUp) {
-        if (!mShowRight) {
-            return null;
-        }
-
-        mRightView = mCarSystemBarViewFactory.getRightBar(isSetUp);
-        setupBar(mRightView, mRightBarTouchListeners, mNotificationsShadeController,
-                mHvacPanelController, mHvacPanelOverlayViewController,
-                mNotificationPanelViewController);
-        return mRightView;
-    }
-
-    private void setupBar(CarSystemBarView view, Set<View.OnTouchListener> statusBarTouchListeners,
-            NotificationsShadeController notifShadeController,
-            HvacPanelController hvacPanelController,
-            HvacPanelOverlayViewController hvacPanelOverlayViewController,
-            NotificationPanelViewController notificationPanelViewController) {
-        view.updateHomeButtonVisibility(CarSystemUIUserUtil.isSecondaryMUMDSystemUI());
-        view.setStatusBarWindowTouchListeners(statusBarTouchListeners);
-        view.setNotificationsPanelController(notifShadeController);
-        view.registerNotificationPanelViewController(notificationPanelViewController);
-        view.setHvacPanelController(hvacPanelController);
-        view.registerHvacPanelOverlayViewController(hvacPanelOverlayViewController);
-        view.updateControlCenterButtonVisibility(CarSystemUIUserUtil.isMUMDSystemUI());
-        mButtonSelectionStateController.addAllButtonsWithSelectionState(view);
-        mButtonRoleHolderController.addAllButtonsWithRoleName(view);
-        mUserNameViewControllerLazy.get().addUserNameView(view);
-        mMicPrivacyChipViewControllerLazy.get().addPrivacyChipView(view);
-        mCameraPrivacyChipViewControllerLazy.get().addPrivacyChipView(view);
-    }
-
-    private StatusIconPanelViewController setupSensorQcPanel(
-            @Nullable StatusIconPanelViewController panelController, int chipId,
-            @LayoutRes int panelLayoutRes) {
-        if (panelController == null) {
-            View privacyChip = mTopView.findViewById(chipId);
-            if (privacyChip != null) {
-                panelController = mPanelControllerBuilderProvider.get()
-                        .setXOffset(mPrivacyChipXOffset)
-                        .setGravity(Gravity.TOP | Gravity.END)
-                        .build(privacyChip, panelLayoutRes, R.dimen.car_sensor_qc_panel_width);
-                panelController.init();
-            }
-        }
-        return panelController;
-    }
-
-    private void setupProfilePanel() {
-        View profilePickerView = mTopView.findViewById(R.id.user_name);
-        if (mProfilePanelController == null && profilePickerView != null) {
-            boolean profilePanelDisabledWhileDriving = mContext.getResources().getBoolean(
-                    R.bool.config_profile_panel_disabled_while_driving);
-            mProfilePanelController = mPanelControllerBuilderProvider.get()
-                    .setGravity(Gravity.TOP | Gravity.END)
-                    .setDisabledWhileDriving(profilePanelDisabledWhileDriving)
-                    .build(profilePickerView, R.layout.qc_profile_switcher,
-                            R.dimen.car_profile_quick_controls_panel_width);
-            mProfilePanelController.init();
-        }
-    }
-
-    /** Sets a touch listener for the top navigation bar. */
-    public void registerTopBarTouchListener(View.OnTouchListener listener) {
-        boolean setModified = mTopBarTouchListeners.add(listener);
-        if (setModified && mTopView != null) {
-            mTopView.setStatusBarWindowTouchListeners(mTopBarTouchListeners);
-        }
-    }
-
-    /** Sets a touch listener for the bottom navigation bar. */
-    public void registerBottomBarTouchListener(View.OnTouchListener listener) {
-        boolean setModified = mBottomBarTouchListeners.add(listener);
-        if (setModified && mBottomView != null) {
-            mBottomView.setStatusBarWindowTouchListeners(mBottomBarTouchListeners);
-        }
-    }
-
-    /** Sets a touch listener for the left navigation bar. */
-    public void registerLeftBarTouchListener(View.OnTouchListener listener) {
-        boolean setModified = mLeftBarTouchListeners.add(listener);
-        if (setModified && mLeftView != null) {
-            mLeftView.setStatusBarWindowTouchListeners(mLeftBarTouchListeners);
-        }
-    }
-
-    /** Sets a touch listener for the right navigation bar. */
-    public void registerRightBarTouchListener(View.OnTouchListener listener) {
-        boolean setModified = mRightBarTouchListeners.add(listener);
-        if (setModified && mRightView != null) {
-            mRightView.setStatusBarWindowTouchListeners(mRightBarTouchListeners);
-        }
-    }
-
-    /** Sets a notification controller which toggles the notification panel. */
-    public void registerNotificationController(
-            NotificationsShadeController notificationsShadeController) {
-        mNotificationsShadeController = notificationsShadeController;
-        if (mTopView != null) {
-            mTopView.setNotificationsPanelController(mNotificationsShadeController);
-        }
-        if (mBottomView != null) {
-            mBottomView.setNotificationsPanelController(mNotificationsShadeController);
-        }
-        if (mLeftView != null) {
-            mLeftView.setNotificationsPanelController(mNotificationsShadeController);
-        }
-        if (mRightView != null) {
-            mRightView.setNotificationsPanelController(mNotificationsShadeController);
-        }
-    }
-
-    /** Sets the NotificationPanelViewController for views to listen to the panel's state. */
-    public void registerNotificationPanelViewController(
-            NotificationPanelViewController notificationPanelViewController) {
-        mNotificationPanelViewController = notificationPanelViewController;
-        if (mTopView != null) {
-            mTopView.registerNotificationPanelViewController(mNotificationPanelViewController);
-        }
-        if (mBottomView != null) {
-            mBottomView.registerNotificationPanelViewController(mNotificationPanelViewController);
-        }
-        if (mLeftView != null) {
-            mLeftView.registerNotificationPanelViewController(mNotificationPanelViewController);
-        }
-        if (mRightView != null) {
-            mRightView.registerNotificationPanelViewController(mNotificationPanelViewController);
-        }
-    }
-
-    /** Sets an HVAC controller which toggles the HVAC panel. */
-    public void registerHvacPanelController(HvacPanelController hvacPanelController) {
-        mHvacPanelController = hvacPanelController;
-        if (mTopView != null) {
-            mTopView.setHvacPanelController(mHvacPanelController);
-        }
-        if (mBottomView != null) {
-            mBottomView.setHvacPanelController(mHvacPanelController);
-        }
-        if (mLeftView != null) {
-            mLeftView.setHvacPanelController(mHvacPanelController);
-        }
-        if (mRightView != null) {
-            mRightView.setHvacPanelController(mHvacPanelController);
-        }
-    }
-
-    /** Sets the HVACPanelOverlayViewController for views to listen to the panel's state. */
-    public void registerHvacPanelOverlayViewController(
-            HvacPanelOverlayViewController hvacPanelOverlayViewController) {
-        mHvacPanelOverlayViewController = hvacPanelOverlayViewController;
-        if (mTopView != null) {
-            mTopView.registerHvacPanelOverlayViewController(mHvacPanelOverlayViewController);
-        }
-        if (mBottomView != null) {
-            mBottomView.registerHvacPanelOverlayViewController(mHvacPanelOverlayViewController);
-        }
-        if (mLeftView != null) {
-            mLeftView.registerHvacPanelOverlayViewController(mHvacPanelOverlayViewController);
-        }
-        if (mRightView != null) {
-            mRightView.registerHvacPanelOverlayViewController(mHvacPanelOverlayViewController);
-        }
-    }
+    void showTransient(int displayId, @InsetsType int types, boolean isGestureOnSystemBar);
 
     /**
-     * Shows all of the navigation buttons on the valid instances of {@link CarSystemBarView}.
+     * See {@code CommandQueue.Callback#abortTransient}
      */
-    public void showAllNavigationButtons(boolean isSetUp) {
-        checkAllBars(isSetUp);
-        if (mTopView != null) {
-            mTopView.showButtonsOfType(CarSystemBarView.BUTTON_TYPE_NAVIGATION);
-        }
-        if (mBottomView != null) {
-            mBottomView.showButtonsOfType(CarSystemBarView.BUTTON_TYPE_NAVIGATION);
-        }
-        if (mLeftView != null) {
-            mLeftView.showButtonsOfType(CarSystemBarView.BUTTON_TYPE_NAVIGATION);
-        }
-        if (mRightView != null) {
-            mRightView.showButtonsOfType(CarSystemBarView.BUTTON_TYPE_NAVIGATION);
-        }
-    }
+    void abortTransient(int displayId, @InsetsType int types);
 
     /**
-     * Shows all of the keyguard specific buttons on the valid instances of
-     * {@link CarSystemBarView}.
+     * See {@code CommandQueue.Callback#disable}
      */
-    public void showAllKeyguardButtons(boolean isSetUp) {
-        checkAllBars(isSetUp);
-        if (mTopView != null) {
-            mTopView.showButtonsOfType(CarSystemBarView.BUTTON_TYPE_KEYGUARD);
-        }
-        if (mBottomView != null) {
-            mBottomView.showButtonsOfType(CarSystemBarView.BUTTON_TYPE_KEYGUARD);
-        }
-        if (mLeftView != null) {
-            mLeftView.showButtonsOfType(CarSystemBarView.BUTTON_TYPE_KEYGUARD);
-        }
-        if (mRightView != null) {
-            mRightView.showButtonsOfType(CarSystemBarView.BUTTON_TYPE_KEYGUARD);
-        }
-    }
+    void disable(int displayId, @DisableFlags int state1, @Disable2Flags int state2,
+                boolean animate);
 
     /**
-     * Shows all of the occlusion state buttons on the valid instances of
-     * {@link CarSystemBarView}.
+     * See {@code CommandQueue.Callback#setSystemBarStates}
      */
-    public void showAllOcclusionButtons(boolean isSetUp) {
-        checkAllBars(isSetUp);
-        if (mTopView != null) {
-            mTopView.showButtonsOfType(CarSystemBarView.BUTTON_TYPE_OCCLUSION);
-        }
-        if (mBottomView != null) {
-            mBottomView.showButtonsOfType(CarSystemBarView.BUTTON_TYPE_OCCLUSION);
-        }
-        if (mLeftView != null) {
-            mLeftView.showButtonsOfType(CarSystemBarView.BUTTON_TYPE_OCCLUSION);
-        }
-        if (mRightView != null) {
-            mRightView.showButtonsOfType(CarSystemBarView.BUTTON_TYPE_OCCLUSION);
-        }
-    }
-
-    /** Toggles whether the notifications icon has an unseen indicator or not. */
-    public void toggleAllNotificationsUnseenIndicator(boolean isSetUp, boolean hasUnseen) {
-        checkAllBars(isSetUp);
-        if (mTopView != null) {
-            mTopView.toggleNotificationUnseenIndicator(hasUnseen);
-        }
-        if (mBottomView != null) {
-            mBottomView.toggleNotificationUnseenIndicator(hasUnseen);
-        }
-        if (mLeftView != null) {
-            mLeftView.toggleNotificationUnseenIndicator(hasUnseen);
-        }
-        if (mRightView != null) {
-            mRightView.toggleNotificationUnseenIndicator(hasUnseen);
-        }
-    }
-
-    /** Interface for controlling the notifications shade. */
-    public interface NotificationsShadeController {
-        /** Toggles the visibility of the notifications shade. */
-        void togglePanel();
+    void setSystemBarStates(@DisableFlags int state, @DisableFlags int state2);
 
-        /** Returns {@code true} if the panel is open. */
-        boolean isNotificationPanelOpen();
-    }
-
-    /** Interface for controlling the HVAC panel. */
-    public interface HvacPanelController {
-        /** Toggles the visibility of the HVAC shade. */
-        void togglePanel();
-
-        /** Returns {@code true} if the panel is open. */
-        boolean isHvacPanelOpen();
-    }
+    /**
+     * Changes window visibility of the given system bar side.
+     */
+    boolean setBarVisibility(@SystemBarSide int side, @View.Visibility int visibility);
 
-    private void checkAllBars(boolean isSetUp) {
-        mTopView = getTopBar(isSetUp);
-        mBottomView = getBottomBar(isSetUp);
-        mLeftView = getLeftBar(isSetUp);
-        mRightView = getRightBar(isSetUp);
-    }
+    /**
+     * Returns the window of the given system bar side.
+     */
+    ViewGroup getBarWindow(@SystemBarSide int side);
 
-    private List<CarSystemBarView> getAllAvailableSystemBarViews() {
-        List<CarSystemBarView> barViews = new ArrayList<>();
-        if (mTopView != null) {
-            barViews.add(mTopView);
-        }
-        if (mBottomView != null) {
-            barViews.add(mBottomView);
-        }
-        if (mLeftView != null) {
-            barViews.add(mLeftView);
-        }
-        if (mRightView != null) {
-            barViews.add(mRightView);
-        }
-        return barViews;
-    }
+    /**
+     * Returns the view of the given system bar side.
+     */
+    CarSystemBarView getBarView(@SystemBarSide int side, boolean isSetUp);
 
-    /** Resets the cached Views. */
-    protected void resetViewCache() {
-        mCarSystemBarViewFactory.resetSystemBarViewCache();
-    }
+    /**
+     * Registers a touch listener callbar for the given system bar side.
+     */
+    void registerBarTouchListener(@SystemBarSide int side, View.OnTouchListener listener);
 
     /**
-     * Invalidate SystemBarConfigs and fetch again from Resources.
-     * TODO(): b/260206944, Can remove this after we have a fix for overlaid resources not applied.
+     * Toggles all notification unseen indicator.
      */
-    protected void resetSystemBarConfigs() {
-        mSystemBarConfigs.resetSystemBarConfigs();
-        mCarSystemBarViewFactory.resetSystemBarWindowCache();
-        readConfigs();
-    }
+    void toggleAllNotificationsUnseenIndicator(boolean isSetUp, boolean hasUnseen);
 
-    /** Stores the ID of the View that is currently focused and hides the focus. */
-    protected void cacheAndHideFocus() {
-        mTopFocusedViewId = cacheAndHideFocus(mTopView);
-        if (mTopFocusedViewId != View.NO_ID) return;
-        mBottomFocusedViewId = cacheAndHideFocus(mBottomView);
-        if (mBottomFocusedViewId != View.NO_ID) return;
-        mLeftFocusedViewId = cacheAndHideFocus(mLeftView);
-        if (mLeftFocusedViewId != View.NO_ID) return;
-        mRightFocusedViewId = cacheAndHideFocus(mRightView);
-    }
+    /**
+     * Registers a {@link HvacPanelController}
+     */
+    void registerHvacPanelController(HvacPanelController hvacPanelController);
 
-    @VisibleForTesting
-    int cacheAndHideFocus(@Nullable View rootView) {
-        if (rootView == null) return View.NO_ID;
-        View focusedView = rootView.findFocus();
-        if (focusedView == null || focusedView instanceof FocusParkingView) return View.NO_ID;
-        int focusedViewId = focusedView.getId();
-        ViewUtils.hideFocus(rootView);
-        return focusedViewId;
-    }
+    /**
+     * Registers a {@link HvacPanelOverlayViewController}
+     */
+    void registerHvacPanelOverlayViewController(
+            HvacPanelOverlayViewController hvacPanelOverlayViewController);
 
-    /** Requests focus on the View that matches the cached ID. */
-    protected void restoreFocus() {
-        if (restoreFocus(mTopView, mTopFocusedViewId)) return;
-        if (restoreFocus(mBottomView, mBottomFocusedViewId)) return;
-        if (restoreFocus(mLeftView, mLeftFocusedViewId)) return;
-        restoreFocus(mRightView, mRightFocusedViewId);
-    }
+    /**
+     * Registers a {@link NotificationsShadeController}
+     */
+    void registerNotificationController(
+            NotificationsShadeController notificationsShadeController);
 
-    private boolean restoreFocus(@Nullable View rootView, @IdRes int viewToFocusId) {
-        if (rootView == null || viewToFocusId == View.NO_ID) return false;
-        View focusedView = rootView.findViewById(viewToFocusId);
-        if (focusedView == null) return false;
-        focusedView.requestFocus();
-        return true;
-    }
+    /**
+     * Registers a {@link NotificationPanelViewController}
+     */
+    void registerNotificationPanelViewController(
+            NotificationPanelViewController notificationPanelViewController);
 }
diff --git a/src/com/android/systemui/car/systembar/CarSystemBarControllerImpl.java b/src/com/android/systemui/car/systembar/CarSystemBarControllerImpl.java
new file mode 100644
index 00000000..c5cee380
--- /dev/null
+++ b/src/com/android/systemui/car/systembar/CarSystemBarControllerImpl.java
@@ -0,0 +1,1548 @@
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
+package com.android.systemui.car.systembar;
+
+import static android.content.Intent.ACTION_OVERLAY_CHANGED;
+import static android.view.WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS;
+
+import static com.android.systemui.car.systembar.CarSystemBarController.BOTTOM;
+import static com.android.systemui.car.systembar.CarSystemBarController.LEFT;
+import static com.android.systemui.car.systembar.CarSystemBarController.RIGHT;
+import static com.android.systemui.car.systembar.CarSystemBarController.TOP;
+import static com.android.systemui.car.Flags.configAwareSystemui;
+import static com.android.systemui.shared.statusbar.phone.BarTransitions.MODE_SEMI_TRANSPARENT;
+import static com.android.systemui.shared.statusbar.phone.BarTransitions.MODE_TRANSPARENT;
+
+import android.annotation.LayoutRes;
+import android.app.ActivityManager;
+import android.app.ActivityManager.RunningTaskInfo;
+import android.app.StatusBarManager;
+import android.app.StatusBarManager.Disable2Flags;
+import android.app.StatusBarManager.DisableFlags;
+import android.content.BroadcastReceiver;
+import android.content.Context;
+import android.content.Intent;
+import android.content.IntentFilter;
+import android.content.res.Configuration;
+import android.graphics.Rect;
+import android.inputmethodservice.InputMethodService;
+import android.os.Build;
+import android.os.PatternMatcher;
+import android.os.RemoteException;
+import android.util.ArraySet;
+import android.util.Log;
+import android.view.Gravity;
+import android.view.View;
+import android.view.ViewGroup;
+import android.view.WindowInsets;
+import android.view.WindowInsets.Type.InsetsType;
+import android.view.WindowInsetsController;
+import android.view.WindowManager;
+import android.widget.Toast;
+
+import androidx.annotation.IdRes;
+import androidx.annotation.Nullable;
+import androidx.annotation.VisibleForTesting;
+
+import com.android.car.ui.FocusParkingView;
+import com.android.car.ui.utils.ViewUtils;
+import com.android.internal.statusbar.IStatusBarService;
+import com.android.internal.statusbar.LetterboxDetails;
+import com.android.internal.statusbar.RegisterStatusBarResult;
+import com.android.internal.view.AppearanceRegion;
+import com.android.systemui.R;
+import com.android.systemui.car.CarDeviceProvisionedController;
+import com.android.systemui.car.CarDeviceProvisionedListener;
+import com.android.systemui.car.displaycompat.ToolbarController;
+import com.android.systemui.car.hvac.HvacController;
+import com.android.systemui.car.hvac.HvacPanelController;
+import com.android.systemui.car.hvac.HvacPanelOverlayViewController;
+import com.android.systemui.car.keyguard.KeyguardSystemBarPresenter;
+import com.android.systemui.car.notification.NotificationPanelViewController;
+import com.android.systemui.car.notification.NotificationsShadeController;
+import com.android.systemui.car.statusicon.StatusIconPanelViewController;
+import com.android.systemui.car.users.CarSystemUIUserUtil;
+import com.android.systemui.dagger.SysUISingleton;
+import com.android.systemui.dagger.qualifiers.Main;
+import com.android.systemui.plugins.DarkIconDispatcher;
+import com.android.systemui.settings.DisplayTracker;
+import com.android.systemui.settings.UserTracker;
+import com.android.systemui.shared.statusbar.phone.BarTransitions;
+import com.android.systemui.shared.system.TaskStackChangeListener;
+import com.android.systemui.shared.system.TaskStackChangeListeners;
+import com.android.systemui.statusbar.AutoHideUiElement;
+import com.android.systemui.statusbar.CommandQueue;
+import com.android.systemui.statusbar.phone.AutoHideController;
+import com.android.systemui.statusbar.phone.LightBarController;
+import com.android.systemui.statusbar.phone.PhoneStatusBarPolicy;
+import com.android.systemui.statusbar.phone.SysuiDarkIconDispatcher;
+import com.android.systemui.statusbar.policy.ConfigurationController;
+import com.android.systemui.statusbar.policy.KeyguardStateController;
+import com.android.systemui.util.concurrency.DelayableExecutor;
+
+import dagger.Lazy;
+
+import java.util.ArrayList;
+import java.util.List;
+import java.util.Locale;
+import java.util.Set;
+
+import javax.inject.Provider;
+
+/** A single class which controls the system bar views. */
+@SysUISingleton
+public class CarSystemBarControllerImpl implements CarSystemBarController,
+        CommandQueue.Callbacks, ConfigurationController.ConfigurationListener,
+        KeyguardSystemBarPresenter {
+    private static final boolean DEBUG = Build.IS_ENG || Build.IS_USERDEBUG;
+
+    private static final String TAG = CarSystemBarController.class.getSimpleName();
+
+    private static final String OVERLAY_FILTER_DATA_SCHEME = "package";
+
+    private final Context mContext;
+    private final CarSystemBarViewFactory mCarSystemBarViewFactory;
+    private final ButtonSelectionStateController mButtonSelectionStateController;
+    private final ButtonRoleHolderController mButtonRoleHolderController;
+    private final Provider<StatusIconPanelViewController.Builder> mPanelControllerBuilderProvider;
+    private final Lazy<MicPrivacyChipViewController> mMicPrivacyChipViewControllerLazy;
+    private final Lazy<CameraPrivacyChipViewController> mCameraPrivacyChipViewControllerLazy;
+    private final SystemBarConfigs mSystemBarConfigs;
+    private final SysuiDarkIconDispatcher mStatusBarIconController;
+    private final WindowManager mWindowManager;
+    private final CarDeviceProvisionedController mCarDeviceProvisionedController;
+    private final CommandQueue mCommandQueue;
+    private final AutoHideController mAutoHideController;
+    private final ButtonSelectionStateListener mButtonSelectionStateListener;
+    private final DelayableExecutor mExecutor;
+    private final IStatusBarService mBarService;
+    private final DisplayTracker mDisplayTracker;
+    private final Lazy<KeyguardStateController> mKeyguardStateControllerLazy;
+    private final Lazy<PhoneStatusBarPolicy> mIconPolicyLazy;
+    private final HvacController mHvacController;
+    private final ConfigurationController mConfigurationController;
+    private final CarSystemBarRestartTracker mCarSystemBarRestartTracker;
+    private final int mDisplayId;
+    @Nullable
+    private final ToolbarController mDisplayCompatToolbarController;
+    private final Set<View.OnTouchListener> mTopBarTouchListeners = new ArraySet<>();
+    private final Set<View.OnTouchListener> mBottomBarTouchListeners = new ArraySet<>();
+    private final Set<View.OnTouchListener> mLeftBarTouchListeners = new ArraySet<>();
+    private final Set<View.OnTouchListener> mRightBarTouchListeners = new ArraySet<>();
+
+    protected final UserTracker mUserTracker;
+
+    private NotificationsShadeController mNotificationsShadeController;
+    private HvacPanelController mHvacPanelController;
+    private StatusIconPanelViewController mMicPanelController;
+    private StatusIconPanelViewController mCameraPanelController;
+    private StatusIconPanelViewController mProfilePanelController;
+    private HvacPanelOverlayViewController mHvacPanelOverlayViewController;
+    private NotificationPanelViewController mNotificationPanelViewController;
+
+    private int mPrivacyChipXOffset;
+    // Saved StatusBarManager.DisableFlags
+    private int mStatusBarState;
+    // Saved StatusBarManager.Disable2Flags
+    private int mStatusBarState2;
+    private int mLockTaskMode;
+
+    // If the nav bar should be hidden when the soft keyboard is visible.
+    private boolean mHideTopBarForKeyboard;
+    private boolean mHideLeftBarForKeyboard;
+    private boolean mHideRightBarForKeyboard;
+    private boolean mHideBottomBarForKeyboard;
+
+    // Nav bar views.
+    private ViewGroup mTopSystemBarWindow;
+    private ViewGroup mBottomSystemBarWindow;
+    private ViewGroup mLeftSystemBarWindow;
+    private ViewGroup mRightSystemBarWindow;
+    private CarSystemBarView mTopView;
+    private CarSystemBarView mBottomView;
+    private CarSystemBarView mLeftView;
+    private CarSystemBarView mRightView;
+    private boolean mTopSystemBarAttached;
+    private boolean mBottomSystemBarAttached;
+    private boolean mLeftSystemBarAttached;
+    private boolean mRightSystemBarAttached;
+    @IdRes
+    private int mTopFocusedViewId;
+    @IdRes
+    private int mBottomFocusedViewId;
+    @IdRes
+    private int mLeftFocusedViewId;
+    @IdRes
+    private int mRightFocusedViewId;
+    private boolean mShowTop;
+    private boolean mShowBottom;
+    private boolean mShowLeft;
+    private boolean mShowRight;
+
+    // To be attached to the navigation bars such that they can close the notification panel if
+    // it's open.
+    private boolean mDeviceIsSetUpForUser = true;
+    private boolean mIsUserSetupInProgress = false;
+
+    private AppearanceRegion[] mAppearanceRegions = new AppearanceRegion[0];
+    @BarTransitions.TransitionMode
+    private int mStatusBarMode;
+    @BarTransitions.TransitionMode
+    private int mSystemBarMode;
+    private boolean mStatusBarTransientShown;
+    private boolean mNavBarTransientShown;
+
+    private boolean mIsUiModeNight = false;
+
+    private Locale mCurrentLocale;
+
+    public CarSystemBarControllerImpl(Context context,
+            UserTracker userTracker,
+            CarSystemBarViewFactory carSystemBarViewFactory,
+            ButtonSelectionStateController buttonSelectionStateController,
+            Lazy<MicPrivacyChipViewController> micPrivacyChipViewControllerLazy,
+            Lazy<CameraPrivacyChipViewController> cameraPrivacyChipViewControllerLazy,
+            ButtonRoleHolderController buttonRoleHolderController,
+            SystemBarConfigs systemBarConfigs,
+            Provider<StatusIconPanelViewController.Builder> panelControllerBuilderProvider,
+            // TODO(b/156052638): Should not need to inject LightBarController
+            LightBarController lightBarController,
+            DarkIconDispatcher darkIconDispatcher,
+            WindowManager windowManager,
+            CarDeviceProvisionedController deviceProvisionedController,
+            CommandQueue commandQueue,
+            AutoHideController autoHideController,
+            ButtonSelectionStateListener buttonSelectionStateListener,
+            @Main DelayableExecutor mainExecutor,
+            IStatusBarService barService,
+            Lazy<KeyguardStateController> keyguardStateControllerLazy,
+            Lazy<PhoneStatusBarPolicy> iconPolicyLazy,
+            HvacController hvacController,
+            ConfigurationController configurationController,
+            CarSystemBarRestartTracker restartTracker,
+            DisplayTracker displayTracker,
+            @Nullable ToolbarController toolbarController) {
+        mContext = context;
+        mUserTracker = userTracker;
+        mCarSystemBarViewFactory = carSystemBarViewFactory;
+        mButtonSelectionStateController = buttonSelectionStateController;
+        mMicPrivacyChipViewControllerLazy = micPrivacyChipViewControllerLazy;
+        mCameraPrivacyChipViewControllerLazy = cameraPrivacyChipViewControllerLazy;
+        mButtonRoleHolderController = buttonRoleHolderController;
+        mPanelControllerBuilderProvider = panelControllerBuilderProvider;
+        mSystemBarConfigs = systemBarConfigs;
+        mStatusBarIconController = (SysuiDarkIconDispatcher) darkIconDispatcher;
+        mWindowManager = windowManager;
+        mCarDeviceProvisionedController = deviceProvisionedController;
+        mCommandQueue = commandQueue;
+        mAutoHideController = autoHideController;
+        mButtonSelectionStateListener = buttonSelectionStateListener;
+        mExecutor = mainExecutor;
+        mBarService = barService;
+        mKeyguardStateControllerLazy = keyguardStateControllerLazy;
+        mIconPolicyLazy = iconPolicyLazy;
+        mHvacController = hvacController;
+        mDisplayId = context.getDisplayId();
+        mDisplayTracker = displayTracker;
+        mIsUiModeNight = mContext.getResources().getConfiguration().isNightModeActive();
+        mCurrentLocale = mContext.getResources().getConfiguration().getLocales().get(0);
+        mConfigurationController = configurationController;
+        mCarSystemBarRestartTracker = restartTracker;
+        mDisplayCompatToolbarController = toolbarController;
+    }
+
+    /**
+     * Initializes the SystemBars
+     */
+    public void init() {
+
+        resetSystemBarConfigs();
+
+        mPrivacyChipXOffset = -mContext.getResources()
+                .getDimensionPixelOffset(R.dimen.privacy_chip_horizontal_padding);
+
+        // Set initial state.
+        mHideTopBarForKeyboard = mSystemBarConfigs.getHideForKeyboardBySide(TOP);
+        mHideBottomBarForKeyboard = mSystemBarConfigs.getHideForKeyboardBySide(BOTTOM);
+        mHideLeftBarForKeyboard = mSystemBarConfigs.getHideForKeyboardBySide(LEFT);
+        mHideRightBarForKeyboard = mSystemBarConfigs.getHideForKeyboardBySide(RIGHT);
+
+        // Connect into the status bar manager service
+        mCommandQueue.addCallback(this);
+
+        mAutoHideController.setStatusBar(new AutoHideUiElement() {
+            @Override
+            public void synchronizeState() {
+                // No op.
+            }
+
+            @Override
+            public boolean isVisible() {
+                return mStatusBarTransientShown;
+            }
+
+            @Override
+            public void hide() {
+                clearTransient();
+            }
+        });
+
+        mAutoHideController.setNavigationBar(new AutoHideUiElement() {
+            @Override
+            public void synchronizeState() {
+                // No op.
+            }
+
+            @Override
+            public boolean isVisible() {
+                return mNavBarTransientShown;
+            }
+
+            @Override
+            public void hide() {
+                clearTransient();
+            }
+        });
+
+        mDeviceIsSetUpForUser = mCarDeviceProvisionedController.isCurrentUserSetup();
+        mIsUserSetupInProgress = mCarDeviceProvisionedController.isCurrentUserSetupInProgress();
+        mCarDeviceProvisionedController.addCallback(
+                new CarDeviceProvisionedListener() {
+                    @Override
+                    public void onUserSetupInProgressChanged() {
+                        mExecutor.execute(() -> resetSystemBarContentIfNecessary());
+                    }
+
+                    @Override
+                    public void onUserSetupChanged() {
+                        mExecutor.execute(() -> resetSystemBarContentIfNecessary());
+                    }
+
+                    @Override
+                    public void onUserSwitched() {
+                        mExecutor.execute(() -> resetSystemBarContentIfNecessary());
+                    }
+                });
+
+        mConfigurationController.addCallback(/* listener= */ this);
+        registerOverlayChangeBroadcastReceiver();
+
+        createSystemBar();
+
+        TaskStackChangeListeners.getInstance().registerTaskStackListener(
+                mButtonSelectionStateListener);
+        TaskStackChangeListeners.getInstance().registerTaskStackListener(
+                new TaskStackChangeListener() {
+                    @Override
+                    public void onLockTaskModeChanged(int mode) {
+                        refreshSystemBar();
+                    }
+
+                    @Override
+                    public void onTaskMovedToFront(RunningTaskInfo taskInfo) {
+                        if (mDisplayCompatToolbarController != null) {
+                            mDisplayCompatToolbarController.update(taskInfo);
+                        }
+                    }
+                });
+
+        // Lastly, call to the icon policy to install/update all the icons.
+        // Must be called on the main thread due to the use of observeForever() in
+        // mIconPolicy.init().
+        mExecutor.execute(() -> {
+            mIconPolicyLazy.get().init();
+        });
+    }
+
+    /**
+     * We register for soft keyboard visibility events such that we can hide the navigation bar
+     * giving more screen space to the IME. Note: this is optional and controlled by
+     * {@code com.android.internal.R.bool.config_hideNavBarForKeyboard}.
+     */
+    @Override
+    public void setImeWindowStatus(int displayId, int visibility, int backDisposition,
+            boolean showImeSwitcher) {
+        if (mContext.getDisplayId() != displayId) {
+            return;
+        }
+
+        boolean isKeyboardVisible = (visibility & InputMethodService.IME_VISIBLE) != 0;
+
+        updateKeyboardVisibility(isKeyboardVisible);
+    }
+
+    @Override
+    public void onSystemBarAttributesChanged(
+            int displayId,
+            @WindowInsetsController.Appearance int appearance,
+            AppearanceRegion[] appearanceRegions,
+            boolean navbarColorManagedByIme,
+            @WindowInsetsController.Behavior int behavior,
+            @InsetsType int requestedVisibleTypes,
+            String packageName,
+            LetterboxDetails[] letterboxDetails) {
+        if (displayId != mDisplayId) {
+            return;
+        }
+        boolean barModeChanged = updateStatusBarMode(
+                mStatusBarTransientShown ? MODE_SEMI_TRANSPARENT : MODE_TRANSPARENT);
+        int numStacks = appearanceRegions.length;
+        boolean stackAppearancesChanged = mAppearanceRegions.length != numStacks;
+        for (int i = 0; i < numStacks && !stackAppearancesChanged; i++) {
+            stackAppearancesChanged |= !appearanceRegions[i].equals(mAppearanceRegions[i]);
+        }
+        if (stackAppearancesChanged || barModeChanged) {
+            mAppearanceRegions = appearanceRegions;
+            updateStatusBarAppearance();
+        }
+        refreshSystemBar();
+    }
+
+    @Override
+    public void disable(int displayId, @DisableFlags int state1, @Disable2Flags int state2,
+            boolean animate) {
+        if (displayId != mDisplayId) {
+            return;
+        }
+        setSystemBarStates(state1, state2);
+    }
+
+    @Override
+    public void showTransient(int displayId, int types, boolean isGestureOnSystemBar) {
+        if (displayId != mDisplayId) {
+            return;
+        }
+        if ((types & WindowInsets.Type.statusBars()) != 0) {
+            if (!mStatusBarTransientShown) {
+                mStatusBarTransientShown = true;
+                handleTransientChanged();
+            }
+        }
+        if ((types & WindowInsets.Type.navigationBars()) != 0) {
+            if (!mNavBarTransientShown) {
+                mNavBarTransientShown = true;
+                handleTransientChanged();
+            }
+        }
+    }
+
+    @Override
+    public void abortTransient(int displayId, int types) {
+        if (displayId != mDisplayId) {
+            return;
+        }
+        if ((types & (WindowInsets.Type.statusBars() | WindowInsets.Type.navigationBars())) == 0) {
+            return;
+        }
+        clearTransient();
+    }
+
+    @Override
+    public void onConfigChanged(Configuration newConfig) {
+        Locale oldLocale = mCurrentLocale;
+        mCurrentLocale = newConfig.getLocales().get(0);
+
+        boolean isConfigNightMode = newConfig.isNightModeActive();
+        if (isConfigNightMode == mIsUiModeNight
+                && ((mCurrentLocale != null && mCurrentLocale.equals(oldLocale))
+                || mCurrentLocale == oldLocale)) {
+            return;
+        }
+
+        // Refresh UI on Night mode or system language changes.
+        if (isConfigNightMode != mIsUiModeNight) {
+            mIsUiModeNight = isConfigNightMode;
+        }
+
+        // cache the current state
+        // The focused view will be destroyed during re-layout, causing the framework to adjust
+        // the focus unexpectedly. To avoid that, move focus to a view that won't be
+        // destroyed during re-layout and has no focus highlight (the FocusParkingView), then
+        // move focus back to the previously focused view after re-layout.
+        cacheAndHideFocus();
+        View profilePickerView = null;
+        boolean isProfilePickerOpen = false;
+        if (mTopView != null) {
+            profilePickerView = mTopView.findViewById(R.id.user_name);
+        }
+        if (profilePickerView != null) isProfilePickerOpen = profilePickerView.isSelected();
+        if (isProfilePickerOpen) {
+            profilePickerView.callOnClick();
+        }
+
+        resetSystemBarContent(/* isProvisionedStateChange= */ false);
+
+        // retrieve the previous state
+        if (isProfilePickerOpen) {
+            if (mTopView != null) {
+                profilePickerView = mTopView.findViewById(R.id.user_name);
+            }
+            if (profilePickerView != null) profilePickerView.callOnClick();
+        }
+
+        restoreFocus();
+    }
+
+    private void readConfigs() {
+        mShowTop = mSystemBarConfigs.getEnabledStatusBySide(TOP);
+        mShowBottom = mSystemBarConfigs.getEnabledStatusBySide(BOTTOM);
+        mShowLeft = mSystemBarConfigs.getEnabledStatusBySide(LEFT);
+        mShowRight = mSystemBarConfigs.getEnabledStatusBySide(RIGHT);
+    }
+
+    /**
+     * Hides all system bars.
+     */
+    public void hideBars() {
+        setTopWindowVisibility(View.GONE);
+        setBottomWindowVisibility(View.GONE);
+        setLeftWindowVisibility(View.GONE);
+        setRightWindowVisibility(View.GONE);
+    }
+
+    /**
+     * Shows all system bars.
+     */
+    public void showBars() {
+        setTopWindowVisibility(View.VISIBLE);
+        setBottomWindowVisibility(View.VISIBLE);
+        setLeftWindowVisibility(View.VISIBLE);
+        setRightWindowVisibility(View.VISIBLE);
+    }
+
+    /** Clean up */
+    public void removeAll() {
+        mButtonSelectionStateController.removeAll();
+        mButtonRoleHolderController.removeAll();
+        mMicPrivacyChipViewControllerLazy.get().removeAll();
+        mCameraPrivacyChipViewControllerLazy.get().removeAll();
+
+        mMicPanelController = null;
+        mCameraPanelController = null;
+        mProfilePanelController = null;
+    }
+
+    /** Gets the top window if configured to do so. */
+    @Nullable
+    public ViewGroup getTopWindow() {
+        return mShowTop ? mCarSystemBarViewFactory.getTopWindow() : null;
+    }
+
+    /** Gets the bottom window if configured to do so. */
+    @Nullable
+    public ViewGroup getBottomWindow() {
+        return mShowBottom ? mCarSystemBarViewFactory.getBottomWindow() : null;
+    }
+
+    /** Gets the left window if configured to do so. */
+    @Nullable
+    public ViewGroup getLeftWindow() {
+        return mShowLeft ? mCarSystemBarViewFactory.getLeftWindow() : null;
+    }
+
+    /** Gets the right window if configured to do so. */
+    @Nullable
+    public ViewGroup getRightWindow() {
+        return mShowRight ? mCarSystemBarViewFactory.getRightWindow() : null;
+    }
+
+    /** Toggles the top nav bar visibility. */
+    public boolean setTopWindowVisibility(@View.Visibility int visibility) {
+        return setWindowVisibility(getTopWindow(), visibility);
+    }
+
+    /** Toggles the bottom nav bar visibility. */
+    public boolean setBottomWindowVisibility(@View.Visibility int visibility) {
+        return setWindowVisibility(getBottomWindow(), visibility);
+    }
+
+    /** Toggles the left nav bar visibility. */
+    public boolean setLeftWindowVisibility(@View.Visibility int visibility) {
+        return setWindowVisibility(getLeftWindow(), visibility);
+    }
+
+    /** Toggles the right nav bar visibility. */
+    public boolean setRightWindowVisibility(@View.Visibility int visibility) {
+        return setWindowVisibility(getRightWindow(), visibility);
+    }
+
+    private boolean setWindowVisibility(ViewGroup window, @View.Visibility int visibility) {
+        if (window == null) {
+            return false;
+        }
+
+        if (window.getVisibility() == visibility) {
+            return false;
+        }
+
+        window.setVisibility(visibility);
+        return true;
+    }
+
+    /**
+     * Sets the system bar states - {@code StatusBarManager.DisableFlags},
+     * {@code StatusBarManager.Disable2Flags}, lock task mode. When there is a change in state,
+     * and refreshes the system bars.
+     *
+     * @param state {@code StatusBarManager.DisableFlags}
+     * @param state2 {@code StatusBarManager.Disable2Flags}
+     */
+    public void setSystemBarStates(int state, int state2) {
+        int diff = (state ^ mStatusBarState) | (state2 ^ mStatusBarState2);
+        int lockTaskMode = getLockTaskModeState();
+        if (diff == 0 && mLockTaskMode == lockTaskMode) {
+            if (DEBUG) {
+                Log.d(TAG, "setSystemBarStates(): status bar states unchanged: state: "
+                        + state + " state2: " +  state2 + " lockTaskMode: " + mLockTaskMode);
+            }
+            return;
+        }
+        mStatusBarState = state;
+        mStatusBarState2 = state2;
+        mLockTaskMode = lockTaskMode;
+        refreshSystemBar();
+    }
+
+    @VisibleForTesting
+    protected int getStatusBarState() {
+        return mStatusBarState;
+    }
+
+    @VisibleForTesting
+    protected int getStatusBarState2() {
+        return mStatusBarState2;
+    }
+
+    @VisibleForTesting
+    protected int getLockTaskMode() {
+        return mLockTaskMode;
+    }
+
+    /**
+     * Refreshes system bar views and sets the visibility of certain components based on
+     * {@link StatusBarManager} flags and lock task mode.
+     * <ul>
+     * <li>Home button will be disabled when {@code StatusBarManager.DISABLE_HOME} is set.
+     * <li>Phone call button will be disable in lock task mode.
+     * <li>App grid button will be disable when {@code StatusBarManager.DISABLE_HOME} is set.
+     * <li>Notification button will be disable when
+     * {@code StatusBarManager.DISABLE_NOTIFICATION_ICONS} is set.
+     * <li>Quick settings and user switcher will be hidden when in lock task mode or when
+     * {@code StatusBarManager.DISABLE2_QUICK_SETTINGS} is set.
+     * </ul>
+     */
+    public void refreshSystemBar() {
+        boolean homeDisabled = ((mStatusBarState & StatusBarManager.DISABLE_HOME) > 0);
+        boolean notificationDisabled =
+                ((mStatusBarState & StatusBarManager.DISABLE_NOTIFICATION_ICONS) > 0);
+        boolean locked = (mLockTaskMode == ActivityManager.LOCK_TASK_MODE_LOCKED);
+        boolean qcDisabled =
+                ((mStatusBarState2 & StatusBarManager.DISABLE2_QUICK_SETTINGS) > 0) || locked;
+        boolean systemIconsDisabled =
+                ((mStatusBarState2 & StatusBarManager.DISABLE2_SYSTEM_ICONS) > 0) || locked;
+
+        setDisabledSystemBarButton(R.id.home, homeDisabled, "home");
+        setDisabledSystemBarButton(R.id.passenger_home, homeDisabled, "passenger_home");
+        setDisabledSystemBarButton(R.id.phone_nav, locked, "phone_nav");
+        setDisabledSystemBarButton(R.id.grid_nav, homeDisabled, "grid_nav");
+        setDisabledSystemBarButton(R.id.notifications, notificationDisabled, "notifications");
+
+        if (DEBUG) {
+            Log.d(TAG, "refreshSystemBar: locked?: " + locked
+                    + " homeDisabled: " + homeDisabled
+                    + " notificationDisabled: " + notificationDisabled
+                    + " qcDisabled: " + qcDisabled
+                    + " systemIconsDisabled: " + systemIconsDisabled);
+        }
+    }
+
+    private int getLockTaskModeState() {
+        return mContext.getSystemService(ActivityManager.class).getLockTaskModeState();
+    }
+
+    private void setDisabledSystemBarButton(int viewId, boolean disabled,
+                @Nullable String buttonName) {
+        for (CarSystemBarView barView : getAllAvailableSystemBarViews()) {
+            barView.setDisabledSystemBarButton(viewId, disabled,
+                    () -> showAdminSupportDetailsDialog(), buttonName);
+        }
+    }
+
+    private void showAdminSupportDetailsDialog() {
+        // TODO(b/205891123): launch AdminSupportDetailsDialog after moving
+        // AdminSupportDetailsDialog out of CarSettings since CarSettings is not and should not
+        // be allowlisted for lock task mode.
+        Toast.makeText(mContext, "This action is unavailable for your profile",
+                Toast.LENGTH_LONG).show();
+    }
+
+    @Override
+    public boolean setBarVisibility(@SystemBarSide int side, @View.Visibility int visibility) {
+        switch (side) {
+            case BOTTOM:
+                return setBottomWindowVisibility(visibility);
+            case LEFT:
+                return setLeftWindowVisibility(visibility);
+            case RIGHT:
+                return setRightWindowVisibility(visibility);
+            case TOP:
+                return setTopWindowVisibility(visibility);
+            default:
+                return false;
+        }
+    }
+
+    @Override
+    @Nullable
+    public ViewGroup getBarWindow(@SystemBarSide int side) {
+        switch (side) {
+            case BOTTOM:
+                return getBottomWindow();
+            case LEFT:
+                return getLeftWindow();
+            case RIGHT:
+                return getRightWindow();
+            case TOP:
+                return getTopWindow();
+            default:
+                return null;
+        }
+    }
+
+    @Override
+    @Nullable
+    public CarSystemBarView getBarView(@SystemBarSide int side, boolean isSetUp) {
+        switch (side) {
+            case BOTTOM:
+                return getBottomBar(isSetUp);
+            case LEFT:
+                return getLeftBar(isSetUp);
+            case RIGHT:
+                return getRightBar(isSetUp);
+            case TOP:
+                return getTopBar(isSetUp);
+            default:
+                return null;
+        }
+    }
+
+    @Override
+    public void registerBarTouchListener(@SystemBarSide int side, View.OnTouchListener listener) {
+        switch (side) {
+            case BOTTOM:
+                registerBottomBarTouchListener(listener);
+                break;
+            case LEFT:
+                registerLeftBarTouchListener(listener);
+                break;
+            case RIGHT:
+                registerRightBarTouchListener(listener);
+                break;
+            case TOP:
+                registerTopBarTouchListener(listener);
+                break;
+            default:
+                break;
+        }
+    }
+
+    /** Gets the top navigation bar with the appropriate listeners set. */
+    @Nullable
+    public CarSystemBarView getTopBar(boolean isSetUp) {
+        if (!mShowTop) {
+            return null;
+        }
+
+        mTopView = mCarSystemBarViewFactory.getTopBar(isSetUp);
+        setupBar(mTopView, mTopBarTouchListeners, mNotificationsShadeController,
+                mHvacPanelController, mHvacPanelOverlayViewController,
+                mNotificationPanelViewController);
+
+        if (isSetUp) {
+            // We do not want the privacy chips or the profile picker to be clickable in
+            // unprovisioned mode.
+            mMicPanelController = setupSensorQcPanel(mMicPanelController, R.id.mic_privacy_chip,
+                    R.layout.qc_mic_panel);
+            mCameraPanelController = setupSensorQcPanel(mCameraPanelController,
+                    R.id.camera_privacy_chip, R.layout.qc_camera_panel);
+            setupProfilePanel();
+        }
+
+        return mTopView;
+    }
+
+    /** Gets the bottom navigation bar with the appropriate listeners set. */
+    @Nullable
+    public CarSystemBarView getBottomBar(boolean isSetUp) {
+        if (!mShowBottom) {
+            return null;
+        }
+
+        mBottomView = mCarSystemBarViewFactory.getBottomBar(isSetUp);
+        setupBar(mBottomView, mBottomBarTouchListeners, mNotificationsShadeController,
+                mHvacPanelController, mHvacPanelOverlayViewController,
+                mNotificationPanelViewController);
+
+        return mBottomView;
+    }
+
+    /** Gets the left navigation bar with the appropriate listeners set. */
+    @Nullable
+    public CarSystemBarView getLeftBar(boolean isSetUp) {
+        if (!mShowLeft) {
+            return null;
+        }
+
+        mLeftView = mCarSystemBarViewFactory.getLeftBar(isSetUp);
+        setupBar(mLeftView, mLeftBarTouchListeners, mNotificationsShadeController,
+                mHvacPanelController, mHvacPanelOverlayViewController,
+                mNotificationPanelViewController);
+        return mLeftView;
+    }
+
+    /** Gets the right navigation bar with the appropriate listeners set. */
+    @Nullable
+    public CarSystemBarView getRightBar(boolean isSetUp) {
+        if (!mShowRight) {
+            return null;
+        }
+
+        mRightView = mCarSystemBarViewFactory.getRightBar(isSetUp);
+        setupBar(mRightView, mRightBarTouchListeners, mNotificationsShadeController,
+                mHvacPanelController, mHvacPanelOverlayViewController,
+                mNotificationPanelViewController);
+        return mRightView;
+    }
+
+    private void setupBar(CarSystemBarView view, Set<View.OnTouchListener> statusBarTouchListeners,
+            NotificationsShadeController notifShadeController,
+            HvacPanelController hvacPanelController,
+            HvacPanelOverlayViewController hvacPanelOverlayViewController,
+            NotificationPanelViewController notificationPanelViewController) {
+        view.updateHomeButtonVisibility(CarSystemUIUserUtil.isSecondaryMUMDSystemUI());
+        view.setStatusBarWindowTouchListeners(statusBarTouchListeners);
+        view.setNotificationsPanelController(notifShadeController);
+        view.registerNotificationPanelViewController(notificationPanelViewController);
+        view.setHvacPanelController(hvacPanelController);
+        view.registerHvacPanelOverlayViewController(hvacPanelOverlayViewController);
+        view.updateControlCenterButtonVisibility(CarSystemUIUserUtil.isMUMDSystemUI());
+        mButtonSelectionStateController.addAllButtonsWithSelectionState(view);
+        mButtonRoleHolderController.addAllButtonsWithRoleName(view);
+        mMicPrivacyChipViewControllerLazy.get().addPrivacyChipView(view);
+        mCameraPrivacyChipViewControllerLazy.get().addPrivacyChipView(view);
+    }
+
+    private StatusIconPanelViewController setupSensorQcPanel(
+            @Nullable StatusIconPanelViewController panelController, int chipId,
+            @LayoutRes int panelLayoutRes) {
+        if (panelController == null) {
+            View privacyChip = mTopView.findViewById(chipId);
+            if (privacyChip != null) {
+                panelController = mPanelControllerBuilderProvider.get()
+                        .setXOffset(mPrivacyChipXOffset)
+                        .setGravity(Gravity.TOP | Gravity.END)
+                        .build(privacyChip, panelLayoutRes, R.dimen.car_sensor_qc_panel_width);
+                panelController.init();
+            }
+        }
+        return panelController;
+    }
+
+    private void setupProfilePanel() {
+        View profilePickerView = mTopView.findViewById(R.id.user_name);
+        if (mProfilePanelController == null && profilePickerView != null) {
+            boolean profilePanelDisabledWhileDriving = mContext.getResources().getBoolean(
+                    R.bool.config_profile_panel_disabled_while_driving);
+            mProfilePanelController = mPanelControllerBuilderProvider.get()
+                    .setGravity(Gravity.TOP | Gravity.END)
+                    .setDisabledWhileDriving(profilePanelDisabledWhileDriving)
+                    .build(profilePickerView, R.layout.qc_profile_switcher,
+                            R.dimen.car_profile_quick_controls_panel_width);
+            mProfilePanelController.init();
+        }
+    }
+
+    /** Sets a touch listener for the top navigation bar. */
+    public void registerTopBarTouchListener(View.OnTouchListener listener) {
+        boolean setModified = mTopBarTouchListeners.add(listener);
+        if (setModified && mTopView != null) {
+            mTopView.setStatusBarWindowTouchListeners(mTopBarTouchListeners);
+        }
+    }
+
+    /** Sets a touch listener for the bottom navigation bar. */
+    public void registerBottomBarTouchListener(View.OnTouchListener listener) {
+        boolean setModified = mBottomBarTouchListeners.add(listener);
+        if (setModified && mBottomView != null) {
+            mBottomView.setStatusBarWindowTouchListeners(mBottomBarTouchListeners);
+        }
+    }
+
+    /** Sets a touch listener for the left navigation bar. */
+    public void registerLeftBarTouchListener(View.OnTouchListener listener) {
+        boolean setModified = mLeftBarTouchListeners.add(listener);
+        if (setModified && mLeftView != null) {
+            mLeftView.setStatusBarWindowTouchListeners(mLeftBarTouchListeners);
+        }
+    }
+
+    /** Sets a touch listener for the right navigation bar. */
+    public void registerRightBarTouchListener(View.OnTouchListener listener) {
+        boolean setModified = mRightBarTouchListeners.add(listener);
+        if (setModified && mRightView != null) {
+            mRightView.setStatusBarWindowTouchListeners(mRightBarTouchListeners);
+        }
+    }
+
+    /** Sets a notification controller which toggles the notification panel. */
+    public void registerNotificationController(
+            NotificationsShadeController notificationsShadeController) {
+        mNotificationsShadeController = notificationsShadeController;
+        if (mTopView != null) {
+            mTopView.setNotificationsPanelController(mNotificationsShadeController);
+        }
+        if (mBottomView != null) {
+            mBottomView.setNotificationsPanelController(mNotificationsShadeController);
+        }
+        if (mLeftView != null) {
+            mLeftView.setNotificationsPanelController(mNotificationsShadeController);
+        }
+        if (mRightView != null) {
+            mRightView.setNotificationsPanelController(mNotificationsShadeController);
+        }
+    }
+
+    /** Sets the NotificationPanelViewController for views to listen to the panel's state. */
+    public void registerNotificationPanelViewController(
+            NotificationPanelViewController notificationPanelViewController) {
+        mNotificationPanelViewController = notificationPanelViewController;
+        if (mTopView != null) {
+            mTopView.registerNotificationPanelViewController(mNotificationPanelViewController);
+        }
+        if (mBottomView != null) {
+            mBottomView.registerNotificationPanelViewController(mNotificationPanelViewController);
+        }
+        if (mLeftView != null) {
+            mLeftView.registerNotificationPanelViewController(mNotificationPanelViewController);
+        }
+        if (mRightView != null) {
+            mRightView.registerNotificationPanelViewController(mNotificationPanelViewController);
+        }
+    }
+
+    /** Sets an HVAC controller which toggles the HVAC panel. */
+    public void registerHvacPanelController(HvacPanelController hvacPanelController) {
+        mHvacPanelController = hvacPanelController;
+        if (mTopView != null) {
+            mTopView.setHvacPanelController(mHvacPanelController);
+        }
+        if (mBottomView != null) {
+            mBottomView.setHvacPanelController(mHvacPanelController);
+        }
+        if (mLeftView != null) {
+            mLeftView.setHvacPanelController(mHvacPanelController);
+        }
+        if (mRightView != null) {
+            mRightView.setHvacPanelController(mHvacPanelController);
+        }
+    }
+
+    /** Sets the HVACPanelOverlayViewController for views to listen to the panel's state. */
+    public void registerHvacPanelOverlayViewController(
+            HvacPanelOverlayViewController hvacPanelOverlayViewController) {
+        mHvacPanelOverlayViewController = hvacPanelOverlayViewController;
+        if (mTopView != null) {
+            mTopView.registerHvacPanelOverlayViewController(mHvacPanelOverlayViewController);
+        }
+        if (mBottomView != null) {
+            mBottomView.registerHvacPanelOverlayViewController(mHvacPanelOverlayViewController);
+        }
+        if (mLeftView != null) {
+            mLeftView.registerHvacPanelOverlayViewController(mHvacPanelOverlayViewController);
+        }
+        if (mRightView != null) {
+            mRightView.registerHvacPanelOverlayViewController(mHvacPanelOverlayViewController);
+        }
+    }
+
+    /**
+     * Shows all of the navigation buttons on the valid instances of {@link CarSystemBarView}.
+     */
+    @Override
+    public void showAllNavigationButtons() {
+        showAllNavigationButtons(true);
+    }
+
+    // TODO(b/368407601): can we remove this?
+    protected void showAllNavigationButtons(boolean isSetup) {
+        checkAllBars(isSetup);
+        if (mTopView != null) {
+            mTopView.showButtonsOfType(CarSystemBarView.BUTTON_TYPE_NAVIGATION);
+        }
+        if (mBottomView != null) {
+            mBottomView.showButtonsOfType(CarSystemBarView.BUTTON_TYPE_NAVIGATION);
+        }
+        if (mLeftView != null) {
+            mLeftView.showButtonsOfType(CarSystemBarView.BUTTON_TYPE_NAVIGATION);
+        }
+        if (mRightView != null) {
+            mRightView.showButtonsOfType(CarSystemBarView.BUTTON_TYPE_NAVIGATION);
+        }
+    }
+
+    /**
+     * Shows all of the keyguard specific buttons on the valid instances of
+     * {@link CarSystemBarView}.
+     */
+    @Override
+    public void showAllKeyguardButtons() {
+        showAllKeyguardButtons(true);
+    }
+
+    @VisibleForTesting
+    // TODO(b/368407601): can we remove this?
+    protected void showAllKeyguardButtons(boolean isSetUp) {
+        checkAllBars(isSetUp);
+        if (mTopView != null) {
+            mTopView.showButtonsOfType(CarSystemBarView.BUTTON_TYPE_KEYGUARD);
+        }
+        if (mBottomView != null) {
+            mBottomView.showButtonsOfType(CarSystemBarView.BUTTON_TYPE_KEYGUARD);
+        }
+        if (mLeftView != null) {
+            mLeftView.showButtonsOfType(CarSystemBarView.BUTTON_TYPE_KEYGUARD);
+        }
+        if (mRightView != null) {
+            mRightView.showButtonsOfType(CarSystemBarView.BUTTON_TYPE_KEYGUARD);
+        }
+    }
+
+    /**
+     * Shows all of the occlusion state buttons on the valid instances of
+     * {@link CarSystemBarView}.
+     */
+    @Override
+    public void showAllOcclusionButtons() {
+        showAllOcclusionButtons(true);
+    }
+
+    // TODO(b/368407601): can we remove this?
+    protected void showAllOcclusionButtons(boolean isSetUp) {
+        checkAllBars(isSetUp);
+        if (mTopView != null) {
+            mTopView.showButtonsOfType(CarSystemBarView.BUTTON_TYPE_OCCLUSION);
+        }
+        if (mBottomView != null) {
+            mBottomView.showButtonsOfType(CarSystemBarView.BUTTON_TYPE_OCCLUSION);
+        }
+        if (mLeftView != null) {
+            mLeftView.showButtonsOfType(CarSystemBarView.BUTTON_TYPE_OCCLUSION);
+        }
+        if (mRightView != null) {
+            mRightView.showButtonsOfType(CarSystemBarView.BUTTON_TYPE_OCCLUSION);
+        }
+    }
+
+    /** Toggles whether the notifications icon has an unseen indicator or not. */
+    public void toggleAllNotificationsUnseenIndicator(boolean isSetUp, boolean hasUnseen) {
+        checkAllBars(isSetUp);
+        if (mTopView != null) {
+            mTopView.toggleNotificationUnseenIndicator(hasUnseen);
+        }
+        if (mBottomView != null) {
+            mBottomView.toggleNotificationUnseenIndicator(hasUnseen);
+        }
+        if (mLeftView != null) {
+            mLeftView.toggleNotificationUnseenIndicator(hasUnseen);
+        }
+        if (mRightView != null) {
+            mRightView.toggleNotificationUnseenIndicator(hasUnseen);
+        }
+    }
+
+    private void checkAllBars(boolean isSetUp) {
+        mTopView = getTopBar(isSetUp);
+        mBottomView = getBottomBar(isSetUp);
+        mLeftView = getLeftBar(isSetUp);
+        mRightView = getRightBar(isSetUp);
+    }
+
+    private List<CarSystemBarView> getAllAvailableSystemBarViews() {
+        List<CarSystemBarView> barViews = new ArrayList<>();
+        if (mTopView != null) {
+            barViews.add(mTopView);
+        }
+        if (mBottomView != null) {
+            barViews.add(mBottomView);
+        }
+        if (mLeftView != null) {
+            barViews.add(mLeftView);
+        }
+        if (mRightView != null) {
+            barViews.add(mRightView);
+        }
+        return barViews;
+    }
+
+    /** Resets the cached Views. */
+    protected void resetViewCache() {
+        mCarSystemBarViewFactory.resetSystemBarViewCache();
+    }
+
+    /**
+     * Invalidate SystemBarConfigs and fetch again from Resources.
+     * TODO(): b/260206944, Can remove this after we have a fix for overlaid resources not applied.
+     */
+    protected void resetSystemBarConfigs() {
+        mSystemBarConfigs.resetSystemBarConfigs();
+        mCarSystemBarViewFactory.resetSystemBarWindowCache();
+        readConfigs();
+    }
+
+    /** Stores the ID of the View that is currently focused and hides the focus. */
+    protected void cacheAndHideFocus() {
+        mTopFocusedViewId = cacheAndHideFocus(mTopView);
+        if (mTopFocusedViewId != View.NO_ID) return;
+        mBottomFocusedViewId = cacheAndHideFocus(mBottomView);
+        if (mBottomFocusedViewId != View.NO_ID) return;
+        mLeftFocusedViewId = cacheAndHideFocus(mLeftView);
+        if (mLeftFocusedViewId != View.NO_ID) return;
+        mRightFocusedViewId = cacheAndHideFocus(mRightView);
+    }
+
+    @VisibleForTesting
+    int cacheAndHideFocus(@Nullable View rootView) {
+        if (rootView == null) return View.NO_ID;
+        View focusedView = rootView.findFocus();
+        if (focusedView == null || focusedView instanceof FocusParkingView) return View.NO_ID;
+        int focusedViewId = focusedView.getId();
+        ViewUtils.hideFocus(rootView);
+        return focusedViewId;
+    }
+
+    /** Requests focus on the View that matches the cached ID. */
+    protected void restoreFocus() {
+        if (restoreFocus(mTopView, mTopFocusedViewId)) return;
+        if (restoreFocus(mBottomView, mBottomFocusedViewId)) return;
+        if (restoreFocus(mLeftView, mLeftFocusedViewId)) return;
+        restoreFocus(mRightView, mRightFocusedViewId);
+    }
+
+    private boolean restoreFocus(@Nullable View rootView, @IdRes int viewToFocusId) {
+        if (rootView == null || viewToFocusId == View.NO_ID) return false;
+        View focusedView = rootView.findViewById(viewToFocusId);
+        if (focusedView == null) return false;
+        focusedView.requestFocus();
+        return true;
+    }
+
+    protected void updateKeyboardVisibility(boolean isKeyboardVisible) {
+        if (mHideTopBarForKeyboard) {
+            setTopWindowVisibility(isKeyboardVisible ? View.GONE : View.VISIBLE);
+        }
+
+        if (mHideBottomBarForKeyboard) {
+            setBottomWindowVisibility(isKeyboardVisible ? View.GONE : View.VISIBLE);
+        }
+
+        if (mHideLeftBarForKeyboard) {
+            setLeftWindowVisibility(isKeyboardVisible ? View.GONE : View.VISIBLE);
+        }
+        if (mHideRightBarForKeyboard) {
+            setRightWindowVisibility(isKeyboardVisible ? View.GONE : View.VISIBLE);
+        }
+    }
+
+    protected void createSystemBar() {
+        RegisterStatusBarResult result = null;
+        try {
+            // Register only for Primary User.
+            result = mBarService.registerStatusBar(mCommandQueue);
+
+            onSystemBarAttributesChanged(mDisplayId, result.mAppearance, result.mAppearanceRegions,
+                    result.mNavbarColorManagedByIme, result.mBehavior,
+                    result.mRequestedVisibleTypes,
+                    result.mPackageName, result.mLetterboxDetails);
+
+            setImeWindowStatus(mDisplayId, result.mImeWindowVis, result.mImeBackDisposition,
+                    result.mShowImeSwitcher);
+
+            // Set up the initial icon state
+            int numIcons = result.mIcons.size();
+            for (int i = 0; i < numIcons; i++) {
+                mCommandQueue.setIcon(result.mIcons.keyAt(i), result.mIcons.valueAt(i));
+            }
+        } catch (RemoteException ex) {
+            ex.rethrowFromSystemServer();
+        }
+
+        // Try setting up the initial state of the nav bar if applicable.
+        if (result != null) {
+            setImeWindowStatus(mDisplayTracker.getDefaultDisplayId(), result.mImeWindowVis,
+                    result.mImeBackDisposition, result.mShowImeSwitcher);
+        }
+
+        createNavBar();
+    }
+
+    protected void createNavBar() {
+        buildNavBarWindows();
+        buildNavBarContent();
+        attachNavBarWindows();
+    }
+
+    private void buildNavBarWindows() {
+        mTopSystemBarWindow = getTopWindow();
+        mBottomSystemBarWindow = getBottomWindow();
+        mLeftSystemBarWindow = getLeftWindow();
+        mRightSystemBarWindow = getRightWindow();
+
+        if (mDisplayCompatToolbarController != null) {
+            if (mSystemBarConfigs
+                    .isLeftDisplayCompatToolbarEnabled()) {
+                mDisplayCompatToolbarController.init(mLeftSystemBarWindow);
+            } else if (mSystemBarConfigs
+                    .isRightDisplayCompatToolbarEnabled()) {
+                mDisplayCompatToolbarController.init(mRightSystemBarWindow);
+            }
+        }
+    }
+
+    private void buildNavBarContent() {
+        mTopView = getTopBar(isDeviceSetupForUser());
+        if (mTopView != null) {
+            mSystemBarConfigs.insetSystemBar(TOP, mTopView);
+            mHvacController.registerHvacViews(mTopView);
+            mTopSystemBarWindow.addView(mTopView);
+        }
+
+        mBottomView = getBottomBar(isDeviceSetupForUser());
+        if (mBottomView != null) {
+            mSystemBarConfigs.insetSystemBar(BOTTOM, mBottomView);
+            mHvacController.registerHvacViews(mBottomView);
+            mBottomSystemBarWindow.addView(mBottomView);
+        }
+
+        mLeftView = getLeftBar(isDeviceSetupForUser());
+        if (mLeftView != null) {
+            mSystemBarConfigs.insetSystemBar(LEFT, mLeftView);
+            mHvacController.registerHvacViews(mLeftView);
+            mLeftSystemBarWindow.addView(mLeftView);
+        }
+
+        mRightView = getRightBar(isDeviceSetupForUser());
+        if (mRightView != null) {
+            mSystemBarConfigs.insetSystemBar(RIGHT, mRightView);
+            mHvacController.registerHvacViews(mRightView);
+            mRightSystemBarWindow.addView(mRightView);
+        }
+    }
+
+    private void attachNavBarWindows() {
+        mSystemBarConfigs.getSystemBarSidesByZOrder().forEach(this::attachNavBarBySide);
+    }
+
+    @VisibleForTesting
+    ViewGroup getSystemBarWindowBySide(int side) {
+        switch (side) {
+            case TOP:
+                return mTopSystemBarWindow;
+            case BOTTOM:
+                return mBottomSystemBarWindow;
+            case LEFT:
+                return mLeftSystemBarWindow;
+            case RIGHT:
+                return mRightSystemBarWindow;
+            default:
+                return null;
+        }
+    }
+
+    private void attachNavBarBySide(int side) {
+        switch (side) {
+            case TOP:
+                if (DEBUG) {
+                    Log.d(TAG, "mTopSystemBarWindow = " + mTopSystemBarWindow
+                            + ", mTopSystemBarAttached=" + mTopSystemBarAttached
+                            + ", enabled=" + mSystemBarConfigs.getEnabledStatusBySide(TOP));
+                }
+                if (mTopSystemBarWindow != null && !mTopSystemBarAttached
+                        && mSystemBarConfigs.getEnabledStatusBySide(TOP)) {
+                    mWindowManager.addView(mTopSystemBarWindow,
+                            mSystemBarConfigs.getLayoutParamsBySide(TOP));
+                    mTopSystemBarAttached = true;
+                }
+                break;
+            case BOTTOM:
+                if (DEBUG) {
+                    Log.d(TAG, "mBottomSystemBarWindow = " + mBottomSystemBarWindow
+                            + ", mBottomSystemBarAttached=" + mBottomSystemBarAttached
+                            + ", enabled=" + mSystemBarConfigs.getEnabledStatusBySide(BOTTOM));
+                }
+                if (mBottomSystemBarWindow != null && !mBottomSystemBarAttached
+                        && mSystemBarConfigs.getEnabledStatusBySide(BOTTOM)) {
+                    mWindowManager.addView(mBottomSystemBarWindow,
+                            mSystemBarConfigs.getLayoutParamsBySide(BOTTOM));
+                    mBottomSystemBarAttached = true;
+                }
+                break;
+            case LEFT:
+                if (DEBUG) {
+                    Log.d(TAG, "mLeftSystemBarWindow = " + mLeftSystemBarWindow
+                            + ", mLeftSystemBarAttached=" + mLeftSystemBarAttached
+                            + ", enabled=" + mSystemBarConfigs.getEnabledStatusBySide(LEFT));
+                }
+                if (mLeftSystemBarWindow != null && !mLeftSystemBarAttached
+                        && mSystemBarConfigs.getEnabledStatusBySide(LEFT)) {
+                    mWindowManager.addView(mLeftSystemBarWindow,
+                            mSystemBarConfigs.getLayoutParamsBySide(LEFT));
+                    mLeftSystemBarAttached = true;
+                }
+                break;
+            case RIGHT:
+                if (DEBUG) {
+                    Log.d(TAG, "mRightSystemBarWindow = " + mRightSystemBarWindow
+                            + ", mRightSystemBarAttached=" + mRightSystemBarAttached
+                            + ", "
+                            + "enabled=" + mSystemBarConfigs.getEnabledStatusBySide(RIGHT));
+                }
+                if (mRightSystemBarWindow != null && !mRightSystemBarAttached
+                        && mSystemBarConfigs.getEnabledStatusBySide(RIGHT)) {
+                    mWindowManager.addView(mRightSystemBarWindow,
+                            mSystemBarConfigs.getLayoutParamsBySide(RIGHT));
+                    mRightSystemBarAttached = true;
+                }
+                break;
+            default:
+                return;
+        }
+    }
+
+    private void registerOverlayChangeBroadcastReceiver() {
+        if (!configAwareSystemui()) {
+            if (DEBUG) {
+                Log.d(TAG, "Ignore overlay change for car systemui");
+            }
+            return;
+        }
+        IntentFilter overlayFilter = new IntentFilter(ACTION_OVERLAY_CHANGED);
+        overlayFilter.addDataScheme(OVERLAY_FILTER_DATA_SCHEME);
+        overlayFilter.addDataSchemeSpecificPart(mContext.getPackageName(),
+                PatternMatcher.PATTERN_LITERAL);
+        BroadcastReceiver receiver = new BroadcastReceiver() {
+            @Override
+            public void onReceive(Context context, Intent intent) {
+                if (mTopSystemBarAttached || mBottomSystemBarAttached || mLeftSystemBarAttached
+                        || mRightSystemBarAttached) {
+                    restartSystemBars();
+                }
+            }
+        };
+        mContext.registerReceiver(receiver, overlayFilter, /* broadcastPermission= */
+                null, /* handler= */ null);
+    }
+
+    private void resetSystemBarContentIfNecessary() {
+        boolean currentUserSetup = mCarDeviceProvisionedController.isCurrentUserSetup();
+        boolean currentUserSetupInProgress = mCarDeviceProvisionedController
+                .isCurrentUserSetupInProgress();
+        if (mIsUserSetupInProgress != currentUserSetupInProgress
+                || mDeviceIsSetUpForUser != currentUserSetup) {
+            mDeviceIsSetUpForUser = currentUserSetup;
+            mIsUserSetupInProgress = currentUserSetupInProgress;
+            resetSystemBarContent(/* isProvisionedStateChange= */ true);
+        }
+    }
+
+    /**
+     * Remove all content from navbars and rebuild them. Used to allow for different nav bars
+     * before and after the device is provisioned. . Also for change of density and font size.
+     */
+    private void resetSystemBarContent(boolean isProvisionedStateChange) {
+        mCarSystemBarRestartTracker.notifyPendingRestart(/* recreateWindows= */ false,
+                isProvisionedStateChange);
+
+        if (!isProvisionedStateChange) {
+            resetViewCache();
+        }
+        // remove and reattach all components such that we don't keep a reference to unused ui
+        // elements
+        removeAll();
+        clearSystemBarWindow(/* removeUnusedWindow= */ false);
+
+        buildNavBarContent();
+        // If the UI was rebuilt (day/night change or user change) while the keyguard was up we need
+        // to correctly respect that state.
+        if (mKeyguardStateControllerLazy.get().isShowing()) {
+            showAllKeyguardButtons(isDeviceSetupForUser());
+        } else {
+            showAllNavigationButtons(isDeviceSetupForUser());
+        }
+
+        // Upon restarting the Navigation Bar, CarFacetButtonController should immediately apply the
+        // selection state that reflects the current task stack.
+        mButtonSelectionStateListener.onTaskStackChanged();
+
+        mCarSystemBarRestartTracker.notifyRestartComplete(/* windowRecreated= */ false,
+                isProvisionedStateChange);
+    }
+
+    private boolean isDeviceSetupForUser() {
+        return mDeviceIsSetUpForUser && !mIsUserSetupInProgress;
+    }
+
+    private void updateStatusBarAppearance() {
+        int numStacks = mAppearanceRegions.length;
+        final ArrayList<Rect> lightBarBounds = new ArrayList<>();
+
+        for (int i = 0; i < numStacks; i++) {
+            final AppearanceRegion ar = mAppearanceRegions[i];
+            if (isLight(ar.getAppearance())) {
+                lightBarBounds.add(ar.getBounds());
+            }
+        }
+
+        // If all stacks are light, all icons become dark.
+        if (lightBarBounds.size() == numStacks) {
+            mStatusBarIconController.setIconsDarkArea(null);
+            mStatusBarIconController.getTransitionsController().setIconsDark(
+                    /* dark= */ true, /* animate= */ false);
+        } else if (lightBarBounds.isEmpty()) {
+            // If no one is light, all icons become white.
+            mStatusBarIconController.getTransitionsController().setIconsDark(
+                    /* dark= */ false, /* animate= */ false);
+        } else {
+            // Not the same for every stack, update icons in area only.
+            mStatusBarIconController.setIconsDarkArea(lightBarBounds);
+            mStatusBarIconController.getTransitionsController().setIconsDark(
+                    /* dark= */ true, /* animate= */ false);
+        }
+    }
+
+    private static boolean isLight(int appearance) {
+        return (appearance & APPEARANCE_LIGHT_STATUS_BARS) != 0;
+    }
+
+    private void handleTransientChanged() {
+        updateStatusBarMode(mStatusBarTransientShown ? MODE_SEMI_TRANSPARENT : MODE_TRANSPARENT);
+        updateNavBarMode(mNavBarTransientShown ? MODE_SEMI_TRANSPARENT : MODE_TRANSPARENT);
+    }
+
+    // Returns true if the status bar mode has changed.
+    private boolean updateStatusBarMode(int barMode) {
+        if (mStatusBarMode != barMode) {
+            mStatusBarMode = barMode;
+            mAutoHideController.touchAutoHide();
+            return true;
+        }
+        return false;
+    }
+
+    // Returns true if the nav bar mode has changed.
+    private boolean updateNavBarMode(int barMode) {
+        if (mSystemBarMode != barMode) {
+            mSystemBarMode = barMode;
+            mAutoHideController.touchAutoHide();
+            return true;
+        }
+        return false;
+    }
+
+    @VisibleForTesting
+    void restartSystemBars() {
+        mCarSystemBarRestartTracker.notifyPendingRestart(/* recreateWindows= */ true,
+                /* provisionedStateChanged= */ false);
+
+        removeAll();
+        resetSystemBarConfigs();
+        clearSystemBarWindow(/* removeUnusedWindow= */ true);
+        buildNavBarWindows();
+        buildNavBarContent();
+        attachNavBarWindows();
+
+        mCarSystemBarRestartTracker.notifyRestartComplete(/* windowRecreated= */ true,
+                /* provisionedStateChanged= */ false);
+    }
+
+    private void clearSystemBarWindow(boolean removeUnusedWindow) {
+        if (mTopSystemBarWindow != null) {
+            mTopSystemBarWindow.removeAllViews();
+            mHvacController.unregisterViews(mTopView);
+            if (removeUnusedWindow) {
+                mWindowManager.removeViewImmediate(mTopSystemBarWindow);
+                mTopSystemBarAttached = false;
+            }
+            mTopView = null;
+        }
+
+        if (mBottomSystemBarWindow != null) {
+            mBottomSystemBarWindow.removeAllViews();
+            mHvacController.unregisterViews(mBottomView);
+            if (removeUnusedWindow) {
+                mWindowManager.removeViewImmediate(mBottomSystemBarWindow);
+                mBottomSystemBarAttached = false;
+            }
+            mBottomView = null;
+        }
+
+        if (mLeftSystemBarWindow != null) {
+            mLeftSystemBarWindow.removeAllViews();
+            mHvacController.unregisterViews(mLeftView);
+            if (removeUnusedWindow) {
+                mWindowManager.removeViewImmediate(mLeftSystemBarWindow);
+                mLeftSystemBarAttached = false;
+            }
+            mLeftView = null;
+        }
+
+        if (mRightSystemBarWindow != null) {
+            mRightSystemBarWindow.removeAllViews();
+            mHvacController.unregisterViews(mRightView);
+            if (removeUnusedWindow) {
+                mWindowManager.removeViewImmediate(mRightSystemBarWindow);
+                mRightSystemBarAttached = false;
+            }
+            mRightView = null;
+        }
+    }
+
+    @VisibleForTesting
+    boolean getIsUiModeNight() {
+        return mIsUiModeNight;
+    }
+
+    private void clearTransient() {
+        if (mStatusBarTransientShown) {
+            mStatusBarTransientShown = false;
+            handleTransientChanged();
+        }
+        if (mNavBarTransientShown) {
+            mNavBarTransientShown = false;
+            handleTransientChanged();
+        }
+    }
+
+    @VisibleForTesting
+    boolean isStatusBarTransientShown() {
+        return mStatusBarTransientShown;
+    }
+
+    @VisibleForTesting
+    boolean isNavBarTransientShown() {
+        return mNavBarTransientShown;
+    }
+}
diff --git a/src/com/android/systemui/car/systembar/CarSystemBarMediator.java b/src/com/android/systemui/car/systembar/CarSystemBarMediator.java
deleted file mode 100644
index 13e7fa6a..00000000
--- a/src/com/android/systemui/car/systembar/CarSystemBarMediator.java
+++ /dev/null
@@ -1,107 +0,0 @@
-/*
- * Copyright (C) 2022 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-package com.android.systemui.car.systembar;
-
-import android.content.Context;
-import android.content.om.OverlayManager;
-import android.content.res.Configuration;
-import android.os.Build;
-import android.os.UserHandle;
-import android.util.Log;
-
-import com.android.systemui.CoreStartable;
-import com.android.systemui.R;
-import com.android.systemui.car.users.CarSystemUIUserUtil;
-import com.android.systemui.dagger.SysUISingleton;
-import com.android.systemui.settings.UserTracker;
-import com.android.systemui.statusbar.policy.ConfigurationController;
-
-import javax.inject.Inject;
-
-/**
- * TODO(): b/260206944, Can remove this after we have a fix for overlaid resources not applied.
- * <p>
- *     Currently because of Bug:b/260206944, RROs are not applied to the secondary user.
- *     This class acts as a Mediator, which toggles the Overlay state of the RRO package, which
- *     in turn triggers onConfigurationChange. Only after this change start the CarSystemBar
- *     with overlaid resources.
- * </p>
- */
-@SysUISingleton
-public class CarSystemBarMediator implements CoreStartable,
-        ConfigurationController.ConfigurationListener {
-    private static final boolean DEBUG = Build.IS_ENG || Build.IS_USERDEBUG;
-
-    private final CarSystemBar mCarSystemBar;
-    private final SystemBarConfigs mSystemBarConfigs;
-    private final CarSystemBarController mCarSystemBarController;
-    private final OverlayManager mOverlayManager;
-    private final UserTracker mUserTracker;
-
-    private static final String TAG = CarSystemBarMediator.class.getSimpleName();
-    private boolean mCarSystemBarStarted = false;
-    private final Context mContext;
-
-    @Inject
-    public CarSystemBarMediator(CarSystemBar carSystemBar, SystemBarConfigs systemBarConfigs,
-            CarSystemBarController carSystemBarController, Context context,
-            UserTracker userTracker) {
-        mCarSystemBar = carSystemBar;
-        mSystemBarConfigs = systemBarConfigs;
-        mCarSystemBarController = carSystemBarController;
-        mOverlayManager = context.getSystemService(OverlayManager.class);
-        mUserTracker = userTracker;
-        mContext = context;
-    }
-
-    @Override
-    public void start() {
-        String rroPackageName = mContext.getString(
-                R.string.config_secondaryUserSystemUIRROPackageName);
-        if (DEBUG) {
-            Log.d(TAG, "start(), toggle RRO package:" + rroPackageName);
-        }
-        // The RRO must be applied to the user that SystemUI is running as.
-        // MUPAND SystemUI runs as the system user, not the actual user.
-        UserHandle userHandle = CarSystemUIUserUtil.isMUPANDSystemUI() ? UserHandle.SYSTEM
-                : mUserTracker.getUserHandle();
-        try {
-            mOverlayManager.setEnabled(rroPackageName, false, userHandle);
-            mOverlayManager.setEnabled(rroPackageName, true, userHandle);
-        } catch (IllegalArgumentException ex) {
-            Log.w(TAG, "Failed to set overlay package: " + ex);
-            mCarSystemBar.start();
-            mCarSystemBarStarted = true;
-        }
-    }
-
-    @Override
-    public void onConfigChanged(Configuration newConfig) {
-        if (DEBUG) {
-            Log.d(TAG, "onConfigurationChanged(), reset resources and start CarSystemBar");
-        }
-        // Do not start any components which depend on the overlaid resources before RROs gets
-        // applied.
-        if (mCarSystemBarStarted) {
-            return;
-        }
-        mSystemBarConfigs.resetSystemBarConfigs();
-        mCarSystemBarController.resetSystemBarConfigs();
-        mCarSystemBar.start();
-        mCarSystemBarStarted = true;
-    }
-}
diff --git a/src/com/android/systemui/car/systembar/CarSystemBarModule.java b/src/com/android/systemui/car/systembar/CarSystemBarModule.java
index 0d5d2eac..e42fad7d 100644
--- a/src/com/android/systemui/car/systembar/CarSystemBarModule.java
+++ b/src/com/android/systemui/car/systembar/CarSystemBarModule.java
@@ -16,20 +16,36 @@
 
 package com.android.systemui.car.systembar;
 
+import android.annotation.Nullable;
 import android.content.Context;
-import android.content.res.Resources;
+import android.os.Handler;
+import android.view.IWindowManager;
+import android.view.WindowManager;
 
+import com.android.internal.statusbar.IStatusBarService;
 import com.android.systemui.CoreStartable;
 import com.android.systemui.R;
+import com.android.systemui.car.CarDeviceProvisionedController;
 import com.android.systemui.car.dagger.CarSysUIDynamicOverride;
-import com.android.systemui.car.statusbar.UserNameViewController;
+import com.android.systemui.car.displaycompat.ToolbarController;
+import com.android.systemui.car.hvac.HvacController;
+import com.android.systemui.car.keyguard.KeyguardSystemBarPresenter;
 import com.android.systemui.car.statusicon.StatusIconPanelViewController;
 import com.android.systemui.car.systembar.element.CarSystemBarElementController;
 import com.android.systemui.car.users.CarSystemUIUserUtil;
 import com.android.systemui.dagger.SysUISingleton;
 import com.android.systemui.dagger.qualifiers.Main;
+import com.android.systemui.plugins.DarkIconDispatcher;
+import com.android.systemui.settings.DisplayTracker;
 import com.android.systemui.settings.UserTracker;
+import com.android.systemui.statusbar.CommandQueue;
+import com.android.systemui.statusbar.phone.AutoHideController;
+import com.android.systemui.statusbar.phone.LightBarController;
+import com.android.systemui.statusbar.phone.PhoneStatusBarPolicy;
+import com.android.systemui.statusbar.policy.ConfigurationController;
 import com.android.systemui.statusbar.policy.ConfigurationController.ConfigurationListener;
+import com.android.systemui.statusbar.policy.KeyguardStateController;
+import com.android.systemui.util.concurrency.DelayableExecutor;
 
 import dagger.Binds;
 import dagger.BindsOptionalOf;
@@ -55,38 +71,19 @@ import javax.inject.Provider;
  */
 @Module
 public abstract class CarSystemBarModule {
-    /**
-     * TODO(): b/260206944,
-     * @return CarSystemBarMediator for SecondaryMUMDSystemUI which blocks CarSystemBar#start()
-     * util RROs are applied, otherwise return CarSystemBar
-     */
+
     @Provides
     @IntoMap
     @ClassKey(CarSystemBar.class)
-    static CoreStartable bindCarSystemBarStartable(
-            Lazy<CarSystemBar> systemBarService,
-            Lazy<CarSystemBarMediator> applyRROService,
-            @Main Resources resources) {
-        if ((CarSystemUIUserUtil.isSecondaryMUMDSystemUI()
-                || CarSystemUIUserUtil.isMUPANDSystemUI())
-                && resources.getBoolean(R.bool.config_enableSecondaryUserRRO)) {
-            return applyRROService.get();
-        }
-        return systemBarService.get();
+    static CoreStartable bindCarSystemBarStartable(CarSystemBar systemBarService) {
+        return systemBarService;
     }
 
     @Provides
     @IntoSet
     static ConfigurationListener provideCarSystemBarConfigListener(
-            Lazy<CarSystemBar> systemBarService,
-            Lazy<CarSystemBarMediator> applyRROService,
-            @Main Resources resources) {
-        if ((CarSystemUIUserUtil.isSecondaryMUMDSystemUI()
-                || CarSystemUIUserUtil.isMUPANDSystemUI())
-                && resources.getBoolean(R.bool.config_enableSecondaryUserRRO)) {
-            return applyRROService.get();
-        }
-        return systemBarService.get();
+            CarSystemBarController carSystemBarController) {
+        return carSystemBarController;
     }
 
     @BindsOptionalOf
@@ -131,24 +128,65 @@ public abstract class CarSystemBarModule {
     @SysUISingleton
     @Provides
     static CarSystemBarController provideCarSystemBarController(
+            IWindowManager iWindowManager,
+            @Main Handler mainHandler,
             @CarSysUIDynamicOverride Optional<CarSystemBarController> carSystemBarController,
             Context context,
             UserTracker userTracker,
             CarSystemBarViewFactory carSystemBarViewFactory,
             ButtonSelectionStateController buttonSelectionStateController,
-            Lazy<UserNameViewController> userNameViewControllerLazy,
             Lazy<MicPrivacyChipViewController> micPrivacyChipViewControllerLazy,
             Lazy<CameraPrivacyChipViewController> cameraPrivacyChipViewControllerLazy,
             ButtonRoleHolderController buttonRoleHolderController,
             SystemBarConfigs systemBarConfigs,
-            Provider<StatusIconPanelViewController.Builder> panelControllerBuilderProvider) {
+            Provider<StatusIconPanelViewController.Builder> panelControllerBuilderProvider,
+            // TODO(b/156052638): Should not need to inject LightBarController
+            LightBarController lightBarController,
+            DarkIconDispatcher darkIconDispatcher,
+            WindowManager windowManager,
+            CarDeviceProvisionedController deviceProvisionedController,
+            CommandQueue commandQueue,
+            AutoHideController autoHideController,
+            ButtonSelectionStateListener buttonSelectionStateListener,
+            @Main DelayableExecutor mainExecutor,
+            IStatusBarService barService,
+            Lazy<KeyguardStateController> keyguardStateControllerLazy,
+            Lazy<PhoneStatusBarPolicy> iconPolicyLazy,
+            HvacController hvacController,
+            ConfigurationController configurationController,
+            CarSystemBarRestartTracker restartTracker,
+            DisplayTracker displayTracker,
+            @Nullable ToolbarController toolbarController) {
+
         if (carSystemBarController.isPresent()) {
             return carSystemBarController.get();
         }
-        return new CarSystemBarController(context, userTracker, carSystemBarViewFactory,
-                buttonSelectionStateController, userNameViewControllerLazy,
-                micPrivacyChipViewControllerLazy, cameraPrivacyChipViewControllerLazy,
-                buttonRoleHolderController, systemBarConfigs, panelControllerBuilderProvider);
+
+        boolean isSecondaryMUMDSystemUI = (CarSystemUIUserUtil.isSecondaryMUMDSystemUI()
+                || CarSystemUIUserUtil.isMUPANDSystemUI());
+        boolean isSecondaryUserRROsEnabled = context.getResources()
+                .getBoolean(R.bool.config_enableSecondaryUserRRO);
+
+        if (isSecondaryMUMDSystemUI && isSecondaryUserRROsEnabled) {
+            return new MDSystemBarsControllerImpl(iWindowManager, mainHandler, context, userTracker,
+                    carSystemBarViewFactory, buttonSelectionStateController,
+                    micPrivacyChipViewControllerLazy, cameraPrivacyChipViewControllerLazy,
+                    buttonRoleHolderController, systemBarConfigs, panelControllerBuilderProvider,
+                    lightBarController, darkIconDispatcher, windowManager,
+                    deviceProvisionedController, commandQueue, autoHideController,
+                    buttonSelectionStateListener, mainExecutor, barService,
+                    keyguardStateControllerLazy, iconPolicyLazy, hvacController,
+                    configurationController, restartTracker, displayTracker, toolbarController);
+        } else {
+            return new CarSystemBarControllerImpl(context, userTracker, carSystemBarViewFactory,
+                    buttonSelectionStateController, micPrivacyChipViewControllerLazy,
+                    cameraPrivacyChipViewControllerLazy, buttonRoleHolderController,
+                    systemBarConfigs, panelControllerBuilderProvider, lightBarController,
+                    darkIconDispatcher, windowManager, deviceProvisionedController, commandQueue,
+                    autoHideController, buttonSelectionStateListener, mainExecutor, barService,
+                    keyguardStateControllerLazy, iconPolicyLazy, hvacController,
+                    configurationController, restartTracker, displayTracker, toolbarController);
+        }
     }
 
     // CarSystemBarElements
@@ -177,4 +215,44 @@ public abstract class CarSystemBarModule {
     @ClassKey(DataSubscriptionUnseenIconController.class)
     public abstract CarSystemBarElementController.Factory bindDataSubscriptionUnseenIconController(
             DataSubscriptionUnseenIconController.Factory factory);
+
+    /** Injects UserNamePanelButtonViewController */
+    @Binds
+    @IntoMap
+    @ClassKey(UserNamePanelButtonViewController.class)
+    public abstract CarSystemBarElementController.Factory bindUserNamePanelButtonViewController(
+            UserNamePanelButtonViewController.Factory factory);
+
+    /** Injects UserNameTextViewController */
+    @Binds
+    @IntoMap
+    @ClassKey(UserNameTextViewController.class)
+    public abstract CarSystemBarElementController.Factory bindUserNameTextViewController(
+            UserNameTextViewController.Factory factory);
+
+    /** Injects UserNameImageViewController */
+    @Binds
+    @IntoMap
+    @ClassKey(UserNameImageViewController.class)
+    public abstract CarSystemBarElementController.Factory bindUserNameImageViewController(
+            UserNameImageViewController.Factory factory);
+
+    /** Injects KeyguardSystemBarPresenter */
+    @SysUISingleton
+    @Provides
+    static Optional<KeyguardSystemBarPresenter> bindKeyguardSystemBarPresenter(
+             CarSystemBarController controller) {
+        if (controller instanceof KeyguardSystemBarPresenter) {
+            return Optional.of((KeyguardSystemBarPresenter) controller);
+        } else {
+            return Optional.empty();
+        }
+    }
+
+    /** Injects DebugPanelButtonViewController */
+    @Binds
+    @IntoMap
+    @ClassKey(DebugPanelButtonViewController.class)
+    public abstract CarSystemBarElementController.Factory bindDebugPanelButtonViewController(
+            DebugPanelButtonViewController.Factory factory);
 }
diff --git a/src/com/android/systemui/car/systembar/CarSystemBarView.java b/src/com/android/systemui/car/systembar/CarSystemBarView.java
index 8f21623f..8871bc40 100644
--- a/src/com/android/systemui/car/systembar/CarSystemBarView.java
+++ b/src/com/android/systemui/car/systembar/CarSystemBarView.java
@@ -16,8 +16,6 @@
 
 package com.android.systemui.car.systembar;
 
-import static com.android.systemui.car.systembar.CarSystemBar.DEBUG;
-
 import android.annotation.IntDef;
 import android.annotation.Nullable;
 import android.content.Context;
@@ -28,14 +26,13 @@ import android.view.View;
 import android.view.ViewGroup;
 import android.widget.LinearLayout;
 
-import com.android.car.dockutil.Flags;
 import com.android.systemui.R;
+import com.android.systemui.car.hvac.HvacPanelController;
 import com.android.systemui.car.hvac.HvacPanelOverlayViewController;
 import com.android.systemui.car.hvac.HvacView;
 import com.android.systemui.car.hvac.TemperatureControlView;
 import com.android.systemui.car.notification.NotificationPanelViewController;
-import com.android.systemui.car.systembar.CarSystemBarController.HvacPanelController;
-import com.android.systemui.car.systembar.CarSystemBarController.NotificationsShadeController;
+import com.android.systemui.car.notification.NotificationsShadeController;
 import com.android.systemui.settings.UserTracker;
 
 import java.lang.annotation.ElementType;
@@ -56,6 +53,7 @@ public class CarSystemBarView extends LinearLayout {
     }
 
     private static final String TAG = CarSystemBarView.class.getSimpleName();
+    private static final boolean DEBUG = Log.isLoggable(TAG, Log.DEBUG);
 
     public static final int BUTTON_TYPE_NAVIGATION = 0;
     public static final int BUTTON_TYPE_KEYGUARD = 1;
@@ -126,7 +124,7 @@ public class CarSystemBarView extends LinearLayout {
             mHvacButton.setOnClickListener(this::onHvacClick);
         }
 
-        if (Flags.dockFeature()) {
+        if (com.android.car.dockutil.Flags.dockFeature()) {
             if (mDriverHvacView instanceof TemperatureControlView) {
                 ((TemperatureControlView) mDriverHvacView).setTemperatureTextClickListener(
                         this::onHvacClick);
diff --git a/src/com/android/systemui/car/systembar/DebugPanelButtonViewController.java b/src/com/android/systemui/car/systembar/DebugPanelButtonViewController.java
new file mode 100644
index 00000000..84f4b896
--- /dev/null
+++ b/src/com/android/systemui/car/systembar/DebugPanelButtonViewController.java
@@ -0,0 +1,90 @@
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
+package com.android.systemui.car.systembar;
+
+import static android.provider.Settings.Global.DEVELOPMENT_SETTINGS_ENABLED;
+
+import android.database.ContentObserver;
+import android.net.Uri;
+import android.os.Build;
+import android.os.Handler;
+
+import com.android.settingslib.development.DevelopmentSettingsEnabler;
+import com.android.systemui.car.statusicon.StatusIconPanelViewController;
+import com.android.systemui.car.systembar.element.CarSystemBarElementController;
+import com.android.systemui.car.systembar.element.CarSystemBarElementStateController;
+import com.android.systemui.car.systembar.element.CarSystemBarElementStatusBarDisableController;
+import com.android.systemui.dagger.qualifiers.Main;
+import com.android.systemui.util.settings.GlobalSettings;
+
+import dagger.assisted.Assisted;
+import dagger.assisted.AssistedFactory;
+import dagger.assisted.AssistedInject;
+
+import javax.inject.Provider;
+
+/**
+ * A controller for the debug panel button.
+ */
+public class DebugPanelButtonViewController extends CarSystemBarPanelButtonViewController {
+    private static final boolean DEBUG = Build.IS_ENG || Build.IS_USERDEBUG;
+    private final GlobalSettings mGlobalSettings;
+    private final Uri mDevelopEnabled;
+    private final ContentObserver mDeveloperSettingsObserver;
+
+    @AssistedInject
+    protected DebugPanelButtonViewController(@Assisted CarSystemBarPanelButtonView view,
+            CarSystemBarElementStatusBarDisableController disableController,
+            CarSystemBarElementStateController stateController,
+            Provider<StatusIconPanelViewController.Builder> statusIconPanelBuilder,
+            @Main Handler mainHandler, GlobalSettings globalSettings) {
+        super(view, disableController, stateController, statusIconPanelBuilder);
+        mGlobalSettings = globalSettings;
+        mDevelopEnabled = globalSettings.getUriFor(DEVELOPMENT_SETTINGS_ENABLED);
+        mDeveloperSettingsObserver = new ContentObserver(mainHandler) {
+            @Override
+            public void onChange(boolean selfChange, Uri uri) {
+                super.onChange(selfChange, uri);
+                updateVisibility();
+            }
+        };
+    }
+
+    @AssistedFactory
+    public interface Factory extends
+            CarSystemBarElementController.Factory<CarSystemBarPanelButtonView,
+                    DebugPanelButtonViewController> {
+    }
+
+    @Override
+    protected void onViewAttached() {
+        super.onViewAttached();
+        mGlobalSettings.registerContentObserverAsync(mDevelopEnabled, mDeveloperSettingsObserver);
+        updateVisibility();
+    }
+
+    @Override
+    protected void onViewDetached() {
+        super.onViewDetached();
+        mGlobalSettings.unregisterContentObserverAsync(mDeveloperSettingsObserver);
+    }
+
+    @Override
+    protected boolean shouldBeVisible() {
+        return DEBUG && DevelopmentSettingsEnabler.isDevelopmentSettingsEnabled(getContext());
+    }
+}
diff --git a/src/com/android/systemui/wm/MDSystemBarsController.java b/src/com/android/systemui/car/systembar/MDSystemBarsControllerImpl.java
similarity index 51%
rename from src/com/android/systemui/wm/MDSystemBarsController.java
rename to src/com/android/systemui/car/systembar/MDSystemBarsControllerImpl.java
index a716d1f4..5e41196b 100644
--- a/src/com/android/systemui/wm/MDSystemBarsController.java
+++ b/src/com/android/systemui/car/systembar/MDSystemBarsControllerImpl.java
@@ -14,14 +14,17 @@
  * limitations under the License.
  */
 
-package com.android.systemui.wm;
+package com.android.systemui.car.systembar;
 
 import android.annotation.Nullable;
 import android.content.ComponentName;
 import android.content.Context;
+import android.content.om.OverlayManager;
+import android.content.res.Configuration;
 import android.os.Build;
 import android.os.Handler;
 import android.os.RemoteException;
+import android.os.UserHandle;
 import android.util.Log;
 import android.view.Display;
 import android.view.IDisplayWindowInsetsController;
@@ -30,33 +33,52 @@ import android.view.InsetsSource;
 import android.view.InsetsSourceControl;
 import android.view.InsetsState;
 import android.view.WindowInsets;
+import android.view.WindowManager;
 import android.view.inputmethod.ImeTracker;
 
 import androidx.annotation.BinderThread;
 import androidx.annotation.MainThread;
 
 import com.android.internal.statusbar.IStatusBarService;
-import com.android.systemui.car.systembar.CarSystemBar;
+import com.android.systemui.R;
+import com.android.systemui.car.CarDeviceProvisionedController;
+import com.android.systemui.car.displaycompat.ToolbarController;
+import com.android.systemui.car.hvac.HvacController;
+import com.android.systemui.car.statusicon.StatusIconPanelViewController;
+import com.android.systemui.car.users.CarSystemUIUserUtil;
 import com.android.systemui.dagger.qualifiers.Main;
+import com.android.systemui.plugins.DarkIconDispatcher;
+import com.android.systemui.settings.DisplayTracker;
+import com.android.systemui.settings.UserTracker;
 import com.android.systemui.statusbar.CommandQueue;
+import com.android.systemui.statusbar.phone.AutoHideController;
+import com.android.systemui.statusbar.phone.LightBarController;
+import com.android.systemui.statusbar.phone.PhoneStatusBarPolicy;
+import com.android.systemui.statusbar.policy.ConfigurationController;
+import com.android.systemui.statusbar.policy.KeyguardStateController;
+import com.android.systemui.util.concurrency.DelayableExecutor;
+
+import dagger.Lazy;
 
 import java.util.HashSet;
 import java.util.Set;
 
+import javax.inject.Provider;
+
 /**
  * b/259604616, This controller is created as a workaround for NavBar issues in concurrent
  * {@link CarSystemBar}/SystemUI.
  * Problem: CarSystemBar relies on {@link IStatusBarService},
  * which can register only one process to listen for the {@link CommandQueue} events.
- * Solution: {@link MDSystemBarsController} intercepts Insets change event by registering the
+ * Solution: {@link MDSystemBarsControllerImpl} intercepts Insets change event by registering the
  * {@link BinderThread} with
  * {@link IWindowManager#setDisplayWindowInsetsController(int, IDisplayWindowInsetsController)} and
  * notifies its listener for both Primary and Secondary SystemUI
  * process.
  */
-public class MDSystemBarsController {
+public class MDSystemBarsControllerImpl extends CarSystemBarControllerImpl {
 
-    private static final String TAG = MDSystemBarsController.class.getSimpleName();
+    private static final String TAG = MDSystemBarsControllerImpl.class.getSimpleName();
     private static final boolean DEBUG = Build.IS_ENG || Build.IS_USERDEBUG;
     private Set<Listener> mListeners;
     private int mDisplayId = Display.INVALID_DISPLAY;
@@ -64,14 +86,123 @@ public class MDSystemBarsController {
     private final IWindowManager mIWindowManager;
     private final Handler mMainHandler;
     private final Context mContext;
+    private final Listener mListener = new Listener() {
+        @Override
+        public void onKeyboardVisibilityChanged(boolean show) {
+            MDSystemBarsControllerImpl.this.updateKeyboardVisibility(show);
+        }
+    };
+    private final OverlayManager mOverlayManager;
+
+    private boolean mInitialized = false;
 
-    public MDSystemBarsController(
-            IWindowManager wmService,
+    public MDSystemBarsControllerImpl(IWindowManager wmService,
             @Main Handler mainHandler,
-            Context context) {
+            Context context,
+            UserTracker userTracker,
+            CarSystemBarViewFactory carSystemBarViewFactory,
+            ButtonSelectionStateController buttonSelectionStateController,
+            Lazy<MicPrivacyChipViewController> micPrivacyChipViewControllerLazy,
+            Lazy<CameraPrivacyChipViewController> cameraPrivacyChipViewControllerLazy,
+            ButtonRoleHolderController buttonRoleHolderController,
+            SystemBarConfigs systemBarConfigs,
+            Provider<StatusIconPanelViewController.Builder> panelControllerBuilderProvider,
+            // TODO(b/156052638): Should not need to inject LightBarController
+            LightBarController lightBarController,
+            DarkIconDispatcher darkIconDispatcher,
+            WindowManager windowManager,
+            CarDeviceProvisionedController deviceProvisionedController,
+            CommandQueue commandQueue,
+            AutoHideController autoHideController,
+            ButtonSelectionStateListener buttonSelectionStateListener,
+            @Main DelayableExecutor mainExecutor,
+            IStatusBarService barService,
+            Lazy<KeyguardStateController> keyguardStateControllerLazy,
+            Lazy<PhoneStatusBarPolicy> iconPolicyLazy,
+            HvacController hvacController,
+            ConfigurationController configurationController,
+            CarSystemBarRestartTracker restartTracker,
+            DisplayTracker displayTracker,
+            @Nullable ToolbarController toolbarController) {
+        super(context,
+                userTracker,
+                carSystemBarViewFactory,
+                buttonSelectionStateController,
+                micPrivacyChipViewControllerLazy,
+                cameraPrivacyChipViewControllerLazy,
+                buttonRoleHolderController,
+                systemBarConfigs,
+                panelControllerBuilderProvider,
+                lightBarController,
+                darkIconDispatcher,
+                windowManager,
+                deviceProvisionedController,
+                commandQueue,
+                autoHideController,
+                buttonSelectionStateListener,
+                mainExecutor,
+                barService,
+                keyguardStateControllerLazy,
+                iconPolicyLazy,
+                hvacController,
+                configurationController,
+                restartTracker,
+                displayTracker,
+                toolbarController);
         mIWindowManager = wmService;
         mMainHandler = mainHandler;
         mContext = context;
+        mOverlayManager = context.getSystemService(OverlayManager.class);
+    }
+
+    @Override
+    public void init() {
+        mInitialized = false;
+
+        String rroPackageName = mContext.getString(
+                R.string.config_secondaryUserSystemUIRROPackageName);
+        if (DEBUG) {
+            Log.d(TAG, "start(), toggle RRO package:" + rroPackageName);
+        }
+        // The RRO must be applied to the user that SystemUI is running as.
+        // MUPAND SystemUI runs as the system user, not the actual user.
+        UserHandle userHandle = CarSystemUIUserUtil.isMUPANDSystemUI() ? UserHandle.SYSTEM
+                : mUserTracker.getUserHandle();
+        try {
+             // TODO(b/260206944): Can remove this after we have a fix for overlaid resources not
+             // applied.
+             //
+             // Currently because of Bug:b/260206944, RROs are not applied to the secondary user.
+             // This class acts as a Mediator, which toggles the Overlay state of the RRO package,
+             // which in turn triggers onConfigurationChange. Only after this change start the
+             // CarSystemBar with overlaid resources.
+            mOverlayManager.setEnabled(rroPackageName, false, userHandle);
+            mOverlayManager.setEnabled(rroPackageName, true, userHandle);
+        } catch (IllegalArgumentException ex) {
+            Log.w(TAG, "Failed to set overlay package: " + ex);
+            mInitialized = true;
+            super.init();
+        }
+    }
+
+    @Override
+    public void onConfigChanged(Configuration newConfig) {
+        if (!mInitialized) {
+            mInitialized = true;
+            super.init();
+        } else {
+            super.onConfigChanged(newConfig);
+        }
+    }
+
+    @Override
+    protected void createSystemBar() {
+        if (!CarSystemUIUserUtil.isSecondaryMUMDSystemUI()) {
+            super.createSystemBar();
+        } else {
+            addListener(mListener);
+            createNavBar();
+        }
     }
 
     /**
@@ -89,7 +220,7 @@ public class MDSystemBarsController {
      * @param listener SystemBar Inset events
      */
     @MainThread
-    public void addListener(Listener listener) {
+    private void addListener(Listener listener) {
         if (mDisplayId != Display.INVALID_DISPLAY && mDisplayId != mContext.getDisplayId()) {
             Log.e(TAG, "Unexpected Display Id change");
             mListeners = null;
diff --git a/src/com/android/systemui/car/systembar/PrivacyChipViewController.java b/src/com/android/systemui/car/systembar/PrivacyChipViewController.java
index cfb672a7..a4785644 100644
--- a/src/com/android/systemui/car/systembar/PrivacyChipViewController.java
+++ b/src/com/android/systemui/car/systembar/PrivacyChipViewController.java
@@ -148,7 +148,7 @@ public abstract class PrivacyChipViewController implements SensorQcPanel.SensorI
     @Override
     public void toggleSensor() {
         mSensorPrivacyManager.setSensorPrivacy(/* source= */ QS_TILE, /* sensor= */ getChipSensor(),
-                /* enable= */ isSensorEnabled());
+                /* enable= */ isSensorEnabled(), mUserTracker.getUserId());
     }
 
     @Override
diff --git a/src/com/android/systemui/car/systembar/SystemBarConfigs.java b/src/com/android/systemui/car/systembar/SystemBarConfigs.java
index f1a5fa62..bacfb854 100644
--- a/src/com/android/systemui/car/systembar/SystemBarConfigs.java
+++ b/src/com/android/systemui/car/systembar/SystemBarConfigs.java
@@ -18,9 +18,13 @@ package com.android.systemui.car.systembar;
 
 import static android.view.WindowManager.LayoutParams.LAYOUT_IN_DISPLAY_CUTOUT_MODE_ALWAYS;
 
-import static com.android.systemui.car.systembar.CarSystemBar.DEBUG;
+import static com.android.car.dockutil.Flags.dockFeature;
+import static com.android.systemui.car.Flags.displayCompatibilityV2;
+import static com.android.systemui.car.systembar.CarSystemBarController.BOTTOM;
+import static com.android.systemui.car.systembar.CarSystemBarController.LEFT;
+import static com.android.systemui.car.systembar.CarSystemBarController.RIGHT;
+import static com.android.systemui.car.systembar.CarSystemBarController.TOP;
 
-import android.annotation.IntDef;
 import android.content.res.Resources;
 import android.graphics.PixelFormat;
 import android.os.Binder;
@@ -33,16 +37,14 @@ import android.view.ViewGroup;
 import android.view.WindowInsets;
 import android.view.WindowManager;
 
-import com.android.car.dockutil.Flags;
 import com.android.internal.annotations.VisibleForTesting;
 import com.android.systemui.R;
 import com.android.systemui.car.notification.BottomNotificationPanelViewMediator;
 import com.android.systemui.car.notification.TopNotificationPanelViewMediator;
+import com.android.systemui.car.systembar.CarSystemBarController.SystemBarSide;
 import com.android.systemui.dagger.SysUISingleton;
 import com.android.systemui.dagger.qualifiers.Main;
 
-import java.lang.annotation.ElementType;
-import java.lang.annotation.Target;
 import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.Comparator;
@@ -60,19 +62,11 @@ import javax.inject.Inject;
 public class SystemBarConfigs {
 
     private static final String TAG = SystemBarConfigs.class.getSimpleName();
+    private static final boolean DEBUG = Log.isLoggable(TAG, Log.DEBUG);
+
     // The z-order from which system bars will start to appear on top of HUN's.
     private static final int HUN_ZORDER = 10;
 
-    @IntDef(value = {TOP, BOTTOM, LEFT, RIGHT})
-    @Target({ElementType.TYPE_PARAMETER, ElementType.TYPE_USE})
-    private @interface SystemBarSide {
-    }
-
-    public static final int TOP = 0;
-    public static final int BOTTOM = 1;
-    public static final int LEFT = 2;
-    public static final int RIGHT = 3;
-
     private static final Binder INSETS_OWNER = new Binder();
 
     /*
@@ -123,7 +117,7 @@ public class SystemBarConfigs {
         checkHideBottomBarForKeyboardConfigSync();
 
         setInsetPaddingsForOverlappingCorners();
-        sortSystemBarSidesByZOrder();
+        sortSystemBarTypesByZOrder();
     }
 
     /**
@@ -480,7 +474,7 @@ public class SystemBarConfigs {
         updateInsetPaddings(RIGHT, systemBarVisibilityOnInit);
     }
 
-    private void sortSystemBarSidesByZOrder() {
+    private void sortSystemBarTypesByZOrder() {
         List<SystemBarConfig> systemBarsByZOrder = new ArrayList<>(mSystemBarConfigMap.values());
 
         systemBarsByZOrder.sort(new Comparator<SystemBarConfig>() {
@@ -541,11 +535,11 @@ public class SystemBarConfigs {
         return side == LEFT || side == RIGHT;
     }
     boolean isLeftDisplayCompatToolbarEnabled() {
-        return mDisplayCompatToolbarState == 1;
+        return displayCompatibilityV2() && mDisplayCompatToolbarState == 1;
     }
 
     boolean isRightDisplayCompatToolbarEnabled() {
-        return mDisplayCompatToolbarState == 2;
+        return displayCompatibilityV2() && mDisplayCompatToolbarState == 2;
     }
 
     private static final class SystemBarConfig {
@@ -609,7 +603,7 @@ public class SystemBarConfigs {
             lp.windowAnimations = 0;
             lp.gravity = BAR_GRAVITY_MAP.get(mSide);
             lp.layoutInDisplayCutoutMode = LAYOUT_IN_DISPLAY_CUTOUT_MODE_ALWAYS;
-            if (Flags.dockFeature()) {
+            if (dockFeature()) {
                 lp.privateFlags = lp.privateFlags
                         | WindowManager.LayoutParams.PRIVATE_FLAG_INTERCEPT_GLOBAL_DRAG_AND_DROP;
             }
diff --git a/src/com/android/systemui/car/systembar/SystemBarUtil.kt b/src/com/android/systemui/car/systembar/SystemBarUtil.kt
index 633b05ce..b31d4bd0 100644
--- a/src/com/android/systemui/car/systembar/SystemBarUtil.kt
+++ b/src/com/android/systemui/car/systembar/SystemBarUtil.kt
@@ -25,13 +25,22 @@ import android.provider.Settings
 import android.text.TextUtils
 import android.util.ArraySet
 import android.util.Log
+import android.view.WindowInsets.Type.navigationBars
+import android.view.WindowInsets.Type.statusBars
 import com.android.systemui.R
 import com.android.systemui.settings.UserTracker
+import com.android.systemui.wm.BarControlPolicy
 import java.net.URISyntaxException
 
 object SystemBarUtil {
     private const val TAG = "SystemBarUtil"
     private const val TOS_DISABLED_APPS_SEPARATOR = ","
+    const val SYSTEM_BAR_PERSISTENCY_CONFIG_NON_IMMERSIVE = 0
+    const val SYSTEM_BAR_PERSISTENCY_CONFIG_IMMERSIVE = 1
+    const val SYSTEM_BAR_PERSISTENCY_CONFIG_IMMERSIVE_WITH_NAV = 2
+    const val SYSTEM_BAR_PERSISTENCY_CONFIG_BARPOLICY = 3
+    const val VISIBLE_BAR_VISIBILITIES_TYPES_INDEX: Int = 0
+    const val INVISIBLE_BAR_VISIBILITIES_TYPES_INDEX: Int = 1
 
     /**
      * Returns a set of packages that are disabled by tos
@@ -45,8 +54,11 @@ object SystemBarUtil {
         if (uid == null) {
             return ArraySet()
         }
-        val settingsValue = Settings.Secure
-                .getStringForUser(context.contentResolver, KEY_UNACCEPTED_TOS_DISABLED_APPS, uid)
+        val settingsValue = Settings.Secure.getStringForUser(
+            context.contentResolver,
+            KEY_UNACCEPTED_TOS_DISABLED_APPS,
+            uid
+        )
         return if (TextUtils.isEmpty(settingsValue)) {
             ArraySet()
         } else {
@@ -104,4 +116,49 @@ object SystemBarUtil {
         }
         launchApp(context, tosIntent, userHandle)
     }
+
+    /**
+     * Helper function that returns {@code true} if the navigation bar is persistent on the display.
+     */
+    fun isNavBarPersistent(context: Context): Boolean {
+        val behavior = context.resources.getInteger(R.integer.config_systemBarPersistency)
+        val remoteInsetsControllerControlsSystemBars =
+            context.resources.getBoolean(
+                android.R.bool.config_remoteInsetsControllerControlsSystemBars
+            )
+        val navBarVisibleOnBarControlPolicy =
+            (behavior == SYSTEM_BAR_PERSISTENCY_CONFIG_BARPOLICY) &&
+                    isBarVisibleOnBarControlPolicy(context, navigationBars())
+
+        return remoteInsetsControllerControlsSystemBars &&
+                (behavior == SYSTEM_BAR_PERSISTENCY_CONFIG_NON_IMMERSIVE ||
+                        behavior == SYSTEM_BAR_PERSISTENCY_CONFIG_IMMERSIVE_WITH_NAV ||
+                        navBarVisibleOnBarControlPolicy)
+    }
+
+    /**
+     * Helper function that returns {@code true} if the status bar is persistent on the display.
+     */
+    fun isStatusBarPersistent(context: Context): Boolean {
+        val behavior = context.resources.getInteger(R.integer.config_systemBarPersistency)
+        val remoteInsetsControllerControlsSystemBars =
+            context.resources.getBoolean(
+                android.R.bool.config_remoteInsetsControllerControlsSystemBars
+            )
+        val statusBarVisibleOnBarControlPolicy =
+            (behavior == SYSTEM_BAR_PERSISTENCY_CONFIG_BARPOLICY) &&
+                    isBarVisibleOnBarControlPolicy(context, statusBars())
+
+        return remoteInsetsControllerControlsSystemBars &&
+                (behavior == SYSTEM_BAR_PERSISTENCY_CONFIG_NON_IMMERSIVE ||
+                        statusBarVisibleOnBarControlPolicy)
+    }
+
+    private fun isBarVisibleOnBarControlPolicy(context: Context, type: Int): Boolean {
+        val showTypes =
+            BarControlPolicy.getBarVisibilities(
+                context.packageName
+            )[VISIBLE_BAR_VISIBILITIES_TYPES_INDEX]
+        return (showTypes and type) != 0
+    }
 }
diff --git a/src/com/android/systemui/car/systembar/UserNameImageViewController.java b/src/com/android/systemui/car/systembar/UserNameImageViewController.java
new file mode 100644
index 00000000..8d3eee5e
--- /dev/null
+++ b/src/com/android/systemui/car/systembar/UserNameImageViewController.java
@@ -0,0 +1,117 @@
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
+package com.android.systemui.car.systembar;
+
+import android.content.Context;
+import android.content.pm.UserInfo;
+import android.graphics.drawable.Drawable;
+import android.os.UserManager;
+
+import com.android.systemui.car.systembar.element.CarSystemBarElementController;
+import com.android.systemui.car.systembar.element.CarSystemBarElementStateController;
+import com.android.systemui.car.systembar.element.CarSystemBarElementStatusBarDisableController;
+import com.android.systemui.car.systembar.element.layout.CarSystemBarImageView;
+import com.android.systemui.car.users.CarProfileIconUpdater;
+import com.android.systemui.car.userswitcher.UserIconProvider;
+import com.android.systemui.dagger.qualifiers.Main;
+import com.android.systemui.settings.UserTracker;
+
+import dagger.assisted.Assisted;
+import dagger.assisted.AssistedFactory;
+import dagger.assisted.AssistedInject;
+
+import java.util.concurrent.Executor;
+
+/**
+ * Controls user name ImageView for the current logged in user.
+ */
+public final class UserNameImageViewController extends
+        CarSystemBarElementController<CarSystemBarImageView> {
+    private final Context mContext;
+    private final Executor mMainExecutor;
+    private final UserTracker mUserTracker;
+    private final UserManager mUserManager;
+    private final CarProfileIconUpdater mCarProfileIconUpdater;
+    private final UserIconProvider mUserIconProvider;
+    private boolean mUserLifecycleListenerRegistered;
+
+    private final UserTracker.Callback mUserChangedCallback =
+            new UserTracker.Callback() {
+                @Override
+                public void onUserChanged(int newUser, Context userContext) {
+                    updateUser(newUser);
+                }
+            };
+
+    private final CarProfileIconUpdater.Callback mUserIconUpdateCallback = this::updateUser;
+
+    @AssistedInject
+    protected UserNameImageViewController(@Assisted CarSystemBarImageView view,
+            CarSystemBarElementStatusBarDisableController disableController,
+            CarSystemBarElementStateController stateController, Context context,
+            @Main Executor mainExecutor, UserTracker userTracker, UserManager userManager,
+            CarProfileIconUpdater carProfileIconUpdater, UserIconProvider userIconProvider) {
+        super(view, disableController, stateController);
+        mContext = context;
+        mMainExecutor = mainExecutor;
+        mUserTracker = userTracker;
+        mUserManager = userManager;
+        mCarProfileIconUpdater = carProfileIconUpdater;
+        mUserIconProvider = userIconProvider;
+    }
+
+    @AssistedFactory
+    public interface Factory extends
+            CarSystemBarElementController.Factory<CarSystemBarImageView,
+                    UserNameImageViewController> {
+    }
+
+    @Override
+    protected void onViewAttached() {
+        super.onViewAttached();
+        registerForUserChangeEvents();
+        updateUser(mUserTracker.getUserId());
+    }
+
+    @Override
+    protected void onViewDetached() {
+        super.onViewDetached();
+        if (mUserLifecycleListenerRegistered) {
+            mCarProfileIconUpdater.removeCallback(mUserIconUpdateCallback);
+            mUserTracker.removeCallback(mUserChangedCallback);
+            mUserLifecycleListenerRegistered = false;
+        }
+    }
+
+    private void registerForUserChangeEvents() {
+        if (mUserLifecycleListenerRegistered) {
+            return;
+        }
+        mUserLifecycleListenerRegistered = true;
+        // Register for user switching
+        mUserTracker.addCallback(mUserChangedCallback, mMainExecutor);
+        // Also register for user icon changing
+        mCarProfileIconUpdater.addCallback(mUserIconUpdateCallback);
+    }
+
+    private void updateUser(int userId) {
+        UserInfo currentUserInfo = mUserManager.getUserInfo(userId);
+
+        Drawable circleIcon = mUserIconProvider.getRoundedUserIcon(currentUserInfo, mContext);
+        mView.setImageDrawable(circleIcon);
+    }
+}
diff --git a/src/com/android/systemui/car/systembar/UserNamePanelButtonViewController.java b/src/com/android/systemui/car/systembar/UserNamePanelButtonViewController.java
new file mode 100644
index 00000000..a457c02e
--- /dev/null
+++ b/src/com/android/systemui/car/systembar/UserNamePanelButtonViewController.java
@@ -0,0 +1,174 @@
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
+package com.android.systemui.car.systembar;
+
+import android.app.ActivityOptions;
+import android.car.app.CarActivityManager;
+import android.content.Context;
+import android.content.Intent;
+import android.os.Build;
+import android.text.TextUtils;
+import android.util.Log;
+import android.view.View;
+import android.widget.Toast;
+
+import com.android.car.ui.utils.CarUxRestrictionsUtil;
+import com.android.systemui.R;
+import com.android.systemui.car.CarDeviceProvisionedController;
+import com.android.systemui.car.CarServiceProvider;
+import com.android.systemui.car.statusicon.StatusIconPanelViewController;
+import com.android.systemui.car.systembar.element.CarSystemBarElementController;
+import com.android.systemui.car.systembar.element.CarSystemBarElementStateController;
+import com.android.systemui.car.systembar.element.CarSystemBarElementStatusBarDisableController;
+import com.android.systemui.car.users.CarSystemUIUserUtil;
+import com.android.systemui.settings.UserTracker;
+
+import dagger.assisted.Assisted;
+import dagger.assisted.AssistedFactory;
+import dagger.assisted.AssistedInject;
+
+import java.net.URISyntaxException;
+
+import javax.inject.Provider;
+
+public class UserNamePanelButtonViewController extends CarSystemBarPanelButtonViewController {
+    private static final String TAG = UserNamePanelButtonViewController.class.getName();
+    private final Context mContext;
+    private final UserTracker mUserTracker;
+    private final CarServiceProvider mCarServiceProvider;
+    private final CarDeviceProvisionedController mCarDeviceProvisionedController;
+    private final boolean mIsMUMDSystemUI;
+    private CarActivityManager mCarActivityManager;
+
+    private final CarServiceProvider.CarServiceOnConnectedListener mCarServiceOnConnectedListener =
+            car -> {
+                mCarActivityManager = car.getCarManager(CarActivityManager.class);
+            };
+
+    @AssistedInject
+    protected UserNamePanelButtonViewController(@Assisted CarSystemBarPanelButtonView view,
+            CarSystemBarElementStatusBarDisableController disableController,
+            CarSystemBarElementStateController stateController,
+            Provider<StatusIconPanelViewController.Builder> statusIconPanelBuilder,
+            Context context, UserTracker userTracker, CarServiceProvider carServiceProvider,
+            CarDeviceProvisionedController deviceProvisionedController) {
+        super(view, disableController, stateController, statusIconPanelBuilder);
+        mContext = context;
+        mUserTracker = userTracker;
+        mCarServiceProvider = carServiceProvider;
+        mCarDeviceProvisionedController = deviceProvisionedController;
+        mIsMUMDSystemUI = CarSystemUIUserUtil.isMUMDSystemUI();
+    }
+
+    @AssistedFactory
+    public interface Factory extends
+            CarSystemBarElementController.Factory<CarSystemBarPanelButtonView,
+                    UserNamePanelButtonViewController> {
+    }
+
+    @Override
+    protected void onInit() {
+        if (mIsMUMDSystemUI) {
+            // TODO(b/269490856): consider removal of UserPicker carve-outs
+            mView.setOnClickListener(getMUMDUserPickerClickListener());
+        } else {
+            super.onInit();
+        }
+        if (!Build.IS_ENG && !Build.IS_USERDEBUG) {
+            return;
+        }
+        String longIntentString = mContext.getString(R.string.user_profile_long_press_intent);
+        if (!TextUtils.isEmpty(longIntentString)) {
+            Intent intent;
+            try {
+                intent = Intent.parseUri(longIntentString, Intent.URI_INTENT_SCHEME);
+            } catch (URISyntaxException e) {
+                return;
+            }
+            Intent finalIntent = intent;
+            mView.setOnLongClickListener(v -> {
+                Intent broadcast = new Intent(Intent.ACTION_CLOSE_SYSTEM_DIALOGS);
+                mContext.sendBroadcastAsUser(broadcast, mUserTracker.getUserHandle());
+                try {
+                    ActivityOptions options = ActivityOptions.makeBasic();
+                    options.setLaunchDisplayId(mContext.getDisplayId());
+                    mContext.startActivityAsUser(finalIntent, options.toBundle(),
+                            mUserTracker.getUserHandle());
+                } catch (Exception e) {
+                    Log.e(TAG, "Failed to launch intent", e);
+                }
+                return true;
+            });
+        }
+    }
+
+    @Override
+    protected void onViewAttached() {
+        super.onViewAttached();
+        if (mIsMUMDSystemUI) {
+            mCarServiceProvider.addListener(mCarServiceOnConnectedListener);
+        }
+    }
+
+    @Override
+    protected void onViewDetached() {
+        super.onViewDetached();
+        if (mIsMUMDSystemUI) {
+            mCarServiceProvider.removeListener(mCarServiceOnConnectedListener);
+            mCarActivityManager = null;
+        }
+    }
+
+    @Override
+    protected boolean shouldRestoreState() {
+        // TODO(b/269490856): consider removal of UserPicker carve-outs
+        return !CarSystemUIUserUtil.isMUMDSystemUI();
+    }
+
+    private View.OnClickListener getMUMDUserPickerClickListener() {
+        boolean disabledWhileDriving =
+                mView.getDisabledWhileDriving() != null ? mView.getDisabledWhileDriving()
+                        : false;
+        boolean disabledWhileUnprovisioned = mView.getDisabledWhileUnprovisioned() != null
+                ? mView.getDisabledWhileUnprovisioned() : false;
+        CarUxRestrictionsUtil carUxRestrictionsUtil;
+        if (disabledWhileDriving) {
+            carUxRestrictionsUtil = CarUxRestrictionsUtil.getInstance(mContext);
+        } else {
+            carUxRestrictionsUtil = null;
+        }
+        return v -> {
+            if (disabledWhileUnprovisioned && !isDeviceSetupForUser()) {
+                return;
+            }
+            if (disabledWhileDriving && carUxRestrictionsUtil.getCurrentRestrictions()
+                    .isRequiresDistractionOptimization()) {
+                Toast.makeText(mContext, R.string.car_ui_restricted_while_driving,
+                        Toast.LENGTH_LONG).show();
+                return;
+            }
+            if (mCarActivityManager != null) {
+                mCarActivityManager.startUserPickerOnDisplay(mContext.getDisplayId());
+            }
+        };
+    }
+
+    private boolean isDeviceSetupForUser() {
+        return mCarDeviceProvisionedController.isCurrentUserSetup()
+                && !mCarDeviceProvisionedController.isCurrentUserSetupInProgress();
+    }
+}
diff --git a/src/com/android/systemui/car/systembar/UserNameTextViewController.java b/src/com/android/systemui/car/systembar/UserNameTextViewController.java
new file mode 100644
index 00000000..97283d8d
--- /dev/null
+++ b/src/com/android/systemui/car/systembar/UserNameTextViewController.java
@@ -0,0 +1,121 @@
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
+package com.android.systemui.car.systembar;
+
+import android.content.BroadcastReceiver;
+import android.content.Context;
+import android.content.Intent;
+import android.content.IntentFilter;
+import android.content.pm.UserInfo;
+import android.os.UserHandle;
+import android.os.UserManager;
+
+import com.android.systemui.broadcast.BroadcastDispatcher;
+import com.android.systemui.car.systembar.element.CarSystemBarElementController;
+import com.android.systemui.car.systembar.element.CarSystemBarElementStateController;
+import com.android.systemui.car.systembar.element.CarSystemBarElementStatusBarDisableController;
+import com.android.systemui.car.systembar.element.layout.CarSystemBarTextView;
+import com.android.systemui.dagger.qualifiers.Main;
+import com.android.systemui.settings.UserTracker;
+
+import dagger.assisted.Assisted;
+import dagger.assisted.AssistedFactory;
+import dagger.assisted.AssistedInject;
+
+import java.util.concurrent.Executor;
+
+/**
+ * Controls user name TextView for the current logged in user.
+ */
+public final class UserNameTextViewController extends
+        CarSystemBarElementController<CarSystemBarTextView> {
+    private final Executor mMainExecutor;
+    private final UserTracker mUserTracker;
+    private final UserManager mUserManager;
+    private final BroadcastDispatcher mBroadcastDispatcher;
+    private boolean mUserLifecycleListenerRegistered;
+
+    private final UserTracker.Callback mUserChangedCallback =
+            new UserTracker.Callback() {
+                @Override
+                public void onUserChanged(int newUser, Context userContext) {
+                    updateUser(newUser);
+                }
+            };
+
+    private final BroadcastReceiver mUserUpdateReceiver = new BroadcastReceiver() {
+        @Override
+        public void onReceive(Context context, Intent intent) {
+            updateUser(mUserTracker.getUserId());
+        }
+    };
+
+    @AssistedInject
+    protected UserNameTextViewController(@Assisted CarSystemBarTextView view,
+            CarSystemBarElementStatusBarDisableController disableController,
+            CarSystemBarElementStateController stateController,
+            @Main Executor mainExecutor, UserTracker userTracker, UserManager userManager,
+            BroadcastDispatcher broadcastDispatcher) {
+        super(view, disableController, stateController);
+        mMainExecutor = mainExecutor;
+        mUserTracker = userTracker;
+        mUserManager = userManager;
+        mBroadcastDispatcher = broadcastDispatcher;
+    }
+
+    @AssistedFactory
+    public interface Factory extends
+            CarSystemBarElementController.Factory<CarSystemBarTextView,
+                    UserNameTextViewController> {
+    }
+
+    @Override
+    protected void onViewAttached() {
+        super.onViewAttached();
+        registerForUserChangeEvents();
+        updateUser(mUserTracker.getUserId());
+    }
+
+    @Override
+    protected void onViewDetached() {
+        super.onViewDetached();
+        if (mUserLifecycleListenerRegistered) {
+            mBroadcastDispatcher.unregisterReceiver(mUserUpdateReceiver);
+            mUserTracker.removeCallback(mUserChangedCallback);
+            mUserLifecycleListenerRegistered = false;
+        }
+    }
+
+    private void registerForUserChangeEvents() {
+        if (mUserLifecycleListenerRegistered) {
+            return;
+        }
+        mUserLifecycleListenerRegistered = true;
+        // Register for user switching
+        mUserTracker.addCallback(mUserChangedCallback, mMainExecutor);
+        // Also register for user info changing
+        IntentFilter filter = new IntentFilter();
+        filter.addAction(Intent.ACTION_USER_INFO_CHANGED);
+        mBroadcastDispatcher.registerReceiver(mUserUpdateReceiver, filter, /* executor= */ null,
+                UserHandle.ALL);
+    }
+
+    private void updateUser(int userId) {
+        UserInfo currentUserInfo = mUserManager.getUserInfo(userId);
+        mView.setText(currentUserInfo.name);
+    }
+}
diff --git a/src/com/android/systemui/car/systembar/element/CarSystemBarElement.java b/src/com/android/systemui/car/systembar/element/CarSystemBarElement.java
index c2580084..c20302f1 100644
--- a/src/com/android/systemui/car/systembar/element/CarSystemBarElement.java
+++ b/src/com/android/systemui/car/systembar/element/CarSystemBarElement.java
@@ -18,9 +18,12 @@ package com.android.systemui.car.systembar.element;
 
 import android.app.StatusBarManager;
 
+import androidx.annotation.Nullable;
+
 /** Generic interface for CarSystemBar UI elements */
 public interface CarSystemBarElement {
     /** Returns the class to be instantiated to control this element */
+    @Nullable
     Class<?> getElementControllerClass();
 
     /** Return the system bar disable flag for this element */
diff --git a/src/com/android/systemui/car/systembar/element/CarSystemBarElementInitializer.java b/src/com/android/systemui/car/systembar/element/CarSystemBarElementInitializer.java
index 6071a495..6849ef1d 100644
--- a/src/com/android/systemui/car/systembar/element/CarSystemBarElementInitializer.java
+++ b/src/com/android/systemui/car/systembar/element/CarSystemBarElementInitializer.java
@@ -21,6 +21,8 @@ import android.util.Log;
 import android.view.View;
 import android.view.ViewGroup;
 
+import androidx.annotation.Nullable;
+
 import com.android.systemui.dagger.SysUISingleton;
 
 import java.util.ArrayList;
@@ -115,6 +117,7 @@ public class CarSystemBarElementInitializer {
             return mView;
         }
 
+        @Nullable
         Class<?> getControllerClass() {
             return mControllerClass;
         }
diff --git a/src/com/android/systemui/car/systembar/element/layout/CarSystemBarFrameLayout.java b/src/com/android/systemui/car/systembar/element/layout/CarSystemBarFrameLayout.java
index a99163cc..5367bdac 100644
--- a/src/com/android/systemui/car/systembar/element/layout/CarSystemBarFrameLayout.java
+++ b/src/com/android/systemui/car/systembar/element/layout/CarSystemBarFrameLayout.java
@@ -29,6 +29,7 @@ import com.android.systemui.car.systembar.element.CarSystemBarElementResolver;
 
 /** Implementation of FrameLayout ViewGroup that supports {@link CarSystemBarElement} attributes */
 public class CarSystemBarFrameLayout extends FrameLayout implements CarSystemBarElement {
+    @Nullable
     private Class<?> mElementControllerClassAttr;
     private int mSystemBarDisableFlags;
     private int mSystemBarDisable2Flags;
diff --git a/src/com/android/systemui/car/systembar/element/layout/CarSystemBarImageView.java b/src/com/android/systemui/car/systembar/element/layout/CarSystemBarImageView.java
index 6daebb7f..48bb5a10 100644
--- a/src/com/android/systemui/car/systembar/element/layout/CarSystemBarImageView.java
+++ b/src/com/android/systemui/car/systembar/element/layout/CarSystemBarImageView.java
@@ -26,8 +26,9 @@ import com.android.systemui.car.systembar.element.CarSystemBarElement;
 import com.android.systemui.car.systembar.element.CarSystemBarElementFlags;
 import com.android.systemui.car.systembar.element.CarSystemBarElementResolver;
 
-/** Implementation of ImageView  that supports {@link CarSystemBarElement} attributes */
+/** Implementation of ImageView that supports {@link CarSystemBarElement} attributes */
 public class CarSystemBarImageView extends ImageView implements CarSystemBarElement {
+    @Nullable
     private Class<?> mElementControllerClassAttr;
     private int mSystemBarDisableFlags;
     private int mSystemBarDisable2Flags;
diff --git a/src/com/android/systemui/car/systembar/element/layout/CarSystemBarTextView.java b/src/com/android/systemui/car/systembar/element/layout/CarSystemBarTextView.java
new file mode 100644
index 00000000..0ad57a36
--- /dev/null
+++ b/src/com/android/systemui/car/systembar/element/layout/CarSystemBarTextView.java
@@ -0,0 +1,93 @@
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
+package com.android.systemui.car.systembar.element.layout;
+
+import android.annotation.NonNull;
+import android.annotation.Nullable;
+import android.content.Context;
+import android.util.AttributeSet;
+import android.widget.TextView;
+
+import com.android.systemui.car.systembar.element.CarSystemBarElement;
+import com.android.systemui.car.systembar.element.CarSystemBarElementFlags;
+import com.android.systemui.car.systembar.element.CarSystemBarElementResolver;
+
+/** Implementation of TextView that supports {@link CarSystemBarElement} attributes */
+public class CarSystemBarTextView extends TextView implements CarSystemBarElement {
+    @Nullable
+    private Class<?> mElementControllerClassAttr;
+    private int mSystemBarDisableFlags;
+    private int mSystemBarDisable2Flags;
+    private boolean mDisableForLockTaskModeLocked;
+
+    public CarSystemBarTextView(@NonNull Context context) {
+        super(context);
+        init(context, /* attrs= */ null);
+    }
+
+    public CarSystemBarTextView(@NonNull Context context,
+            @Nullable AttributeSet attrs) {
+        super(context, attrs);
+        init(context, attrs);
+    }
+
+    public CarSystemBarTextView(@NonNull Context context, @Nullable AttributeSet attrs,
+            int defStyleAttr) {
+        super(context, attrs, defStyleAttr);
+        init(context, attrs);
+    }
+
+    public CarSystemBarTextView(@NonNull Context context, @Nullable AttributeSet attrs,
+            int defStyleAttr, int defStyleRes) {
+        super(context, attrs, defStyleAttr, defStyleRes);
+        init(context, attrs);
+    }
+
+    private void init(Context context, @Nullable AttributeSet attrs) {
+        mElementControllerClassAttr =
+                CarSystemBarElementResolver.getElementControllerClassFromAttributes(context, attrs);
+        mSystemBarDisableFlags =
+                CarSystemBarElementFlags.getStatusBarManagerDisableFlagsFromAttributes(context,
+                        attrs);
+        mSystemBarDisable2Flags =
+                CarSystemBarElementFlags.getStatusBarManagerDisable2FlagsFromAttributes(context,
+                        attrs);
+        mDisableForLockTaskModeLocked =
+                CarSystemBarElementFlags.getDisableForLockTaskModeLockedFromAttributes(context,
+                        attrs);
+    }
+
+    @Override
+    public Class<?> getElementControllerClass() {
+        return mElementControllerClassAttr;
+    }
+
+    @Override
+    public int getSystemBarDisableFlags() {
+        return mSystemBarDisableFlags;
+    }
+
+    @Override
+    public int getSystemBarDisable2Flags() {
+        return mSystemBarDisable2Flags;
+    }
+
+    @Override
+    public boolean disableForLockTaskModeLocked() {
+        return mDisableForLockTaskModeLocked;
+    }
+}
diff --git a/src/com/android/systemui/car/userpicker/CarServiceMediator.java b/src/com/android/systemui/car/userpicker/CarServiceMediator.java
index ca5af547..672d0798 100644
--- a/src/com/android/systemui/car/userpicker/CarServiceMediator.java
+++ b/src/com/android/systemui/car/userpicker/CarServiceMediator.java
@@ -124,9 +124,7 @@ final class CarServiceMediator {
             UserLifecycleListener listener) {
         mUserLifecycleListeners.put(listener, new Pair<>(receiver, filter));
         if (mCarUserManager != null) {
-            mCarServiceProvider.addListener(car -> {
-                mCarUserManager.addListener(receiver, filter, listener);
-            });
+            mCarUserManager.addListener(receiver, filter, listener);
         }
     }
 
diff --git a/src/com/android/systemui/car/userpicker/UserPickerActivity.java b/src/com/android/systemui/car/userpicker/UserPickerActivity.java
index 8519f35e..cb8313ed 100644
--- a/src/com/android/systemui/car/userpicker/UserPickerActivity.java
+++ b/src/com/android/systemui/car/userpicker/UserPickerActivity.java
@@ -16,7 +16,7 @@
 
 package com.android.systemui.car.userpicker;
 
-import static android.view.WindowManager.LayoutParams.SYSTEM_FLAG_HIDE_NON_SYSTEM_OVERLAY_WINDOWS;
+import static android.view.WindowInsetsController.BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE;
 import static android.window.OnBackInvokedDispatcher.PRIORITY_DEFAULT;
 
 import static com.android.systemui.car.userpicker.HeaderState.HEADER_STATE_CHANGE_USER;
@@ -26,6 +26,8 @@ import static com.android.systemui.car.users.CarSystemUIUserUtil.isMUPANDSystemU
 import android.app.Activity;
 import android.content.Context;
 import android.content.res.Configuration;
+import android.graphics.Insets;
+import android.os.Build;
 import android.os.Bundle;
 import android.util.Log;
 import android.util.Slog;
@@ -35,7 +37,6 @@ import android.view.ViewGroup;
 import android.view.Window;
 import android.view.WindowInsets;
 import android.view.WindowInsetsController;
-import android.view.WindowManager;
 import android.window.OnBackInvokedCallback;
 
 import androidx.annotation.NonNull;
@@ -46,6 +47,7 @@ import com.android.car.ui.recyclerview.CarUiRecyclerView;
 import com.android.systemui.Dumpable;
 import com.android.systemui.R;
 import com.android.systemui.car.CarServiceProvider;
+import com.android.systemui.car.systembar.SystemBarUtil;
 import com.android.systemui.car.systembar.element.CarSystemBarElementInitializer;
 import com.android.systemui.car.userpicker.UserPickerController.Callbacks;
 import com.android.systemui.dump.DumpManager;
@@ -65,11 +67,10 @@ import javax.inject.Inject;
  */
 public class UserPickerActivity extends Activity implements Dumpable {
     private static final String TAG = UserPickerActivity.class.getSimpleName();
-    private static final boolean DEBUG = Log.isLoggable(TAG, Log.DEBUG);
+    private static final boolean DEBUG = Build.IS_DEBUGGABLE;
 
     private UserPickerActivityComponent mUserPickerActivityComponent;
     private boolean mIsDriver;
-
     @Inject
     CarSystemBarElementInitializer mCarSystemBarElementInitializer;
     @Inject
@@ -185,12 +186,6 @@ public class UserPickerActivity extends Activity implements Dumpable {
         mDumpManager.registerNormalDumpable(dumpableName, /* module= */ this);
     }
 
-    @Override
-    protected void onStart() {
-        super.onStart();
-        getWindow().addSystemFlags(SYSTEM_FLAG_HIDE_NON_SYSTEM_OVERLAY_WINDOWS);
-    }
-
     private void initViews() {
         View powerBtn = mRootView.findViewById(R.id.power_button_icon_view);
         powerBtn.setOnClickListener(v -> mController.screenOffDisplay());
@@ -226,14 +221,33 @@ public class UserPickerActivity extends Activity implements Dumpable {
 
     private void initWindow() {
         Window window = getWindow();
+        window.getDecorView().getRootView().setOnApplyWindowInsetsListener(
+                mOnApplyWindowInsetsListener);
+
         WindowInsetsController insetsController = window.getInsetsController();
         if (insetsController != null) {
             insetsController.setAnimationsDisabled(true);
             insetsController.hide(WindowInsets.Type.statusBars()
                     | WindowInsets.Type.navigationBars());
+            // TODO(b/271139033): Supports passenger display. Currently only systemBars on main
+            // display supports showing transient by swipe.
+            insetsController.setSystemBarsBehavior(BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE);
         }
     }
 
+    // Avoid activity resizing due to dismissible system bars.
+    private final View.OnApplyWindowInsetsListener mOnApplyWindowInsetsListener = (v, insets) -> {
+        if (!SystemBarUtil.INSTANCE.isStatusBarPersistent(this)) {
+            Insets statusBarInsets = insets.getInsets(WindowInsets.Type.statusBars());
+            insets.inset(statusBarInsets);
+        }
+        if (!SystemBarUtil.INSTANCE.isNavBarPersistent(/* context*/ this)) {
+            Insets navBarInsets = insets.getInsets(WindowInsets.Type.navigationBars());
+            insets.inset(navBarInsets);
+        }
+        return insets;
+    };
+
     private void initManagers(View rootView) {
         mDialogManager.initContextFromView(rootView);
         mSnackbarManager.setRootView(rootView, R.id.user_picker_bottom_bar);
@@ -258,16 +272,6 @@ public class UserPickerActivity extends Activity implements Dumpable {
         return !isMUPANDSystemUI() && getDisplayId() == mDisplayTracker.getDefaultDisplayId();
     }
 
-    @Override
-    protected void onStop() {
-        Window window = getWindow();
-        WindowManager.LayoutParams attrs = window.getAttributes();
-        attrs.privateFlags &= ~SYSTEM_FLAG_HIDE_NON_SYSTEM_OVERLAY_WINDOWS;
-        window.setAttributes(attrs);
-
-        super.onStop();
-    }
-
     @Override
     protected void onDestroy() {
         if (DEBUG) {
diff --git a/src/com/android/systemui/car/userpicker/UserPickerAdapter.java b/src/com/android/systemui/car/userpicker/UserPickerAdapter.java
index e21440a4..f58be587 100644
--- a/src/com/android/systemui/car/userpicker/UserPickerAdapter.java
+++ b/src/com/android/systemui/car/userpicker/UserPickerAdapter.java
@@ -16,7 +16,9 @@
 
 package com.android.systemui.car.userpicker;
 
+import android.car.feature.Flags;
 import android.content.Context;
+import android.view.Display;
 import android.view.LayoutInflater;
 import android.view.View;
 import android.view.ViewGroup;
@@ -50,6 +52,7 @@ final class UserPickerAdapter extends Adapter<UserPickerAdapter.UserPickerAdapte
     private String mLoggedInText;
     private String mPrefixOtherSeatLoggedInInfo;
     private String mStoppingUserText;
+    private String mUnavailableSecureUserText;
 
     UserPickerAdapter(Context context) {
         mContext = context;
@@ -73,6 +76,13 @@ final class UserPickerAdapter extends Adapter<UserPickerAdapter.UserPickerAdapte
 
     private void setUserLoggedInInfo(UserPickerAdapterViewHolder holder, UserRecord userRecord) {
         if (!userRecord.mIsStopping && !userRecord.mIsLoggedIn) {
+            if (userRecord.mIsSecure && mDisplayId != Display.DEFAULT_DISPLAY
+                    && !Flags.supportsSecurePassengerUsers()) {
+                holder.mUserBorderImageView.setVisibility(View.INVISIBLE);
+                holder.mLoggedInTextView.setText(mUnavailableSecureUserText);
+                updateAlpha(holder, /* disabled= */ true);
+                return;
+            }
             holder.mUserBorderImageView.setVisibility(View.INVISIBLE);
             holder.mLoggedInTextView.setText("");
             updateAlpha(holder, /* disabled= */ false);
@@ -141,6 +151,7 @@ final class UserPickerAdapter extends Adapter<UserPickerAdapter.UserPickerAdapte
         mPrefixOtherSeatLoggedInInfo = mContext
                 .getString(R.string.prefix_logged_in_info_for_other_seat);
         mStoppingUserText = mContext.getString(R.string.stopping_user_text);
+        mUnavailableSecureUserText = mContext.getString(R.string.unavailable_secure_user_text);
     }
 
     // TODO(b/281729191) use RecyclerView.ItemDecoration when supported by CarUiRecyclerView
diff --git a/src/com/android/systemui/car/userpicker/UserPickerController.java b/src/com/android/systemui/car/userpicker/UserPickerController.java
index 13985575..de32b161 100644
--- a/src/com/android/systemui/car/userpicker/UserPickerController.java
+++ b/src/com/android/systemui/car/userpicker/UserPickerController.java
@@ -32,6 +32,7 @@ import static com.android.systemui.car.userpicker.HeaderState.HEADER_STATE_LOGOU
 import android.annotation.IntDef;
 import android.annotation.UserIdInt;
 import android.app.ActivityManager;
+import android.car.feature.Flags;
 import android.car.user.UserCreationResult;
 import android.content.Context;
 import android.content.pm.UserInfo;
@@ -141,7 +142,7 @@ final class UserPickerController {
         UserCreationResult result = mUserEventManager.createNewUser();
         runOnMainHandler(REQ_DISMISS_ADDING_DIALOG);
 
-        if (result.isSuccess()) {
+        if (result != null && result.isSuccess()) {
             UserInfo newUserInfo = mUserEventManager.getUserInfo(result.getUser().getIdentifier());
             UserRecord userRecord = UserRecord.create(newUserInfo, newUserInfo.name,
                     /* isStartGuestSession= */ false, /* isAddUser= */ false,
@@ -151,7 +152,7 @@ final class UserPickerController {
             mIsUserPickerClickable = false;
             handleUserSelected(userRecord);
         } else {
-            Slog.w(TAG, "Unsuccessful UserCreationResult:" + result.toString());
+            Slog.w(TAG, "Unsuccessful UserCreationResult:" + result);
             // Show snack bar message for the failure of user creation.
             runOnMainHandler(REQ_SHOW_SNACKBAR,
                     mContext.getString(R.string.create_user_failed_message));
@@ -314,6 +315,7 @@ final class UserPickerController {
                         /* isForeground= */ true,
                         /* icon= */ mUserIconProvider.getRoundedUserIcon(foregroundUser, mContext),
                         /* listenerMaker */ new OnClickListenerCreator(),
+                        mLockPatternUtils.isSecure(foregroundUser.id),
                         /* isLoggedIn= */ true, /* loggedInDisplay= */ mDisplayId,
                         /* seatLocationName= */ mCarServiceMediator.getSeatString(mDisplayId),
                         /* isStopping= */ false));
@@ -333,6 +335,7 @@ final class UserPickerController {
                     /* isForeground= */ userInfo.id == foregroundUser.id,
                     /* icon= */ mUserIconProvider.getRoundedUserIcon(userInfo, mContext),
                     /* listenerMaker */ new OnClickListenerCreator(),
+                    /* isSecure= */ mLockPatternUtils.isSecure(userInfo.id),
                     /* isLoggedIn= */ loggedInDisplayId != INVALID_DISPLAY,
                     /* loggedInDisplay= */ loggedInDisplayId,
                     /* seatLocationName= */ mCarServiceMediator.getSeatString(loggedInDisplayId),
@@ -369,6 +372,7 @@ final class UserPickerController {
                 /* isForeground= */ false,
                 /* icon= */ mUserIconProvider.getRoundedGuestDefaultIcon(mContext),
                 /* listenerMaker */ new OnClickListenerCreator(),
+                /* isSecure */ false,
                 loggedIn, loggedInDisplay,
                 /* seatLocationName= */mCarServiceMediator.getSeatString(loggedInDisplay),
                 /* isStopping= */ false);
@@ -400,13 +404,20 @@ final class UserPickerController {
                 return;
             }
 
+            boolean isFgUserStart = prevUserId == ActivityManager.getCurrentUser();
+
             // Second, check user has been already logged-in in another display or is stopping.
-            if (userRecord.mIsLoggedIn && userRecord.mLoggedInDisplay != mDisplayId
-                    || mUserPickerSharedState.isStoppingUser(userId)) {
+            if ((userRecord.mIsLoggedIn && userRecord.mLoggedInDisplay != mDisplayId)
+                    || mUserPickerSharedState.isStoppingUser(userId)
+                    || (!Flags.supportsSecurePassengerUsers() && userRecord.mIsSecure
+                    && !isFgUserStart)) {
                 String message;
                 if (userRecord.mIsStopping) {
                     message = mContext.getString(R.string.wait_for_until_stopped_message,
                             userRecord.mName);
+                } else if (!Flags.supportsSecurePassengerUsers() && userRecord.mIsSecure
+                        && !isFgUserStart) {
+                    message = mContext.getString(R.string.unavailable_secure_user_message);
                 } else {
                     message = mContext.getString(R.string.already_logged_in_message,
                             userRecord.mName, userRecord.mSeatLocationName);
@@ -443,7 +454,6 @@ final class UserPickerController {
                     return;
                 }
 
-                boolean isFgUserStart = prevUserId == ActivityManager.getCurrentUser();
                 if (!isFgUserStart && !stopUserAssignedToDisplay(prevUserId)) {
                     return;
                 }
diff --git a/src/com/android/systemui/car/userpicker/UserPickerFrameLayout.java b/src/com/android/systemui/car/userpicker/UserPickerFrameLayout.java
new file mode 100644
index 00000000..c1789dec
--- /dev/null
+++ b/src/com/android/systemui/car/userpicker/UserPickerFrameLayout.java
@@ -0,0 +1,53 @@
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
+package com.android.systemui.car.userpicker;
+
+import android.content.Context;
+import android.util.AttributeSet;
+import android.view.MotionEvent;
+import android.widget.FrameLayout;
+
+import androidx.annotation.NonNull;
+import androidx.annotation.Nullable;
+
+/** Standard FrameLayout with added touch filtering when partially obscured. */
+public class UserPickerFrameLayout extends FrameLayout {
+    public UserPickerFrameLayout(@NonNull Context context) {
+        super(context);
+    }
+
+    public UserPickerFrameLayout(@NonNull Context context,
+            @Nullable AttributeSet attrs) {
+        super(context, attrs);
+    }
+
+    public UserPickerFrameLayout(@NonNull Context context, @Nullable AttributeSet attrs,
+            int defStyleAttr) {
+        super(context, attrs, defStyleAttr);
+    }
+
+    public UserPickerFrameLayout(@NonNull Context context, @Nullable AttributeSet attrs,
+            int defStyleAttr, int defStyleRes) {
+        super(context, attrs, defStyleAttr, defStyleRes);
+    }
+
+    @Override
+    public boolean onFilterTouchEventForSecurity(MotionEvent event) {
+        return ((event.getFlags() & MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED) == 0)
+                && super.onFilterTouchEventForSecurity(event);
+    }
+}
diff --git a/src/com/android/systemui/car/userpicker/UserRecord.java b/src/com/android/systemui/car/userpicker/UserRecord.java
index 611fa092..c22b04f0 100644
--- a/src/com/android/systemui/car/userpicker/UserRecord.java
+++ b/src/com/android/systemui/car/userpicker/UserRecord.java
@@ -39,6 +39,7 @@ final class UserRecord {
     public final boolean mIsAddUser;
     public final boolean mIsForeground;
     public final Drawable mIcon;
+    public final boolean mIsSecure;
     public final boolean mIsLoggedIn;
     public final int mLoggedInDisplay;
     public final String mSeatLocationName;
@@ -48,14 +49,15 @@ final class UserRecord {
     public View.OnClickListener mOnClickListener;
 
     private UserRecord(UserInfo info, String name, boolean isStartGuestSession, boolean isAddUser,
-            boolean isForeground, Drawable icon, boolean isLoggedIn, int loggedInDisplay,
-            String seatLocationName, boolean isStopping) {
+            boolean isForeground, Drawable icon, boolean isSecure, boolean isLoggedIn,
+            int loggedInDisplay, String seatLocationName, boolean isStopping) {
         mInfo = info;
         mName = name;
         mIsStartGuestSession = isStartGuestSession;
         mIsAddUser = isAddUser;
         mIsForeground = isForeground;
         mIcon = icon;
+        mIsSecure = isSecure;
         mIsLoggedIn = isLoggedIn;
         mLoggedInDisplay = loggedInDisplay;
         mSeatLocationName = seatLocationName;
@@ -66,15 +68,16 @@ final class UserRecord {
             boolean isAddUser, boolean isForeground, Drawable icon,
             OnClickListenerCreatorBase listenerMaker) {
         return create(info, name, isStartGuestSession, isAddUser, isForeground, icon, listenerMaker,
-                false, INVALID_DISPLAY, null, false);
+                false, false, INVALID_DISPLAY, null, false);
     }
 
     static UserRecord create(UserInfo info, String name, boolean isStartGuestSession,
             boolean isAddUser, boolean isForeground, Drawable icon,
-            OnClickListenerCreatorBase listenerMaker, boolean isLoggedIn, int loggedInDisplay,
-            String seatLocationName, boolean isStopping) {
+            OnClickListenerCreatorBase listenerMaker, boolean isSecure, boolean isLoggedIn,
+            int loggedInDisplay, String seatLocationName, boolean isStopping) {
         UserRecord userRecord = new UserRecord(info, name, isStartGuestSession, isAddUser,
-                isForeground, icon, isLoggedIn, loggedInDisplay, seatLocationName, isStopping);
+                isForeground, icon, isSecure, isLoggedIn, loggedInDisplay, seatLocationName,
+                isStopping);
         listenerMaker.setUserRecord(userRecord);
         userRecord.mOnClickListener = listenerMaker.createOnClickListenerWithUserRecord();
         return userRecord;
diff --git a/src/com/android/systemui/car/users/CarDisplayTrackerImpl.java b/src/com/android/systemui/car/users/CarMUMDDisplayTrackerImpl.java
similarity index 93%
rename from src/com/android/systemui/car/users/CarDisplayTrackerImpl.java
rename to src/com/android/systemui/car/users/CarMUMDDisplayTrackerImpl.java
index 32905cba..492edf7e 100644
--- a/src/com/android/systemui/car/users/CarDisplayTrackerImpl.java
+++ b/src/com/android/systemui/car/users/CarMUMDDisplayTrackerImpl.java
@@ -43,11 +43,11 @@ import java.util.List;
 import java.util.concurrent.Executor;
 
 /**
- * Custom {@link DisplayTracker} for CarSystemUI. This class utilizes the
- * {@link CarOccupantZoneManager} to provide the relevant displays and callbacks for a particular
- * SystemUI instance running for a particular user.
+ * Custom {@link DisplayTracker} for multi-user multi-display configurations of CarSystemUI.
+ * This class utilizes the {@link CarOccupantZoneManager} to provide the relevant displays and
+ * callbacks for a particular SystemUI instance running for a particular user.
  */
-public class CarDisplayTrackerImpl implements DisplayTracker {
+public class CarMUMDDisplayTrackerImpl implements DisplayTracker {
     private final Context mContext;
     private final DisplayManager mDisplayManager;
     private final UserTracker mUserTracker;
@@ -76,7 +76,7 @@ public class CarDisplayTrackerImpl implements DisplayTracker {
                     synchronized (mDisplayCallbacks) {
                         callbacks = List.copyOf(mDisplayCallbacks);
                     }
-                    CarDisplayTrackerImpl.this.onDisplayAdded(displayId, callbacks);
+                    CarMUMDDisplayTrackerImpl.this.onDisplayAdded(displayId, callbacks);
                 }
 
                 @Override
@@ -85,7 +85,7 @@ public class CarDisplayTrackerImpl implements DisplayTracker {
                     synchronized (mDisplayCallbacks) {
                         callbacks = List.copyOf(mDisplayCallbacks);
                     }
-                    CarDisplayTrackerImpl.this.onDisplayRemoved(displayId, callbacks);
+                    CarMUMDDisplayTrackerImpl.this.onDisplayRemoved(displayId, callbacks);
                 }
 
                 @Override
@@ -94,7 +94,7 @@ public class CarDisplayTrackerImpl implements DisplayTracker {
                     synchronized (mDisplayCallbacks) {
                         callbacks = List.copyOf(mDisplayCallbacks);
                     }
-                    CarDisplayTrackerImpl.this.onDisplayChanged(displayId, callbacks);
+                    CarMUMDDisplayTrackerImpl.this.onDisplayChanged(displayId, callbacks);
                 }
             };
 
@@ -114,11 +114,11 @@ public class CarDisplayTrackerImpl implements DisplayTracker {
                     synchronized (mBrightnessCallbacks) {
                         callbacks = List.copyOf(mBrightnessCallbacks);
                     }
-                    CarDisplayTrackerImpl.this.onDisplayChanged(displayId, callbacks);
+                    CarMUMDDisplayTrackerImpl.this.onDisplayChanged(displayId, callbacks);
                 }
             };
 
-    public CarDisplayTrackerImpl(Context context, UserTracker userTracker,
+    public CarMUMDDisplayTrackerImpl(Context context, UserTracker userTracker,
             CarServiceProvider carServiceProvider, Handler backgroundHandler) {
         mContext = context;
         mDisplayManager = mContext.getSystemService(DisplayManager.class);
diff --git a/src/com/android/systemui/car/users/CarMultiUserUtilsModule.java b/src/com/android/systemui/car/users/CarMultiUserUtilsModule.java
index e528bce8..29cbc756 100644
--- a/src/com/android/systemui/car/users/CarMultiUserUtilsModule.java
+++ b/src/com/android/systemui/car/users/CarMultiUserUtilsModule.java
@@ -16,9 +16,12 @@
 
 package com.android.systemui.car.users;
 
+import static com.android.systemui.car.users.CarSystemUIUserUtil.isMUMDSystemUI;
+
 import android.app.ActivityManager;
 import android.app.IActivityManager;
 import android.content.Context;
+import android.hardware.display.DisplayManager;
 import android.os.Handler;
 import android.os.Process;
 import android.os.UserHandle;
@@ -33,6 +36,7 @@ import com.android.systemui.dagger.qualifiers.Background;
 import com.android.systemui.dump.DumpManager;
 import com.android.systemui.flags.FeatureFlagsClassic;
 import com.android.systemui.settings.DisplayTracker;
+import com.android.systemui.settings.DisplayTrackerImpl;
 import com.android.systemui.settings.UserContentResolverProvider;
 import com.android.systemui.settings.UserContextProvider;
 import com.android.systemui.settings.UserFileManager;
@@ -40,16 +44,17 @@ import com.android.systemui.settings.UserFileManagerImpl;
 import com.android.systemui.settings.UserTracker;
 
 import dagger.Binds;
+import dagger.Lazy;
 import dagger.Module;
 import dagger.Provides;
 import dagger.multibindings.ClassKey;
 import dagger.multibindings.IntoMap;
 
-import javax.inject.Provider;
-
 import kotlinx.coroutines.CoroutineDispatcher;
 import kotlinx.coroutines.CoroutineScope;
 
+import javax.inject.Provider;
+
 /**
  * Car-specific dagger Module for classes found within the com.android.systemui.settings package.
  */
@@ -101,12 +106,23 @@ public abstract class CarMultiUserUtilsModule {
     @SysUISingleton
     @Provides
     static DisplayTracker provideDisplayTracker(
+            Lazy<DisplayTrackerImpl> defaultImpl,
             Context context,
             UserTracker userTracker,
             CarServiceProvider carServiceProvider,
             @Background Handler handler
     ) {
-        return new CarDisplayTrackerImpl(context, userTracker, carServiceProvider, handler);
+        if (!isMUMDSystemUI()) {
+            return defaultImpl.get();
+        }
+        return new CarMUMDDisplayTrackerImpl(context, userTracker, carServiceProvider, handler);
+    }
+
+    @SysUISingleton
+    @Provides
+    static DisplayTrackerImpl provideDefaultDisplayTrackerImpl(DisplayManager displayManager,
+            @Background Handler handler) {
+        return new DisplayTrackerImpl(displayManager, handler);
     }
 
     @Binds
@@ -117,5 +133,8 @@ public abstract class CarMultiUserUtilsModule {
     @Binds
     abstract UserFileManager bindUserFileManager(UserFileManagerImpl impl);
 
-
+    @Binds
+    @IntoMap
+    @ClassKey(CarProfileIconUpdater.class)
+    abstract CoreStartable bindCarProfileIconUpdaterStartable(CarProfileIconUpdater iconUpdater);
 }
diff --git a/src/com/android/systemui/car/users/CarProfileIconUpdater.java b/src/com/android/systemui/car/users/CarProfileIconUpdater.java
new file mode 100644
index 00000000..ed73cead
--- /dev/null
+++ b/src/com/android/systemui/car/users/CarProfileIconUpdater.java
@@ -0,0 +1,147 @@
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
+package com.android.systemui.car.users;
+
+import android.annotation.UserIdInt;
+import android.content.BroadcastReceiver;
+import android.content.Context;
+import android.content.Intent;
+import android.content.IntentFilter;
+import android.content.pm.UserInfo;
+import android.os.UserManager;
+import android.util.ArraySet;
+
+import androidx.annotation.GuardedBy;
+
+import com.android.systemui.CoreStartable;
+import com.android.systemui.broadcast.BroadcastDispatcher;
+import com.android.systemui.car.userswitcher.UserIconProvider;
+import com.android.systemui.dagger.SysUISingleton;
+import com.android.systemui.dagger.qualifiers.Main;
+import com.android.systemui.settings.UserTracker;
+
+import java.util.Set;
+import java.util.concurrent.Executor;
+
+import javax.inject.Inject;
+
+/**
+ * CoreStartable service to keep the user icon updated and allow other components to listen to
+ * these updates.
+ */
+@SysUISingleton
+public class CarProfileIconUpdater implements CoreStartable {
+    private final Context mContext;
+    private final Executor mMainExecutor;
+    private final UserTracker mUserTracker;
+    private final UserManager mUserManager;
+    private final BroadcastDispatcher mBroadcastDispatcher;
+    private final UserIconProvider mUserIconProvider;
+    @GuardedBy("mCallbacks")
+    private final Set<Callback> mCallbacks = new ArraySet<>();
+
+    private boolean mUserLifecycleListenerRegistered;
+    private String mLastUserName;
+
+    private final UserTracker.Callback mUserChangedCallback =
+            new UserTracker.Callback() {
+                @Override
+                public void onUserChanged(int newUser, Context userContext) {
+                    mBroadcastDispatcher.unregisterReceiver(mUserUpdateReceiver);
+                    registerForUserInfoChange();
+                }
+            };
+
+    private final BroadcastReceiver mUserUpdateReceiver = new BroadcastReceiver() {
+        @Override
+        public void onReceive(Context context, Intent intent) {
+            updateUserIcon(mUserTracker.getUserId());
+        }
+    };
+
+    @Inject
+    public CarProfileIconUpdater(Context context, @Main Executor mainExecutor,
+            UserTracker userTracker, UserManager userManager,
+            BroadcastDispatcher broadcastDispatcher, UserIconProvider userIconProvider) {
+        mContext = context;
+        mMainExecutor = mainExecutor;
+        mUserTracker = userTracker;
+        mUserManager = userManager;
+        mBroadcastDispatcher = broadcastDispatcher;
+        mUserIconProvider = userIconProvider;
+    }
+
+    @Override
+    public void start() {
+        registerForUserChangeEvents();
+    }
+
+    /** Add a callback to listen to user icon updates */
+    public void addCallback(Callback callback) {
+        synchronized (mCallbacks) {
+            mCallbacks.add(callback);
+        }
+    }
+
+    /** Remove callback for user icon updates */
+    public void removeCallback(Callback callback) {
+        synchronized (mCallbacks) {
+            mCallbacks.remove(callback);
+        }
+    }
+
+    protected void updateUserIcon(@UserIdInt int userId) {
+        UserInfo currentUserInfo = mUserManager.getUserInfo(userId);
+
+        // Update user icon with the first letter of the user name
+        if (mLastUserName == null || !mLastUserName.equals(currentUserInfo.name)) {
+            mLastUserName = currentUserInfo.name;
+            mUserIconProvider.setRoundedUserIcon(currentUserInfo, mContext);
+            notifyCallbacks(userId);
+        }
+    }
+
+    protected void notifyCallbacks(@UserIdInt int userId) {
+        synchronized (mCallbacks) {
+            for (Callback callback : mCallbacks) {
+                callback.onUserIconUpdated(userId);
+            }
+        }
+    }
+
+    private void registerForUserChangeEvents() {
+        if (mUserLifecycleListenerRegistered) {
+            return;
+        }
+        mUserLifecycleListenerRegistered = true;
+        mUserTracker.addCallback(mUserChangedCallback, mMainExecutor);
+        registerForUserInfoChange();
+    }
+
+    private void registerForUserInfoChange() {
+        mLastUserName = mUserManager.getUserInfo(mUserTracker.getUserId()).name;
+        IntentFilter filter = new IntentFilter();
+        filter.addAction(Intent.ACTION_USER_INFO_CHANGED);
+        mBroadcastDispatcher.registerReceiver(mUserUpdateReceiver, filter, /* executor= */ null,
+                mUserTracker.getUserHandle());
+    }
+
+    public interface Callback {
+        /** Called when the user icon is updated for a specific userId. */
+        void onUserIconUpdated(int userId);
+    }
+}
diff --git a/src/com/android/systemui/car/users/CarSystemUIUserUtil.java b/src/com/android/systemui/car/users/CarSystemUIUserUtil.java
index 3ee69707..7f13d8c8 100644
--- a/src/com/android/systemui/car/users/CarSystemUIUserUtil.java
+++ b/src/com/android/systemui/car/users/CarSystemUIUserUtil.java
@@ -64,6 +64,16 @@ public final class CarSystemUIUserUtil {
         return UserManager.isVisibleBackgroundUsersEnabled();
     }
 
+    /**
+     * Helper function that returns {@code true} if the current SystemUI instance is the driver
+     * (primary) SystemUI on an MUMD system.
+     */
+    public static boolean isDriverMUMDSystemUI() {
+        UserHandle myUserHandle = Process.myUserHandle();
+        return isMUMDSystemUI() && !UserManager.isVisibleBackgroundUsersOnDefaultDisplayEnabled()
+                && myUserHandle.isSystem();
+    }
+
     /**
      * Helper function that returns {@code true} if the current instance of SystemUI is running as
      * a secondary user on MUMD system.
diff --git a/src/com/android/systemui/car/userswitcher/UserIconProvider.java b/src/com/android/systemui/car/userswitcher/UserIconProvider.java
index 193705ae..3f063d1b 100644
--- a/src/com/android/systemui/car/userswitcher/UserIconProvider.java
+++ b/src/com/android/systemui/car/userswitcher/UserIconProvider.java
@@ -32,10 +32,17 @@ import com.android.car.admin.ui.UserAvatarView;
 import com.android.car.internal.user.UserHelper;
 import com.android.systemui.R;
 
+import javax.inject.Inject;
+
 /**
  * Simple class for providing icons for users.
  */
 public class UserIconProvider {
+
+    @Inject
+    public UserIconProvider() {
+    }
+
     /**
      * Sets a rounded icon with the first letter of the given user name.
      * This method will update UserManager to use that icon.
diff --git a/src/com/android/systemui/car/volume/CarVolumeDialogImpl.java b/src/com/android/systemui/car/volume/CarVolumeDialogImpl.java
index ef59b530..fbc18697 100644
--- a/src/com/android/systemui/car/volume/CarVolumeDialogImpl.java
+++ b/src/com/android/systemui/car/volume/CarVolumeDialogImpl.java
@@ -35,7 +35,6 @@ import android.annotation.DrawableRes;
 import android.annotation.Nullable;
 import android.app.Dialog;
 import android.app.KeyguardManager;
-import android.app.UiModeManager;
 import android.car.Car;
 import android.car.CarOccupantZoneManager;
 import android.car.media.CarAudioManager;
@@ -78,6 +77,7 @@ import androidx.recyclerview.widget.RecyclerView;
 import com.android.systemui.R;
 import com.android.systemui.car.CarServiceProvider;
 import com.android.systemui.plugins.VolumeDialog;
+import com.android.systemui.plugins.VolumeDialogController;
 import com.android.systemui.settings.UserTracker;
 import com.android.systemui.statusbar.policy.ConfigurationController;
 import com.android.systemui.volume.Events;
@@ -123,9 +123,9 @@ public class CarVolumeDialogImpl
     private final int mExpNormalTimeout;
     private final int mExpHoveringTimeout;
     private final CarServiceProvider mCarServiceProvider;
+    private final VolumeDialogController mController;
     private final ConfigurationController mConfigurationController;
     private final UserTracker mUserTracker;
-    private final UiModeManager mUiModeManager;
     private final Executor mExecutor;
 
     private Window mWindow;
@@ -219,17 +219,18 @@ public class CarVolumeDialogImpl
                     mCarAudioManager = (CarAudioManager) car.getCarManager(Car.AUDIO_SERVICE);
                     if (mCarAudioManager != null) {
                         int volumeGroupCount = mCarAudioManager.getVolumeGroupCount(mAudioZoneId);
+                        List<VolumeItem> availableVolumeItems = new ArrayList<>();
                         // Populates volume slider items from volume groups to UI.
                         for (int groupId = 0; groupId < volumeGroupCount; groupId++) {
                             VolumeItem volumeItem = getVolumeItemForUsages(
                                     mCarAudioManager.getUsagesForVolumeGroupId(mAudioZoneId,
                                             groupId));
-                            mAvailableVolumeItems.add(volumeItem);
-                            // The first one is the default item.
-                            if (groupId == 0) {
-                                clearAllAndSetupDefaultCarVolumeLineItem(0);
-                            }
+                            availableVolumeItems.add(volumeItem);
                         }
+                        mAvailableVolumeItems.clear();
+                        mAvailableVolumeItems.addAll(availableVolumeItems);
+                        // The first one is the default item.
+                        clearAllAndSetupDefaultCarVolumeLineItem(0);
 
                         // If list is already initiated, update its content.
                         if (mVolumeItemsAdapter != null) {
@@ -277,6 +278,7 @@ public class CarVolumeDialogImpl
     public CarVolumeDialogImpl(
             Context context,
             CarServiceProvider carServiceProvider,
+            VolumeDialogController volumeDialogController,
             ConfigurationController configurationController,
             UserTracker userTracker) {
         mContext = context;
@@ -291,8 +293,8 @@ public class CarVolumeDialogImpl
                 R.integer.car_volume_dialog_display_expanded_normal_timeout);
         mExpHoveringTimeout = mContext.getResources().getInteger(
                 R.integer.car_volume_dialog_display_expanded_hovering_timeout);
+        mController = volumeDialogController;
         mConfigurationController = configurationController;
-        mUiModeManager = mContext.getSystemService(UiModeManager.class);
         mIsUiModeNight = mContext.getResources().getConfiguration().isNightModeActive();
         mExecutor = context.getMainExecutor();
     }
@@ -339,6 +341,7 @@ public class CarVolumeDialogImpl
 
     @Override
     public void destroy() {
+        mController.notifyVisible(false);
         mHandler.removeCallbacksAndMessages(/* token= */ null);
 
         mUserTracker.removeCallback(mUserTrackerCallback);
@@ -364,7 +367,6 @@ public class CarVolumeDialogImpl
 
         if (isConfigNightMode != mIsUiModeNight) {
             mIsUiModeNight = isConfigNightMode;
-            mUiModeManager.setNightModeActivated(mIsUiModeNight);
             // Call notifyDataSetChanged to force trigger the mVolumeItemsAdapter#onBindViewHolder
             // and reset items background color. notify() or invalidate() don't work here.
             mVolumeItemsAdapter.notifyDataSetChanged();
@@ -473,6 +475,7 @@ public class CarVolumeDialogImpl
         clearAllAndSetupDefaultCarVolumeLineItem(mCurrentlyDisplayingGroupId);
         mDismissing = false;
         mDialog.show();
+        mController.notifyVisible(true);
         Events.writeEvent(Events.EVENT_SHOW_DIALOG, reason, mKeyguard.isKeyguardLocked());
     }
 
diff --git a/src/com/android/systemui/car/volume/CarVolumeModule.java b/src/com/android/systemui/car/volume/CarVolumeModule.java
index ff25c2de..4b3b64f8 100644
--- a/src/com/android/systemui/car/volume/CarVolumeModule.java
+++ b/src/com/android/systemui/car/volume/CarVolumeModule.java
@@ -23,10 +23,13 @@ import android.content.Context;
 import com.android.systemui.CoreStartable;
 import com.android.systemui.car.CarServiceProvider;
 import com.android.systemui.plugins.VolumeDialog;
+import com.android.systemui.plugins.VolumeDialogController;
 import com.android.systemui.settings.UserTracker;
 import com.android.systemui.statusbar.policy.ConfigurationController;
 import com.android.systemui.volume.VolumeComponent;
 import com.android.systemui.volume.VolumeDialogComponent;
+import com.android.systemui.volume.dagger.AudioModule;
+import com.android.systemui.volume.dagger.AudioSharingEmptyImplModule;
 
 import dagger.Binds;
 import dagger.Module;
@@ -36,9 +39,14 @@ import dagger.multibindings.IntoMap;
 import dagger.multibindings.IntoSet;
 
 /** Dagger module for code in car/volume. */
-@Module
+@Module(
+        includes = {
+                AudioSharingEmptyImplModule.class,
+                AudioModule.class,
+        }
+)
 public interface CarVolumeModule {
-    /** Starts VolumeUI.  */
+    /** Starts VolumeUI. */
     @Binds
     @IntoMap
     @ClassKey(VolumeUI.class)
@@ -49,17 +57,20 @@ public interface CarVolumeModule {
     @IntoSet
     ConfigurationController.ConfigurationListener bindVolumeUIConfigChanges(VolumeUI impl);
 
-    /** */
+    /**  */
     @Binds
     VolumeComponent provideVolumeComponent(VolumeDialogComponent volumeDialogComponent);
 
-    /** */
+    /**  */
     @Provides
-    static VolumeDialog provideVolumeDialog(Context context,
+    static VolumeDialog provideVolumeDialog(
+            Context context,
             CarServiceProvider carServiceProvider,
+            VolumeDialogController volumeDialogController,
             ConfigurationController configurationController,
             UserTracker userTracker) {
-        return new CarVolumeDialogImpl(context, carServiceProvider, configurationController,
+        return new CarVolumeDialogImpl(
+                context, carServiceProvider, volumeDialogController, configurationController,
                 userTracker);
     }
 }
diff --git a/src/com/android/systemui/car/window/OverlayPanelViewController.java b/src/com/android/systemui/car/window/OverlayPanelViewController.java
index 8a97bb97..d4630879 100644
--- a/src/com/android/systemui/car/window/OverlayPanelViewController.java
+++ b/src/com/android/systemui/car/window/OverlayPanelViewController.java
@@ -30,6 +30,7 @@ import android.view.View;
 import android.view.ViewTreeObserver;
 
 import androidx.annotation.CallSuper;
+import androidx.annotation.Nullable;
 
 import com.android.systemui.car.CarDeviceProvisionedController;
 import com.android.systemui.dagger.qualifiers.Main;
@@ -375,12 +376,12 @@ public abstract class OverlayPanelViewController extends OverlayViewController {
         }
         mIsAnimating = true;
         mIsTracking = true;
-        ValueAnimator animator = ValueAnimator.ofFloat(from, to);
-        animator.addUpdateListener(
-                animation -> {
-                    float animatedValue = (Float) animation.getAnimatedValue();
-                    setViewClipBounds((int) animatedValue);
-                });
+
+        Animator animator = getCustomAnimator(from, to, velocity, isClosing);
+        if (animator == null) {
+            animator = getDefaultAnimator(from, to);
+        }
+
         animator.addListener(new AnimatorListenerAdapter() {
             @Override
             public void onAnimationEnd(Animator animation) {
@@ -394,6 +395,8 @@ public abstract class OverlayPanelViewController extends OverlayViewController {
                 } else {
                     onExpandAnimationEnd();
                     setPanelExpanded(true);
+                    setViewClipBounds((int) to);
+
                 }
             }
         });
@@ -401,6 +404,22 @@ public abstract class OverlayPanelViewController extends OverlayViewController {
         animator.start();
     }
 
+    /** Specify a custom animator to be run when the panel state is changing. */
+    @Nullable
+    protected Animator getCustomAnimator(float from, float to, float velocity, boolean isClosing) {
+        return null;
+    }
+
+    private Animator getDefaultAnimator(float from, float to) {
+        ValueAnimator animator = ValueAnimator.ofFloat(from, to);
+        animator.addUpdateListener(
+                animation -> {
+                    float animatedValue = (Float) animation.getAnimatedValue();
+                    setViewClipBounds((int) animatedValue);
+                });
+        return animator;
+    }
+
     protected void resetPanelVisibility() {
         setPanelVisible(false);
         getLayout().setClipBounds(null);
diff --git a/src/com/android/systemui/car/window/OverlayWindowModule.java b/src/com/android/systemui/car/window/OverlayWindowModule.java
index 7bac9dd9..756b39b8 100644
--- a/src/com/android/systemui/car/window/OverlayWindowModule.java
+++ b/src/com/android/systemui/car/window/OverlayWindowModule.java
@@ -24,11 +24,13 @@ import com.android.systemui.car.notification.TopNotificationPanelViewMediator;
 import com.android.systemui.car.systemdialogs.SystemDialogsViewMediator;
 import com.android.systemui.car.userswitcher.FullscreenUserSwitcherViewMediator;
 import com.android.systemui.car.userswitcher.UserSwitchTransitionViewMediator;
+import com.android.systemui.statusbar.policy.ConfigurationController.ConfigurationListener;
 
 import dagger.Binds;
 import dagger.Module;
 import dagger.multibindings.ClassKey;
 import dagger.multibindings.IntoMap;
+import dagger.multibindings.IntoSet;
 
 /**
  * Dagger injection module for {@link SystemUIOverlayWindowManager}
@@ -91,4 +93,10 @@ public abstract class OverlayWindowModule {
     @ClassKey(SystemDialogsViewMediator.class)
     public abstract OverlayViewMediator bindSystemDialogsViewMediator(
             SystemDialogsViewMediator sysui);
+
+    /** Listen to config changes for SystemUIOverlayWindowManager. */
+    @Binds
+    @IntoSet
+    public abstract ConfigurationListener bindSystemUIOverlayWindowManagerConfigChanges(
+            SystemUIOverlayWindowManager systemUIOverlayWindowManager);
 }
diff --git a/src/com/android/systemui/car/window/SystemUIOverlayWindowManager.java b/src/com/android/systemui/car/window/SystemUIOverlayWindowManager.java
index 40fd28b8..afe1d8d1 100644
--- a/src/com/android/systemui/car/window/SystemUIOverlayWindowManager.java
+++ b/src/com/android/systemui/car/window/SystemUIOverlayWindowManager.java
@@ -17,11 +17,16 @@
 package com.android.systemui.car.window;
 
 import android.content.Context;
+import android.content.res.Configuration;
+import android.os.Build;
 import android.util.Log;
 
 import com.android.systemui.CoreStartable;
 import com.android.systemui.R;
+import com.android.systemui.car.users.CarSystemUIUserUtil;
 import com.android.systemui.dagger.SysUISingleton;
+import com.android.systemui.settings.UserTracker;
+import com.android.systemui.statusbar.policy.ConfigurationController;
 
 import java.lang.reflect.Constructor;
 import java.lang.reflect.InvocationTargetException;
@@ -35,18 +40,23 @@ import javax.inject.Provider;
  * OverlayViewController}(s) to allow for the correct visibility of system bars.
  */
 @SysUISingleton
-public class SystemUIOverlayWindowManager implements CoreStartable {
+public class SystemUIOverlayWindowManager implements CoreStartable,
+        ConfigurationController.ConfigurationListener {
+    private static final boolean DEBUG = Build.isDebuggable();
     private static final String TAG = "SystemUIOverlayWM";
     private final Context mContext;
     private final Map<Class<?>, Provider<OverlayViewMediator>>
             mContentMediatorCreators;
     private final OverlayViewGlobalStateController mOverlayViewGlobalStateController;
+    private boolean mSystemUiOverlayViewsMediatorsStarted = false;
 
     @Inject
     public SystemUIOverlayWindowManager(
             Context context,
             Map<Class<?>, Provider<OverlayViewMediator>> contentMediatorCreators,
-            OverlayViewGlobalStateController overlayViewGlobalStateController) {
+            OverlayViewGlobalStateController overlayViewGlobalStateController,
+            UserTracker userTracker
+    ) {
         mContext = context;
         mContentMediatorCreators = contentMediatorCreators;
         mOverlayViewGlobalStateController = overlayViewGlobalStateController;
@@ -54,13 +64,25 @@ public class SystemUIOverlayWindowManager implements CoreStartable {
 
     @Override
     public void start() {
+        // TODO(b/282070679): ideally resources should be ready in start(), so no need to wait for
+        //  config change.
+        if (!hasPendingConfigChangeForSecondaryUser()) {
+            startInternal();
+        }
+    }
+
+    private void startInternal() {
         String[] names = mContext.getResources().getStringArray(
                 R.array.config_carSystemUIOverlayViewsMediators);
         startServices(names);
+        mSystemUiOverlayViewsMediatorsStarted = true;
     }
 
     private void startServices(String[] services) {
         for (String clsName : services) {
+            if (DEBUG) {
+                Log.d(TAG, "Initialization of " + clsName + "for user: " + mContext.getUserId());
+            }
             long ti = System.currentTimeMillis();
             try {
                 OverlayViewMediator obj = resolveContentMediator(clsName);
@@ -98,4 +120,20 @@ public class SystemUIOverlayWindowManager implements CoreStartable {
             return null;
         }
     }
+
+    @Override
+    public void onConfigChanged(Configuration newConfig) {
+        if (DEBUG) {
+            Log.d(TAG, "onConfigChanged for user: " + mContext.getUserId());
+        }
+        if (!mSystemUiOverlayViewsMediatorsStarted) {
+            startInternal();
+        }
+    }
+
+    private boolean hasPendingConfigChangeForSecondaryUser() {
+        return mContext.getResources().getBoolean(R.bool.config_enableSecondaryUserRRO) && (
+                CarSystemUIUserUtil.isSecondaryMUMDSystemUI()
+                        || CarSystemUIUserUtil.isMUPANDSystemUI());
+    }
 }
diff --git a/src/com/android/systemui/car/wm/CarFullscreenTaskMonitorListener.java b/src/com/android/systemui/car/wm/CarFullscreenTaskMonitorListener.java
index 8f7a2022..50b52f6e 100644
--- a/src/com/android/systemui/car/wm/CarFullscreenTaskMonitorListener.java
+++ b/src/com/android/systemui/car/wm/CarFullscreenTaskMonitorListener.java
@@ -16,16 +16,9 @@
 
 package com.android.systemui.car.wm;
 
-import static android.app.WindowConfiguration.WINDOWING_MODE_FULLSCREEN;
-
 import android.app.ActivityManager;
-import android.car.Car;
-import android.car.app.CarActivityManager;
 import android.content.Context;
-import android.hardware.display.DisplayManager;
 import android.util.Log;
-import android.util.Slog;
-import android.view.Display;
 import android.view.SurfaceControl;
 
 import com.android.systemui.car.CarServiceProvider;
@@ -34,17 +27,18 @@ import com.android.wm.shell.common.SyncTransactionQueue;
 import com.android.wm.shell.fullscreen.FullscreenTaskListener;
 import com.android.wm.shell.recents.RecentTasksController;
 import com.android.wm.shell.sysui.ShellInit;
+import com.android.wm.shell.taskview.TaskViewTransitions;
 import com.android.wm.shell.windowdecor.WindowDecorViewModel;
 
-import java.util.ArrayList;
-import java.util.List;
 import java.util.Optional;
-import java.util.concurrent.atomic.AtomicReference;
 
 /**
  * The Car version of {@link FullscreenTaskListener}, which reports Task lifecycle to CarService
  * only when the {@link CarSystemUIProxyImpl} should be registered.
  *
+ * Please note that this reports FULLSCREEN + MULTI_WINDOW tasks to the CarActivityService but
+ * excludes the tasks that are associated with a taskview.
+ *
  * <p>When {@link CarSystemUIProxyImpl#shouldRegisterCarSystemUIProxy(Context)} returns true, the
  * task organizer is registered by the system ui alone and hence SystemUI is responsible to act as
  * a task monitor for the car service.
@@ -54,14 +48,29 @@ import java.util.concurrent.atomic.AtomicReference;
  * multiple task events to the car service.
  */
 public class CarFullscreenTaskMonitorListener extends FullscreenTaskListener {
-
-    private static final String TAG = "CarFullscrTaskMonitor";
-    private static final boolean DBG = Log.isLoggable(TAG, Log.DEBUG);
-    private final AtomicReference<CarActivityManager> mCarActivityManagerRef =
-            new AtomicReference<>();
+    static final String TAG = "CarFullscrTaskMonitor";
+    static final boolean DBG = Log.isLoggable(TAG, Log.DEBUG);
     private final ShellTaskOrganizer mShellTaskOrganizer;
-    private final DisplayManager mDisplayManager;
-    private final boolean mShouldConnectToCarActivityService;
+    private final CarServiceTaskReporter mCarServiceTaskReporter;
+
+    private final ShellTaskOrganizer.TaskListener mMultiWindowTaskListener =
+            new ShellTaskOrganizer.TaskListener() {
+                @Override
+                public void onTaskAppeared(ActivityManager.RunningTaskInfo taskInfo,
+                        SurfaceControl leash) {
+                    mCarServiceTaskReporter.reportTaskAppeared(taskInfo, leash);
+                }
+
+                @Override
+                public void onTaskInfoChanged(ActivityManager.RunningTaskInfo taskInfo) {
+                    mCarServiceTaskReporter.reportTaskInfoChanged(taskInfo);
+                }
+
+                @Override
+                public void onTaskVanished(ActivityManager.RunningTaskInfo taskInfo) {
+                    mCarServiceTaskReporter.reportTaskVanished(taskInfo);
+                }
+            };
 
     public CarFullscreenTaskMonitorListener(
             Context context,
@@ -70,117 +79,37 @@ public class CarFullscreenTaskMonitorListener extends FullscreenTaskListener {
             ShellTaskOrganizer shellTaskOrganizer,
             SyncTransactionQueue syncQueue,
             Optional<RecentTasksController> recentTasksOptional,
-            Optional<WindowDecorViewModel> windowDecorViewModelOptional) {
+            Optional<WindowDecorViewModel> windowDecorViewModelOptional,
+            TaskViewTransitions taskViewTransitions) {
         super(shellInit, shellTaskOrganizer, syncQueue, recentTasksOptional,
                 windowDecorViewModelOptional);
-
         mShellTaskOrganizer = shellTaskOrganizer;
-        mDisplayManager = context.getSystemService(DisplayManager.class);
-        // Rely on whether or not CarSystemUIProxy should be registered to account for these cases:
-        // 1. Legacy system where System UI + launcher both register a TaskOrganizer.
-        //    CarFullScreenTaskMonitorListener will not forward the task lifecycle to the car
-        //    service, as launcher has its own FullScreenTaskMonitorListener.
-        // 2. MUMD system where only System UI registers a TaskOrganizer but the user associated
-        //    with the current display is not a system user. CarSystemUIProxy will be registered
-        //    for system user alone and hence CarFullScreenTaskMonitorListener should be registered
-        //    only then.
-        mShouldConnectToCarActivityService =
-                CarSystemUIProxyImpl.shouldRegisterCarSystemUIProxy(context);
-
-        if (mShouldConnectToCarActivityService) {
-            carServiceProvider.addListener(this::onCarConnected);
-        }
+        mCarServiceTaskReporter = new CarServiceTaskReporter(context, carServiceProvider,
+                taskViewTransitions,
+                shellTaskOrganizer);
+
+        shellInit.addInitCallback(
+                () -> mShellTaskOrganizer.addListenerForType(mMultiWindowTaskListener,
+                        ShellTaskOrganizer.TASK_LISTENER_TYPE_MULTI_WINDOW),
+                this);
     }
 
     @Override
     public void onTaskAppeared(ActivityManager.RunningTaskInfo taskInfo,
             SurfaceControl leash) {
         super.onTaskAppeared(taskInfo, leash);
-
-        if (!mShouldConnectToCarActivityService) {
-            if (DBG) {
-                Slog.w(TAG, "onTaskAppeared() handled in SystemUI as conditions not met for "
-                        + "connecting to car service.");
-            }
-            return;
-        }
-
-        CarActivityManager carAM = mCarActivityManagerRef.get();
-        if (carAM != null) {
-            carAM.onTaskAppeared(taskInfo, leash);
-        } else {
-            Slog.w(TAG, "CarActivityManager is null, skip onTaskAppeared: taskInfo=" + taskInfo);
-        }
+        mCarServiceTaskReporter.reportTaskAppeared(taskInfo, leash);
     }
 
     @Override
     public void onTaskInfoChanged(ActivityManager.RunningTaskInfo taskInfo) {
         super.onTaskInfoChanged(taskInfo);
-
-        if (!mShouldConnectToCarActivityService) {
-            if (DBG) {
-                Slog.w(TAG, "onTaskInfoChanged() handled in SystemUI as conditions not met for "
-                        + "connecting to car service.");
-            }
-            return;
-        }
-
-        CarActivityManager carAM = mCarActivityManagerRef.get();
-        if (carAM != null) {
-            carAM.onTaskInfoChanged(taskInfo);
-        } else {
-            Slog.w(TAG, "CarActivityManager is null, skip onTaskInfoChanged: taskInfo=" + taskInfo);
-        }
+        mCarServiceTaskReporter.reportTaskInfoChanged(taskInfo);
     }
 
     @Override
     public void onTaskVanished(ActivityManager.RunningTaskInfo taskInfo) {
         super.onTaskVanished(taskInfo);
-
-        if (!mShouldConnectToCarActivityService) {
-            if (DBG) {
-                Slog.w(TAG, "onTaskVanished() handled in SystemUI as conditions not met for "
-                        + "connecting to car service.");
-            }
-            return;
-        }
-
-        CarActivityManager carAM = mCarActivityManagerRef.get();
-        if (carAM != null) {
-            carAM.onTaskVanished(taskInfo);
-        } else {
-            Slog.w(TAG, "CarActivityManager is null, skip onTaskVanished: taskInfo=" + taskInfo);
-        }
-    }
-
-    private void onCarConnected(Car car) {
-        mCarActivityManagerRef.set(car.getCarManager(CarActivityManager.class));
-        // The tasks that have already appeared need to be reported to the CarActivityManager.
-        // The code uses null as the leash because there is no way to get the leash at the moment.
-        // And the leash is only required for mirroring cases. Those tasks will anyway appear after
-        // the car service is connected and hence will go via the {@link #onTaskAppeared} flow.
-        List<ActivityManager.RunningTaskInfo> runningFullscreenTaskInfos =
-                getRunningFullscreenTasks();
-        for (ActivityManager.RunningTaskInfo runningTaskInfo : runningFullscreenTaskInfos) {
-            Slog.d(TAG, "Sending onTaskAppeared for an already existing fullscreen task: "
-                    + runningTaskInfo.taskId);
-            mCarActivityManagerRef.get().onTaskAppeared(runningTaskInfo, null);
-        }
-    }
-
-    private List<ActivityManager.RunningTaskInfo> getRunningFullscreenTasks() {
-        Display[] displays = mDisplayManager.getDisplays();
-        List<ActivityManager.RunningTaskInfo> fullScreenTaskInfos = new ArrayList<>();
-        for (int i = 0; i < displays.length; i++) {
-            List<ActivityManager.RunningTaskInfo> taskInfos =
-                    mShellTaskOrganizer.getRunningTasks(displays[i].getDisplayId());
-            for (ActivityManager.RunningTaskInfo taskInfo : taskInfos) {
-                // In Auto, only TaskView tasks have WINDOWING_MODE_MULTI_WINDOW as of now.
-                if (taskInfo.getWindowingMode() == WINDOWING_MODE_FULLSCREEN) {
-                    fullScreenTaskInfos.add(taskInfo);
-                }
-            }
-        }
-        return fullScreenTaskInfos;
+        mCarServiceTaskReporter.reportTaskVanished(taskInfo);
     }
 }
diff --git a/src/com/android/systemui/car/wm/CarServiceTaskReporter.java b/src/com/android/systemui/car/wm/CarServiceTaskReporter.java
new file mode 100644
index 00000000..9e21552d
--- /dev/null
+++ b/src/com/android/systemui/car/wm/CarServiceTaskReporter.java
@@ -0,0 +1,174 @@
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
+package com.android.systemui.car.wm;
+
+import static com.android.systemui.car.wm.CarFullscreenTaskMonitorListener.DBG;
+import static com.android.systemui.car.wm.CarFullscreenTaskMonitorListener.TAG;
+
+import android.app.ActivityManager;
+import android.car.Car;
+import android.car.app.CarActivityManager;
+import android.content.Context;
+import android.hardware.display.DisplayManager;
+import android.util.Slog;
+import android.view.Display;
+import android.view.SurfaceControl;
+
+import com.android.systemui.car.CarServiceProvider;
+import com.android.wm.shell.ShellTaskOrganizer;
+import com.android.wm.shell.taskview.TaskViewTransitions;
+
+import java.util.ArrayList;
+import java.util.List;
+import java.util.concurrent.atomic.AtomicReference;
+
+/**
+ * This class reports the task events to CarService using {@link CarActivityManager}.
+ */
+final class CarServiceTaskReporter {
+    private final DisplayManager mDisplayManager;
+    private final AtomicReference<CarActivityManager> mCarActivityManagerRef =
+            new AtomicReference<>();
+    private final boolean mShouldConnectToCarActivityService;
+    private final TaskViewTransitions mTaskViewTransitions;
+    private final ShellTaskOrganizer mShellTaskOrganizer;
+
+    CarServiceTaskReporter(Context context, CarServiceProvider carServiceProvider,
+            TaskViewTransitions taskViewTransitions,
+            ShellTaskOrganizer shellTaskOrganizer) {
+        mDisplayManager = context.getSystemService(DisplayManager.class);
+        mTaskViewTransitions = taskViewTransitions;
+        // Rely on whether or not CarSystemUIProxy should be registered to account for these
+        // cases:
+        // 1. Legacy system where System UI + launcher both register a TaskOrganizer.
+        //    CarFullScreenTaskMonitorListener will not forward the task lifecycle to the car
+        //    service, as launcher has its own FullScreenTaskMonitorListener.
+        // 2. MUMD system where only System UI registers a TaskOrganizer but the user associated
+        //    with the current display is not a system user. CarSystemUIProxy will be registered
+        //    for system user alone and hence CarFullScreenTaskMonitorListener should be
+        //    registered only then.
+        mShouldConnectToCarActivityService = CarSystemUIProxyImpl.shouldRegisterCarSystemUIProxy(
+                context);
+        mShellTaskOrganizer = shellTaskOrganizer;
+
+        if (mShouldConnectToCarActivityService) {
+            carServiceProvider.addListener(this::onCarConnected);
+        }
+    }
+
+    public void reportTaskAppeared(ActivityManager.RunningTaskInfo taskInfo, SurfaceControl leash) {
+        if (!mShouldConnectToCarActivityService) {
+            if (DBG) {
+                Slog.w(TAG, "onTaskAppeared() handled in SystemUI as conditions not met for "
+                        + "connecting to car service.");
+            }
+            return;
+        }
+
+        if (mTaskViewTransitions.isTaskViewTask(taskInfo)) {
+            if (DBG) {
+                Slog.w(TAG, "not reporting onTaskAppeared for taskview task = " + taskInfo.taskId);
+            }
+            return;
+        }
+        CarActivityManager carAM = mCarActivityManagerRef.get();
+        if (carAM != null) {
+            carAM.onTaskAppeared(taskInfo, leash);
+        } else {
+            Slog.w(TAG, "CarActivityManager is null, skip onTaskAppeared: taskInfo=" + taskInfo);
+        }
+    }
+
+    public void reportTaskInfoChanged(ActivityManager.RunningTaskInfo taskInfo) {
+        if (!mShouldConnectToCarActivityService) {
+            if (DBG) {
+                Slog.w(TAG, "onTaskInfoChanged() handled in SystemUI as conditions not met for "
+                        + "connecting to car service.");
+            }
+            return;
+        }
+
+        if (mTaskViewTransitions.isTaskViewTask(taskInfo)) {
+            if (DBG) {
+                Slog.w(TAG,
+                        "not reporting onTaskInfoChanged for taskview task = " + taskInfo.taskId);
+            }
+            return;
+        }
+
+        CarActivityManager carAM = mCarActivityManagerRef.get();
+        if (carAM != null) {
+            carAM.onTaskInfoChanged(taskInfo);
+        } else {
+            Slog.w(TAG, "CarActivityManager is null, skip onTaskInfoChanged: taskInfo=" + taskInfo);
+        }
+    }
+
+    public void reportTaskVanished(ActivityManager.RunningTaskInfo taskInfo) {
+        if (!mShouldConnectToCarActivityService) {
+            if (DBG) {
+                Slog.w(TAG, "onTaskVanished() handled in SystemUI as conditions not met for "
+                        + "connecting to car service.");
+            }
+            return;
+        }
+
+        if (mTaskViewTransitions.isTaskViewTask(taskInfo)) {
+            if (DBG) {
+                Slog.w(TAG, "not reporting onTaskVanished for taskview task = " + taskInfo.taskId);
+            }
+            return;
+        }
+
+        CarActivityManager carAM = mCarActivityManagerRef.get();
+        if (carAM != null) {
+            carAM.onTaskVanished(taskInfo);
+        } else {
+            Slog.w(TAG, "CarActivityManager is null, skip onTaskVanished: taskInfo=" + taskInfo);
+        }
+    }
+
+    private void onCarConnected(Car car) {
+        mCarActivityManagerRef.set(car.getCarManager(CarActivityManager.class));
+        // The tasks that have already appeared need to be reported to the CarActivityManager.
+        // The code uses null as the leash because there is no way to get the leash at the moment.
+        // And the leash is only required for mirroring cases. Those tasks will anyway appear
+        // after the car service is connected and hence will go via the {@link #onTaskAppeared}
+        // flow.
+        List<ActivityManager.RunningTaskInfo> runningTasks = getRunningNonTaskViewTasks();
+        for (ActivityManager.RunningTaskInfo runningTaskInfo : runningTasks) {
+            Slog.d(TAG, "Sending onTaskAppeared for an already existing task: "
+                    + runningTaskInfo.taskId);
+            mCarActivityManagerRef.get().onTaskAppeared(runningTaskInfo, /* leash = */ null);
+        }
+    }
+
+    private List<ActivityManager.RunningTaskInfo> getRunningNonTaskViewTasks() {
+        Display[] displays = mDisplayManager.getDisplays();
+        List<ActivityManager.RunningTaskInfo> tasksToReturn = new ArrayList<>();
+        for (int i = 0; i < displays.length; i++) {
+            List<ActivityManager.RunningTaskInfo> taskInfos = mShellTaskOrganizer.getRunningTasks(
+                    displays[i].getDisplayId());
+            for (ActivityManager.RunningTaskInfo taskInfo : taskInfos) {
+                if (!mTaskViewTransitions.isTaskViewTask(taskInfo)) {
+                    tasksToReturn.add(taskInfo);
+                }
+            }
+        }
+        return tasksToReturn;
+    }
+}
diff --git a/src/com/android/systemui/car/wm/activity/ActivityBlockingActivity.java b/src/com/android/systemui/car/wm/activity/ActivityBlockingActivity.java
index a0bf0ffa..925995fc 100644
--- a/src/com/android/systemui/car/wm/activity/ActivityBlockingActivity.java
+++ b/src/com/android/systemui/car/wm/activity/ActivityBlockingActivity.java
@@ -15,6 +15,8 @@
  */
 package com.android.systemui.car.wm.activity;
 
+import static android.app.WindowConfiguration.WINDOWING_MODE_MULTI_WINDOW;
+
 import static com.android.systemui.car.Flags.configAppBlockingActivities;
 
 import android.app.ActivityManager;
@@ -28,6 +30,7 @@ import android.content.ActivityNotFoundException;
 import android.content.ComponentName;
 import android.content.Context;
 import android.content.Intent;
+import android.content.pm.PackageManager;
 import android.graphics.Insets;
 import android.graphics.Rect;
 import android.hardware.display.DisplayManager;
@@ -40,11 +43,13 @@ import android.os.UserHandle;
 import android.text.TextUtils;
 import android.util.Log;
 import android.util.Slog;
+import android.view.Display;
 import android.view.DisplayInfo;
 import android.view.View;
 import android.view.ViewTreeObserver;
 import android.view.WindowInsets;
 import android.widget.Button;
+import android.widget.LinearLayout;
 import android.widget.TextView;
 
 import androidx.fragment.app.FragmentActivity;
@@ -153,9 +158,11 @@ public class ActivityBlockingActivity extends FragmentActivity {
 
         setupGLSurface();
 
-        if (!configAppBlockingActivities()) {
+        if (!configAppBlockingActivities()
+                || !getResources().getBoolean(R.bool.config_enableAppBlockingActivities)) {
             Slog.d(TAG, "Ignoring app blocking activity feature");
-        } else if (getResources().getBoolean(R.bool.config_enableAppBlockingActivities)) {
+            displayBlockingContent();
+        } else {
             mBlockedActivityName = getIntent().getStringExtra(
                     CarPackageManager.BLOCKING_INTENT_EXTRA_BLOCKED_ACTIVITY_NAME);
             BlockerViewModel blockerViewModel = new ViewModelProvider(this, mViewModelFactory)
@@ -173,7 +180,7 @@ public class ActivityBlockingActivity extends FragmentActivity {
                             getString(R.string.config_dialerBlockingActivity));
                     case MEDIA -> startBlockingActivity(
                             getString(R.string.config_mediaBlockingActivity));
-                    case NONE -> { /* no-op */ }
+                    case NONE -> displayBlockingContent();
                 }
             });
         }
@@ -242,7 +249,14 @@ public class ActivityBlockingActivity extends FragmentActivity {
         DisplayInfo displayInfo = new DisplayInfo();
 
         int displayId = getDisplayId();
-        displayManager.getDisplay(displayId).getDisplayInfo(displayInfo);
+        Display display = displayManager.getDisplay(displayId);
+        if (display == null) {
+            Slog.e(TAG, "Can't find display handle for : " + displayId);
+            // force close this activity since it has no home
+            finish();
+            return;
+        }
+        display.getDisplayInfo(displayInfo);
 
         Rect windowRect = getAppWindowRect();
 
@@ -284,6 +298,14 @@ public class ActivityBlockingActivity extends FragmentActivity {
         return new Rect(leftX, topY, rightX, bottomY);
     }
 
+    private void displayBlockingContent() {
+        LinearLayout blockingContent = findViewById(R.id.activity_blocking_content);
+
+        if (blockingContent != null) {
+            blockingContent.setVisibility(View.VISIBLE);
+        }
+    }
+
     private void displayExitButton() {
         String exitButtonText = getExitButtonText();
 
@@ -326,6 +348,17 @@ public class ActivityBlockingActivity extends FragmentActivity {
                 continue;
             }
 
+            // TODO(b/359583186): Remove this check when targets with splitscreen multitasking
+            // feature are moved to DaViews.
+            if (getApplicationContext().getPackageManager().hasSystemFeature(
+                    PackageManager.FEATURE_CAR_SPLITSCREEN_MULTITASKING)
+                    && taskInfo.getWindowingMode() != WINDOWING_MODE_MULTI_WINDOW) {
+                // targets which have splitscreen multitasking feature, can have other visible
+                // tasks such as home which are not blocked. Only consider tasks with multi
+                // window windowing mode.
+                continue;
+            }
+
             if (getComponentName().equals(taskInfo.topActivity)) {
                 // quit when stack with the blocking activity is encountered because the last seen
                 // task will be the topStackBehindAba.
@@ -486,6 +519,10 @@ public class ActivityBlockingActivity extends FragmentActivity {
     }
 
     private void startBlockingActivity(String blockingActivity) {
+        if (isFinishing()) {
+            return;
+        }
+
         int userOnDisplay = getUserForCurrentDisplay();
         if (userOnDisplay == CarOccupantZoneManager.INVALID_USER_ID) {
             Slog.w(TAG, "Can't find user on display " + getDisplayId()
@@ -499,6 +536,7 @@ public class ActivityBlockingActivity extends FragmentActivity {
         intent.putExtra(Intent.EXTRA_COMPONENT_NAME, mBlockedActivityName);
         try {
             startActivityAsUser(intent, UserHandle.of(userOnDisplay));
+            finish();
         } catch (ActivityNotFoundException ex) {
             Slog.e(TAG, "Unable to resolve blocking activity " + blockingActivity, ex);
         } catch (RuntimeException ex) {
diff --git a/src/com/android/systemui/car/wm/taskview/RemoteCarTaskViewServerImpl.java b/src/com/android/systemui/car/wm/taskview/RemoteCarTaskViewServerImpl.java
index 11060e0f..5d53d3a9 100644
--- a/src/com/android/systemui/car/wm/taskview/RemoteCarTaskViewServerImpl.java
+++ b/src/com/android/systemui/car/wm/taskview/RemoteCarTaskViewServerImpl.java
@@ -118,7 +118,8 @@ public class RemoteCarTaskViewServerImpl implements TaskViewBase {
             ensureManageSystemUIPermission(mContext);
             ActivityOptions opt = ActivityOptions.fromBundle(options);
             // Need this for the pending intent to work under BAL hardening.
-            opt.setPendingIntentBackgroundActivityLaunchAllowedByPermission(true);
+            opt.setPendingIntentBackgroundActivityStartMode(
+                    ActivityOptions.MODE_BACKGROUND_ACTIVITY_START_ALLOW_ALWAYS);
             mTaskViewTaskController.startActivity(
                     pendingIntent,
                     fillInIntent,
@@ -249,7 +250,7 @@ public class RemoteCarTaskViewServerImpl implements TaskViewBase {
             }
             WindowContainerTransaction wct = new WindowContainerTransaction();
             wct.addInsetsSource(mTaskViewTaskController.getTaskInfo().token,
-                    mInsetsOwner, index, type, frame, /* boundingRects = */ null);
+                    mInsetsOwner, index, type, frame, /* boundingRects = */ null, /* flags = */ 0);
             mShellTaskOrganizer.applyTransaction(wct);
         }
 
@@ -389,7 +390,7 @@ public class RemoteCarTaskViewServerImpl implements TaskViewBase {
             final Rect frame = mInsets.valueAt(i);
             wct.addInsetsSource(mTaskViewTaskController.getTaskInfo().token,
                     mInsetsOwner, InsetsSource.getIndex(id), InsetsSource.getType(id), frame,
-                    null /* boundingRects */);
+                    null /* boundingRects */, 0 /* flags */);
         }
         mShellTaskOrganizer.applyTransaction(wct);
     }
diff --git a/src/com/android/systemui/car/wm/taskview/RemoteCarTaskViewTransitions.java b/src/com/android/systemui/car/wm/taskview/RemoteCarTaskViewTransitions.java
index 83ed5e58..7a3750ac 100644
--- a/src/com/android/systemui/car/wm/taskview/RemoteCarTaskViewTransitions.java
+++ b/src/com/android/systemui/car/wm/taskview/RemoteCarTaskViewTransitions.java
@@ -46,6 +46,7 @@ import javax.inject.Inject;
  */
 @WMSingleton
 public final class RemoteCarTaskViewTransitions implements Transitions.TransitionHandler {
+    // TODO(b/359584498): Add unit tests for this class.
     private static final String TAG = "CarTaskViewTransit";
 
     private final Transitions mTransitions;
@@ -82,18 +83,7 @@ public final class RemoteCarTaskViewTransitions implements Transitions.Transitio
         //  on a per taskview basis and remove the ACTIVITY_TYPE_HOME check.
         if (isHome(request.getTriggerTask())
                 && TransitionUtil.isOpeningType(request.getType())) {
-            wct = new WindowContainerTransaction();
-            for (int i = mCarSystemUIProxy.get().getAllTaskViews().size() - 1; i >= 0; i--) {
-                ActivityManager.RunningTaskInfo task =
-                        mCarSystemUIProxy.get().getAllTaskViews().valueAt(i).getTaskInfo();
-                if (task == null) continue;
-                if (task.displayId != request.getTriggerTask().displayId) continue;
-                if (Log.isLoggable(TAG, Log.DEBUG)) {
-                    Slog.d(TAG, "Adding transition work to bring the embedded "
-                            + task.topActivity + " to top");
-                }
-                wct.reorder(task.token, true);
-            }
+            wct = reorderEmbeddedTasksToTop(request.getTriggerTask().displayId);
         }
 
         // TODO(b/333923667): Think of moving this to CarUiPortraitSystemUI instead.
@@ -119,12 +109,29 @@ public final class RemoteCarTaskViewTransitions implements Transitions.Transitio
         return taskInfo.getWindowingMode() == WindowConfiguration.WINDOWING_MODE_FULLSCREEN;
     }
 
+    private WindowContainerTransaction reorderEmbeddedTasksToTop(int endDisplayId) {
+        WindowContainerTransaction wct = new WindowContainerTransaction();
+        for (int i = mCarSystemUIProxy.get().getAllTaskViews().size() - 1; i >= 0; i--) {
+            // TODO(b/359586295): Handle restarting of tasks if required.
+            ActivityManager.RunningTaskInfo task =
+                    mCarSystemUIProxy.get().getAllTaskViews().valueAt(i).getTaskInfo();
+            if (task == null) continue;
+            if (task.displayId != endDisplayId) continue;
+            if (Log.isLoggable(TAG, Log.DEBUG)) {
+                Slog.d(TAG, "Adding transition work to bring the embedded " + task.topActivity
+                        + " to top");
+            }
+            wct.reorder(task.token, true);
+        }
+        return wct;
+    }
+
     @Override
     public boolean startAnimation(@NonNull IBinder transition, @NonNull TransitionInfo info,
             @NonNull SurfaceControl.Transaction startTransaction,
             @NonNull SurfaceControl.Transaction finishTransaction,
             @NonNull Transitions.TransitionFinishCallback finishCallback) {
-        // No animation required for now.
+        // TODO(b/369186876): Implement reordering of task view task with the host task
         return false;
     }
 }
diff --git a/src/com/android/systemui/wm/BarControlPolicy.java b/src/com/android/systemui/wm/BarControlPolicy.java
index 0452b83b..c7a8daf9 100644
--- a/src/com/android/systemui/wm/BarControlPolicy.java
+++ b/src/com/android/systemui/wm/BarControlPolicy.java
@@ -114,7 +114,7 @@ public class BarControlPolicy {
      *         is the inset types that should be hidden.
      */
     @WindowInsets.Type.InsetsType
-    static int[] getBarVisibilities(String packageName) {
+    public static int[] getBarVisibilities(String packageName) {
         int hideTypes = 0;
         int showTypes = 0;
         if (matchesStatusFilter(packageName)) {
diff --git a/src/com/android/systemui/wm/DisplaySystemBarsController.java b/src/com/android/systemui/wm/DisplaySystemBarsController.java
index 56b64413..7fe37881 100644
--- a/src/com/android/systemui/wm/DisplaySystemBarsController.java
+++ b/src/com/android/systemui/wm/DisplaySystemBarsController.java
@@ -21,6 +21,12 @@ import static android.view.WindowInsets.Type.navigationBars;
 import static android.view.WindowInsets.Type.statusBars;
 import static android.view.WindowInsets.Type.systemBars;
 
+import static com.android.systemui.car.systembar.SystemBarUtil.SYSTEM_BAR_PERSISTENCY_CONFIG_BARPOLICY;
+import static com.android.systemui.car.systembar.SystemBarUtil.SYSTEM_BAR_PERSISTENCY_CONFIG_IMMERSIVE;
+import static com.android.systemui.car.systembar.SystemBarUtil.SYSTEM_BAR_PERSISTENCY_CONFIG_IMMERSIVE_WITH_NAV;
+import static com.android.systemui.car.systembar.SystemBarUtil.SYSTEM_BAR_PERSISTENCY_CONFIG_NON_IMMERSIVE;
+import static com.android.systemui.car.systembar.SystemBarUtil.VISIBLE_BAR_VISIBILITIES_TYPES_INDEX;
+import static com.android.systemui.car.systembar.SystemBarUtil.INVISIBLE_BAR_VISIBILITIES_TYPES_INDEX;
 import static com.android.systemui.car.users.CarSystemUIUserUtil.isSecondaryMUMDSystemUI;
 
 import android.annotation.Nullable;
@@ -29,11 +35,10 @@ import android.content.ComponentName;
 import android.content.Context;
 import android.content.Intent;
 import android.content.IntentFilter;
+import android.os.Build;
 import android.os.Handler;
 import android.os.PatternMatcher;
 import android.os.RemoteException;
-import android.os.UserHandle;
-import android.util.Log;
 import android.util.Slog;
 import android.util.SparseArray;
 import android.view.IDisplayWindowInsetsController;
@@ -54,6 +59,7 @@ import com.android.wm.shell.common.DisplayController;
 import com.android.wm.shell.common.DisplayInsetsController;
 
 import java.util.Arrays;
+import java.util.Objects;
 
 /**
  * Controller that maps between displays and {@link IDisplayWindowInsetsController} in order to
@@ -68,8 +74,7 @@ public class DisplaySystemBarsController implements DisplayController.OnDisplays
     private static final int STATE_IMMERSIVE_WITH_NAV_BAR = navigationBars();
     private static final int STATE_IMMERSIVE_WITH_STATUS_BAR = statusBars();
     private static final int STATE_IMMERSIVE = 0;
-    private static final boolean DEBUG = Log.isLoggable(DisplayController.class.getSimpleName(),
-            Log.DEBUG);
+    private static final boolean DEBUG = Build.IS_DEBUGGABLE;
 
     protected final Context mContext;
     protected final IWindowManager mWmService;
@@ -152,6 +157,7 @@ public class DisplaySystemBarsController implements DisplayController.OnDisplays
         int mRequestedVisibleTypes = WindowInsets.Type.defaultVisible();
         String mPackageName;
         int mBehavior = 0;
+        BroadcastReceiver mOverlayChangeBroadcastReceiver;
 
         PerDisplay(int displayId) {
             mDisplayId = displayId;
@@ -165,15 +171,16 @@ public class DisplaySystemBarsController implements DisplayController.OnDisplays
             );
             mBehavior = mContext.getResources().getInteger(
                     R.integer.config_systemBarPersistency);
-            registerOverlayChangeBroadcastReceiver();
         }
 
         public void register() {
             mDisplayInsetsController.addInsetsChangedListener(mDisplayId, this);
+            registerOverlayChangeBroadcastReceiver();
         }
 
         public void unregister() {
             mDisplayInsetsController.removeInsetsChangedListener(mDisplayId, this);
+            unregisterOverlayChangeBroadcastReceiver();
         }
 
         @Override
@@ -214,50 +221,59 @@ public class DisplaySystemBarsController implements DisplayController.OnDisplays
         @Override
         public void topFocusedWindowChanged(ComponentName component,
                 @InsetsType int requestedVisibleTypes) {
-            String packageName = component != null ? component.getPackageName() : null;
-            boolean showNavRequest =
-                    (requestedVisibleTypes & navigationBars()) == navigationBars();
-            boolean showStatusRequest =
-                    (requestedVisibleTypes & statusBars()) == statusBars();
-
-
-            boolean maybeUpdate = (mWindowRequestedVisibleTypes != requestedVisibleTypes || (
-                    mPackageName != null && !mPackageName.equals(packageName)));
-
             if (DEBUG) {
                 Slog.d(TAG, "topFocusedWindowChanged behavior = " + mBehavior
                         + ", component = " + component
                         + ", requestedVisibleTypes = " + requestedVisibleTypes
-                        + ", showNavRequest = " + showNavRequest
-                        + ", showStatusRequest = " + showStatusRequest
                         + ", mWindowRequestedVisibleTypes = " + mWindowRequestedVisibleTypes
                         + ", mPackageName = " + mPackageName
-                        + ", maybeUpdate = " + maybeUpdate);
+                        + ", userId = " + mContext.getUserId()
+                        + ", display id = " + mDisplayId
+                );
             }
+            String packageName = component != null ? component.getPackageName() : null;
 
-            if (maybeUpdate) {
-                if (mBehavior == 1) {
-                    mImmersiveState = 0;
-                    if (showNavRequest) {
-                        mImmersiveState |= navigationBars();
-                    }
-                    if (showStatusRequest) {
-                        mImmersiveState |= statusBars();
-                    }
-                } else if (mBehavior == 2) {
-                    mImmersiveState = navigationBars();
-                    if (showStatusRequest) {
-                        mImmersiveState |= statusBars();
-                    }
+            if (mBehavior == SYSTEM_BAR_PERSISTENCY_CONFIG_BARPOLICY) {
+                if (Objects.equals(mPackageName, packageName)) {
+                    return;
                 }
             } else {
-                mImmersiveState = STATE_NON_IMMERSIVE;
+                if (mWindowRequestedVisibleTypes == requestedVisibleTypes) {
+                    return;
+                }
             }
 
+            updateImmersiveState(requestedVisibleTypes);
+            mWindowRequestedVisibleTypes = requestedVisibleTypes;
             mPackageName = packageName;
             updateDisplayWindowRequestedVisibleTypes();
         }
 
+        private void updateImmersiveState(@InsetsType int requestedVisibleTypes) {
+            boolean showNavRequest =
+                    (requestedVisibleTypes & navigationBars()) == navigationBars();
+            boolean showStatusRequest =
+                    (requestedVisibleTypes & statusBars()) == statusBars();
+
+            if (mBehavior == SYSTEM_BAR_PERSISTENCY_CONFIG_IMMERSIVE) {
+                mImmersiveState = 0;
+                if (showNavRequest) {
+                    mImmersiveState |= navigationBars();
+                }
+                if (showStatusRequest) {
+                    mImmersiveState |= statusBars();
+                }
+            } else if (mBehavior == SYSTEM_BAR_PERSISTENCY_CONFIG_IMMERSIVE_WITH_NAV) {
+                mImmersiveState = navigationBars();
+                if (showStatusRequest) {
+                    mImmersiveState |= statusBars();
+                }
+            } else if (mBehavior == SYSTEM_BAR_PERSISTENCY_CONFIG_NON_IMMERSIVE) {
+                mImmersiveState = systemBars();
+            }
+            Slog.d(TAG, "ImmersiveState =" + mImmersiveState);
+        }
+
         @Override
         public void setImeInputTargetRequestedVisibility(boolean visible) {
             // TODO
@@ -268,18 +284,24 @@ public class DisplaySystemBarsController implements DisplayController.OnDisplays
             overlayFilter.addDataScheme(OVERLAY_FILTER_DATA_SCHEME);
             overlayFilter.addDataSchemeSpecificPart(mContext.getPackageName(),
                     PatternMatcher.PATTERN_LITERAL);
-            BroadcastReceiver receiver = new BroadcastReceiver() {
+            mOverlayChangeBroadcastReceiver = new BroadcastReceiver() {
                 @Override
                 public void onReceive(Context context, Intent intent) {
-                    Slog.d(TAG, "topFocusedWindowChanged behavior = ");
                     mBehavior = mContext.getResources().getInteger(
                             R.integer.config_systemBarPersistency);
-                    Slog.d(TAG, "Refresh system bar persistency behavior on overlay change"
-                            + mBehavior);
+                    Slog.d(TAG, "Update system bar persistency behavior to" + mBehavior
+                            + " on overlay change on userId = " + mContext.getUserId()
+                            + " on display = " + mDisplayId);
                 }
             };
-            mContext.registerReceiverAsUser(receiver, UserHandle.ALL,
-                    overlayFilter, /* broadcastPermission= */null, /* handler= */ null);
+            mContext.registerReceiver(mOverlayChangeBroadcastReceiver,
+                    overlayFilter, /* broadcastPermission= */ null, /* handler= */ null);
+        }
+
+        private void unregisterOverlayChangeBroadcastReceiver() {
+            if (mOverlayChangeBroadcastReceiver != null) {
+                mContext.unregisterReceiver(mOverlayChangeBroadcastReceiver);
+            }
         }
 
         protected void updateDisplayWindowRequestedVisibleTypes() {
@@ -287,33 +309,24 @@ public class DisplaySystemBarsController implements DisplayController.OnDisplays
                 return;
             }
 
-            int[] barVisibilities;
-            if (mImmersiveState == STATE_IMMERSIVE_WITH_NAV_BAR) {
-                barVisibilities = mImmersiveWithNavBarVisibilities;
-            } else if (mImmersiveState == STATE_IMMERSIVE_WITH_STATUS_BAR) {
-                barVisibilities = mImmersiveWithStatusBarVisibilities;
-            } else if (mImmersiveState == STATE_IMMERSIVE) {
-                barVisibilities = mImmersiveVisibilities;
-            } else if (mImmersiveState == STATE_NON_IMMERSIVE) {
-                barVisibilities = mDefaultVisibilities;
-            } else {
-                barVisibilities = mDefaultVisibilities;
-            }
-            if (DEBUG) {
-                Slog.d(TAG, "mImmersiveState = " + mImmersiveState + "barVisibilities to "
-                        + Arrays.toString(barVisibilities));
-            }
+            int[] barVisibilities = getBarVisibilities(mImmersiveState);
 
-            updateRequestedVisibleTypes(barVisibilities[0], /* visible= */ true);
-            updateRequestedVisibleTypes(barVisibilities[1], /* visible= */ false);
+            updateRequestedVisibleTypes(
+                    barVisibilities[VISIBLE_BAR_VISIBILITIES_TYPES_INDEX],
+                    /* visible= */ true);
+            updateRequestedVisibleTypes(
+                    barVisibilities[INVISIBLE_BAR_VISIBILITIES_TYPES_INDEX],
+                    /* visible= */ false);
 
             if (mAppRequestedVisibleTypes == mRequestedVisibleTypes) {
                 return;
             }
             mAppRequestedVisibleTypes = mRequestedVisibleTypes;
 
-            showInsets(barVisibilities[0], /* fromIme= */ false, /* statsToken= */ null);
-            hideInsets(barVisibilities[1], /* fromIme= */ false, /* statsToken = */ null);
+            showInsets(barVisibilities[VISIBLE_BAR_VISIBILITIES_TYPES_INDEX],
+                    /* fromIme= */ false, /* statsToken= */ null);
+            hideInsets(barVisibilities[INVISIBLE_BAR_VISIBILITIES_TYPES_INDEX],
+                    /* fromIme= */ false, /* statsToken = */ null);
             try {
                 mWmService.updateDisplayWindowRequestedVisibleTypes(mDisplayId,
                         mRequestedVisibleTypes);
@@ -322,6 +335,28 @@ public class DisplaySystemBarsController implements DisplayController.OnDisplays
             }
         }
 
+        private int[] getBarVisibilities(int immersiveState) {
+            int[] barVisibilities;
+            if (mBehavior == SYSTEM_BAR_PERSISTENCY_CONFIG_BARPOLICY) {
+                barVisibilities = BarControlPolicy.getBarVisibilities(mPackageName);
+            } else if (immersiveState == STATE_IMMERSIVE_WITH_NAV_BAR) {
+                barVisibilities = mImmersiveWithNavBarVisibilities;
+            } else if (immersiveState == STATE_IMMERSIVE_WITH_STATUS_BAR) {
+                barVisibilities = mImmersiveWithStatusBarVisibilities;
+            } else if (immersiveState == STATE_IMMERSIVE) {
+                barVisibilities = mImmersiveVisibilities;
+            } else if (immersiveState == STATE_NON_IMMERSIVE) {
+                barVisibilities = mDefaultVisibilities;
+            } else {
+                barVisibilities = mDefaultVisibilities;
+            }
+            if (DEBUG) {
+                Slog.d(TAG, "mBehavior=" + mBehavior + ", mImmersiveState = " + immersiveState
+                        + ", barVisibilities to " + Arrays.toString(barVisibilities));
+            }
+            return barVisibilities;
+        }
+
         protected void updateRequestedVisibleTypes(@InsetsType int types, boolean visible) {
             mRequestedVisibleTypes = visible
                     ? (mRequestedVisibleTypes | types)
diff --git a/src/com/android/systemui/wm/DisplaySystemBarsInsetsControllerHost.java b/src/com/android/systemui/wm/DisplaySystemBarsInsetsControllerHost.java
index 1d037471..cf20a46e 100644
--- a/src/com/android/systemui/wm/DisplaySystemBarsInsetsControllerHost.java
+++ b/src/com/android/systemui/wm/DisplaySystemBarsInsetsControllerHost.java
@@ -19,6 +19,7 @@ package com.android.systemui.wm;
 import static android.view.WindowInsetsController.BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE;
 
 import android.annotation.NonNull;
+import android.annotation.Nullable;
 import android.os.Handler;
 import android.os.IBinder;
 import android.view.InsetsController;
@@ -27,6 +28,7 @@ import android.view.SyncRtSurfaceTransactionApplier;
 import android.view.WindowInsets;
 import android.view.WindowInsetsAnimation;
 import android.view.WindowInsetsController;
+import android.view.inputmethod.ImeTracker;
 import android.view.inputmethod.InputMethodManager;
 
 import java.util.List;
@@ -97,7 +99,8 @@ public class DisplaySystemBarsInsetsControllerHost implements InsetsController.H
     }
 
     @Override
-    public void updateRequestedVisibleTypes(@WindowInsets.Type.InsetsType int types) {
+    public void updateRequestedVisibleTypes(@WindowInsets.Type.InsetsType int types,
+            @Nullable ImeTracker.Token statsToken) {
         mRequestedVisibleTypesCallback.accept(types);
     }
 
diff --git a/src/com/android/systemui/wmshell/CarWMComponent.java b/src/com/android/systemui/wmshell/CarWMComponent.java
index db1a5595..75cb4613 100644
--- a/src/com/android/systemui/wmshell/CarWMComponent.java
+++ b/src/com/android/systemui/wmshell/CarWMComponent.java
@@ -20,15 +20,11 @@ import com.android.systemui.car.wm.CarSystemUIProxyImpl;
 import com.android.systemui.car.wm.taskview.RemoteCarTaskViewTransitions;
 import com.android.systemui.dagger.WMComponent;
 import com.android.systemui.wm.DisplaySystemBarsController;
-import com.android.systemui.wm.MDSystemBarsController;
 import com.android.wm.shell.RootTaskDisplayAreaOrganizer;
 import com.android.wm.shell.dagger.WMSingleton;
 
 import dagger.Subcomponent;
 
-import java.util.Optional;
-
-
 /**
  * Dagger Subcomponent for WindowManager.
  */
@@ -50,12 +46,6 @@ public interface CarWMComponent extends WMComponent {
     @WMSingleton
     DisplaySystemBarsController getDisplaySystemBarsController();
 
-    /**
-     * gets the SystemBarController for Inset events.
-     */
-    @WMSingleton
-    Optional<MDSystemBarsController> getMDSystemBarController();
-
     /**
      * Returns the implementation of car system ui proxy which will be used by other apps to
      * interact with the car system ui.
diff --git a/src/com/android/systemui/wmshell/CarWMShellModule.java b/src/com/android/systemui/wmshell/CarWMShellModule.java
index 3478d205..992a906e 100644
--- a/src/com/android/systemui/wmshell/CarWMShellModule.java
+++ b/src/com/android/systemui/wmshell/CarWMShellModule.java
@@ -21,11 +21,9 @@ import android.os.Handler;
 import android.view.IWindowManager;
 
 import com.android.systemui.car.CarServiceProvider;
-import com.android.systemui.car.users.CarSystemUIUserUtil;
 import com.android.systemui.car.wm.CarFullscreenTaskMonitorListener;
 import com.android.systemui.dagger.qualifiers.Main;
 import com.android.systemui.wm.DisplaySystemBarsController;
-import com.android.systemui.wm.MDSystemBarsController;
 import com.android.wm.shell.ShellTaskOrganizer;
 import com.android.wm.shell.common.DisplayController;
 import com.android.wm.shell.common.DisplayInsetsController;
@@ -37,6 +35,7 @@ import com.android.wm.shell.fullscreen.FullscreenTaskListener;
 import com.android.wm.shell.pip.Pip;
 import com.android.wm.shell.recents.RecentTasksController;
 import com.android.wm.shell.sysui.ShellInit;
+import com.android.wm.shell.taskview.TaskViewTransitions;
 import com.android.wm.shell.windowdecor.WindowDecorViewModel;
 
 import dagger.BindsOptionalOf;
@@ -59,19 +58,6 @@ public abstract class CarWMShellModule {
                 displayInsetsController, mainHandler);
     }
 
-    @WMSingleton
-    @Provides
-    static Optional<MDSystemBarsController> provideMUMDPerDisplayInsetsChangeController(
-            IWindowManager windowManager,
-            @Main Handler mainHandler,
-            Context context) {
-        if (CarSystemUIUserUtil.isSecondaryMUMDSystemUI()) {
-            return Optional.of(
-                    new MDSystemBarsController(windowManager, mainHandler, context));
-        }
-        return Optional.empty();
-    }
-
     @BindsOptionalOf
     abstract Pip optionalPip();
 
@@ -84,13 +70,15 @@ public abstract class CarWMShellModule {
             ShellTaskOrganizer shellTaskOrganizer,
             SyncTransactionQueue syncQueue,
             Optional<RecentTasksController> recentTasksOptional,
-            Optional<WindowDecorViewModel> windowDecorViewModelOptional) {
+            Optional<WindowDecorViewModel> windowDecorViewModelOptional,
+            TaskViewTransitions taskViewTransitions) {
         return new CarFullscreenTaskMonitorListener(context,
                 carServiceProvider,
                 shellInit,
                 shellTaskOrganizer,
                 syncQueue,
                 recentTasksOptional,
-                windowDecorViewModelOptional);
+                windowDecorViewModelOptional,
+                taskViewTransitions);
     }
 }
diff --git a/tests/Android.bp b/tests/Android.bp
index 5a407a3e..2e617694 100644
--- a/tests/Android.bp
+++ b/tests/Android.bp
@@ -40,13 +40,19 @@ android_test {
         "libstaticjvmtiagent",
     ],
     libs: [
-        "android.test.runner",
+        "android.test.runner.stubs.system",
         "telephony-common",
-        "android.test.base",
+        "android.test.base.stubs.system",
     ],
     aaptflags: [
         "--extra-packages com.android.systemui",
     ],
 
     certificate: "platform",
+
+    // TODO(b/319708040): re-enable use_resource_processor
+    use_resource_processor: false,
+
+    additional_manifests: ["AndroidManifest.xml"],
+    manifest: "AndroidManifest-base.xml",
 }
diff --git a/tests/AndroidManifest-base.xml b/tests/AndroidManifest-base.xml
new file mode 100644
index 00000000..7708f83c
--- /dev/null
+++ b/tests/AndroidManifest-base.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!-- Copyright (C) 2024 The Android Open Source Project
+
+    Licensed under the Apache License, Version 2.0 (the "License");
+    you may not use this file except in compliance with the License.
+    You may obtain a copy of the License at
+
+         http://www.apache.org/licenses/LICENSE-2.0
+
+    Unless required by applicable law or agreed to in writing, software
+    distributed under the License is distributed on an "AS IS" BASIS,
+    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+    See the License for the specific language governing permissions and
+    limitations under the License.
+-->
+
+<manifest xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:androidprv="http://schemas.android.com/apk/prv/res/android"
+    xmlns:tools="http://schemas.android.com/tools"
+    android:sharedUserId="android.uid.system"
+    package="com.android.systemui.tests" />
\ No newline at end of file
diff --git a/tests/robolectric/config/robolectric.properties b/tests/robolectric/config/robolectric.properties
new file mode 100644
index 00000000..c7aee002
--- /dev/null
+++ b/tests/robolectric/config/robolectric.properties
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
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+#
+sdk=NEWEST_SDK
+shadows=\
+  com.android.systemui.testutils.shadow.ShadowLockPatternUtils \
+  com.android.systemui.testutils.shadow.ShadowTestableLooper
\ No newline at end of file
diff --git a/tests/src/com/android/systemui/CarSystemUITestInitializer.java b/tests/src/com/android/systemui/CarSystemUITestInitializer.java
index 030a6753..fb5a89db 100644
--- a/tests/src/com/android/systemui/CarSystemUITestInitializer.java
+++ b/tests/src/com/android/systemui/CarSystemUITestInitializer.java
@@ -22,7 +22,6 @@ import android.content.Context;
 
 import com.android.systemui.dagger.SysUIComponent;
 import com.android.systemui.dagger.WMComponent;
-import com.android.systemui.wm.MDSystemBarsController;
 import com.android.wm.shell.RootTaskDisplayAreaOrganizer;
 
 import java.util.Optional;
@@ -36,7 +35,6 @@ public class CarSystemUITestInitializer extends CarSystemUIInitializer {
     protected SysUIComponent.Builder prepareSysUIComponentBuilder(
             SysUIComponent.Builder sysUIBuilder, WMComponent wm) {
         return ((CarSysUIComponent.Builder) sysUIBuilder).setRootTaskDisplayAreaOrganizer(
-                Optional.of(mock(RootTaskDisplayAreaOrganizer.class)))
-                .setMDSystemBarsController(Optional.of(mock(MDSystemBarsController.class)));
+                Optional.of(mock(RootTaskDisplayAreaOrganizer.class)));
     }
 }
diff --git a/tests/src/com/android/systemui/car/displayconfig/ExternalDisplayControllerTest.kt b/tests/src/com/android/systemui/car/displayconfig/ExternalDisplayControllerTest.kt
new file mode 100644
index 00000000..6c0c522c
--- /dev/null
+++ b/tests/src/com/android/systemui/car/displayconfig/ExternalDisplayControllerTest.kt
@@ -0,0 +1,102 @@
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
+package com.android.systemui.car.displayconfig
+
+import android.testing.AndroidTestingRunner
+import android.testing.TestableLooper.RunWithLooper
+import android.view.Display
+import androidx.test.filters.SmallTest
+import com.android.systemui.SysuiTestCase
+import com.android.systemui.car.CarSystemUiTest
+import com.android.systemui.display.data.repository.DisplayRepository
+import com.android.systemui.display.data.repository.DisplayRepository.PendingDisplay
+import com.android.systemui.process.ProcessWrapper
+import kotlinx.coroutines.ExperimentalCoroutinesApi
+import kotlinx.coroutines.cancelChildren
+import kotlinx.coroutines.flow.Flow
+import kotlinx.coroutines.flow.emptyFlow
+import kotlinx.coroutines.flow.flowOf
+import kotlinx.coroutines.launch
+import kotlinx.coroutines.test.StandardTestDispatcher
+import kotlinx.coroutines.test.TestScope
+import kotlinx.coroutines.test.advanceUntilIdle
+import kotlinx.coroutines.test.runTest
+import org.junit.Test
+import org.junit.runner.RunWith
+import org.mockito.kotlin.mock
+import org.mockito.kotlin.never
+import org.mockito.kotlin.verify
+import org.mockito.kotlin.whenever
+
+@CarSystemUiTest
+@RunWith(AndroidTestingRunner::class)
+@RunWithLooper
+@SmallTest
+class ExternalDisplayControllerTest : SysuiTestCase() {
+
+    private val testScope = TestScope()
+    private val bgDispatcher =
+        StandardTestDispatcher(testScope.testScheduler, name = "Background dispatcher")
+    private val pendingDisplayMock: PendingDisplay = mock()
+    private val fakePendingDisplayFlow = flowOf(null, pendingDisplayMock)
+    private val fakeDisplayRepository = FakeDisplayRepository(fakePendingDisplayFlow)
+    private val processWrapper: ProcessWrapper = mock()
+
+    private val externalDisplayController = ExternalDisplayController(
+        fakeDisplayRepository,
+        processWrapper,
+        testScope,
+        bgDispatcher
+    )
+
+    @OptIn(ExperimentalCoroutinesApi::class)
+    @Test
+    fun start_whenSystemUser_enablesPendingDisplays() = testScope.runTest() {
+        whenever(processWrapper.isSystemUser).thenReturn(true)
+
+        launch(StandardTestDispatcher(testScheduler)) {
+            externalDisplayController.start()
+        }
+        advanceUntilIdle()
+        coroutineContext.cancelChildren()
+
+        verify(pendingDisplayMock).enable()
+    }
+
+    @OptIn(ExperimentalCoroutinesApi::class)
+    @Test
+    fun start_whenNonSystemUser_noOp() = testScope.runTest {
+        whenever(processWrapper.isSystemUser).thenReturn(false)
+
+        launch(StandardTestDispatcher(testScheduler)) {
+            externalDisplayController.start()
+        }
+        advanceUntilIdle()
+        coroutineContext.cancelChildren()
+
+        verify(pendingDisplayMock, never()).enable()
+    }
+}
+
+class FakeDisplayRepository(
+    private val fakePendingDisplayFlow: Flow<PendingDisplay?>,
+    override val displayChangeEvent: Flow<Int> = emptyFlow(),
+    override val displayAdditionEvent: Flow<Display?> = emptyFlow(),
+    override val displays: Flow<Set<Display>> = emptyFlow(),
+    override val defaultDisplayOff: Flow<Boolean> = emptyFlow(),
+    override val pendingDisplay: Flow<PendingDisplay?> = fakePendingDisplayFlow
+) : DisplayRepository
diff --git a/tests/src/com/android/systemui/car/hvac/HvacPanelOverlayViewControllerTest.java b/tests/src/com/android/systemui/car/hvac/HvacPanelOverlayViewControllerTest.java
index 8d13cbdf..eb410022 100644
--- a/tests/src/com/android/systemui/car/hvac/HvacPanelOverlayViewControllerTest.java
+++ b/tests/src/com/android/systemui/car/hvac/HvacPanelOverlayViewControllerTest.java
@@ -20,16 +20,19 @@ import static com.android.systemui.car.window.OverlayPanelViewController.OVERLAY
 
 import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.anyFloat;
+import static org.mockito.ArgumentMatchers.anyLong;
 import static org.mockito.ArgumentMatchers.argThat;
 import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.mock;
+import static org.mockito.Mockito.never;
 import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.when;
 
-import android.app.UiModeManager;
 import android.content.res.Configuration;
+import android.os.Handler;
 import android.testing.AndroidTestingRunner;
 import android.testing.TestableLooper;
+import android.testing.TestableResources;
 import android.view.View;
 import android.view.ViewGroup;
 import android.widget.TextView;
@@ -60,6 +63,7 @@ import java.util.Collections;
 @SmallTest
 public class HvacPanelOverlayViewControllerTest extends SysuiTestCase {
     HvacPanelOverlayViewController mHvacPanelOverlayViewController;
+    TestableResources mTestableResources;
 
     @Mock
     HvacController mHvacController;
@@ -74,7 +78,7 @@ public class HvacPanelOverlayViewControllerTest extends SysuiTestCase {
     @Mock
     ConfigurationController mConfigurationController;
     @Mock
-    UiModeManager mUiModeManager;
+    private Handler mHandler;
 
     @Before
     public void setUp() {
@@ -86,14 +90,12 @@ public class HvacPanelOverlayViewControllerTest extends SysuiTestCase {
                 mFlingAnimationUtilsBuilder);
         when(mFlingAnimationUtilsBuilder.build()).thenReturn(mFlingAnimationUtils);
 
-        mHvacPanelOverlayViewController = new HvacPanelOverlayViewController(
-                mContext, getContext().getOrCreateTestableResources().getResources(),
-                mHvacController, mOverlayViewGlobalStateController, mFlingAnimationUtilsBuilder,
-                mCarDeviceProvisionedController, mConfigurationController, mUiModeManager);
+        mTestableResources = getContext().getOrCreateTestableResources();
     }
 
     @Test
     public void onScroll_updateDim() {
+        createHvacPanelOverlayViewController();
         int height = 100;
         View mockLayout = mock(View.class);
         when(mockLayout.getHeight()).thenReturn(height);
@@ -106,8 +108,45 @@ public class HvacPanelOverlayViewControllerTest extends SysuiTestCase {
                 eq(mHvacPanelOverlayViewController), anyFloat());
     }
 
+    @Test
+    public void onAnimateExpandPanel_noTimeout_timeoutNotSet() {
+        mTestableResources.addOverride(R.integer.config_hvacAutoDismissDurationMs, 0);
+        createHvacPanelOverlayViewController();
+        View mockLayout = mock(View.class);
+        mHvacPanelOverlayViewController.setLayout(mockLayout);
+
+        mHvacPanelOverlayViewController.onAnimateExpandPanel();
+
+        verify(mHandler, never()).postDelayed(any(), anyLong());
+    }
+
+    @Test
+    public void onAnimateExpandPanel_timeoutSet() {
+        mTestableResources.addOverride(R.integer.config_hvacAutoDismissDurationMs, 1000);
+        createHvacPanelOverlayViewController();
+        View mockLayout = mock(View.class);
+        mHvacPanelOverlayViewController.setLayout(mockLayout);
+
+        mHvacPanelOverlayViewController.onAnimateExpandPanel();
+
+        verify(mHandler).postDelayed(any(), anyLong());
+    }
+
+    @Test
+    public void onAnimateCollapsePanel_timeoutCancelled() {
+        mTestableResources.addOverride(R.integer.config_hvacAutoDismissDurationMs, 1000);
+        createHvacPanelOverlayViewController();
+        View mockLayout = mock(View.class);
+        mHvacPanelOverlayViewController.setLayout(mockLayout);
+
+        mHvacPanelOverlayViewController.onAnimateCollapsePanel();
+
+        verify(mHandler).removeCallbacks(any());
+    }
+
     @Test
     public void onConfigChanged_oldHVACViewRemoved_newHVACViewAdded() {
+        createHvacPanelOverlayViewController();
         Configuration config = new Configuration();
         config.uiMode = Configuration.UI_MODE_NIGHT_YES;
         int mockIndex = 3;
@@ -132,4 +171,11 @@ public class HvacPanelOverlayViewControllerTest extends SysuiTestCase {
                 argThat(view -> view.hashCode() != mockHvacPanelView.hashCode()),
                 eq(mockIndex));
     }
+
+    private void createHvacPanelOverlayViewController() {
+        mHvacPanelOverlayViewController = new HvacPanelOverlayViewController(
+                mContext, mTestableResources.getResources(), mHandler,
+                mHvacController, mOverlayViewGlobalStateController, mFlingAnimationUtilsBuilder,
+                mCarDeviceProvisionedController, mConfigurationController);
+    }
 }
diff --git a/tests/src/com/android/systemui/car/keyguard/CarKeyguardViewControllerTest.java b/tests/src/com/android/systemui/car/keyguard/CarKeyguardViewControllerTest.java
index f56abad4..aaff6b62 100644
--- a/tests/src/com/android/systemui/car/keyguard/CarKeyguardViewControllerTest.java
+++ b/tests/src/com/android/systemui/car/keyguard/CarKeyguardViewControllerTest.java
@@ -49,7 +49,6 @@ import com.android.systemui.bouncer.domain.interactor.PrimaryBouncerInteractor;
 import com.android.systemui.bouncer.ui.BouncerView;
 import com.android.systemui.bouncer.ui.viewmodel.KeyguardBouncerViewModel;
 import com.android.systemui.car.CarSystemUiTest;
-import com.android.systemui.car.systembar.CarSystemBarController;
 import com.android.systemui.car.window.OverlayViewGlobalStateController;
 import com.android.systemui.car.window.SystemUIOverlayWindowController;
 import com.android.systemui.keyguard.ui.viewmodel.PrimaryBouncerToGoneTransitionViewModel;
@@ -70,6 +69,8 @@ import org.mockito.Mock;
 import org.mockito.Mockito;
 import org.mockito.MockitoAnnotations;
 
+import java.util.Optional;
+
 @CarSystemUiTest
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper(setAsMainLooper = true)
@@ -102,9 +103,9 @@ public class CarKeyguardViewControllerTest extends SysuiTestCase {
     @Mock
     private PrimaryBouncerToGoneTransitionViewModel mPrimaryBouncerToGoneTransitionViewModel;
     @Mock
-    private CarSystemBarController mCarSystemBarController;
-    @Mock
     private BouncerView mBouncerView;
+    @Mock
+    private KeyguardSystemBarPresenter mKeyguardSystemBarPresenter;
 
     @Before
     public void setUp() {
@@ -135,7 +136,6 @@ public class CarKeyguardViewControllerTest extends SysuiTestCase {
                 mock(KeyguardUpdateMonitor.class),
                 () -> mock(BiometricUnlockController.class),
                 mock(ViewMediatorCallback.class),
-                mCarSystemBarController,
                 mPrimaryBouncerCallbackInteractor,
                 mPrimaryBouncerInteractor,
                 mKeyguardSecurityModel,
@@ -146,7 +146,8 @@ public class CarKeyguardViewControllerTest extends SysuiTestCase {
                 mock(KeyguardMessageAreaController.Factory.class),
                 mock(BouncerLogger.class),
                 mock(BouncerMessageInteractor.class),
-                mock(SelectedUserInteractor.class)
+                mock(SelectedUserInteractor.class),
+                Optional.of(mKeyguardSystemBarPresenter)
         );
         mCarKeyguardViewController.inflate((ViewGroup) LayoutInflater.from(mContext).inflate(
                 R.layout.sysui_overlay_window, /* root= */ null));
@@ -246,11 +247,11 @@ public class CarKeyguardViewControllerTest extends SysuiTestCase {
 
         when(mKeyguardStateController.isUnlocked()).thenReturn(true);
         mCarKeyguardViewController.setOccluded(/* occluded= */ true, /* animate= */ false);
-        verify(mCarSystemBarController, never()).showAllOcclusionButtons(true);
+        verify(mKeyguardSystemBarPresenter, never()).showAllOcclusionButtons();
 
         when(mKeyguardStateController.isUnlocked()).thenReturn(false);
         mCarKeyguardViewController.setOccluded(/* occluded= */ true, /* animate= */ false);
-        verify(mCarSystemBarController).showAllOcclusionButtons(true);
+        verify(mKeyguardSystemBarPresenter).showAllOcclusionButtons();
     }
 
     @Test
diff --git a/tests/src/com/android/systemui/car/ndo/BlockerViewModelTest.java b/tests/src/com/android/systemui/car/ndo/BlockerViewModelTest.java
index a28c3ddb..286d4a31 100644
--- a/tests/src/com/android/systemui/car/ndo/BlockerViewModelTest.java
+++ b/tests/src/com/android/systemui/car/ndo/BlockerViewModelTest.java
@@ -78,7 +78,8 @@ public class BlockerViewModelTest extends SysuiTestCase {
     public void setup() {
         MockitoAnnotations.initMocks(/* testClass= */ this);
         mInCallServiceManager = new InCallServiceManager();
-        mBlockerViewModel = new BlockerViewModel(mContext, mInCallServiceManager);
+        mBlockerViewModel = new BlockerViewModel(mContext, mInCallServiceManager,
+                mMediaSessionHelper);
         mBlockingLiveData = mBlockerViewModel.getBlockingTypeLiveData();
     }
 
@@ -165,9 +166,8 @@ public class BlockerViewModelTest extends SysuiTestCase {
     }
 
     private void initializeViewModel() {
+        when(mMediaSessionHelper.getActiveMediaSessions()).thenReturn(mMediaLiveData);
         mBlockerViewModel.initialize(BLOCKED_ACTIVITY, UserHandle.CURRENT);
         mBlockerViewModel.mInCallLiveData = mInCallLiveData;
-        mBlockerViewModel.mMediaSessionHelper = mMediaSessionHelper;
-        when(mMediaSessionHelper.getActiveMediaSessions()).thenReturn(mMediaLiveData);
     }
 }
diff --git a/tests/src/com/android/systemui/car/ndo/MediaSessionHelperTest.java b/tests/src/com/android/systemui/car/ndo/MediaSessionHelperTest.java
index f4bbea48..b40fcd06 100644
--- a/tests/src/com/android/systemui/car/ndo/MediaSessionHelperTest.java
+++ b/tests/src/com/android/systemui/car/ndo/MediaSessionHelperTest.java
@@ -27,10 +27,14 @@ import static org.mockito.Mockito.times;
 import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.when;
 
+import android.app.INotificationManager;
+import android.app.Notification;
 import android.media.session.MediaController;
 import android.media.session.MediaSessionManager;
 import android.media.session.PlaybackState;
+import android.os.Bundle;
 import android.os.UserHandle;
+import android.service.notification.StatusBarNotification;
 import android.testing.AndroidTestingRunner;
 import android.testing.TestableLooper;
 
@@ -66,13 +70,25 @@ public class MediaSessionHelperTest extends SysuiTestCase {
 
     @Mock
     private MediaSessionManager mMediaSessionManager;
+    @Mock
+    private INotificationManager mINotificationManager;
+    @Mock
+    private StatusBarNotification mStatusBarNotification;
+    @Mock
+    private Notification mNotification;
 
     @Before
-    public void setup() {
+    public void setup() throws Exception {
         MockitoAnnotations.initMocks(/* testClass= */ this);
         mContext = spy(mContext);
         when(mContext.getSystemService(MediaSessionManager.class)).thenReturn(mMediaSessionManager);
 
+        StatusBarNotification[] statusBarNotifications = { mStatusBarNotification };
+        when(mINotificationManager.getActiveNotificationsWithAttribution(
+                eq(mContext.getPackageName()), isNull())).thenReturn(statusBarNotifications);
+        when(mStatusBarNotification.getNotification()).thenReturn(mNotification);
+        mNotification.extras = new Bundle();
+
         mActiveMediaController = mock(MediaController.class);
         PlaybackState activePlaybackState = mock(PlaybackState.class);
         when(mActiveMediaController.getPlaybackState()).thenReturn(activePlaybackState);
@@ -89,28 +105,52 @@ public class MediaSessionHelperTest extends SysuiTestCase {
         when(mMediaSessionManager.getActiveSessionsForUser(isNull(), eq(mUserHandle)))
                 .thenReturn(mediaControllers);
 
-        mMediaSessionHelper = new MediaSessionHelper(mContext, mUserHandle);
+        mMediaSessionHelper = new MediaSessionHelper(mContext, mINotificationManager);
+        mMediaSessionHelper.init(mUserHandle);
     }
 
     @Test
     public void onCreate_setsInitialValue() {
-        assertControllersSet();
+        assertThat(mMediaSessionHelper.getActiveMediaSessions().getValue().size())
+                .isEqualTo(0);
+        assertThat(mMediaSessionHelper.mMediaControllersList.size()).isEqualTo(2);
+    }
+
+    @Test
+    public void onActivePlaybackStateChanged_hasMediaNotification_queriesNewMediaSessions() {
+        PlaybackState playbackState = mock(PlaybackState.class);
+        when(playbackState.isActive()).thenReturn(true);
+        when(mNotification.isMediaNotification()).thenReturn(true);
+
+        mMediaSessionHelper.onPlaybackStateChanged(playbackState);
+
+        assertThat(mMediaSessionHelper.getActiveMediaSessions().getValue().size())
+                .isEqualTo(1);
+        assertThat(mMediaSessionHelper.getActiveMediaSessions().getValue().getFirst())
+                .isEqualTo(mActiveMediaController);
+        assertThat(mMediaSessionHelper.mMediaControllersList.size()).isEqualTo(1);
+        assertThat(mMediaSessionHelper.mMediaControllersList.getFirst())
+                .isEqualTo(mInactiveMediaController);
     }
 
     @Test
-    public void onActivePlaybackStateChanged_queriesNewMediaSessions() {
+    public void onActivePlaybackStateChanged_noMediaNotification_queriesNewMediaSessions() {
         PlaybackState playbackState = mock(PlaybackState.class);
         when(playbackState.isActive()).thenReturn(true);
+        when(mNotification.isMediaNotification()).thenReturn(false);
 
         mMediaSessionHelper.onPlaybackStateChanged(playbackState);
 
-        assertControllersSet();
+        assertThat(mMediaSessionHelper.getActiveMediaSessions().getValue().size())
+                .isEqualTo(0);
+        assertThat(mMediaSessionHelper.mMediaControllersList.size()).isEqualTo(2);
     }
 
     @Test
     public void onInactivePlaybackStateChanged_doesNothing() {
         PlaybackState playbackState = mock(PlaybackState.class);
         when(playbackState.isActive()).thenReturn(false);
+        when(mNotification.isMediaNotification()).thenReturn(true);
 
         mMediaSessionHelper.onPlaybackStateChanged(playbackState);
 
@@ -127,14 +167,4 @@ public class MediaSessionHelperTest extends SysuiTestCase {
         assertThat(mMediaSessionHelper.mMediaControllersList.isEmpty()).isTrue();
         verify(mMediaSessionManager).removeOnActiveSessionsChangedListener(any());
     }
-
-    private void assertControllersSet() {
-        assertThat(mMediaSessionHelper.getActiveMediaSessions().getValue().size())
-                .isEqualTo(1);
-        assertThat(mMediaSessionHelper.getActiveMediaSessions().getValue().getFirst())
-                .isEqualTo(mActiveMediaController);
-        assertThat(mMediaSessionHelper.mMediaControllersList.size()).isEqualTo(1);
-        assertThat(mMediaSessionHelper.mMediaControllersList.getFirst())
-                .isEqualTo(mInactiveMediaController);
-    }
 }
diff --git a/tests/src/com/android/systemui/car/notification/NotificationVisibilityLoggerTest.java b/tests/src/com/android/systemui/car/notification/NotificationVisibilityLoggerTest.java
index d51aeb18..4c3fae5c 100644
--- a/tests/src/com/android/systemui/car/notification/NotificationVisibilityLoggerTest.java
+++ b/tests/src/com/android/systemui/car/notification/NotificationVisibilityLoggerTest.java
@@ -16,9 +16,12 @@
 
 package com.android.systemui.car.notification;
 
+import static com.android.dx.mockito.inline.extended.ExtendedMockito.doReturn;
+
 import static com.google.common.truth.Truth.assertThat;
 
 import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.Mockito.never;
 import static org.mockito.Mockito.reset;
 import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.when;
@@ -34,19 +37,23 @@ import androidx.test.filters.SmallTest;
 
 import com.android.car.notification.AlertEntry;
 import com.android.car.notification.NotificationDataManager;
+import com.android.dx.mockito.inline.extended.ExtendedMockito;
 import com.android.internal.statusbar.IStatusBarService;
 import com.android.internal.statusbar.NotificationVisibility;
 import com.android.systemui.SysuiTestCase;
 import com.android.systemui.car.CarSystemUiTest;
+import com.android.systemui.car.users.CarSystemUIUserUtil;
 import com.android.systemui.util.concurrency.FakeExecutor;
 import com.android.systemui.util.time.FakeSystemClock;
 
+import org.junit.After;
 import org.junit.Before;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.mockito.ArgumentCaptor;
 import org.mockito.Mock;
-import org.mockito.MockitoAnnotations;
+import org.mockito.MockitoSession;
+import org.mockito.quality.Strictness;
 
 import java.util.Collections;
 
@@ -73,13 +80,18 @@ public class NotificationVisibilityLoggerTest extends SysuiTestCase {
     @Mock
     private NotificationDataManager mNotificationDataManager;
 
+    private MockitoSession mSession;
     private NotificationVisibilityLogger mNotificationVisibilityLogger;
     private FakeExecutor mUiBgExecutor;
     private AlertEntry mMessageNotification;
 
     @Before
     public void setUp() {
-        MockitoAnnotations.initMocks(/* testClass= */this);
+        mSession = ExtendedMockito.mockitoSession()
+                .initMocks(this)
+                .spyStatic(CarSystemUIUserUtil.class)
+                .strictness(Strictness.LENIENT)
+                .startMocking();
 
         mUiBgExecutor = new FakeExecutor(new FakeSystemClock());
         Notification.Builder mNotificationBuilder1 = new Notification.Builder(mContext, CHANNEL_ID)
@@ -90,11 +102,20 @@ public class NotificationVisibilityLoggerTest extends SysuiTestCase {
 
         when(mNotificationDataManager.getVisibleNotifications()).thenReturn(
                 Collections.singletonList(mMessageNotification));
+        doReturn(false).when(() -> CarSystemUIUserUtil.isSecondaryMUMDSystemUI());
 
         mNotificationVisibilityLogger = new NotificationVisibilityLogger(
                 mUiBgExecutor, mBarService, mNotificationDataManager);
     }
 
+    @After
+    public void tearDown() {
+        if (mSession != null) {
+            mSession.finishMocking();
+            mSession = null;
+        }
+    }
+
     @Test
     public void log_notifiesStatusBarService() throws RemoteException {
         mNotificationVisibilityLogger.log(/* isVisible= */ true);
@@ -104,6 +125,18 @@ public class NotificationVisibilityLoggerTest extends SysuiTestCase {
                 any(NotificationVisibility[].class), any(NotificationVisibility[].class));
     }
 
+    @Test
+    public void log_visibleBackgroundUser_doesNotNotifyStatusBarService() throws RemoteException {
+        // TODO: b/341604160 - support visible background users properly.
+        doReturn(true).when(() -> CarSystemUIUserUtil.isSecondaryMUMDSystemUI());
+
+        mNotificationVisibilityLogger.log(/* isVisible= */ true);
+        mUiBgExecutor.runNextReady();
+
+        verify(mBarService, never()).onNotificationVisibilityChanged(
+                any(NotificationVisibility[].class), any(NotificationVisibility[].class));
+    }
+
     @Test
     public void log_isVisibleIsTrue_notifiesOfNewlyVisibleItems() throws RemoteException {
         ArgumentCaptor<NotificationVisibility[]> newlyVisibleCaptor =
diff --git a/tests/src/com/android/systemui/car/qc/ProfileSwitcherTest.java b/tests/src/com/android/systemui/car/qc/ProfileSwitcherTest.java
index 5e63181d..219e9903 100644
--- a/tests/src/com/android/systemui/car/qc/ProfileSwitcherTest.java
+++ b/tests/src/com/android/systemui/car/qc/ProfileSwitcherTest.java
@@ -320,6 +320,16 @@ public class ProfileSwitcherTest extends SysuiTestCase {
                 mContext.getString(R.string.car_add_user));
     }
 
+    @Test
+    public void switchAllowed_currentUser_hasSubtitle() {
+        UserInfo currentUser = generateUser(mUserTracker.getUserId(), "User1");
+        mAliveUsers.add(currentUser);
+        when(mUserManager.getUserInfo(mUserTracker.getUserId())).thenReturn(currentUser);
+        List<QCRow> rows = getProfileRows();
+        assertThat(rows.get(0).getSubtitle()).isEqualTo(
+                mContext.getString(R.string.current_profile_subtitle));
+    }
+
     @Test
     public void onUserPressed_triggersSwitch() {
         int currentUserId = 1000;
diff --git a/tests/src/com/android/systemui/car/qc/QCUserPickerButtonControllerTest.java b/tests/src/com/android/systemui/car/qc/QCUserPickerButtonControllerTest.java
index 9b532eb4..de4bca19 100644
--- a/tests/src/com/android/systemui/car/qc/QCUserPickerButtonControllerTest.java
+++ b/tests/src/com/android/systemui/car/qc/QCUserPickerButtonControllerTest.java
@@ -16,11 +16,8 @@
 
 package com.android.systemui.car.qc;
 
-import static com.android.dx.mockito.inline.extended.ExtendedMockito.spyOn;
-
 import static com.google.common.truth.Truth.assertThat;
 
-import static org.mockito.Mockito.any;
 import static org.mockito.Mockito.eq;
 import static org.mockito.Mockito.spy;
 import static org.mockito.Mockito.verify;
@@ -28,25 +25,18 @@ import static org.mockito.Mockito.when;
 
 import android.car.Car;
 import android.car.app.CarActivityManager;
-import android.content.pm.UserInfo;
-import android.graphics.drawable.Drawable;
 import android.os.UserHandle;
-import android.os.UserManager;
 import android.testing.AndroidTestingRunner;
 import android.testing.TestableLooper;
-import android.widget.ImageView;
 
 import androidx.test.filters.SmallTest;
 
 import com.android.systemui.SysuiTestCase;
-import com.android.systemui.broadcast.BroadcastDispatcher;
 import com.android.systemui.car.CarServiceProvider;
 import com.android.systemui.car.CarSystemUiTest;
-import com.android.systemui.car.statusbar.UserNameViewController;
 import com.android.systemui.car.systembar.element.CarSystemBarElementStateController;
 import com.android.systemui.car.systembar.element.CarSystemBarElementStatusBarDisableController;
 import com.android.systemui.settings.UserTracker;
-import com.android.systemui.tests.R;
 
 import org.junit.Before;
 import org.junit.Test;
@@ -60,8 +50,6 @@ import org.mockito.MockitoAnnotations;
 @TestableLooper.RunWithLooper
 @SmallTest
 public class QCUserPickerButtonControllerTest extends SysuiTestCase {
-    private final UserInfo mUserInfo =
-            new UserInfo(/* id= */ 0, /* name= */ "Test User", /* flags= */ 0);
     @Mock
     private Car mCar;
     @Mock
@@ -69,12 +57,6 @@ public class QCUserPickerButtonControllerTest extends SysuiTestCase {
     @Mock
     private UserTracker mUserTracker;
     @Mock
-    private BroadcastDispatcher mBroadcastDispatcher;
-    @Mock
-    private UserManager mUserManager;
-    @Mock
-    private ImageView mUserIconView;
-    @Mock
     private CarServiceProvider mCarServiceProvider;
     @Mock
     private CarSystemBarElementStatusBarDisableController mDisableController;
@@ -91,16 +73,12 @@ public class QCUserPickerButtonControllerTest extends SysuiTestCase {
 
         mContext = spy(mContext);
         mUserHandle = UserHandle.of(1000);
-        when(mContext.getSystemService(UserManager.class)).thenReturn(mUserManager);
         when(mUserTracker.getUserHandle()).thenReturn(mUserHandle);
-        when(mUserTracker.getUserInfo()).thenReturn(mUserInfo);
         when(mCar.getCarManager(CarActivityManager.class)).thenReturn(mCarActivityManager);
 
         mView = spy(new QCFooterView(mContext));
-        when(mView.findViewById(R.id.user_icon)).thenReturn(mUserIconView);
         mController = new QCUserPickerButtonController(mView, mDisableController,
-                mStateController, mContext, mUserTracker, mCarServiceProvider,
-                mBroadcastDispatcher);
+                mStateController, mContext, mUserTracker, mCarServiceProvider);
         mController.init();
 
         attachCarService();
@@ -116,21 +94,6 @@ public class QCUserPickerButtonControllerTest extends SysuiTestCase {
         verify(mCarActivityManager).startUserPickerOnDisplay(eq(displayId));
     }
 
-    @Test
-    public void onInit_setUserIconView() {
-        verify(mUserIconView).setImageDrawable(any(Drawable.class));
-    }
-
-    @Test
-    public void onDetachedFromWindow_removeUserNameView() {
-        spyOn(mController.mUserNameViewController);
-        UserNameViewController controllerSpy = mController.mUserNameViewController;
-
-        mController.onViewDetached();
-
-        verify(controllerSpy).removeUserNameView(eq(mView));
-    }
-
     private void attachCarService() {
         ArgumentCaptor<CarServiceProvider.CarServiceOnConnectedListener> captor =
                 ArgumentCaptor.forClass(CarServiceProvider.CarServiceOnConnectedListener.class);
diff --git a/tests/src/com/android/systemui/car/statusbar/UserNameViewControllerTest.java b/tests/src/com/android/systemui/car/statusbar/UserNameViewControllerTest.java
deleted file mode 100644
index 27d0ae9c..00000000
--- a/tests/src/com/android/systemui/car/statusbar/UserNameViewControllerTest.java
+++ /dev/null
@@ -1,229 +0,0 @@
-/*
- * Copyright (C) 2020 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-package com.android.systemui.car.statusbar;
-
-import static com.android.dx.mockito.inline.extended.ExtendedMockito.doReturn;
-import static com.android.dx.mockito.inline.extended.ExtendedMockito.spyOn;
-import static com.android.dx.mockito.inline.extended.ExtendedMockito.verify;
-
-import static org.junit.Assert.assertEquals;
-import static org.mockito.ArgumentMatchers.any;
-import static org.mockito.Mockito.eq;
-import static org.mockito.Mockito.never;
-import static org.mockito.Mockito.reset;
-import static org.mockito.Mockito.verifyZeroInteractions;
-import static org.mockito.Mockito.when;
-
-import android.content.BroadcastReceiver;
-import android.content.Intent;
-import android.content.pm.UserInfo;
-import android.graphics.drawable.Drawable;
-import android.os.UserManager;
-import android.testing.AndroidTestingRunner;
-import android.testing.TestableLooper;
-import android.view.View;
-import android.widget.ImageView;
-import android.widget.TextView;
-
-import androidx.test.filters.SmallTest;
-
-import com.android.systemui.R;
-import com.android.systemui.SysuiTestCase;
-import com.android.systemui.broadcast.BroadcastDispatcher;
-import com.android.systemui.car.CarSystemUiTest;
-import com.android.systemui.settings.UserTracker;
-
-import org.junit.Before;
-import org.junit.Test;
-import org.junit.runner.RunWith;
-import org.mockito.ArgumentCaptor;
-import org.mockito.Mock;
-import org.mockito.MockitoAnnotations;
-
-@CarSystemUiTest
-@RunWith(AndroidTestingRunner.class)
-@TestableLooper.RunWithLooper
-@SmallTest
-public class UserNameViewControllerTest extends SysuiTestCase {
-    private final UserInfo mUserInfo1 =
-            new UserInfo(/* id= */ 0, /* name= */ "User 1", /* flags= */ 0);
-    private final UserInfo mUserInfo2 =
-            new UserInfo(/* id= */ 1, /* name= */ "User 2", /* flags= */ 0);
-
-    private TextView mTextView;
-    private ImageView mImageView;
-    private View mView;
-    private UserNameViewController mUserNameViewController;
-
-    @Mock
-    private UserTracker mUserTracker;
-    @Mock
-    private UserManager mUserManager;
-    @Mock
-    private Drawable mDrawable;
-    @Mock
-    private BroadcastDispatcher mBroadcastDispatcher;
-
-    @Before
-    public void setUp() {
-        MockitoAnnotations.initMocks(this);
-
-        when(mUserManager.getUserInfo(mUserInfo1.id)).thenReturn(mUserInfo1);
-        when(mUserManager.getUserInfo(mUserInfo2.id)).thenReturn(mUserInfo2);
-
-        mUserNameViewController = new UserNameViewController(getContext(), mUserTracker,
-                mUserManager, mBroadcastDispatcher);
-        spyOn(mUserNameViewController.mUserIconProvider);
-        spyOn(mUserNameViewController.mUserNameViews);
-        spyOn(mUserNameViewController.mUserIconViews);
-
-        mView = new View(getContext());
-        spyOn(mView);
-
-        mTextView = new TextView(getContext());
-        mTextView.setId(R.id.user_name_text);
-        mImageView = new ImageView(getContext());
-        spyOn(mImageView);
-
-        doReturn(mTextView).when(mView).findViewById(eq(R.id.user_name_text));
-        doReturn(mImageView).when(mView).findViewById(eq(R.id.user_icon));
-    }
-
-    @Test
-    public void addUserNameViewToController_withTextView_updatesUserNameView() {
-        when(mUserTracker.getUserId()).thenReturn(mUserInfo1.id);
-
-        mUserNameViewController.addUserNameView(mTextView);
-
-        assertEquals(mTextView.getText(), mUserInfo1.name);
-    }
-
-    @Test
-    public void addUserNameViewToController_withTextAndImageView_updatesViews() {
-        when(mUserTracker.getUserId()).thenReturn(mUserInfo1.id);
-        when(mUserNameViewController.mUserIconProvider.getRoundedUserIcon(mUserInfo1, mContext))
-                .thenReturn(mDrawable);
-
-        mUserNameViewController.addUserNameView(mView);
-
-        verify(mUserNameViewController.mUserNameViews).add(eq(mTextView));
-        verify(mUserNameViewController.mUserIconViews).add(eq(mImageView));
-        verify(mUserNameViewController.mUserIconProvider).setRoundedUserIcon(eq(mUserInfo1), any());
-        verify(mImageView).setImageDrawable(eq(mDrawable));
-    }
-
-    @Test
-    public void addUserNameViewToController_withNoTextView_doesNotUpdate() {
-        View nullView = new View(getContext());
-
-        mUserNameViewController.addUserNameView(nullView);
-
-        assertEquals(mTextView.getText(), "");
-        verify(mUserTracker, never()).addCallback(any(), any());
-        verifyZeroInteractions(mUserManager);
-    }
-
-    @Test
-    public void removeUserNameViewToController_textViewAndImageViewAdded_removeViews() {
-        when(mUserTracker.getUserId()).thenReturn(mUserInfo1.id);
-        when(mUserNameViewController.mUserIconProvider.getRoundedUserIcon(mUserInfo1, mContext))
-                .thenReturn(mDrawable);
-        mUserNameViewController.addUserNameView(mView);
-        mUserNameViewController.removeUserNameView(mView);
-
-        verify(mUserNameViewController.mUserNameViews).remove(eq(mTextView));
-        verify(mUserNameViewController.mUserIconViews).remove(eq(mImageView));
-    }
-
-    @Test
-    public void removeAll_withNoRegisteredListener_doesNotUnregister() {
-        mUserNameViewController.removeAll();
-
-        verifyZeroInteractions(mUserTracker);
-        verifyZeroInteractions(mBroadcastDispatcher);
-    }
-
-    @Test
-    public void userLifecycleListener_onUserSwitchLifecycleEvent_updatesUserNameView() {
-        ArgumentCaptor<UserTracker.Callback> userTrackerCallbackCaptor =
-                ArgumentCaptor.forClass(UserTracker.Callback.class);
-        when(mUserTracker.getUserId()).thenReturn(mUserInfo1.id);
-        // Add the initial TextView, which registers the UserLifecycleListener
-        mUserNameViewController.addUserNameView(mTextView);
-        assertEquals(mTextView.getText(), mUserInfo1.name);
-        verify(mUserTracker).addCallback(userTrackerCallbackCaptor.capture(), any());
-
-        userTrackerCallbackCaptor.getValue().onUserChanged(mUserInfo2.id, mContext);
-
-        assertEquals(mTextView.getText(), mUserInfo2.name);
-    }
-
-    @Test
-    public void userInfoChangedBroadcast_withUserNameViewInitialized_updatesUserNameView() {
-        ArgumentCaptor<BroadcastReceiver> broadcastReceiverArgumentCaptor = ArgumentCaptor.forClass(
-                BroadcastReceiver.class);
-        when(mUserTracker.getUserId()).thenReturn(mUserInfo1.id);
-        mUserNameViewController.addUserNameView(mTextView);
-        assertEquals(mTextView.getText(), mUserInfo1.name);
-        verify(mBroadcastDispatcher).registerReceiver(broadcastReceiverArgumentCaptor.capture(),
-                any(), any(), any());
-
-        reset(mUserTracker);
-        when(mUserTracker.getUserId()).thenReturn(mUserInfo2.id);
-        broadcastReceiverArgumentCaptor.getValue().onReceive(getContext(),
-                new Intent(Intent.ACTION_USER_INFO_CHANGED));
-
-        assertEquals(mTextView.getText(), mUserInfo2.name);
-        verify(mUserTracker).getUserId();
-    }
-
-    @Test
-    public void userInfoChangedBroadcast_whenUserNameIsSame_notSetRoundedUserIcon() {
-        ArgumentCaptor<BroadcastReceiver> broadcastReceiverArgumentCaptor = ArgumentCaptor.forClass(
-                BroadcastReceiver.class);
-        when(mUserTracker.getUserId()).thenReturn(mUserInfo1.id);
-        mUserNameViewController.addUserNameView(mView);
-        assertEquals(mTextView.getText(), mUserInfo1.name);
-        verify(mBroadcastDispatcher).registerReceiver(broadcastReceiverArgumentCaptor.capture(),
-                any(), any(), any());
-        reset(mUserNameViewController.mUserIconProvider);
-
-        broadcastReceiverArgumentCaptor.getValue().onReceive(getContext(),
-                new Intent(Intent.ACTION_USER_INFO_CHANGED));
-
-        verify(mUserNameViewController.mUserIconProvider, never())
-                .setRoundedUserIcon(eq(mUserInfo1), any());
-    }
-
-    @Test
-    public void userInfoChangedBroadcast_whenUserNameIsChanged_setRoundedUserIcon() {
-        ArgumentCaptor<BroadcastReceiver> broadcastReceiverArgumentCaptor = ArgumentCaptor.forClass(
-                BroadcastReceiver.class);
-        when(mUserTracker.getUserId()).thenReturn(mUserInfo1.id);
-        mUserNameViewController.addUserNameView(mView);
-        assertEquals(mTextView.getText(), mUserInfo1.name);
-        verify(mBroadcastDispatcher).registerReceiver(broadcastReceiverArgumentCaptor.capture(),
-                any(), any(), any());
-        reset(mUserNameViewController.mUserIconProvider);
-        mUserInfo1.name = "User X";
-
-        broadcastReceiverArgumentCaptor.getValue().onReceive(getContext(),
-                new Intent(Intent.ACTION_USER_INFO_CHANGED));
-
-        verify(mUserNameViewController.mUserIconProvider).setRoundedUserIcon(eq(mUserInfo1), any());
-    }
-}
diff --git a/tests/src/com/android/systemui/car/statusicon/StatusIconPanelViewControllerTest.java b/tests/src/com/android/systemui/car/statusicon/StatusIconPanelViewControllerTest.java
index ad11c941..98ef2c2b 100644
--- a/tests/src/com/android/systemui/car/statusicon/StatusIconPanelViewControllerTest.java
+++ b/tests/src/com/android/systemui/car/statusicon/StatusIconPanelViewControllerTest.java
@@ -45,7 +45,6 @@ import com.android.systemui.R;
 import com.android.systemui.SysuiTestCase;
 import com.android.systemui.broadcast.BroadcastDispatcher;
 import com.android.systemui.car.CarDeviceProvisionedController;
-import com.android.systemui.car.CarServiceProvider;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.car.systembar.element.CarSystemBarElementInitializer;
 import com.android.systemui.settings.UserTracker;
@@ -71,8 +70,6 @@ public class StatusIconPanelViewControllerTest extends SysuiTestCase {
     @Mock
     private UserTracker mUserTracker;
     @Mock
-    private CarServiceProvider mCarServiceProvider;
-    @Mock
     private BroadcastDispatcher mBroadcastDispatcher;
     @Mock
     private ConfigurationController mConfigurationController;
@@ -93,8 +90,8 @@ public class StatusIconPanelViewControllerTest extends SysuiTestCase {
         mAnchorView.setImageDrawable(mContext.getDrawable(R.drawable.ic_bluetooth_status_off));
         mAnchorView.setColorFilter(mContext.getColor(R.color.car_status_icon_color));
         mViewController = new StatusIconPanelViewController.Builder(mContext, mUserTracker,
-                mCarServiceProvider, mBroadcastDispatcher, mConfigurationController,
-                mDeviceProvisionedController, mCarSystemBarElementInitializer).build(mAnchorView,
+                mBroadcastDispatcher, mConfigurationController, mDeviceProvisionedController,
+                mCarSystemBarElementInitializer).build(mAnchorView,
                 R.layout.qc_display_panel, R.dimen.car_status_icon_panel_default_width);
         spyOn(mViewController);
         reset(mAnchorView);
@@ -115,13 +112,11 @@ public class StatusIconPanelViewControllerTest extends SysuiTestCase {
         verify(mBroadcastDispatcher).registerReceiver(any(), any(), any(), any());
         verify(mUserTracker).addCallback(any(), any());
         verify(mConfigurationController).addCallback(any());
-        verify(mCarServiceProvider).addListener(any());
     }
 
     @Test
     public void onViewDetached_unregistersListeners() {
         mViewController.onViewDetached();
-        verify(mCarServiceProvider).removeListener(any());
         verify(mConfigurationController).removeCallback(any());
         verify(mUserTracker).removeCallback(any());
         verify(mBroadcastDispatcher).unregisterReceiver(any());
diff --git a/tests/src/com/android/systemui/car/statusicon/ui/MediaVolumeStatusIconControllerTest.java b/tests/src/com/android/systemui/car/statusicon/ui/MediaVolumeStatusIconControllerTest.java
index 91d3fb93..0ae76ecd 100644
--- a/tests/src/com/android/systemui/car/statusicon/ui/MediaVolumeStatusIconControllerTest.java
+++ b/tests/src/com/android/systemui/car/statusicon/ui/MediaVolumeStatusIconControllerTest.java
@@ -217,6 +217,7 @@ public class MediaVolumeStatusIconControllerTest extends SysuiTestCase {
         doReturn(mCarOccupantZoneManager).when(mCar).getCarManager(Car.CAR_OCCUPANT_ZONE_SERVICE);
         mInfo.zoneId = mInitZoneId;
         doReturn(mInfo).when(mCarOccupantZoneManager).getMyOccupantZone();
+        doReturn(mInitZoneId).when(mCarOccupantZoneManager).getAudioZoneIdForOccupant(mInfo);
         doReturn(mCarAudioManager).when(mCar).getCarManager(Car.AUDIO_SERVICE);
         doReturn(mInitGroupId).when(mCarAudioManager)
                 .getVolumeGroupIdForUsage(mInitZoneId, USAGE_MEDIA);
diff --git a/tests/src/com/android/systemui/car/systembar/CameraPrivacyChipViewControllerTest.java b/tests/src/com/android/systemui/car/systembar/CameraPrivacyChipViewControllerTest.java
index a2fbcdc6..47aeff09 100644
--- a/tests/src/com/android/systemui/car/systembar/CameraPrivacyChipViewControllerTest.java
+++ b/tests/src/com/android/systemui/car/systembar/CameraPrivacyChipViewControllerTest.java
@@ -66,6 +66,7 @@ import java.util.concurrent.Executor;
 @TestableLooper.RunWithLooper
 @SmallTest
 public class CameraPrivacyChipViewControllerTest extends SysuiTestCase {
+    private static final int TEST_USER_ID = 1001;
 
     private CameraPrivacyChipViewController mCameraPrivacyChipViewController;
     private FrameLayout mFrameLayout;
@@ -106,6 +107,7 @@ public class CameraPrivacyChipViewControllerTest extends SysuiTestCase {
 
         when(mContext.getMainExecutor()).thenReturn(mExecutor);
         when(mCar.isConnected()).thenReturn(true);
+        when(mUserTracker.getUserId()).thenReturn(TEST_USER_ID);
 
         mCameraPrivacyChipViewController = new CameraPrivacyChipViewController(mContext,
                 mPrivacyItemController, mSensorPrivacyManager, mUserTracker);
@@ -311,7 +313,8 @@ public class CameraPrivacyChipViewControllerTest extends SysuiTestCase {
 
         mCameraPrivacyChipViewController.toggleSensor();
 
-        verify(mSensorPrivacyManager).setSensorPrivacy(eq(QS_TILE), eq(CAMERA), eq(true));
+        verify(mSensorPrivacyManager).setSensorPrivacy(eq(QS_TILE), eq(CAMERA), eq(true),
+                eq(TEST_USER_ID));
     }
 
     @Test
@@ -321,6 +324,7 @@ public class CameraPrivacyChipViewControllerTest extends SysuiTestCase {
 
         mCameraPrivacyChipViewController.toggleSensor();
 
-        verify(mSensorPrivacyManager).setSensorPrivacy(eq(QS_TILE), eq(CAMERA), eq(false));
+        verify(mSensorPrivacyManager).setSensorPrivacy(eq(QS_TILE), eq(CAMERA), eq(false),
+                eq(TEST_USER_ID));
     }
 }
diff --git a/tests/src/com/android/systemui/car/systembar/CarSystemBarButtonTest.java b/tests/src/com/android/systemui/car/systembar/CarSystemBarButtonTest.java
index d53ac25b..ed3947ff 100644
--- a/tests/src/com/android/systemui/car/systembar/CarSystemBarButtonTest.java
+++ b/tests/src/com/android/systemui/car/systembar/CarSystemBarButtonTest.java
@@ -21,6 +21,7 @@ import static android.app.WindowConfiguration.WINDOWING_MODE_FULLSCREEN;
 
 import static com.google.common.truth.Truth.assertThat;
 
+import static org.junit.Assume.assumeFalse;
 import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.ArgumentMatchers.argThat;
@@ -34,6 +35,7 @@ import static org.mockito.Mockito.when;
 import android.app.ActivityManager;
 import android.app.ActivityTaskManager;
 import android.content.Intent;
+import android.content.pm.PackageManager;
 import android.graphics.drawable.Drawable;
 import android.os.RemoteException;
 import android.testing.AndroidTestingRunner;
@@ -252,6 +254,8 @@ public class CarSystemBarButtonTest extends SysuiTestCase {
 
     @Test
     public void onClick_launchesIntentActivity() {
+        assumeFalse(hasSplitscreenMultitaskingFeature());
+
         mDefaultButton.performClick();
 
         CarSystemBarButton dialerButton = mTestView.findViewById(R.id.dialer_activity);
@@ -263,6 +267,8 @@ public class CarSystemBarButtonTest extends SysuiTestCase {
 
     @Test
     public void onLongClick_longIntentDefined_launchesLongIntentActivity() {
+        assumeFalse(hasSplitscreenMultitaskingFeature());
+
         mDefaultButton.performClick();
         waitForIdleSync();
 
@@ -378,4 +384,12 @@ public class CarSystemBarButtonTest extends SysuiTestCase {
             return null;
         }
     }
+
+    /**
+     * Checks whether the device has automotive split-screen multitasking feature enabled
+     */
+    private boolean hasSplitscreenMultitaskingFeature() {
+        return mContext.getPackageManager()
+            .hasSystemFeature(PackageManager.FEATURE_CAR_SPLITSCREEN_MULTITASKING);
+    }
 }
diff --git a/tests/src/com/android/systemui/car/systembar/CarSystemBarControllerTest.java b/tests/src/com/android/systemui/car/systembar/CarSystemBarControllerTest.java
index 0c643514..703b1b07 100644
--- a/tests/src/com/android/systemui/car/systembar/CarSystemBarControllerTest.java
+++ b/tests/src/com/android/systemui/car/systembar/CarSystemBarControllerTest.java
@@ -20,6 +20,10 @@ import static android.app.StatusBarManager.DISABLE2_QUICK_SETTINGS;
 import static android.app.StatusBarManager.DISABLE_HOME;
 import static android.app.StatusBarManager.DISABLE_NOTIFICATION_ICONS;
 
+import static com.android.systemui.car.systembar.CarSystemBarController.BOTTOM;
+import static com.android.systemui.car.systembar.CarSystemBarController.LEFT;
+import static com.android.systemui.car.systembar.CarSystemBarController.RIGHT;
+import static com.android.systemui.car.systembar.CarSystemBarController.TOP;
 import static com.android.dx.mockito.inline.extended.ExtendedMockito.doReturn;
 
 import static com.google.common.truth.Truth.assertThat;
@@ -38,25 +42,45 @@ import android.content.Context;
 import android.testing.AndroidTestingRunner;
 import android.testing.TestableLooper;
 import android.testing.TestableResources;
+import android.util.ArrayMap;
 import android.view.View;
 import android.view.ViewGroup;
+import android.view.WindowManager;
 
 import androidx.test.filters.SmallTest;
 
 import com.android.car.dockutil.Flags;
 import com.android.car.ui.FocusParkingView;
 import com.android.dx.mockito.inline.extended.ExtendedMockito;
+import com.android.internal.statusbar.IStatusBarService;
+import com.android.internal.statusbar.LetterboxDetails;
+import com.android.internal.statusbar.RegisterStatusBarResult;
+import com.android.internal.view.AppearanceRegion;
 import com.android.systemui.R;
 import com.android.systemui.SysuiTestCase;
+import com.android.systemui.car.CarDeviceProvisionedController;
 import com.android.systemui.car.CarSystemUiTest;
-import com.android.systemui.car.statusbar.UserNameViewController;
+import com.android.systemui.car.hvac.HvacController;
+import com.android.systemui.car.hvac.HvacPanelController;
+import com.android.systemui.car.notification.NotificationsShadeController;
 import com.android.systemui.car.statusicon.StatusIconPanelViewController;
 import com.android.systemui.car.systembar.element.CarSystemBarElementInitializer;
 import com.android.systemui.car.users.CarSystemUIUserUtil;
 import com.android.systemui.flags.FeatureFlags;
 import com.android.systemui.plugins.DarkIconDispatcher;
+import com.android.systemui.settings.FakeDisplayTracker;
 import com.android.systemui.settings.UserTracker;
+import com.android.systemui.statusbar.CommandQueue;
+import com.android.systemui.statusbar.phone.AutoHideController;
+import com.android.systemui.statusbar.phone.LightBarController;
+import com.android.systemui.statusbar.phone.PhoneStatusBarPolicy;
+import com.android.systemui.statusbar.phone.StatusBarSignalPolicy;
+import com.android.systemui.statusbar.phone.SysuiDarkIconDispatcher;
 import com.android.systemui.statusbar.phone.ui.StatusBarIconController;
+import com.android.systemui.statusbar.policy.ConfigurationController;
+import com.android.systemui.statusbar.policy.KeyguardStateController;
+import com.android.systemui.util.concurrency.FakeExecutor;
+import com.android.systemui.util.time.FakeSystemClock;
 
 import org.junit.After;
 import org.junit.Before;
@@ -77,7 +101,7 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
             "com.android.systemui.car.notification.TopNotificationPanelViewMediator";
     private static final String BOTTOM_NOTIFICATION_PANEL =
             "com.android.systemui.car.notification.BottomNotificationPanelViewMediator";
-    private CarSystemBarController mCarSystemBar;
+    private CarSystemBarControllerImpl mCarSystemBarController;
     private CarSystemBarViewFactory mCarSystemBarViewFactory;
     private TestableResources mTestableResources;
     private Context mSpiedContext;
@@ -92,8 +116,6 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
     @Mock
     private ButtonRoleHolderController mButtonRoleHolderController;
     @Mock
-    private UserNameViewController mUserNameViewController;
-    @Mock
     private MicPrivacyChipViewController mMicPrivacyChipViewController;
     @Mock
     private CameraPrivacyChipViewController mCameraPrivacyChipViewController;
@@ -105,6 +127,35 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
     private StatusIconPanelViewController mPanelController;
     @Mock
     private CarSystemBarElementInitializer mCarSystemBarElementInitializer;
+    @Mock
+    private LightBarController mLightBarController;
+    @Mock
+    private SysuiDarkIconDispatcher mStatusBarIconController;
+    @Mock
+    private WindowManager mWindowManager;
+    @Mock
+    private CarDeviceProvisionedController mDeviceProvisionedController;
+    @Mock
+    private AutoHideController mAutoHideController;
+    @Mock
+    private ButtonSelectionStateListener mButtonSelectionStateListener;
+    @Mock
+    private IStatusBarService mBarService;
+    @Mock
+    private KeyguardStateController mKeyguardStateController;
+    @Mock
+    private PhoneStatusBarPolicy mIconPolicy;
+    @Mock
+    private StatusBarIconController mIconController;
+    @Mock
+    private StatusBarSignalPolicy mSignalPolicy;
+    @Mock
+    private HvacController mHvacController;
+    @Mock
+    private ConfigurationController mConfigurationController;
+    @Mock
+    private CarSystemBarRestartTracker mCarSystemBarRestartTracker;
+    RegisterStatusBarResult mRegisterStatusBarResult;
 
     @Before
     public void setUp() throws Exception {
@@ -120,9 +171,16 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
                 mock(UserTracker.class), mCarSystemBarElementInitializer);
         setupPanelControllerBuilderMocks();
 
+        mRegisterStatusBarResult = new RegisterStatusBarResult(new ArrayMap<>(), 0, 0,
+                new AppearanceRegion[0], 0, 0, false, 0, false, 0, 0, "", 0,
+                new LetterboxDetails[0]);
+        when(mBarService.registerStatusBar(any())).thenReturn(mRegisterStatusBarResult);
+
         // Needed to inflate top navigation bar.
         mDependency.injectMockDependency(DarkIconDispatcher.class);
         mDependency.injectMockDependency(StatusBarIconController.class);
+
+        initCarSystemBar();
     }
 
     @After
@@ -132,38 +190,61 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
         }
     }
 
-    private CarSystemBarController createSystemBarController() {
-        return new CarSystemBarController(mSpiedContext, mUserTracker, mCarSystemBarViewFactory,
-                mButtonSelectionStateController, () -> mUserNameViewController,
-                () -> mMicPrivacyChipViewController, () -> mCameraPrivacyChipViewController,
+    private void initCarSystemBar() {
+        SystemBarConfigs systemBarConfigs = new SystemBarConfigs(mTestableResources.getResources());
+        FakeDisplayTracker displayTracker = new FakeDisplayTracker(mContext);
+        FakeExecutor executor = new FakeExecutor(new FakeSystemClock());
+
+        mCarSystemBarController = new CarSystemBarControllerImpl(mSpiedContext,
+                mUserTracker,
+                mCarSystemBarViewFactory,
+                mButtonSelectionStateController,
+                () -> mMicPrivacyChipViewController,
+                () -> mCameraPrivacyChipViewController,
                 mButtonRoleHolderController,
-                new SystemBarConfigs(mTestableResources.getResources()),
-                () -> mPanelControllerBuilder);
+                systemBarConfigs,
+                () -> mPanelControllerBuilder,
+                mLightBarController,
+                mStatusBarIconController,
+                mWindowManager,
+                mDeviceProvisionedController,
+                new CommandQueue(mContext, displayTracker),
+                mAutoHideController,
+                mButtonSelectionStateListener,
+                executor,
+                mBarService,
+                () -> mKeyguardStateController,
+                () -> mIconPolicy,
+                mHvacController,
+                mConfigurationController,
+                mCarSystemBarRestartTracker,
+                displayTracker,
+                null);
     }
 
     @Test
     public void testRemoveAll_callsButtonRoleHolderControllerRemoveAll() {
-        mCarSystemBar = createSystemBarController();
+        mCarSystemBarController.init();
 
-        mCarSystemBar.removeAll();
+        mCarSystemBarController.removeAll();
 
         verify(mButtonRoleHolderController).removeAll();
     }
 
     @Test
     public void testRemoveAll_callsButtonSelectionStateControllerRemoveAll() {
-        mCarSystemBar = createSystemBarController();
+        mCarSystemBarController.init();
 
-        mCarSystemBar.removeAll();
+        mCarSystemBarController.removeAll();
 
         verify(mButtonSelectionStateController).removeAll();
     }
 
     @Test
     public void testRemoveAll_callsPrivacyChipViewControllerRemoveAll() {
-        mCarSystemBar = createSystemBarController();
+        mCarSystemBarController.init();
 
-        mCarSystemBar.removeAll();
+        mCarSystemBarController.removeAll();
 
         verify(mMicPrivacyChipViewController).removeAll();
         verify(mCameraPrivacyChipViewController).removeAll();
@@ -177,9 +258,9 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
         // expected to crash.
         mTestableResources.addOverride(R.string.config_notificationPanelViewMediator,
                 BOTTOM_NOTIFICATION_PANEL);
-        mCarSystemBar = createSystemBarController();
+        mCarSystemBarController.init();
 
-        ViewGroup window = mCarSystemBar.getTopWindow();
+        ViewGroup window = mCarSystemBarController.getBarWindow(TOP);
 
         assertThat(window).isNull();
     }
@@ -187,9 +268,9 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
     @Test
     public void testGetTopWindow_topEnabled_returnsWindow() {
         mTestableResources.addOverride(R.bool.config_enableTopSystemBar, true);
-        mCarSystemBar = createSystemBarController();
+        mCarSystemBarController.init();
 
-        ViewGroup window = mCarSystemBar.getTopWindow();
+        ViewGroup window = mCarSystemBarController.getBarWindow(TOP);
 
         assertThat(window).isNotNull();
     }
@@ -197,10 +278,10 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
     @Test
     public void testGetTopWindow_topEnabled_calledTwice_returnsSameWindow() {
         mTestableResources.addOverride(R.bool.config_enableTopSystemBar, true);
-        mCarSystemBar = createSystemBarController();
+        mCarSystemBarController.init();
 
-        ViewGroup window1 = mCarSystemBar.getTopWindow();
-        ViewGroup window2 = mCarSystemBar.getTopWindow();
+        ViewGroup window1 = mCarSystemBarController.getBarWindow(TOP);
+        ViewGroup window2 = mCarSystemBarController.getBarWindow(TOP);
 
         assertThat(window1).isEqualTo(window2);
     }
@@ -213,9 +294,9 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
         // SystemUI is expected to crash.
         mTestableResources.addOverride(R.string.config_notificationPanelViewMediator,
                 TOP_NOTIFICATION_PANEL);
-        mCarSystemBar = createSystemBarController();
+        mCarSystemBarController.init();
 
-        ViewGroup window = mCarSystemBar.getBottomWindow();
+        ViewGroup window = mCarSystemBarController.getBarWindow(BOTTOM);
 
         assertThat(window).isNull();
     }
@@ -223,9 +304,9 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
     @Test
     public void testGetBottomWindow_bottomEnabled_returnsWindow() {
         mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
-        mCarSystemBar = createSystemBarController();
+        mCarSystemBarController.init();
 
-        ViewGroup window = mCarSystemBar.getBottomWindow();
+        ViewGroup window = mCarSystemBarController.getBarWindow(BOTTOM);
 
         assertThat(window).isNotNull();
     }
@@ -233,10 +314,10 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
     @Test
     public void testGetBottomWindow_bottomEnabled_calledTwice_returnsSameWindow() {
         mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
-        mCarSystemBar = createSystemBarController();
+        mCarSystemBarController.init();
 
-        ViewGroup window1 = mCarSystemBar.getBottomWindow();
-        ViewGroup window2 = mCarSystemBar.getBottomWindow();
+        ViewGroup window1 = mCarSystemBarController.getBarWindow(BOTTOM);
+        ViewGroup window2 = mCarSystemBarController.getBarWindow(BOTTOM);
 
         assertThat(window1).isEqualTo(window2);
     }
@@ -245,8 +326,8 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
     public void testGetLeftWindow_leftDisabled_returnsNull() {
         mTestableResources.addOverride(R.integer.config_showDisplayCompatToolbarOnSystemBar, 0);
         mTestableResources.addOverride(R.bool.config_enableLeftSystemBar, false);
-        mCarSystemBar = createSystemBarController();
-        ViewGroup window = mCarSystemBar.getLeftWindow();
+        mCarSystemBarController.init();
+        ViewGroup window = mCarSystemBarController.getBarWindow(LEFT);
         assertThat(window).isNull();
     }
 
@@ -254,9 +335,9 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
     public void testGetLeftWindow_leftEnabled_returnsWindow() {
         mTestableResources.addOverride(R.integer.config_showDisplayCompatToolbarOnSystemBar, 0);
         mTestableResources.addOverride(R.bool.config_enableLeftSystemBar, true);
-        mCarSystemBar = createSystemBarController();
+        mCarSystemBarController.init();
 
-        ViewGroup window = mCarSystemBar.getLeftWindow();
+        ViewGroup window = mCarSystemBarController.getBarWindow(LEFT);
 
         assertThat(window).isNotNull();
     }
@@ -265,10 +346,10 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
     public void testGetLeftWindow_leftEnabled_calledTwice_returnsSameWindow() {
         mTestableResources.addOverride(R.integer.config_showDisplayCompatToolbarOnSystemBar, 0);
         mTestableResources.addOverride(R.bool.config_enableLeftSystemBar, true);
-        mCarSystemBar = createSystemBarController();
+        mCarSystemBarController.init();
 
-        ViewGroup window1 = mCarSystemBar.getLeftWindow();
-        ViewGroup window2 = mCarSystemBar.getLeftWindow();
+        ViewGroup window1 = mCarSystemBarController.getBarWindow(LEFT);
+        ViewGroup window2 = mCarSystemBarController.getBarWindow(LEFT);
 
         assertThat(window1).isEqualTo(window2);
     }
@@ -276,9 +357,9 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
     @Test
     public void testGetRightWindow_rightDisabled_returnsNull() {
         mTestableResources.addOverride(R.bool.config_enableRightSystemBar, false);
-        mCarSystemBar = createSystemBarController();
+        mCarSystemBarController.init();
 
-        ViewGroup window = mCarSystemBar.getRightWindow();
+        ViewGroup window = mCarSystemBarController.getBarWindow(RIGHT);
 
         assertThat(window).isNull();
     }
@@ -286,9 +367,9 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
     @Test
     public void testGetRightWindow_rightEnabled_returnsWindow() {
         mTestableResources.addOverride(R.bool.config_enableRightSystemBar, true);
-        mCarSystemBar = createSystemBarController();
+        mCarSystemBarController.init();
 
-        ViewGroup window = mCarSystemBar.getRightWindow();
+        ViewGroup window = mCarSystemBarController.getBarWindow(RIGHT);
 
         assertThat(window).isNotNull();
     }
@@ -296,10 +377,10 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
     @Test
     public void testGetRightWindow_rightEnabled_calledTwice_returnsSameWindow() {
         mTestableResources.addOverride(R.bool.config_enableRightSystemBar, true);
-        mCarSystemBar = createSystemBarController();
+        mCarSystemBarController.init();
 
-        ViewGroup window1 = mCarSystemBar.getRightWindow();
-        ViewGroup window2 = mCarSystemBar.getRightWindow();
+        ViewGroup window1 = mCarSystemBarController.getBarWindow(RIGHT);
+        ViewGroup window2 = mCarSystemBarController.getBarWindow(RIGHT);
 
         assertThat(window1).isEqualTo(window2);
     }
@@ -307,10 +388,10 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
     @Test
     public void testSetTopWindowVisibility_setTrue_isVisible() {
         mTestableResources.addOverride(R.bool.config_enableTopSystemBar, true);
-        mCarSystemBar = createSystemBarController();
+        mCarSystemBarController.init();
 
-        ViewGroup window = mCarSystemBar.getTopWindow();
-        mCarSystemBar.setTopWindowVisibility(View.VISIBLE);
+        ViewGroup window = mCarSystemBarController.getBarWindow(TOP);
+        mCarSystemBarController.setTopWindowVisibility(View.VISIBLE);
 
         assertThat(window.getVisibility()).isEqualTo(View.VISIBLE);
     }
@@ -318,10 +399,10 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
     @Test
     public void testSetTopWindowVisibility_setFalse_isGone() {
         mTestableResources.addOverride(R.bool.config_enableTopSystemBar, true);
-        mCarSystemBar = createSystemBarController();
+        mCarSystemBarController.init();
 
-        ViewGroup window = mCarSystemBar.getTopWindow();
-        mCarSystemBar.setTopWindowVisibility(View.GONE);
+        ViewGroup window = mCarSystemBarController.getBarWindow(TOP);
+        mCarSystemBarController.setTopWindowVisibility(View.GONE);
 
         assertThat(window.getVisibility()).isEqualTo(View.GONE);
     }
@@ -329,10 +410,10 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
     @Test
     public void testSetBottomWindowVisibility_setTrue_isVisible() {
         mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
-        mCarSystemBar = createSystemBarController();
+        mCarSystemBarController.init();
 
-        ViewGroup window = mCarSystemBar.getBottomWindow();
-        mCarSystemBar.setBottomWindowVisibility(View.VISIBLE);
+        ViewGroup window = mCarSystemBarController.getBarWindow(BOTTOM);
+        mCarSystemBarController.setBottomWindowVisibility(View.VISIBLE);
 
         assertThat(window.getVisibility()).isEqualTo(View.VISIBLE);
     }
@@ -340,10 +421,10 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
     @Test
     public void testSetBottomWindowVisibility_setFalse_isGone() {
         mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
-        mCarSystemBar = createSystemBarController();
+        mCarSystemBarController.init();
 
-        ViewGroup window = mCarSystemBar.getBottomWindow();
-        mCarSystemBar.setBottomWindowVisibility(View.GONE);
+        ViewGroup window = mCarSystemBarController.getBarWindow(BOTTOM);
+        mCarSystemBarController.setBottomWindowVisibility(View.GONE);
 
         assertThat(window.getVisibility()).isEqualTo(View.GONE);
     }
@@ -352,10 +433,10 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
     public void testSetLeftWindowVisibility_setTrue_isVisible() {
         mTestableResources.addOverride(R.integer.config_showDisplayCompatToolbarOnSystemBar, 0);
         mTestableResources.addOverride(R.bool.config_enableLeftSystemBar, true);
-        mCarSystemBar = createSystemBarController();
+        mCarSystemBarController.init();
 
-        ViewGroup window = mCarSystemBar.getLeftWindow();
-        mCarSystemBar.setLeftWindowVisibility(View.VISIBLE);
+        ViewGroup window = mCarSystemBarController.getBarWindow(LEFT);
+        mCarSystemBarController.setLeftWindowVisibility(View.VISIBLE);
 
         assertThat(window.getVisibility()).isEqualTo(View.VISIBLE);
     }
@@ -364,10 +445,10 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
     public void testSetLeftWindowVisibility_setFalse_isGone() {
         mTestableResources.addOverride(R.integer.config_showDisplayCompatToolbarOnSystemBar, 0);
         mTestableResources.addOverride(R.bool.config_enableLeftSystemBar, true);
-        mCarSystemBar = createSystemBarController();
+        mCarSystemBarController.init();
 
-        ViewGroup window = mCarSystemBar.getLeftWindow();
-        mCarSystemBar.setLeftWindowVisibility(View.GONE);
+        ViewGroup window = mCarSystemBarController.getBarWindow(LEFT);
+        mCarSystemBarController.setLeftWindowVisibility(View.GONE);
 
         assertThat(window.getVisibility()).isEqualTo(View.GONE);
     }
@@ -375,10 +456,10 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
     @Test
     public void testSetRightWindowVisibility_setTrue_isVisible() {
         mTestableResources.addOverride(R.bool.config_enableRightSystemBar, true);
-        mCarSystemBar = createSystemBarController();
+        mCarSystemBarController.init();
 
-        ViewGroup window = mCarSystemBar.getRightWindow();
-        mCarSystemBar.setRightWindowVisibility(View.VISIBLE);
+        ViewGroup window = mCarSystemBarController.getBarWindow(RIGHT);
+        mCarSystemBarController.setRightWindowVisibility(View.VISIBLE);
 
         assertThat(window.getVisibility()).isEqualTo(View.VISIBLE);
     }
@@ -386,10 +467,10 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
     @Test
     public void testSetRightWindowVisibility_setFalse_isGone() {
         mTestableResources.addOverride(R.bool.config_enableRightSystemBar, true);
-        mCarSystemBar = createSystemBarController();
+        mCarSystemBarController.init();
 
-        ViewGroup window = mCarSystemBar.getRightWindow();
-        mCarSystemBar.setRightWindowVisibility(View.GONE);
+        ViewGroup window = mCarSystemBarController.getBarWindow(RIGHT);
+        mCarSystemBarController.setRightWindowVisibility(View.GONE);
 
         assertThat(window.getVisibility()).isEqualTo(View.GONE);
     }
@@ -397,13 +478,14 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
     @Test
     public void testRegisterBottomBarTouchListener_createViewFirst_registrationSuccessful() {
         mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
-        mCarSystemBar = createSystemBarController();
+        mCarSystemBarController.init();
 
-        CarSystemBarView bottomBar = mCarSystemBar.getBottomBar(/* isSetUp= */ true);
+        CarSystemBarView bottomBar = mCarSystemBarController.getBarView(BOTTOM,
+                /* isSetUp= */ true);
         Set<View.OnTouchListener> controllers = bottomBar.getStatusBarWindowTouchListeners();
         assertThat(controllers).isNotNull();
         assertThat(controllers.size()).isEqualTo(0);
-        mCarSystemBar.registerBottomBarTouchListener(mock(View.OnTouchListener.class));
+        mCarSystemBarController.registerBottomBarTouchListener(mock(View.OnTouchListener.class));
         controllers = bottomBar.getStatusBarWindowTouchListeners();
 
         assertThat(controllers).isNotNull();
@@ -413,10 +495,11 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
     @Test
     public void testRegisterBottomBarTouchListener_registerFirst_registrationSuccessful() {
         mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
-        mCarSystemBar = createSystemBarController();
+        mCarSystemBarController.init();
 
-        mCarSystemBar.registerBottomBarTouchListener(mock(View.OnTouchListener.class));
-        CarSystemBarView bottomBar = mCarSystemBar.getBottomBar(/* isSetUp= */ true);
+        mCarSystemBarController.registerBottomBarTouchListener(mock(View.OnTouchListener.class));
+        CarSystemBarView bottomBar = mCarSystemBarController.getBarView(BOTTOM,
+                /* isSetUp= */ true);
         Set<View.OnTouchListener> controllers = bottomBar.getStatusBarWindowTouchListeners();
 
         assertThat(controllers).isNotNull();
@@ -426,14 +509,15 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
     @Test
     public void testRegisterNotificationController_createViewFirst_registrationSuccessful() {
         mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
-        mCarSystemBar = createSystemBarController();
+        mCarSystemBarController.init();
 
-        CarSystemBarView bottomBar = mCarSystemBar.getBottomBar(/* isSetUp= */ true);
-        CarSystemBarController.NotificationsShadeController controller =
+        CarSystemBarView bottomBar = mCarSystemBarController.getBarView(BOTTOM,
+                /* isSetUp= */ true);
+        NotificationsShadeController controller =
                 bottomBar.getNotificationsPanelController();
         assertThat(controller).isNull();
-        mCarSystemBar.registerNotificationController(
-                mock(CarSystemBarController.NotificationsShadeController.class));
+        mCarSystemBarController.registerNotificationController(
+                mock(NotificationsShadeController.class));
         controller = bottomBar.getNotificationsPanelController();
 
         assertThat(controller).isNotNull();
@@ -442,12 +526,13 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
     @Test
     public void testRegisterNotificationController_registerFirst_registrationSuccessful() {
         mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
-        mCarSystemBar = createSystemBarController();
+        mCarSystemBarController.init();
 
-        mCarSystemBar.registerNotificationController(
-                mock(CarSystemBarController.NotificationsShadeController.class));
-        CarSystemBarView bottomBar = mCarSystemBar.getBottomBar(/* isSetUp= */ true);
-        CarSystemBarController.NotificationsShadeController controller =
+        mCarSystemBarController.registerNotificationController(
+                mock(NotificationsShadeController.class));
+        CarSystemBarView bottomBar = mCarSystemBarController.getBarView(BOTTOM,
+                /* isSetUp= */ true);
+        NotificationsShadeController controller =
                 bottomBar.getNotificationsPanelController();
 
         assertThat(controller).isNotNull();
@@ -456,13 +541,14 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
     @Test
     public void testRegisterHvacController_createViewFirst_registrationSuccessful() {
         mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
-        mCarSystemBar = createSystemBarController();
+        mCarSystemBarController.init();
 
-        CarSystemBarView bottomBar = mCarSystemBar.getBottomBar(/* isSetUp= */ true);
-        CarSystemBarController.HvacPanelController controller = bottomBar.getHvacPanelController();
+        CarSystemBarView bottomBar = mCarSystemBarController.getBarView(BOTTOM,
+                /* isSetUp= */ true);
+        HvacPanelController controller = bottomBar.getHvacPanelController();
         assertThat(controller).isNull();
-        mCarSystemBar.registerHvacPanelController(
-                mock(CarSystemBarController.HvacPanelController.class));
+        mCarSystemBarController.registerHvacPanelController(
+                mock(HvacPanelController.class));
         controller = bottomBar.getHvacPanelController();
 
         assertThat(controller).isNotNull();
@@ -471,12 +557,13 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
     @Test
     public void testRegisterHvacController_registerFirst_registrationSuccessful() {
         mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
-        mCarSystemBar = createSystemBarController();
+        mCarSystemBarController.init();
 
-        mCarSystemBar.registerHvacPanelController(
-                mock(CarSystemBarController.HvacPanelController.class));
-        CarSystemBarView bottomBar = mCarSystemBar.getBottomBar(/* isSetUp= */ true);
-        CarSystemBarController.HvacPanelController controller = bottomBar.getHvacPanelController();
+        mCarSystemBarController.registerHvacPanelController(
+                mock(HvacPanelController.class));
+        CarSystemBarView bottomBar = mCarSystemBarController.getBarView(BOTTOM,
+                /* isSetUp= */ true);
+        HvacPanelController controller = bottomBar.getHvacPanelController();
 
         assertThat(controller).isNotNull();
     }
@@ -484,11 +571,12 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
     @Test
     public void testShowAllNavigationButtons_bottomEnabled_bottomNavigationButtonsVisible() {
         mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
-        mCarSystemBar = createSystemBarController();
-        CarSystemBarView bottomBar = mCarSystemBar.getBottomBar(/* isSetUp= */ true);
+        mCarSystemBarController.init();
+        CarSystemBarView bottomBar = mCarSystemBarController.getBarView(BOTTOM,
+                /* isSetUp= */ true);
         View bottomNavButtons = bottomBar.findViewById(R.id.nav_buttons);
 
-        mCarSystemBar.showAllNavigationButtons(/* isSetUp= */ true);
+        mCarSystemBarController.showAllNavigationButtons();
 
         assertThat(bottomNavButtons.getVisibility()).isEqualTo(View.VISIBLE);
     }
@@ -496,11 +584,12 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
     @Test
     public void testShowAllNavigationButtons_bottomEnabled_bottomKeyguardButtonsGone() {
         mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
-        mCarSystemBar = createSystemBarController();
-        CarSystemBarView bottomBar = mCarSystemBar.getBottomBar(/* isSetUp= */ true);
+        mCarSystemBarController.init();
+        CarSystemBarView bottomBar = mCarSystemBarController.getBarView(BOTTOM,
+                /* isSetUp= */ true);
         View bottomKeyguardButtons = bottomBar.findViewById(R.id.lock_screen_nav_buttons);
 
-        mCarSystemBar.showAllNavigationButtons(/* isSetUp= */ true);
+        mCarSystemBarController.showAllNavigationButtons();
 
         assertThat(bottomKeyguardButtons.getVisibility()).isEqualTo(View.GONE);
     }
@@ -508,11 +597,12 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
     @Test
     public void testShowAllNavigationButtons_bottomEnabled_bottomOcclusionButtonsGone() {
         mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
-        mCarSystemBar = createSystemBarController();
-        CarSystemBarView bottomBar = mCarSystemBar.getBottomBar(/* isSetUp= */ true);
+        mCarSystemBarController.init();
+        CarSystemBarView bottomBar = mCarSystemBarController.getBarView(BOTTOM,
+                /* isSetUp= */ true);
         View occlusionButtons = bottomBar.findViewById(R.id.occlusion_buttons);
 
-        mCarSystemBar.showAllNavigationButtons(/* isSetUp= */ true);
+        mCarSystemBarController.showAllNavigationButtons();
 
         assertThat(occlusionButtons.getVisibility()).isEqualTo(View.GONE);
     }
@@ -520,11 +610,12 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
     @Test
     public void testShowAllKeyguardButtons_bottomEnabled_bottomKeyguardButtonsVisible() {
         mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
-        mCarSystemBar = createSystemBarController();
-        CarSystemBarView bottomBar = mCarSystemBar.getBottomBar(/* isSetUp= */ true);
+        mCarSystemBarController.init();
+        CarSystemBarView bottomBar = mCarSystemBarController.getBarView(BOTTOM,
+                /* isSetUp= */ true);
         View bottomKeyguardButtons = bottomBar.findViewById(R.id.lock_screen_nav_buttons);
 
-        mCarSystemBar.showAllKeyguardButtons(/* isSetUp= */ true);
+        mCarSystemBarController.showAllKeyguardButtons();
 
         assertThat(bottomKeyguardButtons.getVisibility()).isEqualTo(View.VISIBLE);
     }
@@ -532,11 +623,12 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
     @Test
     public void testShowAllKeyguardButtons_bottomEnabled_bottomNavigationButtonsGone() {
         mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
-        mCarSystemBar = createSystemBarController();
-        CarSystemBarView bottomBar = mCarSystemBar.getBottomBar(/* isSetUp= */ true);
+        mCarSystemBarController.init();
+        CarSystemBarView bottomBar = mCarSystemBarController.getBarView(BOTTOM,
+                /* isSetUp= */ true);
         View bottomNavButtons = bottomBar.findViewById(R.id.nav_buttons);
 
-        mCarSystemBar.showAllKeyguardButtons(/* isSetUp= */ true);
+        mCarSystemBarController.showAllKeyguardButtons();
 
         assertThat(bottomNavButtons.getVisibility()).isEqualTo(View.GONE);
     }
@@ -544,11 +636,12 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
     @Test
     public void testShowAllKeyguardButtons_bottomEnabled_bottomOcclusionButtonsGone() {
         mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
-        mCarSystemBar = createSystemBarController();
-        CarSystemBarView bottomBar = mCarSystemBar.getBottomBar(/* isSetUp= */ true);
+        mCarSystemBarController.init();
+        CarSystemBarView bottomBar = mCarSystemBarController.getBarView(BOTTOM,
+                /* isSetUp= */ true);
         View occlusionButtons = bottomBar.findViewById(R.id.occlusion_buttons);
 
-        mCarSystemBar.showAllKeyguardButtons(/* isSetUp= */ true);
+        mCarSystemBarController.showAllKeyguardButtons();
 
         assertThat(occlusionButtons.getVisibility()).isEqualTo(View.GONE);
     }
@@ -556,11 +649,12 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
     @Test
     public void testShowOcclusionButtons_bottomEnabled_bottomOcclusionButtonsVisible() {
         mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
-        mCarSystemBar = createSystemBarController();
-        CarSystemBarView bottomBar = mCarSystemBar.getBottomBar(/* isSetUp= */ true);
+        mCarSystemBarController.init();
+        CarSystemBarView bottomBar = mCarSystemBarController.getBarView(BOTTOM,
+                /* isSetUp= */ true);
         View occlusionButtons = bottomBar.findViewById(R.id.occlusion_buttons);
 
-        mCarSystemBar.showAllOcclusionButtons(/* isSetUp= */ true);
+        mCarSystemBarController.showAllOcclusionButtons();
 
         assertThat(occlusionButtons.getVisibility()).isEqualTo(View.VISIBLE);
     }
@@ -568,11 +662,12 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
     @Test
     public void testShowOcclusionButtons_bottomEnabled_bottomNavigationButtonsGone() {
         mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
-        mCarSystemBar = createSystemBarController();
-        CarSystemBarView bottomBar = mCarSystemBar.getBottomBar(/* isSetUp= */ true);
+        mCarSystemBarController.init();
+        CarSystemBarView bottomBar = mCarSystemBarController.getBarView(BOTTOM,
+                /* isSetUp= */ true);
         View bottomNavButtons = bottomBar.findViewById(R.id.nav_buttons);
 
-        mCarSystemBar.showAllOcclusionButtons(/* isSetUp= */ true);
+        mCarSystemBarController.showAllOcclusionButtons();
 
         assertThat(bottomNavButtons.getVisibility()).isEqualTo(View.GONE);
     }
@@ -580,11 +675,12 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
     @Test
     public void testShowOcclusionButtons_bottomEnabled_bottomKeyguardButtonsGone() {
         mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
-        mCarSystemBar = createSystemBarController();
-        CarSystemBarView bottomBar = mCarSystemBar.getBottomBar(/* isSetUp= */ true);
+        mCarSystemBarController.init();
+        CarSystemBarView bottomBar = mCarSystemBarController.getBarView(BOTTOM,
+                /* isSetUp= */ true);
         View keyguardButtons = bottomBar.findViewById(R.id.lock_screen_nav_buttons);
 
-        mCarSystemBar.showAllOcclusionButtons(/* isSetUp= */ true);
+        mCarSystemBarController.showAllOcclusionButtons();
 
         assertThat(keyguardButtons.getVisibility()).isEqualTo(View.GONE);
     }
@@ -592,11 +688,11 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
     @Test
     public void testToggleAllNotificationsUnseenIndicator_bottomEnabled_hasUnseen_setCorrectly() {
         enableSystemBarWithNotificationButton();
-        mCarSystemBar = createSystemBarController();
+        mCarSystemBarController.init();
         CarSystemBarButton notifications = getNotificationCarSystemBarButton();
 
         boolean hasUnseen = true;
-        mCarSystemBar.toggleAllNotificationsUnseenIndicator(/* isSetUp= */ true,
+        mCarSystemBarController.toggleAllNotificationsUnseenIndicator(/* isSetUp= */ true,
                 hasUnseen);
 
         assertThat(notifications.getUnseen()).isTrue();
@@ -605,11 +701,11 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
     @Test
     public void testToggleAllNotificationsUnseenIndicator_bottomEnabled_noUnseen_setCorrectly() {
         enableSystemBarWithNotificationButton();
-        mCarSystemBar = createSystemBarController();
+        mCarSystemBarController.init();
         CarSystemBarButton notifications = getNotificationCarSystemBarButton();
 
         boolean hasUnseen = false;
-        mCarSystemBar.toggleAllNotificationsUnseenIndicator(/* isSetUp= */ true,
+        mCarSystemBarController.toggleAllNotificationsUnseenIndicator(/* isSetUp= */ true,
                 hasUnseen);
 
         assertThat(notifications.getUnseen()).isFalse();
@@ -618,35 +714,36 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
     @Test
     public void testSetSystemBarStates_stateUpdated() {
         mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
-        mCarSystemBar = createSystemBarController();
+        mCarSystemBarController.init();
         clearSystemBarStates();
 
-        mCarSystemBar.setSystemBarStates(DISABLE_HOME, /* state2= */ 0);
+        mCarSystemBarController.setSystemBarStates(DISABLE_HOME, /* state2= */ 0);
 
-        assertThat(mCarSystemBar.getStatusBarState()).isEqualTo(DISABLE_HOME);
+        assertThat(mCarSystemBarController.getStatusBarState()).isEqualTo(DISABLE_HOME);
     }
 
     @Test
     public void testSetSystemBarStates_state2Updated() {
         mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
-        mCarSystemBar = createSystemBarController();
+        mCarSystemBarController.init();
         clearSystemBarStates();
 
-        mCarSystemBar.setSystemBarStates(0, DISABLE2_QUICK_SETTINGS);
+        mCarSystemBarController.setSystemBarStates(0, DISABLE2_QUICK_SETTINGS);
 
-        assertThat(mCarSystemBar.getStatusBarState2()).isEqualTo(DISABLE2_QUICK_SETTINGS);
+        assertThat(mCarSystemBarController.getStatusBarState2()).isEqualTo(DISABLE2_QUICK_SETTINGS);
     }
 
     @Test
     public void testRefreshSystemBar_homeDisabled() {
         mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
-        mCarSystemBar = createSystemBarController();
-        CarSystemBarView bottomBar = mCarSystemBar.getBottomBar(/* isSetUp= */ true);
+        mCarSystemBarController.init();
+        CarSystemBarView bottomBar = mCarSystemBarController.getBarView(BOTTOM,
+                /* isSetUp= */ true);
         clearSystemBarStates();
         CarSystemBarButton button = bottomBar.findViewById(R.id.home);
         assertThat(button.getDisabled()).isFalse();
 
-        mCarSystemBar.setSystemBarStates(DISABLE_HOME, /* state2= */ 0);
+        mCarSystemBarController.setSystemBarStates(DISABLE_HOME, /* state2= */ 0);
 
         assertThat(button.getDisabled()).isTrue();
     }
@@ -656,8 +753,9 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
         assumeFalse("Phone nav button is removed when Dock is enabled", Flags.dockFeature());
 
         mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
-        mCarSystemBar = createSystemBarController();
-        CarSystemBarView bottomBar = mCarSystemBar.getBottomBar(/* isSetUp= */ true);
+        mCarSystemBarController.init();
+        CarSystemBarView bottomBar = mCarSystemBarController.getBarView(BOTTOM,
+                /* isSetUp= */ true);
         clearSystemBarStates();
         CarSystemBarButton button = bottomBar.findViewById(R.id.phone_nav);
         assertThat(button.getDisabled()).isFalse();
@@ -670,13 +768,14 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
     @Test
     public void testRefreshSystemBar_appGridisabled() {
         mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
-        mCarSystemBar = createSystemBarController();
-        CarSystemBarView bottomBar = mCarSystemBar.getBottomBar(/* isSetUp= */ true);
+        mCarSystemBarController.init();
+        CarSystemBarView bottomBar = mCarSystemBarController.getBarView(BOTTOM,
+                /* isSetUp= */ true);
         clearSystemBarStates();
         CarSystemBarButton button = bottomBar.findViewById(R.id.grid_nav);
         assertThat(button.getDisabled()).isFalse();
 
-        mCarSystemBar.setSystemBarStates(DISABLE_HOME, /* state2= */ 0);
+        mCarSystemBarController.setSystemBarStates(DISABLE_HOME, /* state2= */ 0);
 
         assertThat(button.getDisabled()).isTrue();
     }
@@ -684,53 +783,24 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
     @Test
     public void testRefreshSystemBar_notificationDisabled() {
         enableSystemBarWithNotificationButton();
-        mCarSystemBar = createSystemBarController();
+        mCarSystemBarController.init();
         clearSystemBarStates();
         CarSystemBarButton button = getNotificationCarSystemBarButton();
         assertThat(button.getDisabled()).isFalse();
 
-        mCarSystemBar.setSystemBarStates(DISABLE_NOTIFICATION_ICONS, /* state2= */ 0);
+        mCarSystemBarController.setSystemBarStates(DISABLE_NOTIFICATION_ICONS, /* state2= */ 0);
 
         assertThat(button.getDisabled()).isTrue();
     }
 
-    @Test
-    public void testRefreshSystemBar_disableQcFlagOn_userSwitcherHidden() {
-        mTestableResources.addOverride(R.bool.config_enableTopSystemBar, true);
-        mCarSystemBar = createSystemBarController();
-        CarSystemBarView topBar = mCarSystemBar.getTopBar(/* isSetUp= */ true);
-
-        View userSwitcher = topBar.findViewById(R.id.user_name_container);
-        clearSystemBarStates();
-        assertThat(userSwitcher.getVisibility()).isEqualTo(View.VISIBLE);
-
-        mCarSystemBar.setSystemBarStates(0, DISABLE2_QUICK_SETTINGS);
-
-        assertThat(userSwitcher.getVisibility()).isEqualTo(View.INVISIBLE);
-    }
-
-    @Test
-    public void testRefreshSystemBar_lockTaskModeOn_userSwitcherHidden() {
-        mTestableResources.addOverride(R.bool.config_enableTopSystemBar, true);
-        mCarSystemBar = createSystemBarController();
-        CarSystemBarView topBar = mCarSystemBar.getTopBar(/* isSetUp= */ true);
-        View userSwitcher = topBar.findViewById(R.id.user_name_container);
-        clearSystemBarStates();
-        assertThat(userSwitcher.getVisibility()).isEqualTo(View.VISIBLE);
-
-        setLockTaskModeLocked(/* locked= */ true);
-
-        assertThat(userSwitcher.getVisibility()).isEqualTo(View.INVISIBLE);
-    }
-
     @Test
     public void cacheAndHideFocus_doesntCallHideFocus_if_focusParkingViewIsFocused() {
-        mCarSystemBar = createSystemBarController();
+        mCarSystemBarController.init();
         View mockFocusParkingView = mock(FocusParkingView.class);
         View mockContainerView = mock(View.class);
         when(mockContainerView.findFocus()).thenReturn(mockFocusParkingView);
 
-        int returnFocusedViewId = mCarSystemBar.cacheAndHideFocus(mockContainerView);
+        int returnFocusedViewId = mCarSystemBarController.cacheAndHideFocus(mockContainerView);
 
         assertThat(returnFocusedViewId).isEqualTo(View.NO_ID);
     }
@@ -740,9 +810,10 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
         doReturn(false).when(() ->
                 CarSystemUIUserUtil.isSecondaryMUMDSystemUI());
         mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, /* value= */ true);
-        mCarSystemBar = createSystemBarController();
+        mCarSystemBarController.init();
 
-        CarSystemBarView bottomBar = mCarSystemBar.getBottomBar(/* isSetUp= */ true);
+        CarSystemBarView bottomBar = mCarSystemBarController.getBarView(BOTTOM,
+                /* isSetUp= */ true);
         View driverHomeButton = bottomBar.findViewById(R.id.home);
         View passengerHomeButton = bottomBar.findViewById(R.id.passenger_home);
 
@@ -755,9 +826,10 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
         doReturn(true).when(() ->
                 CarSystemUIUserUtil.isSecondaryMUMDSystemUI());
         mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
-        mCarSystemBar = createSystemBarController();
+        mCarSystemBarController.init();
 
-        CarSystemBarView bottomBar = mCarSystemBar.getBottomBar(/* isSetUp= */ true);
+        CarSystemBarView bottomBar = mCarSystemBarController.getBarView(BOTTOM,
+                /* isSetUp= */ true);
         View driverHomeButton = bottomBar.findViewById(R.id.home);
         View passengerHomeButton = bottomBar.findViewById(R.id.passenger_home);
 
@@ -766,8 +838,8 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
     }
 
     private void clearSystemBarStates() {
-        if (mCarSystemBar != null) {
-            mCarSystemBar.setSystemBarStates(/* state= */ 0, /* state2= */ 0);
+        if (mCarSystemBarController != null) {
+            mCarSystemBarController.setSystemBarStates(/* state= */ 0, /* state2= */ 0);
         }
         setLockTaskModeLocked(false);
     }
@@ -776,7 +848,7 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
         when(mActivityManager.getLockTaskModeState()).thenReturn(locked
                 ? ActivityManager.LOCK_TASK_MODE_LOCKED
                 : ActivityManager.LOCK_TASK_MODE_NONE);
-        mCarSystemBar.setSystemBarStates(/* state= */ 0, /* state2= */ 0);
+        mCarSystemBarController.setSystemBarStates(/* state= */ 0, /* state2= */ 0);
     }
 
     private void setupPanelControllerBuilderMocks() {
@@ -800,10 +872,11 @@ public class CarSystemBarControllerTest extends SysuiTestCase {
 
     private CarSystemBarButton getNotificationCarSystemBarButton() {
         if (Flags.dockFeature()) {
-            CarSystemBarView topBar = mCarSystemBar.getTopBar(/* isSetUp= */ true);
+            CarSystemBarView topBar = mCarSystemBarController.getBarView(TOP, /* isSetUp= */ true);
             return topBar.findViewById(R.id.notifications);
         } else {
-            CarSystemBarView bottomBar = mCarSystemBar.getBottomBar(/* isSetUp= */ true);
+            CarSystemBarView bottomBar = mCarSystemBarController.getBarView(BOTTOM,
+                    /* isSetUp= */ true);
             return bottomBar.findViewById(R.id.notifications);
         }
     }
diff --git a/tests/src/com/android/systemui/car/systembar/CarSystemBarTest.java b/tests/src/com/android/systemui/car/systembar/CarSystemBarTest.java
index 276c6f89..29eaecfb 100644
--- a/tests/src/com/android/systemui/car/systembar/CarSystemBarTest.java
+++ b/tests/src/com/android/systemui/car/systembar/CarSystemBarTest.java
@@ -20,34 +20,33 @@ import static android.view.WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS;
 import static android.view.WindowInsetsController.APPEARANCE_OPAQUE_STATUS_BARS;
 import static android.view.WindowInsetsController.BEHAVIOR_DEFAULT;
 
-import static com.android.systemui.car.systembar.SystemBarConfigs.BOTTOM;
-import static com.android.systemui.car.systembar.SystemBarConfigs.LEFT;
-import static com.android.systemui.car.systembar.SystemBarConfigs.RIGHT;
-import static com.android.systemui.car.systembar.SystemBarConfigs.TOP;
+import static com.android.systemui.car.systembar.CarSystemBarController.BOTTOM;
+import static com.android.systemui.car.systembar.CarSystemBarController.LEFT;
+import static com.android.systemui.car.systembar.CarSystemBarController.RIGHT;
+import static com.android.systemui.car.systembar.CarSystemBarController.TOP;
 
 import static com.google.common.truth.Truth.assertThat;
 
-import static org.junit.Assume.assumeFalse;
 import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.anyBoolean;
 import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.never;
+import static org.mockito.Mockito.spy;
 import static org.mockito.Mockito.times;
 import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.when;
 
-import android.app.UiModeManager;
+import android.app.ActivityManager;
+import android.content.Context;
 import android.content.res.Configuration;
 import android.graphics.Rect;
 import android.os.RemoteException;
-import android.os.UserManager;
 import android.testing.AndroidTestingRunner;
 import android.testing.TestableLooper;
 import android.testing.TestableResources;
 import android.util.ArrayMap;
 import android.view.Display;
-import android.view.View;
 import android.view.ViewGroup;
 import android.view.WindowInsets;
 import android.view.WindowManager;
@@ -62,7 +61,11 @@ import com.android.systemui.SysuiTestCase;
 import com.android.systemui.car.CarDeviceProvisionedController;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.car.hvac.HvacController;
+import com.android.systemui.car.statusicon.StatusIconPanelViewController;
+import com.android.systemui.car.systembar.element.CarSystemBarElementInitializer;
+import com.android.systemui.plugins.DarkIconDispatcher;
 import com.android.systemui.settings.FakeDisplayTracker;
+import com.android.systemui.settings.UserTracker;
 import com.android.systemui.statusbar.CommandQueue;
 import com.android.systemui.statusbar.phone.AutoHideController;
 import com.android.systemui.statusbar.phone.LightBarController;
@@ -80,26 +83,41 @@ import org.junit.Before;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.mockito.ArgumentCaptor;
-import org.mockito.InOrder;
 import org.mockito.Mock;
 import org.mockito.MockitoAnnotations;
-import org.mockito.internal.InOrderImpl;
-
-import java.util.Arrays;
-import java.util.Optional;
 
+/**
+ * TODO(b/362280147): move related tests to CarSystemBarControllerTest.
+ */
 @CarSystemUiTest
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper
 @SmallTest
 public class CarSystemBarTest extends SysuiTestCase {
 
-    private CarSystemBar mCarSystemBar;
     private TestableResources mTestableResources;
+    private Context mSpiedContext;
     private FakeExecutor mExecutor;
+    private CarSystemBarControllerImpl mCarSystemBarController;
 
     @Mock
-    private CarSystemBarController mCarSystemBarController;
+    private UserTracker mUserTracker;
+    @Mock
+    private ActivityManager mActivityManager;
+    @Mock
+    private ButtonSelectionStateController mButtonSelectionStateController;
+    @Mock
+    private ButtonRoleHolderController mButtonRoleHolderController;
+    @Mock
+    private MicPrivacyChipViewController mMicPrivacyChipViewController;
+    @Mock
+    private CameraPrivacyChipViewController mCameraPrivacyChipViewController;
+    @Mock
+    private StatusIconPanelViewController.Builder mPanelControllerBuilder;
+    @Mock
+    private StatusIconPanelViewController mPanelController;
+    @Mock
+    private CarSystemBarElementInitializer mCarSystemBarElementInitializer;
     @Mock
     private LightBarController mLightBarController;
     @Mock
@@ -115,14 +133,10 @@ public class CarSystemBarTest extends SysuiTestCase {
     @Mock
     private ButtonSelectionStateListener mButtonSelectionStateListener;
     @Mock
-    private ButtonRoleHolderController mButtonRoleHolderController;
-    @Mock
     private IStatusBarService mBarService;
     @Mock
     private KeyguardStateController mKeyguardStateController;
     @Mock
-    private ButtonSelectionStateController mButtonSelectionStateController;
-    @Mock
     private PhoneStatusBarPolicy mIconPolicy;
     @Mock
     private StatusBarIconController mIconController;
@@ -130,6 +144,28 @@ public class CarSystemBarTest extends SysuiTestCase {
     private StatusBarSignalPolicy mSignalPolicy;
     @Mock
     private HvacController mHvacController;
+    @Mock
+    private ConfigurationController mConfigurationController;
+    @Mock
+    private CarSystemBarRestartTracker mCarSystemBarRestartTracker;
+    @Mock
+    private CarSystemBarViewFactory mCarSystemBarViewFactory;
+    @Mock
+    private CarSystemBarView mTopBar;
+    @Mock
+    private ViewGroup mTopWindow;
+    @Mock
+    private CarSystemBarView mRigthBar;
+    @Mock
+    private ViewGroup mRightWindow;
+    @Mock
+    private CarSystemBarView mLeftBar;
+    @Mock
+    private ViewGroup mLeftWindow;
+    @Mock
+    private CarSystemBarView mBottomBar;
+    @Mock
+    private ViewGroup mBottomWindow;
 
     private RegisterStatusBarResult mBarResult;
     private AppearanceRegion[] mAppearanceRegions;
@@ -142,8 +178,18 @@ public class CarSystemBarTest extends SysuiTestCase {
         mTestableResources = mContext.getOrCreateTestableResources();
         mExecutor = new FakeExecutor(new FakeSystemClock());
         mUiBgExecutor = new FakeExecutor(new FakeSystemClock());
+        mSpiedContext = spy(mContext);
+        when(mSpiedContext.getSystemService(ActivityManager.class)).thenReturn(mActivityManager);
         when(mStatusBarIconController.getTransitionsController()).thenReturn(
                 mLightBarTransitionsController);
+        when(mCarSystemBarViewFactory.getTopBar(anyBoolean())).thenReturn(mTopBar);
+        when(mCarSystemBarViewFactory.getTopWindow()).thenReturn(mTopWindow);
+        when(mCarSystemBarViewFactory.getRightBar(anyBoolean())).thenReturn(mRigthBar);
+        when(mCarSystemBarViewFactory.getRightWindow()).thenReturn(mRightWindow);
+        when(mCarSystemBarViewFactory.getBottomBar(anyBoolean())).thenReturn(mBottomBar);
+        when(mCarSystemBarViewFactory.getBottomWindow()).thenReturn(mBottomWindow);
+        when(mCarSystemBarViewFactory.getLeftBar(anyBoolean())).thenReturn(mLeftBar);
+        when(mCarSystemBarViewFactory.getLeftWindow()).thenReturn(mLeftWindow);
         mAppearanceRegions = new AppearanceRegion[]{
                 new AppearanceRegion(APPEARANCE_LIGHT_STATUS_BARS, new Rect())
         };
@@ -156,7 +202,6 @@ public class CarSystemBarTest extends SysuiTestCase {
                 /* imeBackDisposition= */ 0,
                 /* showImeSwitcher= */ false,
                 /* disabledFlags2= */ 0,
-                /* imeToken= */ null,
                 /* navbarColorMangedByIme= */ false,
                 BEHAVIOR_DEFAULT,
                 WindowInsets.Type.defaultVisible(),
@@ -168,25 +213,44 @@ public class CarSystemBarTest extends SysuiTestCase {
         } catch (RemoteException e) {
             e.printStackTrace();
         }
-        when(mCarSystemBarController.getTopWindow()).thenReturn(mock(ViewGroup.class));
-        when(mCarSystemBarController.getBottomWindow()).thenReturn(mock(ViewGroup.class));
-        when(mCarSystemBarController.getLeftWindow()).thenReturn(mock(ViewGroup.class));
-        when(mCarSystemBarController.getRightWindow()).thenReturn(mock(ViewGroup.class));
+
+        // Needed to inflate top navigation bar.
+        mDependency.injectMockDependency(DarkIconDispatcher.class);
+        mDependency.injectMockDependency(StatusBarIconController.class);
+
+        setupPanelControllerBuilderMocks();
+
         initCarSystemBar();
     }
 
     private void initCarSystemBar() {
+        SystemBarConfigs systemBarConfigs = new SystemBarConfigs(mTestableResources.getResources());
         FakeDisplayTracker displayTracker = new FakeDisplayTracker(mContext);
-        mSystemBarConfigs = new SystemBarConfigs(mTestableResources.getResources());
-        mCarSystemBar = new CarSystemBar(mContext, mCarSystemBarController, mLightBarController,
-                mStatusBarIconController, mWindowManager, mDeviceProvisionedController,
-                new CommandQueue(mContext, displayTracker), mAutoHideController,
-                mButtonSelectionStateListener, mExecutor, mUiBgExecutor, mBarService,
-                () -> mKeyguardStateController, () -> mIconPolicy, mHvacController, mSignalPolicy,
-                mSystemBarConfigs,
-                mock(ConfigurationController.class), mock(CarSystemBarRestartTracker.class),
-                displayTracker, Optional.empty(), null);
-        mCarSystemBar.setSignalPolicy(mSignalPolicy);
+        mCarSystemBarController = spy(new CarSystemBarControllerImpl(mSpiedContext,
+                mUserTracker,
+                mCarSystemBarViewFactory,
+                mButtonSelectionStateController,
+                () -> mMicPrivacyChipViewController,
+                () -> mCameraPrivacyChipViewController,
+                mButtonRoleHolderController,
+                systemBarConfigs,
+                () -> mPanelControllerBuilder,
+                mLightBarController,
+                mStatusBarIconController,
+                mWindowManager,
+                mDeviceProvisionedController,
+                new CommandQueue(mContext, displayTracker),
+                mAutoHideController,
+                mButtonSelectionStateListener,
+                mExecutor,
+                mBarService,
+                () -> mKeyguardStateController,
+                () -> mIconPolicy,
+                mHvacController,
+                mConfigurationController,
+                mCarSystemBarRestartTracker,
+                displayTracker,
+                null));
     }
 
     @Test
@@ -197,7 +261,7 @@ public class CarSystemBarTest extends SysuiTestCase {
                 deviceProvisionedCallbackCaptor = ArgumentCaptor.forClass(
                 CarDeviceProvisionedController.DeviceProvisionedListener.class);
         when(mDeviceProvisionedController.isCurrentUserSetup()).thenReturn(true);
-        mCarSystemBar.start();
+        mCarSystemBarController.init();
         // switching the currentUserSetup value to force restart the navbars.
         when(mDeviceProvisionedController.isCurrentUserSetup()).thenReturn(false);
         verify(mDeviceProvisionedController).addCallback(deviceProvisionedCallbackCaptor.capture());
@@ -216,7 +280,7 @@ public class CarSystemBarTest extends SysuiTestCase {
                 deviceProvisionedCallbackCaptor = ArgumentCaptor.forClass(
                 CarDeviceProvisionedController.DeviceProvisionedListener.class);
         when(mDeviceProvisionedController.isCurrentUserSetup()).thenReturn(true);
-        mCarSystemBar.start();
+        mCarSystemBarController.init();
         when(mKeyguardStateController.isShowing()).thenReturn(true);
         // switching the currentUserSetup value to force restart the navbars.
         when(mDeviceProvisionedController.isCurrentUserSetup()).thenReturn(false);
@@ -236,7 +300,7 @@ public class CarSystemBarTest extends SysuiTestCase {
                 deviceProvisionedCallbackCaptor = ArgumentCaptor.forClass(
                 CarDeviceProvisionedController.DeviceProvisionedListener.class);
         when(mDeviceProvisionedController.isCurrentUserSetup()).thenReturn(true);
-        mCarSystemBar.start();
+        mCarSystemBarController.init();
         when(mKeyguardStateController.isShowing()).thenReturn(true);
         // switching the currentUserSetup value to force restart the navbars.
         when(mDeviceProvisionedController.isCurrentUserSetup()).thenReturn(false);
@@ -256,7 +320,7 @@ public class CarSystemBarTest extends SysuiTestCase {
     public void restartNavBars_lightAppearance_darkensAllIcons() {
         mAppearanceRegions[0] = new AppearanceRegion(APPEARANCE_LIGHT_STATUS_BARS, new Rect());
 
-        mCarSystemBar.start();
+        mCarSystemBarController.init();
 
         verify(mLightBarTransitionsController).setIconsDark(
                 /* dark= */ true, /* animate= */ false);
@@ -266,7 +330,7 @@ public class CarSystemBarTest extends SysuiTestCase {
     public void restartNavBars_opaqueAppearance_lightensAllIcons() {
         mAppearanceRegions[0] = new AppearanceRegion(APPEARANCE_OPAQUE_STATUS_BARS, new Rect());
 
-        mCarSystemBar.start();
+        mCarSystemBarController.init();
 
         verify(mLightBarTransitionsController).setIconsDark(
                 /* dark= */ false, /* animate= */ false);
@@ -277,13 +341,13 @@ public class CarSystemBarTest extends SysuiTestCase {
         mTestableResources.addOverride(R.bool.config_enableTopSystemBar, true);
         mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
         when(mDeviceProvisionedController.isCurrentUserSetup()).thenReturn(true);
-        mCarSystemBar.start();
+        mCarSystemBarController.init();
 
         int randomDisplay = Display.DEFAULT_DISPLAY + 10;
         int insetTypes = 0;
-        mCarSystemBar.showTransient(randomDisplay, insetTypes, false);
+        mCarSystemBarController.showTransient(randomDisplay, insetTypes, false);
 
-        assertThat(mCarSystemBar.isStatusBarTransientShown()).isFalse();
+        assertThat(mCarSystemBarController.isStatusBarTransientShown()).isFalse();
     }
 
     @Test
@@ -291,12 +355,12 @@ public class CarSystemBarTest extends SysuiTestCase {
         mTestableResources.addOverride(R.bool.config_enableTopSystemBar, true);
         mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
         when(mDeviceProvisionedController.isCurrentUserSetup()).thenReturn(true);
-        mCarSystemBar.start();
+        mCarSystemBarController.init();
 
         int insetTypes = 0;
-        mCarSystemBar.showTransient(Display.DEFAULT_DISPLAY, insetTypes, false);
+        mCarSystemBarController.showTransient(Display.DEFAULT_DISPLAY, insetTypes, false);
 
-        assertThat(mCarSystemBar.isStatusBarTransientShown()).isFalse();
+        assertThat(mCarSystemBarController.isStatusBarTransientShown()).isFalse();
     }
 
     @Test
@@ -304,12 +368,12 @@ public class CarSystemBarTest extends SysuiTestCase {
         mTestableResources.addOverride(R.bool.config_enableTopSystemBar, true);
         mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
         when(mDeviceProvisionedController.isCurrentUserSetup()).thenReturn(true);
-        mCarSystemBar.start();
+        mCarSystemBarController.init();
 
         int insetTypes = WindowInsets.Type.statusBars();
-        mCarSystemBar.showTransient(Display.DEFAULT_DISPLAY, insetTypes, false);
+        mCarSystemBarController.showTransient(Display.DEFAULT_DISPLAY, insetTypes, false);
 
-        assertThat(mCarSystemBar.isStatusBarTransientShown()).isTrue();
+        assertThat(mCarSystemBarController.isStatusBarTransientShown()).isTrue();
     }
 
     @Test
@@ -317,12 +381,12 @@ public class CarSystemBarTest extends SysuiTestCase {
         mTestableResources.addOverride(R.bool.config_enableTopSystemBar, true);
         mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
         when(mDeviceProvisionedController.isCurrentUserSetup()).thenReturn(true);
-        mCarSystemBar.start();
+        mCarSystemBarController.init();
 
         int insetTypes = 0;
-        mCarSystemBar.showTransient(Display.DEFAULT_DISPLAY, insetTypes, false);
+        mCarSystemBarController.showTransient(Display.DEFAULT_DISPLAY, insetTypes, false);
 
-        assertThat(mCarSystemBar.isNavBarTransientShown()).isFalse();
+        assertThat(mCarSystemBarController.isNavBarTransientShown()).isFalse();
     }
 
     @Test
@@ -330,12 +394,12 @@ public class CarSystemBarTest extends SysuiTestCase {
         mTestableResources.addOverride(R.bool.config_enableTopSystemBar, true);
         mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
         when(mDeviceProvisionedController.isCurrentUserSetup()).thenReturn(true);
-        mCarSystemBar.start();
+        mCarSystemBarController.init();
 
         int insetTypes = WindowInsets.Type.navigationBars();
-        mCarSystemBar.showTransient(Display.DEFAULT_DISPLAY, insetTypes, false);
+        mCarSystemBarController.showTransient(Display.DEFAULT_DISPLAY, insetTypes, false);
 
-        assertThat(mCarSystemBar.isNavBarTransientShown()).isTrue();
+        assertThat(mCarSystemBarController.isNavBarTransientShown()).isTrue();
     }
 
     @Test
@@ -343,21 +407,21 @@ public class CarSystemBarTest extends SysuiTestCase {
         mTestableResources.addOverride(R.bool.config_enableTopSystemBar, true);
         mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
         when(mDeviceProvisionedController.isCurrentUserSetup()).thenReturn(true);
-        mCarSystemBar.start();
-        mCarSystemBar.showTransient(
+        mCarSystemBarController.init();
+        mCarSystemBarController.showTransient(
                 Display.DEFAULT_DISPLAY,
                 WindowInsets.Type.statusBars() | WindowInsets.Type.navigationBars(),
                 false);
-        assertThat(mCarSystemBar.isStatusBarTransientShown()).isTrue();
-        assertThat(mCarSystemBar.isNavBarTransientShown()).isTrue();
+        assertThat(mCarSystemBarController.isStatusBarTransientShown()).isTrue();
+        assertThat(mCarSystemBarController.isNavBarTransientShown()).isTrue();
 
         int insetTypes = 0;
         int randomDisplay = Display.DEFAULT_DISPLAY + 10;
-        mCarSystemBar.abortTransient(randomDisplay, insetTypes);
+        mCarSystemBarController.abortTransient(randomDisplay, insetTypes);
 
         // The transient booleans were not cleared.
-        assertThat(mCarSystemBar.isStatusBarTransientShown()).isTrue();
-        assertThat(mCarSystemBar.isNavBarTransientShown()).isTrue();
+        assertThat(mCarSystemBarController.isStatusBarTransientShown()).isTrue();
+        assertThat(mCarSystemBarController.isNavBarTransientShown()).isTrue();
     }
 
     @Test
@@ -365,20 +429,20 @@ public class CarSystemBarTest extends SysuiTestCase {
         mTestableResources.addOverride(R.bool.config_enableTopSystemBar, true);
         mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
         when(mDeviceProvisionedController.isCurrentUserSetup()).thenReturn(true);
-        mCarSystemBar.start();
-        mCarSystemBar.showTransient(
+        mCarSystemBarController.init();
+        mCarSystemBarController.showTransient(
                 Display.DEFAULT_DISPLAY,
                 WindowInsets.Type.statusBars() | WindowInsets.Type.navigationBars(),
                 false);
-        assertThat(mCarSystemBar.isStatusBarTransientShown()).isTrue();
-        assertThat(mCarSystemBar.isNavBarTransientShown()).isTrue();
+        assertThat(mCarSystemBarController.isStatusBarTransientShown()).isTrue();
+        assertThat(mCarSystemBarController.isNavBarTransientShown()).isTrue();
 
         int insetTypes = 0;
-        mCarSystemBar.abortTransient(Display.DEFAULT_DISPLAY, insetTypes);
+        mCarSystemBarController.abortTransient(Display.DEFAULT_DISPLAY, insetTypes);
 
         // The transient booleans were not cleared.
-        assertThat(mCarSystemBar.isStatusBarTransientShown()).isTrue();
-        assertThat(mCarSystemBar.isNavBarTransientShown()).isTrue();
+        assertThat(mCarSystemBarController.isStatusBarTransientShown()).isTrue();
+        assertThat(mCarSystemBarController.isNavBarTransientShown()).isTrue();
     }
 
     @Test
@@ -386,20 +450,20 @@ public class CarSystemBarTest extends SysuiTestCase {
         mTestableResources.addOverride(R.bool.config_enableTopSystemBar, true);
         mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
         when(mDeviceProvisionedController.isCurrentUserSetup()).thenReturn(true);
-        mCarSystemBar.start();
-        mCarSystemBar.showTransient(
+        mCarSystemBarController.init();
+        mCarSystemBarController.showTransient(
                 Display.DEFAULT_DISPLAY,
                 WindowInsets.Type.statusBars() | WindowInsets.Type.navigationBars(),
                 false);
-        assertThat(mCarSystemBar.isStatusBarTransientShown()).isTrue();
-        assertThat(mCarSystemBar.isNavBarTransientShown()).isTrue();
+        assertThat(mCarSystemBarController.isStatusBarTransientShown()).isTrue();
+        assertThat(mCarSystemBarController.isNavBarTransientShown()).isTrue();
 
         int insetTypes = WindowInsets.Type.statusBars();
-        mCarSystemBar.abortTransient(Display.DEFAULT_DISPLAY, insetTypes);
+        mCarSystemBarController.abortTransient(Display.DEFAULT_DISPLAY, insetTypes);
 
         // The transient booleans were cleared.
-        assertThat(mCarSystemBar.isStatusBarTransientShown()).isFalse();
-        assertThat(mCarSystemBar.isNavBarTransientShown()).isFalse();
+        assertThat(mCarSystemBarController.isStatusBarTransientShown()).isFalse();
+        assertThat(mCarSystemBarController.isNavBarTransientShown()).isFalse();
     }
 
     @Test
@@ -407,34 +471,34 @@ public class CarSystemBarTest extends SysuiTestCase {
         mTestableResources.addOverride(R.bool.config_enableTopSystemBar, true);
         mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
         when(mDeviceProvisionedController.isCurrentUserSetup()).thenReturn(true);
-        mCarSystemBar.start();
-        mCarSystemBar.showTransient(
+        mCarSystemBarController.init();
+        mCarSystemBarController.showTransient(
                 Display.DEFAULT_DISPLAY,
                 WindowInsets.Type.statusBars() | WindowInsets.Type.navigationBars(),
                 false);
-        assertThat(mCarSystemBar.isStatusBarTransientShown()).isTrue();
-        assertThat(mCarSystemBar.isNavBarTransientShown()).isTrue();
+        assertThat(mCarSystemBarController.isStatusBarTransientShown()).isTrue();
+        assertThat(mCarSystemBarController.isNavBarTransientShown()).isTrue();
 
         int insetTypes = WindowInsets.Type.navigationBars();
-        mCarSystemBar.abortTransient(Display.DEFAULT_DISPLAY, insetTypes);
+        mCarSystemBarController.abortTransient(Display.DEFAULT_DISPLAY, insetTypes);
 
         // The transient booleans were cleared.
-        assertThat(mCarSystemBar.isStatusBarTransientShown()).isFalse();
-        assertThat(mCarSystemBar.isNavBarTransientShown()).isFalse();
+        assertThat(mCarSystemBarController.isStatusBarTransientShown()).isFalse();
+        assertThat(mCarSystemBarController.isNavBarTransientShown()).isFalse();
     }
 
     @Test
     public void disable_wrongDisplayId_notSetStatusBarState() {
         int randomDisplay = Display.DEFAULT_DISPLAY + 10;
 
-        mCarSystemBar.disable(randomDisplay, 0, 0, false);
+        mCarSystemBarController.disable(randomDisplay, 0, 0, false);
 
         verify(mCarSystemBarController, never()).setSystemBarStates(anyInt(), anyInt());
     }
 
     @Test
     public void disable_correctDisplayId_setSystemBarStates() {
-        mCarSystemBar.disable(Display.DEFAULT_DISPLAY, 0, 0, false);
+        mCarSystemBarController.disable(Display.DEFAULT_DISPLAY, 0, 0, false);
 
         verify(mCarSystemBarController).setSystemBarStates(0, 0);
     }
@@ -446,36 +510,11 @@ public class CarSystemBarTest extends SysuiTestCase {
         Configuration config = new Configuration();
         config.uiMode =
                 isNightMode ? Configuration.UI_MODE_NIGHT_NO : Configuration.UI_MODE_NIGHT_YES;
-        UiModeManager mockUiModeManager = mock(UiModeManager.class);
-        mCarSystemBar.setUiModeManager(mockUiModeManager);
-
-        mCarSystemBar.onConfigChanged(config);
-
-        verify(mockUiModeManager).setNightModeActivated(!isNightMode);
-    }
-
-    @Test
-    public void onConfigChanged_callOnClick_profilePickerViewIsSelected() {
-        // alternative profile picker used on multi-display systems
-        assumeFalse(UserManager.isVisibleBackgroundUsersEnabled());
-        Configuration config = new Configuration();
-        config.uiMode = mContext.getResources().getConfiguration().isNightModeActive()
-                ? Configuration.UI_MODE_NIGHT_NO : Configuration.UI_MODE_NIGHT_YES;
-        View mockProfilePickerView = mock(View.class);
-        when(mockProfilePickerView.isSelected()).thenReturn(true);
-        CarSystemBarView mockTopBarView = mock(CarSystemBarView.class);
-        when(mockTopBarView.findViewById(R.id.user_name)).thenReturn(mockProfilePickerView);
-        when(mCarSystemBarController.getTopBar(anyBoolean())).thenReturn(mockTopBarView);
-        initCarSystemBar();
 
-        mCarSystemBar.start();
-        mCarSystemBar.onConfigChanged(config);
+        mCarSystemBarController.init();
+        mCarSystemBarController.onConfigChanged(config);
 
-        InOrder inOrder = new InOrderImpl(Arrays.asList(mockProfilePickerView, mockTopBarView));
-        inOrder.verify(mockTopBarView).findViewById(R.id.user_name);
-        inOrder.verify(mockProfilePickerView).callOnClick();
-        inOrder.verify(mockTopBarView).findViewById(R.id.user_name);
-        inOrder.verify(mockProfilePickerView).callOnClick();
+        assertThat(mCarSystemBarController.getIsUiModeNight()).isNotEqualTo(isNightMode);
     }
 
     @Test
@@ -485,39 +524,50 @@ public class CarSystemBarTest extends SysuiTestCase {
         mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, true);
         mTestableResources.addOverride(R.bool.config_enableLeftSystemBar, false);
         mTestableResources.addOverride(R.bool.config_enableRightSystemBar, false);
-        when(mCarSystemBarController.getTopWindow()).thenReturn(mock(ViewGroup.class));
-        when(mCarSystemBarController.getBottomWindow()).thenReturn(mock(ViewGroup.class));
-        when(mCarSystemBarController.getLeftWindow()).thenReturn(null);
-        when(mCarSystemBarController.getRightWindow()).thenReturn(null);
+        when(mCarSystemBarController.getBarWindow(TOP)).thenReturn(mock(ViewGroup.class));
+        when(mCarSystemBarController.getBarWindow(BOTTOM)).thenReturn(mock(ViewGroup.class));
+        when(mCarSystemBarController.getBarWindow(LEFT)).thenReturn(null);
+        when(mCarSystemBarController.getBarWindow(RIGHT)).thenReturn(null);
 
         initCarSystemBar();
-        mCarSystemBar.start();
-        assertThat(mCarSystemBar.getSystemBarWindowBySide(TOP)).isNotNull();
-        assertThat(mCarSystemBar.getSystemBarWindowBySide(BOTTOM)).isNotNull();
-        assertThat(mCarSystemBar.getSystemBarWindowBySide(LEFT)).isNull();
-        assertThat(mCarSystemBar.getSystemBarWindowBySide(RIGHT)).isNull();
+        mCarSystemBarController.init();
+        assertThat(mCarSystemBarController.getBarWindow(TOP)).isNotNull();
+        assertThat(mCarSystemBarController.getBarWindow(BOTTOM)).isNotNull();
+        assertThat(mCarSystemBarController.getBarWindow(LEFT)).isNull();
+        assertThat(mCarSystemBarController.getBarWindow(RIGHT)).isNull();
 
         mTestableResources.addOverride(R.bool.config_enableTopSystemBar, true);
         mTestableResources.addOverride(R.bool.config_enableBottomSystemBar, false);
         mTestableResources.addOverride(R.bool.config_enableLeftSystemBar, true);
         mTestableResources.addOverride(R.bool.config_enableRightSystemBar, true);
         mSystemBarConfigs = new SystemBarConfigs(mTestableResources.getResources());
-        when(mCarSystemBarController.getTopWindow()).thenReturn(mock(ViewGroup.class));
-        when(mCarSystemBarController.getBottomWindow()).thenReturn(null);
-        when(mCarSystemBarController.getLeftWindow()).thenReturn(mock(ViewGroup.class));
-        when(mCarSystemBarController.getRightWindow()).thenReturn(mock(ViewGroup.class));
-        mCarSystemBar.restartSystemBars();
+        when(mCarSystemBarController.getBarWindow(TOP)).thenReturn(mock(ViewGroup.class));
+        when(mCarSystemBarController.getBarWindow(BOTTOM)).thenReturn(null);
+        when(mCarSystemBarController.getBarWindow(LEFT)).thenReturn(mock(ViewGroup.class));
+        when(mCarSystemBarController.getBarWindow(RIGHT)).thenReturn(mock(ViewGroup.class));
+        mCarSystemBarController.restartSystemBars();
 
         verify(mCarSystemBarController, times(1)).removeAll();
-        verify(mCarSystemBarController, times(1)).resetSystemBarConfigs();
-        assertThat(mCarSystemBar.getSystemBarWindowBySide(TOP)).isNotNull();
-        assertThat(mCarSystemBar.getSystemBarWindowBySide(BOTTOM)).isNull();
-        assertThat(mCarSystemBar.getSystemBarWindowBySide(LEFT)).isNotNull();
-        assertThat(mCarSystemBar.getSystemBarWindowBySide(RIGHT)).isNotNull();
+        verify(mCarSystemBarController, times(2)).resetSystemBarConfigs();
+        assertThat(mCarSystemBarController.getBarWindow(TOP)).isNotNull();
+        assertThat(mCarSystemBarController.getBarWindow(BOTTOM)).isNull();
+        assertThat(mCarSystemBarController.getBarWindow(LEFT)).isNotNull();
+        assertThat(mCarSystemBarController.getBarWindow(RIGHT)).isNotNull();
     }
 
     private void waitForDelayableExecutor() {
         mExecutor.advanceClockToLast();
         mExecutor.runAllReady();
     }
+
+    private void setupPanelControllerBuilderMocks() {
+        when(mPanelControllerBuilder.setXOffset(anyInt())).thenReturn(mPanelControllerBuilder);
+        when(mPanelControllerBuilder.setYOffset(anyInt())).thenReturn(mPanelControllerBuilder);
+        when(mPanelControllerBuilder.setGravity(anyInt())).thenReturn(mPanelControllerBuilder);
+        when(mPanelControllerBuilder.setDisabledWhileDriving(anyBoolean())).thenReturn(
+                mPanelControllerBuilder);
+        when(mPanelControllerBuilder.setShowAsDropDown(anyBoolean())).thenReturn(
+                mPanelControllerBuilder);
+        when(mPanelControllerBuilder.build(any(), anyInt(), anyInt())).thenReturn(mPanelController);
+    }
 }
diff --git a/tests/src/com/android/systemui/car/systembar/CarSystemBarViewTest.java b/tests/src/com/android/systemui/car/systembar/CarSystemBarViewTest.java
index ab72c842..e4258422 100644
--- a/tests/src/com/android/systemui/car/systembar/CarSystemBarViewTest.java
+++ b/tests/src/com/android/systemui/car/systembar/CarSystemBarViewTest.java
@@ -31,6 +31,7 @@ import androidx.test.filters.SmallTest;
 import com.android.systemui.R;
 import com.android.systemui.SysuiTestCase;
 import com.android.systemui.car.CarSystemUiTest;
+import com.android.systemui.car.notification.NotificationsShadeController;
 
 import org.junit.After;
 import org.junit.Before;
@@ -50,7 +51,7 @@ public class CarSystemBarViewTest extends SysuiTestCase {
     private CarSystemBarView mNavBarView;
 
     @Mock
-    private CarSystemBarController.NotificationsShadeController mNotificationsShadeController;
+    private NotificationsShadeController mNotificationsShadeController;
 
     @Mock
     private View.OnTouchListener mNavBarTouchListener;
diff --git a/tests/src/com/android/systemui/car/systembar/MicPrivacyChipViewControllerTest.java b/tests/src/com/android/systemui/car/systembar/MicPrivacyChipViewControllerTest.java
index c5119c14..48a1ddb9 100644
--- a/tests/src/com/android/systemui/car/systembar/MicPrivacyChipViewControllerTest.java
+++ b/tests/src/com/android/systemui/car/systembar/MicPrivacyChipViewControllerTest.java
@@ -66,6 +66,7 @@ import java.util.concurrent.Executor;
 @TestableLooper.RunWithLooper
 @SmallTest
 public class MicPrivacyChipViewControllerTest extends SysuiTestCase {
+    private static final int TEST_USER_ID = 1001;
 
     private MicPrivacyChipViewController mMicPrivacyChipViewController;
     private FrameLayout mFrameLayout;
@@ -106,6 +107,7 @@ public class MicPrivacyChipViewControllerTest extends SysuiTestCase {
 
         when(mContext.getMainExecutor()).thenReturn(mExecutor);
         when(mCar.isConnected()).thenReturn(true);
+        when(mUserTracker.getUserId()).thenReturn(TEST_USER_ID);
 
         mMicPrivacyChipViewController = new MicPrivacyChipViewController(mContext,
                 mPrivacyItemController, mSensorPrivacyManager, mUserTracker);
@@ -311,7 +313,8 @@ public class MicPrivacyChipViewControllerTest extends SysuiTestCase {
 
         mMicPrivacyChipViewController.toggleSensor();
 
-        verify(mSensorPrivacyManager).setSensorPrivacy(eq(QS_TILE), eq(MICROPHONE), eq(true));
+        verify(mSensorPrivacyManager).setSensorPrivacy(eq(QS_TILE), eq(MICROPHONE), eq(true),
+                eq(TEST_USER_ID));
     }
 
     @Test
@@ -321,6 +324,7 @@ public class MicPrivacyChipViewControllerTest extends SysuiTestCase {
 
         mMicPrivacyChipViewController.toggleSensor();
 
-        verify(mSensorPrivacyManager).setSensorPrivacy(eq(QS_TILE), eq(MICROPHONE), eq(false));
+        verify(mSensorPrivacyManager).setSensorPrivacy(eq(QS_TILE), eq(MICROPHONE), eq(false),
+                eq(TEST_USER_ID));
     }
 }
diff --git a/tests/src/com/android/systemui/car/systembar/SystemBarConfigsTest.java b/tests/src/com/android/systemui/car/systembar/SystemBarConfigsTest.java
index f9bb7a57..9f5220a0 100644
--- a/tests/src/com/android/systemui/car/systembar/SystemBarConfigsTest.java
+++ b/tests/src/com/android/systemui/car/systembar/SystemBarConfigsTest.java
@@ -18,6 +18,11 @@ package com.android.systemui.car.systembar;
 
 import static android.view.WindowManager.LayoutParams.LAYOUT_IN_DISPLAY_CUTOUT_MODE_ALWAYS;
 
+import static com.android.systemui.car.systembar.CarSystemBarController.BOTTOM;
+import static com.android.systemui.car.systembar.CarSystemBarController.LEFT;
+import static com.android.systemui.car.systembar.CarSystemBarController.RIGHT;
+import static com.android.systemui.car.systembar.CarSystemBarController.TOP;
+
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertNotNull;
@@ -25,7 +30,6 @@ import static org.junit.Assert.assertNull;
 import static org.junit.Assert.assertTrue;
 import static org.mockito.Mockito.when;
 
-import android.app.UiModeManager;
 import android.content.Context;
 import android.content.res.Resources;
 import android.testing.AndroidTestingRunner;
@@ -88,14 +92,14 @@ public class SystemBarConfigsTest extends SysuiTestCase {
     }
 
     @Test
-    public void onInit_allSystemBarsEnabled_systemBarSidesSortedByZOrder() {
+    public void onInit_allSystemBarsEnabled_systemBarTypesSortedByZOrder() {
         mSystemBarConfigs = new SystemBarConfigs(mResources);
         List<Integer> actualOrder = mSystemBarConfigs.getSystemBarSidesByZOrder();
         List<Integer> expectedOrder = new ArrayList<>();
-        expectedOrder.add(SystemBarConfigs.LEFT);
-        expectedOrder.add(SystemBarConfigs.RIGHT);
-        expectedOrder.add(SystemBarConfigs.TOP);
-        expectedOrder.add(SystemBarConfigs.BOTTOM);
+        expectedOrder.add(LEFT);
+        expectedOrder.add(RIGHT);
+        expectedOrder.add(TOP);
+        expectedOrder.add(BOTTOM);
 
         assertTrue(actualOrder.equals(expectedOrder));
     }
@@ -149,7 +153,7 @@ public class SystemBarConfigsTest extends SysuiTestCase {
     public void getTopSystemBarLayoutParams_topBarEnabled_returnsTopSystemBarLayoutParams() {
         mSystemBarConfigs = new SystemBarConfigs(mResources);
         WindowManager.LayoutParams lp = mSystemBarConfigs.getLayoutParamsBySide(
-                SystemBarConfigs.TOP);
+                TOP);
 
         assertNotNull(lp);
     }
@@ -158,7 +162,7 @@ public class SystemBarConfigsTest extends SysuiTestCase {
     public void getTopSystemBarLayoutParams_containsLayoutInDisplayCutoutMode() {
         mSystemBarConfigs = new SystemBarConfigs(mResources);
         WindowManager.LayoutParams lp = mSystemBarConfigs.getLayoutParamsBySide(
-                SystemBarConfigs.TOP);
+                TOP);
 
         assertNotNull(lp);
         assertEquals(lp.layoutInDisplayCutoutMode, LAYOUT_IN_DISPLAY_CUTOUT_MODE_ALWAYS);
@@ -169,7 +173,7 @@ public class SystemBarConfigsTest extends SysuiTestCase {
         when(mResources.getBoolean(R.bool.config_enableTopSystemBar)).thenReturn(false);
         mSystemBarConfigs = new SystemBarConfigs(mResources);
         WindowManager.LayoutParams lp = mSystemBarConfigs.getLayoutParamsBySide(
-                SystemBarConfigs.TOP);
+                TOP);
 
         assertNull(lp);
     }
@@ -179,7 +183,7 @@ public class SystemBarConfigsTest extends SysuiTestCase {
         when(mResources.getBoolean(R.bool.config_hideTopSystemBarForKeyboard)).thenReturn(true);
         mSystemBarConfigs = new SystemBarConfigs(mResources);
 
-        boolean hideKeyboard = mSystemBarConfigs.getHideForKeyboardBySide(SystemBarConfigs.TOP);
+        boolean hideKeyboard = mSystemBarConfigs.getHideForKeyboardBySide(TOP);
 
         assertTrue(hideKeyboard);
     }
@@ -189,7 +193,7 @@ public class SystemBarConfigsTest extends SysuiTestCase {
         when(mResources.getBoolean(R.bool.config_enableTopSystemBar)).thenReturn(false);
         mSystemBarConfigs = new SystemBarConfigs(mResources);
 
-        boolean hideKeyboard = mSystemBarConfigs.getHideForKeyboardBySide(SystemBarConfigs.TOP);
+        boolean hideKeyboard = mSystemBarConfigs.getHideForKeyboardBySide(TOP);
 
         assertFalse(hideKeyboard);
     }
@@ -200,7 +204,7 @@ public class SystemBarConfigsTest extends SysuiTestCase {
                 SystemBarConfigs.getHunZOrder() + 1);
         mSystemBarConfigs = new SystemBarConfigs(mResources);
         WindowManager.LayoutParams lp = mSystemBarConfigs.getLayoutParamsBySide(
-                SystemBarConfigs.TOP);
+                TOP);
 
         assertEquals(lp.type, WindowManager.LayoutParams.TYPE_NAVIGATION_BAR_PANEL);
     }
@@ -211,7 +215,7 @@ public class SystemBarConfigsTest extends SysuiTestCase {
                 SystemBarConfigs.getHunZOrder() - 1);
         mSystemBarConfigs = new SystemBarConfigs(mResources);
         WindowManager.LayoutParams lp = mSystemBarConfigs.getLayoutParamsBySide(
-                SystemBarConfigs.TOP);
+                TOP);
 
         assertEquals(lp.type, WindowManager.LayoutParams.TYPE_STATUS_BAR_ADDITIONAL);
     }
@@ -221,13 +225,13 @@ public class SystemBarConfigsTest extends SysuiTestCase {
         mSystemBarConfigs = new SystemBarConfigs(mResources);
         CarSystemBarView leftBar = new CarSystemBarView(mContext, /* attrs= */ null);
         Map<Integer, Boolean> visibilities = new ArrayMap<>();
-        visibilities.put(SystemBarConfigs.TOP, false);
-        visibilities.put(SystemBarConfigs.BOTTOM, true);
-        visibilities.put(SystemBarConfigs.LEFT, true);
-        visibilities.put(SystemBarConfigs.RIGHT, true);
+        visibilities.put(TOP, false);
+        visibilities.put(BOTTOM, true);
+        visibilities.put(LEFT, true);
+        visibilities.put(RIGHT, true);
 
-        mSystemBarConfigs.updateInsetPaddings(SystemBarConfigs.LEFT, visibilities);
-        mSystemBarConfigs.insetSystemBar(SystemBarConfigs.LEFT, leftBar);
+        mSystemBarConfigs.updateInsetPaddings(LEFT, visibilities);
+        mSystemBarConfigs.insetSystemBar(LEFT, leftBar);
 
         assertEquals(0, leftBar.getPaddingTop());
     }
@@ -237,16 +241,16 @@ public class SystemBarConfigsTest extends SysuiTestCase {
         mSystemBarConfigs = new SystemBarConfigs(mResources);
         CarSystemBarView leftBar = new CarSystemBarView(mContext, /* attrs= */ null);
         Map<Integer, Boolean> visibilities = new ArrayMap<>();
-        visibilities.put(SystemBarConfigs.TOP, false);
-        visibilities.put(SystemBarConfigs.BOTTOM, true);
-        visibilities.put(SystemBarConfigs.LEFT, true);
-        visibilities.put(SystemBarConfigs.RIGHT, true);
+        visibilities.put(TOP, false);
+        visibilities.put(BOTTOM, true);
+        visibilities.put(LEFT, true);
+        visibilities.put(RIGHT, true);
 
-        mSystemBarConfigs.updateInsetPaddings(SystemBarConfigs.LEFT, visibilities);
-        mSystemBarConfigs.insetSystemBar(SystemBarConfigs.LEFT, leftBar);
-        visibilities.put(SystemBarConfigs.TOP, true);
-        mSystemBarConfigs.updateInsetPaddings(SystemBarConfigs.LEFT, visibilities);
-        mSystemBarConfigs.insetSystemBar(SystemBarConfigs.LEFT, leftBar);
+        mSystemBarConfigs.updateInsetPaddings(LEFT, visibilities);
+        mSystemBarConfigs.insetSystemBar(LEFT, leftBar);
+        visibilities.put(TOP, true);
+        mSystemBarConfigs.updateInsetPaddings(LEFT, visibilities);
+        mSystemBarConfigs.insetSystemBar(LEFT, leftBar);
 
         assertEquals(SYSTEM_BAR_GIRTH, leftBar.getPaddingTop());
     }
@@ -305,19 +309,19 @@ public class SystemBarConfigsTest extends SysuiTestCase {
         CarSystemBarView rightBar = new CarSystemBarView(mContext, /* attrs= */ null);
 
         Map<Integer, Boolean> visibilities = new ArrayMap<>();
-        visibilities.put(SystemBarConfigs.TOP, true);
-        visibilities.put(SystemBarConfigs.BOTTOM, true);
-        visibilities.put(SystemBarConfigs.LEFT, true);
-        visibilities.put(SystemBarConfigs.RIGHT, true);
-
-        mSystemBarConfigs.updateInsetPaddings(SystemBarConfigs.TOP, visibilities);
-        mSystemBarConfigs.insetSystemBar(SystemBarConfigs.TOP, topBar);
-        mSystemBarConfigs.updateInsetPaddings(SystemBarConfigs.BOTTOM, visibilities);
-        mSystemBarConfigs.insetSystemBar(SystemBarConfigs.BOTTOM, bottomBar);
-        mSystemBarConfigs.updateInsetPaddings(SystemBarConfigs.LEFT, visibilities);
-        mSystemBarConfigs.insetSystemBar(SystemBarConfigs.LEFT, leftBar);
-        mSystemBarConfigs.updateInsetPaddings(SystemBarConfigs.RIGHT, visibilities);
-        mSystemBarConfigs.insetSystemBar(SystemBarConfigs.RIGHT, rightBar);
+        visibilities.put(TOP, true);
+        visibilities.put(BOTTOM, true);
+        visibilities.put(LEFT, true);
+        visibilities.put(RIGHT, true);
+
+        mSystemBarConfigs.updateInsetPaddings(TOP, visibilities);
+        mSystemBarConfigs.insetSystemBar(TOP, topBar);
+        mSystemBarConfigs.updateInsetPaddings(BOTTOM, visibilities);
+        mSystemBarConfigs.insetSystemBar(BOTTOM, bottomBar);
+        mSystemBarConfigs.updateInsetPaddings(LEFT, visibilities);
+        mSystemBarConfigs.insetSystemBar(LEFT, leftBar);
+        mSystemBarConfigs.updateInsetPaddings(RIGHT, visibilities);
+        mSystemBarConfigs.insetSystemBar(RIGHT, rightBar);
 
         assertEquals(horizontalBarHorizontalPadding, bottomBar.getPaddingLeft());
         assertEquals(horizontalBarHorizontalPadding, bottomBar.getPaddingRight());
@@ -377,11 +381,10 @@ public class SystemBarConfigsTest extends SysuiTestCase {
                 BroadcastDispatcher broadcastDispatcher,
                 UserTracker userTracker,
                 CarDeviceProvisionedController carDeviceProvisionedController,
-                ConfigurationController configurationController,
-                UiModeManager uiModeManager) {
+                ConfigurationController configurationController) {
             super(context, carSystemBarController, notificationPanelViewController,
                     powerManagerHelper, broadcastDispatcher, userTracker,
-                    carDeviceProvisionedController, configurationController, uiModeManager);
+                    carDeviceProvisionedController, configurationController);
         }
     }
 }
diff --git a/tests/src/com/android/systemui/car/userpicker/UserPickerBottomBarTest.java b/tests/src/com/android/systemui/car/userpicker/UserPickerBottomBarTest.java
index d0e199e6..c9619d88 100644
--- a/tests/src/com/android/systemui/car/userpicker/UserPickerBottomBarTest.java
+++ b/tests/src/com/android/systemui/car/userpicker/UserPickerBottomBarTest.java
@@ -17,9 +17,11 @@ package com.android.systemui.car.userpicker;
 
 import static com.google.common.truth.Truth.assertThat;
 
+import android.graphics.Insets;
 import android.testing.AndroidTestingRunner;
 import android.testing.TestableLooper;
 import android.view.View;
+import android.view.WindowInsets;
 
 import androidx.constraintlayout.widget.ConstraintLayout;
 import androidx.test.ext.junit.rules.ActivityScenarioRule;
@@ -59,8 +61,6 @@ public class UserPickerBottomBarTest extends UserPickerTestCase {
 
             assertThat(height).isEqualTo(target_height);
         });
-
-
     }
 
     @Test
@@ -71,4 +71,14 @@ public class UserPickerBottomBarTest extends UserPickerTestCase {
             assertThat(clock.getVisibility()).isEqualTo(View.VISIBLE);
         });
     }
+
+    @Test
+    public void checkNavBarInsets_isZero() {
+        mActivityRule.getScenario().onActivity(activity -> {
+            Insets insets = activity.getWindow().getDecorView().getRootWindowInsets().getInsets(
+                    WindowInsets.Type.navigationBars());
+            int height = insets.bottom - insets.top;
+            assertThat(height).isEqualTo(0);
+        });
+    }
 }
diff --git a/tests/src/com/android/systemui/car/userpicker/UserPickerPassengerHeaderTest.java b/tests/src/com/android/systemui/car/userpicker/UserPickerPassengerHeaderTest.java
index 3b5f2a43..4de7f545 100644
--- a/tests/src/com/android/systemui/car/userpicker/UserPickerPassengerHeaderTest.java
+++ b/tests/src/com/android/systemui/car/userpicker/UserPickerPassengerHeaderTest.java
@@ -146,6 +146,8 @@ public class UserPickerPassengerHeaderTest extends UserPickerTestCase {
         mHeaderstate.setState(HEADER_STATE_CHANGE_USER);
         mActivityRule.getScenario().onActivity(activity -> {
             activity.setupHeaderBar(mHeaderstate);
+            // clear any previous caches
+            clearInvocations(activity.mAdapter);
             // initial settings
             Configuration origConfiguration = activity.getResources().getConfiguration();
             Configuration newConfiguration = origConfiguration;
diff --git a/tests/src/com/android/systemui/car/userpicker/UserPickerRecyclerViewTest.java b/tests/src/com/android/systemui/car/userpicker/UserPickerRecyclerViewTest.java
index 8a2f70e7..50e9f9d0 100644
--- a/tests/src/com/android/systemui/car/userpicker/UserPickerRecyclerViewTest.java
+++ b/tests/src/com/android/systemui/car/userpicker/UserPickerRecyclerViewTest.java
@@ -36,6 +36,8 @@ import androidx.test.filters.SmallTest;
 import com.android.systemui.R;
 import com.android.systemui.car.CarSystemUiTest;
 import com.android.systemui.car.userswitcher.UserIconProvider;
+import com.android.systemui.settings.UserTracker;
+import com.android.systemui.tuner.TunerService;
 
 import org.junit.Before;
 import org.junit.Ignore;
@@ -78,6 +80,9 @@ public class UserPickerRecyclerViewTest extends UserPickerTestCase {
     public void setUp() {
         MockitoAnnotations.initMocks(this);
 
+        mDependency.injectMockDependency(TunerService.class);
+        mDependency.injectMockDependency(UserTracker.class);
+
         doReturn(mDriverUserInfo).when(mMockUserManager).getUserInfo(USER_ID_DRIVER);
         doReturn(mFrontUserInfo).when(mMockUserManager).getUserInfo(USER_ID_FRONT);
         doReturn(mRearUserInfo).when(mMockUserManager).getUserInfo(USER_ID_REAR);
@@ -88,22 +93,22 @@ public class UserPickerRecyclerViewTest extends UserPickerTestCase {
                 /* mIsStartGuestSession= */ false, /* mIsAddUser= */ false,
                 /* mIsForeground= */ true,
                 /* mIcon= */ mMockUserIconProvider.getRoundedUserIcon(mDriverUserInfo, mContext),
-                /* OnClickListenerMaker */ new OnClickListenerCreator(), /* mIsLoggedIn= */ true,
-                /* mLoggedInDisplay= */ MAIN_DISPLAY_ID,
+                /* OnClickListenerMaker */ new OnClickListenerCreator(), /* mIsSecure= */ false,
+                /* mIsLoggedIn= */ true, /* mLoggedInDisplay= */ MAIN_DISPLAY_ID,
                 /* mSeatLocationName= */ USER_NAME_DRIVER, /* mIsStopping= */ false);
         mFront = UserRecord.create(mFrontUserInfo, /* mName= */ mFrontUserInfo.name,
                 /* mIsStartGuestSession= */ false, /* mIsAddUser= */ false,
                 /* mIsForeground= */ false,
                 /* mIcon= */ mMockUserIconProvider.getRoundedUserIcon(mFrontUserInfo, mContext),
-                /* OnClickListenerMaker */ new OnClickListenerCreator(), /* mIsLoggedIn= */ true,
-                /* mLoggedInDisplay= */ FRONT_PASSENGER_DISPLAY_ID,
+                /* OnClickListenerMaker */ new OnClickListenerCreator(), /* mIsSecure= */ false,
+                /* mIsLoggedIn= */ true, /* mLoggedInDisplay= */ FRONT_PASSENGER_DISPLAY_ID,
                 /* mSeatLocationName= */ USER_NAME_FRONT, /* mIsStopping= */ false);
         mRear = UserRecord.create(mRearUserInfo, /* mName= */ mRearUserInfo.name,
                 /* mIsStartGuestSession= */ false, /* mIsAddUser= */ false,
                 /* mIsForeground= */ false,
                 /* mIcon= */ mMockUserIconProvider.getRoundedUserIcon(mRearUserInfo, mContext),
-                /* OnClickListenerMaker */ new OnClickListenerCreator(), /* mIsLoggedIn= */ false,
-                /* mLoggedInDisplay= */ INVALID_DISPLAY,
+                /* OnClickListenerMaker */ new OnClickListenerCreator(), /* mIsSecure= */ false,
+                /* mIsLoggedIn= */ false, /* mLoggedInDisplay= */ INVALID_DISPLAY,
                 /* mSeatLocationName= */ "", /* mIsStopping= */ false);
     }
 
@@ -152,8 +157,8 @@ public class UserPickerRecyclerViewTest extends UserPickerTestCase {
                 /* mIsStartGuestSession= */ true, /* mIsAddUser= */ false,
                 /* mIsForeground= */ false,
                 mMockUserIconProvider.getRoundedGuestDefaultIcon(mContext),
-                /* OnClickListenerMaker */ new OnClickListenerCreator(), false, INVALID_DISPLAY,
-                /* mSeatLocationName= */"", /* mIsStopping= */ false);
+                /* OnClickListenerMaker */ new OnClickListenerCreator(), false, false,
+                INVALID_DISPLAY, /* mSeatLocationName= */"", /* mIsStopping= */ false);
         UserRecord mAddUser = UserRecord.create(/* mInfo= */ null, /* mName= */ mAddLabel,
                 /* mIsStartGuestSession= */ false, /* mIsAddUser= */ true,
                 /* mIsForeground= */ false,
@@ -196,15 +201,16 @@ public class UserPickerRecyclerViewTest extends UserPickerTestCase {
                 /* mIsStartGuestSession= */ false, /* mIsAddUser= */ false,
                 /* mIsForeground= */ false,
                 /* mIcon= */ mMockUserIconProvider.getRoundedUserIcon(mFrontUserInfo, mContext),
-                /* OnClickListenerMaker */ new OnClickListenerCreator(), /* mIsLoggedIn= */ false,
+                /* OnClickListenerMaker */ new OnClickListenerCreator(),
+                /* mIsSecure= */ false, /* mIsLoggedIn= */ false,
                 /* mLoggedInDisplay= */ -1,
                 /* mSeatLocationName= */ "Test", /* mIsStopping= */ false);
         UserRecord mGuest = UserRecord.create(/* mInfo= */ null, /* mName= */ mGuestLabel,
                 /* mIsStartGuestSession= */ true, /* mIsAddUser= */ false,
                 /* mIsForeground= */ false,
                 mMockUserIconProvider.getRoundedGuestDefaultIcon(mContext),
-                /* OnClickListenerMaker */ new OnClickListenerCreator(), false, INVALID_DISPLAY,
-                /* mSeatLocationName= */"", /* mIsStopping= */ false);
+                /* OnClickListenerMaker */ new OnClickListenerCreator(), false, false,
+                INVALID_DISPLAY, /* mSeatLocationName= */"", /* mIsStopping= */ false);
         UserRecord mAddUser = UserRecord.create(/* mInfo= */ null, /* mName= */ mAddLabel,
                 /* mIsStartGuestSession= */ false, /* mIsAddUser= */ true,
                 /* mIsForeground= */ false,
@@ -250,8 +256,8 @@ public class UserPickerRecyclerViewTest extends UserPickerTestCase {
                     /* mIsStartGuestSession= */ false, /* mIsAddUser= */ false,
                     /* mIsForeground= */ false,
                     /* mIcon= */ mMockUserIconProvider.getRoundedUserIcon(newUserInfo, mContext),
-                    /* OnClickListenerMaker */ new OnClickListenerCreator(), /* mIsLoggedIn= */
-                    false,
+                    /* OnClickListenerMaker */ new OnClickListenerCreator(), /* mIsSecure= */ false,
+                    /* mIsLoggedIn= */ false,
                     /* mLoggedInDisplay= */ INVALID_DISPLAY,
                     /* mSeatLocationName= */ "", /* mIsStopping= */ false);
             mUserList = List.of(mDriver, mFront, mNew, mRear);
@@ -296,8 +302,8 @@ public class UserPickerRecyclerViewTest extends UserPickerTestCase {
                     /* mIsStartGuestSession= */ false, /* mIsAddUser= */ false,
                     /* mIsForeground= */ false,
                     /* mIcon= */ mMockUserIconProvider.getRoundedUserIcon(mRearUserInfo, mContext),
-                    /* OnClickListenerMaker */ new OnClickListenerCreator(), /* mIsLoggedIn= */
-                    true,
+                    /* OnClickListenerMaker */ new OnClickListenerCreator(), /* mIsSecure= */ false,
+                    /* mIsLoggedIn= */ true,
                     /* mLoggedInDisplay= */ REAR_PASSENGER_DISPLAY_ID,
                     /* mSeatLocationName= */ USER_NAME_REAR, /* mIsStopping= */ false);
             mUserList = List.of(mDriver, mFront, mRear);
@@ -318,7 +324,8 @@ public class UserPickerRecyclerViewTest extends UserPickerTestCase {
                 /* mIsStartGuestSession= */ false, /* mIsAddUser= */ false,
                 /* mIsForeground= */ false,
                 /* mIcon= */ mMockUserIconProvider.getRoundedUserIcon(mRearUserInfo, mContext),
-                /* OnClickListenerMaker */ new OnClickListenerCreator(), /* mIsLoggedIn= */ true,
+                /* OnClickListenerMaker */ new OnClickListenerCreator(),
+                /* mIsSecure= */ false, /* mIsLoggedIn= */ true,
                 /* mLoggedInDisplay= */ REAR_PASSENGER_DISPLAY_ID,
                 /* mSeatLocationName= */ USER_NAME_REAR, /* mIsStopping= */ false);
         mUserList = List.of(mDriver, mFront, mRear);
@@ -334,8 +341,8 @@ public class UserPickerRecyclerViewTest extends UserPickerTestCase {
                     /* mIsStartGuestSession= */ false, /* mIsAddUser= */ false,
                     /* mIsForeground= */ false,
                     /* mIcon= */ mMockUserIconProvider.getRoundedUserIcon(mRearUserInfo, mContext),
-                    /* OnClickListenerMaker */ new OnClickListenerCreator(), /* mIsLoggedIn= */
-                    false,
+                    /* OnClickListenerMaker */ new OnClickListenerCreator(), /* mIsSecure= */ false,
+                    /* mIsLoggedIn= */ false,
                     /* mLoggedInDisplay= */ INVALID_DISPLAY,
                     /* mSeatLocationName= */ "", /* mIsStopping= */ false);
             mUserList = List.of(mDriver, mFront, mRear);
@@ -364,8 +371,8 @@ public class UserPickerRecyclerViewTest extends UserPickerTestCase {
                     /* mIsStartGuestSession= */ false, /* mIsAddUser= */ false,
                     /* mIsForeground= */ false,
                     /* mIcon= */ mMockUserIconProvider.getRoundedUserIcon(mRearUserInfo, mContext),
-                    /* OnClickListenerMaker */ new OnClickListenerCreator(), /* mIsLoggedIn= */
-                    false,
+                    /* OnClickListenerMaker */ new OnClickListenerCreator(), /* mIsSecure= */ false,
+                    /* mIsLoggedIn= */ false,
                     /* mLoggedInDisplay= */ INVALID_DISPLAY,
                     /* mSeatLocationName= */ "", /* mIsStopping= */ false);
             mUserList = List.of(mDriver, mFront, mRear);
```

