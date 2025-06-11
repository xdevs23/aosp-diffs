```diff
diff --git a/Android.bp b/Android.bp
index f81f6ee..c108e5e 100644
--- a/Android.bp
+++ b/Android.bp
@@ -25,7 +25,10 @@ android_app {
 
     optimize: {
         enabled: true,
+        optimize: true,
+        shrink_resources: true,
     },
+
     static_libs: [
         "MultiuserWidgetLib",
     ],
@@ -38,18 +41,22 @@ android_library {
     manifest: "AndroidManifest-Widget.xml",
     srcs: ["Widget/src/main/java/**/*.kt"],
     resource_dirs: ["Widget/src/main/res"],
+
+    optimize: {
+        enabled: true,
+        optimize: true,
+        shrink_resources: true,
+    },
+
     static_libs: [
         "androidx.activity_activity-compose",
         "androidx.annotation_annotation",
         "androidx.appcompat_appcompat",
         "androidx.compose.runtime_runtime",
-        "androidx.compose.ui_ui",
         "androidx.glance_glance-appwidget",
         "androidx.glance_glance",
-        "androidx.room_room-runtime",
-        "androidx.room_room-ktx",
+        "PlatformComposeCore",
     ],
-    plugins: ["androidx.room_room-compiler-plugin"],
     kotlincflags: ["-Xjvm-default=all"],
 }
 
@@ -60,13 +67,43 @@ android_test {
     use_resource_processor: true,
     platform_apis: true,
     instrumentation_for: "MultiuserWidgetLib",
-    srcs: ["Widget/src/tests/**/*.kt"],
+    srcs: ["Widget/src/tests/unit/**/*.kt"],
+    resource_dirs: [
+        "Widget/src/main/res",
+        "Widget/src/tests/res",
+    ],
+    static_libs: [
+        "MultiuserWidgetLib",
+        "androidx.test.core",
+        "androidx.test.rules",
+        "androidx.test.ext.junit",
+        "kotlinx_coroutines_test",
+        "flag-junit",
+        "androidx.test.runner",
+        "kotlin-test",
+    ],
+    kotlincflags: ["-Xjvm-default=all"],
+    test_suites: ["device-tests"],
+}
+
+android_test {
+    name: "MultiuserWidgetUiTests",
+    manifest: "AndroidManifestUiTests.xml",
+    certificate: "platform",
+    use_resource_processor: true,
+    platform_apis: true,
+    instrumentation_for: "MultiuserWidgetLib",
+    srcs: ["Widget/src/tests/ui/**/*.kt"],
     resource_dirs: [
         "Widget/src/main/res",
         "Widget/src/tests/res",
     ],
     static_libs: [
         "MultiuserWidgetLib",
+        "androidx.compose.runtime_runtime",
+        "androidx.compose.ui_ui-test",
+        "androidx.compose.ui_ui-test-junit4",
+        "androidx.compose.ui_ui-test-manifest",
         "androidx.test.core",
         "androidx.test.rules",
         "androidx.test.ext.junit",
@@ -74,7 +111,6 @@ android_test {
         "flag-junit",
         "androidx.test.runner",
         "kotlin-test",
-        "androidx.room_room-testing",
     ],
     kotlincflags: ["-Xjvm-default=all"],
     test_suites: ["device-tests"],
diff --git a/AndroidManifest-Widget.xml b/AndroidManifest-Widget.xml
index a97c29b..24a2b7c 100644
--- a/AndroidManifest-Widget.xml
+++ b/AndroidManifest-Widget.xml
@@ -21,17 +21,21 @@
         <receiver
             android:name=".MultiuserWidgetReceiver"
             android:label="@string/multiuser_widget_name"
-            android:exported="true">
+            android:exported="false">
             <intent-filter>
                 <action android:name="android.appwidget.action.APPWIDGET_UPDATE" />
                 <action android:name="android.settings.USER_SETTINGS" />
+                <!--To be changed to wakeup frozen widget-->
+                <action android:name="android.intent.action.USER_INFO_CHANGED_BACKGROUND"/>
+                <action android:name="android.intent.action.USER_REMOVED" />
+                <action android:name="android.intent.action.USER_ADDED" />
             </intent-filter>
             <meta-data
                 android:name="android.appwidget.provider"
                 android:resource="@xml/multiuser_widget_info" />
         </receiver>
-        <activity android:name=".action.util.DialogActivity"
-            android:exported="true"
+        <activity android:name=".ui.DialogActivity"
+            android:exported="false"
             android:theme="@style/Theme.Transparent"
             android:launchMode="singleTask"
             android:excludeFromRecents="true">
diff --git a/AndroidManifest.xml b/AndroidManifest.xml
index e377372..441539f 100644
--- a/AndroidManifest.xml
+++ b/AndroidManifest.xml
@@ -21,6 +21,7 @@
     <uses-permission android:name="android.permission.MANAGE_USERS"/>
     <application
         android:label="@string/multiuser_app_name"
+        android:theme="@style/Theme.MultiuserWidget"
         android:icon="@mipmap/ic_launcher">
     </application>
 </manifest>
diff --git a/AndroidManifestUiTests.xml b/AndroidManifestUiTests.xml
new file mode 100644
index 0000000..45e6a81
--- /dev/null
+++ b/AndroidManifestUiTests.xml
@@ -0,0 +1,29 @@
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
+<manifest xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:tools="http://schemas.android.com/tools"
+    package="com.android.multiuser.widget.ui.tests">
+
+    <application android:debuggable="true">
+        <uses-library android:name="android.test.runner" />
+    </application>
+
+    <instrumentation android:name="androidx.test.runner.AndroidJUnitRunner"
+        android:targetPackage="com.android.multiuser.widget.ui.tests"
+        android:label="Users Widget UI Test Cases">
+    </instrumentation>
+</manifest>
\ No newline at end of file
diff --git a/TEST_MAPPING b/TEST_MAPPING
index f4d9a9a..40af0d7 100644
--- a/TEST_MAPPING
+++ b/TEST_MAPPING
@@ -1,5 +1,8 @@
 {
   "postsubmit": [
+    {
+      "name": "MultiuserWidgetUiTests"
+    },
     {
       "name": "MultiuserWidgetUnitTests"
     }
diff --git a/Widget/src/main/java/com/android/multiuser/widget/MultiuserWidget.kt b/Widget/src/main/java/com/android/multiuser/widget/MultiuserWidget.kt
index 8f44326..b57ade5 100644
--- a/Widget/src/main/java/com/android/multiuser/widget/MultiuserWidget.kt
+++ b/Widget/src/main/java/com/android/multiuser/widget/MultiuserWidget.kt
@@ -17,44 +17,58 @@
 package com.android.multiuser.widget
 
 import android.content.Context
+import android.os.UserManager
 import androidx.compose.runtime.collectAsState
 import androidx.compose.runtime.Composable
+import androidx.compose.runtime.getValue
+import androidx.compose.runtime.rememberCoroutineScope
 import androidx.glance.appwidget.GlanceAppWidget
 import androidx.glance.appwidget.SizeMode
 import androidx.glance.appwidget.provideContent
 import androidx.glance.GlanceId
 import androidx.glance.GlanceTheme
+import com.android.multiuser.widget.domain.ILoadUsersUseCase
+import com.android.multiuser.widget.domain.LoadUsersFromServerUseCase
 import com.android.multiuser.widget.data.ActionsRepository
-import com.android.multiuser.widget.data.UsersDatabase.Companion.getDatabase
-import com.android.multiuser.widget.domain.LoadUsersUseCase
+import com.android.multiuser.widget.data.ImageRepository
+import com.android.multiuser.widget.data.IntentRepository
+import com.android.multiuser.widget.data.UsersRepository
 import com.android.multiuser.widget.ui.view.layout.ErrorLayout
 import com.android.multiuser.widget.ui.view.layout.LoadingLayout
 import com.android.multiuser.widget.ui.view.layout.MultiuserWidgetLayout
-import com.android.multiuser.widget.viewmodel.StateViewModel.Loading
+import com.android.multiuser.widget.viewmodel.UiState
 import com.android.multiuser.widget.viewmodel.UsersViewModel
-import kotlinx.coroutines.flow.Flow
+
+import kotlinx.coroutines.launch
 
 class MultiuserWidget : GlanceAppWidget() {
   override val sizeMode: SizeMode = SizeMode.Exact
+
   override suspend fun provideGlance(context: Context, id: GlanceId) {
-    val loadUsersUseCase = LoadUsersUseCase(
-      userDao = getDatabase(context).getUserDao(),
-      actionsRepository = ActionsRepository(context)
+    val userManager = MultiuserWidgetUtil.getUserManager(context)
+    val useCase: ILoadUsersUseCase = LoadUsersFromServerUseCase(
+      UsersRepository(userManager, MultiuserWidgetUtil.getActivityManager(context)),
+      ActionsRepository(context.resources),
+      ImageRepository(userManager, context.resources),
+      IntentRepository(context.resources)
     )
-    val usersViewModelFlow = loadUsersUseCase()
 
     provideContent {
-      GlanceTheme {
-        Content(usersViewModelFlow)
-      }
+      GlanceTheme { Content(UsersViewModel(useCase)) }
     }
   }
 
   @Composable
-  private fun Content(usersViewModelFlow: Flow<UsersViewModel>) {
-    when(val usersViewModel = usersViewModelFlow.collectAsState(Loading).value) {
-      is Loading -> LoadingLayout()
-      is UsersViewModel -> MultiuserWidgetLayout(usersViewModel)
+  private fun Content(viewModel: UsersViewModel) {
+    val uiState by viewModel.uiState.collectAsState()
+    val scope = rememberCoroutineScope()
+
+    when (uiState) {
+      is UiState.Invalid ->
+        scope.launch { viewModel.reload() }
+
+      is UiState.Loading -> LoadingLayout()
+      is UiState.Success -> MultiuserWidgetLayout(viewModel)
       else -> ErrorLayout()
     }
   }
diff --git a/Widget/src/main/java/com/android/multiuser/widget/MultiuserWidgetReceiver.kt b/Widget/src/main/java/com/android/multiuser/widget/MultiuserWidgetReceiver.kt
index ea5409e..b0e337a 100644
--- a/Widget/src/main/java/com/android/multiuser/widget/MultiuserWidgetReceiver.kt
+++ b/Widget/src/main/java/com/android/multiuser/widget/MultiuserWidgetReceiver.kt
@@ -16,10 +16,39 @@
 
 package com.android.multiuser.widget
 
+import android.content.Context
+import android.content.Intent
+
 import androidx.glance.appwidget.GlanceAppWidget
 import androidx.glance.appwidget.GlanceAppWidgetReceiver
+import androidx.glance.appwidget.updateAll
+
+import kotlinx.coroutines.CoroutineDispatcher
+import kotlinx.coroutines.CoroutineScope
+import kotlinx.coroutines.Dispatchers
+import kotlinx.coroutines.launch
+
+import com.android.multiuser.widget.viewmodel.UsersViewModel
 
 /** Broadcast receiver for multiuser widget registered in the Manifest. */
-class MultiuserWidgetReceiver : GlanceAppWidgetReceiver() {
+class MultiuserWidgetReceiver(
+    private val dispatcher: CoroutineDispatcher = Dispatchers.IO) : GlanceAppWidgetReceiver() {
     override val glanceAppWidget: GlanceAppWidget = MultiuserWidget()
+    private val allowedActions = arrayOf(
+        // Start widget
+        "android.intent.action.USER_INFO_CHANGED_BACKGROUND",
+        "android.intent.action.USER_REMOVED",
+        "android.intent.action.USER_ADDED"
+    )
+
+    override fun onReceive(context: Context, intent: Intent) {
+        super.onReceive(context, intent)
+        if (intent.action in allowedActions) {
+            // inform runnung widget that data changed
+            UsersViewModel.invalidate()
+            CoroutineScope(dispatcher).launch {
+                glanceAppWidget.updateAll(context)
+            }
+        }
+    }
 }
diff --git a/Widget/src/main/java/com/android/multiuser/widget/action/UserSwitchExecutor.kt b/Widget/src/main/java/com/android/multiuser/widget/action/UserSwitchExecutor.kt
deleted file mode 100644
index 1efb815..0000000
--- a/Widget/src/main/java/com/android/multiuser/widget/action/UserSwitchExecutor.kt
+++ /dev/null
@@ -1,56 +0,0 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
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
-package com.android.multiuser.widget.action
-
-import android.content.Context
-import android.content.Intent
-import android.os.UserHandle
-import android.os.UserManager
-import com.android.multiuser.widget.action.util.DialogActivity
-import com.android.multiuser.widget.MultiuserWidgetUtil
-
-fun switchUsers(userId: Int, context: Context) {
-    val userManager = MultiuserWidgetUtil.getUserManager(context)
-    if(userManager == null) {
-        showFailedDialog(context, /* showSwitchFailedDialog=*/ true)
-        return
-    }
-
-    if(userManager.getUserSwitchability() != UserManager.SWITCHABILITY_STATUS_OK) {
-        showFailedDialog(context, /* showSwitchFailedDialog=*/ true)
-        return
-    }
-
-    if(!userManager.isUserSwitcherEnabled(true)) {
-        showFailedDialog(context, /* showSwitchFailedDialog=*/ false)
-        return
-    }
-
-    val activityManager = MultiuserWidgetUtil.getActivityManager(context)
-    if(activityManager == null || !activityManager.switchUser(UserHandle(userId))) {
-        showFailedDialog(context, /* showSwitchFailedDialog=*/ true)
-    }
-}
-
-private fun showFailedDialog(context: Context, showSwitchFailedDialog: Boolean) {
-    context.startActivity(
-        Intent(context, DialogActivity::class.java).apply {
-            putExtra("showFailedDialog", showSwitchFailedDialog)
-            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
-        }
-    )
-}
diff --git a/Widget/src/main/java/com/android/multiuser/widget/action/util/DialogActivity.kt b/Widget/src/main/java/com/android/multiuser/widget/action/util/DialogActivity.kt
deleted file mode 100644
index aa5c7d8..0000000
--- a/Widget/src/main/java/com/android/multiuser/widget/action/util/DialogActivity.kt
+++ /dev/null
@@ -1,49 +0,0 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
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
-package com.android.multiuser.widget.action.util
-
-import android.app.AlertDialog
-import android.os.Bundle
-import androidx.appcompat.app.AppCompatActivity
-import com.android.multiuser.widget.domain.SwitchFailedUseCase
-import com.android.multiuser.widget.repository.ResourceRepository
-
-class DialogActivity: AppCompatActivity() {
-    override fun onCreate(savedInstanceState: Bundle?) {
-        super.onCreate(savedInstanceState)
-
-        val switchFailedUseCase =
-            SwitchFailedUseCase(ResourceRepository(this.getResources()), intent)
-        val dialogViewModel = switchFailedUseCase()
-
-        val dialogBuilder = AlertDialog.Builder(this)
-            .setMessage(dialogViewModel.message)
-            .setNegativeButton(dialogViewModel.negativeButtonText, /* listener=*/ null)
-        if(dialogViewModel.positiveButtonText != null && dialogViewModel.actionIntent != null) {
-            dialogBuilder.setPositiveButton(dialogViewModel.positiveButtonText) {  _, _ ->
-                this.startActivity(dialogViewModel.actionIntent)
-            }
-        }
-
-        val dialog = dialogBuilder.create()
-
-        // Ensure the activity stops when the dialog is closed.
-        dialog.setOnDismissListener{ finish() }
-
-        dialog.show()
-    }
-}
diff --git a/Widget/src/main/java/com/android/multiuser/widget/data/ActionsRepository.kt b/Widget/src/main/java/com/android/multiuser/widget/data/ActionsRepository.kt
index 57b5229..c03c41c 100644
--- a/Widget/src/main/java/com/android/multiuser/widget/data/ActionsRepository.kt
+++ b/Widget/src/main/java/com/android/multiuser/widget/data/ActionsRepository.kt
@@ -16,14 +16,14 @@
 
 package com.android.multiuser.widget.data
 
-import android.content.Context
+import android.content.res.Resources
 import com.android.multiuser.widget.data.model.Action
 import com.android.multiuser.widget.R
 
-class ActionsRepository(private val context: Context) {
+class ActionsRepository(private val resources: Resources) {
     fun getAddUserAction() = Action(
-        title = context.getString(R.string.add_user_button_title),
-        contentDescription = context.getString(R.string.add_user_button_content_description),
+        title = resources.getString(R.string.add_user_button_title),
+        contentDescription = resources.getString(R.string.add_user_button_content_description),
         resourceId = R.drawable.person_add,
     )
 }
diff --git a/Widget/src/main/java/com/android/multiuser/widget/data/UsersDatabaseHelper.kt b/Widget/src/main/java/com/android/multiuser/widget/data/IUsersRepository.kt
similarity index 58%
rename from Widget/src/main/java/com/android/multiuser/widget/data/UsersDatabaseHelper.kt
rename to Widget/src/main/java/com/android/multiuser/widget/data/IUsersRepository.kt
index 6c5bae8..14700d5 100644
--- a/Widget/src/main/java/com/android/multiuser/widget/data/UsersDatabaseHelper.kt
+++ b/Widget/src/main/java/com/android/multiuser/widget/data/IUsersRepository.kt
@@ -16,15 +16,14 @@
 
 package com.android.multiuser.widget.data
 
-import android.content.Context
-import com.android.multiuser.widget.MultiuserWidgetUtil
-import com.android.multiuser.widget.repository.UsersRepository
-import java.util.concurrent.Executors
+import kotlin.collections.List
+import com.android.multiuser.widget.data.model.User
+import com.android.multiuser.widget.data.model.UserSwitchRestrictions
 
-fun populateWithInitialData(context: Context, userDao: UserDao) {
-    val usersList = UsersRepository(MultiuserWidgetUtil.getUserManager(context)).getUsers(context)
-
-    Executors.newSingleThreadExecutor().execute {
-        userDao.addUsers(*usersList.toTypedArray())
-    }
-}
+interface IUsersRepository {
+    suspend fun getUsers(): List<User>
+    suspend fun disableSwitchUsers(): Boolean
+    fun isCurrentUserAdmin(): Boolean
+    fun checkUserSwitchRestrictions(): UserSwitchRestrictions
+    fun switchToUser(userId: Int): Boolean
+}
\ No newline at end of file
diff --git a/Widget/src/main/java/com/android/multiuser/widget/data/ImageRepository.kt b/Widget/src/main/java/com/android/multiuser/widget/data/ImageRepository.kt
new file mode 100644
index 0000000..d4637b0
--- /dev/null
+++ b/Widget/src/main/java/com/android/multiuser/widget/data/ImageRepository.kt
@@ -0,0 +1,32 @@
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
+package com.android.multiuser.widget.data
+
+import android.content.res.Resources
+import android.graphics.Bitmap
+import android.os.UserManager
+import com.android.internal.util.UserIcons
+import java.io.File
+import java.io.FileOutputStream
+import java.io.IOException
+
+class ImageRepository(val userManager: UserManager?, val resources: Resources) {
+
+suspend fun getAvatar(userId: Int): Bitmap = userManager?.getUserIcon(userId)
+    ?: UserIcons.getDefaultUserIcon(resources, userId, false)
+        .let { UserIcons.convertToBitmapAtUserIconSize(resources, it) }
+}
\ No newline at end of file
diff --git a/Widget/src/main/java/com/android/multiuser/widget/data/IntentRepository.kt b/Widget/src/main/java/com/android/multiuser/widget/data/IntentRepository.kt
new file mode 100644
index 0000000..1872937
--- /dev/null
+++ b/Widget/src/main/java/com/android/multiuser/widget/data/IntentRepository.kt
@@ -0,0 +1,111 @@
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
+package com.android.multiuser.widget.data
+
+import android.content.ComponentName
+import android.content.Intent
+import android.content.res.Resources
+import android.provider.Settings
+import android.os.UserManager
+import com.android.multiuser.widget.R
+import com.android.multiuser.widget.data.model.UserSwitchRestrictions
+
+class IntentRepository(val res: Resources) {
+    fun getUserSwitchRestrictedIntent(restriction: UserSwitchRestrictions) =
+        Intent(Settings.ACTION_USER_SETTINGS)
+            .setComponent(
+                ComponentName(
+                    "com.android.multiuser",
+                    "com.android.multiuser.widget.ui.DialogActivity"
+                )
+            )
+            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
+            .putExtra("title", res.getUserSwitchRestrictedTitle(restriction))
+            .putExtra("message", res.getUserSwitchRestrictedMessage(restriction))
+            .multiuserSettingsIntent(restriction)
+
+    private fun Resources.getUserSwitchRestrictedTitle(
+        restriction: UserSwitchRestrictions
+    ): String {
+        return when (restriction) {
+            UserSwitchRestrictions.WORK_POLICY ->
+                getString(R.string.widget_switch_work_restriction_dialog_title)
+            UserSwitchRestrictions.ONCALL_OR_LOCKED ->
+                getString(R.string.widget_switch_not_allowed_dialog_title)
+            UserSwitchRestrictions.DISABLED ->
+                getString(R.string.widget_switch_disabled_dialog_title)
+            else ->
+                getString(R.string.widget_switch_failed_dialog_title)
+        }
+    }
+
+    private fun Resources.getUserSwitchRestrictedMessage(
+        restriction: UserSwitchRestrictions
+    ): String {
+        return when (restriction) {
+            UserSwitchRestrictions.WORK_POLICY ->
+                getString(R.string.widget_switch_work_restriction_dialog_message)
+            // impossible to show widged on locked system?
+            UserSwitchRestrictions.ONCALL_OR_LOCKED ->
+                getString(R.string.widget_switch_not_allowed_dialog_message)
+            UserSwitchRestrictions.DISABLED ->
+                getString(R.string.widget_switch_disabled_dialog_message)
+            else ->
+                getString(R.string.widget_switch_failed_dialog_message)
+        }
+    }
+
+    private fun Intent.multiuserSettingsIntent(
+        restriction: UserSwitchRestrictions
+    ): Intent {
+        if (restriction == UserSwitchRestrictions.DISABLED) {
+            putExtra("intent_action", Settings.ACTION_USER_SETTINGS)
+            putExtra("intent_package", "com.android.settings")
+            putExtra(
+                "intent_class",
+                "com.android.settings.Settings\$UserSettingsActivity"
+            )
+            putExtra(
+                "intent_flags",
+                Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
+            )
+            putExtra(
+                "action_text",
+                res.getString(
+                    R.string.widget_switch_disabled_dialog_open_settings_button
+                )
+            )
+        }
+        return this
+    }
+}
+
+fun Intent.getActionIntent() : Intent? {
+    var intent: Intent? = null
+    getStringExtra("intent_action")?.let { action ->
+        intent = Intent(action)
+        getStringExtra("intent_package")?.let { intentPackage ->
+            getStringExtra("intent_class")?.let { intentClass ->
+                intent.component = ComponentName(intentPackage, intentClass)
+            }
+        }
+        getIntExtra("intent_flags", 0)?.let { intent.flags = it }
+    }
+    return intent
+}
+
+
diff --git a/Widget/src/main/java/com/android/multiuser/widget/data/UserDao.kt b/Widget/src/main/java/com/android/multiuser/widget/data/UserDao.kt
deleted file mode 100644
index 6219fa7..0000000
--- a/Widget/src/main/java/com/android/multiuser/widget/data/UserDao.kt
+++ /dev/null
@@ -1,44 +0,0 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
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
-package com.android.multiuser.widget.data
-
-import androidx.room.Dao
-import androidx.room.Delete
-import androidx.room.Insert
-import androidx.room.OnConflictStrategy
-import androidx.room.Update
-import androidx.room.Query
-import com.android.multiuser.widget.data.model.User
-import kotlinx.coroutines.flow.Flow
-
-@Dao
-interface UserDao {
-    @Query("SELECT * FROM UserModels ORDER BY creationTime ASC")
-    fun getUsers(): Flow<List<User>>
-
-    @Query("SELECT * FROM UserModels WHERE isCurrentUser = TRUE LIMIT 1")
-    fun getCurrentUser(): Flow<User>
-
-    @Insert(onConflict = OnConflictStrategy.REPLACE)
-    fun addUsers(vararg users: User)
-
-    @Update
-    fun updateUsers(vararg users: User)
-
-    @Delete
-    fun deleteUser(vararg users: User)
-}
\ No newline at end of file
diff --git a/Widget/src/main/java/com/android/multiuser/widget/data/UsersDatabase.kt b/Widget/src/main/java/com/android/multiuser/widget/data/UsersDatabase.kt
deleted file mode 100644
index f71b9be..0000000
--- a/Widget/src/main/java/com/android/multiuser/widget/data/UsersDatabase.kt
+++ /dev/null
@@ -1,53 +0,0 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
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
-package com.android.multiuser.widget.data
-
-import android.content.Context
-import androidx.room.Database
-import androidx.room.Room
-import androidx.room.RoomDatabase
-import com.android.multiuser.widget.data.model.User
-
-@Database(
-    entities = [User::class],
-    version = 1,
-    exportSchema = false)
-abstract class UsersDatabase : RoomDatabase() {
-
-    // This is how the database exposes DAOs.
-    abstract fun getUserDao(): UserDao
-
-    companion object {
-        // Singleton prevents multiple instances of database opening at the same time.
-        @Volatile
-        private var INSTANCE: UsersDatabase? = null
-
-        fun getDatabase(context: Context): UsersDatabase {
-            if(INSTANCE == null) {
-                // temporary instance that will be populated with initial data
-                val instance = Room.databaseBuilder(
-                    context.applicationContext,
-                    UsersDatabase::class.java,
-                    "multiuser_widget_database"
-                ).build()
-                populateWithInitialData(context, instance.getUserDao())
-                INSTANCE = instance
-            }
-            return INSTANCE as UsersDatabase
-        }
-    }
-}
diff --git a/Widget/src/main/java/com/android/multiuser/widget/data/UsersRepository.kt b/Widget/src/main/java/com/android/multiuser/widget/data/UsersRepository.kt
new file mode 100644
index 0000000..d172cee
--- /dev/null
+++ b/Widget/src/main/java/com/android/multiuser/widget/data/UsersRepository.kt
@@ -0,0 +1,89 @@
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
+package com.android.multiuser.widget.data
+
+import android.app.ActivityManager
+import android.content.Context
+import android.content.ContextWrapper
+import android.content.pm.UserInfo
+import android.graphics.Bitmap
+import android.os.UserHandle
+import android.os.UserManager
+import java.io.File
+import java.io.FileOutputStream
+import java.io.IOException
+import kotlin.collections.List
+import com.android.multiuser.widget.data.model.User
+import com.android.multiuser.widget.data.model.UserSwitchRestrictions
+
+class UsersRepository(private val userManager: UserManager?,
+    private var activityManager: ActivityManager?): IUsersRepository {
+    val currentUserId = UserHandle.myUserId()
+
+    override suspend fun getUsers(): List<User> {
+        if (userManager == null) {
+            // This ensures the error layout is shown in the UI.
+            return listOf()
+        }
+        var userInfoList = userManager.getAliveUsers()
+            .filter { it.isFull() && it.supportsSwitchTo() }
+        return userInfoList
+            .map { userInfo: UserInfo ->
+                User(
+                    id = userInfo.id,
+                    name = userInfo.name ?: "",
+                    creationTime = userInfo.creationTime,
+                    isCurrentUser = (currentUserId == userInfo.id),
+                    isAdmin = userInfo.isAdmin(),
+                    switchable = !disableSwitchUsers()
+                )
+            }
+    }
+
+    override suspend fun disableSwitchUsers(): Boolean {
+        return checkUserSwitchRestrictions() != UserSwitchRestrictions.NONE
+    }
+
+    override fun isCurrentUserAdmin(): Boolean {
+        return userManager?.isUserAdmin(currentUserId) ?: false
+    }
+
+    override fun checkUserSwitchRestrictions(): UserSwitchRestrictions {
+        if (userManager == null) {
+            return UserSwitchRestrictions.UNKNOWN
+        }
+        if (userManager.hasUserRestriction(
+                UserManager.DISALLOW_USER_SWITCH
+            )
+        ) {
+            return UserSwitchRestrictions.WORK_POLICY
+        }
+        if (userManager.getUserSwitchability() !=
+            UserManager.SWITCHABILITY_STATUS_OK
+        ) {
+            return UserSwitchRestrictions.ONCALL_OR_LOCKED
+        }
+        if (!userManager.isUserSwitcherEnabled(true)) {
+            return UserSwitchRestrictions.DISABLED
+        }
+        return UserSwitchRestrictions.NONE
+    }
+
+    override fun switchToUser(userId: Int) :Boolean {
+        return activityManager?.switchUser(UserHandle(userId))?: false
+    }
+}
diff --git a/Widget/src/main/java/com/android/multiuser/widget/data/model/User.kt b/Widget/src/main/java/com/android/multiuser/widget/data/model/User.kt
index fd97e61..9d8479d 100644
--- a/Widget/src/main/java/com/android/multiuser/widget/data/model/User.kt
+++ b/Widget/src/main/java/com/android/multiuser/widget/data/model/User.kt
@@ -24,9 +24,9 @@ data class User(
         @PrimaryKey val id: Int,
         val name: String,
         val creationTime: Long,
-        val iconPath: String,
         var isCurrentUser: Boolean,
-        val isAdmin: Boolean
+        val isAdmin: Boolean,
+        val switchable: Boolean
 ) {
     override fun equals(other: Any?): Boolean {
         if (this === other) return true
@@ -37,18 +37,18 @@ data class User(
         return id == other.id &&
             name == other.name &&
             creationTime == other.creationTime &&
-            iconPath == other.iconPath &&
             isCurrentUser == other.isCurrentUser &&
-            isAdmin == other.isAdmin
+            isAdmin == other.isAdmin &&
+            switchable == other.switchable
     }
 
     override fun hashCode(): Int {
         var result = id.hashCode()
         result = 31 * result + name.hashCode()
         result = 31 * result + creationTime.hashCode()
-        result = 31 * result + iconPath.hashCode()
         result = 31 * result + isCurrentUser.hashCode()
         result = 31 * result + isAdmin.hashCode()
+        result = 31 * result + switchable.hashCode()
         return result
     }
 }
\ No newline at end of file
diff --git a/Widget/src/main/java/com/android/multiuser/widget/data/model/UserSwitchRestrictions.kt b/Widget/src/main/java/com/android/multiuser/widget/data/model/UserSwitchRestrictions.kt
new file mode 100644
index 0000000..0b2a789
--- /dev/null
+++ b/Widget/src/main/java/com/android/multiuser/widget/data/model/UserSwitchRestrictions.kt
@@ -0,0 +1,25 @@
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
+package com.android.multiuser.widget.data.model
+
+enum class UserSwitchRestrictions(int: Int) {
+    NONE(0),
+    WORK_POLICY(1),
+    ONCALL_OR_LOCKED(2),
+    DISABLED(3),
+    UNKNOWN(4)
+}
\ No newline at end of file
diff --git a/Widget/src/main/java/com/android/multiuser/widget/domain/DialogUseCase.kt b/Widget/src/main/java/com/android/multiuser/widget/domain/DialogUseCase.kt
new file mode 100644
index 0000000..fd984c4
--- /dev/null
+++ b/Widget/src/main/java/com/android/multiuser/widget/domain/DialogUseCase.kt
@@ -0,0 +1,48 @@
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
+package com.android.multiuser.widget.domain
+
+import android.content.Intent
+import android.content.res.Resources
+
+import androidx.compose.ui.res.stringResource
+
+import kotlinx.coroutines.CoroutineDispatcher
+import kotlinx.coroutines.Dispatchers
+import kotlinx.coroutines.withContext
+
+import com.android.multiuser.widget.R
+import com.android.multiuser.widget.data.getActionIntent
+import com.android.multiuser.widget.viewmodel.DialogViewModel
+
+/**
+ * Load DialogViewModel from intent and resources.
+ */
+class DialogUseCase(private val intent:Intent,
+                        private val resources: Resources) {
+    operator fun invoke() : DialogViewModel {
+        return DialogViewModel(
+            title = intent.getStringExtra("title")
+                ?: resources.getString(R.string.widget_switch_not_allowed_dialog_message),
+            message = intent.getStringExtra("message")
+                ?: resources.getString(R.string.widget_switch_not_allowed_dialog_message),
+            positiveButtonText =
+                intent.getStringExtra("action_text"),
+            actionIntent = intent.getActionIntent()
+        )
+    }
+}
diff --git a/Widget/src/main/java/com/android/multiuser/widget/domain/ILoadUsersUseCase.kt b/Widget/src/main/java/com/android/multiuser/widget/domain/ILoadUsersUseCase.kt
new file mode 100644
index 0000000..dafda8f
--- /dev/null
+++ b/Widget/src/main/java/com/android/multiuser/widget/domain/ILoadUsersUseCase.kt
@@ -0,0 +1,28 @@
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
+package com.android.multiuser.widget.domain
+
+import com.android.multiuser.widget.viewmodel.GridItemViewModel
+import kotlin.collections.List
+
+/**
+ * Interface to load Users content.
+ */
+
+interface ILoadUsersUseCase {
+    suspend operator fun invoke(): List<GridItemViewModel>
+}
diff --git a/Widget/src/main/java/com/android/multiuser/widget/domain/SwitchFailedUseCase.kt b/Widget/src/main/java/com/android/multiuser/widget/domain/LoadUserAvatarUseCase.kt
similarity index 53%
rename from Widget/src/main/java/com/android/multiuser/widget/domain/SwitchFailedUseCase.kt
rename to Widget/src/main/java/com/android/multiuser/widget/domain/LoadUserAvatarUseCase.kt
index a364879..2e5ac76 100644
--- a/Widget/src/main/java/com/android/multiuser/widget/domain/SwitchFailedUseCase.kt
+++ b/Widget/src/main/java/com/android/multiuser/widget/domain/LoadUserAvatarUseCase.kt
@@ -16,21 +16,22 @@
 
 package com.android.multiuser.widget.domain
 
-import android.content.Intent
-import com.android.multiuser.widget.repository.ResourceRepository
+import android.graphics.Bitmap
+import com.android.multiuser.widget.data.ImageRepository
+
+import kotlinx.coroutines.CoroutineDispatcher
+import kotlinx.coroutines.Dispatchers
+import kotlinx.coroutines.withContext
 
 /**
- * Returns a dialog that is displayed when user switching is not successful.
+ * LoadUserAvatarUseCase for user and return Bitmap
  */
-class SwitchFailedUseCase(private val repository: ResourceRepository, intent: Intent) {
-    private val showFailedDialog =
-        intent.getBooleanExtra("showFailedDialog", /* defaultValue=*/true)
-
-    operator fun invoke(): ResourceRepository.DialogViewModel {
-        return if(showFailedDialog) {
-            repository.getSwitchFailed()
-        } else {
-            repository.getSwitchNotAllowed()
-        }
+class LoadUserAvatarUseCase(
+    private val userId: Int,
+    private val imageRepository: ImageRepository,
+    private val dispatcher: CoroutineDispatcher = Dispatchers.IO
+) {
+    suspend operator fun invoke(): Bitmap = withContext(dispatcher) {
+        return@withContext imageRepository.getAvatar(userId)
     }
-}
+}
\ No newline at end of file
diff --git a/Widget/src/main/java/com/android/multiuser/widget/domain/LoadUsersUseCase.kt b/Widget/src/main/java/com/android/multiuser/widget/domain/LoadUsersFromServerUseCase.kt
similarity index 60%
rename from Widget/src/main/java/com/android/multiuser/widget/domain/LoadUsersUseCase.kt
rename to Widget/src/main/java/com/android/multiuser/widget/domain/LoadUsersFromServerUseCase.kt
index b7fa8cc..59efa94 100644
--- a/Widget/src/main/java/com/android/multiuser/widget/domain/LoadUsersUseCase.kt
+++ b/Widget/src/main/java/com/android/multiuser/widget/domain/LoadUsersFromServerUseCase.kt
@@ -17,66 +17,55 @@
 package com.android.multiuser.widget.domain
 
 import com.android.multiuser.widget.data.ActionsRepository
-import com.android.multiuser.widget.data.UserDao
+import com.android.multiuser.widget.data.ImageRepository
+import com.android.multiuser.widget.data.IntentRepository
+import com.android.multiuser.widget.data.IUsersRepository
 import com.android.multiuser.widget.data.model.Action
-import com.android.multiuser.widget.data.model.User
 import com.android.multiuser.widget.util.SHOULD_DISPLAY_ADD_USER_BUTTON
 import com.android.multiuser.widget.viewmodel.ActionViewModel
 import com.android.multiuser.widget.viewmodel.UserViewModel
-import com.android.multiuser.widget.viewmodel.UsersViewModel
+import com.android.multiuser.widget.viewmodel.GridItemViewModel
 import kotlinx.coroutines.CoroutineDispatcher
 import kotlinx.coroutines.Dispatchers
-import kotlinx.coroutines.flow.Flow
-import kotlinx.coroutines.flow.first
-import kotlinx.coroutines.flow.flow
 import kotlinx.coroutines.withContext
+import kotlin.collections.List
 
 /**
- * Maps data from the local Room database into viewmodel [UsersViewModel].
+ * Maps data from the local service into list of GridItemViewModel.
  */
-class LoadUsersUseCase(
-    private val userDao: UserDao,
-    private val dispatcher: CoroutineDispatcher = Dispatchers.Default,
-    private val actionsRepository: ActionsRepository
-) {
-    suspend operator fun invoke(): Flow<UsersViewModel> = withContext(dispatcher) {
-        return@withContext loadUsersViewModel()
+class LoadUsersFromServerUseCase(
+    private val usersRepository: IUsersRepository,
+    private val actionsRepository: ActionsRepository,
+    private val imageRepository: ImageRepository,
+    private val intentRepository: IntentRepository,
+    private val dispatcher: CoroutineDispatcher = Dispatchers.IO
+) : ILoadUsersUseCase{
+    override suspend operator fun invoke(): List<GridItemViewModel> = withContext(dispatcher) {
+        return@withContext getUserViewModels() + getActionViewModels()
     }
-
-    private fun loadUsersViewModel(): Flow<UsersViewModel>  {
-        return flow {
-            val model = UsersViewModel(
-                users = getUserViewModels(),
-                actions = getActionViewModels(),
-            )
-            emit(model)
-        }
-    }
-
     private suspend fun getUserViewModels() =
-            userDao.getUsers().first().map { user -> mapUserToUserViewModel(user) }
+        usersRepository.getUsers().map { user -> UserViewModel (
+            id = user.id,
+            name = user.name,
+            isSelected = user.isCurrentUser,
+            // TODO: check content auto-generated description.
+            // contentDescription is auto-generated because user icons are selectable
+            contentDescription = null,
+            enabled = user.isCurrentUser || user.switchable,
+            loadAvatarUseCase = LoadUserAvatarUseCase(user.id, imageRepository),
+            userSwitchUseCase = UserSwitchUseCase(user.id, usersRepository, intentRepository)
+        )}
 
     private suspend fun getActionViewModels(): List<ActionViewModel> {
         // If the current user is an admin and SHOW_ADD_USER_BUTTON is set to true, include the
         // button for adding users.
-        if(userDao.getCurrentUser().first().isAdmin && SHOULD_DISPLAY_ADD_USER_BUTTON) {
+        if(usersRepository.isCurrentUserAdmin() && SHOULD_DISPLAY_ADD_USER_BUTTON) {
             return listOf(mapActionToActionViewModel(actionsRepository.getAddUserAction()))
         }
 
         return emptyList()
     }
 
-    private fun mapUserToUserViewModel(user: User): UserViewModel {
-        return UserViewModel(
-            iconPath = user.iconPath,
-            id = user.id,
-            name = user.name,
-            isSelected = user.isCurrentUser,
-            // contentDescription is auto-generated because user icons are selectable
-            contentDescription = null,
-        )
-    }
-
     private fun mapActionToActionViewModel(action: Action): ActionViewModel {
         return ActionViewModel (
             title = action.title,
@@ -84,4 +73,4 @@ class LoadUsersUseCase(
             contentDescription = action.contentDescription
         )
     }
-}
+}
\ No newline at end of file
diff --git a/Widget/src/main/java/com/android/multiuser/widget/domain/UpdateUsersUseCase.kt b/Widget/src/main/java/com/android/multiuser/widget/domain/UpdateUsersUseCase.kt
deleted file mode 100644
index da2a868..0000000
--- a/Widget/src/main/java/com/android/multiuser/widget/domain/UpdateUsersUseCase.kt
+++ /dev/null
@@ -1,76 +0,0 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
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
-package com.android.multiuser.widget.domain
-
-import com.android.multiuser.widget.data.UserDao
-import com.android.multiuser.widget.data.model.User
-import kotlinx.coroutines.CoroutineDispatcher
-import kotlinx.coroutines.Dispatchers
-import kotlinx.coroutines.flow.flow
-import kotlinx.coroutines.flow.Flow
-import kotlinx.coroutines.flow.first
-import kotlinx.coroutines.withContext
-
-/**
- * Maps data from the repository to the local Room database.
- */
-class UpdateUsersUseCase(
-    private val userDao: UserDao,
-    private val dispatcher: CoroutineDispatcher = Dispatchers.Default,
-) {
-    suspend fun onUserNameChanged(user: User): Flow<Boolean> = withContext(dispatcher) {
-        return@withContext updateUser(user)
-    }
-
-    suspend fun onUserAvatarChanged(user: User): Flow<Boolean> = withContext(dispatcher) {
-        return@withContext updateUser(user)
-    }
-
-    suspend fun onUserIsAdminChanged(user: User): Flow<Boolean> = withContext(dispatcher) {
-        return@withContext updateUser(user)
-    }
-
-    suspend fun onUserAdded(user: User): Flow<Boolean> = withContext(dispatcher) {
-        return@withContext flow {
-            userDao.addUsers(user)
-            emit(true)
-        }
-    }
-
-    suspend fun onUserRemoved(user: User): Flow<Boolean> = withContext(dispatcher) {
-        return@withContext flow {
-            userDao.deleteUser(user)
-            emit(true)
-        }
-    }
-
-    suspend fun onUserSwitch(newCurrentUser: User): Flow<Boolean> = withContext(dispatcher) {
-        return@withContext flow {
-            var previousCurrentUser = userDao.getCurrentUser().first()
-            previousCurrentUser.isCurrentUser = false
-
-            userDao.updateUsers(previousCurrentUser, newCurrentUser)
-        }
-    }
-
-    private fun updateUser(user: User): Flow<Boolean> {
-        return flow {
-            userDao.updateUsers(user)
-            emit(true)
-        }
-    }
-}
diff --git a/Widget/src/main/java/com/android/multiuser/widget/domain/UserSwitchUseCase.kt b/Widget/src/main/java/com/android/multiuser/widget/domain/UserSwitchUseCase.kt
new file mode 100644
index 0000000..495cba6
--- /dev/null
+++ b/Widget/src/main/java/com/android/multiuser/widget/domain/UserSwitchUseCase.kt
@@ -0,0 +1,45 @@
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
+package com.android.multiuser.widget.domain
+
+import android.content.Intent
+
+import kotlinx.coroutines.CoroutineDispatcher
+import kotlinx.coroutines.Dispatchers
+import kotlinx.coroutines.withContext
+
+import com.android.multiuser.widget.data.IUsersRepository
+import com.android.multiuser.widget.data.IntentRepository
+import com.android.multiuser.widget.data.model.UserSwitchRestrictions
+
+/**
+ * Returns a dialog that is displayed when user switching is not restricted or unsuccessful.
+ */
+class UserSwitchUseCase(private val userId: Int,
+    private val usersRepo: IUsersRepository,
+    private val intentRepo: IntentRepository) {
+    operator fun invoke() : Intent? {
+        val restriction = usersRepo.checkUserSwitchRestrictions()
+        if (restriction != UserSwitchRestrictions.NONE) {
+            return intentRepo.getUserSwitchRestrictedIntent(restriction);
+        }
+        if (!usersRepo.switchToUser(userId)) {
+            return intentRepo.getUserSwitchRestrictedIntent(UserSwitchRestrictions.UNKNOWN);
+        }
+        return null
+    }
+}
diff --git a/Widget/src/main/java/com/android/multiuser/widget/repository/ResourceRepository.kt b/Widget/src/main/java/com/android/multiuser/widget/repository/ResourceRepository.kt
deleted file mode 100644
index b6ab9c9..0000000
--- a/Widget/src/main/java/com/android/multiuser/widget/repository/ResourceRepository.kt
+++ /dev/null
@@ -1,52 +0,0 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
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
-package com.android.multiuser.widget.repository
-
-import android.content.ComponentName
-import android.content.Intent
-import android.content.res.Resources
-import android.provider.Settings
-import com.android.multiuser.widget.R
-
-class ResourceRepository(val resources: Resources) {
-    class DialogViewModel(
-        val message: String,
-        val positiveButtonText: String? = null,
-        val negativeButtonText: String,
-        val actionIntent: Intent? = null
-    )
-
-    fun getSwitchFailed() = DialogViewModel(
-        message = resources.getString(R.string.widget_switch_failed_dialog_message),
-        negativeButtonText =
-            resources.getString(R.string.widget_switch_failed_dialog_dismiss_button_text),
-    )
-
-    fun getSwitchNotAllowed() = DialogViewModel(
-        message = resources.getString(R.string.widget_switch_not_allowed_dialog_message),
-        positiveButtonText =
-            resources.getString(R.string.widget_switch_not_allowed_dialog_settings_button_text),
-        negativeButtonText =
-            resources.getString(R.string.widget_switch_not_allowed_dialog_dismiss_button_text),
-        actionIntent = Intent(Settings.ACTION_USER_SETTINGS)
-            .setComponent(
-                ComponentName("com.android.settings",
-                    "com.android.settings.Settings\$UserSettingsActivity")
-            )
-            .setFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK),
-    )
-}
diff --git a/Widget/src/main/java/com/android/multiuser/widget/repository/UsersRepository.kt b/Widget/src/main/java/com/android/multiuser/widget/repository/UsersRepository.kt
deleted file mode 100644
index 10b0e4f..0000000
--- a/Widget/src/main/java/com/android/multiuser/widget/repository/UsersRepository.kt
+++ /dev/null
@@ -1,81 +0,0 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
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
-package com.android.multiuser.widget.repository
-
-import android.content.Context
-import android.content.ContextWrapper
-import android.content.pm.UserInfo
-import android.graphics.Bitmap
-import android.os.UserManager
-import com.android.internal.util.UserIcons
-import com.android.multiuser.widget.data.model.User
-import java.io.File
-import java.io.FileOutputStream
-import java.io.IOException
-import kotlin.collections.List
-
-class UsersRepository(private val userManager: UserManager?) {
-    fun getUsers(context: Context): List<User> {
-        if(userManager == null) {
-            // This ensures the error layout is shown in the UI.
-            return listOf()
-        }
-        var userInfoList = userManager.getAliveUsers().filter { it.isFull() }
-        return userInfoList.map { userInfo: UserInfo -> mapUserInfoToUser(userInfo, context) }
-    }
-
-    private fun mapUserInfoToUser(userInfo: UserInfo, context: Context): User {
-        // Get the user icon. If the user manager doesn't provide an icon,
-        // get the default icon and convert it to the appropriate size.
-        val userIcon = userManager?.getUserIcon(userInfo.id) ?: UserIcons.getDefaultUserIcon(
-            context.resources,
-            userInfo.id,
-            false
-        ).let { UserIcons.convertToBitmapAtUserIconSize(context.resources, it) }
-
-
-        return User(
-            id = userInfo.id,
-            name = userInfo.name ?: "",
-            creationTime = userInfo.creationTime,
-            iconPath = saveToInternalStorage(userIcon, userInfo.id, context),
-            isCurrentUser = (context.user.identifier == userInfo.id),
-            isAdmin = userManager?.isUserAdmin(userInfo.id) ?: false,
-        )
-    }
-
-    private fun saveToInternalStorage(bitmapImage: Bitmap, id: Int, context: Context): String {
-        val cw = ContextWrapper(context)
-        // path to /data/user/{id}/com.android.multiuser/app_imageDir
-        val directory: File = cw.getDir("imageDir", Context.MODE_PRIVATE)
-        val filePath = File(directory, "$id.png")
-        var fos: FileOutputStream? = null
-        try {
-            fos = FileOutputStream(filePath)
-            bitmapImage.compress(Bitmap.CompressFormat.PNG, /*quality= */100, fos)
-        } catch (e: Exception) {
-            e.printStackTrace()
-        } finally {
-            try {
-                fos?.close()
-            } catch (e: IOException) {
-                e.printStackTrace()
-            }
-        }
-        return filePath.absolutePath
-    }
-}
diff --git a/Widget/src/main/java/com/android/multiuser/widget/ui/DialogActivity.kt b/Widget/src/main/java/com/android/multiuser/widget/ui/DialogActivity.kt
new file mode 100644
index 0000000..08e2b8f
--- /dev/null
+++ b/Widget/src/main/java/com/android/multiuser/widget/ui/DialogActivity.kt
@@ -0,0 +1,67 @@
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
+package com.android.multiuser.widget.ui
+
+import android.app.Activity
+import android.content.Intent
+import android.os.Bundle
+import androidx.activity.ComponentActivity
+import androidx.activity.compose.setContent
+import androidx.compose.foundation.layout.fillMaxSize
+import androidx.compose.material3.Surface
+import androidx.compose.runtime.*
+import androidx.compose.ui.graphics.Color
+import androidx.compose.ui.Modifier
+import androidx.core.view.WindowCompat
+
+import com.android.compose.theme.PlatformTheme
+import com.android.multiuser.widget.domain.DialogUseCase
+
+/**
+ * Activity to display a dialog with a title, message, icon, and one or two buttons.
+ *
+ * This activity is launched when user switch fails or is disabled.
+ */
+class DialogActivity : ComponentActivity() {
+    override fun onCreate(savedInstanceState: Bundle?) {
+        super.onCreate(savedInstanceState)
+        // Make the activity transparent
+        WindowCompat.setDecorFitsSystemWindows(window, false)
+        // Transparent status bar
+        window.statusBarColor = Color.Transparent.hashCode()
+        // Transparent navigation bar (if applicable)
+        window.navigationBarColor = Color.Transparent.hashCode()
+        val dialogUseCase = DialogUseCase(intent, resources)
+
+        setContent {
+            PlatformTheme {
+                Surface(
+                    modifier = Modifier.fillMaxSize(),
+                    color = Color.Transparent // Important: Set the surface color to transparent
+                ) {
+                    DialogView(
+                        dialogUseCase(),
+                        { finish() },
+                        {
+                            it?.let { intent -> startActivity(intent) }
+                            finish()
+                        })
+                }
+            }
+        }
+    }
+}
diff --git a/Widget/src/main/java/com/android/multiuser/widget/ui/grid/UsersView.kt b/Widget/src/main/java/com/android/multiuser/widget/ui/grid/UsersView.kt
index 8918127..b79c986 100644
--- a/Widget/src/main/java/com/android/multiuser/widget/ui/grid/UsersView.kt
+++ b/Widget/src/main/java/com/android/multiuser/widget/ui/grid/UsersView.kt
@@ -16,7 +16,9 @@
 
 package com.android.multiuser.widget.ui.grid
 
+import androidx.compose.runtime.collectAsState
 import androidx.compose.runtime.Composable
+import androidx.compose.runtime.getValue
 import androidx.glance.LocalSize
 import androidx.glance.appwidget.lazy.GridCells
 import androidx.glance.appwidget.lazy.LazyVerticalGrid
@@ -28,7 +30,9 @@ import com.android.multiuser.widget.ui.grid.item.UserView
 import com.android.multiuser.widget.ui.util.GridItemModifierForIndex
 import com.android.multiuser.widget.ui.util.NumberOfColumns
 import com.android.multiuser.widget.ui.util.WidgetGlanceModifiers.VerticalGridBoxModifier
+import com.android.multiuser.widget.viewmodel.ActionViewModel
 import com.android.multiuser.widget.viewmodel.UsersViewModel
+import com.android.multiuser.widget.viewmodel.UserViewModel
 import kotlin.math.ceil
 
 @Composable
@@ -36,26 +40,26 @@ fun UsersView(model: UsersViewModel) {
     Box(
         modifier = VerticalGridBoxModifier()
     ) {
-        val users = model.users
-        val actionItems = model.actions
+        val items by model.data.collectAsState()
         val gridCells = NumberOfColumns(LocalSize.current)
-        val numRows = ceil((users.size + actionItems.size).toDouble() / gridCells).toInt()
+        val numRows = ceil((items.size).toDouble() / gridCells).toInt()
 
         LazyVerticalGrid(
             gridCells = GridCells.Fixed(gridCells),
             horizontalAlignment = Alignment.Start
         ) {
-            itemsIndexed(users) { index, user ->
-                UserView(
-                    viewModel = user,
-                    modifier = GridItemModifierForIndex(index, gridCells, numRows),
-                )
-            }
-            itemsIndexed(actionItems) { index, actionItem ->
-                ActionView(
-                    viewModel = actionItem,
-                    modifier = GridItemModifierForIndex(index + users.size, gridCells, numRows),
-                )
+            itemsIndexed(items) { index, item ->
+                if (item is UserViewModel) {
+                    UserView(
+                        viewModel = item,
+                        modifier = GridItemModifierForIndex(index, gridCells, numRows),
+                    )
+                } else if (item is ActionViewModel) {
+                    ActionView(
+                        viewModel = item,
+                        modifier = GridItemModifierForIndex(index, gridCells, numRows),
+                    )
+                }
             }
         }
     }
diff --git a/Widget/src/main/java/com/android/multiuser/widget/ui/grid/item/UserView.kt b/Widget/src/main/java/com/android/multiuser/widget/ui/grid/item/UserView.kt
index 7c16060..523794a 100644
--- a/Widget/src/main/java/com/android/multiuser/widget/ui/grid/item/UserView.kt
+++ b/Widget/src/main/java/com/android/multiuser/widget/ui/grid/item/UserView.kt
@@ -16,8 +16,12 @@
 
 package com.android.multiuser.widget.ui.grid.item
 
-import androidx.glance.action.clickable
+import android.graphics.Bitmap
+import androidx.compose.runtime.collectAsState
 import androidx.compose.runtime.Composable
+import androidx.compose.runtime.getValue
+import androidx.compose.runtime.rememberCoroutineScope
+import androidx.glance.action.clickable
 import androidx.glance.GlanceModifier
 import androidx.glance.Image
 import androidx.glance.ImageProvider
@@ -32,13 +36,14 @@ import androidx.glance.layout.Spacer
 import androidx.glance.layout.wrapContentHeight
 import androidx.glance.LocalContext
 import androidx.glance.text.Text
-import com.android.multiuser.widget.action.switchUsers
 import com.android.multiuser.widget.R
 import com.android.multiuser.widget.ui.util.readFromInternalStorage
 import com.android.multiuser.widget.ui.util.WidgetGlanceModifiers.UserBoxModifier
 import com.android.multiuser.widget.ui.util.WidgetGlanceModifiers.TrailingBottomModifier
 import com.android.multiuser.widget.ui.util.WidgetTextStyles
+import com.android.multiuser.widget.viewmodel.UiState
 import com.android.multiuser.widget.viewmodel.UserViewModel
+import kotlinx.coroutines.launch
 
 /**
  * Displays user data in the widget.
@@ -49,19 +54,29 @@ fun UserView (
     modifier: GlanceModifier,
 ) {
     val context = LocalContext.current
+    val bitmap by viewModel.bitmap.collectAsState()
+    val scope = rememberCoroutineScope()
+    val uiState by viewModel.uiState.collectAsState()
+    val alpha = if (viewModel.enabled) { 1.0f } else { 0.38f }
+    scope.launch {
+        if(uiState != UiState.Loading) {
+            viewModel.loadAvatar()
+        }
+    }
     Column(
         modifier = modifier,
         verticalAlignment = Alignment.CenterVertically,
         horizontalAlignment = Alignment.CenterHorizontally,
     ) {
         // Top
-        Box (modifier = UserBoxModifier(viewModel.isSelected)
-            .clickable{ switchUsers(viewModel.id, context) }
+        Box (modifier = UserBoxModifier(viewModel.isSelected, alpha)
+            .clickable{ viewModel.switch() { context.startActivity(it) } }
         ) {
             Image(
-                provider = readFromInternalStorage(viewModel.iconPath)?.let { ImageProvider(it) }
+                provider = bitmap?.let { ImageProvider(it) }
                     ?: ImageProvider(R.drawable.account_circle),
                 contentScale = ContentScale.Fit,
+                alpha = alpha,
                 contentDescription = viewModel.contentDescription,
                 modifier = GlanceModifier.fillMaxWidth().wrapContentHeight()
             )
diff --git a/Widget/src/main/java/com/android/multiuser/widget/ui/util/WidgetGlanceModifiers.kt b/Widget/src/main/java/com/android/multiuser/widget/ui/util/WidgetGlanceModifiers.kt
index 358d79d..d77f2d4 100644
--- a/Widget/src/main/java/com/android/multiuser/widget/ui/util/WidgetGlanceModifiers.kt
+++ b/Widget/src/main/java/com/android/multiuser/widget/ui/util/WidgetGlanceModifiers.kt
@@ -31,9 +31,9 @@ import com.android.multiuser.widget.R
 
 object WidgetGlanceModifiers {
     @Composable
-    fun UserBoxModifier (isSelected: Boolean): GlanceModifier {
+    fun UserBoxModifier (isSelected: Boolean, alpha: Float): GlanceModifier {
         return if(isSelected) {
-            SelectedUserBoxModifier()
+            SelectedUserBoxModifier(alpha)
         } else {
             DefaultUserBoxModifier()
         }
@@ -44,11 +44,12 @@ object WidgetGlanceModifiers {
         .width(ResourceDp(R.dimen.widget_grid_bottom_spacing))
 
     @Composable
-    fun SelectedUserBoxModifier() = GlanceModifier
+    fun SelectedUserBoxModifier(alpha: Float) = GlanceModifier
         .wrapContentSize()
         .padding(ResourceDp(R.dimen.widget_grid_content_padding))
         .background(
                 ImageProvider(R.drawable.current_user_border),
+                alpha = alpha,
                 colorFilter = ColorFilter.tint(GlanceTheme.colors.primary))
 
     @Composable
diff --git a/Widget/src/main/java/com/android/multiuser/widget/ui/view/DialogView.kt b/Widget/src/main/java/com/android/multiuser/widget/ui/view/DialogView.kt
new file mode 100644
index 0000000..5944f9b
--- /dev/null
+++ b/Widget/src/main/java/com/android/multiuser/widget/ui/view/DialogView.kt
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
+package com.android.multiuser.widget.ui
+
+import android.content.Intent
+import androidx.compose.foundation.Image
+import androidx.compose.material3.AlertDialog
+import androidx.compose.material3.Button
+import androidx.compose.material3.MaterialTheme
+import androidx.compose.material3.OutlinedButton
+import androidx.compose.material3.Text
+import androidx.compose.runtime.Composable
+import androidx.compose.ui.Modifier
+import androidx.compose.ui.graphics.ColorFilter
+import androidx.compose.ui.res.painterResource
+import androidx.compose.ui.res.stringResource
+import androidx.compose.ui.graphics.Color
+
+import com.android.multiuser.widget.R
+import com.android.multiuser.widget.viewmodel.DialogViewModel
+
+@Composable
+fun DialogView(dialogViewModel : DialogViewModel, onDismiss: () -> Unit, onConfirm: (intent: Intent?) -> Unit) {
+    AlertDialog(
+        onDismissRequest = { onDismiss() },
+        title = { Text(dialogViewModel.title) },
+        text = { Text(dialogViewModel.message) },
+        icon = {
+            Image(
+                painter = painterResource(id = R.drawable.lock),
+                contentDescription = stringResource(id = R.string.lock_icon_content_description),
+                colorFilter = ColorFilter.tint(MaterialTheme.colorScheme.primary)
+            )
+        },
+        confirmButton = {
+            dialogViewModel.positiveButtonText?.let {
+                Button(onClick = {
+                    onConfirm(dialogViewModel.actionIntent)
+                }) {
+                    Text(it)
+                }
+            }
+        },
+        dismissButton = {
+            OutlinedButton(onClick = { onDismiss() }) {
+                Text(stringResource(R.string.dialog_close_button_text))
+            }
+        }
+    )
+}
\ No newline at end of file
diff --git a/Widget/src/main/java/com/android/multiuser/widget/ui/view/layout/MultiuserWidgetLayout.kt b/Widget/src/main/java/com/android/multiuser/widget/ui/view/layout/MultiuserWidgetLayout.kt
index 750f4b6..25563c0 100644
--- a/Widget/src/main/java/com/android/multiuser/widget/ui/view/layout/MultiuserWidgetLayout.kt
+++ b/Widget/src/main/java/com/android/multiuser/widget/ui/view/layout/MultiuserWidgetLayout.kt
@@ -41,10 +41,6 @@ fun MultiuserWidgetLayout(
         horizontalPadding = ResourceDp(R.dimen.widget_grid_content_padding),
         modifier = GlanceModifier.padding(bottom = R.dimen.widget_grid_content_padding)
     ) {
-        if (model.users.isEmpty()) {
-            ErrorLayout()
-        } else {
-            UsersView(model)
-        }
+        UsersView(model)
     }
 }
diff --git a/Widget/src/main/java/com/android/multiuser/widget/viewmodel/DialogViewModel.kt b/Widget/src/main/java/com/android/multiuser/widget/viewmodel/DialogViewModel.kt
new file mode 100644
index 0000000..9b95efe
--- /dev/null
+++ b/Widget/src/main/java/com/android/multiuser/widget/viewmodel/DialogViewModel.kt
@@ -0,0 +1,26 @@
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
+package com.android.multiuser.widget.viewmodel
+
+import android.content.Intent
+
+class DialogViewModel(
+    val title: String,
+    val message: String,
+    val positiveButtonText: String? = null,
+    val actionIntent: Intent? = null
+)
\ No newline at end of file
diff --git a/Widget/src/main/java/com/android/multiuser/widget/viewmodel/UiState.kt b/Widget/src/main/java/com/android/multiuser/widget/viewmodel/UiState.kt
new file mode 100644
index 0000000..8e163da
--- /dev/null
+++ b/Widget/src/main/java/com/android/multiuser/widget/viewmodel/UiState.kt
@@ -0,0 +1,24 @@
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
+package com.android.multiuser.widget.viewmodel
+
+sealed interface UiState {
+    object Invalid : UiState
+    object Error : UiState
+    object Loading : UiState
+    object Success : UiState
+}
\ No newline at end of file
diff --git a/Widget/src/main/java/com/android/multiuser/widget/viewmodel/UserViewModel.kt b/Widget/src/main/java/com/android/multiuser/widget/viewmodel/UserViewModel.kt
index 2e20353..a4783e1 100644
--- a/Widget/src/main/java/com/android/multiuser/widget/viewmodel/UserViewModel.kt
+++ b/Widget/src/main/java/com/android/multiuser/widget/viewmodel/UserViewModel.kt
@@ -16,32 +16,64 @@
 
 package com.android.multiuser.widget.viewmodel
 
-data class UserViewModel(
-    val iconPath: String,
+import android.content.Intent
+import android.graphics.Bitmap
+import com.android.multiuser.widget.domain.LoadUserAvatarUseCase
+import com.android.multiuser.widget.domain.UserSwitchUseCase
+import kotlinx.coroutines.flow.MutableStateFlow
+import kotlinx.coroutines.flow.StateFlow
+import kotlinx.coroutines.flow.asStateFlow
+
+class UserViewModel(
     val id: Int,
     val name: String,
     override val contentDescription: String?,
-    val isSelected: Boolean
+    val isSelected: Boolean,
+    val enabled: Boolean,
+    private val loadAvatarUseCase: LoadUserAvatarUseCase,
+    private val userSwitchUseCase: UserSwitchUseCase
 ) : GridItemViewModel(name, contentDescription) {
+    private val _uiState = MutableStateFlow<UiState>(UiState.Success)
+    private val _bitmap = MutableStateFlow<Bitmap?>(null)
+    val uiState: StateFlow<UiState> = _uiState.asStateFlow()
+    val bitmap: StateFlow<Bitmap?> = _bitmap.asStateFlow()
+
     override fun equals(other: Any?): Boolean {
         if (this === other) return true
         if (javaClass != other?.javaClass) return false
 
         other as UserViewModel
 
-        return iconPath == other.iconPath &&
-            id == other.id &&
-            name == other.name &&
-            contentDescription == other.contentDescription &&
-            isSelected == other.isSelected
+        return bitmap.value == other.bitmap.value &&
+                id == other.id &&
+                name == other.name &&
+                contentDescription == other.contentDescription &&
+                isSelected == other.isSelected &&
+                enabled == other.enabled
     }
 
     override fun hashCode(): Int {
-        var result = iconPath.hashCode()
+        var result = bitmap.value.hashCode()
         result = 31 * result + id.hashCode()
         result = 31 * result + name.hashCode()
         result = 31 * result + contentDescription.hashCode()
         result = 31 * result + isSelected.hashCode()
+        result = 31 * result + enabled.hashCode()
         return result
     }
+
+    suspend fun loadAvatar() {
+        _uiState.value = UiState.Loading
+        _bitmap.value = loadAvatarUseCase()
+        _uiState.value = UiState.Success
+    }
+
+    //callback: (List<User>) -> Unit
+    fun switch(showError: (intent: Intent) -> Unit) {
+        userSwitchUseCase()?.let { showError(it) }
+    }
+
+    fun invalidate() {
+        _uiState.value = UiState.Invalid
+    }
 }
diff --git a/Widget/src/main/java/com/android/multiuser/widget/viewmodel/UsersViewModel.kt b/Widget/src/main/java/com/android/multiuser/widget/viewmodel/UsersViewModel.kt
index e6414c8..54643a9 100644
--- a/Widget/src/main/java/com/android/multiuser/widget/viewmodel/UsersViewModel.kt
+++ b/Widget/src/main/java/com/android/multiuser/widget/viewmodel/UsersViewModel.kt
@@ -16,12 +16,59 @@
 
 package com.android.multiuser.widget.viewmodel
 
-sealed interface StateViewModel {
-    object Error : StateViewModel
-    object Loading : StateViewModel
-}
+import android.util.Log
+import com.android.multiuser.widget.domain.ILoadUsersUseCase
+import java.lang.Exception
+import kotlinx.coroutines.flow.MutableStateFlow
+import kotlinx.coroutines.flow.StateFlow
+import kotlinx.coroutines.flow.asStateFlow
+
+class UsersViewModel(private val useCase: ILoadUsersUseCase) {
+    val data: StateFlow<List<GridItemViewModel>> = getData()
+    val uiState: StateFlow<UiState> = getState()
+
+    companion object {
+        private val _data = MutableStateFlow<List<GridItemViewModel>>(emptyList())
+        private val _uiState = MutableStateFlow<UiState>(UiState.Invalid)
+
+        fun setState(value: UiState) {
+            if(_uiState.value != value) {
+                _uiState.value = value
+            }
+        }
+        fun getData() = _data.asStateFlow()
+        fun setData(value: List<GridItemViewModel>) {
+            if (value != _data.value) {
+                _data.value = value
+            }
+        }
+
+        fun getState() = _uiState.asStateFlow()
 
-data class UsersViewModel(
-    val users: List<UserViewModel>,
-    val actions: List<ActionViewModel>,
-) : StateViewModel
+        fun invalidate() {
+            setState(UiState.Invalid)
+        }
+    }
+
+    suspend fun reload() {
+        if (uiState.value != UiState.Loading) {
+            setState(UiState.Loading)
+            try {
+                val newData = useCase()
+                if (newData != data.value) {
+                    setData(newData)
+                }
+                if (data.value.size == 0) {
+                    setState(UiState.Error)
+                } else {
+                    setState(UiState.Success)
+                }
+
+            } catch (exc: Exception) {
+                Log.e(this.javaClass.name, "Unspecified exception")
+                setState(UiState.Error)
+            }
+        }
+    }
+
+}
diff --git a/Widget/src/main/res/drawable/lock.xml b/Widget/src/main/res/drawable/lock.xml
new file mode 100644
index 0000000..6132d14
--- /dev/null
+++ b/Widget/src/main/res/drawable/lock.xml
@@ -0,0 +1,26 @@
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
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+    android:width="24dp"
+    android:height="24dp"
+    android:viewportWidth="960"
+    android:viewportHeight="960"
+    android:tint="?attr/colorControlNormal">
+  <path
+      android:fillColor="@android:color/white"
+      android:pathData="M240,880Q207,880 183.5,856.5Q160,833 160,800L160,400Q160,367 183.5,343.5Q207,320 240,320L280,320L280,240Q280,157 338.5,98.5Q397,40 480,40Q563,40 621.5,98.5Q680,157 680,240L680,320L720,320Q753,320 776.5,343.5Q800,367 800,400L800,800Q800,833 776.5,856.5Q753,880 720,880L240,880ZM240,800L720,800Q720,800 720,800Q720,800 720,800L720,400Q720,400 720,400Q720,400 720,400L240,400Q240,400 240,400Q240,400 240,400L240,800Q240,800 240,800Q240,800 240,800ZM480,680Q513,680 536.5,656.5Q560,633 560,600Q560,567 536.5,543.5Q513,520 480,520Q447,520 423.5,543.5Q400,567 400,600Q400,633 423.5,656.5Q447,680 480,680ZM360,320L600,320L600,240Q600,190 565,155Q530,120 480,120Q430,120 395,155Q360,190 360,240L360,320ZM240,800Q240,800 240,800Q240,800 240,800L240,400Q240,400 240,400Q240,400 240,400L240,400Q240,400 240,400Q240,400 240,400L240,800Q240,800 240,800Q240,800 240,800Z"/>
+</vector>
diff --git a/Widget/src/main/res/drawable/preview_layout_container.xml b/Widget/src/main/res/drawable/preview_layout_container.xml
new file mode 100644
index 0000000..4e84508
--- /dev/null
+++ b/Widget/src/main/res/drawable/preview_layout_container.xml
@@ -0,0 +1,21 @@
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
+<shape xmlns:android="http://schemas.android.com/apk/res/android">
+    <solid android:color="@color/widgetBackground"/>
+    <corners android:radius="16dp"/>
+</shape>
diff --git a/Widget/src/main/res/drawable/preview_user_avatar_1.png b/Widget/src/main/res/drawable/preview_user_avatar_1.png
new file mode 100644
index 0000000..bed2877
Binary files /dev/null and b/Widget/src/main/res/drawable/preview_user_avatar_1.png differ
diff --git a/Widget/src/main/res/drawable/preview_user_avatar_2.png b/Widget/src/main/res/drawable/preview_user_avatar_2.png
new file mode 100644
index 0000000..1a0d47d
Binary files /dev/null and b/Widget/src/main/res/drawable/preview_user_avatar_2.png differ
diff --git a/Widget/src/main/res/drawable/rounded_background.xml b/Widget/src/main/res/drawable/rounded_background.xml
new file mode 100644
index 0000000..1f9a23c
--- /dev/null
+++ b/Widget/src/main/res/drawable/rounded_background.xml
@@ -0,0 +1,21 @@
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
+<shape xmlns:android="http://schemas.android.com/apk/res/android">
+    <solid android:color="@android:color/transparent"/>
+    <corners android:radius="64dp"/>
+</shape>
\ No newline at end of file
diff --git a/Widget/src/main/res/layout/multiuser_widget_preview_layout.xml b/Widget/src/main/res/layout/multiuser_widget_preview_layout.xml
new file mode 100644
index 0000000..9a48ab2
--- /dev/null
+++ b/Widget/src/main/res/layout/multiuser_widget_preview_layout.xml
@@ -0,0 +1,132 @@
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
+<RelativeLayout
+    xmlns:android="http://schemas.android.com/apk/res/android"
+    android:layout_width="wrap_content"
+    android:layout_height="wrap_content"
+    android:orientation="vertical"
+    android:padding="8dp"
+    android:background="@drawable/preview_layout_container">
+
+    <!-- Container for the icon and title in the upper-left corner -->
+    <RelativeLayout
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        android:orientation="horizontal"
+        android:layout_alignParentTop="true"
+        android:layout_margin="8dp">
+
+        <ImageView
+            android:id="@+id/users_icon"
+            android:layout_width="24dp"
+            android:layout_height="24dp"
+            android:src="@drawable/users_icon"
+            android:tint="@color/onSurface"
+            android:contentDescription="@string/preview_users_icon_content_description"/>
+
+        <!-- Title -->
+        <TextView
+            android:id="@+id/widget_title"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:layout_marginStart="8dp"
+            android:text="@string/multiuser_widget_title"
+            android:layout_toEndOf="@id/users_icon"
+            android:textSize="16sp"
+            android:textColor="@color/onSurface"/>
+
+
+        <ImageView
+            android:id="@+id/settings_icon"
+            android:layout_width="24dp"
+            android:layout_height="24dp"
+            android:src="@drawable/settings"
+            android:tint="@color/onSurface"
+            android:contentDescription="@string/preview_settings_icon_content_description"
+            android:layout_alignParentEnd="true"/>
+    </RelativeLayout>
+
+
+    <!-- Container for two side-by-side rounded images with titles -->
+    <LinearLayout
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        android:layout_alignParentBottom="true"
+        android:orientation="horizontal"
+        android:gravity="center"
+        android:layout_below="@id/widget_title"
+        android:layout_centerHorizontal="true">
+
+        <!-- First image with a border and title in a vertical layout -->
+        <LinearLayout
+            android:layout_width="0dp"
+            android:layout_weight="1"
+            android:layout_height="wrap_content"
+            android:orientation="vertical"
+            android:gravity="center"
+            android:layout_marginEnd="16dp">
+
+            <!-- First rounded image with an outline -->
+            <ImageView
+                android:id="@+id/first_image"
+                style="@style/CircularImageViewStyle"
+                android:src="@drawable/preview_user_avatar_1"
+                android:background="@drawable/rounded_background"
+                android:contentDescription="@string/preview_first_avatar_content_description"/>
+
+            <!-- Title for the first image -->
+            <TextView
+                android:id="@+id/first_user_name"
+                android:layout_width="wrap_content"
+                android:layout_height="wrap_content"
+                android:layout_marginTop="8dp"
+                android:text="@string/preview_first_user_name"
+                android:textSize="14sp"
+                android:textColor="@color/onSurface"
+                android:gravity="center"/>
+        </LinearLayout>
+
+        <!-- Second image and title in a vertical layout -->
+        <LinearLayout
+            android:layout_width="0dp"
+            android:layout_height="match_parent"
+            android:layout_weight="1"
+            android:orientation="vertical"
+            android:gravity="center">
+
+            <!-- Second rounded image (without outline) -->
+            <ImageView
+                android:id="@+id/second_image"
+                style="@style/CircularImageViewStyle"
+                android:src="@drawable/preview_user_avatar_2"
+                android:contentDescription="@string/preview_second_avatar_content_description"/>
+
+            <!-- Title for the second image -->
+            <TextView
+                android:id="@+id/second_user_name"
+                android:layout_width="wrap_content"
+                android:layout_height="wrap_content"
+                android:layout_marginTop="8dp"
+                android:text="@string/preview_second_user_name"
+                android:textSize="14sp"
+                android:textColor="@color/onSurface"
+                android:gravity="center"/>
+        </LinearLayout>
+    </LinearLayout>
+
+</RelativeLayout>
diff --git a/Widget/src/main/res/values/colors.xml b/Widget/src/main/res/values/colors.xml
new file mode 100644
index 0000000..afad343
--- /dev/null
+++ b/Widget/src/main/res/values/colors.xml
@@ -0,0 +1,24 @@
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
+<resources xmlns:androidprv="http://schemas.android.com/apk/prv/res/android">
+    <!-- Color definitions used just for the XML layout preview. -->
+    <color name="onPrimary">@androidprv:color/materialColorOnPrimary</color>
+    <color name="onSurface">@androidprv:color/materialColorOnSurface</color>
+    <color name="widgetBackground">@androidprv:color/materialColorSecondaryContainer</color>
+    <color name="primary">@androidprv:color/materialColorPrimary</color>
+</resources>
\ No newline at end of file
diff --git a/Widget/src/main/res/values/integers.xml b/Widget/src/main/res/values/integers.xml
index 14cf250..f863e68 100644
--- a/Widget/src/main/res/values/integers.xml
+++ b/Widget/src/main/res/values/integers.xml
@@ -22,6 +22,6 @@
     <integer name="widget_update_period_millis">86400000</integer>
     <!-- Target cell height and width are the default dimensions the widget has in the widget
     picker. -->
-    <integer name="widget_target_cell_height">3</integer>
+    <integer name="widget_target_cell_height">2</integer>
     <integer name="widget_target_cell_width">2</integer>
 </resources>
diff --git a/Widget/src/main/res/values/strings.xml b/Widget/src/main/res/values/strings.xml
index 2b75ea3..6277b2a 100644
--- a/Widget/src/main/res/values/strings.xml
+++ b/Widget/src/main/res/values/strings.xml
@@ -16,18 +16,79 @@
  * limitations under the License.
  */
  -->
-<!-- TODO: b/371006714: These strings are user visible and need to be approved. -->
 <resources>
-  <string name="multiuser_app_name" translation_description="The Users app name displayed in the widget library. [CHAR_LIMIT=NONE]">Users</string>
-  <string name="add_user_button_title" translation_description="Title for the button that allows adding a user. [CHAR_LIMIT=NONE]">Add user</string>
-  <string name="add_user_button_content_description" translation_description="Content description for the button that allows adding a user. [CHAR_LIMIT=NONE]">Add user</string>
-  <string name="multiuser_widget_name" translation_description="The widget name displayed in the widget picker. [CHAR_LIMIT=NONE]">Multiuser widget</string>
-  <string name="multiuser_widget_title" translation_description="The text displayed in the title bar. [CHAR_LIMIT=NONE]">Switch user</string>
-  <string name="multiuser_widget_error_message" translation_description="The text displayed when user data doesn't load. [CHAR_LIMIT=NONE]">Failed to load widget.</string>
-  <string name="widget_settings_button_content_description" translation_description="Text describing the action of the Settings button on the widget. Used by accessibility services. {CHAR_LIMIT=NONE}">Go to Users Settings.</string>
-  <string name="widget_switch_failed_dialog_dismiss_button_text" translation_description="Text that appears as a negative button in an alert dialog when user tries to switch and the switch fails. Clicking on this text dismisses the dialog. {CHAR_LIMIT=NONE}">Dismiss</string>
-  <string name="widget_switch_failed_dialog_message" translation_description="Text that appears in an alert dialog when user tries to switch and the switch fails. {CHAR_LIMIT=NONE}">User switch could not be performed.</string>
-  <string name="widget_switch_not_allowed_dialog_dismiss_button_text" translation_description="Text that appears as a negative button in an alert dialog when user tries to switch but switching is disallowed. Clicking on this text dismisses the dialog. {CHAR_LIMIT=NONE}">Dismiss</string>
-  <string name="widget_switch_not_allowed_dialog_message" translation_description="Text that appears in an alert dialog when user tries to switch but switching is disallowed. {CHAR_LIMIT=NONE}">User switch is not allowed.</string>
-  <string name="widget_switch_not_allowed_dialog_settings_button_text" translation_description="Text that appears as a positive button in an alert dialog when user tries to switch but switching is disallowed. Clicking on this text leads to User Settings. {CHAR_LIMIT=NONE}">Settings</string>
-</resources>
+  <string translation_description="The Users app name displayed in the widget library. [CHAR_LIMIT=NONE]"
+      name="multiuser_app_name">Users</string>
+
+  <string translation_description="Title for the button that allows adding a user. [CHAR_LIMIT=NONE]"
+      name="add_user_button_title">Add user</string>
+
+  <string translation_description="Content description for the button that allows adding a user. [CHAR_LIMIT=NONE]"
+      name="add_user_button_content_description">Add user</string>
+
+  <string translation_description="The widget name displayed in the widget picker. [CHAR_LIMIT=NONE]"
+      name="multiuser_widget_name">Switch users</string>
+
+  <string translation_description="The widget description displayed in the widget picker. [CHAR_LIMIT=NONE]"
+      name="multiuser_widget_description">Quickly switch users</string>
+
+  <string translation_description="The text displayed in the title bar. [CHAR_LIMIT=NONE]"
+      name="multiuser_widget_title">Switch user</string>
+
+  <string translation_description="The text displayed when user data doesn't load. [CHAR_LIMIT=NONE]"
+      name="multiuser_widget_error_message">Failed to load widget.</string>
+
+  <string translation_description="Text describing the action of the Settings button on the widget. Used by accessibility services. {CHAR_LIMIT=NONE}"
+      name="widget_settings_button_content_description">Go to Users Settings.</string>
+
+  <string translation_description="Generic dialog close button text {CHAR_LIMIT=25}"
+      name="dialog_close_button_text">Close</string>
+
+  <string translation_description="Title that appears when user switch is restricted by work policy {CHAR_LIMIT=NONE}"
+      name="widget_switch_work_restriction_dialog_title">Blocked by work policy</string>
+
+  <string translation_description="Message that appears when user switch is restricted by work policy {CHAR_LIMIT=NONE}"
+      name="widget_switch_work_restriction_dialog_message">Your organization doesn’t allow you to change users. For more info, contact your IT admin.</string>
+
+  <string translation_description="Title that appears in an alert dialog when user tries to switch and the switch fails. {CHAR_LIMIT=NONE}"
+      name="widget_switch_failed_dialog_title">Can’t switch user</string>
+
+  <string translation_description="Message that appears in an alert dialog when user tries to switch and the switch fails. {CHAR_LIMIT=NONE}"
+      name="widget_switch_failed_dialog_message">Something went wrong.</string>
+
+  <string translation_description="Title that appears in an alert dialog when user tries to switch but switching is disallowed. {CHAR_LIMIT=NONE}"
+      name="widget_switch_not_allowed_dialog_title">Can’t switch user</string>
+
+  <string translation_description="Message that appears in an alert dialog when user tries to switch but switching is disallowed. {CHAR_LIMIT=NONE}"
+      name="widget_switch_not_allowed_dialog_message">You can’t switch user during a call</string>
+
+  <string translation_description="Title that appears in an alert dialog when user tries to switch but switching is disabled in settings. {CHAR_LIMIT=NONE}"
+      name="widget_switch_disabled_dialog_title">Can’t switch user</string>
+
+  <string translation_description="Message that appears in an alert dialog when user tries to switch but switching is disabled in settings. {CHAR_LIMIT=NONE}"
+      name="widget_switch_disabled_dialog_message">Allow user switching in Settings then try again</string>
+
+  <string translation_description="Text that appears as a positive button in an alert dialog when user tries to switch but switching is disallowed. Clicking on this text leads to User Settings. {CHAR_LIMIT=NONE}"
+      name="widget_switch_disabled_dialog_open_settings_button">Settings</string>
+
+  <string translation_description="The name of the first user in the multiuser widget preview displayed in the widget picker. {CHAR_LIMIT=NONE}"
+      name="preview_first_user_name">Brenda</string>
+
+  <string translation_description="The name of the second user in the multiuser widget preview displayed in the widget picker. {CHAR_LIMIT=NONE}"
+      name="preview_second_user_name">Elia</string>
+
+  <string translation_description="Content description for the first user's avatar in the multiuser widget preview displayed in the widget picker. {CHAR_LIMIT=NONE}"
+      name="preview_first_avatar_content_description">Picture of Brenda</string>
+
+  <string translation_description="Content description for the Second user's avatar in the multiuser widget preview displayed in the widget picker. {CHAR_LIMIT=NONE}"
+      name="preview_second_avatar_content_description">Picture of Elia</string>
+
+  <string translation_description="Content description for the users icon. {CHAR_LIMIT=NONE}"
+      name="preview_users_icon_content_description">Users icon</string>
+
+  <string translation_description="Content description for the settings icon that opens users settings page. {CHAR_LIMIT=NONE}"
+      name="preview_settings_icon_content_description">Settings icon - select to manage users</string>
+
+  <string translation_description="Content description to lock icon visible on dialog alert. {CHAR_LIMIT=NONE}"
+      name="lock_icon_content_description">Lock icon</string>
+</resources>
\ No newline at end of file
diff --git a/Widget/src/main/res/values/styles.xml b/Widget/src/main/res/values/styles.xml
index ddc88d3..49ace96 100644
--- a/Widget/src/main/res/values/styles.xml
+++ b/Widget/src/main/res/values/styles.xml
@@ -19,4 +19,15 @@
         <item name="android:windowIsTranslucent">true</item>
         <item name="android:windowContentOverlay">@null</item>
     </style>
+
+    <style name="Theme.MultiuserWidget" parent="android:Theme.Material.Light.NoActionBar">
+    </style>
+
+    <style name="CircularImageViewStyle">
+        <item name="android:layout_width">128dp</item>
+        <item name="android:layout_height">128dp</item>
+        <item name="android:scaleType">centerCrop</item>
+        <item name="android:background">@drawable/rounded_background</item>
+        <item name="android:clipToOutline">true</item>
+    </style>
 </resources>
diff --git a/Widget/src/main/res/xml/multiuser_widget_info.xml b/Widget/src/main/res/xml/multiuser_widget_info.xml
index a0a9798..9ff13be 100644
--- a/Widget/src/main/res/xml/multiuser_widget_info.xml
+++ b/Widget/src/main/res/xml/multiuser_widget_info.xml
@@ -17,7 +17,8 @@
  */
  -->
 <appwidget-provider xmlns:android="http://schemas.android.com/apk/res/android"
-    android:description="@string/multiuser_widget_name"
+    android:label="@string/multiuser_widget_name"
+    android:description="@string/multiuser_widget_description"
     android:minHeight="@dimen/widget_min_height"
     android:minWidth="@dimen/widget_min_width"
     android:targetCellHeight="@integer/widget_target_cell_height"
@@ -28,4 +29,5 @@
     android:updatePeriodMillis="@integer/widget_update_period_millis"
     android:widgetCategory="home_screen|keyguard"
     android:widgetFeatures="reconfigurable|configuration_optional"
-    android:initialLayout="@layout/glance_default_loading_layout"/>
+    android:initialLayout="@layout/glance_default_loading_layout"
+    android:previewLayout="@layout/multiuser_widget_preview_layout"/>
diff --git a/Widget/src/tests/ui/AndroidTest.xml b/Widget/src/tests/ui/AndroidTest.xml
new file mode 100644
index 0000000..41744ce
--- /dev/null
+++ b/Widget/src/tests/ui/AndroidTest.xml
@@ -0,0 +1,32 @@
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
+<configuration description="Runs Multiuser Widget UI Test Cases.">
+    <option name="test-suite-tag" value="apct" />
+    <option name="test-suite-tag" value="apct-instrumentation" />
+    <target_preparer class="com.android.tradefed.targetprep.suite.SuiteApkInstaller">
+        <option name="cleanup-apks" value="true" />
+        <option name="test-file-name" value="MultiuserUiTests.apk" />
+        <option name="aapt-version" value="AAPT2" />
+    </target_preparer>
+
+    <option name="test-tag" value="MultiuserWidgetUiTests" />
+    <test class="com.android.tradefed.testtype.AndroidJUnitTest" >
+        <option name="package" value="com.android.multiuser.widget.ui.tests" />
+        <option name="runner" value="androidx.test.runner.AndroidJUnitRunner" />
+        <option name="hidden-api-checks" value="false"/>
+    </test>
+</configuration>
diff --git a/Widget/src/tests/ui/DialogViewTest.kt b/Widget/src/tests/ui/DialogViewTest.kt
new file mode 100644
index 0000000..7f587fe
--- /dev/null
+++ b/Widget/src/tests/ui/DialogViewTest.kt
@@ -0,0 +1,162 @@
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
+package com.android.multiuser.widget.ui.tests
+
+import androidx.activity.ComponentActivity
+import androidx.compose.ui.test.assertCountEquals
+import androidx.compose.ui.test.onAllNodesWithText
+import androidx.compose.ui.test.onNodeWithText
+import androidx.compose.ui.test.performClick
+import androidx.compose.ui.test.junit4.createAndroidComposeRule
+import androidx.test.platform.app.InstrumentationRegistry;
+import androidx.test.ext.junit.runners.AndroidJUnit4
+
+import org.junit.Rule
+import org.junit.Test
+import org.junit.runner.RunWith
+import org.junit.Assert.assertEquals
+import org.junit.Assert.assertFalse
+import org.junit.Assert.assertTrue
+import org.junit.Assert.assertNull
+import org.junit.Assert.assertNotNull
+
+import android.content.Context;
+import android.content.Intent;
+
+import com.android.multiuser.widget.data.IntentRepository
+import com.android.multiuser.widget.data.model.UserSwitchRestrictions
+import com.android.multiuser.widget.domain.DialogUseCase
+import com.android.multiuser.widget.ui.DialogView
+
+@RunWith(AndroidJUnit4::class)
+class DialogViewTest {
+    @get:Rule val composeTestRule = createAndroidComposeRule<ComponentActivity>()
+
+    @Test
+    fun testSwitchFailedDialog() {
+        val context = InstrumentationRegistry.getInstrumentation().getTargetContext()
+        val intentRepository = IntentRepository(context.resources)
+        val intent = intentRepository.getUserSwitchRestrictedIntent(UserSwitchRestrictions.UNKNOWN)
+        val dialogUseCase = DialogUseCase(intent, context.resources)
+        val model = dialogUseCase()
+        var dismissed = false
+        var actionIntent: Intent? = null
+        composeTestRule.setContent {
+            DialogView(model, { dismissed = true }, { actionIntent = it })
+        }
+        val title = context.getString(R.string.widget_switch_failed_dialog_title)
+        val message = context.getString(R.string.widget_switch_failed_dialog_message)
+        val closeButton = context.getString(R.string.dialog_close_button_text)
+        val actionButton = context.getString(R.string.widget_switch_disabled_dialog_open_settings_button)
+        assertEquals(model.title, title)
+        composeTestRule.onAllNodesWithText(title).assertCountEquals(1)
+        assertEquals(model.message, message)
+        composeTestRule.onAllNodesWithText(message).assertCountEquals(1)
+        composeTestRule.onAllNodesWithText(closeButton).assertCountEquals(1)
+        composeTestRule.onAllNodesWithText(actionButton).assertCountEquals(0)
+        assertFalse(dismissed)
+        composeTestRule.onNodeWithText(closeButton).performClick()
+        assertTrue(dismissed)
+    }
+
+    @Test
+    fun testSwitchDisabledByUser() {
+        val context = InstrumentationRegistry.getInstrumentation().getTargetContext()
+        val intentRepository = IntentRepository(context.resources)
+        val intent = intentRepository.getUserSwitchRestrictedIntent(UserSwitchRestrictions.DISABLED)
+        val dialogUseCase = DialogUseCase(intent, context.resources)
+        val model = dialogUseCase()
+        var dismissed = false
+        var actionIntent: Intent? = null
+        composeTestRule.setContent {
+            DialogView(model, { dismissed = true }, { actionIntent = it })
+        }
+        val title: String = context.getString(R.string.widget_switch_disabled_dialog_title)
+        val message: String = context.getString(R.string.widget_switch_disabled_dialog_message)
+        val closeButton: String = context.getString(R.string.dialog_close_button_text)
+        val actionButton: String = context.getString(R.string.widget_switch_disabled_dialog_open_settings_button)
+
+        assertEquals(model.title, title)
+        composeTestRule.onAllNodesWithText(title).assertCountEquals(1)
+        assertEquals(model.message, message)
+        composeTestRule.onAllNodesWithText(message).assertCountEquals(1)
+        composeTestRule.onAllNodesWithText(closeButton).assertCountEquals(1)
+        composeTestRule.onAllNodesWithText(actionButton).assertCountEquals(1)
+        assertFalse(dismissed)
+        composeTestRule.onNodeWithText(closeButton).performClick()
+        assertTrue(dismissed)
+        assertNull(actionIntent)
+        composeTestRule.onNodeWithText(actionButton).performClick()
+        assertNotNull(actionIntent)
+    }
+
+
+    @Test
+    fun testSwitchDisabledByWorkPolicy() {
+        val context = InstrumentationRegistry.getInstrumentation().getTargetContext()
+        val intentRepository = IntentRepository(context.resources)
+        val intent = intentRepository.getUserSwitchRestrictedIntent(UserSwitchRestrictions.WORK_POLICY)
+        val dialogUseCase = DialogUseCase(intent, context.resources)
+        val model = dialogUseCase()
+        var dismissed = false
+        var actionIntent: Intent? = null
+        composeTestRule.setContent {
+            DialogView(model, { dismissed = true }, { actionIntent = it })
+        }
+        val title: String = context.getString(R.string.widget_switch_work_restriction_dialog_title)
+        val message: String = context.getString(R.string.widget_switch_work_restriction_dialog_message)
+        val closeButton: String = context.getString(R.string.dialog_close_button_text)
+        val actionButton: String = context.getString(R.string.widget_switch_disabled_dialog_open_settings_button)
+
+        assertEquals(model.title, title)
+        composeTestRule.onAllNodesWithText(title).assertCountEquals(1)
+        assertEquals(model.message, message)
+        composeTestRule.onAllNodesWithText(message).assertCountEquals(1)
+        composeTestRule.onAllNodesWithText(closeButton).assertCountEquals(1)
+        composeTestRule.onAllNodesWithText(actionButton).assertCountEquals(0)
+        assertFalse(dismissed)
+        composeTestRule.onNodeWithText(closeButton).performClick()
+        assertTrue(dismissed)
+    }
+
+    @Test
+    fun testSwitchDisabledNotAllowedOnCall() {
+        val context = InstrumentationRegistry.getInstrumentation().getTargetContext()
+        val intentRepository = IntentRepository(context.resources)
+        val intent = intentRepository.getUserSwitchRestrictedIntent(UserSwitchRestrictions.ONCALL_OR_LOCKED)
+        val dialogUseCase = DialogUseCase(intent, context.resources)
+        val model = dialogUseCase()
+        var dismissed = false
+        var actionIntent: Intent? = null
+        composeTestRule.setContent {
+            DialogView(model, { dismissed = true }, { actionIntent = it })
+        }
+        val title: String = context.getString(R.string.widget_switch_not_allowed_dialog_title)
+        val message: String = context.getString(R.string.widget_switch_not_allowed_dialog_message)
+        val closeButton: String = context.getString(R.string.dialog_close_button_text)
+        val actionButton: String = context.getString(R.string.widget_switch_disabled_dialog_open_settings_button)
+
+        assertEquals(model.title, title)
+        composeTestRule.onAllNodesWithText(title).assertCountEquals(1)
+        assertEquals(model.message, message)
+        composeTestRule.onAllNodesWithText(message).assertCountEquals(1)
+        composeTestRule.onAllNodesWithText(closeButton).assertCountEquals(1)
+        composeTestRule.onAllNodesWithText(actionButton).assertCountEquals(0)
+        assertFalse(dismissed)
+        composeTestRule.onNodeWithText(closeButton).performClick()
+        assertTrue(dismissed)
+    }
+}
diff --git a/Widget/src/tests/unit/DialogUseCaseTest.kt b/Widget/src/tests/unit/DialogUseCaseTest.kt
new file mode 100644
index 0000000..9c4a3ae
--- /dev/null
+++ b/Widget/src/tests/unit/DialogUseCaseTest.kt
@@ -0,0 +1,129 @@
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
+package com.android.multiuser.widget.ui.tests
+
+import android.content.Context;
+import android.content.Intent;
+
+import androidx.test.platform.app.InstrumentationRegistry;
+import androidx.test.ext.junit.runners.AndroidJUnit4
+
+import com.android.multiuser.widget.data.IntentRepository
+import com.android.multiuser.widget.data.model.UserSwitchRestrictions
+import com.android.multiuser.widget.domain.DialogUseCase
+import com.android.multiuser.widget.domain.UserSwitchUseCase
+import com.android.multiuser.widget.R
+
+import org.junit.Rule
+import org.junit.Test
+import org.junit.runner.RunWith
+import org.junit.Assert.assertEquals
+import org.junit.Assert.assertNull
+import org.junit.Assert.assertNotNull
+
+@RunWith(AndroidJUnit4::class)
+class DialogUseCaseTest {
+
+    @Test
+    fun testSwitchSucceeded() {
+        val context = InstrumentationRegistry.getInstrumentation().getTargetContext()
+        val intentRepository = IntentRepository(context.resources)
+        val userRepository = FakeUserRepository()
+        userRepository.switchSucceeded = true
+        val userSwitchUseCase = UserSwitchUseCase(11, userRepository, intentRepository)
+        val intent = userSwitchUseCase()
+        assertNull(intent)
+    }
+
+    @Test
+    fun testSwitchFailed() {
+        val context = InstrumentationRegistry.getInstrumentation().getTargetContext()
+        val intentRepository = IntentRepository(context.resources)
+        val userRepository = FakeUserRepository()
+        userRepository.switchSucceeded = false
+        val userSwitchUseCase = UserSwitchUseCase(11, userRepository, intentRepository)
+        val intent = userSwitchUseCase()
+        assertNotNull(intent)
+        val dialogUseCase = DialogUseCase(intent!!, context.resources)
+        val model = dialogUseCase()
+        val title: String = context.getString(R.string.widget_switch_failed_dialog_title)
+        val message: String = context.getString(R.string.widget_switch_failed_dialog_message)
+        assertEquals(model.title, title)
+        assertEquals(model.message, message)
+        assertNull(model.positiveButtonText)
+        assertNull(model.actionIntent)
+    }
+
+    @Test
+    fun testSwitchDisabledByUser() {
+        val context = InstrumentationRegistry.getInstrumentation().getTargetContext()
+        val intentRepository = IntentRepository(context.resources)
+        val userRepository = FakeUserRepository()
+        userRepository.userRestrictions = UserSwitchRestrictions.DISABLED
+        val userSwitchUseCase = UserSwitchUseCase(11, userRepository, intentRepository)
+        val intent = userSwitchUseCase()
+        assertNotNull(intent)
+        val dialogUseCase = DialogUseCase(intent!!, context.resources)
+        val model = dialogUseCase()
+        val title: String = context.getString(R.string.widget_switch_disabled_dialog_title)
+        val message: String = context.getString(R.string.widget_switch_disabled_dialog_message)
+        val actionButton: String = context.getString(R.string.widget_switch_disabled_dialog_open_settings_button)
+        assertEquals(model.title, title)
+        assertEquals(model.message, message)
+        assertEquals(model.positiveButtonText, actionButton)
+        assertNotNull(model.actionIntent)
+    }
+
+
+    @Test
+    fun testSwitchDisabledByWorkPolicy() {
+        val context = InstrumentationRegistry.getInstrumentation().getTargetContext()
+        val intentRepository = IntentRepository(context.resources)
+        val userRepository = FakeUserRepository()
+        userRepository.userRestrictions = UserSwitchRestrictions.WORK_POLICY
+        val userSwitchUseCase = UserSwitchUseCase(11, userRepository, intentRepository)
+        val intent = userSwitchUseCase()
+        assertNotNull(intent)
+        val dialogUseCase = DialogUseCase(intent!!, context.resources)
+        val model = dialogUseCase()
+        val title: String = context.getString(R.string.widget_switch_work_restriction_dialog_title)
+        val message: String = context.getString(R.string.widget_switch_work_restriction_dialog_message)
+        assertEquals(model.title, title)
+        assertEquals(model.message, message)
+        assertNull(model.positiveButtonText)
+        assertNull(model.actionIntent)
+    }
+
+    @Test
+    fun testSwitchDisabledNotAllowedOnCall() {
+        val context = InstrumentationRegistry.getInstrumentation().getTargetContext()
+        val intentRepository = IntentRepository(context.resources)
+        val userRepository = FakeUserRepository()
+        userRepository.userRestrictions = UserSwitchRestrictions.ONCALL_OR_LOCKED
+        val userSwitchUseCase = UserSwitchUseCase(11, userRepository, intentRepository)
+        val intent = userSwitchUseCase()
+        assertNotNull(intent)
+        val dialogUseCase = DialogUseCase(intent!!, context.resources)
+        val model = dialogUseCase()
+        val title: String = context.getString(R.string.widget_switch_not_allowed_dialog_title)
+        val message: String = context.getString(R.string.widget_switch_not_allowed_dialog_message)
+        assertEquals(model.title, title)
+        assertEquals(model.message, message)
+        assertNull(model.positiveButtonText)
+        assertNull(model.actionIntent)
+    }
+}
diff --git a/Widget/src/tests/unit/FakeUserRepository.kt b/Widget/src/tests/unit/FakeUserRepository.kt
new file mode 100644
index 0000000..d2ba758
--- /dev/null
+++ b/Widget/src/tests/unit/FakeUserRepository.kt
@@ -0,0 +1,40 @@
+package com.android.multiuser.widget.ui.tests
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
+import com.android.multiuser.widget.data.IUsersRepository
+import com.android.multiuser.widget.data.model.User
+import com.android.multiuser.widget.data.model.UserSwitchRestrictions
+import com.android.multiuser.widget.R
+
+import kotlin.collections.List
+
+/**
+ * Fake User Repository so we don't have to mock UserManager
+ */
+class FakeUserRepository : IUsersRepository {
+    var users = listOf<User>( User(  10, "main",  0,  true,  true, true ),
+        User(  11, "secondary",  1,  false,  true, true ))
+    var currentUserAdmin = true
+    var userRestrictions = UserSwitchRestrictions.NONE
+    var switchSucceeded = true
+
+    override suspend fun getUsers() = users
+    override suspend fun disableSwitchUsers() = userRestrictions != UserSwitchRestrictions.NONE
+    override fun isCurrentUserAdmin() = currentUserAdmin
+    override fun checkUserSwitchRestrictions() = userRestrictions
+    override fun switchToUser(userId: Int) = switchSucceeded
+}
\ No newline at end of file
diff --git a/Widget/src/tests/unit/java/com/android/multiuser/widget/tests/unit/data/UserDaoTest.kt b/Widget/src/tests/unit/java/com/android/multiuser/widget/tests/unit/data/UserDaoTest.kt
deleted file mode 100644
index 1ad0c8c..0000000
--- a/Widget/src/tests/unit/java/com/android/multiuser/widget/tests/unit/data/UserDaoTest.kt
+++ /dev/null
@@ -1,182 +0,0 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
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
-package com.android.multiuser.widget.tests.unit.data
-
-import android.content.Context
-import androidx.test.ext.junit.runners.AndroidJUnit4
-import androidx.room.Room
-import androidx.test.core.app.ApplicationProvider
-import com.android.multiuser.widget.data.model.User
-import com.android.multiuser.widget.data.UserDao
-import com.android.multiuser.widget.data.UsersDatabase
-import java.io.IOException
-import java.util.concurrent.CountDownLatch
-import kotlin.test.assertEquals
-import kotlin.test.assertTrue
-import kotlinx.coroutines.async
-import kotlinx.coroutines.cancelAndJoin
-import kotlinx.coroutines.Dispatchers
-import kotlinx.coroutines.flow.first
-import kotlinx.coroutines.runBlocking
-import org.junit.After
-import org.junit.Before
-import org.junit.Test
-import org.junit.runner.RunWith
-
-@RunWith(AndroidJUnit4::class)
-class UserDaoTest {
-    private lateinit var database: UsersDatabase
-    private lateinit var userDao: UserDao
-
-    @Before
-    fun setUpDatabase() {
-        val context = ApplicationProvider.getApplicationContext<Context>()
-        database = Room.inMemoryDatabaseBuilder(context, UsersDatabase::class.java).build()
-        userDao = database.getUserDao()
-    }
-
-    @After
-    @Throws(IOException::class)
-    fun closeDatabase() {
-        database.close()
-    }
-
-    @Test
-    fun addUser_returnsTrue() = runBlocking {
-        val fakeUser = User(
-            id = 0,
-            name = "fake_user_name",
-            creationTime = 0,
-            iconPath = "fake_icon_uri",
-            isCurrentUser = false,
-            isAdmin = false,
-        )
-        userDao.addUsers(fakeUser)
-
-        val latch = CountDownLatch(1)
-        val job = async(Dispatchers.IO) {
-            val usersFromDatabase = userDao.getUsers().first()
-            assertEquals(usersFromDatabase.size, 1)
-            assertEquals(usersFromDatabase.get(0), fakeUser)
-            latch.countDown()
-        }
-
-        latch.await()
-        job.cancelAndJoin()
-    }
-
-    @Test
-    fun addUsers_returnsOrderedUserInfos() = runBlocking {
-        val fakeUser0 = User(
-            id = 0,
-            name = "fake_user_name_0",
-            creationTime = 0,
-            iconPath = "fake_icon_path_0",
-            isCurrentUser = false,
-            isAdmin = false,
-        )
-        val fakeUser1 = User(
-            id = 1,
-            name = "fake_user_name_1",
-            creationTime = 1,
-            iconPath = "fake_icon_path_1",
-            isCurrentUser = false,
-            isAdmin = false,
-        )
-
-        userDao.addUsers(fakeUser1)
-        userDao.addUsers(fakeUser0)
-
-        val latch = CountDownLatch(1)
-        val job = async(Dispatchers.IO) {
-            val usersFromDatabase = userDao.getUsers().first()
-            assertEquals(usersFromDatabase.size, 2)
-            assertTrue(usersFromDatabase.get(0).creationTime
-                    <= usersFromDatabase.get(1).creationTime)
-            latch.countDown()
-        }
-
-        latch.await()
-        job.cancelAndJoin()
-    }
-
-    @Test
-    fun addUsers_returnsCurrentUser() = runBlocking {
-        val fakeCurrentUser = User(
-            id = 0,
-            name = "fake_user_name_0",
-            creationTime = 0,
-            iconPath = "fake_icon_path_0",
-            isCurrentUser = true,
-            isAdmin = false,
-        )
-        val fakeUser = User(
-            id = 1,
-            name = "fake_user_name_1",
-            creationTime = 1,
-            iconPath = "fake_icon_path_1",
-            isCurrentUser = false,
-            isAdmin = false,
-        )
-
-        userDao.addUsers(fakeCurrentUser)
-        userDao.addUsers(fakeUser)
-
-        val latch = CountDownLatch(1)
-        val job = async(Dispatchers.IO) {
-            val currentUser = userDao.getCurrentUser().first()
-            assertEquals(currentUser, fakeCurrentUser)
-            latch.countDown()
-        }
-
-        latch.await()
-        job.cancelAndJoin()
-    }
-
-    @Test
-    fun updateUsers_replacesExistingUserInfoWithNew() = runBlocking {
-        val fakeUser = User(
-            id = 0,
-            name = "fake_user_name",
-            creationTime = 0,
-            iconPath = "fake_icon_path",
-            isCurrentUser = false,
-            isAdmin = false,
-        )
-        val updatedFakeUser = User(
-            id = 0,
-            name = "updated_fake_user_name",
-            creationTime = 0,
-            iconPath = "fake_icon_path",
-            isCurrentUser = false,
-            isAdmin = false,
-        )
-        userDao.addUsers(fakeUser)
-        userDao.addUsers(updatedFakeUser)
-
-        val latch = CountDownLatch(1)
-        val job = async(Dispatchers.IO) {
-            val usersFromDatabase = userDao.getUsers().first()
-            assertEquals(usersFromDatabase.size, 1)
-            assertEquals(usersFromDatabase.get(0), updatedFakeUser)
-            latch.countDown()
-        }
-
-        latch.await()
-        job.cancelAndJoin()
-    }
-}
diff --git a/Widget/src/tests/unit/java/com/android/multiuser/widget/tests/unit/domain/LoadUsersUseCaseTest.kt b/Widget/src/tests/unit/java/com/android/multiuser/widget/tests/unit/domain/LoadUsersUseCaseTest.kt
deleted file mode 100644
index 510b34d..0000000
--- a/Widget/src/tests/unit/java/com/android/multiuser/widget/tests/unit/domain/LoadUsersUseCaseTest.kt
+++ /dev/null
@@ -1,196 +0,0 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
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
-package com.android.multiuser.widget.tests.unit.domain
-
-import android.content.Context
-import androidx.room.Room
-import androidx.test.core.app.ApplicationProvider
-import androidx.test.ext.junit.runners.AndroidJUnit4
-import com.android.multiuser.widget.tests.R
-import com.android.multiuser.widget.data.ActionsRepository
-import com.android.multiuser.widget.data.UserDao
-import com.android.multiuser.widget.data.UsersDatabase
-import com.android.multiuser.widget.data.model.User
-import com.android.multiuser.widget.domain.LoadUsersUseCase
-import com.android.multiuser.widget.util.SHOULD_DISPLAY_ADD_USER_BUTTON
-import com.android.multiuser.widget.viewmodel.ActionViewModel
-import com.android.multiuser.widget.viewmodel.UserViewModel
-import java.io.IOException
-import java.util.concurrent.CountDownLatch
-import kotlin.test.assertContains
-import kotlin.test.assertEquals
-import kotlin.test.assertFalse
-import kotlinx.coroutines.Dispatchers
-import kotlinx.coroutines.async
-import kotlinx.coroutines.cancelAndJoin
-import kotlinx.coroutines.flow.first
-import kotlinx.coroutines.runBlocking
-import org.junit.After
-import org.junit.Before
-import org.junit.Test
-import org.junit.runner.RunWith
-
-@RunWith(AndroidJUnit4::class)
-class LoadUsersUseCaseTest {
-    private lateinit var database: UsersDatabase
-    private lateinit var userDao: UserDao
-    private lateinit var loadUsersUseCase: LoadUsersUseCase
-    private lateinit var actionsRepository: ActionsRepository
-    private val addUserActionViewModel = ActionViewModel (
-        resourceId = R.drawable.person_add,
-        title = "Add user",
-        contentDescription = "Add user",
-    )
-
-    @Before
-    fun setUp() {
-        val context = ApplicationProvider.getApplicationContext<Context>()
-        actionsRepository = ActionsRepository(context)
-        database = Room.inMemoryDatabaseBuilder(context, UsersDatabase::class.java).build()
-        userDao = database.getUserDao()
-        loadUsersUseCase =
-            LoadUsersUseCase(userDao = userDao, actionsRepository = actionsRepository)
-    }
-
-    @After
-    @Throws(IOException::class)
-    fun closeDatabase() {
-        database.close()
-    }
-
-    @Test
-    fun loadUsersModel_mapsUserToUserViewModel() = runBlocking {
-        val fakeUser1 = User(
-            id = 0,
-            name = "fake_user_name_1",
-            creationTime = 0,
-            iconPath = "fake_icon_path_1",
-            isCurrentUser = true,
-            isAdmin = false,
-        )
-        val fakeUser2 = User(
-            id = 1,
-            name = "fake_user_name_2",
-            creationTime = 1,
-            iconPath = "fake_icon_path_2",
-            isCurrentUser = false,
-            isAdmin = true,
-        )
-        userDao.addUsers(fakeUser1)
-        userDao.addUsers(fakeUser2)
-
-        val expectedUserViewModel1 = UserViewModel(
-            iconPath = "fake_icon_path_1",
-            id = 0,
-            name = "fake_user_name_1",
-            contentDescription = null,
-            isSelected = true,
-        )
-        val expectedUserViewModel2 = UserViewModel(
-            iconPath = "fake_icon_path_2",
-            id = 1,
-            name = "fake_user_name_2",
-            contentDescription = null,
-            isSelected = false,
-        )
-
-        val latch = CountDownLatch(1)
-        val job = async(Dispatchers.IO) {
-            val model = loadUsersUseCase().first()
-            assertEquals(model.users.size, 2)
-            assertContains(model.users, expectedUserViewModel1)
-            assertContains(model.users, expectedUserViewModel2)
-            latch.countDown()
-        }
-
-        latch.await()
-        job.cancelAndJoin()
-    }
-
-    @Test
-    fun currentUserIsAdminAndAddUserButtonFlagIsSet_viewmodelIncludesAddUserButton() = runBlocking {
-        val fakeUser = User(
-            id = 0,
-            name = "fake_user_name",
-            creationTime = 0,
-            iconPath = "fake_icon_path",
-            isCurrentUser = true,
-            isAdmin = true,
-        )
-        userDao.addUsers(fakeUser)
-        SHOULD_DISPLAY_ADD_USER_BUTTON = true
-
-        val latch = CountDownLatch(1)
-        val job = async(Dispatchers.IO) {
-            val model = loadUsersUseCase().first()
-            assertEquals(model.actions.size, 1)
-            assertContains(model.actions, addUserActionViewModel)
-            latch.countDown()
-        }
-
-        latch.await()
-        job.cancelAndJoin()
-    }
-
-    @Test
-    fun currentUserIsAdminAndAddUserButtonFlagIsNotSet_viewmodelDoesNotIncludeAddUserButton()
-        = runBlocking {
-        val fakeUser = User(
-            id = 0,
-            name = "fake_user_name",
-            creationTime = 0,
-            iconPath = "fake_icon_path",
-            isCurrentUser = true,
-            isAdmin = true,
-        )
-        userDao.addUsers(fakeUser)
-        SHOULD_DISPLAY_ADD_USER_BUTTON = false
-
-        val latch = CountDownLatch(1)
-        val job = async(Dispatchers.IO) {
-            val model = loadUsersUseCase().first()
-            assertFalse(model.actions.contains(addUserActionViewModel))
-            latch.countDown()
-        }
-
-        latch.await()
-        job.cancelAndJoin()
-    }
-
-    @Test
-    fun currentUserIsNotAdmin_viewmodelDoesNotIncludeAddUserButton() = runBlocking {
-        val fakeUser = User(
-            id = 0,
-            name = "fake_user_name",
-            creationTime = 0,
-            iconPath = "fake_icon_path",
-            isCurrentUser = true,
-            isAdmin = false,
-        )
-        userDao.addUsers(fakeUser)
-
-        val latch = CountDownLatch(1)
-        val job = async(Dispatchers.IO) {
-            val model = loadUsersUseCase().first()
-            assertFalse(model.actions.contains(addUserActionViewModel))
-            latch.countDown()
-        }
-
-        latch.await()
-        job.cancelAndJoin()
-    }
-}
```

