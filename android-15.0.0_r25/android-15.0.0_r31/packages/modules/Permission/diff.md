```diff
diff --git a/service/java/com/android/role/RoleService.java b/service/java/com/android/role/RoleService.java
index 20250b4f6..b3370b823 100644
--- a/service/java/com/android/role/RoleService.java
+++ b/service/java/com/android/role/RoleService.java
@@ -585,6 +585,9 @@ public class RoleService extends SystemService implements RoleUserState.Callback
         @Override
         @Nullable
         public String getDefaultApplicationAsUser(@NonNull String roleName, @UserIdInt int userId) {
+            // The MANAGE_DEFAULT_APPLICATIONS permission is only available on U+
+            Preconditions.checkState(SdkLevel.isAtLeastU(),
+                    "This API is only available on Android 34 and above");
             UserUtils.enforceCrossUserPermission(userId, false, "getDefaultApplicationAsUser",
                     getContext());
             if (!UserUtils.isUserExistent(userId, getContext())) {
@@ -610,6 +613,9 @@ public class RoleService extends SystemService implements RoleUserState.Callback
         public void setDefaultApplicationAsUser(@NonNull String roleName,
                 @Nullable String packageName, @RoleManager.ManageHoldersFlags int flags,
                 @UserIdInt int userId, @NonNull RemoteCallback callback) {
+            // The MANAGE_DEFAULT_APPLICATIONS permission is only available on U+
+            Preconditions.checkState(SdkLevel.isAtLeastU(),
+                    "This API is only available on Android 34 and above");
             UserUtils.enforceCrossUserPermission(userId, false, "setDefaultApplicationAsUser",
                     getContext());
             if (!UserUtils.isUserExistent(userId, getContext())) {
diff --git a/tests/cts/role/src/android/app/role/cts/RoleManagerSecurityTest.kt b/tests/cts/role/src/android/app/role/cts/RoleManagerSecurityTest.kt
new file mode 100644
index 000000000..59a8c21b2
--- /dev/null
+++ b/tests/cts/role/src/android/app/role/cts/RoleManagerSecurityTest.kt
@@ -0,0 +1,148 @@
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
+package android.app.role.cts
+
+import android.app.role.RoleManager
+import android.content.Context
+import android.os.Build
+import android.os.Process
+import android.os.UserHandle
+import androidx.test.ext.junit.runners.AndroidJUnit4
+import androidx.test.filters.SdkSuppress
+import androidx.test.platform.app.InstrumentationRegistry
+import com.android.compatibility.common.util.SystemUtil
+import com.google.common.truth.Truth.assertThat
+import java.util.concurrent.CompletableFuture
+import java.util.concurrent.Executor
+import java.util.concurrent.TimeUnit
+import java.util.function.Consumer
+import org.junit.After
+import org.junit.Assert.fail
+import org.junit.Assume.assumeTrue
+import org.junit.Before
+import org.junit.Test
+import org.junit.runner.RunWith
+
+/** Tests {@link RoleManager} security fixes. */
+@RunWith(AndroidJUnit4::class)
+class RoleManagerSecurityTest {
+    private var browserRoleHolder: String? = null
+
+    @Before
+    fun setUp() {
+        saveBrowserRoleHolder()
+    }
+
+    @After
+    fun tearDown() {
+        restoreBrowserRoleHolder()
+    }
+
+    private fun saveBrowserRoleHolder() {
+        val roleHolders: List<String> = getRoleHolders(RoleManager.ROLE_BROWSER, roleManager)
+        browserRoleHolder = if (roleHolders.isNotEmpty()) roleHolders[0] else null
+    }
+
+    private fun restoreBrowserRoleHolder() {
+        browserRoleHolder?.let { packageName ->
+            addRoleHolderAsUser(
+                RoleManager.ROLE_BROWSER,
+                packageName,
+                Process.myUserHandle(),
+                true,
+                roleManager,
+                context.mainExecutor,
+            )
+        }
+    }
+
+    private fun getRoleHolders(roleName: String, roleManager: RoleManager): List<String> {
+        return SystemUtil.callWithShellPermissionIdentity { roleManager.getRoleHolders(roleName) }
+    }
+
+    private fun addRoleHolderAsUser(
+        roleName: String,
+        packageName: String,
+        userHandle: UserHandle,
+        expectSuccess: Boolean,
+        roleManager: RoleManager,
+        executor: Executor,
+    ) {
+        val future = CallbackFuture()
+        SystemUtil.runWithShellPermissionIdentity {
+            roleManager.addRoleHolderAsUser(roleName, packageName, 0, userHandle, executor, future)
+        }
+        assertThat(future.get(TIMEOUT_MILLIS, TimeUnit.MILLISECONDS)).isEqualTo(expectSuccess)
+    }
+
+    @SdkSuppress(
+        minSdkVersion = Build.VERSION_CODES.S,
+        maxSdkVersion = Build.VERSION_CODES.TIRAMISU,
+    )
+    @Test
+    fun cannotGetDefaultApplicationOnOlderSdk() {
+        assumeTrue(roleManager.isRoleAvailable(RoleManager.ROLE_BROWSER))
+        try {
+            roleManager.getDefaultApplication(RoleManager.ROLE_BROWSER)
+        } catch (e: NoSuchMethodError) {
+            // Expected when permission module hasn't been updated
+        } catch (e: IllegalStateException) {
+            // Expected when permission module has been updated, and SDK 33 or below
+        } catch (e: Throwable) {
+            fail("Missing patch for cveBugId = [379362792]")
+        }
+    }
+
+    @SdkSuppress(
+        minSdkVersion = Build.VERSION_CODES.S,
+        maxSdkVersion = Build.VERSION_CODES.TIRAMISU,
+    )
+    @Test
+    fun cannotSetDefaultApplicationOnOlderSdk() {
+        assumeTrue(roleManager.isRoleAvailable(RoleManager.ROLE_BROWSER))
+        val future = CallbackFuture()
+        try {
+            roleManager.setDefaultApplication(
+                RoleManager.ROLE_BROWSER,
+                APP_PACKAGE_NAME,
+                0,
+                context.mainExecutor,
+                future,
+            )
+            future.get(TIMEOUT_MILLIS, TimeUnit.MILLISECONDS)
+        } catch (e: NoSuchMethodError) {
+            // Expected when permission module hasn't been updated
+        } catch (e: IllegalStateException) {
+            // Expected when permission module has been updated, and SDK 33 or below
+        } catch (e: Throwable) {
+            fail("Missing patch for cveBugId = [379362792]")
+        }
+    }
+
+    private class CallbackFuture : CompletableFuture<Boolean?>(), Consumer<Boolean?> {
+        override fun accept(successful: Boolean?) {
+            complete(successful)
+        }
+    }
+
+    companion object {
+        private const val TIMEOUT_MILLIS: Long = (15 * 1000).toLong()
+        private const val APP_PACKAGE_NAME: String = "android.app.role.cts.app"
+
+        private val context: Context = InstrumentationRegistry.getInstrumentation().targetContext
+        private val roleManager: RoleManager = context.getSystemService(RoleManager::class.java)
+    }
+}
```

