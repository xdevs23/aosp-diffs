```diff
diff --git a/core/java/android/app/BackgroundStartPrivileges.java b/core/java/android/app/BackgroundStartPrivileges.java
index 20278eaee3b2..adea0a8a0702 100644
--- a/core/java/android/app/BackgroundStartPrivileges.java
+++ b/core/java/android/app/BackgroundStartPrivileges.java
@@ -23,12 +23,13 @@ import android.os.IBinder;
 import com.android.internal.util.Preconditions;
 
 import java.util.List;
+import java.util.Objects;
 
 /**
  * Privileges granted to a Process that allows it to execute starts from the background.
  * @hide
  */
-public class BackgroundStartPrivileges {
+public final class BackgroundStartPrivileges {
     /** No privileges. */
     public static final BackgroundStartPrivileges NONE = new BackgroundStartPrivileges(
             false, false, null);
@@ -190,4 +191,22 @@ public class BackgroundStartPrivileges {
                 + ", originatingToken=" + mOriginatingToken
                 + ']';
     }
+
+    @Override
+    public boolean equals(Object o) {
+        if (this == o) return true;
+        if (o == null || getClass() != o.getClass()) return false;
+        BackgroundStartPrivileges that = (BackgroundStartPrivileges) o;
+        return mAllowsBackgroundActivityStarts == that.mAllowsBackgroundActivityStarts
+                && mAllowsBackgroundForegroundServiceStarts
+                == that.mAllowsBackgroundForegroundServiceStarts
+                && Objects.equals(mOriginatingToken, that.mOriginatingToken);
+    }
+
+    @Override
+    public int hashCode() {
+        return Objects.hash(mAllowsBackgroundActivityStarts,
+                mAllowsBackgroundForegroundServiceStarts,
+                mOriginatingToken);
+    }
 }
diff --git a/core/java/android/app/IUserSwitchObserver.aidl b/core/java/android/app/IUserSwitchObserver.aidl
index 1ff7a17e578f..d71ee7c712e7 100644
--- a/core/java/android/app/IUserSwitchObserver.aidl
+++ b/core/java/android/app/IUserSwitchObserver.aidl
@@ -19,10 +19,10 @@ package android.app;
 import android.os.IRemoteCallback;
 
 /** {@hide} */
-interface IUserSwitchObserver {
-    void onBeforeUserSwitching(int newUserId);
-    oneway void onUserSwitching(int newUserId, IRemoteCallback reply);
-    oneway void onUserSwitchComplete(int newUserId);
-    oneway void onForegroundProfileSwitch(int newProfileId);
-    oneway void onLockedBootComplete(int newUserId);
+oneway interface IUserSwitchObserver {
+    void onBeforeUserSwitching(int newUserId, IRemoteCallback reply);
+    void onUserSwitching(int newUserId, IRemoteCallback reply);
+    void onUserSwitchComplete(int newUserId);
+    void onForegroundProfileSwitch(int newProfileId);
+    void onLockedBootComplete(int newUserId);
 }
diff --git a/core/java/android/app/UserSwitchObserver.java b/core/java/android/app/UserSwitchObserver.java
index 727799a1f948..1664cfb6f7a8 100644
--- a/core/java/android/app/UserSwitchObserver.java
+++ b/core/java/android/app/UserSwitchObserver.java
@@ -30,7 +30,11 @@ public class UserSwitchObserver extends IUserSwitchObserver.Stub {
     }
 
     @Override
-    public void onBeforeUserSwitching(int newUserId) throws RemoteException {}
+    public void onBeforeUserSwitching(int newUserId, IRemoteCallback reply) throws RemoteException {
+        if (reply != null) {
+            reply.sendResult(null);
+        }
+    }
 
     @Override
     public void onUserSwitching(int newUserId, IRemoteCallback reply) throws RemoteException {
diff --git a/core/java/android/content/res/Configuration.java b/core/java/android/content/res/Configuration.java
index ef200c328d63..2e0999410483 100644
--- a/core/java/android/content/res/Configuration.java
+++ b/core/java/android/content/res/Configuration.java
@@ -2358,8 +2358,13 @@ public final class Configuration implements Parcelable, Comparable<Configuration
      * @param locales The locale list. If null, an empty LocaleList will be assigned.
      */
     public void setLocales(@Nullable LocaleList locales) {
+        LocaleList oldList = mLocaleList;
         mLocaleList = locales == null ? LocaleList.getEmptyLocaleList() : locales;
         locale = mLocaleList.get(0);
+        if (!mLocaleList.equals(oldList)) {
+            Slog.v(TAG, "Updating configuration, locales updated from " + oldList
+                    + " to " + mLocaleList);
+        }
         setLayoutDirection(locale);
     }
 
diff --git a/core/java/android/content/res/ResourcesImpl.java b/core/java/android/content/res/ResourcesImpl.java
index e6b93427f413..b002194a6143 100644
--- a/core/java/android/content/res/ResourcesImpl.java
+++ b/core/java/android/content/res/ResourcesImpl.java
@@ -475,6 +475,9 @@ public class ResourcesImpl {
                             }
                             defaultLocale =
                                     adjustLanguageTag(lc.getDefaultLocale().toLanguageTag());
+                            Slog.v(TAG, "Updating configuration, with default locale "
+                                    + defaultLocale + " and selected locales "
+                                    + Arrays.toString(selectedLocales));
                         } else {
                             String[] availableLocales;
                             // The LocaleList has changed. We must query the AssetManager's
@@ -510,6 +513,7 @@ public class ResourcesImpl {
                         for (int i = 0; i < locales.size(); i++) {
                             selectedLocales[i] = adjustLanguageTag(locales.get(i).toLanguageTag());
                         }
+                        defaultLocale = adjustLanguageTag(lc.getDefaultLocale().toLanguageTag());
                     } else {
                         selectedLocales = new String[]{
                                 adjustLanguageTag(locales.get(0).toLanguageTag())};
diff --git a/core/java/android/permission/flags.aconfig b/core/java/android/permission/flags.aconfig
index bca5bcc99c7e..4bc0b3a27b4f 100644
--- a/core/java/android/permission/flags.aconfig
+++ b/core/java/android/permission/flags.aconfig
@@ -266,3 +266,14 @@ flag {
     description: "This fixed read-only flag is used to enable replacing permission BODY_SENSORS (and BODY_SENSORS_BACKGROUND) with granular health permission READ_HEART_RATE (and READ_HEALTH_DATA_IN_BACKGROUND)"
     bug: "364638912"
 }
+
+flag {
+    name: "delay_uid_state_changes_from_capability_updates"
+    is_fixed_read_only: true
+    namespace: "permissions"
+    description: "If proc state is decreasing over the restriction threshold and capability is changed, delay if no new capabilities are added"
+    bug: "308573169"
+    metadata {
+        purpose: PURPOSE_BUGFIX
+    }
+}
diff --git a/core/java/android/window/flags/responsible_apis.aconfig b/core/java/android/window/flags/responsible_apis.aconfig
index cd31850b281c..95eb9bc4aa3d 100644
--- a/core/java/android/window/flags/responsible_apis.aconfig
+++ b/core/java/android/window/flags/responsible_apis.aconfig
@@ -78,4 +78,16 @@ flag {
     bug: "362575865"
 }
 
+flag {
+    name: "bal_strict_mode_grace_period"
+    namespace: "responsible_apis"
+    description: "Strict mode violation triggered by grace period usage"
+    bug: "384807495"
+}
 
+flag {
+    name: "bal_clear_allowlist_duration"
+    namespace: "responsible_apis"
+    description: "Clear the allowlist duration when clearAllowBgActivityStarts is called"
+    bug: "322159724"
+}
diff --git a/core/jni/android_util_AssetManager.cpp b/core/jni/android_util_AssetManager.cpp
index 7fe6731b7116..bb832d2bc010 100644
--- a/core/jni/android_util_AssetManager.cpp
+++ b/core/jni/android_util_AssetManager.cpp
@@ -398,19 +398,17 @@ static void NativeSetConfiguration(JNIEnv* env, jclass /*clazz*/, jlong ptr, jin
     configs.push_back(configuration);
   }
 
-  uint32_t default_locale_int = 0;
+  std::optional<ResTable_config> default_locale_opt;
   if (default_locale != nullptr) {
-    ResTable_config config;
-    static_assert(std::is_same_v<decltype(config.locale), decltype(default_locale_int)>);
-    ScopedUtfChars locale_utf8(env, default_locale);
-    CHECK(locale_utf8.c_str() != nullptr);
-    config.setBcp47Locale(locale_utf8.c_str());
-    default_locale_int = config.locale;
+      ScopedUtfChars locale_utf8(env, default_locale);
+      CHECK(locale_utf8.c_str() != nullptr);
+      default_locale_opt.emplace();
+      default_locale_opt->setBcp47Locale(locale_utf8.c_str());
   }
 
   auto assetmanager = LockAndStartAssetManager(ptr);
   assetmanager->SetConfigurations(std::move(configs), force_refresh != JNI_FALSE);
-  assetmanager->SetDefaultLocale(default_locale_int);
+  assetmanager->SetDefaultLocale(default_locale_opt);
 }
 
 static jobject NativeGetAssignedPackageIdentifiers(JNIEnv* env, jclass /*clazz*/, jlong ptr,
diff --git a/core/res/res/values/config.xml b/core/res/res/values/config.xml
index 07efad89010a..3fd4f79f1960 100644
--- a/core/res/res/values/config.xml
+++ b/core/res/res/values/config.xml
@@ -7140,4 +7140,8 @@
     <string name="identity_check_settings_action"></string>
     <!-- Package for opening identity check settings page [CHAR LIMIT=NONE] [DO NOT TRANSLATE] -->
     <string name="identity_check_settings_package_name">com\u002eandroid\u002esettings</string>
+
+    <!-- List of protected packages that require biometric authentication for modification
+         (Disable, force-stop or uninstalling updates). -->
+    <string-array name="config_biometric_protected_package_names" translatable="false" />
 </resources>
diff --git a/core/res/res/values/symbols.xml b/core/res/res/values/symbols.xml
index 06b36b8f74af..8032de97b2db 100644
--- a/core/res/res/values/symbols.xml
+++ b/core/res/res/values/symbols.xml
@@ -5615,4 +5615,8 @@
   <!-- Identity check strings -->
   <java-symbol type="string" name="identity_check_settings_action" />
   <java-symbol type="string" name="identity_check_settings_package_name" />
+
+  <!-- List of protected packages that require biometric authentication for modification -->
+  <java-symbol type="array" name="config_biometric_protected_package_names" />
+
 </resources>
diff --git a/core/tests/coretests/src/android/app/BackgroundStartPrivilegesTest.java b/core/tests/coretests/src/android/app/BackgroundStartPrivilegesTest.java
index cf6266c756ce..931d64640ea2 100644
--- a/core/tests/coretests/src/android/app/BackgroundStartPrivilegesTest.java
+++ b/core/tests/coretests/src/android/app/BackgroundStartPrivilegesTest.java
@@ -119,4 +119,15 @@ public class BackgroundStartPrivilegesTest {
                 Arrays.asList(BSP_ALLOW_A, BSP_ALLOW_A, BSP_ALLOW_A, BSP_ALLOW_A)))
                 .isEqualTo(BSP_ALLOW_A);
     }
+
+    @Test
+    public void backgroundStartPrivilege_equals_works() {
+        assertThat(NONE).isEqualTo(NONE);
+        assertThat(ALLOW_BAL).isEqualTo(ALLOW_BAL);
+        assertThat(ALLOW_FGS).isEqualTo(ALLOW_FGS);
+        assertThat(BSP_ALLOW_A).isEqualTo(BSP_ALLOW_A);
+        assertThat(NONE).isNotEqualTo(ALLOW_BAL);
+        assertThat(ALLOW_FGS).isNotEqualTo(ALLOW_BAL);
+        assertThat(BSP_ALLOW_A).isNotEqualTo(BSP_ALLOW_B);
+    }
 }
diff --git a/libs/WindowManager/Jetpack/src/androidx/window/extensions/embedding/SplitController.java b/libs/WindowManager/Jetpack/src/androidx/window/extensions/embedding/SplitController.java
index db4bb0e5e75e..0c6547ed3439 100644
--- a/libs/WindowManager/Jetpack/src/androidx/window/extensions/embedding/SplitController.java
+++ b/libs/WindowManager/Jetpack/src/androidx/window/extensions/embedding/SplitController.java
@@ -18,6 +18,7 @@ package androidx.window.extensions.embedding;
 
 import static android.app.ActivityManager.START_SUCCESS;
 import static android.app.ActivityOptions.KEY_LAUNCH_TASK_FRAGMENT_TOKEN;
+import static android.app.ActivityTaskManager.INVALID_TASK_ID;
 import static android.app.WindowConfiguration.WINDOWING_MODE_PINNED;
 import static android.app.WindowConfiguration.WINDOWING_MODE_UNDEFINED;
 import static android.view.Display.DEFAULT_DISPLAY;
@@ -3078,15 +3079,22 @@ public class SplitController implements JetpackTaskFragmentOrganizer.TaskFragmen
                 final WindowContainerTransaction wct = transactionRecord.getTransaction();
                 final TaskFragmentContainer launchedInTaskFragment;
                 if (launchingActivity != null) {
-                    final int taskId = getTaskId(launchingActivity);
                     final String overlayTag = options.getString(KEY_OVERLAY_TAG);
                     if (Flags.activityEmbeddingOverlayPresentationFlag()
                             && overlayTag != null) {
                         launchedInTaskFragment = createOrUpdateOverlayTaskFragmentIfNeeded(wct,
                                 options, intent, launchingActivity);
                     } else {
-                        launchedInTaskFragment = resolveStartActivityIntent(wct, taskId, intent,
-                                launchingActivity);
+                        final int taskId = getTaskId(launchingActivity);
+                        if (taskId != INVALID_TASK_ID) {
+                            launchedInTaskFragment = resolveStartActivityIntent(wct, taskId, intent,
+                                    launchingActivity);
+                        } else {
+                            // We cannot get a valid task id of launchingActivity so we fall back to
+                            // treat it as a non-Activity context.
+                            launchedInTaskFragment =
+                                    resolveStartActivityIntentFromNonActivityContext(wct, intent);
+                        }
                     }
                 } else {
                     launchedInTaskFragment = resolveStartActivityIntentFromNonActivityContext(wct,
diff --git a/libs/androidfw/AssetManager2.cpp b/libs/androidfw/AssetManager2.cpp
index 0fa31c7a832e..4d83c9dc6903 100644
--- a/libs/androidfw/AssetManager2.cpp
+++ b/libs/androidfw/AssetManager2.cpp
@@ -23,6 +23,7 @@
 #include <map>
 #include <set>
 #include <span>
+#include <sstream>
 #include <utility>
 
 #include "android-base/logging.h"
@@ -438,6 +439,24 @@ bool AssetManager2::ContainsAllocatedTable() const {
   return false;
 }
 
+static std::string ConfigVecToString(std::span<const ResTable_config> configurations) {
+  std::stringstream ss;
+  ss << "[";
+  bool first = true;
+  for (const auto& config : configurations) {
+    if (!first) {
+      ss << ",";
+    }
+    char out[RESTABLE_MAX_LOCALE_LEN] = {};
+    config.getBcp47Locale(out);
+    ss << out;
+    first = false;
+  }
+  ss << "]";
+  return ss.str();
+}
+
+
 void AssetManager2::SetConfigurations(std::span<const ResTable_config> configurations,
                                       bool force_refresh) {
   int diff = 0;
@@ -452,6 +471,17 @@ void AssetManager2::SetConfigurations(std::span<const ResTable_config> configura
       }
     }
   }
+
+  // Log the locale list change to investigate b/392255526
+  if (diff & ConfigDescription::CONFIG_LOCALE) {
+    auto oldstr = ConfigVecToString(configurations_);
+    auto newstr = ConfigVecToString(configurations);
+    if (oldstr != newstr) {
+      LOG(INFO) << "AssetManager2(" << this << ") locale list changing from "
+                << oldstr << " to " << newstr;
+    }
+  }
+
   configurations_.clear();
   for (auto&& config : configurations) {
     configurations_.emplace_back(config);
@@ -462,6 +492,28 @@ void AssetManager2::SetConfigurations(std::span<const ResTable_config> configura
   }
 }
 
+void AssetManager2::SetDefaultLocale(std::optional<ResTable_config> default_locale) {
+  int diff = 0;
+  if (default_locale_ && default_locale) {
+    diff = default_locale_->diff(default_locale.value());
+  } else if (default_locale_ || default_locale) {
+    diff = -1;
+  }
+  if (diff & ConfigDescription::CONFIG_LOCALE) {
+    char old_loc[RESTABLE_MAX_LOCALE_LEN] = {};
+    char new_loc[RESTABLE_MAX_LOCALE_LEN] = {};
+    if (default_locale_) {
+      default_locale_->getBcp47Locale(old_loc);
+    }
+    if (default_locale) {
+      default_locale->getBcp47Locale(new_loc);
+    }
+    LOG(INFO) << "AssetManager2(" << this << ") default locale changing from '"
+              << old_loc << "' to '" << new_loc << "'";
+  }
+  default_locale_ = default_locale;
+}
+
 std::set<AssetManager2::ApkAssetsPtr> AssetManager2::GetNonSystemOverlays() const {
   std::set<ApkAssetsPtr> non_system_overlays;
   for (const PackageGroup& package_group : package_groups_) {
@@ -708,7 +760,7 @@ base::expected<FindEntryResult, NullOrIOError> AssetManager2::FindEntry(
             ConfigDescription best_frro_config;
             Res_value best_frro_value;
             bool frro_found = false;
-            for( const auto& [config, value] : overlay_entry.GetInlineValue()) {
+            for (const auto& [config, value] : overlay_entry.GetInlineValue()) {
               if ((!frro_found || config.isBetterThan(best_frro_config, desired_config))
                   && config.match(*desired_config)) {
                 frro_found = true;
@@ -787,11 +839,11 @@ base::expected<FindEntryResult, NullOrIOError> AssetManager2::FindEntry(
 
     bool has_locale = false;
     if (result->config.locale == 0) {
-      if (default_locale_ != 0) {
-        ResTable_config conf = {.locale = default_locale_};
-        // Since we know conf has a locale and only a locale, match will tell us if that locale
-        // matches
-        has_locale = conf.match(config);
+      // The default_locale_ is the locale used for any resources with no locale in the config
+      if (default_locale_) {
+        // Since we know default_locale_ has a locale and only a locale, match will tell us if that
+        // locale matches
+        has_locale = default_locale_->match(config);
       }
     } else {
       has_locale = true;
diff --git a/libs/androidfw/include/androidfw/AssetManager2.h b/libs/androidfw/include/androidfw/AssetManager2.h
index 0fdeefa09e26..803399af0191 100644
--- a/libs/androidfw/include/androidfw/AssetManager2.h
+++ b/libs/androidfw/include/androidfw/AssetManager2.h
@@ -21,6 +21,7 @@
 
 #include <array>
 #include <limits>
+#include <optional>
 #include <set>
 #include <span>
 #include <unordered_map>
@@ -167,9 +168,7 @@ class AssetManager2 {
     return configurations_;
   }
 
-  inline void SetDefaultLocale(uint32_t default_locale) {
-    default_locale_ = default_locale;
-  }
+  void SetDefaultLocale(const std::optional<ResTable_config> default_locale);
 
   // Returns all configurations for which there are resources defined, or an I/O error if reading
   // resource data failed.
@@ -474,7 +473,7 @@ class AssetManager2 {
   // without taking too much memory.
   std::array<uint8_t, std::numeric_limits<uint8_t>::max() + 1> package_ids_ = {};
 
-  uint32_t default_locale_ = 0;
+  std::optional<ResTable_config> default_locale_;
 
   // The current configurations set for this AssetManager. When this changes, cached resources
   // may need to be purged.
diff --git a/packages/SystemUI/src/com/android/systemui/settings/UserTracker.kt b/packages/SystemUI/src/com/android/systemui/settings/UserTracker.kt
index e1631ccdcb06..bbb13d5c1dfe 100644
--- a/packages/SystemUI/src/com/android/systemui/settings/UserTracker.kt
+++ b/packages/SystemUI/src/com/android/systemui/settings/UserTracker.kt
@@ -61,9 +61,18 @@ interface UserTracker : UserContentResolverProvider, UserContextProvider {
     /** Callback for notifying of changes. */
     @WeaklyReferencedCallback
     interface Callback {
-        /** Notifies that the current user will be changed. */
+        /**
+         * Same as {@link onBeforeUserSwitching(Int, Runnable)} but the callback will be called
+         * automatically after the completion of this method.
+         */
         fun onBeforeUserSwitching(newUser: Int) {}
 
+        /** Notifies that the current user will be changed. */
+        fun onBeforeUserSwitching(newUser: Int, resultCallback: Runnable) {
+            onBeforeUserSwitching(newUser)
+            resultCallback.run()
+        }
+
         /**
          * Same as {@link onUserChanging(Int, Context, Runnable)} but the callback will be called
          * automatically after the completion of this method.
diff --git a/packages/SystemUI/src/com/android/systemui/settings/UserTrackerImpl.kt b/packages/SystemUI/src/com/android/systemui/settings/UserTrackerImpl.kt
index 1863e12187cd..afcf9504c5b4 100644
--- a/packages/SystemUI/src/com/android/systemui/settings/UserTrackerImpl.kt
+++ b/packages/SystemUI/src/com/android/systemui/settings/UserTrackerImpl.kt
@@ -195,8 +195,9 @@ internal constructor(
     private fun registerUserSwitchObserver() {
         iActivityManager.registerUserSwitchObserver(
             object : UserSwitchObserver() {
-                override fun onBeforeUserSwitching(newUserId: Int) {
+                override fun onBeforeUserSwitching(newUserId: Int, reply: IRemoteCallback?) {
                     handleBeforeUserSwitching(newUserId)
+                    reply?.sendResult(null)
                 }
 
                 override fun onUserSwitching(newUserId: Int, reply: IRemoteCallback?) {
@@ -235,8 +236,7 @@ internal constructor(
         setUserIdInternal(newUserId)
 
         notifySubscribers { callback, resultCallback ->
-                callback.onBeforeUserSwitching(newUserId)
-                resultCallback.run()
+                callback.onBeforeUserSwitching(newUserId, resultCallback)
             }
             .await()
     }
diff --git a/packages/SystemUI/tests/src/com/android/systemui/settings/UserTrackerImplTest.kt b/packages/SystemUI/tests/src/com/android/systemui/settings/UserTrackerImplTest.kt
index a0ecb802dd61..f695c13a9e62 100644
--- a/packages/SystemUI/tests/src/com/android/systemui/settings/UserTrackerImplTest.kt
+++ b/packages/SystemUI/tests/src/com/android/systemui/settings/UserTrackerImplTest.kt
@@ -76,6 +76,8 @@ class UserTrackerImplTest : SysuiTestCase() {
 
     @Mock private lateinit var iActivityManager: IActivityManager
 
+    @Mock private lateinit var beforeUserSwitchingReply: IRemoteCallback
+
     @Mock private lateinit var userSwitchingReply: IRemoteCallback
 
     @Mock(stubOnly = true) private lateinit var dumpManager: DumpManager
@@ -199,9 +201,10 @@ class UserTrackerImplTest : SysuiTestCase() {
 
             val captor = ArgumentCaptor.forClass(IUserSwitchObserver::class.java)
             verify(iActivityManager).registerUserSwitchObserver(capture(captor), anyString())
-            captor.value.onBeforeUserSwitching(newID)
+            captor.value.onBeforeUserSwitching(newID, beforeUserSwitchingReply)
             captor.value.onUserSwitching(newID, userSwitchingReply)
             runCurrent()
+            verify(beforeUserSwitchingReply).sendResult(any())
             verify(userSwitchingReply).sendResult(any())
 
             verify(userManager).getProfiles(newID)
@@ -341,10 +344,11 @@ class UserTrackerImplTest : SysuiTestCase() {
 
             val captor = ArgumentCaptor.forClass(IUserSwitchObserver::class.java)
             verify(iActivityManager).registerUserSwitchObserver(capture(captor), anyString())
-            captor.value.onBeforeUserSwitching(newID)
+            captor.value.onBeforeUserSwitching(newID, beforeUserSwitchingReply)
             captor.value.onUserSwitching(newID, userSwitchingReply)
             runCurrent()
 
+            verify(beforeUserSwitchingReply).sendResult(any())
             verify(userSwitchingReply).sendResult(any())
             assertThat(callback.calledOnUserChanging).isEqualTo(1)
             assertThat(callback.lastUser).isEqualTo(newID)
@@ -395,7 +399,7 @@ class UserTrackerImplTest : SysuiTestCase() {
 
             val captor = ArgumentCaptor.forClass(IUserSwitchObserver::class.java)
             verify(iActivityManager).registerUserSwitchObserver(capture(captor), anyString())
-            captor.value.onBeforeUserSwitching(newID)
+            captor.value.onBeforeUserSwitching(newID, any())
             captor.value.onUserSwitchComplete(newID)
             runCurrent()
 
@@ -453,8 +457,10 @@ class UserTrackerImplTest : SysuiTestCase() {
 
             val captor = ArgumentCaptor.forClass(IUserSwitchObserver::class.java)
             verify(iActivityManager).registerUserSwitchObserver(capture(captor), anyString())
+            captor.value.onBeforeUserSwitching(newID, beforeUserSwitchingReply)
             captor.value.onUserSwitching(newID, userSwitchingReply)
             runCurrent()
+            verify(beforeUserSwitchingReply).sendResult(any())
             verify(userSwitchingReply).sendResult(any())
             captor.value.onUserSwitchComplete(newID)
 
@@ -488,6 +494,7 @@ class UserTrackerImplTest : SysuiTestCase() {
         }
 
     private class TestCallback : UserTracker.Callback {
+        var calledOnBeforeUserChanging = 0
         var calledOnUserChanging = 0
         var calledOnUserChanged = 0
         var calledOnProfilesChanged = 0
@@ -495,6 +502,11 @@ class UserTrackerImplTest : SysuiTestCase() {
         var lastUserContext: Context? = null
         var lastUserProfiles = emptyList<UserInfo>()
 
+        override fun onBeforeUserSwitching(newUser: Int) {
+            calledOnBeforeUserChanging++
+            lastUser = newUser
+        }
+
         override fun onUserChanging(newUser: Int, userContext: Context) {
             calledOnUserChanging++
             lastUser = newUser
diff --git a/services/core/java/com/android/server/VpnManagerService.java b/services/core/java/com/android/server/VpnManagerService.java
index 626fa708b4e7..7e68239e0c3b 100644
--- a/services/core/java/com/android/server/VpnManagerService.java
+++ b/services/core/java/com/android/server/VpnManagerService.java
@@ -19,6 +19,7 @@ package com.android.server;
 import static android.Manifest.permission.NETWORK_STACK;
 
 import static com.android.net.module.util.PermissionUtils.enforceAnyPermissionOf;
+import static com.android.net.module.util.PermissionUtils.enforceNetworkStackPermission;
 
 import android.annotation.NonNull;
 import android.annotation.Nullable;
@@ -1020,6 +1021,8 @@ public class VpnManagerService extends IVpnManager.Stub {
     @Override
     @Nullable
     public byte[] getFromVpnProfileStore(@NonNull String name) {
+        // TODO(b/307903113): Replace NETWORK_STACK permission and adopt proper permission
+        enforceNetworkStackPermission(mContext);
         return mVpnProfileStore.get(name);
     }
 
@@ -1037,6 +1040,8 @@ public class VpnManagerService extends IVpnManager.Stub {
      */
     @Override
     public boolean putIntoVpnProfileStore(@NonNull String name, @NonNull byte[] blob) {
+        // TODO(b/307903113): Replace NETWORK_STACK permission and adopt proper permission
+        enforceNetworkStackPermission(mContext);
         return mVpnProfileStore.put(name, blob);
     }
 
@@ -1052,6 +1057,8 @@ public class VpnManagerService extends IVpnManager.Stub {
      */
     @Override
     public boolean removeFromVpnProfileStore(@NonNull String name) {
+        // TODO(b/307903113): Replace NETWORK_STACK permission and adopt proper permission
+        enforceNetworkStackPermission(mContext);
         return mVpnProfileStore.remove(name);
     }
 
@@ -1069,6 +1076,8 @@ public class VpnManagerService extends IVpnManager.Stub {
     @Override
     @NonNull
     public String[] listFromVpnProfileStore(@NonNull String prefix) {
+        // TODO(b/307903113): Replace NETWORK_STACK permission and adopt proper permission
+        enforceNetworkStackPermission(mContext);
         return mVpnProfileStore.list(prefix);
     }
 
diff --git a/services/core/java/com/android/server/am/BroadcastController.java b/services/core/java/com/android/server/am/BroadcastController.java
index 15f1085b7125..d77d7f2d6bf5 100644
--- a/services/core/java/com/android/server/am/BroadcastController.java
+++ b/services/core/java/com/android/server/am/BroadcastController.java
@@ -303,8 +303,7 @@ class BroadcastController {
                 return null;
             }
             if (callerApp.info.uid != SYSTEM_UID
-                    && !callerApp.getPkgList().containsKey(callerPackage)
-                    && !"android".equals(callerPackage)) {
+                    && !callerApp.getPkgList().containsKey(callerPackage)) {
                 throw new SecurityException("Given caller package " + callerPackage
                         + " is not running in process " + callerApp);
             }
diff --git a/services/core/java/com/android/server/am/PendingIntentRecord.java b/services/core/java/com/android/server/am/PendingIntentRecord.java
index 6857b6bcde15..59ff9bc031f8 100644
--- a/services/core/java/com/android/server/am/PendingIntentRecord.java
+++ b/services/core/java/com/android/server/am/PendingIntentRecord.java
@@ -24,6 +24,8 @@ import static android.app.ActivityOptions.MODE_BACKGROUND_ACTIVITY_START_COMPAT;
 import static android.app.ActivityOptions.MODE_BACKGROUND_ACTIVITY_START_DENIED;
 import static android.app.ActivityOptions.MODE_BACKGROUND_ACTIVITY_START_SYSTEM_DEFINED;
 import static android.app.ActivityOptions.MODE_BACKGROUND_ACTIVITY_START_ALLOW_IF_VISIBLE;
+import static android.os.PowerWhitelistManager.TEMPORARY_ALLOWLIST_TYPE_FOREGROUND_SERVICE_ALLOWED;
+import static android.os.PowerWhitelistManager.TEMPORARY_ALLOWLIST_TYPE_FOREGROUND_SERVICE_NOT_ALLOWED;
 import static android.os.Process.ROOT_UID;
 import static android.os.Process.SYSTEM_UID;
 
@@ -305,6 +307,10 @@ public final class PendingIntentRecord extends IIntentSender.Stub {
         this.stringName = null;
     }
 
+    @VisibleForTesting TempAllowListDuration getAllowlistDurationLocked(IBinder allowlistToken) {
+        return mAllowlistDuration.get(allowlistToken);
+    }
+
     void setAllowBgActivityStarts(IBinder token, int flags) {
         if (token == null) return;
         if ((flags & FLAG_ACTIVITY_SENDER) != 0) {
@@ -323,6 +329,13 @@ public final class PendingIntentRecord extends IIntentSender.Stub {
         mAllowBgActivityStartsForActivitySender.remove(token);
         mAllowBgActivityStartsForBroadcastSender.remove(token);
         mAllowBgActivityStartsForServiceSender.remove(token);
+        if (mAllowlistDuration != null) {
+            TempAllowListDuration duration = mAllowlistDuration.get(token);
+            if (duration != null
+                    && duration.type == TEMPORARY_ALLOWLIST_TYPE_FOREGROUND_SERVICE_ALLOWED) {
+                duration.type = TEMPORARY_ALLOWLIST_TYPE_FOREGROUND_SERVICE_NOT_ALLOWED;
+            }
+        }
     }
 
     public void registerCancelListenerLocked(IResultReceiver receiver) {
@@ -693,7 +706,7 @@ public final class PendingIntentRecord extends IIntentSender.Stub {
         return res;
     }
 
-    private BackgroundStartPrivileges getBackgroundStartPrivilegesForActivitySender(
+    @VisibleForTesting BackgroundStartPrivileges getBackgroundStartPrivilegesForActivitySender(
             IBinder allowlistToken) {
         return mAllowBgActivityStartsForActivitySender.contains(allowlistToken)
                 ? BackgroundStartPrivileges.allowBackgroundActivityStarts(allowlistToken)
diff --git a/services/core/java/com/android/server/am/UserController.java b/services/core/java/com/android/server/am/UserController.java
index 262c76e4a4d7..2b41edc6b791 100644
--- a/services/core/java/com/android/server/am/UserController.java
+++ b/services/core/java/com/android/server/am/UserController.java
@@ -160,6 +160,7 @@ import java.util.concurrent.CountDownLatch;
 import java.util.concurrent.TimeUnit;
 import java.util.concurrent.atomic.AtomicBoolean;
 import java.util.concurrent.atomic.AtomicInteger;
+import java.util.function.BiConsumer;
 import java.util.function.Consumer;
 
 /**
@@ -1920,180 +1921,195 @@ class UserController implements Handler.Callback {
                 return false;
             }
 
-            boolean needStart = false;
-            boolean updateUmState = false;
-            UserState uss;
-
-            // If the user we are switching to is not currently started, then
-            // we need to start it now.
-            t.traceBegin("updateStartedUserArrayStarting");
-            synchronized (mLock) {
-                uss = mStartedUsers.get(userId);
-                if (uss == null) {
-                    uss = new UserState(UserHandle.of(userId));
-                    uss.mUnlockProgress.addListener(new UserProgressListener());
-                    mStartedUsers.put(userId, uss);
-                    updateStartedUserArrayLU();
-                    needStart = true;
-                    updateUmState = true;
-                } else if (uss.state == UserState.STATE_SHUTDOWN
-                        || mDoNotAbortShutdownUserIds.contains(userId)) {
-                    Slogf.i(TAG, "User #" + userId
-                            + " is shutting down - will start after full shutdown");
-                    mPendingUserStarts.add(new PendingUserStart(userId, userStartMode,
-                            unlockListener));
-                    t.traceEnd(); // updateStartedUserArrayStarting
-                    return true;
-                }
+            final Runnable continueStartUserInternal = () -> continueStartUserInternal(userInfo,
+                    oldUserId, userStartMode, unlockListener, callingUid, callingPid);
+            if (foreground) {
+                mHandler.post(() -> dispatchOnBeforeUserSwitching(userId, () ->
+                        mHandler.post(continueStartUserInternal)));
+            } else {
+                continueStartUserInternal.run();
             }
+        } finally {
+            Binder.restoreCallingIdentity(ident);
+        }
 
-            // No matter what, the fact that we're requested to start the user (even if it is
-            // already running) puts it towards the end of the mUserLru list.
-            addUserToUserLru(userId);
-            if (android.multiuser.Flags.scheduleStopOfBackgroundUser()) {
-                mHandler.removeEqualMessages(SCHEDULED_STOP_BACKGROUND_USER_MSG,
-                        Integer.valueOf(userId));
-            }
+        return true;
+    }
 
-            if (unlockListener != null) {
-                uss.mUnlockProgress.addListener(unlockListener);
-            }
-            t.traceEnd(); // updateStartedUserArrayStarting
+    private void continueStartUserInternal(UserInfo userInfo, int oldUserId, int userStartMode,
+            IProgressListener unlockListener, int callingUid, int callingPid) {
+        final TimingsTraceAndSlog t = new TimingsTraceAndSlog();
+        final boolean foreground = userStartMode == USER_START_MODE_FOREGROUND;
+        final int userId = userInfo.id;
 
-            if (updateUmState) {
-                t.traceBegin("setUserState");
-                mInjector.getUserManagerInternal().setUserState(userId, uss.state);
-                t.traceEnd();
-            }
-            t.traceBegin("updateConfigurationAndProfileIds");
-            if (foreground) {
-                // Make sure the old user is no longer considering the display to be on.
-                mInjector.reportGlobalUsageEvent(UsageEvents.Event.SCREEN_NON_INTERACTIVE);
-                boolean userSwitchUiEnabled;
-                synchronized (mLock) {
-                    mCurrentUserId = userId;
-                    ActivityManager.invalidateGetCurrentUserIdCache();
-                    userSwitchUiEnabled = mUserSwitchUiEnabled;
-                }
-                mInjector.updateUserConfiguration();
-                // NOTE: updateProfileRelatedCaches() is called on both if and else parts, ideally
-                // it should be moved outside, but for now it's not as there are many calls to
-                // external components here afterwards
-                updateProfileRelatedCaches();
-                dispatchOnBeforeUserSwitching(userId);
-                mInjector.getWindowManager().setCurrentUser(userId);
-                mInjector.reportCurWakefulnessUsageEvent();
-                // Once the internal notion of the active user has switched, we lock the device
-                // with the option to show the user switcher on the keyguard.
-                if (userSwitchUiEnabled) {
-                    mInjector.getWindowManager().setSwitchingUser(true);
-                    // Only lock if the user has a secure keyguard PIN/Pattern/Pwd
-                    if (mInjector.getKeyguardManager().isDeviceSecure(userId)) {
-                        // Make sure the device is locked before moving on with the user switch
-                        mInjector.lockDeviceNowAndWaitForKeyguardShown();
-                    }
-                }
+        boolean needStart = false;
+        boolean updateUmState = false;
+        UserState uss;
 
-            } else {
-                updateProfileRelatedCaches();
-                // We are starting a non-foreground user. They have already been added to the end
-                // of mUserLru, so we need to ensure that the foreground user isn't displaced.
-                addUserToUserLru(mCurrentUserId);
-            }
-            if (userStartMode == USER_START_MODE_BACKGROUND && !userInfo.isProfile()) {
-                scheduleStopOfBackgroundUser(userId);
+        // If the user we are switching to is not currently started, then
+        // we need to start it now.
+        t.traceBegin("updateStartedUserArrayStarting");
+        synchronized (mLock) {
+            uss = mStartedUsers.get(userId);
+            if (uss == null) {
+                uss = new UserState(UserHandle.of(userId));
+                uss.mUnlockProgress.addListener(new UserProgressListener());
+                mStartedUsers.put(userId, uss);
+                updateStartedUserArrayLU();
+                needStart = true;
+                updateUmState = true;
+            } else if (uss.state == UserState.STATE_SHUTDOWN
+                    || mDoNotAbortShutdownUserIds.contains(userId)) {
+                Slogf.i(TAG, "User #" + userId
+                        + " is shutting down - will start after full shutdown");
+                mPendingUserStarts.add(new PendingUserStart(userId, userStartMode,
+                        unlockListener));
+                t.traceEnd(); // updateStartedUserArrayStarting
+                return;
             }
-            t.traceEnd();
+        }
 
-            // Make sure user is in the started state.  If it is currently
-            // stopping, we need to knock that off.
-            if (uss.state == UserState.STATE_STOPPING) {
-                t.traceBegin("updateStateStopping");
-                // If we are stopping, we haven't sent ACTION_SHUTDOWN,
-                // so we can just fairly silently bring the user back from
-                // the almost-dead.
-                uss.setState(uss.lastState);
-                mInjector.getUserManagerInternal().setUserState(userId, uss.state);
-                synchronized (mLock) {
-                    updateStartedUserArrayLU();
-                }
-                needStart = true;
-                t.traceEnd();
-            } else if (uss.state == UserState.STATE_SHUTDOWN) {
-                t.traceBegin("updateStateShutdown");
-                // This means ACTION_SHUTDOWN has been sent, so we will
-                // need to treat this as a new boot of the user.
-                uss.setState(UserState.STATE_BOOTING);
-                mInjector.getUserManagerInternal().setUserState(userId, uss.state);
-                synchronized (mLock) {
-                    updateStartedUserArrayLU();
+        // No matter what, the fact that we're requested to start the user (even if it is
+        // already running) puts it towards the end of the mUserLru list.
+        addUserToUserLru(userId);
+        if (android.multiuser.Flags.scheduleStopOfBackgroundUser()) {
+            mHandler.removeEqualMessages(SCHEDULED_STOP_BACKGROUND_USER_MSG,
+                    Integer.valueOf(userId));
+        }
+
+        if (unlockListener != null) {
+            uss.mUnlockProgress.addListener(unlockListener);
+        }
+        t.traceEnd(); // updateStartedUserArrayStarting
+
+        if (updateUmState) {
+            t.traceBegin("setUserState");
+            mInjector.getUserManagerInternal().setUserState(userId, uss.state);
+            t.traceEnd();
+        }
+        t.traceBegin("updateConfigurationAndProfileIds");
+        if (foreground) {
+            // Make sure the old user is no longer considering the display to be on.
+            mInjector.reportGlobalUsageEvent(UsageEvents.Event.SCREEN_NON_INTERACTIVE);
+            boolean userSwitchUiEnabled;
+            synchronized (mLock) {
+                mCurrentUserId = userId;
+                ActivityManager.invalidateGetCurrentUserIdCache();
+                userSwitchUiEnabled = mUserSwitchUiEnabled;
+            }
+            mInjector.updateUserConfiguration();
+            // NOTE: updateProfileRelatedCaches() is called on both if and else parts, ideally
+            // it should be moved outside, but for now it's not as there are many calls to
+            // external components here afterwards
+            updateProfileRelatedCaches();
+            mInjector.getWindowManager().setCurrentUser(userId);
+            mInjector.reportCurWakefulnessUsageEvent();
+            // Once the internal notion of the active user has switched, we lock the device
+            // with the option to show the user switcher on the keyguard.
+            if (userSwitchUiEnabled) {
+                mInjector.getWindowManager().setSwitchingUser(true);
+                // Only lock if the user has a secure keyguard PIN/Pattern/Pwd
+                if (mInjector.getKeyguardManager().isDeviceSecure(userId)) {
+                    // Make sure the device is locked before moving on with the user switch
+                    mInjector.lockDeviceNowAndWaitForKeyguardShown();
                 }
-                needStart = true;
-                t.traceEnd();
             }
 
-            if (uss.state == UserState.STATE_BOOTING) {
-                t.traceBegin("updateStateBooting");
-                // Give user manager a chance to propagate user restrictions
-                // to other services and prepare app storage
-                mInjector.getUserManager().onBeforeStartUser(userId);
+        } else {
+            updateProfileRelatedCaches();
+            // We are starting a non-foreground user. They have already been added to the end
+            // of mUserLru, so we need to ensure that the foreground user isn't displaced.
+            addUserToUserLru(mCurrentUserId);
+        }
+        if (userStartMode == USER_START_MODE_BACKGROUND && !userInfo.isProfile()) {
+            scheduleStopOfBackgroundUser(userId);
+        }
+        t.traceEnd();
 
-                // Booting up a new user, need to tell system services about it.
-                // Note that this is on the same handler as scheduling of broadcasts,
-                // which is important because it needs to go first.
-                mHandler.sendMessage(mHandler.obtainMessage(USER_START_MSG, userId, NO_ARG2));
-                t.traceEnd();
+        // Make sure user is in the started state.  If it is currently
+        // stopping, we need to knock that off.
+        if (uss.state == UserState.STATE_STOPPING) {
+            t.traceBegin("updateStateStopping");
+            // If we are stopping, we haven't sent ACTION_SHUTDOWN,
+            // so we can just fairly silently bring the user back from
+            // the almost-dead.
+            uss.setState(uss.lastState);
+            mInjector.getUserManagerInternal().setUserState(userId, uss.state);
+            synchronized (mLock) {
+                updateStartedUserArrayLU();
             }
-
-            t.traceBegin("sendMessages");
-            if (foreground) {
-                mHandler.sendMessage(mHandler.obtainMessage(USER_CURRENT_MSG, userId, oldUserId));
-                mHandler.removeMessages(REPORT_USER_SWITCH_MSG);
-                mHandler.removeMessages(USER_SWITCH_TIMEOUT_MSG);
-                mHandler.sendMessage(mHandler.obtainMessage(REPORT_USER_SWITCH_MSG,
-                        oldUserId, userId, uss));
-                mHandler.sendMessageDelayed(mHandler.obtainMessage(USER_SWITCH_TIMEOUT_MSG,
-                        oldUserId, userId, uss), getUserSwitchTimeoutMs());
+            needStart = true;
+            t.traceEnd();
+        } else if (uss.state == UserState.STATE_SHUTDOWN) {
+            t.traceBegin("updateStateShutdown");
+            // This means ACTION_SHUTDOWN has been sent, so we will
+            // need to treat this as a new boot of the user.
+            uss.setState(UserState.STATE_BOOTING);
+            mInjector.getUserManagerInternal().setUserState(userId, uss.state);
+            synchronized (mLock) {
+                updateStartedUserArrayLU();
             }
+            needStart = true;
+            t.traceEnd();
+        }
 
-            if (userInfo.preCreated) {
-                needStart = false;
-            }
+        if (uss.state == UserState.STATE_BOOTING) {
+            t.traceBegin("updateStateBooting");
+            // Give user manager a chance to propagate user restrictions
+            // to other services and prepare app storage
+            mInjector.getUserManager().onBeforeStartUser(userId);
 
-            // In most cases, broadcast for the system user starting/started is sent by
-            // ActivityManagerService#systemReady(). However on some HSUM devices (e.g. tablets)
-            // the user switches from the system user to a secondary user while running
-            // ActivityManagerService#systemReady(), thus broadcast is not sent for the system user.
-            // Therefore we send the broadcast for the system user here as well in HSUM.
-            // TODO(b/266158156): Improve/refactor the way broadcasts are sent for the system user
-            // in HSUM. Ideally it'd be best to have one single place that sends this notification.
-            final boolean isSystemUserInHeadlessMode = (userId == UserHandle.USER_SYSTEM)
-                    && mInjector.isHeadlessSystemUserMode();
-            if (needStart || isSystemUserInHeadlessMode) {
-                sendUserStartedBroadcast(userId, callingUid, callingPid);
-            }
+            // Booting up a new user, need to tell system services about it.
+            // Note that this is on the same handler as scheduling of broadcasts,
+            // which is important because it needs to go first.
+            mHandler.sendMessage(mHandler.obtainMessage(USER_START_MSG, userId, NO_ARG2));
             t.traceEnd();
+        }
 
-            if (foreground) {
-                t.traceBegin("moveUserToForeground");
-                moveUserToForeground(uss, userId);
-                t.traceEnd();
-            } else {
-                t.traceBegin("finishUserBoot");
-                finishUserBoot(uss);
-                t.traceEnd();
-            }
+        t.traceBegin("sendMessages");
+        if (foreground) {
+            mHandler.sendMessage(mHandler.obtainMessage(USER_CURRENT_MSG, userId, oldUserId));
+            mHandler.removeMessages(REPORT_USER_SWITCH_MSG);
+            mHandler.removeMessages(USER_SWITCH_TIMEOUT_MSG);
+            mHandler.sendMessage(mHandler.obtainMessage(REPORT_USER_SWITCH_MSG,
+                    oldUserId, userId, uss));
+            mHandler.sendMessageDelayed(mHandler.obtainMessage(USER_SWITCH_TIMEOUT_MSG,
+                    oldUserId, userId, uss), getUserSwitchTimeoutMs());
+        }
 
-            if (needStart || isSystemUserInHeadlessMode) {
-                t.traceBegin("sendRestartBroadcast");
-                sendUserStartingBroadcast(userId, callingUid, callingPid);
-                t.traceEnd();
-            }
-        } finally {
-            Binder.restoreCallingIdentity(ident);
+        if (userInfo.preCreated) {
+            needStart = false;
         }
 
-        return true;
+        // In most cases, broadcast for the system user starting/started is sent by
+        // ActivityManagerService#systemReady(). However on some HSUM devices (e.g. tablets)
+        // the user switches from the system user to a secondary user while running
+        // ActivityManagerService#systemReady(), thus broadcast is not sent for the system user.
+        // Therefore we send the broadcast for the system user here as well in HSUM.
+        // TODO(b/266158156): Improve/refactor the way broadcasts are sent for the system user
+        // in HSUM. Ideally it'd be best to have one single place that sends this notification.
+        final boolean isSystemUserInHeadlessMode = (userId == UserHandle.USER_SYSTEM)
+                && mInjector.isHeadlessSystemUserMode();
+        if (needStart || isSystemUserInHeadlessMode) {
+            sendUserStartedBroadcast(userId, callingUid, callingPid);
+        }
+        t.traceEnd();
+
+        if (foreground) {
+            t.traceBegin("moveUserToForeground");
+            moveUserToForeground(uss, userId);
+            t.traceEnd();
+        } else {
+            t.traceBegin("finishUserBoot");
+            finishUserBoot(uss);
+            t.traceEnd();
+        }
+
+        if (needStart || isSystemUserInHeadlessMode) {
+            t.traceBegin("sendRestartBroadcast");
+            sendUserStartingBroadcast(userId, callingUid, callingPid);
+            t.traceEnd();
+        }
     }
 
     /**
@@ -2286,25 +2302,42 @@ class UserController implements Handler.Callback {
         mUserSwitchObservers.finishBroadcast();
     }
 
-    private void dispatchOnBeforeUserSwitching(@UserIdInt int newUserId) {
+    private void dispatchOnBeforeUserSwitching(@UserIdInt int newUserId, Runnable onComplete) {
         final TimingsTraceAndSlog t = new TimingsTraceAndSlog();
         t.traceBegin("dispatchOnBeforeUserSwitching-" + newUserId);
-        final int observerCount = mUserSwitchObservers.beginBroadcast();
-        for (int i = 0; i < observerCount; i++) {
-            final String name = "#" + i + " " + mUserSwitchObservers.getBroadcastCookie(i);
-            t.traceBegin("onBeforeUserSwitching-" + name);
+        final AtomicBoolean isFirst = new AtomicBoolean(true);
+        startTimeoutForOnBeforeUserSwitching(isFirst, onComplete);
+        informUserSwitchObservers((observer, callback) -> {
             try {
-                mUserSwitchObservers.getBroadcastItem(i).onBeforeUserSwitching(newUserId);
+                observer.onBeforeUserSwitching(newUserId, callback);
             } catch (RemoteException e) {
-                // Ignore
-            } finally {
-                t.traceEnd();
+                // ignore
             }
-        }
-        mUserSwitchObservers.finishBroadcast();
+        }, () -> {
+            if (isFirst.getAndSet(false)) {
+                onComplete.run();
+            }
+        }, "onBeforeUserSwitching");
         t.traceEnd();
     }
 
+    private void startTimeoutForOnBeforeUserSwitching(AtomicBoolean isFirst,
+            Runnable onComplete) {
+        final long timeout = getUserSwitchTimeoutMs();
+        mHandler.postDelayed(() -> {
+            if (isFirst.getAndSet(false)) {
+                String unresponsiveObservers;
+                synchronized (mLock) {
+                    unresponsiveObservers = String.join(", ", mCurWaitingUserSwitchCallbacks);
+                }
+                Slogf.e(TAG, "Timeout on dispatchOnBeforeUserSwitching. These UserSwitchObservers "
+                        + "did not respond in " + timeout + "ms: " + unresponsiveObservers + ".");
+                onComplete.run();
+            }
+        }, timeout);
+    }
+
+
     /** Called on handler thread */
     @VisibleForTesting
     void dispatchUserSwitchComplete(@UserIdInt int oldUserId, @UserIdInt int newUserId) {
@@ -2517,70 +2550,76 @@ class UserController implements Handler.Callback {
         t.traceBegin("dispatchUserSwitch-" + oldUserId + "-to-" + newUserId);
 
         EventLog.writeEvent(EventLogTags.UC_DISPATCH_USER_SWITCH, oldUserId, newUserId);
+        uss.switching = true;
+        informUserSwitchObservers((observer, callback) -> {
+            try {
+                observer.onUserSwitching(newUserId, callback);
+            } catch (RemoteException e) {
+                // ignore
+            }
+        }, () -> {
+            synchronized (mLock) {
+                sendContinueUserSwitchLU(uss, oldUserId, newUserId);
+            }
+        }, "onUserSwitching");
+        t.traceEnd();
+    }
 
+    void informUserSwitchObservers(BiConsumer<IUserSwitchObserver, IRemoteCallback> consumer,
+            final Runnable onComplete, String trace) {
         final int observerCount = mUserSwitchObservers.beginBroadcast();
-        if (observerCount > 0) {
-            final ArraySet<String> curWaitingUserSwitchCallbacks = new ArraySet<>();
+        if (observerCount == 0) {
+            onComplete.run();
+            mUserSwitchObservers.finishBroadcast();
+            return;
+        }
+        final ArraySet<String> curWaitingUserSwitchCallbacks = new ArraySet<>();
+        synchronized (mLock) {
+            mCurWaitingUserSwitchCallbacks = curWaitingUserSwitchCallbacks;
+        }
+        final AtomicInteger waitingCallbacksCount = new AtomicInteger(observerCount);
+        final long userSwitchTimeoutMs = getUserSwitchTimeoutMs();
+        final long dispatchStartedTime = SystemClock.elapsedRealtime();
+        for (int i = 0; i < observerCount; i++) {
+            final long dispatchStartedTimeForObserver = SystemClock.elapsedRealtime();
+            // Prepend with unique prefix to guarantee that keys are unique
+            final String name = "#" + i + " " + mUserSwitchObservers.getBroadcastCookie(i);
             synchronized (mLock) {
-                uss.switching = true;
-                mCurWaitingUserSwitchCallbacks = curWaitingUserSwitchCallbacks;
-            }
-            final AtomicInteger waitingCallbacksCount = new AtomicInteger(observerCount);
-            final long userSwitchTimeoutMs = getUserSwitchTimeoutMs();
-            final long dispatchStartedTime = SystemClock.elapsedRealtime();
-            for (int i = 0; i < observerCount; i++) {
-                final long dispatchStartedTimeForObserver = SystemClock.elapsedRealtime();
-                try {
-                    // Prepend with unique prefix to guarantee that keys are unique
-                    final String name = "#" + i + " " + mUserSwitchObservers.getBroadcastCookie(i);
+                curWaitingUserSwitchCallbacks.add(name);
+            }
+            final IRemoteCallback callback = new IRemoteCallback.Stub() {
+                @Override
+                public void sendResult(Bundle data) throws RemoteException {
+                    asyncTraceEnd(trace + "-" + name, 0);
                     synchronized (mLock) {
-                        curWaitingUserSwitchCallbacks.add(name);
-                    }
-                    final IRemoteCallback callback = new IRemoteCallback.Stub() {
-                        @Override
-                        public void sendResult(Bundle data) throws RemoteException {
-                            asyncTraceEnd("onUserSwitching-" + name, newUserId);
-                            synchronized (mLock) {
-                                long delayForObserver = SystemClock.elapsedRealtime()
-                                        - dispatchStartedTimeForObserver;
-                                if (delayForObserver > LONG_USER_SWITCH_OBSERVER_WARNING_TIME_MS) {
-                                    Slogf.w(TAG, "User switch slowed down by observer " + name
-                                            + ": result took " + delayForObserver
-                                            + " ms to process.");
-                                }
-
-                                long totalDelay = SystemClock.elapsedRealtime()
-                                        - dispatchStartedTime;
-                                if (totalDelay > userSwitchTimeoutMs) {
-                                    Slogf.e(TAG, "User switch timeout: observer " + name
-                                            + "'s result was received " + totalDelay
-                                            + " ms after dispatchUserSwitch.");
-                                }
-
-                                curWaitingUserSwitchCallbacks.remove(name);
-                                // Continue switching if all callbacks have been notified and
-                                // user switching session is still valid
-                                if (waitingCallbacksCount.decrementAndGet() == 0
-                                        && (curWaitingUserSwitchCallbacks
-                                        == mCurWaitingUserSwitchCallbacks)) {
-                                    sendContinueUserSwitchLU(uss, oldUserId, newUserId);
-                                }
-                            }
+                        long delayForObserver = SystemClock.elapsedRealtime()
+                                - dispatchStartedTimeForObserver;
+                        if (delayForObserver > LONG_USER_SWITCH_OBSERVER_WARNING_TIME_MS) {
+                            Slogf.w(TAG, "User switch slowed down by observer " + name
+                                    + ": result took " + delayForObserver
+                                    + " ms to process. " + trace);
                         }
-                    };
-                    asyncTraceBegin("onUserSwitching-" + name, newUserId);
-                    mUserSwitchObservers.getBroadcastItem(i).onUserSwitching(newUserId, callback);
-                } catch (RemoteException e) {
-                    // Ignore
+                        long totalDelay = SystemClock.elapsedRealtime() - dispatchStartedTime;
+                        if (totalDelay > userSwitchTimeoutMs) {
+                            Slogf.e(TAG, "User switch timeout: observer " + name
+                                    + "'s result was received " + totalDelay
+                                    + " ms after dispatchUserSwitch. " + trace);
+                        }
+                        curWaitingUserSwitchCallbacks.remove(name);
+                        // Continue switching if all callbacks have been notified and
+                        // user switching session is still valid
+                        if (waitingCallbacksCount.decrementAndGet() == 0
+                                && (curWaitingUserSwitchCallbacks
+                                == mCurWaitingUserSwitchCallbacks)) {
+                            onComplete.run();
+                        }
+                    }
                 }
-            }
-        } else {
-            synchronized (mLock) {
-                sendContinueUserSwitchLU(uss, oldUserId, newUserId);
-            }
+            };
+            asyncTraceBegin(trace + "-" + name, 0);
+            consumer.accept(mUserSwitchObservers.getBroadcastItem(i), callback);
         }
         mUserSwitchObservers.finishBroadcast();
-        t.traceEnd(); // end dispatchUserSwitch-
     }
 
     @GuardedBy("mLock")
diff --git a/services/core/java/com/android/server/appop/AppOpsService.java b/services/core/java/com/android/server/appop/AppOpsService.java
index 61dec12d74e5..a8a31dc6e145 100644
--- a/services/core/java/com/android/server/appop/AppOpsService.java
+++ b/services/core/java/com/android/server/appop/AppOpsService.java
@@ -172,6 +172,7 @@ import com.android.server.SystemServiceManager;
 import com.android.server.companion.virtual.VirtualDeviceManagerInternal;
 import com.android.server.pm.PackageList;
 import com.android.server.pm.PackageManagerLocal;
+import com.android.server.pm.ProtectedPackages;
 import com.android.server.pm.UserManagerInternal;
 import com.android.server.pm.pkg.AndroidPackage;
 import com.android.server.pm.pkg.PackageState;
@@ -226,6 +227,13 @@ public class AppOpsService extends IAppOpsService.Stub {
      */
     private static final int CURRENT_VERSION = 1;
 
+    /**
+     * The upper limit of total number of attributed op entries that can be returned in a binder
+     * transaction to avoid TransactionTooLargeException
+     */
+    private static final int NUM_ATTRIBUTED_OP_ENTRY_THRESHOLD = 2000;
+
+
     private SensorPrivacyManager mSensorPrivacyManager;
 
     // Write at most every 30 minutes.
@@ -291,6 +299,8 @@ public class AppOpsService extends IAppOpsService.Stub {
     private final IPlatformCompat mPlatformCompat = IPlatformCompat.Stub.asInterface(
             ServiceManager.getService(Context.PLATFORM_COMPAT_SERVICE));
 
+    private ProtectedPackages mProtectedPackages;
+
     /**
      * Registered callbacks, called from {@link #collectAsyncNotedOp}.
      *
@@ -1675,6 +1685,8 @@ public class AppOpsService extends IAppOpsService.Stub {
                 Manifest.permission.GET_APP_OPS_STATS,
                 Binder.getCallingPid(), Binder.getCallingUid())
                 == PackageManager.PERMISSION_GRANTED;
+        int totalAttributedOpEntryCount = 0;
+
         if (ops == null) {
             resOps = new ArrayList<>();
             for (int j = 0; j < pkgOps.size(); j++) {
@@ -1682,7 +1694,12 @@ public class AppOpsService extends IAppOpsService.Stub {
                 if (opRestrictsRead(curOp.op) && !shouldReturnRestrictedAppOps) {
                     continue;
                 }
-                resOps.add(getOpEntryForResult(curOp, persistentDeviceId));
+                if (totalAttributedOpEntryCount > NUM_ATTRIBUTED_OP_ENTRY_THRESHOLD) {
+                    break;
+                }
+                OpEntry opEntry = getOpEntryForResult(curOp, persistentDeviceId);
+                resOps.add(opEntry);
+                totalAttributedOpEntryCount += opEntry.getAttributedOpEntries().size();
             }
         } else {
             for (int j = 0; j < ops.length; j++) {
@@ -1694,10 +1711,21 @@ public class AppOpsService extends IAppOpsService.Stub {
                     if (opRestrictsRead(curOp.op) && !shouldReturnRestrictedAppOps) {
                         continue;
                     }
-                    resOps.add(getOpEntryForResult(curOp, persistentDeviceId));
+                    if (totalAttributedOpEntryCount > NUM_ATTRIBUTED_OP_ENTRY_THRESHOLD) {
+                        break;
+                    }
+                    OpEntry opEntry = getOpEntryForResult(curOp, persistentDeviceId);
+                    resOps.add(opEntry);
+                    totalAttributedOpEntryCount += opEntry.getAttributedOpEntries().size();
                 }
             }
         }
+
+        if (totalAttributedOpEntryCount > NUM_ATTRIBUTED_OP_ENTRY_THRESHOLD) {
+            Slog.w(TAG, "The number of attributed op entries has exceeded the threshold. This "
+                    + "could be due to DoS attack from malicious apps. The result is throttled.");
+        }
+
         return resOps;
     }
 
@@ -2050,6 +2078,12 @@ public class AppOpsService extends IAppOpsService.Stub {
 
         enforceManageAppOpsModes(Binder.getCallingPid(), Binder.getCallingUid(), uid);
         verifyIncomingOp(code);
+
+        if (isDeviceProvisioningPackage(uid, null)) {
+            Slog.w(TAG, "Cannot set uid mode for device provisioning app by Shell");
+            return;
+        }
+
         code = AppOpsManager.opToSwitch(code);
 
         if (permissionPolicyCallback == null) {
@@ -2360,6 +2394,11 @@ public class AppOpsService extends IAppOpsService.Stub {
             return;
         }
 
+        if (isDeviceProvisioningPackage(uid, packageName)) {
+            Slog.w(TAG, "Cannot set op mode for device provisioning app by Shell");
+            return;
+        }
+
         code = AppOpsManager.opToSwitch(code);
 
         PackageVerificationResult pvr;
@@ -2390,6 +2429,36 @@ public class AppOpsService extends IAppOpsService.Stub {
         notifyStorageManagerOpModeChangedSync(code, uid, packageName, mode, previousMode);
     }
 
+    // Device provisioning package is restricted from setting app op mode through shell command
+    private boolean isDeviceProvisioningPackage(int uid,
+            @Nullable String packageName) {
+        if (UserHandle.getAppId(Binder.getCallingUid()) == Process.SHELL_UID) {
+            ProtectedPackages protectedPackages = getProtectedPackages();
+
+            if (packageName != null && protectedPackages.isDeviceProvisioningPackage(packageName)) {
+                return true;
+            }
+
+            String[] packageNames = mContext.getPackageManager().getPackagesForUid(uid);
+            if (packageNames != null) {
+                for (String pkg : packageNames) {
+                    if (protectedPackages.isDeviceProvisioningPackage(pkg)) {
+                        return true;
+                    }
+                }
+            }
+        }
+        return false;
+    }
+
+    // Race condition is allowed here for better performance
+    private ProtectedPackages getProtectedPackages() {
+        if (mProtectedPackages == null) {
+            mProtectedPackages = new ProtectedPackages(mContext);
+        }
+        return mProtectedPackages;
+    }
+
     private void notifyOpChanged(ArraySet<OnOpModeChangedListener> callbacks, int code,
             int uid, String packageName, String persistentDeviceId) {
         for (int i = 0; i < callbacks.size(); i++) {
diff --git a/services/core/java/com/android/server/appop/AppOpsUidStateTrackerImpl.java b/services/core/java/com/android/server/appop/AppOpsUidStateTrackerImpl.java
index 03c81560be89..ed41f2e881f8 100644
--- a/services/core/java/com/android/server/appop/AppOpsUidStateTrackerImpl.java
+++ b/services/core/java/com/android/server/appop/AppOpsUidStateTrackerImpl.java
@@ -36,6 +36,7 @@ import static android.app.AppOpsManager.UID_STATE_FOREGROUND_SERVICE;
 import static android.app.AppOpsManager.UID_STATE_MAX_LAST_NON_RESTRICTED;
 import static android.app.AppOpsManager.UID_STATE_NONEXISTENT;
 import static android.app.AppOpsManager.UID_STATE_TOP;
+import static android.permission.flags.Flags.delayUidStateChangesFromCapabilityUpdates;
 import static android.permission.flags.Flags.finishRunningOpsForKilledPackages;
 
 import static com.android.server.appop.AppOpsUidStateTracker.processStateToUidState;
@@ -236,20 +237,26 @@ class AppOpsUidStateTrackerImpl implements AppOpsUidStateTracker {
             mPendingUidStates.put(uid, uidState);
             mPendingCapability.put(uid, capability);
 
+            boolean hasLostCapability = (prevCapability & ~capability) != 0;
+
             if (procState == PROCESS_STATE_NONEXISTENT) {
                 mPendingGone.put(uid, true);
                 commitUidPendingState(uid);
-            } else if (uidState < prevUidState
-                    || (uidState <= UID_STATE_MAX_LAST_NON_RESTRICTED
-                    && prevUidState > UID_STATE_MAX_LAST_NON_RESTRICTED)) {
+            } else if (uidState < prevUidState) {
                 // We are moving to a more important state, or the new state may be in the
                 // foreground and the old state is in the background, then always do it
                 // immediately.
                 commitUidPendingState(uid);
-            } else if (uidState == prevUidState && capability != prevCapability) {
+            } else if (delayUidStateChangesFromCapabilityUpdates()
+                    && uidState == prevUidState && !hasLostCapability) {
+                // No change on process state, but process capability hasn't decreased.
+                commitUidPendingState(uid);
+            } else if (!delayUidStateChangesFromCapabilityUpdates()
+                    && uidState == prevUidState && capability != prevCapability) {
                 // No change on process state, but process capability has changed.
                 commitUidPendingState(uid);
-            } else if (uidState <= UID_STATE_MAX_LAST_NON_RESTRICTED) {
+            } else if (uidState <= UID_STATE_MAX_LAST_NON_RESTRICTED
+                    && (!delayUidStateChangesFromCapabilityUpdates() || !hasLostCapability)) {
                 // We are moving to a less important state, but it doesn't cross the restriction
                 // threshold.
                 commitUidPendingState(uid);
diff --git a/services/core/java/com/android/server/pm/ProtectedPackages.java b/services/core/java/com/android/server/pm/ProtectedPackages.java
index 524252c1469f..e71588168972 100644
--- a/services/core/java/com/android/server/pm/ProtectedPackages.java
+++ b/services/core/java/com/android/server/pm/ProtectedPackages.java
@@ -20,6 +20,7 @@ import android.annotation.Nullable;
 import android.annotation.UserIdInt;
 import android.content.Context;
 import android.os.UserHandle;
+import android.text.TextUtils;
 import android.util.ArraySet;
 import android.util.SparseArray;
 
@@ -27,6 +28,7 @@ import com.android.internal.R;
 import com.android.internal.annotations.GuardedBy;
 
 import java.util.List;
+import java.util.Objects;
 import java.util.Set;
 
 /**
@@ -164,4 +166,13 @@ public class ProtectedPackages {
         return hasDeviceOwnerOrProfileOwner(userId, packageName)
                 || isProtectedPackage(userId, packageName);
     }
+
+    /**
+     * Returns {@code true} if a given package is the device provisioning package. Otherwise,
+     * returns {@code false}.
+     */
+    public synchronized boolean isDeviceProvisioningPackage(String packageName) {
+        return !TextUtils.isEmpty(mDeviceProvisioningPackage) && Objects.equals(
+                mDeviceProvisioningPackage, packageName);
+    }
 }
diff --git a/services/core/java/com/android/server/wm/ActivityStartInterceptor.java b/services/core/java/com/android/server/wm/ActivityStartInterceptor.java
index 1a9d21187ddb..5cc186c40b6c 100644
--- a/services/core/java/com/android/server/wm/ActivityStartInterceptor.java
+++ b/services/core/java/com/android/server/wm/ActivityStartInterceptor.java
@@ -16,6 +16,7 @@
 
 package com.android.server.wm;
 
+import static android.Manifest.permission.MANAGE_ACTIVITY_TASKS;
 import static android.app.ActivityManager.INTENT_SENDER_ACTIVITY;
 import static android.app.ActivityOptions.ANIM_OPEN_CROSS_PROFILE_APPS;
 import static android.app.ActivityOptions.MODE_BACKGROUND_ACTIVITY_START_ALLOWED;
@@ -25,6 +26,9 @@ import static android.app.PendingIntent.FLAG_ONE_SHOT;
 import static android.app.admin.DevicePolicyManager.EXTRA_RESTRICTION;
 import static android.app.admin.DevicePolicyManager.POLICY_SUSPEND_PACKAGES;
 import static android.content.Context.KEYGUARD_SERVICE;
+import static android.content.Intent.ACTION_MAIN;
+import static android.content.Intent.CATEGORY_HOME;
+import static android.content.Intent.CATEGORY_SECONDARY_HOME;
 import static android.content.Intent.EXTRA_INTENT;
 import static android.content.Intent.EXTRA_PACKAGE_NAME;
 import static android.content.Intent.EXTRA_TASK_ID;
@@ -32,6 +36,7 @@ import static android.content.Intent.FLAG_ACTIVITY_EXCLUDE_FROM_RECENTS;
 import static android.content.Intent.FLAG_ACTIVITY_NEW_TASK;
 import static android.content.Intent.FLAG_ACTIVITY_TASK_ON_HOME;
 import static android.content.pm.ApplicationInfo.FLAG_SUSPENDED;
+import static android.content.pm.PackageManager.PERMISSION_GRANTED;
 
 import static com.android.server.pm.PackageManagerService.PLATFORM_PACKAGE_NAME;
 
@@ -40,6 +45,7 @@ import android.app.ActivityOptions;
 import android.app.KeyguardManager;
 import android.app.TaskInfo;
 import android.app.admin.DevicePolicyManagerInternal;
+import android.content.ComponentName;
 import android.content.Context;
 import android.content.IIntentSender;
 import android.content.Intent;
@@ -119,6 +125,11 @@ class ActivityStartInterceptor {
      */
     TaskDisplayArea mPresumableLaunchDisplayArea;
 
+    /**
+     * Whether the component is specified originally in the given Intent.
+     */
+    boolean mComponentSpecified;
+
     ActivityStartInterceptor(
             ActivityTaskManagerService service, ActivityTaskSupervisor supervisor) {
         this(service, supervisor, service.mContext);
@@ -185,6 +196,14 @@ class ActivityStartInterceptor {
         return TaskFragment.fromTaskFragmentToken(taskFragToken, mService);
     }
 
+    // TODO: consolidate this method with the one below since this is used for test only.
+    boolean intercept(Intent intent, ResolveInfo rInfo, ActivityInfo aInfo, String resolvedType,
+            Task inTask, TaskFragment inTaskFragment, int callingPid, int callingUid,
+            ActivityOptions activityOptions, TaskDisplayArea presumableLaunchDisplayArea) {
+        return intercept(intent, rInfo, aInfo, resolvedType, inTask, inTaskFragment, callingPid,
+                callingUid, activityOptions, presumableLaunchDisplayArea, false);
+    }
+
     /**
      * Intercept the launch intent based on various signals. If an interception happened the
      * internal variables get assigned and need to be read explicitly by the caller.
@@ -193,7 +212,8 @@ class ActivityStartInterceptor {
      */
     boolean intercept(Intent intent, ResolveInfo rInfo, ActivityInfo aInfo, String resolvedType,
             Task inTask, TaskFragment inTaskFragment, int callingPid, int callingUid,
-            ActivityOptions activityOptions, TaskDisplayArea presumableLaunchDisplayArea) {
+            ActivityOptions activityOptions, TaskDisplayArea presumableLaunchDisplayArea,
+            boolean componentSpecified) {
         mUserManager = UserManager.get(mServiceContext);
 
         mIntent = intent;
@@ -206,6 +226,7 @@ class ActivityStartInterceptor {
         mInTaskFragment = inTaskFragment;
         mActivityOptions = activityOptions;
         mPresumableLaunchDisplayArea = presumableLaunchDisplayArea;
+        mComponentSpecified = componentSpecified;
 
         if (interceptQuietProfileIfNeeded()) {
             // If work profile is turned off, skip the work challenge since the profile can only
@@ -230,7 +251,8 @@ class ActivityStartInterceptor {
         }
         if (interceptHomeIfNeeded()) {
             // Replace primary home intents directed at displays that do not support primary home
-            // but support secondary home with the relevant secondary home activity.
+            // but support secondary home with the relevant secondary home activity. Or the home
+            // intent is not in the correct format.
             return true;
         }
 
@@ -479,9 +501,80 @@ class ActivityStartInterceptor {
         if (mPresumableLaunchDisplayArea == null || mService.mRootWindowContainer == null) {
             return false;
         }
-        if (!ActivityRecord.isHomeIntent(mIntent)) {
+
+        boolean intercepted = false;
+        if (!ACTION_MAIN.equals(mIntent.getAction()) || (!mIntent.hasCategory(CATEGORY_HOME)
+                && !mIntent.hasCategory(CATEGORY_SECONDARY_HOME))) {
+            // not a home intent
             return false;
         }
+
+        if (mComponentSpecified) {
+            Slog.w(TAG, "Starting home with component specified, uid=" + mCallingUid);
+            if (mService.isCallerRecents(mCallingUid)
+                    || ActivityTaskManagerService.checkPermission(MANAGE_ACTIVITY_TASKS,
+                    mCallingPid, mCallingUid) == PERMISSION_GRANTED) {
+                // Allow home component specified from trusted callers.
+                return false;
+            }
+
+            final ComponentName homeComponent = mIntent.getComponent();
+            final Intent homeIntent = mService.getHomeIntent();
+            final ActivityInfo aInfo = mService.mRootWindowContainer.resolveHomeActivity(
+                    mUserId, homeIntent);
+            if (!aInfo.getComponentName().equals(homeComponent)) {
+                // Do nothing if the intent is not for the default home component.
+                return false;
+            }
+        }
+
+        if (!ActivityRecord.isHomeIntent(mIntent) || mComponentSpecified) {
+            // This is not a standard home intent, make it so if possible.
+            normalizeHomeIntent();
+            intercepted = true;
+        }
+
+        intercepted |= replaceToSecondaryHomeIntentIfNeeded();
+        if (intercepted) {
+            mCallingPid = mRealCallingPid;
+            mCallingUid = mRealCallingUid;
+            mResolvedType = null;
+
+            mRInfo = mSupervisor.resolveIntent(mIntent, mResolvedType, mUserId, /* flags= */ 0,
+                    mRealCallingUid, mRealCallingPid);
+            mAInfo = mSupervisor.resolveActivity(mIntent, mRInfo, mStartFlags, /*profilerInfo=*/
+                    null);
+        }
+        return intercepted;
+    }
+
+    private void normalizeHomeIntent() {
+        Slog.w(TAG, "The home Intent is not correctly formatted");
+        if (mIntent.getCategories().size() > 1) {
+            Slog.d(TAG, "Purge home intent categories");
+            boolean isSecondaryHome = false;
+            final Object[] categories = mIntent.getCategories().toArray();
+            for (int i = categories.length - 1; i >= 0; i--) {
+                final String category = (String) categories[i];
+                if (CATEGORY_SECONDARY_HOME.equals(category)) {
+                    isSecondaryHome = true;
+                }
+                mIntent.removeCategory(category);
+            }
+            mIntent.addCategory(isSecondaryHome ? CATEGORY_SECONDARY_HOME : CATEGORY_HOME);
+        }
+        if (mIntent.getType() != null || mIntent.getData() != null) {
+            Slog.d(TAG, "Purge home intent data/type");
+            mIntent.setType(null);
+        }
+        if (mComponentSpecified) {
+            Slog.d(TAG, "Purge home intent component, " + mIntent.getComponent());
+            mIntent.setComponent(null);
+        }
+        mIntent.addFlags(FLAG_ACTIVITY_NEW_TASK);
+    }
+
+    private boolean replaceToSecondaryHomeIntentIfNeeded() {
         if (!mIntent.hasCategory(Intent.CATEGORY_HOME)) {
             // Already a secondary home intent, leave it alone.
             return false;
@@ -506,13 +599,6 @@ class ActivityStartInterceptor {
         // and should not be moved to the caller's task. Also, activities cannot change their type,
         // e.g. a standard activity cannot become a home activity.
         mIntent.addFlags(FLAG_ACTIVITY_NEW_TASK);
-        mCallingPid = mRealCallingPid;
-        mCallingUid = mRealCallingUid;
-        mResolvedType = null;
-
-        mRInfo = mSupervisor.resolveIntent(mIntent, mResolvedType, mUserId, /* flags= */ 0,
-                mRealCallingUid, mRealCallingPid);
-        mAInfo = mSupervisor.resolveActivity(mIntent, mRInfo, mStartFlags, /*profilerInfo=*/ null);
         return true;
     }
 
diff --git a/services/core/java/com/android/server/wm/ActivityStarter.java b/services/core/java/com/android/server/wm/ActivityStarter.java
index b0de21d4b531..16e409bd6e35 100644
--- a/services/core/java/com/android/server/wm/ActivityStarter.java
+++ b/services/core/java/com/android/server/wm/ActivityStarter.java
@@ -1227,7 +1227,8 @@ class ActivityStarter {
         mInterceptor.setStates(userId, realCallingPid, realCallingUid, startFlags, callingPackage,
                 callingFeatureId);
         if (mInterceptor.intercept(intent, rInfo, aInfo, resolvedType, inTask, inTaskFragment,
-                callingPid, callingUid, checkedOptions, suggestedLaunchDisplayArea)) {
+                callingPid, callingUid, checkedOptions, suggestedLaunchDisplayArea,
+                request.componentSpecified)) {
             // activity start was intercepted, e.g. because the target user is currently in quiet
             // mode (turn off work) or the target application is suspended
             intent = mInterceptor.mIntent;
diff --git a/services/core/java/com/android/server/wm/LockTaskController.java b/services/core/java/com/android/server/wm/LockTaskController.java
index e65396e00b20..a76cf9882d18 100644
--- a/services/core/java/com/android/server/wm/LockTaskController.java
+++ b/services/core/java/com/android/server/wm/LockTaskController.java
@@ -653,6 +653,10 @@ public class LockTaskController {
         if (!isSystemCaller) {
             task.mLockTaskUid = callingUid;
             if (task.mLockTaskAuth == LOCK_TASK_AUTH_PINNABLE) {
+                if (mLockTaskModeTasks.contains(task)) {
+                    ProtoLog.w(WM_DEBUG_LOCKTASK, "Already locked.");
+                    return;
+                }
                 // startLockTask() called by app, but app is not part of lock task allowlist. Show
                 // app pinning request. We will come back here with isSystemCaller true.
                 ProtoLog.w(WM_DEBUG_LOCKTASK, "Mode default, asking user");
diff --git a/services/core/java/com/android/server/wm/WindowManagerService.java b/services/core/java/com/android/server/wm/WindowManagerService.java
index b8f47cce6005..3d91cf4ffac5 100644
--- a/services/core/java/com/android/server/wm/WindowManagerService.java
+++ b/services/core/java/com/android/server/wm/WindowManagerService.java
@@ -7115,12 +7115,12 @@ public class WindowManagerService extends IWindowManager.Stub
 
     @Override
     public void dump(FileDescriptor fd, PrintWriter pw, String[] args) {
+        if (!DumpUtils.checkDumpPermission(mContext, TAG, pw)) return;
         PriorityDump.dump(mPriorityDumper, fd, pw, args);
     }
 
     @NeverCompile // Avoid size overhead of debugging code.
     private void doDump(FileDescriptor fd, PrintWriter pw, String[] args, boolean useProto) {
-        if (!DumpUtils.checkDumpPermission(mContext, TAG, pw)) return;
         boolean dumpAll = false;
 
         int opti = 0;
diff --git a/services/tests/mockingservicestests/src/com/android/server/am/PendingIntentControllerTest.java b/services/tests/mockingservicestests/src/com/android/server/am/PendingIntentControllerTest.java
index 89b48bad2358..ab3784b07e10 100644
--- a/services/tests/mockingservicestests/src/com/android/server/am/PendingIntentControllerTest.java
+++ b/services/tests/mockingservicestests/src/com/android/server/am/PendingIntentControllerTest.java
@@ -16,6 +16,9 @@
 
 package com.android.server.am;
 
+import static android.os.PowerWhitelistManager.REASON_NOTIFICATION_SERVICE;
+import static android.os.PowerWhitelistManager.TEMPORARY_ALLOWLIST_TYPE_FOREGROUND_SERVICE_ALLOWED;
+import static android.os.PowerWhitelistManager.TEMPORARY_ALLOWLIST_TYPE_FOREGROUND_SERVICE_NOT_ALLOWED;
 import static android.os.Process.INVALID_UID;
 
 import static com.android.dx.mockito.inline.extended.ExtendedMockito.doReturn;
@@ -27,9 +30,11 @@ import static com.android.server.am.PendingIntentRecord.CANCEL_REASON_OWNER_CANC
 import static com.android.server.am.PendingIntentRecord.CANCEL_REASON_OWNER_FORCE_STOPPED;
 import static com.android.server.am.PendingIntentRecord.CANCEL_REASON_SUPERSEDED;
 import static com.android.server.am.PendingIntentRecord.CANCEL_REASON_USER_STOPPED;
+import static com.android.server.am.PendingIntentRecord.FLAG_ACTIVITY_SENDER;
 import static com.android.server.am.PendingIntentRecord.cancelReasonToString;
 
 import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertNotNull;
 import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.ArgumentMatchers.anyLong;
 import static org.mockito.ArgumentMatchers.eq;
@@ -39,9 +44,11 @@ import static org.mockito.Mockito.when;
 import android.app.ActivityManager;
 import android.app.ActivityManagerInternal;
 import android.app.AppGlobals;
+import android.app.BackgroundStartPrivileges;
 import android.app.PendingIntent;
 import android.content.Intent;
 import android.content.pm.IPackageManager;
+import android.os.Binder;
 import android.os.Looper;
 import android.os.UserHandle;
 
@@ -179,6 +186,39 @@ public class PendingIntentControllerTest {
         }
     }
 
+    @Test
+    public void testClearAllowBgActivityStartsClearsToken() {
+        final PendingIntentRecord pir = createPendingIntentRecord(0);
+        Binder token = new Binder();
+        pir.setAllowBgActivityStarts(token, FLAG_ACTIVITY_SENDER);
+        assertEquals(BackgroundStartPrivileges.allowBackgroundActivityStarts(token),
+                pir.getBackgroundStartPrivilegesForActivitySender(token));
+        pir.clearAllowBgActivityStarts(token);
+        assertEquals(BackgroundStartPrivileges.NONE,
+                pir.getBackgroundStartPrivilegesForActivitySender(token));
+    }
+
+    @Test
+    public void testClearAllowBgActivityStartsClearsDuration() {
+        final PendingIntentRecord pir = createPendingIntentRecord(0);
+        Binder token = new Binder();
+        pir.setAllowlistDurationLocked(token, 1000,
+                TEMPORARY_ALLOWLIST_TYPE_FOREGROUND_SERVICE_ALLOWED, REASON_NOTIFICATION_SERVICE,
+                "NotificationManagerService");
+        PendingIntentRecord.TempAllowListDuration allowlistDurationLocked =
+                pir.getAllowlistDurationLocked(token);
+        assertEquals(1000, allowlistDurationLocked.duration);
+        assertEquals(TEMPORARY_ALLOWLIST_TYPE_FOREGROUND_SERVICE_ALLOWED,
+                allowlistDurationLocked.type);
+        pir.clearAllowBgActivityStarts(token);
+        PendingIntentRecord.TempAllowListDuration allowlistDurationLockedAfterClear =
+                pir.getAllowlistDurationLocked(token);
+        assertNotNull(allowlistDurationLockedAfterClear);
+        assertEquals(1000, allowlistDurationLockedAfterClear.duration);
+        assertEquals(TEMPORARY_ALLOWLIST_TYPE_FOREGROUND_SERVICE_NOT_ALLOWED,
+                allowlistDurationLocked.type);
+    }
+
     private void assertCancelReason(int expectedReason, int actualReason) {
         final String errMsg = "Expected: " + cancelReasonToString(expectedReason)
                 + "; Actual: " + cancelReasonToString(actualReason);
diff --git a/services/tests/mockingservicestests/src/com/android/server/appop/AppOpsUidStateTrackerTest.java b/services/tests/mockingservicestests/src/com/android/server/appop/AppOpsUidStateTrackerTest.java
index 1731590be3c9..026e72f117b4 100644
--- a/services/tests/mockingservicestests/src/com/android/server/appop/AppOpsUidStateTrackerTest.java
+++ b/services/tests/mockingservicestests/src/com/android/server/appop/AppOpsUidStateTrackerTest.java
@@ -31,12 +31,14 @@ import static android.app.AppOpsManager.UID_STATE_FOREGROUND;
 import static android.app.AppOpsManager.UID_STATE_FOREGROUND_SERVICE;
 import static android.app.AppOpsManager.UID_STATE_MAX_LAST_NON_RESTRICTED;
 import static android.app.AppOpsManager.UID_STATE_TOP;
+import static android.permission.flags.Flags.delayUidStateChangesFromCapabilityUpdates;
 
 import static com.android.server.appop.AppOpsUidStateTracker.processStateToUidState;
 
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertTrue;
+import static org.junit.Assume.assumeTrue;
 import static org.mockito.ArgumentMatchers.anyBoolean;
 import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.ArgumentMatchers.eq;
@@ -325,6 +327,10 @@ public class AppOpsUidStateTrackerTest {
                 .backgroundState()
                 .update();
 
+        assertEquals(MODE_IGNORED, mIntf.evalMode(UID, OP_RECORD_AUDIO, MODE_FOREGROUND));
+        assertEquals(MODE_IGNORED,
+                mIntf.evalMode(UID, OP_RECEIVE_EXPLICIT_USER_INTERACTION_AUDIO, MODE_FOREGROUND));
+
         procStateBuilder(UID)
                 .backgroundState()
                 .microphoneCapability()
@@ -342,10 +348,23 @@ public class AppOpsUidStateTrackerTest {
                 .microphoneCapability()
                 .update();
 
+        assertEquals(MODE_ALLOWED, mIntf.evalMode(UID, OP_RECORD_AUDIO, MODE_FOREGROUND));
+        assertEquals(MODE_ALLOWED,
+                mIntf.evalMode(UID, OP_RECEIVE_EXPLICIT_USER_INTERACTION_AUDIO, MODE_FOREGROUND));
+
         procStateBuilder(UID)
                 .backgroundState()
                 .update();
 
+        if (delayUidStateChangesFromCapabilityUpdates()) {
+            mClock.advanceTime(mConstants.BG_STATE_SETTLE_TIME - 1);
+            assertEquals(MODE_ALLOWED, mIntf.evalMode(UID, OP_RECORD_AUDIO, MODE_FOREGROUND));
+            assertEquals(MODE_ALLOWED,
+                    mIntf.evalMode(UID, OP_RECEIVE_EXPLICIT_USER_INTERACTION_AUDIO,
+                            MODE_FOREGROUND));
+
+            mClock.advanceTime(1);
+        }
         assertEquals(MODE_IGNORED, mIntf.evalMode(UID, OP_RECORD_AUDIO, MODE_FOREGROUND));
         assertEquals(MODE_IGNORED,
                 mIntf.evalMode(UID, OP_RECEIVE_EXPLICIT_USER_INTERACTION_AUDIO, MODE_FOREGROUND));
@@ -357,6 +376,8 @@ public class AppOpsUidStateTrackerTest {
                 .backgroundState()
                 .update();
 
+        assertEquals(MODE_IGNORED, mIntf.evalMode(UID, OP_CAMERA, MODE_FOREGROUND));
+
         procStateBuilder(UID)
                 .backgroundState()
                 .cameraCapability()
@@ -372,10 +393,18 @@ public class AppOpsUidStateTrackerTest {
                 .cameraCapability()
                 .update();
 
+        assertEquals(MODE_ALLOWED, mIntf.evalMode(UID, OP_CAMERA, MODE_FOREGROUND));
+
         procStateBuilder(UID)
                 .backgroundState()
                 .update();
 
+        if (delayUidStateChangesFromCapabilityUpdates()) {
+            mClock.advanceTime(mConstants.BG_STATE_SETTLE_TIME - 1);
+            assertEquals(MODE_ALLOWED, mIntf.evalMode(UID, OP_CAMERA, MODE_FOREGROUND));
+
+            mClock.advanceTime(1);
+        }
         assertEquals(MODE_IGNORED, mIntf.evalMode(UID, OP_CAMERA, MODE_FOREGROUND));
     }
 
@@ -385,6 +414,9 @@ public class AppOpsUidStateTrackerTest {
                 .backgroundState()
                 .update();
 
+        assertEquals(MODE_IGNORED, mIntf.evalMode(UID, OP_COARSE_LOCATION, MODE_FOREGROUND));
+        assertEquals(MODE_IGNORED, mIntf.evalMode(UID, OP_FINE_LOCATION, MODE_FOREGROUND));
+
         procStateBuilder(UID)
                 .backgroundState()
                 .locationCapability()
@@ -401,14 +433,54 @@ public class AppOpsUidStateTrackerTest {
                 .locationCapability()
                 .update();
 
+        assertEquals(MODE_ALLOWED, mIntf.evalMode(UID, OP_COARSE_LOCATION, MODE_FOREGROUND));
+        assertEquals(MODE_ALLOWED, mIntf.evalMode(UID, OP_FINE_LOCATION, MODE_FOREGROUND));
+
         procStateBuilder(UID)
                 .backgroundState()
                 .update();
 
+        if (delayUidStateChangesFromCapabilityUpdates()) {
+            mClock.advanceTime(mConstants.BG_STATE_SETTLE_TIME - 1);
+            assertEquals(MODE_ALLOWED, mIntf.evalMode(UID, OP_COARSE_LOCATION, MODE_FOREGROUND));
+            assertEquals(MODE_ALLOWED, mIntf.evalMode(UID, OP_FINE_LOCATION, MODE_FOREGROUND));
+
+            mClock.advanceTime(1);
+        }
         assertEquals(MODE_IGNORED, mIntf.evalMode(UID, OP_COARSE_LOCATION, MODE_FOREGROUND));
         assertEquals(MODE_IGNORED, mIntf.evalMode(UID, OP_FINE_LOCATION, MODE_FOREGROUND));
     }
 
+    @Test
+    public void testProcStateChangesAndStaysUnrestrictedAndCapabilityRemoved() {
+        assumeTrue(delayUidStateChangesFromCapabilityUpdates());
+
+        procStateBuilder(UID)
+                .topState()
+                .microphoneCapability()
+                .cameraCapability()
+                .locationCapability()
+                .update();
+
+        assertEquals(MODE_ALLOWED, mIntf.evalMode(UID, OP_RECORD_AUDIO, MODE_FOREGROUND));
+        assertEquals(MODE_ALLOWED, mIntf.evalMode(UID, OP_CAMERA, MODE_FOREGROUND));
+        assertEquals(MODE_ALLOWED, mIntf.evalMode(UID, OP_COARSE_LOCATION, MODE_FOREGROUND));
+
+        procStateBuilder(UID)
+                .foregroundState()
+                .update();
+
+        mClock.advanceTime(mConstants.TOP_STATE_SETTLE_TIME - 1);
+        assertEquals(MODE_ALLOWED, mIntf.evalMode(UID, OP_RECORD_AUDIO, MODE_FOREGROUND));
+        assertEquals(MODE_ALLOWED, mIntf.evalMode(UID, OP_CAMERA, MODE_FOREGROUND));
+        assertEquals(MODE_ALLOWED, mIntf.evalMode(UID, OP_COARSE_LOCATION, MODE_FOREGROUND));
+
+        mClock.advanceTime(1);
+        assertEquals(MODE_IGNORED, mIntf.evalMode(UID, OP_RECORD_AUDIO, MODE_FOREGROUND));
+        assertEquals(MODE_IGNORED, mIntf.evalMode(UID, OP_CAMERA, MODE_FOREGROUND));
+        assertEquals(MODE_IGNORED, mIntf.evalMode(UID, OP_COARSE_LOCATION, MODE_FOREGROUND));
+    }
+
     @Test
     public void testVisibleAppWidget() {
         procStateBuilder(UID)
diff --git a/services/tests/servicestests/src/com/android/server/am/UserControllerTest.java b/services/tests/servicestests/src/com/android/server/am/UserControllerTest.java
index 390eb937fe25..6411463fe0d9 100644
--- a/services/tests/servicestests/src/com/android/server/am/UserControllerTest.java
+++ b/services/tests/servicestests/src/com/android/server/am/UserControllerTest.java
@@ -94,6 +94,7 @@ import android.os.Looper;
 import android.os.Message;
 import android.os.PowerManagerInternal;
 import android.os.RemoteException;
+import android.os.SystemClock;
 import android.os.UserHandle;
 import android.os.UserManager;
 import android.os.storage.IStorageManager;
@@ -417,17 +418,12 @@ public class UserControllerTest {
     @Test
     public void testDispatchUserSwitch() throws RemoteException {
         // Prepare mock observer and register it
-        IUserSwitchObserver observer = mock(IUserSwitchObserver.class);
-        when(observer.asBinder()).thenReturn(new Binder());
-        doAnswer(invocation -> {
-            IRemoteCallback callback = (IRemoteCallback) invocation.getArguments()[1];
-            callback.sendResult(null);
-            return null;
-        }).when(observer).onUserSwitching(anyInt(), any());
-        mUserController.registerUserSwitchObserver(observer, "mock");
+        IUserSwitchObserver observer = registerUserSwitchObserver(
+                /* replyToOnBeforeUserSwitchingCallback= */ true,
+                /* replyToOnUserSwitchingCallback= */ true);
         // Start user -- this will update state of mUserController
         mUserController.startUser(TEST_USER_ID, USER_START_MODE_FOREGROUND);
-        verify(observer, times(1)).onBeforeUserSwitching(eq(TEST_USER_ID));
+        verify(observer, times(1)).onBeforeUserSwitching(eq(TEST_USER_ID), any());
         Message reportMsg = mInjector.mHandler.getMessageForCode(REPORT_USER_SWITCH_MSG);
         assertNotNull(reportMsg);
         UserState userState = (UserState) reportMsg.obj;
@@ -452,13 +448,13 @@ public class UserControllerTest {
 
     @Test
     public void testDispatchUserSwitchBadReceiver() throws RemoteException {
-        // Prepare mock observer which doesn't notify the callback and register it
-        IUserSwitchObserver observer = mock(IUserSwitchObserver.class);
-        when(observer.asBinder()).thenReturn(new Binder());
-        mUserController.registerUserSwitchObserver(observer, "mock");
+        // Prepare mock observer which doesn't notify the onUserSwitching callback and register it
+        IUserSwitchObserver observer = registerUserSwitchObserver(
+                /* replyToOnBeforeUserSwitchingCallback= */ true,
+                /* replyToOnUserSwitchingCallback= */ false);
         // Start user -- this will update state of mUserController
         mUserController.startUser(TEST_USER_ID, USER_START_MODE_FOREGROUND);
-        verify(observer, times(1)).onBeforeUserSwitching(eq(TEST_USER_ID));
+        verify(observer, times(1)).onBeforeUserSwitching(eq(TEST_USER_ID), any());
         Message reportMsg = mInjector.mHandler.getMessageForCode(REPORT_USER_SWITCH_MSG);
         assertNotNull(reportMsg);
         UserState userState = (UserState) reportMsg.obj;
@@ -549,7 +545,6 @@ public class UserControllerTest {
         expectedCodes.add(REPORT_USER_SWITCH_COMPLETE_MSG);
         if (backgroundUserStopping) {
             expectedCodes.add(CLEAR_USER_JOURNEY_SESSION_MSG);
-            expectedCodes.add(0); // this is for directly posting in stopping.
         }
         if (expectScheduleBackgroundUserStopping) {
             expectedCodes.add(SCHEDULED_STOP_BACKGROUND_USER_MSG);
@@ -565,9 +560,9 @@ public class UserControllerTest {
     @Test
     public void testDispatchUserSwitchComplete() throws RemoteException {
         // Prepare mock observer and register it
-        IUserSwitchObserver observer = mock(IUserSwitchObserver.class);
-        when(observer.asBinder()).thenReturn(new Binder());
-        mUserController.registerUserSwitchObserver(observer, "mock");
+        IUserSwitchObserver observer = registerUserSwitchObserver(
+                /* replyToOnBeforeUserSwitchingCallback= */ true,
+                /* replyToOnUserSwitchingCallback= */ true);
         // Start user -- this will update state of mUserController
         mUserController.startUser(TEST_USER_ID, USER_START_MODE_FOREGROUND);
         Message reportMsg = mInjector.mHandler.getMessageForCode(REPORT_USER_SWITCH_MSG);
@@ -1750,6 +1745,29 @@ public class UserControllerTest {
         verify(mInjector, never()).onSystemUserVisibilityChanged(anyBoolean());
     }
 
+    private IUserSwitchObserver registerUserSwitchObserver(
+            boolean replyToOnBeforeUserSwitchingCallback, boolean replyToOnUserSwitchingCallback)
+            throws RemoteException {
+        IUserSwitchObserver observer = mock(IUserSwitchObserver.class);
+        when(observer.asBinder()).thenReturn(new Binder());
+        if (replyToOnBeforeUserSwitchingCallback) {
+            doAnswer(invocation -> {
+                IRemoteCallback callback = (IRemoteCallback) invocation.getArguments()[1];
+                callback.sendResult(null);
+                return null;
+            }).when(observer).onBeforeUserSwitching(anyInt(), any());
+        }
+        if (replyToOnUserSwitchingCallback) {
+            doAnswer(invocation -> {
+                IRemoteCallback callback = (IRemoteCallback) invocation.getArguments()[1];
+                callback.sendResult(null);
+                return null;
+            }).when(observer).onUserSwitching(anyInt(), any());
+        }
+        mUserController.registerUserSwitchObserver(observer, "mock");
+        return observer;
+    }
+
     // Should be public to allow mocking
     private static class TestInjector extends UserController.Injector {
         public final TestHandler mHandler;
@@ -1955,6 +1973,7 @@ public class UserControllerTest {
          * fix this, but in the meantime, this is your warning.
          */
         private final List<Message> mMessages = new ArrayList<>();
+        private final List<Runnable> mPendingCallbacks = new ArrayList<>();
 
         TestHandler(Looper looper) {
             super(looper);
@@ -1987,14 +2006,24 @@ public class UserControllerTest {
 
         @Override
         public boolean sendMessageAtTime(Message msg, long uptimeMillis) {
-            Message copy = new Message();
-            copy.copyFrom(msg);
-            mMessages.add(copy);
-            if (msg.getCallback() != null) {
-                msg.getCallback().run();
+            if (msg.getCallback() == null) {
+                Message copy = new Message();
+                copy.copyFrom(msg);
+                mMessages.add(copy);
+            } else {
+                if (SystemClock.uptimeMillis() >= uptimeMillis) {
+                    msg.getCallback().run();
+                } else {
+                    mPendingCallbacks.add(msg.getCallback());
+                }
                 msg.setCallback(null);
             }
             return super.sendMessageAtTime(msg, uptimeMillis);
         }
+
+        private void runPendingCallbacks() {
+            mPendingCallbacks.forEach(Runnable::run);
+            mPendingCallbacks.clear();
+        }
     }
 }
diff --git a/services/tests/wmtests/src/com/android/server/wm/ActivityStartInterceptorTest.java b/services/tests/wmtests/src/com/android/server/wm/ActivityStartInterceptorTest.java
index 670f9f697a5c..97e97a9e74e7 100644
--- a/services/tests/wmtests/src/com/android/server/wm/ActivityStartInterceptorTest.java
+++ b/services/tests/wmtests/src/com/android/server/wm/ActivityStartInterceptorTest.java
@@ -236,6 +236,19 @@ public class ActivityStartInterceptorTest {
         return dialogInfo;
     }
 
+    @Test
+    public void testInterceptIncorrectHomeIntent() {
+        // Create a non-standard home intent
+        final Intent homeIntent = new Intent(Intent.ACTION_MAIN);
+        homeIntent.addCategory(Intent.CATEGORY_HOME);
+        homeIntent.addCategory(Intent.CATEGORY_LAUNCHER);
+
+        // Ensure the intent is intercepted and normalized to standard home intent.
+        assertTrue(mInterceptor.intercept(homeIntent, null, mAInfo, null, null, null, 0, 0, null,
+                mTaskDisplayArea, false));
+        assertTrue(ActivityRecord.isHomeIntent(homeIntent));
+    }
+
     @Test
     public void testInterceptLockTaskModeViolationPackage() {
         when(mLockTaskController.isActivityAllowed(
diff --git a/services/tests/wmtests/src/com/android/server/wm/LockTaskControllerTest.java b/services/tests/wmtests/src/com/android/server/wm/LockTaskControllerTest.java
index bef4531c9f28..5122aeee588a 100644
--- a/services/tests/wmtests/src/com/android/server/wm/LockTaskControllerTest.java
+++ b/services/tests/wmtests/src/com/android/server/wm/LockTaskControllerTest.java
@@ -239,6 +239,11 @@ public class LockTaskControllerTest {
         verifyLockTaskStarted(STATUS_BAR_MASK_PINNED, DISABLE2_NONE);
         // THEN screen pinning toast should be shown
         verify(mStatusBarService).showPinningEnterExitToast(eq(true /* entering */));
+
+        // WHEN the app calls startLockTaskMode while the Task is already locked
+        mLockTaskController.startLockTaskMode(tr, false, TEST_UID);
+        // THEN a pinning request should NOT be shown
+        verify(mStatusBarManagerInternal, never()).showScreenPinningRequest(anyInt(), anyInt());
     }
 
     @Test
```

