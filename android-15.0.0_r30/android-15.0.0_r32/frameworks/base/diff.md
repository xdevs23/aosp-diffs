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
index bcaceb24d767..0fb267e33b22 100644
--- a/core/java/android/content/res/ResourcesImpl.java
+++ b/core/java/android/content/res/ResourcesImpl.java
@@ -491,6 +491,9 @@ public class ResourcesImpl {
                             }
                             defaultLocale =
                                     adjustLanguageTag(lc.getDefaultLocale().toLanguageTag());
+                            Slog.v(TAG, "Updating configuration, with default locale "
+                                    + defaultLocale + " and selected locales "
+                                    + Arrays.toString(selectedLocales));
                         } else {
                             String[] availableLocales;
                             // The LocaleList has changed. We must query the AssetManager's
@@ -526,6 +529,7 @@ public class ResourcesImpl {
                         for (int i = 0; i < locales.size(); i++) {
                             selectedLocales[i] = adjustLanguageTag(locales.get(i).toLanguageTag());
                         }
+                        defaultLocale = adjustLanguageTag(lc.getDefaultLocale().toLanguageTag());
                     } else {
                         selectedLocales = new String[]{
                                 adjustLanguageTag(locales.get(0).toLanguageTag())};
diff --git a/core/java/android/window/flags/responsible_apis.aconfig b/core/java/android/window/flags/responsible_apis.aconfig
index d5ba32cafebd..36219812c002 100644
--- a/core/java/android/window/flags/responsible_apis.aconfig
+++ b/core/java/android/window/flags/responsible_apis.aconfig
@@ -75,4 +75,16 @@ flag {
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
index 57bfc7086ed5..c90ebd937adf 100644
--- a/core/jni/android_util_AssetManager.cpp
+++ b/core/jni/android_util_AssetManager.cpp
@@ -409,19 +409,17 @@ static void NativeSetConfiguration(JNIEnv* env, jclass /*clazz*/, jlong ptr, jin
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
diff --git a/core/res/res/values/config_telephony.xml b/core/res/res/values/config_telephony.xml
index 666f1cf39fe3..bddcd03b2b3e 100644
--- a/core/res/res/values/config_telephony.xml
+++ b/core/res/res/values/config_telephony.xml
@@ -64,6 +64,13 @@
     <integer name="auto_data_switch_performance_stability_time_threshold_millis">120000</integer>
     <java-symbol type="integer" name="auto_data_switch_performance_stability_time_threshold_millis" />
 
+    <!-- Define the bar for switching data back to the default SIM when both SIMs are out of service
+         in milliseconds. A value of 0 means an immediate switch, otherwise for a negative value,
+         the threshold defined by auto_data_switch_availability_stability_time_threshold_millis
+         will be used instead. -->
+    <integer name="auto_data_switch_availability_switchback_stability_time_threshold_millis">150000</integer>
+    <java-symbol type="integer" name="auto_data_switch_availability_switchback_stability_time_threshold_millis" />
+
     <!-- Define the maximum retry times when a validation for switching failed.-->
     <integer name="auto_data_switch_validation_max_retry">7</integer>
     <java-symbol type="integer" name="auto_data_switch_validation_max_retry" />
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
index 4c7e47769613..4ded26f5cfaf 100644
--- a/libs/WindowManager/Jetpack/src/androidx/window/extensions/embedding/SplitController.java
+++ b/libs/WindowManager/Jetpack/src/androidx/window/extensions/embedding/SplitController.java
@@ -18,6 +18,7 @@ package androidx.window.extensions.embedding;
 
 import static android.app.ActivityManager.START_SUCCESS;
 import static android.app.ActivityOptions.KEY_LAUNCH_TASK_FRAGMENT_TOKEN;
+import static android.app.ActivityTaskManager.INVALID_TASK_ID;
 import static android.app.WindowConfiguration.WINDOWING_MODE_PINNED;
 import static android.app.WindowConfiguration.WINDOWING_MODE_UNDEFINED;
 import static android.view.Display.DEFAULT_DISPLAY;
@@ -3148,15 +3149,22 @@ public class SplitController implements JetpackTaskFragmentOrganizer.TaskFragmen
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
index 354f281551b2..aa06b7ecf76c 100644
--- a/services/core/java/com/android/server/am/BroadcastController.java
+++ b/services/core/java/com/android/server/am/BroadcastController.java
@@ -316,8 +316,7 @@ class BroadcastController {
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
index 3817ba1a28b9..ac30be99979e 100644
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
@@ -703,7 +716,7 @@ public final class PendingIntentRecord extends IIntentSender.Stub {
         return res;
     }
 
-    private BackgroundStartPrivileges getBackgroundStartPrivilegesForActivitySender(
+    @VisibleForTesting BackgroundStartPrivileges getBackgroundStartPrivilegesForActivitySender(
             IBinder allowlistToken) {
         return mAllowBgActivityStartsForActivitySender.contains(allowlistToken)
                 ? BackgroundStartPrivileges.allowBackgroundActivityStarts(allowlistToken)
diff --git a/services/core/java/com/android/server/appop/AppOpsService.java b/services/core/java/com/android/server/appop/AppOpsService.java
index 82a51c3e0acc..ef72481c1567 100644
--- a/services/core/java/com/android/server/appop/AppOpsService.java
+++ b/services/core/java/com/android/server/appop/AppOpsService.java
@@ -180,6 +180,7 @@ import com.android.server.SystemServiceManager;
 import com.android.server.companion.virtual.VirtualDeviceManagerInternal;
 import com.android.server.pm.PackageList;
 import com.android.server.pm.PackageManagerLocal;
+import com.android.server.pm.ProtectedPackages;
 import com.android.server.pm.UserManagerInternal;
 import com.android.server.pm.pkg.AndroidPackage;
 import com.android.server.pm.pkg.PackageState;
@@ -236,6 +237,13 @@ public class AppOpsService extends IAppOpsService.Stub {
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
@@ -301,6 +309,8 @@ public class AppOpsService extends IAppOpsService.Stub {
     private final IPlatformCompat mPlatformCompat = IPlatformCompat.Stub.asInterface(
             ServiceManager.getService(Context.PLATFORM_COMPAT_SERVICE));
 
+    private ProtectedPackages mProtectedPackages;
+
     /**
      * Registered callbacks, called from {@link #collectAsyncNotedOp}.
      *
@@ -1699,6 +1709,8 @@ public class AppOpsService extends IAppOpsService.Stub {
                 Manifest.permission.GET_APP_OPS_STATS,
                 Binder.getCallingPid(), Binder.getCallingUid())
                 == PackageManager.PERMISSION_GRANTED;
+        int totalAttributedOpEntryCount = 0;
+
         if (ops == null) {
             resOps = new ArrayList<>();
             for (int j = 0; j < pkgOps.size(); j++) {
@@ -1706,7 +1718,12 @@ public class AppOpsService extends IAppOpsService.Stub {
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
@@ -1718,10 +1735,21 @@ public class AppOpsService extends IAppOpsService.Stub {
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
 
@@ -2074,6 +2102,12 @@ public class AppOpsService extends IAppOpsService.Stub {
 
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
@@ -2384,6 +2418,11 @@ public class AppOpsService extends IAppOpsService.Stub {
             return;
         }
 
+        if (isDeviceProvisioningPackage(uid, packageName)) {
+            Slog.w(TAG, "Cannot set op mode for device provisioning app by Shell");
+            return;
+        }
+
         code = AppOpsManager.opToSwitch(code);
 
         PackageVerificationResult pvr;
@@ -2414,6 +2453,36 @@ public class AppOpsService extends IAppOpsService.Stub {
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
index 1a9d21187ddb..7b6ebbfcef90 100644
--- a/services/core/java/com/android/server/wm/ActivityStartInterceptor.java
+++ b/services/core/java/com/android/server/wm/ActivityStartInterceptor.java
@@ -25,6 +25,9 @@ import static android.app.PendingIntent.FLAG_ONE_SHOT;
 import static android.app.admin.DevicePolicyManager.EXTRA_RESTRICTION;
 import static android.app.admin.DevicePolicyManager.POLICY_SUSPEND_PACKAGES;
 import static android.content.Context.KEYGUARD_SERVICE;
+import static android.content.Intent.ACTION_MAIN;
+import static android.content.Intent.CATEGORY_HOME;
+import static android.content.Intent.CATEGORY_SECONDARY_HOME;
 import static android.content.Intent.EXTRA_INTENT;
 import static android.content.Intent.EXTRA_PACKAGE_NAME;
 import static android.content.Intent.EXTRA_TASK_ID;
@@ -40,6 +43,7 @@ import android.app.ActivityOptions;
 import android.app.KeyguardManager;
 import android.app.TaskInfo;
 import android.app.admin.DevicePolicyManagerInternal;
+import android.content.ComponentName;
 import android.content.Context;
 import android.content.IIntentSender;
 import android.content.Intent;
@@ -119,6 +123,11 @@ class ActivityStartInterceptor {
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
@@ -185,6 +194,14 @@ class ActivityStartInterceptor {
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
@@ -193,7 +210,8 @@ class ActivityStartInterceptor {
      */
     boolean intercept(Intent intent, ResolveInfo rInfo, ActivityInfo aInfo, String resolvedType,
             Task inTask, TaskFragment inTaskFragment, int callingPid, int callingUid,
-            ActivityOptions activityOptions, TaskDisplayArea presumableLaunchDisplayArea) {
+            ActivityOptions activityOptions, TaskDisplayArea presumableLaunchDisplayArea,
+            boolean componentSpecified) {
         mUserManager = UserManager.get(mServiceContext);
 
         mIntent = intent;
@@ -206,6 +224,7 @@ class ActivityStartInterceptor {
         mInTaskFragment = inTaskFragment;
         mActivityOptions = activityOptions;
         mPresumableLaunchDisplayArea = presumableLaunchDisplayArea;
+        mComponentSpecified = componentSpecified;
 
         if (interceptQuietProfileIfNeeded()) {
             // If work profile is turned off, skip the work challenge since the profile can only
@@ -230,7 +249,8 @@ class ActivityStartInterceptor {
         }
         if (interceptHomeIfNeeded()) {
             // Replace primary home intents directed at displays that do not support primary home
-            // but support secondary home with the relevant secondary home activity.
+            // but support secondary home with the relevant secondary home activity. Or the home
+            // intent is not in the correct format.
             return true;
         }
 
@@ -479,9 +499,72 @@ class ActivityStartInterceptor {
         if (mPresumableLaunchDisplayArea == null || mService.mRootWindowContainer == null) {
             return false;
         }
-        if (!ActivityRecord.isHomeIntent(mIntent)) {
+
+        boolean intercepted = false;
+       if (!ACTION_MAIN.equals(mIntent.getAction()) || (!mIntent.hasCategory(CATEGORY_HOME)
+                && !mIntent.hasCategory(CATEGORY_SECONDARY_HOME))) {
+            // not a home intent
             return false;
         }
+
+        if (mComponentSpecified) {
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
@@ -506,13 +589,6 @@ class ActivityStartInterceptor {
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
index 2781592c6b4f..c352575f0102 100644
--- a/services/core/java/com/android/server/wm/ActivityStarter.java
+++ b/services/core/java/com/android/server/wm/ActivityStarter.java
@@ -1340,7 +1340,8 @@ class ActivityStarter {
                 callingPackage,
                 callingFeatureId);
         if (mInterceptor.intercept(intent, rInfo, aInfo, resolvedType, inTask, inTaskFragment,
-                callingPid, callingUid, checkedOptions, suggestedLaunchDisplayArea)) {
+                callingPid, callingUid, checkedOptions, suggestedLaunchDisplayArea,
+                request.componentSpecified)) {
             // activity start was intercepted, e.g. because the target user is currently in quiet
             // mode (turn off work) or the target application is suspended
             intent = mInterceptor.mIntent;
diff --git a/services/core/java/com/android/server/wm/LockTaskController.java b/services/core/java/com/android/server/wm/LockTaskController.java
index 06049530da18..559b0636dc0b 100644
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
index db08be3e366c..866798deeea4 100644
--- a/services/core/java/com/android/server/wm/WindowManagerService.java
+++ b/services/core/java/com/android/server/wm/WindowManagerService.java
@@ -7206,12 +7206,12 @@ public class WindowManagerService extends IWindowManager.Stub
 
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
diff --git a/services/tests/wmtests/src/com/android/server/wm/ActivityStartInterceptorTest.java b/services/tests/wmtests/src/com/android/server/wm/ActivityStartInterceptorTest.java
index 670f9f697a5c..6c4f638e72f2 100644
--- a/services/tests/wmtests/src/com/android/server/wm/ActivityStartInterceptorTest.java
+++ b/services/tests/wmtests/src/com/android/server/wm/ActivityStartInterceptorTest.java
@@ -54,6 +54,7 @@ import android.os.RemoteException;
 import android.os.UserHandle;
 import android.os.UserManager;
 import android.platform.test.annotations.Presubmit;
+import android.platform.test.flag.junit.SetFlagsRule;
 import android.testing.DexmakerShareClassLoaderRule;
 import android.util.Pair;
 import android.util.SparseArray;
@@ -133,6 +134,8 @@ public class ActivityStartInterceptorTest {
     private SparseArray<ActivityInterceptorCallback> mActivityInterceptorCallbacks =
             new SparseArray<>();
 
+    @Rule public final SetFlagsRule mSetFlagsRule = new SetFlagsRule();
+
     @Before
     public void setUp() throws RemoteException {
         MockitoAnnotations.initMocks(this);
@@ -236,6 +239,19 @@ public class ActivityStartInterceptorTest {
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

