```diff
diff --git a/.gitignore b/.gitignore
new file mode 100644
index 00000000..0cc2124b
--- /dev/null
+++ b/.gitignore
@@ -0,0 +1,2 @@
+*.iml
+.idea/
diff --git a/DeviceLockController/Android.bp b/DeviceLockController/Android.bp
index b7dd6966..984349fe 100644
--- a/DeviceLockController/Android.bp
+++ b/DeviceLockController/Android.bp
@@ -102,6 +102,7 @@ java_library {
     libs: [
         "devicelockcontroller-proto-lite",
         "framework-connectivity.stubs.module_lib",
+        "devicelockcontroller-stats",
     ],
     visibility: [
         "//packages/modules/DeviceLock:__subpackages__",
@@ -119,6 +120,7 @@ java_test_helper_library {
     libs: [
         "framework-statsd.stubs.module_lib",
         "modules-utils-expresslog",
+        "devicelockcontroller-common-lib",
     ],
     static_libs: [
         "androidx.annotation_annotation",
diff --git a/DeviceLockController/res/values-cs/strings.xml b/DeviceLockController/res/values-cs/strings.xml
index 0e8baadd..7b27d350 100644
--- a/DeviceLockController/res/values-cs/strings.xml
+++ b/DeviceLockController/res/values-cs/strings.xml
@@ -74,7 +74,7 @@
     <string name="restrictions_lifted" msgid="5785586265984319396">"Veškerá omezení na vašem zařízení byla zrušena"</string>
     <string name="uninstall_kiosk_app" msgid="3459557395024053988">"Ze zařízení můžete odinstalovat terminálovou aplikaci"</string>
     <string name="getting_device_ready" msgid="2829009584599871699">"Příprava zařízení…"</string>
-    <string name="this_may_take_a_few_minutes" msgid="2482876246874429351">"Může to trvat několik minut"</string>
+    <string name="this_may_take_a_few_minutes" msgid="2482876246874429351">"Může to chvíli trvat"</string>
     <string name="installing_kiosk_app" msgid="324208168205545860">"Instaluje se aplikace <xliff:g id="CREDITOR_APP">%1$s</xliff:g>…"</string>
     <string name="opening_kiosk_app" msgid="2021888641430165654">"Otevírání aplikace <xliff:g id="CREDITOR_APP">%1$s</xliff:g>…"</string>
     <string name="settings_banner_title" msgid="527041021011279252">"Zařízení poskytuje společnost <xliff:g id="PROVIDER_NAME">%1$s</xliff:g>"</string>
diff --git a/DeviceLockController/res/values-es/strings.xml b/DeviceLockController/res/values-es/strings.xml
index 3cc982ad..dc4d7122 100644
--- a/DeviceLockController/res/values-es/strings.xml
+++ b/DeviceLockController/res/values-es/strings.xml
@@ -74,7 +74,7 @@
     <string name="restrictions_lifted" msgid="5785586265984319396">"Se han retirado todas las restricciones de tu dispositivo"</string>
     <string name="uninstall_kiosk_app" msgid="3459557395024053988">"Puedes desinstalar la aplicación de kiosko de tu dispositivo"</string>
     <string name="getting_device_ready" msgid="2829009584599871699">"Preparando tu dispositivo…"</string>
-    <string name="this_may_take_a_few_minutes" msgid="2482876246874429351">"Este proceso puede tardar unos minutos"</string>
+    <string name="this_may_take_a_few_minutes" msgid="2482876246874429351">"Esto puede tardar unos minutos"</string>
     <string name="installing_kiosk_app" msgid="324208168205545860">"Instalando la aplicación <xliff:g id="CREDITOR_APP">%1$s</xliff:g>…"</string>
     <string name="opening_kiosk_app" msgid="2021888641430165654">"Abriendo aplicación <xliff:g id="CREDITOR_APP">%1$s</xliff:g>…"</string>
     <string name="settings_banner_title" msgid="527041021011279252">"Dispositivo proporcionado por <xliff:g id="PROVIDER_NAME">%1$s</xliff:g>"</string>
diff --git a/DeviceLockController/res/values-eu/strings.xml b/DeviceLockController/res/values-eu/strings.xml
index 5bf10a72..600a4025 100644
--- a/DeviceLockController/res/values-eu/strings.xml
+++ b/DeviceLockController/res/values-eu/strings.xml
@@ -86,7 +86,7 @@
     <string name="settings_intro_preference_key" msgid="6610461073400554162">"settings_intro_preference_key"</string>
     <string name="settings_restrictions_category" msgid="5746868117342406677">"Gailua guztiz ordaindu arte, ezingo dituzu egin hauek:"</string>
     <string name="settings_restrictions_category_preference_key" msgid="88318147152676512">"settings_restrictions_category_preference_key"</string>
-    <string name="settings_install_apps" msgid="3634279771448183713">"Play Store-tik kanpoko aplikazioak instalatu."</string>
+    <string name="settings_install_apps" msgid="3634279771448183713">"Google Play Store-tik kanpoko aplikazioak instalatu."</string>
     <string name="settings_install_apps_preference_key" msgid="27542314345238427">"settings_install_apps_preference_key"</string>
     <string name="settings_safe_mode" msgid="3035228015586375153">"Gailua modu seguruan berrabiarazi."</string>
     <string name="settings_safe_mode_preference_key" msgid="2106617747358027424">"settings_safe_mode_preference_key"</string>
diff --git a/DeviceLockController/res/values-hi/strings.xml b/DeviceLockController/res/values-hi/strings.xml
index fe2cbe64..4b39869c 100644
--- a/DeviceLockController/res/values-hi/strings.xml
+++ b/DeviceLockController/res/values-hi/strings.xml
@@ -90,7 +90,7 @@
     <string name="settings_install_apps_preference_key" msgid="27542314345238427">"settings_install_apps_preference_key"</string>
     <string name="settings_safe_mode" msgid="3035228015586375153">"अपने डिवाइस को सुरक्षित मोड में फिर से चालू करें"</string>
     <string name="settings_safe_mode_preference_key" msgid="2106617747358027424">"settings_safe_mode_preference_key"</string>
-    <string name="settings_developer_options" msgid="880701002025216672">"डेवलपर के लिए सेटिंग और टूल का इस्तेमाल करें"</string>
+    <string name="settings_developer_options" msgid="880701002025216672">"डेवलपर के लिए सेटिंग और टूल इस्तेमाल करें"</string>
     <string name="settings_developer_options_preference_key" msgid="6807036808722582954">"settings_developer_options_preference_key"</string>
     <string name="settings_credit_provider_capabilities_category" msgid="1274440595211820868">"डिवाइस में गड़बड़ी होने पर <xliff:g id="PROVIDER_NAME">%1$s</xliff:g> यह कर सकता है:"</string>
     <string name="settings_credit_provider_capabilities_category_preference_key" msgid="4571685720898641262">"settings_credit_provider_capabilities_category_preference_key"</string>
diff --git a/DeviceLockController/res/values-my/strings.xml b/DeviceLockController/res/values-my/strings.xml
index 741a5f82..6672aa09 100644
--- a/DeviceLockController/res/values-my/strings.xml
+++ b/DeviceLockController/res/values-my/strings.xml
@@ -72,7 +72,7 @@
     <string name="device_removed_from_subsidy_program" msgid="1243434945619071051">"စက်ကို <xliff:g id="PROVIDER_NAME">%1$s</xliff:g> ထောက်ပံ့ကြေး ပရိုဂရမ်မှ ဖယ်ရှားထားသည်"</string>
     <string name="device_removed_from_finance_program" msgid="825548999540107578">"သင့်စက်ကို <xliff:g id="PROVIDER_NAME">%1$s</xliff:g> ၏ ငွေကြေးဆိုင်ရာ ပရိုဂရမ်မှ ဖယ်ရှားထားသည်"</string>
     <string name="restrictions_lifted" msgid="5785586265984319396">"သင့်စက်ရှိ ကန့်သတ်ချက်များအားလုံးကို ရုပ်သိမ်းလိုက်ပါပြီ"</string>
-    <string name="uninstall_kiosk_app" msgid="3459557395024053988">"သင့်စက်မှ Kiosk app ပရိုဂရမ်ကို ဖယ်ရှားနိုင်သည်"</string>
+    <string name="uninstall_kiosk_app" msgid="3459557395024053988">"သင့်စက်မှ Kiosk app ကို ဖြုတ်နိုင်သည်"</string>
     <string name="getting_device_ready" msgid="2829009584599871699">"သင့်စက်ကို အသင့်ပြင်နေသည်…"</string>
     <string name="this_may_take_a_few_minutes" msgid="2482876246874429351">"မိနစ်အနည်းငယ် ကြာနိုင်ပါသည်"</string>
     <string name="installing_kiosk_app" msgid="324208168205545860">"<xliff:g id="CREDITOR_APP">%1$s</xliff:g> အက်ပ်ကို ထည့်သွင်းနေသည်…"</string>
@@ -114,7 +114,7 @@
     <string name="settings_fully_paid_category_preference_key" msgid="1759690898170600559">"settings_fully_paid_category_preference_key"</string>
     <string name="settings_restrictions_removed" msgid="1398080654904863221">"<xliff:g id="PROVIDER_NAME">%1$s</xliff:g> သည် သင့်စက်ကို ကန့်သတ်၍မရပါ (သို့) စက်ဆက်တင်များကို ပြောင်း၍မရပါ"</string>
     <string name="settings_restrictions_removed_preference_key" msgid="7741933477145197391">"settings_restrictions_removed_preference_key"</string>
-    <string name="settings_uninstall_kiosk_app" msgid="2611134364295637875">"<xliff:g id="KIOSK_APP">%1$s</xliff:g> အက်ပ်ကို ပရိုဂရမ်ဖယ်ရှားနိုင်သည်"</string>
+    <string name="settings_uninstall_kiosk_app" msgid="2611134364295637875">"<xliff:g id="KIOSK_APP">%1$s</xliff:g> အက်ပ်ကို ဖြုတ်နိုင်သည်"</string>
     <string name="settings_uninstall_kiosk_app_preference_key" msgid="5578103644009268125">"settings_uninstall_kiosk_app_preference_key"</string>
     <string name="settings_support_category" msgid="7210906871924935770">"အကူအညီရယူရန်-"</string>
     <string name="settings_support_category_preference_key" msgid="1818953199283261021">"settings_support_category_preference_key"</string>
diff --git a/DeviceLockController/res/values-or/strings.xml b/DeviceLockController/res/values-or/strings.xml
index 887f557f..50e1c621 100644
--- a/DeviceLockController/res/values-or/strings.xml
+++ b/DeviceLockController/res/values-or/strings.xml
@@ -90,7 +90,7 @@
     <string name="settings_install_apps_preference_key" msgid="27542314345238427">"settings_install_apps_preference_key"</string>
     <string name="settings_safe_mode" msgid="3035228015586375153">"ଆପଣଙ୍କ ଡିଭାଇସକୁ ସୁରକ୍ଷିତ ମୋଡରେ ରିବୁଟ କରନ୍ତୁ"</string>
     <string name="settings_safe_mode_preference_key" msgid="2106617747358027424">"settings_safe_mode_preference_key"</string>
-    <string name="settings_developer_options" msgid="880701002025216672">"ଡେଭେଲପର ବିକଳ୍ପଗୁଡ଼ିକୁ ବ୍ୟବହାର କରିପାରିବ"</string>
+    <string name="settings_developer_options" msgid="880701002025216672">"ଡେଭେଲପର ବିକଳ୍ପଗୁଡ଼ିକୁ ବ୍ୟବହାର କରନ୍ତୁ"</string>
     <string name="settings_developer_options_preference_key" msgid="6807036808722582954">"settings_developer_options_preference_key"</string>
     <string name="settings_credit_provider_capabilities_category" msgid="1274440595211820868">"ଯଦି ଡିଭାଇସରେ କିଛି ତ୍ରୁଟି ହୁଏ, ତେବେ <xliff:g id="PROVIDER_NAME">%1$s</xliff:g>:"</string>
     <string name="settings_credit_provider_capabilities_category_preference_key" msgid="4571685720898641262">"settings_credit_provider_capabilities_category_preference_key"</string>
diff --git a/DeviceLockController/res/values-pt/strings.xml b/DeviceLockController/res/values-pt/strings.xml
index 90e5f764..6f377b92 100644
--- a/DeviceLockController/res/values-pt/strings.xml
+++ b/DeviceLockController/res/values-pt/strings.xml
@@ -18,7 +18,7 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="app_name" msgid="5655878067457216814">"DeviceLockController"</string>
-    <string name="next_button" msgid="1856423430963548653">"Próxima"</string>
+    <string name="next_button" msgid="1856423430963548653">"Avançar"</string>
     <string name="reset_button" msgid="4649354411129240809">"Reiniciar"</string>
     <string name="setup_more_button" msgid="4456370972302510109">"Mais"</string>
     <string name="setup_info_title_text" msgid="299562193092219293">"Como o app <xliff:g id="CREDITOR_APP">%1$s</xliff:g> pode gerenciar este dispositivo"</string>
@@ -52,7 +52,7 @@
     <string name="restrict_device_if_dont_make_payment" msgid="1619095674945507015">"A <xliff:g id="PROVIDER_NAME">%1$s</xliff:g> pode restringir este dispositivo caso você não faça os pagamentos necessários. Para mais detalhes, consulte os <xliff:g id="TERMS_AND_CONDITIONS_LINK_START">&lt;a href=%2$s&gt;</xliff:g>Termos e Condições<xliff:g id="TERMS_AND_CONDITIONS_LINK_END">&lt;/a&gt;</xliff:g>."</string>
     <string name="contact_provider_for_help" msgid="3872028089834808884">"Para receber ajuda, <xliff:g id="SUPPORT_LINK_START">&lt;a href=%2$s&gt;</xliff:g>entre em contato com <xliff:g id="PROVIDER_NAME">%1$s</xliff:g><xliff:g id="SUPPORT_LINK_END">&lt;/a&gt;</xliff:g>."</string>
     <string name="previous" msgid="5241891780917802570">"Anterior"</string>
-    <string name="next" msgid="8248291863254324326">"Próxima"</string>
+    <string name="next" msgid="8248291863254324326">"Avançar"</string>
     <string name="start" msgid="2842214844667658537">"Iniciar"</string>
     <string name="ok" msgid="3568398726528719749">"OK"</string>
     <string name="done" msgid="4507782734740410307">"Concluído"</string>
diff --git a/DeviceLockController/res/values-zh-rCN/strings.xml b/DeviceLockController/res/values-zh-rCN/strings.xml
index ececc6bb..95ecff12 100644
--- a/DeviceLockController/res/values-zh-rCN/strings.xml
+++ b/DeviceLockController/res/values-zh-rCN/strings.xml
@@ -73,7 +73,7 @@
     <string name="device_removed_from_finance_program" msgid="825548999540107578">"您的设备已退出<xliff:g id="PROVIDER_NAME">%1$s</xliff:g>的分期付款计划"</string>
     <string name="restrictions_lifted" msgid="5785586265984319396">"针对设备的所有限制均已解除"</string>
     <string name="uninstall_kiosk_app" msgid="3459557395024053988">"您可以从设备上卸载自助服务终端应用"</string>
-    <string name="getting_device_ready" msgid="2829009584599871699">"正在准备您的设备…"</string>
+    <string name="getting_device_ready" msgid="2829009584599871699">"正在设置设备…"</string>
     <string name="this_may_take_a_few_minutes" msgid="2482876246874429351">"这可能需要几分钟的时间"</string>
     <string name="installing_kiosk_app" msgid="324208168205545860">"正在安装“<xliff:g id="CREDITOR_APP">%1$s</xliff:g>”应用…"</string>
     <string name="opening_kiosk_app" msgid="2021888641430165654">"正在打开“<xliff:g id="CREDITOR_APP">%1$s</xliff:g>”应用…"</string>
diff --git a/DeviceLockController/res/values/overlayable.xml b/DeviceLockController/res/values/overlayable.xml
deleted file mode 100644
index 5fc1fde9..00000000
--- a/DeviceLockController/res/values/overlayable.xml
+++ /dev/null
@@ -1,32 +0,0 @@
-<?xml version="1.0" encoding="utf-8"?><!--
-  Copyright (c) 2022, The Android Open Source Project
-
-  Licensed under the Apache License, Version 2.0 (the "License");
-  you may not use this file except in compliance with the License.
-  You may obtain a copy of the License at
-
-      http://www.apache.org/licenses/LICENSE-2.0
-
-  Unless required by applicable law or agreed to in writing, software
-  distributed under the License is distributed on an "AS IS" BASIS,
-  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-  See the License for the specific language governing permissions and
-  limitations under the License.
--->
-
-<resources>
-    <overlayable name="DeviceLockResources">
-        <policy type="system|vendor|product">
-            <item name="lock_task_allowlist" type="array" />
-            <item name="device_id_type_bitmap" type="integer" />
-            <item name="check_in_server_host_name" type="string" />
-            <item name="check_in_server_port_number" type="integer" />
-            <item name="check_in_service_api_key_name" type="string" />
-            <item name="check_in_service_api_key_value" type="string" />
-            <item name="finalize_server_port_number" type="integer" />
-            <item name="finalize_server_host_name" type="string" />
-            <item name="finalize_service_api_key_name" type="string" />
-            <item name="finalize_service_api_key_value" type="string" />
-        </policy>
-    </overlayable>
-</resources>
diff --git a/DeviceLockController/src/com/android/devicelockcontroller/DeviceLockControllerApplication.java b/DeviceLockController/src/com/android/devicelockcontroller/DeviceLockControllerApplication.java
index ef69e518..87995e9b 100644
--- a/DeviceLockController/src/com/android/devicelockcontroller/DeviceLockControllerApplication.java
+++ b/DeviceLockController/src/com/android/devicelockcontroller/DeviceLockControllerApplication.java
@@ -119,7 +119,7 @@ public class DeviceLockControllerApplication extends Application implements
     @Override
     public synchronized StatsLogger getStatsLogger() {
         if (null == mStatsLogger) {
-            mStatsLogger = new StatsLoggerImpl();
+            mStatsLogger = new StatsLoggerImpl(this);
         }
         return mStatsLogger;
     }
diff --git a/DeviceLockController/src/com/android/devicelockcontroller/DeviceLockControllerService.java b/DeviceLockController/src/com/android/devicelockcontroller/DeviceLockControllerService.java
index 7b999314..efcb1048 100644
--- a/DeviceLockController/src/com/android/devicelockcontroller/DeviceLockControllerService.java
+++ b/DeviceLockController/src/com/android/devicelockcontroller/DeviceLockControllerService.java
@@ -16,9 +16,15 @@
 
 package com.android.devicelockcontroller;
 
+import static com.android.devicelockcontroller.DevicelockStatsLog.DEVICE_LOCK_DEVICE_STATE_EVENT__EVENT__EVENT_LOCK;
+import static com.android.devicelockcontroller.DevicelockStatsLog.DEVICE_LOCK_DEVICE_STATE_EVENT__EVENT__EVENT_UNLOCK;
+import static com.android.devicelockcontroller.DevicelockStatsLog.DEVICE_LOCK_PROVISION_STATE_EVENT__EVENT__EVENT_FINALIZATION;
+import static com.android.devicelockcontroller.DevicelockStatsLog.DEVICE_LOCK_PROVISION_STATE_EVENT__EVENT__EVENT_FINALIZATION_FAILURE;
+
 import android.app.Service;
 import android.content.Intent;
 import android.content.pm.PackageManager;
+import android.devicelock.DeviceLockManager;
 import android.devicelock.ParcelableException;
 import android.os.Bundle;
 import android.os.IBinder;
@@ -27,6 +33,7 @@ import android.os.RemoteCallback;
 import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
 
+import com.android.devicelockcontroller.common.DeviceLockConstants.ProvisioningType;
 import com.android.devicelockcontroller.policy.DevicePolicyController;
 import com.android.devicelockcontroller.policy.DeviceStateController;
 import com.android.devicelockcontroller.policy.FinalizationController;
@@ -53,18 +60,29 @@ public final class DeviceLockControllerService extends Service {
     private FinalizationController mFinalizationController;
     private PackageManager mPackageManager;
     private StatsLogger mStatsLogger;
-
+    // Checkstyle results in line too long when using original constant.
+    private static final int FINALIZATION =
+            DEVICE_LOCK_PROVISION_STATE_EVENT__EVENT__EVENT_FINALIZATION;
+    // Checkstyle results in line too long when using original constant.
+    private static final int FINALIZATION_FAILURE =
+            DEVICE_LOCK_PROVISION_STATE_EVENT__EVENT__EVENT_FINALIZATION_FAILURE;
+    // Checkstyle results in line too long when using original constant.
+    private static final int LOCK = DEVICE_LOCK_DEVICE_STATE_EVENT__EVENT__EVENT_LOCK;
+    // Checkstyle results in line too long when using original constant.
+    private static final int UNLOCK = DEVICE_LOCK_DEVICE_STATE_EVENT__EVENT__EVENT_UNLOCK;
     private final IDeviceLockControllerService.Stub mBinder =
             new IDeviceLockControllerService.Stub() {
                 @Override
                 public void lockDevice(RemoteCallback remoteCallback) {
                     logKioskAppRequest();
                     ListenableFuture<Void> lockDeviceFuture = mDeviceStateController.lockDevice();
-                    Futures.addCallback(lockDeviceFuture,
+                    Futures.addCallback(
+                            lockDeviceFuture,
                             remoteCallbackWrapper(remoteCallback),
                             MoreExecutors.directExecutor());
-                    Futures.addCallback(lockDeviceFuture,
-                            logLockUnlockDeviceCallback(/* isLockDevice = */ true),
+                    Futures.addCallback(
+                            lockDeviceFuture,
+                            logLockUnlockDeviceCallback(/* isLockDevice= */ true),
                             MoreExecutors.directExecutor());
                 }
 
@@ -73,18 +91,21 @@ public final class DeviceLockControllerService extends Service {
                     logKioskAppRequest();
                     ListenableFuture<Void> unlockDeviceFuture =
                             mDeviceStateController.unlockDevice();
-                    Futures.addCallback(unlockDeviceFuture,
+                    Futures.addCallback(
+                            unlockDeviceFuture,
                             remoteCallbackWrapper(remoteCallback),
                             MoreExecutors.directExecutor());
-                    Futures.addCallback(unlockDeviceFuture,
-                            logLockUnlockDeviceCallback(/* isLockDevice = */ false),
+                    Futures.addCallback(
+                            unlockDeviceFuture,
+                            logLockUnlockDeviceCallback(/* isLockDevice= */ false),
                             MoreExecutors.directExecutor());
                 }
 
                 @Override
                 public void isDeviceLocked(RemoteCallback remoteCallback) {
                     logKioskAppRequest();
-                    Futures.addCallback(mDeviceStateController.isLocked(),
+                    Futures.addCallback(
+                            mDeviceStateController.isLocked(),
                             remoteCallbackWrapper(remoteCallback, KEY_RESULT),
                             MoreExecutors.directExecutor());
                 }
@@ -101,21 +122,101 @@ public final class DeviceLockControllerService extends Service {
                 @Override
                 public void clearDeviceRestrictions(RemoteCallback remoteCallback) {
                     logKioskAppRequest();
-                    Futures.addCallback(
-                            Futures.transformAsync(mDeviceStateController.clearDevice(),
+                    ListenableFuture<Void> clearDeviceFuture = mDeviceStateController.clearDevice();
+                    ListenableFuture<Void> restrictionsClearedChain =
+                            Futures.transformAsync(
+                                    clearDeviceFuture,
                                     unused -> mFinalizationController.notifyRestrictionsCleared(),
+                                    MoreExecutors.directExecutor());
+
+                    // Attaching this callback because it allows us to log finalization success &
+                    // failure.
+                    Futures.addCallback(
+                            restrictionsClearedChain,
+                            new FutureCallback<Void>() {
+                                @Override
+                                public void onSuccess(Void result) {
+                                    mStatsLogger.logProvisionStateEvent(FINALIZATION);
+                                    sendResult(null, remoteCallback, result);
+                                }
+
+                                @Override
+                                public void onFailure(Throwable t) {
+                                    mStatsLogger.logProvisionStateEvent(FINALIZATION_FAILURE);
+                                    sendFailure(t, remoteCallback);
+                                }
+                            },
+                            MoreExecutors.directExecutor());
+                }
+
+                @Override
+                public void getEnrollmentType(RemoteCallback remoteCallback) {
+                    logKioskAppRequest();
+
+                    Futures.addCallback(
+                            Futures.transform(
+                                    SetupParametersClient.getInstance().getProvisioningType(),
+                                    provisioningType -> {
+                                        switch (provisioningType) {
+                                            case ProvisioningType.TYPE_FINANCED:
+                                                return DeviceLockManager.ENROLLMENT_TYPE_FINANCE;
+                                            case ProvisioningType.TYPE_SUBSIDY:
+                                                return DeviceLockManager.ENROLLMENT_TYPE_SUBSIDY;
+                                            default:
+                                                // For the ProvisioningType.TYPE_UNDEFINED case.
+                                                return DeviceLockManager.ENROLLMENT_TYPE_NONE;
+                                        }
+                                    },
+                                    MoreExecutors.directExecutor()),
+                            remoteCallbackWrapper(remoteCallback, KEY_RESULT),
+                            MoreExecutors.directExecutor());
+                }
+
+                @Override
+                public void notifyKioskSetupFinished(RemoteCallback remoteCallback) {
+                    logKioskAppRequest();
+                    // Future to execute the lock/unlock device command.
+                    ListenableFuture<Void> lockUnlockDeviceFuture =
+                            Futures.transformAsync(
+                                    mDeviceStateController.isLocked(),
+                                    isLocked -> {
+                                        if (isLocked) {
+                                            return mDeviceStateController.lockDevice();
+                                        }
+                                        return mDeviceStateController.unlockDevice();
+                                    },
+                                    MoreExecutors.directExecutor());
+                    Futures.addCallback(
+                            Futures.catchingAsync(
+                                    lockUnlockDeviceFuture,
+                                    IllegalStateException.class,
+                                    unused -> mDeviceStateController.unlockDevice(),
                                     MoreExecutors.directExecutor()),
                             remoteCallbackWrapper(remoteCallback),
                             MoreExecutors.directExecutor());
+
+                    // Execute the log callback after the device is locked or unlocked.
+                    try {
+                        ListenableFuture<Boolean> isLocked = mDeviceStateController.isLocked();
+                        Futures.addCallback(
+                                Futures.transform(
+                                        isLocked, unused -> null, MoreExecutors.directExecutor()),
+                                logLockUnlockDeviceCallback(/* isLockDevice= */ isLocked.get()),
+                                MoreExecutors.directExecutor());
+                    } catch (Exception e) {
+                        LogUtil.e(TAG, "Failed to get device state", e);
+                    }
                 }
 
                 @Override
                 public void onUserSwitching(RemoteCallback remoteCallback) {
                     Futures.addCallback(
-                            Futures.transformAsync(mPolicyController.enforceCurrentPolicies(),
+                            Futures.transformAsync(
+                                    mPolicyController.enforceCurrentPolicies(),
                                     // Force read from disk in case it progressed on the other user
-                                    unused -> mFinalizationController.enforceDiskState(
-                                            /* force= */ true),
+                                    unused ->
+                                            mFinalizationController.enforceDiskState(
+                                                    /* force= */ true),
                                     MoreExecutors.directExecutor()),
                             remoteCallbackWrapper(remoteCallback),
                             MoreExecutors.directExecutor());
@@ -123,33 +224,38 @@ public final class DeviceLockControllerService extends Service {
 
                 @Override
                 public void onUserUnlocked(RemoteCallback remoteCallback) {
-                    Futures.addCallback(mPolicyController.onUserUnlocked(),
+                    Futures.addCallback(
+                            mPolicyController.onUserUnlocked(),
                             remoteCallbackWrapper(remoteCallback),
                             MoreExecutors.directExecutor());
                 }
 
                 @Override
                 public void onUserSetupCompleted(RemoteCallback remoteCallback) {
-                    Futures.addCallback(mPolicyController.onUserSetupCompleted(),
+                    Futures.addCallback(
+                            mPolicyController.onUserSetupCompleted(),
                             remoteCallbackWrapper(remoteCallback),
                             MoreExecutors.directExecutor());
                 }
 
                 @Override
                 public void onAppCrashed(boolean isKiosk, RemoteCallback remoteCallback) {
-                    Futures.addCallback(mPolicyController.onAppCrashed(isKiosk),
+                    Futures.addCallback(
+                            mPolicyController.onAppCrashed(isKiosk),
                             remoteCallbackWrapper(remoteCallback),
                             MoreExecutors.directExecutor());
                 }
 
                 private void logKioskAppRequest() {
-                    Futures.addCallback(SetupParametersClient.getInstance().getKioskPackage(),
+                    Futures.addCallback(
+                            SetupParametersClient.getInstance().getKioskPackage(),
                             new FutureCallback<>() {
                                 @Override
                                 public void onSuccess(String result) {
                                     try {
-                                        final int uid = mPackageManager.getPackageUid(
-                                                result, /* flags= */ 0);
+                                        final int uid =
+                                                mPackageManager.getPackageUid(
+                                                        result, /* flags= */ 0);
                                         mStatsLogger.logKioskAppRequest(uid);
                                     } catch (PackageManager.NameNotFoundException e) {
                                         LogUtil.e(TAG, "Kiosk App package name not found", e);
@@ -162,7 +268,6 @@ public final class DeviceLockControllerService extends Service {
                                 }
                             },
                             MoreExecutors.directExecutor());
-
                 }
             };
 
@@ -203,6 +308,8 @@ public final class DeviceLockControllerService extends Service {
                 bundle.putBoolean(key, (Boolean) result);
             } else if (result instanceof String) {
                 bundle.putString(key, (String) result);
+            } else if (result instanceof Integer){
+                bundle.putInt(key, (Integer) result);
             }
         }
         remoteCallback.sendResult(bundle);
@@ -220,15 +327,16 @@ public final class DeviceLockControllerService extends Service {
             @Override
             public void onSuccess(Void result) {
                 if (isLockDevice) {
-                    mStatsLogger.logSuccessfulLockingDevice();
+                    mStatsLogger.logDeviceStateEvent(LOCK);
                 } else {
-                    mStatsLogger.logSuccessfulUnlockingDevice();
+                    mStatsLogger.logDeviceStateEvent(UNLOCK);
                 }
             }
 
             @Override
             public void onFailure(Throwable t) {
-                Futures.addCallback(mDeviceStateController.getDeviceState(),
+                Futures.addCallback(
+                        mDeviceStateController.getDeviceState(),
                         new FutureCallback<Integer>() {
                             @Override
                             public void onSuccess(Integer result) {
@@ -246,8 +354,9 @@ public final class DeviceLockControllerService extends Service {
                                     case DeviceStateController.DeviceState.UNDEFINED ->
                                             deviceStatePostCommand =
                                                     StatsLogger.DeviceStateStats.UNDEFINED;
-                                    default -> deviceStatePostCommand =
-                                            StatsLogger.DeviceStateStats.UNDEFINED;
+                                    default ->
+                                            deviceStatePostCommand =
+                                                    StatsLogger.DeviceStateStats.UNDEFINED;
                                 }
                                 if (isLockDevice) {
                                     mStatsLogger.logLockDeviceFailure(deviceStatePostCommand);
@@ -262,7 +371,8 @@ public final class DeviceLockControllerService extends Service {
                                 LogUtil.e(TAG, "Failed to get device State", t);
                                 throw new RuntimeException(t);
                             }
-                        }, MoreExecutors.directExecutor());
+                        },
+                        MoreExecutors.directExecutor());
             }
         };
     }
diff --git a/DeviceLockController/src/com/android/devicelockcontroller/IDeviceLockControllerService.aidl b/DeviceLockController/src/com/android/devicelockcontroller/IDeviceLockControllerService.aidl
index bbc8cff2..dc14e0b5 100644
--- a/DeviceLockController/src/com/android/devicelockcontroller/IDeviceLockControllerService.aidl
+++ b/DeviceLockController/src/com/android/devicelockcontroller/IDeviceLockControllerService.aidl
@@ -58,6 +58,16 @@ oneway interface IDeviceLockControllerService {
      */
     void clearDeviceRestrictions(in RemoteCallback callback);
 
+    /**
+     * Notifies the controller that the kiosk setup has finished.
+     */
+    void notifyKioskSetupFinished(in RemoteCallback callback);
+
+    /**
+     * Gets the enrollment type.
+     */
+    void getEnrollmentType(in RemoteCallback callback);
+
     /**
      * Called when a user has just been switched to.
      *
diff --git a/DeviceLockController/src/com/android/devicelockcontroller/common/DeviceLockConstants.java b/DeviceLockController/src/com/android/devicelockcontroller/common/DeviceLockConstants.java
index 22f867ae..15efb0e5 100644
--- a/DeviceLockController/src/com/android/devicelockcontroller/common/DeviceLockConstants.java
+++ b/DeviceLockController/src/com/android/devicelockcontroller/common/DeviceLockConstants.java
@@ -45,6 +45,7 @@ public final class DeviceLockConstants {
             DeviceIdType.DEVICE_ID_TYPE_UNSPECIFIED,
             DeviceIdType.DEVICE_ID_TYPE_IMEI,
             DeviceIdType.DEVICE_ID_TYPE_MEID,
+            DeviceIdType.DEVICE_ID_TYPE_SERIAL_NUMBER,
     })
     public @interface DeviceIdType {
         // The device id type is unspecified
@@ -53,10 +54,12 @@ public final class DeviceLockConstants {
         int DEVICE_ID_TYPE_IMEI = 0;
         // The device id is a MEID
         int DEVICE_ID_TYPE_MEID = 1;
+        // The device id is a serial number
+        int DEVICE_ID_TYPE_SERIAL_NUMBER = 2;
     }
 
     @DeviceIdType
-    private static final int LAST_DEVICE_ID_TYPE = DeviceIdType.DEVICE_ID_TYPE_MEID;
+    private static final int LAST_DEVICE_ID_TYPE = DeviceIdType.DEVICE_ID_TYPE_SERIAL_NUMBER;
     public static final int TOTAL_DEVICE_ID_TYPES = LAST_DEVICE_ID_TYPE + 1;
 
     // Constants related to unique device identifiers.
diff --git a/DeviceLockController/src/com/android/devicelockcontroller/policy/DevicePolicyControllerImpl.java b/DeviceLockController/src/com/android/devicelockcontroller/policy/DevicePolicyControllerImpl.java
index de3c6318..a2434e31 100644
--- a/DeviceLockController/src/com/android/devicelockcontroller/policy/DevicePolicyControllerImpl.java
+++ b/DeviceLockController/src/com/android/devicelockcontroller/policy/DevicePolicyControllerImpl.java
@@ -41,7 +41,6 @@ import android.database.sqlite.SQLiteException;
 import android.os.Build;
 import android.os.UserManager;
 
-import androidx.annotation.GuardedBy;
 import androidx.annotation.VisibleForTesting;
 import androidx.work.ExistingWorkPolicy;
 import androidx.work.OneTimeWorkRequest;
@@ -54,6 +53,7 @@ import com.android.devicelockcontroller.activities.LandingActivity;
 import com.android.devicelockcontroller.activities.ProvisioningActivity;
 import com.android.devicelockcontroller.common.DeviceLockConstants;
 import com.android.devicelockcontroller.common.DeviceLockConstants.ProvisioningType;
+import com.android.devicelockcontroller.policy.DevicePolicyController.LockTaskType;
 import com.android.devicelockcontroller.policy.DeviceStateController.DeviceState;
 import com.android.devicelockcontroller.policy.ProvisionStateController.ProvisionState;
 import com.android.devicelockcontroller.provision.worker.ReportDeviceProvisionStateWorker;
@@ -79,46 +79,47 @@ import java.util.concurrent.Executor;
  * request until the former completes.
  */
 public final class DevicePolicyControllerImpl implements DevicePolicyController {
+    static final String ACTION_DEVICE_LOCK_KIOSK_SETUP =
+            "com.android.devicelock.action.KIOSK_SETUP";
+    private static final String DEVICE_LOCK_VERSION_EXTRA =
+            "android.devicelock.extra.DEVICE_LOCK_VERSION";
+    // Added for support to existing implementations before the
+    // DEVICE_LOCK_VERSION_EXTRA is merged to 25Q4
+    // TODO: b/417696889 - deprecate this.
+    private static final String OLD_DEVICE_LOCK_VERSION_EXTRA =
+            "DEVICE_LOCK_VERSION";
     private static final String TAG = "DevicePolicyControllerImpl";
-
+    private static final int DEVICE_LOCK_VERSION = 2;
     private final List<PolicyHandler> mPolicyList = new ArrayList<>();
     private final Context mContext;
     private final DevicePolicyManager mDpm;
     private final ProvisionStateController mProvisionStateController;
-    // A future that returns the current lock task type for the current provision/device state
-    // after policies enforcement are done.
-    @GuardedBy("this")
-    private ListenableFuture<@LockTaskType Integer> mCurrentEnforcedLockTaskTypeFuture =
-            Futures.immediateFuture(LockTaskType.UNDEFINED);
     private final Executor mBgExecutor;
-    static final String ACTION_DEVICE_LOCK_KIOSK_SETUP =
-            "com.android.devicelock.action.KIOSK_SETUP";
-    private static final String DEVICE_LOCK_VERSION_EXTRA = "DEVICE_LOCK_VERSION";
-    private static final int DEVICE_LOCK_VERSION = 2;
     private final UserManager mUserManager;
 
     /**
      * Create a new policy controller.
      *
      * @param context The context used by this policy controller.
-     * @param devicePolicyManager  The device policy manager.
+     * @param devicePolicyManager The device policy manager.
      * @param userManager The user manager.
      * @param systemDeviceLockManager The system device lock manager.
      * @param provisionStateController The provision state controller.
      * @param bgExecutor The background executor.
      */
-    public DevicePolicyControllerImpl(Context context,
+    public DevicePolicyControllerImpl(
+            Context context,
             DevicePolicyManager devicePolicyManager,
             UserManager userManager,
             SystemDeviceLockManager systemDeviceLockManager,
             ProvisionStateController provisionStateController,
             Executor bgExecutor) {
-        this(context,
+        this(
+                context,
                 devicePolicyManager,
                 userManager,
-                new UserRestrictionsPolicyHandler(devicePolicyManager, userManager,
-                        Build.isDebuggable(),
-                        bgExecutor),
+                new UserRestrictionsPolicyHandler(
+                        devicePolicyManager, userManager, Build.isDebuggable(), bgExecutor),
                 new AppOpsPolicyHandler(systemDeviceLockManager, bgExecutor),
                 new LockTaskModePolicyHandler(context, devicePolicyManager, bgExecutor),
                 new PackagePolicyHandler(context, devicePolicyManager, bgExecutor),
@@ -131,7 +132,8 @@ public final class DevicePolicyControllerImpl implements DevicePolicyController
     }
 
     @VisibleForTesting
-    DevicePolicyControllerImpl(Context context,
+    DevicePolicyControllerImpl(
+            Context context,
             DevicePolicyManager devicePolicyManager,
             UserManager userManager,
             PolicyHandler userRestrictionsPolicyHandler,
@@ -163,8 +165,9 @@ public final class DevicePolicyControllerImpl implements DevicePolicyController
     public boolean wipeDevice() {
         LogUtil.i(TAG, "Wiping device");
         try {
-            mDpm.wipeDevice(DevicePolicyManager.WIPE_SILENTLY
-                    | DevicePolicyManager.WIPE_RESET_PROTECTION_DATA);
+            mDpm.wipeDevice(
+                    DevicePolicyManager.WIPE_SILENTLY
+                            | DevicePolicyManager.WIPE_RESET_PROTECTION_DATA);
         } catch (SecurityException e) {
             LogUtil.e(TAG, "Cannot wipe device", e);
             return false;
@@ -174,8 +177,8 @@ public final class DevicePolicyControllerImpl implements DevicePolicyController
 
     @Override
     public ListenableFuture<Void> enforceCurrentPolicies() {
-        return Futures.transform(enforceCurrentPoliciesAndResolveLockTaskType(
-                        /* failure= */ false),
+        return Futures.transform(
+                enforceCurrentPoliciesAndResolveLockTaskType(/* failure= */ false),
                 mode -> {
                     startLockTaskModeIfNeeded(mode);
                     return null;
@@ -185,8 +188,8 @@ public final class DevicePolicyControllerImpl implements DevicePolicyController
 
     @Override
     public ListenableFuture<Void> enforceCurrentPoliciesForCriticalFailure() {
-        return Futures.transform(enforceCurrentPoliciesAndResolveLockTaskType(
-                        /* failure= */ true),
+        return Futures.transform(
+                enforceCurrentPoliciesAndResolveLockTaskType(/* failure= */ true),
                 mode -> {
                     startLockTaskModeIfNeeded(mode);
                     handlePolicyEnforcementFailure();
@@ -203,7 +206,8 @@ public final class DevicePolicyControllerImpl implements DevicePolicyController
         // Hard failure due to policy enforcement, treat it as mandatory reset device alarm.
         scheduler.scheduleMandatoryResetDeviceAlarm();
 
-        ReportDeviceProvisionStateWorker.reportSetupFailed(WorkManager.getInstance(mContext),
+        ReportDeviceProvisionStateWorker.reportSetupFailed(
+                WorkManager.getInstance(mContext),
                 DeviceLockConstants.ProvisionFailureReason.POLICY_ENFORCEMENT_FAILED);
     }
 
@@ -219,7 +223,8 @@ public final class DevicePolicyControllerImpl implements DevicePolicyController
             // current lock task type must be assigned to a local variable; otherwise, if
             // retrieved down the execution flow, it will be returning the new type after execution.
             ListenableFuture<@LockTaskType Integer> currentLockTaskType =
-                    mCurrentEnforcedLockTaskTypeFuture;
+                    GlobalParametersClient.getInstance().getLockTaskType();
+
             ListenableFuture<@LockTaskType Integer> policiesEnforcementFuture =
                     Futures.transformAsync(
                             currentLockTaskType,
@@ -230,34 +235,54 @@ public final class DevicePolicyControllerImpl implements DevicePolicyController
                                         GlobalParametersClient.getInstance().getDeviceState();
                                 return Futures.whenAllSucceed(provisionState, deviceState)
                                         .callAsync(
-                                                () -> enforcePoliciesForCurrentStates(
-                                                        Futures.getDone(provisionState),
-                                                        Futures.getDone(deviceState)),
-                                                mBgExecutor
-                                );
+                                                () ->
+                                                        enforcePoliciesForCurrentStates(
+                                                                Futures.getDone(provisionState),
+                                                                Futures.getDone(deviceState)),
+                                                mBgExecutor);
                             },
                             mBgExecutor);
             if (failure) {
-                mCurrentEnforcedLockTaskTypeFuture = Futures.immediateFuture(
-                        LockTaskType.CRITICAL_ERROR);
-                return mCurrentEnforcedLockTaskTypeFuture;
+                return Futures.transform(
+                        GlobalParametersClient.getInstance()
+                                .setLockTaskType(LockTaskType.CRITICAL_ERROR),
+                        unused -> LockTaskType.CRITICAL_ERROR,
+                        mBgExecutor);
             } else {
                 // To prevent exception propagate to future policies enforcement, catch any
                 // exceptions that might happen during the execution and fallback to previous type
                 // if exception happens.
-                mCurrentEnforcedLockTaskTypeFuture = Futures.catchingAsync(
-                        policiesEnforcementFuture,
-                        Exception.class, unused -> currentLockTaskType,
-                        MoreExecutors.directExecutor());
+                ListenableFuture<@LockTaskType Integer> outcomeFuture =
+                        Futures.catchingAsync(
+                                policiesEnforcementFuture,
+                                Exception.class,
+                                unused -> currentLockTaskType,
+                                MoreExecutors.directExecutor());
+                ListenableFuture<Void> storageFuture =
+                        Futures.transformAsync(
+                                outcomeFuture,
+                                newLockTaskType -> {
+                                    LogUtil.i(
+                                            TAG,
+                                            "Resolved LockTaskType: " + newLockTaskType);
+                                    return GlobalParametersClient.getInstance()
+                                            .setLockTaskType(newLockTaskType);
+                                },
+                                mBgExecutor);
+                return Futures.transformAsync(
+                        storageFuture, unused -> policiesEnforcementFuture, mBgExecutor);
             }
-            return policiesEnforcementFuture;
         }
     }
 
     private ListenableFuture<@LockTaskType Integer> enforcePoliciesForCurrentStates(
             @ProvisionState int provisionState, @DeviceState int deviceState) {
-        LogUtil.i(TAG, "Enforcing policies for provision state " + provisionState
-                + " and device state " + deviceState);
+        LogUtil.i(
+                TAG,
+                "Enforcing policies for provision state "
+                        + provisionState
+                        + " and device state "
+                        + deviceState);
         List<ListenableFuture<Boolean>> futures = new ArrayList<>();
         if (deviceState == CLEARED) {
             // If device is cleared, then ignore provision state and add cleared policies
@@ -310,22 +335,23 @@ public final class DevicePolicyControllerImpl implements DevicePolicyController
                 }
             }
         }
-        return Futures.transform(Futures.allAsList(futures),
+        return Futures.transform(
+                Futures.allAsList(futures),
                 results -> {
                     if (results.stream().reduce(true, (a, r) -> a && r)) {
                         return resolveLockTaskType(provisionState, deviceState);
                     } else {
                         throw new IllegalStateException(
-                                "Failed to enforce policies for provision state " + provisionState
-                                        + " and device state " + deviceState);
+                                "Failed to enforce policies for provision state "
+                                        + provisionState
+                                        + " and device state "
+                                        + deviceState);
                     }
                 },
                 MoreExecutors.directExecutor());
     }
 
-    /**
-     * Determines the lock task type based on the current provision and device state
-     */
+    /** Determines the lock task type based on the current provision and device state */
     private @LockTaskType int resolveLockTaskType(int provisionState, int deviceState) {
         if (provisionState == UNPROVISIONED || deviceState == CLEARED) {
             return LockTaskType.NOT_IN_LOCK_TASK;
@@ -349,16 +375,16 @@ public final class DevicePolicyControllerImpl implements DevicePolicyController
                     if (kioskPackage == null) {
                         throw new IllegalStateException("Missing kiosk package parameter!");
                     }
-                    Intent homeIntent = new Intent(Intent.ACTION_MAIN)
-                            .addCategory(Intent.CATEGORY_HOME)
-                            .setPackage(kioskPackage);
+                    Intent homeIntent =
+                            new Intent(Intent.ACTION_MAIN)
+                                    .addCategory(Intent.CATEGORY_HOME)
+                                    .setPackage(kioskPackage);
                     PackageManager pm = mContext.getPackageManager();
-                    ResolveInfo resolvedInfo = pm.resolveActivity(homeIntent,
-                            PackageManager.MATCH_DEFAULT_ONLY);
+                    ResolveInfo resolvedInfo =
+                            pm.resolveActivity(homeIntent, PackageManager.MATCH_DEFAULT_ONLY);
                     if (resolvedInfo != null && resolvedInfo.activityInfo != null) {
                         return homeIntent.setComponent(
-                                new ComponentName(kioskPackage,
-                                        resolvedInfo.activityInfo.name));
+                                new ComponentName(kioskPackage, resolvedInfo.activityInfo.name));
                     }
                     // Kiosk app does not have an activity to handle the default
                     // home intent. Fall back to the launch activity.
@@ -370,14 +396,15 @@ public final class DevicePolicyControllerImpl implements DevicePolicyController
                                 "Failed to get launch intent for kiosk app!");
                     }
                     return launchIntent;
-                }, mBgExecutor);
+                },
+                mBgExecutor);
     }
 
     private ListenableFuture<Intent> getLandingActivityIntent() {
         SetupParametersClient client = SetupParametersClient.getInstance();
-        ListenableFuture<@ProvisioningType Integer> provisioningType =
-                client.getProvisioningType();
-        return Futures.transform(provisioningType,
+        ListenableFuture<@ProvisioningType Integer> provisioningType = client.getProvisioningType();
+        return Futures.transform(
+                provisioningType,
                 type -> {
                     Intent resultIntent = new Intent(mContext, LandingActivity.class);
                     switch (type) {
@@ -394,39 +421,49 @@ public final class DevicePolicyControllerImpl implements DevicePolicyController
                         default:
                             throw new IllegalArgumentException("Provisioning type is unknown!");
                     }
-                }, mBgExecutor);
+                },
+                mBgExecutor);
     }
 
     private ListenableFuture<Intent> getKioskSetupActivityIntent() {
-        return Futures.transform(SetupParametersClient.getInstance().getKioskPackage(),
+        return Futures.transform(
+                SetupParametersClient.getInstance().getKioskPackage(),
                 kioskPackageName -> {
                     if (kioskPackageName == null) {
                         throw new IllegalStateException("Missing kiosk package parameter!");
                     }
                     final Intent kioskSetupIntent = new Intent(ACTION_DEVICE_LOCK_KIOSK_SETUP);
                     kioskSetupIntent.setPackage(kioskPackageName);
-                    final ResolveInfo resolveInfo = mContext.getPackageManager()
-                            .resolveActivity(kioskSetupIntent, PackageManager.MATCH_DEFAULT_ONLY);
+                    final ResolveInfo resolveInfo =
+                            mContext.getPackageManager()
+                                    .resolveActivity(
+                                            kioskSetupIntent, PackageManager.MATCH_DEFAULT_ONLY);
                     if (resolveInfo == null || resolveInfo.activityInfo == null) {
                         throw new IllegalStateException(
                                 "Failed to get setup activity intent for kiosk app!");
                     }
                     kioskSetupIntent.putExtra(DEVICE_LOCK_VERSION_EXTRA, DEVICE_LOCK_VERSION);
-                    return kioskSetupIntent.setComponent(new ComponentName(kioskPackageName,
-                            resolveInfo.activityInfo.name));
-                }, mBgExecutor);
+                    // Added for support to existing implementations before the
+                    // DEVICE_LOCK_VERSION_EXTRA is merged to 25Q4
+                    // TODO: b/417696889 - deprecate this.
+                    kioskSetupIntent.putExtra(OLD_DEVICE_LOCK_VERSION_EXTRA, DEVICE_LOCK_VERSION);
+                    return kioskSetupIntent.setComponent(
+                            new ComponentName(kioskPackageName, resolveInfo.activityInfo.name));
+                },
+                mBgExecutor);
     }
 
     private ListenableFuture<Intent> getProvisioningActivityIntentForCriticalFailure() {
-        final Intent intent = new Intent(mContext, ProvisioningActivity.class)
-                .putExtra(EXTRA_SHOW_CRITICAL_PROVISION_FAILED_UI_ON_START, true);
+        final Intent intent =
+                new Intent(mContext, ProvisioningActivity.class)
+                        .putExtra(EXTRA_SHOW_CRITICAL_PROVISION_FAILED_UI_ON_START, true);
         return Futures.immediateFuture(intent);
     }
 
-
     @Override
     public ListenableFuture<Intent> getLaunchIntentForCurrentState() {
-        return Futures.transformAsync(getCurrentEnforcedLockTaskType(),
+        return Futures.transformAsync(
+                getCurrentEnforcedLockTaskType(),
                 type -> {
                     switch (type) {
                         case LockTaskType.NOT_IN_LOCK_TASK:
@@ -442,7 +479,8 @@ public final class DevicePolicyControllerImpl implements DevicePolicyController
                         default:
                             throw new IllegalArgumentException("Invalid lock task type!");
                     }
-                }, mBgExecutor);
+                },
+                mBgExecutor);
     }
 
     /**
@@ -451,29 +489,40 @@ public final class DevicePolicyControllerImpl implements DevicePolicyController
      */
     private ListenableFuture<@LockTaskType Integer> getCurrentEnforcedLockTaskType() {
         synchronized (this) {
+            final ListenableFuture<@LockTaskType Integer> lockTaskTypeFuture =
+                    GlobalParametersClient.getInstance().getLockTaskType();
+
             return Futures.transformAsync(
-                    mCurrentEnforcedLockTaskTypeFuture,
-                    type -> type == LockTaskType.UNDEFINED
-                            ? Futures.transform(enforceCurrentPoliciesAndResolveLockTaskType(
-                                    /* failure= */ false),
-                                    mode -> {
-                                        startLockTaskModeIfNeeded(mode);
-                                        return mode;
-                                    }, mBgExecutor)
-                            : Futures.immediateFuture(type),
+                    lockTaskTypeFuture,
+                    type -> {
+                        LogUtil.i(TAG, "Current LockTaskType: " + type);
+                        return type == LockTaskType.UNDEFINED
+                                ? Futures.transform(
+                                        enforceCurrentPoliciesAndResolveLockTaskType(
+                                                /* failure= */ false),
+                                        mode -> {
+                                            startLockTaskModeIfNeeded(mode);
+                                            return mode;
+                                        },
+                                        mBgExecutor)
+                                : Futures.immediateFuture(type);
+                    },
                     mBgExecutor);
         }
     }
 
     @Override
     public ListenableFuture<Void> onUserUnlocked() {
-        return Futures.transformAsync(mProvisionStateController.onUserUnlocked(),
-                unused -> Futures.transform(getCurrentEnforcedLockTaskType(),
-                        mode -> {
-                            startLockTaskModeIfNeeded(mode);
-                            return null;
-                        },
-                        mBgExecutor),
+        return Futures.transformAsync(
+                mProvisionStateController.onUserUnlocked(),
+                unused ->
+                        Futures.transform(
+                                getCurrentEnforcedLockTaskType(),
+                                mode -> {
+                                    startLockTaskModeIfNeeded(mode);
+                                    return null;
+                                },
+                                mBgExecutor),
                 mBgExecutor);
     }
 
@@ -485,9 +534,13 @@ public final class DevicePolicyControllerImpl implements DevicePolicyController
     @Override
     public ListenableFuture<Void> onAppCrashed(boolean isKiosk) {
         final String crashedApp = isKiosk ? "kiosk" : "dlc";
-        LogUtil.i(TAG, "Controller notified about " + crashedApp
-                + " having crashed while in lock task mode");
-        return Futures.transform(getCurrentEnforcedLockTaskType(),
+        LogUtil.i(
+                TAG,
+                "Controller notified about "
+                        + crashedApp
+                        + " having crashed while in lock task mode");
+        return Futures.transform(
+                getCurrentEnforcedLockTaskType(),
                 mode -> {
                     startLockTaskModeIfNeeded(mode);
                     return null;
@@ -500,28 +553,35 @@ public final class DevicePolicyControllerImpl implements DevicePolicyController
             return;
         }
         WorkManager workManager = WorkManager.getInstance(mContext);
-        OneTimeWorkRequest startLockTask = new OneTimeWorkRequest.Builder(
-                StartLockTaskModeWorker.class)
-                .setExpedited(OutOfQuotaPolicy.RUN_AS_NON_EXPEDITED_WORK_REQUEST)
-                .build();
+        OneTimeWorkRequest startLockTask =
+                new OneTimeWorkRequest.Builder(StartLockTaskModeWorker.class)
+                        .setExpedited(OutOfQuotaPolicy.RUN_AS_NON_EXPEDITED_WORK_REQUEST)
+                        .build();
         final ListenableFuture<Operation.State.SUCCESS> enqueueResult =
-                workManager.enqueueUniqueWork(START_LOCK_TASK_MODE_WORK_NAME,
-                        ExistingWorkPolicy.REPLACE, startLockTask).getResult();
-        Futures.addCallback(enqueueResult, new FutureCallback<>() {
-            @Override
-            public void onSuccess(Operation.State.SUCCESS result) {
-                // Enqueued
-            }
+                workManager
+                        .enqueueUniqueWork(
+                                START_LOCK_TASK_MODE_WORK_NAME,
+                                ExistingWorkPolicy.REPLACE,
+                                startLockTask)
+                        .getResult();
+        Futures.addCallback(
+                enqueueResult,
+                new FutureCallback<>() {
+                    @Override
+                    public void onSuccess(Operation.State.SUCCESS result) {
+                        // Enqueued
+                    }
 
-            @Override
-            public void onFailure(Throwable t) {
-                LogUtil.e(TAG, "Failed to enqueue 'start lock task mode' work", t);
-                if (t instanceof SQLiteException) {
-                    wipeDevice();
-                } else {
-                    LogUtil.e(TAG, "Not wiping device (non SQL exception)");
-                }
-            }
-        }, mBgExecutor);
+                    @Override
+                    public void onFailure(Throwable t) {
+                        LogUtil.e(TAG, "Failed to enqueue 'start lock task mode' work", t);
+                        if (t instanceof SQLiteException) {
+                            wipeDevice();
+                        } else {
+                            LogUtil.e(TAG, "Not wiping device (non SQL exception)");
+                        }
+                    }
+                },
+                mBgExecutor);
     }
 }
diff --git a/DeviceLockController/src/com/android/devicelockcontroller/policy/FinalizationControllerImpl.java b/DeviceLockController/src/com/android/devicelockcontroller/policy/FinalizationControllerImpl.java
index 935f686e..4fc9f912 100644
--- a/DeviceLockController/src/com/android/devicelockcontroller/policy/FinalizationControllerImpl.java
+++ b/DeviceLockController/src/com/android/devicelockcontroller/policy/FinalizationControllerImpl.java
@@ -271,12 +271,12 @@ public final class FinalizationControllerImpl implements FinalizationController
     /**
      * Disables the entire device lock controller application.
      *
-     * This will remove any work, alarms, receivers, etc., and this application should never run
+     * <p>This will remove any work, alarms, receivers, etc., and this application should never run
      * on the device again after this point.
      *
-     * This method returns a future but it is a bit of an odd case as the application itself
-     * may end up disabled before/after the future is handled depending on when package manager
-     * enforces the application is disabled.
+     * <p>This method returns a future but it is a bit of an odd case as the application itself may
+     * end up disabled before/after the future is handled depending on when package manager enforces
+     * the application is disabled.
      *
      * @return future for when this is done
      */
@@ -286,25 +286,30 @@ public final class FinalizationControllerImpl implements FinalizationController
         AlarmManager alarmManager = mContext.getSystemService(AlarmManager.class);
         alarmManager.cancelAll();
         // This kills and disables the app
-        ListenableFuture<Void> disableApplicationFuture = CallbackToFutureAdapter.getFuture(
-                completer -> {
-                        mSystemDeviceLockManager.setDeviceFinalized(true, mBgExecutor,
-                                new OutcomeReceiver<>() {
-                                    @Override
-                                    public void onResult(Void result) {
-                                        completer.set(null);
-                                    }
+        ListenableFuture<Void> disableApplicationFuture =
+                CallbackToFutureAdapter.getFuture(
+                        completer -> {
+                            mSystemDeviceLockManager.setDeviceFinalized(
+                                    true,
+                                    mBgExecutor,
+                                    new OutcomeReceiver<>() {
+                                        @Override
+                                        public void onResult(Void result) {
+                                            completer.set(null);
+                                        }
 
-                                    @Override
-                                    public void onError(@NonNull Exception error) {
-                                        LogUtil.e(TAG, "Failed to set device finalized in"
-                                                + "system service.", error);
-                                        completer.setException(error);
-                                    }
-                                });
-                    return "Disable application future";
-                }
-        );
+                                        @Override
+                                        public void onError(@NonNull Exception error) {
+                                            LogUtil.e(
+                                                    TAG,
+                                                    "Failed to set device finalized in"
+                                                            + "system service.",
+                                                    error);
+                                            completer.setException(error);
+                                        }
+                                    });
+                            return "Disable application future";
+                        });
         return disableApplicationFuture;
     }
 }
diff --git a/DeviceLockController/src/com/android/devicelockcontroller/policy/ProvisionStateControllerImpl.java b/DeviceLockController/src/com/android/devicelockcontroller/policy/ProvisionStateControllerImpl.java
index c074dc99..02ea924e 100644
--- a/DeviceLockController/src/com/android/devicelockcontroller/policy/ProvisionStateControllerImpl.java
+++ b/DeviceLockController/src/com/android/devicelockcontroller/policy/ProvisionStateControllerImpl.java
@@ -16,6 +16,7 @@
 
 package com.android.devicelockcontroller.policy;
 
+import static com.android.devicelockcontroller.DevicelockStatsLog.DEVICE_LOCK_PROVISION_STATE_EVENT__EVENT__EVENT_SUCCESSFUL_PROVISIONING;
 import static com.android.devicelockcontroller.policy.ProvisionStateController.ProvisionEvent.PROVISION_FAILURE;
 import static com.android.devicelockcontroller.policy.ProvisionStateController.ProvisionEvent.PROVISION_KIOSK;
 import static com.android.devicelockcontroller.policy.ProvisionStateController.ProvisionEvent.PROVISION_PAUSE;
@@ -70,6 +71,9 @@ import java.util.concurrent.Executors;
 public final class ProvisionStateControllerImpl implements ProvisionStateController {
 
     public static final String TAG = "ProvisionStateControllerImpl";
+    // Checkstyle complains line too long when using original constant.
+    private static final int SUCCESSFUL_PROVISIONING =
+            DEVICE_LOCK_PROVISION_STATE_EVENT__EVENT__EVENT_SUCCESSFUL_PROVISIONING;
     private final Context mContext;
     private final DevicePolicyController mPolicyController;
     private final DeviceStateController mDeviceStateController;
@@ -137,18 +141,20 @@ public final class ProvisionStateControllerImpl implements ProvisionStateControl
                                 // We treat when the event is PROVISION_READY as the start of the
                                 // provisioning time.
                                 if (PROVISION_READY == event) {
-                                    UserParameters.setProvisioningStartTimeMillis(mContext,
-                                            SystemClock.elapsedRealtime());
+                                    UserParameters.setProvisioningStartTimeMillis(
+                                            mContext, SystemClock.elapsedRealtime());
                                     ReviewDeviceProvisionStateWorker.scheduleDailyReview(
                                             WorkManager.getInstance(mContext));
                                 }
 
                                 if (PROVISION_SUCCESS == event) {
                                     ((StatsLoggerProvider) mContext.getApplicationContext())
-                                            .getStatsLogger().logSuccessfulProvisioning();
+                                            .getStatsLogger()
+                                            .logProvisionStateEvent(SUCCESSFUL_PROVISIONING);
                                 }
                                 return newState;
-                            }, mBgExecutor);
+                            },
+                            mBgExecutor);
             // To prevent exception propagate to future state transitions, catch any exceptions
             // that might happen during the execution and fallback to previous state if exception
             // happens.
diff --git a/DeviceLockController/src/com/android/devicelockcontroller/provision/grpc/DeviceCheckInClient.java b/DeviceLockController/src/com/android/devicelockcontroller/provision/grpc/DeviceCheckInClient.java
index e59f7f41..09951f29 100644
--- a/DeviceLockController/src/com/android/devicelockcontroller/provision/grpc/DeviceCheckInClient.java
+++ b/DeviceLockController/src/com/android/devicelockcontroller/provision/grpc/DeviceCheckInClient.java
@@ -121,7 +121,7 @@ public abstract class DeviceCheckInClient {
                                 (DeviceCheckInClient) clazz.getDeclaredConstructor().newInstance();
                     } else {
                         sClient = new DeviceCheckInClientImpl(clientInterceptor,
-                                context.getSystemService(ConnectivityManager.class));
+                                context.getSystemService(ConnectivityManager.class), context);
                     }
                 }
             } catch (Exception e) {
diff --git a/DeviceLockController/src/com/android/devicelockcontroller/provision/grpc/impl/DeviceCheckInClientImpl.java b/DeviceLockController/src/com/android/devicelockcontroller/provision/grpc/impl/DeviceCheckInClientImpl.java
index b58f2e98..11a4c830 100644
--- a/DeviceLockController/src/com/android/devicelockcontroller/provision/grpc/impl/DeviceCheckInClientImpl.java
+++ b/DeviceLockController/src/com/android/devicelockcontroller/provision/grpc/impl/DeviceCheckInClientImpl.java
@@ -16,6 +16,7 @@
 
 package com.android.devicelockcontroller.provision.grpc.impl;
 
+import static com.android.devicelockcontroller.DevicelockStatsLog.DEVICE_LOCK_PROVISION_STATE_EVENT__EVENT__EVENT_UNSUCCESSFUL_CHECKIN_REQUEST;
 import static com.android.devicelockcontroller.proto.ClientProvisionFailureReason.PROVISION_FAILURE_REASON_COUNTRY_INFO_UNAVAILABLE;
 import static com.android.devicelockcontroller.proto.ClientProvisionFailureReason.PROVISION_FAILURE_REASON_DEADLINE_PASSED;
 import static com.android.devicelockcontroller.proto.ClientProvisionFailureReason.PROVISION_FAILURE_REASON_NOT_IN_ELIGIBLE_COUNTRY;
@@ -24,6 +25,7 @@ import static com.android.devicelockcontroller.proto.ClientProvisionFailureReaso
 import static com.android.devicelockcontroller.proto.ClientProvisionFailureReason.PROVISION_FAILURE_REASON_POLICY_ENFORCEMENT_FAILED;
 import static com.android.devicelockcontroller.proto.ClientProvisionFailureReason.PROVISION_FAILURE_REASON_UNSPECIFIED;
 
+import android.content.Context;
 import android.net.ConnectivityManager;
 import android.net.ConnectivityManager.NetworkCallback;
 import android.net.Network;
@@ -61,6 +63,8 @@ import com.android.devicelockcontroller.provision.grpc.IsDeviceInApprovedCountry
 import com.android.devicelockcontroller.provision.grpc.PauseDeviceProvisioningGrpcResponse;
 import com.android.devicelockcontroller.provision.grpc.ReportDeviceProvisionStateGrpcResponse;
 import com.android.devicelockcontroller.provision.grpc.UpdateFcmTokenGrpcResponse;
+import com.android.devicelockcontroller.stats.StatsLogger;
+import com.android.devicelockcontroller.stats.StatsLoggerProvider;
 import com.android.devicelockcontroller.util.LogUtil;
 import com.android.devicelockcontroller.util.ThreadAsserts;
 
@@ -140,24 +144,34 @@ public final class DeviceCheckInClientImpl extends DeviceCheckInClient {
     @GuardedBy("this")
     private DeviceLockCheckinServiceBlockingStub mNonVpnBlockingStub;
 
-    public DeviceCheckInClientImpl(ClientInterceptor clientInterceptor,
-            ConnectivityManager connectivityManager) {
-        this(clientInterceptor, connectivityManager,
-                (host, port, socketFactory) -> OkHttpChannelBuilder
-                        .forAddress(host, port)
-                        .socketFactory(socketFactory)
-                        .build());
+    private final StatsLogger mStatsLogger;
+
+    public DeviceCheckInClientImpl(
+            ClientInterceptor clientInterceptor,
+            ConnectivityManager connectivityManager,
+            Context context) {
+        this(
+                clientInterceptor,
+                connectivityManager,
+                (host, port, socketFactory) ->
+                        OkHttpChannelBuilder.forAddress(host, port)
+                                .socketFactory(socketFactory)
+                                .build(),
+                context);
     }
 
-    DeviceCheckInClientImpl(ClientInterceptor clientInterceptor,
+    DeviceCheckInClientImpl(
+            ClientInterceptor clientInterceptor,
             ConnectivityManager connectivityManager,
-            ChannelFactory channelFactory) {
+            ChannelFactory channelFactory,
+            Context context) {
         mClientInterceptor = clientInterceptor;
         mConnectivityManager = connectivityManager;
         mChannelFactory = channelFactory;
         mDefaultChannel = mChannelFactory.buildChannel(sHostName, sPortNumber);
-        mDefaultBlockingStub = DeviceLockCheckinServiceGrpc.newBlockingStub(mDefaultChannel)
-                .withInterceptors(clientInterceptor);
+        mDefaultBlockingStub =
+                DeviceLockCheckinServiceGrpc.newBlockingStub(mDefaultChannel)
+                        .withInterceptors(clientInterceptor);
         HandlerThread handlerThread = new HandlerThread("NetworkCallbackThread");
         handlerThread.start();
         Handler handler = new Handler(handlerThread.getLooper());
@@ -174,6 +188,9 @@ public final class DeviceCheckInClientImpl extends DeviceCheckInClient {
                         .build(),
                 mNetworkCallback,
                 handler);
+
+        StatsLoggerProvider loggerProvider = (StatsLoggerProvider) context.getApplicationContext();
+        mStatsLogger = loggerProvider.getStatsLogger();
     }
 
     @Override
@@ -230,6 +247,8 @@ public final class DeviceCheckInClientImpl extends DeviceCheckInClient {
                                             deviceLockApexVersion,
                                             fcmRegistrationToken)));
         } catch (StatusRuntimeException e) {
+            mStatsLogger.logProvisionStateEvent(
+                    DEVICE_LOCK_PROVISION_STATE_EVENT__EVENT__EVENT_UNSUCCESSFUL_CHECKIN_REQUEST);
             return new GetDeviceCheckInStatusGrpcResponseWrapper(e.getStatus());
         }
     }
diff --git a/DeviceLockController/src/com/android/devicelockcontroller/provision/worker/DeviceCheckInWorker.java b/DeviceLockController/src/com/android/devicelockcontroller/provision/worker/DeviceCheckInWorker.java
index 1a937dc3..6b8d09f2 100644
--- a/DeviceLockController/src/com/android/devicelockcontroller/provision/worker/DeviceCheckInWorker.java
+++ b/DeviceLockController/src/com/android/devicelockcontroller/provision/worker/DeviceCheckInWorker.java
@@ -118,9 +118,6 @@ public final class DeviceCheckInWorker extends AbstractCheckInWorker {
                             boolean isResponseHandlingSuccessful = mCheckInHelper
                                     .handleGetDeviceCheckInStatusResponse(response, scheduler,
                                             fcmToken);
-                            if (isResponseHandlingSuccessful) {
-                                mStatsLogger.logSuccessfulCheckIn();
-                            }
                             return isResponseHandlingSuccessful ? Result.success() : Result.retry();
                         }
 
diff --git a/DeviceLockController/src/com/android/devicelockcontroller/receivers/ResetDeviceReceiver.java b/DeviceLockController/src/com/android/devicelockcontroller/receivers/ResetDeviceReceiver.java
index 177a9a9f..4dd1a9da 100644
--- a/DeviceLockController/src/com/android/devicelockcontroller/receivers/ResetDeviceReceiver.java
+++ b/DeviceLockController/src/com/android/devicelockcontroller/receivers/ResetDeviceReceiver.java
@@ -16,6 +16,8 @@
 
 package com.android.devicelockcontroller.receivers;
 
+import static com.android.devicelockcontroller.DevicelockStatsLog.DEVICE_LOCK_PROVISION_STATE_EVENT__EVENT__EVENT_DEVICE_RESET;
+
 import android.content.BroadcastReceiver;
 import android.content.Context;
 import android.content.Intent;
@@ -55,15 +57,19 @@ public final class ResetDeviceReceiver extends BroadcastReceiver {
         if (!ResetDeviceReceiver.class.getName().equals(intent.getComponent().getClassName())) {
             throw new IllegalArgumentException("Can not handle implicit intent!");
         }
-        Futures.addCallback(SetupParametersClient.getInstance().isProvisionMandatory(),
-                new FutureCallback<Boolean>() {
+        Futures.addCallback(
+                SetupParametersClient.getInstance().isProvisionMandatory(),
+                new FutureCallback() {
                     @Override
-                    public void onSuccess(Boolean isProvisionMandatory) {
-                        StatsLogger logger = ((StatsLoggerProvider) context.getApplicationContext())
-                                .getStatsLogger();
-                        logger.logDeviceReset(isProvisionMandatory);
+                    public void onSuccess(Object unused) {
+                        StatsLogger logger =
+                                ((StatsLoggerProvider) context.getApplicationContext())
+                                        .getStatsLogger();
+                        logger.logProvisionStateEvent(
+                                DEVICE_LOCK_PROVISION_STATE_EVENT__EVENT__EVENT_DEVICE_RESET);
                         ((PolicyObjectsProvider) context.getApplicationContext())
-                                .getPolicyController().wipeDevice();
+                                .getPolicyController()
+                                .wipeDevice();
                     }
 
                     @Override
@@ -72,8 +78,10 @@ public final class ResetDeviceReceiver extends BroadcastReceiver {
                         // we just log the error here and proceed.
                         LogUtil.e(TAG, "Error querying isProvisionMandatory", t);
                         ((PolicyObjectsProvider) context.getApplicationContext())
-                                .getPolicyController().wipeDevice();
+                                .getPolicyController()
+                                .wipeDevice();
                     }
-                }, mExecutor);
+                },
+                mExecutor);
     }
 }
diff --git a/DeviceLockController/src/com/android/devicelockcontroller/stats/StatsLogger.java b/DeviceLockController/src/com/android/devicelockcontroller/stats/StatsLogger.java
index 2a438dc9..7b147a1d 100644
--- a/DeviceLockController/src/com/android/devicelockcontroller/stats/StatsLogger.java
+++ b/DeviceLockController/src/com/android/devicelockcontroller/stats/StatsLogger.java
@@ -73,17 +73,6 @@ public interface StatsLogger {
      */
     void logDeviceReset(boolean isProvisioningMandatory);
 
-    /**
-     * Logs the analytics event of successfully handling a check in response received from the
-     * server.
-     */
-    void logSuccessfulCheckIn();
-
-    /**
-     * Logs the analytics event of successfully completing the provisioning.
-     */
-    void logSuccessfulProvisioning();
-
     /**
      * Logs the analytics event of retrying a check in request.
      *
@@ -170,12 +159,22 @@ public interface StatsLogger {
     }
 
     /**
-     * Logs the analytics event of successfully locking the device.
+     * Logs the analytics event of failing to install the kiosk app.
+     */
+    void logKioskAppInstallationFailed();
+
+    /**
+     * Logs the analytics event of a device state event occurring on the device.
+     */
+    void logDeviceStateEvent(int event);
+
+    /**
+     * Logs the analytics event of a provision state event occurring on the device.
      */
-    void logSuccessfulLockingDevice();
+    void logProvisionStateEvent(int event);
 
     /**
-     * Logs the analytics event of successfully unlocking the device.
+     * Logs the analytics event of a device receiving an FCM message from the server.
      */
-    void logSuccessfulUnlockingDevice();
+    void logFcmMessageReceived();
 }
diff --git a/DeviceLockController/src/com/android/devicelockcontroller/stats/StatsLoggerImpl.java b/DeviceLockController/src/com/android/devicelockcontroller/stats/StatsLoggerImpl.java
index d583d539..8d3bec14 100644
--- a/DeviceLockController/src/com/android/devicelockcontroller/stats/StatsLoggerImpl.java
+++ b/DeviceLockController/src/com/android/devicelockcontroller/stats/StatsLoggerImpl.java
@@ -25,10 +25,14 @@ import static com.android.devicelockcontroller.DevicelockStatsLog.DEVICE_LOCK_CH
 import static com.android.devicelockcontroller.DevicelockStatsLog.DEVICE_LOCK_CHECK_IN_REQUEST_REPORTED__TYPE__PAUSE_DEVICE_PROVISIONING;
 import static com.android.devicelockcontroller.DevicelockStatsLog.DEVICE_LOCK_CHECK_IN_REQUEST_REPORTED__TYPE__REPORT_DEVICE_PROVISION_STATE;
 import static com.android.devicelockcontroller.DevicelockStatsLog.DEVICE_LOCK_CHECK_IN_RETRY_REPORTED;
+import static com.android.devicelockcontroller.DevicelockStatsLog.DEVICE_LOCK_DEVICE_STATE_EVENT;
+import static com.android.devicelockcontroller.DevicelockStatsLog.DEVICE_LOCK_FCM_MESSAGE_RECEIVED;
+import static com.android.devicelockcontroller.DevicelockStatsLog.DEVICE_LOCK_KIOSK_APP_INSTALLATION_FAILED;
 import static com.android.devicelockcontroller.DevicelockStatsLog.DEVICE_LOCK_KIOSK_APP_REQUEST_REPORTED;
 import static com.android.devicelockcontroller.DevicelockStatsLog.DEVICE_LOCK_LOCK_UNLOCK_DEVICE_FAILURE_REPORTED;
 import static com.android.devicelockcontroller.DevicelockStatsLog.DEVICE_LOCK_PROVISIONING_COMPLETE_REPORTED;
 import static com.android.devicelockcontroller.DevicelockStatsLog.DEVICE_LOCK_PROVISION_FAILURE_REPORTED;
+import static com.android.devicelockcontroller.DevicelockStatsLog.DEVICE_LOCK_PROVISION_STATE_EVENT;
 import static com.android.devicelockcontroller.DevicelockStatsLog.LOCK_UNLOCK_DEVICE_FAILURE_REPORTED__STATE_POST_COMMAND__CLEARED;
 import static com.android.devicelockcontroller.DevicelockStatsLog.LOCK_UNLOCK_DEVICE_FAILURE_REPORTED__STATE_POST_COMMAND__LOCKED;
 import static com.android.devicelockcontroller.DevicelockStatsLog.LOCK_UNLOCK_DEVICE_FAILURE_REPORTED__STATE_POST_COMMAND__UNDEFINED;
@@ -50,12 +54,17 @@ import static com.android.devicelockcontroller.stats.StatsLogger.ProvisionFailur
 import static com.android.devicelockcontroller.stats.StatsLogger.ProvisionFailureReasonStats.POLICY_ENFORCEMENT_FAILED;
 import static com.android.devicelockcontroller.stats.StatsLogger.ProvisionFailureReasonStats.UNKNOWN;
 
+import android.content.Context;
+import android.content.pm.PackageManager;
+
 import com.android.devicelockcontroller.DevicelockStatsLog;
+import com.android.devicelockcontroller.util.LogUtil;
 import com.android.modules.expresslog.Counter;
 
 import java.util.concurrent.TimeUnit;
 
 public final class StatsLoggerImpl implements StatsLogger{
+
     // The Telemetry Express metric ID for the counter of device reset due to failure of mandatory
     // provisioning. As defined in
     // platform/frameworks/proto_logging/stats/express/catalog/device_lock.cfg
@@ -83,7 +92,11 @@ public final class StatsLoggerImpl implements StatsLogger{
     static final String TEX_ID_SUCCESSFUL_UNLOCKING_COUNT =
             "device_lock.value_successful_unlocking_count";
     private static final String TAG = "StatsLogger";
+    private final Context mContext;
 
+    public StatsLoggerImpl(Context context) {
+        mContext = context;
+    }
     @Override
     public void logGetDeviceCheckInStatus() {
         DevicelockStatsLog.write(DevicelockStatsLog.DEVICE_LOCK_CHECK_IN_REQUEST_REPORTED,
@@ -128,16 +141,6 @@ public final class StatsLoggerImpl implements StatsLogger{
         }
     }
 
-    @Override
-    public void logSuccessfulCheckIn() {
-        Counter.logIncrement(TEX_ID_SUCCESSFUL_CHECK_IN_RESPONSE_COUNT);
-    }
-
-    @Override
-    public void logSuccessfulProvisioning() {
-        Counter.logIncrement(TEX_ID_SUCCESSFUL_PROVISIONING_COUNT);
-    }
-
     @Override
     public void logCheckInRetry(@CheckInRetryReason int reason) {
         int checkInRetryReason;
@@ -209,12 +212,37 @@ public final class StatsLoggerImpl implements StatsLogger{
     }
 
     @Override
-    public void logSuccessfulLockingDevice() {
-        Counter.logIncrement(TEX_ID_SUCCESSFUL_LOCKING_COUNT);
+    public void logKioskAppInstallationFailed() {
+        DevicelockStatsLog.write(DEVICE_LOCK_KIOSK_APP_INSTALLATION_FAILED,
+                getDeviceLockApexVersion());
+    }
+
+    @Override
+    public void logProvisionStateEvent(int event) {
+        DevicelockStatsLog.write(
+                DEVICE_LOCK_PROVISION_STATE_EVENT, event, getDeviceLockApexVersion());
     }
 
     @Override
-    public void logSuccessfulUnlockingDevice() {
-        Counter.logIncrement(TEX_ID_SUCCESSFUL_UNLOCKING_COUNT);
+    public void logDeviceStateEvent(int event) {
+        DevicelockStatsLog.write(
+                DEVICE_LOCK_DEVICE_STATE_EVENT, event, getDeviceLockApexVersion());
+    }
+
+    @Override
+    public void logFcmMessageReceived() {
+        DevicelockStatsLog.write(DEVICE_LOCK_FCM_MESSAGE_RECEIVED, getDeviceLockApexVersion());
+    }
+
+    private long getDeviceLockApexVersion() {
+        try {
+            return mContext
+                    .getPackageManager()
+                    .getPackageInfo(mContext.getPackageName(), PackageManager.MATCH_APEX)
+                    .getLongVersionCode();
+        } catch (PackageManager.NameNotFoundException e) {
+            LogUtil.e(TAG, "Failed to get device lock apex version", e);
+        }
+        return 0;
     }
 }
diff --git a/DeviceLockController/src/com/android/devicelockcontroller/storage/GlobalParameters.java b/DeviceLockController/src/com/android/devicelockcontroller/storage/GlobalParameters.java
index 58c3c7a5..73a2ba3a 100644
--- a/DeviceLockController/src/com/android/devicelockcontroller/storage/GlobalParameters.java
+++ b/DeviceLockController/src/com/android/devicelockcontroller/storage/GlobalParameters.java
@@ -23,6 +23,7 @@ import android.os.Build;
 import androidx.annotation.Nullable;
 
 import com.android.devicelockcontroller.common.DeviceLockConstants.DeviceProvisionState;
+import com.android.devicelockcontroller.policy.DevicePolicyController.LockTaskType;
 import com.android.devicelockcontroller.policy.DeviceStateController.DeviceState;
 import com.android.devicelockcontroller.policy.FinalizationControllerImpl.FinalizationState;
 import com.android.devicelockcontroller.util.LogUtil;
@@ -31,10 +32,10 @@ import java.util.Locale;
 
 /**
  * Stores global parameters.
- * <p>
- * Note that, these parameter values are common across all users which means any users can read or
- * write them. Due to this reason, unlike {@link UserParameters}, they must be accessed all the time
- * via the {@link GlobalParametersClient}.
+ *
+ * <p>Note that, these parameter values are common across all users which means any users can read
+ * or write them. Due to this reason, unlike {@link UserParameters}, they must be accessed all the
+ * time via the {@link GlobalParametersClient}.
  */
 final class GlobalParameters {
     private static final String FILENAME = "global-params";
@@ -44,11 +45,10 @@ final class GlobalParameters {
     private static final String TAG = "GlobalParameters";
     private static final String KEY_DEVICE_STATE = "device_state";
     private static final String KEY_FINALIZATION_STATE = "finalization_state";
+    private static final String KEY_LOCK_TASK_TYPE = "lock-task-type";
     public static final String KEY_IS_PROVISION_READY = "key-is-provision-ready";
 
-
-    private GlobalParameters() {
-    }
+    private GlobalParameters() {}
 
     private static SharedPreferences getSharedPreferences(Context context) {
         final Context deviceContext = context.createDeviceProtectedStorageContext();
@@ -61,8 +61,10 @@ final class GlobalParameters {
     }
 
     static void setProvisionReady(Context context, boolean isProvisionReady) {
-        getSharedPreferences(context).edit().putBoolean(KEY_IS_PROVISION_READY,
-                isProvisionReady).apply();
+        getSharedPreferences(context)
+                .edit()
+                .putBoolean(KEY_IS_PROVISION_READY, isProvisionReady)
+                .apply();
     }
 
     /**
@@ -70,7 +72,7 @@ final class GlobalParameters {
      *
      * @param context Context used to get the shared preferences.
      * @return The registered device unique identifier; null if device has never checked in with
-     * backed server.
+     *     backed server.
      */
     @Nullable
     static String getRegisteredDeviceId(Context context) {
@@ -81,7 +83,7 @@ final class GlobalParameters {
     /**
      * Set the unique identifier that is registered to DeviceLock backend server.
      *
-     * @param context            Context used to get the shared preferences.
+     * @param context Context used to get the shared preferences.
      * @param registeredDeviceId The registered device unique identifier.
      */
     static void setRegisteredDeviceId(Context context, String registeredDeviceId) {
@@ -101,33 +103,25 @@ final class GlobalParameters {
         return getSharedPreferences(context).getBoolean(KEY_FORCED_PROVISION, false);
     }
 
-    /**
-     * Gets the current device state.
-     */
+    /** Gets the current device state. */
     @DeviceState
     static int getDeviceState(Context context) {
         return getSharedPreferences(context).getInt(KEY_DEVICE_STATE, DeviceState.UNDEFINED);
     }
 
-    /**
-     * Sets the current device state.
-     */
+    /** Sets the current device state. */
     static void setDeviceState(Context context, @DeviceState int state) {
         getSharedPreferences(context).edit().putInt(KEY_DEVICE_STATE, state).apply();
     }
 
-    /**
-     * Gets the current {@link FinalizationState}.
-     */
+    /** Gets the current {@link FinalizationState}. */
     @FinalizationState
     static int getFinalizationState(Context context) {
-        return getSharedPreferences(context).getInt(
-                KEY_FINALIZATION_STATE, FinalizationState.UNFINALIZED);
+        return getSharedPreferences(context)
+                .getInt(KEY_FINALIZATION_STATE, FinalizationState.UNFINALIZED);
     }
 
-    /**
-     * Sets the current {@link FinalizationState}.
-     */
+    /** Sets the current {@link FinalizationState}. */
     static void setFinalizationState(Context context, @FinalizationState int state) {
         getSharedPreferences(context).edit().putInt(KEY_FINALIZATION_STATE, state).apply();
     }
@@ -135,30 +129,50 @@ final class GlobalParameters {
     /**
      * Set provision is forced
      *
-     * @param context  Context used to get the shared preferences.
+     * @param context Context used to get the shared preferences.
      * @param isForced The new value of the forced provision flag.
      */
     static void setProvisionForced(Context context, boolean isForced) {
-        getSharedPreferences(context)
-                .edit()
-                .putBoolean(KEY_FORCED_PROVISION, isForced)
-                .apply();
+        getSharedPreferences(context).edit().putBoolean(KEY_FORCED_PROVISION, isForced).apply();
     }
 
     @DeviceProvisionState
     static int getLastReceivedProvisionState(Context context) {
-        return getSharedPreferences(context).getInt(KEY_LAST_RECEIVED_PROVISION_STATE,
-                DeviceProvisionState.PROVISION_STATE_UNSPECIFIED);
+        return getSharedPreferences(context)
+                .getInt(
+                        KEY_LAST_RECEIVED_PROVISION_STATE,
+                        DeviceProvisionState.PROVISION_STATE_UNSPECIFIED);
     }
 
-    static void setLastReceivedProvisionState(Context context,
-            @DeviceProvisionState int provisionState) {
+    static void setLastReceivedProvisionState(
+            Context context, @DeviceProvisionState int provisionState) {
         getSharedPreferences(context)
                 .edit()
                 .putInt(KEY_LAST_RECEIVED_PROVISION_STATE, provisionState)
                 .apply();
     }
 
+    /**
+     * Get the current lock task type
+     *
+     * @param context Context used to get the shared preferences.
+     * @return The current lock task type
+     */
+    @LockTaskType
+    static int getLockTaskType(Context context) {
+        return getSharedPreferences(context).getInt(KEY_LOCK_TASK_TYPE, LockTaskType.UNDEFINED);
+    }
+
+    /**
+     * Set the current lock task type
+     *
+     * @param context Context used get the shared preferences.
+     * @param lockTaskType The new value of the lock task type
+     */
+    static void setLockTaskType(Context context, @LockTaskType Integer lockTaskType) {
+        getSharedPreferences(context).edit().putInt(KEY_LOCK_TASK_TYPE, lockTaskType).apply();
+    }
+
     static void clear(Context context) {
         if (!Build.isDebuggable()) {
             throw new SecurityException("Clear is not allowed in non-debuggable build!");
@@ -167,18 +181,28 @@ final class GlobalParameters {
     }
 
     static void dump(Context context) {
-        LogUtil.d(TAG, String.format(Locale.US,
-                "Dumping GlobalParameters ...\n"
-                        + "%s: %s\n"    // registered_device_id:
-                        + "%s: %s\n"    // forced_provision:
-                        + "%s: %s\n"    // last-received-provision-state:
-                        + "%s: %s\n"    // device_state:
-                        + "%s: %s\n",    // is-provision-ready:
-                KEY_REGISTERED_DEVICE_ID, getRegisteredDeviceId(context),
-                KEY_FORCED_PROVISION, isProvisionForced(context),
-                KEY_LAST_RECEIVED_PROVISION_STATE, getLastReceivedProvisionState(context),
-                KEY_DEVICE_STATE, getDeviceState(context),
-                KEY_IS_PROVISION_READY, isProvisionReady(context)
-        ));
+        LogUtil.d(
+                TAG,
+                String.format(
+                        Locale.US,
+                        "Dumping GlobalParameters ...\n"
+                                + "%s: %s\n" // registered_device_id:
+                                + "%s: %s\n" // forced_provision:
+                                + "%s: %s\n" // last-received-provision-state:
+                                + "%s: %s\n" // device_state:
+                                + "%s: %s\n" // is-provision-ready:
+                                + "%s: %s\n", // lock-task-type:
+                        KEY_REGISTERED_DEVICE_ID,
+                        getRegisteredDeviceId(context),
+                        KEY_FORCED_PROVISION,
+                        isProvisionForced(context),
+                        KEY_LAST_RECEIVED_PROVISION_STATE,
+                        getLastReceivedProvisionState(context),
+                        KEY_DEVICE_STATE,
+                        getDeviceState(context),
+                        KEY_IS_PROVISION_READY,
+                        isProvisionReady(context),
+                        KEY_LOCK_TASK_TYPE,
+                        getLockTaskType(context)));
     }
 }
diff --git a/DeviceLockController/src/com/android/devicelockcontroller/storage/GlobalParametersClient.java b/DeviceLockController/src/com/android/devicelockcontroller/storage/GlobalParametersClient.java
index ceb0115b..6dfb72b1 100644
--- a/DeviceLockController/src/com/android/devicelockcontroller/storage/GlobalParametersClient.java
+++ b/DeviceLockController/src/com/android/devicelockcontroller/storage/GlobalParametersClient.java
@@ -29,6 +29,7 @@ import androidx.annotation.VisibleForTesting;
 
 import com.android.devicelockcontroller.DeviceLockControllerApplication;
 import com.android.devicelockcontroller.common.DeviceLockConstants.DeviceProvisionState;
+import com.android.devicelockcontroller.policy.DevicePolicyController.LockTaskType;
 import com.android.devicelockcontroller.policy.DeviceStateController.DeviceState;
 import com.android.devicelockcontroller.policy.FinalizationControllerImpl.FinalizationState;
 
@@ -38,9 +39,7 @@ import com.google.common.util.concurrent.MoreExecutors;
 
 import java.util.concurrent.Executors;
 
-/**
- * A class used to access Global Parameters from any user.
- */
+/** A class used to access Global Parameters from any user. */
 public final class GlobalParametersClient extends DlcClient {
 
     private static final Object sInstanceLock = new Object();
@@ -49,40 +48,36 @@ public final class GlobalParametersClient extends DlcClient {
     @GuardedBy("sInstanceLock")
     private static GlobalParametersClient sClient;
 
-    private GlobalParametersClient(@NonNull Context context,
-            ListeningExecutorService executorService) {
+    private GlobalParametersClient(
+            @NonNull Context context, ListeningExecutorService executorService) {
         super(context, new ComponentName(context, GlobalParametersService.class), executorService);
     }
 
-    /**
-     * Get the GlobalParametersClient singleton instance.
-     */
+    /** Get the GlobalParametersClient singleton instance. */
     public static GlobalParametersClient getInstance() {
-        return getInstance(DeviceLockControllerApplication.getAppContext(),
-                /* executorService= */ null);
+        return getInstance(
+                DeviceLockControllerApplication.getAppContext(), /* executorService= */ null);
     }
 
-    /**
-     * Get the GlobalParametersClient singleton instance.
-     */
+    /** Get the GlobalParametersClient singleton instance. */
     @VisibleForTesting
-    public static GlobalParametersClient getInstance(Context appContext,
-            @Nullable ListeningExecutorService executorService) {
+    public static GlobalParametersClient getInstance(
+            Context appContext, @Nullable ListeningExecutorService executorService) {
         synchronized (sInstanceLock) {
             if (sClient == null) {
-                sClient = new GlobalParametersClient(
-                        appContext,
-                        executorService == null
-                                ? MoreExecutors.listeningDecorator(Executors.newCachedThreadPool())
-                                : executorService);
+                sClient =
+                        new GlobalParametersClient(
+                                appContext,
+                                executorService == null
+                                        ? MoreExecutors.listeningDecorator(
+                                                Executors.newCachedThreadPool())
+                                        : executorService);
             }
             return sClient;
         }
     }
 
-    /**
-     * Reset the Client singleton instance
-     */
+    /** Reset the Client singleton instance */
     @VisibleForTesting
     public static void reset() {
         synchronized (sInstanceLock) {
@@ -94,26 +89,26 @@ public final class GlobalParametersClient extends DlcClient {
     }
 
     /**
-     * Clear any existing global parameters.
-     * Note that this API can only be called in debuggable build for debugging purpose.
+     * Clear any existing global parameters. Note that this API can only be called in debuggable
+     * build for debugging purpose.
      */
     @SuppressWarnings("GuardedBy") // mLock already held in "call" (error prone).
     public ListenableFuture<Void> clear() {
-        return call(() -> {
-            asInterface(getService()).clear();
-            return null;
-        });
+        return call(
+                () -> {
+                    asInterface(getService()).clear();
+                    return null;
+                });
     }
 
-    /**
-     * Dump current values of SetupParameters to logcat.
-     */
+    /** Dump current values of SetupParameters to logcat. */
     @SuppressWarnings("GuardedBy") // mLock already held in "call" (error prone).
     public ListenableFuture<Void> dump() {
-        return call(() -> {
-            asInterface(getService()).dump();
-            return null;
-        });
+        return call(
+                () -> {
+                    asInterface(getService()).dump();
+                    return null;
+                });
     }
 
     /**
@@ -133,17 +128,18 @@ public final class GlobalParametersClient extends DlcClient {
      */
     @SuppressWarnings("GuardedBy") // mLock already held in "call" (error prone).
     public ListenableFuture<Void> setProvisionReady(boolean isProvisionReady) {
-        return call(() -> {
-            asInterface(getService()).setProvisionReady(isProvisionReady);
-            return null;
-        });
+        return call(
+                () -> {
+                    asInterface(getService()).setProvisionReady(isProvisionReady);
+                    return null;
+                });
     }
 
     /**
      * Gets the unique identifier that is registered to DeviceLock backend server.
      *
      * @return The registered device unique identifier; null if device has never checked in with
-     * backed server.
+     *     backed server.
      */
     @Nullable
     @SuppressWarnings("GuardedBy") // mLock already held in "call" (error prone).
@@ -158,10 +154,11 @@ public final class GlobalParametersClient extends DlcClient {
      */
     @SuppressWarnings("GuardedBy") // mLock already held in "call" (error prone).
     public ListenableFuture<Void> setRegisteredDeviceId(String registeredDeviceId) {
-        return call(() -> {
-            asInterface(getService()).setRegisteredDeviceId(registeredDeviceId);
-            return null;
-        });
+        return call(
+                () -> {
+                    asInterface(getService()).setRegisteredDeviceId(registeredDeviceId);
+                    return null;
+                });
     }
 
     /**
@@ -181,10 +178,11 @@ public final class GlobalParametersClient extends DlcClient {
      */
     @SuppressWarnings("GuardedBy") // mLock already held in "call" (error prone).
     public ListenableFuture<Void> setProvisionForced(boolean isForced) {
-        return call(() -> {
-            asInterface(getService()).setProvisionForced(isForced);
-            return null;
-        });
+        return call(
+                () -> {
+                    asInterface(getService()).setProvisionForced(isForced);
+                    return null;
+                });
     }
 
     /**
@@ -204,10 +202,11 @@ public final class GlobalParametersClient extends DlcClient {
      */
     @SuppressWarnings("GuardedBy") // mLock already held in "call" (error prone).
     public ListenableFuture<Void> setDeviceState(@DeviceState int state) {
-        return call(() -> {
-            asInterface(getService()).setDeviceState(state);
-            return null;
-        });
+        return call(
+                () -> {
+                    asInterface(getService()).setDeviceState(state);
+                    return null;
+                });
     }
 
     /**
@@ -227,10 +226,11 @@ public final class GlobalParametersClient extends DlcClient {
      */
     @SuppressWarnings("GuardedBy") // mLock already held in "call" (error prone).
     public ListenableFuture<Void> setFinalizationState(@FinalizationState int state) {
-        return call(() -> {
-            asInterface(getService()).setFinalizationState(state);
-            return null;
-        });
+        return call(
+                () -> {
+                    asInterface(getService()).setFinalizationState(state);
+                    return null;
+                });
     }
 
     /**
@@ -249,9 +249,36 @@ public final class GlobalParametersClient extends DlcClient {
      */
     public ListenableFuture<Void> setLastReceivedProvisionState(
             @DeviceProvisionState int provisionState) {
-        return call(() -> {
-            asInterface(getService()).setLastReceivedProvisionState(provisionState);
-            return null;
-        });
+        return call(
+                () -> {
+                    asInterface(getService()).setLastReceivedProvisionState(provisionState);
+                    return null;
+                });
+    }
+
+    /**
+     * Get the current lock task type.
+     *
+     * @return one of {@link LockTaskType}.
+     */
+    @SuppressWarnings("GuardedBy") // mLock already held in "call" (error prone).
+    public ListenableFuture<Integer> getLockTaskType() {
+        return call(() -> asInterface(getService()).getLockTaskType());
+    }
+
+    /**
+     * Set the lock task type for the current provision/device state after enforcement of policies
+     * is complete.
+     *
+     * @param lockTaskType the new lock task type
+     * @return void.
+     */
+    @SuppressWarnings("GuardedBy") // mLock already held in "call" (error prone).
+    public ListenableFuture<Void> setLockTaskType(@LockTaskType Integer lockTaskType) {
+        return call(
+                () -> {
+                    asInterface(getService()).setLockTaskType(lockTaskType);
+                    return null;
+                });
     }
 }
diff --git a/DeviceLockController/src/com/android/devicelockcontroller/storage/GlobalParametersService.java b/DeviceLockController/src/com/android/devicelockcontroller/storage/GlobalParametersService.java
index 94ec96a1..773c7c5c 100644
--- a/DeviceLockController/src/com/android/devicelockcontroller/storage/GlobalParametersService.java
+++ b/DeviceLockController/src/com/android/devicelockcontroller/storage/GlobalParametersService.java
@@ -22,13 +22,12 @@ import android.content.Intent;
 import android.os.IBinder;
 
 import com.android.devicelockcontroller.common.DeviceLockConstants.DeviceProvisionState;
+import com.android.devicelockcontroller.policy.DevicePolicyController.LockTaskType;
 import com.android.devicelockcontroller.policy.DeviceStateController.DeviceState;
 import com.android.devicelockcontroller.policy.FinalizationControllerImpl.FinalizationState;
 import com.android.devicelockcontroller.util.LogUtil;
 
-/**
- * A class exposing Global Parameters as a service.
- */
+/** A class exposing Global Parameters as a service. */
 public final class GlobalParametersService extends Service {
     private static final String TAG = "GlobalParametersService";
 
@@ -107,6 +106,17 @@ public final class GlobalParametersService extends Service {
                         @DeviceProvisionState int provisionState) {
                     GlobalParameters.setLastReceivedProvisionState(mContext, provisionState);
                 }
+
+                @Override
+                @LockTaskType
+                public int getLockTaskType() {
+                    return GlobalParameters.getLockTaskType(mContext);
+                }
+
+                @Override
+                public void setLockTaskType(@LockTaskType int lockTaskType) {
+                    GlobalParameters.setLockTaskType(mContext, lockTaskType);
+                }
             };
 
     @Override
diff --git a/DeviceLockController/src/com/android/devicelockcontroller/storage/IGlobalParametersService.aidl b/DeviceLockController/src/com/android/devicelockcontroller/storage/IGlobalParametersService.aidl
index b8ce9b0f..d1e1a5b0 100644
--- a/DeviceLockController/src/com/android/devicelockcontroller/storage/IGlobalParametersService.aidl
+++ b/DeviceLockController/src/com/android/devicelockcontroller/storage/IGlobalParametersService.aidl
@@ -35,4 +35,6 @@ interface IGlobalParametersService {
     void setFinalizationState(int state);
     int getLastReceivedProvisionState();
     void setLastReceivedProvisionState(int provisionState);
+    int getLockTaskType();
+    void setLockTaskType(int lockTaskType);
 }
\ No newline at end of file
diff --git a/DeviceLockController/tests/android_test/Android.bp b/DeviceLockController/tests/android_test/Android.bp
index de6d6a25..bf3c3373 100644
--- a/DeviceLockController/tests/android_test/Android.bp
+++ b/DeviceLockController/tests/android_test/Android.bp
@@ -27,6 +27,8 @@ android_test {
     static_libs: [
         "devicelockcontroller-stats",
         "statsdprotolite",
+        "androidx.test.core",
+        "androidx.test.runner",
     ],
     srcs: [
         "src/**/*.java",
diff --git a/DeviceLockController/tests/android_test/src/com/android/devicelockcontroller/stats/StatsLoggerImplTest.java b/DeviceLockController/tests/android_test/src/com/android/devicelockcontroller/stats/StatsLoggerImplTest.java
index d642b507..b4836b24 100644
--- a/DeviceLockController/tests/android_test/src/com/android/devicelockcontroller/stats/StatsLoggerImplTest.java
+++ b/DeviceLockController/tests/android_test/src/com/android/devicelockcontroller/stats/StatsLoggerImplTest.java
@@ -25,10 +25,21 @@ import static com.android.devicelockcontroller.DevicelockStatsLog.DEVICE_LOCK_CH
 import static com.android.devicelockcontroller.DevicelockStatsLog.DEVICE_LOCK_CHECK_IN_REQUEST_REPORTED__TYPE__PAUSE_DEVICE_PROVISIONING;
 import static com.android.devicelockcontroller.DevicelockStatsLog.DEVICE_LOCK_CHECK_IN_REQUEST_REPORTED__TYPE__REPORT_DEVICE_PROVISION_STATE;
 import static com.android.devicelockcontroller.DevicelockStatsLog.DEVICE_LOCK_CHECK_IN_RETRY_REPORTED;
+import static com.android.devicelockcontroller.DevicelockStatsLog.DEVICE_LOCK_DEVICE_STATE_EVENT;
+import static com.android.devicelockcontroller.DevicelockStatsLog.DEVICE_LOCK_DEVICE_STATE_EVENT__EVENT__EVENT_LOCK;
+import static com.android.devicelockcontroller.DevicelockStatsLog.DEVICE_LOCK_DEVICE_STATE_EVENT__EVENT__EVENT_UNLOCK;
+import static com.android.devicelockcontroller.DevicelockStatsLog.DEVICE_LOCK_KIOSK_APP_INSTALLATION_FAILED;
 import static com.android.devicelockcontroller.DevicelockStatsLog.DEVICE_LOCK_KIOSK_APP_REQUEST_REPORTED;
 import static com.android.devicelockcontroller.DevicelockStatsLog.DEVICE_LOCK_LOCK_UNLOCK_DEVICE_FAILURE_REPORTED;
 import static com.android.devicelockcontroller.DevicelockStatsLog.DEVICE_LOCK_PROVISIONING_COMPLETE_REPORTED;
 import static com.android.devicelockcontroller.DevicelockStatsLog.DEVICE_LOCK_PROVISION_FAILURE_REPORTED;
+import static com.android.devicelockcontroller.DevicelockStatsLog.DEVICE_LOCK_PROVISION_STATE_EVENT;
+import static com.android.devicelockcontroller.DevicelockStatsLog.DEVICE_LOCK_FCM_MESSAGE_RECEIVED;
+import static com.android.devicelockcontroller.DevicelockStatsLog.DEVICE_LOCK_PROVISION_STATE_EVENT__EVENT__EVENT_DEVICE_RESET;
+import static com.android.devicelockcontroller.DevicelockStatsLog.DEVICE_LOCK_PROVISION_STATE_EVENT__EVENT__EVENT_FINALIZATION;
+import static com.android.devicelockcontroller.DevicelockStatsLog.DEVICE_LOCK_PROVISION_STATE_EVENT__EVENT__EVENT_FINALIZATION_FAILURE;
+import static com.android.devicelockcontroller.DevicelockStatsLog.DEVICE_LOCK_PROVISION_STATE_EVENT__EVENT__EVENT_SUCCESSFUL_PROVISIONING;
+import static com.android.devicelockcontroller.DevicelockStatsLog.DEVICE_LOCK_PROVISION_STATE_EVENT__EVENT__EVENT_UNSUCCESSFUL_CHECKIN_REQUEST;
 import static com.android.devicelockcontroller.DevicelockStatsLog.LOCK_UNLOCK_DEVICE_FAILURE_REPORTED__STATE_POST_COMMAND__LOCKED;
 import static com.android.devicelockcontroller.DevicelockStatsLog.LOCK_UNLOCK_DEVICE_FAILURE_REPORTED__STATE_POST_COMMAND__UNLOCKED;
 import static com.android.devicelockcontroller.DevicelockStatsLog.PROVISION_FAILURE_REPORTED__REASON__COUNTRY_INFO_UNAVAILABLE;
@@ -45,25 +56,47 @@ import static com.android.devicelockcontroller.stats.StatsLogger.ProvisionFailur
 import static com.android.devicelockcontroller.stats.StatsLogger.ProvisionFailureReasonStats.UNKNOWN;
 import static com.android.devicelockcontroller.stats.StatsLoggerImpl.TEX_ID_DEVICE_RESET_PROVISION_DEFERRED;
 import static com.android.devicelockcontroller.stats.StatsLoggerImpl.TEX_ID_DEVICE_RESET_PROVISION_MANDATORY;
-import static com.android.devicelockcontroller.stats.StatsLoggerImpl.TEX_ID_SUCCESSFUL_CHECK_IN_RESPONSE_COUNT;
-import static com.android.devicelockcontroller.stats.StatsLoggerImpl.TEX_ID_SUCCESSFUL_LOCKING_COUNT;
-import static com.android.devicelockcontroller.stats.StatsLoggerImpl.TEX_ID_SUCCESSFUL_PROVISIONING_COUNT;
-import static com.android.devicelockcontroller.stats.StatsLoggerImpl.TEX_ID_SUCCESSFUL_UNLOCKING_COUNT;
 import static com.android.dx.mockito.inline.extended.ExtendedMockito.verify;
 
+import static org.mockito.Mockito.when;
+
+import android.content.Context;
+import android.content.pm.PackageInfo;
+import android.content.pm.PackageManager;
+
+import androidx.test.core.app.ApplicationProvider;
+
 import com.android.devicelockcontroller.DevicelockStatsLog;
 import com.android.modules.expresslog.Counter;
 import com.android.modules.utils.testing.ExtendedMockitoRule;
 
+import org.junit.After;
+import org.junit.Before;
 import org.junit.Rule;
 import org.junit.Test;
+import org.mockito.Mock;
+import org.mockito.MockitoAnnotations;
 
 import java.util.concurrent.TimeUnit;
 
 public final class StatsLoggerImplTest {
     private static final int UID = 123;
     private static final long PROVISIONING_TIME_MILLIS = 2000;
-    private final StatsLogger mStatsLogger = new StatsLoggerImpl();
+    private static final long APEX_VERSION = 10L;
+    // Checkstyle results in line too long when using original constant.
+    private static final int UNSUCCESSFUL_CHECKIN_REQUEST =
+            DEVICE_LOCK_PROVISION_STATE_EVENT__EVENT__EVENT_UNSUCCESSFUL_CHECKIN_REQUEST;
+    // Checkstyle results in line too long when using original constant.
+    private static final int SUCCESSFUL_PROVISIONING =
+            DEVICE_LOCK_PROVISION_STATE_EVENT__EVENT__EVENT_SUCCESSFUL_PROVISIONING;
+    // Checkstyle results in line too long when using original constant.
+    private static final int FINALIZATION_FAILURE =
+            DEVICE_LOCK_PROVISION_STATE_EVENT__EVENT__EVENT_FINALIZATION_FAILURE;
+
+    private final StatsLogger mStatsLogger =
+            new StatsLoggerImpl(ApplicationProvider.getApplicationContext());
+
+    private StatsLoggerImpl mStatsLoggerWithMockedContext;
 
     @Rule
     public final ExtendedMockitoRule mExtendedMockitoRule =
@@ -72,6 +105,33 @@ public final class StatsLoggerImplTest {
                     .mockStatic(Counter.class)
                     .build();
 
+    @Mock private Context mMockContext;
+    @Mock private PackageManager mMockPackageManager;
+    @Mock private PackageInfo mMockPackageInfo;
+
+
+    private AutoCloseable mCloseable;
+
+    @Before
+    public void setUp() throws PackageManager.NameNotFoundException {
+        mCloseable = MockitoAnnotations.openMocks(this);
+
+        when(mMockContext.getPackageName()).thenReturn("com.google.android.devicelockcontroller");
+        when(mMockContext.getPackageManager()).thenReturn(mMockPackageManager);
+        when(mMockPackageManager.getPackageInfo(
+                mMockContext.getPackageName(), PackageManager.MATCH_APEX))
+                .thenReturn(mMockPackageInfo);
+        when(mMockPackageInfo.getLongVersionCode()).thenReturn(APEX_VERSION);
+        mStatsLoggerWithMockedContext = new StatsLoggerImpl(mMockContext);
+    }
+
+    @After
+    public void tearDown() throws Exception {
+        if (mCloseable != null) {
+            mCloseable.close();
+        }
+    }
+
     @Test
     public void logGetDeviceCheckInStatus_shouldWriteCorrectLog() {
         mStatsLogger.logGetDeviceCheckInStatus();
@@ -132,20 +192,6 @@ public final class StatsLoggerImplTest {
         verify(() -> Counter.logIncrement(TEX_ID_DEVICE_RESET_PROVISION_DEFERRED));
     }
 
-    @Test
-    public void logSuccessfulCheckIn_shouldLogToTelemetryExpress() {
-        mStatsLogger.logSuccessfulCheckIn();
-
-        verify(() -> Counter.logIncrement(TEX_ID_SUCCESSFUL_CHECK_IN_RESPONSE_COUNT));
-    }
-
-    @Test
-    public void logSuccessfulProvisioning_shouldLogToTelemetryExpress() {
-        mStatsLogger.logSuccessfulProvisioning();
-
-        verify(() -> Counter.logIncrement(TEX_ID_SUCCESSFUL_PROVISIONING_COUNT));
-    }
-
     @Test
     public void logCheckInRetry_shouldWriteCorrectLogWhenReasonUnspecified() {
         mStatsLogger.logCheckInRetry(StatsLogger.CheckInRetryReason.RESPONSE_UNSPECIFIED);
@@ -246,15 +292,112 @@ public final class StatsLoggerImplTest {
 
     @Test
     public void logSuccessfulLockingDevice_shouldWriteCorrectLog() {
-        mStatsLogger.logSuccessfulLockingDevice();
-
-        verify(() -> Counter.logIncrement(TEX_ID_SUCCESSFUL_LOCKING_COUNT));
+        mStatsLoggerWithMockedContext.logDeviceStateEvent(
+                DEVICE_LOCK_DEVICE_STATE_EVENT__EVENT__EVENT_LOCK);
+
+        verify(
+                () -> DevicelockStatsLog.write(
+                        DEVICE_LOCK_DEVICE_STATE_EVENT,
+                        DEVICE_LOCK_DEVICE_STATE_EVENT__EVENT__EVENT_LOCK,
+                        APEX_VERSION
+                )
+        );
     }
 
     @Test
     public void logSuccessfulUnlockingDevice_shouldWriteCorrectLog() {
-        mStatsLogger.logSuccessfulUnlockingDevice();
+        mStatsLoggerWithMockedContext.logDeviceStateEvent(
+                DEVICE_LOCK_DEVICE_STATE_EVENT__EVENT__EVENT_UNLOCK);
+
+        verify(
+                () -> DevicelockStatsLog.write(
+                        DEVICE_LOCK_DEVICE_STATE_EVENT,
+                        DEVICE_LOCK_DEVICE_STATE_EVENT__EVENT__EVENT_UNLOCK,
+                        APEX_VERSION
+                )
+        );
+    }
+
+    @Test
+    public void logKioskAppInstallationFailed_writesCorrectLog() {
+        mStatsLoggerWithMockedContext.logKioskAppInstallationFailed();
+
+        verify(
+                () ->
+                        DevicelockStatsLog.write(
+                                DEVICE_LOCK_KIOSK_APP_INSTALLATION_FAILED, APEX_VERSION));
+    }
+
+    @Test
+    public void logProvisionStateEvent_unsuccessfulCheckIn_writesCorrectLog() {
+        mStatsLoggerWithMockedContext.logProvisionStateEvent(
+                UNSUCCESSFUL_CHECKIN_REQUEST);
+
+        verify(
+                () ->
+                        DevicelockStatsLog.write(
+                                DEVICE_LOCK_PROVISION_STATE_EVENT,
+                                UNSUCCESSFUL_CHECKIN_REQUEST,
+                                APEX_VERSION));
+    }
+
+    @Test
+    public void logProvisionStateEvent_successfulProvisioning_writesCorrectLog() {
+        mStatsLoggerWithMockedContext.logProvisionStateEvent(
+                DEVICE_LOCK_PROVISION_STATE_EVENT__EVENT__EVENT_SUCCESSFUL_PROVISIONING);
+
+        verify(
+                () ->
+                        DevicelockStatsLog.write(
+                                DEVICE_LOCK_PROVISION_STATE_EVENT,
+                                // CHECKSTYLE_OFF: LineLength
+                                SUCCESSFUL_PROVISIONING,
+                                APEX_VERSION));
+    }
+
+    @Test
+    public void logProvisionStateEvent_deviceReset_writesCorrectLog() {
+        mStatsLoggerWithMockedContext.logProvisionStateEvent(
+                DEVICE_LOCK_PROVISION_STATE_EVENT__EVENT__EVENT_DEVICE_RESET);
+
+        verify(
+                () ->
+                        DevicelockStatsLog.write(
+                                DEVICE_LOCK_PROVISION_STATE_EVENT,
+                                DEVICE_LOCK_PROVISION_STATE_EVENT__EVENT__EVENT_DEVICE_RESET,
+                                APEX_VERSION));
+    }
+
+    @Test
+    public void logProvisionStateEvent_successfulFinalization_writesCorrectLog() {
+        mStatsLoggerWithMockedContext.logProvisionStateEvent(
+                DEVICE_LOCK_PROVISION_STATE_EVENT__EVENT__EVENT_FINALIZATION);
+
+        verify(
+                () ->
+                        DevicelockStatsLog.write(
+                                DEVICE_LOCK_PROVISION_STATE_EVENT,
+                                DEVICE_LOCK_PROVISION_STATE_EVENT__EVENT__EVENT_FINALIZATION,
+                                APEX_VERSION));
+    }
+
+    @Test
+    public void logProvisionStateEvent_finalizationFailure_writesCorrectLog() {
+        mStatsLoggerWithMockedContext.logProvisionStateEvent(
+                DEVICE_LOCK_PROVISION_STATE_EVENT__EVENT__EVENT_FINALIZATION_FAILURE);
+
+        verify(
+                () ->
+                        DevicelockStatsLog.write(
+                                DEVICE_LOCK_PROVISION_STATE_EVENT,
+                                FINALIZATION_FAILURE,
+                                APEX_VERSION));
+    }
+
+    @Test
+    public void logFcmMessageReceived_writesCorrectLog() {
+        mStatsLoggerWithMockedContext.logFcmMessageReceived();
 
-        verify(() -> Counter.logIncrement(TEX_ID_SUCCESSFUL_UNLOCKING_COUNT));
+        verify(() -> DevicelockStatsLog.write(DEVICE_LOCK_FCM_MESSAGE_RECEIVED, APEX_VERSION));
     }
 }
diff --git a/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/DeviceLockControllerServiceTest.java b/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/DeviceLockControllerServiceTest.java
index 454fb8b5..b317a7cf 100644
--- a/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/DeviceLockControllerServiceTest.java
+++ b/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/DeviceLockControllerServiceTest.java
@@ -16,6 +16,10 @@
 
 package com.android.devicelockcontroller;
 
+import static com.android.devicelockcontroller.DevicelockStatsLog.DEVICE_LOCK_DEVICE_STATE_EVENT__EVENT__EVENT_LOCK;
+import static com.android.devicelockcontroller.DevicelockStatsLog.DEVICE_LOCK_DEVICE_STATE_EVENT__EVENT__EVENT_UNLOCK;
+import static com.android.devicelockcontroller.DevicelockStatsLog.DEVICE_LOCK_PROVISION_STATE_EVENT__EVENT__EVENT_FINALIZATION;
+import static com.android.devicelockcontroller.DevicelockStatsLog.DEVICE_LOCK_PROVISION_STATE_EVENT__EVENT__EVENT_FINALIZATION_FAILURE;
 import static com.android.devicelockcontroller.common.DeviceLockConstants.EXTRA_KIOSK_PACKAGE;
 
 import static com.google.common.truth.Truth.assertThat;
@@ -67,6 +71,13 @@ public final class DeviceLockControllerServiceTest {
 
     private static final String KIOSK_APP_PACKAGE_NAME = "TEST_PACKAGE";
 
+    // Checkstyle results in line too long when using original constant.
+    private static final int FINALIZATION =
+            DEVICE_LOCK_PROVISION_STATE_EVENT__EVENT__EVENT_FINALIZATION;
+
+    // Checkstyle results in line too long when using original constant.
+    private static final int FINALIZATION_FAILURE =
+            DEVICE_LOCK_PROVISION_STATE_EVENT__EVENT__EVENT_FINALIZATION_FAILURE;
     private StatsLogger mStatsLogger;
     private TestDeviceLockControllerApplication mTestApp;
 
@@ -106,7 +117,7 @@ public final class DeviceLockControllerServiceTest {
         serviceStub.lockDevice(new RemoteCallback((result -> {})));
 
         verify(mStatsLogger).logKioskAppRequest(eq(KIOSK_APP_UID));
-        verify(mStatsLogger).logSuccessfulLockingDevice();
+        verify(mStatsLogger).logDeviceStateEvent(DEVICE_LOCK_DEVICE_STATE_EVENT__EVENT__EVENT_LOCK);
     }
 
     @Test
@@ -142,7 +153,8 @@ public final class DeviceLockControllerServiceTest {
         serviceStub.unlockDevice(new RemoteCallback((result -> {})));
 
         verify(mStatsLogger).logKioskAppRequest(eq(KIOSK_APP_UID));
-        verify(mStatsLogger).logSuccessfulUnlockingDevice();
+        verify(mStatsLogger)
+                .logDeviceStateEvent(DEVICE_LOCK_DEVICE_STATE_EVENT__EVENT__EVENT_UNLOCK);
     }
 
     @Test
@@ -164,6 +176,48 @@ public final class DeviceLockControllerServiceTest {
         verify(mStatsLogger).logUnlockDeviceFailure(DeviceStateController.DeviceState.LOCKED);
     }
 
+    @Test
+    public void notifyKioskSetupFinished_deviceUnlocked_shouldLogKioskRequest_AndLogUnlockSuccess()
+            throws RemoteException, TimeoutException {
+        DeviceStateController deviceStateController = mTestApp.getDeviceStateController();
+        Intent serviceIntent = new Intent(mTestApp, DeviceLockControllerService.class);
+        IBinder binder = mServiceRule.bindService(serviceIntent);
+
+        when(mTestApp.getDeviceStateController().isLocked()).thenReturn(
+                Futures.immediateFuture(false));
+
+        when(deviceStateController.unlockDevice()).thenReturn(
+                Futures.immediateVoidFuture());
+
+        assertThat(binder).isNotNull();
+
+        IDeviceLockControllerService.Stub serviceStub = (IDeviceLockControllerService.Stub) binder;
+        serviceStub.notifyKioskSetupFinished(new RemoteCallback((result -> {})));
+
+        verify(mStatsLogger).logKioskAppRequest(eq(KIOSK_APP_UID));
+        verify(mStatsLogger)
+                .logDeviceStateEvent(DEVICE_LOCK_DEVICE_STATE_EVENT__EVENT__EVENT_UNLOCK);
+    }
+
+    @Test
+    public void notifyKioskSetupFinished_deviceLocked_shouldLogKioskRequest_andLogLockSuccess()
+            throws RemoteException, TimeoutException {
+        DeviceStateController deviceStateController = mTestApp.getDeviceStateController();
+        Intent serviceIntent = new Intent(mTestApp, DeviceLockControllerService.class);
+        IBinder binder = mServiceRule.bindService(serviceIntent);
+
+        when(deviceStateController.isLocked()).thenReturn(
+                Futures.immediateFuture(true));
+
+        assertThat(binder).isNotNull();
+
+        IDeviceLockControllerService.Stub serviceStub = (IDeviceLockControllerService.Stub) binder;
+        serviceStub.notifyKioskSetupFinished(new RemoteCallback((result -> {})));
+
+        verify(mStatsLogger).logKioskAppRequest(eq(KIOSK_APP_UID));
+        verify(mStatsLogger).logDeviceStateEvent(DEVICE_LOCK_DEVICE_STATE_EVENT__EVENT__EVENT_LOCK);
+    }
+
     @Test
     public void isDeviceLocked_shouldLogKioskRequest() throws RemoteException, TimeoutException {
         Intent serviceIntent = new Intent(mTestApp, DeviceLockControllerService.class);
@@ -212,6 +266,58 @@ public final class DeviceLockControllerServiceTest {
         verify(mStatsLogger).logKioskAppRequest(eq(KIOSK_APP_UID));
     }
 
+    @Test
+    public void clearDeviceRestrictions_success_shouldLogFinalizationSuccess()
+            throws TimeoutException, RemoteException {
+        Intent serviceIntent = new Intent(mTestApp, DeviceLockControllerService.class);
+        IBinder binder = mServiceRule.bindService(serviceIntent);
+        DeviceStateController deviceStateController = mTestApp.getDeviceStateController();
+        when(deviceStateController.clearDevice()).thenReturn(Futures.immediateVoidFuture());
+        FinalizationController finalizationController = mTestApp.getFinalizationController();
+        when(finalizationController.notifyRestrictionsCleared())
+                .thenReturn(Futures.immediateVoidFuture());
+
+        assertThat(binder).isNotNull();
+
+        IDeviceLockControllerService.Stub serviceStub = (IDeviceLockControllerService.Stub) binder;
+        serviceStub.clearDeviceRestrictions(new RemoteCallback((result -> {})));
+
+        verify(mStatsLogger).logProvisionStateEvent(FINALIZATION);
+    }
+
+    @Test
+    public void clearDeviceRestrictions_failure_shouldLogFinalizationFailure()
+            throws TimeoutException, RemoteException {
+        Intent serviceIntent = new Intent(mTestApp, DeviceLockControllerService.class);
+        IBinder binder = mServiceRule.bindService(serviceIntent);
+        DeviceStateController deviceStateController = mTestApp.getDeviceStateController();
+        when(deviceStateController.clearDevice()).thenReturn(Futures.immediateVoidFuture());
+        FinalizationController finalizationController = mTestApp.getFinalizationController();
+        when(finalizationController.notifyRestrictionsCleared())
+                .thenReturn(Futures.immediateFailedFuture(new RuntimeException("Test Exception")));
+
+        assertThat(binder).isNotNull();
+
+        IDeviceLockControllerService.Stub serviceStub = (IDeviceLockControllerService.Stub) binder;
+        serviceStub.clearDeviceRestrictions(new RemoteCallback((result -> {})));
+
+        verify(mStatsLogger).logProvisionStateEvent(FINALIZATION_FAILURE);
+    }
+
+    @Test
+    public void getEnrollmentType_shouldLogKioskRequest()
+            throws RemoteException, TimeoutException {
+        Intent serviceIntent = new Intent(mTestApp, DeviceLockControllerService.class);
+        IBinder binder = mServiceRule.bindService(serviceIntent);
+
+        assertThat(binder).isNotNull();
+
+        IDeviceLockControllerService.Stub serviceStub = (IDeviceLockControllerService.Stub) binder;
+        serviceStub.getEnrollmentType(new RemoteCallback((result -> {})));
+
+        verify(mStatsLogger).logKioskAppRequest(eq(KIOSK_APP_UID));
+    }
+
     @Test
     public void onUserSwitching_enforcePoliciesAndFinalizationState()
             throws RemoteException, TimeoutException {
diff --git a/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/policy/DevicePolicyControllerImplTest.java b/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/policy/DevicePolicyControllerImplTest.java
index ad2b2eab..40b853e9 100644
--- a/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/policy/DevicePolicyControllerImplTest.java
+++ b/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/policy/DevicePolicyControllerImplTest.java
@@ -64,6 +64,7 @@ import com.android.devicelockcontroller.SystemDeviceLockManager;
 import com.android.devicelockcontroller.TestDeviceLockControllerApplication;
 import com.android.devicelockcontroller.activities.LandingActivity;
 import com.android.devicelockcontroller.activities.ProvisioningActivity;
+import com.android.devicelockcontroller.policy.DevicePolicyController.LockTaskType;
 import com.android.devicelockcontroller.policy.ProvisionStateController.ProvisionState;
 import com.android.devicelockcontroller.storage.GlobalParametersClient;
 import com.android.devicelockcontroller.storage.SetupParametersClient;
@@ -184,6 +185,7 @@ public final class DevicePolicyControllerImplTest {
 
         shadowOf(Looper.getMainLooper()).idle();
         assertLockTaskModeNotStarted();
+        assertLockTaskType(LockTaskType.NOT_IN_LOCK_TASK);
     }
 
     @Test
@@ -201,6 +203,7 @@ public final class DevicePolicyControllerImplTest {
 
         shadowOf(Looper.getMainLooper()).idle();
         assertLockTaskModeStarted();
+        assertLockTaskType(LockTaskType.LANDING_ACTIVITY);
     }
 
     @Test
@@ -219,6 +222,7 @@ public final class DevicePolicyControllerImplTest {
 
         shadowOf(Looper.getMainLooper()).idle();
         assertLockTaskModeStarted();
+        assertLockTaskType(LockTaskType.KIOSK_SETUP_ACTIVITY);
     }
 
     @Test
@@ -234,6 +238,7 @@ public final class DevicePolicyControllerImplTest {
 
         shadowOf(Looper.getMainLooper()).idle();
         assertLockTaskModeNotStarted();
+        assertLockTaskType(LockTaskType.NOT_IN_LOCK_TASK);
     }
 
     @Test
@@ -250,6 +255,7 @@ public final class DevicePolicyControllerImplTest {
 
         shadowOf(Looper.getMainLooper()).idle();
         assertLockTaskModeNotStarted();
+        assertLockTaskType(LockTaskType.NOT_IN_LOCK_TASK);
     }
 
     @Test
@@ -265,6 +271,7 @@ public final class DevicePolicyControllerImplTest {
 
         shadowOf(Looper.getMainLooper()).idle();
         assertLockTaskModeNotStarted();
+        assertLockTaskType(LockTaskType.NOT_IN_LOCK_TASK);
     }
 
     @Test
@@ -280,6 +287,7 @@ public final class DevicePolicyControllerImplTest {
 
         shadowOf(Looper.getMainLooper()).idle();
         assertLockTaskModeNotStarted();
+        assertLockTaskType(LockTaskType.NOT_IN_LOCK_TASK);
     }
 
     @Test
@@ -297,6 +305,7 @@ public final class DevicePolicyControllerImplTest {
 
         shadowOf(Looper.getMainLooper()).idle();
         assertLockTaskModeStarted();
+        assertLockTaskType(LockTaskType.KIOSK_LOCK_ACTIVITY);
     }
 
     @Test
@@ -314,6 +323,7 @@ public final class DevicePolicyControllerImplTest {
 
         shadowOf(Looper.getMainLooper()).idle();
         assertLockTaskModeNotStarted();
+        assertLockTaskType(LockTaskType.NOT_IN_LOCK_TASK);
     }
 
     @Test
@@ -335,6 +345,7 @@ public final class DevicePolicyControllerImplTest {
 
         shadowOf(Looper.getMainLooper()).idle();
         assertLockTaskModeNotStarted();
+        assertLockTaskType(LockTaskType.NOT_IN_LOCK_TASK);
     }
 
     @Test
@@ -356,6 +367,7 @@ public final class DevicePolicyControllerImplTest {
 
         shadowOf(Looper.getMainLooper()).idle();
         assertLockTaskModeNotStarted();
+        assertLockTaskType(LockTaskType.NOT_IN_LOCK_TASK);
     }
 
     @Test
@@ -374,6 +386,7 @@ public final class DevicePolicyControllerImplTest {
 
         shadowOf(Looper.getMainLooper()).idle();
         assertLockTaskModeStarted();
+        assertLockTaskType(LockTaskType.KIOSK_LOCK_ACTIVITY);
     }
 
     @Test
@@ -1153,6 +1166,12 @@ public final class DevicePolicyControllerImplTest {
                 EXTRA_SHOW_CRITICAL_PROVISION_FAILED_UI_ON_START)).isTrue();
     }
 
+    private static void assertLockTaskType(@LockTaskType int lockTaskType)
+            throws ExecutionException, InterruptedException {
+        assertThat(GlobalParametersClient.getInstance().getLockTaskType().get())
+                .isEqualTo(lockTaskType);
+    }
+
     private void installKioskAppWithoutCategoryHomeIntentFilter() {
         ShadowPackageManager shadowPackageManager = Shadows.shadowOf(mTestApp.getPackageManager());
         PackageInfo kioskPackageInfo = new PackageInfo();
diff --git a/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/policy/DeviceStateControllerImplTest.java b/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/policy/DeviceStateControllerImplTest.java
index 4983640f..dafbaf1d 100644
--- a/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/policy/DeviceStateControllerImplTest.java
+++ b/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/policy/DeviceStateControllerImplTest.java
@@ -22,6 +22,7 @@ import static org.junit.Assert.assertThrows;
 import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.when;
 
+import android.platform.test.annotations.DisableFlags;
 import android.platform.test.annotations.EnableFlags;
 import android.platform.test.flag.junit.SetFlagsRule;
 
@@ -281,6 +282,7 @@ public final class DeviceStateControllerImplTest {
     }
 
     @Test
+    @DisableFlags(Flags.FLAG_CLEAR_DEVICE_RESTRICTIONS)
     public void clearDevice_withUnprovisionedState_shouldThrowException()
             throws ExecutionException, InterruptedException {
         when(mMockProvisionStateController.getState()).thenReturn(
diff --git a/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/policy/ProvisionStateControllerImplTest.java b/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/policy/ProvisionStateControllerImplTest.java
index 0ce95c0e..dae19a29 100644
--- a/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/policy/ProvisionStateControllerImplTest.java
+++ b/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/policy/ProvisionStateControllerImplTest.java
@@ -16,6 +16,8 @@
 
 package com.android.devicelockcontroller.policy;
 
+import static com.android.devicelockcontroller.DevicelockStatsLog.DEVICE_LOCK_PROVISION_STATE_EVENT__EVENT__EVENT_SUCCESSFUL_PROVISIONING;
+
 import static com.google.common.truth.Truth.assertThat;
 
 import static org.junit.Assert.assertThrows;
@@ -71,6 +73,9 @@ public final class ProvisionStateControllerImplTest {
     private TestDeviceLockControllerApplication mTestApp;
     private ProvisionStateController mProvisionStateController;
     private StatsLogger mStatsLogger;
+    // Checkstyle complains line too long when using original constant.
+    private static final int SUCCESSFUL_PROVISIONING =
+            DEVICE_LOCK_PROVISION_STATE_EVENT__EVENT__EVENT_SUCCESSFUL_PROVISIONING;
 
     @Before
     public void setUp() {
@@ -158,7 +163,7 @@ public final class ProvisionStateControllerImplTest {
 
         mProvisionStateController.setNextStateForEvent(ProvisionEvent.PROVISION_SUCCESS).get();
 
-        verify(mStatsLogger).logSuccessfulProvisioning();
+        verify(mStatsLogger).logProvisionStateEvent(SUCCESSFUL_PROVISIONING);
     }
 
     @Test
diff --git a/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/provision/grpc/impl/DeviceCheckinClientImplTest.java b/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/provision/grpc/impl/DeviceCheckinClientImplTest.java
index f86c5815..345eb1e1 100644
--- a/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/provision/grpc/impl/DeviceCheckinClientImplTest.java
+++ b/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/provision/grpc/impl/DeviceCheckinClientImplTest.java
@@ -18,12 +18,15 @@ package com.android.devicelockcontroller.provision.grpc.impl;
 
 import static android.net.NetworkCapabilities.NET_CAPABILITY_VALIDATED;
 
+import static com.android.devicelockcontroller.DevicelockStatsLog.DEVICE_LOCK_PROVISION_STATE_EVENT__EVENT__EVENT_UNSUCCESSFUL_CHECKIN_REQUEST;
 import static com.android.devicelockcontroller.common.DeviceLockConstants.DeviceProvisionState.PROVISION_STATE_UNSPECIFIED;
 import static com.android.devicelockcontroller.common.DeviceLockConstants.ProvisionFailureReason.UNKNOWN_REASON;
 import static com.android.devicelockcontroller.common.DeviceLockConstants.USER_DEFERRED_DEVICE_PROVISIONING;
 
 import static com.google.common.truth.Truth.assertThat;
 
+import static org.mockito.Mockito.verify;
+
 import android.content.Context;
 import android.net.ConnectivityManager;
 import android.net.Network;
@@ -49,6 +52,8 @@ import com.android.devicelockcontroller.provision.grpc.IsDeviceInApprovedCountry
 import com.android.devicelockcontroller.provision.grpc.PauseDeviceProvisioningGrpcResponse;
 import com.android.devicelockcontroller.provision.grpc.ReportDeviceProvisionStateGrpcResponse;
 import com.android.devicelockcontroller.provision.grpc.UpdateFcmTokenGrpcResponse;
+import com.android.devicelockcontroller.stats.StatsLogger;
+import com.android.devicelockcontroller.stats.StatsLoggerProvider;
 
 import io.grpc.CallOptions;
 import io.grpc.Channel;
@@ -95,6 +100,10 @@ public final  class DeviceCheckinClientImplTest {
     private static final int NON_VPN_NET_ID = 10;
     private static final String TEST_DEVICE_LOCALE = "en-US";
     private static final long TEST_DEVICE_LOCK_APEX_VERSION = 1234567890;
+    // Checkstyle complains line too long when using original constant.
+    private static final int UNSUCCESSFUL_CHECKIN =
+            DEVICE_LOCK_PROVISION_STATE_EVENT__EVENT__EVENT_UNSUCCESSFUL_CHECKIN_REQUEST;
+    private StatsLogger mStatsLogger;
 
     @Rule
     public MockitoRule mMockitoRule = MockitoJUnit.rule();
@@ -151,7 +160,10 @@ public final  class DeviceCheckinClientImplTest {
                             InProcessChannelBuilder.forName(serverName).directExecutor().build();
                     mCreatedChannels.add(newChannel);
                     return mGrpcCleanup.register(newChannel);
-                });
+                }, mContext);
+
+        StatsLoggerProvider loggerProvider = (StatsLoggerProvider) mContext;
+        mStatsLogger = loggerProvider.getStatsLogger();
     }
 
     @Test
@@ -394,6 +406,39 @@ public final  class DeviceCheckinClientImplTest {
         assertThat(response.get().hasRecoverableError()).isTrue();
     }
 
+    @Test
+    public void getCheckInStatus_noConnectivityOrNonVpnNetwork_logsUnsuccessfulCheckin()
+            throws Exception {
+        // GIVEN non-VPN network connects and then loses connectivity
+        Set<ConnectivityManager.NetworkCallback> networkCallbacks =
+                mShadowConnectivityManager.getNetworkCallbacks();
+        for (ConnectivityManager.NetworkCallback callback : networkCallbacks) {
+            callback.onUnavailable();
+        }
+
+        // GIVEN the service fails through the default network
+        mGrpcCleanup.register(InProcessServerBuilder
+                .forName(mDefaultNetworkServerName)
+                .directExecutor()
+                .addService(makeFailingService())
+                .build()
+                .start());
+
+        // WHEN we ask for the check in status
+        AtomicReference<GetDeviceCheckInStatusGrpcResponse> response = new AtomicReference<>();
+        mBgExecutor.submit(() -> response.set(
+                        mDeviceCheckInClientImpl.getDeviceCheckInStatus(
+                                new ArraySet<>(),
+                                TEST_CARRIER_INFO,
+                                TEST_DEVICE_LOCALE,
+                                TEST_DEVICE_LOCK_APEX_VERSION,
+                                TEST_FCM_TOKEN)))
+                .get();
+
+        // THEN the unsuccessful checkin is logged
+        verify(mStatsLogger).logProvisionStateEvent(UNSUCCESSFUL_CHECKIN);
+    }
+
     @Test
     public void getCheckInStatus_lostNonVpnConnection_isNotSuccessful()
             throws Exception {
diff --git a/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/provision/worker/DeviceCheckInWorkerTest.java b/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/provision/worker/DeviceCheckInWorkerTest.java
index f637e257..86d31705 100644
--- a/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/provision/worker/DeviceCheckInWorkerTest.java
+++ b/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/provision/worker/DeviceCheckInWorkerTest.java
@@ -137,7 +137,6 @@ public class DeviceCheckInWorkerTest {
         assertThat(result).isEqualTo(Result.success());
         // THEN check in request was logged
         verify(mStatsLogger).logGetDeviceCheckInStatus();
-        verify(mStatsLogger).logSuccessfulCheckIn();
     }
 
     @Test
@@ -156,9 +155,8 @@ public class DeviceCheckInWorkerTest {
 
         // THEN work succeeded
         assertThat(result).isEqualTo(Result.retry());
-        // THEN check in request was logged, but successful check in is NOT
+        // THEN check in request was logged
         verify(mStatsLogger).logGetDeviceCheckInStatus();
-        verify(mStatsLogger, never()).logSuccessfulCheckIn();
     }
 
     @Test
@@ -177,9 +175,8 @@ public class DeviceCheckInWorkerTest {
 
         // THEN work succeeded
         assertThat(result).isEqualTo(Result.retry());
-        // THEN attempt of check in request WAS logged, but the successful check in was NOT logged.
+        // THEN attempt of check in request was logged
         verify(mStatsLogger).logGetDeviceCheckInStatus();
-        verify(mStatsLogger, never()).logSuccessfulCheckIn();
     }
 
     @Test
@@ -204,9 +201,8 @@ public class DeviceCheckInWorkerTest {
                 ((TestDeviceLockControllerApplication) ApplicationProvider.getApplicationContext())
                         .getDeviceLockControllerScheduler();
         verify(scheduler).scheduleRetryCheckInWork(eq(RETRY_ON_FAILURE_DELAY));
-        // THEN attempt of check in request WAS logged, but the successful check in was NOT logged.
+        // THEN attempt of check in request was logged
         verify(mStatsLogger).logGetDeviceCheckInStatus();
-        verify(mStatsLogger, never()).logSuccessfulCheckIn();
     }
 
     @Test
@@ -277,7 +273,6 @@ public class DeviceCheckInWorkerTest {
         assertThat(result).isEqualTo(Result.success());
         // THEN check in request was logged
         verify(mStatsLogger).logGetDeviceCheckInStatus();
-        verify(mStatsLogger).logSuccessfulCheckIn();
     }
 
     @Test
diff --git a/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/receivers/ResetDeviceReceiverTest.java b/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/receivers/ResetDeviceReceiverTest.java
index 6e1f3174..e68fd3cb 100644
--- a/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/receivers/ResetDeviceReceiverTest.java
+++ b/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/receivers/ResetDeviceReceiverTest.java
@@ -16,19 +16,17 @@
 
 package com.android.devicelockcontroller.receivers;
 
-import static com.android.devicelockcontroller.common.DeviceLockConstants.EXTRA_MANDATORY_PROVISION;
+import static com.android.devicelockcontroller.DevicelockStatsLog.DEVICE_LOCK_PROVISION_STATE_EVENT__EVENT__EVENT_DEVICE_RESET;
 
 import static org.mockito.Mockito.verify;
 
 import android.content.Intent;
-import android.os.Bundle;
 
 import androidx.test.core.app.ApplicationProvider;
 
 import com.android.devicelockcontroller.TestDeviceLockControllerApplication;
 import com.android.devicelockcontroller.stats.StatsLogger;
 import com.android.devicelockcontroller.stats.StatsLoggerProvider;
-import com.android.devicelockcontroller.storage.SetupParametersClient;
 
 import com.google.common.util.concurrent.testing.TestingExecutors;
 
@@ -37,20 +35,18 @@ import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.robolectric.RobolectricTestRunner;
 
-import java.util.concurrent.ExecutionException;
-
 @RunWith(RobolectricTestRunner.class)
 public class ResetDeviceReceiverTest {
-    private SetupParametersClient mSetupParameters;
     private Intent mIntent;
     private TestDeviceLockControllerApplication mTestApp;
     private ResetDeviceReceiver mReceiver;
     private StatsLogger mStatsLogger;
+    // Checkstyle results in line too long when using original constant.
+    private static final int RESET = DEVICE_LOCK_PROVISION_STATE_EVENT__EVENT__EVENT_DEVICE_RESET;
 
     @Before
     public void setUp() throws Exception {
         mTestApp = ApplicationProvider.getApplicationContext();
-        mSetupParameters = SetupParametersClient.getInstance();
         mIntent = new Intent(mTestApp, ResetDeviceReceiver.class);
         mReceiver = new ResetDeviceReceiver(TestingExecutors.sameThreadScheduledExecutor());
         StatsLoggerProvider loggerProvider =
@@ -59,26 +55,9 @@ public class ResetDeviceReceiverTest {
     }
 
     @Test
-    public void onReceive_shouldLogToStatsLoggerWhenCalled_whenProvisionIsMandatory()
-            throws ExecutionException, InterruptedException {
-        final Bundle bundle = new Bundle();
-        bundle.putBoolean(EXTRA_MANDATORY_PROVISION, true);
-        mSetupParameters.createPrefs(bundle).get();
-
-        mReceiver.onReceive(mTestApp, mIntent);
-
-        verify(mStatsLogger).logDeviceReset(/* isProvisionMandatory= */true);
-    }
-
-    @Test
-    public void onReceive_shouldLogToStatsLoggerWhenCalled_whenProvisionIsNotMandatory()
-            throws ExecutionException, InterruptedException {
-        final Bundle bundle = new Bundle();
-        bundle.putBoolean(EXTRA_MANDATORY_PROVISION, false);
-        mSetupParameters.createPrefs(bundle).get();
-
+    public void onReceive_shouldLogToStatsLogger() {
         mReceiver.onReceive(mTestApp, mIntent);
 
-        verify(mStatsLogger).logDeviceReset(/* isProvisionMandatory= */false);
+        verify(mStatsLogger).logProvisionStateEvent(RESET);
     }
 }
diff --git a/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/storage/GlobalParametersServiceTest.java b/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/storage/GlobalParametersServiceTest.java
index c824e466..fa8bd677 100644
--- a/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/storage/GlobalParametersServiceTest.java
+++ b/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/storage/GlobalParametersServiceTest.java
@@ -16,6 +16,8 @@
 
 package com.android.devicelockcontroller.storage;
 
+import static com.android.devicelockcontroller.policy.DevicePolicyController.LockTaskType.KIOSK_LOCK_ACTIVITY;
+
 import static com.google.common.truth.Truth.assertThat;
 
 import android.content.Intent;
@@ -48,8 +50,8 @@ public class GlobalParametersServiceTest extends AbstractGlobalParametersTestBas
 
         mIGlobalParametersService.setRegisteredDeviceId(REGISTERED_DEVICE_ID);
 
-        assertThat(mIGlobalParametersService.getRegisteredDeviceId()).isEqualTo(
-                REGISTERED_DEVICE_ID);
+        assertThat(mIGlobalParametersService.getRegisteredDeviceId())
+                .isEqualTo(REGISTERED_DEVICE_ID);
     }
 
     @Test
@@ -63,12 +65,21 @@ public class GlobalParametersServiceTest extends AbstractGlobalParametersTestBas
 
     @Test
     public void getLastReceivedProvisionState_shouldReturnExpectedResult() throws RemoteException {
-        assertThat(mIGlobalParametersService.getLastReceivedProvisionState()).isNotEqualTo(
-                LAST_RECEIVED_PROVISION_STATE);
+        assertThat(mIGlobalParametersService.getLastReceivedProvisionState())
+                .isNotEqualTo(LAST_RECEIVED_PROVISION_STATE);
 
         mIGlobalParametersService.setLastReceivedProvisionState(LAST_RECEIVED_PROVISION_STATE);
 
-        assertThat(mIGlobalParametersService.getLastReceivedProvisionState()).isEqualTo(
-                LAST_RECEIVED_PROVISION_STATE);
+        assertThat(mIGlobalParametersService.getLastReceivedProvisionState())
+                .isEqualTo(LAST_RECEIVED_PROVISION_STATE);
+    }
+
+    @Test
+    public void getLockTaskType_shouldReturnExpectedResult() throws RemoteException {
+        assertThat(mIGlobalParametersService.getLockTaskType()).isNotEqualTo(KIOSK_LOCK_ACTIVITY);
+
+        mIGlobalParametersService.setLockTaskType(KIOSK_LOCK_ACTIVITY);
+
+        assertThat(mIGlobalParametersService.getLockTaskType()).isEqualTo(KIOSK_LOCK_ACTIVITY);
     }
 }
diff --git a/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/storage/GlobalParametersTest.java b/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/storage/GlobalParametersTest.java
index a7b374b0..17de19ed 100644
--- a/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/storage/GlobalParametersTest.java
+++ b/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/storage/GlobalParametersTest.java
@@ -16,6 +16,7 @@
 
 package com.android.devicelockcontroller.storage;
 
+import static com.android.devicelockcontroller.policy.DevicePolicyController.LockTaskType.KIOSK_LOCK_ACTIVITY;
 import static com.android.devicelockcontroller.policy.FinalizationControllerImpl.FinalizationState.FINALIZED;
 
 import static com.google.common.truth.Truth.assertThat;
@@ -44,8 +45,8 @@ public final class GlobalParametersTest extends AbstractGlobalParametersTestBase
 
         GlobalParameters.setRegisteredDeviceId(mContext, REGISTERED_DEVICE_ID);
 
-        assertThat(GlobalParameters.getRegisteredDeviceId(mContext)).isEqualTo(
-                REGISTERED_DEVICE_ID);
+        assertThat(GlobalParameters.getRegisteredDeviceId(mContext))
+                .isEqualTo(REGISTERED_DEVICE_ID);
     }
 
     @Test
@@ -59,13 +60,13 @@ public final class GlobalParametersTest extends AbstractGlobalParametersTestBase
 
     @Test
     public void getLastReceivedProvisionState_shouldReturnExpectedResult() {
-        assertThat(GlobalParameters.getLastReceivedProvisionState(mContext)).isNotEqualTo(
-                LAST_RECEIVED_PROVISION_STATE);
+        assertThat(GlobalParameters.getLastReceivedProvisionState(mContext))
+                .isNotEqualTo(LAST_RECEIVED_PROVISION_STATE);
 
         GlobalParameters.setLastReceivedProvisionState(mContext, LAST_RECEIVED_PROVISION_STATE);
 
-        assertThat(GlobalParameters.getLastReceivedProvisionState(mContext)).isEqualTo(
-                LAST_RECEIVED_PROVISION_STATE);
+        assertThat(GlobalParameters.getLastReceivedProvisionState(mContext))
+                .isEqualTo(LAST_RECEIVED_PROVISION_STATE);
     }
 
     @Test
@@ -76,4 +77,13 @@ public final class GlobalParametersTest extends AbstractGlobalParametersTestBase
 
         assertThat(GlobalParameters.getFinalizationState(mContext)).isEqualTo(FINALIZED);
     }
+
+    @Test
+    public void getLockTaskType_shouldReturnExpectedResult() {
+        assertThat(GlobalParameters.getLockTaskType(mContext)).isNotEqualTo(KIOSK_LOCK_ACTIVITY);
+
+        GlobalParameters.setLockTaskType(mContext, KIOSK_LOCK_ACTIVITY);
+
+        assertThat(GlobalParameters.getLockTaskType(mContext)).isEqualTo(KIOSK_LOCK_ACTIVITY);
+    }
 }
diff --git a/flags/Android.bp b/flags/Android.bp
index ad63d9d3..c7ecedd2 100644
--- a/flags/Android.bp
+++ b/flags/Android.bp
@@ -50,5 +50,6 @@ java_aconfig_library {
     defaults: ["framework-minus-apex-aconfig-java-defaults"],
     visibility: [
         "//packages/modules/DeviceLock:__subpackages__",
+        "//frameworks/base:__subpackages__",
     ],
 }
diff --git a/flags/flags.aconfig b/flags/flags.aconfig
index 45b97f1b..9dc0c2e5 100644
--- a/flags/flags.aconfig
+++ b/flags/flags.aconfig
@@ -4,7 +4,39 @@ container: "com.android.devicelock"
 flag {
     name: "clear_device_restrictions"
     is_exported: true
-    namespace: "devicelock"
+    namespace: "growth_dlc"
     description: "Flag for API to clear device restrictions"
     bug: "349177010"
 }
+
+flag {
+    name: "extra_device_lock_version"
+    is_exported: true
+    namespace: "growth_dlc"
+    description: "Flag for API to expose the EXTRA_DEVICE_LOCK_VERSION string constant"
+    bug: "402302552"
+}
+
+flag {
+    name: "get_enrollment_type"
+    is_exported: true
+    namespace: "growth_dlc"
+    description: "Flag for API to get the enrollment type for a device"
+    bug: "402302549"
+}
+
+flag {
+    name: "notify_kiosk_setup_finished"
+    is_exported: true
+    namespace: "growth_dlc"
+    description: "Flag for API to notify the controller that the kiosk setup has finished"
+    bug: "402292744"
+}
+
+flag {
+    name: "device_id_type_serial"
+    is_exported: true
+    namespace: "growth_dlc"
+    description: "Flag for API to add the DEVICE_ID_TYPE_SERIAL to the Device ID types"
+    bug: "402292747"
+}
\ No newline at end of file
diff --git a/framework/Android.bp b/framework/Android.bp
index 646d97dd..5605affe 100644
--- a/framework/Android.bp
+++ b/framework/Android.bp
@@ -29,15 +29,6 @@ filegroup {
     ],
 }
 
-filegroup {
-    name: "framework-devicelock-sources-shared-with-tests",
-    srcs: ["java/**/DeviceId.java"],
-    path: "java",
-    visibility: [
-        "//packages/modules/DeviceLock:__subpackages__",
-    ],
-}
-
 java_sdk_library {
     name: "framework-devicelock",
     srcs: [":framework-devicelock-sources"],
diff --git a/framework/api/current.txt b/framework/api/current.txt
index 3ff70e34..37256ed1 100644
--- a/framework/api/current.txt
+++ b/framework/api/current.txt
@@ -6,6 +6,7 @@ package android.devicelock {
     method public int getType();
     field public static final int DEVICE_ID_TYPE_IMEI = 0; // 0x0
     field public static final int DEVICE_ID_TYPE_MEID = 1; // 0x1
+    field @FlaggedApi("com.android.devicelock.flags.device_id_type_serial") public static final int DEVICE_ID_TYPE_SERIAL_NUMBER = 2; // 0x2
   }
 
   public final class DeviceLockManager {
@@ -14,8 +15,10 @@ package android.devicelock {
     method public void getKioskApps(@NonNull java.util.concurrent.Executor, @NonNull android.os.OutcomeReceiver<java.util.Map<java.lang.Integer,java.lang.String>,java.lang.Exception>);
     method @RequiresPermission(android.Manifest.permission.MANAGE_DEVICE_LOCK_STATE) public void isDeviceLocked(@NonNull java.util.concurrent.Executor, @NonNull android.os.OutcomeReceiver<java.lang.Boolean,java.lang.Exception>);
     method @RequiresPermission(android.Manifest.permission.MANAGE_DEVICE_LOCK_STATE) public void lockDevice(@NonNull java.util.concurrent.Executor, @NonNull android.os.OutcomeReceiver<java.lang.Void,java.lang.Exception>);
+    method @FlaggedApi("com.android.devicelock.flags.notify_kiosk_setup_finished") @RequiresPermission(android.Manifest.permission.MANAGE_DEVICE_LOCK_STATE) public void notifyKioskSetupFinished(@NonNull java.util.concurrent.Executor, @NonNull android.os.OutcomeReceiver<java.lang.Void,java.lang.Exception>);
     method @RequiresPermission(android.Manifest.permission.MANAGE_DEVICE_LOCK_STATE) public void unlockDevice(@NonNull java.util.concurrent.Executor, @NonNull android.os.OutcomeReceiver<java.lang.Void,java.lang.Exception>);
     field public static final int DEVICE_LOCK_ROLE_FINANCING = 0; // 0x0
+    field @FlaggedApi("com.android.devicelock.flags.extra_device_lock_version") public static final String EXTRA_DEVICE_LOCK_VERSION = "android.devicelock.extra.DEVICE_LOCK_VERSION";
   }
 
 }
diff --git a/framework/api/system-current.txt b/framework/api/system-current.txt
index d802177e..5c46790c 100644
--- a/framework/api/system-current.txt
+++ b/framework/api/system-current.txt
@@ -1 +1,12 @@
 // Signature format: 2.0
+package android.devicelock {
+
+  public final class DeviceLockManager {
+    method @FlaggedApi("com.android.devicelock.flags.get_enrollment_type") @RequiresPermission(android.Manifest.permission.GET_DEVICE_LOCK_ENROLLMENT_TYPE) public void getEnrollmentType(@NonNull java.util.concurrent.Executor, @NonNull android.os.OutcomeReceiver<java.lang.Integer,java.lang.Exception>);
+    field @FlaggedApi("com.android.devicelock.flags.get_enrollment_type") public static final int ENROLLMENT_TYPE_FINANCE = 1; // 0x1
+    field @FlaggedApi("com.android.devicelock.flags.get_enrollment_type") public static final int ENROLLMENT_TYPE_NONE = 0; // 0x0
+    field @FlaggedApi("com.android.devicelock.flags.get_enrollment_type") public static final int ENROLLMENT_TYPE_SUBSIDY = 2; // 0x2
+  }
+
+}
+
diff --git a/framework/java/android/devicelock/DeviceId.java b/framework/java/android/devicelock/DeviceId.java
index f0404d0e..1910a976 100644
--- a/framework/java/android/devicelock/DeviceId.java
+++ b/framework/java/android/devicelock/DeviceId.java
@@ -16,6 +16,9 @@
 
 package android.devicelock;
 
+import static com.android.devicelock.flags.Flags.FLAG_DEVICE_ID_TYPE_SERIAL;
+
+import android.annotation.FlaggedApi;
 import android.annotation.IntDef;
 import android.annotation.NonNull;
 
@@ -24,8 +27,9 @@ import java.lang.annotation.RetentionPolicy;
 
 /**
  * The response returned from {@link DeviceLockManager#getDeviceId} on success.
- * A DeviceId represents a stable identifier (i.e. an identifier that is preserved after a factory
- * reset). At this moment, the only supported identifiers are IMEI and MEID.
+ * A DeviceId represents a stable identifier (i.e. an identifier that is
+ * preserved after a factory reset). At this moment, the only supported
+ * identifiers are IMEI, MEID and the Device Serial Number.
  */
 public final class DeviceId {
     /** @hide */
@@ -33,12 +37,16 @@ public final class DeviceId {
     @IntDef(prefix = "DEVICE_ID_TYPE_", value = {
         DEVICE_ID_TYPE_IMEI,
         DEVICE_ID_TYPE_MEID,
+        DEVICE_ID_TYPE_SERIAL_NUMBER,
     })
     public @interface DeviceIdType {}
     /** The device id is an IMEI */
     public static final int DEVICE_ID_TYPE_IMEI = 0;
     /** The device id is a MEID */
     public static final int DEVICE_ID_TYPE_MEID = 1;
+    /** The device id is a serial number */
+    @FlaggedApi(FLAG_DEVICE_ID_TYPE_SERIAL)
+    public static final int DEVICE_ID_TYPE_SERIAL_NUMBER = 2;
 
     private final @DeviceIdType int mType;
     private final String mId;
diff --git a/framework/java/android/devicelock/DeviceLockManager.java b/framework/java/android/devicelock/DeviceLockManager.java
index 46aa33fc..a5fd2abc 100644
--- a/framework/java/android/devicelock/DeviceLockManager.java
+++ b/framework/java/android/devicelock/DeviceLockManager.java
@@ -17,6 +17,9 @@
 package android.devicelock;
 
 import static com.android.devicelock.flags.Flags.FLAG_CLEAR_DEVICE_RESTRICTIONS;
+import static com.android.devicelock.flags.Flags.FLAG_EXTRA_DEVICE_LOCK_VERSION;
+import static com.android.devicelock.flags.Flags.FLAG_GET_ENROLLMENT_TYPE;
+import static com.android.devicelock.flags.Flags.FLAG_NOTIFY_KIOSK_SETUP_FINISHED;
 
 import android.Manifest.permission;
 import android.annotation.CallbackExecutor;
@@ -26,6 +29,7 @@ import android.annotation.NonNull;
 import android.annotation.RequiresFeature;
 import android.annotation.RequiresNoPermission;
 import android.annotation.RequiresPermission;
+import android.annotation.SystemApi;
 import android.annotation.SystemService;
 import android.content.Context;
 import android.content.pm.PackageManager;
@@ -33,8 +37,10 @@ import android.os.OutcomeReceiver;
 import android.os.RemoteException;
 import android.text.TextUtils;
 
+import java.lang.annotation.ElementType;
 import java.lang.annotation.Retention;
 import java.lang.annotation.RetentionPolicy;
+import java.lang.annotation.Target;
 import java.util.Map;
 import java.util.Objects;
 import java.util.concurrent.Executor;
@@ -71,6 +77,55 @@ public final class DeviceLockManager {
      */
     public static final int DEVICE_LOCK_ROLE_FINANCING = 0;
 
+    /**
+     * Extra passed to the kiosk setup activity containing the version of
+     * the Device Lock solution that started the activity.
+     *
+     * The kiosk setup activity can retrieve the version by calling
+     * getIntent().getIntExtra(DeviceLockManager.EXTRA_DEVICE_LOCK_VERSION, 1)
+     *
+     * This is meant to be used by kiosk apps sharing the same setup
+     * activity between the legacy Device Owner(DO) based DeviceLock
+     * solution (version 1) and successive versions.
+     */
+    @FlaggedApi(FLAG_EXTRA_DEVICE_LOCK_VERSION)
+    public static final String EXTRA_DEVICE_LOCK_VERSION =
+            "android.devicelock.extra.DEVICE_LOCK_VERSION";
+
+    /** @hide */
+    @Target(ElementType.TYPE_USE)
+    @Retention(RetentionPolicy.SOURCE)
+    @IntDef(prefix = "ENROLLMENT_TYPE_", value = {
+            ENROLLMENT_TYPE_NONE,
+            ENROLLMENT_TYPE_FINANCE,
+            ENROLLMENT_TYPE_SUBSIDY,
+    })
+    public @interface EnrollmentType {}
+
+    /**
+     * Device not enrolled in any program.
+     * @hide
+     */
+    @SystemApi
+    @FlaggedApi(FLAG_GET_ENROLLMENT_TYPE)
+    public static final int ENROLLMENT_TYPE_NONE = 0;
+
+    /**
+     * Device enrolled in the finance program.
+     * @hide
+     */
+    @SystemApi
+    @FlaggedApi(FLAG_GET_ENROLLMENT_TYPE)
+    public static final int ENROLLMENT_TYPE_FINANCE = 1;
+
+    /**
+     * Device enrolled in the subsidy program.
+     * @hide
+     */
+    @SystemApi
+    @FlaggedApi(FLAG_GET_ENROLLMENT_TYPE)
+    public static final int ENROLLMENT_TYPE_SUBSIDY = 2;
+
     /**
      * @hide
      */
@@ -91,10 +146,23 @@ public final class DeviceLockManager {
     }
 
     /**
-     * Lock the device.
+     * Locks the device.
+     *
+     * <p>Exceptions that can be returned through the ParcelableException on the callback's
+     * {@code onError} method:
+     * <ul>
+     *     <li>{@link SecurityException} if the caller is missing the
+     *     {@link android.android.Manifest.permission.MANAGE_DEVICE_LOCK_STATE} permission.
+     *     <li>{@link IllegalStateException} if the device has already been cleared or if
+     *     policies could not be enforced for the lock state.
+     *     <li>{@link java.util.concurrent.TimeoutException} if the response from the
+     *     underlying binder call is not received within the specified duration
+     *     (10 seconds).
+     * </ul>
      *
      * @param executor the {@link Executor} on which to invoke the callback.
      * @param callback this returns either success or an exception.
+     * @throws RuntimeException if there are binder communications errors
      */
     @RequiresPermission(permission.MANAGE_DEVICE_LOCK_STATE)
     public void lockDevice(@NonNull @CallbackExecutor Executor executor,
@@ -116,15 +184,28 @@ public final class DeviceLockManager {
                         }
                     });
         } catch (RemoteException e) {
-            executor.execute(() -> callback.onError(new RuntimeException(e)));
+            throw e.rethrowFromSystemServer();
         }
     }
 
     /**
-     * Unlock the device.
+     * Unlocks the device.
+     *
+     * <p>Exceptions that can be returned through the ParcelableException on the callback's
+     * {@code onError} method:
+     * <ul>
+     *     <li>{@link SecurityException} if the caller is missing the
+     *     {@link android.android.Manifest.permission.MANAGE_DEVICE_LOCK_STATE} permission.
+     *     <li>{@link IllegalStateException} if the device has already been cleared or if
+     *     policies could not be enforced for the unlock state.
+     *     <li>{@link java.util.concurrent.TimeoutException} If the response from the
+     *     underlying binder call is not received within the specified duration
+     *     (10 seconds).
+     * </ul>
      *
      * @param executor the {@link Executor} on which to invoke the callback.
      * @param callback this returns either success or an exception.
+     * @throws RuntimeException if there are binder communications errors
      */
     @RequiresPermission(permission.MANAGE_DEVICE_LOCK_STATE)
     public void unlockDevice(@NonNull @CallbackExecutor Executor executor,
@@ -146,15 +227,28 @@ public final class DeviceLockManager {
                         }
                     });
         } catch (RemoteException e) {
-            executor.execute(() -> callback.onError(new RuntimeException(e)));
+            throw e.rethrowFromSystemServer();
         }
     }
 
     /**
-     * Check if the device is locked or not.
+     * Checks if the device is locked or not.
+     *
+     * <p>Exceptions that can be returned through the ParcelableException on the callback's
+     * {@code onError} method:
+     * <ul>
+     *     <li>{@link SecurityException} if the caller is missing the
+     *     {@link android.android.Manifest.permission.MANAGE_DEVICE_LOCK_STATE} permission.
+     *     <li>{@link IllegalStateException} if called before setting the locked state of the device
+     *     through {@link #lockDevice} or {@link #unlockDevice}.
+     *     <li>{@link java.util.concurrent.TimeoutException} if the response from the
+     *     underlying binder call is not received within the specified duration
+     *     (10 seconds).
+     * </ul>
      *
      * @param executor the {@link Executor} on which to invoke the callback.
      * @param callback this returns either the lock status or an exception.
+     * @throws RuntimeException if there are binder communications errors
      */
     @RequiresPermission(permission.MANAGE_DEVICE_LOCK_STATE)
     public void isDeviceLocked(@NonNull @CallbackExecutor Executor executor,
@@ -177,7 +271,7 @@ public final class DeviceLockManager {
                         }
                     });
         } catch (RemoteException e) {
-            executor.execute(() -> callback.onError(new RuntimeException(e)));
+            throw e.rethrowFromSystemServer();
         }
     }
 
@@ -189,7 +283,7 @@ public final class DeviceLockManager {
      *
      * <p>At this point, the device is "restricted" and the creditor kiosk app is able to lock
      * the device. For example, a creditor kiosk app in a financing use case may lock the device
-     * (using {@link #lockDevice}) if payments are missed and unlock (using {@link #unlockDevice})
+     * (using {@link #lockDevice}) if payments are missed and unlock (using {@link #unlockDevice}))
      * once they are resumed.
      *
      * <p>The Device Lock solution will also put in place some additional restrictions when a device
@@ -211,8 +305,21 @@ public final class DeviceLockManager {
      *
      * <p>At this point, the kiosk app has relinquished its ability to lock the device.
      *
+     * <p>Exceptions that can be returned through the ParcelableException on the callback's
+     * {@code onError} method:
+     * <ul>
+     *     <li>{@link SecurityException} if the caller is missing the
+     *     {@link android.android.Manifest.permission.MANAGE_DEVICE_LOCK_STATE} permission.
+     *     <li>{@link IllegalStateException} if the device has already been cleared or if
+     *     policies could not be enforced for the clear state.
+     *     <li>{@link java.util.concurrent.TimeoutException} if the response from the
+     *     underlying binder call is not received within the specified duration
+     *     (10 seconds).
+     * </ul>
+     *
      * @param executor the {@link Executor} on which to invoke the callback.
      * @param callback this returns either success or an exception.
+     * @throws RuntimeException if there are binder communications errors
      */
     @RequiresPermission(permission.MANAGE_DEVICE_LOCK_STATE)
     @FlaggedApi(FLAG_CLEAR_DEVICE_RESTRICTIONS)
@@ -236,15 +343,27 @@ public final class DeviceLockManager {
                     }
             );
         } catch (RemoteException e) {
-            executor.execute(() -> callback.onError(new RuntimeException(e)));
+            throw e.rethrowFromSystemServer();
         }
     }
 
     /**
-     * Get the device id.
+     * Gets the device id.
+     *
+     * <p>Exceptions that can be returned through the ParcelableException on the callback's
+     * {@code onError} method:
+     * <ul>
+     *     <li>{@link SecurityException} if the caller is missing the
+     *     {@link android.android.Manifest.permission.MANAGE_DEVICE_LOCK_STATE} permission.
+     *     <li>{@link IllegalStateException} if no registered Device ID is found.
+     *     <li>{@link java.util.concurrent.TimeoutException} if the response from the
+     *     underlying binder call is not received within the specified duration
+     *     (10 seconds).
+     * </ul>
      *
      * @param executor the {@link Executor} on which to invoke the callback.
      * @param callback this returns either the {@link DeviceId} or an exception.
+     * @throws RuntimeException if there are binder communications errors
      */
     @RequiresPermission(permission.MANAGE_DEVICE_LOCK_STATE)
     public void getDeviceId(@NonNull @CallbackExecutor Executor executor,
@@ -275,7 +394,7 @@ public final class DeviceLockManager {
                     }
             );
         } catch (RemoteException e) {
-            executor.execute(() -> callback.onError(new RuntimeException(e)));
+            throw e.rethrowFromSystemServer();
         }
     }
 
@@ -286,8 +405,9 @@ public final class DeviceLockManager {
      * @param callback this returns either a {@link Map} of device roles/package names,
      *                 or an exception. The Integer in the map represent the device lock role
      *                 (at this moment, the only supported role is
-     *                 {@value #DEVICE_LOCK_ROLE_FINANCING}. The String represents tha package
+     *                 {@value #DEVICE_LOCK_ROLE_FINANCING}. The String represents the package
      *                 name of the kiosk app for that role.
+     * @throws RuntimeException if there are binder communications errors
      */
     @RequiresNoPermission
     public void getKioskApps(@NonNull @CallbackExecutor Executor executor,
@@ -310,7 +430,112 @@ public final class DeviceLockManager {
                     }
             );
         } catch (RemoteException e) {
-            executor.execute(() -> callback.onError(new RuntimeException(e)));
+            throw e.rethrowFromSystemServer();
+        }
+    }
+
+    /**
+     * Get the device lock solution enrollment type.
+     *
+     * <p>The enrollment type is returned asynchronously by the callback as an integer whose
+     * value can be one of {@link ENROLLMENT_TYPE_NONE}, {@link ENROLLMENT_TYPE_FINANCE},
+     * {@link ENROLLMENT_TYPE_SUBSIDY}.
+     *
+     * <p>Exceptions that can be returned through the ParcelableException on the callback's
+     * {@code onError} method:
+     * <ul>
+     *     <li>{@link SecurityException} if the caller is missing the
+     *     {@link android.android.Manifest.permission.GET_DEVICE_LOCK_ENROLLMENT_TYPE} permission.
+     *     <li>{@link java.util.concurrent.TimeoutException} if the response from the
+     *     underlying binder call is not received within the specified duration
+     *     (10 seconds).
+     * </ul>
+     *
+     * @param executor the {@link Executor} on which to invoke the callback.
+     * @param callback returns either the enrollment type or an exception.
+     * @throws RuntimeException if there are binder communications errors
+     *
+     * @hide
+     */
+    @SystemApi
+    @FlaggedApi(FLAG_GET_ENROLLMENT_TYPE)
+    @RequiresPermission(permission.GET_DEVICE_LOCK_ENROLLMENT_TYPE)
+    public void getEnrollmentType(
+            @NonNull @CallbackExecutor Executor executor,
+            @NonNull OutcomeReceiver<@EnrollmentType Integer, Exception> callback) {
+        Objects.requireNonNull(executor);
+        Objects.requireNonNull(callback);
+
+        try {
+            mService.getEnrollmentType(
+                    new IGetEnrollmentTypeCallback.Stub() {
+                        @Override
+                        public void onEnrollmentTypeReceived(@EnrollmentType int enrollmentType) {
+                            executor.execute(() -> callback.onResult(enrollmentType));
+                        }
+
+                        @Override
+                        public void onError(ParcelableException parcelableException) {
+                            callback.onError(parcelableException.getException());
+                        }
+                    }
+            );
+        } catch (RemoteException e) {
+            throw e.rethrowFromSystemServer();
+        }
+    }
+
+    /**
+     * Notifies DLC that kiosk set-up has finished and we no longer need to
+     * lock to the set-up activity.
+     *
+     * This will close the set-up activity as specified through a callback and
+     * then respect the current device lock state. If the device has never been
+     * locked or unlocked by the kiosk, it will unlock the device. Invoking
+     * {@link #lockDevice} or {@link #unlockDevice} will also result in the
+     * device provision state moving from kiosk_provisioned to
+     * provision_success.
+     *
+     * <p>Exceptions that can be returned through the ParcelableException on the callback's
+     * {@code onError} method:
+     * <ul>
+     *     <li>{@link SecurityException} if the caller is missing the
+     *     {@link android.android.Manifest.permission.MANAGE_DEVICE_LOCK_STATE} permission.
+     *     <li>{@link IllegalStateException} if the device has already been cleared or if
+     *     policies could not be enforced for the lock or unlock state.
+     *     <li>{@link java.util.concurrent.TimeoutException} if the response from the
+     *     underlying binder call is not received within the specified duration
+     *     (10 seconds).
+     * </ul>
+     *
+     * @param executor the {@link Executor} on which to invoke the callback.
+     * @param callback this returns either success or an exception.
+     * @throws RuntimeException if there are binder communications errors
+     */
+    @RequiresPermission(permission.MANAGE_DEVICE_LOCK_STATE)
+    @FlaggedApi(FLAG_NOTIFY_KIOSK_SETUP_FINISHED)
+    public void notifyKioskSetupFinished(
+            @NonNull @CallbackExecutor Executor executor,
+            @NonNull OutcomeReceiver<Void, Exception> callback){
+        Objects.requireNonNull(executor);
+        Objects.requireNonNull(callback);
+
+        try {
+            mService.notifyKioskSetupFinished(
+                    new IVoidResultCallback.Stub() {
+                        @Override
+                        public void onSuccess() {
+                            executor.execute(() -> callback.onResult(/* result= */ null));
+                        }
+
+                        @Override
+                        public void onError(ParcelableException parcelableException) {
+                            callback.onError(parcelableException.getException());
+                        }
+                    }
+            );
+        } catch (RemoteException e) {
+            throw e.rethrowFromSystemServer();
         }
     }
 }
diff --git a/framework/java/android/devicelock/IDeviceLockService.aidl b/framework/java/android/devicelock/IDeviceLockService.aidl
index 90fb272b..cc41dd15 100644
--- a/framework/java/android/devicelock/IDeviceLockService.aidl
+++ b/framework/java/android/devicelock/IDeviceLockService.aidl
@@ -18,6 +18,7 @@ package android.devicelock;
 
 import android.devicelock.IGetKioskAppsCallback;
 import android.devicelock.IGetDeviceIdCallback;
+import android.devicelock.IGetEnrollmentTypeCallback;
 import android.devicelock.IIsDeviceLockedCallback;
 import android.devicelock.IVoidResultCallback;
 
@@ -48,11 +49,21 @@ oneway interface IDeviceLockService {
      */
     void clearDeviceRestrictions(in IVoidResultCallback callback);
 
+    /**
+     * Asynchronously notify DLC that kiosk set-up has finished.
+     */
+    void notifyKioskSetupFinished(in IVoidResultCallback callback);
+
     /**
      * Asynchronously retrieve the device identifier.
      */
     void getDeviceId(in IGetDeviceIdCallback callback);
 
+    /**
+     * Asynchronously retrieve the enrollment type.
+     */
+    void getEnrollmentType(in IGetEnrollmentTypeCallback callback);
+
     /**
      * Constant corresponding to a financed device role.
      * Returned by {@link #getKioskApps}.
diff --git a/framework/java/android/devicelock/IGetEnrollmentTypeCallback.aidl b/framework/java/android/devicelock/IGetEnrollmentTypeCallback.aidl
new file mode 100644
index 00000000..d7813968
--- /dev/null
+++ b/framework/java/android/devicelock/IGetEnrollmentTypeCallback.aidl
@@ -0,0 +1,29 @@
+/*
+ * Copyright (C) 2022 The Android Open Source Project
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
+package android.devicelock;
+
+import android.devicelock.ParcelableException;
+
+/**
+  * Callback interface for getEnrollmentType() request.
+  * {@hide}
+  */
+oneway interface IGetEnrollmentTypeCallback {
+    void onEnrollmentTypeReceived(in int enrollmentType);
+
+    void onError(in ParcelableException exception);
+}
diff --git a/service/java/com/android/server/devicelock/DeviceLockControllerConnector.java b/service/java/com/android/server/devicelock/DeviceLockControllerConnector.java
index 8de87fe1..9fc978ff 100644
--- a/service/java/com/android/server/devicelock/DeviceLockControllerConnector.java
+++ b/service/java/com/android/server/devicelock/DeviceLockControllerConnector.java
@@ -48,11 +48,21 @@ public interface DeviceLockControllerConnector {
      */
     void getDeviceId(OutcomeReceiver<String, Exception> callback);
 
+    /**
+     * Gets the enrollment type.
+     */
+    void getEnrollmentType(OutcomeReceiver<Integer, Exception> callback);
+
     /**
      * Clears the device restrictions
      */
     void clearDeviceRestrictions(OutcomeReceiver<Void, Exception> callback);
 
+    /**
+     * Notifies the controller that kiosk set-up has finished.
+     */
+    void notifyKioskSetupFinished(OutcomeReceiver<Void, Exception> callback);
+
     /**
      * Called when the user has switched.
      */
diff --git a/service/java/com/android/server/devicelock/DeviceLockControllerConnectorImpl.java b/service/java/com/android/server/devicelock/DeviceLockControllerConnectorImpl.java
index 4e7dfe60..944f2706 100644
--- a/service/java/com/android/server/devicelock/DeviceLockControllerConnectorImpl.java
+++ b/service/java/com/android/server/devicelock/DeviceLockControllerConnectorImpl.java
@@ -16,6 +16,8 @@
 
 package com.android.server.devicelock;
 
+import static android.devicelock.DeviceLockManager.EnrollmentType;
+
 import android.annotation.NonNull;
 import android.annotation.Nullable;
 import android.content.ComponentName;
@@ -355,6 +357,26 @@ final class DeviceLockControllerConnectorImpl implements DeviceLockControllerCon
         }, callback);
     }
 
+    @Override
+    public void notifyKioskSetupFinished(OutcomeReceiver<Void, Exception> callback) {
+        RemoteCallback remoteCallback = new RemoteCallback(checkTimeout(callback, result -> {
+            if (maybeReportException(callback, result)) {
+                return;
+            }
+
+            mHandler.post(() -> callback.onResult(null));
+        }));
+
+        callControllerApi(new Callable<Void>() {
+            @Override
+            @SuppressWarnings("GuardedBy") // mLock already held in callControllerApi (error prone).
+            public Void call() throws Exception {
+                mDeviceLockControllerService.notifyKioskSetupFinished(remoteCallback);
+                return null;
+            }
+        }, callback);
+    }
+
     @Override
     public void getDeviceId(OutcomeReceiver<String, Exception> callback) {
         RemoteCallback remoteCallback = new RemoteCallback(checkTimeout(callback, result -> {
@@ -402,6 +424,27 @@ final class DeviceLockControllerConnectorImpl implements DeviceLockControllerCon
         }, callback);
     }
 
+    @Override
+    public void getEnrollmentType(OutcomeReceiver<@EnrollmentType Integer, Exception> callback) {
+        RemoteCallback remoteCallback = new RemoteCallback(checkTimeout(callback, result -> {
+            if (maybeReportException(callback, result)) {
+                return;
+            }
+            final int enrollmentType =
+                    result.getInt(IDeviceLockControllerService.KEY_RESULT);
+            mHandler.post(() -> callback.onResult(enrollmentType));
+        }));
+
+        callControllerApi(new Callable<Void>() {
+            @Override
+            @SuppressWarnings("GuardedBy") // mLock already held in callControllerApi (error prone).
+            public Void call() throws Exception {
+                mDeviceLockControllerService.getEnrollmentType(remoteCallback);
+                return null;
+            }
+        }, callback);
+    }
+
     @Override
     public void onUserSwitching(OutcomeReceiver<Void, Exception> callback) {
         RemoteCallback remoteCallback = new RemoteCallback(checkTimeout(callback, result -> {
diff --git a/service/java/com/android/server/devicelock/DeviceLockControllerConnectorStub.java b/service/java/com/android/server/devicelock/DeviceLockControllerConnectorStub.java
index 3e5d618b..ae8a30e0 100644
--- a/service/java/com/android/server/devicelock/DeviceLockControllerConnectorStub.java
+++ b/service/java/com/android/server/devicelock/DeviceLockControllerConnectorStub.java
@@ -16,7 +16,10 @@
 
 package com.android.server.devicelock;
 
+import static android.devicelock.DeviceLockManager.ENROLLMENT_TYPE_NONE;
+
 import android.annotation.IntDef;
+import android.devicelock.DeviceLockManager.EnrollmentType;
 import android.os.OutcomeReceiver;
 
 import com.android.devicelock.flags.Flags;
@@ -116,6 +119,29 @@ public class DeviceLockControllerConnectorStub implements DeviceLockControllerCo
         callback.onResult(/* result= */ null);
     }
 
+    @Override
+    public void notifyKioskSetupFinished(OutcomeReceiver<Void, Exception> callback) {
+        synchronized (this) {
+            if (setExceptionIfDeviceIsCleared(callback)) {
+                return;
+            }
+            // If the device is in undefined state, we assume that the device is unlocked.
+            if (mPseudoState == DevicePseudoState.UNDEFINED) {
+                mPseudoState = DevicePseudoState.UNLOCKED;
+            }
+
+            // If the device is locked/unlocked already, we maintain the state as is and enforce
+            // the necessary policies.
+        }
+
+        callback.onResult(/* result= */ null);
+    }
+
+    @Override
+    public void getEnrollmentType(OutcomeReceiver<@EnrollmentType Integer, Exception> callback) {
+        callback.onResult(ENROLLMENT_TYPE_NONE);
+    }
+
     @Override
     public void onUserSwitching(OutcomeReceiver<Void, Exception> callback) {
         // Do not throw exception as we expect this to be called
diff --git a/service/java/com/android/server/devicelock/DeviceLockServiceImpl.java b/service/java/com/android/server/devicelock/DeviceLockServiceImpl.java
index 309e090f..94fbdcc1 100644
--- a/service/java/com/android/server/devicelock/DeviceLockServiceImpl.java
+++ b/service/java/com/android/server/devicelock/DeviceLockServiceImpl.java
@@ -26,6 +26,7 @@ import static android.content.pm.PackageManager.DONT_KILL_APP;
 import static android.content.pm.PackageManager.PERMISSION_GRANTED;
 import static android.devicelock.DeviceId.DEVICE_ID_TYPE_IMEI;
 import static android.devicelock.DeviceId.DEVICE_ID_TYPE_MEID;
+import static android.devicelock.DeviceId.DEVICE_ID_TYPE_SERIAL_NUMBER;
 import static android.provider.Settings.Secure.USER_SETUP_COMPLETE;
 
 import android.Manifest;
@@ -47,8 +48,10 @@ import android.content.pm.ServiceInfo;
 import android.database.ContentObserver;
 import android.devicelock.DeviceId.DeviceIdType;
 import android.devicelock.DeviceLockManager;
+import android.devicelock.DeviceLockManager.EnrollmentType;
 import android.devicelock.IDeviceLockService;
 import android.devicelock.IGetDeviceIdCallback;
+import android.devicelock.IGetEnrollmentTypeCallback;
 import android.devicelock.IGetKioskAppsCallback;
 import android.devicelock.IIsDeviceLockedCallback;
 import android.devicelock.IVoidResultCallback;
@@ -56,6 +59,7 @@ import android.devicelock.ParcelableException;
 import android.net.NetworkPolicyManager;
 import android.net.Uri;
 import android.os.Binder;
+import android.os.Build;
 import android.os.Bundle;
 import android.os.Environment;
 import android.os.IBinder;
@@ -181,7 +185,7 @@ final class DeviceLockServiceImpl extends IDeviceLockService.Stub {
     }
 
     // Last supported device id type
-    private static final @DeviceIdType int LAST_DEVICE_ID_TYPE = DEVICE_ID_TYPE_MEID;
+    private static final @DeviceIdType int LAST_DEVICE_ID_TYPE = DEVICE_ID_TYPE_SERIAL_NUMBER;
 
     @VisibleForTesting
     static final String MANAGE_DEVICE_LOCK_SERVICE_FROM_CONTROLLER =
@@ -598,6 +602,43 @@ final class DeviceLockServiceImpl extends IDeviceLockService.Stub {
         });
     }
 
+    @Override
+    public void notifyKioskSetupFinished(@NonNull IVoidResultCallback callback) {
+        if (!checkCallerPermission()) {
+            try {
+                callback.onError(new ParcelableException(new SecurityException()));
+            } catch (RemoteException e) {
+                Slog.e(TAG, "notifyKioskSetupFinished() - Unable to send error to the callback", e);
+            }
+            return;
+        }
+
+        // Check the device status and call lock or unlock accordingly.
+        getDeviceLockControllerConnector().notifyKioskSetupFinished(new OutcomeReceiver<>() {
+            @Override
+            public void onResult(Void ignored) {
+                Slog.i(TAG, "Kiosk setup finished");
+                try {
+                    callback.onSuccess();
+                } catch (RemoteException e) {
+                    Slog.e(TAG, "notifyKioskSetupFinished() - Unable to send result to the "
+                            + "callback", e);
+                }
+            }
+
+            @Override
+            public void onError(Exception ex) {
+                Slog.e(TAG, "notifyKioskSetupFinished exception: ", ex);
+                try {
+                    callback.onError(getParcelableException(ex));
+                } catch (RemoteException e) {
+                    Slog.e(TAG, "notifyKioskSetupFinished() - Unable to send error to the "
+                            + "callback", e);
+                }
+            }
+        });
+    }
+
     private boolean hasCdma() {
         return mContext.getPackageManager().hasSystemFeature(
                 PackageManager.FEATURE_TELEPHONY_CDMA);
@@ -637,6 +678,13 @@ final class DeviceLockServiceImpl extends IDeviceLockService.Stub {
             }
         }
 
+        final StringBuilder deviceSerialNumber = new StringBuilder();
+        if((deviceIdTypeBitmap & (1 << DEVICE_ID_TYPE_SERIAL_NUMBER)) != 0){
+            if(Build.getSerial() != Build.UNKNOWN){
+                deviceSerialNumber.append(Build.getSerial());
+            }
+        }
+
         getDeviceLockControllerConnector().getDeviceId(new OutcomeReceiver<>() {
             @Override
             public void onResult(String deviceId) {
@@ -650,6 +698,12 @@ final class DeviceLockServiceImpl extends IDeviceLockService.Stub {
                         callback.onDeviceIdReceived(DEVICE_ID_TYPE_IMEI, deviceId);
                         return;
                     }
+                    if(!deviceSerialNumber.isEmpty() &&
+                            deviceId.equals(deviceSerialNumber.toString())){
+                        callback.onDeviceIdReceived(DEVICE_ID_TYPE_SERIAL_NUMBER,
+                                deviceId.toString());
+                        return;
+                    }
                     // When a device ID is returned from DLC App, but none of the IDs got from
                     // TelephonyManager matches that device ID.
                     //
@@ -724,6 +778,41 @@ final class DeviceLockServiceImpl extends IDeviceLockService.Stub {
         }
     }
 
+    @Override
+    public void getEnrollmentType(@NonNull IGetEnrollmentTypeCallback callback){
+        if (mContext.checkCallingOrSelfPermission(
+                Manifest.permission.GET_DEVICE_LOCK_ENROLLMENT_TYPE) != PERMISSION_GRANTED) {
+            try {
+                callback.onError(new ParcelableException(new SecurityException()));
+            } catch (RemoteException e) {
+                Slog.e(TAG, "getEnrollmentType() - Unable to send error to the callback", e);
+            }
+            return;
+        }
+
+        getDeviceLockControllerConnector().getEnrollmentType(new OutcomeReceiver<>() {
+            @Override
+            public void onResult(@EnrollmentType Integer enrollmentType) {
+                Slog.i(TAG, "Get enrollment type: " + enrollmentType);
+                try {
+                    callback.onEnrollmentTypeReceived(enrollmentType);
+                } catch (RemoteException e) {
+                    Slog.e(TAG, "getEnrollmentType() - Unable to send result to the callback", e);
+                }
+            }
+
+            @Override
+            public void onError(Exception ex) {
+                Slog.e(TAG, "getEnrollmentType exception: ", ex);
+                try {
+                    callback.onError(getParcelableException(ex));
+                } catch (RemoteException e) {
+                    Slog.e(TAG, "getEnrollmentType() - Unable to send error to the callback", e);
+                }
+            }
+        });
+    }
+
     // For calls from Controller to System Service.
 
     private void reportErrorToCaller(@NonNull RemoteCallback remoteCallback) {
diff --git a/tests/cts/Android.bp b/tests/cts/Android.bp
index 9892101f..f2b87a72 100644
--- a/tests/cts/Android.bp
+++ b/tests/cts/Android.bp
@@ -23,18 +23,19 @@ android_test {
     defaults: ["cts_defaults"],
     srcs: [
         "src/**/*.java",
-        ":framework-devicelock-sources-shared-with-tests",
     ],
+    libs: ["framework-annotations-lib"],
     static_libs: [
         "androidx.test.rules",
         "truth",
         "androidx.test.core",
         "compatibility-device-util-axt",
-        "devicelock-exported-aconfig-flags-lib",
+        "devicelock-aconfig-flags-lib",
     ],
     test_suites: [
         "general-tests",
         "cts",
     ],
-    platform_apis: true,
+
+    sdk_version: "test_current",
 }
diff --git a/tests/cts/src/com/android/cts/devicelock/DeviceLockManagerTest.java b/tests/cts/src/com/android/cts/devicelock/DeviceLockManagerTest.java
index f3c12b71..6d808b47 100644
--- a/tests/cts/src/com/android/cts/devicelock/DeviceLockManagerTest.java
+++ b/tests/cts/src/com/android/cts/devicelock/DeviceLockManagerTest.java
@@ -20,7 +20,10 @@ import static com.google.common.truth.Truth.assertThat;
 
 import static org.junit.Assert.assertThrows;
 
+import android.Manifest.permission;
+import android.app.UiAutomation;
 import android.content.Context;
+import android.content.Intent;
 import android.devicelock.DeviceId;
 import android.devicelock.DeviceLockManager;
 import android.os.Build;
@@ -209,6 +212,46 @@ public final class DeviceLockManagerTest {
                 });
     }
 
+    private ListenableFuture<Void> getNotifyKioskSetupFinishedFuture() {
+        return CallbackToFutureAdapter.getFuture(
+                completer -> {
+                    mDeviceLockManager.notifyKioskSetupFinished(mExecutorService,
+                            new OutcomeReceiver<>() {
+                                @Override
+                                public void onResult(Void result) {
+                                    completer.set(null);
+                                }
+
+                                @Override
+                                public void onError(Exception error) {
+                                    completer.setException(error);
+                                }
+                            });
+                    // Used only for debugging.
+                    return "notifyKioskSetupFinished operation";
+                });
+    }
+
+    private ListenableFuture</* EnrollmentType */ Integer> getEnrollmentTypeFuture() {
+        return CallbackToFutureAdapter.getFuture(
+                completer -> {
+                    mDeviceLockManager.getEnrollmentType(mExecutorService,
+                            new OutcomeReceiver<>() {
+                                @Override
+                                public void onResult(/* EnrollmentType */ Integer enrollmentType) {
+                                    completer.set(enrollmentType);
+                                }
+
+                                @Override
+                                public void onError(Exception error) {
+                                    completer.setException(error);
+                                }
+                            });
+                    // Used only for debugging.
+                    return "getEnrollmentType operation";
+                });
+    }
+
     @Test
     @ApiTest(apis = {"android.devicelock.DeviceLockManager#lockDevice"})
     public void lockDevicePermissionCheck() {
@@ -275,6 +318,35 @@ public final class DeviceLockManagerTest {
                 .isInstanceOf(SecurityException.class);
     }
 
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_NOTIFY_KIOSK_SETUP_FINISHED)
+    @ApiTest(apis = {"android.devicelock.DeviceLockManager#notifyKioskSetupFinished"})
+    public void notifyKioskSetupFinishedCheck(){
+        ListenableFuture<Void> notifyKioskSetupFinishedFuture = getNotifyKioskSetupFinishedFuture();
+
+        Exception notifyKioskSetupFinishedException =
+                assertThrows(
+                        ExecutionException.class,
+                        () -> notifyKioskSetupFinishedFuture.get(TIMEOUT, TimeUnit.SECONDS));
+        assertThat(notifyKioskSetupFinishedException).hasCauseThat()
+                .isInstanceOf(SecurityException.class);
+    }
+
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_GET_ENROLLMENT_TYPE)
+    @ApiTest(apis = {"android.devicelock.DeviceLockManager#getEnrollmentType"})
+    public void getEnrollmentTypePermissionCheck() {
+        ListenableFuture</* EnrollmentType */ Integer> getEnrollmentTypeFuture =
+                getEnrollmentTypeFuture();
+
+        Exception getEnrollmentTypeResponseException =
+                assertThrows(
+                        ExecutionException.class,
+                        () -> getEnrollmentTypeFuture.get(TIMEOUT, TimeUnit.SECONDS));
+        assertThat(getEnrollmentTypeResponseException).hasCauseThat()
+                .isInstanceOf(SecurityException.class);
+    }
+
     @Test
     @ApiTest(
             apis = {
@@ -361,4 +433,109 @@ public final class DeviceLockManagerTest {
             removeFinancedDeviceKioskRole();
         }
     }
+
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_EXTRA_DEVICE_LOCK_VERSION)
+    @ApiTest(apis = {"android.devicelock.DeviceLockManager#EXTRA_DEVICE_LOCK_VERSION"})
+    public void extraDeviceLockVersionShouldHaveValidValue() {
+        assertThat(DeviceLockManager.EXTRA_DEVICE_LOCK_VERSION)
+                .isEqualTo("android.devicelock.extra.DEVICE_LOCK_VERSION");
+
+        final Intent intent = new Intent();
+        intent.putExtra(DeviceLockManager.EXTRA_DEVICE_LOCK_VERSION, 1);
+        assertThat(intent.hasExtra(DeviceLockManager.EXTRA_DEVICE_LOCK_VERSION)).isTrue();
+        assertThat(intent.getIntExtra(DeviceLockManager.EXTRA_DEVICE_LOCK_VERSION, 0)).isEqualTo(1);
+    }
+
+
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_NOTIFY_KIOSK_SETUP_FINISHED)
+    @ApiTest(
+            apis = {
+                    "andriod.devicelock.DeviceLockManager#notifyKioskSetupFinished",
+                    "android.devicelock.DeviceLockManager#isDeviceLocked"
+            })
+    public void notifyKioskSetupFinishedShouldSucceed_whenDeviceStateIsUndefined()
+            throws ExecutionException, InterruptedException, TimeoutException {
+        try {
+            // Device state is currently undefined as device is not locked/unlocked.
+
+            addFinancedDeviceKioskRole();
+
+            getNotifyKioskSetupFinishedFuture().get(TIMEOUT, TimeUnit.SECONDS);
+
+            boolean locked = getIsDeviceLockedFuture().get(TIMEOUT, TimeUnit.SECONDS);
+            assertThat(locked).isFalse();
+        } finally {
+            removeFinancedDeviceKioskRole();
+        }
+    }
+
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_NOTIFY_KIOSK_SETUP_FINISHED)
+    @ApiTest(
+            apis = {
+                    "andriod.devicelock.DeviceLockManager#notifyKioskSetupFinished",
+                    "android.devicelock.DeviceLockManager#isDeviceLocked"
+            })
+    public void notifyKioskSetupFinishedShouldSucceed_whenDeviceStateIsLocked()
+            throws ExecutionException, InterruptedException, TimeoutException {
+        try {
+            // Device state is currently undefined as device is not locked/unlocked.
+
+            addFinancedDeviceKioskRole();
+
+            getLockDeviceFuture().get(TIMEOUT, TimeUnit.SECONDS);
+
+            getNotifyKioskSetupFinishedFuture().get(TIMEOUT, TimeUnit.SECONDS);
+
+            boolean locked = getIsDeviceLockedFuture().get(TIMEOUT, TimeUnit.SECONDS);
+            assertThat(locked).isTrue();
+        } finally {
+            removeFinancedDeviceKioskRole();
+        }
+    }
+
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_NOTIFY_KIOSK_SETUP_FINISHED)
+    @ApiTest(
+            apis = {
+                    "andriod.devicelock.DeviceLockManager#notifyKioskSetupFinished",
+                    "android.devicelock.DeviceLockManager#isDeviceLocked"
+            })
+    public void notifyKioskSetupFinishedShouldSucceed_whenDeviceStateIsUnlocked()
+            throws ExecutionException, InterruptedException, TimeoutException {
+        try {
+            // Device state is currently undefined as device is not locked/unlocked.
+
+            addFinancedDeviceKioskRole();
+
+            getUnlockDeviceFuture().get(TIMEOUT, TimeUnit.SECONDS);
+
+            getNotifyKioskSetupFinishedFuture().get(TIMEOUT, TimeUnit.SECONDS);
+
+            boolean locked = getIsDeviceLockedFuture().get(TIMEOUT, TimeUnit.SECONDS);
+            assertThat(locked).isFalse();
+        } finally {
+            removeFinancedDeviceKioskRole();
+        }
+    }
+
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_GET_ENROLLMENT_TYPE)
+    @ApiTest(apis = {"android.devicelock.DeviceLockManager#getEnrollmentType"})
+    public void getEnrollmentTypeShouldReturnNone()
+            throws ExecutionException, InterruptedException, TimeoutException {
+        UiAutomation uiAutomation =
+                InstrumentationRegistry.getInstrumentation().getUiAutomation();
+        try {
+            uiAutomation.adoptShellPermissionIdentity(permission.GET_DEVICE_LOCK_ENROLLMENT_TYPE);
+            /* EnrollmentType */
+            Integer enrollmentType =
+                    getEnrollmentTypeFuture().get(TIMEOUT, TimeUnit.SECONDS);
+            assertThat(enrollmentType).isEqualTo(DeviceLockManager.ENROLLMENT_TYPE_NONE);
+        } finally {
+            uiAutomation.dropShellPermissionIdentity();
+        }
+    }
 }
diff --git a/tests/unittests/src/com/android/server/devicelock/DeviceLockControllerConnectorStubTest.java b/tests/unittests/src/com/android/server/devicelock/DeviceLockControllerConnectorStubTest.java
index 402f8152..dd9a36af 100644
--- a/tests/unittests/src/com/android/server/devicelock/DeviceLockControllerConnectorStubTest.java
+++ b/tests/unittests/src/com/android/server/devicelock/DeviceLockControllerConnectorStubTest.java
@@ -16,10 +16,13 @@
 
 package com.android.server.devicelock;
 
+import static android.devicelock.DeviceLockManager.ENROLLMENT_TYPE_NONE;
+
 import static com.google.common.truth.Truth.assertThat;
 
 import static org.junit.Assert.assertThrows;
 
+import android.devicelock.DeviceLockManager.EnrollmentType;
 import android.os.OutcomeReceiver;
 import android.platform.test.annotations.DisableFlags;
 import android.platform.test.flag.junit.SetFlagsRule;
@@ -182,6 +185,47 @@ public final class DeviceLockControllerConnectorStubTest {
         assertThat(thrown).hasCauseThat().isInstanceOf(IllegalStateException.class);
     }
 
+    @Test
+    public void notifyKioskSetupFinished_withLockedState_shouldLockDevice()
+            throws ExecutionException, InterruptedException, TimeoutException {
+        // Given the device state is LOCKED
+        lockDeviceAsync().get(TIMEOUT_SEC, TimeUnit.SECONDS);
+
+        // Notifying kiosk setup finished succeeds
+        notifyKioskSetupFinishedAsync().get(TIMEOUT_SEC, TimeUnit.SECONDS);
+    }
+
+    @Test
+    public void notifyKioskSetupFinished_withUnlockedState_shouldUnlockDevice()
+            throws ExecutionException, InterruptedException, TimeoutException {
+        // Given the device state is UNLOCKED
+        unlockDeviceAsync().get(TIMEOUT_SEC, TimeUnit.SECONDS);
+
+        // Notifying kiosk setup finished succeeds
+        notifyKioskSetupFinishedAsync().get(TIMEOUT_SEC, TimeUnit.SECONDS);
+    }
+
+    @Test
+    public void notifyKioskSetupFinished_withUndefinedState_shouldUnlockDevice()
+            throws ExecutionException, InterruptedException, TimeoutException {
+        // Given the device state is UNDEFINED
+
+        // Notifying kiosk setup finished succeeds
+        notifyKioskSetupFinishedAsync().get(TIMEOUT_SEC, TimeUnit.SECONDS);
+    }
+
+    @Test
+    public void notifyKioskSetupFinished_withClearedState_shouldThrowException()
+            throws ExecutionException, InterruptedException, TimeoutException {
+        // Given the device state is CLEARED
+        clearDeviceRestrictionsAsync().get(TIMEOUT_SEC, TimeUnit.SECONDS);
+
+        // Notifying kiosk setup finished fails
+        ExecutionException thrown = assertThrows(ExecutionException.class,
+                () -> notifyKioskSetupFinishedAsync().get(TIMEOUT_SEC, TimeUnit.SECONDS));
+        assertThat(thrown).hasCauseThat().isInstanceOf(IllegalStateException.class);
+    }
+
     @Test
     public void isDeviceLocked_withUndefinedState_shouldThrownException() {
         // Given the device state is UNDEFINED
@@ -225,6 +269,14 @@ public final class DeviceLockControllerConnectorStubTest {
         assertThat(thrown).hasCauseThat().isInstanceOf(IllegalStateException.class);
     }
 
+    @Test
+    public void getEnrollmentType_shouldReturnEnrollmentTypeNone()
+            throws ExecutionException, InterruptedException, TimeoutException {
+        // The stub should always return "none" as enrollment type.
+        assertThat(getEnrollmentTypeAsync().get(TIMEOUT_SEC, TimeUnit.SECONDS)).isEqualTo(
+                ENROLLMENT_TYPE_NONE);
+    }
+
     private ListenableFuture<Void> lockDeviceAsync() {
         return CallbackToFutureAdapter.getFuture(
                 completer -> {
@@ -305,4 +357,44 @@ public final class DeviceLockControllerConnectorStubTest {
                 });
     }
 
+    private ListenableFuture<Void> notifyKioskSetupFinishedAsync(){
+        return CallbackToFutureAdapter.getFuture(
+                completer -> {
+                    mDeviceLockControllerConnectorStub.notifyKioskSetupFinished(
+                            new OutcomeReceiver<>() {
+                                @Override
+                                public void onResult(Void result) {
+                                    completer.set(null);
+                                }
+
+                                @Override
+                                public void onError(Exception error) {
+                                    completer.setException(error);
+                                }
+                            });
+                    // Used only for debugging.
+                    return "notifyKioskSetupFinished operation";
+                }
+        );
+    }
+    private ListenableFuture<Integer> getEnrollmentTypeAsync() {
+        return CallbackToFutureAdapter.getFuture(
+                completer -> {
+                    mDeviceLockControllerConnectorStub.getEnrollmentType(
+                            new OutcomeReceiver<>() {
+                                @Override
+                                public void onResult(@EnrollmentType Integer enrollmentType) {
+                                    completer.set(enrollmentType);
+                                }
+
+                                @Override
+                                public void onError(Exception error) {
+                                    completer.setException(error);
+                                }
+                            });
+                    // Used only for debugging.
+                    return "getEnrollmentType operation";
+                });
+    }
+
 }
diff --git a/tests/unittests/src/com/android/server/devicelock/DeviceLockServiceImplTest.java b/tests/unittests/src/com/android/server/devicelock/DeviceLockServiceImplTest.java
index 72f7a085..9bc1833f 100644
--- a/tests/unittests/src/com/android/server/devicelock/DeviceLockServiceImplTest.java
+++ b/tests/unittests/src/com/android/server/devicelock/DeviceLockServiceImplTest.java
@@ -16,11 +16,13 @@
 
 package com.android.server.devicelock;
 
+import static android.Manifest.permission.GET_DEVICE_LOCK_ENROLLMENT_TYPE;
 import static android.app.AppOpsManager.OPSTR_SYSTEM_EXEMPT_FROM_HIBERNATION;
 import static android.content.pm.PackageManager.COMPONENT_ENABLED_STATE_DEFAULT;
 import static android.content.pm.PackageManager.COMPONENT_ENABLED_STATE_DISABLED;
 import static android.devicelock.DeviceId.DEVICE_ID_TYPE_IMEI;
 import static android.devicelock.DeviceId.DEVICE_ID_TYPE_MEID;
+import static android.devicelock.DeviceId.DEVICE_ID_TYPE_SERIAL_NUMBER;
 import static android.devicelock.IDeviceLockService.KEY_REMOTE_CALLBACK_RESULT;
 import static android.os.UserHandle.USER_SYSTEM;
 
@@ -52,7 +54,10 @@ import android.content.pm.PackageInfo;
 import android.content.pm.PackageManager;
 import android.content.pm.ResolveInfo;
 import android.content.pm.ServiceInfo;
+import android.devicelock.DeviceLockManager;
 import android.devicelock.IGetDeviceIdCallback;
+import android.devicelock.IGetEnrollmentTypeCallback;
+import android.devicelock.ParcelableException;
 import android.os.Binder;
 import android.os.Bundle;
 import android.os.Looper;
@@ -71,6 +76,8 @@ import org.junit.Before;
 import org.junit.Rule;
 import org.junit.Test;
 import org.junit.runner.RunWith;
+import org.mockito.ArgumentCaptor;
+import org.mockito.Captor;
 import org.mockito.Mock;
 import org.mockito.junit.MockitoJUnit;
 import org.mockito.junit.MockitoRule;
@@ -79,6 +86,7 @@ import org.robolectric.RobolectricTestRunner;
 import org.robolectric.shadows.ShadowAppOpsManager;
 import org.robolectric.shadows.ShadowApplication;
 import org.robolectric.shadows.ShadowBinder;
+import org.robolectric.shadows.ShadowBuild;
 import org.robolectric.shadows.ShadowPackageManager;
 import org.robolectric.shadows.ShadowTelephonyManager;
 import org.robolectric.shadows.ShadowUserManager;
@@ -118,6 +126,7 @@ public final class DeviceLockServiceImplTest {
     private ShadowPackageManager mShadowPackageManager;
     private PackageManager mPackageManager;
     private ShadowUserManager mShadowUserManager;
+    private ShadowBuild mShadowBuild;
     private UserHandle mSystemUser;
     private UserHandle mSecondaryUser;
 
@@ -126,6 +135,9 @@ public final class DeviceLockServiceImplTest {
     @Mock
     private PowerExemptionManager mPowerExemptionManager;
 
+    @Captor
+    private ArgumentCaptor<ParcelableException> mParcelableExceptionArgumentCaptor;
+
     private ShadowApplication mShadowApplication;
 
     private DeviceLockServiceImpl mService;
@@ -225,6 +237,128 @@ public final class DeviceLockServiceImplTest {
                 eq(DEVICE_ID_TYPE_MEID), eq(testMeid));
     }
 
+    @Test
+    public void getDeviceId_withSerialType_shouldReturnSerial() throws Exception {
+        // GIVEN a serial number registered in build
+        final String testSerial = "1234567890";
+        mShadowBuild.setSerial(testSerial);
+
+        // GIVEN a successful service call to DLC app
+        doAnswer((Answer<Void>) invocation -> {
+            RemoteCallback callback = invocation.getArgument(0);
+            Bundle bundle = new Bundle();
+            bundle.putString(IDeviceLockControllerService.KEY_RESULT, testSerial);
+            callback.sendResult(bundle);
+            return null;
+        }).when(mDeviceLockControllerService).getDeviceIdentifier(any(RemoteCallback.class));
+
+        IGetDeviceIdCallback mockCallback = mock(IGetDeviceIdCallback.class);
+
+        // WHEN the device id is requested with the serial device type
+        mService.getDeviceId(mockCallback, 1 << DEVICE_ID_TYPE_SERIAL_NUMBER);
+        waitUntilConnected();
+
+        // THEN the serial id is received
+        verify(mockCallback, timeout(ONE_SEC_MILLIS)).onDeviceIdReceived(
+                eq(DEVICE_ID_TYPE_SERIAL_NUMBER), eq(testSerial));
+    }
+
+    @Test
+    public void getEnrollmentType_withoutHoldingPermission_shouldReturnSecurityException()
+            throws Exception {
+        // GIVEN the app does NOT holds the GET_DEVICE_LOCK_ENROLLMENT_TYPE permission
+
+        // WHEN the enrollment type is requested
+        IGetEnrollmentTypeCallback mockCallback = mock(IGetEnrollmentTypeCallback.class);
+        mService.getEnrollmentType(mockCallback);
+
+        // THEN an exception is returned
+        verify(mockCallback, timeout(ONE_SEC_MILLIS)).onError(
+                mParcelableExceptionArgumentCaptor.capture());
+
+        // THEN the exception is a security exception
+        assertThat(mParcelableExceptionArgumentCaptor.getValue().getException())
+                .isInstanceOf(SecurityException.class);
+    }
+
+    @Test
+    public void getEnrollmentType_withDlcReportingNone_shouldReturnNone() throws Exception {
+        // GIVEN the app holds the GET_DEVICE_LOCK_ENROLLMENT_TYPE permission
+        mShadowApplication.grantPermissions(GET_DEVICE_LOCK_ENROLLMENT_TYPE);
+
+        // GIVEN a successful service call to DLC app
+        doAnswer((Answer<Void>) invocation -> {
+            RemoteCallback callback = invocation.getArgument(0);
+            Bundle bundle = new Bundle();
+            bundle.putInt(IDeviceLockControllerService.KEY_RESULT,
+                    DeviceLockManager.ENROLLMENT_TYPE_NONE);
+            callback.sendResult(bundle);
+            return null;
+        }).when(mDeviceLockControllerService).getEnrollmentType(any(RemoteCallback.class));
+
+        IGetEnrollmentTypeCallback mockCallback = mock(IGetEnrollmentTypeCallback.class);
+
+        // WHEN the enrollment type is requested
+        mService.getEnrollmentType(mockCallback);
+        waitUntilConnected();
+
+        // THEN the correct enrollment type is received
+        verify(mockCallback, timeout(ONE_SEC_MILLIS)).onEnrollmentTypeReceived(
+                eq(DeviceLockManager.ENROLLMENT_TYPE_NONE));
+    }
+
+    @Test
+    public void getEnrollmentType_withDlcReportingFinance_shouldReturnFinance() throws Exception {
+        // GIVEN the app holds the GET_DEVICE_LOCK_ENROLLMENT_TYPE permission
+        mShadowApplication.grantPermissions(GET_DEVICE_LOCK_ENROLLMENT_TYPE);
+
+        // GIVEN a successful service call to DLC app
+        doAnswer((Answer<Void>) invocation -> {
+            RemoteCallback callback = invocation.getArgument(0);
+            Bundle bundle = new Bundle();
+            bundle.putInt(IDeviceLockControllerService.KEY_RESULT,
+                    DeviceLockManager.ENROLLMENT_TYPE_FINANCE);
+            callback.sendResult(bundle);
+            return null;
+        }).when(mDeviceLockControllerService).getEnrollmentType(any(RemoteCallback.class));
+
+        IGetEnrollmentTypeCallback mockCallback = mock(IGetEnrollmentTypeCallback.class);
+
+        // WHEN the enrollment type is requested
+        mService.getEnrollmentType(mockCallback);
+        waitUntilConnected();
+
+        // THEN the correct enrollment type is received
+        verify(mockCallback, timeout(ONE_SEC_MILLIS)).onEnrollmentTypeReceived(
+                eq(DeviceLockManager.ENROLLMENT_TYPE_FINANCE));
+    }
+
+    @Test
+    public void getEnrollmentType_withDlcReportingSubsidy_shouldReturnSubsidy() throws Exception {
+        // GIVEN the app holds the GET_DEVICE_LOCK_ENROLLMENT_TYPE permission
+        mShadowApplication.grantPermissions(GET_DEVICE_LOCK_ENROLLMENT_TYPE);
+
+        // GIVEN a successful service call to DLC app
+        doAnswer((Answer<Void>) invocation -> {
+            RemoteCallback callback = invocation.getArgument(0);
+            Bundle bundle = new Bundle();
+            bundle.putInt(IDeviceLockControllerService.KEY_RESULT,
+                    DeviceLockManager.ENROLLMENT_TYPE_SUBSIDY);
+            callback.sendResult(bundle);
+            return null;
+        }).when(mDeviceLockControllerService).getEnrollmentType(any(RemoteCallback.class));
+
+        IGetEnrollmentTypeCallback mockCallback = mock(IGetEnrollmentTypeCallback.class);
+
+        // WHEN the enrollment type is requested
+        mService.getEnrollmentType(mockCallback);
+        waitUntilConnected();
+
+        // THEN the correct enrollment type is received
+        verify(mockCallback, timeout(ONE_SEC_MILLIS)).onEnrollmentTypeReceived(
+                eq(DeviceLockManager.ENROLLMENT_TYPE_SUBSIDY));
+    }
+
     @Test
     public void setCallerAllowedToSendUndismissibleNotifications_trueAllowsAppOp() {
         final AtomicBoolean succeeded = new AtomicBoolean(false);
```

