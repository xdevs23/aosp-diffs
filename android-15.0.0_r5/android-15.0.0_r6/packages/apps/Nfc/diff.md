```diff
diff --git a/Android.bp b/Android.bp
index cb45f3eb..806b03b1 100644
--- a/Android.bp
+++ b/Android.bp
@@ -42,6 +42,9 @@ java_defaults {
         "nfc-event-log-proto",
         "nfc_flags_lib",
     ],
+    flags_packages: [
+        "nfc_aconfig_flags",
+    ],
     privileged: true,
     optimize: {
         proguard_flags_files: ["proguard.flags"],
@@ -76,6 +79,12 @@ android_app {
         // does not ship one in /product
         "libnfc-nci.conf-default",
     ],
+    lint: {
+        baseline_filename: "lint-baseline-nfcnci.xml",
+        warning_checks: [
+            "FlaggedApi",
+        ],
+    },
 }
 
 // NCI Configuration embedded in NFC apex.
@@ -92,15 +101,15 @@ android_app {
     ],
     libs: [
         "framework-annotations-lib",
-        "framework-bluetooth",
-        "framework-configinfrastructure",
+        "framework-bluetooth.stubs.module_lib",
+        "framework-configinfrastructure.stubs.module_lib",
         "framework-nfc.impl",
-        "framework-permission-s",
-        "framework-permission",
+        "framework-permission-s.stubs.module_lib",
+        "framework-permission.stubs.module_lib",
         "framework-statsd.stubs.module_lib",
-        "framework-wifi",
+        "framework-wifi.stubs.module_lib",
         "android.nfc.flags-aconfig-java",
-        "android.permission.flags-aconfig-java-export",
+        "android.permission.flags-aconfig-java",
         "android.service.chooser.flags-aconfig-java",
         "unsupportedappusage",
     ],
diff --git a/AndroidManifest.xml b/AndroidManifest.xml
index 1f5b9511..5d28f26b 100755
--- a/AndroidManifest.xml
+++ b/AndroidManifest.xml
@@ -69,6 +69,91 @@
     <uses-permission android:name="android.permission.DUMP"/>
     <uses-permission android:name="android.permission.QUERY_CLONED_APPS"/>
     <uses-permission android:name="android.permission.READ_PRIVILEGED_PHONE_STATE"/>
+    <uses-permission android:name="android.permission.MODIFY_PHONE_STATE"/>
+
+    <protected-broadcast android:name="android.nfc.intent.action.WATCHDOG" />
+
+    <application android:name=".NfcApplication"
+                 android:icon="@drawable/icon"
+                 android:label="@string/app_name"
+                 android:theme="@android:style/Theme.Material.Light"
+                 android:persistent="true"
+                 android:persistentWhenFeatureAvailable="android.hardware.nfc.any"
+                 android:restoreAnyVersion="true"
+                 android:backupAgent="com.android.nfc.NfcBackupAgent"
+                 android:killAfterRestore="false"
+                 android:usesCleartextTraffic="false"
+                 android:supportsRtl="true"
+                 android:hardwareAccelerated="false"
+                 android:memtagMode="async"
+                 android:featureFlag="!com.android.nfc.flags.enable_direct_boot_aware"
+    >
+        <meta-data android:name="com.google.android.backup.api_key"
+            android:value="AEdPqrEAAAAIbiKKs0wlimxeJ9y8iRIaBOH6aeb2IurmZyBHvg" />
+
+        <provider android:name="androidx.core.content.FileProvider"
+            android:authorities="com.google.android.nfc.fileprovider"
+            android:grantUriPermissions="true"
+            android:exported="false">
+            <meta-data
+                android:name="android.support.FILE_PROVIDER_PATHS"
+                android:resource="@xml/file_paths" />
+        </provider>
+
+        <activity android:name=".TechListChooserActivity"
+            android:theme="@*android:style/Theme.Dialog.Alert"
+            android:finishOnCloseSystemDialogs="true"
+            android:excludeFromRecents="true"
+            android:multiprocess="true"
+        />
+
+        <activity android:name=".cardemulation.AppChooserActivity"
+            android:finishOnCloseSystemDialogs="true"
+            android:excludeFromRecents="true"
+            android:clearTaskOnLaunch="true"
+            android:multiprocess="true"
+            android:theme="@style/BottomSheetDialogStyle"
+        />
+
+        <activity android:name=".cardemulation.TapAgainDialog"
+            android:finishOnCloseSystemDialogs="true"
+            android:excludeFromRecents="true"
+            android:clearTaskOnLaunch="true"
+            android:multiprocess="true"
+        />
+        <activity android:name=".NfcRootActivity"
+            android:theme="@*android:style/Theme.Translucent.NoTitleBar"
+            android:excludeFromRecents="true"
+            android:noHistory="true"
+        />
+        <activity android:name=".handover.ConfirmConnectActivity"
+            android:finishOnCloseSystemDialogs="true"
+            android:excludeFromRecents="true"
+            android:theme="@android:style/Theme.Translucent.NoTitleBar"
+            android:noHistory="true"
+            android:configChanges="orientation|keyboardHidden|screenSize"
+        />
+        <activity android:name=".ConfirmConnectToWifiNetworkActivity"
+            android:finishOnCloseSystemDialogs="true"
+            android:excludeFromRecents="true"
+            android:theme="@android:style/Theme.Translucent.NoTitleBar"
+            android:noHistory="true"
+        />
+        <activity android:name=".NfcEnableAllowlistActivity"
+            android:theme="@android:style/Theme.Translucent.NoTitleBar"
+            android:noHistory="true"
+        />
+
+        <receiver android:name=".NfcBootCompletedReceiver"
+            android:exported="true">
+            <intent-filter>
+                <action android:name="android.intent.action.BOOT_COMPLETED" />
+            </intent-filter>
+        </receiver>
+
+        <service android:name=".handover.PeripheralHandoverService"
+        />
+    </application>
 
     <application android:name=".NfcApplication"
                  android:icon="@drawable/icon"
@@ -83,6 +168,9 @@
                  android:supportsRtl="true"
                  android:hardwareAccelerated="false"
                  android:memtagMode="async"
+                 android:directBootAware="true"
+                 android:defaultToDeviceProtectedStorage="true"
+                 android:featureFlag="com.android.nfc.flags.enable_direct_boot_aware"
     >
         <meta-data android:name="com.google.android.backup.api_key"
             android:value="AEdPqrEAAAAIbiKKs0wlimxeJ9y8iRIaBOH6aeb2IurmZyBHvg" />
diff --git a/TEST_MAPPING b/TEST_MAPPING
index 33978ca8..1bc8a166 100644
--- a/TEST_MAPPING
+++ b/TEST_MAPPING
@@ -11,6 +11,9 @@
     }
   ],
   "postsubmit": [
+    {
+      "name": "NfcTestCases"
+    },
     {
       "name": "NfcNciInstrumentationTests",
       "keywords": ["primary-device"]
@@ -18,6 +21,10 @@
     {
       "name": "NfcNciUnitTests",
       "keywords": ["primary-device"]
+    },
+    {
+      "name": "nfc.nci.jni.tests",
+      "keywords": ["primary-device"]
     }
   ],
   "pts-prebuilt": [
diff --git a/com.android.nfc.xml b/com.android.nfc.xml
index 2046ab50..8bb6b14a 100644
--- a/com.android.nfc.xml
+++ b/com.android.nfc.xml
@@ -35,5 +35,6 @@
         <permission name="android.permission.DUMP"/>
         <permission name="android.permission.QUERY_CLONED_APPS"/>
         <permission name="android.permission.READ_PRIVILEGED_PHONE_STATE"/>
+        <permission name="android.permission.MODIFY_PHONE_STATE"/>
     </privapp-permissions>
 </permissions>
diff --git a/flags/nfc_flags.aconfig b/flags/nfc_flags.aconfig
index 618396ba..c52b4466 100644
--- a/flags/nfc_flags.aconfig
+++ b/flags/nfc_flags.aconfig
@@ -32,3 +32,24 @@ flag {
         purpose: PURPOSE_BUGFIX
   }
 }
+
+flag {
+    name: "send_view_intent_for_url_tag_dispatch"
+    namespace: "nfc"
+    description: "Send VIEW intent instead of NFC_TAG_DISCOVERED for URL tag dispatch"
+    bug: "345570691"
+}
+
+flag {
+    name: "enable_direct_boot_aware"
+    namespace: "nfc"
+    description: "Enable direct boot aware for nfc service"
+    bug: "321310938"
+}
+
+flag {
+    name: "observe_mode_without_rf"
+    namespace: "nfc"
+    description: "Enable setting obseve mode state with out deactivating RF"
+    bug: "368655283"
+}
diff --git a/lint-baseline-nfcnci.xml b/lint-baseline-nfcnci.xml
new file mode 100644
index 00000000..3bca22f3
--- /dev/null
+++ b/lint-baseline-nfcnci.xml
@@ -0,0 +1,334 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<issues format="6" by="lint 8.4.0-alpha08" type="baseline" client="" dependencies="true" name="" variant="all" version="8.4.0-alpha08">
+
+    <issue
+        id="FlaggedApi"
+        message="Method `updateForShouldDefaultToObserveMode()` is a flagged API and should be inside an `if (Flags.nfcObserveMode())` check (or annotate the surrounding method `updateForShouldDefaultToObserveMode` with `@FlaggedApi(Flags.FLAG_NFC_OBSERVE_MODE) to transfer requirement to caller`)"
+        errorLine1="            mHostEmulationManager.updateForShouldDefaultToObserveMode(enableObserveMode);"
+        errorLine2="            ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/cardemulation/CardEmulationManager.java"
+            line="1095"
+            column="13"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Field `SE_NAME_HCE` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `HostEmulationManager` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="        this(context, looper, aidCache, new StatsdUtils(StatsdUtils.SE_NAME_HCE));"
+        errorLine2="                                                                    ~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/cardemulation/HostEmulationManager.java"
+            line="200"
+            column="69"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `StatsdUtils()` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `HostEmulationManager` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="        this(context, looper, aidCache, new StatsdUtils(StatsdUtils.SE_NAME_HCE));"
+        errorLine2="                                        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/cardemulation/HostEmulationManager.java"
+            line="200"
+            column="41"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `tallyPollingFrame()` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `onPollingLoopDetected` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="                        mStatsdUtils.tallyPollingFrame(dataStr, pollingFrame);"
+        errorLine2="                        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/cardemulation/HostEmulationManager.java"
+            line="412"
+            column="25"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `logPollingFrames()` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `onPollingLoopDetected` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="                    mStatsdUtils.logPollingFrames();"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/cardemulation/HostEmulationManager.java"
+            line="418"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `setCardEmulationEventCategory()` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `onHostEmulationData` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="                        mStatsdUtils.setCardEmulationEventCategory(resolveInfo.category);"
+        errorLine2="                        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/cardemulation/HostEmulationManager.java"
+            line="610"
+            column="25"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `setCardEmulationEventUid()` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `onHostEmulationData` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="                        mStatsdUtils.setCardEmulationEventUid(defaultServiceInfo.getUid());"
+        errorLine2="                        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/cardemulation/HostEmulationManager.java"
+            line="611"
+            column="25"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `logCardEmulationWrongSettingEvent()` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `onHostEmulationData` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="                            mStatsdUtils.logCardEmulationWrongSettingEvent();"
+        errorLine2="                            ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/cardemulation/HostEmulationManager.java"
+            line="621"
+            column="29"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `setCardEmulationEventCategory()` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `onHostEmulationData` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="                        mStatsdUtils.setCardEmulationEventCategory(CardEmulation.CATEGORY_OTHER);"
+        errorLine2="                        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/cardemulation/HostEmulationManager.java"
+            line="663"
+            column="25"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `logCardEmulationWrongSettingEvent()` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `onHostEmulationData` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="                        mStatsdUtils.logCardEmulationWrongSettingEvent();"
+        errorLine2="                        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/cardemulation/HostEmulationManager.java"
+            line="664"
+            column="25"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `setCardEmulationEventUid()` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `onHostEmulationData` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="                            mStatsdUtils.setCardEmulationEventUid(uid);"
+        errorLine2="                            ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/cardemulation/HostEmulationManager.java"
+            line="676"
+            column="29"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `setCardEmulationEventCategory()` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `onHostEmulationData` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="                            mStatsdUtils.setCardEmulationEventCategory(resolveInfo.category);"
+        errorLine2="                            ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/cardemulation/HostEmulationManager.java"
+            line="677"
+            column="29"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `notifyCardEmulationEventWaitingForResponse()` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `onHostEmulationData` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="                            mStatsdUtils.notifyCardEmulationEventWaitingForResponse();"
+        errorLine2="                            ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/cardemulation/HostEmulationManager.java"
+            line="694"
+            column="29"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `logCardEmulationDeactivatedEvent()` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `onHostEmulationDeactivated` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="                mStatsdUtils.logCardEmulationDeactivatedEvent();"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/cardemulation/HostEmulationManager.java"
+            line="760"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `notifyCardEmulationEventWaitingForService()` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `bindServiceIfNeededLocked` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="                mStatsdUtils.notifyCardEmulationEventWaitingForService();"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/cardemulation/HostEmulationManager.java"
+            line="825"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `notifyCardEmulationEventServiceBound()` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `onServiceConnected` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="                        mStatsdUtils.notifyCardEmulationEventServiceBound();"
+        errorLine2="                        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/cardemulation/HostEmulationManager.java"
+            line="1065"
+            column="25"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `notifyCardEmulationEventResponseReceived()` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `handleMessage` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="                        mStatsdUtils.notifyCardEmulationEventResponseReceived();"
+        errorLine2="                        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/cardemulation/HostEmulationManager.java"
+            line="1125"
+            column="25"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `logCardEmulationWrongSettingEvent()` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `onHostEmulationData` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="                    mStatsdUtils.logCardEmulationWrongSettingEvent();"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/cardemulation/HostNfcFEmulationManager.java"
+            line="138"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `setCardEmulationEventUid()` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `onHostEmulationData` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="                        mStatsdUtils.setCardEmulationEventUid(uid);"
+        errorLine2="                        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/cardemulation/HostNfcFEmulationManager.java"
+            line="169"
+            column="25"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `notifyCardEmulationEventWaitingForResponse()` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `onHostEmulationData` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="                        mStatsdUtils.notifyCardEmulationEventWaitingForResponse();"
+        errorLine2="                        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/cardemulation/HostNfcFEmulationManager.java"
+            line="170"
+            column="25"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `logCardEmulationDeactivatedEvent()` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `onHostEmulationDeactivated` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="                mStatsdUtils.logCardEmulationDeactivatedEvent();"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/cardemulation/HostNfcFEmulationManager.java"
+            line="199"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `notifyCardEmulationEventWaitingForService()` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `bindServiceIfNeededLocked` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="                mStatsdUtils.notifyCardEmulationEventWaitingForService();"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/cardemulation/HostNfcFEmulationManager.java"
+            line="273"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `notifyCardEmulationEventServiceBound()` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `onServiceConnected` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="                        mStatsdUtils.notifyCardEmulationEventServiceBound();"
+        errorLine2="                        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/cardemulation/HostNfcFEmulationManager.java"
+            line="327"
+            column="25"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `notifyCardEmulationEventResponseReceived()` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `handleMessage` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="                        mStatsdUtils.notifyCardEmulationEventResponseReceived();"
+        errorLine2="                        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/cardemulation/HostNfcFEmulationManager.java"
+            line="381"
+            column="25"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `StatsdUtils()` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `NfcInjector` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="        mStatsdUtils = mFeatureFlags.statsdCeEventsFlag() ? new StatsdUtils() : null;"
+        errorLine2="                                                            ~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/NfcInjector.java"
+            line="102"
+            column="61"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `logFieldChanged()` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `onRemoteFieldActivated` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="            mStatsdUtils.logFieldChanged(true, 0);"
+        errorLine2="            ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/NfcService.java"
+            line="508"
+            column="13"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `logFieldChanged()` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `onRemoteFieldDeactivated` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="            mStatsdUtils.logFieldChanged(false, 0);"
+        errorLine2="            ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/NfcService.java"
+            line="517"
+            column="13"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `logObserveModeStateChanged()` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `setObserveMode` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="                mStatsdUtils.logObserveModeStateChanged(enable, triggerSource, latency);"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/NfcService.java"
+            line="1802"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `setCardEmulationEventCategory()` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `sendOffHostTransactionEvent` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="                    mStatsdUtils.setCardEmulationEventCategory(aidCategory);"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/NfcService.java"
+            line="3979"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `logCardEmulationOffhostEvent()` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `sendOffHostTransactionEvent` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="                    mStatsdUtils.logCardEmulationOffhostEvent(reader);"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/NfcService.java"
+            line="4073"
+            column="21"/>
+    </issue>
+
+</issues>
diff --git a/lint-baseline.xml b/lint-baseline.xml
index 0f1aefa1..6a5981b0 100644
--- a/lint-baseline.xml
+++ b/lint-baseline.xml
@@ -1739,4 +1739,334 @@
             column="60"/>
     </issue>
 
+    <issue
+        id="FlaggedApi"
+        message="Method `updateForShouldDefaultToObserveMode()` is a flagged API and should be inside an `if (Flags.nfcObserveMode())` check (or annotate the surrounding method `updateForShouldDefaultToObserveMode` with `@FlaggedApi(Flags.FLAG_NFC_OBSERVE_MODE) to transfer requirement to caller`)"
+        errorLine1="            mHostEmulationManager.updateForShouldDefaultToObserveMode(enableObserveMode);"
+        errorLine2="            ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/cardemulation/CardEmulationManager.java"
+            line="1095"
+            column="13"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Field `SE_NAME_HCE` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `HostEmulationManager` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="        this(context, looper, aidCache, new StatsdUtils(StatsdUtils.SE_NAME_HCE));"
+        errorLine2="                                                                    ~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/cardemulation/HostEmulationManager.java"
+            line="200"
+            column="69"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `StatsdUtils()` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `HostEmulationManager` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="        this(context, looper, aidCache, new StatsdUtils(StatsdUtils.SE_NAME_HCE));"
+        errorLine2="                                        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/cardemulation/HostEmulationManager.java"
+            line="200"
+            column="41"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `tallyPollingFrame()` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `onPollingLoopDetected` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="                        mStatsdUtils.tallyPollingFrame(dataStr, pollingFrame);"
+        errorLine2="                        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/cardemulation/HostEmulationManager.java"
+            line="412"
+            column="25"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `logPollingFrames()` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `onPollingLoopDetected` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="                    mStatsdUtils.logPollingFrames();"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/cardemulation/HostEmulationManager.java"
+            line="418"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `setCardEmulationEventCategory()` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `onHostEmulationData` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="                        mStatsdUtils.setCardEmulationEventCategory(resolveInfo.category);"
+        errorLine2="                        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/cardemulation/HostEmulationManager.java"
+            line="610"
+            column="25"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `setCardEmulationEventUid()` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `onHostEmulationData` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="                        mStatsdUtils.setCardEmulationEventUid(defaultServiceInfo.getUid());"
+        errorLine2="                        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/cardemulation/HostEmulationManager.java"
+            line="611"
+            column="25"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `logCardEmulationWrongSettingEvent()` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `onHostEmulationData` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="                            mStatsdUtils.logCardEmulationWrongSettingEvent();"
+        errorLine2="                            ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/cardemulation/HostEmulationManager.java"
+            line="621"
+            column="29"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `setCardEmulationEventCategory()` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `onHostEmulationData` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="                        mStatsdUtils.setCardEmulationEventCategory(CardEmulation.CATEGORY_OTHER);"
+        errorLine2="                        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/cardemulation/HostEmulationManager.java"
+            line="663"
+            column="25"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `logCardEmulationWrongSettingEvent()` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `onHostEmulationData` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="                        mStatsdUtils.logCardEmulationWrongSettingEvent();"
+        errorLine2="                        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/cardemulation/HostEmulationManager.java"
+            line="664"
+            column="25"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `setCardEmulationEventUid()` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `onHostEmulationData` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="                            mStatsdUtils.setCardEmulationEventUid(uid);"
+        errorLine2="                            ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/cardemulation/HostEmulationManager.java"
+            line="676"
+            column="29"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `setCardEmulationEventCategory()` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `onHostEmulationData` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="                            mStatsdUtils.setCardEmulationEventCategory(resolveInfo.category);"
+        errorLine2="                            ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/cardemulation/HostEmulationManager.java"
+            line="677"
+            column="29"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `notifyCardEmulationEventWaitingForResponse()` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `onHostEmulationData` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="                            mStatsdUtils.notifyCardEmulationEventWaitingForResponse();"
+        errorLine2="                            ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/cardemulation/HostEmulationManager.java"
+            line="694"
+            column="29"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `logCardEmulationDeactivatedEvent()` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `onHostEmulationDeactivated` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="                mStatsdUtils.logCardEmulationDeactivatedEvent();"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/cardemulation/HostEmulationManager.java"
+            line="760"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `notifyCardEmulationEventWaitingForService()` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `bindServiceIfNeededLocked` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="                mStatsdUtils.notifyCardEmulationEventWaitingForService();"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/cardemulation/HostEmulationManager.java"
+            line="825"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `notifyCardEmulationEventServiceBound()` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `onServiceConnected` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="                        mStatsdUtils.notifyCardEmulationEventServiceBound();"
+        errorLine2="                        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/cardemulation/HostEmulationManager.java"
+            line="1065"
+            column="25"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `notifyCardEmulationEventResponseReceived()` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `handleMessage` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="                        mStatsdUtils.notifyCardEmulationEventResponseReceived();"
+        errorLine2="                        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/cardemulation/HostEmulationManager.java"
+            line="1125"
+            column="25"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `logCardEmulationWrongSettingEvent()` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `onHostEmulationData` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="                    mStatsdUtils.logCardEmulationWrongSettingEvent();"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/cardemulation/HostNfcFEmulationManager.java"
+            line="138"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `setCardEmulationEventUid()` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `onHostEmulationData` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="                        mStatsdUtils.setCardEmulationEventUid(uid);"
+        errorLine2="                        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/cardemulation/HostNfcFEmulationManager.java"
+            line="169"
+            column="25"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `notifyCardEmulationEventWaitingForResponse()` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `onHostEmulationData` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="                        mStatsdUtils.notifyCardEmulationEventWaitingForResponse();"
+        errorLine2="                        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/cardemulation/HostNfcFEmulationManager.java"
+            line="170"
+            column="25"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `logCardEmulationDeactivatedEvent()` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `onHostEmulationDeactivated` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="                mStatsdUtils.logCardEmulationDeactivatedEvent();"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/cardemulation/HostNfcFEmulationManager.java"
+            line="199"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `notifyCardEmulationEventWaitingForService()` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `bindServiceIfNeededLocked` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="                mStatsdUtils.notifyCardEmulationEventWaitingForService();"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/cardemulation/HostNfcFEmulationManager.java"
+            line="273"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `notifyCardEmulationEventServiceBound()` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `onServiceConnected` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="                        mStatsdUtils.notifyCardEmulationEventServiceBound();"
+        errorLine2="                        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/cardemulation/HostNfcFEmulationManager.java"
+            line="327"
+            column="25"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `notifyCardEmulationEventResponseReceived()` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `handleMessage` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="                        mStatsdUtils.notifyCardEmulationEventResponseReceived();"
+        errorLine2="                        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/cardemulation/HostNfcFEmulationManager.java"
+            line="381"
+            column="25"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `StatsdUtils()` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `NfcInjector` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="        mStatsdUtils = mFeatureFlags.statsdCeEventsFlag() ? new StatsdUtils() : null;"
+        errorLine2="                                                            ~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/NfcInjector.java"
+            line="102"
+            column="61"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `logFieldChanged()` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `onRemoteFieldActivated` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="            mStatsdUtils.logFieldChanged(true, 0);"
+        errorLine2="            ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/NfcService.java"
+            line="508"
+            column="13"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `logFieldChanged()` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `onRemoteFieldDeactivated` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="            mStatsdUtils.logFieldChanged(false, 0);"
+        errorLine2="            ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/NfcService.java"
+            line="517"
+            column="13"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `logObserveModeStateChanged()` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `setObserveMode` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="                mStatsdUtils.logObserveModeStateChanged(enable, triggerSource, latency);"
+        errorLine2="                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/NfcService.java"
+            line="1802"
+            column="17"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `setCardEmulationEventCategory()` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `sendOffHostTransactionEvent` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="                    mStatsdUtils.setCardEmulationEventCategory(aidCategory);"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/NfcService.java"
+            line="3979"
+            column="21"/>
+    </issue>
+
+    <issue
+        id="FlaggedApi"
+        message="Method `logCardEmulationOffhostEvent()` is a flagged API and should be inside an `if (Flags.statsdCeEventsFlag())` check (or annotate the surrounding method `sendOffHostTransactionEvent` with `@FlaggedApi(Flags.FLAG_STATSD_CE_EVENTS_FLAG) to transfer requirement to caller`)"
+        errorLine1="                    mStatsdUtils.logCardEmulationOffhostEvent(reader);"
+        errorLine2="                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~">
+        <location
+            file="packages/apps/Nfc/src/com/android/nfc/NfcService.java"
+            line="4073"
+            column="21"/>
+    </issue>
+
 </issues>
\ No newline at end of file
diff --git a/nci/jni/Android.bp b/nci/jni/Android.bp
index 9d90301b..5836aeb4 100644
--- a/nci/jni/Android.bp
+++ b/nci/jni/Android.bp
@@ -3,8 +3,21 @@ package {
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
+cc_library_static {
+    name: "libnfc_nci_jni_static",
+    defaults: ["libnfc_nci_jni_defaults"],
+    visibility: [
+        "//packages/apps/Nfc/nci/jni",
+    ],
+}
+
 cc_library_shared {
     name: "libnfc_nci_jni",
+    defaults: ["libnfc_nci_jni_defaults"],
+}
+
+cc_defaults {
+    name: "libnfc_nci_jni_defaults",
 
     cflags: [
         "-Wall",
@@ -46,7 +59,7 @@ cc_library_shared {
         "android.hardware.nfc@1.1",
         "android.hardware.nfc@1.2",
         // Add for AIDL
-        "android.hardware.nfc-V1-ndk",
+        "android.hardware.nfc-V2-ndk",
         "libnfcutils",
         "libnfc-nci",
         "libnfc-nci_flags",
@@ -91,14 +104,40 @@ cc_test {
     srcs: ["NfcTagTest.cpp"],
 
     shared_libs: [
-        "libnfc-nci",
-        "libnfc_nci_jni",
-        "libstatslog_nfc",
+        "libnativehelper",
+        "libcutils",
+        "libutils",
+        "liblog",
+        "libbase",
+        // Treble configuration
+        "libhidlbase",
+        "libutils",
+        "libbinder_ndk",
+        "libstatssocket",
+        "libz",
     ],
 
     static_libs: [
         "libgmock",
         "libgtest",
+        "libnfc-nci",
+        "libnfc_nci_jni_static",
+        "android.hardware.nfc@1.0",
+        "android.hardware.nfc@1.1",
+        "android.hardware.nfc@1.2",
+        // Add for AIDL
+        "android.hardware.nfc-V2-ndk",
+        "libnfcutils",
+        "libnfc-nci",
+        "libnfc-nci_flags",
+        "libstatslog_nfc",
+        "android_nfc_flags_aconfig_c_lib",
+        "server_configurable_flags",
+        "libxml2",
+    ],
+
+    defaults: [
+        "aconfig_lib_cc_static_link.defaults",
     ],
 
     header_libs: [
@@ -114,4 +153,5 @@ cc_test {
         "system/nfc/src/nfc/include",
         "system/nfc/utils/include",
     ],
+    test_suites: ["general-tests"],
 }
diff --git a/nci/jni/HciEventManager.cpp b/nci/jni/HciEventManager.cpp
index 952ede96..6c5740b4 100644
--- a/nci/jni/HciEventManager.cpp
+++ b/nci/jni/HciEventManager.cpp
@@ -26,7 +26,7 @@
 
 const char* APP_NAME = "NfcNci";
 uint8_t HciEventManager::sEsePipe;
-uint8_t HciEventManager::sSimPipe;
+std::vector<uint8_t> HciEventManager::sSimPipeIds;
 
 using android::base::StringPrintf;
 
@@ -45,7 +45,13 @@ void HciEventManager::initialize(nfc_jni_native_data* native) {
     LOG(ERROR) << "HCI registration failed; status=" << nfaStat;
   }
   sEsePipe = NfcConfig::getUnsigned(NAME_OFF_HOST_ESE_PIPE_ID, 0x16);
-  sSimPipe = NfcConfig::getUnsigned(NAME_OFF_HOST_SIM_PIPE_ID, 0x0A);
+  // Backward compatibility or For vendor supporting only single sim pipe ID
+  if (!NfcConfig::hasKey(NAME_OFF_HOST_SIM_PIPE_IDS)) {
+    uint8_t simPipeId = NfcConfig::getUnsigned(NAME_OFF_HOST_SIM_PIPE_ID, 0x0A);
+    sSimPipeIds = {simPipeId};
+  } else {
+    sSimPipeIds = NfcConfig::getBytes(NAME_OFF_HOST_SIM_PIPE_IDS);
+  }
 }
 
 void HciEventManager::notifyTransactionListenersOfAid(std::vector<uint8_t> aid,
@@ -147,11 +153,20 @@ void HciEventManager::nfaHciCallback(tNFA_HCI_EVT event,
   std::string evtSrc;
   if (eventData->rcvd_evt.pipe == sEsePipe) {
     evtSrc = "eSE1";
-  } else if (eventData->rcvd_evt.pipe == sSimPipe) {
-    evtSrc = "SIM1";
   } else {
-    LOG(WARNING) << "Incorrect Pipe Id";
-    return;
+    bool isSimPipeId = false;
+    for (size_t i = 0; i < (size_t)sSimPipeIds.size(); i++) {
+      if (eventData->rcvd_evt.pipe == sSimPipeIds[i]) {
+        evtSrc = "SIM" + std::to_string(i + 1);
+        isSimPipeId = true;
+        break;
+      }
+    }
+
+    if (!isSimPipeId) {
+      LOG(WARNING) << "Incorrect Pipe Id";
+      return;
+    }
   }
 
   // Check the event and check if it contains the AID
diff --git a/nci/jni/HciEventManager.h b/nci/jni/HciEventManager.h
index 6c21d952..34b81de1 100644
--- a/nci/jni/HciEventManager.h
+++ b/nci/jni/HciEventManager.h
@@ -29,7 +29,7 @@ class HciEventManager {
  private:
   nfc_jni_native_data* mNativeData;
   static uint8_t sEsePipe;
-  static uint8_t sSimPipe;
+  static std::vector<uint8_t> sSimPipeIds;
 
   HciEventManager();
   std::vector<uint8_t> getDataFromBerTlv(std::vector<uint8_t> berTlv);
diff --git a/nci/jni/NativeNfcManager.cpp b/nci/jni/NativeNfcManager.cpp
index 8de85557..732857ed 100644
--- a/nci/jni/NativeNfcManager.cpp
+++ b/nci/jni/NativeNfcManager.cpp
@@ -33,6 +33,7 @@
 #endif /* DTA_ENABLED */
 #include "NfcJniUtil.h"
 #include "NfcTag.h"
+#include "NfceeManager.h"
 #include "PowerSwitch.h"
 #include "RoutingManager.h"
 #include "SyncEvent.h"
@@ -101,6 +102,8 @@ jmethodID gCachedNfcManagerNotifyPollingLoopFrame;
 jmethodID gCachedNfcManagerNotifyWlcStopped;
 jmethodID gCachedNfcManagerNotifyVendorSpecificEvent;
 jmethodID gCachedNfcManagerNotifyCommandTimeout;
+jmethodID gCachedNfcManagerNotifyObserveModeChanged;
+jmethodID gCachedNfcManagerNotifyRfDiscoveryEvent;
 const char* gNativeNfcTagClassName = "com/android/nfc/dhimpl/NativeNfcTag";
 const char* gNativeNfcManagerClassName =
     "com/android/nfc/dhimpl/NativeNfcManager";
@@ -174,8 +177,9 @@ uint8_t gConfig[256];
 std::vector<uint8_t> gCaps(0);
 static int prevScreenState = NFA_SCREEN_STATE_OFF_LOCKED;
 static int NFA_SCREEN_POLLING_TAG_MASK = 0x10;
-static bool gIsDtaEnabled = false;
+bool gIsDtaEnabled = false;
 static bool gObserveModeEnabled = false;
+static int gPartialInitMode = ENABLE_MODE_DEFAULT;
 /////////////////////////////////////////////////////////////
 /////////////////////////////////////////////////////////////
 
@@ -314,6 +318,20 @@ static void nfaConnectionCallback(uint8_t connEvent,
 
       SyncEventGuard guard(sNfaEnableDisablePollingEvent);
       sNfaEnableDisablePollingEvent.notifyOne();
+      struct nfc_jni_native_data* nat = getNative(NULL, NULL);
+      if (!nat) {
+        LOG(ERROR) << StringPrintf("cached nat is null");
+        return;
+      }
+      JNIEnv* e = NULL;
+      ScopedAttach attach(nat->vm, &e);
+      if (e == NULL) {
+        LOG(ERROR) << StringPrintf("jni env is null");
+        return;
+      }
+      e->CallVoidMethod(nat->manager,
+                        android::gCachedNfcManagerNotifyRfDiscoveryEvent,
+                        JNI_TRUE);
     } break;
 
     case NFA_RF_DISCOVERY_STOPPED_EVT:  // RF Discovery stopped event
@@ -326,6 +344,20 @@ static void nfaConnectionCallback(uint8_t connEvent,
 
       SyncEventGuard guard(sNfaEnableDisablePollingEvent);
       sNfaEnableDisablePollingEvent.notifyOne();
+      struct nfc_jni_native_data* nat = getNative(NULL, NULL);
+      if (!nat) {
+        LOG(ERROR) << StringPrintf("cached nat is null");
+        return;
+      }
+      JNIEnv* e = NULL;
+      ScopedAttach attach(nat->vm, &e);
+      if (e == NULL) {
+        LOG(ERROR) << StringPrintf("jni env is null");
+        return;
+      }
+      e->CallVoidMethod(nat->manager,
+                        android::gCachedNfcManagerNotifyRfDiscoveryEvent,
+                        JNI_FALSE);
     } break;
 
     case NFA_DISC_RESULT_EVT:  // NFC link/protocol discovery notificaiton
@@ -419,6 +451,20 @@ static void nfaConnectionCallback(uint8_t connEvent,
       // Send the RF Event.
       if (isListenMode(eventData->activated)) {
         sSeRfActive = true;
+        struct nfc_jni_native_data* nat = getNative(NULL, NULL);
+        if (!nat) {
+          LOG(ERROR) << StringPrintf("cached nat is null");
+          return;
+        }
+        JNIEnv* e = NULL;
+        ScopedAttach attach(nat->vm, &e);
+        if (e == NULL) {
+          LOG(ERROR) << "jni env is null";
+          return;
+        }
+        e->CallVoidMethod(nat->manager,
+                          android::gCachedNfcManagerNotifyHostEmuActivated,
+                          (int)activatedProtocol);
       }
     } break;
     case NFA_DEACTIVATED_EVT:  // NFC link/protocol deactivated
@@ -448,6 +494,20 @@ static void nfaConnectionCallback(uint8_t connEvent,
           (eventData->deactivated.type == NFA_DEACTIVATE_TYPE_DISCOVERY)) {
         if (sSeRfActive) {
           sSeRfActive = false;
+          struct nfc_jni_native_data* nat = getNative(NULL, NULL);
+          if (!nat) {
+            LOG(ERROR) << StringPrintf("cached nat is null");
+            return;
+          }
+          JNIEnv* e = NULL;
+          ScopedAttach attach(nat->vm, &e);
+          if (e == NULL) {
+            LOG(ERROR) << "jni env is null";
+            return;
+          }
+          e->CallVoidMethod(nat->manager,
+                            android::gCachedNfcManagerNotifyHostEmuDeactivated,
+                            NFA_TECHNOLOGY_MASK_A);
         }
       }
 
@@ -640,6 +700,12 @@ static jboolean nfcManager_initNativeStruc(JNIEnv* e, jobject o) {
   gCachedNfcManagerNotifyCommandTimeout =
       e->GetMethodID(cls.get(), "notifyCommandTimeout", "()V");
 
+  gCachedNfcManagerNotifyObserveModeChanged =
+      e->GetMethodID(cls.get(), "notifyObserveModeChanged", "(Z)V");
+
+  gCachedNfcManagerNotifyRfDiscoveryEvent =
+      e->GetMethodID(cls.get(), "notifyRFDiscoveryEvent", "(Z)V");
+
   if (nfc_jni_cache_object(e, gNativeNfcTagClassName, &(nat->cached_NfcTag)) ==
       -1) {
     LOG(ERROR) << StringPrintf("%s: fail cache NativeNfcTag", __func__);
@@ -818,6 +884,12 @@ void nfaDeviceManagementCallback(uint8_t dmEvent,
         PowerSwitch::getInstance().abort();
 
         if (!sIsDisabling && sIsNfaEnabled) {
+          if (gIsDtaEnabled == true) {
+            LOG(DEBUG) << StringPrintf("%s: DTA; unset dta flag in core stack",
+                                       __func__);
+            NFA_DisableDtamode();
+          }
+
           NFA_Disable(FALSE);
           sIsDisabling = true;
         } else {
@@ -984,9 +1056,7 @@ void static nfaVSCallback(uint8_t event, uint16_t param_len, uint8_t* p_param) {
         case NCI_ANDROID_GET_CAPS: {
           gVSCmdStatus = p_param[4];
           SyncEventGuard guard(gNfaVsCommand);
-          u_int16_t android_version = *(u_int16_t*)&p_param[5];
-          u_int8_t len = p_param[7];
-          gCaps.assign(p_param + 8, p_param + 8 + len);
+          gCaps.assign(p_param + 8, p_param + param_len);
           gNfaVsCommand.notifyOne();
         } break;
         case NCI_ANDROID_POLLING_FRAME_NTF: {
@@ -1056,6 +1126,22 @@ void static nfaVSCallback(uint8_t event, uint16_t param_len, uint8_t* p_param) {
   }
 }
 
+static void nfcManager_injectNtf(JNIEnv* e, jobject, jbyteArray data) {
+  ScopedByteArrayRO bytes(e, data);
+  size_t bufLen = bytes.size();
+  tNFC_HAL_EVT_MSG* p_msg;
+  p_msg = (tNFC_HAL_EVT_MSG*)GKI_getbuf(sizeof(tNFC_HAL_EVT_MSG) + bufLen + 1);
+  if (p_msg != NULL) {
+    p_msg->hdr.len = bufLen + 3;
+    p_msg->hdr.event = BT_EVT_TO_NFC_NCI;
+    p_msg->hdr.offset = sizeof(tNFC_HAL_EVT_MSG) - 7;
+    p_msg->hdr.layer_specific = 0;
+    memcpy(((uint8_t*)p_msg) + sizeof(tNFC_HAL_EVT_MSG) + 1, bytes.get(),
+           bufLen);
+    GKI_send_msg(NFC_TASK, NFC_MBOX_ID, p_msg);
+  }
+}
+
 static jboolean isObserveModeSupported(JNIEnv* e, jobject o) {
   ScopedLocalRef<jclass> cls(e, e->GetObjectClass(o));
   jmethodID isSupported =
@@ -1100,12 +1186,21 @@ static void nfaSendRawVsCmdCallback(uint8_t event, uint16_t param_len,
   gNfaVsCommand.notifyOne();
 }
 
+bool isObserveModeSupportedWithoutRfDeactivation(JNIEnv* e, jobject o) {
+  ScopedLocalRef<jclass> cls(e, e->GetObjectClass(o));
+  jmethodID isSupported = e->GetMethodID(
+      cls.get(), "isObserveModeSupportedWithoutRfDeactivation", "()Z");
+  return e->CallBooleanMethod(o, isSupported);
+}
+
 static jboolean nfcManager_setObserveMode(JNIEnv* e, jobject o,
                                           jboolean enable) {
   if (isObserveModeSupported(e, o) == JNI_FALSE) {
     return false;
   }
 
+  bool needToTurnOffRadio = !isObserveModeSupportedWithoutRfDeactivation(e, o);
+
   if ((gObserveModeEnabled == enable) &&
       ((enable != JNI_FALSE) ==
        (nfcManager_isObserveModeEnabled(e, o) != JNI_FALSE))) {
@@ -1116,7 +1211,7 @@ static jboolean nfcManager_setObserveMode(JNIEnv* e, jobject o,
     return true;
   }
   bool reenbleDiscovery = false;
-  if (sRfEnabled) {
+  if (sRfEnabled && needToTurnOffRadio) {
     startRfDiscovery(false);
     reenbleDiscovery = true;
   }
@@ -1157,7 +1252,13 @@ static jboolean nfcManager_setObserveMode(JNIEnv* e, jobject o,
       "%s: Set observe mode to %s with result %x, observe mode is now %s.",
       __FUNCTION__, (enable != JNI_FALSE ? "TRUE" : "FALSE"), gVSCmdStatus,
       (gObserveModeEnabled ? "enabled" : "disabled"));
-  return gObserveModeEnabled == enable;
+  if (gObserveModeEnabled == enable) {
+    e->CallVoidMethod(o, android::gCachedNfcManagerNotifyObserveModeChanged,
+                      enable);
+    return true;
+  } else {
+    return false;
+  }
 }
 
 /*******************************************************************************
@@ -1231,6 +1332,48 @@ static jint nfcManager_getLfT3tMax(JNIEnv*, jobject) {
   return sLfT3tMax;
 }
 
+/*******************************************************************************
+**
+** Function:        doPartialInit
+**
+** Description:     Partial Nfc initialization based on mode set
+**	            ENABLE_MODE_TRANSPARENT : Minimum initialization to allow
+**                                 NFCC transport
+**	            ENABLE_MODE_EE : Minimum Initialization to allow card
+**                                 emulation operation
+**
+** Returns:         True if ok.
+**
+*******************************************************************************/
+static jboolean doPartialInit() {
+  LOG(DEBUG) << StringPrintf("%s: enter", __func__);
+  tNFA_STATUS stat = NFA_STATUS_OK;
+
+  NfcAdaptation& theInstance = NfcAdaptation::GetInstance();
+  theInstance.Initialize();  // start GKI, NCI task, NFC task
+
+  {
+    SyncEventGuard guard(sNfaEnableEvent);
+    tHAL_NFC_ENTRY* halFuncEntries = theInstance.GetHalEntryFuncs();
+    NFA_Partial_Init(halFuncEntries, gPartialInitMode);
+    LOG(DEBUG) << StringPrintf("%s: calling enable", __func__);
+    stat = NFA_Enable(nfaDeviceManagementCallback, nfaConnectionCallback);
+    if (stat == NFA_STATUS_OK) {
+      sNfaEnableEvent.wait();  // wait for NFA command to finish
+    }
+    NFA_SetNfccMode(ENABLE_MODE_DEFAULT);
+  }
+
+  // sIsNfaEnabled indicates whether stack started successfully
+  if (!sIsNfaEnabled) {
+    NFA_Disable(false /* ungraceful */);
+    theInstance.Finalize();
+    return JNI_FALSE;
+  }
+  LOG(DEBUG) << StringPrintf("%s: exit", __func__);
+  return JNI_TRUE;
+}
+
 /*******************************************************************************
 **
 ** Function:        nfcManager_doInitialize
@@ -1253,7 +1396,9 @@ static jboolean nfcManager_doInitialize(JNIEnv* e, jobject o) {
     LOG(DEBUG) << StringPrintf("%s: already enabled", __func__);
     goto TheEnd;
   }
-
+  if (gPartialInitMode != ENABLE_MODE_DEFAULT) {
+    return doPartialInit();
+  }
   powerSwitch.initialize(PowerSwitch::FULL_POWER);
 
   {
@@ -1267,6 +1412,13 @@ static jboolean nfcManager_doInitialize(JNIEnv* e, jobject o) {
 
       NFA_Init(halFuncEntries);
 
+      if (gIsDtaEnabled == true) {
+        // Allows to set appl_dta_mode_flag
+        LOG(DEBUG) << StringPrintf("%s: DTA; set dta flag in core stack",
+                                   __func__);
+        NFA_EnableDtamode((tNFA_eDtaModes)NFA_DTA_APPL_MODE);
+      }
+
       stat = NFA_Enable(nfaDeviceManagementCallback, nfaConnectionCallback);
       if (stat == NFA_STATUS_OK) {
         sNfaEnableEvent.wait();  // wait for NFA command to finish
@@ -1286,17 +1438,6 @@ static jboolean nfcManager_doInitialize(JNIEnv* e, jobject o) {
         /////////////////////////////////////////////////////////////////////////////////
         // Add extra configuration here (work-arounds, etc.)
 
-        if (gIsDtaEnabled == true) {
-          uint8_t configData = 0;
-          configData = 0x01; /* Poll NFC-DEP : Highest Available Bit Rates */
-          NFA_SetConfig(NCI_PARAM_ID_BITR_NFC_DEP, sizeof(uint8_t),
-                        &configData);
-          configData = 0x0B; /* Listen NFC-DEP : Waiting Time */
-          NFA_SetConfig(NFC_PMID_WT, sizeof(uint8_t), &configData);
-          configData = 0x0F; /* Specific Parameters for NFC-DEP RF Interface */
-          NFA_SetConfig(NCI_PARAM_ID_NFC_DEP_OP, sizeof(uint8_t), &configData);
-        }
-
         struct nfc_jni_native_data* nat = getNative(e, o);
         if (nat) {
           nat->tech_mask =
@@ -1339,6 +1480,12 @@ static jboolean nfcManager_doInitialize(JNIEnv* e, jobject o) {
       }
     }
 
+    if (gIsDtaEnabled == true) {
+      LOG(DEBUG) << StringPrintf("%s: DTA; unset dta flag in core stack",
+                                 __func__);
+      NFA_DisableDtamode();
+    }
+
     LOG(ERROR) << StringPrintf("%s: fail nfa enable; error=0x%X", __func__,
                                stat);
 
@@ -1360,11 +1507,17 @@ TheEnd:
   return sIsNfaEnabled ? JNI_TRUE : JNI_FALSE;
 }
 
+static void nfcManager_doSetPartialInitMode(JNIEnv*, jobject, jint mode) {
+  gPartialInitMode = mode;
+}
+
 static void nfcManager_doEnableDtaMode(JNIEnv*, jobject) {
+  LOG(DEBUG) << StringPrintf("%s: enter", __func__);
   gIsDtaEnabled = true;
 }
 
 static void nfcManager_doDisableDtaMode(JNIEnv*, jobject) {
+  LOG(DEBUG) << StringPrintf("%s: enter", __func__);
   gIsDtaEnabled = false;
 }
 
@@ -1537,6 +1690,39 @@ TheEnd:
   LOG(DEBUG) << StringPrintf("%s: exit: Status = 0x%X", __func__, status);
 }
 
+/*******************************************************************************
+**
+** Function:        doPartialDeinit
+**
+** Description:     Partial DeInit for mode TRANSPARENT, CE ..
+**
+** Returns:         True if ok.
+**
+*******************************************************************************/
+static jboolean doPartialDeinit() {
+  LOG(DEBUG) << StringPrintf("%s: enter", __func__);
+  tNFA_STATUS stat = NFA_STATUS_OK;
+  sIsDisabling = true;
+  if (sIsNfaEnabled) {
+    SyncEventGuard guard(sNfaDisableEvent);
+    stat = NFA_Disable(TRUE /* graceful */);
+    if (stat == NFA_STATUS_OK) {
+      LOG(DEBUG) << StringPrintf("%s: wait for completion", __func__);
+      sNfaDisableEvent.wait();  // wait for NFA command to finish
+    } else {
+      LOG(ERROR) << StringPrintf("%s: fail disable; error=0x%X", __func__,
+                                 stat);
+    }
+  }
+  sIsDisabling = false;
+
+  NfcAdaptation& theInstance = NfcAdaptation::GetInstance();
+  LOG(DEBUG) << StringPrintf("%s: exit", __func__);
+  theInstance.Finalize();
+
+  return stat == NFA_STATUS_OK ? JNI_TRUE : JNI_FALSE;
+}
+
 /*******************************************************************************
 **
 ** Function:        nfcManager_doDeinitialize
@@ -1550,7 +1736,9 @@ TheEnd:
 *******************************************************************************/
 static jboolean nfcManager_doDeinitialize(JNIEnv*, jobject) {
   LOG(DEBUG) << StringPrintf("%s: enter", __func__);
-
+  if (gPartialInitMode != ENABLE_MODE_DEFAULT) {
+    return doPartialDeinit();
+  }
   sIsDisabling = true;
 
   if (!recovery_option || !sIsRecovering) {
@@ -1561,6 +1749,13 @@ static jboolean nfcManager_doDeinitialize(JNIEnv*, jobject) {
 
   if (sIsNfaEnabled) {
     SyncEventGuard guard(sNfaDisableEvent);
+
+    if (gIsDtaEnabled == true) {
+      LOG(DEBUG) << StringPrintf("%s: DTA; unset dta flag in core stack",
+                                 __func__);
+      NFA_DisableDtamode();
+    }
+
     tNFA_STATUS stat = NFA_Disable(TRUE /* graceful */);
     if (stat == NFA_STATUS_OK) {
       LOG(DEBUG) << StringPrintf("%s: wait for completion", __func__);
@@ -2013,10 +2208,10 @@ static void nfcManager_updateIsoDepProtocolRoute(JNIEnv* e, jobject o,
   RoutingManager::getInstance().updateIsoDepProtocolRoute(route);
 }
 
-static void nfcManager_updateTechnologyABRoute(JNIEnv* e, jobject o,
-                                               jint route) {
+static void nfcManager_updateTechnologyABFRoute(JNIEnv* e, jobject o,
+                                                jint route) {
   LOG(DEBUG) << StringPrintf("%s: clearFlags=0x%X", __func__, route);
-  RoutingManager::getInstance().updateTechnologyABRoute(route);
+  RoutingManager::getInstance().updateTechnologyABFRoute(route);
 }
 
 /*******************************************************************************
@@ -2103,6 +2298,11 @@ static void ncfManager_nativeEnableVendorNciNotifications(JNIEnv* env,
   sEnableVendorNciNotifications = (enable == JNI_TRUE);
 }
 
+static jobject nfcManager_dofetchActiveNfceeList(JNIEnv* e, jobject o) {
+  (void)o;
+  return NfceeManager::getInstance().getActiveNfceeList(e);
+}
+
 static jobject nfcManager_nativeSendRawVendorCmd(JNIEnv* env, jobject o,
                                                  jint mt, jint gid, jint oid,
                                                  jbyteArray payload) {
@@ -2123,13 +2323,10 @@ static jobject nfcManager_nativeSendRawVendorCmd(JNIEnv* env, jobject o,
   std::vector<uint8_t> command;
   command.push_back((uint8_t)((mt << NCI_MT_SHIFT) | gid));
   command.push_back((uint8_t)oid);
+  command.push_back((uint8_t)payloaBytes.size());
   if (payloaBytes.size() > 0) {
-    command.push_back((uint8_t)payloaBytes.size());
     command.insert(command.end(), &payloaBytes[0],
                    &payloaBytes[payloaBytes.size()]);
-  } else {
-    return env->NewObject(cls.get(), responseConstructor, mStatus, resGid,
-                          resOid, resPayload);
   }
 
   SyncEventGuard guard(gSendRawVsCmdEvent);
@@ -2186,6 +2383,8 @@ static JNINativeMethod gMethods[] = {
 
     {"doInitialize", "()Z", (void*)nfcManager_doInitialize},
 
+    {"doSetPartialInitMode", "(I)V", (void*)nfcManager_doSetPartialInitMode},
+
     {"doDeinitialize", "()Z", (void*)nfcManager_doDeinitialize},
 
     {"sendRawFrame", "([B)Z", (void*)nfcManager_sendRawFrame},
@@ -2256,7 +2455,8 @@ static JNINativeMethod gMethods[] = {
     {"setIsoDepProtocolRoute", "(I)V",
      (void*)nfcManager_updateIsoDepProtocolRoute},
 
-    {"setTechnologyABRoute", "(I)V", (void*)nfcManager_updateTechnologyABRoute},
+    {"setTechnologyABFRoute", "(I)V",
+     (void*)nfcManager_updateTechnologyABFRoute},
 
     {"setDiscoveryTech", "(II)V", (void*)nfcManager_setDiscoveryTech},
 
@@ -2264,9 +2464,13 @@ static JNINativeMethod gMethods[] = {
     {"nativeSendRawVendorCmd", "(III[B)Lcom/android/nfc/NfcVendorNciResponse;",
      (void*)nfcManager_nativeSendRawVendorCmd},
 
+    {"dofetchActiveNfceeList", "()Ljava/util/List;",
+     (void*)nfcManager_dofetchActiveNfceeList},
+
     {"getProprietaryCaps", "()[B", (void*)nfcManager_getProprietaryCaps},
     {"enableVendorNciNotifications", "(Z)V",
      (void*)ncfManager_nativeEnableVendorNciNotifications},
+    {"injectNtf", "([B)V", (void*)nfcManager_injectNtf},
 };
 
 /*******************************************************************************
diff --git a/nci/jni/NativeNfcTag.cpp b/nci/jni/NativeNfcTag.cpp
index 53e1fb41..1c5aff0e 100644
--- a/nci/jni/NativeNfcTag.cpp
+++ b/nci/jni/NativeNfcTag.cpp
@@ -127,6 +127,7 @@ static int sPresCheckErrCnt = 0;
 static int sPresCheckStatus = 0;
 static int reSelect(tNFA_INTF_TYPE rfInterface, bool fSwitchIfNeeded);
 static bool switchRfInterface(tNFA_INTF_TYPE rfInterface);
+extern bool gIsDtaEnabled;
 
 /*******************************************************************************
 **
@@ -578,6 +579,14 @@ static int reSelect(tNFA_INTF_TYPE rfInterface, bool fSwitchIfNeeded) {
     return 0;  // success
   }
 
+  if (gIsDtaEnabled == true) {
+    LOG(DEBUG) << StringPrintf("%s: DTA; bypass reselection of T2T or T4T tag",
+                               __func__);
+    sRfInterfaceMutex.unlock();
+    return 0;  // success
+  } else
+    LOG(DEBUG) << StringPrintf("%s: DTA; bypass flag not set", __func__);
+
   NfcTag& natTag = NfcTag::getInstance();
 
   tNFA_STATUS status = NFA_STATUS_OK;
diff --git a/nci/jni/NfceeManager.cpp b/nci/jni/NfceeManager.cpp
new file mode 100644
index 00000000..0278de39
--- /dev/null
+++ b/nci/jni/NfceeManager.cpp
@@ -0,0 +1,155 @@
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
+#include "NfceeManager.h"
+
+#include <android-base/logging.h>
+#include <android-base/stringprintf.h>
+#include <errno.h>
+#include <nativehelper/ScopedLocalRef.h>
+
+#include "nfc_config.h"
+
+using android::base::StringPrintf;
+
+NfceeManager NfceeManager::sNfceeManager;
+
+/*******************************************************************************
+**
+** Function:        NfceeManager
+**
+** Description:     Initialize member variables.
+**
+** Returns:         None
+**
+*******************************************************************************/
+NfceeManager::NfceeManager() : mNumEePresent(0) {
+  mActualNumEe = MAX_NUM_NFCEE;
+  eseName = "eSE";
+  uiccName = "SIM";
+  memset(&mNfceeData_t, 0, sizeof(mNfceeData));
+}
+
+/*******************************************************************************
+**
+** Function:        ~NfceeManager
+**
+** Description:     Release all resources.
+**
+** Returns:         None
+**
+*******************************************************************************/
+NfceeManager::~NfceeManager() {}
+
+/*******************************************************************************
+**
+** Function:        getInstance
+**
+** Description:     Get the singleton of this object.
+**
+** Returns:         Reference to this object.
+**
+*******************************************************************************/
+NfceeManager& NfceeManager::getInstance() { return sNfceeManager; }
+
+/*******************************************************************************
+**
+** Function:        getActiveNfceeList
+**
+** Description:     Get the list of Activated NFCEE.
+**                  e: Java Virtual Machine.
+**
+** Returns:         List of Activated NFCEE.
+**
+*******************************************************************************/
+jobject NfceeManager::getActiveNfceeList(JNIEnv* e) {
+  ScopedLocalRef<jclass> listClass(e, e->FindClass(mArrayListClassName));
+  jmethodID listConstructor = e->GetMethodID(listClass.get(), "<init>", "()V");
+  jmethodID listAdd =
+      e->GetMethodID(listClass.get(), "add", "(Ljava/lang/Object;)Z");
+  jobject nfceeListObj = e->NewObject(listClass.get(), listConstructor);
+  if (!getNFCEeInfo()) return (nfceeListObj);
+
+  vector<uint8_t> eSERoute;
+  vector<uint8_t> uiccRoute;
+  map<uint8_t, std::string> nfceeMap;
+
+  if (NfcConfig::hasKey(NAME_OFFHOST_ROUTE_ESE)) {
+    eSERoute = NfcConfig::getBytes(NAME_OFFHOST_ROUTE_ESE);
+  }
+
+  if (NfcConfig::hasKey(NAME_OFFHOST_ROUTE_UICC)) {
+    uiccRoute = NfcConfig::getBytes(NAME_OFFHOST_ROUTE_UICC);
+  }
+
+  for (uint8_t i = 0; i < eSERoute.size(); ++i) {
+    nfceeMap[eSERoute[i]] = eseName + std::to_string(i + 1);
+  }
+
+  for (uint8_t i = 0; i < uiccRoute.size(); ++i) {
+    nfceeMap[uiccRoute[i]] = uiccName + std::to_string(i + 1);
+  }
+
+  for (int i = 0; i < mNfceeData_t.mNfceePresent; i++) {
+    uint8_t id = (mNfceeData_t.mNfceeID[i] & ~NFA_HANDLE_GROUP_EE);
+    uint8_t status = mNfceeData_t.mNfceeStatus[i];
+    if ((nfceeMap.find(id) != nfceeMap.end()) &&
+        (status == NFC_NFCEE_STATUS_ACTIVE)) {
+      jstring element = e->NewStringUTF(nfceeMap[id].c_str());
+      e->CallBooleanMethod(nfceeListObj, listAdd, element);
+      e->DeleteLocalRef(element);
+    }
+  }
+  return nfceeListObj;
+}
+
+/*******************************************************************************
+**
+** Function:        getNFCEeInfo
+**
+** Description:     Get latest information about execution
+**                  environments from stack.
+** Returns:         True if at least 1 EE is available.
+**
+*******************************************************************************/
+bool NfceeManager::getNFCEeInfo() {
+  static const char fn[] = "getNFCEeInfo";
+  LOG(INFO) << StringPrintf("%s: enter", fn);
+  tNFA_STATUS nfaStat = NFA_STATUS_FAILED;
+  mNumEePresent = 0x00;
+  memset(&mNfceeData_t, 0, sizeof(mNfceeData_t));
+
+  /* Reading latest NFCEE info  in case it is updated */
+  if ((nfaStat = NFA_EeGetInfo(&mActualNumEe, mEeInfo)) != NFA_STATUS_OK) {
+    LOG(ERROR) << StringPrintf("%s: fail get info; error=0x%X", fn, nfaStat);
+    mActualNumEe = 0;
+  } else {
+    LOG(INFO) << StringPrintf("%s: num NFCEE discovered: %u", fn, mActualNumEe);
+    if (mActualNumEe != 0) {
+      for (uint8_t xx = 0; xx < mActualNumEe; xx++) {
+        if (mEeInfo[xx].ee_interface[0] != NCI_NFCEE_INTERFACE_HCI_ACCESS)
+          mNumEePresent++;
+
+        mNfceeData_t.mNfceeID[xx] = mEeInfo[xx].ee_handle;
+        mNfceeData_t.mNfceeStatus[xx] = mEeInfo[xx].ee_status;
+      }
+    }
+  }
+  LOG(INFO) << StringPrintf("%s: exit; mActualNumEe=%d, mNumEePresent=%d", fn,
+                            mActualNumEe, mNumEePresent);
+  mNfceeData_t.mNfceePresent = mNumEePresent;
+  return (mActualNumEe != 0);
+}
diff --git a/nci/jni/NfceeManager.h b/nci/jni/NfceeManager.h
new file mode 100644
index 00000000..f61ad076
--- /dev/null
+++ b/nci/jni/NfceeManager.h
@@ -0,0 +1,110 @@
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
+#include <map>
+#include <string>
+#include <vector>
+
+#include "NfcJniUtil.h"
+#include "nfa_ee_api.h"
+
+using namespace std;
+
+#define MAX_NUM_NFCEE 0x06
+
+struct mNfceeData {
+  uint16_t mNfceeID[MAX_NUM_NFCEE];
+  tNFA_EE_STATUS mNfceeStatus[MAX_NUM_NFCEE];
+  uint8_t mNfceePresent;
+};
+
+/*****************************************************************************
+**
+**  Name:           NfceeManager
+**
+**  Description:    Manages NFC Execution Environments (NFCEE) by providing
+**                  methods to initialize JNI elements,retrieve active NFCEE
+**                  lists, and fetch NFCEE information from the NFC stack.
+**
+*****************************************************************************/
+class NfceeManager {
+ public:
+  /*******************************************************************************
+  **
+  ** Function:        NfceeManager
+  **
+  ** Description:     Initialize member variables.
+  **
+  ** Returns:         None
+  **
+  *******************************************************************************/
+  NfceeManager();
+
+  /*******************************************************************************
+  **
+  ** Function:        ~NfceeManager
+  **
+  ** Description:     Release all resources.
+  **
+  ** Returns:         None
+  **
+  *******************************************************************************/
+  ~NfceeManager();
+
+  /*******************************************************************************
+  **
+  ** Function:        getInstance
+  **
+  ** Description:     Get the singleton of this object.
+  **
+  ** Returns:         Reference to this object.
+  **
+  *******************************************************************************/
+  static NfceeManager& getInstance();
+
+  /*******************************************************************************
+  **
+  ** Function:        getActiveNfceeList
+  **
+  ** Description:     Get the list of Activated NFCEE.
+  **                  e: Java Virtual Machine.
+  **
+  ** Returns:         List of Activated NFCEE.
+  **
+  *******************************************************************************/
+  jobject getActiveNfceeList(JNIEnv* e);
+
+  /*******************************************************************************
+  **
+  ** Function:        getNFCEeInfo
+  **
+  ** Description:     Get latest information about execution environments from
+  *stack.
+  **
+  ** Returns:         True if at least 1 EE is available.
+  **
+  *******************************************************************************/
+  bool getNFCEeInfo();
+
+ private:
+  static NfceeManager sNfceeManager;
+  string eseName;
+  string uiccName;
+  tNFA_EE_INFO mEeInfo[MAX_NUM_NFCEE];
+  uint8_t mNumEePresent;
+  uint8_t mActualNumEe;
+  mNfceeData mNfceeData_t;
+  const char* mArrayListClassName = "java/util/ArrayList";
+};
\ No newline at end of file
diff --git a/nci/jni/RoutingManager.cpp b/nci/jni/RoutingManager.cpp
index ed25b153..e7676089 100755
--- a/nci/jni/RoutingManager.cpp
+++ b/nci/jni/RoutingManager.cpp
@@ -707,8 +707,8 @@ void RoutingManager::updateDefaultRoute() {
   }
 }
 
-tNFA_TECHNOLOGY_MASK RoutingManager::updateTechnologyABRoute(int route) {
-  static const char fn[] = "RoutingManager::updateTechnologyABRoute";
+tNFA_TECHNOLOGY_MASK RoutingManager::updateTechnologyABFRoute(int route) {
+  static const char fn[] = "RoutingManager::updateTechnologyABFRoute";
 
   tNFA_STATUS nfaStat;
 
@@ -721,6 +721,14 @@ tNFA_TECHNOLOGY_MASK RoutingManager::updateTechnologyABRoute(int route) {
   else
     LOG(ERROR) << fn << "Fail to clear Tech route";
 
+  nfaStat =
+      NFA_EeClearDefaultTechRouting(mDefaultFelicaRoute, NFA_TECHNOLOGY_MASK_F);
+  if (nfaStat == NFA_STATUS_OK)
+    mRoutingEvent.wait();
+  else
+    LOG(ERROR) << fn << "Fail to clear Default Felica route";
+
+  mDefaultFelicaRoute = route;
   mDefaultOffHostRoute = route;
   return updateEeTechRouteSetting();
 }
@@ -729,9 +737,6 @@ tNFA_TECHNOLOGY_MASK RoutingManager::updateEeTechRouteSetting() {
   static const char fn[] = "RoutingManager::updateEeTechRouteSetting";
   tNFA_TECHNOLOGY_MASK allSeTechMask = 0x00;
 
-  if (mDefaultOffHostRoute == 0 && mDefaultFelicaRoute == 0)
-    return allSeTechMask;
-
   LOG(DEBUG) << fn << ": Number of EE is " << (int)mEeInfo.num_ee;
 
   tNFA_STATUS nfaStat;
@@ -790,6 +795,23 @@ tNFA_TECHNOLOGY_MASK RoutingManager::updateEeTechRouteSetting() {
     }
   }
 
+  if (mDefaultOffHostRoute == NFC_DH_ID) {
+    tNFA_TECHNOLOGY_MASK hostTechMask = 0;
+    LOG(DEBUG) << StringPrintf(
+        "%s: Setting technology route to host with A,B and F type", fn);
+    hostTechMask |= NFA_TECHNOLOGY_MASK_A;
+    hostTechMask |= NFA_TECHNOLOGY_MASK_B;
+    hostTechMask |= NFA_TECHNOLOGY_MASK_F;
+    hostTechMask &= mHostListenTechMask;
+    nfaStat = NFA_EeSetDefaultTechRouting(NFC_DH_ID, hostTechMask, 0, 0,
+                                          mSecureNfcEnabled ? 0 : hostTechMask,
+                                          mSecureNfcEnabled ? 0 : hostTechMask,
+                                          mSecureNfcEnabled ? 0 : hostTechMask);
+    if (nfaStat != NFA_STATUS_OK)
+      LOG(ERROR) << fn << "Failed to configure DH technology routing.";
+    return hostTechMask;
+  }
+
   // Clear DH technology route on NFC-A
   if ((mHostListenTechMask & NFA_TECHNOLOGY_MASK_A) &&
       (allSeTechMask & NFA_TECHNOLOGY_MASK_A) != 0) {
diff --git a/nci/jni/RoutingManager.h b/nci/jni/RoutingManager.h
index 8a689407..01198ab0 100755
--- a/nci/jni/RoutingManager.h
+++ b/nci/jni/RoutingManager.h
@@ -48,7 +48,7 @@ class RoutingManager {
   void updateRoutingTable();
   void eeSetPwrAndLinkCtrl(uint8_t config);
   void updateIsoDepProtocolRoute(int route);
-  tNFA_TECHNOLOGY_MASK updateTechnologyABRoute(int route);
+  tNFA_TECHNOLOGY_MASK updateTechnologyABFRoute(int route);
   void clearRoutingEntry(int clearFlags);
   void setEeTechRouteUpdateRequired();
 
diff --git a/nci/src/com/android/nfc/dhimpl/NativeNfcManager.java b/nci/src/com/android/nfc/dhimpl/NativeNfcManager.java
index aacbce45..c994d6b6 100755
--- a/nci/src/com/android/nfc/dhimpl/NativeNfcManager.java
+++ b/nci/src/com/android/nfc/dhimpl/NativeNfcManager.java
@@ -26,6 +26,7 @@ import android.nfc.tech.Ndef;
 import android.nfc.tech.TagTechnology;
 import android.os.Bundle;
 import android.os.Trace;
+import android.sysprop.NfcProperties;
 import android.util.Log;
 
 import com.android.nfc.DeviceHost;
@@ -35,12 +36,14 @@ import com.android.nfc.NfcStatsLog;
 import com.android.nfc.NfcVendorNciResponse;
 import com.android.nfc.NfcProprietaryCaps;
 import java.io.FileDescriptor;
+import java.io.PrintWriter;
 import java.nio.ByteBuffer;
 import java.nio.ByteOrder;
 import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.HashMap;
 import java.util.Iterator;
+import java.util.List;
 
 /** Native interface to the NFC Manager functions */
 public class NativeNfcManager implements DeviceHost {
@@ -97,8 +100,7 @@ public class NativeNfcManager implements DeviceHost {
     @Override
     public boolean initialize() {
         boolean ret = doInitialize();
-        if (mContext.getResources().getBoolean(
-                com.android.nfc.R.bool.nfc_proprietary_getcaps_supported)) {
+        if (isProprietaryGetCapsSupported()) {
             mProprietaryCaps = NfcProprietaryCaps.createFromByteArray(getProprietaryCaps());
             Log.i(TAG, "mProprietaryCaps: " + mProprietaryCaps);
             logProprietaryCaps(mProprietaryCaps);
@@ -107,6 +109,22 @@ public class NativeNfcManager implements DeviceHost {
         return ret;
     }
 
+    boolean isObserveModeSupportedWithoutRfDeactivation() {
+        if (!com.android.nfc.flags.Flags.observeModeWithoutRf()) {
+            return false;
+        }
+        return mProprietaryCaps != null &&
+                mProprietaryCaps.getPassiveObserveMode() ==
+                        NfcProprietaryCaps.PassiveObserveMode.SUPPORT_WITHOUT_RF_DEACTIVATION;
+    }
+
+    private native void doSetPartialInitMode(int mode);
+
+    @Override
+    public void setPartialInitMode(int mode) {
+        doSetPartialInitMode(mode);
+    }
+
     private native void doEnableDtaMode();
 
     @Override
@@ -169,6 +187,19 @@ public class NativeNfcManager implements DeviceHost {
 
     public native int doRegisterT3tIdentifier(byte[] t3tIdentifier);
 
+    /**
+     * Injects a NTF to the HAL.
+     *
+     * This is only used for testing.
+     */
+    public native void injectNtf(byte[] data);
+
+    public boolean isProprietaryGetCapsSupported() {
+        return mContext.getResources()
+                .getBoolean(com.android.nfc.R.bool.nfc_proprietary_getcaps_supported)
+                && NfcProperties.get_caps_supported().orElse(true);
+    }
+
     @Override
     public boolean isObserveModeSupported() {
         if (!android.nfc.Flags.nfcObserveMode()) {
@@ -180,8 +211,10 @@ public class NativeNfcManager implements DeviceHost {
                 com.android.nfc.R.bool.nfc_observe_mode_supported)) {
             return false;
         }
-        if (mContext.getResources().getBoolean(
-                com.android.nfc.R.bool.nfc_proprietary_getcaps_supported)) {
+        if (!NfcProperties.observe_mode_supported().orElse(true)) {
+            return false;
+        }
+        if (isProprietaryGetCapsSupported()) {
             return isObserveModeSupportedCaps(mProprietaryCaps);
         }
         return true;
@@ -321,7 +354,8 @@ public class NativeNfcManager implements DeviceHost {
     private native void doDump(FileDescriptor fd);
 
     @Override
-    public void dump(FileDescriptor fd) {
+    public void dump(PrintWriter pw, FileDescriptor fd) {
+        pw.println("Native Proprietary Caps=" + mProprietaryCaps);
         doDump(fd);
     }
 
@@ -354,6 +388,9 @@ public class NativeNfcManager implements DeviceHost {
 
     public native boolean isMultiTag();
 
+    @Override
+    public native List<String> dofetchActiveNfceeList();
+
     private native NfcVendorNciResponse nativeSendRawVendorCmd(
             int mt, int gid, int oid, byte[] payload);
 
@@ -414,6 +451,12 @@ public class NativeNfcManager implements DeviceHost {
         final int TLV_gain_offset = 7;
         final int TLV_data_offset = 8;
         ArrayList<PollingFrame> frames = new ArrayList<PollingFrame>();
+        if (data_len >= TLV_header_len) {
+            int tlv_len = Byte.toUnsignedInt(p_data[TLV_len_offset]) + TLV_header_len;
+            if (tlv_len < data_len) {
+                data_len = tlv_len;
+            }
+        }
         while (pos + TLV_len_offset < data_len) {
             @PollingFrame.PollingFrameType int frameType;
             Bundle frame = new Bundle();
@@ -489,6 +532,10 @@ public class NativeNfcManager implements DeviceHost {
         }
     }
 
+    private void notifyRFDiscoveryEvent(boolean isDiscoveryStarted) {
+        mListener.onRfDiscoveryEvent(isDiscoveryStarted);
+    }
+
     @Override
     public native void setDiscoveryTech(int pollTech, int listenTech);
 
@@ -502,7 +549,7 @@ public class NativeNfcManager implements DeviceHost {
     public native void setIsoDepProtocolRoute(int route);
 
     @Override
-    public native void setTechnologyABRoute(int route);
+    public native void setTechnologyABFRoute(int route);
 
     private native byte[] getProprietaryCaps();
 
@@ -547,4 +594,8 @@ public class NativeNfcManager implements DeviceHost {
                 proprietaryCaps.isPowerSavingModeSupported(),
                 proprietaryCaps.isAutotransactPollingLoopFilterSupported());
     }
+
+    public void notifyObserveModeChanged(boolean enabled) {
+        mListener.onObserveModeStateChanged(enabled);
+    }
 }
diff --git a/proto/event.proto b/proto/event.proto
index 589ce163..0aca4529 100644
--- a/proto/event.proto
+++ b/proto/event.proto
@@ -40,6 +40,14 @@ message EventType {
     NfcCeUnroutableAid ce_unroutable_aid = 4;
     NfcObserveModeChange observe_mode_change = 5;
     NfcWalletRoleHolderChange wallet_role_holder_change = 6;
+    NfcHostCardEmulationStateChange host_card_emulation_state_change = 7;
+    NfcHostCardEmulationData host_card_emulation_data = 8;
+    NfcRemoteFieldStateChange remote_field_state_change = 9;
+    NfcDiscoveryTechnologyUpdate discovery_technology_update = 10;
+    NfcSecureChange secure_change = 11;
+    NfcWlcStateChange wlc_state_change = 12;
+    NfcReaderOptionChange reader_option_change = 13;
+    NfcClearPreference clear_preference = 14;
   }
 }
 
@@ -75,4 +83,39 @@ message NfcObserveModeChange {
 
 message NfcWalletRoleHolderChange {
   optional string package_name = 1;
-}
\ No newline at end of file
+}
+
+message NfcHostCardEmulationStateChange {
+  required int32 technology = 1;
+  required bool enable = 2;
+}
+
+message NfcHostCardEmulationData {
+  required int32 technology = 1;
+  required bytes data = 2;
+}
+
+message NfcRemoteFieldStateChange {
+  required bool enable = 1;
+}
+
+message NfcDiscoveryTechnologyUpdate {
+  required NfcAppInfo app_info = 1;
+  required int32 poll_tech = 2;
+  required int32 listen_tech = 3;
+}
+
+message NfcSecureChange {
+  required bool enable = 1;
+}
+
+message NfcWlcStateChange {
+  required bool enable = 1;
+}
+
+message NfcReaderOptionChange {
+  required bool enable = 1;
+  required NfcAppInfo app_info = 2;
+}
+
+message NfcClearPreference {}
diff --git a/res/drawable/nfc_icon.xml b/res/drawable/nfc_icon.xml
index 77047d6a..3c91c8ce 100644
--- a/res/drawable/nfc_icon.xml
+++ b/res/drawable/nfc_icon.xml
@@ -1,23 +1,252 @@
-<?xml version="1.0" encoding="utf-8"?>
-<vector xmlns:android="http://schemas.android.com/apk/res/android"
-        android:width="32dp"
-        android:height="32dp"
-        android:viewportWidth="24"
-        android:viewportHeight="24">
-    <path
-        android:fillColor="@color/nfc_icon"
-        android:fillType="evenOdd"
-        android:pathData="M5.76634 12.5029C5.76641 12.4896 5.76693 12.4766 5.76693 12.4633C5.76693 10.7155 5.16371 9.45721 4.81296 8.87314C4.69187 8.66237 4.6048 8.54146 4.59219 8.52438C4.25652 8.06704 3.67985 8.02753 3.30426 8.43643C2.92867 8.84525 2.89637 9.54742 3.23211 10.0048C3.23286 10.0058 3.24278 10.0199 3.25905 10.0452L3.25509 10.0498L3.24845 10.0414C3.2542 10.0489 3.28651 10.0931 3.33336 10.1683C3.52742 10.5071 3.93345 11.3531 3.94203 12.5029C3.93286 13.6497 3.52854 14.4938 3.33426 14.8335C3.28695 14.9096 3.2542 14.9543 3.24845 14.9619L3.25502 14.9535L3.25905 14.9582C3.24278 14.9834 3.23293 14.9975 3.23211 14.9986C2.89637 15.4559 2.92875 16.158 3.30426 16.5668C3.67993 16.9756 4.25659 16.9363 4.59226 16.4791C4.60487 16.4618 4.69239 16.3402 4.81408 16.1282C5.16505 15.5432 5.76686 14.2858 5.76686 12.54C5.76686 12.5275 5.76634 12.5153 5.76634 12.5029" />
-    <path
-        android:fillColor="@color/nfc_icon"
-        android:fillType="evenOdd"
-        android:pathData="M8.38344 18.2765C8.15054 18.2765 7.9159 18.2062 7.71664 18.061C7.23389 17.7093 7.1415 17.0509 7.51023 16.5905C7.51866 16.5795 8.7738 14.9387 8.7738 12.2611C8.7738 9.56432 7.49996 7.77608 7.48713 7.75868C7.13572 7.28616 7.25249 6.63128 7.74789 6.2961C8.24329 5.96074 8.92989 6.07221 9.2813 6.5449C9.35041 6.63775 10.9735 8.85943 10.9735 12.2611C10.9735 15.683 9.32832 17.7767 9.25829 17.8641C9.0418 18.1344 8.7145 18.2765 8.38344 18.2765" />
-    <path
-        android:fillColor="@color/nfc_icon"
-        android:fillType="evenOdd"
-        android:pathData="M12.7655 19.7034C12.5162 19.7034 12.2648 19.6377 12.0497 19.5015C11.5198 19.166 11.4111 18.5301 11.807 18.0809C11.8236 18.0616 13.7851 15.7505 13.7851 11.9741C13.7851 8.13613 11.8024 5.66932 11.7824 5.64479C11.4054 5.18424 11.5404 4.55183 12.0839 4.23228C12.6273 3.9129 13.3736 4.02726 13.7505 4.4878C13.8497 4.60909 16.1803 7.50794 16.1803 11.9741C16.1803 16.4598 13.8261 19.1822 13.7259 19.2958C13.4908 19.5626 13.1304 19.7034 12.7655 19.7034" />
-    <path
-        android:fillColor="@color/nfc_icon"
-        android:fillType="evenOdd"
-        android:pathData="M17.4365 22C17.2182 22 16.998 21.9332 16.8097 21.7947C16.3456 21.4536 16.2504 20.8071 16.5971 20.3505C16.618 20.3225 18.9023 17.2117 18.9023 12.127C18.9023 7.01696 16.5972 3.65042 16.5739 3.61697C16.247 3.14791 16.3667 2.50575 16.8427 2.18286C17.3187 1.85997 17.9697 1.97571 18.2992 2.44306C18.4094 2.59947 21 6.34048 21 12.127C21 17.9335 18.3888 21.4393 18.2776 21.5856C18.0717 21.8568 17.756 22 17.4365 22" />
+<vector xmlns:android="http://schemas.android.com/apk/res/android" xmlns:aapt="http://schemas.android.com/aapt"
+    android:viewportWidth="32"
+    android:viewportHeight="32"
+    android:width="32dp"
+    android:height="32dp">
+    <path
+        android:pathData="M16.5 10L19.5 14L16.5 10Z"
+        android:fillColor="#000000"
+        android:fillAlpha="0.9921569"
+        android:strokeColor="#000000"
+        android:strokeAlpha="0.9921569"
+        android:strokeWidth="1" />
+    <path
+        android:pathData="M12.5 18L15.5 22L12.5 18Z"
+        android:fillColor="#000000"
+        android:fillAlpha="0.9921569"
+        android:strokeColor="#000000"
+        android:strokeAlpha="0.9921569"
+        android:strokeWidth="1" />
+    <path
+        android:pathData="M2.5 2Q7 1.5 7 2.5L7 26.5L8 30L2.5 30L2 28.5L1 27.5L1 3.5L2.5 2Z"
+        android:fillColor="#000000"
+        android:strokeColor="#000000"
+        android:strokeWidth="1" />
+    <path
+        android:pathData="M8.5 2L17.5 2L20 4.5L21 6.5L21 20.5L12 13.5Q10.8 20.8 15.5 22L24 29.5L14.5 30L11 25.5L11 11.5L20 18.5Q21.3 11.3 16.5 10L8.5 2Z"
+        android:fillColor="#000000"
+        android:strokeColor="#000000"
+        android:strokeWidth="1" />
+    <path
+        android:pathData="M24 2L29.5 2L30 3.5L31 4.5L31 28.5Q29.6 31.3 25 30L25 6.5L24 2Z"
+        android:fillColor="#000000"
+        android:strokeColor="#000000"
+        android:strokeWidth="1" />
+    <path
+        android:pathData="M0 0L31.5 0L32 3.5L31 3.5L29.5 1L22.5 1L22 2.5L24 5.5L24 27.5L13 17.5L13.5 16L21.5 23L22 6.5L19.5 2L17.5 1L2.5 1L0 2.5L0 0Z"
+        android:fillColor="#000000"
+        android:fillAlpha="0.01568627"
+        android:strokeColor="#000000"
+        android:strokeAlpha="0.01568627"
+        android:strokeWidth="1" />
+    <path
+        android:pathData="M8.5 4L19 15.5L17.5 15L10.5 9L10 25.5L12.5 30L14.5 31L29.5 31L32 29.5L31.5 32L0 32L0.5 28L2.5 31L9.5 31L10 29.5L8 26.5L8.5 4Z"
+        android:fillColor="#000000"
+        android:fillAlpha="0.01568627"
+        android:strokeColor="#000000"
+        android:strokeAlpha="0.01568627"
+        android:strokeWidth="1" />
+    <path
+        android:pathData="M2.5 1L7 1.5L2.5 2L2.5 1Z"
+        android:fillColor="#000000"
+        android:fillAlpha="0.3372549"
+        android:strokeColor="#000000"
+        android:strokeAlpha="0.3372549"
+        android:strokeWidth="1" />
+    <path
+        android:pathData="M22 1L29 1.5L22.5 3L22 1Z"
+        android:fillColor="#000000"
+        android:fillAlpha="0.3372549"
+        android:strokeColor="#000000"
+        android:strokeAlpha="0.3372549"
+        android:strokeWidth="1" />
+    <path
+        android:pathData="M7.5 5L8 20.5L7 20.5L7.5 5Z"
+        android:fillColor="#000000"
+        android:fillAlpha="0.3372549"
+        android:strokeColor="#000000"
+        android:strokeAlpha="0.3372549"
+        android:strokeWidth="1" />
+    <path
+        android:pathData="M14.5 9L20 14.5L20 17.5L19 17.5L19 14.5L14.5 9Z"
+        android:fillColor="#000000"
+        android:fillAlpha="0.3372549"
+        android:strokeColor="#000000"
+        android:strokeAlpha="0.3372549"
+        android:strokeWidth="1" />
+    <path
+        android:pathData="M24.5 13L25 24.5L24 24.5L24.5 13Z"
+        android:fillColor="#000000"
+        android:fillAlpha="0.3372549"
+        android:strokeColor="#000000"
+        android:strokeAlpha="0.3372549"
+        android:strokeWidth="1" />
+    <path
+        android:pathData="M12.5 17L16.5 22L12.5 17Z"
+        android:fillColor="#000000"
+        android:fillAlpha="0.3372549"
+        android:strokeColor="#000000"
+        android:strokeAlpha="0.3372549"
+        android:strokeWidth="1" />
+    <path
+        android:pathData="M9.5 29L10 31L3 30.5L9.5 29Z"
+        android:fillColor="#000000"
+        android:fillAlpha="0.3372549"
+        android:strokeColor="#000000"
+        android:strokeAlpha="0.3372549"
+        android:strokeWidth="1" />
+    <path
+        android:pathData="M25.5 30L30 30.5L25.5 31L25.5 30Z"
+        android:fillColor="#000000"
+        android:fillAlpha="0.3372549"
+        android:strokeColor="#000000"
+        android:strokeAlpha="0.3372549"
+        android:strokeWidth="1" />
+    <path
+        android:pathData="M7.5 1L15 1.5L7.5 2L7.5 1Z"
+        android:fillColor="#000000"
+        android:fillAlpha="0.6431373"
+        android:strokeColor="#000000"
+        android:strokeAlpha="0.6431373"
+        android:strokeWidth="1" />
+    <path
+        android:pathData="M7 3L14 8.5L8.5 4L7 4.5L7 3Z"
+        android:fillColor="#000000"
+        android:fillAlpha="0.6431373"
+        android:strokeColor="#000000"
+        android:strokeAlpha="0.6431373"
+        android:strokeWidth="1" />
+    <path
+        android:pathData="M24.5 7L25 12.5L24 12.5L24.5 7Z"
+        android:fillColor="#000000"
+        android:fillAlpha="0.6431373"
+        android:strokeColor="#000000"
+        android:strokeAlpha="0.6431373"
+        android:strokeWidth="1" />
+    <path
+        android:pathData="M21.5 8L22 10.5L21 10.5L21.5 8Z"
+        android:fillColor="#000000"
+        android:fillAlpha="0.6431373"
+        android:strokeColor="#000000"
+        android:strokeAlpha="0.6431373"
+        android:strokeWidth="1" />
+    <path
+        android:pathData="M10.5 9L14.5 14L10.5 9Z"
+        android:fillColor="#000000"
+        android:fillAlpha="0.6431373"
+        android:strokeColor="#000000"
+        android:strokeAlpha="0.6431373"
+        android:strokeWidth="1" />
+    <path
+        android:pathData="M17.5 18L21.5 23L17.5 18Z"
+        android:fillColor="#000000"
+        android:fillAlpha="0.6431373"
+        android:strokeColor="#000000"
+        android:strokeAlpha="0.6431373"
+        android:strokeWidth="1" />
+    <path
+        android:pathData="M7.5 21L8 24.5L7 24.5L7.5 21Z"
+        android:fillColor="#000000"
+        android:fillAlpha="0.6431373"
+        android:strokeColor="#000000"
+        android:strokeAlpha="0.6431373"
+        android:strokeWidth="1" />
+    <path
+        android:pathData="M10.5 21L11 23.5L10 23.5L10.5 21Z"
+        android:fillColor="#000000"
+        android:fillAlpha="0.6431373"
+        android:strokeColor="#000000"
+        android:strokeAlpha="0.6431373"
+        android:strokeWidth="1" />
+    <path
+        android:pathData="M17.5 22L24 27.5L24.5 25L25 29L23.5 29L17.5 22Z"
+        android:fillColor="#000000"
+        android:fillAlpha="0.6431373"
+        android:strokeColor="#000000"
+        android:strokeAlpha="0.6431373"
+        android:strokeWidth="1" />
+    <path
+        android:pathData="M17.5 30L25 30.5L17.5 31L17.5 30Z"
+        android:fillColor="#000000"
+        android:fillAlpha="0.6431373"
+        android:strokeColor="#000000"
+        android:strokeAlpha="0.6431373"
+        android:strokeWidth="1" />
+    <path
+        android:pathData="M10.5 10L11 13.5L10 13.5L10.5 10Z"
+        android:fillColor="#000000"
+        android:fillAlpha="0.9568627"
+        android:strokeColor="#000000"
+        android:strokeAlpha="0.9568627"
+        android:strokeWidth="1" />
+    <path
+        android:pathData="M21.5 11L22 15.5L21 15.5L21.5 11Z"
+        android:fillColor="#000000"
+        android:fillAlpha="0.9568627"
+        android:strokeColor="#000000"
+        android:strokeAlpha="0.9568627"
+        android:strokeWidth="1" />
+    <path
+        android:pathData="M13.5 14L15.5 14L19 17.5L16.5 18L13.5 14Z"
+        android:fillColor="#000000"
+        android:fillAlpha="0.9568627"
+        android:strokeColor="#000000"
+        android:strokeAlpha="0.9568627"
+        android:strokeWidth="1" />
+    <path
+        android:pathData="M10.5 16L11 20.5L10 20.5L10.5 16Z"
+        android:fillColor="#000000"
+        android:fillAlpha="0.9568627"
+        android:strokeColor="#000000"
+        android:strokeAlpha="0.9568627"
+        android:strokeWidth="1" />
+    <path
+        android:pathData="M21.5 18L22 21.5L21 21.5L21.5 18Z"
+        android:fillColor="#000000"
+        android:fillAlpha="0.9568627"
+        android:strokeColor="#000000"
+        android:strokeAlpha="0.9568627"
+        android:strokeWidth="1" />
+    <path
+        android:pathData="M19.5 2L20.5 4L19.5 2Z"
+        android:fillColor="#000000"
+        android:fillAlpha="0.1607843"
+        android:strokeColor="#000000"
+        android:strokeAlpha="0.1607843"
+        android:strokeWidth="1" />
+    <path
+        android:pathData="M0.5 3L1 27.5L0 27.5L0.5 3Z"
+        android:fillColor="#000000"
+        android:fillAlpha="0.1607843"
+        android:strokeColor="#000000"
+        android:strokeAlpha="0.1607843"
+        android:strokeWidth="1" />
+    <path
+        android:pathData="M31.5 4L32 28.5L31 28.5L31.5 4Z"
+        android:fillColor="#000000"
+        android:fillAlpha="0.1607843"
+        android:strokeColor="#000000"
+        android:strokeAlpha="0.1607843"
+        android:strokeWidth="1" />
+    <path
+        android:pathData="M12 15L15 16.5L12 16.5L12 15Z"
+        android:fillColor="#000000"
+        android:fillAlpha="0.1607843"
+        android:strokeColor="#000000"
+        android:strokeAlpha="0.1607843"
+        android:strokeWidth="1" />
+    <path
+        android:pathData="M17.5 15L18.5 17L17.5 15Z"
+        android:fillColor="#000000"
+        android:fillAlpha="0.1607843"
+        android:strokeColor="#000000"
+        android:strokeAlpha="0.1607843"
+        android:strokeWidth="1" />
+    <path
+        android:pathData="M11.5 28L12.5 30L11.5 28Z"
+        android:fillColor="#000000"
+        android:fillAlpha="0.1607843"
+        android:strokeColor="#000000"
+        android:strokeAlpha="0.1607843"
+        android:strokeWidth="1" />
 </vector>
diff --git a/res/raw/start.ogg b/res/raw/start.ogg
deleted file mode 100644
index 3c4d8c55..00000000
Binary files a/res/raw/start.ogg and /dev/null differ
diff --git a/res/values-be/strings.xml b/res/values-be/strings.xml
index c222dbf3..ee42a242 100644
--- a/res/values-be/strings.xml
+++ b/res/values-be/strings.xml
@@ -13,7 +13,7 @@
     <string name="cancel" msgid="61873902552555096">"Скасаваць"</string>
     <string name="beam_tap_to_view" msgid="7430394753262448349">"Краніце для прагляду"</string>
     <string name="beam_handover_not_supported" msgid="4083165921751489015">"Прылада атрымальніка не падтрымлівае перадачу вялікіх файлаў праз Beam."</string>
-    <string name="beam_try_again" msgid="3364677301009783455">"Зноў аб\'яднаць прылады"</string>
+    <string name="beam_try_again" msgid="3364677301009783455">"Зноў аб’яднаць прылады"</string>
     <string name="beam_busy" msgid="5253335587620612576">"Beam зараз заняты. Паспрабуйце яшчэ раз пасля завяршэння папярэдняй перадачы."</string>
     <string name="device" msgid="4459621591392478151">"прылада"</string>
     <string name="connecting_peripheral" msgid="1296182660525660935">"Падлучаецца <xliff:g id="DEVICE_NAME">%1$s</xliff:g>"</string>
diff --git a/res/values-en-rCA/strings.xml b/res/values-en-rCA/strings.xml
index f34dc73d..bfe4cb26 100644
--- a/res/values-en-rCA/strings.xml
+++ b/res/values-en-rCA/strings.xml
@@ -9,7 +9,7 @@
     <string name="beam_outgoing" msgid="4679536649779123495">"Beaming..."</string>
     <string name="beam_complete" msgid="477026736424637435">"Beam complete"</string>
     <string name="beam_failed" msgid="5116241718189888630">"Beam did not complete"</string>
-    <string name="beam_canceled" msgid="5425192751826544741">"Beam cancelled"</string>
+    <string name="beam_canceled" msgid="5425192751826544741">"Beam canceled"</string>
     <string name="cancel" msgid="61873902552555096">"Cancel"</string>
     <string name="beam_tap_to_view" msgid="7430394753262448349">"Tap to view"</string>
     <string name="beam_handover_not_supported" msgid="4083165921751489015">"The receiver\'s device doesn\'t support large file transfer via beam."</string>
@@ -33,7 +33,7 @@
     <string name="appchooser_description" msgid="2554187931814833244">"Choose app to scan"</string>
     <string name="transaction_failure" msgid="7828102078637936513">"This transaction couldn\'t be completed with <xliff:g id="APP">%1$s</xliff:g>."</string>
     <string name="could_not_use_app" msgid="8137587876138569083">"Couldn\'t use <xliff:g id="APP">%1$s</xliff:g>."</string>
-    <string name="pay_with" msgid="5531545488795798945">"Pay with:"</string>
+    <string name="pay_with" msgid="5531545488795798945">"Pay with"</string>
     <string name="complete_with" msgid="6797459104103012992">"Complete with"</string>
     <string name="default_pay_app_removed" msgid="4108250545457437360">"Your preferred service for tap &amp; pay was removed. Choose another?"</string>
     <string name="ask_nfc_tap" msgid="2925239870458286340">"Tap another device to complete"</string>
@@ -47,8 +47,7 @@
     <string name="beam_requires_external_storage_permission" msgid="8798337545702206901">"Application does not have External Storage Permission. This is required to Beam this file"</string>
     <string name="title_confirm_url_open" msgid="8069968913244794478">"Open link?"</string>
     <string name="summary_confirm_url_open" msgid="1246398412196449226">"Your phone received a link through NFC:"</string>
-    <!-- no translation found for summary_confirm_url_open_tablet (771152442325809851) -->
-    <skip />
+    <string name="summary_confirm_url_open_tablet" msgid="771152442325809851">"Your tablet received a link through NFC:"</string>
     <string name="action_confirm_url_open" msgid="3458322738812921189">"Open link"</string>
     <string name="tag_read_error" msgid="2485274498885877547">"NFC read error. Try again."</string>
     <string name="tag_dispatch_failed" msgid="3562984995049738400">"No supported application for this NFC Tag"</string>
@@ -56,10 +55,7 @@
     <string name="nfc_blocking_alert_message" msgid="7003156052570107490">"Tap to learn how to fix."</string>
     <string name="nfc_logging_alert_title" msgid="5300867034660942987">"NFC data is being recorded"</string>
     <string name="nfc_logging_alert_message" msgid="1550187184825467942">"Tap to stop recording."</string>
-    <!-- no translation found for title_package_enabling_nfc (5736481508428918024) -->
-    <skip />
-    <!-- no translation found for enable_nfc_yes (694867197186062792) -->
-    <skip />
-    <!-- no translation found for enable_nfc_no (6549033065900624599) -->
-    <skip />
+    <string name="title_package_enabling_nfc" msgid="5736481508428918024">"Allow <xliff:g id="PKG">%1$s</xliff:g> to enable NFC?"</string>
+    <string name="enable_nfc_yes" msgid="694867197186062792">"Yes"</string>
+    <string name="enable_nfc_no" msgid="6549033065900624599">"No"</string>
 </resources>
diff --git a/res/values-hy/strings.xml b/res/values-hy/strings.xml
index daad903b..60f29440 100644
--- a/res/values-hy/strings.xml
+++ b/res/values-hy/strings.xml
@@ -11,7 +11,7 @@
     <string name="beam_failed" msgid="5116241718189888630">"Ռադիոհաղորդմամբ գործընթացն ավարտված չէ"</string>
     <string name="beam_canceled" msgid="5425192751826544741">"Ռադիոհաղորդմամբ գործընթացը չեղարկված է"</string>
     <string name="cancel" msgid="61873902552555096">"Չեղարկել"</string>
-    <string name="beam_tap_to_view" msgid="7430394753262448349">"Հպեք՝ դիտելու համար"</string>
+    <string name="beam_tap_to_view" msgid="7430394753262448349">"Հպեք դիտելու համար"</string>
     <string name="beam_handover_not_supported" msgid="4083165921751489015">"Ընդունողի սարքը չի աջակցում ռադիոհաղորդմամբ մեծ ֆայլերի փոխանցումը:"</string>
     <string name="beam_try_again" msgid="3364677301009783455">"Սարքերը կրկին միմյանց հետ կցել"</string>
     <string name="beam_busy" msgid="5253335587620612576">"Այս պահին տվյալների փոխանցումը զբաղված է: Փորձեք կրկին նախորդ փոխանցումը ավարտելուց հետո:"</string>
diff --git a/res/values-night/styles.xml b/res/values-night/styles.xml
index da6e6517..48daf6b2 100644
--- a/res/values-night/styles.xml
+++ b/res/values-night/styles.xml
@@ -15,7 +15,10 @@
 -->
 
 <resources>
-    <style name="DialogAlertDayNight" parent="@android:style/Theme.DeviceDefault.Dialog.Alert"/>
+    <style name="DialogAlertDayNight" parent="@android:style/Theme.DeviceDefault.Dialog.Alert">
+        <item name="android:windowMinWidthMajor">80%</item>
+        <item name="android:windowMinWidthMinor">80%</item>
+    </style>
 
     <style name="TapAgainDayNight" parent="Theme.AppCompat.DayNight">
         <item name="android:fontFamily">google-sans</item>
diff --git a/res/values/config.xml b/res/values/config.xml
index f0ca0ff5..50d44f67 100644
--- a/res/values/config.xml
+++ b/res/values/config.xml
@@ -38,4 +38,25 @@
     <integer name="max_event_log_num">50</integer>
     <!-- Overlay to indicate that the OEM plans to use OEM extension -->
     <bool name="enable_oem_extension">false</bool>
+    <string name="nfc_default_route" translatable="false"></string>
+    <!-- Default ISODEP Route value -->
+    <string name="nfc_default_isodep_route" translatable="false"></string>
+    <!-- Default OffHost Route value -->
+    <string name="nfc_default_offhost_route" translatable="false"></string>
+    <!-- Overlay to enable NFC developer option notification-->
+    <bool name="enable_developer_option_notification">true</bool>
+    <!-- Whether to enable NFC by default on boot or not. -->
+    <bool name="enable_nfc_default">true</bool>
+    <!-- Reader mode should be ON or OFF if reader_option_capable is enabled -->
+    <bool name="reader_option_default">true</bool>
+    <!-- Secure NFC default value-->
+    <bool name="secure_nfc_default">false</bool>
+    <!-- Block list that contains the package names which are not desired to get tag intents -->
+    <string-array name="tag_intent_blocked_app_list" translatable="false" />
+    <!-- Use display state callbacks along with screen on/off intent in determining SCREEN_STATE -->
+    <bool name="check_display_state_for_screen_state">false</bool>
+    <!-- Enable EUICC support for offhost card emulation -->
+    <bool name="enable_euicc_support">false</bool>
+    <!-- Whether to indicate user activity using PowerManager.userActivity for HCE activation -->
+    <bool name="indicate_user_activity_for_hce">true</bool>
 </resources>
diff --git a/res/values/overlayable.xml b/res/values/overlayable.xml
index b14f24b3..1568df46 100644
--- a/res/values/overlayable.xml
+++ b/res/values/overlayable.xml
@@ -46,6 +46,22 @@
             <item name="nfc_proprietary_getcaps_supported" type="bool" />
             <item name="max_event_log_num" type="integer" />
             <item name="enable_oem_extension" type="bool" />
+            <item name="nfc_default_route" type="string"/>
+            <item name="nfc_default_isodep_route" type="string"/>
+            <item name="nfc_default_offhost_route" type="string"/>
+            <item name="enable_developer_option_notification" type="bool" />
+            <!-- Allow list that contains the package name which are allowed to use NFC -->
+            <item name="nfc_allow_list" type="array" />
+            <!-- Whether to enable NFC by default on boot or not. -->
+            <item name="enable_nfc_default" type="bool" />
+            <!-- Reader mode should be ON or OFF if reader_option_capable is enabled -->
+            <item name="reader_option_default" type="bool"/>
+            <!-- Secure NFC default value-->
+            <item name="secure_nfc_default" type="bool"/>
+            <item name="tag_intent_blocked_app_list" type="array" />
+            <item name="check_display_state_for_screen_state" type="bool" />
+            <item name="enable_euicc_support" type="bool" />
+            <item name="indicate_user_activity_for_hce" type="bool" />
           <!-- Params from config.xml that can be overlaid -->
 
           <!-- Params from strings.xml that can be overlaid -->
@@ -55,6 +71,7 @@
           <!-- Params from styles.xml that can be overlaid -->
 
           <!-- Params from drawable/ that can be overlaid -->
+          <item type="drawable" name="nfc_icon" />
           <!-- Params from drawable/ that can be overlaid -->
 
           <!-- Params from layout/ that can be overlaid -->
diff --git a/res/values/styles.xml b/res/values/styles.xml
index ea151baa..9a5894a3 100644
--- a/res/values/styles.xml
+++ b/res/values/styles.xml
@@ -15,7 +15,10 @@
 -->
 
 <resources>
-    <style name="DialogAlertDayNight" parent="@android:style/Theme.DeviceDefault.Light.Dialog"/>
+    <style name="DialogAlertDayNight" parent="@android:style/Theme.DeviceDefault.Light.Dialog">
+        <item name="android:windowMinWidthMajor">80%</item>
+        <item name="android:windowMinWidthMinor">80%</item>
+    </style>
 
     <style name="TapAgainDayNight" parent="Theme.AppCompat.DayNight">
         <item name="android:fontFamily">google-sans</item>
diff --git a/src/com/android/nfc/ConfirmConnectToWifiNetworkActivity.java b/src/com/android/nfc/ConfirmConnectToWifiNetworkActivity.java
index 0816b296..a70117a6 100644
--- a/src/com/android/nfc/ConfirmConnectToWifiNetworkActivity.java
+++ b/src/com/android/nfc/ConfirmConnectToWifiNetworkActivity.java
@@ -15,12 +15,14 @@ import android.net.wifi.WifiManager;
 import android.os.Binder;
 import android.os.Bundle;
 import android.os.Handler;
+import android.util.Log;
 import android.view.View;
 import android.widget.Toast;
 
 public class ConfirmConnectToWifiNetworkActivity extends Activity
         implements View.OnClickListener, DialogInterface.OnDismissListener {
 
+    static final String TAG = "ConfirmConnectToWifiNetworkActivity";
     public static final int ENABLE_WIFI_TIMEOUT_MILLIS = 5000;
     private WifiConfiguration mCurrentWifiConfiguration;
     private AlertDialog mAlertDialog;
@@ -35,6 +37,11 @@ public class ConfirmConnectToWifiNetworkActivity extends Activity
         mCurrentWifiConfiguration =
                 intent.getParcelableExtra(NfcWifiProtectedSetup.EXTRA_WIFI_CONFIG);
 
+        if (mCurrentWifiConfiguration == null) {
+            Log.e(TAG, "mCurrentWifiConfiguration is null.");
+            finish();
+            return;
+        }
         String printableSsid = mCurrentWifiConfiguration.getPrintableSsid();
         mAlertDialog = new AlertDialog.Builder(this, R.style.DialogAlertDayNight)
                 .setTitle(R.string.title_connect_to_network)
@@ -147,13 +154,11 @@ public class ConfirmConnectToWifiNetworkActivity extends Activity
             String action = intent.getAction();
             if (action.equals(WifiManager.WIFI_STATE_CHANGED_ACTION)) {
                 int wifiState = intent.getIntExtra(WifiManager.EXTRA_WIFI_STATE, 0);
-                if (mCurrentWifiConfiguration != null
-                        && wifiState == WifiManager.WIFI_STATE_ENABLED) {
-                    if (getAndClearEnableWifiInProgress()) {
-                        doConnect(
-                                ConfirmConnectToWifiNetworkActivity.this
-                                        .getSystemService(WifiManager.class));
-                    }
+                if (wifiState == WifiManager.WIFI_STATE_ENABLED
+                        && getAndClearEnableWifiInProgress()) {
+                    doConnect(
+                            ConfirmConnectToWifiNetworkActivity.this
+                                    .getSystemService(WifiManager.class));
                 }
             }
         }
diff --git a/src/com/android/nfc/DeviceConfigFacade.java b/src/com/android/nfc/DeviceConfigFacade.java
index 4f7df10c..3d80910e 100644
--- a/src/com/android/nfc/DeviceConfigFacade.java
+++ b/src/com/android/nfc/DeviceConfigFacade.java
@@ -19,6 +19,8 @@ package com.android.nfc;
 import android.content.Context;
 import android.os.Handler;
 import android.provider.DeviceConfig;
+import android.os.SystemProperties;
+import android.text.TextUtils;
 import androidx.annotation.VisibleForTesting;
 
 /**
@@ -34,6 +36,21 @@ public class DeviceConfigFacade {
     // Cached values of fields updated via updateDeviceConfigFlags()
     private boolean mAntennaBlockedAlertEnabled;
 
+    public static final String KEY_READER_OPTION_DEFAULT = "reader_option_default";
+    public static final String KEY_ENABLE_NFC_DEFAULT = "enable_nfc_default";
+    public static final String KEY_ENABLE_READER_OPTION_SUPPORT = "enable_reader_option_support";
+    public static final String KEY_SECURE_NFC_CAPABLE = "enable_secure_nfc_support";
+    public static final String KEY_SECURE_NFC_DEFAULT = "secure_nfc_default";
+
+    private boolean mNfcDefaultState;
+    private boolean mReaderOptionSupport;
+    private boolean mReaderOptionDefault;
+    private boolean mSecureNfcCapable;
+    private boolean mSecureNfcDefault;
+    private String mDefaultRoute;
+    private String mDefaultIsoDepRoute;
+    private String mDefaultOffHostRoute;
+
     private static DeviceConfigFacade sInstance;
     public static DeviceConfigFacade getInstance(Context context, Handler handler) {
         if (sInstance == null) {
@@ -60,12 +77,66 @@ public class DeviceConfigFacade {
         mAntennaBlockedAlertEnabled = DeviceConfig.getBoolean(DEVICE_CONFIG_NAMESPACE_NFC,
                 "enable_antenna_blocked_alert",
                 mContext.getResources().getBoolean(R.bool.enable_antenna_blocked_alert));
+
+        mNfcDefaultState = DeviceConfig.getBoolean(DeviceConfig.NAMESPACE_NFC,
+            KEY_ENABLE_NFC_DEFAULT,
+            mContext.getResources().getBoolean(R.bool.enable_nfc_default));
+
+        mReaderOptionSupport = DeviceConfig.getBoolean(DeviceConfig.NAMESPACE_NFC,
+            KEY_ENABLE_READER_OPTION_SUPPORT,
+            mContext.getResources().getBoolean(R.bool.enable_reader_option_support));
+
+        mReaderOptionDefault = DeviceConfig.getBoolean(DeviceConfig.NAMESPACE_NFC,
+            KEY_READER_OPTION_DEFAULT,
+            mContext.getResources().getBoolean(R.bool.reader_option_default));
+
+        mSecureNfcCapable = DeviceConfig.getBoolean(DeviceConfig.NAMESPACE_NFC,
+            KEY_SECURE_NFC_CAPABLE, isSecureNfcCapableDefault());
+
+        mSecureNfcDefault = DeviceConfig.getBoolean(DeviceConfig.NAMESPACE_NFC,
+            KEY_SECURE_NFC_DEFAULT,
+            mContext.getResources().getBoolean(R.bool.secure_nfc_default));
+
+        mDefaultRoute = DeviceConfig.getString(DEVICE_CONFIG_NAMESPACE_NFC,
+                "nfc_default_route",
+                mContext.getResources().getString(R.string.nfc_default_route));
+
+        mDefaultIsoDepRoute = DeviceConfig.getString(DEVICE_CONFIG_NAMESPACE_NFC,
+                "nfc_default_isodep_route",
+                mContext.getResources().getString(R.string.nfc_default_isodep_route));
+
+        mDefaultOffHostRoute = DeviceConfig.getString(DEVICE_CONFIG_NAMESPACE_NFC,
+                "nfc_default_offhost_route",
+                mContext.getResources().getString(R.string.nfc_default_offhost_route));
+    }
+
+    private boolean isSecureNfcCapableDefault() {
+        if (mContext.getResources().getBoolean(R.bool.enable_secure_nfc_support)) {
+            return true;
+        }
+        String[] skuList = mContext.getResources().getStringArray(
+                R.array.config_skuSupportsSecureNfc);
+        String sku = SystemProperties.get("ro.boot.hardware.sku");
+        if (TextUtils.isEmpty(sku) || !Utils.arrayContains(skuList, sku)) {
+            return false;
+        }
+        return true;
     }
 
+
     /**
      * Get whether antenna blocked alert is enabled or not.
      */
     public boolean isAntennaBlockedAlertEnabled() {
         return mAntennaBlockedAlertEnabled;
     }
+
+    public boolean getNfcDefaultState(){ return mNfcDefaultState; }
+    public boolean isReaderOptionCapable() { return mReaderOptionSupport; }
+    public boolean getDefaultReaderOption() { return mReaderOptionDefault; }
+    public boolean isSecureNfcCapable() {return mSecureNfcCapable; }
+    public boolean getDefaultSecureNfcState() { return mSecureNfcDefault; }
+    public String getDefaultRoute() { return mDefaultRoute; }
+    public String getDefaultIsoDepRoute() { return mDefaultIsoDepRoute; }
+    public String getDefaultOffHostRoute() { return mDefaultOffHostRoute; }
 }
diff --git a/src/com/android/nfc/DeviceHost.java b/src/com/android/nfc/DeviceHost.java
index d18f67e1..da03a338 100644
--- a/src/com/android/nfc/DeviceHost.java
+++ b/src/com/android/nfc/DeviceHost.java
@@ -23,6 +23,7 @@ import android.os.Bundle;
 
 import java.io.FileDescriptor;
 import java.io.IOException;
+import java.io.PrintWriter;
 import java.util.List;
 
 public interface DeviceHost {
@@ -50,6 +51,10 @@ public interface DeviceHost {
         public void onWlcStopped(int wpt_end_condition);
 
         public void onVendorSpecificEvent(int gid, int oid, byte[] payload);
+
+        public void onObserveModeStateChanged(boolean enable);
+
+        public void onRfDiscoveryEvent(boolean isDiscoveryStarted);
     }
 
     public interface TagEndpoint {
@@ -136,6 +141,8 @@ public interface DeviceHost {
 
     public boolean initialize();
 
+    public void setPartialInitMode(int mode);
+
     public boolean deinitialize();
 
     public String getName();
@@ -176,7 +183,7 @@ public interface DeviceHost {
 
     boolean getExtendedLengthApdusSupported();
 
-    void dump(FileDescriptor fd);
+    void dump(PrintWriter pw, FileDescriptor fd);
 
     public void doSetScreenState(int screen_state_mask, boolean alwaysPoll);
 
@@ -226,7 +233,7 @@ public interface DeviceHost {
     boolean isMultiTag();
 
     void setIsoDepProtocolRoute(int route);
-    void setTechnologyABRoute(int route);
+    void setTechnologyABFRoute(int route);
     void clearRoutingEntry(int clearFlags);
 
     /**
@@ -240,4 +247,9 @@ public interface DeviceHost {
     NfcVendorNciResponse sendRawVendorCmd(int mt, int gid, int oid, byte[] payload);
 
     void enableVendorNciNotifications(boolean enabled);
+
+    /**
+     * Get the active NFCEE list
+     */
+    public List<String> dofetchActiveNfceeList();
 }
diff --git a/src/com/android/nfc/ForegroundUtils.java b/src/com/android/nfc/ForegroundUtils.java
index 00d5d8c8..bcd044a1 100644
--- a/src/com/android/nfc/ForegroundUtils.java
+++ b/src/com/android/nfc/ForegroundUtils.java
@@ -114,8 +114,9 @@ public class ForegroundUtils implements ActivityManager.OnUidImportanceListener
      *         if none are found.
      */
     public List<Integer> getForegroundUids() {
-        ArrayList<Integer> uids = new ArrayList<Integer>(mForegroundUids.size());
+        ArrayList<Integer> uids = null;
         synchronized (mLock) {
+            uids = new ArrayList<Integer>(mForegroundUids.size());
             for (int i = 0; i < mForegroundUids.size(); i++) {
                 if (mForegroundUids.valueAt(i)) {
                     uids.add(mForegroundUids.keyAt(i));
@@ -193,6 +194,8 @@ public class ForegroundUtils implements ActivityManager.OnUidImportanceListener
 
     @VisibleForTesting
     public void clearForegroundlist() {
-        mForegroundUids.clear();
+        synchronized (mLock) {
+            mForegroundUids.clear();
+        }
     }
 }
diff --git a/src/com/android/nfc/NfcBackupAgent.java b/src/com/android/nfc/NfcBackupAgent.java
index 7e233957..d56dfee8 100644
--- a/src/com/android/nfc/NfcBackupAgent.java
+++ b/src/com/android/nfc/NfcBackupAgent.java
@@ -38,25 +38,26 @@ public class NfcBackupAgent extends BackupAgentHelper {
     public void onRestoreFinished() {
         NfcAdapter nfcAdapter = NfcAdapter.getDefaultAdapter(this);
         NfcService.sIsNfcRestore = true;
+        DeviceConfigFacade deviceConfigFacade = NfcInjector.getInstance().getDeviceConfigFacade();
 
         if (nfcAdapter != null) {
             SharedPreferences prefs = getSharedPreferences(NfcService.PREF,
                 Context.MODE_MULTI_PROCESS);
             if (prefs.getBoolean(NfcService.PREF_NFC_ON,
-                    NfcService.NFC_ON_DEFAULT)) {
+                    deviceConfigFacade.getNfcDefaultState())) {
                 nfcAdapter.enable();
             } else {
                 nfcAdapter.disable();
             }
 
             if (prefs.getBoolean(NfcService.PREF_NFC_READER_OPTION_ON,
-                    NfcService.NFC_READER_OPTION_DEFAULT)) {
+                    deviceConfigFacade.getDefaultReaderOption())) {
                 nfcAdapter.enableReaderOption(true);
             } else {
                 nfcAdapter.enableReaderOption(false);
             }
 
-            if (prefs.getBoolean(NfcService.PREF_SECURE_NFC_ON, NfcService.SECURE_NFC_ON_DEFAULT)
+            if (prefs.getBoolean(NfcService.PREF_SECURE_NFC_ON, deviceConfigFacade.getDefaultSecureNfcState())
                     && nfcAdapter.isSecureNfcSupported()) {
                 nfcAdapter.enableSecureNfc(true);
             } else {
diff --git a/src/com/android/nfc/NfcBlockedNotification.java b/src/com/android/nfc/NfcBlockedNotification.java
index 83d02bbb..d57f33bf 100644
--- a/src/com/android/nfc/NfcBlockedNotification.java
+++ b/src/com/android/nfc/NfcBlockedNotification.java
@@ -60,7 +60,7 @@ public class NfcBlockedNotification {
         Notification.Builder builder = new Notification.Builder(mContext, NFC_NOTIFICATION_CHANNEL);
         builder.setContentTitle(mContext.getString(R.string.nfc_blocking_alert_title))
                 .setContentText(mContext.getString(R.string.nfc_blocking_alert_message))
-                .setSmallIcon(android.R.drawable.stat_sys_warning)
+                .setSmallIcon(R.drawable.nfc_icon)
                 .setPriority(NotificationManager.IMPORTANCE_DEFAULT)
                 .setAutoCancel(true)
                 .setContentIntent(PendingIntent.getActivity(mContext, 0, infoIntent,
diff --git a/src/com/android/nfc/NfcDeveloperOptionNotification.java b/src/com/android/nfc/NfcDeveloperOptionNotification.java
index 926e5613..6bdddf37 100644
--- a/src/com/android/nfc/NfcDeveloperOptionNotification.java
+++ b/src/com/android/nfc/NfcDeveloperOptionNotification.java
@@ -60,7 +60,7 @@ public class NfcDeveloperOptionNotification {
         Notification.Builder builder = new Notification.Builder(mContext, NFC_NOTIFICATION_CHANNEL);
         builder.setContentTitle(mContext.getString(R.string.nfc_logging_alert_title))
                 .setContentText(mContext.getString(R.string.nfc_logging_alert_message))
-                .setSmallIcon(android.R.drawable.stat_sys_warning)
+                .setSmallIcon(R.drawable.nfc_icon)
                 .setPriority(NotificationManager.IMPORTANCE_HIGH)
                 .setOngoing(true)
                 .setAutoCancel(false)
diff --git a/src/com/android/nfc/NfcDispatcher.java b/src/com/android/nfc/NfcDispatcher.java
index 7bd0b35d..276bc8d6 100644
--- a/src/com/android/nfc/NfcDispatcher.java
+++ b/src/com/android/nfc/NfcDispatcher.java
@@ -55,6 +55,7 @@ import android.os.SystemProperties;
 import android.os.UserHandle;
 import android.os.UserManager;
 import android.sysprop.NfcProperties;
+import android.text.TextUtils;
 import android.util.Log;
 import android.util.proto.ProtoOutputStream;
 import android.view.LayoutInflater;
@@ -99,6 +100,7 @@ class NfcDispatcher {
     private final ScreenStateHelper mScreenStateHelper;
     private final NfcUnlockManager mNfcUnlockManager;
     private final boolean mDeviceSupportsBluetooth;
+    private final NfcInjector mNfcInjector;
     private final Handler mMessageHandler = new MessageHandler();
     private final Messenger mMessenger = new Messenger(mMessageHandler);
     private AtomicBoolean mBluetoothEnabledByNfc = new AtomicBoolean();
@@ -115,12 +117,14 @@ class NfcDispatcher {
 
     NfcDispatcher(Context context,
                   HandoverDataParser handoverDataParser,
+                  NfcInjector nfcInjector,
                   boolean provisionOnly) {
         mContext = context;
         mTechListFilters = new RegisteredComponentCache(mContext,
                 NfcAdapter.ACTION_TECH_DISCOVERED, NfcAdapter.ACTION_TECH_DISCOVERED);
         mContentResolver = context.getContentResolver();
         mHandoverDataParser = handoverDataParser;
+        mNfcInjector = nfcInjector;
         mScreenStateHelper = new ScreenStateHelper(context);
         mNfcUnlockManager = NfcUnlockManager.getInstance();
         mDeviceSupportsBluetooth = BluetoothAdapter.getDefaultAdapter() != null;
@@ -270,6 +274,20 @@ class NfcDispatcher {
             return null;
         }
 
+        public Intent setViewIntent() {
+            intent.setAction(Intent.ACTION_VIEW);
+            intent.addCategory(Intent.CATEGORY_DEFAULT);
+            intent.addCategory(Intent.CATEGORY_BROWSABLE);
+            if (ndefUri != null) {
+                intent.setData(ndefUri);
+                return intent;
+            } else if (ndefMimeType != null) {
+                intent.setType(ndefMimeType);
+                return intent;
+            }
+            return null;
+        }
+
         public Intent setTechIntent() {
             intent.setData(null);
             intent.setType(null);
@@ -545,7 +563,10 @@ class NfcDispatcher {
 
         boolean screenUnlocked = false;
         if (!provisioningOnly &&
-                mScreenStateHelper.checkScreenState() == ScreenStateHelper.SCREEN_STATE_ON_LOCKED) {
+                mScreenStateHelper.checkScreenState(
+                        mContext.getResources().getBoolean(
+                                R.bool.check_display_state_for_screen_state))
+                        == ScreenStateHelper.SCREEN_STATE_ON_LOCKED) {
             screenUnlocked = handleNfcUnlock(tag);
             if (!screenUnlocked)
                 return DISPATCH_FAIL;
@@ -842,19 +863,25 @@ class NfcDispatcher {
         // regular launch
         dispatch.intent.setPackage(null);
 
-        if (dispatch.isWebIntent() && dispatch.hasIntentReceiver()) {
-            if (showWebLinkConfirmation(dispatch)) {
-                if (DBG) Log.i(TAG, "matched Web link - prompting user");
-                NfcStatsLog.write(
-                        NfcStatsLog.NFC_TAG_OCCURRED,
-                        NfcStatsLog.NFC_TAG_OCCURRED__TYPE__URL,
-                        -1,
-                        dispatch.tag.getTechCodeList(),
-                        BluetoothProtoEnums.MAJOR_CLASS_UNCATEGORIZED,
-                        "");
-                return true;
+        if (dispatch.isWebIntent()) {
+            if (mNfcInjector.getFeatureFlags().sendViewIntentForUrlTagDispatch()) {
+                dispatch.setViewIntent();
+                Log.d(TAG, "Sending VIEW intent instead of NFC specific intent");
+            }
+            if (dispatch.hasIntentReceiver()) {
+                if (showWebLinkConfirmation(dispatch)) {
+                    if (DBG) Log.i(TAG, "matched Web link - prompting user");
+                    NfcStatsLog.write(
+                            NfcStatsLog.NFC_TAG_OCCURRED,
+                            NfcStatsLog.NFC_TAG_OCCURRED__TYPE__URL,
+                            -1,
+                            dispatch.tag.getTechCodeList(),
+                            BluetoothProtoEnums.MAJOR_CLASS_UNCATEGORIZED,
+                            "");
+                    return true;
+                }
+                return false;
             }
-            return false;
         }
 
         for (UserHandle uh : luh) {
@@ -966,6 +993,14 @@ class NfcDispatcher {
         return false;
     }
 
+    private String getPeripheralName(HandoverDataParser.BluetoothHandoverData handover) {
+        if (!TextUtils.isEmpty(handover.name)) {
+            return handover.name;
+        }
+        // If name is empty in the handover data, use a generic name.
+        return mContext.getResources().getString(R.string.device);
+    }
+
     public boolean tryPeripheralHandover(NdefMessage m, Tag tag) {
         if (m == null || !mDeviceSupportsBluetooth) return false;
         if (DBG) Log.d(TAG, "tryHandover(): " + m.toString());
@@ -981,7 +1016,8 @@ class NfcDispatcher {
 
         Intent intent = new Intent(mContext, PeripheralHandoverService.class);
         intent.putExtra(PeripheralHandoverService.EXTRA_PERIPHERAL_DEVICE, handover.device);
-        intent.putExtra(PeripheralHandoverService.EXTRA_PERIPHERAL_NAME, handover.name);
+        intent.putExtra(
+            PeripheralHandoverService.EXTRA_PERIPHERAL_NAME, getPeripheralName(handover));
         intent.putExtra(PeripheralHandoverService.EXTRA_PERIPHERAL_TRANSPORT, handover.transport);
         if (handover.oobData != null) {
             intent.putExtra(PeripheralHandoverService.EXTRA_PERIPHERAL_OOB_DATA, handover.oobData);
diff --git a/src/com/android/nfc/NfcInjector.java b/src/com/android/nfc/NfcInjector.java
index 4f8be3a9..fcdc0dfa 100644
--- a/src/com/android/nfc/NfcInjector.java
+++ b/src/com/android/nfc/NfcInjector.java
@@ -27,18 +27,15 @@ import android.nfc.NfcFrameworkInitializer;
 import android.nfc.NfcServiceManager;
 import android.os.Handler;
 import android.os.HandlerThread;
-import android.os.IBinder;
 import android.os.Looper;
 import android.os.RemoteException;
 import android.os.SystemClock;
 import android.os.SystemProperties;
-import android.os.UserHandle;
 import android.os.VibrationEffect;
 import android.provider.Settings;
 import android.se.omapi.ISecureElementService;
 import android.se.omapi.SeFrameworkInitializer;
 import android.se.omapi.SeServiceManager;
-import android.text.TextUtils;
 import android.util.AtomicFile;
 import android.util.Log;
 
@@ -46,7 +43,6 @@ import com.android.nfc.cardemulation.util.StatsdUtils;
 import com.android.nfc.dhimpl.NativeNfcManager;
 import com.android.nfc.flags.FeatureFlags;
 import com.android.nfc.handover.HandoverDataParser;
-import com.android.nfc.proto.NfcEventProto;
 
 import java.io.File;
 import java.time.LocalDateTime;
@@ -77,6 +73,7 @@ public class NfcInjector {
     private final ForegroundUtils mForegroundUtils;
     private final NfcDiagnostics mNfcDiagnostics;
     private final NfcServiceManager.ServiceRegisterer mNfcManagerRegisterer;
+    private final NfcWatchdog mNfcWatchdog;
     private static NfcInjector sInstance;
 
     public static NfcInjector getInstance() {
@@ -95,7 +92,8 @@ public class NfcInjector {
         mNfcUnlockManager = NfcUnlockManager.getInstance();
         mHandoverDataParser = new HandoverDataParser();
         mDeviceConfigFacade = new DeviceConfigFacade(mContext, new Handler(mainLooper));
-        mNfcDispatcher = new NfcDispatcher(mContext, mHandoverDataParser, isInProvisionMode());
+        mNfcDispatcher =
+            new NfcDispatcher(mContext, mHandoverDataParser, this, isInProvisionMode());
         mVibrationEffect = VibrationEffect.createOneShot(200, VibrationEffect.DEFAULT_AMPLITUDE);
         mBackupManager = new BackupManager(mContext);
         mFeatureFlags = new com.android.nfc.flags.FeatureFlagsImpl();
@@ -116,6 +114,7 @@ public class NfcInjector {
         eventLogThread.start();
         mNfcEventLog = new NfcEventLog(mContext, this, eventLogThread.getLooper(),
                 new AtomicFile(new File(NFC_DATA_DIR, EVENT_LOG_FILE_NAME)));
+        mNfcWatchdog = new NfcWatchdog(mContext);
         sInstance = this;
     }
 
@@ -183,6 +182,10 @@ public class NfcInjector {
         return mNfcManagerRegisterer;
     }
 
+    public NfcWatchdog getNfcWatchdog() {
+        return mNfcWatchdog;
+    }
+
     public DeviceHost makeDeviceHost(DeviceHost.DeviceHostListener listener) {
         return new NativeNfcManager(mContext, listener);
     }
@@ -215,19 +218,6 @@ public class NfcInjector {
         }
     }
 
-    public boolean checkIsSecureNfcCapable() {
-        if (mContext.getResources().getBoolean(R.bool.enable_secure_nfc_support)) {
-            return true;
-        }
-        String[] skuList = mContext.getResources().getStringArray(
-                R.array.config_skuSupportsSecureNfc);
-        String sku = SystemProperties.get("ro.boot.hardware.sku");
-        if (TextUtils.isEmpty(sku) || !Utils.arrayContains(skuList, sku)) {
-            return false;
-        }
-        return true;
-    }
-
     public ISecureElementService connectToSeService() throws RemoteException {
         SeServiceManager manager = SeFrameworkInitializer.getSeServiceManager();
         if (manager == null) {
@@ -259,6 +249,7 @@ public class NfcInjector {
                 mContext.getContentResolver(), Constants.SETTINGS_SATELLITE_MODE_ENABLED, 0) == 1;
     }
 
+
     /**
      * Get the current time of the clock in milliseconds.
      *
@@ -285,4 +276,17 @@ public class NfcInjector {
     public long getElapsedSinceBootNanos() {
         return SystemClock.elapsedRealtimeNanos();
     }
+
+    /**
+     * Temporary location to store nfc properties being added in Android 16 for OEM convergence.
+     * Will move all of these together to libsysprop later to avoid multiple rounds of API reviews.
+     */
+    public static final class NfcProperties {
+        private static final String NFC_EUICC_SUPPORTED_PROP_KEY = "ro.nfc.euicc_supported";
+
+        public static boolean isEuiccSupported() {
+            return SystemProperties.getBoolean(NFC_EUICC_SUPPORTED_PROP_KEY, true);
+        }
+
+    }
 }
\ No newline at end of file
diff --git a/src/com/android/nfc/NfcPermissions.java b/src/com/android/nfc/NfcPermissions.java
index 5733ac8c..ed92a76b 100644
--- a/src/com/android/nfc/NfcPermissions.java
+++ b/src/com/android/nfc/NfcPermissions.java
@@ -5,14 +5,12 @@ import static android.content.pm.PackageManager.PERMISSION_GRANTED;
 import android.annotation.Nullable;
 import android.app.ActivityManager;
 import android.app.admin.DevicePolicyManager;
-import android.content.ComponentName;
 import android.content.Context;
 import android.content.pm.PackageManager;
 import android.os.Binder;
 import android.os.UserHandle;
 import android.os.UserManager;
 import android.util.Log;
-import android.util.Pair;
 
 import java.util.List;
 
@@ -119,30 +117,6 @@ public class NfcPermissions {
         return devicePolicyManager;
     }
 
-    @Nullable
-    private Pair<UserHandle, ComponentName> getDeviceOwner() {
-        DevicePolicyManager devicePolicyManager =
-                retrieveDevicePolicyManagerFromContext(mContext);
-        if (devicePolicyManager == null) return null;
-        long ident = Binder.clearCallingIdentity();
-        UserHandle deviceOwnerUser = null;
-        ComponentName deviceOwnerComponent = null;
-        try {
-            deviceOwnerUser = devicePolicyManager.getDeviceOwnerUser();
-            deviceOwnerComponent = devicePolicyManager.getDeviceOwnerComponentOnAnyUser();
-        } finally {
-            Binder.restoreCallingIdentity(ident);
-        }
-        if (deviceOwnerUser == null || deviceOwnerComponent == null) return null;
-
-        if (deviceOwnerComponent.getPackageName() == null) {
-            // shouldn't happen
-            Log.wtf(TAG, "no package name on device owner component: " + deviceOwnerComponent);
-            return null;
-        }
-        return new Pair<>(deviceOwnerUser, deviceOwnerComponent);
-    }
-
     /**
      * Returns {@code true} if the calling {@code uid} and {@code packageName} is the device owner.
      */
@@ -153,14 +127,10 @@ public class NfcPermissions {
             Log.e(TAG, "isDeviceOwner: packageName is null, returning false");
             return false;
         }
-        Pair<UserHandle, ComponentName> deviceOwner = getDeviceOwner();
-        Log.v(TAG, "deviceOwner:" + deviceOwner);
-
-        // no device owner
-        if (deviceOwner == null) return false;
-
-        return deviceOwner.first.equals(UserHandle.getUserHandleForUid(uid))
-                && deviceOwner.second.getPackageName().equals(packageName);
+        DevicePolicyManager devicePolicyManager =
+                retrieveDevicePolicyManagerFromUserContext(uid);
+        if (devicePolicyManager == null) return false;
+        return devicePolicyManager.isDeviceOwnerApp(packageName);
     }
 
     @Nullable
diff --git a/src/com/android/nfc/NfcService.java b/src/com/android/nfc/NfcService.java
index db80a2b6..a7e0a051 100644
--- a/src/com/android/nfc/NfcService.java
+++ b/src/com/android/nfc/NfcService.java
@@ -19,6 +19,8 @@ package com.android.nfc;
 import static com.android.nfc.NfcStatsLog.NFC_OBSERVE_MODE_STATE_CHANGED__TRIGGER_SOURCE__FOREGROUND_APP;
 import static com.android.nfc.NfcStatsLog.NFC_OBSERVE_MODE_STATE_CHANGED__TRIGGER_SOURCE__TRIGGER_SOURCE_UNKNOWN;
 import static com.android.nfc.NfcStatsLog.NFC_OBSERVE_MODE_STATE_CHANGED__TRIGGER_SOURCE__WALLET_ROLE_HOLDER;
+import static com.android.nfc.ScreenStateHelper.SCREEN_STATE_ON_LOCKED;
+import static com.android.nfc.ScreenStateHelper.SCREEN_STATE_ON_UNLOCKED;
 
 import android.annotation.NonNull;
 import android.app.ActivityManager;
@@ -41,8 +43,11 @@ import android.content.pm.ApplicationInfo;
 import android.content.pm.PackageInfo;
 import android.content.pm.PackageManager;
 import android.database.ContentObserver;
+import android.hardware.display.DisplayManager;
+import android.hardware.display.DisplayManager.DisplayListener;
 import android.media.AudioAttributes;
 import android.media.SoundPool;
+import android.media.SoundPool.OnLoadCompleteListener;
 import android.net.Uri;
 import android.nfc.AvailableNfcAntenna;
 import android.nfc.Constants;
@@ -64,6 +69,7 @@ import android.nfc.ITagRemovedCallback;
 import android.nfc.NdefMessage;
 import android.nfc.NfcAdapter;
 import android.nfc.NfcAntennaInfo;
+import android.nfc.NfcOemExtension;
 import android.nfc.Tag;
 import android.nfc.TechListParcel;
 import android.nfc.TransceiveResult;
@@ -85,6 +91,7 @@ import android.os.PowerManager;
 import android.os.PowerManager.OnThermalStatusChangedListener;
 import android.os.Process;
 import android.os.RemoteException;
+import android.os.ResultReceiver;
 import android.os.SystemClock;
 import android.os.UserHandle;
 import android.os.UserManager;
@@ -98,6 +105,7 @@ import android.sysprop.NfcProperties;
 import android.util.EventLog;
 import android.util.Log;
 import android.util.proto.ProtoOutputStream;
+import android.view.Display;
 import android.widget.Toast;
 
 import androidx.annotation.VisibleForTesting;
@@ -111,6 +119,7 @@ import com.android.nfc.flags.FeatureFlags;
 import com.android.nfc.handover.HandoverDataParser;
 import com.android.nfc.proto.NfcEventProto;
 import com.android.nfc.wlc.NfcCharging;
+import com.google.protobuf.ByteString;
 
 import org.json.JSONException;
 import org.json.JSONObject;
@@ -120,6 +129,7 @@ import java.io.FileDescriptor;
 import java.io.FileOutputStream;
 import java.io.IOException;
 import java.io.PrintWriter;
+import java.io.StringWriter;
 import java.io.UnsupportedEncodingException;
 import java.nio.ByteBuffer;
 import java.nio.file.Files;
@@ -136,6 +146,7 @@ import java.util.Map;
 import java.util.NoSuchElementException;
 import java.util.Scanner;
 import java.util.Set;
+import java.util.concurrent.CountDownLatch;
 import java.util.concurrent.ExecutionException;
 import java.util.concurrent.ExecutorService;
 import java.util.concurrent.Executors;
@@ -159,16 +170,14 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
     public static final String PREF_TAG_APP_LIST = "TagIntentAppPreferenceListPrefs";
 
     static final String PREF_NFC_ON = "nfc_on";
-    static final boolean NFC_ON_DEFAULT = true;
 
     static final String PREF_NFC_READER_OPTION_ON = "nfc_reader_on";
-    static final boolean NFC_READER_OPTION_DEFAULT = true;
 
     static final String PREF_NFC_CHARGING_ON = "nfc_charging_on";
     static final boolean NFC_CHARGING_ON_DEFAULT = true;
 
+    static final String PREF_MIGRATE_TO_DE_COMPLETE = "migrate_to_de_complete";
     static final String PREF_SECURE_NFC_ON = "secure_nfc_on";
-    static final boolean SECURE_NFC_ON_DEFAULT = false;
     static final String PREF_FIRST_BOOT = "first_boot";
 
     static final String PREF_ANTENNA_BLOCKED_MESSAGE_SHOWN = "antenna_blocked_message_shown";
@@ -204,7 +213,8 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
     static final int MSG_DELAY_POLLING = 20;
     static final int MSG_CLEAR_ROUTING_TABLE = 21;
     static final int MSG_UPDATE_ISODEP_PROTOCOL_ROUTE = 22;
-    static final int MSG_UPDATE_TECHNOLOGY_AB_ROUTE = 23;
+    static final int MSG_UPDATE_TECHNOLOGY_ABF_ROUTE = 23;
+    static final int MSG_WATCHDOG_PING = 24;
 
     static final String MSG_ROUTE_AID_PARAM_TAG = "power";
 
@@ -215,6 +225,8 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
 
     static final int MAX_TOAST_DEBOUNCE_TIME = 10000;
 
+    static final int DISABLE_POLLING_FLAGS = 0x1000;
+
     static final int TASK_ENABLE = 1;
     static final int TASK_DISABLE = 2;
     static final int TASK_BOOT = 3;
@@ -277,7 +289,6 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
     public static boolean sIsNfcRestore = false;
 
     // for use with playSound()
-    public static final int SOUND_START = 0;
     public static final int SOUND_END = 1;
     public static final int SOUND_ERROR = 2;
 
@@ -300,6 +311,8 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
     private static final int NCI_MSG_PROP_ANDROID = 0x0C;
     private static final int NCI_MSG_PROP_ANDROID_POWER_SAVING = 0x01;
 
+    private static final int WAIT_FOR_OEM_CALLBACK_TIMEOUT_MS = 3000;
+
     private final Looper mLooper;
     private final UserManager mUserManager;
     private final ActivityManager mActivityManager;
@@ -326,6 +339,9 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
     HashMap<Integer, HashMap<String, Boolean>> mTagAppPrefList =
             new HashMap<Integer, HashMap<String, Boolean>>();
 
+    // Tag app preference blocked list from overlay.
+    List<String> mTagAppDefaultBlockList = new ArrayList<String>();
+
     // cached version of installed packages requesting Android.permission.NFC_TRANSACTION_EVENTS
     // for current user and profiles. The Integer part is the userId.
     HashMap<Integer, List<String>> mNfcEventInstalledPackages =
@@ -373,6 +389,7 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
     // mAlwaysOnState is protected by this, however it is only modified in onCreate()
     // and the default AsyncTask thread so it is read unprotected from that thread
     int mAlwaysOnState;  // one of NfcAdapter.STATE_ON, STATE_TURNING_ON, etc
+    int mAlwaysOnMode; // one of NfcOemExtension.ENABLE_DEFAULT, ENABLE_TRANSPARENT, etc
     private boolean mIsPowerSavingModeEnabled = false;
 
     // fields below are final after onCreate()
@@ -389,7 +406,6 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
     private PowerManager.WakeLock mRoutingWakeLock;
     private PowerManager.WakeLock mRequireUnlockWakeLock;
 
-    int mStartSound;
     int mEndSound;
     int mErrorSound;
     SoundPool mSoundPool; // playback synchronized on this
@@ -434,7 +450,9 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
     private KeyguardManager mKeyguard;
     private HandoverDataParser mHandoverDataParser;
     private ContentResolver mContentResolver;
-    private CardEmulationManager mCardEmulationManager;
+
+    @VisibleForTesting
+    CardEmulationManager mCardEmulationManager;
     private NfcCharging mNfcCharging;
     private Vibrator mVibrator;
     private VibrationEffect mVibrationEffect;
@@ -463,14 +481,73 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
     private final Set<INfcWlcStateListener> mWlcStateListener =
             Collections.synchronizedSet(new HashSet<>());
     private final StatsdUtils mStatsdUtils;
+    private final boolean mCheckDisplayStateForScreenState;
 
     private  INfcVendorNciCallback mNfcVendorNciCallBack = null;
     private  INfcOemExtensionCallback mNfcOemExtensionCallback = null;
+    private final DisplayListener mDisplayListener = new DisplayListener() {
+        @Override
+        public void onDisplayAdded(int displayId) {
+        }
+
+        @Override
+        public void onDisplayRemoved(int displayId) {
+        }
+
+        @Override
+        public void onDisplayChanged(int displayId) {
+            if (displayId == Display.DEFAULT_DISPLAY) {
+                handleScreenStateChanged();
+            }
+        }
+    };
+
+    private boolean mCardEmulationActivated = false;
+    private boolean mRfFieldActivated = false;
+    private boolean mRfDiscoveryStarted = false;
+
+    private static final int STATUS_OK = NfcOemExtension.STATUS_OK;
+    private static final int STATUS_UNKNOWN_ERROR = NfcOemExtension.STATUS_UNKNOWN_ERROR;
+
+    private static final int ACTION_ON_ENABLE = 0;
+    private static final int ACTION_ON_DISABLE = 1;
+    private static final int ACTION_ON_TAG_DISPATCH = 2;
+    private static final int ACTION_ON_READ_NDEF = 3;
+    private static final int ACTION_ON_APPLY_ROUTING = 4;
 
     public static NfcService getInstance() {
         return sService;
     }
 
+    private static class NfcCallbackResultReceiver extends ResultReceiver {
+        CountDownLatch mCountDownLatch;
+        OnReceiveResultListener mOnReceiveResultListener;
+
+        public NfcCallbackResultReceiver(CountDownLatch latch, OnReceiveResultListener listener) {
+            super(null);
+            mCountDownLatch = latch;
+            mOnReceiveResultListener = listener;
+        }
+
+        @Override
+        protected void onReceiveResult(int resultCode, Bundle resultData) {
+            mOnReceiveResultListener.onReceiveResult(resultCode == 1);
+            mCountDownLatch.countDown();
+        }
+    }
+
+    private static class OnReceiveResultListener {
+        boolean result;
+
+        void onReceiveResult(boolean result) {
+            this.result = result;
+        }
+
+        boolean getResult() {
+            return result;
+        }
+    }
+
     @Override
     public void onRemoteEndpointDiscovered(TagEndpoint tag) {
         sendMessage(NfcService.MSG_NDEF_TAG, tag);
@@ -481,8 +558,26 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
      */
     @Override
     public void onHostCardEmulationActivated(int technology) {
+        mCardEmulationActivated = true;
+        try {
+            if (mNfcOemExtensionCallback != null) {
+                mNfcOemExtensionCallback.onCardEmulationActivated(mCardEmulationActivated);
+            }
+        } catch (RemoteException e) {
+            Log.e(TAG, "Failed to send onHostCardEmulationActivated", e);
+        }
         if (mCardEmulationManager != null) {
             mCardEmulationManager.onHostCardEmulationActivated(technology);
+            if (android.nfc.Flags.nfcPersistLog()) {
+                mNfcEventLog.logEvent(
+                        NfcEventProto.EventType.newBuilder()
+                                .setHostCardEmulationStateChange(
+                                        NfcEventProto.NfcHostCardEmulationStateChange.newBuilder()
+                                                .setTechnology(technology)
+                                                .setEnable(true)
+                                                .build())
+                                .build());
+            }
         }
     }
 
@@ -490,32 +585,94 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
     public void onHostCardEmulationData(int technology, byte[] data) {
         if (mCardEmulationManager != null) {
             mCardEmulationManager.onHostCardEmulationData(technology, data);
+            if (android.nfc.Flags.nfcPersistLog()) {
+                mNfcEventLog.logEvent(
+                        NfcEventProto.EventType.newBuilder()
+                                .setHostCardEmulationData(
+                                        NfcEventProto.NfcHostCardEmulationData.newBuilder()
+                                                .setTechnology(technology)
+                                                .setData(ByteString.copyFrom(data))
+                                                .build())
+                                .build());
+            }
         }
     }
 
     @Override
     public void onHostCardEmulationDeactivated(int technology) {
+        mCardEmulationActivated = false;
+        try {
+            if (mNfcOemExtensionCallback != null) {
+                mNfcOemExtensionCallback.onCardEmulationActivated(mCardEmulationActivated);
+            }
+        } catch (RemoteException e) {
+            Log.e(TAG, "Failed to send onHostCardEmulationDeactivated", e);
+        }
         if (mCardEmulationManager != null) {
             mCardEmulationManager.onHostCardEmulationDeactivated(technology);
+            if (android.nfc.Flags.nfcPersistLog()) {
+                mNfcEventLog.logEvent(
+                        NfcEventProto.EventType.newBuilder()
+                                .setHostCardEmulationStateChange(
+                                        NfcEventProto.NfcHostCardEmulationStateChange.newBuilder()
+                                                .setTechnology(technology)
+                                                .setEnable(false)
+                                                .build())
+                                .build());
+            }
         }
     }
 
     @Override
     public void onRemoteFieldActivated() {
+        mRfFieldActivated = true;
+        try {
+            if (mNfcOemExtensionCallback != null) {
+                mNfcOemExtensionCallback.onRfFieldActivated(mRfFieldActivated);
+            }
+        } catch (RemoteException e) {
+            Log.e(TAG, "Failed to send onRemoteFieldActivated", e);
+        }
         sendMessage(NfcService.MSG_RF_FIELD_ACTIVATED, null);
 
         if (mStatsdUtils != null) {
             mStatsdUtils.logFieldChanged(true, 0);
         }
+        if (android.nfc.Flags.nfcPersistLog()) {
+            mNfcEventLog.logEvent(
+                    NfcEventProto.EventType.newBuilder()
+                            .setRemoteFieldStateChange(
+                                    NfcEventProto.NfcRemoteFieldStateChange.newBuilder()
+                                            .setEnable(true)
+                                            .build())
+                            .build());
+        }
     }
 
     @Override
     public void onRemoteFieldDeactivated() {
+        mRfFieldActivated = false;
+        try {
+            if (mNfcOemExtensionCallback != null) {
+                mNfcOemExtensionCallback.onRfFieldActivated(mRfFieldActivated);
+            }
+        } catch (RemoteException e) {
+            Log.e(TAG, "Failed to send onRemoteFieldDeactivated", e);
+        }
         sendMessage(NfcService.MSG_RF_FIELD_DEACTIVATED, null);
 
         if (mStatsdUtils != null) {
             mStatsdUtils.logFieldChanged(false, 0);
         }
+        if (android.nfc.Flags.nfcPersistLog()) {
+            mNfcEventLog.logEvent(
+                    NfcEventProto.EventType.newBuilder()
+                            .setRemoteFieldStateChange(
+                                    NfcEventProto.NfcRemoteFieldStateChange.newBuilder()
+                                            .setEnable(false)
+                                            .build())
+                            .build());
+        }
     }
 
     @Override
@@ -557,6 +714,25 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
         mHandler.post(() -> mNfcAdapter.sendVendorNciNotification(gid, oid, payload));
     }
 
+    @Override
+    public void onObserveModeStateChanged(boolean enable) {
+        if (mCardEmulationManager != null) {
+            mCardEmulationManager.onObserveModeStateChange(enable);
+        }
+    }
+
+    @Override
+    public void onRfDiscoveryEvent(boolean isDiscoveryStarted) {
+        mRfDiscoveryStarted = isDiscoveryStarted;
+        try {
+            if (mNfcOemExtensionCallback != null) {
+                mNfcOemExtensionCallback.onRfDiscoveryStarted(mRfDiscoveryStarted);
+            }
+        } catch (RemoteException e) {
+            Log.e(TAG, "Failed to send onRfDiscoveryStarted", e);
+        }
+    }
+
     /**
      * Enable or Disable PowerSaving Mode based on flag
      */
@@ -635,7 +811,7 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
 
     boolean getNfcOnSetting() {
         synchronized (NfcService.this) {
-            return mPrefs.getBoolean(PREF_NFC_ON, NFC_ON_DEFAULT);
+            return mPrefs.getBoolean(PREF_NFC_ON, mDeviceConfigFacade.getNfcDefaultState());
         }
     }
 
@@ -682,7 +858,55 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
     }
 
     boolean shouldEnableNfc() {
-        return getNfcOnSetting() && !mNfcInjector.isSatelliteModeOn() && !isNfcUserRestricted();
+        return getNfcOnSetting() && !mNfcInjector.isSatelliteModeOn()
+                && !isNfcUserRestricted() && allowOemEnable();
+    }
+
+    boolean allowOemEnable() {
+        if (mNfcOemExtensionCallback == null) return true;
+        return receiveOemCallbackResult(ACTION_ON_ENABLE);
+    }
+
+    boolean allowOemDisable() {
+        if (mNfcOemExtensionCallback == null) return true;
+        return receiveOemCallbackResult(ACTION_ON_DISABLE);
+    }
+
+    boolean receiveOemCallbackResult(int action) {
+        CountDownLatch latch = new CountDownLatch(1);
+        OnReceiveResultListener listener = new OnReceiveResultListener();
+        ResultReceiver receiver = new NfcCallbackResultReceiver(latch, listener);
+        try {
+            switch (action) {
+                case ACTION_ON_ENABLE:
+                    mNfcOemExtensionCallback.onEnable(receiver);
+                    break;
+                case ACTION_ON_DISABLE:
+                    mNfcOemExtensionCallback.onDisable(receiver);
+                    break;
+                case ACTION_ON_TAG_DISPATCH:
+                    mNfcOemExtensionCallback.onTagDispatch(receiver);
+                    break;
+                case ACTION_ON_READ_NDEF:
+                    mNfcOemExtensionCallback.onNdefRead(receiver);
+                    break;
+                case ACTION_ON_APPLY_ROUTING:
+                    mNfcOemExtensionCallback.onApplyRouting(receiver);
+                    break;
+            }
+        } catch (RemoteException remoteException) {
+            return false;
+        }
+        try {
+            boolean success = latch.await(WAIT_FOR_OEM_CALLBACK_TIMEOUT_MS, TimeUnit.MILLISECONDS);
+            if (!success) {
+                return false;
+            } else {
+                return listener.getResult();
+            }
+        } catch (InterruptedException ie) {
+            return false;
+        }
     }
 
     private void registerGlobalBroadcastsReceiver() {
@@ -691,6 +915,7 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
         filter.addAction(Intent.ACTION_USER_PRESENT);
         filter.addAction(Intent.ACTION_USER_SWITCHED);
         filter.addAction(Intent.ACTION_USER_ADDED);
+        if (mFeatureFlags.enableDirectBootAware()) filter.addAction(Intent.ACTION_USER_UNLOCKED);
         mContext.registerReceiverForAllUsers(mReceiver, filter, null, null);
     }
 
@@ -726,6 +951,7 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
 
         mState = NfcAdapter.STATE_OFF;
         mAlwaysOnState = NfcAdapter.STATE_OFF;
+        mAlwaysOnMode = NfcOemExtension.ENABLE_DEFAULT;
 
         mIsDebugBuild = "userdebug".equals(Build.TYPE) || "eng".equals(Build.TYPE);
 
@@ -757,10 +983,16 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
         }
         mAlarmManager = mContext.getSystemService(AlarmManager.class);
 
+        mCheckDisplayStateForScreenState =
+                mContext.getResources().getBoolean(R.bool.check_display_state_for_screen_state);
         if (mInProvisionMode) {
             mScreenState = mScreenStateHelper.checkScreenStateProvisionMode();
         } else {
-            mScreenState = mScreenStateHelper.checkScreenState();
+            mScreenState = mScreenStateHelper.checkScreenState(mCheckDisplayStateForScreenState);
+        }
+        if (mCheckDisplayStateForScreenState) {
+            DisplayManager displayManager = mContext.getSystemService(DisplayManager.class);
+            displayManager.registerDisplayListener(mDisplayListener, mHandler);
         }
 
         mBackupManager = mNfcInjector.getBackupManager();
@@ -811,13 +1043,14 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
         mIsHceFCapable =
                 pm.hasSystemFeature(PackageManager.FEATURE_NFC_HOST_CARD_EMULATION_NFCF);
         if (mIsHceCapable) {
-            mCardEmulationManager = new CardEmulationManager(mContext, mNfcInjector);
+            mCardEmulationManager =
+                new CardEmulationManager(mContext, mNfcInjector, mDeviceConfigFacade);
         }
         mForegroundUtils = mNfcInjector.getForegroundUtils();
-        mIsSecureNfcCapable = mNfcInjector.checkIsSecureNfcCapable();
-        mIsSecureNfcEnabled =
-            mPrefs.getBoolean(PREF_SECURE_NFC_ON, SECURE_NFC_ON_DEFAULT) &&
-            mIsSecureNfcCapable;
+        mIsSecureNfcCapable = mDeviceConfigFacade.isSecureNfcCapable();
+        mIsSecureNfcEnabled = mPrefs.getBoolean(PREF_SECURE_NFC_ON,
+            mDeviceConfigFacade.getDefaultSecureNfcState())
+            && mIsSecureNfcCapable;
         mDeviceHost.setNfcSecure(mIsSecureNfcEnabled);
 
         sToast_debounce_time_ms =
@@ -862,6 +1095,12 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
 
         mIsTagAppPrefSupported =
             mContext.getResources().getBoolean(R.bool.tag_intent_app_pref_supported);
+        if (mIsTagAppPrefSupported) {
+            // Get default blocked package list from resource file overlay
+            mTagAppDefaultBlockList = new ArrayList<>(
+                    Arrays.asList(mContext.getResources().getStringArray(
+                            R.array.tag_intent_blocked_app_list)));
+        }
 
         Uri uri = Settings.Global.getUriFor(Constants.SETTINGS_SATELLITE_MODE_ENABLED);
         if (uri == null) {
@@ -909,80 +1148,85 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
         );
 
         mNfcPermissions = new NfcPermissions(mContext);
-        mReaderOptionCapable =
-                mContext.getResources().getBoolean(R.bool.enable_reader_option_support);
+        mReaderOptionCapable = mDeviceConfigFacade.isReaderOptionCapable();
 
         if(mReaderOptionCapable) {
             mIsReaderOptionEnabled =
-                mPrefs.getBoolean(PREF_NFC_READER_OPTION_ON, NFC_READER_OPTION_DEFAULT);
+                mPrefs.getBoolean(PREF_NFC_READER_OPTION_ON,
+                    mDeviceConfigFacade.getDefaultReaderOption() || mInProvisionMode);
         }
 
         executeTaskBoot();  // do blocking boot tasks
 
-        if (NFC_SNOOP_LOG_MODE.equals(NfcProperties.snoop_log_mode_values.FULL) ||
-            NFC_VENDOR_DEBUG_ENABLED) {
+        if ((NFC_SNOOP_LOG_MODE.equals(NfcProperties.snoop_log_mode_values.FULL) ||
+            NFC_VENDOR_DEBUG_ENABLED) && mContext.getResources().getBoolean(
+                    R.bool.enable_developer_option_notification)) {
             new NfcDeveloperOptionNotification(mContext).startNotification();
         }
 
         connectToSeService();
     }
 
-    private AlarmManager.OnAlarmListener mDelayedBootAlarmListener =
-            () -> {
-                Log.i(TAG, "Executing delayed boot");
-                mDelayedBootAlarmListenerSet = false;
-                new EnableDisableTask().execute(TASK_BOOT);
-            };
-    private boolean mDelayedBootAlarmListenerSet = false;
-
     private void executeTaskBoot() {
         // If overlay is set, delay the NFC boot up until the OEM extension indicates it is ready to
         // proceed with NFC bootup.
         if (mContext.getResources().getBoolean(R.bool.enable_oem_extension)) {
-            mAlarmManager.setExact(AlarmManager.ELAPSED_REALTIME_WAKEUP,
-                    mNfcInjector.getElapsedSinceBootMillis() + WAIT_FOR_OEM_ALLOW_BOOT_TIMEOUT_MS,
-                    WAIT_FOR_OEM_ALLOW_BOOT_TIMER_TAG, mDelayedBootAlarmListener, mHandler);
-            mDelayedBootAlarmListenerSet = true;
             return;
         }
         new EnableDisableTask().execute(TASK_BOOT);
     }
 
+    private List<Integer> getEnabledUserIds() {
+        List<Integer> userIds = new ArrayList<Integer>();
+        UserManager um =
+                mContext.createContextAsUser(UserHandle.of(ActivityManager.getCurrentUser()), 0)
+                        .getSystemService(UserManager.class);
+        List<UserHandle> luh = um.getEnabledProfiles();
+        for (UserHandle uh : luh) {
+            userIds.add(uh.getIdentifier());
+        }
+        return userIds;
+    }
+
     private void initTagAppPrefList() {
         if (!mIsTagAppPrefSupported) return;
         mTagAppPrefList.clear();
         mTagAppPrefListPrefs = mContext.getSharedPreferences(PREF_TAG_APP_LIST,
                 Context.MODE_PRIVATE);
+        boolean changed = false;
+        if (mTagAppPrefListPrefs == null) {
+            Log.e(TAG, "Can't get PREF_TAG_APP_LIST");
+            return;
+        }
         try {
-            if (mTagAppPrefListPrefs != null) {
-                UserManager um = mContext.createContextAsUser(
-                        UserHandle.of(ActivityManager.getCurrentUser()), 0)
-                        .getSystemService(UserManager.class);
-                List<UserHandle> luh = um.getEnabledProfiles();
-                for (UserHandle uh : luh) {
-                    HashMap<String, Boolean> map = new HashMap<>();
-                    int userId = uh.getIdentifier();
-                    String jsonString =
-                            mTagAppPrefListPrefs.getString(Integer.toString(userId),
-                                    (new JSONObject()).toString());
-                    if (jsonString != null) {
-                        JSONObject jsonObject = new JSONObject(jsonString);
-                        Iterator<String> keysItr = jsonObject.keys();
-                        while (keysItr.hasNext()) {
-                            String key = keysItr.next();
-                            Boolean value = jsonObject.getBoolean(key);
-                            map.put(key, value);
-                            if (DBG) Log.d(TAG, "uid:" + userId + "key:" + key + ": " + value);
-                        }
+            for (Integer userId : getEnabledUserIds()) {
+                HashMap<String, Boolean> map = new HashMap<>();
+                String jsonString =
+                        mTagAppPrefListPrefs.getString(Integer.toString(userId),
+                                (new JSONObject()).toString());
+                if (jsonString != null) {
+                    JSONObject jsonObject = new JSONObject(jsonString);
+                    Iterator<String> keysItr = jsonObject.keys();
+                    while (keysItr.hasNext()) {
+                        String key = keysItr.next();
+                        Boolean value = jsonObject.getBoolean(key);
+                        map.put(key, value);
+                        if (DBG) Log.d(TAG, "uid:" + userId + "key:" + key + ": " + value);
                     }
-                    mTagAppPrefList.put(userId, map);
                 }
-            } else {
-                Log.e(TAG, "Can't get PREF_TAG_APP_LIST");
+                // Put default blocked pkgs if not exist in the list
+                for (String pkg : mTagAppDefaultBlockList) {
+                    if (!map.containsKey(pkg) && isPackageInstalled(pkg, userId)) {
+                        map.put(pkg, false);
+                        changed = true;
+                    }
+                }
+                mTagAppPrefList.put(userId, map);
             }
         } catch (JSONException e) {
             Log.e(TAG, "JSONException: " + e);
         }
+        if (changed) storeTagAppPrefList();
     }
 
     private void storeTagAppPrefList() {
@@ -990,13 +1234,8 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
         mTagAppPrefListPrefs = mContext.getSharedPreferences(PREF_TAG_APP_LIST,
                 Context.MODE_PRIVATE);
         if (mTagAppPrefListPrefs != null) {
-            UserManager um = mContext.createContextAsUser(
-                    UserHandle.of(ActivityManager.getCurrentUser()), 0)
-                    .getSystemService(UserManager.class);
-            List<UserHandle> luh = um.getEnabledProfiles();
-            for (UserHandle uh : luh) {
+            for (Integer userId : getEnabledUserIds()) {
                 SharedPreferences.Editor editor = mTagAppPrefListPrefs.edit();
-                int userId = uh.getIdentifier();
                 HashMap<String, Boolean> map;
                 synchronized (NfcService.this) {
                     map = mTagAppPrefList.getOrDefault(userId, new HashMap<>());
@@ -1023,23 +1262,31 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
         return info != null;
     }
     // Remove obsolete entries
-    // return true if the preference list changed.
-    private boolean renewTagAppPrefList() {
-        if (!mIsTagAppPrefSupported) return false;
+    private void renewTagAppPrefList(String action) {
+        if (!mIsTagAppPrefSupported) return;
+        if (!action.equals(Intent.ACTION_PACKAGE_ADDED)
+                && !action.equals(Intent.ACTION_PACKAGE_REMOVED)) return;
         boolean changed = false;
-        UserManager um = mContext.createContextAsUser(
-                UserHandle.of(ActivityManager.getCurrentUser()), 0)
-                .getSystemService(UserManager.class);
-        List<UserHandle> luh = um.getEnabledProfiles();
-        for (UserHandle uh : luh) {
-            int userId = uh.getIdentifier();
+        for (Integer userId : getEnabledUserIds()) {
             synchronized (NfcService.this) {
-                changed = mTagAppPrefList.getOrDefault(userId, new HashMap<>())
-                        .keySet().removeIf(k2 -> !isPackageInstalled(k2, userId));
+                if (action.equals(Intent.ACTION_PACKAGE_ADDED)) {
+                    HashMap<String, Boolean> map =
+                            mTagAppPrefList.getOrDefault(userId, new HashMap<>());
+                    for (String pkg : mTagAppDefaultBlockList) {
+                        if (!map.containsKey(pkg) && isPackageInstalled(pkg, userId)) {
+                            map.put(pkg, false);
+                            changed = true;
+                            mTagAppPrefList.put(userId, map);
+                        }
+                    }
+                } else if (action.equals(Intent.ACTION_PACKAGE_REMOVED)) {
+                    changed |= mTagAppPrefList.getOrDefault(userId, new HashMap<>())
+                            .keySet().removeIf(k2 -> !isPackageInstalled(k2, userId));
+                }
             }
         }
         if (DBG) Log.d(TAG, "TagAppPreference changed " + changed);
-        return changed;
+        if (changed) storeTagAppPrefList();
     }
 
     private boolean isSEServiceAvailable() {
@@ -1061,9 +1308,22 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
         }
     }
 
-    void initSoundPool() {
+    void initSoundPoolIfNeededAndPlaySound(Runnable playSoundRunnable) {
         synchronized (this) {
             if (mSoundPool == null) {
+                // For the first sound play which triggers the sound pool initialization, play the
+                // sound after sound pool load is complete.
+                OnLoadCompleteListener onLoadCompleteListener = new OnLoadCompleteListener() {
+                    private int mNumLoadComplete = 0;
+                    @Override
+                    public void onLoadComplete(SoundPool soundPool, int sampleId, int status) {
+                        // Check that both end/error sounds are loaded before playing the sound.
+                        if (++mNumLoadComplete == 2) {
+                            Log.d(TAG, "Sound pool onLoadComplete: playing sound");
+                            playSoundRunnable.run();
+                        }
+                    }
+                };
                 mSoundPool = new SoundPool.Builder()
                         .setMaxStreams(1)
                         .setAudioAttributes(
@@ -1072,9 +1332,13 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
                                         .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION)
                                         .build())
                         .build();
-                mStartSound = mSoundPool.load(mContext, R.raw.start, 1);
+                mSoundPool.setOnLoadCompleteListener(onLoadCompleteListener);
                 mEndSound = mSoundPool.load(mContext, R.raw.end, 1);
                 mErrorSound = mSoundPool.load(mContext, R.raw.error, 1);
+            } else {
+                // sound pool already loaded, play the sound.
+                Log.d(TAG, "Sound pool is already loaded, playing sound");
+                playSoundRunnable.run();
             }
         }
     }
@@ -1159,18 +1423,21 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
      * preferences
      * <p>{@link #TASK_BOOT} does first boot work and may enable NFC
      */
-    class EnableDisableTask extends AsyncTask<Integer, Void, Void> {
+    class EnableDisableTask extends AsyncTask<Integer, Void, Boolean> {
+        int action;
         @Override
-        protected Void doInBackground(Integer... params) {
+        protected Boolean doInBackground(Integer... params) {
             // Quick check mState
             switch (mState) {
                 case NfcAdapter.STATE_TURNING_OFF:
                 case NfcAdapter.STATE_TURNING_ON:
                     Log.e(TAG, "Processing EnableDisable task " + params[0] + " from bad state " +
                             mState);
-                    return null;
+                    return false;
             }
 
+            action = params[0].intValue();
+            boolean result = true;
             /* AsyncTask sets this thread to THREAD_PRIORITY_BACKGROUND,
              * override with the default. THREAD_PRIORITY_BACKGROUND causes
              * us to service software I2C too slow for firmware download
@@ -1179,19 +1446,28 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
              * problem only occurs on I2C platforms using PN544
              */
             Process.setThreadPriority(Process.THREAD_PRIORITY_DEFAULT);
-
-            switch (params[0].intValue()) {
+            switch (action) {
                 case TASK_ENABLE:
-                    enableInternal();
-                    if (sIsNfcRestore && mIsTagAppPrefSupported) {
-                        synchronized (NfcService.this) {
-                            initTagAppPrefList();
-                            sIsNfcRestore = false;
+                    if (shouldEnableNfc()) {
+                        onOemPreExecute();
+                        result = enableInternal();
+                        if (sIsNfcRestore && mIsTagAppPrefSupported) {
+                            synchronized (NfcService.this) {
+                                initTagAppPrefList();
+                                sIsNfcRestore = false;
+                            }
                         }
+                    } else {
+                        result = false;
                     }
                     break;
                 case TASK_DISABLE:
-                    disableInternal();
+                    if(allowOemDisable()) {
+                        onOemPreExecute();
+                        result = disableInternal();
+                    } else {
+                        result = false;
+                    }
                     break;
                 case TASK_BOOT:
                     // Initialize the event log cache.
@@ -1205,6 +1481,7 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
                     }
                     Log.d(TAG, "checking on firmware download");
                     boolean enableNfc = shouldEnableNfc();
+                    onOemPreExecute();
                     if (enableNfc) {
                         Log.d(TAG, "NFC is on. Doing normal stuff");
                         initialized = enableInternal();
@@ -1224,23 +1501,64 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
                         // Remove this code when a replacement API is added.
                         NfcProperties.initialized(true);
                     }
-                    if (mIsTagAppPrefSupported) {
-                        synchronized (NfcService.this) {
-                            initTagAppPrefList();
-                        }
+                    synchronized (NfcService.this) {
+                        initTagAppPrefList();
                     }
+                    result = initialized;
                     break;
                 case TASK_ENABLE_ALWAYS_ON:
-                    enableAlwaysOnInternal();
+                    /* Get mode from AsyncTask params */
+                    result = enableAlwaysOnInternal(params[1]);
                     break;
                 case TASK_DISABLE_ALWAYS_ON:
-                    disableAlwaysOnInternal();
+                    result = disableAlwaysOnInternal();
+                    break;
+                default:
                     break;
             }
 
             // Restore default AsyncTask priority
             Process.setThreadPriority(Process.THREAD_PRIORITY_BACKGROUND);
-            return null;
+            return result;
+        }
+
+        @Override
+        protected void onPostExecute(Boolean result) {
+            Log.d(TAG, "onPostExecute / result - " + result);
+            if (mNfcOemExtensionCallback != null) {
+                try {
+                    if (action == TASK_BOOT)
+                        mNfcOemExtensionCallback
+                                .onBootFinished(result ? STATUS_OK : STATUS_UNKNOWN_ERROR);
+                    else if (action == TASK_ENABLE)
+                        mNfcOemExtensionCallback
+                                .onEnableFinished(result ? STATUS_OK : STATUS_UNKNOWN_ERROR);
+                    else if (action == TASK_DISABLE)
+                        mNfcOemExtensionCallback
+                                .onDisableFinished(result ? STATUS_OK : STATUS_UNKNOWN_ERROR);
+                } catch (RemoteException remoteException) {
+                    Log.e(TAG, "Failed to call remote oem extension callback");
+                }
+            }
+        }
+
+        void onOemPreExecute() {
+            if (mNfcOemExtensionCallback != null) {
+                try {
+                    if (action == TASK_BOOT)
+                        mNfcOemExtensionCallback.onBootStarted();
+                    else if (action == TASK_ENABLE)
+                        mNfcOemExtensionCallback.onEnableStarted();
+                    else if (action == TASK_DISABLE)
+                        mNfcOemExtensionCallback.onDisableStarted();
+                } catch (RemoteException remoteException) {
+                    Log.e(TAG, "Failed to call remote oem extension callback");
+                }
+            }
+        }
+
+        boolean isAlwaysOnInDefaultMode() {
+            return mAlwaysOnMode == NfcOemExtension.ENABLE_DEFAULT;
         }
 
         /**
@@ -1250,6 +1568,11 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
         boolean enableInternal() {
             if (mState == NfcAdapter.STATE_ON) {
                 return true;
+            } else if (mAlwaysOnState == NfcAdapter.STATE_ON) {
+                if (!isAlwaysOnInDefaultMode()) {
+                    Log.i(TAG, "ControllerAlwaysOn Not In DEFAULT_MODE - disableAlwaysOn!");
+                    disableAlwaysOnInternal();
+                }
             }
             Log.i(TAG, "Enabling NFC");
             NfcStatsLog.write(NfcStatsLog.NFC_STATE_CHANGED,
@@ -1278,7 +1601,7 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
                             || mAlwaysOnState == NfcAdapter.STATE_TURNING_OFF) {
                         Log.i(TAG, "Already initialized");
                     } else {
-                        Log.e(TAG, "Unexptected bad state " + mAlwaysOnState);
+                        Log.e(TAG, "Unexpected bad state " + mAlwaysOnState);
                         updateState(NfcAdapter.STATE_OFF);
                         return false;
                     }
@@ -1304,12 +1627,10 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
                 onPreferredPaymentChanged(NfcAdapter.PREFERRED_PAYMENT_LOADED);
             }
 
-            initSoundPool();
-
             if (mInProvisionMode) {
                 mScreenState = mScreenStateHelper.checkScreenStateProvisionMode();
             } else {
-                mScreenState = mScreenStateHelper.checkScreenState();
+                mScreenState = mScreenStateHelper.checkScreenState(mCheckDisplayStateForScreenState);
             }
             int screen_state_mask = (mNfcUnlockManager.isLockscreenPollingEnabled()) ?
                              (ScreenStateHelper.SCREEN_POLLING_TAG_MASK | mScreenState) : mScreenState;
@@ -1361,7 +1682,6 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
                 mDeviceHost.setPowerSavingMode(false);
                 mIsPowerSavingModeEnabled = false;
             }
-
             return true;
         }
 
@@ -1442,50 +1762,59 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
         /**
          * Enable always on feature.
          */
-        void enableAlwaysOnInternal() {
+        boolean enableAlwaysOnInternal(int mode) {
             if (mAlwaysOnState == NfcAdapter.STATE_ON) {
-                return;
+                return true;
             } else if (mState == NfcAdapter.STATE_TURNING_ON
                     || mAlwaysOnState == NfcAdapter.STATE_TURNING_OFF) {
                 Log.e(TAG, "Processing enableAlwaysOnInternal() from bad state");
-                return;
+                return false;
             } else if (mState == NfcAdapter.STATE_ON) {
                 updateAlwaysOnState(NfcAdapter.STATE_TURNING_ON);
                 mDeviceHost.setNfceePowerAndLinkCtrl(true);
                 updateAlwaysOnState(NfcAdapter.STATE_ON);
             } else if (mState == NfcAdapter.STATE_OFF) {
                 /* Special case when NFCC is OFF without initialize.
-                 * Temperatorily enable NfcAdapter but don't applyRouting.
+                 * Temporarily enable NfcAdapter but don't applyRouting.
                  * Then disable NfcAdapter without deinitialize to keep the NFCC stays initialized.
                  * mState will switch back to OFF in the end.
                  * And the NFCC stays initialized.
                  */
                 updateAlwaysOnState(NfcAdapter.STATE_TURNING_ON);
+                if (mode != NfcOemExtension.ENABLE_DEFAULT) {
+                    mDeviceHost.setPartialInitMode(mode);
+                    mAlwaysOnMode = mode;
+                }
                 if (!enableInternal()) {
                     updateAlwaysOnState(NfcAdapter.STATE_OFF);
-                    return;
+                    return false;
                 }
                 disableInternal();
                 mDeviceHost.setNfceePowerAndLinkCtrl(true);
                 updateAlwaysOnState(NfcAdapter.STATE_ON);
             }
+            return true;
         }
 
         /**
          * Disable always on feature.
          */
-        void disableAlwaysOnInternal() {
+        boolean disableAlwaysOnInternal() {
             if (mAlwaysOnState == NfcAdapter.STATE_OFF) {
-                return;
-            } else if (mState == NfcAdapter.STATE_TURNING_ON
-                    || mAlwaysOnState == NfcAdapter.STATE_TURNING_OFF) {
-                Log.e(TAG, "Processing disableAlwaysOnInternal() from bad state");
-                return;
+                return true;
+            } else if ((mState == NfcAdapter.STATE_TURNING_ON
+                    || mAlwaysOnState == NfcAdapter.STATE_TURNING_OFF)
+                    && (!(mAlwaysOnState == NfcAdapter.STATE_ON))) {
+                if (!isAlwaysOnInDefaultMode()) {
+                    Log.e(TAG, "Processing disableAlwaysOnInternal() from bad state");
+                    return false;
+                }
             } else if (mState == NfcAdapter.STATE_ON) {
                 updateAlwaysOnState(NfcAdapter.STATE_TURNING_OFF);
                 mDeviceHost.setNfceePowerAndLinkCtrl(false);
                 updateAlwaysOnState(NfcAdapter.STATE_OFF);
-            } else if (mState == NfcAdapter.STATE_OFF) {
+            } else if (mState == NfcAdapter.STATE_OFF
+                        || (mAlwaysOnState == NfcAdapter.STATE_ON)) {
                 /* Special case when mState is OFF but NFCC is already initialized.
                  * Deinitialize mDevicehost directly.
                  */
@@ -1494,7 +1823,9 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
                 boolean result = mDeviceHost.deinitialize();
                 if (DBG) Log.d(TAG, "mDeviceHost.deinitialize() = " + result);
                 updateAlwaysOnState(NfcAdapter.STATE_OFF);
+                return result;
             }
+            return true;
         }
 
         void updateState(int newState) {
@@ -1511,6 +1842,12 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
                     intent.setFlags(Intent.FLAG_RECEIVER_REGISTERED_ONLY_BEFORE_BOOT);
                     intent.putExtra(NfcAdapter.EXTRA_ADAPTER_STATE, mState);
                     mContext.sendBroadcastAsUser(intent, UserHandle.CURRENT);
+                    if(mNfcOemExtensionCallback != null)
+                        try {
+                            mNfcOemExtensionCallback.onStateUpdated(mState);
+                        } catch (RemoteException remoteException) {
+                            Log.e(TAG, "Failed to invoke onStateUpdated oem callback");
+                        }
                 }
             }
         }
@@ -1520,6 +1857,10 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
                 if (newState == mAlwaysOnState) {
                     return;
                 }
+                if (newState == NfcAdapter.STATE_OFF) {
+                    mAlwaysOnMode = NfcOemExtension.ENABLE_DEFAULT;
+                    mDeviceHost.setPartialInitMode(NfcOemExtension.ENABLE_DEFAULT);
+                }
                 mAlwaysOnState = newState;
                 if (mAlwaysOnState == NfcAdapter.STATE_OFF
                         || mAlwaysOnState == NfcAdapter.STATE_ON) {
@@ -1549,26 +1890,27 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
         }
     }
 
+
     public void playSound(int sound) {
         synchronized (this) {
-            if (mSoundPool == null) {
-                Log.w(TAG, "Not playing sound when NFC is disabled");
-                return;
-            }
-
             if (mVrManager != null && mVrManager.isVrModeEnabled()) {
                 Log.d(TAG, "Not playing NFC sound when Vr Mode is enabled");
                 return;
             }
             switch (sound) {
-                case SOUND_START:
-                    mSoundPool.play(mStartSound, 1.0f, 1.0f, 0, 0, 1.0f);
-                    break;
                 case SOUND_END:
-                    mSoundPool.play(mEndSound, 1.0f, 1.0f, 0, 0, 1.0f);
+                    // Lazy init sound pool when needed.
+                    initSoundPoolIfNeededAndPlaySound(() -> {
+                        int playReturn = mSoundPool.play(mEndSound, 1.0f, 1.0f, 0, 0, 1.0f);
+                        Log.d(TAG, "Sound pool play return: " + playReturn);
+                    });
                     break;
                 case SOUND_ERROR:
-                    mSoundPool.play(mErrorSound, 1.0f, 1.0f, 0, 0, 1.0f);
+                    // Lazy init sound pool when needed.
+                    initSoundPoolIfNeededAndPlaySound(() -> {
+                        int playReturn = mSoundPool.play(mErrorSound, 1.0f, 1.0f, 0, 0, 1.0f);
+                        Log.d(TAG, "Sound pool play return: " + playReturn);
+                    });
                     break;
             }
         }
@@ -1621,9 +1963,7 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
     public void enableNfc() {
         saveNfcOnSetting(true);
 
-        if (shouldEnableNfc()) {
-            new EnableDisableTask().execute(TASK_ENABLE);
-        }
+        new EnableDisableTask().execute(TASK_ENABLE);
     }
 
     private @NonNull CharSequence getAppName(@NonNull String packageName, int uid) {
@@ -1668,12 +2008,17 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
                 throw new SecurityException("Change nfc state by system app is not allowed!");
             }
 
+            if(!NfcProperties.initialized().orElse(Boolean.FALSE)) {
+                Log.e(TAG, "NFC is not initialized yet:" +
+                        NfcProperties.initialized().orElse(Boolean.FALSE)) ;
+                return false;
+            }
             Log.i(TAG, "Enabling Nfc service. Package:" + pkg);
             List<String> allowlist = new ArrayList<>(
                     Arrays.asList(mContext.getResources().getStringArray(R.array.nfc_allow_list)));
             if (!allowlist.isEmpty() && !allowlist.contains(pkg)) {
                 Intent allowUsingNfcIntent = new Intent()
-                        .putExtra(APP_NAME_ENABLING_NFC, getAppName(pkg, mUserId))
+                        .putExtra(APP_NAME_ENABLING_NFC, getAppName(pkg, getUserId()))
                         .setClass(mContext, NfcEnableAllowlistActivity.class);
 
                 mContext.startActivityAsUser(allowUsingNfcIntent, UserHandle.CURRENT);
@@ -1797,9 +2142,6 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
 
             long start = SystemClock.elapsedRealtime();
             boolean result = mDeviceHost.setObserveMode(enable);
-            if (result && mCardEmulationManager != null) {
-                mCardEmulationManager.onObserveModeStateChange(enable);
-            }
             int latency = Math.toIntExact(SystemClock.elapsedRealtime() - start);
             if (mStatsdUtils != null) {
                 mStatsdUtils.logObserveModeStateChanged(enable, triggerSource, latency);
@@ -1885,6 +2227,15 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
                 mIsSecureNfcEnabled = enable;
                 mBackupManager.dataChanged();
                 mDeviceHost.setNfcSecure(enable);
+                if (android.nfc.Flags.nfcPersistLog()) {
+                    mNfcEventLog.logEvent(
+                            NfcEventProto.EventType.newBuilder()
+                                    .setSecureChange(
+                                            NfcEventProto.NfcSecureChange.newBuilder()
+                                                    .setEnable(enable)
+                                                    .build())
+                                    .build());
+                }
                 if (mIsHceCapable) {
                     // update HCE/HCEF routing and commitRouting if Nfc is enabled
                     mCardEmulationManager.onSecureNfcToggled();
@@ -2025,17 +2376,15 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
         }
 
         @Override
-        public void updateDiscoveryTechnology(IBinder binder, int pollTech, int listenTech)
+        public void updateDiscoveryTechnology(
+                IBinder binder, int pollTech, int listenTech, String packageName)
                 throws RemoteException {
             NfcPermissions.enforceUserPermissions(mContext);
             int callingUid = Binder.getCallingUid();
             boolean privilegedCaller = isPrivileged(callingUid)
                     || NfcPermissions.checkAdminPermissions(mContext);
             // Allow non-foreground callers with system uid or systemui
-            String packageName = getPackageNameFromUid(callingUid);
-            if (packageName != null) {
-                privilegedCaller |= packageName.equals(SYSTEM_UI);
-            }
+            privilegedCaller |= packageName.equals(SYSTEM_UI);
             Log.d(TAG, "updateDiscoveryTechnology: uid=" + callingUid +
                     ", packageName: " + packageName);
             if (!privilegedCaller) {
@@ -2050,10 +2399,15 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
             } else if (((pollTech & NfcAdapter.FLAG_SET_DEFAULT_TECH) != 0
                         || (listenTech & NfcAdapter.FLAG_SET_DEFAULT_TECH) != 0)) {
 
+                if (!isNfcEnabled()) {
+                    Log.d(TAG, "updateDiscoveryTechnology: NFC is not enabled.");
+                    return;
+                }
                 if ((pollTech & NfcAdapter.FLAG_SET_DEFAULT_TECH) != 0) {
                     if ((pollTech & NfcAdapter.FLAG_READER_KEEP) == 0 &&
                         (pollTech & NfcAdapter.FLAG_USE_ALL_TECH)
                             != NfcAdapter.FLAG_USE_ALL_TECH) {
+                        pollTech = getReaderModeTechMask(pollTech);
                         saveNfcPollTech(pollTech & ~NfcAdapter.FLAG_SET_DEFAULT_TECH);
                         Log.i(TAG, "Default pollTech is set to 0x" +
                             Integer.toHexString(pollTech));
@@ -2102,12 +2456,28 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
                 } else if (!(pollTech == NfcAdapter.FLAG_USE_ALL_TECH && // Do not call for
                                                                          // resetDiscoveryTech
                         listenTech == NfcAdapter.FLAG_USE_ALL_TECH)) {
+                        pollTech = getReaderModeTechMask(pollTech);
                     try {
                         mDeviceHost.setDiscoveryTech(pollTech, listenTech);
                         mDiscoveryTechParams = new DiscoveryTechParams();
                         mDiscoveryTechParams.uid = callingUid;
                         mDiscoveryTechParams.binder = binder;
                         binder.linkToDeath(mDiscoveryTechDeathRecipient, 0);
+                        if (android.nfc.Flags.nfcPersistLog()) {
+                            mNfcEventLog.logEvent(
+                                    NfcEventProto.EventType.newBuilder()
+                                            .setDiscoveryTechnologyUpdate(NfcEventProto
+                                                    .NfcDiscoveryTechnologyUpdate.newBuilder()
+                                                    .setAppInfo(NfcEventProto.NfcAppInfo
+                                                            .newBuilder()
+                                                            .setPackageName(packageName)
+                                                            .setUid(callingUid)
+                                                            .build())
+                                                    .setPollTech(pollTech)
+                                                    .setListenTech(listenTech)
+                                                    .build())
+                                            .build());
+                        }
                     } catch (RemoteException e) {
                         Log.e(TAG, "Remote binder has already died.");
                         return;
@@ -2121,17 +2491,15 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
         }
 
         @Override
-        public void setReaderMode(IBinder binder, IAppCallback callback, int flags, Bundle extras)
+        public void setReaderMode(
+                IBinder binder, IAppCallback callback, int flags, Bundle extras, String packageName)
                 throws RemoteException {
             int callingUid = Binder.getCallingUid();
             int callingPid = Binder.getCallingPid();
             boolean privilegedCaller = isPrivileged(callingUid)
                     || NfcPermissions.checkAdminPermissions(mContext);
             // Allow non-foreground callers with system uid or systemui
-            String packageName = getPackageNameFromUid(callingUid);
-            if (packageName != null) {
-                privilegedCaller |= packageName.equals(SYSTEM_UI);
-            }
+            privilegedCaller |= packageName.equals(SYSTEM_UI);
             Log.d(TAG, "setReaderMode: uid=" + callingUid + ", packageName: "
                     + packageName + ", flags: " + flags);
             if (!privilegedCaller
@@ -2262,14 +2630,28 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
                     R.array.antenna_x);
             int positionY[] = mContext.getResources().getIntArray(
                     R.array.antenna_y);
+            int width = mContext.getResources().getInteger(R.integer.device_width);
+            int height = mContext.getResources().getInteger(R.integer.device_height);
+            boolean isFoldable = mContext.getResources().getBoolean(R.bool.device_foldable);
+
+            // If overlays are not set, try reading properties.
+            if (positionX.length == 0 || positionY.length == 0) {
+                positionX = NfcProperties.info_antpos_X().stream()
+                        .mapToInt(Integer::intValue)
+                        .toArray();
+                positionY = NfcProperties.info_antpos_Y().stream()
+                        .mapToInt(Integer::intValue)
+                        .toArray();
+                width = NfcProperties.info_antpos_device_width().orElse(0);
+                height = NfcProperties.info_antpos_device_height().orElse(0);
+                isFoldable = NfcProperties.info_antpos_device_foldable().orElse(false);
+            }
             if(positionX.length != positionY.length){
                 return null;
             }
-            int width = mContext.getResources().getInteger(R.integer.device_width);
-            int height = mContext.getResources().getInteger(R.integer.device_height);
             List<AvailableNfcAntenna> availableNfcAntennas = new ArrayList<>();
             for(int i = 0; i < positionX.length; i++){
-                if(positionX[i] >= width | positionY[i] >= height){
+                if(positionX[i] >= width || positionY[i] >= height){
                     return null;
                 }
                 availableNfcAntennas.add(new AvailableNfcAntenna(positionX[i], positionY[i]));
@@ -2277,7 +2659,7 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
             return new NfcAntennaInfo(
                     width,
                     height,
-                    mContext.getResources().getBoolean(R.bool.device_foldable),
+                    isFoldable,
                     availableNfcAntennas);
         }
 
@@ -2299,6 +2681,15 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
                 mIsWlcEnabled = enable;
                 mBackupManager.dataChanged();
             }
+            if (android.nfc.Flags.nfcPersistLog()) {
+                mNfcEventLog.logEvent(
+                        NfcEventProto.EventType.newBuilder()
+                                .setWlcStateChange(
+                                        NfcEventProto.NfcWlcStateChange.newBuilder()
+                                                .setEnable(enable)
+                                                .build())
+                                .build());
+            }
             return true;
         }
 
@@ -2405,17 +2796,18 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
         }
 
         @Override
-        public boolean setControllerAlwaysOn(boolean value) throws RemoteException {
+        public void setControllerAlwaysOn(int mode) throws RemoteException {
             NfcPermissions.enforceSetControllerAlwaysOnPermissions(mContext);
             if (!mIsAlwaysOnSupported) {
-                return false;
+                throw new UnsupportedOperationException("isControllerAlwaysOn not supported");
             }
-            if (value) {
-                new EnableDisableTask().execute(TASK_ENABLE_ALWAYS_ON);
+            if (mode != NfcOemExtension.DISABLE) {
+                /* AsyncTask params */
+                Integer[] paramIntegers = {TASK_ENABLE_ALWAYS_ON, mode};
+                new EnableDisableTask().execute(paramIntegers);
             } else {
                 new EnableDisableTask().execute(TASK_DISABLE_ALWAYS_ON);
             }
-            return true;
         }
 
         @Override
@@ -2469,8 +2861,9 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
         }
 
         @Override
-        public boolean enableReaderOption(boolean enable) {
-            Log.d(TAG, "enableReaderOption enabled=" + enable);
+        public boolean enableReaderOption(boolean enable, String pkg) {
+            Log.d(TAG, "enableReaderOption enabled = " + enable + " calling uid = "
+                    + Binder.getCallingUid());
             if (!mReaderOptionCapable) return false;
             NfcPermissions.enforceAdminPermissions(mContext);
             synchronized (NfcService.this) {
@@ -2480,6 +2873,28 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
                 mBackupManager.dataChanged();
             }
             applyRouting(true);
+            if (mNfcOemExtensionCallback != null) {
+                try {
+                    mNfcOemExtensionCallback.onReaderOptionChanged(enable);
+                } catch (RemoteException e) {
+                    Log.e(TAG, "onReaderOptionChanged failed e = " + e.toString());
+                }
+            }
+
+            if (android.nfc.Flags.nfcPersistLog()) {
+                mNfcEventLog.logEvent(
+                        NfcEventProto.EventType.newBuilder()
+                                .setReaderOptionChange(
+                                        NfcEventProto.NfcReaderOptionChange.newBuilder()
+                                                .setEnable(enable)
+                                                .setAppInfo(
+                                                        NfcEventProto.NfcAppInfo.newBuilder()
+                                                    .setPackageName(pkg)
+                                                    .setUid(Binder.getCallingUid())
+                                                    .build())
+                                                .build())
+                                .build());
+            }
             return true;
         }
 
@@ -2531,7 +2946,8 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
                         (byte) (timestamp >>> 8),
                         (byte) timestamp });
                 int frame_data_length = frame_data == null ? 0 : frame_data.length;
-                String frame_data_str = frame_data_length == 0 ? "" : " " + format.formatHex(frame_data);
+                String frame_data_str =
+                        frame_data_length == 0 ? "" : " " + format.formatHex(frame_data);
                 String type_str = "FF";
                 switch (type) {
                     case PollingFrame.POLLING_LOOP_TYPE_ON:
@@ -2559,12 +2975,17 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
                         + " 03 " + type_str
                         + " 00 " + String.format("%02x", 5 + frame_data_length) + " "
                         + timestampBytes + " " + String.format("%02x", gain) + frame_data_str);
-                ((NativeNfcManager) mDeviceHost).notifyPollingLoopFrame(data.length, data);
+                ((NativeNfcManager) mDeviceHost).injectNtf(data);
             } catch (Exception ex) {
                 Log.e(TAG, "error when notifying polling loop", ex);
             }
         }
 
+        @Override
+        public void notifyTestHceData(int technology, byte[] data) {
+            onHostCardEmulationData(technology, data);
+        }
+
         @Override
         public void notifyHceDeactivated() {
             try {
@@ -2593,7 +3014,7 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
         public synchronized int sendVendorNciMessage(int mt, int gid, int oid, byte[] payload)
                 throws RemoteException {
             NfcPermissions.enforceAdminPermissions(mContext);
-            if ((!isNfcEnabled() && !mIsPowerSavingModeEnabled)) {
+            if ((!isNfcEnabled() && !mIsPowerSavingModeEnabled) && !isControllerAlwaysOn()) {
                 Log.e(TAG, "sendRawVendor : Nfc is not enabled");
                 return NCI_STATUS_FAILED;
             }
@@ -2651,6 +3072,10 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
             if (DBG) Log.i(TAG, "Register the oem extension callback");
             NfcPermissions.enforceAdminPermissions(mContext);
             mNfcOemExtensionCallback = callbacks;
+            updateNfCState();
+            if (mCardEmulationManager != null) {
+                mCardEmulationManager.setOemExtension(mNfcOemExtensionCallback);
+            }
         }
 
         @Override
@@ -2660,11 +3085,26 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
             NfcPermissions.enforceAdminPermissions(mContext);
             mNfcOemExtensionCallback = null;
         }
+        @Override
+        public List<String> fetchActiveNfceeList() throws RemoteException {
+            List<String> list = new ArrayList<String>();
+            if (isNfcEnabled()) {
+                list = mDeviceHost.dofetchActiveNfceeList();
+            }
+            return list;
+        }
 
         @Override
         public void clearPreference() throws RemoteException {
             if (DBG) Log.i(TAG, "clearPreference");
             NfcPermissions.enforceAdminPermissions(mContext);
+            if (android.nfc.Flags.nfcPersistLog()) {
+                mNfcEventLog.logEvent(NfcEventProto.EventType.newBuilder()
+                                .setClearPreference(
+                                        NfcEventProto.NfcClearPreference.newBuilder()
+                                                .build())
+                                .build());
+            }
             // TODO: Implement this.
         }
 
@@ -2672,7 +3112,7 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
         public void setScreenState() throws RemoteException {
             if (DBG) Log.i(TAG, "setScreenState");
             NfcPermissions.enforceAdminPermissions(mContext);
-            applyScreenState(mScreenStateHelper.checkScreenState());
+            applyScreenState(mScreenStateHelper.checkScreenState(mCheckDisplayStateForScreenState));
         }
 
         @Override
@@ -2683,13 +3123,22 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
         }
 
         // TODO(b/321304762): Add the OEM extension API.
-        public void allowBoot() throws RemoteException {
-            if (DBG) Log.i(TAG, "allowBoot");
+        public void triggerInitialization() throws RemoteException {
+            if (DBG) Log.i(TAG, "triggerInitialization");
             NfcPermissions.enforceAdminPermissions(mContext);
-            if (mDelayedBootAlarmListenerSet) {
-                Log.i(TAG, "OEM executing delayed boot");
-                mAlarmManager.cancel(mDelayedBootAlarmListener);
-                mDelayedBootAlarmListener.onAlarm();
+            new EnableDisableTask().execute(TASK_BOOT);
+        }
+
+        private void updateNfCState() {
+            if (mNfcOemExtensionCallback != null) {
+                try {
+                    if (DBG) Log.i(TAG, "updateNfCState");
+                    mNfcOemExtensionCallback.onCardEmulationActivated(mCardEmulationActivated);
+                    mNfcOemExtensionCallback.onRfFieldActivated(mRfFieldActivated);
+                    mNfcOemExtensionCallback.onRfDiscoveryStarted(mRfDiscoveryStarted);
+                } catch (RemoteException e) {
+                    Log.e(TAG, "Failed to update OemExtension with updateNfCState", e);
+                }
             }
         }
 
@@ -3150,7 +3599,9 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
             if(!sIsDtaMode) {
                 mDeviceHost.enableDtaMode();
                 sIsDtaMode = true;
-                Log.d(TAG, "DTA Mode is Enabled ");
+                Log.d(TAG, "DTA Mode is Enabled");
+            } else {
+                Log.d(TAG, "DTA Mode is already Enabled");
             }
         }
 
@@ -3159,6 +3610,9 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
             if(sIsDtaMode) {
                 mDeviceHost.disableDtaMode();
                 sIsDtaMode = false;
+                Log.d(TAG, "DTA Mode is Disabled");
+            } else {
+                Log.d(TAG, "DTA Mode is already Disabled");
             }
         }
 
@@ -3232,7 +3686,7 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
                 }
             } catch (InterruptedException e) {
                 // Should not happen; fall-through to abort.
-                Log.w(TAG, "Watchdog thread interruped.");
+                Log.w(TAG, "Watchdog thread interrupted.");
                 interrupt();
             }
             if(mRoutingWakeLock.isHeld()){
@@ -3263,8 +3717,13 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
         }
         byte[] data = new byte[len / 2];
         for (int i = 0; i < len; i += 2) {
-            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
-                    + Character.digit(s.charAt(i + 1), 16));
+            int high = Character.digit(s.charAt(i), 16);
+            int low = Character.digit(s.charAt(i + 1), 16);
+            if (high == -1 || low == -1) {
+                Log.e(TAG, "Invalid hex character found.");
+                return null;
+            }
+            data[i / 2] = (byte) ((high << 4) + low);
         }
         return data;
     }
@@ -3286,7 +3745,7 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
         @Override
         public void onKeyguardLockedStateChanged(boolean isKeyguardLocked) {
             if (!mIsWlcCapable || !mNfcCharging.NfcChargingOnGoing) {
-                applyScreenState(mScreenStateHelper.checkScreenState());
+                applyScreenState(mScreenStateHelper.checkScreenState(mCheckDisplayStateForScreenState));
             }
         }
     };
@@ -3335,7 +3794,11 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
             if (!isNfcEnabledOrShuttingDown()) {
                 return;
             }
-            WatchDogThread watchDog = new WatchDogThread("applyRouting", ROUTING_WATCHDOG_MS);
+            if(mNfcOemExtensionCallback != null
+                   && receiveOemCallbackResult(ACTION_ON_APPLY_ROUTING)) {
+                Log.d(TAG, "applyRouting: skip due to oem callback");
+                return;
+            }
             if (mInProvisionMode) {
                 mInProvisionMode = Settings.Global.getInt(mContentResolver,
                         Settings.Global.DEVICE_PROVISIONED, 0) == 0;
@@ -3345,6 +3808,10 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
                     mNfcDispatcher.disableProvisioningMode();
                 }
             }
+            if (mPollingPaused) {
+                Log.d(TAG, "Not updating discovery parameters, polling paused.");
+                return;
+            }
             // Special case: if we're transitioning to unlocked state while
             // still talking to a tag, postpone re-configuration.
             if (mScreenState == ScreenStateHelper.SCREEN_STATE_ON_UNLOCKED && isTagPresent()) {
@@ -3354,6 +3821,7 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
                 return;
             }
 
+            WatchDogThread watchDog = new WatchDogThread("applyRouting", ROUTING_WATCHDOG_MS);
             try {
                 watchDog.start();
                 // Compute new polling parameters
@@ -3402,9 +3870,9 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
             } else {
                 paramsBuilder.setTechMask(NfcDiscoveryParameters.NFC_POLL_DEFAULT);
             }
-        } else if (screenState == ScreenStateHelper.SCREEN_STATE_ON_LOCKED && mInProvisionMode) {
+        } else if (screenState == SCREEN_STATE_ON_LOCKED && mInProvisionMode) {
             paramsBuilder.setTechMask(NfcDiscoveryParameters.NFC_POLL_DEFAULT);
-        } else if (screenState == ScreenStateHelper.SCREEN_STATE_ON_LOCKED &&
+        } else if (screenState == SCREEN_STATE_ON_LOCKED &&
             mNfcUnlockManager.isLockscreenPollingEnabled() && isReaderOptionEnabled()) {
             int techMask = 0;
             if (mNfcUnlockManager.isLockscreenPollingEnabled())
@@ -3413,9 +3881,11 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
             paramsBuilder.setEnableLowPowerDiscovery(false);
         }
 
-        if (mIsHceCapable && mReaderModeParams == null) {
+        if (mIsHceCapable) {
             // Host routing is always enabled, provided we aren't in reader mode
-            paramsBuilder.setEnableHostRouting(true);
+            if (mReaderModeParams == null || mReaderModeParams.flags == DISABLE_POLLING_FLAGS) {
+                paramsBuilder.setEnableHostRouting(true);
+            }
         }
 
         return paramsBuilder.build();
@@ -3575,7 +4045,7 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
         if (DBG) Log.d(TAG, "sendScreenMessageAfterNfcCharging() ");
 
         if (mPendingPowerStateUpdate == true) {
-            int screenState = mScreenStateHelper.checkScreenState();
+            int screenState = mScreenStateHelper.checkScreenState(mCheckDisplayStateForScreenState);
             if (DBG) Log.d(TAG,
                   "sendScreenMessageAfterNfcCharging - applying postponed screen state "
                           + screenState);
@@ -3602,8 +4072,8 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
         sendMessage(MSG_UPDATE_ISODEP_PROTOCOL_ROUTE, route);
     }
 
-    public void setTechnologyABRoute(int route) {
-        sendMessage(MSG_UPDATE_TECHNOLOGY_AB_ROUTE, route);
+    public void setTechnologyABFRoute(int route) {
+        sendMessage(MSG_UPDATE_TECHNOLOGY_ABF_ROUTE, route);
     }
 
     void sendMessage(int what, Object obj) {
@@ -3720,6 +4190,8 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
                 }
 
                 case MSG_NDEF_TAG:
+                    if (!isNfcEnabled())
+                        break;
                     if (DBG) Log.d(TAG, "Tag detected, notifying applications");
                     TagEndpoint tag = (TagEndpoint) msg.obj;
                     byte[] debounceTagUid;
@@ -3743,6 +4215,12 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
                     synchronized (NfcService.this) {
                         readerParams = mReaderModeParams;
                     }
+                    if (mNfcOemExtensionCallback != null
+                            && receiveOemCallbackResult(ACTION_ON_READ_NDEF)) {
+                        Log.d(TAG, "MSG_NDEF_TAG: skip due to oem callback");
+                        tag.startPresenceChecking(presenceCheckDelay, callback);
+                        break;
+                    }
                     if (readerParams != null) {
                         presenceCheckDelay = readerParams.presenceCheckDelay;
                         if ((readerParams.flags & NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK) != 0) {
@@ -3916,7 +4394,9 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
 
                         mDeviceHost.doSetScreenState(screen_state_mask, mIsWlcEnabled);
                     } finally {
-                        mRoutingWakeLock.release();
+                        if (mRoutingWakeLock.isHeld()) {
+                            mRoutingWakeLock.release();
+                        }
                     }
                     break;
 
@@ -3951,6 +4431,7 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
                     if (DBG) Log.d(TAG, "Polling is started");
                     break;
                 case MSG_CLEAR_ROUTING_TABLE:
+                    if (!isNfcEnabled()) break;
                     if (DBG) Log.d(TAG, "Clear routing table");
                     int clearFlags = (Integer)msg.obj;
                     mDeviceHost.clearRoutingEntry(clearFlags);
@@ -3959,9 +4440,13 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
                     if (DBG) Log.d(TAG, "Update IsoDep Protocol Route");
                     mDeviceHost.setIsoDepProtocolRoute((Integer)msg.obj);
                     break;
-                case MSG_UPDATE_TECHNOLOGY_AB_ROUTE:
-                    if (DBG) Log.d(TAG, "Update technology A&B route");
-                    mDeviceHost.setTechnologyABRoute((Integer)msg.obj);
+                case MSG_UPDATE_TECHNOLOGY_ABF_ROUTE:
+                    if (DBG) Log.d(TAG, "Update technology A,B&F route");
+                    mDeviceHost.setTechnologyABFRoute((Integer)msg.obj);
+                    break;
+                case MSG_WATCHDOG_PING:
+                    NfcWatchdog watchdog = (NfcWatchdog) msg.obj;
+                    watchdog.notifyHasReturned();
                     break;
                 default:
                     Log.e(TAG, "Unknown message received");
@@ -4228,6 +4713,11 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
         }
 
         private void dispatchTagEndpoint(TagEndpoint tagEndpoint, ReaderModeParams readerParams) {
+            if (mNfcOemExtensionCallback != null
+                    && receiveOemCallbackResult(ACTION_ON_TAG_DISPATCH)) {
+                Log.d(TAG, "dispatchTagEndpoint: skip due to oem callback");
+                return;
+            }
             try {
                 /* Avoid setting mCookieUpToDate to negative values */
                 mCookieUpToDate = mCookieGenerator.nextLong() >>> 1;
@@ -4262,7 +4752,7 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
                     }
                 }
                 int dispatchResult = mNfcDispatcher.dispatchTag(tag);
-                if (dispatchResult == NfcDispatcher.DISPATCH_FAIL && !mInProvisionMode) {
+                if (dispatchResult == NfcDispatcher.DISPATCH_FAIL) {
                     if (DBG) Log.d(TAG, "Tag dispatch failed");
                     unregisterObject(tagEndpoint.getHandle());
                     if (mPollDelayTime > NO_POLL_DELAY) {
@@ -4271,7 +4761,8 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
                     } else {
                         Log.d(TAG, "Keep presence checking.");
                     }
-                    if (mScreenState == ScreenStateHelper.SCREEN_STATE_ON_UNLOCKED && mNotifyDispatchFailed) {
+                    if (mScreenState == ScreenStateHelper.SCREEN_STATE_ON_UNLOCKED
+                            && mNotifyDispatchFailed && !mInProvisionMode) {
                         if (!sToast_debounce) {
                             Toast.makeText(mContext, R.string.tag_dispatch_failed,
                                            Toast.LENGTH_SHORT).show();
@@ -4336,6 +4827,24 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
         }
     }
 
+    private void handleScreenStateChanged() {
+        // Perform applyRouting() in AsyncTask to serialize blocking calls
+        if (mIsWlcCapable && mNfcCharging.NfcChargingOnGoing) {
+            Log.d(TAG,
+                    "MSG_APPLY_SCREEN_STATE postponing due to a charging pier device");
+            mPendingPowerStateUpdate = true;
+            return;
+        }
+        int screenState = mScreenStateHelper.checkScreenState(mCheckDisplayStateForScreenState);
+        if (screenState == SCREEN_STATE_ON_LOCKED || screenState == SCREEN_STATE_ON_UNLOCKED) {
+            synchronized (NfcService.this) {
+                mPollDelayCount = 0;
+                mReadErrorCount = 0;
+            }
+        }
+        applyScreenState(screenState);
+    }
+
     private final BroadcastReceiver mReceiver = new BroadcastReceiver() {
         @Override
         public void onReceive(Context context, Intent intent) {
@@ -4343,21 +4852,7 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
             if (action.equals(Intent.ACTION_SCREEN_ON)
                     || action.equals(Intent.ACTION_SCREEN_OFF)
                     || action.equals(Intent.ACTION_USER_PRESENT)) {
-                // Perform applyRouting() in AsyncTask to serialize blocking calls
-
-                if (mIsWlcCapable && mNfcCharging.NfcChargingOnGoing) {
-                    Log.d(TAG,
-                        "MSG_APPLY_SCREEN_STATE postponing due to a charging pier device");
-                    mPendingPowerStateUpdate = true;
-                    return;
-                }
-                if (action.equals(Intent.ACTION_SCREEN_ON)) {
-                    synchronized (NfcService.this) {
-                        mPollDelayCount = 0;
-                        mReadErrorCount = 0;
-                    }
-                }
-                applyScreenState(mScreenStateHelper.checkScreenState());
+                handleScreenStateChanged();
             } else if (action.equals(Intent.ACTION_USER_SWITCHED)) {
                 int userId = intent.getIntExtra(Intent.EXTRA_USER_HANDLE, 0);
                 mUserId = userId;
@@ -4366,24 +4861,51 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
                 if (mIsHceCapable) {
                     mCardEmulationManager.onUserSwitched(getUserId());
                 }
-                applyScreenState(mScreenStateHelper.checkScreenState());
+                applyScreenState(mScreenStateHelper.checkScreenState(mCheckDisplayStateForScreenState));
 
-                if (NFC_SNOOP_LOG_MODE.equals(NfcProperties.snoop_log_mode_values.FULL) ||
-                        NFC_VENDOR_DEBUG_ENABLED) {
+                if ((NFC_SNOOP_LOG_MODE.equals(NfcProperties.snoop_log_mode_values.FULL) ||
+                        NFC_VENDOR_DEBUG_ENABLED) && mContext.getResources().getBoolean(
+                                R.bool.enable_developer_option_notification)){
                     new NfcDeveloperOptionNotification(mContext.createContextAsUser(
                             UserHandle.of(ActivityManager.getCurrentUser()), /*flags=*/0))
                             .startNotification();
                 }
+                // Reload when another userId activated
+                synchronized (NfcService.this) {
+                    initTagAppPrefList();
+                }
             } else if (action.equals(Intent.ACTION_USER_ADDED)) {
                 int userId = intent.getIntExtra(Intent.EXTRA_USER_HANDLE, 0);
                 setPaymentForegroundPreference(userId);
 
-                if (NFC_SNOOP_LOG_MODE.equals(NfcProperties.snoop_log_mode_values.FULL) ||
-                        NFC_VENDOR_DEBUG_ENABLED) {
+                if ((NFC_SNOOP_LOG_MODE.equals(NfcProperties.snoop_log_mode_values.FULL) ||
+                        NFC_VENDOR_DEBUG_ENABLED) && mContext.getResources().getBoolean(
+                        R.bool.enable_developer_option_notification)) {
                     new NfcDeveloperOptionNotification(mContext.createContextAsUser(
                             UserHandle.of(ActivityManager.getCurrentUser()), /*flags=*/0))
                             .startNotification();
                 }
+            } else if (action.equals(Intent.ACTION_USER_UNLOCKED)
+                    && mFeatureFlags.enableDirectBootAware()) {
+                // If this is first unlock after upgrading to NFC stack that is direct boot aware,
+                // migrate over the data from CE directory to DE directory for access before user
+                // unlock in subsequent bootups.
+                if (!mPrefs.getBoolean(PREF_MIGRATE_TO_DE_COMPLETE, false)) {
+                    Log.i(TAG, "Migrating shared prefs to DE directory from CE directory");
+                    Context ceContext = mContext.createCredentialProtectedStorageContext();
+                    SharedPreferences cePreferences =
+                        ceContext.getSharedPreferences(PREF, Context.MODE_PRIVATE);
+                    Log.i(TAG, "CE Shared Pref values: " + cePreferences.getAll());
+                    if (!mContext.moveSharedPreferencesFrom(ceContext, PREF)) {
+                        Log.e(TAG, "Failed to migrate NFC Shared preferences to DE directory");
+                        return;
+                    }
+                    // If the move is completed, refresh our reference to the shared preferences.
+                    mPrefs = mContext.getSharedPreferences(PREF, Context.MODE_PRIVATE);
+                    mPrefsEditor = mPrefs.edit();
+                    mPrefsEditor.putBoolean(PREF_MIGRATE_TO_DE_COMPLETE, true);
+                    mPrefsEditor.apply();
+                }
             }
         }
     };
@@ -4410,6 +4932,9 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
                 if (DBG) Log.d(TAG, action + " received with UserId: " + user.getIdentifier());
                 mCardEmulationManager.onManagedProfileChanged();
                 setPaymentForegroundPreference(user.getIdentifier());
+                synchronized (NfcService.this) {
+                    initTagAppPrefList();
+                }
             }
         }
     };
@@ -4418,13 +4943,12 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
         @Override
         public void onReceive(Context context, Intent intent) {
             String action = intent.getAction();
-            if (action.equals(Intent.ACTION_PACKAGE_REMOVED) ||
-                    action.equals(Intent.ACTION_PACKAGE_ADDED) ||
-                    action.equals(Intent.ACTION_EXTERNAL_APPLICATIONS_AVAILABLE) ||
-                    action.equals(Intent.ACTION_EXTERNAL_APPLICATIONS_UNAVAILABLE)) {
+            if (action.equals(Intent.ACTION_PACKAGE_REMOVED)
+                    || action.equals(Intent.ACTION_PACKAGE_ADDED)
+                    || action.equals(Intent.ACTION_EXTERNAL_APPLICATIONS_AVAILABLE)
+                    || action.equals(Intent.ACTION_EXTERNAL_APPLICATIONS_UNAVAILABLE)) {
                 updatePackageCache();
-                if (action.equals(Intent.ACTION_PACKAGE_REMOVED)
-                        && renewTagAppPrefList()) storeTagAppPrefList();
+                renewTagAppPrefList(action);
             } else if (action.equals(Intent.ACTION_SHUTDOWN)) {
                 if (DBG) Log.d(TAG, "Shutdown received with UserId: " +
                                  getSendingUser().getIdentifier());
@@ -4446,7 +4970,7 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
         if(mFeatureFlags.reduceStateTransition() &&
                 mIsWatchType && !mCardEmulationManager.isRequiresScreenOnServiceExist()) {
             if (screenState == ScreenStateHelper.SCREEN_STATE_OFF_LOCKED) {
-                screenState = ScreenStateHelper.SCREEN_STATE_ON_LOCKED;
+                screenState = SCREEN_STATE_ON_LOCKED;
             } else if (screenState == ScreenStateHelper.SCREEN_STATE_OFF_UNLOCKED) {
                 screenState = ScreenStateHelper.SCREEN_STATE_ON_UNLOCKED;
             }
@@ -4543,7 +5067,7 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
             }
 
             fos = new FileOutputStream(file, true);
-            mDeviceHost.dump(fos.getFD());
+            mDeviceHost.dump(new PrintWriter(new StringWriter()), fos.getFD());
             fos.flush();
         } catch (IOException e) {
             Log.e(TAG, "Exception in storeNativeCrashLogs " + e);
@@ -4560,22 +5084,16 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
 
     private void dumpTagAppPreference(PrintWriter pw) {
         pw.println("mIsTagAppPrefSupported =" + mIsTagAppPrefSupported);
-        if (mIsTagAppPrefSupported) {
-            pw.println("TagAppPreference:");
-            UserManager um = mContext.createContextAsUser(
-                    UserHandle.of(ActivityManager.getCurrentUser()), 0)
-                    .getSystemService(UserManager.class);
-            List<UserHandle> luh = um.getEnabledProfiles();
-            for (UserHandle uh : luh) {
-                int userId = uh.getIdentifier();
-                HashMap<String, Boolean> map;
-                synchronized (NfcService.this) {
-                    map = mTagAppPrefList.getOrDefault(userId, new HashMap<>());
-                }
-                if (map.size() > 0) pw.println("userId=" + userId);
-                for (Map.Entry<String, Boolean> entry : map.entrySet()) {
-                    pw.println("pkg: " + entry.getKey() + " : " + entry.getValue());
-                }
+        if (!mIsTagAppPrefSupported) return;
+        pw.println("TagAppPreference:");
+        for (Integer userId : getEnabledUserIds()) {
+            HashMap<String, Boolean> map;
+            synchronized (NfcService.this) {
+                map = mTagAppPrefList.getOrDefault(userId, new HashMap<>());
+            }
+            if (map.size() > 0) pw.println("userId=" + userId);
+            for (Map.Entry<String, Boolean> entry : map.entrySet()) {
+                pw.println("pkg: " + entry.getKey() + " : " + entry.getValue());
             }
         }
     }
@@ -4583,7 +5101,7 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
     void dump(FileDescriptor fd, PrintWriter pw, String[] args) {
         if (mContext.checkCallingOrSelfPermission(android.Manifest.permission.DUMP)
                 != PackageManager.PERMISSION_GRANTED) {
-            pw.println("Permission Denial: can't dump nfc from from pid="
+            pw.println("Permission Denial: can't dump nfc from pid="
                     + Binder.getCallingPid() + ", uid=" + Binder.getCallingUid()
                     + " without permission " + android.Manifest.permission.DUMP);
             return;
@@ -4627,6 +5145,10 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
             pw.println("SnoopLogMode=" + NFC_SNOOP_LOG_MODE);
             pw.println("VendorDebugEnabled=" + NFC_VENDOR_DEBUG_ENABLED);
             pw.println("mIsPowerSavingModeEnabled=" + mIsPowerSavingModeEnabled);
+            pw.println("mIsObserveModeSupported=" + mNfcAdapter.isObserveModeSupported());
+            pw.println("mIsObserveModeEnabled=" + mNfcAdapter.isObserveModeEnabled());
+            pw.println("listenTech=" + getNfcListenTech());
+            pw.println("pollTech=" + getNfcPollTech());
             pw.println(mCurrentDiscoveryParameters);
             if (mIsHceCapable) {
                 mCardEmulationManager.dump(fd, pw, args);
@@ -4639,7 +5161,7 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
             mNfcInjector.getNfcEventLog().dump(fd, pw, args);
             copyNativeCrashLogsIfAny(pw);
             pw.flush();
-            mDeviceHost.dump(fd);
+            mDeviceHost.dump(pw,fd);
         }
     }
 
@@ -4703,4 +5225,9 @@ public class NfcService implements DeviceHostListener, ForegroundUtils.Callback
             throw e;
         }
     }
+
+    @VisibleForTesting
+    public Handler getHandler() {
+        return mHandler;
+    }
 }
diff --git a/src/com/android/nfc/NfcShellCommand.java b/src/com/android/nfc/NfcShellCommand.java
index 1c1de25f..30d0718c 100644
--- a/src/com/android/nfc/NfcShellCommand.java
+++ b/src/com/android/nfc/NfcShellCommand.java
@@ -17,6 +17,7 @@
 package com.android.nfc;
 
 import android.content.Context;
+import android.nfc.INfcDta;
 import android.os.Binder;
 import android.os.Process;
 import android.os.RemoteException;
@@ -99,21 +100,26 @@ public class NfcShellCommand extends BasicShellCommandHandler {
                     boolean enable_polling =
                             getNextArgRequiredTrueOrFalse("enable-polling", "disable-polling");
                     int flags = enable_polling ? ENABLE_POLLING_FLAGS : DISABLE_POLLING_FLAGS;
-                    mNfcService.mNfcAdapter.setReaderMode(new Binder(), null, flags, null);
+                    mNfcService.mNfcAdapter.setReaderMode(
+                        new Binder(), null, flags, null, mContext.getPackageName());
                     return 0;
                 case "set-observe-mode":
                     boolean enable = getNextArgRequiredTrueOrFalse("enable", "disable");
                     mNfcService.mNfcAdapter.setObserveMode(enable, mContext.getPackageName());
                     return 0;
                 case "set-controller-always-on":
-                    boolean enableAlwaysOn = getNextArgRequiredTrueOrFalse("enable", "disable");
-                    mNfcService.mNfcAdapter.setControllerAlwaysOn(enableAlwaysOn);
+                    int mode = Integer.parseInt(getNextArgRequired());
+                    mNfcService.mNfcAdapter.setControllerAlwaysOn(mode);
                     return 0;
                 case "set-discovery-tech":
                     int pollTech = Integer.parseInt(getNextArg());
                     int listenTech = Integer.parseInt(getNextArg());
                     mNfcService.mNfcAdapter.updateDiscoveryTechnology(
-                            new Binder(), pollTech, listenTech);
+                            new Binder(), pollTech, listenTech, mContext.getPackageName());
+                    return 0;
+                case "configure-dta":
+                    boolean enableDta = getNextArgRequiredTrueOrFalse("enable", "disable");
+                    configureDta(enableDta);
                     return 0;
                 default:
                     return handleDefaultCommands(cmd);
@@ -129,6 +135,25 @@ public class NfcShellCommand extends BasicShellCommandHandler {
         }
     }
 
+    private void configureDta(boolean enable) {
+        final PrintWriter pw = getOutPrintWriter();
+        pw.println("  configure-dta");
+        try {
+            INfcDta dtaService =
+                    mNfcService.mNfcAdapter.getNfcDtaInterface(mContext.getPackageName());
+            if (enable) {
+                pw.println("  enableDta()");
+                dtaService.enableDta();
+            } else {
+                pw.println("  disableDta()");
+                dtaService.disableDta();
+            }
+        } catch (Exception e) {
+            pw.println("Exception while executing nfc shell command configureDta():");
+            e.printStackTrace(pw);
+        }
+    }
+
     private static boolean argTrueOrFalse(String arg, String trueString, String falseString) {
         if (trueString.equals(arg)) {
             return true;
@@ -165,9 +190,12 @@ public class NfcShellCommand extends BasicShellCommandHandler {
         pw.println("    Enable or disable observe mode.");
         pw.println("  set-reader-mode enable-polling|disable-polling");
         pw.println("    Enable or reader mode polling");
-        pw.println("  set-controller-always-on enable|disable");
+        pw.println("  set-controller-always-on <mode>");
         pw.println("    Enable or disable controller always on");
         pw.println("  set-discovery-tech poll-mask|listen-mask");
+        pw.println("    set discovery technology for polling and listening.");
+        pw.println("  configure-dta enable|disable");
+        pw.println("    Enable or disable DTA");
     }
 
     @Override
diff --git a/src/com/android/nfc/NfcWatchdog.java b/src/com/android/nfc/NfcWatchdog.java
new file mode 100644
index 00000000..f9badbd5
--- /dev/null
+++ b/src/com/android/nfc/NfcWatchdog.java
@@ -0,0 +1,125 @@
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
+package com.android.nfc;
+
+import android.annotation.NonNull;
+import android.app.AlarmManager;
+import android.app.PendingIntent;
+import android.content.BroadcastReceiver;
+import android.content.Context;
+import android.content.Intent;
+import android.content.IntentFilter;
+import android.content.pm.PackageManager;
+import android.os.Process;
+import android.os.SystemClock;
+import android.util.Log;
+
+import java.util.concurrent.CountDownLatch;
+import java.util.concurrent.TimeUnit;
+
+/** @hide */
+public class NfcWatchdog extends BroadcastReceiver {
+    static final String TAG = "NfcWatchdog";
+    static final long NFC_SERVICE_TIMEOUT_MS = 1000;
+    static final long NFC_MONITOR_INTERVAL = 60_000;
+    static final String ACTION_WATCHDOG = "android.nfc.intent.action.WATCHDOG";
+
+    CountDownLatch mCountDownLatch;
+    private Intent mWatchdogIntent = new Intent(ACTION_WATCHDOG);
+
+    NfcWatchdog(Context context) {
+        if (android.nfc.Flags.nfcWatchdog()) {
+            PendingIntent pendingIntent =
+                    PendingIntent.getBroadcast(
+                            context, 0, mWatchdogIntent, PendingIntent.FLAG_IMMUTABLE);
+            context.registerReceiver(this, new IntentFilter(ACTION_WATCHDOG),
+                    Context.RECEIVER_EXPORTED);
+            AlarmManager alarmManager = context.getSystemService(AlarmManager.class);
+            alarmManager.setInexactRepeating(
+                    AlarmManager.ELAPSED_REALTIME,
+                    SystemClock.elapsedRealtime() + NFC_MONITOR_INTERVAL,
+                    NFC_MONITOR_INTERVAL,
+                    pendingIntent);
+        }
+    }
+
+    synchronized void  notifyHasReturned() {
+        if (mCountDownLatch != null) {
+            mCountDownLatch.countDown();
+        }
+    }
+
+    @Override
+    public void onReceive(Context context, Intent intent) {
+        if (ACTION_WATCHDOG.equals(intent.getAction())) {
+            monitor();
+        }
+    }
+
+    public synchronized void monitor() {
+        if (mCountDownLatch != null) {
+            return;
+        }
+
+        mCountDownLatch = new CountDownLatch(1);
+
+        Thread testThread = new TestThread();
+        new MonitorThread(testThread).start();
+        testThread.start();
+    }
+
+    void killNfcProcess() {
+        Log.wtf(TAG, "Killing nfc process.");
+        Process.killProcess(Process.myPid());
+    }
+
+    class TestThread extends Thread {
+
+        @Override
+        public void run() {
+            final NfcService nfcService = NfcService.getInstance();
+            if (nfcService != null) {
+                synchronized (nfcService) {
+                    nfcService.sendMessage(NfcService.MSG_WATCHDOG_PING, NfcWatchdog.this);
+                }
+            }
+        }
+    }
+
+    class MonitorThread extends Thread {
+        Thread mTestThread;
+
+        MonitorThread(@NonNull Thread testThread) {
+            mTestThread = testThread;
+        }
+
+        @Override
+        public void run() {
+            try {
+                if (!mCountDownLatch.await(NFC_SERVICE_TIMEOUT_MS,
+                            TimeUnit.MILLISECONDS)) {
+                    killNfcProcess();
+                }
+                synchronized (NfcWatchdog.this) {
+                    mCountDownLatch = null;
+                }
+            } catch (InterruptedException e) {
+                Log.wtf(TAG, e);
+            }
+        }
+    }
+}
diff --git a/src/com/android/nfc/ScreenStateHelper.java b/src/com/android/nfc/ScreenStateHelper.java
index 102af6f3..b643f4a6 100644
--- a/src/com/android/nfc/ScreenStateHelper.java
+++ b/src/com/android/nfc/ScreenStateHelper.java
@@ -2,7 +2,9 @@ package com.android.nfc;
 
 import android.app.KeyguardManager;
 import android.content.Context;
+import android.hardware.display.DisplayManager;
 import android.os.PowerManager;
+import android.view.Display;
 
 /**
  * Helper class for determining the current screen state for NFC activities.
@@ -21,14 +23,21 @@ class ScreenStateHelper {
 
     private final PowerManager mPowerManager;
     private final KeyguardManager mKeyguardManager;
+    private final DisplayManager mDisplayManager;
 
     ScreenStateHelper(Context context) {
         mKeyguardManager = context.getSystemService(KeyguardManager.class);
         mPowerManager = context.getSystemService(PowerManager.class);
+        mDisplayManager = context.getSystemService(DisplayManager.class);
     }
 
-    int checkScreenState() {
-        if (!mPowerManager.isInteractive()) {
+    private boolean isDisplayOn() {
+        Display display = mDisplayManager.getDisplay(Display.DEFAULT_DISPLAY);
+        return display.getState() == Display.STATE_ON;
+    }
+
+    int checkScreenState(boolean checkDisplayState) {
+        if (!mPowerManager.isInteractive() || (checkDisplayState && !isDisplayOn())) {
             if (mKeyguardManager.isKeyguardLocked()) {
                 return SCREEN_STATE_OFF_LOCKED;
             } else {
diff --git a/src/com/android/nfc/cardemulation/AidRoutingManager.java b/src/com/android/nfc/cardemulation/AidRoutingManager.java
index fc9fc349..786302a5 100644
--- a/src/com/android/nfc/cardemulation/AidRoutingManager.java
+++ b/src/com/android/nfc/cardemulation/AidRoutingManager.java
@@ -29,6 +29,8 @@ import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.HashMap;
 import java.util.HashSet;
+import java.util.Iterator;
+import java.util.List;
 import java.util.Map;
 import java.util.Objects;
 import java.util.Set;
@@ -62,7 +64,7 @@ public class AidRoutingManager {
     final byte[] mOffHostRouteEse;
     // Used for backward compatibility in case application doesn't specify the
     // SE
-    final int mDefaultOffHostRoute;
+    int mDefaultOffHostRoute;
 
     // How the NFC controller can match AIDs in the routing table;
     // see AID_MATCHING constants
@@ -88,6 +90,7 @@ public class AidRoutingManager {
         int route;
         int aidInfo;
         int power;
+        List<String> unCheckedOffHostSE = new ArrayList<>();
     }
 
     public AidRoutingManager() {
@@ -246,15 +249,46 @@ public class AidRoutingManager {
         return false;
     }
 
+    private void checkOffHostRouteToHost(HashMap<String, AidEntry> routeCache) {
+        Iterator<Map.Entry<String, AidEntry> > it = routeCache.entrySet().iterator();
+        while (it.hasNext()) {
+            Map.Entry<String, AidEntry> entry = it.next();
+            String aid = entry.getKey();
+            AidEntry aidEntry = entry.getValue();
+
+            if (!aidEntry.isOnHost || aidEntry.unCheckedOffHostSE.size() == 0) {
+                continue;
+            }
+            boolean mustHostRoute = aidEntry.unCheckedOffHostSE.stream()
+                    .anyMatch(offHost -> getRouteForSecureElement(offHost) == mDefaultRoute);
+            if (mustHostRoute) {
+                if (DBG) Log.d(TAG, aid + " is route to host due to unchecked off host and " +
+                        "default route(0x" + Integer.toHexString(mDefaultRoute) + ") is same");
+            }
+            else {
+                if (DBG) Log.d(TAG, aid + " remove in host route list");
+                it.remove();
+            }
+        }
+    }
+
     public boolean configureRouting(HashMap<String, AidEntry> aidMap, boolean force) {
         boolean aidRouteResolved = false;
         HashMap<String, AidEntry> aidRoutingTableCache = new HashMap<String, AidEntry>(aidMap.size());
         ArrayList<Integer> seList = new ArrayList<Integer>();
+
+        int prevDefaultRoute = mDefaultRoute;
+
         if (mRoutingOptionManager.isRoutingTableOverrided()) {
             mDefaultRoute = mRoutingOptionManager.getOverrideDefaultRoute();
+            mDefaultIsoDepRoute = mRoutingOptionManager.getOverrideDefaultIsoDepRoute();
+            mDefaultOffHostRoute = mRoutingOptionManager.getOverrideDefaultOffHostRoute();
         } else {
             mDefaultRoute = mRoutingOptionManager.getDefaultRoute();
+            mDefaultIsoDepRoute = mRoutingOptionManager.getDefaultIsoDepRoute();
+            mDefaultOffHostRoute = mRoutingOptionManager.getDefaultOffHostRoute();
         }
+
         boolean isPowerStateUpdated = false;
         seList.add(mDefaultRoute);
         if (mDefaultRoute != ROUTE_HOST) {
@@ -297,6 +331,13 @@ public class AidRoutingManager {
             infoForAid.put(aid, aidType);
         }
 
+        if (!mRoutingOptionManager.isAutoChangeEnabled() && seList.size() >= 2) {
+            Log.d(TAG, "AutoRouting is not enabled, make only one item in list");
+            int firstRoute = seList.get(0);
+            seList.clear();
+            seList.add(firstRoute);
+        }
+
         synchronized (mLock) {
             if (routeForAid.equals(mRouteForAid) && powerForAid.equals(mPowerForAid) && !force) {
                 if (DBG) Log.d(TAG, "Routing table unchanged, not updating");
@@ -458,6 +499,12 @@ public class AidRoutingManager {
                     }
                 }
 
+                // Unchecked Offhosts rout to host
+                if (mDefaultRoute != ROUTE_HOST) {
+                    Log.d(TAG, "check offHost route to host");
+                    checkOffHostRouteToHost(aidRoutingTableCache);
+                }
+
               if (calculateAidRouteSize(aidRoutingTableCache) <= mMaxAidRoutingTableSize ||
                     mRoutingOptionManager.isRoutingTableOverrided()) {
                   aidRouteResolved = true;
@@ -467,9 +514,12 @@ public class AidRoutingManager {
 
             boolean mIsUnrouteRequired = checkUnrouteAid(prevRouteForAid, prevPowerForAid);
             boolean isRouteTableUpdated = checkRouteAid(prevRouteForAid, prevPowerForAid);
+            boolean isRoutingOptionUpdated = (prevDefaultRoute != mDefaultRoute);
 
-            if (isPowerStateUpdated || isRouteTableUpdated || mIsUnrouteRequired || force) {
-                if (aidRouteResolved == true) {
+            if (isPowerStateUpdated || isRouteTableUpdated || mIsUnrouteRequired
+                    || isRoutingOptionUpdated || force) {
+                if (aidRouteResolved) {
+                    sendRoutingTable(isRoutingOptionUpdated, force);
                     commit(aidRoutingTableCache);
                 } else {
                     NfcStatsLog.write(NfcStatsLog.NFC_ERROR_OCCURRED,
@@ -506,6 +556,30 @@ public class AidRoutingManager {
         NfcService.getInstance().commitRouting();
     }
 
+    private void sendRoutingTable(boolean optionChanged, boolean force) {
+        Log.d(TAG, "sendRoutingTable");
+        if (!mRoutingOptionManager.isRoutingTableOverrided()) {
+            if (mDefaultRoute != ROUTE_HOST) {
+                Log.d(TAG, "Protocol and Technology entries need to sync with"
+                    + " mDefaultRoute: " + mDefaultRoute);
+                mDefaultIsoDepRoute = mDefaultRoute;
+                mDefaultOffHostRoute = mDefaultRoute;
+            }
+            else {
+                Log.d(TAG, "Default route is DeviceHost, use previous protocol, technology");
+            }
+
+            if (force || optionChanged) {
+                NfcService.getInstance().setIsoDepProtocolRoute(mDefaultIsoDepRoute);
+                NfcService.getInstance().setTechnologyABFRoute(mDefaultOffHostRoute);
+            }
+        }
+        else {
+            Log.d(TAG, "Routing table is override, Do not send the protocol, tech");
+        }
+    }
+
+
     /**
      * This notifies that the AID routing table in the controller
      * has been cleared (usually due to NFC being turned off).
diff --git a/src/com/android/nfc/cardemulation/AppChooserActivity.java b/src/com/android/nfc/cardemulation/AppChooserActivity.java
index 256df678..dcbfc915 100644
--- a/src/com/android/nfc/cardemulation/AppChooserActivity.java
+++ b/src/com/android/nfc/cardemulation/AppChooserActivity.java
@@ -97,6 +97,11 @@ public class AppChooserActivity extends AppCompatActivity
         boolean isPayment = CardEmulation.CATEGORY_PAYMENT.equals(mCategory);
 
         final NfcAdapter adapter = NfcAdapter.getDefaultAdapter(this);
+        if (adapter == null) {
+            Log.e(TAG, "adapter is null.");
+            finish();
+            return;
+        }
         mCardEmuManager = CardEmulation.getInstance(adapter);
 
         final ActivityManager am = getSystemService(ActivityManager.class);
@@ -208,7 +213,13 @@ public class AppChooserActivity extends AppCompatActivity
         private List<DisplayAppInfo> mList;
 
         public ListAdapter(Context context, ArrayList<ApduServiceInfo> services) {
-            mInflater = context.getSystemService(LayoutInflater.class);
+            LayoutInflater inflater = null;
+            try {
+                inflater = context.getSystemService(LayoutInflater.class);
+            } catch (Exception e) {
+                Log.e(TAG, "Initiate mInflater failed.", e);
+            }
+            mInflater = inflater;
             // For each component, get the corresponding app name and icon
             PackageManager pm = getPackageManager();
             mList = new ArrayList<DisplayAppInfo>();
@@ -251,7 +262,7 @@ public class AppChooserActivity extends AppCompatActivity
         @Override
         public View getView(int position, View convertView, ViewGroup parent) {
             View view;
-            if (convertView == null) {
+            if (convertView == null && mInflater != null) {
                 if (mIsPayment) {
                     view = mInflater.inflate(
                             com.android.nfc.R.layout.cardemu_payment_item, parent, false);
diff --git a/src/com/android/nfc/cardemulation/CardEmulationManager.java b/src/com/android/nfc/cardemulation/CardEmulationManager.java
index 6ab143b9..e8c9da35 100644
--- a/src/com/android/nfc/cardemulation/CardEmulationManager.java
+++ b/src/com/android/nfc/cardemulation/CardEmulationManager.java
@@ -27,7 +27,9 @@ import android.content.pm.PackageManager.NameNotFoundException;
 import android.nfc.Constants;
 import android.nfc.INfcCardEmulation;
 import android.nfc.INfcFCardEmulation;
+import android.nfc.INfcOemExtensionCallback;
 import android.nfc.NfcAdapter;
+import android.nfc.NfcOemExtension;
 import android.nfc.cardemulation.AidGroup;
 import android.nfc.cardemulation.ApduServiceInfo;
 import android.nfc.cardemulation.CardEmulation;
@@ -48,16 +50,20 @@ import android.util.Log;
 import android.util.proto.ProtoOutputStream;
 
 import com.android.internal.annotations.VisibleForTesting;
+import com.android.nfc.DeviceConfigFacade;
 import com.android.nfc.ForegroundUtils;
 import com.android.nfc.NfcInjector;
 import com.android.nfc.NfcPermissions;
 import com.android.nfc.NfcService;
+import com.android.nfc.R;
 
 import java.io.FileDescriptor;
 import java.io.PrintWriter;
+import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.List;
 import java.util.Objects;
+import java.util.stream.Collectors;
 
 import com.android.nfc.R;
 import android.permission.flags.Flags;
@@ -119,12 +125,14 @@ public class CardEmulationManager implements RegisteredServicesCache.Callback,
     final ForegroundUtils mForegroundUtils;
     private int mForegroundUid;
 
-    RoutingOptionManager mRoutingOptionManager;
+    private final RoutingOptionManager mRoutingOptionManager;
     final byte[] mOffHostRouteUicc;
     final byte[] mOffHostRouteEse;
+    private INfcOemExtensionCallback mNfcOemExtensionCallback;
 
     // TODO: Move this object instantiation and dependencies to NfcInjector.
-    public CardEmulationManager(Context context, NfcInjector nfcInjector) {
+    public CardEmulationManager(Context context, NfcInjector nfcInjector,
+        DeviceConfigFacade deviceConfigFacade) {
         mContext = context;
         mCardEmulationInterface = new CardEmulationInterface();
         mNfcFCardEmulationInterface = new NfcFCardEmulationInterface();
@@ -132,6 +140,12 @@ public class CardEmulationManager implements RegisteredServicesCache.Callback,
             context.getSystemService(ActivityManager.class));
         mWalletRoleObserver = new WalletRoleObserver(context,
                 context.getSystemService(RoleManager.class), this, nfcInjector);
+
+        mRoutingOptionManager = RoutingOptionManager.getInstance();
+        mOffHostRouteEse = mRoutingOptionManager.getOffHostRouteEse();
+        mOffHostRouteUicc = mRoutingOptionManager.getOffHostRouteUicc();
+        mRoutingOptionManager.readRoutingOptionsFromPrefs(mContext, deviceConfigFacade);
+
         mAidCache = new RegisteredAidCache(context, mWalletRoleObserver);
         mT3tIdentifiersCache = new RegisteredT3tIdentifiersCache(context);
         mHostEmulationManager =
@@ -144,9 +158,6 @@ public class CardEmulationManager implements RegisteredServicesCache.Callback,
         mEnabledNfcFServices = new EnabledNfcFServices(
                 context, mNfcFServicesCache, mT3tIdentifiersCache, this);
         mPowerManager = context.getSystemService(PowerManager.class);
-        mRoutingOptionManager = RoutingOptionManager.getInstance();
-        mOffHostRouteEse = mRoutingOptionManager.getOffHostRouteEse();
-        mOffHostRouteUicc = mRoutingOptionManager.getOffHostRouteUicc();
         initialize();
     }
 
@@ -184,6 +195,10 @@ public class CardEmulationManager implements RegisteredServicesCache.Callback,
         initialize();
     }
 
+    public void setOemExtension(INfcOemExtensionCallback nfcOemExtensionCallback) {
+        mNfcOemExtensionCallback = nfcOemExtensionCallback;
+    }
+
     private void initialize() {
         mServiceCache.initialize();
         mNfcFServicesCache.initialize();
@@ -208,12 +223,24 @@ public class CardEmulationManager implements RegisteredServicesCache.Callback,
         mHostEmulationManager.onPollingLoopDetected(pollingFrames);
     }
 
+    public void onObserveModeStateChanged(boolean enable) {
+        mHostEmulationManager.onObserveModeStateChange(enable);
+    }
+
     public void onFieldChangeDetected(boolean fieldOn) {
         mHostEmulationManager.onFieldChangeDetected(fieldOn);
     }
 
     public void onHostCardEmulationActivated(int technology) {
-        if (mPowerManager != null) {
+        if(mNfcOemExtensionCallback!=null) {
+            try {
+                mNfcOemExtensionCallback.onHceEventReceived(NfcOemExtension.HCE_ACTIVATE);
+            } catch (RemoteException e) {
+                Log.e(TAG, "onHceEventReceived failed",e);
+            }
+        }
+        if (mContext.getResources().getBoolean(R.bool.indicate_user_activity_for_hce)
+                && mPowerManager != null) {
             // Use USER_ACTIVITY_FLAG_INDIRECT to applying power hints without resets
             // the screen timeout
             mPowerManager.userActivity(SystemClock.uptimeMillis(),
@@ -232,6 +259,14 @@ public class CardEmulationManager implements RegisteredServicesCache.Callback,
     }
 
     public void onHostCardEmulationData(int technology, byte[] data) {
+        if(mNfcOemExtensionCallback != null) {
+            try {
+                mNfcOemExtensionCallback.onHceEventReceived(NfcOemExtension.HCE_DATA_TRANSFERRED);
+            } catch (RemoteException e) {
+                Log.e(TAG, "onHceEventReceived failed",e);
+            }
+        }
+
         if (technology == NFC_HCE_APDU) {
             mHostEmulationManager.onHostEmulationData(data);
         } else if (technology == NFC_HCE_NFCF) {
@@ -254,6 +289,13 @@ public class CardEmulationManager implements RegisteredServicesCache.Callback,
             mNfcFServicesCache.onHostEmulationDeactivated();
             mEnabledNfcFServices.onHostEmulationDeactivated();
         }
+        if(mNfcOemExtensionCallback != null) {
+            try {
+                mNfcOemExtensionCallback.onHceEventReceived(NfcOemExtension.HCE_DEACTIVATE);
+            } catch (RemoteException e) {
+                Log.e(TAG, "onHceEventReceived failed",e);
+            }
+        }
     }
 
     public void onOffHostAidSelected() {
@@ -853,15 +895,23 @@ public class CardEmulationManager implements RegisteredServicesCache.Callback,
         }
 
         @Override
-        public boolean overrideRoutingTable(int userHandle, String protocol, String technology) {
+        public void overrideRoutingTable(int userHandle, String protocol, String technology,
+                String pkg) {
             Log.d(TAG, "overrideRoutingTable. userHandle " + userHandle + ", protocol " + protocol +
                     ", technology " + technology);
 
             int callingUid = Binder.getCallingUid();
+            if (android.nfc.Flags.nfcOverrideRecoverRoutingTable()) {
+                if (!isPreferredServicePackageNameForUser(pkg,
+                        UserHandle.getUserHandleForUid(callingUid).getIdentifier())) {
+                    Log.e(TAG, "overrideRoutingTable: Caller not preferred NFC service.");
+                    throw new SecurityException("Caller not preferred NFC service");
+                }
+            }
             if (!mForegroundUtils
                     .registerUidToBackgroundCallback(mForegroundCallback, callingUid)) {
                 Log.e(TAG, "overrideRoutingTable: Caller is not in foreground.");
-                return false;
+                throw new IllegalArgumentException("Caller is not in foreground.");
             }
             mForegroundUid = callingUid;
 
@@ -875,25 +925,81 @@ public class CardEmulationManager implements RegisteredServicesCache.Callback,
             mRoutingOptionManager.overrideDefaultOffHostRoute(technologyRoute);
             mAidCache.onRoutingOverridedOrRecovered();
 //            NfcService.getInstance().commitRouting();
-
-            return true;
         }
 
         @Override
-        public boolean recoverRoutingTable(int userHandle) {
+        public void recoverRoutingTable(int userHandle) {
             Log.d(TAG, "recoverRoutingTable. userHandle " + userHandle);
 
             if (!mForegroundUtils.isInForeground(Binder.getCallingUid())) {
                 if (DBG) Log.d(TAG, "recoverRoutingTable : not in foreground.");
-                return false;
+                throw new IllegalArgumentException("Caller is not in foreground.");
             }
             mForegroundUid = Process.INVALID_UID;
 
             mRoutingOptionManager.recoverOverridedRoutingTable();
             mAidCache.onRoutingOverridedOrRecovered();
 //            NfcService.getInstance().commitRouting();
+        }
 
-            return true;
+        // TODO: Need corresponding API
+        public void overwriteRoutingTable(int userHandle, String aids,
+            String protocol, String technology) {
+            Log.d(TAG, "overwriteRoutingTable. userHandle " + userHandle
+                + ", emptyAid " + aids + ", protocol " + protocol
+                + ", technology " + technology);
+
+            int aidRoute = mRoutingOptionManager.getRouteForSecureElement(aids);
+            int protocolRoute = mRoutingOptionManager.getRouteForSecureElement(protocol);
+            int technologyRoute = mRoutingOptionManager.getRouteForSecureElement(technology);
+
+            if (DBG) {
+                Log.d(TAG, "aidRoute " + aidRoute + ", protocolRoute "
+                    + protocolRoute + ", technologyRoute " + technologyRoute);
+            }
+            if (aids != null) {
+                mRoutingOptionManager.overrideDefaultRoute(aidRoute);
+                mRoutingOptionManager.overrideDefaultIsoDepRoute(protocolRoute);
+                mRoutingOptionManager.overrideDefaultOffHostRoute(technologyRoute);
+                mRoutingOptionManager.overwriteRoutingTable();
+            }
+            mAidCache.onRoutingOverridedOrRecovered();
+        }
+
+        // TODO: Need corresponding API
+        public List<String> getRoutingStatus() {
+            List<Integer> routingList = new ArrayList<>();
+
+            if (mRoutingOptionManager.isRoutingTableOverrided()) {
+                routingList.add(mRoutingOptionManager.getOverrideDefaultRoute());
+                routingList.add(mRoutingOptionManager.getOverrideDefaultIsoDepRoute());
+                routingList.add(mRoutingOptionManager.getOverrideDefaultOffHostRoute());
+            }
+            else {
+                routingList.add(mRoutingOptionManager.getDefaultRoute());
+                routingList.add(mRoutingOptionManager.getDefaultIsoDepRoute());
+                routingList.add(mRoutingOptionManager.getDefaultOffHostRoute());
+            }
+
+            return routingList.stream()
+                .map(route->mRoutingOptionManager.getSecureElementForRoute(route))
+                .collect(Collectors.toList());
+        }
+
+        // TODO: Need corresponding API
+        public void setAutoChangeStatus(boolean state) {
+            mRoutingOptionManager.setAutoChangeStatus(state);
+        }
+
+        // TODO: Need corresponding API
+        public boolean isAutoChangeEnabled() {
+            return mRoutingOptionManager.isAutoChangeEnabled();
+        }
+
+        @Override
+        public boolean isEuiccSupported() {
+            return mContext.getResources().getBoolean(R.bool.enable_euicc_support)
+                    && NfcInjector.NfcProperties.isEuiccSupported();
         }
     }
 
@@ -1065,7 +1171,6 @@ public class CardEmulationManager implements RegisteredServicesCache.Callback,
     public void onPreferredForegroundServiceChanged(int userId, ComponentName service) {
         Log.i(TAG, "onPreferredForegroundServiceChanged");
         ComponentName oldPreferredService = mAidCache.getPreferredService().second;
-        mAidCache.onPreferredForegroundServiceChanged(userId, service);
         mHostEmulationManager.onPreferredForegroundServiceChanged(userId, service);
         ComponentName newPreferredService = mAidCache.getPreferredService().second;
 
diff --git a/src/com/android/nfc/cardemulation/HostEmulationManager.java b/src/com/android/nfc/cardemulation/HostEmulationManager.java
index 62539b02..fdd7ebfc 100644
--- a/src/com/android/nfc/cardemulation/HostEmulationManager.java
+++ b/src/com/android/nfc/cardemulation/HostEmulationManager.java
@@ -175,11 +175,7 @@ public class HostEmulationManager {
         public void run() {
             synchronized (mLock) {
                 Log.d(TAG, "Have been outside field, returning to idle state");
-                mPendingPollingLoopFrames = null;
-                mPollingFramesToSend = null;
-                mPollingLoopState = PollingLoopState.EVALUATING_POLLING_LOOP;
-                resetActiveService();
-                mState = STATE_IDLE;
+                returnToIdleStateLocked();
             }
         }
     };
@@ -193,9 +189,13 @@ public class HostEmulationManager {
               Log.d(TAG, "re-enabling observe mode after transaction.");
               mEnableObserveModeAfterTransaction = false;
               mEnableObserveModeOnFieldOff = false;
-              NfcAdapter adapter = NfcAdapter.getDefaultAdapter(mContext);
-              adapter.setObserveModeEnabled(true);
             }
+            NfcAdapter adapter = NfcAdapter.getDefaultAdapter(mContext);
+            if (adapter == null) {
+                Log.e(TAG, "adapter is null, returning");
+                return;
+            }
+            adapter.setObserveModeEnabled(true);
         }
     };
 
@@ -266,13 +266,13 @@ public class HostEmulationManager {
     @FlaggedApi(android.nfc.Flags.FLAG_NFC_OBSERVE_MODE)
     public void updateForShouldDefaultToObserveMode(boolean enabled) {
         synchronized (mLock) {
-            if (!isHostCardEmulationActivated()) {
-                NfcAdapter adapter = NfcAdapter.getDefaultAdapter(mContext);
-                adapter.setObserveModeEnabled(enabled);
-            } else {
+            if (isHostCardEmulationActivated()) {
                 mEnableObserveModeAfterTransaction = enabled;
+                return;
             }
         }
+        NfcAdapter adapter = NfcAdapter.getDefaultAdapter(mContext);
+        adapter.setObserveModeEnabled(enabled);
     }
 
 
@@ -306,6 +306,19 @@ public class HostEmulationManager {
 
     public void onObserveModeStateChange(boolean enabled) {
         synchronized(mLock) {
+            if (android.nfc.Flags.nfcEventListener()) {
+                Messenger service = getForegroundServiceOrDefault();
+                if (service != null) {
+                    Message msg = Message.obtain(null, HostApduService.MSG_OBSERVE_MODE_CHANGE);
+                    msg.arg1 = enabled ? 1 : 0;
+                    msg.replyTo = mMessenger;
+                    try {
+                        service.send(msg);
+                    } catch (RemoteException e) {
+                        Log.e(TAG, "Remote service has died", e);
+                    }
+                }
+            }
             if (!enabled && mAutoDisableObserveModeRunnable != null) {
                 mHandler.removeCallbacks(mAutoDisableObserveModeRunnable);
                 mAutoDisableObserveModeRunnable = null;
@@ -313,7 +326,6 @@ public class HostEmulationManager {
         }
     }
 
-
     class AutoDisableObserveModeRunnable implements Runnable {
         Set<String> mServicePackageNames;
         AutoDisableObserveModeRunnable(ComponentName componentName) {
@@ -561,6 +573,39 @@ public class HostEmulationManager {
      */
     public void onPreferredForegroundServiceChanged(int userId, ComponentName service) {
         synchronized (mLock) {
+            if (android.nfc.Flags.nfcEventListener()) {
+                Pair<Integer, ComponentName> oldServiceAndUser = mAidCache.getPreferredService();
+                Messenger oldPreferredService = null;
+                if (oldServiceAndUser != null && oldServiceAndUser.second != null) {
+                    if (mPaymentServiceName != null
+                        && mPaymentServiceName.equals(oldServiceAndUser.second)
+                        && mPaymentServiceUserId == oldServiceAndUser.first) {
+                        oldPreferredService = mPaymentService;
+                    } else if (mServiceName != null && mServiceName.equals(oldServiceAndUser.second)
+                            && mServiceUserId == oldServiceAndUser.first) {
+                        oldPreferredService = mService;
+                    } else {
+                        Log.w(TAG, oldServiceAndUser.second +
+                            " is no longer the preferred NFC service but isn't bound");
+                    }
+                    if (oldPreferredService != null) {
+                        Message msg =
+                        Message.obtain(null, HostApduService.MSG_PREFERRED_SERVICE_CHANGED);
+                        msg.arg1 = 0;
+                        msg.replyTo = mMessenger;
+                        try {
+                            oldPreferredService.send(msg);
+                        } catch (RemoteException e) {
+                            Log.e(TAG, "Remote service has died", e);
+                        }
+                    }
+                } else {
+                    Log.i(TAG, "old service is null");
+                }
+            }
+
+            mAidCache.onPreferredForegroundServiceChanged(userId, service);
+
             if (!isHostCardEmulationActivated()) {
                 Log.d(TAG, "onPreferredForegroundServiceChanged, resetting active service");
                 resetActiveService();
@@ -821,12 +866,8 @@ public class HostEmulationManager {
                 Log.e(TAG, "Got deactivation event while in idle state");
             }
             sendDeactivateToActiveServiceLocked(HostApduService.DEACTIVATION_LINK_LOSS);
-            resetActiveService();
-            mPendingPollingLoopFrames = null;
-            mPollingFramesToSend = null;
             unbindServiceIfNeededLocked();
-            mState = STATE_IDLE;
-            mPollingLoopState = PollingLoopState.EVALUATING_POLLING_LOOP;
+            returnToIdleStateLocked();
 
             if (mAutoDisableObserveModeRunnable != null) {
                 mHandler.removeCallbacks(mAutoDisableObserveModeRunnable);
@@ -993,6 +1034,17 @@ public class HostEmulationManager {
     }
 
     void unbindPaymentServiceLocked() {
+        if (android.nfc.Flags.nfcEventListener() &&
+            mPaymentService != null) {
+            Message msg = Message.obtain(null, HostApduService.MSG_PREFERRED_SERVICE_CHANGED);
+            msg.arg1 = 0;
+            msg.replyTo = mMessenger;
+            try {
+                mPaymentService.send(msg);
+            } catch (RemoteException e) {
+                Log.e(TAG, "Remote service has died", e);
+            }
+        }
         Log.d(TAG, "Unbinding payment service");
         if (mPaymentServiceBound) {
             try {
@@ -1090,6 +1142,15 @@ public class HostEmulationManager {
         return null;
     }
 
+    private void returnToIdleStateLocked() {
+        mPendingPollingLoopFrames = null;
+        mPollingFramesToSend = null;
+        mUnprocessedPollingFrames = null;
+        resetActiveService();
+        mPollingLoopState = PollingLoopState.EVALUATING_POLLING_LOOP;
+        mState = STATE_IDLE;
+    }
+
     private void resetActiveService() {
         mActiveService = null;
         mActiveServiceName = null;
@@ -1109,6 +1170,18 @@ public class HostEmulationManager {
                 mPaymentServiceName = name;
                 mPaymentService = new Messenger(service);
                 Log.i(TAG, "Payment service bound: " + name);
+                if (android.nfc.Flags.nfcEventListener() &&
+                    mPaymentService != null) {
+                    Message msg =
+                        Message.obtain(null, HostApduService.MSG_PREFERRED_SERVICE_CHANGED);
+                    msg.arg1 = 1;
+                    msg.replyTo = mMessenger;
+                    try {
+                        mPaymentService.send(msg);
+                    } catch (RemoteException e) {
+                        Log.e(TAG, "Remote service has died", e);
+                    }
+                }
             }
         }
 
@@ -1125,7 +1198,9 @@ public class HostEmulationManager {
         public void onBindingDied(ComponentName name) {
             Log.i(TAG, "Payment service died: " + name);
             synchronized (mLock) {
-                bindPaymentServiceLocked(mPaymentServiceUserId, mLastBoundPaymentServiceName);
+                if (mPaymentServiceUserId >= 0) {
+                    bindPaymentServiceLocked(mPaymentServiceUserId, mLastBoundPaymentServiceName);
+                }
             }
         }
     };
@@ -1134,14 +1209,31 @@ public class HostEmulationManager {
         @Override
         public void onServiceConnected(ComponentName name, IBinder service) {
             synchronized (mLock) {
-                /* Service is already deactivated, don't bind */
-                if (mState == STATE_IDLE) {
+                Pair<Integer, ComponentName> preferredUserAndService =
+                    mAidCache.getPreferredService();
+                ComponentName preferredServiceName =
+                    preferredUserAndService == null ? null : preferredUserAndService.second;
+                /* Service is already deactivated and not preferred, don't bind */
+                if (mState == STATE_IDLE && !name.equals(preferredServiceName)) {
                   return;
                 }
                 mService = new Messenger(service);
                 mServiceName = name;
                 mServiceBound = true;
                 Log.d(TAG, "Service bound: " + name);
+                if (android.nfc.Flags.nfcEventListener() &&
+                    name.equals(preferredServiceName) &&
+                    mService != null) {
+                    Message msg =
+                        Message.obtain(null, HostApduService.MSG_PREFERRED_SERVICE_CHANGED);
+                    msg.arg1 = 1;
+                    msg.replyTo = mMessenger;
+                    try {
+                        mService.send(msg);
+                    } catch (RemoteException e) {
+                        Log.e(TAG, "Remote service has died", e);
+                    }
+                }
                 // Send pending select APDU
                 if (mSelectApdu != null) {
                     if (mStatsdUtils != null) {
diff --git a/src/com/android/nfc/cardemulation/PreferredServices.java b/src/com/android/nfc/cardemulation/PreferredServices.java
index 52a132aa..b0bc6b35 100644
--- a/src/com/android/nfc/cardemulation/PreferredServices.java
+++ b/src/com/android/nfc/cardemulation/PreferredServices.java
@@ -289,8 +289,8 @@ public class PreferredServices implements com.android.nfc.ForegroundUtils.Callba
                         UserHandle.getUserHandleForUid(mForegroundUid).getIdentifier();
             }
             if (preferredService != null && (!preferredService.equals(mForegroundCurrent)
-                      || preferredServiceUserId
-                      != UserHandle.getUserHandleForUid(mForegroundCurrentUid).getIdentifier())) {
+                    || preferredServiceUserId
+                    != UserHandle.getUserHandleForUid(mForegroundCurrentUid).getIdentifier())) {
                 mForegroundCurrent = preferredService;
                 mForegroundCurrentUid = mForegroundUid;
                 changed = true;
@@ -499,7 +499,7 @@ public class PreferredServices implements com.android.nfc.ForegroundUtils.Callba
                 return true;
             }
             return (mForegroundCurrent != null
-                && packageName.equals(mForegroundCurrent.getPackageName()));
+                    && packageName.equals(mForegroundCurrent.getPackageName()));
         }
     }
 
diff --git a/src/com/android/nfc/cardemulation/RegisteredAidCache.java b/src/com/android/nfc/cardemulation/RegisteredAidCache.java
index df2c53ae..538bff5c 100644
--- a/src/com/android/nfc/cardemulation/RegisteredAidCache.java
+++ b/src/com/android/nfc/cardemulation/RegisteredAidCache.java
@@ -132,6 +132,7 @@ public class RegisteredAidCache {
         String category = null;
         boolean mustRoute = true; // Whether this AID should be routed at all
         ResolvedPrefixConflictAid prefixInfo = null;
+        List<String> unCheckedOffHostSecureElement = new ArrayList<>();
         @Override
         public String toString() {
             return "AidResolveInfo{" +
@@ -328,7 +329,19 @@ public class RegisteredAidCache {
                 if (VDBG) Log.d(TAG, "resolveAidLocked: " + serviceAidInfo.service.getComponent() +
                         " is selected other service");
                 resolveInfo.services.add(serviceAidInfo.service);
+            } else {
+                if (DBG) Log.d(TAG, "resolveAidLocked: " + serviceAidInfo.service.getComponent() +
+                        " is unselected other service");
+                if(!serviceAidInfo.service.isOnHost()) {
+                    String offHostName = serviceAidInfo.service.getOffHostSecureElement();
+                    if (offHostName != null &&
+                            !resolveInfo.unCheckedOffHostSecureElement.contains(offHostName)) {
+                        if (DBG) Log.d(TAG, "add " + offHostName + " to disabled offHosts");
+                        resolveInfo.unCheckedOffHostSecureElement.add(offHostName);
+                    }
+                }
             }
+
         }
     }
 
@@ -393,11 +406,19 @@ public class RegisteredAidCache {
                     && componentName.getPackageName().equals(
                     mDefaultWalletHolderPackageName)) {
                     if (VDBG) Log.d(TAG, "Prioritizing default wallet services.");
-                    resolveInfo.services.add(serviceAidInfo.service);
-                    if (serviceClaimsPaymentAid) {
-                        resolveInfo.category = CardEmulation.CATEGORY_PAYMENT;
+
+                    if (serviceClaimsPaymentAid ||
+                            serviceAidInfo.service.isCategoryOtherServiceEnabled()) {
+                        resolveInfo.services.add(serviceAidInfo.service);
+                        if (serviceClaimsPaymentAid) {
+                            resolveInfo.category = CardEmulation.CATEGORY_PAYMENT;
+                        }
+                        defaultWalletServices.add(serviceAidInfo.service);
+                    } else {
+                        if (VDBG) Log.d(TAG, "Service disabled in default wallet, " +
+                                "resolving against other applications");
+                        nonDefaultResolution(serviceClaimsPaymentAid, serviceAidInfo, resolveInfo);
                     }
-                    defaultWalletServices.add(serviceAidInfo.service);
                 } else {
                     nonDefaultResolution(serviceClaimsPaymentAid, serviceAidInfo, resolveInfo);
                 }
@@ -695,15 +716,15 @@ public class RegisteredAidCache {
     }
 
     static boolean isExact(String aid) {
-        return (!((aid.endsWith("*") || (aid.endsWith("#")))));
+        return aid == null ? false : !(aid.endsWith("*") || aid.endsWith("#"));
     }
 
     static boolean isPrefix(String aid) {
-        return aid.endsWith("*");
+        return aid == null ? false : aid.endsWith("*");
     }
 
     static boolean isSubset(String aid) {
-        return aid.endsWith("#");
+        return aid == null ? false : aid.endsWith("#");
     }
 
     final class ResolvedPrefixConflictAid {
@@ -1076,6 +1097,14 @@ public class RegisteredAidCache {
             }
             if (resolveInfo.services.size() == 0) {
                 // No interested services
+                // prevent unchecked offhost aids route to offhostSE
+		if (!resolveInfo.unCheckedOffHostSecureElement.isEmpty()) {
+                    aidType.unCheckedOffHostSE.addAll(resolveInfo.unCheckedOffHostSecureElement);
+                    aidType.isOnHost = true;
+                    aidType.power = POWER_STATE_SWITCH_ON;
+                    routingEntries.put(aid, aidType);
+                    force = true;
+		}
             } else if (resolveInfo.defaultService != null) {
                 // There is a default service set, route to where that service resides -
                 // either on the host (HCE) or on an SE.
diff --git a/src/com/android/nfc/cardemulation/RegisteredNfcFServicesCache.java b/src/com/android/nfc/cardemulation/RegisteredNfcFServicesCache.java
index 6b2c5b13..49f8d482 100644
--- a/src/com/android/nfc/cardemulation/RegisteredNfcFServicesCache.java
+++ b/src/com/android/nfc/cardemulation/RegisteredNfcFServicesCache.java
@@ -831,5 +831,4 @@ public class RegisteredNfcFServicesCache {
     public boolean isActivated() {
         return mActivated;
     }
-
 }
diff --git a/src/com/android/nfc/cardemulation/RegisteredServicesCache.java b/src/com/android/nfc/cardemulation/RegisteredServicesCache.java
index 8f63c939..93770932 100644
--- a/src/com/android/nfc/cardemulation/RegisteredServicesCache.java
+++ b/src/com/android/nfc/cardemulation/RegisteredServicesCache.java
@@ -107,6 +107,9 @@ public class RegisteredServicesCache {
     final ServiceParser mServiceParser;
     final RoutingOptionManager mRoutingOptionManager;
 
+    final Intent mHostApduServiceIntent = new Intent(HostApduService.SERVICE_INTERFACE);
+    final Intent mOffHostApduServiceIntent = new Intent(OffHostApduService.SERVICE_INTERFACE);
+
     public interface Callback {
         /**
          * ServicesUpdated for specific userId.
@@ -417,11 +420,11 @@ public class RegisteredServicesCache {
         ArrayList<ApduServiceInfo> validServices = new ArrayList<ApduServiceInfo>();
 
         List<ResolveInfo> resolvedServices = new ArrayList<>(pm.queryIntentServicesAsUser(
-                new Intent(HostApduService.SERVICE_INTERFACE),
+                mHostApduServiceIntent,
                 ResolveInfoFlags.of(PackageManager.GET_META_DATA), UserHandle.of(userId)));
 
         List<ResolveInfo> resolvedOffHostServices = pm.queryIntentServicesAsUser(
-                new Intent(OffHostApduService.SERVICE_INTERFACE),
+                mOffHostApduServiceIntent,
                 ResolveInfoFlags.of(PackageManager.GET_META_DATA), UserHandle.of(userId));
         resolvedServices.addAll(resolvedOffHostServices);
         for (ResolveInfo resolvedService : resolvedServices) {
@@ -1237,6 +1240,9 @@ public class RegisteredServicesCache {
             }
         }
         if (success) {
+            List<ApduServiceInfo> otherServices = getServicesForCategory(userId,
+                    CardEmulation.CATEGORY_OTHER);
+            invalidateOther(userId, otherServices);
             // Make callback without the lock held
             mCallback.onServicesUpdated(userId, newServices, true);
         }
@@ -1330,6 +1336,9 @@ public class RegisteredServicesCache {
             }
         }
         if (success) {
+            List<ApduServiceInfo> otherServices = getServicesForCategory(userId,
+                    CardEmulation.CATEGORY_OTHER);
+            invalidateOther(userId, otherServices);
             mCallback.onServicesUpdated(userId, newServices, true);
         }
         return success;
diff --git a/src/com/android/nfc/cardemulation/RoutingOptionManager.java b/src/com/android/nfc/cardemulation/RoutingOptionManager.java
index f417b265..f9b2f859 100644
--- a/src/com/android/nfc/cardemulation/RoutingOptionManager.java
+++ b/src/com/android/nfc/cardemulation/RoutingOptionManager.java
@@ -15,14 +15,20 @@
  */
 package com.android.nfc.cardemulation;
 
+import android.content.Context;
+import android.content.SharedPreferences;
 import android.os.SystemProperties;
+import android.text.TextUtils;
 import android.util.Log;
 
 import androidx.annotation.VisibleForTesting;
 
+import com.android.nfc.DeviceConfigFacade;
 import com.android.nfc.NfcService;
 
 import java.util.Arrays;
+import java.util.HashMap;
+import java.util.Optional;
 
 public class RoutingOptionManager {
     public final String TAG = "RoutingOptionManager";
@@ -31,6 +37,19 @@ public class RoutingOptionManager {
 
     static final int ROUTE_UNKNOWN = -1;
 
+    public static final String DEVICE_HOST = "DH";
+    public static final String SE_PREFIX_SIM = "SIM";
+    public static final String SE_PREFIX_ESE = "eSE";
+
+    public static final String PREF_ROUTING_OPTIONS = "RoutingOptionPrefs";
+    public static final String KEY_DEFAULT_ROUTE = "default_route";
+    public static final String KEY_DEFAULT_ISO_DEP_ROUTE = "default_iso_dep_route";
+    public static final String KEY_DEFAULT_OFFHOST_ROUTE = "default_offhost_route";
+    public static final String KEY_AUTO_CHANGE_CAPABLE = "allow_auto_routing_changed";
+    Context mContext;
+    private SharedPreferences mPrefs;
+
+
     int mDefaultRoute;
     int mDefaultIsoDepRoute;
     int mDefaultOffHostRoute;
@@ -44,6 +63,16 @@ public class RoutingOptionManager {
 
     boolean mIsRoutingTableOverrided = false;
 
+
+    boolean mIsAutoChangeCapable = true;
+
+    // Look up table for secure element name to route id
+    HashMap<String, Integer> mRouteForSecureElement = new HashMap<>();
+
+    // Look up table for route id to secure element name
+    HashMap<Integer, String> mSecureElementForRoute = new HashMap<>();
+
+
     @VisibleForTesting
     native int doGetDefaultRouteDestination();
     @VisibleForTesting
@@ -84,27 +113,53 @@ public class RoutingOptionManager {
             Log.d(TAG, "mOffHostRouteEse=" + Arrays.toString(mOffHostRouteEse));
         mAidMatchingSupport = doGetAidMatchingMode();
         if (DBG) Log.d(TAG, "mAidMatchingSupport=0x" + Integer.toHexString(mAidMatchingSupport));
+
+        createLookUpTable();
     }
 
-//    public void overrideDefaultRoute(int defaultRoute) {
-//        mOverrideDefaultRoute = defaultRoute;
-//        NfcService.getInstance().setIsoDepProtocolRoute(defaultRoute);
-//    }
+    public void overwriteRoutingTable() {
+        Log.e(TAG, "overwriteRoutingTable");
+        if (mOverrideDefaultRoute != ROUTE_UNKNOWN) {
+            Log.e(TAG, "overwrite mDefaultRoute : " + mOverrideDefaultRoute);
+            mDefaultRoute = mOverrideDefaultRoute;
+            writeRoutingOption(KEY_DEFAULT_ROUTE, getSecureElementForRoute(mDefaultRoute));
+        }
+
+        if (mOverrideDefaultIsoDepRoute != ROUTE_UNKNOWN) {
+            Log.e(TAG, "overwrite mDefaultIsoDepRoute : " + mOverrideDefaultIsoDepRoute);
+            mDefaultIsoDepRoute = mOverrideDefaultIsoDepRoute;
+            writeRoutingOption(
+                KEY_DEFAULT_ISO_DEP_ROUTE, getSecureElementForRoute(mDefaultIsoDepRoute));
+        }
+
+        if (mOverrideDefaultOffHostRoute != ROUTE_UNKNOWN) {
+            Log.e(TAG, "overwrite mDefaultOffHostRoute : " + mOverrideDefaultOffHostRoute);
+            mDefaultOffHostRoute = mOverrideDefaultOffHostRoute;
+            writeRoutingOption(
+                KEY_DEFAULT_OFFHOST_ROUTE, getSecureElementForRoute(mDefaultOffHostRoute));
+        }
+
+        mOverrideDefaultRoute = mOverrideDefaultIsoDepRoute = mOverrideDefaultOffHostRoute
+                = ROUTE_UNKNOWN;
+    }
+
+    public void overrideDefaultRoute(int defaultRoute) {
+        mOverrideDefaultRoute = defaultRoute;
+    }
 
     public void overrideDefaultIsoDepRoute(int isoDepRoute) {
-        mOverrideDefaultRoute = isoDepRoute;
         mOverrideDefaultIsoDepRoute = isoDepRoute;
         NfcService.getInstance().setIsoDepProtocolRoute(isoDepRoute);
     }
 
     public void overrideDefaultOffHostRoute(int offHostRoute) {
         mOverrideDefaultOffHostRoute = offHostRoute;
-        NfcService.getInstance().setTechnologyABRoute(offHostRoute);
+        NfcService.getInstance().setTechnologyABFRoute(offHostRoute);
     }
 
     public void recoverOverridedRoutingTable() {
         NfcService.getInstance().setIsoDepProtocolRoute(mDefaultIsoDepRoute);
-        NfcService.getInstance().setTechnologyABRoute(mDefaultOffHostRoute);
+        NfcService.getInstance().setTechnologyABFRoute(mDefaultOffHostRoute);
         mOverrideDefaultRoute = mOverrideDefaultIsoDepRoute = mOverrideDefaultOffHostRoute
             = ROUTE_UNKNOWN;
     }
@@ -117,10 +172,15 @@ public class RoutingOptionManager {
         return mDefaultRoute;
     }
 
+    public int getOverrideDefaultIsoDepRoute() { return mOverrideDefaultIsoDepRoute;}
+
     public int getDefaultIsoDepRoute() {
         return mDefaultIsoDepRoute;
     }
 
+    public int getOverrideDefaultOffHostRoute() {
+        return mOverrideDefaultOffHostRoute;
+    }
     public int getDefaultOffHostRoute() {
         return mDefaultOffHostRoute;
     }
@@ -138,7 +198,110 @@ public class RoutingOptionManager {
     }
 
     public boolean isRoutingTableOverrided() {
-        return mOverrideDefaultIsoDepRoute != ROUTE_UNKNOWN
+        return mOverrideDefaultRoute != ROUTE_UNKNOWN
+            || mOverrideDefaultIsoDepRoute != ROUTE_UNKNOWN
             || mOverrideDefaultOffHostRoute != ROUTE_UNKNOWN;
     }
+
+    private void createLookUpTable() {
+        mRouteForSecureElement.putIfAbsent(DEVICE_HOST, 0);
+        mSecureElementForRoute.put(0, DEVICE_HOST);
+
+        mRouteForSecureElement.putIfAbsent("UNKNOWN", ROUTE_UNKNOWN);
+        mSecureElementForRoute.put(ROUTE_UNKNOWN, "UNKNOWN");
+
+        addOrUpdateTableItems(SE_PREFIX_SIM, mOffHostRouteUicc);
+        addOrUpdateTableItems(SE_PREFIX_ESE, mOffHostRouteEse);
+    }
+
+    boolean isRoutingTableOverwrittenOrOverlaid(
+            DeviceConfigFacade deviceConfigFacade, SharedPreferences prefs) {
+        return !TextUtils.isEmpty(deviceConfigFacade.getDefaultRoute())
+                || !TextUtils.isEmpty(deviceConfigFacade.getDefaultIsoDepRoute())
+                || !TextUtils.isEmpty(deviceConfigFacade.getDefaultOffHostRoute())
+                || !prefs.getAll().isEmpty();
+    }
+
+    public void readRoutingOptionsFromPrefs(
+            Context context, DeviceConfigFacade deviceConfigFacade) {
+        Log.d(TAG, "readRoutingOptions with Context");
+        if (mPrefs == null) {
+            Log.d(TAG, "create mPrefs in readRoutingOptions");
+            mContext = context;
+            mPrefs = context.getSharedPreferences(PREF_ROUTING_OPTIONS, Context.MODE_PRIVATE);
+        }
+
+        // If the OEM does not set default routes in the overlay and if no app has overwritten
+        // the routing table using `overwriteRoutingTable`, skip this preference reading.
+        if (!isRoutingTableOverwrittenOrOverlaid(deviceConfigFacade, mPrefs)) {
+            Log.d(TAG, "Routing table not overwritten or overlaid");
+            return;
+        }
+
+        // read default route
+        if (!mPrefs.contains(KEY_DEFAULT_ROUTE)) {
+            writeRoutingOption(KEY_DEFAULT_ROUTE, deviceConfigFacade.getDefaultRoute());
+        }
+        mDefaultRoute = getRouteForSecureElement(mPrefs.getString(KEY_DEFAULT_ROUTE, null));
+
+        // read default iso dep route
+        if (!mPrefs.contains(KEY_DEFAULT_ISO_DEP_ROUTE)) {
+            writeRoutingOption(
+                KEY_DEFAULT_ISO_DEP_ROUTE, deviceConfigFacade.getDefaultIsoDepRoute());
+        }
+        mDefaultIsoDepRoute =
+            getRouteForSecureElement(mPrefs.getString(KEY_DEFAULT_ISO_DEP_ROUTE, null));
+
+        // read default offhost route
+        if (!mPrefs.contains(KEY_DEFAULT_OFFHOST_ROUTE)) {
+            writeRoutingOption(
+                KEY_DEFAULT_OFFHOST_ROUTE, deviceConfigFacade.getDefaultOffHostRoute());
+        }
+        mDefaultOffHostRoute =
+            getRouteForSecureElement(mPrefs.getString(KEY_DEFAULT_OFFHOST_ROUTE, null));
+
+        // read auto change capable
+        if (!mPrefs.contains(KEY_AUTO_CHANGE_CAPABLE)) {
+            writeRoutingOption(KEY_AUTO_CHANGE_CAPABLE, true);
+        }
+        mIsAutoChangeCapable = mPrefs.getBoolean(KEY_AUTO_CHANGE_CAPABLE, true);
+        Log.d(TAG, "ReadOptions - " + toString());
+    }
+
+    public void setAutoChangeStatus(boolean status) {
+        mIsAutoChangeCapable = status;
+    }
+
+    public boolean isAutoChangeEnabled() { return mIsAutoChangeCapable;}
+
+    private void writeRoutingOption(String key, String name) {
+        mPrefs.edit().putString(key, name).apply();
+    }
+
+    private void writeRoutingOption(String key, boolean value) {
+        mPrefs.edit().putBoolean(key, value).apply();
+    }
+
+    public int getRouteForSecureElement(String se) {
+        return Optional.ofNullable(mRouteForSecureElement.get(se)).orElseGet(()->0x00);
+    }
+
+    public String getSecureElementForRoute(int route) {
+        return Optional.ofNullable(mSecureElementForRoute.get(route)).orElseGet(()->DEVICE_HOST);
+    }
+
+
+    private void addOrUpdateTableItems(String prefix, byte[] routes) {
+        if (routes!= null && routes.length != 0) {
+            for (int index=1; index<=routes.length; index++) {
+                int route = routes[index-1] & 0xFF;
+                String name = prefix + index;
+                mRouteForSecureElement.putIfAbsent(name, route);
+                mSecureElementForRoute.putIfAbsent(route, name);
+            }
+        }
+
+        Log.d(TAG, "RouteForSecureElement: " + mRouteForSecureElement.toString());
+        Log.d(TAG, "mSecureElementForRoute: " + mSecureElementForRoute.toString());
+    }
 }
diff --git a/src/com/android/nfc/cardemulation/TapAgainDialog.java b/src/com/android/nfc/cardemulation/TapAgainDialog.java
index 3d575729..19679c40 100644
--- a/src/com/android/nfc/cardemulation/TapAgainDialog.java
+++ b/src/com/android/nfc/cardemulation/TapAgainDialog.java
@@ -32,7 +32,6 @@ import android.view.View;
 import android.view.Window;
 import android.view.WindowManager;
 import android.widget.ImageView;
-import android.widget.TextView;
 import androidx.appcompat.widget.Toolbar;
 
 import com.android.nfc.cardemulation.util.AlertActivity;
diff --git a/src/com/android/nfc/cardemulation/WalletRoleObserver.java b/src/com/android/nfc/cardemulation/WalletRoleObserver.java
index 55323ec7..28ba0c54 100644
--- a/src/com/android/nfc/cardemulation/WalletRoleObserver.java
+++ b/src/com/android/nfc/cardemulation/WalletRoleObserver.java
@@ -23,6 +23,7 @@ import android.os.Binder;
 import android.os.UserHandle;
 import android.permission.flags.Flags;
 import android.util.Log;
+import android.sysprop.NfcProperties;
 
 import com.android.internal.annotations.VisibleForTesting;
 import com.android.nfc.NfcEventLog;
@@ -32,6 +33,7 @@ import com.android.nfc.proto.NfcEventProto;
 import java.util.List;
 
 public class WalletRoleObserver {
+    static final boolean DBG = NfcProperties.debug_enabled().orElse(true);
     private static final String TAG = "WalletRoleObserver";
 
     public interface Callback {
@@ -54,9 +56,10 @@ public class WalletRoleObserver {
             if (!roleName.equals(RoleManager.ROLE_WALLET)) {
                 return;
             }
-            List<String> roleHolders = roleManager.getRoleHolders(RoleManager.ROLE_WALLET);
+            List<String> roleHolders = roleManager.getRoleHoldersAsUser(RoleManager.ROLE_WALLET,
+                    user);
             String roleHolder = roleHolders.isEmpty() ? null : roleHolders.get(0);
-            Log.i(TAG, "Wallet role changed for user " + user.getIdentifier() + " to "
+            if (DBG) Log.i(TAG, "Wallet role changed for user " + user.getIdentifier() + " to "
                        + roleHolder);
             mNfcEventLog.logEvent(
                     NfcEventProto.EventType.newBuilder()
@@ -96,7 +99,7 @@ public class WalletRoleObserver {
 
     public void onUserSwitched(int userId) {
         String roleHolder = getDefaultWalletRoleHolder(userId);
-        Log.i(TAG, "Wallet role for user " + userId + ": " + roleHolder);
+        if (DBG) Log.i(TAG, "Wallet role for user " + userId + ": " + roleHolder);
         mCallback.onWalletRoleHolderChanged(roleHolder, userId);
     }
 }
diff --git a/src/com/android/nfc/handover/BluetoothPeripheralHandover.java b/src/com/android/nfc/handover/BluetoothPeripheralHandover.java
index c41aec1c..bba08752 100644
--- a/src/com/android/nfc/handover/BluetoothPeripheralHandover.java
+++ b/src/com/android/nfc/handover/BluetoothPeripheralHandover.java
@@ -60,8 +60,9 @@ public class BluetoothPeripheralHandover implements BluetoothProfile.ServiceList
     static final String ACTION_ALLOW_CONNECT = "com.android.nfc.handover.action.ALLOW_CONNECT";
     static final String ACTION_DENY_CONNECT = "com.android.nfc.handover.action.DENY_CONNECT";
     static final String ACTION_TIMEOUT_CONNECT = "com.android.nfc.handover.action.TIMEOUT_CONNECT";
+    static final String ACTION_CANCEL_CONNECT = "com.android.nfc.handover.action.CANCEL_CONNECT";
 
-    static final int TIMEOUT_MS = 20000;
+    static final int TIMEOUT_MS = 25000;
     static final int RETRY_PAIRING_WAIT_TIME_MS = 2000;
     static final int RETRY_CONNECT_WAIT_TIME_MS = 5000;
 
@@ -115,6 +116,7 @@ public class BluetoothPeripheralHandover implements BluetoothProfile.ServiceList
     BluetoothA2dp mA2dp;
     BluetoothHeadset mHeadset;
     BluetoothHidHost mInput;
+    boolean mShouldAbortBroadcast = false;
 
     public interface Callback {
         public void onBluetoothPeripheralHandoverComplete(boolean connected);
@@ -170,6 +172,7 @@ public class BluetoothPeripheralHandover implements BluetoothProfile.ServiceList
         IntentFilter filter = new IntentFilter();
         filter.addAction(BluetoothAdapter.ACTION_STATE_CHANGED);
         filter.addAction(BluetoothDevice.ACTION_BOND_STATE_CHANGED);
+        filter.addAction(BluetoothDevice.ACTION_PAIRING_REQUEST);
         filter.addAction(BluetoothA2dp.ACTION_CONNECTION_STATE_CHANGED);
         filter.addAction(BluetoothHeadset.ACTION_CONNECTION_STATE_CHANGED);
         filter.addAction(BluetoothHidHost.ACTION_CONNECTION_STATE_CHANGED);
@@ -533,6 +536,14 @@ public class BluetoothPeripheralHandover implements BluetoothProfile.ServiceList
                 mHidResult = RESULT_DISCONNECTED;
                 nextStep();
             }
+        } else if (BluetoothDevice.ACTION_PAIRING_REQUEST.equals(action)) {
+            int type = intent.getIntExtra(BluetoothDevice.EXTRA_PAIRING_VARIANT,
+                BluetoothDevice.ERROR);
+            if (type == BluetoothDevice.PAIRING_VARIANT_CONSENT) {
+                mDevice.setPairingConfirmation(true);
+                mShouldAbortBroadcast = true;
+                Log.d(TAG, "PAIRING_REQUEST is Auto Confirmed");
+            }
         }
     }
 
@@ -661,6 +672,10 @@ public class BluetoothPeripheralHandover implements BluetoothProfile.ServiceList
         @Override
         public void onReceive(Context context, Intent intent) {
             handleIntent(intent);
+            if (mShouldAbortBroadcast) {
+                mShouldAbortBroadcast = false;
+                abortBroadcast();
+            }
         }
     };
 
diff --git a/src/com/android/nfc/handover/ConfirmConnectActivity.java b/src/com/android/nfc/handover/ConfirmConnectActivity.java
index 159eee0c..0ed9c6c8 100644
--- a/src/com/android/nfc/handover/ConfirmConnectActivity.java
+++ b/src/com/android/nfc/handover/ConfirmConnectActivity.java
@@ -20,6 +20,7 @@ import static android.view.WindowManager.LayoutParams.SYSTEM_FLAG_HIDE_NON_SYSTE
 
 import android.app.Activity;
 import android.app.AlertDialog;
+import android.bluetooth.BluetoothAdapter;
 import android.bluetooth.BluetoothDevice;
 import android.content.BroadcastReceiver;
 import android.content.Context;
@@ -28,10 +29,12 @@ import android.content.Intent;
 import android.content.IntentFilter;
 import android.content.res.Resources;
 import android.os.Bundle;
+import android.util.Log;
 
 import com.android.nfc.R;
 
 public class ConfirmConnectActivity extends Activity {
+    static final String TAG = "ConfirmConnectActivity";
     BluetoothDevice mDevice;
     AlertDialog mAlert = null;
     @Override
@@ -74,8 +77,10 @@ public class ConfirmConnectActivity extends Activity {
         mAlert = builder.create();
         mAlert.show();
 
-        registerReceiver(mReceiver,
-                new IntentFilter(BluetoothPeripheralHandover.ACTION_TIMEOUT_CONNECT));
+        IntentFilter filter = new IntentFilter();
+        filter.addAction(BluetoothPeripheralHandover.ACTION_TIMEOUT_CONNECT);
+        filter.addAction(BluetoothPeripheralHandover.ACTION_CANCEL_CONNECT);
+        registerReceiver(mReceiver, filter, Context.RECEIVER_EXPORTED);
     }
 
     @Override
@@ -98,6 +103,21 @@ public class ConfirmConnectActivity extends Activity {
             if (BluetoothPeripheralHandover.ACTION_TIMEOUT_CONNECT.equals(intent.getAction())) {
                 finish();
             }
+            /*
+              if Bluetooth turned off from Notification Panel, finish this activity.
+              Also, sendBroadcast(ACTION_DENY_CONNECT) because otherwise when Bluetooth
+              is later turned On, headset seen as paired.
+            */
+            else if (BluetoothPeripheralHandover.ACTION_CANCEL_CONNECT
+                    .equals(intent.getAction())) {
+                Log.i(TAG, "Received ACTION_CANCEL_CONNECT action.");
+                Intent denyIntent =
+                        new Intent(BluetoothPeripheralHandover.ACTION_DENY_CONNECT);
+                denyIntent.putExtra(BluetoothDevice.EXTRA_DEVICE, mDevice);
+                denyIntent.setPackage("com.android.nfc");
+                context.sendBroadcast(denyIntent);
+                finish();
+            }
         }
     };
 }
diff --git a/src/com/android/nfc/handover/HandoverDataParser.java b/src/com/android/nfc/handover/HandoverDataParser.java
index 8363f756..7b87ba1a 100644
--- a/src/com/android/nfc/handover/HandoverDataParser.java
+++ b/src/com/android/nfc/handover/HandoverDataParser.java
@@ -341,12 +341,12 @@ public class HandoverDataParser {
         byte[] type = r.getType();
 
         // Check for BT OOB record
-        if (r.getTnf() == NdefRecord.TNF_MIME_MEDIA && Arrays.equals(r.getType(), TYPE_BT_OOB)) {
+        if (tnf == NdefRecord.TNF_MIME_MEDIA && Arrays.equals(type, TYPE_BT_OOB)) {
             return parseBtOob(ByteBuffer.wrap(r.getPayload()));
         }
 
         // Check for BLE OOB record
-        if (r.getTnf() == NdefRecord.TNF_MIME_MEDIA && Arrays.equals(r.getType(), TYPE_BLE_OOB)) {
+        if (tnf == NdefRecord.TNF_MIME_MEDIA && Arrays.equals(type, TYPE_BLE_OOB)) {
             return parseBleOob(ByteBuffer.wrap(r.getPayload()));
         }
 
diff --git a/src/com/android/nfc/handover/PeripheralHandoverService.java b/src/com/android/nfc/handover/PeripheralHandoverService.java
index 39b60e1a..16a7f020 100644
--- a/src/com/android/nfc/handover/PeripheralHandoverService.java
+++ b/src/com/android/nfc/handover/PeripheralHandoverService.java
@@ -16,6 +16,8 @@
 
 package com.android.nfc.handover;
 
+import static com.android.nfc.handover.BluetoothPeripheralHandover.ACTION_CANCEL_CONNECT;
+
 import android.app.Service;
 import android.bluetooth.BluetoothAdapter;
 import android.bluetooth.BluetoothClass;
@@ -34,8 +36,10 @@ import android.os.Messenger;
 import android.os.ParcelUuid;
 import android.os.Parcelable;
 import android.os.RemoteException;
+import android.text.TextUtils;
 import android.util.Log;
 
+import java.util.Objects;
 import java.util.Set;
 
 public class PeripheralHandoverService extends Service implements BluetoothPeripheralHandover.Callback {
@@ -73,9 +77,11 @@ public class PeripheralHandoverService extends Service implements BluetoothPerip
     Handler mHandler;
     BluetoothPeripheralHandover mBluetoothPeripheralHandover;
     BluetoothDevice mDevice;
+    String mName;
     Messenger mClient;
     boolean mBluetoothHeadsetConnected;
     boolean mBluetoothEnabledByNfc;
+    Bundle mPendingMsgData = null;
 
     class MessageHandler extends Handler {
         @Override
@@ -109,9 +115,29 @@ public class PeripheralHandoverService extends Service implements BluetoothPerip
 
     @Override
     public int onStartCommand(Intent intent, int flags, int startId) {
+        if (intent == null) {
+            if (DBG) Log.e(TAG, "Intent is null, can't do peripheral handover.");
+            synchronized (sLock) {
+                stopSelf(startId);
+                mStartId = 0;
+            }
+            return START_NOT_STICKY;
+        }
+
+        Bundle msgData = intent.getExtras();
+        BluetoothDevice device = msgData.getParcelable(EXTRA_PERIPHERAL_DEVICE);
+        String name = msgData.getString(EXTRA_PERIPHERAL_NAME);
 
         synchronized (sLock) {
             if (mStartId != 0) {
+                Log.d(TAG, "Ongoing handover to " + mDevice);
+                if (!Objects.equals(mDevice, device) || !TextUtils.equals(mName, name)) {
+                    Log.w(TAG, "Cancel ongoing handover");
+                    sendBroadcast(new Intent(ACTION_CANCEL_CONNECT));
+                    // Wait for the previous attempt to be fully cancelled. Store the new pairing
+                    // data to start the pairing after cancellation.
+                    mPendingMsgData = new Bundle(msgData);
+                }
                 mStartId = startId;
                 // already running
                 return START_STICKY;
@@ -119,15 +145,6 @@ public class PeripheralHandoverService extends Service implements BluetoothPerip
             mStartId = startId;
         }
 
-        if (intent == null) {
-            if (DBG) Log.e(TAG, "Intent is null, can't do peripheral handover.");
-            synchronized (sLock) {
-                stopSelf(startId);
-                mStartId = 0;
-            }
-            return START_NOT_STICKY;
-        }
-
         if (doPeripheralHandover(intent.getExtras())) {
             return START_STICKY;
         } else {
@@ -152,6 +169,7 @@ public class PeripheralHandoverService extends Service implements BluetoothPerip
     }
 
     boolean doPeripheralHandover(Bundle msgData) {
+        Log.d(TAG, "doPeripheralHandover: " + msgData);
         if (mBluetoothPeripheralHandover != null) {
             Log.d(TAG, "Ignoring pairing request, existing handover in progress.");
             return true;
@@ -162,7 +180,7 @@ public class PeripheralHandoverService extends Service implements BluetoothPerip
         }
 
         mDevice = msgData.getParcelable(EXTRA_PERIPHERAL_DEVICE);
-        String name = msgData.getString(EXTRA_PERIPHERAL_NAME);
+        mName = msgData.getString(EXTRA_PERIPHERAL_NAME);
         int transport = msgData.getInt(EXTRA_PERIPHERAL_TRANSPORT);
         OobData oobData = msgData.getParcelable(EXTRA_PERIPHERAL_OOB_DATA);
         Parcelable[] parcelables = msgData.getParcelableArray(EXTRA_PERIPHERAL_UUIDS);
@@ -180,7 +198,7 @@ public class PeripheralHandoverService extends Service implements BluetoothPerip
         mBluetoothEnabledByNfc = msgData.getBoolean(EXTRA_BT_ENABLED);
 
         mBluetoothPeripheralHandover = new BluetoothPeripheralHandover(
-                this, mDevice, name, transport, oobData, uuids, btClass, this);
+                this, mDevice, mName, transport, oobData, uuids, btClass, this);
 
         if (transport == BluetoothDevice.TRANSPORT_LE) {
             mHandler.sendMessageDelayed(
@@ -204,7 +222,9 @@ public class PeripheralHandoverService extends Service implements BluetoothPerip
     private void handleBluetoothStateChanged(Intent intent) {
         int state = intent.getIntExtra(BluetoothAdapter.EXTRA_STATE,
                 BluetoothAdapter.ERROR);
-        if (state == BluetoothAdapter.STATE_ON) {
+        if (state == BluetoothAdapter.STATE_OFF) {
+            sendBroadcast(new Intent(ACTION_CANCEL_CONNECT));
+        } else if (state == BluetoothAdapter.STATE_ON) {
             // If there is a pending device pairing, start it
             if (mBluetoothPeripheralHandover != null &&
                     !mBluetoothPeripheralHandover.hasStarted()) {
@@ -239,9 +259,15 @@ public class PeripheralHandoverService extends Service implements BluetoothPerip
         disableBluetoothIfNeeded();
         replyToClient(connected);
 
-        synchronized (sLock) {
-            stopSelf(mStartId);
-            mStartId = 0;
+        if (mPendingMsgData != null) {
+            Log.d(TAG, "Resume next handover after cancellation of previous handover");
+            doPeripheralHandover(mPendingMsgData);
+            mPendingMsgData = null;
+        } else {
+            synchronized (sLock) {
+                stopSelf(mStartId);
+                mStartId = 0;
+            }
         }
     }
 
diff --git a/tests/instrumentation/Android.bp b/tests/instrumentation/Android.bp
index c9f6667b..87a20046 100644
--- a/tests/instrumentation/Android.bp
+++ b/tests/instrumentation/Android.bp
@@ -9,9 +9,9 @@ android_test {
     certificate: "platform",
 
     libs: [
-        "android.test.runner",
-        "android.test.base",
-        "android.test.mock",
+        "android.test.runner.stubs.system",
+        "android.test.base.stubs.system",
+        "android.test.mock.stubs.system",
         "framework-nfc.impl",
         "unsupportedappusage",
     ],
@@ -36,6 +36,7 @@ android_test {
 
     test_suites: [
         "device-tests",
+        "device-pixel-tests",
         "device-platinum-tests",
     ],
 
diff --git a/tests/instrumentation/src/com/android/nfc/cardemulation/AppChooserActivityTest.java b/tests/instrumentation/src/com/android/nfc/cardemulation/AppChooserActivityTest.java
index 9e942aee..93463b66 100644
--- a/tests/instrumentation/src/com/android/nfc/cardemulation/AppChooserActivityTest.java
+++ b/tests/instrumentation/src/com/android/nfc/cardemulation/AppChooserActivityTest.java
@@ -154,6 +154,7 @@ public class AppChooserActivityTest {
                                                     /* withServices = */ true));
 
     assertThat(scenario.getState()).isAtLeast(Lifecycle.State.CREATED);
+    scenario.moveToState(Lifecycle.State.RESUMED);
     String expectedText = context.getString(R.string.appchooser_description);
     onView(withId(R.id.appchooser_text)).check(matches(withText(expectedText)));
     scenario.onActivity(activity -> {
diff --git a/tests/instrumentation/src/com/android/nfc/cardemulation/TapAgainDialogTest.java b/tests/instrumentation/src/com/android/nfc/cardemulation/TapAgainDialogTest.java
index 5ec96226..af9eedff 100644
--- a/tests/instrumentation/src/com/android/nfc/cardemulation/TapAgainDialogTest.java
+++ b/tests/instrumentation/src/com/android/nfc/cardemulation/TapAgainDialogTest.java
@@ -65,8 +65,10 @@ public class TapAgainDialogTest {
 
   @Test
   public void testOnClick() throws Exception {
-    ActivityScenario.launch(getStartIntent());
+    ActivityScenario<TapAgainDialog> scenario = ActivityScenario.launch(getStartIntent());
 
+    assertThat(scenario.getState()).isAtLeast(Lifecycle.State.CREATED);
+    scenario.moveToState(Lifecycle.State.RESUMED);
     onView(withId(R.id.tap_again_toolbar)).perform(click());
 
     onView(withId(ALERT_DIALOG_ID)).check(matches(isDisplayed()));
diff --git a/tests/testcases/Android.bp b/tests/testcases/Android.bp
new file mode 100644
index 00000000..11e95b07
--- /dev/null
+++ b/tests/testcases/Android.bp
@@ -0,0 +1,51 @@
+package {
+    default_team: "trendy_team_fwk_nfc",
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+android_test {
+    name: "NfcTestCases",
+    defaults: ["NfcNciDefaults"],
+    platform_apis: true,
+
+    libs: [
+        "android.test.runner.stubs.system",
+        "android.test.base.stubs.system",
+        "framework-nfc.impl",
+        "flag-junit",
+        "platform-test-annotations",
+        "testables",
+        "testng",
+        "unsupportedappusage",
+    ],
+
+    static_libs: [
+        "androidx.test.ext.junit",
+        "androidx.test.uiautomator_uiautomator",
+        "flag-junit",
+        "androidx.test.core",
+        "androidx.test.rules",
+        "androidx.test.ext.junit",
+        "frameworks-base-testutils",
+        "truth",
+        "androidx.annotation_annotation",
+        "androidx.appcompat_appcompat",
+        "com.google.android.material_material",
+        "nfc-event-log-proto",
+        "nfc_flags_lib",
+        "flag-junit",
+        "platform-test-annotations",
+        "testables",
+        "compatibility-common-util-devicesidelib",
+        "compatibility-device-util-axt",
+    ],
+
+    // Include all test java files.
+    srcs: [
+        "src/**/*.java",
+        ":framework-nfc-updatable-sources",
+    ],
+
+    test_suites: ["general-tests"],
+
+}
diff --git a/tests/testcases/AndroidManifest.xml b/tests/testcases/AndroidManifest.xml
new file mode 100644
index 00000000..392d0ffd
--- /dev/null
+++ b/tests/testcases/AndroidManifest.xml
@@ -0,0 +1,66 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!-- Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+-->
+
+<manifest xmlns:android="http://schemas.android.com/apk/res/android"
+          package="android.nfc.test"
+          android:targetSandboxVersion="2">
+    <uses-permission android:name="android.permission.DISABLE_KEYGUARD" />
+    <uses-permission android:name="android.permission.NFC" />
+    <uses-permission android:name="android.permission.NFC_PREFERRED_PAYMENT_INFO" />
+    <uses-permission android:name="android.permission.WRITE_SECURE_SETTINGS" />
+    <uses-permission android:name="android.permission.INTERACT_ACROSS_USERS"/>
+    <queries>
+        <package android:name="com.android.test.foregroundnfc" />
+        <package android:name="com.android.test.walletroleholder" />
+    </queries>
+    <application android:testOnly="true">
+        <uses-library android:name="android.test.runner"/>
+        <service android:name=".CustomHostApduService" android:exported="true"
+                 android:permission="android.permission.BIND_NFC_SERVICE">
+            <intent-filter>
+                <action android:name="android.nfc.cardemulation.action.HOST_APDU_SERVICE"/>
+            </intent-filter>
+            <meta-data android:name="android.nfc.cardemulation.host_apdu_service"
+                       android:resource="@xml/custom_aid_list"/>
+        </service>
+        <service android:name=".SecondHostApduService" android:exported="true"
+                 android:permission="android.permission.BIND_NFC_SERVICE">
+            <intent-filter>
+                <action android:name="android.nfc.cardemulation.action.HOST_APDU_SERVICE"/>
+            </intent-filter>
+            <meta-data android:name="android.nfc.cardemulation.host_apdu_service"
+                       android:resource="@xml/second_aid_list"/>
+        </service>
+        <activity android:name="android.nfc.test.NfcFCardEmulationActivity"
+             android:exported="false">
+        </activity>
+        <activity android:name="android.nfc.test.ForegroundHceActivity"
+             android:exported="false">
+        </activity>
+        <receiver android:name=".PollingLoopBroadcastReceiver"
+            android:enabled="true"
+            android:exported="true">
+            <intent-filter>
+                <action android:name="android.nfc.test.PollingLoopFired" />
+            </intent-filter>
+        </receiver>
+    </application>
+    <!-- This is a self-instrumenting test package. -->
+    <instrumentation android:name="androidx.test.runner.AndroidJUnitRunner"
+                     android:label="Stress and regression tests for NFC CardEmulation API"
+                     android:targetPackage="android.nfc.test">
+    </instrumentation>
+</manifest>
diff --git a/tests/testcases/AndroidTest.xml b/tests/testcases/AndroidTest.xml
new file mode 100644
index 00000000..e9a66391
--- /dev/null
+++ b/tests/testcases/AndroidTest.xml
@@ -0,0 +1,38 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!-- Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+-->
+<configuration description="Config for Nfc test cases">
+    <option name="test-suite-tag" value="apct" />
+    <option name="test-suite-tag" value="apct-instrumentation" />
+    <target_preparer class="com.android.tradefed.targetprep.RootTargetPreparer">
+        <option name="force-root" value="true" />
+    </target_preparer>
+    <option name="config-descriptor:metadata" key="component" value="systems"/>
+    <option name="config-descriptor:metadata" key="parameter" value="not_instant_app" />
+    <option name="config-descriptor:metadata" key="parameter" value="not_multi_abi" />
+    <option name="config-descriptor:metadata" key="parameter" value="secondary_user" />
+    <option name="config-descriptor:metadata" key="parameter" value="no_foldable_states" />
+    <option name="not-shardable" value="true" />
+    <option name="install-arg" value="-t" />
+    <target_preparer class="com.android.tradefed.targetprep.suite.SuiteApkInstaller">
+        <option name="cleanup-apks" value="true"/>
+        <option name="test-file-name" value="NfcTestCases.apk" />
+    </target_preparer>
+    <test class="com.android.tradefed.testtype.AndroidJUnitTest">
+        <option name="package" value="android.nfc.test"/>
+        <option name="runner" value="androidx.test.runner.AndroidJUnitRunner" />
+        <option name="runtime-hint" value="10m10s"/>
+    </test>
+</configuration>
diff --git a/tests/testcases/jarjar-rules.txt b/tests/testcases/jarjar-rules.txt
new file mode 100644
index 00000000..e69de29b
diff --git a/tests/testcases/res/values-af/strings.xml b/tests/testcases/res/values-af/strings.xml
new file mode 100644
index 00000000..d984802a
--- /dev/null
+++ b/tests/testcases/res/values-af/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"Gepasmaakte NFC-toetsdiens"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"Tweede NFC-toetsdiens"</string>
+</resources>
diff --git a/tests/testcases/res/values-am/strings.xml b/tests/testcases/res/values-am/strings.xml
new file mode 100644
index 00000000..bbc90b4d
--- /dev/null
+++ b/tests/testcases/res/values-am/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"ብጁ ኤንኤፍሲ የሙከራ አገልግሎት"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"ሁለተኛ ኤንኤፍሲ ሙከራ አገልግሎት"</string>
+</resources>
diff --git a/tests/testcases/res/values-ar/strings.xml b/tests/testcases/res/values-ar/strings.xml
new file mode 100644
index 00000000..7b966011
--- /dev/null
+++ b/tests/testcases/res/values-ar/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"‏خدمة اختبار تكنولوجيا NFC المخصّصة"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"‏خدمة اختبار تكنولوجيا NFC الثانية"</string>
+</resources>
diff --git a/tests/testcases/res/values-as/strings.xml b/tests/testcases/res/values-as/strings.xml
new file mode 100644
index 00000000..d018f668
--- /dev/null
+++ b/tests/testcases/res/values-as/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"কাষ্টম Nfc পৰীক্ষণ সেৱা"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"দ্বিতীয় Nfc পৰীক্ষণ সেৱা"</string>
+</resources>
diff --git a/tests/testcases/res/values-az/strings.xml b/tests/testcases/res/values-az/strings.xml
new file mode 100644
index 00000000..1d69f2ce
--- /dev/null
+++ b/tests/testcases/res/values-az/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"Fərdi NFC Test Xidməti"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"İkinci NFC Test Xidməti"</string>
+</resources>
diff --git a/tests/testcases/res/values-b+sr+Latn/strings.xml b/tests/testcases/res/values-b+sr+Latn/strings.xml
new file mode 100644
index 00000000..838dd22a
--- /dev/null
+++ b/tests/testcases/res/values-b+sr+Latn/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"Prilagođena usluga NFC testiranja"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"Usluga drugog NFC testiranja"</string>
+</resources>
diff --git a/tests/testcases/res/values-be/strings.xml b/tests/testcases/res/values-be/strings.xml
new file mode 100644
index 00000000..5b093d1c
--- /dev/null
+++ b/tests/testcases/res/values-be/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"Карыстальніцкі сэрвіс тэсціравання Nfc"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"Другі сэрвіс тэсціравання NFC"</string>
+</resources>
diff --git a/tests/testcases/res/values-bg/strings.xml b/tests/testcases/res/values-bg/strings.xml
new file mode 100644
index 00000000..f9913d58
--- /dev/null
+++ b/tests/testcases/res/values-bg/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"Тестова услуга за персонализирана функция за NFC"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"Втора тестова услуга за NFC"</string>
+</resources>
diff --git a/tests/testcases/res/values-bn/strings.xml b/tests/testcases/res/values-bn/strings.xml
new file mode 100644
index 00000000..35acc4e2
--- /dev/null
+++ b/tests/testcases/res/values-bn/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"কাস্টম NFC-এর পরীক্ষামূলক পরিষেবা"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"NFC-এর পরীক্ষামূলক দ্বিতীয় পরিষেবা"</string>
+</resources>
diff --git a/tests/testcases/res/values-bs/strings.xml b/tests/testcases/res/values-bs/strings.xml
new file mode 100644
index 00000000..83186dae
--- /dev/null
+++ b/tests/testcases/res/values-bs/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"Usluga testiranja prilagođenog NFC-a"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"Usluga drugog testa NFC-a"</string>
+</resources>
diff --git a/tests/testcases/res/values-ca/strings.xml b/tests/testcases/res/values-ca/strings.xml
new file mode 100644
index 00000000..bb61d506
--- /dev/null
+++ b/tests/testcases/res/values-ca/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"Servei de prova de l\'NFC personalitzat"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"Segon servei de prova de l\'NFC"</string>
+</resources>
diff --git a/tests/testcases/res/values-cs/strings.xml b/tests/testcases/res/values-cs/strings.xml
new file mode 100644
index 00000000..72500a68
--- /dev/null
+++ b/tests/testcases/res/values-cs/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"Vlastní testovací služba NFC"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"Druhá testovací služba NFC"</string>
+</resources>
diff --git a/tests/testcases/res/values-da/strings.xml b/tests/testcases/res/values-da/strings.xml
new file mode 100644
index 00000000..fb6234da
--- /dev/null
+++ b/tests/testcases/res/values-da/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"Tilpasset NFC-testtjeneste"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"Anden NFC-testtjeneste"</string>
+</resources>
diff --git a/tests/testcases/res/values-de/strings.xml b/tests/testcases/res/values-de/strings.xml
new file mode 100644
index 00000000..3018aec4
--- /dev/null
+++ b/tests/testcases/res/values-de/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"Benutzerdefinierter NFC-Testdienst"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"Zweiter NFC‑Testdienst"</string>
+</resources>
diff --git a/tests/testcases/res/values-el/strings.xml b/tests/testcases/res/values-el/strings.xml
new file mode 100644
index 00000000..b3c6ff70
--- /dev/null
+++ b/tests/testcases/res/values-el/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"Προσαρμοσμένη υπηρεσία δοκιμής NFC"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"Δεύτερη δοκιμαστική υπηρεσία NFC"</string>
+</resources>
diff --git a/tests/testcases/res/values-en-rAU/strings.xml b/tests/testcases/res/values-en-rAU/strings.xml
new file mode 100644
index 00000000..a451fbaf
--- /dev/null
+++ b/tests/testcases/res/values-en-rAU/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"Custom NFC test service"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"Second NFC test service"</string>
+</resources>
diff --git a/tests/testcases/res/values-en-rCA/strings.xml b/tests/testcases/res/values-en-rCA/strings.xml
new file mode 100644
index 00000000..44d94ace
--- /dev/null
+++ b/tests/testcases/res/values-en-rCA/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"Custom Nfc Test Service"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"Second Nfc Test Service"</string>
+</resources>
diff --git a/tests/testcases/res/values-en-rGB/strings.xml b/tests/testcases/res/values-en-rGB/strings.xml
new file mode 100644
index 00000000..a451fbaf
--- /dev/null
+++ b/tests/testcases/res/values-en-rGB/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"Custom NFC test service"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"Second NFC test service"</string>
+</resources>
diff --git a/tests/testcases/res/values-en-rIN/strings.xml b/tests/testcases/res/values-en-rIN/strings.xml
new file mode 100644
index 00000000..a451fbaf
--- /dev/null
+++ b/tests/testcases/res/values-en-rIN/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"Custom NFC test service"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"Second NFC test service"</string>
+</resources>
diff --git a/tests/testcases/res/values-en-rXC/strings.xml b/tests/testcases/res/values-en-rXC/strings.xml
new file mode 100644
index 00000000..a0a86aca
--- /dev/null
+++ b/tests/testcases/res/values-en-rXC/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‎‏‎‎‏‎‏‏‎‏‏‏‏‏‏‏‏‏‎‎‎‎‎‎‎‏‏‏‏‎‎‎‎‏‎‎‎‏‎‎‎‏‏‏‎‎‎‏‎‎‎‎‏‎‎‎‎‎‏‎‎‎‎‎‏‎‏‏‏‏‎‎‏‎‎‎‏‏‎Custom Nfc Test Service‎‏‎‎‏‎"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‏‎‏‎‎‏‎‏‏‎‏‏‏‏‎‏‏‎‎‎‏‎‎‎‏‏‏‎‎‎‏‎‎‎‎‎‏‏‏‏‏‎‎‎‏‏‎‎‎‎‎‏‏‏‎‏‎‏‎‏‏‎‏‏‏‎‏‎‏‎‎‎‏‏‏‏‎‎Second Nfc Test Service‎‏‎‎‏‎"</string>
+</resources>
diff --git a/tests/testcases/res/values-es-rUS/strings.xml b/tests/testcases/res/values-es-rUS/strings.xml
new file mode 100644
index 00000000..9332b8a9
--- /dev/null
+++ b/tests/testcases/res/values-es-rUS/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"Servicio de prueba de NFC personalizado"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"Segundo servicio de prueba de NFC"</string>
+</resources>
diff --git a/tests/testcases/res/values-es/strings.xml b/tests/testcases/res/values-es/strings.xml
new file mode 100644
index 00000000..9332b8a9
--- /dev/null
+++ b/tests/testcases/res/values-es/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"Servicio de prueba de NFC personalizado"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"Segundo servicio de prueba de NFC"</string>
+</resources>
diff --git a/tests/testcases/res/values-et/strings.xml b/tests/testcases/res/values-et/strings.xml
new file mode 100644
index 00000000..76ab428b
--- /dev/null
+++ b/tests/testcases/res/values-et/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"Kohandatud NFC testimisteenus"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"Teine NFC testimisteenus"</string>
+</resources>
diff --git a/tests/testcases/res/values-eu/strings.xml b/tests/testcases/res/values-eu/strings.xml
new file mode 100644
index 00000000..93b85231
--- /dev/null
+++ b/tests/testcases/res/values-eu/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"NFC pertsonalizatuak probatzeko zerbitzua"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"NFCaren bigarren proba-zerbitzua"</string>
+</resources>
diff --git a/tests/testcases/res/values-fa/strings.xml b/tests/testcases/res/values-fa/strings.xml
new file mode 100644
index 00000000..3c1502a8
--- /dev/null
+++ b/tests/testcases/res/values-fa/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"‏سرویس تست NFC سفارشی"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"‏دومین سرویس آزمایشی Nfc"</string>
+</resources>
diff --git a/tests/testcases/res/values-fi/strings.xml b/tests/testcases/res/values-fi/strings.xml
new file mode 100644
index 00000000..c04d85a6
--- /dev/null
+++ b/tests/testcases/res/values-fi/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"Oma NFC-testipalvelu"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"Toinen NFC-testipalvelu"</string>
+</resources>
diff --git a/tests/testcases/res/values-fr-rCA/strings.xml b/tests/testcases/res/values-fr-rCA/strings.xml
new file mode 100644
index 00000000..35d7eb14
--- /dev/null
+++ b/tests/testcases/res/values-fr-rCA/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"Service de test de CCP personnalisé"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"Deuxième service de test de CCP"</string>
+</resources>
diff --git a/tests/testcases/res/values-fr/strings.xml b/tests/testcases/res/values-fr/strings.xml
new file mode 100644
index 00000000..5696350a
--- /dev/null
+++ b/tests/testcases/res/values-fr/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"Service de test NFC personnalisé"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"Deuxième service de test NFC"</string>
+</resources>
diff --git a/tests/testcases/res/values-gl/strings.xml b/tests/testcases/res/values-gl/strings.xml
new file mode 100644
index 00000000..2dec19b4
--- /dev/null
+++ b/tests/testcases/res/values-gl/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"Servizo de proba de NFC personalizado"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"Segundo servizo de proba de NFC"</string>
+</resources>
diff --git a/tests/testcases/res/values-gu/strings.xml b/tests/testcases/res/values-gu/strings.xml
new file mode 100644
index 00000000..c0d0b352
--- /dev/null
+++ b/tests/testcases/res/values-gu/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"NFCની કસ્ટમ પરીક્ષણ સેવા"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"બીજી NFC પરીક્ષણ સેવા"</string>
+</resources>
diff --git a/tests/testcases/res/values-hi/strings.xml b/tests/testcases/res/values-hi/strings.xml
new file mode 100644
index 00000000..8dbc4ffc
--- /dev/null
+++ b/tests/testcases/res/values-hi/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"कस्टम एनएफ़सी की जांच की सेवा"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"एनएफ़सी की जांच से जुड़ी दूसरी सेवा"</string>
+</resources>
diff --git a/tests/testcases/res/values-hr/strings.xml b/tests/testcases/res/values-hr/strings.xml
new file mode 100644
index 00000000..2945b668
--- /dev/null
+++ b/tests/testcases/res/values-hr/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"Usluga testiranja prilagođenog NFC-a"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"Druga usluga testiranja NFC-a"</string>
+</resources>
diff --git a/tests/testcases/res/values-hu/strings.xml b/tests/testcases/res/values-hu/strings.xml
new file mode 100644
index 00000000..52f76144
--- /dev/null
+++ b/tests/testcases/res/values-hu/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"Egyedi NFC-tesztszolgáltatás"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"Az NFC második tesztszolgáltatása"</string>
+</resources>
diff --git a/tests/testcases/res/values-hy/strings.xml b/tests/testcases/res/values-hy/strings.xml
new file mode 100644
index 00000000..1d5a8785
--- /dev/null
+++ b/tests/testcases/res/values-hy/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"NFC-ի ստուգման սեփական ծառայություն"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"NFC-ի երկրորդ փորձարկման ծառայություն"</string>
+</resources>
diff --git a/tests/testcases/res/values-in/strings.xml b/tests/testcases/res/values-in/strings.xml
new file mode 100644
index 00000000..a9331852
--- /dev/null
+++ b/tests/testcases/res/values-in/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"Layanan Pengujian Nfc Kustom"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"Layanan Pengujian NFC Kedua"</string>
+</resources>
diff --git a/tests/testcases/res/values-is/strings.xml b/tests/testcases/res/values-is/strings.xml
new file mode 100644
index 00000000..da80d27d
--- /dev/null
+++ b/tests/testcases/res/values-is/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"Sérsniðin Nfc-prófunarþjónusta"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"Aukaþjónusta fyrir NFC-prófun"</string>
+</resources>
diff --git a/tests/testcases/res/values-it/strings.xml b/tests/testcases/res/values-it/strings.xml
new file mode 100644
index 00000000..44fc5c8b
--- /dev/null
+++ b/tests/testcases/res/values-it/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"Servizio di test NFC personalizzato"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"Secondo servizio di test NFC"</string>
+</resources>
diff --git a/tests/testcases/res/values-iw/strings.xml b/tests/testcases/res/values-iw/strings.xml
new file mode 100644
index 00000000..d954501a
--- /dev/null
+++ b/tests/testcases/res/values-iw/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"‏שירות מותאם אישית לבדיקת NFC"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"‏שירות שני לבדיקת NFC"</string>
+</resources>
diff --git a/tests/testcases/res/values-ja/strings.xml b/tests/testcases/res/values-ja/strings.xml
new file mode 100644
index 00000000..9d6876e9
--- /dev/null
+++ b/tests/testcases/res/values-ja/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"カスタム NFC テストサービス"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"2 つ目の NFC テストサービス"</string>
+</resources>
diff --git a/tests/testcases/res/values-ka/strings.xml b/tests/testcases/res/values-ka/strings.xml
new file mode 100644
index 00000000..0a9cdf9b
--- /dev/null
+++ b/tests/testcases/res/values-ka/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"მორგებული NFc ტესტირების სერვისი"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"მეორე Nfc ტესტირების სერვისი"</string>
+</resources>
diff --git a/tests/testcases/res/values-kk/strings.xml b/tests/testcases/res/values-kk/strings.xml
new file mode 100644
index 00000000..c4a50065
--- /dev/null
+++ b/tests/testcases/res/values-kk/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"Арнаулы NFC технологиясын сынау қызметі"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"NFC технологиясын екінші сынау қызметі"</string>
+</resources>
diff --git a/tests/testcases/res/values-km/strings.xml b/tests/testcases/res/values-km/strings.xml
new file mode 100644
index 00000000..9bcfca68
--- /dev/null
+++ b/tests/testcases/res/values-km/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"សេវាកម្មធ្វើតេស្ត Nfc ផ្ទាល់ខ្លួន"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"សេវាកម្មធ្វើតេស្ត Nfc ទីពីរ"</string>
+</resources>
diff --git a/tests/testcases/res/values-kn/strings.xml b/tests/testcases/res/values-kn/strings.xml
new file mode 100644
index 00000000..7baeab98
--- /dev/null
+++ b/tests/testcases/res/values-kn/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"ಕಸ್ಟಮ್ Nfc ಟೆಸ್ಟ್ ಸೇವೆ"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"ಎರಡನೇ Nfc ಪರೀಕ್ಷಾ ಸೇವೆ"</string>
+</resources>
diff --git a/tests/testcases/res/values-ko/strings.xml b/tests/testcases/res/values-ko/strings.xml
new file mode 100644
index 00000000..8b8b3dde
--- /dev/null
+++ b/tests/testcases/res/values-ko/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"맞춤 NFC 테스트 서비스"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"2차 NFC 테스트 서비스"</string>
+</resources>
diff --git a/tests/testcases/res/values-ky/strings.xml b/tests/testcases/res/values-ky/strings.xml
new file mode 100644
index 00000000..92c979fd
--- /dev/null
+++ b/tests/testcases/res/values-ky/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"NFC жеке сыноо кызматы"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"Экинчн NFC сыноо кызматы"</string>
+</resources>
diff --git a/tests/testcases/res/values-lo/strings.xml b/tests/testcases/res/values-lo/strings.xml
new file mode 100644
index 00000000..a3bf2994
--- /dev/null
+++ b/tests/testcases/res/values-lo/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"ບໍລິການທົດສອບ Nfc ແບບກຳນົດເອງ"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"ບໍລິການທົດສອບ NFC ເທື່ອທີສອງ"</string>
+</resources>
diff --git a/tests/testcases/res/values-lt/strings.xml b/tests/testcases/res/values-lt/strings.xml
new file mode 100644
index 00000000..faaf2005
--- /dev/null
+++ b/tests/testcases/res/values-lt/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"Tinkinta NFC testavimo paslauga"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"Antroji NFC testavimo paslauga"</string>
+</resources>
diff --git a/tests/testcases/res/values-lv/strings.xml b/tests/testcases/res/values-lv/strings.xml
new file mode 100644
index 00000000..ee63089f
--- /dev/null
+++ b/tests/testcases/res/values-lv/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"Pielāgots NFC pārbaudes pakalpojums"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"Otrais NFC pārbaudes pakalpojums"</string>
+</resources>
diff --git a/tests/testcases/res/values-mk/strings.xml b/tests/testcases/res/values-mk/strings.xml
new file mode 100644
index 00000000..37ebb770
--- /dev/null
+++ b/tests/testcases/res/values-mk/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"Приспособена услуга за тестирање NFC"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"Втора услуга за тестирање NFC"</string>
+</resources>
diff --git a/tests/testcases/res/values-ml/strings.xml b/tests/testcases/res/values-ml/strings.xml
new file mode 100644
index 00000000..980f5c69
--- /dev/null
+++ b/tests/testcases/res/values-ml/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"ഇഷ്‍ടാനുസൃത NFC പരിശോധനാ സേവനം"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"രണ്ടാമത്തെ Nfc പരിശോധനാ സേവനം"</string>
+</resources>
diff --git a/tests/testcases/res/values-mn/strings.xml b/tests/testcases/res/values-mn/strings.xml
new file mode 100644
index 00000000..3480d56b
--- /dev/null
+++ b/tests/testcases/res/values-mn/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"Захиалгат NFC-н туршилтын үйлчилгээ"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"Хоёрдогч Nfc-н шалгалтын үйлчилгээ"</string>
+</resources>
diff --git a/tests/testcases/res/values-mr/strings.xml b/tests/testcases/res/values-mr/strings.xml
new file mode 100644
index 00000000..675dda29
--- /dev/null
+++ b/tests/testcases/res/values-mr/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"कस्टम NFC चाचणी सेवा"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"दुसरी Nfc चाचणी सेवा"</string>
+</resources>
diff --git a/tests/testcases/res/values-ms/strings.xml b/tests/testcases/res/values-ms/strings.xml
new file mode 100644
index 00000000..3ba3e7cc
--- /dev/null
+++ b/tests/testcases/res/values-ms/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"Perkhidmatan Ujian NFC Tersuai"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"Perkhidmatan Ujian Nfc Kedua"</string>
+</resources>
diff --git a/tests/testcases/res/values-my/strings.xml b/tests/testcases/res/values-my/strings.xml
new file mode 100644
index 00000000..df6b4728
--- /dev/null
+++ b/tests/testcases/res/values-my/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"စိတ်ကြိုက် Nfc စမ်းသပ်ဝန်ဆောင်မှု"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"ဒုတိယ NFC စမ်းသပ်ဝန်ဆောင်မှု"</string>
+</resources>
diff --git a/tests/testcases/res/values-nb/strings.xml b/tests/testcases/res/values-nb/strings.xml
new file mode 100644
index 00000000..fa176a52
--- /dev/null
+++ b/tests/testcases/res/values-nb/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"Egendefinert NFC-testtjeneste"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"Andre NFC-testtjeneste"</string>
+</resources>
diff --git a/tests/testcases/res/values-ne/strings.xml b/tests/testcases/res/values-ne/strings.xml
new file mode 100644
index 00000000..5ac297fc
--- /dev/null
+++ b/tests/testcases/res/values-ne/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"Nfc परीक्षण गर्ने कस्टम सेवा"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"NFC परीक्षण गर्ने दोस्रो सेवा"</string>
+</resources>
diff --git a/tests/testcases/res/values-nl/strings.xml b/tests/testcases/res/values-nl/strings.xml
new file mode 100644
index 00000000..6f312aab
--- /dev/null
+++ b/tests/testcases/res/values-nl/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"Aangepaste NFC-testservice"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"2e NFC-testservice"</string>
+</resources>
diff --git a/tests/testcases/res/values-or/strings.xml b/tests/testcases/res/values-or/strings.xml
new file mode 100644
index 00000000..82703ee1
--- /dev/null
+++ b/tests/testcases/res/values-or/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"କଷ୍ଟମ Nfc ଟେଷ୍ଟ ସେବା"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"ଦ୍ୱିତୀୟ Nfc ଟେଷ୍ଟ ସେବା"</string>
+</resources>
diff --git a/tests/testcases/res/values-pa/strings.xml b/tests/testcases/res/values-pa/strings.xml
new file mode 100644
index 00000000..a4889a6f
--- /dev/null
+++ b/tests/testcases/res/values-pa/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"ਵਿਉਂਤੀ NFC ਜਾਂਚ ਸੇਵਾ"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"NFC ਜਾਂਚ ਸੰਬੰਧੀ ਦੂਜੀ ਸੇਵਾ"</string>
+</resources>
diff --git a/tests/testcases/res/values-pl/strings.xml b/tests/testcases/res/values-pl/strings.xml
new file mode 100644
index 00000000..b690d824
--- /dev/null
+++ b/tests/testcases/res/values-pl/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"Niestandardowa usługa testu NFC"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"Druga usługa testu NFC"</string>
+</resources>
diff --git a/tests/testcases/res/values-pt-rPT/strings.xml b/tests/testcases/res/values-pt-rPT/strings.xml
new file mode 100644
index 00000000..65d8ab5c
--- /dev/null
+++ b/tests/testcases/res/values-pt-rPT/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"Serviço de teste de NFC personalizado"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"Segundo serviço de teste de NFC"</string>
+</resources>
diff --git a/tests/testcases/res/values-pt/strings.xml b/tests/testcases/res/values-pt/strings.xml
new file mode 100644
index 00000000..8a0a6b68
--- /dev/null
+++ b/tests/testcases/res/values-pt/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"Personalizar serviço de testes de NFC"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"Segundo serviço de testes de NFC"</string>
+</resources>
diff --git a/tests/testcases/res/values-ro/strings.xml b/tests/testcases/res/values-ro/strings.xml
new file mode 100644
index 00000000..255f9d76
--- /dev/null
+++ b/tests/testcases/res/values-ro/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"Serviciul de testare a tehnologiei NFC personalizate"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"Al doilea serviciu de testare a tehnologiei NFC"</string>
+</resources>
diff --git a/tests/testcases/res/values-ru/strings.xml b/tests/testcases/res/values-ru/strings.xml
new file mode 100644
index 00000000..b6457db5
--- /dev/null
+++ b/tests/testcases/res/values-ru/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"Собственная служба тестирования NFC"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"Вторая служба тестирования NFC"</string>
+</resources>
diff --git a/tests/testcases/res/values-si/strings.xml b/tests/testcases/res/values-si/strings.xml
new file mode 100644
index 00000000..f99c8cc0
--- /dev/null
+++ b/tests/testcases/res/values-si/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"අභිරුචි Nfc පරීක්ෂණ සේවාව"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"දෙවන Nfc පරීක්ෂණ සේවාව"</string>
+</resources>
diff --git a/tests/testcases/res/values-sk/strings.xml b/tests/testcases/res/values-sk/strings.xml
new file mode 100644
index 00000000..ad4237ef
--- /dev/null
+++ b/tests/testcases/res/values-sk/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"Vlastná služba na testovanie technológie NFC"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"Druhá testovacia služba technológie NFC"</string>
+</resources>
diff --git a/tests/testcases/res/values-sl/strings.xml b/tests/testcases/res/values-sl/strings.xml
new file mode 100644
index 00000000..6222d5b3
--- /dev/null
+++ b/tests/testcases/res/values-sl/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"Storitev preizkušanja tehnologije NFC po meri"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"Druga storitev preizkušanja tehnologije NFC"</string>
+</resources>
diff --git a/tests/testcases/res/values-sq/strings.xml b/tests/testcases/res/values-sq/strings.xml
new file mode 100644
index 00000000..2d442a1f
--- /dev/null
+++ b/tests/testcases/res/values-sq/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"Shërbimi i personalizuar për testimin e NFC-së"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"Shërbimi për testimin e dytë të NFC-së"</string>
+</resources>
diff --git a/tests/testcases/res/values-sr/strings.xml b/tests/testcases/res/values-sr/strings.xml
new file mode 100644
index 00000000..6ab28041
--- /dev/null
+++ b/tests/testcases/res/values-sr/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"Прилагођена услуга NFC тестирања"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"Услуга другог NFC тестирања"</string>
+</resources>
diff --git a/tests/testcases/res/values-sv/strings.xml b/tests/testcases/res/values-sv/strings.xml
new file mode 100644
index 00000000..513fa3ac
--- /dev/null
+++ b/tests/testcases/res/values-sv/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"Anpassad NFC-testtjänst"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"Andra NFC-testtjänsten"</string>
+</resources>
diff --git a/tests/testcases/res/values-sw/strings.xml b/tests/testcases/res/values-sw/strings.xml
new file mode 100644
index 00000000..2eb17576
--- /dev/null
+++ b/tests/testcases/res/values-sw/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"Huduma Maalum ya Majaribio ya NFC"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"Huduma ya Ziada ya Majaribio ya NFC"</string>
+</resources>
diff --git a/tests/testcases/res/values-ta/strings.xml b/tests/testcases/res/values-ta/strings.xml
new file mode 100644
index 00000000..5410c6a7
--- /dev/null
+++ b/tests/testcases/res/values-ta/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"பிரத்தியேகமான NFC பரிசோதனைச் சேவை"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"இரண்டாவது NFC பரிசோதனைச் சேவை"</string>
+</resources>
diff --git a/tests/testcases/res/values-te/strings.xml b/tests/testcases/res/values-te/strings.xml
new file mode 100644
index 00000000..3c9d13d2
--- /dev/null
+++ b/tests/testcases/res/values-te/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"అనుకూల Nfc టెస్ట్ సర్వీస్"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"రెండవ Nfc టెస్ట్ సర్వీస్"</string>
+</resources>
diff --git a/tests/testcases/res/values-th/strings.xml b/tests/testcases/res/values-th/strings.xml
new file mode 100644
index 00000000..9144ecaa
--- /dev/null
+++ b/tests/testcases/res/values-th/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"บริการทดสอบ NFC ที่กำหนดเอง"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"บริการทดสอบ NFC ครั้งที่ 2"</string>
+</resources>
diff --git a/tests/testcases/res/values-tl/strings.xml b/tests/testcases/res/values-tl/strings.xml
new file mode 100644
index 00000000..32296741
--- /dev/null
+++ b/tests/testcases/res/values-tl/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"Custom na Pansubok na Serbisyo sa Nfc"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"Pangalawang Pansubok na Serbisyo sa Nfc"</string>
+</resources>
diff --git a/tests/testcases/res/values-tr/strings.xml b/tests/testcases/res/values-tr/strings.xml
new file mode 100644
index 00000000..64d597be
--- /dev/null
+++ b/tests/testcases/res/values-tr/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"Özel NFC Testi Hizmeti"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"İkinci NFC Test Hizmeti"</string>
+</resources>
diff --git a/tests/testcases/res/values-uk/strings.xml b/tests/testcases/res/values-uk/strings.xml
new file mode 100644
index 00000000..0d47213c
--- /dev/null
+++ b/tests/testcases/res/values-uk/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"Власний сервіс перевірки NFC"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"Другий сервіс перевірки NFC"</string>
+</resources>
diff --git a/tests/testcases/res/values-ur/strings.xml b/tests/testcases/res/values-ur/strings.xml
new file mode 100644
index 00000000..5a7dbe77
--- /dev/null
+++ b/tests/testcases/res/values-ur/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"‏حسب ضرورت NFC کو ٹیسٹ کرنے کی سروس"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"‏دوسری NFC ٹیسٹ سروس"</string>
+</resources>
diff --git a/tests/testcases/res/values-uz/strings.xml b/tests/testcases/res/values-uz/strings.xml
new file mode 100644
index 00000000..2641a5da
--- /dev/null
+++ b/tests/testcases/res/values-uz/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"Maxsus Nfc sinov xizmati"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"Ikkinchi Nfc sinov xizmati"</string>
+</resources>
diff --git a/tests/testcases/res/values-vi/strings.xml b/tests/testcases/res/values-vi/strings.xml
new file mode 100644
index 00000000..50f03269
--- /dev/null
+++ b/tests/testcases/res/values-vi/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"Dịch vụ kiểm tra NFC tuỳ chỉnh"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"Dịch vụ kiểm tra NFC thứ hai"</string>
+</resources>
diff --git a/tests/testcases/res/values-zh-rCN/strings.xml b/tests/testcases/res/values-zh-rCN/strings.xml
new file mode 100644
index 00000000..efb85739
--- /dev/null
+++ b/tests/testcases/res/values-zh-rCN/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"自定义 NFC 测试服务"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"第二项 NFC 测试服务"</string>
+</resources>
diff --git a/tests/testcases/res/values-zh-rHK/strings.xml b/tests/testcases/res/values-zh-rHK/strings.xml
new file mode 100644
index 00000000..46265579
--- /dev/null
+++ b/tests/testcases/res/values-zh-rHK/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"自訂 NFC 測試服務"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"次要 NFC 測試服務"</string>
+</resources>
diff --git a/tests/testcases/res/values-zh-rTW/strings.xml b/tests/testcases/res/values-zh-rTW/strings.xml
new file mode 100644
index 00000000..6dd69800
--- /dev/null
+++ b/tests/testcases/res/values-zh-rTW/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"自訂 NFC 測試服務"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"第二個 NFC 測試服務"</string>
+</resources>
diff --git a/tests/testcases/res/values-zu/strings.xml b/tests/testcases/res/values-zu/strings.xml
new file mode 100644
index 00000000..651a1f11
--- /dev/null
+++ b/tests/testcases/res/values-zu/strings.xml
@@ -0,0 +1,21 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!--  Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="CustomPaymentService" msgid="8078913594613837603">"Isevisi Yangokwezifiso Yokuhlola Ye-Nfc"</string>
+    <string name="SecondPaymentService" msgid="1232932903544648990">"Isevisi Yesibili Yokuhlola Ye-Nfc"</string>
+</resources>
diff --git a/tests/testcases/res/values/strings.xml b/tests/testcases/res/values/strings.xml
new file mode 100644
index 00000000..577885fd
--- /dev/null
+++ b/tests/testcases/res/values/strings.xml
@@ -0,0 +1,19 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!-- Copyright (C) 2020 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+-->
+<resources>
+    <string name="CustomPaymentService">Custom Nfc Test Service</string>
+    <string name="SecondPaymentService">Second Nfc Test Service</string>
+</resources>
diff --git a/tests/testcases/res/xml/custom_aid_list.xml b/tests/testcases/res/xml/custom_aid_list.xml
new file mode 100644
index 00000000..1d4bfc3e
--- /dev/null
+++ b/tests/testcases/res/xml/custom_aid_list.xml
@@ -0,0 +1,13 @@
+<host-apdu-service xmlns:android="http://schemas.android.com/apk/res/android"
+    android:description="@string/CustomPaymentService">
+    <aid-group android:description="@string/CustomPaymentService" android:category="payment">
+        <aid-filter android:name="A000000004101018"/>
+    </aid-group>
+    <polling-loop-filter android:name="9464965c"/>
+    <polling-loop-filter android:name="b652c8f0"/>
+    <polling-loop-filter android:name="70dca719"/>
+    <polling-loop-filter android:name="261c0050"/>
+    <polling-loop-filter android:name="7f71156b" android:autoTransact="true"/>"
+    <polling-loop-filter android:name="b0343a5e" android:autoTransact="true"/>
+    <polling-loop-pattern-filter android:name="ae24db68.*"/>
+</host-apdu-service>
diff --git a/tests/testcases/res/xml/second_aid_list.xml b/tests/testcases/res/xml/second_aid_list.xml
new file mode 100644
index 00000000..3e905d4f
--- /dev/null
+++ b/tests/testcases/res/xml/second_aid_list.xml
@@ -0,0 +1,7 @@
+<host-apdu-service xmlns:android="http://schemas.android.com/apk/res/android"
+    android:description="@string/SecondPaymentService">
+    <aid-group android:description="@string/SecondPaymentService" android:category="payment">
+        <aid-filter android:name="A000000004101011"/>
+    </aid-group>
+    <polling-loop-filter android:name="48294018"/>
+</host-apdu-service>
diff --git a/tests/testcases/src/android/nfc/test/CustomHostApduService.java b/tests/testcases/src/android/nfc/test/CustomHostApduService.java
new file mode 100644
index 00000000..31edcd50
--- /dev/null
+++ b/tests/testcases/src/android/nfc/test/CustomHostApduService.java
@@ -0,0 +1,56 @@
+/*
+ * Copyright (C) 2023 The Android Open Source Project
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
+package android.nfc.test;
+
+import static android.nfc.test.TestUtils.sCurrentCommandApduProcessor;
+import static android.nfc.test.TestUtils.sCurrentPollLoopReceiver;
+
+import android.nfc.cardemulation.*;
+import android.nfc.cardemulation.PollingFrame;
+import android.os.Bundle;
+import java.util.List;
+
+public class CustomHostApduService extends HostApduService {
+  static final String POLLING_LOOP_RECEIVED_ACTION = "CTS_NFC_POLLING_LOOP";
+  static final String SERVICE_NAME_EXTRA = "CTS_NFC_SERVICE_NAME_EXTRA";
+  static final String POLLING_FRAMES_EXTRA = "CTS_NFC_POLLING_FRAMES_EXTRA";
+
+  public void ctsNotifyUnhandled() {
+    return;
+  }
+
+  @Override
+  public byte[] processCommandApdu(byte[] apdu, Bundle extras) {
+    if (sCurrentCommandApduProcessor != null) {
+      return sCurrentCommandApduProcessor.processCommandApdu(this.getClass().getName(),
+          apdu, extras);
+    }
+    return new byte[0];
+  }
+
+  @Override
+  public void onDeactivated(int reason) {
+    return;
+  }
+
+  @Override
+  public void processPollingFrames(List<PollingFrame> frames) {
+    if (sCurrentPollLoopReceiver != null) {
+      sCurrentPollLoopReceiver.notifyPollingLoop(this.getClass().getName(), frames);
+    }
+  }
+}
diff --git a/tests/testcases/src/android/nfc/test/ForegroundHceActivity.java b/tests/testcases/src/android/nfc/test/ForegroundHceActivity.java
new file mode 100644
index 00000000..6623f9a1
--- /dev/null
+++ b/tests/testcases/src/android/nfc/test/ForegroundHceActivity.java
@@ -0,0 +1,31 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+package android.nfc.test;
+
+import android.app.Activity;
+
+public class ForegroundHceActivity extends Activity {
+  public Runnable mOnPauseRunnable = null;
+
+  public void onPause() {
+    super.onPause();
+
+    if (mOnPauseRunnable != null) {
+      mOnPauseRunnable.run();
+    }
+  }
+}
diff --git a/tests/testcases/src/android/nfc/test/NfcFCardEmulationActivity.java b/tests/testcases/src/android/nfc/test/NfcFCardEmulationActivity.java
new file mode 100644
index 00000000..a5e4aa31
--- /dev/null
+++ b/tests/testcases/src/android/nfc/test/NfcFCardEmulationActivity.java
@@ -0,0 +1,21 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+package android.nfc.test;
+
+import android.app.Activity;
+
+public class NfcFCardEmulationActivity extends Activity {}
diff --git a/tests/testcases/src/android/nfc/test/ObserveModeTests.java b/tests/testcases/src/android/nfc/test/ObserveModeTests.java
new file mode 100644
index 00000000..e364c182
--- /dev/null
+++ b/tests/testcases/src/android/nfc/test/ObserveModeTests.java
@@ -0,0 +1,312 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+package android.nfc.test;
+
+import static android.nfc.test.TestUtils.createAndResumeActivity;
+import static android.nfc.test.TestUtils.createFrame;
+import static android.nfc.test.TestUtils.createFrameWithData;
+import static android.nfc.test.TestUtils.notifyPollingLoopAndWait;
+import static android.nfc.test.TestUtils.supportsHardware;
+import static org.junit.Assert.assertArrayEquals;
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.assertNotNull;
+import static org.junit.Assert.assertTrue;
+import static org.junit.Assume.assumeTrue;
+
+import android.app.Activity;
+import android.app.Instrumentation;
+import android.content.ComponentName;
+import android.content.Context;
+import android.nfc.NfcAdapter;
+import android.nfc.cardemulation.CardEmulation;
+import android.nfc.cardemulation.PollingFrame;
+import android.os.Bundle;
+import android.os.RemoteException;
+import android.platform.test.annotations.RequiresFlagsEnabled;
+import android.util.Log;
+import androidx.test.platform.app.InstrumentationRegistry;
+import java.util.ArrayList;
+import java.util.List;
+import java.util.concurrent.CountDownLatch;
+import java.util.concurrent.TimeUnit;
+import java.util.concurrent.atomic.AtomicBoolean;
+import org.junit.Before;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
+@RunWith(JUnit4.class)
+public class ObserveModeTests {
+  private Context mContext;
+  final int STRESS_TEST_DURATION = 10000;
+
+  @Before
+  public void setUp() throws NoSuchFieldException, RemoteException {
+    assumeTrue(supportsHardware());
+    mContext = InstrumentationRegistry.getInstrumentation().getContext();
+  }
+
+  @Test(timeout = 20000)
+  @RequiresFlagsEnabled(android.nfc.Flags.FLAG_NFC_OBSERVE_MODE)
+  public void testObserveModeStress() throws InterruptedException {
+    final NfcAdapter adapter = initNfcAdapterWithObserveModeOrSkipTest();
+    CardEmulation cardEmulation = CardEmulation.getInstance(adapter);
+    try {
+      Activity activity = createAndResumeActivity();
+      cardEmulation.setShouldDefaultToObserveModeForService(
+          new ComponentName(mContext, CustomHostApduService.class), true);
+      assertTrue(
+          cardEmulation.setPreferredService(
+              activity, new ComponentName(mContext, CustomHostApduService.class)));
+      TestUtils.ensurePreferredService(CustomHostApduService.class, mContext);
+      long stop = System.currentTimeMillis() + STRESS_TEST_DURATION;
+      Thread thread1 =
+          new Thread() {
+            @Override
+            public void run() {
+              while (System.currentTimeMillis() < stop) {
+                assertTrue(adapter.setObserveModeEnabled(true));
+              }
+            }
+          };
+
+      Thread thread2 =
+          new Thread() {
+            @Override
+            public void run() {
+              while (System.currentTimeMillis() < stop) {
+                assertTrue(adapter.setObserveModeEnabled(false));
+              }
+            }
+          };
+      thread1.start();
+      thread2.start();
+      thread1.join();
+      thread2.join();
+
+    } finally {
+      cardEmulation.setShouldDefaultToObserveModeForService(
+          new ComponentName(mContext, CustomHostApduService.class), false);
+    }
+  }
+
+  @Test
+  @RequiresFlagsEnabled(android.nfc.Flags.FLAG_NFC_OBSERVE_MODE)
+  public void testInterleavePlfAndAid() {
+    final NfcAdapter adapter = initNfcAdapterWithObserveModeOrSkipTest();
+    adapter.notifyHceDeactivated();
+    CardEmulation cardEmulation = CardEmulation.getInstance(adapter);
+    try {
+      Activity activity = createAndResumeActivity();
+      cardEmulation.setShouldDefaultToObserveModeForService(
+          new ComponentName(mContext, CustomHostApduService.class), true);
+      assertTrue(cardEmulation.setPreferredService(
+              activity, new ComponentName(mContext, CustomHostApduService.class)));
+      TestUtils.ensurePreferredService(CustomHostApduService.class, mContext);
+      ArrayList<PollingFrame> frames = new ArrayList<PollingFrame>(6);
+      frames.add(createFrame(PollingFrame.POLLING_LOOP_TYPE_ON));
+      frames.add(createFrame(PollingFrame.POLLING_LOOP_TYPE_A));
+      frames.add(createFrame(PollingFrame.POLLING_LOOP_TYPE_OFF));
+      frames.add(createFrame(PollingFrame.POLLING_LOOP_TYPE_ON));
+      frames.add(createFrame(PollingFrame.POLLING_LOOP_TYPE_A));
+      frames.add(createFrame(PollingFrame.POLLING_LOOP_TYPE_OFF));
+      notifyPollingLoopAndWait(
+          new ArrayList<PollingFrame>(frames), CustomHostApduService.class.getName());
+      byte[] selectAidCmd =
+          new byte[] {
+            0x00, (byte) 0xa4, 0x04, 0x00, (byte) 0xA0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10, 0x18
+          };
+
+      TestUtils.sCurrentCommandApduProcessor =
+          new TestUtils.CommandApduProcessor() {
+            @Override
+            public byte[] processCommandApdu(String serviceName, byte[] apdu, Bundle extras) {
+              assertEquals(serviceName, CustomHostApduService.class.getName());
+              assertArrayEquals(apdu, selectAidCmd);
+              return new byte[0];
+            }
+          };
+      adapter.notifyTestHceData(1, selectAidCmd);
+      notifyPollingLoopAndWait(
+          new ArrayList<PollingFrame>(frames), CustomHostApduService.class.getName());
+
+      byte[] nextCommandApdu = new byte[] {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
+      TestUtils.sCurrentCommandApduProcessor =
+          new TestUtils.CommandApduProcessor() {
+            @Override
+            public byte[] processCommandApdu(String serviceName, byte[] apdu, Bundle extras) {
+              assertEquals(serviceName, CustomHostApduService.class.getName());
+              assertArrayEquals(apdu, nextCommandApdu);
+              return new byte[0];
+            }
+          };
+      adapter.notifyTestHceData(1, nextCommandApdu);
+    } finally {
+      cardEmulation.setShouldDefaultToObserveModeForService(
+          new ComponentName(mContext, CustomHostApduService.class), false);
+      adapter.notifyHceDeactivated();
+    }
+  }
+
+  @Test
+  @RequiresFlagsEnabled(android.nfc.Flags.FLAG_NFC_OBSERVE_MODE)
+  public void testInterleavePlfSecondServiceAndAid() {
+    final NfcAdapter adapter = initNfcAdapterWithObserveModeOrSkipTest();
+    adapter.notifyHceDeactivated();
+    CardEmulation cardEmulation = CardEmulation.getInstance(adapter);
+    try {
+      Activity activity = createAndResumeActivity();
+      cardEmulation.setShouldDefaultToObserveModeForService(
+          new ComponentName(mContext, CustomHostApduService.class), true);
+      assertTrue(
+          cardEmulation.setPreferredService(
+              activity, new ComponentName(mContext, CustomHostApduService.class)));
+      TestUtils.ensurePreferredService(CustomHostApduService.class, mContext);
+      ArrayList<PollingFrame> frames = new ArrayList<PollingFrame>(6);
+      frames.add(createFrame(PollingFrame.POLLING_LOOP_TYPE_ON));
+      frames.add(createFrame(PollingFrame.POLLING_LOOP_TYPE_A));
+      frames.add(createFrame(PollingFrame.POLLING_LOOP_TYPE_OFF));
+      frames.add(createFrame(PollingFrame.POLLING_LOOP_TYPE_ON));
+      frames.add(createFrame(PollingFrame.POLLING_LOOP_TYPE_A));
+      frames.add(createFrame(PollingFrame.POLLING_LOOP_TYPE_OFF));
+      notifyPollingLoopAndWait(
+          new ArrayList<PollingFrame>(frames), CustomHostApduService.class.getName());
+      byte[] selectAidCmd =
+          new byte[] {
+            0x00, (byte) 0xa4, 0x04, 0x00, (byte) 0xA0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10, 0x18
+          };
+
+      TestUtils.sCurrentCommandApduProcessor =
+          new TestUtils.CommandApduProcessor() {
+            @Override
+            public byte[] processCommandApdu(String serviceName, byte[] apdu, Bundle extras) {
+              assertEquals(serviceName, CustomHostApduService.class.getName());
+              assertArrayEquals(apdu, selectAidCmd);
+              return new byte[0];
+            }
+          };
+      adapter.notifyTestHceData(1, selectAidCmd);
+      ArrayList<PollingFrame> oneFrame = new ArrayList<PollingFrame>(6);
+      oneFrame.add(
+          createFrameWithData(
+              PollingFrame.POLLING_LOOP_TYPE_UNKNOWN, new byte[] {0x48, 0x29, 0x40, 0x18}));
+      notifyPollingLoopAndWait(
+          new ArrayList<PollingFrame>(oneFrame), SecondHostApduService.class.getName());
+
+      byte[] nextCommandApdu = new byte[] {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
+      TestUtils.sCurrentCommandApduProcessor =
+          new TestUtils.CommandApduProcessor() {
+            @Override
+            public byte[] processCommandApdu(String serviceName, byte[] apdu, Bundle extras) {
+              assertEquals(serviceName, CustomHostApduService.class.getName());
+              assertArrayEquals(apdu, nextCommandApdu);
+              return new byte[0];
+            }
+          };
+      adapter.notifyTestHceData(1, nextCommandApdu);
+    } finally {
+      cardEmulation.setShouldDefaultToObserveModeForService(
+          new ComponentName(mContext, CustomHostApduService.class), false);
+      adapter.notifyHceDeactivated();
+    }
+  }
+
+  /**
+   * A regression test for a HostEmulationManager deadlock as seen in b/361084133.
+   */
+  @Test
+  @RequiresFlagsEnabled(android.nfc.Flags.FLAG_NFC_OBSERVE_MODE)
+  public void testOnPauseAndOnResume() throws InterruptedException {
+    final NfcAdapter adapter = initNfcAdapterWithObserveModeOrSkipTest();
+    final CardEmulation cardEmulation = CardEmulation.getInstance(adapter);
+    boolean nfcIsProbablyStuck = true;
+
+    try {
+      Instrumentation instrumentation = InstrumentationRegistry.getInstrumentation();
+
+      for (int i = 0; i < 5; i++) {
+        final ForegroundHceActivity activity =
+            (ForegroundHceActivity)createAndResumeActivity(ForegroundHceActivity.class);
+
+        AtomicBoolean setPreferredServiceResult = new AtomicBoolean(false);
+
+        runInAThreadInCaseItLocksUp("could not set preferred service", () -> {
+          setPreferredServiceResult.set(cardEmulation.setPreferredService(
+                  activity, new ComponentName(mContext, CustomHostApduService.class)));
+        });
+        assertTrue("Could not set preferred service", setPreferredServiceResult.get());
+
+        TestUtils.ensurePreferredService(CustomHostApduService.class, mContext);
+
+        AtomicBoolean setObserveModeResult = new AtomicBoolean(false);
+        runInAThreadInCaseItLocksUp("could not enable observe mode", () -> {
+          setObserveModeResult.set(adapter.setObserveModeEnabled(true));
+        });
+        assertTrue("Could not enable observe mode", setObserveModeResult.get());
+
+        CountDownLatch onPauseLatch = new CountDownLatch(1);
+        Thread disableObserveModeThread = new Thread() {
+          @Override
+          public void run() {
+            adapter.setObserveModeEnabled(false);
+          }
+        };
+        activity.mOnPauseRunnable = () -> {
+          disableObserveModeThread.start();
+          onPauseLatch.countDown();
+        };
+
+        instrumentation.runOnMainSync(() -> {
+          activity.finish();
+        });
+
+        assertTrue(onPauseLatch.await(1000, TimeUnit.MILLISECONDS));
+        disableObserveModeThread.interrupt();
+      }
+      nfcIsProbablyStuck = false;
+    } finally {
+      if (nfcIsProbablyStuck) {
+        Log.w("ObserveModeTests", "NFC is probably stuck, restarting...");
+        TestUtils.killNfcService();
+      }
+    }
+  }
+
+  private void runInAThreadInCaseItLocksUp(String message, Runnable runnable)
+      throws InterruptedException {
+    Thread thread = new Thread(runnable);
+    thread.start();
+    thread.join(1000);
+    // if it doesn't finish in 1s, it's probably stuck
+    assertFalse(message, thread.isAlive());
+    thread.interrupt();
+  }
+
+  private NfcAdapter initNfcAdapterWithObserveModeOrSkipTest() {
+    assertNotNull(mContext);
+    final NfcAdapter adapter = NfcAdapter.getDefaultAdapter(mContext);
+    assertNotNull(adapter);
+    assumeTrue(adapter.isObserveModeSupported());
+
+    return adapter;
+  }
+
+  List<PollingFrame> notifyPollingLoopAndWait(ArrayList<PollingFrame> frames, String serviceName) {
+    return TestUtils.notifyPollingLoopAndWait(frames, serviceName, mContext);
+  }
+}
diff --git a/tests/testcases/src/android/nfc/test/SecondHostApduService.java b/tests/testcases/src/android/nfc/test/SecondHostApduService.java
new file mode 100644
index 00000000..7f57007e
--- /dev/null
+++ b/tests/testcases/src/android/nfc/test/SecondHostApduService.java
@@ -0,0 +1,56 @@
+/*
+ * Copyright (C) 2023 The Android Open Source Project
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
+package android.nfc.test;
+
+import static android.nfc.test.TestUtils.sCurrentCommandApduProcessor;
+import static android.nfc.test.TestUtils.sCurrentPollLoopReceiver;
+
+import android.nfc.cardemulation.*;
+import android.nfc.cardemulation.PollingFrame;
+import android.os.Bundle;
+import java.util.List;
+
+public class SecondHostApduService extends HostApduService {
+  static final String POLLING_LOOP_RECEIVED_ACTION = "CTS_NFC_POLLING_LOOP";
+  static final String SERVICE_NAME_EXTRA = "CTS_NFC_SERVICE_NAME_EXTRA";
+  static final String POLLING_FRAMES_EXTRA = "CTS_NFC_POLLING_FRAMES_EXTRA";
+
+  public void ctsNotifyUnhandled() {
+    return;
+  }
+
+  @Override
+  public byte[] processCommandApdu(byte[] apdu, Bundle extras) {
+    if (sCurrentCommandApduProcessor != null) {
+      return sCurrentCommandApduProcessor.processCommandApdu(this.getClass().getName(),
+          apdu, extras);
+    }
+    return new byte[0];
+  }
+
+  @Override
+  public void onDeactivated(int reason) {
+    return;
+  }
+
+  @Override
+  public void processPollingFrames(List<PollingFrame> frames) {
+    if (sCurrentPollLoopReceiver != null) {
+      sCurrentPollLoopReceiver.notifyPollingLoop(this.getClass().getName(), frames);
+    }
+  }
+}
diff --git a/tests/testcases/src/android/nfc/test/TestUtils.java b/tests/testcases/src/android/nfc/test/TestUtils.java
new file mode 100644
index 00000000..762ab51d
--- /dev/null
+++ b/tests/testcases/src/android/nfc/test/TestUtils.java
@@ -0,0 +1,218 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+package android.nfc.test;
+
+import static org.junit.Assume.assumeFalse;
+
+import android.app.Activity;
+import android.app.Instrumentation;
+import android.app.KeyguardManager;
+import android.content.Context;
+import android.content.Intent;
+import android.content.pm.PackageManager;
+import android.nfc.NfcAdapter;
+import android.nfc.cardemulation.CardEmulation;
+import android.nfc.cardemulation.PollingFrame;
+import android.nfc.cardemulation.PollingFrame.PollingFrameType;
+import android.os.Bundle;
+import android.os.PowerManager;
+import android.os.UserManager;
+import android.util.Log;
+import android.view.KeyEvent;
+import androidx.test.core.app.ApplicationProvider;
+import androidx.test.platform.app.InstrumentationRegistry;
+import com.android.compatibility.common.util.CommonTestUtils;
+import com.android.compatibility.common.util.SystemUtil;
+import java.util.ArrayList;
+import java.util.List;
+import org.junit.Assert;
+
+public class TestUtils {
+  static boolean supportsHardware() {
+    final PackageManager pm = InstrumentationRegistry.getInstrumentation().getContext()
+        .getPackageManager();
+    return pm.hasSystemFeature(PackageManager.FEATURE_NFC_HOST_CARD_EMULATION);
+  }
+
+  static Activity createAndResumeActivity() {
+    return createAndResumeActivity(NfcFCardEmulationActivity.class);
+  }
+
+  static Activity createAndResumeActivity(Class<? extends Activity> activityClass) {
+    ensureUnlocked();
+    Intent intent = new Intent(ApplicationProvider.getApplicationContext(), activityClass);
+    intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
+    Activity activity = InstrumentationRegistry.getInstrumentation().startActivitySync(intent);
+    InstrumentationRegistry.getInstrumentation().callActivityOnResume(activity);
+
+    return activity;
+  }
+
+  static void ensurePreferredService(Class serviceClass, Context context) {
+    NfcAdapter adapter = NfcAdapter.getDefaultAdapter(context);
+    final CardEmulation cardEmulation = CardEmulation.getInstance(adapter);
+    int resId =
+        serviceClass == CustomHostApduService.class
+            ? android.nfc.test.R.string.CustomPaymentService
+            : -1;
+    final String desc = context.getResources().getString(resId);
+    ensurePreferredService(desc, context);
+  }
+
+  static void ensureUnlocked() {
+    final Context context = InstrumentationRegistry.getInstrumentation().getContext();
+    final UserManager userManager = context.getSystemService(UserManager.class);
+    assumeFalse(userManager.isHeadlessSystemUserMode());
+    final Instrumentation instrumentation = InstrumentationRegistry.getInstrumentation();
+    final PowerManager pm = context.getSystemService(PowerManager.class);
+    final KeyguardManager km = context.getSystemService(KeyguardManager.class);
+    try {
+      if (pm != null && !pm.isInteractive()) {
+        SystemUtil.runShellCommand("input keyevent KEYCODE_WAKEUP");
+        CommonTestUtils.waitUntil(
+            "Device does not wake up after 5 seconds", 5, () -> pm != null && pm.isInteractive());
+      }
+      if (km != null && km.isKeyguardLocked()) {
+        CommonTestUtils.waitUntil(
+            "Device does not unlock after 30 seconds",
+            30,
+            () -> {
+              SystemUtil.runWithShellPermissionIdentity(
+                  () -> instrumentation.sendKeyDownUpSync((KeyEvent.KEYCODE_MENU)));
+              return km != null && !km.isKeyguardLocked();
+            });
+      }
+    } catch (InterruptedException ie) {
+    }
+  }
+
+  static void ensurePreferredService(String serviceDesc, Context context) {
+    NfcAdapter adapter = NfcAdapter.getDefaultAdapter(context);
+    final CardEmulation cardEmulation = CardEmulation.getInstance(adapter);
+    try {
+      CommonTestUtils.waitUntil(
+          "Default service hasn't updated",
+          6,
+          () -> serviceDesc.equals(cardEmulation.getDescriptionForPreferredPaymentService()));
+    } catch (InterruptedException ie) {
+    }
+  }
+
+  static PollLoopReceiver sCurrentPollLoopReceiver = null;
+
+  static class PollLoopReceiver {
+    int mFrameIndex = 0;
+    ArrayList<PollingFrame> mFrames;
+    String mServiceName;
+    ArrayList<PollingFrame> mReceivedFrames;
+    String mReceivedServiceName;
+    ArrayList<String> mReceivedServiceNames;
+
+    PollLoopReceiver(ArrayList<PollingFrame> frames, String serviceName) {
+      mFrames = frames;
+      mServiceName = serviceName;
+      mReceivedFrames = new ArrayList<PollingFrame>();
+      mReceivedServiceNames = new ArrayList<String>();
+    }
+
+    void notifyPollingLoop(String className, List<PollingFrame> receivedFrames) {
+      if (receivedFrames == null) {
+        return;
+      }
+      mReceivedFrames.addAll(receivedFrames);
+      mReceivedServiceName = className;
+      mReceivedServiceNames.add(className);
+      if (mReceivedFrames.size() < mFrames.size()) {
+        return;
+      }
+      synchronized (this) {
+        this.notify();
+      }
+    }
+
+    void test() {
+      if (mReceivedFrames.size() > mFrames.size()) {
+        Assert.fail("received more frames than sent");
+      } else if (mReceivedFrames.size() < mFrames.size()) {
+        Assert.fail("received fewer frames than sent");
+      }
+      for (PollingFrame receivedFrame : mReceivedFrames) {
+        Assert.assertEquals(mFrames.get(mFrameIndex).getType(), receivedFrame.getType());
+        Assert.assertEquals(
+            mFrames.get(mFrameIndex).getVendorSpecificGain(),
+            receivedFrame.getVendorSpecificGain());
+        Assert.assertEquals(mFrames.get(mFrameIndex).getTimestamp(), receivedFrame.getTimestamp());
+        Assert.assertArrayEquals(mFrames.get(mFrameIndex).getData(), receivedFrame.getData());
+        mFrameIndex++;
+      }
+      if (mServiceName != null) {
+        Assert.assertEquals(mServiceName, mReceivedServiceName);
+      }
+    }
+  }
+
+  static List<PollingFrame> notifyPollingLoopAndWait(
+      ArrayList<PollingFrame> frames, String serviceName, Context context) {
+    NfcAdapter adapter = NfcAdapter.getDefaultAdapter(context);
+    sCurrentPollLoopReceiver = new PollLoopReceiver(frames, serviceName);
+    for (PollingFrame frame : frames) {
+      adapter.notifyPollingLoop(frame);
+    }
+    synchronized (sCurrentPollLoopReceiver) {
+      try {
+        sCurrentPollLoopReceiver.wait(5000);
+      } catch (InterruptedException ie) {
+        Assert.assertNull(ie);
+      }
+    }
+    sCurrentPollLoopReceiver.test();
+    Assert.assertEquals(frames.size(), sCurrentPollLoopReceiver.mFrameIndex);
+    List<PollingFrame> receivedFrames = sCurrentPollLoopReceiver.mReceivedFrames;
+    sCurrentPollLoopReceiver = null;
+    return receivedFrames;
+  }
+
+  static PollingFrame createFrame(@PollingFrameType int type) {
+    if (type == PollingFrame.POLLING_LOOP_TYPE_ON || type == PollingFrame.POLLING_LOOP_TYPE_OFF) {
+      return new PollingFrame(
+          type,
+          new byte[] {((type == PollingFrame.POLLING_LOOP_TYPE_ON) ? (byte) 0x01 : (byte) 0x00)},
+          8,
+          0,
+          false);
+    }
+    return new PollingFrame(type, null, 8, 0, false);
+  }
+
+  static PollingFrame createFrameWithData(@PollingFrameType int type, byte[] data) {
+    return new PollingFrame(type, data, 8, (long) Integer.MAX_VALUE + 1L, false);
+  }
+
+  public abstract static class CommandApduProcessor {
+    public abstract byte[] processCommandApdu(String serviceName, byte[] apdu, Bundle extras);
+  }
+
+  static CommandApduProcessor sCurrentCommandApduProcessor = null;
+
+  public static void killNfcService() {
+    Log.w(TAG, "Attempting to kill the NFC service...");
+
+    SystemUtil.runShellCommand("killall com.android.nfc");
+  }
+
+  private static final String TAG = "TestUtils";
+}
diff --git a/tests/unit/Android.bp b/tests/unit/Android.bp
index 0c2efc9f..6522f21a 100644
--- a/tests/unit/Android.bp
+++ b/tests/unit/Android.bp
@@ -9,9 +9,9 @@ android_test {
     certificate: "platform",
 
     libs: [
-        "android.test.runner",
-        "android.test.base",
-        "android.test.mock",
+        "android.test.runner.stubs.system",
+        "android.test.base.stubs.system",
+        "android.test.mock.stubs.system",
         "framework-nfc.impl",
         "unsupportedappusage",
     ],
diff --git a/tests/unit/AndroidTest.xml b/tests/unit/AndroidTest.xml
index f5ab09b8..428d05d4 100644
--- a/tests/unit/AndroidTest.xml
+++ b/tests/unit/AndroidTest.xml
@@ -31,4 +31,8 @@
         <option name="hidden-api-checks" value="false"/>
         <option name="test-filter-dir" value="/data/data/com.android.nfc.tests.unit" />
     </test>
+    <object type="module_controller"
+            class="com.android.tradefed.testtype.suite.module.DeviceFeatureModuleController">
+        <option name="required-feature" value="android.hardware.nfc.any" />
+    </object>
 </configuration>
diff --git a/tests/unit/src/com/android/nfc/AidRoutingManagerTest.java b/tests/unit/src/com/android/nfc/AidRoutingManagerTest.java
index 845d59c2..cdb0a1e3 100644
--- a/tests/unit/src/com/android/nfc/AidRoutingManagerTest.java
+++ b/tests/unit/src/com/android/nfc/AidRoutingManagerTest.java
@@ -45,7 +45,6 @@ import java.util.Map;
 public class AidRoutingManagerTest {
 
     private static final String TAG = AidRoutingManagerTest.class.getSimpleName();
-    private boolean mNfcSupported;
     private MockitoSession mStaticMockSession;
     private AidRoutingManager mAidRoutingManager;
 
@@ -57,15 +56,6 @@ public class AidRoutingManagerTest {
                 .mockStatic(NfcStatsLog.class)
                 .strictness(Strictness.LENIENT)
                 .startMocking();
-
-        Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
-        PackageManager pm = context.getPackageManager();
-        if (!pm.hasSystemFeature(PackageManager.FEATURE_NFC_ANY)) {
-            mNfcSupported = false;
-            return;
-        }
-        mNfcSupported = true;
-
         RoutingOptionManager routingOptionManager = mock(RoutingOptionManager.class);
         when(RoutingOptionManager.getInstance()).thenReturn(routingOptionManager);
         InstrumentationRegistry.getInstrumentation().runOnMainSync(
@@ -80,8 +70,6 @@ public class AidRoutingManagerTest {
 
     @Test
     public void testCalculateAidRouteSize() {
-        if (!mNfcSupported) return;
-
         HashMap<String, AidRoutingManager.AidEntry> aidEntryMap = new HashMap<>();
         int size = mAidRoutingManager.calculateAidRouteSize(aidEntryMap);
         Assert.assertEquals(0, size);
@@ -93,8 +81,6 @@ public class AidRoutingManagerTest {
 
     @Test
     public void testOnNfccRoutingTableCleared() {
-        if (!mNfcSupported) return;
-
         mAidRoutingManager.onNfccRoutingTableCleared();
         boolean isTableCleared = mAidRoutingManager.isRoutingTableCleared();
         Assert.assertTrue(isTableCleared);
@@ -102,24 +88,18 @@ public class AidRoutingManagerTest {
 
     @Test
     public void testSupportsAidPrefixRouting() {
-        if (!mNfcSupported) return;
-
         boolean isSupportPrefixRouting = mAidRoutingManager.supportsAidPrefixRouting();
         Assert.assertFalse(isSupportPrefixRouting);
     }
 
     @Test
     public void testSupportsAidSubsetRouting() {
-        if (!mNfcSupported) return;
-
         boolean isSupportSubsetRouting = mAidRoutingManager.supportsAidSubsetRouting();
         Assert.assertFalse(isSupportSubsetRouting);
     }
 
     @Test
     public void testConfigureRoutingErrorOccurred() {
-        if (!mNfcSupported) return;
-
         NfcService nfcService = mock(NfcService.class);
         when(NfcService.getInstance()).thenReturn(nfcService);
         when(nfcService.getNciVersion()).thenReturn(NfcService.NCI_VERSION_2_0);
@@ -135,8 +115,6 @@ public class AidRoutingManagerTest {
 
     @Test
     public void testConfigureRouting() {
-        if (!mNfcSupported) return;
-
         NfcService nfcService = mock(NfcService.class);
         when(NfcService.getInstance()).thenReturn(nfcService);
         when(nfcService.getNciVersion()).thenReturn(NfcService.NCI_VERSION_2_0);
@@ -150,4 +128,4 @@ public class AidRoutingManagerTest {
                 0,
                 0));
     }
-}
\ No newline at end of file
+}
diff --git a/tests/unit/src/com/android/nfc/DeviceConfigFacadeTest.java b/tests/unit/src/com/android/nfc/DeviceConfigFacadeTest.java
index b6574a0c..85ca9eac 100644
--- a/tests/unit/src/com/android/nfc/DeviceConfigFacadeTest.java
+++ b/tests/unit/src/com/android/nfc/DeviceConfigFacadeTest.java
@@ -45,7 +45,6 @@ import com.android.dx.mockito.inline.extended.ExtendedMockito;
 public class DeviceConfigFacadeTest {
 
     private static final String TAG = DeviceConfigFacadeTest.class.getSimpleName();
-    private boolean mNfcSupported;
     private MockitoSession mStaticMockSession;
     private DeviceConfigFacade mDeviceConfigFacade;
     private DeviceConfigFacade mDeviceConfigFacadeFalse;
@@ -55,14 +54,7 @@ public class DeviceConfigFacadeTest {
         mStaticMockSession = ExtendedMockito.mockitoSession()
                 .strictness(Strictness.LENIENT)
                 .startMocking();
-
         Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
-        PackageManager pm = context.getPackageManager();
-        if (!pm.hasSystemFeature(PackageManager.FEATURE_NFC_ANY)) {
-            mNfcSupported = false;
-            return;
-        }
-        mNfcSupported = true;
         Handler handler = mock(Handler.class);
         InstrumentationRegistry.getInstrumentation().runOnMainSync(
                 () -> mDeviceConfigFacade = new DeviceConfigFacade(getMockedContext(
@@ -97,8 +89,6 @@ public class DeviceConfigFacadeTest {
 
     @Test
     public void testIsAntennaBlockedAlertEnabled() {
-        if (!mNfcSupported) return;
-
         boolean isAlertEnabled = mDeviceConfigFacade.isAntennaBlockedAlertEnabled();
         Log.d(TAG, "isAlertEnabled -" + isAlertEnabled);
         Assert.assertTrue(isAlertEnabled);
@@ -106,8 +96,6 @@ public class DeviceConfigFacadeTest {
 
     @Test
     public void testIsAntennaBlockedAlertDisabled() {
-        if (!mNfcSupported) return;
-
         boolean isAlertEnabled = mDeviceConfigFacadeFalse.isAntennaBlockedAlertEnabled();
         Log.d(TAG, "isAlertEnabled -" + isAlertEnabled);
         Assert.assertFalse(isAlertEnabled);
diff --git a/tests/unit/src/com/android/nfc/DtaServiceConnectorTest.java b/tests/unit/src/com/android/nfc/DtaServiceConnectorTest.java
index 5ebad895..6172b073 100644
--- a/tests/unit/src/com/android/nfc/DtaServiceConnectorTest.java
+++ b/tests/unit/src/com/android/nfc/DtaServiceConnectorTest.java
@@ -59,7 +59,6 @@ import java.util.List;
 public class DtaServiceConnectorTest {
 
     private static final String TAG = DtaServiceConnectorTest.class.getSimpleName();
-    private boolean mNfcSupported;
     private MockitoSession mStaticMockSession;
     private Context mockContext;
     private DtaServiceConnector mDtaServiceConnector;
@@ -70,15 +69,7 @@ public class DtaServiceConnectorTest {
         mStaticMockSession = ExtendedMockito.mockitoSession()
                 .strictness(Strictness.LENIENT)
                 .startMocking();
-
         Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
-        PackageManager pm = context.getPackageManager();
-        if (!pm.hasSystemFeature(PackageManager.FEATURE_NFC_ANY)) {
-            mNfcSupported = false;
-            return;
-        }
-        mNfcSupported = true;
-
         Resources mockResources = Mockito.mock(Resources.class);
         when(mockResources.getBoolean(eq(R.bool.tag_intent_app_pref_supported)))
                 .thenReturn(false);
@@ -129,8 +120,6 @@ public class DtaServiceConnectorTest {
 
     @Test
     public void testCreateExplicitFromImplicitIntent() {
-        if (!mNfcSupported) return;
-
         Intent intent = DtaServiceConnector.createExplicitFromImplicitIntent(mockContext,
                 implicitIntent);
         Assert.assertNotNull(intent);
@@ -138,4 +127,4 @@ public class DtaServiceConnectorTest {
         Assert.assertNotNull(componentName);
         Assert.assertEquals("com.android.nfc", componentName.getPackageName());
     }
-}
\ No newline at end of file
+}
diff --git a/tests/unit/src/com/android/nfc/EnableNfcFServiceTest.java b/tests/unit/src/com/android/nfc/EnableNfcFServiceTest.java
index bdd5f45e..d6524e21 100644
--- a/tests/unit/src/com/android/nfc/EnableNfcFServiceTest.java
+++ b/tests/unit/src/com/android/nfc/EnableNfcFServiceTest.java
@@ -51,7 +51,6 @@ import org.mockito.quality.Strictness;
 public class EnableNfcFServiceTest {
 
     private static final String TAG = EnableNfcFServiceTest.class.getSimpleName();
-    private boolean mNfcSupported;
     private MockitoSession mStaticMockSession;
     private ComponentName mComponentName;
     private NfcFServiceInfo mNfcFServiceInfo;
@@ -68,17 +67,8 @@ public class EnableNfcFServiceTest {
                 .mockStatic(ForegroundUtils.class)
                 .strictness(Strictness.LENIENT)
                 .startMocking();
-
         Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
-        PackageManager pm = context.getPackageManager();
-        if (!pm.hasSystemFeature(PackageManager.FEATURE_NFC_ANY)) {
-            mNfcSupported = false;
-            return;
-        }
-        mNfcSupported = true;
-
         Context mockContext = new ContextWrapper(context) {
-
         };
 
         mForegroundUtils = mock(ForegroundUtils.class);
@@ -112,8 +102,6 @@ public class EnableNfcFServiceTest {
 
     @Test
     public void testOnHostEmulationActivated() {
-        if (!mNfcSupported) return;
-
         boolean isActivated = mEnabledNfcFServices.isActivated();
         Assert.assertFalse(isActivated);
         mEnabledNfcFServices.onHostEmulationActivated();
@@ -123,8 +111,6 @@ public class EnableNfcFServiceTest {
 
     @Test
     public void testOnHostEmulationDeactivated() {
-        if (!mNfcSupported) return;
-
         mEnabledNfcFServices.onHostEmulationActivated();
         boolean isActivated = mEnabledNfcFServices.isActivated();
         Assert.assertTrue(isActivated);
@@ -135,8 +121,6 @@ public class EnableNfcFServiceTest {
 
     @Test
     public void testRegisterEnabledForegroundService() {
-        if (!mNfcSupported) return;
-
         UserHandle userHandle = mock(UserHandle.class);
         when(userHandle.getIdentifier()).thenReturn(1);
         when(UserHandle.getUserHandleForUid(1)).thenReturn(userHandle);
@@ -153,8 +137,6 @@ public class EnableNfcFServiceTest {
 
     @Test
     public void testOnNfcDisabled() {
-        if (!mNfcSupported) return;
-
         mEnabledNfcFServices.onNfcDisabled();
         boolean isNfcDisabled = mEnabledNfcFServices.isNfcDisabled();
         Assert.assertTrue(isNfcDisabled);
@@ -162,8 +144,6 @@ public class EnableNfcFServiceTest {
 
     @Test
     public void testOnUserSwitched() {
-        if (!mNfcSupported) return;
-
         mEnabledNfcFServices.onUserSwitched(0);
         boolean isUserSwitched = mEnabledNfcFServices.isUserSwitched();
         Assert.assertTrue(isUserSwitched);
diff --git a/tests/unit/src/com/android/nfc/ForegroundUtilsTest.java b/tests/unit/src/com/android/nfc/ForegroundUtilsTest.java
index 1caef0ef..e0276145 100644
--- a/tests/unit/src/com/android/nfc/ForegroundUtilsTest.java
+++ b/tests/unit/src/com/android/nfc/ForegroundUtilsTest.java
@@ -43,7 +43,6 @@ import java.util.List;
 @RunWith(AndroidJUnit4.class)
 public class ForegroundUtilsTest {
     private static final String TAG = ForegroundUtilsTest.class.getSimpleName();
-    private boolean mNfcSupported;
     private MockitoSession mStaticMockSession;
     private ForegroundUtils mForegroundUtils;
     private ActivityManager mActivityManager;
@@ -53,15 +52,6 @@ public class ForegroundUtilsTest {
         mStaticMockSession = ExtendedMockito.mockitoSession()
                 .strictness(Strictness.LENIENT)
                 .startMocking();
-
-        Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
-        PackageManager pm = context.getPackageManager();
-        if (!pm.hasSystemFeature(PackageManager.FEATURE_NFC_ANY)) {
-            mNfcSupported = false;
-            return;
-        }
-        mNfcSupported = true;
-
         mActivityManager = mock(ActivityManager.class);
 
         InstrumentationRegistry.getInstrumentation().runOnMainSync(
@@ -76,8 +66,6 @@ public class ForegroundUtilsTest {
 
     @Test
     public void testRegisterUidToBackgroundCallback() {
-        if (!mNfcSupported) return;
-
         ForegroundUtils.Callback callback = uid -> {
             Log.d(TAG, "testRegisterUidToBackgroundCallback callback received");
         };
@@ -89,8 +77,6 @@ public class ForegroundUtilsTest {
 
     @Test
     public void testIsInForeground() {
-        if (!mNfcSupported) return;
-
         when(mActivityManager.getUidImportance(0)).thenReturn(100);
         when(mActivityManager.getUidImportance(10)).thenReturn(1);
         boolean isInForegroundTrue = mForegroundUtils.isInForeground(0);
@@ -101,8 +87,6 @@ public class ForegroundUtilsTest {
 
     @Test
     public void testOnUidImportance() {
-        if (!mNfcSupported) return;
-
         mForegroundUtils.clearForegroundlist();
         mForegroundUtils.onUidImportance(0,
                 ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND);
@@ -118,8 +102,6 @@ public class ForegroundUtilsTest {
 
     @Test
     public void testOnUidImportanceBackground() {
-        if (!mNfcSupported) return;
-
         mForegroundUtils.onUidImportance(0,
                 ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND);
         List<Integer> uids = mForegroundUtils.getForegroundUids();
@@ -144,8 +126,6 @@ public class ForegroundUtilsTest {
 
    @Test
     public void testGetForegroundUids() {
-        if (!mNfcSupported) return;
-
         mForegroundUtils.onUidImportance(0,
                 ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND);
         mForegroundUtils.onUidImportance(1,
@@ -157,4 +137,4 @@ public class ForegroundUtilsTest {
         int uid = uids.get(0);
         Assert.assertEquals(0, uid);
     }
-}
\ No newline at end of file
+}
diff --git a/tests/unit/src/com/android/nfc/HostNfcFEmulationManagerTest.java b/tests/unit/src/com/android/nfc/HostNfcFEmulationManagerTest.java
index 7d89638f..f70057af 100644
--- a/tests/unit/src/com/android/nfc/HostNfcFEmulationManagerTest.java
+++ b/tests/unit/src/com/android/nfc/HostNfcFEmulationManagerTest.java
@@ -72,7 +72,6 @@ import com.android.nfc.flags.Flags;
 public class HostNfcFEmulationManagerTest {
 
     private static final String TAG = HostNfcFEmulationManagerTest.class.getSimpleName();
-    private boolean mNfcSupported;
     private MockitoSession mStaticMockSession;
     private HostNfcFEmulationManager mHostNfcFEmulationManager;
     private ComponentName componentName;
@@ -85,15 +84,7 @@ public class HostNfcFEmulationManagerTest {
                 .mockStatic(Message.class)
                 .strictness(Strictness.LENIENT)
                 .startMocking();
-
-        Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
-        PackageManager pm = context.getPackageManager();
-        if (!pm.hasSystemFeature(PackageManager.FEATURE_NFC_ANY)) {
-            mNfcSupported = false;
-            return;
-        }
-        mNfcSupported = true;
-
+	Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
         Context mockContext = new ContextWrapper(context) {
 
             public Context createContextAsUser(@NonNull UserHandle user,
@@ -153,8 +144,6 @@ public class HostNfcFEmulationManagerTest {
 
     @Test
     public void testOnEnabledForegroundNfcFServiceChanged() {
-        if (!mNfcSupported) return;
-
         String packageName = mHostNfcFEmulationManager.getEnabledFgServiceName();
         Assert.assertNull(packageName);
         when(componentName.getPackageName()).thenReturn("com.android.nfc");
@@ -167,8 +156,6 @@ public class HostNfcFEmulationManagerTest {
 
     @Test
     public void testOnHostEmulationData() {
-        if (!mNfcSupported) return;
-
         testOnEnabledForegroundNfcFServiceChanged();
         mHostNfcFEmulationManager.onHostEmulationData("com.android.nfc".getBytes());
         ExtendedMockito.verify(() -> NfcStatsLog.write(NfcStatsLog.NFC_CARDEMULATION_OCCURRED,
@@ -179,8 +166,6 @@ public class HostNfcFEmulationManagerTest {
 
     @Test
     public void testOnNfcDisabled() {
-        if (!mNfcSupported) return;
-
         testOnHostEmulationData();
         ServiceConnection serviceConnection = mHostNfcFEmulationManager.getServiceConnection();
         Message message = mock(Message.class);
@@ -197,8 +182,6 @@ public class HostNfcFEmulationManagerTest {
 
     @Test
     public void testOnUserSwitched() {
-        if (!mNfcSupported) return;
-
         testOnHostEmulationData();
         ServiceConnection serviceConnection = mHostNfcFEmulationManager.getServiceConnection();
         Message message = mock(Message.class);
@@ -216,8 +199,6 @@ public class HostNfcFEmulationManagerTest {
 
     @Test
     public void testOnHostEmulationDeactivated() {
-        if (!mNfcSupported) return;
-
         testOnHostEmulationData();
         ServiceConnection serviceConnection = mHostNfcFEmulationManager.getServiceConnection();
         Message message = mock(Message.class);
diff --git a/tests/unit/src/com/android/nfc/NdefRecordTest.java b/tests/unit/src/com/android/nfc/NdefRecordTest.java
new file mode 100644
index 00000000..70aaba44
--- /dev/null
+++ b/tests/unit/src/com/android/nfc/NdefRecordTest.java
@@ -0,0 +1,169 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ * http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.nfc;
+import android.nfc.NdefRecord;
+import android.os.Parcel;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertNotEquals;
+import static org.junit.Assert.assertNotNull;
+import static org.junit.Assert.assertThrows;
+
+import java.io.UnsupportedEncodingException;
+import java.util.Locale;
+
+/** Unit tests for {@link NdefRecord}. */
+@RunWith(JUnit4.class)
+public class NdefRecordTest {
+
+    private static final byte[] PAYLOAD = new byte[] { 0x01, 0x02, 0x03 };
+    private static final String LANGUAGE_CODE = "en";
+    private static final String TEXT = "Hello, world!";
+
+    String getLanguageCode(NdefRecord record) {
+        byte len = record.getPayload()[0];
+        return new String(record.getPayload(), 1, len);
+    }
+    String getText(NdefRecord record) {
+        byte langLen = record.getPayload()[0];
+        int bufLen = record.getPayload().length;
+        return new String(record.getPayload(), langLen + 1, bufLen - langLen - 1);
+    }
+
+    @Test
+    public void testCreateRecord() throws UnsupportedEncodingException {
+        NdefRecord record = NdefRecord.createTextRecord(LANGUAGE_CODE, TEXT);
+        assertEquals(NdefRecord.TNF_WELL_KNOWN, record.getTnf());
+        assertEquals(LANGUAGE_CODE, getLanguageCode(record));
+        assertEquals(TEXT, getText(record));
+    }
+
+    @Test
+    public void testCreateRecordWithEmptyPayload() throws UnsupportedEncodingException {
+        NdefRecord record = NdefRecord.createTextRecord(LANGUAGE_CODE, "");
+        assertEquals(NdefRecord.TNF_WELL_KNOWN, record.getTnf());
+        assertEquals(LANGUAGE_CODE, getLanguageCode(record));
+        assertEquals(3, record.getPayload().length);
+    }
+
+    @Test
+    public void testCreateRecordWithNullLanguageCode() throws UnsupportedEncodingException {
+        NdefRecord record = NdefRecord.createTextRecord(null, TEXT);
+        assertEquals(NdefRecord.TNF_WELL_KNOWN, record.getTnf());
+        assertEquals(Locale.getDefault().getLanguage(), getLanguageCode(record));
+        assertEquals(TEXT, getText(record));
+    }
+
+    @Test
+    public void testCreateRecordWithInvalidTnf() {
+        assertThrows(IllegalArgumentException.class, () -> {
+            NdefRecord record = new NdefRecord((short) 21, null, null, PAYLOAD);
+            assertNotNull(record);
+        });
+    }
+
+    @Test
+    public void testCreateRecordWithNullPayload() {
+        assertThrows(NullPointerException.class, () -> {
+            NdefRecord record = NdefRecord.createTextRecord( null, null);
+            assertNotNull(record);
+        });
+    }
+
+    @Test
+    public void testEquals() {
+        NdefRecord record1 = NdefRecord.createTextRecord(LANGUAGE_CODE, TEXT);
+        NdefRecord record2 = NdefRecord.createTextRecord(LANGUAGE_CODE, TEXT);
+        assertEquals(record1, record2);
+    }
+
+    @Test
+    public void testEqualsWithDifferentTnf() {
+        NdefRecord record1 = NdefRecord.createTextRecord(LANGUAGE_CODE, TEXT);
+        NdefRecord record2 = NdefRecord.createTextRecord(null, new String(PAYLOAD));
+        assertNotEquals(record1, record2);
+    }
+
+    @Test
+    public void testEqualsWithDifferentLanguageCode() {
+        NdefRecord record1 = NdefRecord.createTextRecord(LANGUAGE_CODE, TEXT);
+        NdefRecord record2 = NdefRecord.createTextRecord("fr", TEXT);
+        assertNotEquals(record1, record2);
+    }
+
+    @Test
+    public void testEqualsWithDifferentPayload() {
+        NdefRecord record1 = NdefRecord.createTextRecord(LANGUAGE_CODE, TEXT);
+        NdefRecord record2 = NdefRecord.createTextRecord(LANGUAGE_CODE, "Goodbye, world!");
+        assertNotEquals(record1, record2);
+    }
+
+    @Test
+    public void testHashCode() {
+        NdefRecord record1 = NdefRecord.createTextRecord(LANGUAGE_CODE, TEXT);
+        NdefRecord record2 = NdefRecord.createTextRecord(LANGUAGE_CODE, TEXT);
+        assertEquals(record1.hashCode(), record2.hashCode());
+    }
+
+    @Test
+    public void testHashCodeWithDifferentTnf() {
+        NdefRecord record1 = NdefRecord.createTextRecord(LANGUAGE_CODE, TEXT);
+        NdefRecord record2 = NdefRecord.createTextRecord(null, new String(PAYLOAD));
+        assertNotEquals(record1.hashCode(), record2.hashCode());
+    }
+
+    @Test
+    public void testHashCodeWithDifferentLanguageCode() {
+        NdefRecord record1 = NdefRecord.createTextRecord(LANGUAGE_CODE, TEXT);
+        NdefRecord record2 = NdefRecord.createTextRecord("fr", TEXT);
+        assertNotEquals(record1.hashCode(), record2.hashCode());
+    }
+
+    @Test
+    public void testHashCodeWithDifferentPayload() {
+        NdefRecord record1 = NdefRecord.createTextRecord(LANGUAGE_CODE, TEXT);
+        NdefRecord record2 = NdefRecord.createTextRecord(LANGUAGE_CODE, "Goodbye, world!");
+        assertNotEquals(record1.hashCode(), record2.hashCode());
+    }
+
+    @Test
+    public void testToString() {
+        NdefRecord record = NdefRecord.createTextRecord(LANGUAGE_CODE, TEXT);
+        assertEquals("NdefRecord tnf=1 type=54 payload=02656E48656C6C6F2C20776F726C6421",
+                record.toString());
+    }
+
+    @Test
+    public void testToStringWithNullLanguageCode() {
+        NdefRecord record = NdefRecord.createTextRecord(null, TEXT);
+        assertEquals(Locale.getDefault().getLanguage(), getLanguageCode(record));
+        assertEquals(TEXT, getText(record));
+    }
+
+    @Test
+    public void testParcelable() {
+        NdefRecord record = NdefRecord.createTextRecord(LANGUAGE_CODE, TEXT);
+        Parcel parcel = Parcel.obtain();
+        record.writeToParcel(parcel, 0);
+        parcel.setDataPosition(0);
+        NdefRecord newRecord = NdefRecord.CREATOR.createFromParcel(parcel);
+        assertEquals(record, newRecord);
+    }
+}
\ No newline at end of file
diff --git a/tests/unit/src/com/android/nfc/NfcBlockedNotificationTest.java b/tests/unit/src/com/android/nfc/NfcBlockedNotificationTest.java
index d22ccbb9..50297e52 100644
--- a/tests/unit/src/com/android/nfc/NfcBlockedNotificationTest.java
+++ b/tests/unit/src/com/android/nfc/NfcBlockedNotificationTest.java
@@ -53,7 +53,6 @@ import org.mockito.quality.Strictness;
 public class NfcBlockedNotificationTest {
 
     private static final String TAG = NfcBlockedNotificationTest.class.getSimpleName();
-    private boolean mNfcSupported;
     private MockitoSession mStaticMockSession;
     private Context mockContext;
     private NfcBlockedNotification mBlockedNotification;
@@ -64,20 +63,12 @@ public class NfcBlockedNotificationTest {
         mStaticMockSession = ExtendedMockito.mockitoSession()
                 .strictness(Strictness.LENIENT)
                 .startMocking();
-
-        Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
-        PackageManager pm = context.getPackageManager();
-        if (!pm.hasSystemFeature(PackageManager.FEATURE_NFC_ANY)) {
-            mNfcSupported = false;
-            return;
-        }
-        mNfcSupported = true;
-
         mockNotificationManager = Mockito.mock(NotificationManager.class);
         Resources mockResources = Mockito.mock(Resources.class);
         when(mockResources.getBoolean(eq(R.bool.tag_intent_app_pref_supported)))
                 .thenReturn(false);
 
+	Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
         mockContext = new ContextWrapper(context) {
             @Override
             public Object getSystemService(String name) {
@@ -115,10 +106,7 @@ public class NfcBlockedNotificationTest {
 
     @Test
     public void testStartNotification() {
-        if (!mNfcSupported) return;
-
-
         mBlockedNotification.startNotification();
         verify(mockNotificationManager).createNotificationChannel(any());
     }
-}
\ No newline at end of file
+}
diff --git a/tests/unit/src/com/android/nfc/NfcDeveloperOptionNotificationTest.java b/tests/unit/src/com/android/nfc/NfcDeveloperOptionNotificationTest.java
index 595eb030..48b796a1 100644
--- a/tests/unit/src/com/android/nfc/NfcDeveloperOptionNotificationTest.java
+++ b/tests/unit/src/com/android/nfc/NfcDeveloperOptionNotificationTest.java
@@ -62,7 +62,6 @@ import androidx.test.platform.app.InstrumentationRegistry;
 public class NfcDeveloperOptionNotificationTest {
 
     private static final String TAG = NfcDeveloperOptionNotificationTest.class.getSimpleName();
-    private boolean mNfcSupported;
     private MockitoSession mStaticMockSession;
     private Context mockContext;
     private NfcDeveloperOptionNotification mNfcDevOptionNoti;
@@ -73,20 +72,12 @@ public class NfcDeveloperOptionNotificationTest {
         mStaticMockSession = ExtendedMockito.mockitoSession()
                 .strictness(Strictness.LENIENT)
                 .startMocking();
-
-        Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
-        PackageManager pm = context.getPackageManager();
-        if (!pm.hasSystemFeature(PackageManager.FEATURE_NFC_ANY)) {
-            mNfcSupported = false;
-            return;
-        }
-        mNfcSupported = true;
-
         mockNotificationManager = Mockito.mock(NotificationManager.class);
         Resources mockResources = Mockito.mock(Resources.class);
         when(mockResources.getBoolean(eq(R.bool.tag_intent_app_pref_supported)))
                 .thenReturn(false);
 
+	Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
         mockContext = new ContextWrapper(context) {
             @Override
             public Object getSystemService(String name) {
@@ -124,10 +115,7 @@ public class NfcDeveloperOptionNotificationTest {
 
     @Test
     public void testStartNotification() {
-        if (!mNfcSupported) return;
-
-
         mNfcDevOptionNoti.startNotification();
         verify(mockNotificationManager).createNotificationChannel(any());
     }
-}
\ No newline at end of file
+}
diff --git a/tests/unit/src/com/android/nfc/NfcDiscoveryParametersTest.java b/tests/unit/src/com/android/nfc/NfcDiscoveryParametersTest.java
index 1bd20b3a..8d786a4d 100644
--- a/tests/unit/src/com/android/nfc/NfcDiscoveryParametersTest.java
+++ b/tests/unit/src/com/android/nfc/NfcDiscoveryParametersTest.java
@@ -36,7 +36,6 @@ import com.android.dx.mockito.inline.extended.ExtendedMockito;
 public class NfcDiscoveryParametersTest {
 
     private static final String TAG = NfcDiscoveryParametersTest.class.getSimpleName();
-    private boolean mNfcSupported;
     private MockitoSession mStaticMockSession;
 
     @Before
@@ -44,14 +43,6 @@ public class NfcDiscoveryParametersTest {
         mStaticMockSession = ExtendedMockito.mockitoSession()
                 .strictness(Strictness.LENIENT)
                 .startMocking();
-
-        Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
-        PackageManager pm = context.getPackageManager();
-        if (!pm.hasSystemFeature(PackageManager.FEATURE_NFC_ANY)) {
-            mNfcSupported = false;
-            return;
-        }
-        mNfcSupported = true;
     }
 
     @After
@@ -72,8 +63,6 @@ public class NfcDiscoveryParametersTest {
 
     @Test
     public void testGetTechMask() {
-        if (!mNfcSupported) return;
-
         NfcDiscoveryParameters nfcDiscoveryParameters = computeDiscoveryParameters();
         int techMask = nfcDiscoveryParameters.getTechMask();
         Assert.assertEquals(1, techMask);
@@ -81,8 +70,6 @@ public class NfcDiscoveryParametersTest {
 
     @Test
     public void testDiscoveryParameters() {
-        if (!mNfcSupported) return;
-
         NfcDiscoveryParameters.Builder paramsBuilder = NfcDiscoveryParameters.newBuilder();
         NfcDiscoveryParameters nfcDiscoveryParameters = paramsBuilder.build();
         boolean shouldEnableDiscovery = nfcDiscoveryParameters.shouldEnableDiscovery();
diff --git a/tests/unit/src/com/android/nfc/NfcDispatcherTest.java b/tests/unit/src/com/android/nfc/NfcDispatcherTest.java
index 6f95d053..0cb4738c 100644
--- a/tests/unit/src/com/android/nfc/NfcDispatcherTest.java
+++ b/tests/unit/src/com/android/nfc/NfcDispatcherTest.java
@@ -52,6 +52,7 @@ import org.junit.Assert;
 import org.junit.Before;
 import org.junit.Test;
 import org.junit.runner.RunWith;
+import org.mockito.Mock;
 import org.mockito.Mockito;
 import org.mockito.MockitoSession;
 import org.mockito.quality.Strictness;
@@ -63,8 +64,7 @@ import java.nio.charset.StandardCharsets;
 public final class NfcDispatcherTest {
 
     private static final String TAG = NfcDispatcherTest.class.getSimpleName();
-    private boolean mNfcSupported;
-
+    @Mock private NfcInjector mNfcInjector;
     private MockitoSession mStaticMockSession;
     private NfcDispatcher mNfcDispatcher;
 
@@ -78,15 +78,7 @@ public final class NfcDispatcherTest {
                 .mockStatic(NfcWifiProtectedSetup.class)
                 .strictness(Strictness.LENIENT)
                 .startMocking();
-
-        Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
-        PackageManager pm = context.getPackageManager();
-        if (!pm.hasSystemFeature(PackageManager.FEATURE_NFC_ANY)) {
-            mNfcSupported = false;
-            return;
-        }
-        mNfcSupported = true;
-
+	Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
         PowerManager mockPowerManager = Mockito.mock(PowerManager.class);
         when(mockPowerManager.isInteractive()).thenReturn(false);
         Resources mockResources = Mockito.mock(Resources.class);
@@ -119,7 +111,7 @@ public final class NfcDispatcherTest {
 
         InstrumentationRegistry.getInstrumentation().runOnMainSync(
               () -> mNfcDispatcher = new NfcDispatcher(mockContext,
-                      new HandoverDataParser(), false));
+                      new HandoverDataParser(), mNfcInjector, false));
         Assert.assertNotNull(mNfcDispatcher);
     }
 
@@ -130,8 +122,6 @@ public final class NfcDispatcherTest {
 
     @Test
     public void testLogOthers() {
-        if (!mNfcSupported) return;
-
         Tag tag = Tag.createMockTag(null, new int[0], new Bundle[0], 0L);
         mNfcDispatcher.dispatchTag(tag);
         ExtendedMockito.verify(() -> NfcStatsLog.write(
@@ -144,7 +134,6 @@ public final class NfcDispatcherTest {
     }
         @Test
         public void testSetForegroundDispatchForWifiConnect() {
-            if (!mNfcSupported) return;
             PendingIntent pendingIntent = mock(PendingIntent.class);
             mNfcDispatcher.setForegroundDispatch(pendingIntent, new IntentFilter[]{},
                     new String[][]{});
@@ -173,8 +162,6 @@ public final class NfcDispatcherTest {
 
     @Test
     public void testPeripheralHandoverBTParing() {
-        if (!mNfcSupported) return;
-
         String btOobPayload = "00060E4C00520100000000000000000000000000000000000000000001";
         Bundle bundle = mock(Bundle.class);
         when(bundle.getParcelable(EXTRA_NDEF_MSG, android.nfc.NdefMessage.class)).thenReturn(
diff --git a/tests/unit/src/com/android/nfc/NfcReaderConflictOccurredTest.java b/tests/unit/src/com/android/nfc/NfcReaderConflictOccurredTest.java
index 29312c31..f18ab9f9 100644
--- a/tests/unit/src/com/android/nfc/NfcReaderConflictOccurredTest.java
+++ b/tests/unit/src/com/android/nfc/NfcReaderConflictOccurredTest.java
@@ -57,6 +57,7 @@ import org.junit.Assert;
 import org.junit.Before;
 import org.junit.Test;
 import org.junit.runner.RunWith;
+import org.mockito.Mock;
 import org.mockito.Mockito;
 import org.mockito.MockitoSession;
 import org.mockito.quality.Strictness;
@@ -65,8 +66,7 @@ import org.mockito.quality.Strictness;
 public final class NfcReaderConflictOccurredTest {
 
     private static final String TAG = NfcReaderConflictOccurredTest.class.getSimpleName();
-    private boolean mNfcSupported;
-
+    @Mock private NfcInjector mNfcInjector;
     private MockitoSession mStaticMockSession;
     private NfcDispatcher mNfcDispatcher;
 
@@ -76,15 +76,7 @@ public final class NfcReaderConflictOccurredTest {
                 .mockStatic(NfcStatsLog.class)
                 .strictness(Strictness.LENIENT)
                 .startMocking();
-
-        Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
-        PackageManager mPackageManager = context.getPackageManager();
-        if (!mPackageManager.hasSystemFeature(PackageManager.FEATURE_NFC_ANY)) {
-            mNfcSupported = false;
-            return;
-        }
-        mNfcSupported = true;
-
+	Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
         PackageManager mockPackageManager = Mockito.mock(PackageManager.class);
         // multiple resolveInfos for Tag
         when(mockPackageManager.queryIntentActivitiesAsUser(
@@ -129,7 +121,7 @@ public final class NfcReaderConflictOccurredTest {
 
         InstrumentationRegistry.getInstrumentation().runOnMainSync(
               () -> mNfcDispatcher = new NfcDispatcher(
-                      mockContext, new HandoverDataParser(), false));
+                      mockContext, new HandoverDataParser(), mNfcInjector, false));
         Assert.assertNotNull(mNfcDispatcher);
     }
 
@@ -140,8 +132,6 @@ public final class NfcReaderConflictOccurredTest {
 
     @Test
     public void testLogReaderConflict() {
-        if (!mNfcSupported) return;
-
         Tag tag = Tag.createMockTag(null, new int[0], new Bundle[0], 0L);
         int result = mNfcDispatcher.dispatchTag(tag);
         ExtendedMockito.verify(() -> NfcStatsLog.write(
@@ -151,8 +141,6 @@ public final class NfcReaderConflictOccurredTest {
 
     @Test
     public void testLogReaderSuccess() {
-        if (!mNfcSupported) return;
-
         Tag tag = Tag.createMockTag(null, new int[0], new Bundle[0], 0L);
         int result = mNfcDispatcher.dispatchTag(tag);
         Assert.assertEquals(result,DISPATCH_SUCCESS);
diff --git a/tests/unit/src/com/android/nfc/NfcServiceTest.java b/tests/unit/src/com/android/nfc/NfcServiceTest.java
index aaeb5e3f..ffc14093 100644
--- a/tests/unit/src/com/android/nfc/NfcServiceTest.java
+++ b/tests/unit/src/com/android/nfc/NfcServiceTest.java
@@ -15,19 +15,30 @@
  */
 package com.android.nfc;
 
+import static android.nfc.NfcAdapter.ACTION_PREFERRED_PAYMENT_CHANGED;
+
+import static com.android.nfc.NfcService.INVALID_NATIVE_HANDLE;
 import static com.android.nfc.NfcService.PREF_NFC_ON;
+import static com.android.nfc.NfcService.SOUND_END;
+import static com.android.nfc.NfcService.SOUND_ERROR;
+import static com.android.nfc.NfcService.SOUND_END;
+
+import static com.google.common.truth.Truth.assertThat;
 
 import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.anyBoolean;
+import static org.mockito.ArgumentMatchers.anyFloat;
 import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.ArgumentMatchers.anyLong;
 import static org.mockito.ArgumentMatchers.anyString;
 import static org.mockito.ArgumentMatchers.argThat;
 import static org.mockito.ArgumentMatchers.eq;
+import static org.mockito.ArgumentMatchers.isNull;
 import static org.mockito.Mockito.atLeastOnce;
 import static org.mockito.Mockito.clearInvocations;
-import static org.mockito.Mockito.doNothing;
+import static org.mockito.Mockito.doAnswer;
 import static org.mockito.Mockito.mock;
+import static org.mockito.Mockito.never;
 import static org.mockito.Mockito.times;
 import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.verifyNoMoreInteractions;
@@ -40,25 +51,45 @@ import android.app.KeyguardManager;
 import android.app.backup.BackupManager;
 import android.content.BroadcastReceiver;
 import android.content.ContentResolver;
+import android.content.Context;
 import android.content.Intent;
 import android.content.SharedPreferences;
+import android.content.pm.ApplicationInfo;
+import android.content.pm.PackageInfo;
 import android.content.pm.PackageManager;
 import android.content.res.Resources;
+import android.database.ContentObserver;
+import android.media.SoundPool;
+import android.nfc.NdefMessage;
 import android.nfc.NfcAdapter;
+import android.nfc.NfcAntennaInfo;
 import android.nfc.NfcServiceManager;
+import android.nfc.Tag;
+import android.nfc.cardemulation.CardEmulation;
 import android.nfc.tech.Ndef;
+import android.nfc.tech.TagTechnology;
 import android.os.AsyncTask;
 import android.os.Bundle;
 import android.os.Handler;
 import android.os.HandlerExecutor;
+import android.os.IBinder;
+import android.os.Message;
 import android.os.PowerManager;
+import android.os.RemoteException;
+import android.os.ResultReceiver;
 import android.os.UserManager;
 import android.os.test.TestLooper;
+import android.se.omapi.ISecureElementService;
+import android.sysprop.NfcProperties;
+import android.nfc.INfcOemExtensionCallback;
 
 import androidx.test.ext.junit.runners.AndroidJUnit4;
 
 
 import com.android.dx.mockito.inline.extended.ExtendedMockito;
+import com.android.nfc.cardemulation.CardEmulationManager;
+import com.android.nfc.flags.FeatureFlags;
+
 
 import org.junit.After;
 import org.junit.Assert;
@@ -70,13 +101,23 @@ import org.mockito.Captor;
 import org.mockito.Mock;
 import org.mockito.MockitoAnnotations;
 import org.mockito.MockitoSession;
+import org.mockito.invocation.InvocationOnMock;
 import org.mockito.quality.Strictness;
+import org.mockito.stubbing.Answer;
 
+import java.util.ArrayList;
+import java.util.Arrays;
+import java.util.List;
 import java.util.Optional;
 
 @RunWith(AndroidJUnit4.class)
 public final class NfcServiceTest {
     private static final String PKG_NAME = "com.test";
+    private static final int[] ANTENNA_POS_X = { 5 };
+    private static final int[] ANTENNA_POS_Y = { 6 };
+    private static final int ANTENNA_DEVICE_WIDTH = 9;
+    private static final int ANTENNA_DEVICE_HEIGHT = 10;
+    private static final boolean ANTENNA_DEVICE_FOLDABLE = true;
     @Mock Application mApplication;
     @Mock NfcInjector mNfcInjector;
     @Mock DeviceHost mDeviceHost;
@@ -99,16 +140,28 @@ public final class NfcServiceTest {
     @Mock Bundle mUserRestrictions;
     @Mock BackupManager mBackupManager;
     @Mock AlarmManager mAlarmManager;
+    @Mock SoundPool mSoundPool;
+    @Mock FeatureFlags mFeatureFlags;
     @Captor ArgumentCaptor<DeviceHost.DeviceHostListener> mDeviceHostListener;
     @Captor ArgumentCaptor<BroadcastReceiver> mGlobalReceiver;
-    @Captor ArgumentCaptor<AlarmManager.OnAlarmListener> mAlarmListener;
+    @Captor ArgumentCaptor<IBinder> mIBinderArgumentCaptor;
+    @Captor ArgumentCaptor<Integer> mSoundCaptor;
+    @Captor ArgumentCaptor<Intent> mIntentArgumentCaptor;
+    @Captor ArgumentCaptor<ContentObserver> mContentObserverArgumentCaptor;
     TestLooper mLooper;
     NfcService mNfcService;
     private MockitoSession mStaticMockSession;
+    private ContentObserver mContentObserver;
 
     @Before
     public void setUp() {
         mLooper = new TestLooper();
+        mStaticMockSession = ExtendedMockito.mockitoSession()
+                .mockStatic(NfcProperties.class)
+                .mockStatic(android.nfc.Flags.class)
+                .mockStatic(NfcStatsLog.class)
+                .strictness(Strictness.LENIENT)
+                .startMocking();
         MockitoAnnotations.initMocks(this);
         AsyncTask.setDefaultExecutor(new HandlerExecutor(new Handler(mLooper.getLooper())));
 
@@ -122,6 +175,8 @@ public final class NfcServiceTest {
         when(mNfcInjector.getBackupManager()).thenReturn(mBackupManager);
         when(mNfcInjector.getNfcDispatcher()).thenReturn(mNfcDispatcher);
         when(mNfcInjector.getNfcUnlockManager()).thenReturn(mNfcUnlockManager);
+        when(mNfcInjector.getFeatureFlags()).thenReturn(mFeatureFlags);
+        when(mNfcInjector.isSatelliteModeSensitive()).thenReturn(true);
         when(mApplication.getSharedPreferences(anyString(), anyInt())).thenReturn(mPreferences);
         when(mApplication.getSystemService(PowerManager.class)).thenReturn(mPowerManager);
         when(mApplication.getSystemService(UserManager.class)).thenReturn(mUserManager);
@@ -137,16 +192,29 @@ public final class NfcServiceTest {
         when(mPreferences.edit()).thenReturn(mPreferencesEditor);
         when(mPowerManager.newWakeLock(anyInt(), anyString()))
                 .thenReturn(mock(PowerManager.WakeLock.class));
+        when(mResources.getIntArray(R.array.antenna_x)).thenReturn(new int[0]);
+        when(mResources.getIntArray(R.array.antenna_y)).thenReturn(new int[0]);
+        when(NfcProperties.info_antpos_X()).thenReturn(List.of());
+        when(NfcProperties.info_antpos_Y()).thenReturn(List.of());
+        when(NfcProperties.initialized()).thenReturn(Optional.of(Boolean.TRUE));
         createNfcService();
     }
 
     @After
     public void tearDown() {
+        mStaticMockSession.finishMocking();
     }
 
     private void createNfcService() {
+        when(android.nfc.Flags.enableNfcCharging()).thenReturn(true);
+        when(mPackageManager.hasSystemFeature(PackageManager.FEATURE_NFC_CHARGING))
+                .thenReturn(true);
         mNfcService = new NfcService(mApplication, mNfcInjector);
         mLooper.dispatchAll();
+        verify(mContentResolver, atLeastOnce()).registerContentObserver(any(),
+                anyBoolean(), mContentObserverArgumentCaptor.capture());
+        mContentObserver = mContentObserverArgumentCaptor.getValue();
+        Assert.assertNotNull(mContentObserver);
         verify(mNfcInjector).makeDeviceHost(mDeviceHostListener.capture());
         verify(mApplication).registerReceiverForAllUsers(
                 mGlobalReceiver.capture(),
@@ -187,6 +255,21 @@ public final class NfcServiceTest {
         disableAndVerify();
     }
 
+    @Test
+    public void testEnable_WheOemExtensionEnabledAndNotInitialized() throws Exception {
+        when(mResources.getBoolean(R.bool.enable_oem_extension)).thenReturn(true);
+        when(NfcProperties.initialized()).thenReturn(Optional.of(Boolean.FALSE));
+
+        createNfcService();
+
+        when(mDeviceHost.initialize()).thenReturn(true);
+        when(mPreferences.getBoolean(eq(PREF_NFC_ON), anyBoolean())).thenReturn(true);
+        mNfcService.mNfcAdapter.enable(PKG_NAME);
+        verify(mPreferencesEditor, never()).putBoolean(PREF_NFC_ON, true);
+        mLooper.dispatchAll();
+        verify(mDeviceHost, never()).initialize();
+    }
+
     @Test
     public void testBootupWithNfcOn() throws Exception {
         when(mPreferences.getBoolean(eq(PREF_NFC_ON), anyBoolean())).thenReturn(true);
@@ -213,20 +296,7 @@ public final class NfcServiceTest {
         when(mResources.getBoolean(R.bool.enable_oem_extension)).thenReturn(true);
         createNfcService();
 
-        mNfcService.mNfcAdapter.allowBoot();
-        mLooper.dispatchAll();
-        verify(mDeviceHost).initialize();
-    }
-
-    @Test
-    public void testBootupWithNfcOn_WhenOemExtensionEnabled_ThenTimeout() throws Exception {
-        when(mPreferences.getBoolean(eq(PREF_NFC_ON), anyBoolean())).thenReturn(true);
-        when(mResources.getBoolean(R.bool.enable_oem_extension)).thenReturn(true);
-        createNfcService();
-        verify(mAlarmManager).setExact(
-                anyInt(), anyLong(), anyString(), mAlarmListener.capture(), any());
-
-        mAlarmListener.getValue().onAlarm();
+        mNfcService.mNfcAdapter.triggerInitialization();
         mLooper.dispatchAll();
         verify(mDeviceHost).initialize();
     }
@@ -268,4 +338,470 @@ public final class NfcServiceTest {
         mNfcService.mNfcAdapter.disable(true, PKG_NAME);
         assert(mNfcService.mState == NfcAdapter.STATE_ON);
     }
+
+    @Test
+    public void testHandlerResumePolling() {
+        Handler handler = mNfcService.getHandler();
+        Assert.assertNotNull(handler);
+        handler.handleMessage(handler.obtainMessage(NfcService.MSG_RESUME_POLLING));
+        verify(mNfcManagerRegisterer).register(mIBinderArgumentCaptor.capture());
+        Assert.assertNotNull(mIBinderArgumentCaptor.getValue());
+        Assert.assertFalse(handler.hasMessages(NfcService.MSG_RESUME_POLLING));
+        Assert.assertEquals(mIBinderArgumentCaptor.getValue(), mNfcService.mNfcAdapter);
+    }
+
+    @Test
+    public void testHandlerRoute_Aid() {
+        Handler handler = mNfcService.getHandler();
+        Assert.assertNotNull(handler);
+        Message msg = handler.obtainMessage(NfcService.MSG_ROUTE_AID);
+        msg.arg1 = 1;
+        msg.arg2 = 2;
+        msg.obj = "test";
+        handler.handleMessage(msg);
+        verify(mDeviceHost).routeAid(any(), anyInt(), anyInt(), anyInt());
+    }
+
+    @Test
+    public void testHandlerUnRoute_Aid() {
+        Handler handler = mNfcService.getHandler();
+        Assert.assertNotNull(handler);
+        Message msg = handler.obtainMessage(NfcService.MSG_UNROUTE_AID);
+        msg.obj = "test";
+        handler.handleMessage(msg);
+        verify(mDeviceHost).unrouteAid(any());
+    }
+
+    @Test
+    public void testGetAntennaInfo_NoneSet() throws Exception {
+        enableAndVerify();
+        NfcAntennaInfo nfcAntennaInfo = mNfcService.mNfcAdapter.getNfcAntennaInfo();
+        assertThat(nfcAntennaInfo).isNotNull();
+        assertThat(nfcAntennaInfo.getDeviceWidth()).isEqualTo(0);
+        assertThat(nfcAntennaInfo.getDeviceHeight()).isEqualTo(0);
+        assertThat(nfcAntennaInfo.isDeviceFoldable()).isEqualTo(false);
+        assertThat(nfcAntennaInfo.getAvailableNfcAntennas()).isEmpty();
+    }
+
+    @Test
+    public void testGetAntennaInfo_ReadFromResources() throws Exception {
+        enableAndVerify();
+        when(mResources.getIntArray(R.array.antenna_x)).thenReturn(ANTENNA_POS_X);
+        when(mResources.getIntArray(R.array.antenna_y)).thenReturn(ANTENNA_POS_Y);
+        when(mResources.getInteger(R.integer.device_width)).thenReturn(ANTENNA_DEVICE_WIDTH);
+        when(mResources.getInteger(R.integer.device_height)).thenReturn(ANTENNA_DEVICE_HEIGHT);
+        when(mResources.getBoolean(R.bool.device_foldable)).thenReturn(ANTENNA_DEVICE_FOLDABLE);
+        NfcAntennaInfo nfcAntennaInfo = mNfcService.mNfcAdapter.getNfcAntennaInfo();
+        assertThat(nfcAntennaInfo).isNotNull();
+        assertThat(nfcAntennaInfo.getDeviceWidth()).isEqualTo(ANTENNA_DEVICE_WIDTH);
+        assertThat(nfcAntennaInfo.getDeviceHeight()).isEqualTo(ANTENNA_DEVICE_HEIGHT);
+        assertThat(nfcAntennaInfo.isDeviceFoldable()).isEqualTo(ANTENNA_DEVICE_FOLDABLE);
+        assertThat(nfcAntennaInfo.getAvailableNfcAntennas()).isNotEmpty();
+        assertThat(nfcAntennaInfo.getAvailableNfcAntennas().get(0).getLocationX())
+                .isEqualTo(ANTENNA_POS_X[0]);
+        assertThat(nfcAntennaInfo.getAvailableNfcAntennas().get(0).getLocationY())
+                .isEqualTo(ANTENNA_POS_Y[0]);
+    }
+
+    @Test
+    public void testGetAntennaInfo_ReadFromSysProp() throws Exception {
+        enableAndVerify();
+        when(NfcProperties.info_antpos_X())
+                .thenReturn(Arrays.stream(ANTENNA_POS_X).boxed().toList());
+        when(NfcProperties.info_antpos_Y())
+                .thenReturn(Arrays.stream(ANTENNA_POS_Y).boxed().toList());
+        when(NfcProperties.info_antpos_device_width())
+                .thenReturn(Optional.of(ANTENNA_DEVICE_WIDTH));
+        when(NfcProperties.info_antpos_device_height())
+                .thenReturn(Optional.of(ANTENNA_DEVICE_HEIGHT));
+        when(NfcProperties.info_antpos_device_foldable())
+                .thenReturn(Optional.of(ANTENNA_DEVICE_FOLDABLE));
+        NfcAntennaInfo nfcAntennaInfo = mNfcService.mNfcAdapter.getNfcAntennaInfo();
+        assertThat(nfcAntennaInfo).isNotNull();
+        assertThat(nfcAntennaInfo.getDeviceWidth()).isEqualTo(ANTENNA_DEVICE_WIDTH);
+        assertThat(nfcAntennaInfo.getDeviceHeight()).isEqualTo(ANTENNA_DEVICE_HEIGHT);
+        assertThat(nfcAntennaInfo.isDeviceFoldable()).isEqualTo(ANTENNA_DEVICE_FOLDABLE);
+        assertThat(nfcAntennaInfo.getAvailableNfcAntennas()).isNotEmpty();
+        assertThat(nfcAntennaInfo.getAvailableNfcAntennas().get(0).getLocationX())
+                .isEqualTo(ANTENNA_POS_X[0]);
+        assertThat(nfcAntennaInfo.getAvailableNfcAntennas().get(0).getLocationY())
+                .isEqualTo(ANTENNA_POS_Y[0]);
+    }
+
+    @Test
+    public void testHandlerMsgRegisterT3tIdentifier() {
+        Handler handler = mNfcService.getHandler();
+        Assert.assertNotNull(handler);
+        Message msg = handler.obtainMessage(NfcService.MSG_REGISTER_T3T_IDENTIFIER);
+        msg.obj = "test".getBytes();
+        handler.handleMessage(msg);
+        verify(mDeviceHost).disableDiscovery();
+        verify(mDeviceHost).registerT3tIdentifier(any());
+        verify(mDeviceHost).enableDiscovery(any(), anyBoolean());
+        Message msgDeregister = handler.obtainMessage(NfcService.MSG_DEREGISTER_T3T_IDENTIFIER);
+        msgDeregister.obj = "test".getBytes();
+        handler.handleMessage(msgDeregister);
+        verify(mDeviceHost, times(2)).disableDiscovery();
+        verify(mDeviceHost, times(2)).enableDiscovery(any(), anyBoolean());
+    }
+
+    @Test
+    public void testHandlerMsgCommitRouting() {
+        Handler handler = mNfcService.getHandler();
+        Assert.assertNotNull(handler);
+        Message msg = handler.obtainMessage(NfcService.MSG_COMMIT_ROUTING);
+        mNfcService.mState = NfcAdapter.STATE_OFF;
+        handler.handleMessage(msg);
+        verify(mDeviceHost, never()).commitRouting();
+        mNfcService.mState = NfcAdapter.STATE_ON;
+        NfcDiscoveryParameters nfcDiscoveryParameters = mock(NfcDiscoveryParameters.class);
+        when(nfcDiscoveryParameters.shouldEnableDiscovery()).thenReturn(true);
+        mNfcService.mCurrentDiscoveryParameters = nfcDiscoveryParameters;
+        handler.handleMessage(msg);
+        verify(mDeviceHost).commitRouting();
+    }
+
+    @Test
+    public void testHandlerMsgMockNdef() {
+        Handler handler = mNfcService.getHandler();
+        Assert.assertNotNull(handler);
+        Message msg = handler.obtainMessage(NfcService.MSG_MOCK_NDEF);
+        NdefMessage ndefMessage = mock(NdefMessage.class);
+        msg.obj = ndefMessage;
+        handler.handleMessage(msg);
+        verify(mNfcDispatcher).dispatchTag(any());
+    }
+
+    @Test
+    public void testInitSoundPool_Start() {
+        mNfcService.playSound(SOUND_END);
+
+        verify(mSoundPool, never()).play(mSoundCaptor.capture(),
+                anyFloat(), anyFloat(), anyInt(), anyInt(), anyFloat());
+        mNfcService.mSoundPool = mSoundPool;
+        mNfcService.playSound(SOUND_END);
+        verify(mSoundPool, atLeastOnce()).play(mSoundCaptor.capture(),
+                anyFloat(), anyFloat(), anyInt(), anyInt(), anyFloat());
+        Integer value = mSoundCaptor.getValue();
+        Assert.assertEquals(mNfcService.mEndSound, (int) value);
+    }
+
+    @Test
+    public void testInitSoundPool_End() {
+        mNfcService.playSound(SOUND_END);
+
+        verify(mSoundPool, never()).play(mSoundCaptor.capture(),
+                anyFloat(), anyFloat(), anyInt(), anyInt(), anyFloat());
+        mNfcService.mSoundPool = mSoundPool;
+        mNfcService.playSound(SOUND_END);
+        verify(mSoundPool, atLeastOnce()).play(mSoundCaptor.capture(),
+                anyFloat(), anyFloat(), anyInt(), anyInt(), anyFloat());
+        Integer value = mSoundCaptor.getValue();
+        Assert.assertEquals(mNfcService.mEndSound, (int) value);
+    }
+
+    @Test
+    public void testInitSoundPool_Error() {
+        mNfcService.playSound(SOUND_ERROR);
+
+        verify(mSoundPool, never()).play(mSoundCaptor.capture(),
+                anyFloat(), anyFloat(), anyInt(), anyInt(), anyFloat());
+        mNfcService.mSoundPool = mSoundPool;
+        mNfcService.playSound(SOUND_ERROR);
+        verify(mSoundPool, atLeastOnce()).play(mSoundCaptor.capture(),
+                anyFloat(), anyFloat(), anyInt(), anyInt(), anyFloat());
+        Integer value = mSoundCaptor.getValue();
+        Assert.assertEquals(mNfcService.mErrorSound, (int) value);
+    }
+
+    @Test
+    public void testMsg_Rf_Field_Activated() {
+        Handler handler = mNfcService.getHandler();
+        Assert.assertNotNull(handler);
+        Message msg = handler.obtainMessage(NfcService.MSG_RF_FIELD_ACTIVATED);
+        List<String> userlist = new ArrayList<>();
+        userlist.add("com.android.nfc");
+        mNfcService.mNfcEventInstalledPackages.put(1, userlist);
+        mNfcService.mIsSecureNfcEnabled = true;
+        mNfcService.mIsRequestUnlockShowed = false;
+        when(mKeyguardManager.isKeyguardLocked()).thenReturn(true);
+        handler.handleMessage(msg);
+        verify(mApplication).sendBroadcastAsUser(mIntentArgumentCaptor.capture(), any());
+        Intent intent = mIntentArgumentCaptor.getValue();
+        Assert.assertNotNull(intent);
+        Assert.assertEquals(NfcService.ACTION_RF_FIELD_ON_DETECTED, intent.getAction());
+        verify(mApplication).sendBroadcast(mIntentArgumentCaptor.capture());
+        intent = mIntentArgumentCaptor.getValue();
+        Assert.assertEquals(NfcAdapter.ACTION_REQUIRE_UNLOCK_FOR_NFC, intent.getAction());
+    }
+
+    @Test
+    public void testMsg_Rf_Field_Deactivated() {
+        Handler handler = mNfcService.getHandler();
+        Assert.assertNotNull(handler);
+        Message msg = handler.obtainMessage(NfcService.MSG_RF_FIELD_DEACTIVATED);
+        List<String> userlist = new ArrayList<>();
+        userlist.add("com.android.nfc");
+        mNfcService.mNfcEventInstalledPackages.put(1, userlist);
+        handler.handleMessage(msg);
+        verify(mApplication).sendBroadcastAsUser(mIntentArgumentCaptor.capture(), any());
+        Intent intent = mIntentArgumentCaptor.getValue();
+        Assert.assertNotNull(intent);
+        Assert.assertEquals(NfcService.ACTION_RF_FIELD_OFF_DETECTED, intent.getAction());
+    }
+
+    @Test
+    public void testMsg_Tag_Debounce() {
+        Handler handler = mNfcService.getHandler();
+        Assert.assertNotNull(handler);
+        Message msg = handler.obtainMessage(NfcService.MSG_TAG_DEBOUNCE);
+        handler.handleMessage(msg);
+        Assert.assertEquals(INVALID_NATIVE_HANDLE, mNfcService.mDebounceTagNativeHandle);
+    }
+
+    @Test
+    public void testMsg_Apply_Screen_State() {
+        Handler handler = mNfcService.getHandler();
+        Assert.assertNotNull(handler);
+        Message msg = handler.obtainMessage(NfcService.MSG_APPLY_SCREEN_STATE);
+        msg.obj = ScreenStateHelper.SCREEN_STATE_ON_UNLOCKED;
+        handler.handleMessage(msg);
+        verify(mDeviceHost).doSetScreenState(anyInt(), anyBoolean());
+    }
+
+    @Test
+    public void testMsg_Transaction_Event_Cardemulation_Occurred() {
+        CardEmulationManager cardEmulationManager = mock(CardEmulationManager.class);
+        when(cardEmulationManager.getRegisteredAidCategory(anyString())).
+                thenReturn(CardEmulation.CATEGORY_PAYMENT);
+        mNfcService.mCardEmulationManager = cardEmulationManager;
+        Handler handler = mNfcService.getHandler();
+        Assert.assertNotNull(handler);
+        Message msg = handler.obtainMessage(NfcService.MSG_TRANSACTION_EVENT);
+        byte[][] data = {NfcService.hexStringToBytes("F00102030405"),
+                NfcService.hexStringToBytes("02FE00010002"),
+                NfcService.hexStringToBytes("03000000")};
+        msg.obj = data;
+        handler.handleMessage(msg);
+        ExtendedMockito.verify(() -> NfcStatsLog.write(NfcStatsLog.NFC_CARDEMULATION_OCCURRED,
+                NfcStatsLog
+                        .NFC_CARDEMULATION_OCCURRED__CATEGORY__OFFHOST_PAYMENT,
+                new String(NfcService.hexStringToBytes("03000000"), "UTF-8"),
+                -1));
+    }
+
+    @Test
+    public void testMsg_Transaction_Event() throws RemoteException {
+        CardEmulationManager cardEmulationManager = mock(CardEmulationManager.class);
+        when(cardEmulationManager.getRegisteredAidCategory(anyString())).
+                thenReturn(CardEmulation.CATEGORY_PAYMENT);
+        mNfcService.mCardEmulationManager = cardEmulationManager;
+        Handler handler = mNfcService.getHandler();
+        Assert.assertNotNull(handler);
+        Message msg = handler.obtainMessage(NfcService.MSG_TRANSACTION_EVENT);
+        byte[][] data = {NfcService.hexStringToBytes("F00102030405"),
+                NfcService.hexStringToBytes("02FE00010002"),
+                NfcService.hexStringToBytes("03000000")};
+        msg.obj = data;
+        List<String> userlist = new ArrayList<>();
+        userlist.add("com.android.nfc");
+        mNfcService.mNfcEventInstalledPackages.put(1, userlist);
+        ISecureElementService iSecureElementService = mock(ISecureElementService.class);
+        IBinder iBinder = mock(IBinder.class);
+        when(iSecureElementService.asBinder()).thenReturn(iBinder);
+        boolean[] nfcAccess = {true};
+        when(iSecureElementService.isNfcEventAllowed(anyString(), any(), any(), anyInt()))
+                .thenReturn(nfcAccess);
+        when(mNfcInjector.connectToSeService()).thenReturn(iSecureElementService);
+        handler.handleMessage(msg);
+        verify(mApplication).sendBroadcastAsUser(mIntentArgumentCaptor.capture(),
+                any(), any(), any());
+    }
+
+    @Test
+    public void testMsg_Preferred_Payment_Changed()
+            throws RemoteException, PackageManager.NameNotFoundException {
+        Handler handler = mNfcService.getHandler();
+        Assert.assertNotNull(handler);
+        Message msg = handler.obtainMessage(NfcService.MSG_PREFERRED_PAYMENT_CHANGED);
+        msg.obj = 1;
+        List<String> packagesList = new ArrayList<>();
+        packagesList.add("com.android.nfc");
+        packagesList.add("com.sample.nfc");
+        mNfcService.mNfcPreferredPaymentChangedInstalledPackages.put(1, packagesList);
+        ISecureElementService iSecureElementService = mock(ISecureElementService.class);
+        IBinder iBinder = mock(IBinder.class);
+        when(iSecureElementService.asBinder()).thenReturn(iBinder);
+        when(iSecureElementService.getReaders()).thenReturn(new String[]{"com.android.nfc"});
+        when(iSecureElementService.isNfcEventAllowed(anyString(), isNull(), any(), anyInt()))
+                .thenReturn(new boolean[]{true});
+        boolean[] nfcAccess = {true};
+        when(iSecureElementService.isNfcEventAllowed(anyString(), any(), any(), anyInt()))
+                .thenReturn(nfcAccess);
+        when(mNfcInjector.connectToSeService()).thenReturn(iSecureElementService);
+        PackageInfo info = mock(PackageInfo.class);
+        ApplicationInfo applicationInfo = mock(ApplicationInfo.class);
+        applicationInfo.flags = 1;
+        info.applicationInfo = applicationInfo;
+        when(mPackageManager.getPackageInfo(anyString(), anyInt())).thenReturn(info);
+        handler.handleMessage(msg);
+        verify(mApplication, times(2))
+                .sendBroadcastAsUser(mIntentArgumentCaptor.capture(), any());
+        Intent intent = mIntentArgumentCaptor.getValue();
+        Assert.assertEquals(ACTION_PREFERRED_PAYMENT_CHANGED, intent.getAction());
+    }
+
+    @Test
+    public void testMSG_NDEF_TAG() {
+        Handler handler = mNfcService.getHandler();
+        Assert.assertNotNull(handler);
+        Message msg = handler.obtainMessage(NfcService.MSG_NDEF_TAG);
+        mNfcService.mState = NfcAdapter.STATE_ON;
+        DeviceHost.TagEndpoint tagEndpoint = mock(DeviceHost.TagEndpoint.class);
+        when(tagEndpoint.getConnectedTechnology()).thenReturn(TagTechnology.NDEF);
+        NdefMessage ndefMessage = mock(NdefMessage.class);
+        when(tagEndpoint.findAndReadNdef()).thenReturn(ndefMessage);
+        msg.obj = tagEndpoint;
+        handler.handleMessage(msg);
+        verify(tagEndpoint, atLeastOnce()).startPresenceChecking(anyInt(), any());
+    }
+
+    @Test
+    public void testMsg_Ndef_Tag_Wlc_Enabled() {
+        Handler handler = mNfcService.getHandler();
+        Assert.assertNotNull(handler);
+        Message msg = handler.obtainMessage(NfcService.MSG_NDEF_TAG);
+        mNfcService.mState = NfcAdapter.STATE_ON;
+        DeviceHost.TagEndpoint tagEndpoint = mock(DeviceHost.TagEndpoint.class);
+        when(tagEndpoint.getConnectedTechnology()).thenReturn(TagTechnology.NDEF);
+        when(tagEndpoint.getUid()).thenReturn(NfcService
+                .hexStringToBytes("0x040000010100000000000000"));
+        when(tagEndpoint.getTechList()).thenReturn(new int[]{Ndef.NDEF});
+        when(tagEndpoint.getTechExtras()).thenReturn(new Bundle[]{});
+        when(tagEndpoint.getHandle()).thenReturn(1);
+        NdefMessage ndefMessage = mock(NdefMessage.class);
+        when(tagEndpoint.findAndReadNdef()).thenReturn(ndefMessage);
+        msg.obj = tagEndpoint;
+        mNfcService.mIsWlcEnabled = true;
+        mNfcService.mIsRWCapable = true;
+        handler.handleMessage(msg);
+        verify(tagEndpoint, atLeastOnce()).startPresenceChecking(anyInt(), any());
+        ArgumentCaptor<Tag> tagCaptor = ArgumentCaptor
+                .forClass(Tag.class);
+        verify(mNfcDispatcher).dispatchTag(tagCaptor.capture());
+        Tag tag = tagCaptor.getValue();
+        Assert.assertNotNull(tag);
+        Assert.assertEquals("android.nfc.tech.Ndef", tag.getTechList()[0]);
+    }
+
+    @Test
+    public void testMsg_Clear_Routing_Table() {
+        Handler handler = mNfcService.getHandler();
+        Assert.assertNotNull(handler);
+        Message msg = handler.obtainMessage(NfcService.MSG_CLEAR_ROUTING_TABLE);
+        mNfcService.mState = NfcAdapter.STATE_ON;
+        msg.obj = 1;
+        handler.handleMessage(msg);
+        ArgumentCaptor<Integer> flagCaptor = ArgumentCaptor.forClass(Integer.class);
+        verify(mDeviceHost).clearRoutingEntry(flagCaptor.capture());
+        int flag = flagCaptor.getValue();
+        Assert.assertEquals(1, flag);
+    }
+
+    @Test
+    public void testMsg_Update_Isodep_Protocol_Route() {
+        Handler handler = mNfcService.getHandler();
+        Assert.assertNotNull(handler);
+        Message msg = handler.obtainMessage(NfcService.MSG_UPDATE_ISODEP_PROTOCOL_ROUTE);
+        msg.obj = 1;
+        handler.handleMessage(msg);
+        ArgumentCaptor<Integer> flagCaptor = ArgumentCaptor.forClass(Integer.class);
+        verify(mDeviceHost).setIsoDepProtocolRoute(flagCaptor.capture());
+        int flag = flagCaptor.getValue();
+        Assert.assertEquals(1, flag);
+    }
+
+    @Test
+    public void testMsg_Update_Technology_Abf_Route() {
+        Handler handler = mNfcService.getHandler();
+        Assert.assertNotNull(handler);
+        Message msg = handler.obtainMessage(NfcService.MSG_UPDATE_TECHNOLOGY_ABF_ROUTE);
+        msg.obj = 1;
+        handler.handleMessage(msg);
+        ArgumentCaptor<Integer> flagCaptor = ArgumentCaptor.forClass(Integer.class);
+        verify(mDeviceHost).setTechnologyABFRoute(flagCaptor.capture());
+        int flag = flagCaptor.getValue();
+        Assert.assertEquals(1, flag);
+    }
+
+    @Test
+    public void testDirectBootAware() throws Exception {
+        when(mPreferences.getBoolean(eq(PREF_NFC_ON), anyBoolean())).thenReturn(true);
+        when(mFeatureFlags.enableDirectBootAware()).thenReturn(true);
+        mNfcService = new NfcService(mApplication, mNfcInjector);
+        mLooper.dispatchAll();
+        verify(mNfcInjector).makeDeviceHost(mDeviceHostListener.capture());
+        verify(mApplication).registerReceiverForAllUsers(
+                mGlobalReceiver.capture(),
+                argThat(intent -> intent.hasAction(Intent.ACTION_USER_UNLOCKED)), any(), any());
+        verify(mDeviceHost).initialize();
+
+        clearInvocations(mApplication, mPreferences, mPreferencesEditor);
+        Context ceContext = mock(Context.class);
+        when(mApplication.createCredentialProtectedStorageContext()).thenReturn(ceContext);
+        when(ceContext.getSharedPreferences(anyString(), anyInt())).thenReturn(mPreferences);
+        when(mApplication.moveSharedPreferencesFrom(ceContext, NfcService.PREF)).thenReturn(true);
+        mGlobalReceiver.getValue().onReceive(mApplication, new Intent(Intent.ACTION_USER_UNLOCKED));
+        verify(mApplication).moveSharedPreferencesFrom(ceContext, NfcService.PREF);
+        verify(mApplication).getSharedPreferences(eq(NfcService.PREF), anyInt());
+        verify(mPreferences).edit();
+        verify(mPreferencesEditor).putBoolean(NfcService.PREF_MIGRATE_TO_DE_COMPLETE, true);
+        verify(mPreferencesEditor).apply();
+    }
+
+    @Test
+    public void testAllowOemOnTagDispatchCallback() throws Exception {
+        when(mPreferences.getBoolean(eq(PREF_NFC_ON), anyBoolean())).thenReturn(true);
+        INfcOemExtensionCallback callback = mock(INfcOemExtensionCallback.class);
+        mNfcService.mNfcAdapter.registerOemExtensionCallback(callback);
+        Handler handler = mNfcService.getHandler();
+        Assert.assertNotNull(handler);
+        Message msg = handler.obtainMessage(NfcService.MSG_NDEF_TAG);
+        mNfcService.mState = NfcAdapter.STATE_ON;
+        DeviceHost.TagEndpoint tagEndpoint = mock(DeviceHost.TagEndpoint.class);
+        when(tagEndpoint.getConnectedTechnology()).thenReturn(TagTechnology.NDEF);
+        when(tagEndpoint.getUid()).thenReturn(NfcService
+                .hexStringToBytes("0x040000010100000000000000"));
+        when(tagEndpoint.getTechList()).thenReturn(new int[]{Ndef.NDEF});
+        when(tagEndpoint.getTechExtras()).thenReturn(new Bundle[]{});
+        when(tagEndpoint.getHandle()).thenReturn(1);
+        NdefMessage ndefMessage = mock(NdefMessage.class);
+        when(tagEndpoint.findAndReadNdef()).thenReturn(ndefMessage);
+        msg.obj = tagEndpoint;
+        mNfcService.mIsWlcEnabled = true;
+        mNfcService.mIsRWCapable = true;
+        handler.handleMessage(msg);
+        verify(tagEndpoint, atLeastOnce()).startPresenceChecking(anyInt(), any());
+        ArgumentCaptor<Tag> tagCaptor = ArgumentCaptor
+                .forClass(Tag.class);
+        verify(mNfcDispatcher).dispatchTag(tagCaptor.capture());
+        Tag tag = tagCaptor.getValue();
+        Assert.assertNotNull(tag);
+        Assert.assertEquals("android.nfc.tech.Ndef", tag.getTechList()[0]);
+
+        doAnswer(new Answer() {
+            @Override
+            public Void answer(InvocationOnMock invocation) throws Throwable {
+                ResultReceiver r = invocation.getArgument(0);
+                r.send(1, null);
+                return null;
+            }
+        }).when(callback).onTagDispatch(any(ResultReceiver.class));
+        mContentObserver.onChange(true);
+        ArgumentCaptor<ResultReceiver> receiverArgumentCaptor = ArgumentCaptor
+                .forClass(ResultReceiver.class);
+        verify(callback).onTagDispatch(receiverArgumentCaptor.capture());
+        ResultReceiver resultReceiver = receiverArgumentCaptor.getValue();
+        Assert.assertNotNull(resultReceiver);
+    }
 }
diff --git a/tests/unit/src/com/android/nfc/NfcWifiProtectedSetupTest.java b/tests/unit/src/com/android/nfc/NfcWifiProtectedSetupTest.java
index 21f7f31a..df9f8807 100644
--- a/tests/unit/src/com/android/nfc/NfcWifiProtectedSetupTest.java
+++ b/tests/unit/src/com/android/nfc/NfcWifiProtectedSetupTest.java
@@ -66,7 +66,6 @@ import java.nio.ByteBuffer;
 public class NfcWifiProtectedSetupTest extends TestCase {
 
     private static final String TAG = NfcWifiProtectedSetupTest.class.getSimpleName();
-    private boolean mNfcSupported;
     private MockitoSession mStaticMockSession;
     private Context mockContext;
     public static final byte[] CREDENTIAL = {0x10, 0x0e};
@@ -88,15 +87,7 @@ public class NfcWifiProtectedSetupTest extends TestCase {
                 .mockStatic(Ndef.class)
                 .strictness(Strictness.LENIENT)
                 .startMocking();
-
         Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
-        PackageManager pm = context.getPackageManager();
-        if (!pm.hasSystemFeature(PackageManager.FEATURE_NFC_ANY)) {
-            mNfcSupported = false;
-            return;
-        }
-        mNfcSupported = true;
-
         PowerManager mockPowerManager = Mockito.mock(PowerManager.class);
         when(mockPowerManager.isInteractive()).thenReturn(false);
         Resources mockResources = Mockito.mock(Resources.class);
@@ -136,8 +127,6 @@ public class NfcWifiProtectedSetupTest extends TestCase {
 
     @Test
     public void testTryNfcWifiSetupFailed() {
-        if (!mNfcSupported) return;
-
         Ndef ndef = mock(Ndef.class);
         NdefMessage ndefMessage = mock(NdefMessage.class);
 
@@ -175,4 +164,4 @@ public class NfcWifiProtectedSetupTest extends TestCase {
                 MAC_ADDRESS, mac);
         return NdefRecord.createMime(NFC_TOKEN_MIME_TYPE, payload);
     }
-}
\ No newline at end of file
+}
diff --git a/tests/unit/src/com/android/nfc/RegisteredAidCacheTest.java b/tests/unit/src/com/android/nfc/RegisteredAidCacheTest.java
deleted file mode 100644
index 38d55b30..00000000
--- a/tests/unit/src/com/android/nfc/RegisteredAidCacheTest.java
+++ /dev/null
@@ -1,101 +0,0 @@
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
-package com.android.nfc;
-
-import static org.mockito.Mockito.mock;
-
-import android.content.ComponentName;
-import android.content.Context;
-import android.content.ContextWrapper;
-import android.content.pm.PackageManager;
-
-import org.junit.After;
-import org.junit.Assert;
-import org.junit.Before;
-import org.junit.Test;
-import org.junit.runner.RunWith;
-import org.mockito.Mock;
-import org.mockito.MockitoSession;
-import org.mockito.quality.Strictness;
-
-import androidx.test.ext.junit.runners.AndroidJUnit4;
-import androidx.test.platform.app.InstrumentationRegistry;
-
-import com.android.dx.mockito.inline.extended.ExtendedMockito;
-import com.android.nfc.cardemulation.AidRoutingManager;
-import com.android.nfc.cardemulation.RegisteredAidCache;
-import com.android.nfc.cardemulation.WalletRoleObserver;
-
-@RunWith(AndroidJUnit4.class)
-public class RegisteredAidCacheTest {
-
-    private static final String TAG = RegisteredAidCacheTest.class.getSimpleName();
-    private boolean mNfcSupported;
-    private MockitoSession mStaticMockSession;
-    private RegisteredAidCache mRegisteredAidCache;
-    private Context mockContext;
-    @Mock
-    private WalletRoleObserver mWalletRoleObserver;
-
-    @Before
-    public void setUp() throws Exception {
-        mStaticMockSession = ExtendedMockito.mockitoSession()
-                .strictness(Strictness.LENIENT)
-                .startMocking();
-
-        Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
-        PackageManager pm = context.getPackageManager();
-        if (!pm.hasSystemFeature(PackageManager.FEATURE_NFC_ANY)) {
-            mNfcSupported = false;
-            return;
-        }
-        mNfcSupported = true;
-
-        mockContext = new ContextWrapper(context) {
-
-        };
-
-        AidRoutingManager routingManager = mock(AidRoutingManager.class);
-        InstrumentationRegistry.getInstrumentation().runOnMainSync(
-                () -> mRegisteredAidCache = new RegisteredAidCache(
-                        mockContext, mWalletRoleObserver, routingManager));
-        Assert.assertNotNull(mRegisteredAidCache);
-    }
-
-    @After
-    public void tearDown() throws Exception {
-        mStaticMockSession.finishMocking();
-    }
-
-
-    @Test
-    public void testOnPreferredForegroundServiceChanged() {
-        if (!mNfcSupported) return;
-
-        ComponentName componentName = mRegisteredAidCache.getPreferredService().second;
-        Assert.assertNull(componentName);
-
-        componentName = new ComponentName("com.android.nfc",
-                RegisteredAidCacheTest.class.getName());
-        mRegisteredAidCache.onPreferredForegroundServiceChanged(0, componentName);
-        ComponentName preferredService = mRegisteredAidCache.getPreferredService().second;
-
-        Assert.assertNotNull(preferredService);
-        Assert.assertEquals(componentName.getClassName(), preferredService.getClassName());
-    }
-
-}
\ No newline at end of file
diff --git a/tests/unit/src/com/android/nfc/RegisteredComponentCacheTest.java b/tests/unit/src/com/android/nfc/RegisteredComponentCacheTest.java
index 2282cf17..a433d817 100644
--- a/tests/unit/src/com/android/nfc/RegisteredComponentCacheTest.java
+++ b/tests/unit/src/com/android/nfc/RegisteredComponentCacheTest.java
@@ -62,21 +62,12 @@ import java.util.List;
 public final class RegisteredComponentCacheTest {
 
     private RegisteredComponentCache mRegisteredComponentCache;
-    private boolean mNfcSupported;
     private Context mockContext;
     private static final String TAG = RegisteredComponentCacheTest.class.getSimpleName();
 
     @Before
     public void setUp() {
-
         Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
-        PackageManager pm = context.getPackageManager();
-        if (!pm.hasSystemFeature(PackageManager.FEATURE_NFC_ANY)) {
-            mNfcSupported = false;
-            return;
-        }
-        mNfcSupported = true;
-
         PowerManager mockPowerManager = mock(PowerManager.class);
         when(mockPowerManager.isInteractive()).thenReturn(false);
         Resources mockResources = mock(Resources.class);
@@ -148,11 +139,9 @@ public final class RegisteredComponentCacheTest {
 
     @Test
     public void testGetComponents() {
-        if (!mNfcSupported) return;
-
         ArrayList<RegisteredComponentCache.ComponentInfo> componentInfos =
                 mRegisteredComponentCache.getComponents();
         Assert.assertNotNull(componentInfos);
         Assert.assertTrue(componentInfos.size() > 0);
     }
-}
\ No newline at end of file
+}
diff --git a/tests/unit/src/com/android/nfc/RegisteredNfcFServicesCacheTest.java b/tests/unit/src/com/android/nfc/RegisteredNfcFServicesCacheTest.java
index af5d1d0a..338b8eda 100644
--- a/tests/unit/src/com/android/nfc/RegisteredNfcFServicesCacheTest.java
+++ b/tests/unit/src/com/android/nfc/RegisteredNfcFServicesCacheTest.java
@@ -64,6 +64,7 @@ import org.mockito.MockitoSession;
 import org.mockito.quality.Strictness;
 import org.xmlpull.v1.XmlPullParser;
 import org.xmlpull.v1.XmlPullParserException;
+import org.xmlpull.v1.XmlSerializer;
 
 import java.io.IOException;
 import java.util.ArrayList;
@@ -73,7 +74,6 @@ import java.util.List;
 public class RegisteredNfcFServicesCacheTest {
 
     private static String TAG = RegisteredNfcFServicesCacheTest.class.getSimpleName();
-    private boolean mNfcSupported;
     private MockitoSession mStaticMockSession;
     private RegisteredNfcFServicesCache mNfcFServicesCache;
     private int mUserId = -1;
@@ -81,21 +81,12 @@ public class RegisteredNfcFServicesCacheTest {
 
     @Before
     public void setUp() throws Exception {
-
+        Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
         mStaticMockSession = ExtendedMockito.mockitoSession()
                 .mockStatic(Xml.class)
                 .mockStatic(NfcStatsLog.class)
                 .strictness(Strictness.LENIENT)
                 .startMocking();
-
-        Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
-        PackageManager pm = context.getPackageManager();
-        if (!pm.hasSystemFeature(PackageManager.FEATURE_NFC_ANY)) {
-            mNfcSupported = false;
-            return;
-        }
-        mNfcSupported = true;
-
         Context mockContext = new ContextWrapper(context) {
             public Intent registerReceiverForAllUsers(@Nullable BroadcastReceiver receiver,
                     @NonNull IntentFilter filter, @Nullable String broadcastPermission,
@@ -130,18 +121,30 @@ public class RegisteredNfcFServicesCacheTest {
                 }
                 XmlResourceParser parser = mock(XmlResourceParser.class);
                 AttributeSet attributeSet = mock(AttributeSet.class);
-                TypedArray typedArray = mock(TypedArray.class);
-                when(typedArray.getString(
+
+                TypedArray typedArrayHost = mock(TypedArray.class);
+                when(typedArrayHost.getString(
                         com.android.internal.R.styleable.HostNfcFService_description)).thenReturn(
                         "nfc");
-                when(resources.obtainAttributes(attributeSet,
-                        com.android.internal.R.styleable.HostNfcFService)).thenReturn(typedArray);
+                TypedArray typedArrayNfcid2 = mock(TypedArray.class);
+                when(typedArrayNfcid2.getString(
+                        com.android.internal.R.styleable.Nfcid2Filter_name)).thenReturn(
+                        "02FEC1DE32456789");
+                TypedArray typedArraySystem = mock(TypedArray.class);
+                when(typedArraySystem.getString(
+                        com.android.internal.R.styleable.SystemCodeFilter_name)).thenReturn(
+                        "42BC");
+                when(resources.obtainAttributes(any(), any())).thenReturn(typedArrayHost,
+                        typedArraySystem, typedArrayNfcid2);
+
                 when(Xml.asAttributeSet(parser)).thenReturn(attributeSet);
                 try {
                     when(parser.getEventType()).thenReturn(XmlPullParser.START_TAG,
                             XmlPullParser.END_TAG);
-                    when(parser.next()).thenReturn(1, 0);
-                    when(parser.getName()).thenReturn("host-nfcf-service");
+                    when(parser.next()).thenReturn(XmlPullParser.START_TAG, XmlPullParser.START_TAG,
+                            XmlPullParser.END_TAG);
+                    when(parser.getName()).thenReturn("host-nfcf-service",
+                            "system-code-filter", "nfcid2-filter");
                 } catch (XmlPullParserException e) {
                 } catch (IOException e) {
                     throw new RuntimeException(e);
@@ -176,8 +179,6 @@ public class RegisteredNfcFServicesCacheTest {
 
     @Test
     public void testOnHostEmulationActivated() {
-        if (!mNfcSupported) return;
-
         boolean isActive = mNfcFServicesCache.isActivated();
         Assert.assertFalse(isActive);
         mNfcFServicesCache.onHostEmulationActivated();
@@ -187,8 +188,6 @@ public class RegisteredNfcFServicesCacheTest {
 
     @Test
     public void testOnHostEmulationDeactivated() {
-        if (!mNfcSupported) return;
-
         mNfcFServicesCache.onHostEmulationActivated();
         boolean isActive = mNfcFServicesCache.isActivated();
         Assert.assertTrue(isActive);
@@ -199,8 +198,6 @@ public class RegisteredNfcFServicesCacheTest {
 
     @Test
     public void testOnNfcDisabled() {
-        if (!mNfcSupported) return;
-
         mNfcFServicesCache.onHostEmulationActivated();
         boolean isActive = mNfcFServicesCache.isActivated();
         Assert.assertTrue(isActive);
@@ -211,8 +208,6 @@ public class RegisteredNfcFServicesCacheTest {
 
     @Test
     public void testInvalidateCache() {
-        if (!mNfcSupported) return;
-
         Assert.assertEquals(-1, mUserId);
         mNfcFServicesCache.invalidateCache(1);
         List<NfcFServiceInfo> services = mNfcFServicesCache.getServices(1);
@@ -225,10 +220,24 @@ public class RegisteredNfcFServicesCacheTest {
         Assert.assertEquals("com.android.nfc", cName.getPackageName());
     }
 
+
     @Test
-    public void testGetServices() {
-        if (!mNfcSupported) return;
+    public void testGetService() {
+        mNfcFServicesCache.invalidateCache(1);
+        List<NfcFServiceInfo> services = mNfcFServicesCache.getServices(1);
+        Assert.assertNotNull(services);
+        Assert.assertTrue(services.size() > 0);
+        NfcFServiceInfo nfcFServiceInfo = services.get(0);
+        ComponentName cName = nfcFServiceInfo.getComponent();
+        Assert.assertNotNull(cName);
+
+        NfcFServiceInfo serviceInfo = mNfcFServicesCache.getService(1, cName);
+        Assert.assertNotNull(serviceInfo);
+        Assert.assertEquals(nfcFServiceInfo, serviceInfo);
+    }
 
+    @Test
+    public void testGetNfcid2ForService() {
         mNfcFServicesCache.invalidateCache(1);
         List<NfcFServiceInfo> services = mNfcFServicesCache.getServices(1);
         Assert.assertNotNull(services);
@@ -236,6 +245,68 @@ public class RegisteredNfcFServicesCacheTest {
         NfcFServiceInfo nfcFServiceInfo = services.get(0);
         ComponentName cName = nfcFServiceInfo.getComponent();
         Assert.assertNotNull(cName);
-        Assert.assertEquals("com.android.nfc", cName.getPackageName());
+
+        String nfcId2 = mNfcFServicesCache.getNfcid2ForService(1, 0, cName);
+        Assert.assertNotNull(nfcId2);
+        Assert.assertEquals("02FEC1DE32456789", nfcId2);
+    }
+
+    @Test
+    public void testSetNfcid2ForService() {
+        mNfcFServicesCache.invalidateCache(1);
+        List<NfcFServiceInfo> services = mNfcFServicesCache.getServices(1);
+        Assert.assertNotNull(services);
+        Assert.assertTrue(services.size() > 0);
+        NfcFServiceInfo nfcFServiceInfo = services.get(0);
+        ComponentName cName = nfcFServiceInfo.getComponent();
+        Assert.assertNotNull(cName);
+        XmlSerializer xmlSerializer = mock(XmlSerializer.class);
+        when(Xml.newSerializer()).thenReturn(xmlSerializer);
+        String nfcId2 = "02FE9876543210AB";
+        boolean isSet = mNfcFServicesCache.setNfcid2ForService(1, 0, cName, nfcId2);
+        Assert.assertTrue(isSet);
+    }
+
+    @Test
+    public void testRemoveSystemCodeForService() {
+        mNfcFServicesCache.invalidateCache(1);
+        List<NfcFServiceInfo> services = mNfcFServicesCache.getServices(1);
+        Assert.assertNotNull(services);
+        Assert.assertTrue(services.size() > 0);
+        NfcFServiceInfo nfcFServiceInfo = services.get(0);
+        ComponentName cName = nfcFServiceInfo.getComponent();
+        Assert.assertNotNull(cName);
+        XmlSerializer xmlSerializer = mock(XmlSerializer.class);
+        when(Xml.newSerializer()).thenReturn(xmlSerializer);
+        boolean isRemove = mNfcFServicesCache.removeSystemCodeForService(1, 0, cName);
+        Assert.assertTrue(isRemove);
+
+    }
+
+    @Test
+    public void  testHasService() {
+        mNfcFServicesCache.invalidateCache(1);
+        List<NfcFServiceInfo> services = mNfcFServicesCache.getServices(1);
+        Assert.assertNotNull(services);
+        Assert.assertTrue(services.size() > 0);
+        NfcFServiceInfo nfcFServiceInfo = services.get(0);
+        ComponentName cName = nfcFServiceInfo.getComponent();
+        Assert.assertNotNull(cName);
+        boolean hasService = mNfcFServicesCache.hasService(1, cName);
+        Assert.assertTrue(hasService);
+
+    }
+
+    @Test
+    public void testGetSystemCodeForService() {
+        mNfcFServicesCache.invalidateCache(1);
+        List<NfcFServiceInfo> services = mNfcFServicesCache.getServices(1);
+        Assert.assertNotNull(services);
+        Assert.assertFalse(services.isEmpty());
+        NfcFServiceInfo nfcFServiceInfo = services.get(0);
+        ComponentName cName = nfcFServiceInfo.getComponent();
+        String systemCode = mNfcFServicesCache.getSystemCodeForService(1, 0, cName);
+        Assert.assertNotNull(systemCode);
+        Assert.assertEquals("42BC", systemCode);
     }
 }
\ No newline at end of file
diff --git a/tests/unit/src/com/android/nfc/cardemulation/AidRoutingManagerTest.java b/tests/unit/src/com/android/nfc/cardemulation/AidRoutingManagerTest.java
index 30aa829a..3f909e75 100644
--- a/tests/unit/src/com/android/nfc/cardemulation/AidRoutingManagerTest.java
+++ b/tests/unit/src/com/android/nfc/cardemulation/AidRoutingManagerTest.java
@@ -274,6 +274,7 @@ public class AidRoutingManagerTest {
     when(mRoutingOptionManager.getOffHostRouteEse()).thenReturn(OFFHOST_ROUTE_ESE);
     when(mRoutingOptionManager.getAidMatchingSupport()).thenReturn(AID_MATCHING_PREFIX_ONLY);
     when(mRoutingOptionManager.getDefaultIsoDepRoute()).thenReturn(ROUTE_HOST);
+    when(mRoutingOptionManager.isAutoChangeEnabled()).thenReturn(true);
     when(mNfcService.getNciVersion()).thenReturn(NfcService.NCI_VERSION_1_0);
     when(mNfcService.getAidRoutingTableSize()).thenReturn(0);
     manager = new AidRoutingManager();
@@ -404,12 +405,12 @@ public class AidRoutingManagerTest {
   @Test
   public void testConfigureRoutingTestCase5_CommitsCache() {
     when(mRoutingOptionManager.isRoutingTableOverrided()).thenReturn(true);
-    when(mRoutingOptionManager.getDefaultOffHostRoute()).thenReturn(DEFAULT_OFFHOST_ROUTE);
     when(mRoutingOptionManager.getOverrideDefaultRoute()).thenReturn(OVERRIDE_DEFAULT_ROUTE);
+    when(mRoutingOptionManager.getOverrideDefaultOffHostRoute()).thenReturn(DEFAULT_OFFHOST_ROUTE);
+    when(mRoutingOptionManager.getOverrideDefaultIsoDepRoute()).thenReturn(ROUTE_HOST);
     when(mRoutingOptionManager.getOffHostRouteUicc()).thenReturn(null);
     when(mRoutingOptionManager.getOffHostRouteEse()).thenReturn(null);
     when(mRoutingOptionManager.getAidMatchingSupport()).thenReturn(AID_MATCHING_EXACT_OR_PREFIX);
-    when(mRoutingOptionManager.getDefaultIsoDepRoute()).thenReturn(ROUTE_HOST);
     when(mNfcService.getNciVersion()).thenReturn(NfcService.NCI_VERSION_2_0);
     when(mNfcService.getAidRoutingTableSize()).thenReturn(0);
     manager = new AidRoutingManager();
@@ -466,13 +467,13 @@ public class AidRoutingManagerTest {
   @Test
   public void testConfigureRoutingTestCase6_CommitsCache() {
     when(mRoutingOptionManager.isRoutingTableOverrided()).thenReturn(true);
-    when(mRoutingOptionManager.getDefaultOffHostRoute()).thenReturn(DEFAULT_OFFHOST_ROUTE);
     when(mRoutingOptionManager.getOverrideDefaultRoute()).thenReturn(OVERRIDE_DEFAULT_ROUTE);
+    when(mRoutingOptionManager.getOverrideDefaultOffHostRoute()).thenReturn(DEFAULT_OFFHOST_ROUTE);
+    when(mRoutingOptionManager.getOverrideDefaultIsoDepRoute()).thenReturn(ROUTE_HOST);
     when(mRoutingOptionManager.getOffHostRouteUicc()).thenReturn(null);
     when(mRoutingOptionManager.getOffHostRouteEse()).thenReturn(null);
     when(mRoutingOptionManager.getAidMatchingSupport())
         .thenReturn(AID_MATCHING_EXACT_OR_SUBSET_OR_PREFIX);
-    when(mRoutingOptionManager.getDefaultIsoDepRoute()).thenReturn(ROUTE_HOST);
     when(mNfcService.getNciVersion()).thenReturn(NfcService.NCI_VERSION_2_0);
     when(mNfcService.getAidRoutingTableSize()).thenReturn(0);
     manager = new AidRoutingManager();
@@ -627,4 +628,4 @@ public class AidRoutingManagerTest {
 
     return aidMap;
   }
-}
\ No newline at end of file
+}
diff --git a/tests/unit/src/com/android/nfc/cardemulation/CardEmulationManagerTest.java b/tests/unit/src/com/android/nfc/cardemulation/CardEmulationManagerTest.java
index ea76099d..aafd3f74 100644
--- a/tests/unit/src/com/android/nfc/cardemulation/CardEmulationManagerTest.java
+++ b/tests/unit/src/com/android/nfc/cardemulation/CardEmulationManagerTest.java
@@ -16,6 +16,11 @@
 
 package com.android.nfc.cardemulation;
 
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.assertNotNull;
+import static org.junit.Assert.assertNull;
+import static org.junit.Assert.assertThrows;
 import static org.junit.Assert.assertTrue;
 import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.anyBoolean;
@@ -53,7 +58,6 @@ import com.android.nfc.NfcService;
 import com.android.nfc.R;
 
 import org.junit.After;
-import org.junit.Assert;
 import org.junit.Before;
 import org.junit.Test;
 import org.mockito.ArgumentCaptor;
@@ -152,6 +156,7 @@ public class CardEmulationManagerTest {
                 any(), anyInt())).thenReturn(mContext);
         when(mContext.getResources()).thenReturn(mResources);
         when(mContext.getSystemService(eq(UserManager.class))).thenReturn(mUserManager);
+        when(mResources.getBoolean(R.bool.indicate_user_activity_for_hce)).thenReturn(true);
         mCardEmulationManager = createInstanceWithMockParams();
     }
 
@@ -180,8 +185,8 @@ public class CardEmulationManagerTest {
 
     @Test
     public void testGetters() {
-        Assert.assertNotNull(mCardEmulationManager.getNfcCardEmulationInterface());
-        Assert.assertNotNull(mCardEmulationManager.getNfcFCardEmulationInterface());
+        assertNotNull(mCardEmulationManager.getNfcCardEmulationInterface());
+        assertNotNull(mCardEmulationManager.getNfcFCardEmulationInterface());
     }
 
     @Test
@@ -189,7 +194,7 @@ public class CardEmulationManagerTest {
         mCardEmulationManager.onPollingLoopDetected(POLLING_LOOP_FRAMES);
 
         verify(mHostEmulationManager).onPollingLoopDetected(mPollingLoopFrameCaptor.capture());
-        Assert.assertEquals(mPollingLoopFrameCaptor.getValue(), POLLING_LOOP_FRAMES);
+        assertEquals(POLLING_LOOP_FRAMES, mPollingLoopFrameCaptor.getValue());
     }
 
     @Test
@@ -200,7 +205,7 @@ public class CardEmulationManagerTest {
                 eq(PowerManager.USER_ACTIVITY_FLAG_INDIRECT));
         verify(mHostEmulationManager).onHostEmulationActivated();
         verify(mPreferredServices).onHostEmulationActivated();
-        Assert.assertFalse(mCardEmulationManager.mNotSkipAid);
+        assertFalse(mCardEmulationManager.mNotSkipAid);
         verifyZeroInteractions(mHostNfcFEmulationManager);
         verifyZeroInteractions(mEnabledNfcFServices);
     }
@@ -222,19 +227,19 @@ public class CardEmulationManagerTest {
     @Test
     public void testSkipAid_nullData_isFalse() {
         mCardEmulationManager.mNotSkipAid = false;
-        Assert.assertFalse(mCardEmulationManager.isSkipAid(null));
+        assertFalse(mCardEmulationManager.isSkipAid(null));
     }
 
     @Test
     public void testSkipAid_notSkipTrue_isFalse() {
         mCardEmulationManager.mNotSkipAid = true;
-        Assert.assertFalse(mCardEmulationManager.isSkipAid(TEST_DATA_1));
+        assertFalse(mCardEmulationManager.isSkipAid(TEST_DATA_1));
     }
 
     @Test
     public void testSkipAid_wrongData_isFalse() {
         mCardEmulationManager.mNotSkipAid = false;
-        Assert.assertFalse(mCardEmulationManager.isSkipAid(TEST_DATA_1));
+        assertFalse(mCardEmulationManager.isSkipAid(TEST_DATA_1));
     }
 
     @Test
@@ -255,7 +260,7 @@ public class CardEmulationManagerTest {
                 PROPER_SKIP_DATA_NDF1_HEADER);
 
         verify(mHostEmulationManager).onHostEmulationData(mDataCaptor.capture());
-        Assert.assertEquals(PROPER_SKIP_DATA_NDF1_HEADER, mDataCaptor.getValue());
+        assertEquals(PROPER_SKIP_DATA_NDF1_HEADER, mDataCaptor.getValue());
         verifyZeroInteractions(mHostNfcFEmulationManager);
         verifyZeroInteractions(mPowerManager);
     }
@@ -266,7 +271,7 @@ public class CardEmulationManagerTest {
                 PROPER_SKIP_DATA_NDF1_HEADER);
 
         verify(mHostNfcFEmulationManager).onHostEmulationData(mDataCaptor.capture());
-        Assert.assertEquals(PROPER_SKIP_DATA_NDF1_HEADER, mDataCaptor.getValue());
+        assertEquals(PROPER_SKIP_DATA_NDF1_HEADER, mDataCaptor.getValue());
         verifyZeroInteractions(mHostEmulationManager);
         verify(mPowerManager).userActivity(anyLong(), eq(PowerManager.USER_ACTIVITY_EVENT_TOUCH),
                 eq(0));
@@ -366,7 +371,7 @@ public class CardEmulationManagerTest {
         verify(mWalletRoleObserver, times(2)).isWalletRoleFeatureEnabled();
         verify(mRegisteredAidCache).onServicesUpdated(eq(USER_ID), mServiceListCaptor.capture());
         verify(mPreferredServices).onServicesUpdated();
-        Assert.assertEquals(UPDATED_SERVICES, mServiceListCaptor.getValue());
+        assertEquals(UPDATED_SERVICES, mServiceListCaptor.getValue());
         verifyZeroInteractions(mHostEmulationManager);
         verify(mNfcService).onPreferredPaymentChanged(eq(NfcAdapter.PREFERRED_PAYMENT_UPDATED));
     }
@@ -384,8 +389,8 @@ public class CardEmulationManagerTest {
         verify(mHostEmulationManager).updatePollingLoopFilters(eq(USER_ID),
                 mServiceListCaptor.capture());
         verify(mNfcService).onPreferredPaymentChanged(eq(NfcAdapter.PREFERRED_PAYMENT_UPDATED));
-        Assert.assertEquals(UPDATED_SERVICES, mServiceListCaptor.getAllValues().getFirst());
-        Assert.assertEquals(UPDATED_SERVICES, mServiceListCaptor.getAllValues().getLast());
+        assertEquals(UPDATED_SERVICES, mServiceListCaptor.getAllValues().getFirst());
+        assertEquals(UPDATED_SERVICES, mServiceListCaptor.getAllValues().getLast());
     }
 
     @Test
@@ -394,7 +399,7 @@ public class CardEmulationManagerTest {
 
         verify(mRegisteredT3tIdentifiersCache).onServicesUpdated(eq(USER_ID),
                 mNfcServiceListCaptor.capture());
-        Assert.assertEquals(UPDATED_NFC_SERVICES, mNfcServiceListCaptor.getValue());
+        assertEquals(UPDATED_NFC_SERVICES, mNfcServiceListCaptor.getValue());
     }
 
     @Test
@@ -412,7 +417,7 @@ public class CardEmulationManagerTest {
     public void testIsServiceRegistered_serviceDoesNotExists() {
         when(mRegisteredServicesCache.hasService(eq(USER_ID), any())).thenReturn(false);
 
-        Assert.assertFalse(mCardEmulationManager
+        assertFalse(mCardEmulationManager
                 .isServiceRegistered(USER_ID, WALLET_PAYMENT_SERVICE));
 
         verify(mRegisteredServicesCache).invalidateCache(eq(USER_ID), eq(true));
@@ -435,7 +440,7 @@ public class CardEmulationManagerTest {
     public void testIsNfcServiceInstalled_serviceDoesNotExists() {
         when(mRegisteredNfcFServicesCache.hasService(eq(USER_ID), any())).thenReturn(false);
 
-        Assert.assertFalse(mCardEmulationManager
+        assertFalse(mCardEmulationManager
                 .isNfcFServiceInstalled(USER_ID, WALLET_PAYMENT_SERVICE));
 
         verify(mRegisteredNfcFServicesCache).invalidateCache(eq(USER_ID));
@@ -482,7 +487,7 @@ public class CardEmulationManagerTest {
         when(mRegisteredServicesCache.hasService(eq(USER_ID), any())).thenReturn(false);
 
         assertConstructorMethodCalls();
-        Assert.assertFalse(mCardEmulationManager.getNfcCardEmulationInterface()
+        assertFalse(mCardEmulationManager.getNfcCardEmulationInterface()
                 .isDefaultServiceForCategory(USER_ID, WALLET_PAYMENT_SERVICE,
                         CardEmulation.CATEGORY_PAYMENT));
 
@@ -526,7 +531,7 @@ public class CardEmulationManagerTest {
             throws RemoteException {
         when(mRegisteredServicesCache.hasService(eq(USER_ID), any())).thenReturn(false);
 
-        Assert.assertFalse(mCardEmulationManager.getNfcCardEmulationInterface()
+        assertFalse(mCardEmulationManager.getNfcCardEmulationInterface()
                 .isDefaultServiceForAid(USER_ID, WALLET_PAYMENT_SERVICE,
                         PAYMENT_AID_1));
 
@@ -569,7 +574,7 @@ public class CardEmulationManagerTest {
             throws RemoteException {
         when(mRegisteredServicesCache.hasService(eq(USER_ID), any())).thenReturn(false);
 
-        Assert.assertFalse(mCardEmulationManager.getNfcCardEmulationInterface()
+        assertFalse(mCardEmulationManager.getNfcCardEmulationInterface()
                 .setDefaultForNextTap(USER_ID, WALLET_PAYMENT_SERVICE));
 
         ExtendedMockito.verify(() -> {
@@ -656,7 +661,7 @@ public class CardEmulationManagerTest {
             throws RemoteException {
         when(mRegisteredServicesCache.hasService(eq(USER_ID), any())).thenReturn(false);
 
-        Assert.assertFalse(mCardEmulationManager.getNfcCardEmulationInterface()
+        assertFalse(mCardEmulationManager.getNfcCardEmulationInterface()
                 .setShouldDefaultToObserveModeForService(USER_ID, WALLET_PAYMENT_SERVICE,
                         false));
 
@@ -706,7 +711,7 @@ public class CardEmulationManagerTest {
                 any())).thenReturn(true);
         AidGroup aidGroup = Mockito.mock(AidGroup.class);
 
-        Assert.assertFalse(mCardEmulationManager.getNfcCardEmulationInterface()
+        assertFalse(mCardEmulationManager.getNfcCardEmulationInterface()
                 .registerAidGroupForService(USER_ID, WALLET_PAYMENT_SERVICE, aidGroup));
 
         ExtendedMockito.verify(() -> {
@@ -757,7 +762,7 @@ public class CardEmulationManagerTest {
                 any(), any(),anyBoolean())).thenReturn(true);
         String pollingLoopFilter = "filter";
 
-        Assert.assertFalse(mCardEmulationManager.getNfcCardEmulationInterface()
+        assertFalse(mCardEmulationManager.getNfcCardEmulationInterface()
                 .registerPollingLoopFilterForService(USER_ID, WALLET_PAYMENT_SERVICE,
                         pollingLoopFilter, true));
 
@@ -808,7 +813,7 @@ public class CardEmulationManagerTest {
                 any(), any())).thenReturn(true);
         String pollingLoopFilter = "filter";
 
-        Assert.assertFalse(mCardEmulationManager.getNfcCardEmulationInterface()
+        assertFalse(mCardEmulationManager.getNfcCardEmulationInterface()
                 .removePollingLoopFilterForService(USER_ID, WALLET_PAYMENT_SERVICE,
                         pollingLoopFilter));
 
@@ -859,7 +864,7 @@ public class CardEmulationManagerTest {
                 anyInt(), any(), any(), anyBoolean())).thenReturn(true);
         String pollingLoopFilter = "filter";
 
-        Assert.assertFalse(mCardEmulationManager.getNfcCardEmulationInterface()
+        assertFalse(mCardEmulationManager.getNfcCardEmulationInterface()
                 .registerPollingLoopPatternFilterForService(USER_ID, WALLET_PAYMENT_SERVICE,
                         pollingLoopFilter, true));
 
@@ -910,7 +915,7 @@ public class CardEmulationManagerTest {
                 anyInt(), any(), any())).thenReturn(true);
         String pollingLoopFilter = "filter";
 
-        Assert.assertFalse(mCardEmulationManager.getNfcCardEmulationInterface()
+        assertFalse(mCardEmulationManager.getNfcCardEmulationInterface()
                 .removePollingLoopPatternFilterForService(USER_ID, WALLET_PAYMENT_SERVICE,
                         pollingLoopFilter));
 
@@ -960,7 +965,7 @@ public class CardEmulationManagerTest {
                 anyInt(), any(), any())).thenReturn(true);
         String offhostse = "offhostse";
 
-        Assert.assertFalse(mCardEmulationManager.getNfcCardEmulationInterface()
+        assertFalse(mCardEmulationManager.getNfcCardEmulationInterface()
                 .setOffHostForService(USER_ID, WALLET_PAYMENT_SERVICE, offhostse));
 
         ExtendedMockito.verify(() -> {
@@ -1008,7 +1013,7 @@ public class CardEmulationManagerTest {
         when(mRegisteredServicesCache.resetOffHostSecureElement(eq(USER_ID),
                 anyInt(), any())).thenReturn(true);
 
-        Assert.assertFalse(mCardEmulationManager.getNfcCardEmulationInterface()
+        assertFalse(mCardEmulationManager.getNfcCardEmulationInterface()
                 .unsetOffHostForService(USER_ID, WALLET_PAYMENT_SERVICE));
 
         ExtendedMockito.verify(() -> {
@@ -1032,9 +1037,9 @@ public class CardEmulationManagerTest {
         when(mRegisteredServicesCache.getAidGroupForService(eq(USER_ID),
                 anyInt(), any(), eq(CardEmulation.CATEGORY_PAYMENT))).thenReturn(aidGroup);
 
-        Assert.assertEquals(mCardEmulationManager.getNfcCardEmulationInterface()
+        assertEquals(aidGroup, mCardEmulationManager.getNfcCardEmulationInterface()
                 .getAidGroupForService(USER_ID, WALLET_PAYMENT_SERVICE,
-                        CardEmulation.CATEGORY_PAYMENT), aidGroup);
+                        CardEmulation.CATEGORY_PAYMENT));
 
         ExtendedMockito.verify(() -> {
             NfcPermissions.enforceUserPermissions(mContext);
@@ -1058,7 +1063,7 @@ public class CardEmulationManagerTest {
         when(mRegisteredServicesCache.getAidGroupForService(eq(USER_ID),
                 anyInt(), any(), eq(CardEmulation.CATEGORY_PAYMENT))).thenReturn(aidGroup);
 
-        Assert.assertNull(mCardEmulationManager.getNfcCardEmulationInterface()
+        assertNull(mCardEmulationManager.getNfcCardEmulationInterface()
                 .getAidGroupForService(USER_ID, WALLET_PAYMENT_SERVICE,
                         CardEmulation.CATEGORY_PAYMENT));
 
@@ -1108,7 +1113,7 @@ public class CardEmulationManagerTest {
         when(mRegisteredServicesCache.removeAidGroupForService(eq(USER_ID),
                 anyInt(), any(), eq(CardEmulation.CATEGORY_PAYMENT))).thenReturn(true);
 
-        Assert.assertFalse(mCardEmulationManager.getNfcCardEmulationInterface()
+        assertFalse(mCardEmulationManager.getNfcCardEmulationInterface()
                 .removeAidGroupForService(USER_ID, WALLET_PAYMENT_SERVICE,
                         CardEmulation.CATEGORY_PAYMENT));
 
@@ -1132,8 +1137,8 @@ public class CardEmulationManagerTest {
         when(mRegisteredServicesCache.getServicesForCategory(eq(USER_ID),
                 eq(CardEmulation.CATEGORY_PAYMENT))).thenReturn(UPDATED_SERVICES);
 
-        Assert.assertEquals(mCardEmulationManager.getNfcCardEmulationInterface()
-                .getServices(USER_ID, CardEmulation.CATEGORY_PAYMENT), UPDATED_SERVICES);
+        assertEquals(UPDATED_SERVICES, mCardEmulationManager.getNfcCardEmulationInterface()
+                .getServices(USER_ID, CardEmulation.CATEGORY_PAYMENT));
 
         ExtendedMockito.verify(() -> {
             NfcPermissions.validateProfileId(mContext, USER_ID);
@@ -1178,7 +1183,7 @@ public class CardEmulationManagerTest {
         when(mPreferredServices.registerPreferredForegroundService(eq(WALLET_PAYMENT_SERVICE),
                 anyInt())).thenReturn(false);
 
-        Assert.assertFalse(mCardEmulationManager.getNfcCardEmulationInterface()
+        assertFalse(mCardEmulationManager.getNfcCardEmulationInterface()
                 .setPreferredService(WALLET_PAYMENT_SERVICE));
 
         ExtendedMockito.verify(() -> {
@@ -1219,8 +1224,7 @@ public class CardEmulationManagerTest {
         when(mPreferredServices.unregisteredPreferredForegroundService(anyInt()))
                 .thenReturn(false);
 
-        Assert.assertFalse(mCardEmulationManager.getNfcCardEmulationInterface()
-                .unsetPreferredService());
+        assertFalse(mCardEmulationManager.getNfcCardEmulationInterface().unsetPreferredService());
 
         ExtendedMockito.verify(() -> {
             NfcPermissions.enforceUserPermissions(mContext);
@@ -1244,7 +1248,7 @@ public class CardEmulationManagerTest {
             throws RemoteException {
         when(mRegisteredAidCache.supportsAidPrefixRegistration()).thenReturn(false);
 
-        Assert.assertFalse(mCardEmulationManager.getNfcCardEmulationInterface()
+        assertFalse(mCardEmulationManager.getNfcCardEmulationInterface()
                 .supportsAidPrefixRegistration());
 
         verify(mRegisteredAidCache).onWalletRoleHolderChanged(eq(WALLET_HOLDER_PACKAGE_NAME),
@@ -1262,8 +1266,8 @@ public class CardEmulationManagerTest {
         when(mRegisteredServicesCache.getService(eq(USER_ID), eq(WALLET_PAYMENT_SERVICE)))
                 .thenReturn(apduServiceInfo);
 
-        Assert.assertEquals(mCardEmulationManager.getNfcCardEmulationInterface()
-                .getPreferredPaymentService(USER_ID), apduServiceInfo);
+        assertEquals(apduServiceInfo, mCardEmulationManager.getNfcCardEmulationInterface()
+                .getPreferredPaymentService(USER_ID));
 
         ExtendedMockito.verify(() -> {
             NfcPermissions.validateUserId(USER_ID);
@@ -1309,7 +1313,7 @@ public class CardEmulationManagerTest {
         when(mRegisteredServicesCache.registerOtherForService(anyInt(), any(), anyBoolean()))
                 .thenReturn(true);
 
-        Assert.assertFalse(mCardEmulationManager.getNfcCardEmulationInterface()
+        assertFalse(mCardEmulationManager.getNfcCardEmulationInterface()
                 .setServiceEnabledForCategoryOther(USER_ID, WALLET_PAYMENT_SERVICE, true));
 
         verify(mRegisteredServicesCache).initialize();
@@ -1340,7 +1344,7 @@ public class CardEmulationManagerTest {
                 .thenReturn(null);
         when(Binder.getCallingUserHandle()).thenReturn(USER_HANDLE);
 
-        Assert.assertFalse(mCardEmulationManager.getNfcCardEmulationInterface()
+        assertFalse(mCardEmulationManager.getNfcCardEmulationInterface()
                 .isDefaultPaymentRegistered());
 
         verify(mWalletRoleObserver, times(2)).isWalletRoleFeatureEnabled();
@@ -1356,8 +1360,9 @@ public class CardEmulationManagerTest {
         String protocol = "DH";
         String technology = "DH";
 
-        Assert.assertFalse(mCardEmulationManager.getNfcCardEmulationInterface()
-                .overrideRoutingTable(USER_ID, protocol, technology));
+        assertThrows(IllegalArgumentException.class,
+                () -> mCardEmulationManager.getNfcCardEmulationInterface()
+                .overrideRoutingTable(USER_ID, protocol, technology, WALLET_HOLDER_PACKAGE_NAME));
 
         verify(mRegisteredAidCache).onWalletRoleHolderChanged(eq(WALLET_HOLDER_PACKAGE_NAME),
                 eq(USER_ID));
@@ -1373,8 +1378,8 @@ public class CardEmulationManagerTest {
         when(mForegroundUtils.registerUidToBackgroundCallback(any(), anyInt()))
                 .thenReturn(true);
 
-        assertTrue(mCardEmulationManager.getNfcCardEmulationInterface()
-                .overrideRoutingTable(USER_ID, null, null));
+        mCardEmulationManager.getNfcCardEmulationInterface()
+                .overrideRoutingTable(USER_ID, null, null, WALLET_HOLDER_PACKAGE_NAME);
 
         verify(mRegisteredAidCache).onWalletRoleHolderChanged(eq(WALLET_HOLDER_PACKAGE_NAME),
                 eq(USER_ID));
@@ -1395,8 +1400,8 @@ public class CardEmulationManagerTest {
         String protocol = "DH";
         String technology = "DH";
 
-        assertTrue(mCardEmulationManager.getNfcCardEmulationInterface()
-                .overrideRoutingTable(USER_ID, protocol, technology));
+        mCardEmulationManager.getNfcCardEmulationInterface()
+                .overrideRoutingTable(USER_ID, protocol, technology, WALLET_HOLDER_PACKAGE_NAME);
 
         verify(mRegisteredAidCache).onWalletRoleHolderChanged(eq(WALLET_HOLDER_PACKAGE_NAME),
                 eq(USER_ID));
@@ -1417,8 +1422,8 @@ public class CardEmulationManagerTest {
         String protocol = "eSE1";
         String technology = "eSE1";
 
-        assertTrue(mCardEmulationManager.getNfcCardEmulationInterface()
-                .overrideRoutingTable(USER_ID, protocol, technology));
+        mCardEmulationManager.getNfcCardEmulationInterface()
+                .overrideRoutingTable(USER_ID, protocol, technology, WALLET_HOLDER_PACKAGE_NAME);
 
         verify(mRegisteredAidCache).onWalletRoleHolderChanged(eq(WALLET_HOLDER_PACKAGE_NAME),
                 eq(USER_ID));
@@ -1439,8 +1444,8 @@ public class CardEmulationManagerTest {
         String protocol = "SIM1";
         String technology = "SIM1";
 
-        assertTrue(mCardEmulationManager.getNfcCardEmulationInterface()
-                .overrideRoutingTable(USER_ID, protocol, technology));
+        mCardEmulationManager.getNfcCardEmulationInterface()
+                .overrideRoutingTable(USER_ID, protocol, technology, WALLET_HOLDER_PACKAGE_NAME);
 
         verify(mRegisteredAidCache).onWalletRoleHolderChanged(eq(WALLET_HOLDER_PACKAGE_NAME),
                 eq(USER_ID));
@@ -1459,8 +1464,8 @@ public class CardEmulationManagerTest {
         when(mForegroundUtils.isInForeground(anyInt()))
                 .thenReturn(true);
 
-        assertTrue(mCardEmulationManager.getNfcCardEmulationInterface()
-                .recoverRoutingTable(USER_ID));
+        mCardEmulationManager.getNfcCardEmulationInterface()
+                .recoverRoutingTable(USER_ID);
 
         verify(mRegisteredAidCache).onWalletRoleHolderChanged(eq(WALLET_HOLDER_PACKAGE_NAME),
                 eq(USER_ID));
@@ -1478,7 +1483,8 @@ public class CardEmulationManagerTest {
         when(mForegroundUtils.isInForeground(anyInt()))
                 .thenReturn(false);
 
-        Assert.assertFalse(mCardEmulationManager.getNfcCardEmulationInterface()
+        assertThrows(IllegalArgumentException.class,
+                () -> mCardEmulationManager.getNfcCardEmulationInterface()
                 .recoverRoutingTable(USER_ID));
 
         verify(mRegisteredAidCache).onWalletRoleHolderChanged(eq(WALLET_HOLDER_PACKAGE_NAME),
@@ -1498,8 +1504,8 @@ public class CardEmulationManagerTest {
         when(mRegisteredNfcFServicesCache.getSystemCodeForService(anyInt(),
                 anyInt(), any())).thenReturn(systemCode);
 
-        Assert.assertEquals(mCardEmulationManager.getNfcFCardEmulationInterface()
-                .getSystemCodeForService(USER_ID, WALLET_PAYMENT_SERVICE), systemCode);
+        assertEquals(systemCode, mCardEmulationManager.getNfcFCardEmulationInterface()
+                .getSystemCodeForService(USER_ID, WALLET_PAYMENT_SERVICE));
 
         ExtendedMockito.verify(() -> {
             NfcPermissions.validateUserId(USER_ID);
@@ -1524,7 +1530,7 @@ public class CardEmulationManagerTest {
         when(mRegisteredNfcFServicesCache.getSystemCodeForService(anyInt(),
                 anyInt(), any())).thenReturn(systemCode);
 
-        Assert.assertNull(mCardEmulationManager.getNfcFCardEmulationInterface()
+        assertNull(mCardEmulationManager.getNfcFCardEmulationInterface()
                 .getSystemCodeForService(USER_ID, WALLET_PAYMENT_SERVICE));
 
         ExtendedMockito.verify(() -> {
@@ -1575,7 +1581,7 @@ public class CardEmulationManagerTest {
         when(mRegisteredNfcFServicesCache.registerSystemCodeForService(anyInt(),
                 anyInt(), any(), anyString())).thenReturn(true);
 
-        Assert.assertFalse(mCardEmulationManager.getNfcFCardEmulationInterface()
+        assertFalse(mCardEmulationManager.getNfcFCardEmulationInterface()
                 .registerSystemCodeForService(USER_ID, WALLET_PAYMENT_SERVICE, systemCode));
 
         ExtendedMockito.verify(() -> {
@@ -1624,7 +1630,7 @@ public class CardEmulationManagerTest {
         when(mRegisteredNfcFServicesCache.removeSystemCodeForService(anyInt(),
                 anyInt(), any())).thenReturn(true);
 
-        Assert.assertFalse(mCardEmulationManager.getNfcFCardEmulationInterface()
+        assertFalse(mCardEmulationManager.getNfcFCardEmulationInterface()
                 .removeSystemCodeForService(USER_ID, WALLET_PAYMENT_SERVICE));
 
         ExtendedMockito.verify(() -> {
@@ -1649,8 +1655,8 @@ public class CardEmulationManagerTest {
         when(mRegisteredNfcFServicesCache.getNfcid2ForService(anyInt(),
                 anyInt(), any())).thenReturn(nfcid2);
 
-        Assert.assertEquals(mCardEmulationManager.getNfcFCardEmulationInterface()
-                .getNfcid2ForService(USER_ID, WALLET_PAYMENT_SERVICE), nfcid2);
+        assertEquals(nfcid2, mCardEmulationManager.getNfcFCardEmulationInterface()
+                .getNfcid2ForService(USER_ID, WALLET_PAYMENT_SERVICE));
 
         ExtendedMockito.verify(() -> {
             NfcPermissions.validateUserId(USER_ID);
@@ -1675,7 +1681,7 @@ public class CardEmulationManagerTest {
         when(mRegisteredNfcFServicesCache.getNfcid2ForService(anyInt(),
                 anyInt(), any())).thenReturn(nfcid2);
 
-        Assert.assertNull(mCardEmulationManager.getNfcFCardEmulationInterface()
+        assertNull(mCardEmulationManager.getNfcFCardEmulationInterface()
                 .getNfcid2ForService(USER_ID, WALLET_PAYMENT_SERVICE));
 
         ExtendedMockito.verify(() -> {
@@ -1726,7 +1732,7 @@ public class CardEmulationManagerTest {
         when(mRegisteredNfcFServicesCache.setNfcid2ForService(anyInt(),
                 anyInt(), any(), anyString())).thenReturn(true);
 
-        Assert.assertFalse(mCardEmulationManager.getNfcFCardEmulationInterface()
+        assertFalse(mCardEmulationManager.getNfcFCardEmulationInterface()
                 .setNfcid2ForService(USER_ID, WALLET_PAYMENT_SERVICE, nfcid2));
 
         ExtendedMockito.verify(() -> {
@@ -1773,7 +1779,7 @@ public class CardEmulationManagerTest {
         when(mEnabledNfcFServices.registerEnabledForegroundService(any(),
                 anyInt())).thenReturn(true);
 
-        Assert.assertFalse(mCardEmulationManager.getNfcFCardEmulationInterface()
+        assertFalse(mCardEmulationManager.getNfcFCardEmulationInterface()
                 .enableNfcFForegroundService(WALLET_PAYMENT_SERVICE));
 
         ExtendedMockito.verify(() -> {
@@ -1809,8 +1815,8 @@ public class CardEmulationManagerTest {
         when(mRegisteredNfcFServicesCache.getServices(anyInt()))
                 .thenReturn(UPDATED_NFC_SERVICES);
 
-        Assert.assertEquals(mCardEmulationManager.getNfcFCardEmulationInterface()
-                .getNfcFServices(USER_ID), UPDATED_NFC_SERVICES);
+        assertEquals(UPDATED_NFC_SERVICES, mCardEmulationManager.getNfcFCardEmulationInterface()
+                .getNfcFServices(USER_ID));
 
         ExtendedMockito.verify(() -> {
             NfcPermissions.validateProfileId(mContext, USER_ID);
@@ -1826,10 +1832,11 @@ public class CardEmulationManagerTest {
     @Test
     public void testNfcFCardEmulationGetMaxNumOfRegisterableSystemCodes()
             throws RemoteException {
-        when(mNfcService.getLfT3tMax()).thenReturn(3);
+        int MAX = 3;
+        when(mNfcService.getLfT3tMax()).thenReturn(MAX);
 
-        Assert.assertEquals(mCardEmulationManager.getNfcFCardEmulationInterface()
-                .getMaxNumOfRegisterableSystemCodes(), 3);
+        assertEquals(MAX, mCardEmulationManager.getNfcFCardEmulationInterface()
+                .getMaxNumOfRegisterableSystemCodes());
 
         ExtendedMockito.verify(() -> {
             NfcPermissions.enforceUserPermissions(mContext);
@@ -1898,8 +1905,6 @@ public class CardEmulationManagerTest {
                 eq(WALLET_HOLDER_PACKAGE_NAME), eq(USER_ID));
         verify(mHostEmulationManager).onPreferredForegroundServiceChanged(eq(USER_ID),
                 eq(WALLET_PAYMENT_SERVICE));
-        verify(mRegisteredAidCache).onPreferredForegroundServiceChanged(eq(USER_ID),
-                eq(WALLET_PAYMENT_SERVICE));
         verify(mRegisteredServicesCache).initialize();
         verify(mNfcService).onPreferredPaymentChanged(eq(NfcAdapter.PREFERRED_PAYMENT_CHANGED));
     }
@@ -1918,8 +1923,6 @@ public class CardEmulationManagerTest {
                 eq(WALLET_PAYMENT_SERVICE));
         verify(mRegisteredAidCache).onWalletRoleHolderChanged(
                 eq(WALLET_HOLDER_PACKAGE_NAME), eq(USER_ID));
-        verify(mRegisteredAidCache).onPreferredForegroundServiceChanged(eq(USER_ID),
-                eq(WALLET_PAYMENT_SERVICE));
         verify(mRegisteredServicesCache).initialize();
         verify(mNfcService).onPreferredPaymentChanged(eq(NfcAdapter.PREFERRED_PAYMENT_CHANGED));
         assertUpdateForShouldDefaultToObserveMode(false);
@@ -1987,8 +1990,8 @@ public class CardEmulationManagerTest {
 
         when(mRegisteredAidCache.resolveAid(anyString())).thenReturn(aidResolveInfo);
 
-        Assert.assertEquals(mCardEmulationManager.getRegisteredAidCategory(PAYMENT_AID_1),
-                CardEmulation.CATEGORY_PAYMENT);
+        assertEquals(CardEmulation.CATEGORY_PAYMENT,
+            mCardEmulationManager.getRegisteredAidCategory(PAYMENT_AID_1));
 
         verify(mRegisteredAidCache).resolveAid(eq(PAYMENT_AID_1));
         verify(aidResolveInfo).getCategory();
diff --git a/tests/unit/src/com/android/nfc/cardemulation/HostEmulationManagerTest.java b/tests/unit/src/com/android/nfc/cardemulation/HostEmulationManagerTest.java
index 6090bd87..dbfec389 100644
--- a/tests/unit/src/com/android/nfc/cardemulation/HostEmulationManagerTest.java
+++ b/tests/unit/src/com/android/nfc/cardemulation/HostEmulationManagerTest.java
@@ -15,6 +15,11 @@
  */
 package com.android.nfc.cardemulation;
 
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.assertNotNull;
+import static org.junit.Assert.assertNull;
+import static org.junit.Assert.assertTrue;
 import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.ArgumentMatchers.anyList;
@@ -44,6 +49,7 @@ import android.os.IBinder;
 import android.os.Message;
 import android.os.Messenger;
 import android.os.PowerManager;
+import android.os.Process;
 import android.os.RemoteException;
 import android.os.UserHandle;
 import android.testing.AndroidTestingRunner;
@@ -58,7 +64,6 @@ import com.android.nfc.NfcStatsLog;
 import com.android.nfc.cardemulation.util.StatsdUtils;
 
 import org.junit.After;
-import org.junit.Assert;
 import org.junit.Before;
 import org.junit.Test;
 import org.junit.runner.RunWith;
@@ -109,7 +114,7 @@ public class HostEmulationManagerTest {
     @Mock
     private NfcAdapter mNfcAdapter;
     @Mock
-    private Messenger mMessanger;
+    private Messenger mMessenger;
     @Mock
     private NfcService mNfcService;
     @Mock
@@ -199,13 +204,11 @@ public class HostEmulationManagerTest {
                 eq(userHandle));
         verifyNoMoreInteractions(mContext);
         Intent intent = mIntentArgumentCaptor.getValue();
-        Assert.assertEquals(intent.getAction(), HostApduService.SERVICE_INTERFACE);
-        Assert.assertEquals(intent.getComponent(), WALLET_PAYMENT_SERVICE);
-        Assert.assertTrue(mHostEmulationManager.mPaymentServiceBound);
-        Assert.assertEquals(mHostEmulationManager.mLastBoundPaymentServiceName,
-                WALLET_PAYMENT_SERVICE);
-        Assert.assertEquals(mHostEmulationManager.mPaymentServiceUserId,
-                USER_ID);
+        assertEquals(HostApduService.SERVICE_INTERFACE, intent.getAction());
+        assertEquals(WALLET_PAYMENT_SERVICE, intent.getComponent());
+        assertTrue(mHostEmulationManager.mPaymentServiceBound);
+        assertEquals(WALLET_PAYMENT_SERVICE, mHostEmulationManager.mLastBoundPaymentServiceName);
+        assertEquals(USER_ID, mHostEmulationManager.mPaymentServiceUserId);
     }
 
     @Test
@@ -226,14 +229,12 @@ public class HostEmulationManagerTest {
                 eq(userHandle));
         verifyNoMoreInteractions(mContext);
         Intent intent = mIntentArgumentCaptor.getValue();
-        Assert.assertEquals(intent.getAction(), HostApduService.SERVICE_INTERFACE);
-        Assert.assertEquals(intent.getComponent(), WALLET_PAYMENT_SERVICE);
-        Assert.assertTrue(mHostEmulationManager.mPaymentServiceBound);
-        Assert.assertEquals(mHostEmulationManager.mLastBoundPaymentServiceName,
-                WALLET_PAYMENT_SERVICE);
-        Assert.assertEquals(mHostEmulationManager.mPaymentServiceUserId,
-                USER_ID);
-        Assert.assertNotNull(mServiceConnectionArgumentCaptor.getValue());
+        assertEquals(HostApduService.SERVICE_INTERFACE, intent.getAction());
+        assertEquals(WALLET_PAYMENT_SERVICE, intent.getComponent());
+        assertTrue(mHostEmulationManager.mPaymentServiceBound);
+        assertEquals(WALLET_PAYMENT_SERVICE, mHostEmulationManager.mLastBoundPaymentServiceName);
+        assertEquals(USER_ID, mHostEmulationManager.mPaymentServiceUserId);
+        assertNotNull(mServiceConnectionArgumentCaptor.getValue());
     }
 
     @Test
@@ -253,15 +254,15 @@ public class HostEmulationManagerTest {
                 = mHostEmulationManager.getPollingLoopFilters();
         Map<Integer, Map<Pattern, List<ApduServiceInfo>>> pollingLoopPatternFilters
                 = mHostEmulationManager.getPollingLoopPatternFilters();
-        Assert.assertTrue(pollingLoopFilters.containsKey(USER_ID));
-        Assert.assertTrue(pollingLoopPatternFilters.containsKey(USER_ID));
+        assertTrue(pollingLoopFilters.containsKey(USER_ID));
+        assertTrue(pollingLoopPatternFilters.containsKey(USER_ID));
         Map<String, List<ApduServiceInfo>> filtersForUser = pollingLoopFilters.get(USER_ID);
         Map<Pattern, List<ApduServiceInfo>> patternFiltersForUser = pollingLoopPatternFilters
                 .get(USER_ID);
-        Assert.assertTrue(filtersForUser.containsKey(PL_FILTER));
-        Assert.assertTrue(patternFiltersForUser.containsKey(PL_PATTERN));
-        Assert.assertTrue(filtersForUser.get(PL_FILTER).contains(serviceWithFilter));
-        Assert.assertTrue(patternFiltersForUser.get(PL_PATTERN).contains(serviceWithPatternFilter));
+        assertTrue(filtersForUser.containsKey(PL_FILTER));
+        assertTrue(patternFiltersForUser.containsKey(PL_PATTERN));
+        assertTrue(filtersForUser.get(PL_FILTER).contains(serviceWithFilter));
+        assertTrue(patternFiltersForUser.get(PL_PATTERN).contains(serviceWithPatternFilter));
     }
 
     @Test
@@ -298,7 +299,7 @@ public class HostEmulationManagerTest {
         PollingFrame frame2 = new PollingFrame(PollingFrame.POLLING_LOOP_TYPE_OFF,
                 null, 0, 0, false);
 
-        mHostEmulationManager.mActiveService = mMessanger;
+        mHostEmulationManager.mActiveService = mMessenger;
 
         mHostEmulationManager.onPollingLoopDetected(List.of(frame1, frame2));
         mTestableLooper.processAllMessages();
@@ -307,13 +308,12 @@ public class HostEmulationManagerTest {
         verify(mContext).getSystemService(eq(KeyguardManager.class));
         verify(mRegisteredAidCache)
                 .resolvePollingLoopFilterConflict(mServiceListArgumentCaptor.capture());
-        Assert.assertTrue(mServiceListArgumentCaptor.getValue().contains(serviceWithFilter));
-        Assert.assertTrue(mServiceListArgumentCaptor.getValue()
-                .contains(overlappingServiceWithFilter));
+        assertTrue(mServiceListArgumentCaptor.getValue().contains(serviceWithFilter));
+        assertTrue(mServiceListArgumentCaptor.getValue().contains(overlappingServiceWithFilter));
         verify(mNfcAdapter).setObserveModeEnabled(eq(false));
-        Assert.assertTrue(mHostEmulationManager.mEnableObserveModeAfterTransaction);
-        Assert.assertTrue(frame1.getTriggeredAutoTransact());
-        Assert.assertEquals(mHostEmulationManager.mState, HostEmulationManager.STATE_POLLING_LOOP);
+        assertTrue(mHostEmulationManager.mEnableObserveModeAfterTransaction);
+        assertTrue(frame1.getTriggeredAutoTransact());
+        assertEquals(HostEmulationManager.STATE_POLLING_LOOP, mHostEmulationManager.mState);
     }
 
     @Test
@@ -341,25 +341,25 @@ public class HostEmulationManagerTest {
                 null, 0, 0, false);
         PollingFrame frame4 = new PollingFrame(PollingFrame.POLLING_LOOP_TYPE_OFF,
                 null, 0, 0, false);
-        mHostEmulationManager.mPaymentService = mMessanger;
+        mHostEmulationManager.mPaymentService = mMessenger;
         mHostEmulationManager.mPaymentServiceName = WALLET_PAYMENT_SERVICE;
 
         mHostEmulationManager.onPollingLoopDetected(List.of(frame1, frame2, frame3, frame4));
 
         verify(mContext).getSystemService(eq(PowerManager.class));
         verify(mContext).getSystemService(eq(KeyguardManager.class));
-        verify(mMessanger).send(mMessageArgumentCaptor.capture());
+        verify(mMessenger).send(mMessageArgumentCaptor.capture());
         Message message = mMessageArgumentCaptor.getValue();
         Bundle bundle = message.getData();
-        Assert.assertEquals(message.what, HostApduService.MSG_POLLING_LOOP);
-        Assert.assertTrue(bundle.containsKey(HostApduService.KEY_POLLING_LOOP_FRAMES_BUNDLE));
+        assertEquals(HostApduService.MSG_POLLING_LOOP, message.what);
+        assertTrue(bundle.containsKey(HostApduService.KEY_POLLING_LOOP_FRAMES_BUNDLE));
         ArrayList<PollingFrame> sentFrames = bundle
                 .getParcelableArrayList(HostApduService.KEY_POLLING_LOOP_FRAMES_BUNDLE);
-        Assert.assertTrue(sentFrames.contains(frame1));
-        Assert.assertTrue(sentFrames.contains(frame2));
-        Assert.assertTrue(sentFrames.contains(frame3));
-        Assert.assertTrue(sentFrames.contains(frame4));
-        Assert.assertNull(mHostEmulationManager.mPendingPollingLoopFrames);
+        assertTrue(sentFrames.contains(frame1));
+        assertTrue(sentFrames.contains(frame2));
+        assertTrue(sentFrames.contains(frame3));
+        assertTrue(sentFrames.contains(frame4));
+        assertNull(mHostEmulationManager.mPendingPollingLoopFrames);
     }
 
     @Test
@@ -377,10 +377,10 @@ public class HostEmulationManagerTest {
                 eq(userHandle));
         verifyNoMoreInteractions(mContext);
         Intent intent = mIntentArgumentCaptor.getValue();
-        Assert.assertEquals(intent.getAction(), HostApduService.SERVICE_INTERFACE);
-        Assert.assertEquals(intent.getComponent(), WALLET_PAYMENT_SERVICE);
-        Assert.assertTrue(mHostEmulationManager.mServiceBound);
-        Assert.assertEquals(mHostEmulationManager.mServiceUserId, USER_ID);
+        assertEquals(HostApduService.SERVICE_INTERFACE, intent.getAction());
+        assertEquals(WALLET_PAYMENT_SERVICE, intent.getComponent());
+        assertTrue(mHostEmulationManager.mServiceBound);
+        assertEquals(USER_ID, mHostEmulationManager.mServiceUserId);
     }
 
     @Test
@@ -412,11 +412,11 @@ public class HostEmulationManagerTest {
                 eq(userHandle));
         verifyNoMoreInteractions(mContext);
         Intent intent = mIntentArgumentCaptor.getValue();
-        Assert.assertEquals(intent.getAction(), HostApduService.SERVICE_INTERFACE);
-        Assert.assertEquals(intent.getComponent(), WALLET_PAYMENT_SERVICE);
-        Assert.assertTrue(mHostEmulationManager.mServiceBound);
-        Assert.assertEquals(mHostEmulationManager.mServiceUserId, USER_ID);
-        Assert.assertNotNull(mServiceConnectionArgumentCaptor.getValue());
+        assertEquals(HostApduService.SERVICE_INTERFACE, intent.getAction());
+        assertEquals(WALLET_PAYMENT_SERVICE, intent.getComponent());
+        assertTrue(mHostEmulationManager.mServiceBound);
+        assertEquals(USER_ID, mHostEmulationManager.mServiceUserId);
+        assertNotNull(mServiceConnectionArgumentCaptor.getValue());
     }
 
     @Test
@@ -425,11 +425,11 @@ public class HostEmulationManagerTest {
 
         // Should not change state immediately
         mHostEmulationManager.onFieldChangeDetected(false);
-        Assert.assertEquals(HostEmulationManager.STATE_XFER, mHostEmulationManager.getState());
+        assertEquals(HostEmulationManager.STATE_XFER, mHostEmulationManager.getState());
 
         mTestableLooper.moveTimeForward(5000);
         mTestableLooper.processAllMessages();
-        Assert.assertEquals(HostEmulationManager.STATE_IDLE, mHostEmulationManager.getState());
+        assertEquals(HostEmulationManager.STATE_IDLE, mHostEmulationManager.getState());
     }
 
     @Test
@@ -439,12 +439,11 @@ public class HostEmulationManagerTest {
         PollingFrame frame2 = new PollingFrame(PollingFrame.POLLING_LOOP_TYPE_OFF,
                 null, 0, 0, false);
         mHostEmulationManager.onPollingLoopDetected(List.of(frame1, frame2));
-        Assert.assertEquals(HostEmulationManager.STATE_POLLING_LOOP,
-                mHostEmulationManager.getState());
+        assertEquals(HostEmulationManager.STATE_POLLING_LOOP, mHostEmulationManager.getState());
 
         mTestableLooper.moveTimeForward(5000);
         mTestableLooper.processAllMessages();
-        Assert.assertEquals(HostEmulationManager.STATE_IDLE, mHostEmulationManager.getState());
+        assertEquals(HostEmulationManager.STATE_IDLE, mHostEmulationManager.getState());
     }
 
     @Test
@@ -457,9 +456,9 @@ public class HostEmulationManagerTest {
                 eq(UserHandle.ALL));
         verifyNoMoreInteractions(mContext);
         Intent intent = mIntentArgumentCaptor.getValue();
-        Assert.assertEquals(TapAgainDialog.ACTION_CLOSE, intent.getAction());
-        Assert.assertEquals(HostEmulationManager.NFC_PACKAGE, intent.getPackage());
-        Assert.assertEquals(HostEmulationManager.STATE_W4_SELECT, mHostEmulationManager.getState());
+        assertEquals(TapAgainDialog.ACTION_CLOSE, intent.getAction());
+        assertEquals(HostEmulationManager.NFC_PACKAGE, intent.getPackage());
+        assertEquals(HostEmulationManager.STATE_W4_SELECT, mHostEmulationManager.getState());
     }
 
     @Test
@@ -469,7 +468,7 @@ public class HostEmulationManagerTest {
 
         mTestableLooper.moveTimeForward(5000);
         mTestableLooper.processAllMessages();
-        Assert.assertEquals(HostEmulationManager.STATE_W4_SELECT, mHostEmulationManager.getState());
+        assertEquals(HostEmulationManager.STATE_W4_SELECT, mHostEmulationManager.getState());
     }
 
     @Test
@@ -684,8 +683,7 @@ public class HostEmulationManagerTest {
         });
         verify(mStatsUtils).setCardEmulationEventCategory(eq(CardEmulation.CATEGORY_OTHER));
         verify(mStatsUtils).logCardEmulationWrongSettingEvent();
-        Assert.assertEquals(HostEmulationManager.STATE_W4_DEACTIVATE,
-                mHostEmulationManager.getState());
+        assertEquals(HostEmulationManager.STATE_W4_DEACTIVATE, mHostEmulationManager.getState());
         verify(mRegisteredAidCache).resolveAid(eq(MOCK_AID));
         verify(mContext).getSystemService(eq(PowerManager.class));
         verify(mContext).getSystemService(eq(KeyguardManager.class));
@@ -714,15 +712,15 @@ public class HostEmulationManagerTest {
         when(mPowerManager.isScreenOn()).thenReturn(true);
         when(mRegisteredAidCache.resolveAid(eq(MOCK_AID))).thenReturn(aidResolveInfo);
         mHostEmulationManager.mActiveServiceName = WALLET_PAYMENT_SERVICE;
-        mHostEmulationManager.mActiveService = mMessanger;
-        when(mMessanger.getBinder()).thenReturn(binder);
+        mHostEmulationManager.mActiveService = mMessenger;
+        when(mMessenger.getBinder()).thenReturn(binder);
         mHostEmulationManager.mPaymentServiceBound = true;
         mHostEmulationManager.mPaymentServiceName = WALLET_PAYMENT_SERVICE;
-        mHostEmulationManager.mPaymentService = mMessanger;
+        mHostEmulationManager.mPaymentService = mMessenger;
 
         mHostEmulationManager.onHostEmulationData(mockAidData);
 
-        Assert.assertEquals(HostEmulationManager.STATE_XFER, mHostEmulationManager.getState());
+        assertEquals(HostEmulationManager.STATE_XFER, mHostEmulationManager.getState());
         verify(apduServiceInfo).getUid();
         verify(mStatsUtils).setCardEmulationEventCategory(eq(CardEmulation.CATEGORY_PAYMENT));
         verify(mStatsUtils).setCardEmulationEventUid(eq(USER_ID));
@@ -731,13 +729,13 @@ public class HostEmulationManagerTest {
         verify(mContext).getSystemService(eq(PowerManager.class));
         verify(mContext).getSystemService(eq(KeyguardManager.class));
         verifyNoMoreInteractions(mContext);
-        verify(mMessanger).send(mMessageArgumentCaptor.capture());
+        verify(mMessenger).send(mMessageArgumentCaptor.capture());
         Message message = mMessageArgumentCaptor.getValue();
         Bundle bundle = message.getData();
-        Assert.assertEquals(message.what, HostApduService.MSG_COMMAND_APDU);
-        Assert.assertTrue(bundle.containsKey(HostEmulationManager.DATA_KEY));
-        Assert.assertEquals(mockAidData, bundle.getByteArray(HostEmulationManager.DATA_KEY));
-        Assert.assertEquals(mHostEmulationManager.getLocalMessenger(), message.replyTo);
+        assertEquals(HostApduService.MSG_COMMAND_APDU, message.what);
+        assertTrue(bundle.containsKey(HostEmulationManager.DATA_KEY));
+        assertEquals(mockAidData, bundle.getByteArray(HostEmulationManager.DATA_KEY));
+        assertEquals(mHostEmulationManager.getLocalMessenger(), message.replyTo);
     }
 
     @Test
@@ -765,9 +763,8 @@ public class HostEmulationManagerTest {
 
         mHostEmulationManager.onHostEmulationData(mockAidData);
 
-        Assert.assertEquals(HostEmulationManager.STATE_W4_SERVICE,
-                mHostEmulationManager.getState());
-        Assert.assertEquals(mockAidData, mHostEmulationManager.mSelectApdu);
+        assertEquals(HostEmulationManager.STATE_W4_SERVICE, mHostEmulationManager.getState());
+        assertEquals(mockAidData, mHostEmulationManager.mSelectApdu);
         verify(apduServiceInfo).getUid();
         verify(mStatsUtils).setCardEmulationEventCategory(eq(CardEmulation.CATEGORY_PAYMENT));
         verify(mStatsUtils).setCardEmulationEventUid(eq(USER_ID));
@@ -780,12 +777,12 @@ public class HostEmulationManagerTest {
                 eq(Context.BIND_AUTO_CREATE | Context.BIND_ALLOW_BACKGROUND_ACTIVITY_STARTS),
                 eq(USER_HANDLE));
         Intent intent = mIntentArgumentCaptor.getValue();
-        Assert.assertEquals(intent.getAction(), HostApduService.SERVICE_INTERFACE);
-        Assert.assertEquals(intent.getComponent(), WALLET_PAYMENT_SERVICE);
-        Assert.assertEquals(mHostEmulationManager.getServiceConnection(),
+        assertEquals(HostApduService.SERVICE_INTERFACE, intent.getAction());
+        assertEquals(WALLET_PAYMENT_SERVICE, intent.getComponent());
+        assertEquals(mHostEmulationManager.getServiceConnection(),
                 mServiceConnectionArgumentCaptor.getValue());
-        Assert.assertTrue(mHostEmulationManager.mServiceBound);
-        Assert.assertEquals(USER_ID, mHostEmulationManager.mServiceUserId);
+        assertTrue(mHostEmulationManager.mServiceBound);
+        assertEquals(USER_ID, mHostEmulationManager.mServiceUserId);
         verifyNoMoreInteractions(mContext);
     }
 
@@ -794,7 +791,7 @@ public class HostEmulationManagerTest {
         mHostEmulationManager.mState = HostEmulationManager.STATE_W4_SELECT;
         mHostEmulationManager.mPaymentServiceBound = true;
         mHostEmulationManager.mPaymentServiceName = WALLET_PAYMENT_SERVICE;
-        mHostEmulationManager.mPaymentService = mMessanger;
+        mHostEmulationManager.mPaymentService = mMessenger;
 
         mHostEmulationManager.onHostEmulationData(null);
 
@@ -822,19 +819,19 @@ public class HostEmulationManagerTest {
         byte[] data = new byte[3];
         mHostEmulationManager.mState = HostEmulationManager.STATE_XFER;
         mHostEmulationManager.mActiveServiceName = WALLET_PAYMENT_SERVICE;
-        mHostEmulationManager.mActiveService = mMessanger;
+        mHostEmulationManager.mActiveService = mMessenger;
 
         mHostEmulationManager.onHostEmulationData(data);
 
         verify(mContext).getSystemService(eq(PowerManager.class));
         verify(mContext).getSystemService(eq(KeyguardManager.class));
-        verify(mMessanger).send(mMessageArgumentCaptor.capture());
+        verify(mMessenger).send(mMessageArgumentCaptor.capture());
         Message message = mMessageArgumentCaptor.getValue();
         Bundle bundle = message.getData();
-        Assert.assertEquals(message.what, HostApduService.MSG_COMMAND_APDU);
-        Assert.assertTrue(bundle.containsKey(HostEmulationManager.DATA_KEY));
-        Assert.assertEquals(data, bundle.getByteArray(HostEmulationManager.DATA_KEY));
-        Assert.assertEquals(mHostEmulationManager.getLocalMessenger(), message.replyTo);
+        assertEquals(HostApduService.MSG_COMMAND_APDU, message.what);
+        assertTrue(bundle.containsKey(HostEmulationManager.DATA_KEY));
+        assertEquals(data, bundle.getByteArray(HostEmulationManager.DATA_KEY));
+        assertEquals(mHostEmulationManager.getLocalMessenger(), message.replyTo);
         verifyNoMoreInteractions(mNfcService);
         verifyNoMoreInteractions(mContext);
     }
@@ -858,24 +855,24 @@ public class HostEmulationManagerTest {
         when(mPowerManager.isScreenOn()).thenReturn(true);
         when(mRegisteredAidCache.resolveAid(eq(MOCK_AID))).thenReturn(aidResolveInfo);
         mHostEmulationManager.mActiveServiceName = WALLET_PAYMENT_SERVICE;
-        mHostEmulationManager.mActiveService = mMessanger;
-        when(mMessanger.getBinder()).thenReturn(binder);
+        mHostEmulationManager.mActiveService = mMessenger;
+        when(mMessenger.getBinder()).thenReturn(binder);
         mHostEmulationManager.mPaymentServiceBound = true;
         mHostEmulationManager.mPaymentServiceName = WALLET_PAYMENT_SERVICE;
-        mHostEmulationManager.mPaymentService = mMessanger;
+        mHostEmulationManager.mPaymentService = mMessenger;
 
         mHostEmulationManager.onHostEmulationData(mockAidData);
 
-        Assert.assertEquals(HostEmulationManager.STATE_XFER, mHostEmulationManager.getState());
+        assertEquals(HostEmulationManager.STATE_XFER, mHostEmulationManager.getState());
         verify(mContext).getSystemService(eq(PowerManager.class));
         verify(mContext).getSystemService(eq(KeyguardManager.class));
-        verify(mMessanger).send(mMessageArgumentCaptor.capture());
+        verify(mMessenger).send(mMessageArgumentCaptor.capture());
         Message message = mMessageArgumentCaptor.getValue();
         Bundle bundle = message.getData();
-        Assert.assertEquals(message.what, HostApduService.MSG_COMMAND_APDU);
-        Assert.assertTrue(bundle.containsKey(HostEmulationManager.DATA_KEY));
-        Assert.assertEquals(mockAidData, bundle.getByteArray(HostEmulationManager.DATA_KEY));
-        Assert.assertEquals(mHostEmulationManager.getLocalMessenger(), message.replyTo);
+        assertEquals(HostApduService.MSG_COMMAND_APDU, message.what);
+        assertTrue(bundle.containsKey(HostEmulationManager.DATA_KEY));
+        assertEquals(mockAidData, bundle.getByteArray(HostEmulationManager.DATA_KEY));
+        assertEquals(mHostEmulationManager.getLocalMessenger(), message.replyTo);
         verifyNoMoreInteractions(mContext);
     }
 
@@ -904,8 +901,7 @@ public class HostEmulationManagerTest {
 
         mHostEmulationManager.onHostEmulationData(mockAidData);
 
-        Assert.assertEquals(HostEmulationManager.STATE_W4_SERVICE,
-                mHostEmulationManager.getState());
+        assertEquals(HostEmulationManager.STATE_W4_SERVICE, mHostEmulationManager.getState());
         verify(mContext).getSystemService(eq(PowerManager.class));
         verify(mContext).getSystemService(eq(KeyguardManager.class));
         verify(mContext).bindServiceAsUser(mIntentArgumentCaptor.capture(),
@@ -913,12 +909,12 @@ public class HostEmulationManagerTest {
                 eq(Context.BIND_AUTO_CREATE | Context.BIND_ALLOW_BACKGROUND_ACTIVITY_STARTS),
                 eq(USER_HANDLE));
         Intent intent = mIntentArgumentCaptor.getValue();
-        Assert.assertEquals(intent.getAction(), HostApduService.SERVICE_INTERFACE);
-        Assert.assertEquals(intent.getComponent(), WALLET_PAYMENT_SERVICE);
-        Assert.assertEquals(mHostEmulationManager.getServiceConnection(),
+        assertEquals(HostApduService.SERVICE_INTERFACE, intent.getAction());
+        assertEquals(WALLET_PAYMENT_SERVICE, intent.getComponent());
+        assertEquals(mHostEmulationManager.getServiceConnection(),
                 mServiceConnectionArgumentCaptor.getValue());
-        Assert.assertTrue(mHostEmulationManager.mServiceBound);
-        Assert.assertEquals(USER_ID, mHostEmulationManager.mServiceUserId);
+        assertTrue(mHostEmulationManager.mServiceBound);
+        assertEquals(USER_ID, mHostEmulationManager.mServiceUserId);
         verifyNoMoreInteractions(mContext);
     }
 
@@ -932,13 +928,13 @@ public class HostEmulationManagerTest {
 
         mTestableLooper.moveTimeForward(5000);
         mTestableLooper.processAllMessages();
-        Assert.assertEquals(HostEmulationManager.STATE_XFER, mHostEmulationManager.getState());
+        assertEquals(HostEmulationManager.STATE_XFER, mHostEmulationManager.getState());
     }
 
     @Test
     public void testOnHostEmulationDeactivated_activeService_enableObserveModeAfterTransaction()
             throws RemoteException {
-        mHostEmulationManager.mActiveService = mMessanger;
+        mHostEmulationManager.mActiveService = mMessenger;
         mHostEmulationManager.mServiceBound = true;
         mHostEmulationManager.mServiceUserId = USER_ID;
         mHostEmulationManager.mServiceName = WALLET_PAYMENT_SERVICE;
@@ -947,31 +943,31 @@ public class HostEmulationManagerTest {
         mHostEmulationManager.onHostEmulationDeactivated();
         mTestableLooper.processAllMessages();
 
-        Assert.assertNull(mHostEmulationManager.mActiveService);
-        Assert.assertNull(mHostEmulationManager.mActiveServiceName);
-        Assert.assertNull(mHostEmulationManager.mServiceName);
-        Assert.assertNull(mHostEmulationManager.mService);
-        Assert.assertNull(mHostEmulationManager.mPendingPollingLoopFrames);
-        Assert.assertEquals(-1, mHostEmulationManager.mActiveServiceUserId);
-        Assert.assertEquals(-1, mHostEmulationManager.mServiceUserId);
-        Assert.assertEquals(HostEmulationManager.STATE_IDLE, mHostEmulationManager.getState());
-        Assert.assertFalse(mHostEmulationManager.mServiceBound);
-        verify(mMessanger).send(mMessageArgumentCaptor.capture());
+        assertNull(mHostEmulationManager.mActiveService);
+        assertNull(mHostEmulationManager.mActiveServiceName);
+        assertNull(mHostEmulationManager.mServiceName);
+        assertNull(mHostEmulationManager.mService);
+        assertNull(mHostEmulationManager.mPendingPollingLoopFrames);
+        assertEquals(Process.INVALID_UID, mHostEmulationManager.mActiveServiceUserId);
+        assertEquals(Process.INVALID_UID, mHostEmulationManager.mServiceUserId);
+        assertEquals(HostEmulationManager.STATE_IDLE, mHostEmulationManager.getState());
+        assertFalse(mHostEmulationManager.mServiceBound);
+        verify(mMessenger).send(mMessageArgumentCaptor.capture());
         Message message = mMessageArgumentCaptor.getValue();
-        Assert.assertEquals(message.what, HostApduService.MSG_DEACTIVATED);
-        Assert.assertEquals(message.arg1, HostApduService.DEACTIVATION_LINK_LOSS);
+        assertEquals(HostApduService.MSG_DEACTIVATED, message.what);
+        assertEquals(HostApduService.DEACTIVATION_LINK_LOSS, message.arg1);
         verify(mContext).getSystemService(eq(PowerManager.class));
         verify(mContext).getSystemService(eq(KeyguardManager.class));
         verify(mContext).unbindService(mServiceConnectionArgumentCaptor.capture());
-        Assert.assertEquals(mHostEmulationManager.getServiceConnection(),
+        assertEquals(mHostEmulationManager.getServiceConnection(),
                 mServiceConnectionArgumentCaptor.getValue());
         verify(mStatsUtils).logCardEmulationDeactivatedEvent();
 
         mTestableLooper.moveTimeForward(5000);
         mTestableLooper.processAllMessages();
         verify(mNfcAdapter).setObserveModeEnabled(eq(true));
-        Assert.assertFalse(mHostEmulationManager.mEnableObserveModeAfterTransaction);
-        verifyNoMoreInteractions(mMessanger);
+        assertFalse(mHostEmulationManager.mEnableObserveModeAfterTransaction);
+        verifyNoMoreInteractions(mMessenger);
         verifyNoMoreInteractions(mContext);
     }
 
@@ -984,20 +980,20 @@ public class HostEmulationManagerTest {
 
         mHostEmulationManager.onHostEmulationDeactivated();
 
-        Assert.assertNull(mHostEmulationManager.mActiveService);
-        Assert.assertNull(mHostEmulationManager.mActiveServiceName);
-        Assert.assertNull(mHostEmulationManager.mServiceName);
-        Assert.assertNull(mHostEmulationManager.mService);
-        Assert.assertNull(mHostEmulationManager.mPendingPollingLoopFrames);
-        Assert.assertEquals(-1, mHostEmulationManager.mActiveServiceUserId);
-        Assert.assertEquals(-1, mHostEmulationManager.mServiceUserId);
-        Assert.assertEquals(HostEmulationManager.STATE_IDLE, mHostEmulationManager.getState());
-        Assert.assertFalse(mHostEmulationManager.mEnableObserveModeAfterTransaction);
-        Assert.assertFalse(mHostEmulationManager.mServiceBound);
+        assertNull(mHostEmulationManager.mActiveService);
+        assertNull(mHostEmulationManager.mActiveServiceName);
+        assertNull(mHostEmulationManager.mServiceName);
+        assertNull(mHostEmulationManager.mService);
+        assertNull(mHostEmulationManager.mPendingPollingLoopFrames);
+        assertEquals(Process.INVALID_UID, mHostEmulationManager.mActiveServiceUserId);
+        assertEquals(Process.INVALID_UID, mHostEmulationManager.mServiceUserId);
+        assertEquals(HostEmulationManager.STATE_IDLE, mHostEmulationManager.getState());
+        assertFalse(mHostEmulationManager.mEnableObserveModeAfterTransaction);
+        assertFalse(mHostEmulationManager.mServiceBound);
         verify(mContext).getSystemService(eq(PowerManager.class));
         verify(mContext).getSystemService(eq(KeyguardManager.class));
-        verifyZeroInteractions(mMessanger);
-        verifyNoMoreInteractions(mMessanger);
+        verifyZeroInteractions(mMessenger);
+        verifyNoMoreInteractions(mMessenger);
         verifyNoMoreInteractions(mContext);
         verify(mStatsUtils).logCardEmulationDeactivatedEvent();
     }
@@ -1010,71 +1006,68 @@ public class HostEmulationManagerTest {
 
         mHostEmulationManager.onOffHostAidSelected();
 
-        Assert.assertNull(mHostEmulationManager.mActiveService);
-        Assert.assertNull(mHostEmulationManager.mActiveServiceName);
-        Assert.assertEquals(-1, mHostEmulationManager.mActiveServiceUserId);
-        Assert.assertFalse(mHostEmulationManager.mServiceBound);
+        assertNull(mHostEmulationManager.mActiveService);
+        assertNull(mHostEmulationManager.mActiveServiceName);
+        assertEquals(Process.INVALID_UID, mHostEmulationManager.mActiveServiceUserId);
+        assertFalse(mHostEmulationManager.mServiceBound);
         verify(mContext).getSystemService(eq(PowerManager.class));
         verify(mContext).getSystemService(eq(KeyguardManager.class));
         verify(mContext).sendBroadcastAsUser(mIntentArgumentCaptor.capture(), eq(UserHandle.ALL));
-        Assert.assertEquals(HostEmulationManager.STATE_W4_SELECT,
-                mHostEmulationManager.getState());
+        assertEquals(HostEmulationManager.STATE_W4_SELECT, mHostEmulationManager.getState());
         Intent intent = mIntentArgumentCaptor.getValue();
-        Assert.assertEquals(TapAgainDialog.ACTION_CLOSE, intent.getAction());
-        Assert.assertEquals(HostEmulationManager.NFC_PACKAGE, intent.getPackage());
+        assertEquals(TapAgainDialog.ACTION_CLOSE, intent.getAction());
+        assertEquals(HostEmulationManager.NFC_PACKAGE, intent.getPackage());
         verifyNoMoreInteractions(mContext);
     }
 
     @Test
     public void testOnOffHostAidSelected_activeServiceBound_stateXfer() throws RemoteException {
-        mHostEmulationManager.mActiveService = mMessanger;
+        mHostEmulationManager.mActiveService = mMessenger;
         mHostEmulationManager.mServiceBound = true;
         mHostEmulationManager.mState = HostEmulationManager.STATE_XFER;
 
         mHostEmulationManager.onOffHostAidSelected();
 
-        Assert.assertNull(mHostEmulationManager.mActiveService);
-        Assert.assertNull(mHostEmulationManager.mActiveServiceName);
-        Assert.assertEquals(-1, mHostEmulationManager.mActiveServiceUserId);
-        Assert.assertFalse(mHostEmulationManager.mServiceBound);
+        assertNull(mHostEmulationManager.mActiveService);
+        assertNull(mHostEmulationManager.mActiveServiceName);
+        assertEquals(Process.INVALID_UID, mHostEmulationManager.mActiveServiceUserId);
+        assertFalse(mHostEmulationManager.mServiceBound);
         verify(mContext).unbindService(mServiceConnectionArgumentCaptor.capture());
         verify(mContext).getSystemService(eq(PowerManager.class));
         verify(mContext).getSystemService(eq(KeyguardManager.class));
         verify(mContext).sendBroadcastAsUser(mIntentArgumentCaptor.capture(), eq(UserHandle.ALL));
-        Assert.assertEquals(HostEmulationManager.STATE_W4_SELECT,
-                mHostEmulationManager.getState());
+        assertEquals(HostEmulationManager.STATE_W4_SELECT, mHostEmulationManager.getState());
         Intent intent = mIntentArgumentCaptor.getValue();
-        Assert.assertEquals(TapAgainDialog.ACTION_CLOSE, intent.getAction());
-        Assert.assertEquals(HostEmulationManager.NFC_PACKAGE, intent.getPackage());
-        verify(mMessanger).send(mMessageArgumentCaptor.capture());
+        assertEquals(TapAgainDialog.ACTION_CLOSE, intent.getAction());
+        assertEquals(HostEmulationManager.NFC_PACKAGE, intent.getPackage());
+        verify(mMessenger).send(mMessageArgumentCaptor.capture());
         Message message = mMessageArgumentCaptor.getValue();
-        Assert.assertEquals(message.what, HostApduService.MSG_DEACTIVATED);
-        Assert.assertEquals(message.arg1, HostApduService.DEACTIVATION_DESELECTED);
+        assertEquals(HostApduService.MSG_DEACTIVATED, message.what);
+        assertEquals(HostApduService.DEACTIVATION_DESELECTED, message.arg1);
         verifyNoMoreInteractions(mContext);
     }
 
     @Test
     public void testOnOffHostAidSelected_activeServiceBound_stateNonXfer() throws RemoteException {
-        mHostEmulationManager.mActiveService = mMessanger;
+        mHostEmulationManager.mActiveService = mMessenger;
         mHostEmulationManager.mServiceBound = true;
         mHostEmulationManager.mState = HostEmulationManager.STATE_IDLE;
 
         mHostEmulationManager.onOffHostAidSelected();
 
-        Assert.assertNull(mHostEmulationManager.mActiveService);
-        Assert.assertNull(mHostEmulationManager.mActiveServiceName);
-        Assert.assertEquals(-1, mHostEmulationManager.mActiveServiceUserId);
-        Assert.assertFalse(mHostEmulationManager.mServiceBound);
+        assertNull(mHostEmulationManager.mActiveService);
+        assertNull(mHostEmulationManager.mActiveServiceName);
+        assertEquals(Process.INVALID_UID, mHostEmulationManager.mActiveServiceUserId);
+        assertFalse(mHostEmulationManager.mServiceBound);
         verify(mContext).unbindService(mServiceConnectionArgumentCaptor.capture());
         verify(mContext).getSystemService(eq(PowerManager.class));
         verify(mContext).getSystemService(eq(KeyguardManager.class));
         verify(mContext).sendBroadcastAsUser(mIntentArgumentCaptor.capture(), eq(UserHandle.ALL));
-        Assert.assertEquals(HostEmulationManager.STATE_W4_SELECT,
-                mHostEmulationManager.getState());
+        assertEquals(HostEmulationManager.STATE_W4_SELECT, mHostEmulationManager.getState());
         Intent intent = mIntentArgumentCaptor.getValue();
-        Assert.assertEquals(TapAgainDialog.ACTION_CLOSE, intent.getAction());
-        Assert.assertEquals(HostEmulationManager.NFC_PACKAGE, intent.getPackage());
-        verifyZeroInteractions(mMessanger);
+        assertEquals(TapAgainDialog.ACTION_CLOSE, intent.getAction());
+        assertEquals(HostEmulationManager.NFC_PACKAGE, intent.getPackage());
+        verifyZeroInteractions(mMessenger);
         verifyNoMoreInteractions(mContext);
     }
 
@@ -1088,12 +1081,12 @@ public class HostEmulationManagerTest {
         mHostEmulationManager.getServiceConnection().onServiceConnected(WALLET_PAYMENT_SERVICE,
                 service);
 
-        Assert.assertEquals(mHostEmulationManager.mServiceName, WALLET_PAYMENT_SERVICE);
-        Assert.assertNotNull(mHostEmulationManager.mService);
-        Assert.assertTrue(mHostEmulationManager.mServiceBound);
+        assertEquals(WALLET_PAYMENT_SERVICE, mHostEmulationManager.mServiceName);
+        assertNotNull(mHostEmulationManager.mService);
+        assertTrue(mHostEmulationManager.mServiceBound);
         verify(mStatsUtils).notifyCardEmulationEventServiceBound();
-        Assert.assertEquals(HostEmulationManager.STATE_XFER, mHostEmulationManager.getState());
-        Assert.assertNull(mHostEmulationManager.mSelectApdu);
+        assertEquals(HostEmulationManager.STATE_XFER, mHostEmulationManager.getState());
+        assertNull(mHostEmulationManager.mSelectApdu);
         verify(service).transact(eq(1), any(), eq(null), eq(1));
     }
 
@@ -1110,11 +1103,11 @@ public class HostEmulationManagerTest {
         mHostEmulationManager.getServiceConnection().onServiceConnected(WALLET_PAYMENT_SERVICE,
                 service);
 
-        Assert.assertEquals(mHostEmulationManager.mServiceName, WALLET_PAYMENT_SERVICE);
-        Assert.assertNotNull(mHostEmulationManager.mService);
-        Assert.assertTrue(mHostEmulationManager.mServiceBound);
-        Assert.assertEquals(HostEmulationManager.STATE_W4_SELECT, mHostEmulationManager.getState());
-        Assert.assertNull(mHostEmulationManager.mPollingFramesToSend.get(WALLET_PAYMENT_SERVICE));
+        assertEquals(WALLET_PAYMENT_SERVICE, mHostEmulationManager.mServiceName);
+        assertNotNull(mHostEmulationManager.mService);
+        assertTrue(mHostEmulationManager.mServiceBound);
+        assertEquals(HostEmulationManager.STATE_W4_SELECT, mHostEmulationManager.getState());
+        assertNull(mHostEmulationManager.mPollingFramesToSend.get(WALLET_PAYMENT_SERVICE));
         verify(service).transact(eq(1), any(), eq(null), eq(1));
     }
 
@@ -1131,15 +1124,15 @@ public class HostEmulationManagerTest {
 
     @Test
     public void testServiceConnectionOnServiceDisconnected() {
-        mHostEmulationManager.mService = mMessanger;
+        mHostEmulationManager.mService = mMessenger;
         mHostEmulationManager.mServiceBound = true;
         mHostEmulationManager.mServiceName = WALLET_PAYMENT_SERVICE;
 
         mHostEmulationManager.getServiceConnection().onServiceDisconnected(WALLET_PAYMENT_SERVICE);
 
-        Assert.assertNull(mHostEmulationManager.mService);
-        Assert.assertFalse(mHostEmulationManager.mServiceBound);
-        Assert.assertNull(mHostEmulationManager.mServiceName);
+        assertNull(mHostEmulationManager.mService);
+        assertFalse(mHostEmulationManager.mServiceBound);
+        assertNull(mHostEmulationManager.mServiceName);
     }
 
     @Test
@@ -1150,20 +1143,20 @@ public class HostEmulationManagerTest {
         mHostEmulationManager.getPaymentConnection().onServiceConnected(WALLET_PAYMENT_SERVICE,
                 service);
 
-        Assert.assertNotNull(mHostEmulationManager.mPaymentServiceName);
-        Assert.assertEquals(WALLET_PAYMENT_SERVICE, mHostEmulationManager.mPaymentServiceName);
+        assertNotNull(mHostEmulationManager.mPaymentServiceName);
+        assertEquals(WALLET_PAYMENT_SERVICE, mHostEmulationManager.mPaymentServiceName);
     }
 
     @Test
     public void testPaymentServiceConnectionOnServiceDisconnected() {
-        mHostEmulationManager.mPaymentService = mMessanger;
+        mHostEmulationManager.mPaymentService = mMessenger;
         mHostEmulationManager.mPaymentServiceBound = true;
         mHostEmulationManager.mPaymentServiceName = WALLET_PAYMENT_SERVICE;
 
         mHostEmulationManager.getPaymentConnection().onServiceDisconnected(WALLET_PAYMENT_SERVICE);
 
-        Assert.assertNull(mHostEmulationManager.mPaymentService);
-        Assert.assertNull(mHostEmulationManager.mPaymentServiceName);
+        assertNull(mHostEmulationManager.mPaymentService);
+        assertNull(mHostEmulationManager.mPaymentServiceName);
     }
 
     @Test
@@ -1172,13 +1165,13 @@ public class HostEmulationManagerTest {
 
         UserHandle userHandle = UserHandle.of(USER_ID);
 
-        mHostEmulationManager.mPaymentService = mMessanger;
+        mHostEmulationManager.mPaymentService = mMessenger;
         mHostEmulationManager.mPaymentServiceBound = true;
         mHostEmulationManager.mPaymentServiceName = WALLET_PAYMENT_SERVICE;
 
         mHostEmulationManager.getPaymentConnection().onServiceDisconnected(WALLET_PAYMENT_SERVICE);
-        Assert.assertNull(mHostEmulationManager.mPaymentService);
-        Assert.assertNull(mHostEmulationManager.mPaymentServiceName);
+        assertNull(mHostEmulationManager.mPaymentService);
+        assertNull(mHostEmulationManager.mPaymentServiceName);
 
         mHostEmulationManager.getPaymentConnection().onBindingDied(WALLET_PAYMENT_SERVICE);
 
@@ -1188,8 +1181,8 @@ public class HostEmulationManagerTest {
                 eq(Context.BIND_AUTO_CREATE | Context.BIND_ALLOW_BACKGROUND_ACTIVITY_STARTS),
                 eq(userHandle));
 
-        Assert.assertEquals(USER_ID, mHostEmulationManager.mPaymentServiceUserId);
-        Assert.assertTrue(mHostEmulationManager.mPaymentServiceBound);
+        assertEquals(USER_ID, mHostEmulationManager.mPaymentServiceUserId);
+        assertTrue(mHostEmulationManager.mPaymentServiceBound);
     }
 
     @Test
@@ -1200,23 +1193,23 @@ public class HostEmulationManagerTest {
 
         UserHandle userHandle = UserHandle.of(USER_ID);
 
-        mHostEmulationManager.mPaymentService = mMessanger;
+        mHostEmulationManager.mPaymentService = mMessenger;
         mHostEmulationManager.mPaymentServiceBound = true;
         mHostEmulationManager.mPaymentServiceName = WALLET_PAYMENT_SERVICE;
 
         mHostEmulationManager.getPaymentConnection().onServiceDisconnected(WALLET_PAYMENT_SERVICE);
-        Assert.assertNull(mHostEmulationManager.mPaymentService);
-        Assert.assertNull(mHostEmulationManager.mPaymentServiceName);
+        assertNull(mHostEmulationManager.mPaymentService);
+        assertNull(mHostEmulationManager.mPaymentServiceName);
 
         mHostEmulationManager.getPaymentConnection().onBindingDied(WALLET_PAYMENT_SERVICE);
 
         verify(mContext).unbindService(eq(mHostEmulationManager.getPaymentConnection()));
-        Assert.assertFalse(verify(mContext).bindServiceAsUser(mIntentArgumentCaptor.capture(),
+        assertFalse(verify(mContext).bindServiceAsUser(mIntentArgumentCaptor.capture(),
                 mServiceConnectionArgumentCaptor.capture(),
                 eq(Context.BIND_AUTO_CREATE | Context.BIND_ALLOW_BACKGROUND_ACTIVITY_STARTS),
                 eq(userHandle)));
 
-        Assert.assertFalse(mHostEmulationManager.mPaymentServiceBound);
+        assertFalse(mHostEmulationManager.mPaymentServiceBound);
 
         when(mContext.bindServiceAsUser(any(), any(), anyInt(), any())).thenReturn(true);
 
@@ -1227,8 +1220,8 @@ public class HostEmulationManagerTest {
                 eq(Context.BIND_AUTO_CREATE | Context.BIND_ALLOW_BACKGROUND_ACTIVITY_STARTS),
                 eq(userHandle));
 
-        Assert.assertEquals(USER_ID, mHostEmulationManager.mPaymentServiceUserId);
-        Assert.assertTrue(mHostEmulationManager.mPaymentServiceBound);
+        assertEquals(USER_ID, mHostEmulationManager.mPaymentServiceUserId);
+        assertTrue(mHostEmulationManager.mPaymentServiceBound);
     }
 
     @Test
@@ -1237,14 +1230,14 @@ public class HostEmulationManagerTest {
 
         String aidString = mHostEmulationManager.findSelectAid(aidData);
 
-        Assert.assertEquals(MOCK_AID, aidString);
+        assertEquals(MOCK_AID, aidString);
     }
 
     @Test
     public void testFindSelectAid_nullData() {
         String aidString = mHostEmulationManager.findSelectAid(null);
 
-        Assert.assertNull(aidString);
+        assertNull(aidString);
     }
 
     @Test
@@ -1253,7 +1246,7 @@ public class HostEmulationManagerTest {
 
         String aidString = mHostEmulationManager.findSelectAid(aidData);
 
-        Assert.assertNull(aidString);
+        assertNull(aidString);
     }
 
     @Test
@@ -1264,18 +1257,54 @@ public class HostEmulationManagerTest {
 
         String aidString = mHostEmulationManager.findSelectAid(aidData);
 
-        Assert.assertNull(aidString);
+        assertNull(aidString);
+    }
+
+    @Test
+    public void testOnPollingLoopDetected_noServiceBound() {
+        ApduServiceInfo serviceWithFilter = mock(ApduServiceInfo.class);
+        when(serviceWithFilter.getPollingLoopFilters()).thenReturn(POLLING_LOOP_FILTER);
+        when(serviceWithFilter.getPollingLoopPatternFilters()).thenReturn(List.of());
+        mHostEmulationManager.updatePollingLoopFilters(USER_ID, List.of(serviceWithFilter));
+
+        // Preferred payment service is defined, but not bound
+        when(mRegisteredAidCache.getPreferredService())
+                .thenReturn(new Pair<>(USER_ID, WALLET_PAYMENT_SERVICE));
+        when(mRegisteredAidCache.getPreferredPaymentService())
+            .thenReturn(new Pair<>(USER_ID, WALLET_PAYMENT_SERVICE));
+        mHostEmulationManager.mPaymentServiceName = WALLET_PAYMENT_SERVICE;
+        assertNull(mHostEmulationManager.mPaymentService);
+        assertFalse(mHostEmulationManager.mPaymentServiceBound);
+
+        PollingFrame frame1 = new PollingFrame(PollingFrame.POLLING_LOOP_TYPE_UNKNOWN,
+                HexFormat.of().parseHex("42"), 0, 0, false);
+        PollingFrame offFrame = new PollingFrame(PollingFrame.POLLING_LOOP_TYPE_OFF,
+                null, 0, 0, false);
+
+        mHostEmulationManager.onPollingLoopDetected(List.of(frame1, offFrame));
+
+        assertEquals(HostEmulationManager.STATE_POLLING_LOOP, mHostEmulationManager.mState);
+        assertNotNull(mHostEmulationManager.mPollingFramesToSend);
+        assertNotNull(mHostEmulationManager.mUnprocessedPollingFrames);
+
+        // Return to idle state after timeout
+        mTestableLooper.moveTimeForward(mHostEmulationManager.FIELD_OFF_IDLE_DELAY_MS);
+        mTestableLooper.processAllMessages();
+
+        assertEquals(HostEmulationManager.STATE_IDLE, mHostEmulationManager.mState);
+        assertNull(mHostEmulationManager.mPollingFramesToSend);
+        assertNull(mHostEmulationManager.mUnprocessedPollingFrames);
     }
 
     private void verifyTapAgainLaunched(ApduServiceInfo service, String category) {
         verify(mContext).getPackageName();
         verify(mContext).startActivityAsUser(mIntentArgumentCaptor.capture(), eq(USER_HANDLE));
         Intent intent = mIntentArgumentCaptor.getValue();
-        Assert.assertEquals(category, intent.getStringExtra(TapAgainDialog.EXTRA_CATEGORY));
-        Assert.assertEquals(service, intent.getParcelableExtra(TapAgainDialog.EXTRA_APDU_SERVICE));
+        assertEquals(category, intent.getStringExtra(TapAgainDialog.EXTRA_CATEGORY));
+        assertEquals(service, intent.getParcelableExtra(TapAgainDialog.EXTRA_APDU_SERVICE));
         int flags = Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK;
-        Assert.assertEquals(flags, intent.getFlags());
-        Assert.assertEquals(TapAgainDialog.class.getCanonicalName(),
+        assertEquals(flags, intent.getFlags());
+        assertEquals(TapAgainDialog.class.getCanonicalName(),
                 intent.getComponent().getClassName());
     }
 
@@ -1284,16 +1313,16 @@ public class HostEmulationManagerTest {
         verify(mContext).getPackageName();
         verify(mContext).startActivityAsUser(mIntentArgumentCaptor.capture(), eq(UserHandle.CURRENT));
         Intent intent = mIntentArgumentCaptor.getValue();
-        Assert.assertEquals(category, intent.getStringExtra(AppChooserActivity.EXTRA_CATEGORY));
-        Assert.assertEquals(services,
+        assertEquals(category, intent.getStringExtra(AppChooserActivity.EXTRA_CATEGORY));
+        assertEquals(services,
                 intent.getParcelableArrayListExtra(AppChooserActivity.EXTRA_APDU_SERVICES));
         if (failedComponent != null) {
-            Assert.assertEquals(failedComponent,
+            assertEquals(failedComponent,
                     intent.getParcelableExtra(AppChooserActivity.EXTRA_FAILED_COMPONENT));
         }
         int flags = Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK;
-        Assert.assertEquals(flags, intent.getFlags());
-        Assert.assertEquals(AppChooserActivity.class.getCanonicalName(),
+        assertEquals(flags, intent.getFlags());
+        assertEquals(AppChooserActivity.class.getCanonicalName(),
                 intent.getComponent().getClassName());
     }
 
diff --git a/tests/unit/src/com/android/nfc/cardemulation/NfcAidConflictOccurredTest.java b/tests/unit/src/com/android/nfc/cardemulation/NfcAidConflictOccurredTest.java
index 0c31f5d5..047a82a6 100644
--- a/tests/unit/src/com/android/nfc/cardemulation/NfcAidConflictOccurredTest.java
+++ b/tests/unit/src/com/android/nfc/cardemulation/NfcAidConflictOccurredTest.java
@@ -15,6 +15,7 @@
  */
 package com.android.nfc.cardemulation;
 
+import static org.junit.Assert.assertNotNull;
 import static org.mockito.ArgumentMatchers.anyString;
 import static org.mockito.Mockito.when;
 
@@ -45,7 +46,6 @@ import java.util.ArrayList;
 import java.util.List;
 
 import org.junit.After;
-import org.junit.Assert;
 import org.junit.Before;
 import org.junit.Rule;
 import org.junit.Test;
@@ -57,8 +57,6 @@ import org.mockito.MockitoSession;
 public final class NfcAidConflictOccurredTest {
 
     private static final String TAG = NfcAidConflictOccurredTest.class.getSimpleName();
-    private boolean mNfcSupported;
-
     private MockitoSession mStaticMockSession;
     private HostEmulationManager mHostEmulation;
     @Rule
@@ -67,18 +65,10 @@ public final class NfcAidConflictOccurredTest {
 
     @Before
     public void setUp() {
+        Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
         mStaticMockSession = ExtendedMockito.mockitoSession()
                 .mockStatic(NfcStatsLog.class)
                 .startMocking();
-
-        Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
-        PackageManager pm = context.getPackageManager();
-        if (!pm.hasSystemFeature(PackageManager.FEATURE_NFC_HOST_CARD_EMULATION)) {
-            mNfcSupported = false;
-            return;
-        }
-        mNfcSupported = true;
-
         RegisteredAidCache mockAidCache = Mockito.mock(RegisteredAidCache.class);
         ApduServiceInfo apduServiceInfo = Mockito.mock(ApduServiceInfo.class);
         AidResolveInfo aidResolveInfo = mockAidCache.new AidResolveInfo();
@@ -101,7 +91,7 @@ public final class NfcAidConflictOccurredTest {
         InstrumentationRegistry.getInstrumentation().runOnMainSync(
               () -> mHostEmulation = new HostEmulationManager(
                       mockContext, mTestLooper.getLooper(), mockAidCache));
-        Assert.assertNotNull(mHostEmulation);
+        assertNotNull(mHostEmulation);
 
         mHostEmulation.onHostEmulationActivated();
     }
@@ -114,8 +104,6 @@ public final class NfcAidConflictOccurredTest {
 
     @Test
     public void testHCEOther() {
-        if (!mNfcSupported) return;
-
         byte[] aidBytes = new byte[] {
             0x00, (byte)0xA4, 0x04, 0x00,  // command
             0x08,  // data length
@@ -132,8 +120,6 @@ public final class NfcAidConflictOccurredTest {
     @Test
     @RequiresFlagsEnabled(Flags.FLAG_TEST_FLAG)
     public void testHCEOtherWithTestFlagEnabled() {
-        if (!mNfcSupported) return;
-
         byte[] aidBytes = new byte[] {
                 0x00, (byte)0xA4, 0x04, 0x00,  // command
                 0x08,  // data length
diff --git a/tests/unit/src/com/android/nfc/cardemulation/NfcCardEmulationOccurredTest.java b/tests/unit/src/com/android/nfc/cardemulation/NfcCardEmulationOccurredTest.java
index d1b1c08d..5fe77f64 100644
--- a/tests/unit/src/com/android/nfc/cardemulation/NfcCardEmulationOccurredTest.java
+++ b/tests/unit/src/com/android/nfc/cardemulation/NfcCardEmulationOccurredTest.java
@@ -63,7 +63,6 @@ import java.util.ArrayList;
 import java.util.List;
 
 import org.junit.After;
-import org.junit.Assert;
 import org.junit.Before;
 import org.junit.Rule;
 import org.junit.Test;
@@ -77,8 +76,6 @@ import org.mockito.quality.Strictness;
 public final class NfcCardEmulationOccurredTest {
 
     private static final String TAG = NfcCardEmulationOccurredTest.class.getSimpleName();
-    private boolean mNfcSupported;
-
     private MockitoSession mStaticMockSession;
     private HostEmulationManager mHostEmulation;
     private RegisteredAidCache mockAidCache;
@@ -93,21 +90,13 @@ public final class NfcCardEmulationOccurredTest {
 
     @Before
     public void setUp() {
+        Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
         mStaticMockSession = ExtendedMockito.mockitoSession()
                 .mockStatic(NfcStatsLog.class)
                 .mockStatic(Flags.class)
                 .mockStatic(NfcService.class)
                 .strictness(Strictness.LENIENT)
                 .startMocking();
-
-        Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
-        packageManager = context.getPackageManager();
-        if (!packageManager.hasSystemFeature(PackageManager.FEATURE_NFC_HOST_CARD_EMULATION)) {
-            mNfcSupported = false;
-            return;
-        }
-        mNfcSupported = true;
-
         initMockContext(context);
 
         mockAidCache = Mockito.mock(RegisteredAidCache.class);
@@ -170,8 +159,6 @@ public final class NfcCardEmulationOccurredTest {
     @RequiresFlagsDisabled(Flags.FLAG_STATSD_CE_EVENTS_FLAG)
     @Test
     public void testHCEOther() {
-        if (!mNfcSupported) return;
-
         byte[] aidBytes = new byte[] {
                 0x00, (byte)0xA4, 0x04, 0x00,  // command
                 0x08,  // data length
@@ -189,17 +176,13 @@ public final class NfcCardEmulationOccurredTest {
 
     @Test
     public void testOnHostEmulationActivated() {
-        if (!mNfcSupported) return;
-
         mHostEmulation.onHostEmulationActivated();
         int value = mHostEmulation.getState();
-        Assert.assertEquals(value, STATE_W4_SELECT);
+        assertEquals(STATE_W4_SELECT, value);
     }
 
     @Test
     public void testOnPollingLoopDetected() {
-        if (!mNfcSupported) return;
-
         PollingFrame pollingFrame = mock(PollingFrame.class);
         ArrayList<PollingFrame> pollingFrames = new ArrayList<PollingFrame>();
         pollingFrames.add(pollingFrame);
@@ -209,13 +192,11 @@ public final class NfcCardEmulationOccurredTest {
                 .thenReturn(new Pair<>(0, componentName));
         mHostEmulation.onPollingLoopDetected(pollingFrames);
         PollingFrame resultPollingFrame = mHostEmulation.mPendingPollingLoopFrames.get(0);
-        Assert.assertEquals(pollingFrame, resultPollingFrame);
+        assertEquals(pollingFrame, resultPollingFrame);
     }
 
     @Test
     public void testOnPollingLoopDetectedServiceBound() {
-        if (!mNfcSupported) return;
-
         PollingFrame pollingLoopTypeOnFrame = mock(PollingFrame.class);
         ArrayList<PollingFrame> pollingLoopTypeOnFrames = new ArrayList<PollingFrame>();
         pollingLoopTypeOnFrames.add(pollingLoopTypeOnFrame);
@@ -238,14 +219,12 @@ public final class NfcCardEmulationOccurredTest {
         mHostEmulation.onPollingLoopDetected(pollingLoopTypeOffFrames);
         mHostEmulation.onPollingLoopDetected(pollingLoopTypeOffFrames);
         IBinder mActiveService = mHostEmulation.getMessenger();
-        Assert.assertNotNull(mActiveService);
-        Assert.assertEquals(iBinder, mActiveService);
+        assertNotNull(mActiveService);
+        assertEquals(iBinder, mActiveService);
     }
 
     @Test
     public void testOnPollingLoopDetectedSTATE_XFER() {
-        if (!mNfcSupported) return;
-
         ComponentName componentName = mock(ComponentName.class);
         when(componentName.getPackageName()).thenReturn("com.android.nfc");
         IBinder iBinder = new Binder();
@@ -263,22 +242,18 @@ public final class NfcCardEmulationOccurredTest {
         };
         mHostEmulation.onHostEmulationData(aidBytes);
         state = mHostEmulation.getState();
-        assertEquals(state, STATE_W4_SERVICE);
+        assertEquals(STATE_W4_SERVICE, state);
     }
 
     @Test
     public void testOnOffHostAidSelected() {
-        if (!mNfcSupported) return;
-
         mHostEmulation.onOffHostAidSelected();
         int state = mHostEmulation.getState();
-        assertEquals(state, STATE_W4_SELECT);
+        assertEquals(STATE_W4_SELECT, state);
     }
 
     @Test
     public void testOnPreferredPaymentServiceChanged() {
-        if (!mNfcSupported) return;
-
         ComponentName componentName = mock(ComponentName.class);
         when(componentName.getPackageName()).thenReturn("com.android.nfc");
         int userId = 0;
@@ -291,8 +266,6 @@ public final class NfcCardEmulationOccurredTest {
 
     @Test
     public void testOnPreferredForegroundServiceChanged() {
-        if (!mNfcSupported) return;
-
         ComponentName componentName = mock(ComponentName.class);
         when(componentName.getPackageName()).thenReturn("com.android.nfc");
         int userId = 0;
@@ -301,4 +274,4 @@ public final class NfcCardEmulationOccurredTest {
         assertNotNull(isServiceBounded);
         assertTrue(isServiceBounded);
     }
-}
\ No newline at end of file
+}
diff --git a/tests/unit/src/com/android/nfc/cardemulation/PreferredServicesTest.java b/tests/unit/src/com/android/nfc/cardemulation/PreferredServicesTest.java
index d29b7414..a77f76f8 100644
--- a/tests/unit/src/com/android/nfc/cardemulation/PreferredServicesTest.java
+++ b/tests/unit/src/com/android/nfc/cardemulation/PreferredServicesTest.java
@@ -17,13 +17,16 @@
 package com.android.nfc.cardemulation;
 
 import static com.google.common.truth.Truth.assertThat;
+import static org.junit.Assert.assertTrue;
 import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.anyBoolean;
 import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.ArgumentMatchers.anyString;
 import static org.mockito.ArgumentMatchers.eq;
+import static org.mockito.Mockito.atLeast;
 import static org.mockito.Mockito.doNothing;
 import static org.mockito.Mockito.doReturn;
+import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.never;
 import static org.mockito.Mockito.times;
 import static org.mockito.Mockito.verify;
@@ -35,12 +38,16 @@ import android.content.ComponentName;
 import android.content.Context;
 import android.content.ContentResolver;
 import android.content.ContextWrapper;
+import android.database.ContentObserver;
+import android.nfc.Constants;
+import android.os.Process;
 import android.os.UserHandle;
 import android.os.UserManager;
 import android.net.Uri;
 import android.nfc.cardemulation.ApduServiceInfo;
 import android.nfc.cardemulation.CardEmulation;
 import android.provider.Settings;
+import android.util.Log;
 
 import androidx.test.platform.app.InstrumentationRegistry;
 import androidx.test.runner.AndroidJUnit4;
@@ -67,582 +74,628 @@ import org.mockito.quality.Strictness;
 @RunWith(AndroidJUnit4.class)
 public class PreferredServicesTest {
 
-  private PreferredServices services;
-  private MockitoSession mStaticMockSession;
-  private Context mContext;
-
-  @Mock
-  private RegisteredServicesCache mServicesCache;
-  @Mock
-  private PreferredServices.Callback mCallback;
-  @Mock
-  private RegisteredAidCache mAidCache;
-  @Mock
-  private WalletRoleObserver mObserver;
-  @Mock
-  private ForegroundUtils mForegroundUtils;
-  @Mock
-  private ContentResolver mContentResolver;
-  @Mock
-  private UserManager mUserManager;
-  @Mock
-  private ActivityManager mActivityManager;
-  @Mock
-  private ApduServiceInfo mServiceInfoPayment;
-  @Mock
-  private ApduServiceInfo mServiceInfoNonPayment;
-  @Mock
-  private UserHandle mUserHandle;
-  @Mock
-  private PrintWriter mPrintWriter;
-  @Mock
-  private RegisteredAidCache.AidResolveInfo mResolveInfo;
-
-  @Captor
-  private ArgumentCaptor<Integer> userIdCaptor;
-  @Captor
-  private ArgumentCaptor<ComponentName> candidateCaptor;
-
-  private static final String WALLET_HOLDER_PACKAGE_NAME = "com.android.test.walletroleholder";
-  private static final ComponentName TEST_COMPONENT
-      = new ComponentName(WALLET_HOLDER_PACKAGE_NAME,
-      "com.android.test.walletroleholder.WalletRoleHolderApduService");
-  private static final int USER_ID = 1;
-  private static final int FOREGROUND_UID = 7;
-
-  @Before
-  public void setUp() throws Exception {
-    mStaticMockSession = ExtendedMockito.mockitoSession()
-        .mockStatic(ForegroundUtils.class)
-        .mockStatic(ActivityManager.class)
-        .mockStatic(UserHandle.class)
-        .mockStatic(Settings.Secure.class)
-        .mockStatic(ComponentName.class)
-        .strictness(Strictness.LENIENT)
-        .startMocking();
-    MockitoAnnotations.initMocks(this);
-    mContext = new ContextWrapper(InstrumentationRegistry.getInstrumentation().getTargetContext()) {
-      @Override
-      public Object getSystemService(String name) {
-        if (Context.ACTIVITY_SERVICE.equals(name)) {
-          return (ActivityManager) mActivityManager;
-        } else if (Context.USER_SERVICE.equals(name)) {
-          return (UserManager) mUserManager;
-        } else {
-          return null;
-        }
-      }
-
-      @Override
-      public Context createContextAsUser(UserHandle user, int flags) {
-        return mContext;
-      }
-
-      @Override
-      public ContentResolver getContentResolver() {
-        return mContentResolver;
-      }
-    };
-
-    when(ForegroundUtils.getInstance(any(ActivityManager.class))).thenReturn(mForegroundUtils);
-    when(ActivityManager.getCurrentUser()).thenReturn(USER_ID);
-    doNothing().when(mContentResolver)
-        .registerContentObserverAsUser(any(Uri.class), anyBoolean(), any(), any(UserHandle.class));
-    doNothing().when(mCallback).onPreferredPaymentServiceChanged(anyInt(), any());
-    when(Settings.Secure.getString(any(ContentResolver.class), anyString())).thenReturn("");
-    when(Settings.Secure.getInt(any(ContentResolver.class), anyString())).thenReturn(USER_ID);
-    when(UserHandle.getUserHandleForUid(anyInt())).thenReturn(mUserHandle);
-    when(UserHandle.of(anyInt())).thenReturn(mUserHandle);
-    when(mUserHandle.getIdentifier()).thenReturn(FOREGROUND_UID);
-    when(mObserver.getDefaultWalletRoleHolder(anyInt())).thenReturn(null);
-    when(mServiceInfoPayment.getComponent()).thenReturn(TEST_COMPONENT);
-    when(mServiceInfoPayment.getAids()).thenReturn(getAids());
-    when(mServiceInfoPayment
-        .getCategoryForAid(anyString())).thenReturn(CardEmulation.CATEGORY_PAYMENT);
-    when(mServiceInfoPayment.hasCategory(eq(CardEmulation.CATEGORY_PAYMENT))).thenReturn(true);
-    when(mServiceInfoNonPayment.hasCategory(eq(CardEmulation.CATEGORY_PAYMENT))).thenReturn(false);
-    when(mServiceInfoNonPayment.getAids()).thenReturn(getAids());
-    when(mAidCache.resolveAid(anyString())).thenReturn(mResolveInfo);
-    when(mUserManager.getEnabledProfiles()).thenReturn(getUserHandles());
-    // Wallet role feature is enabled by default; several test cases set this value to false
-    when(mObserver.isWalletRoleFeatureEnabled()).thenReturn(true);
-  }
-
-  @After
-  public void tearDown() {
-    mStaticMockSession.finishMocking();
-  }
-
-  @Test
-  public void testConstructorWhenWalletRoleFeatureIsNotEnabled() {
-    when(mObserver.isWalletRoleFeatureEnabled()).thenReturn(false);
-
-    services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
-
-    assertThat(services.mContext).isEqualTo(mContext);
-    assertThat(services.mWalletRoleObserver).isEqualTo(mObserver);
-    assertThat(services.mForegroundUtils).isEqualTo(mForegroundUtils);
-    assertThat(services.mServiceCache).isEqualTo(mServicesCache);
-    assertThat(services.mAidCache).isEqualTo(mAidCache);
-    assertThat(services.mCallback).isEqualTo(mCallback);
-    assertThat(services.mSettingsObserver).isNotNull();
-    verify(mContentResolver, times(2))
-        .registerContentObserverAsUser(any(), anyBoolean(), any(), any(UserHandle.class));
-    verify(mUserManager).getEnabledProfiles();
-    verify(mObserver, never()).getDefaultWalletRoleHolder(anyInt());
-  }
-
-  @Test
-  public void testConstructorWhenWalletRoleFeatureIsEnabled() {
-    services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
-
-    assertThat(services.mContext).isEqualTo(mContext);
-    assertThat(services.mWalletRoleObserver).isEqualTo(mObserver);
-    assertThat(services.mForegroundUtils).isEqualTo(mForegroundUtils);
-    assertThat(services.mServiceCache).isEqualTo(mServicesCache);
-    assertThat(services.mAidCache).isEqualTo(mAidCache);
-    assertThat(services.mCallback).isEqualTo(mCallback);
-    assertThat(services.mSettingsObserver).isNotNull();
-    verify(mContentResolver, times(2))
-        .registerContentObserverAsUser(any(), anyBoolean(), any(), any(UserHandle.class));
-    verify(mUserManager).getEnabledProfiles();
-    verify(mObserver).getDefaultWalletRoleHolder(anyInt());
-    assertThat(services.mDefaultWalletHolderPaymentService).isNull();
-    verify(mCallback).onPreferredPaymentServiceChanged(anyInt(), any());
-  }
-
-  @Test
-  public void testOnWalletRoleHolderChangedWithNullPackageName() {
-    services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
-
-    services.onWalletRoleHolderChanged(null, USER_ID);
-
-    verify(mCallback, times(2))
-        .onPreferredPaymentServiceChanged(userIdCaptor.capture(), candidateCaptor.capture());
-    List<Integer> userIds = userIdCaptor.getAllValues();
-    assertThat(userIds.get(0)).isEqualTo(USER_ID);
-    assertThat(userIds.get(1)).isEqualTo(USER_ID);
-    List<ComponentName> candidates = candidateCaptor.getAllValues();
-    assertThat(candidates.get(0)).isNull();
-    assertThat(candidates.get(1)).isNull();
-    assertThat(services.mDefaultWalletHolderPaymentService).isNull();
-  }
-
-  @Test
-  public void testOnWalletRoleHolderChangedWithExistingPackageNameAndExistingServiceInfos() {
-    when(mServicesCache.getInstalledServices(eq(USER_ID))).thenReturn(getPaymentServices());
-    services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
-
-    services.onWalletRoleHolderChanged(WALLET_HOLDER_PACKAGE_NAME, USER_ID);
-
-    assertThat(services.mUserIdDefaultWalletHolder).isEqualTo(USER_ID);
-    verify(mCallback, times(2))
-        .onPreferredPaymentServiceChanged(userIdCaptor.capture(), candidateCaptor.capture());
-    List<Integer> userIds = userIdCaptor.getAllValues();
-    assertThat(userIds.get(0)).isEqualTo(USER_ID);
-    assertThat(userIds.get(1)).isEqualTo(USER_ID);
-    List<ComponentName> candidates = candidateCaptor.getAllValues();
-    assertThat(candidates.get(0)).isNull();
-    assertThat(candidates.get(1)).isEqualTo(TEST_COMPONENT);
-    assertThat(services.mDefaultWalletHolderPaymentService).isEqualTo(TEST_COMPONENT);
-  }
-
-  @Test
-  public void testOnWalletRoleHolderChangedWithExistingPackageNameAndNoServiceInfo() {
-    ArrayList<ApduServiceInfo> emptyList = new ArrayList<>();
-    when(mServicesCache.getInstalledServices(eq(USER_ID))).thenReturn(emptyList);
-    services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
-
-    services.onWalletRoleHolderChanged(WALLET_HOLDER_PACKAGE_NAME, USER_ID);
-
-    assertThat(services.mUserIdDefaultWalletHolder).isEqualTo(USER_ID);
-    verify(mCallback).onPreferredPaymentServiceChanged(anyInt(), any());
-    assertThat(services.mDefaultWalletHolderPaymentService).isNull();
-  }
-
-  @Test
-  public void testOnWalletRoleHolderChangedWithIncorrectPackageName() {
-    when(mServicesCache.getInstalledServices(eq(USER_ID))).thenReturn(getPaymentServices());
-    services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
-
-    services.onWalletRoleHolderChanged(/* defaultWalletHolderPackageName = */ "", USER_ID);
-
-    assertThat(services.mUserIdDefaultWalletHolder).isEqualTo(USER_ID);
-    verify(mCallback).onPreferredPaymentServiceChanged(anyInt(), any());
-    assertThat(services.mDefaultWalletHolderPaymentService).isNull();
-  }
-
-  @Test
-  public void testSetDefaultForNextTapWithNonNullService_NotifyChange() {
-    services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
-    services.mForegroundUid = FOREGROUND_UID;
-
-    boolean result = services.setDefaultForNextTap(USER_ID, TEST_COMPONENT);
-
-    assertThat(result).isTrue();
-    assertThat(services.mNextTapDefault).isEqualTo(TEST_COMPONENT);
-    assertThat(services.mNextTapDefaultUserId).isEqualTo(USER_ID);
-    assertThat(services.mForegroundCurrent).isEqualTo(TEST_COMPONENT);
-    assertThat(services.mForegroundCurrentUid).isEqualTo(FOREGROUND_UID);
-    verify(mCallback)
-        .onPreferredForegroundServiceChanged(userIdCaptor.capture(), candidateCaptor.capture());
-    assertThat(userIdCaptor.getValue()).isEqualTo(USER_ID);
-    assertThat(candidateCaptor.getValue()).isEqualTo(TEST_COMPONENT);
-  }
-
-  @Test
-  public void testSetDefaultForNextTapWithNullService_NoChange() {
-    services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
-    services.mForegroundUid = FOREGROUND_UID;
-    services.mForegroundRequested = null;
-    services.mForegroundCurrent = null;
-
-    boolean result = services.setDefaultForNextTap(USER_ID, /* service = */ null);
-
-    assertThat(result).isTrue();
-    assertThat(services.mNextTapDefault).isNull();
-    assertThat(services.mNextTapDefaultUserId).isEqualTo(USER_ID);
-    assertThat(services.mForegroundCurrent).isEqualTo(null);
-    assertThat(services.mForegroundCurrentUid).isEqualTo(0);
-    verify(mCallback, never()).onPreferredForegroundServiceChanged(anyInt(), any());
-  }
-
-  @Test
-  public void testSetDefaultForNextTapWithNonNullService_NoChange() {
-    services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
-    services.mForegroundCurrent = TEST_COMPONENT;
-
-    boolean result = services.setDefaultForNextTap(FOREGROUND_UID, TEST_COMPONENT);
-
-    assertThat(result).isTrue();
-    assertThat(services.mNextTapDefault).isEqualTo(TEST_COMPONENT);
-    assertThat(services.mNextTapDefaultUserId).isEqualTo(FOREGROUND_UID);
-    assertThat(services.mForegroundCurrent).isEqualTo(TEST_COMPONENT);
-    assertThat(services.mForegroundCurrentUid).isEqualTo(0);
-    verify(mCallback, never()).onPreferredForegroundServiceChanged(anyInt(), any());
-  }
-
-  @Test
-  public void testSetDefaultForNextTapWithNullService_NotifyChange() {
-    services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
-    services.mForegroundUid = FOREGROUND_UID;
-    services.mForegroundRequested = null;
-    services.mForegroundCurrent = TEST_COMPONENT;
-
-    boolean result = services.setDefaultForNextTap(USER_ID, /* service = */ null);
-
-    assertThat(result).isTrue();
-    assertThat(services.mNextTapDefault).isNull();
-    assertThat(services.mNextTapDefaultUserId).isEqualTo(USER_ID);
-    assertThat(services.mForegroundCurrent).isEqualTo(null);
-    assertThat(services.mForegroundCurrentUid).isEqualTo(FOREGROUND_UID);
-    verify(mCallback)
-        .onPreferredForegroundServiceChanged(userIdCaptor.capture(), candidateCaptor.capture());
-    assertThat(userIdCaptor.getValue()).isEqualTo(FOREGROUND_UID);
-    assertThat(candidateCaptor.getValue()).isNull();
-  }
-
-  @Test
-  public void testOnServicesUpdatedWithNullForeground_NoChange() {
-    services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
-    services.mForegroundCurrent = null;
-
-    services.onServicesUpdated();
-
-    assertThat(services.mForegroundRequested).isNull();
-    assertThat(services.mForegroundUid).isEqualTo(0);
-    assertThat(services.mForegroundCurrentUid).isEqualTo(0);
-  }
-
-  @Test
-  public void testOnServicesUpdatedWithNonNullForegroundAndPaymentServiceInfo_CommitsChange() {
-    when(mObserver.isWalletRoleFeatureEnabled()).thenReturn(true);
-    when(mServicesCache.getInstalledServices(eq(USER_ID))).thenReturn(getPaymentServices());
-    when(mServicesCache.getService(anyInt(), any())).thenReturn(mServiceInfoPayment);
-    when(mObserver.getDefaultWalletRoleHolder(eq(USER_ID))).thenReturn(WALLET_HOLDER_PACKAGE_NAME);
-    services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
-    services.mUserIdDefaultWalletHolder = USER_ID;
-    services.mForegroundCurrent = TEST_COMPONENT;
-    services.mForegroundCurrentUid = FOREGROUND_UID;
-    services.mPaymentDefaults.currentPreferred = null;
-    services.mPaymentDefaults.preferForeground = false;
-
-    services.onServicesUpdated();
-
-    assertThat(services.mForegroundRequested).isNull();
-    assertThat(services.mForegroundUid).isEqualTo(-1);
-    assertThat(services.mForegroundCurrentUid).isEqualTo(-1);
-    assertWalletRoleHolderUpdated();
-  }
-
-  @Test
-  public void testOnServicesUpdatedWithNonNullForegroundAndNonPaymentServiceInfo_CommitsChange() {
-    when(mObserver.isWalletRoleFeatureEnabled()).thenReturn(true);
-    when(mServicesCache.getInstalledServices(eq(USER_ID))).thenReturn(getPaymentServices());
-    when(mServicesCache.getService(anyInt(), any())).thenReturn(mServiceInfoNonPayment);
-    when(mObserver.getDefaultWalletRoleHolder(eq(USER_ID))).thenReturn(WALLET_HOLDER_PACKAGE_NAME);
-    mResolveInfo.category = CardEmulation.CATEGORY_PAYMENT;
-    mResolveInfo.defaultService = mServiceInfoNonPayment;
-    services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
-    services.mUserIdDefaultWalletHolder = USER_ID;
-    services.mForegroundCurrent = TEST_COMPONENT;
-    services.mForegroundCurrentUid = FOREGROUND_UID;
-    services.mPaymentDefaults.currentPreferred = null;
-    services.mPaymentDefaults.mUserHandle = mUserHandle;
-    services.mPaymentDefaults.preferForeground = false;
-
-    services.onServicesUpdated();
-
-    assertThat(services.mForegroundRequested).isNull();
-    assertThat(services.mForegroundUid).isEqualTo(-1);
-    assertThat(services.mForegroundCurrentUid).isEqualTo(-1);
-    assertWalletRoleHolderUpdated();
-  }
-
-  @Test
-  public void testOnServicesUpdatedWithNonNullForegroundAndNonPaymentServiceInfo_NoChange() {
-    when(mObserver.isWalletRoleFeatureEnabled()).thenReturn(true);
-    when(mServicesCache.getInstalledServices(eq(USER_ID))).thenReturn(getPaymentServices());
-    when(mServicesCache.getService(anyInt(), any())).thenReturn(mServiceInfoNonPayment);
-    when(mObserver.getDefaultWalletRoleHolder(eq(USER_ID))).thenReturn(WALLET_HOLDER_PACKAGE_NAME);
-    mResolveInfo.category = CardEmulation.CATEGORY_PAYMENT;
-    mResolveInfo.defaultService = null;
-    services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
-    services.mUserIdDefaultWalletHolder = USER_ID;
-    services.mForegroundCurrent = TEST_COMPONENT;
-    services.mForegroundCurrentUid = FOREGROUND_UID;
-    services.mPaymentDefaults.currentPreferred = null;
-    services.mPaymentDefaults.mUserHandle = mUserHandle;
-    services.mPaymentDefaults.preferForeground = false;
-
-    services.onServicesUpdated();
-
-    assertThat(services.mForegroundRequested).isNull();
-    assertThat(services.mForegroundUid).isEqualTo(0);
-    assertThat(services.mForegroundCurrentUid).isEqualTo(FOREGROUND_UID);
-    assertWalletRoleHolderUpdated();
-  }
-
-  @Test
-  public void testRegisterPreferredForegroundServiceWithSuccess() {
-    when(mForegroundUtils.registerUidToBackgroundCallback(any(), anyInt())).thenReturn(true);
-    services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
-    services.mPaymentDefaults.currentPreferred = TEST_COMPONENT;
-
-    boolean result = services.registerPreferredForegroundService(TEST_COMPONENT, USER_ID);
-
-    assertThat(result).isTrue();
-    assertThat(services.mForegroundRequested).isEqualTo(TEST_COMPONENT);
-    assertThat(services.mForegroundUid).isEqualTo(USER_ID);
-  }
-
-  @Test
-  public void testRegisterPreferredForegroundServiceWithFailure() {
-    when(mForegroundUtils.registerUidToBackgroundCallback(any(), anyInt())).thenReturn(false);
-    services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
-    services.mPaymentDefaults.currentPreferred = TEST_COMPONENT;
-
-    boolean result = services.registerPreferredForegroundService(TEST_COMPONENT, USER_ID);
-
-    assertThat(result).isFalse();
-    assertThat(services.mForegroundRequested).isNull();
-    assertThat(services.mForegroundUid).isEqualTo(0);
-  }
-
-  @Test
-  public void testUnregisteredPreferredForegroundServiceInForeground_ReturnsSuccess() {
-    when(mForegroundUtils.isInForeground(anyInt())).thenReturn(true);
-    services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
-    services.mForegroundUid = FOREGROUND_UID;
-
-    boolean result = services.unregisteredPreferredForegroundService(FOREGROUND_UID);
-
-    assertThat(result).isTrue();
-    assertThat(services.mForegroundRequested).isNull();
-    assertThat(services.mForegroundUid).isEqualTo(-1);
-  }
-
-  @Test
-  public void testUnregisteredPreferredForegroundServiceInForeground_ReturnsFailure() {
-    when(mForegroundUtils.isInForeground(anyInt())).thenReturn(true);
-    services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
-    services.mForegroundUid = FOREGROUND_UID;
-
-    boolean result = services.unregisteredPreferredForegroundService(USER_ID);
-
-    assertThat(result).isFalse();
-    assertThat(services.mForegroundRequested).isNull();
-    assertThat(services.mForegroundUid).isEqualTo(FOREGROUND_UID);
-  }
-
-  @Test
-  public void testUnregisteredPreferredForegroundServiceNotInForeground_ReturnsFailure() {
-    when(mForegroundUtils.isInForeground(anyInt())).thenReturn(false);
-    services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
-
-    boolean result = services.unregisteredPreferredForegroundService(USER_ID);
-
-    assertThat(result).isFalse();
-    assertThat(services.mForegroundRequested).isNull();
-    assertThat(services.mForegroundUid).isEqualTo(0);
-  }
-
-  @Test
-  public void testOnUidToBackground_SuccessfullyUnregistersService() {
-    services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
-    services.mForegroundUid = FOREGROUND_UID;
-
-    services.onUidToBackground(FOREGROUND_UID);
-
-    assertThat(services.mForegroundUid).isEqualTo(-1);
-  }
-
-  @Test
-  public void testOnUidToBackground_FailsToUnregisterService() {
-    services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
-    services.mForegroundUid = FOREGROUND_UID;
-
-    services.onUidToBackground(USER_ID);
-
-    assertThat(services.mForegroundUid).isEqualTo(FOREGROUND_UID);
-  }
-
-  @Test
-  public void testOnHostEmulationActivated() {
-    services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
-    services.mNextTapDefault = TEST_COMPONENT;
+    private PreferredServices services;
+    private MockitoSession mStaticMockSession;
+    private Context mContext;
+
+    @Mock
+    private RegisteredServicesCache mServicesCache;
+    @Mock
+    private PreferredServices.Callback mCallback;
+    @Mock
+    private RegisteredAidCache mAidCache;
+    @Mock
+    private WalletRoleObserver mObserver;
+    @Mock
+    private ForegroundUtils mForegroundUtils;
+    @Mock
+    private ContentResolver mContentResolver;
+    @Mock
+    private UserManager mUserManager;
+    @Mock
+    private ActivityManager mActivityManager;
+    @Mock
+    private ApduServiceInfo mServiceInfoPayment;
+    @Mock
+    private ApduServiceInfo mServiceInfoNonPayment;
+    @Mock
+    private UserHandle mUserHandle;
+    @Mock
+    private PrintWriter mPrintWriter;
+    @Mock
+    private RegisteredAidCache.AidResolveInfo mResolveInfo;
+    @Captor
+    private ArgumentCaptor<Integer> userIdCaptor;
+    @Captor
+    private ArgumentCaptor<ComponentName> candidateCaptor;
+    @Captor
+    private ArgumentCaptor<ContentObserver> mSettingsObserverCaptor;
+
+    private static final String WALLET_HOLDER_PACKAGE_NAME = "com.android.test.walletroleholder";
+    private static final ComponentName TEST_COMPONENT
+            = new ComponentName(WALLET_HOLDER_PACKAGE_NAME,
+            "com.android.test.walletroleholder.WalletRoleHolderApduService");
+    private static final int USER_ID = 1;
+    private static final int FOREGROUND_UID = 7;
+
+    @Before
+    public void setUp() throws Exception {
+        mStaticMockSession = ExtendedMockito.mockitoSession()
+                .mockStatic(ForegroundUtils.class)
+                .mockStatic(ActivityManager.class)
+                .mockStatic(UserHandle.class)
+                .mockStatic(Settings.Secure.class)
+                .mockStatic(ComponentName.class)
+                .strictness(Strictness.LENIENT)
+                .startMocking();
+        MockitoAnnotations.initMocks(this);
+        mContext = new ContextWrapper(
+                InstrumentationRegistry.getInstrumentation().getTargetContext()) {
+            @Override
+            public Object getSystemService(String name) {
+                if (Context.ACTIVITY_SERVICE.equals(name)) {
+                    return (ActivityManager) mActivityManager;
+                } else if (Context.USER_SERVICE.equals(name)) {
+                    return (UserManager) mUserManager;
+                } else {
+                    return null;
+                }
+            }
+
+            @Override
+            public Context createContextAsUser(UserHandle user, int flags) {
+                return mContext;
+            }
+
+            @Override
+            public ContentResolver getContentResolver() {
+                return mContentResolver;
+            }
+        };
+
+        when(ForegroundUtils.getInstance(any(ActivityManager.class))).thenReturn(mForegroundUtils);
+        when(ActivityManager.getCurrentUser()).thenReturn(USER_ID);
+        doNothing().when(mContentResolver)
+                .registerContentObserverAsUser(any(Uri.class), anyBoolean(), any(),
+                        any(UserHandle.class));
+        doNothing().when(mCallback).onPreferredPaymentServiceChanged(anyInt(), any());
+        when(Settings.Secure.getString(any(ContentResolver.class), anyString()))
+                .thenReturn("com.android.test.walletroleholder/com.android"
+                        + ".test.walletroleholder.WalletRoleHolderApduService");
+        when(Settings.Secure.getInt(any(ContentResolver.class), anyString())).thenReturn(USER_ID);
+        when(UserHandle.getUserHandleForUid(anyInt())).thenReturn(mUserHandle);
+        when(UserHandle.of(anyInt())).thenReturn(mUserHandle);
+        when(mUserHandle.getIdentifier()).thenReturn(FOREGROUND_UID);
+        when(mObserver.getDefaultWalletRoleHolder(anyInt())).thenReturn(null);
+        when(mServiceInfoPayment.getComponent()).thenReturn(TEST_COMPONENT);
+        when(mServiceInfoPayment.getAids()).thenReturn(getAids());
+        when(mServiceInfoPayment
+                .getCategoryForAid(anyString())).thenReturn(CardEmulation.CATEGORY_PAYMENT);
+        when(mServiceInfoPayment.hasCategory(eq(CardEmulation.CATEGORY_PAYMENT)))
+                .thenReturn(true);
+        when(mServiceInfoNonPayment.hasCategory(eq(CardEmulation.CATEGORY_PAYMENT))).thenReturn(
+                false);
+        when(mServiceInfoNonPayment.getAids()).thenReturn(getAids());
+        when(mAidCache.resolveAid(anyString())).thenReturn(mResolveInfo);
+        when(mUserManager.getEnabledProfiles()).thenReturn(getUserHandles());
+        // Wallet role feature is enabled by default; several test cases set this value to false
+        when(mObserver.isWalletRoleFeatureEnabled()).thenReturn(true);
+    }
+
+    @After
+    public void tearDown() {
+        mStaticMockSession.finishMocking();
+    }
+
+    @Test
+    public void testConstructorWhenWalletRoleFeatureIsNotEnabled() {
+        when(mObserver.isWalletRoleFeatureEnabled()).thenReturn(false);
+
+        services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
+
+        assertThat(services.mContext).isEqualTo(mContext);
+        assertThat(services.mWalletRoleObserver).isEqualTo(mObserver);
+        assertThat(services.mForegroundUtils).isEqualTo(mForegroundUtils);
+        assertThat(services.mServiceCache).isEqualTo(mServicesCache);
+        assertThat(services.mAidCache).isEqualTo(mAidCache);
+        assertThat(services.mCallback).isEqualTo(mCallback);
+        assertThat(services.mSettingsObserver).isNotNull();
+        verify(mContentResolver, times(2))
+                .registerContentObserverAsUser(any(), anyBoolean(), any(), any(UserHandle.class));
+        verify(mUserManager).getEnabledProfiles();
+        verify(mObserver, never()).getDefaultWalletRoleHolder(anyInt());
+    }
+
+    @Test
+    public void testConstructorWhenWalletRoleFeatureIsEnabled() {
+        services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
+
+        assertThat(services.mContext).isEqualTo(mContext);
+        assertThat(services.mWalletRoleObserver).isEqualTo(mObserver);
+        assertThat(services.mForegroundUtils).isEqualTo(mForegroundUtils);
+        assertThat(services.mServiceCache).isEqualTo(mServicesCache);
+        assertThat(services.mAidCache).isEqualTo(mAidCache);
+        assertThat(services.mCallback).isEqualTo(mCallback);
+        assertThat(services.mSettingsObserver).isNotNull();
+        verify(mContentResolver, times(2))
+                .registerContentObserverAsUser(any(), anyBoolean(), any(), any(UserHandle.class));
+        verify(mUserManager).getEnabledProfiles();
+        verify(mObserver).getDefaultWalletRoleHolder(anyInt());
+        assertThat(services.mDefaultWalletHolderPaymentService).isNull();
+        verify(mCallback).onPreferredPaymentServiceChanged(anyInt(), any());
+    }
+
+    @Test
+    public void testOnWalletRoleHolderChangedWithNullPackageName() {
+        services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
+
+        services.onWalletRoleHolderChanged(null, USER_ID);
+
+        verify(mCallback, times(2))
+                .onPreferredPaymentServiceChanged(userIdCaptor.capture(),
+                        candidateCaptor.capture());
+        List<Integer> userIds = userIdCaptor.getAllValues();
+        assertThat(userIds.get(0)).isEqualTo(USER_ID);
+        assertThat(userIds.get(1)).isEqualTo(USER_ID);
+        List<ComponentName> candidates = candidateCaptor.getAllValues();
+        assertThat(candidates.get(0)).isNull();
+        assertThat(candidates.get(1)).isNull();
+        assertThat(services.mDefaultWalletHolderPaymentService).isNull();
+    }
+
+    @Test
+    public void testOnWalletRoleHolderChangedWithExistingPackageNameAndExistingServiceInfos() {
+        when(mServicesCache.getInstalledServices(eq(USER_ID))).thenReturn(getPaymentServices());
+        services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
+
+        services.onWalletRoleHolderChanged(WALLET_HOLDER_PACKAGE_NAME, USER_ID);
+
+        assertThat(services.mUserIdDefaultWalletHolder).isEqualTo(USER_ID);
+        verify(mCallback, times(2))
+                .onPreferredPaymentServiceChanged(userIdCaptor.capture(),
+                        candidateCaptor.capture());
+        List<Integer> userIds = userIdCaptor.getAllValues();
+        assertThat(userIds.get(0)).isEqualTo(USER_ID);
+        assertThat(userIds.get(1)).isEqualTo(USER_ID);
+        List<ComponentName> candidates = candidateCaptor.getAllValues();
+        assertThat(candidates.get(0)).isNull();
+        assertThat(candidates.get(1)).isEqualTo(TEST_COMPONENT);
+        assertThat(services.mDefaultWalletHolderPaymentService).isEqualTo(TEST_COMPONENT);
+    }
+
+    @Test
+    public void testOnWalletRoleHolderChangedWithExistingPackageNameAndNoServiceInfo() {
+        ArrayList<ApduServiceInfo> emptyList = new ArrayList<>();
+        when(mServicesCache.getInstalledServices(eq(USER_ID))).thenReturn(emptyList);
+        services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
+
+        services.onWalletRoleHolderChanged(WALLET_HOLDER_PACKAGE_NAME, USER_ID);
+
+        assertThat(services.mUserIdDefaultWalletHolder).isEqualTo(USER_ID);
+        verify(mCallback).onPreferredPaymentServiceChanged(anyInt(), any());
+        assertThat(services.mDefaultWalletHolderPaymentService).isNull();
+    }
+
+    @Test
+    public void testOnWalletRoleHolderChangedWithIncorrectPackageName() {
+        when(mServicesCache.getInstalledServices(eq(USER_ID))).thenReturn(getPaymentServices());
+        services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
+
+        services.onWalletRoleHolderChanged(/* defaultWalletHolderPackageName = */ "", USER_ID);
+
+        assertThat(services.mUserIdDefaultWalletHolder).isEqualTo(USER_ID);
+        verify(mCallback).onPreferredPaymentServiceChanged(anyInt(), any());
+        assertThat(services.mDefaultWalletHolderPaymentService).isNull();
+    }
+
+    @Test
+    public void testSetDefaultForNextTapWithNonNullService_NotifyChange() {
+        services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
+        services.mForegroundUid = FOREGROUND_UID;
+
+        boolean result = services.setDefaultForNextTap(USER_ID, TEST_COMPONENT);
+
+        assertThat(result).isTrue();
+        assertThat(services.mNextTapDefault).isEqualTo(TEST_COMPONENT);
+        assertThat(services.mNextTapDefaultUserId).isEqualTo(USER_ID);
+        assertThat(services.mForegroundCurrent).isEqualTo(TEST_COMPONENT);
+        assertThat(services.mForegroundCurrentUid).isEqualTo(FOREGROUND_UID);
+        verify(mCallback)
+                .onPreferredForegroundServiceChanged(userIdCaptor.capture(),
+                        candidateCaptor.capture());
+        assertThat(userIdCaptor.getValue()).isEqualTo(USER_ID);
+        assertThat(candidateCaptor.getValue()).isEqualTo(TEST_COMPONENT);
+    }
+
+    @Test
+    public void testSetDefaultForNextTapWithNullService_NoChange() {
+        services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
+        services.mForegroundUid = FOREGROUND_UID;
+        services.mForegroundRequested = null;
+        services.mForegroundCurrent = null;
+
+        boolean result = services.setDefaultForNextTap(USER_ID, /* service = */ null);
+
+        assertThat(result).isTrue();
+        assertThat(services.mNextTapDefault).isNull();
+        assertThat(services.mNextTapDefaultUserId).isEqualTo(USER_ID);
+        assertThat(services.mForegroundCurrent).isEqualTo(null);
+        assertThat(services.mForegroundCurrentUid).isEqualTo(0);
+        verify(mCallback, never()).onPreferredForegroundServiceChanged(anyInt(), any());
+    }
+
+    @Test
+    public void testSetDefaultForNextTapWithNonNullService_NoChange() {
+        services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
+        services.mForegroundCurrent = TEST_COMPONENT;
+
+        boolean result = services.setDefaultForNextTap(FOREGROUND_UID, TEST_COMPONENT);
+
+        assertThat(result).isTrue();
+        assertThat(services.mNextTapDefault).isEqualTo(TEST_COMPONENT);
+        assertThat(services.mNextTapDefaultUserId).isEqualTo(FOREGROUND_UID);
+        assertThat(services.mForegroundCurrent).isEqualTo(TEST_COMPONENT);
+        assertThat(services.mForegroundCurrentUid).isEqualTo(0);
+        verify(mCallback, never()).onPreferredForegroundServiceChanged(anyInt(), any());
+    }
+
+    @Test
+    public void testSetDefaultForNextTapWithNullService_NotifyChange() {
+        services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
+        services.mForegroundUid = FOREGROUND_UID;
+        services.mForegroundRequested = null;
+        services.mForegroundCurrent = TEST_COMPONENT;
+
+        boolean result = services.setDefaultForNextTap(USER_ID, /* service = */ null);
+
+        assertThat(result).isTrue();
+        assertThat(services.mNextTapDefault).isNull();
+        assertThat(services.mNextTapDefaultUserId).isEqualTo(USER_ID);
+        assertThat(services.mForegroundCurrent).isEqualTo(null);
+        assertThat(services.mForegroundCurrentUid).isEqualTo(FOREGROUND_UID);
+        verify(mCallback)
+                .onPreferredForegroundServiceChanged(userIdCaptor.capture(),
+                        candidateCaptor.capture());
+        assertThat(userIdCaptor.getValue()).isEqualTo(FOREGROUND_UID);
+        assertThat(candidateCaptor.getValue()).isNull();
+    }
+
+    @Test
+    public void testOnServicesUpdatedWithNullForeground_NoChange() {
+        services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
+        services.mForegroundCurrent = null;
+
+        services.onServicesUpdated();
+
+        assertThat(services.mForegroundRequested).isNull();
+        assertThat(services.mForegroundUid).isEqualTo(0);
+        assertThat(services.mForegroundCurrentUid).isEqualTo(0);
+    }
+
+    @Test
+    public void testOnServicesUpdatedWithNonNullForegroundAndPaymentServiceInfo_CommitsChange() {
+        when(mObserver.isWalletRoleFeatureEnabled()).thenReturn(true);
+        when(mServicesCache.getInstalledServices(eq(USER_ID))).thenReturn(getPaymentServices());
+        when(mServicesCache.getService(anyInt(), any())).thenReturn(mServiceInfoPayment);
+        when(mObserver.getDefaultWalletRoleHolder(eq(USER_ID))).thenReturn(
+                WALLET_HOLDER_PACKAGE_NAME);
+        services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
+        services.mUserIdDefaultWalletHolder = USER_ID;
+        services.mForegroundCurrent = TEST_COMPONENT;
+        services.mForegroundCurrentUid = FOREGROUND_UID;
+        services.mPaymentDefaults.currentPreferred = null;
+        services.mPaymentDefaults.preferForeground = false;
+
+        services.onServicesUpdated();
+
+        assertThat(services.mForegroundRequested).isNull();
+        assertThat(services.mForegroundUid).isEqualTo(Process.INVALID_UID);
+        assertThat(services.mForegroundCurrentUid).isEqualTo(Process.INVALID_UID);
+        assertWalletRoleHolderUpdated();
+    }
+
+    @Test
+    public void testOnServicesUpdatedWithNonNullForegroundAndNonPaymentServiceInfo_CommitsChange() {
+        when(mObserver.isWalletRoleFeatureEnabled()).thenReturn(true);
+        when(mServicesCache.getInstalledServices(eq(USER_ID))).thenReturn(getPaymentServices());
+        when(mServicesCache.getService(anyInt(), any())).thenReturn(mServiceInfoNonPayment);
+        when(mObserver.getDefaultWalletRoleHolder(eq(USER_ID))).thenReturn(
+                WALLET_HOLDER_PACKAGE_NAME);
+        mResolveInfo.category = CardEmulation.CATEGORY_PAYMENT;
+        mResolveInfo.defaultService = mServiceInfoNonPayment;
+        services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
+        services.mUserIdDefaultWalletHolder = USER_ID;
+        services.mForegroundCurrent = TEST_COMPONENT;
+        services.mForegroundCurrentUid = FOREGROUND_UID;
+        services.mPaymentDefaults.currentPreferred = null;
+        services.mPaymentDefaults.mUserHandle = mUserHandle;
+        services.mPaymentDefaults.preferForeground = false;
+
+        services.onServicesUpdated();
+
+        assertThat(services.mForegroundRequested).isNull();
+        assertThat(services.mForegroundUid).isEqualTo(Process.INVALID_UID);
+        assertThat(services.mForegroundCurrentUid).isEqualTo(Process.INVALID_UID);
+        assertWalletRoleHolderUpdated();
+    }
+
+    @Test
+    public void testOnServicesUpdatedWithNonNullForegroundAndNonPaymentServiceInfo_NoChange() {
+        when(mObserver.isWalletRoleFeatureEnabled()).thenReturn(true);
+        when(mServicesCache.getInstalledServices(eq(USER_ID))).thenReturn(getPaymentServices());
+        when(mServicesCache.getService(anyInt(), any())).thenReturn(mServiceInfoNonPayment);
+        when(mObserver.getDefaultWalletRoleHolder(eq(USER_ID))).thenReturn(
+                WALLET_HOLDER_PACKAGE_NAME);
+        mResolveInfo.category = CardEmulation.CATEGORY_PAYMENT;
+        mResolveInfo.defaultService = null;
+        services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
+        services.mUserIdDefaultWalletHolder = USER_ID;
+        services.mForegroundCurrent = TEST_COMPONENT;
+        services.mForegroundCurrentUid = FOREGROUND_UID;
+        services.mPaymentDefaults.currentPreferred = null;
+        services.mPaymentDefaults.mUserHandle = mUserHandle;
+        services.mPaymentDefaults.preferForeground = false;
+
+        services.onServicesUpdated();
+
+        assertThat(services.mForegroundRequested).isNull();
+        assertThat(services.mForegroundUid).isEqualTo(0);
+        assertThat(services.mForegroundCurrentUid).isEqualTo(FOREGROUND_UID);
+        assertWalletRoleHolderUpdated();
+    }
+
+    @Test
+    public void testRegisterPreferredForegroundServiceWithSuccess() {
+        when(mForegroundUtils.registerUidToBackgroundCallback(any(), anyInt())).thenReturn(true);
+        services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
+        services.mPaymentDefaults.currentPreferred = TEST_COMPONENT;
+
+        boolean result = services.registerPreferredForegroundService(TEST_COMPONENT, USER_ID);
+
+        assertThat(result).isTrue();
+        assertThat(services.mForegroundRequested).isEqualTo(TEST_COMPONENT);
+        assertThat(services.mForegroundUid).isEqualTo(USER_ID);
+    }
+
+    @Test
+    public void testRegisterPreferredForegroundServiceWithFailure() {
+        when(mForegroundUtils.registerUidToBackgroundCallback(any(), anyInt())).thenReturn(false);
+        services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
+        services.mPaymentDefaults.currentPreferred = TEST_COMPONENT;
+
+        boolean result = services.registerPreferredForegroundService(TEST_COMPONENT, USER_ID);
+
+        assertThat(result).isFalse();
+        assertThat(services.mForegroundRequested).isNull();
+        assertThat(services.mForegroundUid).isEqualTo(0);
+    }
+
+    @Test
+    public void testUnregisteredPreferredForegroundServiceInForeground_ReturnsSuccess() {
+        when(mForegroundUtils.isInForeground(anyInt())).thenReturn(true);
+        services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
+        services.mForegroundUid = FOREGROUND_UID;
+
+        boolean result = services.unregisteredPreferredForegroundService(FOREGROUND_UID);
+
+        assertThat(result).isTrue();
+        assertThat(services.mForegroundRequested).isNull();
+        assertThat(services.mForegroundUid).isEqualTo(Process.INVALID_UID);
+    }
+
+    @Test
+    public void testUnregisteredPreferredForegroundServiceInForeground_ReturnsFailure() {
+        when(mForegroundUtils.isInForeground(anyInt())).thenReturn(true);
+        services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
+        services.mForegroundUid = FOREGROUND_UID;
+
+        boolean result = services.unregisteredPreferredForegroundService(USER_ID);
+
+        assertThat(result).isFalse();
+        assertThat(services.mForegroundRequested).isNull();
+        assertThat(services.mForegroundUid).isEqualTo(FOREGROUND_UID);
+    }
+
+    @Test
+    public void testUnregisteredPreferredForegroundServiceNotInForeground_ReturnsFailure() {
+        when(mForegroundUtils.isInForeground(anyInt())).thenReturn(false);
+        services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
+
+        boolean result = services.unregisteredPreferredForegroundService(USER_ID);
+
+        assertThat(result).isFalse();
+        assertThat(services.mForegroundRequested).isNull();
+        assertThat(services.mForegroundUid).isEqualTo(0);
+    }
+
+    @Test
+    public void testOnUidToBackground_SuccessfullyUnregistersService() {
+        services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
+        services.mForegroundUid = FOREGROUND_UID;
+
+        services.onUidToBackground(FOREGROUND_UID);
+
+        assertThat(services.mForegroundUid).isEqualTo(Process.INVALID_UID);
+    }
+
+    @Test
+    public void testOnUidToBackground_FailsToUnregisterService() {
+        services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
+        services.mForegroundUid = FOREGROUND_UID;
+
+        services.onUidToBackground(USER_ID);
+
+        assertThat(services.mForegroundUid).isEqualTo(FOREGROUND_UID);
+    }
+
+    @Test
+    public void testOnHostEmulationActivated() {
+        services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
+        services.mNextTapDefault = TEST_COMPONENT;
+
+        services.onHostEmulationActivated();
 
-    services.onHostEmulationActivated();
+        assertThat(services.mClearNextTapDefault).isTrue();
+    }
 
-    assertThat(services.mClearNextTapDefault).isTrue();
-  }
-
-  @Test
-  public void testOnHostEmulationDeactivated() {
-    services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
-    services.mClearNextTapDefault = true;
-    services.mNextTapDefault = TEST_COMPONENT;
-
-    services.onHostEmulationDeactivated();
-
-    assertThat(services.mNextTapDefault).isNull();
-    assertThat(services.mClearNextTapDefault).isFalse();
-  }
-
-  @Test
-  public void testOnUserSwitchedWithChange() {
-    when(mObserver.isWalletRoleFeatureEnabled()).thenReturn(false);
-    services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
-    services.mPaymentDefaults.preferForeground = false;
-    services.mPaymentDefaults.currentPreferred = TEST_COMPONENT;
-
-    services.onUserSwitched(USER_ID);
-
-    assertThat(services.mPaymentDefaults.preferForeground).isTrue();
-    assertThat(services.mPaymentDefaults.settingsDefault).isEqualTo(null);
-    assertThat(services.mPaymentDefaults.currentPreferred).isEqualTo(null);
-    assertThat(services.mPaymentDefaults.mUserHandle).isEqualTo(mUserHandle);
-    verify(mCallback)
-        .onPreferredPaymentServiceChanged(userIdCaptor.capture(), candidateCaptor.capture());
-    assertThat(userIdCaptor.getValue()).isEqualTo(FOREGROUND_UID);
-    assertThat(candidateCaptor.getValue()).isEqualTo(null);
-  }
-
-  @Test
-  public void testOnUserSwitchedWithNoChange() throws Exception {
-    when(mUserManager.getEnabledProfiles()).thenReturn(getUserHandles());
-    services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
-    services.mPaymentDefaults.preferForeground = false;
-    services.mPaymentDefaults.currentPreferred = null;
-    verify(mCallback).onPreferredPaymentServiceChanged(anyInt(), any());
-
-    services.onUserSwitched(USER_ID);
-
-    assertThat(services.mPaymentDefaults.preferForeground).isTrue();
-    assertThat(services.mPaymentDefaults.settingsDefault).isEqualTo(null);
-    assertThat(services.mPaymentDefaults.currentPreferred).isEqualTo(null);
-    assertThat(services.mPaymentDefaults.mUserHandle).isEqualTo(null);
-    verifyNoMoreInteractions(mCallback);
-  }
-
-  @Test
-  public void testPackageHasPreferredServiceWithNullPackageName_ReturnsFalse() {
-    services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
-
-    boolean result = services.packageHasPreferredService(/* packageName = */ null);
-
-    assertThat(result).isFalse();
-  }
-
-  @Test
-  public void testPackageHasPreferredServiceWithMatchingPackageName_ReturnsTrue() {
-    services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
-    services.mPaymentDefaults.currentPreferred = TEST_COMPONENT;
-
-    boolean result = services.packageHasPreferredService(WALLET_HOLDER_PACKAGE_NAME);
-
-    assertThat(result).isTrue();
-  }
-
-  @Test
-  public void testPackageHasPreferredServiceWithNonMatchingPackageName_ReturnsFalse() {
-    services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
-
-    boolean result = services.packageHasPreferredService(WALLET_HOLDER_PACKAGE_NAME);
-
-    assertThat(result).isFalse();
-  }
-
-  @Test
-  public void testDump() {
-    when(mObserver.isWalletRoleFeatureEnabled()).thenReturn(false);
-    when(mUserManager.getUserName()).thenReturn("");
-    services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
-
-    services.dump(null, mPrintWriter, null);
-
-    verify(mPrintWriter, times(8)).println(anyString());
-  }
-
-  @Test
-  public void testDump_withWalletRole() {
-    when(mObserver.isWalletRoleFeatureEnabled()).thenReturn(true);
-    when(mUserManager.getUserName()).thenReturn("");
-    services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
-
-    services.dump(null, mPrintWriter, null);
-
-    verify(mPrintWriter, times(7)).println(anyString());
-  }
-
-  private void assertWalletRoleHolderUpdated() {
-    verify(mObserver, times(4)).isWalletRoleFeatureEnabled();
-    verify(mObserver, times(2)).getDefaultWalletRoleHolder(eq(USER_ID));
-    assertThat(services.mUserIdDefaultWalletHolder).isEqualTo(USER_ID);
-    verify(mCallback)
-            .onPreferredPaymentServiceChanged(userIdCaptor.capture(), candidateCaptor.capture());
-    List<Integer> userIds = userIdCaptor.getAllValues();
-    assertThat(userIds.get(0)).isEqualTo(USER_ID);
-    List<ComponentName> candidates = candidateCaptor.getAllValues();
-    assertThat(candidates.get(0)).isEqualTo(TEST_COMPONENT);
-    assertThat(services.mDefaultWalletHolderPaymentService).isEqualTo(TEST_COMPONENT);
-  }
-
-  private ArrayList<String> getAids() {
-    ArrayList<String> aids = new ArrayList<>();
-    aids.add("aid");
-    return aids;
-  }
-
-  private ArrayList<ApduServiceInfo> getPaymentServices() {
-    ArrayList<ApduServiceInfo> serviceInfos = new ArrayList<>();
-    serviceInfos.add(mServiceInfoPayment);
-    return serviceInfos;
-  }
-
-  private ArrayList<UserHandle> getUserHandles() {
-    ArrayList<UserHandle> list = new ArrayList<>();
-    list.add(mUserHandle);
-    return list;
-  }
+    @Test
+    public void testOnHostEmulationDeactivated() {
+        services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
+        services.mClearNextTapDefault = true;
+        services.mNextTapDefault = TEST_COMPONENT;
+
+        services.onHostEmulationDeactivated();
+
+        assertThat(services.mNextTapDefault).isNull();
+        assertThat(services.mClearNextTapDefault).isFalse();
+    }
+
+    @Test
+    public void testOnUserSwitchedWithChange() {
+        when(mObserver.isWalletRoleFeatureEnabled()).thenReturn(false);
+        services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
+        services.mPaymentDefaults.preferForeground = false;
+        services.mPaymentDefaults.currentPreferred = TEST_COMPONENT;
+
+        services.onUserSwitched(USER_ID);
+
+        assertThat(services.mPaymentDefaults.preferForeground).isTrue();
+        assertThat(services.mPaymentDefaults.settingsDefault).isEqualTo(null);
+        assertThat(services.mPaymentDefaults.currentPreferred).isEqualTo(null);
+        assertThat(services.mPaymentDefaults.mUserHandle).isEqualTo(mUserHandle);
+        verify(mCallback)
+                .onPreferredPaymentServiceChanged(userIdCaptor.capture(),
+                        candidateCaptor.capture());
+        assertThat(userIdCaptor.getValue()).isEqualTo(FOREGROUND_UID);
+        assertThat(candidateCaptor.getValue()).isEqualTo(null);
+    }
+
+    @Test
+    public void testOnUserSwitchedWithNoChange() throws Exception {
+        when(mUserManager.getEnabledProfiles()).thenReturn(getUserHandles());
+        services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
+        services.mPaymentDefaults.preferForeground = false;
+        services.mPaymentDefaults.currentPreferred = null;
+        verify(mCallback).onPreferredPaymentServiceChanged(anyInt(), any());
+
+        services.onUserSwitched(USER_ID);
+
+        assertThat(services.mPaymentDefaults.preferForeground).isTrue();
+        assertThat(services.mPaymentDefaults.settingsDefault).isEqualTo(null);
+        assertThat(services.mPaymentDefaults.currentPreferred).isEqualTo(null);
+        assertThat(services.mPaymentDefaults.mUserHandle).isEqualTo(null);
+        verifyNoMoreInteractions(mCallback);
+    }
+
+    @Test
+    public void testPackageHasPreferredServiceWithNullPackageName_ReturnsFalse() {
+        services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
+
+        boolean result = services.packageHasPreferredService(/* packageName = */ null);
+
+        assertThat(result).isFalse();
+    }
+
+    @Test
+    public void testPackageHasPreferredServiceWithMatchingPackageName_ReturnsTrue() {
+        services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
+        services.mPaymentDefaults.currentPreferred = TEST_COMPONENT;
+
+        boolean result = services.packageHasPreferredService(WALLET_HOLDER_PACKAGE_NAME);
+
+        assertThat(result).isTrue();
+    }
+
+    @Test
+    public void testPackageHasPreferredServiceWithNonMatchingPackageName_ReturnsFalse() {
+        services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
+
+        boolean result = services.packageHasPreferredService(WALLET_HOLDER_PACKAGE_NAME);
+
+        assertThat(result).isFalse();
+    }
+
+    @Test
+    public void testDump() {
+        when(mObserver.isWalletRoleFeatureEnabled()).thenReturn(false);
+        when(mUserManager.getUserName()).thenReturn("");
+        services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
+
+        services.dump(null, mPrintWriter, null);
+
+        verify(mPrintWriter, times(8)).println(anyString());
+    }
+
+    @Test
+    public void testDump_withWalletRole() {
+        when(mObserver.isWalletRoleFeatureEnabled()).thenReturn(true);
+        when(mUserManager.getUserName()).thenReturn("");
+        services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
+
+        services.dump(null, mPrintWriter, null);
+
+        verify(mPrintWriter, times(7)).println(anyString());
+    }
+
+    private void assertWalletRoleHolderUpdated() {
+        verify(mObserver, times(4)).isWalletRoleFeatureEnabled();
+        verify(mObserver, times(2)).getDefaultWalletRoleHolder(eq(USER_ID));
+        assertThat(services.mUserIdDefaultWalletHolder).isEqualTo(USER_ID);
+        verify(mCallback)
+                .onPreferredPaymentServiceChanged(userIdCaptor.capture(),
+                        candidateCaptor.capture());
+        List<Integer> userIds = userIdCaptor.getAllValues();
+        assertThat(userIds.get(0)).isEqualTo(USER_ID);
+        List<ComponentName> candidates = candidateCaptor.getAllValues();
+        assertThat(candidates.get(0)).isEqualTo(TEST_COMPONENT);
+        assertThat(services.mDefaultWalletHolderPaymentService).isEqualTo(TEST_COMPONENT);
+    }
+
+    private ArrayList<String> getAids() {
+        ArrayList<String> aids = new ArrayList<>();
+        aids.add("aid");
+        return aids;
+    }
+
+    private ArrayList<ApduServiceInfo> getPaymentServices() {
+        ArrayList<ApduServiceInfo> serviceInfos = new ArrayList<>();
+        serviceInfos.add(mServiceInfoPayment);
+        return serviceInfos;
+    }
+
+    private ArrayList<UserHandle> getUserHandles() {
+        ArrayList<UserHandle> list = new ArrayList<>();
+        list.add(mUserHandle);
+        return list;
+    }
+
+    @Test
+    public void testSettingObserverOnChange() {
+        when(mUserManager.getUserName()).thenReturn("");
+        services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
+        verify(mContentResolver, times(2)).registerContentObserverAsUser(
+                any(), anyBoolean(), mSettingsObserverCaptor.capture(), any());
+        Uri uri = Settings.Secure.getUriFor(
+                Constants.SETTINGS_SECURE_NFC_PAYMENT_DEFAULT_COMPONENT);
+        mSettingsObserverCaptor.getValue().onChange(true, uri);
+        verify(mObserver, atLeast(1)).isWalletRoleFeatureEnabled();
+        assertTrue(services.mPaymentDefaults.preferForeground);
+    }
+
+    @Test
+    public void testSettingObserverOnChange_compute() {
+        when(mUserManager.getUserName()).thenReturn("");
+        services = new PreferredServices(mContext, mServicesCache, mAidCache, mObserver, mCallback);
+        services.mForegroundUid = FOREGROUND_UID;
+        boolean result = services.setDefaultForNextTap(USER_ID, TEST_COMPONENT);
+        assertThat(result).isTrue();
+        verify(mContentResolver, times(2)).registerContentObserverAsUser(
+                any(), anyBoolean(), mSettingsObserverCaptor.capture(), any());
+        Uri uri = Settings.Secure.getUriFor(
+                Constants.SETTINGS_SECURE_NFC_PAYMENT_DEFAULT_COMPONENT);
+        mSettingsObserverCaptor.getValue().onChange(true, uri);
+        verify(mObserver, atLeast(1)).isWalletRoleFeatureEnabled();
+        assertTrue(services.mPaymentDefaults.preferForeground);
+        verify(mCallback).onPreferredForegroundServiceChanged(anyInt(), any());
+    }
 }
\ No newline at end of file
diff --git a/tests/unit/src/com/android/nfc/cardemulation/RegisteredAidCacheTest.java b/tests/unit/src/com/android/nfc/cardemulation/RegisteredAidCacheTest.java
index 96c049c7..27138d83 100644
--- a/tests/unit/src/com/android/nfc/cardemulation/RegisteredAidCacheTest.java
+++ b/tests/unit/src/com/android/nfc/cardemulation/RegisteredAidCacheTest.java
@@ -16,6 +16,10 @@
 
 package com.android.nfc.cardemulation;
 
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.assertNull;
+import static org.junit.Assert.assertTrue;
 import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.ArgumentMatchers.eq;
@@ -137,8 +141,8 @@ public class RegisteredAidCacheTest {
 
         verify(mAidRoutingManager).supportsAidPrefixRouting();
         verify(mAidRoutingManager).supportsAidSubsetRouting();
-        Assert.assertTrue(mRegisteredAidCache.supportsAidPrefixRegistration());
-        Assert.assertTrue(mRegisteredAidCache.supportsAidSubsetRegistration());
+        assertTrue(mRegisteredAidCache.supportsAidPrefixRegistration());
+        assertTrue(mRegisteredAidCache.supportsAidSubsetRegistration());
     }
 
     @Test
@@ -149,20 +153,24 @@ public class RegisteredAidCacheTest {
 
         verify(mAidRoutingManager).supportsAidPrefixRouting();
         verify(mAidRoutingManager).supportsAidSubsetRouting();
-        Assert.assertFalse(mRegisteredAidCache.supportsAidPrefixRegistration());
-        Assert.assertFalse(mRegisteredAidCache.supportsAidSubsetRegistration());
+        assertFalse(mRegisteredAidCache.supportsAidPrefixRegistration());
+        assertFalse(mRegisteredAidCache.supportsAidSubsetRegistration());
     }
 
     @Test
     public void testAidStaticMethods() {
-        Assert.assertTrue(RegisteredAidCache.isPrefix(PREFIX_AID));
-        Assert.assertTrue(RegisteredAidCache.isSubset(SUBSET_AID));
-        Assert.assertTrue(RegisteredAidCache.isExact(EXACT_AID));
-
-        Assert.assertFalse(RegisteredAidCache.isPrefix(EXACT_AID));
-        Assert.assertFalse(RegisteredAidCache.isSubset(EXACT_AID));
-        Assert.assertFalse(RegisteredAidCache.isExact(PREFIX_AID));
-        Assert.assertFalse(RegisteredAidCache.isExact(SUBSET_AID));
+        assertTrue(RegisteredAidCache.isPrefix(PREFIX_AID));
+        assertTrue(RegisteredAidCache.isSubset(SUBSET_AID));
+        assertTrue(RegisteredAidCache.isExact(EXACT_AID));
+
+        assertFalse(RegisteredAidCache.isPrefix(EXACT_AID));
+        assertFalse(RegisteredAidCache.isSubset(EXACT_AID));
+        assertFalse(RegisteredAidCache.isExact(PREFIX_AID));
+        assertFalse(RegisteredAidCache.isExact(SUBSET_AID));
+
+        assertFalse(RegisteredAidCache.isPrefix(null));
+        assertFalse(RegisteredAidCache.isSubset(null));
+        assertFalse(RegisteredAidCache.isExact(null));
     }
 
     @Test
@@ -210,11 +218,11 @@ public class RegisteredAidCacheTest {
 
         verify(mAidRoutingManager).supportsAidPrefixRouting();
         verify(mAidRoutingManager).supportsAidSubsetRouting();
-        Assert.assertEquals(resolveInfo.defaultService.getComponent(), FOREGROUND_SERVICE);
-        Assert.assertEquals(mRegisteredAidCache.getPreferredService(),
-                new Pair<>(USER_ID, FOREGROUND_SERVICE));
-        Assert.assertEquals(resolveInfo.services.size(), 1);
-        Assert.assertEquals(resolveInfo.category, CardEmulation.CATEGORY_PAYMENT);
+        assertEquals(FOREGROUND_SERVICE, resolveInfo.defaultService.getComponent());
+        assertEquals(new Pair<>(USER_ID, FOREGROUND_SERVICE),
+                mRegisteredAidCache.getPreferredService());
+        assertEquals(1, resolveInfo.services.size());
+        assertEquals(CardEmulation.CATEGORY_PAYMENT, resolveInfo.category);
         verifyNoMoreInteractions(mAidRoutingManager);
     }
 
@@ -263,25 +271,23 @@ public class RegisteredAidCacheTest {
         RegisteredAidCache.AidResolveInfo nonPaymentResolveInfo
                 = mRegisteredAidCache.resolveAid(NON_PAYMENT_AID_1);
 
-        Assert.assertEquals(paymentResolveInfo.defaultService.getComponent(),
-                WALLET_PAYMENT_SERVICE);
-        Assert.assertEquals(paymentResolveInfo.services.size(), 1);
-        Assert.assertEquals(paymentResolveInfo.category, CardEmulation.CATEGORY_PAYMENT);
-        Assert.assertEquals(nonPaymentResolveInfo.defaultService.getComponent(),
-                NON_PAYMENT_SERVICE);
-        Assert.assertEquals(nonPaymentResolveInfo.services.size(), 1);
-        Assert.assertEquals(nonPaymentResolveInfo.category, CardEmulation.CATEGORY_OTHER);
+        assertEquals(WALLET_PAYMENT_SERVICE, paymentResolveInfo.defaultService.getComponent());
+        assertEquals(1, paymentResolveInfo.services.size());
+        assertEquals(CardEmulation.CATEGORY_PAYMENT, paymentResolveInfo.category);
+        assertEquals(NON_PAYMENT_SERVICE, nonPaymentResolveInfo.defaultService.getComponent());
+        assertEquals(1, nonPaymentResolveInfo.services.size());
+        assertEquals(CardEmulation.CATEGORY_OTHER, nonPaymentResolveInfo.category);
         verify(mAidRoutingManager).configureRouting(mRoutingEntryMapCaptor.capture(),
                 eq(false));
         HashMap<String, AidRoutingManager.AidEntry> routingEntries =
                 mRoutingEntryMapCaptor.getValue();
-        Assert.assertTrue(routingEntries.containsKey(PAYMENT_AID_1));
-        Assert.assertTrue(routingEntries.containsKey(NON_PAYMENT_AID_1));
-        Assert.assertTrue(routingEntries.get(PAYMENT_AID_1).isOnHost);
-        Assert.assertTrue(routingEntries.get(NON_PAYMENT_AID_1).isOnHost);
-        Assert.assertNull(routingEntries.get(PAYMENT_AID_1).offHostSE);
-        Assert.assertNull(routingEntries.get(NON_PAYMENT_AID_1).offHostSE);
-        Assert.assertTrue(mRegisteredAidCache.isRequiresScreenOnServiceExist());
+        assertTrue(routingEntries.containsKey(PAYMENT_AID_1));
+        assertTrue(routingEntries.containsKey(NON_PAYMENT_AID_1));
+        assertTrue(routingEntries.get(PAYMENT_AID_1).isOnHost);
+        assertTrue(routingEntries.get(NON_PAYMENT_AID_1).isOnHost);
+        assertNull(routingEntries.get(PAYMENT_AID_1).offHostSE);
+        assertNull(routingEntries.get(NON_PAYMENT_AID_1).offHostSE);
+        assertTrue(mRegisteredAidCache.isRequiresScreenOnServiceExist());
     }
 
     @Test
@@ -329,14 +335,12 @@ public class RegisteredAidCacheTest {
         RegisteredAidCache.AidResolveInfo nonPaymentResolveInfo
                 = mRegisteredAidCache.resolveAid(NON_PAYMENT_AID_1);
 
-        Assert.assertEquals(paymentResolveInfo.defaultService.getComponent(),
-                WALLET_PAYMENT_SERVICE);
-        Assert.assertEquals(paymentResolveInfo.services.size(), 1);
-        Assert.assertEquals(paymentResolveInfo.category, CardEmulation.CATEGORY_PAYMENT);
-        Assert.assertEquals(nonPaymentResolveInfo.defaultService.getComponent(),
-                NON_PAYMENT_SERVICE);
-        Assert.assertEquals(nonPaymentResolveInfo.services.size(), 1);
-        Assert.assertEquals(nonPaymentResolveInfo.category, CardEmulation.CATEGORY_OTHER);
+        assertEquals(WALLET_PAYMENT_SERVICE, paymentResolveInfo.defaultService.getComponent());
+        assertEquals(1, paymentResolveInfo.services.size());
+        assertEquals(CardEmulation.CATEGORY_PAYMENT, paymentResolveInfo.category);
+        assertEquals(NON_PAYMENT_SERVICE, nonPaymentResolveInfo.defaultService.getComponent());
+        assertEquals(1, nonPaymentResolveInfo.services.size());
+        assertEquals(CardEmulation.CATEGORY_OTHER, nonPaymentResolveInfo.category);
     }
 
     @Test
@@ -380,9 +384,72 @@ public class RegisteredAidCacheTest {
         mRegisteredAidCache.onWalletRoleHolderChanged(WALLET_HOLDER_PACKAGE_NAME, USER_ID);
         RegisteredAidCache.AidResolveInfo resolveInfo
                 = mRegisteredAidCache.resolveAid(PAYMENT_AID_1);
-        Assert.assertEquals(resolveInfo.defaultService.getComponent(), WALLET_PAYMENT_SERVICE);
-        Assert.assertEquals(resolveInfo.services.size(), 2);
-        Assert.assertEquals(resolveInfo.category, CardEmulation.CATEGORY_PAYMENT);
+        assertEquals(WALLET_PAYMENT_SERVICE, resolveInfo.defaultService.getComponent());
+        assertEquals(2, resolveInfo.services.size());
+        assertEquals(CardEmulation.CATEGORY_PAYMENT, resolveInfo.category);
+    }
+
+    @Test
+    public void testAidConflictResolution_walletOtherServiceDisabled_nonDefaultServiceWins() {
+        setWalletRoleFlag(true);
+        supportPrefixAndSubset(false);
+        mRegisteredAidCache = new RegisteredAidCache(mContext, mWalletRoleObserver,
+                mAidRoutingManager);
+
+        List<ApduServiceInfo> apduServiceInfos = new ArrayList<>();
+        apduServiceInfos.add(createServiceInfoForAidRouting(
+                WALLET_PAYMENT_SERVICE,
+                true,
+                List.of(PAYMENT_AID_1, NON_PAYMENT_AID_1),
+                List.of(CardEmulation.CATEGORY_PAYMENT, CardEmulation.CATEGORY_OTHER),
+                false,
+                false,
+                USER_ID,
+                false));
+        apduServiceInfos.add(createServiceInfoForAidRouting(
+                PAYMENT_SERVICE,
+                true,
+                List.of(PAYMENT_AID_1, NON_PAYMENT_AID_1),
+                List.of(CardEmulation.CATEGORY_PAYMENT, CardEmulation.CATEGORY_OTHER),
+                false,
+                false,
+                USER_ID,
+                true));
+
+        mRegisteredAidCache.generateUserApduServiceInfoLocked(USER_ID, apduServiceInfos);
+        mRegisteredAidCache.generateServiceMapLocked(apduServiceInfos);
+        mRegisteredAidCache.onWalletRoleHolderChanged(WALLET_HOLDER_PACKAGE_NAME, USER_ID);
+        RegisteredAidCache.AidResolveInfo resolveInfo
+                = mRegisteredAidCache.resolveAid(NON_PAYMENT_AID_1);
+        assertEquals(PAYMENT_SERVICE, resolveInfo.defaultService.getComponent());
+        assertEquals(1, resolveInfo.services.size());
+    }
+
+    @Test
+    public void testAidConflictResolution_walletOtherServiceDisabled_emptyServices() {
+        setWalletRoleFlag(true);
+        supportPrefixAndSubset(false);
+        mRegisteredAidCache = new RegisteredAidCache(mContext, mWalletRoleObserver,
+                mAidRoutingManager);
+
+        List<ApduServiceInfo> apduServiceInfos = new ArrayList<>();
+        apduServiceInfos.add(createServiceInfoForAidRouting(
+                WALLET_PAYMENT_SERVICE,
+                true,
+                List.of(PAYMENT_AID_1, NON_PAYMENT_AID_1),
+                List.of(CardEmulation.CATEGORY_PAYMENT, CardEmulation.CATEGORY_OTHER),
+                false,
+                false,
+                USER_ID,
+                false));
+
+        mRegisteredAidCache.generateUserApduServiceInfoLocked(USER_ID, apduServiceInfos);
+        mRegisteredAidCache.generateServiceMapLocked(apduServiceInfos);
+        mRegisteredAidCache.onWalletRoleHolderChanged(WALLET_HOLDER_PACKAGE_NAME, USER_ID);
+        RegisteredAidCache.AidResolveInfo resolveInfo
+                = mRegisteredAidCache.resolveAid(NON_PAYMENT_AID_1);
+        assertNull(resolveInfo.defaultService);
+        assertTrue(resolveInfo.services.isEmpty());
     }
 
     @Test
@@ -426,22 +493,22 @@ public class RegisteredAidCacheTest {
 
         verify(mAidRoutingManager).supportsAidPrefixRouting();
         verify(mAidRoutingManager).supportsAidSubsetRouting();
-        Assert.assertTrue(mRegisteredAidCache.mAidServices.containsKey(PAYMENT_AID_1));
-        Assert.assertTrue(mRegisteredAidCache.mAidServices.containsKey(NON_PAYMENT_AID_1));
-        Assert.assertEquals(mRegisteredAidCache.mAidServices.get(PAYMENT_AID_1).size(), 2);
-        Assert.assertEquals(mRegisteredAidCache.mAidServices.get(NON_PAYMENT_AID_1).size(), 1);
-        Assert.assertEquals(mRegisteredAidCache.mAidServices.get(PAYMENT_AID_1).get(0)
-                .service.getComponent(), WALLET_PAYMENT_SERVICE);
-        Assert.assertEquals(mRegisteredAidCache.mAidServices.get(PAYMENT_AID_1).get(1)
-                        .service.getComponent(), PAYMENT_SERVICE);
+        assertTrue(mRegisteredAidCache.mAidServices.containsKey(PAYMENT_AID_1));
+        assertTrue(mRegisteredAidCache.mAidServices.containsKey(NON_PAYMENT_AID_1));
+        assertEquals(2, mRegisteredAidCache.mAidServices.get(PAYMENT_AID_1).size());
+        assertEquals(1, mRegisteredAidCache.mAidServices.get(NON_PAYMENT_AID_1).size());
+        assertEquals(WALLET_PAYMENT_SERVICE,
+            mRegisteredAidCache.mAidServices.get(PAYMENT_AID_1).get(0).service.getComponent());
+        assertEquals(PAYMENT_SERVICE,
+            mRegisteredAidCache.mAidServices.get(PAYMENT_AID_1).get(1).service.getComponent());
         verify(mAidRoutingManager).configureRouting(mRoutingEntryMapCaptor.capture(),
                 eq(false));
         HashMap<String, AidRoutingManager.AidEntry> routingEntries =
                 mRoutingEntryMapCaptor.getValue();
-        Assert.assertTrue(routingEntries.containsKey(NON_PAYMENT_AID_1));
-        Assert.assertTrue(routingEntries.get(NON_PAYMENT_AID_1).isOnHost);
-        Assert.assertNull(routingEntries.get(NON_PAYMENT_AID_1).offHostSE);
-        Assert.assertTrue(mRegisteredAidCache.isRequiresScreenOnServiceExist());
+        assertTrue(routingEntries.containsKey(NON_PAYMENT_AID_1));
+        assertTrue(routingEntries.get(NON_PAYMENT_AID_1).isOnHost);
+        assertNull(routingEntries.get(NON_PAYMENT_AID_1).offHostSE);
+        assertTrue(mRegisteredAidCache.isRequiresScreenOnServiceExist());
     }
 
     @Test
@@ -488,7 +555,7 @@ public class RegisteredAidCacheTest {
         verify(mAidRoutingManager).supportsAidSubsetRouting();
         verify(mAidRoutingManager).configureRouting(mRoutingEntryMapCaptor.capture(),
                 eq(false));
-        Assert.assertFalse(mRegisteredAidCache.isRequiresScreenOnServiceExist());
+        assertFalse(mRegisteredAidCache.isRequiresScreenOnServiceExist());
     }
 
     @Test
@@ -547,7 +614,7 @@ public class RegisteredAidCacheTest {
         ApduServiceInfo resolvedApdu =
                 mRegisteredAidCache.resolvePollingLoopFilterConflict(apduServiceInfos);
 
-        Assert.assertEquals(resolvedApdu, apduServiceInfos.get(1));
+        assertEquals(resolvedApdu, apduServiceInfos.get(1));
     }
 
     @Test
@@ -592,7 +659,7 @@ public class RegisteredAidCacheTest {
         ApduServiceInfo resolvedApdu =
                 mRegisteredAidCache.resolvePollingLoopFilterConflict(apduServiceInfos);
 
-        Assert.assertEquals(resolvedApdu, apduServiceInfos.get(0));
+        assertEquals(resolvedApdu, apduServiceInfos.get(0));
     }
 
     private void setWalletRoleFlag(boolean flag) {
@@ -625,4 +692,17 @@ public class RegisteredAidCacheTest {
         return apduServiceInfo;
     }
 
+    @Test
+    public void testGetPreferredService() {
+
+        mRegisteredAidCache = new RegisteredAidCache(mContext, mWalletRoleObserver,
+                mAidRoutingManager);
+        Pair<Integer, ComponentName> servicePair = mRegisteredAidCache.getPreferredService();
+        Assert.assertNull(servicePair.second);
+        mRegisteredAidCache.onPreferredForegroundServiceChanged(USER_ID, FOREGROUND_SERVICE);
+        servicePair = mRegisteredAidCache.getPreferredService();
+        Assert.assertNotNull(servicePair.second);
+        assertEquals(new Pair<>(USER_ID, FOREGROUND_SERVICE), servicePair);
+    }
+
 }
diff --git a/tests/unit/src/com/android/nfc/cardemulation/RegisteredNfcFServicesCacheTest.java b/tests/unit/src/com/android/nfc/cardemulation/RegisteredNfcFServicesCacheTest.java
index 5a5af816..e804c20b 100644
--- a/tests/unit/src/com/android/nfc/cardemulation/RegisteredNfcFServicesCacheTest.java
+++ b/tests/unit/src/com/android/nfc/cardemulation/RegisteredNfcFServicesCacheTest.java
@@ -16,6 +16,11 @@
 
 package com.android.nfc.cardemulation;
 
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.assertNotNull;
+import static org.junit.Assert.assertNull;
+import static org.junit.Assert.assertTrue;
 import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.ArgumentMatchers.anyString;
@@ -62,7 +67,6 @@ import java.util.List;
 import java.util.Locale;
 
 import org.junit.After;
-import org.junit.Assert;
 import org.junit.Before;
 import org.junit.Test;
 import org.junit.runner.RunWith;
@@ -189,32 +193,32 @@ public class RegisteredNfcFServicesCacheTest {
     verify(mContext, times(2))
         .registerReceiverForAllUsers(receiverCaptor.capture(), intentFilterCaptor.capture(),
             broadcastPermissionCaptor.capture(), schedulerCaptor.capture());
-    Assert.assertEquals(receiverCaptor.getAllValues().get(0), cache.mReceiver.get());
-    Assert.assertEquals(receiverCaptor.getAllValues().get(1), cache.mReceiver.get());
-    Assert.assertNotNull(cache.mReceiver.get());
+    assertEquals(cache.mReceiver.get(), receiverCaptor.getAllValues().get(0));
+    assertEquals(cache.mReceiver.get(), receiverCaptor.getAllValues().get(1));
+    assertNotNull(cache.mReceiver.get());
     IntentFilter intentFilter = intentFilterCaptor.getAllValues().get(0);
     IntentFilter sdFilter = intentFilterCaptor.getAllValues().get(1);
-    Assert.assertTrue(intentFilter.hasAction(Intent.ACTION_PACKAGE_ADDED));
-    Assert.assertTrue(intentFilter.hasAction(Intent.ACTION_PACKAGE_CHANGED));
-    Assert.assertTrue(intentFilter.hasAction(Intent.ACTION_PACKAGE_REMOVED));
-    Assert.assertTrue(intentFilter.hasAction(Intent.ACTION_PACKAGE_REPLACED));
-    Assert.assertTrue(intentFilter.hasAction(Intent.ACTION_PACKAGE_FIRST_LAUNCH));
-    Assert.assertTrue(intentFilter.hasAction(Intent.ACTION_PACKAGE_RESTARTED));
-    Assert.assertTrue(intentFilter.hasDataScheme("package"));
-    Assert.assertTrue(sdFilter.hasAction(Intent.ACTION_EXTERNAL_APPLICATIONS_AVAILABLE));
-    Assert.assertTrue(sdFilter.hasAction(Intent.ACTION_EXTERNAL_APPLICATIONS_UNAVAILABLE));
-    Assert.assertNull(broadcastPermissionCaptor.getAllValues().get(0));
-    Assert.assertNull(broadcastPermissionCaptor.getAllValues().get(1));
-    Assert.assertNull(schedulerCaptor.getAllValues().get(0));
-    Assert.assertNull(schedulerCaptor.getAllValues().get(1));
+    assertTrue(intentFilter.hasAction(Intent.ACTION_PACKAGE_ADDED));
+    assertTrue(intentFilter.hasAction(Intent.ACTION_PACKAGE_CHANGED));
+    assertTrue(intentFilter.hasAction(Intent.ACTION_PACKAGE_REMOVED));
+    assertTrue(intentFilter.hasAction(Intent.ACTION_PACKAGE_REPLACED));
+    assertTrue(intentFilter.hasAction(Intent.ACTION_PACKAGE_FIRST_LAUNCH));
+    assertTrue(intentFilter.hasAction(Intent.ACTION_PACKAGE_RESTARTED));
+    assertTrue(intentFilter.hasDataScheme("package"));
+    assertTrue(sdFilter.hasAction(Intent.ACTION_EXTERNAL_APPLICATIONS_AVAILABLE));
+    assertTrue(sdFilter.hasAction(Intent.ACTION_EXTERNAL_APPLICATIONS_UNAVAILABLE));
+    assertNull(broadcastPermissionCaptor.getAllValues().get(0));
+    assertNull(broadcastPermissionCaptor.getAllValues().get(1));
+    assertNull(schedulerCaptor.getAllValues().get(0));
+    assertNull(schedulerCaptor.getAllValues().get(1));
     synchronized (cache.mLock) {
-      Assert.assertEquals(cache.mUserHandles.get(0), USER_HANDLE);
+      assertEquals(USER_HANDLE, cache.mUserHandles.get(0));
     }
-    Assert.assertEquals(cache.mContext, mContext);
-    Assert.assertEquals(cache.mCallback, mCallback);
-    Assert.assertEquals(cache.mDynamicSystemCodeNfcid2File.getBaseFile().getParentFile(), DIR);
-    Assert.assertEquals(cache.mDynamicSystemCodeNfcid2File.getBaseFile().getAbsolutePath(),
-        DIR + "dynamic_systemcode_nfcid2.xml");
+    assertEquals(mContext, cache.mContext);
+    assertEquals(mCallback, cache.mCallback);
+    assertEquals(DIR, cache.mDynamicSystemCodeNfcid2File.getBaseFile().getParentFile());
+    assertEquals(DIR + "dynamic_systemcode_nfcid2.xml",
+        cache.mDynamicSystemCodeNfcid2File.getBaseFile().getAbsolutePath());
   }
 
   @Test
@@ -239,8 +243,8 @@ public class RegisteredNfcFServicesCacheTest {
     cache.mReceiver.get().onReceive(mContext, getBroadcastReceiverIntent());
 
     verify(mCallback).onNfcFServicesUpdated(userIdCaptor.capture(), servicesCaptor.capture());
-    Assert.assertEquals(userIdCaptor.getValue(), Integer.valueOf(USER_ID));
-    Assert.assertEquals(servicesCaptor.getValue().get(0), mNfcFServiceInfo);
+    assertEquals(Integer.valueOf(USER_ID), userIdCaptor.getValue());
+    assertEquals(mNfcFServiceInfo, servicesCaptor.getValue().get(0));
   }
 
   @Test
@@ -249,7 +253,7 @@ public class RegisteredNfcFServicesCacheTest {
 
     boolean result = cache.hasService(USER_ID, WALLET_COMPONENT);
 
-    Assert.assertFalse(result);
+    assertFalse(result);
   }
 
   @Test
@@ -259,7 +263,7 @@ public class RegisteredNfcFServicesCacheTest {
 
     boolean result = cache.hasService(USER_ID, WALLET_COMPONENT);
 
-    Assert.assertTrue(result);
+    assertTrue(result);
   }
 
   @Test
@@ -268,7 +272,7 @@ public class RegisteredNfcFServicesCacheTest {
 
     NfcFServiceInfo result = cache.getService(USER_ID, WALLET_COMPONENT);
 
-    Assert.assertNull(result);
+    assertNull(result);
   }
 
   @Test
@@ -278,7 +282,7 @@ public class RegisteredNfcFServicesCacheTest {
 
     NfcFServiceInfo result = cache.getService(USER_ID, WALLET_COMPONENT);
 
-    Assert.assertEquals(result, mNfcFServiceInfo);
+    assertEquals(mNfcFServiceInfo, result);
   }
 
   @Test
@@ -288,7 +292,7 @@ public class RegisteredNfcFServicesCacheTest {
 
     List<NfcFServiceInfo> result = cache.getServices(USER_ID);
 
-    Assert.assertEquals(result.get(0), mNfcFServiceInfo);
+    assertEquals(mNfcFServiceInfo, result.get(0));
   }
 
 
@@ -319,12 +323,12 @@ public class RegisteredNfcFServicesCacheTest {
     cache.invalidateCache(USER_ID);
 
     verify(mCallback).onNfcFServicesUpdated(userIdCaptor.capture(), servicesCaptor.capture());
-    Assert.assertEquals(userIdCaptor.getValue(), Integer.valueOf(USER_ID));
-    Assert.assertEquals(servicesCaptor.getValue().get(0), mNfcFServiceInfo);
+    assertEquals(Integer.valueOf(USER_ID), userIdCaptor.getValue());
+    assertEquals(mNfcFServiceInfo, servicesCaptor.getValue().get(0));
     UserServices userServicesResult = cache.mUserServices.get(USER_ID);
-    Assert.assertEquals(userServicesResult.services.get(WALLET_COMPONENT), mNfcFServiceInfo);
-    Assert.assertTrue(userServicesResult.dynamicSystemCode.isEmpty());
-    Assert.assertTrue(userServicesResult.dynamicNfcid2.isEmpty());
+    assertEquals(mNfcFServiceInfo, userServicesResult.services.get(WALLET_COMPONENT));
+    assertTrue(userServicesResult.dynamicSystemCode.isEmpty());
+    assertTrue(userServicesResult.dynamicNfcid2.isEmpty());
     verify(mNfcFServiceInfo, never()).setDynamicSystemCode(anyString());
     verify(mNfcFServiceInfo, never()).setDynamicNfcid2(anyString());
   }
@@ -347,14 +351,14 @@ public class RegisteredNfcFServicesCacheTest {
     cache.invalidateCache(USER_ID);
 
     verify(mCallback).onNfcFServicesUpdated(userIdCaptor.capture(), servicesCaptor.capture());
-    Assert.assertEquals(userIdCaptor.getValue(), Integer.valueOf(USER_ID));
-    Assert.assertEquals(servicesCaptor.getValue().get(0), mNfcFServiceInfo);
+    assertEquals(Integer.valueOf(USER_ID), userIdCaptor.getValue());
+    assertEquals(mNfcFServiceInfo, servicesCaptor.getValue().get(0));
     UserServices userServicesResult = cache.mUserServices.get(USER_ID);
-    Assert.assertEquals(userServicesResult.services.get(WALLET_COMPONENT), mNfcFServiceInfo);
-    Assert.assertEquals(1, userServicesResult.dynamicSystemCode.size());
+    assertEquals(mNfcFServiceInfo, userServicesResult.services.get(WALLET_COMPONENT));
+    assertEquals(1, userServicesResult.dynamicSystemCode.size());
     verify(mNfcFServiceInfo).setDynamicSystemCode(systemCodeCaptor.capture());
-    Assert.assertEquals(SYSTEM_CODE, systemCodeCaptor.getValue());
-    Assert.assertTrue(userServicesResult.dynamicNfcid2.isEmpty());
+    assertEquals(SYSTEM_CODE, systemCodeCaptor.getValue());
+    assertTrue(userServicesResult.dynamicNfcid2.isEmpty());
     verify(mNfcFServiceInfo, never()).setDynamicNfcid2(anyString());
   }
 
@@ -376,15 +380,15 @@ public class RegisteredNfcFServicesCacheTest {
     cache.invalidateCache(USER_ID);
 
     verify(mCallback).onNfcFServicesUpdated(userIdCaptor.capture(), servicesCaptor.capture());
-    Assert.assertEquals(userIdCaptor.getValue(), Integer.valueOf(USER_ID));
-    Assert.assertEquals(servicesCaptor.getValue().get(0), mNfcFServiceInfo);
+    assertEquals(Integer.valueOf(USER_ID), userIdCaptor.getValue());
+    assertEquals(mNfcFServiceInfo, servicesCaptor.getValue().get(0));
     UserServices userServicesResult = cache.mUserServices.get(USER_ID);
-    Assert.assertEquals(userServicesResult.services.get(WALLET_COMPONENT), mNfcFServiceInfo);
-    Assert.assertTrue(userServicesResult.dynamicSystemCode.isEmpty());
+    assertEquals(mNfcFServiceInfo, userServicesResult.services.get(WALLET_COMPONENT));
+    assertTrue(userServicesResult.dynamicSystemCode.isEmpty());
     verify(mNfcFServiceInfo, never()).setDynamicSystemCode(anyString());
-    Assert.assertEquals(1, userServicesResult.dynamicNfcid2.size());
+    assertEquals(1, userServicesResult.dynamicNfcid2.size());
     verify(mNfcFServiceInfo).setDynamicNfcid2(nfcid2Captor.capture());
-    Assert.assertEquals(NFCID2, nfcid2Captor.getValue());
+    assertEquals(NFCID2, nfcid2Captor.getValue());
   }
 
   /**
@@ -405,13 +409,13 @@ public class RegisteredNfcFServicesCacheTest {
     cache.invalidateCache(USER_ID);
 
     verify(mCallback).onNfcFServicesUpdated(userIdCaptor.capture(), servicesCaptor.capture());
-    Assert.assertEquals(userIdCaptor.getValue(), Integer.valueOf(USER_ID));
-    Assert.assertEquals(servicesCaptor.getValue().get(0), mNfcFServiceInfo);
+    assertEquals(Integer.valueOf(USER_ID), userIdCaptor.getValue());
+    assertEquals(mNfcFServiceInfo, servicesCaptor.getValue().get(0));
     UserServices userServicesResult = cache.mUserServices.get(USER_ID);
-    Assert.assertEquals(userServicesResult.services.get(WALLET_COMPONENT), mNfcFServiceInfo);
-    Assert.assertTrue(userServicesResult.dynamicSystemCode.isEmpty());
+    assertEquals(mNfcFServiceInfo, userServicesResult.services.get(WALLET_COMPONENT));
+    assertTrue(userServicesResult.dynamicSystemCode.isEmpty());
     verify(mNfcFServiceInfo, never()).setDynamicSystemCode(anyString());
-    Assert.assertEquals(1, userServicesResult.dynamicNfcid2.size());
+    assertEquals(1, userServicesResult.dynamicNfcid2.size());
     verify(mNfcFServiceInfo).setDynamicNfcid2(anyString());
   }
 
@@ -424,7 +428,7 @@ public class RegisteredNfcFServicesCacheTest {
     boolean result
         = cache.registerSystemCodeForService(USER_ID, SERVICE_UID, WALLET_COMPONENT, SYSTEM_CODE);
 
-    Assert.assertFalse(result);
+    assertFalse(result);
   }
 
   @Test
@@ -435,7 +439,7 @@ public class RegisteredNfcFServicesCacheTest {
     boolean result
         = cache.registerSystemCodeForService(USER_ID, SERVICE_UID, WALLET_COMPONENT, SYSTEM_CODE);
 
-    Assert.assertFalse(result);
+    assertFalse(result);
   }
 
   @Test
@@ -447,7 +451,7 @@ public class RegisteredNfcFServicesCacheTest {
     boolean result
         = cache.registerSystemCodeForService(USER_ID, SERVICE_UID, WALLET_COMPONENT, SYSTEM_CODE);
 
-    Assert.assertFalse(result);
+    assertFalse(result);
   }
 
   @Test
@@ -460,7 +464,7 @@ public class RegisteredNfcFServicesCacheTest {
     boolean result
         = cache.registerSystemCodeForService(USER_ID, SERVICE_UID, WALLET_COMPONENT, SYSTEM_CODE);
 
-    Assert.assertFalse(result);
+    assertFalse(result);
   }
 
   @Test
@@ -473,7 +477,7 @@ public class RegisteredNfcFServicesCacheTest {
     boolean result
         = cache.registerSystemCodeForService(USER_ID, SERVICE_UID, WALLET_COMPONENT, SYSTEM_CODE);
 
-    Assert.assertFalse(result);
+    assertFalse(result);
     verify(mCallback, never()).onNfcFServicesUpdated(anyInt(), any());
   }
 
@@ -487,17 +491,17 @@ public class RegisteredNfcFServicesCacheTest {
     boolean result
         = cache.registerSystemCodeForService(USER_ID, SERVICE_UID, WALLET_COMPONENT, SYSTEM_CODE);
 
-    Assert.assertTrue(result);
+    assertTrue(result);
     verify(mNfcFServiceInfo).setDynamicSystemCode(systemCodeCaptor.capture());
-    Assert.assertEquals(SYSTEM_CODE.toUpperCase(Locale.ROOT), systemCodeCaptor.getValue());
+    assertEquals(SYSTEM_CODE.toUpperCase(Locale.ROOT), systemCodeCaptor.getValue());
     UserServices userServicesResult = cache.mUserServices.get(USER_ID);
-    Assert.assertEquals(1, userServicesResult.dynamicSystemCode.size());
+    assertEquals(1, userServicesResult.dynamicSystemCode.size());
     DynamicSystemCode resultSystemCode = userServicesResult.dynamicSystemCode.get(WALLET_COMPONENT);
-    Assert.assertEquals(SERVICE_UID, resultSystemCode.uid);
-    Assert.assertEquals(SYSTEM_CODE.toUpperCase(Locale.ROOT), resultSystemCode.systemCode);
+    assertEquals(SERVICE_UID, resultSystemCode.uid);
+    assertEquals(SYSTEM_CODE.toUpperCase(Locale.ROOT), resultSystemCode.systemCode);
     verify(mCallback).onNfcFServicesUpdated(userIdCaptor.capture(), servicesCaptor.capture());
-    Assert.assertEquals(userIdCaptor.getValue(), Integer.valueOf(USER_ID));
-    Assert.assertEquals(servicesCaptor.getValue().get(0), mNfcFServiceInfo);
+    assertEquals(Integer.valueOf(USER_ID), userIdCaptor.getValue());
+    assertEquals(mNfcFServiceInfo, servicesCaptor.getValue().get(0));
   }
 
   @Test
@@ -506,7 +510,7 @@ public class RegisteredNfcFServicesCacheTest {
 
     String result = cache.getSystemCodeForService(USER_ID, SERVICE_UID, WALLET_COMPONENT);
 
-    Assert.assertNull(result);
+    assertNull(result);
   }
 
   @Test
@@ -516,7 +520,7 @@ public class RegisteredNfcFServicesCacheTest {
 
     String result = cache.getSystemCodeForService(USER_ID, SERVICE_UID, WALLET_COMPONENT);
 
-    Assert.assertNull(result);
+    assertNull(result);
   }
 
   @Test
@@ -526,7 +530,7 @@ public class RegisteredNfcFServicesCacheTest {
 
     String result = cache.getSystemCodeForService(USER_ID, SERVICE_UID, WALLET_COMPONENT);
 
-    Assert.assertEquals(SYSTEM_CODE, result);
+    assertEquals(SYSTEM_CODE, result);
   }
 
   @Test
@@ -538,16 +542,16 @@ public class RegisteredNfcFServicesCacheTest {
 
     boolean result = cache.removeSystemCodeForService(USER_ID, SERVICE_UID, WALLET_COMPONENT);
 
-    Assert.assertTrue(result);
+    assertTrue(result);
     verify(mNfcFServiceInfo).setDynamicSystemCode(systemCodeCaptor.capture());
-    Assert.assertEquals("NULL", systemCodeCaptor.getValue());
+    assertEquals("NULL", systemCodeCaptor.getValue());
     DynamicSystemCode resultSystemCode
         = cache.mUserServices.get(USER_ID).dynamicSystemCode.get(WALLET_COMPONENT);
-    Assert.assertEquals(SERVICE_UID, resultSystemCode.uid);
-    Assert.assertEquals("NULL", resultSystemCode.systemCode);
+    assertEquals(SERVICE_UID, resultSystemCode.uid);
+    assertEquals("NULL", resultSystemCode.systemCode);
     verify(mCallback).onNfcFServicesUpdated(userIdCaptor.capture(), servicesCaptor.capture());
-    Assert.assertEquals(userIdCaptor.getValue(), Integer.valueOf(USER_ID));
-    Assert.assertEquals(servicesCaptor.getValue().get(0), mNfcFServiceInfo);
+    assertEquals(Integer.valueOf(USER_ID), userIdCaptor.getValue());
+    assertEquals(mNfcFServiceInfo, servicesCaptor.getValue().get(0));
   }
 
 
@@ -559,7 +563,7 @@ public class RegisteredNfcFServicesCacheTest {
 
     boolean result = cache.setNfcid2ForService(USER_ID, SERVICE_UID, WALLET_COMPONENT, NFCID2);
 
-    Assert.assertFalse(result);
+    assertFalse(result);
   }
 
   @Test
@@ -569,7 +573,7 @@ public class RegisteredNfcFServicesCacheTest {
 
     boolean result = cache.setNfcid2ForService(USER_ID, SERVICE_UID, WALLET_COMPONENT, NFCID2);
 
-    Assert.assertFalse(result);
+    assertFalse(result);
   }
 
   @Test
@@ -580,7 +584,7 @@ public class RegisteredNfcFServicesCacheTest {
 
     boolean result = cache.setNfcid2ForService(USER_ID, SERVICE_UID, WALLET_COMPONENT, NFCID2);
 
-    Assert.assertFalse(result);
+    assertFalse(result);
   }
 
   @Test
@@ -592,7 +596,7 @@ public class RegisteredNfcFServicesCacheTest {
 
     boolean result = cache.setNfcid2ForService(USER_ID, SERVICE_UID, WALLET_COMPONENT, NFCID2);
 
-    Assert.assertFalse(result);
+    assertFalse(result);
   }
 
   @Test
@@ -604,7 +608,7 @@ public class RegisteredNfcFServicesCacheTest {
 
     boolean result = cache.setNfcid2ForService(USER_ID, SERVICE_UID, WALLET_COMPONENT, NFCID2);
 
-    Assert.assertFalse(result);
+    assertFalse(result);
     verify(mCallback, never()).onNfcFServicesUpdated(anyInt(), any());
   }
 
@@ -617,16 +621,16 @@ public class RegisteredNfcFServicesCacheTest {
 
     boolean result = cache.setNfcid2ForService(USER_ID, SERVICE_UID, WALLET_COMPONENT, NFCID2);
 
-    Assert.assertTrue(result);
+    assertTrue(result);
     verify(mNfcFServiceInfo).setDynamicNfcid2(nfcid2Captor.capture());
-    Assert.assertEquals(NFCID2.toUpperCase(Locale.ROOT), nfcid2Captor.getValue());
+    assertEquals(NFCID2.toUpperCase(Locale.ROOT), nfcid2Captor.getValue());
     DynamicNfcid2 resultNfcid2
         = cache.mUserServices.get(USER_ID).dynamicNfcid2.get(WALLET_COMPONENT);
-    Assert.assertEquals(SERVICE_UID, resultNfcid2.uid);
-    Assert.assertEquals(NFCID2.toUpperCase(Locale.ROOT), resultNfcid2.nfcid2);
+    assertEquals(SERVICE_UID, resultNfcid2.uid);
+    assertEquals(NFCID2.toUpperCase(Locale.ROOT), resultNfcid2.nfcid2);
     verify(mCallback).onNfcFServicesUpdated(userIdCaptor.capture(), servicesCaptor.capture());
-    Assert.assertEquals(userIdCaptor.getValue(), Integer.valueOf(USER_ID));
-    Assert.assertEquals(servicesCaptor.getValue().get(0), mNfcFServiceInfo);
+    assertEquals(Integer.valueOf(USER_ID), userIdCaptor.getValue());
+    assertEquals(mNfcFServiceInfo, servicesCaptor.getValue().get(0));
   }
 
   @Test
@@ -635,7 +639,7 @@ public class RegisteredNfcFServicesCacheTest {
 
     String result = cache.getNfcid2ForService(USER_ID, SERVICE_UID, WALLET_COMPONENT);
 
-    Assert.assertNull(result);
+    assertNull(result);
   }
 
   @Test
@@ -645,7 +649,7 @@ public class RegisteredNfcFServicesCacheTest {
 
     String result = cache.getNfcid2ForService(USER_ID, SERVICE_UID, WALLET_COMPONENT);
 
-    Assert.assertNull(result);
+    assertNull(result);
   }
 
   @Test
@@ -655,7 +659,7 @@ public class RegisteredNfcFServicesCacheTest {
 
     String result = cache.getNfcid2ForService(USER_ID, SERVICE_UID, WALLET_COMPONENT);
 
-    Assert.assertEquals(NFCID2, result);
+    assertEquals(NFCID2, result);
   }
 
   @Test
@@ -664,7 +668,7 @@ public class RegisteredNfcFServicesCacheTest {
 
     cache.onHostEmulationActivated();
 
-    Assert.assertTrue(cache.mActivated);
+    assertTrue(cache.mActivated);
   }
 
   @Test
@@ -673,7 +677,7 @@ public class RegisteredNfcFServicesCacheTest {
 
     cache.onHostEmulationDeactivated();
 
-    Assert.assertFalse(cache.mActivated);
+    assertFalse(cache.mActivated);
   }
 
   @Test
@@ -682,7 +686,7 @@ public class RegisteredNfcFServicesCacheTest {
 
     cache.onNfcDisabled();
 
-    Assert.assertFalse(cache.mActivated);
+    assertFalse(cache.mActivated);
   }
 
   @Test
@@ -691,9 +695,9 @@ public class RegisteredNfcFServicesCacheTest {
 
     cache.onUserSwitched();
 
-    Assert.assertTrue(cache.mUserSwitched);
+    assertTrue(cache.mUserSwitched);
     synchronized (cache.mLock) {
-      Assert.assertEquals(cache.mUserHandles.get(0), USER_HANDLE);
+      assertEquals(USER_HANDLE, cache.mUserHandles.get(0));
     }
   }
 
@@ -704,7 +708,7 @@ public class RegisteredNfcFServicesCacheTest {
     cache.onManagedProfileChanged();
 
     synchronized (cache.mLock) {
-      Assert.assertEquals(cache.mUserHandles.get(0), USER_HANDLE);
+      assertEquals(USER_HANDLE, cache.mUserHandles.get(0));
     }
   }
 
@@ -727,7 +731,7 @@ public class RegisteredNfcFServicesCacheTest {
 
     boolean result = cache.writeDynamicSystemCodeNfcid2Locked();
 
-    Assert.assertFalse(result);
+    assertFalse(result);
     verify(mAtomicFile, never()).failWrite(any(FileOutputStream.class));
   }
 
@@ -737,7 +741,7 @@ public class RegisteredNfcFServicesCacheTest {
 
     boolean result = cache.writeDynamicSystemCodeNfcid2Locked();
 
-    Assert.assertTrue(result);
+    assertTrue(result);
     verify(mAtomicFile).startWrite();
     verify(mAtomicFile).finishWrite(any(FileOutputStream.class));
     verify(mAtomicFile, never()).failWrite(any(FileOutputStream.class));
@@ -750,7 +754,7 @@ public class RegisteredNfcFServicesCacheTest {
 
     boolean result = cache.writeDynamicSystemCodeNfcid2Locked();
 
-    Assert.assertTrue(result);
+    assertTrue(result);
     verify(mAtomicFile).startWrite();
     verify(mAtomicFile).finishWrite(any(FileOutputStream.class));
     verify(mAtomicFile, never()).failWrite(any(FileOutputStream.class));
@@ -776,8 +780,8 @@ public class RegisteredNfcFServicesCacheTest {
     verify(mAtomicFile, never()).delete();
     verify(mParser, times(2)).next();
     verify(mParser, times(5)).getAttributeValue(any(), anyString());
-    Assert.assertEquals(1, cache.mUserServices.get(USER_ID).dynamicSystemCode.size());
-    Assert.assertEquals(1, cache.mUserServices.get(USER_ID).dynamicNfcid2.size());
+    assertEquals(1, cache.mUserServices.get(USER_ID).dynamicSystemCode.size());
+    assertEquals(1, cache.mUserServices.get(USER_ID).dynamicNfcid2.size());
   }
 
   private void setResolveInfoList() {
diff --git a/tests/unit/src/com/android/nfc/cardemulation/RegisteredServicesCacheTest.java b/tests/unit/src/com/android/nfc/cardemulation/RegisteredServicesCacheTest.java
index 6cf35c7c..83f3f2de 100644
--- a/tests/unit/src/com/android/nfc/cardemulation/RegisteredServicesCacheTest.java
+++ b/tests/unit/src/com/android/nfc/cardemulation/RegisteredServicesCacheTest.java
@@ -16,8 +16,11 @@
 
 package com.android.nfc.cardemulation;
 
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertNotNull;
 import static org.junit.Assert.assertNull;
+import static org.junit.Assert.assertTrue;
 import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.anyBoolean;
 import static org.mockito.ArgumentMatchers.anyInt;
@@ -55,7 +58,6 @@ import com.android.nfc.NfcService;
 import com.android.nfc.NfcStatsLog;
 
 import org.junit.After;
-import org.junit.Assert;
 import org.junit.Before;
 import org.junit.Test;
 import org.junit.runner.RunWith;
@@ -232,8 +234,8 @@ public class RegisteredServicesCacheTest {
                 mRoutingOptionManager);
 
         // Verify that the users handles are populated correctly
-        Assert.assertEquals(1, mRegisteredServicesCache.mUserHandles.size());
-        Assert.assertEquals(mRegisteredServicesCache.mUserHandles.get(0), USER_HANDLE);
+        assertEquals(1, mRegisteredServicesCache.mUserHandles.size());
+        assertEquals(USER_HANDLE, mRegisteredServicesCache.mUserHandles.get(0));
         // Verify that broadcast receivers for apk changes are created and registered properly
         assertNotNull(mRegisteredServicesCache.mReceiver.get());
         verify(mContext).createContextAsUser(eq(USER_HANDLE), eq(0));
@@ -242,34 +244,30 @@ public class RegisteredServicesCacheTest {
                 eq(null), eq(null));
         IntentFilter packageInstallTrackerIntent = mIntentFilterArgumentCaptor
                 .getAllValues().get(0);
-        Assert.assertTrue(packageInstallTrackerIntent.hasAction(Intent.ACTION_PACKAGE_ADDED));
-        Assert.assertTrue(packageInstallTrackerIntent.hasAction(Intent.ACTION_PACKAGE_CHANGED));
-        Assert.assertTrue(packageInstallTrackerIntent.hasAction(Intent.ACTION_PACKAGE_REMOVED));
-        Assert.assertTrue(packageInstallTrackerIntent.hasAction(Intent.ACTION_PACKAGE_REPLACED));
-        Assert.assertTrue(packageInstallTrackerIntent
-                .hasAction(Intent.ACTION_PACKAGE_FIRST_LAUNCH));
-        Assert.assertTrue(packageInstallTrackerIntent.hasAction(Intent.ACTION_PACKAGE_RESTARTED));
-        Assert.assertTrue(packageInstallTrackerIntent
+        assertTrue(packageInstallTrackerIntent.hasAction(Intent.ACTION_PACKAGE_ADDED));
+        assertTrue(packageInstallTrackerIntent.hasAction(Intent.ACTION_PACKAGE_CHANGED));
+        assertTrue(packageInstallTrackerIntent.hasAction(Intent.ACTION_PACKAGE_REMOVED));
+        assertTrue(packageInstallTrackerIntent.hasAction(Intent.ACTION_PACKAGE_REPLACED));
+        assertTrue(packageInstallTrackerIntent.hasAction(Intent.ACTION_PACKAGE_FIRST_LAUNCH));
+        assertTrue(packageInstallTrackerIntent.hasAction(Intent.ACTION_PACKAGE_RESTARTED));
+        assertTrue(packageInstallTrackerIntent
                 .hasDataScheme(RegisteredServicesCache.PACKAGE_DATA));
         IntentFilter sdCardIntentFilter = mIntentFilterArgumentCaptor.getAllValues().get(1);
-        Assert.assertTrue(sdCardIntentFilter
-                .hasAction(Intent.ACTION_EXTERNAL_APPLICATIONS_AVAILABLE));
-        Assert.assertTrue(sdCardIntentFilter
-                .hasAction(Intent.ACTION_EXTERNAL_APPLICATIONS_UNAVAILABLE));
-        Assert.assertEquals(mRegisteredServicesCache.mReceiver.get(),
+        assertTrue(sdCardIntentFilter.hasAction(Intent.ACTION_EXTERNAL_APPLICATIONS_AVAILABLE));
+        assertTrue(sdCardIntentFilter.hasAction(Intent.ACTION_EXTERNAL_APPLICATIONS_UNAVAILABLE));
+        assertEquals(mRegisteredServicesCache.mReceiver.get(),
                 mReceiverArgumentCaptor.getAllValues().get(0));
-        Assert.assertEquals(mRegisteredServicesCache.mReceiver.get(),
+        assertEquals(mRegisteredServicesCache.mReceiver.get(),
                 mReceiverArgumentCaptor.getAllValues().get(1));
         verify(mContext, times(2)).getFilesDir();
         // Verify that correct file setting directories are set
-        Assert.assertEquals(mRegisteredServicesCache.mDynamicSettingsFile.getBaseFile()
-                        .getParentFile(), DIR);
-        Assert.assertEquals(mRegisteredServicesCache.mDynamicSettingsFile.getBaseFile()
-                        .getAbsolutePath(), DIR + RegisteredServicesCache.AID_XML_PATH);
-        Assert.assertEquals(mRegisteredServicesCache.mOthersFile.getBaseFile().getParentFile(),
-                DIR);
-        Assert.assertEquals(mRegisteredServicesCache.mOthersFile.getBaseFile()
-                .getAbsolutePath(), DIR + RegisteredServicesCache.OTHER_STATUS_PATH);
+        assertEquals(DIR,
+            mRegisteredServicesCache.mDynamicSettingsFile.getBaseFile().getParentFile());
+        assertEquals(DIR + RegisteredServicesCache.AID_XML_PATH,
+            mRegisteredServicesCache.mDynamicSettingsFile.getBaseFile().getAbsolutePath());
+        assertEquals(DIR, mRegisteredServicesCache.mOthersFile.getBaseFile().getParentFile());
+        assertEquals(DIR + RegisteredServicesCache.OTHER_STATUS_PATH,
+            mRegisteredServicesCache.mOthersFile.getBaseFile().getAbsolutePath());
     }
 
     @Test
@@ -298,47 +296,43 @@ public class RegisteredServicesCacheTest {
         verifyNoMoreInteractions(mDynamicSettingsFile);
         verifyNoMoreInteractions(mOtherSettingsFile);
         // Verify that user services are read properly
-        Assert.assertEquals(1, mRegisteredServicesCache.mUserServices.size());
+        assertEquals(1, mRegisteredServicesCache.mUserServices.size());
         RegisteredServicesCache.UserServices userServices
                 = mRegisteredServicesCache.mUserServices.get(USER_ID);
-        Assert.assertEquals(2, userServices.services.size());
-        Assert.assertTrue(userServices.services.containsKey(WALLET_HOLDER_SERVICE_COMPONENT));
-        Assert.assertTrue(userServices.services.containsKey(ANOTHER_SERVICE_COMPONENT));
-        Assert.assertEquals(3, userServices.dynamicSettings.size());
+        assertEquals(2, userServices.services.size());
+        assertTrue(userServices.services.containsKey(WALLET_HOLDER_SERVICE_COMPONENT));
+        assertTrue(userServices.services.containsKey(ANOTHER_SERVICE_COMPONENT));
+        assertEquals(3, userServices.dynamicSettings.size());
         // Verify that dynamic settings are read properly
-        Assert.assertTrue(userServices.dynamicSettings
-                .containsKey(WALLET_HOLDER_SERVICE_COMPONENT));
-        Assert.assertTrue(userServices.dynamicSettings.containsKey(NON_PAYMENT_SERVICE_COMPONENT));
+        assertTrue(userServices.dynamicSettings.containsKey(WALLET_HOLDER_SERVICE_COMPONENT));
+        assertTrue(userServices.dynamicSettings.containsKey(NON_PAYMENT_SERVICE_COMPONENT));
         // Verify that dynamic settings are properly populated for each service in the xml
         // Verify the details of service 1
         RegisteredServicesCache.DynamicSettings walletHolderSettings =
                 userServices.dynamicSettings.get(WALLET_HOLDER_SERVICE_COMPONENT);
-        Assert.assertEquals(OFFHOST_SE_STRING+"1", walletHolderSettings.offHostSE);
-        Assert.assertEquals(1, walletHolderSettings.uid);
-        Assert.assertEquals(TRUE_STRING, walletHolderSettings.shouldDefaultToObserveModeStr);
-        Assert.assertTrue(walletHolderSettings.aidGroups
-                .containsKey(CardEmulation.CATEGORY_PAYMENT));
-        Assert.assertTrue(walletHolderSettings.aidGroups.get(CardEmulation.CATEGORY_PAYMENT)
+        assertEquals(OFFHOST_SE_STRING + "1", walletHolderSettings.offHostSE);
+        assertEquals(1, walletHolderSettings.uid);
+        assertEquals(TRUE_STRING, walletHolderSettings.shouldDefaultToObserveModeStr);
+        assertTrue(walletHolderSettings.aidGroups.containsKey(CardEmulation.CATEGORY_PAYMENT));
+        assertTrue(walletHolderSettings.aidGroups.get(CardEmulation.CATEGORY_PAYMENT)
                         .getAids().containsAll(PAYMENT_AIDS));
-        Assert.assertFalse(walletHolderSettings.aidGroups
-                .containsKey(CardEmulation.CATEGORY_OTHER));
+        assertFalse(walletHolderSettings.aidGroups.containsKey(CardEmulation.CATEGORY_OTHER));
         // Verify the details of service 2
         RegisteredServicesCache.DynamicSettings nonPaymentSettings =
                 userServices.dynamicSettings.get(NON_PAYMENT_SERVICE_COMPONENT);
-        Assert.assertEquals(OFFHOST_SE_STRING+"2", nonPaymentSettings.offHostSE);
-        Assert.assertEquals(1, nonPaymentSettings.uid);
-        Assert.assertEquals(FALSE_STRING, nonPaymentSettings.shouldDefaultToObserveModeStr);
-        Assert.assertTrue(nonPaymentSettings.aidGroups
-                .containsKey(CardEmulation.CATEGORY_OTHER));
-        Assert.assertTrue(nonPaymentSettings.aidGroups.get(CardEmulation.CATEGORY_OTHER)
+        assertEquals(OFFHOST_SE_STRING + "2", nonPaymentSettings.offHostSE);
+        assertEquals(1, nonPaymentSettings.uid);
+        assertEquals(FALSE_STRING, nonPaymentSettings.shouldDefaultToObserveModeStr);
+        assertTrue(nonPaymentSettings.aidGroups.containsKey(CardEmulation.CATEGORY_OTHER));
+        assertTrue(nonPaymentSettings.aidGroups.get(CardEmulation.CATEGORY_OTHER)
                 .getAids().containsAll(NON_PAYMENT_AID));
         // Verify that other settings are read properly
-        Assert.assertEquals(1, userServices.others.size());
-        Assert.assertTrue(userServices.others.containsKey(ANOTHER_SERVICE_COMPONENT));
+        assertEquals(1, userServices.others.size());
+        assertTrue(userServices.others.containsKey(ANOTHER_SERVICE_COMPONENT));
         RegisteredServicesCache.OtherServiceStatus otherServiceStatus
                 = userServices.others.get(ANOTHER_SERVICE_COMPONENT);
-        Assert.assertTrue(otherServiceStatus.checked);
-        Assert.assertEquals(1, otherServiceStatus.uid);
+        assertTrue(otherServiceStatus.checked);
+        assertEquals(1, otherServiceStatus.uid);
         // Verify that the installed services are populated properly
         verify(mContext)
                 .createPackageContextAsUser(eq(ANDROID_STRING), eq(0), eq(USER_HANDLE));
@@ -347,13 +341,13 @@ public class RegisteredServicesCacheTest {
                 .queryIntentServicesAsUser(mIntentArgumentCaptor.capture(),
                         mFlagArgumentCaptor.capture(), eq(USER_HANDLE));
         Intent onHostIntent = mIntentArgumentCaptor.getAllValues().get(0);
-        Assert.assertEquals(HostApduService.SERVICE_INTERFACE, onHostIntent.getAction());
+        assertEquals(HostApduService.SERVICE_INTERFACE, onHostIntent.getAction());
         Intent offHostIntent = mIntentArgumentCaptor.getAllValues().get(1);
-        Assert.assertEquals(OffHostApduService.SERVICE_INTERFACE, offHostIntent.getAction());
+        assertEquals(OffHostApduService.SERVICE_INTERFACE, offHostIntent.getAction());
         PackageManager.ResolveInfoFlags onHostFlag = mFlagArgumentCaptor.getAllValues().get(0);
-        Assert.assertEquals(PackageManager.GET_META_DATA, onHostFlag.getValue());
+        assertEquals(PackageManager.GET_META_DATA, onHostFlag.getValue());
         PackageManager.ResolveInfoFlags offHostFlag = mFlagArgumentCaptor.getAllValues().get(1);
-        Assert.assertEquals(PackageManager.GET_META_DATA, offHostFlag.getValue());
+        assertEquals(PackageManager.GET_META_DATA, offHostFlag.getValue());
         // Verify that the installed services are filtered properly
         verify(mPackageManager).checkPermission(eq(android.Manifest.permission.NFC),
                 eq(WALLET_HOLDER_PACKAGE_NAME));
@@ -365,10 +359,9 @@ public class RegisteredServicesCacheTest {
         verify(mCallback).onServicesUpdated(eq(USER_ID), mApduServiceListCaptor.capture(),
                 eq(false));
         List<ApduServiceInfo> apduServiceInfos = mApduServiceListCaptor.getValue();
-        Assert.assertEquals(2, apduServiceInfos.size());
-        Assert.assertEquals(WALLET_HOLDER_SERVICE_COMPONENT, apduServiceInfos.get(0)
-                .getComponent());
-        Assert.assertEquals(ANOTHER_SERVICE_COMPONENT, apduServiceInfos.get(1).getComponent());
+        assertEquals(2, apduServiceInfos.size());
+        assertEquals(WALLET_HOLDER_SERVICE_COMPONENT, apduServiceInfos.get(0).getComponent());
+        assertEquals(ANOTHER_SERVICE_COMPONENT, apduServiceInfos.get(1).getComponent());
     }
 
     @Test
@@ -390,25 +383,24 @@ public class RegisteredServicesCacheTest {
         verify(mOtherSettingsFile).finishWrite(fileOutputStreamArgumentCaptor.capture());
         verifyNoMoreInteractions(mOtherSettingsFile);
         // Validate that no dynamic settings are read
-        Assert.assertEquals(1, mRegisteredServicesCache.mUserServices.size());
+        assertEquals(1, mRegisteredServicesCache.mUserServices.size());
         RegisteredServicesCache.UserServices userServices
                 = mRegisteredServicesCache.mUserServices.get(USER_ID);
-        Assert.assertTrue(userServices.dynamicSettings.isEmpty());
+        assertTrue(userServices.dynamicSettings.isEmpty());
         // Verify that other settings are only read from system services
-        Assert.assertEquals(1, userServices.others.size());
-        Assert.assertTrue(userServices.others.containsKey(ANOTHER_SERVICE_COMPONENT));
+        assertEquals(1, userServices.others.size());
+        assertTrue(userServices.others.containsKey(ANOTHER_SERVICE_COMPONENT));
         RegisteredServicesCache.OtherServiceStatus otherServiceStatus
                 = userServices.others.get(ANOTHER_SERVICE_COMPONENT);
-        Assert.assertTrue(otherServiceStatus.checked);
-        Assert.assertEquals(USER_ID, otherServiceStatus.uid);
+        assertTrue(otherServiceStatus.checked);
+        assertEquals(USER_ID, otherServiceStatus.uid);
         // Verify that the callback is called with properly installed and filtered services.
         verify(mCallback).onServicesUpdated(eq(USER_ID), mApduServiceListCaptor.capture(),
                 eq(false));
         List<ApduServiceInfo> apduServiceInfos = mApduServiceListCaptor.getValue();
-        Assert.assertEquals(2, apduServiceInfos.size());
-        Assert.assertEquals(WALLET_HOLDER_SERVICE_COMPONENT, apduServiceInfos.get(0)
-                .getComponent());
-        Assert.assertEquals(ANOTHER_SERVICE_COMPONENT, apduServiceInfos.get(1).getComponent());
+        assertEquals(2, apduServiceInfos.size());
+        assertEquals(WALLET_HOLDER_SERVICE_COMPONENT, apduServiceInfos.get(0).getComponent());
+        assertEquals(ANOTHER_SERVICE_COMPONENT, apduServiceInfos.get(1).getComponent());
         // Validate that other setting file is written properly with a setting
         // that previously did not exists.
         InputStream otherSettingsIs = mockFileOutputStream.toInputStream();
@@ -419,12 +411,12 @@ public class RegisteredServicesCacheTest {
         Map<Integer, List<Pair<ComponentName, RegisteredServicesCache.OtherServiceStatus>>>
                 readOtherSettingsFromFile = RegisteredServicesCache
                 .readOtherFromFile(otherSettingsFile);
-        Assert.assertEquals(mockFileOutputStream, fileOutputStreamArgumentCaptor.getValue());
-        Assert.assertTrue(readOtherSettingsFromFile.containsKey(USER_ID));
-        Assert.assertFalse(readOtherSettingsFromFile.get(USER_ID).isEmpty());
-        Assert.assertEquals(readOtherSettingsFromFile.get(USER_ID).get(0).first,
-                ANOTHER_SERVICE_COMPONENT);
-        Assert.assertTrue(readOtherSettingsFromFile.get(USER_ID).get(0).second.checked);
+        assertEquals(mockFileOutputStream, fileOutputStreamArgumentCaptor.getValue());
+        assertTrue(readOtherSettingsFromFile.containsKey(USER_ID));
+        assertFalse(readOtherSettingsFromFile.get(USER_ID).isEmpty());
+        assertEquals(ANOTHER_SERVICE_COMPONENT,
+            readOtherSettingsFromFile.get(USER_ID).get(0).first);
+        assertTrue(readOtherSettingsFromFile.get(USER_ID).get(0).second.checked);
     }
 
     @SuppressWarnings("GuardedBy")
@@ -442,8 +434,8 @@ public class RegisteredServicesCacheTest {
         mRegisteredServicesCache.onUserSwitched();
 
         // Validate that quite mode profiles get filtered out.
-        Assert.assertEquals(1, mRegisteredServicesCache.mUserHandles.size());
-        Assert.assertEquals(mRegisteredServicesCache.mUserHandles.get(0), USER_HANDLE);
+        assertEquals(1, mRegisteredServicesCache.mUserHandles.size());
+        assertEquals(USER_HANDLE, mRegisteredServicesCache.mUserHandles.get(0));
     }
 
     @SuppressWarnings("GuardedBy")
@@ -461,8 +453,8 @@ public class RegisteredServicesCacheTest {
         mRegisteredServicesCache.onManagedProfileChanged();
 
         // Validate that quite mode profiles get filtered out.
-        Assert.assertEquals(1, mRegisteredServicesCache.mUserHandles.size());
-        Assert.assertEquals(mRegisteredServicesCache.mUserHandles.get(0), USER_HANDLE);
+        assertEquals(1, mRegisteredServicesCache.mUserHandles.size());
+        assertEquals(USER_HANDLE, mRegisteredServicesCache.mUserHandles.get(0));
     }
 
     @Test
@@ -473,9 +465,8 @@ public class RegisteredServicesCacheTest {
                 mDynamicSettingsFile, mOtherSettingsFile, mServiceParser, mRoutingOptionManager);
         mRegisteredServicesCache.initialize();
 
-        Assert.assertTrue(mRegisteredServicesCache.hasService(USER_ID, ANOTHER_SERVICE_COMPONENT));
-        Assert.assertTrue(mRegisteredServicesCache.hasService(USER_ID,
-                WALLET_HOLDER_SERVICE_COMPONENT));
+        assertTrue(mRegisteredServicesCache.hasService(USER_ID, ANOTHER_SERVICE_COMPONENT));
+        assertTrue(mRegisteredServicesCache.hasService(USER_ID, WALLET_HOLDER_SERVICE_COMPONENT));
     }
 
     @Test
@@ -488,8 +479,8 @@ public class RegisteredServicesCacheTest {
 
         ApduServiceInfo serviceInfo = mRegisteredServicesCache.getService(USER_ID,
                 WALLET_HOLDER_SERVICE_COMPONENT);
-        Assert.assertEquals(WALLET_HOLDER_SERVICE_COMPONENT, serviceInfo.getComponent());
-        Assert.assertEquals(SERVICE_UID, serviceInfo.getUid());
+        assertEquals(WALLET_HOLDER_SERVICE_COMPONENT, serviceInfo.getComponent());
+        assertEquals(SERVICE_UID, serviceInfo.getUid());
     }
 
     @Test
@@ -501,10 +492,10 @@ public class RegisteredServicesCacheTest {
         mRegisteredServicesCache.initialize();
 
         List<ApduServiceInfo> serviceInfos = mRegisteredServicesCache.getServices(USER_ID);
-        Assert.assertFalse(serviceInfos.isEmpty());
-        Assert.assertEquals(2, serviceInfos.size());
-        Assert.assertEquals(ANOTHER_SERVICE_COMPONENT, serviceInfos.get(0).getComponent());
-        Assert.assertEquals(WALLET_HOLDER_SERVICE_COMPONENT, serviceInfos.get(1).getComponent());
+        assertFalse(serviceInfos.isEmpty());
+        assertEquals(2, serviceInfos.size());
+        assertEquals(ANOTHER_SERVICE_COMPONENT, serviceInfos.get(0).getComponent());
+        assertEquals(WALLET_HOLDER_SERVICE_COMPONENT, serviceInfos.get(1).getComponent());
     }
 
     @Test
@@ -517,9 +508,9 @@ public class RegisteredServicesCacheTest {
 
         List<ApduServiceInfo> serviceInfos = mRegisteredServicesCache
                 .getServicesForCategory(USER_ID, CardEmulation.CATEGORY_PAYMENT);
-        Assert.assertFalse(serviceInfos.isEmpty());
-        Assert.assertEquals(1, serviceInfos.size());
-        Assert.assertEquals(WALLET_HOLDER_SERVICE_COMPONENT, serviceInfos.get(0).getComponent());
+        assertFalse(serviceInfos.isEmpty());
+        assertEquals(1, serviceInfos.size());
+        assertEquals(WALLET_HOLDER_SERVICE_COMPONENT, serviceInfos.get(0).getComponent());
     }
 
     @Test
@@ -532,9 +523,9 @@ public class RegisteredServicesCacheTest {
 
         List<ApduServiceInfo> serviceInfos = mRegisteredServicesCache
                 .getServicesForCategory(USER_ID, CardEmulation.CATEGORY_OTHER);
-        Assert.assertFalse(serviceInfos.isEmpty());
-        Assert.assertEquals(1, serviceInfos.size());
-        Assert.assertEquals(ANOTHER_SERVICE_COMPONENT, serviceInfos.get(0).getComponent());
+        assertFalse(serviceInfos.isEmpty());
+        assertEquals(1, serviceInfos.size());
+        assertEquals(ANOTHER_SERVICE_COMPONENT, serviceInfos.get(0).getComponent());
     }
 
     @Test
@@ -544,7 +535,7 @@ public class RegisteredServicesCacheTest {
         mRegisteredServicesCache.initialize();
         ComponentName wrongComponentName = new ComponentName("test","com.wrong.class");
 
-        Assert.assertFalse(mRegisteredServicesCache.setOffHostSecureElement(USER_ID,
+        assertFalse(mRegisteredServicesCache.setOffHostSecureElement(USER_ID,
                 SERVICE_UID, wrongComponentName, "offhostse1"));
     }
 
@@ -554,7 +545,7 @@ public class RegisteredServicesCacheTest {
                 mDynamicSettingsFile, mOtherSettingsFile, mServiceParser, mRoutingOptionManager);
         mRegisteredServicesCache.initialize();
 
-        Assert.assertFalse(mRegisteredServicesCache.setOffHostSecureElement(USER_ID,
+        assertFalse(mRegisteredServicesCache.setOffHostSecureElement(USER_ID,
                 3, WALLET_HOLDER_SERVICE_COMPONENT, "offhostse1"));
     }
 
@@ -564,7 +555,7 @@ public class RegisteredServicesCacheTest {
                 mDynamicSettingsFile, mOtherSettingsFile, mServiceParser, mRoutingOptionManager);
         mRegisteredServicesCache.initialize();
 
-        Assert.assertFalse(mRegisteredServicesCache.setOffHostSecureElement(USER_ID,
+        assertFalse(mRegisteredServicesCache.setOffHostSecureElement(USER_ID,
                 SERVICE_UID, WALLET_HOLDER_SERVICE_COMPONENT, null));
     }
 
@@ -585,23 +576,21 @@ public class RegisteredServicesCacheTest {
         mRegisteredServicesCache.initialize();
         String newOffHostValue = "newOffhostValue";
 
-        Assert.assertTrue(mRegisteredServicesCache.setOffHostSecureElement(USER_ID,
+        assertTrue(mRegisteredServicesCache.setOffHostSecureElement(USER_ID,
                 SERVICE_UID, WALLET_HOLDER_SERVICE_COMPONENT, newOffHostValue));
         verify(mDynamicSettingsFile).exists();
         verify(mDynamicSettingsFile).openRead();
         verify(mDynamicSettingsFile).startWrite();
         verify(mDynamicSettingsFile).finishWrite(fileOutputStreamArgumentCaptor.capture());
         verifyNoMoreInteractions(mDynamicSettingsFile);
-        Assert.assertEquals(mockFileOutputStream, fileOutputStreamArgumentCaptor.getValue());
+        assertEquals(mockFileOutputStream, fileOutputStreamArgumentCaptor.getValue());
         // Verify that the callback is called with properly installed and filtered services.
         verify(mCallback).onServicesUpdated(eq(USER_ID), mApduServiceListCaptor.capture(),
                 eq(true));
         List<ApduServiceInfo> apduServiceInfos = mApduServiceListCaptor.getValue();
-        Assert.assertEquals(2, apduServiceInfos.size());
-        Assert.assertEquals(ANOTHER_SERVICE_COMPONENT, apduServiceInfos.get(0)
-                .getComponent());
-        Assert.assertEquals(WALLET_HOLDER_SERVICE_COMPONENT, apduServiceInfos.get(1)
-                .getComponent());
+        assertEquals(2, apduServiceInfos.size());
+        assertEquals(ANOTHER_SERVICE_COMPONENT, apduServiceInfos.get(0).getComponent());
+        assertEquals(WALLET_HOLDER_SERVICE_COMPONENT, apduServiceInfos.get(1).getComponent());
         verify(apduServiceInfos.get(1)).setOffHostSecureElement(eq(newOffHostValue));
         // Verify that dynamic settings file is updated
         InputStream dynamicSettingsMockIs = mockFileOutputStream.toInputStream();
@@ -612,13 +601,13 @@ public class RegisteredServicesCacheTest {
         Map<Integer, List<Pair<ComponentName, RegisteredServicesCache.DynamicSettings>>>
                 readDynamicSettingsFromFile = RegisteredServicesCache
                 .readDynamicSettingsFromFile(dynamicSettingsFile);
-        Assert.assertFalse(readDynamicSettingsFromFile.isEmpty());
-        Assert.assertTrue(readDynamicSettingsFromFile.containsKey(USER_ID));
+        assertFalse(readDynamicSettingsFromFile.isEmpty());
+        assertTrue(readDynamicSettingsFromFile.containsKey(USER_ID));
         RegisteredServicesCache.DynamicSettings dynamicSettings
                 = readDynamicSettingsFromFile.get(USER_ID).get(1).second;
-        Assert.assertEquals(WALLET_HOLDER_SERVICE_COMPONENT,
+        assertEquals(WALLET_HOLDER_SERVICE_COMPONENT,
                 readDynamicSettingsFromFile.get(USER_ID).get(1).first);
-        Assert.assertEquals(newOffHostValue, dynamicSettings.offHostSE);
+        assertEquals(newOffHostValue, dynamicSettings.offHostSE);
     }
 
     @Test
@@ -628,7 +617,7 @@ public class RegisteredServicesCacheTest {
         mRegisteredServicesCache.initialize();
         ComponentName wrongComponentName = new ComponentName("test","com.wrong.class");
 
-        Assert.assertFalse(mRegisteredServicesCache.resetOffHostSecureElement(USER_ID,
+        assertFalse(mRegisteredServicesCache.resetOffHostSecureElement(USER_ID,
                 SERVICE_UID, wrongComponentName));
     }
 
@@ -638,7 +627,7 @@ public class RegisteredServicesCacheTest {
                 mDynamicSettingsFile, mOtherSettingsFile, mServiceParser, mRoutingOptionManager);
         mRegisteredServicesCache.initialize();
 
-        Assert.assertFalse(mRegisteredServicesCache.resetOffHostSecureElement(USER_ID,
+        assertFalse(mRegisteredServicesCache.resetOffHostSecureElement(USER_ID,
                 3, WALLET_HOLDER_SERVICE_COMPONENT));
     }
 
@@ -648,7 +637,7 @@ public class RegisteredServicesCacheTest {
                 mDynamicSettingsFile, mOtherSettingsFile, mServiceParser, mRoutingOptionManager);
         mRegisteredServicesCache.initialize();
 
-        Assert.assertFalse(mRegisteredServicesCache.resetOffHostSecureElement(USER_ID,
+        assertFalse(mRegisteredServicesCache.resetOffHostSecureElement(USER_ID,
                 SERVICE_UID, WALLET_HOLDER_SERVICE_COMPONENT));
     }
 
@@ -670,23 +659,21 @@ public class RegisteredServicesCacheTest {
         when(mRegisteredServicesCache.getService(USER_ID, ANOTHER_SERVICE_COMPONENT)
                 .getOffHostSecureElement()).thenReturn("offhost");
 
-        Assert.assertTrue(mRegisteredServicesCache.resetOffHostSecureElement(USER_ID,
+        assertTrue(mRegisteredServicesCache.resetOffHostSecureElement(USER_ID,
                 SERVICE_UID, ANOTHER_SERVICE_COMPONENT));
         verify(mDynamicSettingsFile).exists();
         verify(mDynamicSettingsFile).openRead();
         verify(mDynamicSettingsFile).startWrite();
         verify(mDynamicSettingsFile).finishWrite(fileOutputStreamArgumentCaptor.capture());
         verifyNoMoreInteractions(mDynamicSettingsFile);
-        Assert.assertEquals(mockFileOutputStream, fileOutputStreamArgumentCaptor.getValue());
+        assertEquals(mockFileOutputStream, fileOutputStreamArgumentCaptor.getValue());
         // Verify that the callback is called with properly installed and filtered services.
         verify(mCallback).onServicesUpdated(eq(USER_ID), mApduServiceListCaptor.capture(),
                 eq(true));
         List<ApduServiceInfo> apduServiceInfos = mApduServiceListCaptor.getValue();
-        Assert.assertEquals(2, apduServiceInfos.size());
-        Assert.assertEquals(ANOTHER_SERVICE_COMPONENT, apduServiceInfos.get(0)
-                .getComponent());
-        Assert.assertEquals(WALLET_HOLDER_SERVICE_COMPONENT, apduServiceInfos.get(1)
-                .getComponent());
+        assertEquals(2, apduServiceInfos.size());
+        assertEquals(ANOTHER_SERVICE_COMPONENT, apduServiceInfos.get(0).getComponent());
+        assertEquals(WALLET_HOLDER_SERVICE_COMPONENT, apduServiceInfos.get(1).getComponent());
         verify(apduServiceInfos.get(0)).resetOffHostSecureElement();
         // Verify that dynamic settings file is updated
         InputStream dynamicSettingsMockIs = mockFileOutputStream.toInputStream();
@@ -697,11 +684,11 @@ public class RegisteredServicesCacheTest {
         Map<Integer, List<Pair<ComponentName, RegisteredServicesCache.DynamicSettings>>>
                 readDynamicSettingsFromFile = RegisteredServicesCache
                 .readDynamicSettingsFromFile(dynamicSettingsFile);
-        Assert.assertFalse(readDynamicSettingsFromFile.isEmpty());
-        Assert.assertTrue(readDynamicSettingsFromFile.containsKey(USER_ID));
+        assertFalse(readDynamicSettingsFromFile.isEmpty());
+        assertTrue(readDynamicSettingsFromFile.containsKey(USER_ID));
         RegisteredServicesCache.DynamicSettings dynamicSettings
                 = readDynamicSettingsFromFile.get(USER_ID).get(0).second;
-        Assert.assertEquals(ANOTHER_SERVICE_COMPONENT,
+        assertEquals(ANOTHER_SERVICE_COMPONENT,
                 readDynamicSettingsFromFile.get(USER_ID).get(0).first);
         assertNull(dynamicSettings.offHostSE);
     }
@@ -713,7 +700,7 @@ public class RegisteredServicesCacheTest {
         mRegisteredServicesCache.initialize();
         ComponentName wrongComponentName = new ComponentName("test","com.wrong.class");
 
-        Assert.assertFalse(mRegisteredServicesCache.setShouldDefaultToObserveModeForService(USER_ID,
+        assertFalse(mRegisteredServicesCache.setShouldDefaultToObserveModeForService(USER_ID,
                 SERVICE_UID, wrongComponentName, true));
     }
 
@@ -723,7 +710,7 @@ public class RegisteredServicesCacheTest {
                 mDynamicSettingsFile, mOtherSettingsFile, mServiceParser, mRoutingOptionManager);
         mRegisteredServicesCache.initialize();
 
-        Assert.assertFalse(mRegisteredServicesCache.setShouldDefaultToObserveModeForService(USER_ID,
+        assertFalse(mRegisteredServicesCache.setShouldDefaultToObserveModeForService(USER_ID,
                 3, WALLET_HOLDER_SERVICE_COMPONENT, true));
     }
 
@@ -739,9 +726,9 @@ public class RegisteredServicesCacheTest {
                 mDynamicSettingsFile, mOtherSettingsFile, mServiceParser, mRoutingOptionManager);
         mRegisteredServicesCache.initialize();
 
-        Assert.assertTrue(mRegisteredServicesCache.setShouldDefaultToObserveModeForService(USER_ID,
+        assertTrue(mRegisteredServicesCache.setShouldDefaultToObserveModeForService(USER_ID,
                 SERVICE_UID, WALLET_HOLDER_SERVICE_COMPONENT, true));
-        Assert.assertEquals("true", mRegisteredServicesCache.mUserServices.get(USER_ID)
+        assertEquals("true", mRegisteredServicesCache.mUserServices.get(USER_ID)
                 .dynamicSettings.get(WALLET_HOLDER_SERVICE_COMPONENT)
                 .shouldDefaultToObserveModeStr);
         verify(mRegisteredServicesCache.getService(USER_ID, WALLET_HOLDER_SERVICE_COMPONENT),
@@ -755,7 +742,7 @@ public class RegisteredServicesCacheTest {
         mRegisteredServicesCache.initialize();
         ComponentName wrongComponentName = new ComponentName("test","com.wrong.class");
 
-        Assert.assertFalse(mRegisteredServicesCache.registerPollingLoopFilterForService(USER_ID,
+        assertFalse(mRegisteredServicesCache.registerPollingLoopFilterForService(USER_ID,
                 SERVICE_UID, wrongComponentName, "empty", true));
     }
 
@@ -765,7 +752,7 @@ public class RegisteredServicesCacheTest {
                 mDynamicSettingsFile, mOtherSettingsFile, mServiceParser, mRoutingOptionManager);
         mRegisteredServicesCache.initialize();
 
-        Assert.assertFalse(mRegisteredServicesCache.registerPollingLoopFilterForService(USER_ID,
+        assertFalse(mRegisteredServicesCache.registerPollingLoopFilterForService(USER_ID,
                 3, WALLET_HOLDER_SERVICE_COMPONENT, "empty", true));
     }
 
@@ -776,16 +763,16 @@ public class RegisteredServicesCacheTest {
         mRegisteredServicesCache.initialize();
         String plFilter = "afilter";
 
-        Assert.assertTrue(mRegisteredServicesCache.registerPollingLoopFilterForService(USER_ID,
+        assertTrue(mRegisteredServicesCache.registerPollingLoopFilterForService(USER_ID,
                 SERVICE_UID, WALLET_HOLDER_SERVICE_COMPONENT, plFilter, true));
         // Verify that the callback is called with properly installed and filtered services.
         verify(mCallback).onServicesUpdated(eq(USER_ID), mApduServiceListCaptor.capture(),
                 eq(true));
         List<ApduServiceInfo> apduServiceInfos = mApduServiceListCaptor.getValue();
-        Assert.assertEquals(2, apduServiceInfos.size());
-        Assert.assertEquals(ANOTHER_SERVICE_COMPONENT, apduServiceInfos.get(0)
+        assertEquals(2, apduServiceInfos.size());
+        assertEquals(ANOTHER_SERVICE_COMPONENT, apduServiceInfos.get(0)
                 .getComponent());
-        Assert.assertEquals(WALLET_HOLDER_SERVICE_COMPONENT, apduServiceInfos.get(1)
+        assertEquals(WALLET_HOLDER_SERVICE_COMPONENT, apduServiceInfos.get(1)
                 .getComponent());
         verify(apduServiceInfos.get(1)).addPollingLoopFilter(eq(plFilter), eq(true));
     }
@@ -797,7 +784,7 @@ public class RegisteredServicesCacheTest {
         mRegisteredServicesCache.initialize();
         ComponentName wrongComponentName = new ComponentName("test","com.wrong.class");
 
-        Assert.assertFalse(mRegisteredServicesCache.removePollingLoopFilterForService(USER_ID,
+        assertFalse(mRegisteredServicesCache.removePollingLoopFilterForService(USER_ID,
                 SERVICE_UID, wrongComponentName, "empty"));
     }
 
@@ -807,7 +794,7 @@ public class RegisteredServicesCacheTest {
                 mDynamicSettingsFile, mOtherSettingsFile, mServiceParser, mRoutingOptionManager);
         mRegisteredServicesCache.initialize();
 
-        Assert.assertFalse(mRegisteredServicesCache.removePollingLoopFilterForService(USER_ID,
+        assertFalse(mRegisteredServicesCache.removePollingLoopFilterForService(USER_ID,
                 3, WALLET_HOLDER_SERVICE_COMPONENT, "empty"));
     }
 
@@ -818,17 +805,15 @@ public class RegisteredServicesCacheTest {
         mRegisteredServicesCache.initialize();
         String plFilter = "afilter";
 
-        Assert.assertTrue(mRegisteredServicesCache.removePollingLoopFilterForService(USER_ID,
+        assertTrue(mRegisteredServicesCache.removePollingLoopFilterForService(USER_ID,
                 SERVICE_UID, WALLET_HOLDER_SERVICE_COMPONENT, plFilter));
         // Verify that the callback is called with properly installed and filtered services.
         verify(mCallback).onServicesUpdated(eq(USER_ID), mApduServiceListCaptor.capture(),
                 eq(true));
         List<ApduServiceInfo> apduServiceInfos = mApduServiceListCaptor.getValue();
-        Assert.assertEquals(2, apduServiceInfos.size());
-        Assert.assertEquals(ANOTHER_SERVICE_COMPONENT, apduServiceInfos.get(0)
-                .getComponent());
-        Assert.assertEquals(WALLET_HOLDER_SERVICE_COMPONENT, apduServiceInfos.get(1)
-                .getComponent());
+        assertEquals(2, apduServiceInfos.size());
+        assertEquals(ANOTHER_SERVICE_COMPONENT, apduServiceInfos.get(0).getComponent());
+        assertEquals(WALLET_HOLDER_SERVICE_COMPONENT, apduServiceInfos.get(1).getComponent());
         verify(apduServiceInfos.get(1)).removePollingLoopFilter(eq(plFilter));
     }
 
@@ -839,7 +824,7 @@ public class RegisteredServicesCacheTest {
         mRegisteredServicesCache.initialize();
         ComponentName wrongComponentName = new ComponentName("test","com.wrong.class");
 
-        Assert.assertFalse(mRegisteredServicesCache.registerPollingLoopPatternFilterForService(
+        assertFalse(mRegisteredServicesCache.registerPollingLoopPatternFilterForService(
                 USER_ID, SERVICE_UID, wrongComponentName, "empty",
                 true));
     }
@@ -850,7 +835,7 @@ public class RegisteredServicesCacheTest {
                 mDynamicSettingsFile, mOtherSettingsFile, mServiceParser, mRoutingOptionManager);
         mRegisteredServicesCache.initialize();
 
-        Assert.assertFalse(mRegisteredServicesCache
+        assertFalse(mRegisteredServicesCache
                 .registerPollingLoopPatternFilterForService(USER_ID, 3,
                         WALLET_HOLDER_SERVICE_COMPONENT, "empty", true));
     }
@@ -862,17 +847,15 @@ public class RegisteredServicesCacheTest {
         mRegisteredServicesCache.initialize();
         String plFilter = "afilter";
 
-        Assert.assertTrue(mRegisteredServicesCache.registerPollingLoopPatternFilterForService(
+        assertTrue(mRegisteredServicesCache.registerPollingLoopPatternFilterForService(
                 USER_ID, SERVICE_UID, WALLET_HOLDER_SERVICE_COMPONENT, plFilter, true));
         // Verify that the callback is called with properly installed and filtered services.
         verify(mCallback).onServicesUpdated(eq(USER_ID), mApduServiceListCaptor.capture(),
                 eq(true));
         List<ApduServiceInfo> apduServiceInfos = mApduServiceListCaptor.getValue();
-        Assert.assertEquals(2, apduServiceInfos.size());
-        Assert.assertEquals(ANOTHER_SERVICE_COMPONENT, apduServiceInfos.get(0)
-                .getComponent());
-        Assert.assertEquals(WALLET_HOLDER_SERVICE_COMPONENT, apduServiceInfos.get(1)
-                .getComponent());
+        assertEquals(2, apduServiceInfos.size());
+        assertEquals(ANOTHER_SERVICE_COMPONENT, apduServiceInfos.get(0).getComponent());
+        assertEquals(WALLET_HOLDER_SERVICE_COMPONENT, apduServiceInfos.get(1).getComponent());
         verify(apduServiceInfos.get(1)).addPollingLoopPatternFilter(eq(plFilter), eq(true));
     }
 
@@ -883,7 +866,7 @@ public class RegisteredServicesCacheTest {
         mRegisteredServicesCache.initialize();
         ComponentName wrongComponentName = new ComponentName("test","com.wrong.class");
 
-        Assert.assertFalse(mRegisteredServicesCache.removePollingLoopPatternFilterForService(
+        assertFalse(mRegisteredServicesCache.removePollingLoopPatternFilterForService(
                 USER_ID, SERVICE_UID, wrongComponentName, "empty"));
     }
 
@@ -893,7 +876,7 @@ public class RegisteredServicesCacheTest {
                 mDynamicSettingsFile, mOtherSettingsFile, mServiceParser, mRoutingOptionManager);
         mRegisteredServicesCache.initialize();
 
-        Assert.assertFalse(mRegisteredServicesCache.removePollingLoopFilterForService(USER_ID,
+        assertFalse(mRegisteredServicesCache.removePollingLoopFilterForService(USER_ID,
                 3, WALLET_HOLDER_SERVICE_COMPONENT, "empty"));
     }
 
@@ -904,17 +887,15 @@ public class RegisteredServicesCacheTest {
         mRegisteredServicesCache.initialize();
         String plFilter = "afilter";
 
-        Assert.assertTrue(mRegisteredServicesCache.removePollingLoopPatternFilterForService(USER_ID,
+        assertTrue(mRegisteredServicesCache.removePollingLoopPatternFilterForService(USER_ID,
                 SERVICE_UID, WALLET_HOLDER_SERVICE_COMPONENT, plFilter));
         // Verify that the callback is called with properly installed and filtered services.
         verify(mCallback).onServicesUpdated(eq(USER_ID), mApduServiceListCaptor.capture(),
                 eq(true));
         List<ApduServiceInfo> apduServiceInfos = mApduServiceListCaptor.getValue();
-        Assert.assertEquals(2, apduServiceInfos.size());
-        Assert.assertEquals(ANOTHER_SERVICE_COMPONENT, apduServiceInfos.get(0)
-                .getComponent());
-        Assert.assertEquals(WALLET_HOLDER_SERVICE_COMPONENT, apduServiceInfos.get(1)
-                .getComponent());
+        assertEquals(2, apduServiceInfos.size());
+        assertEquals(ANOTHER_SERVICE_COMPONENT, apduServiceInfos.get(0).getComponent());
+        assertEquals(WALLET_HOLDER_SERVICE_COMPONENT, apduServiceInfos.get(1).getComponent());
         verify(apduServiceInfos.get(1)).removePollingLoopPatternFilter(eq(plFilter));
     }
 
@@ -926,7 +907,7 @@ public class RegisteredServicesCacheTest {
         ComponentName wrongComponentName = new ComponentName("test","com.wrong.class");
         AidGroup aidGroup = createAidGroup(CardEmulation.CATEGORY_PAYMENT);
 
-        Assert.assertFalse(mRegisteredServicesCache.registerAidGroupForService(
+        assertFalse(mRegisteredServicesCache.registerAidGroupForService(
                 USER_ID, SERVICE_UID, wrongComponentName, aidGroup));
     }
 
@@ -937,7 +918,7 @@ public class RegisteredServicesCacheTest {
         mRegisteredServicesCache.initialize();
         AidGroup aidGroup = createAidGroup(CardEmulation.CATEGORY_PAYMENT);
 
-        Assert.assertFalse(mRegisteredServicesCache.registerAidGroupForService(USER_ID,
+        assertFalse(mRegisteredServicesCache.registerAidGroupForService(USER_ID,
                 3, WALLET_HOLDER_SERVICE_COMPONENT, aidGroup));
     }
 
@@ -957,24 +938,22 @@ public class RegisteredServicesCacheTest {
         mRegisteredServicesCache.initialize();
         AidGroup aidGroup = createAidGroup(CardEmulation.CATEGORY_OTHER);
 
-        Assert.assertTrue(mRegisteredServicesCache.registerAidGroupForService(USER_ID,
+        assertTrue(mRegisteredServicesCache.registerAidGroupForService(USER_ID,
                 SERVICE_UID, WALLET_HOLDER_SERVICE_COMPONENT, aidGroup));
 
         ApduServiceInfo serviceInfo = mRegisteredServicesCache.getService(USER_ID,
                 WALLET_HOLDER_SERVICE_COMPONENT);
         verify(serviceInfo).setDynamicAidGroup(eq(aidGroup));
-        Assert.assertEquals(aidGroup, mRegisteredServicesCache.mUserServices.get(USER_ID)
+        assertEquals(aidGroup, mRegisteredServicesCache.mUserServices.get(USER_ID)
                 .dynamicSettings.get(WALLET_HOLDER_SERVICE_COMPONENT)
                 .aidGroups.get(CardEmulation.CATEGORY_OTHER));
         // Verify that the callback is called with properly installed and filtered services.
         verify(mCallback).onServicesUpdated(eq(USER_ID), mApduServiceListCaptor.capture(),
                 eq(true));
         List<ApduServiceInfo> apduServiceInfos = mApduServiceListCaptor.getValue();
-        Assert.assertEquals(2, apduServiceInfos.size());
-        Assert.assertEquals(ANOTHER_SERVICE_COMPONENT, apduServiceInfos.get(0)
-                .getComponent());
-        Assert.assertEquals(WALLET_HOLDER_SERVICE_COMPONENT, apduServiceInfos.get(1)
-                .getComponent());
+        assertEquals(2, apduServiceInfos.size());
+        assertEquals(ANOTHER_SERVICE_COMPONENT, apduServiceInfos.get(0).getComponent());
+        assertEquals(WALLET_HOLDER_SERVICE_COMPONENT, apduServiceInfos.get(1).getComponent());
         // Verify that dynamic settings file is updated
         InputStream dynamicSettingsMockIs = mockFileOutputStream.toInputStream();
         RegisteredServicesCache.SettingsFile dynamicSettingsFile
@@ -984,14 +963,14 @@ public class RegisteredServicesCacheTest {
         Map<Integer, List<Pair<ComponentName, RegisteredServicesCache.DynamicSettings>>>
                 readDynamicSettingsFromFile = RegisteredServicesCache
                 .readDynamicSettingsFromFile(dynamicSettingsFile);
-        Assert.assertFalse(readDynamicSettingsFromFile.isEmpty());
-        Assert.assertTrue(readDynamicSettingsFromFile.containsKey(USER_ID));
+        assertFalse(readDynamicSettingsFromFile.isEmpty());
+        assertTrue(readDynamicSettingsFromFile.containsKey(USER_ID));
         RegisteredServicesCache.DynamicSettings dynamicSettings
                 = readDynamicSettingsFromFile.get(USER_ID).get(0).second;
-        Assert.assertEquals(ANOTHER_SERVICE_COMPONENT,
+        assertEquals(ANOTHER_SERVICE_COMPONENT,
                 readDynamicSettingsFromFile.get(USER_ID).get(0).first);
-        Assert.assertTrue(dynamicSettings.aidGroups.containsKey(CardEmulation.CATEGORY_OTHER));
-        Assert.assertEquals(aidGroup.getAids(),
+        assertTrue(dynamicSettings.aidGroups.containsKey(CardEmulation.CATEGORY_OTHER));
+        assertEquals(aidGroup.getAids(),
                 dynamicSettings.aidGroups.get(CardEmulation.CATEGORY_OTHER).getAids());
     }
 
@@ -1029,7 +1008,7 @@ public class RegisteredServicesCacheTest {
 
         AidGroup aidGroupReceived = mRegisteredServicesCache.getAidGroupForService(USER_ID,
                 SERVICE_UID, WALLET_HOLDER_SERVICE_COMPONENT, CardEmulation.CATEGORY_OTHER);
-        Assert.assertEquals(aidGroup, aidGroupReceived);
+        assertEquals(aidGroup, aidGroupReceived);
     }
 
     @Test
@@ -1039,7 +1018,7 @@ public class RegisteredServicesCacheTest {
         mRegisteredServicesCache.initialize();
         ComponentName wrongComponentName = new ComponentName("test","com.wrong.class");
 
-        Assert.assertFalse(mRegisteredServicesCache.removeAidGroupForService(
+        assertFalse(mRegisteredServicesCache.removeAidGroupForService(
                 USER_ID, SERVICE_UID, wrongComponentName, CardEmulation.CATEGORY_PAYMENT));
     }
 
@@ -1049,7 +1028,7 @@ public class RegisteredServicesCacheTest {
                 mDynamicSettingsFile, mOtherSettingsFile, mServiceParser, mRoutingOptionManager);
         mRegisteredServicesCache.initialize();
 
-        Assert.assertFalse(mRegisteredServicesCache.removeAidGroupForService(USER_ID,
+        assertFalse(mRegisteredServicesCache.removeAidGroupForService(USER_ID,
                 3, WALLET_HOLDER_SERVICE_COMPONENT, CardEmulation.CATEGORY_PAYMENT));
     }
 
@@ -1072,21 +1051,21 @@ public class RegisteredServicesCacheTest {
         when(serviceInfo.removeDynamicAidGroupForCategory(eq(CardEmulation.CATEGORY_PAYMENT)))
                 .thenReturn(true);
 
-        Assert.assertTrue(mRegisteredServicesCache.removeAidGroupForService(USER_ID,
+        assertTrue(mRegisteredServicesCache.removeAidGroupForService(USER_ID,
                 SERVICE_UID, WALLET_HOLDER_SERVICE_COMPONENT, CardEmulation.CATEGORY_PAYMENT));
 
         verify(serviceInfo).removeDynamicAidGroupForCategory(eq(CardEmulation.CATEGORY_PAYMENT));
-        Assert.assertFalse(mRegisteredServicesCache.mUserServices.get(USER_ID)
+        assertFalse(mRegisteredServicesCache.mUserServices.get(USER_ID)
                 .dynamicSettings.get(WALLET_HOLDER_SERVICE_COMPONENT)
                 .aidGroups.containsKey(CardEmulation.CATEGORY_PAYMENT));
         // Verify that the callback is called with properly installed and filtered services.
         verify(mCallback).onServicesUpdated(eq(USER_ID), mApduServiceListCaptor.capture(),
                 eq(true));
         List<ApduServiceInfo> apduServiceInfos = mApduServiceListCaptor.getValue();
-        Assert.assertEquals(2, apduServiceInfos.size());
-        Assert.assertEquals(ANOTHER_SERVICE_COMPONENT, apduServiceInfos.get(0)
+        assertEquals(2, apduServiceInfos.size());
+        assertEquals(ANOTHER_SERVICE_COMPONENT, apduServiceInfos.get(0)
                 .getComponent());
-        Assert.assertEquals(WALLET_HOLDER_SERVICE_COMPONENT, apduServiceInfos.get(1)
+        assertEquals(WALLET_HOLDER_SERVICE_COMPONENT, apduServiceInfos.get(1)
                 .getComponent());
         // Verify that dynamic settings file is updated
         InputStream dynamicSettingsMockIs = mockFileOutputStream.toInputStream();
@@ -1097,13 +1076,13 @@ public class RegisteredServicesCacheTest {
         Map<Integer, List<Pair<ComponentName, RegisteredServicesCache.DynamicSettings>>>
                 readDynamicSettingsFromFile = RegisteredServicesCache
                 .readDynamicSettingsFromFile(dynamicSettingsFile);
-        Assert.assertFalse(readDynamicSettingsFromFile.isEmpty());
-        Assert.assertTrue(readDynamicSettingsFromFile.containsKey(USER_ID));
+        assertFalse(readDynamicSettingsFromFile.isEmpty());
+        assertTrue(readDynamicSettingsFromFile.containsKey(USER_ID));
         RegisteredServicesCache.DynamicSettings dynamicSettings
                 = readDynamicSettingsFromFile.get(USER_ID).get(0).second;
-        Assert.assertEquals(ANOTHER_SERVICE_COMPONENT,
+        assertEquals(ANOTHER_SERVICE_COMPONENT,
                 readDynamicSettingsFromFile.get(USER_ID).get(0).first);
-        Assert.assertFalse(dynamicSettings.aidGroups.containsKey(CardEmulation.CATEGORY_PAYMENT));
+        assertFalse(dynamicSettings.aidGroups.containsKey(CardEmulation.CATEGORY_PAYMENT));
     }
     @Test
     public void testHandlePackageRemoved() {
diff --git a/tests/unit/src/com/android/nfc/cardemulation/RegisteredT3tIdentifiersCacheTest.java b/tests/unit/src/com/android/nfc/cardemulation/RegisteredT3tIdentifiersCacheTest.java
index dd90fb6f..b9f6f1eb 100644
--- a/tests/unit/src/com/android/nfc/cardemulation/RegisteredT3tIdentifiersCacheTest.java
+++ b/tests/unit/src/com/android/nfc/cardemulation/RegisteredT3tIdentifiersCacheTest.java
@@ -16,6 +16,11 @@
 
 package com.android.nfc.cardemulation;
 
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.assertNotNull;
+import static org.junit.Assert.assertNull;
+import static org.junit.Assert.assertTrue;
 import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.anyString;
 import static org.mockito.Mockito.never;
@@ -39,7 +44,6 @@ import java.util.List;
 import java.util.Locale;
 
 import org.junit.After;
-import org.junit.Assert;
 import org.junit.Before;
 import org.junit.Test;
 import org.junit.runner.RunWith;
@@ -109,8 +113,8 @@ public class RegisteredT3tIdentifiersCacheTest {
   public void testConstructor() {
     cache = new RegisteredT3tIdentifiersCache(mContext);
 
-    Assert.assertEquals(cache.mContext, mContext);
-    Assert.assertNotNull(cache.mRoutingManager);
+    assertEquals(mContext, cache.mContext);
+    assertNotNull(cache.mRoutingManager);
   }
 
   @Test
@@ -122,7 +126,7 @@ public class RegisteredT3tIdentifiersCacheTest {
 
     boolean result = firstIdentifier.equals(secondIdentifier);
 
-    Assert.assertTrue(result);
+    assertTrue(result);
   }
 
   @Test
@@ -133,7 +137,7 @@ public class RegisteredT3tIdentifiersCacheTest {
 
     boolean result = firstIdentifier.equals(secondIdentifier);
 
-    Assert.assertFalse(result);
+    assertFalse(result);
   }
 
   @Test
@@ -143,7 +147,7 @@ public class RegisteredT3tIdentifiersCacheTest {
 
     NfcFServiceInfo result = cache.resolveNfcid2(NFCID2);
 
-    Assert.assertEquals(result, mNfcFServiceInfo);
+    assertEquals(mNfcFServiceInfo, result);
   }
 
   @Test
@@ -167,13 +171,13 @@ public class RegisteredT3tIdentifiersCacheTest {
     verify(mRoutingManager, times(2)).configureRouting(identifiersCaptor.capture());
     List<T3tIdentifier> firstList = identifiersCaptor.getAllValues().get(0);
     List<T3tIdentifier> secondList = identifiersCaptor.getAllValues().get(1);
-    Assert.assertEquals(1, firstList.size());
+    assertEquals(1, firstList.size());
     T3tIdentifier identifier = firstList.get(0);
-    Assert.assertEquals(SYSTEM_CODE, identifier.systemCode);
-    Assert.assertEquals(NFCID2, identifier.nfcid2);
-    Assert.assertEquals(T3TPMM, identifier.t3tPmm);
-    Assert.assertEquals(1, secondList.size());
-    Assert.assertEquals(secondList.get(0), identifier);
+    assertEquals(SYSTEM_CODE, identifier.systemCode);
+    assertEquals(NFCID2, identifier.nfcid2);
+    assertEquals(T3TPMM, identifier.t3tPmm);
+    assertEquals(1, secondList.size());
+    assertEquals(secondList.get(0), identifier);
   }
 
   @Test
@@ -183,8 +187,8 @@ public class RegisteredT3tIdentifiersCacheTest {
 
     cache.onServicesUpdated(USER_ID, serviceList);
 
-    Assert.assertEquals(1, cache.mUserNfcFServiceInfo.size());
-    Assert.assertEquals(serviceList, cache.mUserNfcFServiceInfo.get(USER_ID));
+    assertEquals(1, cache.mUserNfcFServiceInfo.size());
+    assertEquals(serviceList, cache.mUserNfcFServiceInfo.get(USER_ID));
   }
 
   /**
@@ -200,8 +204,8 @@ public class RegisteredT3tIdentifiersCacheTest {
 
     cache.onEnabledForegroundNfcFServiceChanged(USER_ID, /* component = */ null);
 
-    Assert.assertEquals(USER_ID, cache.mEnabledForegroundServiceUserId);
-    Assert.assertNull(cache.mEnabledForegroundService);
+    assertEquals(USER_ID, cache.mEnabledForegroundServiceUserId);
+    assertNull(cache.mEnabledForegroundService);
     verify(mRoutingManager, never()).configureRouting(any());
   }
 
@@ -218,10 +222,10 @@ public class RegisteredT3tIdentifiersCacheTest {
 
     cache.onEnabledForegroundNfcFServiceChanged(USER_ID, /* component = */ null);
 
-    Assert.assertNull(cache.mEnabledForegroundService);
-    Assert.assertEquals(-1, cache.mEnabledForegroundServiceUserId);
+    assertNull(cache.mEnabledForegroundService);
+    assertEquals(-1, cache.mEnabledForegroundServiceUserId);
     verify(mRoutingManager).configureRouting(identifiersCaptor.capture());
-    Assert.assertTrue(identifiersCaptor.getValue().isEmpty());
+    assertTrue(identifiersCaptor.getValue().isEmpty());
   }
 
   /**
@@ -238,14 +242,14 @@ public class RegisteredT3tIdentifiersCacheTest {
 
     cache.onEnabledForegroundNfcFServiceChanged(USER_ID, NON_PAYMENT_SERVICE_COMPONENT);
 
-    Assert.assertEquals(NON_PAYMENT_SERVICE_COMPONENT, cache.mEnabledForegroundService);
-    Assert.assertEquals(USER_ID, cache.mEnabledForegroundServiceUserId);
+    assertEquals(NON_PAYMENT_SERVICE_COMPONENT, cache.mEnabledForegroundService);
+    assertEquals(USER_ID, cache.mEnabledForegroundServiceUserId);
     verify(mRoutingManager).configureRouting(identifiersCaptor.capture());
-    Assert.assertEquals(1, identifiersCaptor.getValue().size());
+    assertEquals(1, identifiersCaptor.getValue().size());
     T3tIdentifier identifier = identifiersCaptor.getValue().get(0);
-    Assert.assertEquals(SYSTEM_CODE, identifier.systemCode);
-    Assert.assertEquals(NFCID2, identifier.nfcid2);
-    Assert.assertEquals(T3TPMM, identifier.t3tPmm);
+    assertEquals(SYSTEM_CODE, identifier.systemCode);
+    assertEquals(NFCID2, identifier.nfcid2);
+    assertEquals(T3TPMM, identifier.t3tPmm);
   }
 
   /**
@@ -261,8 +265,8 @@ public class RegisteredT3tIdentifiersCacheTest {
 
     cache.onEnabledForegroundNfcFServiceChanged(USER_ID, NON_PAYMENT_SERVICE_COMPONENT);
 
-    Assert.assertEquals(WALLET_HOLDER_SERVICE_COMPONENT, cache.mEnabledForegroundService);
-    Assert.assertEquals(USER_ID, cache.mEnabledForegroundServiceUserId);
+    assertEquals(WALLET_HOLDER_SERVICE_COMPONENT, cache.mEnabledForegroundService);
+    assertEquals(USER_ID, cache.mEnabledForegroundServiceUserId);
     verify(mRoutingManager, never()).configureRouting(any());
   }
 
@@ -272,7 +276,7 @@ public class RegisteredT3tIdentifiersCacheTest {
 
     cache.onNfcEnabled();
 
-    Assert.assertTrue(cache.mNfcEnabled);
+    assertTrue(cache.mNfcEnabled);
   }
 
   @Test
@@ -285,10 +289,10 @@ public class RegisteredT3tIdentifiersCacheTest {
 
     cache.onNfcDisabled();
 
-    Assert.assertFalse(cache.mNfcEnabled);
-    Assert.assertTrue(cache.mForegroundT3tIdentifiersCache.isEmpty());
-    Assert.assertNull(cache.mEnabledForegroundService);
-    Assert.assertEquals(-1, cache.mEnabledForegroundServiceUserId);
+    assertFalse(cache.mNfcEnabled);
+    assertTrue(cache.mForegroundT3tIdentifiersCache.isEmpty());
+    assertNull(cache.mEnabledForegroundService);
+    assertEquals(-1, cache.mEnabledForegroundServiceUserId);
     verify(mRoutingManager).onNfccRoutingTableCleared();
   }
 
@@ -302,11 +306,11 @@ public class RegisteredT3tIdentifiersCacheTest {
 
     cache.onUserSwitched();
 
-    Assert.assertTrue(cache.mForegroundT3tIdentifiersCache.isEmpty());
-    Assert.assertNull(cache.mEnabledForegroundService);
-    Assert.assertEquals(-1, cache.mEnabledForegroundServiceUserId);
+    assertTrue(cache.mForegroundT3tIdentifiersCache.isEmpty());
+    assertNull(cache.mEnabledForegroundService);
+    assertEquals(-1, cache.mEnabledForegroundServiceUserId);
     verify(mRoutingManager).configureRouting(identifiersCaptor.capture());
-    Assert.assertTrue(identifiersCaptor.getValue().isEmpty());
+    assertTrue(identifiersCaptor.getValue().isEmpty());
   }
 
   @Test
diff --git a/tests/unit/src/com/android/nfc/cardemulation/RoutingOptionManagerTest.java b/tests/unit/src/com/android/nfc/cardemulation/RoutingOptionManagerTest.java
index e3872c39..b80e9023 100644
--- a/tests/unit/src/com/android/nfc/cardemulation/RoutingOptionManagerTest.java
+++ b/tests/unit/src/com/android/nfc/cardemulation/RoutingOptionManagerTest.java
@@ -15,6 +15,8 @@
  */
 package com.android.nfc.cardemulation;
 
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertFalse;
 import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.when;
@@ -25,7 +27,6 @@ import com.android.dx.mockito.inline.extended.ExtendedMockito;
 import com.android.nfc.NfcService;
 
 import org.junit.After;
-import org.junit.Assert;
 import org.junit.Before;
 import org.junit.Test;
 import org.junit.runner.RunWith;
@@ -110,12 +111,12 @@ public class RoutingOptionManagerTest {
   public void testConstructor() {
     manager = new TestRoutingOptionManager();
 
-    Assert.assertEquals(DEFAULT_ROUTE, manager.mDefaultRoute);
-    Assert.assertEquals(DEFAULT_ISO_DEP_ROUTE, manager.mDefaultIsoDepRoute);
-    Assert.assertEquals(DEFAULT_OFF_HOST_ROUTE, manager.mDefaultOffHostRoute);
-    Assert.assertEquals(OFF_HOST_UICC, manager.mOffHostRouteUicc);
-    Assert.assertEquals(OFF_HOST_ESE, manager.mOffHostRouteEse);
-    Assert.assertEquals(AID_MATCHING_MODE, manager.mAidMatchingSupport);
+    assertEquals(DEFAULT_ROUTE, manager.mDefaultRoute);
+    assertEquals(DEFAULT_ISO_DEP_ROUTE, manager.mDefaultIsoDepRoute);
+    assertEquals(DEFAULT_OFF_HOST_ROUTE, manager.mDefaultOffHostRoute);
+    assertEquals(OFF_HOST_UICC, manager.mOffHostRouteUicc);
+    assertEquals(OFF_HOST_ESE, manager.mOffHostRouteEse);
+    assertEquals(AID_MATCHING_MODE, manager.mAidMatchingSupport);
   }
 
   @Test
@@ -124,10 +125,9 @@ public class RoutingOptionManagerTest {
 
     manager.overrideDefaultIsoDepRoute(OVERRIDDEN_ISO_DEP_ROUTE);
 
-    Assert.assertEquals(OVERRIDDEN_ISO_DEP_ROUTE, manager.mOverrideDefaultRoute);
-    Assert.assertEquals(OVERRIDDEN_ISO_DEP_ROUTE, manager.mOverrideDefaultIsoDepRoute);
+    assertEquals(OVERRIDDEN_ISO_DEP_ROUTE, manager.getOverrideDefaultIsoDepRoute());
     verify(mNfcService).setIsoDepProtocolRoute(routeCaptor.capture());
-    Assert.assertEquals(routeCaptor.getValue(), Integer.valueOf(OVERRIDDEN_ISO_DEP_ROUTE));
+    assertEquals(Integer.valueOf(OVERRIDDEN_ISO_DEP_ROUTE), routeCaptor.getValue());
   }
 
   @Test
@@ -136,9 +136,18 @@ public class RoutingOptionManagerTest {
 
     manager.overrideDefaultOffHostRoute(OVERRIDDEN_OFF_HOST_ROUTE);
 
-    Assert.assertEquals(OVERRIDDEN_OFF_HOST_ROUTE, manager.mOverrideDefaultOffHostRoute);
-    verify(mNfcService).setTechnologyABRoute(routeCaptor.capture());
-    Assert.assertEquals(routeCaptor.getValue(), Integer.valueOf(OVERRIDDEN_OFF_HOST_ROUTE));
+    assertEquals(OVERRIDDEN_OFF_HOST_ROUTE, manager.getOverrideDefaultOffHostRoute());
+    verify(mNfcService).setTechnologyABFRoute(routeCaptor.capture());
+    assertEquals(Integer.valueOf(OVERRIDDEN_OFF_HOST_ROUTE), routeCaptor.getValue());
+  }
+
+  @Test
+  public void testOverrideDefaulttRoute() {
+    manager = new TestRoutingOptionManager();
+
+    manager.overrideDefaultRoute(OVERRIDDEN_OFF_HOST_ROUTE);
+
+    assertEquals(OVERRIDDEN_OFF_HOST_ROUTE, manager.getOverrideDefaultRoute());
   }
 
   @Test
@@ -148,10 +157,10 @@ public class RoutingOptionManagerTest {
     manager.recoverOverridedRoutingTable();
 
     verify(mNfcService).setIsoDepProtocolRoute(anyInt());
-    verify(mNfcService).setTechnologyABRoute(anyInt());
-    Assert.assertEquals(RoutingOptionManager.ROUTE_UNKNOWN, manager.mOverrideDefaultRoute);
-    Assert.assertEquals(RoutingOptionManager.ROUTE_UNKNOWN, manager.mOverrideDefaultIsoDepRoute);
-    Assert.assertEquals(RoutingOptionManager.ROUTE_UNKNOWN, manager.mOverrideDefaultOffHostRoute);
+    verify(mNfcService).setTechnologyABFRoute(anyInt());
+    assertEquals(RoutingOptionManager.ROUTE_UNKNOWN, manager.mOverrideDefaultRoute);
+    assertEquals(RoutingOptionManager.ROUTE_UNKNOWN, manager.mOverrideDefaultIsoDepRoute);
+    assertEquals(RoutingOptionManager.ROUTE_UNKNOWN, manager.mOverrideDefaultOffHostRoute);
   }
 
   @Test
@@ -166,13 +175,13 @@ public class RoutingOptionManagerTest {
     byte[] offHostRouteEse = manager.getOffHostRouteEse();
     int aidMatchingSupport = manager.getAidMatchingSupport();
 
-    Assert.assertEquals(-1, overrideDefaultRoute);
-    Assert.assertEquals(DEFAULT_ROUTE, defaultRoute);
-    Assert.assertEquals(DEFAULT_ISO_DEP_ROUTE, defaultIsoDepRoute);
-    Assert.assertEquals(DEFAULT_OFF_HOST_ROUTE, defaultOffHostRoute);
-    Assert.assertEquals(offHostRouteUicc, OFF_HOST_UICC);
-    Assert.assertEquals(offHostRouteEse, OFF_HOST_ESE);
-    Assert.assertEquals(AID_MATCHING_MODE, aidMatchingSupport);
+    assertEquals(-1, overrideDefaultRoute);
+    assertEquals(DEFAULT_ROUTE, defaultRoute);
+    assertEquals(DEFAULT_ISO_DEP_ROUTE, defaultIsoDepRoute);
+    assertEquals(DEFAULT_OFF_HOST_ROUTE, defaultOffHostRoute);
+    assertEquals(OFF_HOST_UICC, offHostRouteUicc);
+    assertEquals(OFF_HOST_ESE, offHostRouteEse);
+    assertEquals(AID_MATCHING_MODE, aidMatchingSupport);
   }
 
   @Test
@@ -181,6 +190,6 @@ public class RoutingOptionManagerTest {
 
     boolean result = manager.isRoutingTableOverrided();
 
-    Assert.assertFalse(result);
+    assertFalse(result);
   }
 }
diff --git a/tests/unit/src/com/android/nfc/cardemulation/WalletRoleObserverTest.java b/tests/unit/src/com/android/nfc/cardemulation/WalletRoleObserverTest.java
index bd415fe6..cc35adb9 100644
--- a/tests/unit/src/com/android/nfc/cardemulation/WalletRoleObserverTest.java
+++ b/tests/unit/src/com/android/nfc/cardemulation/WalletRoleObserverTest.java
@@ -16,6 +16,8 @@
 
 package com.android.nfc.cardemulation;
 
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertNull;
 import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.verify;
@@ -32,7 +34,6 @@ import com.google.common.collect.ImmutableList;
 import com.android.nfc.NfcEventLog;
 import com.android.nfc.NfcInjector;
 
-import org.junit.Assert;
 import org.junit.Before;
 import org.junit.Test;
 import org.junit.runner.RunWith;
@@ -89,8 +90,8 @@ public class WalletRoleObserverTest {
         verify(mContext).getMainExecutor();
         verify(mRoleManager).addOnRoleHoldersChangedListenerAsUser(mExecutorCaptor.capture(),any(),
                 mUserHandlerCaptor.capture());
-        Assert.assertEquals(mExecutor, mExecutorCaptor.getValue());
-        Assert.assertEquals(UserHandle.ALL, mUserHandlerCaptor.getValue());
+        assertEquals(mExecutor, mExecutorCaptor.getValue());
+        assertEquals(UserHandle.ALL, mUserHandlerCaptor.getValue());
     }
 
     @Test
@@ -105,9 +106,9 @@ public class WalletRoleObserverTest {
         verify(mRoleManager).isRoleAvailable(mRoleNameCaptor.capture());
         verify(mRoleManager).getRoleHoldersAsUser(mRoleNameCaptor.capture(),
                 mUserHandlerCaptor.capture());
-        Assert.assertEquals(roleHolder, WALLET_ROLE_HOLDER);
-        Assert.assertEquals(RoleManager.ROLE_WALLET, mRoleNameCaptor.getAllValues().get(0));
-        Assert.assertEquals(RoleManager.ROLE_WALLET, mRoleNameCaptor.getAllValues().get(1));
+        assertEquals(WALLET_ROLE_HOLDER, roleHolder);
+        assertEquals(RoleManager.ROLE_WALLET, mRoleNameCaptor.getAllValues().get(0));
+        assertEquals(RoleManager.ROLE_WALLET, mRoleNameCaptor.getAllValues().get(1));
     }
 
     @Test
@@ -116,20 +117,21 @@ public class WalletRoleObserverTest {
 
         String roleHolder = mWalletRoleObserver.getDefaultWalletRoleHolder(USER_ID);
 
-        Assert.assertNull(roleHolder);
+        assertNull(roleHolder);
     }
 
     @Test
     public void testCallbackFiringOnRoleChange_roleWallet() {
         List<String> roleHolders = ImmutableList.of(WALLET_ROLE_HOLDER);
-        when(mRoleManager.getRoleHolders(eq(RoleManager.ROLE_WALLET))).thenReturn(roleHolders);
+        when(mRoleManager.getRoleHoldersAsUser(eq(RoleManager.ROLE_WALLET), eq(USER_HANDLE)))
+                .thenReturn(roleHolders);
         mWalletRoleObserver.mOnRoleHoldersChangedListener
                 .onRoleHoldersChanged(RoleManager.ROLE_WALLET, USER_HANDLE);
 
-        verify(mRoleManager).getRoleHolders(mRoleNameCaptor.capture());
+        verify(mRoleManager).getRoleHoldersAsUser(mRoleNameCaptor.capture(), eq(USER_HANDLE));
         verify(mCallback).onWalletRoleHolderChanged(mRoleHolderCaptor.capture(), eq(USER_ID));
-        Assert.assertEquals(RoleManager.ROLE_WALLET, mRoleNameCaptor.getValue());
-        Assert.assertEquals(WALLET_ROLE_HOLDER, mRoleHolderCaptor.getValue());
+        assertEquals(RoleManager.ROLE_WALLET, mRoleNameCaptor.getValue());
+        assertEquals(WALLET_ROLE_HOLDER, mRoleHolderCaptor.getValue());
     }
 
     @Test
@@ -152,9 +154,9 @@ public class WalletRoleObserverTest {
         verify(mRoleManager).getRoleHoldersAsUser(mRoleNameCaptor.capture(),
                 mUserHandlerCaptor.capture());
         verify(mCallback).onWalletRoleHolderChanged(mRoleHolderCaptor.capture(), eq(USER_ID));
-        Assert.assertEquals(WALLET_ROLE_HOLDER, mRoleHolderCaptor.getValue());
-        Assert.assertEquals(RoleManager.ROLE_WALLET, mRoleNameCaptor.getAllValues().get(0));
-        Assert.assertEquals(RoleManager.ROLE_WALLET, mRoleNameCaptor.getAllValues().get(1));
+        assertEquals(WALLET_ROLE_HOLDER, mRoleHolderCaptor.getValue());
+        assertEquals(RoleManager.ROLE_WALLET, mRoleNameCaptor.getAllValues().get(0));
+        assertEquals(RoleManager.ROLE_WALLET, mRoleNameCaptor.getAllValues().get(1));
     }
 
 }
diff --git a/tests/unit/src/com/android/nfc/wlc/NfcChargingTest.java b/tests/unit/src/com/android/nfc/wlc/NfcChargingTest.java
new file mode 100644
index 00000000..d9b9486c
--- /dev/null
+++ b/tests/unit/src/com/android/nfc/wlc/NfcChargingTest.java
@@ -0,0 +1,181 @@
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
+package com.android.nfc.wlc;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.assertTrue;
+import static org.mockito.Mockito.mock;
+import static org.mockito.Mockito.verify;
+import static org.mockito.Mockito.when;
+
+import android.app.ActivityManager;
+import android.content.ContentResolver;
+import android.content.Context;
+import android.content.ContextWrapper;
+import android.nfc.NdefMessage;
+import android.nfc.NdefRecord;
+import android.os.UserHandle;
+import android.os.UserManager;
+
+import androidx.test.ext.junit.runners.AndroidJUnit4;
+import androidx.test.platform.app.InstrumentationRegistry;
+
+import com.android.dx.mockito.inline.extended.ExtendedMockito;
+import com.android.nfc.DeviceHost;
+import com.android.nfc.NfcService;
+
+import com.google.common.truth.Truth;
+
+import org.junit.After;
+import org.junit.Assert;
+import org.junit.Before;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.mockito.Mock;
+import org.mockito.MockitoAnnotations;
+import org.mockito.MockitoSession;
+import org.mockito.quality.Strictness;
+
+import java.util.HashMap;
+import java.util.Map;
+
+@RunWith(AndroidJUnit4.class)
+public class NfcChargingTest {
+    private static String TAG = NfcChargingTest.class.getSimpleName();
+    private MockitoSession mStaticMockSession;
+    private NfcCharging mNfcCharging;
+    private Context mContext;
+    @Mock
+    private DeviceHost mDeviceHost;
+
+    @Mock
+    private DeviceHost.TagEndpoint mTagEndpoint;
+
+    @Before
+    public void setUp() throws Exception {
+        mStaticMockSession = ExtendedMockito.mockitoSession()
+                .mockStatic(NfcService.class)
+                .strictness(Strictness.LENIENT)
+                .startMocking();
+        MockitoAnnotations.initMocks(this);
+
+        mContext = new ContextWrapper(
+                InstrumentationRegistry.getInstrumentation().getTargetContext()) {
+        };
+
+
+        InstrumentationRegistry.getInstrumentation().runOnMainSync(
+                () -> mNfcCharging = new NfcCharging(mContext, mDeviceHost));
+        mNfcCharging.TagHandler = mTagEndpoint;
+        Assert.assertNotNull(mNfcCharging);
+    }
+
+    @After
+    public void tearDown() {
+        mStaticMockSession.finishMocking();
+    }
+
+    @Test
+    public void bytesToHex_convertsByteArrayToHexString() {
+        byte[] bytes = new byte[] {0x01, 0x0A, (byte) 0xFF};
+        String hexString = NfcCharging.bytesToHex(bytes);
+        assertThat(hexString).isEqualTo("010AFF");
+    }
+
+    @Test
+    public void testResetInternalValues() {
+        // Set some values to non-default
+        mNfcCharging.mCnt = 10;
+        mNfcCharging.WlcCtl_BatteryLevel = 50;
+        mNfcCharging.WlcDeviceInfo.put(NfcCharging.BatteryLevel, 80);
+
+        mNfcCharging.resetInternalValues();
+
+        assertEquals(-1, mNfcCharging.mCnt);
+        assertEquals(-1, mNfcCharging.WlcCtl_BatteryLevel);
+        assertEquals(-1, mNfcCharging.WlcDeviceInfo.get(NfcCharging.BatteryLevel).intValue());
+    }
+
+    @Test
+    public void testCheckWlcCapMsg_InvalidMessageType() {
+        // Construct an NDEF message with an invalid type
+        byte[] type = NfcCharging.WLCCTL; // Incorrect type
+        byte[] payload = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04,0x05 };
+        NdefRecord record = new NdefRecord(NdefRecord.TNF_WELL_KNOWN, type, new byte[] {}, payload);
+        NdefMessage ndefMessage = new NdefMessage(record);
+
+        assertFalse(mNfcCharging.checkWlcCapMsg(ndefMessage));
+    }
+
+    @Test
+    public void testCheckWlcCtlMsg_ValidMessage() {
+        // Construct a valid WLCCTL NDEF message
+        byte[] type = NfcCharging.WLCCTL;
+        byte[] payload = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 };
+        NdefRecord record = new NdefRecord(NdefRecord.TNF_WELL_KNOWN, type, new byte[] {}, payload);
+        NdefMessage ndefMessage = new NdefMessage(record);
+
+        assertTrue(mNfcCharging.checkWlcCtlMsg(ndefMessage));
+        assertEquals(0, mNfcCharging.WlcCtl_ErrorFlag);
+        assertEquals(0, mNfcCharging.WlcCtl_BatteryStatus);
+    }
+
+    @Test
+    public void testCheckWlcCtlMsg_InvalidMessageType() {
+        // Construct an NDEF message with an invalid type
+        byte[] type = NfcCharging.WLCCAP; // Incorrect type
+        byte[] payload = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 };
+        NdefRecord record = new NdefRecord(NdefRecord.TNF_WELL_KNOWN, type, new byte[] {}, payload);
+        NdefMessage ndefMessage = new NdefMessage(record);
+
+        assertFalse(mNfcCharging.checkWlcCtlMsg(ndefMessage));
+    }
+
+    @Test
+    public void testWLCL_Presence() {
+        NdefMessage ndefMessage = mock(NdefMessage.class);
+        when(mTagEndpoint.getNdef()).thenReturn(ndefMessage);
+        mNfcCharging.mFirstOccurrence = false;
+        NfcService nfcService = mock(NfcService.class);
+        when(NfcService.getInstance()).thenReturn(nfcService);
+        mNfcCharging.HandleWLCState();
+        verify(mNfcCharging.mNdefMessage).getRecords();
+        Assert.assertFalse(mNfcCharging.WLCL_Presence);
+    }
+
+    @Test
+    public void testHandleWlcCap_ModeReq_State6() {
+        NdefMessage ndefMessage = mock(NdefMessage.class);
+        NdefRecord ndefRecord = mock(NdefRecord.class);
+        when(ndefRecord.getType()).thenReturn(NfcCharging.WLCCAP);
+        byte[] payload = {0x01, 0x02, 0x01, 0x10, 0x02, 0x01};
+        when(ndefRecord.getPayload()).thenReturn(payload);
+        NdefRecord[] records = {ndefRecord};
+        when(ndefMessage.getRecords()).thenReturn(records);
+        when(mTagEndpoint.getNdef()).thenReturn(ndefMessage);
+        mNfcCharging.mFirstOccurrence = false;
+        NfcService nfcService = mock(NfcService.class);
+        when(NfcService.getInstance()).thenReturn(nfcService);
+        mNfcCharging.HandleWLCState();
+        Assert.assertEquals(1, mNfcCharging.WLCState);
+    }
+
+}
+
diff --git a/testutils/Android.bp b/testutils/Android.bp
index 83c1ffdf..994bce17 100644
--- a/testutils/Android.bp
+++ b/testutils/Android.bp
@@ -52,7 +52,20 @@ android_test {
 
 python_library {
     name: "pn532-python",
-    srcs: ["pn532/**/*.py"],
+    srcs: [
+        "pn532/**/*.py",
+        "pn532/nfcutils/**/*.py",
+    ],
     host_supported: true,
     device_supported: true,
 }
+
+android_library {
+    name: "pn532-kt",
+    srcs: [
+        "pn532/src/**/*.kt",
+    ],
+    manifest: "src/com/android/nfc/utils/AndroidManifest.xml",
+    sdk_version: "test_current",
+
+}
diff --git a/testutils/__init__.py b/testutils/__init__.py
new file mode 100644
index 00000000..e69de29b
diff --git a/testutils/pn532/nfcutils/__init__.py b/testutils/pn532/nfcutils/__init__.py
new file mode 100644
index 00000000..0639bc66
--- /dev/null
+++ b/testutils/pn532/nfcutils/__init__.py
@@ -0,0 +1,17 @@
+#  Copyright (C) 2024 The Android Open Source Project
+#
+#  Licensed under the Apache License, Version 2.0 (the "License");
+#  you may not use this file except in compliance with the License.
+#  You may obtain a copy of the License at
+#
+#       http://www.apache.org/licenses/LICENSE-2.0
+#
+#  Unless required by applicable law or agreed to in writing, software
+#  distributed under the License is distributed on an "AS IS" BASIS,
+#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+#  See the License for the specific language governing permissions and
+#  limitations under the License.
+
+# Lint as: python3
+
+from .nfcutils import *
diff --git a/testutils/pn532/nfcutils/nfcutils.py b/testutils/pn532/nfcutils/nfcutils.py
new file mode 100644
index 00000000..38ca5829
--- /dev/null
+++ b/testutils/pn532/nfcutils/nfcutils.py
@@ -0,0 +1,158 @@
+#  Copyright (C) 2024 The Android Open Source Project
+#
+#  Licensed under the Apache License, Version 2.0 (the "License");
+#  you may not use this file except in compliance with the License.
+#  You may obtain a copy of the License at
+#
+#       http://www.apache.org/licenses/LICENSE-2.0
+#
+#  Unless required by applicable law or agreed to in writing, software
+#  distributed under the License is distributed on an "AS IS" BASIS,
+#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+#  See the License for the specific language governing permissions and
+#  limitations under the License.
+
+# Lint as: python3
+
+_NUM_POLLING_LOOPS = 50
+
+def create_select_apdu(aid_hex):
+    """Creates a select APDU command for the given AID"""
+    aid_bytes = bytearray.fromhex(aid_hex)
+    return bytearray.fromhex("00A40400") + bytearray([len(aid_bytes)]) + aid_bytes
+
+def poll_and_transact(pn532, command_apdus, response_apdus, custom_frame = None):
+    """Polls for an NFC Type-A tag 50 times. If tag is found, performs a transaction.
+
+    :param pn532: PN532 device
+    :param command_apdus: Command APDUs in transaction
+    :param response_apdus: Response APDUs in transaction
+    :param custom_frame: A custom frame to send as part of te polling loop other than pollA().
+
+    :return: [if tag is found, if transaction was successful]
+    """
+    transacted = False
+    tag = None
+    for i in range(_NUM_POLLING_LOOPS):
+        tag = pn532.poll_a()
+        if tag is not None:
+            transacted = tag.transact(command_apdus, response_apdus)
+            pn532.mute()
+            break
+        if custom_frame is not None:
+            pn532.send_broadcast(bytearray.fromhex(custom_frame))
+        pn532.mute()
+    return tag is not None, transacted
+
+def parse_protocol_params(sak, ats):
+    """
+    Helper function to check whether protocol parameters are properly set.
+    :param sak: SAK byte
+    :param ats: ATS byte
+    :return: whether bits are set correctly, message to print
+    """
+    msg = ""
+    success = True
+    msg += "SAK:\n"
+    if sak & 0x20 != 0:
+        msg += "    (OK) ISO-DEP bit (0x20) is set.\n"
+    else:
+        success = False
+        msg += "    (FAIL) ISO-DEP bit (0x20) is NOT set.\n"
+    if sak & 0x40 != 0:
+        msg += "    (OK) P2P bit (0x40) is set.\n"
+    else:
+        msg += "    (WARN) P2P bit (0x40) is NOT set.\n"
+
+    ta_present = False
+    tb_present = False
+    tc_present = False
+    atsIndex = 0
+    if ats[atsIndex] & 0x40 != 0:
+        msg += "        (OK) T(C) is present (bit 7 is set).\n"
+        tc_present = True
+    else:
+        success = False
+        msg += "        (FAIL) T(C) is not present (bit 7 is NOT set).\n"
+    if ats[atsIndex] and 0x20 != 0:
+        msg += "        (OK) T(B) is present (bit 6 is set).\n"
+        tb_present = True
+    else:
+        success = False
+        msg += "        (FAIL) T(B) is not present (bit 6 is NOT set).\n"
+    if ats[atsIndex] and 0x10 != 0:
+        msg += "        (OK) T(A) is present (bit 5 is set).\n"
+        ta_present = True
+    else:
+        success = False
+        msg += "        (FAIL) T(A) is not present (bit 5 is NOT set).\n"
+    fsc = ats[atsIndex] & 0x0F
+    if fsc > 8:
+        success = False
+        msg += "        (FAIL) FSC " + str(fsc) + " is > 8\n"
+    elif fsc < 2:
+        msg += "        (FAIL EMVCO) FSC " + str(fsc) + " is < 2\n"
+    else:
+        msg += "        (OK) FSC = " + str(fsc) + "\n"
+
+    atsIndex += 1
+    if ta_present:
+        msg += "    TA: 0x" + str(ats[atsIndex] & 0xff) + "\n"
+        if ats[atsIndex] & 0x80 != 0:
+            msg += "        (OK) bit 8 set, indicating only same bit rate divisor.\n"
+        else:
+            msg += "        (FAIL EMVCO) bit 8 NOT set, indicating support for asymmetric bit rate divisors. EMVCo requires bit 8 set.\n"
+        if ats[atsIndex] & 0x70 != 0:
+            msg += "        (FAIL EMVCO) EMVCo requires bits 7 to 5 set to 0.\n"
+        else:
+            msg += "        (OK) bits 7 to 5 indicating only 106 kbit/s L->P supported.\n"
+        if ats[atsIndex] & 0x7 != 0:
+            msg += "        (FAIL EMVCO) EMVCo requires bits 3 to 1 set to 0.\n"
+        else:
+            msg += "        (OK) bits 3 to 1 indicating only 106 kbit/s P->L supported.\n"
+        atsIndex += 1
+
+    if tb_present:
+        msg += "    TB: 0x" + str(ats[3] & 0xFF) + "\n"
+        fwi = (ats[atsIndex] & 0xF0) >> 4
+        if fwi > 8:
+            msg += "        (FAIL) FWI=" + str(fwi) + ", should be <= 8\n"
+        elif fwi == 8:
+            msg += "        (FAIL EMVCO) FWI=" + str(fwi) + ", EMVCo requires <= 7\n"
+        else:
+            msg += "        (OK) FWI=" + str(fwi) + "\n"
+        sfgi = ats[atsIndex] & 0x0F
+        if sfgi > 8:
+            success = False
+            msg += "        (FAIL) SFGI=" + str(sfgi) + ", should be <= 8\n"
+        else:
+            msg += "        (OK) SFGI=" + str(sfgi) + "\n"
+        atsIndex += 1
+    if tc_present:
+        msg += "    TC: 0x" + str(ats[atsIndex] & 0xFF) + "\n"
+        nadSupported = ats[atsIndex] & 0x01 != 0
+        if nadSupported:
+            success = False
+            msg += "        (FAIL) NAD bit is not allowed to be set.\n"
+        else:
+            msg += "        (OK) NAD bit is not set.\n"
+        atsIndex += 1
+        if atsIndex + 1 < len(ats):
+            historical_bytes = len(ats) - atsIndex
+            msg +=  "\n(OK) Historical bytes: " + hexlify(historical_bytes).decode()
+    return success, msg
+
+def get_apdus(nfc_emulator, service_name):
+    """
+    Gets apdus for a given service.
+    :param nfc_emulator: emulator snippet.
+    :param service_name: Service name of APDU sequence to fetch.
+    :return: [command APDU byte array, response APDU byte array]
+    """
+    command_apdus = nfc_emulator.getCommandApdus(service_name)
+    response_apdus = nfc_emulator.getResponseApdus(service_name)
+    return [bytearray.fromhex(apdu) for apdu in command_apdus], [
+        (bytearray.fromhex(apdu) if apdu != "*" else apdu) for apdu in response_apdus]
+
+def to_byte_array(apdu_array):
+    return [bytearray.fromhex(apdu) for apdu in apdu_array]
diff --git a/testutils/pn532/pn532.py b/testutils/pn532/pn532.py
index c8af4b7a..7c8d9a27 100644
--- a/testutils/pn532/pn532.py
+++ b/testutils/pn532/pn532.py
@@ -29,7 +29,7 @@ IN_COMMUNICATE_THRU = 0x42
 IN_LIST_PASSIVE_TARGET = 0x4A
 WRITE_REGISTER = 0x08
 LONG_PREAMBLE = bytearray(20)
-
+TG_INIT_AS_TARGET = 0x8C
 
 def crc16a(data):
     w_crc = 0x6363
@@ -63,7 +63,7 @@ class PN532:
             },
         )
         self.log.debug("Serial port: %s", path)
-        self.device = serial.Serial(path, 115200, timeout=0.1)
+        self.device = serial.Serial(path, 115200, timeout=0.5)
 
         self.device.flush()
         self.device.write(LONG_PREAMBLE + bytearray.fromhex("0000ff00ff00"))
@@ -150,6 +150,50 @@ class PN532:
 
         return tag.TypeATag(self, target_id, sense_res, sel_res, nfcid, ats)
 
+    def initialize_target_mode(self):
+        """Configures the PN532 as target."""
+        self.log.debug("Initializing target mode")
+        self.send_frame(
+            self.construct_frame([TG_INIT_AS_TARGET,
+                                  0x05, #Mode
+                                  0x04, #SENS_RES (2 bytes)
+                                  0x00,
+                                  0x12, #nfcid1T (3 BYTES)
+                                  0x34,
+                                  0x56,
+                                  0x20, #SEL_RES
+                                  0x00, #FeliCAParams[] (18 bytes)
+                                  0x00,
+                                  0x00,
+                                  0x00,
+                                  0x00,
+                                  0x00,
+                                  0x00,
+                                  0x00,
+                                  0x00,
+                                  0x00,
+                                  0x00,
+                                  0x00,
+                                  0x00,
+                                  0x00,
+                                  0x00,
+                                  0x00,
+                                  0x00,
+                                  0x00,
+                                  0x00,#NFCID3T[] (10 bytes)
+                                  0x00,
+                                  0x00,
+                                  0x00,
+                                  0x00,
+                                  0x00,
+                                  0x00,
+                                  0x00,
+                                  0x00,
+                                  0x00,
+                                  0x00, #LEN Gt
+                                  0x00, #LEN Tk
+                                  ]))
+
     def poll_b(self):
         """Attempts to detect target for NFC type B."""
         self.log.debug("Polling B")
@@ -159,6 +203,29 @@ class PN532:
         if not rsp:
             raise RuntimeError("No response for send poll_b frame.")
 
+        if rsp[0] != IN_LIST_PASSIVE_TARGET + 1:
+            self.log.error("Got unexpected command code in response")
+        del rsp[0]
+
+        afi = rsp[0]
+
+        deselect_command = 0xC2
+        self.send_broadcast(bytearray(deselect_command))
+
+        wupb_command = [0x05, afi, 0x08]
+        self.send_frame(
+            self.construct_frame([WRITE_REGISTER, 0x63, 0x3D, 0x00])
+        )
+        rsp = self.send_frame(
+            self.construct_frame(
+                [IN_COMMUNICATE_THRU] + list(with_crc16a(wupb_command))
+            )
+        )
+        if not rsp:
+            raise RuntimeError("No response for WUPB command")
+
+        return tag.TypeBTag(self, 0x03, rsp)
+
     def send_broadcast(self, broadcast):
         """Emits broadcast frame with CRC. This should be called after poll_a()."""
         self.log.debug("Sending broadcast %s", hexlify(broadcast).decode())
@@ -202,8 +269,8 @@ class PN532:
             0x00,
             0x00,
             0xFF,
-            len(data) + 1,
-            (~(len(data) + 1) & 0xFF) + 0x01,
+            (len(data) + 1) & 0xFF,
+            ((~(len(data) + 1) & 0xFF) + 0x01) & 0xFF,
             0xD4,
             ]
         data_sum = 0xD4
@@ -212,20 +279,24 @@ class PN532:
         for b in data:
             data_sum += b
             frame.append(b)
-        frame.append((~data_sum & 0xFF) + 0x01)  # Data checksum
-        frame.append(0x00)  # Postamble
+        frame.append(((~data_sum & 0xFF) + 0x01) & 0xFF)  # Data checksum
 
+        frame.append(0x00)  # Postamble
         self.log.debug("Constructed frame " + hexlify(bytearray(frame)).decode())
 
         return bytearray(frame)
 
-    def send_frame(self, frame, timeout=0.1):
+    def send_frame(self, frame, timeout=0.5):
         """
         Writes a frame to the device and returns the response.
         """
         self.device.write(frame)
         return self.get_device_response(timeout)
 
+    def reset_buffers(self):
+        self.device.reset_input_buffer()
+        self.device.reset_output_buffer()
+
     def get_device_response(self, timeout=0.5):
         """
         Confirms we get an ACK frame from device, reads response frame, and writes ACK.
@@ -277,7 +348,7 @@ class PN532:
                     "Unexpected postamble byte when performing read, got %02x", frame[4]
                 )
 
-        self.device.timeout = 0.1
+        self.device.timeout = 0.5
         self.device.write(
             bytearray.fromhex("0000ff00ff00")
         )  # send ACK frame, there is no response.
diff --git a/testutils/pn532/src/com/android/nfc/pn532/AndroidManifest.xml b/testutils/pn532/src/com/android/nfc/pn532/AndroidManifest.xml
new file mode 100644
index 00000000..00cd1ddd
--- /dev/null
+++ b/testutils/pn532/src/com/android/nfc/pn532/AndroidManifest.xml
@@ -0,0 +1,22 @@
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
+<!-- Stub AndroidManifest.xml to build resources -->
+<manifest xmlns:android="http://schemas.android.com/apk/res/android"
+    package="com.android.nfc.pn532">
+    <uses-sdk android:targetSdkVersion="35" android:minSdkVersion="35"/>
+    <application />
+</manifest>
diff --git a/testutils/pn532/src/com/android/nfc/pn532/PN532.kt b/testutils/pn532/src/com/android/nfc/pn532/PN532.kt
new file mode 100644
index 00000000..7a84d7cd
--- /dev/null
+++ b/testutils/pn532/src/com/android/nfc/pn532/PN532.kt
@@ -0,0 +1,332 @@
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
+package com.android.nfc.pn532
+
+import android.hardware.usb.UsbDevice
+import android.hardware.usb.UsbDeviceConnection
+import android.util.Log
+
+/**
+ * Handles communication with PN532 given a UsbDevice and UsbDeviceConnection object. Relevant
+ * protocols of device are located at https://www.nxp.com/docs/en/user-guide/141520.pdf
+ */
+class PN532(val device: UsbDevice, val connection: UsbDeviceConnection) {
+    private val transportLayer: TransportLayer
+
+    init {
+        Log.d(TAG, "Starting initialization")
+        transportLayer = TransportLayer(device, connection)
+
+        // Wake up device and send initial configs
+        transportLayer.write(LONG_PREAMBLE + ACK)
+        sendFrame(constructFrame(byteArrayOf(SAM_CONFIGURATION, 0x01, 0x00)))
+        sendFrame(constructFrame(byteArrayOf(RF_CONFIGURATION, 0x05, 0x01, 0x00, 0x01)))
+    }
+
+    /** Polls for NFC Type-A. Returns tag if discovered. */
+    fun pollA(): TypeATag? {
+        Log.d(TAG, "Polling A")
+        val rsp =
+            sendFrame(constructFrame(byteArrayOf(IN_LIST_PASSIVE_TARGET, 0X01, 0X00)), timeout = 5000)
+        if (rsp == null || rsp.size == 0) return null
+        if (rsp[0] != (IN_LIST_PASSIVE_TARGET + 1).toByte()) {
+            Log.e(TAG, "Got unexpected command code in response")
+            return null
+        }
+        val targetData = rsp.drop(1).toByteArray()
+        if (targetData.size < 6 || targetData[0] == 0.toByte()) {
+            Log.d(TAG, "No tag found")
+            return null
+        }
+        Log.d(TAG, "Tag found. Response: " + rsp.toHex())
+
+        // Page 116 of https://www.nxp.com/docs/en/user-guide/141520.pdf for response format info
+        val targetId = targetData[1]
+        val senseRes = targetData.slice(2..3).toByteArray()
+        val selRes = targetData[4]
+        val nfcIdLen = targetData[5]
+
+        if (6 + nfcIdLen > targetData.size) {
+            Log.e(
+                TAG,
+                "Corrupt data - expected remaining size of list to be at least: " +
+                        nfcIdLen +
+                        " , but was " +
+                        (targetData.size - 6),
+            )
+            return null
+        }
+
+        val nfcIdList = targetData.slice(6..6 + nfcIdLen - 1).toByteArray()
+        val ats = targetData.drop(6 + nfcIdLen).toByteArray()
+        if (ats.size == 0) {
+            Log.e(TAG, "Corrupt data - expected ATS information")
+            return null
+        }
+        val atsLen = ats[0]
+        val atsList = ats.drop(1).toByteArray()
+        if (atsList.size != atsLen.toInt() - 1) {
+            Log.e(
+                TAG,
+                "Corrupt data - expected list of size " +
+                        (atsLen.toInt() - 1) +
+                        " , but was " +
+                        (atsList.size),
+            )
+            return null
+        }
+
+        return TypeATag(this, targetId, senseRes, selRes, nfcIdList, atsList)
+    }
+
+    /** Polls for NFC Type-B */
+    fun pollB() {
+        Log.d(TAG, "Polling B")
+        sendFrame(constructFrame(byteArrayOf(IN_LIST_PASSIVE_TARGET, 0x01, 0x03, 0x00)))
+    }
+
+    /** Emits broadcast frame with CRC. Call this after pollA() to send a custom frame */
+    fun sendBroadcast(broadcast: ByteArray) {
+        Log.d(TAG, "sendBroadcast: " + broadcast.toHex())
+        sendFrame(constructFrame(byteArrayOf(WRITE_REGISTER, 0X63, 0X3D, 0X00)))
+        sendFrame(constructFrame(byteArrayOf(IN_COMMUNICATE_THRU) + withCrc16a(broadcast)))
+    }
+
+    /** Send command to PN-532 and receive response. */
+    fun transceive(data: ByteArray): ByteArray? {
+        Log.d(TAG, "Transceiving: " + data.toHex())
+        var response = sendFrame(constructFrame(byteArrayOf(IN_DATA_EXCHANGE) + data))
+        if (response == null) return null
+        Log.d(TAG, "Response: " + response.toHex())
+
+        if (response[0] != (IN_DATA_EXCHANGE + 1).toByte()) {
+            Log.e(TAG, "Got unexpected command code in response")
+        }
+        if (response[1] != 0.toByte()) {
+            Log.e(TAG, "Got error exchanging data")
+            return null
+        }
+        return response.drop(2).toByteArray()
+    }
+
+    /** Mute reader. Should be called after each polling loop. */
+    fun mute() {
+        Log.d(TAG, "Muting PN532")
+        sendFrame(constructFrame(byteArrayOf(RF_CONFIGURATION, 0x01, 0x02)))
+    }
+
+    private fun sendFrame(frame: ByteArray, timeout: Long = 500.toLong()): ByteArray? {
+        transportLayer.write(frame)
+        return getDeviceResponse(timeout)
+    }
+
+    private fun isAckFrame(frame: ByteArray): Boolean {
+        return frame.toHex().contentEquals(ACK.toHex())
+    }
+
+    private fun getDeviceResponse(timeoutMs: Long = 500.toLong()): ByteArray? {
+        // First response from device should be ACK frame
+        var data = transportLayer.read(timeoutMs, numBytes = 255)
+        if (data == null || data.size < 6) return null
+
+        val firstFrame = data.slice(0..5).toByteArray()
+        if (!isAckFrame(firstFrame)) {
+            Log.w(TAG, "Did not get ack frame - got " + firstFrame.toHex())
+            return null
+        } else {
+            Log.d(TAG, "Got ack frame")
+        }
+
+        // Response will either be appended to first read, or will require an additional read
+        var responseFrame: ByteArray? = data.drop(6).toByteArray()
+
+        // Some instances require a second read of data
+        var secondRead = false
+        if (responseFrame?.size == 0) {
+            responseFrame = transportLayer.read(timeoutMs, numBytes = 255)
+            secondRead = true
+        }
+        if (responseFrame == null || responseFrame.size == 0) {
+            Log.d(TAG, "No additional data")
+            return null
+        }
+        if (responseFrame.size < 6) {
+            Log.w(TAG, "Expected at least 6 bytes of response data. Got " + responseFrame.size)
+            return null
+        }
+
+        if (isAckFrame(responseFrame)) {
+            Log.d(TAG, "Got another ack frame")
+            return null
+        }
+
+        if (!responseFrame.slice(0..2).toByteArray().toHex().contentEquals("0000ff")) {
+            Log.e(
+                TAG,
+                "Unexpected start to frame - got " +
+                        responseFrame.slice(0..2).toByteArray().toHex() +
+                        ", expected " +
+                        "0000ff",
+            )
+        } else {
+            Log.d(TAG, "Correct start to frame")
+        }
+
+        val dataLength = responseFrame[3]
+        val lengthChecksum = responseFrame[4]
+
+        if ((lengthChecksum + dataLength) and 0xFF != 0) {
+            Log.e(
+                TAG,
+                "Frame failed length checksum. lengthChecksum: " +
+                        lengthChecksum +
+                        ", dataLength: " +
+                        dataLength +
+                        ", responseFrame: " +
+                        responseFrame.toHex() +
+                        ", data: " +
+                        data,
+            )
+        }
+
+        val tfi = responseFrame[5]
+        if (tfi != 0xD5.toByte()) {
+            Log.e(TAG, "Unexpected TFI Byte: Got " + tfi + ", expected 0xD5")
+        }
+
+        var dataPacket: ByteArray?
+        var dataCheckSum: Byte
+        var postAmble: Byte
+        if (secondRead) {
+            dataPacket = responseFrame.slice(6..responseFrame.size - 3).toByteArray()
+            dataCheckSum = responseFrame[responseFrame.size - 2]
+            postAmble = responseFrame[responseFrame.size - 1]
+        } else {
+            dataPacket = data.slice(12..data.size - 3).toByteArray()
+            dataCheckSum = data[data.size - 2]
+            postAmble = data[data.size - 1]
+        }
+
+        if (dataPacket.size != 0 && dataPacket.size != dataLength.toInt() - 1) {
+            Log.e(
+                TAG,
+                "Unexpected data packet size: Got " +
+                        dataPacket.size +
+                        ", expected " +
+                        (dataLength.toInt() - 1).toString() +
+                        ",",
+            )
+        }
+
+        val sum = dataPacket.sum()
+
+        if ((tfi + sum + dataCheckSum) and 0xFF != 0) {
+            Log.e(
+                TAG,
+                "Frame failed data checksum. TFI: " +
+                        tfi +
+                        ", sum: " +
+                        sum +
+                        ", secondFrame: " +
+                        responseFrame.toHex(),
+            )
+        }
+
+        if (postAmble != 0x00.toByte()) {
+            if (tfi != 0xD5.toByte()) {
+                Log.e(TAG, "Unexpected postamble byte when performing read - got " + responseFrame[4])
+            }
+            return null
+        }
+
+        transportLayer.write(ACK)
+        Log.d(TAG, "Received frame - " + responseFrame.toHex() + ", dataPacket: " + dataPacket.toHex())
+
+        return dataPacket
+    }
+
+    fun ByteArray.sum(): Byte {
+        var sum = 0
+        for (byte in this) {
+            sum += byte
+        }
+        return sum.toByte()
+    }
+
+    private fun crc16a(data: ByteArray): ByteArray {
+        var w_crc = 0x6363
+        for (byte in data) {
+            var newByte = byte.toInt() xor (w_crc and 0xFF).toInt()
+            newByte = (newByte xor newByte shl 4) and 0xFF
+            w_crc = ((w_crc shr 8) xor (newByte shl 8) xor (newByte shl 3) xor (newByte shr 4)) and 0xFF
+        }
+
+        return byteArrayOf((w_crc and 0xFF).toByte(), ((w_crc shr 8) and 0xFF).toByte())
+    }
+
+    private fun withCrc16a(data: ByteArray): ByteArray {
+        return data + crc16a(data)
+    }
+
+    private fun constructFrame(data: ByteArray): ByteArray {
+        var frame: ByteArray =
+            byteArrayOf(
+                0x00,
+                0x00,
+                0xFF.toByte(),
+                (data.size + 1).toByte(),
+                ((data.size + 1 and 0xFF).inv() + 0x01).toByte(),
+                0xD4.toByte(),
+            )
+        var sum = 0xD4
+        for (byte in data) {
+            sum += byte
+        }
+        frame += (data)
+        frame += ((sum.inv() and 0xFF) + 0x01).toByte()
+        frame += (0x00).toByte()
+
+        return frame
+    }
+
+    private fun ByteArray.toHex(): String =
+        joinToString(separator = "") { eachByte -> "%02x".format(eachByte) }
+
+    private fun String.decodeHex(): ByteArray {
+        check(length % 2 == 0) { "Must have an even length" }
+        return chunked(2).map { it.toInt(16).toByte() }.toByteArray()
+    }
+
+    companion object {
+        private const val TAG = "PN532"
+        val ACK: ByteArray =
+            byteArrayOf(
+                0x00.toByte(),
+                0x00.toByte(),
+                0xFF.toByte(),
+                0x00.toByte(),
+                0xFF.toByte(),
+                0x00.toByte(),
+            )
+        private const val SAM_CONFIGURATION = 0x14.toByte()
+        private const val IN_LIST_PASSIVE_TARGET = 0x4A.toByte()
+        private const val RF_CONFIGURATION = 0x32.toByte()
+        private const val WRITE_REGISTER = 0X08.toByte()
+        private const val IN_COMMUNICATE_THRU = 0x42.toByte()
+        private const val IN_DATA_EXCHANGE = 0x40.toByte()
+        private val LONG_PREAMBLE = ByteArray(20)
+    }
+}
diff --git a/testutils/pn532/src/com/android/nfc/pn532/TransportLayer.kt b/testutils/pn532/src/com/android/nfc/pn532/TransportLayer.kt
new file mode 100644
index 00000000..895154ac
--- /dev/null
+++ b/testutils/pn532/src/com/android/nfc/pn532/TransportLayer.kt
@@ -0,0 +1,97 @@
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
+package com.android.nfc.pn532
+
+import android.hardware.usb.UsbConstants
+import android.hardware.usb.UsbDevice
+import android.hardware.usb.UsbDeviceConnection
+import android.hardware.usb.UsbEndpoint
+import android.hardware.usb.UsbRequest
+import android.util.Log
+
+/** TransportLayer - handles reads/write to USB device */
+class TransportLayer(val device: UsbDevice, val connection: UsbDeviceConnection) {
+
+    lateinit var endpointIn: UsbEndpoint
+    lateinit var endpointOut: UsbEndpoint
+    val dataRequest: UsbRequest = UsbRequest()
+
+    init {
+        for (i in 0 until device.interfaceCount) {
+            val ui = device.getInterface(i)
+            for (j in 0 until ui.endpointCount) {
+                val endPoint = ui.getEndpoint(j)
+                when (endPoint.type) {
+                    UsbConstants.USB_ENDPOINT_XFER_BULK -> {
+                        connection.claimInterface(ui, true)
+                        if (endPoint.direction == UsbConstants.USB_DIR_IN) {
+                            endpointIn = endPoint
+                            dataRequest.initialize(connection, endpointIn)
+                        } else {
+                            endpointOut = endPoint
+                        }
+                    }
+                }
+            }
+        }
+    }
+
+    fun read(timeout: Long, numBytes: Int = 255): ByteArray? {
+        if (numBytes < 0) return null
+        val buffer = ByteArray(numBytes)
+
+        val size = connection.bulkTransfer(endpointIn, buffer, buffer.size, timeout.toInt())
+        Log.d(TAG, "Got $size bytes back from reading.")
+        if (size > 0) {
+            val ret = ByteArray(size)
+            System.arraycopy(buffer, 0, ret, 0, size)
+            return ret
+        } else {
+            Log.e(TAG, "Got no data back. Response: " + size)
+        }
+        return null
+    }
+
+    fun write(bytes: ByteArray): Boolean {
+        val size = connection.bulkTransfer(endpointOut, bytes, bytes.size, endpointOut.interval)
+        if (size > 0) {
+            return true
+        }
+        Log.e(TAG, "Unsuccessful write")
+        return false
+    }
+
+    fun write(hexString: String): Boolean {
+        return write(hexStringToBytes(hexString))
+    }
+
+    companion object {
+        private const val TAG: String = "PN532"
+
+        fun bytesToString(bytes: ByteArray): String {
+            val sb = StringBuilder()
+            for (b: Byte in bytes) {
+                sb.append(String.format("%02X ", b))
+            }
+
+            return sb.toString()
+        }
+
+        fun hexStringToBytes(hexString: String): ByteArray {
+            return hexString.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
+        }
+    }
+}
diff --git a/testutils/pn532/src/com/android/nfc/pn532/TypeATag.kt b/testutils/pn532/src/com/android/nfc/pn532/TypeATag.kt
new file mode 100644
index 00000000..95b80469
--- /dev/null
+++ b/testutils/pn532/src/com/android/nfc/pn532/TypeATag.kt
@@ -0,0 +1,69 @@
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
+package com.android.nfc.pn532
+
+import android.util.Log
+
+/** TypeA Tag - used to transact a specific command and response sequence */
+class TypeATag(
+    val pn532: PN532,
+    val targetId: Byte,
+    val senseRes: ByteArray,
+    val selRes: Byte,
+    val nfcId: ByteArray,
+    val ats: ByteArray,
+) {
+
+    /**
+     * Completes a transaction of APDUs between reader and emulator, with command APDUs and expected
+     * response APDUs passed in as parameters. Returns true if transaction is successful
+     */
+    fun transact(commandApdus: Array<String>, responseApdus: Array<String>): Boolean {
+        if (commandApdus.size != responseApdus.size) {
+            Log.e(TAG, "Command and response APDU size mismatch")
+            return false
+        }
+
+        Log.d(TAG, "Transacting with a TypeATag - targetId: " + targetId + ", senseRes: " +
+        senseRes + ", selRes: " + selRes + ", nfcId: " + nfcId + ", ats: " + ats)
+
+        var success = true
+        for (i in 0 until commandApdus.size) {
+            val rsp = pn532.transceive(byteArrayOf(targetId) + commandApdus[i].decodeHex())
+            if (responseApdus[i] != "*" && !rsp.contentEquals(responseApdus[i].decodeHex())) {
+                Log.e(
+                    TAG,
+                    "Unexpected APDU: received " + rsp + ", expected " + responseApdus[i].decodeHex(),
+                )
+                success = false
+            }
+        }
+        return success
+    }
+
+    fun String.decodeHex(): ByteArray {
+        check(length % 2 == 0) { "Must have an even length" }
+
+        return chunked(2).map { it.toInt(16).toByte() }.toByteArray()
+    }
+
+    fun ByteArray.toHex(): String =
+        joinToString(separator = "") { eachByte -> "%02x".format(eachByte) }
+
+    companion object {
+        private const val TAG = "TypeATag"
+    }
+}
diff --git a/testutils/pn532/tag.py b/testutils/pn532/tag.py
index 8fc0237a..aaaa4869 100644
--- a/testutils/pn532/tag.py
+++ b/testutils/pn532/tag.py
@@ -16,8 +16,27 @@
 
 from binascii import hexlify
 
+class Tag:
+    def __init__(self, target_id: int):
+        self.target_id = target_id
+
+    def transact(self, command_apdus, response_apdus):
+        self.log.debug("Starting transaction with %d commands", len(command_apdus))
+        for i in range(len(command_apdus)):
+            rsp = self.pn532.transceive(bytearray([self.target_id]) + command_apdus[i])
+            if response_apdus[i] != "*" and rsp != response_apdus[i]:
+                received_apdu = hexlify(rsp).decode() if type(rsp) is bytes else "None"
+                self.log.error(
+                    "Unexpected APDU: received %s, expected %s",
+                    received_apdu,
+                    hexlify(response_apdus[i]).decode(),
+                )
+                return False
+
+        return True
 
-class TypeATag:
+
+class TypeATag(Tag):
 
     def __init__(
             self,
@@ -37,16 +56,16 @@ class TypeATag:
 
         self.log = pn532.log
 
-    def transact(self, command_apdus, response_apdus):
-        self.log.debug("Starting transaction with %d commands", len(command_apdus))
-        for i in range(len(command_apdus)):
-            rsp = self.pn532.transceive(bytearray([self.target_id]) + command_apdus[i])
-            if response_apdus[i] != "*" and rsp != response_apdus[i]:
-                self.log.error(
-                    "Unexpected APDU: received %s, expected %s",
-                    hexlify(rsp).decode(),
-                    hexlify(response_apdus[i]).decode(),
-                )
-                return False
+class TypeBTag(Tag):
 
-        return True
+    def __init__(
+            self,
+            pn532: "PN532",
+            target_id: int,
+            sensb_res: bytearray,
+    ):
+        self.pn532 = pn532
+        self.target_id = target_id
+        self.sensb_res = sensb_res
+
+        self.log = pn532.log
diff --git a/testutils/src/com/android/nfc/emulator/ForegroundPaymentEmulatorActivity.java b/testutils/src/com/android/nfc/emulator/AccessServiceTurnObserveModeOnProcessApduEmulatorActivity.java
similarity index 73%
rename from testutils/src/com/android/nfc/emulator/ForegroundPaymentEmulatorActivity.java
rename to testutils/src/com/android/nfc/emulator/AccessServiceTurnObserveModeOnProcessApduEmulatorActivity.java
index ea71d0ae..d5727871 100644
--- a/testutils/src/com/android/nfc/emulator/ForegroundPaymentEmulatorActivity.java
+++ b/testutils/src/com/android/nfc/emulator/AccessServiceTurnObserveModeOnProcessApduEmulatorActivity.java
@@ -18,45 +18,42 @@ package com.android.nfc.emulator;
 import android.content.ComponentName;
 import android.os.Bundle;
 
-import com.android.nfc.service.PaymentService1;
-import com.android.nfc.service.PaymentService2;
-
-public class ForegroundPaymentEmulatorActivity extends BaseEmulatorActivity {
+import com.android.nfc.service.AccessServiceTurnObserveModeOnProcessApdu;
 
+public class AccessServiceTurnObserveModeOnProcessApduEmulatorActivity
+        extends BaseEmulatorActivity {
     @Override
     protected void onCreate(Bundle savedInstanceState) {
         super.onCreate(savedInstanceState);
     }
 
+    @Override
+    public void onApduSequenceComplete(ComponentName component, long duration) {
+        if (component.equals(AccessServiceTurnObserveModeOnProcessApdu.COMPONENT)) {
+            setTestPassed();
+        }
+    }
+
     @Override
     protected void onResume() {
         super.onResume();
-        setupServices(PaymentService2.COMPONENT, PaymentService1.COMPONENT);
+        setupServices(AccessServiceTurnObserveModeOnProcessApdu.COMPONENT);
     }
 
     @Override
     protected void onServicesSetup() {
-        makeDefaultWalletRoleHolder();
         mCardEmulation.setPreferredService(
-                this, PaymentService2.COMPONENT);
+                this, AccessServiceTurnObserveModeOnProcessApdu.COMPONENT);
     }
 
     @Override
-    protected void onPause() {
-        super.onPause();
-        mCardEmulation.unsetPreferredService(this);
-    }
-
-    @Override
-    public void onApduSequenceComplete(ComponentName component, long duration) {
-        if (component.equals(PaymentService2.COMPONENT)) {
-            setTestPassed();
-        }
+    public ComponentName getPreferredServiceComponent() {
+        return AccessServiceTurnObserveModeOnProcessApdu.COMPONENT;
     }
 
-    /* Gets preferred service description */
     @Override
-    public ComponentName getPreferredServiceComponent() {
-        return PaymentService2.COMPONENT;
+    protected void onPause() {
+        super.onPause();
+        mCardEmulation.unsetPreferredService(this);
     }
 }
diff --git a/testutils/src/com/android/nfc/emulator/AndroidManifest.xml b/testutils/src/com/android/nfc/emulator/AndroidManifest.xml
index c93b2abf..49b2547d 100644
--- a/testutils/src/com/android/nfc/emulator/AndroidManifest.xml
+++ b/testutils/src/com/android/nfc/emulator/AndroidManifest.xml
@@ -35,6 +35,15 @@
         <meta-data
             android:name="mobly-snippets"
             android:value="com.android.nfc.emulator.NfcEmulatorDeviceSnippet"/>
+        <activity
+            android:name=".AccessServiceTurnObserveModeOnProcessApduEmulatorActivity"
+            android:label="Access Service Observe Mode Emulator"
+            android:exported="true">
+        </activity>
+        <activity android:name=".PollingAndOffHostEmulatorActivity"
+            android:label="Polling And Off Host Emulator"
+            android:exported="true">
+        </activity>
         <activity
             android:name=".PollingLoopEmulatorActivity"
             android:label="Polling Loop Emulator"
@@ -46,13 +55,8 @@
             android:exported="true">
         </activity>
         <activity
-            android:name=".SingleNonPaymentEmulatorActivity"
-            android:label="Single Non Payment Emulator"
-            android:exported="true">
-        </activity>
-        <activity
-            android:name=".SinglePaymentEmulatorActivity"
-            android:label="Single Payment Emulator"
+            android:name=".SimpleEmulatorActivity"
+            android:label="Simple Emulator"
             android:exported="true">
         </activity>
         <activity
@@ -65,16 +69,6 @@
             android:label="On and Off Host Emulator"
             android:exported="true">
         </activity>
-        <activity
-            android:name=".DualPaymentEmulatorActivity"
-            android:label="Dual Payment Emulator"
-            android:exported="true">
-        </activity>
-        <activity
-            android:name=".ForegroundPaymentEmulatorActivity"
-            android:label="Foreground Payment Emulator"
-            android:exported="true">
-        </activity>
         <activity
             android:name=".DynamicAidEmulatorActivity"
             android:label="Dynamic Payment AID emulator"
@@ -90,31 +84,16 @@
             android:label="Prefix Payment 2 emulator"
             android:exported="true">
         </activity>
-        <activity
-            android:name=".DualNonPaymentEmulatorActivity"
-            android:label="Dual Non Payment emulator"
-            android:exported="true">
-        </activity>
         <activity
             android:name=".DualNonPaymentPrefixEmulatorActivity"
             android:label="Dual Non-Payment Prefix emulator"
             android:exported="true">
         </activity>
-        <activity
-            android:name=".ForegroundNonPaymentEmulatorActivity"
-            android:label="Foreground Non Payment emulator"
-            android:exported="true">
-        </activity>
         <activity
             android:name=".ThroughputEmulatorActivity"
             android:label="Throughput emulator"
             android:exported="true">
         </activity>
-        <activity
-            android:name=".TapTestEmulatorActivity"
-            android:label="Tap Test emulator"
-            android:exported="true">
-        </activity>
         <activity
             android:name=".LargeNumAidsEmulatorActivity"
             android:label="Large Num Aids emulator"
@@ -125,15 +104,6 @@
             android:label="Screen Off Payment emulator"
             android:exported="true">
         </activity>
-        <activity
-            android:name=".ProtocolParamsEmulatorActivity"
-            android:label="Protocol Params emulator"
-            android:exported="true">
-        </activity>
-        <activity android:name=".ConflictingNonPaymentEmulatorActivity"
-            android:label="Conflicting Non-Payment Emulator"
-            android:exported="true">
-        </activity>
         <activity android:name=".ConflictingNonPaymentPrefixEmulatorActivity"
             android:label="Conflicting Non-Payment Prefix Emulator"
             android:exported="true">
@@ -142,6 +112,11 @@
             android:label="Screen-On Off Host Emulator"
             android:exported="true">
         </activity>
+        <activity
+            android:name=".PN532Activity"
+            android:label="PN532 Activity"
+            android:exported="true">
+        </activity>
         <service android:name="com.android.nfc.service.PollingLoopService" android:exported="true"
             android:permission="android.permission.BIND_NFC_SERVICE"
             android:enabled="true">
@@ -160,6 +135,15 @@
             </intent-filter>
             <meta-data android:name="android.nfc.cardemulation.host_apdu_service" android:resource="@xml/access_aid_list_2"/>
         </service>
+        <service android:name="com.android.nfc.service.AccessServiceTurnObserveModeOnProcessApdu" android:exported="true"
+            android:permission="android.permission.BIND_NFC_SERVICE"
+            android:enabled="false">
+            <intent-filter>
+                <action android:name="android.nfc.cardemulation.action.HOST_APDU_SERVICE"/>
+                <category android:name="android.intent.category.DEFAULT"/>
+            </intent-filter>
+            <meta-data android:name="android.nfc.cardemulation.host_apdu_service" android:resource="@xml/access_aid_list"/>
+        </service>
         <service android:name="com.android.nfc.service.TransportService1" android:exported="true"
             android:permission="android.permission.BIND_NFC_SERVICE"
             android:enabled="false">
@@ -196,6 +180,15 @@
             </intent-filter>
             <meta-data android:name="android.nfc.cardemulation.host_apdu_service" android:resource="@xml/payment_aid_list_1"/>
         </service>
+        <service android:name="com.android.nfc.service.PaymentServiceNoIndexReset" android:exported="true"
+            android:permission="android.permission.BIND_NFC_SERVICE"
+            android:enabled="false">
+            <intent-filter>
+                <action android:name="android.nfc.cardemulation.action.HOST_APDU_SERVICE"/>
+                <category android:name="android.intent.category.DEFAULT"/>
+            </intent-filter>
+            <meta-data android:name="android.nfc.cardemulation.host_apdu_service" android:resource="@xml/payment_aid_list_1"/>
+        </service>
         <service android:name="com.android.nfc.service.OffHostService" android:exported="true"
             android:permission="android.permission.BIND_NFC_SERVICE"
             android:enabled="false">
diff --git a/testutils/src/com/android/nfc/emulator/BaseEmulatorActivity.java b/testutils/src/com/android/nfc/emulator/BaseEmulatorActivity.java
index 5c1529ea..424e9540 100644
--- a/testutils/src/com/android/nfc/emulator/BaseEmulatorActivity.java
+++ b/testutils/src/com/android/nfc/emulator/BaseEmulatorActivity.java
@@ -22,8 +22,10 @@ import android.content.ComponentName;
 import android.content.Context;
 import android.content.Intent;
 import android.content.IntentFilter;
+import android.content.pm.PackageInfo;
 import android.content.pm.PackageManager;
 import android.content.pm.PackageManager.NameNotFoundException;
+import android.content.pm.ServiceInfo;
 import android.content.res.XmlResourceParser;
 import android.nfc.NfcAdapter;
 import android.nfc.cardemulation.CardEmulation;
@@ -34,25 +36,7 @@ import android.util.Log;
 import android.util.Xml;
 
 import com.android.compatibility.common.util.CommonTestUtils;
-import com.android.nfc.service.AccessService;
 import com.android.nfc.service.HceService;
-import com.android.nfc.service.LargeNumAidsService;
-import com.android.nfc.service.OffHostService;
-import com.android.nfc.service.PaymentService1;
-import com.android.nfc.service.PaymentService2;
-import com.android.nfc.service.PaymentServiceDynamicAids;
-import com.android.nfc.service.PollingLoopService;
-import com.android.nfc.service.PollingLoopService2;
-import com.android.nfc.service.PrefixAccessService;
-import com.android.nfc.service.PrefixPaymentService1;
-import com.android.nfc.service.PrefixPaymentService2;
-import com.android.nfc.service.PrefixTransportService1;
-import com.android.nfc.service.PrefixTransportService2;
-import com.android.nfc.service.ScreenOffPaymentService;
-import com.android.nfc.service.ScreenOnOnlyOffHostService;
-import com.android.nfc.service.ThroughputService;
-import com.android.nfc.service.TransportService1;
-import com.android.nfc.service.TransportService2;
 import com.android.nfc.utils.HceUtils;
 
 import org.xmlpull.v1.XmlPullParserException;
@@ -69,27 +53,6 @@ public abstract class BaseEmulatorActivity extends Activity {
 
     // Intent action that's sent after the test condition is met.
     protected static final String ACTION_TEST_PASSED = PACKAGE_NAME + ".ACTION_TEST_PASSED";
-    protected static final ArrayList<ComponentName> SERVICES =
-            new ArrayList<>(
-                    List.of(
-                            TransportService1.COMPONENT,
-                            TransportService2.COMPONENT,
-                            AccessService.COMPONENT,
-                            PaymentService1.COMPONENT,
-                            PaymentService2.COMPONENT,
-                            PaymentServiceDynamicAids.COMPONENT,
-                            PrefixPaymentService1.COMPONENT,
-                            PrefixPaymentService2.COMPONENT,
-                            PrefixTransportService1.COMPONENT,
-                            PrefixTransportService2.COMPONENT,
-                            PrefixAccessService.COMPONENT,
-                            ThroughputService.COMPONENT,
-                            LargeNumAidsService.COMPONENT,
-                            ScreenOffPaymentService.COMPONENT,
-                            OffHostService.COMPONENT,
-                            ScreenOnOnlyOffHostService.COMPONENT,
-                            PollingLoopService.COMPONENT,
-                            PollingLoopService2.COMPONENT));
     protected static final String TAG = "BaseEmulatorActivity";
     protected NfcAdapter mAdapter;
     protected CardEmulation mCardEmulation;
@@ -136,19 +99,18 @@ public abstract class BaseEmulatorActivity extends Activity {
     }
 
     public void disableServices() {
-        for (ComponentName component : SERVICES) {
+        for (ComponentName component : getServices()) {
             Log.d(TAG, "Disabling component " + component);
             HceUtils.disableComponent(getPackageManager(), component);
         }
     }
 
     /* Gets preferred service description */
-    public String getPreferredServiceDescription() {
+    public String getServiceDescriptionFromComponent(ComponentName component) {
         try {
             Bundle data =
                     getPackageManager()
-                            .getServiceInfo(
-                                    getPreferredServiceComponent(), PackageManager.GET_META_DATA)
+                            .getServiceInfo(component, PackageManager.GET_META_DATA)
                             .metaData;
             XmlResourceParser xrp =
                     getResources().getXml(data.getInt(HostApduService.SERVICE_META_DATA));
@@ -184,6 +146,8 @@ public abstract class BaseEmulatorActivity extends Activity {
             }
         } catch (NameNotFoundException e) {
             Log.w(TAG, "NameNotFoundException. Test will probably fail.");
+        } catch (Exception e) {
+            Log.w(TAG, "Exception while parsing service description.", e);
         }
         return "";
     }
@@ -191,23 +155,41 @@ public abstract class BaseEmulatorActivity extends Activity {
     void ensurePreferredService(String serviceDesc, Context context, CardEmulation cardEmulation) {
         Log.d(TAG, "ensurePreferredService: " + serviceDesc);
         try {
-            CommonTestUtils.waitUntil("Default service hasn't updated", 6,
-                    () -> serviceDesc.equals(
-                            cardEmulation.getDescriptionForPreferredPaymentService().toString()));
-        } catch (InterruptedException ie) {
-            Log.w(TAG, "Default service not updated. This may cause tests to fail");
+            CommonTestUtils.waitUntil(
+                    "Default service hasn't updated",
+                    6,
+                    () ->
+                            cardEmulation.getDescriptionForPreferredPaymentService() != null
+                                    && serviceDesc.equals(
+                                            cardEmulation
+                                                    .getDescriptionForPreferredPaymentService()
+                                                    .toString()));
+        } catch (Exception e) {
+            Log.e(TAG, "Default service not updated. This may cause tests to fail", e);
         }
     }
 
     /** Sets observe mode. */
     public boolean setObserveModeEnabled(boolean enable) {
-        ensurePreferredService(getPreferredServiceDescription(), this, mCardEmulation);
+        ensurePreferredService(
+                getServiceDescriptionFromComponent(getPreferredServiceComponent()),
+                this,
+                mCardEmulation);
         return mAdapter.setObserveModeEnabled(enable);
     }
 
     /** Waits for preferred service to be set, and sends broadcast afterwards. */
-    public void waitForService() {
-        ensurePreferredService(getPreferredServiceDescription(), this, mCardEmulation);
+    public void waitForPreferredService() {
+        ensurePreferredService(
+                getServiceDescriptionFromComponent(getPreferredServiceComponent()),
+                this,
+                mCardEmulation);
+    }
+
+    /** Waits for given service to be set */
+    public void waitForService(ComponentName componentName) {
+        ensurePreferredService(
+                getServiceDescriptionFromComponent(componentName), this, mCardEmulation);
     }
 
     void waitForObserveModeEnabled(boolean enabled) {
@@ -215,8 +197,8 @@ public abstract class BaseEmulatorActivity extends Activity {
         try {
             CommonTestUtils.waitUntil("Observe mode has not been set", 6,
                     () -> mAdapter.isObserveModeEnabled() == enabled);
-        } catch (InterruptedException ie) {
-            Log.w(TAG, "Observe mode not set to " + enabled + ". This may cause tests to fail");
+        } catch (Exception e) {
+            Log.e(TAG, "Observe mode not set to " + enabled + ". This may cause tests to fail", e);
         }
     }
 
@@ -229,8 +211,7 @@ public abstract class BaseEmulatorActivity extends Activity {
     /** Sets up HCE services for this emulator */
     public void setupServices(ComponentName... componentNames) {
         List<ComponentName> enableComponents = Arrays.asList(componentNames);
-        Log.d(TAG, "setupServices called");
-        for (ComponentName component : SERVICES) {
+        for (ComponentName component : getServices()) {
             if (enableComponents.contains(component)) {
                 Log.d(TAG, "Enabling component " + component);
                 HceUtils.enableComponent(getPackageManager(), component);
@@ -293,4 +274,24 @@ public abstract class BaseEmulatorActivity extends Activity {
     public void resetListenTech() {
         mAdapter.resetDiscoveryTechnology(this);
     }
+
+    /* Fetch all services in the package */
+    private List<ComponentName> getServices() {
+        List<ComponentName> services = new ArrayList<>();
+        try {
+            PackageInfo packageInfo = getPackageManager().getPackageInfo(PACKAGE_NAME,
+                    PackageManager.GET_SERVICES
+                            | PackageManager.MATCH_DISABLED_COMPONENTS);
+
+            if (packageInfo.services != null) {
+                for (ServiceInfo info : packageInfo.services) {
+                    services.add(new ComponentName(PACKAGE_NAME, info.name));
+                }
+            }
+
+        } catch (PackageManager.NameNotFoundException e) {
+            Log.e(TAG, "Package, application or component name cannot be found", e);
+        }
+        return services;
+    }
 }
diff --git a/testutils/src/com/android/nfc/emulator/ConflictingNonPaymentEmulatorActivity.java b/testutils/src/com/android/nfc/emulator/ConflictingNonPaymentEmulatorActivity.java
deleted file mode 100644
index 04eccdd8..00000000
--- a/testutils/src/com/android/nfc/emulator/ConflictingNonPaymentEmulatorActivity.java
+++ /dev/null
@@ -1,58 +0,0 @@
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
-package com.android.nfc.emulator;
-
-import android.content.ComponentName;
-import android.os.Bundle;
-import android.util.Log;
-
-import com.android.nfc.service.TransportService1;
-import com.android.nfc.service.TransportService2;
-
-public class ConflictingNonPaymentEmulatorActivity extends BaseEmulatorActivity {
-    protected static final String TAG = "ConflictingNonPayment";
-
-    @Override
-    protected void onCreate(Bundle savedInstanceState) {
-        Log.d(TAG, "onCreate");
-        super.onCreate(savedInstanceState);
-        setupServices(TransportService1.COMPONENT, TransportService2.COMPONENT);
-    }
-
-    @Override
-    protected void onResume() {
-        super.onResume();
-        Log.d(TAG, "onResume");
-    }
-
-    @Override
-    protected void onPause() {
-        super.onPause();
-        Log.d(TAG, "onPause");
-    }
-
-    @Override
-    protected void onApduSequenceComplete(ComponentName component, long duration) {
-        if (component.equals(TransportService2.COMPONENT)) {
-            setTestPassed();
-        }
-    }
-
-    @Override
-    public ComponentName getPreferredServiceComponent(){
-        return TransportService2.COMPONENT;
-    }
-}
diff --git a/testutils/src/com/android/nfc/emulator/DualNonPaymentEmulatorActivity.java b/testutils/src/com/android/nfc/emulator/DualNonPaymentEmulatorActivity.java
deleted file mode 100644
index ff231491..00000000
--- a/testutils/src/com/android/nfc/emulator/DualNonPaymentEmulatorActivity.java
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
-package com.android.nfc.emulator;
-
-import android.content.ComponentName;
-import android.os.Bundle;
-
-import com.android.nfc.service.AccessService;
-import com.android.nfc.service.TransportService2;
-
-public class DualNonPaymentEmulatorActivity extends BaseEmulatorActivity {
-    @Override
-    protected void onCreate(Bundle savedInstanceState) {
-        super.onCreate(savedInstanceState);
-    }
-
-    @Override
-    protected void onResume() {
-        super.onResume();
-        setupServices(TransportService2.COMPONENT, AccessService.COMPONENT);
-    }
-
-    @Override
-    protected void onPause() {
-        super.onPause();
-    }
-
-    @Override
-    protected void onApduSequenceComplete(ComponentName component, long duration) {
-        if (component.equals(TransportService2.COMPONENT)) {
-            setTestPassed();
-        }
-    }
-
-    @Override
-    public ComponentName getPreferredServiceComponent(){
-        return TransportService2.COMPONENT;
-    }
-}
diff --git a/testutils/src/com/android/nfc/emulator/DualPaymentEmulatorActivity.java b/testutils/src/com/android/nfc/emulator/DualPaymentEmulatorActivity.java
deleted file mode 100644
index 1984279e..00000000
--- a/testutils/src/com/android/nfc/emulator/DualPaymentEmulatorActivity.java
+++ /dev/null
@@ -1,68 +0,0 @@
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
-package com.android.nfc.emulator;
-
-import android.content.ComponentName;
-import android.os.Bundle;
-import android.util.Log;
-
-import com.android.nfc.service.PaymentService1;
-import com.android.nfc.service.PaymentService2;
-
-public class DualPaymentEmulatorActivity extends BaseEmulatorActivity {
-
-    private static final String TAG = "DualPaymentEm";
-    private static final int STATE_IDLE = 0;
-    private static final int STATE_SERVICE1_SETTING_UP = 1;
-    private static final int STATE_SERVICE2_SETTING_UP = 2;
-
-    private int mState = STATE_IDLE;
-
-    @Override
-    protected void onCreate(Bundle savedInstanceState) {
-        super.onCreate(savedInstanceState);
-    }
-
-    @Override
-    protected void onResume() {
-        super.onResume();
-        Log.d(TAG, "onResume");
-        mState = STATE_SERVICE2_SETTING_UP;
-        setupServices(PaymentService2.COMPONENT);
-    }
-
-    @Override
-    protected void onServicesSetup() {
-        if (mState == STATE_SERVICE2_SETTING_UP) {
-            mState = STATE_SERVICE1_SETTING_UP;
-            setupServices(PaymentService1.COMPONENT, PaymentService2.COMPONENT);
-            return;
-        }
-        makeDefaultWalletRoleHolder();
-    }
-
-    @Override
-    public void onApduSequenceComplete(ComponentName component, long duration) {
-        if (component.equals(PaymentService1.COMPONENT)) {
-            setTestPassed();
-        }
-    }
-
-    @Override
-    public ComponentName getPreferredServiceComponent() {
-        return PaymentService1.COMPONENT;
-    }
-}
diff --git a/testutils/src/com/android/nfc/emulator/ForegroundNonPaymentEmulatorActivity.java b/testutils/src/com/android/nfc/emulator/ForegroundNonPaymentEmulatorActivity.java
deleted file mode 100644
index c69050d6..00000000
--- a/testutils/src/com/android/nfc/emulator/ForegroundNonPaymentEmulatorActivity.java
+++ /dev/null
@@ -1,62 +0,0 @@
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
-package com.android.nfc.emulator;
-
-import android.content.ComponentName;
-import android.os.Bundle;
-
-import com.android.nfc.service.TransportService1;
-import com.android.nfc.service.TransportService2;
-
-public class ForegroundNonPaymentEmulatorActivity extends BaseEmulatorActivity {
-    @Override
-    protected void onCreate(Bundle savedInstanceState) {
-        super.onCreate(savedInstanceState);
-    }
-
-    @Override
-    protected void onResume() {
-        super.onResume();
-        setupServices(TransportService1.COMPONENT, TransportService2.COMPONENT);
-    }
-
-    @Override
-    protected void onPause() {
-        super.onPause();
-        mCardEmulation.unsetPreferredService(this);
-    }
-
-    @Override
-    protected void onServicesSetup() {
-        // Tell NFC service we prefer TransportService2
-        mCardEmulation.setPreferredService(
-                this,
-                TransportService2.COMPONENT)
-        ;
-    }
-
-    @Override
-    protected void onApduSequenceComplete(ComponentName component, long duration) {
-        if (component.equals(TransportService2.COMPONENT)) {
-            setTestPassed();
-        }
-    }
-
-    @Override
-    public ComponentName getPreferredServiceComponent(){
-        return TransportService2.COMPONENT;
-    }
-}
diff --git a/testutils/src/com/android/nfc/emulator/NfcEmulatorDeviceSnippet.java b/testutils/src/com/android/nfc/emulator/NfcEmulatorDeviceSnippet.java
index 32e5b9b2..6580adf2 100644
--- a/testutils/src/com/android/nfc/emulator/NfcEmulatorDeviceSnippet.java
+++ b/testutils/src/com/android/nfc/emulator/NfcEmulatorDeviceSnippet.java
@@ -17,6 +17,7 @@ package com.android.nfc.emulator;
 
 
 import android.app.Instrumentation;
+import android.content.ComponentName;
 import android.content.Intent;
 import android.nfc.NfcAdapter;
 import android.util.Log;
@@ -27,11 +28,18 @@ import androidx.test.uiautomator.UiObjectNotFoundException;
 import androidx.test.uiautomator.UiScrollable;
 import androidx.test.uiautomator.UiSelector;
 
+import com.android.nfc.service.AccessServiceTurnObserveModeOnProcessApdu;
+import com.android.nfc.utils.CommandApdu;
+import com.android.nfc.utils.HceUtils;
 import com.android.nfc.utils.NfcSnippet;
 
 import com.google.android.mobly.snippet.rpc.AsyncRpc;
 import com.google.android.mobly.snippet.rpc.Rpc;
 
+import java.util.ArrayList;
+import java.util.Arrays;
+import java.util.List;
+
 public class NfcEmulatorDeviceSnippet extends NfcSnippet {
 
     static String sRfOnAction = "com.android.nfc_extras.action.RF_FIELD_ON_DETECTED";
@@ -39,58 +47,62 @@ public class NfcEmulatorDeviceSnippet extends NfcSnippet {
 
     private static final long TIMEOUT_MS = 10_000L;
 
-    /** Opens single Non Payment emulator */
-    @Rpc(description = "Open single non payment emulator activity")
-    public void startSingleNonPaymentEmulatorActivity() {
-        Instrumentation instrumentation = InstrumentationRegistry.getInstrumentation();
-
-        Intent intent = new Intent(Intent.ACTION_MAIN);
-        intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
-        intent.setClassName(
-                instrumentation.getTargetContext(),
-                SingleNonPaymentEmulatorActivity.class.getName());
-
-        mActivity = (SingleNonPaymentEmulatorActivity) instrumentation.startActivitySync(intent);
-    }
-
-    /** Opens single payment emulator activity */
-    @Rpc(description = "Open single payment emulator activity")
-    public void startSinglePaymentEmulatorActivity() {
-        Instrumentation instrumentation = InstrumentationRegistry.getInstrumentation();
-
-        Intent intent = new Intent(Intent.ACTION_MAIN);
-        intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
-        intent.setClassName(
-                instrumentation.getTargetContext(), SinglePaymentEmulatorActivity.class.getName());
-
-        mActivity = (SinglePaymentEmulatorActivity) instrumentation.startActivitySync(intent);
-    }
-
-    /** Opens dual payment emulator activity */
-    @Rpc(description = "Opens dual payment emulator activity")
-    public void startDualPaymentEmulatorActivity() {
-        Instrumentation instrumentation = InstrumentationRegistry.getInstrumentation();
-
-        Intent intent = new Intent(Intent.ACTION_MAIN);
-        intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
-        intent.setClassName(
-                instrumentation.getTargetContext(), DualPaymentEmulatorActivity.class.getName());
-
-        mActivity = (DualPaymentEmulatorActivity) instrumentation.startActivitySync(intent);
+    /**
+     * Starts emulator activity for simple multidevice tests
+     *
+     * @param serviceClassNames - service class names to enable
+     * @param testPassClassName - class name of service that should handle the APDUs
+     * @param isPaymentActivity - whether or not it is a payment activity
+     */
+    @Rpc(description = "Start simple emulator activity")
+    public void startSimpleEmulatorActivity(
+            String[] serviceClassNames, String testPassClassName, boolean isPaymentActivity) {
+        Intent intent =
+                buildSimpleEmulatorActivityIntent(
+                        serviceClassNames, testPassClassName, null, isPaymentActivity);
+        mActivity =
+                (SimpleEmulatorActivity)
+                        InstrumentationRegistry.getInstrumentation().startActivitySync(intent);
+    }
+
+    /**
+     * Starts emulator activity for simple multidevice tests
+     *
+     * @param serviceClassNames - services to enable
+     * @param testPassClassName - service that should handle the APDU
+     * @param preferredServiceClassName - preferred service to set
+     * @param isPaymentActivity - whether or not this is a payment activity
+     */
+    @Rpc(description = "Start simple emulator activity with preferred service")
+    public void startSimpleEmulatorActivityWithPreferredService(
+            String[] serviceClassNames,
+            String testPassClassName,
+            String preferredServiceClassName,
+            boolean isPaymentActivity) {
+        Intent intent =
+                buildSimpleEmulatorActivityIntent(
+                        serviceClassNames,
+                        testPassClassName,
+                        preferredServiceClassName,
+                        isPaymentActivity);
+        mActivity =
+                (SimpleEmulatorActivity)
+                        InstrumentationRegistry.getInstrumentation().startActivitySync(intent);
     }
 
-    /** Opens foreground payment emulator activity */
-    @Rpc(description = "Opens foreground payment emulator activity")
-    public void startForegroundPaymentEmulatorActivity() {
+    @Rpc(description = "Opens emulator activity with Access Service that turns on observe mode")
+    public void startAccessServiceObserveModeEmulatorActivity() {
         Instrumentation instrumentation = InstrumentationRegistry.getInstrumentation();
 
         Intent intent = new Intent(Intent.ACTION_MAIN);
         intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
         intent.setClassName(
                 instrumentation.getTargetContext(),
-                ForegroundPaymentEmulatorActivity.class.getName());
+                AccessServiceTurnObserveModeOnProcessApduEmulatorActivity.class.getName());
 
-        mActivity = (ForegroundPaymentEmulatorActivity) instrumentation.startActivitySync(intent);
+        mActivity =
+                (AccessServiceTurnObserveModeOnProcessApduEmulatorActivity)
+                        instrumentation.startActivitySync(intent);
     }
 
     /** Opens dynamic AID emulator activity */
@@ -188,34 +200,6 @@ public class NfcEmulatorDeviceSnippet extends NfcSnippet {
         mActivity = (OnAndOffHostEmulatorActivity) instrumentation.startActivitySync(intent);
     }
 
-    /** Opens dual non-payment emulator activity */
-    @Rpc(description = "Opens dual non-payment emulator activity")
-    public void startDualNonPaymentEmulatorActivity() {
-        Instrumentation instrumentation = InstrumentationRegistry.getInstrumentation();
-
-        Intent intent = new Intent(Intent.ACTION_MAIN);
-        intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
-        intent.setClassName(
-                instrumentation.getTargetContext(), DualNonPaymentEmulatorActivity.class.getName());
-
-        mActivity = (DualNonPaymentEmulatorActivity) instrumentation.startActivitySync(intent);
-    }
-
-    /** Opens foreground non-payment emulator activity */
-    @Rpc(description = "Opens foreground non-payment emulator activity")
-    public void startForegroundNonPaymentEmulatorActivity() {
-        Instrumentation instrumentation = InstrumentationRegistry.getInstrumentation();
-
-        Intent intent = new Intent(Intent.ACTION_MAIN);
-        intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
-        intent.setClassName(
-                instrumentation.getTargetContext(),
-                ForegroundNonPaymentEmulatorActivity.class.getName());
-
-        mActivity =
-                (ForegroundNonPaymentEmulatorActivity) instrumentation.startActivitySync(intent);
-    }
-
     /** Opens throughput emulator activity */
     @Rpc(description = "Opens throughput emulator activity")
     public void startThroughputEmulatorActivity() {
@@ -229,19 +213,6 @@ public class NfcEmulatorDeviceSnippet extends NfcSnippet {
         mActivity = (ThroughputEmulatorActivity) instrumentation.startActivitySync(intent);
     }
 
-    /** Opens tap test emulator activity */
-    @Rpc(description = "Opens tap test emulator activity")
-    public void startTapTestEmulatorActivity() {
-        Instrumentation instrumentation = InstrumentationRegistry.getInstrumentation();
-
-        Intent intent = new Intent(Intent.ACTION_MAIN);
-        intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
-        intent.setClassName(
-                instrumentation.getTargetContext(), TapTestEmulatorActivity.class.getName());
-
-        mActivity = (TapTestEmulatorActivity) instrumentation.startActivitySync(intent);
-    }
-
     /** Opens large num AIDs emulator activity */
     @Rpc(description = "Opens large num AIDs emulator activity")
     public void startLargeNumAidsEmulatorActivity() {
@@ -269,20 +240,6 @@ public class NfcEmulatorDeviceSnippet extends NfcSnippet {
         mActivity = (ScreenOffPaymentEmulatorActivity) instrumentation.startActivitySync(intent);
     }
 
-    /** Opens conflicting non-payment emulator activity */
-    @Rpc(description = "Opens conflicting non-payment emulator activity")
-    public void startConflictingNonPaymentEmulatorActivity() {
-        Instrumentation instrumentation = InstrumentationRegistry.getInstrumentation();
-
-        Intent intent = new Intent(Intent.ACTION_MAIN);
-        intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
-        intent.setClassName(
-                instrumentation.getTargetContext(),
-                ConflictingNonPaymentEmulatorActivity.class.getName());
-        mActivity =
-                (ConflictingNonPaymentEmulatorActivity) instrumentation.startActivitySync(intent);
-    }
-
     /** Opens conflicting non-payment prefix emulator activity */
     @Rpc(description = "Opens conflicting non-payment prefix emulator activity")
     public void startConflictingNonPaymentPrefixEmulatorActivity() {
@@ -334,6 +291,19 @@ public class NfcEmulatorDeviceSnippet extends NfcSnippet {
         return false;
     }
 
+    /** Open polling and off host emulator activity */
+    @Rpc(description = "Open polling and off host emulator activity")
+    public void startPollingAndOffHostEmulatorActivity() {
+        Instrumentation instrumentation = InstrumentationRegistry.getInstrumentation();
+        Intent intent = new Intent(Intent.ACTION_MAIN);
+        intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
+        intent.setClassName(
+                instrumentation.getTargetContext(),
+                PollingAndOffHostEmulatorActivity.class.getName());
+        intent.putExtra(PollingLoopEmulatorActivity.NFC_TECH_KEY, NfcAdapter.FLAG_READER_NFC_A);
+        mActivity = (PollingAndOffHostEmulatorActivity) instrumentation.startActivitySync(intent);
+    }
+
     /** Open polling loop emulator activity for Type A */
     @Rpc(description = "Open polling loop emulator activity for polling loop A test")
     public void startPollingLoopAEmulatorActivity() {
@@ -388,12 +358,40 @@ public class NfcEmulatorDeviceSnippet extends NfcSnippet {
         mActivity = (TwoPollingFrameEmulatorActivity) instrumentation.startActivitySync(intent);
     }
 
+    @Rpc(description = "Opens PN532 Activity\"")
+    public void startPN532Activity() {
+        Instrumentation instrumentation = InstrumentationRegistry.getInstrumentation();
+
+        Intent intent = new Intent(Intent.ACTION_MAIN);
+        intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
+        intent.setClassName(
+                instrumentation.getTargetContext(),
+                PN532Activity.class.getName());
+
+        mActivity = (PN532Activity) instrumentation.startActivitySync(intent);
+    }
+
     /** Registers receiver that waits for RF field broadcast */
     @AsyncRpc(description = "Waits for RF field detected broadcast")
     public void asyncWaitForRfOnBroadcast(String callbackId, String eventName) {
         registerSnippetBroadcastReceiver(callbackId, eventName, sRfOnAction);
     }
 
+    /** Registers receiver that waits for RF field broadcast */
+    @AsyncRpc(description = "Waits for RF field detected broadcast")
+    public void asyncWaitsForTagDiscovered(String callbackId, String eventName) {
+        registerSnippetBroadcastReceiver(
+                callbackId, eventName, PN532Activity.ACTION_TAG_DISCOVERED);
+    }
+
+    @Rpc(description = "Enable reader mode with given flags")
+    public void enableReaderMode(int flags) {
+        if (mActivity == null || !(mActivity instanceof PN532Activity)) {
+            return;
+        }
+        ((PN532Activity) mActivity).enableReaderMode(flags);
+    }
+
     /** Registers receiver for polling loop action */
     @AsyncRpc(description = "Waits for seen correct polling loop")
     public void asyncWaitsForSeenCorrectPollingLoop(String callbackId, String eventName) {
@@ -429,6 +427,14 @@ public class NfcEmulatorDeviceSnippet extends NfcSnippet {
         registerSnippetBroadcastReceiver(callbackId, eventName, Intent.ACTION_SCREEN_ON);
     }
 
+    @AsyncRpc(description = "Waits for Observe Mode False")
+    public void asyncWaitForObserveModeFalse(String callbackId, String eventName) {
+        registerSnippetBroadcastReceiver(
+                callbackId,
+                eventName,
+                AccessServiceTurnObserveModeOnProcessApdu.OBSERVE_MODE_FALSE);
+    }
+
     /** Sets the listen tech for the active emulator activity */
     @Rpc(description = "Set the listen tech for the emulator")
     public void setListenTech(Integer listenTech) {
@@ -485,12 +491,34 @@ public class NfcEmulatorDeviceSnippet extends NfcSnippet {
 
     /** Wait for preferred service to be set */
     @Rpc(description = "Waits for preferred service to be set")
-    public void waitForService() {
+    public void waitForPreferredService() {
         if (mActivity != null) {
-            mActivity.waitForService();
+            mActivity.waitForPreferredService();
         }
     }
 
+    /** Wait for preferred service to be set */
+    @Rpc(description = "Waits for preferred service to be set")
+    public void waitForService(String serviceName) {
+        if (mActivity != null) {
+            mActivity.waitForService(
+                    new ComponentName(HceUtils.EMULATOR_PACKAGE_NAME, serviceName));
+        }
+    }
+
+    @Rpc(description = "Gets command apdus")
+    public String[] getCommandApdus(String serviceClassName) {
+        CommandApdu[] commandApdus = HceUtils.COMMAND_APDUS_BY_SERVICE.get(serviceClassName);
+        return Arrays.stream(commandApdus)
+                .map(commandApdu -> new String(commandApdu.getApdu()))
+                .toArray(String[]::new);
+    }
+
+    @Rpc(description = "Gets response apdus")
+    public String[] getResponseApdus(String serviceClassName) {
+        return HceUtils.RESPONSE_APDUS_BY_SERVICE.get(serviceClassName);
+    }
+
     /** Builds intent to launch polling loop emulators */
     private Intent buildPollingLoopEmulatorIntent(Instrumentation instrumentation, int nfcTech) {
         Intent intent = new Intent(Intent.ACTION_MAIN);
@@ -500,4 +528,42 @@ public class NfcEmulatorDeviceSnippet extends NfcSnippet {
         intent.putExtra(PollingLoopEmulatorActivity.NFC_TECH_KEY, nfcTech);
         return intent;
     }
+
+    /** Builds intent to launch simple emulator activity */
+    private Intent buildSimpleEmulatorActivityIntent(
+            String[] serviceClassNames,
+            String expectedServiceClassName,
+            String preferredServiceClassName,
+            boolean isPaymentActivity) {
+
+        Intent intent = new Intent(Intent.ACTION_MAIN);
+        intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
+        intent.setClassName(
+                InstrumentationRegistry.getInstrumentation().getTargetContext(),
+                SimpleEmulatorActivity.class.getName());
+
+        if (serviceClassNames != null && serviceClassNames.length > 0) {
+            List<ComponentName> services =
+                    Arrays.stream(serviceClassNames)
+                            .map(cls -> new ComponentName(HceUtils.EMULATOR_PACKAGE_NAME, cls))
+                            .toList();
+            intent.putExtra(SimpleEmulatorActivity.EXTRA_SERVICES, new ArrayList<>(services));
+        }
+
+        if (expectedServiceClassName != null) {
+            intent.putExtra(
+                    SimpleEmulatorActivity.EXTRA_EXPECTED_SERVICE,
+                    new ComponentName(HceUtils.EMULATOR_PACKAGE_NAME, expectedServiceClassName));
+        }
+
+        if (preferredServiceClassName != null) {
+            intent.putExtra(
+                    SimpleEmulatorActivity.EXTRA_PREFERRED_SERVICE,
+                    new ComponentName(HceUtils.EMULATOR_PACKAGE_NAME, preferredServiceClassName));
+        }
+
+        intent.putExtra(SimpleEmulatorActivity.EXTRA_IS_PAYMENT_ACTIVITY, isPaymentActivity);
+
+        return intent;
+    }
 }
diff --git a/testutils/src/com/android/nfc/emulator/PN532Activity.java b/testutils/src/com/android/nfc/emulator/PN532Activity.java
new file mode 100644
index 00000000..54090b5b
--- /dev/null
+++ b/testutils/src/com/android/nfc/emulator/PN532Activity.java
@@ -0,0 +1,51 @@
+package com.android.nfc.emulator;
+
+import android.content.ComponentName;
+import android.content.Intent;
+import android.nfc.NfcAdapter.ReaderCallback;
+import android.nfc.Tag;
+import android.os.Bundle;
+import android.util.Log;
+
+import com.android.nfc.service.PollingLoopService;
+
+public class PN532Activity extends BaseEmulatorActivity implements ReaderCallback {
+    public static final String ACTION_TAG_DISCOVERED = PACKAGE_NAME + ".TAG_DISCOVERED";
+
+    @Override
+    protected void onCreate(Bundle savedInstanceState) {
+        super.onCreate(savedInstanceState);
+        setupServices(PollingLoopService.COMPONENT);
+    }
+
+    @Override
+    protected void onResume() {
+        super.onResume();
+        mCardEmulation.setPreferredService(this, PollingLoopService.COMPONENT);
+    }
+
+    @Override
+    protected void onPause() {
+        super.onPause();
+        mCardEmulation.unsetPreferredService(this);
+    }
+
+    @Override
+    public ComponentName getPreferredServiceComponent() {
+        return PollingLoopService.COMPONENT;
+    }
+
+
+    public void enableReaderMode(int flags) {
+        Log.d(TAG, "enableReaderMode: " + flags);
+        mAdapter.enableReaderMode(this, this, flags, null);
+    }
+
+    @Override
+    public void onTagDiscovered(Tag tag) {
+        Log.d(TAG, "onTagDiscovered");
+        Intent intent = new Intent(ACTION_TAG_DISCOVERED);
+        sendBroadcast(intent);
+    }
+
+}
diff --git a/testutils/src/com/android/nfc/emulator/PollingAndOffHostEmulatorActivity.java b/testutils/src/com/android/nfc/emulator/PollingAndOffHostEmulatorActivity.java
new file mode 100644
index 00000000..1b562143
--- /dev/null
+++ b/testutils/src/com/android/nfc/emulator/PollingAndOffHostEmulatorActivity.java
@@ -0,0 +1,57 @@
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
+package com.android.nfc.emulator;
+
+import android.content.BroadcastReceiver;
+import android.content.Context;
+import android.content.Intent;
+import android.content.IntentFilter;
+import android.os.Bundle;
+
+import com.android.nfc.service.OffHostService;
+import com.android.nfc.service.PollingLoopService;
+
+public class PollingAndOffHostEmulatorActivity extends PollingLoopEmulatorActivity {
+    @Override
+    protected void onCreate(Bundle savedInstanceState) {
+        super.onCreate(savedInstanceState);
+        setupServices(PollingLoopService.COMPONENT, OffHostService.COMPONENT);
+    }
+
+    @Override
+    public void onResume() {
+        super.onResume();
+        IntentFilter filter = new IntentFilter(SEEN_CORRECT_POLLING_LOOP_ACTION);
+        registerReceiver(mSeenCorrectLoopReceiver, filter, RECEIVER_EXPORTED);
+    }
+
+    @Override
+    public void onPause() {
+        super.onPause();
+        unregisterReceiver(mSeenCorrectLoopReceiver);
+    }
+
+    final BroadcastReceiver mSeenCorrectLoopReceiver =
+            new BroadcastReceiver() {
+                @Override
+                public void onReceive(Context context, Intent intent) {
+                    String action = intent.getAction();
+                    if (action.equals(SEEN_CORRECT_POLLING_LOOP_ACTION)) {
+                        mAdapter.setObserveModeEnabled(false);
+                    }
+                }
+            };
+}
diff --git a/testutils/src/com/android/nfc/emulator/PollingLoopEmulatorActivity.java b/testutils/src/com/android/nfc/emulator/PollingLoopEmulatorActivity.java
index b129bb40..d320a510 100644
--- a/testutils/src/com/android/nfc/emulator/PollingLoopEmulatorActivity.java
+++ b/testutils/src/com/android/nfc/emulator/PollingLoopEmulatorActivity.java
@@ -75,7 +75,7 @@ public class PollingLoopEmulatorActivity extends BaseEmulatorActivity {
 
         mCustomFrame = getIntent().getStringExtra(NFC_CUSTOM_FRAME_KEY);
         boolean isPreferredServiceSet = mCardEmulation.setPreferredService(this, serviceName);
-        waitForService();
+        waitForPreferredService();
         waitForObserveModeEnabled(true);
 
         mNfcACount = 0;
@@ -107,6 +107,13 @@ public class PollingLoopEmulatorActivity extends BaseEmulatorActivity {
         mCardEmulation.unsetPreferredService(this);
     }
 
+    @Override
+    protected void onApduSequenceComplete(ComponentName component, long duration) {
+        if (component.equals(PollingLoopService.COMPONENT)) {
+            setTestPassed();
+        }
+    }
+
     @Override
     public ComponentName getPreferredServiceComponent() {
         return PollingLoopService.COMPONENT;
diff --git a/testutils/src/com/android/nfc/emulator/SimpleEmulatorActivity.java b/testutils/src/com/android/nfc/emulator/SimpleEmulatorActivity.java
new file mode 100644
index 00000000..670ecd3c
--- /dev/null
+++ b/testutils/src/com/android/nfc/emulator/SimpleEmulatorActivity.java
@@ -0,0 +1,74 @@
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
+package com.android.nfc.emulator;
+
+import android.content.ComponentName;
+
+import java.util.List;
+import java.util.Objects;
+
+public class SimpleEmulatorActivity extends BaseEmulatorActivity {
+    protected static final String TAG = "SimpleEmulatorActivity";
+
+    public static final String EXTRA_SERVICES = "EXTRA_SERVICES";
+    public static final String EXTRA_IS_PAYMENT_ACTIVITY = "EXTRA_IS_PAYMENT_ACTIVITY";
+    public static final String EXTRA_PREFERRED_SERVICE = "EXTRA_PREFERRED_SERVICE";
+    public static final String EXTRA_EXPECTED_SERVICE = "EXTRA_EXPECTED_SERVICE";
+
+    private ComponentName mPreferredService = null;
+
+    @Override
+    protected void onResume() {
+        super.onResume();
+
+        List<ComponentName> components =
+                getIntent().getExtras().getParcelableArrayList(EXTRA_SERVICES, ComponentName.class);
+        if (components != null) {
+            setupServices(components.toArray(new ComponentName[0]));
+        }
+
+        if (getIntent().getBooleanExtra(EXTRA_IS_PAYMENT_ACTIVITY, false)) {
+            makeDefaultWalletRoleHolder();
+        }
+
+        mPreferredService =
+                getIntent().getExtras().getParcelable(EXTRA_PREFERRED_SERVICE, ComponentName.class);
+
+        if (mPreferredService != null) {
+            mCardEmulation.setPreferredService(this, mPreferredService);
+        }
+    }
+
+    @Override
+    protected void onPause() {
+        super.onPause();
+        mCardEmulation.unsetPreferredService(this);
+    }
+
+    @Override
+    protected void onApduSequenceComplete(ComponentName component, long duration) {
+        if (component.equals(
+                Objects.requireNonNull(getIntent().getExtras())
+                        .getParcelable(EXTRA_EXPECTED_SERVICE, ComponentName.class))) {
+            setTestPassed();
+        }
+    }
+
+    @Override
+    public ComponentName getPreferredServiceComponent() {
+        return mPreferredService;
+    }
+}
diff --git a/testutils/src/com/android/nfc/emulator/SingleNonPaymentEmulatorActivity.java b/testutils/src/com/android/nfc/emulator/SingleNonPaymentEmulatorActivity.java
deleted file mode 100644
index a76d5e3d..00000000
--- a/testutils/src/com/android/nfc/emulator/SingleNonPaymentEmulatorActivity.java
+++ /dev/null
@@ -1,59 +0,0 @@
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
-package com.android.nfc.emulator;
-
-import android.content.ComponentName;
-import android.os.Bundle;
-
-import com.android.nfc.service.ScreenOnOnlyOffHostService;
-import com.android.nfc.service.TransportService1;
-
-public class SingleNonPaymentEmulatorActivity extends BaseEmulatorActivity {
-    @Override
-    protected void onCreate(Bundle savedInstanceState) {
-        super.onCreate(savedInstanceState);
-    }
-
-    @Override
-    public void onApduSequenceComplete(ComponentName component, long duration) {
-        if (component.equals(TransportService1.COMPONENT)) {
-            setTestPassed();
-        }
-    }
-
-    @Override
-    protected void onResume() {
-        super.onResume();
-        setupServices(TransportService1.COMPONENT);
-    }
-
-    @Override
-    protected void onServicesSetup() {
-        mCardEmulation.setPreferredService(
-                this, TransportService1.COMPONENT);
-    }
-
-    @Override
-    public ComponentName getPreferredServiceComponent(){
-        return TransportService1.COMPONENT;
-    }
-
-    @Override
-    protected void onPause() {
-        super.onPause();
-        mCardEmulation.unsetPreferredService(this);
-    }
-}
diff --git a/testutils/src/com/android/nfc/emulator/SinglePaymentEmulatorActivity.java b/testutils/src/com/android/nfc/emulator/SinglePaymentEmulatorActivity.java
deleted file mode 100644
index 5eadce4a..00000000
--- a/testutils/src/com/android/nfc/emulator/SinglePaymentEmulatorActivity.java
+++ /dev/null
@@ -1,50 +0,0 @@
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
-package com.android.nfc.emulator;
-
-import android.content.ComponentName;
-import android.os.Bundle;
-import android.util.Log;
-
-import com.android.nfc.service.PaymentService1;
-
-public class SinglePaymentEmulatorActivity extends BaseEmulatorActivity {
-    @Override
-    protected void onCreate(Bundle savedInstanceState) {
-        super.onCreate(savedInstanceState);
-    }
-
-    @Override
-    protected void onResume() {
-        super.onResume();
-        Log.d(TAG, "onResume");
-        setupServices(PaymentService1.COMPONENT);
-        makeDefaultWalletRoleHolder();
-    }
-
-    @Override
-    public void onApduSequenceComplete(ComponentName component, long duration) {
-        if (component.equals(PaymentService1.COMPONENT)) {
-            setTestPassed();
-        }
-    }
-
-    @Override
-    public ComponentName getPreferredServiceComponent() {
-        return PaymentService1.COMPONENT;
-    }
-}
diff --git a/testutils/src/com/android/nfc/emulator/TapTestEmulatorActivity.java b/testutils/src/com/android/nfc/emulator/TapTestEmulatorActivity.java
deleted file mode 100644
index 7b520e59..00000000
--- a/testutils/src/com/android/nfc/emulator/TapTestEmulatorActivity.java
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
-package com.android.nfc.emulator;
-
-import android.content.ComponentName;
-import android.os.Bundle;
-import android.util.Log;
-
-import com.android.nfc.service.ScreenOnOnlyOffHostService;
-import com.android.nfc.service.TransportService1;
-
-public class TapTestEmulatorActivity extends BaseEmulatorActivity {
-
-    private static final String TAG = "TapTestEm";
-
-    @Override
-    protected void onCreate(Bundle savedInstanceState) {
-        super.onCreate(savedInstanceState);
-    }
-
-    @Override
-    protected void onResume() {
-        super.onResume();
-        Log.d(TAG, "onResume");
-        setupServices(TransportService1.COMPONENT);
-    }
-
-    @Override
-    public void onApduSequenceComplete(ComponentName component, long duration) {
-        if (component.equals(TransportService1.COMPONENT)) {
-            setTestPassed();
-        }
-    }
-
-    @Override
-    public ComponentName getPreferredServiceComponent(){
-        return TransportService1.COMPONENT;
-    }
-}
diff --git a/testutils/src/com/android/nfc/emulator/TwoPollingFrameEmulatorActivity.java b/testutils/src/com/android/nfc/emulator/TwoPollingFrameEmulatorActivity.java
index b4d00f09..1c6fe69e 100644
--- a/testutils/src/com/android/nfc/emulator/TwoPollingFrameEmulatorActivity.java
+++ b/testutils/src/com/android/nfc/emulator/TwoPollingFrameEmulatorActivity.java
@@ -65,7 +65,7 @@ public class TwoPollingFrameEmulatorActivity extends BaseEmulatorActivity {
         mCardEmulation.setShouldDefaultToObserveModeForService(serviceName2, true);
 
         mCardEmulation.setPreferredService(this, serviceName1);
-        waitForService();
+        waitForPreferredService();
         waitForObserveModeEnabled(true);
     }
 
diff --git a/testutils/src/com/android/nfc/emulator/res/values-en-rCA/strings.xml b/testutils/src/com/android/nfc/emulator/res/values-en-rCA/strings.xml
new file mode 100644
index 00000000..214eb1f8
--- /dev/null
+++ b/testutils/src/com/android/nfc/emulator/res/values-en-rCA/strings.xml
@@ -0,0 +1,31 @@
+<?xml version="1.0" encoding="UTF-8"?>
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
+   -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="transportService1" msgid="7110581386972746468">"Transport Service #1"</string>
+    <string name="transportService2" msgid="1627086442493069484">"Transport Service #2"</string>
+    <string name="paymentService1" msgid="5034369200915462734">"Payment Service #1"</string>
+    <string name="paymentService2" msgid="7677362631959614876">"Payment Service #2"</string>
+    <string name="offhostService" msgid="2153585078114315278">"Offhost Service"</string>
+    <string name="accessService" msgid="169603026393620416">"Access Service"</string>
+    <string name="screenOffPaymentService" msgid="4807235640853231967">"Screen Off Payment Service"</string>
+    <string name="screenOnOnlyOffHostService" msgid="1209570782652205407">"Screen On Only OffHost Service"</string>
+    <string name="ppse" msgid="3369197818756940218">"PPSE"</string>
+    <string name="mastercard" msgid="2202161212986753725">"MasterCard"</string>
+    <string name="visa" msgid="8369831032637923417">"Visa"</string>
+</resources>
diff --git a/testutils/src/com/android/nfc/emulator/res/xml/payment_aid_list_1.xml b/testutils/src/com/android/nfc/emulator/res/xml/payment_aid_list_1.xml
index 77614ec5..a12308d1 100644
--- a/testutils/src/com/android/nfc/emulator/res/xml/payment_aid_list_1.xml
+++ b/testutils/src/com/android/nfc/emulator/res/xml/payment_aid_list_1.xml
@@ -7,4 +7,5 @@
         <aid-filter android:name="A0000000041010"
             android:description="@string/mastercard"/>
     </aid-group>
+    <polling-loop-filter android:name="41fbc7b9" android:autoTransact="true"/>
 </host-apdu-service>
diff --git a/testutils/src/com/android/nfc/service/AccessServiceTurnObserveModeOnProcessApdu.java b/testutils/src/com/android/nfc/service/AccessServiceTurnObserveModeOnProcessApdu.java
new file mode 100644
index 00000000..fbcc3e9a
--- /dev/null
+++ b/testutils/src/com/android/nfc/service/AccessServiceTurnObserveModeOnProcessApdu.java
@@ -0,0 +1,47 @@
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
+package com.android.nfc.service;
+
+import android.content.ComponentName;
+import android.content.Intent;
+import android.nfc.NfcAdapter;
+import android.os.Bundle;
+
+public class AccessServiceTurnObserveModeOnProcessApdu extends AccessService {
+    public static final ComponentName COMPONENT =
+            new ComponentName(
+                    "com.android.nfc.emulator",
+                    AccessServiceTurnObserveModeOnProcessApdu.class.getName());
+
+    public static final String OBSERVE_MODE_FALSE = "com.android.nfc.service.OBSERVE_MODE_FALSE";
+
+    @Override
+    public ComponentName getComponent() {
+        return AccessServiceTurnObserveModeOnProcessApdu.COMPONENT;
+    }
+
+    @Override
+    public byte[] processCommandApdu(byte[] arg0, Bundle arg1) {
+        if (mApduIndex == 1) {
+            NfcAdapter adapter = NfcAdapter.getDefaultAdapter(this);
+
+            if (adapter != null && !adapter.setObserveModeEnabled(true)) {
+                sendBroadcast(new Intent(OBSERVE_MODE_FALSE));
+            }
+        }
+        return super.processCommandApdu(arg0, arg1);
+    }
+}
diff --git a/testutils/src/com/android/nfc/service/HceService.java b/testutils/src/com/android/nfc/service/HceService.java
index 58d24f70..cb8d9adb 100644
--- a/testutils/src/com/android/nfc/service/HceService.java
+++ b/testutils/src/com/android/nfc/service/HceService.java
@@ -21,8 +21,8 @@ import android.nfc.cardemulation.HostApduService;
 import android.os.Bundle;
 import android.util.Log;
 
-import com.android.nfc.utils.HceUtils;
 import com.android.nfc.utils.CommandApdu;
+import com.android.nfc.utils.HceUtils;
 
 import java.util.Arrays;
 
@@ -35,9 +35,9 @@ public abstract class HceService extends HostApduService {
     public static final String EXTRA_COMPONENT = "component";
     public static final String EXTRA_DURATION = "duration";
 
-    private static final int STATE_IDLE = 0;
-    private static final int STATE_IN_PROGRESS = 1;
-    private static final int STATE_FAILED = 2;
+    protected static final int STATE_IDLE = 0;
+    protected static final int STATE_IN_PROGRESS = 1;
+    protected static final int STATE_FAILED = 2;
 
     // Variables below only used on main thread
     CommandApdu[] mCommandApdus = null;
@@ -82,7 +82,7 @@ public abstract class HceService extends HostApduService {
      */
     @Override
     public byte[] processCommandApdu(byte[] arg0, Bundle arg1) {
-        Log.d(TAG, "processCommandApdu called");
+        Log.d(TAG, "processCommandApdu called: " + HceUtils.getHexBytes("", arg0));
         if (mState == STATE_FAILED) {
             // Don't accept any more APDUs until deactivated
             return null;
@@ -114,7 +114,13 @@ public abstract class HceService extends HostApduService {
 
             if (!Arrays.equals(
                     HceUtils.hexStringToBytes(mCommandApdus[mApduIndex].getApdu()), arg0)) {
-                Log.d(TAG, "Unexpected command APDU: " + HceUtils.getHexBytes("", arg0));
+                Log.d(
+                        TAG,
+                        "Unexpected command APDU. Got: "
+                                + HceUtils.getHexBytes("", arg0)
+                                + ", "
+                                + "expected: "
+                                + mCommandApdus[mApduIndex].getApdu());
                 return null;
             } else {
                 // Send corresponding response APDU
diff --git a/testutils/src/com/android/nfc/service/OffHostService.java b/testutils/src/com/android/nfc/service/OffHostService.java
index d1a839e5..e1db817a 100644
--- a/testutils/src/com/android/nfc/service/OffHostService.java
+++ b/testutils/src/com/android/nfc/service/OffHostService.java
@@ -15,21 +15,18 @@
  */
 package com.android.nfc.service;
 
-import com.android.nfc.utils.HceUtils;
 import android.content.ComponentName;
+import android.content.Intent;
+import android.nfc.cardemulation.OffHostApduService;
+import android.os.IBinder;
 
-public class OffHostService extends HceService {
+public class OffHostService extends OffHostApduService {
     public static final ComponentName COMPONENT = new ComponentName(
             "com.android.nfc.emulator", OffHostService.class.getName()
     );
 
-    public OffHostService() {
-        super(
-                HceUtils.COMMAND_APDUS_BY_SERVICE.get(OffHostService.class.getName()),
-                HceUtils.RESPONSE_APDUS_BY_SERVICE.get(OffHostService.class.getName()));
-    }
     @Override
-    public ComponentName getComponent() {
-        return OffHostService.COMPONENT;
+    public IBinder onBind(Intent intent) {
+        return null;
     }
 }
diff --git a/testutils/src/com/android/nfc/service/PaymentServiceNoIndexReset.java b/testutils/src/com/android/nfc/service/PaymentServiceNoIndexReset.java
new file mode 100644
index 00000000..df72af13
--- /dev/null
+++ b/testutils/src/com/android/nfc/service/PaymentServiceNoIndexReset.java
@@ -0,0 +1,43 @@
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
+package com.android.nfc.service;
+
+import android.content.ComponentName;
+import android.util.Log;
+
+/**
+ * Modifies the behavior of onDeactivated in PaymentService1 to not reset the APDU index when
+ * onDeactivated is called
+ */
+public class PaymentServiceNoIndexReset extends PaymentService1 {
+
+    private static final String TAG = "PaymentService3";
+    public static final ComponentName COMPONENT =
+            new ComponentName("com.android.nfc.emulator",
+                    PaymentServiceNoIndexReset.class.getName());
+
+    @Override
+    public ComponentName getComponent() {
+        return PaymentServiceNoIndexReset.COMPONENT;
+    }
+
+    /** Called when service is deactivated - don't reset the apduIndex. */
+    @Override
+    public void onDeactivated(int arg0) {
+        Log.d(TAG, "onDeactivated");
+        mState = STATE_IDLE;
+    }
+}
diff --git a/testutils/src/com/android/nfc/service/ScreenOnOnlyOffHostService.java b/testutils/src/com/android/nfc/service/ScreenOnOnlyOffHostService.java
index 854957dc..9c22465d 100644
--- a/testutils/src/com/android/nfc/service/ScreenOnOnlyOffHostService.java
+++ b/testutils/src/com/android/nfc/service/ScreenOnOnlyOffHostService.java
@@ -15,11 +15,19 @@
  */
 package com.android.nfc.service;
 import android.content.ComponentName;
+import android.content.Intent;
+import android.nfc.cardemulation.OffHostApduService;
+import android.os.IBinder;
 
-public class ScreenOnOnlyOffHostService {
+public class ScreenOnOnlyOffHostService extends OffHostApduService {
     public static final ComponentName COMPONENT =
             new ComponentName(
                     "com.android.nfc.emulator",
                     ScreenOnOnlyOffHostService.class.getName()
             );
+
+    @Override
+    public IBinder onBind(Intent intent) {
+        return null;
+    }
 }
diff --git a/testutils/src/com/android/nfc/utils/HceUtils.java b/testutils/src/com/android/nfc/utils/HceUtils.java
index 012c35b0..274a2d75 100644
--- a/testutils/src/com/android/nfc/utils/HceUtils.java
+++ b/testutils/src/com/android/nfc/utils/HceUtils.java
@@ -31,6 +31,7 @@ import com.android.nfc.service.OffHostService;
 import com.android.nfc.service.PaymentService1;
 import com.android.nfc.service.PaymentService2;
 import com.android.nfc.service.PaymentServiceDynamicAids;
+import com.android.nfc.service.PollingLoopService;
 import com.android.nfc.service.PrefixAccessService;
 import com.android.nfc.service.PrefixPaymentService1;
 import com.android.nfc.service.PrefixPaymentService2;
@@ -39,7 +40,6 @@ import com.android.nfc.service.PrefixTransportService2;
 import com.android.nfc.service.ScreenOffPaymentService;
 import com.android.nfc.service.ScreenOnOnlyOffHostService;
 import com.android.nfc.service.ThroughputService;
-import com.android.nfc.service.PollingLoopService;
 import com.android.nfc.service.TransportService1;
 import com.android.nfc.service.TransportService2;
 
@@ -70,6 +70,8 @@ public final class HceUtils {
     public static final String LARGE_NUM_AIDS_PREFIX = "F00102030414";
     public static final String LARGE_NUM_AIDS_POSTFIX = "81";
 
+    public static final String EMULATOR_PACKAGE_NAME = "com.android.nfc.emulator";
+
     /** Service-specific APDU Command/Response sequences */
     public static final HashMap<String, CommandApdu[]> COMMAND_APDUS_BY_SERVICE = new HashMap<>();
 
```

