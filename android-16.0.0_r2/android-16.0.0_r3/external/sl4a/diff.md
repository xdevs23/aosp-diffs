```diff
diff --git a/ScriptingLayerForAndroid/AndroidManifest.xml b/ScriptingLayerForAndroid/AndroidManifest.xml
index e937bcff..5bf36665 100644
--- a/ScriptingLayerForAndroid/AndroidManifest.xml
+++ b/ScriptingLayerForAndroid/AndroidManifest.xml
@@ -204,8 +204,8 @@
         <activity android:name=".activity.FutureActivity" android:configChanges="keyboardHidden|orientation" android:theme="@android:style/Theme.DeviceDefault.NoActionBar.TranslucentDecor" />
         <activity android:name="org.connectbot.HelpActivity" android:configChanges="keyboardHidden|orientation" />
         <activity android:name="org.connectbot.HelpTopicActivity" android:configChanges="keyboardHidden|orientation" />
-        <service android:name=".service.ScriptingLayerService" />
-        <service android:name=".service.TriggerService" />
+        <service android:name=".service.ScriptingLayerService" android:foregroundServiceType="remoteMessaging"/>
+        <service android:name=".service.TriggerService" android:foregroundServiceType="remoteMessaging"/>
         <service android:name="com.googlecode.android_scripting.facade.telephony.InCallServiceImpl"
                  android:permission="android.permission.BIND_INCALL_SERVICE"
                  android:exported="true">
@@ -215,7 +215,7 @@
             <meta-data android:name="android.telecom.INCLUDE_EXTERNAL_CALLS" android:value="true" />
             <meta-data android:name="android.telecom.INCLUDE_SELF_MANAGED_CALLS" android:value="true" />
         </service>
-        <service android:name=".service.FacadeService" android:enabled="true" android:exported="true" >
+        <service android:name=".service.FacadeService" android:enabled="true" android:exported="true" android:foregroundServiceType="remoteMessaging">
             <intent-filter>
                 <action android:name="com.googlecode.android_scripting.service.FacadeService.ACTION_BIND" />
             </intent-filter>
```

