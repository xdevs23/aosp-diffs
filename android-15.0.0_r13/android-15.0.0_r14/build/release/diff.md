```diff
diff --git a/aconfig/ap3a/com.android.server.backup/enable_increased_bmm_logging_for_restore_at_install_flag_values.textproto b/aconfig/ap3a/com.android.server.backup/enable_increased_bmm_logging_for_restore_at_install_flag_values.textproto
index 9822ed57..b3d1ff19 100644
--- a/aconfig/ap3a/com.android.server.backup/enable_increased_bmm_logging_for_restore_at_install_flag_values.textproto
+++ b/aconfig/ap3a/com.android.server.backup/enable_increased_bmm_logging_for_restore_at_install_flag_values.textproto
@@ -1,6 +1,6 @@
 flag_value {
   package: "com.android.server.backup"
   name: "enable_increased_bmm_logging_for_restore_at_install"
-  state: DISABLED
+  state: ENABLED
   permission: READ_ONLY
 }
diff --git a/aconfig/ap4a/Android.bp b/aconfig/ap4a/Android.bp
index fa762a32..c0f1713b 100644
--- a/aconfig/ap4a/Android.bp
+++ b/aconfig/ap4a/Android.bp
@@ -13,212 +13,163 @@
 // limitations under the License.
 
 aconfig_value_set {
-  name: "aconfig_value_set-platform_build_release-ap4a",
-  values: [
-        "aconfig-values-platform_build_release-ap4a-android.service.autofill-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.server.deviceidle-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.hardware.libsensor.flags-all",
-        "aconfig-values-platform_build_release-ap4a-android.permission.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.server.power.feature.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.providers.contacts.flags-all",
-        "aconfig-values-platform_build_release-ap4a-android.media.codec-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.providers.media.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.media.audioserver-all",
-        "aconfig-values-platform_build_release-ap4a-android.hardware.flags-all",
-        "aconfig-values-platform_build_release-ap4a-android.content.flags-all",
-        "aconfig-values-platform_build_release-ap4a-android.os.profiling-all",
-        "aconfig-values-platform_build_release-ap4a-com.google.android.iwlan.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.server.deviceconfig-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.graphics.libgui.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.server.power.optimization-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.sdksandbox.flags-all",
-        "aconfig-values-platform_build_release-ap4a-android.media.audio-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.launcher3-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.server.telecom.flags-all",
-        "aconfig-values-platform_build_release-ap4a-android.view.contentprotection.flags-all",
-        "aconfig-values-platform_build_release-ap4a-android.car.feature-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.server.usage-all",
-        "aconfig-values-platform_build_release-ap4a-android.security.flag-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.media.aaudio-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.server.feature.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.internal.pm.pkg.component.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.settingslib.media.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.server.connectivity-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.server.usb.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.internal.jank-all",
-        "aconfig-values-platform_build_release-ap4a-android.nfc-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.os.statsd.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.server.notification-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.trunk_stable_workflow_testing-all",
-        "aconfig-values-platform_build_release-ap4a-android.content.pm-all",
-        "aconfig-values-platform_build_release-ap4a-android.server-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.server.accessibility-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.media.mainline.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.server.backup-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.media.projection.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.libcore-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.media.codec.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.nfc.nci.flags-all",
-        "aconfig-values-platform_build_release-ap4a-android.provider.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.adservices.ondevicepersonalization.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.frameworks.sensorservice.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.settings.media_drm-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.hardware.input-all",
-        "aconfig-values-platform_build_release-ap4a-android.media.midi-all",
-        "aconfig-values-platform_build_release-ap4a-android.service.appprediction.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.graphics.libvulkan.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.car.settings-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.hardware.camera2-all",
-        "aconfig-values-platform_build_release-ap4a-android.appwidget.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.server.alarm-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.intentresolver-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.healthfitness.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.server.updates-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.car.carlauncher-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.wallpaper-all",
-        "aconfig-values-platform_build_release-ap4a-android.chre.flags-all",
-        "aconfig-values-platform_build_release-ap4a-android.provider.configinfrastructure.framework-all",
-        "aconfig-values-platform_build_release-ap4a-android.server.app-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.telephony.phone.flags-all",
-        "aconfig-values-platform_build_release-ap4a-android.location.flags-all",
-        "aconfig-values-platform_build_release-ap4a-android.service.voice.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.wm.shell-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.settings.connecteddevice.flags-all",
-        "aconfig-values-platform_build_release-ap4a-android.net.wifi.flags-all",
-        "aconfig-values-platform_build_release-ap4a-android.adaptiveauth-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.car.dockutil-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.media.editing.flags-all",
-        "aconfig-values-platform_build_release-ap4a-android.app.jank-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.settings.keyboard-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.server.companion.virtual-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.settings.flags-all",
-        "aconfig-values-platform_build_release-ap4a-android.companion-all",
-        "aconfig-values-platform_build_release-ap4a-vendor.vibrator.hal.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.system.virtualmachine.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.settingslib.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.car.datasubscription-all",
-        "aconfig-values-platform_build_release-ap4a-android.os-all",
-        "aconfig-values-platform_build_release-ap4a-android.companion.virtualdevice.flags-all",
-        "aconfig-values-platform_build_release-ap4a-android.tracing-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.server.power.hint-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.btaudio.hal.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.graphics.flags-all",
-        "aconfig-values-platform_build_release-ap4a-android.widget.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.server.net-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.aconfig.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.media.audioclient-all",
-        "aconfig-values-platform_build_release-ap4a-android.net.vcn-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.settingslib.widget.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.graphics.hwui.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.graphics.bufferstreams.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.aconfig.test-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.systemui.shared-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.graphics.surfaceflinger.flags-all",
-        "aconfig-values-platform_build_release-ap4a-android.credentials.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.art.flags-all",
-        "aconfig-values-platform_build_release-ap4a-android.hardware.radio-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.managedprovisioning.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.org.conscrypt-all",
-        "aconfig-values-platform_build_release-ap4a-android.os.vibrator-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.devicelock.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.server.job-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.internal.foldables.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.settings.development-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.settings.factory_reset-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.systemui.communal-all",
-        "aconfig-values-platform_build_release-ap4a-android.view.contentcapture.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.healthconnect.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.bluetooth.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.media.flags-all",
-        "aconfig-values-platform_build_release-ap4a-android.multiuser-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.server.policy-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.systemui.accessibility.accessibilitymenu-all",
-        "aconfig-values-platform_build_release-ap4a-android.service.dreams-all",
-        "aconfig-values-platform_build_release-ap4a-android.crashrecovery.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.uwb.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.server.dreams-all",
-        "aconfig-values-platform_build_release-ap4a-android.app.job-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.egg.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.icu-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.settingslib.widget.selectorwithwidgetpreference.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.media.playback.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.internal.camera.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.systemui.aconfig-all",
-        "aconfig-values-platform_build_release-ap4a-android.service.notification-all",
-        "aconfig-values-platform_build_release-ap4a-com.example.android.aconfig.demo.flags-all",
-        "aconfig-values-platform_build_release-ap4a-android.security-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.net.thread.flags-all",
-        "aconfig-values-platform_build_release-ap4a-android.service.controls.flags-all",
-        "aconfig-values-platform_build_release-ap4a-android.hardware.usb.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.adservices.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.wifi.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.google.android.platform.launcher.aconfig.flags-all",
-        "aconfig-values-platform_build_release-ap4a-android.view.accessibility-all",
-        "aconfig-values-platform_build_release-ap4a-android.app.appfunctions.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.providers.settings-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.systemui-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.server.utils-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.cellbroadcastreceiver.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.server.devicepolicy.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.settings.accessibility-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.internal.compat.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.server.policy.feature.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.media.performance.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.aconfig_new_storage-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.server.stats-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.permission.flags-all",
-        "aconfig-values-platform_build_release-ap4a-android.app.wearable-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.server.security-all",
-        "aconfig-values-platform_build_release-ap4a-android.app.ondeviceintelligence.flags-all",
-        "aconfig-values-platform_build_release-ap4a-android.app.admin.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.ipsec.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.nearby.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.server.os-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.server.contextualsearch.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.input.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.net.ct.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.server.pm-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.server.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.libhardware.dynamic.sensors.flags-all",
-        "aconfig-values-platform_build_release-ap4a-android.graphics.pdf.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.deviceaswebcam.flags-all",
-        "aconfig-values-platform_build_release-ap4a-android.database.sqlite-all",
-        "aconfig-values-platform_build_release-ap4a-android.service.chooser-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.net.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.server.power.batterysaver-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.server.biometrics-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.text.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.net.thread.platform.flags-all",
-        "aconfig-values-platform_build_release-ap4a-android.view.inputmethod-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.providers.contactkeys.flags-all",
-        "aconfig-values-platform_build_release-ap4a-android.view.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.systemui.car-all",
-        "aconfig-values-platform_build_release-ap4a-android.media.audiopolicy-all",
-        "aconfig-values-platform_build_release-ap4a-android.media.soundtrigger-all",
-        "aconfig-values-platform_build_release-ap4a-android.security.keystore2-all",
-        "aconfig-values-platform_build_release-ap4a-android.app.smartspace.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.media.audio-all",
-        "aconfig-values-platform_build_release-ap4a-android.net.platform.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.server.am-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.server.display.feature.flags-all",
-        "aconfig-values-platform_build_release-ap4a-android.hardware.devicestate.feature.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.window.flags-all",
-        "aconfig-values-platform_build_release-ap4a-android.app.contextualsearch.flags-all",
-        "aconfig-values-platform_build_release-ap4a-android.hardware.biometrics-all",
-        "aconfig-values-platform_build_release-ap4a-android.speech.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.server.powerstats-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.internal.os-all",
-        "aconfig-values-platform_build_release-ap4a-android.content.res-all",
-        "aconfig-values-platform_build_release-ap4a-android.app.usage-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.nfc.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.server.locksettings-all",
-        "aconfig-values-platform_build_release-ap4a-android.sdk-all",
-        "aconfig-values-platform_build_release-ap4a-android.provider-all",
-        "aconfig-values-platform_build_release-ap4a-android.app-all",
-        "aconfig-values-platform_build_release-ap4a-android.companion.virtual.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.appsearch.flags-all",
-        "aconfig-values-platform_build_release-ap4a-com.android.internal.telephony.flags-all",
-        "aconfig-values-platform_build_release-ap4a-android.media.tv.flags-all",
-        "aconfig-values-platform_build_release-ap4a-android.webkit-all",
-      ]
+    name: "aconfig_value_set-platform_build_release-ap4a",
+    values: [
+      "aconfig-values-platform_build_release-ap4a-com.android.server.alarm-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.systemui.accessibility.accessibilitymenu-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.server.notification-all",
+      "aconfig-values-platform_build_release-ap4a-android.companion-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.providers.settings-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.btaudio.hal.flags-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.server.powerstats-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.uwb.flags-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.server.biometrics-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.internal.pm.pkg.component.flags-all",
+      "aconfig-values-platform_build_release-ap4a-android.net.wifi.flags-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.providers.media.flags-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.adservices.flags-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.server.stats-all",
+      "aconfig-values-platform_build_release-ap4a-android.content.pm-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.server.policy-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.server.power.batterysaver-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.systemui-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.media.playback.flags-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.intentresolver-all",
+      "aconfig-values-platform_build_release-ap4a-android.provider-all",
+      "aconfig-values-platform_build_release-ap4a-android.multiuser-all",
+      "aconfig-values-platform_build_release-ap4a-android.hardware.devicestate.feature.flags-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.server.backup-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.server.deviceidle-all",
+      "aconfig-values-platform_build_release-ap4a-android.database.sqlite-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.media.audio-all",
+      "aconfig-values-platform_build_release-ap4a-android.app.contextualsearch.flags-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.media.performance.flags-all",
+      "aconfig-values-platform_build_release-ap4a-android.service.notification-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.server.net-all",
+      "aconfig-values-platform_build_release-ap4a-android.permission.flags-all",
+      "aconfig-values-platform_build_release-ap4a-android.view.inputmethod-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.internal.telephony.flags-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.net.flags-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.internal.foldables.flags-all",
+      "aconfig-values-platform_build_release-ap4a-android.net.platform.flags-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.media.flags-all",
+      "aconfig-values-platform_build_release-ap4a-android.webkit-all",
+      "aconfig-values-platform_build_release-ap4a-android.hardware.usb.flags-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.settingslib.widget.selectorwithwidgetpreference.flags-all",
+      "aconfig-values-platform_build_release-ap4a-android.view.contentcapture.flags-all",
+      "aconfig-values-platform_build_release-ap4a-android.service.voice.flags-all",
+      "aconfig-values-platform_build_release-ap4a-android.service.dreams-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.launcher3-all",
+      "aconfig-values-platform_build_release-ap4a-android.crashrecovery.flags-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.server.power.hint-all",
+      "aconfig-values-platform_build_release-ap4a-android.security.flag-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.server.flags-all",
+      "aconfig-values-platform_build_release-ap4a-android.app.job-all",
+      "aconfig-values-platform_build_release-ap4a-android.app-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.permission.flags-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.server.feature.flags-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.settings.accessibility-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.aconfig.test-all",
+      "aconfig-values-platform_build_release-ap4a-android.view.flags-all",
+      "aconfig-values-platform_build_release-ap4a-android.security-all",
+      "aconfig-values-platform_build_release-ap4a-android.hardware.biometrics-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.server.power.feature.flags-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.media.audioserver-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.car.carlauncher-all",
+      "aconfig-values-platform_build_release-ap4a-android.service.autofill-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.settingslib.widget.flags-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.bluetooth.flags-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.settings.development-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.settings.media_drm-all",
+      "aconfig-values-platform_build_release-ap4a-android.location.flags-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.server.policy.feature.flags-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.wm.shell-all",
+      "aconfig-values-platform_build_release-ap4a-android.service.controls.flags-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.server.accessibility-all",
+      "aconfig-values-platform_build_release-ap4a-vendor.vibrator.hal.flags-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.hardware.libsensor.flags-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.settings.flags-all",
+      "aconfig-values-platform_build_release-ap4a-android.nfc-all",
+      "aconfig-values-platform_build_release-ap4a-android.speech.flags-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.media.codec.flags-all",
+      "aconfig-values-platform_build_release-ap4a-android.os-all",
+      "aconfig-values-platform_build_release-ap4a-android.service.chooser-all",
+      "aconfig-values-platform_build_release-ap4a-android.widget.flags-all",
+      "aconfig-values-platform_build_release-ap4a-android.media.midi-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.settings.factory_reset-all",
+      "aconfig-values-platform_build_release-ap4a-android.companion.virtualdevice.flags-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.server.usb.flags-all",
+      "aconfig-values-platform_build_release-ap4a-android.os.profiling-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.hardware.input-all",
+      "aconfig-values-platform_build_release-ap4a-android.app.wearable-all",
+      "aconfig-values-platform_build_release-ap4a-android.media.codec-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.providers.contactkeys.flags-all",
+      "aconfig-values-platform_build_release-ap4a-android.content.res-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.server.dreams-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.systemui.shared-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.wifi.flags-all",
+      "aconfig-values-platform_build_release-ap4a-android.app.smartspace.flags-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.car.datasubscription-all",
+      "aconfig-values-platform_build_release-ap4a-android.graphics.pdf.flags-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.sdksandbox.flags-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.systemui.car-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.nearby.flags-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.deviceaswebcam.flags-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.window.flags-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.server.job-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.media.editing.flags-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.ipsec.flags-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.icu-all",
+      "aconfig-values-platform_build_release-ap4a-android.content.flags-all",
+      "aconfig-values-platform_build_release-ap4a-android.view.accessibility-all",
+      "aconfig-values-platform_build_release-ap4a-android.hardware.radio-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.server.deviceconfig-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.internal.compat.flags-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.media.aaudio-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.input.flags-all",
+      "aconfig-values-platform_build_release-ap4a-android.app.usage-all",
+      "aconfig-values-platform_build_release-ap4a-android.credentials.flags-all",
+      "aconfig-values-platform_build_release-ap4a-android.app.ondeviceintelligence.flags-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.settingslib.media.flags-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.system.virtualmachine.flags-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.appsearch.flags-all",
+      "aconfig-values-platform_build_release-ap4a-android.app.admin.flags-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.car.settings-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.graphics.libgui.flags-all",
+      "aconfig-values-platform_build_release-ap4a-android.car.feature-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.internal.camera.flags-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.server.usage-all",
+      "aconfig-values-platform_build_release-ap4a-android.companion.virtual.flags-all",
+      "aconfig-values-platform_build_release-ap4a-android.os.vibrator-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.server.power.optimization-all",
+      "aconfig-values-platform_build_release-ap4a-android.hardware.flags-all",
+      "aconfig-values-platform_build_release-ap4a-android.media.audiopolicy-all",
+      "aconfig-values-platform_build_release-ap4a-android.net.vcn-all",
+      "aconfig-values-platform_build_release-ap4a-android.view.contentprotection.flags-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.server.display.feature.flags-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.media.mainline.flags-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.settingslib.flags-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.net.thread.flags-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.server.am-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.healthconnect.flags-all",
+      "aconfig-values-platform_build_release-ap4a-android.media.audio-all",
+      "aconfig-values-platform_build_release-ap4a-android.adaptiveauth-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.graphics.surfaceflinger.flags-all",
+      "aconfig-values-platform_build_release-ap4a-android.server.app-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.adservices.ondevicepersonalization.flags-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.car.dockutil-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.internal.os-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.text.flags-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.nfc.flags-all",
+      "aconfig-values-platform_build_release-ap4a-android.chre.flags-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.frameworks.sensorservice.flags-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.libcore-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.graphics.hwui.flags-all",
+      "aconfig-values-platform_build_release-ap4a-com.google.android.iwlan.flags-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.libhardware.dynamic.sensors.flags-all",
+      "aconfig-values-platform_build_release-ap4a-android.server-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.server.telecom.flags-all",
+      "aconfig-values-platform_build_release-ap4a-android.appwidget.flags-all",
+      "aconfig-values-platform_build_release-ap4a-com.android.egg.flags-all"
+    ]
 }
diff --git a/aconfig/ap4a/android.app.admin.flags/allow_screen_brightness_control_on_cope_flag_values.textproto b/aconfig/ap4a/android.app.admin.flags/allow_screen_brightness_control_on_cope_flag_values.textproto
deleted file mode 100644
index a6e7b7f4..00000000
--- a/aconfig/ap4a/android.app.admin.flags/allow_screen_brightness_control_on_cope_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.app.admin.flags"
-  name: "allow_screen_brightness_control_on_cope"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/android.app.admin.flags/always_persist_do_flag_values.textproto b/aconfig/ap4a/android.app.admin.flags/always_persist_do_flag_values.textproto
deleted file mode 100644
index 48f783b4..00000000
--- a/aconfig/ap4a/android.app.admin.flags/always_persist_do_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.app.admin.flags"
-  name: "always_persist_do"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/android.app.admin.flags/coexistence_migration_for_non_emm_management_enabled_flag_values.textproto b/aconfig/ap4a/android.app.admin.flags/coexistence_migration_for_non_emm_management_enabled_flag_values.textproto
deleted file mode 100644
index 38993b86..00000000
--- a/aconfig/ap4a/android.app.admin.flags/coexistence_migration_for_non_emm_management_enabled_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.app.admin.flags"
-  name: "coexistence_migration_for_non_emm_management_enabled"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/android.app.admin.flags/copy_account_with_retry_enabled_flag_values.textproto b/aconfig/ap4a/android.app.admin.flags/copy_account_with_retry_enabled_flag_values.textproto
deleted file mode 100644
index a411289f..00000000
--- a/aconfig/ap4a/android.app.admin.flags/copy_account_with_retry_enabled_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.app.admin.flags"
-  name: "copy_account_with_retry_enabled"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/android.app.admin.flags/dedicated_device_control_enabled_flag_values.textproto b/aconfig/ap4a/android.app.admin.flags/dedicated_device_control_enabled_flag_values.textproto
deleted file mode 100644
index c7b7af0d..00000000
--- a/aconfig/ap4a/android.app.admin.flags/dedicated_device_control_enabled_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.app.admin.flags"
-  name: "dedicated_device_control_enabled"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/android.app.admin.flags/delete_private_space_under_restriction_flag_values.textproto b/aconfig/ap4a/android.app.admin.flags/delete_private_space_under_restriction_flag_values.textproto
deleted file mode 100644
index 781503a1..00000000
--- a/aconfig/ap4a/android.app.admin.flags/delete_private_space_under_restriction_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.app.admin.flags"
-  name: "delete_private_space_under_restriction"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/android.app.admin.flags/device_policy_size_tracking_internal_bug_fix_enabled_flag_values.textproto b/aconfig/ap4a/android.app.admin.flags/device_policy_size_tracking_internal_bug_fix_enabled_flag_values.textproto
deleted file mode 100644
index 637e161c..00000000
--- a/aconfig/ap4a/android.app.admin.flags/device_policy_size_tracking_internal_bug_fix_enabled_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.app.admin.flags"
-  name: "device_policy_size_tracking_internal_bug_fix_enabled"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/android.app.admin.flags/disallow_user_control_bg_usage_fix_flag_values.textproto b/aconfig/ap4a/android.app.admin.flags/disallow_user_control_bg_usage_fix_flag_values.textproto
deleted file mode 100644
index 798cac36..00000000
--- a/aconfig/ap4a/android.app.admin.flags/disallow_user_control_bg_usage_fix_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.app.admin.flags"
-  name: "disallow_user_control_bg_usage_fix"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/android.app.admin.flags/dmrh_set_app_restrictions_flag_values.textproto b/aconfig/ap4a/android.app.admin.flags/dmrh_set_app_restrictions_flag_values.textproto
deleted file mode 100644
index d16c94c8..00000000
--- a/aconfig/ap4a/android.app.admin.flags/dmrh_set_app_restrictions_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.app.admin.flags"
-  name: "dmrh_set_app_restrictions"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/android.app.admin.flags/dumpsys_policy_engine_migration_enabled_flag_values.textproto b/aconfig/ap4a/android.app.admin.flags/dumpsys_policy_engine_migration_enabled_flag_values.textproto
deleted file mode 100644
index a191802a..00000000
--- a/aconfig/ap4a/android.app.admin.flags/dumpsys_policy_engine_migration_enabled_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.app.admin.flags"
-  name: "dumpsys_policy_engine_migration_enabled"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/android.app.admin.flags/headless_device_owner_delegate_security_logging_bug_fix_flag_values.textproto b/aconfig/ap4a/android.app.admin.flags/headless_device_owner_delegate_security_logging_bug_fix_flag_values.textproto
deleted file mode 100644
index 9c652115..00000000
--- a/aconfig/ap4a/android.app.admin.flags/headless_device_owner_delegate_security_logging_bug_fix_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.app.admin.flags"
-  name: "headless_device_owner_delegate_security_logging_bug_fix"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/android.app.admin.flags/headless_device_owner_provisioning_fix_enabled_flag_values.textproto b/aconfig/ap4a/android.app.admin.flags/headless_device_owner_provisioning_fix_enabled_flag_values.textproto
deleted file mode 100644
index 4270e086..00000000
--- a/aconfig/ap4a/android.app.admin.flags/headless_device_owner_provisioning_fix_enabled_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.app.admin.flags"
-  name: "headless_device_owner_provisioning_fix_enabled"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/android.app.admin.flags/headless_single_user_bad_device_admin_state_fix_flag_values.textproto b/aconfig/ap4a/android.app.admin.flags/headless_single_user_bad_device_admin_state_fix_flag_values.textproto
deleted file mode 100644
index 2f80a21b..00000000
--- a/aconfig/ap4a/android.app.admin.flags/headless_single_user_bad_device_admin_state_fix_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.app.admin.flags"
-  name: "headless_single_user_bad_device_admin_state_fix"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/android.app.admin.flags/headless_single_user_compatibility_fix_flag_values.textproto b/aconfig/ap4a/android.app.admin.flags/headless_single_user_compatibility_fix_flag_values.textproto
deleted file mode 100644
index ced1da40..00000000
--- a/aconfig/ap4a/android.app.admin.flags/headless_single_user_compatibility_fix_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.app.admin.flags"
-  name: "headless_single_user_compatibility_fix"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/android.app.admin.flags/headless_single_user_fixes_flag_values.textproto b/aconfig/ap4a/android.app.admin.flags/headless_single_user_fixes_flag_values.textproto
deleted file mode 100644
index 5f16586d..00000000
--- a/aconfig/ap4a/android.app.admin.flags/headless_single_user_fixes_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.app.admin.flags"
-  name: "headless_single_user_fixes"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/android.app.admin.flags/hsum_unlock_notification_fix_flag_values.textproto b/aconfig/ap4a/android.app.admin.flags/hsum_unlock_notification_fix_flag_values.textproto
deleted file mode 100644
index af13126e..00000000
--- a/aconfig/ap4a/android.app.admin.flags/hsum_unlock_notification_fix_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.app.admin.flags"
-  name: "hsum_unlock_notification_fix"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/android.app.admin.flags/permission_migration_for_zero_trust_impl_enabled_flag_values.textproto b/aconfig/ap4a/android.app.admin.flags/permission_migration_for_zero_trust_impl_enabled_flag_values.textproto
deleted file mode 100644
index a49d304c..00000000
--- a/aconfig/ap4a/android.app.admin.flags/permission_migration_for_zero_trust_impl_enabled_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.app.admin.flags"
-  name: "permission_migration_for_zero_trust_impl_enabled"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/android.app.admin.flags/power_exemption_bg_usage_fix_flag_values.textproto b/aconfig/ap4a/android.app.admin.flags/power_exemption_bg_usage_fix_flag_values.textproto
deleted file mode 100644
index c6656793..00000000
--- a/aconfig/ap4a/android.app.admin.flags/power_exemption_bg_usage_fix_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.app.admin.flags"
-  name: "power_exemption_bg_usage_fix"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/android.app.appfunctions.flags/Android.bp b/aconfig/ap4a/android.app.appfunctions.flags/Android.bp
deleted file mode 100644
index e91a45d2..00000000
--- a/aconfig/ap4a/android.app.appfunctions.flags/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-ap4a-android.app.appfunctions.flags-all",
-  package: "android.app.appfunctions.flags",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/ap4a/android.app.jank/Android.bp b/aconfig/ap4a/android.app.jank/Android.bp
deleted file mode 100644
index 0eb0e4cb..00000000
--- a/aconfig/ap4a/android.app.jank/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-ap4a-android.app.jank-all",
-  package: "android.app.jank",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/ap4a/android.chre.flags/bug_fix_reduce_lock_holding_period_flag_values.textproto b/aconfig/ap4a/android.chre.flags/bug_fix_reduce_lock_holding_period_flag_values.textproto
deleted file mode 100644
index 68053671..00000000
--- a/aconfig/ap4a/android.chre.flags/bug_fix_reduce_lock_holding_period_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.chre.flags"
-  name: "bug_fix_reduce_lock_holding_period"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/android.chre.flags/flag_log_nanoapp_load_metrics_flag_values.textproto b/aconfig/ap4a/android.chre.flags/flag_log_nanoapp_load_metrics_flag_values.textproto
deleted file mode 100644
index 0fccef1e..00000000
--- a/aconfig/ap4a/android.chre.flags/flag_log_nanoapp_load_metrics_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.chre.flags"
-  name: "flag_log_nanoapp_load_metrics"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/android.chre.flags/metrics_reporter_in_the_daemon_flag_values.textproto b/aconfig/ap4a/android.chre.flags/metrics_reporter_in_the_daemon_flag_values.textproto
deleted file mode 100644
index feefe54b..00000000
--- a/aconfig/ap4a/android.chre.flags/metrics_reporter_in_the_daemon_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.chre.flags"
-  name: "metrics_reporter_in_the_daemon"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/android.chre.flags/remove_ap_wakeup_metric_report_limit_flag_values.textproto b/aconfig/ap4a/android.chre.flags/remove_ap_wakeup_metric_report_limit_flag_values.textproto
deleted file mode 100644
index 8fbd5143..00000000
--- a/aconfig/ap4a/android.chre.flags/remove_ap_wakeup_metric_report_limit_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.chre.flags"
-  name: "remove_ap_wakeup_metric_report_limit"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/android.companion.virtual.flags/consistent_display_flags_flag_values.textproto b/aconfig/ap4a/android.companion.virtual.flags/consistent_display_flags_flag_values.textproto
deleted file mode 100644
index 6e2709f7..00000000
--- a/aconfig/ap4a/android.companion.virtual.flags/consistent_display_flags_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.companion.virtual.flags"
-  name: "consistent_display_flags"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/android.companion.virtual.flags/express_metrics_flag_values.textproto b/aconfig/ap4a/android.companion.virtual.flags/express_metrics_flag_values.textproto
deleted file mode 100644
index 3e9f6bd2..00000000
--- a/aconfig/ap4a/android.companion.virtual.flags/express_metrics_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.companion.virtual.flags"
-  name: "express_metrics"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/android.companion.virtual.flags/interactive_screen_mirror_flag_values.textproto b/aconfig/ap4a/android.companion.virtual.flags/interactive_screen_mirror_flag_values.textproto
deleted file mode 100644
index afad149d..00000000
--- a/aconfig/ap4a/android.companion.virtual.flags/interactive_screen_mirror_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.companion.virtual.flags"
-  name: "interactive_screen_mirror"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/android.companion.virtual.flags/intercept_intents_before_applying_policy_flag_values.textproto b/aconfig/ap4a/android.companion.virtual.flags/intercept_intents_before_applying_policy_flag_values.textproto
deleted file mode 100644
index befd0c4f..00000000
--- a/aconfig/ap4a/android.companion.virtual.flags/intercept_intents_before_applying_policy_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.companion.virtual.flags"
-  name: "intercept_intents_before_applying_policy"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/android.companion.virtual.flags/stream_permissions_flag_values.textproto b/aconfig/ap4a/android.companion.virtual.flags/stream_permissions_flag_values.textproto
deleted file mode 100644
index f1e4abfa..00000000
--- a/aconfig/ap4a/android.companion.virtual.flags/stream_permissions_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.companion.virtual.flags"
-  name: "stream_permissions"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/android.companion.virtualdevice.flags/intent_interception_action_matching_fix_flag_values.textproto b/aconfig/ap4a/android.companion.virtualdevice.flags/intent_interception_action_matching_fix_flag_values.textproto
deleted file mode 100644
index 81ab2e6a..00000000
--- a/aconfig/ap4a/android.companion.virtualdevice.flags/intent_interception_action_matching_fix_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.companion.virtualdevice.flags"
-  name: "intent_interception_action_matching_fix"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/android.companion.virtualdevice.flags/metrics_collection_flag_values.textproto b/aconfig/ap4a/android.companion.virtualdevice.flags/metrics_collection_flag_values.textproto
deleted file mode 100644
index ff413d9d..00000000
--- a/aconfig/ap4a/android.companion.virtualdevice.flags/metrics_collection_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.companion.virtualdevice.flags"
-  name: "metrics_collection"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/android.companion.virtualdevice.flags/virtual_display_multi_window_mode_support_flag_values.textproto b/aconfig/ap4a/android.companion.virtualdevice.flags/virtual_display_multi_window_mode_support_flag_values.textproto
deleted file mode 100644
index 88a72cbf..00000000
--- a/aconfig/ap4a/android.companion.virtualdevice.flags/virtual_display_multi_window_mode_support_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.companion.virtualdevice.flags"
-  name: "virtual_display_multi_window_mode_support"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/android.media.soundtrigger/Android.bp b/aconfig/ap4a/android.media.soundtrigger/Android.bp
deleted file mode 100644
index 14d0c405..00000000
--- a/aconfig/ap4a/android.media.soundtrigger/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-ap4a-android.media.soundtrigger-all",
-  package: "android.media.soundtrigger",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/ap4a/android.media.tv.flags/Android.bp b/aconfig/ap4a/android.media.tv.flags/Android.bp
deleted file mode 100644
index 59ec5065..00000000
--- a/aconfig/ap4a/android.media.tv.flags/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-ap4a-android.media.tv.flags-all",
-  package: "android.media.tv.flags",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/ap4a/android.net.vcn/allow_disable_ipsec_loss_detector_flag_values.textproto b/aconfig/ap4a/android.net.vcn/allow_disable_ipsec_loss_detector_flag_values.textproto
deleted file mode 100644
index da2ea944..00000000
--- a/aconfig/ap4a/android.net.vcn/allow_disable_ipsec_loss_detector_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.net.vcn"
-  name: "allow_disable_ipsec_loss_detector"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/android.os.vibrator/keyboard_category_enabled_flag_values.textproto b/aconfig/ap4a/android.os.vibrator/keyboard_category_enabled_flag_values.textproto
deleted file mode 100644
index 9c51ed42..00000000
--- a/aconfig/ap4a/android.os.vibrator/keyboard_category_enabled_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.os.vibrator"
-  name: "keyboard_category_enabled"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/android.os.vibrator/use_vibrator_haptic_feedback_flag_values.textproto b/aconfig/ap4a/android.os.vibrator/use_vibrator_haptic_feedback_flag_values.textproto
deleted file mode 100644
index 53803180..00000000
--- a/aconfig/ap4a/android.os.vibrator/use_vibrator_haptic_feedback_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.os.vibrator"
-  name: "use_vibrator_haptic_feedback"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/android.os/bugreport_mode_max_value_flag_values.textproto b/aconfig/ap4a/android.os/bugreport_mode_max_value_flag_values.textproto
deleted file mode 100644
index ec2b3d95..00000000
--- a/aconfig/ap4a/android.os/bugreport_mode_max_value_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.os"
-  name: "bugreport_mode_max_value"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/android.provider.configinfrastructure.framework/Android.bp b/aconfig/ap4a/android.provider.configinfrastructure.framework/Android.bp
deleted file mode 100644
index 161af532..00000000
--- a/aconfig/ap4a/android.provider.configinfrastructure.framework/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-ap4a-android.provider.configinfrastructure.framework-all",
-  package: "android.provider.configinfrastructure.framework",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/ap4a/android.provider.flags/Android.bp b/aconfig/ap4a/android.provider.flags/Android.bp
deleted file mode 100644
index 3eeb2d38..00000000
--- a/aconfig/ap4a/android.provider.flags/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-ap4a-android.provider.flags-all",
-  package: "android.provider.flags",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/ap4a/android.sdk/Android.bp b/aconfig/ap4a/android.sdk/Android.bp
deleted file mode 100644
index dd32af16..00000000
--- a/aconfig/ap4a/android.sdk/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-ap4a-android.sdk-all",
-  package: "android.sdk",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/ap4a/android.security.keystore2/Android.bp b/aconfig/ap4a/android.security.keystore2/Android.bp
deleted file mode 100644
index b245f5fe..00000000
--- a/aconfig/ap4a/android.security.keystore2/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-ap4a-android.security.keystore2-all",
-  package: "android.security.keystore2",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/ap4a/android.security/fix_unlocked_device_required_keys_v2_flag_values.textproto b/aconfig/ap4a/android.security/fix_unlocked_device_required_keys_v2_flag_values.textproto
deleted file mode 100644
index 24c6f6d6..00000000
--- a/aconfig/ap4a/android.security/fix_unlocked_device_required_keys_v2_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.security"
-  name: "fix_unlocked_device_required_keys_v2"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/android.service.appprediction.flags/Android.bp b/aconfig/ap4a/android.service.appprediction.flags/Android.bp
deleted file mode 100644
index b30c01ce..00000000
--- a/aconfig/ap4a/android.service.appprediction.flags/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-ap4a-android.service.appprediction.flags-all",
-  package: "android.service.appprediction.flags",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/ap4a/android.tracing/Android.bp b/aconfig/ap4a/android.tracing/Android.bp
deleted file mode 100644
index 8afb7727..00000000
--- a/aconfig/ap4a/android.tracing/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-ap4a-android.tracing-all",
-  package: "android.tracing",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/ap4a/com.android.aconfig.flags/Android.bp b/aconfig/ap4a/com.android.aconfig.flags/Android.bp
deleted file mode 100644
index 0280a862..00000000
--- a/aconfig/ap4a/com.android.aconfig.flags/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-ap4a-com.android.aconfig.flags-all",
-  package: "com.android.aconfig.flags",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/ap4a/com.android.aconfig_new_storage/Android.bp b/aconfig/ap4a/com.android.aconfig_new_storage/Android.bp
deleted file mode 100644
index e483c312..00000000
--- a/aconfig/ap4a/com.android.aconfig_new_storage/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-ap4a-com.android.aconfig_new_storage-all",
-  package: "com.android.aconfig_new_storage",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/ap4a/com.android.art.flags/Android.bp b/aconfig/ap4a/com.android.art.flags/Android.bp
deleted file mode 100644
index b448c97a..00000000
--- a/aconfig/ap4a/com.android.art.flags/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-ap4a-com.android.art.flags-all",
-  package: "com.android.art.flags",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/a2dp_offload_codec_extensibility_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/a2dp_offload_codec_extensibility_flag_values.textproto
deleted file mode 100644
index c6441b1d..00000000
--- a/aconfig/ap4a/com.android.bluetooth.flags/a2dp_offload_codec_extensibility_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "a2dp_offload_codec_extensibility"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/airplane_mode_x_ble_on_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/airplane_mode_x_ble_on_flag_values.textproto
deleted file mode 100644
index 1cbccf0d..00000000
--- a/aconfig/ap4a/com.android.bluetooth.flags/airplane_mode_x_ble_on_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "airplane_mode_x_ble_on"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/asha_asrc_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/asha_asrc_flag_values.textproto
deleted file mode 100644
index 02b91207..00000000
--- a/aconfig/ap4a/com.android.bluetooth.flags/asha_asrc_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "asha_asrc"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/auto_connect_on_hfp_when_no_a2dp_device_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/auto_connect_on_hfp_when_no_a2dp_device_flag_values.textproto
deleted file mode 100644
index ceb2afac..00000000
--- a/aconfig/ap4a/com.android.bluetooth.flags/auto_connect_on_hfp_when_no_a2dp_device_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "auto_connect_on_hfp_when_no_a2dp_device"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/auto_on_feature_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/auto_on_feature_flag_values.textproto
deleted file mode 100644
index 562075c3..00000000
--- a/aconfig/ap4a/com.android.bluetooth.flags/auto_on_feature_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "auto_on_feature"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/bta_dm_disc_stuck_in_cancelling_fix_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/bta_dm_disc_stuck_in_cancelling_fix_flag_values.textproto
deleted file mode 100644
index 7ca6c506..00000000
--- a/aconfig/ap4a/com.android.bluetooth.flags/bta_dm_disc_stuck_in_cancelling_fix_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "bta_dm_disc_stuck_in_cancelling_fix"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/a2dp_concurrent_source_sink_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/btsec_check_valid_discovery_database_flag_values.textproto
similarity index 67%
rename from aconfig/ap4a/com.android.bluetooth.flags/a2dp_concurrent_source_sink_flag_values.textproto
rename to aconfig/ap4a/com.android.bluetooth.flags/btsec_check_valid_discovery_database_flag_values.textproto
index b3a0c817..c4fab1d1 100644
--- a/aconfig/ap4a/com.android.bluetooth.flags/a2dp_concurrent_source_sink_flag_values.textproto
+++ b/aconfig/ap4a/com.android.bluetooth.flags/btsec_check_valid_discovery_database_flag_values.textproto
@@ -1,6 +1,6 @@
 flag_value {
   package: "com.android.bluetooth.flags"
-  name: "a2dp_concurrent_source_sink"
+  name: "btsec_check_valid_discovery_database"
   state: ENABLED
   permission: READ_ONLY
 }
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/close_rfcomm_instead_of_reset_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/close_rfcomm_instead_of_reset_flag_values.textproto
deleted file mode 100644
index 0ad7900f..00000000
--- a/aconfig/ap4a/com.android.bluetooth.flags/close_rfcomm_instead_of_reset_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "close_rfcomm_instead_of_reset"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/connect_hid_after_service_discovery_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/connect_hid_after_service_discovery_flag_values.textproto
deleted file mode 100644
index 42926ae3..00000000
--- a/aconfig/ap4a/com.android.bluetooth.flags/connect_hid_after_service_discovery_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "connect_hid_after_service_discovery"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/correct_bond_type_of_loaded_devices_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/correct_bond_type_of_loaded_devices_flag_values.textproto
deleted file mode 100644
index f5e92c12..00000000
--- a/aconfig/ap4a/com.android.bluetooth.flags/correct_bond_type_of_loaded_devices_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "correct_bond_type_of_loaded_devices"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/delay_bonding_when_busy_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/delay_bonding_when_busy_flag_values.textproto
deleted file mode 100644
index 7fbfd3d0..00000000
--- a/aconfig/ap4a/com.android.bluetooth.flags/delay_bonding_when_busy_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "delay_bonding_when_busy"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/divide_long_single_gap_data_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/divide_long_single_gap_data_flag_values.textproto
deleted file mode 100644
index 4e6e5860..00000000
--- a/aconfig/ap4a/com.android.bluetooth.flags/divide_long_single_gap_data_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "divide_long_single_gap_data"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/do_not_replace_existing_cod_with_uncategorized_cod_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/do_not_replace_existing_cod_with_uncategorized_cod_flag_values.textproto
deleted file mode 100644
index 4dc106ca..00000000
--- a/aconfig/ap4a/com.android.bluetooth.flags/do_not_replace_existing_cod_with_uncategorized_cod_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "do_not_replace_existing_cod_with_uncategorized_cod"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/dumpsys_acquire_stack_when_executing_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/dumpsys_acquire_stack_when_executing_flag_values.textproto
deleted file mode 100644
index cacd7160..00000000
--- a/aconfig/ap4a/com.android.bluetooth.flags/dumpsys_acquire_stack_when_executing_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "dumpsys_acquire_stack_when_executing"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/dumpsys_use_passed_in_fd_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/dumpsys_use_passed_in_fd_flag_values.textproto
deleted file mode 100644
index 3617ee05..00000000
--- a/aconfig/ap4a/com.android.bluetooth.flags/dumpsys_use_passed_in_fd_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "dumpsys_use_passed_in_fd"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/ensure_valid_adv_flag_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/ensure_valid_adv_flag_flag_values.textproto
deleted file mode 100644
index 13c82dac..00000000
--- a/aconfig/ap4a/com.android.bluetooth.flags/ensure_valid_adv_flag_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "ensure_valid_adv_flag"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/explicit_kill_from_system_server_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/explicit_kill_from_system_server_flag_values.textproto
deleted file mode 100644
index 5f10fdae..00000000
--- a/aconfig/ap4a/com.android.bluetooth.flags/explicit_kill_from_system_server_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "explicit_kill_from_system_server"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/fix_le_oob_pairing_bypass_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/fix_le_oob_pairing_bypass_flag_values.textproto
deleted file mode 100644
index bd59a55a..00000000
--- a/aconfig/ap4a/com.android.bluetooth.flags/fix_le_oob_pairing_bypass_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "fix_le_oob_pairing_bypass"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/fix_le_pairing_passkey_entry_bypass_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/fix_le_pairing_passkey_entry_bypass_flag_values.textproto
deleted file mode 100644
index dff4dac6..00000000
--- a/aconfig/ap4a/com.android.bluetooth.flags/fix_le_pairing_passkey_entry_bypass_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "fix_le_pairing_passkey_entry_bypass"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/fix_pairing_failure_reason_from_remote_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/fix_pairing_failure_reason_from_remote_flag_values.textproto
deleted file mode 100644
index 79339209..00000000
--- a/aconfig/ap4a/com.android.bluetooth.flags/fix_pairing_failure_reason_from_remote_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "fix_pairing_failure_reason_from_remote"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/force_bredr_for_sdp_retry_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/force_bredr_for_sdp_retry_flag_values.textproto
deleted file mode 100644
index 597790fb..00000000
--- a/aconfig/ap4a/com.android.bluetooth.flags/force_bredr_for_sdp_retry_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "force_bredr_for_sdp_retry"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/gatt_drop_acl_on_out_of_resources_fix_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/gatt_drop_acl_on_out_of_resources_fix_flag_values.textproto
deleted file mode 100644
index a0e7e90a..00000000
--- a/aconfig/ap4a/com.android.bluetooth.flags/gatt_drop_acl_on_out_of_resources_fix_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "gatt_drop_acl_on_out_of_resources_fix"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/gatt_reconnect_on_bt_on_fix_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/gatt_reconnect_on_bt_on_fix_flag_values.textproto
deleted file mode 100644
index b1955ddc..00000000
--- a/aconfig/ap4a/com.android.bluetooth.flags/gatt_reconnect_on_bt_on_fix_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "gatt_reconnect_on_bt_on_fix"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/get_address_type_api_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/get_address_type_api_flag_values.textproto
deleted file mode 100644
index 45a38177..00000000
--- a/aconfig/ap4a/com.android.bluetooth.flags/get_address_type_api_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "get_address_type_api"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/hfp_codec_aptx_voice_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/hfp_codec_aptx_voice_flag_values.textproto
deleted file mode 100644
index d0432b0a..00000000
--- a/aconfig/ap4a/com.android.bluetooth.flags/hfp_codec_aptx_voice_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "hfp_codec_aptx_voice"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/ignore_bond_type_for_le_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/ignore_bond_type_for_le_flag_values.textproto
deleted file mode 100644
index d02c6895..00000000
--- a/aconfig/ap4a/com.android.bluetooth.flags/ignore_bond_type_for_le_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "ignore_bond_type_for_le"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/keep_hfp_active_during_leaudio_handover_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/keep_hfp_active_during_leaudio_handover_flag_values.textproto
deleted file mode 100644
index a36c842d..00000000
--- a/aconfig/ap4a/com.android.bluetooth.flags/keep_hfp_active_during_leaudio_handover_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "keep_hfp_active_during_leaudio_handover"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/keep_stopped_media_browser_service_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/keep_stopped_media_browser_service_flag_values.textproto
deleted file mode 100644
index 51c63f18..00000000
--- a/aconfig/ap4a/com.android.bluetooth.flags/keep_stopped_media_browser_service_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "keep_stopped_media_browser_service"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/le_audio_dev_type_detection_fix_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/le_audio_dev_type_detection_fix_flag_values.textproto
deleted file mode 100644
index 68dc062d..00000000
--- a/aconfig/ap4a/com.android.bluetooth.flags/le_audio_dev_type_detection_fix_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "le_audio_dev_type_detection_fix"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/le_audio_fast_bond_params_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/le_audio_fast_bond_params_flag_values.textproto
deleted file mode 100644
index 33f29913..00000000
--- a/aconfig/ap4a/com.android.bluetooth.flags/le_audio_fast_bond_params_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "le_audio_fast_bond_params"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/le_periodic_scanning_reassembler_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/le_periodic_scanning_reassembler_flag_values.textproto
deleted file mode 100644
index d2e12d42..00000000
--- a/aconfig/ap4a/com.android.bluetooth.flags/le_periodic_scanning_reassembler_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "le_periodic_scanning_reassembler"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/le_scan_parameters_fix_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/le_scan_parameters_fix_flag_values.textproto
deleted file mode 100644
index b8057b2d..00000000
--- a/aconfig/ap4a/com.android.bluetooth.flags/le_scan_parameters_fix_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "le_scan_parameters_fix"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/leaudio_active_device_manager_group_handling_fix_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/leaudio_active_device_manager_group_handling_fix_flag_values.textproto
deleted file mode 100644
index a126b4e9..00000000
--- a/aconfig/ap4a/com.android.bluetooth.flags/leaudio_active_device_manager_group_handling_fix_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "leaudio_active_device_manager_group_handling_fix"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/leaudio_add_sampling_frequencies_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/leaudio_add_sampling_frequencies_flag_values.textproto
deleted file mode 100644
index 5745147d..00000000
--- a/aconfig/ap4a/com.android.bluetooth.flags/leaudio_add_sampling_frequencies_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "leaudio_add_sampling_frequencies"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/leaudio_api_synchronized_block_fix_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/leaudio_api_synchronized_block_fix_flag_values.textproto
deleted file mode 100644
index dc718910..00000000
--- a/aconfig/ap4a/com.android.bluetooth.flags/leaudio_api_synchronized_block_fix_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "leaudio_api_synchronized_block_fix"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/leaudio_broadcast_assistant_handle_command_statuses_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/leaudio_broadcast_assistant_handle_command_statuses_flag_values.textproto
deleted file mode 100644
index 4978d05f..00000000
--- a/aconfig/ap4a/com.android.bluetooth.flags/leaudio_broadcast_assistant_handle_command_statuses_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "leaudio_broadcast_assistant_handle_command_statuses"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/leaudio_callback_on_group_stream_status_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/leaudio_callback_on_group_stream_status_flag_values.textproto
deleted file mode 100644
index c7252176..00000000
--- a/aconfig/ap4a/com.android.bluetooth.flags/leaudio_callback_on_group_stream_status_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "leaudio_callback_on_group_stream_status"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/leaudio_enable_health_based_actions_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/leaudio_enable_health_based_actions_flag_values.textproto
deleted file mode 100644
index 6a795284..00000000
--- a/aconfig/ap4a/com.android.bluetooth.flags/leaudio_enable_health_based_actions_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "leaudio_enable_health_based_actions"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/leaudio_mcs_tbs_authorization_rebond_fix_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/leaudio_mcs_tbs_authorization_rebond_fix_flag_values.textproto
deleted file mode 100644
index 49c48c78..00000000
--- a/aconfig/ap4a/com.android.bluetooth.flags/leaudio_mcs_tbs_authorization_rebond_fix_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "leaudio_mcs_tbs_authorization_rebond_fix"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/leaudio_quick_leaudio_toggle_switch_fix_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/leaudio_quick_leaudio_toggle_switch_fix_flag_values.textproto
deleted file mode 100644
index c332319d..00000000
--- a/aconfig/ap4a/com.android.bluetooth.flags/leaudio_quick_leaudio_toggle_switch_fix_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "leaudio_quick_leaudio_toggle_switch_fix"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/leaudio_resume_active_after_hfp_handover_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/leaudio_resume_active_after_hfp_handover_flag_values.textproto
deleted file mode 100644
index 3a8ef518..00000000
--- a/aconfig/ap4a/com.android.bluetooth.flags/leaudio_resume_active_after_hfp_handover_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "leaudio_resume_active_after_hfp_handover"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/leaudio_start_stream_race_fix_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/leaudio_start_stream_race_fix_flag_values.textproto
deleted file mode 100644
index 9ec54b3b..00000000
--- a/aconfig/ap4a/com.android.bluetooth.flags/leaudio_start_stream_race_fix_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "leaudio_start_stream_race_fix"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/leaudio_unicast_inactivate_device_based_on_context_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/leaudio_unicast_inactivate_device_based_on_context_flag_values.textproto
deleted file mode 100644
index 044dde18..00000000
--- a/aconfig/ap4a/com.android.bluetooth.flags/leaudio_unicast_inactivate_device_based_on_context_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "leaudio_unicast_inactivate_device_based_on_context"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/leaudio_volume_change_on_ringtone_fix_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/leaudio_volume_change_on_ringtone_fix_flag_values.textproto
deleted file mode 100644
index df5df590..00000000
--- a/aconfig/ap4a/com.android.bluetooth.flags/leaudio_volume_change_on_ringtone_fix_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "leaudio_volume_change_on_ringtone_fix"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/load_did_config_from_sysprops_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/load_did_config_from_sysprops_flag_values.textproto
deleted file mode 100644
index 76ccde4a..00000000
--- a/aconfig/ap4a/com.android.bluetooth.flags/load_did_config_from_sysprops_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "load_did_config_from_sysprops"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/mfi_has_uuid_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/mfi_has_uuid_flag_values.textproto
deleted file mode 100644
index e574bfb5..00000000
--- a/aconfig/ap4a/com.android.bluetooth.flags/mfi_has_uuid_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "mfi_has_uuid"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/pretend_network_service_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/pretend_network_service_flag_values.textproto
deleted file mode 100644
index b6392a8d..00000000
--- a/aconfig/ap4a/com.android.bluetooth.flags/pretend_network_service_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "pretend_network_service"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/read_model_num_fix_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/read_model_num_fix_flag_values.textproto
deleted file mode 100644
index 1bcb0ae0..00000000
--- a/aconfig/ap4a/com.android.bluetooth.flags/read_model_num_fix_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "read_model_num_fix"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/report_vsc_data_from_the_gd_controller_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/report_vsc_data_from_the_gd_controller_flag_values.textproto
deleted file mode 100644
index 85f9aa02..00000000
--- a/aconfig/ap4a/com.android.bluetooth.flags/report_vsc_data_from_the_gd_controller_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "report_vsc_data_from_the_gd_controller"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/bluffs_mitigation_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/reset_after_collision_flag_values.textproto
similarity index 75%
rename from aconfig/ap4a/com.android.bluetooth.flags/bluffs_mitigation_flag_values.textproto
rename to aconfig/ap4a/com.android.bluetooth.flags/reset_after_collision_flag_values.textproto
index 31b47771..8109a82e 100644
--- a/aconfig/ap4a/com.android.bluetooth.flags/bluffs_mitigation_flag_values.textproto
+++ b/aconfig/ap4a/com.android.bluetooth.flags/reset_after_collision_flag_values.textproto
@@ -1,6 +1,6 @@
 flag_value {
   package: "com.android.bluetooth.flags"
-  name: "bluffs_mitigation"
+  name: "reset_after_collision"
   state: ENABLED
   permission: READ_ONLY
 }
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/reset_pairing_only_for_related_service_discovery_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/reset_pairing_only_for_related_service_discovery_flag_values.textproto
deleted file mode 100644
index 7e93475f..00000000
--- a/aconfig/ap4a/com.android.bluetooth.flags/reset_pairing_only_for_related_service_discovery_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "reset_pairing_only_for_related_service_discovery"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/rnr_cancel_before_event_race_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/rnr_cancel_before_event_race_flag_values.textproto
deleted file mode 100644
index b440e9d5..00000000
--- a/aconfig/ap4a/com.android.bluetooth.flags/rnr_cancel_before_event_race_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "rnr_cancel_before_event_race"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/rnr_present_during_service_discovery_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/rnr_present_during_service_discovery_flag_values.textproto
deleted file mode 100644
index c89b1b7d..00000000
--- a/aconfig/ap4a/com.android.bluetooth.flags/rnr_present_during_service_discovery_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "rnr_present_during_service_discovery"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/rnr_reset_state_at_cancel_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/rnr_reset_state_at_cancel_flag_values.textproto
deleted file mode 100644
index ddfe5ba6..00000000
--- a/aconfig/ap4a/com.android.bluetooth.flags/rnr_reset_state_at_cancel_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "rnr_reset_state_at_cancel"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/separate_service_and_device_discovery_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/separate_service_and_device_discovery_flag_values.textproto
deleted file mode 100644
index f1b89771..00000000
--- a/aconfig/ap4a/com.android.bluetooth.flags/separate_service_and_device_discovery_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "separate_service_and_device_discovery"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/synchronous_bta_sec_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/synchronous_bta_sec_flag_values.textproto
deleted file mode 100644
index 8482d343..00000000
--- a/aconfig/ap4a/com.android.bluetooth.flags/synchronous_bta_sec_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "synchronous_bta_sec"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/update_inquiry_result_on_flag_change_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/update_inquiry_result_on_flag_change_flag_values.textproto
deleted file mode 100644
index 6cf44219..00000000
--- a/aconfig/ap4a/com.android.bluetooth.flags/update_inquiry_result_on_flag_change_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "update_inquiry_result_on_flag_change"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/use_dsp_codec_when_controller_does_not_support_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/use_dsp_codec_when_controller_does_not_support_flag_values.textproto
deleted file mode 100644
index 9557c22d..00000000
--- a/aconfig/ap4a/com.android.bluetooth.flags/use_dsp_codec_when_controller_does_not_support_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "use_dsp_codec_when_controller_does_not_support"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.cellbroadcastreceiver.flags/Android.bp b/aconfig/ap4a/com.android.cellbroadcastreceiver.flags/Android.bp
deleted file mode 100644
index e1a51345..00000000
--- a/aconfig/ap4a/com.android.cellbroadcastreceiver.flags/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-ap4a-com.android.cellbroadcastreceiver.flags-all",
-  package: "com.android.cellbroadcastreceiver.flags",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/ap4a/com.android.devicelock.flags/Android.bp b/aconfig/ap4a/com.android.devicelock.flags/Android.bp
deleted file mode 100644
index 3b8b72c1..00000000
--- a/aconfig/ap4a/com.android.devicelock.flags/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-ap4a-com.android.devicelock.flags-all",
-  package: "com.android.devicelock.flags",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/ap4a/com.android.graphics.bufferstreams.flags/Android.bp b/aconfig/ap4a/com.android.graphics.bufferstreams.flags/Android.bp
deleted file mode 100644
index cd0aefbd..00000000
--- a/aconfig/ap4a/com.android.graphics.bufferstreams.flags/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-ap4a-com.android.graphics.bufferstreams.flags-all",
-  package: "com.android.graphics.bufferstreams.flags",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/ap4a/com.android.graphics.flags/Android.bp b/aconfig/ap4a/com.android.graphics.flags/Android.bp
deleted file mode 100644
index 82ba6327..00000000
--- a/aconfig/ap4a/com.android.graphics.flags/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-ap4a-com.android.graphics.flags-all",
-  package: "com.android.graphics.flags",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/ap4a/com.android.graphics.libvulkan.flags/Android.bp b/aconfig/ap4a/com.android.graphics.libvulkan.flags/Android.bp
deleted file mode 100644
index 43b3d575..00000000
--- a/aconfig/ap4a/com.android.graphics.libvulkan.flags/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-ap4a-com.android.graphics.libvulkan.flags-all",
-  package: "com.android.graphics.libvulkan.flags",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/ap4a/com.android.hardware.camera2/Android.bp b/aconfig/ap4a/com.android.hardware.camera2/Android.bp
deleted file mode 100644
index c02f3393..00000000
--- a/aconfig/ap4a/com.android.hardware.camera2/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-ap4a-com.android.hardware.camera2-all",
-  package: "com.android.hardware.camera2",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/ap4a/com.android.healthfitness.flags/Android.bp b/aconfig/ap4a/com.android.healthfitness.flags/Android.bp
deleted file mode 100644
index 2697f96d..00000000
--- a/aconfig/ap4a/com.android.healthfitness.flags/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-ap4a-com.android.healthfitness.flags-all",
-  package: "com.android.healthfitness.flags",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/ap4a/com.android.input.flags/enable_gestures_library_timer_provider_flag_values.textproto b/aconfig/ap4a/com.android.input.flags/enable_gestures_library_timer_provider_flag_values.textproto
deleted file mode 100644
index a5177143..00000000
--- a/aconfig/ap4a/com.android.input.flags/enable_gestures_library_timer_provider_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.input.flags"
-  name: "enable_gestures_library_timer_provider"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.input.flags/remove_pointer_event_tracking_in_wm_flag_values.textproto b/aconfig/ap4a/com.android.input.flags/remove_pointer_event_tracking_in_wm_flag_values.textproto
deleted file mode 100644
index c0576623..00000000
--- a/aconfig/ap4a/com.android.input.flags/remove_pointer_event_tracking_in_wm_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.input.flags"
-  name: "remove_pointer_event_tracking_in_wm"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.intentresolver/bespoke_label_view_flag_values.textproto b/aconfig/ap4a/com.android.intentresolver/bespoke_label_view_flag_values.textproto
deleted file mode 100644
index 2d584098..00000000
--- a/aconfig/ap4a/com.android.intentresolver/bespoke_label_view_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.intentresolver"
-  name: "bespoke_label_view"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.intentresolver/fix_partial_image_edit_transition_flag_values.textproto b/aconfig/ap4a/com.android.intentresolver/fix_partial_image_edit_transition_flag_values.textproto
deleted file mode 100644
index 5560bfbe..00000000
--- a/aconfig/ap4a/com.android.intentresolver/fix_partial_image_edit_transition_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.intentresolver"
-  name: "fix_partial_image_edit_transition"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.intentresolver/fix_shortcuts_flashing_flag_values.textproto b/aconfig/ap4a/com.android.intentresolver/fix_shortcuts_flashing_flag_values.textproto
deleted file mode 100644
index 25d88905..00000000
--- a/aconfig/ap4a/com.android.intentresolver/fix_shortcuts_flashing_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.intentresolver"
-  name: "fix_shortcuts_flashing"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.intentresolver/fix_target_list_footer_flag_values.textproto b/aconfig/ap4a/com.android.intentresolver/fix_target_list_footer_flag_values.textproto
deleted file mode 100644
index 10e856bc..00000000
--- a/aconfig/ap4a/com.android.intentresolver/fix_target_list_footer_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.intentresolver"
-  name: "fix_target_list_footer"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.internal.camera.flags/lazy_aidl_wait_for_service_flag_values.textproto b/aconfig/ap4a/com.android.internal.camera.flags/lazy_aidl_wait_for_service_flag_values.textproto
deleted file mode 100644
index eafc30b8..00000000
--- a/aconfig/ap4a/com.android.internal.camera.flags/lazy_aidl_wait_for_service_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.internal.camera.flags"
-  name: "lazy_aidl_wait_for_service"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.internal.camera.flags/log_ultrawide_usage_flag_values.textproto b/aconfig/ap4a/com.android.internal.camera.flags/log_ultrawide_usage_flag_values.textproto
deleted file mode 100644
index 2b154426..00000000
--- a/aconfig/ap4a/com.android.internal.camera.flags/log_ultrawide_usage_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.internal.camera.flags"
-  name: "log_ultrawide_usage"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.internal.camera.flags/log_zoom_override_usage_flag_values.textproto b/aconfig/ap4a/com.android.internal.camera.flags/log_zoom_override_usage_flag_values.textproto
deleted file mode 100644
index ca4a9c8a..00000000
--- a/aconfig/ap4a/com.android.internal.camera.flags/log_zoom_override_usage_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.internal.camera.flags"
-  name: "log_zoom_override_usage"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.internal.camera.flags/realtime_priority_bump_flag_values.textproto b/aconfig/ap4a/com.android.internal.camera.flags/realtime_priority_bump_flag_values.textproto
deleted file mode 100644
index d5f82fdb..00000000
--- a/aconfig/ap4a/com.android.internal.camera.flags/realtime_priority_bump_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.internal.camera.flags"
-  name: "realtime_priority_bump"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.internal.camera.flags/single_thread_executor_flag_values.textproto b/aconfig/ap4a/com.android.internal.camera.flags/single_thread_executor_flag_values.textproto
deleted file mode 100644
index e02e144c..00000000
--- a/aconfig/ap4a/com.android.internal.camera.flags/single_thread_executor_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.internal.camera.flags"
-  name: "single_thread_executor"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.internal.camera.flags/surface_ipc_flag_values.textproto b/aconfig/ap4a/com.android.internal.camera.flags/surface_ipc_flag_values.textproto
deleted file mode 100644
index e721feb9..00000000
--- a/aconfig/ap4a/com.android.internal.camera.flags/surface_ipc_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.internal.camera.flags"
-  name: "surface_ipc"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.internal.camera.flags/surface_leak_fix_flag_values.textproto b/aconfig/ap4a/com.android.internal.camera.flags/surface_leak_fix_flag_values.textproto
deleted file mode 100644
index 09166fda..00000000
--- a/aconfig/ap4a/com.android.internal.camera.flags/surface_leak_fix_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.internal.camera.flags"
-  name: "surface_leak_fix"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.internal.camera.flags/watch_foreground_changes_flag_values.textproto b/aconfig/ap4a/com.android.internal.camera.flags/watch_foreground_changes_flag_values.textproto
deleted file mode 100644
index 71d833c5..00000000
--- a/aconfig/ap4a/com.android.internal.camera.flags/watch_foreground_changes_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.internal.camera.flags"
-  name: "watch_foreground_changes"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.internal.jank/Android.bp b/aconfig/ap4a/com.android.internal.jank/Android.bp
deleted file mode 100644
index 10094958..00000000
--- a/aconfig/ap4a/com.android.internal.jank/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-ap4a-com.android.internal.jank-all",
-  package: "com.android.internal.jank",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/ap4a/com.android.internal.telephony.flags/add_anomaly_when_notify_config_changed_with_invalid_phone_flag_values.textproto b/aconfig/ap4a/com.android.internal.telephony.flags/add_anomaly_when_notify_config_changed_with_invalid_phone_flag_values.textproto
deleted file mode 100644
index 8bfdfa99..00000000
--- a/aconfig/ap4a/com.android.internal.telephony.flags/add_anomaly_when_notify_config_changed_with_invalid_phone_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.internal.telephony.flags"
-  name: "add_anomaly_when_notify_config_changed_with_invalid_phone"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.internal.telephony.flags/allow_mmtel_in_non_vops_flag_values.textproto b/aconfig/ap4a/com.android.internal.telephony.flags/allow_mmtel_in_non_vops_flag_values.textproto
deleted file mode 100644
index 79514414..00000000
--- a/aconfig/ap4a/com.android.internal.telephony.flags/allow_mmtel_in_non_vops_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.internal.telephony.flags"
-  name: "allow_mmtel_in_non_vops"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.internal.telephony.flags/cleanup_open_logical_channel_record_on_dispose_flag_values.textproto b/aconfig/ap4a/com.android.internal.telephony.flags/cleanup_open_logical_channel_record_on_dispose_flag_values.textproto
deleted file mode 100644
index 84c39870..00000000
--- a/aconfig/ap4a/com.android.internal.telephony.flags/cleanup_open_logical_channel_record_on_dispose_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.internal.telephony.flags"
-  name: "cleanup_open_logical_channel_record_on_dispose"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.internal.telephony.flags/data_only_service_allow_emergency_call_only_flag_values.textproto b/aconfig/ap4a/com.android.internal.telephony.flags/data_only_service_allow_emergency_call_only_flag_values.textproto
deleted file mode 100644
index 9ddecbb2..00000000
--- a/aconfig/ap4a/com.android.internal.telephony.flags/data_only_service_allow_emergency_call_only_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.internal.telephony.flags"
-  name: "data_only_service_allow_emergency_call_only"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.internal.telephony.flags/fix_crash_on_getting_config_when_phone_is_gone_flag_values.textproto b/aconfig/ap4a/com.android.internal.telephony.flags/fix_crash_on_getting_config_when_phone_is_gone_flag_values.textproto
deleted file mode 100644
index 2a3ec157..00000000
--- a/aconfig/ap4a/com.android.internal.telephony.flags/fix_crash_on_getting_config_when_phone_is_gone_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.internal.telephony.flags"
-  name: "fix_crash_on_getting_config_when_phone_is_gone"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.internal.telephony.flags/force_iwlan_mms_flag_values.textproto b/aconfig/ap4a/com.android.internal.telephony.flags/force_iwlan_mms_flag_values.textproto
deleted file mode 100644
index e6a7cba5..00000000
--- a/aconfig/ap4a/com.android.internal.telephony.flags/force_iwlan_mms_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.internal.telephony.flags"
-  name: "force_iwlan_mms"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.internal.telephony.flags/hide_preinstalled_carrier_app_at_most_once_flag_values.textproto b/aconfig/ap4a/com.android.internal.telephony.flags/hide_preinstalled_carrier_app_at_most_once_flag_values.textproto
deleted file mode 100644
index 2bc156f4..00000000
--- a/aconfig/ap4a/com.android.internal.telephony.flags/hide_preinstalled_carrier_app_at_most_once_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.internal.telephony.flags"
-  name: "hide_preinstalled_carrier_app_at_most_once"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.internal.telephony.flags/ignore_existing_networks_for_internet_allowed_checking_flag_values.textproto b/aconfig/ap4a/com.android.internal.telephony.flags/ignore_existing_networks_for_internet_allowed_checking_flag_values.textproto
deleted file mode 100644
index 6c22a014..00000000
--- a/aconfig/ap4a/com.android.internal.telephony.flags/ignore_existing_networks_for_internet_allowed_checking_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.internal.telephony.flags"
-  name: "ignore_existing_networks_for_internet_allowed_checking"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.internal.telephony.flags/metered_embb_urlcc_flag_values.textproto b/aconfig/ap4a/com.android.internal.telephony.flags/metered_embb_urlcc_flag_values.textproto
deleted file mode 100644
index 287b4f3a..00000000
--- a/aconfig/ap4a/com.android.internal.telephony.flags/metered_embb_urlcc_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.internal.telephony.flags"
-  name: "metered_embb_urlcc"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.internal.telephony.flags/notify_data_activity_changed_with_slot_flag_values.textproto b/aconfig/ap4a/com.android.internal.telephony.flags/notify_data_activity_changed_with_slot_flag_values.textproto
deleted file mode 100644
index be540f81..00000000
--- a/aconfig/ap4a/com.android.internal.telephony.flags/notify_data_activity_changed_with_slot_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.internal.telephony.flags"
-  name: "notify_data_activity_changed_with_slot"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.internal.telephony.flags/refine_preferred_data_profile_selection_flag_values.textproto b/aconfig/ap4a/com.android.internal.telephony.flags/refine_preferred_data_profile_selection_flag_values.textproto
deleted file mode 100644
index 7d6f36e6..00000000
--- a/aconfig/ap4a/com.android.internal.telephony.flags/refine_preferred_data_profile_selection_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.internal.telephony.flags"
-  name: "refine_preferred_data_profile_selection"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.internal.telephony.flags/relax_ho_teardown_flag_values.textproto b/aconfig/ap4a/com.android.internal.telephony.flags/relax_ho_teardown_flag_values.textproto
deleted file mode 100644
index 428461ce..00000000
--- a/aconfig/ap4a/com.android.internal.telephony.flags/relax_ho_teardown_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.internal.telephony.flags"
-  name: "relax_ho_teardown"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.internal.telephony.flags/support_phone_uid_check_for_multiuser_flag_values.textproto b/aconfig/ap4a/com.android.internal.telephony.flags/support_phone_uid_check_for_multiuser_flag_values.textproto
deleted file mode 100644
index b3552d92..00000000
--- a/aconfig/ap4a/com.android.internal.telephony.flags/support_phone_uid_check_for_multiuser_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.internal.telephony.flags"
-  name: "support_phone_uid_check_for_multiuser"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.internal.telephony.flags/unthrottle_check_transport_flag_values.textproto b/aconfig/ap4a/com.android.internal.telephony.flags/unthrottle_check_transport_flag_values.textproto
deleted file mode 100644
index 0fe31c80..00000000
--- a/aconfig/ap4a/com.android.internal.telephony.flags/unthrottle_check_transport_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.internal.telephony.flags"
-  name: "unthrottle_check_transport"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.internal.telephony.flags/use_alarm_callback_flag_values.textproto b/aconfig/ap4a/com.android.internal.telephony.flags/use_alarm_callback_flag_values.textproto
deleted file mode 100644
index d372cf6c..00000000
--- a/aconfig/ap4a/com.android.internal.telephony.flags/use_alarm_callback_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.internal.telephony.flags"
-  name: "use_alarm_callback"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.managedprovisioning.flags/Android.bp b/aconfig/ap4a/com.android.managedprovisioning.flags/Android.bp
deleted file mode 100644
index c2efa3f3..00000000
--- a/aconfig/ap4a/com.android.managedprovisioning.flags/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-ap4a-com.android.managedprovisioning.flags-all",
-  package: "com.android.managedprovisioning.flags",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/ap4a/com.android.media.audioclient/Android.bp b/aconfig/ap4a/com.android.media.audioclient/Android.bp
deleted file mode 100644
index 6811512a..00000000
--- a/aconfig/ap4a/com.android.media.audioclient/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-ap4a-com.android.media.audioclient-all",
-  package: "com.android.media.audioclient",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/ap4a/com.android.media.projection.flags/Android.bp b/aconfig/ap4a/com.android.media.projection.flags/Android.bp
deleted file mode 100644
index 1801e112..00000000
--- a/aconfig/ap4a/com.android.media.projection.flags/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-ap4a-com.android.media.projection.flags-all",
-  package: "com.android.media.projection.flags",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/ap4a/com.android.net.ct.flags/Android.bp b/aconfig/ap4a/com.android.net.ct.flags/Android.bp
deleted file mode 100644
index 588be0c8..00000000
--- a/aconfig/ap4a/com.android.net.ct.flags/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-ap4a-com.android.net.ct.flags-all",
-  package: "com.android.net.ct.flags",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/ap4a/com.android.net.thread.platform.flags/Android.bp b/aconfig/ap4a/com.android.net.thread.platform.flags/Android.bp
deleted file mode 100644
index b59a4d64..00000000
--- a/aconfig/ap4a/com.android.net.thread.platform.flags/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-ap4a-com.android.net.thread.platform.flags-all",
-  package: "com.android.net.thread.platform.flags",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/ap4a/com.android.nfc.nci.flags/Android.bp b/aconfig/ap4a/com.android.nfc.nci.flags/Android.bp
deleted file mode 100644
index a1906661..00000000
--- a/aconfig/ap4a/com.android.nfc.nci.flags/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-ap4a-com.android.nfc.nci.flags-all",
-  package: "com.android.nfc.nci.flags",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/ap4a/com.android.org.conscrypt/Android.bp b/aconfig/ap4a/com.android.org.conscrypt/Android.bp
deleted file mode 100644
index 7823a89f..00000000
--- a/aconfig/ap4a/com.android.org.conscrypt/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-ap4a-com.android.org.conscrypt-all",
-  package: "com.android.org.conscrypt",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/ap4a/com.android.os.statsd.flags/Android.bp b/aconfig/ap4a/com.android.os.statsd.flags/Android.bp
deleted file mode 100644
index a585bd4c..00000000
--- a/aconfig/ap4a/com.android.os.statsd.flags/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-ap4a-com.android.os.statsd.flags-all",
-  package: "com.android.os.statsd.flags",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/ap4a/com.android.providers.contacts.flags/Android.bp b/aconfig/ap4a/com.android.providers.contacts.flags/Android.bp
deleted file mode 100644
index 6a6c8fd0..00000000
--- a/aconfig/ap4a/com.android.providers.contacts.flags/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-ap4a-com.android.providers.contacts.flags-all",
-  package: "com.android.providers.contacts.flags",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/ap4a/com.android.server.companion.virtual/Android.bp b/aconfig/ap4a/com.android.server.companion.virtual/Android.bp
deleted file mode 100644
index af1718c7..00000000
--- a/aconfig/ap4a/com.android.server.companion.virtual/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-ap4a-com.android.server.companion.virtual-all",
-  package: "com.android.server.companion.virtual",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/ap4a/com.android.server.companion.virtual/dump_history_flag_values.textproto b/aconfig/ap4a/com.android.server.companion.virtual/dump_history_flag_values.textproto
deleted file mode 100644
index ddcb135d..00000000
--- a/aconfig/ap4a/com.android.server.companion.virtual/dump_history_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.server.companion.virtual"
-  name: "dump_history"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.server.connectivity/Android.bp b/aconfig/ap4a/com.android.server.connectivity/Android.bp
deleted file mode 100644
index 6a8e22dc..00000000
--- a/aconfig/ap4a/com.android.server.connectivity/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-ap4a-com.android.server.connectivity-all",
-  package: "com.android.server.connectivity",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/ap4a/com.android.server.contextualsearch.flags/Android.bp b/aconfig/ap4a/com.android.server.contextualsearch.flags/Android.bp
deleted file mode 100644
index bc830d0e..00000000
--- a/aconfig/ap4a/com.android.server.contextualsearch.flags/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-ap4a-com.android.server.contextualsearch.flags-all",
-  package: "com.android.server.contextualsearch.flags",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/ap4a/com.android.server.devicepolicy.flags/Android.bp b/aconfig/ap4a/com.android.server.devicepolicy.flags/Android.bp
deleted file mode 100644
index 6f37a3a1..00000000
--- a/aconfig/ap4a/com.android.server.devicepolicy.flags/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-ap4a-com.android.server.devicepolicy.flags-all",
-  package: "com.android.server.devicepolicy.flags",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/ap4a/com.android.server.locksettings/Android.bp b/aconfig/ap4a/com.android.server.locksettings/Android.bp
deleted file mode 100644
index 3f15fc1a..00000000
--- a/aconfig/ap4a/com.android.server.locksettings/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-ap4a-com.android.server.locksettings-all",
-  package: "com.android.server.locksettings",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/ap4a/com.android.server.os/Android.bp b/aconfig/ap4a/com.android.server.os/Android.bp
deleted file mode 100644
index 2b37aa5b..00000000
--- a/aconfig/ap4a/com.android.server.os/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-ap4a-com.android.server.os-all",
-  package: "com.android.server.os",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/ap4a/com.android.server.pm/Android.bp b/aconfig/ap4a/com.android.server.pm/Android.bp
deleted file mode 100644
index 1598f02e..00000000
--- a/aconfig/ap4a/com.android.server.pm/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-ap4a-com.android.server.pm-all",
-  package: "com.android.server.pm",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/ap4a/com.android.server.security/Android.bp b/aconfig/ap4a/com.android.server.security/Android.bp
deleted file mode 100644
index 23bb01c9..00000000
--- a/aconfig/ap4a/com.android.server.security/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-ap4a-com.android.server.security-all",
-  package: "com.android.server.security",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/ap4a/com.android.server.updates/Android.bp b/aconfig/ap4a/com.android.server.updates/Android.bp
deleted file mode 100644
index 84f60842..00000000
--- a/aconfig/ap4a/com.android.server.updates/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-ap4a-com.android.server.updates-all",
-  package: "com.android.server.updates",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/ap4a/com.android.server.utils/Android.bp b/aconfig/ap4a/com.android.server.utils/Android.bp
deleted file mode 100644
index 793ba41b..00000000
--- a/aconfig/ap4a/com.android.server.utils/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-ap4a-com.android.server.utils-all",
-  package: "com.android.server.utils",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/ap4a/com.android.settings.connecteddevice.flags/Android.bp b/aconfig/ap4a/com.android.settings.connecteddevice.flags/Android.bp
deleted file mode 100644
index 46b68bfe..00000000
--- a/aconfig/ap4a/com.android.settings.connecteddevice.flags/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-ap4a-com.android.settings.connecteddevice.flags-all",
-  package: "com.android.settings.connecteddevice.flags",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/ap4a/com.android.settings.flags/enable_bluetooth_profile_toggle_visibility_checker_flag_values.textproto b/aconfig/ap4a/com.android.settings.flags/enable_bluetooth_profile_toggle_visibility_checker_flag_values.textproto
deleted file mode 100644
index 3070dc63..00000000
--- a/aconfig/ap4a/com.android.settings.flags/enable_bluetooth_profile_toggle_visibility_checker_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.settings.flags"
-  name: "enable_bluetooth_profile_toggle_visibility_checker"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.settings.flags/enable_subsequent_pair_settings_integration_flag_values.textproto b/aconfig/ap4a/com.android.settings.flags/enable_subsequent_pair_settings_integration_flag_values.textproto
deleted file mode 100644
index 19c747b6..00000000
--- a/aconfig/ap4a/com.android.settings.flags/enable_subsequent_pair_settings_integration_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.settings.flags"
-  name: "enable_subsequent_pair_settings_integration"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.settings.flags/internet_preference_controller_v2_flag_values.textproto b/aconfig/ap4a/com.android.settings.flags/internet_preference_controller_v2_flag_values.textproto
deleted file mode 100644
index 3870feb1..00000000
--- a/aconfig/ap4a/com.android.settings.flags/internet_preference_controller_v2_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.settings.flags"
-  name: "internet_preference_controller_v2"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.settings.keyboard/Android.bp b/aconfig/ap4a/com.android.settings.keyboard/Android.bp
deleted file mode 100644
index cd8b0fe4..00000000
--- a/aconfig/ap4a/com.android.settings.keyboard/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-ap4a-com.android.settings.keyboard-all",
-  package: "com.android.settings.keyboard",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/ap4a/com.android.settingslib.flags/enable_cached_bluetooth_device_dedup_flag_values.textproto b/aconfig/ap4a/com.android.settingslib.flags/enable_cached_bluetooth_device_dedup_flag_values.textproto
deleted file mode 100644
index ef19087e..00000000
--- a/aconfig/ap4a/com.android.settingslib.flags/enable_cached_bluetooth_device_dedup_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.settingslib.flags"
-  name: "enable_cached_bluetooth_device_dedup"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.systemui.aconfig/Android.bp b/aconfig/ap4a/com.android.systemui.aconfig/Android.bp
deleted file mode 100644
index ad1d70e9..00000000
--- a/aconfig/ap4a/com.android.systemui.aconfig/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-ap4a-com.android.systemui.aconfig-all",
-  package: "com.android.systemui.aconfig",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/ap4a/com.android.systemui.communal/Android.bp b/aconfig/ap4a/com.android.systemui.communal/Android.bp
deleted file mode 100644
index f85f8986..00000000
--- a/aconfig/ap4a/com.android.systemui.communal/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-ap4a-com.android.systemui.communal-all",
-  package: "com.android.systemui.communal",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/ap4a/com.android.systemui/bp_talkback_flag_values.textproto b/aconfig/ap4a/com.android.systemui/bp_talkback_flag_values.textproto
deleted file mode 100644
index 1232057b..00000000
--- a/aconfig/ap4a/com.android.systemui/bp_talkback_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.systemui"
-  name: "bp_talkback"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.systemui/centralized_status_bar_height_fix_flag_values.textproto b/aconfig/ap4a/com.android.systemui/centralized_status_bar_height_fix_flag_values.textproto
deleted file mode 100644
index ff854144..00000000
--- a/aconfig/ap4a/com.android.systemui/centralized_status_bar_height_fix_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.systemui"
-  name: "centralized_status_bar_height_fix"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.systemui/constraint_bp_flag_values.textproto b/aconfig/ap4a/com.android.systemui/constraint_bp_flag_values.textproto
deleted file mode 100644
index de5fbef7..00000000
--- a/aconfig/ap4a/com.android.systemui/constraint_bp_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.systemui"
-  name: "constraint_bp"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.systemui/haptic_brightness_slider_flag_values.textproto b/aconfig/ap4a/com.android.systemui/haptic_brightness_slider_flag_values.textproto
deleted file mode 100644
index 28675cbd..00000000
--- a/aconfig/ap4a/com.android.systemui/haptic_brightness_slider_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.systemui"
-  name: "haptic_brightness_slider"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.systemui/haptic_volume_slider_flag_values.textproto b/aconfig/ap4a/com.android.systemui/haptic_volume_slider_flag_values.textproto
deleted file mode 100644
index 022c227a..00000000
--- a/aconfig/ap4a/com.android.systemui/haptic_volume_slider_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.systemui"
-  name: "haptic_volume_slider"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.systemui/ignore_touches_next_to_notification_shelf_flag_values.textproto b/aconfig/ap4a/com.android.systemui/ignore_touches_next_to_notification_shelf_flag_values.textproto
index 7eda2f99..ea328229 100644
--- a/aconfig/ap4a/com.android.systemui/ignore_touches_next_to_notification_shelf_flag_values.textproto
+++ b/aconfig/ap4a/com.android.systemui/ignore_touches_next_to_notification_shelf_flag_values.textproto
@@ -3,4 +3,4 @@ flag_value {
   name: "ignore_touches_next_to_notification_shelf"
   state: ENABLED
   permission: READ_ONLY
-}
\ No newline at end of file
+}
diff --git a/aconfig/ap4a/com.android.systemui/lockscreen_preview_renderer_create_on_main_thread_flag_values.textproto b/aconfig/ap4a/com.android.systemui/lockscreen_preview_renderer_create_on_main_thread_flag_values.textproto
deleted file mode 100644
index e8da3491..00000000
--- a/aconfig/ap4a/com.android.systemui/lockscreen_preview_renderer_create_on_main_thread_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.systemui"
-  name: "lockscreen_preview_renderer_create_on_main_thread"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.systemui/privacy_dot_unfold_wrong_corner_fix_flag_values.textproto b/aconfig/ap4a/com.android.systemui/privacy_dot_unfold_wrong_corner_fix_flag_values.textproto
deleted file mode 100644
index 11827bf6..00000000
--- a/aconfig/ap4a/com.android.systemui/privacy_dot_unfold_wrong_corner_fix_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.systemui"
-  name: "privacy_dot_unfold_wrong_corner_fix"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.systemui/pss_app_selector_abrupt_exit_fix_flag_values.textproto b/aconfig/ap4a/com.android.systemui/pss_app_selector_abrupt_exit_fix_flag_values.textproto
deleted file mode 100644
index bd3128a6..00000000
--- a/aconfig/ap4a/com.android.systemui/pss_app_selector_abrupt_exit_fix_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.systemui"
-  name: "pss_app_selector_abrupt_exit_fix"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.systemui/qs_new_pipeline_flag_values.textproto b/aconfig/ap4a/com.android.systemui/qs_new_pipeline_flag_values.textproto
deleted file mode 100644
index cc1c39b4..00000000
--- a/aconfig/ap4a/com.android.systemui/qs_new_pipeline_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.systemui"
-  name: "qs_new_pipeline"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.systemui/screenshot_private_profile_accessibility_announcement_fix_flag_values.textproto b/aconfig/ap4a/com.android.systemui/screenshot_private_profile_accessibility_announcement_fix_flag_values.textproto
deleted file mode 100644
index d7aff613..00000000
--- a/aconfig/ap4a/com.android.systemui/screenshot_private_profile_accessibility_announcement_fix_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.systemui"
-  name: "screenshot_private_profile_accessibility_announcement_fix"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.systemui/screenshot_private_profile_behavior_fix_flag_values.textproto b/aconfig/ap4a/com.android.systemui/screenshot_private_profile_behavior_fix_flag_values.textproto
deleted file mode 100644
index 9c7addc1..00000000
--- a/aconfig/ap4a/com.android.systemui/screenshot_private_profile_behavior_fix_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.systemui"
-  name: "screenshot_private_profile_behavior_fix"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.systemui/screenshot_save_image_exporter_flag_values.textproto b/aconfig/ap4a/com.android.systemui/screenshot_save_image_exporter_flag_values.textproto
deleted file mode 100644
index caca07de..00000000
--- a/aconfig/ap4a/com.android.systemui/screenshot_save_image_exporter_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.systemui"
-  name: "screenshot_save_image_exporter"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.systemui/screenshot_shelf_ui2_flag_values.textproto b/aconfig/ap4a/com.android.systemui/screenshot_shelf_ui2_flag_values.textproto
deleted file mode 100644
index abfa3c0f..00000000
--- a/aconfig/ap4a/com.android.systemui/screenshot_shelf_ui2_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.systemui"
-  name: "screenshot_shelf_ui2"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.systemui/truncated_status_bar_icons_fix_flag_values.textproto b/aconfig/ap4a/com.android.systemui/truncated_status_bar_icons_fix_flag_values.textproto
deleted file mode 100644
index 6a58584f..00000000
--- a/aconfig/ap4a/com.android.systemui/truncated_status_bar_icons_fix_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.systemui"
-  name: "truncated_status_bar_icons_fix"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.telephony.phone.flags/Android.bp b/aconfig/ap4a/com.android.telephony.phone.flags/Android.bp
deleted file mode 100644
index fc2e2d84..00000000
--- a/aconfig/ap4a/com.android.telephony.phone.flags/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-ap4a-com.android.telephony.phone.flags-all",
-  package: "com.android.telephony.phone.flags",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/ap4a/com.android.text.flags/deprecate_ui_fonts_flag_values.textproto b/aconfig/ap4a/com.android.text.flags/deprecate_ui_fonts_flag_values.textproto
deleted file mode 100644
index e1ffe46e..00000000
--- a/aconfig/ap4a/com.android.text.flags/deprecate_ui_fonts_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.text.flags"
-  name: "deprecate_ui_fonts"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.text.flags/fix_double_underline_flag_values.textproto b/aconfig/ap4a/com.android.text.flags/fix_double_underline_flag_values.textproto
deleted file mode 100644
index 89f8ec0a..00000000
--- a/aconfig/ap4a/com.android.text.flags/fix_double_underline_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.text.flags"
-  name: "fix_double_underline"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.text.flags/fix_font_update_failure_flag_values.textproto b/aconfig/ap4a/com.android.text.flags/fix_font_update_failure_flag_values.textproto
deleted file mode 100644
index ce278209..00000000
--- a/aconfig/ap4a/com.android.text.flags/fix_font_update_failure_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.text.flags"
-  name: "fix_font_update_failure"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.text.flags/fix_misaligned_context_menu_flag_values.textproto b/aconfig/ap4a/com.android.text.flags/fix_misaligned_context_menu_flag_values.textproto
deleted file mode 100644
index cf7c84a4..00000000
--- a/aconfig/ap4a/com.android.text.flags/fix_misaligned_context_menu_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.text.flags"
-  name: "fix_misaligned_context_menu"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.text.flags/icu_bidi_migration_flag_values.textproto b/aconfig/ap4a/com.android.text.flags/icu_bidi_migration_flag_values.textproto
deleted file mode 100644
index 66ea0b6b..00000000
--- a/aconfig/ap4a/com.android.text.flags/icu_bidi_migration_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.text.flags"
-  name: "icu_bidi_migration"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.text.flags/lazy_variation_instance_flag_values.textproto b/aconfig/ap4a/com.android.text.flags/lazy_variation_instance_flag_values.textproto
deleted file mode 100644
index 98b9d3af..00000000
--- a/aconfig/ap4a/com.android.text.flags/lazy_variation_instance_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.text.flags"
-  name: "lazy_variation_instance"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.text.flags/phrase_strict_fallback_flag_values.textproto b/aconfig/ap4a/com.android.text.flags/phrase_strict_fallback_flag_values.textproto
deleted file mode 100644
index 94fe0cba..00000000
--- a/aconfig/ap4a/com.android.text.flags/phrase_strict_fallback_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.text.flags"
-  name: "phrase_strict_fallback"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.text.flags/portuguese_hyphenator_flag_values.textproto b/aconfig/ap4a/com.android.text.flags/portuguese_hyphenator_flag_values.textproto
deleted file mode 100644
index 6ed92a62..00000000
--- a/aconfig/ap4a/com.android.text.flags/portuguese_hyphenator_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.text.flags"
-  name: "portuguese_hyphenator"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.text.flags/vendor_custom_locale_fallback_flag_values.textproto b/aconfig/ap4a/com.android.text.flags/vendor_custom_locale_fallback_flag_values.textproto
deleted file mode 100644
index 5958a97f..00000000
--- a/aconfig/ap4a/com.android.text.flags/vendor_custom_locale_fallback_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.text.flags"
-  name: "vendor_custom_locale_fallback"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.trunk_stable_workflow_testing/Android.bp b/aconfig/ap4a/com.android.trunk_stable_workflow_testing/Android.bp
deleted file mode 100644
index 21171027..00000000
--- a/aconfig/ap4a/com.android.trunk_stable_workflow_testing/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-ap4a-com.android.trunk_stable_workflow_testing-all",
-  package: "com.android.trunk_stable_workflow_testing",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/ap4a/com.android.wallpaper/Android.bp b/aconfig/ap4a/com.android.wallpaper/Android.bp
deleted file mode 100644
index 90d55b0b..00000000
--- a/aconfig/ap4a/com.android.wallpaper/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-ap4a-com.android.wallpaper-all",
-  package: "com.android.wallpaper",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/ap4a/com.android.window.flags/activity_snapshot_by_default_flag_values.textproto b/aconfig/ap4a/com.android.window.flags/activity_snapshot_by_default_flag_values.textproto
deleted file mode 100644
index a6801519..00000000
--- a/aconfig/ap4a/com.android.window.flags/activity_snapshot_by_default_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.window.flags"
-  name: "activity_snapshot_by_default"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.window.flags/activity_window_info_flag_flag_values.textproto b/aconfig/ap4a/com.android.window.flags/activity_window_info_flag_flag_values.textproto
deleted file mode 100644
index edda5051..00000000
--- a/aconfig/ap4a/com.android.window.flags/activity_window_info_flag_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.window.flags"
-  name: "activity_window_info_flag"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.window.flags/always_defer_transition_when_apply_wct_flag_values.textproto b/aconfig/ap4a/com.android.window.flags/always_defer_transition_when_apply_wct_flag_values.textproto
deleted file mode 100644
index 26582b45..00000000
--- a/aconfig/ap4a/com.android.window.flags/always_defer_transition_when_apply_wct_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.window.flags"
-  name: "always_defer_transition_when_apply_wct"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.window.flags/bundle_client_transaction_flag_flag_values.textproto b/aconfig/ap4a/com.android.window.flags/bundle_client_transaction_flag_flag_values.textproto
deleted file mode 100644
index 221b52ff..00000000
--- a/aconfig/ap4a/com.android.window.flags/bundle_client_transaction_flag_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.window.flags"
-  name: "bundle_client_transaction_flag"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.window.flags/defer_display_updates_flag_values.textproto b/aconfig/ap4a/com.android.window.flags/defer_display_updates_flag_values.textproto
deleted file mode 100644
index 38314f28..00000000
--- a/aconfig/ap4a/com.android.window.flags/defer_display_updates_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.window.flags"
-  name: "defer_display_updates"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.window.flags/disable_object_pool_flag_values.textproto b/aconfig/ap4a/com.android.window.flags/disable_object_pool_flag_values.textproto
deleted file mode 100644
index d335d064..00000000
--- a/aconfig/ap4a/com.android.window.flags/disable_object_pool_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.window.flags"
-  name: "disable_object_pool"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.window.flags/do_not_skip_ime_by_target_visibility_flag_values.textproto b/aconfig/ap4a/com.android.window.flags/do_not_skip_ime_by_target_visibility_flag_values.textproto
deleted file mode 100644
index 54a72800..00000000
--- a/aconfig/ap4a/com.android.window.flags/do_not_skip_ime_by_target_visibility_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.window.flags"
-  name: "do_not_skip_ime_by_target_visibility"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.window.flags/embedded_activity_back_nav_flag_flag_values.textproto b/aconfig/ap4a/com.android.window.flags/embedded_activity_back_nav_flag_flag_values.textproto
deleted file mode 100644
index e8a946d7..00000000
--- a/aconfig/ap4a/com.android.window.flags/embedded_activity_back_nav_flag_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.window.flags"
-  name: "embedded_activity_back_nav_flag"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.window.flags/enforce_shell_thread_model_flag_values.textproto b/aconfig/ap4a/com.android.window.flags/enforce_shell_thread_model_flag_values.textproto
deleted file mode 100644
index 1f1be81b..00000000
--- a/aconfig/ap4a/com.android.window.flags/enforce_shell_thread_model_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.window.flags"
-  name: "enforce_shell_thread_model"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.window.flags/fix_no_container_update_without_resize_flag_values.textproto b/aconfig/ap4a/com.android.window.flags/fix_no_container_update_without_resize_flag_values.textproto
deleted file mode 100644
index afdf387e..00000000
--- a/aconfig/ap4a/com.android.window.flags/fix_no_container_update_without_resize_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.window.flags"
-  name: "fix_no_container_update_without_resize"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.window.flags/fix_pip_restore_to_overlay_flag_values.textproto b/aconfig/ap4a/com.android.window.flags/fix_pip_restore_to_overlay_flag_values.textproto
deleted file mode 100644
index 49d19f4f..00000000
--- a/aconfig/ap4a/com.android.window.flags/fix_pip_restore_to_overlay_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.window.flags"
-  name: "fix_pip_restore_to_overlay"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.window.flags/fullscreen_dim_flag_flag_values.textproto b/aconfig/ap4a/com.android.window.flags/fullscreen_dim_flag_flag_values.textproto
deleted file mode 100644
index 3fc8a069..00000000
--- a/aconfig/ap4a/com.android.window.flags/fullscreen_dim_flag_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.window.flags"
-  name: "fullscreen_dim_flag"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.window.flags/insets_control_changed_item_flag_values.textproto b/aconfig/ap4a/com.android.window.flags/insets_control_changed_item_flag_values.textproto
deleted file mode 100644
index a6a0b493..00000000
--- a/aconfig/ap4a/com.android.window.flags/insets_control_changed_item_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.window.flags"
-  name: "insets_control_changed_item"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.window.flags/introduce_smoother_dimmer_flag_values.textproto b/aconfig/ap4a/com.android.window.flags/introduce_smoother_dimmer_flag_values.textproto
deleted file mode 100644
index 843fbad5..00000000
--- a/aconfig/ap4a/com.android.window.flags/introduce_smoother_dimmer_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.window.flags"
-  name: "introduce_smoother_dimmer"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.window.flags/keyguard_appear_transition_flag_values.textproto b/aconfig/ap4a/com.android.window.flags/keyguard_appear_transition_flag_values.textproto
deleted file mode 100644
index 1703ca3f..00000000
--- a/aconfig/ap4a/com.android.window.flags/keyguard_appear_transition_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.window.flags"
-  name: "keyguard_appear_transition"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.window.flags/per_user_display_window_settings_flag_values.textproto b/aconfig/ap4a/com.android.window.flags/per_user_display_window_settings_flag_values.textproto
deleted file mode 100644
index 1d691543..00000000
--- a/aconfig/ap4a/com.android.window.flags/per_user_display_window_settings_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.window.flags"
-  name: "per_user_display_window_settings"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.window.flags/remove_prepare_surface_in_placement_flag_values.textproto b/aconfig/ap4a/com.android.window.flags/remove_prepare_surface_in_placement_flag_values.textproto
deleted file mode 100644
index 1c847d9b..00000000
--- a/aconfig/ap4a/com.android.window.flags/remove_prepare_surface_in_placement_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.window.flags"
-  name: "remove_prepare_surface_in_placement"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.window.flags/skip_sleeping_when_switching_display_flag_values.textproto b/aconfig/ap4a/com.android.window.flags/skip_sleeping_when_switching_display_flag_values.textproto
deleted file mode 100644
index 27654d88..00000000
--- a/aconfig/ap4a/com.android.window.flags/skip_sleeping_when_switching_display_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.window.flags"
-  name: "skip_sleeping_when_switching_display"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.window.flags/window_session_relayout_info_flag_values.textproto b/aconfig/ap4a/com.android.window.flags/window_session_relayout_info_flag_values.textproto
deleted file mode 100644
index 8ab8a120..00000000
--- a/aconfig/ap4a/com.android.window.flags/window_session_relayout_info_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.window.flags"
-  name: "window_session_relayout_info"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.android.window.flags/window_token_config_thread_safe_flag_values.textproto b/aconfig/ap4a/com.android.window.flags/window_token_config_thread_safe_flag_values.textproto
deleted file mode 100644
index 8e07249b..00000000
--- a/aconfig/ap4a/com.android.window.flags/window_token_config_thread_safe_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.window.flags"
-  name: "window_token_config_thread_safe"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/ap4a/com.example.android.aconfig.demo.flags/Android.bp b/aconfig/ap4a/com.example.android.aconfig.demo.flags/Android.bp
deleted file mode 100644
index 4895b197..00000000
--- a/aconfig/ap4a/com.example.android.aconfig.demo.flags/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-ap4a-com.example.android.aconfig.demo.flags-all",
-  package: "com.example.android.aconfig.demo.flags",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/ap4a/com.google.android.platform.launcher.aconfig.flags/Android.bp b/aconfig/ap4a/com.google.android.platform.launcher.aconfig.flags/Android.bp
deleted file mode 100644
index cd0e50a2..00000000
--- a/aconfig/ap4a/com.google.android.platform.launcher.aconfig.flags/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-ap4a-com.google.android.platform.launcher.aconfig.flags-all",
-  package: "com.google.android.platform.launcher.aconfig.flags",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/trunk_staging/Android.bp b/aconfig/trunk_staging/Android.bp
index 87ad4ff0..2f36c6ef 100644
--- a/aconfig/trunk_staging/Android.bp
+++ b/aconfig/trunk_staging/Android.bp
@@ -13,213 +13,191 @@
 // limitations under the License.
 
 aconfig_value_set {
-  name: "aconfig_value_set-platform_build_release-trunk_staging",
-  values: [
-        "aconfig-values-platform_build_release-trunk_staging-android.service.autofill-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.server.deviceidle-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.hardware.libsensor.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.permission.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.server.power.feature.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.providers.contacts.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.media.codec-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.providers.media.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.media.audioserver-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.hardware.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.content.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.os.profiling-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.google.android.iwlan.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.server.deviceconfig-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.graphics.libgui.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.server.power.optimization-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.sdksandbox.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.media.audio-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.launcher3-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.server.telecom.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.view.contentprotection.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.car.feature-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.server.usage-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.security.flag-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.media.aaudio-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.server.feature.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.internal.pm.pkg.component.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.settingslib.media.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.server.connectivity-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.server.usb.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.internal.jank-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.nfc-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.os.statsd.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.server.notification-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.trunk_stable_workflow_testing-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.content.pm-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.server-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.server.accessibility-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.media.mainline.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.server.backup-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.media.projection.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.libcore-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.media.codec.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.nfc.nci.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.provider.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.adservices.ondevicepersonalization.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-libgooglecamerahal.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.frameworks.sensorservice.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.settings.media_drm-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.hardware.input-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.media.midi-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.service.appprediction.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.graphics.libvulkan.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.car.settings-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.hardware.camera2-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.appwidget.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.server.alarm-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.intentresolver-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.healthfitness.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.server.updates-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.car.carlauncher-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.wallpaper-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.chre.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.provider.configinfrastructure.framework-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.server.app-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.telephony.phone.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.location.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.service.voice.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.wm.shell-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.settings.connecteddevice.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.net.wifi.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.adaptiveauth-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.car.dockutil-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.media.editing.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.app.jank-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.settings.keyboard-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.server.companion.virtual-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.settings.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.companion-all",
-        "aconfig-values-platform_build_release-trunk_staging-vendor.vibrator.hal.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.system.virtualmachine.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.settingslib.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.car.datasubscription-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.os-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.companion.virtualdevice.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.tracing-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.server.power.hint-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.btaudio.hal.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.graphics.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.widget.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.server.net-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.aconfig.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.media.audioclient-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.net.vcn-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.settingslib.widget.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.graphics.hwui.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.graphics.bufferstreams.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.aconfig.test-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.systemui.shared-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.graphics.surfaceflinger.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.credentials.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.art.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.hardware.radio-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.managedprovisioning.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.org.conscrypt-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.os.vibrator-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.devicelock.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.server.job-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.internal.foldables.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.settings.development-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.settings.factory_reset-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.systemui.communal-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.view.contentcapture.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.healthconnect.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.bluetooth.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.media.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.multiuser-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.server.policy-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.systemui.accessibility.accessibilitymenu-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.service.dreams-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.crashrecovery.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.uwb.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.server.dreams-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.app.job-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.egg.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.icu-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.settingslib.widget.selectorwithwidgetpreference.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.media.playback.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.internal.camera.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.systemui.aconfig-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.service.notification-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.example.android.aconfig.demo.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.security-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.net.thread.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.service.controls.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.hardware.usb.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.adservices.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.wifi.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.google.android.platform.launcher.aconfig.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.view.accessibility-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.app.appfunctions.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.providers.settings-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.systemui-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.server.utils-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.cellbroadcastreceiver.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.server.devicepolicy.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.settings.accessibility-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.internal.compat.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.server.policy.feature.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.media.performance.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.aconfig_new_storage-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.server.stats-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.permission.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.app.wearable-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.server.security-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.app.ondeviceintelligence.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.app.admin.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.ipsec.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.nearby.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.server.os-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.server.contextualsearch.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.input.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.net.ct.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.server.pm-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.server.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.libhardware.dynamic.sensors.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.graphics.pdf.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.deviceaswebcam.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.database.sqlite-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.service.chooser-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.net.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.server.power.batterysaver-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.server.biometrics-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.text.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.net.thread.platform.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.view.inputmethod-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.providers.contactkeys.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.view.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.systemui.car-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.media.audiopolicy-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.media.soundtrigger-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.security.keystore2-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.app.smartspace.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.media.audio-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.net.platform.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.server.am-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.server.display.feature.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.hardware.devicestate.feature.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.window.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.app.contextualsearch.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.hardware.biometrics-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.speech.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.server.powerstats-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.internal.os-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.content.res-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.app.usage-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.nfc.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.server.locksettings-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.sdk-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.provider-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.app-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.companion.virtual.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.appsearch.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-com.android.internal.telephony.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.media.tv.flags-all",
-        "aconfig-values-platform_build_release-trunk_staging-android.webkit-all",
-      ]
-}
\ No newline at end of file
+    name: "aconfig_value_set-platform_build_release-trunk_staging",
+    values: [
+      "aconfig-values-platform_build_release-trunk_staging-com.android.frameworks.sensorservice.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.net.vcn-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.bluetooth.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.media.performance.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.net.thread.platform.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.server.am-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.app.wearable-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.net.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-vendor.vibrator.hal.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.service.chooser-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.hardware.libsensor.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.healthfitness.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.graphics.libgui.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.org.conscrypt-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.chre.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.media.mainline.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.app.usage-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.adaptiveauth-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.provider.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.server.notification-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.app.appfunctions.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.os-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.nfc.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.input.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.server.biometrics-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.media.codec-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.hardware.radio-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.service.dreams-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.security-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.adservices.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.security.flag-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.egg.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.app.admin.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.net.wifi.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.settings.media_drm-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.server-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.graphics.surfaceflinger.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.server.usb.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.hardware.input-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.content.pm-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.server.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.icu-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.service.voice.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.btaudio.hal.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.webkit-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.server.job-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.net.ct.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.app.ondeviceintelligence.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.appwidget.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.service.autofill-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.aconfig_new_storage-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.server.display.feature.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.sdk-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.view.inputmethod-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.aconfig.test-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.managedprovisioning.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.media.editing.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.wm.shell-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.service.controls.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.server.backup-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.app-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.location.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.appsearch.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.security.keystore2-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.media.codec.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.hardware.usb.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.wifi.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.app.smartspace.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.car.dockutil-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.sdksandbox.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.os.vibrator-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.hardware.devicestate.feature.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.internal.pm.pkg.component.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.launcher3-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.systemui.accessibility.accessibilitymenu-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.media.audioclient-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.internal.os-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.speech.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.server.updates-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.media.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.server.stats-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.car.carlauncher-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.systemui-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.server.power.feature.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.companion.virtualdevice.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.database.sqlite-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.net.thread.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.crashrecovery.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.system.virtualmachine.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.view.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.settings.accessibility-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.os.profiling-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.car.settings-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.view.contentcapture.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.app.job-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.providers.contactkeys.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.settingslib.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.wallpaper-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.server.power.hint-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.providers.settings-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.internal.telephony.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.settings.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.hardware.biometrics-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.server.alarm-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.trunk_stable_workflow_testing-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.server.usage-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.internal.foldables.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.server.accessibility-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.settingslib.widget.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.server.feature.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.text.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.media.audio-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.server.deviceconfig-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.settingslib.media.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.server.dreams-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.uprobestats.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.provider-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.media.tv.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.art.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.media.aaudio-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.media.projection.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.graphics.hwui.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.service.appprediction.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-libgooglecamerahal.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.deviceaswebcam.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.multiuser-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.intentresolver-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.settings.factory_reset-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.graphics.pdf.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.credentials.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.permission.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.media.playback.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.service.notification-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.libcore-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.media.audiopolicy-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.internal.camera.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.companion.virtual.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.settingslib.widget.selectorwithwidgetpreference.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.ipsec.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.internal.compat.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.healthconnect.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.server.deviceidle-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.content.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.app.contextualsearch.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.systemui.car-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.google.android.iwlan.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.server.telecom.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.uwb.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.window.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.server.policy.feature.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.libhardware.dynamic.sensors.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.content.res-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.graphics.libvulkan.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.media.midi-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.adservices.ondevicepersonalization.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.graphics.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.hardware.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.server.utils-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.example.android.aconfig.demo.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.widget.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.companion-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.media.audio-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.car.feature-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.car.datasubscription-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.os.statsd.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.server.policy-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.media.audioserver-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.server.power.batterysaver-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.net.platform.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.tracing-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.view.accessibility-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.nfc.nci.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.server.power.optimization-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.providers.media.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.nearby.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.nfc-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.server.app-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.server.net-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.media.soundtrigger-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.permission.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.server.powerstats-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.settings.development-all",
+      "aconfig-values-platform_build_release-trunk_staging-android.view.contentprotection.flags-all",
+      "aconfig-values-platform_build_release-trunk_staging-com.android.systemui.shared-all"
+    ]
+}
diff --git a/aconfig/trunk_staging/android.app.admin.flags/allow_screen_brightness_control_on_cope_flag_values.textproto b/aconfig/trunk_staging/android.app.admin.flags/allow_screen_brightness_control_on_cope_flag_values.textproto
deleted file mode 100644
index baa7848b..00000000
--- a/aconfig/trunk_staging/android.app.admin.flags/allow_screen_brightness_control_on_cope_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.app.admin.flags"
-  name: "allow_screen_brightness_control_on_cope"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/android.app.admin.flags/always_persist_do_flag_values.textproto b/aconfig/trunk_staging/android.app.admin.flags/always_persist_do_flag_values.textproto
deleted file mode 100644
index 198ad9d3..00000000
--- a/aconfig/trunk_staging/android.app.admin.flags/always_persist_do_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.app.admin.flags"
-  name: "always_persist_do"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/android.app.admin.flags/coexistence_migration_for_non_emm_management_enabled_flag_values.textproto b/aconfig/trunk_staging/android.app.admin.flags/coexistence_migration_for_non_emm_management_enabled_flag_values.textproto
deleted file mode 100644
index 599537ce..00000000
--- a/aconfig/trunk_staging/android.app.admin.flags/coexistence_migration_for_non_emm_management_enabled_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.app.admin.flags"
-  name: "coexistence_migration_for_non_emm_management_enabled"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/android.app.admin.flags/copy_account_with_retry_enabled_flag_values.textproto b/aconfig/trunk_staging/android.app.admin.flags/copy_account_with_retry_enabled_flag_values.textproto
deleted file mode 100644
index 671b5b3b..00000000
--- a/aconfig/trunk_staging/android.app.admin.flags/copy_account_with_retry_enabled_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.app.admin.flags"
-  name: "copy_account_with_retry_enabled"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/android.app.admin.flags/dedicated_device_control_enabled_flag_values.textproto b/aconfig/trunk_staging/android.app.admin.flags/dedicated_device_control_enabled_flag_values.textproto
deleted file mode 100644
index 9ac9ca3c..00000000
--- a/aconfig/trunk_staging/android.app.admin.flags/dedicated_device_control_enabled_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.app.admin.flags"
-  name: "dedicated_device_control_enabled"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/android.app.admin.flags/delete_private_space_under_restriction_flag_values.textproto b/aconfig/trunk_staging/android.app.admin.flags/delete_private_space_under_restriction_flag_values.textproto
deleted file mode 100644
index ab1aade3..00000000
--- a/aconfig/trunk_staging/android.app.admin.flags/delete_private_space_under_restriction_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.app.admin.flags"
-  name: "delete_private_space_under_restriction"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/android.app.admin.flags/device_policy_size_tracking_internal_bug_fix_enabled_flag_values.textproto b/aconfig/trunk_staging/android.app.admin.flags/device_policy_size_tracking_internal_bug_fix_enabled_flag_values.textproto
deleted file mode 100644
index 1de347cb..00000000
--- a/aconfig/trunk_staging/android.app.admin.flags/device_policy_size_tracking_internal_bug_fix_enabled_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.app.admin.flags"
-  name: "device_policy_size_tracking_internal_bug_fix_enabled"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/android.app.admin.flags/disallow_user_control_bg_usage_fix_flag_values.textproto b/aconfig/trunk_staging/android.app.admin.flags/disallow_user_control_bg_usage_fix_flag_values.textproto
deleted file mode 100644
index cd7174a9..00000000
--- a/aconfig/trunk_staging/android.app.admin.flags/disallow_user_control_bg_usage_fix_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.app.admin.flags"
-  name: "disallow_user_control_bg_usage_fix"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/android.app.admin.flags/dmrh_set_app_restrictions_flag_values.textproto b/aconfig/trunk_staging/android.app.admin.flags/dmrh_set_app_restrictions_flag_values.textproto
deleted file mode 100644
index 02164905..00000000
--- a/aconfig/trunk_staging/android.app.admin.flags/dmrh_set_app_restrictions_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.app.admin.flags"
-  name: "dmrh_set_app_restrictions"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/android.app.admin.flags/dumpsys_policy_engine_migration_enabled_flag_values.textproto b/aconfig/trunk_staging/android.app.admin.flags/dumpsys_policy_engine_migration_enabled_flag_values.textproto
deleted file mode 100644
index abb3da1c..00000000
--- a/aconfig/trunk_staging/android.app.admin.flags/dumpsys_policy_engine_migration_enabled_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.app.admin.flags"
-  name: "dumpsys_policy_engine_migration_enabled"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/android.app.admin.flags/headless_device_owner_delegate_security_logging_bug_fix_flag_values.textproto b/aconfig/trunk_staging/android.app.admin.flags/headless_device_owner_delegate_security_logging_bug_fix_flag_values.textproto
deleted file mode 100644
index f75e493c..00000000
--- a/aconfig/trunk_staging/android.app.admin.flags/headless_device_owner_delegate_security_logging_bug_fix_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.app.admin.flags"
-  name: "headless_device_owner_delegate_security_logging_bug_fix"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/android.app.admin.flags/headless_device_owner_provisioning_fix_enabled_flag_values.textproto b/aconfig/trunk_staging/android.app.admin.flags/headless_device_owner_provisioning_fix_enabled_flag_values.textproto
deleted file mode 100644
index 60b012f8..00000000
--- a/aconfig/trunk_staging/android.app.admin.flags/headless_device_owner_provisioning_fix_enabled_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.app.admin.flags"
-  name: "headless_device_owner_provisioning_fix_enabled"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/android.app.admin.flags/headless_single_user_bad_device_admin_state_fix_flag_values.textproto b/aconfig/trunk_staging/android.app.admin.flags/headless_single_user_bad_device_admin_state_fix_flag_values.textproto
deleted file mode 100644
index b8ebbd86..00000000
--- a/aconfig/trunk_staging/android.app.admin.flags/headless_single_user_bad_device_admin_state_fix_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.app.admin.flags"
-  name: "headless_single_user_bad_device_admin_state_fix"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/android.app.admin.flags/headless_single_user_compatibility_fix_flag_values.textproto b/aconfig/trunk_staging/android.app.admin.flags/headless_single_user_compatibility_fix_flag_values.textproto
deleted file mode 100644
index 970769ad..00000000
--- a/aconfig/trunk_staging/android.app.admin.flags/headless_single_user_compatibility_fix_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.app.admin.flags"
-  name: "headless_single_user_compatibility_fix"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/android.app.admin.flags/headless_single_user_fixes_flag_values.textproto b/aconfig/trunk_staging/android.app.admin.flags/headless_single_user_fixes_flag_values.textproto
deleted file mode 100644
index 6f5fb05e..00000000
--- a/aconfig/trunk_staging/android.app.admin.flags/headless_single_user_fixes_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.app.admin.flags"
-  name: "headless_single_user_fixes"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/android.app.admin.flags/hsum_unlock_notification_fix_flag_values.textproto b/aconfig/trunk_staging/android.app.admin.flags/hsum_unlock_notification_fix_flag_values.textproto
deleted file mode 100644
index ae16913d..00000000
--- a/aconfig/trunk_staging/android.app.admin.flags/hsum_unlock_notification_fix_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.app.admin.flags"
-  name: "hsum_unlock_notification_fix"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/android.app.admin.flags/permission_migration_for_zero_trust_impl_enabled_flag_values.textproto b/aconfig/trunk_staging/android.app.admin.flags/permission_migration_for_zero_trust_impl_enabled_flag_values.textproto
deleted file mode 100644
index 50e5222c..00000000
--- a/aconfig/trunk_staging/android.app.admin.flags/permission_migration_for_zero_trust_impl_enabled_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.app.admin.flags"
-  name: "permission_migration_for_zero_trust_impl_enabled"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/android.app.admin.flags/power_exemption_bg_usage_fix_flag_values.textproto b/aconfig/trunk_staging/android.app.admin.flags/power_exemption_bg_usage_fix_flag_values.textproto
deleted file mode 100644
index fda919d4..00000000
--- a/aconfig/trunk_staging/android.app.admin.flags/power_exemption_bg_usage_fix_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.app.admin.flags"
-  name: "power_exemption_bg_usage_fix"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/android.chre.flags/bug_fix_reduce_lock_holding_period_flag_values.textproto b/aconfig/trunk_staging/android.chre.flags/bug_fix_reduce_lock_holding_period_flag_values.textproto
deleted file mode 100644
index 779cd745..00000000
--- a/aconfig/trunk_staging/android.chre.flags/bug_fix_reduce_lock_holding_period_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.chre.flags"
-  name: "bug_fix_reduce_lock_holding_period"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/android.chre.flags/flag_log_nanoapp_load_metrics_flag_values.textproto b/aconfig/trunk_staging/android.chre.flags/flag_log_nanoapp_load_metrics_flag_values.textproto
deleted file mode 100644
index 5b547757..00000000
--- a/aconfig/trunk_staging/android.chre.flags/flag_log_nanoapp_load_metrics_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.chre.flags"
-  name: "flag_log_nanoapp_load_metrics"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/android.chre.flags/metrics_reporter_in_the_daemon_flag_values.textproto b/aconfig/trunk_staging/android.chre.flags/metrics_reporter_in_the_daemon_flag_values.textproto
deleted file mode 100644
index e5e50f3e..00000000
--- a/aconfig/trunk_staging/android.chre.flags/metrics_reporter_in_the_daemon_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.chre.flags"
-  name: "metrics_reporter_in_the_daemon"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/android.chre.flags/reduce_lock_holding_period_flag_values.textproto b/aconfig/trunk_staging/android.chre.flags/reduce_lock_holding_period_flag_values.textproto
deleted file mode 100644
index 37d20729..00000000
--- a/aconfig/trunk_staging/android.chre.flags/reduce_lock_holding_period_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.chre.flags"
-  name: "reduce_lock_holding_period"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/android.chre.flags/remove_ap_wakeup_metric_report_limit_flag_values.textproto b/aconfig/trunk_staging/android.chre.flags/remove_ap_wakeup_metric_report_limit_flag_values.textproto
deleted file mode 100644
index a6777997..00000000
--- a/aconfig/trunk_staging/android.chre.flags/remove_ap_wakeup_metric_report_limit_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.chre.flags"
-  name: "remove_ap_wakeup_metric_report_limit"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/android.companion.virtual.flags/consistent_display_flags_flag_values.textproto b/aconfig/trunk_staging/android.companion.virtual.flags/consistent_display_flags_flag_values.textproto
deleted file mode 100644
index 6d284a3e..00000000
--- a/aconfig/trunk_staging/android.companion.virtual.flags/consistent_display_flags_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.companion.virtual.flags"
-  name: "consistent_display_flags"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/android.companion.virtual.flags/express_metrics_flag_values.textproto b/aconfig/trunk_staging/android.companion.virtual.flags/express_metrics_flag_values.textproto
deleted file mode 100644
index 8d44be57..00000000
--- a/aconfig/trunk_staging/android.companion.virtual.flags/express_metrics_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.companion.virtual.flags"
-  name: "express_metrics"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/android.companion.virtual.flags/interactive_screen_mirror_flag_values.textproto b/aconfig/trunk_staging/android.companion.virtual.flags/interactive_screen_mirror_flag_values.textproto
deleted file mode 100644
index c826b8fc..00000000
--- a/aconfig/trunk_staging/android.companion.virtual.flags/interactive_screen_mirror_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.companion.virtual.flags"
-  name: "interactive_screen_mirror"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/android.companion.virtual.flags/intercept_intents_before_applying_policy_flag_values.textproto b/aconfig/trunk_staging/android.companion.virtual.flags/intercept_intents_before_applying_policy_flag_values.textproto
deleted file mode 100644
index 206962f8..00000000
--- a/aconfig/trunk_staging/android.companion.virtual.flags/intercept_intents_before_applying_policy_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.companion.virtual.flags"
-  name: "intercept_intents_before_applying_policy"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/android.companion.virtual.flags/stream_permissions_flag_values.textproto b/aconfig/trunk_staging/android.companion.virtual.flags/stream_permissions_flag_values.textproto
deleted file mode 100644
index 15b8a850..00000000
--- a/aconfig/trunk_staging/android.companion.virtual.flags/stream_permissions_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.companion.virtual.flags"
-  name: "stream_permissions"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/android.companion.virtualdevice.flags/intent_interception_action_matching_fix_flag_values.textproto b/aconfig/trunk_staging/android.companion.virtualdevice.flags/intent_interception_action_matching_fix_flag_values.textproto
deleted file mode 100644
index c1bd30e4..00000000
--- a/aconfig/trunk_staging/android.companion.virtualdevice.flags/intent_interception_action_matching_fix_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.companion.virtualdevice.flags"
-  name: "intent_interception_action_matching_fix"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/android.companion.virtualdevice.flags/metrics_collection_flag_values.textproto b/aconfig/trunk_staging/android.companion.virtualdevice.flags/metrics_collection_flag_values.textproto
deleted file mode 100644
index ff413d9d..00000000
--- a/aconfig/trunk_staging/android.companion.virtualdevice.flags/metrics_collection_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.companion.virtualdevice.flags"
-  name: "metrics_collection"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/trunk_staging/android.companion.virtualdevice.flags/virtual_display_multi_window_mode_support_flag_values.textproto b/aconfig/trunk_staging/android.companion.virtualdevice.flags/virtual_display_multi_window_mode_support_flag_values.textproto
deleted file mode 100644
index 88a72cbf..00000000
--- a/aconfig/trunk_staging/android.companion.virtualdevice.flags/virtual_display_multi_window_mode_support_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.companion.virtualdevice.flags"
-  name: "virtual_display_multi_window_mode_support"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/trunk_staging/android.companion/companion_transport_apis_flag_values.textproto b/aconfig/trunk_staging/android.companion/companion_transport_apis_flag_values.textproto
deleted file mode 100644
index 38effbad..00000000
--- a/aconfig/trunk_staging/android.companion/companion_transport_apis_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.companion"
-  name: "companion_transport_apis"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/android.credentials.flags/wear_credential_manager_enabled_flag_values.textproto b/aconfig/trunk_staging/android.credentials.flags/wear_credential_manager_enabled_flag_values.textproto
new file mode 100644
index 00000000..d4d5621d
--- /dev/null
+++ b/aconfig/trunk_staging/android.credentials.flags/wear_credential_manager_enabled_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.credentials.flags"
+  name: "wear_credential_manager_enabled"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/android.net.vcn/TEST_MAPPING b/aconfig/trunk_staging/android.net.vcn/TEST_MAPPING
deleted file mode 100644
index 48ee9340..00000000
--- a/aconfig/trunk_staging/android.net.vcn/TEST_MAPPING
+++ /dev/null
@@ -1,7 +0,0 @@
-{
-  "imports": [
-    {
-      "path": "frameworks/base/services/core/java/com/android/server/vcn"
-    }
-  ]
-}
\ No newline at end of file
diff --git a/aconfig/trunk_staging/android.net.vcn/allow_disable_ipsec_loss_detector_flag_values.textproto b/aconfig/trunk_staging/android.net.vcn/allow_disable_ipsec_loss_detector_flag_values.textproto
deleted file mode 100644
index 51d69e46..00000000
--- a/aconfig/trunk_staging/android.net.vcn/allow_disable_ipsec_loss_detector_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.net.vcn"
-  name: "allow_disable_ipsec_loss_detector"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/android.os.vibrator/keyboard_category_enabled_flag_values.textproto b/aconfig/trunk_staging/android.os.vibrator/keyboard_category_enabled_flag_values.textproto
deleted file mode 100644
index 29b12be4..00000000
--- a/aconfig/trunk_staging/android.os.vibrator/keyboard_category_enabled_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.os.vibrator"
-  name: "keyboard_category_enabled"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/android.os.vibrator/use_vibrator_haptic_feedback_flag_values.textproto b/aconfig/trunk_staging/android.os.vibrator/use_vibrator_haptic_feedback_flag_values.textproto
deleted file mode 100644
index ed2358eb..00000000
--- a/aconfig/trunk_staging/android.os.vibrator/use_vibrator_haptic_feedback_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.os.vibrator"
-  name: "use_vibrator_haptic_feedback"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/android.os/adpf_fmq_eager_send_flag_values.textproto b/aconfig/trunk_staging/android.os/adpf_fmq_eager_send_flag_values.textproto
deleted file mode 100644
index cf1804d9..00000000
--- a/aconfig/trunk_staging/android.os/adpf_fmq_eager_send_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.os"
-  name: "adpf_fmq_eager_send"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/trunk_staging/android.os/bugreport_mode_max_value_flag_values.textproto b/aconfig/trunk_staging/android.os/bugreport_mode_max_value_flag_values.textproto
deleted file mode 100644
index 094b7f93..00000000
--- a/aconfig/trunk_staging/android.os/bugreport_mode_max_value_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.os"
-  name: "bugreport_mode_max_value"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/android.provider.configinfrastructure.framework/Android.bp b/aconfig/trunk_staging/android.provider.configinfrastructure.framework/Android.bp
deleted file mode 100644
index 8e0013b7..00000000
--- a/aconfig/trunk_staging/android.provider.configinfrastructure.framework/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-trunk_staging-android.provider.configinfrastructure.framework-all",
-  package: "android.provider.configinfrastructure.framework",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/trunk_staging/android.security/fix_unlocked_device_required_keys_v2_flag_values.textproto b/aconfig/trunk_staging/android.security/fix_unlocked_device_required_keys_v2_flag_values.textproto
deleted file mode 100644
index 24c6f6d6..00000000
--- a/aconfig/trunk_staging/android.security/fix_unlocked_device_required_keys_v2_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.security"
-  name: "fix_unlocked_device_required_keys_v2"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/trunk_staging/android.app.jank/Android.bp b/aconfig/trunk_staging/android.uprobestats.flags/Android.bp
similarity index 91%
rename from aconfig/trunk_staging/android.app.jank/Android.bp
rename to aconfig/trunk_staging/android.uprobestats.flags/Android.bp
index 30762340..f0ef3782 100644
--- a/aconfig/trunk_staging/android.app.jank/Android.bp
+++ b/aconfig/trunk_staging/android.uprobestats.flags/Android.bp
@@ -13,8 +13,8 @@
 // limitations under the License.
 
 aconfig_values {
-  name: "aconfig-values-platform_build_release-trunk_staging-android.app.jank-all",
-  package: "android.app.jank",
+  name: "aconfig-values-platform_build_release-trunk_staging-android.uprobestats.flags-all",
+  package: "android.uprobestats.flags",
   srcs: [
     "*_flag_values.textproto",
   ]
diff --git a/aconfig/trunk_staging/android.uprobestats.flags/enable_uprobestats_flag_values.textproto b/aconfig/trunk_staging/android.uprobestats.flags/enable_uprobestats_flag_values.textproto
new file mode 100644
index 00000000..dfba4d6e
--- /dev/null
+++ b/aconfig/trunk_staging/android.uprobestats.flags/enable_uprobestats_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.uprobestats.flags"
+  name: "enable_uprobestats"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/trunk_staging/android.view.accessibility/TEST_MAPPING b/aconfig/trunk_staging/android.view.accessibility/TEST_MAPPING
deleted file mode 100644
index ccac2489..00000000
--- a/aconfig/trunk_staging/android.view.accessibility/TEST_MAPPING
+++ /dev/null
@@ -1,7 +0,0 @@
-{
-  "imports": [
-    {
-      "path": "frameworks/base/core/java/android/view/accessibility/TEST_MAPPING"
-    }
-  ]
-}
\ No newline at end of file
diff --git a/aconfig/trunk_staging/android.view.inputmethod/TEST_MAPPING b/aconfig/trunk_staging/android.view.inputmethod/TEST_MAPPING
deleted file mode 100644
index 84f31fae..00000000
--- a/aconfig/trunk_staging/android.view.inputmethod/TEST_MAPPING
+++ /dev/null
@@ -1,7 +0,0 @@
-{
- "imports": [
-    {
-      "path": "frameworks/base/services/core/java/com/android/server/inputmethod"
-    }
-  ]
-}
diff --git a/aconfig/trunk_staging/com.android.aconfig.flags/Android.bp b/aconfig/trunk_staging/com.android.aconfig.flags/Android.bp
deleted file mode 100644
index 27bbaa30..00000000
--- a/aconfig/trunk_staging/com.android.aconfig.flags/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-trunk_staging-com.android.aconfig.flags-all",
-  package: "com.android.aconfig.flags",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/trunk_staging/com.android.art.flags/OWNERS b/aconfig/trunk_staging/com.android.art.flags/OWNERS
deleted file mode 100644
index 3414a746..00000000
--- a/aconfig/trunk_staging/com.android.art.flags/OWNERS
+++ /dev/null
@@ -1 +0,0 @@
-include platform/art:/OWNERS
diff --git a/aconfig/trunk_staging/com.android.art.flags/m2024_09_ramp_flag_values.textproto b/aconfig/trunk_staging/com.android.art.flags/m2024_09_ramp_flag_values.textproto
deleted file mode 100644
index 3e5fb0c2..00000000
--- a/aconfig/trunk_staging/com.android.art.flags/m2024_09_ramp_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.art.flags"
-  name: "m2024_09_ramp"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/trunk_staging/com.android.art.flags/m2024_10_ramp_flag_values.textproto b/aconfig/trunk_staging/com.android.art.flags/m2024_10_ramp_flag_values.textproto
deleted file mode 100644
index 741cb582..00000000
--- a/aconfig/trunk_staging/com.android.art.flags/m2024_10_ramp_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.art.flags"
-  name: "m2024_10_ramp"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/TEST_MAPPING b/aconfig/trunk_staging/com.android.bluetooth.flags/TEST_MAPPING
deleted file mode 100644
index f337913b..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/TEST_MAPPING
+++ /dev/null
@@ -1,7 +0,0 @@
-{
-  "imports": [
-    {
-      "path": "packages/modules/Bluetooth"
-    }
-  ]
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/a2dp_concurrent_source_sink_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/a2dp_concurrent_source_sink_flag_values.textproto
deleted file mode 100644
index cb22de46..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/a2dp_concurrent_source_sink_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "a2dp_concurrent_source_sink"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/a2dp_offload_codec_extensibility_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/a2dp_offload_codec_extensibility_flag_values.textproto
deleted file mode 100644
index 127c266a..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/a2dp_offload_codec_extensibility_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "a2dp_offload_codec_extensibility"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/airplane_mode_x_ble_on_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/airplane_mode_x_ble_on_flag_values.textproto
deleted file mode 100644
index cd6a377b..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/airplane_mode_x_ble_on_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "airplane_mode_x_ble_on"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/asha_asrc_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/asha_asrc_flag_values.textproto
deleted file mode 100644
index 756bd4a3..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/asha_asrc_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "asha_asrc"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/auto_connect_on_hfp_when_no_a2dp_device_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/auto_connect_on_hfp_when_no_a2dp_device_flag_values.textproto
deleted file mode 100644
index 22cc03c8..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/auto_connect_on_hfp_when_no_a2dp_device_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "auto_connect_on_hfp_when_no_a2dp_device"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/auto_on_feature_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/auto_on_feature_flag_values.textproto
deleted file mode 100644
index 91fa763d..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/auto_on_feature_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "auto_on_feature"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/bluffs_mitigation_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/browsing_refactor_flag_values.textproto
similarity index 77%
rename from aconfig/trunk_staging/com.android.bluetooth.flags/bluffs_mitigation_flag_values.textproto
rename to aconfig/trunk_staging/com.android.bluetooth.flags/browsing_refactor_flag_values.textproto
index 3aaff76a..da5d1e4d 100644
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/bluffs_mitigation_flag_values.textproto
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/browsing_refactor_flag_values.textproto
@@ -1,6 +1,6 @@
 flag_value {
   package: "com.android.bluetooth.flags"
-  name: "bluffs_mitigation"
+  name: "browsing_refactor"
   state: ENABLED
   permission: READ_WRITE
 }
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/bta_dm_disc_stuck_in_cancelling_fix_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/bta_dm_disc_stuck_in_cancelling_fix_flag_values.textproto
deleted file mode 100644
index b0926321..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/bta_dm_disc_stuck_in_cancelling_fix_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "bta_dm_disc_stuck_in_cancelling_fix"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/close_rfcomm_instead_of_reset_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/close_rfcomm_instead_of_reset_flag_values.textproto
deleted file mode 100644
index b6c9d918..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/close_rfcomm_instead_of_reset_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "close_rfcomm_instead_of_reset"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/connect_hid_after_service_discovery_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/connect_hid_after_service_discovery_flag_values.textproto
deleted file mode 100644
index 77a677f9..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/connect_hid_after_service_discovery_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "connect_hid_after_service_discovery"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/continue_service_discovery_when_cancel_device_discovery_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/continue_service_discovery_when_cancel_device_discovery_flag_values.textproto
deleted file mode 100644
index 7f88b893..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/continue_service_discovery_when_cancel_device_discovery_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "continue_service_discovery_when_cancel_device_discovery"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/correct_bond_type_of_loaded_devices_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/correct_bond_type_of_loaded_devices_flag_values.textproto
deleted file mode 100644
index 35dd6f62..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/correct_bond_type_of_loaded_devices_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "correct_bond_type_of_loaded_devices"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/delay_bonding_when_busy_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/delay_bonding_when_busy_flag_values.textproto
deleted file mode 100644
index b7e249c6..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/delay_bonding_when_busy_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "delay_bonding_when_busy"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/divide_long_single_gap_data_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/divide_long_single_gap_data_flag_values.textproto
deleted file mode 100644
index 61447271..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/divide_long_single_gap_data_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "divide_long_single_gap_data"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/do_not_replace_existing_cod_with_uncategorized_cod_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/do_not_replace_existing_cod_with_uncategorized_cod_flag_values.textproto
deleted file mode 100644
index e73a0a01..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/do_not_replace_existing_cod_with_uncategorized_cod_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "do_not_replace_existing_cod_with_uncategorized_cod"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/dumpsys_acquire_stack_when_executing_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/dumpsys_acquire_stack_when_executing_flag_values.textproto
deleted file mode 100644
index d80d7d2f..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/dumpsys_acquire_stack_when_executing_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "dumpsys_acquire_stack_when_executing"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/dumpsys_use_passed_in_fd_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/dumpsys_use_passed_in_fd_flag_values.textproto
deleted file mode 100644
index 116d965c..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/dumpsys_use_passed_in_fd_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "dumpsys_use_passed_in_fd"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/ensure_valid_adv_flag_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/ensure_valid_adv_flag_flag_values.textproto
deleted file mode 100644
index 22423376..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/ensure_valid_adv_flag_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "ensure_valid_adv_flag"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/explicit_kill_from_system_server_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/explicit_kill_from_system_server_flag_values.textproto
deleted file mode 100644
index 5a06d64b..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/explicit_kill_from_system_server_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "explicit_kill_from_system_server"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/fix_le_oob_pairing_bypass_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/fix_le_oob_pairing_bypass_flag_values.textproto
deleted file mode 100644
index ea261e66..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/fix_le_oob_pairing_bypass_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "fix_le_oob_pairing_bypass"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/fix_le_pairing_passkey_entry_bypass_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/fix_le_pairing_passkey_entry_bypass_flag_values.textproto
deleted file mode 100644
index 8684b95d..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/fix_le_pairing_passkey_entry_bypass_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "fix_le_pairing_passkey_entry_bypass"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/fix_pairing_failure_reason_from_remote_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/fix_pairing_failure_reason_from_remote_flag_values.textproto
deleted file mode 100644
index df785701..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/fix_pairing_failure_reason_from_remote_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "fix_pairing_failure_reason_from_remote"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/force_bredr_for_sdp_retry_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/force_bredr_for_sdp_retry_flag_values.textproto
deleted file mode 100644
index a4206a62..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/force_bredr_for_sdp_retry_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "force_bredr_for_sdp_retry"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/gatt_drop_acl_on_out_of_resources_fix_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/gatt_drop_acl_on_out_of_resources_fix_flag_values.textproto
deleted file mode 100644
index 6cd4fdb5..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/gatt_drop_acl_on_out_of_resources_fix_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "gatt_drop_acl_on_out_of_resources_fix"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/gatt_reconnect_on_bt_on_fix_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/gatt_reconnect_on_bt_on_fix_flag_values.textproto
deleted file mode 100644
index 80ccb8de..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/gatt_reconnect_on_bt_on_fix_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "gatt_reconnect_on_bt_on_fix"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/get_address_type_api_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/get_address_type_api_flag_values.textproto
deleted file mode 100644
index 02eba004..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/get_address_type_api_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "get_address_type_api"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/hfp_codec_aptx_voice_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/hfp_codec_aptx_voice_flag_values.textproto
deleted file mode 100644
index 62d99bcf..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/hfp_codec_aptx_voice_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "hfp_codec_aptx_voice"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/ignore_bond_type_for_le_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/ignore_bond_type_for_le_flag_values.textproto
deleted file mode 100644
index 8b1fa06b..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/ignore_bond_type_for_le_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "ignore_bond_type_for_le"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/keep_hfp_active_during_leaudio_handover_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/keep_hfp_active_during_leaudio_handover_flag_values.textproto
deleted file mode 100644
index 86a4fb65..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/keep_hfp_active_during_leaudio_handover_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "keep_hfp_active_during_leaudio_handover"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/keep_stopped_media_browser_service_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/keep_stopped_media_browser_service_flag_values.textproto
deleted file mode 100644
index 7214436d..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/keep_stopped_media_browser_service_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "keep_stopped_media_browser_service"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/le_audio_dev_type_detection_fix_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/le_audio_dev_type_detection_fix_flag_values.textproto
deleted file mode 100644
index 6717d405..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/le_audio_dev_type_detection_fix_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "le_audio_dev_type_detection_fix"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/le_audio_fast_bond_params_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/le_audio_fast_bond_params_flag_values.textproto
deleted file mode 100644
index 1c05743e..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/le_audio_fast_bond_params_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "le_audio_fast_bond_params"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/le_periodic_scanning_reassembler_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/le_periodic_scanning_reassembler_flag_values.textproto
deleted file mode 100644
index 31edf4b1..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/le_periodic_scanning_reassembler_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "le_periodic_scanning_reassembler"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/le_scan_parameters_fix_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/le_scan_parameters_fix_flag_values.textproto
deleted file mode 100644
index a0981833..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/le_scan_parameters_fix_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "le_scan_parameters_fix"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_active_device_manager_group_handling_fix_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_active_device_manager_group_handling_fix_flag_values.textproto
deleted file mode 100644
index 2b6c1a23..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_active_device_manager_group_handling_fix_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "leaudio_active_device_manager_group_handling_fix"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_add_sampling_frequencies_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_add_sampling_frequencies_flag_values.textproto
deleted file mode 100644
index 475c7019..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_add_sampling_frequencies_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "leaudio_add_sampling_frequencies"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_api_synchronized_block_fix_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_api_synchronized_block_fix_flag_values.textproto
deleted file mode 100644
index e65d26d0..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_api_synchronized_block_fix_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "leaudio_api_synchronized_block_fix"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_broadcast_assistant_handle_command_statuses_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_broadcast_assistant_handle_command_statuses_flag_values.textproto
deleted file mode 100644
index f9c383ee..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_broadcast_assistant_handle_command_statuses_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "leaudio_broadcast_assistant_handle_command_statuses"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_callback_on_group_stream_status_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_callback_on_group_stream_status_flag_values.textproto
deleted file mode 100644
index f69b4329..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_callback_on_group_stream_status_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "leaudio_callback_on_group_stream_status"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_enable_health_based_actions_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_enable_health_based_actions_flag_values.textproto
deleted file mode 100644
index 613a8ebd..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_enable_health_based_actions_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "leaudio_enable_health_based_actions"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_mcs_tbs_authorization_rebond_fix_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_mcs_tbs_authorization_rebond_fix_flag_values.textproto
deleted file mode 100644
index f7981227..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_mcs_tbs_authorization_rebond_fix_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "leaudio_mcs_tbs_authorization_rebond_fix"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_quick_leaudio_toggle_switch_fix_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_quick_leaudio_toggle_switch_fix_flag_values.textproto
deleted file mode 100644
index 958cb177..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_quick_leaudio_toggle_switch_fix_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "leaudio_quick_leaudio_toggle_switch_fix"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_resume_active_after_hfp_handover_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_resume_active_after_hfp_handover_flag_values.textproto
deleted file mode 100644
index da8655e5..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_resume_active_after_hfp_handover_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "leaudio_resume_active_after_hfp_handover"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_start_stream_race_fix_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_start_stream_race_fix_flag_values.textproto
deleted file mode 100644
index 07142917..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_start_stream_race_fix_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "leaudio_start_stream_race_fix"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_unicast_inactivate_device_based_on_context_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_unicast_inactivate_device_based_on_context_flag_values.textproto
deleted file mode 100644
index dc2ba8fc..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_unicast_inactivate_device_based_on_context_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "leaudio_unicast_inactivate_device_based_on_context"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_volume_change_on_ringtone_fix_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_volume_change_on_ringtone_fix_flag_values.textproto
deleted file mode 100644
index 3eac0c5a..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_volume_change_on_ringtone_fix_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "leaudio_volume_change_on_ringtone_fix"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/load_did_config_from_sysprops_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/load_did_config_from_sysprops_flag_values.textproto
deleted file mode 100644
index 6be64b17..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/load_did_config_from_sysprops_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "load_did_config_from_sysprops"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/mfi_has_uuid_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/mfi_has_uuid_flag_values.textproto
deleted file mode 100644
index 3d0add36..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/mfi_has_uuid_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "mfi_has_uuid"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/pretend_network_service_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/pretend_network_service_flag_values.textproto
deleted file mode 100644
index 39be5818..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/pretend_network_service_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "pretend_network_service"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/read_model_num_fix_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/read_model_num_fix_flag_values.textproto
deleted file mode 100644
index b2fd19f9..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/read_model_num_fix_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "read_model_num_fix"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/report_vsc_data_from_the_gd_controller_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/report_vsc_data_from_the_gd_controller_flag_values.textproto
deleted file mode 100644
index ba5e8eab..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/report_vsc_data_from_the_gd_controller_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "report_vsc_data_from_the_gd_controller"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/reset_pairing_only_for_related_service_discovery_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/reset_pairing_only_for_related_service_discovery_flag_values.textproto
deleted file mode 100644
index 3b15ac19..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/reset_pairing_only_for_related_service_discovery_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "reset_pairing_only_for_related_service_discovery"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/rnr_cancel_before_event_race_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/rnr_cancel_before_event_race_flag_values.textproto
deleted file mode 100644
index b6eee145..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/rnr_cancel_before_event_race_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "rnr_cancel_before_event_race"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/rnr_present_during_service_discovery_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/rnr_present_during_service_discovery_flag_values.textproto
deleted file mode 100644
index dba4766a..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/rnr_present_during_service_discovery_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "rnr_present_during_service_discovery"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/rnr_reset_state_at_cancel_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/rnr_reset_state_at_cancel_flag_values.textproto
deleted file mode 100644
index fa8d15b3..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/rnr_reset_state_at_cancel_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "rnr_reset_state_at_cancel"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/separate_service_and_device_discovery_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/separate_service_and_device_discovery_flag_values.textproto
deleted file mode 100644
index 2c88f1e5..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/separate_service_and_device_discovery_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "separate_service_and_device_discovery"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/synchronous_bta_sec_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/synchronous_bta_sec_flag_values.textproto
deleted file mode 100644
index 8b49bfd0..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/synchronous_bta_sec_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "synchronous_bta_sec"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/update_inquiry_result_on_flag_change_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/update_inquiry_result_on_flag_change_flag_values.textproto
deleted file mode 100644
index 9c0decaa..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/update_inquiry_result_on_flag_change_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "update_inquiry_result_on_flag_change"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/use_dsp_codec_when_controller_does_not_support_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/use_dsp_codec_when_controller_does_not_support_flag_values.textproto
deleted file mode 100644
index 01d801f9..00000000
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/use_dsp_codec_when_controller_does_not_support_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.bluetooth.flags"
-  name: "use_dsp_codec_when_controller_does_not_support"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.cellbroadcastreceiver.flags/Android.bp b/aconfig/trunk_staging/com.android.cellbroadcastreceiver.flags/Android.bp
deleted file mode 100644
index 7214119f..00000000
--- a/aconfig/trunk_staging/com.android.cellbroadcastreceiver.flags/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-trunk_staging-com.android.cellbroadcastreceiver.flags-all",
-  package: "com.android.cellbroadcastreceiver.flags",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/trunk_staging/com.android.devicelock.flags/Android.bp b/aconfig/trunk_staging/com.android.devicelock.flags/Android.bp
deleted file mode 100644
index 23fc0a03..00000000
--- a/aconfig/trunk_staging/com.android.devicelock.flags/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-trunk_staging-com.android.devicelock.flags-all",
-  package: "com.android.devicelock.flags",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/trunk_staging/com.android.graphics.bufferstreams.flags/Android.bp b/aconfig/trunk_staging/com.android.graphics.bufferstreams.flags/Android.bp
deleted file mode 100644
index feb5c304..00000000
--- a/aconfig/trunk_staging/com.android.graphics.bufferstreams.flags/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-trunk_staging-com.android.graphics.bufferstreams.flags-all",
-  package: "com.android.graphics.bufferstreams.flags",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/trunk_staging/com.android.graphics.surfaceflinger.flags/TEST_MAPPING b/aconfig/trunk_staging/com.android.graphics.surfaceflinger.flags/TEST_MAPPING
deleted file mode 100644
index d0592d17..00000000
--- a/aconfig/trunk_staging/com.android.graphics.surfaceflinger.flags/TEST_MAPPING
+++ /dev/null
@@ -1,10 +0,0 @@
-{
-  "imports": [
-    {
-      "path": "frameworks/native"
-    },
-    {
-      "path": "frameworks/native/services/surfaceflinger"
-    }
-  ]
-}
diff --git a/aconfig/trunk_staging/com.android.hardware.camera2/Android.bp b/aconfig/trunk_staging/com.android.hardware.camera2/Android.bp
deleted file mode 100644
index ed0e265b..00000000
--- a/aconfig/trunk_staging/com.android.hardware.camera2/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-trunk_staging-com.android.hardware.camera2-all",
-  package: "com.android.hardware.camera2",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/trunk_staging/com.android.hardware.input/TEST_MAPPING b/aconfig/trunk_staging/com.android.hardware.input/TEST_MAPPING
deleted file mode 100644
index 7c0dc275..00000000
--- a/aconfig/trunk_staging/com.android.hardware.input/TEST_MAPPING
+++ /dev/null
@@ -1,7 +0,0 @@
-{
-  "imports": [
-    {
-      "path": "frameworks/native/services/inputflinger"
-    }
-  ]
-}
\ No newline at end of file
diff --git a/aconfig/trunk_staging/com.android.input.flags/TEST_MAPPING b/aconfig/trunk_staging/com.android.input.flags/TEST_MAPPING
deleted file mode 100644
index 7c0dc275..00000000
--- a/aconfig/trunk_staging/com.android.input.flags/TEST_MAPPING
+++ /dev/null
@@ -1,7 +0,0 @@
-{
-  "imports": [
-    {
-      "path": "frameworks/native/services/inputflinger"
-    }
-  ]
-}
\ No newline at end of file
diff --git a/aconfig/trunk_staging/com.android.input.flags/enable_gestures_library_timer_provider_flag_values.textproto b/aconfig/trunk_staging/com.android.input.flags/enable_gestures_library_timer_provider_flag_values.textproto
deleted file mode 100644
index 091c8fa2..00000000
--- a/aconfig/trunk_staging/com.android.input.flags/enable_gestures_library_timer_provider_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.input.flags"
-  name: "enable_gestures_library_timer_provider"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.input.flags/remove_pointer_event_tracking_in_wm_flag_values.textproto b/aconfig/trunk_staging/com.android.input.flags/remove_pointer_event_tracking_in_wm_flag_values.textproto
deleted file mode 100644
index f49f6c82..00000000
--- a/aconfig/trunk_staging/com.android.input.flags/remove_pointer_event_tracking_in_wm_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.input.flags"
-  name: "remove_pointer_event_tracking_in_wm"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.intentresolver/bespoke_label_view_flag_values.textproto b/aconfig/trunk_staging/com.android.intentresolver/bespoke_label_view_flag_values.textproto
deleted file mode 100644
index 40dc3d95..00000000
--- a/aconfig/trunk_staging/com.android.intentresolver/bespoke_label_view_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.intentresolver"
-  name: "bespoke_label_view"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.intentresolver/fix_partial_image_edit_transition_flag_values.textproto b/aconfig/trunk_staging/com.android.intentresolver/fix_partial_image_edit_transition_flag_values.textproto
deleted file mode 100644
index 6edc1f4c..00000000
--- a/aconfig/trunk_staging/com.android.intentresolver/fix_partial_image_edit_transition_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.intentresolver"
-  name: "fix_partial_image_edit_transition"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.intentresolver/fix_shortcuts_flashing_flag_values.textproto b/aconfig/trunk_staging/com.android.intentresolver/fix_shortcuts_flashing_flag_values.textproto
deleted file mode 100644
index 0cc18ccc..00000000
--- a/aconfig/trunk_staging/com.android.intentresolver/fix_shortcuts_flashing_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.intentresolver"
-  name: "fix_shortcuts_flashing"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.intentresolver/fix_target_list_footer_flag_values.textproto b/aconfig/trunk_staging/com.android.intentresolver/fix_target_list_footer_flag_values.textproto
deleted file mode 100644
index bb7cdf9c..00000000
--- a/aconfig/trunk_staging/com.android.intentresolver/fix_target_list_footer_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.intentresolver"
-  name: "fix_target_list_footer"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.internal.camera.flags/lazy_aidl_wait_for_service_flag_values.textproto b/aconfig/trunk_staging/com.android.internal.camera.flags/lazy_aidl_wait_for_service_flag_values.textproto
deleted file mode 100644
index 97de2403..00000000
--- a/aconfig/trunk_staging/com.android.internal.camera.flags/lazy_aidl_wait_for_service_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.internal.camera.flags"
-  name: "lazy_aidl_wait_for_service"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.internal.camera.flags/log_ultrawide_usage_flag_values.textproto b/aconfig/trunk_staging/com.android.internal.camera.flags/log_ultrawide_usage_flag_values.textproto
deleted file mode 100644
index 3a1577a3..00000000
--- a/aconfig/trunk_staging/com.android.internal.camera.flags/log_ultrawide_usage_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.internal.camera.flags"
-  name: "log_ultrawide_usage"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.internal.camera.flags/log_zoom_override_usage_flag_values.textproto b/aconfig/trunk_staging/com.android.internal.camera.flags/log_zoom_override_usage_flag_values.textproto
deleted file mode 100644
index 9daa87d6..00000000
--- a/aconfig/trunk_staging/com.android.internal.camera.flags/log_zoom_override_usage_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.internal.camera.flags"
-  name: "log_zoom_override_usage"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.internal.camera.flags/realtime_priority_bump_flag_values.textproto b/aconfig/trunk_staging/com.android.internal.camera.flags/realtime_priority_bump_flag_values.textproto
deleted file mode 100644
index 4e51cad4..00000000
--- a/aconfig/trunk_staging/com.android.internal.camera.flags/realtime_priority_bump_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.internal.camera.flags"
-  name: "realtime_priority_bump"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.internal.camera.flags/single_thread_executor_flag_values.textproto b/aconfig/trunk_staging/com.android.internal.camera.flags/single_thread_executor_flag_values.textproto
deleted file mode 100644
index caa225a6..00000000
--- a/aconfig/trunk_staging/com.android.internal.camera.flags/single_thread_executor_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.internal.camera.flags"
-  name: "single_thread_executor"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.internal.camera.flags/surface_ipc_flag_values.textproto b/aconfig/trunk_staging/com.android.internal.camera.flags/surface_ipc_flag_values.textproto
deleted file mode 100644
index f95e3f77..00000000
--- a/aconfig/trunk_staging/com.android.internal.camera.flags/surface_ipc_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.internal.camera.flags"
-  name: "surface_ipc"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.internal.camera.flags/surface_leak_fix_flag_values.textproto b/aconfig/trunk_staging/com.android.internal.camera.flags/surface_leak_fix_flag_values.textproto
deleted file mode 100644
index 9dcf979b..00000000
--- a/aconfig/trunk_staging/com.android.internal.camera.flags/surface_leak_fix_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.internal.camera.flags"
-  name: "surface_leak_fix"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.internal.camera.flags/watch_foreground_changes_flag_values.textproto b/aconfig/trunk_staging/com.android.internal.camera.flags/watch_foreground_changes_flag_values.textproto
deleted file mode 100644
index 4a7bc869..00000000
--- a/aconfig/trunk_staging/com.android.internal.camera.flags/watch_foreground_changes_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.internal.camera.flags"
-  name: "watch_foreground_changes"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.internal.jank/Android.bp b/aconfig/trunk_staging/com.android.internal.jank/Android.bp
deleted file mode 100644
index d4cf386d..00000000
--- a/aconfig/trunk_staging/com.android.internal.jank/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-trunk_staging-com.android.internal.jank-all",
-  package: "com.android.internal.jank",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/trunk_staging/com.android.internal.telephony.flags/add_anomaly_when_notify_config_changed_with_invalid_phone_flag_values.textproto b/aconfig/trunk_staging/com.android.internal.telephony.flags/add_anomaly_when_notify_config_changed_with_invalid_phone_flag_values.textproto
deleted file mode 100644
index 8ef81bae..00000000
--- a/aconfig/trunk_staging/com.android.internal.telephony.flags/add_anomaly_when_notify_config_changed_with_invalid_phone_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.internal.telephony.flags"
-  name: "add_anomaly_when_notify_config_changed_with_invalid_phone"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.internal.telephony.flags/allow_mmtel_in_non_vops_flag_values.textproto b/aconfig/trunk_staging/com.android.internal.telephony.flags/allow_mmtel_in_non_vops_flag_values.textproto
deleted file mode 100644
index 9414e4a4..00000000
--- a/aconfig/trunk_staging/com.android.internal.telephony.flags/allow_mmtel_in_non_vops_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.internal.telephony.flags"
-  name: "allow_mmtel_in_non_vops"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.internal.telephony.flags/cleanup_open_logical_channel_record_on_dispose_flag_values.textproto b/aconfig/trunk_staging/com.android.internal.telephony.flags/cleanup_open_logical_channel_record_on_dispose_flag_values.textproto
deleted file mode 100644
index 3f984fd9..00000000
--- a/aconfig/trunk_staging/com.android.internal.telephony.flags/cleanup_open_logical_channel_record_on_dispose_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.internal.telephony.flags"
-  name: "cleanup_open_logical_channel_record_on_dispose"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.internal.telephony.flags/data_only_service_allow_emergency_call_only_flag_values.textproto b/aconfig/trunk_staging/com.android.internal.telephony.flags/data_only_service_allow_emergency_call_only_flag_values.textproto
deleted file mode 100644
index ec13d53a..00000000
--- a/aconfig/trunk_staging/com.android.internal.telephony.flags/data_only_service_allow_emergency_call_only_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.internal.telephony.flags"
-  name: "data_only_service_allow_emergency_call_only"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.internal.telephony.flags/fix_crash_on_getting_config_when_phone_is_gone_flag_values.textproto b/aconfig/trunk_staging/com.android.internal.telephony.flags/fix_crash_on_getting_config_when_phone_is_gone_flag_values.textproto
deleted file mode 100644
index 9e004db0..00000000
--- a/aconfig/trunk_staging/com.android.internal.telephony.flags/fix_crash_on_getting_config_when_phone_is_gone_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.internal.telephony.flags"
-  name: "fix_crash_on_getting_config_when_phone_is_gone"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.internal.telephony.flags/force_iwlan_mms_flag_values.textproto b/aconfig/trunk_staging/com.android.internal.telephony.flags/force_iwlan_mms_flag_values.textproto
deleted file mode 100644
index 1052d0a9..00000000
--- a/aconfig/trunk_staging/com.android.internal.telephony.flags/force_iwlan_mms_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.internal.telephony.flags"
-  name: "force_iwlan_mms"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.internal.telephony.flags/hide_preinstalled_carrier_app_at_most_once_flag_values.textproto b/aconfig/trunk_staging/com.android.internal.telephony.flags/hide_preinstalled_carrier_app_at_most_once_flag_values.textproto
deleted file mode 100644
index a98707a1..00000000
--- a/aconfig/trunk_staging/com.android.internal.telephony.flags/hide_preinstalled_carrier_app_at_most_once_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.internal.telephony.flags"
-  name: "hide_preinstalled_carrier_app_at_most_once"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.internal.telephony.flags/ignore_existing_networks_for_internet_allowed_checking_flag_values.textproto b/aconfig/trunk_staging/com.android.internal.telephony.flags/ignore_existing_networks_for_internet_allowed_checking_flag_values.textproto
deleted file mode 100644
index 83e71ae4..00000000
--- a/aconfig/trunk_staging/com.android.internal.telephony.flags/ignore_existing_networks_for_internet_allowed_checking_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.internal.telephony.flags"
-  name: "ignore_existing_networks_for_internet_allowed_checking"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.internal.telephony.flags/metered_embb_urlcc_flag_values.textproto b/aconfig/trunk_staging/com.android.internal.telephony.flags/metered_embb_urlcc_flag_values.textproto
deleted file mode 100644
index 4e72ad6f..00000000
--- a/aconfig/trunk_staging/com.android.internal.telephony.flags/metered_embb_urlcc_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.internal.telephony.flags"
-  name: "metered_embb_urlcc"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.internal.telephony.flags/notify_data_activity_changed_with_slot_flag_values.textproto b/aconfig/trunk_staging/com.android.internal.telephony.flags/notify_data_activity_changed_with_slot_flag_values.textproto
deleted file mode 100644
index 519f8f75..00000000
--- a/aconfig/trunk_staging/com.android.internal.telephony.flags/notify_data_activity_changed_with_slot_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.internal.telephony.flags"
-  name: "notify_data_activity_changed_with_slot"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.internal.telephony.flags/refine_preferred_data_profile_selection_flag_values.textproto b/aconfig/trunk_staging/com.android.internal.telephony.flags/refine_preferred_data_profile_selection_flag_values.textproto
deleted file mode 100644
index d028cb62..00000000
--- a/aconfig/trunk_staging/com.android.internal.telephony.flags/refine_preferred_data_profile_selection_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.internal.telephony.flags"
-  name: "refine_preferred_data_profile_selection"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.internal.telephony.flags/relax_ho_teardown_flag_values.textproto b/aconfig/trunk_staging/com.android.internal.telephony.flags/relax_ho_teardown_flag_values.textproto
deleted file mode 100644
index 5405abe8..00000000
--- a/aconfig/trunk_staging/com.android.internal.telephony.flags/relax_ho_teardown_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.internal.telephony.flags"
-  name: "relax_ho_teardown"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.internal.telephony.flags/support_phone_uid_check_for_multiuser_flag_values.textproto b/aconfig/trunk_staging/com.android.internal.telephony.flags/support_phone_uid_check_for_multiuser_flag_values.textproto
deleted file mode 100644
index 40dbd981..00000000
--- a/aconfig/trunk_staging/com.android.internal.telephony.flags/support_phone_uid_check_for_multiuser_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.internal.telephony.flags"
-  name: "support_phone_uid_check_for_multiuser"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.internal.telephony.flags/unthrottle_check_transport_flag_values.textproto b/aconfig/trunk_staging/com.android.internal.telephony.flags/unthrottle_check_transport_flag_values.textproto
deleted file mode 100644
index 89b5b67f..00000000
--- a/aconfig/trunk_staging/com.android.internal.telephony.flags/unthrottle_check_transport_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.internal.telephony.flags"
-  name: "unthrottle_check_transport"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.internal.telephony.flags/use_alarm_callback_flag_values.textproto b/aconfig/trunk_staging/com.android.internal.telephony.flags/use_alarm_callback_flag_values.textproto
deleted file mode 100644
index a8c51ced..00000000
--- a/aconfig/trunk_staging/com.android.internal.telephony.flags/use_alarm_callback_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.internal.telephony.flags"
-  name: "use_alarm_callback"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.providers.contacts.flags/Android.bp b/aconfig/trunk_staging/com.android.providers.contacts.flags/Android.bp
deleted file mode 100644
index ca0e2d89..00000000
--- a/aconfig/trunk_staging/com.android.providers.contacts.flags/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-trunk_staging-com.android.providers.contacts.flags-all",
-  package: "com.android.providers.contacts.flags",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/trunk_staging/com.android.server.accessibility/TEST_MAPPING b/aconfig/trunk_staging/com.android.server.accessibility/TEST_MAPPING
deleted file mode 100644
index e1115242..00000000
--- a/aconfig/trunk_staging/com.android.server.accessibility/TEST_MAPPING
+++ /dev/null
@@ -1,7 +0,0 @@
-{
-  "imports": [
-    {
-      "path": "frameworks/base/services/accessibility/TEST_MAPPING"
-    }
-  ]
-}
\ No newline at end of file
diff --git a/aconfig/trunk_staging/com.android.server.alarm/TEST_MAPPING b/aconfig/trunk_staging/com.android.server.alarm/TEST_MAPPING
deleted file mode 100644
index 990ede40..00000000
--- a/aconfig/trunk_staging/com.android.server.alarm/TEST_MAPPING
+++ /dev/null
@@ -1,7 +0,0 @@
-{
-  "imports": [
-    {
-      "path": "frameworks/base/apex/jobscheduler/service/java/com/android/server/alarm"
-    }
-  ]
-}
diff --git a/aconfig/trunk_staging/com.android.server.am/TEST_MAPPING b/aconfig/trunk_staging/com.android.server.am/TEST_MAPPING
deleted file mode 100644
index ea347143..00000000
--- a/aconfig/trunk_staging/com.android.server.am/TEST_MAPPING
+++ /dev/null
@@ -1,7 +0,0 @@
-{
-  "imports": [
-    {
-      "path": "frameworks/base/services/core/java/com/android/server/am"
-    }
-  ]
-}
diff --git a/aconfig/trunk_staging/com.android.server.companion.virtual/Android.bp b/aconfig/trunk_staging/com.android.server.companion.virtual/Android.bp
deleted file mode 100644
index 48162597..00000000
--- a/aconfig/trunk_staging/com.android.server.companion.virtual/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-trunk_staging-com.android.server.companion.virtual-all",
-  package: "com.android.server.companion.virtual",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/trunk_staging/com.android.server.companion.virtual/dump_history_flag_values.textproto b/aconfig/trunk_staging/com.android.server.companion.virtual/dump_history_flag_values.textproto
deleted file mode 100644
index 46798015..00000000
--- a/aconfig/trunk_staging/com.android.server.companion.virtual/dump_history_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.server.companion.virtual"
-  name: "dump_history"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.server.connectivity/Android.bp b/aconfig/trunk_staging/com.android.server.connectivity/Android.bp
deleted file mode 100644
index 75b6c758..00000000
--- a/aconfig/trunk_staging/com.android.server.connectivity/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-trunk_staging-com.android.server.connectivity-all",
-  package: "com.android.server.connectivity",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/trunk_staging/com.android.server.contextualsearch.flags/Android.bp b/aconfig/trunk_staging/com.android.server.contextualsearch.flags/Android.bp
deleted file mode 100644
index 20aa26a8..00000000
--- a/aconfig/trunk_staging/com.android.server.contextualsearch.flags/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-trunk_staging-com.android.server.contextualsearch.flags-all",
-  package: "com.android.server.contextualsearch.flags",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/trunk_staging/com.android.server.devicepolicy.flags/Android.bp b/aconfig/trunk_staging/com.android.server.devicepolicy.flags/Android.bp
deleted file mode 100644
index 4d2419e7..00000000
--- a/aconfig/trunk_staging/com.android.server.devicepolicy.flags/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-trunk_staging-com.android.server.devicepolicy.flags-all",
-  package: "com.android.server.devicepolicy.flags",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/trunk_staging/com.android.server.display.feature.flags/TEST_MAPPING b/aconfig/trunk_staging/com.android.server.display.feature.flags/TEST_MAPPING
deleted file mode 100644
index 477860d3..00000000
--- a/aconfig/trunk_staging/com.android.server.display.feature.flags/TEST_MAPPING
+++ /dev/null
@@ -1,7 +0,0 @@
-{
-  "imports": [
-    {
-      "path": "frameworks/base/services/core/java/com/android/server/display"
-    }
-  ]
-}
diff --git a/aconfig/trunk_staging/com.android.server.locksettings/Android.bp b/aconfig/trunk_staging/com.android.server.locksettings/Android.bp
deleted file mode 100644
index 82ae828a..00000000
--- a/aconfig/trunk_staging/com.android.server.locksettings/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-trunk_staging-com.android.server.locksettings-all",
-  package: "com.android.server.locksettings",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/trunk_staging/com.android.server.notification/TEST_MAPPING b/aconfig/trunk_staging/com.android.server.notification/TEST_MAPPING
deleted file mode 100644
index 43fe2935..00000000
--- a/aconfig/trunk_staging/com.android.server.notification/TEST_MAPPING
+++ /dev/null
@@ -1,7 +0,0 @@
-{
-  "imports": [
-    {
-      "path": "cts/tests/tests/notification"
-    }
-  ]
-}
\ No newline at end of file
diff --git a/aconfig/trunk_staging/com.android.server.os/Android.bp b/aconfig/trunk_staging/com.android.server.os/Android.bp
deleted file mode 100644
index dd1b61d2..00000000
--- a/aconfig/trunk_staging/com.android.server.os/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-trunk_staging-com.android.server.os-all",
-  package: "com.android.server.os",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/trunk_staging/com.android.server.pm/Android.bp b/aconfig/trunk_staging/com.android.server.pm/Android.bp
deleted file mode 100644
index 3da38b2e..00000000
--- a/aconfig/trunk_staging/com.android.server.pm/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-trunk_staging-com.android.server.pm-all",
-  package: "com.android.server.pm",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/trunk_staging/com.android.server.security/Android.bp b/aconfig/trunk_staging/com.android.server.security/Android.bp
deleted file mode 100644
index 50a51927..00000000
--- a/aconfig/trunk_staging/com.android.server.security/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-trunk_staging-com.android.server.security-all",
-  package: "com.android.server.security",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/trunk_staging/com.android.settings.connecteddevice.flags/Android.bp b/aconfig/trunk_staging/com.android.settings.connecteddevice.flags/Android.bp
deleted file mode 100644
index 023eff19..00000000
--- a/aconfig/trunk_staging/com.android.settings.connecteddevice.flags/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-trunk_staging-com.android.settings.connecteddevice.flags-all",
-  package: "com.android.settings.connecteddevice.flags",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/trunk_staging/com.android.settings.flags/enable_bluetooth_profile_toggle_visibility_checker_flag_values.textproto b/aconfig/trunk_staging/com.android.settings.flags/enable_bluetooth_profile_toggle_visibility_checker_flag_values.textproto
deleted file mode 100644
index df9bd222..00000000
--- a/aconfig/trunk_staging/com.android.settings.flags/enable_bluetooth_profile_toggle_visibility_checker_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.settings.flags"
-  name: "enable_bluetooth_profile_toggle_visibility_checker"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.settings.flags/enable_subsequent_pair_settings_integration_flag_values.textproto b/aconfig/trunk_staging/com.android.settings.flags/enable_subsequent_pair_settings_integration_flag_values.textproto
deleted file mode 100644
index 9fcf560e..00000000
--- a/aconfig/trunk_staging/com.android.settings.flags/enable_subsequent_pair_settings_integration_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.settings.flags"
-  name: "enable_subsequent_pair_settings_integration"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.settings.flags/internet_preference_controller_v2_flag_values.textproto b/aconfig/trunk_staging/com.android.settings.flags/internet_preference_controller_v2_flag_values.textproto
deleted file mode 100644
index 34d69472..00000000
--- a/aconfig/trunk_staging/com.android.settings.flags/internet_preference_controller_v2_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.settings.flags"
-  name: "internet_preference_controller_v2"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.settings.keyboard/Android.bp b/aconfig/trunk_staging/com.android.settings.keyboard/Android.bp
deleted file mode 100644
index 27b2f14d..00000000
--- a/aconfig/trunk_staging/com.android.settings.keyboard/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-trunk_staging-com.android.settings.keyboard-all",
-  package: "com.android.settings.keyboard",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/trunk_staging/com.android.settingslib.flags/enable_cached_bluetooth_device_dedup_flag_values.textproto b/aconfig/trunk_staging/com.android.settingslib.flags/enable_cached_bluetooth_device_dedup_flag_values.textproto
deleted file mode 100644
index 518035e5..00000000
--- a/aconfig/trunk_staging/com.android.settingslib.flags/enable_cached_bluetooth_device_dedup_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.settingslib.flags"
-  name: "enable_cached_bluetooth_device_dedup"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.systemui.aconfig/Android.bp b/aconfig/trunk_staging/com.android.systemui.aconfig/Android.bp
deleted file mode 100644
index f6ea2426..00000000
--- a/aconfig/trunk_staging/com.android.systemui.aconfig/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-trunk_staging-com.android.systemui.aconfig-all",
-  package: "com.android.systemui.aconfig",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/trunk_staging/com.android.systemui.communal/Android.bp b/aconfig/trunk_staging/com.android.systemui.communal/Android.bp
deleted file mode 100644
index f45237d1..00000000
--- a/aconfig/trunk_staging/com.android.systemui.communal/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-trunk_staging-com.android.systemui.communal-all",
-  package: "com.android.systemui.communal",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/trunk_staging/com.android.systemui/TEST_MAPPING b/aconfig/trunk_staging/com.android.systemui/TEST_MAPPING
deleted file mode 100644
index 44ac02fa..00000000
--- a/aconfig/trunk_staging/com.android.systemui/TEST_MAPPING
+++ /dev/null
@@ -1,10 +0,0 @@
-{
-  "imports": [
-    {
-      "path": "frameworks/base/packages/SystemUI"
-    },
-    {
-      "path": "frameworks/base/services/core/java/com/android/server/notification"
-    }
-  ]
-}
diff --git a/aconfig/trunk_staging/com.android.systemui/bp_talkback_flag_values.textproto b/aconfig/trunk_staging/com.android.systemui/bp_talkback_flag_values.textproto
deleted file mode 100644
index fa544966..00000000
--- a/aconfig/trunk_staging/com.android.systemui/bp_talkback_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.systemui"
-  name: "bp_talkback"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.systemui/centralized_status_bar_height_fix_flag_values.textproto b/aconfig/trunk_staging/com.android.systemui/centralized_status_bar_height_fix_flag_values.textproto
deleted file mode 100644
index b743da83..00000000
--- a/aconfig/trunk_staging/com.android.systemui/centralized_status_bar_height_fix_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.systemui"
-  name: "centralized_status_bar_height_fix"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.systemui/constraint_bp_flag_values.textproto b/aconfig/trunk_staging/com.android.systemui/constraint_bp_flag_values.textproto
deleted file mode 100644
index f7a579d8..00000000
--- a/aconfig/trunk_staging/com.android.systemui/constraint_bp_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.systemui"
-  name: "constraint_bp"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.systemui/haptic_brightness_slider_flag_values.textproto b/aconfig/trunk_staging/com.android.systemui/haptic_brightness_slider_flag_values.textproto
deleted file mode 100644
index d9c76f87..00000000
--- a/aconfig/trunk_staging/com.android.systemui/haptic_brightness_slider_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.systemui"
-  name: "haptic_brightness_slider"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.systemui/haptic_volume_slider_flag_values.textproto b/aconfig/trunk_staging/com.android.systemui/haptic_volume_slider_flag_values.textproto
deleted file mode 100644
index 753b3736..00000000
--- a/aconfig/trunk_staging/com.android.systemui/haptic_volume_slider_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.systemui"
-  name: "haptic_volume_slider"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.systemui/lockscreen_preview_renderer_create_on_main_thread_flag_values.textproto b/aconfig/trunk_staging/com.android.systemui/lockscreen_preview_renderer_create_on_main_thread_flag_values.textproto
deleted file mode 100644
index d18f81c5..00000000
--- a/aconfig/trunk_staging/com.android.systemui/lockscreen_preview_renderer_create_on_main_thread_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.systemui"
-  name: "lockscreen_preview_renderer_create_on_main_thread"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.systemui/privacy_dot_unfold_wrong_corner_fix_flag_values.textproto b/aconfig/trunk_staging/com.android.systemui/privacy_dot_unfold_wrong_corner_fix_flag_values.textproto
deleted file mode 100644
index d38aafd0..00000000
--- a/aconfig/trunk_staging/com.android.systemui/privacy_dot_unfold_wrong_corner_fix_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.systemui"
-  name: "privacy_dot_unfold_wrong_corner_fix"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.systemui/pss_app_selector_abrupt_exit_fix_flag_values.textproto b/aconfig/trunk_staging/com.android.systemui/pss_app_selector_abrupt_exit_fix_flag_values.textproto
deleted file mode 100644
index b9db0e32..00000000
--- a/aconfig/trunk_staging/com.android.systemui/pss_app_selector_abrupt_exit_fix_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.systemui"
-  name: "pss_app_selector_abrupt_exit_fix"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.systemui/qs_new_pipeline_flag_values.textproto b/aconfig/trunk_staging/com.android.systemui/qs_new_pipeline_flag_values.textproto
deleted file mode 100644
index 7d585d00..00000000
--- a/aconfig/trunk_staging/com.android.systemui/qs_new_pipeline_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.systemui"
-  name: "qs_new_pipeline"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.systemui/screenshot_private_profile_accessibility_announcement_fix_flag_values.textproto b/aconfig/trunk_staging/com.android.systemui/screenshot_private_profile_accessibility_announcement_fix_flag_values.textproto
deleted file mode 100644
index 19345a5a..00000000
--- a/aconfig/trunk_staging/com.android.systemui/screenshot_private_profile_accessibility_announcement_fix_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.systemui"
-  name: "screenshot_private_profile_accessibility_announcement_fix"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.systemui/screenshot_private_profile_behavior_fix_flag_values.textproto b/aconfig/trunk_staging/com.android.systemui/screenshot_private_profile_behavior_fix_flag_values.textproto
deleted file mode 100644
index 901a9951..00000000
--- a/aconfig/trunk_staging/com.android.systemui/screenshot_private_profile_behavior_fix_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.systemui"
-  name: "screenshot_private_profile_behavior_fix"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.systemui/screenshot_save_image_exporter_flag_values.textproto b/aconfig/trunk_staging/com.android.systemui/screenshot_save_image_exporter_flag_values.textproto
deleted file mode 100644
index e17529a4..00000000
--- a/aconfig/trunk_staging/com.android.systemui/screenshot_save_image_exporter_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.systemui"
-  name: "screenshot_save_image_exporter"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.systemui/screenshot_shelf_ui2_flag_values.textproto b/aconfig/trunk_staging/com.android.systemui/screenshot_shelf_ui2_flag_values.textproto
deleted file mode 100644
index 9070838c..00000000
--- a/aconfig/trunk_staging/com.android.systemui/screenshot_shelf_ui2_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.systemui"
-  name: "screenshot_shelf_ui2"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.systemui/truncated_status_bar_icons_fix_flag_values.textproto b/aconfig/trunk_staging/com.android.systemui/truncated_status_bar_icons_fix_flag_values.textproto
deleted file mode 100644
index d43a77e8..00000000
--- a/aconfig/trunk_staging/com.android.systemui/truncated_status_bar_icons_fix_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.systemui"
-  name: "truncated_status_bar_icons_fix"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.telephony.phone.flags/Android.bp b/aconfig/trunk_staging/com.android.telephony.phone.flags/Android.bp
deleted file mode 100644
index 8bd2b80b..00000000
--- a/aconfig/trunk_staging/com.android.telephony.phone.flags/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-trunk_staging-com.android.telephony.phone.flags-all",
-  package: "com.android.telephony.phone.flags",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/aconfig/trunk_staging/com.android.text.flags/deprecate_ui_fonts_flag_values.textproto b/aconfig/trunk_staging/com.android.text.flags/deprecate_ui_fonts_flag_values.textproto
deleted file mode 100644
index da2950d9..00000000
--- a/aconfig/trunk_staging/com.android.text.flags/deprecate_ui_fonts_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.text.flags"
-  name: "deprecate_ui_fonts"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.text.flags/fix_double_underline_flag_values.textproto b/aconfig/trunk_staging/com.android.text.flags/fix_double_underline_flag_values.textproto
deleted file mode 100644
index 00bdaceb..00000000
--- a/aconfig/trunk_staging/com.android.text.flags/fix_double_underline_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.text.flags"
-  name: "fix_double_underline"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.text.flags/fix_font_update_failure_flag_values.textproto b/aconfig/trunk_staging/com.android.text.flags/fix_font_update_failure_flag_values.textproto
deleted file mode 100644
index ce278209..00000000
--- a/aconfig/trunk_staging/com.android.text.flags/fix_font_update_failure_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.text.flags"
-  name: "fix_font_update_failure"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/trunk_staging/com.android.text.flags/fix_misaligned_context_menu_flag_values.textproto b/aconfig/trunk_staging/com.android.text.flags/fix_misaligned_context_menu_flag_values.textproto
deleted file mode 100644
index 7b4476ab..00000000
--- a/aconfig/trunk_staging/com.android.text.flags/fix_misaligned_context_menu_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.text.flags"
-  name: "fix_misaligned_context_menu"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.text.flags/icu_bidi_migration_flag_values.textproto b/aconfig/trunk_staging/com.android.text.flags/icu_bidi_migration_flag_values.textproto
deleted file mode 100644
index f592eba7..00000000
--- a/aconfig/trunk_staging/com.android.text.flags/icu_bidi_migration_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.text.flags"
-  name: "icu_bidi_migration"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.text.flags/lazy_variation_instance_flag_values.textproto b/aconfig/trunk_staging/com.android.text.flags/lazy_variation_instance_flag_values.textproto
deleted file mode 100644
index 98b9d3af..00000000
--- a/aconfig/trunk_staging/com.android.text.flags/lazy_variation_instance_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.text.flags"
-  name: "lazy_variation_instance"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/trunk_staging/com.android.text.flags/phrase_strict_fallback_flag_values.textproto b/aconfig/trunk_staging/com.android.text.flags/phrase_strict_fallback_flag_values.textproto
deleted file mode 100644
index 714c437a..00000000
--- a/aconfig/trunk_staging/com.android.text.flags/phrase_strict_fallback_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.text.flags"
-  name: "phrase_strict_fallback"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.text.flags/portuguese_hyphenator_flag_values.textproto b/aconfig/trunk_staging/com.android.text.flags/portuguese_hyphenator_flag_values.textproto
deleted file mode 100644
index 666caeca..00000000
--- a/aconfig/trunk_staging/com.android.text.flags/portuguese_hyphenator_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.text.flags"
-  name: "portuguese_hyphenator"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.text.flags/vendor_custom_locale_fallback_flag_values.textproto b/aconfig/trunk_staging/com.android.text.flags/vendor_custom_locale_fallback_flag_values.textproto
deleted file mode 100644
index 5958a97f..00000000
--- a/aconfig/trunk_staging/com.android.text.flags/vendor_custom_locale_fallback_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.text.flags"
-  name: "vendor_custom_locale_fallback"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/trunk_staging/com.android.window.flags/TEST_MAPPING b/aconfig/trunk_staging/com.android.window.flags/TEST_MAPPING
deleted file mode 100644
index d0592d17..00000000
--- a/aconfig/trunk_staging/com.android.window.flags/TEST_MAPPING
+++ /dev/null
@@ -1,10 +0,0 @@
-{
-  "imports": [
-    {
-      "path": "frameworks/native"
-    },
-    {
-      "path": "frameworks/native/services/surfaceflinger"
-    }
-  ]
-}
diff --git a/aconfig/trunk_staging/com.android.window.flags/activity_snapshot_by_default_flag_values.textproto b/aconfig/trunk_staging/com.android.window.flags/activity_snapshot_by_default_flag_values.textproto
deleted file mode 100644
index a6801519..00000000
--- a/aconfig/trunk_staging/com.android.window.flags/activity_snapshot_by_default_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.window.flags"
-  name: "activity_snapshot_by_default"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/trunk_staging/com.android.window.flags/activity_window_info_flag_flag_values.textproto b/aconfig/trunk_staging/com.android.window.flags/activity_window_info_flag_flag_values.textproto
deleted file mode 100644
index edda5051..00000000
--- a/aconfig/trunk_staging/com.android.window.flags/activity_window_info_flag_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.window.flags"
-  name: "activity_window_info_flag"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/trunk_staging/com.android.window.flags/always_defer_transition_when_apply_wct_flag_values.textproto b/aconfig/trunk_staging/com.android.window.flags/always_defer_transition_when_apply_wct_flag_values.textproto
deleted file mode 100644
index 1ca35a80..00000000
--- a/aconfig/trunk_staging/com.android.window.flags/always_defer_transition_when_apply_wct_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.window.flags"
-  name: "always_defer_transition_when_apply_wct"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.window.flags/bundle_client_transaction_flag_flag_values.textproto b/aconfig/trunk_staging/com.android.window.flags/bundle_client_transaction_flag_flag_values.textproto
deleted file mode 100644
index 221b52ff..00000000
--- a/aconfig/trunk_staging/com.android.window.flags/bundle_client_transaction_flag_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.window.flags"
-  name: "bundle_client_transaction_flag"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/trunk_staging/com.android.window.flags/defer_display_updates_flag_values.textproto b/aconfig/trunk_staging/com.android.window.flags/defer_display_updates_flag_values.textproto
deleted file mode 100644
index 38314f28..00000000
--- a/aconfig/trunk_staging/com.android.window.flags/defer_display_updates_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.window.flags"
-  name: "defer_display_updates"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/trunk_staging/com.android.window.flags/disable_object_pool_flag_values.textproto b/aconfig/trunk_staging/com.android.window.flags/disable_object_pool_flag_values.textproto
deleted file mode 100644
index d335d064..00000000
--- a/aconfig/trunk_staging/com.android.window.flags/disable_object_pool_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.window.flags"
-  name: "disable_object_pool"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/trunk_staging/com.android.window.flags/do_not_skip_ime_by_target_visibility_flag_values.textproto b/aconfig/trunk_staging/com.android.window.flags/do_not_skip_ime_by_target_visibility_flag_values.textproto
deleted file mode 100644
index dbfc7894..00000000
--- a/aconfig/trunk_staging/com.android.window.flags/do_not_skip_ime_by_target_visibility_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.window.flags"
-  name: "do_not_skip_ime_by_target_visibility"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.window.flags/embedded_activity_back_nav_flag_flag_values.textproto b/aconfig/trunk_staging/com.android.window.flags/embedded_activity_back_nav_flag_flag_values.textproto
deleted file mode 100644
index 01993cb8..00000000
--- a/aconfig/trunk_staging/com.android.window.flags/embedded_activity_back_nav_flag_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.window.flags"
-  name: "embedded_activity_back_nav_flag"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.window.flags/enforce_shell_thread_model_flag_values.textproto b/aconfig/trunk_staging/com.android.window.flags/enforce_shell_thread_model_flag_values.textproto
deleted file mode 100644
index 1f1be81b..00000000
--- a/aconfig/trunk_staging/com.android.window.flags/enforce_shell_thread_model_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.window.flags"
-  name: "enforce_shell_thread_model"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/trunk_staging/com.android.window.flags/fullscreen_dim_flag_flag_values.textproto b/aconfig/trunk_staging/com.android.window.flags/ensure_wallpaper_in_transitions_flag_values.textproto
similarity index 69%
rename from aconfig/trunk_staging/com.android.window.flags/fullscreen_dim_flag_flag_values.textproto
rename to aconfig/trunk_staging/com.android.window.flags/ensure_wallpaper_in_transitions_flag_values.textproto
index a76cae4a..6668a098 100644
--- a/aconfig/trunk_staging/com.android.window.flags/fullscreen_dim_flag_flag_values.textproto
+++ b/aconfig/trunk_staging/com.android.window.flags/ensure_wallpaper_in_transitions_flag_values.textproto
@@ -1,6 +1,6 @@
 flag_value {
   package: "com.android.window.flags"
-  name: "fullscreen_dim_flag"
+  name: "ensure_wallpaper_in_transitions"
   state: ENABLED
   permission: READ_WRITE
 }
diff --git a/aconfig/trunk_staging/com.android.window.flags/fix_no_container_update_without_resize_flag_values.textproto b/aconfig/trunk_staging/com.android.window.flags/fix_no_container_update_without_resize_flag_values.textproto
deleted file mode 100644
index afdf387e..00000000
--- a/aconfig/trunk_staging/com.android.window.flags/fix_no_container_update_without_resize_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.window.flags"
-  name: "fix_no_container_update_without_resize"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/trunk_staging/com.android.window.flags/fix_pip_restore_to_overlay_flag_values.textproto b/aconfig/trunk_staging/com.android.window.flags/fix_pip_restore_to_overlay_flag_values.textproto
deleted file mode 100644
index ff9c4fd3..00000000
--- a/aconfig/trunk_staging/com.android.window.flags/fix_pip_restore_to_overlay_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.window.flags"
-  name: "fix_pip_restore_to_overlay"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.window.flags/insets_control_changed_item_flag_values.textproto b/aconfig/trunk_staging/com.android.window.flags/insets_control_changed_item_flag_values.textproto
deleted file mode 100644
index 2dbde3b7..00000000
--- a/aconfig/trunk_staging/com.android.window.flags/insets_control_changed_item_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.window.flags"
-  name: "insets_control_changed_item"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.android.window.flags/introduce_smoother_dimmer_flag_values.textproto b/aconfig/trunk_staging/com.android.window.flags/introduce_smoother_dimmer_flag_values.textproto
deleted file mode 100644
index 843fbad5..00000000
--- a/aconfig/trunk_staging/com.android.window.flags/introduce_smoother_dimmer_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.window.flags"
-  name: "introduce_smoother_dimmer"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/trunk_staging/com.android.window.flags/keyguard_appear_transition_flag_values.textproto b/aconfig/trunk_staging/com.android.window.flags/keyguard_appear_transition_flag_values.textproto
deleted file mode 100644
index 1703ca3f..00000000
--- a/aconfig/trunk_staging/com.android.window.flags/keyguard_appear_transition_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.window.flags"
-  name: "keyguard_appear_transition"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/trunk_staging/com.android.window.flags/per_user_display_window_settings_flag_values.textproto b/aconfig/trunk_staging/com.android.window.flags/per_user_display_window_settings_flag_values.textproto
deleted file mode 100644
index 1d691543..00000000
--- a/aconfig/trunk_staging/com.android.window.flags/per_user_display_window_settings_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.window.flags"
-  name: "per_user_display_window_settings"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/trunk_staging/com.android.window.flags/remove_prepare_surface_in_placement_flag_values.textproto b/aconfig/trunk_staging/com.android.window.flags/remove_prepare_surface_in_placement_flag_values.textproto
deleted file mode 100644
index 1c847d9b..00000000
--- a/aconfig/trunk_staging/com.android.window.flags/remove_prepare_surface_in_placement_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.window.flags"
-  name: "remove_prepare_surface_in_placement"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/trunk_staging/com.android.window.flags/skip_sleeping_when_switching_display_flag_values.textproto b/aconfig/trunk_staging/com.android.window.flags/skip_sleeping_when_switching_display_flag_values.textproto
deleted file mode 100644
index 27654d88..00000000
--- a/aconfig/trunk_staging/com.android.window.flags/skip_sleeping_when_switching_display_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.window.flags"
-  name: "skip_sleeping_when_switching_display"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/trunk_staging/com.android.window.flags/window_session_relayout_info_flag_values.textproto b/aconfig/trunk_staging/com.android.window.flags/window_session_relayout_info_flag_values.textproto
deleted file mode 100644
index 8ab8a120..00000000
--- a/aconfig/trunk_staging/com.android.window.flags/window_session_relayout_info_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.window.flags"
-  name: "window_session_relayout_info"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/trunk_staging/com.android.window.flags/window_token_config_thread_safe_flag_values.textproto b/aconfig/trunk_staging/com.android.window.flags/window_token_config_thread_safe_flag_values.textproto
deleted file mode 100644
index e5ec4546..00000000
--- a/aconfig/trunk_staging/com.android.window.flags/window_token_config_thread_safe_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "com.android.window.flags"
-  name: "window_token_config_thread_safe"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/com.google.android.platform.launcher.aconfig.flags/Android.bp b/aconfig/trunk_staging/com.google.android.platform.launcher.aconfig.flags/Android.bp
deleted file mode 100644
index 9e453a9c..00000000
--- a/aconfig/trunk_staging/com.google.android.platform.launcher.aconfig.flags/Android.bp
+++ /dev/null
@@ -1,21 +0,0 @@
-// Copyright 2024 Google Inc. All rights reserved.
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-aconfig_values {
-  name: "aconfig-values-platform_build_release-trunk_staging-com.google.android.platform.launcher.aconfig.flags-all",
-  package: "com.google.android.platform.launcher.aconfig.flags",
-  srcs: [
-    "*_flag_values.textproto",
-  ]
-}
diff --git a/flag_values/ap4a/RELEASE_KERNEL_AKITA_DIR.textproto b/flag_values/ap4a/RELEASE_KERNEL_AKITA_DIR.textproto
index 40b54638..5f21ca54 100644
--- a/flag_values/ap4a/RELEASE_KERNEL_AKITA_DIR.textproto
+++ b/flag_values/ap4a/RELEASE_KERNEL_AKITA_DIR.textproto
@@ -1,4 +1,4 @@
 name: "RELEASE_KERNEL_AKITA_DIR"
 value: {
-  string_value: "device/google/akita-kernels/5.15/24Q4-12506254"
+  string_value: "device/google/akita-kernels/5.15/24Q4-12796583"
 }
diff --git a/flag_values/ap4a/RELEASE_KERNEL_BLUEJAY_DIR.textproto b/flag_values/ap4a/RELEASE_KERNEL_BLUEJAY_DIR.textproto
index 3d446863..55a588b3 100644
--- a/flag_values/ap4a/RELEASE_KERNEL_BLUEJAY_DIR.textproto
+++ b/flag_values/ap4a/RELEASE_KERNEL_BLUEJAY_DIR.textproto
@@ -1,4 +1,4 @@
 name: "RELEASE_KERNEL_BLUEJAY_DIR"
 value: {
-  string_value: "device/google/bluejay-kernels/5.10/24Q4-12476354"
+  string_value: "device/google/bluejay-kernels/5.10/24Q4-12796571"
 }
diff --git a/flag_values/ap4a/RELEASE_KERNEL_CAIMAN_DIR.textproto b/flag_values/ap4a/RELEASE_KERNEL_CAIMAN_DIR.textproto
index 38a4373a..e4667b61 100644
--- a/flag_values/ap4a/RELEASE_KERNEL_CAIMAN_DIR.textproto
+++ b/flag_values/ap4a/RELEASE_KERNEL_CAIMAN_DIR.textproto
@@ -1,4 +1,4 @@
 name: "RELEASE_KERNEL_CAIMAN_DIR"
 value: {
-  string_value: "device/google/caimito-kernels/6.1/24Q4-12646621"
+  string_value: "device/google/caimito-kernels/6.1/24Q4-12796570"
 }
diff --git a/flag_values/ap4a/RELEASE_KERNEL_CHEETAH_DIR.textproto b/flag_values/ap4a/RELEASE_KERNEL_CHEETAH_DIR.textproto
index 3ddeeb5d..5b761ca3 100644
--- a/flag_values/ap4a/RELEASE_KERNEL_CHEETAH_DIR.textproto
+++ b/flag_values/ap4a/RELEASE_KERNEL_CHEETAH_DIR.textproto
@@ -1,4 +1,4 @@
 name: "RELEASE_KERNEL_CHEETAH_DIR"
 value: {
-  string_value: "device/google/pantah-kernels/5.10/24Q4-12476354"
+  string_value: "device/google/pantah-kernels/5.10/24Q4-12796571"
 }
diff --git a/flag_values/ap4a/RELEASE_KERNEL_COMET_DIR.textproto b/flag_values/ap4a/RELEASE_KERNEL_COMET_DIR.textproto
index 1740e869..c3005891 100644
--- a/flag_values/ap4a/RELEASE_KERNEL_COMET_DIR.textproto
+++ b/flag_values/ap4a/RELEASE_KERNEL_COMET_DIR.textproto
@@ -1,4 +1,4 @@
 name: "RELEASE_KERNEL_COMET_DIR"
 value: {
-  string_value: "device/google/comet-kernels/6.1/24Q4-12646621"
+  string_value: "device/google/comet-kernels/6.1/24Q4-12796570"
 }
diff --git a/flag_values/ap4a/RELEASE_KERNEL_FELIX_DIR.textproto b/flag_values/ap4a/RELEASE_KERNEL_FELIX_DIR.textproto
index d7813990..f7c3b491 100644
--- a/flag_values/ap4a/RELEASE_KERNEL_FELIX_DIR.textproto
+++ b/flag_values/ap4a/RELEASE_KERNEL_FELIX_DIR.textproto
@@ -1,4 +1,4 @@
 name: "RELEASE_KERNEL_FELIX_DIR"
 value: {
-  string_value: "device/google/felix-kernels/5.10/24Q4-12476354"
+  string_value: "device/google/felix-kernels/5.10/24Q4-12796571"
 }
diff --git a/flag_values/ap4a/RELEASE_KERNEL_HUSKY_DIR.textproto b/flag_values/ap4a/RELEASE_KERNEL_HUSKY_DIR.textproto
index 5705f982..44c32c07 100644
--- a/flag_values/ap4a/RELEASE_KERNEL_HUSKY_DIR.textproto
+++ b/flag_values/ap4a/RELEASE_KERNEL_HUSKY_DIR.textproto
@@ -1,4 +1,4 @@
 name: "RELEASE_KERNEL_HUSKY_DIR"
 value: {
-  string_value: "device/google/shusky-kernels/5.15/24Q4-12506254"
+  string_value: "device/google/shusky-kernels/5.15/24Q4-12796583"
 }
diff --git a/flag_values/ap4a/RELEASE_KERNEL_KOMODO_DIR.textproto b/flag_values/ap4a/RELEASE_KERNEL_KOMODO_DIR.textproto
index 46bfe9d3..00220b79 100644
--- a/flag_values/ap4a/RELEASE_KERNEL_KOMODO_DIR.textproto
+++ b/flag_values/ap4a/RELEASE_KERNEL_KOMODO_DIR.textproto
@@ -1,4 +1,4 @@
 name: "RELEASE_KERNEL_KOMODO_DIR"
 value: {
-  string_value: "device/google/caimito-kernels/6.1/24Q4-12646621"
+  string_value: "device/google/caimito-kernels/6.1/24Q4-12796570"
 }
diff --git a/flag_values/ap4a/RELEASE_KERNEL_LYNX_DIR.textproto b/flag_values/ap4a/RELEASE_KERNEL_LYNX_DIR.textproto
index e15625d2..2170b11e 100644
--- a/flag_values/ap4a/RELEASE_KERNEL_LYNX_DIR.textproto
+++ b/flag_values/ap4a/RELEASE_KERNEL_LYNX_DIR.textproto
@@ -1,4 +1,4 @@
 name: "RELEASE_KERNEL_LYNX_DIR"
 value: {
-  string_value: "device/google/lynx-kernels/5.10/24Q4-12476354"
+  string_value: "device/google/lynx-kernels/5.10/24Q4-12796571"
 }
diff --git a/flag_values/ap4a/RELEASE_KERNEL_ORIOLE_DIR.textproto b/flag_values/ap4a/RELEASE_KERNEL_ORIOLE_DIR.textproto
index 63f778f6..e3394e4c 100644
--- a/flag_values/ap4a/RELEASE_KERNEL_ORIOLE_DIR.textproto
+++ b/flag_values/ap4a/RELEASE_KERNEL_ORIOLE_DIR.textproto
@@ -1,4 +1,4 @@
 name: "RELEASE_KERNEL_ORIOLE_DIR"
 value: {
-  string_value: "device/google/raviole-kernels/5.10/24Q4-12476354"
+  string_value: "device/google/raviole-kernels/5.10/24Q4-12796571"
 }
diff --git a/flag_values/ap4a/RELEASE_KERNEL_PANTHER_DIR.textproto b/flag_values/ap4a/RELEASE_KERNEL_PANTHER_DIR.textproto
index b678dfbe..983ae137 100644
--- a/flag_values/ap4a/RELEASE_KERNEL_PANTHER_DIR.textproto
+++ b/flag_values/ap4a/RELEASE_KERNEL_PANTHER_DIR.textproto
@@ -1,4 +1,4 @@
 name: "RELEASE_KERNEL_PANTHER_DIR"
 value: {
-  string_value: "device/google/pantah-kernels/5.10/24Q4-12476354"
+  string_value: "device/google/pantah-kernels/5.10/24Q4-12796571"
 }
diff --git a/flag_values/ap4a/RELEASE_KERNEL_RAVEN_DIR.textproto b/flag_values/ap4a/RELEASE_KERNEL_RAVEN_DIR.textproto
index f2c64423..d0e996bb 100644
--- a/flag_values/ap4a/RELEASE_KERNEL_RAVEN_DIR.textproto
+++ b/flag_values/ap4a/RELEASE_KERNEL_RAVEN_DIR.textproto
@@ -1,4 +1,4 @@
 name: "RELEASE_KERNEL_RAVEN_DIR"
 value: {
-  string_value: "device/google/raviole-kernels/5.10/24Q4-12476354"
+  string_value: "device/google/raviole-kernels/5.10/24Q4-12796571"
 }
diff --git a/flag_values/ap4a/RELEASE_KERNEL_SHIBA_DIR.textproto b/flag_values/ap4a/RELEASE_KERNEL_SHIBA_DIR.textproto
index c64f47b4..92eb744e 100644
--- a/flag_values/ap4a/RELEASE_KERNEL_SHIBA_DIR.textproto
+++ b/flag_values/ap4a/RELEASE_KERNEL_SHIBA_DIR.textproto
@@ -1,4 +1,4 @@
 name: "RELEASE_KERNEL_SHIBA_DIR"
 value: {
-  string_value: "device/google/shusky-kernels/5.15/24Q4-12506254"
+  string_value: "device/google/shusky-kernels/5.15/24Q4-12796583"
 }
diff --git a/flag_values/ap4a/RELEASE_KERNEL_TANGORPRO_DIR.textproto b/flag_values/ap4a/RELEASE_KERNEL_TANGORPRO_DIR.textproto
index b462bf0b..1d62908e 100644
--- a/flag_values/ap4a/RELEASE_KERNEL_TANGORPRO_DIR.textproto
+++ b/flag_values/ap4a/RELEASE_KERNEL_TANGORPRO_DIR.textproto
@@ -1,4 +1,4 @@
 name: "RELEASE_KERNEL_TANGORPRO_DIR"
 value: {
-  string_value: "device/google/tangorpro-kernels/5.10/24Q4-12476354"
+  string_value: "device/google/tangorpro-kernels/5.10/24Q4-12796571"
 }
diff --git a/flag_values/ap4a/RELEASE_KERNEL_TOKAY_DIR.textproto b/flag_values/ap4a/RELEASE_KERNEL_TOKAY_DIR.textproto
index c7e1accd..02e2d6ec 100644
--- a/flag_values/ap4a/RELEASE_KERNEL_TOKAY_DIR.textproto
+++ b/flag_values/ap4a/RELEASE_KERNEL_TOKAY_DIR.textproto
@@ -1,4 +1,4 @@
 name: "RELEASE_KERNEL_TOKAY_DIR"
 value: {
-  string_value: "device/google/caimito-kernels/6.1/24Q4-12646621"
+  string_value: "device/google/caimito-kernels/6.1/24Q4-12796570"
 }
diff --git a/flag_values/ap4a/RELEASE_PLATFORM_SECURITY_PATCH.textproto b/flag_values/ap4a/RELEASE_PLATFORM_SECURITY_PATCH.textproto
index 61094716..46d856b6 100644
--- a/flag_values/ap4a/RELEASE_PLATFORM_SECURITY_PATCH.textproto
+++ b/flag_values/ap4a/RELEASE_PLATFORM_SECURITY_PATCH.textproto
@@ -1,4 +1,5 @@
 name: "RELEASE_PLATFORM_SECURITY_PATCH"
 value: {
-  string_value: "2025-01-05"
-}
\ No newline at end of file
+  string_value: "2025-02-05"
+}
+
diff --git a/flag_values/trunk_staging/RELEASE_APPFUNCTION_SIDECAR.textproto b/flag_values/trunk_staging/RELEASE_APPFUNCTION_SIDECAR.textproto
index e5b76ccb..87beb96e 100644
--- a/flag_values/trunk_staging/RELEASE_APPFUNCTION_SIDECAR.textproto
+++ b/flag_values/trunk_staging/RELEASE_APPFUNCTION_SIDECAR.textproto
@@ -1,4 +1,4 @@
-name:  "RELEASE_APPFUNCTION_SIDECAR"
-value:  {
-  bool_value:  true
-}
\ No newline at end of file
+name: "RELEASE_APPFUNCTION_SIDECAR"
+value: {
+  bool_value: true
+}
diff --git a/flag_values/trunk_staging/RELEASE_AVF_ENABLE_TPU_ASSIGNABLE_DEVICE.textproto b/flag_values/trunk_staging/RELEASE_AVF_ENABLE_TPU_ASSIGNABLE_DEVICE.textproto
index ed85ec5b..eaacdcc0 100644
--- a/flag_values/trunk_staging/RELEASE_AVF_ENABLE_TPU_ASSIGNABLE_DEVICE.textproto
+++ b/flag_values/trunk_staging/RELEASE_AVF_ENABLE_TPU_ASSIGNABLE_DEVICE.textproto
@@ -1,4 +1,4 @@
-name:  "RELEASE_AVF_ENABLE_TPU_ASSIGNABLE_DEVICE"
-value:  {
-  bool_value:  true
+name: "RELEASE_AVF_ENABLE_TPU_ASSIGNABLE_DEVICE"
+value: {
+  bool_value: true
 }
diff --git a/flag_values/trunk_staging/RELEASE_AVF_ENABLE_WIDEVINE_PVM.textproto b/flag_values/trunk_staging/RELEASE_AVF_ENABLE_WIDEVINE_PVM.textproto
deleted file mode 100644
index ffdabf95..00000000
--- a/flag_values/trunk_staging/RELEASE_AVF_ENABLE_WIDEVINE_PVM.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name:  "RELEASE_AVF_ENABLE_WIDEVINE_PVM"
-value:  {
-  bool_value:  true
-}
diff --git a/flag_values/trunk_staging/RELEASE_AVF_IMPROVE_DEBUGGABLE_VMS.textproto b/flag_values/trunk_staging/RELEASE_AVF_IMPROVE_DEBUGGABLE_VMS.textproto
index 9c3ca6b5..2973d176 100644
--- a/flag_values/trunk_staging/RELEASE_AVF_IMPROVE_DEBUGGABLE_VMS.textproto
+++ b/flag_values/trunk_staging/RELEASE_AVF_IMPROVE_DEBUGGABLE_VMS.textproto
@@ -1,4 +1,4 @@
-name:  "RELEASE_AVF_IMPROVE_DEBUGGABLE_VMS"
-value:  {
-  bool_value:  true
+name: "RELEASE_AVF_IMPROVE_DEBUGGABLE_VMS"
+value: {
+  bool_value: true
 }
diff --git a/flag_values/trunk_staging/RELEASE_AVF_SUPPORT_LONG_RUNNING_VMS.textproto b/flag_values/trunk_staging/RELEASE_AVF_SUPPORT_LONG_RUNNING_VMS.textproto
deleted file mode 100644
index 48050256..00000000
--- a/flag_values/trunk_staging/RELEASE_AVF_SUPPORT_LONG_RUNNING_VMS.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name:  "RELEASE_AVF_SUPPORT_LONG_RUNNING_VMS"
-value:  {
-  bool_value:  true
-}
diff --git a/flag_values/trunk_staging/RELEASE_GOOGLE_AKITA_16K_DEVELOPER_OPTION.textproto b/flag_values/trunk_staging/RELEASE_GOOGLE_AKITA_16K_DEVELOPER_OPTION.textproto
new file mode 100644
index 00000000..8b97f2d2
--- /dev/null
+++ b/flag_values/trunk_staging/RELEASE_GOOGLE_AKITA_16K_DEVELOPER_OPTION.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_GOOGLE_AKITA_16K_DEVELOPER_OPTION"
+value: {
+  bool_value: true
+}
diff --git a/flag_values/trunk_staging/RELEASE_GOOGLE_HUSKY_16K_DEVELOPER_OPTION.textproto b/flag_values/trunk_staging/RELEASE_GOOGLE_HUSKY_16K_DEVELOPER_OPTION.textproto
new file mode 100644
index 00000000..7a40dccf
--- /dev/null
+++ b/flag_values/trunk_staging/RELEASE_GOOGLE_HUSKY_16K_DEVELOPER_OPTION.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_GOOGLE_HUSKY_16K_DEVELOPER_OPTION"
+value: {
+  bool_value: true
+}
diff --git a/flag_values/trunk_staging/RELEASE_GOOGLE_SHIBA_16K_DEVELOPER_OPTION.textproto b/flag_values/trunk_staging/RELEASE_GOOGLE_SHIBA_16K_DEVELOPER_OPTION.textproto
new file mode 100644
index 00000000..5057404f
--- /dev/null
+++ b/flag_values/trunk_staging/RELEASE_GOOGLE_SHIBA_16K_DEVELOPER_OPTION.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_GOOGLE_SHIBA_16K_DEVELOPER_OPTION"
+value: {
+  bool_value: true
+}
diff --git a/flag_values/trunk_staging/RELEASE_LIBBINDER_CLIENT_CACHE.textproto b/flag_values/trunk_staging/RELEASE_LIBBINDER_CLIENT_CACHE.textproto
index 97e354b6..162f55fe 100644
--- a/flag_values/trunk_staging/RELEASE_LIBBINDER_CLIENT_CACHE.textproto
+++ b/flag_values/trunk_staging/RELEASE_LIBBINDER_CLIENT_CACHE.textproto
@@ -1,4 +1,4 @@
-name:  "RELEASE_LIBBINDER_CLIENT_CACHE"
-value:  {
-  bool_value:  true
+name: "RELEASE_LIBBINDER_CLIENT_CACHE"
+value: {
+  bool_value: true
 }
diff --git a/flag_values/trunk_staging/RELEASE_LIBPOWER_NO_LOCK_BINDER_TXN.textproto b/flag_values/trunk_staging/RELEASE_LIBPOWER_NO_LOCK_BINDER_TXN.textproto
index ced836ea..ae7d1bc8 100644
--- a/flag_values/trunk_staging/RELEASE_LIBPOWER_NO_LOCK_BINDER_TXN.textproto
+++ b/flag_values/trunk_staging/RELEASE_LIBPOWER_NO_LOCK_BINDER_TXN.textproto
@@ -1,4 +1,4 @@
-name:  "RELEASE_LIBPOWER_NO_LOCK_BINDER_TXN"
+name: "RELEASE_LIBPOWER_NO_LOCK_BINDER_TXN"
 value: {
   bool_value: true
 }
diff --git a/flag_values/trunk_staging/RELEASE_PLATFORM_SECURITY_PATCH.textproto b/flag_values/trunk_staging/RELEASE_PLATFORM_SECURITY_PATCH.textproto
index 8853c743..46d856b6 100644
--- a/flag_values/trunk_staging/RELEASE_PLATFORM_SECURITY_PATCH.textproto
+++ b/flag_values/trunk_staging/RELEASE_PLATFORM_SECURITY_PATCH.textproto
@@ -1,4 +1,5 @@
 name: "RELEASE_PLATFORM_SECURITY_PATCH"
 value: {
-  string_value: "2025-01-05"
+  string_value: "2025-02-05"
 }
+
diff --git a/flag_values/trunk_staging/RELEASE_READ_FROM_NEW_STORAGE.textproto b/flag_values/trunk_staging/RELEASE_READ_FROM_NEW_STORAGE.textproto
new file mode 100644
index 00000000..6cb08946
--- /dev/null
+++ b/flag_values/trunk_staging/RELEASE_READ_FROM_NEW_STORAGE.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_READ_FROM_NEW_STORAGE"
+value: {
+  bool_value: true
+}
diff --git a/gms_mainline/optional/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_REMOTEKEYPROVISIONING.textproto b/gms_mainline/optional/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_REMOTEKEYPROVISIONING.textproto
deleted file mode 100644
index 965e4cad..00000000
--- a/gms_mainline/optional/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_REMOTEKEYPROVISIONING.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_REMOTEKEYPROVISIONING"
-value: {
-  string_value: "rkpd.google.contributions.prebuilt"
-}
diff --git a/gms_mainline/optional/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_UWB.textproto b/gms_mainline/optional/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_UWB.textproto
deleted file mode 100644
index 6f8574f3..00000000
--- a/gms_mainline/optional/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_UWB.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_UWB"
-value: {
-  string_value: "uwb.google.contributions.prebuilt"
-}
diff --git a/gms_mainline/optional/release_config_map.textproto b/gms_mainline/optional/release_config_map.textproto
deleted file mode 100644
index 3237b81f..00000000
--- a/gms_mainline/optional/release_config_map.textproto
+++ /dev/null
@@ -1 +0,0 @@
-default_containers: "vendor"
diff --git a/gms_mainline/optional/release_configs/ap3a.textproto b/gms_mainline/optional/release_configs/ap3a.textproto
deleted file mode 100644
index c25b670b..00000000
--- a/gms_mainline/optional/release_configs/ap3a.textproto
+++ /dev/null
@@ -1 +0,0 @@
-name: "ap3a"
diff --git a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_ADBD.textproto b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_ADBD.textproto
deleted file mode 100644
index 63be0c04..00000000
--- a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_ADBD.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_ADBD"
-value: {
-  string_value: "adbd.google.contributions.prebuilt"
-}
diff --git a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_ADSERVICES.textproto b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_ADSERVICES.textproto
deleted file mode 100644
index 60a6486c..00000000
--- a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_ADSERVICES.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_ADSERVICES"
-value: {
-  string_value: "adservices.google.contributions.prebuilt"
-}
diff --git a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_APPSEARCH.textproto b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_APPSEARCH.textproto
deleted file mode 100644
index d5e3ef3b..00000000
--- a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_APPSEARCH.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_APPSEARCH"
-value: {
-  string_value: "appsearch.google.contributions.prebuilt"
-}
diff --git a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_ART.textproto b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_ART.textproto
deleted file mode 100644
index 64e36bc3..00000000
--- a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_ART.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_ART"
-value: {
-  string_value: "art.google.contributions.prebuilt"
-}
diff --git a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CAPTIVEPORTALLOGIN.textproto b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CAPTIVEPORTALLOGIN.textproto
deleted file mode 100644
index efe3115e..00000000
--- a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CAPTIVEPORTALLOGIN.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_CAPTIVEPORTALLOGIN"
-value: {
-  string_value: "captiveportallogin.google.contributions.prebuilt"
-}
diff --git a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CELLBROADCAST.textproto b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CELLBROADCAST.textproto
deleted file mode 100644
index 200a543e..00000000
--- a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CELLBROADCAST.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_CELLBROADCAST"
-value: {
-  string_value: "cellbroadcast.google.contributions.prebuilt"
-}
diff --git a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CONFIGINFRASTRUCTURE.textproto b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CONFIGINFRASTRUCTURE.textproto
deleted file mode 100644
index 3876a849..00000000
--- a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CONFIGINFRASTRUCTURE.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_CONFIGINFRASTRUCTURE"
-value: {
-  string_value: "configinfrastructure.google.contributions.prebuilt"
-}
diff --git a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CONNECTIVITY.textproto b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CONNECTIVITY.textproto
deleted file mode 100644
index d6832f08..00000000
--- a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CONNECTIVITY.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_CONNECTIVITY"
-value: {
-  string_value: "connectivity.google.contributions.prebuilt"
-}
diff --git a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CONSCRYPT.textproto b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CONSCRYPT.textproto
deleted file mode 100644
index a59cda3e..00000000
--- a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CONSCRYPT.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_CONSCRYPT"
-value: {
-  string_value: "conscrypt.google.contributions.prebuilt"
-}
diff --git a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_DOCUMENTSUIGOOGLE.textproto b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_DOCUMENTSUIGOOGLE.textproto
deleted file mode 100644
index c43b395a..00000000
--- a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_DOCUMENTSUIGOOGLE.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_DOCUMENTSUIGOOGLE"
-value: {
-  string_value: "documentsui.google.contributions.prebuilt"
-}
diff --git a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_EXTSERVICES.textproto b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_EXTSERVICES.textproto
deleted file mode 100644
index 3744cd73..00000000
--- a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_EXTSERVICES.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_EXTSERVICES"
-value: {
-  string_value: "extservices.google.contributions.prebuilt"
-}
diff --git a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_HEALTHFITNESS.textproto b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_HEALTHFITNESS.textproto
deleted file mode 100644
index 49592211..00000000
--- a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_HEALTHFITNESS.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_HEALTHFITNESS"
-value: {
-  string_value: "healthfitness.google.contributions.prebuilt"
-}
diff --git a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_IPSEC.textproto b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_IPSEC.textproto
deleted file mode 100644
index 44d34289..00000000
--- a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_IPSEC.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_IPSEC"
-value: {
-  string_value: "ipsec.google.contributions.prebuilt"
-}
diff --git a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_MEDIA.textproto b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_MEDIA.textproto
deleted file mode 100644
index 702f81b0..00000000
--- a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_MEDIA.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_MEDIA"
-value: {
-  string_value: "media.google.contributions.prebuilt"
-}
diff --git a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_MEDIAPROVIDER.textproto b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_MEDIAPROVIDER.textproto
deleted file mode 100644
index ee3b3cf3..00000000
--- a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_MEDIAPROVIDER.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_MEDIAPROVIDER"
-value: {
-  string_value: "mediaprovider.google.contributions.prebuilt"
-}
diff --git a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_MODULE_METADATA.textproto b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_MODULE_METADATA.textproto
deleted file mode 100644
index 5ba98fb4..00000000
--- a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_MODULE_METADATA.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_MODULE_METADATA"
-value: {
-  string_value: "modulemetadata.google.contributions.prebuilt"
-}
diff --git a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_NETWORKSTACKGOOGLE.textproto b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_NETWORKSTACKGOOGLE.textproto
deleted file mode 100644
index c3d30849..00000000
--- a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_NETWORKSTACKGOOGLE.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_NETWORKSTACKGOOGLE"
-value: {
-  string_value: "networkstack.google.contributions.prebuilt"
-}
diff --git a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_NEURALNETWORKS.textproto b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_NEURALNETWORKS.textproto
deleted file mode 100644
index c6b22ba0..00000000
--- a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_NEURALNETWORKS.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_NEURALNETWORKS"
-value: {
-  string_value: "neuralnetworks.google.contributions.prebuilt"
-}
diff --git a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_ONDEVICEPERSONALIZATION.textproto b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_ONDEVICEPERSONALIZATION.textproto
deleted file mode 100644
index fade2224..00000000
--- a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_ONDEVICEPERSONALIZATION.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_ONDEVICEPERSONALIZATION"
-value: {
-  string_value: "ondevicepersonalization.google.contributions.prebuilt"
-}
diff --git a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_PERMISSION.textproto b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_PERMISSION.textproto
deleted file mode 100644
index c4ec08da..00000000
--- a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_PERMISSION.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_PERMISSION"
-value: {
-  string_value: "permission.google.contributions.prebuilt"
-}
diff --git a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_PRIMARY_LIBS.textproto b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_PRIMARY_LIBS.textproto
deleted file mode 100644
index 53054247..00000000
--- a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_PRIMARY_LIBS.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_PRIMARY_LIBS"
-value: {
-  string_value: "primarylibs.google.contributions.prebuilt"
-}
diff --git a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_RESOLV.textproto b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_RESOLV.textproto
deleted file mode 100644
index fcdf9066..00000000
--- a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_RESOLV.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_RESOLV"
-value: {
-  string_value: "resolv.google.contributions.prebuilt"
-}
diff --git a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_SCHEDULING.textproto b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_SCHEDULING.textproto
deleted file mode 100644
index faf36d06..00000000
--- a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_SCHEDULING.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_SCHEDULING"
-value: {
-  string_value: "scheduling.google.contributions.prebuilt"
-}
diff --git a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_SDKEXTENSIONS.textproto b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_SDKEXTENSIONS.textproto
deleted file mode 100644
index 6ad93e2a..00000000
--- a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_SDKEXTENSIONS.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_SDKEXTENSIONS"
-value: {
-  string_value: "sdkextensions.google.contributions.prebuilt"
-}
diff --git a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_STATSD.textproto b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_STATSD.textproto
deleted file mode 100644
index 0adeaee7..00000000
--- a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_STATSD.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_STATSD"
-value: {
-  string_value: "statsd.google.contributions.prebuilt"
-}
diff --git a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_SWCODEC.textproto b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_SWCODEC.textproto
deleted file mode 100644
index 15ec8b12..00000000
--- a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_SWCODEC.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_SWCODEC"
-value: {
-  string_value: "swcodec.google.contributions.prebuilt"
-}
diff --git a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_TZDATA.textproto b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_TZDATA.textproto
deleted file mode 100644
index b3f0666f..00000000
--- a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_TZDATA.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_TZDATA"
-value: {
-  string_value: "tzdata.google.contributions.prebuilt"
-}
diff --git a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_WIFI.textproto b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_WIFI.textproto
deleted file mode 100644
index c25af166..00000000
--- a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_WIFI.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_WIFI"
-value: {
-  string_value: "wifi.google.contributions.prebuilt"
-}
diff --git a/gms_mainline/required/flag_values/ap4a/RELEASE_APEX_BOOT_JARS_PREBUILT_EXCLUDED_LIST.textproto b/gms_mainline/required/flag_values/ap4a/RELEASE_APEX_BOOT_JARS_PREBUILT_EXCLUDED_LIST.textproto
deleted file mode 100644
index 461c996f..00000000
--- a/gms_mainline/required/flag_values/ap4a/RELEASE_APEX_BOOT_JARS_PREBUILT_EXCLUDED_LIST.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name:  "RELEASE_APEX_BOOT_JARS_PREBUILT_EXCLUDED_LIST"
-value:  {
-  string_value:  "com.android.mediaprovider:framework-photopicker"
-}
diff --git a/gms_mainline/required/release_config_map.textproto b/gms_mainline/required/release_config_map.textproto
deleted file mode 100644
index 3237b81f..00000000
--- a/gms_mainline/required/release_config_map.textproto
+++ /dev/null
@@ -1 +0,0 @@
-default_containers: "vendor"
diff --git a/gms_mainline/required/release_configs/ap3a.textproto b/gms_mainline/required/release_configs/ap3a.textproto
deleted file mode 100644
index c25b670b..00000000
--- a/gms_mainline/required/release_configs/ap3a.textproto
+++ /dev/null
@@ -1 +0,0 @@
-name: "ap3a"
diff --git a/gms_mainline/required/release_configs/ap4a.textproto b/gms_mainline/required/release_configs/ap4a.textproto
deleted file mode 100644
index 5e1ad743..00000000
--- a/gms_mainline/required/release_configs/ap4a.textproto
+++ /dev/null
@@ -1 +0,0 @@
-name:  "ap4a"
diff --git a/gms_mainline/rkpd/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_REMOTEKEYPROVISIONING.textproto b/gms_mainline/rkpd/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_REMOTEKEYPROVISIONING.textproto
deleted file mode 100644
index 965e4cad..00000000
--- a/gms_mainline/rkpd/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_REMOTEKEYPROVISIONING.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_REMOTEKEYPROVISIONING"
-value: {
-  string_value: "rkpd.google.contributions.prebuilt"
-}
diff --git a/gms_mainline/rkpd/release_config_map.textproto b/gms_mainline/rkpd/release_config_map.textproto
deleted file mode 100644
index 3237b81f..00000000
--- a/gms_mainline/rkpd/release_config_map.textproto
+++ /dev/null
@@ -1 +0,0 @@
-default_containers: "vendor"
diff --git a/gms_mainline/rkpd/release_configs/ap3a.textproto b/gms_mainline/rkpd/release_configs/ap3a.textproto
deleted file mode 100644
index c25b670b..00000000
--- a/gms_mainline/rkpd/release_configs/ap3a.textproto
+++ /dev/null
@@ -1 +0,0 @@
-name: "ap3a"
diff --git a/gms_mainline/uwb/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_UWB.textproto b/gms_mainline/uwb/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_UWB.textproto
deleted file mode 100644
index 6f8574f3..00000000
--- a/gms_mainline/uwb/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_UWB.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_UWB"
-value: {
-  string_value: "uwb.google.contributions.prebuilt"
-}
diff --git a/gms_mainline/uwb/release_config_map.textproto b/gms_mainline/uwb/release_config_map.textproto
deleted file mode 100644
index 3237b81f..00000000
--- a/gms_mainline/uwb/release_config_map.textproto
+++ /dev/null
@@ -1 +0,0 @@
-default_containers: "vendor"
diff --git a/gms_mainline/uwb/release_configs/ap3a.textproto b/gms_mainline/uwb/release_configs/ap3a.textproto
deleted file mode 100644
index c25b670b..00000000
--- a/gms_mainline/uwb/release_configs/ap3a.textproto
+++ /dev/null
@@ -1 +0,0 @@
-name: "ap3a"
diff --git a/gms_mainline_go/optional/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_BLUETOOTH.textproto b/gms_mainline_go/optional/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_BLUETOOTH.textproto
deleted file mode 100644
index 17e34f70..00000000
--- a/gms_mainline_go/optional/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_BLUETOOTH.textproto
+++ /dev/null
@@ -1,5 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_BLUETOOTH"
-value: {
-  string_value: ""
-
-}
diff --git a/gms_mainline_go/optional/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_REMOTEKEYPROVISIONING.textproto b/gms_mainline_go/optional/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_REMOTEKEYPROVISIONING.textproto
deleted file mode 100644
index 13c89e80..00000000
--- a/gms_mainline_go/optional/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_REMOTEKEYPROVISIONING.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_REMOTEKEYPROVISIONING"
-value: {
-  string_value: "rkpd.go.google.contributions.prebuilt"
-}
diff --git a/gms_mainline_go/optional/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_UWB.textproto b/gms_mainline_go/optional/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_UWB.textproto
deleted file mode 100644
index 11c1935f..00000000
--- a/gms_mainline_go/optional/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_UWB.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_UWB"
-value: {
-  string_value: "uwb.go.google.contributions.prebuilt"
-}
diff --git a/gms_mainline_go/optional/release_config_map.textproto b/gms_mainline_go/optional/release_config_map.textproto
deleted file mode 100644
index 3237b81f..00000000
--- a/gms_mainline_go/optional/release_config_map.textproto
+++ /dev/null
@@ -1 +0,0 @@
-default_containers: "vendor"
diff --git a/gms_mainline_go/optional/release_configs/ap3a.textproto b/gms_mainline_go/optional/release_configs/ap3a.textproto
deleted file mode 100644
index c25b670b..00000000
--- a/gms_mainline_go/optional/release_configs/ap3a.textproto
+++ /dev/null
@@ -1 +0,0 @@
-name: "ap3a"
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_ADBD.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_ADBD.textproto
deleted file mode 100644
index 5df73519..00000000
--- a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_ADBD.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_ADBD"
-value: {
-  string_value: "adbd.go.google.contributions.prebuilt"
-}
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_ADSERVICES.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_ADSERVICES.textproto
deleted file mode 100644
index 196f4d4a..00000000
--- a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_ADSERVICES.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_ADSERVICES"
-value: {
-  string_value: "adservices.go.google.contributions.prebuilt"
-}
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_APPSEARCH.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_APPSEARCH.textproto
deleted file mode 100644
index abc22e08..00000000
--- a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_APPSEARCH.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_APPSEARCH"
-value: {
-  string_value: "appsearch.go.google.contributions.prebuilt"
-}
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_ART.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_ART.textproto
deleted file mode 100644
index c1d1df78..00000000
--- a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_ART.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_ART"
-value: {
-  string_value: "art.go.google.contributions.prebuilt"
-}
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CAPTIVEPORTALLOGIN.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CAPTIVEPORTALLOGIN.textproto
deleted file mode 100644
index 304b8693..00000000
--- a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CAPTIVEPORTALLOGIN.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_CAPTIVEPORTALLOGIN"
-value: {
-  string_value: "captiveportallogin.go.google.contributions.prebuilt"
-}
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CELLBROADCAST.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CELLBROADCAST.textproto
deleted file mode 100644
index c588c4e1..00000000
--- a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CELLBROADCAST.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_CELLBROADCAST"
-value: {
-  string_value: "cellbroadcast.go.google.contributions.prebuilt"
-}
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CONFIGINFRASTRUCTURE.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CONFIGINFRASTRUCTURE.textproto
deleted file mode 100644
index ed8b9a2e..00000000
--- a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CONFIGINFRASTRUCTURE.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_CONFIGINFRASTRUCTURE"
-value: {
-  string_value: "configinfrastructure.go.google.contributions.prebuilt"
-}
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CONNECTIVITY.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CONNECTIVITY.textproto
deleted file mode 100644
index 26ab1962..00000000
--- a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CONNECTIVITY.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_CONNECTIVITY"
-value: {
-  string_value: "connectivity.go.google.contributions.prebuilt"
-}
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CONSCRYPT.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CONSCRYPT.textproto
deleted file mode 100644
index 6d3ed3ae..00000000
--- a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CONSCRYPT.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_CONSCRYPT"
-value: {
-  string_value: "conscrypt.go.google.contributions.prebuilt"
-}
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_DOCUMENTSUIGOOGLE.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_DOCUMENTSUIGOOGLE.textproto
deleted file mode 100644
index 0cfcfb8f..00000000
--- a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_DOCUMENTSUIGOOGLE.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_DOCUMENTSUIGOOGLE"
-value: {
-  string_value: "documentsui.go.google.contributions.prebuilt"
-}
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_EXTSERVICES.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_EXTSERVICES.textproto
deleted file mode 100644
index 50d8c140..00000000
--- a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_EXTSERVICES.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_EXTSERVICES"
-value: {
-  string_value: "extservices.go.google.contributions.prebuilt"
-}
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_HEALTHFITNESS.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_HEALTHFITNESS.textproto
deleted file mode 100644
index d73d8d1b..00000000
--- a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_HEALTHFITNESS.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_HEALTHFITNESS"
-value: {
-  string_value: "healthfitness.go.google.contributions.prebuilt"
-}
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_IPSEC.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_IPSEC.textproto
deleted file mode 100644
index 51193c0a..00000000
--- a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_IPSEC.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_IPSEC"
-value: {
-  string_value: "ipsec.go.google.contributions.prebuilt"
-}
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_MEDIA.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_MEDIA.textproto
deleted file mode 100644
index 9439b406..00000000
--- a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_MEDIA.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_MEDIA"
-value: {
-  string_value: "media.go.google.contributions.prebuilt"
-}
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_MEDIAPROVIDER.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_MEDIAPROVIDER.textproto
deleted file mode 100644
index 58d39203..00000000
--- a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_MEDIAPROVIDER.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_MEDIAPROVIDER"
-value: {
-  string_value: "mediaprovider.go.google.contributions.prebuilt"
-}
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_MODULE_METADATA.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_MODULE_METADATA.textproto
deleted file mode 100644
index 190b8625..00000000
--- a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_MODULE_METADATA.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_MODULE_METADATA"
-value: {
-  string_value: "modulemetadata.go.google.contributions.prebuilt"
-}
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_NETWORKSTACKGOOGLE.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_NETWORKSTACKGOOGLE.textproto
deleted file mode 100644
index 91a51662..00000000
--- a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_NETWORKSTACKGOOGLE.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_NETWORKSTACKGOOGLE"
-value: {
-  string_value: "networkstack.go.google.contributions.prebuilt"
-}
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_NEURALNETWORKS.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_NEURALNETWORKS.textproto
deleted file mode 100644
index f1ff08c4..00000000
--- a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_NEURALNETWORKS.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_NEURALNETWORKS"
-value: {
-  string_value: "neuralnetworks.go.google.contributions.prebuilt"
-}
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_ONDEVICEPERSONALIZATION.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_ONDEVICEPERSONALIZATION.textproto
deleted file mode 100644
index 0efbaf7f..00000000
--- a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_ONDEVICEPERSONALIZATION.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_ONDEVICEPERSONALIZATION"
-value: {
-  string_value: "ondevicepersonalization.go.google.contributions.prebuilt"
-}
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_PERMISSION.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_PERMISSION.textproto
deleted file mode 100644
index e0f1f182..00000000
--- a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_PERMISSION.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_PERMISSION"
-value: {
-  string_value: "permission.go.google.contributions.prebuilt"
-}
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_PRIMARY_LIBS.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_PRIMARY_LIBS.textproto
deleted file mode 100644
index b8ae44dd..00000000
--- a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_PRIMARY_LIBS.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_PRIMARY_LIBS"
-value: {
-  string_value: "primarylibs.go.google.contributions.prebuilt"
-}
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_RESOLV.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_RESOLV.textproto
deleted file mode 100644
index 757dfc8b..00000000
--- a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_RESOLV.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_RESOLV"
-value: {
-  string_value: "resolv.go.google.contributions.prebuilt"
-}
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_SCHEDULING.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_SCHEDULING.textproto
deleted file mode 100644
index 3906dd80..00000000
--- a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_SCHEDULING.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_SCHEDULING"
-value: {
-  string_value: "scheduling.go.google.contributions.prebuilt"
-}
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_SDKEXTENSIONS.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_SDKEXTENSIONS.textproto
deleted file mode 100644
index 97be6a8c..00000000
--- a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_SDKEXTENSIONS.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_SDKEXTENSIONS"
-value: {
-  string_value: "sdkextensions.go.google.contributions.prebuilt"
-}
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_STATSD.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_STATSD.textproto
deleted file mode 100644
index 04718644..00000000
--- a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_STATSD.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_STATSD"
-value: {
-  string_value: "statsd.go.google.contributions.prebuilt"
-}
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_SWCODEC.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_SWCODEC.textproto
deleted file mode 100644
index e1cb4c58..00000000
--- a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_SWCODEC.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_SWCODEC"
-value: {
-  string_value: "swcodec.go.google.contributions.prebuilt"
-}
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_TELEMETRY_TVP.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_TELEMETRY_TVP.textproto
deleted file mode 100644
index 0560e0ae..00000000
--- a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_TELEMETRY_TVP.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_TELEMETRY_TVP"
-value: {
-  string_value: "telemetrytvp.go.google.contributions.prebuilt"
-}
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_TZDATA.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_TZDATA.textproto
deleted file mode 100644
index 2a221042..00000000
--- a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_TZDATA.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_TZDATA"
-value: {
-  string_value: "tzdata.go.google.contributions.prebuilt"
-}
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_WIFI.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_WIFI.textproto
deleted file mode 100644
index c08b952b..00000000
--- a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_WIFI.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_WIFI"
-value: {
-  string_value: "wifi.go.google.contributions.prebuilt"
-}
diff --git a/gms_mainline_go/required/flag_values/ap4a/RELEASE_APEX_BOOT_JARS_PREBUILT_EXCLUDED_LIST.textproto b/gms_mainline_go/required/flag_values/ap4a/RELEASE_APEX_BOOT_JARS_PREBUILT_EXCLUDED_LIST.textproto
deleted file mode 100644
index 461c996f..00000000
--- a/gms_mainline_go/required/flag_values/ap4a/RELEASE_APEX_BOOT_JARS_PREBUILT_EXCLUDED_LIST.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name:  "RELEASE_APEX_BOOT_JARS_PREBUILT_EXCLUDED_LIST"
-value:  {
-  string_value:  "com.android.mediaprovider:framework-photopicker"
-}
diff --git a/gms_mainline_go/required/release_config_map.textproto b/gms_mainline_go/required/release_config_map.textproto
deleted file mode 100644
index 3237b81f..00000000
--- a/gms_mainline_go/required/release_config_map.textproto
+++ /dev/null
@@ -1 +0,0 @@
-default_containers: "vendor"
diff --git a/gms_mainline_go/required/release_configs/ap3a.textproto b/gms_mainline_go/required/release_configs/ap3a.textproto
deleted file mode 100644
index c25b670b..00000000
--- a/gms_mainline_go/required/release_configs/ap3a.textproto
+++ /dev/null
@@ -1 +0,0 @@
-name: "ap3a"
diff --git a/gms_mainline_go/required/release_configs/ap4a.textproto b/gms_mainline_go/required/release_configs/ap4a.textproto
deleted file mode 100644
index 5e1ad743..00000000
--- a/gms_mainline_go/required/release_configs/ap4a.textproto
+++ /dev/null
@@ -1 +0,0 @@
-name:  "ap4a"
diff --git a/gms_mainline_go/rkpd/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_REMOTEKEYPROVISIONING.textproto b/gms_mainline_go/rkpd/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_REMOTEKEYPROVISIONING.textproto
deleted file mode 100644
index 13c89e80..00000000
--- a/gms_mainline_go/rkpd/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_REMOTEKEYPROVISIONING.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_REMOTEKEYPROVISIONING"
-value: {
-  string_value: "rkpd.go.google.contributions.prebuilt"
-}
diff --git a/gms_mainline_go/rkpd/release_config_map.textproto b/gms_mainline_go/rkpd/release_config_map.textproto
deleted file mode 100644
index 3237b81f..00000000
--- a/gms_mainline_go/rkpd/release_config_map.textproto
+++ /dev/null
@@ -1 +0,0 @@
-default_containers: "vendor"
diff --git a/gms_mainline_go/rkpd/release_configs/ap3a.textproto b/gms_mainline_go/rkpd/release_configs/ap3a.textproto
deleted file mode 100644
index c25b670b..00000000
--- a/gms_mainline_go/rkpd/release_configs/ap3a.textproto
+++ /dev/null
@@ -1 +0,0 @@
-name: "ap3a"
diff --git a/gms_mainline_go/uwb/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_UWB.textproto b/gms_mainline_go/uwb/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_UWB.textproto
deleted file mode 100644
index 11c1935f..00000000
--- a/gms_mainline_go/uwb/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_UWB.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_APEX_CONTRIBUTIONS_UWB"
-value: {
-  string_value: "uwb.go.google.contributions.prebuilt"
-}
diff --git a/gms_mainline_go/uwb/release_config_map.textproto b/gms_mainline_go/uwb/release_config_map.textproto
deleted file mode 100644
index 3237b81f..00000000
--- a/gms_mainline_go/uwb/release_config_map.textproto
+++ /dev/null
@@ -1 +0,0 @@
-default_containers: "vendor"
diff --git a/gms_mainline_go/uwb/release_configs/ap3a.textproto b/gms_mainline_go/uwb/release_configs/ap3a.textproto
deleted file mode 100644
index c25b670b..00000000
--- a/gms_mainline_go/uwb/release_configs/ap3a.textproto
+++ /dev/null
@@ -1 +0,0 @@
-name: "ap3a"
```

