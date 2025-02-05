```diff
diff --git a/aconfig/ap3a/com.android.server.backup/enable_increased_bmm_logging_for_restore_at_install_flag_values.textproto b/aconfig/ap3a/com.android.server.backup/enable_increased_bmm_logging_for_restore_at_install_flag_values.textproto
index b3d1ff19..9822ed57 100644
--- a/aconfig/ap3a/com.android.server.backup/enable_increased_bmm_logging_for_restore_at_install_flag_values.textproto
+++ b/aconfig/ap3a/com.android.server.backup/enable_increased_bmm_logging_for_restore_at_install_flag_values.textproto
@@ -1,6 +1,6 @@
 flag_value {
   package: "com.android.server.backup"
   name: "enable_increased_bmm_logging_for_restore_at_install"
-  state: ENABLED
+  state: DISABLED
   permission: READ_ONLY
 }
diff --git a/aconfig/ap4a/Android.bp b/aconfig/ap4a/Android.bp
index c0f1713b..fa762a32 100644
--- a/aconfig/ap4a/Android.bp
+++ b/aconfig/ap4a/Android.bp
@@ -13,163 +13,212 @@
 // limitations under the License.
 
 aconfig_value_set {
-    name: "aconfig_value_set-platform_build_release-ap4a",
-    values: [
-      "aconfig-values-platform_build_release-ap4a-com.android.server.alarm-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.systemui.accessibility.accessibilitymenu-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.server.notification-all",
-      "aconfig-values-platform_build_release-ap4a-android.companion-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.providers.settings-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.btaudio.hal.flags-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.server.powerstats-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.uwb.flags-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.server.biometrics-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.internal.pm.pkg.component.flags-all",
-      "aconfig-values-platform_build_release-ap4a-android.net.wifi.flags-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.providers.media.flags-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.adservices.flags-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.server.stats-all",
-      "aconfig-values-platform_build_release-ap4a-android.content.pm-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.server.policy-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.server.power.batterysaver-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.systemui-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.media.playback.flags-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.intentresolver-all",
-      "aconfig-values-platform_build_release-ap4a-android.provider-all",
-      "aconfig-values-platform_build_release-ap4a-android.multiuser-all",
-      "aconfig-values-platform_build_release-ap4a-android.hardware.devicestate.feature.flags-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.server.backup-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.server.deviceidle-all",
-      "aconfig-values-platform_build_release-ap4a-android.database.sqlite-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.media.audio-all",
-      "aconfig-values-platform_build_release-ap4a-android.app.contextualsearch.flags-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.media.performance.flags-all",
-      "aconfig-values-platform_build_release-ap4a-android.service.notification-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.server.net-all",
-      "aconfig-values-platform_build_release-ap4a-android.permission.flags-all",
-      "aconfig-values-platform_build_release-ap4a-android.view.inputmethod-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.internal.telephony.flags-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.net.flags-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.internal.foldables.flags-all",
-      "aconfig-values-platform_build_release-ap4a-android.net.platform.flags-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.media.flags-all",
-      "aconfig-values-platform_build_release-ap4a-android.webkit-all",
-      "aconfig-values-platform_build_release-ap4a-android.hardware.usb.flags-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.settingslib.widget.selectorwithwidgetpreference.flags-all",
-      "aconfig-values-platform_build_release-ap4a-android.view.contentcapture.flags-all",
-      "aconfig-values-platform_build_release-ap4a-android.service.voice.flags-all",
-      "aconfig-values-platform_build_release-ap4a-android.service.dreams-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.launcher3-all",
-      "aconfig-values-platform_build_release-ap4a-android.crashrecovery.flags-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.server.power.hint-all",
-      "aconfig-values-platform_build_release-ap4a-android.security.flag-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.server.flags-all",
-      "aconfig-values-platform_build_release-ap4a-android.app.job-all",
-      "aconfig-values-platform_build_release-ap4a-android.app-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.permission.flags-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.server.feature.flags-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.settings.accessibility-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.aconfig.test-all",
-      "aconfig-values-platform_build_release-ap4a-android.view.flags-all",
-      "aconfig-values-platform_build_release-ap4a-android.security-all",
-      "aconfig-values-platform_build_release-ap4a-android.hardware.biometrics-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.server.power.feature.flags-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.media.audioserver-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.car.carlauncher-all",
-      "aconfig-values-platform_build_release-ap4a-android.service.autofill-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.settingslib.widget.flags-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.bluetooth.flags-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.settings.development-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.settings.media_drm-all",
-      "aconfig-values-platform_build_release-ap4a-android.location.flags-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.server.policy.feature.flags-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.wm.shell-all",
-      "aconfig-values-platform_build_release-ap4a-android.service.controls.flags-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.server.accessibility-all",
-      "aconfig-values-platform_build_release-ap4a-vendor.vibrator.hal.flags-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.hardware.libsensor.flags-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.settings.flags-all",
-      "aconfig-values-platform_build_release-ap4a-android.nfc-all",
-      "aconfig-values-platform_build_release-ap4a-android.speech.flags-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.media.codec.flags-all",
-      "aconfig-values-platform_build_release-ap4a-android.os-all",
-      "aconfig-values-platform_build_release-ap4a-android.service.chooser-all",
-      "aconfig-values-platform_build_release-ap4a-android.widget.flags-all",
-      "aconfig-values-platform_build_release-ap4a-android.media.midi-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.settings.factory_reset-all",
-      "aconfig-values-platform_build_release-ap4a-android.companion.virtualdevice.flags-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.server.usb.flags-all",
-      "aconfig-values-platform_build_release-ap4a-android.os.profiling-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.hardware.input-all",
-      "aconfig-values-platform_build_release-ap4a-android.app.wearable-all",
-      "aconfig-values-platform_build_release-ap4a-android.media.codec-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.providers.contactkeys.flags-all",
-      "aconfig-values-platform_build_release-ap4a-android.content.res-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.server.dreams-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.systemui.shared-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.wifi.flags-all",
-      "aconfig-values-platform_build_release-ap4a-android.app.smartspace.flags-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.car.datasubscription-all",
-      "aconfig-values-platform_build_release-ap4a-android.graphics.pdf.flags-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.sdksandbox.flags-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.systemui.car-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.nearby.flags-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.deviceaswebcam.flags-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.window.flags-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.server.job-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.media.editing.flags-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.ipsec.flags-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.icu-all",
-      "aconfig-values-platform_build_release-ap4a-android.content.flags-all",
-      "aconfig-values-platform_build_release-ap4a-android.view.accessibility-all",
-      "aconfig-values-platform_build_release-ap4a-android.hardware.radio-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.server.deviceconfig-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.internal.compat.flags-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.media.aaudio-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.input.flags-all",
-      "aconfig-values-platform_build_release-ap4a-android.app.usage-all",
-      "aconfig-values-platform_build_release-ap4a-android.credentials.flags-all",
-      "aconfig-values-platform_build_release-ap4a-android.app.ondeviceintelligence.flags-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.settingslib.media.flags-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.system.virtualmachine.flags-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.appsearch.flags-all",
-      "aconfig-values-platform_build_release-ap4a-android.app.admin.flags-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.car.settings-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.graphics.libgui.flags-all",
-      "aconfig-values-platform_build_release-ap4a-android.car.feature-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.internal.camera.flags-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.server.usage-all",
-      "aconfig-values-platform_build_release-ap4a-android.companion.virtual.flags-all",
-      "aconfig-values-platform_build_release-ap4a-android.os.vibrator-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.server.power.optimization-all",
-      "aconfig-values-platform_build_release-ap4a-android.hardware.flags-all",
-      "aconfig-values-platform_build_release-ap4a-android.media.audiopolicy-all",
-      "aconfig-values-platform_build_release-ap4a-android.net.vcn-all",
-      "aconfig-values-platform_build_release-ap4a-android.view.contentprotection.flags-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.server.display.feature.flags-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.media.mainline.flags-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.settingslib.flags-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.net.thread.flags-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.server.am-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.healthconnect.flags-all",
-      "aconfig-values-platform_build_release-ap4a-android.media.audio-all",
-      "aconfig-values-platform_build_release-ap4a-android.adaptiveauth-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.graphics.surfaceflinger.flags-all",
-      "aconfig-values-platform_build_release-ap4a-android.server.app-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.adservices.ondevicepersonalization.flags-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.car.dockutil-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.internal.os-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.text.flags-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.nfc.flags-all",
-      "aconfig-values-platform_build_release-ap4a-android.chre.flags-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.frameworks.sensorservice.flags-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.libcore-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.graphics.hwui.flags-all",
-      "aconfig-values-platform_build_release-ap4a-com.google.android.iwlan.flags-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.libhardware.dynamic.sensors.flags-all",
-      "aconfig-values-platform_build_release-ap4a-android.server-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.server.telecom.flags-all",
-      "aconfig-values-platform_build_release-ap4a-android.appwidget.flags-all",
-      "aconfig-values-platform_build_release-ap4a-com.android.egg.flags-all"
-    ]
+  name: "aconfig_value_set-platform_build_release-ap4a",
+  values: [
+        "aconfig-values-platform_build_release-ap4a-android.service.autofill-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.server.deviceidle-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.hardware.libsensor.flags-all",
+        "aconfig-values-platform_build_release-ap4a-android.permission.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.server.power.feature.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.providers.contacts.flags-all",
+        "aconfig-values-platform_build_release-ap4a-android.media.codec-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.providers.media.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.media.audioserver-all",
+        "aconfig-values-platform_build_release-ap4a-android.hardware.flags-all",
+        "aconfig-values-platform_build_release-ap4a-android.content.flags-all",
+        "aconfig-values-platform_build_release-ap4a-android.os.profiling-all",
+        "aconfig-values-platform_build_release-ap4a-com.google.android.iwlan.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.server.deviceconfig-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.graphics.libgui.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.server.power.optimization-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.sdksandbox.flags-all",
+        "aconfig-values-platform_build_release-ap4a-android.media.audio-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.launcher3-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.server.telecom.flags-all",
+        "aconfig-values-platform_build_release-ap4a-android.view.contentprotection.flags-all",
+        "aconfig-values-platform_build_release-ap4a-android.car.feature-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.server.usage-all",
+        "aconfig-values-platform_build_release-ap4a-android.security.flag-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.media.aaudio-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.server.feature.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.internal.pm.pkg.component.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.settingslib.media.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.server.connectivity-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.server.usb.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.internal.jank-all",
+        "aconfig-values-platform_build_release-ap4a-android.nfc-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.os.statsd.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.server.notification-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.trunk_stable_workflow_testing-all",
+        "aconfig-values-platform_build_release-ap4a-android.content.pm-all",
+        "aconfig-values-platform_build_release-ap4a-android.server-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.server.accessibility-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.media.mainline.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.server.backup-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.media.projection.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.libcore-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.media.codec.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.nfc.nci.flags-all",
+        "aconfig-values-platform_build_release-ap4a-android.provider.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.adservices.ondevicepersonalization.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.frameworks.sensorservice.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.settings.media_drm-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.hardware.input-all",
+        "aconfig-values-platform_build_release-ap4a-android.media.midi-all",
+        "aconfig-values-platform_build_release-ap4a-android.service.appprediction.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.graphics.libvulkan.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.car.settings-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.hardware.camera2-all",
+        "aconfig-values-platform_build_release-ap4a-android.appwidget.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.server.alarm-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.intentresolver-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.healthfitness.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.server.updates-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.car.carlauncher-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.wallpaper-all",
+        "aconfig-values-platform_build_release-ap4a-android.chre.flags-all",
+        "aconfig-values-platform_build_release-ap4a-android.provider.configinfrastructure.framework-all",
+        "aconfig-values-platform_build_release-ap4a-android.server.app-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.telephony.phone.flags-all",
+        "aconfig-values-platform_build_release-ap4a-android.location.flags-all",
+        "aconfig-values-platform_build_release-ap4a-android.service.voice.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.wm.shell-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.settings.connecteddevice.flags-all",
+        "aconfig-values-platform_build_release-ap4a-android.net.wifi.flags-all",
+        "aconfig-values-platform_build_release-ap4a-android.adaptiveauth-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.car.dockutil-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.media.editing.flags-all",
+        "aconfig-values-platform_build_release-ap4a-android.app.jank-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.settings.keyboard-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.server.companion.virtual-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.settings.flags-all",
+        "aconfig-values-platform_build_release-ap4a-android.companion-all",
+        "aconfig-values-platform_build_release-ap4a-vendor.vibrator.hal.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.system.virtualmachine.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.settingslib.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.car.datasubscription-all",
+        "aconfig-values-platform_build_release-ap4a-android.os-all",
+        "aconfig-values-platform_build_release-ap4a-android.companion.virtualdevice.flags-all",
+        "aconfig-values-platform_build_release-ap4a-android.tracing-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.server.power.hint-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.btaudio.hal.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.graphics.flags-all",
+        "aconfig-values-platform_build_release-ap4a-android.widget.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.server.net-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.aconfig.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.media.audioclient-all",
+        "aconfig-values-platform_build_release-ap4a-android.net.vcn-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.settingslib.widget.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.graphics.hwui.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.graphics.bufferstreams.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.aconfig.test-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.systemui.shared-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.graphics.surfaceflinger.flags-all",
+        "aconfig-values-platform_build_release-ap4a-android.credentials.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.art.flags-all",
+        "aconfig-values-platform_build_release-ap4a-android.hardware.radio-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.managedprovisioning.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.org.conscrypt-all",
+        "aconfig-values-platform_build_release-ap4a-android.os.vibrator-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.devicelock.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.server.job-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.internal.foldables.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.settings.development-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.settings.factory_reset-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.systemui.communal-all",
+        "aconfig-values-platform_build_release-ap4a-android.view.contentcapture.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.healthconnect.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.bluetooth.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.media.flags-all",
+        "aconfig-values-platform_build_release-ap4a-android.multiuser-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.server.policy-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.systemui.accessibility.accessibilitymenu-all",
+        "aconfig-values-platform_build_release-ap4a-android.service.dreams-all",
+        "aconfig-values-platform_build_release-ap4a-android.crashrecovery.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.uwb.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.server.dreams-all",
+        "aconfig-values-platform_build_release-ap4a-android.app.job-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.egg.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.icu-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.settingslib.widget.selectorwithwidgetpreference.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.media.playback.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.internal.camera.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.systemui.aconfig-all",
+        "aconfig-values-platform_build_release-ap4a-android.service.notification-all",
+        "aconfig-values-platform_build_release-ap4a-com.example.android.aconfig.demo.flags-all",
+        "aconfig-values-platform_build_release-ap4a-android.security-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.net.thread.flags-all",
+        "aconfig-values-platform_build_release-ap4a-android.service.controls.flags-all",
+        "aconfig-values-platform_build_release-ap4a-android.hardware.usb.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.adservices.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.wifi.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.google.android.platform.launcher.aconfig.flags-all",
+        "aconfig-values-platform_build_release-ap4a-android.view.accessibility-all",
+        "aconfig-values-platform_build_release-ap4a-android.app.appfunctions.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.providers.settings-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.systemui-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.server.utils-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.cellbroadcastreceiver.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.server.devicepolicy.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.settings.accessibility-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.internal.compat.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.server.policy.feature.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.media.performance.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.aconfig_new_storage-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.server.stats-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.permission.flags-all",
+        "aconfig-values-platform_build_release-ap4a-android.app.wearable-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.server.security-all",
+        "aconfig-values-platform_build_release-ap4a-android.app.ondeviceintelligence.flags-all",
+        "aconfig-values-platform_build_release-ap4a-android.app.admin.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.ipsec.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.nearby.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.server.os-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.server.contextualsearch.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.input.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.net.ct.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.server.pm-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.server.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.libhardware.dynamic.sensors.flags-all",
+        "aconfig-values-platform_build_release-ap4a-android.graphics.pdf.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.deviceaswebcam.flags-all",
+        "aconfig-values-platform_build_release-ap4a-android.database.sqlite-all",
+        "aconfig-values-platform_build_release-ap4a-android.service.chooser-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.net.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.server.power.batterysaver-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.server.biometrics-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.text.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.net.thread.platform.flags-all",
+        "aconfig-values-platform_build_release-ap4a-android.view.inputmethod-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.providers.contactkeys.flags-all",
+        "aconfig-values-platform_build_release-ap4a-android.view.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.systemui.car-all",
+        "aconfig-values-platform_build_release-ap4a-android.media.audiopolicy-all",
+        "aconfig-values-platform_build_release-ap4a-android.media.soundtrigger-all",
+        "aconfig-values-platform_build_release-ap4a-android.security.keystore2-all",
+        "aconfig-values-platform_build_release-ap4a-android.app.smartspace.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.media.audio-all",
+        "aconfig-values-platform_build_release-ap4a-android.net.platform.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.server.am-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.server.display.feature.flags-all",
+        "aconfig-values-platform_build_release-ap4a-android.hardware.devicestate.feature.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.window.flags-all",
+        "aconfig-values-platform_build_release-ap4a-android.app.contextualsearch.flags-all",
+        "aconfig-values-platform_build_release-ap4a-android.hardware.biometrics-all",
+        "aconfig-values-platform_build_release-ap4a-android.speech.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.server.powerstats-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.internal.os-all",
+        "aconfig-values-platform_build_release-ap4a-android.content.res-all",
+        "aconfig-values-platform_build_release-ap4a-android.app.usage-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.nfc.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.server.locksettings-all",
+        "aconfig-values-platform_build_release-ap4a-android.sdk-all",
+        "aconfig-values-platform_build_release-ap4a-android.provider-all",
+        "aconfig-values-platform_build_release-ap4a-android.app-all",
+        "aconfig-values-platform_build_release-ap4a-android.companion.virtual.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.appsearch.flags-all",
+        "aconfig-values-platform_build_release-ap4a-com.android.internal.telephony.flags-all",
+        "aconfig-values-platform_build_release-ap4a-android.media.tv.flags-all",
+        "aconfig-values-platform_build_release-ap4a-android.webkit-all",
+      ]
 }
diff --git a/aconfig/ap4a/android.app.admin.flags/allow_screen_brightness_control_on_cope_flag_values.textproto b/aconfig/ap4a/android.app.admin.flags/allow_screen_brightness_control_on_cope_flag_values.textproto
new file mode 100644
index 00000000..a6e7b7f4
--- /dev/null
+++ b/aconfig/ap4a/android.app.admin.flags/allow_screen_brightness_control_on_cope_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.app.admin.flags"
+  name: "allow_screen_brightness_control_on_cope"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/android.app.admin.flags/always_persist_do_flag_values.textproto b/aconfig/ap4a/android.app.admin.flags/always_persist_do_flag_values.textproto
new file mode 100644
index 00000000..48f783b4
--- /dev/null
+++ b/aconfig/ap4a/android.app.admin.flags/always_persist_do_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.app.admin.flags"
+  name: "always_persist_do"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/android.app.admin.flags/coexistence_migration_for_non_emm_management_enabled_flag_values.textproto b/aconfig/ap4a/android.app.admin.flags/coexistence_migration_for_non_emm_management_enabled_flag_values.textproto
new file mode 100644
index 00000000..38993b86
--- /dev/null
+++ b/aconfig/ap4a/android.app.admin.flags/coexistence_migration_for_non_emm_management_enabled_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.app.admin.flags"
+  name: "coexistence_migration_for_non_emm_management_enabled"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/android.app.admin.flags/copy_account_with_retry_enabled_flag_values.textproto b/aconfig/ap4a/android.app.admin.flags/copy_account_with_retry_enabled_flag_values.textproto
new file mode 100644
index 00000000..a411289f
--- /dev/null
+++ b/aconfig/ap4a/android.app.admin.flags/copy_account_with_retry_enabled_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.app.admin.flags"
+  name: "copy_account_with_retry_enabled"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/android.app.admin.flags/dedicated_device_control_enabled_flag_values.textproto b/aconfig/ap4a/android.app.admin.flags/dedicated_device_control_enabled_flag_values.textproto
new file mode 100644
index 00000000..c7b7af0d
--- /dev/null
+++ b/aconfig/ap4a/android.app.admin.flags/dedicated_device_control_enabled_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.app.admin.flags"
+  name: "dedicated_device_control_enabled"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/android.app.admin.flags/delete_private_space_under_restriction_flag_values.textproto b/aconfig/ap4a/android.app.admin.flags/delete_private_space_under_restriction_flag_values.textproto
new file mode 100644
index 00000000..781503a1
--- /dev/null
+++ b/aconfig/ap4a/android.app.admin.flags/delete_private_space_under_restriction_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.app.admin.flags"
+  name: "delete_private_space_under_restriction"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/android.app.admin.flags/device_policy_size_tracking_internal_bug_fix_enabled_flag_values.textproto b/aconfig/ap4a/android.app.admin.flags/device_policy_size_tracking_internal_bug_fix_enabled_flag_values.textproto
new file mode 100644
index 00000000..637e161c
--- /dev/null
+++ b/aconfig/ap4a/android.app.admin.flags/device_policy_size_tracking_internal_bug_fix_enabled_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.app.admin.flags"
+  name: "device_policy_size_tracking_internal_bug_fix_enabled"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/android.app.admin.flags/disallow_user_control_bg_usage_fix_flag_values.textproto b/aconfig/ap4a/android.app.admin.flags/disallow_user_control_bg_usage_fix_flag_values.textproto
new file mode 100644
index 00000000..798cac36
--- /dev/null
+++ b/aconfig/ap4a/android.app.admin.flags/disallow_user_control_bg_usage_fix_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.app.admin.flags"
+  name: "disallow_user_control_bg_usage_fix"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/android.app.admin.flags/dmrh_set_app_restrictions_flag_values.textproto b/aconfig/ap4a/android.app.admin.flags/dmrh_set_app_restrictions_flag_values.textproto
new file mode 100644
index 00000000..d16c94c8
--- /dev/null
+++ b/aconfig/ap4a/android.app.admin.flags/dmrh_set_app_restrictions_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.app.admin.flags"
+  name: "dmrh_set_app_restrictions"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/android.app.admin.flags/dumpsys_policy_engine_migration_enabled_flag_values.textproto b/aconfig/ap4a/android.app.admin.flags/dumpsys_policy_engine_migration_enabled_flag_values.textproto
new file mode 100644
index 00000000..a191802a
--- /dev/null
+++ b/aconfig/ap4a/android.app.admin.flags/dumpsys_policy_engine_migration_enabled_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.app.admin.flags"
+  name: "dumpsys_policy_engine_migration_enabled"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/android.app.admin.flags/headless_device_owner_delegate_security_logging_bug_fix_flag_values.textproto b/aconfig/ap4a/android.app.admin.flags/headless_device_owner_delegate_security_logging_bug_fix_flag_values.textproto
new file mode 100644
index 00000000..9c652115
--- /dev/null
+++ b/aconfig/ap4a/android.app.admin.flags/headless_device_owner_delegate_security_logging_bug_fix_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.app.admin.flags"
+  name: "headless_device_owner_delegate_security_logging_bug_fix"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/android.app.admin.flags/headless_device_owner_provisioning_fix_enabled_flag_values.textproto b/aconfig/ap4a/android.app.admin.flags/headless_device_owner_provisioning_fix_enabled_flag_values.textproto
new file mode 100644
index 00000000..4270e086
--- /dev/null
+++ b/aconfig/ap4a/android.app.admin.flags/headless_device_owner_provisioning_fix_enabled_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.app.admin.flags"
+  name: "headless_device_owner_provisioning_fix_enabled"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/android.app.admin.flags/headless_single_user_bad_device_admin_state_fix_flag_values.textproto b/aconfig/ap4a/android.app.admin.flags/headless_single_user_bad_device_admin_state_fix_flag_values.textproto
new file mode 100644
index 00000000..2f80a21b
--- /dev/null
+++ b/aconfig/ap4a/android.app.admin.flags/headless_single_user_bad_device_admin_state_fix_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.app.admin.flags"
+  name: "headless_single_user_bad_device_admin_state_fix"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/android.app.admin.flags/headless_single_user_compatibility_fix_flag_values.textproto b/aconfig/ap4a/android.app.admin.flags/headless_single_user_compatibility_fix_flag_values.textproto
new file mode 100644
index 00000000..ced1da40
--- /dev/null
+++ b/aconfig/ap4a/android.app.admin.flags/headless_single_user_compatibility_fix_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.app.admin.flags"
+  name: "headless_single_user_compatibility_fix"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/android.app.admin.flags/headless_single_user_fixes_flag_values.textproto b/aconfig/ap4a/android.app.admin.flags/headless_single_user_fixes_flag_values.textproto
new file mode 100644
index 00000000..5f16586d
--- /dev/null
+++ b/aconfig/ap4a/android.app.admin.flags/headless_single_user_fixes_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.app.admin.flags"
+  name: "headless_single_user_fixes"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/android.app.admin.flags/hsum_unlock_notification_fix_flag_values.textproto b/aconfig/ap4a/android.app.admin.flags/hsum_unlock_notification_fix_flag_values.textproto
new file mode 100644
index 00000000..af13126e
--- /dev/null
+++ b/aconfig/ap4a/android.app.admin.flags/hsum_unlock_notification_fix_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.app.admin.flags"
+  name: "hsum_unlock_notification_fix"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/android.app.admin.flags/permission_migration_for_zero_trust_impl_enabled_flag_values.textproto b/aconfig/ap4a/android.app.admin.flags/permission_migration_for_zero_trust_impl_enabled_flag_values.textproto
new file mode 100644
index 00000000..a49d304c
--- /dev/null
+++ b/aconfig/ap4a/android.app.admin.flags/permission_migration_for_zero_trust_impl_enabled_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.app.admin.flags"
+  name: "permission_migration_for_zero_trust_impl_enabled"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/android.app.admin.flags/power_exemption_bg_usage_fix_flag_values.textproto b/aconfig/ap4a/android.app.admin.flags/power_exemption_bg_usage_fix_flag_values.textproto
new file mode 100644
index 00000000..c6656793
--- /dev/null
+++ b/aconfig/ap4a/android.app.admin.flags/power_exemption_bg_usage_fix_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.app.admin.flags"
+  name: "power_exemption_bg_usage_fix"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/android.app.appfunctions.flags/Android.bp b/aconfig/ap4a/android.app.appfunctions.flags/Android.bp
new file mode 100644
index 00000000..e91a45d2
--- /dev/null
+++ b/aconfig/ap4a/android.app.appfunctions.flags/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-ap4a-android.app.appfunctions.flags-all",
+  package: "android.app.appfunctions.flags",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/ap4a/android.app.jank/Android.bp b/aconfig/ap4a/android.app.jank/Android.bp
new file mode 100644
index 00000000..0eb0e4cb
--- /dev/null
+++ b/aconfig/ap4a/android.app.jank/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-ap4a-android.app.jank-all",
+  package: "android.app.jank",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/ap4a/android.chre.flags/bug_fix_reduce_lock_holding_period_flag_values.textproto b/aconfig/ap4a/android.chre.flags/bug_fix_reduce_lock_holding_period_flag_values.textproto
new file mode 100644
index 00000000..68053671
--- /dev/null
+++ b/aconfig/ap4a/android.chre.flags/bug_fix_reduce_lock_holding_period_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.chre.flags"
+  name: "bug_fix_reduce_lock_holding_period"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/android.chre.flags/flag_log_nanoapp_load_metrics_flag_values.textproto b/aconfig/ap4a/android.chre.flags/flag_log_nanoapp_load_metrics_flag_values.textproto
new file mode 100644
index 00000000..0fccef1e
--- /dev/null
+++ b/aconfig/ap4a/android.chre.flags/flag_log_nanoapp_load_metrics_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.chre.flags"
+  name: "flag_log_nanoapp_load_metrics"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/android.chre.flags/metrics_reporter_in_the_daemon_flag_values.textproto b/aconfig/ap4a/android.chre.flags/metrics_reporter_in_the_daemon_flag_values.textproto
new file mode 100644
index 00000000..feefe54b
--- /dev/null
+++ b/aconfig/ap4a/android.chre.flags/metrics_reporter_in_the_daemon_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.chre.flags"
+  name: "metrics_reporter_in_the_daemon"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/android.chre.flags/remove_ap_wakeup_metric_report_limit_flag_values.textproto b/aconfig/ap4a/android.chre.flags/remove_ap_wakeup_metric_report_limit_flag_values.textproto
new file mode 100644
index 00000000..8fbd5143
--- /dev/null
+++ b/aconfig/ap4a/android.chre.flags/remove_ap_wakeup_metric_report_limit_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.chre.flags"
+  name: "remove_ap_wakeup_metric_report_limit"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/android.companion.virtual.flags/consistent_display_flags_flag_values.textproto b/aconfig/ap4a/android.companion.virtual.flags/consistent_display_flags_flag_values.textproto
new file mode 100644
index 00000000..6e2709f7
--- /dev/null
+++ b/aconfig/ap4a/android.companion.virtual.flags/consistent_display_flags_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.companion.virtual.flags"
+  name: "consistent_display_flags"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/android.companion.virtual.flags/express_metrics_flag_values.textproto b/aconfig/ap4a/android.companion.virtual.flags/express_metrics_flag_values.textproto
new file mode 100644
index 00000000..3e9f6bd2
--- /dev/null
+++ b/aconfig/ap4a/android.companion.virtual.flags/express_metrics_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.companion.virtual.flags"
+  name: "express_metrics"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/android.companion.virtual.flags/interactive_screen_mirror_flag_values.textproto b/aconfig/ap4a/android.companion.virtual.flags/interactive_screen_mirror_flag_values.textproto
new file mode 100644
index 00000000..afad149d
--- /dev/null
+++ b/aconfig/ap4a/android.companion.virtual.flags/interactive_screen_mirror_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.companion.virtual.flags"
+  name: "interactive_screen_mirror"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/android.companion.virtual.flags/intercept_intents_before_applying_policy_flag_values.textproto b/aconfig/ap4a/android.companion.virtual.flags/intercept_intents_before_applying_policy_flag_values.textproto
new file mode 100644
index 00000000..befd0c4f
--- /dev/null
+++ b/aconfig/ap4a/android.companion.virtual.flags/intercept_intents_before_applying_policy_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.companion.virtual.flags"
+  name: "intercept_intents_before_applying_policy"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/android.companion.virtual.flags/stream_permissions_flag_values.textproto b/aconfig/ap4a/android.companion.virtual.flags/stream_permissions_flag_values.textproto
new file mode 100644
index 00000000..f1e4abfa
--- /dev/null
+++ b/aconfig/ap4a/android.companion.virtual.flags/stream_permissions_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.companion.virtual.flags"
+  name: "stream_permissions"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/android.companion.virtualdevice.flags/intent_interception_action_matching_fix_flag_values.textproto b/aconfig/ap4a/android.companion.virtualdevice.flags/intent_interception_action_matching_fix_flag_values.textproto
new file mode 100644
index 00000000..81ab2e6a
--- /dev/null
+++ b/aconfig/ap4a/android.companion.virtualdevice.flags/intent_interception_action_matching_fix_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.companion.virtualdevice.flags"
+  name: "intent_interception_action_matching_fix"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/android.companion.virtualdevice.flags/metrics_collection_flag_values.textproto b/aconfig/ap4a/android.companion.virtualdevice.flags/metrics_collection_flag_values.textproto
new file mode 100644
index 00000000..ff413d9d
--- /dev/null
+++ b/aconfig/ap4a/android.companion.virtualdevice.flags/metrics_collection_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.companion.virtualdevice.flags"
+  name: "metrics_collection"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/android.companion.virtualdevice.flags/virtual_display_multi_window_mode_support_flag_values.textproto b/aconfig/ap4a/android.companion.virtualdevice.flags/virtual_display_multi_window_mode_support_flag_values.textproto
new file mode 100644
index 00000000..88a72cbf
--- /dev/null
+++ b/aconfig/ap4a/android.companion.virtualdevice.flags/virtual_display_multi_window_mode_support_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.companion.virtualdevice.flags"
+  name: "virtual_display_multi_window_mode_support"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/android.media.soundtrigger/Android.bp b/aconfig/ap4a/android.media.soundtrigger/Android.bp
new file mode 100644
index 00000000..14d0c405
--- /dev/null
+++ b/aconfig/ap4a/android.media.soundtrigger/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-ap4a-android.media.soundtrigger-all",
+  package: "android.media.soundtrigger",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/ap4a/android.media.tv.flags/Android.bp b/aconfig/ap4a/android.media.tv.flags/Android.bp
new file mode 100644
index 00000000..59ec5065
--- /dev/null
+++ b/aconfig/ap4a/android.media.tv.flags/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-ap4a-android.media.tv.flags-all",
+  package: "android.media.tv.flags",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/ap4a/android.net.vcn/allow_disable_ipsec_loss_detector_flag_values.textproto b/aconfig/ap4a/android.net.vcn/allow_disable_ipsec_loss_detector_flag_values.textproto
new file mode 100644
index 00000000..da2ea944
--- /dev/null
+++ b/aconfig/ap4a/android.net.vcn/allow_disable_ipsec_loss_detector_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.net.vcn"
+  name: "allow_disable_ipsec_loss_detector"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/android.os.vibrator/keyboard_category_enabled_flag_values.textproto b/aconfig/ap4a/android.os.vibrator/keyboard_category_enabled_flag_values.textproto
new file mode 100644
index 00000000..9c51ed42
--- /dev/null
+++ b/aconfig/ap4a/android.os.vibrator/keyboard_category_enabled_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.os.vibrator"
+  name: "keyboard_category_enabled"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/android.os.vibrator/use_vibrator_haptic_feedback_flag_values.textproto b/aconfig/ap4a/android.os.vibrator/use_vibrator_haptic_feedback_flag_values.textproto
new file mode 100644
index 00000000..53803180
--- /dev/null
+++ b/aconfig/ap4a/android.os.vibrator/use_vibrator_haptic_feedback_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.os.vibrator"
+  name: "use_vibrator_haptic_feedback"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/android.os/bugreport_mode_max_value_flag_values.textproto b/aconfig/ap4a/android.os/bugreport_mode_max_value_flag_values.textproto
new file mode 100644
index 00000000..ec2b3d95
--- /dev/null
+++ b/aconfig/ap4a/android.os/bugreport_mode_max_value_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.os"
+  name: "bugreport_mode_max_value"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/android.provider.configinfrastructure.framework/Android.bp b/aconfig/ap4a/android.provider.configinfrastructure.framework/Android.bp
new file mode 100644
index 00000000..161af532
--- /dev/null
+++ b/aconfig/ap4a/android.provider.configinfrastructure.framework/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-ap4a-android.provider.configinfrastructure.framework-all",
+  package: "android.provider.configinfrastructure.framework",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/ap4a/android.provider.flags/Android.bp b/aconfig/ap4a/android.provider.flags/Android.bp
new file mode 100644
index 00000000..3eeb2d38
--- /dev/null
+++ b/aconfig/ap4a/android.provider.flags/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-ap4a-android.provider.flags-all",
+  package: "android.provider.flags",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/ap4a/android.sdk/Android.bp b/aconfig/ap4a/android.sdk/Android.bp
new file mode 100644
index 00000000..dd32af16
--- /dev/null
+++ b/aconfig/ap4a/android.sdk/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-ap4a-android.sdk-all",
+  package: "android.sdk",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/ap4a/android.security.keystore2/Android.bp b/aconfig/ap4a/android.security.keystore2/Android.bp
new file mode 100644
index 00000000..b245f5fe
--- /dev/null
+++ b/aconfig/ap4a/android.security.keystore2/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-ap4a-android.security.keystore2-all",
+  package: "android.security.keystore2",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/ap4a/android.security/fix_unlocked_device_required_keys_v2_flag_values.textproto b/aconfig/ap4a/android.security/fix_unlocked_device_required_keys_v2_flag_values.textproto
new file mode 100644
index 00000000..24c6f6d6
--- /dev/null
+++ b/aconfig/ap4a/android.security/fix_unlocked_device_required_keys_v2_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.security"
+  name: "fix_unlocked_device_required_keys_v2"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/android.service.appprediction.flags/Android.bp b/aconfig/ap4a/android.service.appprediction.flags/Android.bp
new file mode 100644
index 00000000..b30c01ce
--- /dev/null
+++ b/aconfig/ap4a/android.service.appprediction.flags/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-ap4a-android.service.appprediction.flags-all",
+  package: "android.service.appprediction.flags",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/ap4a/android.tracing/Android.bp b/aconfig/ap4a/android.tracing/Android.bp
new file mode 100644
index 00000000..8afb7727
--- /dev/null
+++ b/aconfig/ap4a/android.tracing/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-ap4a-android.tracing-all",
+  package: "android.tracing",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/ap4a/com.android.aconfig.flags/Android.bp b/aconfig/ap4a/com.android.aconfig.flags/Android.bp
new file mode 100644
index 00000000..0280a862
--- /dev/null
+++ b/aconfig/ap4a/com.android.aconfig.flags/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-ap4a-com.android.aconfig.flags-all",
+  package: "com.android.aconfig.flags",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/ap4a/com.android.aconfig_new_storage/Android.bp b/aconfig/ap4a/com.android.aconfig_new_storage/Android.bp
new file mode 100644
index 00000000..e483c312
--- /dev/null
+++ b/aconfig/ap4a/com.android.aconfig_new_storage/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-ap4a-com.android.aconfig_new_storage-all",
+  package: "com.android.aconfig_new_storage",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/ap4a/com.android.art.flags/Android.bp b/aconfig/ap4a/com.android.art.flags/Android.bp
new file mode 100644
index 00000000..b448c97a
--- /dev/null
+++ b/aconfig/ap4a/com.android.art.flags/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-ap4a-com.android.art.flags-all",
+  package: "com.android.art.flags",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/btsec_check_valid_discovery_database_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/a2dp_concurrent_source_sink_flag_values.textproto
similarity index 67%
rename from aconfig/ap4a/com.android.bluetooth.flags/btsec_check_valid_discovery_database_flag_values.textproto
rename to aconfig/ap4a/com.android.bluetooth.flags/a2dp_concurrent_source_sink_flag_values.textproto
index c4fab1d1..b3a0c817 100644
--- a/aconfig/ap4a/com.android.bluetooth.flags/btsec_check_valid_discovery_database_flag_values.textproto
+++ b/aconfig/ap4a/com.android.bluetooth.flags/a2dp_concurrent_source_sink_flag_values.textproto
@@ -1,6 +1,6 @@
 flag_value {
   package: "com.android.bluetooth.flags"
-  name: "btsec_check_valid_discovery_database"
+  name: "a2dp_concurrent_source_sink"
   state: ENABLED
   permission: READ_ONLY
 }
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/a2dp_offload_codec_extensibility_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/a2dp_offload_codec_extensibility_flag_values.textproto
new file mode 100644
index 00000000..c6441b1d
--- /dev/null
+++ b/aconfig/ap4a/com.android.bluetooth.flags/a2dp_offload_codec_extensibility_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "a2dp_offload_codec_extensibility"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/airplane_mode_x_ble_on_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/airplane_mode_x_ble_on_flag_values.textproto
new file mode 100644
index 00000000..1cbccf0d
--- /dev/null
+++ b/aconfig/ap4a/com.android.bluetooth.flags/airplane_mode_x_ble_on_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "airplane_mode_x_ble_on"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/reset_after_collision_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/asha_asrc_flag_values.textproto
similarity index 75%
rename from aconfig/ap4a/com.android.bluetooth.flags/reset_after_collision_flag_values.textproto
rename to aconfig/ap4a/com.android.bluetooth.flags/asha_asrc_flag_values.textproto
index 8109a82e..02b91207 100644
--- a/aconfig/ap4a/com.android.bluetooth.flags/reset_after_collision_flag_values.textproto
+++ b/aconfig/ap4a/com.android.bluetooth.flags/asha_asrc_flag_values.textproto
@@ -1,6 +1,6 @@
 flag_value {
   package: "com.android.bluetooth.flags"
-  name: "reset_after_collision"
+  name: "asha_asrc"
   state: ENABLED
   permission: READ_ONLY
 }
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/auto_connect_on_hfp_when_no_a2dp_device_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/auto_connect_on_hfp_when_no_a2dp_device_flag_values.textproto
new file mode 100644
index 00000000..ceb2afac
--- /dev/null
+++ b/aconfig/ap4a/com.android.bluetooth.flags/auto_connect_on_hfp_when_no_a2dp_device_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "auto_connect_on_hfp_when_no_a2dp_device"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/auto_on_feature_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/auto_on_feature_flag_values.textproto
new file mode 100644
index 00000000..562075c3
--- /dev/null
+++ b/aconfig/ap4a/com.android.bluetooth.flags/auto_on_feature_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "auto_on_feature"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/bluffs_mitigation_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/bluffs_mitigation_flag_values.textproto
new file mode 100644
index 00000000..31b47771
--- /dev/null
+++ b/aconfig/ap4a/com.android.bluetooth.flags/bluffs_mitigation_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "bluffs_mitigation"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/bta_dm_disc_stuck_in_cancelling_fix_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/bta_dm_disc_stuck_in_cancelling_fix_flag_values.textproto
new file mode 100644
index 00000000..7ca6c506
--- /dev/null
+++ b/aconfig/ap4a/com.android.bluetooth.flags/bta_dm_disc_stuck_in_cancelling_fix_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "bta_dm_disc_stuck_in_cancelling_fix"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/close_rfcomm_instead_of_reset_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/close_rfcomm_instead_of_reset_flag_values.textproto
new file mode 100644
index 00000000..0ad7900f
--- /dev/null
+++ b/aconfig/ap4a/com.android.bluetooth.flags/close_rfcomm_instead_of_reset_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "close_rfcomm_instead_of_reset"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/connect_hid_after_service_discovery_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/connect_hid_after_service_discovery_flag_values.textproto
new file mode 100644
index 00000000..42926ae3
--- /dev/null
+++ b/aconfig/ap4a/com.android.bluetooth.flags/connect_hid_after_service_discovery_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "connect_hid_after_service_discovery"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/correct_bond_type_of_loaded_devices_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/correct_bond_type_of_loaded_devices_flag_values.textproto
new file mode 100644
index 00000000..f5e92c12
--- /dev/null
+++ b/aconfig/ap4a/com.android.bluetooth.flags/correct_bond_type_of_loaded_devices_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "correct_bond_type_of_loaded_devices"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/delay_bonding_when_busy_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/delay_bonding_when_busy_flag_values.textproto
new file mode 100644
index 00000000..7fbfd3d0
--- /dev/null
+++ b/aconfig/ap4a/com.android.bluetooth.flags/delay_bonding_when_busy_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "delay_bonding_when_busy"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/divide_long_single_gap_data_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/divide_long_single_gap_data_flag_values.textproto
new file mode 100644
index 00000000..4e6e5860
--- /dev/null
+++ b/aconfig/ap4a/com.android.bluetooth.flags/divide_long_single_gap_data_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "divide_long_single_gap_data"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/do_not_replace_existing_cod_with_uncategorized_cod_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/do_not_replace_existing_cod_with_uncategorized_cod_flag_values.textproto
new file mode 100644
index 00000000..4dc106ca
--- /dev/null
+++ b/aconfig/ap4a/com.android.bluetooth.flags/do_not_replace_existing_cod_with_uncategorized_cod_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "do_not_replace_existing_cod_with_uncategorized_cod"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/dumpsys_acquire_stack_when_executing_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/dumpsys_acquire_stack_when_executing_flag_values.textproto
new file mode 100644
index 00000000..cacd7160
--- /dev/null
+++ b/aconfig/ap4a/com.android.bluetooth.flags/dumpsys_acquire_stack_when_executing_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "dumpsys_acquire_stack_when_executing"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/dumpsys_use_passed_in_fd_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/dumpsys_use_passed_in_fd_flag_values.textproto
new file mode 100644
index 00000000..3617ee05
--- /dev/null
+++ b/aconfig/ap4a/com.android.bluetooth.flags/dumpsys_use_passed_in_fd_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "dumpsys_use_passed_in_fd"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/ensure_valid_adv_flag_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/ensure_valid_adv_flag_flag_values.textproto
new file mode 100644
index 00000000..13c82dac
--- /dev/null
+++ b/aconfig/ap4a/com.android.bluetooth.flags/ensure_valid_adv_flag_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "ensure_valid_adv_flag"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/explicit_kill_from_system_server_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/explicit_kill_from_system_server_flag_values.textproto
new file mode 100644
index 00000000..5f10fdae
--- /dev/null
+++ b/aconfig/ap4a/com.android.bluetooth.flags/explicit_kill_from_system_server_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "explicit_kill_from_system_server"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/fix_le_oob_pairing_bypass_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/fix_le_oob_pairing_bypass_flag_values.textproto
new file mode 100644
index 00000000..bd59a55a
--- /dev/null
+++ b/aconfig/ap4a/com.android.bluetooth.flags/fix_le_oob_pairing_bypass_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "fix_le_oob_pairing_bypass"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/fix_le_pairing_passkey_entry_bypass_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/fix_le_pairing_passkey_entry_bypass_flag_values.textproto
new file mode 100644
index 00000000..dff4dac6
--- /dev/null
+++ b/aconfig/ap4a/com.android.bluetooth.flags/fix_le_pairing_passkey_entry_bypass_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "fix_le_pairing_passkey_entry_bypass"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/fix_pairing_failure_reason_from_remote_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/fix_pairing_failure_reason_from_remote_flag_values.textproto
new file mode 100644
index 00000000..79339209
--- /dev/null
+++ b/aconfig/ap4a/com.android.bluetooth.flags/fix_pairing_failure_reason_from_remote_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "fix_pairing_failure_reason_from_remote"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/force_bredr_for_sdp_retry_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/force_bredr_for_sdp_retry_flag_values.textproto
new file mode 100644
index 00000000..597790fb
--- /dev/null
+++ b/aconfig/ap4a/com.android.bluetooth.flags/force_bredr_for_sdp_retry_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "force_bredr_for_sdp_retry"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/gatt_drop_acl_on_out_of_resources_fix_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/gatt_drop_acl_on_out_of_resources_fix_flag_values.textproto
new file mode 100644
index 00000000..a0e7e90a
--- /dev/null
+++ b/aconfig/ap4a/com.android.bluetooth.flags/gatt_drop_acl_on_out_of_resources_fix_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "gatt_drop_acl_on_out_of_resources_fix"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/gatt_reconnect_on_bt_on_fix_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/gatt_reconnect_on_bt_on_fix_flag_values.textproto
new file mode 100644
index 00000000..b1955ddc
--- /dev/null
+++ b/aconfig/ap4a/com.android.bluetooth.flags/gatt_reconnect_on_bt_on_fix_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "gatt_reconnect_on_bt_on_fix"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/get_address_type_api_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/get_address_type_api_flag_values.textproto
new file mode 100644
index 00000000..45a38177
--- /dev/null
+++ b/aconfig/ap4a/com.android.bluetooth.flags/get_address_type_api_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "get_address_type_api"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/hfp_codec_aptx_voice_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/hfp_codec_aptx_voice_flag_values.textproto
new file mode 100644
index 00000000..d0432b0a
--- /dev/null
+++ b/aconfig/ap4a/com.android.bluetooth.flags/hfp_codec_aptx_voice_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "hfp_codec_aptx_voice"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/ignore_bond_type_for_le_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/ignore_bond_type_for_le_flag_values.textproto
new file mode 100644
index 00000000..d02c6895
--- /dev/null
+++ b/aconfig/ap4a/com.android.bluetooth.flags/ignore_bond_type_for_le_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "ignore_bond_type_for_le"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/keep_hfp_active_during_leaudio_handover_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/keep_hfp_active_during_leaudio_handover_flag_values.textproto
new file mode 100644
index 00000000..a36c842d
--- /dev/null
+++ b/aconfig/ap4a/com.android.bluetooth.flags/keep_hfp_active_during_leaudio_handover_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "keep_hfp_active_during_leaudio_handover"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/keep_stopped_media_browser_service_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/keep_stopped_media_browser_service_flag_values.textproto
new file mode 100644
index 00000000..51c63f18
--- /dev/null
+++ b/aconfig/ap4a/com.android.bluetooth.flags/keep_stopped_media_browser_service_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "keep_stopped_media_browser_service"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/le_audio_dev_type_detection_fix_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/le_audio_dev_type_detection_fix_flag_values.textproto
new file mode 100644
index 00000000..68dc062d
--- /dev/null
+++ b/aconfig/ap4a/com.android.bluetooth.flags/le_audio_dev_type_detection_fix_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "le_audio_dev_type_detection_fix"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/le_audio_fast_bond_params_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/le_audio_fast_bond_params_flag_values.textproto
new file mode 100644
index 00000000..33f29913
--- /dev/null
+++ b/aconfig/ap4a/com.android.bluetooth.flags/le_audio_fast_bond_params_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "le_audio_fast_bond_params"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/le_periodic_scanning_reassembler_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/le_periodic_scanning_reassembler_flag_values.textproto
new file mode 100644
index 00000000..d2e12d42
--- /dev/null
+++ b/aconfig/ap4a/com.android.bluetooth.flags/le_periodic_scanning_reassembler_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "le_periodic_scanning_reassembler"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/le_scan_parameters_fix_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/le_scan_parameters_fix_flag_values.textproto
new file mode 100644
index 00000000..b8057b2d
--- /dev/null
+++ b/aconfig/ap4a/com.android.bluetooth.flags/le_scan_parameters_fix_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "le_scan_parameters_fix"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/leaudio_active_device_manager_group_handling_fix_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/leaudio_active_device_manager_group_handling_fix_flag_values.textproto
new file mode 100644
index 00000000..a126b4e9
--- /dev/null
+++ b/aconfig/ap4a/com.android.bluetooth.flags/leaudio_active_device_manager_group_handling_fix_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "leaudio_active_device_manager_group_handling_fix"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/leaudio_add_sampling_frequencies_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/leaudio_add_sampling_frequencies_flag_values.textproto
new file mode 100644
index 00000000..5745147d
--- /dev/null
+++ b/aconfig/ap4a/com.android.bluetooth.flags/leaudio_add_sampling_frequencies_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "leaudio_add_sampling_frequencies"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/leaudio_api_synchronized_block_fix_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/leaudio_api_synchronized_block_fix_flag_values.textproto
new file mode 100644
index 00000000..dc718910
--- /dev/null
+++ b/aconfig/ap4a/com.android.bluetooth.flags/leaudio_api_synchronized_block_fix_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "leaudio_api_synchronized_block_fix"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/leaudio_broadcast_assistant_handle_command_statuses_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/leaudio_broadcast_assistant_handle_command_statuses_flag_values.textproto
new file mode 100644
index 00000000..4978d05f
--- /dev/null
+++ b/aconfig/ap4a/com.android.bluetooth.flags/leaudio_broadcast_assistant_handle_command_statuses_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "leaudio_broadcast_assistant_handle_command_statuses"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/leaudio_callback_on_group_stream_status_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/leaudio_callback_on_group_stream_status_flag_values.textproto
new file mode 100644
index 00000000..c7252176
--- /dev/null
+++ b/aconfig/ap4a/com.android.bluetooth.flags/leaudio_callback_on_group_stream_status_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "leaudio_callback_on_group_stream_status"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/leaudio_enable_health_based_actions_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/leaudio_enable_health_based_actions_flag_values.textproto
new file mode 100644
index 00000000..6a795284
--- /dev/null
+++ b/aconfig/ap4a/com.android.bluetooth.flags/leaudio_enable_health_based_actions_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "leaudio_enable_health_based_actions"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/leaudio_mcs_tbs_authorization_rebond_fix_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/leaudio_mcs_tbs_authorization_rebond_fix_flag_values.textproto
new file mode 100644
index 00000000..49c48c78
--- /dev/null
+++ b/aconfig/ap4a/com.android.bluetooth.flags/leaudio_mcs_tbs_authorization_rebond_fix_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "leaudio_mcs_tbs_authorization_rebond_fix"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/leaudio_quick_leaudio_toggle_switch_fix_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/leaudio_quick_leaudio_toggle_switch_fix_flag_values.textproto
new file mode 100644
index 00000000..c332319d
--- /dev/null
+++ b/aconfig/ap4a/com.android.bluetooth.flags/leaudio_quick_leaudio_toggle_switch_fix_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "leaudio_quick_leaudio_toggle_switch_fix"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/leaudio_resume_active_after_hfp_handover_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/leaudio_resume_active_after_hfp_handover_flag_values.textproto
new file mode 100644
index 00000000..3a8ef518
--- /dev/null
+++ b/aconfig/ap4a/com.android.bluetooth.flags/leaudio_resume_active_after_hfp_handover_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "leaudio_resume_active_after_hfp_handover"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/leaudio_start_stream_race_fix_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/leaudio_start_stream_race_fix_flag_values.textproto
new file mode 100644
index 00000000..9ec54b3b
--- /dev/null
+++ b/aconfig/ap4a/com.android.bluetooth.flags/leaudio_start_stream_race_fix_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "leaudio_start_stream_race_fix"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/leaudio_unicast_inactivate_device_based_on_context_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/leaudio_unicast_inactivate_device_based_on_context_flag_values.textproto
new file mode 100644
index 00000000..044dde18
--- /dev/null
+++ b/aconfig/ap4a/com.android.bluetooth.flags/leaudio_unicast_inactivate_device_based_on_context_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "leaudio_unicast_inactivate_device_based_on_context"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/leaudio_volume_change_on_ringtone_fix_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/leaudio_volume_change_on_ringtone_fix_flag_values.textproto
new file mode 100644
index 00000000..df5df590
--- /dev/null
+++ b/aconfig/ap4a/com.android.bluetooth.flags/leaudio_volume_change_on_ringtone_fix_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "leaudio_volume_change_on_ringtone_fix"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/load_did_config_from_sysprops_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/load_did_config_from_sysprops_flag_values.textproto
new file mode 100644
index 00000000..76ccde4a
--- /dev/null
+++ b/aconfig/ap4a/com.android.bluetooth.flags/load_did_config_from_sysprops_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "load_did_config_from_sysprops"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/mfi_has_uuid_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/mfi_has_uuid_flag_values.textproto
new file mode 100644
index 00000000..e574bfb5
--- /dev/null
+++ b/aconfig/ap4a/com.android.bluetooth.flags/mfi_has_uuid_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "mfi_has_uuid"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/pretend_network_service_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/pretend_network_service_flag_values.textproto
new file mode 100644
index 00000000..b6392a8d
--- /dev/null
+++ b/aconfig/ap4a/com.android.bluetooth.flags/pretend_network_service_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "pretend_network_service"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/read_model_num_fix_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/read_model_num_fix_flag_values.textproto
new file mode 100644
index 00000000..1bcb0ae0
--- /dev/null
+++ b/aconfig/ap4a/com.android.bluetooth.flags/read_model_num_fix_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "read_model_num_fix"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/report_vsc_data_from_the_gd_controller_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/report_vsc_data_from_the_gd_controller_flag_values.textproto
new file mode 100644
index 00000000..85f9aa02
--- /dev/null
+++ b/aconfig/ap4a/com.android.bluetooth.flags/report_vsc_data_from_the_gd_controller_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "report_vsc_data_from_the_gd_controller"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/reset_pairing_only_for_related_service_discovery_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/reset_pairing_only_for_related_service_discovery_flag_values.textproto
new file mode 100644
index 00000000..7e93475f
--- /dev/null
+++ b/aconfig/ap4a/com.android.bluetooth.flags/reset_pairing_only_for_related_service_discovery_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "reset_pairing_only_for_related_service_discovery"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/rnr_cancel_before_event_race_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/rnr_cancel_before_event_race_flag_values.textproto
new file mode 100644
index 00000000..b440e9d5
--- /dev/null
+++ b/aconfig/ap4a/com.android.bluetooth.flags/rnr_cancel_before_event_race_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "rnr_cancel_before_event_race"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/rnr_present_during_service_discovery_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/rnr_present_during_service_discovery_flag_values.textproto
new file mode 100644
index 00000000..c89b1b7d
--- /dev/null
+++ b/aconfig/ap4a/com.android.bluetooth.flags/rnr_present_during_service_discovery_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "rnr_present_during_service_discovery"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/rnr_reset_state_at_cancel_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/rnr_reset_state_at_cancel_flag_values.textproto
new file mode 100644
index 00000000..ddfe5ba6
--- /dev/null
+++ b/aconfig/ap4a/com.android.bluetooth.flags/rnr_reset_state_at_cancel_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "rnr_reset_state_at_cancel"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/separate_service_and_device_discovery_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/separate_service_and_device_discovery_flag_values.textproto
new file mode 100644
index 00000000..f1b89771
--- /dev/null
+++ b/aconfig/ap4a/com.android.bluetooth.flags/separate_service_and_device_discovery_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "separate_service_and_device_discovery"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/synchronous_bta_sec_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/synchronous_bta_sec_flag_values.textproto
new file mode 100644
index 00000000..8482d343
--- /dev/null
+++ b/aconfig/ap4a/com.android.bluetooth.flags/synchronous_bta_sec_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "synchronous_bta_sec"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/update_inquiry_result_on_flag_change_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/update_inquiry_result_on_flag_change_flag_values.textproto
new file mode 100644
index 00000000..6cf44219
--- /dev/null
+++ b/aconfig/ap4a/com.android.bluetooth.flags/update_inquiry_result_on_flag_change_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "update_inquiry_result_on_flag_change"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.bluetooth.flags/use_dsp_codec_when_controller_does_not_support_flag_values.textproto b/aconfig/ap4a/com.android.bluetooth.flags/use_dsp_codec_when_controller_does_not_support_flag_values.textproto
new file mode 100644
index 00000000..9557c22d
--- /dev/null
+++ b/aconfig/ap4a/com.android.bluetooth.flags/use_dsp_codec_when_controller_does_not_support_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "use_dsp_codec_when_controller_does_not_support"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.cellbroadcastreceiver.flags/Android.bp b/aconfig/ap4a/com.android.cellbroadcastreceiver.flags/Android.bp
new file mode 100644
index 00000000..e1a51345
--- /dev/null
+++ b/aconfig/ap4a/com.android.cellbroadcastreceiver.flags/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-ap4a-com.android.cellbroadcastreceiver.flags-all",
+  package: "com.android.cellbroadcastreceiver.flags",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/ap4a/com.android.devicelock.flags/Android.bp b/aconfig/ap4a/com.android.devicelock.flags/Android.bp
new file mode 100644
index 00000000..3b8b72c1
--- /dev/null
+++ b/aconfig/ap4a/com.android.devicelock.flags/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-ap4a-com.android.devicelock.flags-all",
+  package: "com.android.devicelock.flags",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/ap4a/com.android.graphics.bufferstreams.flags/Android.bp b/aconfig/ap4a/com.android.graphics.bufferstreams.flags/Android.bp
new file mode 100644
index 00000000..cd0aefbd
--- /dev/null
+++ b/aconfig/ap4a/com.android.graphics.bufferstreams.flags/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-ap4a-com.android.graphics.bufferstreams.flags-all",
+  package: "com.android.graphics.bufferstreams.flags",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/ap4a/com.android.graphics.flags/Android.bp b/aconfig/ap4a/com.android.graphics.flags/Android.bp
new file mode 100644
index 00000000..82ba6327
--- /dev/null
+++ b/aconfig/ap4a/com.android.graphics.flags/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-ap4a-com.android.graphics.flags-all",
+  package: "com.android.graphics.flags",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/ap4a/com.android.graphics.libvulkan.flags/Android.bp b/aconfig/ap4a/com.android.graphics.libvulkan.flags/Android.bp
new file mode 100644
index 00000000..43b3d575
--- /dev/null
+++ b/aconfig/ap4a/com.android.graphics.libvulkan.flags/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-ap4a-com.android.graphics.libvulkan.flags-all",
+  package: "com.android.graphics.libvulkan.flags",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/ap4a/com.android.hardware.camera2/Android.bp b/aconfig/ap4a/com.android.hardware.camera2/Android.bp
new file mode 100644
index 00000000..c02f3393
--- /dev/null
+++ b/aconfig/ap4a/com.android.hardware.camera2/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-ap4a-com.android.hardware.camera2-all",
+  package: "com.android.hardware.camera2",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/ap4a/com.android.healthfitness.flags/Android.bp b/aconfig/ap4a/com.android.healthfitness.flags/Android.bp
new file mode 100644
index 00000000..2697f96d
--- /dev/null
+++ b/aconfig/ap4a/com.android.healthfitness.flags/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-ap4a-com.android.healthfitness.flags-all",
+  package: "com.android.healthfitness.flags",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/ap4a/com.android.input.flags/enable_gestures_library_timer_provider_flag_values.textproto b/aconfig/ap4a/com.android.input.flags/enable_gestures_library_timer_provider_flag_values.textproto
new file mode 100644
index 00000000..a5177143
--- /dev/null
+++ b/aconfig/ap4a/com.android.input.flags/enable_gestures_library_timer_provider_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.input.flags"
+  name: "enable_gestures_library_timer_provider"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.input.flags/remove_pointer_event_tracking_in_wm_flag_values.textproto b/aconfig/ap4a/com.android.input.flags/remove_pointer_event_tracking_in_wm_flag_values.textproto
new file mode 100644
index 00000000..c0576623
--- /dev/null
+++ b/aconfig/ap4a/com.android.input.flags/remove_pointer_event_tracking_in_wm_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.input.flags"
+  name: "remove_pointer_event_tracking_in_wm"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.intentresolver/bespoke_label_view_flag_values.textproto b/aconfig/ap4a/com.android.intentresolver/bespoke_label_view_flag_values.textproto
new file mode 100644
index 00000000..2d584098
--- /dev/null
+++ b/aconfig/ap4a/com.android.intentresolver/bespoke_label_view_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.intentresolver"
+  name: "bespoke_label_view"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.intentresolver/fix_partial_image_edit_transition_flag_values.textproto b/aconfig/ap4a/com.android.intentresolver/fix_partial_image_edit_transition_flag_values.textproto
new file mode 100644
index 00000000..5560bfbe
--- /dev/null
+++ b/aconfig/ap4a/com.android.intentresolver/fix_partial_image_edit_transition_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.intentresolver"
+  name: "fix_partial_image_edit_transition"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.intentresolver/fix_target_list_footer_flag_values.textproto b/aconfig/ap4a/com.android.intentresolver/fix_target_list_footer_flag_values.textproto
new file mode 100644
index 00000000..10e856bc
--- /dev/null
+++ b/aconfig/ap4a/com.android.intentresolver/fix_target_list_footer_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.intentresolver"
+  name: "fix_target_list_footer"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.internal.camera.flags/lazy_aidl_wait_for_service_flag_values.textproto b/aconfig/ap4a/com.android.internal.camera.flags/lazy_aidl_wait_for_service_flag_values.textproto
new file mode 100644
index 00000000..eafc30b8
--- /dev/null
+++ b/aconfig/ap4a/com.android.internal.camera.flags/lazy_aidl_wait_for_service_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.internal.camera.flags"
+  name: "lazy_aidl_wait_for_service"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.internal.camera.flags/log_ultrawide_usage_flag_values.textproto b/aconfig/ap4a/com.android.internal.camera.flags/log_ultrawide_usage_flag_values.textproto
new file mode 100644
index 00000000..2b154426
--- /dev/null
+++ b/aconfig/ap4a/com.android.internal.camera.flags/log_ultrawide_usage_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.internal.camera.flags"
+  name: "log_ultrawide_usage"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.internal.camera.flags/log_zoom_override_usage_flag_values.textproto b/aconfig/ap4a/com.android.internal.camera.flags/log_zoom_override_usage_flag_values.textproto
new file mode 100644
index 00000000..ca4a9c8a
--- /dev/null
+++ b/aconfig/ap4a/com.android.internal.camera.flags/log_zoom_override_usage_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.internal.camera.flags"
+  name: "log_zoom_override_usage"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.internal.camera.flags/realtime_priority_bump_flag_values.textproto b/aconfig/ap4a/com.android.internal.camera.flags/realtime_priority_bump_flag_values.textproto
new file mode 100644
index 00000000..d5f82fdb
--- /dev/null
+++ b/aconfig/ap4a/com.android.internal.camera.flags/realtime_priority_bump_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.internal.camera.flags"
+  name: "realtime_priority_bump"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.internal.camera.flags/single_thread_executor_flag_values.textproto b/aconfig/ap4a/com.android.internal.camera.flags/single_thread_executor_flag_values.textproto
new file mode 100644
index 00000000..e02e144c
--- /dev/null
+++ b/aconfig/ap4a/com.android.internal.camera.flags/single_thread_executor_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.internal.camera.flags"
+  name: "single_thread_executor"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.internal.camera.flags/surface_ipc_flag_values.textproto b/aconfig/ap4a/com.android.internal.camera.flags/surface_ipc_flag_values.textproto
new file mode 100644
index 00000000..e721feb9
--- /dev/null
+++ b/aconfig/ap4a/com.android.internal.camera.flags/surface_ipc_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.internal.camera.flags"
+  name: "surface_ipc"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.internal.camera.flags/surface_leak_fix_flag_values.textproto b/aconfig/ap4a/com.android.internal.camera.flags/surface_leak_fix_flag_values.textproto
new file mode 100644
index 00000000..09166fda
--- /dev/null
+++ b/aconfig/ap4a/com.android.internal.camera.flags/surface_leak_fix_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.internal.camera.flags"
+  name: "surface_leak_fix"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.internal.camera.flags/watch_foreground_changes_flag_values.textproto b/aconfig/ap4a/com.android.internal.camera.flags/watch_foreground_changes_flag_values.textproto
new file mode 100644
index 00000000..71d833c5
--- /dev/null
+++ b/aconfig/ap4a/com.android.internal.camera.flags/watch_foreground_changes_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.internal.camera.flags"
+  name: "watch_foreground_changes"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.internal.jank/Android.bp b/aconfig/ap4a/com.android.internal.jank/Android.bp
new file mode 100644
index 00000000..10094958
--- /dev/null
+++ b/aconfig/ap4a/com.android.internal.jank/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-ap4a-com.android.internal.jank-all",
+  package: "com.android.internal.jank",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/ap4a/com.android.internal.telephony.flags/add_anomaly_when_notify_config_changed_with_invalid_phone_flag_values.textproto b/aconfig/ap4a/com.android.internal.telephony.flags/add_anomaly_when_notify_config_changed_with_invalid_phone_flag_values.textproto
new file mode 100644
index 00000000..8bfdfa99
--- /dev/null
+++ b/aconfig/ap4a/com.android.internal.telephony.flags/add_anomaly_when_notify_config_changed_with_invalid_phone_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.internal.telephony.flags"
+  name: "add_anomaly_when_notify_config_changed_with_invalid_phone"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.internal.telephony.flags/allow_mmtel_in_non_vops_flag_values.textproto b/aconfig/ap4a/com.android.internal.telephony.flags/allow_mmtel_in_non_vops_flag_values.textproto
new file mode 100644
index 00000000..79514414
--- /dev/null
+++ b/aconfig/ap4a/com.android.internal.telephony.flags/allow_mmtel_in_non_vops_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.internal.telephony.flags"
+  name: "allow_mmtel_in_non_vops"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.internal.telephony.flags/cleanup_open_logical_channel_record_on_dispose_flag_values.textproto b/aconfig/ap4a/com.android.internal.telephony.flags/cleanup_open_logical_channel_record_on_dispose_flag_values.textproto
new file mode 100644
index 00000000..84c39870
--- /dev/null
+++ b/aconfig/ap4a/com.android.internal.telephony.flags/cleanup_open_logical_channel_record_on_dispose_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.internal.telephony.flags"
+  name: "cleanup_open_logical_channel_record_on_dispose"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.internal.telephony.flags/data_only_service_allow_emergency_call_only_flag_values.textproto b/aconfig/ap4a/com.android.internal.telephony.flags/data_only_service_allow_emergency_call_only_flag_values.textproto
new file mode 100644
index 00000000..9ddecbb2
--- /dev/null
+++ b/aconfig/ap4a/com.android.internal.telephony.flags/data_only_service_allow_emergency_call_only_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.internal.telephony.flags"
+  name: "data_only_service_allow_emergency_call_only"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.internal.telephony.flags/fix_crash_on_getting_config_when_phone_is_gone_flag_values.textproto b/aconfig/ap4a/com.android.internal.telephony.flags/fix_crash_on_getting_config_when_phone_is_gone_flag_values.textproto
new file mode 100644
index 00000000..2a3ec157
--- /dev/null
+++ b/aconfig/ap4a/com.android.internal.telephony.flags/fix_crash_on_getting_config_when_phone_is_gone_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.internal.telephony.flags"
+  name: "fix_crash_on_getting_config_when_phone_is_gone"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.internal.telephony.flags/force_iwlan_mms_flag_values.textproto b/aconfig/ap4a/com.android.internal.telephony.flags/force_iwlan_mms_flag_values.textproto
new file mode 100644
index 00000000..e6a7cba5
--- /dev/null
+++ b/aconfig/ap4a/com.android.internal.telephony.flags/force_iwlan_mms_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.internal.telephony.flags"
+  name: "force_iwlan_mms"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.internal.telephony.flags/hide_preinstalled_carrier_app_at_most_once_flag_values.textproto b/aconfig/ap4a/com.android.internal.telephony.flags/hide_preinstalled_carrier_app_at_most_once_flag_values.textproto
new file mode 100644
index 00000000..2bc156f4
--- /dev/null
+++ b/aconfig/ap4a/com.android.internal.telephony.flags/hide_preinstalled_carrier_app_at_most_once_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.internal.telephony.flags"
+  name: "hide_preinstalled_carrier_app_at_most_once"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.internal.telephony.flags/ignore_existing_networks_for_internet_allowed_checking_flag_values.textproto b/aconfig/ap4a/com.android.internal.telephony.flags/ignore_existing_networks_for_internet_allowed_checking_flag_values.textproto
new file mode 100644
index 00000000..6c22a014
--- /dev/null
+++ b/aconfig/ap4a/com.android.internal.telephony.flags/ignore_existing_networks_for_internet_allowed_checking_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.internal.telephony.flags"
+  name: "ignore_existing_networks_for_internet_allowed_checking"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.internal.telephony.flags/metered_embb_urlcc_flag_values.textproto b/aconfig/ap4a/com.android.internal.telephony.flags/metered_embb_urlcc_flag_values.textproto
new file mode 100644
index 00000000..287b4f3a
--- /dev/null
+++ b/aconfig/ap4a/com.android.internal.telephony.flags/metered_embb_urlcc_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.internal.telephony.flags"
+  name: "metered_embb_urlcc"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.internal.telephony.flags/notify_data_activity_changed_with_slot_flag_values.textproto b/aconfig/ap4a/com.android.internal.telephony.flags/notify_data_activity_changed_with_slot_flag_values.textproto
new file mode 100644
index 00000000..be540f81
--- /dev/null
+++ b/aconfig/ap4a/com.android.internal.telephony.flags/notify_data_activity_changed_with_slot_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.internal.telephony.flags"
+  name: "notify_data_activity_changed_with_slot"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.internal.telephony.flags/refine_preferred_data_profile_selection_flag_values.textproto b/aconfig/ap4a/com.android.internal.telephony.flags/refine_preferred_data_profile_selection_flag_values.textproto
new file mode 100644
index 00000000..7d6f36e6
--- /dev/null
+++ b/aconfig/ap4a/com.android.internal.telephony.flags/refine_preferred_data_profile_selection_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.internal.telephony.flags"
+  name: "refine_preferred_data_profile_selection"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.internal.telephony.flags/relax_ho_teardown_flag_values.textproto b/aconfig/ap4a/com.android.internal.telephony.flags/relax_ho_teardown_flag_values.textproto
new file mode 100644
index 00000000..428461ce
--- /dev/null
+++ b/aconfig/ap4a/com.android.internal.telephony.flags/relax_ho_teardown_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.internal.telephony.flags"
+  name: "relax_ho_teardown"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.internal.telephony.flags/support_phone_uid_check_for_multiuser_flag_values.textproto b/aconfig/ap4a/com.android.internal.telephony.flags/support_phone_uid_check_for_multiuser_flag_values.textproto
new file mode 100644
index 00000000..b3552d92
--- /dev/null
+++ b/aconfig/ap4a/com.android.internal.telephony.flags/support_phone_uid_check_for_multiuser_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.internal.telephony.flags"
+  name: "support_phone_uid_check_for_multiuser"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.internal.telephony.flags/unthrottle_check_transport_flag_values.textproto b/aconfig/ap4a/com.android.internal.telephony.flags/unthrottle_check_transport_flag_values.textproto
new file mode 100644
index 00000000..0fe31c80
--- /dev/null
+++ b/aconfig/ap4a/com.android.internal.telephony.flags/unthrottle_check_transport_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.internal.telephony.flags"
+  name: "unthrottle_check_transport"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.internal.telephony.flags/use_alarm_callback_flag_values.textproto b/aconfig/ap4a/com.android.internal.telephony.flags/use_alarm_callback_flag_values.textproto
new file mode 100644
index 00000000..d372cf6c
--- /dev/null
+++ b/aconfig/ap4a/com.android.internal.telephony.flags/use_alarm_callback_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.internal.telephony.flags"
+  name: "use_alarm_callback"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.managedprovisioning.flags/Android.bp b/aconfig/ap4a/com.android.managedprovisioning.flags/Android.bp
new file mode 100644
index 00000000..c2efa3f3
--- /dev/null
+++ b/aconfig/ap4a/com.android.managedprovisioning.flags/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-ap4a-com.android.managedprovisioning.flags-all",
+  package: "com.android.managedprovisioning.flags",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/ap4a/com.android.media.audioclient/Android.bp b/aconfig/ap4a/com.android.media.audioclient/Android.bp
new file mode 100644
index 00000000..6811512a
--- /dev/null
+++ b/aconfig/ap4a/com.android.media.audioclient/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-ap4a-com.android.media.audioclient-all",
+  package: "com.android.media.audioclient",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/ap4a/com.android.media.projection.flags/Android.bp b/aconfig/ap4a/com.android.media.projection.flags/Android.bp
new file mode 100644
index 00000000..1801e112
--- /dev/null
+++ b/aconfig/ap4a/com.android.media.projection.flags/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-ap4a-com.android.media.projection.flags-all",
+  package: "com.android.media.projection.flags",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/ap4a/com.android.net.ct.flags/Android.bp b/aconfig/ap4a/com.android.net.ct.flags/Android.bp
new file mode 100644
index 00000000..588be0c8
--- /dev/null
+++ b/aconfig/ap4a/com.android.net.ct.flags/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-ap4a-com.android.net.ct.flags-all",
+  package: "com.android.net.ct.flags",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/ap4a/com.android.net.thread.platform.flags/Android.bp b/aconfig/ap4a/com.android.net.thread.platform.flags/Android.bp
new file mode 100644
index 00000000..b59a4d64
--- /dev/null
+++ b/aconfig/ap4a/com.android.net.thread.platform.flags/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-ap4a-com.android.net.thread.platform.flags-all",
+  package: "com.android.net.thread.platform.flags",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/ap4a/com.android.nfc.nci.flags/Android.bp b/aconfig/ap4a/com.android.nfc.nci.flags/Android.bp
new file mode 100644
index 00000000..a1906661
--- /dev/null
+++ b/aconfig/ap4a/com.android.nfc.nci.flags/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-ap4a-com.android.nfc.nci.flags-all",
+  package: "com.android.nfc.nci.flags",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/ap4a/com.android.org.conscrypt/Android.bp b/aconfig/ap4a/com.android.org.conscrypt/Android.bp
new file mode 100644
index 00000000..7823a89f
--- /dev/null
+++ b/aconfig/ap4a/com.android.org.conscrypt/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-ap4a-com.android.org.conscrypt-all",
+  package: "com.android.org.conscrypt",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/ap4a/com.android.os.statsd.flags/Android.bp b/aconfig/ap4a/com.android.os.statsd.flags/Android.bp
new file mode 100644
index 00000000..a585bd4c
--- /dev/null
+++ b/aconfig/ap4a/com.android.os.statsd.flags/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-ap4a-com.android.os.statsd.flags-all",
+  package: "com.android.os.statsd.flags",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/ap4a/com.android.providers.contacts.flags/Android.bp b/aconfig/ap4a/com.android.providers.contacts.flags/Android.bp
new file mode 100644
index 00000000..6a6c8fd0
--- /dev/null
+++ b/aconfig/ap4a/com.android.providers.contacts.flags/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-ap4a-com.android.providers.contacts.flags-all",
+  package: "com.android.providers.contacts.flags",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/ap4a/com.android.server.companion.virtual/Android.bp b/aconfig/ap4a/com.android.server.companion.virtual/Android.bp
new file mode 100644
index 00000000..af1718c7
--- /dev/null
+++ b/aconfig/ap4a/com.android.server.companion.virtual/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-ap4a-com.android.server.companion.virtual-all",
+  package: "com.android.server.companion.virtual",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/ap4a/com.android.server.companion.virtual/dump_history_flag_values.textproto b/aconfig/ap4a/com.android.server.companion.virtual/dump_history_flag_values.textproto
new file mode 100644
index 00000000..ddcb135d
--- /dev/null
+++ b/aconfig/ap4a/com.android.server.companion.virtual/dump_history_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.server.companion.virtual"
+  name: "dump_history"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.server.connectivity/Android.bp b/aconfig/ap4a/com.android.server.connectivity/Android.bp
new file mode 100644
index 00000000..6a8e22dc
--- /dev/null
+++ b/aconfig/ap4a/com.android.server.connectivity/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-ap4a-com.android.server.connectivity-all",
+  package: "com.android.server.connectivity",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/ap4a/com.android.server.contextualsearch.flags/Android.bp b/aconfig/ap4a/com.android.server.contextualsearch.flags/Android.bp
new file mode 100644
index 00000000..bc830d0e
--- /dev/null
+++ b/aconfig/ap4a/com.android.server.contextualsearch.flags/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-ap4a-com.android.server.contextualsearch.flags-all",
+  package: "com.android.server.contextualsearch.flags",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/ap4a/com.android.server.devicepolicy.flags/Android.bp b/aconfig/ap4a/com.android.server.devicepolicy.flags/Android.bp
new file mode 100644
index 00000000..6f37a3a1
--- /dev/null
+++ b/aconfig/ap4a/com.android.server.devicepolicy.flags/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-ap4a-com.android.server.devicepolicy.flags-all",
+  package: "com.android.server.devicepolicy.flags",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/ap4a/com.android.server.locksettings/Android.bp b/aconfig/ap4a/com.android.server.locksettings/Android.bp
new file mode 100644
index 00000000..3f15fc1a
--- /dev/null
+++ b/aconfig/ap4a/com.android.server.locksettings/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-ap4a-com.android.server.locksettings-all",
+  package: "com.android.server.locksettings",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/ap4a/com.android.server.os/Android.bp b/aconfig/ap4a/com.android.server.os/Android.bp
new file mode 100644
index 00000000..2b37aa5b
--- /dev/null
+++ b/aconfig/ap4a/com.android.server.os/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-ap4a-com.android.server.os-all",
+  package: "com.android.server.os",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/ap4a/com.android.server.pm/Android.bp b/aconfig/ap4a/com.android.server.pm/Android.bp
new file mode 100644
index 00000000..1598f02e
--- /dev/null
+++ b/aconfig/ap4a/com.android.server.pm/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-ap4a-com.android.server.pm-all",
+  package: "com.android.server.pm",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/ap4a/com.android.server.security/Android.bp b/aconfig/ap4a/com.android.server.security/Android.bp
new file mode 100644
index 00000000..23bb01c9
--- /dev/null
+++ b/aconfig/ap4a/com.android.server.security/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-ap4a-com.android.server.security-all",
+  package: "com.android.server.security",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/ap4a/com.android.server.updates/Android.bp b/aconfig/ap4a/com.android.server.updates/Android.bp
new file mode 100644
index 00000000..84f60842
--- /dev/null
+++ b/aconfig/ap4a/com.android.server.updates/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-ap4a-com.android.server.updates-all",
+  package: "com.android.server.updates",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/ap4a/com.android.server.utils/Android.bp b/aconfig/ap4a/com.android.server.utils/Android.bp
new file mode 100644
index 00000000..793ba41b
--- /dev/null
+++ b/aconfig/ap4a/com.android.server.utils/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-ap4a-com.android.server.utils-all",
+  package: "com.android.server.utils",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/ap4a/com.android.settings.connecteddevice.flags/Android.bp b/aconfig/ap4a/com.android.settings.connecteddevice.flags/Android.bp
new file mode 100644
index 00000000..46b68bfe
--- /dev/null
+++ b/aconfig/ap4a/com.android.settings.connecteddevice.flags/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-ap4a-com.android.settings.connecteddevice.flags-all",
+  package: "com.android.settings.connecteddevice.flags",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/ap4a/com.android.settings.flags/enable_bluetooth_profile_toggle_visibility_checker_flag_values.textproto b/aconfig/ap4a/com.android.settings.flags/enable_bluetooth_profile_toggle_visibility_checker_flag_values.textproto
new file mode 100644
index 00000000..3070dc63
--- /dev/null
+++ b/aconfig/ap4a/com.android.settings.flags/enable_bluetooth_profile_toggle_visibility_checker_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.settings.flags"
+  name: "enable_bluetooth_profile_toggle_visibility_checker"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.settings.flags/enable_subsequent_pair_settings_integration_flag_values.textproto b/aconfig/ap4a/com.android.settings.flags/enable_subsequent_pair_settings_integration_flag_values.textproto
new file mode 100644
index 00000000..19c747b6
--- /dev/null
+++ b/aconfig/ap4a/com.android.settings.flags/enable_subsequent_pair_settings_integration_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.settings.flags"
+  name: "enable_subsequent_pair_settings_integration"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.settings.flags/internet_preference_controller_v2_flag_values.textproto b/aconfig/ap4a/com.android.settings.flags/internet_preference_controller_v2_flag_values.textproto
new file mode 100644
index 00000000..3870feb1
--- /dev/null
+++ b/aconfig/ap4a/com.android.settings.flags/internet_preference_controller_v2_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.settings.flags"
+  name: "internet_preference_controller_v2"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.settings.keyboard/Android.bp b/aconfig/ap4a/com.android.settings.keyboard/Android.bp
new file mode 100644
index 00000000..cd8b0fe4
--- /dev/null
+++ b/aconfig/ap4a/com.android.settings.keyboard/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-ap4a-com.android.settings.keyboard-all",
+  package: "com.android.settings.keyboard",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/ap4a/com.android.settingslib.flags/enable_cached_bluetooth_device_dedup_flag_values.textproto b/aconfig/ap4a/com.android.settingslib.flags/enable_cached_bluetooth_device_dedup_flag_values.textproto
new file mode 100644
index 00000000..ef19087e
--- /dev/null
+++ b/aconfig/ap4a/com.android.settingslib.flags/enable_cached_bluetooth_device_dedup_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.settingslib.flags"
+  name: "enable_cached_bluetooth_device_dedup"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.systemui.aconfig/Android.bp b/aconfig/ap4a/com.android.systemui.aconfig/Android.bp
new file mode 100644
index 00000000..ad1d70e9
--- /dev/null
+++ b/aconfig/ap4a/com.android.systemui.aconfig/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-ap4a-com.android.systemui.aconfig-all",
+  package: "com.android.systemui.aconfig",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/ap4a/com.android.systemui.communal/Android.bp b/aconfig/ap4a/com.android.systemui.communal/Android.bp
new file mode 100644
index 00000000..f85f8986
--- /dev/null
+++ b/aconfig/ap4a/com.android.systemui.communal/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-ap4a-com.android.systemui.communal-all",
+  package: "com.android.systemui.communal",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/ap4a/com.android.systemui/bp_talkback_flag_values.textproto b/aconfig/ap4a/com.android.systemui/bp_talkback_flag_values.textproto
new file mode 100644
index 00000000..1232057b
--- /dev/null
+++ b/aconfig/ap4a/com.android.systemui/bp_talkback_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.systemui"
+  name: "bp_talkback"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.systemui/centralized_status_bar_height_fix_flag_values.textproto b/aconfig/ap4a/com.android.systemui/centralized_status_bar_height_fix_flag_values.textproto
new file mode 100644
index 00000000..ff854144
--- /dev/null
+++ b/aconfig/ap4a/com.android.systemui/centralized_status_bar_height_fix_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.systemui"
+  name: "centralized_status_bar_height_fix"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.systemui/constraint_bp_flag_values.textproto b/aconfig/ap4a/com.android.systemui/constraint_bp_flag_values.textproto
new file mode 100644
index 00000000..de5fbef7
--- /dev/null
+++ b/aconfig/ap4a/com.android.systemui/constraint_bp_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.systemui"
+  name: "constraint_bp"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.systemui/haptic_brightness_slider_flag_values.textproto b/aconfig/ap4a/com.android.systemui/haptic_brightness_slider_flag_values.textproto
new file mode 100644
index 00000000..28675cbd
--- /dev/null
+++ b/aconfig/ap4a/com.android.systemui/haptic_brightness_slider_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.systemui"
+  name: "haptic_brightness_slider"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.systemui/haptic_volume_slider_flag_values.textproto b/aconfig/ap4a/com.android.systemui/haptic_volume_slider_flag_values.textproto
new file mode 100644
index 00000000..022c227a
--- /dev/null
+++ b/aconfig/ap4a/com.android.systemui/haptic_volume_slider_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.systemui"
+  name: "haptic_volume_slider"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.systemui/ignore_touches_next_to_notification_shelf_flag_values.textproto b/aconfig/ap4a/com.android.systemui/ignore_touches_next_to_notification_shelf_flag_values.textproto
index ea328229..7eda2f99 100644
--- a/aconfig/ap4a/com.android.systemui/ignore_touches_next_to_notification_shelf_flag_values.textproto
+++ b/aconfig/ap4a/com.android.systemui/ignore_touches_next_to_notification_shelf_flag_values.textproto
@@ -3,4 +3,4 @@ flag_value {
   name: "ignore_touches_next_to_notification_shelf"
   state: ENABLED
   permission: READ_ONLY
-}
+}
\ No newline at end of file
diff --git a/aconfig/ap4a/com.android.systemui/lockscreen_preview_renderer_create_on_main_thread_flag_values.textproto b/aconfig/ap4a/com.android.systemui/lockscreen_preview_renderer_create_on_main_thread_flag_values.textproto
new file mode 100644
index 00000000..e8da3491
--- /dev/null
+++ b/aconfig/ap4a/com.android.systemui/lockscreen_preview_renderer_create_on_main_thread_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.systemui"
+  name: "lockscreen_preview_renderer_create_on_main_thread"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.systemui/privacy_dot_unfold_wrong_corner_fix_flag_values.textproto b/aconfig/ap4a/com.android.systemui/privacy_dot_unfold_wrong_corner_fix_flag_values.textproto
new file mode 100644
index 00000000..11827bf6
--- /dev/null
+++ b/aconfig/ap4a/com.android.systemui/privacy_dot_unfold_wrong_corner_fix_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.systemui"
+  name: "privacy_dot_unfold_wrong_corner_fix"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.systemui/pss_app_selector_abrupt_exit_fix_flag_values.textproto b/aconfig/ap4a/com.android.systemui/pss_app_selector_abrupt_exit_fix_flag_values.textproto
new file mode 100644
index 00000000..bd3128a6
--- /dev/null
+++ b/aconfig/ap4a/com.android.systemui/pss_app_selector_abrupt_exit_fix_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.systemui"
+  name: "pss_app_selector_abrupt_exit_fix"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.systemui/qs_new_pipeline_flag_values.textproto b/aconfig/ap4a/com.android.systemui/qs_new_pipeline_flag_values.textproto
new file mode 100644
index 00000000..cc1c39b4
--- /dev/null
+++ b/aconfig/ap4a/com.android.systemui/qs_new_pipeline_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.systemui"
+  name: "qs_new_pipeline"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.systemui/screenshot_private_profile_accessibility_announcement_fix_flag_values.textproto b/aconfig/ap4a/com.android.systemui/screenshot_private_profile_accessibility_announcement_fix_flag_values.textproto
new file mode 100644
index 00000000..d7aff613
--- /dev/null
+++ b/aconfig/ap4a/com.android.systemui/screenshot_private_profile_accessibility_announcement_fix_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.systemui"
+  name: "screenshot_private_profile_accessibility_announcement_fix"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.systemui/screenshot_private_profile_behavior_fix_flag_values.textproto b/aconfig/ap4a/com.android.systemui/screenshot_private_profile_behavior_fix_flag_values.textproto
new file mode 100644
index 00000000..9c7addc1
--- /dev/null
+++ b/aconfig/ap4a/com.android.systemui/screenshot_private_profile_behavior_fix_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.systemui"
+  name: "screenshot_private_profile_behavior_fix"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.systemui/screenshot_save_image_exporter_flag_values.textproto b/aconfig/ap4a/com.android.systemui/screenshot_save_image_exporter_flag_values.textproto
new file mode 100644
index 00000000..caca07de
--- /dev/null
+++ b/aconfig/ap4a/com.android.systemui/screenshot_save_image_exporter_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.systemui"
+  name: "screenshot_save_image_exporter"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.systemui/screenshot_shelf_ui2_flag_values.textproto b/aconfig/ap4a/com.android.systemui/screenshot_shelf_ui2_flag_values.textproto
new file mode 100644
index 00000000..abfa3c0f
--- /dev/null
+++ b/aconfig/ap4a/com.android.systemui/screenshot_shelf_ui2_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.systemui"
+  name: "screenshot_shelf_ui2"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.systemui/truncated_status_bar_icons_fix_flag_values.textproto b/aconfig/ap4a/com.android.systemui/truncated_status_bar_icons_fix_flag_values.textproto
new file mode 100644
index 00000000..6a58584f
--- /dev/null
+++ b/aconfig/ap4a/com.android.systemui/truncated_status_bar_icons_fix_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.systemui"
+  name: "truncated_status_bar_icons_fix"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.telephony.phone.flags/Android.bp b/aconfig/ap4a/com.android.telephony.phone.flags/Android.bp
new file mode 100644
index 00000000..fc2e2d84
--- /dev/null
+++ b/aconfig/ap4a/com.android.telephony.phone.flags/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-ap4a-com.android.telephony.phone.flags-all",
+  package: "com.android.telephony.phone.flags",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/ap4a/com.android.text.flags/deprecate_ui_fonts_flag_values.textproto b/aconfig/ap4a/com.android.text.flags/deprecate_ui_fonts_flag_values.textproto
new file mode 100644
index 00000000..e1ffe46e
--- /dev/null
+++ b/aconfig/ap4a/com.android.text.flags/deprecate_ui_fonts_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.text.flags"
+  name: "deprecate_ui_fonts"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.text.flags/fix_double_underline_flag_values.textproto b/aconfig/ap4a/com.android.text.flags/fix_double_underline_flag_values.textproto
new file mode 100644
index 00000000..89f8ec0a
--- /dev/null
+++ b/aconfig/ap4a/com.android.text.flags/fix_double_underline_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.text.flags"
+  name: "fix_double_underline"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.text.flags/fix_font_update_failure_flag_values.textproto b/aconfig/ap4a/com.android.text.flags/fix_font_update_failure_flag_values.textproto
new file mode 100644
index 00000000..ce278209
--- /dev/null
+++ b/aconfig/ap4a/com.android.text.flags/fix_font_update_failure_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.text.flags"
+  name: "fix_font_update_failure"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.text.flags/fix_misaligned_context_menu_flag_values.textproto b/aconfig/ap4a/com.android.text.flags/fix_misaligned_context_menu_flag_values.textproto
new file mode 100644
index 00000000..cf7c84a4
--- /dev/null
+++ b/aconfig/ap4a/com.android.text.flags/fix_misaligned_context_menu_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.text.flags"
+  name: "fix_misaligned_context_menu"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.text.flags/icu_bidi_migration_flag_values.textproto b/aconfig/ap4a/com.android.text.flags/icu_bidi_migration_flag_values.textproto
new file mode 100644
index 00000000..66ea0b6b
--- /dev/null
+++ b/aconfig/ap4a/com.android.text.flags/icu_bidi_migration_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.text.flags"
+  name: "icu_bidi_migration"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.text.flags/lazy_variation_instance_flag_values.textproto b/aconfig/ap4a/com.android.text.flags/lazy_variation_instance_flag_values.textproto
new file mode 100644
index 00000000..98b9d3af
--- /dev/null
+++ b/aconfig/ap4a/com.android.text.flags/lazy_variation_instance_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.text.flags"
+  name: "lazy_variation_instance"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.text.flags/phrase_strict_fallback_flag_values.textproto b/aconfig/ap4a/com.android.text.flags/phrase_strict_fallback_flag_values.textproto
new file mode 100644
index 00000000..94fe0cba
--- /dev/null
+++ b/aconfig/ap4a/com.android.text.flags/phrase_strict_fallback_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.text.flags"
+  name: "phrase_strict_fallback"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.text.flags/portuguese_hyphenator_flag_values.textproto b/aconfig/ap4a/com.android.text.flags/portuguese_hyphenator_flag_values.textproto
new file mode 100644
index 00000000..6ed92a62
--- /dev/null
+++ b/aconfig/ap4a/com.android.text.flags/portuguese_hyphenator_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.text.flags"
+  name: "portuguese_hyphenator"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.text.flags/vendor_custom_locale_fallback_flag_values.textproto b/aconfig/ap4a/com.android.text.flags/vendor_custom_locale_fallback_flag_values.textproto
new file mode 100644
index 00000000..5958a97f
--- /dev/null
+++ b/aconfig/ap4a/com.android.text.flags/vendor_custom_locale_fallback_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.text.flags"
+  name: "vendor_custom_locale_fallback"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.trunk_stable_workflow_testing/Android.bp b/aconfig/ap4a/com.android.trunk_stable_workflow_testing/Android.bp
new file mode 100644
index 00000000..21171027
--- /dev/null
+++ b/aconfig/ap4a/com.android.trunk_stable_workflow_testing/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-ap4a-com.android.trunk_stable_workflow_testing-all",
+  package: "com.android.trunk_stable_workflow_testing",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/ap4a/com.android.wallpaper/Android.bp b/aconfig/ap4a/com.android.wallpaper/Android.bp
new file mode 100644
index 00000000..90d55b0b
--- /dev/null
+++ b/aconfig/ap4a/com.android.wallpaper/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-ap4a-com.android.wallpaper-all",
+  package: "com.android.wallpaper",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/ap4a/com.android.window.flags/activity_snapshot_by_default_flag_values.textproto b/aconfig/ap4a/com.android.window.flags/activity_snapshot_by_default_flag_values.textproto
new file mode 100644
index 00000000..a6801519
--- /dev/null
+++ b/aconfig/ap4a/com.android.window.flags/activity_snapshot_by_default_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.window.flags"
+  name: "activity_snapshot_by_default"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.window.flags/activity_window_info_flag_flag_values.textproto b/aconfig/ap4a/com.android.window.flags/activity_window_info_flag_flag_values.textproto
new file mode 100644
index 00000000..edda5051
--- /dev/null
+++ b/aconfig/ap4a/com.android.window.flags/activity_window_info_flag_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.window.flags"
+  name: "activity_window_info_flag"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.window.flags/always_defer_transition_when_apply_wct_flag_values.textproto b/aconfig/ap4a/com.android.window.flags/always_defer_transition_when_apply_wct_flag_values.textproto
new file mode 100644
index 00000000..26582b45
--- /dev/null
+++ b/aconfig/ap4a/com.android.window.flags/always_defer_transition_when_apply_wct_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.window.flags"
+  name: "always_defer_transition_when_apply_wct"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.window.flags/bundle_client_transaction_flag_flag_values.textproto b/aconfig/ap4a/com.android.window.flags/bundle_client_transaction_flag_flag_values.textproto
new file mode 100644
index 00000000..221b52ff
--- /dev/null
+++ b/aconfig/ap4a/com.android.window.flags/bundle_client_transaction_flag_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.window.flags"
+  name: "bundle_client_transaction_flag"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.window.flags/defer_display_updates_flag_values.textproto b/aconfig/ap4a/com.android.window.flags/defer_display_updates_flag_values.textproto
new file mode 100644
index 00000000..38314f28
--- /dev/null
+++ b/aconfig/ap4a/com.android.window.flags/defer_display_updates_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.window.flags"
+  name: "defer_display_updates"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.window.flags/disable_object_pool_flag_values.textproto b/aconfig/ap4a/com.android.window.flags/disable_object_pool_flag_values.textproto
new file mode 100644
index 00000000..d335d064
--- /dev/null
+++ b/aconfig/ap4a/com.android.window.flags/disable_object_pool_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.window.flags"
+  name: "disable_object_pool"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.window.flags/do_not_skip_ime_by_target_visibility_flag_values.textproto b/aconfig/ap4a/com.android.window.flags/do_not_skip_ime_by_target_visibility_flag_values.textproto
new file mode 100644
index 00000000..54a72800
--- /dev/null
+++ b/aconfig/ap4a/com.android.window.flags/do_not_skip_ime_by_target_visibility_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.window.flags"
+  name: "do_not_skip_ime_by_target_visibility"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.window.flags/embedded_activity_back_nav_flag_flag_values.textproto b/aconfig/ap4a/com.android.window.flags/embedded_activity_back_nav_flag_flag_values.textproto
new file mode 100644
index 00000000..e8a946d7
--- /dev/null
+++ b/aconfig/ap4a/com.android.window.flags/embedded_activity_back_nav_flag_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.window.flags"
+  name: "embedded_activity_back_nav_flag"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.window.flags/enforce_shell_thread_model_flag_values.textproto b/aconfig/ap4a/com.android.window.flags/enforce_shell_thread_model_flag_values.textproto
new file mode 100644
index 00000000..1f1be81b
--- /dev/null
+++ b/aconfig/ap4a/com.android.window.flags/enforce_shell_thread_model_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.window.flags"
+  name: "enforce_shell_thread_model"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.window.flags/fix_no_container_update_without_resize_flag_values.textproto b/aconfig/ap4a/com.android.window.flags/fix_no_container_update_without_resize_flag_values.textproto
new file mode 100644
index 00000000..afdf387e
--- /dev/null
+++ b/aconfig/ap4a/com.android.window.flags/fix_no_container_update_without_resize_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.window.flags"
+  name: "fix_no_container_update_without_resize"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.window.flags/fix_pip_restore_to_overlay_flag_values.textproto b/aconfig/ap4a/com.android.window.flags/fix_pip_restore_to_overlay_flag_values.textproto
new file mode 100644
index 00000000..49d19f4f
--- /dev/null
+++ b/aconfig/ap4a/com.android.window.flags/fix_pip_restore_to_overlay_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.window.flags"
+  name: "fix_pip_restore_to_overlay"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.window.flags/fullscreen_dim_flag_flag_values.textproto b/aconfig/ap4a/com.android.window.flags/fullscreen_dim_flag_flag_values.textproto
new file mode 100644
index 00000000..3fc8a069
--- /dev/null
+++ b/aconfig/ap4a/com.android.window.flags/fullscreen_dim_flag_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.window.flags"
+  name: "fullscreen_dim_flag"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.window.flags/insets_control_changed_item_flag_values.textproto b/aconfig/ap4a/com.android.window.flags/insets_control_changed_item_flag_values.textproto
new file mode 100644
index 00000000..a6a0b493
--- /dev/null
+++ b/aconfig/ap4a/com.android.window.flags/insets_control_changed_item_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.window.flags"
+  name: "insets_control_changed_item"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.window.flags/introduce_smoother_dimmer_flag_values.textproto b/aconfig/ap4a/com.android.window.flags/introduce_smoother_dimmer_flag_values.textproto
new file mode 100644
index 00000000..843fbad5
--- /dev/null
+++ b/aconfig/ap4a/com.android.window.flags/introduce_smoother_dimmer_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.window.flags"
+  name: "introduce_smoother_dimmer"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.window.flags/keyguard_appear_transition_flag_values.textproto b/aconfig/ap4a/com.android.window.flags/keyguard_appear_transition_flag_values.textproto
new file mode 100644
index 00000000..1703ca3f
--- /dev/null
+++ b/aconfig/ap4a/com.android.window.flags/keyguard_appear_transition_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.window.flags"
+  name: "keyguard_appear_transition"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.window.flags/per_user_display_window_settings_flag_values.textproto b/aconfig/ap4a/com.android.window.flags/per_user_display_window_settings_flag_values.textproto
new file mode 100644
index 00000000..1d691543
--- /dev/null
+++ b/aconfig/ap4a/com.android.window.flags/per_user_display_window_settings_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.window.flags"
+  name: "per_user_display_window_settings"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.window.flags/remove_prepare_surface_in_placement_flag_values.textproto b/aconfig/ap4a/com.android.window.flags/remove_prepare_surface_in_placement_flag_values.textproto
new file mode 100644
index 00000000..1c847d9b
--- /dev/null
+++ b/aconfig/ap4a/com.android.window.flags/remove_prepare_surface_in_placement_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.window.flags"
+  name: "remove_prepare_surface_in_placement"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.window.flags/skip_sleeping_when_switching_display_flag_values.textproto b/aconfig/ap4a/com.android.window.flags/skip_sleeping_when_switching_display_flag_values.textproto
new file mode 100644
index 00000000..27654d88
--- /dev/null
+++ b/aconfig/ap4a/com.android.window.flags/skip_sleeping_when_switching_display_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.window.flags"
+  name: "skip_sleeping_when_switching_display"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.window.flags/window_session_relayout_info_flag_values.textproto b/aconfig/ap4a/com.android.window.flags/window_session_relayout_info_flag_values.textproto
new file mode 100644
index 00000000..8ab8a120
--- /dev/null
+++ b/aconfig/ap4a/com.android.window.flags/window_session_relayout_info_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.window.flags"
+  name: "window_session_relayout_info"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.android.window.flags/window_token_config_thread_safe_flag_values.textproto b/aconfig/ap4a/com.android.window.flags/window_token_config_thread_safe_flag_values.textproto
new file mode 100644
index 00000000..8e07249b
--- /dev/null
+++ b/aconfig/ap4a/com.android.window.flags/window_token_config_thread_safe_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.window.flags"
+  name: "window_token_config_thread_safe"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/ap4a/com.example.android.aconfig.demo.flags/Android.bp b/aconfig/ap4a/com.example.android.aconfig.demo.flags/Android.bp
new file mode 100644
index 00000000..4895b197
--- /dev/null
+++ b/aconfig/ap4a/com.example.android.aconfig.demo.flags/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-ap4a-com.example.android.aconfig.demo.flags-all",
+  package: "com.example.android.aconfig.demo.flags",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/ap4a/com.google.android.platform.launcher.aconfig.flags/Android.bp b/aconfig/ap4a/com.google.android.platform.launcher.aconfig.flags/Android.bp
new file mode 100644
index 00000000..cd0e50a2
--- /dev/null
+++ b/aconfig/ap4a/com.google.android.platform.launcher.aconfig.flags/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-ap4a-com.google.android.platform.launcher.aconfig.flags-all",
+  package: "com.google.android.platform.launcher.aconfig.flags",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/trunk_staging/Android.bp b/aconfig/trunk_staging/Android.bp
index 2f36c6ef..87ad4ff0 100644
--- a/aconfig/trunk_staging/Android.bp
+++ b/aconfig/trunk_staging/Android.bp
@@ -13,191 +13,213 @@
 // limitations under the License.
 
 aconfig_value_set {
-    name: "aconfig_value_set-platform_build_release-trunk_staging",
-    values: [
-      "aconfig-values-platform_build_release-trunk_staging-com.android.frameworks.sensorservice.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.net.vcn-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.bluetooth.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.media.performance.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.net.thread.platform.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.server.am-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.app.wearable-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.net.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-vendor.vibrator.hal.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.service.chooser-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.hardware.libsensor.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.healthfitness.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.graphics.libgui.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.org.conscrypt-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.chre.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.media.mainline.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.app.usage-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.adaptiveauth-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.provider.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.server.notification-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.app.appfunctions.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.os-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.nfc.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.input.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.server.biometrics-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.media.codec-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.hardware.radio-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.service.dreams-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.security-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.adservices.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.security.flag-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.egg.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.app.admin.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.net.wifi.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.settings.media_drm-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.server-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.graphics.surfaceflinger.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.server.usb.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.hardware.input-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.content.pm-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.server.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.icu-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.service.voice.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.btaudio.hal.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.webkit-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.server.job-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.net.ct.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.app.ondeviceintelligence.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.appwidget.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.service.autofill-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.aconfig_new_storage-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.server.display.feature.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.sdk-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.view.inputmethod-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.aconfig.test-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.managedprovisioning.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.media.editing.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.wm.shell-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.service.controls.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.server.backup-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.app-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.location.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.appsearch.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.security.keystore2-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.media.codec.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.hardware.usb.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.wifi.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.app.smartspace.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.car.dockutil-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.sdksandbox.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.os.vibrator-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.hardware.devicestate.feature.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.internal.pm.pkg.component.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.launcher3-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.systemui.accessibility.accessibilitymenu-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.media.audioclient-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.internal.os-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.speech.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.server.updates-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.media.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.server.stats-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.car.carlauncher-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.systemui-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.server.power.feature.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.companion.virtualdevice.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.database.sqlite-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.net.thread.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.crashrecovery.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.system.virtualmachine.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.view.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.settings.accessibility-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.os.profiling-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.car.settings-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.view.contentcapture.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.app.job-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.providers.contactkeys.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.settingslib.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.wallpaper-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.server.power.hint-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.providers.settings-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.internal.telephony.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.settings.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.hardware.biometrics-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.server.alarm-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.trunk_stable_workflow_testing-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.server.usage-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.internal.foldables.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.server.accessibility-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.settingslib.widget.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.server.feature.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.text.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.media.audio-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.server.deviceconfig-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.settingslib.media.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.server.dreams-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.uprobestats.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.provider-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.media.tv.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.art.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.media.aaudio-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.media.projection.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.graphics.hwui.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.service.appprediction.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-libgooglecamerahal.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.deviceaswebcam.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.multiuser-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.intentresolver-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.settings.factory_reset-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.graphics.pdf.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.credentials.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.permission.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.media.playback.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.service.notification-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.libcore-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.media.audiopolicy-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.internal.camera.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.companion.virtual.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.settingslib.widget.selectorwithwidgetpreference.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.ipsec.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.internal.compat.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.healthconnect.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.server.deviceidle-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.content.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.app.contextualsearch.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.systemui.car-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.google.android.iwlan.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.server.telecom.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.uwb.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.window.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.server.policy.feature.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.libhardware.dynamic.sensors.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.content.res-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.graphics.libvulkan.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.media.midi-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.adservices.ondevicepersonalization.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.graphics.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.hardware.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.server.utils-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.example.android.aconfig.demo.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.widget.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.companion-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.media.audio-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.car.feature-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.car.datasubscription-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.os.statsd.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.server.policy-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.media.audioserver-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.server.power.batterysaver-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.net.platform.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.tracing-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.view.accessibility-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.nfc.nci.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.server.power.optimization-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.providers.media.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.nearby.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.nfc-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.server.app-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.server.net-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.media.soundtrigger-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.permission.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.server.powerstats-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.settings.development-all",
-      "aconfig-values-platform_build_release-trunk_staging-android.view.contentprotection.flags-all",
-      "aconfig-values-platform_build_release-trunk_staging-com.android.systemui.shared-all"
-    ]
-}
+  name: "aconfig_value_set-platform_build_release-trunk_staging",
+  values: [
+        "aconfig-values-platform_build_release-trunk_staging-android.service.autofill-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.server.deviceidle-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.hardware.libsensor.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.permission.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.server.power.feature.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.providers.contacts.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.media.codec-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.providers.media.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.media.audioserver-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.hardware.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.content.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.os.profiling-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.google.android.iwlan.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.server.deviceconfig-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.graphics.libgui.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.server.power.optimization-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.sdksandbox.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.media.audio-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.launcher3-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.server.telecom.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.view.contentprotection.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.car.feature-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.server.usage-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.security.flag-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.media.aaudio-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.server.feature.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.internal.pm.pkg.component.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.settingslib.media.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.server.connectivity-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.server.usb.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.internal.jank-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.nfc-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.os.statsd.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.server.notification-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.trunk_stable_workflow_testing-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.content.pm-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.server-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.server.accessibility-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.media.mainline.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.server.backup-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.media.projection.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.libcore-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.media.codec.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.nfc.nci.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.provider.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.adservices.ondevicepersonalization.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-libgooglecamerahal.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.frameworks.sensorservice.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.settings.media_drm-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.hardware.input-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.media.midi-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.service.appprediction.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.graphics.libvulkan.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.car.settings-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.hardware.camera2-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.appwidget.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.server.alarm-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.intentresolver-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.healthfitness.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.server.updates-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.car.carlauncher-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.wallpaper-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.chre.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.provider.configinfrastructure.framework-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.server.app-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.telephony.phone.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.location.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.service.voice.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.wm.shell-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.settings.connecteddevice.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.net.wifi.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.adaptiveauth-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.car.dockutil-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.media.editing.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.app.jank-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.settings.keyboard-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.server.companion.virtual-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.settings.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.companion-all",
+        "aconfig-values-platform_build_release-trunk_staging-vendor.vibrator.hal.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.system.virtualmachine.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.settingslib.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.car.datasubscription-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.os-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.companion.virtualdevice.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.tracing-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.server.power.hint-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.btaudio.hal.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.graphics.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.widget.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.server.net-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.aconfig.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.media.audioclient-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.net.vcn-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.settingslib.widget.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.graphics.hwui.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.graphics.bufferstreams.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.aconfig.test-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.systemui.shared-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.graphics.surfaceflinger.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.credentials.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.art.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.hardware.radio-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.managedprovisioning.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.org.conscrypt-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.os.vibrator-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.devicelock.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.server.job-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.internal.foldables.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.settings.development-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.settings.factory_reset-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.systemui.communal-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.view.contentcapture.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.healthconnect.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.bluetooth.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.media.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.multiuser-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.server.policy-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.systemui.accessibility.accessibilitymenu-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.service.dreams-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.crashrecovery.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.uwb.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.server.dreams-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.app.job-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.egg.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.icu-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.settingslib.widget.selectorwithwidgetpreference.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.media.playback.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.internal.camera.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.systemui.aconfig-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.service.notification-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.example.android.aconfig.demo.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.security-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.net.thread.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.service.controls.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.hardware.usb.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.adservices.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.wifi.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.google.android.platform.launcher.aconfig.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.view.accessibility-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.app.appfunctions.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.providers.settings-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.systemui-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.server.utils-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.cellbroadcastreceiver.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.server.devicepolicy.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.settings.accessibility-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.internal.compat.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.server.policy.feature.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.media.performance.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.aconfig_new_storage-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.server.stats-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.permission.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.app.wearable-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.server.security-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.app.ondeviceintelligence.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.app.admin.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.ipsec.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.nearby.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.server.os-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.server.contextualsearch.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.input.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.net.ct.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.server.pm-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.server.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.libhardware.dynamic.sensors.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.graphics.pdf.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.deviceaswebcam.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.database.sqlite-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.service.chooser-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.net.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.server.power.batterysaver-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.server.biometrics-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.text.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.net.thread.platform.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.view.inputmethod-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.providers.contactkeys.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.view.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.systemui.car-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.media.audiopolicy-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.media.soundtrigger-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.security.keystore2-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.app.smartspace.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.media.audio-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.net.platform.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.server.am-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.server.display.feature.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.hardware.devicestate.feature.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.window.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.app.contextualsearch.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.hardware.biometrics-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.speech.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.server.powerstats-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.internal.os-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.content.res-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.app.usage-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.nfc.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.server.locksettings-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.sdk-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.provider-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.app-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.companion.virtual.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.appsearch.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-com.android.internal.telephony.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.media.tv.flags-all",
+        "aconfig-values-platform_build_release-trunk_staging-android.webkit-all",
+      ]
+}
\ No newline at end of file
diff --git a/aconfig/trunk_staging/android.app.admin.flags/allow_screen_brightness_control_on_cope_flag_values.textproto b/aconfig/trunk_staging/android.app.admin.flags/allow_screen_brightness_control_on_cope_flag_values.textproto
new file mode 100644
index 00000000..baa7848b
--- /dev/null
+++ b/aconfig/trunk_staging/android.app.admin.flags/allow_screen_brightness_control_on_cope_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.app.admin.flags"
+  name: "allow_screen_brightness_control_on_cope"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/android.app.admin.flags/always_persist_do_flag_values.textproto b/aconfig/trunk_staging/android.app.admin.flags/always_persist_do_flag_values.textproto
new file mode 100644
index 00000000..198ad9d3
--- /dev/null
+++ b/aconfig/trunk_staging/android.app.admin.flags/always_persist_do_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.app.admin.flags"
+  name: "always_persist_do"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/android.app.admin.flags/coexistence_migration_for_non_emm_management_enabled_flag_values.textproto b/aconfig/trunk_staging/android.app.admin.flags/coexistence_migration_for_non_emm_management_enabled_flag_values.textproto
new file mode 100644
index 00000000..599537ce
--- /dev/null
+++ b/aconfig/trunk_staging/android.app.admin.flags/coexistence_migration_for_non_emm_management_enabled_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.app.admin.flags"
+  name: "coexistence_migration_for_non_emm_management_enabled"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/android.app.admin.flags/copy_account_with_retry_enabled_flag_values.textproto b/aconfig/trunk_staging/android.app.admin.flags/copy_account_with_retry_enabled_flag_values.textproto
new file mode 100644
index 00000000..671b5b3b
--- /dev/null
+++ b/aconfig/trunk_staging/android.app.admin.flags/copy_account_with_retry_enabled_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.app.admin.flags"
+  name: "copy_account_with_retry_enabled"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/android.app.admin.flags/dedicated_device_control_enabled_flag_values.textproto b/aconfig/trunk_staging/android.app.admin.flags/dedicated_device_control_enabled_flag_values.textproto
new file mode 100644
index 00000000..9ac9ca3c
--- /dev/null
+++ b/aconfig/trunk_staging/android.app.admin.flags/dedicated_device_control_enabled_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.app.admin.flags"
+  name: "dedicated_device_control_enabled"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/android.app.admin.flags/delete_private_space_under_restriction_flag_values.textproto b/aconfig/trunk_staging/android.app.admin.flags/delete_private_space_under_restriction_flag_values.textproto
new file mode 100644
index 00000000..ab1aade3
--- /dev/null
+++ b/aconfig/trunk_staging/android.app.admin.flags/delete_private_space_under_restriction_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.app.admin.flags"
+  name: "delete_private_space_under_restriction"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/android.app.admin.flags/device_policy_size_tracking_internal_bug_fix_enabled_flag_values.textproto b/aconfig/trunk_staging/android.app.admin.flags/device_policy_size_tracking_internal_bug_fix_enabled_flag_values.textproto
new file mode 100644
index 00000000..1de347cb
--- /dev/null
+++ b/aconfig/trunk_staging/android.app.admin.flags/device_policy_size_tracking_internal_bug_fix_enabled_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.app.admin.flags"
+  name: "device_policy_size_tracking_internal_bug_fix_enabled"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/android.app.admin.flags/disallow_user_control_bg_usage_fix_flag_values.textproto b/aconfig/trunk_staging/android.app.admin.flags/disallow_user_control_bg_usage_fix_flag_values.textproto
new file mode 100644
index 00000000..cd7174a9
--- /dev/null
+++ b/aconfig/trunk_staging/android.app.admin.flags/disallow_user_control_bg_usage_fix_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.app.admin.flags"
+  name: "disallow_user_control_bg_usage_fix"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/android.app.admin.flags/dmrh_set_app_restrictions_flag_values.textproto b/aconfig/trunk_staging/android.app.admin.flags/dmrh_set_app_restrictions_flag_values.textproto
new file mode 100644
index 00000000..02164905
--- /dev/null
+++ b/aconfig/trunk_staging/android.app.admin.flags/dmrh_set_app_restrictions_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.app.admin.flags"
+  name: "dmrh_set_app_restrictions"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/android.app.admin.flags/dumpsys_policy_engine_migration_enabled_flag_values.textproto b/aconfig/trunk_staging/android.app.admin.flags/dumpsys_policy_engine_migration_enabled_flag_values.textproto
new file mode 100644
index 00000000..abb3da1c
--- /dev/null
+++ b/aconfig/trunk_staging/android.app.admin.flags/dumpsys_policy_engine_migration_enabled_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.app.admin.flags"
+  name: "dumpsys_policy_engine_migration_enabled"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/android.app.admin.flags/headless_device_owner_delegate_security_logging_bug_fix_flag_values.textproto b/aconfig/trunk_staging/android.app.admin.flags/headless_device_owner_delegate_security_logging_bug_fix_flag_values.textproto
new file mode 100644
index 00000000..f75e493c
--- /dev/null
+++ b/aconfig/trunk_staging/android.app.admin.flags/headless_device_owner_delegate_security_logging_bug_fix_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.app.admin.flags"
+  name: "headless_device_owner_delegate_security_logging_bug_fix"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/android.app.admin.flags/headless_device_owner_provisioning_fix_enabled_flag_values.textproto b/aconfig/trunk_staging/android.app.admin.flags/headless_device_owner_provisioning_fix_enabled_flag_values.textproto
new file mode 100644
index 00000000..60b012f8
--- /dev/null
+++ b/aconfig/trunk_staging/android.app.admin.flags/headless_device_owner_provisioning_fix_enabled_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.app.admin.flags"
+  name: "headless_device_owner_provisioning_fix_enabled"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/android.app.admin.flags/headless_single_user_bad_device_admin_state_fix_flag_values.textproto b/aconfig/trunk_staging/android.app.admin.flags/headless_single_user_bad_device_admin_state_fix_flag_values.textproto
new file mode 100644
index 00000000..b8ebbd86
--- /dev/null
+++ b/aconfig/trunk_staging/android.app.admin.flags/headless_single_user_bad_device_admin_state_fix_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.app.admin.flags"
+  name: "headless_single_user_bad_device_admin_state_fix"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/android.app.admin.flags/headless_single_user_compatibility_fix_flag_values.textproto b/aconfig/trunk_staging/android.app.admin.flags/headless_single_user_compatibility_fix_flag_values.textproto
new file mode 100644
index 00000000..970769ad
--- /dev/null
+++ b/aconfig/trunk_staging/android.app.admin.flags/headless_single_user_compatibility_fix_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.app.admin.flags"
+  name: "headless_single_user_compatibility_fix"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/android.app.admin.flags/headless_single_user_fixes_flag_values.textproto b/aconfig/trunk_staging/android.app.admin.flags/headless_single_user_fixes_flag_values.textproto
new file mode 100644
index 00000000..6f5fb05e
--- /dev/null
+++ b/aconfig/trunk_staging/android.app.admin.flags/headless_single_user_fixes_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.app.admin.flags"
+  name: "headless_single_user_fixes"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/android.app.admin.flags/hsum_unlock_notification_fix_flag_values.textproto b/aconfig/trunk_staging/android.app.admin.flags/hsum_unlock_notification_fix_flag_values.textproto
new file mode 100644
index 00000000..ae16913d
--- /dev/null
+++ b/aconfig/trunk_staging/android.app.admin.flags/hsum_unlock_notification_fix_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.app.admin.flags"
+  name: "hsum_unlock_notification_fix"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/android.app.admin.flags/permission_migration_for_zero_trust_impl_enabled_flag_values.textproto b/aconfig/trunk_staging/android.app.admin.flags/permission_migration_for_zero_trust_impl_enabled_flag_values.textproto
new file mode 100644
index 00000000..50e5222c
--- /dev/null
+++ b/aconfig/trunk_staging/android.app.admin.flags/permission_migration_for_zero_trust_impl_enabled_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.app.admin.flags"
+  name: "permission_migration_for_zero_trust_impl_enabled"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/android.app.admin.flags/power_exemption_bg_usage_fix_flag_values.textproto b/aconfig/trunk_staging/android.app.admin.flags/power_exemption_bg_usage_fix_flag_values.textproto
new file mode 100644
index 00000000..fda919d4
--- /dev/null
+++ b/aconfig/trunk_staging/android.app.admin.flags/power_exemption_bg_usage_fix_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.app.admin.flags"
+  name: "power_exemption_bg_usage_fix"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/android.uprobestats.flags/Android.bp b/aconfig/trunk_staging/android.app.jank/Android.bp
similarity index 91%
rename from aconfig/trunk_staging/android.uprobestats.flags/Android.bp
rename to aconfig/trunk_staging/android.app.jank/Android.bp
index f0ef3782..30762340 100644
--- a/aconfig/trunk_staging/android.uprobestats.flags/Android.bp
+++ b/aconfig/trunk_staging/android.app.jank/Android.bp
@@ -13,8 +13,8 @@
 // limitations under the License.
 
 aconfig_values {
-  name: "aconfig-values-platform_build_release-trunk_staging-android.uprobestats.flags-all",
-  package: "android.uprobestats.flags",
+  name: "aconfig-values-platform_build_release-trunk_staging-android.app.jank-all",
+  package: "android.app.jank",
   srcs: [
     "*_flag_values.textproto",
   ]
diff --git a/aconfig/trunk_staging/android.chre.flags/bug_fix_reduce_lock_holding_period_flag_values.textproto b/aconfig/trunk_staging/android.chre.flags/bug_fix_reduce_lock_holding_period_flag_values.textproto
new file mode 100644
index 00000000..779cd745
--- /dev/null
+++ b/aconfig/trunk_staging/android.chre.flags/bug_fix_reduce_lock_holding_period_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.chre.flags"
+  name: "bug_fix_reduce_lock_holding_period"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/android.chre.flags/flag_log_nanoapp_load_metrics_flag_values.textproto b/aconfig/trunk_staging/android.chre.flags/flag_log_nanoapp_load_metrics_flag_values.textproto
new file mode 100644
index 00000000..5b547757
--- /dev/null
+++ b/aconfig/trunk_staging/android.chre.flags/flag_log_nanoapp_load_metrics_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.chre.flags"
+  name: "flag_log_nanoapp_load_metrics"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/android.chre.flags/metrics_reporter_in_the_daemon_flag_values.textproto b/aconfig/trunk_staging/android.chre.flags/metrics_reporter_in_the_daemon_flag_values.textproto
new file mode 100644
index 00000000..e5e50f3e
--- /dev/null
+++ b/aconfig/trunk_staging/android.chre.flags/metrics_reporter_in_the_daemon_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.chre.flags"
+  name: "metrics_reporter_in_the_daemon"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/android.chre.flags/reduce_lock_holding_period_flag_values.textproto b/aconfig/trunk_staging/android.chre.flags/reduce_lock_holding_period_flag_values.textproto
new file mode 100644
index 00000000..37d20729
--- /dev/null
+++ b/aconfig/trunk_staging/android.chre.flags/reduce_lock_holding_period_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.chre.flags"
+  name: "reduce_lock_holding_period"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/android.chre.flags/remove_ap_wakeup_metric_report_limit_flag_values.textproto b/aconfig/trunk_staging/android.chre.flags/remove_ap_wakeup_metric_report_limit_flag_values.textproto
new file mode 100644
index 00000000..a6777997
--- /dev/null
+++ b/aconfig/trunk_staging/android.chre.flags/remove_ap_wakeup_metric_report_limit_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.chre.flags"
+  name: "remove_ap_wakeup_metric_report_limit"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/android.companion.virtual.flags/consistent_display_flags_flag_values.textproto b/aconfig/trunk_staging/android.companion.virtual.flags/consistent_display_flags_flag_values.textproto
new file mode 100644
index 00000000..6d284a3e
--- /dev/null
+++ b/aconfig/trunk_staging/android.companion.virtual.flags/consistent_display_flags_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.companion.virtual.flags"
+  name: "consistent_display_flags"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/android.companion.virtual.flags/express_metrics_flag_values.textproto b/aconfig/trunk_staging/android.companion.virtual.flags/express_metrics_flag_values.textproto
new file mode 100644
index 00000000..8d44be57
--- /dev/null
+++ b/aconfig/trunk_staging/android.companion.virtual.flags/express_metrics_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.companion.virtual.flags"
+  name: "express_metrics"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/android.companion.virtual.flags/interactive_screen_mirror_flag_values.textproto b/aconfig/trunk_staging/android.companion.virtual.flags/interactive_screen_mirror_flag_values.textproto
new file mode 100644
index 00000000..c826b8fc
--- /dev/null
+++ b/aconfig/trunk_staging/android.companion.virtual.flags/interactive_screen_mirror_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.companion.virtual.flags"
+  name: "interactive_screen_mirror"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/android.companion.virtual.flags/intercept_intents_before_applying_policy_flag_values.textproto b/aconfig/trunk_staging/android.companion.virtual.flags/intercept_intents_before_applying_policy_flag_values.textproto
new file mode 100644
index 00000000..206962f8
--- /dev/null
+++ b/aconfig/trunk_staging/android.companion.virtual.flags/intercept_intents_before_applying_policy_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.companion.virtual.flags"
+  name: "intercept_intents_before_applying_policy"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/android.companion.virtual.flags/stream_permissions_flag_values.textproto b/aconfig/trunk_staging/android.companion.virtual.flags/stream_permissions_flag_values.textproto
new file mode 100644
index 00000000..15b8a850
--- /dev/null
+++ b/aconfig/trunk_staging/android.companion.virtual.flags/stream_permissions_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.companion.virtual.flags"
+  name: "stream_permissions"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/android.companion.virtualdevice.flags/intent_interception_action_matching_fix_flag_values.textproto b/aconfig/trunk_staging/android.companion.virtualdevice.flags/intent_interception_action_matching_fix_flag_values.textproto
new file mode 100644
index 00000000..c1bd30e4
--- /dev/null
+++ b/aconfig/trunk_staging/android.companion.virtualdevice.flags/intent_interception_action_matching_fix_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.companion.virtualdevice.flags"
+  name: "intent_interception_action_matching_fix"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/android.companion.virtualdevice.flags/metrics_collection_flag_values.textproto b/aconfig/trunk_staging/android.companion.virtualdevice.flags/metrics_collection_flag_values.textproto
new file mode 100644
index 00000000..ff413d9d
--- /dev/null
+++ b/aconfig/trunk_staging/android.companion.virtualdevice.flags/metrics_collection_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.companion.virtualdevice.flags"
+  name: "metrics_collection"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/trunk_staging/android.companion.virtualdevice.flags/virtual_display_multi_window_mode_support_flag_values.textproto b/aconfig/trunk_staging/android.companion.virtualdevice.flags/virtual_display_multi_window_mode_support_flag_values.textproto
new file mode 100644
index 00000000..88a72cbf
--- /dev/null
+++ b/aconfig/trunk_staging/android.companion.virtualdevice.flags/virtual_display_multi_window_mode_support_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.companion.virtualdevice.flags"
+  name: "virtual_display_multi_window_mode_support"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/trunk_staging/android.companion/companion_transport_apis_flag_values.textproto b/aconfig/trunk_staging/android.companion/companion_transport_apis_flag_values.textproto
new file mode 100644
index 00000000..38effbad
--- /dev/null
+++ b/aconfig/trunk_staging/android.companion/companion_transport_apis_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.companion"
+  name: "companion_transport_apis"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/android.credentials.flags/wear_credential_manager_enabled_flag_values.textproto b/aconfig/trunk_staging/android.credentials.flags/wear_credential_manager_enabled_flag_values.textproto
deleted file mode 100644
index d4d5621d..00000000
--- a/aconfig/trunk_staging/android.credentials.flags/wear_credential_manager_enabled_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.credentials.flags"
-  name: "wear_credential_manager_enabled"
-  state: ENABLED
-  permission: READ_WRITE
-}
diff --git a/aconfig/trunk_staging/android.net.vcn/TEST_MAPPING b/aconfig/trunk_staging/android.net.vcn/TEST_MAPPING
new file mode 100644
index 00000000..48ee9340
--- /dev/null
+++ b/aconfig/trunk_staging/android.net.vcn/TEST_MAPPING
@@ -0,0 +1,7 @@
+{
+  "imports": [
+    {
+      "path": "frameworks/base/services/core/java/com/android/server/vcn"
+    }
+  ]
+}
\ No newline at end of file
diff --git a/aconfig/trunk_staging/android.net.vcn/allow_disable_ipsec_loss_detector_flag_values.textproto b/aconfig/trunk_staging/android.net.vcn/allow_disable_ipsec_loss_detector_flag_values.textproto
new file mode 100644
index 00000000..51d69e46
--- /dev/null
+++ b/aconfig/trunk_staging/android.net.vcn/allow_disable_ipsec_loss_detector_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.net.vcn"
+  name: "allow_disable_ipsec_loss_detector"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/android.os.vibrator/keyboard_category_enabled_flag_values.textproto b/aconfig/trunk_staging/android.os.vibrator/keyboard_category_enabled_flag_values.textproto
new file mode 100644
index 00000000..29b12be4
--- /dev/null
+++ b/aconfig/trunk_staging/android.os.vibrator/keyboard_category_enabled_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.os.vibrator"
+  name: "keyboard_category_enabled"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/android.os.vibrator/use_vibrator_haptic_feedback_flag_values.textproto b/aconfig/trunk_staging/android.os.vibrator/use_vibrator_haptic_feedback_flag_values.textproto
new file mode 100644
index 00000000..ed2358eb
--- /dev/null
+++ b/aconfig/trunk_staging/android.os.vibrator/use_vibrator_haptic_feedback_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.os.vibrator"
+  name: "use_vibrator_haptic_feedback"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/android.os/adpf_fmq_eager_send_flag_values.textproto b/aconfig/trunk_staging/android.os/adpf_fmq_eager_send_flag_values.textproto
new file mode 100644
index 00000000..cf1804d9
--- /dev/null
+++ b/aconfig/trunk_staging/android.os/adpf_fmq_eager_send_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.os"
+  name: "adpf_fmq_eager_send"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/trunk_staging/android.os/bugreport_mode_max_value_flag_values.textproto b/aconfig/trunk_staging/android.os/bugreport_mode_max_value_flag_values.textproto
new file mode 100644
index 00000000..094b7f93
--- /dev/null
+++ b/aconfig/trunk_staging/android.os/bugreport_mode_max_value_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.os"
+  name: "bugreport_mode_max_value"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/android.provider.configinfrastructure.framework/Android.bp b/aconfig/trunk_staging/android.provider.configinfrastructure.framework/Android.bp
new file mode 100644
index 00000000..8e0013b7
--- /dev/null
+++ b/aconfig/trunk_staging/android.provider.configinfrastructure.framework/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-trunk_staging-android.provider.configinfrastructure.framework-all",
+  package: "android.provider.configinfrastructure.framework",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/trunk_staging/android.security/fix_unlocked_device_required_keys_v2_flag_values.textproto b/aconfig/trunk_staging/android.security/fix_unlocked_device_required_keys_v2_flag_values.textproto
new file mode 100644
index 00000000..24c6f6d6
--- /dev/null
+++ b/aconfig/trunk_staging/android.security/fix_unlocked_device_required_keys_v2_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "android.security"
+  name: "fix_unlocked_device_required_keys_v2"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/trunk_staging/android.uprobestats.flags/enable_uprobestats_flag_values.textproto b/aconfig/trunk_staging/android.uprobestats.flags/enable_uprobestats_flag_values.textproto
deleted file mode 100644
index dfba4d6e..00000000
--- a/aconfig/trunk_staging/android.uprobestats.flags/enable_uprobestats_flag_values.textproto
+++ /dev/null
@@ -1,6 +0,0 @@
-flag_value {
-  package: "android.uprobestats.flags"
-  name: "enable_uprobestats"
-  state: ENABLED
-  permission: READ_ONLY
-}
diff --git a/aconfig/trunk_staging/android.view.accessibility/TEST_MAPPING b/aconfig/trunk_staging/android.view.accessibility/TEST_MAPPING
new file mode 100644
index 00000000..ccac2489
--- /dev/null
+++ b/aconfig/trunk_staging/android.view.accessibility/TEST_MAPPING
@@ -0,0 +1,7 @@
+{
+  "imports": [
+    {
+      "path": "frameworks/base/core/java/android/view/accessibility/TEST_MAPPING"
+    }
+  ]
+}
\ No newline at end of file
diff --git a/aconfig/trunk_staging/android.view.inputmethod/TEST_MAPPING b/aconfig/trunk_staging/android.view.inputmethod/TEST_MAPPING
new file mode 100644
index 00000000..84f31fae
--- /dev/null
+++ b/aconfig/trunk_staging/android.view.inputmethod/TEST_MAPPING
@@ -0,0 +1,7 @@
+{
+ "imports": [
+    {
+      "path": "frameworks/base/services/core/java/com/android/server/inputmethod"
+    }
+  ]
+}
diff --git a/aconfig/trunk_staging/com.android.aconfig.flags/Android.bp b/aconfig/trunk_staging/com.android.aconfig.flags/Android.bp
new file mode 100644
index 00000000..27bbaa30
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.aconfig.flags/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-trunk_staging-com.android.aconfig.flags-all",
+  package: "com.android.aconfig.flags",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/trunk_staging/com.android.art.flags/OWNERS b/aconfig/trunk_staging/com.android.art.flags/OWNERS
new file mode 100644
index 00000000..3414a746
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.art.flags/OWNERS
@@ -0,0 +1 @@
+include platform/art:/OWNERS
diff --git a/aconfig/trunk_staging/com.android.art.flags/m2024_09_ramp_flag_values.textproto b/aconfig/trunk_staging/com.android.art.flags/m2024_09_ramp_flag_values.textproto
new file mode 100644
index 00000000..3e5fb0c2
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.art.flags/m2024_09_ramp_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.art.flags"
+  name: "m2024_09_ramp"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/trunk_staging/com.android.art.flags/m2024_10_ramp_flag_values.textproto b/aconfig/trunk_staging/com.android.art.flags/m2024_10_ramp_flag_values.textproto
new file mode 100644
index 00000000..741cb582
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.art.flags/m2024_10_ramp_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.art.flags"
+  name: "m2024_10_ramp"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/TEST_MAPPING b/aconfig/trunk_staging/com.android.bluetooth.flags/TEST_MAPPING
new file mode 100644
index 00000000..f337913b
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/TEST_MAPPING
@@ -0,0 +1,7 @@
+{
+  "imports": [
+    {
+      "path": "packages/modules/Bluetooth"
+    }
+  ]
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/a2dp_concurrent_source_sink_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/a2dp_concurrent_source_sink_flag_values.textproto
new file mode 100644
index 00000000..cb22de46
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/a2dp_concurrent_source_sink_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "a2dp_concurrent_source_sink"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/a2dp_offload_codec_extensibility_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/a2dp_offload_codec_extensibility_flag_values.textproto
new file mode 100644
index 00000000..127c266a
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/a2dp_offload_codec_extensibility_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "a2dp_offload_codec_extensibility"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/airplane_mode_x_ble_on_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/airplane_mode_x_ble_on_flag_values.textproto
new file mode 100644
index 00000000..cd6a377b
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/airplane_mode_x_ble_on_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "airplane_mode_x_ble_on"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/browsing_refactor_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/asha_asrc_flag_values.textproto
similarity index 77%
rename from aconfig/trunk_staging/com.android.bluetooth.flags/browsing_refactor_flag_values.textproto
rename to aconfig/trunk_staging/com.android.bluetooth.flags/asha_asrc_flag_values.textproto
index da5d1e4d..756bd4a3 100644
--- a/aconfig/trunk_staging/com.android.bluetooth.flags/browsing_refactor_flag_values.textproto
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/asha_asrc_flag_values.textproto
@@ -1,6 +1,6 @@
 flag_value {
   package: "com.android.bluetooth.flags"
-  name: "browsing_refactor"
+  name: "asha_asrc"
   state: ENABLED
   permission: READ_WRITE
 }
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/auto_connect_on_hfp_when_no_a2dp_device_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/auto_connect_on_hfp_when_no_a2dp_device_flag_values.textproto
new file mode 100644
index 00000000..22cc03c8
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/auto_connect_on_hfp_when_no_a2dp_device_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "auto_connect_on_hfp_when_no_a2dp_device"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/auto_on_feature_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/auto_on_feature_flag_values.textproto
new file mode 100644
index 00000000..91fa763d
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/auto_on_feature_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "auto_on_feature"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/bluffs_mitigation_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/bluffs_mitigation_flag_values.textproto
new file mode 100644
index 00000000..3aaff76a
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/bluffs_mitigation_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "bluffs_mitigation"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/bta_dm_disc_stuck_in_cancelling_fix_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/bta_dm_disc_stuck_in_cancelling_fix_flag_values.textproto
new file mode 100644
index 00000000..b0926321
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/bta_dm_disc_stuck_in_cancelling_fix_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "bta_dm_disc_stuck_in_cancelling_fix"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/close_rfcomm_instead_of_reset_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/close_rfcomm_instead_of_reset_flag_values.textproto
new file mode 100644
index 00000000..b6c9d918
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/close_rfcomm_instead_of_reset_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "close_rfcomm_instead_of_reset"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/connect_hid_after_service_discovery_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/connect_hid_after_service_discovery_flag_values.textproto
new file mode 100644
index 00000000..77a677f9
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/connect_hid_after_service_discovery_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "connect_hid_after_service_discovery"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/continue_service_discovery_when_cancel_device_discovery_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/continue_service_discovery_when_cancel_device_discovery_flag_values.textproto
new file mode 100644
index 00000000..7f88b893
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/continue_service_discovery_when_cancel_device_discovery_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "continue_service_discovery_when_cancel_device_discovery"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/correct_bond_type_of_loaded_devices_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/correct_bond_type_of_loaded_devices_flag_values.textproto
new file mode 100644
index 00000000..35dd6f62
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/correct_bond_type_of_loaded_devices_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "correct_bond_type_of_loaded_devices"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/delay_bonding_when_busy_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/delay_bonding_when_busy_flag_values.textproto
new file mode 100644
index 00000000..b7e249c6
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/delay_bonding_when_busy_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "delay_bonding_when_busy"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/divide_long_single_gap_data_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/divide_long_single_gap_data_flag_values.textproto
new file mode 100644
index 00000000..61447271
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/divide_long_single_gap_data_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "divide_long_single_gap_data"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/do_not_replace_existing_cod_with_uncategorized_cod_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/do_not_replace_existing_cod_with_uncategorized_cod_flag_values.textproto
new file mode 100644
index 00000000..e73a0a01
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/do_not_replace_existing_cod_with_uncategorized_cod_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "do_not_replace_existing_cod_with_uncategorized_cod"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/dumpsys_acquire_stack_when_executing_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/dumpsys_acquire_stack_when_executing_flag_values.textproto
new file mode 100644
index 00000000..d80d7d2f
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/dumpsys_acquire_stack_when_executing_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "dumpsys_acquire_stack_when_executing"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/dumpsys_use_passed_in_fd_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/dumpsys_use_passed_in_fd_flag_values.textproto
new file mode 100644
index 00000000..116d965c
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/dumpsys_use_passed_in_fd_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "dumpsys_use_passed_in_fd"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/ensure_valid_adv_flag_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/ensure_valid_adv_flag_flag_values.textproto
new file mode 100644
index 00000000..22423376
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/ensure_valid_adv_flag_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "ensure_valid_adv_flag"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/explicit_kill_from_system_server_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/explicit_kill_from_system_server_flag_values.textproto
new file mode 100644
index 00000000..5a06d64b
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/explicit_kill_from_system_server_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "explicit_kill_from_system_server"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/fix_le_oob_pairing_bypass_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/fix_le_oob_pairing_bypass_flag_values.textproto
new file mode 100644
index 00000000..ea261e66
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/fix_le_oob_pairing_bypass_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "fix_le_oob_pairing_bypass"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/fix_le_pairing_passkey_entry_bypass_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/fix_le_pairing_passkey_entry_bypass_flag_values.textproto
new file mode 100644
index 00000000..8684b95d
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/fix_le_pairing_passkey_entry_bypass_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "fix_le_pairing_passkey_entry_bypass"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/fix_pairing_failure_reason_from_remote_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/fix_pairing_failure_reason_from_remote_flag_values.textproto
new file mode 100644
index 00000000..df785701
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/fix_pairing_failure_reason_from_remote_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "fix_pairing_failure_reason_from_remote"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/force_bredr_for_sdp_retry_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/force_bredr_for_sdp_retry_flag_values.textproto
new file mode 100644
index 00000000..a4206a62
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/force_bredr_for_sdp_retry_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "force_bredr_for_sdp_retry"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/gatt_drop_acl_on_out_of_resources_fix_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/gatt_drop_acl_on_out_of_resources_fix_flag_values.textproto
new file mode 100644
index 00000000..6cd4fdb5
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/gatt_drop_acl_on_out_of_resources_fix_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "gatt_drop_acl_on_out_of_resources_fix"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/gatt_reconnect_on_bt_on_fix_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/gatt_reconnect_on_bt_on_fix_flag_values.textproto
new file mode 100644
index 00000000..80ccb8de
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/gatt_reconnect_on_bt_on_fix_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "gatt_reconnect_on_bt_on_fix"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/get_address_type_api_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/get_address_type_api_flag_values.textproto
new file mode 100644
index 00000000..02eba004
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/get_address_type_api_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "get_address_type_api"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/hfp_codec_aptx_voice_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/hfp_codec_aptx_voice_flag_values.textproto
new file mode 100644
index 00000000..62d99bcf
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/hfp_codec_aptx_voice_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "hfp_codec_aptx_voice"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/ignore_bond_type_for_le_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/ignore_bond_type_for_le_flag_values.textproto
new file mode 100644
index 00000000..8b1fa06b
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/ignore_bond_type_for_le_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "ignore_bond_type_for_le"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/keep_hfp_active_during_leaudio_handover_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/keep_hfp_active_during_leaudio_handover_flag_values.textproto
new file mode 100644
index 00000000..86a4fb65
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/keep_hfp_active_during_leaudio_handover_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "keep_hfp_active_during_leaudio_handover"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/keep_stopped_media_browser_service_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/keep_stopped_media_browser_service_flag_values.textproto
new file mode 100644
index 00000000..7214436d
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/keep_stopped_media_browser_service_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "keep_stopped_media_browser_service"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/le_audio_dev_type_detection_fix_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/le_audio_dev_type_detection_fix_flag_values.textproto
new file mode 100644
index 00000000..6717d405
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/le_audio_dev_type_detection_fix_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "le_audio_dev_type_detection_fix"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/le_audio_fast_bond_params_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/le_audio_fast_bond_params_flag_values.textproto
new file mode 100644
index 00000000..1c05743e
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/le_audio_fast_bond_params_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "le_audio_fast_bond_params"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/le_periodic_scanning_reassembler_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/le_periodic_scanning_reassembler_flag_values.textproto
new file mode 100644
index 00000000..31edf4b1
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/le_periodic_scanning_reassembler_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "le_periodic_scanning_reassembler"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/le_scan_parameters_fix_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/le_scan_parameters_fix_flag_values.textproto
new file mode 100644
index 00000000..a0981833
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/le_scan_parameters_fix_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "le_scan_parameters_fix"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_active_device_manager_group_handling_fix_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_active_device_manager_group_handling_fix_flag_values.textproto
new file mode 100644
index 00000000..2b6c1a23
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_active_device_manager_group_handling_fix_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "leaudio_active_device_manager_group_handling_fix"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_add_sampling_frequencies_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_add_sampling_frequencies_flag_values.textproto
new file mode 100644
index 00000000..475c7019
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_add_sampling_frequencies_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "leaudio_add_sampling_frequencies"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_api_synchronized_block_fix_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_api_synchronized_block_fix_flag_values.textproto
new file mode 100644
index 00000000..e65d26d0
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_api_synchronized_block_fix_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "leaudio_api_synchronized_block_fix"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_broadcast_assistant_handle_command_statuses_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_broadcast_assistant_handle_command_statuses_flag_values.textproto
new file mode 100644
index 00000000..f9c383ee
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_broadcast_assistant_handle_command_statuses_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "leaudio_broadcast_assistant_handle_command_statuses"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_callback_on_group_stream_status_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_callback_on_group_stream_status_flag_values.textproto
new file mode 100644
index 00000000..f69b4329
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_callback_on_group_stream_status_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "leaudio_callback_on_group_stream_status"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_enable_health_based_actions_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_enable_health_based_actions_flag_values.textproto
new file mode 100644
index 00000000..613a8ebd
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_enable_health_based_actions_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "leaudio_enable_health_based_actions"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_mcs_tbs_authorization_rebond_fix_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_mcs_tbs_authorization_rebond_fix_flag_values.textproto
new file mode 100644
index 00000000..f7981227
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_mcs_tbs_authorization_rebond_fix_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "leaudio_mcs_tbs_authorization_rebond_fix"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_quick_leaudio_toggle_switch_fix_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_quick_leaudio_toggle_switch_fix_flag_values.textproto
new file mode 100644
index 00000000..958cb177
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_quick_leaudio_toggle_switch_fix_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "leaudio_quick_leaudio_toggle_switch_fix"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_resume_active_after_hfp_handover_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_resume_active_after_hfp_handover_flag_values.textproto
new file mode 100644
index 00000000..da8655e5
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_resume_active_after_hfp_handover_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "leaudio_resume_active_after_hfp_handover"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_start_stream_race_fix_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_start_stream_race_fix_flag_values.textproto
new file mode 100644
index 00000000..07142917
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_start_stream_race_fix_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "leaudio_start_stream_race_fix"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_unicast_inactivate_device_based_on_context_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_unicast_inactivate_device_based_on_context_flag_values.textproto
new file mode 100644
index 00000000..dc2ba8fc
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_unicast_inactivate_device_based_on_context_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "leaudio_unicast_inactivate_device_based_on_context"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_volume_change_on_ringtone_fix_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_volume_change_on_ringtone_fix_flag_values.textproto
new file mode 100644
index 00000000..3eac0c5a
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/leaudio_volume_change_on_ringtone_fix_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "leaudio_volume_change_on_ringtone_fix"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/load_did_config_from_sysprops_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/load_did_config_from_sysprops_flag_values.textproto
new file mode 100644
index 00000000..6be64b17
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/load_did_config_from_sysprops_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "load_did_config_from_sysprops"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/mfi_has_uuid_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/mfi_has_uuid_flag_values.textproto
new file mode 100644
index 00000000..3d0add36
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/mfi_has_uuid_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "mfi_has_uuid"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/pretend_network_service_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/pretend_network_service_flag_values.textproto
new file mode 100644
index 00000000..39be5818
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/pretend_network_service_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "pretend_network_service"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/read_model_num_fix_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/read_model_num_fix_flag_values.textproto
new file mode 100644
index 00000000..b2fd19f9
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/read_model_num_fix_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "read_model_num_fix"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/report_vsc_data_from_the_gd_controller_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/report_vsc_data_from_the_gd_controller_flag_values.textproto
new file mode 100644
index 00000000..ba5e8eab
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/report_vsc_data_from_the_gd_controller_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "report_vsc_data_from_the_gd_controller"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/reset_pairing_only_for_related_service_discovery_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/reset_pairing_only_for_related_service_discovery_flag_values.textproto
new file mode 100644
index 00000000..3b15ac19
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/reset_pairing_only_for_related_service_discovery_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "reset_pairing_only_for_related_service_discovery"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/rnr_cancel_before_event_race_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/rnr_cancel_before_event_race_flag_values.textproto
new file mode 100644
index 00000000..b6eee145
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/rnr_cancel_before_event_race_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "rnr_cancel_before_event_race"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/rnr_present_during_service_discovery_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/rnr_present_during_service_discovery_flag_values.textproto
new file mode 100644
index 00000000..dba4766a
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/rnr_present_during_service_discovery_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "rnr_present_during_service_discovery"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/rnr_reset_state_at_cancel_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/rnr_reset_state_at_cancel_flag_values.textproto
new file mode 100644
index 00000000..fa8d15b3
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/rnr_reset_state_at_cancel_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "rnr_reset_state_at_cancel"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/separate_service_and_device_discovery_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/separate_service_and_device_discovery_flag_values.textproto
new file mode 100644
index 00000000..2c88f1e5
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/separate_service_and_device_discovery_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "separate_service_and_device_discovery"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/synchronous_bta_sec_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/synchronous_bta_sec_flag_values.textproto
new file mode 100644
index 00000000..8b49bfd0
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/synchronous_bta_sec_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "synchronous_bta_sec"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/update_inquiry_result_on_flag_change_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/update_inquiry_result_on_flag_change_flag_values.textproto
new file mode 100644
index 00000000..9c0decaa
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/update_inquiry_result_on_flag_change_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "update_inquiry_result_on_flag_change"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.bluetooth.flags/use_dsp_codec_when_controller_does_not_support_flag_values.textproto b/aconfig/trunk_staging/com.android.bluetooth.flags/use_dsp_codec_when_controller_does_not_support_flag_values.textproto
new file mode 100644
index 00000000..01d801f9
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.bluetooth.flags/use_dsp_codec_when_controller_does_not_support_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.bluetooth.flags"
+  name: "use_dsp_codec_when_controller_does_not_support"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.cellbroadcastreceiver.flags/Android.bp b/aconfig/trunk_staging/com.android.cellbroadcastreceiver.flags/Android.bp
new file mode 100644
index 00000000..7214119f
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.cellbroadcastreceiver.flags/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-trunk_staging-com.android.cellbroadcastreceiver.flags-all",
+  package: "com.android.cellbroadcastreceiver.flags",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/trunk_staging/com.android.devicelock.flags/Android.bp b/aconfig/trunk_staging/com.android.devicelock.flags/Android.bp
new file mode 100644
index 00000000..23fc0a03
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.devicelock.flags/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-trunk_staging-com.android.devicelock.flags-all",
+  package: "com.android.devicelock.flags",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/trunk_staging/com.android.graphics.bufferstreams.flags/Android.bp b/aconfig/trunk_staging/com.android.graphics.bufferstreams.flags/Android.bp
new file mode 100644
index 00000000..feb5c304
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.graphics.bufferstreams.flags/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-trunk_staging-com.android.graphics.bufferstreams.flags-all",
+  package: "com.android.graphics.bufferstreams.flags",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/trunk_staging/com.android.graphics.surfaceflinger.flags/TEST_MAPPING b/aconfig/trunk_staging/com.android.graphics.surfaceflinger.flags/TEST_MAPPING
new file mode 100644
index 00000000..d0592d17
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.graphics.surfaceflinger.flags/TEST_MAPPING
@@ -0,0 +1,10 @@
+{
+  "imports": [
+    {
+      "path": "frameworks/native"
+    },
+    {
+      "path": "frameworks/native/services/surfaceflinger"
+    }
+  ]
+}
diff --git a/aconfig/trunk_staging/com.android.hardware.camera2/Android.bp b/aconfig/trunk_staging/com.android.hardware.camera2/Android.bp
new file mode 100644
index 00000000..ed0e265b
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.hardware.camera2/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-trunk_staging-com.android.hardware.camera2-all",
+  package: "com.android.hardware.camera2",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/trunk_staging/com.android.hardware.input/TEST_MAPPING b/aconfig/trunk_staging/com.android.hardware.input/TEST_MAPPING
new file mode 100644
index 00000000..7c0dc275
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.hardware.input/TEST_MAPPING
@@ -0,0 +1,7 @@
+{
+  "imports": [
+    {
+      "path": "frameworks/native/services/inputflinger"
+    }
+  ]
+}
\ No newline at end of file
diff --git a/aconfig/trunk_staging/com.android.input.flags/TEST_MAPPING b/aconfig/trunk_staging/com.android.input.flags/TEST_MAPPING
new file mode 100644
index 00000000..7c0dc275
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.input.flags/TEST_MAPPING
@@ -0,0 +1,7 @@
+{
+  "imports": [
+    {
+      "path": "frameworks/native/services/inputflinger"
+    }
+  ]
+}
\ No newline at end of file
diff --git a/aconfig/trunk_staging/com.android.input.flags/enable_gestures_library_timer_provider_flag_values.textproto b/aconfig/trunk_staging/com.android.input.flags/enable_gestures_library_timer_provider_flag_values.textproto
new file mode 100644
index 00000000..091c8fa2
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.input.flags/enable_gestures_library_timer_provider_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.input.flags"
+  name: "enable_gestures_library_timer_provider"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.input.flags/remove_pointer_event_tracking_in_wm_flag_values.textproto b/aconfig/trunk_staging/com.android.input.flags/remove_pointer_event_tracking_in_wm_flag_values.textproto
new file mode 100644
index 00000000..f49f6c82
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.input.flags/remove_pointer_event_tracking_in_wm_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.input.flags"
+  name: "remove_pointer_event_tracking_in_wm"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.intentresolver/bespoke_label_view_flag_values.textproto b/aconfig/trunk_staging/com.android.intentresolver/bespoke_label_view_flag_values.textproto
new file mode 100644
index 00000000..40dc3d95
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.intentresolver/bespoke_label_view_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.intentresolver"
+  name: "bespoke_label_view"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.intentresolver/fix_partial_image_edit_transition_flag_values.textproto b/aconfig/trunk_staging/com.android.intentresolver/fix_partial_image_edit_transition_flag_values.textproto
new file mode 100644
index 00000000..6edc1f4c
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.intentresolver/fix_partial_image_edit_transition_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.intentresolver"
+  name: "fix_partial_image_edit_transition"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.intentresolver/fix_target_list_footer_flag_values.textproto b/aconfig/trunk_staging/com.android.intentresolver/fix_target_list_footer_flag_values.textproto
new file mode 100644
index 00000000..bb7cdf9c
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.intentresolver/fix_target_list_footer_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.intentresolver"
+  name: "fix_target_list_footer"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.internal.camera.flags/lazy_aidl_wait_for_service_flag_values.textproto b/aconfig/trunk_staging/com.android.internal.camera.flags/lazy_aidl_wait_for_service_flag_values.textproto
new file mode 100644
index 00000000..97de2403
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.internal.camera.flags/lazy_aidl_wait_for_service_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.internal.camera.flags"
+  name: "lazy_aidl_wait_for_service"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.internal.camera.flags/log_ultrawide_usage_flag_values.textproto b/aconfig/trunk_staging/com.android.internal.camera.flags/log_ultrawide_usage_flag_values.textproto
new file mode 100644
index 00000000..3a1577a3
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.internal.camera.flags/log_ultrawide_usage_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.internal.camera.flags"
+  name: "log_ultrawide_usage"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.internal.camera.flags/log_zoom_override_usage_flag_values.textproto b/aconfig/trunk_staging/com.android.internal.camera.flags/log_zoom_override_usage_flag_values.textproto
new file mode 100644
index 00000000..9daa87d6
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.internal.camera.flags/log_zoom_override_usage_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.internal.camera.flags"
+  name: "log_zoom_override_usage"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.internal.camera.flags/realtime_priority_bump_flag_values.textproto b/aconfig/trunk_staging/com.android.internal.camera.flags/realtime_priority_bump_flag_values.textproto
new file mode 100644
index 00000000..4e51cad4
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.internal.camera.flags/realtime_priority_bump_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.internal.camera.flags"
+  name: "realtime_priority_bump"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.internal.camera.flags/single_thread_executor_flag_values.textproto b/aconfig/trunk_staging/com.android.internal.camera.flags/single_thread_executor_flag_values.textproto
new file mode 100644
index 00000000..caa225a6
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.internal.camera.flags/single_thread_executor_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.internal.camera.flags"
+  name: "single_thread_executor"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.internal.camera.flags/surface_ipc_flag_values.textproto b/aconfig/trunk_staging/com.android.internal.camera.flags/surface_ipc_flag_values.textproto
new file mode 100644
index 00000000..f95e3f77
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.internal.camera.flags/surface_ipc_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.internal.camera.flags"
+  name: "surface_ipc"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.internal.camera.flags/surface_leak_fix_flag_values.textproto b/aconfig/trunk_staging/com.android.internal.camera.flags/surface_leak_fix_flag_values.textproto
new file mode 100644
index 00000000..9dcf979b
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.internal.camera.flags/surface_leak_fix_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.internal.camera.flags"
+  name: "surface_leak_fix"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.internal.camera.flags/watch_foreground_changes_flag_values.textproto b/aconfig/trunk_staging/com.android.internal.camera.flags/watch_foreground_changes_flag_values.textproto
new file mode 100644
index 00000000..4a7bc869
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.internal.camera.flags/watch_foreground_changes_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.internal.camera.flags"
+  name: "watch_foreground_changes"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.internal.jank/Android.bp b/aconfig/trunk_staging/com.android.internal.jank/Android.bp
new file mode 100644
index 00000000..d4cf386d
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.internal.jank/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-trunk_staging-com.android.internal.jank-all",
+  package: "com.android.internal.jank",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/trunk_staging/com.android.internal.telephony.flags/add_anomaly_when_notify_config_changed_with_invalid_phone_flag_values.textproto b/aconfig/trunk_staging/com.android.internal.telephony.flags/add_anomaly_when_notify_config_changed_with_invalid_phone_flag_values.textproto
new file mode 100644
index 00000000..8ef81bae
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.internal.telephony.flags/add_anomaly_when_notify_config_changed_with_invalid_phone_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.internal.telephony.flags"
+  name: "add_anomaly_when_notify_config_changed_with_invalid_phone"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.internal.telephony.flags/allow_mmtel_in_non_vops_flag_values.textproto b/aconfig/trunk_staging/com.android.internal.telephony.flags/allow_mmtel_in_non_vops_flag_values.textproto
new file mode 100644
index 00000000..9414e4a4
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.internal.telephony.flags/allow_mmtel_in_non_vops_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.internal.telephony.flags"
+  name: "allow_mmtel_in_non_vops"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.internal.telephony.flags/cleanup_open_logical_channel_record_on_dispose_flag_values.textproto b/aconfig/trunk_staging/com.android.internal.telephony.flags/cleanup_open_logical_channel_record_on_dispose_flag_values.textproto
new file mode 100644
index 00000000..3f984fd9
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.internal.telephony.flags/cleanup_open_logical_channel_record_on_dispose_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.internal.telephony.flags"
+  name: "cleanup_open_logical_channel_record_on_dispose"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.internal.telephony.flags/data_only_service_allow_emergency_call_only_flag_values.textproto b/aconfig/trunk_staging/com.android.internal.telephony.flags/data_only_service_allow_emergency_call_only_flag_values.textproto
new file mode 100644
index 00000000..ec13d53a
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.internal.telephony.flags/data_only_service_allow_emergency_call_only_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.internal.telephony.flags"
+  name: "data_only_service_allow_emergency_call_only"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.internal.telephony.flags/fix_crash_on_getting_config_when_phone_is_gone_flag_values.textproto b/aconfig/trunk_staging/com.android.internal.telephony.flags/fix_crash_on_getting_config_when_phone_is_gone_flag_values.textproto
new file mode 100644
index 00000000..9e004db0
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.internal.telephony.flags/fix_crash_on_getting_config_when_phone_is_gone_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.internal.telephony.flags"
+  name: "fix_crash_on_getting_config_when_phone_is_gone"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.internal.telephony.flags/force_iwlan_mms_flag_values.textproto b/aconfig/trunk_staging/com.android.internal.telephony.flags/force_iwlan_mms_flag_values.textproto
new file mode 100644
index 00000000..1052d0a9
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.internal.telephony.flags/force_iwlan_mms_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.internal.telephony.flags"
+  name: "force_iwlan_mms"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.internal.telephony.flags/hide_preinstalled_carrier_app_at_most_once_flag_values.textproto b/aconfig/trunk_staging/com.android.internal.telephony.flags/hide_preinstalled_carrier_app_at_most_once_flag_values.textproto
new file mode 100644
index 00000000..a98707a1
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.internal.telephony.flags/hide_preinstalled_carrier_app_at_most_once_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.internal.telephony.flags"
+  name: "hide_preinstalled_carrier_app_at_most_once"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.internal.telephony.flags/ignore_existing_networks_for_internet_allowed_checking_flag_values.textproto b/aconfig/trunk_staging/com.android.internal.telephony.flags/ignore_existing_networks_for_internet_allowed_checking_flag_values.textproto
new file mode 100644
index 00000000..83e71ae4
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.internal.telephony.flags/ignore_existing_networks_for_internet_allowed_checking_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.internal.telephony.flags"
+  name: "ignore_existing_networks_for_internet_allowed_checking"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.internal.telephony.flags/metered_embb_urlcc_flag_values.textproto b/aconfig/trunk_staging/com.android.internal.telephony.flags/metered_embb_urlcc_flag_values.textproto
new file mode 100644
index 00000000..4e72ad6f
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.internal.telephony.flags/metered_embb_urlcc_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.internal.telephony.flags"
+  name: "metered_embb_urlcc"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.internal.telephony.flags/notify_data_activity_changed_with_slot_flag_values.textproto b/aconfig/trunk_staging/com.android.internal.telephony.flags/notify_data_activity_changed_with_slot_flag_values.textproto
new file mode 100644
index 00000000..519f8f75
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.internal.telephony.flags/notify_data_activity_changed_with_slot_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.internal.telephony.flags"
+  name: "notify_data_activity_changed_with_slot"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.internal.telephony.flags/refine_preferred_data_profile_selection_flag_values.textproto b/aconfig/trunk_staging/com.android.internal.telephony.flags/refine_preferred_data_profile_selection_flag_values.textproto
new file mode 100644
index 00000000..d028cb62
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.internal.telephony.flags/refine_preferred_data_profile_selection_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.internal.telephony.flags"
+  name: "refine_preferred_data_profile_selection"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.internal.telephony.flags/relax_ho_teardown_flag_values.textproto b/aconfig/trunk_staging/com.android.internal.telephony.flags/relax_ho_teardown_flag_values.textproto
new file mode 100644
index 00000000..5405abe8
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.internal.telephony.flags/relax_ho_teardown_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.internal.telephony.flags"
+  name: "relax_ho_teardown"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.internal.telephony.flags/support_phone_uid_check_for_multiuser_flag_values.textproto b/aconfig/trunk_staging/com.android.internal.telephony.flags/support_phone_uid_check_for_multiuser_flag_values.textproto
new file mode 100644
index 00000000..40dbd981
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.internal.telephony.flags/support_phone_uid_check_for_multiuser_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.internal.telephony.flags"
+  name: "support_phone_uid_check_for_multiuser"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.internal.telephony.flags/unthrottle_check_transport_flag_values.textproto b/aconfig/trunk_staging/com.android.internal.telephony.flags/unthrottle_check_transport_flag_values.textproto
new file mode 100644
index 00000000..89b5b67f
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.internal.telephony.flags/unthrottle_check_transport_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.internal.telephony.flags"
+  name: "unthrottle_check_transport"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.internal.telephony.flags/use_alarm_callback_flag_values.textproto b/aconfig/trunk_staging/com.android.internal.telephony.flags/use_alarm_callback_flag_values.textproto
new file mode 100644
index 00000000..a8c51ced
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.internal.telephony.flags/use_alarm_callback_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.internal.telephony.flags"
+  name: "use_alarm_callback"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.providers.contacts.flags/Android.bp b/aconfig/trunk_staging/com.android.providers.contacts.flags/Android.bp
new file mode 100644
index 00000000..ca0e2d89
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.providers.contacts.flags/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-trunk_staging-com.android.providers.contacts.flags-all",
+  package: "com.android.providers.contacts.flags",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/trunk_staging/com.android.server.accessibility/TEST_MAPPING b/aconfig/trunk_staging/com.android.server.accessibility/TEST_MAPPING
new file mode 100644
index 00000000..e1115242
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.server.accessibility/TEST_MAPPING
@@ -0,0 +1,7 @@
+{
+  "imports": [
+    {
+      "path": "frameworks/base/services/accessibility/TEST_MAPPING"
+    }
+  ]
+}
\ No newline at end of file
diff --git a/aconfig/trunk_staging/com.android.server.alarm/TEST_MAPPING b/aconfig/trunk_staging/com.android.server.alarm/TEST_MAPPING
new file mode 100644
index 00000000..990ede40
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.server.alarm/TEST_MAPPING
@@ -0,0 +1,7 @@
+{
+  "imports": [
+    {
+      "path": "frameworks/base/apex/jobscheduler/service/java/com/android/server/alarm"
+    }
+  ]
+}
diff --git a/aconfig/trunk_staging/com.android.server.am/TEST_MAPPING b/aconfig/trunk_staging/com.android.server.am/TEST_MAPPING
new file mode 100644
index 00000000..ea347143
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.server.am/TEST_MAPPING
@@ -0,0 +1,7 @@
+{
+  "imports": [
+    {
+      "path": "frameworks/base/services/core/java/com/android/server/am"
+    }
+  ]
+}
diff --git a/aconfig/trunk_staging/com.android.server.companion.virtual/Android.bp b/aconfig/trunk_staging/com.android.server.companion.virtual/Android.bp
new file mode 100644
index 00000000..48162597
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.server.companion.virtual/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-trunk_staging-com.android.server.companion.virtual-all",
+  package: "com.android.server.companion.virtual",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/trunk_staging/com.android.server.companion.virtual/dump_history_flag_values.textproto b/aconfig/trunk_staging/com.android.server.companion.virtual/dump_history_flag_values.textproto
new file mode 100644
index 00000000..46798015
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.server.companion.virtual/dump_history_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.server.companion.virtual"
+  name: "dump_history"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.server.connectivity/Android.bp b/aconfig/trunk_staging/com.android.server.connectivity/Android.bp
new file mode 100644
index 00000000..75b6c758
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.server.connectivity/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-trunk_staging-com.android.server.connectivity-all",
+  package: "com.android.server.connectivity",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/trunk_staging/com.android.server.contextualsearch.flags/Android.bp b/aconfig/trunk_staging/com.android.server.contextualsearch.flags/Android.bp
new file mode 100644
index 00000000..20aa26a8
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.server.contextualsearch.flags/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-trunk_staging-com.android.server.contextualsearch.flags-all",
+  package: "com.android.server.contextualsearch.flags",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/trunk_staging/com.android.server.devicepolicy.flags/Android.bp b/aconfig/trunk_staging/com.android.server.devicepolicy.flags/Android.bp
new file mode 100644
index 00000000..4d2419e7
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.server.devicepolicy.flags/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-trunk_staging-com.android.server.devicepolicy.flags-all",
+  package: "com.android.server.devicepolicy.flags",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/trunk_staging/com.android.server.display.feature.flags/TEST_MAPPING b/aconfig/trunk_staging/com.android.server.display.feature.flags/TEST_MAPPING
new file mode 100644
index 00000000..477860d3
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.server.display.feature.flags/TEST_MAPPING
@@ -0,0 +1,7 @@
+{
+  "imports": [
+    {
+      "path": "frameworks/base/services/core/java/com/android/server/display"
+    }
+  ]
+}
diff --git a/aconfig/trunk_staging/com.android.server.locksettings/Android.bp b/aconfig/trunk_staging/com.android.server.locksettings/Android.bp
new file mode 100644
index 00000000..82ae828a
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.server.locksettings/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-trunk_staging-com.android.server.locksettings-all",
+  package: "com.android.server.locksettings",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/trunk_staging/com.android.server.notification/TEST_MAPPING b/aconfig/trunk_staging/com.android.server.notification/TEST_MAPPING
new file mode 100644
index 00000000..43fe2935
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.server.notification/TEST_MAPPING
@@ -0,0 +1,7 @@
+{
+  "imports": [
+    {
+      "path": "cts/tests/tests/notification"
+    }
+  ]
+}
\ No newline at end of file
diff --git a/aconfig/trunk_staging/com.android.server.os/Android.bp b/aconfig/trunk_staging/com.android.server.os/Android.bp
new file mode 100644
index 00000000..dd1b61d2
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.server.os/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-trunk_staging-com.android.server.os-all",
+  package: "com.android.server.os",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/trunk_staging/com.android.server.pm/Android.bp b/aconfig/trunk_staging/com.android.server.pm/Android.bp
new file mode 100644
index 00000000..3da38b2e
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.server.pm/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-trunk_staging-com.android.server.pm-all",
+  package: "com.android.server.pm",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/trunk_staging/com.android.server.security/Android.bp b/aconfig/trunk_staging/com.android.server.security/Android.bp
new file mode 100644
index 00000000..50a51927
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.server.security/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-trunk_staging-com.android.server.security-all",
+  package: "com.android.server.security",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/trunk_staging/com.android.settings.connecteddevice.flags/Android.bp b/aconfig/trunk_staging/com.android.settings.connecteddevice.flags/Android.bp
new file mode 100644
index 00000000..023eff19
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.settings.connecteddevice.flags/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-trunk_staging-com.android.settings.connecteddevice.flags-all",
+  package: "com.android.settings.connecteddevice.flags",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/trunk_staging/com.android.settings.flags/enable_bluetooth_profile_toggle_visibility_checker_flag_values.textproto b/aconfig/trunk_staging/com.android.settings.flags/enable_bluetooth_profile_toggle_visibility_checker_flag_values.textproto
new file mode 100644
index 00000000..df9bd222
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.settings.flags/enable_bluetooth_profile_toggle_visibility_checker_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.settings.flags"
+  name: "enable_bluetooth_profile_toggle_visibility_checker"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.settings.flags/enable_subsequent_pair_settings_integration_flag_values.textproto b/aconfig/trunk_staging/com.android.settings.flags/enable_subsequent_pair_settings_integration_flag_values.textproto
new file mode 100644
index 00000000..9fcf560e
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.settings.flags/enable_subsequent_pair_settings_integration_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.settings.flags"
+  name: "enable_subsequent_pair_settings_integration"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.settings.flags/internet_preference_controller_v2_flag_values.textproto b/aconfig/trunk_staging/com.android.settings.flags/internet_preference_controller_v2_flag_values.textproto
new file mode 100644
index 00000000..34d69472
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.settings.flags/internet_preference_controller_v2_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.settings.flags"
+  name: "internet_preference_controller_v2"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.settings.keyboard/Android.bp b/aconfig/trunk_staging/com.android.settings.keyboard/Android.bp
new file mode 100644
index 00000000..27b2f14d
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.settings.keyboard/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-trunk_staging-com.android.settings.keyboard-all",
+  package: "com.android.settings.keyboard",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/trunk_staging/com.android.settingslib.flags/enable_cached_bluetooth_device_dedup_flag_values.textproto b/aconfig/trunk_staging/com.android.settingslib.flags/enable_cached_bluetooth_device_dedup_flag_values.textproto
new file mode 100644
index 00000000..518035e5
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.settingslib.flags/enable_cached_bluetooth_device_dedup_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.settingslib.flags"
+  name: "enable_cached_bluetooth_device_dedup"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.systemui.aconfig/Android.bp b/aconfig/trunk_staging/com.android.systemui.aconfig/Android.bp
new file mode 100644
index 00000000..f6ea2426
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.systemui.aconfig/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-trunk_staging-com.android.systemui.aconfig-all",
+  package: "com.android.systemui.aconfig",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/trunk_staging/com.android.systemui.communal/Android.bp b/aconfig/trunk_staging/com.android.systemui.communal/Android.bp
new file mode 100644
index 00000000..f45237d1
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.systemui.communal/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-trunk_staging-com.android.systemui.communal-all",
+  package: "com.android.systemui.communal",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/trunk_staging/com.android.systemui/TEST_MAPPING b/aconfig/trunk_staging/com.android.systemui/TEST_MAPPING
new file mode 100644
index 00000000..44ac02fa
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.systemui/TEST_MAPPING
@@ -0,0 +1,10 @@
+{
+  "imports": [
+    {
+      "path": "frameworks/base/packages/SystemUI"
+    },
+    {
+      "path": "frameworks/base/services/core/java/com/android/server/notification"
+    }
+  ]
+}
diff --git a/aconfig/trunk_staging/com.android.systemui/bp_talkback_flag_values.textproto b/aconfig/trunk_staging/com.android.systemui/bp_talkback_flag_values.textproto
new file mode 100644
index 00000000..fa544966
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.systemui/bp_talkback_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.systemui"
+  name: "bp_talkback"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.systemui/centralized_status_bar_height_fix_flag_values.textproto b/aconfig/trunk_staging/com.android.systemui/centralized_status_bar_height_fix_flag_values.textproto
new file mode 100644
index 00000000..b743da83
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.systemui/centralized_status_bar_height_fix_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.systemui"
+  name: "centralized_status_bar_height_fix"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.systemui/constraint_bp_flag_values.textproto b/aconfig/trunk_staging/com.android.systemui/constraint_bp_flag_values.textproto
new file mode 100644
index 00000000..f7a579d8
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.systemui/constraint_bp_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.systemui"
+  name: "constraint_bp"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.systemui/haptic_brightness_slider_flag_values.textproto b/aconfig/trunk_staging/com.android.systemui/haptic_brightness_slider_flag_values.textproto
new file mode 100644
index 00000000..d9c76f87
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.systemui/haptic_brightness_slider_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.systemui"
+  name: "haptic_brightness_slider"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.systemui/haptic_volume_slider_flag_values.textproto b/aconfig/trunk_staging/com.android.systemui/haptic_volume_slider_flag_values.textproto
new file mode 100644
index 00000000..753b3736
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.systemui/haptic_volume_slider_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.systemui"
+  name: "haptic_volume_slider"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.systemui/lockscreen_preview_renderer_create_on_main_thread_flag_values.textproto b/aconfig/trunk_staging/com.android.systemui/lockscreen_preview_renderer_create_on_main_thread_flag_values.textproto
new file mode 100644
index 00000000..d18f81c5
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.systemui/lockscreen_preview_renderer_create_on_main_thread_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.systemui"
+  name: "lockscreen_preview_renderer_create_on_main_thread"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.systemui/privacy_dot_unfold_wrong_corner_fix_flag_values.textproto b/aconfig/trunk_staging/com.android.systemui/privacy_dot_unfold_wrong_corner_fix_flag_values.textproto
new file mode 100644
index 00000000..d38aafd0
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.systemui/privacy_dot_unfold_wrong_corner_fix_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.systemui"
+  name: "privacy_dot_unfold_wrong_corner_fix"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.systemui/pss_app_selector_abrupt_exit_fix_flag_values.textproto b/aconfig/trunk_staging/com.android.systemui/pss_app_selector_abrupt_exit_fix_flag_values.textproto
new file mode 100644
index 00000000..b9db0e32
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.systemui/pss_app_selector_abrupt_exit_fix_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.systemui"
+  name: "pss_app_selector_abrupt_exit_fix"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.systemui/qs_new_pipeline_flag_values.textproto b/aconfig/trunk_staging/com.android.systemui/qs_new_pipeline_flag_values.textproto
new file mode 100644
index 00000000..7d585d00
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.systemui/qs_new_pipeline_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.systemui"
+  name: "qs_new_pipeline"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.systemui/screenshot_private_profile_accessibility_announcement_fix_flag_values.textproto b/aconfig/trunk_staging/com.android.systemui/screenshot_private_profile_accessibility_announcement_fix_flag_values.textproto
new file mode 100644
index 00000000..19345a5a
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.systemui/screenshot_private_profile_accessibility_announcement_fix_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.systemui"
+  name: "screenshot_private_profile_accessibility_announcement_fix"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.systemui/screenshot_private_profile_behavior_fix_flag_values.textproto b/aconfig/trunk_staging/com.android.systemui/screenshot_private_profile_behavior_fix_flag_values.textproto
new file mode 100644
index 00000000..901a9951
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.systemui/screenshot_private_profile_behavior_fix_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.systemui"
+  name: "screenshot_private_profile_behavior_fix"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.systemui/screenshot_save_image_exporter_flag_values.textproto b/aconfig/trunk_staging/com.android.systemui/screenshot_save_image_exporter_flag_values.textproto
new file mode 100644
index 00000000..e17529a4
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.systemui/screenshot_save_image_exporter_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.systemui"
+  name: "screenshot_save_image_exporter"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.systemui/screenshot_shelf_ui2_flag_values.textproto b/aconfig/trunk_staging/com.android.systemui/screenshot_shelf_ui2_flag_values.textproto
new file mode 100644
index 00000000..9070838c
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.systemui/screenshot_shelf_ui2_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.systemui"
+  name: "screenshot_shelf_ui2"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.systemui/truncated_status_bar_icons_fix_flag_values.textproto b/aconfig/trunk_staging/com.android.systemui/truncated_status_bar_icons_fix_flag_values.textproto
new file mode 100644
index 00000000..d43a77e8
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.systemui/truncated_status_bar_icons_fix_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.systemui"
+  name: "truncated_status_bar_icons_fix"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.telephony.phone.flags/Android.bp b/aconfig/trunk_staging/com.android.telephony.phone.flags/Android.bp
new file mode 100644
index 00000000..8bd2b80b
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.telephony.phone.flags/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-trunk_staging-com.android.telephony.phone.flags-all",
+  package: "com.android.telephony.phone.flags",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/aconfig/trunk_staging/com.android.text.flags/deprecate_ui_fonts_flag_values.textproto b/aconfig/trunk_staging/com.android.text.flags/deprecate_ui_fonts_flag_values.textproto
new file mode 100644
index 00000000..da2950d9
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.text.flags/deprecate_ui_fonts_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.text.flags"
+  name: "deprecate_ui_fonts"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.text.flags/fix_double_underline_flag_values.textproto b/aconfig/trunk_staging/com.android.text.flags/fix_double_underline_flag_values.textproto
new file mode 100644
index 00000000..00bdaceb
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.text.flags/fix_double_underline_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.text.flags"
+  name: "fix_double_underline"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.text.flags/fix_font_update_failure_flag_values.textproto b/aconfig/trunk_staging/com.android.text.flags/fix_font_update_failure_flag_values.textproto
new file mode 100644
index 00000000..ce278209
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.text.flags/fix_font_update_failure_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.text.flags"
+  name: "fix_font_update_failure"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/trunk_staging/com.android.text.flags/fix_misaligned_context_menu_flag_values.textproto b/aconfig/trunk_staging/com.android.text.flags/fix_misaligned_context_menu_flag_values.textproto
new file mode 100644
index 00000000..7b4476ab
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.text.flags/fix_misaligned_context_menu_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.text.flags"
+  name: "fix_misaligned_context_menu"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.text.flags/icu_bidi_migration_flag_values.textproto b/aconfig/trunk_staging/com.android.text.flags/icu_bidi_migration_flag_values.textproto
new file mode 100644
index 00000000..f592eba7
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.text.flags/icu_bidi_migration_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.text.flags"
+  name: "icu_bidi_migration"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.text.flags/lazy_variation_instance_flag_values.textproto b/aconfig/trunk_staging/com.android.text.flags/lazy_variation_instance_flag_values.textproto
new file mode 100644
index 00000000..98b9d3af
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.text.flags/lazy_variation_instance_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.text.flags"
+  name: "lazy_variation_instance"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/trunk_staging/com.android.text.flags/phrase_strict_fallback_flag_values.textproto b/aconfig/trunk_staging/com.android.text.flags/phrase_strict_fallback_flag_values.textproto
new file mode 100644
index 00000000..714c437a
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.text.flags/phrase_strict_fallback_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.text.flags"
+  name: "phrase_strict_fallback"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.text.flags/portuguese_hyphenator_flag_values.textproto b/aconfig/trunk_staging/com.android.text.flags/portuguese_hyphenator_flag_values.textproto
new file mode 100644
index 00000000..666caeca
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.text.flags/portuguese_hyphenator_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.text.flags"
+  name: "portuguese_hyphenator"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.text.flags/vendor_custom_locale_fallback_flag_values.textproto b/aconfig/trunk_staging/com.android.text.flags/vendor_custom_locale_fallback_flag_values.textproto
new file mode 100644
index 00000000..5958a97f
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.text.flags/vendor_custom_locale_fallback_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.text.flags"
+  name: "vendor_custom_locale_fallback"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/trunk_staging/com.android.window.flags/TEST_MAPPING b/aconfig/trunk_staging/com.android.window.flags/TEST_MAPPING
new file mode 100644
index 00000000..d0592d17
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.window.flags/TEST_MAPPING
@@ -0,0 +1,10 @@
+{
+  "imports": [
+    {
+      "path": "frameworks/native"
+    },
+    {
+      "path": "frameworks/native/services/surfaceflinger"
+    }
+  ]
+}
diff --git a/aconfig/trunk_staging/com.android.window.flags/activity_snapshot_by_default_flag_values.textproto b/aconfig/trunk_staging/com.android.window.flags/activity_snapshot_by_default_flag_values.textproto
new file mode 100644
index 00000000..a6801519
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.window.flags/activity_snapshot_by_default_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.window.flags"
+  name: "activity_snapshot_by_default"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/trunk_staging/com.android.window.flags/activity_window_info_flag_flag_values.textproto b/aconfig/trunk_staging/com.android.window.flags/activity_window_info_flag_flag_values.textproto
new file mode 100644
index 00000000..edda5051
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.window.flags/activity_window_info_flag_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.window.flags"
+  name: "activity_window_info_flag"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/trunk_staging/com.android.window.flags/always_defer_transition_when_apply_wct_flag_values.textproto b/aconfig/trunk_staging/com.android.window.flags/always_defer_transition_when_apply_wct_flag_values.textproto
new file mode 100644
index 00000000..1ca35a80
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.window.flags/always_defer_transition_when_apply_wct_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.window.flags"
+  name: "always_defer_transition_when_apply_wct"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.window.flags/bundle_client_transaction_flag_flag_values.textproto b/aconfig/trunk_staging/com.android.window.flags/bundle_client_transaction_flag_flag_values.textproto
new file mode 100644
index 00000000..221b52ff
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.window.flags/bundle_client_transaction_flag_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.window.flags"
+  name: "bundle_client_transaction_flag"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/trunk_staging/com.android.window.flags/defer_display_updates_flag_values.textproto b/aconfig/trunk_staging/com.android.window.flags/defer_display_updates_flag_values.textproto
new file mode 100644
index 00000000..38314f28
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.window.flags/defer_display_updates_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.window.flags"
+  name: "defer_display_updates"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/trunk_staging/com.android.window.flags/disable_object_pool_flag_values.textproto b/aconfig/trunk_staging/com.android.window.flags/disable_object_pool_flag_values.textproto
new file mode 100644
index 00000000..d335d064
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.window.flags/disable_object_pool_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.window.flags"
+  name: "disable_object_pool"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/trunk_staging/com.android.window.flags/do_not_skip_ime_by_target_visibility_flag_values.textproto b/aconfig/trunk_staging/com.android.window.flags/do_not_skip_ime_by_target_visibility_flag_values.textproto
new file mode 100644
index 00000000..dbfc7894
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.window.flags/do_not_skip_ime_by_target_visibility_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.window.flags"
+  name: "do_not_skip_ime_by_target_visibility"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.window.flags/ensure_wallpaper_in_transitions_flag_values.textproto b/aconfig/trunk_staging/com.android.window.flags/embedded_activity_back_nav_flag_flag_values.textproto
similarity index 69%
rename from aconfig/trunk_staging/com.android.window.flags/ensure_wallpaper_in_transitions_flag_values.textproto
rename to aconfig/trunk_staging/com.android.window.flags/embedded_activity_back_nav_flag_flag_values.textproto
index 6668a098..01993cb8 100644
--- a/aconfig/trunk_staging/com.android.window.flags/ensure_wallpaper_in_transitions_flag_values.textproto
+++ b/aconfig/trunk_staging/com.android.window.flags/embedded_activity_back_nav_flag_flag_values.textproto
@@ -1,6 +1,6 @@
 flag_value {
   package: "com.android.window.flags"
-  name: "ensure_wallpaper_in_transitions"
+  name: "embedded_activity_back_nav_flag"
   state: ENABLED
   permission: READ_WRITE
 }
diff --git a/aconfig/trunk_staging/com.android.window.flags/enforce_shell_thread_model_flag_values.textproto b/aconfig/trunk_staging/com.android.window.flags/enforce_shell_thread_model_flag_values.textproto
new file mode 100644
index 00000000..1f1be81b
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.window.flags/enforce_shell_thread_model_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.window.flags"
+  name: "enforce_shell_thread_model"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/trunk_staging/com.android.window.flags/fix_no_container_update_without_resize_flag_values.textproto b/aconfig/trunk_staging/com.android.window.flags/fix_no_container_update_without_resize_flag_values.textproto
new file mode 100644
index 00000000..afdf387e
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.window.flags/fix_no_container_update_without_resize_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.window.flags"
+  name: "fix_no_container_update_without_resize"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/trunk_staging/com.android.window.flags/fix_pip_restore_to_overlay_flag_values.textproto b/aconfig/trunk_staging/com.android.window.flags/fix_pip_restore_to_overlay_flag_values.textproto
new file mode 100644
index 00000000..ff9c4fd3
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.window.flags/fix_pip_restore_to_overlay_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.window.flags"
+  name: "fix_pip_restore_to_overlay"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.window.flags/fullscreen_dim_flag_flag_values.textproto b/aconfig/trunk_staging/com.android.window.flags/fullscreen_dim_flag_flag_values.textproto
new file mode 100644
index 00000000..a76cae4a
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.window.flags/fullscreen_dim_flag_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.window.flags"
+  name: "fullscreen_dim_flag"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.window.flags/insets_control_changed_item_flag_values.textproto b/aconfig/trunk_staging/com.android.window.flags/insets_control_changed_item_flag_values.textproto
new file mode 100644
index 00000000..2dbde3b7
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.window.flags/insets_control_changed_item_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.window.flags"
+  name: "insets_control_changed_item"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.android.window.flags/introduce_smoother_dimmer_flag_values.textproto b/aconfig/trunk_staging/com.android.window.flags/introduce_smoother_dimmer_flag_values.textproto
new file mode 100644
index 00000000..843fbad5
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.window.flags/introduce_smoother_dimmer_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.window.flags"
+  name: "introduce_smoother_dimmer"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/trunk_staging/com.android.window.flags/keyguard_appear_transition_flag_values.textproto b/aconfig/trunk_staging/com.android.window.flags/keyguard_appear_transition_flag_values.textproto
new file mode 100644
index 00000000..1703ca3f
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.window.flags/keyguard_appear_transition_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.window.flags"
+  name: "keyguard_appear_transition"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/trunk_staging/com.android.window.flags/per_user_display_window_settings_flag_values.textproto b/aconfig/trunk_staging/com.android.window.flags/per_user_display_window_settings_flag_values.textproto
new file mode 100644
index 00000000..1d691543
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.window.flags/per_user_display_window_settings_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.window.flags"
+  name: "per_user_display_window_settings"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/trunk_staging/com.android.window.flags/remove_prepare_surface_in_placement_flag_values.textproto b/aconfig/trunk_staging/com.android.window.flags/remove_prepare_surface_in_placement_flag_values.textproto
new file mode 100644
index 00000000..1c847d9b
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.window.flags/remove_prepare_surface_in_placement_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.window.flags"
+  name: "remove_prepare_surface_in_placement"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/trunk_staging/com.android.window.flags/skip_sleeping_when_switching_display_flag_values.textproto b/aconfig/trunk_staging/com.android.window.flags/skip_sleeping_when_switching_display_flag_values.textproto
new file mode 100644
index 00000000..27654d88
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.window.flags/skip_sleeping_when_switching_display_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.window.flags"
+  name: "skip_sleeping_when_switching_display"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/trunk_staging/com.android.window.flags/window_session_relayout_info_flag_values.textproto b/aconfig/trunk_staging/com.android.window.flags/window_session_relayout_info_flag_values.textproto
new file mode 100644
index 00000000..8ab8a120
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.window.flags/window_session_relayout_info_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.window.flags"
+  name: "window_session_relayout_info"
+  state: ENABLED
+  permission: READ_ONLY
+}
diff --git a/aconfig/trunk_staging/com.android.window.flags/window_token_config_thread_safe_flag_values.textproto b/aconfig/trunk_staging/com.android.window.flags/window_token_config_thread_safe_flag_values.textproto
new file mode 100644
index 00000000..e5ec4546
--- /dev/null
+++ b/aconfig/trunk_staging/com.android.window.flags/window_token_config_thread_safe_flag_values.textproto
@@ -0,0 +1,6 @@
+flag_value {
+  package: "com.android.window.flags"
+  name: "window_token_config_thread_safe"
+  state: ENABLED
+  permission: READ_WRITE
+}
diff --git a/aconfig/trunk_staging/com.google.android.platform.launcher.aconfig.flags/Android.bp b/aconfig/trunk_staging/com.google.android.platform.launcher.aconfig.flags/Android.bp
new file mode 100644
index 00000000..9e453a9c
--- /dev/null
+++ b/aconfig/trunk_staging/com.google.android.platform.launcher.aconfig.flags/Android.bp
@@ -0,0 +1,21 @@
+// Copyright 2024 Google Inc. All rights reserved.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+aconfig_values {
+  name: "aconfig-values-platform_build_release-trunk_staging-com.google.android.platform.launcher.aconfig.flags-all",
+  package: "com.google.android.platform.launcher.aconfig.flags",
+  srcs: [
+    "*_flag_values.textproto",
+  ]
+}
diff --git a/flag_values/ap4a/RELEASE_PLATFORM_SECURITY_PATCH.textproto b/flag_values/ap4a/RELEASE_PLATFORM_SECURITY_PATCH.textproto
index 8853c743..61094716 100644
--- a/flag_values/ap4a/RELEASE_PLATFORM_SECURITY_PATCH.textproto
+++ b/flag_values/ap4a/RELEASE_PLATFORM_SECURITY_PATCH.textproto
@@ -1,4 +1,4 @@
 name: "RELEASE_PLATFORM_SECURITY_PATCH"
 value: {
   string_value: "2025-01-05"
-}
+}
\ No newline at end of file
diff --git a/flag_values/trunk_staging/RELEASE_APPFUNCTION_SIDECAR.textproto b/flag_values/trunk_staging/RELEASE_APPFUNCTION_SIDECAR.textproto
index 87beb96e..e5b76ccb 100644
--- a/flag_values/trunk_staging/RELEASE_APPFUNCTION_SIDECAR.textproto
+++ b/flag_values/trunk_staging/RELEASE_APPFUNCTION_SIDECAR.textproto
@@ -1,4 +1,4 @@
-name: "RELEASE_APPFUNCTION_SIDECAR"
-value: {
-  bool_value: true
-}
+name:  "RELEASE_APPFUNCTION_SIDECAR"
+value:  {
+  bool_value:  true
+}
\ No newline at end of file
diff --git a/flag_values/trunk_staging/RELEASE_AVF_ENABLE_TPU_ASSIGNABLE_DEVICE.textproto b/flag_values/trunk_staging/RELEASE_AVF_ENABLE_TPU_ASSIGNABLE_DEVICE.textproto
index eaacdcc0..ed85ec5b 100644
--- a/flag_values/trunk_staging/RELEASE_AVF_ENABLE_TPU_ASSIGNABLE_DEVICE.textproto
+++ b/flag_values/trunk_staging/RELEASE_AVF_ENABLE_TPU_ASSIGNABLE_DEVICE.textproto
@@ -1,4 +1,4 @@
-name: "RELEASE_AVF_ENABLE_TPU_ASSIGNABLE_DEVICE"
-value: {
-  bool_value: true
+name:  "RELEASE_AVF_ENABLE_TPU_ASSIGNABLE_DEVICE"
+value:  {
+  bool_value:  true
 }
diff --git a/flag_values/trunk_staging/RELEASE_AVF_ENABLE_WIDEVINE_PVM.textproto b/flag_values/trunk_staging/RELEASE_AVF_ENABLE_WIDEVINE_PVM.textproto
new file mode 100644
index 00000000..ffdabf95
--- /dev/null
+++ b/flag_values/trunk_staging/RELEASE_AVF_ENABLE_WIDEVINE_PVM.textproto
@@ -0,0 +1,4 @@
+name:  "RELEASE_AVF_ENABLE_WIDEVINE_PVM"
+value:  {
+  bool_value:  true
+}
diff --git a/flag_values/trunk_staging/RELEASE_AVF_IMPROVE_DEBUGGABLE_VMS.textproto b/flag_values/trunk_staging/RELEASE_AVF_IMPROVE_DEBUGGABLE_VMS.textproto
index 2973d176..9c3ca6b5 100644
--- a/flag_values/trunk_staging/RELEASE_AVF_IMPROVE_DEBUGGABLE_VMS.textproto
+++ b/flag_values/trunk_staging/RELEASE_AVF_IMPROVE_DEBUGGABLE_VMS.textproto
@@ -1,4 +1,4 @@
-name: "RELEASE_AVF_IMPROVE_DEBUGGABLE_VMS"
-value: {
-  bool_value: true
+name:  "RELEASE_AVF_IMPROVE_DEBUGGABLE_VMS"
+value:  {
+  bool_value:  true
 }
diff --git a/flag_values/trunk_staging/RELEASE_AVF_SUPPORT_LONG_RUNNING_VMS.textproto b/flag_values/trunk_staging/RELEASE_AVF_SUPPORT_LONG_RUNNING_VMS.textproto
new file mode 100644
index 00000000..48050256
--- /dev/null
+++ b/flag_values/trunk_staging/RELEASE_AVF_SUPPORT_LONG_RUNNING_VMS.textproto
@@ -0,0 +1,4 @@
+name:  "RELEASE_AVF_SUPPORT_LONG_RUNNING_VMS"
+value:  {
+  bool_value:  true
+}
diff --git a/flag_values/trunk_staging/RELEASE_GOOGLE_AKITA_16K_DEVELOPER_OPTION.textproto b/flag_values/trunk_staging/RELEASE_GOOGLE_AKITA_16K_DEVELOPER_OPTION.textproto
deleted file mode 100644
index 8b97f2d2..00000000
--- a/flag_values/trunk_staging/RELEASE_GOOGLE_AKITA_16K_DEVELOPER_OPTION.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_GOOGLE_AKITA_16K_DEVELOPER_OPTION"
-value: {
-  bool_value: true
-}
diff --git a/flag_values/trunk_staging/RELEASE_GOOGLE_HUSKY_16K_DEVELOPER_OPTION.textproto b/flag_values/trunk_staging/RELEASE_GOOGLE_HUSKY_16K_DEVELOPER_OPTION.textproto
deleted file mode 100644
index 7a40dccf..00000000
--- a/flag_values/trunk_staging/RELEASE_GOOGLE_HUSKY_16K_DEVELOPER_OPTION.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_GOOGLE_HUSKY_16K_DEVELOPER_OPTION"
-value: {
-  bool_value: true
-}
diff --git a/flag_values/trunk_staging/RELEASE_GOOGLE_SHIBA_16K_DEVELOPER_OPTION.textproto b/flag_values/trunk_staging/RELEASE_GOOGLE_SHIBA_16K_DEVELOPER_OPTION.textproto
deleted file mode 100644
index 5057404f..00000000
--- a/flag_values/trunk_staging/RELEASE_GOOGLE_SHIBA_16K_DEVELOPER_OPTION.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_GOOGLE_SHIBA_16K_DEVELOPER_OPTION"
-value: {
-  bool_value: true
-}
diff --git a/flag_values/trunk_staging/RELEASE_LIBBINDER_CLIENT_CACHE.textproto b/flag_values/trunk_staging/RELEASE_LIBBINDER_CLIENT_CACHE.textproto
index 162f55fe..97e354b6 100644
--- a/flag_values/trunk_staging/RELEASE_LIBBINDER_CLIENT_CACHE.textproto
+++ b/flag_values/trunk_staging/RELEASE_LIBBINDER_CLIENT_CACHE.textproto
@@ -1,4 +1,4 @@
-name: "RELEASE_LIBBINDER_CLIENT_CACHE"
-value: {
-  bool_value: true
+name:  "RELEASE_LIBBINDER_CLIENT_CACHE"
+value:  {
+  bool_value:  true
 }
diff --git a/flag_values/trunk_staging/RELEASE_LIBPOWER_NO_LOCK_BINDER_TXN.textproto b/flag_values/trunk_staging/RELEASE_LIBPOWER_NO_LOCK_BINDER_TXN.textproto
index ae7d1bc8..ced836ea 100644
--- a/flag_values/trunk_staging/RELEASE_LIBPOWER_NO_LOCK_BINDER_TXN.textproto
+++ b/flag_values/trunk_staging/RELEASE_LIBPOWER_NO_LOCK_BINDER_TXN.textproto
@@ -1,4 +1,4 @@
-name: "RELEASE_LIBPOWER_NO_LOCK_BINDER_TXN"
+name:  "RELEASE_LIBPOWER_NO_LOCK_BINDER_TXN"
 value: {
   bool_value: true
 }
diff --git a/flag_values/trunk_staging/RELEASE_PLATFORM_SECURITY_PATCH.textproto b/flag_values/trunk_staging/RELEASE_PLATFORM_SECURITY_PATCH.textproto
index ce29523c..8853c743 100644
--- a/flag_values/trunk_staging/RELEASE_PLATFORM_SECURITY_PATCH.textproto
+++ b/flag_values/trunk_staging/RELEASE_PLATFORM_SECURITY_PATCH.textproto
@@ -1,4 +1,4 @@
 name: "RELEASE_PLATFORM_SECURITY_PATCH"
 value: {
-  string_value: "2024-11-05"
+  string_value: "2025-01-05"
 }
diff --git a/flag_values/trunk_staging/RELEASE_READ_FROM_NEW_STORAGE.textproto b/flag_values/trunk_staging/RELEASE_READ_FROM_NEW_STORAGE.textproto
deleted file mode 100644
index 6cb08946..00000000
--- a/flag_values/trunk_staging/RELEASE_READ_FROM_NEW_STORAGE.textproto
+++ /dev/null
@@ -1,4 +0,0 @@
-name: "RELEASE_READ_FROM_NEW_STORAGE"
-value: {
-  bool_value: true
-}
diff --git a/gms_mainline/optional/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_REMOTEKEYPROVISIONING.textproto b/gms_mainline/optional/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_REMOTEKEYPROVISIONING.textproto
new file mode 100644
index 00000000..965e4cad
--- /dev/null
+++ b/gms_mainline/optional/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_REMOTEKEYPROVISIONING.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_REMOTEKEYPROVISIONING"
+value: {
+  string_value: "rkpd.google.contributions.prebuilt"
+}
diff --git a/gms_mainline/optional/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_UWB.textproto b/gms_mainline/optional/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_UWB.textproto
new file mode 100644
index 00000000..6f8574f3
--- /dev/null
+++ b/gms_mainline/optional/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_UWB.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_UWB"
+value: {
+  string_value: "uwb.google.contributions.prebuilt"
+}
diff --git a/gms_mainline/optional/release_config_map.textproto b/gms_mainline/optional/release_config_map.textproto
new file mode 100644
index 00000000..3237b81f
--- /dev/null
+++ b/gms_mainline/optional/release_config_map.textproto
@@ -0,0 +1 @@
+default_containers: "vendor"
diff --git a/gms_mainline/optional/release_configs/ap3a.textproto b/gms_mainline/optional/release_configs/ap3a.textproto
new file mode 100644
index 00000000..c25b670b
--- /dev/null
+++ b/gms_mainline/optional/release_configs/ap3a.textproto
@@ -0,0 +1 @@
+name: "ap3a"
diff --git a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_ADBD.textproto b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_ADBD.textproto
new file mode 100644
index 00000000..63be0c04
--- /dev/null
+++ b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_ADBD.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_ADBD"
+value: {
+  string_value: "adbd.google.contributions.prebuilt"
+}
diff --git a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_ADSERVICES.textproto b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_ADSERVICES.textproto
new file mode 100644
index 00000000..60a6486c
--- /dev/null
+++ b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_ADSERVICES.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_ADSERVICES"
+value: {
+  string_value: "adservices.google.contributions.prebuilt"
+}
diff --git a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_APPSEARCH.textproto b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_APPSEARCH.textproto
new file mode 100644
index 00000000..d5e3ef3b
--- /dev/null
+++ b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_APPSEARCH.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_APPSEARCH"
+value: {
+  string_value: "appsearch.google.contributions.prebuilt"
+}
diff --git a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_ART.textproto b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_ART.textproto
new file mode 100644
index 00000000..64e36bc3
--- /dev/null
+++ b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_ART.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_ART"
+value: {
+  string_value: "art.google.contributions.prebuilt"
+}
diff --git a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CAPTIVEPORTALLOGIN.textproto b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CAPTIVEPORTALLOGIN.textproto
new file mode 100644
index 00000000..efe3115e
--- /dev/null
+++ b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CAPTIVEPORTALLOGIN.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_CAPTIVEPORTALLOGIN"
+value: {
+  string_value: "captiveportallogin.google.contributions.prebuilt"
+}
diff --git a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CELLBROADCAST.textproto b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CELLBROADCAST.textproto
new file mode 100644
index 00000000..200a543e
--- /dev/null
+++ b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CELLBROADCAST.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_CELLBROADCAST"
+value: {
+  string_value: "cellbroadcast.google.contributions.prebuilt"
+}
diff --git a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CONFIGINFRASTRUCTURE.textproto b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CONFIGINFRASTRUCTURE.textproto
new file mode 100644
index 00000000..3876a849
--- /dev/null
+++ b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CONFIGINFRASTRUCTURE.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_CONFIGINFRASTRUCTURE"
+value: {
+  string_value: "configinfrastructure.google.contributions.prebuilt"
+}
diff --git a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CONNECTIVITY.textproto b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CONNECTIVITY.textproto
new file mode 100644
index 00000000..d6832f08
--- /dev/null
+++ b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CONNECTIVITY.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_CONNECTIVITY"
+value: {
+  string_value: "connectivity.google.contributions.prebuilt"
+}
diff --git a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CONSCRYPT.textproto b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CONSCRYPT.textproto
new file mode 100644
index 00000000..a59cda3e
--- /dev/null
+++ b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CONSCRYPT.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_CONSCRYPT"
+value: {
+  string_value: "conscrypt.google.contributions.prebuilt"
+}
diff --git a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_DOCUMENTSUIGOOGLE.textproto b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_DOCUMENTSUIGOOGLE.textproto
new file mode 100644
index 00000000..c43b395a
--- /dev/null
+++ b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_DOCUMENTSUIGOOGLE.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_DOCUMENTSUIGOOGLE"
+value: {
+  string_value: "documentsui.google.contributions.prebuilt"
+}
diff --git a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_EXTSERVICES.textproto b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_EXTSERVICES.textproto
new file mode 100644
index 00000000..3744cd73
--- /dev/null
+++ b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_EXTSERVICES.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_EXTSERVICES"
+value: {
+  string_value: "extservices.google.contributions.prebuilt"
+}
diff --git a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_HEALTHFITNESS.textproto b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_HEALTHFITNESS.textproto
new file mode 100644
index 00000000..49592211
--- /dev/null
+++ b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_HEALTHFITNESS.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_HEALTHFITNESS"
+value: {
+  string_value: "healthfitness.google.contributions.prebuilt"
+}
diff --git a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_IPSEC.textproto b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_IPSEC.textproto
new file mode 100644
index 00000000..44d34289
--- /dev/null
+++ b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_IPSEC.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_IPSEC"
+value: {
+  string_value: "ipsec.google.contributions.prebuilt"
+}
diff --git a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_MEDIA.textproto b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_MEDIA.textproto
new file mode 100644
index 00000000..702f81b0
--- /dev/null
+++ b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_MEDIA.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_MEDIA"
+value: {
+  string_value: "media.google.contributions.prebuilt"
+}
diff --git a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_MEDIAPROVIDER.textproto b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_MEDIAPROVIDER.textproto
new file mode 100644
index 00000000..ee3b3cf3
--- /dev/null
+++ b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_MEDIAPROVIDER.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_MEDIAPROVIDER"
+value: {
+  string_value: "mediaprovider.google.contributions.prebuilt"
+}
diff --git a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_MODULE_METADATA.textproto b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_MODULE_METADATA.textproto
new file mode 100644
index 00000000..5ba98fb4
--- /dev/null
+++ b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_MODULE_METADATA.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_MODULE_METADATA"
+value: {
+  string_value: "modulemetadata.google.contributions.prebuilt"
+}
diff --git a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_NETWORKSTACKGOOGLE.textproto b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_NETWORKSTACKGOOGLE.textproto
new file mode 100644
index 00000000..c3d30849
--- /dev/null
+++ b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_NETWORKSTACKGOOGLE.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_NETWORKSTACKGOOGLE"
+value: {
+  string_value: "networkstack.google.contributions.prebuilt"
+}
diff --git a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_NEURALNETWORKS.textproto b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_NEURALNETWORKS.textproto
new file mode 100644
index 00000000..c6b22ba0
--- /dev/null
+++ b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_NEURALNETWORKS.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_NEURALNETWORKS"
+value: {
+  string_value: "neuralnetworks.google.contributions.prebuilt"
+}
diff --git a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_ONDEVICEPERSONALIZATION.textproto b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_ONDEVICEPERSONALIZATION.textproto
new file mode 100644
index 00000000..fade2224
--- /dev/null
+++ b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_ONDEVICEPERSONALIZATION.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_ONDEVICEPERSONALIZATION"
+value: {
+  string_value: "ondevicepersonalization.google.contributions.prebuilt"
+}
diff --git a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_PERMISSION.textproto b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_PERMISSION.textproto
new file mode 100644
index 00000000..c4ec08da
--- /dev/null
+++ b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_PERMISSION.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_PERMISSION"
+value: {
+  string_value: "permission.google.contributions.prebuilt"
+}
diff --git a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_PRIMARY_LIBS.textproto b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_PRIMARY_LIBS.textproto
new file mode 100644
index 00000000..53054247
--- /dev/null
+++ b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_PRIMARY_LIBS.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_PRIMARY_LIBS"
+value: {
+  string_value: "primarylibs.google.contributions.prebuilt"
+}
diff --git a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_RESOLV.textproto b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_RESOLV.textproto
new file mode 100644
index 00000000..fcdf9066
--- /dev/null
+++ b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_RESOLV.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_RESOLV"
+value: {
+  string_value: "resolv.google.contributions.prebuilt"
+}
diff --git a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_SCHEDULING.textproto b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_SCHEDULING.textproto
new file mode 100644
index 00000000..faf36d06
--- /dev/null
+++ b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_SCHEDULING.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_SCHEDULING"
+value: {
+  string_value: "scheduling.google.contributions.prebuilt"
+}
diff --git a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_SDKEXTENSIONS.textproto b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_SDKEXTENSIONS.textproto
new file mode 100644
index 00000000..6ad93e2a
--- /dev/null
+++ b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_SDKEXTENSIONS.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_SDKEXTENSIONS"
+value: {
+  string_value: "sdkextensions.google.contributions.prebuilt"
+}
diff --git a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_STATSD.textproto b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_STATSD.textproto
new file mode 100644
index 00000000..0adeaee7
--- /dev/null
+++ b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_STATSD.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_STATSD"
+value: {
+  string_value: "statsd.google.contributions.prebuilt"
+}
diff --git a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_SWCODEC.textproto b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_SWCODEC.textproto
new file mode 100644
index 00000000..15ec8b12
--- /dev/null
+++ b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_SWCODEC.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_SWCODEC"
+value: {
+  string_value: "swcodec.google.contributions.prebuilt"
+}
diff --git a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_TZDATA.textproto b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_TZDATA.textproto
new file mode 100644
index 00000000..b3f0666f
--- /dev/null
+++ b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_TZDATA.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_TZDATA"
+value: {
+  string_value: "tzdata.google.contributions.prebuilt"
+}
diff --git a/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_WIFI.textproto b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_WIFI.textproto
new file mode 100644
index 00000000..c25af166
--- /dev/null
+++ b/gms_mainline/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_WIFI.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_WIFI"
+value: {
+  string_value: "wifi.google.contributions.prebuilt"
+}
diff --git a/gms_mainline/required/flag_values/ap4a/RELEASE_APEX_BOOT_JARS_PREBUILT_EXCLUDED_LIST.textproto b/gms_mainline/required/flag_values/ap4a/RELEASE_APEX_BOOT_JARS_PREBUILT_EXCLUDED_LIST.textproto
new file mode 100644
index 00000000..461c996f
--- /dev/null
+++ b/gms_mainline/required/flag_values/ap4a/RELEASE_APEX_BOOT_JARS_PREBUILT_EXCLUDED_LIST.textproto
@@ -0,0 +1,4 @@
+name:  "RELEASE_APEX_BOOT_JARS_PREBUILT_EXCLUDED_LIST"
+value:  {
+  string_value:  "com.android.mediaprovider:framework-photopicker"
+}
diff --git a/gms_mainline/required/release_config_map.textproto b/gms_mainline/required/release_config_map.textproto
new file mode 100644
index 00000000..3237b81f
--- /dev/null
+++ b/gms_mainline/required/release_config_map.textproto
@@ -0,0 +1 @@
+default_containers: "vendor"
diff --git a/gms_mainline/required/release_configs/ap3a.textproto b/gms_mainline/required/release_configs/ap3a.textproto
new file mode 100644
index 00000000..c25b670b
--- /dev/null
+++ b/gms_mainline/required/release_configs/ap3a.textproto
@@ -0,0 +1 @@
+name: "ap3a"
diff --git a/gms_mainline/required/release_configs/ap4a.textproto b/gms_mainline/required/release_configs/ap4a.textproto
new file mode 100644
index 00000000..5e1ad743
--- /dev/null
+++ b/gms_mainline/required/release_configs/ap4a.textproto
@@ -0,0 +1 @@
+name:  "ap4a"
diff --git a/gms_mainline/rkpd/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_REMOTEKEYPROVISIONING.textproto b/gms_mainline/rkpd/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_REMOTEKEYPROVISIONING.textproto
new file mode 100644
index 00000000..965e4cad
--- /dev/null
+++ b/gms_mainline/rkpd/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_REMOTEKEYPROVISIONING.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_REMOTEKEYPROVISIONING"
+value: {
+  string_value: "rkpd.google.contributions.prebuilt"
+}
diff --git a/gms_mainline/rkpd/release_config_map.textproto b/gms_mainline/rkpd/release_config_map.textproto
new file mode 100644
index 00000000..3237b81f
--- /dev/null
+++ b/gms_mainline/rkpd/release_config_map.textproto
@@ -0,0 +1 @@
+default_containers: "vendor"
diff --git a/gms_mainline/rkpd/release_configs/ap3a.textproto b/gms_mainline/rkpd/release_configs/ap3a.textproto
new file mode 100644
index 00000000..c25b670b
--- /dev/null
+++ b/gms_mainline/rkpd/release_configs/ap3a.textproto
@@ -0,0 +1 @@
+name: "ap3a"
diff --git a/gms_mainline/uwb/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_UWB.textproto b/gms_mainline/uwb/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_UWB.textproto
new file mode 100644
index 00000000..6f8574f3
--- /dev/null
+++ b/gms_mainline/uwb/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_UWB.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_UWB"
+value: {
+  string_value: "uwb.google.contributions.prebuilt"
+}
diff --git a/gms_mainline/uwb/release_config_map.textproto b/gms_mainline/uwb/release_config_map.textproto
new file mode 100644
index 00000000..3237b81f
--- /dev/null
+++ b/gms_mainline/uwb/release_config_map.textproto
@@ -0,0 +1 @@
+default_containers: "vendor"
diff --git a/gms_mainline/uwb/release_configs/ap3a.textproto b/gms_mainline/uwb/release_configs/ap3a.textproto
new file mode 100644
index 00000000..c25b670b
--- /dev/null
+++ b/gms_mainline/uwb/release_configs/ap3a.textproto
@@ -0,0 +1 @@
+name: "ap3a"
diff --git a/gms_mainline_go/optional/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_BLUETOOTH.textproto b/gms_mainline_go/optional/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_BLUETOOTH.textproto
new file mode 100644
index 00000000..17e34f70
--- /dev/null
+++ b/gms_mainline_go/optional/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_BLUETOOTH.textproto
@@ -0,0 +1,5 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_BLUETOOTH"
+value: {
+  string_value: ""
+
+}
diff --git a/gms_mainline_go/optional/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_REMOTEKEYPROVISIONING.textproto b/gms_mainline_go/optional/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_REMOTEKEYPROVISIONING.textproto
new file mode 100644
index 00000000..13c89e80
--- /dev/null
+++ b/gms_mainline_go/optional/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_REMOTEKEYPROVISIONING.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_REMOTEKEYPROVISIONING"
+value: {
+  string_value: "rkpd.go.google.contributions.prebuilt"
+}
diff --git a/gms_mainline_go/optional/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_UWB.textproto b/gms_mainline_go/optional/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_UWB.textproto
new file mode 100644
index 00000000..11c1935f
--- /dev/null
+++ b/gms_mainline_go/optional/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_UWB.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_UWB"
+value: {
+  string_value: "uwb.go.google.contributions.prebuilt"
+}
diff --git a/gms_mainline_go/optional/release_config_map.textproto b/gms_mainline_go/optional/release_config_map.textproto
new file mode 100644
index 00000000..3237b81f
--- /dev/null
+++ b/gms_mainline_go/optional/release_config_map.textproto
@@ -0,0 +1 @@
+default_containers: "vendor"
diff --git a/gms_mainline_go/optional/release_configs/ap3a.textproto b/gms_mainline_go/optional/release_configs/ap3a.textproto
new file mode 100644
index 00000000..c25b670b
--- /dev/null
+++ b/gms_mainline_go/optional/release_configs/ap3a.textproto
@@ -0,0 +1 @@
+name: "ap3a"
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_ADBD.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_ADBD.textproto
new file mode 100644
index 00000000..5df73519
--- /dev/null
+++ b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_ADBD.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_ADBD"
+value: {
+  string_value: "adbd.go.google.contributions.prebuilt"
+}
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_ADSERVICES.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_ADSERVICES.textproto
new file mode 100644
index 00000000..196f4d4a
--- /dev/null
+++ b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_ADSERVICES.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_ADSERVICES"
+value: {
+  string_value: "adservices.go.google.contributions.prebuilt"
+}
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_APPSEARCH.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_APPSEARCH.textproto
new file mode 100644
index 00000000..abc22e08
--- /dev/null
+++ b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_APPSEARCH.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_APPSEARCH"
+value: {
+  string_value: "appsearch.go.google.contributions.prebuilt"
+}
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_ART.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_ART.textproto
new file mode 100644
index 00000000..c1d1df78
--- /dev/null
+++ b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_ART.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_ART"
+value: {
+  string_value: "art.go.google.contributions.prebuilt"
+}
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CAPTIVEPORTALLOGIN.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CAPTIVEPORTALLOGIN.textproto
new file mode 100644
index 00000000..304b8693
--- /dev/null
+++ b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CAPTIVEPORTALLOGIN.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_CAPTIVEPORTALLOGIN"
+value: {
+  string_value: "captiveportallogin.go.google.contributions.prebuilt"
+}
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CELLBROADCAST.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CELLBROADCAST.textproto
new file mode 100644
index 00000000..c588c4e1
--- /dev/null
+++ b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CELLBROADCAST.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_CELLBROADCAST"
+value: {
+  string_value: "cellbroadcast.go.google.contributions.prebuilt"
+}
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CONFIGINFRASTRUCTURE.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CONFIGINFRASTRUCTURE.textproto
new file mode 100644
index 00000000..ed8b9a2e
--- /dev/null
+++ b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CONFIGINFRASTRUCTURE.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_CONFIGINFRASTRUCTURE"
+value: {
+  string_value: "configinfrastructure.go.google.contributions.prebuilt"
+}
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CONNECTIVITY.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CONNECTIVITY.textproto
new file mode 100644
index 00000000..26ab1962
--- /dev/null
+++ b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CONNECTIVITY.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_CONNECTIVITY"
+value: {
+  string_value: "connectivity.go.google.contributions.prebuilt"
+}
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CONSCRYPT.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CONSCRYPT.textproto
new file mode 100644
index 00000000..6d3ed3ae
--- /dev/null
+++ b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_CONSCRYPT.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_CONSCRYPT"
+value: {
+  string_value: "conscrypt.go.google.contributions.prebuilt"
+}
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_DOCUMENTSUIGOOGLE.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_DOCUMENTSUIGOOGLE.textproto
new file mode 100644
index 00000000..0cfcfb8f
--- /dev/null
+++ b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_DOCUMENTSUIGOOGLE.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_DOCUMENTSUIGOOGLE"
+value: {
+  string_value: "documentsui.go.google.contributions.prebuilt"
+}
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_EXTSERVICES.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_EXTSERVICES.textproto
new file mode 100644
index 00000000..50d8c140
--- /dev/null
+++ b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_EXTSERVICES.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_EXTSERVICES"
+value: {
+  string_value: "extservices.go.google.contributions.prebuilt"
+}
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_HEALTHFITNESS.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_HEALTHFITNESS.textproto
new file mode 100644
index 00000000..d73d8d1b
--- /dev/null
+++ b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_HEALTHFITNESS.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_HEALTHFITNESS"
+value: {
+  string_value: "healthfitness.go.google.contributions.prebuilt"
+}
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_IPSEC.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_IPSEC.textproto
new file mode 100644
index 00000000..51193c0a
--- /dev/null
+++ b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_IPSEC.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_IPSEC"
+value: {
+  string_value: "ipsec.go.google.contributions.prebuilt"
+}
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_MEDIA.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_MEDIA.textproto
new file mode 100644
index 00000000..9439b406
--- /dev/null
+++ b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_MEDIA.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_MEDIA"
+value: {
+  string_value: "media.go.google.contributions.prebuilt"
+}
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_MEDIAPROVIDER.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_MEDIAPROVIDER.textproto
new file mode 100644
index 00000000..58d39203
--- /dev/null
+++ b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_MEDIAPROVIDER.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_MEDIAPROVIDER"
+value: {
+  string_value: "mediaprovider.go.google.contributions.prebuilt"
+}
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_MODULE_METADATA.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_MODULE_METADATA.textproto
new file mode 100644
index 00000000..190b8625
--- /dev/null
+++ b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_MODULE_METADATA.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_MODULE_METADATA"
+value: {
+  string_value: "modulemetadata.go.google.contributions.prebuilt"
+}
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_NETWORKSTACKGOOGLE.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_NETWORKSTACKGOOGLE.textproto
new file mode 100644
index 00000000..91a51662
--- /dev/null
+++ b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_NETWORKSTACKGOOGLE.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_NETWORKSTACKGOOGLE"
+value: {
+  string_value: "networkstack.go.google.contributions.prebuilt"
+}
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_NEURALNETWORKS.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_NEURALNETWORKS.textproto
new file mode 100644
index 00000000..f1ff08c4
--- /dev/null
+++ b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_NEURALNETWORKS.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_NEURALNETWORKS"
+value: {
+  string_value: "neuralnetworks.go.google.contributions.prebuilt"
+}
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_ONDEVICEPERSONALIZATION.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_ONDEVICEPERSONALIZATION.textproto
new file mode 100644
index 00000000..0efbaf7f
--- /dev/null
+++ b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_ONDEVICEPERSONALIZATION.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_ONDEVICEPERSONALIZATION"
+value: {
+  string_value: "ondevicepersonalization.go.google.contributions.prebuilt"
+}
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_PERMISSION.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_PERMISSION.textproto
new file mode 100644
index 00000000..e0f1f182
--- /dev/null
+++ b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_PERMISSION.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_PERMISSION"
+value: {
+  string_value: "permission.go.google.contributions.prebuilt"
+}
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_PRIMARY_LIBS.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_PRIMARY_LIBS.textproto
new file mode 100644
index 00000000..b8ae44dd
--- /dev/null
+++ b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_PRIMARY_LIBS.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_PRIMARY_LIBS"
+value: {
+  string_value: "primarylibs.go.google.contributions.prebuilt"
+}
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_RESOLV.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_RESOLV.textproto
new file mode 100644
index 00000000..757dfc8b
--- /dev/null
+++ b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_RESOLV.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_RESOLV"
+value: {
+  string_value: "resolv.go.google.contributions.prebuilt"
+}
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_SCHEDULING.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_SCHEDULING.textproto
new file mode 100644
index 00000000..3906dd80
--- /dev/null
+++ b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_SCHEDULING.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_SCHEDULING"
+value: {
+  string_value: "scheduling.go.google.contributions.prebuilt"
+}
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_SDKEXTENSIONS.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_SDKEXTENSIONS.textproto
new file mode 100644
index 00000000..97be6a8c
--- /dev/null
+++ b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_SDKEXTENSIONS.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_SDKEXTENSIONS"
+value: {
+  string_value: "sdkextensions.go.google.contributions.prebuilt"
+}
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_STATSD.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_STATSD.textproto
new file mode 100644
index 00000000..04718644
--- /dev/null
+++ b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_STATSD.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_STATSD"
+value: {
+  string_value: "statsd.go.google.contributions.prebuilt"
+}
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_SWCODEC.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_SWCODEC.textproto
new file mode 100644
index 00000000..e1cb4c58
--- /dev/null
+++ b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_SWCODEC.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_SWCODEC"
+value: {
+  string_value: "swcodec.go.google.contributions.prebuilt"
+}
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_TELEMETRY_TVP.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_TELEMETRY_TVP.textproto
new file mode 100644
index 00000000..0560e0ae
--- /dev/null
+++ b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_TELEMETRY_TVP.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_TELEMETRY_TVP"
+value: {
+  string_value: "telemetrytvp.go.google.contributions.prebuilt"
+}
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_TZDATA.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_TZDATA.textproto
new file mode 100644
index 00000000..2a221042
--- /dev/null
+++ b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_TZDATA.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_TZDATA"
+value: {
+  string_value: "tzdata.go.google.contributions.prebuilt"
+}
diff --git a/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_WIFI.textproto b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_WIFI.textproto
new file mode 100644
index 00000000..c08b952b
--- /dev/null
+++ b/gms_mainline_go/required/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_WIFI.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_WIFI"
+value: {
+  string_value: "wifi.go.google.contributions.prebuilt"
+}
diff --git a/gms_mainline_go/required/flag_values/ap4a/RELEASE_APEX_BOOT_JARS_PREBUILT_EXCLUDED_LIST.textproto b/gms_mainline_go/required/flag_values/ap4a/RELEASE_APEX_BOOT_JARS_PREBUILT_EXCLUDED_LIST.textproto
new file mode 100644
index 00000000..461c996f
--- /dev/null
+++ b/gms_mainline_go/required/flag_values/ap4a/RELEASE_APEX_BOOT_JARS_PREBUILT_EXCLUDED_LIST.textproto
@@ -0,0 +1,4 @@
+name:  "RELEASE_APEX_BOOT_JARS_PREBUILT_EXCLUDED_LIST"
+value:  {
+  string_value:  "com.android.mediaprovider:framework-photopicker"
+}
diff --git a/gms_mainline_go/required/release_config_map.textproto b/gms_mainline_go/required/release_config_map.textproto
new file mode 100644
index 00000000..3237b81f
--- /dev/null
+++ b/gms_mainline_go/required/release_config_map.textproto
@@ -0,0 +1 @@
+default_containers: "vendor"
diff --git a/gms_mainline_go/required/release_configs/ap3a.textproto b/gms_mainline_go/required/release_configs/ap3a.textproto
new file mode 100644
index 00000000..c25b670b
--- /dev/null
+++ b/gms_mainline_go/required/release_configs/ap3a.textproto
@@ -0,0 +1 @@
+name: "ap3a"
diff --git a/gms_mainline_go/required/release_configs/ap4a.textproto b/gms_mainline_go/required/release_configs/ap4a.textproto
new file mode 100644
index 00000000..5e1ad743
--- /dev/null
+++ b/gms_mainline_go/required/release_configs/ap4a.textproto
@@ -0,0 +1 @@
+name:  "ap4a"
diff --git a/gms_mainline_go/rkpd/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_REMOTEKEYPROVISIONING.textproto b/gms_mainline_go/rkpd/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_REMOTEKEYPROVISIONING.textproto
new file mode 100644
index 00000000..13c89e80
--- /dev/null
+++ b/gms_mainline_go/rkpd/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_REMOTEKEYPROVISIONING.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_REMOTEKEYPROVISIONING"
+value: {
+  string_value: "rkpd.go.google.contributions.prebuilt"
+}
diff --git a/gms_mainline_go/rkpd/release_config_map.textproto b/gms_mainline_go/rkpd/release_config_map.textproto
new file mode 100644
index 00000000..3237b81f
--- /dev/null
+++ b/gms_mainline_go/rkpd/release_config_map.textproto
@@ -0,0 +1 @@
+default_containers: "vendor"
diff --git a/gms_mainline_go/rkpd/release_configs/ap3a.textproto b/gms_mainline_go/rkpd/release_configs/ap3a.textproto
new file mode 100644
index 00000000..c25b670b
--- /dev/null
+++ b/gms_mainline_go/rkpd/release_configs/ap3a.textproto
@@ -0,0 +1 @@
+name: "ap3a"
diff --git a/gms_mainline_go/uwb/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_UWB.textproto b/gms_mainline_go/uwb/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_UWB.textproto
new file mode 100644
index 00000000..11c1935f
--- /dev/null
+++ b/gms_mainline_go/uwb/flag_values/ap3a/RELEASE_APEX_CONTRIBUTIONS_UWB.textproto
@@ -0,0 +1,4 @@
+name: "RELEASE_APEX_CONTRIBUTIONS_UWB"
+value: {
+  string_value: "uwb.go.google.contributions.prebuilt"
+}
diff --git a/gms_mainline_go/uwb/release_config_map.textproto b/gms_mainline_go/uwb/release_config_map.textproto
new file mode 100644
index 00000000..3237b81f
--- /dev/null
+++ b/gms_mainline_go/uwb/release_config_map.textproto
@@ -0,0 +1 @@
+default_containers: "vendor"
diff --git a/gms_mainline_go/uwb/release_configs/ap3a.textproto b/gms_mainline_go/uwb/release_configs/ap3a.textproto
new file mode 100644
index 00000000..c25b670b
--- /dev/null
+++ b/gms_mainline_go/uwb/release_configs/ap3a.textproto
@@ -0,0 +1 @@
+name: "ap3a"
```

