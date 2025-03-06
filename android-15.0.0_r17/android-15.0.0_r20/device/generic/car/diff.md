```diff
diff --git a/emulator/audio/car_audio_configuration.xml b/emulator/audio/car_audio_configuration.xml
index 65fb605..ce18e91 100644
--- a/emulator/audio/car_audio_configuration.xml
+++ b/emulator/audio/car_audio_configuration.xml
@@ -23,6 +23,10 @@
   in the car environment.
 -->
 <carAudioConfiguration version="4">
+    <deviceConfigurations>
+        <deviceConfiguration name="useCarVolumeGroupMuting" value="true" />
+        <deviceConfiguration name="useHalDuckingSignals" value="true" />
+    </deviceConfigurations>
     <activationVolumeConfigs>
         <activationVolumeConfig name="activation_volume_on_boot_config">
             <activationVolumeConfigEntry maxActivationVolumePercentage="90" invocationType="onBoot" />
diff --git a/emulator/audio/car_emulator_audio.mk b/emulator/audio/car_emulator_audio.mk
index c49b0e4..498ef42 100644
--- a/emulator/audio/car_emulator_audio.mk
+++ b/emulator/audio/car_emulator_audio.mk
@@ -22,6 +22,9 @@ PRODUCT_PACKAGES += audio.primary.caremu
 PRODUCT_PACKAGES += \
     android.hardware.audio@6.0-impl:32
 
+# CarAudioService overlay
+PRODUCT_PACKAGES += CarAudioServiceOverlayEmulator
+
 PRODUCT_COPY_FILES += \
     device/generic/car/emulator/audio/android.hardware.audio.effects@6.0.xml:/vendor/etc/vintf/manifest/android.hardware.audio.effects@6.0.xml
 
diff --git a/emulator/audio/halservice/Android.bp b/emulator/audio/halservice/Android.bp
index 20e4ce3..49fba7d 100644
--- a/emulator/audio/halservice/Android.bp
+++ b/emulator/audio/halservice/Android.bp
@@ -42,12 +42,14 @@ cc_binary {
         "-Wextra",
         "-Werror",
     ],
-
+    defaults: [
+        "latest_android_hardware_audio_common_ndk_shared",
+        "latest_android_hardware_automotive_audiocontrol_ndk_shared",
+    ],
     shared_libs: [
         "android.hardware.audio@6.0",
         "android.hardware.audio.common@6.0",
         "android.hardware.audio.effect@6.0",
-        "android.hardware.automotive.audiocontrol-V3-ndk",
         "audiocontrol-caremu",
         "libbase",
         "libbinder",
@@ -66,15 +68,21 @@ cc_library {
     name: "audiocontrol-caremu",
     vendor: true,
     vintf_fragments: ["audiocontrol-caremu.xml"],
-
+    defaults: [
+        "latest_android_hardware_audio_common_ndk_shared",
+        "latest_android_hardware_automotive_audiocontrol_ndk_shared",
+        "car.audio.configuration.xsd.default",
+        "car.fade.configuration.xsd.default",
+    ],
     shared_libs: [
         "android.hardware.audio.common@7.0-enums",
-        "android.hardware.audio.common-V1-ndk",
-        "android.hardware.automotive.audiocontrol-V3-ndk",
+        "android.hardware.audiocontrol.internal",
+        "libaudio_aidl_conversion_common_ndk",
         "libbase",
         "libbinder_ndk",
         "libcutils",
         "liblog",
+        "libxml2",
         "audio.primary.caremu",
     ],
 
diff --git a/emulator/audio/halservice/AudioControl.cpp b/emulator/audio/halservice/AudioControl.cpp
index f6216aa..d65d8cd 100644
--- a/emulator/audio/halservice/AudioControl.cpp
+++ b/emulator/audio/halservice/AudioControl.cpp
@@ -36,6 +36,8 @@
 
 #include <stdio.h>
 
+#include <CarAudioConfigurationXmlConverter.h>
+
 namespace aidl {
 namespace android {
 namespace hardware {
@@ -48,6 +50,7 @@ using ::android::base::ParseBoolResult;
 using ::android::base::ParseInt;
 using ::std::shared_ptr;
 using ::std::string;
+using ::android::hardware::audiocontrol::internal::CarAudioConfigurationXmlConverter;
 
 namespace xsd {
 using namespace ::android::audio::policy::configuration::V7_0;
@@ -56,6 +59,10 @@ using namespace ::android::audio::policy::configuration::V7_0;
 namespace {
 const float kLowerBound = -1.0f;
 const float kUpperBound = 1.0f;
+
+const static std::string kAudioConfigFile = "/vendor/etc/car_audio_configuration.xml";
+const static std::string kFadeConfigFile = "/vendor/etc/car_audio_fade_configuration.xml";
+
 bool checkCallerHasWritePermissions(int fd) {
     // Double check that's only called by root - it should be be blocked at debug() level,
     // but it doesn't hurt to make sure...
@@ -76,6 +83,52 @@ bool safelyParseInt(string s, int* out) {
     }
     return true;
 }
+
+std::string formatDump(const std::string& input) {
+    const char kSpacer = ' ';
+    std::string output;
+    int indentLevel = 0;
+    bool newLine = false;
+
+    for (char c : input) {
+        switch (c) {
+            case '{':
+                if (!newLine) {
+                    output += '\n';
+                }
+                newLine = true;
+                indentLevel++;
+                for (int i = 0; i < indentLevel; ++i) {
+                    output += kSpacer;
+                }
+                break;
+            case '}':
+                if (!newLine) {
+                    output += '\n';
+                }
+                newLine = true;
+                indentLevel--;
+                for (int i = 0; i < indentLevel; ++i) {
+                    output += kSpacer;
+                }
+                break;
+            case ',':
+                if (!newLine) {
+                    output += '\n';
+                }
+                newLine = true;
+                for (int i = 0; i < indentLevel; ++i) {
+                    output += kSpacer;
+                }
+                break;
+            default:
+                newLine = false;
+                output += c;
+        }
+    }
+
+    return output;
+}
 }  // namespace
 
 
@@ -179,6 +232,12 @@ static inline std::string toEnumString(const std::vector<aidl_enum_type>& in_val
                            });
 }
 
+AudioControl::AudioControl() : AudioControl(kAudioConfigFile, kFadeConfigFile) {}
+
+AudioControl::AudioControl(const std::string& carAudioConfig, const std::string& audioFadeConfig)
+    : mCarAudioConfigurationConverter(std::make_shared<CarAudioConfigurationXmlConverter>(
+        carAudioConfig, audioFadeConfig)) {}
+
 ndk::ScopedAStatus AudioControl::registerFocusListener(
         const shared_ptr<IFocusListener>& in_listener) {
 
@@ -317,6 +376,53 @@ ndk::ScopedAStatus AudioControl::clearModuleChangeCallback() {
     return ndk::ScopedAStatus::ok();
 }
 
+ndk::ScopedAStatus AudioControl::getAudioDeviceConfiguration(
+        AudioDeviceConfiguration* audioDeviceConfig) {
+    if (!audioDeviceConfig) {
+        LOG(ERROR) << __func__ << "Audio device configuration must not be null";
+        return ndk::ScopedAStatus::fromStatus(STATUS_UNEXPECTED_NULL);
+    }
+    const auto& innerDeviceConfig = mCarAudioConfigurationConverter->getAudioDeviceConfiguration();
+    audioDeviceConfig->routingConfig = innerDeviceConfig.routingConfig;
+    audioDeviceConfig->useCoreAudioVolume = innerDeviceConfig.useCoreAudioVolume;
+    audioDeviceConfig->useCarVolumeGroupMuting = innerDeviceConfig.useCarVolumeGroupMuting;
+    audioDeviceConfig->useHalDuckingSignals = innerDeviceConfig.useHalDuckingSignals;
+    return ndk::ScopedAStatus::ok();
+}
+
+ndk::ScopedAStatus AudioControl::getOutputMirroringDevices(
+        std::vector<AudioPort>* mirroringDevices) {
+    if (!mirroringDevices) {
+        LOG(ERROR) << __func__ << "Mirroring devices must not be null";
+        return ndk::ScopedAStatus::fromStatus(STATUS_UNEXPECTED_NULL);
+    }
+    if (!mCarAudioConfigurationConverter->getErrors().empty()) {
+        std::string message = "Could not parse audio configuration file, error: "
+                + mCarAudioConfigurationConverter->getErrors();
+        return ndk::ScopedAStatus::fromExceptionCodeWithMessage(EX_SERVICE_SPECIFIC,
+            message.c_str());
+    }
+    const auto& innerDevice = mCarAudioConfigurationConverter->getOutputMirroringDevices();
+    mirroringDevices->insert(mirroringDevices->end(), innerDevice.begin(), innerDevice.end());
+    return ndk::ScopedAStatus::ok();
+}
+
+ndk::ScopedAStatus AudioControl::getCarAudioZones(std::vector<AudioZone>* audioZones) {
+    if (!audioZones) {
+        LOG(ERROR) << __func__ << "Audio zones must not be null";
+        return ndk::ScopedAStatus::fromStatus(STATUS_UNEXPECTED_NULL);
+    }
+    if (!mCarAudioConfigurationConverter->getErrors().empty()) {
+        std::string message = "Could not parse audio configuration file, error: "
+                + mCarAudioConfigurationConverter->getErrors();
+        return ndk::ScopedAStatus::fromExceptionCodeWithMessage(EX_SERVICE_SPECIFIC,
+            message.c_str());
+    }
+    const auto& innerZones = mCarAudioConfigurationConverter->getAudioZones();
+    audioZones->insert(audioZones->end(), innerZones.begin(), innerZones.end());
+    return ndk::ScopedAStatus::ok();
+}
+
 binder_status_t AudioControl::dump(int fd, const char** args, uint32_t numArgs) {
     if (numArgs == 0) {
         return dumpsys(fd);
@@ -354,6 +460,28 @@ binder_status_t AudioControl::dumpsys(int fd) {
     dprintf(fd, "AudioGainCallback %sregistered\n", (mAudioGainCallback == nullptr ? "NOT " : ""));
     dprintf(fd, "ModuleChangeCallback %sregistered\n",
             (mModuleChangeCallback == nullptr ? "NOT " : ""));
+
+    AudioDeviceConfiguration configuration;
+    ndk::ScopedAStatus status = getAudioDeviceConfiguration(&configuration);
+    if (status.isOk()) {
+        dprintf(fd, "AudioDeviceConfiguration: %s\n", configuration.toString().c_str());
+    } else {
+        dprintf(fd, "Failed to parse car audio configuration, error: %s\n", status.getMessage());
+    }
+    std::vector<AudioZone> audioZones;
+    if (getCarAudioZones(&audioZones).isOk()) {
+        dprintf(fd, "Audio zones count: %zu\n", audioZones.size());
+        for (const auto& zone : audioZones) {
+            dprintf(fd, "AudioZone: %s\n", formatDump(zone.toString()).c_str());
+        }
+    }
+    std::vector<AudioPort> mirroringDevices;
+    if (getOutputMirroringDevices(&mirroringDevices).isOk()) {
+        dprintf(fd, "Mirroring devices count: %zu\n", mirroringDevices.size());
+        for (const auto& device : mirroringDevices) {
+            dprintf(fd, "Mirroring device: %s\n", formatDump(device.toString()).c_str());
+        }
+    }
     return STATUS_OK;
 }
 
diff --git a/emulator/audio/halservice/AudioControl.h b/emulator/audio/halservice/AudioControl.h
index 51303d0..4679c1b 100644
--- a/emulator/audio/halservice/AudioControl.h
+++ b/emulator/audio/halservice/AudioControl.h
@@ -34,6 +34,10 @@
 #include <aidl/android/media/audio/common/AudioIoFlags.h>
 #include <aidl/android/media/audio/common/AudioOutputFlags.h>
 
+namespace android::hardware::audiocontrol::internal {
+    class CarAudioConfigurationXmlConverter;
+}
+
 namespace aidl {
 namespace android {
 namespace hardware {
@@ -45,6 +49,8 @@ namespace audiomediacommon = ::aidl::android::media::audio::common;
 
 class AudioControl : public BnAudioControl {
   public:
+    AudioControl();
+    AudioControl(const std::string& carAudioConfig, const std::string& audioFadeConfig);
     ndk::ScopedAStatus onAudioFocusChange(const std::string& in_usage, int32_t in_zoneId,
                                           AudioFocusChange in_focusChange) override;
     ndk::ScopedAStatus onDevicesToDuckChange(
@@ -66,6 +72,11 @@ class AudioControl : public BnAudioControl {
     ndk::ScopedAStatus setModuleChangeCallback(
             const std::shared_ptr<IModuleChangeCallback>& in_callback) override;
     ndk::ScopedAStatus clearModuleChangeCallback() override;
+    ndk::ScopedAStatus getAudioDeviceConfiguration(
+        AudioDeviceConfiguration* audioDeviceConfig) override;
+    ndk::ScopedAStatus getOutputMirroringDevices(
+            std::vector<::aidl::android::media::audio::common::AudioPort>* mirrorDevices) override;
+    ndk::ScopedAStatus getCarAudioZones(std::vector<AudioZone>* audioZones) override;
 
     binder_status_t dump(int fd, const char** args, uint32_t numArgs) override;
 
@@ -85,6 +96,9 @@ class AudioControl : public BnAudioControl {
     std::shared_ptr<IAudioGainCallback> mAudioGainCallback = nullptr;
     std::shared_ptr<IModuleChangeCallback> mModuleChangeCallback = nullptr;
 
+    std::shared_ptr<::android::hardware::audiocontrol::internal::CarAudioConfigurationXmlConverter>
+            mCarAudioConfigurationConverter = nullptr;
+
     binder_status_t cmdHelp(int fd) const;
     binder_status_t cmdRequestFocus(int fd, const char** args, uint32_t numArgs);
     binder_status_t cmdAbandonFocus(int fd, const char** args, uint32_t numArgs);
diff --git a/emulator/audio/halservice/audiocontrol-caremu.xml b/emulator/audio/halservice/audiocontrol-caremu.xml
index 95cd7f0..ffef7fc 100644
--- a/emulator/audio/halservice/audiocontrol-caremu.xml
+++ b/emulator/audio/halservice/audiocontrol-caremu.xml
@@ -1,7 +1,7 @@
 <manifest version="2.0" type="device">
     <hal format="aidl">
         <name>android.hardware.automotive.audiocontrol</name>
-        <version>3</version>
+        <version>5</version>
         <fqname>IAudioControl/default</fqname>
     </hal>
 </manifest>
diff --git a/emulator/audio/rro_overlays/CarAudioServiceOverlay/Android.bp b/emulator/audio/rro_overlays/CarAudioServiceOverlay/Android.bp
new file mode 100644
index 0000000..6f0c80f
--- /dev/null
+++ b/emulator/audio/rro_overlays/CarAudioServiceOverlay/Android.bp
@@ -0,0 +1,27 @@
+// Copyright (C) 2024 The Android Open Source Project
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
+//
+
+package {
+    default_applicable_licenses: ["device_generic_car_license"],
+}
+
+runtime_resource_overlay {
+    name: "CarAudioServiceOverlayEmulator",
+    resource_dirs: ["res"],
+    manifest: "AndroidManifest.xml",
+    sdk_version: "current",
+    product_specific: true,
+}
diff --git a/emulator/audio/rro_overlays/CarAudioServiceOverlay/AndroidManifest.xml b/emulator/audio/rro_overlays/CarAudioServiceOverlay/AndroidManifest.xml
new file mode 100644
index 0000000..c10b146
--- /dev/null
+++ b/emulator/audio/rro_overlays/CarAudioServiceOverlay/AndroidManifest.xml
@@ -0,0 +1,26 @@
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
+<manifest xmlns:android="http://schemas.android.com/apk/res/android"
+          package="com.android.car.resources.emulator">
+    <application android:hasCode="false"/>
+    <!-- Put lower priority to enable this RRO only when no other overlay exists. -->
+    <overlay android:priority="5000"
+             android:targetPackage="com.android.car.updatable"
+             android:targetName="CarServiceCustomization"
+             android:resourcesMap="@xml/overlays"
+             android:isStatic="true" />
+</manifest>
diff --git a/emulator/audio/rro_overlays/CarAudioServiceOverlay/res/values/config.xml b/emulator/audio/rro_overlays/CarAudioServiceOverlay/res/values/config.xml
new file mode 100644
index 0000000..c135c78
--- /dev/null
+++ b/emulator/audio/rro_overlays/CarAudioServiceOverlay/res/values/config.xml
@@ -0,0 +1,31 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+/*
+** Copyright 2024, The Android Open Source Project
+**
+** Licensed under the Apache License, Version 2.0 (the "License");
+** you may not use this file except in compliance with the License.
+** You may obtain a copy of the License at
+**
+**     http://www.apache.org/licenses/LICENSE-2.0
+**
+** Unless required by applicable law or agreed to in writing, software
+** distributed under the License is distributed on an "AS IS" BASIS,
+** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+** See the License for the specific language governing permissions and
+** limitations under the License.
+*/
+-->
+
+<!-- Resources to configure car audio service based on each OEM's preference. -->
+<resources>
+    <bool name="audioUseDynamicRouting">true</bool>
+    <!--  Configuration to enable muting of individual volume groups. If this is set to
+          false, muting of individual volume groups is disabled, instead muting will toggle master
+          mute. If this is set to true, car volume group muting is enabled and each individual
+          volume group can be muted separately. -->
+    <bool name="audioUseCarVolumeGroupMuting">true</bool>
+    <bool name="audioUseMinMaxActivationVolume">true</bool>
+    <bool name="audioUseFadeManagerConfiguration">true</bool>
+    <bool name="audioUseCarVolumeGroupEvent">true</bool>
+</resources>
diff --git a/emulator/audio/rro_overlays/CarAudioServiceOverlay/res/xml/overlays.xml b/emulator/audio/rro_overlays/CarAudioServiceOverlay/res/xml/overlays.xml
new file mode 100644
index 0000000..de6dd89
--- /dev/null
+++ b/emulator/audio/rro_overlays/CarAudioServiceOverlay/res/xml/overlays.xml
@@ -0,0 +1,23 @@
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
+<overlay>
+    <item target="bool/audioUseDynamicRouting" value="@bool/audioUseDynamicRouting" />
+    <item target="bool/audioUseCarVolumeGroupMuting" value="@bool/audioUseCarVolumeGroupMuting" />
+    <item target="bool/audioUseMinMaxActivationVolume" value="@bool/audioUseMinMaxActivationVolume" />
+    <item target="bool/audioUseFadeManagerConfiguration" value="@bool/audioUseFadeManagerConfiguration" />
+    <item target="bool/audioUseCarVolumeGroupEvent" value="@bool/audioUseCarVolumeGroupEvent" />
+</overlay>
diff --git a/emulator/car_emulator_interfaces/aidl/Android.bp b/emulator/car_emulator_interfaces/aidl/Android.bp
index 5676426..a7b0f2f 100644
--- a/emulator/car_emulator_interfaces/aidl/Android.bp
+++ b/emulator/car_emulator_interfaces/aidl/Android.bp
@@ -12,6 +12,7 @@ package {
 aidl_interface {
     name: "device.generic.car.emulator-aidl",
     vendor_available: true,
+    owner: "google",
     srcs: ["device/generic/car/emulator/*.aidl"],
     stability: "vintf",
     backend: {
@@ -30,7 +31,7 @@ aidl_interface {
         {
             version: "1",
             imports: [
-                "android.hardware.automotive.vehicle-V3",
+                "android.hardware.automotive.vehicle-V4",
                 "android.hardware.automotive.vehicle.property-V4",
             ],
         },
diff --git a/emulator/car_emulator_vendor.mk b/emulator/car_emulator_vendor.mk
index d890d22..643237e 100644
--- a/emulator/car_emulator_vendor.mk
+++ b/emulator/car_emulator_vendor.mk
@@ -46,6 +46,10 @@ ifeq (,$(ENABLE_REAR_VIEW_CAMERA_SAMPLE))
 ENABLE_REAR_VIEW_CAMERA_SAMPLE := true
 endif
 
+# Goldfish emulator features
+PRODUCT_COPY_FILES += \
+    device/generic/car/emulator/data/etc/advancedFeatures.ini.car:advancedFeatures.ini
+
 # Auto modules
 PRODUCT_PACKAGES += \
     android.hardware.automotive.vehicle@V3-emulator-service \
diff --git a/emulator/data/etc/advancedFeatures.ini.car b/emulator/data/etc/advancedFeatures.ini.car
new file mode 100644
index 0000000..744612f
--- /dev/null
+++ b/emulator/data/etc/advancedFeatures.ini.car
@@ -0,0 +1,31 @@
+BluetoothEmulation = on
+GrallocSync = on
+GLDMA = on
+LogcatPipe = on
+GLAsyncSwap = on
+GLESDynamicVersion = on
+EncryptUserData = on
+IntelPerformanceMonitoringUnit = on
+VirtioWifi = on
+HostComposition = on
+RefCountPipe = on
+VirtioInput = on
+HardwareDecoder = on
+DynamicPartition = on
+ModemSimulator = on
+MultiDisplay = on
+YUVCache = on
+GLDirectMem = on
+VulkanNullOptionalStrings = on
+VulkanIgnoredHandles = on
+Mac80211hwsimUserspaceManaged = on
+VirtconsoleLogcat = on
+VirtioVsockPipe = on
+AndroidbootProps2 = on
+DeviceSkinOverlay = on
+VulkanQueueSubmitWithCommands = on
+VulkanBatchedDescriptorSetUpdate = on
+DeviceStateOnBoot = on
+HWCMultiConfigs = on
+VirtioSndCard = on
+Uwb = on
\ No newline at end of file
diff --git a/emulator/usbpt/bluetooth/usb_modeswitch/usb_modeswitch.c b/emulator/usbpt/bluetooth/usb_modeswitch/usb_modeswitch.c
index 9b092ee..6d98210 100644
--- a/emulator/usbpt/bluetooth/usb_modeswitch/usb_modeswitch.c
+++ b/emulator/usbpt/bluetooth/usb_modeswitch/usb_modeswitch.c
@@ -570,7 +570,7 @@ int main(int argc, char **argv)
 	/* Get current configuration of default device, note value if Configuration
 	 * parameter is set. Also sets active_config
 	 */
-	currentConfigVal = get_current_config_value(dev);
+	currentConfigVal = get_current_config_value();
 	if (Configuration > -1) {
 		SHOW_PROGRESS(output,"Current configuration number is %d\n", currentConfigVal);
 	} else
@@ -772,7 +772,7 @@ int main(int argc, char **argv)
 	if (Configuration > 0) {
 		if (currentConfigVal != Configuration) {
 			if (switchConfiguration()) {
-				currentConfigVal = get_current_config_value(dev);
+				currentConfigVal = get_current_config_value();
 				if (currentConfigVal == Configuration) {
 					SHOW_PROGRESS(output,"The configuration was set successfully\n");
 				} else {
diff --git a/emulator/usbpt/usbip-service/Android.bp b/emulator/usbpt/usbip-service/Android.bp
index 265e5ba..1dd11b0 100644
--- a/emulator/usbpt/usbip-service/Android.bp
+++ b/emulator/usbpt/usbip-service/Android.bp
@@ -53,10 +53,9 @@ cc_test {
     name: "usbip_test",
     defaults: ["usbip_defaults"],
     srcs: ["UsbIpTest.cpp"],
-    test_suites: ["general-tests"],
 
     test_options: {
-        unit_test: false,
+        unit_test: true,
     },
     shared_libs: [
         "usbip_utils",
diff --git a/emulator/usbpt/usbip-service/TEST_MAPPING b/emulator/usbpt/usbip-service/TEST_MAPPING
deleted file mode 100644
index 61eb9ae..0000000
--- a/emulator/usbpt/usbip-service/TEST_MAPPING
+++ /dev/null
@@ -1,8 +0,0 @@
-{
-  "presubmit": [
-    {
-      "name": "usbip_test",
-      "host": true
-    }
-  ]
-}
diff --git a/hals/health/android.hardware.health-service.automotive.xml b/hals/health/android.hardware.health-service.automotive.xml
index 2acaaba..8ddfbda 100644
--- a/hals/health/android.hardware.health-service.automotive.xml
+++ b/hals/health/android.hardware.health-service.automotive.xml
@@ -1,7 +1,7 @@
 <manifest version="1.0" type="device">
     <hal format="aidl">
         <name>android.hardware.health</name>
-        <version>3</version>
+        <version>4</version>
         <fqname>IHealth/default</fqname>
     </hal>
 </manifest>
```

