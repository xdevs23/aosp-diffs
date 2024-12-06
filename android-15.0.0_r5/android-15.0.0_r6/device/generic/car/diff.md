```diff
diff --git a/AndroidProducts.mk b/AndroidProducts.mk
index 9fac755..d279dad 100644
--- a/AndroidProducts.mk
+++ b/AndroidProducts.mk
@@ -20,7 +20,7 @@ PRODUCT_MAKEFILES := \
     $(LOCAL_DIR)/sdk_car_arm64.mk \
     $(LOCAL_DIR)/sdk_car_md_arm64.mk \
     $(LOCAL_DIR)/sdk_car_md_x86_64.mk \
-    $(LOCAL_DIR)/sdk_car_portrait_x86_64.mk \
+    $(LOCAL_DIR)/sdk_car_cw_x86_64.mk \
     $(LOCAL_DIR)/sdk_car_x86_64.mk \
 
 COMMON_LUNCH_CHOICES := \
@@ -28,7 +28,7 @@ COMMON_LUNCH_CHOICES := \
     gsi_car_x86_64-trunk_staging-userdebug \
     sdk_car_arm64-trunk_staging-userdebug \
     sdk_car_md_x86_64-trunk_staging-userdebug \
-    sdk_car_portrait_x86_64-trunk_staging-userdebug \
+    sdk_car_cw_x86_64-trunk_staging-userdebug \
     sdk_car_x86_64-trunk_staging-userdebug \
 
 EMULATOR_VENDOR_NO_SOUND_TRIGGER := false
diff --git a/common/car_core_hardware.xml b/common/car_core_hardware.xml
index 5291572..08f291e 100644
--- a/common/car_core_hardware.xml
+++ b/common/car_core_hardware.xml
@@ -49,6 +49,7 @@
     <feature name="android.software.companion_device_setup" />
     <feature name="android.software.cant_save_state" />
     <feature name="android.software.secure_lock_screen" />
+    <feature name="android.software.input_methods" />
 
     <!-- devices with GPS must include android.hardware.location.gps.xml -->
     <!-- devices with an autofocus camera and/or flash must include either
diff --git a/common/car_md.mk b/common/car_md.mk
index d79de9f..6b1830a 100644
--- a/common/car_md.mk
+++ b/common/car_md.mk
@@ -26,9 +26,6 @@ PRODUCT_COPY_FILES += \
     device/generic/car/emulator/multi-display/display_layout_configuration.xml:$(TARGET_COPY_OUT_VENDOR)/etc/displayconfig/display_layout_configuration.xml \
     device/generic/car/emulator/multi-display/display_settings.xml:$(TARGET_COPY_OUT_VENDOR)/etc/display_settings.xml
 
-PRODUCT_PACKAGE_OVERLAYS += \
-    device/generic/car/emulator/multi-display/overlay
-
 PRODUCT_COPY_FILES += \
     device/generic/car/emulator/multi-display/car_audio_configuration.xml:$(TARGET_COPY_OUT_VENDOR)/etc/car_audio_configuration.xml
 
@@ -39,7 +36,8 @@ EMULATOR_MULTIDISPLAY_HW_CONFIG := 1,968,792,160,0,2,1408,792,160,0,3,1408,792,1
 EMULATOR_MULTIDISPLAY_BOOTANIM_CONFIG := 4619827551948147201,4619827124781842690,4619827540095559171
 ENABLE_CLUSTER_OS_DOUBLE:=true
 
-PRODUCT_PACKAGES += CarServiceOverlayMdEmulatorOsDouble
+PRODUCT_PACKAGES += CarServiceOverlayMdEmulatorOsDouble \
+    CarFrameworkResConfigMultiDisplayRRO
 
 # Enable MZ audio by default
 PRODUCT_SYSTEM_DEFAULT_PROPERTIES += \
@@ -48,7 +46,6 @@ PRODUCT_SYSTEM_DEFAULT_PROPERTIES += \
     com.android.car.internal.debug.num_auto_populated_users=1
 
 PRODUCT_PACKAGES += \
-    MultiDisplaySecondaryHomeTestLauncher \
     MultiDisplayTest
 
 # enables the rro package for passenger(secondary) user.
diff --git a/common/overlay/frameworks/base/core/res/res/values/config.xml b/common/overlay/frameworks/base/core/res/res/values/config.xml
index 920d758..a50088d 100644
--- a/common/overlay/frameworks/base/core/res/res/values/config.xml
+++ b/common/overlay/frameworks/base/core/res/res/values/config.xml
@@ -44,4 +44,7 @@
     <integer-array translatable="false" name="config_localPrivateDisplayPorts">
         <item>1</item> <!-- ClusterDisplay -->
     </integer-array>
+
+    <!-- The name of the package that will hold the dialer role by default. -->
+    <string name="config_defaultDialer" translatable="false">com.android.car.dialer</string>
 </resources>
diff --git a/common/overlay/frameworks/base/packages/SettingsProvider/res/values/defaults.xml b/common/overlay/frameworks/base/packages/SettingsProvider/res/values/defaults.xml
index 03f69db..8a1923d 100644
--- a/common/overlay/frameworks/base/packages/SettingsProvider/res/values/defaults.xml
+++ b/common/overlay/frameworks/base/packages/SettingsProvider/res/values/defaults.xml
@@ -17,6 +17,5 @@
  */
 -->
 <resources>
-    <bool name="def_user_setup_complete">true</bool>
     <bool name="def_wifi_on">true</bool>
 </resources>
diff --git a/common/preinstalled-packages-product-car-emulator.xml b/common/preinstalled-packages-product-car-emulator.xml
index 1b65849..9526704 100644
--- a/common/preinstalled-packages-product-car-emulator.xml
+++ b/common/preinstalled-packages-product-car-emulator.xml
@@ -193,9 +193,6 @@
         <install-in user-type="FULL" />
         <install-in user-type="SYSTEM" />
     </install-in-user-type>
-    <install-in-user-type package="com.android.car.multidisplay">
-        <install-in user-type="FULL" />
-    </install-in-user-type>
     <install-in-user-type package="com.google.android.car.multidisplaytest">
         <install-in user-type="FULL" />
     </install-in-user-type>
diff --git a/emulator/aosp_car_emulator.mk b/emulator/aosp_car_emulator.mk
index 7c74015..94f28dd 100644
--- a/emulator/aosp_car_emulator.mk
+++ b/emulator/aosp_car_emulator.mk
@@ -27,10 +27,17 @@ $(call inherit-product, device/generic/car/common/car.mk)
 # This overrides device/generic/car/common/car.mk
 $(call inherit-product, device/generic/car/emulator/audio/car_emulator_audio.mk)
 $(call inherit-product, device/generic/car/emulator/rotary/car_rotary.mk)
+
+ifeq (,$(ENABLE_CAR_USB_PASSTHROUGH))
+ENABLE_CAR_USB_PASSTHROUGH := false
+endif
+
+ifeq (true,$(ENABLE_CAR_USB_PASSTHROUGH))
 # Enables USB related passthrough
 $(call inherit-product, device/generic/car/emulator/usbpt/car_usbpt.mk)
 
 TARGET_PRODUCT_PROP := device/generic/car/emulator/usbpt/bluetooth/bluetooth.prop
+endif
 
 # EVS
 # By default, we enable EvsManager, a sample EVS app, and a mock EVS HAL implementation.
diff --git a/emulator/audio/halservice/Android.bp b/emulator/audio/halservice/Android.bp
index 0e1bd8b..20e4ce3 100644
--- a/emulator/audio/halservice/Android.bp
+++ b/emulator/audio/halservice/Android.bp
@@ -47,7 +47,7 @@ cc_binary {
         "android.hardware.audio@6.0",
         "android.hardware.audio.common@6.0",
         "android.hardware.audio.effect@6.0",
-        "android.hardware.automotive.audiocontrol-V1-ndk",
+        "android.hardware.automotive.audiocontrol-V3-ndk",
         "audiocontrol-caremu",
         "libbase",
         "libbinder",
@@ -69,7 +69,8 @@ cc_library {
 
     shared_libs: [
         "android.hardware.audio.common@7.0-enums",
-        "android.hardware.automotive.audiocontrol-V1-ndk",
+        "android.hardware.audio.common-V1-ndk",
+        "android.hardware.automotive.audiocontrol-V3-ndk",
         "libbase",
         "libbinder_ndk",
         "libcutils",
@@ -82,6 +83,6 @@ cc_library {
     ],
 
     include_dirs: [
-        "device/generic/car/emulator/audio/driver/include"
+        "device/generic/car/emulator/audio/driver/include",
     ],
 }
diff --git a/emulator/audio/halservice/AudioControl.cpp b/emulator/audio/halservice/AudioControl.cpp
index 6b2e5a2..f6216aa 100644
--- a/emulator/audio/halservice/AudioControl.cpp
+++ b/emulator/audio/halservice/AudioControl.cpp
@@ -25,12 +25,15 @@
 #include <aidl/android/hardware/automotive/audiocontrol/IFocusListener.h>
 
 #include <android-base/logging.h>
+#include <android-base/parsebool.h>
 #include <android-base/parseint.h>
 #include <android-base/strings.h>
 
 #include <android_audio_policy_configuration_V7_0-enums.h>
 #include <private/android_filesystem_config.h>
 
+#include <numeric>
+
 #include <stdio.h>
 
 namespace aidl {
@@ -40,6 +43,8 @@ namespace automotive {
 namespace audiocontrol {
 
 using ::android::base::EqualsIgnoreCase;
+using ::android::base::ParseBool;
+using ::android::base::ParseBoolResult;
 using ::android::base::ParseInt;
 using ::std::shared_ptr;
 using ::std::string;
@@ -73,6 +78,107 @@ bool safelyParseInt(string s, int* out) {
 }
 }  // namespace
 
+
+namespace {
+using ::aidl::android::media::audio::common::AudioChannelLayout;
+using ::aidl::android::media::audio::common::AudioDeviceType;
+using ::aidl::android::media::audio::common::AudioFormatType;
+using ::aidl::android::media::audio::common::AudioGain;
+using ::aidl::android::media::audio::common::AudioGainMode;
+using ::aidl::android::media::audio::common::AudioIoFlags;
+using ::aidl::android::media::audio::common::AudioPort;
+using ::aidl::android::media::audio::common::AudioPortDeviceExt;
+using ::aidl::android::media::audio::common::AudioPortExt;
+using ::aidl::android::media::audio::common::AudioProfile;
+using ::aidl::android::media::audio::common::PcmType;
+
+// reuse common code artifacts
+void fillProfile(const std::vector<int32_t>& channelLayouts,
+                 const std::vector<int32_t>& sampleRates, AudioProfile* profile) {
+    for (auto layout : channelLayouts) {
+        profile->channelMasks.push_back(
+                AudioChannelLayout::make<AudioChannelLayout::layoutMask>(layout));
+    }
+    profile->sampleRates.insert(profile->sampleRates.end(), sampleRates.begin(), sampleRates.end());
+}
+
+AudioProfile createProfile(PcmType pcmType, const std::vector<int32_t>& channelLayouts,
+                           const std::vector<int32_t>& sampleRates) {
+    AudioProfile profile;
+    profile.format.type = AudioFormatType::PCM;
+    profile.format.pcm = pcmType;
+    fillProfile(channelLayouts, sampleRates, &profile);
+    return profile;
+}
+
+AudioProfile createProfile(const std::string& encodingType,
+                           const std::vector<int32_t>& channelLayouts,
+                           const std::vector<int32_t>& sampleRates) {
+    AudioProfile profile;
+    profile.format.encoding = encodingType;
+    fillProfile(channelLayouts, sampleRates, &profile);
+    return profile;
+}
+
+AudioPortExt createDeviceExt(AudioDeviceType devType, int32_t flags,
+                             const std::string& connection = "", const std::string& address = "") {
+    AudioPortDeviceExt deviceExt;
+    deviceExt.device.type.type = devType;
+    if (devType == AudioDeviceType::IN_MICROPHONE && connection.empty()) {
+        deviceExt.device.address = "bottom";
+    } else if (devType == AudioDeviceType::IN_MICROPHONE_BACK && connection.empty()) {
+        deviceExt.device.address = "back";
+    } else {
+        deviceExt.device.address = address;
+    }
+    deviceExt.device.type.connection = connection;
+    deviceExt.flags = flags;
+    return AudioPortExt::make<AudioPortExt::Tag::device>(deviceExt);
+}
+
+AudioPort createPort(int32_t id, const std::string& name, int32_t flags, bool isInput,
+                     const AudioPortExt& ext) {
+    AudioPort port;
+    port.id = id;
+    port.name = name;
+    port.flags = isInput ? AudioIoFlags::make<AudioIoFlags::Tag::input>(flags)
+                         : AudioIoFlags::make<AudioIoFlags::Tag::output>(flags);
+    port.ext = ext;
+    return port;
+}
+
+AudioGain createGain(int32_t mode, AudioChannelLayout channelMask, int32_t minValue,
+                     int32_t maxValue, int32_t defaultValue, int32_t stepValue,
+                     int32_t minRampMs = 100, int32_t maxRampMs = 100, bool useForVolume = true) {
+    AudioGain gain;
+    gain.mode = mode;
+    gain.channelMask = channelMask;
+    gain.minValue = minValue;
+    gain.maxValue = maxValue;
+    gain.defaultValue = defaultValue;
+    gain.stepValue = stepValue;
+    gain.minRampMs = minRampMs;
+    gain.maxRampMs = maxRampMs;
+    gain.useForVolume = useForVolume;
+    return gain;
+}
+}  // namespace
+
+template <typename aidl_type>
+static inline std::string toString(const std::vector<aidl_type>& in_values) {
+    return std::accumulate(std::begin(in_values), std::end(in_values), std::string{},
+                           [](const std::string& ls, const aidl_type& rs) {
+                               return ls + (ls.empty() ? "" : ",") + rs.toString();
+                           });
+}
+template <typename aidl_enum_type>
+static inline std::string toEnumString(const std::vector<aidl_enum_type>& in_values) {
+    return std::accumulate(std::begin(in_values), std::end(in_values), std::string{},
+                           [](const std::string& ls, const aidl_enum_type& rs) {
+                               return ls + (ls.empty() ? "" : ",") + toString(rs);
+                           });
+}
+
 ndk::ScopedAStatus AudioControl::registerFocusListener(
         const shared_ptr<IFocusListener>& in_listener) {
 
@@ -155,6 +261,62 @@ ndk::ScopedAStatus AudioControl::onDevicesToMuteChange(
     return ndk::ScopedAStatus::ok();
 }
 
+ndk::ScopedAStatus AudioControl::onAudioFocusChangeWithMetaData(
+        const audiohalcommon::PlaybackTrackMetadata& in_playbackMetaData, int32_t in_zoneId,
+        AudioFocusChange in_focusChange) {
+    LOG(INFO) << "Focus changed: " << toString(in_focusChange).c_str() << " for metadata "
+              << in_playbackMetaData.toString().c_str() << " in zone " << in_zoneId;
+    return ndk::ScopedAStatus::ok();
+}
+
+ndk::ScopedAStatus AudioControl::setAudioDeviceGainsChanged(
+        const std::vector<Reasons>& in_reasons, const std::vector<AudioGainConfigInfo>& in_gains) {
+    LOG(INFO) << "Audio Device Gains changed: reasons: ["
+              << toEnumString(in_reasons).c_str() << "]" << " for devices: ["
+              << toString(in_gains).c_str() << "]";
+    return ndk::ScopedAStatus::ok();
+}
+
+ndk::ScopedAStatus AudioControl::registerGainCallback(
+        const std::shared_ptr<IAudioGainCallback>& in_callback) {
+    LOG(DEBUG) << __func__;
+    if (in_callback) {
+        std::atomic_store(&mAudioGainCallback, in_callback);
+    } else {
+        LOG(ERROR) << "Unexpected nullptr for audio gain callback resulting in no-op.";
+    }
+    return ndk::ScopedAStatus::ok();
+}
+
+ndk::ScopedAStatus AudioControl::setModuleChangeCallback(
+        const std::shared_ptr<IModuleChangeCallback>& in_callback) {
+    LOG(DEBUG) << __func__;
+    if (in_callback.get() == nullptr) {
+        LOG(ERROR) << __func__ << ": Callback is nullptr";
+        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
+    }
+    shared_ptr<IModuleChangeCallback> currentCallback = std::atomic_load(&mModuleChangeCallback);
+    if (currentCallback != nullptr) {
+        LOG(ERROR) << __func__ << ": Module change callback was already registered";
+        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
+    }
+    std::atomic_store(&mModuleChangeCallback, in_callback);
+    return ndk::ScopedAStatus::ok();
+}
+
+ndk::ScopedAStatus AudioControl::clearModuleChangeCallback() {
+    LOG(DEBUG) << __func__;
+    shared_ptr<IModuleChangeCallback> currentCallback = std::atomic_load(&mModuleChangeCallback);
+    if (currentCallback != nullptr) {
+        shared_ptr<IModuleChangeCallback> nullCallback = nullptr;
+        std::atomic_store(&mModuleChangeCallback, nullCallback);
+        LOG(DEBUG) << __func__ << ": Unregistered successfully";
+    } else {
+        LOG(DEBUG) << __func__ << ": No callback registered, no-op";
+    }
+    return ndk::ScopedAStatus::ok();
+}
+
 binder_status_t AudioControl::dump(int fd, const char** args, uint32_t numArgs) {
     if (numArgs == 0) {
         return dumpsys(fd);
@@ -167,6 +329,14 @@ binder_status_t AudioControl::dump(int fd, const char** args, uint32_t numArgs)
         return cmdRequestFocus(fd, args, numArgs);
     } else if (EqualsIgnoreCase(option, "--abandon")) {
         return cmdAbandonFocus(fd, args, numArgs);
+    } else if (EqualsIgnoreCase(option, "--requestFocusWithMetaData")) {
+        return cmdRequestFocusWithMetaData(fd, args, numArgs);
+    } else if (EqualsIgnoreCase(option, "--abandonFocusWithMetaData")) {
+        return cmdAbandonFocusWithMetaData(fd, args, numArgs);
+    } else if (EqualsIgnoreCase(option, "--audioGainCallback")) {
+        return cmdOnAudioDeviceGainsChanged(fd, args, numArgs);
+    } else if (EqualsIgnoreCase(option, "--audioPortsChangedCallback")) {
+        return cmdOnAudioPortsChanged(fd, args, numArgs);
     } else {
         dprintf(fd, "Invalid option: %s\n", option.c_str());
         return STATUS_BAD_VALUE;
@@ -181,20 +351,69 @@ binder_status_t AudioControl::dumpsys(int fd) {
     } else {
         dprintf(fd, "Focus listener registered\n");
     }
+    dprintf(fd, "AudioGainCallback %sregistered\n", (mAudioGainCallback == nullptr ? "NOT " : ""));
+    dprintf(fd, "ModuleChangeCallback %sregistered\n",
+            (mModuleChangeCallback == nullptr ? "NOT " : ""));
     return STATUS_OK;
 }
 
 binder_status_t AudioControl::cmdHelp(int fd) const {
     dprintf(fd, "Usage: \n\n");
-    dprintf(fd, "[no args]: dumps focus listener status\n");
+    dprintf(fd, "[no args]: dumps focus listener status/gain callback registered\n");
     dprintf(fd, "--help: shows this help\n");
     dprintf(fd,
             "--request <USAGE> <ZONE_ID> <FOCUS_GAIN>: requests audio focus for specified "
-            "usage (string), audio zone ID (int), and focus gain type (int)\n");
+            "usage (string), audio zone ID (int), and focus gain type (int)\n"
+            "Deprecated, use MetaData instead\n");
     dprintf(fd,
             "--abandon <USAGE> <ZONE_ID>: abandons audio focus for specified usage (string) and "
-            "audio zone ID (int)\n");
+            "audio zone ID (int)\n"
+            "Deprecated, use MetaData instead\n");
     dprintf(fd, "See audio_policy_configuration.xsd for valid AudioUsage values.\n");
+    dprintf(fd,
+            "--requestFocusWithMetaData <METADATA> <ZONE_ID> <FOCUS_GAIN>: "
+            "requests audio focus for specified metadata, audio zone ID (int), "
+            "and focus gain type (int) "
+            "Example: --requestFocusWithMetaData 1,1,com.oem.strategy=VR 1 2\n");
+    dprintf(fd,
+            "--abandonFocusWithMetaData <METADATA> <ZONE_ID>: "
+            "abandons audio focus for specified metadata and audio zone ID (int) "
+            "Example: --abandonFocusWithMetaData 1,1,com.oem.strategy=VR 1\n");
+    dprintf(fd,
+            "--audioGainCallback <ZONE_ID> <REASON_1>[,<REASON_N> ...]"
+            "<DEVICE_ADDRESS_1> <GAIN_INDEX_1> [<DEVICE_ADDRESS_N> <GAIN_INDEX_N> ...]: fire audio "
+            "gain callback for audio zone ID (int), the given reasons (csv int) for given pairs "
+            "of device address (string) and gain index (int) "
+            "Example: --audioGainCallback 0 8 BUS00_MEDIA 12\n");
+
+    dprintf(fd,
+            "Note on <METADATA>: <USAGE,CONTENT_TYPE[,TAGS]>  specified as where (int)usage, "
+            "(int)content type and tags (string)string)\n");
+    dprintf(fd,
+            "See android/media/audio/common/AudioUsageType.aidl for valid AudioUsage values.\n");
+    dprintf(fd,
+            "See android/media/audio/common/AudioContentType.aidl for valid AudioContentType "
+            "values.\n");
+    dprintf(fd,
+            "Tags are optional. If provided, it must follow the <key>=<value> pattern, where the "
+            "value is namespaced (for example com.google.strategy=VR).\n");
+    dprintf(fd,
+            "--audioPortsChangedCallback <ID_1> <NAME_1> <BUS_ADDRESS_1> <CONNECTION_TYPE_1> "
+            "<AUDIO_GAINS_1> [<ID_N> <NAME_N> <BUS_ADDRESS_N> <CONNECTION_TYPE_N> "
+            "<AUDIO_GAINS_N>]: fires audio ports changed callback. Carries list of modified "
+            "AudioPorts. "
+            "For simplicity, this command accepts limited information for each AudioPort: "
+            "id(int), name(string), port address(string), connection type (string), "
+            "audio gain (csv int) "
+            "Example: --audioPortsChangedCallback 1 media BUS_MEDIA bus 0,0,0,38,10,1,100,100,1 "
+            "2 sys BUS_NOTIFICATIONS bus 0,0,0,38,10,1,100,100,1\n");
+    dprintf(fd, "Notes: \n");
+    dprintf(fd,
+            "1. AudioGain csv should match definition at "
+            "android/media/audio/common/AudioPort.aidl\n");
+    dprintf(fd,
+            "2. See android/media/audio/common/AudioDeviceDescription.aidl for valid "
+            "<CONNECTION_TYPE> values.\n");
     return STATUS_OK;
 }
 
@@ -278,6 +497,338 @@ binder_status_t AudioControl::cmdAbandonFocus(int fd, const char** args, uint32_
     return STATUS_OK;
 }
 
+binder_status_t AudioControl::parseMetaData(int fd, const std::string& metadataLiteral,
+                                            audiohalcommon::PlaybackTrackMetadata& trackMetadata) {
+    std::stringstream csvMetaData(metadataLiteral);
+    std::vector<std::string> splitMetaData;
+    std::string attribute;
+    while (getline(csvMetaData, attribute, ',')) {
+        splitMetaData.push_back(attribute);
+    }
+    if (splitMetaData.size() != 2 && splitMetaData.size() != 3) {
+        dprintf(fd,
+                "Invalid metadata: %s, please provide <METADATA> as <USAGE,CONTENT_TYPE[,TAGS]> "
+                "where (int)usage, (int)content type and tags (string)string)\n",
+                metadataLiteral.c_str());
+        return STATUS_BAD_VALUE;
+    }
+    int usage;
+    if (!safelyParseInt(splitMetaData[0], &usage)) {
+        dprintf(fd, "Non-integer usage provided with request: %s\n", splitMetaData[0].c_str());
+        return STATUS_BAD_VALUE;
+    }
+    int contentType;
+    if (!safelyParseInt(splitMetaData[1], &contentType)) {
+        dprintf(fd, "Non-integer content type provided with request: %s\n",
+                splitMetaData[1].c_str());
+        return STATUS_BAD_VALUE;
+    }
+    const std::string tags = (splitMetaData.size() == 3 ? splitMetaData[2] : "");
+
+    trackMetadata = {.usage = static_cast<audiomediacommon::AudioUsage>(usage),
+                     .contentType = static_cast<audiomediacommon::AudioContentType>(contentType),
+                     .tags = {tags}};
+    return STATUS_OK;
+}
+
+binder_status_t AudioControl::cmdRequestFocusWithMetaData(int fd, const char** args,
+                                                          uint32_t numArgs) {
+    if (!checkCallerHasWritePermissions(fd)) {
+        return STATUS_PERMISSION_DENIED;
+    }
+    if (numArgs != 4) {
+        dprintf(fd,
+                "Invalid number of arguments: please provide:\n"
+                "--requestFocusWithMetaData <METADATA> <ZONE_ID> <FOCUS_GAIN>: "
+                "requests audio focus for specified metadata, audio zone ID (int), "
+                "and focus gain type (int)\n");
+        return STATUS_BAD_VALUE;
+    }
+    std::string metadataLiteral = std::string(args[1]);
+    audiohalcommon::PlaybackTrackMetadata trackMetadata{};
+    auto status = parseMetaData(fd, metadataLiteral, trackMetadata);
+    if (status != STATUS_OK) {
+        return status;
+    }
+
+    int zoneId;
+    if (!safelyParseInt(std::string(args[2]), &zoneId)) {
+        dprintf(fd, "Non-integer zoneId provided with request: %s\n", std::string(args[2]).c_str());
+        return STATUS_BAD_VALUE;
+    }
+
+    int focusGainValue;
+    if (!safelyParseInt(std::string(args[3]), &focusGainValue)) {
+        dprintf(fd, "Non-integer focusGain provided with request: %s\n",
+                std::string(args[3]).c_str());
+        return STATUS_BAD_VALUE;
+    }
+    AudioFocusChange focusGain = AudioFocusChange(focusGainValue);
+
+    if (mFocusListener == nullptr) {
+        dprintf(fd, "Unable to request focus - no focus listener registered\n");
+        return STATUS_BAD_VALUE;
+    }
+    mFocusListener->requestAudioFocusWithMetaData(trackMetadata, zoneId, focusGain);
+    dprintf(fd, "Requested focus for metadata %s, zoneId %d, and focusGain %d\n",
+            trackMetadata.toString().c_str(), zoneId, focusGain);
+    return STATUS_OK;
+}
+
+binder_status_t AudioControl::cmdAbandonFocusWithMetaData(int fd, const char** args,
+                                                          uint32_t numArgs) {
+    if (!checkCallerHasWritePermissions(fd)) {
+        return STATUS_PERMISSION_DENIED;
+    }
+    if (numArgs != 3) {
+        dprintf(fd,
+                "Invalid number of arguments: please provide:\n"
+                "--abandonFocusWithMetaData <METADATA> <ZONE_ID>: "
+                "abandons audio focus for specified metadata and audio zone ID (int)\n");
+        return STATUS_BAD_VALUE;
+    }
+    std::string metadataLiteral = std::string(args[1]);
+    audiohalcommon::PlaybackTrackMetadata trackMetadata{};
+    auto status = parseMetaData(fd, metadataLiteral, trackMetadata);
+    if (status != STATUS_OK) {
+        return status;
+    }
+    int zoneId;
+    if (!safelyParseInt(std::string(args[2]), &zoneId)) {
+        dprintf(fd, "Non-integer zoneId provided with request: %s\n", std::string(args[2]).c_str());
+        return STATUS_BAD_VALUE;
+    }
+    if (mFocusListener == nullptr) {
+        dprintf(fd, "Unable to abandon focus - no focus listener registered\n");
+        return STATUS_BAD_VALUE;
+    }
+
+    mFocusListener->abandonAudioFocusWithMetaData(trackMetadata, zoneId);
+    dprintf(fd, "Abandoned focus for metadata %s and zoneId %d\n", trackMetadata.toString().c_str(),
+            zoneId);
+    return STATUS_OK;
+}
+
+binder_status_t AudioControl::cmdOnAudioDeviceGainsChanged(int fd, const char** args,
+                                                           uint32_t numArgs) {
+    if (!checkCallerHasWritePermissions(fd)) {
+        return STATUS_PERMISSION_DENIED;
+    }
+    if ((numArgs + 1) % 2 != 0) {
+        dprintf(fd,
+                "Invalid number of arguments: please provide\n"
+                "--audioGainCallback <ZONE_ID> <REASON_1>[,<REASON_N> ...]"
+                "<DEVICE_ADDRESS_1> <GAIN_INDEX_1> [<DEVICE_ADDRESS_N> <GAIN_INDEX_N> ...]: "
+                "fire audio gain callback for audio zone ID (int), "
+                "with the given reasons (csv int) for given pairs of device address (string) "
+                "and gain index (int) \n");
+        return STATUS_BAD_VALUE;
+    }
+    int zoneId;
+    if (!safelyParseInt(string(args[1]), &zoneId)) {
+        dprintf(fd, "Non-integer zoneId provided with request: %s\n", std::string(args[1]).c_str());
+        return STATUS_BAD_VALUE;
+    }
+    std::string reasonsLiteral = std::string(args[2]);
+    std::stringstream csvReasonsLiteral(reasonsLiteral);
+    std::vector<Reasons> reasons;
+    std::string reasonLiteral;
+    while (getline(csvReasonsLiteral, reasonLiteral, ',')) {
+        int reason;
+        if (!safelyParseInt(reasonLiteral, &reason)) {
+            dprintf(fd, "Invalid Reason(s) provided %s\n", reasonLiteral.c_str());
+            return STATUS_BAD_VALUE;
+        }
+        reasons.push_back(static_cast<Reasons>(reason));
+    }
+
+    std::vector<AudioGainConfigInfo> agcis{};
+    for (uint32_t i = 3; i < numArgs; i += 2) {
+        std::string deviceAddress = std::string(args[i]);
+        int32_t index;
+        if (!safelyParseInt(std::string(args[i + 1]), &index)) {
+            dprintf(fd, "Non-integer index provided with request: %s\n",
+                    std::string(args[i + 1]).c_str());
+            return STATUS_BAD_VALUE;
+        }
+        AudioGainConfigInfo agci{zoneId, deviceAddress, index};
+        agcis.push_back(agci);
+    }
+    if (mAudioGainCallback == nullptr) {
+        dprintf(fd,
+                "Unable to trig audio gain callback for reasons=%s and gains=%s\n"
+                " - no audio gain callback registered\n",
+                toEnumString(reasons).c_str(), toString(agcis).c_str());
+        return STATUS_BAD_VALUE;
+    }
+
+    mAudioGainCallback->onAudioDeviceGainsChanged(reasons, agcis);
+    dprintf(fd, "Fired audio gain callback for reasons=%s and gains=%s\n",
+            toEnumString(reasons).c_str(), toString(agcis).c_str());
+    return STATUS_OK;
+}
+
+binder_status_t AudioControl::parseAudioGains(int fd, const std::string& stringGain,
+                                              std::vector<AudioGain>& gains) {
+    const int kAudioGainSize = 9;
+    std::stringstream csvGain(stringGain);
+    std::vector<std::string> vecGain;
+    std::string value;
+    while (getline(csvGain, value, ',')) {
+        vecGain.push_back(value);
+    }
+
+    if ((vecGain.size() == 0) || ((vecGain.size() % kAudioGainSize) != 0)) {
+        dprintf(fd, "Erroneous input to generate AudioGain: %s\n", stringGain.c_str());
+        return STATUS_BAD_VALUE;
+    }
+
+    // iterate over injected AudioGains
+    for (int index = 0; index < vecGain.size(); index += kAudioGainSize) {
+        int32_t mode;
+        if (!safelyParseInt(vecGain[index], &mode)) {
+            dprintf(fd, "Non-integer index provided with request: %s\n", vecGain[index].c_str());
+            return STATUS_BAD_VALUE;
+        }
+
+        // car audio framework only supports JOINT mode.
+        // skip injected AudioGains that are not compliant with this.
+        if (mode != static_cast<int>(AudioGainMode::JOINT)) {
+            LOG(WARNING) << __func__ << ": skipping gain since it is not JOINT mode!";
+            continue;
+        }
+
+        int32_t layout;
+        if (!safelyParseInt(vecGain[index + 1], &layout)) {
+            dprintf(fd, "Non-integer index provided with request: %s\n",
+                    vecGain[index + 1].c_str());
+            return STATUS_BAD_VALUE;
+        }
+        AudioChannelLayout channelMask =
+                AudioChannelLayout::make<AudioChannelLayout::layoutMask>(layout);
+
+        int32_t minValue;
+        if (!safelyParseInt(vecGain[index + 2], &minValue)) {
+            dprintf(fd, "Non-integer index provided with request: %s\n",
+                    vecGain[index + 2].c_str());
+            return STATUS_BAD_VALUE;
+        }
+
+        int32_t maxValue;
+        if (!safelyParseInt(vecGain[index + 3], &maxValue)) {
+            dprintf(fd, "Non-integer index provided with request: %s\n",
+                    vecGain[index + 3].c_str());
+            return STATUS_BAD_VALUE;
+        }
+
+        int32_t defaultValue;
+        if (!safelyParseInt(vecGain[index + 4], &defaultValue)) {
+            dprintf(fd, "Non-integer index provided with request: %s\n",
+                    vecGain[index + 4].c_str());
+            return STATUS_BAD_VALUE;
+        }
+
+        int32_t stepValue;
+        if (!safelyParseInt(vecGain[index + 5], &stepValue)) {
+            dprintf(fd, "Non-integer index provided with request: %s\n",
+                    vecGain[index + 5].c_str());
+            return STATUS_BAD_VALUE;
+        }
+
+        int32_t minRampMs;
+        if (!safelyParseInt(vecGain[index + 6], &minRampMs)) {
+            dprintf(fd, "Non-integer index provided with request: %s\n",
+                    vecGain[index + 6].c_str());
+            return STATUS_BAD_VALUE;
+        }
+
+        int32_t maxRampMs;
+        if (!safelyParseInt(vecGain[index + 7], &maxRampMs)) {
+            dprintf(fd, "Non-integer index provided with request: %s\n",
+                    vecGain[index + 7].c_str());
+            return STATUS_BAD_VALUE;
+        }
+
+        ParseBoolResult useForVolume = ParseBool(vecGain[index + 8]);
+        if (useForVolume == ParseBoolResult::kError) {
+            dprintf(fd, "Non-boolean index provided with request: %s\n",
+                    vecGain[index + 8].c_str());
+            return STATUS_BAD_VALUE;
+        } else if (useForVolume == ParseBoolResult::kFalse) {
+            // at this level we only care about gain stages that are relevant
+            // for volume control. skip the gain stage if its flagged as false.
+            LOG(WARNING) << __func__
+                         << ": skipping gain since it is not for volume control!";
+            continue;
+        }
+
+        AudioGain gain = createGain(mode, channelMask, minValue, maxValue, defaultValue, stepValue,
+                                    minRampMs, maxRampMs, true /*useForVolume*/);
+        gains.push_back(gain);
+    }
+    return STATUS_OK;
+}
+
+binder_status_t AudioControl::cmdOnAudioPortsChanged(int fd, const char** args, uint32_t numArgs) {
+    if (!checkCallerHasWritePermissions(fd)) {
+        return STATUS_PERMISSION_DENIED;
+    }
+
+    if ((numArgs < 6) || ((numArgs - 1) % 5 != 0)) {
+        dprintf(fd,
+                "Invalid number of arguments: please provide\n"
+                "--audioPortsChangedCallback <ID_1> <NAME_1> <BUS_ADDRESS_1> <CONNECTION_TYPE_1> "
+                "<AUDIO_GAINS_1> [<ID_N> <NAME_N> <BUS_ADDRESS_N> <CONNECTION_TYPE_N> "
+                "<AUDIO_GAINS_N>]: triggers audio ports changed callback. Carries list of "
+                "modified AudioPorts. "
+                "For simplicity, this command accepts limited information for each AudioPort: "
+                "id(int), name(string), port address(string), connection type (string), "
+                "audio gain (csv int)\n");
+        return STATUS_BAD_VALUE;
+    }
+
+    std::vector<AudioPort> ports;
+    for (uint32_t i = 1; i < numArgs; i += 5) {
+        binder_status_t status;
+        int32_t id;
+        if (!safelyParseInt(std::string(args[i]), &id)) {
+            dprintf(fd, "Non-integer index provided with request: %s\n",
+                    std::string(args[i]).c_str());
+            return STATUS_BAD_VALUE;
+        }
+
+        std::string name = std::string(args[i + 1]);
+        std::string address = std::string(args[i + 2]);
+        std::string connection = std::string(args[i + 3]);
+
+        std::string stringGains = std::string(args[i + 4]);
+        std::vector<AudioGain> gains;
+        status = parseAudioGains(fd, stringGains, gains);
+        if (status != STATUS_OK) {
+            return status;
+        }
+
+        AudioPort port = createPort(
+                id, name, 0 /*flags*/, false /*isInput*/,
+                createDeviceExt(AudioDeviceType::OUT_DEVICE, 0 /*flags*/, connection, address));
+        port.gains.insert(port.gains.begin(), gains.begin(), gains.end());
+
+        ports.push_back(port);
+    }
+
+    shared_ptr<IModuleChangeCallback> callback = std::atomic_load(&mModuleChangeCallback);
+    if (callback == nullptr) {
+        dprintf(fd,
+                "Unable to trigger audio port callback for ports: %s \n"
+                " - no module change callback registered\n",
+                toString(ports).c_str());
+        return STATUS_BAD_VALUE;
+    }
+
+    callback->onAudioPortsChanged(ports);
+    dprintf(fd, "SUCCESS audio port callback for ports: %s \n", toString(ports).c_str());
+    return STATUS_OK;
+}
 }  // namespace audiocontrol
 }  // namespace automotive
 }  // namespace hardware
diff --git a/emulator/audio/halservice/AudioControl.h b/emulator/audio/halservice/AudioControl.h
index af11448..51303d0 100644
--- a/emulator/audio/halservice/AudioControl.h
+++ b/emulator/audio/halservice/AudioControl.h
@@ -17,9 +17,22 @@
 #define ANDROID_HARDWARE_AUTOMOTIVE_AUDIOCONTROL_AUDIOCONTROL_H
 
 #include <aidl/android/hardware/automotive/audiocontrol/AudioFocusChange.h>
+#include <aidl/android/hardware/automotive/audiocontrol/AudioGainConfigInfo.h>
 #include <aidl/android/hardware/automotive/audiocontrol/BnAudioControl.h>
 #include <aidl/android/hardware/automotive/audiocontrol/DuckingInfo.h>
+#include <aidl/android/hardware/automotive/audiocontrol/IAudioGainCallback.h>
+#include <aidl/android/hardware/automotive/audiocontrol/IModuleChangeCallback.h>
 #include <aidl/android/hardware/automotive/audiocontrol/MutingInfo.h>
+#include <aidl/android/hardware/automotive/audiocontrol/Reasons.h>
+#include <aidl/android/hardware/audio/common/PlaybackTrackMetadata.h>
+
+#include <aidl/android/media/audio/common/AudioChannelLayout.h>
+#include <aidl/android/media/audio/common/AudioDeviceType.h>
+#include <aidl/android/media/audio/common/AudioFormatDescription.h>
+#include <aidl/android/media/audio/common/AudioFormatType.h>
+#include <aidl/android/media/audio/common/AudioGainMode.h>
+#include <aidl/android/media/audio/common/AudioIoFlags.h>
+#include <aidl/android/media/audio/common/AudioOutputFlags.h>
 
 namespace aidl {
 namespace android {
@@ -27,6 +40,9 @@ namespace hardware {
 namespace automotive {
 namespace audiocontrol {
 
+namespace audiohalcommon = ::aidl::android::hardware::audio::common;
+namespace audiomediacommon = ::aidl::android::media::audio::common;
+
 class AudioControl : public BnAudioControl {
   public:
     ndk::ScopedAStatus onAudioFocusChange(const std::string& in_usage, int32_t in_zoneId,
@@ -39,6 +55,18 @@ class AudioControl : public BnAudioControl {
             const std::shared_ptr<IFocusListener>& in_listener) override;
     ndk::ScopedAStatus setBalanceTowardRight(float in_value) override;
     ndk::ScopedAStatus setFadeTowardFront(float in_value) override;
+    ndk::ScopedAStatus onAudioFocusChangeWithMetaData(
+            const audiohalcommon::PlaybackTrackMetadata &in_playbackMetaData, int32_t in_zoneId,
+            AudioFocusChange in_focusChange) override;
+    ndk::ScopedAStatus setAudioDeviceGainsChanged(
+            const std::vector <Reasons> &in_reasons,
+            const std::vector <AudioGainConfigInfo> &in_gains) override;
+    ndk::ScopedAStatus registerGainCallback(
+            const std::shared_ptr <IAudioGainCallback> &in_callback) override;
+    ndk::ScopedAStatus setModuleChangeCallback(
+            const std::shared_ptr<IModuleChangeCallback>& in_callback) override;
+    ndk::ScopedAStatus clearModuleChangeCallback() override;
+
     binder_status_t dump(int fd, const char** args, uint32_t numArgs) override;
 
     void setAudioEnabled(bool isEnabled);
@@ -50,9 +78,29 @@ class AudioControl : public BnAudioControl {
     // listener, then it should also include mutexes or make the listener atomic.
     std::shared_ptr<IFocusListener> mFocusListener;
 
+    /**
+     * @brief mAudioGainCallback will be used by this HAL instance to communicate e.g. with a single
+     * instance of CarAudioService to report unexpected gain changed.
+     */
+    std::shared_ptr<IAudioGainCallback> mAudioGainCallback = nullptr;
+    std::shared_ptr<IModuleChangeCallback> mModuleChangeCallback = nullptr;
+
     binder_status_t cmdHelp(int fd) const;
     binder_status_t cmdRequestFocus(int fd, const char** args, uint32_t numArgs);
     binder_status_t cmdAbandonFocus(int fd, const char** args, uint32_t numArgs);
+    binder_status_t cmdRequestFocusWithMetaData(int fd, const char **args, uint32_t numArgs);
+    binder_status_t cmdAbandonFocusWithMetaData(int fd, const char **args, uint32_t numArgs);
+    binder_status_t cmdOnAudioDeviceGainsChanged(int fd, const char **args, uint32_t numArgs);
+    binder_status_t parseMetaData(int fd, const std::string &metadataLiteral,
+                                  audiohalcommon::PlaybackTrackMetadata &trackMetadata);
+    binder_status_t cmdOnAudioPortsChanged(int fd, const char** args, uint32_t numArgs);
+
+    binder_status_t parseAudioGains(
+            int fd, const std::string& stringGain,
+            std::vector<::aidl::android::media::audio::common::AudioGain>& gains);
+    binder_status_t parseSampleRates(int fd, const std::string& sampleRates,
+                                     std::vector<int32_t>& vecSampleRates);
+
     binder_status_t dumpsys(int fd);
 };
 
diff --git a/emulator/audio/halservice/audiocontrol-caremu.xml b/emulator/audio/halservice/audiocontrol-caremu.xml
index 7bc44da..95cd7f0 100644
--- a/emulator/audio/halservice/audiocontrol-caremu.xml
+++ b/emulator/audio/halservice/audiocontrol-caremu.xml
@@ -1,6 +1,7 @@
-<manifest version="1.0" type="device">
+<manifest version="2.0" type="device">
     <hal format="aidl">
         <name>android.hardware.automotive.audiocontrol</name>
+        <version>3</version>
         <fqname>IAudioControl/default</fqname>
     </hal>
-</manifest>
\ No newline at end of file
+</manifest>
diff --git a/emulator/car_emulator_interfaces/aidl/Android.bp b/emulator/car_emulator_interfaces/aidl/Android.bp
index a3345b6..5676426 100644
--- a/emulator/car_emulator_interfaces/aidl/Android.bp
+++ b/emulator/car_emulator_interfaces/aidl/Android.bp
@@ -13,10 +13,6 @@ aidl_interface {
     name: "device.generic.car.emulator-aidl",
     vendor_available: true,
     srcs: ["device/generic/car/emulator/*.aidl"],
-    imports: [
-        "android.hardware.automotive.vehicle-V3",
-        "android.hardware.automotive.vehicle.property-V3",
-    ],
     stability: "vintf",
     backend: {
         cpp: {
@@ -29,14 +25,21 @@ aidl_interface {
             enabled: true,
         },
     },
+    defaults: ["android.hardware.automotive.vehicle-latest-defaults"],
     versions_with_info: [
         {
             version: "1",
             imports: [
                 "android.hardware.automotive.vehicle-V3",
-                "android.hardware.automotive.vehicle.property-V3",
+                "android.hardware.automotive.vehicle.property-V4",
             ],
         },
     ],
+}
 
+cc_defaults {
+    name: "device.generic.car.emulator-aidl-latest-ndk-defaults",
+    shared_libs: [
+        "device.generic.car.emulator-aidl-V2-ndk",
+    ],
 }
diff --git a/emulator/car_emulator_vendor.mk b/emulator/car_emulator_vendor.mk
index 02bd042..d890d22 100644
--- a/emulator/car_emulator_vendor.mk
+++ b/emulator/car_emulator_vendor.mk
@@ -24,8 +24,6 @@ DEVICE_PACKAGE_OVERLAYS := device/generic/goldfish/overlay
 
 PRODUCT_CHARACTERISTICS := emulator
 
-PRODUCT_FULL_TREBLE_OVERRIDE := true
-
 # Enable Google-specific location features,
 # like NetworkLocationProvider and LocationCollector
 PRODUCT_VENDOR_PROPERTIES += \
@@ -160,4 +158,4 @@ $(call inherit-product, device/generic/goldfish/product/generic.mk)
 # Enable socket for qemu VHAL
 BOARD_SEPOLICY_DIRS += device/generic/car/emulator/sepolicy
 
-$(call inherit-product-if-exists, device/generic/car/emulator/skins/overlays/car_emu_skin_overlays.mk)
\ No newline at end of file
+$(call inherit-product-if-exists, device/generic/car/emulator/skins/overlays/car_emu_skin_overlays.mk)
diff --git a/emulator/cluster/rro_overlays/CarServiceOverlay/res/values/config.xml b/emulator/cluster/rro_overlays/CarServiceOverlay/res/values/config.xml
index a02d6f5..966d19e 100644
--- a/emulator/cluster/rro_overlays/CarServiceOverlay/res/values/config.xml
+++ b/emulator/cluster/rro_overlays/CarServiceOverlay/res/values/config.xml
@@ -80,4 +80,5 @@
     <bool name="audioUseCarVolumeGroupMuting">true</bool>
     <bool name="audioUseMinMaxActivationVolume">true</bool>
     <bool name="audioUseFadeManagerConfiguration">true</bool>
+    <bool name="audioUseCarVolumeGroupEvent">true</bool>
 </resources>
diff --git a/emulator/cluster/rro_overlays/CarServiceOverlay/res/xml/overlays.xml b/emulator/cluster/rro_overlays/CarServiceOverlay/res/xml/overlays.xml
index 7e71ba2..b0de3b0 100644
--- a/emulator/cluster/rro_overlays/CarServiceOverlay/res/xml/overlays.xml
+++ b/emulator/cluster/rro_overlays/CarServiceOverlay/res/xml/overlays.xml
@@ -21,4 +21,5 @@
     <item target="bool/audioUseCarVolumeGroupMuting" value="@bool/audioUseCarVolumeGroupMuting" />
     <item target="bool/audioUseMinMaxActivationVolume" value="@bool/audioUseMinMaxActivationVolume" />
     <item target="bool/audioUseFadeManagerConfiguration" value="@bool/audioUseFadeManagerConfiguration" />
+    <item target="bool/audioUseCarVolumeGroupEvent" value="@bool/audioUseCarVolumeGroupEvent" />
 </overlay>
diff --git a/emulator/cluster/rro_overlays/CarServiceOverlay_OsDouble/res/values/config.xml b/emulator/cluster/rro_overlays/CarServiceOverlay_OsDouble/res/values/config.xml
index 30c7235..23f789d 100644
--- a/emulator/cluster/rro_overlays/CarServiceOverlay_OsDouble/res/values/config.xml
+++ b/emulator/cluster/rro_overlays/CarServiceOverlay_OsDouble/res/values/config.xml
@@ -76,4 +76,5 @@
     <bool name="audioUseCarVolumeGroupMuting">true</bool>
     <bool name="audioUseMinMaxActivationVolume">true</bool>
     <bool name="audioUseFadeManagerConfiguration">true</bool>
+    <bool name="audioUseCarVolumeGroupEvent">true</bool>
 </resources>
diff --git a/emulator/cluster/rro_overlays/CarServiceOverlay_OsDouble/res/xml/overlays.xml b/emulator/cluster/rro_overlays/CarServiceOverlay_OsDouble/res/xml/overlays.xml
index 7e71ba2..b0de3b0 100644
--- a/emulator/cluster/rro_overlays/CarServiceOverlay_OsDouble/res/xml/overlays.xml
+++ b/emulator/cluster/rro_overlays/CarServiceOverlay_OsDouble/res/xml/overlays.xml
@@ -21,4 +21,5 @@
     <item target="bool/audioUseCarVolumeGroupMuting" value="@bool/audioUseCarVolumeGroupMuting" />
     <item target="bool/audioUseMinMaxActivationVolume" value="@bool/audioUseMinMaxActivationVolume" />
     <item target="bool/audioUseFadeManagerConfiguration" value="@bool/audioUseFadeManagerConfiguration" />
+    <item target="bool/audioUseCarVolumeGroupEvent" value="@bool/audioUseCarVolumeGroupEvent" />
 </overlay>
diff --git a/emulator/evs/evs.mk b/emulator/evs/evs.mk
index bc013ac..ff60e52 100644
--- a/emulator/evs/evs.mk
+++ b/emulator/evs/evs.mk
@@ -20,13 +20,6 @@ CUSTOMIZE_EVS_SERVICE_PARAMETER := true
 PRODUCT_PACKAGES += \
     android.hardware.automotive.evs-aidl-default-service
 
-# TODO(b/277389752): Below line should be removed when AAOS baseline is fully supported.
-PRODUCT_PACKAGES += cardisplayproxyd
-
-# EVS HAL implementation for the emulators requires AIDL version of the automotive display
-# service implementation.
-USE_AIDL_DISPLAY_SERVICE := true
-
 PRODUCT_COPY_FILES += \
     device/generic/car/emulator/evs/init.evs.rc:$(TARGET_COPY_OUT_VENDOR)/etc/init/init.evs.rc
 endif
diff --git a/emulator/multi-display-dynamic/CarServiceMultiDisplayOverlayEmulator/res/values/config.xml b/emulator/multi-display-dynamic/CarServiceMultiDisplayOverlayEmulator/res/values/config.xml
index edf67d0..5a89957 100644
--- a/emulator/multi-display-dynamic/CarServiceMultiDisplayOverlayEmulator/res/values/config.xml
+++ b/emulator/multi-display-dynamic/CarServiceMultiDisplayOverlayEmulator/res/values/config.xml
@@ -61,4 +61,5 @@
     <bool name="audioUseCarVolumeGroupMuting">true</bool>
     <bool name="audioUseMinMaxActivationVolume">true</bool>
     <bool name="audioUseFadeManagerConfiguration">true</bool>
+    <bool name="audioUseCarVolumeGroupEvent">true</bool>
 </resources>
diff --git a/emulator/multi-display-dynamic/CarServiceMultiDisplayOverlayEmulator/res/xml/overlays.xml b/emulator/multi-display-dynamic/CarServiceMultiDisplayOverlayEmulator/res/xml/overlays.xml
index cce286a..f161afb 100644
--- a/emulator/multi-display-dynamic/CarServiceMultiDisplayOverlayEmulator/res/xml/overlays.xml
+++ b/emulator/multi-display-dynamic/CarServiceMultiDisplayOverlayEmulator/res/xml/overlays.xml
@@ -23,5 +23,6 @@
     <item target="bool/audioUseCarVolumeGroupMuting" value="@bool/audioUseCarVolumeGroupMuting" />
     <item target="bool/audioUseFadeManagerConfiguration" value="@bool/audioUseFadeManagerConfiguration" />
     <item target="bool/audioUseMinMaxActivationVolume" value="@bool/audioUseMinMaxActivationVolume" />
+    <item target="bool/audioUseCarVolumeGroupEvent" value="@bool/audioUseCarVolumeGroupEvent" />
     <item target="xml/car_ux_restrictions_map" value="@xml/car_ux_restrictions_map" />
 </overlay>
diff --git a/emulator/multi-display-dynamic/multi-display-dynamic.mk b/emulator/multi-display-dynamic/multi-display-dynamic.mk
index da36089..29e1bfc 100644
--- a/emulator/multi-display-dynamic/multi-display-dynamic.mk
+++ b/emulator/multi-display-dynamic/multi-display-dynamic.mk
@@ -31,7 +31,6 @@ PRODUCT_COPY_FILES += \
 # support packages for multi-display
 $(call inherit-product, device/generic/goldfish/product/multidisplay.mk)
 PRODUCT_PACKAGES += \
-    MultiDisplaySecondaryHomeTestLauncher \
     MultiDisplayTest \
     SecondaryHomeApp \
     MultiDisplayProvider \
@@ -39,6 +38,5 @@ PRODUCT_PACKAGES += \
 
 PRODUCT_PACKAGES += ClusterHomeSample ClusterOsDouble ClusterHomeSampleOverlay ClusterOsDoubleEmulatorVirtualDisplayOverlay
 
-# Selects the MultiDisplaySecondaryHomeTestLauncher as secondaryHome
 PRODUCT_PACKAGE_OVERLAYS += \
     device/generic/car/emulator/multi-display-dynamic/overlay
diff --git a/emulator/multi-display-dynamic/overlay/frameworks/base/core/res/res/values/config.xml b/emulator/multi-display-dynamic/overlay/frameworks/base/core/res/res/values/config.xml
index cf176b9..e327be1 100644
--- a/emulator/multi-display-dynamic/overlay/frameworks/base/core/res/res/values/config.xml
+++ b/emulator/multi-display-dynamic/overlay/frameworks/base/core/res/res/values/config.xml
@@ -26,16 +26,6 @@
     <!-- Maximum number of users we allow to be running at a time -->
     <integer name="config_multiuserMaxRunningUsers">5</integer>
 
-    <!-- True if the device supports system decorations on secondary displays. -->
-    <bool name="config_supportsSystemDecorsOnSecondaryDisplays">true</bool>
-
-    <!-- This is the default launcher package with an activity to use on secondary displays that
-         support system decorations.
-         This launcher package must have an activity that supports multiple instances and has
-         corresponding launch mode set in AndroidManifest.
-         {@see android.view.Display#FLAG_SHOULD_SHOW_SYSTEM_DECORATIONS} -->
-    <string name="config_secondaryHomePackage" translatable="false">com.android.car.multidisplay</string>
-
     <!-- Whether the system enables per-display focus. If the system has the input method for each
          display, this value should be true. -->
     <bool name="config_perDisplayFocusEnabled">true</bool>
@@ -60,4 +50,8 @@
         support PROFILE user. -->
     <integer name="config_userTypePackageWhitelistMode">2</integer>
 
+    <!-- Whether the device allows users to start in background visible on displays.
+         Should be false for most devices, except automotive vehicle with passenger displays. -->
+    <bool name="config_multiuserVisibleBackgroundUsers">true</bool>
+
 </resources>
diff --git a/emulator/multi-display/androidRRO/Android.bp b/emulator/multi-display/androidRRO/Android.bp
new file mode 100644
index 0000000..2eb7f59
--- /dev/null
+++ b/emulator/multi-display/androidRRO/Android.bp
@@ -0,0 +1,24 @@
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
+
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+runtime_resource_overlay {
+    name: "CarFrameworkResConfigMultiDisplayRRO",
+    resource_dirs: ["res"],
+    certificate: "platform",
+    manifest: "AndroidManifest.xml",
+}
diff --git a/emulator/multi-display/androidRRO/AndroidManifest.xml b/emulator/multi-display/androidRRO/AndroidManifest.xml
new file mode 100644
index 0000000..f5714fe
--- /dev/null
+++ b/emulator/multi-display/androidRRO/AndroidManifest.xml
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
+<manifest xmlns:android="http://schemas.android.com/apk/res/android"
+          package="android.car.config.md.rro">
+    <application android:hasCode="false" />
+    <overlay
+        android:targetPackage="android"
+        android:isStatic="true"
+        android:priority="1000"/>
+</manifest>
diff --git a/emulator/multi-display/overlay/frameworks/base/core/res/res/values/config.xml b/emulator/multi-display/androidRRO/res/values/config.xml
similarity index 81%
rename from emulator/multi-display/overlay/frameworks/base/core/res/res/values/config.xml
rename to emulator/multi-display/androidRRO/res/values/config.xml
index 07ee8f8..2e1c5cd 100644
--- a/emulator/multi-display/overlay/frameworks/base/core/res/res/values/config.xml
+++ b/emulator/multi-display/androidRRO/res/values/config.xml
@@ -28,14 +28,6 @@
     <!-- Maximum number of users we allow to be running at a time -->
     <integer name="config_multiuserMaxRunningUsers">5</integer>
 
-    <!-- True if the device supports system decorations on secondary displays. -->
-    <bool name="config_supportsSystemDecorsOnSecondaryDisplays">true</bool>
-    <!-- This is the default launcher package with an activity to use on secondary displays that
-         support system decorations.
-         This launcher package must have an activity that supports multiple instances and has
-         corresponding launch mode set in AndroidManifest.
-         {@see android.view.Display#FLAG_SHOULD_SHOW_SYSTEM_DECORATIONS} -->
-    <string name="config_secondaryHomePackage" translatable="false">com.android.car.multidisplay</string>
     <!-- Whether to only install system packages on a user if they're whitelisted for that user
          type. These are flags and can be freely combined.
          0  - disable whitelist (install all system packages; no logging)
@@ -58,7 +50,6 @@
 
     <!-- Whether the device allows users to start in background visible on displays.
          Should be false for most devices, except automotive vehicle with passenger displays. -->
-    <!-- The config is enabled for the development purpose only. -->
     <bool name="config_multiuserVisibleBackgroundUsers">true</bool>
 
     <!-- Disable hidding the NavBars (CarSystemBars), as a workaround for b/259604616 -->
diff --git a/emulator/multi-display/overlay/frameworks/base/core/res/res/xml/config_user_types.xml b/emulator/multi-display/androidRRO/res/xml/config_user_types.xml
similarity index 84%
rename from emulator/multi-display/overlay/frameworks/base/core/res/res/xml/config_user_types.xml
rename to emulator/multi-display/androidRRO/res/xml/config_user_types.xml
index 07f21fe..8bd54ad 100644
--- a/emulator/multi-display/overlay/frameworks/base/core/res/res/xml/config_user_types.xml
+++ b/emulator/multi-display/androidRRO/res/xml/config_user_types.xml
@@ -15,6 +15,9 @@
 -->
 
 <user-types>
+    <full-type name="android.os.usertype.full.SECONDARY" >
+        <default-restrictions />
+    </full-type>
     <full-type name="android.os.usertype.full.GUEST"
         max-allowed="3" >
         <default-restrictions no_factory_reset="true" no_remove_user="true"
@@ -25,4 +28,7 @@
     <profile-type name="android.os.usertype.profile.CLONE"
         enabled='0' >
     </profile-type>
+    <profile-type name="android.os.usertype.profile.PRIVATE"
+        enabled='0' >
+    </profile-type>
 </user-types>
diff --git a/emulator/usbpt/car_usbpt.mk b/emulator/usbpt/car_usbpt.mk
index e0e24bc..7994ba3 100644
--- a/emulator/usbpt/car_usbpt.mk
+++ b/emulator/usbpt/car_usbpt.mk
@@ -20,5 +20,13 @@ $(call inherit-product, device/generic/car/emulator/usbpt/wifi/wifi.mk)
 
 # Required for USB passthrough
 PRODUCT_COPY_FILES += \
-    frameworks/native/data/etc/android.hardware.usb.host.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.usb.host.xml \
-    device/generic/car/emulator/usbpt/modules.blocklist:$(TARGET_COPY_OUT_VENDOR_RAMDISK)/lib/modules/modules.blocklist \
+    device/generic/car/emulator/usbpt/modules.blocklist:$(TARGET_COPY_OUT_VENDOR_RAMDISK)/lib/modules/modules.blocklist
+
+ifeq (,$(ENABLE_USB_HOST_MODE))
+ENABLE_USB_HOST_MODE := false
+endif
+
+ifeq (true,$(ENABLE_USB_HOST_MODE))
+PRODUCT_COPY_FILES += \
+    frameworks/native/data/etc/android.hardware.usb.host.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.usb.host.xml
+endif
diff --git a/emulator/usbpt/protocan/protocanbus/Android.bp b/emulator/usbpt/protocan/protocanbus/Android.bp
index f35dfa7..7134521 100644
--- a/emulator/usbpt/protocan/protocanbus/Android.bp
+++ b/emulator/usbpt/protocan/protocanbus/Android.bp
@@ -28,7 +28,10 @@ cc_defaults {
 cc_binary {
     name: "android.device.generic.car.emulator@1.0-protocanbus-service",
     init_rc: ["android.device.generic.car.emulator@1.0-protocanbus-service.rc"],
-    defaults: ["android.device.generic.car.emulator@1.0-protocanbus-defaults"],
+    defaults: [
+        "android.device.generic.car.emulator@1.0-protocanbus-defaults",
+        "device.generic.car.emulator-aidl-latest-ndk-defaults",
+    ],
     vendor: true,
     relative_install_path: "hw",
     srcs: [
@@ -45,7 +48,6 @@ cc_binary {
     include_dirs: ["frameworks/native/include"],
     shared_libs: [
         "android.hardware.automotive.can@1.0",
-        "device.generic.car.emulator-aidl-V1-ndk",
         "libbinder_ndk",
         "libhidlbase",
         "libcutils",
diff --git a/emulator/vhal_aidl/Android.bp b/emulator/vhal_aidl/Android.bp
index 165301f..09376d7 100644
--- a/emulator/vhal_aidl/Android.bp
+++ b/emulator/vhal_aidl/Android.bp
@@ -26,6 +26,7 @@ cc_binary {
         "FakeVehicleHardwareDefaults",
         "VehicleHalDefaults",
         "android-automotive-large-parcelable-defaults",
+        "device.generic.car.emulator-aidl-latest-ndk-defaults",
     ],
     vintf_fragments: ["vhal-emulator-service.xml"],
     init_rc: ["vhal-emulator-service.rc"],
@@ -53,6 +54,5 @@ cc_binary {
         "libutils",
         "libprotobuf-cpp-lite",
         "libbinder_ndk",
-        "device.generic.car.emulator-aidl-V1-ndk",
     ],
 }
diff --git a/emulator/vhal_aidl/VehicleEmulator/Android.bp b/emulator/vhal_aidl/VehicleEmulator/Android.bp
index c393ce0..6fb78d7 100644
--- a/emulator/vhal_aidl/VehicleEmulator/Android.bp
+++ b/emulator/vhal_aidl/VehicleEmulator/Android.bp
@@ -39,12 +39,12 @@ cc_library {
         "libutils",
         "libprotobuf-cpp-lite",
         "libbinder_ndk",
-        "device.generic.car.emulator-aidl-V1-ndk",
     ],
     local_include_dirs: ["include"],
     export_include_dirs: ["include"],
     defaults: [
         "VehicleHalDefaults",
         "FakeVehicleHardwareDefaults",
+        "device.generic.car.emulator-aidl-latest-ndk-defaults",
     ],
 }
diff --git a/emulator/vhal_aidl/VehicleEmulator/test/Android.bp b/emulator/vhal_aidl/VehicleEmulator/test/Android.bp
index 025a368..d1111ef 100644
--- a/emulator/vhal_aidl/VehicleEmulator/test/Android.bp
+++ b/emulator/vhal_aidl/VehicleEmulator/test/Android.bp
@@ -40,10 +40,10 @@ cc_test {
         "libutils",
         "libprotobuf-cpp-lite",
         "libbinder_ndk",
-        "device.generic.car.emulator-aidl-V1-ndk",
     ],
     defaults: [
         "VehicleHalDefaults",
         "FakeVehicleHardwareDefaults",
+        "device.generic.car.emulator-aidl-latest-ndk-defaults",
     ],
 }
diff --git a/emulator_car64_arm64/BoardConfig.mk b/emulator_car64_arm64/BoardConfig.mk
index a048f34..e695328 100644
--- a/emulator_car64_arm64/BoardConfig.mk
+++ b/emulator_car64_arm64/BoardConfig.mk
@@ -15,10 +15,17 @@
 
 # Use emulator64_arm64 BoardConfig as base
 include device/generic/goldfish/board/emu64a/BoardConfig.mk
+
+ifeq (,$(ENABLE_CAR_USB_PASSTHROUGH))
+ENABLE_CAR_USB_PASSTHROUGH := false
+endif
+
+ifeq (true,$(ENABLE_CAR_USB_PASSTHROUGH))
 include device/generic/car/emulator/usbpt/BoardConfig.mk
+endif
 
 # Override BOARD_SUPER_PARTITION_SIZE to increase the mounted system partition.
 BOARD_SUPER_PARTITION_SIZE := 5856296960
 
-# 4G (4 * 1024 * 1024 * 1024)
-BOARD_EMULATOR_DYNAMIC_PARTITIONS_SIZE = 4294967296
+# 5G (5 * 1024 * 1024 * 1024)
+BOARD_EMULATOR_DYNAMIC_PARTITIONS_SIZE = 5368709120
diff --git a/emulator_car64_x86_64/BoardConfig.mk b/emulator_car64_x86_64/BoardConfig.mk
index c5cb8ff..625fb0e 100644
--- a/emulator_car64_x86_64/BoardConfig.mk
+++ b/emulator_car64_x86_64/BoardConfig.mk
@@ -15,10 +15,17 @@
 
 # Use emulator64_x86_64_arm64 BoardConfig as base
 include device/generic/goldfish/board/emu64x/BoardConfig.mk
+
+ifeq (,$(ENABLE_CAR_USB_PASSTHROUGH))
+ENABLE_CAR_USB_PASSTHROUGH := false
+endif
+
+ifeq (true,$(ENABLE_CAR_USB_PASSTHROUGH))
 include device/generic/car/emulator/usbpt/BoardConfig.mk
+endif
 
 # Override BOARD_SUPER_PARTITION_SIZE to increase the mounted system partition.
 BOARD_SUPER_PARTITION_SIZE := 5856296960
 
-# 4G (4 * 1024 * 1024 * 1024)
-BOARD_EMULATOR_DYNAMIC_PARTITIONS_SIZE = 4294967296
+# 5G (5 * 1024 * 1024 * 1024)
+BOARD_EMULATOR_DYNAMIC_PARTITIONS_SIZE = 5368709120
diff --git a/sdk_car_portrait_x86_64.mk b/sdk_car_cw_x86_64.mk
similarity index 94%
rename from sdk_car_portrait_x86_64.mk
rename to sdk_car_cw_x86_64.mk
index 12dd357..8303c72 100644
--- a/sdk_car_portrait_x86_64.mk
+++ b/sdk_car_cw_x86_64.mk
@@ -15,8 +15,8 @@
 
 # Car UI Portrait Emulator Target
 
-# Exclude AAE Car System UI
-DO_NOT_INCLUDE_AAE_CAR_SYSTEM_UI := true
+# Exclude GAS Car Launcher
+DO_NOT_INCLUDE_GAS_CAR_LAUNCHER := true
 
 # Exclude Car UI Reference Design
 DO_NOT_INCLUDE_CAR_UI_REFERENCE_DESIGN := true
@@ -35,7 +35,7 @@ $(call inherit-product, device/generic/car/sdk_car_x86_64.mk)
 # changes from this makefile
 PRODUCT_ENFORCE_ARTIFACT_PATH_REQUIREMENTS := false
 
-PRODUCT_NAME := sdk_car_portrait_x86_64
+PRODUCT_NAME := sdk_car_cw_x86_64
 PRODUCT_MODEL := CarUiPortrait on x86_64 emulator
 PRODUCT_CHARACTERISTICS := automotive
 PRODUCT_SDK_ADDON_NAME := sdk_car_portrait_x86_64
```

