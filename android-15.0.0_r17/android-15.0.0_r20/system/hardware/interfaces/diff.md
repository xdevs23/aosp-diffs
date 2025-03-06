```diff
diff --git a/keystore2/OWNERS b/keystore2/OWNERS
new file mode 100644
index 0000000..f09d658
--- /dev/null
+++ b/keystore2/OWNERS
@@ -0,0 +1 @@
+file:platform/system/security:/keystore2/OWNERS
diff --git a/keystore2/aidl/Android.bp b/keystore2/aidl/Android.bp
index a88f0a3..31853ee 100644
--- a/keystore2/aidl/Android.bp
+++ b/keystore2/aidl/Android.bp
@@ -20,7 +20,7 @@ aidl_interface {
     name: "android.system.keystore2",
     vendor_available: true,
     srcs: ["android/system/keystore2/*.aidl"],
-    imports: ["android.hardware.security.keymint-V3"],
+    defaults: ["android.hardware.security.keymint-latest-defaults"],
     stability: "vintf",
     backend: {
         java: {
@@ -56,16 +56,13 @@ aidl_interface {
         },
 
     ],
-    frozen: true,
+    frozen: false,
 
 }
 
-// Note: This should always be one version ahead of the last frozen version
-latest_android_system_keystore = "android.system.keystore-V4"
-
 aidl_interface_defaults {
-    name: "latest_android_system_keystore_import_interface",
+    name: "android.system.keystore2-latest-defaults",
     imports: [
-        latest_android_system_keystore,
+        "android.system.keystore2-V5",
     ],
 }
diff --git a/keystore2/aidl/aidl_api/android.system.keystore2/current/android/system/keystore2/IKeystoreService.aidl b/keystore2/aidl/aidl_api/android.system.keystore2/current/android/system/keystore2/IKeystoreService.aidl
index d2f03cf..0c292c8 100644
--- a/keystore2/aidl/aidl_api/android.system.keystore2/current/android/system/keystore2/IKeystoreService.aidl
+++ b/keystore2/aidl/aidl_api/android.system.keystore2/current/android/system/keystore2/IKeystoreService.aidl
@@ -47,4 +47,5 @@ interface IKeystoreService {
   void ungrant(in android.system.keystore2.KeyDescriptor key, in int granteeUid);
   int getNumberOfEntries(in android.system.keystore2.Domain domain, in long nspace);
   android.system.keystore2.KeyDescriptor[] listEntriesBatched(in android.system.keystore2.Domain domain, in long nspace, in @nullable String startingPastAlias);
+  byte[] getSupplementaryAttestationInfo(in android.hardware.security.keymint.Tag tag);
 }
diff --git a/keystore2/aidl/aidl_api/android.system.keystore2/current/android/system/keystore2/ResponseCode.aidl b/keystore2/aidl/aidl_api/android.system.keystore2/current/android/system/keystore2/ResponseCode.aidl
index e1ff0bb..51dddf0 100644
--- a/keystore2/aidl/aidl_api/android.system.keystore2/current/android/system/keystore2/ResponseCode.aidl
+++ b/keystore2/aidl/aidl_api/android.system.keystore2/current/android/system/keystore2/ResponseCode.aidl
@@ -55,4 +55,5 @@ enum ResponseCode {
   OUT_OF_KEYS_TRANSIENT_ERROR = 25,
   OUT_OF_KEYS_PERMANENT_ERROR = 26,
   GET_ATTESTATION_APPLICATION_ID_FAILED = 27,
+  INFO_NOT_AVAILABLE = 28,
 }
diff --git a/keystore2/aidl/android/system/keystore2/IKeystoreService.aidl b/keystore2/aidl/android/system/keystore2/IKeystoreService.aidl
index 9beac0a..666985c 100644
--- a/keystore2/aidl/android/system/keystore2/IKeystoreService.aidl
+++ b/keystore2/aidl/android/system/keystore2/IKeystoreService.aidl
@@ -17,14 +17,15 @@
 package android.system.keystore2;
 
 import android.hardware.security.keymint.SecurityLevel;
+import android.hardware.security.keymint.Tag;
 import android.system.keystore2.Domain;
 import android.system.keystore2.IKeystoreSecurityLevel;
 import android.system.keystore2.KeyDescriptor;
 import android.system.keystore2.KeyEntryResponse;
 
 /**
- * `IKeystoreService` is the primary interface to Keystore. It provides
- * access simple database bound requests. Request that require interactions
+ * `IKeystoreService` is the primary interface to Keystore. It primarily provides
+ * access to simple database bound requests. Request that require interactions
  * with a KeyMint backend are delegated to `IKeystoreSecurityLevel` which
  * may be acquired through this interface as well.
  *
@@ -246,4 +247,19 @@ interface IKeystoreService {
     KeyDescriptor[] listEntriesBatched(in Domain domain, in long nspace,
             in @nullable String startingPastAlias);
 
+    /**
+     * Returns tag-specific info required to interpret a tag's attested value.
+     * Attested values themselves are located in the attestation certificate.
+     *
+     * The semantics of the return value is specific to the input tag:
+     *
+     * o Tag::MODULE_HASH: returns the DER-encoded structure corresponding to the `Modules` schema
+     *   described in the KeyMint HAL's KeyCreationResult.aidl. The SHA-256 hash of this encoded
+     *   structure is what's included with the tag in attestations.
+     *
+     * ## Error conditions
+     * `ResponseCode::INVALID_ARGUMENT` if `tag` is not specified in the list above.
+     * `ResponseCode::INFO_NOT_AVAILABLE` if `IKeystoreService` does not have the requested info.
+     */
+    byte[] getSupplementaryAttestationInfo(in Tag tag);
 }
diff --git a/keystore2/aidl/android/system/keystore2/ResponseCode.aidl b/keystore2/aidl/android/system/keystore2/ResponseCode.aidl
index 4fe7db3..0424f5b 100644
--- a/keystore2/aidl/android/system/keystore2/ResponseCode.aidl
+++ b/keystore2/aidl/android/system/keystore2/ResponseCode.aidl
@@ -137,4 +137,8 @@ enum ResponseCode {
      */
     GET_ATTESTATION_APPLICATION_ID_FAILED = 27,
 
+    /**
+     * Indicates that some information is not available.
+     */
+    INFO_NOT_AVAILABLE = 28,
 }
diff --git a/media/Android.bp b/media/Android.bp
index 5ba8985..500dbd6 100644
--- a/media/Android.bp
+++ b/media/Android.bp
@@ -68,7 +68,6 @@ aidl_interface {
         "aidl/android/media/audio/common/AudioOffloadInfo.aidl",
         "aidl/android/media/audio/common/AudioOutputFlags.aidl",
         "aidl/android/media/audio/common/AudioPlaybackRate.aidl",
-        "aidl/android/media/audio/common/AudioPolicyForcedConfig.aidl",
         "aidl/android/media/audio/common/AudioPolicyForceUse.aidl",
         "aidl/android/media/audio/common/AudioPort.aidl",
         "aidl/android/media/audio/common/AudioPortConfig.aidl",
@@ -83,6 +82,7 @@ aidl_interface {
         "aidl/android/media/audio/common/AudioStreamType.aidl",
         "aidl/android/media/audio/common/AudioUsage.aidl",
         "aidl/android/media/audio/common/AudioUuid.aidl",
+        "aidl/android/media/audio/common/AudioVolumeGroupChangeEvent.aidl",
         "aidl/android/media/audio/common/Boolean.aidl",
         "aidl/android/media/audio/common/Byte.aidl",
         "aidl/android/media/audio/common/ExtraAudioDescriptor.aidl",
@@ -124,6 +124,9 @@ aidl_interface {
                 "com.android.btservices",
             ],
         },
+        rust: {
+            enabled: true,
+        },
     },
     versions_with_info: [
         {
@@ -211,6 +214,13 @@ cc_defaults {
     },
 }
 
+rust_defaults {
+    name: "latest_android_media_audio_common_types_rust",
+    rustlibs: [
+        latest_android_media_audio_common_types + "-rust",
+    ],
+}
+
 aidl_interface_defaults {
     name: "latest_android_media_audio_common_types_import_interface",
     imports: [
@@ -340,3 +350,110 @@ aidl_interface_defaults {
         latest_android_media_soundtrigger_types,
     ],
 }
+
+aidl_interface {
+    name: "android.media.audio.eraser.types",
+    vendor_available: true,
+    host_supported: true,
+    flags: [
+        "-Werror",
+        "-Weverything",
+    ],
+    local_include_dir: "aidl",
+    srcs: [
+        "aidl/android/media/audio/eraser/Capability.aidl",
+        "aidl/android/media/audio/eraser/Classification.aidl",
+        "aidl/android/media/audio/eraser/ClassificationConfig.aidl",
+        "aidl/android/media/audio/eraser/ClassificationMetadata.aidl",
+        "aidl/android/media/audio/eraser/ClassificationMetadataList.aidl",
+        "aidl/android/media/audio/eraser/ClassifierCapability.aidl",
+        "aidl/android/media/audio/eraser/Configuration.aidl",
+        "aidl/android/media/audio/eraser/IEraserCallback.aidl",
+        "aidl/android/media/audio/eraser/Mode.aidl",
+        "aidl/android/media/audio/eraser/RemixerCapability.aidl",
+        "aidl/android/media/audio/eraser/SeparatorCapability.aidl",
+        "aidl/android/media/audio/eraser/SoundClassification.aidl",
+    ],
+    stability: "vintf",
+    backend: {
+        cpp: {
+            enabled: true,
+        },
+        java: {
+            sdk_version: "module_current",
+        },
+    },
+    imports: [
+        latest_android_media_audio_common_types,
+    ],
+    frozen: false,
+}
+
+// Note: This should always be one version ahead of the last frozen version
+latest_android_media_audio_eraser_types = "android.media.audio.eraser.types-V1"
+
+cc_defaults {
+    name: "latest_android_media_audio_eraser_types_cpp_shared",
+    shared_libs: [
+        latest_android_media_audio_eraser_types + "-cpp",
+    ],
+}
+
+cc_defaults {
+    name: "latest_android_media_audio_eraser_types_cpp_export_shared",
+    defaults: [
+        "latest_android_media_audio_eraser_types_cpp_shared",
+    ],
+    export_shared_lib_headers: [
+        latest_android_media_audio_eraser_types + "-cpp",
+    ],
+}
+
+cc_defaults {
+    name: "latest_android_media_audio_eraser_types_cpp_static",
+    static_libs: [
+        latest_android_media_audio_eraser_types + "-cpp",
+    ],
+}
+
+cc_defaults {
+    name: "latest_android_media_audio_eraser_types_cpp_export_static",
+    defaults: [
+        "latest_android_media_audio_eraser_types_cpp_static",
+    ],
+    export_static_lib_headers: [
+        latest_android_media_audio_eraser_types + "-cpp",
+    ],
+}
+
+cc_defaults {
+    name: "latest_android_media_audio_eraser_types_ndk_shared",
+    shared_libs: [
+        latest_android_media_audio_eraser_types + "-ndk",
+    ],
+}
+
+cc_defaults {
+    name: "latest_android_media_audio_eraser_types_ndk_static",
+    static_libs: [
+        latest_android_media_audio_eraser_types + "-ndk",
+    ],
+}
+
+cc_defaults {
+    name: "latest_android_media_audio_eraser_types_cpp_target_shared",
+    target: {
+        android: {
+            shared_libs: [
+                latest_android_media_audio_eraser_types + "-cpp",
+            ],
+        },
+    },
+}
+
+aidl_interface_defaults {
+    name: "latest_android_media_audio_eraser_types_import_interface",
+    imports: [
+        latest_android_media_audio_eraser_types,
+    ],
+}
diff --git a/media/aidl/android/media/audio/common/AudioDeviceType.aidl b/media/aidl/android/media/audio/common/AudioDeviceType.aidl
index 5a75da7..79f00fa 100644
--- a/media/aidl/android/media/audio/common/AudioDeviceType.aidl
+++ b/media/aidl/android/media/audio/common/AudioDeviceType.aidl
@@ -192,4 +192,12 @@ enum AudioDeviceType {
      * See the note on `IN_BUS` for details.
      */
     OUT_BUS = OUT_DEVICE,
+    /**
+     * Output to a wireless speaker group supporting multichannel contents. The
+     * speakers in the group are connected together using local network based
+     * protocols. The speaker group requires additional input of the physical
+     * positions of each individual speaker to provide a better experience on
+     * multichannel contents.
+     */
+    OUT_MULTICHANNEL_GROUP = 147,
 }
diff --git a/media/aidl/android/media/audio/common/AudioHalCapConfiguration.aidl b/media/aidl/android/media/audio/common/AudioHalCapConfiguration.aidl
index 6432d84..18d9df4 100644
--- a/media/aidl/android/media/audio/common/AudioHalCapConfiguration.aidl
+++ b/media/aidl/android/media/audio/common/AudioHalCapConfiguration.aidl
@@ -37,7 +37,7 @@ import android.media.audio.common.AudioHalCapRule;
  *                            └──────────────────────────┘ ┌───►                               │  │
  *                                                         │   │ name                          │  │
  *                            ┌──────────────────────────┐ │  ┌┼─rule                          │  │
- *                            │    AudioHalCapComain     │ │  ││ parameterSettings[]───────────┼──┘
+ *                            │    AudioHalCapDomain     │ │  ││ parameterSettings[]───────────┼──┘
  *                            │                          │ │  │└───────────────────────────────┘
  *                         ┌──►name                      │ │  │
  *                         │  │configurations[]──────────┼─┘  │┌───────────────────────────────┐
diff --git a/media/aidl/android/media/audio/common/AudioHalCapCriterionV2.aidl b/media/aidl/android/media/audio/common/AudioHalCapCriterionV2.aidl
index b131358..2416bca 100644
--- a/media/aidl/android/media/audio/common/AudioHalCapCriterionV2.aidl
+++ b/media/aidl/android/media/audio/common/AudioHalCapCriterionV2.aidl
@@ -20,7 +20,6 @@ import android.media.audio.common.AudioDeviceAddress;
 import android.media.audio.common.AudioDeviceDescription;
 import android.media.audio.common.AudioMode;
 import android.media.audio.common.AudioPolicyForceUse;
-import android.media.audio.common.AudioPolicyForcedConfig;
 
 /**
  * AudioHalCapCriterion is a wrapper for a CriterionType and its default value.
@@ -36,6 +35,7 @@ union AudioHalCapCriterionV2 {
      * bitfield, it can have several values). Rules expected on inclusive or exclusive will be
      * different.
      */
+    @Backing(type="byte")
     @VintfStability
     enum LogicalDisjunction {
         EXCLUSIVE = 0,
@@ -47,12 +47,13 @@ union AudioHalCapCriterionV2 {
      */
     @VintfStability
     parcelable ForceConfigForUse {
-        /**  Force usage addressed by this criterion. */
-        AudioPolicyForceUse forceUse = AudioPolicyForceUse.MEDIA;
         /** List of supported value by this criterion. */
-        AudioPolicyForcedConfig[] values;
-        /** Default configuration applied if none is provided. */
-        AudioPolicyForcedConfig defaultValue = AudioPolicyForcedConfig.NONE;
+        AudioPolicyForceUse[] values;
+        /**
+         * Default configuration applied if none is provided. This is the default-initialized
+         * value of 'AudioPolicyForceUse' which is 'forMedia = NONE'.
+         */
+        AudioPolicyForceUse defaultValue;
         /** Logic followed by this criterion, only one value at given time. */
         LogicalDisjunction logic = LogicalDisjunction.EXCLUSIVE;
     }
@@ -69,6 +70,10 @@ union AudioHalCapCriterionV2 {
         /** Logic followed by this criterion, only one value at given time. */
         LogicalDisjunction logic = LogicalDisjunction.EXCLUSIVE;
     }
+    /**
+     * Available device type criterion. It is used to force routing when an input or
+     * output device of a certain type is available.
+     */
     @VintfStability
     parcelable AvailableDevices {
         /** List if supported values (aka audio devices) by this criterion. */
@@ -76,6 +81,10 @@ union AudioHalCapCriterionV2 {
         /** Logic followed by this criterion, multiple devices can be selected/available. */
         LogicalDisjunction logic = LogicalDisjunction.INCLUSIVE;
     }
+    /**
+     * Available device with a certain address criterion. It is used to force routing
+     * when an input or output device at the certain address is available.
+     */
     @VintfStability
     parcelable AvailableDevicesAddresses {
         /** List if supported values (aka audio device addresses) by this criterion. */
@@ -83,22 +92,11 @@ union AudioHalCapCriterionV2 {
         /** Logic followed by this criterion, multiple device addresses can be available. */
         LogicalDisjunction logic = LogicalDisjunction.INCLUSIVE;
     }
+
     AvailableDevices availableInputDevices;
     AvailableDevices availableOutputDevices;
     AvailableDevicesAddresses availableInputDevicesAddresses;
     AvailableDevicesAddresses availableOutputDevicesAddresses;
     TelephonyMode telephonyMode;
     ForceConfigForUse forceConfigForUse;
-
-    /**
-     * Supported criterion types for Configurable Audio Policy Engine.
-     */
-    @VintfStability
-    union Type {
-        AudioDeviceDescription availableDevicesType;
-        AudioDeviceAddress availableDevicesAddressesType;
-        AudioMode telephonyModeType;
-        AudioPolicyForcedConfig forcedConfigType;
-    }
-    Type type;
 }
diff --git a/media/aidl/android/media/audio/common/AudioHalCapDomain.aidl b/media/aidl/android/media/audio/common/AudioHalCapDomain.aidl
index 6b9196c..4e79304 100644
--- a/media/aidl/android/media/audio/common/AudioHalCapDomain.aidl
+++ b/media/aidl/android/media/audio/common/AudioHalCapDomain.aidl
@@ -28,8 +28,7 @@ import android.media.audio.common.AudioHalCapConfiguration;
 @VintfStability
 parcelable AudioHalCapDomain {
     /**
-     * Name of the configurable domain. It must be unique for the given instance of parameter
-     * framework.
+     * Name of the configurable domain. It must be unique within the CAP configuration.
      */
     @utf8InCpp String name;
     /**
diff --git a/media/aidl/android/media/audio/common/AudioHalCapParameter.aidl b/media/aidl/android/media/audio/common/AudioHalCapParameter.aidl
index 665625e..f26afcd 100644
--- a/media/aidl/android/media/audio/common/AudioHalCapParameter.aidl
+++ b/media/aidl/android/media/audio/common/AudioHalCapParameter.aidl
@@ -23,44 +23,64 @@ import android.media.audio.common.AudioSource;
 import android.media.audio.common.AudioStreamType;
 
 /**
- * Defines the audio Cap Engine Parameters expected to be controlled by the configurable engine.
+ * Defines the audio CAP Engine Parameters expected to be controlled by the configurable engine.
  * These parameters deal with:
- *    Volume Profile: for volume curve selection (e.g. dtmf follows call curves during call).
  *    Output/Input device selection for a given strategy based on:
- *        -the type (each device will be a bit in a bitfield, allowing to select multiple devices).
- *        -the address
+ *        -the type (each device will be a bit in a bitfield, allowing to select multiple devices);
+ *        -the address.
+ *    Volume Profile: for volume curve selection (e.g. dtmf follows call curves during call).
  *
  * {@hide}
  */
 @VintfStability
 union AudioHalCapParameter {
-    @VintfStability
-    parcelable StrategyDeviceAddress {
-        AudioDeviceAddress deviceAddress;
-        // AudioHalProductStrategy.id
-        int id = AudioProductStrategyType.SYS_RESERVED_NONE;
-    }
     @VintfStability
     parcelable StrategyDevice {
         AudioDeviceDescription device;
         // AudioHalProductStrategy.id
         int id = AudioProductStrategyType.SYS_RESERVED_NONE;
+        /**
+         * Specifies whether the device is selected or not selected in the configuration.
+         */
         boolean isSelected;
     }
     @VintfStability
     parcelable InputSourceDevice {
         AudioDeviceDescription device;
         AudioSource inputSource = AudioSource.DEFAULT;
+        /**
+         * Specifies whether the device is selected or not selected in the configuration.
+         */
         boolean isSelected;
     }
     @VintfStability
+    parcelable StrategyDeviceAddress {
+        AudioDeviceAddress deviceAddress;
+        // AudioHalProductStrategy.id
+        int id = AudioProductStrategyType.SYS_RESERVED_NONE;
+    }
+    @VintfStability
     parcelable StreamVolumeProfile {
         AudioStreamType stream = AudioStreamType.INVALID;
         AudioStreamType profile = AudioStreamType.INVALID;
     }
 
+    /**
+     * Parameter allowing to choose a device by its type and associate
+     * the choice with a product strategy.
+     */
     StrategyDevice selectedStrategyDevice;
-    StrategyDeviceAddress strategyDeviceAddress;
+    /**
+     * Parameter allowing to choose an input device by and source type.
+     */
     InputSourceDevice selectedInputSourceDevice;
+    /**
+     * Parameter allowing to choose a particular device by its address and
+     * associate the choice with a product strategy.
+     */
+    StrategyDeviceAddress strategyDeviceAddress;
+    /**
+     * Parameter dealing with volume curve selection.
+     */
     StreamVolumeProfile streamVolumeProfile;
 }
diff --git a/media/aidl/android/media/audio/common/AudioHalCapRule.aidl b/media/aidl/android/media/audio/common/AudioHalCapRule.aidl
index aa52796..8f98db8 100644
--- a/media/aidl/android/media/audio/common/AudioHalCapRule.aidl
+++ b/media/aidl/android/media/audio/common/AudioHalCapRule.aidl
@@ -27,9 +27,9 @@ import android.media.audio.common.AudioHalCapCriterionV2;
  *      -type of criterion:
  *              -inclusive -> match rules are "Includes" or "Excludes"
  *              -exclusive -> match rules are "Is" or "IsNot" aka equal or different
- *      -Name of the criterion must match the provided name in AudioHalCapCriterion
+ *      -Name of the criterion must match the provided name in AudioHalCapCriterionV2
  *      -Value of the criterion must match the provided list of literal values from
- *         AudioHalCapCriterionType
+ *         associated AudioHalCapCriterionV2 values
  * Example of rule:
  *      ALL
  *          ANY
@@ -105,14 +105,11 @@ parcelable AudioHalCapRule {
     parcelable CriterionRule {
         MatchingRule matchingRule = MatchingRule.INVALID;
         /*
-         * Must be one of the name defined by {@see AudioHalCapCriterionV2}.
+         * Must be one of the names defined by {@see AudioHalCapCriterionV2}.
+         * By convention, when AudioHalCapCriterionV2 is used as a rule, the rule uses
+         * the first element of the 'values' field which must be a non-empty array.
          */
-        AudioHalCapCriterionV2 criterion;
-        /*
-         * Must be one of the value defined by {@see AudioHalCapCriterionV2::Type}.
-         * Must be one of the associated {@see AudioHalCapCriterionV2} values.
-         */
-        AudioHalCapCriterionV2.Type criterionTypeValue;
+        AudioHalCapCriterionV2 criterionAndValue;
     }
     /*
      * Defines the AND or OR'ed logcal rule between provided criterion rules if any and provided
diff --git a/media/aidl/android/media/audio/common/AudioHalProductStrategy.aidl b/media/aidl/android/media/audio/common/AudioHalProductStrategy.aidl
index c3bc656..612db84 100644
--- a/media/aidl/android/media/audio/common/AudioHalProductStrategy.aidl
+++ b/media/aidl/android/media/audio/common/AudioHalProductStrategy.aidl
@@ -29,6 +29,15 @@ import android.media.audio.common.AudioProductStrategyType;
 @JavaDerive(equals=true, toString=true)
 @VintfStability
 parcelable AudioHalProductStrategy {
+    @VintfStability
+    @Backing(type="int")
+    enum ZoneId {
+        /**
+         * Value indicating that there is no explicit zone associated to the product strategy
+         * It is the case for non-automotive products or for default zone for automotive.
+         */
+        DEFAULT = 0,
+    }
     /**
      * Defines the start of the vendor-defined product strategies
      */
@@ -55,4 +64,16 @@ parcelable AudioHalProductStrategy {
      * must not be null for any.
      */
     @nullable @utf8InCpp String name;
+     /**
+      * Audio zone id can be used to independently manage audio routing and volume for different
+      * audio device configurations.
+      * In automotive for example, audio zone id can be used to route different user id to different
+      * audio zones. Thus providing independent audio routing and volume management for each user
+      * in the car.
+      * Note:
+      * 1/ Audio zone id must begin at DEFAULT and increment respectively from DEFAULT
+      * (i.e. DEFAULT + 1...).
+      * 2/ Audio zone id can be held by one or more product strategy(ies).
+      */
+    int zoneId = ZoneId.DEFAULT;
 }
diff --git a/media/aidl/android/media/audio/common/AudioPolicyForceUse.aidl b/media/aidl/android/media/audio/common/AudioPolicyForceUse.aidl
index f20948c..4a67851 100644
--- a/media/aidl/android/media/audio/common/AudioPolicyForceUse.aidl
+++ b/media/aidl/android/media/audio/common/AudioPolicyForceUse.aidl
@@ -16,20 +16,92 @@
 package android.media.audio.common;
 
 /**
- * List of usages to be used in addition to forced config in order to force the audio routing.
+ * "Force Use" specifies high-level routing policies which are used
+ * in order to override the usual routing behavior.
  *
  * {@hide}
  */
-@Backing(type="int")
 @SuppressWarnings(value={"redundant-name"})
 @VintfStability
-enum AudioPolicyForceUse {
-    COMMUNICATION = 0,
-    MEDIA = 1,
-    RECORD = 2,
-    DOCK = 3,
-    SYSTEM = 4,
-    HDMI_SYSTEM_AUDIO = 5,
-    ENCODED_SURROUND = 6,
-    VIBRATE_RINGING = 7,
+union AudioPolicyForceUse {
+    @Backing(type="byte")
+    @VintfStability
+    enum CommunicationDeviceCategory {
+        NONE = 0,
+        SPEAKER,
+        BT_SCO,
+        BT_BLE,
+        WIRED_ACCESSORY,
+    }
+    @Backing(type="byte")
+    @VintfStability
+    enum MediaDeviceCategory {
+        NONE = 0,
+        SPEAKER,
+        HEADPHONES,
+        BT_A2DP,
+        ANALOG_DOCK,
+        DIGITAL_DOCK,
+        WIRED_ACCESSORY,
+        NO_BT_A2DP,
+    }
+    @Backing(type="byte")
+    @VintfStability
+    enum DockType {
+        NONE = 0,
+        BT_CAR_DOCK,
+        BT_DESK_DOCK,
+        ANALOG_DOCK,
+        DIGITAL_DOCK,
+        WIRED_ACCESSORY,
+    }
+    @Backing(type="byte")
+    @VintfStability
+    enum EncodedSurroundConfig {
+        UNSPECIFIED = 0,
+        NEVER,
+        ALWAYS,
+        MANUAL,
+    }
+
+    /**
+     * Configures the audio device used for media playback.
+     * This is also the default value.
+     */
+    MediaDeviceCategory forMedia = MediaDeviceCategory.NONE;
+    /**
+     * Configures the audio device used for "communication" (telephony, VoIP) use cases.
+     * Note that 'BT_BLE' and 'WIRED_ACCESSORY' can not be used in this case.
+     */
+    CommunicationDeviceCategory forCommunication = CommunicationDeviceCategory.NONE;
+    /**
+     * Configures the audio device used for recording.
+     * Note that 'SPEAKER' and 'BT_BLE' can not be used in this case.
+     */
+    CommunicationDeviceCategory forRecord = CommunicationDeviceCategory.NONE;
+    /**
+     * Configures whether in muted audio mode ringing should also be sent to a BT device.
+     * Note that 'SPEAKER' and 'WIRED_ACCESSORY' can not be used in this case.
+     */
+    CommunicationDeviceCategory forVibrateRinging = CommunicationDeviceCategory.NONE;
+    /**
+     * Specifies whether the phone is currently placed into a dock. The value of
+     * specifies the kind of the dock. This field may also be used that sending
+     * of audio to the dock is overridden by another device.
+     */
+    DockType dock = DockType.NONE;
+    /**
+     * Specifies whether enforcing of certain sounds is enabled, for example,
+     * enforcing of the camera shutter sound.
+     */
+    boolean systemSounds = false;
+    /**
+     * Specifies whether sending of system audio via HDMI is enabled.
+     */
+    boolean hdmiSystemAudio = false;
+    /**
+     * Configures whether support for encoded surround formats is enabled for
+     * applications.
+     */
+    EncodedSurroundConfig encodedSurround = EncodedSurroundConfig.UNSPECIFIED;
 }
diff --git a/media/aidl/android/media/audio/common/AudioPolicyForcedConfig.aidl b/media/aidl/android/media/audio/common/AudioPolicyForcedConfig.aidl
deleted file mode 100644
index 2acf4e1..0000000
--- a/media/aidl/android/media/audio/common/AudioPolicyForcedConfig.aidl
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
-package android.media.audio.common;
-
-/**
- * List of forced configurations aka device categories to be used in addition to the force use
- * in order to force the audio routing.
- *
- * {@hide}
- */
-@Backing(type="int")
-@SuppressWarnings(value={"redundant-name"})
-@VintfStability
-enum AudioPolicyForcedConfig {
-    NONE = 0,
-    SPEAKER = 1,
-    HEADPHONES = 2,
-    BT_SCO = 3,
-    BT_A2DP = 4,
-    WIRED_ACCESSORY = 5,
-    BT_CAR_DOCK = 6,
-    BT_DESK_DOCK = 7,
-    ANALOG_DOCK = 8,
-    DIGITAL_DOCK = 9,
-    /** A2DP sink is not preferred to speaker or wired HS */
-    NO_BT_A2DP = 10,
-    /**
-     * Sink selected to render system enforced sound in certain countries for legal reason.
-     * (like camera shutter tone in Japan).
-     */
-    SYSTEM_ENFORCED = 11,
-    HDMI_SYSTEM_AUDIO_ENFORCED = 12,
-    ENCODED_SURROUND_NEVER = 13,
-    ENCODED_SURROUND_ALWAYS = 14,
-    ENCODED_SURROUND_MANUAL = 15,
-    BT_BLE = 16,
-}
diff --git a/media/aidl/android/media/audio/common/AudioPortDeviceExt.aidl b/media/aidl/android/media/audio/common/AudioPortDeviceExt.aidl
index 4de32c7..f04c9a7 100644
--- a/media/aidl/android/media/audio/common/AudioPortDeviceExt.aidl
+++ b/media/aidl/android/media/audio/common/AudioPortDeviceExt.aidl
@@ -16,6 +16,7 @@
 
 package android.media.audio.common;
 
+import android.media.audio.common.AudioChannelLayout;
 import android.media.audio.common.AudioDevice;
 import android.media.audio.common.AudioFormatDescription;
 
@@ -59,4 +60,16 @@ parcelable AudioPortDeviceExt {
      * default device port in a HAL module in each I/O direction.
      */
     const int FLAG_INDEX_DEFAULT_DEVICE = 0;
+
+    /**
+     * A channel layout that represents the physical layout of output speakers.
+     *
+     * If set, only the `layoutMask` variant of AudioChannelLayout is valid and
+     * supported for this field.
+     *
+     * The layoutMask only indicates which speaker channels are present, the
+     * physical layout of the speakers should be informed by a standard for
+     * multi-channel sound playback systems, such as ITU-R BS.2051.
+     */
+    @nullable AudioChannelLayout speakerLayout;
 }
diff --git a/media/aidl/android/media/audio/common/AudioUsage.aidl b/media/aidl/android/media/audio/common/AudioUsage.aidl
index 34a7185..c81806c 100644
--- a/media/aidl/android/media/audio/common/AudioUsage.aidl
+++ b/media/aidl/android/media/audio/common/AudioUsage.aidl
@@ -138,4 +138,9 @@ enum AudioUsage {
      * Usage value to use when the usage is an announcement.
      */
     ANNOUNCEMENT = 1003,
+    /**
+     * Usage value to use when the usage is to clean up the speaker
+     * transducers and free them of deposits of dust or water
+     */
+    SPEAKER_CLEANUP = 1004,
 }
diff --git a/media/aidl/android/media/audio/common/AudioVolumeGroupChangeEvent.aidl b/media/aidl/android/media/audio/common/AudioVolumeGroupChangeEvent.aidl
new file mode 100644
index 0000000..f79e6a5
--- /dev/null
+++ b/media/aidl/android/media/audio/common/AudioVolumeGroupChangeEvent.aidl
@@ -0,0 +1,98 @@
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
+package android.media.audio.common;
+
+/**
+ * Audio Volume Group Change Event.
+ *
+ * {@hide}
+ */
+@SuppressWarnings(value={"redundant-name"}) // for VOLUME_FLAG_*
+@JavaDerive(equals=true, toString=true)
+@VintfStability
+parcelable AudioVolumeGroupChangeEvent {
+    /**
+     * Shall show a toast containing the current volume.
+     */
+    const int VOLUME_FLAG_SHOW_UI = 1 << 0;
+    /**
+     * Whether to include ringer modes as possible options when changing volume..
+     */
+    const int VOLUME_FLAG_ALLOW_RINGER_MODES = 1 << 1;
+    /**
+     * Whether to play a sound when changing the volume.
+     */
+    const int VOLUME_FLAG_PLAY_SOUND = 1 << 2;
+    /**
+     * Removes any sounds/vibrate that may be in the queue, or are playing.
+     */
+    const int VOLUME_FLAG_REMOVE_SOUND_AND_VIBRATE = 1 << 3;
+    /**
+     * Whether to vibrate if going into the vibrate ringer mode.
+     */
+    const int VOLUME_FLAG_VIBRATE = 1 << 4;
+    /**
+     * Indicates to VolumePanel that the volume slider should be disabled as user cannot
+     * change the volume.
+     */
+    const int VOLUME_FLAG_FIXED_VOLUME = 1 << 5;
+    /**
+     * Indicates the volume set/adjust call is for Bluetooth absolute volume.
+     */
+    const int VOLUME_FLAG_BLUETOOTH_ABS_VOLUME = 1 << 6;
+    /**
+     * Adjusting the volume was prevented due to silent mode, display a hint in the UI.
+     */
+    const int VOLUME_FLAG_SHOW_SILENT_HINT = 1 << 7;
+    /**
+     * Indicates the volume call is for Hdmi Cec system audio volume.
+     */
+    const int VOLUME_FLAG_HDMI_SYSTEM_AUDIO_VOLUME = 1 << 8;
+    /**
+     * Indicates that this should only be handled if media is actively playing.
+     */
+    const int VOLUME_FLAG_ACTIVE_MEDIA_ONLY = 1 << 9;
+    /**
+     * Like FLAG_SHOW_UI, but only dialog warnings and confirmations, no sliders.
+     */
+    const int VOLUME_FLAG_SHOW_UI_WARNINGS = 1 << 10;
+    /**
+     * Adjusting the volume down from vibrated was prevented, display a hint in the UI.
+     */
+    const int VOLUME_FLAG_SHOW_VIBRATE_HINT = 1 << 11;
+    /**
+     * Adjusting the volume due to a hardware key press.
+     */
+    const int VOLUME_FLAG_FROM_KEY = 1 << 12;
+    /**
+     * Indicates that an absolute volume controller is notifying AudioService of a change in the
+     * volume or mute status of an external audio system..
+     */
+    const int VOLUME_FLAG_ABSOLUTE_VOLUME = 1 << 13;
+
+    /** Unique identifier of the volume group. */
+    int groupId;
+    /** Index in UI applied. */
+    int volumeIndex;
+    /** Muted attribute, orthogonal to volume index. */
+    boolean muted;
+    /**
+     * Bitmask indicating a suggested UI behavior or characterising the volume event.
+     * The bit masks are defined in the constants prefixed by VOLUME_FLAG_*.
+     */
+    int flags;
+}
diff --git a/media/aidl/android/media/audio/eraser/Capability.aidl b/media/aidl/android/media/audio/eraser/Capability.aidl
new file mode 100644
index 0000000..a7627e5
--- /dev/null
+++ b/media/aidl/android/media/audio/eraser/Capability.aidl
@@ -0,0 +1,80 @@
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
+package android.media.audio.eraser;
+
+import android.media.audio.common.AudioChannelLayout;
+import android.media.audio.eraser.ClassifierCapability;
+import android.media.audio.eraser.Mode;
+import android.media.audio.eraser.RemixerCapability;
+import android.media.audio.eraser.SeparatorCapability;
+
+/**
+ * Represents the capability of an audio eraser.
+ *
+ * This parcelable defines the supported input/output data formats, available work modes, and the
+ * specific capabilities of the sound classifier, separator, and remixer components within the
+ * eraser effect.
+ */
+@JavaDerive(equals=true, toString=true)
+@VintfStability
+parcelable Capability {
+    /**
+     * List of supported sample rates for the eraser.
+     *
+     * The output audio sample rate will be the same as the input.
+     */
+    int[] sampleRates;
+
+    /**
+     * List of supported channel layouts for the eraser.
+     *
+     * The output audio channel layout will be the same as the input.
+     */
+    AudioChannelLayout[] channelLayouts;
+
+    /**
+     * List of supported work modes.
+     *
+     * Defines the different operational modes (e.g., `ERASER`, `CLASSIFIER`) that the eraser can
+     * work in.
+     */
+    Mode[] modes;
+
+    /**
+     * Separator capability.
+     *
+     * Specifies the capabilities of the sound separator component within the eraser effect,
+     * including the maximum number of sound sources it can separate.
+     */
+    SeparatorCapability separator;
+
+    /**
+     * Classifier capability.
+     *
+     * Specifies the capabilities of the sound classifier component within the eraser effect,
+     * including the sound classifications it can detect.
+     */
+    ClassifierCapability classifier;
+
+    /**
+     * Remixer capability.
+     *
+     * Specifies the capabilities of the sound remixer component within the eraser effect,
+     * including the gainFactor range supported.
+     */
+    RemixerCapability remixer;
+}
diff --git a/media/aidl/android/media/audio/eraser/Classification.aidl b/media/aidl/android/media/audio/eraser/Classification.aidl
new file mode 100644
index 0000000..16aa1ce
--- /dev/null
+++ b/media/aidl/android/media/audio/eraser/Classification.aidl
@@ -0,0 +1,37 @@
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
+package android.media.audio.eraser;
+
+import android.media.audio.eraser.SoundClassification;
+
+/**
+ * Represents a sound classification category.
+ *
+ * The classification includes the top-level sound category based on the AudioSet ontology.
+ */
+@JavaDerive(equals=true, toString=true)
+@VintfStability
+parcelable Classification {
+    /**
+     * The top-level sounds classification supported.
+     *
+     * This field specifies the primary sound category that this classification represents,
+     * as defined in the AudioSet ontology. It helps identify the general type of sound,
+     * such as HUMAN, ANIMAL, MUSIC, etc.
+     */
+    SoundClassification classification = SoundClassification.HUMAN;
+}
diff --git a/media/aidl/android/media/audio/eraser/ClassificationConfig.aidl b/media/aidl/android/media/audio/eraser/ClassificationConfig.aidl
new file mode 100644
index 0000000..ab5191e
--- /dev/null
+++ b/media/aidl/android/media/audio/eraser/ClassificationConfig.aidl
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
+package android.media.audio.eraser;
+
+import android.media.audio.eraser.Classification;
+
+/**
+ * Configuration for the eraser to apply specific gain adjustments to certain sound classifications.
+ *
+ * Gain is applied to the audio signal by scaling the amplitude of the output audio based on the
+ * classification of the input sound.
+ * If a classification exists in the configuration list, the remixer applies the specified gain to
+ * the output audio when the confidence score is higher than `confidenceThreshold`. If a
+ * classification is not present in the configuration, it is considered to have a gain of 1.0
+ * (no gain adjustment).
+ * If a ClassificationConfig contains an empty classification list, the same threshold and gain
+ * specified in the ClassificationConfig will be applied to all classifications not explicitly
+ * configured.
+ *
+ * Examples:
+ *
+ * 1. {classifications = [{classification = SoundClassification.NATURE},
+ *                        {classification = SoundClassification.ENVIRONMENT}],
+ *     confidenceThreshold = 0.8,
+ *     gainFactor = 0.0}
+ *
+ *    - If the input audio is classified as NATURE or ENVIRONMENT, with a confidence score higher
+ *      than 0.8, the output audio will be muted.
+ *    - If the classification confidence score is 0.8 or lower, or if the audio is classified
+ *      differently, the output audio remains unchanged.
+ *
+ * 2.  {classifications = [{classification = SoundClassification.MUSIC}],
+ *      confidenceThreshold = 0.6,
+ *      gainFactor = 0.5}
+ *
+ *    - If the input audio is classified as MUSIC with a confidence score higher than 0.6, the
+ *      output audio should have a gain factor of 0.5 (reduced by half).
+ *    - If the classification confidence score is 0.6 or lower, or if the audio is classified
+ *      differently, the output audio remains unchanged.
+ *
+ * 3. When combined as a list, the eraser can be configured to apply different gainFactor to
+ *    a classifications when confideence score is higher than the corresponding threshold.
+ *    [{classifications = [{classification = SoundClassification.NATURE}],
+ *      confidenceThreshold = 0.8,
+ *      gainFactor = 0.0},
+ *     {classifications = [{classification = SoundClassification.MUSIC}],
+ *      confidenceThreshold = 0.8,
+ *      gainFactor = 0.6},
+ *     {classifications = [{classification = SoundClassification.MUSIC}],
+ *      confidenceThreshold = 0.5,
+ *      gainFactor = 0.5}]
+ *
+ *    - If the input audio is classified as NATURE, and the confidence score is higher than 0.8,
+ *      the output audio classification will be muted (gainFactor = 0.0).
+ *
+ *    - If the input audio is classified as MUSIC with a confidence score higher than 0.8, the
+ *      output audio classification will have a gain factor of 0.6. If the input audio is
+ *      classified as MUSIC with a confidence score higher than 0.5, the output audio
+ *      classification will have a gain factor of 0.5.
+ *
+ *    - For all other sound classifications, the audio signal remains unchanged (gainFactor = 1.0).
+ *
+ * 4. [{classifications = [{classification = SoundClassification.HUMAN}],
+ *      confidenceThreshold = 0.8,
+ *      gainFactor = 1.0},
+ *     {classifications = [],
+ *      confidenceThreshold = 0.0,
+ *      gainFactor = 0.5}]
+ *
+ *    - If the input audio is classified as HUMAN, and the confidence score is higher than 0.8, the
+ *      output audio classification will remains unchanged.
+ *
+ *    - For all other sound classifications, the audio signal will have a gain factor of 0.5.
+ *
+ */
+@JavaDerive(equals=true, toString=true)
+@VintfStability
+parcelable ClassificationConfig {
+    /**
+     * List of sound classifications to which this configuration applies.
+     *
+     * Each entry specifies a sound classification (e.g., MUSIC, NATURE) targeted by this
+     * configuration.
+     */
+    Classification[] classifications;
+
+    /**
+     * Confidence threshold in the range of [0.0, 1.0], only apply the gainFactor when the
+     * classifier's confidence score for the specified classifications exceeds this threshold.
+     *
+     * Default Value is 0.0 which means apply gain regardless of confidence score.
+     */
+    float confidenceThreshold = 0f;
+
+    /**
+     * Gain factor to apply to the output audio when the specified classifications are detected.
+     * Gain factor is applied by multiplying the amplitude of the audio signal by the `gainFactor`.
+     *
+     * - A `gainFactor` of `1.0` means no gain adjustment (the original volume is preserved).
+     * - A `gainFactor` of `0.5` reduces the amplitude of the audio by half.
+     * - A `gainFactor` of `0.0` mutes the audio.
+     * - A `gainFactor` > `1.0` amplifies the audio signal, increasing its volume (useful for
+     *   compressor and amplification cases).
+     * - A `gainFactor` < `0.0` inverts the phase of the audio signal (useful for phase
+     *   cancellation or specific spatial audio manipulation).
+     *
+     * The `gainFactor` must be within the `gainFactorRange` defined in `RemixerCapability`, the
+     * default value is `1.0`.
+     */
+    float gainFactor = 1f;
+}
diff --git a/media/aidl/android/media/audio/eraser/ClassificationMetadata.aidl b/media/aidl/android/media/audio/eraser/ClassificationMetadata.aidl
new file mode 100644
index 0000000..cc79c37
--- /dev/null
+++ b/media/aidl/android/media/audio/eraser/ClassificationMetadata.aidl
@@ -0,0 +1,42 @@
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
+package android.media.audio.eraser;
+
+import android.media.audio.eraser.Classification;
+
+/**
+ * Metadata generated by a sound classification task.
+ *
+ * This parcelable contains the classification result for a segment of the audio stream, along with
+ * a confidence score indicating the certainty of the classification.
+ */
+@JavaDerive(equals=true, toString=true)
+@VintfStability
+parcelable ClassificationMetadata {
+    /**
+     * Confidence score for the classification, ranging from 0.0 to 1.0.
+     *
+     * This score reflects the classifier's confidence in the result, with higher values
+     * representing greater confidence in the prediction.
+     */
+    float confidenceScore;
+
+    /**
+     * The classification result, indicating the top-level sound classification.
+     */
+    Classification classification;
+}
diff --git a/media/aidl/android/media/audio/eraser/ClassificationMetadataList.aidl b/media/aidl/android/media/audio/eraser/ClassificationMetadataList.aidl
new file mode 100644
index 0000000..3a5dd16
--- /dev/null
+++ b/media/aidl/android/media/audio/eraser/ClassificationMetadataList.aidl
@@ -0,0 +1,82 @@
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
+package android.media.audio.eraser;
+
+import android.media.audio.eraser.ClassificationMetadata;
+
+/**
+ * List of active `ClassificationMetadata` aligned to a specific timestamp.
+ *
+ * A `ClassificationMetadata` is considered active when the `confidenceScore` exceeds the
+ * `ClassificationConfig.confidenceThreshold`.
+ *
+ * The classifier component in the eraser must maintain the active metadata list when an
+ * `IEraserCallback` is configured and send the list via `onClassifierUpdate` whenever a change
+ * occurs.
+ */
+
+@JavaDerive(equals=true, toString=true)
+@VintfStability
+parcelable ClassificationMetadataList {
+    /**
+     * Timestamp in milliseconds within the audio stream that this classification result is aligned
+     * with, the timestamp is calculated with audio frames the eraser effect received, starting
+     * from the first frame processed by the eraser effect.
+     *
+     * The `timeMs` indicates the starting point in the audio stream that the classification results
+     * in this metadata list apply to.
+     * Each classifier process window produces a list of `ClassificationMetadata`. The `timeMs` in
+     * the metadata list always aligns with the start of the window (the starting point of the audio
+     * segment processed by the classifier).
+     * In rare cases where the classifier produces an identical list of classifications for
+     * consecutive windows (including confidence scores), the `onClassifierUpdate` callback will
+     * only be triggered once for the first process window, with a `timeMs` indicating the start of
+     * that window. No further `onClassifierUpdate` callbacks will be made for the subsequent
+     * windows, as there is no meaningful change in the classification results. This avoids
+     * redundant updates when the classification remains the same across windows.
+     *
+     * Client Usage:
+     * The `timeMs` allows clients to map the classification results back to a specific portion of
+     * the audio stream. Clients can use this information to synchronize classification results
+     * with the audio data or other events. Each metadata list update corresponds to one window of
+     * classified audio, and the `timeMs` will always point to the start of that window.
+     *
+     * For an example, below is an audio stream timeline with a 1 second classifier window.
+     * Audio stream:
+     * |==========>=========|============>=========|===========>==========|===========>=========|
+     * 0                   1000                  2000                   3000                   4000
+     *                       |                     |                      |                     |
+     *                       V                     V                      V                     V
+     *                [{HUMAN, 0.8}]        [{HUMAN, 0.8},        [{HUMAN, 0.8},      [{HUMAN, 0.8}]
+     *                       |               {NATURE, 0.4}]        {NATURE, 0.4}]               |
+     *                       |                     |                                            |
+     *                       V                     V                                            V
+     *             onClassifierUpdate      onClassifierUpdate                     onClassifierUpdate
+     *                  timeMs: 0             timeMs: 1000                           timeMs: 3000
+     *                [{HUMAN, 0.8}]        [{HUMAN, 0.8},                          [{HUMAN, 0.8}]
+     *                                       {NATURE, 0.4}]
+     */
+    int timeMs;
+
+    /**
+     * List of classification metadata, including the sound classification, confidence score, and
+     * a duration since when the sound class was considered active.
+     *
+     * Metadatas in the list should be ranked in descending order based on the confidence score.
+     */
+    ClassificationMetadata[] metadatas;
+}
diff --git a/media/aidl/android/media/audio/eraser/ClassifierCapability.aidl b/media/aidl/android/media/audio/eraser/ClassifierCapability.aidl
new file mode 100644
index 0000000..5348086
--- /dev/null
+++ b/media/aidl/android/media/audio/eraser/ClassifierCapability.aidl
@@ -0,0 +1,48 @@
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
+package android.media.audio.eraser;
+
+import android.media.audio.eraser.Classification;
+
+/**
+ * Represents the capabilities of a sound classifier component.
+ *
+ * This parcelable contains a list of supported sound classifications that the classifier can
+ * recognize and process.
+ */
+@JavaDerive(equals=true, toString=true)
+@VintfStability
+parcelable ClassifierCapability {
+    /**
+     * The window size of the classifier model in milliseconds.
+     *
+     * Indicates the duration over which the classifier processes audio data to output a
+     * classification result.
+     *
+     * Clients can expect to receive updates at most once per window.
+     */
+    int windowSizeMs;
+
+    /**
+     * List of supported sound classifications.
+     *
+     * Each entry specifies a sound classification category that the classifier can recognize, such
+     * as `HUMAN`, `MUSIC`, `ANIMAL`, etc. This defines the types of sounds the classifier is
+     * capable of identifying in the input audio.
+     */
+    Classification[] supportedClassifications;
+}
diff --git a/media/aidl/android/media/audio/eraser/Configuration.aidl b/media/aidl/android/media/audio/eraser/Configuration.aidl
new file mode 100644
index 0000000..b693244
--- /dev/null
+++ b/media/aidl/android/media/audio/eraser/Configuration.aidl
@@ -0,0 +1,54 @@
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
+package android.media.audio.eraser;
+
+import android.media.audio.eraser.ClassificationConfig;
+import android.media.audio.eraser.IEraserCallback;
+import android.media.audio.eraser.Mode;
+
+/**
+ * Eraser configurations. Configuration for eraser operation mode, sound classification behaviors,
+ * and an optional callback interface.
+ */
+@JavaDerive(equals=true, toString=true)
+@VintfStability
+parcelable Configuration {
+    /**
+     * Work mode for the eraser, specifies the current operating mode of the eraser effect.
+     */
+    Mode mode = Mode.ERASER;
+
+    /**
+     * List of eraser configurations.
+     * Each configuration defines the behavior for specific sound classifications, allowing
+     * different gain factors and confidence thresholds to be applied based on classification
+     * results.
+     */
+    ClassificationConfig[] classificationConfigs;
+
+    /**
+     * Maximum number of classification metadata generated from the sound classification.
+     *
+     * Default value set to 5.
+     */
+    int maxClassificationMetadata = 5;
+
+    /**
+     * Optional callback inerface to get the eraser effect results.
+     */
+    @nullable IEraserCallback callback;
+}
diff --git a/media/aidl/android/media/audio/eraser/IEraserCallback.aidl b/media/aidl/android/media/audio/eraser/IEraserCallback.aidl
new file mode 100644
index 0000000..4863ba5
--- /dev/null
+++ b/media/aidl/android/media/audio/eraser/IEraserCallback.aidl
@@ -0,0 +1,50 @@
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
+package android.media.audio.eraser;
+
+import android.media.audio.eraser.ClassificationMetadataList;
+
+/**
+ * Callback interface for delivering results from the eraser effect.
+ */
+@VintfStability
+interface IEraserCallback {
+    /**
+     * Provides classifier updates, including sound classifications and their confidence scores,
+     * along with the associated timestamp for a given `soundSourceId`.
+     *
+     * The callback is invoked when there is a change in the list of active classification metadata
+     * for each sound source. Changes include the addition and removal of a classification, or
+     * a change in the condidence score.
+     *
+     * The number of metadata elements in the `ClassificationMetadataList.metadatas` list will not
+     * exceed the `maxClassificationMetadata` set in `android.media.audio.eraser.Configuration`.
+     *
+     * Different classifiers may have varying window sizes, regardless of the window size, the
+     * classifier updates occur at most once per window per sound source.
+     *
+     * @param soundSourceId The identifier for the sound source being classified. In ERASER mode,
+     *                      this identifies the separated sound source.
+     *        - In CLASSIFIER mode, the `soundSourceId` is always `0` as there is only one sound
+     *          source for the eraser effect.
+     *        - In ERASER mode, the `soundSourceId` range is [0, `maxSoundSources - 1`], where
+     *          `maxSoundSources` is defined in the eraser capability through `SeparatorCapability`.
+     *
+     * @param metadata The classification metadata list for the current sound source.
+     */
+    oneway void onClassifierUpdate(in int soundSourceId, in ClassificationMetadataList metadata);
+}
diff --git a/media/aidl/android/media/audio/eraser/Mode.aidl b/media/aidl/android/media/audio/eraser/Mode.aidl
new file mode 100644
index 0000000..30745c5
--- /dev/null
+++ b/media/aidl/android/media/audio/eraser/Mode.aidl
@@ -0,0 +1,58 @@
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
+package android.media.audio.eraser;
+
+/**
+ * Defines the operational mode of the Eraser effect.
+ */
+@JavaDerive(equals=true, toString=true)
+@VintfStability
+@Backing(type="byte")
+enum Mode {
+    /**
+     * ERASER mode: The effect operates as an automatic sound eraser.
+     *
+     * In this mode, the Eraser effect processes the input audio using the Sound Separator,
+     * Sound Classifier, and Remixer components. The sound to be erased or retained is determined
+     * by the classifications and gain adjustments specified in eraser configuration.
+     *
+     * - The Sound Separator separates the input audio into multiple sound sources.
+     * - The Sound Classifier analyzes each separated sound to determine its sound category.
+     * - The Remixer applies gain adjustments based on the classifications and configurations, and
+     *   re-mix the processed sounds back into a single output audio stream.
+     *
+     * Requirements: To operate in this mode, the effect must support the classifier, separator,
+     * and remixer capabilities.
+     *
+     * Use Cases: Selectively suppressing or enhancing specific sounds in the audio stream,
+     * such as removing background noise or isolating desired sound sources.
+     */
+    ERASER,
+
+    /**
+     * CLASSIFIER mode: The effect operates as a sound classifier.
+     *
+     * In this mode, the Sound Classifier analyzes the input audio in real-time and emits
+     * classification results based on the sound categories detected. The input audio is directly
+     * passed through to the output without any modification.
+     *
+     * Use Cases: Useful for applications that need to detect specific sound events, monitor audio
+     * content, or provide real-time visual feedback on audio classifications, without altering the
+     * original audio stream.
+     */
+    CLASSIFIER,
+}
diff --git a/media/aidl/android/media/audio/eraser/RemixerCapability.aidl b/media/aidl/android/media/audio/eraser/RemixerCapability.aidl
new file mode 100644
index 0000000..0c89fc1
--- /dev/null
+++ b/media/aidl/android/media/audio/eraser/RemixerCapability.aidl
@@ -0,0 +1,59 @@
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
+package android.media.audio.eraser;
+
+/**
+ * Represents the capabilities of a sound remixer component.
+ *
+ * This parcelable defines the supported range of gainFactors that the remixer can apply to the
+ * audio signal.
+ */
+@JavaDerive(equals=true, toString=true)
+@VintfStability
+parcelable RemixerCapability {
+    /**
+     * Indicates whether sound remixer is supported.
+     *
+     * If `supported` is true, the sound remixer can adjust the gain of the audio signal based on
+     * the provided classifications and gainFactors, and remix the separated sounds into one.
+     */
+    boolean supported;
+
+    /**
+     * Minimum gainFactor supported by the sound remixer.
+     *
+     * Specifies the lowest gainFactor that the remixer can apply. A gainFactor of `0.0`
+     * typically mutes the sound. In some less common cases, a remixer can support a negative
+     * `gainFactor`, which enables some use cases like phase inversion and noise cancellation.
+     *
+     * The minimum gainFactor must be at least `0.0`. The default minimum gainFactor for a remixer
+     * is `0.0` (the sound is muted).
+     */
+    float minGainFactor = 0f;
+
+    /**
+     * Maximum gainFactor supported by the sound remixer.
+     *
+     * Specifies the highest gainFactor that the remixer can apply. A gainFactor of `1.0` means no
+     * adjustment to the sound's original volume. In the case of gainFactor greater than `1.0`, the
+     * remixer may apply amplification to the audio signal.
+     *
+     * The maximum gainFactor must be at least `1.0`, and the default maximum gainFactor for a
+     * remixer is `1.0` (no gain adjustment to the sound).
+     */
+    float maxGainFactor = 1f;
+}
diff --git a/media/aidl/android/media/audio/eraser/SeparatorCapability.aidl b/media/aidl/android/media/audio/eraser/SeparatorCapability.aidl
new file mode 100644
index 0000000..93b959c
--- /dev/null
+++ b/media/aidl/android/media/audio/eraser/SeparatorCapability.aidl
@@ -0,0 +1,55 @@
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
+package android.media.audio.eraser;
+
+/**
+ * Represents the capabilities of a sound separator component.
+ *
+ * This parcelable includes the maximum number of sound sources that can be separated
+ * simultaneously.
+ */
+@JavaDerive(equals=true, toString=true)
+@VintfStability
+parcelable SeparatorCapability {
+    /**
+     * Indicates whether sound separation is supported.
+     *
+     * Note: If sound separation is supported, the effect must also support sound remixing to
+     * handle the separated audio streams, and produce remixed audio as output.
+     */
+    boolean supported;
+
+    /**
+     * The minimum number of sound sources a sound separator must support.
+     */
+    const int MIN_SOUND_SOURCE_SUPPORTED = 2;
+
+    /**
+     * Maximum number of sound sources that can be separated.
+     *
+     * Specifies the maximum number of individual sound sources that the separator can process
+     * simultaneously.
+     *
+     * Each separated sound source have an soundSourceId, range in [0, maxSoundSources -1]. In
+     * ERASER mode, each sound source will be classified with a classifier, identified by the
+     * soundSourceId.
+     *
+     * The minimum value of `maxSoundSources` is 2 as defined by `MIN_SOUND_SOURCE_SUPPORTED`, the
+     * default value is 4.
+     */
+    int maxSoundSources = 4;
+}
diff --git a/media/aidl/android/media/audio/eraser/SoundClassification.aidl b/media/aidl/android/media/audio/eraser/SoundClassification.aidl
new file mode 100644
index 0000000..6ec9b43
--- /dev/null
+++ b/media/aidl/android/media/audio/eraser/SoundClassification.aidl
@@ -0,0 +1,75 @@
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
+package android.media.audio.eraser;
+
+/**
+ * The sound classification is based on the top-level categories of the "AudioSet ontology".
+ *
+ * The AudioSet ontology is a hierarchical collection of sound event classes.
+ * For more details, refer to the ICASSP 2017 paper: "AudioSet: An ontology and human-labeled
+ * dataset for audio events".
+ * https://research.google/pubs/audio-set-an-ontology-and-human-labeled-dataset-for-audio-events/
+ */
+@JavaDerive(equals=true, toString=true)
+@Backing(type="int")
+@VintfStability
+enum SoundClassification {
+    /**
+     * Sounds produced by the human body through the actions of the individual.
+     */
+    HUMAN,
+
+    /**
+     * All sound produced by the bodies and actions of nonhuman animals.
+     */
+    ANIMAL,
+
+    /**
+     * Sounds produced by natural sources in their normal soundscape, excluding animal and human
+     * sounds.
+     */
+    NATURE,
+
+    /**
+     * Music is an art form and cultural activity whose medium is sound and silence. The common
+     * elements of music are pitch, rhythm, dynamics, and the sonic qualities of timbre and texture.
+     */
+    MUSIC,
+
+    /**
+     * Set of sound classes referring to sounds that are immediately understood by listeners as
+     * arising from specific objects (rather than being heard more literally as "sounds").
+     */
+    THINGS,
+
+    /**
+     * Portmanteau class for sounds that do not immediately suggest specific source objects, but
+     * which are more likely to be perceived and described according to their acoustic properties.
+     */
+    AMBIGUOUS,
+
+    /**
+     * A class for sound categories that suggest information about attributes other than the
+     * foreground or target objects.
+     */
+    ENVIRONMENT,
+
+    /**
+     * Vendor customizable extension, for possible classifications not listed above.
+     */
+    VENDOR_EXTENSION,
+}
diff --git a/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioDeviceType.aidl b/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioDeviceType.aidl
index f7d1b77..f31a707 100644
--- a/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioDeviceType.aidl
+++ b/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioDeviceType.aidl
@@ -70,4 +70,5 @@ enum AudioDeviceType {
   OUT_DOCK = 145,
   OUT_BROADCAST = 146,
   OUT_BUS = OUT_DEVICE /* 133 */,
+  OUT_MULTICHANNEL_GROUP = 147,
 }
diff --git a/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioHalCapCriterionV2.aidl b/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioHalCapCriterionV2.aidl
index fd17d6f..b5ceee3 100644
--- a/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioHalCapCriterionV2.aidl
+++ b/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioHalCapCriterionV2.aidl
@@ -41,17 +41,15 @@ union AudioHalCapCriterionV2 {
   android.media.audio.common.AudioHalCapCriterionV2.AvailableDevicesAddresses availableOutputDevicesAddresses;
   android.media.audio.common.AudioHalCapCriterionV2.TelephonyMode telephonyMode;
   android.media.audio.common.AudioHalCapCriterionV2.ForceConfigForUse forceConfigForUse;
-  android.media.audio.common.AudioHalCapCriterionV2.Type type;
-  @VintfStability
+  @Backing(type="byte") @VintfStability
   enum LogicalDisjunction {
     EXCLUSIVE = 0,
     INCLUSIVE,
   }
   @VintfStability
   parcelable ForceConfigForUse {
-    android.media.audio.common.AudioPolicyForceUse forceUse = android.media.audio.common.AudioPolicyForceUse.MEDIA;
-    android.media.audio.common.AudioPolicyForcedConfig[] values;
-    android.media.audio.common.AudioPolicyForcedConfig defaultValue = android.media.audio.common.AudioPolicyForcedConfig.NONE;
+    android.media.audio.common.AudioPolicyForceUse[] values;
+    android.media.audio.common.AudioPolicyForceUse defaultValue;
     android.media.audio.common.AudioHalCapCriterionV2.LogicalDisjunction logic = android.media.audio.common.AudioHalCapCriterionV2.LogicalDisjunction.EXCLUSIVE;
   }
   @VintfStability
@@ -70,11 +68,4 @@ union AudioHalCapCriterionV2 {
     android.media.audio.common.AudioDeviceAddress[] values;
     android.media.audio.common.AudioHalCapCriterionV2.LogicalDisjunction logic = android.media.audio.common.AudioHalCapCriterionV2.LogicalDisjunction.INCLUSIVE;
   }
-  @VintfStability
-  union Type {
-    android.media.audio.common.AudioDeviceDescription availableDevicesType;
-    android.media.audio.common.AudioDeviceAddress availableDevicesAddressesType;
-    android.media.audio.common.AudioMode telephonyModeType;
-    android.media.audio.common.AudioPolicyForcedConfig forcedConfigType;
-  }
 }
diff --git a/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioHalCapParameter.aidl b/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioHalCapParameter.aidl
index 981bd09..c0b1a72 100644
--- a/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioHalCapParameter.aidl
+++ b/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioHalCapParameter.aidl
@@ -36,15 +36,10 @@ package android.media.audio.common;
 @VintfStability
 union AudioHalCapParameter {
   android.media.audio.common.AudioHalCapParameter.StrategyDevice selectedStrategyDevice;
-  android.media.audio.common.AudioHalCapParameter.StrategyDeviceAddress strategyDeviceAddress;
   android.media.audio.common.AudioHalCapParameter.InputSourceDevice selectedInputSourceDevice;
+  android.media.audio.common.AudioHalCapParameter.StrategyDeviceAddress strategyDeviceAddress;
   android.media.audio.common.AudioHalCapParameter.StreamVolumeProfile streamVolumeProfile;
   @VintfStability
-  parcelable StrategyDeviceAddress {
-    android.media.audio.common.AudioDeviceAddress deviceAddress;
-    int id = android.media.audio.common.AudioProductStrategyType.SYS_RESERVED_NONE /* -1 */;
-  }
-  @VintfStability
   parcelable StrategyDevice {
     android.media.audio.common.AudioDeviceDescription device;
     int id = android.media.audio.common.AudioProductStrategyType.SYS_RESERVED_NONE /* -1 */;
@@ -57,6 +52,11 @@ union AudioHalCapParameter {
     boolean isSelected;
   }
   @VintfStability
+  parcelable StrategyDeviceAddress {
+    android.media.audio.common.AudioDeviceAddress deviceAddress;
+    int id = android.media.audio.common.AudioProductStrategyType.SYS_RESERVED_NONE /* -1 */;
+  }
+  @VintfStability
   parcelable StreamVolumeProfile {
     android.media.audio.common.AudioStreamType stream = android.media.audio.common.AudioStreamType.INVALID;
     android.media.audio.common.AudioStreamType profile = android.media.audio.common.AudioStreamType.INVALID;
diff --git a/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioHalCapRule.aidl b/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioHalCapRule.aidl
index fb1719c..e106050 100644
--- a/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioHalCapRule.aidl
+++ b/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioHalCapRule.aidl
@@ -55,7 +55,6 @@ parcelable AudioHalCapRule {
   @VintfStability
   parcelable CriterionRule {
     android.media.audio.common.AudioHalCapRule.MatchingRule matchingRule = android.media.audio.common.AudioHalCapRule.MatchingRule.INVALID;
-    android.media.audio.common.AudioHalCapCriterionV2 criterion;
-    android.media.audio.common.AudioHalCapCriterionV2.Type criterionTypeValue;
+    android.media.audio.common.AudioHalCapCriterionV2 criterionAndValue;
   }
 }
diff --git a/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioHalProductStrategy.aidl b/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioHalProductStrategy.aidl
index 1144574..9878e37 100644
--- a/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioHalProductStrategy.aidl
+++ b/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioHalProductStrategy.aidl
@@ -38,5 +38,10 @@ parcelable AudioHalProductStrategy {
   int id = android.media.audio.common.AudioProductStrategyType.SYS_RESERVED_NONE /* -1 */;
   android.media.audio.common.AudioHalAttributesGroup[] attributesGroups;
   @nullable @utf8InCpp String name;
+  int zoneId = android.media.audio.common.AudioHalProductStrategy.ZoneId.DEFAULT /* 0 */;
   const int VENDOR_STRATEGY_ID_START = 1000;
+  @Backing(type="int") @VintfStability
+  enum ZoneId {
+    DEFAULT = 0,
+  }
 }
diff --git a/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioPolicyForceUse.aidl b/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioPolicyForceUse.aidl
index 7e69f85..eb883e9 100644
--- a/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioPolicyForceUse.aidl
+++ b/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioPolicyForceUse.aidl
@@ -33,14 +33,49 @@
 
 package android.media.audio.common;
 /* @hide */
-@Backing(type="int") @SuppressWarnings(value={"redundant-name"}) @VintfStability
-enum AudioPolicyForceUse {
-  COMMUNICATION = 0,
-  MEDIA = 1,
-  RECORD = 2,
-  DOCK = 3,
-  SYSTEM = 4,
-  HDMI_SYSTEM_AUDIO = 5,
-  ENCODED_SURROUND = 6,
-  VIBRATE_RINGING = 7,
+@SuppressWarnings(value={"redundant-name"}) @VintfStability
+union AudioPolicyForceUse {
+  android.media.audio.common.AudioPolicyForceUse.MediaDeviceCategory forMedia = android.media.audio.common.AudioPolicyForceUse.MediaDeviceCategory.NONE;
+  android.media.audio.common.AudioPolicyForceUse.CommunicationDeviceCategory forCommunication = android.media.audio.common.AudioPolicyForceUse.CommunicationDeviceCategory.NONE;
+  android.media.audio.common.AudioPolicyForceUse.CommunicationDeviceCategory forRecord = android.media.audio.common.AudioPolicyForceUse.CommunicationDeviceCategory.NONE;
+  android.media.audio.common.AudioPolicyForceUse.CommunicationDeviceCategory forVibrateRinging = android.media.audio.common.AudioPolicyForceUse.CommunicationDeviceCategory.NONE;
+  android.media.audio.common.AudioPolicyForceUse.DockType dock = android.media.audio.common.AudioPolicyForceUse.DockType.NONE;
+  boolean systemSounds = false;
+  boolean hdmiSystemAudio = false;
+  android.media.audio.common.AudioPolicyForceUse.EncodedSurroundConfig encodedSurround = android.media.audio.common.AudioPolicyForceUse.EncodedSurroundConfig.UNSPECIFIED;
+  @Backing(type="byte") @VintfStability
+  enum CommunicationDeviceCategory {
+    NONE = 0,
+    SPEAKER,
+    BT_SCO,
+    BT_BLE,
+    WIRED_ACCESSORY,
+  }
+  @Backing(type="byte") @VintfStability
+  enum MediaDeviceCategory {
+    NONE = 0,
+    SPEAKER,
+    HEADPHONES,
+    BT_A2DP,
+    ANALOG_DOCK,
+    DIGITAL_DOCK,
+    WIRED_ACCESSORY,
+    NO_BT_A2DP,
+  }
+  @Backing(type="byte") @VintfStability
+  enum DockType {
+    NONE = 0,
+    BT_CAR_DOCK,
+    BT_DESK_DOCK,
+    ANALOG_DOCK,
+    DIGITAL_DOCK,
+    WIRED_ACCESSORY,
+  }
+  @Backing(type="byte") @VintfStability
+  enum EncodedSurroundConfig {
+    UNSPECIFIED = 0,
+    NEVER,
+    ALWAYS,
+    MANUAL,
+  }
 }
diff --git a/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioPortDeviceExt.aidl b/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioPortDeviceExt.aidl
index 24d9b29..2b3e72c 100644
--- a/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioPortDeviceExt.aidl
+++ b/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioPortDeviceExt.aidl
@@ -40,5 +40,6 @@ parcelable AudioPortDeviceExt {
   android.media.audio.common.AudioFormatDescription[] encodedFormats;
   int encapsulationModes;
   int encapsulationMetadataTypes;
+  @nullable android.media.audio.common.AudioChannelLayout speakerLayout;
   const int FLAG_INDEX_DEFAULT_DEVICE = 0;
 }
diff --git a/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioUsage.aidl b/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioUsage.aidl
index 7c30cd3..3074b9d 100644
--- a/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioUsage.aidl
+++ b/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioUsage.aidl
@@ -58,4 +58,5 @@ enum AudioUsage {
   SAFETY = 1001,
   VEHICLE_STATUS = 1002,
   ANNOUNCEMENT = 1003,
+  SPEAKER_CLEANUP = 1004,
 }
diff --git a/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioVolumeGroupChangeEvent.aidl b/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioVolumeGroupChangeEvent.aidl
new file mode 100644
index 0000000..3a2bc5b
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioVolumeGroupChangeEvent.aidl
@@ -0,0 +1,56 @@
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @SuppressWarnings(value={"redundant-name"}) @VintfStability
+parcelable AudioVolumeGroupChangeEvent {
+  int groupId;
+  int volumeIndex;
+  boolean muted;
+  int flags;
+  const int VOLUME_FLAG_SHOW_UI = (1 << 0) /* 1 */;
+  const int VOLUME_FLAG_ALLOW_RINGER_MODES = (1 << 1) /* 2 */;
+  const int VOLUME_FLAG_PLAY_SOUND = (1 << 2) /* 4 */;
+  const int VOLUME_FLAG_REMOVE_SOUND_AND_VIBRATE = (1 << 3) /* 8 */;
+  const int VOLUME_FLAG_VIBRATE = (1 << 4) /* 16 */;
+  const int VOLUME_FLAG_FIXED_VOLUME = (1 << 5) /* 32 */;
+  const int VOLUME_FLAG_BLUETOOTH_ABS_VOLUME = (1 << 6) /* 64 */;
+  const int VOLUME_FLAG_SHOW_SILENT_HINT = (1 << 7) /* 128 */;
+  const int VOLUME_FLAG_HDMI_SYSTEM_AUDIO_VOLUME = (1 << 8) /* 256 */;
+  const int VOLUME_FLAG_ACTIVE_MEDIA_ONLY = (1 << 9) /* 512 */;
+  const int VOLUME_FLAG_SHOW_UI_WARNINGS = (1 << 10) /* 1024 */;
+  const int VOLUME_FLAG_SHOW_VIBRATE_HINT = (1 << 11) /* 2048 */;
+  const int VOLUME_FLAG_FROM_KEY = (1 << 12) /* 4096 */;
+  const int VOLUME_FLAG_ABSOLUTE_VOLUME = (1 << 13) /* 8192 */;
+}
diff --git a/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioPolicyForcedConfig.aidl b/media/aidl_api/android.media.audio.eraser.types/current/android/media/audio/eraser/Capability.aidl
similarity index 76%
rename from media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioPolicyForcedConfig.aidl
rename to media/aidl_api/android.media.audio.eraser.types/current/android/media/audio/eraser/Capability.aidl
index 5135bcd..a415a42 100644
--- a/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioPolicyForcedConfig.aidl
+++ b/media/aidl_api/android.media.audio.eraser.types/current/android/media/audio/eraser/Capability.aidl
@@ -31,25 +31,13 @@
 // with such a backward incompatible change, it has a high risk of breaking
 // later when a module using the interface is updated, e.g., Mainline modules.
 
-package android.media.audio.common;
-/* @hide */
-@Backing(type="int") @SuppressWarnings(value={"redundant-name"}) @VintfStability
-enum AudioPolicyForcedConfig {
-  NONE = 0,
-  SPEAKER = 1,
-  HEADPHONES = 2,
-  BT_SCO = 3,
-  BT_A2DP = 4,
-  WIRED_ACCESSORY = 5,
-  BT_CAR_DOCK = 6,
-  BT_DESK_DOCK = 7,
-  ANALOG_DOCK = 8,
-  DIGITAL_DOCK = 9,
-  NO_BT_A2DP = 10,
-  SYSTEM_ENFORCED = 11,
-  HDMI_SYSTEM_AUDIO_ENFORCED = 12,
-  ENCODED_SURROUND_NEVER = 13,
-  ENCODED_SURROUND_ALWAYS = 14,
-  ENCODED_SURROUND_MANUAL = 15,
-  BT_BLE = 16,
+package android.media.audio.eraser;
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable Capability {
+  int[] sampleRates;
+  android.media.audio.common.AudioChannelLayout[] channelLayouts;
+  android.media.audio.eraser.Mode[] modes;
+  android.media.audio.eraser.SeparatorCapability separator;
+  android.media.audio.eraser.ClassifierCapability classifier;
+  android.media.audio.eraser.RemixerCapability remixer;
 }
diff --git a/media/aidl_api/android.media.audio.eraser.types/current/android/media/audio/eraser/Classification.aidl b/media/aidl_api/android.media.audio.eraser.types/current/android/media/audio/eraser/Classification.aidl
new file mode 100644
index 0000000..f90f1c1
--- /dev/null
+++ b/media/aidl_api/android.media.audio.eraser.types/current/android/media/audio/eraser/Classification.aidl
@@ -0,0 +1,38 @@
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.eraser;
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable Classification {
+  android.media.audio.eraser.SoundClassification classification = android.media.audio.eraser.SoundClassification.HUMAN;
+}
diff --git a/media/aidl_api/android.media.audio.eraser.types/current/android/media/audio/eraser/ClassificationConfig.aidl b/media/aidl_api/android.media.audio.eraser.types/current/android/media/audio/eraser/ClassificationConfig.aidl
new file mode 100644
index 0000000..763352d
--- /dev/null
+++ b/media/aidl_api/android.media.audio.eraser.types/current/android/media/audio/eraser/ClassificationConfig.aidl
@@ -0,0 +1,40 @@
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.eraser;
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable ClassificationConfig {
+  android.media.audio.eraser.Classification[] classifications;
+  float confidenceThreshold = 0f;
+  float gainFactor = 1f;
+}
diff --git a/media/aidl_api/android.media.audio.eraser.types/current/android/media/audio/eraser/ClassificationMetadata.aidl b/media/aidl_api/android.media.audio.eraser.types/current/android/media/audio/eraser/ClassificationMetadata.aidl
new file mode 100644
index 0000000..cfdbe5b
--- /dev/null
+++ b/media/aidl_api/android.media.audio.eraser.types/current/android/media/audio/eraser/ClassificationMetadata.aidl
@@ -0,0 +1,39 @@
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.eraser;
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable ClassificationMetadata {
+  float confidenceScore;
+  android.media.audio.eraser.Classification classification;
+}
diff --git a/media/aidl_api/android.media.audio.eraser.types/current/android/media/audio/eraser/ClassificationMetadataList.aidl b/media/aidl_api/android.media.audio.eraser.types/current/android/media/audio/eraser/ClassificationMetadataList.aidl
new file mode 100644
index 0000000..36cef59
--- /dev/null
+++ b/media/aidl_api/android.media.audio.eraser.types/current/android/media/audio/eraser/ClassificationMetadataList.aidl
@@ -0,0 +1,39 @@
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.eraser;
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable ClassificationMetadataList {
+  int timeMs;
+  android.media.audio.eraser.ClassificationMetadata[] metadatas;
+}
diff --git a/media/aidl_api/android.media.audio.eraser.types/current/android/media/audio/eraser/ClassifierCapability.aidl b/media/aidl_api/android.media.audio.eraser.types/current/android/media/audio/eraser/ClassifierCapability.aidl
new file mode 100644
index 0000000..fadf920
--- /dev/null
+++ b/media/aidl_api/android.media.audio.eraser.types/current/android/media/audio/eraser/ClassifierCapability.aidl
@@ -0,0 +1,39 @@
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.eraser;
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable ClassifierCapability {
+  int windowSizeMs;
+  android.media.audio.eraser.Classification[] supportedClassifications;
+}
diff --git a/media/aidl_api/android.media.audio.eraser.types/current/android/media/audio/eraser/Configuration.aidl b/media/aidl_api/android.media.audio.eraser.types/current/android/media/audio/eraser/Configuration.aidl
new file mode 100644
index 0000000..8da4032
--- /dev/null
+++ b/media/aidl_api/android.media.audio.eraser.types/current/android/media/audio/eraser/Configuration.aidl
@@ -0,0 +1,41 @@
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.eraser;
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable Configuration {
+  android.media.audio.eraser.Mode mode = android.media.audio.eraser.Mode.ERASER;
+  android.media.audio.eraser.ClassificationConfig[] classificationConfigs;
+  int maxClassificationMetadata = 5;
+  @nullable android.media.audio.eraser.IEraserCallback callback;
+}
diff --git a/media/aidl_api/android.media.audio.eraser.types/current/android/media/audio/eraser/IEraserCallback.aidl b/media/aidl_api/android.media.audio.eraser.types/current/android/media/audio/eraser/IEraserCallback.aidl
new file mode 100644
index 0000000..8d53405
--- /dev/null
+++ b/media/aidl_api/android.media.audio.eraser.types/current/android/media/audio/eraser/IEraserCallback.aidl
@@ -0,0 +1,38 @@
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.eraser;
+@VintfStability
+interface IEraserCallback {
+  oneway void onClassifierUpdate(in int soundSourceId, in android.media.audio.eraser.ClassificationMetadataList metadata);
+}
diff --git a/media/aidl_api/android.media.audio.eraser.types/current/android/media/audio/eraser/Mode.aidl b/media/aidl_api/android.media.audio.eraser.types/current/android/media/audio/eraser/Mode.aidl
new file mode 100644
index 0000000..916b314
--- /dev/null
+++ b/media/aidl_api/android.media.audio.eraser.types/current/android/media/audio/eraser/Mode.aidl
@@ -0,0 +1,39 @@
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.eraser;
+@Backing(type="byte") @JavaDerive(equals=true, toString=true) @VintfStability
+enum Mode {
+  ERASER,
+  CLASSIFIER,
+}
diff --git a/media/aidl_api/android.media.audio.eraser.types/current/android/media/audio/eraser/RemixerCapability.aidl b/media/aidl_api/android.media.audio.eraser.types/current/android/media/audio/eraser/RemixerCapability.aidl
new file mode 100644
index 0000000..82707b1
--- /dev/null
+++ b/media/aidl_api/android.media.audio.eraser.types/current/android/media/audio/eraser/RemixerCapability.aidl
@@ -0,0 +1,40 @@
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.eraser;
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable RemixerCapability {
+  boolean supported;
+  float minGainFactor = 0f;
+  float maxGainFactor = 1f;
+}
diff --git a/media/aidl_api/android.media.audio.eraser.types/current/android/media/audio/eraser/SeparatorCapability.aidl b/media/aidl_api/android.media.audio.eraser.types/current/android/media/audio/eraser/SeparatorCapability.aidl
new file mode 100644
index 0000000..2e983ac
--- /dev/null
+++ b/media/aidl_api/android.media.audio.eraser.types/current/android/media/audio/eraser/SeparatorCapability.aidl
@@ -0,0 +1,40 @@
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.eraser;
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable SeparatorCapability {
+  boolean supported;
+  int maxSoundSources = 4;
+  const int MIN_SOUND_SOURCE_SUPPORTED = 2;
+}
diff --git a/media/aidl_api/android.media.audio.eraser.types/current/android/media/audio/eraser/SoundClassification.aidl b/media/aidl_api/android.media.audio.eraser.types/current/android/media/audio/eraser/SoundClassification.aidl
new file mode 100644
index 0000000..e5483b4
--- /dev/null
+++ b/media/aidl_api/android.media.audio.eraser.types/current/android/media/audio/eraser/SoundClassification.aidl
@@ -0,0 +1,45 @@
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.eraser;
+@Backing(type="int") @JavaDerive(equals=true, toString=true) @VintfStability
+enum SoundClassification {
+  HUMAN,
+  ANIMAL,
+  NATURE,
+  MUSIC,
+  THINGS,
+  AMBIGUOUS,
+  ENVIRONMENT,
+  VENDOR_EXTENSION,
+}
diff --git a/media/lint-baseline.xml b/media/lint-baseline.xml
index 82f05d2..84bab8e 100644
--- a/media/lint-baseline.xml
+++ b/media/lint-baseline.xml
@@ -45,4 +45,26 @@
             column="36"/>
     </issue>
 
-</issues>
\ No newline at end of file
+    <issue
+        id="NewApi"
+        message="Call requires API level 33 (current min is 29): `android.os.Parcel#writeFixedArray`"
+        errorLine1="        _aidl_parcel.writeFixedArray(getHeadToStage(), _aidl_flag, 6);"
+        errorLine2="                     ~~~~~~~~~~~~~~~">
+        <location
+            file="out/soong/.intermediates/system/hardware/interfaces/media/android.media.audio.common.types-V5-java-source/gen/android/media/audio/common/HeadTracking.java"
+            line="193"
+            column="22"/>
+    </issue>
+
+    <issue
+        id="NewApi"
+        message="Call requires API level 33 (current min is 29): `android.os.Parcel#createFixedArray`"
+        errorLine1="        _aidl_value = _aidl_parcel.createFixedArray(float[].class, 6);"
+        errorLine2="                                   ~~~~~~~~~~~~~~~~">
+        <location
+            file="out/soong/.intermediates/system/hardware/interfaces/media/android.media.audio.common.types-V5-java-source/gen/android/media/audio/common/HeadTracking.java"
+            line="204"
+            column="36"/>
+    </issue>
+
+</issues>
diff --git a/suspend/1.0/default/Android.bp b/suspend/1.0/default/Android.bp
index 32cd02a..6652b6d 100644
--- a/suspend/1.0/default/Android.bp
+++ b/suspend/1.0/default/Android.bp
@@ -13,11 +13,15 @@
 // limitations under the License.
 
 package {
+    default_team: "trendy_team_android_kernel",
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
 cc_defaults {
     name: "system_suspend_defaults",
+    defaults: [
+        "aconfig_lib_cc_static_link.defaults",
+    ],
     shared_libs: [
         "libbase",
         "libbinder",
@@ -26,6 +30,10 @@ cc_defaults {
         "libhidlbase",
         "liblog",
         "libutils",
+        "server_configurable_flags",
+    ],
+    static_libs: [
+        "suspend_service_flags_c_lib",
     ],
     cflags: [
         "-Wall",
@@ -67,6 +75,11 @@ cc_defaults {
     ],
 }
 
+vintf_fragment {
+    name: "android.system.suspend-service.xml",
+    src: "android.system.suspend-service.xml",
+}
+
 cc_binary {
     name: "android.system.suspend-service",
     relative_install_path: "hw",
@@ -74,7 +87,7 @@ cc_binary {
         "android.system.suspend-service_defaults",
     ],
     init_rc: ["android.system.suspend-service.rc"],
-    vintf_fragments: ["android.system.suspend-service.xml"],
+    vintf_fragment_modules: ["android.system.suspend-service.xml"],
     srcs: [
         "main.cpp",
     ],
@@ -200,3 +213,15 @@ cc_fuzz {
         "fuzzers/SuspendServiceInternalFuzzer.cpp",
     ],
 }
+
+aconfig_declarations {
+    name: "suspend_service_flags",
+    package: "suspend_service.flags",
+    container: "system",
+    srcs: ["flags.aconfig"],
+}
+
+cc_aconfig_library {
+    name: "suspend_service_flags_c_lib",
+    aconfig_declarations: "suspend_service_flags",
+}
diff --git a/suspend/1.0/default/SuspendControlService.cpp b/suspend/1.0/default/SuspendControlService.cpp
index faadecb..3e88faf 100644
--- a/suspend/1.0/default/SuspendControlService.cpp
+++ b/suspend/1.0/default/SuspendControlService.cpp
@@ -183,7 +183,22 @@ binder::Status SuspendControlServiceInternal::getWakeLockStats(
     }
 
     suspendService->updateStatsNow();
-    suspendService->getStatsList().getWakeLockStats(_aidl_return);
+    suspendService->getStatsList().getWakeLockStats(
+        BnSuspendControlServiceInternal::WAKE_LOCK_INFO_ALL_FIELDS, _aidl_return);
+
+    return binder::Status::ok();
+}
+
+binder::Status SuspendControlServiceInternal::getWakeLockStatsFiltered(
+    int wakeLockInfoFieldBitMask, std::vector<WakeLockInfo>* _aidl_return) {
+    const auto suspendService = mSuspend.promote();
+    if (!suspendService) {
+        return binder::Status::fromExceptionCode(binder::Status::Exception::EX_NULL_POINTER,
+                                                 String8("Null reference to suspendService"));
+    }
+
+    suspendService->updateStatsNow();
+    suspendService->getStatsList().getWakeLockStats(wakeLockInfoFieldBitMask, _aidl_return);
 
     return binder::Status::ok();
 }
@@ -282,6 +297,7 @@ status_t SuspendControlServiceInternal::dump(int fd, const Vector<String16>& arg
             "----- Suspend Stats -----\n"
             "%s: %d\n%s: %d\n%s: %d\n%s: %d\n%s: %d\n"
             "%s: %d\n%s: %d\n%s: %d\n%s: %d\n%s: %d\n"
+            "%s: %" PRIu64 "\n%s: %" PRIu64 "\n%s: %" PRIu64 "\n"
             "\nLast Failures:\n"
             "    %s: %s\n"
             "    %s: %d\n"
@@ -298,6 +314,9 @@ status_t SuspendControlServiceInternal::dump(int fd, const Vector<String16>& arg
             "failed_resume", stats.failedResume,
             "failed_resume_early", stats.failedResumeEarly,
             "failed_resume_noirq", stats.failedResumeNoirq,
+            "last_hw_sleep", stats.lastHwSleep,
+            "total_hw_sleep", stats.totalHwSleep,
+            "max_hw_sleep", stats.maxHwSleep,
             "last_failed_dev", stats.lastFailedDev.c_str(),
             "last_failed_errno", stats.lastFailedErrno,
             "last_failed_step", stats.lastFailedStep.c_str());
diff --git a/suspend/1.0/default/SuspendControlService.h b/suspend/1.0/default/SuspendControlService.h
index 7d7e0ae..b6e34ff 100644
--- a/suspend/1.0/default/SuspendControlService.h
+++ b/suspend/1.0/default/SuspendControlService.h
@@ -75,6 +75,8 @@ class SuspendControlServiceInternal : public BnSuspendControlServiceInternal {
     binder::Status forceSuspend(bool* _aidl_return) override;
     binder::Status getSuspendStats(SuspendInfo* _aidl_return) override;
     binder::Status getWakeLockStats(std::vector<WakeLockInfo>* _aidl_return) override;
+    binder::Status getWakeLockStatsFiltered(int wakeLockInfoFieldBitMask,
+                                            std::vector<WakeLockInfo>* _aidl_return) override;
     binder::Status getWakeupStats(std::vector<WakeupInfo>* _aidl_return) override;
 
     void setSuspendService(const wp<SystemSuspend>& suspend);
diff --git a/suspend/1.0/default/SuspendSepolicyTests.sh b/suspend/1.0/default/SuspendSepolicyTests.sh
index 0dd2a3e..8bab96d 100755
--- a/suspend/1.0/default/SuspendSepolicyTests.sh
+++ b/suspend/1.0/default/SuspendSepolicyTests.sh
@@ -32,7 +32,9 @@ get_wakeup_paths() {
 }
 
 has_wakeup_attr() { #path
-    adb shell ls -dZ "$1" | grep -q "$wakeup_attr"
+    local _path="$1"
+
+    adb shell "ls -dZ $_path | grep -q $wakeup_attr"
     return $?
 }
 
diff --git a/suspend/1.0/default/SystemSuspend.cpp b/suspend/1.0/default/SystemSuspend.cpp
index c628e43..760aea8 100644
--- a/suspend/1.0/default/SystemSuspend.cpp
+++ b/suspend/1.0/default/SystemSuspend.cpp
@@ -23,10 +23,12 @@
 #include <aidl/android/system/suspend/IWakeLock.h>
 #include <android-base/file.h>
 #include <android-base/logging.h>
+#include <android-base/parseint.h>
 #include <android-base/properties.h>
 #include <android-base/stringprintf.h>
 #include <android-base/strings.h>
 #include <android/binder_manager.h>
+#include <android/system/suspend/internal/ISuspendControlServiceInternal.h>
 #include <fcntl.h>
 #include <sys/stat.h>
 #include <sys/types.h>
@@ -42,11 +44,15 @@ using ::aidl::android::system::suspend::IWakeLock;
 using ::aidl::android::system::suspend::WakeLockType;
 using ::android::base::CachedProperty;
 using ::android::base::Error;
+using ::android::base::ParseInt;
+using ::android::base::ParseUint;
 using ::android::base::ReadFdToString;
 using ::android::base::StringPrintf;
 using ::android::base::WriteStringToFd;
 using ::std::string;
 
+using ISCSI = ::android::system::suspend::internal::ISuspendControlServiceInternal;
+
 namespace android {
 namespace system {
 namespace suspend {
@@ -422,7 +428,8 @@ void SystemSuspend::logKernelWakeLockStats() {
     std::stringstream klStats;
     klStats << "Kernel wakesource stats: ";
     std::vector<WakeLockInfo> wlStats;
-    mStatsList.getWakeLockStats(&wlStats);
+    mStatsList.getWakeLockStats(
+        ISCSI::WAKE_LOCK_INFO_ACTIVE_COUNT | ISCSI::WAKE_LOCK_INFO_TOTAL_TIME, &wlStats);
 
     for (const WakeLockInfo& wake : wlStats) {
         if ((wake.isKernelWakelock) && (wake.activeCount > 0)) {
@@ -543,6 +550,26 @@ const WakeupList& SystemSuspend::getWakeupList() const {
     return mWakeupList;
 }
 
+static int parseIntStat(std::string& statName, std::string& valStr) {
+    int statVal = -1;
+    bool parseSuccess = ParseInt(valStr, &statVal);
+    if (!parseSuccess) {
+        LOG(ERROR) << "Failed to parse " << statName << ", val: " << valStr;
+    }
+
+    return statVal;
+}
+
+static uint64_t parseUintStat(std::string& statName, std::string& valStr) {
+    uint64_t statVal = 0;
+    bool parseSuccess = ParseUint(valStr, &statVal);
+    if (!parseSuccess) {
+        LOG(ERROR) << "Failed to parse " << statName << ", val: " << valStr;
+    }
+
+    return statVal;
+}
+
 /**
  * Returns suspend stats.
  */
@@ -593,31 +620,34 @@ Result<SuspendStats> SystemSuspend::getSuspendStats() {
             stats.lastFailedDev = valStr;
         } else if (statName == "last_failed_step") {
             stats.lastFailedStep = valStr;
-        } else {
-            int statVal = std::stoi(valStr);
-            if (statName == "success") {
-                stats.success = statVal;
-            } else if (statName == "fail") {
-                stats.fail = statVal;
-            } else if (statName == "failed_freeze") {
-                stats.failedFreeze = statVal;
-            } else if (statName == "failed_prepare") {
-                stats.failedPrepare = statVal;
-            } else if (statName == "failed_suspend") {
-                stats.failedSuspend = statVal;
-            } else if (statName == "failed_suspend_late") {
-                stats.failedSuspendLate = statVal;
-            } else if (statName == "failed_suspend_noirq") {
-                stats.failedSuspendNoirq = statVal;
-            } else if (statName == "failed_resume") {
-                stats.failedResume = statVal;
-            } else if (statName == "failed_resume_early") {
-                stats.failedResumeEarly = statVal;
-            } else if (statName == "failed_resume_noirq") {
-                stats.failedResumeNoirq = statVal;
-            } else if (statName == "last_failed_errno") {
-                stats.lastFailedErrno = statVal;
-            }
+        } else if (statName == "success") {
+            stats.success = parseIntStat(statName, valStr);
+        } else if (statName == "fail") {
+            stats.fail = parseIntStat(statName, valStr);
+        } else if (statName == "failed_freeze") {
+            stats.failedFreeze = parseIntStat(statName, valStr);
+        } else if (statName == "failed_prepare") {
+            stats.failedPrepare = parseIntStat(statName, valStr);
+        } else if (statName == "failed_suspend") {
+            stats.failedSuspend = parseIntStat(statName, valStr);
+        } else if (statName == "failed_suspend_late") {
+            stats.failedSuspendLate = parseIntStat(statName, valStr);
+        } else if (statName == "failed_suspend_noirq") {
+            stats.failedSuspendNoirq = parseIntStat(statName, valStr);
+        } else if (statName == "failed_resume") {
+            stats.failedResume = parseIntStat(statName, valStr);
+        } else if (statName == "failed_resume_early") {
+            stats.failedResumeEarly = parseIntStat(statName, valStr);
+        } else if (statName == "failed_resume_noirq") {
+            stats.failedResumeNoirq = parseIntStat(statName, valStr);
+        } else if (statName == "last_failed_errno") {
+            stats.lastFailedErrno = parseIntStat(statName, valStr);
+        } else if (statName == "last_hw_sleep") {
+            stats.lastHwSleep = parseUintStat(statName, valStr);
+        } else if (statName == "total_hw_sleep") {
+            stats.totalHwSleep = parseUintStat(statName, valStr);
+        } else if (statName == "max_hw_sleep") {
+            stats.maxHwSleep = parseUintStat(statName, valStr);
         }
     }
 
diff --git a/suspend/1.0/default/SystemSuspend.h b/suspend/1.0/default/SystemSuspend.h
index 5f69ce8..b41a732 100644
--- a/suspend/1.0/default/SystemSuspend.h
+++ b/suspend/1.0/default/SystemSuspend.h
@@ -59,6 +59,9 @@ struct SuspendStats {
     std::string lastFailedDev;
     int lastFailedErrno = 0;
     std::string lastFailedStep;
+    uint64_t lastHwSleep = 0;
+    uint64_t totalHwSleep = 0;
+    uint64_t maxHwSleep = 0;
 };
 
 struct SleepTimeConfig {
diff --git a/suspend/1.0/default/SystemSuspendUnitTest.cpp b/suspend/1.0/default/SystemSuspendUnitTest.cpp
index b751731..f6b6db3 100644
--- a/suspend/1.0/default/SystemSuspendUnitTest.cpp
+++ b/suspend/1.0/default/SystemSuspendUnitTest.cpp
@@ -30,6 +30,7 @@
 #include <gmock/gmock.h>
 #include <gtest/gtest.h>
 #include <hidl/HidlTransportSupport.h>
+#include <suspend_service_flags.h>
 #include <sys/poll.h>
 #include <sys/socket.h>
 #include <sys/types.h>
@@ -228,7 +229,8 @@ class SystemSuspendTest : public ::testing::Test {
 
     size_t getActiveWakeLockCount() {
         std::vector<WakeLockInfo> wlStats;
-        controlServiceInternal->getWakeLockStats(&wlStats);
+        controlServiceInternal->getWakeLockStatsFiltered(
+            ISuspendControlServiceInternal::WAKE_LOCK_INFO_ACTIVE_COUNT, &wlStats);
         return count_if(wlStats.begin(), wlStats.end(), [](auto entry) { return entry.isActive; });
     }
 
@@ -1118,8 +1120,10 @@ class SystemSuspendSameThreadTest : public ::testing::Test {
                          int64_t failedSuspendLate = 42, int64_t failedSuspendNoirq = 42,
                          int64_t failedResume = 42, int64_t failedResumeEarly = 42,
                          int64_t failedResumeNoirq = 42,
-                         const std::string& lastFailedDev = "fakeDev", int64_t lastFailedErrno = 42,
-                         const std::string& lastFailedStep = "fakeStep") {
+                         const std::string& lastFailedDev = "fakeDev",
+                         int64_t lastFailedErrno = -42,
+                         const std::string& lastFailedStep = "fakeStep", uint64_t lastHwSleep = 42,
+                         uint64_t totalHwSleep = 42, uint64_t maxHwSleep = 523986009990) {
         int fd = suspendStatsFd.get();
 
         return writeStatToFile(fd, "success", success) && writeStatToFile(fd, "fail", fail) &&
@@ -1133,7 +1137,10 @@ class SystemSuspendSameThreadTest : public ::testing::Test {
                writeStatToFile(fd, "failed_resume_noirq", failedResumeNoirq) &&
                writeStatToFile(fd, "last_failed_dev", lastFailedDev) &&
                writeStatToFile(fd, "last_failed_errno", lastFailedErrno) &&
-               writeStatToFile(fd, "last_failed_step", lastFailedStep);
+               writeStatToFile(fd, "last_failed_step", lastFailedStep) &&
+               writeStatToFile(fd, "last_hw_sleep", lastHwSleep) &&
+               writeStatToFile(fd, "total_hw_sleep", totalHwSleep) &&
+               writeStatToFile(fd, "max_hw_sleep", maxHwSleep);
     }
 
     bool removeDirectoryEntry(const std::string& path) {
@@ -1194,9 +1201,10 @@ class SystemSuspendSameThreadTest : public ::testing::Test {
     /**
      * Returns wakelock stats.
      */
-    std::vector<WakeLockInfo> getWakelockStats() {
+    std::vector<WakeLockInfo> getWakelockStats(
+        int32_t selectBitmap = ISuspendControlServiceInternal::WAKE_LOCK_INFO_ALL_FIELDS) {
         std::vector<WakeLockInfo> wlStats;
-        controlServiceInternal->getWakeLockStats(&wlStats);
+        controlServiceInternal->getWakeLockStatsFiltered(selectBitmap, &wlStats);
         return wlStats;
     }
 
@@ -1260,6 +1268,24 @@ class SystemSuspendSameThreadTest : public ::testing::Test {
     };
 };
 
+class mock_flag_provider_interface : public suspend_service::flags::flag_provider_interface {
+   public:
+    MOCK_METHOD(bool, fast_kernel_wakelock_reporting, (), (override));
+};
+
+class ParameterizedSystemSuspendSameThreadTest : public SystemSuspendSameThreadTest,
+                                                 public ::testing::WithParamInterface<bool> {
+   protected:
+    void SetUp() override {
+        auto mock_flag_provider = std::make_unique<mock_flag_provider_interface>();
+        ON_CALL(*mock_flag_provider, fast_kernel_wakelock_reporting())
+            .WillByDefault(::testing::Return(GetParam()));
+        suspend_service::flags::provider_ = std::move(mock_flag_provider);
+
+        SystemSuspendSameThreadTest::SetUp();
+    }
+};
+
 // Test that getWakeLockStats has correct information about Native WakeLocks.
 TEST_F(SystemSuspendSameThreadTest, GetNativeWakeLockStats) {
     std::string fakeWlName = "FakeLock";
@@ -1306,8 +1332,11 @@ TEST_F(SystemSuspendSameThreadTest, GetNativeWakeLockStats) {
     ASSERT_EQ(nwlInfo.wakeupCount, 0);
 }
 
+INSTANTIATE_TEST_SUITE_P(ParameterizedSystemSuspendSameThreadTest,
+                         ParameterizedSystemSuspendSameThreadTest, ::testing::Bool());
+
 // Test that getWakeLockStats has correct information about Kernel WakeLocks.
-TEST_F(SystemSuspendSameThreadTest, GetKernelWakeLockStats) {
+TEST_P(ParameterizedSystemSuspendSameThreadTest, GetKernelWakeLockStats) {
     std::string fakeKwlName1 = "fakeKwl1";
     std::string fakeKwlName2 = "fakeKwl2";
     addKernelWakelock(fakeKwlName1);
@@ -1355,7 +1384,7 @@ TEST_F(SystemSuspendSameThreadTest, GetKernelWakeLockStats) {
 }
 
 // Test that getWakeLockStats has correct information about Native AND Kernel WakeLocks.
-TEST_F(SystemSuspendSameThreadTest, GetNativeAndKernelWakeLockStats) {
+TEST_P(ParameterizedSystemSuspendSameThreadTest, GetNativeAndKernelWakeLockStats) {
     std::string fakeNwlName = "fakeNwl";
     std::string fakeKwlName = "fakeKwl";
 
@@ -1484,8 +1513,11 @@ TEST_F(SystemSuspendSameThreadTest, GetSuspendStats) {
     ASSERT_EQ(stats.failedResumeEarly, 42);
     ASSERT_EQ(stats.failedResumeNoirq, 42);
     ASSERT_EQ(stats.lastFailedDev, "fakeDev");
-    ASSERT_EQ(stats.lastFailedErrno, 42);
+    ASSERT_EQ(stats.lastFailedErrno, -42);
     ASSERT_EQ(stats.lastFailedStep, "fakeStep");
+    ASSERT_EQ(stats.lastHwSleep, 42);
+    ASSERT_EQ(stats.totalHwSleep, 42);
+    ASSERT_EQ(stats.maxHwSleep, 523986009990);
 }
 
 class SuspendWakeupTest : public ::testing::Test {
@@ -1817,6 +1849,42 @@ TEST(WakeupListTest, TestLRUEvict) {
     ASSERT_EQ(wakeups[2].count, 2);
 }
 
+struct WakeLockInfoField {
+    int32_t bit = 0;
+    std::function<int(WakeLockInfo)> getter;
+    int64_t expectedValue;
+};
+
+// Test that selected fields are properly set.
+TEST_P(ParameterizedSystemSuspendSameThreadTest, GetKernelWakeLockStatsFiltered) {
+    using ISCSI = ISuspendControlServiceInternal;
+    static const WakeLockInfoField FIELDS[] = {
+        {ISCSI::WAKE_LOCK_INFO_ACTIVE_COUNT, [](WakeLockInfo wl) { return wl.activeCount; }, 1},
+        {ISCSI::WAKE_LOCK_INFO_LAST_CHANGE, [](WakeLockInfo wl) { return wl.lastChange; }, 2},
+        {ISCSI::WAKE_LOCK_INFO_MAX_TIME, [](WakeLockInfo wl) { return wl.maxTime; }, 3},
+        {ISCSI::WAKE_LOCK_INFO_TOTAL_TIME, [](WakeLockInfo wl) { return wl.totalTime; }, 4},
+        {ISCSI::WAKE_LOCK_INFO_ACTIVE_TIME, [](WakeLockInfo wl) { return wl.activeTime; }, 5},
+        {ISCSI::WAKE_LOCK_INFO_EVENT_COUNT, [](WakeLockInfo wl) { return wl.eventCount; }, 6},
+        {ISCSI::WAKE_LOCK_INFO_EXPIRE_COUNT, [](WakeLockInfo wl) { return wl.expireCount; }, 7},
+        {ISCSI::WAKE_LOCK_INFO_PREVENT_SUSPEND_TIME,
+         [](WakeLockInfo wl) { return wl.preventSuspendTime; }, 8},
+        {ISCSI::WAKE_LOCK_INFO_WAKEUP_COUNT, [](WakeLockInfo wl) { return wl.wakeupCount; }, 9},
+    };
+
+    std::string fakeKwlName1 = "fakeKwl1";
+    addKernelWakelock(fakeKwlName1, /* activeCount = */ 1, /* activeTime = */ 5,
+                      /* eventCount = */ 6,
+                      /* expireCount = */ 7, /* lastChange = */ 2, /* maxTime = */ 3,
+                      /* preventSuspendTime = */ 8, /* totalTime = */ 4, /* wakeupCount = */ 9);
+    for (auto field : FIELDS) {
+        std::vector<WakeLockInfo> infos = getWakelockStats(field.bit);
+        WakeLockInfo wli;
+        ASSERT_TRUE(findWakeLockInfoByName(infos, fakeKwlName1, &wli));
+        ASSERT_EQ(field.getter(wli), field.expectedValue)
+            << "Bit mask " << field.bit << " had unexpected value";
+    }
+}
+
 }  // namespace android
 
 int main(int argc, char** argv) {
diff --git a/suspend/1.0/default/WakeLockEntryList.cpp b/suspend/1.0/default/WakeLockEntryList.cpp
index 5a43501..f726586 100644
--- a/suspend/1.0/default/WakeLockEntryList.cpp
+++ b/suspend/1.0/default/WakeLockEntryList.cpp
@@ -20,6 +20,8 @@
 #include <android-base/logging.h>
 #include <android-base/parseint.h>
 #include <android-base/stringprintf.h>
+#include <android/system/suspend/internal/ISuspendControlServiceInternal.h>
+#include <suspend_service_flags.h>
 
 #include <iomanip>
 
@@ -27,12 +29,37 @@ using android::base::ParseInt;
 using android::base::ReadFdToString;
 using android::base::Readlink;
 using android::base::StringPrintf;
+using suspend_service::flags::fast_kernel_wakelock_reporting;
+
+using ISCSI = ::android::system::suspend::internal::ISuspendControlServiceInternal;
 
 namespace android {
 namespace system {
 namespace suspend {
 namespace V1_0 {
 
+namespace {
+
+struct BitAndFilename {
+    int32_t bit;
+    std::string filename;
+};
+
+const BitAndFilename FIELDS[] = {
+    {-1, "name"},
+    {ISCSI::WAKE_LOCK_INFO_ACTIVE_COUNT, "active_count"},
+    {ISCSI::WAKE_LOCK_INFO_LAST_CHANGE, "last_change_ms"},
+    {ISCSI::WAKE_LOCK_INFO_MAX_TIME, "max_time_ms"},
+    {ISCSI::WAKE_LOCK_INFO_TOTAL_TIME, "total_time_ms"},
+    {ISCSI::WAKE_LOCK_INFO_ACTIVE_TIME, "active_time_ms"},
+    {ISCSI::WAKE_LOCK_INFO_EVENT_COUNT, "event_count"},
+    {ISCSI::WAKE_LOCK_INFO_EXPIRE_COUNT, "expire_count"},
+    {ISCSI::WAKE_LOCK_INFO_PREVENT_SUSPEND_TIME, "prevent_suspend_time_ms"},
+    {ISCSI::WAKE_LOCK_INFO_WAKEUP_COUNT, "wakeup_count"},
+};
+
+}  // namespace
+
 static std::ostream& operator<<(std::ostream& out, const WakeLockInfo& entry) {
     const char* sep = " | ";
     const char* notApplicable = "---";
@@ -65,7 +92,7 @@ static std::ostream& operator<<(std::ostream& out, const WakeLockInfo& entry) {
 
 std::ostream& operator<<(std::ostream& out, const WakeLockEntryList& list) {
     std::vector<WakeLockInfo> wlStats;
-    list.getWakeLockStats(&wlStats);
+    list.getWakeLockStats(ISCSI::WAKE_LOCK_INFO_ALL_FIELDS, &wlStats);
     int width = 194;
     const char* sep = " | ";
     std::stringstream ss;
@@ -324,20 +351,146 @@ WakeLockInfo WakeLockEntryList::createKernelEntry(const std::string& kwlId) cons
     return info;
 }
 
-void WakeLockEntryList::getKernelWakelockStats(std::vector<WakeLockInfo>* aidl_return) const {
+/*
+ * Creates and returns a kernel wakelock entry with data read from mKernelWakelockStatsFd.
+ * Has been micro-optimized to reduce CPU time and wall time.
+ */
+WakeLockInfo WakeLockEntryList::createKernelEntry(ScratchSpace* ss, int wakeLockInfoFieldBitMask,
+                                                  const std::string& kwlId) const {
+    WakeLockInfo info;
+
+    info.activeCount = 0;
+    info.lastChange = 0;
+    info.maxTime = 0;
+    info.totalTime = 0;
+    info.isActive = false;
+    info.activeTime = 0;
+    info.isKernelWakelock = true;
+
+    info.pid = -1;  // N/A
+
+    info.eventCount = 0;
+    info.expireCount = 0;
+    info.preventSuspendTime = 0;
+    info.wakeupCount = 0;
+
+    for (const auto& field : FIELDS) {
+        const bool isNameField = field.bit == -1;
+        if (!isNameField && (wakeLockInfoFieldBitMask & field.bit) == 0) {
+            continue;
+        }
+
+        ss->statName = kwlId + "/" + field.filename;
+        int statFd = -1;
+
+        {
+            std::lock_guard<std::mutex> lock(mLock);
+            // Check if we have a valid cached file descriptor.
+            auto it = mFdCache.find(ss->statName);
+            if (it != mFdCache.end() && it->second >= 0) {
+                auto result = lseek(it->second, 0, SEEK_SET);
+                if (result < 0) {
+                    PLOG(ERROR) << "Could not seek to start of FD for " << ss->statName;
+                    mFdCache.erase(it);
+                    PLOG(ERROR) << "Closed the FD.";
+                } else {
+                    statFd = it->second;
+                }
+            }
+
+            if (statFd == -1) {
+                unique_fd tmpFd(TEMP_FAILURE_RETRY(
+                    openat(mKernelWakelockStatsFd, ss->statName.c_str(), O_CLOEXEC | O_RDONLY)));
+                if (tmpFd < 0) {
+                    PLOG(ERROR) << "Error opening " << ss->statName << " for " << kwlId;
+                    continue;
+                }
+                statFd = tmpFd;
+                mFdCache.insert(it, {ss->statName, std::move(tmpFd)});
+            }
+        }  // mLock is released here
+
+        ss->valStr.clear();
+        ssize_t n;
+        while ((n = TEMP_FAILURE_RETRY(read(statFd, &ss->readBuff[0], sizeof(ss->readBuff)))) > 0) {
+            ss->valStr.append(ss->readBuff, n);
+        }
+        if (n < 0) {
+            PLOG(ERROR) << "Error reading " << ss->statName;
+            {
+                std::lock_guard<std::mutex> lock(mLock);
+                mFdCache.erase(ss->statName);
+                PLOG(ERROR) << "Closed the FD.";
+            }
+            continue;
+        }
+
+        // Trim newline
+        ss->valStr.erase(std::remove(ss->valStr.begin(), ss->valStr.end(), '\n'), ss->valStr.end());
+
+        if (isNameField) {
+            info.name = ss->valStr;
+            continue;
+        }
+
+        int64_t statVal;
+        if (!ParseInt(ss->valStr, &statVal)) {
+            std::string path;
+            if (Readlink(StringPrintf("/proc/self/fd/%d", statFd), &path)) {
+                LOG(ERROR) << "Unexpected format for wakelock stat value (" << ss->valStr
+                           << ") from file: " << path;
+            } else {
+                LOG(ERROR) << "Unexpected format for wakelock stat value (" << ss->valStr << ")";
+            }
+            continue;
+        }
+
+        if (field.filename == "active_count") {
+            info.activeCount = statVal;
+        } else if (field.filename == "active_time_ms") {
+            info.activeTime = statVal;
+        } else if (field.filename == "event_count") {
+            info.eventCount = statVal;
+        } else if (field.filename == "expire_count") {
+            info.expireCount = statVal;
+        } else if (field.filename == "last_change_ms") {
+            info.lastChange = statVal;
+        } else if (field.filename == "max_time_ms") {
+            info.maxTime = statVal;
+        } else if (field.filename == "prevent_suspend_time_ms") {
+            info.preventSuspendTime = statVal;
+        } else if (field.filename == "total_time_ms") {
+            info.totalTime = statVal;
+        } else if (field.filename == "wakeup_count") {
+            info.wakeupCount = statVal;
+        }
+    }
+
+    // Derived stats
+    info.isActive = info.activeTime > 0;
+
+    return info;
+}
+
+void WakeLockEntryList::getKernelWakelockStats(int wakeLockInfoFieldBitMask,
+                                               std::vector<WakeLockInfo>* aidl_return) const {
     std::unique_ptr<DIR, decltype(&closedir)> dp(fdopendir(dup(mKernelWakelockStatsFd.get())),
                                                  &closedir);
     if (dp) {
         // rewinddir, else subsequent calls will not get any kernel wakelocks.
         rewinddir(dp.get());
 
+        ScratchSpace ss;
         struct dirent* de;
         while ((de = readdir(dp.get()))) {
             std::string kwlId(de->d_name);
             if ((kwlId == ".") || (kwlId == "..")) {
                 continue;
             }
-            WakeLockInfo entry = createKernelEntry(kwlId);
+            WakeLockInfo entry = fast_kernel_wakelock_reporting()
+                                     ? createKernelEntry(&ss, wakeLockInfoFieldBitMask, kwlId)
+                                     : createKernelEntry(kwlId);
+
             aidl_return->emplace_back(std::move(entry));
         }
     }
@@ -346,7 +499,7 @@ void WakeLockEntryList::getKernelWakelockStats(std::vector<WakeLockInfo>* aidl_r
 void WakeLockEntryList::updateOnAcquire(const std::string& name, int pid) {
     TimestampType timeNow = getTimeNow();
 
-    std::lock_guard<std::mutex> lock(mStatsLock);
+    std::lock_guard<std::mutex> lock(mLock);
 
     auto key = std::make_pair(name, pid);
     auto it = mLookupTable.find(key);
@@ -372,7 +525,7 @@ void WakeLockEntryList::updateOnAcquire(const std::string& name, int pid) {
 void WakeLockEntryList::updateOnRelease(const std::string& name, int pid) {
     TimestampType timeNow = getTimeNow();
 
-    std::lock_guard<std::mutex> lock(mStatsLock);
+    std::lock_guard<std::mutex> lock(mLock);
 
     auto key = std::make_pair(name, pid);
     auto it = mLookupTable.find(key);
@@ -406,7 +559,7 @@ void WakeLockEntryList::updateOnRelease(const std::string& name, int pid) {
  * Updates the native wakelock stats based on the current time.
  */
 void WakeLockEntryList::updateNow() {
-    std::lock_guard<std::mutex> lock(mStatsLock);
+    std::lock_guard<std::mutex> lock(mLock);
 
     TimestampType timeNow = getTimeNow();
 
@@ -421,15 +574,16 @@ void WakeLockEntryList::updateNow() {
     }
 }
 
-void WakeLockEntryList::getWakeLockStats(std::vector<WakeLockInfo>* aidl_return) const {
+void WakeLockEntryList::getWakeLockStats(int wakeLockInfoFieldBitMask,
+                                         std::vector<WakeLockInfo>* aidl_return) const {
     // Under no circumstances should the lock be held while getting kernel wakelock stats
     {
-        std::lock_guard<std::mutex> lock(mStatsLock);
+        std::lock_guard<std::mutex> lock(mLock);
         for (const WakeLockInfo& entry : mStats) {
             aidl_return->emplace_back(entry);
         }
     }
-    getKernelWakelockStats(aidl_return);
+    getKernelWakelockStats(wakeLockInfoFieldBitMask, aidl_return);
 }
 
 }  // namespace V1_0
diff --git a/suspend/1.0/default/WakeLockEntryList.h b/suspend/1.0/default/WakeLockEntryList.h
index 1ebc411..d81727a 100644
--- a/suspend/1.0/default/WakeLockEntryList.h
+++ b/suspend/1.0/default/WakeLockEntryList.h
@@ -49,16 +49,32 @@ class WakeLockEntryList {
     // updateNow() should be called before getWakeLockStats() to ensure stats are
     // updated wrt the current time.
     void updateNow();
-    void getWakeLockStats(std::vector<WakeLockInfo>* aidl_return) const;
+    void getWakeLockStats(int wakeLockInfoFieldBitMask,
+                          std::vector<WakeLockInfo>* aidl_return) const;
     friend std::ostream& operator<<(std::ostream& out, const WakeLockEntryList& list);
 
    private:
-    void evictIfFull() REQUIRES(mStatsLock);
-    void insertEntry(WakeLockInfo entry) REQUIRES(mStatsLock);
-    void deleteEntry(std::list<WakeLockInfo>::iterator entry) REQUIRES(mStatsLock);
+    void evictIfFull() REQUIRES(mLock);
+    void insertEntry(WakeLockInfo entry) REQUIRES(mLock);
+    void deleteEntry(std::list<WakeLockInfo>::iterator entry) REQUIRES(mLock);
     WakeLockInfo createNativeEntry(const std::string& name, int pid, TimestampType timeNow) const;
     WakeLockInfo createKernelEntry(const std::string& name) const;
-    void getKernelWakelockStats(std::vector<WakeLockInfo>* aidl_return) const;
+
+    // Used by createKernelEntry to reduce heap churn on successive calls.
+    struct ScratchSpace {
+        static constexpr const int BUFF_SIZE = 1024;
+        char readBuff[BUFF_SIZE];
+        std::string statName, valStr;
+        ScratchSpace() {
+            valStr.reserve(BUFF_SIZE);
+            statName.reserve(BUFF_SIZE);
+        }
+    };
+    WakeLockInfo createKernelEntry(ScratchSpace* ss, int wakeLockInfoFieldBitMask,
+                                   const std::string& name) const;
+
+    void getKernelWakelockStats(int wakeLockInfoFieldBitMask,
+                                std::vector<WakeLockInfo>* aidl_return) const;
 
     // Hash for WakeLockEntry key (pair<std::string, int>)
     struct LockHash {
@@ -67,17 +83,18 @@ class WakeLockEntryList {
         }
     };
 
+    mutable std::mutex mLock;
+
     size_t mCapacity;
     unique_fd mKernelWakelockStatsFd;
-
-    mutable std::mutex mStatsLock;
+    mutable std::unordered_map<std::string, unique_fd> mFdCache GUARDED_BY(mLock);
 
     // std::list and std::unordered map are used to support both inserting a stat
     // and eviction of the LRU stat in O(1) time. The LRU stat is maintained at
     // the back of the list.
-    std::list<WakeLockInfo> mStats GUARDED_BY(mStatsLock);
+    std::list<WakeLockInfo> mStats GUARDED_BY(mLock);
     std::unordered_map<std::pair<std::string, int>, std::list<WakeLockInfo>::iterator, LockHash>
-        mLookupTable GUARDED_BY(mStatsLock);
+        mLookupTable GUARDED_BY(mLock);
 };
 
 }  // namespace V1_0
diff --git a/suspend/1.0/default/flags.aconfig b/suspend/1.0/default/flags.aconfig
new file mode 100644
index 0000000..5af880d
--- /dev/null
+++ b/suspend/1.0/default/flags.aconfig
@@ -0,0 +1,9 @@
+package: "suspend_service.flags"
+container: "system"
+
+flag {
+  name: "fast_kernel_wakelock_reporting"
+  namespace: "wear_frameworks"
+  description: "Controls using new codepath to speed up polling of /sys/class/wakeup for kernel wakelocks."
+  bug: "364368163"
+}
\ No newline at end of file
diff --git a/suspend/1.0/default/OWNERS b/suspend/OWNERS
similarity index 100%
rename from suspend/1.0/default/OWNERS
rename to suspend/OWNERS
diff --git a/suspend/aidl/Android.bp b/suspend/aidl/Android.bp
index e7f7062..97e0694 100644
--- a/suspend/aidl/Android.bp
+++ b/suspend/aidl/Android.bp
@@ -19,6 +19,7 @@ aidl_interface {
 aidl_interface {
     name: "android.system.suspend.control",
     local_include_dir: ".",
+    frozen: true,
     srcs: [
         "android/system/suspend/ISuspendControlService.aidl",
         "android/system/suspend/ISuspendCallback.aidl",
diff --git a/suspend/aidl/android/system/suspend/internal/ISuspendControlServiceInternal.aidl b/suspend/aidl/android/system/suspend/internal/ISuspendControlServiceInternal.aidl
index 8e0a9a2..065d486 100644
--- a/suspend/aidl/android/system/suspend/internal/ISuspendControlServiceInternal.aidl
+++ b/suspend/aidl/android/system/suspend/internal/ISuspendControlServiceInternal.aidl
@@ -45,6 +45,12 @@ interface ISuspendControlServiceInternal {
      */
     WakeLockInfo[] getWakeLockStats();
 
+    /**
+     * Returns a list of wake lock stats. Fields not selected with the
+     * bit mask are in an undefined state (see WAKE_LOCK_INFO_* below).
+     */
+    WakeLockInfo[] getWakeLockStatsFiltered(int wakeLockInfoFieldBitMask);
+
     /**
      * Returns a list of wakeup stats.
      */
@@ -54,4 +60,27 @@ interface ISuspendControlServiceInternal {
      * Returns stats related to suspend.
      */
     SuspendInfo getSuspendStats();
+
+    /**
+     * Used to select fields from WakeLockInfo that getWakeLockStats should return.
+     * This is in addition to the name of the wake lock, which is always returned.
+     */
+    const int WAKE_LOCK_INFO_ACTIVE_COUNT = 1 << 0;
+    const int WAKE_LOCK_INFO_LAST_CHANGE = 1 << 1;
+    const int WAKE_LOCK_INFO_MAX_TIME = 1 << 2;
+    const int WAKE_LOCK_INFO_TOTAL_TIME = 1 << 3;
+    const int WAKE_LOCK_INFO_IS_ACTIVE = 1 << 4;
+    const int WAKE_LOCK_INFO_ACTIVE_TIME = 1 << 5;
+    const int WAKE_LOCK_INFO_IS_KERNEL_WAKELOCK = 1 << 6;
+
+    // Specific to Native wake locks.
+    const int WAKE_LOCK_INFO_PID = 1 << 7;
+
+    // Specific to Kernel wake locks.
+    const int WAKE_LOCK_INFO_EVENT_COUNT = 1 << 8;
+    const int WAKE_LOCK_INFO_EXPIRE_COUNT = 1 << 9;
+    const int WAKE_LOCK_INFO_PREVENT_SUSPEND_TIME = 1 << 10;
+    const int WAKE_LOCK_INFO_WAKEUP_COUNT = 1 << 11;
+
+    const int WAKE_LOCK_INFO_ALL_FIELDS = (1 << 12) - 1;
 }
diff --git a/vold/Android.bp b/vold/Android.bp
new file mode 100644
index 0000000..c53ae65
--- /dev/null
+++ b/vold/Android.bp
@@ -0,0 +1,30 @@
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+aidl_interface {
+    name: "android.system.vold",
+    vendor_available: true,
+    stability: "vintf",
+    host_supported: true,
+    srcs: [
+        "android/system/vold/CheckpointingState.aidl",
+        "android/system/vold/IVold.aidl",
+        "android/system/vold/IVoldCheckpointListener.aidl",
+    ],
+    backend: {
+        java: {
+            enabled: false,
+        },
+        cpp: {
+            enabled: true,
+        },
+        ndk: {
+            enabled: true,
+        },
+        rust: {
+            enabled: true,
+        },
+    },
+    frozen: false,
+}
diff --git a/vold/aidl_api/android.system.vold/current/android/system/vold/CheckpointingState.aidl b/vold/aidl_api/android.system.vold/current/android/system/vold/CheckpointingState.aidl
new file mode 100644
index 0000000..040b40e
--- /dev/null
+++ b/vold/aidl_api/android.system.vold/current/android/system/vold/CheckpointingState.aidl
@@ -0,0 +1,39 @@
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.system.vold;
+@VintfStability
+enum CheckpointingState {
+  POSSIBLE_CHECKPOINTING,
+  CHECKPOINTING_COMPLETE,
+}
diff --git a/vold/aidl_api/android.system.vold/current/android/system/vold/IVold.aidl b/vold/aidl_api/android.system.vold/current/android/system/vold/IVold.aidl
new file mode 100644
index 0000000..85bcd3b
--- /dev/null
+++ b/vold/aidl_api/android.system.vold/current/android/system/vold/IVold.aidl
@@ -0,0 +1,38 @@
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.system.vold;
+@VintfStability
+interface IVold {
+  android.system.vold.CheckpointingState registerCheckpointListener(android.system.vold.IVoldCheckpointListener listener);
+}
diff --git a/vold/aidl_api/android.system.vold/current/android/system/vold/IVoldCheckpointListener.aidl b/vold/aidl_api/android.system.vold/current/android/system/vold/IVoldCheckpointListener.aidl
new file mode 100644
index 0000000..434fbd2
--- /dev/null
+++ b/vold/aidl_api/android.system.vold/current/android/system/vold/IVoldCheckpointListener.aidl
@@ -0,0 +1,38 @@
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.system.vold;
+@VintfStability
+interface IVoldCheckpointListener {
+  oneway void onCheckpointingComplete();
+}
diff --git a/vold/android/system/vold/CheckpointingState.aidl b/vold/android/system/vold/CheckpointingState.aidl
new file mode 100644
index 0000000..e69bc95
--- /dev/null
+++ b/vold/android/system/vold/CheckpointingState.aidl
@@ -0,0 +1,34 @@
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
+package android.system.vold;
+
+/**
+ * Describes the IVold service's possible checkpointing states.
+ */
+@VintfStability
+enum CheckpointingState {
+    /**
+     * The service has not yet determined whether checkpointing is needed, or there is a checkpoint
+     * active.
+     */
+    POSSIBLE_CHECKPOINTING,
+    /**
+     * There is no checkpoint active and there will not be any more checkpoints before the system
+     * reboots.
+     */
+    CHECKPOINTING_COMPLETE,
+}
\ No newline at end of file
diff --git a/vold/android/system/vold/IVold.aidl b/vold/android/system/vold/IVold.aidl
new file mode 100644
index 0000000..2bcce4b
--- /dev/null
+++ b/vold/android/system/vold/IVold.aidl
@@ -0,0 +1,42 @@
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
+package android.system.vold;
+
+import android.system.vold.CheckpointingState;
+import android.system.vold.IVoldCheckpointListener;
+
+/**
+ * Vendor-available subset of android.os.IVold functionality.
+ */
+@VintfStability
+interface IVold {
+    /**
+     * Register a checkpointing listener.
+     *
+     * @listener:
+     *     listener to be added to the set of callbacks which will be invoked when checkpointing
+     * completes or when Vold service knows that checkpointing will not be necessary.
+     *
+     * Return:
+     *     CHECKPOINTING_COMPLETE when the listener will not be called in the future i.e. when
+     * checkpointing is 1) already completed or 2) not needed.
+     *     POSSIBLE_CHECKPOINTING when the listener will be called in the future, i.e. when
+     * there is an active checkpoint or when service does not yet know whether checkpointing is
+     * needed.
+     */
+    CheckpointingState registerCheckpointListener(IVoldCheckpointListener listener);
+}
diff --git a/vold/android/system/vold/IVoldCheckpointListener.aidl b/vold/android/system/vold/IVoldCheckpointListener.aidl
new file mode 100644
index 0000000..6a3511e
--- /dev/null
+++ b/vold/android/system/vold/IVoldCheckpointListener.aidl
@@ -0,0 +1,29 @@
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
+package android.system.vold;
+
+/**
+ * Listener for changes in checkpointing state.
+ */
+@VintfStability
+oneway interface IVoldCheckpointListener {
+    /**
+     * Invoked when Vold service has determined that no checkpointing is in progress, either
+     * because no checkpointing was necessary, or because the checkpoint completed.
+     */
+    oneway void onCheckpointingComplete();
+}
diff --git a/wifi/keystore/1.0/vts/functional/Android.bp b/wifi/keystore/1.0/vts/functional/Android.bp
index 7f13903..d4e6c03 100644
--- a/wifi/keystore/1.0/vts/functional/Android.bp
+++ b/wifi/keystore/1.0/vts/functional/Android.bp
@@ -15,6 +15,7 @@
 //
 
 package {
+    default_team: "trendy_team_fwk_wifi_hal",
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
```

