```diff
diff --git a/media/Android.bp b/media/Android.bp
index d7a1eac..5ba8985 100644
--- a/media/Android.bp
+++ b/media/Android.bp
@@ -47,8 +47,13 @@ aidl_interface {
         "aidl/android/media/audio/common/AudioGainConfig.aidl",
         "aidl/android/media/audio/common/AudioGainMode.aidl",
         "aidl/android/media/audio/common/AudioHalAttributesGroup.aidl",
+        "aidl/android/media/audio/common/AudioHalCapConfiguration.aidl",
         "aidl/android/media/audio/common/AudioHalCapCriterion.aidl",
+        "aidl/android/media/audio/common/AudioHalCapCriterionV2.aidl",
         "aidl/android/media/audio/common/AudioHalCapCriterionType.aidl",
+        "aidl/android/media/audio/common/AudioHalCapDomain.aidl",
+        "aidl/android/media/audio/common/AudioHalCapParameter.aidl",
+        "aidl/android/media/audio/common/AudioHalCapRule.aidl",
         "aidl/android/media/audio/common/AudioHalEngineConfig.aidl",
         "aidl/android/media/audio/common/AudioHalProductStrategy.aidl",
         "aidl/android/media/audio/common/AudioHalVolumeCurve.aidl",
@@ -63,6 +68,8 @@ aidl_interface {
         "aidl/android/media/audio/common/AudioOffloadInfo.aidl",
         "aidl/android/media/audio/common/AudioOutputFlags.aidl",
         "aidl/android/media/audio/common/AudioPlaybackRate.aidl",
+        "aidl/android/media/audio/common/AudioPolicyForcedConfig.aidl",
+        "aidl/android/media/audio/common/AudioPolicyForceUse.aidl",
         "aidl/android/media/audio/common/AudioPort.aidl",
         "aidl/android/media/audio/common/AudioPortConfig.aidl",
         "aidl/android/media/audio/common/AudioPortDeviceExt.aidl",
@@ -135,12 +142,12 @@ aidl_interface {
         // IMPORTANT: Update latest_android_media_audio_common_types every time
         // you add the latest frozen version to versions_with_info
     ],
-    frozen: true,
+    frozen: false,
 
 }
 
 // Note: This should always be one version ahead of the last frozen version
-latest_android_media_audio_common_types = "android.media.audio.common.types-V3"
+latest_android_media_audio_common_types = "android.media.audio.common.types-V4"
 
 // Modules that depend on android.media.audio.common.types directly can include
 // the following cc_defaults to avoid explicitly managing dependency versions
@@ -261,12 +268,12 @@ aidl_interface {
         },
 
     ],
-    frozen: true,
+    frozen: false,
 
 }
 
 // Note: This should always be one version ahead of the last frozen version
-latest_android_media_soundtrigger_types = "android.media.soundtrigger.types-V2"
+latest_android_media_soundtrigger_types = "android.media.soundtrigger.types-V3"
 
 cc_defaults {
     name: "latest_android_media_soundtrigger_types_cpp_shared",
diff --git a/media/aidl/android/media/audio/common/AudioHalCapConfiguration.aidl b/media/aidl/android/media/audio/common/AudioHalCapConfiguration.aidl
new file mode 100644
index 0000000..6432d84
--- /dev/null
+++ b/media/aidl/android/media/audio/common/AudioHalCapConfiguration.aidl
@@ -0,0 +1,79 @@
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
+package android.media.audio.common;
+
+import android.media.audio.common.AudioHalCapParameter;
+import android.media.audio.common.AudioHalCapRule;
+
+/**
+ * AudioHalCapConfiguration defines the Configurable Audio Policy (CAP) groups of runtime
+ * configurations that may affect a group of parameter within a {@see AudioHalCapDomain}.
+ * The configuration is defined by its name and associated rule based on provided criteria.
+ * The configuration is referred in {@see AudioHalCapSetting} with its name, that must hence be
+ * unique within the belonging domain.
+ *
+ *                            ┌──────────────────────────┐
+ *                            │   AudioHalCapParameter   │
+ *                            │        (union)           ◄────────────────────────────────────────┐
+ *                            │                          │                                        │
+ *                            │selectedStrateguDevice    │                                        │
+ *                            │strateguDeviceAddress     │                                        │
+ *                            │selectedInputSourceDevice │     ┌───────────────────────────────┐  │
+ *                            │streamVolumeProfile       │     │ AudioHalCapConfiguration      │  │
+ *                            └──────────────────────────┘ ┌───►                               │  │
+ *                                                         │   │ name                          │  │
+ *                            ┌──────────────────────────┐ │  ┌┼─rule                          │  │
+ *                            │    AudioHalCapComain     │ │  ││ parameterSettings[]───────────┼──┘
+ *                            │                          │ │  │└───────────────────────────────┘
+ *                         ┌──►name                      │ │  │
+ *                         │  │configurations[]──────────┼─┘  │┌───────────────────────────────┐
+ *                         │  └──────────────────────────┘    └► AudioHalCapRule               │
+ *                         │                                   │                               │
+ * ┌──────────────────────┐│                               ┌───┤ criterionRules[]──────────────┼──┐
+ * │ AudioHalEngineConfig ││                               └───┼─nestedRules[]                 │  │
+ * │                      ││                                   └───────────────────────────────┘  │
+ * │ domains[]────────────┼┘ ┌────────────────────────────────┐                                   │
+ * │ criteriaV2[]─────────┼┐ │   AudioHalCapCriterionV2       │┌───────────────────────────────┐  │
+ * └──────────────────────┘│ │           (union)              ││ CriterionRule                 │  │
+ *                         │ │ type                           ││                               ◄──┘
+ *                         │ │                                ││ matchingRule                  │
+ *                         │ │ availableInputDevices          ││ audioHalCapCriterionV2        │
+ *                         │ │ availableOutputDevices         ││ audioHalCapCriterionV2.type   │
+ *                         └─► availableInputDevicesAddresses │└───────────────────────────────┘
+ *                           │ availableOutputDevicesAddresses│
+ *                           │ telephonyMode                  │
+ *                           │ forcConfigForUse               │
+ *                           └────────────────────────────────┘
+ *
+ * {@hide}
+ */
+@JavaDerive(equals=true, toString=true)
+@VintfStability
+parcelable AudioHalCapConfiguration {
+    /**
+     * Unique name of the configuration within a {@see AudioHalCapDomain}.
+     */
+    @utf8InCpp String name;
+    /**
+     * Rule to be verified to apply this configuration.
+     */
+    AudioHalCapRule rule;
+    /**
+     * A non-empty list of parameter settings, aka a couple of parameter and values.
+     */
+    AudioHalCapParameter[] parameterSettings;
+}
diff --git a/media/aidl/android/media/audio/common/AudioHalCapCriterionV2.aidl b/media/aidl/android/media/audio/common/AudioHalCapCriterionV2.aidl
new file mode 100644
index 0000000..b131358
--- /dev/null
+++ b/media/aidl/android/media/audio/common/AudioHalCapCriterionV2.aidl
@@ -0,0 +1,104 @@
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
+package android.media.audio.common;
+
+import android.media.audio.common.AudioDeviceAddress;
+import android.media.audio.common.AudioDeviceDescription;
+import android.media.audio.common.AudioMode;
+import android.media.audio.common.AudioPolicyForceUse;
+import android.media.audio.common.AudioPolicyForcedConfig;
+
+/**
+ * AudioHalCapCriterion is a wrapper for a CriterionType and its default value.
+ * This is to be used exclusively for the Configurable Audio Policy (CAP) engine
+ * configuration.
+ *
+ * {@hide}
+ */
+@VintfStability
+union AudioHalCapCriterionV2 {
+    /**
+     * A criterion can either be exclusive (can take one value at a time) or inclusive (like a
+     * bitfield, it can have several values). Rules expected on inclusive or exclusive will be
+     * different.
+     */
+    @VintfStability
+    enum LogicalDisjunction {
+        EXCLUSIVE = 0,
+        INCLUSIVE,
+    }
+    /**
+     * Forced configuration for a given usage criterion. It is used to force the audio routing
+     * for a given use case or usage.
+     */
+    @VintfStability
+    parcelable ForceConfigForUse {
+        /**  Force usage addressed by this criterion. */
+        AudioPolicyForceUse forceUse = AudioPolicyForceUse.MEDIA;
+        /** List of supported value by this criterion. */
+        AudioPolicyForcedConfig[] values;
+        /** Default configuration applied if none is provided. */
+        AudioPolicyForcedConfig defaultValue = AudioPolicyForcedConfig.NONE;
+        /** Logic followed by this criterion, only one value at given time. */
+        LogicalDisjunction logic = LogicalDisjunction.EXCLUSIVE;
+    }
+    /**
+     * The telephony mode or call state criterion. It is used to apply specific audio routing for
+     * the telephony use cases.
+     */
+    @VintfStability
+    parcelable TelephonyMode {
+        /** List of supported audio mode values for this criterion. */
+        AudioMode[] values;
+        /** Default value to be applied if none is provided. */
+        AudioMode defaultValue = AudioMode.NORMAL;
+        /** Logic followed by this criterion, only one value at given time. */
+        LogicalDisjunction logic = LogicalDisjunction.EXCLUSIVE;
+    }
+    @VintfStability
+    parcelable AvailableDevices {
+        /** List if supported values (aka audio devices) by this criterion. */
+        AudioDeviceDescription[] values;
+        /** Logic followed by this criterion, multiple devices can be selected/available. */
+        LogicalDisjunction logic = LogicalDisjunction.INCLUSIVE;
+    }
+    @VintfStability
+    parcelable AvailableDevicesAddresses {
+        /** List if supported values (aka audio device addresses) by this criterion. */
+        AudioDeviceAddress[] values;
+        /** Logic followed by this criterion, multiple device addresses can be available. */
+        LogicalDisjunction logic = LogicalDisjunction.INCLUSIVE;
+    }
+    AvailableDevices availableInputDevices;
+    AvailableDevices availableOutputDevices;
+    AvailableDevicesAddresses availableInputDevicesAddresses;
+    AvailableDevicesAddresses availableOutputDevicesAddresses;
+    TelephonyMode telephonyMode;
+    ForceConfigForUse forceConfigForUse;
+
+    /**
+     * Supported criterion types for Configurable Audio Policy Engine.
+     */
+    @VintfStability
+    union Type {
+        AudioDeviceDescription availableDevicesType;
+        AudioDeviceAddress availableDevicesAddressesType;
+        AudioMode telephonyModeType;
+        AudioPolicyForcedConfig forcedConfigType;
+    }
+    Type type;
+}
diff --git a/media/aidl/android/media/audio/common/AudioHalCapDomain.aidl b/media/aidl/android/media/audio/common/AudioHalCapDomain.aidl
new file mode 100644
index 0000000..6b9196c
--- /dev/null
+++ b/media/aidl/android/media/audio/common/AudioHalCapDomain.aidl
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
+package android.media.audio.common;
+
+import android.media.audio.common.AudioHalCapConfiguration;
+
+/**
+ * AudioHalCapDomain defines the Configurable Audio Policy (CAP) groups of parameters that belong
+ * to a given domain and manage the runtime behavior (aka values of the parameter).
+ *
+ * {@hide}
+ */
+@JavaDerive(equals=true, toString=true)
+@VintfStability
+parcelable AudioHalCapDomain {
+    /**
+     * Name of the configurable domain. It must be unique for the given instance of parameter
+     * framework.
+     */
+    @utf8InCpp String name;
+    /**
+     * A non-empty list of configurations aka different runtime conditions that may affect
+     * the value of the parameters controlled by this domain and the values of the parameters.
+     * All the settings within a domain shall define values for  the same parameters belonging
+     * to this domain.
+     */
+    AudioHalCapConfiguration[] configurations;
+}
diff --git a/media/aidl/android/media/audio/common/AudioHalCapParameter.aidl b/media/aidl/android/media/audio/common/AudioHalCapParameter.aidl
new file mode 100644
index 0000000..665625e
--- /dev/null
+++ b/media/aidl/android/media/audio/common/AudioHalCapParameter.aidl
@@ -0,0 +1,66 @@
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
+package android.media.audio.common;
+
+import android.media.audio.common.AudioDeviceAddress;
+import android.media.audio.common.AudioDeviceDescription;
+import android.media.audio.common.AudioProductStrategyType;
+import android.media.audio.common.AudioSource;
+import android.media.audio.common.AudioStreamType;
+
+/**
+ * Defines the audio Cap Engine Parameters expected to be controlled by the configurable engine.
+ * These parameters deal with:
+ *    Volume Profile: for volume curve selection (e.g. dtmf follows call curves during call).
+ *    Output/Input device selection for a given strategy based on:
+ *        -the type (each device will be a bit in a bitfield, allowing to select multiple devices).
+ *        -the address
+ *
+ * {@hide}
+ */
+@VintfStability
+union AudioHalCapParameter {
+    @VintfStability
+    parcelable StrategyDeviceAddress {
+        AudioDeviceAddress deviceAddress;
+        // AudioHalProductStrategy.id
+        int id = AudioProductStrategyType.SYS_RESERVED_NONE;
+    }
+    @VintfStability
+    parcelable StrategyDevice {
+        AudioDeviceDescription device;
+        // AudioHalProductStrategy.id
+        int id = AudioProductStrategyType.SYS_RESERVED_NONE;
+        boolean isSelected;
+    }
+    @VintfStability
+    parcelable InputSourceDevice {
+        AudioDeviceDescription device;
+        AudioSource inputSource = AudioSource.DEFAULT;
+        boolean isSelected;
+    }
+    @VintfStability
+    parcelable StreamVolumeProfile {
+        AudioStreamType stream = AudioStreamType.INVALID;
+        AudioStreamType profile = AudioStreamType.INVALID;
+    }
+
+    StrategyDevice selectedStrategyDevice;
+    StrategyDeviceAddress strategyDeviceAddress;
+    InputSourceDevice selectedInputSourceDevice;
+    StreamVolumeProfile streamVolumeProfile;
+}
diff --git a/media/aidl/android/media/audio/common/AudioHalCapRule.aidl b/media/aidl/android/media/audio/common/AudioHalCapRule.aidl
new file mode 100644
index 0000000..aa52796
--- /dev/null
+++ b/media/aidl/android/media/audio/common/AudioHalCapRule.aidl
@@ -0,0 +1,132 @@
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
+package android.media.audio.common;
+
+import android.media.audio.common.AudioHalCapCriterionV2;
+
+/**
+ * AudioHalCapRule defines the Configurable Audio Policy (CAP) rules for a given configuration.
+ *
+ * Rule may be compounded using a logical operator "ALL" (aka "AND") and "ANY' (aka "OR").
+ * Compounded rule can be nested.
+ * Rules on criterion is made of:
+ *      -type of criterion:
+ *              -inclusive -> match rules are "Includes" or "Excludes"
+ *              -exclusive -> match rules are "Is" or "IsNot" aka equal or different
+ *      -Name of the criterion must match the provided name in AudioHalCapCriterion
+ *      -Value of the criterion must match the provided list of literal values from
+ *         AudioHalCapCriterionType
+ * Example of rule:
+ *      ALL
+ *          ANY
+ *              ALL
+ *                  CriterionRule1
+ *                  CriterionRule2
+ *              CriterionRule3
+ *          CriterionRule4
+ *
+ * It will correspond to
+ *      ALL
+ *          nestedRule1
+ *          CriterionRule4
+ *
+ * where nestedRule1 is
+ *            ANY
+ *              nestedRule2
+ *              CriterionRule3
+ * and nestedRule2 is
+ *              ALL
+ *                  CriterionRule1
+ *                  CriterionRule2
+ *
+ * Translated into:
+ *     { .compoundRule = CompoundRule::ALL, .nestedRule[0] =
+ *         { .compoundRule = CompoundRule::ANY, .nestedRule[0] =
+ *             { .compoundRule = CompoundRule::ALL, .criterionRules =
+ *                  { CriterionRule1, CriterionRule2 }},
+ *           .criterionRules = { CriterionRule3 },
+ *         },
+ *       .criterionRules = { CriterionRule4 }}
+ *
+ * {@hide}
+ */
+@JavaDerive(equals=true, toString=true)
+@VintfStability
+parcelable AudioHalCapRule {
+    @VintfStability
+    enum CompoundRule {
+        INVALID = 0,
+        /*
+         * OR'ed rules
+         */
+        ANY,
+        /*
+         * AND'ed rules
+         */
+        ALL,
+    }
+
+    @VintfStability
+    enum MatchingRule {
+        INVALID = -1,
+        /*
+         * Matching rule on exclusive criterion type.
+         */
+        IS = 0,
+        /*
+         * Exclusion rule on exclusive criterion type.
+         */
+        IS_NOT,
+        /*
+         * Matching rule on inclusive criterion type (aka bitfield type).
+         */
+        INCLUDES,
+        /*
+         * Exclusion rule on inclusive criterion type (aka bitfield type).
+         */
+        EXCLUDES,
+    }
+
+    @VintfStability
+    parcelable CriterionRule {
+        MatchingRule matchingRule = MatchingRule.INVALID;
+        /*
+         * Must be one of the name defined by {@see AudioHalCapCriterionV2}.
+         */
+        AudioHalCapCriterionV2 criterion;
+        /*
+         * Must be one of the value defined by {@see AudioHalCapCriterionV2::Type}.
+         * Must be one of the associated {@see AudioHalCapCriterionV2} values.
+         */
+        AudioHalCapCriterionV2.Type criterionTypeValue;
+    }
+    /*
+     * Defines the AND or OR'ed logcal rule between provided criterion rules if any and provided
+     * nested rule if any.
+     * Even if no rules or nestedRule are provided, a compound is expected with ALL rule to set the
+     * rule of the {@see AudioHalConfiguration} as "always applicable".
+     */
+    CompoundRule compoundRule = CompoundRule.INVALID;
+    /*
+     * An AudioHalCapRule may contain 0..n CriterionRules.
+     */
+    CriterionRule[] criterionRules;
+    /*
+     * An AudioHalCapRule may be nested with 0..n AudioHalCapRules.
+     */
+    AudioHalCapRule[] nestedRules;
+}
diff --git a/media/aidl/android/media/audio/common/AudioHalEngineConfig.aidl b/media/aidl/android/media/audio/common/AudioHalEngineConfig.aidl
index be29348..fb8f4e6 100644
--- a/media/aidl/android/media/audio/common/AudioHalEngineConfig.aidl
+++ b/media/aidl/android/media/audio/common/AudioHalEngineConfig.aidl
@@ -17,7 +17,9 @@
 package android.media.audio.common;
 
 import android.media.audio.common.AudioHalCapCriterion;
+import android.media.audio.common.AudioHalCapCriterionV2;
 import android.media.audio.common.AudioHalCapCriterionType;
+import android.media.audio.common.AudioHalCapDomain;
 import android.media.audio.common.AudioHalProductStrategy;
 import android.media.audio.common.AudioHalVolumeGroup;
 import android.media.audio.common.AudioProductStrategyType;
@@ -57,6 +59,15 @@ parcelable AudioHalEngineConfig {
     parcelable CapSpecificConfig {
         AudioHalCapCriterion[] criteria;
         AudioHalCapCriterionType[] criterionTypes;
+
+        @nullable AudioHalCapCriterionV2[] criteriaV2;
+        /**
+         * AudioHalCapDomains defines the Configurable Audio Policy (CAP) engine configurable
+         * domains that are used by the parameter-framework to define a dynamic management of
+         * policy engine parameters (aka defining the values of the policy parameters according to
+         * the values of provided criteria).
+         */
+        @nullable AudioHalCapDomain[] domains;
     }
     /**
      * Specifies the configuration items that are specific to the Configurable
diff --git a/media/aidl/android/media/audio/common/AudioHalProductStrategy.aidl b/media/aidl/android/media/audio/common/AudioHalProductStrategy.aidl
index 214b3d4..c3bc656 100644
--- a/media/aidl/android/media/audio/common/AudioHalProductStrategy.aidl
+++ b/media/aidl/android/media/audio/common/AudioHalProductStrategy.aidl
@@ -44,4 +44,15 @@ parcelable AudioHalProductStrategy {
      * This is the list of use cases that follow the same routing strategy.
      */
     AudioHalAttributesGroup[] attributesGroups;
+    /**
+     * Name of the strategy. Nullable for backward compatibility. If null, id
+     * are assigned by the audio policy engine, ensuring uniqueness.
+     *
+     * With complete engine configuration AIDL migration, strategy ids are
+     * preallocated (from `VENDOR_STRATEGY_ID_START` to
+     * `VENDOR_STRATEGY_ID_START+39`). A human readable name must be
+     * defined uniquely (to make dump/debug easier) for all strategies and
+     * must not be null for any.
+     */
+    @nullable @utf8InCpp String name;
 }
diff --git a/media/aidl/android/media/audio/common/AudioPolicyForceUse.aidl b/media/aidl/android/media/audio/common/AudioPolicyForceUse.aidl
new file mode 100644
index 0000000..f20948c
--- /dev/null
+++ b/media/aidl/android/media/audio/common/AudioPolicyForceUse.aidl
@@ -0,0 +1,35 @@
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
+package android.media.audio.common;
+
+/**
+ * List of usages to be used in addition to forced config in order to force the audio routing.
+ *
+ * {@hide}
+ */
+@Backing(type="int")
+@SuppressWarnings(value={"redundant-name"})
+@VintfStability
+enum AudioPolicyForceUse {
+    COMMUNICATION = 0,
+    MEDIA = 1,
+    RECORD = 2,
+    DOCK = 3,
+    SYSTEM = 4,
+    HDMI_SYSTEM_AUDIO = 5,
+    ENCODED_SURROUND = 6,
+    VIBRATE_RINGING = 7,
+}
diff --git a/media/aidl/android/media/audio/common/AudioPolicyForcedConfig.aidl b/media/aidl/android/media/audio/common/AudioPolicyForcedConfig.aidl
new file mode 100644
index 0000000..2acf4e1
--- /dev/null
+++ b/media/aidl/android/media/audio/common/AudioPolicyForcedConfig.aidl
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
+package android.media.audio.common;
+
+/**
+ * List of forced configurations aka device categories to be used in addition to the force use
+ * in order to force the audio routing.
+ *
+ * {@hide}
+ */
+@Backing(type="int")
+@SuppressWarnings(value={"redundant-name"})
+@VintfStability
+enum AudioPolicyForcedConfig {
+    NONE = 0,
+    SPEAKER = 1,
+    HEADPHONES = 2,
+    BT_SCO = 3,
+    BT_A2DP = 4,
+    WIRED_ACCESSORY = 5,
+    BT_CAR_DOCK = 6,
+    BT_DESK_DOCK = 7,
+    ANALOG_DOCK = 8,
+    DIGITAL_DOCK = 9,
+    /** A2DP sink is not preferred to speaker or wired HS */
+    NO_BT_A2DP = 10,
+    /**
+     * Sink selected to render system enforced sound in certain countries for legal reason.
+     * (like camera shutter tone in Japan).
+     */
+    SYSTEM_ENFORCED = 11,
+    HDMI_SYSTEM_AUDIO_ENFORCED = 12,
+    ENCODED_SURROUND_NEVER = 13,
+    ENCODED_SURROUND_ALWAYS = 14,
+    ENCODED_SURROUND_MANUAL = 15,
+    BT_BLE = 16,
+}
diff --git a/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioHalCapConfiguration.aidl b/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioHalCapConfiguration.aidl
new file mode 100644
index 0000000..255b10a
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioHalCapConfiguration.aidl
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
+package android.media.audio.common;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable AudioHalCapConfiguration {
+  @utf8InCpp String name;
+  android.media.audio.common.AudioHalCapRule rule;
+  android.media.audio.common.AudioHalCapParameter[] parameterSettings;
+}
diff --git a/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioHalCapCriterionV2.aidl b/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioHalCapCriterionV2.aidl
new file mode 100644
index 0000000..fd17d6f
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioHalCapCriterionV2.aidl
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
+@VintfStability
+union AudioHalCapCriterionV2 {
+  android.media.audio.common.AudioHalCapCriterionV2.AvailableDevices availableInputDevices;
+  android.media.audio.common.AudioHalCapCriterionV2.AvailableDevices availableOutputDevices;
+  android.media.audio.common.AudioHalCapCriterionV2.AvailableDevicesAddresses availableInputDevicesAddresses;
+  android.media.audio.common.AudioHalCapCriterionV2.AvailableDevicesAddresses availableOutputDevicesAddresses;
+  android.media.audio.common.AudioHalCapCriterionV2.TelephonyMode telephonyMode;
+  android.media.audio.common.AudioHalCapCriterionV2.ForceConfigForUse forceConfigForUse;
+  android.media.audio.common.AudioHalCapCriterionV2.Type type;
+  @VintfStability
+  enum LogicalDisjunction {
+    EXCLUSIVE = 0,
+    INCLUSIVE,
+  }
+  @VintfStability
+  parcelable ForceConfigForUse {
+    android.media.audio.common.AudioPolicyForceUse forceUse = android.media.audio.common.AudioPolicyForceUse.MEDIA;
+    android.media.audio.common.AudioPolicyForcedConfig[] values;
+    android.media.audio.common.AudioPolicyForcedConfig defaultValue = android.media.audio.common.AudioPolicyForcedConfig.NONE;
+    android.media.audio.common.AudioHalCapCriterionV2.LogicalDisjunction logic = android.media.audio.common.AudioHalCapCriterionV2.LogicalDisjunction.EXCLUSIVE;
+  }
+  @VintfStability
+  parcelable TelephonyMode {
+    android.media.audio.common.AudioMode[] values;
+    android.media.audio.common.AudioMode defaultValue = android.media.audio.common.AudioMode.NORMAL;
+    android.media.audio.common.AudioHalCapCriterionV2.LogicalDisjunction logic = android.media.audio.common.AudioHalCapCriterionV2.LogicalDisjunction.EXCLUSIVE;
+  }
+  @VintfStability
+  parcelable AvailableDevices {
+    android.media.audio.common.AudioDeviceDescription[] values;
+    android.media.audio.common.AudioHalCapCriterionV2.LogicalDisjunction logic = android.media.audio.common.AudioHalCapCriterionV2.LogicalDisjunction.INCLUSIVE;
+  }
+  @VintfStability
+  parcelable AvailableDevicesAddresses {
+    android.media.audio.common.AudioDeviceAddress[] values;
+    android.media.audio.common.AudioHalCapCriterionV2.LogicalDisjunction logic = android.media.audio.common.AudioHalCapCriterionV2.LogicalDisjunction.INCLUSIVE;
+  }
+  @VintfStability
+  union Type {
+    android.media.audio.common.AudioDeviceDescription availableDevicesType;
+    android.media.audio.common.AudioDeviceAddress availableDevicesAddressesType;
+    android.media.audio.common.AudioMode telephonyModeType;
+    android.media.audio.common.AudioPolicyForcedConfig forcedConfigType;
+  }
+}
diff --git a/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioHalCapDomain.aidl b/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioHalCapDomain.aidl
new file mode 100644
index 0000000..9c20abe
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioHalCapDomain.aidl
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
+package android.media.audio.common;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable AudioHalCapDomain {
+  @utf8InCpp String name;
+  android.media.audio.common.AudioHalCapConfiguration[] configurations;
+}
diff --git a/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioHalCapParameter.aidl b/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioHalCapParameter.aidl
new file mode 100644
index 0000000..981bd09
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioHalCapParameter.aidl
@@ -0,0 +1,64 @@
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
+package android.media.audio.common;
+/* @hide */
+@VintfStability
+union AudioHalCapParameter {
+  android.media.audio.common.AudioHalCapParameter.StrategyDevice selectedStrategyDevice;
+  android.media.audio.common.AudioHalCapParameter.StrategyDeviceAddress strategyDeviceAddress;
+  android.media.audio.common.AudioHalCapParameter.InputSourceDevice selectedInputSourceDevice;
+  android.media.audio.common.AudioHalCapParameter.StreamVolumeProfile streamVolumeProfile;
+  @VintfStability
+  parcelable StrategyDeviceAddress {
+    android.media.audio.common.AudioDeviceAddress deviceAddress;
+    int id = android.media.audio.common.AudioProductStrategyType.SYS_RESERVED_NONE /* -1 */;
+  }
+  @VintfStability
+  parcelable StrategyDevice {
+    android.media.audio.common.AudioDeviceDescription device;
+    int id = android.media.audio.common.AudioProductStrategyType.SYS_RESERVED_NONE /* -1 */;
+    boolean isSelected;
+  }
+  @VintfStability
+  parcelable InputSourceDevice {
+    android.media.audio.common.AudioDeviceDescription device;
+    android.media.audio.common.AudioSource inputSource = android.media.audio.common.AudioSource.DEFAULT;
+    boolean isSelected;
+  }
+  @VintfStability
+  parcelable StreamVolumeProfile {
+    android.media.audio.common.AudioStreamType stream = android.media.audio.common.AudioStreamType.INVALID;
+    android.media.audio.common.AudioStreamType profile = android.media.audio.common.AudioStreamType.INVALID;
+  }
+}
diff --git a/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioHalCapRule.aidl b/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioHalCapRule.aidl
new file mode 100644
index 0000000..fb1719c
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioHalCapRule.aidl
@@ -0,0 +1,61 @@
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
+package android.media.audio.common;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable AudioHalCapRule {
+  android.media.audio.common.AudioHalCapRule.CompoundRule compoundRule = android.media.audio.common.AudioHalCapRule.CompoundRule.INVALID;
+  android.media.audio.common.AudioHalCapRule.CriterionRule[] criterionRules;
+  android.media.audio.common.AudioHalCapRule[] nestedRules;
+  @VintfStability
+  enum CompoundRule {
+    INVALID = 0,
+    ANY,
+    ALL,
+  }
+  @VintfStability
+  enum MatchingRule {
+    INVALID = (-1) /* -1 */,
+    IS = 0,
+    IS_NOT,
+    INCLUDES,
+    EXCLUDES,
+  }
+  @VintfStability
+  parcelable CriterionRule {
+    android.media.audio.common.AudioHalCapRule.MatchingRule matchingRule = android.media.audio.common.AudioHalCapRule.MatchingRule.INVALID;
+    android.media.audio.common.AudioHalCapCriterionV2 criterion;
+    android.media.audio.common.AudioHalCapCriterionV2.Type criterionTypeValue;
+  }
+}
diff --git a/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioHalEngineConfig.aidl b/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioHalEngineConfig.aidl
index 807dd25..bc856da 100644
--- a/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioHalEngineConfig.aidl
+++ b/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioHalEngineConfig.aidl
@@ -43,5 +43,7 @@ parcelable AudioHalEngineConfig {
   parcelable CapSpecificConfig {
     android.media.audio.common.AudioHalCapCriterion[] criteria;
     android.media.audio.common.AudioHalCapCriterionType[] criterionTypes;
+    @nullable android.media.audio.common.AudioHalCapCriterionV2[] criteriaV2;
+    @nullable android.media.audio.common.AudioHalCapDomain[] domains;
   }
 }
diff --git a/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioHalProductStrategy.aidl b/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioHalProductStrategy.aidl
index 9615961..1144574 100644
--- a/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioHalProductStrategy.aidl
+++ b/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioHalProductStrategy.aidl
@@ -37,5 +37,6 @@ package android.media.audio.common;
 parcelable AudioHalProductStrategy {
   int id = android.media.audio.common.AudioProductStrategyType.SYS_RESERVED_NONE /* -1 */;
   android.media.audio.common.AudioHalAttributesGroup[] attributesGroups;
+  @nullable @utf8InCpp String name;
   const int VENDOR_STRATEGY_ID_START = 1000;
 }
diff --git a/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioPolicyForceUse.aidl b/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioPolicyForceUse.aidl
new file mode 100644
index 0000000..7e69f85
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioPolicyForceUse.aidl
@@ -0,0 +1,46 @@
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
+package android.media.audio.common;
+/* @hide */
+@Backing(type="int") @SuppressWarnings(value={"redundant-name"}) @VintfStability
+enum AudioPolicyForceUse {
+  COMMUNICATION = 0,
+  MEDIA = 1,
+  RECORD = 2,
+  DOCK = 3,
+  SYSTEM = 4,
+  HDMI_SYSTEM_AUDIO = 5,
+  ENCODED_SURROUND = 6,
+  VIBRATE_RINGING = 7,
+}
diff --git a/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioPolicyForcedConfig.aidl b/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioPolicyForcedConfig.aidl
new file mode 100644
index 0000000..5135bcd
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioPolicyForcedConfig.aidl
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
+@Backing(type="int") @SuppressWarnings(value={"redundant-name"}) @VintfStability
+enum AudioPolicyForcedConfig {
+  NONE = 0,
+  SPEAKER = 1,
+  HEADPHONES = 2,
+  BT_SCO = 3,
+  BT_A2DP = 4,
+  WIRED_ACCESSORY = 5,
+  BT_CAR_DOCK = 6,
+  BT_DESK_DOCK = 7,
+  ANALOG_DOCK = 8,
+  DIGITAL_DOCK = 9,
+  NO_BT_A2DP = 10,
+  SYSTEM_ENFORCED = 11,
+  HDMI_SYSTEM_AUDIO_ENFORCED = 12,
+  ENCODED_SURROUND_NEVER = 13,
+  ENCODED_SURROUND_ALWAYS = 14,
+  ENCODED_SURROUND_MANUAL = 15,
+  BT_BLE = 16,
+}
diff --git a/suspend/1.0/default/OWNERS b/suspend/1.0/default/OWNERS
index bcc9e5f..b278c1c 100644
--- a/suspend/1.0/default/OWNERS
+++ b/suspend/1.0/default/OWNERS
@@ -1,4 +1,5 @@
 # Bug component: 30545
 krossmo@google.com
 santoscordon@google.com
-trong@google.com
+vilasbhat@google.com
+kaleshsingh@google.com
diff --git a/suspend/1.0/default/SystemSuspend.cpp b/suspend/1.0/default/SystemSuspend.cpp
index 4aa5189..c628e43 100644
--- a/suspend/1.0/default/SystemSuspend.cpp
+++ b/suspend/1.0/default/SystemSuspend.cpp
@@ -396,8 +396,7 @@ void SystemSuspend::initAutosuspendLocked() {
             if (wakeupReasons == std::vector<std::string>({kUnknownWakeup})) {
                 LOG(INFO) << "Unknown/empty wakeup reason. Re-opening wakeup_reason file.";
 
-                mWakeupReasonsFd =
-                    std::move(reopenFileUsingFd(mWakeupReasonsFd.get(), O_CLOEXEC | O_RDONLY));
+                mWakeupReasonsFd = reopenFileUsingFd(mWakeupReasonsFd.get(), O_CLOEXEC | O_RDONLY);
             }
             mWakeupList.update(wakeupReasons);
 
diff --git a/suspend/1.0/default/SystemSuspendUnitTest.cpp b/suspend/1.0/default/SystemSuspendUnitTest.cpp
index 6f19bbd..b751731 100644
--- a/suspend/1.0/default/SystemSuspendUnitTest.cpp
+++ b/suspend/1.0/default/SystemSuspendUnitTest.cpp
@@ -232,6 +232,24 @@ class SystemSuspendTest : public ::testing::Test {
         return count_if(wlStats.begin(), wlStats.end(), [](auto entry) { return entry.isActive; });
     }
 
+    // Wait for wakelock's active count to reach a certain value.
+    bool waitForActiveCount(
+        const std::string& wl_name, int expectedCount,
+        std::chrono::milliseconds timeout = std::chrono::milliseconds(100),
+        std::chrono::milliseconds pollingInterval = std::chrono::milliseconds(10)) {
+        std::chrono::steady_clock::time_point start_time = std::chrono::steady_clock::now();
+        while (std::chrono::steady_clock::now() - start_time < timeout) {
+            std::vector<WakeLockInfo> wlStats = getWakelockStats();
+            WakeLockInfo wlInfo;
+            if (findWakeLockInfoByName(wlStats, wl_name, &wlInfo) &&
+                wlInfo.activeCount == expectedCount) {
+                return true;
+            }
+            std::this_thread::sleep_for(pollingInterval);
+        }
+        return false;
+    }
+
     void checkLoop(int numIter) {
         for (int i = 0; i < numIter; i++) {
             // Mock value for /sys/power/wakeup_count.
@@ -269,6 +287,23 @@ class SystemSuspendTest : public ::testing::Test {
         ASSERT_EQ(actual.count(), expected.count()) << "incorrect sleep time";
     }
 
+    bool findWakeLockInfoByName(const std::vector<WakeLockInfo>& wlStats, const std::string& name,
+                                WakeLockInfo* info) {
+        auto it = std::find_if(wlStats.begin(), wlStats.end(),
+                               [&name](const auto& x) { return x.name == name; });
+        if (it != wlStats.end()) {
+            *info = *it;
+            return true;
+        }
+        return false;
+    }
+
+    std::vector<WakeLockInfo> getWakelockStats() {
+        std::vector<WakeLockInfo> wlStats;
+        controlServiceInternal->getWakeLockStats(&wlStats);
+        return wlStats;
+    }
+
     std::shared_ptr<ISystemSuspend> suspendService;
     sp<ISuspendControlService> controlService;
     sp<ISuspendControlServiceInternal> controlServiceInternal;
@@ -857,6 +892,143 @@ TEST_F(SystemSuspendTest, CallbackNotifyWakelock) {
     cb2->disable();
 }
 
+// Tests for a potential race condition in wakelock stats updates.
+// This checks wakelock accounting when a wakelock is acquired and released, and a re-acquire
+// happens immediately.
+TEST_F(SystemSuspendTest, WakeLockStatsRaceConditionTest) {
+    constexpr int kNumRetries = 100;
+
+    for (int i = 0; i < kNumRetries; i++) {
+        std::string testLockName = "testLock" + std::to_string(i + 1);
+
+        std::shared_ptr<IWakeLock> wlA = acquireWakeLock(testLockName);
+        ASSERT_NE(wlA, nullptr);
+
+        // Release the wakelock. This executes async as 'release()' is marked oneway.
+        wlA->release();
+
+        // Immediately re-acquire the wakelock.
+        std::shared_ptr<IWakeLock> wlB = acquireWakeLock(testLockName);
+        ASSERT_NE(wlB, nullptr);
+
+        // Let the release operation complete.
+        EXPECT_TRUE(waitForActiveCount(testLockName, 1))
+            << "Timeout waiting for activeCount to reach 1 (retry: " << i << ")";
+
+        std::vector<WakeLockInfo> wlStats = getWakelockStats();
+        WakeLockInfo wlInfo;
+        ASSERT_TRUE(findWakeLockInfoByName(wlStats, testLockName, &wlInfo));
+        EXPECT_TRUE(wlInfo.isActive);
+        EXPECT_EQ(wlInfo.activeCount, 1);
+
+        wlB->release();
+        EXPECT_TRUE(waitForActiveCount(testLockName, 0))
+            << "Timeout waiting for activeCount to reach 0 (retry: " << i << ")";
+
+        wlStats = getWakelockStats();
+        ASSERT_TRUE(findWakeLockInfoByName(wlStats, testLockName, &wlInfo));
+        EXPECT_FALSE(wlInfo.isActive);
+        EXPECT_EQ(wlInfo.activeCount, 0);
+        EXPECT_EQ(wlInfo.activeTime, 0);
+    }
+}
+
+// Tests for correctness of the wakelock active count, active status and active time when multiple
+// wakelocks of the same name are acquired and released sequentially.
+// Order tested: Acq A -> Acq B -> Rel A -> Rel B.
+TEST_F(SystemSuspendTest, WakeLockStatsActiveCountDecrementCheck) {
+    std::string testLockName = "testLock";
+
+    std::shared_ptr<IWakeLock> wlA = acquireWakeLock(testLockName);
+    ASSERT_NE(wlA, nullptr);
+
+    std::vector<WakeLockInfo> wlStats = getWakelockStats();
+    WakeLockInfo wlInfo;
+    ASSERT_TRUE(findWakeLockInfoByName(wlStats, testLockName, &wlInfo));
+    EXPECT_TRUE(wlInfo.isActive);
+    EXPECT_EQ(wlInfo.activeCount, 1);
+
+    std::shared_ptr<IWakeLock> wlB = acquireWakeLock(testLockName);
+    ASSERT_NE(wlB, nullptr);
+
+    wlStats = getWakelockStats();
+    ASSERT_TRUE(findWakeLockInfoByName(wlStats, testLockName, &wlInfo));
+    EXPECT_TRUE(wlInfo.isActive);
+    EXPECT_EQ(wlInfo.activeCount, 2);
+
+    wlA->release();
+    // Let the release operation complete.
+    EXPECT_TRUE(waitForActiveCount(testLockName, 1))
+            << "Timeout waiting for activeCount to reach 1";
+    // Sleep for 5ms to test activeTime update later.
+    std::this_thread::sleep_for(5ms);
+
+    wlStats = getWakelockStats();
+    ASSERT_TRUE(findWakeLockInfoByName(wlStats, testLockName, &wlInfo));
+    // wlB of the same name is yet to be released.
+    EXPECT_TRUE(wlInfo.isActive);
+    EXPECT_EQ(wlInfo.activeCount, 1);
+    EXPECT_GE(wlInfo.activeTime, 5);
+
+    wlB->release();
+    EXPECT_TRUE(waitForActiveCount(testLockName, 0))
+            << "Timeout waiting for activeCount to reach 0";
+
+    wlStats = getWakelockStats();
+    ASSERT_TRUE(findWakeLockInfoByName(wlStats, testLockName, &wlInfo));
+    EXPECT_FALSE(wlInfo.isActive);
+    EXPECT_EQ(wlInfo.activeCount, 0);
+    EXPECT_EQ(wlInfo.activeTime, 0);
+}
+
+// Tests for correctness of the wakelock active count, active status and active time when multiple
+// wakelocks are acquired and released sequentially.
+// Order tested: Acq A -> Acq B -> Rel B -> Rel A.
+TEST_F(SystemSuspendTest, WakeLockStatsAcquiredReleasedInLIFOOrder) {
+    std::string testLockName = "testLock";
+
+    std::shared_ptr<IWakeLock> wlA = acquireWakeLock(testLockName);
+    ASSERT_NE(wlA, nullptr);
+
+    std::vector<WakeLockInfo> wlStats = getWakelockStats();
+    WakeLockInfo wlInfo;
+    ASSERT_TRUE(findWakeLockInfoByName(wlStats, testLockName, &wlInfo));
+    EXPECT_TRUE(wlInfo.isActive);
+    EXPECT_EQ(wlInfo.activeCount, 1);
+
+    std::shared_ptr<IWakeLock> wlB = acquireWakeLock(testLockName);
+    ASSERT_NE(wlB, nullptr);
+
+    wlStats = getWakelockStats();
+    ASSERT_TRUE(findWakeLockInfoByName(wlStats, testLockName, &wlInfo));
+    EXPECT_TRUE(wlInfo.isActive);
+    EXPECT_EQ(wlInfo.activeCount, 2);
+
+    wlB->release();
+    // Let the release operation complete.
+    EXPECT_TRUE(waitForActiveCount(testLockName, 1))
+            << "Timeout waiting for activeCount to reach 1";
+    // Sleep for 5ms to test activeTime update later.
+    std::this_thread::sleep_for(5ms);
+
+    wlStats = getWakelockStats();
+    ASSERT_TRUE(findWakeLockInfoByName(wlStats, testLockName, &wlInfo));
+    // wlB of the same name is yet to be released.
+    EXPECT_TRUE(wlInfo.isActive);
+    EXPECT_EQ(wlInfo.activeCount, 1);
+    EXPECT_GE(wlInfo.activeTime, 5);
+
+    wlA->release();
+    EXPECT_TRUE(waitForActiveCount(testLockName, 0))
+            << "Timeout waiting for activeCount to reach 0";
+
+    wlStats = getWakelockStats();
+    ASSERT_TRUE(findWakeLockInfoByName(wlStats, testLockName, &wlInfo));
+    EXPECT_FALSE(wlInfo.isActive);
+    EXPECT_EQ(wlInfo.activeCount, 0);
+    EXPECT_EQ(wlInfo.activeTime, 0);
+}
+
 class SystemSuspendSameThreadTest : public ::testing::Test {
    public:
     std::shared_ptr<IWakeLock> acquireWakeLock(const std::string& name = "TestLock") {
@@ -1119,7 +1291,7 @@ TEST_F(SystemSuspendSameThreadTest, GetNativeWakeLockStats) {
     WakeLockInfo nwlInfo;
     ASSERT_TRUE(findWakeLockInfoByName(wlStats, fakeWlName, &nwlInfo));
     ASSERT_EQ(nwlInfo.name, fakeWlName);
-    ASSERT_EQ(nwlInfo.activeCount, 1);
+    ASSERT_EQ(nwlInfo.activeCount, 0);
     ASSERT_GE(nwlInfo.maxTime, 1000);
     ASSERT_GE(nwlInfo.totalTime, 1000);
     ASSERT_EQ(nwlInfo.isActive, false);
@@ -1238,7 +1410,7 @@ TEST_F(SystemSuspendSameThreadTest, GetNativeAndKernelWakeLockStats) {
     WakeLockInfo nwlInfo;
     ASSERT_TRUE(findWakeLockInfoByName(wlStats, fakeNwlName, &nwlInfo));
     ASSERT_EQ(nwlInfo.name, fakeNwlName);
-    ASSERT_EQ(nwlInfo.activeCount, 1);
+    ASSERT_EQ(nwlInfo.activeCount, 0);
     ASSERT_GE(nwlInfo.maxTime, 1000);
     ASSERT_GE(nwlInfo.totalTime, 1000);
     ASSERT_EQ(nwlInfo.isActive, false);
diff --git a/suspend/1.0/default/WakeLockEntryList.cpp b/suspend/1.0/default/WakeLockEntryList.cpp
index 3c7fa3b..5a43501 100644
--- a/suspend/1.0/default/WakeLockEntryList.cpp
+++ b/suspend/1.0/default/WakeLockEntryList.cpp
@@ -131,14 +131,34 @@ WakeLockEntryList::WakeLockEntryList(size_t capacity, unique_fd kernelWakelockSt
  * Evicts LRU from back of list if stats is at capacity.
  */
 void WakeLockEntryList::evictIfFull() {
+    static std::chrono::steady_clock::time_point lastWarningTime{};
+    static std::chrono::steady_clock::time_point lastEvictionTime{};
+    static long evictionCountSinceLastLog = 0;
+
     if (mStats.size() == mCapacity) {
         auto evictIt = mStats.end();
         std::advance(evictIt, -1);
         auto evictKey = std::make_pair(evictIt->name, evictIt->pid);
         mLookupTable.erase(evictKey);
         mStats.erase(evictIt);
-        LOG(ERROR) << "WakeLock Stats: Stats capacity met, consider adjusting capacity to "
-                      "avoid stats eviction.";
+
+        std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
+        long long secondsSinceLastLog =
+            std::chrono::duration_cast<std::chrono::seconds>(now - lastWarningTime).count();
+        evictionCountSinceLastLog++;
+
+        if (secondsSinceLastLog >= 5) {
+            long long secondsSinceLastEvict =
+                std::chrono::duration_cast<std::chrono::seconds>(now - lastEvictionTime).count();
+            LOG(WARNING) << "WakeLock Stats: Stats capacity met " << evictionCountSinceLastLog
+                         << " time(s) since last warning (" << secondsSinceLastLog
+                         << " seconds ago). An eviction is occurring now, with the previous"
+                         << " eviction occurring " << secondsSinceLastEvict
+                         << " seconds ago. Consider adjusting capacity to avoid stats eviction.";
+            lastWarningTime = now;
+            evictionCountSinceLastLog = 0; // Reset the count
+        }
+        lastEvictionTime = now;
     }
 }
 
@@ -365,10 +385,16 @@ void WakeLockEntryList::updateOnRelease(const std::string& name, int pid) {
 
         // Update entry
         TimestampType timeDelta = timeNow - updatedEntry.lastChange;
-        updatedEntry.isActive = false;
+        if (updatedEntry.activeCount > 0) {
+            updatedEntry.activeCount--;
+        } else {
+            LOG(ERROR) << "WakeLock Stats: Active count attempted to go below zero for "
+                       << "wakelock \"" << name << "\". This is unexpected.";
+        }
+        updatedEntry.isActive = (updatedEntry.activeCount > 0);
         updatedEntry.activeTime += timeDelta;
         updatedEntry.maxTime = std::max(updatedEntry.maxTime, updatedEntry.activeTime);
-        updatedEntry.activeTime = 0;  // No longer active
+        updatedEntry.activeTime = updatedEntry.isActive ? updatedEntry.activeTime : 0;
         updatedEntry.totalTime += timeDelta;
         updatedEntry.lastChange = timeNow;
 
diff --git a/suspend/1.0/default/fuzzers/SuspendServiceFuzzer.cpp b/suspend/1.0/default/fuzzers/SuspendServiceFuzzer.cpp
index 4ed52db..226fce0 100644
--- a/suspend/1.0/default/fuzzers/SuspendServiceFuzzer.cpp
+++ b/suspend/1.0/default/fuzzers/SuspendServiceFuzzer.cpp
@@ -23,6 +23,7 @@ using ::android::sp;
 using ::android::system::suspend::V1_0::SuspendControlService;
 
 extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
+    signal(SIGPIPE, SIG_IGN);
     sp<SuspendControlService> suspendControlService = sp<SuspendControlService>::make();
     fuzzService(suspendControlService, FuzzedDataProvider(data, size));
     return 0;
diff --git a/wifi/keystore/1.0/default/test/WifiLegacyKeystoreIntegrationTest.cpp b/wifi/keystore/1.0/default/test/WifiLegacyKeystoreIntegrationTest.cpp
index ac801e5..68b993e 100644
--- a/wifi/keystore/1.0/default/test/WifiLegacyKeystoreIntegrationTest.cpp
+++ b/wifi/keystore/1.0/default/test/WifiLegacyKeystoreIntegrationTest.cpp
@@ -110,6 +110,9 @@ static const std::vector<uint8_t> kDerTestCert{
 class WifiLegacyKeystoreTest : public TestWithParam<std::string> {
    protected:
     void SetUp() override {
+        if (!isLegacyKeystoreEnabled()) {
+            GTEST_SKIP() << "Legacy Keystore is not fully supported";
+        }
         wifiKeystoreHal = IKeystore::getService(GetParam());
         ASSERT_TRUE(wifiKeystoreHal);
 
@@ -134,6 +137,11 @@ class WifiLegacyKeystoreTest : public TestWithParam<std::string> {
         return false;
     }
 
+    bool isLegacyKeystoreEnabled() {
+        // Legacy Keystore is partly deprecated after Android U
+        return property_get_int32("ro.board.api_level", 0) <= __ANDROID_API_U__;
+    }
+
     sp<IKeystore> wifiKeystoreHal;
     uid_t myRUid;
 };
```

