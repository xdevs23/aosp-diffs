```
7a20ffe5: audio: add audio_output_is_mixed_output_flags (Kuowei Li <kuowei.li@mediatek.com>)
ac09757f: AIDL effect: add version for draining state support (Shunkai Yao <yaoshunkai@google.com>)
90f46b28: Camera: Add desktop effects metadata tags (Imran Ziad <imranziad@google.com>)
081badef: Add UUID for eraser effect uuid (Shunkai Yao <yaoshunkai@google.com>)
432a85fc: Add audio header definitions for IAMF (Jean-Michel Trivi <jmtrivi@google.com>)
4b1d8a6d: Add version number to support effect destroy at any state (Shunkai Yao <yaoshunkai@google.com>)
2e856175: Add audio_uuid_t ToString and equality operator utils (Shunkai Yao <yaoshunkai@google.com>)
bfc170f8: Spatializer: define SPATIALIZER_PARAM_SPATIALIZED_CHANNEL_MASKS (Jean-Michel Trivi <jmtrivi@google.com>)
21cfc78c: Add audio_uuid_t ToString and equality operator utils (Shunkai Yao <yaoshunkai@google.com>)
e5978e3e: AIDL effect: add version for draining state support (Shunkai Yao <yaoshunkai@google.com>)
96f25526: audio_utils: Add Trace handling (Andy Hung <hunga@google.com>)
dd5545e9: Camera: auto-generate non-HAL visible request keys (Shuzhen Wang <shuzhenwang@google.com>)
c00276c2: Revert^2 "audio: Add audio_policy_forced_cfg_to_string" (Mikhail Naganov <mnaganov@google.com>)
8e7d523f: Revert "audio: Add audio_policy_forced_cfg_to_string" (Priyanka Advani (xWF) <padvani@google.com>)
b67df495: audio_utils: Add name format change string utility (Andy Hung <hunga@google.com>)
b612317c: Add element-wise min/max/clamp op for AIDL unions (Shunkai Yao <yaoshunkai@google.com>)
043db477: audio_utils: Move useful string utilities from mediametrics (Andy Hung <hunga@google.com>)
ec1be51b: Add multi-client support in camera2 (Jyoti Bhayana <jbhayana@google.com>)
4faf825f: Camera: Fix missing enums for fwk_only visibility (Shuzhen Wang <shuzhenwang@google.com>)
5d6df118: Camera: Improve physicalCameraIds dumpsys (Shuzhen Wang <shuzhenwang@google.com>)
7aada737: Camera: Add fwk_ndk_public visibility (Shuzhen Wang <shuzhenwang@google.com>)
9c059773: Camera metadata: Support system API for synthetic keys (Eino-Ville Talvala <etalvala@google.com>)
3cd32b57: Camera: Add AE priority mode tags (Ravneet Dhanjal <rdhanjal@google.com>)
bf772c2c: Camera: Add Baklava for feature combination query version (Shuzhen Wang <shuzhenwang@google.com>)
21c627a2: audio: Add audio_policy_forced_cfg_to_string (Mikhail Naganov <mnaganov@google.com>)
f72f59e8: Camera: Add CONTROL_ZOOM_METHOD CaptureRequest key (Shuzhen Wang <shuzhenwang@google.com>)
a66b4a82: Night Mode Indicator (Jag Saund <jagsaund@google.com>)
eb87bb73: Add elementwise min/max utils (Shunkai Yao <yaoshunkai@google.com>)
cc1f5887: Rename clamp_utils to elementwise_op (Shunkai Yao <yaoshunkai@google.com>)
2a465158: Add clamp_utils for structures and vector clamping (Shunkai Yao <yaoshunkai@google.com>)
f2e576a9: Add opAggregateImpl and opAggregateImpl_N for element-wise operation (Shunkai Yao <yaoshunkai@google.com>)
fe17babd: Add elementwise min/max utils (Shunkai Yao <yaoshunkai@google.com>)
18713780: Add clampParameter for effects with elementwise_op utility (Shunkai Yao <yaoshunkai@google.com>)
9884bedd: Rename clamp_utils to elementwise_op (Shunkai Yao <yaoshunkai@google.com>)
67d6d17b: Add clamp_utils for structures and vector clamping (Shunkai Yao <yaoshunkai@google.com>)
96991641: Add opAggregateImpl and opAggregateImpl_N for element-wise operation (Shunkai Yao <yaoshunkai@google.com>)
2278d20f: Add a speaker_layout_channel_mask to audio_port_config_device_ext (Trevor Knight <trevork@google.com>)
5e9c98e4: Camera: Fix CameraMetadataTag.mako template (Shuzhen Wang <shuzhenwang@google.com>)
f6f73cc7: Revert^2 "Add SPEAKER_CLEANUP system usage HAL definition" (Jean-Michel Trivi <jmtrivi@google.com>)
6207e812: Revert "Add SPEAKER_CLEANUP system usage HAL definition" (Liana Kazanova (xWF) <lkazanova@google.com>)
33d713f3: Camera: Add color temperature metadata tags (Ravneet Dhanjal <rdhanjal@google.com>)
8066b250: Add SPEAKER_CLEANUP system usage HAL definition (Jean-Michel Trivi <jmtrivi@google.com>)
c763cfdb: Add audio device type MULTICHANNEL_GROUP (yucliu <yucliu@google.com>)
4f841322: Camera: Add HEIC UltraHDR stream configuration tags (Emilian Peev <epeev@google.com>)
918d570c: camera: Clarify hot pixel map coordinate system when sensor pixel mode i... (Jayant Chowdhary <jchowdhary@google.com>)
f57c7575: Add UUID for eraser effect uuid (Shunkai Yao <yaoshunkai@google.com>)
b46ad028: Update AE_MODE_ON description for flash control. (Rucha Katakwar <ruchamk@google.com>)
e049bec2: audio_utils: Add RunRemote to run methods on a separate process (Andy Hung <hunga@google.com>)
5a4f996b: Change libalsautilsv2 for shared library to cc_library (Weilin Xu <xuweilin@google.com>)
78c7412f: audio_utils: add queue wait analysis (Andy Hung <hunga@google.com>)
f59e9540: audio_utils: Add a std::mutex timed_lock method (Andy Hung <hunga@google.com>)
3e6c58d8: audio: Add support for AC-4 level 4 audio format (Michael Chan <michael.chan@dolby.com>)
38b214f2: audio_utils: Enable unique_lock safety annotations for MelProcessor (Andy Hung <hunga@google.com>)
9e9e0bd0: camera: Remove session_hal_buf_manager flag (Jayant Chowdhary <jchowdhary@google.com>)
bbd6ac2c: audio_utils: Enable unique_lock safety annotations for CommandThread (Andy Hung <hunga@google.com>)
1bd1d3dc: audio_utils: Add unique_lock variant for std::mutex (Andy Hung <hunga@google.com>)
5a8dbea8: Change libalsautilsv2 for shared library to cc_library (Weilin Xu <xuweilin@google.com>)
```

